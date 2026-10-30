package research

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/flow"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

const HistoricalReplaySchema = "historical-replay.v1"

// ErrHistoricalAuthority distinguishes historical playback from current admission.
var ErrHistoricalAuthority = errors.New("historical replay cannot be used as a current result or proof")

type HistoricalArtifact struct {
	Path string `json:"path"`
	SHA256 string `json:"sha256"`
	SizeBytes int64 `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

// HistoricalReplay is an archival wrapper, never an admitted finding. The saved
// report and all sidecars remain byte-identical under original/.
type HistoricalReplay struct {
	Schema string `json:"schema"`
	HistoricalOnly bool `json:"historical_only"`
	CurrentAdmission bool `json:"current_admission"`
	OriginalSchema string `json:"original_schema"`
	OriginalRunID string `json:"original_run_id"`
	Artifacts []HistoricalArtifact `json:"artifacts"`
	files map[string][]byte
	source string
	sourceAlias string
}

// PrepareHistoricalReplay consumes only retained files. No source checkout,
// executable harness, current registry or live investigator is consulted.
func PrepareHistoricalReplay(ctx context.Context, dir string) (HistoricalReplay, error) {
	var out HistoricalReplay
	if ctx == nil || strings.TrimSpace(dir) == "" { return out, fmt.Errorf("historical replay requires context and saved-run directory") }
	base, err := filepath.Abs(dir)
	if err != nil { return out, err }
	sourceAlias := base
	base, err = filepath.EvalSymlinks(base)
	if err != nil { return out, err }
	out = HistoricalReplay{Schema: HistoricalReplaySchema, HistoricalOnly: true, files: map[string][]byte{}, source: base, sourceAlias: sourceAlias}
	err = filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if err := ctx.Err(); err != nil { return err }
		if entry.Type()&os.ModeSymlink != 0 { return fmt.Errorf("historical replay: symlink %s is unsafe", path) }
		if entry.IsDir() { return nil }
		info, err := entry.Info()
		if err != nil { return err }
		if !info.Mode().IsRegular() { return fmt.Errorf("historical replay: non-regular artifact %s", path) }
		rel, err := filepath.Rel(base, path)
		if err != nil { return err }
		b, err := os.ReadFile(path)
		if err != nil { return err }
		out.files[filepath.ToSlash(rel)] = b
		sum := sha256.Sum256(b)
		out.Artifacts = append(out.Artifacts, HistoricalArtifact{Path: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(b)), ModifiedAt: info.ModTime()})
		return nil
	})
	if err != nil { return HistoricalReplay{}, err }
	raw, ok := out.files["report.json"]
	if !ok { return HistoricalReplay{}, fmt.Errorf("historical replay: missing report.json") }
	r, err := ParseReport(raw)
	if err != nil { return HistoricalReplay{}, err }
	switch r.Schema {
	case ReportSchemaV1, ReportSchemaV2, ReportSchemaV3, ReportSchemaV4:
	default: return HistoricalReplay{}, fmt.Errorf("historical replay: schema %q is not a saved /1–/4 report", r.Schema)
	}
	// Validate against an immutable private copy, not files that might change
	// between validation and publication. Absolute provenance paths are never
	// dereferenced; recorded artifact paths must be confined to this archive.
	for name, b := range out.files {
		if name == "report.json" || name == "run-manifest.json" || name == flowResultFile ||
			name == "observations.jsonl" || name == flowObservationLedger {
			dec := json.NewDecoder(bytes.NewReader(b))
			for {
				var value any
				if err := dec.Decode(&value); errors.Is(err, io.EOF) { break } else if err != nil { return HistoricalReplay{}, fmt.Errorf("%s: %w", name, err) }
				if err := out.checkPins(value); err != nil { return HistoricalReplay{}, fmt.Errorf("%s: %w", name, err) }
			}
		}
	}
	tmp, err := os.MkdirTemp("", "izyan-history-validation-")
	if err != nil { return HistoricalReplay{}, err }
	defer os.RemoveAll(tmp)
	if err := out.copyFiles(tmp); err != nil { return HistoricalReplay{}, err }
	// Validation may use optional original advisory bytes. Supply only retained
	// bytes, never the original host/source path, without changing the archive.
	r.Input.Advisory.SourcePath = ""
	if err := Validate(r, tmp); err != nil { return HistoricalReplay{}, err }
	if _, ok := out.files[flowResultFile]; ok {
		var result flow.Result
		if err := decodeHistoricalJSON(out.files[flowResultFile], &result); err != nil { return HistoricalReplay{}, err }
		if err := flow.ValidateHistoricalRecord(result); err != nil { return HistoricalReplay{}, err }
		events, ok := out.files[flowEventsFile]
		if !ok { return HistoricalReplay{}, fmt.Errorf("historical replay: missing %s", flowEventsFile) }
		dec := json.NewDecoder(bytes.NewReader(events))
		dec.DisallowUnknownFields()
		var saved []flow.Event
		for { var ev flow.Event; if err := dec.Decode(&ev); errors.Is(err, io.EOF) { break } else if err != nil { return HistoricalReplay{}, err }; saved = append(saved, ev) }
		want, _ := json.Marshal(result.Events); got, _ := json.Marshal(saved)
		if !bytes.Equal(want, got) { return HistoricalReplay{}, fmt.Errorf("historical replay: flow event sidecar differs from result") }
		if _, ok := out.files[flowObservationLedger]; !ok { return HistoricalReplay{}, fmt.Errorf("historical replay: missing %s", flowObservationLedger) }
		recorded, err := LoadPersistedDecisionRun(tmp)
		if err != nil { return HistoricalReplay{}, err }
		for _, observation := range result.Observations {
			if !observation.AuditBound { continue }
			if err := validateHistoricalAuditObservation(result.Actions, observation, recorded.Audit); err != nil { return HistoricalReplay{}, err }
		}
	}
	out.OriginalSchema, out.OriginalRunID = r.Schema, r.Run.RunID
	return out, nil
}

func decodeHistoricalJSON(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b)); dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil { return err }
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) { return fmt.Errorf("historical replay: trailing JSON: %v", err) }
	return nil
}

func (h HistoricalReplay) checkPins(value any) error {
	switch v := value.(type) {
	case []any:
		for _, child := range v { if err := h.checkPins(child); err != nil { return err } }
	case map[string]any:
		// Advisory and snapshot-source references describe original inputs,
		// not retained output artifacts. Their identity is checked by Validate;
		// playback must not open the original checkout or advisory source.
		if kind, _ := v["kind"].(string); kind == "advisory" || kind == "snapshot-source" { return nil }
		for _, pair := range [][2]string{
			{"path", "sha256"},
			{"prompt_path", "prompt_sha256"},
			{"rendered_prompt_path", "rendered_prompt_sha256"},
			{"e6_preflight_report", "e6_preflight_sha256"},
			{"report_path", "report_sha256"},
		} {
			pathValue := v[pair[0]]
			if pathValue == nil && v[pair[1]] == nil { continue }
			// AgentTurnMetadata repeats the rendered digest; its manifest
			// owns the corresponding path. It is not a second artifact pin.
			if _, metadata := v["role"]; metadata && pair[0] == "rendered_prompt_path" && pathValue == nil { continue }
			path, pathOK := pathValue.(string)
			digest, digestOK := v[pair[1]].(string)
			// Plain path fields also describe unpinned snapshot provenance.
			if pair[0] == "path" && !digestOK { continue }
			if !pathOK || path == "" || !digestOK || !assumptionSHA256Re.MatchString(digest) { return fmt.Errorf("incomplete recorded %s/%s pin", pair[0], pair[1]) }
			if err := h.checkArtifactPin(path, digest); err != nil { return err }
			if size, ok := v["size_bytes"].(float64); pair[0] == "path" && ok && size > 0 && size != float64(len(h.files[path])) { return fmt.Errorf("artifact %s size mismatch", path) }
		}
		for _, child := range v { if err := h.checkPins(child); err != nil { return err } }
	}
	return nil
}

// Named paths may retain an absolute path from this saved run, but must never
// authorize reads outside the immutable retained file set.
func (h HistoricalReplay) checkArtifactPin(path, digest string) error {
	retained := path
	if filepath.IsAbs(path) {
		var err error
		retained, err = filepath.Rel(h.source, path)
		if err != nil { return err }
		if retained == ".." || strings.HasPrefix(retained, "../") {
			retained, err = filepath.Rel(h.sourceAlias, path)
			if err != nil { return err }
		}
	}
	if retained == "" || strings.Contains(retained, "\\") || filepath.Clean(retained) != retained || retained == ".." || strings.HasPrefix(retained, "../") { return fmt.Errorf("unsafe pinned path %q", path) }
	b, ok := h.files[filepath.ToSlash(retained)]
	if !ok { return fmt.Errorf("missing pinned artifact %s", path) }
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != digest { return fmt.Errorf("artifact %s sha256 mismatch", path) }
	return nil
}

func validateHistoricalAuditObservation(actions []flow.PlanAction, observation flow.Observation, audit []evidencetools.AuditRecord) error {
	var record *evidencetools.AuditRecord
	matches := 0
	for i := range audit {
		if audit[i].Observation != nil && audit[i].Observation.ID == observation.ID { record = &audit[i]; matches++ }
	}
	if matches != 1 { return fmt.Errorf("historical replay: audit-bound observation %s has %d ledger rows", observation.ID, matches) }
	o := record.Observation
	digest, err := canonicalObservationDigest(o)
	if err != nil { return err }
	if digest != observation.DataDigest || string(o.ToolStatus) != observation.Status || string(o.Completeness) != observation.Completeness || o.Scope != observation.Scope || !equalHistoricalStrings(o.EvidenceRefs, observation.EvidenceRefs) || !equalHistoricalStrings(o.Limitations, observation.Limitations) {
		return fmt.Errorf("historical replay: observation %s differs from audit contents", observation.ID)
	}
	matchedActions := 0
	for i := range actions {
		a := &actions[i]
		if a.ID != observation.ActionID { continue }
		matchedActions++
		if record.Tool != o.Tool || !toolMatchesAction(a, record.Tool) || !equalJSON(a.Arguments, record.Args) { return fmt.Errorf("historical replay: observation %s differs from executed audit request", observation.ID) }
	}
	if matchedActions != 1 { return fmt.Errorf("historical replay: observation %s has %d executed actions", observation.ID, matchedActions) }
	return nil
}

func equalHistoricalStrings(a, b []string) bool {
	if len(a) != len(b) { return false }
	for i := range a { if a[i] != b[i] { return false } }
	return true
}

func (h HistoricalReplay) copyFiles(dir string) error {
	for _, artifact := range h.Artifacts {
		path := filepath.Join(dir, filepath.FromSlash(artifact.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { return err }
		if err := os.WriteFile(path, h.files[artifact.Path], 0o600); err != nil { return err }
		if err := os.Chtimes(path, artifact.ModifiedAt, artifact.ModifiedAt); err != nil { return err }
	}
	return nil
}

// Write writes to a new directory only. It cannot overwrite a saved run or
// publish report.json at the wrapper root as if it were a current result.
func (h HistoricalReplay) Write(dir string) error {
	if h.Schema != HistoricalReplaySchema || !h.HistoricalOnly || h.CurrentAdmission || len(h.files) == 0 { return ErrHistoricalAuthority }
	if len(h.Artifacts) != len(h.files) { return fmt.Errorf("historical replay: modified artifact manifest") }
	seen := make(map[string]bool, len(h.Artifacts))
	for _, artifact := range h.Artifacts {
		data, ok := h.files[artifact.Path]
		sum := sha256.Sum256(data)
		if !ok || seen[artifact.Path] || artifact.SHA256 != hex.EncodeToString(sum[:]) || artifact.SizeBytes != int64(len(data)) {
			return fmt.Errorf("historical replay: modified artifact manifest")
		}
		seen[artifact.Path] = true
	}
	abs, err := filepath.Abs(dir)
	if err != nil { return err }
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil { return err }
	// If the user pointed directly through a symlinked parent, ensure it evaluates
	// to a concrete directory and remains isolated from the saved run.
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() { return fmt.Errorf("historical replay: invalid output parent") }
	abs = filepath.Join(parent, filepath.Base(abs))
	if abs == h.source || strings.HasPrefix(abs, h.source+string(os.PathSeparator)) { return fmt.Errorf("historical replay: output overlaps saved run") }
	if err := os.Mkdir(abs, 0o700); err != nil { return err }
	if err := h.copyFiles(filepath.Join(abs, "original")); err != nil { return err }
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil { return err }
	return os.WriteFile(filepath.Join(abs, "historical-replay.json"), append(b, '\n'), 0o600)
}
