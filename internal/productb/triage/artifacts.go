package triage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/flock"
	"github.com/fedorovmv/izyan/internal/llm"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

// secretPatterns is the redaction allowlist applied to free-form error text
// before it lands in error.json or a partial raw-agent.json: the artifact
// must never carry a credential the failure happened to echo. The list is
// intentionally conservative — fixed-format API tokens and standard
// env-var spellings only — so diagnostic context survives the redaction.
var secretPatterns = []*regexp.Regexp{
	// Bearer/Authorization headers
	regexp.MustCompile(`(?i)(authorization|bearer)\s*[:=]\s*\S+`),
	// Well-known API-key formats
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	// Generic secret-carrying env vars or KEY=value pairs
	regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*\S+`),
	// OpenAI/Anthropic project keys
	regexp.MustCompile(`\bsk-(proj|ant)-[A-Za-z0-9_-]{20,}\b`),
}

// redactSecrets replaces every credential-shaped token in s with a fixed
// marker. The replacement is lossy by design — the artifact keeps the
// error's structure, never the secret.
func redactSecrets(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// redactAny recursively redacts every string inside a decoded JSON value
// (map[string]any, []any, scalars). Audit, intake and materialization
// projections carry free-form reason/limitation strings nested inside
// stage projections (RefResolutionAudit.FallbackReason,
// IntakeFieldAudit.Reason, MaterializationMetadata.Limitations, event
// Intake/Materialize blocks) — only a deep walk reaches them all.
// Numbers round-trip through json.Number so 64-bit ids and digests keep
// their exact representation.
func redactAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = redactAny(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = redactAny(x)
		}
		return t
	case string:
		return redactSecrets(t)
	default:
		return t
	}
}

// redactedJSON marshals v, deep-redacts every string in the decoded
// value and re-marshals. Field names are keys, never redacted; numbers
// decode as json.Number and re-emit byte-identically, so a hash-bound
// digest field is never rewritten by the walk.
func redactedJSON(v any, pretty bool) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	decoded = redactAny(decoded)
	if pretty {
		return json.MarshalIndent(decoded, "", "  ")
	}
	return json.Marshal(decoded)
}

// writeJSONAtomicRedacted is writeJSONAtomic with the recursive
// credential pass applied to the whole document. It is the boundary for
// the audit/intake/materialization projections whose nested free-form
// fields can carry tool stderr or upstream error text verbatim.
func writeJSONAtomicRedacted(ctx context.Context, finalPath string, v any) error {
	data, err := redactedJSON(v, true)
	if err != nil {
		return fmt.Errorf("agenttriage: encode %s: %w", filepath.Base(finalPath), err)
	}
	return writeFileAtomic(ctx, finalPath, append(data, '\n'))
}

// RawAgentSchemaVersion is the schema of raw-agent.json.
const RawAgentSchemaVersion = "raw-agent.v1"

// ErrorSchemaVersion is the schema of error.json, the technical-failure
// artifact written for findings whose run never produced an assessment.
const ErrorSchemaVersion = "triage-error.v1"

// errorFileName is the failure marker every error path (WriteError and
// WriteFailure) writes inside a run directory.
const errorFileName = "error.json"

// ErrorDocument is error.json: the recorded technical failure of one
// finding. It carries the run identity plus the error text; it is never a
// semantic verdict and never substitutes for assessment.json.
type ErrorDocument struct {
	SchemaVersion string `json:"schema_version"`
	FindingID     string `json:"finding_id"`
	Error         string `json:"error"`
	Time          string `json:"time"`
}

type RunArtifacts struct {
	RootDir              string
	InputPath            string
	SnapshotPath         string
	RawAgentPath         string
	AssessmentPath       string
	MarkdownPath         string
	DecisionPath         string
	DecisionMarkdownPath string
	MaterialsPath        string
	IntakeProposalPath   string
	PromptInputPath      string
	FactGatePath         string
	ObservationPath      string
	FalsifierPath        string
	ConditionCatalogPath string
	CatalogBindingPath   string
	AuditPath            string
	RunID                string
}

type factGateDocument struct {
	SchemaVersion string         `json:"schema_version"`
	Validation    FactValidation `json:"validation"`
}

const FactGateSchemaVersion = "fact-gate.v1"

// RawAgentDocument is raw-agent.json: the preserved agent transcript plus
// run metadata. Messages are stored verbatim; the canonical assessment.json
// is a separate artifact.
type RawAgentDocument struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	FindingID     string `json:"finding_id"`
	PromptHash    string `json:"prompt_hash,omitempty"`
	ResponseHash  string `json:"response_hash,omitempty"`
	Steps         int    `json:"steps,omitempty"`
	ToolCalls     int    `json:"tool_calls,omitempty"`
	// Partial marks a transcript of a run that died before the final
	// assessment; Error and ErrorClass record why it stopped.
	Partial    bool   `json:"partial,omitempty"`
	Error      string `json:"error,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
	// FactPasses is the recorded fact-gate protocol: every report the gate
	// produced plus the structured repair feedback sent after it. Replay
	// and audit recount the bounded passes from here.
	FactPasses []FactGatePass `json:"fact_passes,omitempty"`
	// StabilityRuns preserves the verbatim transcript of every stability
	// retry executed after this primary run (spec §2.4): all attempts are
	// stored, none is ever selected as the preferred response.
	StabilityRuns []StabilityRunDocument `json:"stability_runs,omitempty"`
	Messages      []llm.ChatMessage      `json:"messages"`
}

// ArtifactWriter persists one run under <out>/<finding-id>/. Every JSON and
// Markdown file is written through a temp file in the same directory plus
// os.Rename, so a failed write never leaves a partial file under the final
// name; audit/events.jsonl is the only append-only file. It serializes the
// Assessment it is given and never rewrites agent fields — only the audit
// block (run hashes, tool/model metadata) is composed here.
type ArtifactWriter struct {
	// RunDir, when set, is the reserved directory for the current execution.
	// It prevents post-agent writers from resolving a parent or another run.
	RunDir       string
	Clock        func() time.Time
	Stdout       io.Writer
	Model        string
	ToolVersions map[string]string
	// testAfterHumanDecisionCreate, when non-nil, runs after the review
	// record name is created exclusively and before its bytes are written.
	// It lets concurrency tests hold a writer inside the collection lock.
	testAfterHumanDecisionCreate func()
	// testSyncDir overrides directory fsync; nil uses syncDir. It lets tests
	// inject a directory-sync failure without a platform-specific filesystem.
	testSyncDir func(string) error
}

// Write creates the run directory and all artifacts, then returns their
// paths. A directory already owned by a different finding ID is never
// overwritten. `run` is the PRIMARY attempt: its transcript and
// observations anchor raw-agent.json and the archive. `selected` is the
// attempt the decision package composes from (nil = primary): its
// response/det-tools identity stamps the assessment audit block so replay
// can resolve which attempt's answer the verdict depends on.
func (w ArtifactWriter) Write(
	ctx context.Context,
	outDir string,
	in FindingInput,
	manifest SnapshotManifest,
	run AgentRun,
	assessment Assessment,
	events []AuditEvent,
	selected *AgentRun,
) (RunArtifacts, error) {
	var art RunArtifacts
	if err := ctx.Err(); err != nil {
		return art, err
	}
	findingID := strings.TrimSpace(in.Finding.FindingID)
	if findingID == "" {
		return art, errors.New("agenttriage: finding_id is required")
	}
	dir := strings.TrimSpace(w.RunDir)
	var err error
	if dir == "" {
		name, nameErr := RunDirName(findingID)
		if nameErr != nil {
			return art, nameErr
		}
		dir = filepath.Join(outDir, name)
		if err = os.MkdirAll(dir, 0o755); err != nil {
			return art, fmt.Errorf("agenttriage: create run directory: %w", err)
		}
	}
	if err = claimRunDir(dir, findingID); err != nil {
		return art, err
	}
	if strings.TrimSpace(assessment.FindingID) != findingID {
		return art, fmt.Errorf("agenttriage: assessment finding_id %q does not match input finding_id %q; the writer never rewrites identity", assessment.FindingID, findingID)
	}
	art.RootDir = dir
	art.InputPath = filepath.Join(art.RootDir, "input.json")
	art.SnapshotPath = filepath.Join(art.RootDir, "snapshot.json")
	art.RawAgentPath = filepath.Join(art.RootDir, "raw-agent.json")
	art.AssessmentPath = filepath.Join(art.RootDir, "assessment.json")
	art.MarkdownPath = filepath.Join(art.RootDir, "assessment.md")
	art.DecisionPath = filepath.Join(art.RootDir, "decision.json")
	art.DecisionMarkdownPath = filepath.Join(art.RootDir, "decision.md")
	art.MaterialsPath = filepath.Join(art.RootDir, "materials.json")
	art.IntakeProposalPath = filepath.Join(art.RootDir, "intake-proposal.json")
	art.PromptInputPath = filepath.Join(art.RootDir, PromptInputArtifactName)
	art.FactGatePath = filepath.Join(art.RootDir, "fact-gate.json")
	art.ObservationPath = filepath.Join(art.RootDir, "observation-archive.json")
	art.FalsifierPath = filepath.Join(art.RootDir, "falsifier-verification.json")
	art.ConditionCatalogPath = filepath.Join(art.RootDir, "condition-catalog.json")
	art.CatalogBindingPath = filepath.Join(art.RootDir, "catalog-binding.json")
	art.AuditPath = filepath.Join(art.RootDir, "audit", "events.jsonl")
	art.RunID = newRunID(findingID, w.now())
	if err := claimRunDir(art.RootDir, findingID); err != nil {
		return art, err
	}
	if err := os.MkdirAll(filepath.Dir(art.AuditPath), 0o755); err != nil {
		return art, fmt.Errorf("agenttriage: create run directory: %w", err)
	}

	inputBytes := in.Raw
	if len(inputBytes) == 0 {
		if inputBytes, err = json.MarshalIndent(in.Finding, "", "  "); err != nil {
			return art, fmt.Errorf("agenttriage: encode input: %w", err)
		}
	}
	if err := writeFileAtomic(ctx, art.InputPath, inputBytes); err != nil {
		return art, err
	}
	if err := writeJSONAtomic(ctx, art.SnapshotPath, manifest); err != nil {
		return art, err
	}
	if err := writePromptInput(ctx, art.PromptInputPath, run.PromptInput); err != nil {
		return art, err
	}
	rawDoc := RawAgentDocument{
		SchemaVersion: RawAgentSchemaVersion,
		RunID:         art.RunID,
		FindingID:     findingID,
		PromptHash:    run.PromptHash,
		ResponseHash:  run.ResponseHash,
		Steps:         run.Steps,
		FactPasses:    run.FactPasses,
		ToolCalls:     run.ToolCalls,
		StabilityRuns: stabilityRunDocs(run.Attempts),
		Messages:      run.RawMessages,
	}
	if err := writeJSONAtomic(ctx, art.RawAgentPath, rawDoc); err != nil {
		return art, err
	}
	var observations []RecordedObservation
	observations = append(observations, run.Observations...)
	for _, attempt := range run.Attempts {
		observations = append(observations, attempt.Observations...)
	}
	if err := WriteObservationArchive(ctx, art.ObservationPath, observationSliceStore{items: observations}); err != nil {
		return art, err
	}

	composed := assessment
	composed.SchemaVersion = AssessmentSchemaVersion
	composed.FindingID = findingID
	composed.VerdictSource = "agent"
	inputHash := in.SHA256
	if inputHash == "" && len(in.Raw) > 0 {
		inputHash = hashBytes(in.Raw)
	}
	// Audit pins the SELECTED attempt's identity (response/det-tools) while
	// the transcript stays the primary run's — replay resolves the canonical
	// attempt from these hashes.
	sel := run
	if selected != nil {
		sel = *selected
	}
	composed.Audit = &AssessmentAudit{
		FindingHash:  inputHash,
		SnapshotHash: manifest.ContentHash,
		PromptHash:   sel.PromptHash,
		ResponseHash: sel.ResponseHash,
		Model:        w.Model,
		ToolVersions: w.ToolVersions,
		DetTools:     sel.DetTools,
	}
	composed.Audit.AssessmentHash = canonicalAssessmentHash(composed)
	if err := writeJSONAtomic(ctx, art.AssessmentPath, composed); err != nil {
		return art, err
	}
	if composed.FactValidationDetail != nil {
		if err := writeJSONAtomic(ctx, art.FactGatePath, factGateDocument{SchemaVersion: FactGateSchemaVersion, Validation: *composed.FactValidationDetail}); err != nil {
			return art, err
		}
	}
	if err := writeFileAtomic(ctx, art.MarkdownPath, renderMarkdown(composed, w.now().UTC())); err != nil {
		return art, err
	}

	stamp := w.now().UTC()
	record := append(make([]AuditEvent, 0, len(events)+1), events...)
	record = append(record, AuditEvent{
		Type:      AuditEventArtifactsWritten,
		Timestamp: stamp,
		RunID:     art.RunID,
		Status:    "ok",
		Hash:      composed.Audit.AssessmentHash,
	})
	if err := appendAuditLog(ctx, art.AuditPath, record, art.RunID, stamp); err != nil {
		return art, err
	}
	// investigation artifacts (assessment.json/assessment.md) are not the
	// completed result: the human action package is persisted by
	// WriteDecision, which is what announces the primary result. Printing
	// here would announce success before composition, the final gate and
	// the decision write have run.
	return art, nil
}

// WriteFalsifierReport atomically persists the deterministic verifier report.
// The file is the package's proof sidecar: a package that cites a falsifier
// hash must find exactly this report next to it.
func (w ArtifactWriter) WriteFalsifierReport(ctx context.Context, runDir string, report FalsifierReport) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if report.Hash == "" || report.Hash != reportHash(report) {
		return errors.New("agenttriage: falsifier report hash does not match its content")
	}
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return errors.New("agenttriage: falsifier report: empty finding run directory")
	}
	if stat, err := os.Stat(filepath.Join(dir, "assessment.json")); err != nil || stat.IsDir() {
		return fmt.Errorf("agenttriage: falsifier report: %s is not a finding run directory", dir)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(ctx, filepath.Join(dir, "falsifier-verification.json"), append(data, '\n'))

}

// WriteConditionCatalog persists the run's condition-catalog pair:
// condition-catalog.json (the admission catalog the run bound to, when
// one was supplied) and catalog-binding.json (the run-side binding the
// catalog was checked against). The binding document is always written —
// with or without a catalog — because replay and audit need the exact
// advisory/case/hash identity the run enforced; a run that admitted
// proposals against a catalog it never persisted could never be
// re-verified. Missing or stale catalog state therefore replays closed:
// the binding fails CheckCatalog and every proposal is non-admitted.
func (w ArtifactWriter) WriteConditionCatalog(ctx context.Context, runDir string, catalog *ConditionCatalog, binding CatalogBinding) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return errors.New("agenttriage: condition catalog: empty finding run directory")
	}
	if stat, err := os.Stat(filepath.Join(dir, "assessment.json")); err != nil || stat.IsDir() {
		return fmt.Errorf("agenttriage: condition catalog: %s is not a finding run directory", dir)
	}
	if catalog != nil {
		data, err := json.MarshalIndent(catalog, "", "  ")
		if err != nil {
			return err
		}
		if err := writeFileAtomic(ctx, filepath.Join(dir, "condition-catalog.json"), append(data, '\n')); err != nil {
			return err
		}
	}
	doc := binding.Document(catalog != nil)
	return writeJSONAtomic(ctx, filepath.Join(dir, "catalog-binding.json"), doc)
}

// verifyFalsifierBinding checks the package's proof block against the
// persisted report: same proofs, same report hash, same snapshot and
// ruleset identity, and no proof from another run.
func verifyFalsifierBinding(outDir string, pkg DecisionPackage) error {
	dir := strings.TrimSpace(outDir)
	if dir == "" {
		return errors.New("agenttriage: decision: empty finding run directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "assessment.json")); errors.Is(err, os.ErrNotExist) {
		name, nameErr := RunDirName(pkg.FindingID)
		if nameErr != nil {
			return nameErr
		}
		dir = filepath.Join(dir, name)
	}
	if stat, err := os.Stat(filepath.Join(dir, "assessment.json")); err != nil || stat.IsDir() {
		return fmt.Errorf("agenttriage: decision: %s is not a finding run directory", dir)
	}
	path := filepath.Join(dir, "falsifier-verification.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if pkg.Audit.FalsifierHash != "" || len(pkg.FalsifierProofs) > 0 {
				return fmt.Errorf("agenttriage: decision: falsifier-verification.json is required for a proof-bearing package")
			}
			return nil
		}
		return err
	}
	var report FalsifierReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		return fmt.Errorf("agenttriage: decision: falsifier-verification.json does not parse: %w", err)
	}
	if report.SchemaVersion != FalsifierVerificationSchemaVersion {
		return fmt.Errorf("agenttriage: decision: falsifier report schema %q is not %s", report.SchemaVersion, FalsifierVerificationSchemaVersion)
	}
	if report.Hash == "" || report.Hash != reportHash(report) {
		return fmt.Errorf("agenttriage: decision: falsifier report hash does not match its content")
	}
	if pkg.Audit.FalsifierHash != report.Hash {
		return fmt.Errorf("agenttriage: decision: falsifier hash does not match the persisted report")
	}
	if len(pkg.FalsifierProofs) != len(report.Proofs) {
		return fmt.Errorf("agenttriage: decision: package proofs do not match the persisted report")
	}
	for i := range report.Proofs {
		want, got := report.Proofs[i], pkg.FalsifierProofs[i]
		if want.ID != got.ID || want.Status != got.Status || want.Basis != got.Basis || want.ConditionID != got.ConditionID {
			return fmt.Errorf("agenttriage: decision: proof %s does not match the persisted report", got.ID)
		}
		if want.Status == FalsifierVerified {
			if got.Coverage.SnapshotHash != pkg.Audit.SnapshotHash {
				return fmt.Errorf("agenttriage: decision: proof %s is bound to another snapshot", got.ID)
			}
			if want.Coverage.BuildContextHash == "" {
				return fmt.Errorf("agenttriage: decision: proof %s carries no build-context binding", got.ID)
			}
		}
	}
	if report.RuleSetHash != "" && pkg.Audit.RulesetHash != "" && report.RuleSetHash != pkg.Audit.RulesetHash {
		return fmt.Errorf("agenttriage: decision: falsifier report ruleset does not match the package ruleset")
	}
	return nil
}

// WriteDecision atomically persists the canonical decision-package.v3 and
// Markdown action card into the existing finding run. On success it prints
// the one primary-result line: finding, proposed action, derived support,
// machine disposition and the human card path. A failed write prints
// nothing, so a later failure can never follow a successful announcement.
func (w ArtifactWriter) WriteDecision(ctx context.Context, outDir string, pkg DecisionPackage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(w.RunDir) != "" {
		outDir = w.RunDir
	}
	if pkg.SchemaVersion != DecisionPackageSchemaVersion {
		return fmt.Errorf("agenttriage: decision package: %w", unsupportedLiveSchema("decision.json", pkg.SchemaVersion, DecisionPackageSchemaVersion))
	}
	if err := verifyFalsifierBinding(outDir, pkg); err != nil {
		return err
	}
	if err := pkg.Validate(); err != nil {
		return fmt.Errorf("agenttriage: decision package: %w", err)
	}
	dir := strings.TrimSpace(outDir)
	if _, statErr := os.Stat(filepath.Join(dir, "assessment.json")); errors.Is(statErr, os.ErrNotExist) {
		name, nameErr := RunDirName(pkg.FindingID)
		if nameErr != nil {
			return nameErr
		}
		dir = filepath.Join(dir, name)
	}
	assessmentBytes, err := os.ReadFile(filepath.Join(dir, "assessment.json"))
	if err != nil {
		return fmt.Errorf("agenttriage: decision: assessment.json is required: %w", err)
	}
	var assessment Assessment
	if err := json.Unmarshal(assessmentBytes, &assessment); err != nil {
		return fmt.Errorf("agenttriage: decision: assessment.json does not parse: %w", err)
	}
	if assessment.FindingID != pkg.FindingID || assessment.Audit == nil {
		return fmt.Errorf("agenttriage: decision: assessment identity/audit does not match finding %q", pkg.FindingID)
	}
	inputBytes, err := os.ReadFile(filepath.Join(dir, "input.json"))
	if err != nil {
		return fmt.Errorf("agenttriage: decision: input.json is required: %w", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return fmt.Errorf("agenttriage: decision: snapshot.json is required: %w", err)
	}
	var manifestIdentity struct {
		ContentHash string `json:"content_hash"`
	}
	if err := json.Unmarshal(manifestBytes, &manifestIdentity); err != nil {
		return fmt.Errorf("agenttriage: decision: snapshot.json does not parse: %w", err)
	}
	inputHash := hashBytes(inputBytes)
	if pkg.Audit.SnapshotHash != manifestIdentity.ContentHash || assessment.Audit.SnapshotHash != manifestIdentity.ContentHash {
		return fmt.Errorf("agenttriage: decision: snapshot hash does not match snapshot.json")
	}
	if pkg.Audit.PromptHash != "" && pkg.Audit.PromptHash != assessment.Audit.PromptHash {
		return fmt.Errorf("agenttriage: decision: prompt hash does not match assessment audit")
	}
	if pkg.Audit.Stage0.InputHash != "" && pkg.Audit.Stage0.InputHash != inputHash {
		return fmt.Errorf("agenttriage: decision: stage0 input hash does not match input.json")
	}
	decisionPath := filepath.Join(dir, "decision.json")
	decisionMDPath := filepath.Join(dir, "decision.md")
	auditPath := filepath.Join(dir, "audit", "events.jsonl")
	oldJSON, oldJSONErr := os.ReadFile(decisionPath)
	oldMD, oldMDErr := os.ReadFile(decisionMDPath)
	oldAudit, oldAuditErr := os.ReadFile(auditPath)
	restore := func() {
		if oldJSONErr == nil {
			_ = os.WriteFile(decisionPath, oldJSON, 0o644)
		} else if errors.Is(oldJSONErr, os.ErrNotExist) {
			_ = os.Remove(decisionPath)
		}
		if oldMDErr == nil {
			_ = os.WriteFile(decisionMDPath, oldMD, 0o644)
		} else if errors.Is(oldMDErr, os.ErrNotExist) {
			_ = os.Remove(decisionMDPath)
		}
		if oldAuditErr == nil {
			_ = os.WriteFile(auditPath, oldAudit, 0o644)
		} else if errors.Is(oldAuditErr, os.ErrNotExist) {
			_ = os.Remove(auditPath)
		}
	}
	if err := writeJSONAtomic(ctx, decisionPath, pkg); err != nil {
		restore()
		return err
	}
	if err := writeFileAtomic(ctx, decisionMDPath, RenderDecisionMarkdown(pkg)); err != nil {
		restore()
		return err
	}
	stamp := w.now().UTC()
	if err := appendAuditLog(ctx, auditPath, []AuditEvent{DecisionAuditEvent(pkg, pkg.RunID, stamp)}, pkg.RunID, stamp); err != nil {
		restore()
		return err
	}
	if w.Stdout != nil {
		readiness := ""
		if pkg.HumanReviewPlan != nil { readiness = " readiness=" + pkg.HumanReviewPlan.Readiness }
		fmt.Fprintf(w.Stdout, "triage %s action=%s support=%s machine=%s%s decision=%s\n",
			pkg.FindingID, orDash(string(pkg.ProposedAction.Kind)), orDash(string(pkg.Support.Level)),
			orDash(string(pkg.MachineDisposition.Recommendation)), readiness, decisionMDPath)
	}
	return nil
}
func CanonicalDecisionHash(p DecisionPackage) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return hashBytes(b)
}
func canonicalDecisionHash(p DecisionPackage) string {
	return CanonicalDecisionHash(p)
}

// loadCurrentDecisionPackage reads and strictly validates decision.json from
// one run directory. The live pipeline consumes only decision-package.v3:
// a superseded package is history-only and is never re-admitted as a
// current human result.
func loadCurrentDecisionPackage(runDir string) (DecisionPackage, error) {
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return DecisionPackage{}, errors.New("empty run directory")
	}
	data, err := os.ReadFile(filepath.Join(dir, "decision.json"))
	if err != nil {
		return DecisionPackage{}, fmt.Errorf("decision.json is required: %w", err)
	}
	var head struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return DecisionPackage{}, fmt.Errorf("decision.json does not parse: %w", err)
	}
	if head.SchemaVersion != DecisionPackageSchemaVersion {
		return DecisionPackage{}, unsupportedLiveSchema("decision.json", head.SchemaVersion, DecisionPackageSchemaVersion)
	}
	pkg, err := ValidateDecisionPackageJSON(data)
	if err != nil {
		return DecisionPackage{}, fmt.Errorf("decision.json is invalid: %w", err)
	}
	return pkg, nil
}

// WriteStability atomically persists the completed retry report as
// stability.json inside the finding's run directory and appends the
// stability audit events — one per recorded attempt plus the summary —
// under the run that produced them. The run directory must already exist
// (the artifacts or failure path created it); the report itself is
// written verbatim, so a replay recomposes the identical outcome.
func (w ArtifactWriter) WriteStability(ctx context.Context, runDir, findingID, runID string, report StabilityReport) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return errors.New("agenttriage: stability: empty finding run directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "assessment.json")); err != nil {
		return fmt.Errorf("agenttriage: stability: %s is not a finding run directory: %w", dir, err)
	}
	doc := StabilityDocument{
		SchemaVersion:   StabilitySchemaVersion,
		RunID:           runID,
		FindingID:       findingID,
		StabilityReport: report,
	}
	if err := writeJSONAtomic(ctx, filepath.Join(dir, "stability.json"), doc); err != nil {
		return err
	}
	stamp := w.now().UTC()
	return appendAuditLog(ctx, filepath.Join(dir, "audit", "events.jsonl"),
		StabilityAuditEvents(report, runID, stamp), runID, stamp)

}

// stabilityRunDocs projects the recorded retry runs into their
// raw-agent.json representation, preserving attempt order.
func stabilityRunDocs(attempts []AgentRun) []StabilityRunDocument {
	if len(attempts) == 0 {
		return nil
	}
	out := make([]StabilityRunDocument, len(attempts))
	for i, run := range attempts {
		out[i] = stabilityRunDocument(i+2, run)
	}
	return out
}

func (w ArtifactWriter) now() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now()
}

// reserveRunDir selects one unclaimed execution directory. The first run keeps
// the historical finding directory name; once a run has completed or failed,
// subsequent executions receive deterministic -run-N siblings. A Stage 0
// directory without a terminal artifact is reused by the same execution.
func reserveRunDir(outDir, findingID string) (string, error) {
	name, err := RunDirName(findingID)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(outDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("agenttriage: create run directory: %w", err)
	}
	if err := claimRunDir(dir, findingID); err != nil {
		return "", err
	}
	return dir, nil

}

// ReserveRunDir reserves one isolated run directory for a finding.
func ReserveRunDir(outDir, findingID string) (string, error) {
	return reserveRunDir(outDir, findingID)
}

// claimRunDir refuses to reuse a run directory whose recorded ownership
// belongs to a different finding ID, so a later run — successful or failed —
// can never clobber or mix into another finding's artifacts. The claim is
// atomic across processes: it runs under an flock on `.owner.lock`, then
// checks/pins the persistent `.owner` marker (O_EXCL). Directories claimed
// before the marker existed still fall back to the legacy input.json /
// error.json ownership scan.
func claimRunDir(dir, findingID string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("agenttriage: create run directory: %w", err)
	}
	// Serialize the check+pin across processes for the lifetime of the call
	// — the shared flock primitive (flock on Unix, LockFileEx on Windows).
	unlock, err := flock.Exclusive(filepath.Join(dir, ".owner.lock"), 0o600)
	if err != nil {
		return fmt.Errorf("agenttriage: lock run directory: %w", err)
	}
	defer unlock()
	ownerPath := filepath.Join(dir, ".owner")
	if data, err := os.ReadFile(ownerPath); err == nil {
		if owner := strings.TrimSpace(string(data)); owner != "" && owner != findingID {
			return fmt.Errorf("agenttriage: run directory already belongs to finding %q", owner)
		}
		return nil // same owner re-claiming
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("agenttriage: inspect owner marker: %w", err)
	}

	// Legacy markers (runs recorded before .owner existed).
	for _, marker := range []string{"input.json", errorFileName} {
		data, err := os.ReadFile(filepath.Join(dir, marker))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("agenttriage: inspect existing run directory: %w", err)
		}
		var prev struct {
			FindingID string `json:"finding_id"`
			Finding   struct {
				FindingID string `json:"finding_id"`
			} `json:"finding"`
		}
		if json.Unmarshal(data, &prev) != nil {
			continue
		}
		owner := prev.FindingID
		if owner == "" {
			owner = prev.Finding.FindingID
		}
		if owner != "" && owner != findingID {
			return fmt.Errorf("agenttriage: run directory already belongs to finding %q", owner)
		}
	}

	// Pin the owner atomically; a loser of the O_EXCL race re-reads and
	// accepts only if the winner recorded the same finding.
	f, err := os.OpenFile(ownerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if data, rerr := os.ReadFile(ownerPath); rerr == nil && strings.TrimSpace(string(data)) == findingID {
				return nil
			}
			return fmt.Errorf("agenttriage: run directory was just claimed by another process")
		}
		return fmt.Errorf("agenttriage: pin run-dir owner: %w", err)
	}
	if _, err := f.WriteString(findingID + "\n"); err != nil {
		f.Close()
		return fmt.Errorf("agenttriage: pin run-dir owner: %w", err)
	}
	f.Close()
	return nil
}

// WriteError records a finding's technical failure as <out>/<dir>/error.json.
// It shares the run-directory naming and ownership contract with Write: the
// directory comes from RunDirName and a foreign owner's directory is never
// written into. The artifact is atomic (temp file + rename) and idempotent
// for the same finding.
func (w ArtifactWriter) WriteError(ctx context.Context, outDir string, in FindingInput, runErr error) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	findingID := strings.TrimSpace(in.Finding.FindingID)
	dir := strings.TrimSpace(w.RunDir)
	var err error
	if dir == "" {
		name, nameErr := RunDirName(findingID)
		if nameErr != nil {
			return "", nameErr
		}
		dir = filepath.Join(outDir, name)
		if err = os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("agenttriage: create run directory: %w", err)
		}
	}
	if err = claimRunDir(dir, findingID); err != nil {
		return "", err
	}
	path := filepath.Join(dir, errorFileName)
	if _, statErr := os.Stat(filepath.Join(dir, "decision.json")); statErr == nil {
		for n := 1; ; n++ {
			candidate := filepath.Join(dir, fmt.Sprintf("error-rerun-%d.json", n))
			if _, candidateErr := os.Stat(candidate); errors.Is(candidateErr, os.ErrNotExist) {
				path = candidate
				break
			}
		}
	}
	doc := ErrorDocument{SchemaVersion: ErrorSchemaVersion, FindingID: findingID, Error: redactSecrets(runErr.Error()), Time: w.now().UTC().Format(time.RFC3339Nano)}
	if err := writeJSONAtomic(ctx, path, doc); err != nil {
		return "", err
	}
	return path, nil
}

// WriteFailure records a finding's technical failure: error.json through the
// shared naming/ownership contract plus, when the agent run produced any
// state, a partial raw-agent.json (partial: true, error and error_class) and
// the audit events accumulated before the failure. It never writes an
// assessment and never substitutes for one.
func (w ArtifactWriter) WriteFailure(
	ctx context.Context,
	outDir string,
	in FindingInput,
	run AgentRun,
	runErr error,
	events []AuditEvent,
) (string, error) {
	errPath, err := w.WriteError(ctx, outDir, in, runErr)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(errPath)
	findingID := strings.TrimSpace(in.Finding.FindingID)
	runID := newRunID(findingID, w.now())
	// A caller that carries no run data must never replace a richer failure
	// record written by an inner stage, and no later failure may demote a
	// completed transcript back to partial: the run produced an assessment
	// and its record stays final — the post-agent error lives in
	// error.json and the audit trail instead.
	skipRaw := false
	if existing := readRawAgentDoc(dir); existing != nil {
		if !existing.Partial {
			skipRaw = true
		} else if isEmptyRun(run) {
			return errPath, nil
		}
	}
	if !skipRaw {
		if err := writePromptInput(ctx, filepath.Join(dir, PromptInputArtifactName), run.PromptInput); err != nil {
			return "", err
		}
		doc := RawAgentDocument{
			SchemaVersion: RawAgentSchemaVersion,
			RunID:         runID,
			FindingID:     findingID,
			PromptHash:    run.PromptHash,
			ResponseHash:  run.ResponseHash,
			Steps:         run.Steps,
			ToolCalls:     run.ToolCalls,
			Partial:       true,
			Error:         redactSecrets(runErr.Error()),
			ErrorClass:    run.ErrorClass,
			FactPasses:    run.FactPasses,
			StabilityRuns: stabilityRunDocs(run.Attempts),
			Messages:      run.RawMessages,
		}
		if err := writeJSONAtomic(ctx, filepath.Join(dir, "raw-agent.json"), doc); err != nil {
			return "", err
		}
	}
	auditPath := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o755); err != nil {
		return "", fmt.Errorf("agenttriage: create run directory: %w", err)
	}
	if len(events) == 0 {
		events = []AuditEvent{{Type: AuditEventError, Status: "error", Scope: run.ErrorClass, Limitations: []string{shortErr(runErr.Error())}}}
	}
	if err := appendAuditLog(ctx, auditPath, events, runID, w.now().UTC()); err != nil {
		return "", err
	}
	return errPath, nil
}

// intakeRecordDoc is intake.json: the verbatim Stage 0 transport record plus
// its identity. The raw bytes are preserved unmodified — the ticket_hash
// recomputes over exactly them at replay/audit time.
type intakeRecordDoc struct {
	SchemaVersion string       `json:"schema_version"`
	TicketHash    string       `json:"ticket_hash"`
	Format        IntakeFormat `json:"format"`
	RecordIndex   int          `json:"record_index"`
	Raw           string       `json:"raw"`
}

type stage0Document struct {
	SchemaVersion        string                       `json:"schema_version"`
	FindingID            string                       `json:"finding_id"`
	ConfigHash           string                       `json:"config_hash"`
	CatalogEntry         CatalogEntry                 `json:"catalog_entry"`
	RefResolution        RefResolution                `json:"ref_resolution"`
	CandidateRefs        []RefCandidate               `json:"candidate_refs,omitempty"`
	SelectedRef          RefCandidate                 `json:"selected_ref"`
	Materialization      MaterializationMetadata      `json:"materialization"`
	Advisory             vulnerability.FrozenAdvisory `json:"advisory"`
	ResolutionVuln       *domain.Vulnerability        `json:"resolution_vulnerability,omitempty"`
	ResolutionProjection AdvisoryProjection           `json:"resolution_projection,omitempty"`
	ReleaseToolchain     ReleaseToolchainFact         `json:"release_toolchain"`
	Toolchain            toolchain.Toolchain          `json:"toolchain"`
	PackageCheck         PackageCheckResult           `json:"package_check"`
	Validation           IntakeValidation             `json:"validation"`
	// Investigation is the metadata projection of every captured advisory
	// record/fix the run actually considered (manifest-supplied plus the
	// Stage 0 selected frozen document). Complete bytes live under
	// materials/<sha256>; replay rebuilds the record scope from here.
	Investigation *InvestigationProjection `json:"investigation,omitempty"`
	// BuildTarget is the single product build selection this resolution
	// identified; absent means no product target was supplied.
	BuildTarget *domain.ProductTarget `json:"build_target,omitempty"`
	Limitations []string              `json:"limitations,omitempty"`
}

// domain is used only for the persisted advisory projection in stage0.json.

// stage0RunDir locates (creating when needed) the run directory of the
// finding Stage 0 produced or the record-derived id when resolution died
// before normalization. Ownership is enforced through claimRunDir exactly
// like Write/WriteError.
func stage0RunDir(outDir string, res Stage0Result) (dir, findingID string, err error) {
	findingID = strings.TrimSpace(res.Input.Finding.FindingID)
	if findingID == "" {
		findingID = IntakeFindingID(res.Raw)
	}
	name, nameErr := RunDirName(findingID)
	if nameErr != nil {
		return "", findingID, nameErr
	}
	dir = filepath.Join(outDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", findingID, fmt.Errorf("agenttriage: create run directory: %w", err)
	}
	if err := claimRunDir(dir, findingID); err != nil {
		return "", findingID, err
	}
	return dir, findingID, nil
}

// writeStage0Files persists the Stage 0 artifact set into dir: the verbatim
// intake record, the LLM intake proposal (when extraction completed), the
// snapshot manifest with materialization metadata, the collected material
// set and the stage0.json resolution summary with the config hash.
func writeStage0Files(ctx context.Context, dir string, res Stage0Result, findingID string) error {
	rec := intakeRecordDoc{
		SchemaVersion: IntakeRecordSchemaVersion,
		TicketHash:    res.Raw.TicketHash,
		Format:        res.Raw.Format,
		RecordIndex:   res.Raw.RecordIndex,
		Raw:           string(res.Raw.Raw),
	}
	if err := writeJSONAtomic(ctx, filepath.Join(dir, "intake.json"), rec); err != nil {
		return err
	}
	if res.Proposal.SchemaVersion != "" {
		if err := writeJSONAtomic(ctx, filepath.Join(dir, "intake-proposal.json"), res.Proposal); err != nil {
			return err
		}
	}
	if res.Snapshot.SchemaVersion != "" {
		// snapshot.json carries MaterializationMetadata verbatim — its
		// nested limitations are free-form error text, so the whole
		// manifest goes through the recursive credential pass.
		if err := writeJSONAtomicRedacted(ctx, filepath.Join(dir, "snapshot.json"), res.Snapshot); err != nil {
			return err
		}
	}
	if res.Materials.Materials != nil {
		// Materials carry tool stderr inside nested limitation strings;
		// the recursive pass covers every free-form field, not just the
		// top-level list.
		if err := writeJSONAtomicRedacted(ctx, filepath.Join(dir, "materials.json"), res.Materials); err != nil {
			return err
		}
	}
	if err := writeInvestigationArtifacts(ctx, dir, res.Investigation); err != nil {
		return err
	}
	// res.Limitations aggregates error-derived strings from every stage-0
	// sub-step; nested stage projections (ref fallback reasons, validation
	// field reasons, materialization metadata) can carry the same text,
	// so stage0.json goes through the recursive pass rather than a
	// top-level limitation scrub.
	doc := stage0Document{
		SchemaVersion:   Stage0DocumentSchemaVersion,
		FindingID:       findingID,
		ConfigHash:      res.ConfigHash,
		CatalogEntry:    res.CatalogEntry,
		RefResolution:   res.RefResolution,
		CandidateRefs:   res.CandidateRefs,
		SelectedRef:     res.SelectedRef,
		Materialization: res.Source.Metadata,
		Advisory:        res.Advisory,
		ResolutionVuln: func() *domain.Vulnerability {
			if res.Resolution != nil {
				return res.Resolution.Vulnerability
			}
			return nil
		}(),
		ResolutionProjection: func() AdvisoryProjection {
			if res.Resolution != nil {
				return res.Resolution.Projection
			}
			return AdvisoryProjection{}
		}(),
		ReleaseToolchain: res.ReleaseToolchain,
		Toolchain:        res.Toolchain,
		PackageCheck:     res.PackageCheck,
		Validation:       res.Validation,
		Investigation:    investigationProjectionPtr(res.Investigation),
		BuildTarget:      cloneBuildTarget(res.BuildTarget),
		Limitations:      res.Limitations,
	}
	return writeJSONAtomicRedacted(ctx, filepath.Join(dir, "stage0.json"), doc)
}

// WriteStage0Artifacts persists the Stage 0 resolution of one ticket into
// its run directory before the bounded agent run starts: intake.json keeps
// the verbatim record and its hash, input.json the normalized finding, plus
// intake-proposal.json, snapshot.json (materialization metadata included),
// materials.json and stage0.json (frozen advisory identity + config hash).
// The same files land for a later successful or failed run — Stage 0 output
// is part of the run's provenance either way.
func (w ArtifactWriter) WriteStage0Artifacts(ctx context.Context, outDir string, res Stage0Result) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	findingID := strings.TrimSpace(res.Input.Finding.FindingID)
	if findingID == "" {
		findingID = IntakeFindingID(res.Raw)
	}
	dir := strings.TrimSpace(w.RunDir)
	var err error
	if dir == "" {
		dir, findingID, err = stage0RunDir(outDir, res)
		if err != nil {
			return "", err
		}
	}
	if err := writeStage0Files(ctx, dir, res, findingID); err != nil {
		return "", err
	}
	// input.json is the ownership marker Write/WriteError claim on; write
	// the normalized finding bytes so a rerun never mixes identities.
	inputBytes := res.Input.Raw
	if len(inputBytes) == 0 && res.Input.Finding.FindingID != "" {
		if inputBytes, err = json.MarshalIndent(res.Input.Finding, "", "  "); err != nil {
			return "", fmt.Errorf("agenttriage: encode input: %w", err)
		}
	}
	if len(inputBytes) > 0 {
		if err := writeFileAtomic(ctx, filepath.Join(dir, "input.json"), inputBytes); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// WriteStage0Failure records a Stage 0 technical failure: error.json through
// WriteError plus the raw intake record (intake.json), any accumulated
// Stage 0 artifacts, the partial Stage 0 LLM transcript as raw-agent.json
// (partial:true) and the Stage 0 audit events terminating in an error
// event. No assessment or decision files are ever written here.
func (w ArtifactWriter) WriteStage0Failure(ctx context.Context, outDir string, res Stage0Result, runErr error) (string, error) {
	in := res.Input
	if strings.TrimSpace(in.Finding.FindingID) == "" {
		in.Finding.FindingID = IntakeFindingID(res.Raw)
	}
	errPath, err := w.WriteError(ctx, outDir, in, runErr)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(errPath)
	findingID := in.Finding.FindingID
	if err := writeStage0Files(ctx, dir, res, findingID); err != nil {
		return "", err
	}
	runID := newRunID(findingID, w.now())
	doc := RawAgentDocument{SchemaVersion: RawAgentSchemaVersion, RunID: runID, FindingID: findingID, Partial: true, Error: redactSecrets(runErr.Error()), ErrorClass: "stage0", Messages: res.Transcript}
	if err := writeJSONAtomic(ctx, filepath.Join(dir, "raw-agent.json"), doc); err != nil {
		return "", err
	}
	auditPath := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o755); err != nil {
		return "", fmt.Errorf("agenttriage: create run directory: %w", err)
	}
	events := res.Events
	if len(events) == 0 {
		events = []AuditEvent{{Type: AuditEventError, Status: "error", Scope: "stage0", Limitations: []string{shortErr(runErr.Error())}}}
	}
	if err := appendAuditLog(ctx, auditPath, events, runID, w.now().UTC()); err != nil {
		return "", err
	}
	return errPath, nil
}

// RunDirName maps a finding ID onto its per-finding output directory name.
// Write and WriteError share it, so successful and failed runs of the same
// finding land in one directory. Bytes outside [A-Za-z0-9._-] are
// percent-encoded ('/' → %2f, '%' itself → %25, UTF-8 per byte): the
// mapping is injective — distinct finding IDs can never alias onto one
// directory name, and decoding the name recovers the exact ID.
// claimRunDir remains the backstop for hostile IDs.
func RunDirName(findingID string) (string, error) {
	var b strings.Builder
	for i := range len(findingID) {
		c := findingID[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	name := b.String()
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("agenttriage: finding_id %q produces no usable directory name", findingID)
	}
	return name, nil
}

func newRunID(findingID string, ts time.Time) string {
	var randBuf [4]byte
	if _, err := rand.Read(randBuf[:]); err != nil {
		return fmt.Sprintf("%s@%s", findingID, ts.UTC().Format("20060102T150405.000000000Z"))
	}
	return fmt.Sprintf("%s@%s-%s", findingID, ts.UTC().Format("20060102T150405.000000000Z"), hex.EncodeToString(randBuf[:]))
}

// WritePromptInput persists prompt-input.v1 into dir before the first
// investigator exchange. It is the runner's prompt-sink target.
func (w ArtifactWriter) WritePromptInput(ctx context.Context, dir string, pi PromptInput) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("agenttriage: prompt input directory is empty")
	}
	return writePromptInput(ctx, filepath.Join(dir, PromptInputArtifactName), pi)
}

// writePromptInput persists prompt-input.v1 when the caller carried one.
// A run that never built a prompt (an inner-stage failure before the agent
// loop) has nothing to persist; the artifact is not invented.
func writePromptInput(ctx context.Context, finalPath string, pi PromptInput) error {
	if pi.SchemaVersion == "" && pi.PromptHash == "" && pi.System == "" && len(pi.Messages) == 0 {
		return nil
	}
	if err := pi.Validate(); err != nil {
		return fmt.Errorf("agenttriage: prompt input: %w", err)
	}
	return writeJSONAtomic(ctx, finalPath, pi)
}

// writeFileAtomic writes data to a temp file inside dir of finalPath and
// renames it over finalPath, so readers never see a partial file. On any
// error the temp file is removed and finalPath is left untouched.
func writeFileAtomic(ctx context.Context, finalPath string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return fmt.Errorf("agenttriage: create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(finalPath), "."+filepath.Base(finalPath)+".*.tmp")
	if err != nil {
		return fmt.Errorf("agenttriage: create temp file for %s: %w", filepath.Base(finalPath), err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("agenttriage: write %s: %w", filepath.Base(finalPath), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("agenttriage: sync %s: %w", filepath.Base(finalPath), err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("agenttriage: close %s: %w", filepath.Base(finalPath), err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("agenttriage: commit %s: %w", filepath.Base(finalPath), err)
	}
	return nil
}

func writeJSONAtomic(ctx context.Context, finalPath string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("agenttriage: encode %s: %w", filepath.Base(finalPath), err)
	}
	return writeFileAtomic(ctx, finalPath, append(data, '\n'))
}

// canonicalAssessmentHash hashes the canonical JSON encoding of the
// assessment with assessment_hash cleared. No timestamps or filesystem
// paths enter the document, so identical inputs hash identically across
// output directories.
func canonicalAssessmentHash(a Assessment) string {
	if a.Audit != nil {
		dup := *a.Audit
		dup.AssessmentHash = ""
		a.Audit = &dup
	}
	data, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return hashBytes(data)
}

// appendAuditLog appends one JSONL line per event. The file is append-only:
// a rerun of the same finding adds a new block under its own run ID instead
// of rewriting history. Missing timestamps and run IDs are stamped so every
// line carries the event contract.
func appendAuditLog(ctx context.Context, path string, events []AuditEvent, runID string, ts time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("agenttriage: open audit log: %w", err)
	}
	for _, ev := range events {
		if ev.Timestamp.IsZero() {
			ev.Timestamp = ts
		}
		ev.RunID = runID
		// Free-form text is nested, not only ev.Limitations: stage
		// projections inside an event (RefResolutionAudit.FallbackReason,
		// IntakeAudit reasons, MaterializationMetadata.Limitations) carry
		// the same error-derived strings, so the whole marshaled event
		// goes through the recursive credential pass before it reaches
		// audit/events.jsonl.
		line, err := redactedJSON(ev, false)
		if err != nil {
			f.Close()
			return fmt.Errorf("agenttriage: encode audit event: %w", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			f.Close()
			return fmt.Errorf("agenttriage: write audit event: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("agenttriage: close audit log: %w", err)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func renderMarkdown(a Assessment, generated time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Triage assessment: %s\n\n", a.FindingID)
	fmt.Fprintf(&b, "- **Verdict (agent):** %s\n", orDash(string(a.Verdict)))
	if a.VerdictSubtype != "" {
		fmt.Fprintf(&b, "- **Verdict subtype (agent):** %s\n", a.VerdictSubtype)
	}
	fmt.Fprintf(&b, "- **Fact validation:** %s\n", orDash(string(a.FactValidation)))
	fmt.Fprintf(&b, "- **Generated:** %s\n\n", generated.Format(time.RFC3339))
	if a.Summary != "" {
		fmt.Fprintf(&b, "## Summary\n\n%s\n\n", a.Summary)
	}
	if a.Mechanism != "" {
		fmt.Fprintf(&b, "## Mechanism\n\n%s\n\n", a.Mechanism)
	}
	b.WriteString("## Claims\n\n")
	if len(a.Claims) == 0 {
		b.WriteString("None declared.\n")
	}
	locator := func(id string) string {
		for _, ev := range a.Evidence {
			if ev.ID == id {
				return ev.Locator
			}
		}
		return ""
	}
	for _, c := range a.Claims {
		relevant := "not decision-relevant"
		if c.DecisionRelevant {
			relevant = "decision-relevant"
		}
		fmt.Fprintf(&b, "- **%s** (%s", c.ID, relevant)
		if c.Basis != "" {
			fmt.Fprintf(&b, ", %s", c.Basis)
		}
		fmt.Fprintf(&b, "): %s\n", orDash(c.Statement))
		if c.Subject != "" || c.Scope != "" {
			fmt.Fprintf(&b, "  - subject: %s; scope: %s\n", orDash(c.Subject), orDash(c.Scope))
		}
		for _, ref := range c.EvidenceRefs {
			loc := locator(ref)
			if loc != "" {
				fmt.Fprintf(&b, "  - %s: %s\n", ref, loc)
			} else {
				fmt.Fprintf(&b, "  - %s\n", ref)
			}
		}
		for _, dep := range c.DependsOn {
			fmt.Fprintf(&b, "  - depends on %s\n", dep)
		}
		if c.Binding != nil {
			fmt.Fprintf(&b, "  - binding: %s %s\n", c.Binding.Kind, c.Binding.ReferenceID)
		}
	}
	b.WriteString("\n## Evidence\n\n")
	if len(a.Evidence) == 0 {
		b.WriteString("None declared.\n")
	}
	for _, ev := range a.Evidence {
		fmt.Fprintf(&b, "- **%s**", ev.ID)
		if ev.Kind != "" {
			fmt.Fprintf(&b, " (%s)", ev.Kind)
		}
		if ev.Locator != "" {
			fmt.Fprintf(&b, ": %s", ev.Locator)
		}
		b.WriteString("\n")
		if ev.Quote != "" {
			fmt.Fprintf(&b, "  > %s\n", ev.Quote)
		}
	}
	b.WriteString("\n## Unknowns\n\n")
	if len(a.Unknowns) == 0 {
		b.WriteString("None declared.\n")
	}
	for _, u := range a.Unknowns {
		fmt.Fprintf(&b, "- %s\n", orDash(u.Description))
		if u.Reason != "" {
			fmt.Fprintf(&b, "  - reason: %s\n", u.Reason)
		}
	}
	if a.ProposedAction.Kind != "" || a.ProposedAction.Instruction != "" {
		fmt.Fprintf(&b, "\n## Proposed action\n\n")
		fmt.Fprintf(&b, "- **Kind:** %s\n", orDash(string(a.ProposedAction.Kind)))
		fmt.Fprintf(&b, "- **Scope:** %s\n", orDash(a.ProposedAction.Scope))
		fmt.Fprintf(&b, "\n%s\n\n", orDash(a.ProposedAction.Instruction))
		if a.ProposedAction.Rationale != "" {
			fmt.Fprintf(&b, "- **Rationale:** %s\n", a.ProposedAction.Rationale)
		}
		if len(a.ProposedAction.RecordIDs) > 0 {
			fmt.Fprintf(&b, "- **Records:** %s\n", strings.Join(a.ProposedAction.RecordIDs, ", "))
		}
		if len(a.ProposedAction.DecisiveClaimIDs) > 0 {
			fmt.Fprintf(&b, "- **Decisive claims:** %s\n", strings.Join(a.ProposedAction.DecisiveClaimIDs, ", "))
		}
		for _, reason := range a.ProposedAction.ReconsiderWhen {
			fmt.Fprintf(&b, "- **Reconsider when:** %s\n", reason)
		}
	}
	if d := a.FactValidationDetail; d != nil {
		b.WriteString("\n## Fact validation detail\n\n")
		if len(d.References) == 0 {
			b.WriteString("No per-reference checks recorded.\n")
		}
		for _, rc := range d.References {
			fmt.Fprintf(&b, "- **%s** — %s", orDash(rc.EvidenceID), rc.Status)
			if rc.Locator != "" {
				fmt.Fprintf(&b, " (%s)", rc.Locator)
			}
			if rc.Reason != "" {
				fmt.Fprintf(&b, ": %s", rc.Reason)
			}
			b.WriteString("\n")
		}
		for _, lim := range d.Limitations {
			fmt.Fprintf(&b, "- limitation: %s\n", lim)
		}
	}
	b.WriteString("\n## Limitations\n\n")
	b.WriteString("- This is an agent assessment: semantic correctness of the LLM explanation was not verified; only fact-level references were checked.\n")
	b.WriteString("- Absence of a reference or source is reported as a limitation, never as a negative fact.\n")
	b.WriteString("- The machine automation outcome is a property of the decision package's machine disposition (ALLOW/WARN/BLOCK), not of this assessment and not a second semantic verdict.\n")
	b.WriteString("- Technical audit trail: `audit/events.jsonl`.\n")
	return []byte(b.String())
}

// isEmptyRun reports whether the caller carries no run evidence at all.
func isEmptyRun(run AgentRun) bool {
	return len(run.RawMessages) == 0 && run.Steps == 0 && run.ToolCalls == 0 &&
		len(run.FactPasses) == 0 && len(run.Attempts) == 0 && run.PromptHash == "" &&
		run.ResponseHash == ""
}

// readRawAgentDoc reads the raw-agent document of a run directory; nil
// means there is none or it cannot be decoded — either way a write is
// free to proceed and an unreadable file is repaired rather than kept.
func readRawAgentDoc(dir string) *RawAgentDocument {
	data, err := os.ReadFile(filepath.Join(dir, "raw-agent.json"))
	if err != nil {
		return nil
	}
	var doc RawAgentDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return &doc
}
