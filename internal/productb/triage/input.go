package triage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	domain "github.com/davniy/izyan/internal/productb/domain"
)

// ResolveBuildTarget resolves the one identified product build an
// investigation describes, from the two declaration channels the captured
// inputs may carry: the finding's target.build record and the
// investigation-inputs.v1 `build` object. Both are operator/scanner data;
// neither silently upgrades analysis context into a product fact.
//
// Rules:
//   - neither channel present: the product build is unidentified (nil);
//   - one channel present: it is admitted only when the canonical
//     ProductTarget contract passes, is scoped to a product build, and — for
//     artifact-build-info facts — its artifact digest still matches a binary
//     captured in the snapshot, so measured authority stays bound to the
//     bytes it came from;
//   - both channels present: they must declare one identical selection;
//     contradictory declarations fail closed instead of one silently
//     winning.
//
// A host-default record is rejected here: the analyzer host is analysis
// context, never a product target. The go.mod language minimum and the
// analysis toolchain are deliberately not consulted.
func ResolveBuildTarget(f FindingInput, investigation InvestigationInputs, manifest SnapshotManifest) (*domain.ProductTarget, error) {
	findingTarget, err := admitBuildTarget("finding target.build", f.Finding.Target.Build, manifest)
	if err != nil {
		return nil, err
	}
	bundleTarget, err := admittedInvestigationBuild(investigation, manifest)
	if err != nil {
		return nil, err
	}
	if findingTarget != nil && bundleTarget != nil {
		if err := compareBuildTargets(*findingTarget, *bundleTarget); err != nil {
			return nil, fmt.Errorf("conflicting product build declarations: finding target.build and the investigation build input disagree: %w", err)
		}
		return findingTarget, nil
	}
	if findingTarget != nil {
		return findingTarget, nil
	}
	return bundleTarget, nil
}

// admittedInvestigationBuild decodes and admits the manifest's build object.
// The object is the canonical ProductTarget JSON; unknown fields, a missing
// source/scope or an unidentifiable build fail before any session exists.
func admittedInvestigationBuild(in InvestigationInputs, manifest SnapshotManifest) (*domain.ProductTarget, error) {
	raw := bytes.TrimSpace(in.Build)
	if len(raw) == 0 {
		return nil, nil
	}
	var target domain.ProductTarget
	if err := decodeStrictJSON(raw, &target); err != nil {
		return nil, fmt.Errorf("investigation build input: %w", err)
	}
	return admitBuildTarget("investigation build input", &target, manifest)
}

// admitBuildTarget normalizes and admits one supplied target record.
func admitBuildTarget(origin string, supplied *domain.ProductTarget, manifest SnapshotManifest) (*domain.ProductTarget, error) {
	if supplied == nil {
		return nil, nil
	}
	target := normalizeBuildTarget(*supplied)
	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	if !target.Scoped() {
		return nil, fmt.Errorf("%s declares source %q: the analyzer host is analysis context, never a product build target", origin, target.Source)
	}
	if target.Source == domain.ProductTargetSourceArtifactBuildInfo {
		bound := false
		for _, artifact := range manifest.Artifacts {
			if artifact.Role == "binary" && strings.EqualFold(artifact.SHA256, target.ArtifactSHA256) {
				bound = true
				break
			}
		}
		if !bound {
			return nil, fmt.Errorf("%s: artifact-build-info digest %s matches no binary captured in the snapshot; measured authority stays bound to its artifact/build-info bytes", origin, target.ArtifactSHA256)
		}
	}
	return &target, nil
}

// normalizeBuildTarget copies the target and canonicalizes tag order: the
// same tag set selects the same files, so two declarations that differ only
// in order are one selection.
func normalizeBuildTarget(t domain.ProductTarget) domain.ProductTarget {
	out := t
	out.BuildTags = append([]string(nil), t.BuildTags...)
	sort.Strings(out.BuildTags)
	return out
}

// cloneBuildTarget returns an independent copy (nil stays nil) so a resolved
// selection cannot be mutated through a shared pointer.
func cloneBuildTarget(t *domain.ProductTarget) *domain.ProductTarget {
	if t == nil {
		return nil
	}
	out := normalizeBuildTarget(*t)
	return &out
}

// compareBuildTargets requires two normalized declarations to describe the
// same build selection and names the first divergent field.
func compareBuildTargets(a, b domain.ProductTarget) error {
	switch {
	case a.GOOS != b.GOOS:
		return fmt.Errorf("goos %q != %q", a.GOOS, b.GOOS)
	case a.GOARCH != b.GOARCH:
		return fmt.Errorf("goarch %q != %q", a.GOARCH, b.GOARCH)
	case !sameBuildTags(a.BuildTags, b.BuildTags):
		return fmt.Errorf("build_tags %v != %v", a.BuildTags, b.BuildTags)
	case a.CGOEnabled != b.CGOEnabled:
		return fmt.Errorf("cgo_enabled %v != %v", a.CGOEnabled, b.CGOEnabled)
	case a.Source != b.Source:
		return fmt.Errorf("source %q != %q", a.Source, b.Source)
	case a.Scope != b.Scope:
		return fmt.Errorf("scope %q != %q", a.Scope, b.Scope)
	case !strings.EqualFold(a.ArtifactSHA256, b.ArtifactSHA256):
		return fmt.Errorf("artifact_sha256 %q != %q", a.ArtifactSHA256, b.ArtifactSHA256)
	case !strings.EqualFold(a.BuildInfoSHA256, b.BuildInfoSHA256):
		return fmt.Errorf("build_info_sha256 %q != %q", a.BuildInfoSHA256, b.BuildInfoSHA256)
	case a.BinaryMember != b.BinaryMember:
		return fmt.Errorf("binary_member %q != %q", a.BinaryMember, b.BinaryMember)
	}
	return nil
}

func sameBuildTags(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseFindings reads one finding.v1 JSON object, a JSON array of objects, or
// JSONL (one object per line; blank lines are skipped). Every record keeps its
// original bytes and sha256 in FindingInput. It stays the strict domain parser:
// plain text and tracker-shaped documents without schema_version are rejected —
// those belong to the generic transport, ParseIntake.
func ParseFindings(r io.Reader) ([]FindingInput, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("empty finding input")
	}

	var records []findingRecord
	switch trimmed[0] {
	case '[':
		var elems []json.RawMessage
		if err := json.Unmarshal(trimmed, &elems); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		if len(elems) == 0 {
			return nil, errors.New("no findings in input")
		}
		for i, elem := range elems {
			var f Finding
			if err := json.Unmarshal(elem, &f); err != nil {
				return nil, fmt.Errorf("element %d: %w", i+1, err)
			}
			records = append(records, findingRecord{finding: f, raw: elem, where: fmt.Sprintf("element %d", i+1)})
		}
	case '{':
		var f Finding
		if err := json.Unmarshal(trimmed, &f); err == nil {
			records = append(records, findingRecord{finding: f, raw: trimmed})
			break
		}
		// Not a single valid object: treat as JSONL so a malformed line
		// reports its line number.
		fallthrough
	default:
		if trimmed[0] != '{' {
			return nil, fmt.Errorf("input must be a finding.v1 JSON object, JSON array, or JSONL, got %q", trimmed[0])
		}
		for i, line := range bytes.Split(data, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var f Finding
			if err := json.Unmarshal(line, &f); err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			records = append(records, findingRecord{finding: f, raw: line, where: fmt.Sprintf("line %d", i+1)})
		}
	}

	seen := make(map[string]struct{}, len(records))
	inputs := make([]FindingInput, 0, len(records))
	for _, rec := range records {
		if err := validateFinding(rec.finding, rec.where); err != nil {
			return nil, err
		}
		if _, dup := seen[rec.finding.FindingID]; dup {
			return nil, fmt.Errorf("duplicate finding_id %q", rec.finding.FindingID)
		}
		seen[rec.finding.FindingID] = struct{}{}
		raw := bytes.Clone(rec.raw)
		inputs = append(inputs, FindingInput{
			Finding: rec.finding,
			Raw:     raw,
			SHA256:  hashBytes(raw),
		})
	}
	return inputs, nil
}

type findingRecord struct {
	finding Finding
	raw     []byte
	where   string
}

func validateFinding(f Finding, where string) error {
	prefix := ""
	if where != "" {
		prefix = where + ": "
	}
	if f.SchemaVersion != FindingSchemaVersion {
		return fmt.Errorf("%sschema_version must be %q, got %q", prefix, FindingSchemaVersion, f.SchemaVersion)
	}
	if strings.TrimSpace(f.FindingID) == "" {
		return fmt.Errorf("%sfinding_id is required", prefix)
	}
	if len(f.Vulnerability.IDs) == 0 {
		return fmt.Errorf("%svulnerability.ids must contain at least one vulnerability ID", prefix)
	}
	for _, id := range f.Vulnerability.IDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%svulnerability.ids must not contain empty IDs", prefix)
		}
	}
	return nil
}
