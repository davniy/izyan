package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoFixture builds a real snapshot manifest over a temp tree containing a
// small multi-line file and a binary; the returned manifest is what
// LocalSnapshotBuilder produces, so line bounds and hashes stay consistent.
func repoFixture(t *testing.T) (FindingInput, SnapshotManifest) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), linedFile(60))
	in := snapshotInput(t, Target{Repository: dir})
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return in, m
}

func linedFile(lines int) string {
	var b strings.Builder
	for i := 1; i <= lines; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	return b.String()
}

func gateAssessment(claims []Claim, evidence []EvidenceRef) Assessment {
	return Assessment{
		SchemaVersion: AssessmentSchemaVersion,
		FindingID:     "scanner-123",
		Verdict:       VerdictNotExploitable,
		Claims:        claims,
		Evidence:      evidence,
	}
}

func refClaim(id string, refs ...string) Claim {
	return Claim{
		ID:               id,
		Statement:        "s",
		Basis:            PremiseInterpreted,
		Subject:          "fixture subject",
		Scope:            "fixture scope",
		DecisionRelevant: true,
		EvidenceRefs:     refs,
	}
}

func checksByEvidence(v FactValidation) map[string]FactStatus {
	out := make(map[string]FactStatus, len(v.References))
	for _, c := range v.References {
		out[c.EvidenceID] = c.Status
	}
	return out
}

func fileHash(t *testing.T, m SnapshotManifest, path string) string {
	t.Helper()
	for _, f := range m.Files {
		if f.Path == path {
			return f.SHA256
		}
	}
	t.Fatalf("manifest has no file %q", path)
	return ""
}

// obsRun fabricates a run's recorded-observation surface the way an executor
// would produce it: each recorded call mints an audited observation id,
// writes the canonical archive entry, and appends one hash-only audit
// event — the same inputs the fact gate consumes through
// FactGate.Observations at run time and replay rebuilds from events.jsonl.
type obsRun struct {
	store  ObservationStore
	events []ToolAuditEvent
	seq    int
}

func newObsRun(runID string, attempt int) *obsRun {
	return &obsRun{store: NewRunObservationStore(runID, attempt)}
}

// record mints one recorded observation: an OK call when data is given,
// otherwise a bare status record (DENIED/ERROR/... carrying no fact).
func (r *obsRun) record(tool string, status ToolStatus, coverage string, data json.RawMessage) ToolObservation {
	r.seq++
	obs := ToolObservation{ID: observationID("obs", r.seq, r.store), Tool: tool, Status: string(status), Coverage: coverage}
	if len(data) > 0 {
		obs.Data = data
		obs.archiveData = append(json.RawMessage(nil), data...)
		obs.innerSHA = innerSHA256s(data)
		sum := sha256.Sum256(data)
		obs.DataSHA256 = hex.EncodeToString(sum[:])
	}
	r.events = append(r.events, toolAuditEvent(obs, nil))
	recordObservation(r.store, obs)
	return obs
}

// index is the observation id → pin map FactGate.Observations verifies
// det:/obs: locators against, rebuilt from the run's audit trail.
func (r *obsRun) index() map[string]ObservationPin {
	return ObservationIndex(r.events)
}

// observationGateFixture builds a snapshot over a small repo together with
// a recorded-observation run: the audit index it yields is the same shape
// the run's own audit trail produces.
func observationGateFixture(t *testing.T) (FindingInput, SnapshotManifest, *obsRun) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), linedFile(60))
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.org/library\n\ngo 1.23\n")
	in := snapshotInput(t, Target{Repository: dir})
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	run := newObsRun(AttemptRunID(in.Finding.FindingID, 1), 1)
	return in, m, run
}

func gateRefs(t *testing.T, v FactValidation) map[string]ReferenceCheck {
	t.Helper()
	out := map[string]ReferenceCheck{}
	for _, rc := range v.References {
		out[rc.EvidenceID] = rc
	}
	return out
}

func TestFactGate(t *testing.T) {
	in, m := repoFixture(t)
	mainHash := fileHash(t, m, "main.go")

	cases := []struct {
		name     string
		assess   func() Assessment
		input    FindingInput
		manifest SnapshotManifest
		want     FactValidationStatus
		wantRef  map[string]FactStatus
		wantLim  string
	}{
		{
			name: "valid source span",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:10-20"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "valid file hash form",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go#L42-L57"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "unavailable optional artifact declared but missing",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "sbom", Locator: "sbom.json"}},
				)
			},
			input: snapshotInput(t, Target{Repository: in.Finding.Target.Repository, SBOM: "sbom.json"}),
			manifest: func() SnapshotManifest {
				mm, err := LocalSnapshotBuilder{}.Build(context.Background(),
					snapshotInput(t, Target{Repository: in.Finding.Target.Repository, SBOM: "sbom.json"}))
				if err != nil {
					t.Fatalf("Build: %v", err)
				}
				return mm
			}(),
			want:    ValidationPartial,
			wantRef: map[string]FactStatus{"e1": FactUnavailable},
		},
		{
			name: "decision relevant claim without refs",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{{ID: "c1", Statement: "vuln code unreachable", DecisionRelevant: true}},
					nil,
				)
			},
			input: in, manifest: m,
			want:    ValidationPartial,
			wantRef: map[string]FactStatus{"": FactUnreferenced},
		},
		{
			name: "missing file locator",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "pkg/missing.go:1-5"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactInvalid},
		},
		{
			name: "out of root locator",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "../outside.go:1"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactInvalid},
		},
		{
			name: "line out of bounds",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:55-99"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactInvalid},
		},
		{
			name: "component version mismatch",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "component", Locator: "example.org/library@9.9.9"}},
				)
			},
			input:    componentInput(t, in, "example.org/library", "1.4.2"),
			manifest: m,
			want:     ValidationFailed,
			wantRef:  map[string]FactStatus{"e1": FactConflicting},
		},
		{
			name: "component name mismatch",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "component", Locator: "evil.org/other@1.4.2"}},
				)
			},
			input:    componentInput(t, in, "example.org/library", "1.4.2"),
			manifest: m,
			want:     ValidationFailed,
			wantRef:  map[string]FactStatus{"e1": FactConflicting},
		},
		{
			name: "component identity match",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "component", Locator: "example.org/library@1.4.2"}},
				)
			},
			input:    componentInput(t, in, "example.org/library", "1.4.2"),
			manifest: m,
			want:     ValidationComplete,
			wantRef:  map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "package field identity match",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "package", Locator: "example.org/library/parser"}},
				)
			},
			input:    componentInput(t, in, "example.org/library", "1.4.2"),
			manifest: m,
			want:     ValidationComplete,
			wantRef:  map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "advisory id membership",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "advisory", Locator: "CVE-2025-1234"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "foreign advisory id",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "advisory", Locator: "CVE-1999-0001"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactInvalid},
		},
		{
			name: "no advisory ids declared",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "advisory", Locator: "CVE-2025-1234"}},
				)
			},
			input:    noAdvisoryInput(t),
			manifest: SnapshotManifest{SchemaVersion: SnapshotSchemaVersion},
			want:     ValidationPartial,
			wantRef:  map[string]FactStatus{"e1": FactUnavailable},
		},
		{
			name: "source without repository",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:1"}},
				)
			},
			input:    snapshotInput(t, Target{}),
			manifest: SnapshotManifest{SchemaVersion: SnapshotSchemaVersion},
			want:     ValidationPartial,
			wantRef:  map[string]FactStatus{"e1": FactUnavailable},
		},
		{
			name: "dangling claim reference is unavailable not invalid",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e-ghost")},
					nil,
				)
			},
			input: in, manifest: m,
			want:    ValidationPartial,
			wantRef: map[string]FactStatus{"e-ghost": FactUnavailable},
		},
		{
			name: "duplicate evidence ids",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{
						{ID: "e1", Kind: "file", Locator: "main.go"},
						{ID: "e1", Kind: "file", Locator: "main.go:1"},
					},
				)
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactInvalid},
			wantLim: "duplicate",
		},
		{
			name: "hash conflicts with snapshot",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go", SHA256: strings.Repeat("0", 64)}},
				)
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactConflicting},
		},
		{
			name: "declared hash matches file",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go", SHA256: mainHash}},
				)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "observation evidence is limitation not verdict",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "search_text:run-1"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationPartial,
			wantRef: map[string]FactStatus{"e1": FactUnavailable},
			wantLim: "observation",
		},
		{
			name: "unknown kind is unverifiable not invalid",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "moon_phase", Locator: "full"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationPartial,
			wantRef: map[string]FactStatus{"e1": FactUnavailable},
			wantLim: "cannot verify",
		},
		{
			name: "non decision claim without refs ignored",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{
						{ID: "c1", Statement: "background note"},
						refClaim("c2", "e1"),
					},
					[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{"e1": FactValid},
		},
		{
			name: "mixed valid and unavailable is partial",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1", "e2")},
					[]EvidenceRef{
						{ID: "e1", Kind: "file", Locator: "main.go"},
						{ID: "e2", Kind: "observation", Locator: "run-1"},
					},
				)
			},
			input:    in,
			manifest: m,
			want:     ValidationPartial,
			wantRef:  map[string]FactStatus{"e1": FactValid, "e2": FactUnavailable},
		},
		{
			name: "no claims is complete",
			assess: func() Assessment {
				return gateAssessment(nil, nil)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{},
		},
		{
			name: "malformed schema version fails",
			assess: func() Assessment {
				a := gateAssessment(
					[]Claim{refClaim("c1", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go"}},
				)
				a.SchemaVersion = "assessment.v9"
				return a
			},
			input: in, manifest: m,
			want:    ValidationFailed,
			wantRef: map[string]FactStatus{"e1": FactValid},
			wantLim: "schema_version",
		},
		{
			name: "shared evidence checked once",
			assess: func() Assessment {
				return gateAssessment(
					[]Claim{refClaim("c1", "e1"), refClaim("c2", "e1")},
					[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go"}},
				)
			},
			input: in, manifest: m,
			want:    ValidationComplete,
			wantRef: map[string]FactStatus{"e1": FactValid},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := FactGate{}.Validate(context.Background(), tc.input, tc.manifest, tc.assess())
			if v.Status != tc.want {
				t.Fatalf("status = %q, want %q (refs %+v, limitations %v)", v.Status, tc.want, v.References, v.Limitations)
			}
			got := checksByEvidence(v)
			if len(got) != len(tc.wantRef) {
				t.Fatalf("references = %+v, want keys of %+v", v.References, tc.wantRef)
			}
			for id, want := range tc.wantRef {
				if got[id] != want {
					t.Fatalf("reference %q = %q, want %q (all %+v)", id, got[id], want, v.References)
				}
			}
			if tc.wantLim != "" {
				found := false
				for _, l := range v.Limitations {
					if strings.Contains(l, tc.wantLim) {
						found = true
					}
				}
				if !found {
					t.Fatalf("limitations %v lack %q", v.Limitations, tc.wantLim)
				}
			}
		})
	}
}

// TestFactGateEvidenceKindResolution pins the kind vocabulary: recognized
// synonyms reach the same fact checks as the canonical spellings, and an
// unrecognized kind is resolved by the locator shape alone — never by the
// claim's meaning. Unknown facts stay UNAVAILABLE; a non-canonical kind that
// still reaches a check is recorded through the "inferred" limitation.
func TestFactGateEvidenceKindResolution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), linedFile(60))
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.org/library\n\ngo 1.23\n")
	writeFile(t, filepath.Join(dir, "sbom.json"), `{"bomFormat":"CycloneDX"}`)
	in := snapshotInput(t, Target{Repository: dir, SBOM: "sbom.json"})
	in.Finding.Component = Component{Name: "example.org/library", Version: "1.4.2", Ecosystem: "go"}
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	cases := []struct {
		name    string
		ev      EvidenceRef
		want    FactStatus
		wantLim string
	}{
		// Synonyms resolve to the canonical checks.
		{name: "code synonym is source span", ev: EvidenceRef{ID: "e1", Kind: "code", Locator: "main.go:10-20"}, want: FactValid, wantLim: "inferred"},
		{name: "snippet synonym is source span", ev: EvidenceRef{ID: "e1", Kind: "snippet", Locator: "main.go#L42"}, want: FactValid, wantLim: "inferred"},
		{name: "source kind folded case", ev: EvidenceRef{ID: "e1", Kind: "Source_Span", Locator: "main.go:5"}, want: FactValid},
		{name: "go_mod synonym is file", ev: EvidenceRef{ID: "e1", Kind: "go_mod", Locator: "go.mod"}, want: FactValid, wantLim: "inferred"},
		{name: "dependency manifest synonym is file", ev: EvidenceRef{ID: "e1", Kind: "dependency_manifest", Locator: "go.mod"}, want: FactValid, wantLim: "inferred"},
		{name: "cve synonym is advisory", ev: EvidenceRef{ID: "e1", Kind: "cve", Locator: "CVE-2025-1234"}, want: FactValid, wantLim: "inferred"},
		{name: "bdu synonym is advisory", ev: EvidenceRef{ID: "e1", Kind: "BDU", Locator: "CVE-2025-1234"}, want: FactValid, wantLim: "inferred"},
		{name: "module synonym is component", ev: EvidenceRef{ID: "e1", Kind: "module", Locator: "example.org/library@1.4.2"}, want: FactValid, wantLim: "inferred"},
		{name: "binary synonym is artifact", ev: EvidenceRef{ID: "e1", Kind: "binary", Locator: "sbom.json"}, want: FactValid, wantLim: "inferred"},
		// Observation-family spellings stay limitations unless the locator
		// re-derives: a search:<needle>=<count> locator never verifies, a
		// declared file locator runs the file check as inferred.
		{name: "tool result synonym is observation", ev: EvidenceRef{ID: "e1", Kind: "tool_result", Locator: "run-1"}, want: FactUnavailable, wantLim: "observation"},
		{name: "search pseudo locator is observation", ev: EvidenceRef{ID: "e1", Kind: "search", Locator: "search_text:run-1"}, want: FactUnavailable, wantLim: "observation"},
		{name: "snapshot file list synonym is observation", ev: EvidenceRef{ID: "e1", Kind: "snapshot_file_list", Locator: "files"}, want: FactUnavailable, wantLim: "observation"},
		{name: "observation kind with file locator is inferred file check", ev: EvidenceRef{ID: "e1", Kind: "file_list", Locator: "go.mod"}, want: FactValid, wantLim: "inferred"},
		{name: "observation kind with line locator is inferred file check", ev: EvidenceRef{ID: "e1", Kind: "observation", Locator: "main.go:10-20"}, want: FactValid, wantLim: "inferred"},
		{name: "observation kind with undeclared path stays unavailable", ev: EvidenceRef{ID: "e1", Kind: "observation", Locator: "pkg/missing.go"}, want: FactUnavailable, wantLim: "observation"},
		// Inference from the locator shape for unrecognized kinds.
		{name: "manifest kind resolves go.mod by shape", ev: EvidenceRef{ID: "e1", Kind: "manifest", Locator: "go.mod"}, want: FactValid, wantLim: "inferred"},
		{name: "unknown kind infers advisory id", ev: EvidenceRef{ID: "e1", Kind: "thing", Locator: "CVE-2025-1234"}, want: FactValid, wantLim: "inferred"},
		{name: "unknown kind infers file path", ev: EvidenceRef{ID: "e1", Kind: "something", Locator: "main.go"}, want: FactValid, wantLim: "inferred"},
		{name: "unknown kind infers source span", ev: EvidenceRef{ID: "e1", Kind: "something", Locator: "main.go:10-12"}, want: FactValid, wantLim: "inferred"},
		{name: "unknown kind infers declared artifact", ev: EvidenceRef{ID: "e1", Kind: "thing", Locator: "sbom.json"}, want: FactValid, wantLim: "inferred"},
		{name: "unknown kind infers component identity", ev: EvidenceRef{ID: "e1", Kind: "thing", Locator: "example.org/library@1.4.2"}, want: FactValid, wantLim: "inferred"},
		// No recognized kind and no locator shape: unavailable, never guessed.
		{name: "unknown kind unmatched shape", ev: EvidenceRef{ID: "e1", Kind: "wat", Locator: "???"}, want: FactUnavailable, wantLim: "was not recognized"},
		{name: "unknown kind undeclared path stays unavailable", ev: EvidenceRef{ID: "e1", Kind: "thing", Locator: "pkg/missing.go"}, want: FactUnavailable, wantLim: "was not recognized"},
		{name: "search kind pseudo locator stays unavailable", ev: EvidenceRef{ID: "e1", Kind: "search", Locator: "search:run-1"}, want: FactUnavailable},
		{name: "empty kind never inferred", ev: EvidenceRef{ID: "e1", Kind: "", Locator: "main.go"}, want: FactUnavailable},
		// A placeholder sha256 contradicts the pinned hash as before.
		{name: "sha256 NA stays conflicting", ev: EvidenceRef{ID: "e1", Kind: "file", Locator: "main.go", SHA256: "N/A"}, want: FactConflicting},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := gateAssessment([]Claim{refClaim("c1", "e1")}, []EvidenceRef{tc.ev})
			v := FactGate{}.Validate(context.Background(), in, m, a)
			got := checksByEvidence(v)["e1"]
			if got != tc.want {
				t.Fatalf("e1 = %q, want %q (refs %+v)", got, tc.want, v.References)
			}
			if tc.wantLim != "" {
				found := false
				for _, l := range v.Limitations {
					if strings.Contains(l, tc.wantLim) {
						found = true
					}
				}
				if !found {
					t.Fatalf("limitations %v lack %q", v.Limitations, tc.wantLim)
				}
			}
		})
	}
}

// componentInput clones the fixture input with the given component identity.
func componentInput(t *testing.T, in FindingInput, name, version string) FindingInput {
	t.Helper()
	out := in
	out.Finding.Component = Component{
		Name:      name,
		Version:   version,
		Ecosystem: "go",
		Package:   name + "/parser",
	}
	return out
}

// noAdvisoryInput builds a finding input whose vulnerability carries no IDs.
func noAdvisoryInput(t *testing.T) FindingInput {
	t.Helper()
	in := snapshotInput(t, Target{})
	in.Finding.Vulnerability.IDs = nil
	return in
}

func TestFactGateContentDrift(t *testing.T) {
	t.Run("modified span is conflicting", func(t *testing.T) {
		in, m := repoFixture(t)
		// Mutate the tree after the manifest was pinned; the gate must notice
		// via the recorded hash, not by trusting the manifest entry blindly.
		writeFile(t, filepath.Join(in.Finding.Target.Repository, "main.go"), linedFile(61))
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:60"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationFailed {
			t.Fatalf("status = %q, want FAILED", v.Status)
		}
		if got := checksByEvidence(v)["e1"]; got != FactConflicting {
			t.Fatalf("e1 = %q, want CONFLICTING (drift)", got)
		}
	})

	t.Run("modified whole file is conflicting", func(t *testing.T) {
		in, m := repoFixture(t)
		writeFile(t, filepath.Join(in.Finding.Target.Repository, "main.go"), "package main // changed\n")
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationFailed {
			t.Fatalf("status = %q, want FAILED", v.Status)
		}
		if got := checksByEvidence(v)["e1"]; got != FactConflicting {
			t.Fatalf("e1 = %q, want CONFLICTING (whole-file drift)", got)
		}
	})

	t.Run("deleted whole file is unavailable", func(t *testing.T) {
		in, m := repoFixture(t)
		if err := os.Remove(filepath.Join(in.Finding.Target.Repository, "main.go")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationPartial {
			t.Fatalf("status = %q, want PARTIAL", v.Status)
		}
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE (vanished)", got)
		}
	})
}

func TestFactGateArtifactChecks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	writeFile(t, filepath.Join(dir, "sbom.json"), `{"bomFormat":"CycloneDX"}`)
	in := snapshotInput(t, Target{Repository: dir, SBOM: "sbom.json"})
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Run("declared artifact resolves", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "sbom", Locator: "sbom.json"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationComplete || checksByEvidence(v)["e1"] != FactValid {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("artifact hash conflict", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "sbom", Locator: "sbom.json", SHA256: strings.Repeat("f", 64)}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationFailed || checksByEvidence(v)["e1"] != FactConflicting {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("undeclared artifact is invalid not unavailable", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "binary", Locator: "dist/app.bin"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationFailed || checksByEvidence(v)["e1"] != FactInvalid {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("deleted artifact is unavailable", func(t *testing.T) {
		if err := os.Remove(filepath.Join(dir, "sbom.json")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "sbom", Locator: "sbom.json"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationPartial || checksByEvidence(v)["e1"] != FactUnavailable {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("modified artifact is conflicting", func(t *testing.T) {
		dir2 := t.TempDir()
		writeFile(t, filepath.Join(dir2, "sbom.json"), `{"bomFormat":"CycloneDX"}`)
		in2 := snapshotInput(t, Target{Repository: dir2, SBOM: "sbom.json"})
		m2, err := LocalSnapshotBuilder{}.Build(context.Background(), in2)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		writeFile(t, filepath.Join(dir2, "sbom.json"), `{"bomFormat":"SPDX"}`)
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "sbom", Locator: "sbom.json"}},
		)
		v := FactGate{}.Validate(context.Background(), in2, m2, a)
		if v.Status != ValidationFailed || checksByEvidence(v)["e1"] != FactConflicting {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})
}

func TestFactGateRevision(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-q", "-m", "init")
	gitCmd(t, dir, "tag", "v1.0.0")
	gitCmd(t, dir, "tag", "v2.0.0")

	in := snapshotInput(t, Target{Repository: dir, Revision: "v1.0.0"})
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Run("matching revision valid", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "revision", Locator: "v1.0.0"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationComplete || checksByEvidence(v)["e1"] != FactValid {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("git_ref synonym resolves", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "git_ref", Locator: "v1.0.0"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationComplete || checksByEvidence(v)["e1"] != FactValid {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("different commit conflicts", func(t *testing.T) {
		writeFile(t, filepath.Join(dir, "main.go"), "package main // v2\n")
		gitCmd(t, dir, "add", ".")
		gitCmd(t, dir, "commit", "-q", "-m", "v2")
		gitCmd(t, dir, "tag", "-f", "v2.0.0")
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "revision", Locator: "v2.0.0"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if v.Status != ValidationFailed || checksByEvidence(v)["e1"] != FactConflicting {
			t.Fatalf("status=%q refs=%+v", v.Status, v.References)
		}
	})

	t.Run("unresolvable ref invalid", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "commit", Locator: "no-such-ref"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if checksByEvidence(v)["e1"] == FactValid {
			t.Fatalf("unresolvable ref marked VALID: %+v", v.References)
		}
	})
}

// TestReferenceStatus pins each of the five FactStatus values to its exact
// trigger so later refactors cannot blur the distinctions the spec fixes:
// presence checks never become semantic judgements.
func TestReferenceStatus(t *testing.T) {
	in, m := repoFixture(t)

	t.Run("VALID requires resolvable binding", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:42"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		rc := v.References[0]
		if rc.Status != FactValid || rc.Locator != "main.go:42" {
			t.Fatalf("check = %+v", rc)
		}
	})

	t.Run("UNAVAILABLE is absence of source not of truth", func(t *testing.T) {
		noRepo := snapshotInput(t, Target{})
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go"}},
		)
		v := FactGate{}.Validate(context.Background(), noRepo, SnapshotManifest{SchemaVersion: SnapshotSchemaVersion}, a)
		if checksByEvidence(v)["e1"] != FactUnavailable {
			t.Fatalf("refs = %+v", v.References)
		}
	})

	t.Run("UNREFERENCED only for decision relevant claims", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{{ID: "c1", Statement: "s", DecisionRelevant: true}},
			nil,
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if len(v.References) != 1 || v.References[0].Status != FactUnreferenced {
			t.Fatalf("refs = %+v", v.References)
		}
	})

	t.Run("INVALID for broken in-scope reference", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:1000"}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if checksByEvidence(v)["e1"] != FactInvalid {
			t.Fatalf("refs = %+v", v.References)
		}
	})

	t.Run("CONFLICTING for direct contradiction", func(t *testing.T) {
		a := gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go", SHA256: strings.Repeat("9", 64)}},
		)
		v := FactGate{}.Validate(context.Background(), in, m, a)
		if checksByEvidence(v)["e1"] != FactConflicting {
			t.Fatalf("refs = %+v", v.References)
		}
	})
}

// TestFactGateSearchPseudoLocators pins the canonical-locator contract:
// every synthesized "search:..." spelling is UNAVAILABLE — never VALID,
// never CONFLICTING — with the deterministic repair hint pointing at the
// recorded observation id, regardless of the declared kind.
func TestFactGateSearchPseudoLocators(t *testing.T) {
	in, m, _ := observationGateFixture(t)

	assess := func(locator, kind string) FactValidation {
		return FactGate{}.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: kind, Locator: locator}},
		))
	}

	for _, loc := range []string{
		// Correct counts, wrong counts, zero counts, needles containing
		// '=', and every malformed spelling share one outcome: nothing
		// recorded owns the pseudo-locator, so it can never verify.
		"search:line 42=1", "search:line 42=5", "search:no_such_needle=0",
		"search:line =60", "search:example.org/library=1",
		"search:", "search:=3", "search:foo", "search:foo=x", "search:foo=",
		"Search:line 42=1",
	} {
		for _, kind := range []string{"search", "search_text", "search_result", "observation", "file", "thing"} {
			v := assess(loc, kind)
			rc := gateRefs(t, v)["e1"]
			if rc.Status != FactUnavailable {
				t.Fatalf("locator %q kind %q = %q, want UNAVAILABLE", loc, kind, rc.Status)
			}
			if rc.ExpectedRepair != "cite the recorded observation as obs:<id> or det:<id>" {
				t.Fatalf("locator %q kind %q repair = %q, want the obs/det hint", loc, kind, rc.ExpectedRepair)
			}
			found := false
			for _, l := range v.Limitations {
				if strings.Contains(l, "not canonical evidence") {
					found = true
				}
			}
			if !found {
				t.Fatalf("locator %q kind %q limitations %v lack the pseudo-locator note", loc, kind, v.Limitations)
			}
		}
	}

	t.Run("pseudo locators never reach the live tree", func(t *testing.T) {
		// A re-scan would have found "line " in all 60 lines of main.go;
		// the gate no longer re-derives counts at all.
		v := assess("search:line =60", "search")
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE (no re-scan)", got)
		}
	})
}

// TestFactGateListFilesPseudoLocators: the same contract for the
// list_files: spellings — path, count and even escaping scopes are all
// UNAVAILABLE with the obs:/det: repair hint.
func TestFactGateListFilesPseudoLocators(t *testing.T) {
	in, m, _ := observationGateFixture(t)

	assess := func(locator, kind string) FactValidation {
		return FactGate{}.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: kind, Locator: locator}},
		))
	}
	for _, loc := range []string{
		"list_files:main.go", "list_files:main.go=1", "list_files:pkg",
		"list_files:pkg=3", "list_files:=4", "list_files:pkg=5",
		"list_files:nosuch", "list_files:nosuch=0", "list_files:/etc",
		"list_files:..", "List_Files:main.go",
	} {
		for _, kind := range []string{"observation", "list_files", "file_list", "file", "thing"} {
			v := assess(loc, kind)
			rc := gateRefs(t, v)["e1"]
			if rc.Status != FactUnavailable {
				t.Fatalf("locator %q kind %q = %q, want UNAVAILABLE", loc, kind, rc.Status)
			}
			if rc.ExpectedRepair != "cite the recorded observation as obs:<id> or det:<id>" {
				t.Fatalf("locator %q kind %q repair = %q, want the obs/det hint", loc, kind, rc.ExpectedRepair)
			}
		}
	}
}

// TestFactGateSearchObservationCitation pins the canonical path for
// search/list results: a recorded observation is cited by its id —
// obs:<id> — and resolves VALID, while the recorded payload carries the
// scope the count is bounded to. An id the run never recorded stays
// UNAVAILABLE. The recorded observation here is fabricated with the same
// audit/archive plumbing a real executor drives; the search_text handler
// itself is deferred to the S-06b read-only-tools slice.
func TestFactGateSearchObservationCitation(t *testing.T) {
	in, m, run := observationGateFixture(t)

	search := run.record("search_text", ToolStatusOK, "", json.RawMessage(
		`{"query":"needle","prefix":"","count":3,"files_skipped":2,"matches":[{"path":"a.txt","line":1}]}`))
	if search.Status != string(ToolStatusOK) {
		t.Fatalf("search status = %q", search.Status)
	}
	var d map[string]any
	if err := json.Unmarshal(search.Data, &d); err != nil {
		t.Fatal(err)
	}
	if d["count"].(float64) != 3 || d["files_skipped"].(float64) != 2 {
		t.Fatalf("search payload = %v, want 3 matches over 2 skipped files", d)
	}
	if d["query"] != "needle" {
		t.Fatalf("search payload lacks the query scope: %v", d)
	}
	if _, ok := d["prefix"]; !ok {
		t.Fatalf("search payload lacks the prefix scope: %v", d)
	}
	// The archive carries the recorded payload once, hash-pinned.
	archived := run.store.Observations()
	if len(archived) != 1 || archived[0].ID != search.ID || archived[0].DataSHA256 != search.DataSHA256 {
		t.Fatalf("archive = %+v, want the single recorded %s", archived, search.ID)
	}

	gate := FactGate{Observations: run.index()}
	assess := func(locator, kind string) FactValidation {
		return gate.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: kind, Locator: locator}},
		))
	}

	t.Run("recorded search observation resolves by id", func(t *testing.T) {
		v := assess("obs:"+search.ID, "observation")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
		if v.Status != ValidationComplete {
			t.Fatalf("status = %q, want COMPLETE", v.Status)
		}
	})

	t.Run("search kind reaches the observation check", func(t *testing.T) {
		v := assess("obs:"+search.ID, "search")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
		found := false
		for _, l := range v.Limitations {
			if strings.Contains(l, "inferred from the locator shape") {
				found = true
			}
		}
		if !found {
			t.Fatalf("limitations %v lack the inferred-shape note", v.Limitations)
		}
	})

	t.Run("synthesized search locator stays unavailable next to real observations", func(t *testing.T) {
		v := assess("search:needle=3", "search")
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE", got)
		}
	})

	t.Run("unknown observation id is unavailable", func(t *testing.T) {
		v := assess("obs:obs-9999", "observation")
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE", got)
		}
	})

	t.Run("offline gate resolves the recorded id without the live tree", func(t *testing.T) {
		// The tree is gone: only the recorded audit index can back the
		// citation, exactly the replay situation.
		if err := os.RemoveAll(in.Finding.Target.Repository); err != nil {
			t.Fatal(err)
		}
		offline := FactGate{Observations: run.index(), Offline: true}
		v := offline.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "obs:" + search.ID}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID offline", got)
		}
	})
}

// TestFactGateListFilesObservationCitation: an empty scoped list_files
// result resolves through its recorded observation id — the empty listing
// is a real recorded fact inside its scope — while pseudo spellings stay
// unavailable.
func TestFactGateListFilesObservationCitation(t *testing.T) {
	in, m, run := observationGateFixture(t)

	list := run.record("list_files", ToolStatusOK, "", json.RawMessage(
		`{"path":"pkg","scope":"pkg","total":1,"entries":["a.go"]}`))
	empty := run.record("list_files", ToolStatusOK, "", json.RawMessage(
		`{"path":"empty-dir","scope":"empty-dir","total":0,"entries":[]}`))

	gate := FactGate{Observations: run.index()}
	assess := func(locator string) FactValidation {
		return gate.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: locator}},
		))
	}

	t.Run("scoped listing resolves by observation id", func(t *testing.T) {
		v := assess("obs:" + list.ID)
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})

	t.Run("empty listing resolves by observation id", func(t *testing.T) {
		v := assess("obs:" + empty.ID)
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID (recorded empty scope)", got)
		}
	})

	t.Run("empty search resolves by observation id", func(t *testing.T) {
		none := run.record("search_text", ToolStatusOK, "", json.RawMessage(
			`{"query":"no_such_needle_xyz","prefix":"","count":0}`))
		gate = FactGate{Observations: run.index()}
		v := gate.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "obs:" + none.ID}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID (recorded empty search)", got)
		}
	})

	t.Run("pseudo listing stays unavailable", func(t *testing.T) {
		v := assess("list_files:pkg=1")
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE", got)
		}
	})
}

// TestFactGateForeignObservationID: an observation id minted by another
// attempt/run never resolves in this run's index.
func TestFactGateForeignObservationID(t *testing.T) {
	in, m, _ := observationGateFixture(t)
	other := newObsRun(AttemptRunID(in.Finding.FindingID, 2), 2)
	foreign := other.record("list_files", ToolStatusOK, "", json.RawMessage(`{"total":1}`))
	if !strings.HasPrefix(foreign.ID, "obs-a2-") {
		t.Fatalf("attempt-2 id = %q, want the attempt-qualified space", foreign.ID)
	}

	mine := newObsRun(AttemptRunID(in.Finding.FindingID, 1), 1)
	mine.record("list_files", ToolStatusOK, "", json.RawMessage(`{"total":1}`))
	gate := FactGate{Observations: mine.index()}
	v := gate.Validate(context.Background(), in, m, gateAssessment(
		[]Claim{refClaim("c1", "e1")},
		[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "obs:" + foreign.ID}},
	))
	if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
		t.Fatalf("e1 = %q, want UNAVAILABLE (foreign attempt id %q)", got, foreign.ID)
	}
}

// TestFactGateObservationFileLocator pins the inferred file check for
// observation-family kinds carrying a path[:line] locator: existence,
// line bounds and pinned-hash drift are verified facts; the inferred
// provenance stays visible as a limitation.
func TestFactGateObservationFileLocator(t *testing.T) {
	in, m := repoFixture(t)

	assess := func(locator string) FactValidation {
		return FactGate{}.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: locator}},
		))
	}
	hasLim := func(v FactValidation, sub string) bool {
		for _, l := range v.Limitations {
			if strings.Contains(l, sub) {
				return true
			}
		}
		return false
	}

	t.Run("declared file locator validates with inferred limitation", func(t *testing.T) {
		v := assess("main.go")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
		if !hasLim(v, "evidence kind was inferred from the locator shape") {
			t.Fatalf("limitations %v lack inferred-shape note", v.Limitations)
		}
	})

	t.Run("declared line span validates", func(t *testing.T) {
		v := assess("main.go:10-20")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})

	t.Run("out-of-bounds line is invalid", func(t *testing.T) {
		v := assess("main.go:900")
		if got := checksByEvidence(v)["e1"]; got != FactInvalid {
			t.Fatalf("e1 = %q, want INVALID", got)
		}
	})

	t.Run("hash drift is conflicting", func(t *testing.T) {
		writeFile(t, filepath.Join(in.Finding.Target.Repository, "main.go"), "package main // changed\n")
		v := assess("main.go")
		if got := checksByEvidence(v)["e1"]; got != FactConflicting {
			t.Fatalf("e1 = %q, want CONFLICTING (drift)", got)
		}
	})

	t.Run("undeclared path stays a limitation", func(t *testing.T) {
		in2, m2 := repoFixture(t)
		v := FactGate{}.Validate(context.Background(), in2, m2, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "no-such-file.go"}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE", got)
		}
	})
}

// TestFactGateComponentVersionNormalization pins canonical version
// comparison in the component check: a decorative leading "v"/"V" does not
// distinguish spellings, while "+incompatible" and real version deltas stay
// part of the identity.
func TestFactGateComponentVersionNormalization(t *testing.T) {
	in, m := repoFixture(t)
	in = componentInput(t, in, "example.org/library", "1.10.0")

	assess := func(locator, kind string) FactValidation {
		return FactGate{}.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: kind, Locator: locator}},
		))
	}

	t.Run("v prefix matches bare version", func(t *testing.T) {
		v := assess("example.org/library@v1.10.0", "component")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})

	t.Run("capital V prefix matches", func(t *testing.T) {
		v := assess("example.org/library@V1.10.0", "component")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})

	t.Run("bare locator matches declared v version", func(t *testing.T) {
		in2 := componentInput(t, in, "example.org/library", "v1.10.0")
		v := FactGate{}.Validate(context.Background(), in2, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "component", Locator: "example.org/library@1.10.0"}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})

	t.Run("incompatible suffix stays significant", func(t *testing.T) {
		v := assess("example.org/library@v1.10.0+incompatible", "component")
		if got := checksByEvidence(v)["e1"]; got != FactConflicting {
			t.Fatalf("e1 = %q, want CONFLICTING", got)
		}
		in2 := componentInput(t, in, "example.org/library", "v1.10.0+incompatible")
		v = FactGate{}.Validate(context.Background(), in2, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "component", Locator: "example.org/library@1.10.0+incompatible"}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID (+incompatible)", got)
		}
	})

	t.Run("real version delta still conflicts", func(t *testing.T) {
		v := assess("example.org/library@v1.10.1", "component")
		if got := checksByEvidence(v)["e1"]; got != FactConflicting {
			t.Fatalf("e1 = %q, want CONFLICTING", got)
		}
	})

	t.Run("inferred kind also normalizes", func(t *testing.T) {
		v := assess("example.org/library@v1.10.0", "wat")
		if got := checksByEvidence(v)["e1"]; got != FactValid {
			t.Fatalf("e1 = %q, want VALID via inferred component check", got)
		}
	})
}

// TestFactGateDetObservation pins the det:<id> reference check against the
// run's observation index: the id is the anchor, so a known id verifies
// VALID regardless of a declared sha256 — a hash matching the recorded
// envelope verifies silently, an inner payload hash and a hash matching
// nothing both verify with a limitation (never CONFLICTING), and an
// unknown id is unavailable context.
func TestFactGateDetObservation(t *testing.T) {
	in, m := repoFixture(t)
	const detSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const innerSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	gate := FactGate{Observations: map[string]ObservationPin{
		"det-0001": {Status: string(ToolStatusOK), DataSHA256: detSHA, InnerSHA256: []string{innerSHA}, Tool: "find_callers", ReachEvidence: true},
		"det-0002": {Status: string(ToolStatusOK)}, // recorded call carried no data payload
	}}

	assess := func(ev EvidenceRef) FactValidation {
		return gate.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{ev},
		))
	}
	status := func(v FactValidation) FactStatus { return checksByEvidence(v)["e1"] }
	hasLim := func(v FactValidation, sub string) bool {
		for _, l := range v.Limitations {
			if strings.Contains(l, sub) {
				return true
			}
		}
		return false
	}

	t.Run("known id validates", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001"})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID (refs %+v)", got, v.References)
		}
		if v.Status != ValidationComplete {
			t.Fatalf("status = %q, want COMPLETE", v.Status)
		}
	})

	for _, tc := range []struct {
		name   string
		status string
		cover  string
	}{
		{"DENIED", string(ToolStatusDenied), "COMPLETE"},
		{"ERROR", string(ToolStatusError), "COMPLETE"},
		{"TIMEOUT", string(ToolStatusTimeout), "COMPLETE"},
		{"UNSUPPORTED", string(ToolStatusUnsupported), "COMPLETE"},
		{"PARTIAL", string(ToolStatusOK), "PARTIAL"},
		{"UNKNOWN", string(ToolStatusOK), "UNKNOWN"},
	} {
		t.Run("non-fact "+tc.name+" never validates", func(t *testing.T) {
			gate.Observations["obs-bad"] = ObservationPin{Status: tc.status, Coverage: tc.cover, Tool: "read_file"}
			v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "obs:obs-bad"})
			if got := status(v); got != FactUnavailable {
				t.Fatalf("status = %q, want UNAVAILABLE (%+v)", got, v.References)
			}
			if v.Status == ValidationComplete {
				t.Fatal("non-fact observation must not produce COMPLETE validation")
			}
			delete(gate.Observations, "obs-bad")
		})
	}

	t.Run("matching sha256 validates", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001", SHA256: detSHA})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})

	t.Run("sha256 in locator validates", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001@" + detSHA})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
	})
	t.Run("wrong sha256 still validates with limitation", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001", SHA256: strings.Repeat("9", 64)})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID (id is the anchor)", got)
		}
		if v.Status != ValidationComplete {
			t.Fatalf("status = %q, want COMPLETE (hash mismatch is a limitation)", v.Status)
		}
		if !hasLim(v, "the id is the anchor") {
			t.Fatalf("limitations %v lack the hash-mismatch note", v.Limitations)
		}
	})
	t.Run("conflicting locator sha validates with limitation", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001@" + detSHA, SHA256: strings.Repeat("9", 64)})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID (id is the anchor)", got)
		}
		if !hasLim(v, "the id is the anchor") {
			t.Fatalf("limitations %v lack the hash-mismatch note", v.Limitations)
		}
	})

	t.Run("inner payload hash validates with limitation", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001", SHA256: innerSHA})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID via inner hash", got)
		}
		if v.Status != ValidationComplete {
			t.Fatalf("status = %q, want COMPLETE (inner-hash match is a limitation, not a partial)", v.Status)
		}
		if !hasLim(v, "inner observation hash") {
			t.Fatalf("limitations %v lack the inner-hash note", v.Limitations)
		}
	})

	t.Run("inner payload hash in locator validates", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001@" + innerSHA})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID via inner locator hash", got)
		}
		if !hasLim(v, "inner observation hash") {
			t.Fatalf("limitations %v lack the inner-hash note", v.Limitations)
		}
	})

	t.Run("det reference carries tool and reachability pin", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0001"})
		for _, rc := range v.References {
			if rc.EvidenceID == "e1" && (rc.Tool != "find_callers" || !rc.ReachEvidence) {
				t.Fatalf("reference = %+v, want tool=find_callers reach_evidence=true", rc)
			}
		}
	})

	t.Run("unknown id is unavailable with limitation", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-9999"})
		if got := status(v); got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE", got)
		}
		if v.Status != ValidationPartial {
			t.Fatalf("status = %q, want PARTIAL", v.Status)
		}
		if !hasLim(v, "det-9999") {
			t.Fatalf("limitations %v lack the unknown-id note", v.Limitations)
		}
	})

	t.Run("empty index leaves det refs unavailable", func(t *testing.T) {
		v := (FactGate{}).Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "det:det-0001"}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE (no index)", got)
		}
	})

	t.Run("observation without data validates by id", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "observation", Locator: "det:det-0002"})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID (id is the anchor)", got)
		}
	})

	t.Run("det kind spellings resolve without inferred note", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "det_observation", Locator: "det:det-0001"})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID", got)
		}
		if hasLim(v, "inferred from the locator shape") {
			t.Fatalf("limitations %v carry an unexpected inferred note", v.Limitations)
		}
	})

	t.Run("unknown kind still reaches the det check", func(t *testing.T) {
		v := assess(EvidenceRef{ID: "e1", Kind: "wat", Locator: "det:det-0001"})
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID via inferred observation check", got)
		}
		if !hasLim(v, "inferred from the locator shape") {
			t.Fatalf("limitations %v lack inferred-shape note", v.Limitations)
		}
	})
}

// TestFactGateObservationIDNormalization pins the tolerant observation-id
// resolution: both sides are normalized (lowercased, trimmed, '_' folded
// to '-') so "det:DET-0004", "OBS:obs-0011" or a bare "obs_0011" still
// name the recorded ids — but only when the match is unambiguous, and an
// id the run never produced stays UNAVAILABLE in any spelling.
func TestFactGateObservationIDNormalization(t *testing.T) {
	in, m := repoFixture(t)
	gate := FactGate{Observations: map[string]ObservationPin{
		"det-0004": {Status: string(ToolStatusOK), Tool: "find_callers", ReachEvidence: true},
		"obs-0011": {Status: string(ToolStatusOK), Tool: "read_file"},
	}}

	check := func(locator string) FactValidation {
		return gate.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: locator}},
		))
	}
	status := func(v FactValidation) FactStatus { return checksByEvidence(v)["e1"] }

	for _, tc := range []struct {
		name    string
		locator string
	}{
		{"canonical", "det:det-0004"},
		{"upper id", "det:DET-0004"},
		{"mixed case", "det:Det-0004"},
		{"upper scheme", "DET:det-0004"},
		{"padded", "  det: det-0004  "},
		{"obs scheme", "obs:obs-0011"},
		{"obs scheme upper id", "obs:OBS-0011"},
		{"mixed prefix", "det:obs-0011"},
		{"bare id", "det-0004"},
		{"bare upper", "DET-0004"},
		{"underscore scheme", "det:obs_0011"},
		{"bare underscore", "obs_0011"},
		{"bare upper underscore", "OBS_0011"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := status(check(tc.locator)); got != FactValid {
				t.Fatalf("%q = %q, want VALID", tc.locator, got)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		locator string
	}{
		{"unknown lower", "det:det-9999"},
		{"unknown upper", "det:DET-9999"},
		{"unknown underscore", "obs_9999"},
		{"unknown obs scheme", "obs:OBS-9999"},
		{"unknown bare", "SET-0001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := check(tc.locator)
			if got := status(v); got != FactUnavailable {
				t.Fatalf("%q = %q, want UNAVAILABLE", tc.locator, got)
			}
			var reason string
			for _, rc := range v.References {
				if rc.EvidenceID == "e1" {
					reason = rc.Reason
				}
			}
			if !strings.Contains(reason, "not among the run's recorded tool observations") {
				t.Fatalf("%q reason = %q, want the not-recorded note", tc.locator, reason)
			}
		})
	}

	t.Run("normalized match still verifies by id alone", func(t *testing.T) {
		v := check("obs:OBS_0011@deadbeef")
		if got := status(v); got != FactValid {
			t.Fatalf("e1 = %q, want VALID (id is the anchor)", got)
		}
	})

	t.Run("ambiguous normalized id is unresolved", func(t *testing.T) {
		amb := FactGate{Observations: map[string]ObservationPin{
			"obs-0011": {Status: string(ToolStatusOK)},
			"OBS_0011": {Status: string(ToolStatusOK)}, // different recorded spelling, same normalized id
		}}
		// det:OBS-0011 is no recorded key verbatim, but normalizes to the
		// same "obs-0011" both keys fold to — ambiguous, hence unresolved.
		v := amb.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "det:OBS-0011"}},
		))
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE (ambiguous normalized id)", got)
		}
	})

	t.Run("non-observation bare locator keeps its own shape", func(t *testing.T) {
		v := check("foo-1234")
		if got := status(v); got != FactUnavailable {
			t.Fatalf("e1 = %q, want UNAVAILABLE (not an observation id)", got)
		}
		for _, rc := range v.References {
			if rc.EvidenceID == "e1" && strings.Contains(rc.Reason, "recorded tool observations") {
				t.Fatalf("foo-1234 must not reach the observation check: %+v", rc)
			}
		}
	})
}

// TestFactGateOutsideLocator pins the boundary class: a locator that names
// a file outside the snapshot (module cache, any absolute path) is
// UNAVAILABLE context — never a malformed in-snapshot reference.
func TestFactGateOutsideLocator(t *testing.T) {
	in, m := repoFixture(t)

	assess := func(kind, locator string) FactValidation {
		return FactGate{}.Validate(context.Background(), in, m, gateAssessment(
			[]Claim{refClaim("c1", "e1")},
			[]EvidenceRef{{ID: "e1", Kind: kind, Locator: locator}},
		))
	}
	assertOutside := func(v FactValidation, what string) {
		t.Helper()
		if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
			t.Fatalf("%s: e1 = %q, want UNAVAILABLE (refs %+v)", what, got, v.References)
		}
		found := false
		for _, l := range v.Limitations {
			if strings.Contains(l, "outside the snapshot") {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: limitations %v lack the outside-snapshot note", what, v.Limitations)
		}
	}

	t.Run("file kind absolute module cache path", func(t *testing.T) {
		assertOutside(assess("file", "/go/pkg/mod/example.org/dep@v1.10.0/x.go"), "file /go/pkg/mod")
	})
	t.Run("source span absolute path", func(t *testing.T) {
		assertOutside(assess("source_span", "/tmp/other/main.go:10-20"), "source_span /tmp")
	})
	t.Run("observation kind absolute path", func(t *testing.T) {
		assertOutside(assess("observation", "/go/pkg/mod/dep@v1/x.go"), "observation abs")
	})
	t.Run("unknown kind absolute path", func(t *testing.T) {
		assertOutside(assess("thing", "/etc/passwd"), "unknown abs")
	})
	t.Run("artifact kind undeclared absolute path", func(t *testing.T) {
		assertOutside(assess("artifact", "/tmp/foreign/sbom.json"), "artifact abs")
	})
	t.Run("home-relative locator", func(t *testing.T) {
		assertOutside(assess("file", "~/go/pkg/mod/x.go"), "file ~")
	})
	t.Run("windows drive locator", func(t *testing.T) {
		assertOutside(assess("file", "C:/deps/dep@v1/x.go"), "file C:/")
	})

	t.Run("parent escape stays invalid", func(t *testing.T) {
		v := assess("file", "../outside.go")
		if got := checksByEvidence(v)["e1"]; got != FactInvalid {
			t.Fatalf("e1 = %q, want INVALID (lexical escape)", got)
		}
	})
}
