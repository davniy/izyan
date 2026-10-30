package claimshape

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeJSON persists a value as JSON into dir.
func writeJSON(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// obs builds a recorded observation envelope the way
// observation-archive.json stores it.
func obs(id, tool string, data map[string]any, completeness string) map[string]any {
	payload := map[string]any{
		"id":           id,
		"tool":         tool,
		"fact":         "synthetic",
		"completeness": completeness,
		"tool_status":  "OK",
		"scope_details": map[string]any{
			"snapshot_hash": "snap-1",
			"build_context": map[string]any{"goos": "linux", "goarch": "amd64"},
		},
	}
	if data != nil {
		payload["data"] = data
	}
	return map[string]any{
		"id":            id,
		"tool":          tool,
		"status":        "OK",
		"completeness":  completeness,
		"scope":         "synthetic scope",
		"payload":       payload,
		"snapshot_hash": "snap-1",
		"attempt":       1,
	}
}

// assessment builds a minimal assessment.v1 document.
func assessment(claims []any, evidence []any, proposals []any) map[string]any {
	return map[string]any{
		"schema_version":      "assessment.v1",
		"finding_id":          "intake-1-test-abcdef012345",
		"verdict":             "NOT_EXPLOITABLE",
		"claims":              claims,
		"evidence":            evidence,
		"falsifier_proposals": proposals,
	}
}

func claim(id, status string, dr bool, refs ...string) map[string]any {
	return map[string]any{
		"id":                id,
		"statement":         "statement text never drives shape",
		"status":            status,
		"decision_relevant": dr,
		"evidence_refs":     refs,
	}
}

func evidence(id, kind, locator string) map[string]any {
	return map[string]any{"id": id, "kind": kind, "locator": locator, "quote": "q"}
}

func runDir(t *testing.T, asm, archive, falsifier, stage0 map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	if asm != nil {
		writeJSON(t, dir, "assessment.json", asm)
	}
	if archive != nil {
		writeJSON(t, dir, "observation-archive.json", archive)
	}
	if falsifier != nil {
		writeJSON(t, dir, "falsifier-verification.json", falsifier)
	}
	if stage0 != nil {
		writeJSON(t, dir, "stage0.json", stage0)
	}
	return dir
}

var stage0Doc = map[string]any{
	"schema_version": "stage0.v1",
	"advisory":       map[string]any{"resolved_id": "GHSA-xxxx-yyyy-zzzz"},
	"resolution_vulnerability": map[string]any{
		"id":      "GHSA-xxxx-yyyy-zzzz",
		"aliases": []string{"CVE-2026-0001"},
		"module":  "example.com/mod",
		"package": "example.com/mod",
		"affected_symbols": []map[string]any{
			{"package": "example.com/mod/sub", "symbol": "Vuln"},
		},
		"affected_versions": []map[string]any{
			{"introduced": "0", "fixed": "1.5.0"},
		},
	},
	"materialization": map[string]any{"source_id": "repo-a", "selected_ref": "1.2.3"},
}

// TestNormalizeKnownForms covers every decisional family and the
// contextual rollups with a synthetic run per expectation.
func TestNormalizeKnownForms(t *testing.T) {
	cases := []struct {
		name      string
		obs       map[string]any
		evKind    string
		evLocator string
		wantShape Shape
		wantPolar Polarity
	}{
		{"version_in_range_true", obs("det-0001", "get_module_version", map[string]any{"module": "example.com/mod", "present": true, "version": "v1.2.0"}, "COMPLETE"), "observation", "det:det-0001", ShapeApplicabilityVersionInRange, PolarityTrue},
		{"version_out_of_range", obs("det-0001", "get_module_version", map[string]any{"module": "example.com/mod", "present": true, "version": "v9.9.9"}, "COMPLETE"), "observation", "det:det-0001", ShapeApplicabilityVersionInRange, PolarityFalse},
		{"subject_absent_closed", obs("det-0001", "verify_code_absence", map[string]any{"checked_subjects": []any{map[string]any{"package": "p", "symbol": "S"}}, "absent_subjects": []any{map[string]any{"package": "p", "symbol": "S"}}, "expected_subjects": []any{map[string]any{"package": "p", "symbol": "S"}}}, "COMPLETE"), "observation", "det:det-0001", ShapeSubjectAbsent, PolarityTrue},
		{"subject_declared_found", obs("det-0001", "find_symbol", map[string]any{"found": true}, "COMPLETE"), "observation", "det:det-0001", ShapeSubjectDeclared, PolarityTrue},
		{"subject_absent_zero_refs", obs("det-0001", "find_references", map[string]any{"count": 0}, "PARTIAL"), "observation", "det:det-0001", ShapeSubjectAbsent, PolarityTrue},
		{"path_unreachable_zero_callers", obs("det-0001", "find_callers", map[string]any{"count": 0, "call_sites": []any{}}, "PARTIAL"), "observation", "det:det-0001", ShapePathUnreachable, PolarityTrue},
		{"path_reachable_callers", obs("det-0001", "find_callers", map[string]any{"count": 3}, "PARTIAL"), "observation", "det:det-0001", ShapePathReachable, PolarityTrue},
		{"control_present_guard", obs("det-0001", "check_call_site_guard", map[string]any{"gated": true}, "PARTIAL"), "observation", "det:det-0001", ShapeControlPresent, PolarityTrue},
		{"control_absent_guard", obs("det-0001", "check_call_site_guard", map[string]any{"gated": false}, "PARTIAL"), "observation", "det:det-0001", ShapeControlAbsent, PolarityTrue},
		{"environment_build_gate", obs("det-0001", "get_product_snapshot", map[string]any{"goos": "linux"}, "COMPLETE"), "observation", "det:det-0001", ShapeEnvironmentBuildGate, PolarityTrue},
		{"environment_gated_refs", obs("det-0001", "gated_refs", map[string]any{"count": 2}, "PARTIAL"), "observation", "det:det-0001", ShapeEnvironmentBuildGate, PolarityTrue},
		{"environment_gated_refs_zero", obs("det-0001", "gated_refs", map[string]any{"count": 0}, "PARTIAL"), "observation", "det:det-0001", ShapeEnvironmentBuildGate, PolarityFalse},
		{"configuration_manifest", obs("det-0001", "read_manifest", map[string]any{"count": 2}, "COMPLETE"), "observation", "det:det-0001", ShapeConfigurationPredicate, PolarityTrue},
		{"provenance_advisory", obs("det-0001", "lookup_advisory", map[string]any{"requested_id": "GHSA-xxxx-yyyy-zzzz"}, "COMPLETE"), "observation", "det:det-0001", ShapeProvenanceBound, PolarityTrue},
		{"subject_absent_search_probe", nil, "observation", "search:NewGRPCServer=0", ShapeSubjectAbsent, PolarityTrue},
		{"subject_declared_search_probe", nil, "observation", "search:Serve=14", ShapeSubjectDeclared, PolarityTrue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var observations []any
			if tc.obs != nil {
				observations = append(observations, tc.obs)
			}
			archive := map[string]any{"schema_version": "observation-archive.v1", "observations": observations}
			asm := assessment(
				[]any{claim("c1", "confirmed", true, "e1")},
				[]any{evidence("e1", tc.evKind, tc.evLocator)},
				nil,
			)
			dir := runDir(t, asm, archive, nil, stage0Doc)
			ex, err := ExtractRun(dir, "CASE-T")
			if err != nil {
				t.Fatal(err)
			}
			if len(ex.Claims) != 1 {
				t.Fatalf("claims=%d", len(ex.Claims))
			}
			c := ex.Claims[0]
			if c.Shape != tc.wantShape {
				t.Fatalf("shape=%s want %s", c.Shape, tc.wantShape)
			}
			if c.Polarity != tc.wantPolar {
				t.Fatalf("polarity=%s want %s", c.Polarity, tc.wantPolar)
			}
			if c.Source.Statement == "" {
				t.Fatal("statement must be preserved verbatim")
			}
		})
	}
}

// TestUsageCluster checks that subject+path evidence with a uniform
// negative sign rolls up to path.unreachable, and mixed signs to
// derived.
func TestUsageCluster(t *testing.T) {
	archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
		obs("det-0001", "find_references", map[string]any{"count": 0}, "PARTIAL"),
		obs("det-0002", "find_callers", map[string]any{"count": 0}, "PARTIAL"),
		obs("det-0003", "search_text", map[string]any{"count": 0}, "PARTIAL"),
	}}
	asm := assessment(
		[]any{claim("c1", "confirmed", true, "e1", "e2", "e3")},
		[]any{
			evidence("e1", "observation", "det:det-0001"),
			evidence("e2", "observation", "det:det-0002"),
			evidence("e3", "observation", "det:det-0003"),
		}, nil)
	dir := runDir(t, asm, archive, nil, stage0Doc)
	ex, err := ExtractRun(dir, "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Claims[0].Shape; got != ShapePathUnreachable {
		t.Fatalf("usage cluster shape=%s want path.unreachable", got)
	}
	if got := ex.Claims[0].Polarity; got != PolarityTrue {
		t.Fatalf("polarity=%s", got)
	}
}

// TestUnsupportedExplicit verifies every claim form outside the
// taxonomy is marked UNSUPPORTED with an explicit reason — never
// silently dropped or guessed.
func TestUnsupportedExplicit(t *testing.T) {
	t.Run("no_evidence_refs", func(t *testing.T) {
		asm := assessment([]any{claim("c1", "confirmed", true)}, nil, nil)
		ex, err := ExtractRun(runDir(t, asm, nil, nil, stage0Doc), "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		c := ex.Claims[0]
		if c.Shape != ShapeUnsupported || c.UnsupportedReason != ReasonNoEvidenceRefs {
			t.Fatalf("got %s/%s", c.Shape, c.UnsupportedReason)
		}
	})
	t.Run("weak_evidence_only", func(t *testing.T) {
		asm := assessment(
			[]any{claim("c1", "confirmed", true, "e1", "e2")},
			[]any{evidence("e1", "source_span", "internal/x.go:1-9"), evidence("e2", "file", "internal/y.go")},
			nil)
		ex, err := ExtractRun(runDir(t, asm, nil, nil, stage0Doc), "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		c := ex.Claims[0]
		if c.Shape != ShapeUnsupported || c.UnsupportedReason != ReasonWeakEvidenceOnly {
			t.Fatalf("got %s/%s", c.Shape, c.UnsupportedReason)
		}
	})
	t.Run("unresolved_reference", func(t *testing.T) {
		asm := assessment(
			[]any{claim("c1", "confirmed", true, "e1")},
			[]any{evidence("e1", "observation", "det:det-0999")},
			nil)
		archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
			obs("det-0001", "find_symbol", map[string]any{"found": true}, "COMPLETE"),
		}}
		ex, err := ExtractRun(runDir(t, asm, archive, nil, stage0Doc), "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		c := ex.Claims[0]
		if c.Shape != ShapeUnsupported || c.UnsupportedReason != ReasonUnresolvableReference {
			t.Fatalf("got %s/%s", c.Shape, c.UnsupportedReason)
		}
	})
	t.Run("unregistered_tool", func(t *testing.T) {
		asm := assessment(
			[]any{claim("c1", "confirmed", true, "e1")},
			[]any{evidence("e1", "observation", "det:det-0001")},
			nil)
		archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
			obs("det-0001", "brand_new_tool", map[string]any{"x": 1}, "COMPLETE"),
		}}
		ex, err := ExtractRun(runDir(t, asm, archive, nil, stage0Doc), "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		c := ex.Claims[0]
		if c.Shape != ShapeUnsupported || c.UnsupportedReason != ReasonUnclassifiedEvidence {
			t.Fatalf("got %s/%s", c.Shape, c.UnsupportedReason)
		}
		if len(ex.UnclassifiedTools) != 1 || ex.UnclassifiedTools[0] != "brand_new_tool" {
			t.Fatalf("unclassified tools=%v", ex.UnclassifiedTools)
		}
	})
}

// TestStatementAndVerdictAreInert proves the classifier never reads the
// claim statement, the assessment summary or the verdict: identical
// structured inputs with opposite prose/verdict must produce identical
// canonical claims.
func TestStatementAndVerdictAreInert(t *testing.T) {
	build := func(statement, verdict, summary string) string {
		c := claim("c1", "confirmed", true, "e1")
		c["statement"] = statement
		asm := assessment([]any{c}, []any{evidence("e1", "observation", "det:det-0001")}, nil)
		asm["verdict"] = verdict
		asm["summary"] = summary
		archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
			obs("det-0001", "find_callers", map[string]any{"count": 0}, "PARTIAL"),
		}}
		return runDir(t, asm, archive, nil, stage0Doc)
	}
	var shapes []CanonicalClaim
	for _, variant := range []struct{ stmt, verdict, summary string }{
		{"the vulnerable function is completely unreachable", "NOT_EXPLOITABLE", "safe"},
		{"the vulnerable function is invoked on every request", "EXPLOITABLE", "danger"},
		{"unrelated words with no semantic content", "INCONCLUSIVE", "unknown"},
	} {
		ex, err := ExtractRun(build(variant.stmt, variant.verdict, variant.summary), "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		shapes = append(shapes, ex.Claims[0])
	}
	for i, c := range shapes {
		if c.Shape != ShapePathUnreachable || c.Polarity != PolarityTrue {
			t.Fatalf("variant %d: shape=%s polarity=%s", i, c.Shape, c.Polarity)
		}
	}
	// Canonical identity ignores the prose: identical inputs ⇒
	// identical claims except the verbatim statement.
	strip := func(c CanonicalClaim) CanonicalClaim {
		c.Source.Statement = ""
		return c
	}
	a, b := strip(shapes[0]), strip(shapes[1])
	ba, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ba) != string(bb) {
		t.Fatal("claims differ across opposite statements/verdicts")
	}
}

// TestDeterminism reruns extraction over the same directory and
// requires byte-identical canonical JSON.
func TestDeterminism(t *testing.T) {
	asm := assessment(
		[]any{
			claim("c1", "confirmed", true, "e1", "e2"),
			claim("c2", "tentative", true, "e3"),
			claim("c3", "confirmed", false, "e4"),
			claim("c4", "confirmed", true),
		},
		[]any{
			evidence("e1", "observation", "det:det-0001"),
			evidence("e2", "observation", "det:det-0002"),
			evidence("e3", "observation", "search:x=0"),
			evidence("e4", "advisory", "GHSA-xxxx-yyyy-zzzz"),
		},
		[]any{map[string]any{"id": "fp-1", "claim_id": "c1", "condition_id": "cond-GHSA-xxxx-yyyy-zzzz", "kind": "code_absent",
			"subjects":      []any{map[string]any{"package": "example.com/mod/sub", "symbol": "Vuln", "role": "func"}},
			"evidence_refs": []any{"e1"}}},
	)
	archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
		obs("det-0001", "verify_code_absence", map[string]any{"checked_subjects": []any{map[string]any{"package": "p", "symbol": "S"}}, "absent_subjects": []any{map[string]any{"package": "p", "symbol": "S"}}}, "COMPLETE"),
		obs("det-0002", "find_may_callers", map[string]any{"count": 0, "possible_count": 0}, "PARTIAL"),
	}}
	falsifier := map[string]any{"schema_version": "falsifier-verification.v1", "proofs": []any{
		map[string]any{"id": "fp-1", "proposal_id": "fp-1", "claim_id": "c1", "condition_id": "cond-GHSA-xxxx-yyyy-zzzz", "kind": "code_absent", "status": "UNKNOWN", "basis": "CHECKER_VERIFIED", "mandatory": false, "coverage": map[string]any{}, "reason": "x"},
	}}
	dir := runDir(t, asm, archive, falsifier, stage0Doc)
	one, err := ExtractRun(dir, "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	two, err := ExtractRun(dir, "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(one)
	b2, _ := json.Marshal(two)
	if string(b1) != string(b2) {
		t.Fatal("extraction is not deterministic")
	}
	// Bound proposal carried the persisted proof outcome.
	bp := one.Claims[0].Parameters["bound_proposals"].([]BoundProposal)
	if len(bp) != 1 || bp[0].ProofStatus != "UNKNOWN" || bp[0].ProofBasis != "CHECKER_VERIFIED" {
		t.Fatalf("bound proposals=%+v", bp)
	}
	// A claim without decision relevance still extracts.
	if one.Claims[2].Source.DecisionRelevant {
		t.Fatal("decision_relevant must travel verbatim")
	}
}

// TestBareStringClaim verifies the legacy bare-string claim form
// extracts as decision-relevant with UNSUPPORTED/no_evidence_refs.
func TestBareStringClaim(t *testing.T) {
	asm := map[string]any{
		"schema_version": "assessment.v1",
		"finding_id":     "f",
		"verdict":        "INCONCLUSIVE",
		"claims":         []any{"a bare string claim"},
	}
	ex, err := ExtractRun(runDir(t, asm, nil, nil, nil), "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	c := ex.Claims[0]
	if !c.Source.DecisionRelevant {
		t.Fatal("bare-string claim must stay decision-relevant")
	}
	if c.Shape != ShapeUnsupported || c.UnsupportedReason != ReasonNoEvidenceRefs {
		t.Fatalf("got %s/%s", c.Shape, c.UnsupportedReason)
	}
}

// TestExtractRunCurrentV2Assessment covers the current assessment.v2
// records: the offline reader keeps the premise fields, leaves the
// historical claim_status empty, and classifies evidence exactly as before.
func TestExtractRunCurrentV2Assessment(t *testing.T) {
	asm := map[string]any{
		"schema_version": "assessment.v2",
		"finding_id":     "intake-1-test-abcdef012345",
		"verdict":        "NOT_EXPLOITABLE",
		"claims": []any{map[string]any{
			"id":                "c1",
			"statement":         "statement text never drives shape",
			"basis":             "INTERPRETED",
			"subject":           "call path",
			"scope":             "captured snapshot",
			"decision_relevant": true,
			"evidence_refs":     []string{"e1"},
			"depends_on":        []string{"c0"},
			"binding":           map[string]any{"kind": "OBSERVATION_FACT", "reference_id": "e1"},
			"owner":             "security-team",
			"reason":            "historical status is absent in v2",
			"conflicts_with":    []string{"c2"},
		}},
		"evidence": []any{evidence("e1", "observation", "det:det-0001")},
		"proposed_action": map[string]any{
			"kind": "CLOSE", "instruction": "close as not exploitable",
			"rationale": "no callers were recorded", "scope": "captured snapshot",
			"decisive_claim_ids": []string{"c1"}, "reconsider_when": []string{"callers are captured"},
		},
	}
	archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
		obs("det-0001", "find_callers", map[string]any{"count": 0, "call_sites": []any{}}, "PARTIAL"),
	}}
	ex, err := ExtractRun(runDir(t, asm, archive, nil, stage0Doc), "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Claims) != 1 {
		t.Fatalf("claims=%d", len(ex.Claims))
	}
	c := ex.Claims[0]
	if c.Shape != ShapePathUnreachable || c.Polarity != PolarityTrue {
		t.Fatalf("shape=%s polarity=%s", c.Shape, c.Polarity)
	}
	if c.Source.ClaimStatus != "" {
		t.Fatalf("v2 records must not invent a historical claim status: %q", c.Source.ClaimStatus)
	}
	if !c.Source.DecisionRelevant {
		t.Fatal("decision_relevant must travel verbatim")
	}
	if len(c.EvidenceRefs) != 1 || c.EvidenceRefs[0] != "e1" {
		t.Fatalf("evidence refs=%v", c.EvidenceRefs)
	}
}

// TestLocatorResolution covers the locator schemes the corpus produces.
func TestLocatorResolution(t *testing.T) {
	archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
		obs("obs-0003", "find_symbol", map[string]any{"found": false}, "COMPLETE"),
	}}
	for _, loc := range []string{"det:obs-0003", "obs:obs-0003", "obs-0003", "OBS_0003", "det:obs-0003@abc"} {
		asm := assessment(
			[]any{claim("c1", "confirmed", true, "e1")},
			[]any{evidence("e1", "observation", loc)}, nil)
		ex, err := ExtractRun(runDir(t, asm, archive, nil, nil), "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		c := ex.Claims[0]
		if c.Shape != ShapeSubjectAbsent {
			t.Fatalf("locator %s: shape=%s", loc, c.Shape)
		}
	}
}

// TestProposalFallbackRefs verifies a claim with no evidence_refs but a
// bound proposal classifies from the proposal's evidence_refs.
func TestProposalFallbackRefs(t *testing.T) {
	asm := assessment(
		[]any{claim("c1", "confirmed", true)},
		[]any{evidence("e1", "observation", "det:det-0001")},
		[]any{map[string]any{"id": "fp-1", "claim_id": "c1", "condition_id": "cond", "kind": "code_absent",
			"subjects": []any{map[string]any{"package": "p", "symbol": "S"}}, "evidence_refs": []any{"e1"}}})
	archive := map[string]any{"schema_version": "observation-archive.v1", "observations": []any{
		obs("det-0001", "find_callers", map[string]any{"count": 0}, "PARTIAL"),
	}}
	ex, err := ExtractRun(runDir(t, asm, archive, nil, stage0Doc), "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Claims[0].Shape; got != ShapePathUnreachable {
		t.Fatalf("shape=%s", got)
	}
}

// TestNoAssessmentRun verifies a technical-failure run extracts as
// has_assessment=false with zero claims and an explicit limitation.
func TestNoAssessmentRun(t *testing.T) {
	dir := runDir(t, nil, nil, nil, stage0Doc)
	ex, err := ExtractRun(dir, "CASE-T")
	if err != nil {
		t.Fatal(err)
	}
	if ex.HasAssessment {
		t.Fatal("has_assessment must be false")
	}
	if len(ex.Claims) != 0 {
		t.Fatal("claims must be empty")
	}
	if len(ex.Limitations) == 0 {
		t.Fatal("limitation must be recorded")
	}
}

// TestVersionInRange unit-tests the range evaluation.
func TestVersionInRange(t *testing.T) {
	ranges := []VersionRange{{Introduced: "0", Fixed: "1.5.0"}, {Introduced: "2.0.0", LastAffected: "2.3.9"}}
	cases := []struct {
		v      string
		want   bool
		wantOK bool
	}{
		{"v1.2.0", true, true},
		{"1.2.0", true, true},
		{"v1.5.0", false, true},
		{"v2.3.9", true, true},
		{"v2.4.0", false, true},
		{"garbage", false, false},
	}
	for _, tc := range cases {
		got, ok := VersionInRange(tc.v, ranges)
		if got != tc.want || ok != tc.wantOK {
			t.Fatalf("%s: got %v,%v want %v,%v", tc.v, got, ok, tc.want, tc.wantOK)
		}
	}
}

// TestDecisionLabelsSeparateJudgmentAndMachineDisposition pins the
// decision.json projection: decision-package.v3 exposes the model judgment
// and the machine recommendation as separate labels, while an explicitly
// historical decision-package.v2 record still yields its retired top-level
// recommendation and internal status. Extraction reports either shape as a
// label and never re-derives or re-admits it.
func TestDecisionLabelsSeparateJudgmentAndMachineDisposition(t *testing.T) {
	t.Run("decision-package.v3", func(t *testing.T) {
		dir := runDir(t, assessment(nil, nil, nil), nil, nil, stage0Doc)
		writeJSON(t, dir, "decision.json", map[string]any{
			"schema_version":      "decision-package.v3",
			"run_id":              "run-v3",
			"finding_id":          "intake-1-test-abcdef012345",
			"judgment":            map[string]any{"verdict": "NOT_EXPLOITABLE"},
			"machine_disposition": map[string]any{"recommendation": "UNCHANGED"},
		})
		ex, err := ExtractRun(dir, "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		if ex.Judgment != "NOT_EXPLOITABLE" {
			t.Fatalf("judgment label = %q", ex.Judgment)
		}
		if ex.Recommendation != "UNCHANGED" {
			t.Fatalf("machine recommendation label = %q", ex.Recommendation)
		}
		if ex.InternalStatus != "" {
			t.Fatalf("v3 carries no internal status, got %q", ex.InternalStatus)
		}
	})
	t.Run("historical decision-package.v2", func(t *testing.T) {
		dir := runDir(t, assessment(nil, nil, nil), nil, nil, stage0Doc)
		writeJSON(t, dir, "decision.json", map[string]any{
			"schema_version":       "decision-package.v2",
			"run_id":               "run-v2",
			"finding_id":           "intake-1-test-abcdef012345",
			"recommendation":       "LOWERED",
			"technical_assessment": map[string]any{"internal_status": "INCONCLUSIVE"},
		})
		ex, err := ExtractRun(dir, "CASE-T")
		if err != nil {
			t.Fatal(err)
		}
		if ex.Recommendation != "LOWERED" || ex.InternalStatus != "INCONCLUSIVE" {
			t.Fatalf("historical labels = %q/%q", ex.Recommendation, ex.InternalStatus)
		}
		if ex.Judgment != "" {
			t.Fatalf("history carries no v3 judgment, got %q", ex.Judgment)
		}
	})
}
