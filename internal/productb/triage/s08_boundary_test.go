package triage

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// S-08 acceptance tests: the composer/policy boundary the merge brief
// pins explicitly. Each test names the invariant in §14.5/§14.6 it proves.

// TestDecisionPackageHasNoPolicyOutcome: §14.5 — policy_outcome is not a
// DecisionPackage field. Pinned structurally (no Go field that could
// serialize as policy_outcome/automation/policy) and on the wire (the
// emitted JSON carries no such key).
func TestDecisionPackageHasNoPolicyOutcome(t *testing.T) {
	rt := reflect.TypeOf(DecisionPackage{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		name := strings.ToLower(f.Name + " " + f.Tag.Get("json"))
		if strings.Contains(name, "policy") || strings.Contains(name, "automation") {
			t.Fatalf("DecisionPackage field %s must not encode a policy outcome", f.Name)
		}
	}
	pkg := composeOrFail(t, goodStage0(), goodAssessment(), completeValidation())
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for key := range doc {
		if strings.Contains(strings.ToLower(key), "policy") || strings.Contains(strings.ToLower(key), "automation") {
			t.Fatalf("decision-package.v3 must not serialize %q", key)
		}
	}
	// And symmetric: a document smuggling policy_outcome in fails decode.
	raw := `{"schema_version":"decision-package.v3","run_id":"r","finding_id":"f","execution_mode":"single","policy_outcome":"ALLOW"}`
	var p DecisionPackage
	if err := json.Unmarshal([]byte(raw), &p); err == nil {
		t.Fatal("decision-package.v3 must reject a policy_outcome field")
	}
}

// TestNoAutoDismissalByDefault: the adapter exposes no auto-dismissal
// path — RecommendationDismissed exists only where an admitted decision
// rule fires on verified facts, and the agent's own assessment/automation
// fields can never inject one. Here: a run whose decision facts conflict
// (no reduction basis) must stay UNCHANGED even when the agent's verdict
// asks for the reduction.
func TestNoAutoDismissalByDefault(t *testing.T) {
	s0 := versionRangeStage0(CheckVersionMismatch)
	a := goodAssessment()
	a.Verdict = VerdictNotExploitable
	pkg := composeOrFail(t, s0, a, completeValidation())
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatal("no path may auto-dismiss")
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("recommendation = %s, want UNCHANGED on conflict", pkg.MachineDisposition.Recommendation)
	}
}

// TestUnverifiedReductionStaysUnchanged: an agent-written reduction the
// deterministic basis cannot verify is demoted to UNCHANGED — never
// silently admitted. Compose path: agent says EXPLOITABLE, package-check
// facts are missing → any reduction stays blocked.
func TestUnverifiedReductionStaysUnchanged(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{Class: CheckUnresolved} // unverified ground
	a := goodAssessment()
	a.Verdict = VerdictNotExploitable // agent claims a reduction
	pkg := composeOrFail(t, s0, a, completeValidation())
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed || pkg.MachineDisposition.Recommendation == RecommendationLowered {
		t.Fatalf("unverified reduction must not pass: %s", pkg.MachineDisposition.Recommendation)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("recommendation = %s, want UNCHANGED", pkg.MachineDisposition.Recommendation)
	}
}

// TestTechnicalErrorStaysOnErrorChannel: a composition-time technical
// failure is an error return, never a packaged UNCHANGED that CI could
// misread as "verified no change" — and a missing severity is not one of
// those failures: it yields a human package with a withheld machine
// disposition instead.
func TestTechnicalErrorStaysOnErrorChannel(t *testing.T) {
	if _, err := ComposeDecision(context.Background(), noSeverityStage0(), goodAssessment(), completeValidation(), nil, nil); err != nil {
		t.Fatalf("a missing baseline must still deliver the human package: %v", err)
	}
	a := goodAssessment()
	a.Verdict = "SOME_VERDICT"
	if _, err := ComposeDecision(context.Background(), goodStage0(), a, completeValidation(), nil, nil); err == nil {
		t.Fatal("an invalid judgment verdict must return a technical error, not a package")
	}
}

// TestExitCodeSemantics: exit 0 pass, exit 1 on a policy threshold hit,
// exit 2 on technical/integrity error — and never the reverse.
func TestExitCodeSemantics(t *testing.T) {
	if ExitCodePolicy != 1 || ExitCodeError != 2 || ExitCodeOK != 0 {
		t.Fatalf("exit codes = %d/%d/%d", ExitCodeOK, ExitCodePolicy, ExitCodeError)
	}
	// A policy hit on a completed package is exit 1...
	pkg := composeOrFail(t, versionRangeStage0(CheckVersionMismatch), goodAssessment(), completeValidation())
	if !PackagePolicyHit(pkg, FailOnUnchanged) || pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("fixture should trip FailOnUnchanged: %+v", pkg.TechnicalAssessment)
	}
	// ...while an unknown threshold is a technical error (exit 2), not a hit.
	if _, err := ParseFailOn("auto-dismiss"); err == nil {
		t.Fatal("unknown --fail-on must fail closed")
	}
}

// TestVEXProjectionBoundary: the projection is default-off
// (triage_only=true is mandatory), non-authoritative, and denied for any
// non-DISMISSED package or a dismissal without decisive basis.
func TestVEXProjectionBoundary(t *testing.T) {
	// UNCHANGED package → denied.
	unchanged := composeOrFail(t, versionRangeStage0(CheckVersionMismatch), goodAssessment(), completeValidation())
	if _, err := ProjectVEX(unchanged); !errors.Is(err, ErrVEXProjectionDenied) {
		t.Fatalf("UNCHANGED package projection = %v, want ErrVEXProjectionDenied", err)
	}
	// A projection that lies about triage_only is invalid.
	p := VEXProjection{
		SchemaVersion:  VEXProjectionSchemaVersion,
		FindingID:      "f",
		Recommendation: RecommendationDismissed,
		Status:         vexStatusNotAffected,
		Justification:  vexJustificationComponentNotPresent,
		Provenance:     []string{"decision:abc"},
		TriageOnly:     false,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("triage_only=false must fail validation")
	}
	p.TriageOnly = true
	if err := p.Validate(); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}
}

// TestDecisionPackageFieldPresence: §14.5's canonical field set on the
// wire — every required key present, and no extra key at the top level.
func TestDecisionPackageFieldPresence(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class:       CheckModuleAbsent,
		ClaimedPath: "example.org/library",
		Reason:      "module absent from product graph",
	}
	pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{
		"schema_version", "run_id", "finding_id", "execution_mode",
		"scope", "judgment", "proposed_action", "premises", "support",
		"technical_assessment", "machine_disposition", "facts", "audit", "human_review_plan",
	}
	for _, k := range want {
		if _, ok := doc[k]; !ok {
			t.Fatalf("decision-package.v3 missing required key %q (have %v)", k, doc)
		}
	}
	if doc["schema_version"] != DecisionPackageSchemaVersion {
		t.Fatalf("schema_version = %v", doc["schema_version"])
	}
	allowed := map[string]bool{}
	for _, k := range want {
		allowed[k] = true
	}
	allowed["falsifier_proofs"] = true // optional
	for k := range doc {
		if !allowed[k] {
			t.Fatalf("unexpected top-level key %q in decision-package.v3", k)
		}
	}
}

// TestModelRecordIDsCannotWidenDecisionScope: the model's record_ids are
// text it considered, not record identity. The package scope and the human
// card are projected from the recorded Stage 0 evidence alone, so a
// model-named record the run never captured cannot widen the conclusion to
// a CVE-wide or foreign claim.
func TestModelRecordIDsCannotWidenDecisionScope(t *testing.T) {
	s0 := goodStage0()
	a := supportAssessment(nil, []Claim{{
		ID:               "c1",
		Statement:        "the captured advisory does not apply to the recorded build",
		Basis:            PremiseInterpreted,
		Subject:          "advisory applicability",
		Scope:            "captured advisory record",
		DecisionRelevant: true,
	}}, nil, "c1")
	a.ProposedAction.RecordIDs = []string{"CVE-9999-9999", "GHSA-foreign-record"}
	pkg := composeOrFail(t, s0, a, completeValidation())

	if pkg.Scope.Boundary != DecisionBoundaryExactRecords {
		t.Fatalf("boundary = %q", pkg.Scope.Boundary)
	}
	if len(pkg.Scope.Records) != 1 || pkg.Scope.Records[0].ID != "CVE-2099-0001" ||
		pkg.Scope.Records[0].SHA256 != s0.Advisory.SHA256 {
		t.Fatalf("scope records = %+v, want only the captured record", pkg.Scope.Records)
	}
	for _, requested := range pkg.Scope.RequestedIDs {
		if requested == "CVE-9999-9999" || requested == "GHSA-foreign-record" {
			t.Fatalf("model record id widened the requested ids: %v", pkg.Scope.RequestedIDs)
		}
	}
	card := string(RenderDecisionMarkdown(pkg))
	scopeStart := strings.Index(card, "## Decision scope")
	scopeEnd := strings.Index(card, "## Decisive measured and proved facts")
	if scopeStart < 0 || scopeEnd <= scopeStart {
		t.Fatalf("card lacks the decision scope section:\n%s", card)
	}
	scopeSection := card[scopeStart:scopeEnd]
	for _, foreign := range []string{"CVE-9999-9999", "GHSA-foreign-record"} {
		if strings.Contains(scopeSection, foreign) {
			t.Fatalf("decision scope presented model-named record %q as captured: %s", foreign, scopeSection)
		}
	}
	if !strings.Contains(scopeSection, "CVE-2099-0001") || !strings.Contains(scopeSection, s0.Advisory.SHA256) {
		t.Fatalf("decision scope does not show the recorded record:\n%s", scopeSection)
	}
}
