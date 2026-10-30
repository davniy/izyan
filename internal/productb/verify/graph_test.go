package verify

import (
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// --- fixtures ---

func advisoryWithSymbols() claimshape.AdvisoryFacts {
	return claimshape.AdvisoryFacts{
		ResolvedID: "ADV-1",
		IDs:        []string{"ADV-1"},
		AffectedSymbols: []claimshape.Subject{
			{Kind: claimshape.SubjectSymbol, Package: "dep/pkg", Symbol: "Victim", Name: "dep/pkg.Victim"},
		},
	}
}

// presenceObs is a recorded verify_code_absence check that found the
// subject — a counterexample to subject.absent. mutate, when given,
// may adjust the record (id, completeness, context pins).
func presenceObs(mutate ...func(*triage.RecordedObservation)) triage.RecordedObservation {
	o := triage.RecordedObservation{
		ID: "det-2", Tool: "verify_code_absence", Status: "OK",
		Completeness: evidencetools.CompletenessComplete,
		Payload: json.RawMessage(`{
			"tool":"verify_code_absence","fact":"subject present","scope":"closure","completeness":"COMPLETE","tool_status":"OK",
			"data":{
				"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
				"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
				"present_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
				"coverage_rule":"closed","coverage_rule_version":"4",
				"snapshot_hash":"snap-1","build_context_hash":"bc-1",
				"import_closure":{"complete":true,"hash":"closure-2","scope_hash":"scope-2"}
			},
			"scope_details":{"snapshot_hash":"snap-1","build_context":{"goos":"linux"}}
		}`),
		DataSHA256:   "sha-2",
		SnapshotHash: "snap-1", BuildContextHash: "bc-1",
		RunID: "run-1", Attempt: 1,
	}
	for _, m := range mutate {
		m(&o)
	}
	return o
}

// partialPresenceObs is a PARTIAL counterexample: the subject was found
// inside a non-closed check — the existential refutation stands without
// any scope.closed conjunction.
func partialPresenceObs() triage.RecordedObservation {
	return presenceObs(func(o *triage.RecordedObservation) {
		o.Completeness = evidencetools.CompletenessPartial
		o.Payload = json.RawMessage(`{"data":{"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"present_subjects":[{"package":"dep/pkg","symbol":"Victim"}]}}`)
	})
}

func versionClaim() claimshape.CanonicalClaim {
	return claimshape.CanonicalClaim{
		ID: "c-ver", Shape: claimshape.ShapeApplicabilityVersionInRange, Polarity: claimshape.PolarityTrue,
		Subject:   claimshape.Subject{Kind: claimshape.SubjectModule, Name: "dep"},
		Predicate: claimshape.ShapePredicate(claimshape.ShapeApplicabilityVersionInRange),
		Parameters: map[string]any{
			"module":           "dep",
			"resolved_version": "v1.2.3",
			"affected_ranges": []claimshape.VersionRange{
				{Introduced: "v1.0.0", Fixed: "v1.3.0"},
			},
		},
		Scope:                claimshape.Scope{Completeness: "COMPLETE", SnapshotHash: "snap-1", BuildContextHash: "bc-1"},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeApplicabilityVersionInRange),
	}
}

func perimeterClaim() claimshape.CanonicalClaim {
	return claimshape.CanonicalClaim{
		ID: "c-per", Shape: claimshape.ShapePerimeterExposure, Polarity: claimshape.PolarityTrue,
		Subject:              claimshape.Subject{Kind: claimshape.SubjectModule, Name: "dep"},
		Predicate:            claimshape.ShapePredicate(claimshape.ShapePerimeterExposure),
		Scope:                claimshape.Scope{Completeness: "COMPLETE", SnapshotHash: "snap-1", BuildContextHash: "bc-1"},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapePerimeterExposure),
	}
}

// locusProof builds a VERIFIED locus_function_unreached certificate —
// the kernel's negative-verification artifact — bound to condition id.
func locusProof(id, condID string, subjects []triage.FalsifierSubject) triage.FalsifierProof {
	return triage.FalsifierProof{
		ID: id, ConditionID: condID,
		Kind:   triage.FalsifierLocusFunctionAbsent,
		Status: triage.FalsifierVerified, Basis: triage.BasisCheckerVerified,
		Mandatory:    true,
		RuleID:       triage.UnreachabilityRuleID,
		RuleVersion:  "1",
		EvidenceRefs: []string{"det-kernel"},
		Coverage: triage.FalsifierCoverage{
			Scope: "closure", Completeness: "COMPLETE",
			SnapshotHash:     "snap-1",
			BuildContextHash: "bc-1",
			ExpectedSubjects: subjects,
			CheckedSubjects:  subjects,
			AbsentSubjects:   subjects,
		},
		History: []triage.FalsifierTransition{
			{From: triage.FalsifierUnknown, To: triage.FalsifierVerified, Reason: "kernel closed"},
		},
	}
}

func proofReport(proofs ...triage.FalsifierProof) *triage.FalsifierReport {
	r := &triage.FalsifierReport{
		SchemaVersion: triage.FalsifierVerificationSchemaVersion,
		RuleSetHash:   "rules-1",
		Proofs:        proofs,
	}
	r.Hash = "report-stub"
	return r
}

func graphOf(t *testing.T, rep Report) *Graph {
	t.Helper()
	if rep.Graph == nil {
		t.Fatal("report carries no entailment graph")
	}
	return rep.Graph
}

func condOf(g *Graph, id string) *GraphCondition {
	for i := range g.Conditions {
		if g.Conditions[i].ID == id {
			return &g.Conditions[i]
		}
	}
	return nil
}

func nodeValue(g *Graph, id string) string {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n.Value
		}
	}
	return ""
}

func hasEdge(rep Report, kind, from, to string) bool {
	for _, e := range rep.Edges {
		if e.Kind == kind && e.From == from && e.To == to {
			return true
		}
	}
	return false
}

// --- entailment rules ---

func TestGraphEntailsAndDismissesAbsence(t *testing.T) {
	c := absentClaim()
	in := baseInput(c, absenceObs(t, nil))
	in.Advisory = advisoryWithSymbols()
	rep := Evaluate(in)
	g := graphOf(t, rep)

	ev := rep.ClaimOutcomeOf("c-1")
	if ev.Outcome != OutcomeTrue || ev.Predicate != PredicateHolds {
		t.Fatalf("absence claim = %+v", ev)
	}
	if nodeValue(g, "claim:c-1") != string(OutcomeTrue) {
		t.Fatalf("claim node = %q", nodeValue(g, "claim:c-1"))
	}
	found := false
	for _, e := range rep.Edges {
		if e.Kind == "supports" && e.To == "c-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("no supports edge into the claim")
	}
	cond := condOf(g, triage.AdvisoryConditionID("ADV-1"))
	if cond == nil || cond.Mandatory == "" || cond.Mandatory == "unresolved" {
		t.Fatalf("advisory condition = %+v", cond)
	}
	if cond.Value != "FALSE" || len(cond.Falsifiers) == 0 {
		t.Fatalf("condition not falsified: %+v", cond)
	}
	if rep.Decision().Disposition != "DISMISSED" || rep.Decision().Rule != ruleMandatoryFalsifier {
		t.Fatalf("decision = %+v", rep.Decision())
	}
	if nodeValue(g, "decision:f-1") != "DISMISSED" {
		t.Fatalf("decision node = %q", nodeValue(g, "decision:f-1"))
	}
}

func TestConflictBlocksDismissal(t *testing.T) {
	c := absentClaim()
	c.EvidenceRefs = []string{"det-1", "det-2"}
	in := baseInput(c, absenceObs(t, nil), presenceObs())
	in.Advisory = advisoryWithSymbols()
	rep := Evaluate(in)
	g := graphOf(t, rep)

	ev := rep.ClaimOutcomeOf("c-1")
	if ev.Predicate != PredicateConflicting || ev.Outcome != OutcomeConflicting {
		t.Fatalf("conflicting claim = %+v", ev)
	}
	if cond := condOf(g, triage.AdvisoryConditionID("ADV-1")); cond != nil && cond.Value == "FALSE" {
		t.Fatalf("conflict falsified the condition: %+v", cond)
	}
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("conflict decided: %+v", rep.Decision())
	}
	// The contradicts edge records the evidence clash for audit.
	found := false
	for _, e := range rep.Edges {
		if e.Kind == "contradicts" {
			found = true
		}
	}
	if !found {
		t.Fatal("no contradicts edge recorded")
	}
}

func TestPartialAbsenceNeverDismisses(t *testing.T) {
	c := absentClaim()
	o := absenceObs(t, func(o *triage.RecordedObservation) {
		o.Completeness = evidencetools.CompletenessPartial
	})
	in := baseInput(c, o)
	in.Advisory = advisoryWithSymbols()
	rep := Evaluate(in)
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("PARTIAL absence dismissed: %+v", rep.Decision())
	}
	if rep.ClaimOutcomeOf("c-1").Outcome != OutcomeUnknown {
		t.Fatalf("PARTIAL absence adjudicated: %+v", rep.ClaimOutcomeOf("c-1"))
	}
}

// --- certificates: proposal is diagnostic, never admission ---

func TestDismissedByClaimlessKernelProof(t *testing.T) {
	// The checker-minted kernel proof carries no proposal; a verified
	// mandatory certificate covering the advisory's locus still
	// dismisses — proposal presence is never admission.
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(locusProof("det-kernel-1", triage.AdvisoryConditionID("ADV-1"), subjects))
	rep := Evaluate(in)
	g := graphOf(t, rep)

	if cond := condOf(g, triage.AdvisoryConditionID("ADV-1")); cond == nil || cond.Value != "FALSE" {
		t.Fatalf("advisory condition not falsified by kernel proof: %+v", cond)
	}
	if rep.Decision().Disposition != "DISMISSED" {
		t.Fatalf("kernel proof did not dismiss: %+v", rep.Decision())
	}
}

func TestDismissedByCoverageBoundCertificate(t *testing.T) {
	// A proposal-less certificate names no known condition but covers
	// the advisory's declared locus — coverage binding falsifies it
	// without any proposal in the run.
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	p := locusProof("det-kernel-9", "cond-unrelated", subjects)
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(p)
	rep := Evaluate(in)
	if rep.Decision().Disposition != "DISMISSED" {
		t.Fatalf("coverage-bound certificate did not dismiss: %+v", rep.Decision())
	}
}

func TestDismissedByVerifiedCertificateWithProposal(t *testing.T) {
	// The proposal path stays supported: a proof bound to the claim's
	// own proposal falsifies the proposal's condition.
	c := absentClaim()
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	p := locusProof("fp-1", "cond-1", subjects)
	p.ProposalID = "fp-1"
	p.ClaimID = "c-1"
	c.Parameters = map[string]any{
		"bound_proposals": []any{map[string]any{
			"id": "fp-1", "condition_id": "cond-1", "kind": "locus_function_unreached",
			"check_shape": "subject.absent",
			"subjects":    []any{map[string]any{"package": "dep/pkg", "symbol": "Victim", "kind": "symbol"}},
		}},
	}
	in := baseInput(c)
	in.Falsifiers = proofReport(p)
	rep := Evaluate(in)
	if rep.Decision().Disposition != "DISMISSED" {
		t.Fatalf("proposal-bound proof did not dismiss: %+v", rep.Decision())
	}
}

func TestViolatedCertificateNeverDismisses(t *testing.T) {
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	p := locusProof("det-kernel-2", triage.AdvisoryConditionID("ADV-1"), subjects)
	p.Coverage.SkippedPackages = []string{"dep/skipped"}
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(p)
	rep := Evaluate(in)
	if rep.Decision().Disposition == "DISMISSED" {
		t.Fatalf("violated certificate dismissed: %+v", rep.Decision())
	}
}

func TestContradictedCertificateNeverDismisses(t *testing.T) {
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	p := locusProof("det-kernel-3", triage.AdvisoryConditionID("ADV-1"), subjects)
	p.Status = triage.FalsifierContradicted
	p.Coverage.PresentSubjects = subjects
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(p)
	rep := Evaluate(in)
	if rep.Decision().Disposition == "DISMISSED" {
		t.Fatalf("contradicted certificate dismissed: %+v", rep.Decision())
	}
}

func TestUnverifiedCertificateNeverDismisses(t *testing.T) {
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	p := locusProof("det-kernel-4", triage.AdvisoryConditionID("ADV-1"), subjects)
	p.Status = triage.FalsifierInsufficientScope
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(p)
	rep := Evaluate(in)
	if rep.Decision().Disposition == "DISMISSED" {
		t.Fatalf("unverified certificate dismissed: %+v", rep.Decision())
	}
}

// --- decision compiler ---

func TestLoweredByClosedPerimeterRule(t *testing.T) {
	in := baseInput(versionClaim())
	in.Claims = append(in.Claims, perimeterClaim())
	in.Deploy = &triage.DeployFacts{
		Perimeter: "cluster-internal", SHA256: "dep-sha", Rationale: "no inbound listener",
	}
	rep := Evaluate(in)

	if rep.ClaimOutcomeOf("c-ver").Predicate != PredicateHolds {
		t.Fatalf("applicability = %+v", rep.ClaimOutcomeOf("c-ver"))
	}
	if rep.ClaimOutcomeOf("c-per").Predicate != PredicateDisproved {
		t.Fatalf("perimeter = %+v", rep.ClaimOutcomeOf("c-per"))
	}
	if rep.Decision().Disposition != "LOWERED" || rep.Decision().Rule != ruleClosedPerimeter {
		t.Fatalf("decision = %+v", rep.Decision())
	}
	// The rule premises name the claims it consumed.
	if len(rep.Decision().Premises) != 2 {
		t.Fatalf("lowered premises = %+v", rep.Decision())
	}
}

func TestUnchangedWithoutSatisfiedRules(t *testing.T) {
	// A claim with no observations and a bare proposal never moves:
	// the proposal is diagnostic, and no generic rule fires.
	c := absentClaim()
	c.EvidenceRefs = nil
	c.Parameters = map[string]any{
		"bound_proposals": []any{map[string]any{
			"id": "fp-9", "condition_id": "cond-9", "kind": "code_absent",
		}},
	}
	rep := Evaluate(baseInput(c))
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("unsupported proposal moved the decision: %+v", rep.Decision())
	}
}

func TestDismissedDoesNotDependOnLLMVerdictOrProposal(t *testing.T) {
	// No claim, no proposal, no LLM verdict anywhere in the input —
	// the certificate alone drives DISMISSED.
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(locusProof("det-kernel-5", triage.AdvisoryConditionID("ADV-1"), subjects))
	first := Evaluate(in)
	if first.Decision().Disposition != "DISMISSED" {
		t.Fatalf("decision = %+v", first.Decision())
	}
	// Adding a claim that carries a proposal but contradicting evidence
	// must not change the certificate's authority — and symmetrically,
	// dropping the claim must not change it either. The verdict never
	// enters Input at all: there is no field for it.
	in.Claims = []claimshape.CanonicalClaim{absentClaim()}
	second := Evaluate(in)
	if second.Decision().Disposition != first.Decision().Disposition {
		t.Fatalf("decision changed with a proposal-less claim: %+v vs %+v", first.Decision(), second.Decision())
	}
}

// --- derived claims ---

func TestDerivedMandatoryConditionClaim(t *testing.T) {
	c := absentClaim()
	d := claimshape.CanonicalClaim{
		ID: "c-derived", Shape: claimshape.ShapeDerivedMandatoryCondition, Polarity: claimshape.PolarityTrue,
		Parameters: map[string]any{
			"premise_families": []string{"subject"},
		},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeDerivedMandatoryCondition),
	}
	in := baseInput(c, absenceObs(t, nil))
	in.Claims = append(in.Claims, d)
	rep := Evaluate(in)
	ev := rep.ClaimOutcomeOf("c-derived")
	if ev.Outcome != OutcomeTrue || ev.Predicate != PredicateHolds {
		t.Fatalf("derived condition = %+v", ev)
	}
	if !hasEdge(rep, "depends_on", "claim:c-derived", "claim:c-1") {
		t.Fatal("no depends_on edge to the premise")
	}
}

func TestDerivedConditionFalseWhenPremiseFalse(t *testing.T) {
	// A claim asserting presence refuted by closed absence evidence is
	// FALSE — the derived conjunction inherits it.
	pres := claimshape.CanonicalClaim{
		ID: "c-pres", Shape: claimshape.ShapeSubjectAbsent, Polarity: claimshape.PolarityFalse,
		Subject:              absentClaim().Subject,
		Predicate:            claimshape.ShapePredicate(claimshape.ShapeSubjectAbsent),
		Scope:                absentClaim().Scope,
		EvidenceRefs:         []string{"det-1"},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeSubjectAbsent),
	}
	d := claimshape.CanonicalClaim{
		ID: "c-derived", Shape: claimshape.ShapeDerivedMandatoryCondition, Polarity: claimshape.PolarityTrue,
		Parameters:           map[string]any{"premise_families": []string{"subject"}},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeDerivedMandatoryCondition),
	}
	in := baseInput(pres, absenceObs(t, nil))
	in.Claims = append(in.Claims, d)
	rep := Evaluate(in)
	ev := rep.ClaimOutcomeOf("c-derived")
	if ev.Outcome != OutcomeFalse || ev.Predicate != PredicateDisproved {
		t.Fatalf("derived condition = %+v", ev)
	}
}

func TestDerivedTriageDispositionClaim(t *testing.T) {
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	d := claimshape.CanonicalClaim{
		ID: "c-disp", Shape: claimshape.ShapeDerivedTriageDisposition, Polarity: claimshape.PolarityTrue,
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeDerivedTriageDisposition),
	}
	in := baseInput(d)
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(locusProof("det-kernel-6", triage.AdvisoryConditionID("ADV-1"), subjects))
	rep := Evaluate(in)
	ev := rep.ClaimOutcomeOf("c-disp")
	if ev.Outcome != OutcomeTrue {
		t.Fatalf("disposition claim after DISMISSED = %+v", ev)
	}
	// UNCHANGED compiles to FALSE for a TRUE-polarity disposition claim.
	rep2 := Evaluate(baseInput(d))
	if rep2.ClaimOutcomeOf("c-disp").Outcome != OutcomeFalse {
		t.Fatalf("disposition claim after UNCHANGED = %+v", rep2.ClaimOutcomeOf("c-disp"))
	}
}

// --- determinism and schema stability ---

func TestGraphDeterministic(t *testing.T) {
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	mk := func() Report {
		c := absentClaim()
		in := baseInput(c, absenceObs(t, nil))
		in.Advisory = advisoryWithSymbols()
		in.Falsifiers = proofReport(locusProof("det-kernel-7", triage.AdvisoryConditionID("ADV-1"), subjects))
		return Evaluate(in)
	}
	a, b := mk(), mk()
	if a.Hash != b.Hash {
		t.Fatalf("hash drift: %s vs %s", a.Hash, b.Hash)
	}
	ja, _ := json.Marshal(a.Graph)
	jb, _ := json.Marshal(b.Graph)
	if string(ja) != string(jb) {
		t.Fatal("graph serialization drifted")
	}
}

func TestSchemaVersionAndBackwardCompatibleFields(t *testing.T) {
	rep := Evaluate(baseInput(absentClaim(), absenceObs(t, nil)))
	if rep.SchemaVersion != ContractSchemaVersion {
		t.Fatalf("schema version = %q", rep.SchemaVersion)
	}
	var m map[string]any
	if err := json.Unmarshal(mustMarshal(t, rep), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "claims", "hash"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("report missing key %q", k)
		}
	}
	// Graph is additive: older consumers ignore it.
	if _, ok := m["graph"]; !ok {
		t.Fatal("graph must serialize as an additive field")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
