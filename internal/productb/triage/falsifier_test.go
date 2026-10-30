package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
)

type testMandatorySource struct {
	condition MandatoryCondition
	err       error
	lookups   []MandatoryConditionLookup
}

func (s *testMandatorySource) Resolve(_ context.Context, l MandatoryConditionLookup) (MandatoryCondition, error) {
	s.lookups = append(s.lookups, l)
	return s.condition, s.err
}
func (s *testMandatorySource) RuleSetHash() string { return "rules-1" }

func verifierFixture(kind FalsifierKind, src MandatoryConditionSource) (FalsifierVerificationInput, *RecordedObservation) {
	snap := "snap-1"
	subjects := []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}}
	p := FalsifierProposal{ID: "fp-1", ClaimID: "c-1", ConditionID: "cond-1", Kind: kind, Subjects: subjects, EvidenceRefs: []string{"det-1"}}
	inventory, buildHash := currentInventoryFixture(snap)
	payload, _ := json.Marshal(map[string]any{
		"checked_subjects": subjects, "absent_subjects": subjects, "coverage_rule_version": evidencetools.CodeAbsenceCoverageRuleVersion,
		"import_closure": map[string]any{
			"inventory_raw":inventory.InventoryRaw, "inventory_reference":inventory.InventoryReference,
			"inventory_build":inventory.InventoryBuild, "inventory_run":inventory.InventoryRun, "inventory_scope":inventory.InventoryScope,
			"complete": true, "hash": "closure-test-hash", "open_exceptions": []string{}, "closed_exceptions": []string{},
			"scope_rule": evidencetools.CodeAbsenceScopeRule, "scope_complete": true, "scope_hash": "scope-test-hash", "shipping_roots": []string{"cmd/app"}, "package_states": map[string]string{"cmd/app": "LIVE"}, "scope_unknown": []string{}, "discarded_unreachable": []string{},
			"dynamic_relevance_rule": evidencetools.CodeAbsenceDynamicRule, "dynamic_relevance_complete": true, "observed_dynamic_markers": []string{}, "ignored_dynamic_markers": []string{},
		},
	})
	o := &RecordedObservation{ID: "det-1", Tool: "verify_code_absence", Status: ToolStatusOK, Completeness: evidencetools.CompletenessComplete, Scope: "snapshot", EvidenceRefs: []string{"det-1"}, Payload: payload, SnapshotHash: snap, BuildContextHash: buildHash, RunID: "run-1", Attempt: 1}
	in := FalsifierVerificationInput{Stage0: Stage0Result{Input: FindingInput{Finding: Finding{Vulnerability: Vulnerability{IDs: []string{"ADV-1"}}, Component: Component{Package: "example.org/mod", Version: "v1.0.0"}}}, Snapshot: SnapshotManifest{ContentHash: snap}}, Assessment: Assessment{Claims: []Claim{{ID: "c-1", DecisionRelevant: true, EvidenceRefs: []string{"det-1"}}}}, FactValidation: FactValidation{Status: ValidationComplete, References: []ReferenceCheck{{EvidenceID: "det-1", Status: FactValid, SnapshotHash: snap}}}, Proposals: []FalsifierProposal{p}, Observations: []RecordedObservation{*o}, RulesetHash: "rules-1", ExpectedRulesetHash: "rules-1", RunID: "run-1", Attempt: 1}
	_ = src
	return in, o
}
func sourceFixture() *testMandatorySource {
	_, buildHash := currentInventoryFixture("snap-1")
	return &testMandatorySource{condition: MandatoryCondition{ID: "cond-1", Kind: FalsifierCodeAbsent, Mandatory: true, RuleID: "rule-1", RuleVersion: "v1", ExpectedSubjects: []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}}, SnapshotHash: "snap-1", BuildContextHash: buildHash}}
}
func runProof(t *testing.T, in FalsifierVerificationInput, s MandatoryConditionSource) FalsifierProof {
	t.Helper()
	return NewFalsifierVerifier(s).Verify(context.Background(), in).Proofs[0]
}

func TestFalsifierVerifierVerified(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	p := runProof(t, in, s)
	if p.Status != FalsifierVerified || p.Basis != BasisCheckerVerified || !p.Mandatory || p.Coverage.Completeness != "COMPLETE" {
		t.Fatalf("proof=%+v", p)
	}
}
func TestFalsifierVerifierMandatorySourceBinding(t *testing.T) {
	s := sourceFixture()
	s.condition.SnapshotHash = "other"
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified || p.Mandatory {
		t.Fatalf("source mismatch admitted: %+v", p)
	}
}
func TestFalsifierVerifierSubjectSetComplete(t *testing.T) {
	s := sourceFixture()
	s.condition.ExpectedSubjects = append(s.condition.ExpectedSubjects, FalsifierSubject{Package: "example.org/p", Symbol: "Wrapper"})
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("incomplete subject set admitted")
	}
}
func TestFalsifierVerifierProofHash(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	v := NewFalsifierVerifier(s)
	a, b := v.Verify(context.Background(), in), v.Verify(context.Background(), in)
	if a.Hash != b.Hash {
		t.Fatal("hash not deterministic")
	}
	in.Observations[0].BuildContextHash = "changed"
	c := v.Verify(context.Background(), in)
	if c.Hash == a.Hash {
		t.Fatal("hash ignored semantic coverage")
	}
	s.condition.RuleVersion = "v2"
	d := v.Verify(context.Background(), in)
	if d.Hash == c.Hash {
		t.Fatal("hash ignored rule version")
	}
}

func TestFalsifierVerifierNoProposal(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.Proposals = nil
	r := NewFalsifierVerifier(s).Verify(context.Background(), in)
	if len(r.Proofs) != 0 {
		t.Fatal("empty input admitted")
	}
}
func TestFalsifierVerifierUnsupportedMandatorySource(t *testing.T) {
	in, _ := verifierFixture(FalsifierCodeAbsent, nil)
	p := runProof(t, in, nil)
	if p.Status != FalsifierUnknown {
		t.Fatalf("status=%s", p.Status)
	}
}
func TestFalsifierVerifierPartialCoverage(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Completeness = evidencetools.CompletenessPartial
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("partial admitted")
	}
}
func TestFalsifierVerifierZeroSearchIsUnknown(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Tool = "search_text"
	o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"matches":0}`)
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("zero search admitted")
	}
}
func TestFalsifierVerifierUnresolvedDispatch(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"unresolved_dispatch":["iface"]}`)
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("unresolved dispatch admitted")
	}
}
func markerTest(t *testing.T, marker string) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"dynamic_markers":["` + marker + `"]}`)
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatalf("marker %s admitted", marker)
	}
}
func TestFalsifierVerifierFunctionValue(t *testing.T) { markerTest(t, "func_value") }
func TestFalsifierVerifierLinkname(t *testing.T)      { markerTest(t, "go:linkname") }
func TestFalsifierVerifierBuildTagGap(t *testing.T)   { markerTest(t, "build_tag_gap") }
func TestFalsifierVerifierAlternativeSubject(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Payload = json.RawMessage(`{"checked_subjects":[]}`)
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("alternative subject omitted")
	}
}
func TestFalsifierVerifierForeignSnapshot(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.SnapshotHash = "foreign"
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("foreign snapshot admitted")
	}
}
func TestFalsifierVerifierFactValidationPartial(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.FactValidation.Status = ValidationPartial
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("partial facts admitted")
	}
}
func TestFalsifierVerifierLocusFunctionUnsupported(t *testing.T) {
	s := sourceFixture()
	s.condition.Kind = FalsifierLocusFunctionAbsent
	in, _ := verifierFixture(FalsifierLocusFunctionAbsent, s)
	p := runProof(t, in, s)
	if p.Status != FalsifierInsufficientScope && p.Status != FalsifierUnknown {
		t.Fatalf("status=%s", p.Status)
	}
}
func TestFalsifierVerifierCrossRunEvidence(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Attempt = 2
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("cross-run evidence admitted")
	}
}

// TestFalsifierVerifierAuthoritativeSubjectSubstitution pins the contract
// change: a proposal whose own subject list diverges from the advisory's
// declared affected_symbols no longer dies on the mismatch alone — once the
// authoritative condition, snapshot, build context and ruleset bindings all
// hold, the verifier checks cond.ExpectedSubjects (never the proposal's
// list) and records the substitution in the proof reason.
func TestFalsifierVerifierAuthoritativeSubjectSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		subjects []FalsifierSubject
	}{
		{"missing subject", nil},
		{"wrong subject", []FalsifierSubject{{Package: "example.org/p", Symbol: "Alias"}}},
		{"extra subject", []FalsifierSubject{
			{Package: "example.org/p", Symbol: "Control"},
			{Package: "example.org/p", Symbol: "Extra"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sourceFixture()
			in, _ := verifierFixture(FalsifierCodeAbsent, s)
			in.Proposals[0].Subjects = tc.subjects
			p := runProof(t, in, s)
			if p.Status != FalsifierVerified || p.Basis != BasisCheckerVerified {
				t.Fatalf("authoritative set not verified: %+v", p)
			}
			if len(p.Coverage.ExpectedSubjects) != 1 || p.Coverage.ExpectedSubjects[0].Symbol != "Control" {
				t.Fatalf("coverage not bound to authoritative set: %+v", p.Coverage)
			}
			if !strings.Contains(p.Reason, "authoritative subject set") || len(p.History) == 0 || !strings.Contains(p.History[0].Reason, "authoritative subject set") {
				t.Fatalf("substitution not recorded: %+v", p)
			}
		})
	}

	// `role` is context only: the same package/symbol pair under an
	// agent-invented role is not a divergence, so nothing is substituted
	// and no substitution note appears.
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.Proposals[0].Subjects[0].Role = "agent-chosen-alias"
	p := runProof(t, in, s)
	if p.Status != FalsifierVerified {
		t.Fatalf("role relabelling rejected the authoritative subject: %+v", p)
	}
	if strings.Contains(p.Reason, "authoritative subject set") {
		t.Fatalf("substitution recorded where none happened: %+v", p)
	}
}

// TestFalsifierVerifierErroneousSubjectSetIsNoProof: when the observation
// covers only the proposal's mistaken subjects — never the authoritative
// affected_symbols — substitution cannot rescue the proof: checked subjects
// stay measured against the authoritative set and the proof fails.
func TestFalsifierVerifierErroneousSubjectSetIsNoProof(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	wrong := []FalsifierSubject{{Package: "example.org/p", Symbol: "Alias"}}
	in.Proposals[0].Subjects = wrong
	o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Alias"}]}`)
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("observation over the mistaken set admitted")
	}
	if !strings.Contains(p.Reason, "subject set incomplete") {
		t.Fatalf("reason = %q", p.Reason)
	}
}

// TestFalsifierVerifierSubstitutionRequiresCompleteBinding: the mismatch
// pardon applies only after every authoritative binding holds. An empty
// build-context binding leaves no trustworthy authoritative set, so the
// mismatch keeps its refusal instead of running an unbound check.
func TestFalsifierVerifierSubstitutionRequiresCompleteBinding(t *testing.T) {
	s := sourceFixture()
	s.condition.BuildContextHash = ""
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.Proposals[0].Subjects = []FalsifierSubject{{Package: "example.org/p", Symbol: "Alias"}}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatal("unbound condition admitted")
	}
	if !strings.Contains(p.Reason, "proposal subject set mismatch") {
		t.Fatalf("reason = %q", p.Reason)
	}
}

// TestFalsifierFeedbackItems: one entry per non-VERIFIED proposal proof —
// proposal id, status and the exact verifier reason; VERIFIED proofs and
// the checker-minted kernel proof (ProposalID == "") never feed back.
func TestFalsifierFeedbackItems(t *testing.T) {
	verified := FalsifierProof{ID: "fp-ok", ProposalID: "fp-ok", ClaimID: "c-1", Status: FalsifierVerified, Basis: BasisCheckerVerified, Mandatory: true, Reason: "deterministic checker verified complete absence"}
	failed := FalsifierProof{ID: "fp-bad", ProposalID: "fp-bad", ClaimID: "c-1", Status: FalsifierUnknown, Basis: BasisUnsupported, Reason: "evidence reference is not owned by claim"}
	kernel := FalsifierProof{ID: "det-unreachability-abc", ProposalID: "", Status: FalsifierVerified, Basis: BasisCheckerVerified, Kind: FalsifierLocusFunctionAbsent, Reason: "kernel proved every declared symbol of module example.org/mod unreachable"}
	report := NewFalsifierReport("rules-1", failed, verified, kernel)
	fb := BuildFalsifierFeedback(&report, 1)
	if fb.Pass != 1 || len(fb.Items) != 1 {
		t.Fatalf("feedback = %+v, want exactly the failed proposal item", fb)
	}
	it := fb.Items[0]
	if it.ProposalID != "fp-bad" || it.Status != FalsifierUnknown || it.Reason != "evidence reference is not owned by claim" {
		t.Fatalf("item = %+v", it)
	}
	if !it.Retryable || it.Repair == "" {
		t.Fatalf("ownership failure must carry a contract repair: %+v", it)
	}
	if !fb.Retryable() {
		t.Fatal("retryable failure must mark the pass retryable")
	}
}

// TestFalsifierFeedbackRepairClasses pins the retry boundary: proposal
// bindings the agent controls are retryable; external bindings — ruleset,
// snapshot, run and build-context provenance, an unsupported condition
// source or a semantic verdict — are diagnostics only.
func TestFalsifierFeedbackRepairClasses(t *testing.T) {
	retryable := []string{
		"proposal id is not unique",
		"claim does not exist",
		"claim is not decision-relevant",
		"evidence reference is not owned by claim",
		"evidence reference was not validated",
		"evidence reference is not VALID",
		"mandatory condition binding mismatch",
		"proposal subject set mismatch",
		"subject set incomplete",
		"coverage is not COMPLETE",
		"coverage contains unresolved scope or dynamic markers",
		"function unreached requires the kernel proof: no symbol-unreachability observation was recorded",
		"approved deterministic absence observation missing",
		// The authoritative-subject substitution note never hides the
		// failure class.
		"subject set incomplete (authoritative subject set used)",
		"coverage is not COMPLETE (authoritative subject set used)",
	}
	for _, reason := range retryable {
		repair, ok := falsifierRepair(reason)
		if !ok || repair == "" {
			t.Fatalf("reason %q must be retryable with guidance", reason)
		}
	}
	terminal := []string{
		"ruleset hash mismatch",
		"observation belongs to another run",
		"foreign snapshot",
		"fact validation is not COMPLETE",
		"mandatory condition source unsupported",
		"mandatory condition snapshot mismatch",
		"snapshot binding incomplete",
		"run identity missing",
		"build context binding incomplete",
		"cross-run evidence",
		"cross-run or foreign snapshot evidence",
		"module graph incomplete",
		"locus package present",
		"foreign snapshot (authoritative subject set used)",
	}
	for _, reason := range terminal {
		if repair, ok := falsifierRepair(reason); ok {
			t.Fatalf("reason %q must stay diagnostic-only, got repair %q", reason, repair)
		}
	}
}

// TestFalsifierFeedbackNoSemanticVerdict pins the anti-steering rule on the
// rendered pass: it carries proposal ids, statuses, verifier reasons and
// binding repairs — never verdict or recommendation vocabulary.
func TestFalsifierFeedbackNoSemanticVerdict(t *testing.T) {
	failed := FalsifierProof{ID: "fp-1", ProposalID: "fp-1", ClaimID: "c-1", Status: FalsifierUnknown, Basis: BasisUnsupported, Reason: "proposal subject set mismatch"}
	report := NewFalsifierReport("rules-1", failed)
	fb := BuildFalsifierFeedback(&report, 1)
	msg := FalsifierFeedbackMessage(fb)
	for _, want := range []string{`"proposal_id":"fp-1"`, `"status":"UNKNOWN"`, "proposal subject set mismatch", "affected_symbols"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("feedback message missing %q:\n%s", want, msg)
		}
	}
	for _, banned := range []string{
		"EXPLOITABLE", "NOT_EXPLOITABLE", "INCONCLUSIVE",
		"DISMISSED", "LOWERED", "UNCHANGED", "NOT_AFFECTED",
		"verdict", "recommendation",
	} {
		if strings.Contains(msg, banned) {
			t.Fatalf("feedback message leaks semantic vocabulary %q:\n%s", banned, msg)
		}
	}
}

// TestFalsifierFeedbackCleanReport: a fully verified report and a nil
// report both produce no items, so the caller never sends a repair turn.
func TestFalsifierFeedbackCleanReport(t *testing.T) {
	verified := FalsifierProof{ID: "fp-1", ProposalID: "fp-1", ClaimID: "c-1", Status: FalsifierVerified, Basis: BasisCheckerVerified, Mandatory: true}
	report := NewFalsifierReport("rules-1", verified)
	fb := BuildFalsifierFeedback(&report, 1)
	if len(fb.Items) != 0 || fb.Retryable() {
		t.Fatalf("clean report produced feedback: %+v", fb)
	}
	if fb := BuildFalsifierFeedback(nil, 1); len(fb.Items) != 0 || fb.Retryable() {
		t.Fatalf("nil report produced feedback: %+v", fb)
	}
}

// TestClampFalsifierFeedbackPasses: the bound is fixed at two — configured
// values above it are clamped, a non-positive value means the default.
func TestClampFalsifierFeedbackPasses(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{0, 2}, {-3, 2}, {1, 1}, {2, 2}, {9, 2}} {
		if got := clampFalsifierFeedbackPasses(tc.in); got != tc.want {
			t.Fatalf("clamp(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFalsifierVerifierCanonicalEvidenceDoesNotUseDecoy(t *testing.T) {
	s := sourceFixture()
	in, good := verifierFixture(FalsifierCodeAbsent, s)
	good.ID = "det-good"
	good.EvidenceRefs = nil
	in.Assessment.Evidence = []EvidenceRef{{ID: "e1", Kind: "observation", Locator: "det:det-good"}}
	in.Proposals[0].EvidenceRefs = []string{"e1"}
	in.Assessment.Claims[0].EvidenceRefs = []string{"e1"}
	in.FactValidation.References = []ReferenceCheck{{EvidenceID: "e1", Status: FactValid, SnapshotHash: "snap-1"}}
	decoy := *good
	decoy.ID = "det-bad"
	decoy.EvidenceRefs = []string{"e1"}
	// The decoy arrives first to prove selection is by canonical locator,
	// never by RecordedObservation.EvidenceRefs overlap.
	in.Observations = []RecordedObservation{decoy, *good}
	p := runProof(t, in, s)
	if p.Status != FalsifierVerified {
		t.Fatalf("canonical observation was not selected: %+v", p)
	}
	if len(p.Coverage.CheckedSubjects) == 0 || !sameSubjects(p.Coverage.CheckedSubjects, s.condition.ExpectedSubjects) {
		t.Fatalf("coverage came from the wrong observation: %+v", p.Coverage)
	}
}

func TestFalsifierVerifierPackageAbsenceRequiresProvenance(t *testing.T) {
	s := sourceFixture()
	s.condition.Kind = FalsifierLocusPackageAbsent
	in, o := verifierFixture(FalsifierLocusPackageAbsent, s)
	o.Tool = "verify_package_absence"
	in.Stage0.Materials.ModuleGraph = &ModuleGraph{Complete: true, Modules: []ModuleVersion{{Path: "other"}}}
	for _, mutate := range []func(*RecordedObservation){
		func(o *RecordedObservation) { o.RunID = "" },
		func(o *RecordedObservation) { o.Attempt = 0 },
		func(o *RecordedObservation) { o.SnapshotHash = "" },
		func(o *RecordedObservation) { o.BuildContextHash = "" },
	} {
		bad := *o
		mutate(&bad)
		in.Observations = []RecordedObservation{bad}
		if p := runProof(t, in, s); p.Status == FalsifierVerified {
			t.Fatalf("incomplete provenance admitted: %+v", p)
		}
	}
}

func TestFalsifierVerifierUsesCurrentStabilityAttempt(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	in.Attempt = 2
	in.RunID = "finding-1-attempt-2"
	o.Attempt = 2
	o.RunID = in.RunID
	in.Observations = []RecordedObservation{*o}
	if p := runProof(t, in, s); p.Status != FalsifierVerified {
		t.Fatalf("valid stability attempt rejected: %+v", p)
	}
}
