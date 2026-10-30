package verify

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/productb/claimshape"
	triage "github.com/davniy/izyan/internal/productb/triage"
)

// --- fixtures ---

func absencePayload() json.RawMessage {
	return json.RawMessage(`{
		"tool":"verify_code_absence","fact":"absence proven","scope":"closure","completeness":"COMPLETE","tool_status":"OK",
		"data":{
			"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"absent_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"coverage_rule":"closed","coverage_rule_version":"4",
			"snapshot_hash":"snap-1","build_context_hash":"bc-1",
			"import_closure":{"complete":true,"hash":"closure-1","scope_hash":"scope-1","open_exceptions":[],"observed_dynamic_markers":[]}
		},
		"scope_details":{"snapshot_hash":"snap-1","build_context":{"goos":"linux"}}
	}`)
}

func absentClaim() claimshape.CanonicalClaim {
	return claimshape.CanonicalClaim{
		ID:                   "c-1",
		Shape:                claimshape.ShapeSubjectAbsent,
		Subject:              claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"},
		Polarity:             claimshape.PolarityTrue,
		Predicate:            claimshape.ShapePredicate(claimshape.ShapeSubjectAbsent),
		Scope:                claimshape.Scope{Completeness: "COMPLETE", SnapshotHash: "snap-1", BuildContextHash: "bc-1"},
		EvidenceRefs:         []string{"det-1"},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeSubjectAbsent),
	}
}

func absenceObs(t *testing.T, mutate func(*triage.RecordedObservation)) triage.RecordedObservation {
	t.Helper()
	o := triage.RecordedObservation{
		ID: "det-1", Tool: "verify_code_absence", Status: "OK",
		Completeness: evidencetools.CompletenessComplete,
		Payload:      absencePayload(),
		DataSHA256:   "sha-1",
		SnapshotHash: "snap-1", BuildContextHash: "bc-1",
		RunID: "run-1", Attempt: 1,
	}
	if mutate != nil {
		mutate(&o)
	}
	return o
}

// --- registry: no case identifiers ---

func TestRegistryHasNoCaseIdentifiers(t *testing.T) {
	advisory := regexp.MustCompile(`(?i)(CVE-|GHSA-|GO-\d{4}|CVE-\d)`)
	pathLike := regexp.MustCompile(`[a-z0-9._-]+\.[a-z]{2,}/|golang\.org|github\.com/|google\.golang`)
	for _, c := range Registry() {
		for _, sc := range c.Contracts {
			for _, s := range []string{c.ID, c.Description, sc.RequiredScope, sc.CompleteMeans} {
				if advisory.MatchString(s) {
					t.Fatalf("capability %s carries advisory id in %q", c.ID, s)
				}
				if pathLike.MatchString(s) {
					t.Fatalf("capability %s carries a package path in %q", c.ID, s)
				}
			}
		}
		for _, tool := range c.LiveTools {
			if strings.ContainsAny(tool, "/") {
				t.Fatalf("tool name %q looks like a path", tool)
			}
		}
	}
	// Every canonical shape's required capabilities resolve in the registry.
	for _, s := range claimshape.CanonicalShapes() {
		for _, id := range claimshape.RequiredCapabilities(s) {
			if CapabilityByID(id) == nil {
				t.Fatalf("shape %s requires unregistered capability %q", s, id)
			}
		}
	}
}

// Every bound/live tool name must resolve in the canonical evidence registry —
// a stale name would silently never bind. The offline validator keeps its own
// shape contracts and archive interpretation; it does not become a second tool
// catalog, so the registry is consulted here by id only.
func TestBoundToolsExist(t *testing.T) {
	registry := evidencetools.DefaultCheckCatalog()
	known := map[string]bool{}
	for _, spec := range registry.List() {
		known[spec.ID] = true
	}
	for tool := range toolBindings {
		if !known[tool] {
			t.Fatalf("bound tool %q is not in the canonical evidence registry", tool)
		}
		if _, ok := registry.Lookup(tool); !ok {
			t.Fatalf("bound tool %q does not resolve through Lookup", tool)
		}
	}
	for _, c := range Registry() {
		for _, tool := range c.LiveTools {
			if !known[tool] {
				t.Fatalf("capability %s lists tool %q not in the canonical evidence registry", c.ID, tool)
			}
		}
	}
}

func TestCapabilitiesDeclareGapSources(t *testing.T) {
	for _, c := range Registry() {
		if len(c.GapSources) == 0 {
			t.Fatalf("capability %s has no gap-source declaration", c.ID)
		}
	}
}

// --- hash binding: provenance required, foreign run rejected ---

func baseInput(c claimshape.CanonicalClaim, obs ...triage.RecordedObservation) Input {
	return Input{RunID: "run-1", FindingID: "f-1", Claims: []claimshape.CanonicalClaim{c}, Observations: obs}
}

func TestProvenanceHashBinding(t *testing.T) {
	c := absentClaim()
	ok := absenceObs(t, nil)
	rep := Evaluate(baseInput(c, ok))
	ev := rep.ClaimOutcomeOf("c-1")
	if ev.Outcome != OutcomeTrue || ev.Predicate != PredicateHolds {
		t.Fatalf("complete closed absence should hold: %+v", ev)
	}
	for name, mut := range map[string]func(*triage.RecordedObservation){
		"foreign_run": func(o *triage.RecordedObservation) { o.RunID = "other-run" },
		"missing_run": func(o *triage.RecordedObservation) { o.RunID = ""; o.Attempt = 0 },
		"missing_snapshot": func(o *triage.RecordedObservation) {
			o.SnapshotHash = ""
			o.Payload = json.RawMessage(`{"data":{"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],"absent_subjects":[{"package":"dep/pkg","symbol":"Victim"}],"import_closure":{"complete":true,"hash":"h","scope_hash":"s"}}}`)
		},
		"missing_buildctx": func(o *triage.RecordedObservation) {
			o.BuildContextHash = ""
			o.Payload = json.RawMessage(`{"data":{"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],"absent_subjects":[{"package":"dep/pkg","symbol":"Victim"}],"import_closure":{"complete":true,"hash":"h","scope_hash":"s"}}}`)
		},
	} {
		o := absenceObs(t, mut)
		rep := Evaluate(baseInput(c, o))
		ev := rep.ClaimOutcomeOf("c-1")
		if ev.Outcome == OutcomeTrue || ev.Predicate == PredicateHolds {
			t.Fatalf("%s: observation admitted without provenance binding: %+v", name, ev)
		}
	}
	// Snapshot mismatch against the claim's pinned context: excluded.
	c2 := absentClaim()
	c2.Scope.SnapshotHash = "other-snap"
	rep = Evaluate(baseInput(c2, absenceObs(t, nil)))
	if rep.ClaimOutcomeOf("c-1").Outcome == OutcomeTrue {
		t.Fatal("foreign snapshot context admitted against pinned claim scope")
	}
}

// --- PARTIAL/UNKNOWN never yields the universal direction ---

func TestPartialNeverNegativeAdmission(t *testing.T) {
	c := absentClaim()
	for _, comp := range []evidencetools.Completeness{evidencetools.CompletenessPartial, evidencetools.CompletenessUnknown} {
		o := absenceObs(t, func(o *triage.RecordedObservation) { o.Completeness = comp })
		rep := Evaluate(baseInput(c, o))
		ev := rep.ClaimOutcomeOf("c-1")
		if ev.Predicate == PredicateHolds || ev.Outcome == OutcomeTrue {
			t.Fatalf("%s: partial completeness admitted universal absence: %+v", comp, ev)
		}
		if ev.Outcome != OutcomeUnknown {
			t.Fatalf("%s: outcome %q, want UNKNOWN", comp, ev.Outcome)
		}
	}
	// Open dynamic gap inside an otherwise complete closure: blocked.
	o := absenceObs(t, func(o *triage.RecordedObservation) {
		o.Payload = json.RawMessage(`{
			"data":{"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"absent_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"unresolved_dispatch":["pkg/f.go:10 iface"],
			"import_closure":{"complete":true,"hash":"h","scope_hash":"s","open_exceptions":["plugin:x"]}}}`)
	})
	rep := Evaluate(baseInput(c, o))
	if rep.ClaimOutcomeOf("c-1").Outcome == OutcomeTrue {
		t.Fatal("open dynamic gap admitted a negative absence")
	}
}

// --- counterexample at PARTIAL stands; closed negative never at PARTIAL ---

func TestCounterexampleAndWitnessDirections(t *testing.T) {
	absent := absentClaim()
	// A present subject inside a PARTIAL check refutes absence — the
	// existential counterexample needs no closed scope.
	present := absenceObs(t, func(o *triage.RecordedObservation) {
		o.Completeness = evidencetools.CompletenessPartial
		o.Payload = json.RawMessage(`{"data":{"expected_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"checked_subjects":[{"package":"dep/pkg","symbol":"Victim"}],
			"present_subjects":[{"package":"dep/pkg","symbol":"Victim"}]}}`)
	})
	rep := Evaluate(baseInput(absent, present))
	ev := rep.ClaimOutcomeOf("c-1")
	if ev.Predicate != PredicateDisproved || ev.Outcome != OutcomeFalse {
		t.Fatalf("present counterexample should disprove: %+v", ev)
	}

	// path.reachable: a concrete caller admits at PARTIAL; a zero-count
	// PARTIAL probe can never refute (Global Constraint 4).
	reach := claimshape.CanonicalClaim{
		ID: "c-2", Shape: claimshape.ShapePathReachable, Polarity: claimshape.PolarityTrue,
		Subject:              claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"},
		EvidenceRefs:         []string{"det-2"},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapePathReachable),
	}
	caller := triage.RecordedObservation{
		ID: "det-2", Tool: "find_callers", Status: "OK", Completeness: evidencetools.CompletenessPartial,
		Payload: json.RawMessage(`{"data":{"call_sites":[{"file":"a.go","line":9,"func":"main.main"}],"count":1},
			"scope_details":{"snapshot_hash":"snap-1"}}`),
		DataSHA256: "s2", SnapshotHash: "snap-1", BuildContextHash: "bc-1", RunID: "run-1", Attempt: 1,
	}
	rep = Evaluate(baseInput(reach, caller))
	if rep.ClaimOutcomeOf("c-2").Outcome != OutcomeTrue {
		t.Fatalf("concrete caller should establish reachability: %+v", rep.ClaimOutcomeOf("c-2"))
	}
	zero := caller
	zero.Payload = json.RawMessage(`{"data":{"call_sites":[],"count":0},"scope_details":{"snapshot_hash":"snap-1"}}`)
	rep = Evaluate(baseInput(reach, zero))
	if rep.ClaimOutcomeOf("c-2").Outcome == OutcomeFalse || rep.ClaimOutcomeOf("c-2").Predicate == PredicateDisproved {
		t.Fatalf("zero partial callers must never refute reachability: %+v", rep.ClaimOutcomeOf("c-2"))
	}
}

// --- claims without observations stay UNKNOWN; missing capability is honest ---

func TestClaimWithoutObservationsStaysUnknown(t *testing.T) {
	c := absentClaim()
	c.EvidenceRefs = nil
	rep := Evaluate(baseInput(c))
	ev := rep.ClaimOutcomeOf("c-1")
	if ev.Outcome != OutcomeUnknown || ev.Reason != "no_observations" {
		t.Fatalf("claim without observations: %+v", ev)
	}
	// UNSUPPORTED claim shape: explicit UNKNOWN with reason.
	u := c
	u.Shape = claimshape.ShapeUnsupported
	u.UnsupportedReason = claimshape.ReasonWeakEvidenceOnly
	rep = Evaluate(baseInput(u))
	if rep.ClaimOutcomeOf("c-1").Outcome != OutcomeUnknown ||
		!strings.HasPrefix(rep.ClaimOutcomeOf("c-1").Reason, "unsupported_claim_shape") {
		t.Fatalf("unsupported claim: %+v", rep.ClaimOutcomeOf("c-1"))
	}
	// a claim without resolvable premises stays UNKNOWN with an honest
	// derived reason, never a fake support.
	d := claimshape.CanonicalClaim{
		ID: "c-3", Shape: claimshape.ShapeDerivedMandatoryCondition, Polarity: claimshape.PolarityTrue,
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeDerivedMandatoryCondition),
	}
	rep = Evaluate(baseInput(d))
	ev = rep.ClaimOutcomeOf("c-3")
	if ev.Outcome != OutcomeUnknown || !strings.HasPrefix(ev.Reason, "derived:") {
		t.Fatalf("derived claim without premises must stay UNKNOWN: %+v", ev)
	}
	if len(ev.MissingCaps) != 0 {
		t.Fatalf("entailment capability must be implemented now: %+v", ev)
	}
}

// --- determinism: same input, identical report hash ---

func TestDeterministicEvaluation(t *testing.T) {
	c := absentClaim()
	o := absenceObs(t, nil)
	a := Evaluate(baseInput(c, o))
	b := Evaluate(baseInput(c, o))
	if a.Hash != b.Hash {
		t.Fatal("non-deterministic report hash")
	}
	ba, _ := a.Marshal()
	bb, _ := b.Marshal()
	if string(ba) != string(bb) {
		t.Fatal("non-deterministic report bytes")
	}
}

// --- conflict inside one context: CONFLICTING, never majority vote ---

func TestConflictingObservations(t *testing.T) {
	c := claimshape.CanonicalClaim{
		ID: "c-4", Shape: claimshape.ShapeControlPresent, Polarity: claimshape.PolarityTrue,
		Subject:              claimshape.Subject{Kind: claimshape.SubjectCallSite, Name: "a.go:9"},
		EvidenceRefs:         []string{"det-3", "det-4"},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeControlPresent),
	}
	guarded := triage.RecordedObservation{
		ID: "det-3", Tool: "check_call_site_guard", Status: "OK", Completeness: evidencetools.CompletenessComplete,
		Payload:    json.RawMessage(`{"data":{"gated":true,"dead_code":false,"detail":"ctx"},"scope_details":{"snapshot_hash":"snap-1","subject":"a.go:9"}}`),
		DataSHA256: "s3", SnapshotHash: "snap-1", BuildContextHash: "bc-1", RunID: "run-1", Attempt: 1,
	}
	unguarded := guarded
	unguarded.ID = "det-4"
	unguarded.Payload = json.RawMessage(`{"data":{"gated":false,"dead_code":false,"detail":"none"},"scope_details":{"snapshot_hash":"snap-1","subject":"a.go:9"}}`)
	rep := Evaluate(baseInput(c, guarded, unguarded))
	ev := rep.ClaimOutcomeOf("c-4")
	if ev.Predicate != PredicateConflicting || ev.Outcome != OutcomeConflicting {
		t.Fatalf("same-context contradiction must conflict: %+v", ev)
	}
	var contra bool
	for _, e := range rep.Edges {
		if e.Kind == "contradicts" {
			contra = true
		}
	}
	if !contra {
		t.Fatal("contradicts edge missing")
	}
}

// --- context separation: different build contexts never mix ---

func TestContextSeparation(t *testing.T) {
	c := absentClaim()
	c.Scope = claimshape.Scope{} // unpinned — both contexts evaluate
	good := absenceObs(t, nil)
	other := absenceObs(t, func(o *triage.RecordedObservation) {
		o.BuildContextHash = "bc-other"
		o.Completeness = evidencetools.CompletenessPartial
	})
	rep := Evaluate(baseInput(c, good, other))
	ev := rep.ClaimOutcomeOf("c-1")
	if len(ev.Groups) != 2 {
		t.Fatalf("context groups = %d, want 2", len(ev.Groups))
	}
	// Universal predicate: a group that cannot close blocks the universal.
	if ev.Predicate == PredicateHolds {
		t.Fatalf("partial context must not disappear into a closed verdict: %+v", ev)
	}
}

// --- live path: bounded budget, identical interpretation ---

type fakeCaller struct {
	calls int
	obs   *evidencetools.Observation
}

func (f *fakeCaller) CallTool(_ context.Context, name string, args json.RawMessage) (*evidencetools.Observation, error) {
	f.calls++
	var o evidencetools.Observation
	b, _ := json.Marshal(map[string]any{
		"tool": "verify_code_absence", "tool_status": "OK", "completeness": "COMPLETE",
		"data": map[string]any{
			"expected_subjects": []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
			"checked_subjects":  []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
			"absent_subjects":   []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
			"import_closure":    map[string]any{"complete": true, "hash": "closure-1", "scope_hash": "scope-1"},
		},
		"scope_details": map[string]any{"snapshot_hash": "snap-1", "build_context": map[string]any{"goos": "linux"}},
	})
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

func TestLiveBudgetBounded(t *testing.T) {
	c := absentClaim()
	c.Scope = claimshape.Scope{} // live path binds its own context
	in := baseInput(c)
	f := &fakeCaller{}
	out, err := ExecuteLive(context.Background(), in, f, LiveBudget{MaxCalls: 1})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls > 1 {
		t.Fatalf("budget exceeded: %d calls", f.calls)
	}
	if len(out) > 1 {
		t.Fatalf("recorded %d observations under budget 1", len(out))
	}
	// The live-produced record interprets identically to an archived one.
	in.Observations = out
	rep := Evaluate(in)
	if rep.ClaimOutcomeOf("c-1").Outcome != OutcomeTrue {
		t.Fatalf("live path should admit the same closed absence: %+v", rep.ClaimOutcomeOf("c-1"))
	}
}

// The reviewer channel plans through the identical bounded pipeline:
// challenge-minted claims generate tool queries under the same
// MaxCalls budget — never an unbounded second path.
func TestChallengePlansUnderSameBudget(t *testing.T) {
	in := baseInput(absentClaim())
	in.Challenges = []Challenge{{
		ID: "rev-live", Kind: ChallengeMissingSubject,
		Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"},
	}}
	f := &fakeCaller{}
	out, err := ExecuteLive(context.Background(), in, f, LiveBudget{MaxCalls: 2})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls > 2 {
		t.Fatalf("budget exceeded: %d calls", f.calls)
	}
	// The challenge's find_symbol plan ran: its live record lands in
	// the archive set the evaluator consumes.
	if len(out) == 0 {
		t.Fatal("challenge produced no live query")
	}
	in.Observations = out
	rep := Evaluate(in)
	row := challengeRowOf(rep, "rev-live")
	if row == nil || row.ClaimID == "" {
		t.Fatalf("challenge row = %+v", row)
	}
}

// --- plan: deterministic, never exceeds shapes ---

func TestPlanDeterministic(t *testing.T) {
	c := absentClaim()
	a := PlanQueries(c)
	b := PlanQueries(c)
	ba, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ba) != string(bb) {
		t.Fatal("non-deterministic plan")
	}
	// UNSUPPORTED and derived claims produce no live plan.
	u := c
	u.Shape = claimshape.ShapeUnsupported
	if got := PlanQueries(u); len(got) != 0 {
		t.Fatalf("unsupported claim planned %d queries", len(got))
	}
}
