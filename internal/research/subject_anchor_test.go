package research

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/flow"
)

// The anchored-text subject gate: the deterministic admission layer
// that validates a planner-proposed subject derived from advisory
// text — verbatim anchor required, inside an affected module, well
// formed — before any check may dispatch. Every test is hermetic: the
// lane fixture loads a frozen advisory file, the catalog comes from the
// pinned research configuration, and no session, network or model is
// involved.

const anchorModuleOnlyAdvisory = `{
  "id": "GO-TEST-ANCHOR",
  "aliases": ["CVE-TEST-ANCHOR"],
  "summary": "authz interceptor bypass in the example.com/snapdep module",
  "details": "Requests without a valid token reach the handler because the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation on streaming calls.",
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
  }],
  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
}`

const anchorDeclaredAdvisory = `{
  "id": "GO-TEST-0001",
  "summary": "test advisory for snapdep Parse",
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
  }],
  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
}`

const anchorTwoModuleAdvisory = `{
  "id": "GO-TEST-TWO",
  "summary": "two affected modules",
  "description": "the authz interceptor package is named only in prose",
  "modified": "2026-01-01T00:00:00Z",
  "affected": [
    {"package": {"ecosystem": "Go", "name": "example.com/snapdep"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]},
    {"package": {"ecosystem": "Go", "name": "example.com/other"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
  ]
}`

// anchorLane loads one frozen advisory into a LaneResult the gate
// consumes — the same advisory record the production lane hands it.
func anchorLane(t *testing.T, cve, advisory string) *LaneResult {
	t.Helper()
	p := filepath.Join(t.TempDir(), cve+".json")
	if err := os.WriteFile(p, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := loadFrozenAdvisory(context.Background(), LaneOptions{CVE: cve, AdvisoryFile: p})
	if err != nil {
		t.Fatalf("loadFrozenAdvisory: %v", err)
	}
	return &LaneResult{Advisory: *rec}
}

// anchorGate builds the gated registry over the pinned research
// configuration exactly like RunDecisionReady does — a lane with no
// session, so the zero-capability catalog admits every schema-conform
// request.
func anchorGate(t *testing.T, lane *LaneResult) *subjectGateRegistry {
	t.Helper()
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	cat := newFlowCatalog(cats, evidencetools.DefaultCheckCatalog(), lane.ContentHash)
	reg, err := flow.NewCatalogRegistry(cat, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return newSubjectGateRegistry(reg, lane)
}

func anchorAction(id, adapter, args, anchor string) flow.PlanAction {
	return flow.PlanAction{
		ID: id, AdapterID: adapter, Purpose: "check the mechanism the advisory text names",
		Arguments: json.RawMessage(args), Anchor: anchor,
	}
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("action admitted, want rejection %s", reason)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("rejection %q does not name %s", err.Error(), reason)
	}
}

// An anchored text-derived subject passes admission: the package is not
// part of the advisory's structured declaration, but the recorded
// description names the mechanism package verbatim and the package lies
// inside the declared module.
func TestSubjectGateAnchoredSubjectAdmitted(t *testing.T) {
	gate := anchorGate(t, anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory))
	quote := "the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation"
	err := gate.Check(anchorAction("a1", "package-usage",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz"}`, quote))
	if err != nil {
		t.Fatalf("anchored subject rejected: %v", err)
	}
	// A package-usage naming a symbol inside the anchored package is
	// equally admissible.
	err = gate.Check(anchorAction("a2", "package-usage",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz","symbol":"Authenticate"}`, quote))
	if err != nil {
		t.Fatalf("anchored symbol subject rejected: %v", err)
	}
	// A symbol-unreachability whose subjects[] the text names.
	err = gate.Check(anchorAction("a3", "symbol-unreachability",
		`{"module":"example.com/snapdep","subjects":[{"package":"example.com/snapdep/middleware/authz","symbol":"Authenticate"}]}`,
		quote))
	if err != nil {
		t.Fatalf("anchored unreachability subjects rejected: %v", err)
	}
}

// Without an anchor a non-declared subject keeps the v1–v4 outcome:
// rejection — the fabrication path stays closed.
func TestSubjectGateAnchorMissing(t *testing.T) {
	gate := anchorGate(t, anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory))
	wantReason(t, gate.Check(anchorAction("a1", "package-usage",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz"}`, "")),
		SubjectAnchorMissingReason)
	wantReason(t, gate.Check(anchorAction("a2", "find_symbol",
		`{"package":"example.com/snapdep/middleware/authz","symbol":"Authenticate"}`, "")),
		SubjectAnchorMissingReason)
}

// A quote that is not a verbatim (whitespace-normalized) substring of
// the recorded advisory text is rejected — the anchor is validated
// against summary, description and the raw frozen body.
func TestSubjectGateAnchorNotFound(t *testing.T) {
	gate := anchorGate(t, anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory))
	wantReason(t, gate.Check(anchorAction("a1", "package-usage",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz"}`,
		"a quote the advisory never wrote")),
		SubjectAnchorNotFoundReason)
}

// The subject's package must lie inside an advisory-affected module;
// an anchor quoting real text cannot rescue a subject outside it.
func TestSubjectGateOutsideAffectedModule(t *testing.T) {
	gate := anchorGate(t, anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory))
	quote := "the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation"
	wantReason(t, gate.Check(anchorAction("a1", "package-usage",
		`{"module":"example.com/unrelated","package":"example.com/unrelated/authz"}`, quote)),
		SubjectOutsideModuleReason)
	wantReason(t, gate.Check(anchorAction("a2", "find_symbol",
		`{"package":"example.com/unrelated/authz","symbol":"Authenticate"}`, quote)),
		SubjectOutsideModuleReason)
}

// Malformed subject identities are named by their own reason: invalid
// import paths, invalid symbol shapes, a package outside its named
// module, a symbol without a package.
func TestSubjectGateMalformed(t *testing.T) {
	quote := "the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation"
	t.Run("invalid import path", func(t *testing.T) {
		gate := anchorGate(t, anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory))
		wantReason(t, gate.Check(anchorAction("a1", "package-usage",
			`{"module":"example.com/snapdep","package":"not a path"}`, quote)),
			SubjectMalformedReason)
	})
	t.Run("invalid symbol shape", func(t *testing.T) {
		gate := anchorGate(t, anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory))
		wantReason(t, gate.Check(anchorAction("a1", "package-usage",
			`{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz","symbol":"not a symbol"}`, quote)),
			SubjectMalformedReason)
	})
	t.Run("symbol without package", func(t *testing.T) {
		// No schema-conform action can emit a package-less symbol —
		// the catalog requires package for every symbol member — so the
		// malformed rule is exercised on the extracted identity itself.
		if err := (proposedSubject{Module: "example.com/snapdep", Symbol: "Authenticate"}).wellFormed(); err == nil {
			t.Fatal("a package-less symbol identity is well-formed")
		}
	})
	t.Run("package outside named module", func(t *testing.T) {
		gate := anchorGate(t, anchorLane(t, "GO-TEST-TWO", anchorTwoModuleAdvisory))
		// example.com/snapdep/x is inside an affected module but not
		// inside the module the arguments name.
		wantReason(t, gate.Check(anchorAction("a1", "package-usage",
			`{"module":"example.com/other","package":"example.com/snapdep/x"}`,
			"the authz interceptor package is named only in prose")),
			SubjectMalformedReason)
	})
}

// Declared subjects admit exactly as before — anchor-free like every
// earlier prompt revision — and module-level aggregates stay declared.
func TestSubjectGateDeclaredSubjectsUnchanged(t *testing.T) {
	gate := anchorGate(t, anchorLane(t, "GO-TEST-0001", anchorDeclaredAdvisory))
	for _, args := range []string{
		`{"module":"example.com/snapdep","package":"example.com/snapdep/vuln"}`,
		`{"module":"example.com/snapdep","package":"example.com/snapdep/vuln","symbol":"Parse"}`,
	} {
		if err := gate.Check(anchorAction("a1", "package-usage", args, "")); err != nil {
			t.Fatalf("declared package-usage subject %s rejected: %v", args, err)
		}
	}
	// The module-less SymbolRef form binds the declared package.
	if err := gate.Check(anchorAction("a1b", "find_symbol",
		`{"package":"example.com/snapdep/vuln","symbol":"Parse"}`, "")); err != nil {
		t.Fatalf("declared find_symbol subject rejected: %v", err)
	}
	if err := gate.Check(anchorAction("a2", "usage-scope", `{"module":"example.com/snapdep"}`, "")); err != nil {
		t.Fatalf("declared module aggregate rejected: %v", err)
	}
	if err := gate.Check(anchorAction("a3", "usage-scope",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/vuln"}`, "")); err != nil {
		t.Fatalf("declared usage-scope subject rejected: %v", err)
	}
	if err := gate.Check(anchorAction("a4", "symbol-unreachability",
		`{"module":"example.com/snapdep","subjects":[{"package":"example.com/snapdep/vuln","symbol":"Parse"}]}`, "")); err != nil {
		t.Fatalf("declared symbol-unreachability subject rejected: %v", err)
	}
	// A declared package with a symbol the declaration does not name is
	// NOT declared: it is a new identity and needs an anchor.
	wantReason(t, gate.Check(anchorAction("a5", "package-usage",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/vuln","symbol":"Other"}`, "")),
		SubjectAnchorMissingReason)
	// A non-subject action is untouched by the gate.
	if err := gate.Check(anchorAction("a6", "get_product_snapshot", `{}`, "")); err != nil {
		t.Fatalf("non-subject action rejected: %v", err)
	}
}

// The quoted field is recorded: summary, description and raw_body all
// verify; whitespace differences inside the quote are normalized.
func TestAdvisoryAnchorFields(t *testing.T) {
	lane := anchorLane(t, "GO-TEST-ANCHOR", anchorModuleOnlyAdvisory)
	if f := advisoryAnchorField(lane, "authz interceptor bypass"); f != anchorFieldSummary {
		t.Fatalf("summary anchor field = %q", f)
	}
	if f := advisoryAnchorField(lane,
		"the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation"); f != anchorFieldDescription {
		t.Fatalf("description anchor field = %q", f)
	}
	if f := advisoryAnchorField(lane,
		"the authz interceptor   in\nexample.com/snapdep/middleware/authz\tskips  RBAC evaluation"); f != anchorFieldDescription {
		t.Fatalf("whitespace-normalized anchor field = %q", f)
	}
	if f := advisoryAnchorField(lane, `"ecosystem": "Go"`); f != anchorFieldRawBody {
		t.Fatalf("raw body anchor field = %q", f)
	}
	if f := advisoryAnchorField(lane, "text the advisory never recorded"); f != "" {
		t.Fatalf("unrecorded anchor matched field %q", f)
	}
	// Provenance records the matched field and the verbatim quote.
	gate := anchorGate(t, lane)
	a := anchorAction("a1", "package-usage",
		`{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz"}`,
		"the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation")
	if err := gate.Check(a); err != nil {
		t.Fatalf("anchored check rejected: %v", err)
	}
	p := actionProvenance(lane, &a)
	if p == nil || p.Field != anchorFieldDescription || p.Quote != a.Anchor {
		t.Fatalf("provenance = %+v", p)
	}
	if p := actionProvenance(lane, &flow.PlanAction{ID: "x"}); p != nil {
		t.Fatalf("anchor-less action carried provenance: %+v", p)
	}
}

// The wire contract stays byte-compatible for v1–v4 plans: actions
// without the anchor member decode with an empty anchor, unknown
// members still reject, and a recorded legacy plan action re-encodes
// without the anchor key.
func TestFlowWirePlanAnchorCompatibility(t *testing.T) {
	legacy := `{"step_id":"s","condition_ids":[],"actions":[{"id":"a","adapter_id":"package-usage","arguments":{"module":"m"},"purpose":"p","condition_id":"c"}]}`
	var wire flowWirePlan
	if err := decodeLastJSON(legacy, &wire); err != nil {
		t.Fatalf("legacy plan rejected: %v", err)
	}
	if wire.Actions[0].Anchor != "" {
		t.Fatalf("legacy action gained an anchor: %+v", wire.Actions[0])
	}
	anchored := `{"step_id":"s","condition_ids":[],"actions":[{"id":"a","adapter_id":"package-usage","arguments":{"module":"m"},"purpose":"p","anchor":"the text quote"}]}`
	var wire2 flowWirePlan
	if err := decodeLastJSON(anchored, &wire2); err != nil {
		t.Fatalf("anchored plan rejected: %v", err)
	}
	if wire2.Actions[0].Anchor != "the text quote" {
		t.Fatalf("anchor not bound: %+v", wire2.Actions[0])
	}
	// An unanchored action re-encodes without the member — the recorded
	// legacy byte shape is unchanged.
	b, err := json.Marshal(flow.PlanAction{ID: "a", AdapterID: "x", Purpose: "p", Arguments: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "anchor") {
		t.Fatalf("legacy action encoding gained anchor: %s", b)
	}
	b, err = json.Marshal(flow.PlanAction{ID: "a", AdapterID: "x", Purpose: "p", Arguments: json.RawMessage(`{}`), Anchor: "q"})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(b), `"anchor":"q"`) {
		t.Fatalf("anchored action encoding lost the member: %s", b)
	}
}

// ---- run level: the gate inside RunDecisionReady ----

func anchorRunOptions(t *testing.T, outDir string) LaneOptions {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "GO-TEST-ANCHOR.json")
	if err := os.WriteFile(p, []byte(anchorModuleOnlyAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	return LaneOptions{
		CVE: "GO-TEST-ANCHOR", SnapshotPath: root, AdvisoryFile: p,
		ExternalCommitSHA: "fixture-sha-1", Timeout: 90 * time.Second,
	}
}

const anchorSubjectArgs = `{"module":"example.com/snapdep","package":"example.com/snapdep/middleware/authz"}`
const anchorSubjectQuote = "the authz interceptor in example.com/snapdep/middleware/authz skips RBAC evaluation"

// An anchored text-derived subject dispatches through the real run:
// the module-only advisory marks package-usage inapplicable at run
// start, the anchored proposal still admits and executes, and the
// provenance lands on the recorded check — while the verdict gates
// stay unchanged (no close is ever projected from an anchor).
func TestRunDecisionReadyAnchoredSubjectDispatches(t *testing.T) {
	out := t.TempDir()
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: anchorRunOptions(t, out),
		Agent: &fakeFlowDriver{
			plans: []flow.Plan{{
				StepID: "s1",
				Actions: []flow.PlanAction{{
					ID: "a1", AdapterID: "package-usage",
					Arguments: json.RawMessage(anchorSubjectArgs),
					Purpose:   "check the authz interceptor package the advisory text names",
					Anchor:    anchorSubjectQuote,
				}},
			}},
			reas: []flow.Reassessment{{Status: flow.ReassessReady}},
		},
		ConfigFS:  r6ConfigFS(t),
		OutputDir: out,
		RunID:     "test-anchored-subject",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination == flow.TermUnsupported {
		t.Fatalf("anchored plan rejected: %q", rec.Result.Reason)
	}
	if len(rec.Result.Actions) != 1 {
		t.Fatalf("actions=%d — the anchored check did not dispatch", len(rec.Result.Actions))
	}
	// The module-only advisory records package-usage inapplicable at
	// run start; the anchored dispatch is additional evidence, and the
	// record of both survives.
	if !containsStr(rec.Result.InapplicableChecks, "package-usage") {
		t.Fatalf("inapplicable record lost: %v", rec.Result.InapplicableChecks)
	}
	// The request carries the verified provenance — the matched field
	// recomputed, the quote verbatim — and the report's decision.checks
	// row mirrors it.
	if len(rec.Trace.Requests) != 1 || rec.Trace.Requests[0].DerivedFrom == nil ||
		rec.Trace.Requests[0].DerivedFrom.Field != "description" ||
		rec.Trace.Requests[0].DerivedFrom.Quote != anchorSubjectQuote {
		t.Fatalf("trace provenance = %+v", rec.Trace.Requests)
	}
	var prov *SubjectProvenance
	if report.Decision != nil {
		for _, c := range report.Decision.Checks {
			if c.DerivedFrom != nil {
				prov = c.DerivedFrom
			}
		}
	}
	if prov == nil || prov.Field != "description" || prov.Quote != anchorSubjectQuote {
		t.Fatalf("decision.checks provenance = %+v", prov)
	}
	// The audit trail persists the anchor with the action; flow-facts
	// records the same provenance for the dispatched check.
	if rec.Result.Actions[0].Anchor != anchorSubjectQuote {
		t.Fatalf("recorded action lost its anchor: %+v", rec.Result.Actions[0])
	}
	raw, err := os.ReadFile(filepath.Join(out, flowFactsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"derived_from"`) ||
		!strings.Contains(string(raw), `"field": "description"`) {
		t.Fatalf("flow-facts lacks derived_from provenance:\n%s", raw)
	}
	// An anchor never produces a verdict: the artifact stays a
	// proposal and the decision can never be a close from the anchor
	// alone — the existing complete-proof gates rule unchanged.
	if report.DecisionArtifact == nil {
		t.Fatal("missing artifact")
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// The same text-derived subject without an anchor keeps the v1–v4
// outcome end to end: the plan is rejected at admission, nothing
// dispatches and the recorded reason names the gate.
func TestRunDecisionReadyUnanchoredSubjectRejected(t *testing.T) {
	out := t.TempDir()
	_, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: anchorRunOptions(t, out),
		Agent: &fakeFlowDriver{
			plans: []flow.Plan{{
				StepID: "s1",
				Actions: []flow.PlanAction{{
					ID: "a1", AdapterID: "package-usage",
					Arguments: json.RawMessage(anchorSubjectArgs),
					Purpose:   "check a package the structured data never declared",
				}},
			}},
		},
		ConfigFS:  r6ConfigFS(t),
		OutputDir: out,
		RunID:     "test-unanchored-subject",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination != flow.TermUnsupported {
		t.Fatalf("termination %q want UNSUPPORTED", rec.Result.Termination)
	}
	if !strings.Contains(rec.Result.Reason, SubjectAnchorMissingReason) {
		t.Fatalf("reason %q does not name %s", rec.Result.Reason, SubjectAnchorMissingReason)
	}
	if len(rec.Result.Actions) != 0 {
		t.Fatalf("rejected plan dispatched %d actions", len(rec.Result.Actions))
	}
}

// A plan the subject gate refuses earns the engine's single bounded
// repair turn end to end: the recorded SUBJECT_ANCHOR_MISSING
// rejection and the rejected plan go back through PlanInput's repair
// fields, the corrected plan (same subject, verbatim anchor) is
// admitted and dispatches, and the run continues past admission
// instead of terminating UNSUPPORTED.
func TestRunDecisionReadySubjectRejectionRepair(t *testing.T) {
	out := t.TempDir()
	drv := &fakeFlowDriver{
		plans: []flow.Plan{
			{StepID: "s1", Actions: []flow.PlanAction{{
				ID: "a1", AdapterID: "package-usage",
				Arguments: json.RawMessage(anchorSubjectArgs),
				Purpose:   "check a package the structured data never declared",
			}}},
			{StepID: "s1", Actions: []flow.PlanAction{{
				ID: "a1", AdapterID: "package-usage",
				Arguments: json.RawMessage(anchorSubjectArgs),
				Purpose:   "check the authz interceptor package the advisory text names",
				Anchor:    anchorSubjectQuote,
			}}},
		},
		reas: []flow.Reassessment{{Status: flow.ReassessReady}},
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: anchorRunOptions(t, out),
		Agent:       drv,
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-subject-repair",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Exactly one repair turn: the first plan was contract-valid and
	// admission refused it, so the second PlanInput carries the
	// recorded rejection and the rejected plan re-encoded.
	if len(drv.seenIn) != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn", len(drv.seenIn))
	}
	if drv.seenIn[0].RepairError != "" || drv.seenIn[0].RepairAnswer != "" {
		t.Fatalf("first attempt carried repair feedback: %+v", drv.seenIn[0])
	}
	if !strings.Contains(drv.seenIn[1].RepairError, SubjectAnchorMissingReason) {
		t.Fatalf("repair turn lacks the gate reason: %q", drv.seenIn[1].RepairError)
	}
	if !strings.Contains(drv.seenIn[1].RepairAnswer, "middleware/authz") {
		t.Fatalf("repair turn lacks the rejected plan: %q", drv.seenIn[1].RepairAnswer)
	}
	// The repaired plan was admitted and dispatched — the recorded
	// action carries its verified anchor.
	if rec.Result.Termination == flow.TermUnsupported {
		t.Fatalf("repaired run still rejected: %q", rec.Result.Reason)
	}
	if len(rec.Result.Actions) != 1 || rec.Result.Actions[0].Anchor != anchorSubjectQuote {
		t.Fatalf("repaired plan did not dispatch: %+v", rec.Result.Actions)
	}
	// The rejected plan stays in the event stream on the plan event's
	// error member; the repaired plan follows inside the same step.
	var planErrs, plans int
	for _, ev := range rec.Result.Events {
		if ev.Kind != flow.EventPlan {
			continue
		}
		plans++
		if ev.Error != "" {
			planErrs++
			if !strings.Contains(ev.Error, SubjectAnchorMissingReason) {
				t.Fatalf("rejected plan event error = %q", ev.Error)
			}
		}
	}
	if plans != 2 || planErrs != 1 {
		t.Fatalf("plan events = %d (rejected %d), want 2 (1)", plans, planErrs)
	}
	if report.DecisionArtifact == nil {
		t.Fatal("missing artifact")
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// Replay of a recorded anchored run re-admits the recorded action under
// the same gate and reproduces the recorded outcome — no model, no
// drift.
func TestRunDecisionReadyAnchoredReplay(t *testing.T) {
	src := t.TempDir()
	_, rec1, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: anchorRunOptions(t, src),
		Agent: &fakeFlowDriver{
			plans: []flow.Plan{{
				StepID: "s1",
				Actions: []flow.PlanAction{{
					ID: "a1", AdapterID: "package-usage",
					Arguments: json.RawMessage(anchorSubjectArgs),
					Purpose:   "check the authz interceptor package the advisory text names",
					Anchor:    anchorSubjectQuote,
				}},
			}},
			reas: []flow.Reassessment{{Status: flow.ReassessReady}},
		},
		ConfigFS:  r6ConfigFS(t),
		OutputDir: src,
		RunID:     "test-anchored-replay-src",
	})
	if err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	out := t.TempDir()
	_, rec2, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: anchorRunOptions(t, out),
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		ReplayDir:   src,
		RunID:       "test-anchored-replay",
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rec2.Result.Termination != rec1.Result.Termination {
		t.Fatalf("replay diverged: recorded %s replayed %s",
			rec1.Result.Termination, rec2.Result.Termination)
	}
	if len(rec2.Trace.Requests) != 1 || rec2.Trace.Requests[0].DerivedFrom == nil {
		t.Fatalf("replayed trace lost the anchor provenance: %+v", rec2.Trace.Requests)
	}
}
