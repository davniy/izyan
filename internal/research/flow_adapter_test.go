package research

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/flow"
	"github.com/davniy/izyan/internal/goanalysis"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// ---- fixtures ----

// r6ConfigFS returns the repository-root fs view the production route
func r6ConfigFS(t *testing.T) fs.FS {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return os.DirFS(root)
}

// writeR6Advisory pins the frozen advisory used across the lane tests —
// bound to the testdata/evidencesnap fixture exactly like the
// verification-phase tests.
func writeR6Advisory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0001",
	  "aliases": ["CVE-TEST-1"],
	  "summary": "test advisory for snapdep Parse",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	p := filepath.Join(dir, "GO-TEST-0001.json")
	if err := os.WriteFile(p, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func r6LaneOptions(t *testing.T, outDir string) LaneOptions {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	return LaneOptions{
		CVE: "GO-TEST-0001", SnapshotPath: root, AdvisoryFile: writeR6Advisory(t),
		ExternalCommitSHA: "fixture-sha-1", Timeout: 90 * time.Second,
	}
}

// fakeFlowDriver is the deterministic AgentDriver for tests: it serves
// queued plans/reassessments, never a model. planErrs is consumed in
// call order before plans — a *flow.PlanContractError models the
// driver's contract-failure class so the engine's single bounded
// self-repair turn is exercised end to end. seenIn records every
// PlanInput the engine handed it so tests can assert the advertised
// surface (available/required/discharged checks, repair feedback).
type fakeFlowDriver struct {
	plans    []flow.Plan
	reas     []flow.Reassessment
	planErr  error
	planErrs []error
	pi, ri   int
	seenIn   []flow.PlanInput
}

func (d *fakeFlowDriver) Plan(_ context.Context, in flow.PlanInput) (flow.Plan, AgentTurnMetadata, error) {
	d.seenIn = append(d.seenIn, in)
	d.pi++
	meta := AgentTurnMetadata{Role: "plan", Ordinal: d.pi, Status: AgentOK}
	if d.pi <= len(d.planErrs) {
		perr := d.planErrs[d.pi-1]
		var cerr *flow.PlanContractError
		meta.Status = AgentFailed
		if errors.As(perr, &cerr) {
			meta.Status = AgentInvalidFormat
		}
		meta.Err = perr.Error()
		return flow.Plan{}, meta, perr
	}
	if d.planErr != nil {
		meta.Status, meta.Err = AgentFailed, d.planErr.Error()
		return flow.Plan{}, meta, d.planErr
	}
	if len(d.plans) == 0 {
		return flow.Plan{}, meta, errors.New("fake driver has no plan")
	}
	p := d.plans[min(d.pi-1-len(d.planErrs), len(d.plans)-1)]
	return p, meta, nil
}

func (d *fakeFlowDriver) Reassess(context.Context, flow.ReassessInput) (flow.Reassessment, AgentTurnMetadata, error) {
	d.ri++
	meta := AgentTurnMetadata{Role: "reassess", Ordinal: d.ri, Status: AgentOK}
	if len(d.reas) == 0 {
		return flow.Reassessment{}, meta, errors.New("fake driver has no reassessment")
	}
	r := d.reas[min(d.ri-1, len(d.reas)-1)]
	return r, meta, nil
}

// ---- unit tests: no lane, no session ----

func TestFlowCatalogAdmission(t *testing.T) {
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	cat := newFlowCatalog(cats, evidencetools.DefaultCheckCatalog(), "")
	// Every checks.yaml id is advertised (policy surface).
	listed := map[string]bool{}
	for _, s := range cat.List() {
		listed[s.ID] = true
	}
	for _, ck := range cats.Checks {
		if !listed[ck.ID] {
			t.Fatalf("catalog id %q missing from List()", ck.ID)
		}
	}
	// Lane-internal checks stay registered but are never dispatchable.
	if _, ok := cat.Lookup("affected-resolve"); ok {
		t.Fatal("affected-resolve must not resolve to a dispatchable session spec")
	}
	if err := cat.Validate("affected-resolve", json.RawMessage(`{}`)); err == nil {
		t.Fatal("affected-resolve must fail validation (lane-internal)")
	}
	// A dispatchable id validates against the session schema.
	if err := cat.Validate("find_entrypoints", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("find_entrypoints rejected: %v", err)
	}
	// A checks.yaml id absent from the session catalog fails closed;
	// an unknown id is simply unregistered.
	if err := cat.Validate("run_build", json.RawMessage(`{}`)); err == nil {
		t.Fatal("run_build must not be admitted — it is not in checks.yaml")
	}
	if err := cat.Validate("nonsense-check", json.RawMessage(`{}`)); err == nil {
		t.Fatal("unknown check admitted")
	}
}

// TestFlowCatalogPositiveAnswer pins the catalog's answer-semantics
// verdict the broker stamps onto produced observations: package-usage
// USED with a scoped, snapshot-bound record is a positive answer;
// UNKNOWN, off-snapshot, unscoped or wrong-tool records answer nothing.
func TestFlowCatalogPositiveAnswer(t *testing.T) {
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	cat := newFlowCatalog(cats, evidencetools.DefaultCheckCatalog(), "h1")
	obs := func(tool string, status evidencetools.ToolStatus, comp evidencetools.Completeness,
		scope, snap, usage string) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: "OBS-T", Tool: tool, ToolStatus: status, Completeness: comp, Scope: scope,
			ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: snap},
			Data:         map[string]any{"module": "m", "package": "m/p", "usage": usage},
		}
	}
	unreach := func(comp evidencetools.Completeness, snap string, result goanalysis.UnreachabilityResult) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: "OBS-U", Tool: evidencetools.SymbolUnreachabilityTool,
			ToolStatus: evidencetools.StatusOK, Completeness: comp, Scope: "closed product scope",
			ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: snap},
			Data:         evidencetools.SymbolUnreachabilityData{Result: result},
		}
	}
	reached := goanalysis.UnreachabilityResult{
		Module:   "m",
		Subjects: []goanalysis.UnreachabilitySubject{{Package: "m/p", Symbol: "Parse"}},
		ProductReferences: []domain.CallSite{{
			File: "main.go", Function: "main", Package: "example.com/product", Callee: "vuln.Parse"}},
	}
	chained := goanalysis.UnreachabilityResult{
		Module:          "m",
		Subjects:        []goanalysis.UnreachabilitySubject{{Package: "m/p", Symbol: "Parse"}},
		ModuleReachable: map[string][]string{"m/p.Parse": {"m.Dial", "m/p.Parse"}},
	}
	open := goanalysis.UnreachabilityResult{
		Module:   "m",
		Subjects: []goanalysis.UnreachabilitySubject{{Package: "m/p", Symbol: "Parse"}},
	}
	closed := goanalysis.UnreachabilityResult{
		Module:              "m",
		Subjects:            []goanalysis.UnreachabilitySubject{{Package: "m/p", Symbol: "Parse"}},
		Complete:            true,
		DeclarationComplete: true,
		EntrypointComplete:  true,
	}
	for _, tc := range []struct {
		name string
		o    *evidencetools.Observation
		want bool
	}{
		{"used-partial", obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
			evidencetools.CompletenessPartial, "scope", "h1", "USED"), true},
		{"used-symbol-level", func() *evidencetools.Observation {
			o := obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
				evidencetools.CompletenessPartial, "scope", "h1", "USED")
			o.Data.(map[string]any)["symbol"] = "Parse"
			return o
		}(), true},
		{"unknown-verdict", obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
			evidencetools.CompletenessPartial, "scope", "h1", "UNKNOWN"), false},
		{"not-used-partial", obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
			evidencetools.CompletenessPartial, "scope", "h1", "NOT_USED"), false},
		{"off-snapshot", obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
			evidencetools.CompletenessPartial, "scope", "other", "USED"), false},
		{"unscoped", obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
			evidencetools.CompletenessPartial, " ", "h1", "USED"), false},
		{"errored", obs(evidencetools.PackageUsageTool, evidencetools.StatusError,
			evidencetools.CompletenessUnknown, "scope", "h1", "USED"), false},
		{"wrong-tool", obs("usage-scope", evidencetools.StatusOK,
			evidencetools.CompletenessPartial, "scope", "h1", "USED"), false},
		{"no-payload", func() *evidencetools.Observation {
			o := obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
				evidencetools.CompletenessPartial, "scope", "h1", "USED")
			o.Data = nil
			return o
		}(), false},
		// symbol-unreachability: a disproven record — product
		// references or a module-internal reach chain — answers the
		// check's question; an open proof answers nothing; a closed
		// proof takes the COMPLETE path upstream and is not asked.
		{"disproven-product-refs", unreach(evidencetools.CompletenessPartial, "h1", reached), true},
		{"disproven-module-chain", unreach(evidencetools.CompletenessPartial, "h1", chained), true},
		{"unreach-open-proof", unreach(evidencetools.CompletenessPartial, "h1", open), false},
		{"unreach-closed", unreach(evidencetools.CompletenessComplete, "h1", closed), false},
		{"unreach-off-snapshot", unreach(evidencetools.CompletenessPartial, "other", reached), false},
		{"unreach-bad-payload", func() *evidencetools.Observation {
			o := unreach(evidencetools.CompletenessPartial, "h1", reached)
			o.Data = map[string]any{"result": "garbage"}
			return o
		}(), false},
		{"unreach-unscoped", func() *evidencetools.Observation {
			o := unreach(evidencetools.CompletenessPartial, "h1", reached)
			o.Scope = " "
			return o
		}(), false},
		{"unreach-errored", func() *evidencetools.Observation {
			o := unreach(evidencetools.CompletenessPartial, "h1", reached)
			o.ToolStatus = evidencetools.StatusError
			return o
		}(), false},
	} {
		if got := cat.PositiveAnswer(tc.o); got != tc.want {
			t.Fatalf("%s: PositiveAnswer=%v, want %v", tc.name, got, tc.want)
		}
	}
	// A nil observation and a catalog with no snapshot binding still
	// fail closed.
	if cat.PositiveAnswer(nil) {
		t.Fatal("nil observation answered positively")
	}
	unbound := newFlowCatalog(cats, evidencetools.DefaultCheckCatalog(), "")
	if !unbound.PositiveAnswer(obs(evidencetools.PackageUsageTool, evidencetools.StatusOK,
		evidencetools.CompletenessPartial, "scope", "any-hash", "USED")) {
		t.Fatal("a bound observation with no lane hash must still answer")
	}
}

func TestLoadFlowRubric(t *testing.T) {
	fsys := fstest.MapFS{
		"rubrics/research.yaml": {Data: []byte(`{
		  "schema":"research-flow-rubric/1","max_steps":4,"max_actions":9,
		  "prompts":{"plan":"p/plan.txt","reassess":"p/reassess.txt","counterexample":"p/counter.txt"}}`)},
		"p/plan.txt":     {Data: []byte("plan v1")},
		"p/reassess.txt": {Data: []byte("reassess v1")},
		"p/counter.txt":  {Data: []byte("counter v1")},
	}
	r, err := LoadFlowRubric(fsys)
	if err != nil {
		t.Fatalf("rubric: %v", err)
	}
	if r.MaxSteps != 4 || r.MaxActions != 9 {
		t.Fatalf("budgets %+v", r)
	}
	if !strings.HasPrefix(r.PromptDigest, "sha256:") || len(r.PromptDigest) != len("sha256:")+64 {
		t.Fatalf("prompt digest %q", r.PromptDigest)
	}
	if r.PromptSHA("p/plan.txt") == "" || r.PromptSHA("p/plan.txt") == r.PromptSHA("p/reassess.txt") {
		t.Fatal("prompt pins not distinct")
	}

	badSchema := fstest.MapFS{"rubrics/research.yaml": {Data: []byte(`{"schema":"wrong/1"}`)}}
	if _, err := LoadFlowRubric(badSchema); err == nil {
		t.Fatal("wrong schema accepted")
	}
	badBudget := fstest.MapFS{
		"rubrics/research.yaml": {Data: []byte(`{"schema":"research-flow-rubric/1","max_steps":0,"max_actions":2,"prompts":{"plan":"a","reassess":"b","counterexample":"c"}}`)},
		"a":                     {Data: []byte("x")}, "b": {Data: []byte("y")}, "c": {Data: []byte("z")},
	}
	if _, err := LoadFlowRubric(badBudget); err == nil {
		t.Fatal("zero budget accepted")
	}
	missingPrompt := fstest.MapFS{
		"rubrics/research.yaml": {Data: []byte(`{"schema":"research-flow-rubric/1","max_steps":1,"max_actions":2,"prompts":{"plan":"a","reassess":"b","counterexample":"missing.txt"}}`)},
		"a":                     {Data: []byte("x")}, "b": {Data: []byte("y")},
	}
	if _, err := LoadFlowRubric(missingPrompt); err == nil {
		t.Fatal("missing prompt file accepted")
	}
	if _, err := LoadFlowRubric(r6ConfigFS(t)); err != nil {
		t.Fatalf("committed rubric does not load: %v", err)
	}
}

func TestDischargedLaneChecks(t *testing.T) {
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	lane := &LaneResult{ContentHash: "h1", CanonicalByObs: map[string]string{}}
	// pin registers the persisted (wire-decoded) copy of the record and
	// writes the canonical digest the persistence layer recorded —
	// discharge re-verifies the pinned copy's bytes against the pin.
	pin := func(o *evidencetools.Observation) string {
		t.Helper()
		d, err := canonicalObservationDigest(o)
		if err != nil {
			t.Fatal(err)
		}
		lane.Observations = append(lane.Observations, o)
		lane.CanonicalByObs[o.ID] = d
		return d
	}
	okComplete := func(id, tool, rule string) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: id, Tool: tool, ToolStatus: evidencetools.StatusOK,
			Completeness: evidencetools.CompletenessComplete, Scope: "closed scope",
			ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: "h1", CoverageRule: rule}}
	}
	rec := func(tool string, o *evidencetools.Observation) evidencetools.AuditRecord {
		return evidencetools.AuditRecord{Tool: tool, Args: json.RawMessage(`{}`), Observation: o}
	}

	// OBS-0001: the lane-internal required check — a complete,
	// snapshot-bound, digest-pinned record with NO evidence refs.
	// promotableObservation refuses it (a fact needs pinned evidence);
	// the discharge gate admits it — the record itself is the proof the
	// lane ran the check to a closed scope.
	resolve := okComplete("OBS-0001", "affected-resolve",
		"closed applicability chain: module graph → version ranges → import closure → build relevance")
	pinResolve := pin(resolve)
	// OBS-0002: PARTIAL completeness never discharges.
	partial := okComplete("OBS-0002", "usage-scope", "rule")
	partial.Completeness = evidencetools.CompletenessPartial
	pin(partial)
	// OBS-0009: no canonical pin — never discharges.
	unpinned := okComplete("OBS-0009", "package-usage", "rule")
	// OBS-0003: stale snapshot binding — never discharges.
	stale := okComplete("OBS-0003", "module_usage", "rule")
	stale.ScopeDetails.SnapshotHash = "other"
	pin(stale)
	// OBS-0004: a tool outside the checks catalog cannot discharge a
	// policy check.
	unmapped := okComplete("OBS-0004", "unmapped-tool", "rule")
	pin(unmapped)
	// OBS-0005: an errored record never discharges.
	errored := okComplete("OBS-0005", "affected-resolve", "rule")
	errored.ToolStatus = evidencetools.StatusError
	errored.Completeness = evidencetools.CompletenessUnknown
	pin(errored)
	// OBS-0006: a pin that does not match the record's bytes never
	// discharges — the digest binds the persisted payload.
	mismatch := okComplete("OBS-0006", "usage-scope", "rule")
	lane.Observations = append(lane.Observations, mismatch)
	lane.CanonicalByObs[mismatch.ID] = strings.Repeat("f", 64)
	// OBS-0007: a complete record with no named coverage rule claims no
	// closed scope — never discharges.
	noRule := okComplete("OBS-0007", "module-usage", "")
	pin(noRule)

	lane.Records = []evidencetools.AuditRecord{
		rec("affected-resolve", resolve),
		rec("usage-scope", partial),
		rec("package-usage", unpinned),
		rec("module_usage", stale),
		rec("unmapped-tool", unmapped),
		rec("affected-resolve", errored),
		rec("usage-scope", mismatch),
		rec("module-usage", noRule),
	}
	completed, evidence := dischargedLaneChecks(lane, cats)
	if len(completed) != 1 || completed[0] != "affected-resolve" {
		t.Fatalf("completed=%v, want [affected-resolve]", completed)
	}
	if len(evidence) != 1 || evidence[0].ID != "OBS-0001" || !evidence[0].AuditBound || evidence[0].DataDigest != pinResolve {
		t.Fatalf("evidence=%+v", evidence)
	}
}

// TestDischargedLaneChecksPositiveAnswer pins the positive-answer
// discharge path on the lane gate: a package-usage record whose
// payload answers the check's question (USED, PARTIAL by contract —
// positive static usage never claims runtime execution) discharges
// the required check and stamps the positive path on the evidence
// row, while every degraded shape that answers nothing still fails
// closed.
func TestDischargedLaneChecksPositiveAnswer(t *testing.T) {
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	lane := &LaneResult{ContentHash: "h1", CanonicalByObs: map[string]string{}}
	pin := func(o *evidencetools.Observation) {
		t.Helper()
		d, err := canonicalObservationDigest(o)
		if err != nil {
			t.Fatal(err)
		}
		lane.Observations = append(lane.Observations, o)
		lane.CanonicalByObs[o.ID] = d
	}
	usage := func(id, verdict string) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: id, Tool: evidencetools.PackageUsageTool, ToolStatus: evidencetools.StatusOK,
			Completeness: evidencetools.CompletenessPartial,
			Scope:        "bounded product source scope",
			ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: "h1"},
			Limitations:  []string{"positive static usage does not establish runtime execution or attacker reachability"},
			Data:         map[string]any{"module": "example.com/dep", "package": "example.com/dep/vuln", "usage": verdict},
		}
	}
	rec := func(o *evidencetools.Observation) evidencetools.AuditRecord {
		return evidencetools.AuditRecord{Tool: o.Tool, Args: json.RawMessage(`{}`), Observation: o}
	}

	// OBS-0001: USED at PARTIAL — the positive answer discharges.
	used := usage("OBS-0001", "USED")
	pin(used)
	// OBS-0002: UNKNOWN at PARTIAL — a degraded record that answers
	// nothing never discharges.
	unknown := usage("OBS-0002", "UNKNOWN")
	pin(unknown)
	// OBS-0003: USED but off-snapshot — never discharges.
	stale := usage("OBS-0003", "USED")
	stale.ScopeDetails.SnapshotHash = "other"
	pin(stale)
	// OBS-0004: USED but unscoped — never discharges.
	unscoped := usage("OBS-0004", "USED")
	unscoped.Scope = "  "
	pin(unscoped)
	// OBS-0005: NOT_USED at PARTIAL (unverified negative) — answers
	// nothing on this check's contract.
	negPartial := usage("OBS-0005", "NOT_USED")
	pin(negPartial)

	lane.Records = []evidencetools.AuditRecord{
		rec(used), rec(unknown), rec(stale), rec(unscoped), rec(negPartial),
	}
	completed, evidence := dischargedLaneChecks(lane, cats)
	if len(completed) != 1 || completed[0] != "package-usage" {
		t.Fatalf("completed=%v, want [package-usage]", completed)
	}
	if len(evidence) != 1 || evidence[0].ID != "OBS-0001" ||
		evidence[0].DischargePath != flow.DischargePositiveAnswer {
		t.Fatalf("positive discharge not recorded on the evidence row: %+v", evidence)
	}

	// The closed-negative path is unchanged: a COMPLETE, rule-named,
	// snapshot-bound record still discharges and stamps its own path.
	lane2 := &LaneResult{ContentHash: "h1", CanonicalByObs: map[string]string{}}
	neg := &evidencetools.Observation{
		ID: "OBS-0009", Tool: evidencetools.PackageUsageTool, ToolStatus: evidencetools.StatusOK,
		Completeness: evidencetools.CompletenessComplete,
		Scope:        "closed negative verification scope",
		ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: "h1", CoverageRule: "closed negative verification"},
		Data:         map[string]any{"module": "example.com/dep", "package": "example.com/dep/vuln", "usage": "NOT_USED", "negative_verification": "VERIFIED"},
	}
	d, err := canonicalObservationDigest(neg)
	if err != nil {
		t.Fatal(err)
	}
	lane2.Observations = append(lane2.Observations, neg)
	lane2.CanonicalByObs[neg.ID] = d
	lane2.Records = []evidencetools.AuditRecord{rec(neg)}
	completed2, evidence2 := dischargedLaneChecks(lane2, cats)
	if len(completed2) != 1 || completed2[0] != "package-usage" ||
		len(evidence2) != 1 || evidence2[0].DischargePath != flow.DischargeClosedNegative {
		t.Fatalf("closed-negative discharge = %v / %+v", completed2, evidence2)
	}
}

// TestDischargedLaneChecksUnreachabilityAnswered pins the same
// positive-answer discharge for symbol-unreachability: a disproven
// record (concrete reach evidence, PARTIAL by contract) discharges the
// check through the positive path, while an open proof — or an
// undecodable payload — still discharges nothing.
func TestDischargedLaneChecksUnreachabilityAnswered(t *testing.T) {
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	lane := &LaneResult{ContentHash: "h1", CanonicalByObs: map[string]string{}}
	pin := func(o *evidencetools.Observation) {
		t.Helper()
		d, err := canonicalObservationDigest(o)
		if err != nil {
			t.Fatal(err)
		}
		lane.Observations = append(lane.Observations, o)
		lane.CanonicalByObs[o.ID] = d
	}
	rec := func(o *evidencetools.Observation) evidencetools.AuditRecord {
		return evidencetools.AuditRecord{Tool: o.Tool, Args: json.RawMessage(`{}`), Observation: o}
	}
	unreach := func(id string, result goanalysis.UnreachabilityResult) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: id, Tool: evidencetools.SymbolUnreachabilityTool,
			ToolStatus: evidencetools.StatusOK, Completeness: evidencetools.CompletenessPartial,
			Scope:        "product packages plus module internals",
			ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: "h1"},
			Data:         evidencetools.SymbolUnreachabilityData{Result: result},
		}
	}
	subj := []goanalysis.UnreachabilitySubject{{Package: "example.com/dep/vuln", Symbol: "Parse"}}
	disproven := unreach("OBS-0100", goanalysis.UnreachabilityResult{
		Module:   "example.com/dep",
		Subjects: subj,
		ProductReferences: []domain.CallSite{{
			File: "main.go", Function: "main", Package: "example.com/product", Callee: "vuln.Parse"}},
	})
	pin(disproven)
	openProof := unreach("OBS-0101", goanalysis.UnreachabilityResult{
		Module:   "example.com/dep",
		Subjects: subj,
	})
	pin(openProof)
	garbage := unreach("OBS-0102", goanalysis.UnreachabilityResult{})
	garbage.Data = map[string]any{"result": "not-a-result"}
	pin(garbage)

	lane.Records = []evidencetools.AuditRecord{rec(disproven), rec(openProof), rec(garbage)}
	completed, evidence := dischargedLaneChecks(lane, cats)
	if len(completed) != 1 || completed[0] != "symbol-unreachability" {
		t.Fatalf("completed=%v, want [symbol-unreachability]", completed)
	}
	if len(evidence) != 1 || evidence[0].ID != "OBS-0100" ||
		evidence[0].DischargePath != flow.DischargePositiveAnswer {
		t.Fatalf("unreachability positive discharge = %v / %+v", completed, evidence)
	}
}

func TestFlowTraceAuditBinding(t *testing.T) {
	obs := &evidencetools.Observation{ID: "OBS-0010", Tool: "find_entrypoints",
		ToolStatus: evidencetools.StatusOK, Completeness: evidencetools.CompletenessComplete}
	res := &flow.Result{Actions: []flow.PlanAction{
		{ID: "a1", AdapterID: "find_entrypoints", Arguments: json.RawMessage(`{"x":1,"y":2}`), Purpose: "p"},
		{ID: "a2", AdapterID: "read_source", Arguments: json.RawMessage(`{"file":"m.go"}`), Purpose: "p"},
	}}
	audit := []evidencetools.AuditRecord{
		// Member-order difference still binds (canonical comparison).
		{Tool: "find_entrypoints", Args: json.RawMessage(`{"y":2,"x":1}`), Observation: obs},
		// Recorded arguments differ → unbound, limitation recorded.
		{Tool: "read_source", Args: json.RawMessage(`{"file":"other.go"}`), Observation: obs},
	}
	trace, bound := flowTraceFromRecords(res, audit, nil)
	if len(trace.Requests) != 2 || len(trace.Observations) != 2 || len(bound) != 1 {
		t.Fatalf("requests=%d observations=%d bound=%d", len(trace.Requests), len(trace.Observations), len(bound))
	}
	if trace.Complete {
		t.Fatal("missing audit pairing must make trace incomplete")
	}
	if trace.Requests[0].ID != "a1" || trace.Requests[0].Tool != "find_entrypoints" {
		t.Fatalf("request=%+v", trace.Requests[0])
	}
	if len(trace.Limitations) < 1 {
		t.Fatalf("limitations=%v", trace.Limitations)
	}
	// Catalog-id surface (hyphen) still binds the session tool name.
	res2 := &flow.Result{Actions: []flow.PlanAction{
		{ID: "a1", AdapterID: "find-entrypoints", Arguments: json.RawMessage(`{}`), Purpose: "p"}}}
	audit2 := []evidencetools.AuditRecord{
		{Tool: "find_entrypoints", Args: json.RawMessage(`{}`), Observation: obs}}
	trace2, bound2 := flowTraceFromRecords(res2, audit2, nil)
	if len(bound2) != 1 || len(trace2.Requests) != 1 {
		t.Fatal("hyphen/underscore surface failed to bind")
	}
}

func flowTraceAction(id, tool, args string) flow.PlanAction {
	return flow.PlanAction{ID: id, AdapterID: tool, Arguments: json.RawMessage(args), Purpose: "test"}
}

func flowTraceObservation(id, tool string) *evidencetools.Observation {
	return &evidencetools.Observation{ID: id, Tool: tool, ToolStatus: evidencetools.StatusOK, Completeness: evidencetools.CompletenessComplete, Scope: "closed", ScopeDetails: &evidencetools.ScopeDetails{}}
}

func flowTraceHasLimitation(trace *VerificationTrace, want string) bool {
	for _, limitation := range trace.Limitations {
		if strings.Contains(limitation, want) {
			return true
		}
	}
	return false
}

func TestFlowTracePairingAcceptanceMatrix(t *testing.T) {
	action := flowTraceAction("a1", "tool", `{"x":1}`)
	res := &flow.Result{Actions: []flow.PlanAction{action}}
	good := evidencetools.AuditRecord{Tool: "tool", Args: json.RawMessage(`{"x":1}`), Observation: flowTraceObservation("o1", "tool")}

	t.Run("extra audit row", func(t *testing.T) {
		trace, bound := flowTraceFromRecords(res, []evidencetools.AuditRecord{good, {Tool: "other", Args: json.RawMessage(`{}`), Observation: flowTraceObservation("o2", "other")}}, nil)
		if trace.Complete || len(bound) != 1 || !flowTraceHasLimitation(trace, "cannot become a fact") {
			t.Fatalf("trace=%+v bound=%d", trace, len(bound))
		}
	})
	t.Run("duplicate observation ids", func(t *testing.T) {
		dup := good
		dup.Observation = flowTraceObservation("o1", "tool")
		trace, _ := flowTraceFromRecords(&flow.Result{Actions: []flow.PlanAction{action, flowTraceAction("a2", "tool", `{"x":2}`)}}, []evidencetools.AuditRecord{good, {Tool: "tool", Args: json.RawMessage(`{"x":2}`), Observation: dup.Observation}}, nil)
		if trace.Complete || !flowTraceHasLimitation(trace, "duplicate observation id") {
			t.Fatalf("trace=%+v", trace)
		}
	})
	t.Run("mismatched arguments", func(t *testing.T) {
		trace, _ := flowTraceFromRecords(res, []evidencetools.AuditRecord{{Tool: "tool", Args: json.RawMessage(`{"x":2}`), Observation: good.Observation}}, nil)
		if trace.Complete || !flowTraceHasLimitation(trace, "tool/argument mismatch") {
			t.Fatalf("trace=%+v", trace)
		}
	})
	t.Run("unexecuted contiguous tail", func(t *testing.T) {
		second := flowTraceAction("a2", "tool", `{"x":2}`)
		planned := &flow.Result{Steps: []flow.StepRecord{{Plan: flow.Plan{Actions: []flow.PlanAction{action, second}}}}, Actions: []flow.PlanAction{action}}
		trace, _ := flowTraceFromRecords(planned, []evidencetools.AuditRecord{good}, nil)
		if trace.Complete || len(trace.Requests) != 2 || len(trace.Observations) != 1 || !flowTraceHasLimitation(trace, "unexecuted") {
			t.Fatalf("trace=%+v", trace)
		}
	})
	t.Run("empty audit", func(t *testing.T) {
		trace, _ := flowTraceFromRecords(res, nil, nil)
		if trace.Complete || len(trace.Observations) != 1 || !flowTraceHasLimitation(trace, "no matching session audit") {
			t.Fatalf("trace=%+v", trace)
		}
	})
	t.Run("positive control", func(t *testing.T) {
		trace, bound := flowTraceFromRecords(res, []evidencetools.AuditRecord{good}, nil)
		if !trace.Complete || len(trace.Requests) != 1 || len(trace.Observations) != 1 || len(bound) != 1 {
			t.Fatalf("trace=%+v bound=%d", trace, len(bound))
		}
	})
	t.Run("duplicate actions dispatch order", func(t *testing.T) {
		second := action
		second.ID = "a2"
		firstObs := flowTraceObservation("o1", "tool")
		secondObs := flowTraceObservation("o2", "tool")
		trace, bound := flowTraceFromRecords(&flow.Result{Actions: []flow.PlanAction{action, second}}, []evidencetools.AuditRecord{
			{Tool: "tool", Args: json.RawMessage(`{"x":1}`), Observation: firstObs},
			{Tool: "tool", Args: json.RawMessage(`{"x":1}`), Observation: secondObs},
		}, nil)
		if !trace.Complete || len(bound) != 2 || trace.Observations[0].ID != "o1" || trace.Observations[1].ID != "o2" {
			t.Fatalf("trace=%+v bound=%d", trace, len(bound))
		}
	})
}

func TestFlowTracePairingPersistenceReplay(t *testing.T) {
	action := flowTraceAction("a1", "tool", `{"x":1}`)
	obs := flowTraceObservation("o1", "tool")
	original, _ := flowTraceFromRecords(&flow.Result{Actions: []flow.PlanAction{action}}, []evidencetools.AuditRecord{{Tool: "tool", Args: json.RawMessage(`{"x":1}`), Observation: obs}}, nil)
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var replayed VerificationTrace
	if err := json.Unmarshal(raw, &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.Complete != original.Complete || len(replayed.Requests) != len(original.Requests) || len(replayed.Observations) != len(original.Observations) || len(replayed.Limitations) != len(original.Limitations) {
		t.Fatalf("pairing changed across persistence: original=%+v replayed=%+v", original, &replayed)
	}
}

func TestDecisionForArtifactProjection(t *testing.T) {
	hold := &DecisionArtifact{ProposedDisposition: DispositionHoldUnknown}
	d := decisionForArtifact(hold, nil)
	if d.Verdict != "INCONCLUSIVE" || len(d.HumanQuestions) == 0 || d.Coverage != "NOT_EVALUATED" {
		t.Fatalf("hold projection %+v", d)
	}
	for _, disposition := range []ProposedDisposition{DispositionCloseNotAffected, DispositionCloseNoExploitPath} {
		d = decisionForArtifact(&DecisionArtifact{ProposedDisposition: disposition}, nil)
		if d.Verdict != "INCONCLUSIVE" || d.Coverage != "NOT_EVALUATED" {
			t.Fatalf("close bypassed authority for %s: %+v", disposition, d)
		}
	}
}

func TestCompareReplayedArtifact(t *testing.T) {
	dir := t.TempDir()
	rec := DecisionArtifact{
		Schema:              DecisionArtifactSchemaV1,
		ProposedDisposition: DispositionHoldUnknown,
		Branches: []DecisionBranch{
			{ID: "B-UNKNOWN", Status: BranchNotDecisionReady, ProposedDisposition: DispositionHoldUnknown},
		},
	}
	raw, _ := json.Marshal(rec)
	p := filepath.Join(dir, "decision-artifact.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	same := rec
	if err := compareReplayedArtifact(&same, p); err != nil {
		t.Fatalf("identical artifact rejected: %v", err)
	}
	drift := rec
	drift.ProposedDisposition = DispositionCloseNotAffected
	if err := compareReplayedArtifact(&drift, p); err == nil {
		t.Fatal("disposition drift accepted")
	}
	drift2 := rec
	drift2.Branches = append(drift2.Branches, DecisionBranch{ID: "B-X", Status: BranchComplete})
	if err := compareReplayedArtifact(&drift2, p); err == nil {
		t.Fatal("branch drift accepted")
	}

	// A recorded historical closure that current advisory-scope admission no
	// longer authorizes is refused as policy drift — never silently declared
	// equivalent to the demoted rebuild.
	recorded := validArtifact(t)
	recorded.ProposedDisposition = DispositionCloseNotAffected
	recorded.Branches[0].ProposedDisposition = DispositionCloseNotAffected
	recorded.JustificationGraph[0].Disposition = DispositionCloseNotAffected
	rawClose, err := json.Marshal(recorded)
	if err != nil {
		t.Fatal(err)
	}
	pClose := filepath.Join(dir, "recorded-close.json")
	if err := os.WriteFile(pClose, rawClose, 0o644); err != nil {
		t.Fatal(err)
	}
	demoted := scopeBoundArtifact(nil, recorded)
	if demoted == nil || demoted.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("scope guard did not demote the closure: %+v", demoted)
	}
	err = compareReplayedArtifact(demoted, pClose)
	if err == nil {
		t.Fatal("replay of a no-longer-admissible closure was accepted")
	}
	if !strings.Contains(err.Error(), "policy drift") {
		t.Fatalf("replay refusal must name the policy drift, got: %v", err)
	}
}

// ---- session-backed adapter tests (real lane over testdata fixture) ----

func TestRunDecisionReadyDeterministicOnly(t *testing.T) {
	out := t.TempDir()
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions:       r6LaneOptions(t, out),
		ConfigFS:          r6ConfigFS(t),
		OutputDir:         out,
		DeterministicOnly: true,
		RunID:             "test-det",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination != flow.TermPlannerFailure {
		t.Fatalf("termination %q, want PLANNER_FAILURE", rec.Result.Termination)
	}
	if report.Schema != ReportSchemaV3 || report.DecisionArtifact == nil {
		t.Fatalf("report schema %q artifact %+v", report.Schema, report.DecisionArtifact)
	}
	if report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("non-ready run proposed %s", report.DecisionArtifact.ProposedDisposition)
	}
	if report.Decision == nil || report.Decision.Verdict != "INCONCLUSIVE" {
		t.Fatalf("decision projection %+v", report.Decision)
	}
	for _, f := range []string{flowResultFile, flowEventsFile, flowFactsFile, decisionArtifactFile} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
	if len(rec.Turns) == 0 || rec.Turns[0].Status != AgentFailed {
		t.Fatalf("turns %+v", rec.Turns)
	}
}

func TestRunDecisionReadyReplay(t *testing.T) {
	src := t.TempDir()
	if _, _, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions:       r6LaneOptions(t, src),
		ConfigFS:          r6ConfigFS(t),
		OutputDir:         src,
		DeterministicOnly: true,
		RunID:             "test-replay-src",
	}); err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	out := t.TempDir()
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		ReplayDir:   src,
		RunID:       "test-replay",
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rec.Result.Termination != flow.TermPlannerFailure {
		t.Fatalf("replayed termination %q", rec.Result.Termination)
	}
	if report.DecisionArtifact == nil ||
		report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("replayed artifact %+v", report.DecisionArtifact)
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("replay report invalid:\n%v", err)
	}
}

func TestRunDecisionReadyDriverFailures(t *testing.T) {
	out := t.TempDir()
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent:       &fakeFlowDriver{planErr: errors.New("no model infrastructure")},
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-planerr",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination != flow.TermPlannerFailure {
		t.Fatalf("termination %q", rec.Result.Termination)
	}
	if !strings.Contains(rec.Result.Reason, "no model infrastructure") {
		t.Fatalf("reason %q", rec.Result.Reason)
	}
	if report.DecisionArtifact == nil ||
		report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatal("failure run must hold")
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}

	out2 := t.TempDir()
	report2, rec2, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out2),
		Agent: &fakeFlowDriver{plans: []flow.Plan{{
			StepID: "s1",
			Actions: []flow.PlanAction{
				{ID: "a1", AdapterID: "not-a-check", Arguments: json.RawMessage(`{}`), Purpose: "p"}},
		}}},
		ConfigFS:  r6ConfigFS(t),
		OutputDir: out2,
		RunID:     "test-unsupported",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec2.Result.Termination != flow.TermUnsupported {
		t.Fatalf("termination %q", rec2.Result.Termination)
	}
	if report2.DecisionArtifact == nil ||
		report2.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatal("unsupported run must hold")
	}
}

// TestRunDecisionReadyPlanContractRepair exercises the recorded live
// failure end to end: the driver's first plan answer fails the closed
// wire contract (a PlanContractError — the decode class the harness
// driver produces for e.g. an action-level "module"), the engine
// grants exactly one bounded self-repair turn with the verbatim
// verdict and rejected answer inside PlanInput, and the corrected
// plan continues the run. The manifest records both attempts; the
// event stream records planner_error then plan inside one step.
func TestRunDecisionReadyPlanContractRepair(t *testing.T) {
	out := t.TempDir()
	drv := &fakeFlowDriver{
		planErrs: []error{
			&flow.PlanContractError{
				Answer: `{"step_id":"step-1","actions":[{"id":"s1-a1","adapter_id":"get_product_snapshot","module":"m","arguments":{}}]}`,
				Err:    errors.New(`plan answer did not decode as the plan contract: answer object does not satisfy the contract: json: unknown field "module"`),
			},
		},
		plans: []flow.Plan{{
			StepID: "s1",
			Actions: []flow.PlanAction{
				{ID: "a1", AdapterID: "get_product_snapshot",
					Arguments: json.RawMessage(`{}`), Purpose: "pin snapshot identity"},
			},
		}},
		reas: []flow.Reassessment{{Status: flow.ReassessReady}},
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent:       drv,
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-repair",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(drv.seenIn) != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn", len(drv.seenIn))
	}
	if drv.seenIn[0].RepairError != "" || drv.seenIn[0].RepairAnswer != "" {
		t.Fatalf("first attempt carried repair feedback: %+v", drv.seenIn[0])
	}
	if !strings.Contains(drv.seenIn[1].RepairError, `unknown field "module"`) ||
		!strings.Contains(drv.seenIn[1].RepairAnswer, `"module":"m"`) {
		t.Fatalf("repair turn feedback = %q / %q", drv.seenIn[1].RepairError, drv.seenIn[1].RepairAnswer)
	}
	// Both attempts are recorded: in the manifest turns and in the
	// flow event stream (planner_error then plan at step 1).
	if len(rec.Turns) != 3 || rec.Turns[0].Status != AgentInvalidFormat {
		t.Fatalf("turns %+v, want repaired plan + plan + reassess", rec.Turns)
	}
	var kinds []string
	for _, ev := range rec.Result.Events {
		kinds = append(kinds, ev.Kind)
	}
	if !containsOrdered(kinds, "planner_error", "plan") {
		t.Fatalf("event stream %v lacks the recorded repair sequence", kinds)
	}
	if rec.Result.Termination == flow.TermPlannerFailure {
		t.Fatalf("repaired run still terminated %q", rec.Result.Termination)
	}
	if !rec.Result.Ready && report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("non-ready termination %s proposed %s",
			rec.Result.Termination, report.DecisionArtifact.ProposedDisposition)
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// TestRunDecisionReadyPlanContractRepairFails proves the bound end to
// end: a repair answer that also fails the contract terminates the
// run PLANNER_FAILURE with the second failure recorded — both
// attempts land in the turns and the event stream.
func TestRunDecisionReadyPlanContractRepairFails(t *testing.T) {
	out := t.TempDir()
	drv := &fakeFlowDriver{
		planErrs: []error{
			&flow.PlanContractError{Err: errors.New(`contract: json: unknown field "module"`)},
			&flow.PlanContractError{Err: errors.New(`contract: json: unknown field "symbol"`)},
		},
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent:       drv,
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-repair-fail",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination != flow.TermPlannerFailure {
		t.Fatalf("termination %q, want PLANNER_FAILURE", rec.Result.Termination)
	}
	if !strings.Contains(rec.Result.Reason, `"symbol"`) {
		t.Fatalf("reason %q, want the second contract failure recorded", rec.Result.Reason)
	}
	if len(drv.seenIn) != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn", len(drv.seenIn))
	}
	if len(rec.Turns) != 2 || rec.Turns[0].Status != AgentInvalidFormat ||
		rec.Turns[1].Status != AgentInvalidFormat {
		t.Fatalf("turns %+v, want both malformed attempts recorded", rec.Turns)
	}
	var perr int
	for _, ev := range rec.Result.Events {
		if ev.Kind == "planner_error" {
			perr++
		}
	}
	if perr != 2 {
		t.Fatalf("planner_error events = %d, want both attempts", perr)
	}
	if report.DecisionArtifact == nil ||
		report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatal("failed-repair run must hold")
	}
}

// containsOrdered reports whether want appears inside have in order.
func containsOrdered(have []string, want ...string) bool {
	i := 0
	for _, s := range have {
		if s == want[i] {
			i++
			if i == len(want) {
				return true
			}
		}
	}
	return false
}

func TestRunDecisionReadyFakeDriverFlow(t *testing.T) {
	out := t.TempDir()
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent: &fakeFlowDriver{
			plans: []flow.Plan{{
				StepID: "s1",
				Actions: []flow.PlanAction{
					{ID: "a1", AdapterID: "get_product_snapshot",
						Arguments: json.RawMessage(`{}`), Purpose: "pin snapshot identity"}},
			}},
			reas: []flow.Reassessment{{Status: flow.ReassessReady}},
		},
		ConfigFS:  r6ConfigFS(t),
		OutputDir: out,
		RunID:     "test-fake-flow",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The run either reached a ready state or was correctly held back —
	// never a silent success.
	if rec.Result.Termination != flow.TermDecisionReady &&
		rec.Result.Termination != flow.TermNotDecisionReady &&
		rec.Result.Termination != flow.TermAwaitingEnvironment {
		t.Fatalf("termination %q reason %q", rec.Result.Termination, rec.Result.Reason)
	}
	if !rec.Result.Ready && report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("non-ready termination %s proposed %s",
			rec.Result.Termination, report.DecisionArtifact.ProposedDisposition)
	}
	if len(rec.Turns) != 2 {
		t.Fatalf("turns=%d, want plan+reassess", len(rec.Turns))
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
	// Flow observations persisted through the audit ledger path.
	if len(rec.Result.Actions) == 1 && len(rec.Trace.Observations) != 1 {
		t.Fatalf("trace observations=%d", len(rec.Trace.Observations))
	}
	if _, err := os.Stat(filepath.Join(out, flowObservationLedger)); err != nil {
		t.Fatal("observation ledger missing")
	}
}

// TestRunDecisionReadyReleaseNotRun proves the fail-closed short-circuit:
// a requested artifact channel that cannot resolve terminates the
// decision run NOT_DECISION_READY before any planner turn, the /3 report
// carries the NOT_RUN provenance and run outcome, and validation holds.
func TestRunDecisionReadyReleaseNotRun(t *testing.T) {
	out := t.TempDir()
	opts := r6LaneOptions(t, out)
	opts.ArtifactOptions.Path = filepath.Join(t.TempDir(), "missing-artifact")
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions:       opts,
		ConfigFS:          r6ConfigFS(t),
		OutputDir:         out,
		DeterministicOnly: true,
		RunID:             "test-notrun",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination != flow.TermNotDecisionReady {
		t.Fatalf("termination %q", rec.Result.Termination)
	}
	if !strings.Contains(rec.Result.Reason, domain.ReleaseReasonArtifactPathMissing) {
		t.Fatalf("reason %q lacks the channel reason", rec.Result.Reason)
	}
	if len(rec.Turns) != 0 {
		t.Fatalf("planner turns ran on NOT_RUN: %d", len(rec.Turns))
	}
	if report.Run.Outcome != "NOT_RUN" ||
		report.Run.OutcomeReason != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("run outcome %+v", report.Run)
	}
	if report.Input.Snapshot.ReleaseEvidence == nil ||
		report.Input.Snapshot.ReleaseEvidence.Status != "NOT_RUN" {
		t.Fatalf("release evidence %+v", report.Input.Snapshot.ReleaseEvidence)
	}
	if report.DecisionArtifact == nil ||
		report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("non-ready run proposed %v", report.DecisionArtifact)
	}
	for _, f := range []string{flowResultFile, flowEventsFile, flowFactsFile, decisionArtifactFile} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// TestRunDecisionReadyLaneDischarge proves the lane-discharge path end
// to end over the real deterministic lane: the lane-internal required
// check (affected-resolve) — whose record carries no evidence_refs —
// is discharged from its complete, digest-pinned lane audit record, the
// fixture's USED/PARTIAL package-usage record discharges through the
// positive-answer path (its question is answered; discharge never
// widens to unanswered records), the planner's surface advertises only
// dispatchable checks, and the run closes DECISION_READY.
func TestRunDecisionReadyLaneDischarge(t *testing.T) {
	out := t.TempDir()
	drv := &fakeFlowDriver{
		plans: []flow.Plan{{
			StepID: "s1",
			Actions: []flow.PlanAction{
				{ID: "a1", AdapterID: "get_product_snapshot",
					Arguments: json.RawMessage(`{}`), Purpose: "pin snapshot identity"}},
		}},
		reas: []flow.Reassessment{{Status: flow.ReassessReady}},
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent:       drv,
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-lane-discharge",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The lane's affected-resolve record must be the complete,
	// snapshot-bound, digest-pinned record the discharge gate requires —
	// and it carries no evidence refs (the original defect).
	var resolve *evidencetools.Observation
	for _, r := range rec.Lane.Records {
		if r.Tool == "affected-resolve" {
			resolve = r.Observation
		}
	}
	if resolve == nil || resolve.ToolStatus != evidencetools.StatusOK ||
		resolve.Completeness != evidencetools.CompletenessComplete {
		t.Fatalf("fixture lane record unexpected: %+v", resolve)
	}
	if len(resolve.EvidenceRefs) != 0 {
		t.Fatalf("fixture premise drifted: affected-resolve carries refs %v", resolve.EvidenceRefs)
	}
	// Discharged from the lane records — affected-resolve through the
	// closed-negative path, package-usage through the positive answer —
	// the required surface intact, and the undispatchable id never
	// advertised as an admissible check.
	if len(drv.seenIn) == 0 {
		t.Fatal("planner never ran")
	}
	in := drv.seenIn[0]
	if !containsStr(in.DischargedChecks, "affected-resolve") {
		t.Fatalf("affected-resolve not discharged: %v", in.DischargedChecks)
	}
	if !containsStr(in.DischargedChecks, "package-usage") {
		t.Fatalf("the positively answered package-usage stayed undischarged: %v", in.DischargedChecks)
	}
	if containsStr(in.AvailableChecks, "affected-resolve") {
		t.Fatalf("undispatchable check advertised: %v", in.AvailableChecks)
	}
	if !containsStr(in.RequiredChecks, "affected-resolve") ||
		!containsStr(in.RequiredChecks, "package-usage") {
		t.Fatalf("required surface lost ids: %v", in.RequiredChecks)
	}
	if !containsStr(rec.Result.CompletedChecks, "affected-resolve") ||
		!containsStr(rec.Result.CompletedChecks, "package-usage") {
		t.Fatalf("completed checks = %v", rec.Result.CompletedChecks)
	}
	// The discharge record names which path discharged each check: the
	// pinned lane observations carry the stamped path.
	paths := map[string]string{}
	for _, ev := range rec.Result.Evidence {
		paths[ev.ID] = ev.DischargePath
	}
	var usagePath string
	for _, o := range rec.Lane.Observations {
		if o == nil || o.Tool != evidencetools.PackageUsageTool || paths[o.ID] == "" {
			continue
		}
		usagePath = paths[o.ID]
	}
	if usagePath != flow.DischargePositiveAnswer {
		t.Fatalf("package-usage discharge path = %q, want %q (evidence=%v)",
			usagePath, flow.DischargePositiveAnswer, paths)
	}
	// Admission no longer kills the run: the plan executed one
	// dispatchable action and reached the reassessor.
	if rec.Result.Termination == flow.TermUnsupported {
		t.Fatalf("run died at admission: %q", rec.Result.Reason)
	}
	if len(rec.Result.Actions) != 1 || len(rec.Turns) != 2 {
		t.Fatalf("actions=%d turns=%d — plan did not execute", len(rec.Result.Actions), len(rec.Turns))
	}
	// A positive answer is a complete answer to the required check: the
	// recorded interpretation bound rides in the observation's
	// limitations, and the run closes DECISION_READY — the measured
	// defect (a USED record looping the same check) is gone.
	if rec.Result.Termination != flow.TermDecisionReady {
		t.Fatalf("termination = %q reason %q", rec.Result.Termination, rec.Result.Reason)
	}
	if report.DecisionArtifact == nil {
		t.Fatal("decision artifact missing")
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// TestRunDecisionReadyUnreachabilityDisproven reproduces the live
// defect end to end: the planner runs the advisory's declared subject
// through symbol-unreachability, the real session answers disproven
// (vuln.Parse is called by the fixture product) at PARTIAL — a
// definitive answer to the asked question, stamped positive_answer.
// The ledger stays complete, the run closes DECISION_READY, and the
// artifact is not capped: the answered reachability dimension is
// visible as the contradicted unreachability rule.
func TestRunDecisionReadyUnreachabilityDisproven(t *testing.T) {
	out := t.TempDir()
	drv := &fakeFlowDriver{
		plans: []flow.Plan{{
			StepID: "s1",
			Actions: []flow.PlanAction{
				{ID: "a1", AdapterID: "symbol-unreachability",
					Arguments: json.RawMessage(`{"module":"example.com/snapdep","subjects":[{"package":"example.com/snapdep/vuln","symbol":"Parse"}]}`),
					Purpose:   "prove the declared symbol unreachable from the product"},
			}},
		},
		reas: []flow.Reassessment{{Status: flow.ReassessReady}},
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent:       drv,
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-unreach-disproven",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// The produced observation is the session's disproven record —
	// PARTIAL by the tool's contract — stamped as the positive answer.
	var produced *flow.Observation
	for i := range rec.Result.Observations {
		o := &rec.Result.Observations[i]
		if strings.Contains(o.ID, "OBS") && o.Status == flow.ObsStatusOK &&
			o.Completeness == flow.ObsPartial {
			produced = o
		}
	}
	if produced == nil {
		t.Fatalf("no produced OK/PARTIAL observation: %+v", rec.Result.Observations)
	}
	if produced.DischargePath != flow.DischargePositiveAnswer {
		t.Fatalf("disproven record discharge path = %q, want %q",
			produced.DischargePath, flow.DischargePositiveAnswer)
	}
	// The definitive answer must not degrade the ledger: no coverage
	// limitation names it, and the run closes DECISION_READY.
	for _, l := range rec.Result.Limitations {
		if strings.Contains(l, "coverage is not closed") {
			t.Fatalf("answered record degraded the ledger: %q", l)
		}
	}
	if rec.Result.Termination != flow.TermDecisionReady || !rec.Result.Complete {
		t.Fatalf("termination = %q complete=%v reason %q",
			rec.Result.Termination, rec.Result.Complete, rec.Result.Reason)
	}
	// The artifact is uncapped — a capped run demotes every branch to
	// NOT_DECISION_READY, while this run's conditional branches still
	// stand (the finding stays open for remediation under the recorded
	// posture) — and the answered reachability dimension is recorded:
	// the unreachability close rule is contradicted by the promoted
	// reached fact.
	a := report.DecisionArtifact
	if a == nil {
		t.Fatal("decision artifact missing")
	}
	var standing bool
	for _, br := range a.Branches {
		if br.Status == BranchComplete {
			standing = true
		}
	}
	if !standing {
		t.Fatalf("artifact looks capped: no COMPLETE branch stands (branches=%d)", len(a.Branches))
	}
	var contradicted bool
	for _, c := range a.Contradictions {
		if c.Subject == "rule.declared-symbols-unreached" &&
			c.Kind == ContradictionEvidenceConflict {
			contradicted = true
		}
	}
	if !contradicted {
		t.Fatalf("the reached answer is invisible on the artifact: contradictions=%+v",
			a.Contradictions)
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// TestRunDecisionReadyInformationalPartial reproduces the second live
// overreach: the model explored with module-usage and
// module-internal-reach after answering the required checks — both
// informational tools whose PARTIAL completeness is their own
// contract — and the ledger degraded on them, capping an otherwise
// decision-ready run. A bounded OK record from a non-required check
// must record its bound and never mark coverage incomplete.
func TestRunDecisionReadyInformationalPartial(t *testing.T) {
	out := t.TempDir()
	drv := &fakeFlowDriver{
		plans: []flow.Plan{{
			StepID: "s1",
			Actions: []flow.PlanAction{
				{ID: "a1", AdapterID: "module-usage",
					Arguments: json.RawMessage(`{"module":"example.com/snapdep"}`),
					Purpose:   "enumerate product call sites into the module"},
				{ID: "a2", AdapterID: "module-internal-reach",
					Arguments: json.RawMessage(`{"module":"example.com/snapdep","entries":["example.com/snapdep/vuln.Parse"],"subjects":[{"package":"example.com/snapdep/vuln","symbol":"Parse"}]}`),
					Purpose:   "check module-internal chains to the declared symbol"},
			}},
		},
		reas: []flow.Reassessment{{Status: flow.ReassessReady}},
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: r6LaneOptions(t, out),
		Agent:       drv,
		ConfigFS:    r6ConfigFS(t),
		OutputDir:   out,
		RunID:       "test-informational-partial",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The informational records are produced, bounded and kept — their
	// limitations still name their bounds — but the ledger stays
	// complete and the run closes DECISION_READY.
	if len(rec.Result.Observations) != 2 {
		t.Fatalf("observations = %d, want both informational records", len(rec.Result.Observations))
	}
	var partials int
	for _, l := range rec.Result.Limitations {
		if strings.Contains(l, "completeness is PARTIAL") {
			partials++
		}
	}
	if partials != 2 {
		t.Fatalf("informational bounds unrecorded: %v", rec.Result.Limitations)
	}
	if rec.Result.Termination != flow.TermDecisionReady || !rec.Result.Complete {
		t.Fatalf("termination = %q complete=%v reason %q — informational PARTIAL capped the run",
			rec.Result.Termination, rec.Result.Complete, rec.Result.Reason)
	}
	a := report.DecisionArtifact
	if a == nil {
		t.Fatal("decision artifact missing")
	}
	var standing bool
	for _, br := range a.Branches {
		if br.Status == BranchComplete {
			standing = true
		}
	}
	if !standing {
		t.Fatalf("artifact capped by exploration: %+v", a.Branches)
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// A complete, audit-bound symbol-unreachability proof must survive the
// decision-ready projection: the projection passes the drained session
// audit and its audit-derived index into VerifyDecision, so the
// authority route can resolve its evidence refs. Without the audit the
// same proposal must be demoted — a close is never projected from a
// caller-constructed trace.
func TestDecisionReadySymbolClosureProjectsThroughAudit(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	// The production projection mints the authority condition from the
	// catalog entry id, so the recorded request must carry the same one.
	for i := range in.Trace.Requests {
		in.Trace.Requests[i].ConditionID = "declared-symbol-unreachable"
	}
	a := validArtifact(t)
	a.ProposedDisposition = DispositionCloseNoExploitPath
	a.JustificationGraph = []Justification{{
		ID:            "J-1",
		RuleID:        "rule.declared-symbols-unreached",
		Disposition:   DispositionCloseNoExploitPath,
		CoverageBasis: FactCoverageComplete,
		Statement:     "every advisory-declared symbol is proven unreachable from the recorded product scope",
	}}
	a.AdvisoryBinding.SubjectRefs = []string{"symbol:" + testModule + "|" + testPackage + ".Sink"}

	got := decisionForArtifactWithAuthorityAudit(a, in.Trace, in.Lane, in.Audit)
	if got.Verdict != domain.VerdictNoExploitPathFound || got.Coverage != "COMPLETE" {
		t.Fatalf("audit-bound symbol closure must project: %+v", got)
	}
	without := decisionForArtifactWithAuthority(a, in.Trace, in.Lane)
	if without.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("a close without the drained session audit must not project: %+v", without)
	}
}

// ---- lane-terminal dominance over the recorded run ----

// The measured census defect: the deterministic applicability chain
// resolves an axis FALSE (the lane's own report records
// version_affected=FALSE), the agent flow terminates NOT_DECISION_READY
// with a policy-required check undischarged and the artifact is capped
// to HOLD_UNKNOWN — yet the lane's NOT_AFFECTED must still stand. The
// supporting layer's failure is recorded as a named limitation on the
// verdict, never as a replacement for it.
func TestDecisionForRecordedRunApplicabilityDominatesFlowFailure(t *testing.T) {
	lane := decisionLane(domain.ClaimFalse)
	lane.Affected.EvidenceIDs = []domain.EvidenceID{"EV-AFFECTED-MODULES"}
	lane.AffectedEvidence = []domain.Evidence{
		{ID: "EV-AFFECTED-MODULES", Kind: "MODULE_GRAPH", Quality: "DETERMINISTIC", Source: "vendor/modules.txt"},
	}
	lane.Observations = []*evidencetools.Observation{resolveObservation("OBS-0008")}
	res := &flow.Result{
		Termination:     flow.TermNotDecisionReady,
		Reason:          "policy-required checks remain undischarged: package-usage",
		Policy:          flow.Policy{RequiredChecks: []string{"affected-resolve", "package-usage", "usage-scope"}},
		CompletedChecks: []string{"affected-resolve", "usage-scope"},
	}
	artifact := &DecisionArtifact{ProposedDisposition: DispositionHoldUnknown}
	d, _ := decisionForRecordedRun(res, artifact, nil, lane, nil)
	if d.Verdict != domain.VerdictNotAffected || d.Coverage != "COMPLETE" {
		t.Fatalf("decision=%+v", d)
	}
	if d.Scope != "deterministic applicability chain" {
		t.Fatalf("scope %q must name the lane's own chain", d.Scope)
	}
	if len(d.EvidenceRefs) != 1 || d.EvidenceRefs[0] != "obs:OBS-0008" {
		t.Fatalf("refs must keep the lane's own applicability citation, got %+v", d.EvidenceRefs)
	}
	var named bool
	for _, l := range d.Limitations {
		if strings.Contains(l, "NOT_DECISION_READY") && strings.Contains(l, "package-usage") {
			named = true
		}
	}
	if !named {
		t.Fatalf("flow failure must be a named limitation on the standing verdict: %v", d.Limitations)
	}
}

// The lane-owned symbol proof is the second terminal lane decision: a
// complete audit-bound proof's NO_EXPLOIT_PATH_FOUND stands even when
// the flow failed and the artifact proposes HOLD_UNKNOWN.
func TestDecisionForRecordedRunSymbolProofDominatesFlowFailure(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	in.Lane.SymbolProof = &LaneSymbolProof{
		Trace:    in.Trace,
		Audit:    in.Audit,
		Decision: decide(t, in),
	}
	res := &flow.Result{
		Termination: flow.TermReassessorFailure,
		Reason:      "reassessor returned an error: context deadline exceeded",
		Policy:      flow.Policy{RequiredChecks: []string{"affected-resolve"}},
	}
	artifact := &DecisionArtifact{ProposedDisposition: DispositionHoldUnknown}
	d, _ := decisionForRecordedRun(res, artifact, nil, in.Lane, nil)
	if d.Verdict != domain.VerdictNoExploitPathFound || d.Falsifier != domain.FalsifierDeclaredSymbolUnreached {
		t.Fatalf("lane proof must stand: %+v", d)
	}
	var named bool
	for _, l := range d.Limitations {
		if strings.Contains(l, "REASSESSOR_FAILURE") {
			named = true
		}
	}
	if !named {
		t.Fatalf("flow failure must be a named limitation: %v", d.Limitations)
	}
}

// With no lane terminal decision the artifact's disposition governs
// exactly as before — HOLD_UNKNOWN material stays INCONCLUSIVE.
func TestDecisionForRecordedRunNoLaneTerminalUnchanged(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	res := &flow.Result{
		Termination: flow.TermNotDecisionReady,
		Reason:      "policy-required checks remain undischarged: package-usage",
		Policy:      flow.Policy{RequiredChecks: []string{"package-usage"}},
	}
	artifact := &DecisionArtifact{ProposedDisposition: DispositionHoldUnknown}
	d, _ := decisionForRecordedRun(res, artifact, nil, lane, nil)
	if d.Verdict != domain.VerdictInconclusive ||
		!strings.Contains(d.Reason, "decision-artifact proposed HOLD_UNKNOWN") {
		t.Fatalf("no terminal lane decision must keep the artifact path: %+v", d)
	}
	for _, l := range d.Limitations {
		if strings.Contains(l, "agent flow terminated") {
			t.Fatalf("inconclusive projection must not gain lane-dominance annotations: %v", d.Limitations)
		}
	}
}

// Undischarged-check derivation mirrors the engine's pairing rule: a
// produced OK+audit-bound+digest-pinned observation discharges its
// action's adapter either as a COMPLETE closed negative or as a stamped
// positive answer; caller-completed and inapplicable ids never miss.
func TestUndischargedRequiredChecks(t *testing.T) {
	res := &flow.Result{
		Policy: flow.Policy{RequiredChecks: []string{"affected-resolve", "package-usage", "usage-scope", "module-usage"}},
		Actions: []flow.PlanAction{
			{ID: "a1", AdapterID: "module-usage"},
		},
		Observations: []flow.Observation{
			{ID: "OBS-1", Status: flow.ObsStatusOK, AuditBound: true, DataDigest: "d",
				Completeness: "PARTIAL", DischargePath: flow.DischargePositiveAnswer},
		},
		CompletedChecks:    []string{"affected-resolve"},
		InapplicableChecks: []string{"package-usage"},
	}
	missing := undischargedRequiredChecks(res)
	if len(missing) != 1 || missing[0] != "usage-scope" {
		t.Fatalf("missing=%v, want usage-scope only", missing)
	}
}

// End to end: the deterministic lane proves the advisory version range
// does not cover the recorded product (version_affected=FALSE), the
// deterministic-only run terminates PLANNER_FAILURE and the artifact is
// capped HOLD_UNKNOWN — the reported decision must still be the lane's
// NOT_AFFECTED with the failure named, and the report must validate.
func TestRunDecisionReadyNotAffectedDominatesPlannerFailure(t *testing.T) {
	out := t.TempDir()
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0002",
	  "aliases": ["CVE-TEST-2"],
	  "summary": "advisory whose fixed version is below the recorded product",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.5.0"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	advPath := filepath.Join(dir, "GO-TEST-0002.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: LaneOptions{
			CVE: "GO-TEST-0002", SnapshotPath: root, AdvisoryFile: advPath,
			ExternalCommitSHA: "fixture-sha-1", Timeout: 90 * time.Second,
		},
		ConfigFS:          r6ConfigFS(t),
		OutputDir:         out,
		DeterministicOnly: true,
		RunID:             "test-notaffected-dominates",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Result.Termination != flow.TermPlannerFailure {
		t.Fatalf("termination %q, want PLANNER_FAILURE", rec.Result.Termination)
	}
	if report.DecisionArtifact == nil ||
		report.DecisionArtifact.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("failure run must cap the artifact: %+v", report.DecisionArtifact)
	}
	if report.Decision == nil || report.Decision.Verdict != domain.VerdictNotAffected ||
		report.Decision.Coverage != "COMPLETE" {
		t.Fatalf("the lane's NOT_AFFECTED must dominate the failed run: %+v", report.Decision)
	}
	var named bool
	for _, l := range report.Decision.Limitations {
		if strings.Contains(l, "PLANNER_FAILURE") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the flow failure must stay visible as a limitation: %v", report.Decision.Limitations)
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// End to end for the lane-owned proof: the advisory-declared symbol is
// provably unreachable (lane SymbolProof terminal), the run terminates
// PLANNER_FAILURE and the artifact holds — the decision must keep the
// lane's NO_EXPLOIT_PATH_FOUND with the failure named, and the /3
// report must validate.
func TestRunDecisionReadySymbolProofDominatesPlannerFailure(t *testing.T) {
	out := t.TempDir()
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0003",
	  "aliases": ["CVE-TEST-3"],
	  "summary": "advisory declaring the dead dep symbol",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["helper"]}]}
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	advPath := filepath.Join(dir, "GO-TEST-0003.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	report, rec, err := RunDecisionReady(context.Background(), DecisionReadyOptions{
		LaneOptions: LaneOptions{
			CVE: "GO-TEST-0003", SnapshotPath: root, AdvisoryFile: advPath,
			ExternalCommitSHA: "fixture-sha-1", Timeout: 90 * time.Second,
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
			DefectSemantics: &domain.DefectSemanticsContract{
				Mode:     domain.DefectSemanticsDefectiveCheck,
				RecordID: "GO-TEST-0003",
				Check:    domain.SymbolRef{Package: "example.com/snapdep/vuln", Symbol: "helper"},
			},
		},
		ConfigFS:          r6ConfigFS(t),
		OutputDir:         out,
		DeterministicOnly: true,
		RunID:             "test-symbolproof-dominates",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Lane.SymbolProof == nil {
		t.Fatal("lane did not run its symbol-unreachability attempt")
	}
	if rec.Result.Termination != flow.TermPlannerFailure {
		t.Fatalf("termination %q, want PLANNER_FAILURE", rec.Result.Termination)
	}
	if report.Decision == nil || report.Decision.Verdict != domain.VerdictNoExploitPathFound ||
		report.Decision.Falsifier != domain.FalsifierDeclaredSymbolUnreached {
		t.Fatalf("the lane proof must dominate the failed run: %+v", report.Decision)
	}
	var named bool
	for _, l := range report.Decision.Limitations {
		if strings.Contains(l, "PLANNER_FAILURE") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the flow failure must stay visible as a limitation: %v", report.Decision.Limitations)
	}
	if err := Validate(report, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// The lane's cached symbol proof decision is a negative: it may only be
// projected when the resolved advisory scope covers the requested
// identity. A partial scope refuses the cached CLOSE_NO_EXPLOIT_PATH
// even though the cached decision is itself COMPLETE, while the
// exact-entry counterpart keeps projecting it.
func TestArtifactProjectionPartialScopeRejectsCachedClose(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	in.Lane.SymbolProof = &LaneSymbolProof{Decision: EvidenceDecision{
		Verdict:              domain.VerdictNoExploitPathFound,
		Falsifier:            domain.FalsifierDeclaredSymbolUnreached,
		Coverage:             "COMPLETE",
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		Reason:               "cached lane symbol proof",
	}}
	a := validArtifact(t)
	a.ProposedDisposition = DispositionCloseNoExploitPath
	a.JustificationGraph = []Justification{{
		ID: "J-1", RuleID: "rule.declared-symbols-unreached",
		Disposition:   DispositionCloseNoExploitPath,
		CoverageBasis: FactCoverageComplete,
		Statement:     "every advisory-declared symbol is proven unreachable from the recorded product scope",
	}}
	a.AdvisoryBinding.SubjectRefs = []string{"symbol:" + testModule + "|" + testPackage + ".Sink"}

	if got := decisionForArtifactWithAuthorityAudit(a, in.Trace, in.Lane, in.Audit); got.Verdict != domain.VerdictNoExploitPathFound || got.Coverage != "COMPLETE" {
		t.Fatalf("exact-entry cached close must project: %+v", got)
	}
	in.Lane.Affected.Scope = partialCVEScope()
	got := decisionForArtifactWithAuthorityAudit(a, in.Trace, in.Lane, in.Audit)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "scoped applicability gap") {
		t.Fatalf("partial scope must refuse the cached close: %+v", got)
	}
	// The recorded-run projection applies the same guard to the cached
	// lane proof decisions it would otherwise return verbatim.
	d, _ := decisionForRecordedRun(&flow.Result{Ready: true}, a, in.Trace, in.Lane, in.Audit)
	if d.Verdict != domain.VerdictInconclusive || !strings.Contains(d.Reason, "scoped applicability gap") {
		t.Fatalf("recorded-run projection reused the cached close: %+v", d)
	}

	// The structural refusals behave identically: a Go projection of a
	// broader record, an unbacked full-record claim and a self-contradicting
	// census each refuse the cached COMPLETE close.
	for name, scope := range extentRefusalScopes("GO-TEST-0001") {
		t.Run(name, func(t *testing.T) {
			in.Lane.Affected.Scope = scope
			if got := decisionForArtifactWithAuthorityAudit(a, in.Trace, in.Lane, in.Audit); got.Verdict != domain.VerdictInconclusive ||
				!strings.Contains(got.Reason, "scoped applicability gap") {
				t.Fatalf("extent-refused scope projected the cached close: %+v", got)
			}
			d, _ := decisionForRecordedRun(&flow.Result{Ready: true}, a, in.Trace, in.Lane, in.Audit)
			if d.Verdict != domain.VerdictInconclusive || !strings.Contains(d.Reason, "scoped applicability gap") {
				t.Fatalf("recorded-run projection reused the cached close: %+v", d)
			}
		})
	}
}

// A cached lane proof decision is a COMPLETE negative the recorded-run
// projection would otherwise return verbatim. Both cached authorities — the
// symbol proof and the post-reach config proof — are refused under every
// non-closing scope, while the complete-record control keeps them.
func TestDecisionForRecordedRunExtentGate(t *testing.T) {
	cached := EvidenceDecision{
		Verdict:              domain.VerdictNoExploitPathFound,
		Falsifier:            domain.FalsifierDeclaredSymbolUnreached,
		Coverage:             "COMPLETE",
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		Reason:               "cached lane proof",
		EvidenceRefs:         []string{"obs:OBS-0001"},
	}
	build := func(scope *domain.AdvisoryScope) *LaneResult {
		lane := decisionLane(domain.ClaimTrue)
		lane.Affected.Scope = scope
		lane.SymbolProof = &LaneSymbolProof{Decision: cached}
		lane.ConfigProof = &LaneConfigProof{Decision: cached}
		return lane
	}
	hold := &DecisionArtifact{ProposedDisposition: DispositionHoldUnknown}
	if got, _ := decisionForRecordedRun(&flow.Result{Ready: true}, hold, nil, build(exactAdvisoryScope("GO-TEST-0001")), nil); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("complete-record control must keep the cached proof: %+v", got)
	}
	for name, scope := range extentRefusalScopes("GO-TEST-0001") {
		t.Run(name, func(t *testing.T) {
			got, _ := decisionForRecordedRun(&flow.Result{Ready: true}, hold, nil, build(scope), nil)
			if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "scoped applicability gap") {
				t.Fatalf("recorded-run projection reused the cached negative: %+v", got)
			}
		})
	}
}
