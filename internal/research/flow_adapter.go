package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/flow"
	"github.com/davniy/izyan/internal/goanalysis"
)

// The R6 decision-ready adapter: the deterministic lane runs first and
// stays authoritative; the generic flow engine drives planner/
// reassessor turns over the same confined evidence session; the
// decision-artifact builder re-derives every branch and the proposed
// disposition from the recorded ledgers alone. The agent plans and
// reassesses — it never writes a fact, a branch status or a
// disposition; the wire types carry no field for any of those.
//
// Persisted sibling artifacts (all under OutputDir, alongside the
// lane's own files):
//   flow-result.json               — the recorded flow.Result verbatim
//   flow-events.jsonl              — the recorded event stream, one event per line
//   flow-facts.json                — the promoted fact envelope + bookkeeping (flow-facts/1)
//   decision-artifact.json         — the validated decision-artifact/1 document
//   verification-observations.jsonl— the session audit records of flow-dispatched checks
//   verification-artifacts/obs-*.json — the pinned observation payloads the ledger binds to
//
// The legacy one-turn route writes nothing under these names and is
// untouched; this file is only reachable through the opt-in
// --decision-ready flag.

const (
	flowResultFile          = "flow-result.json"
	flowEventsFile          = "flow-events.jsonl"
	flowFactsFile           = "flow-facts.json"
	decisionArtifactFile    = "decision-artifact.json"
	flowObservationLedger   = "verification-observations.jsonl"
	flowObservationDir      = "verification-artifacts"
	flowObservationSelector = "verification-observation"
	flowFactsSchema         = "flow-facts/1"
)

// DecisionReadyOptions is the opt-in R6 run configuration.
type DecisionReadyOptions struct {
	// LaneOptions are the deterministic lane inputs; OutputDir is set
	// from OutputDir by the adapter — the lane and the flow share the
	// single report directory.
	LaneOptions LaneOptions
	// Agent is the planner/reassessor driver; nil (or a factory that
	// fails) records PLANNER_FAILURE — missing model infrastructure is
	// a recorded HOLD, never an error and never a silent success.
	Agent AgentDriver
	// AgentFactory, consulted only when Agent is nil, binds a driver to
	// the lane result (e.g. the frozen advisory the prompt renders).
	AgentFactory func(lane *LaneResult) (AgentDriver, error)
	// FlowPolicy is the caller's requested flow policy. It must be
	// monotonic over the configured safety policy
	// (rubrics/decision.yaml); a relaxation fails run startup — it
	// never silently replaces the configured one. Empty means "the
	// configured policy with the rubric's budgets".
	FlowPolicy flow.Policy
	// ConfigFS carries the pinned research configuration rooted at the
	// repository root (catalogs, decision rubric, flow rubric and the
	// R6 prompt files). Required — missing or invalid files fail closed.
	ConfigFS fs.FS
	// OutputDir is the only writable location (required, absolute or
	// made absolute by the caller).
	OutputDir string
	// DeterministicOnly runs lane + bounded flow with a failing
	// planner stub: the report is recorded as HOLD_UNKNOWN material.
	DeterministicOnly bool
	// ReplayDir replays a persisted decision-ready run directory
	// instead of driving the planner: the recorded event stream is
	// re-validated through the engine (no model call) and the artifact
	// is rebuilt from the persisted audit ledger. Conflicts with
	// DeterministicOnly.
	ReplayDir string
	// RunID, StartedAt, LaneStartedAt/LaneFinishedAt are run-bookkeeping
	// fields populated by the caller; zero values default internally.
	RunID          string
	StartedAt      time.Time
	LaneStartedAt  time.Time
	LaneFinishedAt time.Time
}

// AgentDriver is the retained planner/reassessor interface for recorded flow
// contracts and injected offline tests. No production live harness implements
// it: triage is the sole live investigator. Each recorded invocation carries
// AgentTurnMetadata so historical manifests retain their original prompt pins.
type AgentDriver interface {
	Plan(context.Context, flow.PlanInput) (flow.Plan, AgentTurnMetadata, error)
	Reassess(context.Context, flow.ReassessInput) (flow.Reassessment, AgentTurnMetadata, error)
}

// AgentTurnMetadata is the audit pin for one flow driver turn: which
// prompt revision rendered it, what the retained artifacts hash to and
// how the turn classified. It uses the existing AgentManifest/
// AttemptArtifact shapes so the run-manifest stays one vocabulary.
type AgentTurnMetadata struct {
	Role           string           `json:"role"`       // "plan" | "reassess" | "counterexample"
	Ordinal        int              `json:"ordinal"`    // 1-based invocation order within the run
	AttemptID      string           `json:"attempt_id"` // retained-artifact dir under agent/
	StepID         string           `json:"step_id,omitempty"`
	Status         string           `json:"status"` // AgentOK / AgentInvalidFormat / AgentFailed / AgentTimeout / AgentProviderRefused
	Err            string           `json:"error,omitempty"`
	PromptPath     string           `json:"prompt_path,omitempty"`
	PromptSHA256   string           `json:"prompt_sha256,omitempty"`
	RenderedSHA256 string           `json:"rendered_prompt_sha256,omitempty"`
	StartedAt      time.Time        `json:"started_at,omitempty"`
	FinishedAt     time.Time        `json:"finished_at,omitempty"`
	ResultArtifact *AttemptArtifact `json:"result_artifact,omitempty"`
	AnswerArtifact *AttemptArtifact `json:"answer_artifact,omitempty"`
	Manifest       AgentManifest    `json:"manifest"` // harness-side pins (path/commit/image/commands)
}

// DecisionRunRecord is the adapter's persisted-run view for callers:
// the report plus everything writeDecisionRunManifest needs to pin
// (flow termination, per-turn prompt/harness pins, replay source). It
// is never written to disk itself — flow-result.json and
// run-manifest.json carry the persistent record.
type DecisionRunRecord struct {
	Result        *flow.Result
	Lane          *LaneResult
	Artifact      *DecisionArtifact
	Turns         []AgentTurnMetadata
	Decision      EvidenceDecision
	Trace         *VerificationTrace
	FlowFacts     []Fact
	ReplayedFrom  string
	Objective     string
	FactsArtifact ArtifactRef
}

// FlowRubric is the flow-loop configuration surface: deterministic
// budgets plus the pinned R6 prompt revisions. A missing file, wrong
// schema, non-positive or oversized budget, or an unpinning prompt path
// is an error — the run never falls back to a default prompt.
type FlowRubric struct {
	MaxSteps            int
	MaxActions          int
	PlanPromptPath      string
	ReassessPromptPath  string
	CounterexPromptPath string
	PromptDigest        string // digest over path+sha pins of the three prompts
	promptSHAs          map[string]string
}

// flowRubricPath is the pinned flow configuration file.
const flowRubricPath = "rubrics/research.yaml"
const flowRubricSchema = "research-flow-rubric/1"

type flowRubricFile struct {
	Schema     string `json:"schema"`
	MaxSteps   int    `json:"max_steps"`
	MaxActions int    `json:"max_actions"`
	Prompts    struct {
		Plan           string `json:"plan"`
		Reassess       string `json:"reassess"`
		Counterexample string `json:"counterexample"`
	} `json:"prompts"`
}

// LoadFlowRubric reads and pins the flow rubric. Budgets are bounded
// (1..64) and every prompt path must exist inside fsys and hash
// distinctly — a rubric that cannot pin its prompts fails closed.
func LoadFlowRubric(fsys fs.FS) (FlowRubric, error) {
	var f flowRubricFile
	if err := readCatalogJSON(fsys, flowRubricPath, &f); err != nil {
		return FlowRubric{}, err
	}
	if f.Schema != flowRubricSchema {
		return FlowRubric{}, fmt.Errorf("research flow rubric %s: schema %q != %q", flowRubricPath, f.Schema, flowRubricSchema)
	}
	bounded := func(v int) bool { return v >= 1 && v <= 64 }
	if !bounded(f.MaxSteps) || !bounded(f.MaxActions) {
		return FlowRubric{}, fmt.Errorf("research flow rubric %s: max_steps/max_actions must be within [1,64] (got %d/%d)",
			flowRubricPath, f.MaxSteps, f.MaxActions)
	}
	paths := []string{f.Prompts.Plan, f.Prompts.Reassess, f.Prompts.Counterexample}
	seen := map[string]bool{}
	r := FlowRubric{
		MaxSteps: f.MaxSteps, MaxActions: f.MaxActions,
		PlanPromptPath: f.Prompts.Plan, ReassessPromptPath: f.Prompts.Reassess,
		CounterexPromptPath: f.Prompts.Counterexample,
		promptSHAs:          map[string]string{},
	}
	var pin strings.Builder
	for _, p := range paths {
		if p == "" {
			return FlowRubric{}, fmt.Errorf("research flow rubric %s: every prompts member is required", flowRubricPath)
		}
		if seen[p] {
			return FlowRubric{}, fmt.Errorf("research flow rubric %s: prompt path %q is reused", flowRubricPath, p)
		}
		seen[p] = true
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return FlowRubric{}, fmt.Errorf("research flow rubric %s: prompt %s unreadable: %w", flowRubricPath, p, err)
		}
		sum := sha256.Sum256(raw)
		r.promptSHAs[p] = hex.EncodeToString(sum[:])
		fmt.Fprintf(&pin, "%s:%s\n", p, r.promptSHAs[p])
	}
	sum := sha256.Sum256([]byte(pin.String()))
	r.PromptDigest = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// PromptSHA is the pinned sha256 of one rubric prompt file; empty when
// the path is not one the rubric declared.
func (r FlowRubric) PromptSHA(path string) string { return r.promptSHAs[path] }

// ---- catalog: the flow view over checks.yaml + the session catalog ----

// mappedFlowCatalog is the single admission and dispatch surface for
// the flow run: ids come from the pinned research checks catalog
// (configs/research/checks.yaml), execution resolution comes from the
// session's capability-gated check catalog. A catalog id that names no
// dispatchable session check stays registered — the lane may already
// have discharged a policy-required check (dischargedLaneChecks) and a
// required id must stay resolvable as a requirement — but Lookup fails
// on it, so it is never dispatchable and never advertised in
// available_checks. An id absent from checks.yaml is never registered
// and never dispatches.
type mappedFlowCatalog struct {
	order []string
	specs map[string]evidencetools.CheckSpec // catalog id -> dispatch spec (session spec, tool rebound)
	inner evidencetools.CheckCatalog         // session capability-gated catalog
	// snapshotHash binds positive-answer stamping to the lane's
	// recorded snapshot: a scoped observation the catalog calls a
	// positive answer only counts when its scope was recorded against
	// this snapshot ("" refuses nothing beyond the required binding —
	// an unbound hash simply cannot match).
	snapshotHash string
}

// newFlowCatalog projects the session catalog through checks.yaml.
// ids in catalog order; a catalog entry whose tool resolves to a
// session check id carries that check's schema and call bound.
// snapshotHash is the lane's recorded content hash the positive-answer
// stamp binds to.
func newFlowCatalog(cats Catalogs, inner evidencetools.CheckCatalog, snapshotHash string) *mappedFlowCatalog {
	m := &mappedFlowCatalog{specs: map[string]evidencetools.CheckSpec{}, inner: inner, snapshotHash: snapshotHash}
	byID := map[string]evidencetools.CheckSpec{}
	byTool := map[string]evidencetools.CheckSpec{}
	if inner != nil {
		for _, s := range inner.List() {
			byID[s.ID] = s
			byTool[s.Tool] = s
		}
	}
	for _, ck := range cats.Checks {
		m.order = append(m.order, ck.ID)
		spec, ok := byID[ck.ID]
		if !ok && ck.Tool != "" {
			spec, ok = byTool[ck.Tool]
		}
		if !ok {
			continue // lane-internal check: registered, never dispatchable
		}
		spec.ID = ck.ID
		m.specs[ck.ID] = spec
	}
	return m
}

func (m *mappedFlowCatalog) Lookup(id string) (evidencetools.CheckSpec, bool) {
	spec, ok := m.specs[id]
	return spec, ok
}

func (m *mappedFlowCatalog) Validate(id string, args json.RawMessage) error {
	spec, ok := m.specs[id]
	if !ok {
		if m.registered(id) {
			return fmt.Errorf("check %q is a lane-internal check without a dispatchable session tool", id)
		}
		return fmt.Errorf("check %q is not registered", id)
	}
	return m.inner.Validate(spec.Tool, args)
}

func (m *mappedFlowCatalog) List() []evidencetools.CheckSpec {
	out := make([]evidencetools.CheckSpec, 0, len(m.order))
	for _, id := range m.order {
		if spec, ok := m.specs[id]; ok {
			out = append(out, spec)
		} else {
			// Lane-internal ids stay visible in the registration surface
			// (Checks() feeds checkKnown and the run-start required-check
			// gate) so a lane-discharged or policy-required id resolves;
			// Lookup refuses them, so the engine's Dispatchable view
			// keeps them out of available_checks and the planner.
			out = append(out, evidencetools.CheckSpec{ID: id, Tool: id})
		}
	}
	return out
}

func (m *mappedFlowCatalog) registered(id string) bool {
	for _, have := range m.order {
		if have == id {
			return true
		}
	}
	return false
}

// PositiveAnswer is the catalog's answer-semantics verdict the flow
// broker stamps onto produced observations: an OK observation that
// answers its check's question positively even though the check's
// contract binds the claim below COMPLETE. For package-usage that is
// the USED verdict (package- or symbol-level): the payload carries a
// concrete product-site answer whose PARTIAL completeness is the
// recorded interpretation bound (static use, never runtime
// execution). For symbol-unreachability it is the disproven payload —
// concrete product references or a module-internal chain reaching a
// declared subject answers "is the declared symbol unreachable?" with
// no, and that finding must never read as missing coverage. Either way
// the required check is answered — the record discharges through the
// positive-answer path with its scope and snapshot binding intact. A
// degraded or UNKNOWN payload, a missing or unscoped record, or an
// off-snapshot observation answers nothing and returns false.
func (m *mappedFlowCatalog) PositiveAnswer(o *evidencetools.Observation) bool {
	if o == nil || o.ToolStatus != evidencetools.StatusOK ||
		strings.TrimSpace(o.Scope) == "" {
		return false
	}
	sd := o.ScopeDetails
	if sd == nil || sd.SnapshotHash == "" ||
		(m.snapshotHash != "" && sd.SnapshotHash != m.snapshotHash) {
		return false
	}
	switch o.Tool {
	case evidencetools.PackageUsageTool:
		d, ok := packageUsageDataOf(o)
		return ok && d.Usage == string(goanalysis.PackageUsageUsed)
	case evidencetools.SymbolUnreachabilityTool:
		return symbolUnreachabilityAnswered(o)
	}
	return false
}

// symbolUnreachabilityAnswered reports whether a symbol-unreachability
// payload answers the check's question positively — the check observed
// concrete reach evidence for at least one declared subject (product
// references or a module-internal chain), which the session tool
// records at PARTIAL by contract ("disproven" never claims every
// subject is reached or that reachability is exploitable — it answers
// the asked question only). An open-scope or undecodable payload
// answers nothing.
func symbolUnreachabilityAnswered(o *evidencetools.Observation) bool {
	var d evidencetools.SymbolUnreachabilityData
	if o == nil || o.Data == nil || !decodeData(o.Data, &d) {
		return false
	}
	return len(d.Result.ProductReferences) > 0 || len(d.Result.ModuleReachable) > 0
}

// catalogConditions renders the pinned conditions.yaml entries into
// flow registry conditions. Only catalog-declared ids exist; the
// planner can never invent one.
func catalogConditions(cats Catalogs, lane *LaneResult) []flow.Condition {
	subjects := canonicalSubjects(lane)
	out := make([]flow.Condition, 0, len(cats.Conditions))
	for _, spec := range cats.Conditions {
		out = append(out, flow.Condition{
			ID:          spec.ID,
			Statement:   spec.Description,
			Role:        spec.Role,
			SubjectRefs: append([]string(nil), subjects...),
			Polarity:    spec.Polarity,
		})
	}
	return out
}

// seededConditions are the conditions the deterministic lane already
// evaluated and the artifact builder needs engaged at run start: the
// applicability chain ids plus deployment-perimeter when the catalog
// declares the variable's answer set. Only catalog ids seed — an id
// the configuration dropped is never engaged.
func seededConditions(lane *LaneResult, cats Catalogs) []string {
	known := map[string]bool{}
	for _, c := range cats.Conditions {
		known[c.ID] = true
	}
	var out []string
	for _, id := range []string{"module-present", "version-in-range"} {
		if known[id] {
			out = append(out, id)
		}
	}
	for _, sub := range declaredSubjects(lane) {
		if sub.Symbol != "" && known["declared-symbol-unreachable"] {
			out = append(out, "declared-symbol-unreachable")
			break
		}
	}
	if _, ok := decisionVariableDecl(variableDeploymentPerimeter, lane, &cats); ok && known["deployment-perimeter"] {
		out = append(out, "deployment-perimeter")
	}
	for _, sub := range declaredSubjects(lane) {
		if sub.Package != "" && known["package-linked"] {
			out = append(out, "package-linked")
			break
		}
	}
	return out
}

// inapplicableRequiredChecks records required checks whose declared
// granularity cannot be applied to any advisory subject. A module-only
// advisory has no package subject; package-usage therefore cannot be
// dispatched without fabricating one. Module-capable usage-scope remains
// required and is not exempted.
func inapplicableRequiredChecks(lane *LaneResult, required []string) []string {
	moduleOnly := true
	for _, sub := range declaredSubjects(lane) {
		if sub.Package != "" || sub.Symbol != "" {
			moduleOnly = false
			break
		}
	}
	if !moduleOnly {
		return nil
	}
	for _, id := range required {
		if id == "package-usage" {
			return []string{id}
		}
	}
	return nil
}

// ---- lane discharge: the recorded lane decides what is already done ----

// dischargedLaneChecks walks the lane's audit ledger: every digest-
// bound record whose observation answers the check's question marks
// its catalog check id discharged for the flow run and contributes one
// prior-evidence row. A lane audit record is the recorded, snapshot-
// bound proof that the deterministic lane already ran the check —
// discharging asserts nothing new. The discharge gate is the lane
// counterpart of the engine's produced-observation rule
// (dischargedChecks) plus the scope binding the lane itself enforces;
// it never requires the digest-bearing evidence reference
// promotableObservation demands — a fact is a downstream claim needing
// pinned evidence, while discharge is the recorded fact that the
// check's question is answered. A degraded, errored, unpinned,
// off-snapshot or scope-less record — or a PARTIAL record that
// answers nothing — is never discharged: the flow must re-check it
// inside the session if the policy still requires it.
func dischargedLaneChecks(lane *LaneResult, cats Catalogs) (completed []string, evidence []flow.Observation) {
	toolToID := map[string]string{}
	for _, ck := range cats.Checks {
		if _, taken := toolToID[ck.Tool]; !taken {
			toolToID[ck.Tool] = ck.ID
		}
		if _, taken := toolToID[ck.ID]; !taken {
			toolToID[ck.ID] = ck.ID
		}
	}
	seen := map[string]bool{}
	for i := range lane.Records {
		rec := &lane.Records[i]
		o := rec.Observation
		if o == nil || o.ID == "" || rec.Tool != o.Tool {
			continue
		}
		// The audit record's observation is the session's pre-wire
		// object (typed payload); persist() pins the wire-decoded copy
		// in lane.Observations. Gate and digest-verify the pinned copy —
		// the bytes an auditor actually resolves — never the audit
		// twin, whose identical content marshals differently.
		po := pinnedLaneObservation(lane, o.ID)
		if po == nil {
			continue
		}
		pinned, ok := lane.CanonicalByObs[o.ID]
		if !ok || pinned == "" {
			continue
		}
		if digest, err := canonicalObservationDigest(po); err != nil || digest != pinned {
			continue
		}
		path := laneDischargePath(lane, po)
		if path == "" {
			continue
		}
		checkID, ok := toolToID[rec.Tool]
		if !ok || checkID == "" {
			continue // session tool outside the flow catalog cannot discharge a policy check
		}
		evidence = append(evidence, flow.Observation{
			ID:           po.ID,
			Status:       string(po.ToolStatus),
			Completeness: string(po.Completeness),
			Scope:        po.Scope,
			DataDigest:   pinned,
			EvidenceRefs: append([]string(nil), po.EvidenceRefs...),
			Limitations:  append([]string(nil), po.Limitations...),
			AuditBound:   true,
			// The row records which answer path discharged the check —
			// a closed negative or an answered positive — so the run
			// record and the report can tell them apart.
			DischargePath: path,
		})
		if !seen[checkID] {
			seen[checkID] = true
			completed = append(completed, checkID)
		}
	}
	return completed, evidence
}

// pinnedLaneObservation resolves the persisted, digest-pinned copy of
// one lane observation: the wire-decoded twin persist() wrote and
// hashed. obsIndex is the primary index; when a LaneResult was built
// without it (fixtures), Observations is scanned. A record whose id
// has no pinned copy is not dischargeable.
func pinnedLaneObservation(lane *LaneResult, id string) *evidencetools.Observation {
	if lane.obsIndex != nil {
		if o := lane.obsIndex[id]; o != nil {
			return o
		}
	}
	for _, o := range lane.Observations {
		if o != nil && o.ID == id {
			return o
		}
	}
	return nil
}

// laneRecordDischarges is the discharge gate for one lane audit record:
// the record discharges when the observation answers the check's
// question — an OK, explicitly scoped, snapshot-bound record is
// admitted either as a closed negative (COMPLETE coverage with a named
// coverage rule — finishLaneObservation admits COMPLETE only on a
// closed, un-gapped scope) or as a positive answer (package-usage
// reports USED at PARTIAL by contract: positive static usage never
// claims runtime execution or attacker reachability;
// symbol-unreachability reports disproven at PARTIAL: a concrete
// reach chain answers the asked question). Anything less (errored,
// timed out, unsupported, degraded, off-snapshot, unscoped, or a
// PARTIAL record that answers nothing) fails closed and cannot
// discharge.
func laneRecordDischarges(lane *LaneResult, o *evidencetools.Observation) bool {
	return laneDischargePath(lane, o) != ""
}

// laneDischargePath returns the discharge path a lane audit record
// satisfies — flow.DischargeClosedNegative for the complete
// closed-scope path, flow.DischargePositiveAnswer for an answered
// positive verdict — or "" when the record discharges nothing. The
// returned path is stamped onto the flow evidence row so the recorded
// run says which answer discharged the required check.
func laneDischargePath(lane *LaneResult, o *evidencetools.Observation) string {
	if o == nil || o.ToolStatus != evidencetools.StatusOK {
		return ""
	}
	if strings.TrimSpace(o.Scope) == "" || o.ScopeDetails == nil {
		return ""
	}
	sd := o.ScopeDetails
	if sd.SnapshotHash == "" || sd.SnapshotHash != lane.ContentHash {
		return ""
	}
	if o.Completeness == evidencetools.CompletenessComplete && sd.CoverageRule != "" {
		return flow.DischargeClosedNegative
	}
	switch o.Tool {
	case evidencetools.PackageUsageTool:
		if d, ok := packageUsageDataOf(o); ok && d.Usage == string(goanalysis.PackageUsageUsed) {
			return flow.DischargePositiveAnswer
		}
	case evidencetools.SymbolUnreachabilityTool:
		if symbolUnreachabilityAnswered(o) {
			return flow.DischargePositiveAnswer
		}
	}
	return ""
}

// ---- driver adapter: AgentDriver -> flow.Planner/Reassessor ----

type driverPlanner struct {
	drv AgentDriver
	rec *[]AgentTurnMetadata
}

func (p *driverPlanner) Plan(ctx context.Context, in flow.PlanInput) (flow.Plan, error) {
	plan, meta, err := p.drv.Plan(ctx, in)
	if p.rec != nil {
		*p.rec = append(*p.rec, meta)
	}
	return plan, err
}

type driverReassessor struct {
	drv AgentDriver
	rec *[]AgentTurnMetadata
}

func (r *driverReassessor) Reassess(ctx context.Context, in flow.ReassessInput) (flow.Reassessment, error) {
	re, meta, err := r.drv.Reassess(ctx, in)
	if r.rec != nil {
		*r.rec = append(*r.rec, meta)
	}
	return re, err
}

// failingDriver is the recorded-failure driver: every call returns the
// construction-time error so the run terminates PLANNER_FAILURE /
// REASSESSOR_FAILURE with the real reason instead of a nil-planner
// stub message.
type failingDriver struct{ err error }

func (d failingDriver) Plan(context.Context, flow.PlanInput) (flow.Plan, AgentTurnMetadata, error) {
	return flow.Plan{}, AgentTurnMetadata{Status: AgentFailed, Err: d.err.Error()}, d.err
}
func (d failingDriver) Reassess(context.Context, flow.ReassessInput) (flow.Reassessment, AgentTurnMetadata, error) {
	return flow.Reassessment{}, AgentTurnMetadata{Status: AgentFailed, Err: d.err.Error()}, d.err
}

// ---- the run ----

// RunDecisionReady executes the opt-in R6 lane: deterministic lane,
// then the bounded react loop over the same confined session, then the
// decision-artifact build and the /3 report. Every failure mode lands
// in a recorded, explicit termination — HOLD_UNKNOWN material — never
// a silent success.
func RunDecisionReady(ctx context.Context, opts DecisionReadyOptions) (*Report, *DecisionRunRecord, error) {
	if ctx == nil {
		return nil, nil, errors.New("decision-ready run requires a non-nil context")
	}
	if opts.ConfigFS == nil {
		return nil, nil, errors.New("decision-ready run requires ConfigFS with the pinned research configuration")
	}
	if opts.OutputDir == "" {
		return nil, nil, errors.New("decision-ready run requires OutputDir")
	}
	if opts.ReplayDir != "" && opts.DeterministicOnly {
		return nil, nil, errors.New("--replay-decision-run cannot be combined with --deterministic-only")
	}

	// ---- pinned configuration (fail closed before any lane work) ----
	cats, err := LoadCatalogs(opts.ConfigFS)
	if err != nil {
		return nil, nil, fmt.Errorf("research catalogs: %w", err)
	}
	loaded, err := LoadSafetyPolicy(opts.ConfigFS)
	if err != nil {
		return nil, nil, fmt.Errorf("research safety policy: %w", err)
	}
	rubric, err := LoadFlowRubric(opts.ConfigFS)
	if err != nil {
		return nil, nil, fmt.Errorf("research flow rubric: %w", err)
	}
	// The effective run policy is the configured safety policy plus the
	// rubric budgets. A caller-supplied FlowPolicy must be monotonic
	// over the configured one — a relaxation rejects the run.
	effective := flow.Policy{
		RequiredRules:       append([]string(nil), loaded.RequiredRules...),
		RequiredChecks:      append([]string(nil), loaded.RequiredChecks...),
		ForbiddenPromotions: append([]string(nil), loaded.ForbiddenPromotions...),
		MaxSteps:            rubric.MaxSteps,
		MaxActions:          rubric.MaxActions,
	}
	configured := effective // the baseline floor this run validates against
	if !flowPolicyUnset(opts.FlowPolicy) {
		if err := flow.ValidateMonotonicPolicy(configured, opts.FlowPolicy); err != nil {
			return nil, nil, fmt.Errorf("flow policy is a relaxation of the configured safety policy: %w", err)
		}
		if opts.FlowPolicy.MaxSteps < 0 || opts.FlowPolicy.MaxActions < 0 {
			return nil, nil, fmt.Errorf("flow policy carries negative budgets")
		}
		effective.RequiredRules = append([]string(nil), opts.FlowPolicy.RequiredRules...)
		effective.RequiredChecks = append([]string(nil), opts.FlowPolicy.RequiredChecks...)
		effective.ForbiddenPromotions = append([]string(nil), opts.FlowPolicy.ForbiddenPromotions...)
		if opts.FlowPolicy.MaxSteps != 0 {
			effective.MaxSteps = opts.FlowPolicy.MaxSteps
		}
		if opts.FlowPolicy.MaxActions != 0 {
			effective.MaxActions = opts.FlowPolicy.MaxActions
		}
	}

	// ---- deterministic lane (identical to the legacy route) ----
	laneOpts := opts.LaneOptions
	laneOpts.OutputDir = opts.OutputDir
	laneStarted := opts.LaneStartedAt
	if laneStarted.IsZero() {
		laneStarted = time.Now()
	}
	lane, es, err := RunDeterministicSession(ctx, laneOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("deterministic lane: %w", err)
	}
	defer es.Close()
	laneFinished := time.Now()

	runID := opts.RunID
	if runID == "" {
		runID = "research-decision-" + strconv.FormatInt(laneFinished.Unix(), 10)
	}
	objective := "decision-ready evidence assessment for advisory " + lane.Advisory.Input.ResolvedID +
		": produce one complete proposed disposition or a finite set of complete conditional branches"

	// ---- admission surfaces ----
	sessionCatalog := es.Catalog()
	flowCatalog := newFlowCatalog(cats, sessionCatalog, lane.ContentHash)
	conditions := catalogConditions(cats, lane)
	baseRegistry, err := flow.NewCatalogRegistry(flowCatalog, conditions)
	if err != nil {
		return nil, nil, fmt.Errorf("flow registry: %w", err)
	}
	// The anchored-text subject gate wraps the catalog registry: any
	// subject identity the advisory's structured declaration does not
	// name needs a verbatim advisory-text anchor plus affected-module
	// membership before a check may dispatch — the same relation replay
	// re-validates, so recorded runs stay admissible only under the
	// same extraction rule that admitted them live.
	registry := flow.Registry(newSubjectGateRegistry(baseRegistry, lane))
	broker, err := flow.NewSessionBroker(flowCatalog, es.CallWithAudit)
	if err != nil {
		return nil, nil, fmt.Errorf("flow broker: %w", err)
	}

	// ---- driver ----
	// A fail-closed release-evidence channel short-circuits the run
	// before any planner/driver is built: the planner/model path never
	// runs, the recorded result terminates NOT_DECISION_READY with the
	// channel's reason, and the adapter continues to persistence so the
	// report + manifest still carry the explicit outcome.
	releaseNotRun, releaseReason := LaneReleaseNotRun(lane)
	var turns []AgentTurnMetadata
	var drv AgentDriver
	var planner flow.Planner
	var reassessor flow.Reassessor
	if !releaseNotRun {
		switch {
		case opts.DeterministicOnly:
			drv = failingDriver{err: errors.New("decision-ready run is deterministic-only: no planner is configured")}
		case opts.Agent != nil:
			drv = opts.Agent
		case opts.AgentFactory != nil:
			if built, ferr := opts.AgentFactory(lane); ferr != nil {
				drv = failingDriver{err: fmt.Errorf("agent driver construction failed: %w", ferr)}
			} else {
				drv = built
			}
		}
		if drv != nil {
			planner = &driverPlanner{drv: drv, rec: &turns}
			reassessor = &driverReassessor{drv: drv, rec: &turns}
		}
	}

	var res flow.Result
	var recAudit []evidencetools.AuditRecord
	var rec *PersistedDecisionRun
	switch {
	case releaseNotRun:
		// The record is real: lane-carried discharges and seeded
		// conditions are preserved exactly as the engine's open() would,
		// then the run terminates without a single step. Steps, Actions
		// and Events stay empty-but-present so the persisted result
		// round-trips; replaying this directory fails closed (a NOT_RUN
		// record replays as a truncated planner stream, never a success).
		completed, evidence := dischargedLaneChecks(lane, cats)
		budget := flow.Budget{MaxSteps: effective.MaxSteps, MaxActions: effective.MaxActions,
			StepsLeft: effective.MaxSteps, ActionsLeft: effective.MaxActions}
		res = flow.Result{
			RunID:              runID,
			Termination:        flow.TermNotDecisionReady,
			Reason:             "release evidence channel failed closed: NOT_RUN (" + releaseReason + ") — planner never ran",
			Steps:              []flow.StepRecord{},
			Actions:            []flow.PlanAction{},
			Observations:       []flow.Observation{},
			Evidence:           evidence,
			Conditions:         seededConditions(lane, cats),
			Policy:             effective,
			CompletedChecks:    completed,
			InapplicableChecks: inapplicableRequiredChecks(lane, effective.RequiredChecks),
			Budget:             budget,
			Events: []flow.Event{
				{Seq: 0, Kind: flow.EventRunStart, Policy: &effective, Budget: &budget},
				{Seq: 1, Kind: flow.EventTerminated, Termination: flow.TermNotDecisionReady,
					Detail: "release evidence channel failed closed: NOT_RUN (" + releaseReason + ")"},
			},
		}
	case opts.ReplayDir != "":
		rec, err = LoadPersistedDecisionRun(opts.ReplayDir)
		if err != nil {
			return nil, nil, fmt.Errorf("replay-decision-run: %w", err)
		}
		res, err = flow.Replay(ctx, flow.ReplayInput{
			Result:   rec.Result,
			Input:    flow.Input{Baseline: configured},
			Registry: registry,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("decision-run replay: %w", err)
		}
		if res.Termination != rec.Result.Termination {
			return nil, nil, fmt.Errorf("decision-run replay diverged: recorded %s, replayed %s",
				rec.Result.Termination, res.Termination)
		}
		recAudit = rec.Audit
	default:
		completed, evidence := dischargedLaneChecks(lane, cats)
		inapplicable := inapplicableRequiredChecks(lane, effective.RequiredChecks)
		eng := &flow.Engine{
			Planner:    planner,
			Reassessor: reassessor,
			Broker:     broker,
			Registry:   registry,
			Policy:     effective,
		}
		res, err = eng.Run(ctx, flow.Input{
			RunID:              runID,
			Objective:          objective,
			Conditions:         seededConditions(lane, cats),
			Evidence:           evidence,
			CompletedChecks:    completed,
			InapplicableChecks: inapplicable,
			Baseline:           configured,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("decision-ready flow: %w", err)
		}
		recAudit = es.DrainAudit()
	}

	// Move flow-produced observation ids out of the session-minted
	// OBS-#### space into ids past the lane's numbering — the same
	// convention the verification phase applies — so every persisted
	// observation id stays unique across ledgers.
	renumberFlowObservations(&res, recAudit, lane)

	// ---- persistence (before assembly: the validator binds to it) ----
	if err := persistFlowResult(opts.OutputDir, &res); err != nil {
		return nil, nil, fmt.Errorf("flow result persistence: %w", err)
	}
	if err := persistFlowEvents(opts.OutputDir, &res); err != nil {
		return nil, nil, fmt.Errorf("flow events persistence: %w", err)
	}
	flowTrace, traceAudit := flowTraceFromRecords(&res, recAudit, lane)
	if err := writeFlowObservationLedger(opts.OutputDir, recAudit); err != nil {
		return nil, nil, fmt.Errorf("flow observation ledger: %w", err)
	}
	flowArts, err := persistFlowArtifacts(opts.OutputDir, flowTrace)
	if err != nil {
		return nil, nil, fmt.Errorf("flow artifacts: %w", err)
	}

	// ---- decision-artifact build ----
	pins, perr := r6Pins(opts.ConfigFS, rubric)
	if perr != nil {
		return nil, nil, fmt.Errorf("replay/policy pins: %w", perr)
	}
	facts, ferr := BuildDecisionFacts(FactBuildInput{Lane: lane, Trace: flowTrace, VerificationAudit: traceAudit})
	if ferr != nil {
		return nil, nil, fmt.Errorf("fact envelope: %w", ferr)
	}
	ruleFacts, ferr := BuildRuleFacts(FactBuildInput{Lane: lane, Trace: flowTrace, VerificationAudit: traceAudit})
	if ferr != nil {
		return nil, nil, fmt.Errorf("rule facts: %w", ferr)
	}
	seeded := map[string]bool{}
	for _, id := range seededConditions(lane, cats) {
		seeded[id] = true
	}
	var proposals []AgentConditionProposal
	for _, cid := range res.Conditions {
		if seeded[cid] {
			continue
		}
		stmt := cid
		if reg, ok := registry.Condition(cid); ok && reg.Statement != "" {
			stmt = reg.Statement
		}
		proposals = append(proposals, AgentConditionProposal{
			ConditionID: cid, SubjectRefs: canonicalSubjects(lane), Statement: stmt,
		})
	}
	var vars []DecisionVariable
	if v, ok := decisionVariableDecl(variableBuildVariant, lane, &cats); ok {
		vars = append(vars, v)
	}
	if v, ok := decisionVariableDecl(variableDeploymentPerimeter, lane, &cats); ok {
		vars = append(vars, v)
	}
	artifact, aerr := BuildDecisionArtifact(ctx, ArtifactInput{
		Lane:           lane,
		Facts:          facts,
		RuleFacts:      ruleFacts,
		Conditions:     engagedConditions(res.Conditions, conditions),
		Variables:      vars,
		Policy:         SafetyPolicy{RequiredRules: effective.RequiredRules, RequiredChecks: effective.RequiredChecks, ForbiddenPromotions: effective.ForbiddenPromotions},
		Catalogs:       &cats,
		Registry:       evaluator.DefaultAdapterRegistry(),
		Pins:           pins,
		AgentProposals: proposals,
	})
	if aerr != nil {
		return nil, nil, fmt.Errorf("decision artifact: %w", aerr)
	}
	// The artifact may propose CLOSE_* only when the run recorded a
	// decision-ready state — DECISION_READY/BRANCHES_COMPLETE or an
	// explicit AWAITING_ENVIRONMENT with declared inputs. Every other
	// termination caps the proposal at HOLD_UNKNOWN so a broken or
	// incomplete run can never carry a decision-looking artifact.
	if !res.Ready && res.Termination != flow.TermAwaitingEnvironment {
		capArtifactToHold(&artifact, &res)
	}
	// Advisory-scope publication re-gate: applied before the replay
	// comparison, the sidecar write and the record so the persisted file,
	// the run record and the embedded report carry the same artifact.
	if guarded := scopeBoundArtifact(lane, &artifact); guarded != nil {
		artifact = *guarded
	}
	record := &DecisionRunRecord{
		Result: &res, Lane: lane, Artifact: &artifact, Turns: turns,
		Trace:        flowTrace,
		ReplayedFrom: opts.ReplayDir, Objective: objective,
	}
	if opts.ReplayDir != "" {
		if derr := compareReplayedArtifact(&artifact, rec.ArtifactPath); derr != nil {
			return nil, nil, derr
		}
	}

	// ---- /3 report ----
	decision, decisionTrace := decisionForRecordedRun(&res, &artifact, flowTrace, lane, traceAudit)
	record.Decision = decision
	factsArtifact, ferr := persistFlowFacts(opts.OutputDir, &res, flowTrace, facts, flowArts)
	if ferr != nil {
		return nil, nil, fmt.Errorf("flow facts: %w", ferr)
	}
	record.FactsArtifact = factsArtifact
	if err := persistDecisionArtifact(opts.OutputDir, &artifact); err != nil {
		return nil, nil, fmt.Errorf("decision artifact persistence: %w", err)
	}

	started := opts.StartedAt
	if started.IsZero() {
		started = laneStarted
	}
	report := Assemble(AssembleInput{
		Lane:              lane,
		Decision:          &decision,
		DecisionArtifact:  &artifact,
		Trace:             decisionTrace,
		VerifArtifacts:    flowArts,
		DeterministicOnly: opts.DeterministicOnly,
		RunID:             runID,
		StartedAt:         started,
		FinishedAt:        time.Now(),
		Timeouts: TimeoutInfo{
			DeterministicMs: laneOpts.Timeout.Milliseconds(),
		},
		LaneStartedAt:  laneStarted,
		LaneFinishedAt: laneFinished,
	})
	record.FlowFacts = facts
	return report, record, nil
}

// flowPolicyUnset reports whether the caller supplied no FlowPolicy
// members at all — the configured policy then stands unchanged.
func flowPolicyUnset(p flow.Policy) bool {
	return len(p.RequiredRules) == 0 && len(p.RequiredChecks) == 0 &&
		len(p.ForbiddenPromotions) == 0 && p.MaxSteps == 0 && p.MaxActions == 0
}

// engagedConditions renders the run's engaged condition ids into
// artifact conditions, seeded first; only registry-known ids render.
func engagedConditions(engaged []string, known []flow.Condition) []Condition {
	byID := map[string]flow.Condition{}
	for _, c := range known {
		byID[c.ID] = c
	}
	var out []Condition
	for _, id := range engaged {
		c, ok := byID[id]
		if !ok {
			continue
		}
		out = append(out, Condition{
			ID:          c.ID,
			Statement:   c.Statement,
			Role:        c.Role,
			SubjectRefs: append([]string(nil), c.SubjectRefs...),
			Required:    true,
			Polarity:    c.Polarity,
		})
	}
	return out
}

// capArtifactToHold demotes a non-ready run's artifact to HOLD_UNKNOWN:
// every branch becomes NOT_DECISION_READY, every justification loses
// its disposition, and the recorded termination is added to the
// unknown branch's limitations so the artifact itself states why no
// proposal stands. The artifact stays contract-valid.
func capArtifactToHold(a *DecisionArtifact, res *flow.Result) {
	detail := fmt.Sprintf("run terminated %s (%s) — no decision-ready state was reached",
		res.Termination, res.Reason)
	for i := range a.Branches {
		br := &a.Branches[i]
		if br.ID != "B-UNKNOWN" && br.Status != BranchNotDecisionReady {
			br.Status = BranchNotDecisionReady
			br.ProposedDisposition = DispositionHoldUnknown
			br.Limitations = dedupeStrings(append(br.Limitations, detail))
		}
	}
	for i := range a.JustificationGraph {
		a.JustificationGraph[i].Disposition = DispositionHoldUnknown
	}
	a.ProposedDisposition = DispositionHoldUnknown
	a.HumanAction.Mode = HumanActionAcceptReject
	a.HumanAction.EnvironmentQuestionRefs = nil
	a.HumanAction.EnvironmentQuestions = nil
	if len(a.HumanAction.MandatoryFactRefs) == 0 {
		seen := map[string]bool{}
		for _, br := range a.Branches {
			for _, ref := range br.FactRefs {
				if seen[ref] || len(a.HumanAction.MandatoryFactRefs) >= MaxMandatoryFacts {
					continue
				}
				for _, f := range a.SharedFacts {
					if f.ID == ref && f.Status == FactStatusVerified {
						a.HumanAction.MandatoryFactRefs = append(a.HumanAction.MandatoryFactRefs, ref)
						seen[ref] = true
						break
					}
				}
			}
		}
	}

}

// decisionForRecordedRun projects the decision for the recorded run:
// the lane's own terminal decisions dominate — a deterministic
// applicability FALSE stands NOT_AFFECTED on its own chain's reason
// and evidence refs, and a lane-owned symbol proof's terminal decision
// stands the same way — no matter what the flow's termination or the
// artifact's disposition says. A supporting layer's failure (a
// non-ready termination, an undischarged policy-required check) is
// recorded as a limitation on the standing verdict, never as a
// replacement for it. Only when the lane carries no terminal decision
// does the artifact's disposition govern — HOLD_UNKNOWN included. The
// returned trace is the ledger the decision grounds on: the proof's
// own lane-renumbered trace for a dominating proof, else the flow
// trace — the report's decision checks and ref translation follow it.
func decisionForRecordedRun(res *flow.Result, a *DecisionArtifact, trace *VerificationTrace, lane *LaneResult, audit []evidencetools.AuditRecord) (EvidenceDecision, *VerificationTrace) {
	if lane != nil {
		// The deterministic applicability chain decides non-applicability
		// on its own — no proposal, trace, flow termination or artifact
		// disposition can suppress it (laneApplicabilityDecision is the
		// shared chain VerifyDecision applies first, and the only route
		// to NOT_AFFECTED).
		if d, ok := laneApplicabilityDecision(lane); ok {
			d.Limitations = dedupeStrings(append(d.Limitations, flowRunLimitations(res)...))
			return d, trace
		}
		// The cached lane proof decisions below are negatives: each may
		// only stand when the resolved advisory scope covers the requested
		// identity. A partial scope skips them, and the artifact
		// projection below refuses the close with the scoped gap named.
		negativeScopeOpen := advisoryScopeAllowsNegativeClosure(lane)
		// A lane-owned bounded symbol proof's terminal authority decision
		// stands the same way — the precedence the legacy route applies
		// when the proposal route stays inconclusive. An INCONCLUSIVE
		// proof is not terminal: the artifact's disposition governs
		// unchanged. The decision grounds on the proof's own
		// lane-renumbered ledger, which the report's ref translation and
		// decision-check rows follow.
		if negativeScopeOpen && lane.SymbolProof != nil && lane.SymbolProof.Decision.Verdict != "" &&
			lane.SymbolProof.Decision.Verdict != domain.VerdictInconclusive {
			d := lane.SymbolProof.Decision
			// The copy must own its limitation list: appending below must
			// never reach into the lane record's backing array.
			d.Limitations = append([]string(nil), d.Limitations...)
			d.Limitations = dedupeStrings(append(d.Limitations, flowRunLimitations(res)...))
			proofTrace := trace
			if lane.SymbolProof.Trace != nil {
				proofTrace = lane.SymbolProof.Trace
			}
			return d, proofTrace
		}
		// The post-reach configuration proof is the second lane-owned
		// terminal authority: the lane only stores it when the exact
		// closure and the verifier re-derivation closed, so an absent
		// proof defers to the artifact's disposition unchanged. It ranks
		// below the symbol proof (a code-level unreachability statement)
		// and above any artifact proposal.
		if negativeScopeOpen && lane.ConfigProof != nil && lane.ConfigProof.Decision.Verdict != "" &&
			lane.ConfigProof.Decision.Verdict != domain.VerdictInconclusive {
			d := lane.ConfigProof.Decision
			d.Limitations = append([]string(nil), d.Limitations...)
			d.Limitations = dedupeStrings(append(d.Limitations, flowRunLimitations(res)...))
			proofTrace := trace
			if lane.ConfigProof.Trace != nil {
				proofTrace = lane.ConfigProof.Trace
			}
			return d, proofTrace
		}
	}
	return decisionForArtifactWithAuthorityAudit(a, trace, lane, audit), trace
}

// flowRunLimitations renders the recorded run's non-ready termination
// and every policy-required check that stayed undischarged — the
// failures the artifact carries as HOLD_UNKNOWN material — as the
// limitations they are on a lane-terminal verdict: recorded, named,
// never hidden, and never a replacement verdict.
func flowRunLimitations(res *flow.Result) []string {
	if res == nil || res.Ready {
		return nil
	}
	var lims []string
	if res.Termination != "" {
		lims = append(lims, fmt.Sprintf("agent flow terminated %s (%s)", res.Termination, res.Reason))
	}
	if missing := undischargedRequiredChecks(res); len(missing) > 0 &&
		!strings.Contains(res.Reason, "undischarged") {
		lims = append(lims, fmt.Sprintf("policy-required checks remain undischarged: %s",
			strings.Join(missing, ", ")))
	}
	return lims
}

// undischargedRequiredChecks derives the policy-required check ids the
// recorded run never discharged, under the engine's own pairing rule
// (dischargedChecks + requiredCoverageWithInapplicable): a produced
// observation answers its action's check when it is OK, audit-bound,
// digest-pinned and either COMPLETE (closed negative) or a stamped
// positive answer; caller-declared completions and inapplicable
// records count out of the required set.
func undischargedRequiredChecks(res *flow.Result) []string {
	discharged := map[string]bool{}
	for _, c := range res.CompletedChecks {
		if c != "" {
			discharged[c] = true
		}
	}
	for i, o := range res.Observations {
		if i >= len(res.Actions) {
			break
		}
		if o.Status == flow.ObsStatusOK && o.AuditBound && o.DataDigest != "" &&
			(o.Completeness == flow.ObsComplete || o.DischargePath == flow.DischargePositiveAnswer) {
			discharged[res.Actions[i].AdapterID] = true
		}
	}
	inapplicable := map[string]bool{}
	for _, c := range res.InapplicableChecks {
		if c != "" {
			inapplicable[c] = true
		}
	}
	var missing []string
	for _, req := range res.Policy.RequiredChecks {
		if !discharged[req] && !inapplicable[req] {
			missing = append(missing, req)
		}
	}
	return missing
}

// decisionForArtifact is the conservative compatibility wrapper. A /3
// close is never projected without the deterministic lane that the
// authority evaluated; callers with only an artifact cannot bypass that
// authority. Production uses decisionForArtifactWithAuthority below.
func decisionForArtifact(a *DecisionArtifact, trace *VerificationTrace) EvidenceDecision {
	return decisionForArtifactWithAuthority(a, trace, nil)
}

// decisionForArtifactWithAuthority is the compatibility entry point for
// callers that hold no drained session audit; a close proposal still
// cannot be projected without the deterministic lane.
func decisionForArtifactWithAuthority(a *DecisionArtifact, trace *VerificationTrace, lane *LaneResult) EvidenceDecision {
	return decisionForArtifactWithAuthorityAudit(a, trace, lane, nil)
}

// decisionForArtifactWithAuthorityAudit projects the artifact only after the
// exact same VerifyDecision authority used by the legacy route has
// evaluated the same lane evidence, with the drained session audit and
// the audit-derived observation index attached so the deterministic
// authority route can bind every proof observation to its persisted
// record. The artifact's proposed disposition is merely a candidate: it
// never promotes a close by itself.
func decisionForArtifactWithAuthorityAudit(a *DecisionArtifact, trace *VerificationTrace, lane *LaneResult, audit []evidencetools.AuditRecord) EvidenceDecision {
	obsRefs := artifactObsRefs(a)
	if isCloseDisposition(a.ProposedDisposition) {
		if lane == nil {
			return inconclusiveArtifactProjection(a, obsRefs, "close proposal has no deterministic lane for VerifyDecision")
		}
		// The cached lane proof decisions reused below are negatives too:
		// a partial scope refuses the artifact's close before any cached
		// proof decision can stand in for the authority.
		if !advisoryScopeAllowsNegativeClosure(lane) {
			return inconclusiveArtifactProjection(a, obsRefs, scopedApplicabilityGap(lane))
		}
		authorityInput := (*VerifiedFalsifierInput)(nil)
		for _, j := range a.JustificationGraph {
			if j.RuleID != "rule.declared-symbols-unreached" || j.Disposition != DispositionCloseNoExploitPath {
				continue
			}
			// Replay/publication admission: a saved justification edge is a
			// proposal, not proof. The close it claims rests on symbol
			// deadness, which is a negative only under the lane's admitted
			// invocation-necessity premise. An old artifact whose record
			// carried an omission conclusion without the contract is
			// refused here even when its saved disposition says CLOSE.
			if err := requireDeclaredDeadnessPremise(lane); err != nil {
				return inconclusiveArtifactProjection(a, obsRefs,
					"declared-symbol-unreached close refused: "+err.Error())
			}
			authorityInput = &VerifiedFalsifierInput{Kind: domain.FalsifierDeclaredSymbolUnreached, ConditionID: "declared-symbol-unreachable", RuleID: j.RuleID}
			break
		}
		if authorityInput != nil {
			for _, sub := range declaredSubjects(lane) {
				if sub.Symbol != "" {
					authorityInput.Subjects = append(authorityInput.Subjects, FactUsageSubject{Module: sub.Module, Package: sub.Package, Symbol: sub.Symbol})
				}
			}
			if len(authorityInput.Subjects) == 0 {
				return inconclusiveArtifactProjection(a, obsRefs, "close proposal has no declared symbol subjects in the deterministic lane")
			}
			want := map[string]bool{}
			for _, s := range authorityInput.Subjects {
				want[subjectRefName(s.Module, s.Package, s.Symbol)] = true
			}
			got := map[string]bool{}
			for _, ref := range a.AdvisoryBinding.SubjectRefs {
				if strings.HasPrefix(ref, "symbol:") {
					v := strings.TrimPrefix(ref, "symbol:")
					parts := strings.SplitN(v, "|", 2)
					if len(parts) == 2 {
						if dot := strings.LastIndex(parts[1], "."); dot > 0 && dot < len(parts[1])-1 {
							got[subjectRefName(parts[0], parts[1][:dot], parts[1][dot+1:])] = true
						}
					}
				}
			}
			for key := range want {
				if !got[key] {
					return inconclusiveArtifactProjection(a, obsRefs, "artifact advisory binding does not match lane-declared symbol subjects")
				}
			}
		}
		var authority EvidenceDecision
		var err error
		switch {
		case authorityInput != nil && lane.SymbolProof != nil:
			// The deterministic lane already ran the declared-symbol
			// proof itself and holds its own VerifyDecision authority
			// decision over the lane-recorded observations — reuse it
			// verbatim rather than re-evaluating a different ledger.
			authority = lane.SymbolProof.Decision
		default:
			// The audit-derived index and the audit records themselves
			// travel with the trace: the symbol-unreachability authority
			// decodes only audit-recorded payloads and resolves only
			// audit-pinned refs. When the lane attempted no proof the
			// flow trace/audit stay the evidence source exactly as
			// before — including a flow re-dispatch of a check the lane
			// could not discharge.
			decisionInput := DecisionInput{Lane: lane, Trace: trace, Audit: audit,
				Authority:        authorityInput,
				ObservationIndex: VerificationObservationIndex(trace, audit)}
			authority, err = VerifyDecision(context.Background(), decisionInput)
		}
		if err != nil || !authorityAllowsClose(authority, a.ProposedDisposition) {
			why := "authoritative VerifyDecision did not yield the artifact's proposed close"
			if err != nil {
				why += ": " + err.Error()
			} else if authority.Reason != "" {
				why += ": " + authority.Reason
			}
			return inconclusiveArtifactProjection(a, obsRefs, why)
		}
		// Keep the authority's reason, coverage and resolved refs. This
		// avoids templated projection prose and ensures the report names
		// exactly what the authority cited.
		if authority.TicketRationale == "" {
			authority.TicketRationale = closeArtifactRationale(a)
		}
		if len(authority.EvidenceRefs) == 0 {
			authority.EvidenceRefs = obsRefs
		}
		return authority
	}
	reason := "decision-artifact proposed " + string(a.ProposedDisposition) + " — no code-grounded closure stands"
	if lane != nil && !advisoryScopeAllowsNegativeClosure(lane) {
		// The governing blocker is the uncovered requested scope, not the
		// artifact's conservative disposition: name it exactly.
		reason = scopedApplicabilityGap(lane) + "; the artifact proposes " + string(a.ProposedDisposition)
	}
	return EvidenceDecision{
		Verdict:        domain.VerdictInconclusive,
		Reason:         reason,
		Coverage:       "NOT_EVALUATED",
		Scope:          "decision-artifact/1 (R6 flow run)",
		EvidenceRefs:   obsRefs,
		HumanQuestions: append([]string(nil), artifactQuestions(a)...),
		TicketRationale: "Decision requires human follow-up: accept or reject the proposed disposition after reading the mandatory fact card" +
			environmentSuffix(len(a.HumanAction.EnvironmentQuestionRefs)),
	}
}

func authorityAllowsClose(d EvidenceDecision, proposed ProposedDisposition) bool {
	switch proposed {
	case DispositionCloseNotAffected:
		return d.Verdict == domain.VerdictNotAffected && d.Coverage == "COMPLETE" && len(d.Limitations) == 0
	case DispositionCloseNoExploitPath:
		return d.Verdict == domain.VerdictNoExploitPathFound && d.Coverage == "COMPLETE" &&
			d.NegativeVerification != nil && d.NegativeVerification.Status == domain.NegativeVerified && len(d.Limitations) == 0
	default:
		return false
	}
}

func inconclusiveArtifactProjection(a *DecisionArtifact, refs []string, reason string) EvidenceDecision {
	return EvidenceDecision{
		Verdict:         domain.VerdictInconclusive,
		Reason:          reason,
		Coverage:        "NOT_EVALUATED",
		Scope:           "decision-artifact/1 (R6 flow run)",
		EvidenceRefs:    refs,
		HumanQuestions:  append([]string(nil), artifactQuestions(a)...),
		TicketRationale: "Decision requires human follow-up: accept or reject the proposed disposition; the authoritative decision path did not permit closure" + environmentSuffix(len(a.HumanAction.EnvironmentQuestionRefs)),
	}
}

func closeArtifactRationale(a *DecisionArtifact) string {
	for _, j := range a.JustificationGraph {
		if isCloseDisposition(j.Disposition) && j.Statement != "" {
			return j.Statement
		}
	}
	return "the authoritative decision path yielded the proposed close on the cited recorded evidence"
}

// environmentSuffix picks the follow-up clause from the count of
// declared environment questions — never from the padded question list,
// which always carries a default and would claim questions exist when
// none are declared.
func environmentSuffix(declared int) string {
	if declared == 0 {
		return "; follow-up: no environment answers are required"
	}
	return "; follow-up: answer the declared environment questions before disposition"
}

// artifactQuestions renders the declared environment questions for the
// inconclusive projection: question text of each variable the human
// action references, else a bounded default.
func artifactQuestions(a *DecisionArtifact) []string {
	var qs []string
	want := map[string]bool{}
	for _, id := range a.HumanAction.EnvironmentQuestionRefs {
		want[id] = true
	}
	for _, v := range a.DecisionVariables {
		if want[v.ID] && v.Question != "" {
			qs = append(qs, v.Question)
		}
	}
	// Derived questions follow the declared contract asks: they name the
	// recorded, case-specific statement behind the environment layer.
	qs = dedupeStrings(append(qs, a.HumanAction.EnvironmentQuestions...))
	if len(qs) == 0 {
		qs = []string{"Review the decision artifact's branch set and accept or reject the proposed disposition."}
	}
	return qs
}

// artifactObsRefs collects the observation refs every artifact fact
// cites — the persisted-observation ids the decision projection may
// reference (they resolve through verification-observations.jsonl).
func artifactObsRefs(a *DecisionArtifact) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range a.SharedFacts {
		for _, ref := range f.ObservationRefs {
			if !seen[ref] {
				seen[ref] = true
				out = append(out, ref)
			}
		}
	}
	return out
}

// ---- trace synthesis: flow records -> VerificationTrace ----

// flowTraceFromRecords projects the recorded flow run into the
// verification-trace shape the fact envelope and the report consume.
// Pairing is audit-bound: a persisted audit record pairs to the first
// recorded action whose resolved tool and canonical arguments match
// the record's — a ledger row that names nothing dispatched never
// becomes a fact, and an action the session never recorded stays a
// limitation instead of a check row. The lane supplies the advisory
// text the request's recorded anchor is re-matched against, so the
// trace carries the same provenance the admission gate verified —
// recomputed, never trusted from the plan.
func flowTraceFromRecords(res *flow.Result, audit []evidencetools.AuditRecord, lane *LaneResult) (*VerificationTrace, []evidencetools.AuditRecord) {
	trace := &VerificationTrace{Complete: true}
	if res == nil {
		trace.Complete = false
		trace.Limitations = append(trace.Limitations, "flow result is missing: declared verification actions cannot be reconstructed")
		return trace, nil
	}
	// The declared sequence is the plans' action sequence, not the subset
	// the broker happened to dispatch. A legacy/result-only record has no
	// plans, so its dispatched action list is the declaration in that case.
	var declared []flow.PlanAction
	for _, step := range res.Steps {
		declared = append(declared, step.Plan.Actions...)
	}
	if len(declared) == 0 {
		declared = append(declared, res.Actions...)
	}
	dispatched := make([]bool, len(declared))
	usedActions := make([]bool, len(res.Actions))
	for i := range declared {
		for j := range res.Actions {
			if usedActions[j] || !sameFlowAction(&declared[i], &res.Actions[j]) {
				continue
			}
			usedActions[j], dispatched[i] = true, true
			break
		}
	}
	for i := range res.Actions {
		if !usedActions[i] {
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf("dispatched flow action %q is not present in the declared action sequence", res.Actions[i].ID))
		}
	}
	usedAudit := make([]bool, len(audit))
	var bound []evidencetools.AuditRecord
	tailStarted := false

	for i := range declared {
		a := &declared[i]
		trace.Requests = append(trace.Requests, VerificationRequest{
			ID: a.ID, Tool: a.AdapterID, Arguments: append(json.RawMessage(nil), a.Arguments...),
			Purpose: a.Purpose, ConditionID: a.ConditionID, DerivedFrom: actionProvenance(lane, a),
		})
		if !dispatched[i] {
			tailStarted = true
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf("verification action %q (tool %s) unexecuted: named contiguous tail begins here", a.ID, a.AdapterID))
			continue
		}
		if tailStarted {
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf("verification action %q (tool %s) executed after an unexecuted action: unexecuted requests are not a contiguous tail", a.ID, a.AdapterID))
		}
		match := -1
		for j := range audit {
			if usedAudit[j] || !toolMatchesAction(a, audit[j].Tool) || !equalJSON(a.Arguments, audit[j].Args) {
				continue
			}
			match = j
			break
		}
		if match < 0 {
			trace.Complete = false
			mismatch := "has no matching session audit record"
			for _, rec := range audit {
				if toolMatchesAction(a, rec.Tool) || equalJSON(a.Arguments, rec.Args) {
					mismatch = "has a session audit tool/argument mismatch"
					break
				}
			}
			trace.Limitations = append(trace.Limitations, fmt.Sprintf("verification action %q (tool %s) %s", a.ID, a.AdapterID, mismatch))
			trace.Observations = append(trace.Observations, flowAuditErrorObservation(a, mismatch))
			continue
		}
		usedAudit[match] = true
		rec := &audit[match]
		trace.Requests[len(trace.Requests)-1].Tool = rec.Tool
		bound = append(bound, *rec)
		if rec.Observation == nil {
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf("verification action %q (tool %s) audit record has no observation", a.ID, a.AdapterID))
			trace.Observations = append(trace.Observations, flowAuditErrorObservation(a, "session audit record has no observation"))
			continue
		}
		trace.Observations = append(trace.Observations, rec.Observation)
		if rec.Observation.ToolStatus != evidencetools.StatusOK || rec.Observation.Completeness != evidencetools.CompletenessComplete {
			trace.Complete = false
		}
	}
	for i := range audit {
		if usedAudit[i] {
			continue
		}
		trace.Complete = false
		trace.Limitations = append(trace.Limitations, fmt.Sprintf("session audit record for tool %q names no declared flow action — it cannot become a fact", audit[i].Tool))
	}
	seenObs := map[string]bool{}
	for _, o := range trace.Observations {
		if o == nil || o.ID == "" {
			continue
		}
		if seenObs[o.ID] {
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf("verification trace contains duplicate observation id %q", o.ID))
		}
		seenObs[o.ID] = true
	}
	if len(trace.Observations) != len(trace.Requests) {
		trace.Complete = false
	}
	return trace, bound
}

func sameFlowAction(a, b *flow.PlanAction) bool {
	return a != nil && b != nil && a.ID == b.ID && toolMatchesAction(a, b.AdapterID) && equalJSON(a.Arguments, b.Arguments)
}

func flowAuditErrorObservation(a *flow.PlanAction, reason string) *evidencetools.Observation {
	return &evidencetools.Observation{Tool: a.AdapterID, Fact: "tool call failed: " + reason, Scope: "check not performed", Completeness: evidencetools.CompletenessUnknown, ToolStatus: evidencetools.StatusError, Error: reason, ScopeDetails: &evidencetools.ScopeDetails{}}
}

// toolMatchesAction reports whether the audit-recorded session tool is
// what the action dispatched: the action's adapter id may equal the
// tool directly or name it through the catalog's id surface.
func toolMatchesAction(a *flow.PlanAction, tool string) bool {
	if a.AdapterID == tool {
		return true
	}
	// The checks catalog may carry hyphenated ids over underscored
	// session tool names; treat them as the same surface only when the
	// normalized form is identical.
	return strings.ReplaceAll(a.AdapterID, "-", "_") == tool
}

func equalJSON(a, b json.RawMessage) bool {
	va, vb := any(nil), any(nil)
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return string(a) == string(b)
	}
	ab, _ := json.Marshal(va)
	bb, _ := json.Marshal(vb)
	return string(ab) == string(bb)
}

// renumberFlowObservations moves flow-produced observation ids past
// the lane's OBS-#### sequence — in the run result (observations,
// steps, events, evidence is untouched) and in the drained audit
// records — so every persisted observation id is unique.
func renumberFlowObservations(res *flow.Result, audit []evidencetools.AuditRecord, lane *LaneResult) {
	maxSeq := 0
	for _, o := range lane.Observations {
		if n, err := strconv.Atoi(strings.TrimPrefix(o.ID, "OBS-")); err == nil && n > maxSeq {
			maxSeq = n
		}
	}
	idmap := map[string]string{}
	renum := func(id string) string {
		if id == "" {
			return ""
		}
		if nid, ok := idmap[id]; ok {
			return nid
		}
		maxSeq++
		nid := fmt.Sprintf("OBS-%04d", maxSeq)
		idmap[id] = nid
		return nid
	}
	for i := range res.Observations {
		res.Observations[i].ID = renum(res.Observations[i].ID)
	}
	for i := range res.Steps {
		for j := range res.Steps[i].Observations {
			res.Steps[i].Observations[j].ID = renum(res.Steps[i].Observations[j].ID)
		}
	}
	for i := range res.Events {
		if res.Events[i].Observation != nil {
			res.Events[i].Observation.ID = renum(res.Events[i].Observation.ID)
		}
	}
	for i := range audit {
		if audit[i].Observation != nil {
			audit[i].Observation.ID = renum(audit[i].Observation.ID)
		}
	}
}

// ---- persistence ----

func persistFlowResult(dir string, res *flow.Result) error {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, flowResultFile), append(b, '\n'), 0o644)
}

func persistFlowEvents(dir string, res *flow.Result) error {
	f, err := os.Create(filepath.Join(dir, flowEventsFile))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for i := range res.Events {
		if err := enc.Encode(&res.Events[i]); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// writeFlowObservationLedger persists the flow phase's session audit
// records — the same ledger name and record shape the verification
// phase uses, so binding semantics (bindPersistedObservations) hold
// unchanged.
func writeFlowObservationLedger(dir string, audit []evidencetools.AuditRecord) error {
	f, err := os.Create(filepath.Join(dir, flowObservationLedger))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for i := range audit {
		if err := enc.Encode(&audit[i]); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// persistFlowArtifacts writes each traced observation's canonical
// payload under verification-artifacts/ and returns the pins keyed by
// the renumbered observation id — the same convention the verification
// phase uses so evidence_quality.references resolves identically.
func persistFlowArtifacts(dir string, trace *VerificationTrace) (map[string]ArtifactRef, error) {
	pins := map[string]ArtifactRef{}
	if trace == nil || len(trace.Observations) == 0 {
		return pins, nil
	}
	artDir := filepath.Join(dir, flowObservationDir)
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		return nil, err
	}
	for _, o := range trace.Observations {
		if o == nil || o.ID == "" {
			continue
		}
		payload, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("flow artifact encode %s: %w", o.ID, err)
		}
		name := strings.ToLower(o.ID) + ".json"
		written := append(payload, '\n')
		if err := os.WriteFile(filepath.Join(artDir, name), written, 0o644); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(written)
		pins[o.ID] = ArtifactRef{
			Path:   filepath.Join(flowObservationDir, name),
			SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(written)),
			Selector: flowObservationSelector,
		}
	}
	return pins, nil
}

// persistDecisionArtifact writes the validated artifact; the artifact
// already passed BuildDecisionArtifact's self-validation.
func persistDecisionArtifact(dir string, a *DecisionArtifact) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, decisionArtifactFile), append(b, '\n'), 0o644)
}

// persistFlowFacts writes the flow-facts/1 bookkeeping document: what
// the run recorded (termination, completeness, per-request outcome and
// pins) — the on-disk mirror of the fact envelope inputs. It returns
// the artifact pin the run-manifest carries.
func persistFlowFacts(dir string, res *flow.Result, trace *VerificationTrace,
	facts []Fact, arts map[string]ArtifactRef) (ArtifactRef, error) {
	type checkRec struct {
		ID            string             `json:"id"`
		Tool          string             `json:"tool"`
		AdapterID     string             `json:"adapter_id,omitempty"`
		ObservationID string             `json:"observation_id,omitempty"`
		Status        string             `json:"status,omitempty"`
		Completeness  string             `json:"completeness,omitempty"`
		Artifact      string             `json:"artifact,omitempty"`
		DerivedFrom   *SubjectProvenance `json:"derived_from,omitempty"`
	}
	actionByID := map[string]string{}
	for i := range res.Actions {
		actionByID[res.Actions[i].ID] = res.Actions[i].AdapterID
	}
	checks := []checkRec{}
	if trace != nil {
		for i, req := range trace.Requests {
			c := checkRec{ID: req.ID, Tool: req.Tool, AdapterID: actionByID[req.ID], DerivedFrom: req.DerivedFrom}
			if i < len(trace.Observations) && trace.Observations[i] != nil {
				o := trace.Observations[i]
				c.ObservationID = o.ID
				c.Status = string(o.ToolStatus)
				c.Completeness = string(o.Completeness)
				if a, ok := arts[o.ID]; ok {
					c.Artifact = a.Path
				}
			}
			checks = append(checks, c)
		}
	}
	doc := map[string]any{
		"schema":              flowFactsSchema,
		"run_id":              res.RunID,
		"termination":         string(res.Termination),
		"reason":              res.Reason,
		"ready":               res.Ready,
		"complete":            res.Complete,
		"checks":              checks,
		"required_checks":     append([]string(nil), res.Policy.RequiredChecks...),
		"completed_checks":    append([]string(nil), res.CompletedChecks...),
		"inapplicable_checks": append([]string(nil), res.InapplicableChecks...),
		"conditions":          append([]string(nil), res.Conditions...),
		"fact_ids":            flowFactIDs(facts),
	}
	if len(res.Limitations) > 0 {
		doc["limitations"] = append([]string(nil), res.Limitations...)
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ArtifactRef{}, err
	}
	written := append(b, '\n')
	path := filepath.Join(dir, flowFactsFile)
	if err := os.WriteFile(path, written, 0o644); err != nil {
		return ArtifactRef{}, err
	}
	sum := sha256.Sum256(written)
	return ArtifactRef{Path: flowFactsFile, SHA256: hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(written)), Selector: "flow facts bookkeeping"}, nil
}

func flowFactIDs(facts []Fact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, f.ID)
	}
	return out
}

// r6Pins computes the replay/policy pins for the artifact: the flow
// rubric's prompt-set digest and the sha256 of every configuration
// file the run was gated by.
func r6Pins(fsys fs.FS, rubric FlowRubric) (ReplayAndPolicyPins, error) {
	// The artifact contract requires bare 64-hex digests and logical
	// catalog names ("conditions", "checks", "dispositions"); the two
	// rubric files pin under their own keys the same way.
	files := map[string]string{
		"conditions":      ConditionsCatalogPath,
		"checks":          ChecksCatalogPath,
		"dispositions":    DispositionsCatalogPath,
		"decision_policy": SafetyPolicyPath,
		"flow_rubric":     flowRubricPath,
	}
	digests := map[string]string{}
	for name, p := range files {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return ReplayAndPolicyPins{}, fmt.Errorf("config pin %s (%s): %w", name, p, err)
		}
		sum := sha256.Sum256(raw)
		digests[name] = hex.EncodeToString(sum[:])
	}
	return ReplayAndPolicyPins{
		PromptDigest:   strings.TrimPrefix(rubric.PromptDigest, "sha256:"),
		PolicyDigest:   digests["decision_policy"],
		CatalogDigests: digests,
	}, nil
}

// ---- replay comparison ----

// compareReplayedArtifact loads the persisted decision-artifact.json
// and verifies the rebuilt artifact reproduces the recorded outcome:
// same proposed disposition, same branch tuple set (id, status,
// disposition) and the same declared environment questions. Config or
// prompt pins are intentionally not compared — a changed configuration
// legitimately re-pins the rebuilt artifact.
func compareReplayedArtifact(rebuilt *DecisionArtifact, artifactPath string) error {
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("replay decision artifact %s: %w", artifactPath, err)
	}
	var rec DecisionArtifact
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("replay decision artifact %s does not decode: %w", artifactPath, err)
	}
	if rec.Schema != DecisionArtifactSchemaV1 {
		return fmt.Errorf("replay decision artifact schema %q != %q", rec.Schema, DecisionArtifactSchemaV1)
	}
	if rebuilt.ProposedDisposition != rec.ProposedDisposition {
		msg := fmt.Sprintf("replay artifact diverged: recorded disposition %s, rebuilt %s",
			rec.ProposedDisposition, rebuilt.ProposedDisposition)
		if isCloseDisposition(rec.ProposedDisposition) && !isCloseDisposition(rebuilt.ProposedDisposition) {
			msg += " — the recorded closure no longer passes current advisory-scope admission (policy drift): the replay is refused, never declared equivalent"
		}
		return fmt.Errorf("%s", msg)
	}
	type branchTuple struct{ id, status, disp string }
	tuples := func(a *DecisionArtifact) []branchTuple {
		var out []branchTuple
		for _, b := range a.Branches {
			out = append(out, branchTuple{b.ID, string(b.Status), string(b.ProposedDisposition)})
		}
		return out
	}
	rt, bt := tuples(&rec), tuples(rebuilt)
	if len(rt) != len(bt) {
		return fmt.Errorf("replay artifact diverged: recorded %d branches, rebuilt %d", len(rt), len(bt))
	}
	for i := range rt {
		if rt[i] != bt[i] {
			msg := fmt.Sprintf("replay artifact diverged at branch %s: recorded (%s,%s), rebuilt (%s,%s)",
				rt[i].id, rt[i].status, rt[i].disp, bt[i].status, bt[i].disp)
			if isCloseDisposition(ProposedDisposition(rt[i].disp)) && !isCloseDisposition(ProposedDisposition(bt[i].disp)) {
				msg += " — the recorded closure no longer passes current advisory-scope admission (policy drift): the replay is refused, never declared equivalent"
			}
			return fmt.Errorf("%s", msg)
		}
	}
	if !equalStringSet(rebuilt.HumanAction.EnvironmentQuestionRefs, rec.HumanAction.EnvironmentQuestionRefs) {
		return fmt.Errorf("replay artifact diverged: environment questions changed")
	}
	return nil
}

func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}
