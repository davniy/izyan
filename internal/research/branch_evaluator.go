package research

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
)

// AgentConditionProposal is the only thing an agent may ever contribute
// to branch construction: a reference to a catalog condition (never a
// new variable, value, rule or branch) plus the subjects it binds to.
// An unknown condition id is rejected — an agent can name what the
// catalog declares, nothing else.
type AgentConditionProposal struct {
	ConditionID  string   `json:"condition_id"`
	SubjectRefs  []string `json:"subject_refs"`
	Statement    string   `json:"statement"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// ArtifactInput is everything BuildDecisionArtifact reads. Facts are
// the promoted, audit-bound fact envelope (BuildDecisionFacts);
// RuleFacts are the evaluator-side view of the same facts
// (BuildRuleFacts) — the builder evaluates the registered rules itself
// so a caller-supplied RuleResult can never claim establishment the
// facts do not carry. Variables and Conditions are activation hints:
// they may reference registry/catalog entries but can never add a
// variable, value or condition. Pins bind the artifact to the exact
// policy and catalog bytes it was produced under.
type ArtifactInput struct {
	Lane        *LaneResult
	Facts       []Fact
	RuleFacts   []evaluator.RuleFact
	Conditions  []Condition
	Variables   []DecisionVariable
	RuleResults []evaluator.RuleResult
	Policy      SafetyPolicy
	Catalogs    *Catalogs
	Registry    *evaluator.AdapterRegistry
	Pins        ReplayAndPolicyPins
	// AgentProposals are catalog-condition references the agent
	// produced; each is admitted only when its id is a catalog
	// condition or a registered evaluator.
	AgentProposals []AgentConditionProposal
}

// closeRules are the registered rules whose ESTABLISHED result grounds
// a code-level closure: applicability closures bind module-level
// subjects and propose CLOSE_NOT_AFFECTED; product-closure, source-usage
// and complete config-origin provenance closures bind every declared
// subject and propose CLOSE_NO_EXPLOIT_PATH. Trusted infrastructure
// never appears here — declared trust is an environment premise. The
// predicate column is what the rule establishes per subject; a close
// is advisory-wide or it is not a close at all — rule evaluation always
// runs over the full declared subject set.
var closeRules = []struct {
	id        string
	predicate string
	moduleLvl bool
	disp      ProposedDisposition
}{
	{"rule.module-absent-from-graph", evaluator.PredicateModulePresent, true, DispositionCloseNotAffected},
	{"rule.version-out-of-range", evaluator.PredicateVersionInRange, true, DispositionCloseNotAffected},
	{"rule.build-not-relevant", evaluator.PredicateBuildRelevant, true, DispositionCloseNotAffected},
	{"rule.implementation-absent", evaluator.PredicateVulnerableImplementationPresent, true, DispositionCloseNotAffected},
	{"rule.subject-absent-from-product-closure", evaluator.PredicateProductClosureMembership, false, DispositionCloseNoExploitPath},
	{"rule.subject-not-used-by-product-source", evaluator.PredicateProductSourceUsage, false, DispositionCloseNoExploitPath},
	{"rule.declared-symbols-unreached", evaluator.PredicateDeclaredSymbolReachability, false, DispositionCloseNoExploitPath},
	{"rule.config-origin-sink-closure", evaluator.PredicateConfigOriginSinkInputs, false, DispositionCloseNoExploitPath},
}

// openRules are the positive-evidence counterparts: ESTABLISHED means
// the affected surface is demonstrably present, which only ever keeps
// the finding open — it can never close it.
var openRules = []string{
	"rule.subject-linked-into-product-closure",
	"rule.subject-used-by-product-source",
}

// Code-owned rule ids for justification edges that are not backed by a
// registered evaluator rule.
const ruleIDEnvironmentalMitigation = "r6.environmental-mitigation"

// BuildDecisionArtifact assembles the decision-artifact/1 document:
// identity/scope/binding pins from the lane, the promoted shared facts,
// the declared environment variables, the code-enumerated branch set,
// the justification edges backing any CLOSE_* proposal, and the
// human-action contract. It never invents variables, values or
// branches; anything it cannot ground fails closed into the explicit
// unknown branch. The artifact is self-validated before return — the
// builder never emits a contract-invalid document.
func BuildDecisionArtifact(ctx context.Context, in ArtifactInput) (DecisionArtifact, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if in.Lane == nil {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires the deterministic lane result")
	}
	if strings.TrimSpace(in.Lane.ContentHash) == "" {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires the lane's snapshot content hash")
	}
	if in.Lane.Advisory.Vuln == nil {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires the frozen advisory record")
	}
	if err := ValidateMonotonicPolicy(BaselineSafetyPolicy(), in.Policy); err != nil {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires a policy at least as strict as the baseline: %w", err)
	}
	reg := in.Registry
	if reg == nil {
		reg = evaluator.DefaultAdapterRegistry()
	}
	cats := in.Catalogs
	if cats == nil {
		cats = &Catalogs{}
	}

	a := DecisionArtifact{
		Schema: DecisionArtifactSchemaV1,
		FindingIdentity: FindingIdentity{
			ID:         "finding-" + in.Lane.Advisory.Vuln.ID,
			AdvisoryID: in.Lane.Advisory.Vuln.ID,
		},
		TargetScope: TargetScope{
			SnapshotContentHash: in.Lane.ContentHash,
			CommitSHA:           laneCommitSHA(in.Lane),
			Scope:               "recorded product snapshot",
		},
		AdvisoryBinding: AdvisoryBinding{
			AdvisoryID:     in.Lane.Advisory.Vuln.ID,
			AdvisoryDigest: in.Lane.Advisory.Input.CanonicalSHA256,
			SubjectRefs:    advisorySubjectIDs(in.Lane),
		},
		SharedFacts:         append([]Fact(nil), in.Facts...),
		ReplayAndPolicyPins: in.Pins,
	}
	if a.TargetScope.CommitSHA == "" {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires the recorded snapshot commit identity")
	}
	if !decisionHex64Re.MatchString(a.AdvisoryBinding.AdvisoryDigest) {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires the advisory digest pin")
	}
	if len(a.AdvisoryBinding.SubjectRefs) == 0 {
		return DecisionArtifact{}, fmt.Errorf("decision artifact requires at least one advisory-declared subject")
	}

	b := &branchBuilder{
		ctx:       ctx,
		in:        in,
		reg:       reg,
		cats:      cats,
		lane:      in.Lane,
		factByID:  map[string]*Fact{},
		ruleRes:   map[string]evaluator.RuleResult{},
		activated: map[string]bool{},
		subjects:  canonicalSubjects(in.Lane),
		modules:   moduleSubjects(in.Lane),
	}
	for i := range a.SharedFacts {
		b.factByID[a.SharedFacts[i].ID] = &a.SharedFacts[i]
	}
	b.admit()
	b.evaluate()
	b.assemble(&a)

	if err := ValidateDecisionArtifact(&a); err != nil {
		return DecisionArtifact{}, fmt.Errorf("decision artifact failed self-validation: %w", err)
	}
	return a, nil
}

// laneCommitSHA is the recorded snapshot identity: the local commit,
// else the externally supplied one.
func laneCommitSHA(lane *LaneResult) string {
	if lane.Snapshot.Commit != "" {
		return lane.Snapshot.Commit
	}
	return lane.Snapshot.ExternalCommitSHA
}

// advisorySubjectIDs returns canonical typed subject identities. Implementation
// ids are report labels, not symbol references, and cannot feed authority.
func advisorySubjectIDs(lane *LaneResult) []string {
	return dedupeStrings(canonicalSubjects(lane))
}

// canonicalSubjects are the subject names the evaluator binds: one per
// advisory-declared subject in the shared module/package/symbol
// grammar — never advisory-entry ids.
func canonicalSubjects(lane *LaneResult) []string {
	var out []string
	for _, sub := range declaredSubjects(lane) {
		out = append(out, subjectRefName(sub.Module, sub.Package, sub.Symbol))
	}
	return out
}

// moduleSubjects are the module-level subject names the applicability
// rules bind to.
func moduleSubjects(lane *LaneResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, sub := range declaredSubjects(lane) {
		if !seen[sub.Module] {
			seen[sub.Module] = true
			out = append(out, subjectRefName(sub.Module, "", ""))
		}
	}
	return out
}

// implemented reports whether a registered variable has phase-1 branch
// semantics; a registered-but-unimplemented variable surfaces
// NOT_DECISION_READY rather than a generic interpretation.
func (s variableSpec) implemented() bool {
	switch s.id {
	case variableDeploymentPerimeter, variableBuildVariant:
		return true
	}
	return false
}

// conditionSpec finds the catalog entry for a condition id.
func (c *Catalogs) conditionSpec(id string) (ConditionSpec, bool) {
	for i := range c.Conditions {
		if c.Conditions[i].ID == id {
			return c.Conditions[i], true
		}
	}
	return ConditionSpec{}, false
}

// catalogConditionRole is the catalog-declared role of a condition;
// unknown ids default to supporting — a weaker premise that can never
// ground a close.
func catalogConditionRole(cats *Catalogs, id string) string {
	if spec, ok := cats.conditionSpec(id); ok && spec.Role != "" {
		return spec.Role
	}
	return ConditionRoleSupporting
}

// branchBuilder carries the evaluation state for one artifact build.
type branchBuilder struct {
	ctx      context.Context
	in       ArtifactInput
	reg      *evaluator.AdapterRegistry
	cats     *Catalogs
	lane     *LaneResult
	factByID map[string]*Fact

	conditions []Condition
	activated  map[string]bool
	problems   []string

	// scopeLimited records advisory-scope refusals: a per-component close
	// rule may be established, but the resolved scope does not cover the
	// requested advisory, so the artifact carries no global close. These
	// land on the unknown branch as explanations; unlike problems they do
	// not by themselves cap an otherwise-open proposal.
	scopeLimited []string

	ruleRes          map[string]evaluator.RuleResult
	condResult       map[string]evaluator.RuleResult
	closeEstablished *closeResult
	contradictions   []Contradiction

	subjects []string
	modules  []string

	// advPrecond caches the advisory-declared environment precondition
	// the environment decision keys on when the derivation yields at
	// least one recorded statement (the first grounds the variable);
	// advPrecondChecked marks the
	// derivation as run so it never recomputes mid-build.
	advPrecond        *SubjectProvenance
	advPrecondChecked bool
}

// closeResult is one admitted closure: the authority-evaluated rule
// result, the predicate it established per subject, and the
// disposition the code table grants it.
type closeResult struct {
	res       evaluator.RuleResult
	predicate string
	disp      ProposedDisposition
}

// overlay records a fail-closed degradation: the artifact stays valid
// but the affected dimension is not decision-ready. Overlays land on
// the unknown branch's limitations and cap the artifact proposal at
// HOLD_UNKNOWN unless a code-grounded close stands.
func (b *branchBuilder) overlay(format string, args ...any) {
	b.problems = append(b.problems, fmt.Sprintf(format, args...))
}

// admit enforces the registry boundary on every caller- or
// agent-supplied condition and variable before anything is evaluated.
func (b *branchBuilder) admit() {
	for _, p := range b.in.AgentProposals {
		if _, ok := b.cats.conditionSpec(p.ConditionID); ok || b.reg.HasCondition(p.ConditionID) {
			b.conditions = append(b.conditions, Condition{
				ID:          p.ConditionID,
				Statement:   p.Statement,
				Role:        catalogConditionRole(b.cats, p.ConditionID),
				SubjectRefs: append([]string(nil), p.SubjectRefs...),
				Required:    true,
				Polarity:    PolarityPositive,
			})
			continue
		}
		b.overlay("agent proposal references unknown condition %q — proposals can only reference catalog conditions", p.ConditionID)
	}
	b.conditions = append(b.conditions, b.in.Conditions...)

	for _, v := range b.in.Variables {
		spec, ok := variableRegistry[v.ID]
		if !ok {
			b.overlay("declared variable %q is not in the code-owned registry — no caller may add variables", v.ID)
			continue
		}
		if !spec.implemented() {
			b.overlay("decision variable %q is registered but unimplemented in phase 1 — dependence on it fails closed", v.ID)
		}
	}
	for _, c := range b.conditions {
		vid := variableForCondition(c.ID)
		if vid == "" {
			continue
		}
		spec, ok := variableRegistry[vid]
		switch {
		case !ok:
			b.overlay("condition %q maps to an undeclared variable %q", c.ID, vid)
		case !spec.implemented():
			b.overlay("condition %q depends on unimplemented decision variable %q", c.ID, vid)
		default:
			b.activated[vid] = true
		}
	}
}

// evaluate runs the registered closure and open rules over the fact
// envelope, then decides each declared condition through its
// registered evaluator. Caller-supplied RuleResults are recorded as
// context only — the builder re-derives every outcome it relies on, so
// a forged establishment can never enter the artifact.
func (b *branchBuilder) evaluate() {
	b.condResult = map[string]evaluator.RuleResult{}
	for _, rr := range b.in.RuleResults {
		if !b.reg.HasRule(rr.RuleID) {
			b.overlay("caller-supplied rule result %q names no registered rule — precomputed outcomes are never authoritative", rr.RuleID)
		}
	}
	for _, rule := range closeRules {
		if !b.reg.HasRule(rule.id) {
			b.overlay("rule %q has no registered evaluator — a close can never ride an unregistered rule", rule.id)
		}
	}
	var close *closeResult
	scopeAllowsClose := advisoryScopeAllowsNegativeClosure(b.lane)
	// The declared-symbol close rests on deadness; it is admissible only
	// under the lane's admitted invocation-necessity premise. A caller-supplied
	// RuleFact set cannot bypass this: the rule is re-evaluated here and the
	// premise is checked independently of the facts.
	deadnessAdmitted := false
	if _, err := domain.RequireDeadnessPremise(b.lane.DefectSemantics, declaredSymbolRefs(b.lane)); err == nil {
		deadnessAdmitted = true
	}
	b.ruleRes, close = verifyArtifactClosure(b.ctx, b.reg, b.in.RuleFacts,
		factByIDOf(b.in.Facts), b.subjects, b.modules, scopeAllowsClose, deadnessAdmitted)
	if !scopeAllowsClose {
		// A per-component rule may still establish — the local facts are
		// recorded evidence — but the resolved scope never lets that local
		// fact become an advisory-wide close. The unknown branch carries
		// the explanation and the local rule refs.
		b.scopeLimited = append(b.scopeLimited, b.scopedCloseRefusal())
	}
	for _, rule := range closeRules {
		res := b.ruleRes[rule.id]
		if len(res.Contradictions) > 0 {
			b.addContradiction(ContradictionEvidenceConflict, rule.id, res.Contradictions,
				"rule %s is contradicted by verified facts", rule.id)
		}
	}
	b.closeEstablished = close

	for _, ruleID := range openRules {
		res, err := b.reg.EvaluateRule(b.ctx, ruleID, evaluator.RuleContext{
			Facts:      b.in.RuleFacts,
			Conditions: subjectsAsConditions(b.subjects),
		})
		if err != nil {
			continue
		}
		b.ruleRes[ruleID] = trustCheckResult(res, b.factByID)
	}
	for _, c := range b.conditions {
		if !b.reg.HasCondition(c.ID) {
			continue
		}
		subjects := c.SubjectRefs
		if len(subjects) == 0 {
			subjects = b.subjects
		}
		res, err := b.reg.EvaluateCondition(b.ctx, evaluator.ConditionInput{
			ID:          c.ID,
			Statement:   c.Statement,
			Role:        c.Role,
			Polarity:    c.Polarity,
			Required:    c.Required,
			SubjectRefs: subjects,
		}, b.in.RuleFacts)
		if err != nil {
			continue
		}
		b.condResult[c.ID] = trustCheckResult(res, b.factByID)
	}
}

// verifyArtifactClosure is the single authority that decides whether a
// code-grounded CLOSE_* may exist on a decision artifact. It evaluates
// every registered close rule over the FULL declared subject set —
// canonical subjects for exploit-path closures, module subjects for
// applicability closures — never a self-selected subset. The gates it
// enforces mirror the decision gates the legacy route's VerifyDecision
// applies to terminal negatives:
//
//   - advisory-wide subject coverage: every declared subject must be
//     covered by a verified, digest-bound, COMPLETE premise fact
//     recording the establishing value (decidePredicate pass 2); a
//     narrowed or partial subject set can never close;
//   - contradiction blocks: a verified fact recording a contradicting
//     value for any declared subject vetoes the rule for the advisory
//     as a whole (decidePredicate pass 1);
//   - fail-closed premise binding: an ESTABLISHED result with zero
//     premise fact refs, or refs absent/non-VERIFIED in the shared
//     envelope, is a defect — it is downgraded to UNKNOWN, never a
//     close (trustCheckResult);
//   - positive-contradiction veto for CLOSE_NO_EXPLOIT_PATH: any
//     verified positive product-linkage or product-source-usage fact
//     bound to a declared subject (directly or, for module-level
//     subjects, a package/symbol inside that module) blocks every
//     exploit-path close — the same positive-use block VerifyDecision
//     applies;
//   - empty operational limitations: an admitted close carries no
//     limitations;
//   - advisory-scope admissibility: only a resolved scope that covers the
//     requested advisory identity may select a global close. Under a
//     partial scope a local rule establishment and its fact refs stay
//     recorded in the result map, but no closeResult is selected.
//
// The artifact builder and the /2-compatible decision projection both
// consult this function and nothing else; a branch, justification or
// verdict the authority did not yield is never a close.
func verifyArtifactClosure(ctx context.Context, reg *evaluator.AdapterRegistry,
	ruleFacts []evaluator.RuleFact, factByID map[string]*Fact,
	subjects, modules []string, scopeAllowsClose, deadnessAdmitted bool) (map[string]evaluator.RuleResult, *closeResult) {
	results := map[string]evaluator.RuleResult{}
	var close *closeResult
	for _, rule := range closeRules {
		subs := subjects
		if rule.moduleLvl {
			subs = modules
		}
		res, err := reg.EvaluateRule(ctx, rule.id, evaluator.RuleContext{
			Facts: ruleFacts, Conditions: subjectsAsConditions(subs),
		})
		if err != nil {
			res = evaluator.RuleResult{RuleID: rule.id, Status: evaluator.RuleUnknown,
				Limitations: []string{"rule has no registered evaluator: " + err.Error()}}
		}
		res = trustCheckResult(res, factByID)
		if res.Status == evaluator.RuleEstablished &&
			rule.disp == DispositionCloseNoExploitPath &&
			positiveRuleFact(ruleFacts, subjects) {
			// A verified product linkage or product-source use of any
			// declared subject blocks every exploit-path closure
			// regardless of which rule carried it.
			res.Status = evaluator.RuleContradicted
			res.FactRefs = nil
			res.Contradictions = append(res.Contradictions,
				rule.id+": verified positive product-linkage/usage fact for a declared subject blocks "+string(rule.disp))
		}
		if rule.id == "rule.declared-symbols-unreached" && !deadnessAdmitted {
			// Deadness of the advisory-declared symbols is not a negative
			// unless the admitted semantics say their invocation is
			// necessary. Genuine-omission contracts bind the omission site,
			// and a lane without a contract admits nothing.
			res.Status = evaluator.RuleUnknown
			res.FactRefs = nil
			res.Limitations = append(res.Limitations,
				"rule.declared-symbols-unreached requires an admitted invocation-necessity premise; the lane carries none, so symbol deadness is not a negative")
		}
		results[rule.id] = res
		// The per-component result is recorded either way: a local
		// establishment and its fact refs stay visible evidence. Only the
		// advisory-wide close is gated on the resolved advisory scope.
		if !scopeAllowsClose {
			continue
		}
		if res.Status == evaluator.RuleEstablished && close == nil {
			r := res
			close = &closeResult{res: r, predicate: rule.predicate, disp: rule.disp}
		}
	}
	return results, close
}

// scopedCloseRefusal renders why the artifact carries no closure under a
// partial advisory scope: the local rule establishments and their fact
// refs are named so the recorded evidence stays visible, while the
// refusal itself names the uncovered requested scope.
func (b *branchBuilder) scopedCloseRefusal() string {
	var local []string
	for _, rule := range closeRules {
		res := b.ruleRes[rule.id]
		if res.Status != evaluator.RuleEstablished || len(res.FactRefs) == 0 {
			continue
		}
		local = append(local, fmt.Sprintf("%s (%s) remains established for the recorded components by %s",
			rule.id, rule.predicate, strings.Join(res.FactRefs, ", ")))
	}
	msg := scopedApplicabilityGap(b.lane)
	if len(local) == 0 {
		return msg + "; no global close can be proposed"
	}
	return msg + "; " + strings.Join(local, "; ") + " — a local fact never grounds a global close"
}

// positiveRuleFact reports whether the promoted fact envelope carries a
// verified positive product-linkage or product-source-usage fact bound
// to one of the declared subjects — the fact-envelope counterpart of
// VerifyDecision's hasPositiveUse gate. For a module-level subject a
// package- or symbol-bound fact inside that module counts as bound.
func positiveRuleFact(facts []evaluator.RuleFact, subjects []string) bool {
	for _, f := range facts {
		if f.Status != "VERIFIED" || f.Digest == "" {
			continue
		}
		positive := false
		switch f.Predicate {
		case evaluator.PredicateProductClosureMembership:
			positive = f.Value == "linked"
		case evaluator.PredicateProductSourceUsage:
			positive = f.Value == "used" || f.Value == "positive-lowerbound"
		}
		if !positive {
			continue
		}
		for _, s := range subjects {
			if f.Subject == s {
				return true
			}
			if strings.HasPrefix(s, "module:") {
				module := strings.TrimPrefix(s, "module:")
				if strings.HasPrefix(f.Subject, "package:"+module+"|") || strings.HasPrefix(f.Subject, "symbol:"+module+"|") {
					return true
				}
			}
		}
	}
	return false
}

// trustCheckResult downgrades any caller- or evaluator-side result that
// cites facts absent from the promoted envelope or not VERIFIED — an
// establishment resting on facts the artifact does not carry can never
// premise a close. An ESTABLISHED result carrying no premise facts is
// an establishment defect: a close branch without verified, digest-bound
// premises is a bare assertion and must fail closed, never default to
// success.
func trustCheckResult(res evaluator.RuleResult, factByID map[string]*Fact) evaluator.RuleResult {
	if res.Status != evaluator.RuleEstablished {
		return res
	}
	if len(res.FactRefs) == 0 {
		res.Status = evaluator.RuleUnknown
		res.Limitations = append(res.Limitations,
			"rule "+res.RuleID+" reported ESTABLISHED with no premise facts — a close requires at least one verified, digest-bound fact")
		return res
	}
	for _, fr := range res.FactRefs {
		f := factByID[fr]
		if f == nil || f.Status != FactStatusVerified {
			res.Status = evaluator.RuleUnknown
			res.Limitations = append(res.Limitations,
				"result cites fact "+fr+" that is absent or not VERIFIED in the shared envelope")
			res.FactRefs = nil
			return res
		}
	}
	return res
}

// factByIDOf indexes the shared fact envelope by id.
func factByIDOf(facts []Fact) map[string]*Fact {
	out := make(map[string]*Fact, len(facts))
	for i := range facts {
		out[facts[i].ID] = &facts[i]
	}
	return out
}

// assemble walks the evaluated state into artifact branches, variables,
// justifications, contradictions and the human-action contract.
func (b *branchBuilder) assemble(a *DecisionArtifact) {
	var branches []DecisionBranch
	var justs []Justification
	jn := 0
	newJust := func() *Justification {
		jn++
		justs = append(justs, Justification{ID: fmt.Sprintf("J-%d", jn)})
		return &justs[len(justs)-1]
	}

	fixed := map[string]string{variableBuildVariant: buildVariantValue(b.lane.Snapshot)}
	var questions []string

	// ---- unconditional code-grounded close branch ----
	if b.closeEstablished != nil {
		res := b.closeEstablished.res
		disp := b.closeEstablished.disp
		conds := b.conditionsForClose(res.RuleID)
		branches = append(branches, DecisionBranch{
			ID:                  "B-" + sanitizeBranchToken(strings.TrimPrefix(res.RuleID, "rule.")),
			Assignments:         fixed,
			Conditions:          conds,
			FactRefs:            append([]string(nil), res.FactRefs...),
			Coverage:            FactCoverageComplete,
			Status:              BranchComplete,
			ProposedDisposition: disp,
		})
		j := newJust()
		j.RuleID = res.RuleID
		j.PremiseFactRefs = append([]string(nil), res.FactRefs...)
		j.ConditionRefs = conditionIDs(conds)
		j.CoverageBasis = "complete deterministic evaluation of " + res.RuleID + " (" + b.closeEstablished.predicate + ") over every advisory-declared subject"
		j.Disposition = disp
		j.Statement = closeJustificationStatement(res.RuleID, b.closeEstablished.predicate, res.FactRefs, b.in.Facts)
	}

	// ---- declared variables + environment branches ----
	// The environment dimension opens only when no code-grounded close
	// already decides the finding: every declared value of the
	// environment key (the advisory-declared precondition when the
	// advisory's text states at least one, else the perimeter) gets its
	// own branch, and the non-recorded build variant is the fixed
	// non-transferable bound.
	if b.closeEstablished == nil {
		vars := b.declareVariables()
		a.DecisionVariables = vars
		questions = b.environmentBranches(&branches, newJust, fixed)
	} else if v, ok := decisionVariableDecl(variableBuildVariant, b.lane, b.cats); ok {
		a.DecisionVariables = []DecisionVariable{v}
	}

	// ---- explicit unknown branch (always) ----
	unknown := DecisionBranch{
		ID:                  "B-UNKNOWN",
		Assignments:         fixed,
		Coverage:            FactCoverageNotEvaluated,
		Status:              BranchNotDecisionReady,
		ProposedDisposition: DispositionHoldUnknown,
	}
	for _, p := range b.problems {
		unknown.Limitations = append(unknown.Limitations, p)
	}
	for _, ruleID := range sortedRuleIDs(b.ruleRes) {
		for _, lim := range b.ruleRes[ruleID].Limitations {
			unknown.Limitations = append(unknown.Limitations, ruleID+": "+lim)
		}
	}
	unknown.Limitations = append(unknown.Limitations, b.scopeLimited...)
	unknown.Limitations = dedupeStrings(unknown.Limitations)
	if len(unknown.Limitations) == 0 {
		unknown.Limitations = []string{"no conditional branch decides the finding for postures outside the declared enumeration"}
	}
	branches = append(branches, unknown)

	a.Branches = branches
	a.JustificationGraph = justs
	a.Contradictions = b.contradictions
	a.HumanAction = HumanAction{
		Mode:             HumanActionAcceptReject,
		AllowedResponses: []string{HumanResponseAccept, HumanResponseReject},
	}
	a.HumanAction.EnvironmentQuestionRefs = dedupeStrings(questions)
	if len(a.HumanAction.EnvironmentQuestionRefs) > 0 {
		a.HumanAction.Mode = HumanActionAnswerThenAcceptReject
	}
	if len(a.HumanAction.EnvironmentQuestionRefs) > MaxEnvironmentQuestions {
		b.overlay("the environment dimension needs more than two questions — the artifact is NOT_DECISION_READY")
		a.HumanAction.EnvironmentQuestionRefs = nil
		a.HumanAction.Mode = HumanActionAcceptReject
	}
	// Derived environment questions elaborate the declared ask with the
	// recorded, case-specific statement the environment must confirm;
	// when the dimension is closed or nothing recorded grounds a
	// question the member stays omitted and the artifact keeps its
	// legacy shape.
	a.HumanAction.EnvironmentQuestions =
		artifactEnvQuestions(b, a.HumanAction.EnvironmentQuestionRefs)
	a.HumanAction.MandatoryFactRefs = b.mandatoryFacts(branches)
	a.ProposedDisposition = b.artifactDisposition(branches)
	a.ProposedDisposition = b.artifactDisposition(branches)
}

// closeJustificationStatement names only the facts actually cited by the
// authority. It intentionally does not claim advisory-wide closure from a
// template: the authority has already checked subject coverage, while this
// text exposes the concrete recorded propositions that carried the result.
func closeJustificationStatement(ruleID, predicate string, refs []string, facts []Fact) string {
	byID := make(map[string]Fact, len(facts))
	for _, f := range facts {
		byID[f.ID] = f
	}
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		if f, ok := byID[ref]; ok && f.Proposition != "" {
			parts = append(parts, ref+": "+f.Proposition)
		}
	}
	if len(parts) == 0 {
		return "rule " + ruleID + " (" + predicate + ") has no cited fact text; closure is not established"
	}
	return "rule " + ruleID + " (" + predicate + ") is established by the cited recorded facts: " + strings.Join(parts, "; ")
}

// declareVariables resolves the decision variables the artifact may
// declare: the derived build-variant bound, then the environment key —
// the advisory-declared precondition when the frozen advisory text
// states at least one (the first recorded statement grounds it), else
// the catalog-owned perimeter. A required variable whose answer set is
// missing fails closed via overlay rather than an invented enumeration.
func (b *branchBuilder) declareVariables() []DecisionVariable {
	var out []DecisionVariable
	if v, ok := decisionVariableDecl(variableBuildVariant, b.lane, b.cats); ok {
		out = append(out, v)
	}
	if adv := b.advisoryPrecondition(); adv != nil {
		// The environment key is the advisory's own declared
		// precondition: its question quotes the recorded statement
		// verbatim and asks whether it holds in the deployed
		// environment; the quote carries its derived_from provenance.
		out = append(out, DecisionVariable{
			ID:            variableAdvisoryPrecondition,
			Question:      fmt.Sprintf("the advisory declares %q — does this exploitation precondition hold for the deployed environment, and is the named input/configuration attacker-influenced or operator-controlled?", adv.Quote),
			AllowedValues: append([]string(nil), advisoryPreconditionValues...),
			Required:      true,
			DerivedFrom:   adv,
		})
	} else if v, ok := decisionVariableDecl(variableDeploymentPerimeter, b.lane, b.cats); ok {
		out = append(out, v)
	} else {
		b.overlay("decision variable %q has no declared allowed_values in the catalog — the environment dimension cannot be enumerated", variableDeploymentPerimeter)
	}
	var activated []string
	for id := range b.activated {
		if id != variableBuildVariant && id != variableDeploymentPerimeter {
			activated = append(activated, id)
		}
	}
	sort.Strings(activated)
	for _, id := range activated {
		b.overlay("decision variable %q is registered but unimplemented in phase 1 — the branch set fails closed", id)
	}
	return out
}

// environmentBranches enumerates the environment answer set — one
// branch per declared value. The dimension is the advisory's own
// declared precondition when the derivation yields at least one
// recorded statement (the first grounds the variable), else the
// catalog-owned perimeter. Trusted-class
// values carry only the contextual mitigation disposition,
// untrusted-class values keep the finding open, and declared values
// with no registered class semantics stay NOT_DECISION_READY. Recorded
// deployment evidence binds the matching perimeter branch and refutes
// every other enumerated branch; the perimeter question is returned
// only while the recorded context leaves the dimension open.
func (b *branchBuilder) environmentBranches(branches *[]DecisionBranch, newJust func() *Justification, fixed map[string]string) []string {
	if b.advisoryPrecondition() != nil {
		return b.advisoryConditionBranches(branches, newJust, fixed)
	}
	vals := decisionVariableValues(variableDeploymentPerimeter, b.lane, b.cats)
	if len(vals) == 0 {
		return nil
	}
	recorded := recordedPerimeter(b.lane)
	envConds := b.envConditions()

	for _, v := range vals {
		assign := mergeAssignments(fixed, map[string]string{variableDeploymentPerimeter: v})
		br := DecisionBranch{
			ID:          "B-PERIMETER-" + sanitizeBranchToken(v),
			Assignments: assign,
			Conditions:  envConds,
		}
		switch classifyPerimeter(v) {
		case classTrusted:
			// The only disposition a declared-trust premise may carry:
			// a contextual mitigation — never a code-level close.
			br.Coverage = FactCoverageComplete
			br.Status = BranchComplete
			br.ProposedDisposition = DispositionAcceptEnvironmentalMitigation
			br.Limitations = []string{
				"rests on the recorded or declared trusted-perimeter premise — a contextual mitigation, never a code-level negative",
			}
		case classUnmapped:
			br.Coverage = FactCoverageNotEvaluated
			br.Status = BranchNotDecisionReady
			br.ProposedDisposition = DispositionHoldUnknown
			br.Limitations = []string{
				"perimeter value " + v + " has no registered branch semantics — it is never interpreted generically",
			}
		default:
			br.Coverage = FactCoverageComplete
			br.Status = BranchComplete
			br.ProposedDisposition = DispositionKeepOpenForRemediation
			br.Limitations = []string{
				"under this perimeter the affected surface is openly reachable; the finding stays open for remediation",
			}
		}
		switch {
		case recorded.value != "" && recorded.value != v && br.Status == BranchComplete:
			br.Status = BranchContradicted
			br.ProposedDisposition = DispositionHoldUnknown
			br.Limitations = append([]string{
				"recorded deployment evidence reports perimeter " + recorded.value + " (" + recorded.source + "), contradicting this branch's premise",
			}, br.Limitations...)
			b.addContradiction(ContradictionEnvironmentVsMachine, variableDeploymentPerimeter,
				nil, "recorded perimeter %q (%s) conflicts with enumerated branch value %q",
				recorded.value, recorded.source, v)
		case recorded.value == v && recorded.premise != nil:
			// The recorded premise binds the matching branch — the audit
			// trail of why this conditional already holds.
			br.EnvironmentAssertions = []EnvironmentAssertion{*recorded.premise}
		}
		*branches = append(*branches, br)
	}

	j := newJust()
	j.RuleID = ruleIDEnvironmentalMitigation
	j.ConditionRefs = conditionIDs(envConds)
	j.CoverageBasis = "recorded or declared deployment premise over the advisory-declared subjects"
	j.Disposition = DispositionAcceptEnvironmentalMitigation
	j.Statement = "a trusted-perimeter premise produces only the contextual mitigation disposition; declared trust never grounds a code-level close"

	// The non-recorded build variant is the fixed bound: the recorded
	// evidence never transfers to it.
	*branches = append(*branches, buildVariantOtherBranch())

	// The question is asked only while the recorded evidence leaves the
	// dimension open: a recorded premise already completes the matching
	// branch and refutes the others, so no answer is needed.
	if recorded.value == "" {
		return []string{variableDeploymentPerimeter}
	}
	return nil
}

// buildVariantOtherBranch is the fixed non-transferable bound every
// environment dimension shares: evidence recorded for the built
// variant never covers an artifact built differently.
func buildVariantOtherBranch() DecisionBranch {
	return DecisionBranch{
		ID:                  "B-BUILD-VARIANT-OTHER",
		Assignments:         map[string]string{variableBuildVariant: buildVariantOther},
		Coverage:            FactCoverageNotEvaluated,
		Status:              BranchNotDecisionReady,
		ProposedDisposition: DispositionHoldUnknown,
		Limitations:         []string{"the recorded evidence binds the recorded build variant only; a differently built artifact is outside its scope"},
	}
}

// advisoryConditionBranches enumerates the three-valued answer set of
// the advisory-declared precondition — the environment key replacing
// the generic perimeter dimension whenever the advisory's frozen text
// states at least one deployment/config-shaped condition (the first
// recorded statement grounds the variable). The branches
// premise on the recorded statement itself (verbatim, as the branch
// condition): does_not_hold carries the contract's conditional
// mitigation disposition (a COMPLETE branch, never a code-level
// close), holds keeps the finding open for remediation, and an
// unknown answer fails closed. The question is always asked — no
// recorded premise ever discharges an advisory-declared precondition.
func (b *branchBuilder) advisoryConditionBranches(branches *[]DecisionBranch, newJust func() *Justification, fixed map[string]string) []string {
	adv := b.advisoryPrecondition()
	if adv == nil {
		// Unreachable today — the only caller gates on the derivation —
		// but a caller that skipped it must fail closed, never deref.
		b.overlay("advisory-condition branches requested with no derived advisory precondition — the environment dimension fails closed")
		return nil
	}
	cond := Condition{
		ID:          "advisory-precondition",
		Statement:   adv.Quote,
		Role:        ConditionRoleDeployment,
		SubjectRefs: advisorySubjectIDs(b.lane),
		Required:    true,
		Polarity:    PolarityPositive,
	}
	for _, v := range advisoryPreconditionValues {
		br := DecisionBranch{
			ID:          "B-ADVISORY-PRECONDITION-" + sanitizeBranchToken(v),
			Assignments: mergeAssignments(fixed, map[string]string{variableAdvisoryPrecondition: v}),
			Conditions:  []Condition{cond},
		}
		switch v {
		case advisoryConditionNotHolds:
			// The recorded precondition does not hold in the deployed
			// environment: the only disposition an environment answer
			// may carry is the contextual mitigation — never a
			// code-level negative.
			br.Coverage = FactCoverageComplete
			br.Status = BranchComplete
			br.ProposedDisposition = DispositionAcceptEnvironmentalMitigation
			br.Limitations = []string{
				"rests on the operator's answer that the advisory-declared precondition does not hold in the deployed environment — a contextual mitigation, never a code-level negative",
			}
		case advisoryConditionHolds:
			br.Coverage = FactCoverageComplete
			br.Status = BranchComplete
			br.ProposedDisposition = DispositionKeepOpenForRemediation
			br.Limitations = []string{
				"the advisory-declared precondition holds: the named input/configuration is attacker-influenced; the finding stays open for remediation",
			}
		default:
			br.Coverage = FactCoverageNotEvaluated
			br.Status = BranchNotDecisionReady
			br.ProposedDisposition = DispositionHoldUnknown
			br.Limitations = []string{
				"the advisory-declared precondition cannot be established for the deployed environment — the artifact fails closed",
			}
		}
		*branches = append(*branches, br)
	}

	j := newJust()
	j.RuleID = ruleIDEnvironmentalMitigation
	j.ConditionRefs = conditionIDs([]Condition{cond})
	j.CoverageBasis = "the operator-confirmed state of the advisory-declared exploitation precondition over the advisory-declared subjects"
	j.Disposition = DispositionAcceptEnvironmentalMitigation
	j.Statement = "an advisory-declared precondition confirmed absent produces only the contextual mitigation disposition; an environment answer never grounds a code-level close"

	// The non-recorded build variant is the fixed bound: the recorded
	// evidence never transfers to it.
	*branches = append(*branches, buildVariantOtherBranch())

	return []string{variableAdvisoryPrecondition}
}

// envConditions instantiates the catalog deployment conditions the
// environment branches premise on.
func (b *branchBuilder) envConditions() []Condition {
	spec, ok := b.cats.conditionSpec("deployment-perimeter")
	stmt := spec.Description
	if !ok || stmt == "" {
		stmt = "the declared deployment perimeter posture"
	}
	role := spec.Role
	if role == "" {
		role = ConditionRoleDeployment
	}
	return []Condition{{
		ID:          "deployment-perimeter",
		Statement:   stmt,
		Role:        role,
		SubjectRefs: advisorySubjectIDs(b.lane),
		Required:    true,
		Polarity:    PolarityPositive,
	}}
}

// conditionsForClose selects the caller- and agent-declared conditions
// a close branch premises on: applicability conditions for
// applicability closures, path conditions for exploit-path closures.
// Conditions whose evaluation was contradicted are never premises.
func (b *branchBuilder) conditionsForClose(ruleID string) []Condition {
	var out []Condition
	applicability := strings.HasPrefix(ruleID, "rule.module") ||
		ruleID == "rule.version-out-of-range" || ruleID == "rule.build-not-relevant" ||
		ruleID == "rule.implementation-absent"
	for _, c := range b.conditions {
		if res, ok := b.condResult[c.ID]; ok && res.Status == evaluator.RuleContradicted {
			continue
		}
		switch {
		case applicability && c.Role == ConditionRoleApplicability:
			out = append(out, c)
		case !applicability && c.Role == ConditionRolePath:
			out = append(out, c)
		}
	}
	return out
}

// artifactDisposition selects the artifact-level proposal: a complete
// code-grounded close wins; then a conditional branch only when it
// already carries a premise — a recorded or operator assertion —
// because an unanswered conditional can never pre-select a
// disposition. Fail-closed overlays cap the proposal at HOLD_UNKNOWN
// unless the close stands.
func (b *branchBuilder) artifactDisposition(branches []DecisionBranch) ProposedDisposition {
	for _, br := range branches {
		if br.Status == BranchComplete && isCloseDisposition(br.ProposedDisposition) {
			return br.ProposedDisposition
		}
	}
	if len(b.problems) > 0 {
		return DispositionHoldUnknown
	}
	for _, br := range branches {
		if br.Status == BranchComplete && len(br.EnvironmentAssertions) > 0 &&
			br.ProposedDisposition == DispositionAcceptEnvironmentalMitigation {
			return DispositionAcceptEnvironmentalMitigation
		}
	}
	for _, br := range branches {
		if br.Status == BranchComplete && len(br.EnvironmentAssertions) > 0 &&
			br.ProposedDisposition == DispositionKeepOpenForRemediation {
			return DispositionKeepOpenForRemediation
		}
	}
	return DispositionHoldUnknown
}

// mandatoryFacts names the first-screen premise facts: the cited
// premises of the proposed branches in deterministic order.
func (b *branchBuilder) mandatoryFacts(branches []DecisionBranch) []string {
	var out []string
	seen := map[string]bool{}
	for _, br := range branches {
		for _, fr := range br.FactRefs {
			if f := b.factByID[fr]; f != nil && !seen[fr] {
				seen[fr] = true
				out = append(out, fr)
			}
		}
	}
	sort.Strings(out)
	if len(out) > MaxMandatoryFacts {
		b.overlay("the mandatory premise set exceeds the seven-fact bound — the artifact is NOT_DECISION_READY")
		out = out[:MaxMandatoryFacts]
	}
	return out
}

// addContradiction appends a contradiction record to the artifact.
func (b *branchBuilder) addContradiction(kind, subject string, refs []string, format string, args ...any) {
	b.contradictions = append(b.contradictions, Contradiction{
		ID:                fmt.Sprintf("CT-%d", len(b.contradictions)+1),
		Kind:              kind,
		Subject:           subject,
		Summary:           fmt.Sprintf(format, args...),
		Resolution:        ResolutionUnresolved,
		DeterministicRefs: refs,
	})
}

// mergeAssignments returns the union of two assignment maps — branch
// construction is the only place assignments are written, and each
// branch carries only its own.
func mergeAssignments(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// conditionIDs projects branch conditions to their ids.
func conditionIDs(cs []Condition) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

// sanitizeBranchToken renders a value as a stable uppercase branch-id
// token.
func sanitizeBranchToken(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out.WriteRune(r)
		default:
			out.WriteRune('-')
		}
	}
	return out.String()
}

// sortedRuleIDs returns rule ids in deterministic order.
func sortedRuleIDs(m map[string]evaluator.RuleResult) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dedupeStrings returns the input without duplicates, order preserved.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// subjectsAsConditions adapts a subject list into the RuleContext
// carrier the registry reads subjects from.
func subjectsAsConditions(subjects []string) []evaluator.ConditionInput {
	out := make([]evaluator.ConditionInput, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, evaluator.ConditionInput{SubjectRefs: []string{s}})
	}
	return out
}
