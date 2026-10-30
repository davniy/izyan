package evaluator

import (
	"context"
	"fmt"
)

// Generic rule/condition adapters for the R6 decision lane
// (Amendment R6 build step 2). They evaluate propositions purely over
// promoted facts: an adapter never sees an observation, an audit
// ledger, a report or a claim — only the fact envelope the research
// lane produced. This file deliberately does not import
// internal/research or internal/evidencetools: adapters are generic
// machinery and new behavior arrives by registering new condition/rule
// specs, never by editing code branches.

// RuleFact is the evaluation-side view of one R6 Fact: identity (ID —
// always the promoting fact's id), the canonical subject name it is
// bound to (module:<m>, package:<m>|<p>, symbol:<m>|<p>.<s> —
// granularity is part of identity and never inferred), the typed
// Predicate/Value the recorded outcome classifies into, and the
// fact's Status, Coverage and Digest. Status/Coverage reuse the
// decision-artifact vocabulary (VERIFIED/DEGRADED/CONTRADICTED and
// COMPLETE/PARTIAL/NOT_EVALUATED); the string type keeps this package
// free of research imports.
type RuleFact struct {
	ID         string
	Subject    string
	Kind       string
	Predicate  string
	Value      string
	Scope      string
	Status     string
	Coverage   string
	Digest     string
	TrustClass string
}

// RuleFact Predicate/Kind values the research mapper emits. They are
// generic outcome classes — never CVE- or package-specific.
const (
	// PredicateModulePresent records whether the named module resolved
	// in the product's dependency graph: Value "true" | "false" |
	// "unknown" (unresolved/pending version data is never "false").
	PredicateModulePresent = "module-present"
	// PredicateVersionInRange records whether the module's resolved
	// version falls inside an advisory-declared affected range for the
	// modules the resolver selected: Value "true" | "false" | "unknown".
	PredicateVersionInRange = "version-in-range"
	// PredicateBuildRelevant records whether the snapshot's recorded
	// build context intersects the advisory's declared build scope for
	// the selected module: Value "true" | "false" | "unknown".
	PredicateBuildRelevant = "build-relevant"
	// PredicateProductClosureMembership is the build-closure class of
	// the bound subject: Value "linked" (product or mixed closure
	// membership), "absent-verified" (absence from the product closure
	// under a verified closed derivation), or "unclassified" — a
	// recorded class that carries no verified product absence.
	PredicateProductClosureMembership = "product-closure-membership"
	// PredicateProductSourceUsage is the bounded product-source usage
	// verdict for the bound subject: Value "used", "not-used-verified",
	// "positive-lowerbound" (a concrete positive inside an open scope),
	PredicateProductSourceUsage     = "product-source-usage"
	PredicateConfigOriginSinkInputs = "config-origin-sink-inputs"
	// PredicateDeclaredSymbolReachability records the bounded proof result
	// for each exact advisory-declared symbol.
	PredicateDeclaredSymbolReachability = "declared-symbol-reachability"
	// PredicateVulnerableImplementationPresent records the affected
	// chain's implementation-presence dimension for the bound module:
	// Value "true" (a selected implementation carries the vulnerable
	// marker), "false" (the admitted locus was deterministically verified
	// absent under the product target scope) or "unknown". It is
	// independent of build-relevant, which keeps its advisory/package
	// platform-restriction meaning.
	PredicateVulnerableImplementationPresent = "vulnerable-implementation-present"

	// PredicateRecorded names the generic class every promoted fact carries.
	PredicateRecorded = "recorded"
)

// RuleFact Kind values mirror the lane fact kinds the mapper sees.
const (
	RuleFactKindPackageUsage         = "PACKAGE_USAGE"
	RuleFactKindUsageBound           = "PACKAGE_USAGE_LOWER_BOUND"
	RuleFactKindUsageScope           = "BUILD_USAGE_SCOPE"
	RuleFactKindApplicability        = "APPLICABILITY"
	RuleFactKindModuleGraph          = "MODULE_GRAPH"
	RuleFactKindObservation          = "OBSERVATION"
	RuleFactKindSymbolUnreachability = "SYMBOL_UNREACHABILITY"
)

// ConditionInput is the wire-level condition statement an evaluator is
// asked to decide: identity, role, the subjects it is bound to, its
// polarity (whether the condition holding supports or undermines the
// premise) and whether a branch requires it.
type ConditionInput struct {
	ID          string
	Statement   string
	Role        string
	Polarity    string
	Required    bool
	SubjectRefs []string
}

// RuleContext is everything a rule may read: the promoted fact
// envelope, the conditions being decided and the fixed branch
// assignments. Adapters never receive agent prose, categories or raw
// observations.
type RuleContext struct {
	Facts       []RuleFact
	Conditions  []ConditionInput
	Assignments map[string]string
}

// RuleResult is the outcome of one rule evaluation. Status is the
// closed enum below; a rule that cannot establish its proposition
// yields UNKNOWN — never a permissive default and never a verdict.
// FactRefs name the RuleFact ids that grounded the result;
// Limitations record why subjects stayed undecidable;
// Contradictions name the contradicting fact ids.
type RuleResult struct {
	RuleID         string
	Status         string
	FactRefs       []string
	Limitations    []string
	Contradictions []string
}

// RuleResult.Status values.
const (
	// RuleEstablished — every required subject is covered by a verified,
	// complete-coverage, digest-bound fact recording the establishing
	// value for the rule's predicate.
	RuleEstablished = "ESTABLISHED"
	// RuleUnknown — the proposition could not be established: missing,
	// degraded, unbound or open-coverage facts, or no subjects at all.
	// This is the fail-closed default, never an error and never a
	// negative answer.
	RuleUnknown = "UNKNOWN"
	// RuleContradicted — at least one subject carries a verified fact
	// recording a value the rule declares contradicting; the opposing
	// evidence blocks establishment regardless of other coverage.
	RuleContradicted = "CONTRADICTED"
)

// VerificationRule evaluates one registered proposition over the fact
// envelope. Implementations are pure and deterministic: no IO, no
// agent input, no research imports, and no terminal verdicts — a rule
// produces an evidence result the decision layer may cite, never a
// disposition.
type VerificationRule interface {
	ID() string
	Evaluate(context.Context, RuleContext) (RuleResult, error)
}

// RuleConditionEvaluator is the condition-side counterpart of
// VerificationRule: it decides whether one catalog condition holds for
// its declared subjects given the fact envelope. (The name differs from
// the legacy ConditionEvaluator interface in this package — that one
// maps domain conditions to claims; this one is typed over RuleFacts.)
type RuleConditionEvaluator interface {
	Evaluate(context.Context, ConditionInput, []RuleFact) (RuleResult, error)
}

// conditionSpec is the registered contract for one condition id: which
// fact predicate decides it, which Value establishes the condition as
// holding, and which Values contradict it. Registration is fail-closed:
// an unknown condition id is an evaluation error, and a spec with an
// empty predicate or establishment value is a registration panic —
// malformed adapters are defects, never defaults.
type conditionSpec struct {
	pred       string
	establish  []string
	contradict []string
}

// ruleSpec is the registered contract for one VerificationRule id: the
// predicate it reads, the Values that establish its proposition, and
// the Values that contradict it.
type ruleSpec struct {
	predicate  string
	establish  []string
	contradict []string
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// conditionAdapter evaluates one registered condition id.
type conditionAdapter struct {
	id   string
	spec conditionSpec
}

func (a conditionAdapter) Evaluate(_ context.Context, c ConditionInput, facts []RuleFact) (RuleResult, error) {
	if c.ID == "" {
		return RuleResult{}, fmt.Errorf("condition evaluation requires a condition id")
	}
	return decidePredicate(c.ID, a.spec.predicateFor(c), a.spec.establish, a.spec.contradict, c.SubjectRefs, facts, true), nil
}

// predicateFor binds the spec to the condition id — the predicate is
// registered per id at construction, so evaluation never guesses.
func (s conditionSpec) predicateFor(c ConditionInput) string { return s.pred }

// outcomeRule is the single VerificationRule implementation: a
// registered (predicate, values) contract applied uniformly to every
// subject the context's conditions name. It has no per-rule code paths.
type outcomeRule struct {
	id   string
	spec ruleSpec
}

func (r outcomeRule) ID() string { return r.id }

func (r outcomeRule) Evaluate(_ context.Context, rc RuleContext) (RuleResult, error) {
	var subjects []string
	seen := map[string]bool{}
	for _, c := range rc.Conditions {
		for _, s := range c.SubjectRefs {
			if s != "" && !seen[s] {
				seen[s] = true
				subjects = append(subjects, s)
			}
		}
	}
	return decidePredicate(r.id, r.spec.predicate, r.spec.establish, r.spec.contradict, subjects, rc.Facts, true), nil
}

// decidePredicate is the shared fail-closed evaluation: every declared
// subject must be covered by a verified, complete-coverage,
// digest-bound fact recording an establishing value for the predicate.
// A verified fact recording a contradicting value for a subject makes
// the whole evaluation CONTRADICTED before coverage is even counted —
// opposing evidence is never silently outweighed. Anything else is
// UNKNOWN with a named limitation per undecidable subject.
func decidePredicate(id, predicate string, establish, contradict, subjects []string, facts []RuleFact, requireComplete bool) RuleResult {
	res := RuleResult{RuleID: id, Status: RuleUnknown}
	if len(subjects) == 0 {
		res.Limitations = append(res.Limitations, "no subject_refs declared: the proposition binds to nothing and cannot be established")
		return res
	}
	// Pass 1: contradictions — a verified contradicting fact for any
	// subject vetoes establishment.
	for _, subj := range subjects {
		for _, f := range facts {
			if f.Subject != subj || f.Predicate != predicate || f.Status != "VERIFIED" || f.Digest == "" {
				continue
			}
			if contains(contradict, f.Value) {
				res.Contradictions = append(res.Contradictions,
					fmt.Sprintf("%s: fact %s records %s=%q for subject %q", id, f.ID, predicate, f.Value, subj))
			}
		}
	}
	if len(res.Contradictions) > 0 {
		res.Status = RuleContradicted
		return res
	}
	// Pass 2: per-subject establishment.
	established := 0
	for _, subj := range subjects {
		var ref string
		var why string
		for _, f := range facts {
			if f.Subject != subj || f.Predicate != predicate {
				continue
			}
			if f.Kind == RuleFactKindApplicability && predicate == PredicateVersionInRange && f.Value == "true" && f.TrustClass != "AUTHORITATIVE" {
				why = fmt.Sprintf("subject %q: version-in-range fact %s is not authoritative release evidence", subj, f.ID)
				continue
			}
			if f.Status != "VERIFIED" {
				why = fmt.Sprintf("subject %q: fact %s status %s is not VERIFIED", subj, f.ID, f.Status)
				continue
			}
			if f.Digest == "" {
				why = fmt.Sprintf("subject %q: fact %s is not digest-bound", subj, f.ID)
				continue
			}
			if requireComplete && f.Coverage != "COMPLETE" {
				why = fmt.Sprintf("subject %q: fact %s coverage %s is not COMPLETE", subj, f.ID, f.Coverage)
				continue
			}
			if !contains(establish, f.Value) {
				why = fmt.Sprintf("subject %q: fact %s records %s=%q which does not establish the proposition", subj, f.ID, predicate, f.Value)
				continue
			}
			ref = f.ID
			break
		}
		if ref != "" {
			established++
			res.FactRefs = append(res.FactRefs, ref)
			continue
		}
		if why == "" {
			why = fmt.Sprintf("subject %q: no fact records %s", subj, predicate)
		}
		res.Limitations = append(res.Limitations, why)
	}
	if established == len(subjects) {
		res.Status = RuleEstablished
	}
	return res
}

// AdapterRegistry is the fail-closed adapter surface: conditions and
// rules must be registered before they evaluate, ids are unique, and
// malformed registrations panic at construction. Evaluation of an
// unregistered id is an error — never a permissive UNKNOWN shortcut.
type AdapterRegistry struct {
	conditions map[string]RuleConditionEvaluator
	rules      map[string]VerificationRule
}

// NewAdapterRegistry builds an empty registry.
func NewAdapterRegistry() *AdapterRegistry {
	return &AdapterRegistry{
		conditions: map[string]RuleConditionEvaluator{},
		rules:      map[string]VerificationRule{},
	}
}

// DefaultAdapterRegistry registers the baseline adapters: the
// applicability condition evaluators the catalog's applicability
// conditions bind to, and the verification rules for the existing
// deterministic applicability and closure outcomes. New behavior is
// added only by registering new specs — the registry contains no
// CVE-, advisory- or package-specific entries.
func DefaultAdapterRegistry() *AdapterRegistry {
	r := NewAdapterRegistry()
	// Applicability conditions (configs/research/conditions.yaml ids).
	r.registerCondition("module-present", conditionSpec{
		pred: PredicateModulePresent, establish: []string{"true"}, contradict: []string{"false"}})
	r.registerCondition("version-in-range", conditionSpec{
		pred: PredicateVersionInRange, establish: []string{"true"}, contradict: []string{"false"}})
	r.registerCondition("declared-symbol-unreachable", conditionSpec{
		pred: PredicateDeclaredSymbolReachability, establish: []string{"unreached"},
		contradict: []string{"reached", "used", "dynamic", "incomplete"}})

	r.registerCondition("package-linked", conditionSpec{
		pred: PredicateProductClosureMembership, establish: []string{"linked"}, contradict: []string{"absent-verified"}})
	// Verification rules over the deterministic outcomes the lane
	// already produces: applicability resolution and the two
	// build-closure/usage checks. They ground propositions only; a
	// terminal verdict remains VerifyDecision's alone.
	r.registerRule("rule.module-absent-from-graph", ruleSpec{
		predicate: PredicateModulePresent, establish: []string{"false"}, contradict: []string{"true"}})
	r.registerRule("rule.version-out-of-range", ruleSpec{
		predicate: PredicateVersionInRange, establish: []string{"false"}, contradict: []string{"true"}})
	r.registerRule("rule.build-not-relevant", ruleSpec{
		predicate: PredicateBuildRelevant, establish: []string{"false"}, contradict: []string{"true"}})
	// The implementation axis closes non-applicability only on a
	// deterministically verified absence: a proposal alone never emits
	// the predicate, and "true" (a selected implementation carries the
	// vulnerable marker) contradicts the close.
	r.registerRule("rule.implementation-absent", ruleSpec{
		predicate: PredicateVulnerableImplementationPresent, establish: []string{"false"}, contradict: []string{"true"}})
	r.registerRule("rule.subject-absent-from-product-closure", ruleSpec{
		predicate: PredicateProductClosureMembership, establish: []string{"absent-verified"}, contradict: []string{"linked"}})
	r.registerRule("rule.subject-linked-into-product-closure", ruleSpec{
		predicate: PredicateProductClosureMembership, establish: []string{"linked"}, contradict: []string{"absent-verified"}})
	r.registerRule("rule.declared-symbols-unreached", ruleSpec{
		predicate: PredicateDeclaredSymbolReachability, establish: []string{"unreached"},
		contradict: []string{"reached", "used", "dynamic", "incomplete"}})

	r.registerRule("rule.subject-not-used-by-product-source", ruleSpec{
		predicate: PredicateProductSourceUsage, establish: []string{"not-used-verified"}, contradict: []string{"used", "positive-lowerbound"}})
	r.registerRule("rule.subject-used-by-product-source", ruleSpec{
		predicate: PredicateProductSourceUsage, establish: []string{"used", "positive-lowerbound"}, contradict: []string{"not-used-verified"}})
	// Config-origin provenance stays a code-level falsifier gate: the
	// rule establishes only when a recorded provenance fact proves every
	// relevant sink input traces to configuration under complete
	// coverage. No producer emits the predicate yet, so the rule fails
	// closed to UNKNOWN until one does.
	r.registerRule("rule.config-origin-sink-closure", ruleSpec{
		predicate:  PredicateConfigOriginSinkInputs,
		establish:  []string{"all-traced-to-configuration"},
		contradict: []string{"external-or-unresolved"},
	})
	return r
}

// registerCondition binds one catalog condition id to its evaluator.
// Registration is fail-closed at construction: malformed specs and
// duplicate ids panic — an adapter that cannot evaluate correctly must
// never be silently reachable.
func (r *AdapterRegistry) registerCondition(id string, spec conditionSpec) {
	if id == "" || spec.pred == "" || len(spec.establish) == 0 {
		panic(fmt.Sprintf("evaluator: malformed condition spec for %q", id))
	}
	if _, dup := r.conditions[id]; dup {
		panic(fmt.Sprintf("evaluator: condition %q registered twice", id))
	}
	r.conditions[id] = conditionAdapter{id: id, spec: spec}
}

// registerRule binds one rule id to its VerificationRule.
func (r *AdapterRegistry) registerRule(id string, spec ruleSpec) {
	if id == "" || spec.predicate == "" || len(spec.establish) == 0 {
		panic(fmt.Sprintf("evaluator: malformed rule spec for %q", id))
	}
	if _, dup := r.rules[id]; dup {
		panic(fmt.Sprintf("evaluator: rule %q registered twice", id))
	}
	r.rules[id] = outcomeRule{id: id, spec: spec}
}

// HasCondition reports whether a condition id has a registered
// evaluator.
func (r *AdapterRegistry) HasCondition(id string) bool {
	_, ok := r.conditions[id]
	return ok
}

// HasRule reports whether a rule id is registered.
func (r *AdapterRegistry) HasRule(id string) bool {
	_, ok := r.rules[id]
	return ok
}

// EvaluateCondition runs the registered evaluator for c.ID. An
// unregistered condition is an error — the flow layer must never guess
// a condition's semantics.
func (r *AdapterRegistry) EvaluateCondition(ctx context.Context, c ConditionInput, facts []RuleFact) (RuleResult, error) {
	ev, ok := r.conditions[c.ID]
	if !ok {
		return RuleResult{}, fmt.Errorf("condition %q has no registered evaluator", c.ID)
	}
	return ev.Evaluate(ctx, c, facts)
}

// EvaluateRule runs the registered rule. An unregistered rule id is an
// error, never a permissive result.
func (r *AdapterRegistry) EvaluateRule(ctx context.Context, ruleID string, rc RuleContext) (RuleResult, error) {
	rule, ok := r.rules[ruleID]
	if !ok {
		return RuleResult{}, fmt.Errorf("rule %q is not registered", ruleID)
	}
	return rule.Evaluate(ctx, rc)
}
