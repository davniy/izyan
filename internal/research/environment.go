package research

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/exposure"
)

// The decision-variable registry (Amendment R6). Branch enumeration is
// code-owned: this table is the complete list of variables a branch may
// ever be conditioned on — the agent may propose that a variable
// matters but can never add a variable, a value, or a branch. Phase 1
// implements two variables:
//
//   - deployment_perimeter (catalog-owned): the required environment
//     question; its allowed values come from the conditions catalog.
//   - build_variant (derived): resolved from the recorded build
//     context, never asked of a human.
//
// Every other listed id is registered-but-unimplemented: referencing it
// produces NOT_DECISION_READY rather than a generic interpretation.
const (
	variableDeploymentPerimeter = "deployment_perimeter"
	variableBuildVariant        = "build_variant"
)

// variableSpec is the code-owned semantics of one decision variable:
// the question text (required variables only), whether an operator may
// be asked, and the per-value class the branch evaluator maps to a
// disposition. A nil classify marks a registered-but-unimplemented
// variable — it is never interpreted generically.
type variableSpec struct {
	id       string
	question string
	required bool
	// classify maps an allowed value to its branch class; nil means the
	// variable is unimplemented and any dependence on it fails closed.
	classify func(string) variableClass
}

// variableClass is the code-owned outcome class of one allowed value.
type variableClass int

const (
	// classTrusted marks a recorded/declared trusted-perimeter posture:
	// the only premise class that may ground
	// ACCEPT_ENVIRONMENTAL_MITIGATION — never a code-level close.
	classTrusted variableClass = iota
	// classUntrusted marks an openly reachable posture: the finding
	// stays open for remediation under it.
	classUntrusted
	// classUnmapped marks a catalog value no evaluator is registered
	// for: its branch is NOT_DECISION_READY, never interpreted.
	classUnmapped
)

// perimeterValues carries the catalog-declared answer set of
// deployment_perimeter; absent from a loaded catalog it stays nil and
// the variable cannot be declared.
var perimeterClass = map[string]variableClass{
	domain.PerimeterClusterInternal: classTrusted,
	domain.PerimeterPublic:          classUntrusted,
}

// classifyPerimeter maps a declared perimeter value to its branch
// class; every value outside the code table is unmapped.
func classifyPerimeter(v string) variableClass {
	if c, ok := perimeterClass[v]; ok {
		return c
	}
	return classUnmapped
}

// variableRegistry is the complete R6 variable table. Unimplemented
// variables are listed deliberately: an agent or configuration that
// declares dependence on one must see the explicit
var variableRegistry = map[string]variableSpec{
	variableDeploymentPerimeter: {
		id:       variableDeploymentPerimeter,
		required: true,
		question: "Which perimeter posture does the analyzed deployment run in?",
		classify: classifyPerimeter,
	},
	variableBuildVariant: {
		id:       variableBuildVariant,
		question: "Which recorded build closure variant produced the analyzed artifact?",
		required: false,
	},
	"peer_trust":         {id: "peer_trust"},
	"config_mode":        {id: "config_mode"},
	"delivered_artifact": {id: "delivered_artifact"},
	"protocol_role":      {id: "protocol_role"},
}

// conditionVariable binds a catalog condition id (kebab-case) to the
// decision variable it asks about. Only deployment-class catalog
// conditions map to variables; a proposal referencing any other id is a
// plain condition, never a variable declaration.
var conditionVariable = map[string]string{
	"deployment-perimeter": variableDeploymentPerimeter,
	"peer-trust":           "peer_trust",
	"config-mode":          "config_mode",
	"build-variant":        variableBuildVariant,
	"delivered-artifact":   "delivered_artifact",
	"protocol-role":        "protocol_role",
}

// variableForCondition returns the decision variable a catalog
// condition binds to, or "" when the condition is not a variable gate.
func variableForCondition(conditionID string) string {
	return conditionVariable[conditionID]
}

// buildVariantValue names the recorded build closure variant. It is
// derived from the snapshot's recorded build context — vendored trees,
// workspace builds and module-resolution builds carry different
// provenance, so the variant is part of what the recorded facts cover.
func buildVariantValue(s domain.ProductSnapshot) string {
	switch {
	case s.VendorMode:
		return "vendor"
	case s.GoWorkFile != "":
		return "workspace"
	default:
		return "module"
	}
}

// buildVariantOther is the sole alternative the recorded build context
// admits: any delivered artifact built under a different variant than
// the recorded one — the recorded evidence does not transfer to it.
const buildVariantOther = "other"

// decisionVariableValues resolves the finite allowed-value set of one
// declared variable: the catalog-owned variable reads its answer set
// from the loaded catalog (empty when the catalog did not declare it);
// the derived variable enumerates the recorded variant plus the
// non-transferable "other"; unimplemented variables get no values.
func decisionVariableValues(id string, lane *LaneResult, cats *Catalogs) []string {
	switch id {
	case variableDeploymentPerimeter:
		if cats == nil {
			return nil
		}
		for _, v := range cats.Variables {
			if v.ID == id {
				return append([]string(nil), v.AllowedValues...)
			}
		}
		return nil
	case variableBuildVariant:
		return []string{buildVariantValue(lane.Snapshot), buildVariantOther}
	}
	return nil
}

// decisionVariableDecl materializes the declared DecisionVariable the
// artifact carries: registry-owned id/question/required flag and the
// resolved value set. It returns false when the variable cannot be
// declared (unknown or catalog-owned with no declared values).
func decisionVariableDecl(id string, lane *LaneResult, cats *Catalogs) (DecisionVariable, bool) {
	spec, ok := variableRegistry[id]
	if !ok {
		return DecisionVariable{}, false
	}
	vals := decisionVariableValues(id, lane, cats)
	if len(vals) == 0 {
		return DecisionVariable{}, false
	}
	return DecisionVariable{
		ID:            spec.id,
		Question:      spec.question,
		AllowedValues: vals,
		Required:      spec.required,
	}, true
}

// environmentEvidence is the machine side of an environment variable:
// the recorded posture the lane observed, plus the typed premise it is
// recorded as. Kind is empty when nothing was recorded — silence is
// never evidence either way.
type environmentEvidence struct {
	value   string
	source  string
	premise *EnvironmentAssertion
}

// recordedPerimeter derives the machine-observed deployment perimeter
// from the lane's recorded configuration: an explicit recorded override
// wins, the declared trusted-peer flag records a trusted posture, and
// otherwise the manifest/exposure classifier decides from structural
// facts. Conflicting recorded postures resolve conservatively: any
// recorded untrusted-class posture outranks a trusted one — recorded
// evidence is never used to widen a trust premise.
func recordedPerimeter(lane *LaneResult) environmentEvidence {
	var trusted *environmentEvidence
	for _, e := range []environmentEvidence{
		perimeterOverrideEvidence(lane),
		trustedPeerEvidence(lane),
		perimeterClassifiedEvidence(lane),
	} {
		if e.value == "" {
			continue
		}
		if classifyPerimeter(e.value) == classUntrusted {
			return e
		}
		if trusted == nil {
			ev := e
			trusted = &ev
		}
	}
	if trusted != nil {
		return *trusted
	}
	return environmentEvidence{}
}

// perimeterOverrideEvidence reads the recorded --perimeter override:
// "auto" records nothing, an unrecognized value records the limitation
// (as an unknown-class premise) so it can never masquerade as trust.
func perimeterOverrideEvidence(lane *LaneResult) environmentEvidence {
	ov := strings.TrimSpace(lane.Snapshot.PerimeterOverride)
	switch ov {
	case "", "auto":
		return environmentEvidence{}
	case "cluster", domain.PerimeterClusterInternal:
		return environmentEvidence{
			value:  domain.PerimeterClusterInternal,
			source: "recorded perimeter override",
			premise: recordedAssertion(
				variableDeploymentPerimeter, domain.PerimeterClusterInternal,
				"perimeter override recorded at snapshot time",
				"perimeter-override", lane),
		}
	case domain.PerimeterPublic:
		return environmentEvidence{
			value:  domain.PerimeterPublic,
			source: "recorded perimeter override",
			premise: recordedAssertion(
				variableDeploymentPerimeter, domain.PerimeterPublic,
				"perimeter override recorded at snapshot time",
				"perimeter-override", lane),
		}
	default:
		return environmentEvidence{value: "other", source: "recorded perimeter override " + ov}
	}
}

// trustedPeerEvidence reads the recorded trusted-peer flag. It is a
// deployment declaration — it may only ever premise the contextual
// mitigation branch, never a code-level falsifier.
func trustedPeerEvidence(lane *LaneResult) environmentEvidence {
	if !lane.Snapshot.TrustedPeer {
		return environmentEvidence{}
	}
	return environmentEvidence{
		value:  domain.PerimeterClusterInternal,
		source: "recorded trusted-peer declaration",
		premise: recordedAssertion(
			variableDeploymentPerimeter, domain.PerimeterClusterInternal,
			"trusted-peer posture declared at snapshot time",
			"trusted-peer-declaration", lane),
	}
}

// perimeterClassifiedEvidence classifies the recorded deployment
// exposure facts with the canonical classifier — the same derivation
// the analyze lane uses, never a reinterpretation.
func perimeterClassifiedEvidence(lane *LaneResult) environmentEvidence {
	if len(lane.ExposureFacts) == 0 {
		return environmentEvidence{}
	}
	assessment := exposure.ClassifyPerimeter(lane.ExposureFacts, laneProductNames(lane))
	scope := assessment.Perimeter
	if scope == domain.PerimeterUnknown || scope == "" {
		return environmentEvidence{}
	}
	return environmentEvidence{
		value:  scope,
		source: "classified from recorded deployment exposure facts",
		premise: recordedAssertion(
			variableDeploymentPerimeter, scope,
			"perimeter classified from recorded exposure facts",
			"exposure-classifier", lane),
	}
}

// laneProductNames collects the identity candidates the classifier uses
// for deploy-fact attribution: module path base names of declared
// advisory modules plus the snapshot root and repository names.
func laneProductNames(lane *LaneResult) []string {
	var names []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			names = append(names, s)
		}
	}
	for _, sub := range declaredSubjects(lane) {
		if i := strings.LastIndex(sub.Module, "/"); i >= 0 {
			add(sub.Module[i+1:])
		}
		add(sub.Module)
	}
	add(filepath.Base(lane.SnapshotRoot))
	add(filepath.Base(lane.Snapshot.Repository))
	return names
}

// recordedAssertion stamps the EnvironmentAssertion a recorded (not
// operator) deployment premise takes inside a branch: principal and
// source name the recorded configuration surface, the timestamp is the
// earliest recorded audit time the lane carries, and freshness binds it
// to the recorded snapshot rather than to a live answer.
func recordedAssertion(variable, value, principal, source string, lane *LaneResult) *EnvironmentAssertion {
	ts := recordedAssertionTime(lane)
	if ts == "" {
		return nil
	}
	return &EnvironmentAssertion{
		Variable:  variable,
		Value:     value,
		Principal: principal,
		Timestamp: ts,
		Source:    source,
		Freshness: "recorded at snapshot time",
	}
}

// recordedAssertionTime is the earliest audit-recorded time the lane
// carries — the stamp a recorded environment premise is bound to.
func recordedAssertionTime(lane *LaneResult) string {
	var min time.Time
	for i := range lane.Records {
		if !lane.Records[i].RecordTime.IsZero() &&
			(min.IsZero() || lane.Records[i].RecordTime.Before(min)) {
			min = lane.Records[i].RecordTime
		}
	}
	if min.IsZero() {
		return ""
	}
	return min.UTC().Format(time.RFC3339)
}

// assertionRef names one recorded assertion for supersession history:
// variable, value and timestamp together identify the answer — a
// superseding answer must name the prior answer it replaces.
func assertionRef(a EnvironmentAssertion) string {
	return fmt.Sprintf("%s=%s@%s", a.Variable, a.Value, a.Timestamp)
}

// machineAssertionSources are the Source values the builder itself
// stamps on recorded environment premises — distinguishing the recorded
// deployment posture from an operator's answer, which carries whatever
// source the caller declared.
var machineAssertionSources = map[string]bool{
	"perimeter-override":       true,
	"trusted-peer-declaration": true,
	"exposure-classifier":      true,
}

// ApplyEnvironmentAssertions records operator answers onto a built
// artifact. It is the only place environment input enters the
// contract, and it stays strictly inside it:
//
//   - the input artifact is never mutated (the result is a copy);
//   - an answer must name a declared required variable, a declared
//     allowed value, and a branch that actually engages the variable —
//     invented variables, values and free-form answers are rejected;
//   - answers are recorded as EnvironmentAssertion with supersession
//     history; they are never converted to claims or facts;
//   - an answer conflicting with recorded machine evidence marks the
//     branch CONTRADICTED and the artifact falls back to HOLD_UNKNOWN;
//   - the result is re-validated before return.
//
// Nothing here touches LaneResult, domain.Claim, EvidenceDecision or
// negative-verification state — those types are not reachable from the
// artifact contract.
func ApplyEnvironmentAssertions(artifact DecisionArtifact, assertions []EnvironmentAssertion) (DecisionArtifact, error) {
	if err := ValidateDecisionArtifact(&artifact); err != nil {
		return DecisionArtifact{}, fmt.Errorf("artifact must be valid before environment answers apply: %w", err)
	}
	vars := map[string]*DecisionVariable{}
	for i := range artifact.DecisionVariables {
		vars[artifact.DecisionVariables[i].ID] = &artifact.DecisionVariables[i]
	}
	for _, as := range assertions {
		v := vars[as.Variable]
		if v == nil {
			return DecisionArtifact{}, fmt.Errorf("environment answer names undeclared variable %q — only declared variables may be answered", as.Variable)
		}
		if !v.Required {
			return DecisionArtifact{}, fmt.Errorf("environment variable %q is derived from recorded context — it is never asked and never answered", as.Variable)
		}
		valOK := false
		for _, av := range v.AllowedValues {
			if av == as.Value {
				valOK = true
				break
			}
		}
		if !valOK {
			return DecisionArtifact{}, fmt.Errorf("environment answer %q for %q is outside the declared allowed_values — invented values are rejected", as.Value, as.Variable)
		}
		if as.Principal == "" || as.Timestamp == "" || as.Source == "" || as.Freshness == "" {
			return DecisionArtifact{}, fmt.Errorf("environment answer for %q lacks principal/timestamp/source/freshness — the audit trail is mandatory", as.Variable)
		}
		engaged := false
		for _, br := range artifact.Branches {
			if _, ok := br.Assignments[as.Variable]; ok {
				engaged = true
			}
		}
		if !engaged {
			return DecisionArtifact{}, fmt.Errorf("no branch engages variable %q — the artifact never asked for this answer", as.Variable)
		}
	}

	out, err := copyArtifact(&artifact)
	if err != nil {
		return DecisionArtifact{}, err
	}
	for _, as := range assertions {
		// Supersession history: the new answer names every earlier
		// operator answer to the same variable it replaces; recorded
		// machine premises are never superseded — they either agree or
		// conflict.
		for _, prior := range priorOperatorAssertions(out, as.Variable) {
			as.Supersedes = append(as.Supersedes, assertionRef(prior))
		}
		as.Supersedes = dedupeStrings(as.Supersedes)
		resetOperatorAnswers(out, as.Variable)
		for i := range out.Branches {
			applyAssertionToBranch(out, &out.Branches[i], as)
		}
	}
	recomputeHumanContract(out)
	if err := ValidateDecisionArtifact(out); err != nil {
		return DecisionArtifact{}, fmt.Errorf("artifact invalid after environment answers: %w", err)
	}
	return *out, nil
}

// priorOperatorAssertions collects the operator-supplied assertions for
// a variable across all branches — the supersession surface.
func priorOperatorAssertions(a *DecisionArtifact, variable string) []EnvironmentAssertion {
	var out []EnvironmentAssertion
	for _, br := range a.Branches {
		for _, as := range br.EnvironmentAssertions {
			if as.Variable == variable && !machineAssertionSources[as.Source] {
				out = append(out, as)
			}
		}
	}
	return out
}

// applyAssertionToBranch records one operator answer on one branch.
// The branch takes the answer only when its own assignment matches —
// a mismatch is another branch's premise and is never borrowed. An
// answer landing on a branch the recorded evidence already contradicts
// extends the recorded contradiction; the operator's word never
// overrides deterministic evidence.
func applyAssertionToBranch(a *DecisionArtifact, br *DecisionBranch, as EnvironmentAssertion) {
	cur, ok := br.Assignments[as.Variable]
	if !ok || cur != as.Value {
		return
	}
	if !hasAssertion(br, as) {
		br.EnvironmentAssertions = append(br.EnvironmentAssertions, as)
	}
	if br.Status == BranchContradicted {
		a.Contradictions = append(a.Contradictions, Contradiction{
			ID:         fmt.Sprintf("CT-%d", nextContradictionOrdinal(a)),
			Kind:       ContradictionEnvironmentVsMachine,
			Subject:    as.Variable,
			Summary:    fmt.Sprintf("operator answer %s=%q conflicts with recorded deterministic evidence on branch %s", as.Variable, as.Value, br.ID),
			Resolution: ResolutionUnresolved,
		})
	}
}

// resetOperatorAnswers removes earlier operator answers to a variable
// from every branch — supersession replaces the premise, while
// recorded machine premises stay. The superseding answer's Supersedes
// refs carry the audit history of what was replaced.
func resetOperatorAnswers(a *DecisionArtifact, variable string) {
	for i := range a.Branches {
		br := &a.Branches[i]
		kept := br.EnvironmentAssertions[:0]
		for _, as := range br.EnvironmentAssertions {
			if as.Variable == variable && !machineAssertionSources[as.Source] {
				continue
			}
			kept = append(kept, as)
		}
		br.EnvironmentAssertions = kept
	}
}

// recomputeHumanContract re-derives the human-facing surface after
// answers landed: a variable stays an open question only while no
// branch carries any premise for it — machine or operator — and the
// proposal follows the answered branches, with contradictions holding
// the artifact at HOLD_UNKNOWN.
func recomputeHumanContract(a *DecisionArtifact) {
	answered := map[string]bool{}
	for _, br := range a.Branches {
		for _, as := range br.EnvironmentAssertions {
			answered[as.Variable] = true
		}
	}
	var questions []string
	for _, v := range a.DecisionVariables {
		if v.Required && !answered[v.ID] {
			questions = append(questions, v.ID)
		}
	}
	a.HumanAction.EnvironmentQuestionRefs = questions
	if len(questions) > MaxEnvironmentQuestions {
		a.HumanAction.EnvironmentQuestionRefs = nil
	}
	if len(a.HumanAction.EnvironmentQuestionRefs) > 0 {
		a.HumanAction.Mode = HumanActionAnswerThenAcceptReject
	} else {
		a.HumanAction.Mode = HumanActionAcceptReject
	}
	a.ProposedDisposition = answeredDisposition(a)
}

// answeredDisposition selects the artifact proposal after answers: any
// branch contradicted while carrying an operator answer holds the
// whole artifact unknown; a complete branch carrying an operator
// answer proposes its disposition; otherwise the pre-answer proposal
// stands.
func answeredDisposition(a *DecisionArtifact) ProposedDisposition {
	for _, br := range a.Branches {
		if br.Status != BranchContradicted {
			continue
		}
		for _, as := range br.EnvironmentAssertions {
			if !machineAssertionSources[as.Source] {
				return DispositionHoldUnknown
			}
		}
	}
	for _, br := range a.Branches {
		if br.Status != BranchComplete {
			continue
		}
		for _, as := range br.EnvironmentAssertions {
			if !machineAssertionSources[as.Source] {
				return br.ProposedDisposition
			}
		}
	}
	return a.ProposedDisposition
}

// hasAssertion reports whether the exact answer is already recorded.
func hasAssertion(br *DecisionBranch, as EnvironmentAssertion) bool {
	for _, cur := range br.EnvironmentAssertions {
		if cur.Variable == as.Variable && cur.Value == as.Value &&
			cur.Timestamp == as.Timestamp && cur.Principal == as.Principal {
			return true
		}
	}
	return false
}

// copyArtifact deep-copies the artifact through its wire form — the
// returned object shares no backing storage with the input, so apply
// can never mutate the caller's artifact.
func copyArtifact(a *DecisionArtifact) (*DecisionArtifact, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var out DecisionArtifact
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// nextContradictionOrdinal derives a fresh contradiction id without
// colliding with existing CT-* ids.
func nextContradictionOrdinal(a *DecisionArtifact) int {
	max := 0
	for _, c := range a.Contradictions {
		var n int
		if _, err := fmt.Sscanf(c.ID, "CT-%d", &n); err == nil && n > max {
			max = n
		}
	}
	return max + 1
}
