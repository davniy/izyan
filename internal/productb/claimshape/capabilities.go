package claimshape

import triage "github.com/fedorovmv/izyan/internal/productb/triage"

// ShapePredicate is the canonical predicate prose of a shape. It is a
// fixed property of the taxonomy — never derived from claim text.
func ShapePredicate(s Shape) string {
	switch s {
	case ShapeApplicabilityVersionInRange:
		return "resolved module version falls inside an advisory affected range"
	case ShapeSubjectDeclared:
		return "subject is declared or occurs in the cited scope"
	case ShapeSubjectAbsent:
		return "subject is absent from the cited scope"
	case ShapePathReachable:
		return "subject is reachable or invoked from the cited scope"
	case ShapePathUnreachable:
		return "no invocation of the subject exists in the cited scope"
	case ShapeInputOrigin:
		return "input has the named provenance"
	case ShapeInputAttackerControlled:
		return "attacker controls the named input"
	case ShapeControlPresent:
		return "the named guard or control is present on the path"
	case ShapeControlAbsent:
		return "the named guard or control is absent from the path"
	case ShapeConfigurationPredicate:
		return "the named configuration predicate holds"
	case ShapeEnvironmentBuildGate:
		return "build or environment context gates the subject in or out"
	case ShapePerimeterExposure:
		return "the named exposure surface exists"
	case ShapeClosureComplete:
		return "the closed scope covers the relevant universe"
	case ShapeProvenanceBound:
		return "subject is bound to an authoritative source"
	case ShapeDerivedMandatoryCondition:
		return "mandatory exploitation condition evaluated over premise claims"
	case ShapeDerivedTriageDisposition:
		return "final triage disposition over the claim graph"
	}
	return ""
}

// shapeCapabilities is the static capability requirement of each
// canonical shape — the generic verifier capabilities of plan §5, named
// by what they can check, never by package, advisory or symbol. The ids
// are the canonical registry keys of internal/verification.
var shapeCapabilities = map[Shape][]string{
	ShapeApplicabilityVersionInRange: {"module_version_resolver", "advisory_range_matcher"},
	ShapeSubjectDeclared:             {"declaration_resolver"},
	ShapeSubjectAbsent:               {"declaration_resolver", "scope.closed"},
	ShapePathReachable:               {"reachability_analyzer", "negative_reachability", "scope.closed"},
	ShapePathUnreachable:             {"negative_reachability", "scope.closed"},
	ShapeInputOrigin:                 {"provenance_tracer"},
	ShapeInputAttackerControlled:     {"provenance_tracer", "deployment_classifier"},
	ShapeControlPresent:              {"guard_checker"},
	ShapeControlAbsent:               {"guard_checker", "declaration_resolver", "scope.closed"},
	ShapeConfigurationPredicate:      {"configuration_analyzer"},
	ShapeEnvironmentBuildGate:        {"build_context_checker"},
	ShapePerimeterExposure:           {"deployment_classifier"},
	ShapeClosureComplete:             {"scope.closed"},
	ShapeProvenanceBound:             {"advisory_record"},
	ShapeDerivedMandatoryCondition:   {"entailment_graph"},
	ShapeDerivedTriageDisposition:    {"entailment_graph"},
}

// RequiredCapabilities returns the generic verifier capabilities a claim
// shape demands (plan §5). UNSUPPORTED claims require none.
func RequiredCapabilities(s Shape) []string {
	return append([]string(nil), shapeCapabilities[s]...)
}

// CheckShapeForFalsifierKind maps a falsifier kind — a deterministic
// check the agent requested or a checker minted — to the canonical
// shape that check verifies. It is informational provenance on the
// claim: the kind never overrides the claim's own evidence-derived
// shape.
func CheckShapeForFalsifierKind(kind triage.FalsifierKind) Shape {
	switch kind {
	case triage.FalsifierCodeAbsent:
		return ShapeSubjectAbsent
	case triage.FalsifierLocusPackageAbsent:
		return ShapeSubjectAbsent
	case triage.FalsifierLocusFunctionAbsent:
		return ShapePathUnreachable
	}
	return ShapeUnsupported
}
