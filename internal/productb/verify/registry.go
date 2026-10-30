package verify

import (
	"fmt"
	"sort"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
)

// Capability ids are generic: they name what a deterministic check can
// establish, never a package, advisory or symbol (plan §5 registry,
// Global Constraint 1). claimshape.RequiredCapabilities emits these ids
// on every canonical claim.
const (
	CapModuleVersionResolver = "module_version_resolver"
	CapAdvisoryRangeMatcher  = "advisory_range_matcher"
	CapAdvisoryRecord        = "advisory_record"
	CapDeclarationResolver   = "declaration_resolver"
	CapScopeClosed           = "scope.closed"
	CapReachability          = "reachability_analyzer"
	CapNegativeReachability  = "negative_reachability"
	CapProvenanceTracer      = "provenance_tracer"
	CapGuardChecker          = "guard_checker"
	CapConfigurationAnalyzer = "configuration_analyzer"
	CapBuildContext          = "build_context_checker"
	CapDeploymentClassifier  = "deployment_classifier"
	CapFalsifierCertificate  = "falsifier_certificate"
	CapEntailmentGraph       = "entailment_graph"
)

// DirectionContract is one direction of a capability's admission contract
// for one claim shape: the minimum completeness the observation must
// report, whether the observation must prove a closed universe, which
// provenance bindings are mandatory, and which other capabilities'
// admitted SUPPORTS observations the direction additionally requires.
//
// The universal direction of a predicate (established over a whole
// relevant universe) always demands COMPLETE + closed scope + full
// provenance; the existential direction (a concrete witness or
// counterexample) may admit at PARTIAL because a single named fact
// carries it. PARTIAL/UNKNOWN can therefore never admit the universal
// direction — the §6.3 invariant — while a concrete counterexample
// remains visible.
type DirectionContract struct {
	// MinCompleteness is the lowest completeness at which this direction
	// may admit.
	MinCompleteness evidencetools.Completeness
	// ClosedScope requires Observation.ClosedScope — the check must have
	// enumerated a closed universe, not merely finished without error.
	ClosedScope bool
	// Provenance names the mandatory provenance bindings.
	Provenance []ProvenanceField
	// AlsoRequires lists additional capabilities that must each
	// contribute an admitted SUPPORTS observation for this direction
	// (e.g. closed-scope absence requires the scope certificate in
	// addition to the declaration resolver's SUPPORTS).
	AlsoRequires []string
}

// ShapeContract binds one capability to one claim shape.
type ShapeContract struct {
	Shape claimshape.Shape
	// claim's predicate (the closed/universal direction for absence,
	// unreachability and closure claims). The opposite result is the
	// existential counterexample.
	NegativeResult Result
	// PredicateEvidence distinguishes predicate evidence from auxiliary
	// conjunction facts. Auxiliary capabilities may satisfy AlsoRequires
	// and expose blockers, but never establish the claim predicate.
	PredicateEvidence bool
	// Supports/Refutes are the admission contracts per result.
	Supports DirectionContract
	Refutes  DirectionContract
	// RequiredScope names the universe the claim needs covered —
	// descriptive, for audit and the report.
	RequiredScope string
	// CompleteMeans records what COMPLETE means for this capability on
	// this shape — a coverage statement, not "the tool finished".
	CompleteMeans string
	// GapBlockers names the open-gap classes that always block the
	// NegativeResult direction: any matching Observation.OpenGaps entry
	// defeats admission regardless of completeness.
	GapBlockers []string
}

// Capability is one registry entry: a generic deterministic check class.
// Implemented marks capabilities the current tool surface can serve;
// an unimplemented capability is an honest capability gap, not an error —
// claims requiring it stay UNKNOWN with reason capability_unavailable.
type Capability struct {
	ID string
	// Description states what the capability establishes, in generic terms.
	Description string
	// Contracts lists the shapes the capability accepts.
	Contracts []ShapeContract
	// Implemented reports whether a deterministic binding exists.
	Implemented bool
	// LiveTools names the evidence tools that produce this capability's
	// observations during live execution (informational for planning;
	// archive interpretation is keyed separately).
	//
	// The ids are canonical evidencetools capability-registry ids, not a
	// second tool catalog: this offline validator never resolves or admits a
	// tool, and the cross-check that every id still exists in
	// evidencetools.DefaultCheckCatalog lives in the package test
	// (TestBoundToolsExist), never at init — a retired live tool must not
	// make historical validation panic.
	LiveTools []string
	// GapSources declares the payload field families that may open a gap for
	// this capability. The registry initializer fills the conservative common
	// surface when a capability has no narrower declaration.
	GapSources []string
}

// contractFor returns the shape contract of a capability, or nil.
func (c Capability) contractFor(shape claimshape.Shape) *ShapeContract {
	for i := range c.Contracts {
		if c.Contracts[i].Shape == shape {
			return &c.Contracts[i]
		}
	}
	return nil
}

// direction returns the admission contract for one result direction.
func (sc *ShapeContract) direction(r Result) DirectionContract {
	if r == ResultRefutes {
		return sc.Refutes
	}
	return sc.Supports
}

// negativeDirection returns the contract of the direction that proves the
// claim's predicate (NegativeResult).
func (sc *ShapeContract) negativeDirection() DirectionContract {
	return sc.direction(sc.NegativeResult)
}

// positiveDirection returns the contract of the counterexample direction.
func (sc *ShapeContract) positiveDirection() DirectionContract {
	if sc.NegativeResult == ResultSupports {
		return sc.Refutes
	}
	return sc.Supports
}

// universal lists the provenance fields every closed-scope direction
// requires: the full §5.1 binding.
var universal = []ProvenanceField{
	ProvRunID, ProvSnapshotHash, ProvBuildContext, ProvScopeHash, ProvToolVersion,
}

// existential lists the provenance fields a witness/counterexample
// direction requires: run and snapshot binding plus tool identity — the
// witness must belong to this run's snapshot, never to a foreign one.
var existential = []ProvenanceField{
	ProvRunID, ProvSnapshotHash, ProvToolVersion,
}

// dynamicGaps are the open-gap classes that block every
// negative-verification direction: dynamic invocation, unresolved
// dispatch, truncated scope and unbounded surfaces make a universal
// conclusion unsafe (plan §5 item 5, proof soundness gates §8.3).
var dynamicGaps = []string{
	"open_dynamic_marker",
	"unresolved_dispatch",
	"open_exception",
	"skipped_package",
	"truncated_scope",
	"unbounded_surface",
	"opaque_dispatch",
	"build_gated_reference",
}

var (
	dirUniversal = DirectionContract{
		MinCompleteness: evidencetools.CompletenessComplete,
		ClosedScope:     true,
		Provenance:      universal,
	}
	dirExistential = DirectionContract{
		MinCompleteness: evidencetools.CompletenessPartial,
		Provenance:      existential,
	}
)

// universalContract builds a shape contract whose NegativeResult is the
// closed/universal direction; the opposite direction keeps the
// existential (witness/counterexample) floor. `also` conjoins extra
// capabilities whose admitted SUPPORTS the universal direction needs.
func universalContract(shape claimshape.Shape, neg Result, scope, means string, also ...string) ShapeContract {
	sup, ref := dirExistential, dirExistential
	uni := dirUniversal
	uni.AlsoRequires = append([]string(nil), also...)
	if neg == ResultSupports {
		sup = uni
	} else if neg == ResultRefutes {
		ref = uni
	}
	return ShapeContract{Shape: shape, NegativeResult: neg, PredicateEvidence: true, Supports: sup, Refutes: ref, RequiredScope: scope, CompleteMeans: means}
}

// existentialContract builds a shape contract for predicates with no
// closed-scope direction on this capability.
func existentialContract(shape claimshape.Shape, neg Result, scope, means string) ShapeContract {
	return ShapeContract{Shape: shape, NegativeResult: neg, PredicateEvidence: true, Supports: dirExistential, Refutes: dirExistential, RequiredScope: scope, CompleteMeans: means}
}

// only. Adding an entry requires no package/advisory/symbol knowledge.
var commonGapSources = []string{
	"unresolved_dispatch", "dynamic_markers", "skipped_packages",
	"gated_references", "import_closure.open_exceptions",
	"import_closure.observed_dynamic_markers", "import_closure.skipped_unscanned",
	"import_closure.unhashed_source", "import_closure.scope_unknown",
	"import_closure.load_budget_exhausted",
}

var registry = []Capability{
	{
		ID:          CapModuleVersionResolver,
		Description: "resolves a module's effective version inside the snapshot's closed dependency graph",
		Implemented: true,
		LiveTools:   []string{"get_module_version", "get_dependency_graph"},
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeApplicabilityVersionInRange, ResultSupports,
				"the snapshot's enumerated module list",
				"the module list was enumerated by the package manager under the recorded build context"),
		},
	},
	{
		ID:          CapAdvisoryRangeMatcher,
		Description: "compares a resolved module version against the authoritative affected ranges",
		Implemented: true,
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeApplicabilityVersionInRange, ResultSupports,
				"the authoritative advisory version ranges",
				"the resolved version was compared against every affected range — both directions are equally complete"),
		},
	},
	{
		ID:          CapAdvisoryRecord,
		Description: "binds a claim subject to the authoritative frozen advisory record",
		Implemented: true,
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeProvenanceBound, ResultSupports,
				"the frozen advisory document of this run",
				"the advisory record resolved and names the bound subject"),
		},
	},
	{
		ID:          CapDeclarationResolver,
		Description: "resolves a subject's declaration or occurrence inside a resolved package or closed scope",
		Implemented: true,
		LiveTools:   []string{"find_symbol", "find_references", "verify_code_absence"},
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeSubjectDeclared, ResultSupports,
				"one resolved package's declaration space",
				"the package loaded and type-checked; the declaration lookup is closed within it"),
			// Closed-scope absence additionally requires the scope
			// certificate: declaration absence inside one package is only
			// meaningful once the scope is proven closed.
			universalContract(claimshape.ShapeSubjectAbsent, ResultSupports,
				"every resolved package the subject could occupy",
				"expected subjects equal checked subjects and each resolution is decided inside a closed scope",
				CapScopeClosed),
			// Control-role absence shares the declaration machinery; the
			// role discriminator (payload subject roles) is what makes it
			// a control predicate rather than a plain subject absence.
			universalContract(claimshape.ShapeControlAbsent, ResultSupports,
				"every resolved package the control subject could occupy",
				"control-role subjects resolved absent inside a closed scope",
				CapScopeClosed),
		},
	},
	{
		ID:          CapScopeClosed,
		Description: "certifies that a source/shipping universe is closed and fully enumerated (import closure, module graph, shipping roots)",
		Implemented: true,
		LiveTools:   []string{"verify_code_absence", "symbol-unreachability"},
		Contracts: []ShapeContract{
			{
				Shape:          claimshape.ShapeClosureComplete,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				// A closure report is itself a closed-scope record:
				// reporting INCOMPLETE is complete evidence against
				// closure, so REFUTES admits at the existential floor.
				Refutes:       dirExistential,
				RequiredScope: "the relevant product universe (import closure / module graph)",
				CompleteMeans: "every member's edges enumerated, source hashed, no skipped member, no open dynamic exception, load budget intact",
				GapBlockers:   append([]string(nil), dynamicGaps...),
			},
			// The certificate also services other shapes as a conjunction
			// member; contractFor() lookups for them resolve to the same
			// SUPPORTS semantics.
			{
				Shape:          claimshape.ShapeSubjectAbsent,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				Refutes:        dirExistential,
				RequiredScope:  "the relevant product universe (import closure / module graph)",
				CompleteMeans:  "every member's edges enumerated, source hashed, no skipped member, no open dynamic exception, load budget intact",
				GapBlockers:    append([]string(nil), dynamicGaps...),
			},
			{
				Shape:          claimshape.ShapePathUnreachable,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				Refutes:        dirExistential,
				RequiredScope:  "the relevant product universe (import closure / module graph)",
				CompleteMeans:  "every member's edges enumerated, source hashed, no skipped member, no open dynamic exception, load budget intact",
				GapBlockers:    append([]string(nil), dynamicGaps...),
			},
			{
				Shape:          claimshape.ShapeControlAbsent,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				Refutes:        dirExistential,
				RequiredScope:  "the relevant product universe (import closure / module graph)",
				CompleteMeans:  "every member's edges enumerated, source hashed, no skipped member, no open dynamic exception, load budget intact",
				GapBlockers:    append([]string(nil), dynamicGaps...),
			},
		},
	},
	{
		ID:          CapReachability,
		Description: "call graph / may-call / dispatch analysis producing concrete reachability witnesses and gap inventories",
		Implemented: true,
		LiveTools: []string{"find_references", "find_callers", "find_may_callers", "find_dep_callers",
			"module_usage", "module_internal_reach", "interface_dispatch_sites", "dep_invocation_state",
			"run_govulncheck", "scan_dynamic"},
		Contracts: []ShapeContract{
			// path.reachable is existential: a concrete site proves it;
			// disproving it needs the negative engine — REFUTES is kept
			// at the universal floor so a zero-count PARTIAL probe can
			// never read as unreachability (Global Constraint 4).
			universalContract(claimshape.ShapePathReachable, ResultRefutes,
				"every reachable call site in the product scope",
				"the whole invocation universe was enumerated; only the negative engine can claim that"),
			// path.unreachable's SUPPORTS direction is universal; the
			// analyzer produces the existential counterexample only —
			// SUPPORTS is declared unreachable by this capability and
			// therefore never admits (the registry records the honest gap).
			{
				Shape:          claimshape.ShapePathUnreachable,
				NegativeResult: ResultSupports,
				Supports:       DirectionContract{MinCompleteness: evidencetools.CompletenessComplete, ClosedScope: true, Provenance: universal},
				Refutes:        dirExistential,
				RequiredScope:  "every reachable call site in the product scope",
				CompleteMeans:  "the whole invocation universe was enumerated — never satisfiable by this capability",
				GapBlockers:    append([]string(nil), dynamicGaps...),
			},
		},
	},
	{
		ID:          CapNegativeReachability,
		Description: "bounded negative reachability verification: every declared subject's invocation universe enumerated and closed",
		Implemented: true,
		LiveTools:   []string{"symbol-unreachability", "verify_code_absence"},
		Contracts: []ShapeContract{
			universalContract(claimshape.ShapePathUnreachable, ResultSupports,
				"every product root, caller class, dispatch site and module-internal path",
				"all inventories closed: references, may-call, dep-internal, dispatch, dynamic markers, gated refs, module reach",
				CapScopeClosed),
			{
				Shape:          claimshape.ShapePathReachable,
				NegativeResult: ResultRefutes,
				Supports:       dirExistential,
				Refutes:        dirUniversal,
				RequiredScope:  "every product root, caller class, dispatch site and module-internal path",
				CompleteMeans:  "all inventories closed: references, may-call, dep-internal, dispatch, dynamic markers, gated refs, module reach",
				GapBlockers:    append([]string(nil), dynamicGaps...),
			},
		},
	},
	{
		ID:          CapProvenanceTracer,
		Description: "bounded dataflow provenance: resolves a call argument's data origin at a site",
		Implemented: true,
		LiveTools:   []string{"trace_argument"},
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeInputOrigin, ResultSupports,
				"the traced call site and its bounded provenance closure",
				"every traced flow resolved to a definite origin class"),
			existentialContract(claimshape.ShapeInputAttackerControlled, ResultSupports,
				"the traced call site and its bounded provenance closure",
				"every traced flow resolved to a definite origin class; the deployment classifier adjudicates external vs attacker",
			),
		},
	},
	{
		ID:          CapGuardChecker,
		Description: "path-sensitive guard/control analysis: guards, validations, statically-dead branches around a call site",
		Implemented: true,
		LiveTools:   []string{"check_call_site_guard", "find_validations", "check_missing_call"},
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeControlPresent, ResultSupports,
				"the guard/validation inventory of the queried call site",
				"the named guard was observed on the site's path or in bounded caller frames"),
			{
				Shape:          claimshape.ShapeControlAbsent,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				Refutes:        dirExistential,
				RequiredScope:  "every path that can reach the subject",
				CompleteMeans:  "all paths to the subject enumerated and guard-free — a single-site check can never claim this",
				GapBlockers:    append([]string(nil), dynamicGaps...),
			},
		},
	},
	{
		ID:          CapConfigurationAnalyzer,
		Description: "configuration-fact analysis: assignments to configuration subjects and manifest content",
		Implemented: true,
		LiveTools:   []string{"field_assignments", "sensitive_fields"},
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeConfigurationPredicate, ResultSupports,
				"assignment/manifest sites of the configuration subject",
				"a concrete assignment or manifest entry was observed"),
		},
	},
	{
		ID:          CapBuildContext,
		Description: "build-context and source-constraint analysis: build-gated code, GOOS/GOARCH/tag exclusion under the recorded context",
		Implemented: true,
		LiveTools:   []string{"gated_refs", "get_product_snapshot"},
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeEnvironmentBuildGate, ResultSupports,
				"the recorded build context's excluded-file set",
				"a concrete build-gated reference was observed, or a snapshot build fact witnessed the gate"),
		},
	},
	{
		ID:          CapDeploymentClassifier,
		Description: "deployment/perimeter fact classification: inbound exposure surface from deployment materials",
		Implemented: true,
		Contracts: []ShapeContract{
			{
				Shape:          claimshape.ShapePerimeterExposure,
				NegativeResult: ResultSupports,
				// A public surface is positive evidence at the
				// existential floor; claiming no exposure requires a
				// closed deployment universe — conservative: only an
				// authoritatively scoped manifest counts.
				Supports:      dirExistential,
				Refutes:       dirUniversal,
				RequiredScope: "the deployment manifests of the analyzed product",
				CompleteMeans: "the deployment universe authoritatively scopes inbound reachability for the product",
				GapBlockers:   []string{"unattributed_deployment", "unknown_inbound_surface"},
			},
			existentialContract(claimshape.ShapeInputAttackerControlled, ResultSupports,
				"the deployment perimeter of the analyzed product",
				"the perimeter classifier resolved a definite inbound exposure for the input plane"),
		},
	},
	{
		ID:          CapFalsifierCertificate,
		Description: "a persisted checker-verified falsifier certificate as a negative-verification observation for its check shape",
		Implemented: true,
		Contracts: []ShapeContract{
			{
				Shape:          claimshape.ShapeSubjectAbsent,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				Refutes:        dirExistential,
				RequiredScope:  "the proof certificate's recorded coverage universe",
				CompleteMeans:  "the certificate passes the generic proof contract: checker basis, mandatory condition, COMPLETE coverage, expected==checked subjects, no open scope/dynamic markers, provenance pins, valid transitions",
				GapBlockers:    append(append([]string(nil), dynamicGaps...), "certificate_violation"),
			},
			{
				Shape:          claimshape.ShapePathUnreachable,
				NegativeResult: ResultSupports,
				Supports:       dirUniversal,
				Refutes:        dirExistential,
				RequiredScope:  "the proof certificate's recorded coverage universe",
				CompleteMeans:  "the certificate passes the generic proof contract: checker basis, mandatory condition, COMPLETE coverage, expected==checked subjects, no open scope/dynamic markers, provenance pins, valid transitions",
				GapBlockers:    append(append([]string(nil), dynamicGaps...), "certificate_violation"),
			},
		},
	},
	{
		ID:          CapEntailmentGraph,
		Description: "derived-claim evaluation over the claim graph (mandatory conditions, triage disposition)",
		Implemented: true, // Task 3 — the entailment graph and decision compiler implement it.
		Contracts: []ShapeContract{
			existentialContract(claimshape.ShapeDerivedMandatoryCondition, ResultSupports,
				"the premise claim set", "every premise claim admitted deterministically"),
			existentialContract(claimshape.ShapeDerivedTriageDisposition, ResultSupports,
				"the whole claim graph", "the decision compiler admitted a disposition"),
		},
	},
}

var capByID = func() map[string]*Capability {
	m := map[string]*Capability{}
	for i := range registry {
		if len(registry[i].GapSources) == 0 {
			registry[i].GapSources = append([]string(nil), commonGapSources...)
		}
		m[registry[i].ID] = &registry[i]
	}
	return m
}()

// Capability returns the registry entry for id, or nil.
func CapabilityByID(id string) *Capability { return capByID[id] }

// Registry returns the closed capability table in stable id order.
func Registry() []Capability {
	out := append([]Capability(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CapabilitiesFor returns the registry entries that declare a contract for
// shape, in stable id order.
func CapabilitiesFor(shape claimshape.Shape) []Capability {
	var out []Capability
	for _, c := range registry {
		if c.contractFor(shape) != nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Contract resolves the (capability, shape) admission contract.
func Contract(capID string, shape claimshape.Shape) *ShapeContract {
	c := capByID[capID]
	if c == nil {
		return nil
	}
	contract := c.contractFor(shape)
	if contract == nil {
		return nil
	}
	// All registered capabilities are predicate evidence by default;
	// scope.closed is the explicit conjunction-only exception for
	// predicate shapes.
	copy := *contract
	copy.PredicateEvidence = capID != CapScopeClosed || shape == claimshape.ShapeClosureComplete
	return &copy
}

// MissingCapabilities lists the capabilities a claim requires that the
// registry does not implement — the honest capability-gap channel.
func MissingCapabilities(c claimshape.CanonicalClaim) []string {
	var out []string
	for _, id := range c.RequiredCapabilities {
		cap := capByID[id]
		if cap == nil || !cap.Implemented {
			out = append(out, id)
		}
	}
	return out
}

// validateRegistry cross-checks the registry against the claimshape
// capability names — every id a canonical shape demands must resolve,
// and every contract must reference valid shapes. Called by tests and by
// package init so a registry drift fails loudly, never silently.
func validateRegistry() error {
	for _, c := range registry {
		seen := map[claimshape.Shape]bool{}
		for _, sc := range c.Contracts {
			if !sc.Shape.Valid() || sc.Shape == claimshape.ShapeUnsupported {
				return fmt.Errorf("verification: capability %s binds invalid shape %q", c.ID, sc.Shape)
			}
			if seen[sc.Shape] {
				return fmt.Errorf("verification: capability %s binds shape %q twice", c.ID, sc.Shape)
			}
			seen[sc.Shape] = true
			for _, also := range sc.Supports.AlsoRequires {
				if capByID[also] == nil {
					return fmt.Errorf("verification: %s/%s requires unknown capability %q", c.ID, sc.Shape, also)
				}
			}
			for _, also := range sc.Refutes.AlsoRequires {
				if capByID[also] == nil {
					return fmt.Errorf("verification: %s/%s requires unknown capability %q", c.ID, sc.Shape, also)
				}
			}
		}
	}
	for _, shape := range claimshape.CanonicalShapes() {
		for _, id := range claimshape.RequiredCapabilities(shape) {
			if capByID[id] == nil {
				return fmt.Errorf("verification: shape %s requires unregistered capability %q", shape, id)
			}
		}
	}
	return nil
}

func init() {
	if err := validateRegistry(); err != nil {
		panic(err)
	}
}
