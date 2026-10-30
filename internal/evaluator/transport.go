package evaluator

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// ServerTransportInput evaluates ATTACKER_CONTROL / INPUT_CONSTRAINT for
// vulnerabilities whose reachable sink is a server-side transport loop
// (e.g. gRPC http2Server.HandleStreams).
//
// Authority comes from typed evidence only: a rooted transport input/trigger
// witness, a resolved argument-provenance origin, the admitted library
// public-API witness, package absence and operator-declared trust. A
// call-path frame inside the vulnerable module, a server-like receiver name
// and a product call into the module are nominations: they are retained as
// explanatory limitations and never establish that peer bytes reach the sink.
// With none of the typed routes the claim stays UNKNOWN.
type ServerTransportInput struct{}

func (ServerTransportInput) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionAttackerControl || cond.Kind == domain.ConditionInputConstraint
}

func (ServerTransportInput) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evaluateServerTransportInput(cond, c))
}

func evaluateServerTransportInput(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	// A proven library public-API payload binding is a typed positive that no
	// transport or trust heuristic may replace: delegate it to argument
	// provenance before trusted-peer/transport reasoning. Failed admission
	// leaves the existing logic untouched — the witness is never a negative.
	if _, _, ok := admittedLibraryWitness(cond, c); ok {
		return ArgumentOrigin{}.Evaluate(cond, c)
	}
	// A declared non-peer input source skips transport reasoning entirely:
	// the pattern asserts the input arrives as an argument or from config.
	if src := cond.Params[domain.ParamInputSource]; src == domain.InputArg || src == domain.InputConfig {
		return ArgumentOrigin{}.Evaluate(cond, c)
	}
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.ServerTransportInput",
	}
	// Subjects whose packages are not linked into the build graph cannot
	// consume peer input — absence outranks declared-trust (code-level
	// proof vs operator assertion) and blocks the unexported+peer-driven
	// TRUE heuristic below from firing on code that is not present.
	if set, ids, err := packageImportSet(c); err == nil {
		subjects := append([]domain.SymbolRef{}, cond.Subjects...)
		if cond.Subject != nil {
			subjects = append(subjects, *cond.Subject)
		}
		if len(subjects) > 0 {
			allAbsent := true
			var pkgs []string
			for _, s := range subjects {
				if s.Package == "" || set[s.Package] {
					allAbsent = false
				} else {
					pkgs = appendUnique(pkgs, s.Package)
				}
			}
			if allAbsent {
				claim.Result = domain.ClaimFalse
				claim.Falsifier = domain.FalsifierPackageAbsent
				claim.EvidenceIDs = ids
				claim.Explanation = fmt.Sprintf(
					"all subject package(s) (%s) are absent from the product's build graph (go list -deps); no transport input can reach defect code that is not linked in",
					strings.Join(pkgs, ", "))
				return claim
			}
		}
	}
	if c.Product.TrustedPeer && wantsPeerInput(cond, c.Vulnerability) {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierTrustedInfrastructure
		claim.FalsifierBasis = domain.BasisDeclaredTrust
		claim.Explanation = "deployment infrastructure declared trusted peer communication (--trusted-peer): network traffic and remote peers/brokers are authenticated and trusted"
		claim.NegativeVerification = &domain.NegativeVerification{
			Status: domain.NegativeVerified,
			Notes:  "deployment infrastructure declared trusted peer communication (--trusted-peer)",
		}
		if HasConfigOriginOutbound(c, c.Vulnerability.Module) {
			claim.FalsifierBasis = domain.BasisConfigOrigin
			claim.Explanation = "outbound destination endpoints are statically configured or loaded from trusted configuration: remote backends are operator-managed"
			claim.NegativeVerification = &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Notes:  "outbound destination endpoints are statically configured or loaded from trusted configuration (config-origin)",
			}
		}
		return claim
	}
	module := c.Vulnerability.Module
	// A recorded rooted-transport witness is the authoritative route: it
	// either earns the claim or reports the typed proof gap. It is checked
	// after package absence and declared trust so those code-level and
	// policy-level falsifiers keep their existing priority. An attempted
	// proof never falls back to a structural observation: a mechanism witness
	// that does not bind its trigger leaves INPUT_CONSTRAINT unknown with the
	// typed gap, and the input embedded in a trigger witness is the same
	// rooted binding for ATTACKER_CONTROL.
	if input, trigger, attempted := transportProofWitnesses(c); attempted {
		switch cond.Kind {
		case domain.ConditionInputConstraint:
			return evaluateTransportTriggerCondition(cond, c, trigger)
		case domain.ConditionAttackerControl:
			return evaluateTransportInputCondition(cond, c, transportInputWitness(input, trigger))
		}
	}

	// Structural observations only. A frame inside the vulnerable module or a
	// product call into its API is a nomination: a receiver/function name and
	// a module-API call do not bind peer bytes to the sink, so neither may
	// establish attacker control. They stay in the claim as explanatory
	// limitations while bounded origin tracing decides.
	var observations []string
	var frames []string
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			if isServerTransportFrame(fr, module) {
				frames = appendUnique(frames, frameName(fr))
			}
		}
	}
	if len(frames) > 0 {
		observations = append(observations, fmt.Sprintf(
			"observed server-side transport frame(s) %s; a frame or receiver name is a nomination, so only a rooted transport witness establishes that peer bytes reach the affected sink",
			strings.Join(frames, ", ")))
	} else if subs := linkedOnly(c, reachabilitySubjects(cond, c)); len(subs) > 0 &&
		allUnexported(subs) && wantsPeerInput(cond, c.Vulnerability) {
		if usages, _ := subjectModuleUsages(c, subs); len(usages) > 0 {
			observations = append(observations, fmt.Sprintf(
				"product calls the subject-owning module's API at %d site(s); unexported transport internals execute inside its peer-driven path, but no traced path binds peer input to the sink",
				len(usages)))
		}
	}

	// Bounded origin tracing decides what the evidence proves: a resolved
	// external origin is a typed positive and an unresolved trace stays
	// UNKNOWN. Declared trust was already applied above, where the condition
	// itself declared peer input.
	out := (ArgumentOrigin{}).Evaluate(cond, c)
	out.Limitations = append(out.Limitations, observations...)
	return out
}

// isServerTransportFrame reports whether a call-path frame inside the
// vulnerable module looks like a server-side transport routine. It is a
// nomination used only for observations and explanations: a receiver or
// function name cannot establish that the frame reads peer-controlled bytes,
// so no claim may rest on it. Product-side helpers coincidentally named
// Serve/Accept do not qualify — only frames within the vuln module.
func isServerTransportFrame(fr domain.CallSite, module string) bool {
	if module != "" && fr.Package != module && !strings.HasPrefix(fr.Package, module+"/") {
		return false
	}
	if strings.Contains(fr.Receiver, "Server") || strings.Contains(fr.Receiver, "server") {
		return true
	}
	switch fr.Function {
	case "Serve", "ServeHTTP", "Accept", "HandleStreams", "NewServerTransport", "newServerTransport":
		return true
	}
	return false
}

// remoteInputRe hints that the condition is about peer/network-controlled
// input — a nomination used by the dep-scope collection gate and the
// explanatory observations, never by a claim.
var remoteInputRe = regexp.MustCompile(`(?i)remote|peer|server|broker|network|unauthenticated|frame|packet|malformed`)

func describesRemoteInput(cond domain.Condition, v domain.Vulnerability) bool {
	return remoteInputRe.MatchString(cond.Description) ||
		remoteInputRe.MatchString(v.Summary) ||
		remoteInputRe.MatchString(v.Description)
}

// WantsPeerInput exposes the peer-input predicate for the evidence
// collector's dep-scope gate — same semantics as wantsPeerInput.
func WantsPeerInput(cond domain.Condition, v domain.Vulnerability) bool {
	return wantsPeerInput(cond, v)
}

// wantsPeerInput reports whether the condition is about peer-controlled
// input. An explicit input_source param outranks the description regex —
// patterns declare peer input even when the condition text carries no
// remote-signal words. The predicate gates evidence collection and the
// explanatory observations; it establishes no claim by itself.
func wantsPeerInput(cond domain.Condition, v domain.Vulnerability) bool {
	if cond.Params[domain.ParamInputSource] == domain.InputPeer {
		return true
	}
	return describesRemoteInput(cond, v)
}

func frameName(fr domain.CallSite) string {
	if fr.Receiver != "" {
		return fr.Package + "." + fr.Receiver + "." + fr.Function
	}
	return fr.Package + "." + fr.Function
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func isTargetingModule(target, callee, pkg, owner, module string) bool {
	if module == "" {
		return false
	}
	if owner != "" {
		return owner == module
	}
	return matchesModule(target, module) ||
		matchesModule(callee, module) ||
		matchesModule(pkg, module)
}

func matchesModule(s, module string) bool {
	if s == "" || module == "" {
		return false
	}
	return s == module || strings.HasPrefix(s, module+"/") || strings.HasPrefix(s, module+".")
}

// HasConfigOriginOutbound reports whether outbound exposure facts targeting module exist
// in the analysis case and all of them have ScopeConfigured or ScopeStatic.
func HasConfigOriginOutbound(c *domain.AnalysisCase, module string) bool {
	if c == nil {
		return false
	}
	var count int
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if (f.Direction == "outbound" || f.Kind == "dial") && f.Direction != "inbound" {
			if module == "" || isTargetingModule(f.Target, f.Callee, f.Package, f.ModuleOwner, module) {
				count++
				if f.Scope != domain.ScopeConfigured && f.Scope != domain.ScopeStatic {
					return false
				}
			}
		}
	}
	return count > 0
}
