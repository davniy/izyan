package domain

// ScopeTransportPeer is the orthogonal exploitability scope of a conclusion
// that a client of the product's affected transport can supply the triggering
// input. It is a scope, not a verdict and not a threat profile: the verdict
// stays EXPLOITABLE under the selected profile, and deployed attacker access to
// that transport remains a separate, unevaluated question.
//
// It is deliberately disjoint from ScopeLibraryAPI: a transport-peer claim is
// not exempt from cluster-perimeter rewriting, and a library-API witness is
// never widened by transport reasoning.
const ScopeTransportPeer ExploitabilityScope = "transport-peer"

// ControlBasisTransportPeerInput marks the mandatory TRUE attacker-control
// claim that grounds ScopeTransportPeer: the bytes reaching the vulnerable sink
// are consumed by an active server transport from its peer, so the peer selects
// them by construction. It never asserts deployment exposure, and a supporting
// exposure observation may not carry it.
const ControlBasisTransportPeerInput ControlBasis = "transport-peer-input"

// TransportPeerScopeLimitation is the mandatory limitation attached to every
// transport-peer-scoped conclusion, verbatim, in machine-readable output.
const TransportPeerScopeLimitation = "Transport-peer scope: a client of the product's affected transport can supply the triggering input. Whether an adversary can access that transport—through socket permissions, placement, ingress or authentication—is not established."

// TransportPeerScopeAdmitted reports whether an admitted mandatory TRUE
// transport-input claim grounds ScopeTransportPeer. The claim must belong to
// the mandatory conjunction and carry ControlBasisTransportPeerInput; a
// supporting claim, an exposure fact or a listener observation alone never
// scopes a verdict. It mirrors the library-API admission shape so the evaluator
// keeps one scope rule.
func TransportPeerScopeAdmitted(mandatory []ConditionID, claims []Claim) bool {
	if len(mandatory) == 0 || len(claims) == 0 {
		return false
	}
	for _, claim := range claims {
		if claim.Result != ClaimTrue || claim.ControlBasis != ControlBasisTransportPeerInput {
			continue
		}
		for _, id := range mandatory {
			if claim.ConditionID == id {
				return true
			}
		}
	}
	return false
}

// TransportPeerScopeLimitations returns a fresh slice holding the mandatory
// transport-peer limitation, so producers cannot alias one shared backing
// array.
func TransportPeerScopeLimitations() []string {
	return []string{TransportPeerScopeLimitation}
}

// KnownExploitabilityScope reports whether scope is a frozen scope constant.
func KnownExploitabilityScope(scope ExploitabilityScope) bool {
	switch scope {
	case ScopeLibraryAPI, ScopeTransportPeer:
		return true
	default:
		return false
	}
}

// ExploitabilityScopeLimitations returns the mandatory limitation text a
// conclusion scoped to scope must carry, or nil for an unscoped conclusion. The
// returned slice is fresh on every call.
func ExploitabilityScopeLimitations(scope ExploitabilityScope) []string {
	switch scope {
	case ScopeTransportPeer:
		return TransportPeerScopeLimitations()
	case ScopeLibraryAPI:
		return []string{LibraryAPIScopeLimitation}
	default:
		return nil
	}
}
