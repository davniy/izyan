package evaluator

import (
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// Exposure evaluates check=exposure conditions — a supporting factor
// that turns the standing "peer exposure is a deployment property"
// caveat into resolved facts: which addresses listeners bind and which
// endpoints outbound calls into the vulnerable module reach.
//
//	TRUE — at least one exposure fact was resolved; the facts are
//	  enumerated in the explanation and their scopes in limitations.
//	UNKNOWN — the scan ran but resolved no facts, or never ran.
//
// The evaluator never returns FALSE: absence of a listener/dial site is
// not proof the surface is unreachable (deployment can add proxies and
// ingress) — it stays UNKNOWN.
type Exposure struct{}

func (Exposure) CanEvaluate(cond domain.Condition) bool {
	return cond.Params[domain.ParamCheck] == domain.CheckExposure
}

func (Exposure) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evaluateExposure(cond, c))
}

func evaluateExposure(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.Exposure",
	}
	var evIDs []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if strings.HasPrefix(e.Source, "source index + repo config scan: exposure") {
			evIDs = appendUniqueID(evIDs, e.ID)
		}
	}
	claim.EvidenceIDs = evIDs
	facts := c.EvidenceGraph.ExposuresList()
	if len(facts) == 0 {
		if len(evIDs) == 0 {
			claim.Limitations = append(claim.Limitations, "exposure scan did not run")
		} else {
			claim.Limitations = append(claim.Limitations,
				"no inbound listener binds or outbound endpoints into the vulnerable module resolved")
		}
		return claim
	}
	var parts []string
	var inboundPublic, inboundLocal, outboundConfigured bool
	var localInbound []domain.ExposureFact
	for _, f := range facts {
		p := f.Direction + " " + f.Target
		if f.Address != "" {
			p += "=" + f.Address
		}
		if f.Scope != "" && f.Scope != domain.ScopeUnknown {
			p += " (" + f.Scope + ")"
		}
		parts = append(parts, p)
		switch f.Scope {
		case domain.ScopeAllInterfaces, domain.ScopeHostSpecific:
			inboundPublic = true
		case domain.ScopeLoopback, domain.ScopeUnix:
			inboundLocal = true
			localInbound = append(localInbound, f)
		case domain.ScopeConfigured:
			outboundConfigured = true
		}
	}
	if cond.Params[domain.ParamScope] == "public" && inboundLocal && !inboundPublic {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierLoopbackOnly
		// A loopback conclusion drawn only from deployment manifests is a
		// declared deployment-policy fact: no build selection can change
		// it. A listener found in loaded product code is code-selected and
		// stays build-dependent.
		if allDeploymentFacts(localInbound) {
			claim.FalsifierBasis = domain.BasisDeployment
		}
		claim.Explanation = "all resolved inbound network binds are loopback/cluster-internal; public network exposure falsified: " + strings.Join(parts, "; ")
		return claim
	}
	claim.Result = domain.ClaimTrue
	claim.Explanation = "network exposure resolved: " + strings.Join(parts, "; ")
	if inboundLocal && !inboundPublic {
		claim.Limitations = append(claim.Limitations,
			"all resolved inbound binds are loopback/unix — remote reachability depends on ingress/proxy outside the code")
	}
	if outboundConfigured {
		claim.Limitations = append(claim.Limitations,
			"outbound endpoint(s) are operator-configured — trusting the configured service is a deployment decision")
	}
	return claim
}

// allDeploymentFacts reports whether every fact came from a deployment
// manifest (structural provenance of the exposure collector), not from
// product code loaded under a build context.
func allDeploymentFacts(facts []domain.ExposureFact) bool {
	if len(facts) == 0 {
		return false
	}
	for _, f := range facts {
		if !deploymentFact(f) {
			return false
		}
	}
	return true
}

// deploymentFact identifies a deployment-manifest exposure record by its
// collector-written shape, never by explanation text: manifest records carry
// the manifest/template address source or a deployment resource kind, while
// code listeners carry a Go call site and its literal/const/env/config
// address source.
func deploymentFact(f domain.ExposureFact) bool {
	if strings.HasPrefix(f.AddressSource, "manifest ") || strings.HasPrefix(f.AddressSource, "template ") {
		return true
	}
	if f.Kind == "deployment" || f.Kind == "auth-middleware" {
		return true
	}
	return strings.HasPrefix(f.Kind, "k8s:") || strings.HasPrefix(f.Kind, "compose:")
}
