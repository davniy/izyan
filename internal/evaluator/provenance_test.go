package evaluator

import (
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func TestArgumentOrigin_ConstantPayloadSurvivesIncompleteClosure(t *testing.T) {
	ao := ArgumentOrigin{}
	cond := domain.Condition{
		ID:       "C-PEER-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: -1,
		Params:   map[string]string{domain.ParamInputSource: "peer"},
	}
	c := &domain.AnalysisCase{
		Product:       admittedProduct(),
		Vulnerability: domain.Vulnerability{Module: "gopkg.in/yaml.v2"},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{
					ConditionID:     cond.ID,
					Arg:             0,
					Origin:          domain.OriginConstant,
					Summary:         "const baseline",
					PayloadUnproven: false,
					Sink: domain.CallSite{
						Package:  "example.com/product",
						Function: "load",
						File:     "main.go",
						Line:     26,
					},
				},
			},
			Evidence: []domain.Evidence{
				{
					ID:   "DF-01",
					Kind: domain.EvidenceDataFlow,
				},
			},
			// Ingress closure with unresolved internal parser items
			IngressClosures: []domain.IngressClosure{
				{
					ConditionID: "C-PEER-INPUT",
					Module:      "gopkg.in/yaml.v2",
					Complete:    false,
					Blockers:    []string{"unmodeled external call"},
				},
			},
		},
	}

	claim := ao.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("expected ClaimFalse for constant payload, got %s (limitations: %v)", claim.Result, claim.Limitations)
	}
	if claim.Falsifier != domain.FalsifierConstantOrGeneratedInput {
		t.Fatalf("expected FalsifierConstantOrGeneratedInput, got %s", claim.Falsifier)
	}
}

// Configuration provenance is a deterministic code fact, not the policy
// assertion: without an admitted config-trust assumption it cannot ground
// a trusted-infrastructure falsifier.
func TestArgumentOrigin_LocalConfigurationWithoutAssumptionStaysUnknown(t *testing.T) {
	ao := ArgumentOrigin{}
	cond := domain.Condition{
		ID:       "C-PEER-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: -1,
		Params:   map[string]string{domain.ParamInputSource: "peer"},
	}
	c := &domain.AnalysisCase{
		Product:       admittedProduct(),
		Vulnerability: domain.Vulnerability{Module: "gopkg.in/yaml.v2"},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{
					ConditionID:     cond.ID,
					Arg:             0,
					Origin:          domain.OriginConfiguration,
					Summary:         "os.ReadFile",
					PayloadUnproven: false,
					Sink: domain.CallSite{
						Package:  "example.com/product",
						Function: "load",
						File:     "main.go",
						Line:     28,
					},
				},
			},
			Evidence: []domain.Evidence{
				{
					ID:   "DF-01",
					Kind: domain.EvidenceDataFlow,
				},
			},
		},
	}

	claim := ao.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("configuration origin without an assumption produced %s/%s (limitations: %v)",
			claim.Result, claim.Falsifier, claim.Limitations)
	}
}

// --trusted-peer is a deployment assertion about peers/services; it is
// never a substitute for the declared administrator-configuration trust
// policy. A configuration-only origin under a trusted-peer declaration
// stays UNKNOWN.
func TestArgumentOrigin_TrustedPeerDoesNotSubstituteForConfigTrust(t *testing.T) {
	ao := ArgumentOrigin{}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: 1,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/transformer", Symbol: "QueryAll"}},
	}
	c := &domain.AnalysisCase{
		Product:       admittedSnapshot(domain.ProductSnapshot{TrustedPeer: true}),
		Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{cond},
		},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{
					ConditionID: cond.ID,
					Arg:         1,
					Origin:      domain.OriginConfiguration,
					Summary:     "Settings.Expression (mapstructure:expression)",
					Sink: domain.CallSite{
						Package: "example.com/product", Function: "run",
						File: "main.go", Line: 22,
					},
				},
			},
		},
	}
	claim := ao.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("trusted-peer substituted for config-trust: got %s/%s", claim.Result, claim.FalsifierBasis)
	}
	if claim.FalsifierBasis != "" || len(claim.AssumptionIDs) != 0 {
		t.Fatalf("unexpected basis/assumption on UNKNOWN claim: %q %v", claim.FalsifierBasis, claim.AssumptionIDs)
	}
}

// A post-reach claim that no longer matches the recorded closure is
// demoted to UNKNOWN and loses its falsifier, basis, assumption ids and
// pre-filled negative verification — no stale policy reference survives.
func TestClosureGate_DemotedConfigClaimDropsAssumption(t *testing.T) {
	cond := domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 1,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/transformer", Symbol: "QueryAll"}},
	}
	c := &domain.AnalysisCase{
		Product:       admittedProduct(),
		Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
		Exploit:       &domain.ExploitModel{MandatoryConditions: []domain.Condition{cond}},
	}
	claim := domain.Claim{
		ConditionID:    cond.ID,
		Result:         domain.ClaimFalse,
		Falsifier:      domain.FalsifierTrustedInfrastructure,
		FalsifierBasis: domain.BasisConfigOrigin,
		AssumptionIDs:  []string{"ASM-CONFIG-TRUST"},
		Producer:       postReachProducer,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}
	out := closureGate(c, claim, nil, nil, 0, nil)
	if out.Result != domain.ClaimUnknown {
		t.Fatalf("stale claim kept %s, want UNKNOWN", out.Result)
	}
	if out.Falsifier != "" || out.FalsifierBasis != "" || out.AssumptionIDs != nil || out.NegativeVerification != nil {
		t.Fatalf("demoted claim retained proof fields: %+v", out)
	}
}
