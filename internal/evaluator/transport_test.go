package evaluator

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestServerTransportInputRoleMismatch_ServerRoleClientOnly(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleServer,
		},
	}
	// Pure client usage: product has outbound dial site into the module, no inbound listeners
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleServer),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE (server-side vulnerability on client-only product)", claim.Result)
	}
	if claim.Falsifier != domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("got falsifier %q, want %q", claim.Falsifier, domain.FalsifierProtocolRoleMismatch)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected negative verification VERIFIED, got %+v", claim.NegativeVerification)
	}
}

func TestServerTransportInputRoleMismatch_ClientRoleServerOnly(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleClient,
		},
	}
	// Pure server usage: inbound listener, zero dial sites
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "inbound",
		Kind:      "listener",
		Target:    "net.Listen",
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleClient),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE (client-side vulnerability on server-only product)", claim.Result)
	}
	if claim.Falsifier != domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("got falsifier %q, want %q", claim.Falsifier, domain.FalsifierProtocolRoleMismatch)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected negative verification VERIFIED, got %+v", claim.NegativeVerification)
	}
}

func TestServerTransportInputRoleMatching_ServerWithInbound(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleServer,
		},
	}
	// Server role and server exposure: not falsified
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "inbound",
		Kind:      "listener",
		Target:    "net.Listen",
	})
	c.EvidenceGraph.CallPaths = []domain.CallPath{
		{
			Frames: []domain.CallSite{
				{Package: "example.com/netmod", Receiver: "Server", Function: "Serve"},
			},
		},
	}

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleServer),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("unexpected falsification: server role matched inbound listener")
	}
}

func TestServerTransportInputRoleMatching_ClientWithOutbound(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleClient,
		},
	}
	// Client role and outbound dial: not falsified by role mismatch
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleClient),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("unexpected falsification: client role matched outbound dial")
	}
}

func TestServerTransportInputRoleMismatch_ClientRoleNoListenersNoOutbound(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleClient,
		},
	}
	// No inbound listeners, no outbound calls: product is not a server, so client role should NOT be falsified
	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleClient),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("unsafe falsification: product without inbound listeners should not falsify client-side vulnerability")
	}
}

func TestServerTransportInputRoleMatching_ClientWithModuleUsageNonDial(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleClient,
		},
	}
	// Pure server inbound listener present
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "inbound",
		Kind:      "listener",
		Target:    "net.Listen",
	})
	// But product calls module via non-dial API (Get/Query)
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Callee:      "example.com/netmod.Get",
		ModuleOwner: "example.com/netmod",
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleClient),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("unexpected falsification: module usage with Get should be recognized as outbound transport")
	}
}

func TestServerTransportInputRoleMatching_ClientWithCallPathNonDial(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Exploit: &domain.ExploitModel{
			ProtocolRole: domain.ProtocolRoleClient,
		},
	}
	// Pure server inbound listener present
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "inbound",
		Kind:      "listener",
		Target:    "net.Listen",
	})
	// But product call path reaches package of module
	c.EvidenceGraph.CallPaths = []domain.CallPath{
		{
			Frames: []domain.CallSite{
				{Package: "example.com/netmod", Function: "ProcessResponse"},
			},
		},
	}

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource:  domain.InputPeer,
			domain.ParamProtocolRole: string(domain.ProtocolRoleClient),
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierProtocolRoleMismatch {
		t.Fatalf("unexpected falsification: call path reaching module package should be recognized as outbound transport")
	}
}

func TestServerTransportInput_ConfiguredOutboundBasisConfigOrigin(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
	}
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
		Scope:     domain.ScopeConfigured,
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource: domain.InputPeer,
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got result %s, want FALSE", claim.Result)
	}
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure {
		t.Fatalf("got falsifier %q, want %q", claim.Falsifier, domain.FalsifierTrustedInfrastructure)
	}
	if claim.FalsifierBasis != domain.BasisConfigOrigin {
		t.Fatalf("got basis %q, want %q", claim.FalsifierBasis, domain.BasisConfigOrigin)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected negative verification VERIFIED, got %+v", claim.NegativeVerification)
	}
	wantNotes := "outbound destination endpoints are statically configured or loaded from trusted configuration (config-origin)"
	if claim.NegativeVerification.Notes != wantNotes {
		t.Fatalf("got notes %q, want %q", claim.NegativeVerification.Notes, wantNotes)
	}
}

func TestServerTransportInput_StaticOutboundBasisConfigOrigin(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
	}
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
		Scope:     domain.ScopeStatic,
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource: domain.InputPeer,
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got result %s, want FALSE", claim.Result)
	}
	if claim.FalsifierBasis != domain.BasisConfigOrigin {
		t.Fatalf("got basis %q, want %q", claim.FalsifierBasis, domain.BasisConfigOrigin)
	}
}

func TestServerTransportInput_MixedScopeOutboundStaysDeclaredTrust(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: "example.com/netmod",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
	}
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
		Scope:     domain.ScopeConfigured,
	})
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Connect",
		Scope:     domain.ScopeUnknown,
	})

	cond := domain.Condition{
		ID:   "C-PEER-INPUT",
		Kind: domain.ConditionAttackerControl,
		Params: map[string]string{
			domain.ParamInputSource: domain.InputPeer,
		},
	}

	claim := ServerTransportInput{}.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got result %s, want FALSE", claim.Result)
	}
	if claim.FalsifierBasis != domain.BasisDeclaredTrust {
		t.Fatalf("got basis %q, want %q (mixed scopes should not ground config-origin)", claim.FalsifierBasis, domain.BasisDeclaredTrust)
	}
}
