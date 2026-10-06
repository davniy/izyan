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
