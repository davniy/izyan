package evaluator

import (
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// TestTransportOrdinaryArgumentNotRewrittenByTransportWitness pins requirement
// (3): an ordinary argument condition is decided by argument provenance, and an
// unrelated transport witness neither satisfies it nor rewrites its params. The
// peer condition on the same case is admitted by that witness, so the control is
// live rather than vacuous.
func TestTransportOrdinaryArgumentNotRewrittenByTransportWitness(t *testing.T) {
	product := admittedSnapshot(domain.ProductSnapshot{Repository: "/repo", Commit: "abc123"})
	input := transportTestInput(product)
	model := transportTestModel()
	c := transportTestCase(product, model, transportTestEvidence(input, nil))

	subject := domain.SymbolRef{Package: "example.com/netmod", Symbol: "HandleStreams"}
	ordinary := domain.Condition{
		ID:          "C-INPUT",
		Kind:        domain.ConditionAttackerControl,
		Mandatory:   true,
		Subjects:    []domain.SymbolRef{subject},
		ArgIndex:    0,
		Description: "attacker controls arg 0 of the affected sink",
		Params:      map[string]string{domain.ParamInputSource: domain.InputArg},
	}

	claim := ServerTransportInput{}.Evaluate(ordinary, c)
	if claim.Producer != "evaluator.ArgumentOrigin" {
		t.Fatalf("ordinary argument condition must delegate to argument provenance, producer=%q", claim.Producer)
	}
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("an unrelated transport witness must not satisfy the ordinary argument condition: %+v", claim)
	}
	if claim.ControlBasis == domain.ControlBasisTransportPeerInput {
		t.Fatalf("transport control basis leaked into the ordinary argument claim: %+v", claim)
	}
	if len(ordinary.Params) != 1 || ordinary.Params[domain.ParamInputSource] != domain.InputArg {
		t.Fatalf("condition params were rewritten by transport reasoning: %+v", ordinary.Params)
	}

	// Control: the same witness does admit the genuine peer condition.
	peer := ServerTransportInput{}.Evaluate(transportTestCondition(model, "C-PEER-INPUT"), c)
	if peer.Result != domain.ClaimTrue || peer.ControlBasis != domain.ControlBasisTransportPeerInput {
		t.Fatalf("control: the peer condition should be admitted by the recorded witness: %+v", peer)
	}
}

// TestLibraryInputRejectsGenuinePeerCondition pins requirement (4): a library
// public-API witness cannot satisfy a peer-input condition, while the same
// witness still admits the identical condition on an ordinary argument.
func TestLibraryInputRejectsGenuinePeerCondition(t *testing.T) {
	c := libraryAdmissionCase(t)
	ordinary := c.Exploit.MandatoryConditions[0]
	if _, _, ok := admittedLibraryWitness(ordinary, c); !ok {
		t.Fatal("baseline: the recorded witness must admit the ordinary argument condition")
	}

	peer := ordinary
	peer.Params = map[string]string{domain.ParamInputSource: domain.InputPeer}
	if _, _, ok := admittedLibraryWitness(peer, c); ok {
		t.Fatal("library witness must not satisfy a genuine peer condition")
	}
	claim := ServerTransportInput{}.Evaluate(peer, c)
	if claim.ControlBasis == domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("library control basis leaked into a peer condition: %+v", claim)
	}
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("peer condition became TRUE without peer evidence: %+v", claim)
	}
}
