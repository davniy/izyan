package evaluator

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// TestProtocolRoleNameCannotFalsify pins the removal of the role-mismatch
// FALSE path. The protocol role is detected from the record's prose and
// fix-diff symbol names — a nomination, not evidence — and no typed
// protocol-role witness exists, so neither a condition param nor the model's
// detected role may turn a transport input condition into a negative. A
// persisted FALSE from that retired path is demoted at the shared verdict
// boundary instead of grounding NO_EXPLOIT_PATH_FOUND.
func TestProtocolRoleNameCannotFalsify(t *testing.T) {
	cases := []struct {
		name  string
		role  domain.ProtocolRole
		facts []domain.ExposureFact
	}{
		{
			name: "server role on a client-only product",
			role: domain.ProtocolRoleServer,
			facts: []domain.ExposureFact{{
				Direction: "outbound",
				Kind:      "dial",
				Target:    "example.com/netmod.Dial",
			}},
		},
		{
			name: "client role on a server-only product",
			role: domain.ProtocolRoleClient,
			facts: []domain.ExposureFact{{
				Direction: "inbound",
				Kind:      "listener",
				Target:    "net.Listen",
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &domain.AnalysisCase{
				Vulnerability: domain.Vulnerability{Module: "example.com/netmod"},
				Exploit:       &domain.ExploitModel{ProtocolRole: tc.role},
			}
			c.Product = admittedSnapshot(c.Product)
			for _, fact := range tc.facts {
				c.EvidenceGraph.AddExposure(fact)
			}
			cond := domain.Condition{
				ID:   "C-PEER-INPUT",
				Kind: domain.ConditionAttackerControl,
				Params: map[string]string{
					domain.ParamInputSource:  domain.InputPeer,
					domain.ParamProtocolRole: string(tc.role),
				},
			}
			claim := ServerTransportInput{}.Evaluate(cond, c)
			if claim.Result == domain.ClaimFalse {
				t.Fatalf("a prose-derived role falsified the condition: %+v", claim)
			}
			if claim.Falsifier != "" || claim.NegativeVerification != nil {
				t.Fatalf("a prose-derived role produced a negative record: %+v", claim)
			}
			if claim.Result != domain.ClaimUnknown {
				t.Fatalf("result=%s, want UNKNOWN without a typed role witness", claim.Result)
			}
		})
	}

	// Replay: the retired path wrote a VERIFIED protocol-role-mismatch FALSE.
	// The verdict boundary demotes it, so an unestablished role cannot decide
	// a negative.
	cond := domain.Condition{
		ID:     "C-PEER-INPUT",
		Kind:   domain.ConditionAttackerControl,
		Params: map[string]string{domain.ParamInputSource: domain.InputPeer},
	}
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{cond}}
	saved := []domain.Claim{{
		ID:          "CL-C-PEER-INPUT",
		ConditionID: cond.ID,
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierProtocolRoleMismatch,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
			Notes:  "protocol role mismatch: server-side vulnerability unreached on pure-client usage",
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdictInput(res, model, saved, nil, domain.Vulnerability{})
	if got.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("a saved role-mismatch FALSE grounded NO_EXPLOIT_PATH_FOUND: %+v", got.Verdict)
	}
	if got.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%s, want INCONCLUSIVE", got.Verdict.Verdict)
	}
	found := false
	for _, gap := range got.Gaps {
		if gap.Code == domain.GapMeasurementNotCompleted && gap.ConditionID == cond.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("demotion did not record the typed measurement gap: %+v", got.Gaps)
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
	c.Product = admittedSnapshot(c.Product)
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
	c.Product = admittedSnapshot(c.Product)
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
	c.Product = admittedSnapshot(c.Product)
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

// --- rooted transport witness fixtures -------------------------------------

func transportTestSite(kind domain.TransportSiteKind, pkg, sym string, line int) domain.TransportSite {
	return domain.TransportSite{
		Kind:   kind,
		Symbol: domain.SymbolRef{Package: pkg, Symbol: sym},
		CallSite: domain.CallSite{
			File:     "/src/" + pkg + "/" + sym + ".go",
			Line:     line,
			Package:  pkg,
			Function: sym,
		},
		Digest: "sha256:" + strings.Repeat("a", 64),
		Source: "func " + sym + "() {}",
	}
}

func transportTestInput(product domain.ProductSnapshot) *domain.TransportInputWitness {
	const module = "example.com/netmod"
	root := transportTestSite(domain.TransportSiteRoot, "example.com/app", "main", 10)
	serve := transportTestSite(domain.TransportSiteServe, module, "Server.Serve", 42)
	return &domain.TransportInputWitness{
		Schema:   domain.TransportProofSchema,
		Record:   domain.RecordPin{RecordID: "GO-TEST-0001", DocumentDigest: "sha256:" + strings.Repeat("b", 64), SourceLocator: "file:///records/GO-TEST-0001.json"},
		Module:   module,
		Affected: []domain.SymbolRef{{Package: module, Symbol: "Server.Serve"}},
		Build:    domain.EffectiveBuildContext(product),
		Root:     domain.TransportRoot{Package: "example.com/app", Production: true, Site: root},
		Chain: []domain.TransportSite{
			root,
			transportTestSite(domain.TransportSiteConstruction, "example.com/app", "serve", 20),
		},
		Server: domain.TransportServerBinding{
			Construction: transportTestSite(domain.TransportSiteConstruction, module, "NewServer", 38),
			Serve:        serve,
			SameValue:    true,
		},
		Listener: domain.TransportListenerBinding{
			Creation:  transportTestSite(domain.TransportSiteListenerCreation, "example.com/app", "createListener", 36),
			Serve:     serve,
			SameValue: true,
		},
		Transport: []domain.TransportSite{
			serve,
			transportTestSite(domain.TransportSiteTransportEntry, module, "HandleStreams", 120),
		},
		Artifacts:   []domain.TransportArtifact{{Path: "/src/main.go", Digest: "sha256:" + strings.Repeat("c", 64)}},
		EvidenceIDs: []domain.EvidenceID{"EV-input"},
	}
}

func transportTestTrigger(product domain.ProductSnapshot, input *domain.TransportInputWitness) *domain.TransportTriggerWitness {
	const module = "example.com/netmod"
	input.Mechanism = domain.MechanismHTTP2RapidReset
	obligations := make([]domain.TransportTriggerObligation, 0, len(domain.TransportTriggerObligationIDs))
	for _, id := range domain.TransportTriggerObligationIDs {
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        id,
			Satisfied: true,
			Sites:     []domain.TransportSite{transportTestSite(domain.TransportSiteFrameLoop, module, "HandleStreams", 120)},
			Detail:    "bound",
		})
	}
	return &domain.TransportTriggerWitness{
		Schema:      domain.TransportProofSchema,
		Mechanism:   domain.MechanismHTTP2RapidReset,
		Record:      input.Record,
		Module:      module,
		Build:       domain.EffectiveBuildContext(product),
		Input:       *input,
		Obligations: obligations,
		Fix: domain.TransportFixBinding{
			URI:              "https://example.com/fix/f2180b4d",
			Digest:           "sha256:" + strings.Repeat("d", 64),
			DiffDigest:       "sha256:" + strings.Repeat("e", 64),
			EnforcementNames: []string{"handlerQuota"},
		},
		EvidenceIDs: []domain.EvidenceID{"EV-trigger"},
	}
}

func transportTestModel() domain.ExploitModel {
	subject := domain.SymbolRef{Package: "example.com/netmod", Symbol: "HandleStreams"}
	return domain.ExploitModel{
		ProtocolRole: domain.ProtocolRoleServer,
		RootCauses:   []domain.SymbolRef{subject},
		MandatoryConditions: []domain.Condition{
			{
				ID:        "C-PEER-INPUT",
				Kind:      domain.ConditionAttackerControl,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{subject},
				Params:    map[string]string{domain.ParamInputSource: domain.InputPeer},
			},
			{
				ID:        "C-CONSTRAINT",
				Kind:      domain.ConditionInputConstraint,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{subject},
				Params:    map[string]string{domain.ParamInputSource: domain.InputPeer},
			},
		},
	}
}

func transportTestEvidence(input *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness) []domain.Evidence {
	var out []domain.Evidence
	if input != nil {
		out = append(out, domain.Evidence{ID: "EV-input", Kind: domain.EvidenceCallPath, TransportInput: input})
	}
	if trigger != nil {
		out = append(out, domain.Evidence{ID: "EV-trigger", Kind: domain.EvidenceCallPath, TransportTrigger: trigger})
	}
	return out
}

func transportTestCase(product domain.ProductSnapshot, model domain.ExploitModel, evidence []domain.Evidence) *domain.AnalysisCase {
	m := model
	c := &domain.AnalysisCase{
		ID:            "CASE-TRANSPORT",
		Vulnerability: domain.Vulnerability{Module: "example.com/netmod"},
		Product:       product,
		Exploit:       &m,
	}
	for _, ev := range evidence {
		c.EvidenceGraph.AddEvidence(ev)
	}
	return c
}

func transportTestCondition(model domain.ExploitModel, id domain.ConditionID) domain.Condition {
	for _, cond := range model.MandatoryConditions {
		if cond.ID == id {
			return cond
		}
	}
	return domain.Condition{ID: id}
}

// TestTransportTriggerAdmission is the transport claim-admission table: a
// complete rooted input witness earns attacker control, a complete
// source/fix-bound trigger witness earns the mechanism constraint, and every
// missing, mismatched or prevented obligation leaves the claim UNKNOWN with
// its typed gap instead of a positive or a FALSE.
func TestTransportTriggerAdmission(t *testing.T) {
	base := admittedSnapshot(domain.ProductSnapshot{Repository: "/repo", Commit: "abc123"})
	model := transportTestModel()

	type admissionCase struct {
		name        string
		withInput   bool
		withTrigger bool
		mutate      func(product *domain.ProductSnapshot, input *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness)
		wantInput   domain.ClaimResult
		wantTrigger domain.ClaimResult
		wantGap     domain.GapCode
	}

	cases := []admissionCase{
		{
			name:        "complete rooted input and source/fix-bound trigger are admitted",
			withInput:   true,
			withTrigger: true,
			wantInput:   domain.ClaimTrue,
			wantTrigger: domain.ClaimTrue,
		},
		{
			// No proof was attempted, so C-CONSTRAINT keeps its
			// non-transport evaluation. The input claim still cannot
			// become TRUE without the witness.
			name:        "no witness refuses the transport claim",
			wantInput:   domain.ClaimUnknown,
			wantTrigger: domain.ClaimUnknown,
		},
		{
			name:      "incomplete input witness is a typed input gap",
			withInput: true,
			mutate: func(_ *domain.ProductSnapshot, input *domain.TransportInputWitness, _ *domain.TransportTriggerWitness) {
				input.Listener.SameValue = false
			},
			wantInput:   domain.ClaimUnknown,
			wantTrigger: domain.ClaimUnknown,
		},
		{
			name:        "witness measured under another build is refused",
			withInput:   true,
			withTrigger: true,
			mutate: func(product *domain.ProductSnapshot, input *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness) {
				other := *product
				other.Commit = "def456"
				input.Build = domain.EffectiveBuildContext(other)
				trigger.Build = input.Build
			},
			wantInput:   domain.ClaimUnknown,
			wantTrigger: domain.ClaimUnknown,
			wantGap:     domain.GapTriggerProofIncomplete,
		},
		{
			name:        "unsatisfied fix obligation is a trigger proof gap",
			withInput:   true,
			withTrigger: true,
			mutate: func(_ *domain.ProductSnapshot, _ *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness) {
				for i := range trigger.Obligations {
					if trigger.Obligations[i].ID == domain.TransportObligationNoFixedQuota {
						trigger.Obligations[i].Satisfied = false
						trigger.Obligations[i].Sites = nil
						trigger.Obligations[i].Detail = "no fixed handler quota was bound"
					}
				}
			},
			wantInput:   domain.ClaimTrue,
			wantTrigger: domain.ClaimUnknown,
			wantGap:     domain.GapTriggerProofIncomplete,
		},
		{
			name:        "effective pre-dispatch quota refuses the trigger",
			withInput:   true,
			withTrigger: true,
			mutate: func(_ *domain.ProductSnapshot, _ *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness) {
				trigger.Controls = []domain.TransportControl{{
					Site:        transportTestSite(domain.TransportSiteControl, "example.com/app", "serve", 30),
					Disposition: domain.TransportControlPreDispatchQuota,
					Detail:      "a bounded handler-slot gate runs before transport dispatch",
				}}
			},
			wantInput:   domain.ClaimTrue,
			wantTrigger: domain.ClaimUnknown,
			wantGap:     domain.GapTriggerProofIncomplete,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			product := base
			var input *domain.TransportInputWitness
			var trigger *domain.TransportTriggerWitness
			if tc.withInput || tc.withTrigger {
				input = transportTestInput(product)
			}
			if tc.withTrigger {
				trigger = transportTestTrigger(product, input)
			}
			if tc.mutate != nil {
				tc.mutate(&product, input, trigger)
			}
			evidence := transportTestEvidence(input, trigger)
			c := transportTestCase(product, model, evidence)

			peerClaim := ServerTransportInput{}.Evaluate(transportTestCondition(model, "C-PEER-INPUT"), c)
			if peerClaim.Result != tc.wantInput {
				t.Fatalf("input claim = %s; want %s (gaps %+v)", peerClaim.Result, tc.wantInput, peerClaim.AnalysisGaps)
			}
			if peerClaim.Result == domain.ClaimTrue && peerClaim.ControlBasis != domain.ControlBasisTransportPeerInput {
				t.Fatalf("admitted input claim carries control basis %q", peerClaim.ControlBasis)
			}

			constraintClaim := ServerTransportInput{}.Evaluate(transportTestCondition(model, "C-CONSTRAINT"), c)
			if constraintClaim.Result != tc.wantTrigger {
				t.Fatalf("constraint claim = %s; want %s (gaps %+v)", constraintClaim.Result, tc.wantTrigger, constraintClaim.AnalysisGaps)
			}
			if tc.wantGap != "" && constraintClaim.Result != domain.ClaimTrue {
				found := false
				for _, gap := range constraintClaim.AnalysisGaps {
					if gap.Code != tc.wantGap {
						continue
					}
					if err := gap.Validate(); err != nil {
						t.Fatalf("typed gap is invalid: %v", err)
					}
					if gap.ConditionID != constraintClaim.ConditionID {
						t.Fatalf("gap condition %q does not name the claim condition %q", gap.ConditionID, constraintClaim.ConditionID)
					}
					if gap.Owner == domain.GapOwnerExternal {
						t.Fatalf("transport proof gap must never be external-owned: %+v", gap)
					}
					found = true
				}
				if !found {
					t.Fatalf("constraint claim carries %v; want %s", constraintClaim.AnalysisGaps, tc.wantGap)
				}
			}

			if err := ValidateTransportInput(product, model, peerClaim, evidence); (err == nil) != (peerClaim.Result == domain.ClaimTrue) {
				t.Fatalf("input re-admission err=%v for claim %s", err, peerClaim.Result)
			}
			if err := ValidateTransportTrigger(product, model, constraintClaim, evidence); (err == nil) != (constraintClaim.Result == domain.ClaimTrue) {
				t.Fatalf("trigger re-admission err=%v for claim %s", err, constraintClaim.Result)
			}
		})
	}
}

// frameObservationCase is one govulncheck call path through a server-side
// transport frame in the vulnerable module and nothing else: no rooted
// transport witness, no argument trace.
func frameObservationCase() *domain.AnalysisCase {
	return serverCase([]domain.CallSite{
		{Package: "lib/grpc/internal/transport", Function: "HandleStreams", Receiver: "*http2Server"},
		{Package: "prod", Function: "Start", Receiver: "*Consumer"},
	})
}

// TestServerFrameWithoutWitnessIsUnknown pins the removal of the
// frame-name/server-receiver TRUE. A transport frame inside the vulnerable
// module is an observation about structure: it is neither a rooted proof that
// a listener serves peer bytes nor a provenance trace of the sink's input.
// With no typed witness the claim stays UNKNOWN, keeps the frame as an
// explanatory limitation, and never falls through to a weaker positive.
func TestServerFrameWithoutWitnessIsUnknown(t *testing.T) {
	t.Run("frame observation only", func(t *testing.T) {
		claim := ServerTransportInput{}.Evaluate(domain.Condition{
			ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
		}, frameObservationCase())
		if claim.Result != domain.ClaimUnknown {
			t.Fatalf("got %s, want UNKNOWN: a frame name is not peer-input proof (%s)",
				claim.Result, claim.Explanation)
		}
		if claim.Falsifier != "" || claim.NegativeVerification != nil {
			t.Fatalf("an observation produced a negative record: %+v", claim)
		}
		why := strings.Join(claim.Limitations, " | ")
		if !strings.Contains(why, "HandleStreams") {
			t.Fatalf("limitations do not retain the observed frame: %v", claim.Limitations)
		}
		if !strings.Contains(why, "rooted transport witness") {
			t.Fatalf("limitations do not name the missing rooted witness: %v", claim.Limitations)
		}
	})

	t.Run("declared trust does not extend a frame name to peer input", func(t *testing.T) {
		c := frameObservationCase()
		c.Product.TrustedPeer = true
		claim := ServerTransportInput{}.Evaluate(domain.Condition{
			ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
		}, c)
		if claim.Result != domain.ClaimUnknown {
			t.Fatalf("got %s, want UNKNOWN: --trusted-peer is a policy assertion about peers, and a frame name does not establish that this input is peer-supplied",
				claim.Result)
		}
		if claim.Falsifier != "" || claim.NegativeVerification != nil {
			t.Fatalf("declared trust over a frame name produced a negative: %+v", claim)
		}
	})

	t.Run("attempted mechanism proof without a trigger witness keeps its typed gap", func(t *testing.T) {
		product := admittedSnapshot(domain.ProductSnapshot{Repository: "/repo", Commit: "abc123"})
		model := transportTestModel()
		input := transportTestInput(product)
		c := transportTestCase(product, model, transportTestEvidence(input, nil))
		// A server-side frame is present; it must not stand in for the
		// missing source/fix-bound trigger witness.
		c.EvidenceGraph.AddCallPath(domain.CallPath{Frames: []domain.CallSite{
			{Package: "example.com/netmod", Function: "HandleStreams", Receiver: "*http2Server"},
		}})
		claim := ServerTransportInput{}.Evaluate(transportTestCondition(model, "C-CONSTRAINT"), c)
		if claim.Result != domain.ClaimUnknown {
			t.Fatalf("got %s, want UNKNOWN: a frame cannot satisfy the mechanism condition (%s)",
				claim.Result, claim.Explanation)
		}
		found := false
		for _, gap := range claim.AnalysisGaps {
			if gap.Code == domain.GapTriggerProofIncomplete && gap.ConditionID == claim.ConditionID {
				found = true
			}
		}
		if !found {
			t.Fatalf("claim carries %v; want a typed %s gap", claim.AnalysisGaps, domain.GapTriggerProofIncomplete)
		}
	})
}
