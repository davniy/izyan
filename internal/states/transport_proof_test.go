package states

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/goanalysis"
)

const transportStatesFixture = "../../testdata/transportresetprod"

// transportStatesFixDiff is the publisher fix shape the trigger proof binds:
// a bounded handler quota acquired before the handler runs.
const transportStatesFixDiff = `commit f2180b4d5403d2210b30b93098eb7da31c05c721
--- a/transport/transport.go
+++ b/transport/transport.go
@@ type ServerTransport struct {
     mu            sync.Mutex
     activeStreams map[uint32]*Stream
+    // handlerQuota bounds how many stream handlers execute at once.
+    handlerQuota chan struct{}
 }
@@ func (t *ServerTransport) operateHeaders(f *http2.MetaHeadersFrame) {
     t.mu.Unlock()
+    select {
+    case t.handlerQuota <- struct{}{}:
+    case <-t.ctx.Done():
+        return
+    }
+    defer func() { <-t.handlerQuota }()
     go t.runHandler(s)
 }
`

func copyTransportStatesFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(transportStatesFixture)); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return dst
}

func transportStatesPin() domain.RecordPin {
	return domain.RecordPin{
		RecordID:       "GO-TEST-TRANSPORT",
		DocumentDigest: "sha256:" + strings.Repeat("1", 64),
		SourceLocator:  "file:///records/GO-TEST-TRANSPORT.json",
	}
}

func transportStatesModel() domain.ExploitModel {
	subject := domain.SymbolRef{Package: "example.com/transportresetdep", Symbol: "Server.Serve"}
	return domain.ExploitModel{
		ProtocolRole: domain.ProtocolRoleServer,
		Class:        "RESOURCE_EXHAUSTION",
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

// transportStatesCase builds the worked shape: a pinned advisory for the
// affected module, a server-role peer-input model, and the recorded fix diff.
func transportStatesCase(t *testing.T, product domain.ProductSnapshot) (*domain.AnalysisCase, *goanalysis.Index) {
	t.Helper()
	dir := copyTransportStatesFixture(t)
	ix := &goanalysis.Index{Dir: dir, Build: product}
	model := transportStatesModel()
	pin := transportStatesPin()
	c := &domain.AnalysisCase{
		ID: "CASE-TRANSPORT-PROOF",
		Vulnerability: domain.Vulnerability{
			ID:               pin.RecordID,
			Module:           "example.com/transportresetdep",
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/transportresetdep"}},
		},
		Product:   product,
		RecordPin: &pin,
		Exploit:   &model,
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceFixDiff,
		Quality: domain.QualityAuthoritative,
		Source:  "https://example.com/fix/f2180b4d",
		Tool:    "fix.HTTPProvider",
		Content: transportStatesFixDiff,
	})
	return c, ix
}

func transportStatesProduct(t *testing.T) domain.ProductSnapshot {
	t.Helper()
	return domain.ProductSnapshot{
		Repository: "/fixture/transportresetprod",
		Commit:     "abc123",
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
	}
}

func transportStatesClaims(t *testing.T, c *domain.AnalysisCase) []domain.Claim {
	t.Helper()
	if c.Exploit == nil {
		t.Fatal("no exploit model")
	}
	var claims []domain.Claim
	for _, cond := range c.Exploit.MandatoryConditions {
		claims = append(claims, evaluator.ServerTransportInput{}.Evaluate(cond, c))
	}
	return claims
}

func transportStatesAffected() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:                   domain.ClaimTrue,
		ResolvedVersion:                 "v1.55.0",
		VersionAffected:                 domain.ClaimTrue,
		PackagePresent:                  domain.ClaimTrue,
		BuildRelevant:                   domain.ClaimTrue,
		VulnerableImplementationPresent: domain.ClaimTrue,
	}
}

func transportStatesVerdict(c *domain.AnalysisCase, claims []domain.Claim) domain.VerdictResult {
	return evaluator.VerdictEvaluator{}.Evaluate(evaluator.VerdictInput{
		Product:  c.Product,
		Affected: transportStatesAffected(),
		Model:    *c.Exploit,
		Claims:   claims,
		Evidence: c.EvidenceGraph.EvidenceList(),
	})
}

func claimFor(claims []domain.Claim, id domain.ConditionID) (domain.Claim, bool) {
	for _, c := range claims {
		if c.ConditionID == id {
			return c, true
		}
	}
	return domain.Claim{}, false
}

// TestTransportScopeAdmission proves the end-to-end transport contract: the
// collector records the rooted input and source/fix-bound trigger witnesses,
// the peer-input claim earns transport-peer scope, and the scope is withheld
// when the witness is absent, the record is unpinned or the deployment
// declares trusted peers.
func TestTransportScopeAdmission(t *testing.T) {
	ctx := context.Background()

	t.Run("rooted witness scopes the earned transport positive", func(t *testing.T) {
		product := transportStatesProduct(t)
		c, ix := transportStatesCase(t, product)
		if _, err := (CollectEvidence{Source: ix}).Run(ctx, c); err != nil {
			t.Fatalf("collect evidence: %v", err)
		}
		input, trigger := domain.TransportWitnessFromEvidence(c.EvidenceGraph.EvidenceList())
		if input == nil {
			t.Fatalf("no rooted input witness recorded; case gaps %+v", c.AnalysisGaps)
		}
		if trigger == nil {
			t.Fatalf("no trigger witness recorded; case gaps %+v", c.AnalysisGaps)
		}
		if err := input.Complete(); err != nil {
			t.Fatalf("input witness incomplete: %v", err)
		}
		if err := trigger.Complete(); err != nil {
			t.Fatalf("trigger witness incomplete: %v", err)
		}
		for _, gap := range c.AnalysisGaps {
			switch gap.Code {
			case domain.GapTriggerProofIncomplete, domain.GapReachabilityProofIncomplete, domain.GapInputResolutionFailed:
				t.Fatalf("completed transport proof left a transport gap: %+v", gap)
			}
		}

		claims := transportStatesClaims(t, c)
		peer, ok := claimFor(claims, "C-PEER-INPUT")
		if !ok || peer.Result != domain.ClaimTrue {
			t.Fatalf("peer-input claim = %+v; want TRUE", peer)
		}
		if peer.ControlBasis != domain.ControlBasisTransportPeerInput {
			t.Fatalf("peer-input control basis = %q; want %q", peer.ControlBasis, domain.ControlBasisTransportPeerInput)
		}
		constraint, ok := claimFor(claims, "C-CONSTRAINT")
		if !ok || constraint.Result != domain.ClaimTrue {
			t.Fatalf("constraint claim = %+v; want TRUE", constraint)
		}

		verdict := transportStatesVerdict(c, claims)
		if verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict = %s (%s); want EXPLOITABLE", verdict.Verdict, verdict.Reason)
		}
		if verdict.ExploitabilityScope != domain.ScopeTransportPeer {
			t.Fatalf("scope = %q; want %q", verdict.ExploitabilityScope, domain.ScopeTransportPeer)
		}
		if !containsString(verdict.Limitations, domain.TransportPeerScopeLimitation) {
			t.Fatalf("verdict limitations = %v; want the transport-peer limitation", verdict.Limitations)
		}
	})

	t.Run("trusted peer rewriting still applies to transport claims", func(t *testing.T) {
		product := transportStatesProduct(t)
		product.TrustedPeer = true
		c, ix := transportStatesCase(t, product)
		if _, err := (CollectEvidence{Source: ix}).Run(ctx, c); err != nil {
			t.Fatalf("collect evidence: %v", err)
		}
		claims := transportStatesClaims(t, c)
		peer, _ := claimFor(claims, "C-PEER-INPUT")
		if peer.Result != domain.ClaimFalse || peer.Falsifier != domain.FalsifierTrustedInfrastructure {
			t.Fatalf("peer-input claim = %+v; want the declared-trust falsifier", peer)
		}
		verdict := transportStatesVerdict(c, claims)
		if verdict.Verdict == domain.VerdictExploitable || verdict.ExploitabilityScope != "" {
			t.Fatalf("trusted-peer verdict = %+v; want no transport-peer positive", verdict)
		}
	})

	t.Run("absent fix evidence leaves a typed trigger gap", func(t *testing.T) {
		product := transportStatesProduct(t)
		c, ix := transportStatesCase(t, product)
		c.EvidenceGraph = domain.EvidenceGraph{}
		if _, err := (CollectEvidence{Source: ix}).Run(ctx, c); err != nil {
			t.Fatalf("collect evidence: %v", err)
		}
		input, trigger := domain.TransportWitnessFromEvidence(c.EvidenceGraph.EvidenceList())
		if input == nil || !transportGapHasCode(c.AnalysisGaps, domain.GapTriggerProofIncomplete) {
			t.Fatalf("input=%v gaps=%+v; want the rooted input plus %s",
				input != nil, c.AnalysisGaps, domain.GapTriggerProofIncomplete)
		}
		if trigger == nil {
			t.Fatal("no trigger witness recorded for the unresolved fix")
		}
		claims := transportStatesClaims(t, c)
		constraint, _ := claimFor(claims, "C-CONSTRAINT")
		if constraint.Result != domain.ClaimUnknown {
			t.Fatalf("constraint claim = %s; want UNKNOWN without fix evidence", constraint.Result)
		}
		gapFound := false
		for _, gap := range constraint.AnalysisGaps {
			if gap.Code == domain.GapTriggerProofIncomplete && gap.Owner == domain.GapOwnerProof {
				gapFound = true
			}
		}
		if !gapFound {
			t.Fatalf("constraint claim gaps = %+v; want a PROOF-owned %s",
				constraint.AnalysisGaps, domain.GapTriggerProofIncomplete)
		}
		if verdict := transportStatesVerdict(c, claims); verdict.Verdict == domain.VerdictExploitable {
			t.Fatal("verdict is EXPLOITABLE without a complete trigger witness")
		}
	})

	t.Run("unpinned record cannot earn transport scope", func(t *testing.T) {
		product := transportStatesProduct(t)
		c, ix := transportStatesCase(t, product)
		c.RecordPin = nil
		if _, err := (CollectEvidence{Source: ix}).Run(ctx, c); err != nil {
			t.Fatalf("collect evidence: %v", err)
		}
		input, _ := domain.TransportWitnessFromEvidence(c.EvidenceGraph.EvidenceList())
		if input != nil {
			t.Fatal("unpinned record produced a rooted witness")
		}
		if !transportGapHasCode(c.AnalysisGaps, domain.GapInputResolutionFailed) {
			t.Fatalf("case gaps = %+v; want %s", c.AnalysisGaps, domain.GapInputResolutionFailed)
		}
		claims := transportStatesClaims(t, c)
		peer, _ := claimFor(claims, "C-PEER-INPUT")
		if peer.Result == domain.ClaimTrue {
			t.Fatalf("peer-input claim = %+v; want no TRUE claim without a witness", peer)
		}
		if verdict := transportStatesVerdict(c, claims); verdict.Verdict == domain.VerdictExploitable {
			t.Fatal("unpinned record produced a positive verdict")
		}
	})
}

func transportGapHasCode(gaps []domain.AnalysisGap, code domain.GapCode) bool {
	for _, g := range gaps {
		if g.Code == code {
			return true
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// unsupportedTransportFixture removes the affected module's frame loop from a
// copy of the transport fixture. The product still constructs and serves the
// module's transport; the module simply implements no supported mechanism.
func unsupportedTransportFixture(t *testing.T) string {
	t.Helper()
	dir := copyTransportStatesFixture(t)
	path := filepath.Join(dir, "dep", "transport", "transport.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transport source: %v", err)
	}
	src := string(raw)
	head := strings.Index(src, "// HandleStreams consumes")
	tail := strings.Index(src, "// operateHeaders admits")
	if head < 0 || tail < 0 || tail <= head {
		t.Fatal("the fixture's frame loop is not where this test expects it")
	}
	stub := `// HandleStreams serves the accepted connection. This module decodes no
// versioned frame protocol, so it carries no stream lifecycle to prove.
func (t *ServerTransport) HandleStreams(ctx context.Context, handle func(context.Context, *Stream)) {
	t.handle = handle
	_ = ctx
}

`
	if err := os.WriteFile(path, []byte(src[:head]+stub+src[tail:]), 0o644); err != nil {
		t.Fatalf("write unsupported transport source: %v", err)
	}
	return dir
}

// TestUnsupportedTransportNeverInvokesSpecializedProof pins the dispatch
// boundary: a model that needs peer input, a nominated server role and a
// captured fix are not evidence that the specialized transport proof applies.
// When the affected module implements no supported mechanism lifecycle the
// checker is never invoked — no witness and no proof gap is recorded, only the
// refusal observation — and the ordinary evaluation stands so Product B's
// independent investigation is not blocked.
func TestUnsupportedTransportNeverInvokesSpecializedProof(t *testing.T) {
	ctx := context.Background()
	product := transportStatesProduct(t)
	dir := unsupportedTransportFixture(t)
	ix := &goanalysis.Index{Dir: dir, Build: product}

	model := transportStatesModel()
	if model.ProtocolRole != domain.ProtocolRoleServer {
		t.Fatalf("the control needs a nominated server role, got %q", model.ProtocolRole)
	}
	pin := transportStatesPin()
	c := &domain.AnalysisCase{
		ID: "CASE-UNSUPPORTED-TRANSPORT",
		Vulnerability: domain.Vulnerability{
			ID:               pin.RecordID,
			Module:           "example.com/transportresetdep",
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/transportresetdep"}},
		},
		Product:   product,
		RecordPin: &pin,
		Exploit:   &model,
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceFixDiff,
		Quality: domain.QualityAuthoritative,
		Source:  "https://example.com/fix/f2180b4d",
		Tool:    "fix.HTTPProvider",
		Content: transportStatesFixDiff,
	})

	if _, err := (CollectEvidence{Source: ix}).Run(ctx, c); err != nil {
		t.Fatalf("collect evidence: %v", err)
	}

	input, trigger := domain.TransportWitnessFromEvidence(c.EvidenceGraph.EvidenceList())
	if input != nil || trigger != nil {
		t.Fatalf("the specialized proof ran for an unsupported transport: input=%+v trigger=%+v", input, trigger)
	}
	for _, gap := range c.AnalysisGaps {
		switch gap.Code {
		case domain.GapTriggerProofIncomplete, domain.GapReachabilityProofIncomplete:
			t.Fatalf("the refused capability left a blocking proof gap: %+v", gap)
		}
	}
	var refusal string
	for _, limitation := range c.EvidenceGraph.Limitations {
		if strings.Contains(limitation, "rooted transport proof is not applicable") {
			refusal = limitation
		}
	}
	if refusal == "" {
		t.Fatalf("no applicability refusal was recorded; limitations=%v", c.EvidenceGraph.Limitations)
	}
	if !strings.Contains(refusal, "implements no supported transport mechanism lifecycle") {
		t.Fatalf("refusal %q does not name the missing lifecycle", refusal)
	}

	claims := transportStatesClaims(t, c)
	for _, claim := range claims {
		if claim.Result == domain.ClaimTrue {
			t.Fatalf("claim %s became TRUE without a witness: %+v", claim.ConditionID, claim)
		}
	}
	if verdict := transportStatesVerdict(c, claims); verdict.Verdict == domain.VerdictExploitable {
		t.Fatal("an unsupported transport produced a positive verdict")
	}
}
