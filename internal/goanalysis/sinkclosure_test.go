package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

var postReachSink = domain.SymbolRef{
	Package: "example.com/postreachdep/transformer", Symbol: "QueryAll",
}

func postReachCase(subjects ...domain.SymbolRef) *domain.AnalysisCase {
	return &domain.AnalysisCase{Product: testProduct(),
		Vulnerability: domain.Vulnerability{
			ID:              "GO-TEST-CONFIG",
			Module:          "example.com/postreachdep",
			AffectedSymbols: append([]domain.SymbolRef(nil), subjects...),
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			RootCauses: append([]domain.SymbolRef(nil), subjects...),
		},
	}
}

func TestSinkSetBasisRequiresEveryDeclaredSink(t *testing.T) {
	c := postReachCase(postReachSink)
	if basis, ok := SinkSetBasis(c, []domain.SymbolRef{postReachSink}, nil); !ok || basis == "" {
		t.Fatalf("complete declared set rejected: basis=%q ok=%v", basis, ok)
	}
	// Advisory membership is not a contract: the same subject set with a
	// second declared sink omitted stays KNOWN_ONLY.
	c.Vulnerability.AffectedSymbols = append(c.Vulnerability.AffectedSymbols,
		domain.SymbolRef{Package: "example.com/postreachdep/transformer", Symbol: "Find"})
	if _, ok := SinkSetBasis(c, []domain.SymbolRef{postReachSink}, nil); ok {
		t.Fatal("omitted declared sink authorized a completeness basis")
	}
}

func TestSinkSetBasisRejectsUnresolvedSubject(t *testing.T) {
	c := postReachCase(postReachSink)
	c.Exploit.UnresolvedSubjects = []domain.SymbolRef{
		{Package: "example.com/postreachdep/transformer", Symbol: "Find"},
	}
	if _, ok := SinkSetBasis(c, []domain.SymbolRef{postReachSink}, nil); ok {
		t.Fatal("unresolved non-absent subject authorized a completeness basis")
	}
	// A proven-absent subject cannot be live, so it no longer blocks the
	// contract. Absence is evidence about a declared subject: the record must
	// declare it, because the shared admission refuses a saved flag with no
	// affirmative basis.
	absent := domain.SymbolRef{Package: "example.com/postreachdep/transformer", Symbol: "Find"}
	c.Vulnerability.AffectedSymbols = append(c.Vulnerability.AffectedSymbols, absent)
	c.Exploit.AbsentSubjects = append(c.Exploit.AbsentSubjects, c.Exploit.UnresolvedSubjects...)
	if _, ok := SinkSetBasis(c, []domain.SymbolRef{postReachSink}, nil); !ok {
		t.Fatal("proven-absent subject blocked the completeness basis")
	}
}

func TestSinkClosureConfigOriginCompleteAndExact(t *testing.T) {
	ix := fixture(t, "configoriginprod")
	c := postReachCase(postReachSink)
	basis, ok := SinkSetBasis(c, []domain.SymbolRef{postReachSink}, nil)
	if !ok {
		t.Fatal("expected a completeness basis")
	}
	cl, evs, err := ix.SinkClosure(context.Background(), "C-INPUT", "example.com/postreachdep",
		basis, []domain.SymbolRef{postReachSink}, 1, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !cl.Complete {
		t.Fatalf("config closure incomplete: blockers=%v sites=%+v", cl.Blockers, cl.Sites)
	}
	if cl.Basis != basis || !strings.Contains(cl.Basis, "advisory GO-TEST-CONFIG") {
		t.Fatalf("basis=%q want the advisory-bound contract", cl.Basis)
	}
	var live int
	for _, s := range cl.Sites {
		if !s.Live {
			continue
		}
		live++
		if s.Sink != postReachSink.Package+"."+postReachSink.Symbol || s.Arg != 1 {
			t.Fatalf("site sink/arg=%s/%d want %s/1", s.Sink, s.Arg, postReachSink.Symbol)
		}
		if s.Origin != domain.OriginConfiguration {
			t.Fatalf("site origin=%s want CONFIGURATION (%s)", s.Origin, s.Detail)
		}
		if s.Function != "run" || s.Line == 0 || !strings.HasSuffix(s.File, "main.go") {
			t.Fatalf("site position=%+v want run@main.go", s.CallSite)
		}
	}
	if live != 1 {
		t.Fatalf("live sites=%d want 1", live)
	}
	if len(evs) != 1 || !strings.Contains(evs[0].Content, "config=1") ||
		!strings.Contains(evs[0].Content, "basis:") {
		t.Fatalf("closure evidence=%+v", evs)
	}
}

func TestSinkClosureMissingExactArgumentBlocks(t *testing.T) {
	ix := fixture(t, "confignoreachprod")
	subject := domain.SymbolRef{Package: "example.com/postreachdep/transformer", Symbol: "Helper"}
	c := postReachCase(subject)
	basis, ok := SinkSetBasis(c, []domain.SymbolRef{subject}, nil)
	if !ok {
		t.Fatal("expected a completeness basis")
	}
	cl, _, err := ix.SinkClosure(context.Background(), "C-INPUT", "example.com/postreachdep",
		basis, []domain.SymbolRef{subject}, 1, 16)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Complete {
		t.Fatalf("zero-argument sink with a declared payload position completed: %+v", cl.Sites)
	}
	if !sinkClosureHasBlocker(cl, "declared payload position 1 is absent") {
		t.Fatalf("missing exact-argument blocker: %v", cl.Blockers)
	}
}

func TestSinkClosureMultiSinkExternalStaysOpen(t *testing.T) {
	ix := fixture(t, "configmultisinkprod")
	subjects := []domain.SymbolRef{
		postReachSink,
		{Package: "example.com/postreachdep/transformer", Symbol: "Find"},
	}
	c := postReachCase(subjects...)
	basis, ok := SinkSetBasis(c, subjects, nil)
	if !ok {
		t.Fatal("expected a completeness basis")
	}
	cl, _, err := ix.SinkClosure(context.Background(), "C-INPUT", "example.com/postreachdep",
		basis, subjects, 1, 16)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Complete {
		t.Fatalf("multi-sink closure with an external site completed: %+v", cl.Sites)
	}
	var config, external bool
	for _, s := range cl.Sites {
		switch s.Origin {
		case domain.OriginConfiguration:
			config = true
		case domain.OriginExternalUntrusted:
			external = true
		}
	}
	if !config || !external {
		t.Fatalf("sites=%+v want both a configuration and an external live site", cl.Sites)
	}
}

func TestVerifyInputConfigRouteUsesExactClosure(t *testing.T) {
	ix := fixture(t, "configoriginprod")
	c := postReachCase(postReachSink)
	c.Exploit.MandatoryConditions = []domain.Condition{{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{postReachSink}, ArgIndex: 1,
	}}
	cond := c.Exploit.MandatoryConditions[0]
	claim := domain.Claim{
		ID: "CL-C-INPUT", ConditionID: cond.ID, Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierTrustedInfrastructure, FalsifierBasis: domain.BasisConfigOrigin,
	}
	out := (Verifier{Source: ix}).VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("config proof not verified: %+v", out.NegativeVerification)
	}
	cl := c.EvidenceGraph.SinkClosureFor(cond.ID)
	if cl == nil || !cl.Complete || cl.Basis == "" {
		t.Fatalf("verified claim has no complete advisory-bound closure: %+v", cl)
	}
}

func TestVerifyInputConfigRouteRejectsExternalWrite(t *testing.T) {
	ix := fixture(t, "configwriteprod")
	c := postReachCase(postReachSink)
	c.Exploit.MandatoryConditions = []domain.Condition{{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{postReachSink}, ArgIndex: 1,
	}}
	cond := c.Exploit.MandatoryConditions[0]
	claim := domain.Claim{
		ID: "CL-C-INPUT", ConditionID: cond.ID, Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierTrustedInfrastructure, FalsifierBasis: domain.BasisConfigOrigin,
	}
	out := (Verifier{Source: ix}).VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status == domain.NegativeVerified {
		t.Fatalf("external write retained a verified config falsifier: %+v", out.NegativeVerification)
	}
}

func sinkClosureHasBlocker(cl domain.SinkClosure, needle string) bool {
	for _, b := range cl.Blockers {
		if strings.Contains(b, needle) {
			return true
		}
	}
	return false
}
