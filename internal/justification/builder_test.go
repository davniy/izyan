package justification_test

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/justification"
	"github.com/fedorovmv/izyan/internal/report"
)

func TestJustification_ExploitableGeneratesHumanRemainder(t *testing.T) {
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-6443",
			AffectedPackages: []domain.AffectedPackage{
				{Path: "google.golang.org/grpc/internal/xds"},
				{Path: "google.golang.org/grpc/internal/transport"},
			},
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
		},
		CVEAnalysis: &domain.CVEAnalysisProposal{
			ID:       "PROP-GO-2026-6443",
			Revision: 1,
			Mechanisms: []domain.DefectMechanism{
				{
					ID:             "M-1",
					Summary:        "panic in RouteAndProcess",
					FaultingSites:  []string{"google.golang.org/grpc/internal/xds server.RouteAndProcess"},
					AuxiliarySites: []string{"google.golang.org/grpc/internal/transport transport.HandleStreams"},
				},
			},
		},
	}

	dossier := justification.Build(caseData)
	caseData.Justification = &dossier

	if len(dossier.HumanRemainder) == 0 {
		t.Fatalf("expected human remainder for unconfirmed auxiliary symbol in EXPLOITABLE case")
	}
	rem := dossier.HumanRemainder[0]
	if rem.Proposal == nil || rem.Proposal.ID != "PROP-GO-2026-6443" || rem.Proposal.MechanismID != "M-1" {
		t.Fatalf("remainder must bind to its proposal: %+v", rem.Proposal)
	}
	if rem.Subject == nil || rem.Subject.Symbol != "transport.HandleStreams" {
		t.Fatalf("remainder must carry the normalized subject: %+v", rem.Subject)
	}
	if strings.Contains(rem.Question, "является вспомогательным") {
		t.Fatalf("question must not presuppose the auxiliary role: %q", rem.Question)
	}

	trackerText := report.TrackerRationale(caseData)
	if !strings.Contains(trackerText, "server.RouteAndProcess") {
		t.Errorf("expected faulting site in tracker rationale")
	}
	if !strings.Contains(trackerText, "HandleStreams") {
		t.Errorf("expected auxiliary site in human remainder rationale")
	}
}

// An LLM-declared faulting site is a hypothesis, not evidence — it must
// never enter VerifiedFacts.
func TestJustification_FaultingSitesNeverVerifiedFacts(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-X"},
		CVEAnalysis: &domain.CVEAnalysisProposal{
			ID:       "P",
			Revision: 1,
			Mechanisms: []domain.DefectMechanism{
				{ID: "M-1", Summary: "s1", FaultingSites: []string{"a/b C.D"}},
				{ID: "M-2", Summary: "s2", FaultingSites: []string{"e/f G.H"}},
			},
		},
	}
	d := justification.Build(c)
	if len(d.VerifiedFacts) != 0 {
		t.Fatalf("LLM faulting sites must not become verified facts: %+v", d.VerifiedFacts)
	}
	// All mechanisms contribute to the mechanism text, not only the first.
	if !strings.Contains(d.TechnicalMechanism, "s1") || !strings.Contains(d.TechnicalMechanism, "s2") {
		t.Fatalf("all mechanisms must be covered: %q", d.TechnicalMechanism)
	}
	if !strings.Contains(d.TechnicalMechanism, "предполагаемые") {
		t.Fatalf("faulting sites must be labeled as proposed, not established: %q", d.TechnicalMechanism)
	}
}

// Auxiliary sites of every mechanism produce obligations; ambiguous raw
// references stay unverified (nil subject) with an honest question.
func TestJustification_AuxiliaryRemainderAllMechanisms(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-Y"},
		CVEAnalysis: &domain.CVEAnalysisProposal{
			ID:       "P",
			Revision: 3,
			Mechanisms: []domain.DefectMechanism{
				{ID: "M-1", Summary: "s1", AuxiliarySites: []string{"mod/pkg Fn"}},
				{ID: "M-2", Summary: "s2", AuxiliarySites: []string{"unresolvable.dotted.path.Fn"}},
			},
		},
	}
	d := justification.Build(c)
	if len(d.HumanRemainder) != 2 {
		t.Fatalf("every mechanism's auxiliary sites must remain for audit: %+v", d.HumanRemainder)
	}
	if d.HumanRemainder[0].Subject == nil {
		t.Fatal("space-separated site must normalize")
	}
	if d.HumanRemainder[1].Subject != nil {
		t.Fatalf("ambiguous reference must stay unverified: %+v", d.HumanRemainder[1].Subject)
	}
	if d.HumanRemainder[1].Proposal == nil || d.HumanRemainder[1].Proposal.MechanismID != "M-2" {
		t.Fatalf("second mechanism remainder must carry its mechanism id: %+v", d.HumanRemainder[1].Proposal)
	}
}

// A TRUE proposal verification is legitimate dossier content — an
// honest verified fact with the check and evidence attached.
func TestJustification_VerifiedFactsFromChecksOnly(t *testing.T) {
	subj := domain.SymbolRef{Package: "a/b", Symbol: "C"}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-Z"},
		ProposalVerifications: []domain.ProposalVerification{
			{
				Proposal: domain.ProposalRef{Source: domain.ProposalSourceCVEResearch, ID: "P", Revision: 1},
				Subject:  &subj, Assertion: domain.AssertionFaultingSite,
				Check: domain.CheckSymbolExists, Result: domain.ClaimTrue, Detail: "declared at x.go:1",
			},
			{
				Proposal: domain.ProposalRef{Source: domain.ProposalSourceCVEResearch, ID: "P", Revision: 1},
				Subject:  &subj, Assertion: domain.AssertionFaultingSite,
				Check: domain.CheckSiteRole, Result: domain.ClaimUnknown, Detail: "no checker",
			},
		},
	}
	d := justification.Build(c)
	if len(d.VerifiedFacts) != 1 || !strings.Contains(d.VerifiedFacts[0], "SYMBOL_EXISTS") {
		t.Fatalf("only TRUE check results are verified facts: %+v", d.VerifiedFacts)
	}
}
