package states

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

func TestActCollectEvidence_MissingCallOmitted(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "missingcall"))
	if err != nil {
		t.Fatal(err)
	}

	c := &domain.AnalysisCase{
		Exploit: omissionTestModel(),
	}

	h := CollectEvidence{Source: &goanalysis.Index{Dir: product}}
	h.actCollectEvidence(context.Background(), c)

	ev := c.EvidenceGraph.EvidenceByID("EV-MISSING-CALL")
	if ev == nil {
		t.Fatal("expected EV-MISSING-CALL in evidence graph, found nil")
	}
	if ev.Kind != domain.EvidenceValidation {
		t.Errorf("ev.Kind = %v, want %v", ev.Kind, domain.EvidenceValidation)
	}
	if ev.Quality != domain.QualityDeterministic {
		t.Errorf("ev.Quality = %v, want %v", ev.Quality, domain.QualityDeterministic)
	}
	if !strings.Contains(ev.Content, "MapClaims.VerifyAudience") || !strings.Contains(ev.Content, "MapClaims.Valid") {
		t.Errorf("ev.Content missing symbols: %s", ev.Content)
	}
	if ev.MissingCall == nil {
		t.Fatal("expected a typed MissingCallWitness")
	}
	if ev.MissingCall.Status != domain.MissingCallOmitted {
		t.Errorf("witness status = %q, want %q", ev.MissingCall.Status, domain.MissingCallOmitted)
	}
	if ev.MissingCall.RecordID != "GO-TEST-OMISSION" {
		t.Errorf("witness record = %q", ev.MissingCall.RecordID)
	}
	if ev.MissingCall.Check.Symbol != "MapClaims.VerifyAudience" || ev.MissingCall.Pipeline.Symbol != "MapClaims.Valid" {
		t.Errorf("witness identities = %+v -> %+v", ev.MissingCall.Check, ev.MissingCall.Pipeline)
	}
	if ev.BuildContext == nil {
		t.Error("expected the witness record to carry a build context")
	}
}

func TestActCollectEvidence_MissingCallInvoked(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "missingcallinvoked"))
	if err != nil {
		t.Fatal(err)
	}

	c := &domain.AnalysisCase{
		Exploit: omissionTestModel(),
	}

	h := CollectEvidence{Source: &goanalysis.Index{Dir: product}}
	h.actCollectEvidence(context.Background(), c)

	if ev := c.EvidenceGraph.EvidenceByID("EV-MISSING-CALL"); ev != nil {
		t.Fatalf("expected no EV-MISSING-CALL when check is invoked, got: %+v", ev)
	}
	ev := c.EvidenceGraph.EvidenceByID("EV-CHECK-PRESENT")
	if ev == nil {
		t.Fatal("expected EV-CHECK-PRESENT when check is invoked, got nil")
	}
	if !strings.Contains(ev.Content, "invoked in product code") {
		t.Errorf("ev.Content unexpected: %s", ev.Content)
	}
	if ev.MissingCall == nil || ev.MissingCall.Status != domain.MissingCallPresent {
		t.Errorf("expected a PRESENT typed witness, got %+v", ev.MissingCall)
	}
}

// omissionTestModel is the admitted OMITTED_CHECK shape the producer binds:
// one omission condition naming the check with the contracted pipeline and
// one pipeline-reach condition. The contract is the only reason the producer
// may measure the omission at all.
func omissionTestModel() *domain.ExploitModel {
	pipeline := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"}
	return &domain.ExploitModel{
		DefectSemantics: &domain.DefectSemanticsContract{
			Mode:     domain.DefectSemanticsOmittedCheck,
			RecordID: "GO-TEST-OMISSION",
			Check:    domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"},
			Pipeline: &pipeline,
		},
		MandatoryConditions: []domain.Condition{
			{
				ID:        "C-REACH",
				Kind:      domain.ConditionSymbolReachable,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{pipeline},
				Params:    map[string]string{"pipeline": pipeline.Symbol},
			},
			{
				ID:        "C-OMISSION",
				Kind:      domain.ConditionMissingCall,
				Mandatory: true,
				Subjects: []domain.SymbolRef{
					{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"},
				},
				Params: map[string]string{
					"pipeline":        pipeline.Symbol,
					domain.ParamCheck: domain.CheckMissingCall,
				},
			},
		},
	}
}
