package justification_test

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/finding"
	"github.com/davniy/izyan/internal/justification"
)

func axesJustificationBuild() domain.BuildContext {
	return domain.BuildContext{
		Repository: "github.com/example/product",
		Commit:     "abcdef1",
		GOOS:       "linux",
		GOARCH:     "amd64",
		GoVersion:  "go1.25.0",
	}
}

func axesJustificationProduct(build domain.BuildContext) domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: build.Repository,
		Commit:     build.Commit,
		GOOS:       build.GOOS,
		GOARCH:     build.GOARCH,
		GoVersion:  build.GoVersion,
	}
}

func axesJustificationPin(id string) domain.RecordPin {
	return domain.RecordPin{
		RecordID:       id,
		DocumentDigest: "sha256:" + strings.Repeat("ab", 32),
		SourceLocator:  "corpus/" + id + ".json",
	}
}

func axesJustificationScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID:  id,
		ResolvedID:   id,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: "example.com/lib"}},
			RepresentedRefs:    []int{0},
		},
	}
}

func axesJustificationAssess(c *domain.AnalysisCase, claims []domain.Claim) domain.AssessmentResult {
	affected := domain.AffectedResult{}
	if c.Affected != nil {
		affected = *c.Affected
	}
	model := domain.ExploitModel{}
	if c.Exploit != nil {
		model = *c.Exploit
	}
	return finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:  c.Product,
			Affected: affected,
			Model:    model,
			Claims:   claims,
			Evidence: c.EvidenceGraph.EvidenceList(),
		},
		AssessmentID: c.ID,
	})
}

func axesJustificationNegative(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := axesJustificationBuild()
	const id = "GO-2026-7777"
	pin := axesJustificationPin(id)
	c := &domain.AnalysisCase{
		ID:            "justification-negative",
		RequestedID:   id,
		Vulnerability: domain.Vulnerability{ID: id, Scope: axesJustificationScope(id)},
		RecordPin:     &pin,
		Product:       axesJustificationProduct(build),
		Affected: &domain.AffectedResult{
			Scope:         axesJustificationScope(id),
			ModulePresent: domain.ClaimFalse,
		},
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         axesJustificationAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize negative: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

func axesJustificationPositive(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := axesJustificationBuild()
	const id = "GO-2026-8888"
	pin := axesJustificationPin(id)
	claims := []domain.Claim{{
		ID:           "CL-C-API",
		ConditionID:  "C-API",
		Result:       domain.ClaimTrue,
		EvidenceIDs:  []domain.EvidenceID{"EV-API"},
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}}
	c := &domain.AnalysisCase{
		ID:            "justification-positive",
		RequestedID:   id,
		Vulnerability: domain.Vulnerability{ID: id, Scope: axesJustificationScope(id)},
		RecordPin:     &pin,
		Product:       axesJustificationProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-API", Kind: domain.ConditionInputConstraint, Mandatory: true,
		}}},
		Claims: claims,
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID: "EV-API", Kind: domain.EvidenceSourceSnippet, Quality: domain.QualityDeterministic,
		Source: "axes-test", Content: "EV-API",
	})
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         axesJustificationAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize positive: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

func TestJustificationAssessmentAxes(t *testing.T) {
	t.Run("an exact negative carries the projected pair", func(t *testing.T) {
		dossier := justification.Build(axesJustificationNegative(t))
		want := "Оси оценки запроса: уязвимый код/версия в оцениваемой сборке: нет; эксплуатируемость: неприменимо"
		if !containsAxisFact(dossier.VerifiedFacts, want) {
			t.Fatalf("dossier lacks %q: %+v", want, dossier.VerifiedFacts)
		}
	})

	t.Run("a scoped positive names its boundary", func(t *testing.T) {
		dossier := justification.Build(axesJustificationPositive(t))
		want := "уязвимый код/версия в оцениваемой сборке: да; эксплуатируемость: да, на границе library API; доступ атакующего в развёртывании не установлен"
		if !containsAxisFact(dossier.VerifiedFacts, want) {
			t.Fatalf("dossier lacks %q: %+v", want, dossier.VerifiedFacts)
		}
		for _, fact := range dossier.VerifiedFacts {
			if strings.Contains(fact, "эксплуатируемость: да;") {
				t.Fatalf("scoped positive read as unqualified exploitability: %q", fact)
			}
		}
	})
}

func containsAxisFact(facts []string, want string) bool {
	for _, fact := range facts {
		if strings.Contains(fact, want) {
			return true
		}
	}
	return false
}
