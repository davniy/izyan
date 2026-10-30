package domain_test

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestAbsenceAdmissionCannotBeMutatedThroughCover(t *testing.T) {
	subject := domain.SymbolRef{Package: "example.com/dep/pkg", Symbol: "Sink"}
	model := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: subject.Package,
			Symbol:  subject.Symbol,
			Role:    domain.RootCauseSink,
			Origin:  domain.RootCauseOriginAdvisory,
		}},
	}
	v := domain.Vulnerability{
		ID:              "GO-TEST-1",
		Module:          "example.com/dep",
		AffectedSymbols: []domain.SymbolRef{subject},
	}
	proof := &domain.ContentAdmission{
		Proof: &domain.FixProof{
			Contract: domain.FixProofContract,
			Rules:    domain.FixProofRules,
			Cover: domain.FixProofCover{
				Rule:          domain.FixProofCoverRule,
				ID:            "cover-id",
				SubjectDigest: domain.AbsenceSubjectSetDigest([]domain.SymbolRef{subject}),
				Subjects:      []domain.SymbolRef{subject},
				Packages:      []string{subject.Package},
			},
		},
		Subjects: []domain.SymbolRef{subject},
	}
	build := domain.AbsenceBuildGraph{
		Paths:    map[string]bool{"example.com/prod": true},
		Admitted: true,
	}

	admission := domain.AdmitAbsenceFor(model, v, nil, nil, nil, build, proof)
	cover1 := admission.Cover()
	if cover1 == nil {
		t.Fatal("expected non-nil cover from admitted content proof")
	}

	// Mutate the returned cover slices and fields
	mutatedSub := domain.SymbolRef{Package: "example.com/dep/pkg", Symbol: "Injected"}
	cover1.Subjects = append(cover1.Subjects, mutatedSub)
	cover1.Packages = append(cover1.Packages, "example.com/injected")
	if len(cover1.Mapped) > 0 {
		cover1.Mapped = append(cover1.Mapped, mutatedSub)
	}

	// Read cover again: defensive projection must prevent mutation of admission's internal cover
	cover2 := admission.Cover()
	if cover2 == nil {
		t.Fatal("cover2 is nil")
	}
	if cover2.Covers(mutatedSub) {
		t.Fatalf("admission internal cover was mutated through previous Cover() pointer: %v", cover2.Subjects)
	}
	if cover2.CoversPackage("example.com/injected") {
		t.Fatalf("admission internal packages mutated: %v", cover2.Packages)
	}
}
