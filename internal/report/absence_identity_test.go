package report

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// The schema-less rendering/export path is a publication surface like any
// other. It must run the same absence-identity admission the verdict boundary
// runs: a saved absent subject whose candidate carries only a patch coordinate,
// and a saved FALSE absence claim over it, are demoted before rendering no
// matter which entry point asked. No route may skip the gate.
func TestLegacyPathRunsAbsenceIdentityGate(t *testing.T) {
	subject := domain.SymbolRef{Package: "example.com/dep/xds", Symbol: "RouteAndProcess"}
	product := domain.ProductSnapshot{
		Repository: "/test/product", Commit: "testcommit", GOOS: "linux", GOARCH: "amd64",
	}
	product.Target = &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	effective := domain.EffectiveBuildContext(product)

	buildCase := func() *domain.AnalysisCase {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{ID: "GO-TEST-LEGACY", Module: "example.com/dep"},
			Product:       product,
			Affected: &domain.AffectedResult{
				ModulePresent:   domain.ClaimTrue,
				VersionAffected: domain.ClaimTrue,
				PackagePresent:  domain.ClaimTrue,
				BuildRelevant:   domain.ClaimTrue,
			},
			Exploit: &domain.ExploitModel{
				RootCauses: []domain.SymbolRef{subject},
				MandatoryConditions: []domain.Condition{{
					ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
					Subjects: []domain.SymbolRef{subject},
				}},
				AbsentSubjects: []domain.SymbolRef{subject},
			},
			RootCause: &domain.RootCauseModel{
				Status: domain.RootCauseResolved,
				RootCauses: []domain.RootCause{{
					Package: subject.Package, Symbol: subject.Symbol, Role: domain.RootCauseSink,
					Origin: domain.RootCauseOriginFixDerived,
					Binding: &domain.CandidateBinding{
						Status: domain.CandidateBindingAdmitted, Module: "example.com/dep",
						PatchPath: "xds/xds.go",
					},
				}},
			},
			Claims: []domain.Claim{{
				ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimFalse,
				Falsifier:   domain.FalsifierPackageAbsent,
				EvidenceIDs: []domain.EvidenceID{"EV-PKGS"},
				Producer:    "evaluator.SymbolReachable",
				NegativeVerification: &domain.NegativeVerification{
					Status:       domain.NegativeVerified,
					EvidenceIDs:  []domain.EvidenceID{"EV-PKGS"},
					BuildContext: &effective,
				},
			}},
			Verdict: &domain.VerdictResult{
				Verdict:      domain.VerdictNoExploitPathFound,
				ConditionIDs: []domain.ConditionID{"C-REACH"},
			},
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:           "EV-PKGS",
			Kind:         domain.EvidencePackageList,
			Quality:      domain.QualityDeterministic,
			Tool:         "go",
			Source:       "go list -deps -test -json ./...",
			Command:      "go list -deps -test -json ./...",
			Content:      `{"ImportPath":"example.com/prod"}`,
			BuildContext: &effective,
			PackageList:  &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./..."},
		})
		return c
	}

	t.Run("coordinate-only candidate and saved absence are refused", func(t *testing.T) {
		c := buildCase()
		projection := admitNegativeConclusions(c)
		out := projection.Case
		if out.Verdict == nil || out.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("legacy NEPF was not demoted: %+v", out.Verdict)
		}
		if out.Claims[0].Result != domain.ClaimUnknown {
			t.Fatalf("claim=%+v — the saved absence claim survived without an admitted basis", out.Claims[0])
		}
		if len(out.Exploit.AbsentSubjects) != 0 {
			t.Fatalf("absent subjects=%+v — the coordinate-only subject survived the gate", out.Exploit.AbsentSubjects)
		}
		var named bool
		for _, refusal := range projection.Refusals {
			if strings.Contains(refusal, "has no admitted absence basis") {
				named = true
			}
		}
		if !named {
			t.Fatalf("refusals=%v — the identity refusal is not named", projection.Refusals)
		}
		// The caller's historical case stays untouched.
		if len(c.Exploit.AbsentSubjects) != 1 || c.Claims[0].Result != domain.ClaimFalse ||
			c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatal("the legacy projection rewrote the caller's history")
		}
	})

	t.Run("record-declared subject keeps its independent route", func(t *testing.T) {
		c := buildCase()
		c.Vulnerability.AffectedSymbols = []domain.SymbolRef{subject}
		out := admitNegativeConclusions(c).Case
		if out.Claims[0].Result != domain.ClaimFalse {
			t.Fatalf("claim=%+v — a record-declared subject lost its independent basis", out.Claims[0])
		}
		if len(out.Exploit.AbsentSubjects) != 1 {
			t.Fatalf("absent subjects=%+v — a record-declared subject was pruned", out.Exploit.AbsentSubjects)
		}
	})
}
