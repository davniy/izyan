package evaluator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fixbinding"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/rootcause"
)

// absenceSourceFixture writes a snapshot root whose vendor tree carries the
// selected module at the recorded version, so a verifier can tell whether a
// proposed coordinate exists in that version's own source.
func absenceSourceFixture(t *testing.T, module, version string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/prod\n\ngo 1.15\n\nrequire "+module+" "+version+"\n")
	write("prod.go", "package prod\n\nfunc Main() {}\n")
	manifest := "# " + module + " " + version + "\n## explicit\n"
	seen := map[string]bool{}
	for rel := range files {
		dir := path.Dir(rel)
		pkg := module
		if dir != "." {
			pkg += "/" + dir
		}
		if !seen[pkg] {
			seen[pkg] = true
			manifest += pkg + "\n"
		}
		write("vendor/"+module+"/"+rel, files[rel])
	}
	write("vendor/modules.txt", manifest)
	return root
}

// llmProposer returns a real llm.RootCauseResolver wired to a stub endpoint that
// answers with reply, so the test drives the production proposal path rather
// than a hand-built candidate.
func llmProposer(t *testing.T, reply string) (*llm.RootCauseResolver, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       map[string]string{"role": "assistant", "content": reply},
				"finish_reason": "stop",
			}},
		})
	}))
	client := llm.NewClient(llm.Config{BaseURL: srv.URL, BuildModel: "stub", Enabled: true})
	return &llm.RootCauseResolver{Client: client}, srv.Close
}

// F3: an LLM proposal is a hypothesis about a location. It may be looked up and
// modelled, but it never establishes a record declaration, a source identity or
// a completeness boundary — so a nonexistent release-line package proposed
// through the real proposal and verifier path admits no absence, no VERIFIED
// absence and no no-exploit-path verdict.
func TestLLMOriginDoesNotEstablishAbsenceIdentity(t *testing.T) {
	const module = "github.com/containerd/containerd"
	const version = "v1.7.27"
	// The selected v1 source has no cmd/containerd/server package at all: the
	// patch's release-line coordinate does not exist in this version.
	root := absenceSourceFixture(t, module, version, map[string]string{
		"services/server/server.go": "package server\n\nfunc CreateTopLevelDirectories() error { return nil }\n",
	})
	subj := domain.SymbolRef{Package: module + "/cmd/containerd/server", Symbol: "CreateTopLevelDirectories"}

	proposer, closeServer := llmProposer(t, `[{"package":"`+subj.Package+
		`","symbol":"`+subj.Symbol+`","mechanism":"directory permissions"}]`)
	defer closeServer()

	product := admittedProduct()
	effective := domain.EffectiveBuildContext(product)
	c := &domain.AnalysisCase{
		Product: product,
		Affected: &domain.AffectedResult{
			SelectedModule:  module,
			SelectedModules: []string{module},
			ResolvedVersion: version,
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
		PackageList:  &domain.PackageListRun{Completed: true, Complete: true, WithTests: true, Pattern: "./..."},
	})
	v := domain.Vulnerability{ID: "GHSA-pwhc-rpq9-4c8w", Module: module}

	proposals, lims, err := proposer.Propose(context.Background(), c, v)
	if err != nil {
		t.Fatalf("propose: %v (limitations %v)", err, lims)
	}
	if len(proposals) != 1 || proposals[0].Origin != domain.RootCauseOriginLLMProposed {
		t.Fatalf("proposals=%+v — want one LLM-proposed candidate", proposals)
	}

	model := &domain.RootCauseModel{Status: domain.RootCauseResolved, RootCauses: proposals}
	rootcause.Verifier{Source: &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}}}.
		Verify(context.Background(), c, model, v)

	for _, rc := range model.Candidates() {
		if rc.Absent {
			t.Fatalf("candidate %s.%s was resolved by absence from an LLM proposal: %+v",
				rc.Package, rc.Symbol, rc)
		}
	}
	if model.Status == domain.RootCauseResolved {
		t.Fatalf("status=%s — an LLM proposal for a nonexistent release-line package left the root cause resolved", model.Status)
	}
	if len(model.Unverified) != 1 {
		t.Fatalf("unverified=%+v — the proposal must stay a blocking obligation", model.Unverified)
	}
	if admission := evaluatorAbsenceIdentity(c, model, subj); admission.Admitted {
		t.Fatalf("the shared admission admitted %s on an LLM proposal (basis %q)", subj, admission.Basis)
	}

	// The persisted conclusion is refused as well: a FALSE absence claim over
	// the proposed subject cannot ground NO_EXPLOIT_PATH_FOUND.
	claims := []domain.Claim{{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{
			Status:       domain.NegativeVerified,
			BuildContext: &effective,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	res.SelectedModule = module
	res.SelectedModules = []string{module}
	res.ResolvedVersion = version
	evaluation := VerdictEvaluator{}.EvaluateDetailed(VerdictInput{
		Product:  product,
		Affected: res,
		Model: domain.ExploitModel{
			RootCauses: []domain.SymbolRef{subj},
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{subj},
			}},
			UnresolvedSubjects: []domain.SymbolRef{subj},
			AbsentSubjects:     []domain.SymbolRef{subj},
		},
		Claims:        claims,
		Evidence:      c.EvidenceGraph.EvidenceList(),
		Vulnerability: v,
		RootCause:     model,
	})
	if evaluation.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("an LLM proposal grounded NO_EXPLOIT_PATH_FOUND: %q", evaluation.Verdict.Reason)
	}
	if !hasVerdictGap(evaluation.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", evaluation.Gaps)
	}
	if len(evaluation.Verdict.Limitations) == 0 {
		t.Fatal("the refusal was not recorded on the verdict")
	}
}

// F10: an absence claim whose evaluated subject set is empty proves nothing
// about any subject. It is refused at the shared admission boundary — whether
// the claim simply binds no subject, or the root-cause model behind it is nil —
// so a persisted VERIFIED negative cannot become a vacuous closure.
func TestEmptyAbsenceRejectedAtSharedBoundary(t *testing.T) {
	t.Run("claim binds no subject", func(t *testing.T) {
		model := domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			}},
		}
		claims := []domain.Claim{{
			ConditionID: "C-REACH",
			Result:      domain.ClaimFalse,
			Falsifier:   domain.FalsifierPackageAbsent,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
			},
		}}
		res := affectedAllTrue()
		res.Scope = exactVerdictScope()
		evaluation := evalVerdictInput(res, model, claims, nil, domain.Vulnerability{ID: "GO-TEST"})
		if evaluation.Verdict.Verdict == domain.VerdictNoExploitPathFound {
			t.Fatalf("a subject-less absence claim grounded NO_EXPLOIT_PATH_FOUND: %q", evaluation.Verdict.Reason)
		}
		if !hasVerdictGap(evaluation.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
			t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", evaluation.Gaps)
		}
		if !containsLimitation(evaluation.Verdict.Limitations, "binds no subject") {
			t.Fatalf("limitations=%v — the empty subject set was not named", evaluation.Verdict.Limitations)
		}
	})

	t.Run("nil root-cause model", func(t *testing.T) {
		sub := domain.SymbolRef{Package: "example.com/dep/internal/xds", Symbol: "RouteAndProcess"}
		if admission := domain.AdmitAbsenceFor(nil, domain.Vulnerability{ID: "GO-TEST"}, nil, nil, nil,
			domain.AbsenceBuildGraph{}, nil).Admits(sub); admission.Admitted {
			t.Fatalf("a nil root-cause model admitted %s (basis %q)", sub, admission.Basis)
		}
		model := domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{sub},
			}},
			UnresolvedSubjects: []domain.SymbolRef{sub},
			AbsentSubjects:     []domain.SymbolRef{sub},
		}
		claims := []domain.Claim{{
			ConditionID: "C-REACH",
			Result:      domain.ClaimFalse,
			Falsifier:   domain.FalsifierPackageAbsent,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
			},
		}}
		res := affectedAllTrue()
		res.Scope = exactVerdictScope()
		evaluation := evalVerdictInput(res, model, claims, nil, domain.Vulnerability{ID: "GO-TEST"})
		if evaluation.Verdict.Verdict == domain.VerdictNoExploitPathFound {
			t.Fatalf("a saved absence over a nil model grounded NO_EXPLOIT_PATH_FOUND: %q", evaluation.Verdict.Reason)
		}
		if !hasVerdictGap(evaluation.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
			t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", evaluation.Gaps)
		}
	})

	t.Run("domain verification gate", func(t *testing.T) {
		product := admittedProduct()
		claim := domain.Claim{
			Result:    domain.ClaimFalse,
			Falsifier: domain.FalsifierPackageAbsent,
			NegativeVerification: &domain.NegativeVerification{
				Status:       domain.NegativeVerified,
				BuildContext: boundContext(),
			},
		}
		evidence := []domain.Evidence{completePackageList()}
		if err := goanalysis.ValidateVerifiedNegative(goanalysis.NegativeAdmissionInput{Product:product,Evidence:evidence}, claim, domain.Condition{ID: "C-REACH"}); err == nil {
			t.Fatal("a subject-less absence negative passed the shared verification gate")
		}
		cond := domain.Condition{ID: "C-REACH", Subjects: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Sink"},
		}}
		if err := goanalysis.ValidateVerifiedNegative(goanalysis.NegativeAdmissionInput{Product:product,Evidence:evidence}, claim, cond); err != nil {
			t.Fatalf("a complete verified absence over a named subject was refused: %v", err)
		}
	})
}

// containsLimitation reports whether one limitation carries the phrase.
func containsLimitation(list []string, phrase string) bool {
	for _, s := range list {
		if strings.Contains(s, phrase) {
			return true
		}
	}
	return false
}

// evaluatorAbsenceIdentity derives the single shared admission for the test
// case and asks it about one subject.
func evaluatorAbsenceIdentity(c *domain.AnalysisCase, m *domain.RootCauseModel,
	s domain.SymbolRef) domain.AbsenceIdentityAdmission {
	if c == nil {
		return domain.AdmitAbsenceFor(m, domain.Vulnerability{}, nil, nil, nil,
			domain.AbsenceBuildGraph{}, fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), m)).Admits(s)
	}
	return domain.AdmitAbsenceFor(m, c.Vulnerability, c.Affected, c.RecordPin, nil,
		affected.AdmittedBuildGraph(c.Product, c.EvidenceGraph.EvidenceList()), fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), m)).Admits(s)
}
