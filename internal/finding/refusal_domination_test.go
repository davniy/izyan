package finding_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/fixbinding"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/rootcause"
)

// F1 — TestRefusedContentDependencyDominatesEveryIdentityLabel.
//
// A coordinate binding is a child observation of the content binding, never an
// alternative authority. The test starts from the actual verifier's output for
// an exact-preimage same-line fix, serialises and replays it, then corrupts and
// removes the proof inputs while preserving the coordinate bindings and adding
// duplicate MANUAL and LLM_PROPOSED labels for the same subject. No dependent
// negative survives: the absent set is pruned, the FALSE claim is demoted, the
// honest recomputation is a root-cause failure, and publication refuses the
// saved NO_EXPLOIT_PATH_FOUND. History is untouched.

const (
	rdModule  = "example.com/dep"
	rdVersion = "v1.0.0"
	rdPkg     = rdModule + "/omitted"
	rdPath    = "omitted/omitted.go"
	rdLocator = "https://example.com/dep/commit/abcdef"
	rdRecord  = "GHSA-refusal-domination"
)

// rdSource is the selected version's own file: the change repairs an omission
// in place.
const rdSource = `package omitted

import "errors"

func Parse(s string) (string, error) {
	return s, nil
}
`

// rdPatch is the captured fix: an ordinary executable omission repair.
const rdPatch = `diff --git a/omitted/omitted.go b/omitted/omitted.go
index 1111111..2222222 100644
--- a/omitted/omitted.go
+++ b/omitted/omitted.go
@@ -4,4 +4,7 @@ func Parse(s string) (string, error) {
 
 func Parse(s string) (string, error) {
-	return s, nil
+	if s == "" {
+		return "", errors.New("empty")
+	}
+	return s, nil
 }
`

// rdAdmission derives the single shared admission for the case and one model.
func rdAdmission(c *domain.AnalysisCase, m *domain.RootCauseModel) domain.AbsenceAdmission {
	var affectedChain *domain.AffectedResult
	if c != nil {
		affectedChain = c.Affected
	}
	return domain.AdmitAbsenceFor(m, c.Vulnerability, affectedChain, c.RecordPin, nil,
		affected.AdmittedBuildGraph(c.Product, c.EvidenceGraph.EvidenceList()), fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), m))
}

// rdCloneBinding copies a candidate binding so a duplicate label can carry the
// same coordinates without sharing storage.
func rdCloneBinding(b *domain.CandidateBinding) *domain.CandidateBinding {
	if b == nil {
		return nil
	}
	out := *b
	if b.SameLine != nil {
		line := *b.SameLine
		out.SameLine = &line
	}
	return &out
}

// rdCase builds the record, product, affected chain and admitted inventory the
// same-line route is measured against.
func rdCase(t *testing.T) (*domain.AnalysisCase, *goanalysis.Index, domain.BuildContext) {
	t.Helper()
	root := projectVerifierFixture(t, rdModule, rdVersion, map[string]string{rdPath: rdSource})
	index := &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}}

	build := composeProduct(composeBuild())
	build.Repository = root
	build.Target = &domain.ProductTarget{
		GOOS: build.GOOS, GOARCH: build.GOARCH,
		Source:          domain.ProductTargetSourceArtifactBuildInfo,
		Scope:           domain.ProductTargetScopeArtifact,
		ArtifactSHA256:  strings.Repeat("a", 64),
		BuildInfoSHA256: strings.Repeat("b", 64),
	}
	effective := domain.EffectiveBuildContext(build)
	pin := composePin(rdRecord)
	c := &domain.AnalysisCase{
		ID:          "refusal-domination",
		RequestedID: rdRecord,
		Vulnerability: domain.Vulnerability{
			ID: rdRecord, Module: rdModule, Scope: outcomeScope(rdRecord),
			// The record declares no subject: the exact-preimage route is the
			// only basis the omitted declaration rests on, so corrupting it
			// cannot be rescued by an independent record declaration.
			References: []domain.Reference{{Type: "FIX", URL: rdLocator}},
		},
		RecordPin: &pin,
		Product:   build,
		Affected: &domain.AffectedResult{
			Scope:           outcomeScope(rdRecord),
			SelectedModule:  rdModule,
			SelectedModules: []string{rdModule},
			ResolvedVersion: rdVersion,
			CheckedPackages: []string{rdPkg},
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
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
	return c, index, effective
}

func TestRefusedContentDependencyDominatesEveryIdentityLabel(t *testing.T) {
	c, index, effective := rdCase(t)
	subject := domain.SymbolRef{Package: rdPkg, Symbol: "Parse"}

	model := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: rdPkg, Symbol: "Parse", Role: domain.RootCauseSink,
			Origin: domain.RootCauseOriginFixDerived,
			Binding: &domain.CandidateBinding{
				Module:    rdModule,
				PatchPath: rdPath,
			},
		}},
		FixArtifacts: []domain.FixArtifact{{
			Locator:     rdLocator,
			Kind:        "commit",
			Outcome:     domain.FixArtifactComplete,
			Provenance:  "captured fixture",
			Digest:      domain.EvidenceContentDigest(rdPatch),
			Size:        len(rdPatch),
			Bytes:       rdPatch,
			Coordinates: []string{rdPath},
		}},
	}

	rootcause.Verifier{Source: index}.Verify(context.Background(), c, model, c.Vulnerability)
	c.RootCause = model

	var absent *domain.RootCause
	for i := range model.RootCauses {
		if model.RootCauses[i].Absent {
			absent = &model.RootCauses[i]
		}
	}
	if absent == nil {
		t.Fatalf("model=%+v unverified=%+v — the verifier did not resolve the exact-preimage subject by absence",
			model.RootCauses, model.Unverified)
	}
	if absent.Binding == nil || absent.Binding.SameLine == nil || !absent.Binding.SameLine.Covers() {
		t.Fatalf("binding=%+v — the verifier did not record a covering same-line route", absent.Binding)
	}
	if !rdAdmission(c, model).Admits(subject).Admitted {
		t.Fatalf("refusals=%v — the fresh verifier output did not admit the subject", rdAdmission(c, model).Refusals())
	}

	// Serialize the actual verifier output and replay it: fresh analysis and
	// replay must reach the same admission decision and the same cover.
	raw, err := json.Marshal(model)
	if err != nil {
		t.Fatalf("serialize verifier output: %v", err)
	}
	var replayed domain.RootCauseModel
	if err := json.Unmarshal(raw, &replayed); err != nil {
		t.Fatalf("restore verifier output: %v", err)
	}
	replayedAdmission := rdAdmission(c, &replayed)
	if !replayedAdmission.Admits(subject).Admitted {
		t.Fatalf("refusals=%v — replay reached a different admission decision", replayedAdmission.Refusals())
	}
	if replayedAdmission.Cover() == nil || replayedAdmission.Cover().SubjectDigest == "" {
		t.Fatal("replay established no cover for the admitted subject")
	}

	t.Run("corrupted proof bytes with retained coordinate bindings", func(t *testing.T) {
		tampered := replayed
		tampered.FixArtifacts = append([]domain.FixArtifact(nil), replayed.FixArtifacts...)
		for i := range tampered.FixArtifacts {
			if tampered.FixArtifacts[i].Bytes == "" {
				continue
			}
			tampered.FixArtifacts[i].Bytes = strings.Replace(
				tampered.FixArtifacts[i].Bytes, "-	return s, nil", "-	return s, err", 1)
			tampered.FixArtifacts[i].Digest = domain.EvidenceContentDigest(tampered.FixArtifacts[i].Bytes)
		}
		if tampered.RootCauses[0].Binding == nil || tampered.RootCauses[0].Binding.PatchPath != rdPath {
			t.Fatal("fixture lost the coordinate binding")
		}

		// Duplicate labels carrying the same coordinates: a MANUAL relabel and
		// an LLM proposal. Neither is a new operator input and neither erases
		// the refused dependency.
		manual := tampered.RootCauses[0]
		manual.Origin = domain.RootCauseOriginManual
		manual.Binding = rdCloneBinding(tampered.RootCauses[0].Binding)
		llm := tampered.RootCauses[0]
		llm.Origin = domain.RootCauseOriginLLMProposed
		llm.Binding = rdCloneBinding(tampered.RootCauses[0].Binding)
		tampered.Alternatives = append(tampered.Alternatives, manual, llm)

		admission := rdAdmission(c, &tampered)
		if admission.Admits(subject).Admitted {
			t.Fatalf("the admission admitted %s despite a refused content dependency (basis %q)",
				subject, admission.Admits(subject).Basis)
		}
		if admission.Cover() != nil {
			t.Fatalf("cover=%+v — a refused route still established a necessary cover", admission.Cover())
		}
	})

	t.Run("removed proof artifact with retained coordinate bindings", func(t *testing.T) {
		tampered := replayed
		tampered.FixArtifacts = nil
		manual := tampered.RootCauses[0]
		manual.Origin = domain.RootCauseOriginManual
		manual.Binding = rdCloneBinding(tampered.RootCauses[0].Binding)
		tampered.Alternatives = append(tampered.Alternatives, manual)
		admission := rdAdmission(c, &tampered)
		if admission.Admits(subject).Admitted {
			t.Fatalf("a missing proof artifact was rescued by a relabelled candidate (basis %q)",
				admission.Admits(subject).Basis)
		}
	})

	t.Run("dependent negative does not survive and publication refuses it", func(t *testing.T) {
		tampered := replayed
		// The saved model also carries a persisted proof contract whose captured
		// inputs are gone: the proof is a second refused content dependency of
		// the same subject, and it must not rescue the conclusion either.
		tampered.FixProof = rdAssertedProof(rdRecord, subject)
		tampered.FixArtifacts = append([]domain.FixArtifact(nil), replayed.FixArtifacts...)
		for i := range tampered.FixArtifacts {
			tampered.FixArtifacts[i].Bytes = strings.Replace(
				tampered.FixArtifacts[i].Bytes, "-	return s, nil", "-	return s, err", 1)
			tampered.FixArtifacts[i].Digest = domain.EvidenceContentDigest(tampered.FixArtifacts[i].Bytes)
		}
		manual := tampered.RootCauses[0]
		manual.Origin = domain.RootCauseOriginManual
		manual.Binding = rdCloneBinding(tampered.RootCauses[0].Binding)
		llm := tampered.RootCauses[0]
		llm.Origin = domain.RootCauseOriginLLMProposed
		llm.Binding = rdCloneBinding(tampered.RootCauses[0].Binding)
		tampered.Alternatives = append(tampered.Alternatives, manual, llm)
		// The saved candidate still carries the pre-corruption absent flag.
		tampered.RootCauses[0].Absent = true
		tampered.RootCauses[0].EvidenceIDs = []domain.EvidenceID{"EV-PKGS"}
		c.RootCause = &tampered

		c.Exploit = &domain.ExploitModel{
			RootCauses: []domain.SymbolRef{subject},
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{subject},
			}},
			UnresolvedSubjects: []domain.SymbolRef{subject},
			AbsentSubjects:     []domain.SymbolRef{subject},
		}
		claims := []domain.Claim{{
			ID:          "CL-C-REACH",
			ConditionID: "C-REACH",
			Result:      domain.ClaimFalse,
			Falsifier:   domain.FalsifierPackageAbsent,
			EvidenceIDs: []domain.EvidenceID{"EV-PKGS"},
			Producer:    "evaluator.SymbolReachable",
			NegativeVerification: &domain.NegativeVerification{
				Status:       domain.NegativeVerified,
				EvidenceIDs:  []domain.EvidenceID{"EV-PKGS"},
				BuildContext: &effective,
			},
		}}
		c.Claims = claims
		c.ProfileAssessments = []domain.ProfileAssessment{{
			Profile:        domain.ProfileZeroTrust,
			IsTargetActual: true,
			Build:          effective,
			Claims:         claims,
		}}

		// The honest recomputation is a root-cause failure, not a negative.
		honest := finding.Assess(finding.AssessmentInput{
			VerdictInput: evaluator.VerdictInput{
				Product:   c.Product,
				Affected:  *c.Affected,
				Model:     *c.Exploit,
				Claims:    claims,
				Evidence:  c.EvidenceGraph.EvidenceList(),
				RecordPin: c.RecordPin,
				AdvisoryRecord: c.AdvisoryRecord,
			},
			RootCause:     c.RootCause,
			Vulnerability: c.Vulnerability,
			AssessmentID:  c.ID,
		})
		if honest.Outcome == domain.OutcomeDecided && honest.Verdict != nil &&
			honest.Verdict.Verdict == domain.VerdictNoExploitPathFound {
			t.Fatalf("dependent absence still admitted: %+v", honest)
		}
		if !projectHasGap(honest.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved) {
			t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED", honest.Gaps)
		}

		// The historical saved conclusion does not publish.
		projectSaveWithdrawnNepf(t, c, "C-REACH")
		if got := c.ProfileAssessments[0].Result.Verdict; got == nil ||
			got.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("fixture did not save a NO_EXPLOIT_PATH_FOUND: %+v", c.ProfileAssessments[0].Result)
		}

		historyModel, err := json.Marshal(c.RootCause)
		if err != nil {
			t.Fatalf("snapshot history: %v", err)
		}
		historyEvidence := len(c.EvidenceGraph.Evidence)
		historyClaim := c.Claims[0].Result

		view, err := finding.Project(c)
		if err == nil {
			t.Fatalf("projection published a conclusion grounded by a refused content dependency: %+v", view.Requested)
		}
		if !strings.Contains(err.Error(), "not supported by the current record assessment") &&
			!strings.Contains(err.Error(), "no longer matches current admission") {
			t.Fatalf("refusal does not name the unsupported saved conclusion: %v", err)
		}

		after, err := json.Marshal(c.RootCause)
		if err != nil {
			t.Fatalf("re-snapshot history: %v", err)
		}
		if string(after) != string(historyModel) {
			t.Fatal("publication refusal rewrote the stored root-cause history")
		}
		if len(c.EvidenceGraph.Evidence) != historyEvidence {
			t.Fatal("publication refusal rewrote the stored evidence history")
		}
		if c.Claims[0].Result != historyClaim {
			t.Fatal("publication refusal rewrote the stored claim history")
		}
	})
}

// rdAssertedProof is a persisted proof whose saved projection claims subject
// but whose captured input bundle reconstructs nothing. It is the shape of a
// saved conclusion the checker refuses.
func rdAssertedProof(recordID string, subjects ...domain.SymbolRef) *domain.FixProof {
	claim := map[string]any{
		"contract":        domain.FixProofContract,
		"rules":           domain.FixProofRules,
		"record_id":       recordID,
		"document_digest": "sha256:" + strings.Repeat("a", 64),
		"entry_ref":       0,
		"cover": map[string]any{
			"rule":           domain.FixProofCoverRule,
			"id":             "sha256:" + strings.Repeat("c", 64),
			"subject_digest": domain.AbsenceSubjectSetDigest(subjects),
			"subjects":       subjects,
		},
	}
	binding, err := json.Marshal(claim)
	if err != nil {
		panic(err)
	}
	return &domain.FixProof{
		Contract:       domain.FixProofContract,
		Rules:          domain.FixProofRules,
		RecordID:       recordID,
		DocumentDigest: "sha256:" + strings.Repeat("a", 64),
		EntryRef:       0,
		Cover: domain.FixProofCover{
			Rule:          domain.FixProofCoverRule,
			ID:            "sha256:" + strings.Repeat("c", 64),
			SubjectDigest: domain.AbsenceSubjectSetDigest(subjects),
			Subjects:      append([]domain.SymbolRef(nil), subjects...),
		},
		Digest:  "sha256:" + strings.Repeat("d", 64),
		Binding: binding,
		Inputs:  json.RawMessage(`{}`),
	}
}
