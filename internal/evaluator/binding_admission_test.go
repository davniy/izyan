package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fixbinding"
)

// This file pins the activated persisted-proof contract at the deterministic
// verdict boundary.
//
// The verdict gate re-derives the model's persisted proof through the pure
// checker. A proof whose captured inputs no longer reconstruct it — or a saved
// projection that claims subjects the reconstruction never produced — cannot
// ground absence, and duplicate operator or LLM labels over the claimed subject
// are dependents of the refused proof, not independent identities.

// assertedFixProof is a persisted proof whose saved projection claims the
// subject, but whose captured input bundle is not the bundle the claim needs.
// It is the shape of a saved conclusion: well-formed, re-derivable in
// principle, and refused the moment the checker looks at the bytes.
func assertedFixProof(recordID string, subjects ...domain.SymbolRef) *domain.FixProof {
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
		// No captured advisory bytes, no selected inventory, no artifact: the
		// proof carries no premise it could be re-derived from.
		Inputs: json.RawMessage(`{}`),
	}
}

// TestRefusedPersistedProofCannotGroundVerdictAbsence is the negative
// activation case: a saved package-absent FALSE over a fix-derived candidate,
// backed by a persisted proof whose inputs do not reconstruct it, must be
// demoted at the verdict boundary. The same boundary refuses the subject and
// establishes no cover.
func TestRefusedPersistedProofCannotGroundVerdictAbsence(t *testing.T) {
	sub := domain.SymbolRef{
		Package: "github.com/containerd/containerd/cmd/containerd/server",
		Symbol:  "CreateTopLevelDirectories",
	}
	binding := &domain.CandidateBinding{
		Status: domain.CandidateBindingAdmitted, Module: "github.com/containerd/containerd",
		Version: "v1.4.3", PatchPath: "cmd/containerd/server/server.go",
	}
	res, exploitModel, claims, rc, v := candidateDerivedNegative(sub, binding, true)
	rc.FixProof = assertedFixProof("GHSA-pwhc-rpq9-4c8w", sub)

	// The shared boundary the verdict gate consults refuses the proof and the
	// subject it claimed.
	admission := domain.AdmitAbsenceFor(rc, v, &res, nil, exploitModel.AbsentSubjects,
		domain.AbsenceBuildGraph{Paths: map[string]bool{"example.com/prod": true}, Admitted: true}, fixbinding.AdmitModelProof(fixbinding.AdmissionInput{Vulnerability: v, Affected: &res}, rc))
	if identity := admission.Admits(sub); identity.Admitted {
		t.Fatalf("a proof with no re-derivable inputs admitted %+v (basis %q)", sub, identity.Basis)
	}
	if admission.Cover() != nil {
		t.Fatalf("a proof with no re-derivable inputs established a cover: %+v", admission.Cover())
	}
	if len(admission.Refusals()) == 0 {
		t.Fatal("the admission preserved no refusal for the persisted proof")
	}

	evaluation := evalVerdictInput(res, exploitModel, claims, rc, v)
	if evaluation.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("a refused persisted proof grounded NO_EXPLOIT_PATH_FOUND")
	}
	if !hasVerdictGap(evaluation.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", evaluation.Gaps)
	}
	if len(evaluation.Verdict.Limitations) == 0 {
		t.Fatal("the refusal was not recorded on the verdict")
	}
}

// TestSavedProjectionCannotAddSubjects pins that the projection is never
// authority: a proof that re-derives is consulted through its reconstruction,
// and a saved cover entry the reconstruction never produced is not admitted,
// even with a coordinate candidate and duplicate operator/LLM labels.
func TestSavedProjectionCannotAddSubjects(t *testing.T) {
	claimed := domain.SymbolRef{Package: "github.com/containerd/containerd/internal/guessed", Symbol: "Create"}
	proof := assertedFixProof("GHSA-pwhc-rpq9-4c8w", claimed)
	// The saved projection is edited after the bytes were fixed: the checker
	// sees the same invalid bundle, so the proof is refused *and* the subject
	// stays refused.
	rc := &domain.RootCauseModel{
		FixProof: proof,
		RootCauses: []domain.RootCause{
			{
				Package: claimed.Package, Symbol: claimed.Symbol, Origin: domain.RootCauseOriginFixDerived,
				Binding: &domain.CandidateBinding{Status: domain.CandidateBindingAdmitted, PatchPath: "internal/guessed/x.go"},
			},
			{Package: claimed.Package, Symbol: claimed.Symbol, Origin: domain.RootCauseOriginManual},
			{Package: claimed.Package, Symbol: claimed.Symbol, Origin: domain.RootCauseOriginLLMProposed},
		},
	}
	v := domain.Vulnerability{ID: "GHSA-pwhc-rpq9-4c8w", Module: "github.com/containerd/containerd"}
	admission := domain.AdmitAbsenceFor(rc, v, nil, nil, nil,
		domain.AbsenceBuildGraph{Paths: map[string]bool{"example.com/prod": true}, Admitted: true}, fixbinding.AdmitModelProof(fixbinding.AdmissionInput{Vulnerability: v}, rc))
	if identity := admission.Admits(claimed); identity.Admitted {
		t.Fatalf("a saved projection edit admitted %+v (basis %q)", claimed, identity.Basis)
	}
	if admission.Cover() != nil {
		t.Fatalf("a saved projection edit established a cover: %+v", admission.Cover())
	}
	if _, err := json.Marshal(rc); err != nil {
		t.Fatalf("the model must remain serializable: %v", err)
	}
}

// TestWithdrawnHistoricalBindingStaysNonAdmittingAtVerdictBoundary keeps the
// withdrawal rule: a stored fix_binding-era payload plus an operator label
// cannot produce a verdict-level negative. The new contract does not revive
// withdrawn history.
func TestWithdrawnHistoricalBindingStaysNonAdmittingAtVerdictBoundary(t *testing.T) {
	sub := domain.SymbolRef{
		Package: "github.com/containerd/containerd/cmd/containerd/server",
		Symbol:  "CreateTopLevelDirectories",
	}
	res, exploitModel, claims, rc, v := candidateDerivedNegative(sub, nil, true)
	rc.FixBinding = &domain.WithdrawnFixBinding{
		RecordID: "GHSA-pwhc-rpq9-4c8w", Status: "ADMITTED",
		Subjects: []domain.SymbolRef{sub},
	}
	rc.RootCauses = append(rc.RootCauses,
		domain.RootCause{Package: sub.Package, Symbol: sub.Symbol, Origin: domain.RootCauseOriginManual})
	evaluation := evalVerdictInput(res, exploitModel, claims, rc, v)
	if evaluation.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("withdrawn historical evidence grounded NO_EXPLOIT_PATH_FOUND")
	}
	if !hasVerdictGap(evaluation.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", evaluation.Gaps)
	}
}
