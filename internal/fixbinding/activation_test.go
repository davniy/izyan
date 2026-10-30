package fixbinding

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/vulnerability"
)

// This file pins the activation contract: a persisted proof is authoritative
// only while the pure checker re-derives it at the shared absence boundary.
//
// Every case starts from the complete fixture bundle — exact advisory bytes,
// captured fix bytes, the anchored selected-implementation inventory and the
// patch-side source capture — so the positive case is a complete fresh proof
// over the exact selected source and the complete recorded inputs, not a
// hand-authored "complete" summary. The negative cases edit exactly one premise
// and require the boundary to refuse.

// persistedFixture persists the fixture derivation and decodes it through the
// persisted schema, so the tests see the bytes a case file would carry.
func persistedFixture(t *testing.T) (domain.FixProof, Binding, Inputs, vulnerability.LoadedRecord) {
	t.Helper()
	in := fixtureInputs(t)
	canonical := deriveFixture(t, in)
	proof, err := Persist(fixtureContext(t), canonical, in)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	var decoded domain.FixProof
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	loaded, err := vulnerability.LoadExactBytes(in.Raw, fixtureRecordID, "osv:test-fixture")
	if err != nil {
		t.Fatalf("load record: %v", err)
	}
	return decoded, canonical, in, loaded
}

// absentBuild is a complete product closure that links none of the fixture's
// declared packages, so every cover member is absent from it.
func absentBuild() domain.AbsenceBuildGraph {
	return domain.AbsenceBuildGraph{
		Paths:      map[string]bool{"example.com/product": true},
		EvidenceID: "EV-PKGS",
		Admitted:   true,
	}
}

// TestPersistedProofReDerivesAtSharedBoundary is the positive activation case:
// the persisted proof re-derives from its captured inputs and grounds the
// aggregate necessary cover at the one boundary every consumer consults.
func TestPersistedProofReDerivesAtSharedBoundary(t *testing.T) {
	proof, canonical, _, loaded := persistedFixture(t)
	model := &domain.RootCauseModel{FixProof: &proof}

	admission := AdmitModelProof(fixtureContext(t), model)
	if !admission.Admitted() {
		t.Fatalf("refusals=%v — the persisted proof did not re-derive from its captured inputs", admission.Refusals)
	}
	if admission.Proof == nil {
		t.Fatal("the checker-created admission carries no canonical proof")
	}
	if !sameSubjects(admission.Proof.Cover.Subjects, canonical.Cover.Subjects) {
		t.Fatalf("admitted subjects %v != reconstructed cover %v",
			admission.Proof.Cover.Subjects, canonical.Cover.Subjects)
	}

	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), admission)
	cover := shared.Cover()
	if cover == nil {
		t.Fatalf("refusals=%v — the persisted proof established no aggregate cover", shared.Refusals())
	}
	if !sameSubjects(cover.Subjects, canonical.Cover.Subjects) {
		t.Fatalf("aggregate cover %v != reconstructed cover %v", cover.Subjects, canonical.Cover.Subjects)
	}
	if !sameSubjects(cover.Mapped, canonical.Cover.Mapped) {
		t.Fatalf("aggregate mapped set %v != reconstructed mapped set %v", cover.Mapped, canonical.Cover.Mapped)
	}
	if !sameSubjects(cover.Alternatives, canonical.Cover.Alternatives) {
		t.Fatalf("aggregate alternatives %v != reconstructed alternatives %v",
			cover.Alternatives, canonical.Cover.Alternatives)
	}
	for _, subject := range cover.Subjects {
		identity := shared.Admits(subject)
		if !identity.Admitted {
			t.Fatalf("cover subject %+v is not admitted: %s", subject, identity.Reason)
		}
		// A record-declared subject keeps its independent record basis; the
		// content binding is what admits the enumerated alternatives the
		// record itself never names.
		if !domain.RecordDeclaresSubject(*loaded.Vuln, subject) &&
			identity.Basis != domain.IdentityBasisContentBinding {
			t.Fatalf("cover subject %+v admitted on basis %q, want %q",
				subject, identity.Basis, domain.IdentityBasisContentBinding)
		}
	}
	// At least one enumerated alternative must be admitted only through the
	// content proof; otherwise the fixture would not exercise the route.
	contentOnly := 0
	for _, subject := range cover.Subjects {
		if !domain.RecordDeclaresSubject(*loaded.Vuln, subject) {
			contentOnly++
		}
	}
	if contentOnly == 0 {
		t.Fatal("no cover subject is established solely by the content proof")
	}

	// The claim must range over exactly this cover, and every cover package
	// must be absent from the admitted build graph.
	claim := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{
			Status:        domain.NegativeVerified,
			CoverID:       cover.ID,
			SubjectDigest: cover.SubjectDigest,
		},
	}
	condition := domain.Condition{ID: "C-REACH", Subjects: append([]domain.SymbolRef(nil), cover.Subjects...)}
	if err := shared.CheckClaim(condition, claim); err != nil {
		t.Fatalf("the canonical claim was refused: %v", err)
	}

	narrowed := condition
	narrowed.Subjects = []domain.SymbolRef{cover.Subjects[0]}
	if err := shared.CheckClaim(narrowed, claim); err == nil {
		t.Fatal("a narrowed condition was admitted against the complete necessary cover")
	}
	linked := absentBuild()
	linked.Paths[cover.Packages[0]] = true
	linkedAdmission := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, linked, admission)
	if err := linkedAdmission.CheckClaim(condition, claim); err == nil {
		t.Fatal("a linked cover member was admitted as absent")
	}
}

// TestAssertedProofSubjectsCannotRescueAbsence is the guessed-proof case: a
// saved binding that claims subjects its captured inputs do not reconstruct,
// with a coordinate candidate and a duplicate operator label for the same
// guessed subject. Nothing admits.
func TestAssertedProofSubjectsCannotRescueAbsence(t *testing.T) {
	proof, canonical, _, loaded := persistedFixture(t)
	guessed := domain.SymbolRef{Package: "example.com/guessed/v2", Symbol: "CreateTopLevelDirectories"}
	proof.Cover.Subjects = append(append([]domain.SymbolRef(nil), proof.Cover.Subjects...), guessed)
	proof.Cover.Packages = append(append([]string(nil), proof.Cover.Packages...), guessed.Package)

	// A coordinate candidate and a duplicate operator label for the same
	// subject: neither is an independent identity for a subject the
	// reconstruction never produced.
	model := &domain.RootCauseModel{
		FixProof: &proof,
		RootCauses: []domain.RootCause{
			{
				Package: guessed.Package, Symbol: guessed.Symbol,
				Origin:  domain.RootCauseOriginFixDerived,
				Binding: &domain.CandidateBinding{Status: domain.CandidateBindingAdmitted, PatchPath: "guessed/v2.go"},
			},
			{
				Package: guessed.Package, Symbol: guessed.Symbol,
				Origin: domain.RootCauseOriginManual,
			},
		},
	}

	admission := AdmitModelProof(fixtureContext(t), model)
	if !admission.Admitted() {
		t.Fatalf("refusals=%v — the saved projection edit changed the reconstruction", admission.Refusals)
	}
	if !sameSubjects(admission.Proof.Cover.Subjects, canonical.Cover.Subjects) {
		t.Fatalf("admitted subjects %v != reconstructed cover %v",
			admission.Proof.Cover.Subjects, canonical.Cover.Subjects)
	}
	for _, subject := range admission.Proof.Cover.Subjects {
		if subject == guessed {
			t.Fatalf("the guessed subject %+v survived into the checker-created cover", guessed)
		}
	}

	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), admission)
	if shared.Admits(guessed).Admitted {
		t.Fatalf("guessed subject %+v admitted (basis %q)", guessed, shared.Admits(guessed).Basis)
	}
	if cover := shared.Cover(); cover != nil && cover.Covers(guessed) {
		t.Fatalf("guessed subject %+v joined the aggregate cover", guessed)
	}
}

// TestRefusedPersistedProofDominatesDependentLabels pins refusal domination:
// when the captured inputs no longer reconstruct the saved proof, the proof's
// claimed subjects cannot be admitted through an operator or LLM label added
// beside them. Independent record declarations still stand.
func TestRefusedPersistedProofDominatesDependentLabels(t *testing.T) {
	base, canonical, _, loaded := persistedFixture(t)
	claimed := canonical.Cover.Subjects[0]
	if domain.RecordDeclaresSubject(*loaded.Vuln, claimed) {
		t.Fatalf("fixture subject %+v is record-declared, so it cannot test dependent-label refusal", claimed)
	}

	mutations := map[string]func(*domain.FixProof){
		"captured advisory bytes replaced": func(p *domain.FixProof) {
			var in Inputs
			if err := json.Unmarshal(p.Inputs, &in); err != nil {
				t.Fatalf("decode inputs: %v", err)
			}
			in.Raw = append([]byte(nil), in.Raw...)
			in.Raw[len(in.Raw)-1] ^= 0xff
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal inputs: %v", err)
			}
			p.Inputs = raw
		},
		"saved cover subject set edited": func(p *domain.FixProof) {
			var claimedBinding Binding
			if err := json.Unmarshal(p.Binding, &claimedBinding); err != nil {
				t.Fatalf("decode binding: %v", err)
			}
			claimedBinding.Cover.Subjects = append([]domain.SymbolRef(nil),
				claimedBinding.Cover.Subjects[1:]...)
			raw, err := json.Marshal(claimedBinding)
			if err != nil {
				t.Fatalf("marshal binding: %v", err)
			}
			p.Binding = raw
		},
		"captured input bundle removed": func(p *domain.FixProof) {
			p.Inputs = nil
		},
		"saved effect inventory edited": func(p *domain.FixProof) {
			var claimedBinding Binding
			if err := json.Unmarshal(p.Binding, &claimedBinding); err != nil {
				t.Fatalf("decode binding: %v", err)
			}
			if len(claimedBinding.Effects) == 0 {
				t.Fatal("fixture has no effect to edit")
			}
			claimedBinding.Effects[0].Disposition = DispositionNonExecutable
			raw, err := json.Marshal(claimedBinding)
			if err != nil {
				t.Fatalf("marshal binding: %v", err)
			}
			p.Binding = raw
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			proof := base
			mutate(&proof)
			model := &domain.RootCauseModel{
				FixProof: &proof,
				RootCauses: []domain.RootCause{
					{Package: claimed.Package, Symbol: claimed.Symbol, Origin: domain.RootCauseOriginManual},
					{Package: claimed.Package, Symbol: claimed.Symbol, Origin: domain.RootCauseOriginLLMProposed},
				},
			}
			admission := AdmitModelProof(fixtureContext(t), model)
			if admission.Admitted() {
				t.Fatal("a proof whose captured inputs do not reconstruct it was admitted")
			}
			if len(admission.Refusals) == 0 {
				t.Fatal("the refusal carries no typed cause")
			}
			shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), admission)
			if identity := shared.Admits(claimed); identity.Admitted {
				t.Fatalf("claimed subject %+v admitted through a dependent label (basis %q)",
					claimed, identity.Basis)
			}
			if cover := shared.Cover(); cover != nil {
				t.Fatalf("a refused proof still established a cover: %+v", cover)
			}
		})
	}
}

// TestWithdrawnHistoricalProofRemainsNonAdmitting keeps the withdrawal
// boundary intact: a stored fix_binding-era payload authorises nothing, even
// when an operator label names one of its subjects. The new proof contract
// does not revive it.
func TestWithdrawnHistoricalProofRemainsNonAdmitting(t *testing.T) {
	proof, canonical, _, loaded := persistedFixture(t)
	claimed := canonical.Cover.Subjects[0]
	withdrawn := &domain.WithdrawnFixBinding{
		RecordID:       proof.RecordID,
		DocumentDigest: proof.DocumentDigest,
		Status:         "ADMITTED",
		Subjects:       []domain.SymbolRef{claimed},
	}
	model := &domain.RootCauseModel{
		FixProof:   &proof,
		FixBinding: withdrawn,
		RootCauses: []domain.RootCause{{Package: claimed.Package, Symbol: claimed.Symbol, Origin: domain.RootCauseOriginManual}},
	}
	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), AdmitModelProof(fixtureContext(t), model))
	identity := shared.Admits(claimed)
	if identity.Admitted {
		t.Fatalf("withdrawn historical subject %+v admitted (basis %q)", claimed, identity.Basis)
	}
	if !strings.Contains(identity.Reason, "withdrawn") {
		t.Fatalf("refusal does not name the withdrawal: %s", identity.Reason)
	}
	// The independent persisted proof still closes through its own route: the
	// withdrawal refuses the label, not unrelated evidence.
	if !AdmitModelProof(fixtureContext(t), model).Admitted() {
		t.Fatal("the independent persisted proof was refused because a withdrawn binding is present")
	}
}

// TestThirdPartyFixProofCannotSubstituteForSelectedSource pins source
// substitution: the same proof re-derived over another module's inventory is
// refused, and no cover is established.
func TestThirdPartyFixProofCannotSubstituteForSelectedSource(t *testing.T) {
	proof, _, _, loaded := persistedFixture(t)
	var in Inputs
	if err := json.Unmarshal(proof.Inputs, &in); err != nil {
		t.Fatalf("decode inputs: %v", err)
	}
	in.Inventory.Module = "example.com/other"
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal inputs: %v", err)
	}
	proof.Inputs = raw
	model := &domain.RootCauseModel{FixProof: &proof}
	if AdmitModelProof(fixtureContext(t), model).Admitted() {
		t.Fatal("a proof re-derived over another module's inventory was admitted")
	}
	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), AdmitModelProof(fixtureContext(t), model))
	if shared.Cover() != nil {
		t.Fatalf("a proof over substituted source established a cover: %+v", shared.Cover())
	}
}

// TestAnotherVersionSourceCannotAnswerTheSelection pins source substitution:
// the persisted proof's input bundle names an effective version, and the
// captured implementation must be exactly that source. Evidence captured for
// v1.4.13 can never answer a v1.4.3 selection, whatever the saved projection
// says.
func TestAnotherVersionSourceCannotAnswerTheSelection(t *testing.T) {
	proof, _, _, loaded := persistedFixture(t)
	var in Inputs
	if err := json.Unmarshal(proof.Inputs, &in); err != nil {
		t.Fatalf("decode inputs: %v", err)
	}
	if len(in.Selection) == 0 {
		t.Fatal("fixture carries no selection")
	}
	in.Selection[0].EffectiveVersion = "v1.4.13"
	in.Selection[0].SourceRoot = in.Selection[0].EffectiveModule + "@v1.4.13"
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal inputs: %v", err)
	}
	proof.Inputs = raw

	model := &domain.RootCauseModel{FixProof: &proof}
	admission := AdmitModelProof(fixtureContext(t), model)
	if admission.Admitted() {
		t.Fatal("another version's captured source answered the recorded selection")
	}
	if !refusalsMention(admission.Refusals, string(RefusalCoordinate)) {
		t.Fatalf("refusals=%v — want the effective-coordinate refusal", admission.Refusals)
	}
	if refusalsMention(admission.Refusals, string(RefusalNonCounterpart)) {
		t.Fatalf("refusals=%v — a substituted source was reported as a non-counterpart disposition", admission.Refusals)
	}
	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), AdmitModelProof(fixtureContext(t), model))
	if shared.Cover() != nil {
		t.Fatalf("a substituted source established a cover: %+v", shared.Cover())
	}
}

// TestMissingExactSourceIsAnInputFailureNotANonCounterpart pins the failure
// direction: without the exact selected source the proof fails as a missing
// input/premise, never as an established non-counterpart.
func TestMissingExactSourceIsAnInputFailureNotANonCounterpart(t *testing.T) {
	proof, _, _, loaded := persistedFixture(t)
	var in Inputs
	if err := json.Unmarshal(proof.Inputs, &in); err != nil {
		t.Fatalf("decode inputs: %v", err)
	}
	in.Selection = nil
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal inputs: %v", err)
	}
	proof.Inputs = raw

	model := &domain.RootCauseModel{FixProof: &proof}
	admission := AdmitModelProof(fixtureContext(t), model)
	if admission.Admitted() {
		t.Fatal("a proof without its exact selected source was admitted")
	}
	if refusalsMention(admission.Refusals, string(RefusalNonCounterpart)) {
		t.Fatalf("refusals=%v — missing source was reported as a non-counterpart proof", admission.Refusals)
	}
	if !refusalsMention(admission.Refusals, string(RefusalCoordinate)) &&
		!refusalsMention(admission.Refusals, string(RefusalInput)) {
		t.Fatalf("refusals=%v — want an input/coordinate failure", admission.Refusals)
	}
	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), AdmitModelProof(fixtureContext(t), model))
	if shared.Cover() != nil {
		t.Fatalf("a proof without its source established a cover: %+v", shared.Cover())
	}
}

// TestGuessedV2SubjectSetCannotGroundAbsence is the Helm guessed-proof case:
// the saved subjects were read from a v2/main-line layout and none of their
// packages is a subject of the selected version. A coordinate binding and a
// duplicated operator label do not establish them, and a proof whose captured
// inputs never produced them does not either.
func TestGuessedV2SubjectSetCannotGroundAbsence(t *testing.T) {
	proof, _, _, loaded := persistedFixture(t)
	guessed := []domain.SymbolRef{
		{Package: "github.com/helm/helm/v2/cmd/helm", Symbol: "newInstallCmd"},
		{Package: "github.com/helm/helm/v2/pkg/chartutil", Symbol: "Create"},
	}
	proof.Cover.Subjects = append([]domain.SymbolRef(nil), guessed...)
	proof.Cover.Packages = []string{guessed[0].Package, guessed[1].Package}
	proof.Cover.SubjectDigest = domain.AbsenceSubjectSetDigest(guessed)

	model := &domain.RootCauseModel{FixProof: &proof}
	for _, subject := range guessed {
		model.RootCauses = append(model.RootCauses,
			domain.RootCause{
				Package: subject.Package, Symbol: subject.Symbol, Origin: domain.RootCauseOriginFixDerived,
				Binding: &domain.CandidateBinding{Status: domain.CandidateBindingAdmitted, PatchPath: "v2/path.go"},
			},
			domain.RootCause{Package: subject.Package, Symbol: subject.Symbol, Origin: domain.RootCauseOriginManual},
		)
	}
	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), AdmitModelProof(fixtureContext(t), model))
	for _, subject := range guessed {
		if identity := shared.Admits(subject); identity.Admitted {
			t.Fatalf("guessed v2 subject %+v admitted (basis %q)", subject, identity.Basis)
		}
	}
	// The persisted proof's captured inputs still reconstruct the real
	// cover; the edited projection must not replace it with the guessed set.
	cover := shared.Cover()
	if cover == nil {
		t.Fatalf("refusals=%v — the reconstruction lost its cover", shared.Refusals())
	}
	for _, subject := range guessed {
		if cover.Covers(subject) {
			t.Fatalf("guessed v2 subject %+v joined the reconstructed cover", subject)
		}
	}
}

// refusalsMention reports whether any preserved refusal names token.
func refusalsMention(refusals []string, token string) bool {
	for _, refusal := range refusals {
		if strings.Contains(refusal, token) {
			return true
		}
	}
	return false
}

// unsupportedFixPatch changes a guard in the selected implementation without
// touching any declaration the supported operation set classifies. It is
// captured fix material — complete bytes with a declared locator — that the
// semantic proof has nothing to be about.
func unsupportedFixPatch() []byte {
	return []byte(`diff --git a/server/server.go b/server/server.go
index 1111111..3333333 100644
--- a/server/server.go
+++ b/server/server.go
@@ -13,6 +13,9 @@
 func CreateTopLevelDirectories(cfg *config.Config) error {
+	if cfg.Root == "" {
+		return errInvalidRoot
+	}
 	if err := os.MkdirAll(cfg.Root, 0711); err != nil {
 		return err
 	}
 	return nil
 }
`)
}

// unsupportedFixInputs is the same complete bundle as the fixture with its
// captured material replaced by a patch that resolves no supported operation.
func unsupportedFixInputs(t *testing.T) Inputs {
	t.Helper()
	patch := unsupportedFixPatch()
	bundle, unmatched := PatchSourceFromSelected(patch,
		ModuleIdentity{Path: fixtureModule, Version: fixtureSelectedVer}, fixtureSelectedFiles())
	if bundle == nil {
		t.Fatalf("the unsupported patch did not apply to the selected source: %v", unmatched)
	}
	in := fixtureInputs(t)
	in.Artifacts = []ArtifactInput{capturedArtifact(fixtureLocator, "commit", patch)}
	in.PatchSources = map[string]*SourceBundle{fixtureLocator: bundle}
	return in
}

// TestUnsupportedFixDoesNotInvokeSemanticProof pins the fix-proof
// applicability contract: material that changes no supported security
// operation is not a mechanism proof. The probe refuses it before the semantic
// derivation is attempted, and the derivation — when called directly — refuses
// too, establishing no effect, no subject and therefore no absence authority.
func TestUnsupportedFixDoesNotInvokeSemanticProof(t *testing.T) {
	in := unsupportedFixInputs(t)
	_, _, _, loaded := persistedFixture(t)

	app := FixApplicability(in)
	if app.Applicable {
		t.Fatalf("material with no supported operation was reported applicable: %+v", app)
	}
	if len(app.Locators) != 1 || app.Locators[0].Locator != fixtureLocator {
		t.Fatalf("applicability did not measure the captured locator: %+v", app.Locators)
	}
	if len(app.Locators[0].Classes) != 0 {
		t.Fatalf("applicability resolved classes %v from material that names none", app.Locators[0].Classes)
	}
	reason := app.Reason()
	if !strings.Contains(reason, fixtureLocator) ||
		!strings.Contains(reason, "resolves none of the supported security operations") {
		t.Fatalf("refusal %q does not name the locator and the missing vocabulary", reason)
	}

	// The positive control for the probe: the fixture's own captured patch
	// changes os.MkdirAll and os.Chmod, so the same bundle applies.
	supported := FixApplicability(fixtureInputs(t))
	if !supported.Applicable {
		t.Fatalf("the fixture's captured patch was reported inapplicable: %+v", supported)
	}

	binding, err := Derive(in)
	if err == nil {
		t.Fatalf("the semantic derivation established a binding over unsupported material: %+v", binding.Cover)
	}
	if code := RefusalCodeOf(err); code != RefusalObligations {
		t.Fatalf("refusal=%s (%v), want %s", code, err, RefusalObligations)
	}
	if code := RefusalCodeOf(err); code == RefusalCover {
		t.Fatalf("unsupported material reached the cover stage: %v", err)
	}
	if len(binding.Effects) != 0 || len(binding.Mechanisms) != 0 || len(binding.Cover.Subjects) != 0 {
		t.Fatalf("unsupported material produced a semantic result: effects=%+v mechanisms=%+v cover=%+v",
			binding.Effects, binding.Mechanisms, binding.Cover)
	}
	var observed bool
	for _, obligation := range binding.Obligations {
		if obligation.Code == "NO_EXECUTABLE_EFFECT" {
			observed = true
		}
	}
	if !observed {
		t.Fatalf("obligations=%+v, want the NO_EXECUTABLE_EFFECT observation", binding.Obligations)
	}

	// With no persisted proof there is nothing for the shared absence boundary
	// to activate: unsupported material grants no absence authority.
	model := &domain.RootCauseModel{}
	if admission := AdmitModelProof(fixtureContext(t), model); admission != nil {
		t.Fatalf("unsupported material was admitted as a content proof: %+v", admission)
	}
	shared := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), nil)
	if cover := shared.Cover(); cover != nil {
		t.Fatalf("unsupported material established an aggregate cover: %+v", cover)
	}
}

func TestAdmissionReuseMatchesFreshDerivation(t *testing.T) {
	proof, _, _, loaded := persistedFixture(t)
	model := &domain.RootCauseModel{FixProof: &proof}

	reused := AdmitModelProof(fixtureContext(t), model)
	if !reused.Admitted() {
		t.Fatalf("reused proof admission refused: %v", reused.Refusals)
	}

	build1 := absentBuild()
	build2 := domain.AbsenceBuildGraph{
		Paths:      map[string]bool{"example.com/other": true},
		EvidenceID: "EV-OTHER",
		Admitted:   true,
	}

	reuse1 := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, build1, reused)
	reuse2 := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, build2, reused)

	fresh1 := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, build1, AdmitModelProof(fixtureContext(t), model))
	fresh2 := domain.AdmitAbsenceFor(model, *loaded.Vuln, nil, &loaded.Pin, nil, build2, AdmitModelProof(fixtureContext(t), model))

	if reuse1.Cover() == nil || fresh1.Cover() == nil || reuse1.Cover().ID != fresh1.Cover().ID {
		t.Fatalf("reuse1 cover ID %v != fresh1 cover ID %v", reuse1.Cover(), fresh1.Cover())
	}
	if reuse2.Cover() == nil || fresh2.Cover() == nil || reuse2.Cover().ID != fresh2.Cover().ID {
		t.Fatalf("reuse2 cover ID %v != fresh2 cover ID %v", reuse2.Cover(), fresh2.Cover())
	}
	for _, sub := range reuse1.Cover().Subjects {
		if reuse1.Admits(sub) != fresh1.Admits(sub) {
			t.Fatalf("admission for %v differs between reuse and fresh", sub)
		}
	}
}

func TestChangedProofRequiresNewAdmission(t *testing.T) {
	proof, _, _, loaded := persistedFixture(t)
	model := &domain.RootCauseModel{FixProof: &proof}

	initial := AdmitModelProof(fixtureContext(t), model)
	if !initial.Admitted() {
		t.Fatalf("initial proof admission refused: %v", initial.Refusals)
	}

	changedProof := proof
	changedProof.Inputs = json.RawMessage(`{"invalid":true}`)
	changedModel := &domain.RootCauseModel{FixProof: &changedProof}

	newAdmission := AdmitModelProof(fixtureContext(t), changedModel)
	if newAdmission != nil && newAdmission.Admitted() {
		t.Fatal("changed proof unexpectedly admitted")
	}

	changedAdmission := domain.AdmitAbsenceFor(changedModel, *loaded.Vuln, nil, &loaded.Pin, nil, absentBuild(), newAdmission)
	if changedAdmission.Cover() != nil {
		t.Fatalf("changed proof established a cover: %+v", changedAdmission.Cover())
	}
}
