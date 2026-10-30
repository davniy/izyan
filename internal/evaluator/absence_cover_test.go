package evaluator

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fixbinding"
	"github.com/davniy/izyan/internal/goanalysis"
)

// F10 — TestAbsenceClaimMustEqualAdmittedNecessaryCover.
//
// A content-derived absence claim must range over exactly the necessary cover
// the admitted proof establishes: a nonempty subject set containing every mapped
// alternative, a verification that records the same cover identity and
// subject-set digest, and a build graph in which every cover member is absent.
// Empty sets, absent-only subsets, edited model subjects, another verification
// cover and mismatched condition subjects are all refused. A linked alternative
// cannot be made to disappear by editing both saved summaries, because the
// declared boundary is re-derived from the record rather than read from the
// summary.

const (
	coverModule = "example.com/dep"
	coverPkgA   = coverModule + "/omitted"
	coverPkgB   = coverModule + "/encoding"
	coverPathA  = "omitted/omitted.go"
	coverPathB  = "encoding/encoding.go"
	coverLocA   = "https://example.com/dep/commit/aaaa"
	coverLocB   = "https://example.com/dep/commit/bbbb"
	coverSymA   = "Parse"
	coverSymB   = "Filter"
)

// coverPatchA/B are the captured fix bytes the route re-hashes. Only the
// complete before-image matters to the digest; the route never re-parses the
// patch beyond that.
const coverPatchA = `diff --git a/omitted/omitted.go b/omitted/omitted.go
--- a/omitted/omitted.go
+++ b/omitted/omitted.go
@@ -1,3 +1,5 @@
 package omitted
 
-func Parse(s string) (string, error) { return s, nil }
+func Parse(s string) (string, error) {
+	return s, nil
+}
`

const coverPatchB = `diff --git a/encoding/encoding.go b/encoding/encoding.go
--- a/encoding/encoding.go
+++ b/encoding/encoding.go
@@ -1,3 +1,5 @@
 package encoding
 
-func Filter(s string) string { return s }
+func Filter(s string) string {
+	return s
+}
`

var (
	coverSubjectA = domain.SymbolRef{Package: coverPkgA, Symbol: coverSymA}
	coverSubjectB = domain.SymbolRef{Package: coverPkgB, Symbol: coverSymB}
)

// coverSameLine builds one complete same-line route record for a subject.
func coverSameLine(t *testing.T, subject domain.SymbolRef, path, locator, patch string) *domain.SameLineCorrespondence {
	t.Helper()
	digest, ok := domain.PreimageDigest([]byte(patch), path)
	if !ok {
		t.Fatalf("fixture patch for %s carries no before-image", path)
	}
	return &domain.SameLineCorrespondence{
		Locator:            locator,
		Path:               path,
		Status:             domain.SameLineCorresponded,
		PreimageDigest:     digest,
		SelectedFileDigest: "sha256:" + strings.Repeat("cd", 32),
		StartLine:          3,
		EndLine:            4,
		RemovedLines:       1,
		AddedLines:         3,
		OmissionSite:       subject,
		Cover:              []string{coverPkgA, coverPkgB},
	}
}

// coverArtifact is one captured fix artifact carrying the exact patch bytes.
func coverArtifact(locator, patch string) domain.FixArtifact {
	return domain.FixArtifact{
		Locator:     locator,
		Kind:        "commit",
		Outcome:     domain.FixArtifactComplete,
		Provenance:  "captured fixture",
		Digest:      domain.EvidenceContentDigest(patch),
		Size:        len(patch),
		Bytes:       patch,
		Coordinates: []string{},
	}
}

// coverModel is the two-mechanism model: two same-line candidates whose
// omission sites are the two members of the declared package boundary.
func coverModel(t *testing.T) *domain.RootCauseModel {
	t.Helper()
	artifactA := coverArtifact(coverLocA, coverPatchA)
	artifactA.Coordinates = []string{coverPathA}
	artifactB := coverArtifact(coverLocB, coverPatchB)
	artifactB.Coordinates = []string{coverPathB}
	return &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{
				Package: coverPkgA, Symbol: coverSymA, Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginFixDerived,
				Binding: &domain.CandidateBinding{
					Status: domain.CandidateBindingAdmitted, Module: coverModule, PatchPath: coverPathA,
					SameLine: coverSameLine(t, coverSubjectA, coverPathA, coverLocA, coverPatchA),
				},
			},
			{
				Package: coverPkgB, Symbol: coverSymB, Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginFixDerived,
				Binding: &domain.CandidateBinding{
					Status: domain.CandidateBindingAdmitted, Module: coverModule, PatchPath: coverPathB,
					SameLine: coverSameLine(t, coverSubjectB, coverPathB, coverLocB, coverPatchB),
				},
			},
		},
		FixArtifacts: []domain.FixArtifact{artifactA, artifactB},
	}
}

// coverInputs is the exact record, affected chain and build graph the cover is
// measured against. The record declares no symbols: the boundary comes from the
// affected chain's checked packages, so an edited saved summary is the only
// place a narrower set could come from.
func coverInputs() (domain.Vulnerability, *domain.AffectedResult, domain.AbsenceBuildGraph) {
	v := domain.Vulnerability{ID: "GO-COVER-TEST", Module: coverModule}
	affected := &domain.AffectedResult{CheckedPackages: []string{coverPkgA, coverPkgB}}
	build := domain.AbsenceBuildGraph{
		Paths:    map[string]bool{"example.com/prod": true},
		Admitted: true,
	}
	return v, affected, build
}

// coverClaim builds the stamped absence claim for condition subjects.
func coverClaim(t *testing.T, admission domain.AbsenceAdmission, subjects []domain.SymbolRef) (domain.Condition, domain.Claim) {
	t.Helper()
	cond := domain.Condition{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Subjects: subjects}
	nv := &domain.NegativeVerification{
		Status:       domain.NegativeVerified,
		EvidenceIDs:  []domain.EvidenceID{"EV-FIXTURE-PACKAGE-LIST"},
		BuildContext: boundContext(),
	}
	if err := admission.Stamp(cond, nv); err != nil {
		t.Fatalf("stamp canonical claim: %v", err)
	}
	return cond, domain.Claim{
		ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimFalse,
		Falsifier:            domain.FalsifierPackageAbsent,
		EvidenceIDs:          []domain.EvidenceID{"EV-FIXTURE-PACKAGE-LIST"},
		Producer:             "evaluator.SymbolReachable",
		NegativeVerification: nv,
	}
}

func TestAbsenceClaimMustEqualAdmittedNecessaryCover(t *testing.T) {
	v, affected, build := coverInputs()
	model := coverModel(t)
	admission := domain.AdmitAbsenceFor(model, v, affected, nil, nil, build,
		fixbinding.AdmitModelProof(fixbinding.AdmissionInput{Vulnerability: v, Affected: affected}, model))

	cover := admission.Cover()
	if cover == nil {
		t.Fatalf("refusals=%v — the two re-derivable routes established no cover", admission.Refusals())
	}
	if len(cover.Subjects) != 2 || !cover.Covers(coverSubjectA) || !cover.Covers(coverSubjectB) {
		t.Fatalf("cover=%+v — the canonical set must carry every mapped subject", cover)
	}
	if len(cover.Packages) != 2 || !cover.CoversPackage(coverPkgA) || !cover.CoversPackage(coverPkgB) {
		t.Fatalf("cover=%+v — the necessary disjunction must carry the declared boundary", cover)
	}
	if cover.SubjectDigest != domain.AbsenceSubjectSetDigest([]domain.SymbolRef{coverSubjectA, coverSubjectB}) {
		t.Fatalf("subject digest=%q does not bind the canonical set", cover.SubjectDigest)
	}

	// The canonical claim passes: every subject is admitted, the subject set
	// equals the cover, the verification records it and no cover member links.
	cond, claim := coverClaim(t, admission, []domain.SymbolRef{coverSubjectA, coverSubjectB})
	if err := admission.CheckClaim(cond, claim); err != nil {
		t.Fatalf("canonical cover refused: %v", err)
	}

	t.Run("empty condition subject set", func(t *testing.T) {
		empty := domain.Condition{ID: "C-REACH", Kind: domain.ConditionSymbolReachable}
		verification := &domain.NegativeVerification{Status: domain.NegativeVerified, BuildContext: boundContext()}
		err := admission.CheckClaim(empty, domain.Claim{
			ConditionID: "C-REACH", Result: domain.ClaimFalse, Falsifier: domain.FalsifierPackageAbsent,
			NegativeVerification: verification,
		})
		if err == nil {
			t.Fatal("a subject-less absence claim re-admitted against the cover")
		}
	})

	t.Run("absent-only subset", func(t *testing.T) {
		subset := domain.Condition{ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{coverSubjectA}}
		if err := admission.CheckClaim(subset, claim); err == nil {
			t.Fatal("a claim naming only one cover member re-admitted")
		}
	})

	t.Run("edited model subjects", func(t *testing.T) {
		edited := coverModel(t)
		edited.RootCauses[1].Symbol = "Nope"
		editedAdmission := domain.AdmitAbsenceFor(edited, v, affected, nil, nil, build,
			fixbinding.AdmitModelProof(fixbinding.AdmissionInput{Vulnerability: v, Affected: affected}, edited))
		if editedAdmission.Cover() == nil || editedAdmission.Cover().Covers(coverSubjectB) {
			t.Fatalf("cover=%+v — a candidate whose recorded subject disagrees with its route still joined the cover",
				editedAdmission.Cover())
		}
		if err := editedAdmission.CheckClaim(cond, claim); err == nil {
			t.Fatal("a claim naming a subject of an edited model re-admitted")
		}
	})

	t.Run("changed verification cover", func(t *testing.T) {
		_, changed := coverClaim(t, admission, []domain.SymbolRef{coverSubjectA, coverSubjectB})
		changed.NegativeVerification.CoverID = "sha256:" + strings.Repeat("ef", 32)
		if err := admission.CheckClaim(cond, changed); err == nil {
			t.Fatal("a verification recording another cover re-admitted")
		}
	})

	t.Run("mismatched condition subjects", func(t *testing.T) {
		narrowed := domain.Condition{ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{coverSubjectA}}
		// A producer cannot stamp a claim that ranges over only one cover
		// member.
		if err := admission.Stamp(narrowed, &domain.NegativeVerification{Status: domain.NegativeVerified}); err == nil {
			t.Fatal("a narrowed condition was stamped with the full cover identity")
		}
		// And the full-stamped verification cannot be read against the
		// narrowed condition.
		if err := admission.CheckClaim(narrowed, claim); err == nil {
			t.Fatal("a narrowed condition re-admitted against the full cover")
		}
		// A verification that recorded the narrowed subject digest does not
		// match the full cover either.
		_, changed := coverClaim(t, admission, []domain.SymbolRef{coverSubjectA, coverSubjectB})
		changed.NegativeVerification.SubjectDigest = domain.AbsenceSubjectSetDigest([]domain.SymbolRef{coverSubjectA})
		if err := admission.CheckClaim(cond, changed); err == nil {
			t.Fatal("a verification recording another subject-set digest re-admitted")
		}
	})

	t.Run("linked alternative cannot disappear by editing both saved summaries", func(t *testing.T) {
		// The product links the encoding member. The saved summaries are edited
		// to hide it: both candidates' recorded cover is narrowed to the omitted
		// member and the claim names only that member.
		linked := build
		linked.Paths = map[string]bool{"example.com/prod": true, coverPkgB: true}
		edited := coverModel(t)
		for i := range edited.RootCauses {
			edited.RootCauses[i].Binding.SameLine.Cover = []string{coverPkgA}
		}
		linkedAdmission := domain.AdmitAbsenceFor(edited, v, affected, nil, nil, linked,
			fixbinding.AdmitModelProof(fixbinding.AdmissionInput{Vulnerability: v, Affected: affected}, edited))
		narrow := domain.Condition{ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{coverSubjectA}}
		narrowClaim := domain.Claim{
			ConditionID: "C-REACH", Result: domain.ClaimFalse, Falsifier: domain.FalsifierPackageAbsent,
			NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified, BuildContext: boundContext()},
		}
		if err := linkedAdmission.CheckClaim(narrow, narrowClaim); err == nil {
			t.Fatal("an edited saved summary hid a linked cover member")
		}
		if linkedAdmission.Cover() != nil {
			t.Fatalf("cover=%+v — a narrowed saved cover was read as the canonical one", linkedAdmission.Cover())
		}
	})

	t.Run("verdict boundary refuses the subset", func(t *testing.T) {
		exploitModel := domain.ExploitModel{
			RootCauses: []domain.SymbolRef{coverSubjectA, coverSubjectB},
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{coverSubjectA, coverSubjectB},
			}},
		}
		res := affectedAllTrue()
		res.Scope = exactVerdictScope()
		res.CheckedPackages = []string{coverPkgA, coverPkgB}
		// Positive control: the canonical claim grounds NEPF.
		accepted := evalVerdictInput(res, exploitModel, []domain.Claim{claim}, model, v)
		if accepted.Verdict.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("canonical claim verdict=%s gaps=%+v", accepted.Verdict.Verdict, accepted.Gaps)
		}
		// The same saved claim over a narrowed condition is demoted.
		subsetCondition := exploitModel
		subsetCondition.MandatoryConditions[0].Subjects = []domain.SymbolRef{coverSubjectA}
		refused := evalVerdictInput(res, subsetCondition, []domain.Claim{claim}, model, v)
		if refused.Verdict.Verdict == domain.VerdictNoExploitPathFound {
			t.Fatalf("narrowed claim still grounded NEPF: %+v", refused.Verdict)
		}
	})
}

// §3.5: an LLM may propose a location, including one that really exists in the
// selected source, but it cannot establish an advisory-relevant complete
// necessary cover. A source-verified proposal therefore stays non-admitting.
func TestSourceVerifiedLLMProposalNeedsAdvisoryCover(t *testing.T) {
	const module = "example.com/dep"
	const version = "v1.0.0"
	root := absenceSourceFixture(t, module, version, map[string]string{
		"real/real.go": "package real\n\nfunc Existing() string { return \"\" }\n",
	})
	subject := domain.SymbolRef{Package: module + "/real", Symbol: "Existing"}

	product := admittedProduct()
	effective := domain.EffectiveBuildContext(product)
	c := &domain.AnalysisCase{
		Product: product,
		Vulnerability: domain.Vulnerability{
			ID: "GO-LLM-COVER", Module: module,
			// The record declares the module, not this subject: the proposal is
			// the only thing naming it.
			AffectedPackages: []domain.AffectedPackage{{Path: module}},
		},
		Affected: &domain.AffectedResult{
			SelectedModule: module, SelectedModules: []string{module}, ResolvedVersion: version,
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
	// The location is real: the selected source declares it.
	source := &goanalysis.Index{Dir: root}
	if _, err := source.LookupSymbol(t.Context(), subject); err != nil {
		t.Fatalf("fixture source does not declare the proposed subject: %v", err)
	}

	model := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: subject.Package, Symbol: subject.Symbol, Role: domain.RootCauseSink,
			Origin: domain.RootCauseOriginLLMProposed,
		}},
	}
	admission := domain.AdmitAbsence(c, domain.AbsenceBuildGraph{}, fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), c.RootCause))
	if admission.Admits(subject).Admitted {
		t.Fatal("a source-verified LLM proposal established an absence identity")
	}
	admission = domain.AdmitAbsenceFor(model, c.Vulnerability, c.Affected, c.RecordPin, nil,
		domain.AbsenceBuildGraph{Paths: map[string]bool{"example.com/prod": true}, Admitted: true}, fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), model))
	if admission.Admits(subject).Admitted {
		t.Fatal("a real proposed location became an admitted absence subject")
	}
	if admission.Cover() != nil {
		t.Fatalf("cover=%+v — a proposal supplied a necessary cover", admission.Cover())
	}
}
