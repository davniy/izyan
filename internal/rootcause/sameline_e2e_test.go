package rootcause

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/exploit"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/fixbinding"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// F11 — TestSameLineResolverVerifierEarnsAbsenceEndToEnd.
//
// The measured defect: root-cause resolution had no content-derived way to name
// a fix's subject, so an ordinary same-line fix-only candidate could not earn
// absence at all — and the "control" that said it could built the candidate
// model by hand, bypassing Resolver, so the withdrawal of the old shortcut went
// unnoticed on the real path.
//
// This test starts at Resolver.Resolve and walks the whole chain: the root-cause
// resolver nominates from the captured patch, the verifier matches the complete
// preimage against the selected version's own source, the exploit builder
// produces the conditions, the negative verifier earns the absence, the verdict
// evaluator grounds NEPF and publication finalises the finding. Nothing in it
// constructs a candidate model directly.
//
// Four cases pin the contract:
//
//   - an ordinary non-permission executable change with exact preimage
//     correspondence and a complete declared boundary, all of whose packages are
//     absent, earns VERIFIED absence and exact-record NEPF;
//   - the same path with a changed preimage stays unresolved;
//   - a required cover member the product links contradicts the absence;
//   - an added helper the changed site never names stays unresolved.

const (
	slE2EModule   = "example.com/dep"
	slE2EVersion  = "v1.0.0"
	slE2EPackage  = slE2EModule + "/omitted"
	slE2ESibling  = slE2EModule + "/encoding"
	slE2EPath     = "omitted/omitted.go"
	slE2ELocator  = "https://example.com/dep/commit/abcdef"
	slE2ERecordID = "GHSA-sameline-e2e"
	slE2EProduct  = "example.com/constprod"
)

// slE2ESource is the selected version's own file. The change repairs an
// omission in place: no permission, directory or other supported operation is
// involved, so the route cannot lean on an operation classifier.
const slE2ESource = `package omitted

import "errors"

func Parse(s string) (string, error) {
	return s, nil
}
`

// slE2EPatch changes one line of Parse and adds a guard — an ordinary
// executable omission repair.
const slE2EPatch = `diff --git a/omitted/omitted.go b/omitted/omitted.go
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

// slE2EPatchWithHelper changes the same site and adds a declaration the changed
// code never names, so the addition is not a repair of an existing pipeline.
const slE2EPatchWithHelper = `diff --git a/omitted/omitted.go b/omitted/omitted.go
index 1111111..2222223 100644
--- a/omitted/omitted.go
+++ b/omitted/omitted.go
@@ -4,4 +4,11 @@ func Parse(s string) (string, error) {
 
 func Parse(s string) (string, error) {
-	return s, nil
+	if s == "" {
+		return "", errors.New("empty")
+	}
+	return s, nil
 }
+
+func normalize(s string) string {
+	return s
+}
`

// slE2EProvider serves the captured patch for the record's fix locator.
type slE2EProvider struct{ patch string }

func (p slE2EProvider) Acquire(_ context.Context, ref fix.Reference) domain.FixArtifact {
	return domain.FixArtifact{
		Locator:    ref.URL,
		Kind:       ref.Kind,
		Provenance: "captured test input",
		Outcome:    domain.FixArtifactComplete,
		Digest:     domain.EvidenceContentDigest(p.patch),
		Size:       len(p.patch),
		Bytes:      p.patch,
		Detail:     "served by the captured provider",
	}
}

// slE2EScope is the exact advisory record the negative closure requires.
func slE2EScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: slE2ERecordID, ResolvedID: slE2ERecordID,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         slE2ERecordID,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: slE2EModule}},
			RepresentedRefs:    []int{0},
		},
	}
}

// slE2EFixture is one end-to-end world: the selected version's source, the
// product build the absence is measured against, and the captured patch.
type slE2EFixture struct {
	root      string
	index     *goanalysis.Index
	product   domain.ProductSnapshot
	source    string
	patch     string
	inventory string
}

func slE2EMakeFixture(t *testing.T, source, patch, inventory string) slE2EFixture {
	t.Helper()
	root := selectedSourceFixture(t, slE2EModule, slE2EVersion, map[string]string{
		slE2EPath: source,
	})
	product := rootCauseProduct()
	index := &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}}
	if err := index.BindBuild(product); err != nil {
		t.Fatalf("bind build: %v", err)
	}
	return slE2EFixture{root: root, index: index, product: product, source: source, patch: patch, inventory: inventory}
}

// slE2ECase records the selected dependency coordinate, the record's own
// declared package boundary and the admitted complete package inventory.
func (f slE2EFixture) caseWith(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	v := domain.Vulnerability{
		ID:         slE2ERecordID,
		Module:     slE2EModule,
		References: []domain.Reference{{Type: "FIX", URL: slE2ELocator}},
	}
	c := &domain.AnalysisCase{
		ID:            domain.CaseID("e2e-same-line"),
		RequestedID:   slE2ERecordID,
		Product:       f.product,
		Vulnerability: v,
		Affected: &domain.AffectedResult{
			Scope:           slE2EScope(),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
			SelectedModule:  slE2EModule,
			SelectedModules: []string{slE2EModule},
			ResolvedVersion: slE2EVersion,
			// The record's own affected-package boundary: what the advisory
			// says the defect can execute in, independent of the patch.
			CheckedPackages: []string{slE2EPackage, slE2ESibling},
		},
	}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		completePackageListEvidence("EV-PKGS", f.product, f.inventory))
	return c
}

// resolveRootCause drives the production resolver and verifier.
func (f slE2EFixture) resolveRootCause(t *testing.T, c *domain.AnalysisCase) (*domain.RootCauseModel, []string) {
	t.Helper()
	model, _, err := Resolver{
		Fix:    fix.Resolver{},
		Patch:  slE2EProvider{patch: f.patch},
		Source: f.index,
	}.Resolve(context.Background(), c, c.Vulnerability)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if model == nil {
		t.Fatal("resolve returned no model")
	}
	lims := Verifier{Source: f.index}.Verify(context.Background(), c, model, c.Vulnerability)
	c.RootCause = model
	return model, lims
}

// publish drives the production exploit-model builder, condition evaluators,
// negative verifier, verdict evaluator and publication.
func (f slE2EFixture) publish(t *testing.T, c *domain.AnalysisCase) (domain.ExploitModel, []domain.Claim, domain.VerdictResult) {
	t.Helper()
	model, lims := exploit.Builder{Source: f.index}.Build(context.Background(), c, c.Vulnerability, c.RootCause)
	if model == nil {
		t.Fatalf("exploit model not built: %v", lims)
	}
	c.Exploit = model

	evaluators := []evaluator.ConditionEvaluator{
		evaluator.SymbolReachable{},
		evaluator.ArgumentOrigin{},
	}
	var claims []domain.Claim
	for _, cond := range model.MandatoryConditions {
		for _, ev := range evaluators {
			if !ev.CanEvaluate(cond) {
				continue
			}
			claim := ev.Evaluate(cond, c)
			if claim.Result == domain.ClaimFalse {
				claim = (goanalysis.Verifier{Source: f.index}).
					VerifyFalse(context.Background(), c, claim, cond)
			}
			claims = append(claims, claim)
			break
		}
	}
	c.Claims = claims

	verdict := evaluator.VerdictEvaluator{}.Evaluate(evaluator.VerdictInput{
		Product:       c.Product,
		Affected:      *c.Affected,
		Model:         *model,
		Claims:        claims,
		Evidence:      c.EvidenceGraph.EvidenceList(),
		Vulnerability: c.Vulnerability,
		RootCause:     c.RootCause,
		RecordPin:     c.RecordPin,
	})
	c.Verdict = &verdict
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          domain.EffectiveBuildContext(f.product),
		Claims:         claims,
		Result: domain.AssessmentResult{
			Outcome: domain.OutcomeDecided,
			Verdict: &verdict,
		},
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return *model, claims, verdict
}

// slE2EInventoryAbsent is a complete product closure that links none of the
// record's declared packages.
func slE2EInventoryAbsent() string {
	return `{"ImportPath":"` + slE2EProduct + `"}` + "\n"
}

// slE2EInventoryWithSibling links one declared cover member: the defect could
// execute there, so the absence of the other member proves nothing.
func slE2EInventoryWithSibling() string {
	return `{"ImportPath":"` + slE2EProduct + `"}` + "\n" +
		`{"ImportPath":"` + slE2ESibling + `"}` + "\n"
}

// subjectOf returns the candidate's absence subject.
func slE2ESubject(rc domain.RootCause) domain.SymbolRef {
	return domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol}
}

// slE2EAbsenceIdentity derives the single shared admission for the fixture and
// asks it about one subject. It is the same record the verifier, builder,
// negative verifier and verdict boundary consult.
func slE2EAbsenceIdentity(t *testing.T, c *domain.AnalysisCase,
	m *domain.RootCauseModel, s domain.SymbolRef) domain.AbsenceIdentityAdmission {
	t.Helper()
	set, id, err := packageImportSet(c)
	if err != nil {
		t.Fatalf("package import set: %v", err)
	}
	build := domain.AbsenceBuildGraph{Paths: set, EvidenceID: id, Admitted: true}
	return domain.AdmitAbsenceFor(m, c.Vulnerability, c.Affected, c.RecordPin, nil, build, fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), m)).Admits(s)
}

// slE2ERequireNotEmpty fail fast when the resolver produced nothing to verify.
func slE2ERequireCandidates(t *testing.T, model *domain.RootCauseModel) {
	t.Helper()
	if len(model.Candidates()) == 0 {
		t.Fatalf("model=%+v — the resolver produced no candidate from the captured patch", model)
	}
}

// The positive case: an opaque same-line omission repair, an exact preimage
// match, a complete declared boundary that is entirely absent from the product,
// and therefore a VERIFIED absence that grounds exact-record NEPF.
func TestSameLineResolverVerifierEarnsAbsenceEndToEnd(t *testing.T) {
	t.Run("earns verified absence and exact-record NEPF", func(t *testing.T) {
		f := slE2EMakeFixture(t, slE2ESource, slE2EPatch, slE2EInventoryAbsent())
		c := f.caseWith(t)
		model, _ := f.resolveRootCause(t, c)
		slE2ERequireCandidates(t, model)

		var absent []domain.RootCause
		for _, rc := range model.Candidates() {
			if rc.Absent {
				absent = append(absent, rc)
			}
		}
		if len(absent) != 1 {
			t.Fatalf("model=%+v unverified=%+v — want exactly one candidate resolved by absence",
				model.RootCauses, model.Unverified)
		}
		rc := absent[0]
		if rc.Binding == nil || rc.Binding.SameLine == nil {
			t.Fatalf("binding=%+v — the same-line route was not recorded", rc.Binding)
		}
		if !rc.Binding.SameLine.Covers() {
			t.Fatalf("same-line=%+v — want a corresponded route", rc.Binding.SameLine)
		}
		if got := rc.Binding.SameLine.OmissionSite; got.Package != slE2EPackage || got.Symbol != "Parse" {
			t.Fatalf("omission site=%+v — want the enclosing selected declaration", got)
		}
		if !slE2EAbsenceIdentity(t, c, c.RootCause, slE2ESubject(rc)).Admitted {
			t.Fatal("the shared admission did not admit the verified same-line subject")
		}

		exploitModel, claims, verdict := f.publish(t, c)
		if len(exploitModel.AbsentSubjects) != 1 || exploitModel.AbsentSubjects[0] != slE2ESubject(rc) {
			t.Fatalf("absent subjects=%+v — want the verified subject", exploitModel.AbsentSubjects)
		}

		var verifiedAbsence bool
		for _, claim := range claims {
			if claim.Result != domain.ClaimFalse || claim.Falsifier != domain.FalsifierPackageAbsent {
				continue
			}
			if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
				t.Fatalf("claim=%+v — the absence must be VERIFIED", claim)
			}
			if claim.NegativeVerification.BuildContext == nil {
				t.Fatalf("claim=%+v — a build-dependent negative records the build it observed", claim)
			}
			// The verification records the admitted cover it relied on, so a
			// replay that re-derives another cover (or no cover) refuses it.
			if claim.NegativeVerification.CoverID == "" ||
				claim.NegativeVerification.SubjectDigest !=
					domain.AbsenceSubjectSetDigest([]domain.SymbolRef{slE2ESubject(rc)}) {
				t.Fatalf("claim=%+v — the verified absence did not record the admitted cover identity", claim)
			}
			verifiedAbsence = true
		}
		if !verifiedAbsence {
			t.Fatalf("claims=%+v — no VERIFIED package-absence claim was produced", claims)
		}
		if verdict.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("verdict=%s reason=%q — want NO_EXPLOIT_PATH_FOUND", verdict.Verdict, verdict.Reason)
		}
		if c.RequestedFinding == nil {
			t.Fatal("publication produced no requested finding")
		}
		if got := c.RequestedFinding.FindingProfile.Verdict; got != domain.VerdictNoExploitPathFound {
			t.Fatalf("published verdict=%q — want the earned NEPF", got)
		}
	})

	t.Run("changed preimage stays unresolved", func(t *testing.T) {
		// Same path, same declared boundary: the selected bytes differ inside
		// the changed region, so nothing corresponds.
		changed := strings.Replace(slE2ESource, "return s, nil", "return s, errors.New(\"x\")", 1)
		f := slE2EMakeFixture(t, changed, slE2EPatch, slE2EInventoryAbsent())
		c := f.caseWith(t)
		model, _ := f.resolveRootCause(t, c)
		slE2ERequireCandidates(t, model)

		for _, rc := range model.Candidates() {
			if rc.Absent {
				t.Fatalf("candidate %s.%s grounded absence on a changed preimage: %+v",
					rc.Package, rc.Symbol, rc)
			}
		}
		if len(model.Unverified) == 0 {
			t.Fatalf("unverified=%+v — a non-corresponding change stays a blocking obligation", model.Unverified)
		}
		if got := model.Unverified[0].Binding.SameLine; got == nil || got.Status != domain.SameLinePreimageUnmatched {
			t.Fatalf("same-line=%+v — want PREIMAGE_UNMATCHED", got)
		}
		if !hasGap(model.AnalysisGaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
			t.Fatalf("gaps=%+v — want the typed unresolved root-cause cause", model.AnalysisGaps)
		}
	})

	t.Run("linked required package contradicts the absence", func(t *testing.T) {
		f := slE2EMakeFixture(t, slE2ESource, slE2EPatch, slE2EInventoryWithSibling())
		c := f.caseWith(t)
		model, _ := f.resolveRootCause(t, c)
		slE2ERequireCandidates(t, model)

		for _, rc := range model.Candidates() {
			if rc.Absent {
				t.Fatalf("candidate %s.%s grounded absence although %s is linked: %+v",
					rc.Package, rc.Symbol, slE2ESibling, rc)
			}
		}
		if len(model.Unverified) == 0 {
			t.Fatalf("unverified=%+v — the contradicted candidate stays a blocking obligation", model.Unverified)
		}
		if got := model.Unverified[0].Binding.SameLine; got == nil || !got.Covers() {
			t.Fatalf("same-line=%+v — the correspondence itself still holds", got)
		}
		var contradicted bool
		for _, gap := range model.AnalysisGaps {
			if gap.Owner == domain.GapOwnerCode && gap.Code == domain.GapRootCauseUnresolved &&
				strings.Contains(gap.Message, slE2ESibling) {
				contradicted = true
			}
		}
		if !contradicted {
			t.Fatalf("gaps=%+v — want the linked cover member named as the contradiction", model.AnalysisGaps)
		}
	})

	t.Run("added helper without an omission carrier stays unresolved", func(t *testing.T) {
		f := slE2EMakeFixture(t, slE2ESource, slE2EPatchWithHelper, slE2EInventoryAbsent())
		c := f.caseWith(t)
		model, _ := f.resolveRootCause(t, c)
		slE2ERequireCandidates(t, model)

		for _, rc := range model.Candidates() {
			if rc.Absent {
				t.Fatalf("candidate %s.%s grounded absence on an uncarried helper: %+v",
					rc.Package, rc.Symbol, rc)
			}
		}
		if len(model.Unverified) == 0 {
			t.Fatalf("unverified=%+v — the uncarried addition stays a blocking obligation", model.Unverified)
		}
		if got := model.Unverified[0].Binding.SameLine; got == nil ||
			got.Status != domain.SameLineAddedHelperWithoutCarrier {
			t.Fatalf("same-line=%+v — want ADDED_HELPER_WITHOUT_CARRIER", got)
		}
	})

	// The recorded route is not the premise: the shared gate re-derives the
	// preimage digest from the model's own captured bytes, so a model whose
	// bytes changed under the record establishes nothing.
	t.Run("captured bytes that no longer hash to the record establish nothing", func(t *testing.T) {
		f := slE2EMakeFixture(t, slE2ESource, slE2EPatch, slE2EInventoryAbsent())
		c := f.caseWith(t)
		model, _ := f.resolveRootCause(t, c)
		slE2ERequireCandidates(t, model)

		var subject domain.SymbolRef
		for _, rc := range model.Candidates() {
			if rc.Binding != nil && rc.Binding.SameLine != nil && rc.Binding.SameLine.Covers() {
				subject = slE2ESubject(rc)
			}
		}
		if subject.Package == "" {
			t.Fatal("the route established no subject to re-derive")
		}
		if !slE2EAbsenceIdentity(t, c, c.RootCause, subject).Admitted {
			t.Fatal("the untouched capture must admit the subject")
		}

		tampered := *model
		tampered.FixArtifacts = append([]domain.FixArtifact(nil), model.FixArtifacts...)
		for i := range tampered.FixArtifacts {
			if tampered.FixArtifacts[i].Bytes == "" {
				continue
			}
			tampered.FixArtifacts[i].Bytes = strings.Replace(
				tampered.FixArtifacts[i].Bytes, "-	return s, nil", "-	return s, err", 1)
			tampered.FixArtifacts[i].Digest = domain.EvidenceContentDigest(tampered.FixArtifacts[i].Bytes)
		}
		if admission := slE2EAbsenceIdentity(t, c, &tampered, subject); admission.Admitted {
			t.Fatalf("the admission admitted a subject whose captured bytes no longer carry the recorded preimage (basis %q)", admission.Basis)
		}
	})
}

// The selected source must be read from the selected version's own tree, so a
// capture that is present but does not carry the file leaves the route
// unmeasured rather than guessing.
func TestSameLineRouteUnmeasuredWithoutSelectedSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/prod\n\ngo 1.15\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &domain.AnalysisCase{
		Affected: &domain.AffectedResult{
			SelectedModule:  slE2EModule,
			SelectedModules: []string{slE2EModule},
			ResolvedVersion: slE2EVersion,
			CheckedPackages: []string{slE2EPackage},
		},
	}
	v := domain.Vulnerability{
		ID:         slE2ERecordID,
		Module:     slE2EModule,
		References: []domain.Reference{{Type: "FIX", URL: slE2ELocator}},
	}
	model, _, err := Resolver{
		Fix:    fix.Resolver{},
		Patch:  slE2EProvider{patch: slE2EPatch},
		Source: &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}},
	}.Resolve(context.Background(), c, v)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, rc := range model.Candidates() {
		if rc.Binding != nil && rc.Binding.SameLine != nil && rc.Binding.SameLine.Covers() {
			t.Fatalf("candidate=%+v — a route was recorded without selected source", rc)
		}
	}
}
