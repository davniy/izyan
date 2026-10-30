package evaluator

import (
	"slices"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func affectedAllTrue() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}
}

// exactVerdictScope is a structurally complete exact-record binding: an exact
// GO- identity over one original affected[] entry that the loaded record fully
// represented as a resolved Go module. It is the only fixture here that
// authorizes a negative finding-level conclusion — COMPLETE coverage alone
// does not (see TestVerdictPartialScopeNegativeMatrix).
func exactVerdictScope() *domain.AdvisoryScope {
	return fullRecordScope("GO-TEST-1", "golang.org/x/net")
}

// fullRecordScope binds id to a full-content census of a single Go entry. The
// digest is a fixed, well-formed sha256 so the fixture carries structural
// evidence without inventing a document.
func fullRecordScope(id, module string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: module}},
			RepresentedRefs:    []int{0},
		},
	}
}

// evalVerdict drives the production entry point inside a fixture world in
// which the producers' measurements actually exist: a scoped product build, a
// complete matching package inventory, and — per claim falsifier — the typed
// run the producer would have cited. Admission refusals themselves are
// exercised by TestTargetAdmission/TestMeasurementAdmission, which call the
// evaluator with deliberately missing or mismatched evidence.
func evalVerdict(res domain.AffectedResult, model domain.ExploitModel, claims []domain.Claim) domain.VerdictResult {
	return evalVerdictInput(res, model, claims, nil, domain.Vulnerability{}).Verdict
}

// evalVerdictInput is evalVerdict carrying the identity re-admission inputs a
// persisted case always has: the exact record and its root-cause model. The
// detailed form is returned so a test can read the typed gap causes too.
func evalVerdictInput(res domain.AffectedResult, model domain.ExploitModel, claims []domain.Claim,
	rc *domain.RootCauseModel, v domain.Vulnerability) VerdictEvaluation {
	product := admittedProduct()
	evidence := []domain.Evidence{completePackageList()}
	admitted := append([]domain.Claim(nil), claims...)
	for i := range admitted {
		cl := &admitted[i]
		if cl.Result != domain.ClaimFalse {
			continue
		}
		if nv := cl.NegativeVerification; nv != nil &&
			nv.Status == domain.NegativeVerified && nv.BuildContext == nil {
			cp := *nv
			cp.BuildContext = boundContext()
			cl.NegativeVerification = &cp
		}
		cond, ok := modelCondition(model, cl.ConditionID)
		if !ok {
			continue
		}
		switch cl.Falsifier {
		case domain.FalsifierGovulncheckSilence:
			ev := fixtureSilenceMeasurement(cond, product)
			evidence = append(evidence, ev)
			cl.EvidenceIDs = append(cl.EvidenceIDs, ev.ID)
		case domain.FalsifierNoModuleUsage, domain.FalsifierUnreachedExportedSubject:
			evidence = append(evidence, fixtureSourceScans(cond, product)...)
		case domain.FalsifierLocusFunctionUnreached:
			evidence = append(evidence, fixtureSourceScans(cond, product)...)
			if cl.NegativeVerification != nil && cl.NegativeVerification.Status == domain.NegativeVerified {
				ev, _ := fixtureLocusKernel(cond, product)
				evidence = append(evidence, ev)
				cp := *cl.NegativeVerification
				cp.EvidenceIDs = append(append([]domain.EvidenceID(nil), cp.EvidenceIDs...), ev.ID)
				cl.NegativeVerification = &cp
			}
		}
	}
	return VerdictEvaluator{}.EvaluateDetailed(VerdictInput{
		Product:       product,
		Affected:      res,
		Model:         model,
		Claims:        admitted,
		Evidence:      evidence,
		Vulnerability: v,
		RootCause:     rc,
	})
}

// modelCondition resolves a model condition by id.
func modelCondition(model domain.ExploitModel, id domain.ConditionID) (domain.Condition, bool) {
	for _, cond := range model.MandatoryConditions {
		if cond.ID == id {
			return cond, true
		}
	}
	for _, cond := range model.SupportingFactors {
		if cond.ID == id {
			return cond, true
		}
	}
	return domain.Condition{}, false
}

// fixtureSilenceMeasurement is a completed-empty govulncheck run of a covered
// advisory over the whole build, declaring every condition subject.
func fixtureSilenceMeasurement(cond domain.Condition, product domain.ProductSnapshot) domain.Evidence {
	build := domain.EffectiveBuildContext(product)
	return domain.Evidence{
		ID:           "EV-FIXTURE-GOVULNCHECK",
		Kind:         domain.EvidenceGovulncheck,
		Quality:      domain.QualityDeterministic,
		BuildContext: &build,
		Govulncheck: &domain.GovulncheckRun{
			Outcome: domain.GovulncheckCompletedEmpty,
			Coverage: domain.GovulncheckCoverage{
				AdvisoryID:    "GO-TEST-1",
				Advisory:      domain.GovulncheckCoverageCovered,
				Subjects:      condSubjects(cond),
				ScopeComplete: true,
			},
		},
	}
}

// fixtureSourceScans are completed, complete, non-opaque source measurements
// covering every condition subject by owning module.
func fixtureSourceScans(cond domain.Condition, product domain.ProductSnapshot) []domain.Evidence {
	build := domain.EffectiveBuildContext(product)
	var out []domain.Evidence
	for i, s := range condSubjects(cond) {
		out = append(out, domain.Evidence{
			ID:           domain.EvidenceID("EV-FIXTURE-SCAN-" + string(rune('A'+i))),
			Kind:         domain.EvidenceSourceScan,
			Quality:      domain.QualityDeterministic,
			BuildContext: &build,
			SourceScan: &domain.SourceScanRun{
				Module:       s.Package,
				Subjects:     []domain.SymbolRef{s},
				EntrySymbols: []string{s.Package + ".Entry"},
				Completed:    true,
				Complete:     true,
			},
		})
	}
	return out
}

func TestVerdictNotAffected(t *testing.T) {
	for field, res := range map[string]domain.AffectedResult{
		"module":  {ModulePresent: domain.ClaimFalse},
		"version": {ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse},
		"package": {ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse},
		"build":   {ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimFalse},
		"implementation": {
			ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue,
			PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue,
			VulnerableImplementationPresent: domain.ClaimFalse,
		},
	} {
		res.Scope = exactVerdictScope()
		got := evalVerdict(res, domain.ExploitModel{}, nil)
		if got.Verdict != domain.VerdictNotAffected {
			t.Errorf("%s FALSE: got %s, want NOT_AFFECTED", field, got.Verdict)
		}
	}
}

// A subject that is present only through test roots must never be
// reported as absent from the recorded closure: the -test stream the
// reason cites is exactly where it WAS found. The typed test-only basis
// names the real exclusion instead.
func TestVerdictTestOnlyReasonNamesTestScopeNotAbsence(t *testing.T) {
	res := domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimFalse,
		BuildRelevant:   domain.ClaimFalse,
		TestOnlyScope:   []string{"gopkg.in/yaml.v3"},
		CheckedPackages: []string{"gopkg.in/yaml.v3"},
		Scope:           exactVerdictScope(),
	}
	got := evalVerdict(res, domain.ExploitModel{}, nil)
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("test-only subject: got %s, want NOT_AFFECTED", got.Verdict)
	}
	if !strings.Contains(got.Reason, "test scope") {
		t.Fatalf("reason must name the test-scope exclusion, got: %s", got.Reason)
	}
	if strings.Contains(got.Reason, "transitive import closure") {
		t.Fatalf("reason must not claim absence from the closure the subject was found in, got: %s", got.Reason)
	}
	// The non-test-only path keeps the closure-absence wording.
	res.TestOnlyScope = nil
	plain := evalVerdict(res, domain.ExploitModel{}, nil)
	if plain.Verdict != domain.VerdictNotAffected {
		t.Fatalf("plain absence: got %s, want NOT_AFFECTED", plain.Verdict)
	}
	if !strings.Contains(plain.Reason, "transitive import closure") {
		t.Fatalf("plain absence must keep the closure wording, got: %s", plain.Reason)
	}
}

// The implementation axis is an affected-chain FALSE, not a reachability
// falsifier: it produces NOT_AFFECTED with the verified locus and target
// scope, while the policy assumption ids stay separate from evidence.
func TestVerdictImplementationAxisNotAffected(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	res.VulnerableImplementationPresent = domain.ClaimFalse
	res.ImplementationLocus = "go.example/dep/resource/host_bsd.go read (marker \"kenv\", //go:build freebsd)"
	res.ImplementationTarget = "linux/amd64"
	res.ImplementationTargetScope = "product"
	res.AssumptionIDs = []string{"AT-linux-only"}
	res.EvidenceIDs = []domain.EvidenceID{"EV-IMPL-1"}
	got := evalVerdict(res, domain.ExploitModel{}, nil)
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("got %s, want NOT_AFFECTED", got.Verdict)
	}
	for _, want := range []string{"host_bsd.go", "linux/amd64", "product target scope"} {
		if !strings.Contains(got.Reason, want) {
			t.Fatalf("reason %q does not name %q", got.Reason, want)
		}
	}
	if len(got.AssumptionIDs) != 1 || got.AssumptionIDs[0] != "AT-linux-only" {
		t.Fatalf("assumption ids = %v", got.AssumptionIDs)
	}
	if len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != "EV-IMPL-1" {
		t.Fatalf("evidence ids = %v", got.EvidenceIDs)
	}
}

// The implementation axis may not close without the established
// package/build axes; UNKNOWN stays INCONCLUSIVE.
func TestVerdictImplementationAxisFailsClosed(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	res.VulnerableImplementationPresent = domain.ClaimFalse
	res.PackagePresent = domain.ClaimUnknown
	if got := evalVerdict(res, domain.ExploitModel{}, nil); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("implementation FALSE without package presence: got %s, want INCONCLUSIVE", got.Verdict)
	}
	res.PackagePresent = domain.ClaimTrue
	res.BuildRelevant = domain.ClaimUnknown
	if got := evalVerdict(res, domain.ExploitModel{}, nil); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("implementation FALSE without build relevance: got %s, want INCONCLUSIVE", got.Verdict)
	}
	res = affectedAllTrue()
	res.VulnerableImplementationPresent = domain.ClaimUnknown
	if got := evalVerdict(res, domain.ExploitModel{}, nil); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("implementation UNKNOWN: got %s, want INCONCLUSIVE", got.Verdict)
	}
	res = affectedAllTrue()
	res.VulnerableImplementationPresent = domain.ClaimTrue
	if got := evalVerdict(res, domain.ExploitModel{}, nil); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("implementation TRUE must not assert a verdict: got %s", got.Verdict)
	}
	// BuildRelevant keeps its own meaning and remains the closing axis
	// when the package is platform-excluded as a whole.
	res = affectedAllTrue()
	res.Scope = exactVerdictScope()
	res.BuildRelevant = domain.ClaimFalse
	res.VulnerableImplementationPresent = domain.ClaimFalse
	got := evalVerdict(res, domain.ExploitModel{}, nil)
	if got.Verdict != domain.VerdictNotAffected || !strings.Contains(got.Reason, "other platforms/build configurations") {
		t.Fatalf("build-relevant FALSE precedence = %s (%q)", got.Verdict, got.Reason)
	}
}

func TestVerdictExploitable(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}, {ID: "C2"}},
	}
	claims := []domain.Claim{
		{ConditionID: "C1", Result: domain.ClaimTrue},
		{ConditionID: "C2", Result: domain.ClaimTrue},
	}
	got := evalVerdict(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictExploitable {
		t.Fatalf("got %s, want EXPLOITABLE", got.Verdict)
	}
}

func TestVerdictNoExploitPathFoundRequiresVerification(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
	}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	unverified := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimFalse}}
	got := evalVerdict(res, model, unverified)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("unverified FALSE: got %s, want INCONCLUSIVE", got.Verdict)
	}

	verified := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got = evalVerdict(res, model, verified)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verified FALSE without falsifier: got %s, want INCONCLUSIVE", got.Verdict)
	}
	verified[0].Falsifier = domain.FalsifierConstantOrGeneratedInput
	got = evalVerdict(res, model, verified)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verified FALSE: got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// An advisory-declared sink that failed source resolution narrows the
// modeled mandatory set — EXPLOITABLE on a partial model would claim
// completeness the pipeline did not prove.
func TestVerdictExploitableBlockedByUnresolvedSubjects(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
		UnresolvedSubjects: []domain.SymbolRef{
			{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"},
		},
	}
	claims := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimTrue}}
	got := evalVerdict(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
	if !strings.Contains(got.Reason, "RouteAndProcess") {
		t.Fatalf("reason must name the unresolved sink: %q", got.Reason)
	}
}

// TestUnresolvedMechanismBlocksAllTruePositive pins the guard for a model
// whose mechanism was only nominated: keyword, fix-diff or conflicting prose
// evidence names a class, so the class pattern's extra conditions were never
// merged — and an all-TRUE conjunction over the reduced set must not become a
// positive merely because the nomination's conditions are gone. An
// independently verified falsifier still decides the negative.
func TestUnresolvedMechanismBlocksAllTruePositive(t *testing.T) {
	conditions := []domain.Condition{
		{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
		{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, ArgIndex: 0,
			Params: map[string]string{domain.ParamInputSource: domain.InputArg}},
	}
	claims := []domain.Claim{
		{ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ConditionID: "C-INPUT", Result: domain.ClaimTrue},
	}
	model := domain.ExploitModel{MandatoryConditions: conditions, UnresolvedMechanism: true}

	got := evalVerdictInput(affectedAllTrue(), model, claims, nil, domain.Vulnerability{})
	if got.Verdict.Verdict == domain.VerdictExploitable {
		t.Fatalf("an unresolved mechanism grounded a positive: %+v", got.Verdict)
	}
	if got.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%s, want INCONCLUSIVE", got.Verdict.Verdict)
	}
	if !strings.Contains(got.Verdict.Reason, "mechanism") {
		t.Fatalf("reason must name the unresolved mechanism: %q", got.Verdict.Reason)
	}
	found := false
	for _, gap := range got.Gaps {
		if gap.Owner == domain.GapOwnerExternal || gap.External != nil {
			t.Fatalf("the mechanism gap must be analyzer work, never external: %+v", gap)
		}
		if gap.Owner == domain.GapOwnerCode && gap.Code == domain.GapRootCauseUnresolved &&
			gap.Obligation == domain.ObligationRootCause {
			found = true
		}
	}
	if !found {
		t.Fatalf("gaps = %+v; want a CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE cause", got.Gaps)
	}

	// The flag is the whole difference: the same conjunction with an
	// established mechanism still earns the positive.
	model.UnresolvedMechanism = false
	if baseline := evalVerdict(affectedAllTrue(), model, claims); baseline.Verdict != domain.VerdictExploitable {
		t.Fatalf("baseline verdict=%s, want EXPLOITABLE without the flag", baseline.Verdict)
	}

	// An independently verified mandatory falsifier still decides a negative:
	// unresolved extra modeling must not fabricate one, and must not veto a
	// real one either.
	model.UnresolvedMechanism = true
	falsified := []domain.Claim{
		{
			ConditionID: "C-REACH",
			Result:      domain.ClaimFalse,
			Falsifier:   domain.FalsifierConstantOrGeneratedInput,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
			},
		},
		{ConditionID: "C-INPUT", Result: domain.ClaimTrue},
	}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	if neg := evalVerdict(res, model, falsified); neg.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verified falsifier verdict=%s, want NO_EXPLOIT_PATH_FOUND", neg.Verdict)
	}
}

// A verified FALSE on the grouped reachability falsifier covers every
// advisory-declared symbol — including the unresolved one — so NEPF stays
// sound on an incomplete model.
func TestVerdictNepfAllowedForCoveringFalsifier(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C1", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}},
		}},
		UnresolvedSubjects: []domain.SymbolRef{{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, claims)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// A verified FALSE bound to the resolved sinks' arguments leaves the
// unresolved sink's exploit shape unconstrained — no NEPF.
func TestVerdictNepfBlockedForNarrowFalsifier(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionInputConstraint}},
		UnresolvedSubjects:  []domain.SymbolRef{{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
}

// A verified locus-package-absent falsifier discharges unresolved subjects
// that are themselves locus members — the same build-graph absence covers
// them.
func TestVerdictNepfAllowedForLocusCoveringUnresolved(t *testing.T) {
	locus := domain.SymbolRef{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
			Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
			Subjects: []domain.SymbolRef{locus},
		}},
		UnresolvedSubjects: []domain.SymbolRef{locus},
	}
	claims := []domain.Claim{{
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	// The record declares the locus subject: that declaration is the
	// affirmative basis the absence falsifier rests on.
	v := domain.Vulnerability{ID: "GO-TEST", AffectedSymbols: []domain.SymbolRef{locus}}
	got := evalVerdictInput(res, model, claims, nil, v).Verdict
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// A verified declared-symbol-unreached falsifier spans every advisory
// declared symbol — the deterministic route only promotes it when the
// complete proof covers the union — so NEPF stays sound on an
// incomplete model.
func TestVerdictNepfAllowedForDeclaredSymbolUnreached(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionSymbolReachable}},
		UnresolvedSubjects:  []domain.SymbolRef{{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierDeclaredSymbolUnreached,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, claims)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// coversAllDeclared must keep admitting exactly the covering falsifiers —
// dropping a member silently demotes a verified negative to INCONCLUSIVE,
// and admitting a narrow falsifier would wrongly close unresolved subjects.
func TestCoversAllDeclaredSet(t *testing.T) {
	for _, kind := range []domain.FalsifierKind{
		domain.FalsifierGovulncheckSilence,
		domain.FalsifierNoModuleUsage,
		domain.FalsifierUnreachedExportedSubject,
		domain.FalsifierConfigGatedOff,
		domain.FalsifierDeclaredSymbolUnreached,
	} {
		if !coversAllDeclared(domain.Claim{Falsifier: string(kind)}) {
			t.Fatalf("covering falsifier %q rejected", kind)
		}
	}
	if !coversAllDeclared(domain.Claim{Falsifier: domain.FalsifierTrustedInfrastructure, FalsifierBasis: domain.BasisDeclaredTrust}) {
		t.Fatal("trusted-infrastructure with declared-trust basis must cover")
	}
	if coversAllDeclared(domain.Claim{Falsifier: domain.FalsifierConstantOrGeneratedInput}) {
		t.Fatal("argument-bound falsifier must not cover unresolved subjects")
	}
}

// An unresolved subject outside the locus set is not covered by the locus
// falsifier — the package absence it verified says nothing about that
// symbol's exploit shape.
func TestVerdictNepfBlockedForLocusOutsideUnresolved(t *testing.T) {
	locus := domain.SymbolRef{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}
	other := domain.SymbolRef{Package: "example.com/dep/internal/transport", Symbol: "HandleStreams"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
			Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
			Subjects: []domain.SymbolRef{locus},
		}},
		UnresolvedSubjects: []domain.SymbolRef{locus, other},
	}
	claims := []domain.Claim{{
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
}

func TestVerdictInconclusiveOnUnknown(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
	}
	claims := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimUnknown}}
	got := evalVerdict(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
	if !strings.Contains(got.Reason, "C1") {
		t.Fatalf("inconclusive reason must name unresolved conditions: %q", got.Reason)
	}
}

// NOT_AFFECTED reasons name the checked subject — a bare code is not a
// justification a reader can audit.
func TestNotAffectedReasonNamesProbedSubjects(t *testing.T) {
	res := domain.AffectedResult{
		Scope:           exactVerdictScope(),
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimFalse,
		CheckedPackages: []string{"example.com/dep/vuln"},
	}
	got := evalVerdict(res, domain.ExploitModel{}, nil)
	if !strings.Contains(got.Reason, "example.com/dep/vuln") {
		t.Fatalf("reason must name probed packages: %q", got.Reason)
	}
}

// An empty exploit model must never produce EXPLOITABLE.
func TestVerdictNoModelNotExploitable(t *testing.T) {
	got := evalVerdict(affectedAllTrue(), domain.ExploitModel{}, nil)
	if got.Verdict == domain.VerdictExploitable {
		t.Fatal("empty exploit model produced EXPLOITABLE")
	}
}

// The generic package-absent falsifier covers unresolved subjects the same
// way the locus variant does: every unresolved symbol must be among the
// condition subjects the verification proved absent from the build graph.
func TestVerdictNepfAllowedForPackageAbsentCoveringUnresolved(t *testing.T) {
	sub := domain.SymbolRef{Package: "example.com/dep/internal/xds", Symbol: "RouteAndProcess"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{sub},
		}},
		UnresolvedSubjects: []domain.SymbolRef{sub},
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
	// The record declares the subject whose package is measured absent.
	v := domain.Vulnerability{ID: "GO-TEST", AffectedSymbols: []domain.SymbolRef{sub}}
	got := evalVerdictInput(res, model, claims, nil, v).Verdict
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// A positive verdict cannot rest on a pruned candidate set: an
// absence-resolved sink joins UnresolvedSubjects, so all-TRUE conditions
// yield INCONCLUSIVE, not EXPLOITABLE.
func TestVerdictExploitableBlockedByAbsentSubject(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}, {ID: "C2"}},
		UnresolvedSubjects: []domain.SymbolRef{
			{Package: "example.com/dep/xds", Symbol: "RouteAndProcess"},
		},
	}
	claims := []domain.Claim{
		{ConditionID: "C1", Result: domain.ClaimTrue},
		{ConditionID: "C2", Result: domain.ClaimTrue},
	}
	got := evalVerdict(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE — pruned candidate set cannot ground EXPLOITABLE", got.Verdict)
	}
}

// A verified locus-function-unreached claim grounds NO_EXPLOIT_PATH_FOUND when
// all present candidate sinks were verified unreached, and any unresolved
// sinks were proven absent (AbsentSubjects, e.g. from newer library versions).
func TestVerdictNepfAllowedForLocusFunctionUnreachedCoveringAbsentSubjects(t *testing.T) {
	presentSubj := domain.SymbolRef{Package: "example.com/dep/fasthttp", Symbol: "ServeFile"}
	absentSubj := domain.SymbolRef{Package: "example.com/dep/fasthttp", Symbol: "ServeFS"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{presentSubj},
		}},
		UnresolvedSubjects: []domain.SymbolRef{absentSubj},
		AbsentSubjects:     []domain.SymbolRef{absentSubj},
	}
	claims := []domain.Claim{{
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	// The absent subject is record-declared: its absence from the build graph
	// is evidence about a declared subject, not a saved model's assertion.
	v := domain.Vulnerability{ID: "GO-TEST", AffectedSymbols: []domain.SymbolRef{absentSubj}}
	got := evalVerdictInput(res, model, claims, nil, v).Verdict
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// But if an unresolved subject is NOT in AbsentSubjects (genuinely unmodeled),
// locus-function-unreached cannot claim completeness and demotes to INCONCLUSIVE.
func TestVerdictNepfBlockedForLocusFunctionUnreachedWithUnmodeledSubject(t *testing.T) {
	presentSubj := domain.SymbolRef{Package: "example.com/dep/fasthttp", Symbol: "ServeFile"}
	unmodeledSubj := domain.SymbolRef{Package: "example.com/dep/fasthttp", Symbol: "UnresolvedSink"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
			Subjects: []domain.SymbolRef{presentSubj},
		}},
		UnresolvedSubjects: []domain.SymbolRef{unmodeledSubj},
		AbsentSubjects:     nil, // not proven absent
	}
	claims := []domain.Claim{{
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
}

// affectedPending reports the resolver's state when applicability ran but
// the version chain could not be closed — e.g. a stdlib entry whose release
// toolchain is unknown, or a linked module with no resolvable version.
func affectedPending() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimUnknown,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		PendingModules:  []string{"stdlib"},
	}
}

// EXPLOITABLE asserts the product is affected: with the version question
// undecidable, all-TRUE mandatory conditions still yield INCONCLUSIVE.
func TestVerdictUndecidableApplicabilityNotExploitable(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}, {ID: "C2"}},
	}
	claims := []domain.Claim{
		{ConditionID: "C1", Result: domain.ClaimTrue},
		{ConditionID: "C2", Result: domain.ClaimTrue},
	}
	got := evalVerdict(affectedPending(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("undecidable applicability must not ground EXPLOITABLE: got %s", got.Verdict)
	}
}

// A verified falsifier evaluated against the analysis toolchain is not
// release-scoped evidence: while version applicability is undecidable it
// cannot close the case as NO_EXPLOIT_PATH_FOUND — the verdict stays
// INCONCLUSIVE.
func TestVerdictUndecidableApplicabilityBlocksNepf(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got := evalVerdict(affectedPending(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("undecidable applicability must block NEPF: got %s", got.Verdict)
	}
}

// Independent deterministic negatives survive the gate: a pending version
// does not shield the case when the affected package is provably absent
// from the build.
func TestVerdictUndecidableApplicabilityKeepsPackageAbsentNegative(t *testing.T) {
	res := domain.AffectedResult{
		Scope:           exactVerdictScope(),
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimUnknown,
		PackagePresent:  domain.ClaimFalse,
		CheckedPackages: []string{"net/http"},
		PendingModules:  []string{"stdlib"},
	}
	got := evalVerdict(res, domain.ExploitModel{}, nil)
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("package absence is toolchain-independent: got %s", got.Verdict)
	}
}

func TestVerdictMissingScopeBlocksModelOnlyNepf(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierTrustedInfrastructure,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got := evalVerdict(domain.AffectedResult{}, model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("missing scope must block model-only NEPF: got %s", got.Verdict)
	}
}

// postReachConfigVerdictClaim is the exact claim shape the post-reach
// route produces once its FALSE survived verification.
func postReachConfigVerdictClaim(condID domain.ConditionID, sink domain.SymbolRef, assumption string) domain.Claim {
	return domain.Claim{
		ID:             domain.ClaimID("CL-" + string(condID)),
		ConditionID:    condID,
		Result:         domain.ClaimFalse,
		Falsifier:      domain.FalsifierTrustedInfrastructure,
		FalsifierBasis: domain.BasisConfigOrigin,
		AssumptionIDs:  []string{assumption},
		EvidenceIDs:    []domain.EvidenceID{"EV-001", "EV-002"},
		Producer:       postReachProducer,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}
}

// Positive: an unresolved advisory subject that IS one of the exact sinks
// of the verified condition is covered by the closed closure. The verdict
// carries the claim's assumption ids and basis separately from evidence
// and can never be NOT_AFFECTED.
func TestVerdictConfigOriginExactSinkCoversUnresolved(t *testing.T) {
	sink := domain.SymbolRef{Package: "example.com/dep/transformer", Symbol: "QueryAll"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 1,
			Subjects: []domain.SymbolRef{sink},
		}},
		UnresolvedSubjects: []domain.SymbolRef{sink},
	}
	claim := postReachConfigVerdictClaim("C-INPUT", sink, "ASM-CONFIG-TRUST")
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, []domain.Claim{claim})
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s (%s), want NO_EXPLOIT_PATH_FOUND", got.Verdict, got.Reason)
	}
	if got.Verdict == domain.VerdictNotAffected {
		t.Fatal("the post-reach route must never produce NOT_AFFECTED")
	}
	if got.GroundBasis != domain.BasisConfigOrigin {
		t.Fatalf("GroundBasis = %q, want %q", got.GroundBasis, domain.BasisConfigOrigin)
	}
	if len(got.AssumptionIDs) != 1 || got.AssumptionIDs[0] != "ASM-CONFIG-TRUST" {
		t.Fatalf("AssumptionIDs = %v", got.AssumptionIDs)
	}
	for _, id := range got.AssumptionIDs {
		for _, ev := range got.EvidenceIDs {
			if string(ev) == id {
				t.Fatalf("assumption %q also appears in EvidenceIDs %v", id, got.EvidenceIDs)
			}
		}
	}
	if len(got.ConditionIDs) != 1 || got.ConditionIDs[0] != "C-INPUT" {
		t.Fatalf("ConditionIDs = %v", got.ConditionIDs)
	}
	if len(got.EvidenceIDs) != 2 {
		t.Fatalf("EvidenceIDs = %v", got.EvidenceIDs)
	}
}

// Negative: an unresolved advisory sink outside the verified condition's
// exact sink set is not covered by the configuration closure — even when
// the assumption is admissible. The verdict stays INCONCLUSIVE.
func TestVerdictConfigOriginUnresolvedOutsideSinkBlocks(t *testing.T) {
	sink := domain.SymbolRef{Package: "example.com/dep/transformer", Symbol: "QueryAll"}
	other := domain.SymbolRef{Package: "example.com/dep/transformer", Symbol: "Find"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 1,
			Subjects: []domain.SymbolRef{sink},
		}},
		UnresolvedSubjects: []domain.SymbolRef{other},
	}
	claim := postReachConfigVerdictClaim("C-INPUT", sink, "ASM-CONFIG-TRUST")
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	got := evalVerdict(res, model, []domain.Claim{claim})
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE: an unmodeled sink keeps the claim local", got.Verdict)
	}
}

// Negative: the exact-sink coverage route requires the claim to cite an
// admitted assumption and to be produced by the post-reach route. A
// same-shaped claim without either stays local.
func TestVerdictConfigOriginRequiresAssumptionAndProducer(t *testing.T) {
	sink := domain.SymbolRef{Package: "example.com/dep/transformer", Symbol: "QueryAll"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 1,
			Subjects: []domain.SymbolRef{sink},
		}},
		UnresolvedSubjects: []domain.SymbolRef{sink},
	}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	noAssumption := postReachConfigVerdictClaim("C-INPUT", sink, "")
	noAssumption.AssumptionIDs = nil
	if got := evalVerdict(res, model, []domain.Claim{noAssumption}); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("claim without an assumption: got %s, want INCONCLUSIVE", got.Verdict)
	}
	otherProducer := postReachConfigVerdictClaim("C-INPUT", sink, "ASM-CONFIG-TRUST")
	otherProducer.Producer = "test"
	if got := evalVerdict(res, model, []domain.Claim{otherProducer}); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("foreign producer: got %s, want INCONCLUSIVE", got.Verdict)
	}
}

// Negative: an external write contradicting the configuration provenance
// keeps the condition TRUE/UNKNOWN — no config claim can ground NEPF.
func TestVerdictConfigOriginExternalWriteStaysInconclusive(t *testing.T) {
	sink := domain.SymbolRef{Package: "example.com/dep/transformer", Symbol: "QueryAll"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 1,
			Subjects: []domain.SymbolRef{sink},
		}},
	}
	// A blocked closure leaves the claim UNKNOWN: no NEPF may rest on it.
	blocked := domain.Claim{
		ConditionID: "C-INPUT", Result: domain.ClaimUnknown, Producer: postReachProducer,
		AssumptionIDs: []string{"ASM-CONFIG-TRUST"},
	}
	if got := evalVerdict(affectedAllTrue(), model, []domain.Claim{blocked}); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("blocked config claim produced %s, want INCONCLUSIVE", got.Verdict)
	}
	// The external write establishes attacker control instead: the case is
	// positively exploitable, never a no-exploit-path conclusion.
	external := domain.Claim{
		ConditionID: "C-INPUT", Result: domain.ClaimTrue, Producer: postReachProducer,
		AssumptionIDs: []string{"ASM-CONFIG-TRUST"},
	}
	got := evalVerdict(affectedAllTrue(), model, []domain.Claim{external})
	if got.Verdict == domain.VerdictNoExploitPathFound || got.Verdict == domain.VerdictNotAffected {
		t.Fatalf("external write produced %s, want EXPLOITABLE", got.Verdict)
	}
}

// coversAllDeclared must keep refusing the config-origin basis: only the
// narrower configClosureCoversUnresolved helper may cover unresolved
// subjects, and only when they are exact condition sinks.
func TestCoversAllDeclaredRefusesConfigOrigin(t *testing.T) {
	claim := postReachConfigVerdictClaim("C-INPUT",
		domain.SymbolRef{Package: "p", Symbol: "S"}, "ASM-CONFIG-TRUST")
	if coversAllDeclared(claim) {
		t.Fatal("config-origin claim must not be treated as sink-agnostic coverage")
	}
	cond := domain.Condition{ID: "C-INPUT", Subjects: []domain.SymbolRef{{Package: "p", Symbol: "S"}}}
	model := domain.ExploitModel{UnresolvedSubjects: []domain.SymbolRef{{Package: "p", Symbol: "S"}}}
	if !configClosureCoversUnresolved(claim, cond, model) {
		t.Fatal("exact-sink unresolved subject must be covered")
	}
	model.UnresolvedSubjects = []domain.SymbolRef{{Package: "p", Symbol: "Other"}}
	if configClosureCoversUnresolved(claim, cond, model) {
		t.Fatal("unresolved subject outside the sink set must not be covered")
	}
}

// assertNoEmptyApplicabilityNames encodes the post-Task-4 resolver contract
// the evaluator fixtures reproduce: a malformed/unnamed advisory entry is
// explicit unresolved data, never a module named "".
func assertNoEmptyApplicabilityNames(t *testing.T, res domain.AffectedResult) {
	t.Helper()
	for _, names := range [][]string{
		res.SelectedModules, res.CheckedModules, res.UnresolvedModules,
		res.PendingModules, res.VersionAffectedModules,
	} {
		if slices.Contains(names, "") {
			t.Fatalf("affected applicability carries an empty module name: %v", names)
		}
	}
}

// TestUnknownUnlinkedAlternativeDoesNotBlockKnownLinkedModule reproduces
// the post-Task-4 resolver shape of the grpc/amqp class: a linked
// third-party entry has a settled, version-affected module while a separate
// stdlib entry stays unresolved because no authoritative release toolchain
// exists. The evaluator consumes the aggregate AffectedResult, so it must
// keep the linked entry's applicability and reach exploit evaluation —
// the unrelated entry's UNKNOWN may not gate the verdict.
func TestUnknownUnlinkedAlternativeDoesNotBlockKnownLinkedModule(t *testing.T) {
	res := domain.AffectedResult{
		ModulePresent:          domain.ClaimTrue,
		VersionAffected:        domain.ClaimTrue,
		PackagePresent:         domain.ClaimTrue,
		BuildRelevant:          domain.ClaimTrue,
		ResolvedVersion:        "v1.0.0",
		SelectedModule:         "example.com/dep",
		SelectedModules:        []string{"example.com/dep"},
		CheckedModules:         []string{"stdlib", "example.com/dep"},
		UnresolvedModules:      []string{"stdlib"},
		VersionAffectedModules: []string{"example.com/dep"},
	}
	assertNoEmptyApplicabilityNames(t, res)

	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable}},
	}
	claims := []domain.Claim{{ConditionID: "C-REACH", Result: domain.ClaimTrue}}

	got := evalVerdict(res, model, claims)
	if got.Verdict != domain.VerdictExploitable {
		t.Fatalf("linked module with settled version: got %s (%s), want EXPLOITABLE — the unresolved unlinked stdlib alternative must not gate exploit evaluation",
			got.Verdict, got.Reason)
	}
}

// TestUnknownLinkedEntryRemainsInconclusive keeps the version-unknown gate:
// no positive model and no verified falsifier may commit to either side
// while the *linked* entry's applicability is undecidable. The shapes cover
// a linked stdlib entry without release evidence, a linked named module
// whose version did not resolve, and a linked subject owned by an unnamed
// (post-Task-4) advisory entry.
func TestUnknownLinkedEntryRemainsInconclusive(t *testing.T) {
	cases := []struct {
		name string
		res  domain.AffectedResult
	}{
		{"linked stdlib release toolchain unknown", affectedPending()},
		{"linked named module version unresolved", domain.AffectedResult{
			ModulePresent:     domain.ClaimTrue,
			VersionAffected:   domain.ClaimUnknown,
			PackagePresent:    domain.ClaimTrue,
			BuildRelevant:     domain.ClaimTrue,
			SelectedModule:    "example.com/dep",
			SelectedModules:   []string{"example.com/dep"},
			PendingModules:    []string{"example.com/dep"},
			UnresolvedModules: []string{"example.com/dep"},
		}},
		{"linked unnamed subject", domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimUnknown,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		}},
	}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionSymbolReachable}},
	}
	claimSets := map[string][]domain.Claim{
		"satisfied conditions": {
			{ConditionID: "C1", Result: domain.ClaimTrue},
		},
		"verified falsifier": {{
			ConditionID: "C1",
			Result:      domain.ClaimFalse,
			Falsifier:   domain.FalsifierConstantOrGeneratedInput,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNoEmptyApplicabilityNames(t, tc.res)
			for label, claims := range claimSets {
				got := evalVerdict(tc.res, model, claims)
				if got.Verdict != domain.VerdictInconclusive {
					t.Fatalf("%s: got %s (%s), want INCONCLUSIVE — UNKNOWN applicability on the linked entry blocks both EXPLOITABLE and falsifier-based NEPF",
						label, got.Verdict, got.Reason)
				}
			}
		})
	}
}

// TestEmptyModuleCannotProduceNotAffected exercises the post-Task-4
// AffectedResult shape of an advisory whose entries carry no module name:
// no empty module strings appear anywhere, and the resulting unknown
// applicability cannot close as NOT_AFFECTED. It also keeps the
// implementation-axis guard: a FALSE axis is not a negative without the
// package/build axes established.
func TestEmptyModuleCannotProduceNotAffected(t *testing.T) {
	linkedUnnamed := domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimUnknown,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}
	unlinkedUnnamed := domain.AffectedResult{
		ModulePresent:   domain.ClaimUnknown,
		VersionAffected: domain.ClaimUnknown,
		PackagePresent:  domain.ClaimUnknown,
		BuildRelevant:   domain.ClaimUnknown,
	}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionSymbolReachable}},
	}
	verifiedFalsifier := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	cases := []struct {
		name   string
		res    domain.AffectedResult
		claims []domain.Claim
	}{
		{
			"linked unnamed subject with satisfied conditions",
			linkedUnnamed,
			[]domain.Claim{{ConditionID: "C1", Result: domain.ClaimTrue}},
		},
		{
			"linked unnamed subject with a verified falsifier",
			linkedUnnamed,
			verifiedFalsifier,
		},
		{
			"unlinked unnamed subject leaves the chain undecided",
			unlinkedUnnamed,
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNoEmptyApplicabilityNames(t, tc.res)
			got := evalVerdict(tc.res, model, tc.claims)
			if got.Verdict == domain.VerdictNotAffected {
				t.Fatalf("empty/malformed applicability produced NOT_AFFECTED: %q", got.Reason)
			}
			if got.Verdict != domain.VerdictInconclusive {
				t.Fatalf("got %s (%s), want INCONCLUSIVE", got.Verdict, got.Reason)
			}
		})
	}

	// A FALSE implementation axis is the fifth affected-chain dimension:
	// without the package/build axes established it must not close the
	// chain even though the other axes are TRUE.
	proposedAbsence := affectedAllTrue()
	proposedAbsence.VulnerableImplementationPresent = domain.ClaimFalse
	proposedAbsence.PackagePresent = domain.ClaimUnknown
	proposedAbsence.BuildRelevant = domain.ClaimUnknown
	proposedAbsence.ImplementationLocus = "proposal-supplied locus"
	if got := evalVerdict(proposedAbsence, domain.ExploitModel{}, nil); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("implementation FALSE without established package/build axes: got %s (%s), want INCONCLUSIVE",
			got.Verdict, got.Reason)
	}
}

// llmProposedClaim models the evaluator-side shape of an agent contribution:
// the proposal producer is recorded, but the evaluator sees only a claim.
// The proposal marker must not buy any authority the claim's own evidence
// does not carry.
func llmProposedClaim(condID domain.ConditionID, result domain.ClaimResult) domain.Claim {
	return domain.Claim{
		ID:          domain.ClaimID("CL-" + string(condID)),
		ConditionID: condID,
		Result:      result,
		Producer:    "research.ExploitLocusProposal",
		Explanation: "LLM-inferred proposal; deterministic verification pending",
	}
}

// TestLLMProposalCannotOverrideUnknownApplicability pins the authority
// boundary at the evaluator: proposals may name catalog conditions, but a
// proposed satisfied model, a proposed unverified falsifier, or a
// proposal-shaped verified falsifier cannot turn an undecidable linked
// applicability into EXPLOITABLE or NO_EXPLOIT_PATH_FOUND. The
// implementation-locus route is equally non-authoritative without the
// established package/build axes.
func TestLLMProposalCannotOverrideUnknownApplicability(t *testing.T) {
	res := affectedPending()
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionSymbolReachable}},
	}

	t.Run("proposed satisfied model", func(t *testing.T) {
		got := evalVerdict(res, model,
			[]domain.Claim{llmProposedClaim("C1", domain.ClaimTrue)})
		if got.Verdict != domain.VerdictInconclusive {
			t.Fatalf("got %s (%s), want INCONCLUSIVE", got.Verdict, got.Reason)
		}
		if !strings.Contains(got.Reason, "version applicability is undecidable") {
			t.Fatalf("proposal bypassed the applicability gate: %q", got.Reason)
		}
	})

	t.Run("proposed falsifier without deterministic verification", func(t *testing.T) {
		claim := llmProposedClaim("C1", domain.ClaimFalse)
		claim.Falsifier = domain.FalsifierTrustedInfrastructure
		got := evalVerdict(res, model, []domain.Claim{claim})
		if got.Verdict != domain.VerdictInconclusive {
			t.Fatalf("got %s (%s), want INCONCLUSIVE", got.Verdict, got.Reason)
		}
	})

	t.Run("proposed falsifier with proposal-asserted verification", func(t *testing.T) {
		claim := llmProposedClaim("C1", domain.ClaimFalse)
		claim.Falsifier = domain.FalsifierNoModuleUsage
		claim.NegativeVerification = &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		}
		got := evalVerdict(res, model, []domain.Claim{claim})
		if got.Verdict != domain.VerdictInconclusive {
			t.Fatalf("got %s (%s), want INCONCLUSIVE", got.Verdict, got.Reason)
		}
	})

	t.Run("proposed implementation absence without package/build axes", func(t *testing.T) {
		proposed := affectedAllTrue()
		proposed.VulnerableImplementationPresent = domain.ClaimFalse
		proposed.PackagePresent = domain.ClaimUnknown
		proposed.BuildRelevant = domain.ClaimUnknown
		proposed.ImplementationLocus = "proposal-supplied locus"
		got := evalVerdict(proposed, domain.ExploitModel{}, nil)
		if got.Verdict != domain.VerdictInconclusive {
			t.Fatalf("got %s (%s), want INCONCLUSIVE", got.Verdict, got.Reason)
		}
	})
}

// amqpRoundTripCase reproduces smoke case confirmed/CASE-553930: a linked
// amqp091-go advisory whose exploit model requires the URI round-trip pair
// and the defect locus. Only the round-trip condition's FALSE is verified;
// the locus condition's FALSE is INSUFFICIENT_SCOPE because URI.String is a
// method of a build interface.
func amqpRoundTripCase() (domain.AffectedResult, domain.ExploitModel, []domain.Claim) {
	uriString := domain.SymbolRef{Package: "github.com/rabbitmq/amqp091-go", Symbol: "URI.String"}
	parseURI := domain.SymbolRef{Package: "github.com/rabbitmq/amqp091-go", Symbol: "ParseURI"}
	affected := domain.AffectedResult{
		Scope:                           fullRecordScope("GO-TEST-1", "github.com/rabbitmq/amqp091-go"),
		ModulePresent:                   domain.ClaimTrue,
		VersionAffected:                 domain.ClaimTrue,
		PackagePresent:                  domain.ClaimTrue,
		BuildRelevant:                   domain.ClaimTrue,
		VulnerableImplementationPresent: domain.ClaimUnknown,
		ResolvedVersion:                 "v1.10.0",
		SelectedModule:                  "github.com/rabbitmq/amqp091-go",
		SelectedModules:                 []string{"github.com/rabbitmq/amqp091-go"},
		CheckedModules:                  []string{"github.com/rabbitmq/amqp091-go"},
		VersionAffectedModules:          []string{"github.com/rabbitmq/amqp091-go"},
	}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{
			{
				ID: "C-ROUNDTRIP", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{uriString, parseURI},
				Params: map[string]string{
					domain.ParamSequence: "github.com/rabbitmq/amqp091-go.URI.String->github.com/rabbitmq/amqp091-go.ParseURI",
				},
			},
			{
				ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{uriString},
				Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
			},
		},
	}
	claims := []domain.Claim{
		{
			ID: "CL-C-ROUNDTRIP", ConditionID: "C-ROUNDTRIP",
			Result:    domain.ClaimFalse,
			Falsifier: domain.FalsifierMissingPairMember,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Notes:  "never-invoked member(s) github.com/rabbitmq/amqp091-go.URI.String, github.com/rabbitmq/amqp091-go.ParseURI have no product references",
			},
			Limitations: []string{"FALSE is a candidate: pair members may be invoked via interface dispatch or reflection"},
		},
		{
			ID: "CL-C-LOCUS", ConditionID: "C-LOCUS",
			Result:    domain.ClaimFalse,
			Falsifier: domain.FalsifierLocusFunctionUnreached,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "метод github.com/rabbitmq/amqp091-go.URI.String может вызываться через интерфейс",
			},
		},
	}
	return affected, model, claims
}

// TestInsufficientScopeMandatoryConditionBlocksNEPF pins the false-safe
// regression: one verified falsifier on C-ROUNDTRIP must not override the
// insufficient-scope C-LOCUS negative on the same vulnerable subject.
// A mandatory FALSE that failed scope verification stays unresolved and the
// case is INCONCLUSIVE, never NO_EXPLOIT_PATH_FOUND.
func TestInsufficientScopeMandatoryConditionBlocksNEPF(t *testing.T) {
	affected, model, claims := amqpRoundTripCase()

	got := evalVerdict(affected, model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s (%s), want INCONCLUSIVE — C-LOCUS INSUFFICIENT_SCOPE must block NEPF",
			got.Verdict, got.Reason)
	}
	if got.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("an unverified mandatory FALSE must not be overridden by another condition's verified falsifier")
	}
	for _, want := range []string{"C-LOCUS", "INSUFFICIENT_SCOPE", "remain unresolved", "cannot override"} {
		if !strings.Contains(got.Reason, want) {
			t.Fatalf("blocking reason %q does not contain %q", got.Reason, want)
		}
	}
	if len(got.ConditionIDs) != 1 || got.ConditionIDs[0] != "C-LOCUS" {
		t.Fatalf("ConditionIDs = %v, want [C-LOCUS]", got.ConditionIDs)
	}

	// Positive control: the same model and affected chain still close as
	// NEPF when every mandatory negative is verified.
	verified := append([]domain.Claim{}, claims...)
	verified[1].NegativeVerification = &domain.NegativeVerification{
		Status: domain.NegativeVerified,
		Notes:  "no path reaches the locus under the recorded target",
	}
	got = evalVerdict(affected, model, verified)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("all-verified negatives: got %s (%s), want NO_EXPLOIT_PATH_FOUND", got.Verdict, got.Reason)
	}
	if got.Reason != "mandatory exploit condition is proven false" {
		t.Fatalf("reason = %q", got.Reason)
	}
}

// projectedScope is an exact-record binding whose loaded document represented
// only its Go entry: the omitted Maven entry is real, so the Go projection can
// never close the requested scope however COMPLETE it claims to be.
func projectedScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentGoProjection,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID: "GO-TEST-1", DocumentDigest: "sha256:" + strings.Repeat("cd", 32),
			AffectedEntryCount: 2,
			Entries: []domain.RecordEntry{
				{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"},
				{Index: 1, Ecosystem: "Maven", Module: "io.grpc:grpc-netty"},
			},
			RepresentedRefs: []int{0},
			OmittedRefs:     []int{1},
		},
	}
}

// missingInventoryScope claims a full record but carries no census at all.
func missingInventoryScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
	}
}

// inconsistentInventoryScope asserts a full record while its own census omits
// an entry and is bound to a different advisory identity.
func inconsistentInventoryScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID: "GO-OTHER-1", DocumentDigest: "sha256:" + strings.Repeat("ef", 32),
			AffectedEntryCount: 2,
			Entries: []domain.RecordEntry{
				{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"},
				{Index: 1, Ecosystem: "Go", Module: "golang.org/x/crypto"},
			},
			RepresentedRefs: []int{0},
			OmittedRefs:     []int{1},
		},
	}
}

// TestVerdictPartialScopeNegativeMatrix: every component-negative axis needs
// the same structural coverage of the requested record. Only a full record
// whose original Go entries are all represented closes; a projection, an
// absent census or a census that contradicts its own extent refuses — even
// when the scope claims an exact identity with COMPLETE coverage.
func TestVerdictPartialScopeNegativeMatrix(t *testing.T) {
	for _, scope := range []struct {
		name  string
		scope *domain.AdvisoryScope
		want  domain.Verdict
	}{
		{"missing", nil, domain.VerdictInconclusive},
		{"cve-known-only", &domain.AdvisoryScope{RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-1", Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly}, domain.VerdictInconclusive},
		{"legacy-complete-no-census", &domain.AdvisoryScope{RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1", Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete}, domain.VerdictInconclusive},
		{"exact-projected", projectedScope(), domain.VerdictInconclusive},
		{"exact-missing-inventory", missingInventoryScope(), domain.VerdictInconclusive},
		{"exact-inconsistent-inventory", inconsistentInventoryScope(), domain.VerdictInconclusive},
		{"exact-full-record", exactVerdictScope(), domain.VerdictNotAffected},
	} {
		for _, axis := range []string{"module", "version", "package", "build", "implementation"} {
			t.Run(scope.name+"/"+axis, func(t *testing.T) {
				res := affectedAllTrue()
				res.Scope = scope.scope
				res.CheckedModules = []string{"golang.org/x/net"}
				res.EvidenceIDs = []domain.EvidenceID{"EV-AFFECTED"}
				switch axis {
				case "module":
					res.ModulePresent = domain.ClaimFalse
				case "version":
					res.VersionAffected = domain.ClaimFalse
				case "package":
					res.PackagePresent = domain.ClaimFalse
				case "build":
					res.BuildRelevant = domain.ClaimFalse
				case "implementation":
					res.VulnerableImplementationPresent = domain.ClaimFalse
				}
				got := evalVerdict(res, domain.ExploitModel{}, nil)
				if got.Verdict != scope.want {
					t.Fatalf("got %s (%s), want %s", got.Verdict, got.Reason, scope.want)
				}
				if !slices.Equal(got.EvidenceIDs, res.EvidenceIDs) {
					t.Fatalf("evidence lost: %v", got.EvidenceIDs)
				}
				if scope.want == domain.VerdictInconclusive && (!strings.Contains(got.Reason, "scope") || !strings.Contains(got.Reason, "golang.org/x/net")) {
					t.Fatalf("reason must name checked component and uncovered scope: %q", got.Reason)
				}
			})
		}
	}
}

// TestVerdictPartialScopeBlocksNepf: NEPF is itself a negative finding-level
// conclusion, so it needs the same structural coverage as every other
// negative — a projection, an absent census or a self-contradicting census
// refuses it even under an exact identity. The scope refusal is added to, never
// substituted for, the pre-existing claim admission: a persisted VERIFIED
// negative without its measurement build context is still refused and reported.
func TestVerdictPartialScopeBlocksNepf(t *testing.T) {
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{ID: "C1"}}}
	for _, scope := range []struct {
		name  string
		scope *domain.AdvisoryScope
		want  domain.Verdict
	}{
		{"missing", nil, domain.VerdictInconclusive},
		{"cve-known-only", &domain.AdvisoryScope{RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-1", Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly}, domain.VerdictInconclusive},
		{"legacy-complete-no-census", &domain.AdvisoryScope{RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1", Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete}, domain.VerdictInconclusive},
		{"exact-projected", projectedScope(), domain.VerdictInconclusive},
		{"exact-missing-inventory", missingInventoryScope(), domain.VerdictInconclusive},
		{"exact-inconsistent-inventory", inconsistentInventoryScope(), domain.VerdictInconclusive},
		{"exact-full-record", exactVerdictScope(), domain.VerdictNoExploitPathFound},
	} {
		t.Run(scope.name, func(t *testing.T) {
			res := affectedAllTrue()
			res.Scope = scope.scope
			res.CheckedModules = []string{"golang.org/x/net"}
			claims := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimFalse, Falsifier: domain.FalsifierConstantOrGeneratedInput, EvidenceIDs: []domain.EvidenceID{"EV-FALSE"}, NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified}}}
			got := evalVerdict(res, model, claims)
			if got.Verdict != scope.want {
				t.Fatalf("%s scope NEPF = %s (%s), want %s", scope.name, got.Verdict, got.Reason, scope.want)
			}
			if scope.want == domain.VerdictInconclusive && !strings.Contains(got.Reason, "scope") {
				t.Fatalf("scope refusal reason = %q", got.Reason)
			}
		})
	}

	// Both authorities run: the scope refusal does not skip the claim
	// admission, whose refusal is still recorded on the INCONCLUSIVE result.
	res := affectedAllTrue()
	res.Scope = projectedScope()
	res.CheckedModules = []string{"golang.org/x/net"}
	res.VersionAffected = domain.ClaimFalse
	unbound := []domain.Claim{{
		ConditionID: "C1", Result: domain.ClaimFalse,
		Falsifier:            domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
	}}
	got := (VerdictEvaluator{}).Evaluate(VerdictInput{
		Product: admittedProduct(), Affected: res, Model: model, Claims: unbound,
	})
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "scope") {
		t.Fatalf("scope-refused NEPF = %s (%s)", got.Verdict, got.Reason)
	}
	joined := strings.Join(got.Limitations, "; ")
	if !strings.Contains(joined, "negative verification for C1 refused") {
		t.Fatalf("claim admission did not run beside the scope refusal: %v", got.Limitations)
	}
}

func TestVerdictPartialScopeKeepsProvenPositive(t *testing.T) {
	for _, scope := range []*domain.AdvisoryScope{nil, {RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-1", Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly}} {
		res := affectedAllTrue()
		res.Scope = scope
		model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{ID: "C1"}}}
		got := evalVerdict(res, model, []domain.Claim{{ConditionID: "C1", Result: domain.ClaimTrue}})
		if got.Verdict != domain.VerdictExploitable {
			t.Fatalf("proven positive = %+v", got)
		}
	}
}

func TestVerdictFixedPartialScopeCannotBecomePositive(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = &domain.AdvisoryScope{RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-1", Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly}
	res.VersionAffected = domain.ClaimFalse
	res.ResolvedVersion = "v0.17.0"
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{ID: "C1"}}}
	got := evalVerdict(res, model, []domain.Claim{{ConditionID: "C1", Result: domain.ClaimTrue}})
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("fixed partial component with all-TRUE claims = %+v", got)
	}
}

// An unresolved high-severity review critique of a mandatory condition
// keeps the case INCONCLUSIVE in both closure directions until an
// explicit condition action resolves it. Independent affected-chain
// negatives still close the case.
func TestVerdictPendingConditionReviewsBlockClosure(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()

	nepfModel := domain.ExploitModel{MandatoryConditions: []domain.Condition{{ID: "C1"}}}
	nepfClaims := []domain.Claim{{
		ConditionID:          "C1",
		Result:               domain.ClaimFalse,
		Falsifier:            domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
	}}
	if got := evalVerdict(res, nepfModel, nepfClaims); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("baseline without pending review = %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
	nepfModel.PendingConditionReviews = []domain.ConditionID{"C1"}
	got := evalVerdict(res, nepfModel, nepfClaims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("pending review next to NEPF = %s, want INCONCLUSIVE", got.Verdict)
	}
	if len(got.ConditionIDs) != 1 || got.ConditionIDs[0] != "C1" {
		t.Fatalf("pending verdict condition ids = %v, want C1", got.ConditionIDs)
	}
	if !strings.Contains(got.Reason, "C1") {
		t.Fatalf("pending verdict reason must name the condition: %q", got.Reason)
	}

	expModel := domain.ExploitModel{MandatoryConditions: []domain.Condition{{ID: "C1"}}}
	expClaims := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimTrue}}
	if got := evalVerdict(res, expModel, expClaims); got.Verdict != domain.VerdictExploitable {
		t.Fatalf("baseline without pending review = %s, want EXPLOITABLE", got.Verdict)
	}
	expModel.PendingConditionReviews = []domain.ConditionID{"C1"}
	if got := evalVerdict(res, expModel, expClaims); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("pending review next to EXPLOITABLE = %s, want INCONCLUSIVE", got.Verdict)
	}

	// A negative affected-chain fact is independent of the exploit
	// conjunction: the module absence still closes the case.
	notAffected := domain.AffectedResult{ModulePresent: domain.ClaimFalse}
	notAffected.Scope = exactVerdictScope()
	pendingModel := domain.ExploitModel{
		MandatoryConditions:     []domain.Condition{{ID: "C1"}},
		PendingConditionReviews: []domain.ConditionID{"C1"},
	}
	if got := evalVerdict(notAffected, pendingModel, nil); got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("affected-chain negative = %s, want NOT_AFFECTED despite pending review", got.Verdict)
	}
}

// --- Library-API exploitability scope ------------------------------------

func libraryScopeComplete() *domain.AdvisoryScope {
	return fullRecordScope("GO-2099-0001", "example.com/dep")
}

func libraryScopeKnownOnly() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "CVE-2099-0001", ResolvedID: "GO-2099-0001",
		Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly,
	}
}

func libraryScopedModel() domain.ExploitModel {
	return domain.ExploitModel{
		MandatoryConditions: []domain.Condition{
			{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
			{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, ArgIndex: 0},
		},
	}
}

func libraryScopedClaims(evidence ...domain.EvidenceID) []domain.Claim {
	return []domain.Claim{
		{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue, Producer: "evaluator.SymbolReachable"},
		{
			ID: "CL-C-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimTrue,
			Producer:     "evaluator.ArgumentOrigin",
			ControlBasis: domain.ControlBasisLibraryPublicAPI,
			EvidenceIDs:  evidence,
			Limitations:  []string{domain.LibraryAPIScopeLimitation},
		},
	}
}

// TestVerdictExploitableLibraryScope: a mandatory TRUE library claim keeps the
// existing EXPLOITABLE verdict and Reason, adds the library-api scope, the
// mandatory limitation and the exact claim/evidence references.
func TestVerdictExploitableLibraryScope(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = libraryScopeComplete()
	got := evalVerdict(res, libraryScopedModel(), libraryScopedClaims("EV-LIB-1"))

	if got.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%s, want EXPLOITABLE", got.Verdict)
	}
	if got.Reason != "all mandatory exploit conditions are satisfied" {
		t.Fatalf("reason=%q, want the unchanged mandatory-conjunction reason", got.Reason)
	}
	if got.ExploitabilityScope != domain.ScopeLibraryAPI {
		t.Fatalf("scope=%q, want %q", got.ExploitabilityScope, domain.ScopeLibraryAPI)
	}
	if !slices.Contains(got.Limitations, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("missing mandatory library limitation: %v", got.Limitations)
	}
	// A positive cites every mandatory TRUE condition it rests on; the
	// library claim must be among them, with its own evidence.
	if !slices.Contains(got.ConditionIDs, domain.ConditionID("C-INPUT")) {
		t.Fatalf("condition ids=%v, want the library claim's C-INPUT", got.ConditionIDs)
	}
	if !slices.Contains(got.EvidenceIDs, domain.EvidenceID("EV-LIB-1")) {
		t.Fatalf("evidence ids=%v, want the library claim's EV-LIB-1", got.EvidenceIDs)
	}
}

// TestVerdictKnownOnlyLibraryPositive: KNOWN_ONLY coverage blocks unsupported
// negative closure but not an otherwise proven positive path — COMPLETE and
// KNOWN_ONLY reach the same scoped EXPLOITABLE verdict.
func TestVerdictKnownOnlyLibraryPositive(t *testing.T) {
	for name, scope := range map[string]*domain.AdvisoryScope{
		"complete":   libraryScopeComplete(),
		"known-only": libraryScopeKnownOnly(),
	} {
		t.Run(name, func(t *testing.T) {
			res := affectedAllTrue()
			res.Scope = scope
			got := evalVerdict(res, libraryScopedModel(), libraryScopedClaims("EV-LIB-1"))
			if got.Verdict != domain.VerdictExploitable {
				t.Fatalf("verdict=%s, want EXPLOITABLE", got.Verdict)
			}
			if got.ExploitabilityScope != domain.ScopeLibraryAPI {
				t.Fatalf("scope=%q, want %q", got.ExploitabilityScope, domain.ScopeLibraryAPI)
			}
		})
	}

	// The same partial coverage still refuses a negative closure: KNOWN_ONLY
	// is not re-labelled as complete.
	res := affectedAllTrue()
	res.Scope = libraryScopeKnownOnly()
	claims := []domain.Claim{
		{
			ConditionID: "C-REACH", Result: domain.ClaimFalse,
			Falsifier:            domain.FalsifierConstantOrGeneratedInput,
			NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		},
		{
			ConditionID: "C-INPUT", Result: domain.ClaimTrue,
			ControlBasis: domain.ControlBasisLibraryPublicAPI,
		},
	}
	got := evalVerdict(res, libraryScopedModel(), claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("KNOWN_ONLY negative closure=%s, want INCONCLUSIVE", got.Verdict)
	}
	if got.ExploitabilityScope != "" {
		t.Fatalf("non-positive verdict carries scope %q", got.ExploitabilityScope)
	}
}

// TestVerdictLibraryScopeRequiresMandatoryClaim: a supporting claim, an
// unproven mandatory claim or an off-model claim never scopes the verdict.
func TestVerdictLibraryScopeRequiresMandatoryClaim(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = libraryScopeComplete()

	supportingModel := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
		SupportingFactors:   []domain.Condition{{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 0}},
	}
	supportingClaims := []domain.Claim{
		{ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ConditionID: "C-INPUT", Result: domain.ClaimTrue, ControlBasis: domain.ControlBasisLibraryPublicAPI},
	}
	if scope := verdictExploitabilityScope(supportingModel, supportingClaims); scope != "" {
		t.Fatalf("supporting claim scoped the verdict: %q", scope)
	}
	got := evalVerdict(res, supportingModel, supportingClaims)
	if got.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%s, want EXPLOITABLE", got.Verdict)
	}
	if got.ExploitabilityScope != "" || slices.Contains(got.Limitations, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("supporting library claim leaked into the verdict: %+v", got)
	}

	unknownModel := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, ArgIndex: 0}},
	}
	unknownClaims := []domain.Claim{{
		ConditionID: "C-INPUT", Result: domain.ClaimUnknown,
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}}
	got = evalVerdict(res, unknownModel, unknownClaims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("unproven library claim verdict=%s, want INCONCLUSIVE", got.Verdict)
	}
	if got.ExploitabilityScope != "" {
		t.Fatalf("unproven library claim carries scope %q", got.ExploitabilityScope)
	}

	offModelClaims := []domain.Claim{
		{ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ConditionID: "C-UNRELATED", Result: domain.ClaimTrue, ControlBasis: domain.ControlBasisLibraryPublicAPI},
	}
	got = evalVerdict(res, domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
	}, offModelClaims)
	if got.Verdict != domain.VerdictExploitable || got.ExploitabilityScope != "" {
		t.Fatalf("off-model library claim scoped the verdict: %+v", got)
	}
}

// TestVerdictNegativesCarryNoLibraryScope: every non-EXPLOITABLE verdict keeps
// an empty exploitability scope and does not inherit the library limitation,
// even when the claim set contains a proven library positive.
func TestVerdictNegativesCarryNoLibraryScope(t *testing.T) {
	res := affectedAllTrue()
	res.Scope = libraryScopeComplete()
	model := libraryScopedModel()
	libraryPositive := domain.Claim{
		ConditionID: "C-INPUT", Result: domain.ClaimTrue,
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
		Limitations:  []string{domain.LibraryAPIScopeLimitation},
	}

	// NEPF: a verified mandatory FALSE grounds the negative; the library
	// positive beside it does not scope the verdict.
	nepfClaims := []domain.Claim{
		{
			ConditionID: "C-REACH", Result: domain.ClaimFalse,
			Falsifier:            domain.FalsifierConstantOrGeneratedInput,
			NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		},
		libraryPositive,
	}
	got := evalVerdict(res, model, nepfClaims)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
	if got.ExploitabilityScope != "" || slices.Contains(got.Limitations, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("NEPF inherited library scope: %+v", got)
	}

	// NOT_AFFECTED: an affected-chain negative closes without the scope.
	notAffected := domain.AffectedResult{ModulePresent: domain.ClaimFalse, Scope: libraryScopeComplete()}
	got = evalVerdict(notAffected, model, libraryScopedClaims())
	if got.Verdict != domain.VerdictNotAffected || got.ExploitabilityScope != "" {
		t.Fatalf("NOT_AFFECTED = %+v", got)
	}

	// INCONCLUSIVE on an incomplete model.
	incomplete := libraryScopedModel()
	incomplete.UnresolvedSubjects = []domain.SymbolRef{{Package: "example.com/dep/yaml", Symbol: "UnmarshalAny"}}
	got = evalVerdict(res, incomplete, libraryScopedClaims())
	if got.Verdict != domain.VerdictInconclusive || got.ExploitabilityScope != "" {
		t.Fatalf("incomplete-model positive = %+v", got)
	}

	// INCONCLUSIVE on an unresolved mandatory review.
	pending := libraryScopedModel()
	pending.PendingConditionReviews = []domain.ConditionID{"C-INPUT"}
	got = evalVerdict(res, pending, libraryScopedClaims())
	if got.Verdict != domain.VerdictInconclusive || got.ExploitabilityScope != "" {
		t.Fatalf("pending-review positive = %+v", got)
	}
}

// F3 regression: a persisted usage-derived negative must meet the same
// completed-govulncheck prerequisite as the live producer. A complete source
// scan plus a failed/untyped run stays UNKNOWN; a completed run grounds NEPF.
func TestVerdictPersistedUsageNegativeRequiresCompletedRun(t *testing.T) {
	product := admittedProduct()
	build := domain.EffectiveBuildContext(product)
	subject := domain.SymbolRef{Package: "example.com/dep", Symbol: "Sink"}
	cond := domain.Condition{ID: "C1", Kind: domain.ConditionSymbolReachable, Subjects: []domain.SymbolRef{subject}}
	claim := domain.Claim{
		ConditionID: "C1", Result: domain.ClaimFalse, Falsifier: domain.FalsifierNoModuleUsage,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified, BuildContext: &build},
	}
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{cond}}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	scan := domain.Evidence{
		ID: "EV-SCAN", Kind: domain.EvidenceSourceScan, BuildContext: &build,
		SourceScan: &domain.SourceScanRun{
			Module: "example.com/dep", Subjects: []domain.SymbolRef{subject},
			Completed: true, Complete: true,
		},
	}
	failedRun := domain.Evidence{
		ID: "EV-GV", Kind: domain.EvidenceGovulncheck, BuildContext: &build,
		Govulncheck: &domain.GovulncheckRun{Outcome: domain.GovulncheckFailed},
	}
	completedRun := domain.Evidence{
		ID: "EV-GV", Kind: domain.EvidenceGovulncheck, BuildContext: &build,
		Govulncheck: &domain.GovulncheckRun{
			Outcome:  domain.GovulncheckCompletedEmpty,
			Coverage: domain.GovulncheckCoverage{AdvisoryID: "GO-TEST-1", Advisory: domain.GovulncheckCoverageCovered, Subjects: []domain.SymbolRef{subject}, ScopeComplete: true},
		},
	}
	eval := func(evidence ...domain.Evidence) domain.VerdictResult {
		return (VerdictEvaluator{}).Evaluate(VerdictInput{
			Product: product, Affected: res, Model: model,
			Claims: []domain.Claim{claim}, Evidence: evidence,
		})
	}
	if got := eval(scan, failedRun); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("failed govulncheck grounded %s (%s)", got.Verdict, got.Reason)
	}
	if got := eval(scan); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("untyped/missing govulncheck grounded %s", got.Verdict)
	}
	if got := eval(scan, completedRun); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("completed run did not ground NEPF: %s (%s)", got.Verdict, got.Reason)
	}
}

// TestTransportVerdictScope proves the boundary projection at the pure verdict
// level: transport-peer is assigned only from an admitted mandatory TRUE
// transport-input claim, and a claim whose witness no longer re-admits cannot
// ground an unexplained positive.
func TestTransportVerdictScope(t *testing.T) {
	product := admittedSnapshot(domain.ProductSnapshot{Repository: "/repo", Commit: "abc123"})
	model := transportTestModel()
	input := transportTestInput(product)
	trigger := transportTestTrigger(product, input)
	peerCond := transportTestCondition(model, "C-PEER-INPUT")
	constraintCond := transportTestCondition(model, "C-CONSTRAINT")
	claims := []domain.Claim{
		transportInputClaim(peerCond, nil, input),
		transportTriggerClaim(constraintCond, nil, trigger),
	}
	evidence := transportTestEvidence(input, trigger)
	affected := transportStatesLikeAffected()

	verdict := VerdictEvaluator{}.Evaluate(VerdictInput{
		Product:  product,
		Affected: affected,
		Model:    model,
		Claims:   claims,
		Evidence: evidence,
	})
	if verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict = %s (%s); want EXPLOITABLE", verdict.Verdict, verdict.Reason)
	}
	if verdict.ExploitabilityScope != domain.ScopeTransportPeer {
		t.Fatalf("scope = %q; want %q", verdict.ExploitabilityScope, domain.ScopeTransportPeer)
	}
	if !containsTransportLimitation(verdict.Limitations) {
		t.Fatalf("limitations = %v; want the transport-peer limitation", verdict.Limitations)
	}
	if !containsConditionID(verdict.ConditionIDs, "C-PEER-INPUT") {
		t.Fatalf("condition ids = %v; want the admitted transport claim", verdict.ConditionIDs)
	}

	// Same claims, no persisted witness: the boundary cannot be re-admitted,
	// so the positive may not publish an unexplained scope.
	unwitnessed := VerdictEvaluator{}.Evaluate(VerdictInput{
		Product:  product,
		Affected: affected,
		Model:    model,
		Claims:   claims,
		Evidence: nil,
	})
	if unwitnessed.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s; want INCONCLUSIVE without the witness", unwitnessed.Verdict)
	}
	if unwitnessed.ExploitabilityScope != "" {
		t.Fatalf("unwitnessed verdict carries scope %q", unwitnessed.ExploitabilityScope)
	}
	if !strings.Contains(unwitnessed.Reason, "failed witness re-admission") {
		t.Fatalf("reason = %q; want the refusal named", unwitnessed.Reason)
	}

	// The transport claim is only supporting: the positive stands on the
	// remaining conjunction and carries no boundary.
	supportingModel := model
	supportingModel.MandatoryConditions = []domain.Condition{constraintCond}
	supporting := VerdictEvaluator{}.Evaluate(VerdictInput{
		Product:  product,
		Affected: affected,
		Model:    supportingModel,
		Claims:   claims,
		Evidence: evidence,
	})
	if supporting.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict = %s (%s); want EXPLOITABLE", supporting.Verdict, supporting.Reason)
	}
	if supporting.ExploitabilityScope != "" {
		t.Fatalf("supporting transport claim scoped the verdict as %q", supporting.ExploitabilityScope)
	}
}

func transportStatesLikeAffected() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:                   domain.ClaimTrue,
		VersionAffected:                 domain.ClaimTrue,
		PackagePresent:                  domain.ClaimTrue,
		BuildRelevant:                   domain.ClaimTrue,
		VulnerableImplementationPresent: domain.ClaimTrue,
	}
}

func containsTransportLimitation(list []string) bool {
	for _, s := range list {
		if s == domain.TransportPeerScopeLimitation {
			return true
		}
	}
	return false
}

func containsConditionID(ids []domain.ConditionID, want domain.ConditionID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// hasVerdictGap reports one typed gap cause in an evaluation.
func hasVerdictGap(gaps []domain.AnalysisGap, owner domain.GapOwner, code domain.GapCode, obligation domain.Obligation) bool {
	for _, g := range gaps {
		if g.Owner == owner && g.Code == code && g.Obligation == obligation {
			return true
		}
	}
	return false
}

// candidateDerivedNegative builds the persisted shape the version-binding rule
// governs: one fix-derived candidate whose package is missing from the build
// graph, grounding a package-absent FALSE over its own subject.
func candidateDerivedNegative(sub domain.SymbolRef, binding *domain.CandidateBinding, absent bool) (
	domain.AffectedResult, domain.ExploitModel, []domain.Claim, *domain.RootCauseModel, domain.Vulnerability) {

	model := domain.ExploitModel{
		RootCauses: []domain.SymbolRef{sub},
		MandatoryConditions: []domain.Condition{{
			ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Subjects: []domain.SymbolRef{sub},
		}},
		UnresolvedSubjects: []domain.SymbolRef{sub},
		AbsentSubjects:     []domain.SymbolRef{sub},
	}
	claims := []domain.Claim{{
		ConditionID:          "C-REACH",
		Result:               domain.ClaimFalse,
		Falsifier:            domain.FalsifierPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
	}}
	rc := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: sub.Package, Symbol: sub.Symbol, Role: domain.RootCauseSink,
			Origin: domain.RootCauseOriginFixDerived, Absent: absent, Binding: binding,
		}},
	}
	v := domain.Vulnerability{ID: "GHSA-pwhc-rpq9-4c8w", Module: bindingModule(binding)}
	res := affectedAllTrue()
	res.Scope = exactVerdictScope()
	return res, model, claims, rc, v
}

func bindingModule(b *domain.CandidateBinding) string {
	if b == nil {
		return "github.com/containerd/containerd"
	}
	return b.Module
}

// The measured defect: a saved negative grounded on subjects that do not exist
// in the selected version must not survive replay. The claim is demoted and the
// failure is a CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE gap — the root cause,
// not the trace, is what remains unresolved.
func TestVerdictCandidateAbsenceRefusedWithoutIdentity(t *testing.T) {
	sub := domain.SymbolRef{
		Package: "github.com/containerd/containerd/cmd/containerd/server",
		Symbol:  "CreateTopLevelDirectories",
	}
	binding := &domain.CandidateBinding{
		Status: domain.CandidateBindingUnmapped, Module: "github.com/containerd/containerd",
		Version: "v1.7.27", PatchPath: "cmd/containerd/server/server.go",
	}
	res, model, claims, rc, v := candidateDerivedNegative(sub, binding, true)
	got := evalVerdictInput(res, model, claims, rc, v)
	if got.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("a candidate subject with no selected-version identity grounded NO_EXPLOIT_PATH_FOUND")
	}
	if !hasVerdictGap(got.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", got.Gaps)
	}
}

// A legacy record that persisted absence without any binding at all gets no
// exemption: missing admission is missing admission.
func TestVerdictCandidateAbsenceRefusedWhenBindingMissing(t *testing.T) {
	sub := domain.SymbolRef{
		Package: "github.com/containerd/containerd/cmd/containerd/server",
		Symbol:  "CreateTopLevelDirectories",
	}
	res, model, claims, rc, v := candidateDerivedNegative(sub, nil, true)
	got := evalVerdictInput(res, model, claims, rc, v)
	if got.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("a candidate without any version binding grounded NO_EXPLOIT_PATH_FOUND")
	}
	if !hasVerdictGap(got.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", got.Gaps)
	}
}

// A resolved patch coordinate is an identity observation, not absence
// authority. While the content-derived identity contract is withdrawn,
// automatic patch-only same-line absence loses its coordinate-only exemption:
// the dependent absent subject is pruned, the FALSE claim is demoted, and the
// failure is a typed CODE / ROOT_CAUSE_UNRESOLVED cause. This is the deliberate
// temporary capability reduction of the withdrawal.
func TestVerdictCandidateAbsenceCoordinateBindingIsNotAuthority(t *testing.T) {
	sub := domain.SymbolRef{Package: "github.com/docker/docker/libnetwork/osl", Symbol: "setIPv6"}
	binding := &domain.CandidateBinding{
		Status: domain.CandidateBindingAdmitted, Module: "github.com/docker/docker",
		Version: "v26.0.1", PatchPath: "libnetwork/osl/namespace_linux.go",
	}
	res, model, claims, rc, v := candidateDerivedNegative(sub, binding, true)
	got := evalVerdictInput(res, model, claims, rc, v)
	if got.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("a coordinate binding alone grounded NO_EXPLOIT_PATH_FOUND: %q", got.Verdict.Reason)
	}
	if !hasVerdictGap(got.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", got.Gaps)
	}
}

// Control: a record-declared subject keeps its own absence route. The
// declaration is the affirmative basis — any coordinate binding on the same
// candidate is incidental.
func TestVerdictCandidateAbsenceAdmittedForRecordDeclaredSubject(t *testing.T) {
	sub := domain.SymbolRef{Package: "github.com/docker/docker/libnetwork/osl", Symbol: "setIPv6"}
	binding := &domain.CandidateBinding{
		Status: domain.CandidateBindingAdmitted, Module: "github.com/docker/docker",
		Version: "v26.0.1", PatchPath: "libnetwork/osl/namespace_linux.go",
	}
	res, model, claims, rc, v := candidateDerivedNegative(sub, binding, true)
	v.AffectedSymbols = []domain.SymbolRef{sub}
	got := evalVerdictInput(res, model, claims, rc, v)
	if got.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s/%q — a record-declared subject keeps its absence route", got.Verdict.Verdict, got.Verdict.Reason)
	}
	if hasVerdictGap(got.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — a record-declared subject carries an admitted basis", got.Gaps)
	}
}
