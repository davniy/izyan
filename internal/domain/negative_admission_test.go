package domain

import (
	"testing"
)

func admittedSnapshot() ProductSnapshot {
	return ProductSnapshot{
		Repository: "/test/product",
		Commit:     "testcommit",
		GOOS:       "linux",
		GOARCH:     "amd64",
		Target: &ProductTarget{
			GOOS:   "linux",
			GOARCH: "amd64",
			Source: ProductTargetSourceOperatorDeclared,
			Scope:  ProductTargetScopeOperator,
		},
	}
}

func hostDefaultSnapshot() ProductSnapshot {
	return ProductSnapshot{
		Repository: "/test/product",
		Commit:     "testcommit",
		GOOS:       "darwin",
		GOARCH:     "arm64",
		Target: &ProductTarget{
			GOOS:   "darwin",
			GOARCH: "arm64",
			Source: ProductTargetSourceHostDefault,
		},
	}
}

// Every falsifier is classified by its actual basis, never by explanation
// text. Missing or unknown bases default to requiring a target.
func TestNegativeAdmissionClassification(t *testing.T) {
	cases := []struct {
		name      string
		falsifier string
		basis     string
		params    map[string]string
		want      bool
	}{
		{"empty falsifier is not a negative", "", "", nil, false},
		{"govulncheck silence", FalsifierGovulncheckSilence, "", nil, true},
		{"no module usage", FalsifierNoModuleUsage, "", nil, true},
		{"unreached exported subject", FalsifierUnreachedExportedSubject, "", nil, true},
		{"no product reader", FalsifierNoProductReader, "", nil, true},
		{"missing pair member", FalsifierMissingPairMember, "", nil, true},
		{"goos mismatch", FalsifierSnapshotFactMismatch, "", map[string]string{"goos": "windows"}, true},
		{"goarch mismatch", FalsifierSnapshotFactMismatch, "", map[string]string{"goarch": "arm64"}, true},
		{"release toolchain contradiction", FalsifierSnapshotFactMismatch, "", map[string]string{"go_version": "<1.18"}, false},
		{"missing source symbol", FalsifierMissingSourceSymbol, "", nil, true},
		{"safe config assignment", FalsifierSafeConfigAssignment, "", nil, true},
		{"zero value config", FalsifierZeroValueConfig, "", nil, true},
		{"repository config key", FalsifierSafeConfigKey, "", nil, false},
		{"guards", FalsifierGuards, "", nil, true},
		{"constant or generated input", FalsifierConstantOrGeneratedInput, "", nil, true},
		{"trusted infrastructure declared trust", FalsifierTrustedInfrastructure, BasisDeclaredTrust, nil, false},
		{"trusted infrastructure auto perimeter", FalsifierTrustedInfrastructure, BasisAutoPerimeter, nil, false},
		{"trusted infrastructure config origin", FalsifierTrustedInfrastructure, BasisConfigOrigin, nil, true},
		{"trusted infrastructure unrecorded basis", FalsifierTrustedInfrastructure, "", nil, true},
		{"locus package absent", FalsifierLocusPackageAbsent, "", nil, true},
		{"package absent", FalsifierPackageAbsent, "", nil, true},
		{"declared symbol unreached", FalsifierDeclaredSymbolUnreached, "", nil, true},
		{"locus function unreached", FalsifierLocusFunctionUnreached, "", nil, true},
		{"config gated off", FalsifierConfigGatedOff, "", nil, true},
		{"loopback from code", FalsifierLoopbackOnly, "", nil, true},
		{"loopback from deployment manifests", FalsifierLoopbackOnly, BasisDeployment, nil, false},
		{"protocol role mismatch", FalsifierProtocolRoleMismatch, "", nil, true},
		{"unknown falsifier defaults conservatively", "some-future-falsifier", "", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim := Claim{Result: ClaimFalse, Falsifier: tc.falsifier, FalsifierBasis: tc.basis}
			cond := Condition{ID: "C1", Params: tc.params}
			if got := NegativeRequiresTarget(claim, cond); got != tc.want {
				t.Fatalf("NegativeRequiresTarget(%q, basis %q) = %v, want %v", tc.falsifier, tc.basis, got, tc.want)
			}
		})
	}
}

// The target gate admits one identified build only: host defaults, nil
// targets and mismatched target facts are all refused.
func TestNegativeAdmissionTargetGate(t *testing.T) {
	cond := Condition{ID: "C1", Kind: ConditionInputConstraint, Subjects: []SymbolRef{{Package: "example.com/dep", Symbol: "Sink"}}}
	claim := Claim{Result: ClaimFalse, Falsifier: FalsifierGuards}

	if err := ValidateNegativeEvidence(admittedSnapshot(), claim, cond, nil); err != nil {
		t.Fatalf("admitted target refused: %v", err)
	}
	if err := ValidateNegativeEvidence(hostDefaultSnapshot(), claim, cond, nil); err == nil {
		t.Fatal("host-default snapshot admitted a build-dependent negative")
	}
	noTarget := admittedSnapshot()
	noTarget.Target = nil
	if err := ValidateNegativeEvidence(noTarget, claim, cond, nil); err == nil {
		t.Fatal("nil target admitted a build-dependent negative")
	}
	mismatched := admittedSnapshot()
	mismatched.GOARCH = "arm64"
	if err := ValidateNegativeEvidence(mismatched, claim, cond, nil); err == nil {
		t.Fatal("target facts mismatching the snapshot admitted a negative")
	}
	partial := admittedSnapshot()
	partial.Target = &ProductTarget{GOOS: "linux", GOARCH: "amd64", BuildTags: []string{"tag"}}
	if err := ValidateNegativeEvidence(partial, claim, cond, nil); err == nil {
		t.Fatal("tags-only target admitted a build-dependent negative")
	}

	// Independent bases do not need a target.
	independent := Claim{Result: ClaimFalse, Falsifier: FalsifierTrustedInfrastructure, FalsifierBasis: BasisDeclaredTrust}
	if err := ValidateNegativeEvidence(hostDefaultSnapshot(), independent, cond, nil); err != nil {
		t.Fatalf("independent negative required a target: %v", err)
	}
}

func packageListEvidence(p ProductSnapshot, complete bool) Evidence {
	build := EffectiveBuildContext(p)
	return Evidence{
		ID: "EV-PKGS", Kind: EvidencePackageList,
		BuildContext: &build,
		PackageList:  &PackageListRun{Completed: true, Complete: complete, Pattern: "./..."},
		Content:      `{"ImportPath":"example.com/prod"}`,
	}
}

func sourceScanEvidence(p ProductSnapshot, module string, subjects []SymbolRef, entries []string, complete, opaque bool) Evidence {
	build := EffectiveBuildContext(p)
	return Evidence{
		ID: "EV-SCAN", Kind: EvidenceSourceScan,
		BuildContext: &build,
		SourceScan: &SourceScanRun{
			Module: module, Subjects: subjects, EntrySymbols: entries,
			Completed: true, Complete: complete, Opaque: opaque,
		},
	}
}

func govulncheckEvidence(p ProductSnapshot, outcome GovulncheckOutcome, coverage GovulncheckCoverage) Evidence {
	build := EffectiveBuildContext(p)
	return Evidence{
		ID: "EV-GOVULNCHECK", Kind: EvidenceGovulncheck,
		BuildContext: &build,
		Govulncheck:  &GovulncheckRun{Outcome: outcome, Coverage: coverage},
	}
}

// A falsifier's measurement must exist, match the build and carry the
// coverage the negative needs. Missing, failed, narrowed and mismatched
// measurements are all refused.
func TestNegativeAdmissionMeasurementGate(t *testing.T) {
	p := admittedSnapshot()
	subject := SymbolRef{Package: "example.com/dep", Symbol: "Sink"}

	silence := Claim{
		Result: ClaimFalse, Falsifier: FalsifierGovulncheckSilence,
		EvidenceIDs: []EvidenceID{"EV-GOVULNCHECK"},
	}
	silenceCond := Condition{ID: "C1", Subjects: []SymbolRef{subject}}
	full := GovulncheckCoverage{
		AdvisoryID: "GO-TEST-1", Advisory: GovulncheckCoverageCovered,
		Subjects: []SymbolRef{subject}, ScopeComplete: true,
	}
	if err := ValidateNegativeEvidence(p, silence, silenceCond, []Evidence{
		govulncheckEvidence(p, GovulncheckCompletedEmpty, full),
	}); err != nil {
		t.Fatalf("covered completed-empty measurement refused: %v", err)
	}
	refusals := map[string]Evidence{
		"failed run":        govulncheckEvidence(p, GovulncheckFailed, full),
		"not-run":           govulncheckEvidence(p, GovulncheckNotRun, full),
		"completed results": govulncheckEvidence(p, GovulncheckCompletedWithResults, full),
		"uncovered advisory": govulncheckEvidence(p, GovulncheckCompletedEmpty,
			GovulncheckCoverage{AdvisoryID: "GO-TEST-1", Advisory: GovulncheckCoverageNotInDB, Subjects: []SymbolRef{subject}, ScopeComplete: true}),
		"narrowed scope": govulncheckEvidence(p, GovulncheckCompletedEmpty,
			GovulncheckCoverage{AdvisoryID: "GO-TEST-1", Advisory: GovulncheckCoverageCovered, Subjects: []SymbolRef{subject}}),
		"declares other symbols": govulncheckEvidence(p, GovulncheckCompletedEmpty,
			GovulncheckCoverage{AdvisoryID: "GO-TEST-1", Advisory: GovulncheckCoverageCovered, Subjects: []SymbolRef{{Package: "example.com/dep", Symbol: "Other"}}, ScopeComplete: true}),
	}
	for name, ev := range refusals {
		if err := ValidateNegativeEvidence(p, silence, silenceCond, []Evidence{ev}); err == nil {
			t.Errorf("%s admitted govulncheck silence", name)
		}
	}
	if err := ValidateNegativeEvidence(p, silence, silenceCond, nil); err == nil {
		t.Error("uncited silence admitted")
	}
	foreign := govulncheckEvidence(hostDefaultSnapshot(), GovulncheckCompletedEmpty, full)
	if err := ValidateNegativeEvidence(p, silence, silenceCond, []Evidence{foreign}); err == nil {
		t.Error("foreign-context measurement admitted")
	}

	packageAbsent := Claim{Result: ClaimFalse, Falsifier: FalsifierPackageAbsent}
	// An absence claim must name the subject set it covers: a subject-less
	// absence negative is a vacuous closure even when the inventory is perfect.
	if err := ValidateNegativeEvidence(p, packageAbsent, Condition{ID: "C1"},
		[]Evidence{packageListEvidence(p, true)}); err == nil {
		t.Error("package absence with no evaluated subject admitted")
	}
	absenceCond := Condition{ID: "C1", Subjects: []SymbolRef{subject}}
	if err := ValidateNegativeEvidence(p, packageAbsent, absenceCond, nil); err == nil {
		t.Error("package absence admitted without an inventory")
	}
	if err := ValidateNegativeEvidence(p, packageAbsent, absenceCond, []Evidence{packageListEvidence(p, false)}); err == nil {
		t.Error("package absence admitted with an incomplete inventory")
	}
	if err := ValidateNegativeEvidence(p, packageAbsent, absenceCond, []Evidence{packageListEvidence(hostDefaultSnapshot(), true)}); err == nil {
		t.Error("package absence admitted with a foreign-context inventory")
	}
	if err := ValidateNegativeEvidence(p, packageAbsent, absenceCond, []Evidence{packageListEvidence(p, true)}); err != nil {
		t.Fatalf("complete matching inventory refused: %v", err)
	}

	noUsage := Claim{Result: ClaimFalse, Falsifier: FalsifierNoModuleUsage}
	usageCond := Condition{ID: "C1", Subjects: []SymbolRef{subject}}
	completedRun := govulncheckEvidence(p, GovulncheckCompletedEmpty, full)
	withResultsRun := govulncheckEvidence(p, GovulncheckCompletedWithResults, full)
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, nil); err == nil {
		t.Error("no-module-usage admitted without a source scan")
	}
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, false, false),
	}); err == nil {
		t.Error("no-module-usage admitted over an incomplete census")
	}
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, true, false),
	}); err == nil {
		t.Error("no-module-usage admitted without an applicable completed run")
	}
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, true, false),
		govulncheckEvidence(p, GovulncheckFailed, full),
	}); err == nil {
		t.Error("no-module-usage admitted after a failed govulncheck run")
	}
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, true, false),
		govulncheckEvidence(p, GovulncheckNotRun, full),
	}); err == nil {
		t.Error("no-module-usage admitted after a not-run govulncheck")
	}
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, true, false),
		completedRun,
	}); err != nil {
		t.Fatalf("complete usage scan with a completed run refused: %v", err)
	}
	if err := ValidateNegativeEvidence(p, noUsage, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, true, false),
		withResultsRun,
	}); err != nil {
		t.Fatalf("complete usage scan with a completed-with-results run refused: %v", err)
	}

	unreached := Claim{Result: ClaimFalse, Falsifier: FalsifierUnreachedExportedSubject}
	if err := ValidateNegativeEvidence(p, unreached, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, []string{"example.com/dep.Entry"}, true, true),
		completedRun,
	}); err == nil {
		t.Error("opaque reach measurement admitted an unreachability negative")
	}
	if err := ValidateNegativeEvidence(p, unreached, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, nil, true, false),
		completedRun,
	}); err == nil {
		t.Error("reach measurement without entries admitted an unreachability negative")
	}
	if err := ValidateNegativeEvidence(p, unreached, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, []string{"example.com/dep.Entry"}, true, false),
		completedRun,
	}); err != nil {
		t.Fatalf("complete non-opaque reach measurement refused: %v", err)
	}
	if err := ValidateNegativeEvidence(p, unreached, usageCond, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, []string{"example.com/dep.Entry"}, true, false),
		govulncheckEvidence(p, GovulncheckFailed, full),
	}); err == nil {
		t.Error("unreached-exported-subject admitted after a failed govulncheck run")
	}

	locus := Claim{Result: ClaimFalse, Falsifier: FalsifierLocusFunctionUnreached}
	twoSubjects := Condition{ID: "C-LOCUS", Subjects: []SymbolRef{
		subject,
		{Package: "example.com/dep/other", Symbol: "Sink2"},
	}}
	if err := ValidateNegativeEvidence(p, locus, twoSubjects, []Evidence{
		sourceScanEvidence(p, "example.com/dep", []SymbolRef{subject}, []string{"example.com/dep.Entry"}, true, false),
	}); err == nil {
		t.Error("locus unreachability admitted without coverage of the whole locus set")
	}
}


// Affected-chain negatives: module graph and version facts are independent;
// package/build/implementation facts describe one build.
func TestNegativeAdmissionAffectedGate(t *testing.T) {
	p := admittedSnapshot()
	if err := ValidateAffectedNegative(hostDefaultSnapshot(), AffectedResult{
		ModulePresent: ClaimFalse, VersionAffected: ClaimFalse,
	}, nil); err != nil {
		t.Fatalf("independent affected negatives refused: %v", err)
	}
	packageAbsent := AffectedResult{
		ModulePresent: ClaimTrue, VersionAffected: ClaimTrue, PackagePresent: ClaimFalse,
	}
	if err := ValidateAffectedNegative(hostDefaultSnapshot(), packageAbsent, nil); err == nil {
		t.Fatal("host-default package absence admitted")
	}
	if err := ValidateAffectedNegative(p, packageAbsent, nil); err == nil {
		t.Fatal("package absence admitted without a complete inventory")
	}
	if err := ValidateAffectedNegative(p, packageAbsent, []Evidence{packageListEvidence(p, true)}); err != nil {
		t.Fatalf("admitted package absence refused: %v", err)
	}
	if err := ValidateAffectedNegative(hostDefaultSnapshot(), AffectedResult{
		ModulePresent: ClaimTrue, VersionAffected: ClaimTrue, PackagePresent: ClaimTrue, BuildRelevant: ClaimFalse,
	}, nil); err == nil {
		t.Fatal("host-default build relevance admitted")
	}
	implementation := AffectedResult{
		ModulePresent: ClaimTrue, VersionAffected: ClaimTrue, PackagePresent: ClaimTrue, BuildRelevant: ClaimTrue,
		VulnerableImplementationPresent: ClaimFalse,
		ImplementationTarget:            "linux/arm64",
	}
	if err := ValidateAffectedNegative(p, implementation, nil); err == nil {
		t.Fatal("implementation verification under a different target admitted")
	}
	implementation.ImplementationTarget = "linux/amd64"
	if err := ValidateAffectedNegative(p, implementation, nil); err != nil {
		t.Fatalf("matching implementation target refused: %v", err)
	}
}
