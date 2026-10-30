package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func measurementContext() BuildContext {
	return BuildContext{
		Repository:        "example.com/prod",
		Commit:            "abc123",
		ExternalCommitSHA: "ext-1",
		ContentHash:       "sha256:tree",
		GOOS:              "linux",
		GOARCH:            "amd64",
		BuildTags:         []string{"netgo", "osusergo"},
		CGOEnabled:        true,
		GoVersion:         "go1.24.1",
		GoModDirective:    "1.23",
		VendorMode:        true,
		GoWorkFile:        "go.work",
		GoFlags:           "-mod=vendor",
		ReplaceDirectives: []ReplaceDirective{{Old: "a", New: "b"}},
		BinaryPath:        "/out/prod",
		BinarySHA256:      strings.Repeat("a", 64),
	}
}

func measurementEvidence() Evidence {
	build := measurementContext()
	return Evidence{
		Kind:         EvidenceGovulncheck,
		Quality:      QualityDeterministic,
		Source:       "govulncheck -json -mode source ./...",
		Tool:         "govulncheck",
		ToolVersion:  "db: file:///vulndb; updated 2026-01-01",
		Content:      `{"config":{"protocol_version":"v1.0.0"}}` + "\n",
		BuildContext: &build,
		Govulncheck: &GovulncheckRun{
			Outcome:   GovulncheckCompletedEmpty,
			Pattern:   "./...",
			Mode:      "source",
			ScanLevel: "symbol",
			Coverage: GovulncheckCoverage{
				AdvisoryID:    "GO-2099-0001",
				Advisory:      GovulncheckCoverageCovered,
				Subjects:      []SymbolRef{{Package: "example.com/dep", Symbol: "Parse"}},
				ScopeComplete: true,
			},
		},
		PackageList: &PackageListRun{
			Completed: true,
			Complete:  true,
			WithTests: false,
			Pattern:   "./...",
		},
		SourceScan: &SourceScanRun{
			Module:       "example.com/dep",
			Subjects:     []SymbolRef{{Package: "example.com/dep", Symbol: "Parse"}},
			EntrySymbols: []string{"example.com/dep.Parse"},
			Completed:    true,
			Complete:     true,
			Opaque:       false,
		},
	}
}

func TestMeasurementJSONRoundTrip(t *testing.T) {
	in := measurementEvidence()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Evidence
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("evidence round-trip changed the record:\n in=%+v\nout=%+v", in, out)
	}

	build := measurementContext()
	nv := NegativeVerification{
		Status:       NegativeVerified,
		EvidenceIDs:  []EvidenceID{"EV-001"},
		BuildContext: &build,
	}
	raw, err = json.Marshal(nv)
	if err != nil {
		t.Fatal(err)
	}
	var got NegativeVerification
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nv, got) {
		t.Fatalf("verification round-trip changed the record:\n in=%+v\nout=%+v", nv, got)
	}
}

func graphHashWith(t *testing.T, ev Evidence) string {
	t.Helper()
	g := &EvidenceGraph{}
	g.AddEvidence(ev)
	if hash := g.ComputeHash(); hash == "" {
		t.Fatal("hash must be computed")
	}
	return g.Hash
}

func TestMeasurementMetadataChangesHash(t *testing.T) {
	base := graphHashWith(t, measurementEvidence())

	withOutcome := measurementEvidence()
	withOutcome.Govulncheck.Outcome = GovulncheckCompletedWithResults
	if got := graphHashWith(t, withOutcome); got == base {
		t.Fatal("changing the outcome must change the evidence hash")
	}

	withCoverage := measurementEvidence()
	withCoverage.Govulncheck.Coverage.Advisory = GovulncheckCoverageNotInDB
	if got := graphHashWith(t, withCoverage); got == base {
		t.Fatal("changing advisory coverage must change the evidence hash")
	}

	withScope := measurementEvidence()
	withScope.Govulncheck.Coverage.ScopeComplete = false
	if got := graphHashWith(t, withScope); got == base {
		t.Fatal("changing scan scope must change the evidence hash")
	}

	withContext := measurementEvidence()
	withContext.BuildContext.GOOS = "darwin"
	if got := graphHashWith(t, withContext); got == base {
		t.Fatal("changing the build context must change the evidence hash")
	}

	withSubject := measurementEvidence()
	withSubject.Govulncheck.Coverage.Subjects = []SymbolRef{{Package: "example.com/dep", Symbol: "Other"}}
	if got := graphHashWith(t, withSubject); got == base {
		t.Fatal("changing covered subjects must change the evidence hash")
	}
}

func TestMeasurementOutcomeAndCoverageValues(t *testing.T) {
	for outcome, want := range map[GovulncheckOutcome]string{
		GovulncheckCompletedWithResults: "completed_with_results",
		GovulncheckCompletedEmpty:       "completed_empty",
		GovulncheckFailed:               "failed",
		GovulncheckNotRun:               "not_run",
	} {
		if string(outcome) != want {
			t.Fatalf("outcome %q != %q", outcome, want)
		}
	}
	for coverage, want := range map[GovulncheckAdvisoryCoverage]string{
		GovulncheckCoverageUnknown: "unknown",
		GovulncheckCoverageCovered: "covered",
		GovulncheckCoverageNotInDB: "not_in_db",
	} {
		if string(coverage) != want {
			t.Fatalf("coverage %q != %q", coverage, want)
		}
	}
}

func TestMeasurementSelectCompletePackageList(t *testing.T) {
	product := ProductSnapshot{
		Repository: "example.com/prod",
		Commit:     "abc123",
		GOOS:       "linux",
		GOARCH:     "amd64",
	}
	build := EffectiveBuildContext(product)
	complete := func(id EvidenceID, mutate func(*Evidence)) Evidence {
		ev := Evidence{
			ID:           id,
			Kind:         EvidencePackageList,
			BuildContext: &build,
			PackageList: &PackageListRun{
				Completed: true,
				Complete:  true,
				Pattern:   "./...",
			},
		}
		if mutate != nil {
			mutate(&ev)
		}
		return ev
	}

	t.Run("complete matching evidence is selected", func(t *testing.T) {
		ev, err := SelectCompletePackageList(product, []Evidence{complete("EV-PKG", nil)})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if ev.ID != "EV-PKG" {
			t.Fatalf("selected %q", ev.ID)
		}
	})

	t.Run("legacy evidence without metadata is non-admitting", func(t *testing.T) {
		_, err := SelectCompletePackageList(product, []Evidence{{
			ID: "EV-LEGACY", Kind: EvidencePackageList, Content: `[{"ImportPath":"example.com/prod"}]`,
		}})
		if err == nil {
			t.Fatal("legacy package-list evidence must not be admitted")
		}
	})

	t.Run("incomplete inventory is non-admitting", func(t *testing.T) {
		for name, mutate := range map[string]func(*Evidence){
			"not completed": func(e *Evidence) { e.PackageList.Completed = false },
			"not complete":  func(e *Evidence) { e.PackageList.Complete = false },
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := SelectCompletePackageList(product, []Evidence{complete("EV-PKG", mutate)}); err == nil {
					t.Fatal("partial inventory must not be admitted")
				}
			})
		}
	})

	t.Run("context mismatch is non-admitting", func(t *testing.T) {
		foreign := build
		foreign.GOARCH = "arm64"
		ev := complete("EV-PKG", func(e *Evidence) { e.BuildContext = &foreign })
		if _, err := SelectCompletePackageList(product, []Evidence{ev}); err == nil {
			t.Fatal("foreign build context must not be admitted")
		}
	})

	t.Run("most recent matching inventory wins", func(t *testing.T) {
		ev, err := SelectCompletePackageList(product, []Evidence{
			complete("EV-PKG-1", nil),
			complete("EV-PKG-2", nil),
		})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if ev.ID != "EV-PKG-2" {
			t.Fatalf("selected %q, want the latest record", ev.ID)
		}
	})
}
