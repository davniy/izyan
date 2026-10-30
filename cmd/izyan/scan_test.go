package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestDedupeAppend(t *testing.T) {
	got := dedupeAppend([]string{"A", "B"}, []string{"B", "C", "A", "D"})
	want := []string{"A", "B", "C", "D"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Order across multiple module queries is stable.
	got = dedupeAppend(got, []string{"D", "E"})
	if !reflect.DeepEqual(got, []string{"A", "B", "C", "D", "E"}) {
		t.Fatalf("second append: %v", got)
	}
}

// prefilterProduct is a scoped operator-declared build: the identity a
// build-dependent affected negative needs.
func prefilterProduct() domain.ProductSnapshot {
	p := domain.ProductSnapshot{Repository: "/test/scan", Commit: "scancommit", GOOS: "linux", GOARCH: "amd64"}
	p.Target = &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	return p
}

func prefilterPackageList(p domain.ProductSnapshot, complete bool) domain.Evidence {
	build := domain.EffectiveBuildContext(p)
	return domain.Evidence{
		ID: "EV-SCAN-PKGS", Kind: domain.EvidencePackageList, Quality: domain.QualityDeterministic,
		BuildContext: &build,
		PackageList:  &domain.PackageListRun{Completed: true, Complete: complete, Pattern: "./..."},
		Content:      `{"ImportPath":"example.com/prod"}`,
	}
}

// completeScope is the only scope authority that filters an advisory out of
// the deep pipeline: an exact GO- identity whose single original affected[]
// entry is a Go module the loaded record fully represented.
func completeScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         "GO-TEST-1",
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"}},
			RepresentedRefs:    []int{0},
		},
	}
}

// projectedScope is an exact identity whose loaded document represented only
// its Go entry. A component negative under it must survive the prefilter.
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

// partialCompleteScope is the legacy persisted shape: COMPLETE coverage with
// no structural census, which no longer filters an advisory.
func partialCompleteScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
	}
}

// The scan prefilter is the common verdict evaluator: only its NOT_AFFECTED
// verdict removes an advisory from the deep pipeline. A private or
// host-default negative stays a survivor.
func TestScanPrefilterOnlyFiltersNotAffected(t *testing.T) {
	admitted := prefilterProduct()
	hostDefault := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}

	cases := []struct {
		name     string
		product  domain.ProductSnapshot
		affected domain.AffectedResult
		evidence []domain.Evidence
		want     domain.Verdict
	}{
		{
			name:     "module absent is independent",
			product:  hostDefault,
			affected: domain.AffectedResult{Scope: completeScope(), ModulePresent: domain.ClaimFalse},
			want:     domain.VerdictNotAffected,
		},
		{
			name:     "version outside range is independent",
			product:  hostDefault,
			affected: domain.AffectedResult{Scope: completeScope(), ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse},
			want:     domain.VerdictNotAffected,
		},
		{
			name:     "projected module absence stays",
			product:  hostDefault,
			affected: domain.AffectedResult{Scope: projectedScope(), ModulePresent: domain.ClaimFalse},
			want:     domain.VerdictInconclusive,
		},
		{
			name:     "projected version negative stays",
			product:  hostDefault,
			affected: domain.AffectedResult{Scope: projectedScope(), ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse},
			want:     domain.VerdictInconclusive,
		},
		{
			name:     "censusless complete scope negative stays",
			product:  hostDefault,
			affected: domain.AffectedResult{Scope: partialCompleteScope(), ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse},
			want:     domain.VerdictInconclusive,
		},
		{
			name:    "package absence under host default stays",
			product: hostDefault,
			affected: domain.AffectedResult{
				Scope: completeScope(), ModulePresent: domain.ClaimTrue,
				VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse,
			},
			want: domain.VerdictInconclusive,
		},
		{
			name:    "package absence without inventory stays",
			product: admitted,
			affected: domain.AffectedResult{
				Scope: completeScope(), ModulePresent: domain.ClaimTrue,
				VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse,
			},
			want: domain.VerdictInconclusive,
		},
		{
			name:    "partial inventory stays",
			product: admitted,
			affected: domain.AffectedResult{
				Scope: completeScope(), ModulePresent: domain.ClaimTrue,
				VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse,
			},
			evidence: []domain.Evidence{prefilterPackageList(admitted, false)},
			want:     domain.VerdictInconclusive,
		},
		{
			name:    "admitted package absence filters",
			product: admitted,
			affected: domain.AffectedResult{
				Scope: completeScope(), ModulePresent: domain.ClaimTrue,
				VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse,
			},
			evidence: []domain.Evidence{prefilterPackageList(admitted, true)},
			want:     domain.VerdictNotAffected,
		},
		{
			name:     "applicable advisory survives",
			product:  admitted,
			affected: domain.AffectedResult{Scope: completeScope(), ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue},
			want:     domain.VerdictInconclusive,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanPrefilter(tc.product, tc.affected, tc.evidence)
			if got.Verdict != tc.want {
				t.Fatalf("verdict=%s (%s), want %s", got.Verdict, got.Reason, tc.want)
			}
			if got.Verdict == domain.VerdictNotAffected && got.Reason == "" {
				t.Fatal("NOT_AFFECTED must carry the evaluator reason")
			}
		})
	}
}
