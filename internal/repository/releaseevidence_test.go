package repository

import (
	"path/filepath"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// Synthetic toolchain values for capability tests — never a real ecosystem
// release.
var (
	synthGo    = "go1.42.10"
	synthGoAlt = "go1.42.8"
	synthGoSup = "go1.41.9"
)

func writeGoMod(t *testing.T, dir, extra string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n"+extra)
}

func itemAtOrNil(items []domain.ReleaseEvidenceItem, src domain.GoVersionSource) *domain.ReleaseEvidenceItem {
	for i := range items {
		if items[i].Source == src {
			return &items[i]
		}
	}
	return nil
}

func itemAt(t *testing.T, items []domain.ReleaseEvidenceItem, src domain.GoVersionSource) domain.ReleaseEvidenceItem {
	t.Helper()
	if it := itemAtOrNil(items, src); it != nil {
		return *it
	}
	t.Fatalf("no %s item in %+v", src, items)
	return domain.ReleaseEvidenceItem{}
}

func TestDiscoverReleaseEvidence_ToolchainDirective(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "\ntoolchain go1.22.8\n")
	sum := DiscoverReleaseEvidence(dir)
	it := itemAt(t, sum.Items, domain.GoVersionSourceToolchain)
	if it.Version != "go1.22.8" {
		t.Fatalf("toolchain item = %+v", it)
	}
	// A toolchain directive is a declarable build input: SUPPORTING only,
	// never enough to resolve the release toolchain.
	if it.TrustClass != domain.ReleaseTrustSupporting {
		t.Fatalf("toolchain trust class = %q", it.TrustClass)
	}
	if sum.Status != domain.ReleaseStatusUnknown || sum.SelectedVersion != "" {
		t.Fatalf("supporting-only evidence resolved: %+v", sum)
	}
}

func TestDiscoverReleaseEvidence_Dockerfile(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.24 AS build\nRUN go build ./...\n")
	sum := DiscoverReleaseEvidence(dir)
	it := itemAt(t, sum.Items, domain.GoVersionSourceDockerfile)
	if it.Version != "go1.24" || it.TrustClass != domain.ReleaseTrustSupporting {
		t.Fatalf("dockerfile item = %+v", it)
	}
	if sum.Status != domain.ReleaseStatusUnknown || sum.SelectedVersion != "" {
		t.Fatalf("dockerfile-only evidence resolved: %+v", sum)
	}
}

func TestDiscoverReleaseEvidence_CI(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	writeFile(t, filepath.Join(dir, ".github", "workflows", "ci.yml"),
		"jobs:\n  build:\n    steps:\n      - uses: actions/setup-go@v5\n        with:\n          go-version: '1.23.1'\n")
	sum := DiscoverReleaseEvidence(dir)
	it := itemAt(t, sum.Items, domain.GoVersionSourceCI)
	if it.Version != "go1.23.1" || it.TrustClass != domain.ReleaseTrustSupporting {
		t.Fatalf("ci item = %+v", it)
	}
	if sum.Status != domain.ReleaseStatusUnknown || sum.SelectedVersion != "" {
		t.Fatalf("ci-only evidence resolved: %+v", sum)
	}
}

func TestDiscoverReleaseEvidence_VersionFile(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	writeFile(t, filepath.Join(dir, ".go-version"), "1.22.5\n")
	sum := DiscoverReleaseEvidence(dir)
	it := itemAt(t, sum.Items, domain.GoVersionSourceVersionFile)
	if it.Version != "go1.22.5" || it.TrustClass != domain.ReleaseTrustSupporting {
		t.Fatalf("version-file item = %+v", it)
	}
	if sum.Status != domain.ReleaseStatusUnknown || sum.SelectedVersion != "" {
		t.Fatalf("version-file-only evidence resolved: %+v", sum)
	}
}

func TestDiscoverReleaseEvidence_UnknownWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	sum := DiscoverReleaseEvidence(dir)
	// go.mod's `go` directive is itself a declaration, so the only truly
	// empty case is a snapshot without go.mod — covered below.
	if sum.Status != domain.ReleaseStatusUnknown || sum.SelectedVersion != "" {
		t.Fatalf("declarations resolved the release toolchain: %+v", sum)
	}
	empty := t.TempDir()
	sum = DiscoverReleaseEvidence(empty)
	if sum.Status != domain.ReleaseStatusUnknown || sum.ReasonCode != domain.ReleaseReasonAbsent {
		t.Fatalf("absent evidence = %+v", sum)
	}
	if len(sum.Items) != 0 {
		t.Fatalf("items recorded for absent evidence: %+v", sum.Items)
	}
}

func TestDiscoverReleaseEvidence_PartialTagInScriptIsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	// Variable substitution: not a literal pin, must yield no evidence.
	writeFile(t, filepath.Join(dir, "Makefile"), "build:\n\tGOTOOLCHAIN=$GO_VERSION go build ./...\n")
	sum := DiscoverReleaseEvidence(dir)
	if itemAtOrNil(sum.Items, domain.GoVersionSourceVersionFile) != nil {
		t.Fatalf("computed version was accepted: %+v", sum)
	}
}

func TestDiscoverReleaseEvidence_CollectsAllDeclarations(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "\ntoolchain go1.22.8\n")
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.24 AS build\nRUN go build ./...\n")
	writeFile(t, filepath.Join(dir, ".github", "workflows", "ci.yml"),
		"steps:\n  - uses: actions/setup-go@v5\n    with:\n      go-version: '1.23.1'\n")
	writeFile(t, filepath.Join(dir, ".go-version"), "1.22.5\n")
	sum := DiscoverReleaseEvidence(dir)
	seen := map[domain.GoVersionSource]bool{}
	for _, it := range sum.Items {
		seen[it.Source] = true
		if it.TrustClass != domain.ReleaseTrustSupporting {
			t.Fatalf("snapshot-local item not SUPPORTING: %+v", it)
		}
		if it.Location == "" {
			t.Fatalf("item missing location provenance: %+v", it)
		}
	}
	for _, src := range []domain.GoVersionSource{
		domain.GoVersionSourceGoMod, domain.GoVersionSourceToolchain,
		domain.GoVersionSourceDockerfile, domain.GoVersionSourceCI,
		domain.GoVersionSourceVersionFile,
	} {
		if !seen[src] {
			t.Fatalf("discovery dropped %s declarations: %+v", src, sum.Items)
		}
	}
	if sum.Status != domain.ReleaseStatusUnknown {
		t.Fatalf("supporting-only declarations resolved: %+v", sum)
	}
}

func TestDiscoverReleaseEvidence_ConflictingSupporting(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.25.8 AS build\n")
	writeFile(t, filepath.Join(dir, ".github", "workflows", "ci.yml"),
		"steps:\n  - uses: actions/setup-go@v5\n    with:\n      go-version: '1.24.0'\n")
	sum := DiscoverReleaseEvidence(dir)
	// Disagreeing declarations are still only SUPPORTING: the outcome is
	// UNKNOWN, never CONFLICTED and never a selected version.
	if sum.Status != domain.ReleaseStatusUnknown || sum.SelectedVersion != "" {
		t.Fatalf("conflicting supporting evidence resolved: %+v", sum)
	}
	if sum.ReasonCode != domain.ReleaseReasonSupportingOnly {
		t.Fatalf("reason = %q, want %s", sum.ReasonCode, domain.ReleaseReasonSupportingOnly)
	}
}

func TestResolveReleaseEvidence_AgreeingAuthoritative(t *testing.T) {
	sum := ResolveReleaseEvidence([]domain.ReleaseEvidenceItem{
		{Version: synthGo, Source: domain.GoVersionSourceBinary, TrustClass: domain.ReleaseTrustAuthoritative, Location: "/bin/app"},
		{Version: "1.42.10", Source: domain.GoVersionSourceExplicit, TrustClass: domain.ReleaseTrustAuthoritative},
		{Version: synthGo, Source: domain.GoVersionSourceDockerfile, TrustClass: domain.ReleaseTrustSupporting, Location: "Dockerfile:1"},
	})
	if sum.Status != domain.ReleaseStatusResolved {
		t.Fatalf("agreeing authoritative = %+v", sum)
	}
	if sum.SelectedVersion != synthGo || sum.SelectedSource != domain.GoVersionSourceBinary {
		t.Fatalf("selection = %q from %s", sum.SelectedVersion, sum.SelectedSource)
	}
	if sum.SelectedTrust != domain.ReleaseTrustAuthoritative {
		t.Fatalf("selected trust = %q", sum.SelectedTrust)
	}
}

func TestResolveReleaseEvidence_ConflictingAuthoritative(t *testing.T) {
	sum := ResolveReleaseEvidence([]domain.ReleaseEvidenceItem{
		{Version: synthGo, Source: domain.GoVersionSourceBinary, TrustClass: domain.ReleaseTrustAuthoritative, Location: "/bin/app"},
		{Version: synthGoAlt, Source: domain.GoVersionSourceExplicit, TrustClass: domain.ReleaseTrustAuthoritative},
	})
	if sum.Status != domain.ReleaseStatusConflicted {
		t.Fatalf("conflicting authoritative = %+v", sum)
	}
	if sum.ReasonCode != domain.ReleaseReasonConflict {
		t.Fatalf("reason = %q, want %s", sum.ReasonCode, domain.ReleaseReasonConflict)
	}
	// The conflict must never silently pick the first or newest value.
	if sum.SelectedVersion != "" || sum.SelectedSource != "" {
		t.Fatalf("conflict selected a version: %q", sum.SelectedVersion)
	}
}

func TestResolveReleaseEvidence_SupportingNeverOverrides(t *testing.T) {
	sum := ResolveReleaseEvidence([]domain.ReleaseEvidenceItem{
		{Version: synthGo, Source: domain.GoVersionSourceBinary, TrustClass: domain.ReleaseTrustAuthoritative, Location: "/bin/app"},
		{Version: synthGoAlt, Source: domain.GoVersionSourceDockerfile, TrustClass: domain.ReleaseTrustSupporting, Location: "Dockerfile:1"},
		{Version: "go1.40.0", Source: domain.GoVersionSourceCI, TrustClass: domain.ReleaseTrustSupporting, Location: "ci.yml:4"},
	})
	// Both supporting items disagree with the measured toolchain; the
	// authoritative value still stands and the disagreement stays visible
	// in the item list.
	if sum.Status != domain.ReleaseStatusResolved || sum.SelectedVersion != synthGo {
		t.Fatalf("supporting evidence overrode the authoritative value: %+v", sum)
	}
	if len(sum.Items) != 3 {
		t.Fatalf("disagreeing supporting evidence was dropped: %+v", sum.Items)
	}
}

func TestResolveReleaseEvidence_SupportingCannotGround(t *testing.T) {
	for _, src := range []domain.GoVersionSource{
		domain.GoVersionSourceGoMod, domain.GoVersionSourceToolchain,
		domain.GoVersionSourceDockerfile, domain.GoVersionSourceCI,
		domain.GoVersionSourceVersionFile,
	} {
		sum := ResolveReleaseEvidence([]domain.ReleaseEvidenceItem{
			{Version: synthGoSup, Source: src, TrustClass: domain.ReleaseTrustSupporting, Location: "src:1"},
		})
		if sum.Status == domain.ReleaseStatusResolved || sum.SelectedVersion != "" {
			t.Fatalf("%s alone grounded a version determination: %+v", src, sum)
		}
		if sum.Status != domain.ReleaseStatusUnknown {
			t.Fatalf("%s alone = %s, want UNKNOWN", src, sum.Status)
		}
	}
}

func TestResolveReleaseEvidence_NoItems(t *testing.T) {
	sum := ResolveReleaseEvidence(nil)
	if sum.Status != domain.ReleaseStatusUnknown || sum.ReasonCode != domain.ReleaseReasonAbsent {
		t.Fatalf("empty evidence = %+v", sum)
	}
}

func TestResolveReleaseEvidence_Normalization(t *testing.T) {
	cases := []struct {
		name     string
		versions [2]string
		want     domain.ReleaseEvidenceStatus
	}{
		{"prefix variants agree", [2]string{synthGo, "v1.42.10"}, domain.ReleaseStatusResolved},
		{"bare digits agree", [2]string{synthGo, "1.42.10"}, domain.ReleaseStatusResolved},
		{"patch release agrees with minor line", [2]string{"go1.42.0", "1.42"}, domain.ReleaseStatusResolved},
		{"platform suffix agrees", [2]string{"go1.42.8", "1.42.8-ubi9"}, domain.ReleaseStatusResolved},
		{"different patch conflicts", [2]string{"go1.42.8", synthGo}, domain.ReleaseStatusConflicted},
		{"minor line vs later patch conflicts", [2]string{"go1.42", synthGo}, domain.ReleaseStatusConflicted},
		// Semver prerelease components are significant: a release
		// candidate is not the stable line and must never merge with it.
		{"prerelease conflicts with stable", [2]string{"go1.44.0-rc.3", "go1.44.0"}, domain.ReleaseStatusConflicted},
		{"prerelease agrees with itself", [2]string{"go1.44.0-rc.3", "1.44.0-rc.3"}, domain.ReleaseStatusResolved},
		{"different prereleases conflict", [2]string{"go1.44.0-rc.3", "go1.44.0-rc.1"}, domain.ReleaseStatusConflicted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum := ResolveReleaseEvidence([]domain.ReleaseEvidenceItem{
				{Version: tc.versions[0], Source: domain.GoVersionSourceBinary, TrustClass: domain.ReleaseTrustAuthoritative},
				{Version: tc.versions[1], Source: domain.GoVersionSourceExplicit, TrustClass: domain.ReleaseTrustAuthoritative},
			})
			if sum.Status != tc.want {
				t.Fatalf("%q vs %q = %s, want %s", tc.versions[0], tc.versions[1], sum.Status, tc.want)
			}
			if tc.want == domain.ReleaseStatusConflicted && sum.SelectedVersion != "" {
				t.Fatalf("conflict selected %q", sum.SelectedVersion)
			}
		})
	}
}

// A malformed AUTHORITATIVE item fails closed as a named invalid outcome —
// it is never silently dropped so that another authority can resolve alone.
func TestResolveReleaseEvidence_InvalidAuthoritative(t *testing.T) {
	sum := ResolveReleaseEvidence([]domain.ReleaseEvidenceItem{
		{Version: synthGo, Source: domain.GoVersionSourceBinary, TrustClass: domain.ReleaseTrustAuthoritative},
		{Version: "not-a-version", Source: domain.GoVersionSourceExplicit, TrustClass: domain.ReleaseTrustAuthoritative},
	})
	if sum.Status != domain.ReleaseStatusConflicted ||
		sum.ReasonCode != domain.ReleaseReasonReleaseVersionInvalid {
		t.Fatalf("malformed authoritative item = %s/%q", sum.Status, sum.ReasonCode)
	}
	if sum.SelectedVersion != "" {
		t.Fatalf("invalid channel selected %q", sum.SelectedVersion)
	}
}
