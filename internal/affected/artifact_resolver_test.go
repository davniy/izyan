package affected

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// Synthetic toolchain values for capability tests — never a real ecosystem
// release.
const (
	synthToolchain      = "go1.42.7"
	synthToolchainAlt   = "go1.41.0"
	synthToolchainMinor = "go1.40"
	synthToolchainSup   = "go1.42.5"
)

// resolvedReleaseEvidence builds the snapshot shape Service.Snapshot
// produces when the artifact channel resolved: an AUTHORITATIVE summary
// carrying the selected toolchain, digests, and the release module graph.
func resolvedReleaseEvidence(mods []domain.ReleaseModule) *domain.ReleaseEvidenceSummary {
	return &domain.ReleaseEvidenceSummary{
		Status:          domain.ReleaseStatusResolved,
		SelectedVersion: synthToolchain,
		SelectedSource:  domain.GoVersionSourceBinary,
		SelectedTrust:   domain.ReleaseTrustAuthoritative,
		Items: []domain.ReleaseEvidenceItem{{
			Version:         synthToolchain,
			Source:          domain.GoVersionSourceBinary,
			TrustClass:      domain.ReleaseTrustAuthoritative,
			ArtifactSHA256:  "aabbcc",
			BinaryMember:    "bundle/bin/tool",
			BuildInfoSHA256: "ddeeff",
		}},
		Modules:         mods,
		ArtifactSHA256:  "aabbcc",
		BinaryMember:    "bundle/bin/tool",
		BuildInfoSHA256: "ddeeff",
	}
}

func depVuln(fixed string) domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GO-REL-0001",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{{
			Module:           "example.com/dep",
			AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: fixed}},
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
		}},
	}
}

func releaseProduct(mods []domain.ReleaseModule) domain.ProductSnapshot {
	p := product()
	p.ReleaseModules = mods
	p.ReleaseEvidence = resolvedReleaseEvidence(mods)
	p.ReleaseGoVersion = synthToolchain
	p.GoVersionSource = domain.GoVersionSourceBinary
	p.ReleaseEvidenceRequired = true
	return p
}

func TestReleaseModulesForSelection(t *testing.T) {
	// An authoritative graph converts to resolver modules, honoring
	// replace directives and never requiring a main flag (a release
	// binary's main path may be the command-line-arguments placeholder).
	rel := []domain.ReleaseModule{
		{Path: "example.com/dep", Version: "v1.0.0"},
		{Path: "example.com/replaced", Version: "v1.0.0",
			Replace: &domain.ReleaseModule{Path: "example.com/replaced", Version: "v1.4.0"}},
	}
	mods, auth, status := ReleaseModulesFor(releaseProduct(rel))
	if !auth || status != "RESOLVED" || len(mods) != 2 {
		t.Fatalf("authoritative graph: auth=%v status=%q mods=%v", auth, status, mods)
	}
	if mods[1].EffectiveVersion() != "v1.4.0" {
		t.Fatalf("replace must carry through: %+v", mods[1])
	}

	// No evidence at all: the axis was never requested.
	mods, auth, status = ReleaseModulesFor(product())
	if auth || mods != nil || status != "NOT_REQUESTED/ARTIFACT_NOT_REQUESTED" {
		t.Fatalf("unrequested: auth=%v status=%q", auth, status)
	}

	// A failed requested channel is named with its reason code.
	p := product()
	p.ReleaseEvidenceRequired = true
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusNotRun, ReasonCode: domain.ReleaseReasonArtifactDownloadFailed}
	mods, auth, status = ReleaseModulesFor(p)
	if auth || mods != nil || status != "NOT_RUN/ARTIFACT_DOWNLOAD_FAILED" {
		t.Fatalf("failed channel: auth=%v status=%q", auth, status)
	}

	// Supporting-only evidence never produces a release graph.
	p2 := product()
	p2.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusUnknown,
		ReasonCode: domain.ReleaseReasonSupportingOnly,
		Items: []domain.ReleaseEvidenceItem{{
			Version: synthToolchainMinor, Source: domain.GoVersionSourceDockerfile,
			TrustClass: domain.ReleaseTrustSupporting, Location: "Dockerfile",
		}},
	}
	mods, auth, status = ReleaseModulesFor(p2)
	if auth || mods != nil || status != "UNKNOWN/RELEASE_EVIDENCE_SUPPORTING_ONLY" {
		t.Fatalf("supporting-only: auth=%v status=%q", auth, status)
	}

	// Required evidence with no recorded summary is treated as a failed
	// channel, never as silence.
	p3 := product()
	p3.ReleaseEvidenceRequired = true
	if !ReleaseVersionAxisBlocked(p3) {
		t.Fatal("required release evidence with no summary must block the version axis")
	}
	if _, _, status := ReleaseModulesFor(p3); status != "NOT_RUN/RELEASE_EVIDENCE_ABSENT" {
		t.Fatalf("missing summary status = %q", status)
	}

	// A resolved channel that produced no module list (a plain binary
	// toolchain read) does not block the source-graph fallback.
	p4 := product()
	p4.ReleaseEvidenceRequired = true
	p4.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:          domain.ReleaseStatusResolved,
		SelectedVersion: synthToolchain,
		SelectedTrust:   domain.ReleaseTrustAuthoritative,
	}
	if ReleaseVersionAxisBlocked(p4) {
		t.Fatal("resolved channel without a module list must not block the fallback")
	}
}

// A failed required channel stays visible when a competing authoritative
// source resolved the toolchain: the version axis is blocked (no source
// substitution) and the axis status names the channel failure.
func TestReleaseAxisBlockedByMaskedChannelFailure(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	p := product()
	p.ReleaseGoVersion = synthToolchain
	p.GoVersionSource = domain.GoVersionSourceExplicit
	p.ReleaseEvidenceRequired = true
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:                  domain.ReleaseStatusResolved,
		SelectedVersion:         synthToolchain,
		SelectedSource:          domain.GoVersionSourceExplicit,
		SelectedTrust:           domain.ReleaseTrustAuthoritative,
		RequiredChannelFailures: []string{domain.ReleaseReasonArtifactPathMissing},
	}
	if !ReleaseVersionAxisBlocked(p) {
		t.Fatal("masked artifact failure must block the version axis")
	}
	if _, _, status := ReleaseModulesFor(p); status != "NOT_RUN/ARTIFACT_PATH_MISSING" {
		t.Fatalf("axis status = %q", status)
	}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), depVuln("1.2.0"), p)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("masked channel failure must keep the version axis UNKNOWN: %s", res.VersionAffected)
	}
	if res.VersionGraphSource != "unavailable" {
		t.Fatalf("graph source = %q", res.VersionGraphSource)
	}
	if res.ReleaseEvidenceStatus != "NOT_RUN" ||
		res.ReleaseEvidenceReason != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("release status = %q/%q", res.ReleaseEvidenceStatus, res.ReleaseEvidenceReason)
	}
}

// The authoritative release module graph wins over the source checkout's
// resolution: the artifact carries v1.4.0 while the source pins v1.0.0.
// The source version is not silently overwritten — it stays recorded as
// source-graph evidence while the release version decides applicability.
func TestReleaseGraphPreferredOverSource(t *testing.T) {
	rel := []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.4.0"}}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	res, ev, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), depVuln("1.2.0"), releaseProduct(rel))
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("release v1.4.0 is fixed (>=1.2.0): VersionAffected=%s", res.VersionAffected)
	}
	if res.ResolvedVersion != "v1.4.0" {
		t.Fatalf("resolved version must come from the release graph: %q", res.ResolvedVersion)
	}
	if res.VersionGraphSource != "release-artifact" || res.VersionGraphTrust != "AUTHORITATIVE" {
		t.Fatalf("graph provenance = %q/%q", res.VersionGraphSource, res.VersionGraphTrust)
	}
	if res.ReleaseEvidenceStatus != "RESOLVED" {
		t.Fatalf("release status = %q", res.ReleaseEvidenceStatus)
	}
	foundReleaseGraph := false
	for _, e := range ev {
		if e.ID == "EV-RELEASE-MODULES" {
			foundReleaseGraph = true
			if e.Quality != domain.QualityAuthoritative {
				t.Fatalf("release graph quality = %q", e.Quality)
			}
			if !strings.Contains(e.Content, `"v1.4.0"`) {
				t.Fatalf("release graph evidence must record v1.4.0: %s", e.Content)
			}
		}
	}
	if !foundReleaseGraph {
		t.Fatal("release module graph must be recorded as authoritative evidence")
	}
	if !hasLimitation(res.Limitations, "authoritative release module graph") {
		t.Fatalf("release-graph limitation missing: %v", res.Limitations)
	}
}

// The release graph's absence is itself a grounded negative: the module
// is not shipped even though the source checkout resolves it. This is
// authoritative absence, unlike the source graph's checkout-only view.
func TestReleaseGraphModuleAbsent(t *testing.T) {
	rel := []domain.ReleaseModule{{Path: "example.com/other", Version: "v9.9.9"}}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods)}}.
		Resolve(context.Background(), depVuln("1.2.0"), releaseProduct(rel))
	if err != nil {
		t.Fatal(err)
	}
	if res.ModulePresent != domain.ClaimFalse || res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("module absent from the release graph must be a deterministic negative: %+v", res)
	}
}

// Conflicting versions inside the authoritative graph resolve to
// UNKNOWN — never the first or the newest entry.
func TestReleaseGraphConflictingVersionsUnknown(t *testing.T) {
	rel := []domain.ReleaseModule{
		{Path: "example.com/dep", Version: "v1.0.0"},
		{Path: "example.com/dep", Version: "v1.4.0"},
	}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), depVuln("1.2.0"), releaseProduct(rel))
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("conflicting authoritative versions must stay UNKNOWN: %s", res.VersionAffected)
	}
	if res.ResolvedVersion == "v1.0.0" || res.ResolvedVersion == "v1.4.0" {
		t.Fatalf("conflict must not pick a value: %q", res.ResolvedVersion)
	}
	if !slices.Contains(res.UnresolvedModules, "example.com/dep") {
		t.Fatalf("conflicted module must be unresolved: %v", res.UnresolvedModules)
	}
	if !hasLimitation(res.Limitations, domain.ReleaseReasonConflict) {
		t.Fatalf("conflict must name its reason code: %v", res.Limitations)
	}
}

// A requested release channel that failed must not fall back to the
// source graph: the version axis stays UNKNOWN and the package/build
// closure still resolves independently from source evidence.
func TestArtifactBlockedKeepsVersionsUnknown(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	p := product()
	p.ReleaseEvidenceRequired = true
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusNotRun, ReasonCode: domain.ReleaseReasonArtifactDownloadFailed}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), depVuln("1.2.0"), p)
	if err != nil {
		t.Fatal(err)
	}
	// The source graph says the module is linked, but its v1.0.0 is not
	// release evidence: the release version stays undecidable.
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("blocked artifact must leave the version axis UNKNOWN: %s", res.VersionAffected)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("source package closure still resolves independently: %s", res.PackagePresent)
	}
	if res.ResolvedVersion != "" {
		t.Fatalf("a source version must never be reported as the release version: %q", res.ResolvedVersion)
	}
	if !slices.Contains(res.UnresolvedModules, "example.com/dep") ||
		!slices.Contains(res.PendingModules, "example.com/dep") {
		t.Fatalf("blocked module must stay unresolved+pending: %v / %v",
			res.UnresolvedModules, res.PendingModules)
	}
	if res.ReleaseEvidenceStatus != "NOT_RUN" || res.ReleaseEvidenceReason != domain.ReleaseReasonArtifactDownloadFailed {
		t.Fatalf("release status = %q/%q", res.ReleaseEvidenceStatus, res.ReleaseEvidenceReason)
	}
	if res.VersionGraphSource != "unavailable" {
		t.Fatalf("graph source = %q", res.VersionGraphSource)
	}
	if !hasLimitation(res.Limitations, "cannot substitute") {
		t.Fatalf("fail-closed limitation missing: %v", res.Limitations)
	}
}

// Under a blocked channel, a module absent from the source graph is not
// evidence of absence from the release: ModulePresent stays UNKNOWN
// instead of collapsing to FALSE.
func TestArtifactBlockedAbsenceNotFalse(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":[]}`
	p := product()
	p.ReleaseEvidenceRequired = true
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusNotRun, ReasonCode: domain.ReleaseReasonArtifactNoGoBinary}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), depVuln("1.2.0"), p)
	if err != nil {
		t.Fatal(err)
	}
	if res.ModulePresent == domain.ClaimFalse {
		t.Fatalf("blocked channel must not assert absence: ModulePresent=%s", res.ModulePresent)
	}
	if !slices.Contains(res.UnresolvedModules, "example.com/dep") {
		t.Fatalf("absent-but-blocked module is still unresolved: %v", res.UnresolvedModules)
	}
}

// Two advisory entries evaluated independently under the release graph:
// the fixed one drops out, the affected one selects.
func TestAffectedResolveMultiEntryReleaseGraph(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-REL-0002",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	// Release graph: dep fixed at v1.4.0, other still vulnerable at v1.5.0.
	rel := []domain.ReleaseModule{
		{Path: "example.com/dep", Version: "v1.4.0"},
		{Path: "example.com/other", Version: "v1.5.0"},
	}
	// Source disagrees on dep (v1.0.0 vulnerable) — release wins.
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v1.5.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln","example.com/other/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep"},"Deps":[]}
{"ImportPath":"example.com/other/vuln","Module":{"Path":"example.com/other"},"Deps":[]}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, releaseProduct(rel))
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("vulnerable entry must select: VersionAffected=%s", res.VersionAffected)
	}
	if res.SelectedModule != "example.com/other" || res.ResolvedVersion != "v1.5.0" {
		t.Fatalf("resolution must pin the affected entry: %s@%s", res.SelectedModule, res.ResolvedVersion)
	}
	if !slices.Contains(res.VersionAffectedModules, "example.com/other") ||
		slices.Contains(res.VersionAffectedModules, "example.com/dep") {
		t.Fatalf("version membership must reflect release versions: %v", res.VersionAffectedModules)
	}
}

// The authoritative toolchain resolves stdlib applicability from build
// info — the supporting Dockerfile declaration plays no role.
func TestStdlibResolvedByReleaseEvidence(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-REL-0003",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{{
			Module:           "stdlib",
			AffectedVersions: []domain.VersionRange{{Introduced: "1.43.0", Fixed: "1.43.6"}},
			AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
		}},
	}
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http"]}
{"ImportPath":"net/http","Deps":[]}`
	p := releaseProduct(nil) // no release modules: toolchain resolved, graph empty
	p.ReleaseEvidence.Items = append(p.ReleaseEvidence.Items, domain.ReleaseEvidenceItem{
		Version: synthToolchainSup, Source: domain.GoVersionSourceDockerfile,
		TrustClass: domain.ReleaseTrustSupporting, Location: "Dockerfile",
	})
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, p)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("%s is outside 1.43.0-1.43.6: VersionAffected=%s", synthToolchain, res.VersionAffected)
	}
	if res.ResolvedVersion != synthToolchain {
		t.Fatalf("stdlib resolves against the release toolchain: %q", res.ResolvedVersion)
	}
}

// Supporting-only evidence (a Dockerfile pin, no authoritative item)
// leaves stdlib UNKNOWN — and the release axis stays on the source graph
// for module versions, the non-artifact behavior unchanged.
func TestStdlibUnknownWithSupportingOnly(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-REL-0004",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{{
			Module:           "stdlib",
			AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.19.3"}},
			AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
		}},
	}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http"]}
{"ImportPath":"net/http","Deps":[]}`
	p := product()
	p.GoModDirective = "1.23"
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusUnknown,
		ReasonCode: domain.ReleaseReasonSupportingOnly,
		Items: []domain.ReleaseEvidenceItem{{
			Version: synthToolchainSup, Source: domain.GoVersionSourceDockerfile,
			TrustClass: domain.ReleaseTrustSupporting, Location: "Dockerfile",
		}},
	}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, p)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("a Dockerfile pin cannot ground stdlib applicability: %s", res.VersionAffected)
	}
	if !slices.Contains(res.UnresolvedModules, "stdlib") {
		t.Fatalf("stdlib entry must stay unresolved: %v", res.UnresolvedModules)
	}
	if res.VersionGraphSource != "source-snapshot" ||
		res.ReleaseEvidenceReason != domain.ReleaseReasonSupportingOnly {
		t.Fatalf("provenance = %q reason=%q", res.VersionGraphSource, res.ReleaseEvidenceReason)
	}
	if !hasLimitation(res.Limitations, domain.ReleaseReasonSupportingOnly) {
		t.Fatalf("supporting-only limitation missing: %v", res.Limitations)
	}
}

// When the release axis is not authoritative, module versions still
// resolve from the source graph exactly as before: supporting evidence
// present or absent, the previous behavior is preserved.
func TestSourceGraphFallbackUnchanged(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	p := product()
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusUnknown, ReasonCode: domain.ReleaseReasonSupportingOnly}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods)}}.
		Resolve(context.Background(), depVuln("1.2.0"), p)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("source graph still resolves module versions: %s", res.VersionAffected)
	}
	if res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("source version reported: %q", res.ResolvedVersion)
	}
	if res.VersionGraphSource != "source-snapshot" {
		t.Fatalf("graph source = %q", res.VersionGraphSource)
	}
}

// Conflicting authoritative toolchain versions leave the stdlib entry
// undecidable — CONFLICTED never picks a value.
func TestStdlibConflictedReleaseVersion(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-REL-0005",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{{
			Module:           "stdlib",
			AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.43.0"}},
			AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
		}},
	}
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":[]}`
	p := product()
	p.ReleaseEvidenceRequired = true
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusConflicted,
		ReasonCode: domain.ReleaseReasonConflict,
		Items: []domain.ReleaseEvidenceItem{
			{Version: synthToolchain, Source: domain.GoVersionSourceBinary, TrustClass: domain.ReleaseTrustAuthoritative},
			{Version: synthToolchainAlt, Source: domain.GoVersionSourceExplicit, TrustClass: domain.ReleaseTrustAuthoritative},
		},
	}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, p)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("conflicted authoritative toolchain must stay UNKNOWN: %s", res.VersionAffected)
	}
	if res.ResolvedVersion != "" {
		t.Fatalf("conflict must not select a toolchain: %q", res.ResolvedVersion)
	}
	if !hasLimitation(res.Limitations, domain.ReleaseReasonConflict) {
		t.Fatalf("conflict limitation missing: %v", res.Limitations)
	}
}

// Axis independence: the authoritative release module graph decides the
// third-party entry's version from what the shipped artifact carries,
// while the stdlib entry stays UNKNOWN because the release Go toolchain
// is a separate axis that only supporting declarations cannot ground.
func TestReleaseGraphResolvesModuleWhileStdlibToolchainUnknown(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-REL-0006",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.19.3"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
			},
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
		},
	}
	rel := []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.1.0"}}
	// The source checkout resolves v1.0.0 (also inside the range): the
	// release graph must still supply the reported version.
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http","example.com/dep/vuln"]}
{"ImportPath":"net/http","Deps":[]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	p := product()
	p.ReleaseModules = rel
	p.ReleaseEvidenceRequired = true
	// Only a SUPPORTING declaration: the release toolchain is UNKNOWN
	// while the operator-supplied module graph is authoritative.
	p.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusUnknown,
		ReasonCode: domain.ReleaseReasonSupportingOnly,
		Modules:    rel,
		Items: []domain.ReleaseEvidenceItem{{
			Version: synthToolchainSup, Source: domain.GoVersionSourceDockerfile,
			TrustClass: domain.ReleaseTrustSupporting, Location: "Dockerfile",
		}},
	}
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, p)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionGraphSource != "release-artifact" ||
		res.VersionGraphTrust != string(domain.ReleaseTrustAuthoritative) {
		t.Fatalf("graph provenance = %q/%q, want the release graph",
			res.VersionGraphSource, res.VersionGraphTrust)
	}
	if res.VersionAffected != domain.ClaimTrue ||
		res.SelectedModule != "example.com/dep" ||
		res.ResolvedVersion != "v1.1.0" {
		t.Fatalf("third-party entry did not resolve from the release graph: %+v", res)
	}
	if !slices.Contains(res.VersionAffectedModules, "example.com/dep") ||
		slices.Contains(res.VersionAffectedModules, "stdlib") {
		t.Fatalf("version membership = %v, want only the release-graph entry", res.VersionAffectedModules)
	}
	if !slices.Contains(res.UnresolvedModules, "stdlib") {
		t.Fatalf("stdlib entry must stay UNKNOWN without release toolchain evidence: %v", res.UnresolvedModules)
	}
	// The supporting Dockerfile pin must never become a stdlib version.
	for _, sel := range res.SelectedModules {
		if strings.HasPrefix(sel, "stdlib@") {
			t.Fatalf("stdlib acquired a supporting-declaration version: %v", res.SelectedModules)
		}
	}
	if !hasLimitation(res.Limitations, "authoritative release module graph") {
		t.Fatalf("release-graph limitation missing: %v", res.Limitations)
	}
	if !hasLimitation(res.Limitations, "no authoritative toolchain version") {
		t.Fatalf("stdlib toolchain limitation missing: %v", res.Limitations)
	}
	// Regression: the toolchain limitation must name the toolchain axis,
	// never the module axis. An authoritative release module graph leaves
	// the toolchain UNKNOWN; the mixed status must not read RESOLVED.
	if hasLimitation(res.Limitations, "unresolved (RESOLVED)") {
		t.Fatalf("stdlib limitation names the module-axis status: %v", res.Limitations)
	}
	if !hasLimitation(res.Limitations, "release toolchain unresolved (UNKNOWN/RELEASE_EVIDENCE_SUPPORTING_ONLY)") {
		t.Fatalf("stdlib limitation must name the toolchain-axis status: %v", res.Limitations)
	}
}
