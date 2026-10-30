package rootcause

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// F12 — TestResolverRequestsAndAccountsForEveryFixLocator.
//
// The measured defect: root-cause resolution fetched the first patch that
// worked and stopped. Every other locator the record declared then became a
// missing-artifact obligation, so a provider holding all of them was never asked
// for the rest, every multi-locator record blocked, and available material was
// labelled PROOF_ARTIFACT_MISSING — a claim of unavailability nobody had
// established.
//
// The contract pinned here:
//
//   - every distinct declared locator is requested from the configured
//     captured-artifact provider, exactly once each, before availability is
//     concluded;
//   - every relevant available artifact is inventoried, so changed functions
//     from all of them appear instead of only the first artifact's;
//   - the gap codes state what was established: an artifact the provider was
//     asked for and does not hold is the only PROOF_ARTIFACT_MISSING claim, an
//     acquisition the provider does not implement is a typed input gap, and
//     available-but-unmapped or applicability-unknown material is code-owned
//     analyzer work;
//   - duplicate locators, alternative release lines and sequential artifacts are
//     accounted without inventing a patch series.

const f12Module = "github.com/example/lib"

// f12SelectedSource writes the selected version's captured source tree — the
// vendored module the recorded build uses — so coordinate resolution never
// touches the host module cache or the network.
func f12SelectedSource(t *testing.T) *goanalysis.Index {
	t.Helper()
	root := selectedSourceFixture(t, f12Module, "v1.4.0", map[string]string{
		"internal/path/path.go": "package path\n\nfunc Clean(p string) string { return p }\n",
		"internal/id/id.go":     "package id\n\nfunc Parse(s string) string { return s }\n",
	})
	return &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}}
}

// f12Case records the selected module coordinate patch coordinates resolve
// against.
func f12Case() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		Affected: &domain.AffectedResult{
			SelectedModule:  f12Module,
			SelectedModules: []string{f12Module},
			ResolvedVersion: "v1.4.0",
		},
	}
}

func f12Vuln(urls ...string) domain.Vulnerability {
	v := domain.Vulnerability{ID: "CVE-F12", Module: f12Module}
	for _, u := range urls {
		v.References = append(v.References, domain.Reference{Type: "FIX", URL: u})
	}
	return v
}

const (
	f12LocPath  = "https://github.com/example/lib/commit/1111aaaa"
	f12LocID    = "https://github.com/example/lib/commit/2222bbbb"
	f12LocNext  = "https://github.com/example/lib/commit/3333cccc"
	f12LocPR    = "https://github.com/example/lib/pull/42"
	f12LocPlain = "https://github.com/example/lib/commit/5555eeee"
)

// f12PathPatch changes internal/path/path.go, which the selected source has.
const f12PathPatch = `diff --git a/internal/path/path.go b/internal/path/path.go
index 111..222 100644
--- a/internal/path/path.go
+++ b/internal/path/path.go
@@ -3,3 +3,4 @@ func Clean(p string) string {
-	return p
+	if p == "" {
+		return ""
+	}
+	return p
`

// f12IDPatch is an alternative representation of the same fix: a different file
// of the selected source, changed by the same advisory.
const f12IDPatch = `diff --git a/internal/id/id.go b/internal/id/id.go
index 333..444 100644
--- a/internal/id/id.go
+++ b/internal/id/id.go
@@ -3,3 +3,4 @@ func Parse(s string) string {
-	return s
+	if s == "" {
+		return "invalid"
+	}
+	return s
`

// f12ReleaseLinePatch changes a path the selected version does not have: the fix
// as it was written on another release line.
const f12ReleaseLinePatch = `diff --git a/cmd/legacy/server.go b/cmd/legacy/server.go
index 555..666 100644
--- a/cmd/legacy/server.go
+++ b/cmd/legacy/server.go
@@ -40,3 +40,4 @@ func CreateDirectories(cfg Config) error {
-	if err := os.Chmod(cfg.Root, 0o711); err != nil {
+	if err := os.Chmod(cfg.Root, 0o700); err != nil {
`

// f12FollowerPatch touches the same file as f12PathPatch in a hunk whose line
// numbers only mean anything once the predecessor hunk has been applied. Nothing
// in the record says the two artifacts are one ordered series.
const f12FollowerPatch = `diff --git a/internal/path/path.go b/internal/path/path.go
index 222..777 100644
--- a/internal/path/path.go
+++ b/internal/path/path.go
@@ -9,9 +9,10 @@ func CleanTrailing(p string) string {
-	return p
+	return strings.TrimRight(p, "/")
`

const f12DocPatch = `diff --git a/README.md b/README.md
index 888..999 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # lib
+Cleaning is now strict.
`

// f12NotADiff captures bytes that are not a unified diff at all — an advisory
// page rather than the patch a FIX-typed reference promised.
const f12NotADiff = "<html><body>Commit 4444dddd is available upstream.</body></html>\n"

// recordingProvider records every locator the resolver asks for, so a test can
// assert that accounting requested each distinct locator exactly once.
type recordingProvider struct {
	inner    fix.ArtifactProvider
	requests []string
}

func (p *recordingProvider) Acquire(ctx context.Context, ref fix.Reference) domain.FixArtifact {
	p.requests = append(p.requests, ref.URL)
	return p.inner.Acquire(ctx, ref)
}

// unsupportedProvider answers one locator the way a provider that does not
// implement its acquisition form would: nothing is measured either way.
type unsupportedProvider struct {
	inner   fix.ArtifactProvider
	locator string
}

func (p unsupportedProvider) Acquire(ctx context.Context, ref fix.Reference) domain.FixArtifact {
	if ref.URL != p.locator {
		return p.inner.Acquire(ctx, ref)
	}
	return domain.FixArtifact{
		Locator:    ref.URL,
		Kind:       ref.Kind,
		Provenance: "test provider",
		Outcome:    domain.FixArtifactUnsupportedAcquisition,
		Detail:     "the configured provider does not implement this locator's acquisition form",
	}
}

func f12Resolve(t *testing.T, source *goanalysis.Index, provider fix.ArtifactProvider,
	v domain.Vulnerability) *domain.RootCauseModel {
	t.Helper()
	model, _, err := Resolver{Fix: fix.Resolver{}, Patch: provider, Source: source}.
		Resolve(context.Background(), f12Case(), v)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if model == nil {
		t.Fatal("resolve returned no model")
	}
	if err := domain.ValidateFixArtifacts(model.FixArtifacts); err != nil {
		t.Fatalf("artifact inventory is not a valid record: %v (%+v)", err, model.FixArtifacts)
	}
	return model
}

func f12Record(t *testing.T, model *domain.RootCauseModel, locator string) domain.FixArtifact {
	t.Helper()
	for _, a := range model.FixArtifacts {
		if a.Locator == locator {
			return a
		}
	}
	t.Fatalf("locator %s has no artifact record: %+v", locator, model.FixArtifacts)
	return domain.FixArtifact{}
}

// f12Gaps returns the gaps with the given owner and code.
func f12Gaps(model *domain.RootCauseModel, owner domain.GapOwner, code domain.GapCode) []domain.AnalysisGap {
	var out []domain.AnalysisGap
	for _, g := range model.AnalysisGaps {
		if g.Owner == owner && g.Code == code {
			out = append(out, g)
		}
	}
	return out
}

func f12Symbols(model *domain.RootCauseModel) []string {
	var out []string
	for _, rc := range model.Candidates() {
		out = append(out, rc.Symbol)
	}
	return out
}

func f12CountSymbol(model *domain.RootCauseModel, symbol string) int {
	n := 0
	for _, s := range f12Symbols(model) {
		if s == symbol {
			n++
		}
	}
	return n
}

func f12RequireSymbol(t *testing.T, model *domain.RootCauseModel, symbol string) {
	t.Helper()
	if f12CountSymbol(model, symbol) == 0 {
		t.Fatalf("symbol %s was not inventoried: candidates=%v", symbol, f12Symbols(model))
	}
}

// f12RequireNoMissingClaim asserts that nothing in the model claims a fix
// artifact is missing.
func f12RequireNoMissingClaim(t *testing.T, model *domain.RootCauseModel) {
	t.Helper()
	if gaps := f12Gaps(model, domain.GapOwnerProof, domain.GapProofArtifactMissing); len(gaps) > 0 {
		t.Fatalf("gaps=%+v — an available artifact was reported as missing bytes", gaps)
	}
}

// f12RequireNoSeriesClaim asserts the resolver did not invent an ordered patch
// series out of independent references.
func f12RequireNoSeriesClaim(t *testing.T, model *domain.RootCauseModel) {
	t.Helper()
	for _, g := range model.AnalysisGaps {
		if strings.Contains(strings.ToLower(g.Message), "series") {
			t.Fatalf("gap=%+v — the resolver claimed a patch series no evidence establishes", g)
		}
	}
	for _, l := range model.Limitations {
		if strings.Contains(strings.ToLower(l), "series") {
			t.Fatalf("limitation=%q — the resolver claimed a patch series no evidence establishes", l)
		}
	}
}

// A provider holding every artifact must be asked for every artifact, and every
// captured artifact that describes the selected version must be inventoried. The
// defect stopped at the first patch and called the rest missing.
func TestResolverRequestsAndAccountsForEveryFixLocator(t *testing.T) {
	t.Run("requests and inventories every available artifact", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPath: f12PathPatch,
			f12LocID:   f12IDPatch,
		}}}
		v := f12Vuln(f12LocPath, f12LocID)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		want := []string{f12LocPath, f12LocID}
		if strings.Join(provider.requests, ",") != strings.Join(want, ",") {
			t.Fatalf("requested=%v, want every distinct locator exactly once: %v", provider.requests, want)
		}
		if len(model.FixArtifacts) != len(want) {
			t.Fatalf("artifacts=%+v — want one record per declared locator", model.FixArtifacts)
		}
		for _, locator := range want {
			record := f12Record(t, model, locator)
			if record.Outcome != domain.FixArtifactComplete {
				t.Fatalf("artifact=%+v — a captured, applicable artifact must be COMPLETE", record)
			}
			if record.Digest == "" || record.Size == 0 || record.Bytes == "" {
				t.Fatalf("artifact=%+v — complete bytes must be recorded with their digest", record)
			}
			if len(record.Coordinates) != 1 {
				t.Fatalf("artifact=%+v — the changed coordinate must be inventoried", record)
			}
		}
		// Every artifact contributes: the first one's functions no longer
		// terminate the inventory.
		f12RequireSymbol(t, model, "Clean")
		f12RequireSymbol(t, model, "Parse")
		f12RequireNoMissingClaim(t, model)
		f12RequireNoSeriesClaim(t, model)
		if model.Status != domain.RootCauseResolved {
			t.Fatalf("status=%s — the patch-derived model must resolve: %+v", model.Status, model.Limitations)
		}
	})

	t.Run("duplicate locators are requested once and keep their provenance", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPath: f12PathPatch,
			f12LocPR:   f12PathPatch, // the same bytes under a second locator
		}}}
		v := f12Vuln(f12LocPath, f12LocPR, f12LocPath)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		want := []string{f12LocPath, f12LocPR}
		if strings.Join(provider.requests, ",") != strings.Join(want, ",") {
			t.Fatalf("requested=%v, want the distinct locators once each and in order: %v", provider.requests, want)
		}
		if len(model.FixArtifacts) != 2 {
			t.Fatalf("artifacts=%+v — a repeated locator must be one record", model.FixArtifacts)
		}
		primary := f12Record(t, model, f12LocPath)
		duplicate := f12Record(t, model, f12LocPR)
		if duplicate.DuplicateOf != f12LocPath {
			t.Fatalf("artifact=%+v — the duplicate must name the locator that recorded the bytes", duplicate)
		}
		if duplicate.Digest != primary.Digest || duplicate.Provenance == "" {
			t.Fatalf("duplicate=%+v primary=%+v — deduplicated bytes keep the digest and provenance", duplicate, primary)
		}
		if duplicate.Bytes != "" {
			t.Fatalf("duplicate=%+v — byte-identical material must not be recorded twice", duplicate)
		}
		if n := f12CountSymbol(model, "Clean"); n != 1 {
			t.Fatalf("Clean appears %d times: %v — one body is inventoried once", n, f12Symbols(model))
		}
		f12RequireNoMissingClaim(t, model)
	})

	t.Run("one unavailable artifact yields exactly one named missing-proof obligation", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPath: f12PathPatch,
			f12LocID:   f12IDPatch,
			// f12LocNext is not held by the configured inputs.
		}}}
		v := f12Vuln(f12LocPath, f12LocID, f12LocNext)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		want := []string{f12LocPath, f12LocID, f12LocNext}
		if strings.Join(provider.requests, ",") != strings.Join(want, ",") {
			t.Fatalf("requested=%v, want every locator requested before availability is concluded: %v",
				provider.requests, want)
		}
		missing := f12Gaps(model, domain.GapOwnerProof, domain.GapProofArtifactMissing)
		if len(missing) != 1 {
			t.Fatalf("gaps=%+v — exactly the unavailable artifact may ground a missing-bytes claim", missing)
		}
		if !strings.Contains(missing[0].Message, f12LocNext) {
			t.Fatalf("gap=%+v — the missing-proof obligation must name the unavailable locator", missing[0])
		}
		for _, other := range []string{f12LocPath, f12LocID} {
			if strings.Contains(missing[0].Message, other) {
				t.Fatalf("gap=%+v — it must name only the unavailable locator, not %s", missing[0], other)
			}
		}
		if record := f12Record(t, model, f12LocNext); record.Outcome != domain.FixArtifactUnavailable {
			t.Fatalf("artifact=%+v — the provider established no bytes for this locator", record)
		}
		// The unavailable locator does not stop the others from being
		// inventoried.
		f12RequireSymbol(t, model, "Clean")
		f12RequireSymbol(t, model, "Parse")
	})

	t.Run("available but unmapped material is code-owned", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPath: f12PathPatch,
			f12LocNext: f12ReleaseLinePatch, // another release line's fix
		}}}
		v := f12Vuln(f12LocPath, f12LocNext)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		unmapped := f12Record(t, model, f12LocNext)
		if unmapped.Outcome != domain.FixArtifactUnmapped {
			t.Fatalf("artifact=%+v — the artifact was captured but does not describe the selected version", unmapped)
		}
		if len(unmapped.Coordinates) != 1 || unmapped.Coordinates[0] != "cmd/legacy/server.go" {
			t.Fatalf("artifact=%+v — the inventory must record what the artifact changes", unmapped)
		}
		codeOwned := f12Gaps(model, domain.GapOwnerCode, domain.GapRootCauseUnresolved)
		if len(codeOwned) == 0 {
			t.Fatalf("gaps=%+v — unmapped material is analyzer work, not missing bytes", model.AnalysisGaps)
		}
		var named bool
		for _, g := range codeOwned {
			named = named || strings.Contains(g.Message, f12LocNext)
		}
		if !named {
			t.Fatalf("gaps=%+v — a code-owned obligation must name the unmapped artifact", codeOwned)
		}
		f12RequireNoMissingClaim(t, model)
		f12RequireSymbol(t, model, "Clean")
		f12RequireNoSeriesClaim(t, model)
	})

	t.Run("no selected source leaves applicability unknown", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPath: f12PathPatch,
		}}}
		v := f12Vuln(f12LocPath)
		// No selected-source index: nothing established whether the captured
		// artifact describes the analysed version.
		model := f12Resolve(t, nil, provider, v)

		record := f12Record(t, model, f12LocPath)
		if record.Outcome != domain.FixArtifactApplicabilityUnknown {
			t.Fatalf("artifact=%+v — without a selected source applicability cannot be established", record)
		}
		if record.Digest == "" {
			t.Fatalf("artifact=%+v — the bytes were captured and must be recorded", record)
		}
		if len(f12Gaps(model, domain.GapOwnerCode, domain.GapRootCauseUnresolved)) == 0 {
			t.Fatalf("gaps=%+v — unknown applicability is analyzer work", model.AnalysisGaps)
		}
		f12RequireNoMissingClaim(t, model)
	})

	t.Run("bytes that are not a diff leave applicability unknown", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPlain: f12NotADiff,
		}}}
		v := f12Vuln(f12LocPlain)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		record := f12Record(t, model, f12LocPlain)
		if record.Outcome != domain.FixArtifactApplicabilityUnknown {
			t.Fatalf("artifact=%+v — captured bytes without a unified diff cannot be inventoried", record)
		}
		if record.Digest == "" {
			t.Fatalf("artifact=%+v — the capture must be recorded even when unusable", record)
		}
		f12RequireNoMissingClaim(t, model)
	})

	t.Run("unsupported acquisition is a typed input gap", func(t *testing.T) {
		provider := unsupportedProvider{
			inner:   fix.CapturedProvider{Artifacts: map[string]string{f12LocID: f12IDPatch}},
			locator: f12LocPath,
		}
		v := f12Vuln(f12LocPath, f12LocID)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		record := f12Record(t, model, f12LocPath)
		if record.Outcome != domain.FixArtifactUnsupportedAcquisition {
			t.Fatalf("artifact=%+v — the provider does not implement this locator's form", record)
		}
		if len(f12Gaps(model, domain.GapOwnerInput, domain.GapInputResolutionFailed)) == 0 {
			t.Fatalf("gaps=%+v — an unsupported acquisition is an input capability gap", model.AnalysisGaps)
		}
		f12RequireNoMissingClaim(t, model)
		// The remaining locator is still acquired and inventoried.
		f12RequireSymbol(t, model, "Parse")
	})

	t.Run("sequential artifacts are accounted without a patch series", func(t *testing.T) {
		provider := &recordingProvider{inner: fix.CapturedProvider{Artifacts: map[string]string{
			f12LocPath: f12PathPatch,
			f12LocNext: f12FollowerPatch,
		}}}
		v := f12Vuln(f12LocPath, f12LocNext)
		model := f12Resolve(t, f12SelectedSource(t), provider, v)

		want := []string{f12LocPath, f12LocNext}
		if strings.Join(provider.requests, ",") != strings.Join(want, ",") {
			t.Fatalf("requested=%v, want both locators requested: %v", provider.requests, want)
		}
		first := f12Record(t, model, f12LocPath)
		second := f12Record(t, model, f12LocNext)
		if first.Digest == second.Digest || second.DuplicateOf != "" {
			t.Fatalf("first=%+v second=%+v — distinct artifacts are not duplicates", first, second)
		}
		for _, record := range []domain.FixArtifact{first, second} {
			if record.Outcome != domain.FixArtifactComplete {
				t.Fatalf("artifact=%+v — both artifacts change a coordinate of the selected source", record)
			}
		}
		// Both are inventoried independently: neither is treated as a
		// predecessor or successor of the other.
		f12RequireSymbol(t, model, "Clean")
		f12RequireSymbol(t, model, "CleanTrailing")
		f12RequireNoMissingClaim(t, model)
		f12RequireNoSeriesClaim(t, model)
	})

	t.Run("no configured provider states absence explicitly", func(t *testing.T) {
		v := f12Vuln(f12LocPath)
		model, _, err := Resolver{Fix: fix.Resolver{}}.Resolve(context.Background(), f12Case(), v)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(model.FixArtifacts) != 0 {
			t.Fatalf("artifacts=%+v — no provider means no acquisition record", model.FixArtifacts)
		}
		if len(f12Gaps(model, domain.GapOwnerInput, domain.GapInputResolutionFailed)) == 0 {
			t.Fatalf("gaps=%+v — an unconfigured provider is an input gap", model.AnalysisGaps)
		}
		f12RequireNoMissingClaim(t, model)
	})
}
