package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/repository"
)

// sourceFixture writes one file under root.
func sourceFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readSourceFixture(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// recordedBuild is the snapshot a real run records for a fixture: the replace
// directives and workspace mode come from the snapshot adapter, not from the
// test's expectations.
func recordedBuild(t *testing.T, root, workFile string) domain.ProductSnapshot {
	t.Helper()
	if workFile == "" {
		workFile = domain.GoWorkOff
	}
	return domain.ProductSnapshot{
		Repository:        root,
		GOOS:              "linux",
		GOARCH:            "amd64",
		VendorMode:        regularFileExists(filepath.Join(root, "vendor", "modules.txt")),
		GoWorkFile:        workFile,
		ReplaceDirectives: repository.ReplaceDirectives(root, workFile),
	}
}

func regularFileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// F9: a module replacement must bind the analyzed candidate to the
// replacement's own source. Caching both the declared original and the fork is
// not enough — only the fork carries the linked implementation, and the
// published original's bytes (including the original's bytes at the fork's
// version) must never answer.
func TestEffectiveReplacementOwnsBindingSource(t *testing.T) {
	t.Run("module_replacement_reads_the_fork", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig => example.com/fork v1.2.0
`)
		// The declared coordinate, the fork's version under the original
		// path, and the fork itself all exist. Only the fork carries the
		// linked implementation.
		sourceFixture(t, cache, "example.com/orig@v1.0.0/pkg/vuln.go",
			"package pkg\n\n// PUBLISHED ORIGINAL\nfunc Vulnerable() error { return nil }\n")
		sourceFixture(t, cache, "example.com/orig@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// WRONG SOURCE: original bytes at the fork version\nfunc Vulnerable() error { return nil }\n")
		sourceFixture(t, cache, "example.com/fork@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// FORK IMPLEMENTATION\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		// The affected chain resolves the declared coordinate against the
		// recorded build and records the effective one.
		source, err := ix.ResolveModuleSource("example.com/orig", "v1.0.0", "v1.2.0")
		if err != nil {
			t.Fatalf("resolve the replaced module: %v", err)
		}
		sel := source.Selection
		if sel.DeclaredModule != "example.com/orig" || sel.DeclaredVersion != "v1.0.0" {
			t.Fatalf("selection=%+v — want the declared coordinate example.com/orig@v1.0.0", sel)
		}
		if sel.SourceKind != domain.ModuleSourceModuleCache ||
			sel.EffectiveModule != "example.com/fork" || sel.EffectiveVersion != "v1.2.0" {
			t.Fatalf("selection=%+v — want the replacement coordinate example.com/fork@v1.2.0", sel)
		}
		if sel.SourceRoot != "example.com/fork@v1.2.0" {
			t.Fatalf("source root=%q — want the replacement's module-cache coordinate", sel.SourceRoot)
		}
		if len(sel.Replacements) != 1 || !strings.Contains(sel.Replacements[0].New, "example.com/fork") {
			t.Fatalf("replacements=%+v — want the applied replace directive recorded", sel.Replacements)
		}
		if want := filepath.Join(cache, "example.com", "fork@v1.2.0"); source.Dir != want {
			t.Fatalf("source dir=%q — want the fork's module-cache entry %q", source.Dir, want)
		}

		// The binding/census reader resolves the same coordinate, so the
		// candidate reads the fork — never the original's bytes.
		got, exists, err := ix.SelectedModuleCoordinate("example.com/orig", "v1.2.0", "pkg/vuln.go")
		if err != nil || !exists {
			t.Fatalf("coordinate in the replacement source: exists=%v err=%v", exists, err)
		}
		body := readSourceFixture(t, got.Dir, "pkg/vuln.go")
		if !strings.Contains(body, "FORK IMPLEMENTATION") {
			t.Fatalf("read %q — the selected source is not the fork", body)
		}
		if strings.Contains(body, "PUBLISHED ORIGINAL") || strings.Contains(body, "WRONG SOURCE") {
			t.Fatalf("read %q — the published original answered for a replaced module", body)
		}
	})

	t.Run("version_pinned_replacement_applies_only_to_its_declared_version", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig v1.0.0 => example.com/fork v1.2.0
`)
		sourceFixture(t, cache, "example.com/fork@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// FORK IMPLEMENTATION\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		source, err := ix.ResolveModuleSource("example.com/orig", "v1.0.0", "v1.2.0")
		if err != nil {
			t.Fatalf("resolve the version-pinned replacement: %v", err)
		}
		if source.Selection.EffectiveModule != "example.com/fork" ||
			source.Selection.EffectiveVersion != "v1.2.0" {
			t.Fatalf("selection=%+v — want the pinned replacement's coordinate", source.Selection)
		}
		// Without the declared version the rule cannot be established, so the
		// resolver refuses instead of guessing (or reading the original).
		if _, err := ix.ResolveModuleSource("example.com/orig", "", "v1.2.0"); err == nil {
			t.Fatal("an unestablished version-pinned replacement resolved a source")
		}
		// A recorded selection carries the declared version, so the binding
		// reader applies the rule exactly as the build did.
		_, exists, err := ix.SelectedModuleCoordinateFor(source.Selection, "pkg/vuln.go")
		if err != nil || !exists {
			t.Fatalf("coordinate for the recorded selection: exists=%v err=%v", exists, err)
		}
	})

	t.Run("missing_fork_is_a_typed_failure", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig => example.com/fork v1.2.0
`)
		// The declared original and even original bytes at the replacement's
		// version are cached; the fork is absent. Neither may answer.
		sourceFixture(t, cache, "example.com/orig@v1.0.0/pkg/vuln.go",
			"package pkg\n\n// PUBLISHED ORIGINAL\nfunc Vulnerable() error { return nil }\n")
		sourceFixture(t, cache, "example.com/orig@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// WRONG SOURCE: original bytes at the fork version\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		source, err := ix.SelectedModuleSource("example.com/orig", "v1.2.0")
		if err == nil {
			t.Fatalf("resolved %+v — a missing replacement source must not resolve", source)
		}
		if !domain.IsModuleSourceFailure(err, domain.ModuleSourceUnavailable) {
			t.Fatalf("err=%v — want a typed SOURCE_UNAVAILABLE input failure", err)
		}
		if source.Dir != "" {
			t.Fatalf("source dir=%q — a failed resolution must not carry a directory", source.Dir)
		}
		_, exists, coordErr := ix.SelectedModuleCoordinate("example.com/orig", "v1.2.0", "pkg/vuln.go")
		if exists || coordErr == nil {
			t.Fatalf("coordinate: exists=%v err=%v — must fail, never fall back to the original", exists, coordErr)
		}
	})

	t.Run("confined_local_replacement_reads_captured_bytes", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig => ./third_party/orig
`)
		sourceFixture(t, root, "third_party/orig/go.mod", "module example.com/orig\n\ngo 1.21\n")
		sourceFixture(t, root, "third_party/orig/pkg/vuln.go",
			"package pkg\n\n// LOCAL REPLACEMENT BYTES\nfunc Vulnerable() error { return nil }\n")
		// The module cache holds the published original: it must not answer.
		sourceFixture(t, cache, "example.com/orig@v1.0.0/pkg/vuln.go",
			"package pkg\n\n// PUBLISHED ORIGINAL\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		source, err := ix.SelectedModuleSource("example.com/orig", "v1.0.0")
		if err != nil {
			t.Fatalf("resolve the local replacement: %v", err)
		}
		sel := source.Selection
		if sel.SourceKind != domain.ModuleSourceLocalReplacement {
			t.Fatalf("selection=%+v — want a local-replacement source", sel)
		}
		if sel.LocalReplacement == nil || sel.LocalReplacement.Directory != "third_party/orig" {
			t.Fatalf("selection=%+v — want the captured local replacement identity", sel)
		}
		if sel.EffectiveVersion != "" {
			t.Fatalf("effective version=%q — a local replacement must not invent a version", sel.EffectiveVersion)
		}
		if sel.SourceRoot != "third_party/orig" || filepath.IsAbs(sel.SourceRoot) {
			t.Fatalf("source root=%q — want the snapshot-relative replacement identity", sel.SourceRoot)
		}
		if sel.ContentDigest == "" {
			t.Fatal("local replacement selection carries no content digest")
		}
		if want := filepath.Join(root, "third_party", "orig"); source.Dir != want {
			t.Fatalf("source dir=%q — want the captured local replacement %q", source.Dir, want)
		}

		got, exists, err := ix.SelectedModuleCoordinate("example.com/orig", "v1.0.0", "pkg/vuln.go")
		if err != nil || !exists {
			t.Fatalf("coordinate in the local replacement: exists=%v err=%v", exists, err)
		}
		if body := readSourceFixture(t, got.Dir, "pkg/vuln.go"); !strings.Contains(body, "LOCAL REPLACEMENT BYTES") {
			t.Fatalf("read %q — the module cache answered for a local replacement", body)
		}
	})

	t.Run("workspace_member_reads_captured_bytes", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", "module example.com/prod\n\ngo 1.21\n")
		workFile := filepath.Join(root, "go.work")
		sourceFixture(t, root, "go.work", "go 1.21\n\nuse ./libs/orig\n")
		sourceFixture(t, root, "libs/orig/go.mod", "module example.com/orig\n\ngo 1.21\n")
		sourceFixture(t, root, "libs/orig/pkg/vuln.go",
			"package pkg\n\n// WORKSPACE BYTES\nfunc Vulnerable() error { return nil }\n")
		sourceFixture(t, cache, "example.com/orig@v1.0.0/pkg/vuln.go",
			"package pkg\n\n// PUBLISHED ORIGINAL\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off"},
			Build: recordedBuild(t, root, workFile),
		}
		// A workspace module has no version: its identity is the captured
		// local tree, so the resolver accepts the empty coordinate.
		source, err := ix.SelectedModuleSource("example.com/orig", "")
		if err != nil {
			t.Fatalf("resolve the workspace member: %v", err)
		}
		sel := source.Selection
		if sel.SourceKind != domain.ModuleSourceWorkspace {
			t.Fatalf("selection=%+v — want a workspace source", sel)
		}
		if sel.Workspace == nil || sel.Workspace.Directory != "libs/orig" {
			t.Fatalf("selection=%+v — want the go.work membership recorded", sel)
		}
		if sel.EffectiveVersion != "" {
			t.Fatalf("effective version=%q — a workspace module has no version", sel.EffectiveVersion)
		}
		if sel.SourceRoot != "libs/orig" || filepath.IsAbs(sel.SourceRoot) {
			t.Fatalf("source root=%q — want the snapshot-relative workspace identity", sel.SourceRoot)
		}
		if sel.ContentDigest == "" {
			t.Fatal("workspace selection carries no content digest")
		}
		if want := filepath.Join(root, "libs", "orig"); source.Dir != want {
			t.Fatalf("source dir=%q — want the workspace member %q", source.Dir, want)
		}

		got, exists, err := ix.SelectedModuleCoordinate("example.com/orig", "", "pkg/vuln.go")
		if err != nil || !exists {
			t.Fatalf("coordinate in the workspace module: exists=%v err=%v", exists, err)
		}
		if body := readSourceFixture(t, got.Dir, "pkg/vuln.go"); !strings.Contains(body, "WORKSPACE BYTES") {
			t.Fatalf("read %q — the module cache answered for a workspace module", body)
		}
	})

	t.Run("vendored_replacement_uses_vendor_provenance", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig => example.com/fork v1.2.0
`)
		sourceFixture(t, root, "vendor/modules.txt", `# example.com/orig v1.0.0 => example.com/fork v1.2.0
## explicit; go 1.21
example.com/orig/pkg
`)
		sourceFixture(t, root, "vendor/example.com/orig/pkg/vuln.go",
			"package pkg\n\n// VENDORED REPLACEMENT BYTES\nfunc Vulnerable() error { return nil }\n")
		sourceFixture(t, cache, "example.com/orig@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// WRONG SOURCE: original bytes at the fork version\nfunc Vulnerable() error { return nil }\n")
		sourceFixture(t, cache, "example.com/fork@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// MODULE CACHE FORK\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		source, err := ix.SelectedModuleSource("example.com/orig", "v1.2.0")
		if err != nil {
			t.Fatalf("resolve the vendored replacement: %v", err)
		}
		sel := source.Selection
		if sel.SourceKind != domain.ModuleSourceVendor {
			t.Fatalf("selection=%+v — want the vendored source", sel)
		}
		if sel.SourceRoot != "vendor/example.com/orig" {
			t.Fatalf("source root=%q — want the declared module's vendored directory", sel.SourceRoot)
		}
		if sel.EffectiveModule != "example.com/fork" || sel.EffectiveVersion != "v1.2.0" {
			t.Fatalf("selection=%+v — want the manifest's effective replacement identity", sel)
		}
		if len(sel.Replacements) != 1 ||
			sel.Replacements[0].Old != "example.com/orig@v1.0.0" ||
			sel.Replacements[0].New != "example.com/fork@v1.2.0" {
			t.Fatalf("replacements=%+v — want the vendored replacement provenance", sel.Replacements)
		}
		if want := filepath.Join(root, "vendor", "example.com", "orig"); source.Dir != want {
			t.Fatalf("source dir=%q — want %q", source.Dir, want)
		}

		got, exists, err := ix.SelectedModuleCoordinate("example.com/orig", "v1.2.0", "pkg/vuln.go")
		if err != nil || !exists {
			t.Fatalf("coordinate in the vendored replacement: exists=%v err=%v", exists, err)
		}
		if body := readSourceFixture(t, got.Dir, "pkg/vuln.go"); !strings.Contains(body, "VENDORED REPLACEMENT BYTES") {
			t.Fatalf("read %q — the vendored replacement bytes did not answer", body)
		}
	})

	t.Run("mutated_local_replacement_invalidates_the_recorded_root", func(t *testing.T) {
		root := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig => ./third_party/orig
`)
		sourceFixture(t, root, "third_party/orig/go.mod", "module example.com/orig\n\ngo 1.21\n")
		sourceFixture(t, root, "third_party/orig/pkg/vuln.go", "package pkg\n\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{Dir: root, Env: []string{"GOMODCACHE=" + t.TempDir(), "GOPROXY=off", "GOWORK=off"}, Build: recordedBuild(t, root, "")}
		source, err := ix.SelectedModuleSource("example.com/orig", "v1.0.0")
		if err != nil {
			t.Fatalf("resolve the local replacement: %v", err)
		}
		recorded := source.Selection
		if err := ix.VerifyModuleSource(recorded); err != nil {
			t.Fatalf("verify the unchanged replacement: %v", err)
		}

		sourceFixture(t, root, "third_party/orig/pkg/vuln.go", "package pkg\n\n// MUTATED AFTER CAPTURE\nfunc Vulnerable() error { return nil }\n")
		err = ix.VerifyModuleSource(recorded)
		if err == nil {
			t.Fatal("a mutated local replacement still verifies against the recorded root")
		}
		if !domain.IsModuleSourceFailure(err, domain.ModuleSourceStale) {
			t.Fatalf("err=%v — want a typed SOURCE_STALE failure", err)
		}
	})

	t.Run("affected_entry_records_the_effective_selection", func(t *testing.T) {
		root := t.TempDir()
		cache := t.TempDir()
		sourceFixture(t, root, "go.mod", `module example.com/prod

go 1.21

require example.com/orig v1.0.0

replace example.com/orig => example.com/fork v1.2.0
`)
		sourceFixture(t, cache, "example.com/fork@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// FORK IMPLEMENTATION\nfunc Vulnerable() error { return nil }\n")

		ix := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + cache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		graph := []byte(`{"Path":"example.com/prod","Main":true}
{"Path":"example.com/orig","Version":"v1.0.0","Replace":{"Path":"example.com/fork","Version":"v1.2.0"}}
`)
		resolver := affected.GoResolver{Tool: sourceGraphTool{modules: graph}, Sources: ix}
		res, _, err := resolver.Resolve(context.Background(), sourceVuln(), recordedBuild(t, root, ""))
		if err != nil {
			t.Fatalf("affected resolver: %v", err)
		}
		if len(res.EffectiveSources) != 1 {
			t.Fatalf("effective sources=%+v — want one descriptor per resolved entry", res.EffectiveSources)
		}
		desc := res.EffectiveSources[0]
		if desc.EntryRef != 0 || desc.DeclaredModule != "example.com/orig" || desc.DeclaredVersion != "v1.0.0" {
			t.Fatalf("descriptor=%+v — want entry 0 declared as example.com/orig@v1.0.0", desc)
		}
		if desc.Failure != nil {
			t.Fatalf("descriptor=%+v — a cached fork must resolve", desc)
		}
		if desc.EffectiveModule != "example.com/fork" || desc.EffectiveVersion != "v1.2.0" {
			t.Fatalf("descriptor=%+v — want the replacement coordinate", desc)
		}
		if desc.SourceKind != domain.ModuleSourceModuleCache || desc.SourceRoot != "example.com/fork@v1.2.0" {
			t.Fatalf("descriptor=%+v — want the fork's module-cache root", desc)
		}

		// With the fork unavailable the persisted input records a typed
		// failure. It must not fall back to the original's cached bytes.
		emptyCache := t.TempDir()
		sourceFixture(t, emptyCache, "example.com/orig@v1.2.0/pkg/vuln.go",
			"package pkg\n\n// WRONG SOURCE: original bytes at the fork version\nfunc Vulnerable() error { return nil }\n")
		broken := &Index{
			Dir:   root,
			Env:   []string{"GOMODCACHE=" + emptyCache, "GOPROXY=off", "GOWORK=off"},
			Build: recordedBuild(t, root, ""),
		}
		res, _, err = (affected.GoResolver{Tool: sourceGraphTool{modules: graph}, Sources: broken}).
			Resolve(context.Background(), sourceVuln(), recordedBuild(t, root, ""))
		if err != nil {
			t.Fatalf("affected resolver: %v", err)
		}
		if len(res.EffectiveSources) != 1 {
			t.Fatalf("effective sources=%+v — want one descriptor", res.EffectiveSources)
		}
		desc = res.EffectiveSources[0]
		if desc.Failure == nil || desc.Failure.Kind != domain.ModuleSourceUnavailable {
			t.Fatalf("descriptor=%+v — want a typed SOURCE_UNAVAILABLE failure", desc)
		}
		if desc.SourceKind != "" || desc.SourceRoot != "" {
			t.Fatalf("descriptor=%+v — a failed selection must not name a source", desc)
		}
		if desc.EffectiveModule != "example.com/fork" || desc.EffectiveVersion != "v1.2.0" {
			t.Fatalf("descriptor=%+v — the replacement identity is still recorded on failure", desc)
		}
	})
}

// sourceGraphTool serves one recorded `go list -m -json all` stream.
type sourceGraphTool struct {
	modules []byte
}

func (s sourceGraphTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return s.modules, "go list -m -json all", nil
}

func (s sourceGraphTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return s.ListPackagesScope(ctx, dir, build, true)
}

func (s sourceGraphTool) ListPackagesScope(context.Context, string, domain.ProductSnapshot, bool) ([]byte, error) {
	return nil, nil
}

func sourceVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:               "GO-2099-0001",
		Module:           "example.com/orig",
		AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
		AffectedPackages: []domain.AffectedPackage{{Path: "example.com/orig/pkg"}},
	}
}
