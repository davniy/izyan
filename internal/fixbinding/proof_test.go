package fixbinding

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/vulnerability"
)

// The fixture below is one pinned input bundle: an exact advisory document, the
// exact captured fix bytes, the exact payload-side source the identifiers are
// resolved against, and an independently anchored inventory of the selected
// implementation. Every premise the checker re-derives comes from these bytes;
// nothing is a hand-written "complete" summary.

const (
	fixtureRecordID    = "GHSA-f2f2-0001-aaaa"
	fixtureModule      = "example.com/dep"
	fixtureDeclaredVer = "v0.9.0"
	fixtureSelectedVer = "v0.8.0"
	fixtureLocator     = "https://github.com/example/dep/commit/abc123"
	fixturePatchPath   = "server/server.go"
)

// fixtureRecordBytes is an exact OSV document. Its digest is the pin every
// derivation is checked against.
func fixtureRecordBytes() []byte {
	doc := map[string]any{
		"schema_version": "1.6.0",
		"id":             fixtureRecordID,
		"modified":       "2026-10-01T00:00:00Z",
		"summary":        "Top-level directories are created with group-accessible permissions",
		"details":        "CreateTopLevelDirectories creates the configured root with mode 0711.",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": fixtureModule},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "0.9.0"}},
			}},
			"ecosystem_specific": map[string]any{
				"imports": []any{map[string]any{
					"path":    fixtureModule + "/server",
					"symbols": []any{"CreateTopLevelDirectories"},
				}},
			},
		}},
		"references": []any{map[string]any{"type": "FIX", "url": fixtureLocator}},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	return raw
}

// fixtureBefore is the complete pre-image of the patched file.
func fixtureBefore() []byte {
	return []byte(`package server

import (
	"os"

	"example.com/dep/config"
)

type Server struct {
	Config *config.Config
}

func CreateTopLevelDirectories(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.Root, 0711); err != nil {
		return err
	}
	return nil
}
`)
}

// fixtureAfter is the complete post-image of the patched file.
func fixtureAfter() []byte {
	return []byte(`package server

import (
	"os"

	"example.com/dep/config"
)

type Server struct {
	Config *config.Config
}

func CreateTopLevelDirectories(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(cfg.Root, 0o700); err != nil {
		return err
	}
	return nil
}
`)
}

// fixturePatchBytes is the exact captured fix artifact: a mode change on the
// root directory plus an added permission repair.
func fixturePatchBytes() []byte {
	return []byte(`diff --git a/server/server.go b/server/server.go
index 1111111..2222222 100644
--- a/server/server.go
+++ b/server/server.go
@@ -14,4 +14,7 @@ func CreateTopLevelDirectories(cfg *config.Config) error {
-	if err := os.MkdirAll(cfg.Root, 0711); err != nil {
+	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
 		return err
 	}
+	if err := os.Chmod(cfg.Root, 0o700); err != nil {
+		return err
+	}
 	return nil
`)
}

// fixtureAddedOnlyAfter is the complete post-image for the added-only patch: the
// vulnerable creation keeps its mode and only the repair is added.
func fixtureAddedOnlyAfter() []byte {
	return []byte(`package server

import (
	"os"

	"example.com/dep/config"
)

type Server struct {
	Config *config.Config
}

func CreateTopLevelDirectories(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.Root, 0711); err != nil {
		return err
	}
	if err := os.Chmod(cfg.Root, 0o700); err != nil {
		return err
	}
	return nil
}
`)
}

// fixtureAddedOnlyPatchBytes captures only the added permission repair, so the
// patch establishes no directory-creation mechanism at all.
func fixtureAddedOnlyPatchBytes() []byte {
	return []byte(`diff --git a/server/server.go b/server/server.go
index 1111111..3333333 100644
--- a/server/server.go
+++ b/server/server.go
@@ -16,2 +16,5 @@ func CreateTopLevelDirectories(cfg *config.Config) error {
 	}
+	if err := os.Chmod(cfg.Root, 0o700); err != nil {
+		return err
+	}
 	return nil
`)
}

// fixtureSelectedFiles is the exact selected implementation of the module.
func fixtureSelectedFiles() map[string][]byte {
	return map[string][]byte{
		"go.mod": []byte("module example.com/dep\n\ngo 1.25\n"),
		"config/config.go": []byte(`package config

type Config struct {
	Root  string
	State string
}
`),
		fixturePatchPath: fixtureBefore(),
		"plugin/plugin.go": []byte(`package plugin

import (
	"os"

	"example.com/dep/config"
)

type Registration struct {
	ID     string
	InitFn func(*config.Config) error
}

// Register records one plugin registration.
func Register(r Registration) {
	_ = r
}

// InitFn supplies the plugin implementation.
func InitFn(cfg *config.Config) error {
	return os.MkdirAll(cfg.Root, 0o755)
}

func init() {
	Register(Registration{ID: "example.com/dep/plugin", InitFn: InitFn})
}
`),
	}
}

// fixturePatchSource is the complete payload-side source of the patched file.
func fixturePatchSource() *SourceBundle {
	return &SourceBundle{
		Module: ModuleIdentity{Path: fixtureModule, Version: fixtureSelectedVer},
		Files: map[string]FileSource{
			fixturePatchPath: {Before: fixtureBefore(), After: fixtureAfter()},
		},
	}
}

// fixtureSelection is the current effective-source descriptor for entry 0.
func fixtureSelection() []domain.EffectiveSourceSelection {
	return []domain.EffectiveSourceSelection{{
		EntryRef:         0,
		DeclaredModule:   fixtureModule,
		DeclaredVersion:  fixtureDeclaredVer,
		EffectiveModule:  fixtureModule,
		EffectiveVersion: fixtureSelectedVer,
		SourceKind:       domain.ModuleSourceModuleCache,
		SourceRoot:       fixtureModule + "@" + fixtureSelectedVer,
	}}
}

// buildArchiveEvidence constructs an exact module archive and the recorded
// go.sum line that pins it, using the checker's own h1 rule.
func buildArchiveEvidence(t *testing.T, module, version string, files map[string][]byte) ([]byte, []byte) {
	t.Helper()
	prefix := module + "@" + version + "/"
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	h := sha256.New()
	for _, name := range names {
		entry, err := writer.Create(prefix + name)
		if err != nil {
			t.Fatalf("zip entry %s: %v", name, err)
		}
		if _, err := entry.Write(files[name]); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(h, "%x  %s\n", sum, prefix+name)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	goSum := []byte(module + " " + version + " h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil)) + "\n")
	return buf.Bytes(), goSum
}

// anchoredInventory builds the independently anchored complete inventory of one
// selected implementation.
func anchoredInventory(t *testing.T, module, version string, files map[string][]byte) SourceInventory {
	t.Helper()
	if _, ok := files["go.mod"]; !ok {
		withModule := make(map[string][]byte, len(files)+1)
		for name, raw := range files { withModule[name] = raw }
		withModule["go.mod"] = []byte("module " + module + "\n\ngo 1.25\n")
		files = withModule
	}
	zipBytes, goSum := buildArchiveEvidence(t, module, version, files)
	anchor, err := CheckArchiveAnchor(ArchiveEvidence{Bytes: zipBytes, Module: module, Version: version, GoSum: goSum})
	if err != nil {
		t.Fatalf("archive anchor: %v", err)
	}
	observed := ObservedSource{
		Kind: SourceModuleCache, Module: module, Version: version,
		Root: module + "@" + version, WalkComplete: true,
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		observed.Files = append(observed.Files, ObservedFile{
			Path: name, Bytes: files[name], Digest: DigestBytes(files[name]),
		})
	}
	inventory := AssembleInventory(InventoryInput{Module: module, Version: version, Observed: observed, Anchor: anchor})
	if !inventory.Anchored() {
		t.Fatalf("fixture inventory is not anchored: %+v", inventory.Input)
	}
	return inventory
}

// capturedArtifact is one complete captured artifact record with its bytes.
func capturedArtifact(locator string, kind string, body []byte) ArtifactInput {
	return ArtifactInput{
		Artifact: domain.FixArtifact{
			Locator: locator, Kind: kind, Outcome: domain.FixArtifactComplete,
			Provenance: "captured-inputs", Digest: DigestBytes(body), Size: len(body),
			Bytes: base64.StdEncoding.EncodeToString(body),
		},
		Bytes: body,
	}
}

// fixtureInputs is the complete immutable input bundle.
func fixtureInputs(t *testing.T) Inputs {
	t.Helper()
	record := fixtureRecordBytes()
	loaded, err := vulnerability.LoadExactBytes(record, fixtureRecordID, "osv:test-fixture")
	if err != nil {
		t.Fatalf("load record: %v", err)
	}
	captures, _ := captureFixture(t, record, fixtureSelectedFiles())
	return Inputs{
		Pin:          loaded.Pin,
		Raw:          record,
		EntryRef:     0,
		Selection:    fixtureSelection(),
		Inventory:    anchoredInventory(t, fixtureModule, fixtureSelectedVer, fixtureSelectedFiles()),
		Artifacts:    []ArtifactInput{capturedArtifact(fixtureLocator, "commit", fixturePatchBytes())},
		PatchSources: map[string]*SourceBundle{fixtureLocator: fixturePatchSource()},
		Captures: captures,
	}
}

// deriveFixture derives the canonical binding and fails the test when the
// fixture itself does not establish a cover.
func deriveFixture(t *testing.T, in Inputs) Binding {
	t.Helper()
	binding, err := Derive(in)
	if err != nil {
		t.Fatalf("derive: %v\nbinding=%s", err, binding.Detail)
	}
	if binding.Status != BindingCover {
		t.Fatalf("status=%s, want %s", binding.Status, BindingCover)
	}
	return binding
}

// claimFor is the condition/verification relationship that references the
// binding's own cover.
func claimFor(binding Binding) *CoverClaim {
	return &CoverClaim{
		ConditionSubjects:         append([]domain.SymbolRef(nil), binding.Cover.Subjects...),
		VerificationCoverID:       binding.Cover.ID,
		VerificationSubjectDigest: binding.Cover.SubjectDigest,
	}
}

// admitFixture admits the canonical binding against the fixture inputs.
func admitFixture(t *testing.T, ctx AdmissionInput, in Inputs, binding Binding) Binding {
	t.Helper()
	in.Claim = claimFor(binding)
	admitted, err := Admit(ctx, binding, in)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if admitted.Status != BindingAdmitted {
		t.Fatalf("status=%s, want %s", admitted.Status, BindingAdmitted)
	}
	return admitted
}

// effectByDisposition returns the effect with the requested disposition.
func effectByDisposition(t *testing.T, binding Binding, disposition Disposition) EffectRecord {
	t.Helper()
	for _, effect := range binding.Effects {
		if effect.Disposition == disposition {
			return effect
		}
	}
	t.Fatalf("no effect with disposition %s in %+v", disposition, binding.Effects)
	return EffectRecord{}
}

// refusedCode asserts an admission error carries the expected refusal code.
func refusedCode(t *testing.T, err error, want RefusalCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("admission succeeded; want refusal %s", want)
	}
	if got := RefusalCodeOf(err); got != want {
		t.Fatalf("refusal=%s (%v), want %s", got, err, want)
	}
}

// hasObligationCode reports whether any obligation carries the code.
func hasObligationCode(obligations []ProofObligation, code string) bool {
	for _, obligation := range obligations {
		if obligation.Code == code {
			return true
		}
	}
	return false
}

// effectText renders an effect for a failure message.
func effectText(effect EffectRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s class=%s disposition=%s", effect.ID, effect.Class, effect.Disposition)
	for _, location := range effect.Locations {
		fmt.Fprintf(&b, " @%s:%d(%s)", location.File, location.Line, location.Declaration)
	}
	return b.String()
}

// fixtureLocatorB is the record's second declared fix locator.
const fixtureLocatorB = "https://example.com/dep/commit/fix-b"

// fixtureTwoRefRecordBytes is the same record with two declared fix locators.
func fixtureTwoRefRecordBytes() []byte {
	doc := map[string]any{
		"schema_version": "1.6.0",
		"id":             fixtureRecordID,
		"modified":       "2026-10-01T00:00:00Z",
		"summary":        "Top-level directories are created with group-accessible permissions",
		"details":        "CreateTopLevelDirectories creates the configured root with mode 0711.",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": fixtureModule},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "0.9.0"}},
			}},
			"ecosystem_specific": map[string]any{
				"imports": []any{map[string]any{
					"path":    fixtureModule + "/server",
					"symbols": []any{"CreateTopLevelDirectories"},
				}},
			},
		}},
		"references": []any{
			map[string]any{"type": "FIX", "url": fixtureLocator},
			map[string]any{"type": "FIX", "url": fixtureLocatorB},
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	return raw
}

// fixturePatchBBytes is a second, independently captured artifact: it changes
// the same pre-existing region to a different valid postimage. The two
// locators are therefore not a series and cannot share one patch-side source.
func fixturePatchBBytes() []byte {
	return []byte(`diff --git a/server/server.go b/server/server.go
index 1111111..4444444 100644
--- a/server/server.go
+++ b/server/server.go
@@ -14,4 +14,7 @@ func CreateTopLevelDirectories(cfg *config.Config) error {
-	if err := os.MkdirAll(cfg.Root, 0711); err != nil {
+	if err := os.MkdirAll(cfg.Root, 0o750); err != nil {
 		return err
 	}
+	if err := os.Chmod(cfg.Root, 0o750); err != nil {
+		return err
+	}
 	return nil
`)
}

// fixtureInputsTwoRefs builds the complete bundle for a record with two
// captured fix locators, each with its own patch-side source derived from the
// selected implementation.
func fixtureInputsTwoRefs(t *testing.T) Inputs {
	t.Helper()
	record := fixtureTwoRefRecordBytes()
	loaded, err := vulnerability.LoadExactBytes(record, fixtureRecordID, "osv:test-fixture")
	if err != nil {
		t.Fatalf("load record: %v", err)
	}
	files := fixtureSelectedFiles()
	module := ModuleIdentity{Path: fixtureModule, Version: fixtureSelectedVer}
	bundleA, unmatched := PatchSourceFromSelected(fixturePatchBytes(), module, files)
	if bundleA == nil {
		t.Fatalf("artifact A did not apply to the selected source: %v", unmatched)
	}
	bundleB, unmatched := PatchSourceFromSelected(fixturePatchBBytes(), module, files)
	if bundleB == nil {
		t.Fatalf("artifact B did not apply to the selected source: %v", unmatched)
	}
	if string(bundleA.Files[fixturePatchPath].After) == string(bundleB.Files[fixturePatchPath].After) {
		t.Fatal("the fixture's two artifacts must splice different postimages")
	}
	captures, _ := captureFixture(t, record, files)
	return Inputs{
		Pin:       loaded.Pin,
		Raw:       record,
		EntryRef:  0,
		Selection: fixtureSelection(),
		Inventory: anchoredInventory(t, fixtureModule, fixtureSelectedVer, files),
		Artifacts: []ArtifactInput{capturedArtifact(fixtureLocator, "commit", fixturePatchBytes()), capturedArtifact(fixtureLocatorB, "commit", fixturePatchBBytes())},
		Captures: captures,
		PatchSources: map[string]*SourceBundle{
			fixtureLocator:  bundleA,
			fixtureLocatorB: bundleB,
		},
	}
}

// TestPerLocatorPatchSourcesPreserveIndependentTreesAndFailClosed pins the
// per-locator patch-side source contract: declared fix locators are not a
// series, so each artifact resolves identifiers only against its own capture,
// and an incomplete artifact refuses the cover for every other artifact.
func TestPerLocatorPatchSourcesPreserveIndependentTreesAndFailClosed(t *testing.T) {
	t.Run("both complete: separate sources, one cover, replay agrees", func(t *testing.T) {
		in := fixtureInputsTwoRefs(t)
		binding := deriveFixture(t, in)

		if len(binding.PatchSources) != 2 {
			t.Fatalf("patch sources=%+v, want one record per captured locator", binding.PatchSources)
		}
		byLocator := map[string]PatchSourceRecord{}
		for _, rec := range binding.PatchSources {
			byLocator[rec.Locator] = rec
			if rec.ArtifactDigest == "" {
				t.Fatalf("record %s carries no artifact digest: %+v", rec.Locator, rec)
			}
		}
		if byLocator[fixtureLocator].ArtifactDigest != DigestBytes(fixturePatchBytes()) {
			t.Fatalf("locator A binds the wrong artifact bytes: %+v", byLocator[fixtureLocator])
		}
		if byLocator[fixtureLocatorB].ArtifactDigest != DigestBytes(fixturePatchBBytes()) {
			t.Fatalf("locator B binds the wrong artifact bytes: %+v", byLocator[fixtureLocatorB])
		}
		if byLocator[fixtureLocator].Digest == byLocator[fixtureLocatorB].Digest {
			t.Fatal("two different postimages share one source digest")
		}

		locators := map[string]bool{}
		for _, effect := range binding.Effects {
			locators[effect.Locator] = true
		}
		if !locators[fixtureLocator] || !locators[fixtureLocatorB] {
			t.Fatalf("effects=%+v — both artifacts' effects must retain their own locator", binding.Effects)
		}

		admitted := admitFixture(t, fixtureTwoRefsContext(t), in, binding)
		proof, err := Persist(fixtureTwoRefsContext(t), admitted, in)
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		replayed, err := Readmit(fixtureTwoRefsContext(t), proof)
		if err != nil {
			t.Fatalf("readmit: %v", err)
		}
		if !reflect.DeepEqual(replayed.PatchSources, binding.PatchSources) {
			t.Fatalf("replayed sources=%+v, want %+v", replayed.PatchSources, binding.PatchSources)
		}
		if replayed.Cover.ID != binding.Cover.ID {
			t.Fatalf("replayed cover %s, want %s", replayed.Cover.ID, binding.Cover.ID)
		}
	})

	t.Run("forged source maps cannot replace captured sources", func(t *testing.T) {
		in := fixtureInputsTwoRefs(t)
		canonical := deriveFixture(t, in)
		delete(in.PatchSources, fixtureLocatorB)
		in.PatchSources[fixtureLocator] = &SourceBundle{Module:ModuleIdentity{Path:"forged.invalid/module"}}
		binding := deriveFixture(t, in)
		if !reflect.DeepEqual(binding, canonical) { t.Fatal("asserted maps changed the capture-derived binding") }
		in.Captures = nil
		if _, err := Derive(in); err == nil { t.Fatal("forged source maps authorized missing captures") }
	})

	t.Run("another locator's capture cannot qualify artifact B", func(t *testing.T) {
		in := fixtureInputsTwoRefs(t)
		archive := *in.Inventory.Anchor.Archive
		in.Captures.PatchBases = []PatchBaseCapture{{Locator:fixtureLocatorB, ArtifactDigest:DigestBytes(fixturePatchBytes()), Archive:archive}}
		if _, err := Derive(in); err == nil { t.Fatal("artifact A capture authorized artifact B") }
	})

	t.Run("a changed source association is refused at replay", func(t *testing.T) {
		in := fixtureInputsTwoRefs(t)
		binding := deriveFixture(t, in)
		admitted := admitFixture(t, fixtureTwoRefsContext(t), in, binding)
		proof, err := Persist(fixtureTwoRefsContext(t), admitted, in)
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		var saved Inputs
		if err := json.Unmarshal(proof.Inputs, &saved); err != nil {
			t.Fatalf("decode inputs: %v", err)
		}
		saved.Captures.SelectedFiles[0].Bytes = []byte("substituted source")
		rewritten, err := json.Marshal(saved)
		if err != nil {
			t.Fatalf("encode inputs: %v", err)
		}
		proof.Inputs = rewritten
		if _, err := Readmit(fixtureTwoRefsContext(t), proof); err == nil {
			t.Fatal("a proof whose captured source bytes changed re-admitted")
		}
	})

	t.Run("a deduplicated artifact keeps its own association", func(t *testing.T) {
		in := fixtureInputsTwoRefs(t)
		duplicate := capturedArtifact(fixtureLocatorB, "commit", fixturePatchBytes())
		duplicate.Artifact.Bytes = ""
		duplicate.Artifact.DuplicateOf = fixtureLocator
		duplicate.Bytes = fixturePatchBytes()
		in.Artifacts = []ArtifactInput{capturedArtifact(fixtureLocator, "commit", fixturePatchBytes()), duplicate}
		in.PatchSources[fixtureLocatorB] = in.PatchSources[fixtureLocator]
		binding := deriveFixture(t, in)
		if len(binding.PatchSources) != 2 {
			t.Fatalf("patch sources=%+v, want both locators recorded", binding.PatchSources)
		}
		if binding.PatchSources[0].Locator == binding.PatchSources[1].Locator {
			t.Fatalf("patch sources=%+v — a duplicate locator inherited its primary's record", binding.PatchSources)
		}
	})
}
