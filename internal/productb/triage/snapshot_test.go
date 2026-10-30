package triage

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/repository"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// snapshotInput builds a FindingInput with the given target; Raw is a
// well-formed finding.v1 record so InputHash derivation stays realistic.
func snapshotInput(t *testing.T, target Target) FindingInput {
	t.Helper()
	raw := []byte(`{"schema_version":"finding.v1","finding_id":"scanner-123","vulnerability":{"ids":["CVE-2025-1234"]},"target":{}}`)
	return FindingInput{
		Finding: Finding{
			SchemaVersion: FindingSchemaVersion,
			FindingID:     "scanner-123",
			Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
			Target:        target,
		},
		Raw:    raw,
		SHA256: sha256Hex(t, raw),
	}
}

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, out)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

func TestSnapshotManifestFromFixture(t *testing.T) {
	repo := filepath.Join("testdata", "snapshot-valid")
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: repo}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.SchemaVersion != SnapshotSchemaVersion {
		t.Fatalf("schema_version = %q", m.SchemaVersion)
	}
	if m.FindingID != "scanner-123" {
		t.Fatalf("finding_id = %q", m.FindingID)
	}
	if m.InputHash == "" {
		t.Fatal("input_hash is empty")
	}
	if m.ContentHash == "" {
		t.Fatal("content_hash is empty")
	}
	if m.RevisionStatus != FactUnavailable {
		t.Fatalf("revision_status = %q, want %q", m.RevisionStatus, FactUnavailable)
	}
	var paths []string
	for _, f := range m.Files {
		paths = append(paths, f.Path)
		if f.SHA256 == "" || f.Size <= 0 {
			t.Fatalf("file %q lacks sha256/size", f.Path)
		}
	}
	want := []string{"README.md", "config/app.ini", "src/app.py"}
	sort.Strings(paths)
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("files = %v, want %v", paths, want)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		t.Fatalf("created_at %q not RFC3339: %v", m.CreatedAt, err)
	}
	if len(m.Artifacts) != 0 {
		t.Fatalf("artifacts = %v, want none", m.Artifacts)
	}
}

func TestSnapshotRequiresInputHash(t *testing.T) {
	in := snapshotInput(t, Target{Repository: filepath.Join("testdata", "snapshot-valid")})
	in.SHA256 = ""
	in.Raw = nil
	if _, err := (LocalSnapshotBuilder{}).Build(context.Background(), in); err == nil {
		t.Fatal("Build succeeded with no input hash and no raw bytes")
	}
}

func TestSnapshotHashStableAcrossFileOrder(t *testing.T) {
	mk := func() string {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "b.txt"), "bravo")
		writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
		writeFile(t, filepath.Join(dir, "sub", "c.txt"), "charlie")
		return dir
	}
	m1, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: mk()}))
	if err != nil {
		t.Fatalf("Build a: %v", err)
	}
	m2, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: mk()}))
	if err != nil {
		t.Fatalf("Build b: %v", err)
	}
	if m1.ContentHash != m2.ContentHash {
		t.Fatalf("content hash differs for identical trees: %s vs %s", m1.ContentHash, m2.ContentHash)
	}
	if !reflect.DeepEqual(m1.Files, m2.Files) {
		t.Fatalf("file lists differ: %v vs %v", m1.Files, m2.Files)
	}
}

func TestSnapshotHashChangesOnMutation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	before, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha!")
	after, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build after mutation: %v", err)
	}
	if before.ContentHash == after.ContentHash {
		t.Fatal("file mutation did not change content_hash")
	}
}

func TestSnapshotHashExcludesGitMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeFile(t, filepath.Join(dir, "sub", "b.txt"), "bravo")

	before, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	writeFile(t, filepath.Join(dir, ".git", "config"), "garbage")
	writeFile(t, filepath.Join(dir, ".git", "objects", "ab", "cdef"), "object")

	after, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build with .git: %v", err)
	}
	if before.ContentHash != after.ContentHash {
		t.Fatalf(".git content changed the hash: %s vs %s", before.ContentHash, after.ContentHash)
	}
	for _, f := range after.Files {
		if f.Path == ".git" || strings.HasPrefix(f.Path, ".git/") {
			t.Fatalf(".git file %q leaked into manifest files", f.Path)
		}
	}
	if !reflect.DeepEqual(before.Files, after.Files) {
		t.Fatal(".git changed file list")
	}
}

func TestSnapshotHashIndependentOfTimestamp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	in := snapshotInput(t, Target{Repository: dir})
	m1, err := LocalSnapshotBuilder{Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build 1: %v", err)
	}
	m2, err := LocalSnapshotBuilder{Now: func() time.Time { return time.Unix(1900000000, 0).UTC() }}.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build 2: %v", err)
	}
	if m1.ContentHash != m2.ContentHash || m1.InputHash != m2.InputHash {
		t.Fatal("hash fields depend on the clock")
	}
	if m1.CreatedAt == m2.CreatedAt {
		t.Fatal("created_at did not reflect the injected clock")
	}
}

func TestSnapshotRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "secret")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "escape.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := (LocalSnapshotBuilder{}).Build(context.Background(), snapshotInput(t, Target{Repository: dir})); err == nil {
		t.Fatal("Build succeeded despite a symlink escaping the snapshot root")
	}
}

func TestSnapshotRejectsPathReplacement(t *testing.T) {
	parent := t.TempDir()
	repo := filepath.Join(parent, "prod")
	writeFile(t, filepath.Join(repo, "main.go"), "package main\n")
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.com/prod\n\ngo 1.25\n\nreplace example.com/dep => ../dep\n")
	writeFile(t, filepath.Join(parent, "dep", "go.mod"), "module example.com/dep\n\ngo 1.25\n")
	if _, err := (LocalSnapshotBuilder{}).Build(context.Background(), snapshotInput(t, Target{Repository: repo})); err == nil {
		t.Fatal("Build succeeded despite an escaping path replacement")
	}
}

func TestSnapshotAllowsInternalSymlink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	if err := os.Symlink("a.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Files) != 1 || m.Files[0].Path != "a.txt" {
		t.Fatalf("files = %v, want only a.txt (symlink is not a regular file)", m.Files)
	}
}

func TestSnapshotRevisionValid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-q", "-m", "init")
	gitCmd(t, dir, "tag", "v1.0.0")
	gitCmd(t, dir, "branch", "feature/x")
	wantSHA := gitOutput(t, dir, "rev-parse", "HEAD")

	for _, rev := range []string{"HEAD", "v1.0.0", "feature/x"} {
		m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir, Revision: rev}))
		if err != nil {
			t.Fatalf("Build rev=%q: %v", rev, err)
		}
		if m.RevisionStatus != FactValid {
			t.Fatalf("revision %q: status = %q, want %q", rev, m.RevisionStatus, FactValid)
		}
		if m.Revision != rev {
			t.Fatalf("revision = %q, want %q", m.Revision, rev)
		}
		if m.ResolvedRevision != wantSHA {
			t.Fatalf("revision %q: resolved_revision = %q, want %q", rev, m.ResolvedRevision, wantSHA)
		}
	}
}

func TestSnapshotRevisionInvalid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-q", "-m", "init")

	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir, Revision: "v9.9.9-does-not-exist"}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.RevisionStatus != FactInvalid {
		t.Fatalf("revision_status = %q, want %q", m.RevisionStatus, FactInvalid)
	}
	if m.ResolvedRevision != "" {
		t.Fatalf("resolved_revision = %q, want empty for unresolved revision", m.ResolvedRevision)
	}
	if m.ContentHash == "" {
		t.Fatal("content_hash empty: the tree was still snapshotted as-is")
	}
}

func TestSnapshotRevisionUnavailable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.RevisionStatus != FactUnavailable {
		t.Fatalf("revision_status = %q, want %q", m.RevisionStatus, FactUnavailable)
	}
	if m.ResolvedRevision != "" {
		t.Fatalf("resolved_revision = %q, want empty", m.ResolvedRevision)
	}
}

func TestSnapshotNoRepository(t *testing.T) {
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.ContentHash != "" || len(m.Files) != 0 {
		t.Fatalf("expected no snapshot content, got hash %q files %v", m.ContentHash, m.Files)
	}
	if m.RevisionStatus != FactUnavailable {
		t.Fatalf("revision_status = %q, want %q", m.RevisionStatus, FactUnavailable)
	}
	if m.InputHash == "" {
		t.Fatal("input_hash is empty")
	}
}

func TestSnapshotArtifacts(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "a.txt"), "alpha")
	writeFile(t, filepath.Join(repo, "sbom.json"), `{"bomFormat":"CycloneDX"}`)
	external := t.TempDir()
	extBin := filepath.Join(external, "app.bin")
	writeFile(t, extBin, "ELF-fake")

	target := Target{Repository: repo, SBOM: "sbom.json", Binary: extBin}

	// Without external allowance only the contained artifact is recorded.
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, target))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Artifacts) != 1 || m.Artifacts[0].Path != "sbom.json" {
		t.Fatalf("artifacts = %v, want only sbom.json", m.Artifacts)
	}
	if m.Artifacts[0].SHA256 == "" || m.Artifacts[0].Size == 0 {
		t.Fatal("artifact lacks hash/size")
	}

	// Explicitly allowed external artifact is recorded by absolute path.
	m, err = LocalSnapshotBuilder{AllowExternalArtifacts: true}.Build(context.Background(), snapshotInput(t, target))
	if err != nil {
		t.Fatalf("Build external: %v", err)
	}
	if len(m.Artifacts) != 2 {
		t.Fatalf("artifacts = %v, want sbom.json + external binary", m.Artifacts)
	}
	if !filepath.IsAbs(m.Artifacts[1].Path) {
		t.Fatalf("external artifact path %q is not absolute", m.Artifacts[1].Path)
	}

	// Missing optional artifact: absent from the manifest, not an error.
	m, err = LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: repo, SBOM: "missing.json"}))
	if err != nil {
		t.Fatalf("Build missing artifact: %v", err)
	}
	if len(m.Artifacts) != 0 {
		t.Fatalf("artifacts = %v, want none for missing sbom", m.Artifacts)
	}
}

func TestSnapshotManifestSerializesAsSnapshotV1(t *testing.T) {
	repo := filepath.Join("testdata", "snapshot-valid")
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: repo}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw["schema_version"] != "snapshot.v1" {
		t.Fatalf("schema_version = %v", raw["schema_version"])
	}
	if raw["revision_status"] != string(FactUnavailable) {
		t.Fatalf("revision_status = %v", raw["revision_status"])
	}
	if raw["input_hash"] == "" || raw["content_hash"] == "" {
		t.Fatal("hash fields missing from serialized manifest")
	}
	if _, ok := raw["revision"]; ok {
		t.Fatal("revision present but empty; omitempty expected")
	}
	if _, ok := raw["resolved_revision"]; ok {
		t.Fatal("resolved_revision present but empty; omitempty expected")
	}
	files, ok := raw["files"].([]any)
	if !ok || len(files) == 0 {
		t.Fatalf("files = %v, want non-empty array", raw["files"])
	}
}

// TestSnapshotMutationDuringBuild proves a tree that changes mid-build is
// reported as a technical error instead of producing a manifest that mixes
// two tree states. afterCollect mutates the tree between the single entry
// collection and the stability re-check.
func TestSnapshotMutationDuringBuild(t *testing.T) {
	mutate := []struct {
		name string
		fn   func(t *testing.T, dir string)
	}{
		{"content", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "a.txt"), "alpha!")
		}},
		{"add", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "new.txt"), "new")
		}},
		{"remove", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "a.txt")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range mutate {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
			b := LocalSnapshotBuilder{afterCollect: func() { tc.fn(t, dir) }}
			if _, err := b.Build(context.Background(), snapshotInput(t, Target{Repository: dir})); err == nil {
				t.Fatal("Build succeeded despite a mid-build tree mutation")
			}
		})
	}
}

// TestSnapshotContentHashMatchesRepository pins the one-pass encoding to
// repository.ContentHash: identical trees must produce identical hashes.
func TestSnapshotContentHashMatchesRepository(t *testing.T) {
	repo := filepath.Join("testdata", "snapshot-valid")
	m, err := LocalSnapshotBuilder{}.Build(context.Background(), snapshotInput(t, Target{Repository: repo}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want, err := repository.ContentHash(repo)
	if err != nil {
		t.Fatalf("repository.ContentHash: %v", err)
	}
	if m.ContentHash != want {
		t.Fatalf("one-pass hash %q diverged from repository.ContentHash %q", m.ContentHash, want)
	}
}

// TestSnapshotMetaFromMaterialized builds a snapshot over a materialized
// worktree: the manifest must carry the materialization provenance and pin
// revision/content identities that agree with the materialized root.
func TestSnapshotMetaFromMaterialized(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, _ := setupMaterializeSource(t)

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo},
		tagCandidate("example-repo", "v1.2.3", shaV123), MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer src.Cleanup()

	m, err := (LocalSnapshotBuilder{}).BuildMaterialized(ctx,
		snapshotInput(t, Target{Revision: "v1.2.3"}), src)
	if err != nil {
		t.Fatalf("BuildMaterialized: %v", err)
	}
	if !reflect.DeepEqual(m.Materialization, src.Metadata) {
		t.Fatalf("materialization metadata = %+v, want %+v", m.Materialization, src.Metadata)
	}
	md := m.Materialization
	if md.Mode != MaterializationWorktree || md.SourceID != "example-repo" || md.SelectedRef != "v1.2.3" {
		t.Fatalf("materialization provenance = %+v", md)
	}
	if md.ResolvedCommit != shaV123 || m.ResolvedRevision != shaV123 {
		t.Fatalf("resolved commits diverge: materialization %q, revision %q", md.ResolvedCommit, m.ResolvedRevision)
	}
	if md.RootHash != m.ContentHash {
		t.Fatalf("root_hash %q != content_hash %q", md.RootHash, m.ContentHash)
	}
	if m.RevisionStatus != FactValid {
		t.Fatalf("revision_status = %q, want %q", m.RevisionStatus, FactValid)
	}
	if m.Repository != src.Root {
		t.Fatalf("repository = %q, want materialized root %q", m.Repository, src.Root)
	}
	if len(m.Files) != 1 || m.Files[0].Path != "version.txt" {
		t.Fatalf("files = %v, want version.txt only", m.Files)
	}
	wantSHA := sha256Hex(t, []byte("v1.2.3"))
	if m.Files[0].SHA256 != wantSHA {
		t.Fatalf("version.txt sha256 = %q, want %q", m.Files[0].SHA256, wantSHA)
	}
	// The source repository never observes the materialization.
	if got := gitOutput(t, repo, "status", "--porcelain"); got != "" {
		t.Fatalf("source checkout dirty: %q", got)
	}
}

// TestSnapshotMetaDrift proves the manifest does not adopt a tree that
// changed between materialization and snapshot build: the recorded root
// hash no longer matches the observed content hash and the build fails as a
// technical error.
func TestSnapshotMetaDrift(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: dir},
		RefCandidate{}, MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	writeFile(t, filepath.Join(dir, "b.txt"), "mutation")
	if _, err := (LocalSnapshotBuilder{}).BuildMaterialized(ctx, snapshotInput(t, Target{}), src); err == nil {
		t.Fatal("BuildMaterialized adopted a tree that drifted after materialization")
	}
}

// TestSnapshotMetaSerialization pins the snapshot.json shape: the
// materialization block serializes provenance refs and hashes, never
// credential material.
func TestSnapshotMetaSerialization(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, _ := setupMaterializeSource(t)

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo, CredentialRef: "secret://scm/example"},
		tagCandidate("example-repo", "v1.2.3", shaV123), MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer src.Cleanup()

	m, err := (LocalSnapshotBuilder{}).BuildMaterialized(ctx,
		snapshotInput(t, Target{Revision: "v1.2.3"}), src)
	if err != nil {
		t.Fatalf("BuildMaterialized: %v", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mat, ok := raw["materialization"].(map[string]any)
	if !ok {
		t.Fatalf("materialization block missing: %s", data)
	}
	if mat["mode"] != string(MaterializationWorktree) {
		t.Fatalf("materialization.mode = %v", mat["mode"])
	}
	if mat["source_id"] != "example-repo" || mat["selected_ref"] != "v1.2.3" {
		t.Fatalf("materialization provenance = %v", mat)
	}
	if mat["resolved_commit"] != shaV123 || mat["root_hash"] != m.ContentHash {
		t.Fatalf("materialization hashes = %v", mat)
	}
	if mat["credential_ref"] != "secret://scm/example" {
		t.Fatalf("materialization.credential_ref = %v", mat["credential_ref"])
	}
	if mat["created_at"] != "2026-10-16T12:00:00Z" {
		t.Fatalf("materialization.created_at = %v", mat["created_at"])
	}
}

// TestSnapshotMetaLocalMode pins metadata for an unmaterialized local build:
// Build leaves the block empty, BuildMaterialized records local mode.
func TestSnapshotMetaLocalMode(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")

	m, err := (LocalSnapshotBuilder{}).Build(ctx, snapshotInput(t, Target{Repository: dir}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Materialization.Mode != "" || m.Materialization.SourceID != "" {
		t.Fatalf("plain Build leaked materialization metadata: %+v", m.Materialization)
	}

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: dir},
		RefCandidate{}, MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	m, err = (LocalSnapshotBuilder{}).BuildMaterialized(ctx, snapshotInput(t, Target{}), src)
	if err != nil {
		t.Fatalf("BuildMaterialized: %v", err)
	}
	if m.Materialization.Mode != MaterializationLocal || m.Materialization.SourceID != "example-local" {
		t.Fatalf("materialization = %+v", m.Materialization)
	}
}
