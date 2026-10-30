package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/davniy/izyan/internal/domain"
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

// initGitRepo makes dir a git repository with one commit, for the regular
// (non-external) snapshot path.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
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
	run("init", "-q")
	run("add", ".")
	run("commit", "-q", "-m", "init")
}

func TestContentHash_StableAndOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "b.txt"), "bravo")
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeFile(t, filepath.Join(dir, "sub", "c.txt"), "charlie")

	h1, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash is not stable: %s vs %s", h1, h2)
	}
	if h1 == "" {
		t.Fatal("empty hash")
	}
}

func TestContentHash_ChangesOnMutation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	before, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha!")
	after, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("mutation did not change the hash")
	}
}

func TestContentHash_RenameChangesHash(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	before, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")); err != nil {
		t.Fatal(err)
	}
	after, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("rename did not change the hash")
	}
}

func TestContentHash_SymlinkHashesTargetNotContent(t *testing.T) {
	// A symlink must contribute its target string, never the bytes it
	// points at — including a target outside the tree.
	outside := t.TempDir()
	target := filepath.Join(outside, "outside.txt")
	writeFile(t, target, "first")
	dir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	before, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Changing the pointed-to file must not change a hash that only records
	// the link target.
	writeFile(t, target, "second")
	after, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("symlink target content altered the tree hash")
	}
	// Changing the link target itself must change the hash.
	if err := os.Remove(filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	retargeted, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before == retargeted {
		t.Fatal("retargeted symlink kept the same hash")
	}
}

func TestContentHash_ExcludesGitMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	before, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main")
	after, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal(".git metadata changed the content hash")
	}
}

func TestContentHash_ConcurrentReuse(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	want, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h, herr := ContentHash(dir)
			if herr != nil {
				t.Errorf("concurrent hash: %v", herr)
				return
			}
			results[i] = h
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r != want {
			t.Fatalf("concurrent result %d = %s, want %s", i, r, want)
		}
	}
}

func TestVerifyContained_RejectsEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.go"), "package secret")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	if err := os.Symlink(filepath.Join(outside, "secret.go"), filepath.Join(dir, "escape.go")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := VerifyContained(dir); err == nil {
		t.Fatal("escaping symlink was accepted")
	}
}

func TestVerifyContained_AllowsInternalSymlink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "real", "a.txt"), "alpha")
	if err := os.Symlink("real/a.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := VerifyContained(dir); err != nil {
		t.Fatalf("internal symlink rejected: %v", err)
	}
}

func TestSnapshot_ExternalCommitSkipsGit(t *testing.T) {
	// A directory with no .git at all: the external path must not run git.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")

	snap, err := Service{}.Snapshot(t.Context(), dir, SnapshotOptions{
		ExternalCommitSHA: "abcdef1234567890",
	})
	if err != nil {
		t.Fatalf("external snapshot failed: %v", err)
	}
	if snap.Commit != "abcdef1234567890" {
		t.Fatalf("commit = %q, want external sha", snap.Commit)
	}
	if snap.ExternalCommitSHA != "abcdef1234567890" {
		t.Fatalf("external sha not recorded: %q", snap.ExternalCommitSHA)
	}
	if snap.ContentHash == "" {
		t.Fatal("content hash not computed for external snapshot")
	}
	if snap.MinimumGoVersion != "1.21" {
		t.Fatalf("minimum go version = %q, want 1.21", snap.MinimumGoVersion)
	}
}

func TestSnapshot_ExternalCommitRejectsEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.go"), "package secret")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n")
	if err := os.Symlink(filepath.Join(outside, "secret.go"), filepath.Join(dir, "escape.go")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	_, err := Service{}.Snapshot(t.Context(), dir, SnapshotOptions{ExternalCommitSHA: "deadbeef"})
	if err == nil {
		t.Fatal("snapshot with escaping symlink was accepted")
	}
}

func TestSnapshot_GitPathSetsContentHash(t *testing.T) {
	// The regular path still resolves the commit from git and sets ContentHash,
	// while keeping external-only fields unset.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	initGitRepo(t, dir)

	snap, err := Service{}.Snapshot(t.Context(), dir, SnapshotOptions{})
	if err != nil {
		t.Fatalf("git snapshot failed: %v", err)
	}
	if snap.Commit == "" {
		t.Fatal("git commit not resolved")
	}
	if snap.ExternalCommitSHA != "" {
		t.Fatalf("external sha set on git path: %q", snap.ExternalCommitSHA)
	}
	if snap.ContentHash == "" {
		t.Fatal("content hash not computed for git snapshot")
	}
}

func TestProductSnapshot_OldJSONReadsWithoutNewFields(t *testing.T) {
	// Restartable cases persisted before these fields existed must still load.
	legacy := []byte(`{"repository":"/tmp/x","commit":"abc","go_version":"go version go1.22 linux/amd64","go_mod_directive":"1.21","goos":"linux","goarch":"amd64"}`)
	var snap domain.ProductSnapshot
	if err := json.Unmarshal(legacy, &snap); err != nil {
		t.Fatalf("legacy JSON rejected: %v", err)
	}
	if snap.MinimumGoVersion != "" || snap.ExternalCommitSHA != "" || snap.GoVersionSource != "" {
		t.Fatalf("unexpected new fields from legacy JSON: %+v", snap)
	}
	// New zero values must not be read as a known release.
	if snap.ReleaseGoVersion != "" {
		t.Fatalf("release version read from legacy: %q", snap.ReleaseGoVersion)
	}
	// Legacy snapshots predate the trust-class fields: no evidence record,
	// no release module graph, no explicit-evidence request marker.
	if snap.ReleaseEvidence != nil {
		t.Fatalf("release evidence read from legacy: %+v", snap.ReleaseEvidence)
	}
	if len(snap.ReleaseModules) != 0 {
		t.Fatalf("release modules read from legacy: %+v", snap.ReleaseModules)
	}
	if snap.ReleaseEvidenceRequired {
		t.Fatal("release_evidence_required read from legacy")
	}
}
func TestContentManifest_CaptureAndValidateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "b.txt"), "bravo")
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeFile(t, filepath.Join(dir, "sub", "c.txt"), "charlie")

	expectedHash, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := CaptureContentManifest(dir)
	if err != nil {
		t.Fatalf("CaptureContentManifest failed: %v", err)
	}

	entries, err := ValidateContentManifest(raw, expectedHash)
	if err != nil {
		t.Fatalf("ValidateContentManifest failed: %v", err)
	}

	// Entries should be sorted: a.txt, b.txt, sub (dir), sub/c.txt
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
	wantPaths := []string{"a.txt", "b.txt", "sub", "sub/c.txt"}
	wantKinds := []string{"file", "file", "dir", "file"}
	for i, e := range entries {
		if e.Path != wantPaths[i] {
			t.Errorf("entry[%d].Path = %q, want %q", i, e.Path, wantPaths[i])
		}
		if e.Kind != wantKinds[i] {
			t.Errorf("entry[%d].Kind = %q, want %q", i, e.Kind, wantKinds[i])
		}
	}
}

func TestContentManifest_ReplayWithoutOriginalTree(t *testing.T) {
	// Smoke check: capture manifest from tree, delete the original tree completely,
	// validate manifest against expectedContentHash without the original tree available.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pkg", "lib.go"), "package pkg\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")

	expectedHash, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := CaptureContentManifest(dir)
	if err != nil {
		t.Fatalf("CaptureContentManifest failed: %v", err)
	}

	// Delete original directory to prove replay/validation works offline
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	entries, err := ValidateContentManifest(raw, expectedHash)
	if err != nil {
		t.Fatalf("ValidateContentManifest failed when tree is removed: %v", err)
	}
	if len(entries) != 3 { // main.go, pkg, pkg/lib.go
		t.Fatalf("entries count = %d, want 3", len(entries))
	}
}

func TestContentManifest_MutationTamperAndRepinnedFail(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeFile(t, filepath.Join(dir, "b.txt"), "bravo")

	expectedHash, err := ContentHash(dir)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := CaptureContentManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Wrong expected hash (mismatch)
	if _, err := ValidateContentManifest(raw, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("ValidateContentManifest accepted wrong expected hash")
	}

	// 2. Tampered byte in payload (manifest content tampered)
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[len(tampered)-2] ^= 0x01
	if _, err := ValidateContentManifest(tampered, expectedHash); err == nil {
		t.Fatal("ValidateContentManifest accepted tampered manifest bytes")
	}

	// 3. Alternative repinned bytes (someone replaces payload and recomputes expected hash)
	// Let's create an alternative manifest that changes a file's content
	dirAlt := t.TempDir()
	writeFile(t, filepath.Join(dirAlt, "a.txt"), "hacked")
	writeFile(t, filepath.Join(dirAlt, "b.txt"), "bravo")
	altRaw, err := CaptureContentManifest(dirAlt)
	if err != nil {
		t.Fatal(err)
	}
	// Alt manifest with original expectedHash must fail
	if _, err := ValidateContentManifest(altRaw, expectedHash); err == nil {
		t.Fatal("ValidateContentManifest accepted repinned alternative bytes under original hash")
	}
}

func TestContentManifest_RejectMalformedFramingAndPaths(t *testing.T) {
	validDir := t.TempDir()
	writeFile(t, filepath.Join(validDir, "a.txt"), "alpha")
	validHash, _ := ContentHash(validDir)
	validRaw, _ := CaptureContentManifest(validDir)

	// Empty manifest
	if _, err := ValidateContentManifest(nil, validHash); err == nil {
		t.Fatal("accepted nil raw")
	}
	if _, err := ValidateContentManifest([]byte{}, validHash); err == nil {
		t.Fatal("accepted empty raw")
	}
	// Empty expected hash
	if _, err := ValidateContentManifest(validRaw, ""); err == nil {
		t.Fatal("accepted empty expected hash")
	}

	// Header version mismatch
	badHeader := []byte("t2\na.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\n")
	h := sha256.Sum256(badHeader)
	if _, err := ValidateContentManifest(badHeader, hex.EncodeToString(h[:])); err == nil {
		t.Fatal("accepted bad version header")
	}

	// Control characters in path (e.g. newline or null byte)
	badPath := []byte("t1\na\x00.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\n")
	h = sha256.Sum256(badPath)
	if _, err := ValidateContentManifest(badPath, hex.EncodeToString(h[:])); err == nil {
		t.Fatal("accepted control character in path")
	}

	// Escaping path "../x"
	escapePath := []byte("t1\n../escape.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\n")
	h = sha256.Sum256(escapePath)
	if _, err := ValidateContentManifest(escapePath, hex.EncodeToString(h[:])); err == nil {
		t.Fatal("accepted escaping path")
	}

	// Out-of-order paths
	outOfOrder := []byte("t1\nb.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\na.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\n")
	h = sha256.Sum256(outOfOrder)
	if _, err := ValidateContentManifest(outOfOrder, hex.EncodeToString(h[:])); err == nil {
		t.Fatal("accepted out-of-order manifest")
	}

	// Duplicate paths
	duplicate := []byte("t1\na.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\na.txt\tfile\t0\t5\t8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465\n")
	h = sha256.Sum256(duplicate)
	if _, err := ValidateContentManifest(duplicate, hex.EncodeToString(h[:])); err == nil {
		t.Fatal("accepted duplicate paths in manifest")
	}

	// Invalid file sha256 digest format
	badDigest := []byte("t1\na.txt\tfile\t0\t5\tnot-a-valid-hex-digest\n")
	h = sha256.Sum256(badDigest)
	if _, err := ValidateContentManifest(badDigest, hex.EncodeToString(h[:])); err == nil {
		t.Fatal("accepted invalid sha256 hex digest")
	}
}

func TestContentManifest_RejectOriginalAmbiguousPaths(t *testing.T) {
	// Without original-name validation this single symlink encodes a fake
	// regular a.go entry followed by a symlink z under the acquired root hash.
	digest := "8ed3b7279f18f0b5165614ff3369c514d04144372965248515e047293f342465"
	// macOS rejects invalid UTF-8 at filesystem creation; test that encoding
	// directly rather than claiming to have created an invalid on-disk name.
	if err := validateManifestPath("invalid\xff"); err == nil {
		t.Fatal("accepted invalid UTF-8 path")
	}
	for _, name := range []string{
		"a.go\tfile\t0\t5\t" + digest + "\nz",
		"tab\tname", "line\nname", "carriage\rname", "back\\slash",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")
			initGitRepo(t, root)
			if err := os.Symlink("missing", filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
			if err := VerifyContained(root); err != nil {
				t.Fatalf("inert missing-target link should pass containment: %v", err)
			}
			if _, err := ContentHash(root); err == nil {
				t.Fatal("independent root acquisition accepted ambiguous original name")
			}
			if _, err := CaptureContentManifest(root); err == nil {
				t.Fatal("capture accepted ambiguous original name")
			}
			if _, err := (Service{}).Snapshot(t.Context(), root, SnapshotOptions{}); err == nil {
				t.Fatal("native snapshot acquired identity for ambiguous original name")
			}
		})
	}
}

func TestSnapshot_SymlinkRootTracksSourceMutationAndOfflineReplay(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\nfunc main() {}\n")
	initGitRepo(t, root)
	alias := filepath.Join(t.TempDir(), "source")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	before, err := (Service{}).Snapshot(t.Context(), alias, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	directHash, err := ContentHash(root)
	if err != nil || before.ContentHash != directHash {
		t.Fatalf("root alias identity = %s, direct = %s, err = %v", before.ContentHash, directHash, err)
	}
	raw, err := CaptureContentManifest(alias)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(alias, "main.go"), "package main\nfunc main() { println(1) }\n")
	after, err := (Service{}).Snapshot(t.Context(), alias, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if after.Commit != before.Commit || after.ContentHash == before.ContentHash {
		t.Fatal("source mutation at unchanged HEAD did not change symlink-root identity")
	}
	mutatedRaw, err := CaptureContentManifest(alias)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateContentManifest(mutatedRaw, before.ContentHash); err == nil {
		t.Fatal("mutated source manifest admitted under acquired original root")
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(alias); !os.IsNotExist(err) {
		t.Fatalf("original source unexpectedly available: %v", err)
	}
	entries, err := ValidateContentManifest(raw, before.ContentHash)
	if err != nil || len(entries) != 2 {
		t.Fatalf("offline original replay: entries = %v, err = %v", entries, err)
	}
}
