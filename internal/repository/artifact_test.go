package repository

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

// testBinary returns a real Go binary path: the running test binary.
func testBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("test binary unavailable: %v", err)
	}
	return exe
}

// buildTestBinary compiles a minimal module binary into dir — a second,
// inventory-distinct Go binary for conflict and preference cases.
func buildTestBinary(t *testing.T, dir, modulePath string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, "go.mod"), "module "+modulePath+"\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	out := filepath.Join(dir, "tool")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY=off", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable: %v: %s", err, b)
	}
	return out
}

// buildTestBinaryFor compiles a minimal module binary for an explicit
// target and build-tag set, so artifact target extraction is exercised
// against real debug.BuildInfo.Settings.
func buildTestBinaryFor(t *testing.T, dir, modulePath, goos, goarch, tags string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, "go.mod"), "module "+modulePath+"\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	out := filepath.Join(dir, "tool-"+goos+"-"+goarch)
	args := []string{"build", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY=off", "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable: %v: %s", err, b)
	}
	return out
}

type zipEntrySpec struct {
	name    string
	content []byte
	mode    os.FileMode // 0 => regular 0644
	stored  bool        // store uncompressed (nested bundle members)
}

func buildZipBytes(t *testing.T, entries []zipEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.stored {
			h.Method = zip.Store
		}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("zip entry %q: %v", e.name, err)
		}
		if _, err := w.Write(e.content); err != nil {
			t.Fatalf("zip entry %q write: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func writeZipFile(t *testing.T, path string, entries []zipEntrySpec) {
	t.Helper()
	if err := os.WriteFile(path, buildZipBytes(t, entries), 0o600); err != nil {
		t.Fatalf("write zip %s: %v", path, err)
	}
}

func artifactOpts(dir string) ArtifactOptions {
	return ArtifactOptions{CacheDir: filepath.Join(dir, "cache")}
}

// patchZipUncompressedSize rewrites the central-directory uncompressed
// size of every entry to the given value, leaving the local headers and
// the real payload untouched — a malformed archive whose declared size
// lies about its content.
func patchZipUncompressedSize(t *testing.T, data []byte, declared uint32) []byte {
	t.Helper()
	out := append([]byte(nil), data...)
	patched := 0
	for i := 0; i+30 <= len(out); i++ {
		if out[i] != 'P' || out[i+1] != 'K' || out[i+2] != 0x01 || out[i+3] != 0x02 {
			continue
		}
		binary.LittleEndian.PutUint32(out[i+24:i+28], declared)
		patched++
		i += 29
	}
	if patched == 0 {
		t.Fatal("no central-directory record patched")
	}
	return out
}

// A member whose central directory claims more content than the entry
// actually holds is a malformed archive; the truncated payload must be
// rejected rather than inspected as if complete.
func TestReleaseArtifact_ZipMemberShorterThanDeclared(t *testing.T) {
	dir := t.TempDir()
	content := []byte("short-payload")
	lied := patchZipUncompressedSize(t,
		buildZipBytes(t, []zipEntrySpec{{name: "pkg/bin/app", content: content, stored: true}}),
		uint32(len(content)+64))
	path := filepath.Join(dir, "lying.zip")
	if err := os.WriteFile(path, lied, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := artifactOpts(dir)
	opts.Path = path
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactArchiveUnsafe)
}

// The cache directory guard must survive symlinks: a cache path whose
// parent links into the snapshot would place extracted artifact data in
// forbidden ground.
func TestPrepareArtifactCache_SymlinkedCacheDirRefused(t *testing.T) {
	base := t.TempDir()
	snapshot := filepath.Join(base, "snapshot")
	if err := os.MkdirAll(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "cache-link")
	if err := os.MkdirAll(filepath.Join(snapshot, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(snapshot, "cache"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := prepareArtifactCache(ArtifactOptions{CacheDir: link, ForbidDirs: []string{snapshot}})
	if err == nil {
		t.Fatal("cache dir symlinked into the snapshot must be refused")
	}
	if !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("err = %v", err)
	}
}

// Provenance never records the operator's absolute path: the basename
// anchors the input and the digest anchors its content.
func TestReleaseArtifact_ProvenanceOmitsPrivatePaths(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	opts := artifactOpts(dir)
	opts.Path = exe
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("resolve = %s/%q err=%v", res.Status, res.Reason, err)
	}
	if got := res.Evidence.ArtifactSHA256; got == "" {
		t.Fatal("missing artifact digest")
	}
	for _, it := range res.Evidence.Items {
		if strings.Contains(it.Location, dir) || strings.Contains(it.Location, string(filepath.Separator)+"..") {
			t.Fatalf("path leaked into provenance: %+v", it)
		}
	}
	if res.Evidence.Items[0].Location != ProvenanceLocalRef(exe) {
		t.Fatalf("location = %q", res.Evidence.Items[0].Location)
	}
}

func wantReason(t *testing.T, res ArtifactResolution, err error, status domain.ReleaseEvidenceStatus, reason string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != status || res.Reason != reason {
		t.Fatalf("resolution = %s/%q, want %s/%s", res.Status, res.Reason, status, reason)
	}
	if res.Evidence.Status != status || res.Evidence.ReasonCode != reason {
		t.Fatalf("evidence = %s/%q, want %s/%s", res.Evidence.Status, res.Evidence.ReasonCode, status, reason)
	}
	if status == domain.ReleaseStatusNotRun && res.Evidence.SelectedVersion != "" {
		t.Fatalf("failed channel selected version %q", res.Evidence.SelectedVersion)
	}
}

func TestReleaseArtifact_NotRequested(t *testing.T) {
	res, err := ResolveReleaseArtifact(context.Background(), ArtifactOptions{})
	wantReason(t, res, err, domain.ReleaseStatusNotRequested, domain.ReleaseReasonArtifactNotRequested)
}

func TestReleaseArtifact_MutuallyExclusiveInputs(t *testing.T) {
	dir := t.TempDir()
	opts := artifactOpts(dir)
	opts.Path = filepath.Join(dir, "a.bin")
	opts.URL = "https://example.invalid/a.zip"
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactURLInvalid)
}

func TestReleaseArtifact_PlainBinary(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	opts := artifactOpts(dir)
	opts.Path = exe
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", res.Status, res.Reason)
	}
	sum := res.Evidence
	if sum.SelectedTrust != domain.ReleaseTrustAuthoritative || !strings.HasPrefix(sum.SelectedVersion, "go") {
		t.Fatalf("selection = %+v", sum)
	}
	if sum.ArtifactSHA256 == "" || sum.BuildInfoSHA256 == "" {
		t.Fatalf("missing digests: %+v", sum)
	}
	wantSHA, _, _ := hashFileSHA256(context.Background(), exe)
	if sum.ArtifactSHA256 != wantSHA {
		t.Fatalf("artifact sha = %s, want %s", sum.ArtifactSHA256, wantSHA)
	}
	if len(sum.Modules) == 0 || !sum.Modules[0].Main {
		t.Fatalf("release modules = %+v", sum.Modules)
	}
	it := itemAt(t, sum.Items, domain.GoVersionSourceBinary)
	// Provenance records only the basename: the operator's absolute path
	// is machine-specific and must not reach reports or manifests.
	if it.TrustClass != domain.ReleaseTrustAuthoritative ||
		it.Location != ProvenanceLocalRef(exe) ||
		strings.Contains(it.Location, filepath.Dir(exe)) {
		t.Fatalf("binary item = %+v", it)
	}
	// A bare binary needs no cache slot.
	if _, err := os.Stat(filepath.Join(opts.CacheDir, sum.ArtifactSHA256)); !os.IsNotExist(err) {
		t.Fatal("plain local binary created a cache slot")
	}
}

// The artifact's build-target facts come from debug.BuildInfo.Settings and
// are bound to the artifact SHA-256, the binary member and the build-info
// digest. Nothing here may fall back to the analyzer host.
func TestReleaseArtifact_TargetBoundToBuildInfo(t *testing.T) {
	dir := t.TempDir()
	exe := buildTestBinaryFor(t, dir, "example.com/targeted", "linux", "amd64", "netgo,osusergo")
	opts := artifactOpts(dir)
	opts.Path = exe
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", res.Status, res.Reason)
	}
	target := res.Target
	if target == nil {
		t.Fatalf("artifact target missing: %+v", res.Evidence)
	}
	if target.GOOS != "linux" || target.GOARCH != "amd64" {
		t.Fatalf("target platform = %s/%s", target.GOOS, target.GOARCH)
	}
	if target.CGOEnabled {
		t.Fatal("CGO_ENABLED=0 build recorded cgo enabled")
	}
	if strings.Join(target.BuildTags, ",") != "netgo,osusergo" {
		t.Fatalf("target tags = %v", target.BuildTags)
	}
	if target.Source != domain.ProductTargetSourceArtifactBuildInfo || target.Scope != domain.ProductTargetScopeArtifact {
		t.Fatalf("target provenance = %+v", target)
	}
	wantSHA, _, err := hashFileSHA256(context.Background(), exe)
	if err != nil {
		t.Fatal(err)
	}
	if target.ArtifactSHA256 != wantSHA {
		t.Fatalf("target artifact sha = %q, want %q", target.ArtifactSHA256, wantSHA)
	}
	if target.BuildInfoSHA256 == "" || len(target.BuildInfoSHA256) != 64 {
		t.Fatalf("target build-info digest = %q", target.BuildInfoSHA256)
	}
	if err := target.Validate(); err != nil {
		t.Fatalf("recorded target does not validate: %v", err)
	}
	if res.Evidence.Target == nil ||
		res.Evidence.Target.GOOS != target.GOOS ||
		res.Evidence.Target.GOARCH != target.GOARCH ||
		res.Evidence.Target.CGOEnabled != target.CGOEnabled ||
		res.Evidence.Target.Source != target.Source ||
		res.Evidence.Target.Scope != target.Scope ||
		res.Evidence.Target.ArtifactSHA256 != target.ArtifactSHA256 ||
		res.Evidence.Target.BuildInfoSHA256 != target.BuildInfoSHA256 ||
		res.Evidence.Target.BinaryMember != target.BinaryMember ||
		strings.Join(res.Evidence.Target.BuildTags, ",") != strings.Join(target.BuildTags, ",") {
		t.Fatalf("summary target = %+v, resolution target = %+v", res.Evidence.Target, target)
	}
	// The target digest is the selected binary's digest, the same one the
	// authoritative build-info evidence item pins.
	it := itemAt(t, res.Evidence.Items, domain.GoVersionSourceBinary)
	if target.BuildInfoSHA256 != it.BuildInfoSHA256 || target.BinaryMember != it.BinaryMember {
		t.Fatalf("target digest/member %q/%q != evidence item %q/%q",
			target.BuildInfoSHA256, target.BinaryMember, it.BuildInfoSHA256, it.BinaryMember)
	}
}

func TestReleaseArtifact_PathMissing(t *testing.T) {
	dir := t.TempDir()
	opts := artifactOpts(dir)
	opts.Path = filepath.Join(dir, "no-such")
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactPathMissing)
}

func TestReleaseArtifact_PathDirectory(t *testing.T) {
	dir := t.TempDir()
	opts := artifactOpts(dir)
	opts.Path = dir
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactPathUnreadable)
}

func TestReleaseArtifact_BuildInfoAbsence(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "notgo.bin")
	writeFile(t, bin, strings.Repeat("not a go binary", 100))
	opts := artifactOpts(dir)
	opts.Path = bin
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactBuildInfoUnreadable)
}

func TestReleaseArtifact_Timeout(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	opts := artifactOpts(dir)
	opts.Path = exe
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	res, err := ResolveReleaseArtifact(ctx, opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactTimeout)
}

func TestReleaseArtifact_ZipSingleBinary(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	zipPath := filepath.Join(dir, "dist.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "README", content: []byte("docs")},
		{name: "bin/tool", content: readFileBytes(t, exe)},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", res.Status, res.Reason)
	}
	if res.Evidence.BinaryMember != "bin/tool" {
		t.Fatalf("member = %q", res.Evidence.BinaryMember)
	}
	wantSHA, _, _ := hashFileSHA256(context.Background(), zipPath)
	if res.Evidence.ArtifactSHA256 != wantSHA {
		t.Fatalf("artifact sha = %s, want %s", res.Evidence.ArtifactSHA256, wantSHA)
	}
	// Extraction landed in the external cache, never next to the source.
	if _, err := os.Stat(filepath.Join(opts.CacheDir, wantSHA, "tree")); err != nil {
		t.Fatalf("cache tree missing: %v", err)
	}
}

func TestReleaseArtifact_NestedStoredZip(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	// A distribution bundle carries component zips; stored members are
	// readable through seekable windows — here simply nested on disk.
	inner := buildZipBytes(t, []zipEntrySpec{
		{name: "pkg/tool", content: readFileBytes(t, exe)},
		{name: "notes.json", content: []byte("{}")},
	})
	zipPath := filepath.Join(dir, "bundle.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "manifest.json", content: []byte("{}")},
		{name: "dist/component.zip", content: inner, stored: true},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", res.Status, res.Reason)
	}
	if res.Evidence.BinaryMember != "dist/component.zip/pkg/tool" {
		t.Fatalf("nested member = %q", res.Evidence.BinaryMember)
	}
	if len(res.Evidence.Modules) == 0 {
		t.Fatal("nested binary produced no module list")
	}
}

func TestReleaseArtifact_ZipEquivalentBinaries(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	content := readFileBytes(t, exe)
	zipPath := filepath.Join(dir, "multi.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "z/tool", content: content},
		{name: "a/tool", content: content},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", res.Status, res.Reason)
	}
	// Byte-equivalent inventories: lexical first is selected, all recorded.
	if res.Evidence.BinaryMember != "a/tool" {
		t.Fatalf("selected = %q, want lexical first", res.Evidence.BinaryMember)
	}
	if len(res.Evidence.Items) != 2 {
		t.Fatalf("recorded items = %+v", res.Evidence.Items)
	}
}

func TestReleaseArtifact_ZipConflictingBinaries(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	other := buildTestBinary(t, filepath.Join(dir, "modsrc"), "example.com/built")
	zipPath := filepath.Join(dir, "conflict.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "a/tool", content: readFileBytes(t, exe)},
		{name: "b/tool", content: readFileBytes(t, other)},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactAmbiguousBinary)
	if len(res.Evidence.Items) != 2 {
		t.Fatalf("ambiguous pool not recorded: %+v", res.Evidence.Items)
	}
	if res.Evidence.ArtifactSHA256 == "" {
		t.Fatal("artifact sha missing on ambiguous outcome")
	}
}

func TestReleaseArtifact_ZipProductModulePreferred(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	other := buildTestBinary(t, filepath.Join(dir, "modsrc"), "example.com/product")
	zipPath := filepath.Join(dir, "pref.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "aaa/tool", content: readFileBytes(t, exe)},
		{name: "zzz/tool", content: readFileBytes(t, other)},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	opts.ProductModule = "example.com/product"
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The product-module match wins over lexical order.
	if res.Status != domain.ReleaseStatusResolved || res.Evidence.BinaryMember != "zzz/tool" {
		t.Fatalf("selection = %s %q", res.Status, res.Evidence.BinaryMember)
	}
	if len(res.Evidence.Modules) == 0 || res.Evidence.Modules[0].Path != "example.com/product" {
		t.Fatalf("release modules = %+v", res.Evidence.Modules)
	}
}

func TestReleaseArtifact_ZipTraversal(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	for _, name := range []string{"../evil", "x/../../evil", "/abs/path", `C:\evil`} {
		zipPath := filepath.Join(dir, "slip.zip")
		writeZipFile(t, zipPath, []zipEntrySpec{
			{name: name, content: []byte("x")},
			{name: "bin/tool", content: readFileBytes(t, exe)},
		})
		opts := artifactOpts(dir)
		opts.Path = zipPath
		res, err := ResolveReleaseArtifact(context.Background(), opts)
		wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactArchiveUnsafe)
		os.Remove(zipPath)
	}
}

func TestReleaseArtifact_ZipSymlink(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	zipPath := filepath.Join(dir, "link.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "link", content: []byte("/etc/passwd"), mode: os.ModeSymlink | 0o777},
		{name: "bin/tool", content: readFileBytes(t, exe)},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactArchiveUnsafe)
}

func TestReleaseArtifact_ZipExtractedSizeLimit(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "big.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "payload", content: bytes.Repeat([]byte("x"), 4096)},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	opts.MaxExtractedBytes = 1024
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactSizeLimit)
}

func TestReleaseArtifact_ZipEntryLimit(t *testing.T) {
	dir := t.TempDir()
	var entries []zipEntrySpec
	for i := range 5 {
		entries = append(entries, zipEntrySpec{name: "f" + itoa(i), content: []byte("x")})
	}
	zipPath := filepath.Join(dir, "many.zip")
	writeZipFile(t, zipPath, entries)
	opts := artifactOpts(dir)
	opts.Path = zipPath
	opts.MaxArchiveEntries = 3
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactSizeLimit)
}

func TestReleaseArtifact_ZipNoGoBinary(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "data.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "data.txt", content: []byte("hello")},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactNoGoBinary)
}

func TestReleaseArtifact_ZipCorrupt(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "corrupt.zip")
	if err := os.WriteFile(zipPath, []byte("PK\x03\x04broken-zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactArchiveUnsafe)
}

func TestReleaseArtifact_CacheReuseLocalZip(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	zipPath := filepath.Join(dir, "dist.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "bin/tool", content: readFileBytes(t, exe)},
	})
	opts := artifactOpts(dir)
	opts.Path = zipPath
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("first resolve = %s/%q err=%v", res.Status, res.Reason, err)
	}
	sha := res.Evidence.ArtifactSHA256
	slot := filepath.Join(opts.CacheDir, sha)
	// Make the slot read-only: a second resolution that re-extracted would
	// fail to replace the tree; success proves the cache was reused.
	if err := os.Chmod(slot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(slot, 0o700) })
	res, err = ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("cache reuse failed = %s/%q err=%v", res.Status, res.Reason, err)
	}
	if res.Evidence.ArtifactSHA256 != sha {
		t.Fatalf("reused sha = %s", res.Evidence.ArtifactSHA256)
	}
}

func TestReleaseArtifact_CacheDirInsideForbidden(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	opts := artifactOpts(dir)
	opts.Path = exe
	opts.ForbidDirs = []string{dir}
	_, err := ResolveReleaseArtifact(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("cache inside snapshot accepted: %v", err)
	}
}

// A requested ZIP artifact resolves into the snapshot's release evidence:
// authoritative build info, artifact/member digests, and the release
// module graph travel on the snapshot.
func TestSnapshot_ReleaseArtifactZip(t *testing.T) {
	dir := snapshotFixture(t)
	exe := testBinary(t)
	zipPath := filepath.Join(t.TempDir(), "dist.zip")
	writeZipFile(t, zipPath, []zipEntrySpec{
		{name: "bin/tool", content: readFileBytes(t, exe)},
	})
	opts := snapshotOpts()
	opts.Artifact = ArtifactOptions{Path: zipPath, CacheDir: filepath.Join(t.TempDir(), "cache")}

	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", snap.ReleaseEvidence.Status, snap.ReleaseEvidence.ReasonCode)
	}
	if snap.ReleaseEvidence.BinaryMember != "bin/tool" || snap.ReleaseEvidence.ArtifactSHA256 == "" {
		t.Fatalf("artifact provenance = %+v", snap.ReleaseEvidence)
	}
	if len(snap.ReleaseModules) == 0 {
		t.Fatal("release module graph not recorded on snapshot")
	}
	if !snap.ReleaseEvidenceRequired {
		t.Fatal("requested artifact not marked required")
	}
}

func TestSnapshot_ReleaseArtifactFailClosed(t *testing.T) {
	dir := snapshotFixture(t)
	opts := snapshotOpts()
	opts.Artifact = ArtifactOptions{
		Path:     filepath.Join(dir, "missing.zip"),
		CacheDir: filepath.Join(t.TempDir(), "cache"),
	}

	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusNotRun {
		t.Fatalf("status = %s", snap.ReleaseEvidence.Status)
	}
	if snap.ReleaseEvidence.ReasonCode != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("reason = %q", snap.ReleaseEvidence.ReasonCode)
	}
	if snap.ReleaseGoVersion != "" {
		t.Fatalf("release version populated despite failed artifact: %q", snap.ReleaseGoVersion)
	}
	if !snap.ReleaseEvidenceRequired {
		t.Fatal("requested artifact not marked required")
	}
}

// marshaledResolution serializes the resolution the way a report would;
// credential tests scan it for leaks.
func marshaledResolution(t *testing.T, res ArtifactResolution) string {
	t.Helper()
	b, err := json.Marshal(res.Evidence)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// The provenance label never carries path structure, whatever the
// operator typed.
func TestProvenanceLocalRefSanitizesStructure(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "local:input"},
		{"..", "local:input"},
		{".", "local:input"},
		{"", "local:input"},
		{"/tmp/x/release.zip", "local:release.zip"},
		{"  /tmp/x/app  ", "local:app"},
	} {
		if got := ProvenanceLocalRef(tc.in); got != tc.want {
			t.Fatalf("ProvenanceLocalRef(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestArtifactCacheRejectsSymlinkedMember(t *testing.T) {
	dir := t.TempDir()
	slot := filepath.Join(dir, "slot")
	tree := filepath.Join(slot, "tree", "m")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(tree, "member")
	if err := os.Symlink(target, member); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	meta := &artifactMeta{SHA256: "sha", Members: []artifactMember{{Path: "m/member", Size: 7, SHA256: "bad"}}}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "meta.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readArtifactMeta(slot, "sha", false); got != nil {
		t.Fatal("symlinked member trusted")
	}
}

func TestArtifactCacheRejectsHardLinkedMember(t *testing.T) {
	dir := t.TempDir()
	slot := filepath.Join(dir, "slot")
	tree := filepath.Join(slot, "tree", "m")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(tree, "member")
	if err := os.Link(target, member); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	sha, size, err := hashFileSHA256(context.Background(), member)
	if err != nil {
		t.Fatal(err)
	}
	meta := &artifactMeta{SHA256: "sha", Members: []artifactMember{{Path: "m/member", Size: size, SHA256: sha}}}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "meta.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readArtifactMeta(slot, "sha", false); got != nil {
		t.Fatal("hard-linked member trusted")
	}
}

func TestPrepareArtifactCache_CaseVariedForbiddenPath(t *testing.T) {
	dir := t.TempDir()
	forbid := filepath.Join(dir, "Snapshot")
	if err := os.MkdirAll(forbid, 0o700); err != nil {
		t.Fatal(err)
	}
	variant := filepath.Join(dir, "snapshot")
	if _, err := os.Stat(variant); err != nil {
		t.Skipf("filesystem is case-sensitive: %v", err)
	}
	cache := filepath.Join(variant, "cache")
	if _, err := prepareArtifactCache(ArtifactOptions{CacheDir: cache, ForbidDirs: []string{forbid}}); err == nil {
		t.Fatal("case-varied cache path inside forbidden root accepted")
	}
}

func TestProvenanceLocalRefRejectsControlCharacter(t *testing.T) {
	if got := ProvenanceLocalRef("/tmp/release\x00.zip"); got != "local:input" {
		t.Fatalf("control-character basename = %q", got)
	}
}
