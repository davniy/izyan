package vexbench_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/vexbench"
)

// fixtureFetcher serves OSV documents from testdata/advisory/<id>.json;
// a missing file simulates a transport failure.
func fixtureFetcher(ctx context.Context, id string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join("testdata", "advisory", id+".json"))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", id, err)
	}
	return b, nil
}

func dirEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ents
}

func TestPrepareAdvisoryUsable(t *testing.T) {
	dir := t.TempDir()
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0001", dir, fixtureFetcher)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable {
		t.Fatalf("outcome=%v want usable (%q)", res.Outcome, res.Reason)
	}
	if res.Source != "osv:vulns/CVE-2099-0001" || res.Resolved != "CVE-2099-0001" {
		t.Fatalf("source=%q resolved=%q", res.Source, res.Resolved)
	}
	if res.Path == "" || filepath.Dir(res.Path) != dir {
		t.Fatalf("path %q not inside %s", res.Path, dir)
	}
	saved, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(saved)
	if res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 %q does not match saved bytes", res.SHA256)
	}
	if n := len(dirEntries(t, dir)); n != 1 {
		t.Fatalf("advisory dir must hold exactly one file, got %d", n)
	}
}

func TestPrepareAdvisoryPartial(t *testing.T) {
	// Counterexample F07: one usable Go entry plus a Go entry with GIT-only
	// ranges → partial; the document is still saved, never turned into
	// usable (the unbacked entry must not become VersionAffected=FALSE).
	dir := t.TempDir()
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0002", dir, fixtureFetcher)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryPartial {
		t.Fatalf("outcome=%v want partial (%q)", res.Outcome, res.Reason)
	}
	if res.Path == "" || res.SHA256 == "" {
		t.Fatalf("partial must still save the document: %+v", res)
	}
	if n := len(dirEntries(t, dir)); n != 1 {
		t.Fatalf("advisory dir must hold exactly one file, got %d", n)
	}
}

func TestPrepareAdvisoryUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name, cve string
	}{
		{"imports without ranges", "CVE-2099-0004"},
		{"semver without events", "CVE-2099-0005"},
		{"non-Go ecosystem", "CVE-2099-0006"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			res, err := vexbench.PrepareAdvisory(context.Background(), tc.cve, dir, fixtureFetcher)
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != vexbench.AdvisoryUnsupported {
				t.Fatalf("outcome=%v want unsupported", res.Outcome)
			}
			if res.Reason == "" || res.Path != "" {
				t.Fatalf("unsupported: reason=%q path=%q", res.Reason, res.Path)
			}
			if n := len(dirEntries(t, dir)); n != 0 {
				t.Fatalf("unsupported must save nothing, got %d files", n)
			}
		})
	}
}

func TestPrepareAdvisoryAliasFallback(t *testing.T) {
	dir := t.TempDir()
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0003", dir, fixtureFetcher)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable {
		t.Fatalf("outcome=%v want usable via alias (%q)", res.Outcome, res.Reason)
	}
	if res.Resolved != "GO-2099-0003" || !strings.Contains(res.Source, "GO-2099-0003") {
		t.Fatalf("alias doc must be the saved one: %+v", res)
	}
	saved, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "advisory", "GO-2099-0003.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != string(want) {
		t.Fatal("saved document is not the GO alias bytes")
	}
}

func TestPrepareAdvisoryDirectBeatsAlias(t *testing.T) {
	// Direct document is usable: aliases must not even be fetched.
	var fetched []string
	fetch := func(ctx context.Context, id string) ([]byte, error) {
		fetched = append(fetched, id)
		return fixtureFetcher(ctx, id)
	}
	dir := t.TempDir()
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0010", dir, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable || res.Resolved != "CVE-2099-0010" {
		t.Fatalf("outcome=%v resolved=%q", res.Outcome, res.Resolved)
	}
	if len(fetched) != 1 || fetched[0] != "CVE-2099-0010" {
		t.Fatalf("alias fetched unnecessarily: %v", fetched)
	}
}

func TestPrepareAdvisoryContinuesPastUnusableAndFailedAliases(t *testing.T) {
	// First GO-* alias unusable → second alias saved.
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0012", t.TempDir(), fixtureFetcher)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable || res.Resolved != "CVE-2099-0013" {
		t.Fatalf("outcome=%v resolved=%q, want usable via CVE-2099-0013", res.Outcome, res.Resolved)
	}
	// First GO-* alias fails to fetch → later usable alias still wins.
	res, err = vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0014", t.TempDir(), fixtureFetcher)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable || res.Resolved != "GO-2099-0015" {
		t.Fatalf("outcome=%v resolved=%q, want usable via GO-2099-0015", res.Outcome, res.Resolved)
	}
}

func TestPrepareAdvisoryErrors(t *testing.T) {
	for _, tc := range []struct {
		name, cve string
	}{
		{"transport", "CVE-2099-0008"},     // no fixture → fetch error
		{"parse", "CVE-2099-0007"},         // invalid JSON
		{"identity", "CVE-2099-0009"},      // id matches neither request nor aliases
		{"alias failure", "CVE-2099-0011"}, // only alias unfetchable
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			res, err := vexbench.PrepareAdvisory(context.Background(), tc.cve, dir, fixtureFetcher)
			if err != nil {
				t.Fatalf("advisory-level failures return a result, not an error: %v", err)
			}
			if res.Outcome != vexbench.AdvisoryError {
				t.Fatalf("outcome=%v want error", res.Outcome)
			}
			if res.Reason == "" || res.Path != "" {
				t.Fatalf("error outcome: reason=%q path=%q", res.Reason, res.Path)
			}
		})
	}
}

func TestPrepareFrozenAdvisoryNoNetworkAndMissing(t *testing.T) {
	root := t.TempDir()
	body, err := os.ReadFile(filepath.Join("testdata", "advisory", "CVE-2099-0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "CVE-2099-0001.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := vexbench.PrepareFrozenAdvisory(context.Background(), "CVE-2099-0001", t.TempDir(), root)
	if err != nil || res.Outcome != vexbench.AdvisoryUsable {
		t.Fatalf("frozen result: %+v err=%v", res, err)
	}
	if res.SHA256 == "" || res.CanonicalSHA256 == "" {
		t.Fatalf("digests missing: %+v", res)
	}
	missing, err := vexbench.PrepareFrozenAdvisory(context.Background(), "CVE-2099-9999", t.TempDir(), root)
	if err != nil || !strings.Contains(missing.Reason, "CVE-2099-9999") {
		t.Fatalf("missing record must name CVE: %+v err=%v", missing, err)
	}
}

func TestFrozenFetcherRejectsTraversal(t *testing.T) {
	fetch := vexbench.FrozenFetcher(t.TempDir())
	for _, id := range []string{"../CVE-2099-0001", "x/y"} {
		if _, err := fetch(context.Background(), id); err == nil {
			t.Errorf("%q should be rejected", id)
		}
	}
}

func TestCanonicalAndRawAdvisoryDigests(t *testing.T) {
	a := []byte(`{"id":"CVE-2099-0001","aliases":[],"affected":[]}`)
	b := []byte(`{"affected":[],"aliases":[],"id":"CVE-2099-0001"}`)
	da, err := vexbench.CanonicalSHA256(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := vexbench.CanonicalSHA256(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("canonical digests differ: %s %s", da, db)
	}
	if fmt.Sprintf("%x", sha256.Sum256(a)) == fmt.Sprintf("%x", sha256.Sum256(b)) {
		t.Fatal("raw digests unexpectedly equal")
	}
	if _, err := vexbench.CanonicalSHA256([]byte("not-json")); err == nil {
		t.Fatal("malformed JSON must fail canonical digest")
	}
}
