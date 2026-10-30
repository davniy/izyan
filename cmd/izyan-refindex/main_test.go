package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func refindexFixture(t *testing.T, parts ...string) string {
	t.Helper()
	parts = append([]string{"..", "..", "internal", "productb", "refindex", "testdata"}, parts...)
	abs, err := filepath.Abs(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestRunDeterministic runs the command twice over the same fixture and
// requires byte-identical output and a matching sha256 field.
func TestRunDeterministic(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	dir := t.TempDir()
	out1 := filepath.Join(dir, "r1.json")
	out2 := filepath.Join(dir, "r2.json")
	args := []string{
		"--snapshot", refindexFixture(t, "forkprod"),
		"--advisory", refindexFixture(t, "advisories", "dep-parse.json"),
		"--no-net",
	}
	if err := run(append(args, "--out", out1)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := run(append(args, "--out", out2)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("repeated run is not byte-identical")
	}
	var doc struct {
		Schema string `json:"schema"`
		CaseID string `json:"case_id"`
		Usage  struct {
			Stratum string `json:"stratum"`
			Binding string `json:"binding"`
			State   string `json:"state"`
		} `json:"usage"`
		Hashes struct {
			CanonicalSHA256 string `json:"canonical_sha256"`
		} `json:"hashes"`
	}
	if err := json.Unmarshal(b1, &doc); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if doc.Schema != "izyan-refindex/1" {
		t.Fatalf("schema = %q", doc.Schema)
	}
	if doc.CaseID != "GO-EVAL-RI-PARSE" {
		t.Fatalf("case_id = %q", doc.CaseID)
	}
	if doc.Usage.Stratum != "reachable_complete" || doc.Usage.State != "USED" {
		t.Fatalf("usage = %s/%s", doc.Usage.Stratum, doc.Usage.State)
	}
	if doc.Usage.Binding != "fork_copy" {
		t.Fatalf("binding = %s, want fork_copy", doc.Usage.Binding)
	}
	if doc.Hashes.CanonicalSHA256 == "" {
		t.Fatal("canonical hash missing")
	}
}

// TestRunRequiresArgs checks the mandatory flags fail loudly.
func TestRunRequiresArgs(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("missing --snapshot must fail")
	}
	if err := run([]string{"--snapshot", t.TempDir()}); err == nil {
		t.Fatal("missing advisory must fail")
	}
}

// TestRunCVEWrapperFamilyPromotion covers the real failure shape: a CVE
// wrapper document selected by --cve declares no affected entry, while the
// aliased GO sibling in the same directory carries the symbols. The CLI
// must promote the family locus and stay byte-identical across runs.
func TestRunCVEWrapperFamilyPromotion(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	dir := t.TempDir()
	out1 := filepath.Join(dir, "w1.json")
	out2 := filepath.Join(dir, "w2.json")
	args := []string{
		"--snapshot", refindexFixture(t, "forkprod"),
		"--advisory", refindexFixture(t, "advisories", "family"),
		"--cve", "CVE-2099-0001",
		"--no-net",
	}
	if err := run(append(args, "--out", out1)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := run(append(args, "--out", out2)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("repeated wrapper run is not byte-identical")
	}
	var doc struct {
		CaseID string `json:"case_id"`
		Locus  struct {
			Atoms []struct {
				Symbol     string `json:"symbol"`
				AdvisoryID string `json:"advisory_id"`
			} `json:"atoms"`
			Status string `json:"status"`
		} `json:"locus"`
		Hashes struct {
			CanonicalSHA256 string `json:"canonical_sha256"`
		} `json:"hashes"`
	}
	if err := json.Unmarshal(b1, &doc); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if doc.CaseID != "CVE-2099-0001" {
		t.Fatalf("case_id = %q", doc.CaseID)
	}
	if len(doc.Locus.Atoms) == 0 || doc.Locus.Status == "na" {
		t.Fatalf("locus = %+v (%s)", doc.Locus.Atoms, doc.Locus.Status)
	}
	for _, a := range doc.Locus.Atoms {
		if a.AdvisoryID != "GO-EVAL-RI-FAM" {
			t.Fatalf("atom %s advisory_id = %q", a.Symbol, a.AdvisoryID)
		}
	}
	if doc.Hashes.CanonicalSHA256 == "" {
		t.Fatal("canonical hash missing")
	}
}
