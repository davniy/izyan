package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --binary and --release-go-version are the release-evidence inputs of the
// analyze/scan surface. Both must stay registered and reach the snapshot
// options unchanged: the service — not the CLI — applies the trust-class
// precedence.
func TestCLI_ReleaseEvidenceFlagsWired(t *testing.T) {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	for _, name := range []string{"binary", "release-go-version"} {
		if fs.Lookup(name) == nil {
			t.Fatalf("flag --%s missing", name)
		}
	}
	if err := fs.Parse([]string{
		"--binary", "/tmp/release-bin",
		"--release-go-version", "go1.22.3",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.binary != "/tmp/release-bin" || o.releaseGo != "go1.22.3" {
		t.Fatalf("opts: binary=%q releaseGo=%q", o.binary, o.releaseGo)
	}
	opts, err := buildSnapshotOptions(o)
	if err != nil {
		t.Fatalf("buildSnapshotOptions: %v", err)
	}
	if opts.BinaryPath != "/tmp/release-bin" || opts.ReleaseGoVersion != "go1.22.3" {
		t.Fatalf("snapshot options: BinaryPath=%q ReleaseGoVersion=%q",
			opts.BinaryPath, opts.ReleaseGoVersion)
	}
}

// writeAxesAdvisory pins a two-entry advisory: a stdlib entry whose
// applicability depends on the release Go toolchain, and a third-party
// module whose version the release module graph carries.
func writeAxesAdvisory(t *testing.T) string {
	t.Helper()
	adv := `{
	  "id": "GO-TEST-AXES",
	  "summary": "stdlib toolchain entry plus third-party module entry",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [
	    {
	      "package": {"ecosystem": "Go", "name": "stdlib"},
	      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.19.3"}]}],
	      "ecosystem_specific": {"imports": [{"path": "net/http"}]}
	    },
	    {
	      "package": {"ecosystem": "Go", "name": "example.com/usagedep"},
	      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
	      "ecosystem_specific": {"imports": [{"path": "example.com/usagedep/shared"}]}
	    }
	  ]
	}`
	p := filepath.Join(t.TempDir(), "GO-TEST-AXES.json")
	if err := os.WriteFile(p, []byte(adv), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeModulesOnlyMetadata pins a release-metadata/1 document carrying an
// authoritative module graph and NO go_version: the shipped module
// versions are known while the release Go toolchain stays UNKNOWN.
func writeModulesOnlyMetadata(t *testing.T, version string) string {
	t.Helper()
	doc := `{"schema":"release-metadata/1","modules":[{"path":"example.com/usagedep","version":"` + version + `"}]}`
	p := filepath.Join(t.TempDir(), "meta.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeReleaseMetadata pins a release-metadata/1 document declaring both
// the shipped toolchain and the shipped module graph.
func writeReleaseMetadata(t *testing.T, goVersion, moduleVersion string) string {
	t.Helper()
	doc := `{"schema":"release-metadata/1","go_version":"` + goVersion +
		`","modules":[{"path":"example.com/usagedep","version":"` + moduleVersion + `"}]}`
	p := filepath.Join(t.TempDir(), "meta.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// axesReport is the report projection the acceptance names: every axis is
// a distinct member, never one field standing in for another.
type axesReport struct {
	Input struct {
		Snapshot struct {
			GoVersion        string  `json:"go_version"`
			MinimumGoVersion *string `json:"minimum_go_version"`
			ReleaseGoVersion *string `json:"release_go_version"`
			GoVersionSource  *string `json:"go_version_source"`
			ReleaseEvidence  *struct {
				Status             string `json:"status"`
				ReasonCode         string `json:"reason_code"`
				SelectedVersion    string `json:"selected_version"`
				SelectedSource     string `json:"selected_source"`
				SelectedTrust      string `json:"selected_trust"`
				VersionGraphSource string `json:"version_graph_source"`
				VersionGraphTrust  string `json:"version_graph_trust"`
				ModuleCount        int    `json:"module_count"`
				Modules            []struct {
					Path    string `json:"path"`
					Version string `json:"version"`
				} `json:"modules"`
			} `json:"release_evidence"`
		} `json:"snapshot"`
	} `json:"input"`
	Applicability struct {
		ResolvedVersion        *string  `json:"resolved_version"`
		VersionAffected        string   `json:"version_affected"`
		SelectedModule         *string  `json:"selected_module"`
		UnresolvedModules      []string `json:"unresolved_modules"`
		VersionAffectedModules []string `json:"version_affected_modules"`
	} `json:"product_applicability"`
}

func runAxesReport(t *testing.T, extra ...string) (axesReport, string) {
	t.Helper()
	root, adv := decisionFixtureRoot(t), writeAxesAdvisory(t)
	out := filepath.Join(t.TempDir(), "out")
	args := []string{
		"--snapshot", root, "--cve", "GO-TEST-AXES",
		"--advisory-file", adv, "--output-dir", out,
		"--external-commit-sha", "fixture-sha-t6",
	}
	args = append(args, extra...)
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc axesReport
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatalf("report.json decode: %v", err)
	}
	mb, err := os.ReadFile(filepath.Join(out, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Input.Snapshot
	// The analysis toolchain and the go.mod language minimum are separate
	// facts and neither is the release toolchain.
	if s.GoVersion == "" {
		t.Fatal("analysis toolchain not reported")
	}
	if s.MinimumGoVersion == nil || *s.MinimumGoVersion != "1.23" {
		t.Fatalf("minimum_go_version=%v, want the go.mod directive 1.23", s.MinimumGoVersion)
	}
	if s.ReleaseEvidence == nil {
		t.Fatal("release evidence block missing")
	}
	return doc, string(mb)
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// assertUnknownReleaseToolchain pins the missing-evidence report shape: no
// non-toolchain fact (analysis go, go.mod minimum, a module graph) may
// populate the release toolchain, and the stdlib entry stays UNKNOWN.
func assertUnknownReleaseToolchain(t *testing.T, doc axesReport) {
	t.Helper()
	s := doc.Input.Snapshot
	if s.ReleaseGoVersion != nil || s.GoVersionSource != nil {
		t.Fatalf("release toolchain fabricated from non-toolchain evidence: %v/%v",
			s.ReleaseGoVersion, s.GoVersionSource)
	}
	re := s.ReleaseEvidence
	if re.SelectedVersion != "" || re.SelectedSource != "" || re.SelectedTrust != "" {
		t.Fatalf("unknown release toolchain carries a selection: %+v", re)
	}
	if re.Status != "UNKNOWN" || re.ReasonCode != "RELEASE_EVIDENCE_SUPPORTING_ONLY" {
		t.Fatalf("release evidence = %s/%s, want UNKNOWN/supporting-only", re.Status, re.ReasonCode)
	}
	if !contains(doc.Applicability.UnresolvedModules, "stdlib") {
		t.Fatalf("stdlib entry must stay UNKNOWN: %v", doc.Applicability.UnresolvedModules)
	}
}

// TestResearch_ReleaseEvidenceAxesReport pins the report contract the
// acceptance requires: analysis toolchain, minimum go.mod version,
// authoritative release toolchain, authoritative release module graph and
// the source/vendor fallback are distinct facts. An authoritative module
// graph resolves the third-party entry while the stdlib entry stays
// UNKNOWN because the release toolchain is unresolved on its own axis.
func TestResearch_ReleaseEvidenceAxesReport(t *testing.T) {
	t.Run("authoritative release module graph", func(t *testing.T) {
		meta := writeModulesOnlyMetadata(t, "v1.1.0")
		doc, md := runAxesReport(t, "--release-metadata", meta)
		assertUnknownReleaseToolchain(t, doc)
		// The human report carries the same distinction as report.json.
		for _, want := range []string{
			"- analysis toolchain: `" + doc.Input.Snapshot.GoVersion + "`",
			"- minimum go.mod version: `1.23`",
			"- release toolchain: `UNKNOWN` — `UNKNOWN` / RELEASE_EVIDENCE_SUPPORTING_ONLY",
			"- release module graph: `release-artifact` trust `AUTHORITATIVE` modules=1",
		} {
			if !strings.Contains(md, want) {
				t.Fatalf("report.md missing %q:\n%s", want, md)
			}
		}
		// The operator-supplied module graph is authoritative even though
		// the toolchain axis is unknown.
		re := doc.Input.Snapshot.ReleaseEvidence
		if re.VersionGraphSource != "release-artifact" ||
			re.VersionGraphTrust != "AUTHORITATIVE" ||
			re.ModuleCount != 1 ||
			len(re.Modules) != 1 ||
			re.Modules[0].Path != "example.com/usagedep" ||
			re.Modules[0].Version != "v1.1.0" {
			t.Fatalf("release module graph = %+v", re)
		}
		a := doc.Applicability
		if a.ResolvedVersion == nil || *a.ResolvedVersion != "v1.1.0" {
			t.Fatalf("resolved_version=%v, want the release-graph v1.1.0", a.ResolvedVersion)
		}
		if a.VersionAffected != "TRUE" {
			t.Fatalf("version_affected=%q, want TRUE for the release-graph entry", a.VersionAffected)
		}
		if a.SelectedModule == nil || *a.SelectedModule != "example.com/usagedep" {
			t.Fatalf("selected_module=%v", a.SelectedModule)
		}
		if len(a.VersionAffectedModules) != 1 || a.VersionAffectedModules[0] != "example.com/usagedep" {
			t.Fatalf("version_affected_modules=%v, want only the release-graph entry", a.VersionAffectedModules)
		}
		if strings.Contains(md, "release module graph: `source-snapshot`") {
			t.Fatalf("report.md labels the authoritative graph as fallback:\n%s", md)
		}
	})

	t.Run("authoritative release toolchain", func(t *testing.T) {
		meta := writeReleaseMetadata(t, "go1.22.3", "v1.1.0")
		doc, md := runAxesReport(t, "--release-metadata", meta)
		s := doc.Input.Snapshot
		if s.ReleaseGoVersion == nil || *s.ReleaseGoVersion != "go1.22.3" ||
			s.GoVersionSource == nil || *s.GoVersionSource != "explicit" {
			t.Fatalf("release toolchain = %v from %v", s.ReleaseGoVersion, s.GoVersionSource)
		}
		re := s.ReleaseEvidence
		if re.Status != "RESOLVED" || re.SelectedVersion != "go1.22.3" ||
			re.SelectedSource != "explicit" || re.SelectedTrust != "AUTHORITATIVE" {
			t.Fatalf("release evidence selection = %+v", re)
		}
		if !strings.Contains(md, "- release toolchain: `go1.22.3`") {
			t.Fatalf("report.md missing the authoritative release toolchain:\n%s", md)
		}
		// Both axes are authoritative here: the toolchain resolves the
		// stdlib entry (1.22.3 is above the fixed 1.19.3) and the module
		// graph still supplies the third-party version.
		if re.VersionGraphSource != "release-artifact" || re.VersionGraphTrust != "AUTHORITATIVE" {
			t.Fatalf("graph provenance = %+v", re)
		}
		a := doc.Applicability
		if a.ResolvedVersion == nil || *a.ResolvedVersion != "v1.1.0" {
			t.Fatalf("resolved_version=%v, want the release-graph v1.1.0", a.ResolvedVersion)
		}
		if a.VersionAffected != "TRUE" ||
			len(a.VersionAffectedModules) != 1 ||
			a.VersionAffectedModules[0] != "example.com/usagedep" {
			t.Fatalf("applicability = %+v", a)
		}
		if contains(a.UnresolvedModules, "stdlib") {
			t.Fatalf("resolved release toolchain must decide the stdlib entry: %v", a.UnresolvedModules)
		}
	})

	t.Run("source checkout fallback", func(t *testing.T) {
		doc, md := runAxesReport(t)
		assertUnknownReleaseToolchain(t, doc)
		// No release channel ran: the source graph grounds module versions.
		re := doc.Input.Snapshot.ReleaseEvidence
		if re.VersionGraphSource != "source-snapshot" ||
			re.VersionGraphTrust != "" ||
			re.ModuleCount != 0 ||
			len(re.Modules) != 0 {
			t.Fatalf("fallback graph provenance = %+v", re)
		}
		if !strings.Contains(md, "release module graph: `source-snapshot` fallback") {
			t.Fatalf("report.md missing the fallback provenance:\n%s", md)
		}
		a := doc.Applicability
		if a.ResolvedVersion == nil || *a.ResolvedVersion != "v1.0.0" {
			t.Fatalf("resolved_version=%v, want the source checkout's v1.0.0", a.ResolvedVersion)
		}
		if a.VersionAffected != "TRUE" {
			t.Fatalf("version_affected=%q, want TRUE for the source-graph entry", a.VersionAffected)
		}
	})
}
