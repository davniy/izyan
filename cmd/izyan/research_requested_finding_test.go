package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/research"
)

func TestResearchCLIEmitsCanonicalRequestedFinding(t *testing.T) {
	report, c, out := runCanonicalResearchCLI(t, false)
	view, err := finding.Project(c)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != research.ReportSchemaV5 || report.RequestComposition == nil || report.DecisionArtifact != nil {
		t.Fatalf("wrong current contract: %s", report.Schema)
	}
	want, _ := json.Marshal(view.Requested)
	got, _ := json.Marshal(report.RequestComposition)
	if string(want) != string(got) {
		t.Fatal("CLI did not publish canonical projection")
	}
	if err := research.Validate(report, out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "requested-case.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := research.Validate(report, out); err == nil {
		t.Fatal("tampered requested-case bytes accepted")
	}
}

func TestResearchCandidateNegatives(t *testing.T) {
	report, c, out := runCanonicalResearchCLI(t, true)
	if len(c.RelatedRecords) != 1 || c.RelatedRecords[0].Analysis == nil {
		t.Fatalf("candidate was not independently assessed: %+v", c.RelatedRecords)
	}
	child := c.RelatedRecords[0].Analysis
	if child.RecordPin.Same(*c.RecordPin) || child.Vulnerability.AffectedModules[0].Module == c.Vulnerability.AffectedModules[0].Module {
		t.Fatal("candidate borrowed primary record bytes or subjects")
	}
	if c.CorpusDeclaration != nil || report.RequestComposition.CorpusNegativeBasis != nil {
		t.Fatal("undeclared feed manufactured a corpus closure")
	}
	if report.RequestComposition.Verdict == domain.VerdictNotAffected || report.RequestComposition.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("candidate negatives closed CVE without corpus/proof admission")
	}
	if err := research.Validate(report, out); err != nil {
		t.Fatal(err)
	}
}

func runCanonicalResearchCLI(t *testing.T, candidates bool) (*research.Report, *domain.AnalysisCase, string) {
	t.Helper()
	t.Setenv(osvURLEnv, "")
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advisory := filepath.Join(dir, "GO-CANONICAL.json")
	doc := `{"id":"GO-CANONICAL","aliases":["CVE-2099-9999"],"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"example.com/absent"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	if err := os.WriteFile(advisory, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	requested := "GO-CANONICAL"
	if candidates {
		requested = "CVE-2099-9999"
	}
	args := []string{"--snapshot", root, "--cve", requested, "--advisory-file", advisory, "--output-dir", out, "--external-commit-sha", "task9-offline", "--overall-timeout", "3m", "--deterministic-timeout", "1m"}
	if candidates {
		feed := filepath.Join(dir, "feed")
		if err := os.MkdirAll(feed, 0o755); err != nil {
			t.Fatal(err)
		}
		candidate := `{"id":"GO-CANDIDATE","aliases":["CVE-2099-9999"],"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"example.com/other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
		if err := os.WriteFile(filepath.Join(feed, "GO-CANDIDATE.json"), []byte(candidate), 0o644); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--osv-feed", feed)
	}
	if err := runResearch(args); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "requested-case.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c domain.AnalysisCase
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report research.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return &report, &c, out
}
