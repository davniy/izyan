package states_test

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/states"
)

// outcomeRunner controls the raw stream, the actually-used pattern, and the
// process error independently — the recorder must never infer success from
// runner presence or from a parseable prefix.
type outcomeRunner struct {
	raw     []byte
	pattern string
	err     error
}

func (r outcomeRunner) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return r.raw, r.pattern, r.err
}

func collectGovulncheck(t *testing.T, runner interface {
	RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error)
}, product domain.ProductSnapshot) *domain.AnalysisCase {
	t.Helper()
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-OUT-1", Module: "example.com/dep"},
		Product:       product,
	}
	// A runner typed nil must behave like an absent runner.
	var h states.CollectEvidence
	if runner != nil {
		h.Govulncheck = runner
	}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("collect evidence: %v", err)
	}
	return c
}

func govulncheckRecords(c *domain.AnalysisCase) []domain.Evidence {
	var out []domain.Evidence
	for _, ev := range c.EvidenceGraph.Evidence {
		if ev.Kind == domain.EvidenceGovulncheck {
			out = append(out, ev)
		}
	}
	return out
}

func TestGovulncheckOutcomeFirstClassRecords(t *testing.T) {
	build := domain.ProductSnapshot{Repository: "/repo", Commit: "abc", GOOS: "linux", GOARCH: "amd64"}
	validOSV := `{"osv":{"id":"GO-OUT-1","affected":[{"ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}]}}` + "\n"
	validFinding := `{"finding":{"osv":"GO-OUT-1","trace":[{"module":"example.com/prod","package":"example.com/prod","function":"main"},{"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse"}]}}` + "\n"
	config := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n"

	t.Run("missing runner records not_run", func(t *testing.T) {
		c := collectGovulncheck(t, nil, build)
		records := govulncheckRecords(c)
		if len(records) != 1 {
			t.Fatalf("govulncheck records=%d want exactly one", len(records))
		}
		run := records[0].Govulncheck
		if run == nil || run.Outcome != domain.GovulncheckNotRun {
			t.Fatalf("run=%+v", run)
		}
		if records[0].BuildContext == nil ||
			records[0].BuildContext.Matches(domain.EffectiveBuildContext(build)) != nil {
			t.Fatalf("not_run evidence must carry the effective context: %+v", records[0].BuildContext)
		}
		if len(c.EvidenceGraph.CallPaths) != 0 {
			t.Fatal("not_run must not publish call paths")
		}
	})

	t.Run("failed process records failed and publishes no prefix", func(t *testing.T) {
		runner := outcomeRunner{
			raw:     []byte(config + validOSV + validFinding),
			pattern: "./...",
			err:     context.DeadlineExceeded,
		}
		c := collectGovulncheck(t, runner, build)
		records := govulncheckRecords(c)
		if len(records) != 1 || records[0].Govulncheck == nil ||
			records[0].Govulncheck.Outcome != domain.GovulncheckFailed {
			t.Fatalf("records=%+v", records)
		}
		if len(c.EvidenceGraph.CallPaths) != 0 {
			t.Fatalf("failed process published call paths: %+v", c.EvidenceGraph.CallPaths)
		}
		if records[0].Content == "" {
			t.Fatal("raw prefix must remain in evidence for audit")
		}
	})

	t.Run("completed with results binds call paths to the run", func(t *testing.T) {
		runner := outcomeRunner{
			raw:     []byte(config + validOSV + validFinding),
			pattern: "./...",
		}
		c := collectGovulncheck(t, runner, build)
		records := govulncheckRecords(c)
		if len(records) != 1 || records[0].Govulncheck.Outcome != domain.GovulncheckCompletedWithResults {
			t.Fatalf("records=%+v", records)
		}
		if len(c.EvidenceGraph.CallPaths) != 1 {
			t.Fatalf("call paths=%+v", c.EvidenceGraph.CallPaths)
		}
		if c.EvidenceGraph.CallPaths[0].EvidenceID != records[0].ID {
			t.Fatalf("call path evidence=%q want %q", c.EvidenceGraph.CallPaths[0].EvidenceID, records[0].ID)
		}
		if !records[0].Govulncheck.Coverage.ScopeComplete {
			t.Fatal("whole-tree scan must be complete scope")
		}
	})

	t.Run("completed empty records no call paths", func(t *testing.T) {
		runner := outcomeRunner{raw: []byte(config), pattern: "./..."}
		c := collectGovulncheck(t, runner, build)
		records := govulncheckRecords(c)
		if len(records) != 1 || records[0].Govulncheck.Outcome != domain.GovulncheckCompletedEmpty {
			t.Fatalf("records=%+v", records)
		}
		if len(c.EvidenceGraph.CallPaths) != 0 {
			t.Fatalf("completed-empty published call paths: %+v", c.EvidenceGraph.CallPaths)
		}
		if records[0].Govulncheck.Coverage.Advisory != domain.GovulncheckCoverageNotInDB {
			t.Fatalf("coverage=%+v", records[0].Govulncheck.Coverage)
		}
	})

	t.Run("narrowed fallback is partial scope", func(t *testing.T) {
		runner := outcomeRunner{
			raw:     []byte(config + validOSV + validFinding),
			pattern: "./cmd/...",
		}
		c := collectGovulncheck(t, runner, build)
		records := govulncheckRecords(c)
		if records[0].Govulncheck.Coverage.ScopeComplete {
			t.Fatal("narrowed scope must never grant full coverage")
		}
		found := false
		for _, lim := range c.EvidenceGraph.ToolLimitations {
			if strings.Contains(lim, "./cmd/...") && strings.Contains(lim, "narrowed scope") {
				found = true
			}
		}
		if !found {
			t.Fatalf("narrowed-scope limitation missing: %v", c.EvidenceGraph.ToolLimitations)
		}
		// Positives remain usable despite partial scope.
		if len(c.EvidenceGraph.CallPaths) != 1 {
			t.Fatalf("call paths=%+v", c.EvidenceGraph.CallPaths)
		}
	})

	t.Run("separate cases get separate metadata from cached raw output", func(t *testing.T) {
		// A caching runner returns the same bytes for every case; each
		// collector invocation must still record its own outcome record and
		// build context.
		runner := outcomeRunner{raw: []byte(config + validOSV), pattern: "./..."}
		linux := build
		darwin := build
		darwin.GOOS, darwin.GOARCH = "darwin", "arm64"

		first := collectGovulncheck(t, runner, linux)
		second := collectGovulncheck(t, runner, darwin)
		firstRecords := govulncheckRecords(first)
		secondRecords := govulncheckRecords(second)
		if len(firstRecords) != 1 || len(secondRecords) != 1 {
			t.Fatalf("records=%d/%d", len(firstRecords), len(secondRecords))
		}
		if firstRecords[0].Govulncheck == secondRecords[0].Govulncheck {
			t.Fatal("cached output must not share one run record across cases")
		}
		if firstRecords[0].BuildContext == secondRecords[0].BuildContext {
			t.Fatal("cached output must not share one build context across cases")
		}
		if firstRecords[0].BuildContext.GOOS != "linux" ||
			secondRecords[0].BuildContext.GOOS != "darwin" {
			t.Fatalf("contexts=%q/%q", firstRecords[0].BuildContext.GOOS, secondRecords[0].BuildContext.GOOS)
		}
		if firstRecords[0].PackageList != nil || secondRecords[0].PackageList != nil {
			t.Fatal("govulncheck evidence must not fabricate package-list metadata")
		}
	})

	// The assessment record is pinned to exact bytes: durable coverage names
	// that pin and carries only the subjects the record's own document
	// declares.
	t.Run("pinned record binds coverage and projected subjects", func(t *testing.T) {
		runner := outcomeRunner{
			raw:     []byte(config + validOSV + validFinding),
			pattern: "./...",
		}
		pin := testRecordPin("GO-OUT-1")
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:              "GO-OUT-1",
				Module:          "example.com/dep",
				AffectedSymbols: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
			},
			Product:   build,
			RecordPin: pin,
		}
		h := states.CollectEvidence{Govulncheck: runner}
		if _, err := h.Run(context.Background(), c); err != nil {
			t.Fatalf("collect evidence: %v", err)
		}
		records := govulncheckRecords(c)
		if len(records) != 1 || records[0].Govulncheck == nil {
			t.Fatalf("records=%+v", records)
		}
		coverage := records[0].Govulncheck.Coverage
		if coverage.Record == nil || !coverage.Record.Same(*pin) {
			t.Fatalf("coverage must name the assessed record pin: %+v", coverage.Record)
		}
		want := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
		if len(coverage.Subjects) != 1 || coverage.Subjects[0] != want {
			t.Fatalf("subjects=%v", coverage.Subjects)
		}
		if len(c.EvidenceGraph.CallPaths) != 1 {
			t.Fatalf("call paths=%+v", c.EvidenceGraph.CallPaths)
		}
	})

	// Two records sharing a CVE key: the stream emitted only the other
	// record's document, so this case must stay not_in_db with no inherited
	// call path. Coverage still names the assessed pin.
	t.Run("shared CVE key does not cover another record", func(t *testing.T) {
		otherOSV := `{"osv":{"id":"GO-OUT-1","aliases":["CVE-OUT-1"],"affected":[{"package":{"name":"example.com/other"},"ecosystem_specific":{"imports":[{"path":"example.com/other/vuln","symbols":["OtherSink"]}]}}]}}` + "\n"
		otherFinding := `{"finding":{"osv":"GO-OUT-1","trace":[{"module":"example.com/other","package":"example.com/other/vuln","function":"OtherSink"}]}}` + "\n"
		runner := outcomeRunner{
			raw:     []byte(config + otherOSV + otherFinding),
			pattern: "./...",
		}
		pin := testRecordPin("GHSA-OUT-2")
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:              "GHSA-OUT-2",
				Aliases:         []string{"CVE-OUT-1"},
				Module:          "example.com/dep",
				AffectedSymbols: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
			},
			Product:   build,
			RecordPin: pin,
		}
		h := states.CollectEvidence{Govulncheck: runner}
		if _, err := h.Run(context.Background(), c); err != nil {
			t.Fatalf("collect evidence: %v", err)
		}
		records := govulncheckRecords(c)
		if len(records) != 1 || records[0].Govulncheck == nil {
			t.Fatalf("records=%+v", records)
		}
		coverage := records[0].Govulncheck.Coverage
		if coverage.Advisory != domain.GovulncheckCoverageNotInDB {
			t.Fatalf("shared CVE key conferred coverage: %+v", coverage)
		}
		if len(coverage.Subjects) != 0 || len(coverage.Modules) != 0 {
			t.Fatalf("shared CVE key conferred bindings: %+v", coverage)
		}
		if coverage.Record == nil || !coverage.Record.Same(*pin) {
			t.Fatalf("coverage must still name the assessed pin: %+v", coverage.Record)
		}
		if len(c.EvidenceGraph.CallPaths) != 0 {
			t.Fatalf("another record's call path leaked: %+v", c.EvidenceGraph.CallPaths)
		}
	})
}

// testRecordPin builds a valid digest-pinned record identity for a case.
func testRecordPin(recordID string) *domain.RecordPin {
	return &domain.RecordPin{
		RecordID:       recordID,
		DocumentDigest: "sha256:" + strings.Repeat("a", 64),
		SourceLocator:  "testdata/" + recordID + ".json",
	}
}
