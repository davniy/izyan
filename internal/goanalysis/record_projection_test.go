package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// Two records sharing one CVE key but declaring disjoint modules and
// subjects. This is the shape the alias-union path used to merge.
const (
	projectionConfig = `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n"
	alphaDoc         = `{"id":"GO-2099-1001","aliases":["CVE-2099-9001"],"affected":[{"package":{"name":"example.com/alpha"},"ecosystem_specific":{"imports":[{"path":"example.com/alpha/vuln","symbols":["AlphaSink"]}]}}]}`
	betaDoc          = `{"id":"GO-2099-1002","aliases":["CVE-2099-9001"],"affected":[{"package":{"name":"example.com/beta"},"ecosystem_specific":{"imports":[{"path":"example.com/beta/vuln","symbols":["BetaSink"]}]}}]}`
	alphaFinding     = `{"finding":{"osv":"GO-2099-1001","trace":[{"module":"example.com/prod","package":"example.com/prod","function":"main"},{"module":"example.com/alpha","package":"example.com/alpha/vuln","function":"AlphaSink"}]}}`
	betaFinding      = `{"finding":{"osv":"GO-2099-1002","trace":[{"module":"example.com/prod","package":"example.com/prod","function":"main"},{"module":"example.com/beta","package":"example.com/beta/vuln","function":"BetaSink"}]}}`
)

// osvMsg wraps a raw OSV document body in a stream OSV message.
func osvMsg(doc string) string { return `{"osv":` + doc + `}` }

func projectionStream(parts ...string) []byte {
	return []byte(projectionConfig + strings.Join(parts, "\n") + "\n")
}

func projectionRecords(t *testing.T) (vulnerability.LoadedRecord, vulnerability.LoadedRecord) {
	t.Helper()
	return pinnedRecord(t, "GO-2099-1001", alphaDoc),
		pinnedRecord(t, "GO-2099-1002", betaDoc)
}

func mustProject(t *testing.T, res Result, record vulnerability.LoadedRecord) RecordProjection {
	t.Helper()
	projection, err := res.ProjectRecord(record)
	if err != nil {
		t.Fatalf("project %s: %v", record.Pin.RecordID, err)
	}
	return projection
}

// TestGovulncheckRecordProjection pins the reusable-measurement contract:
// one raw stream may serve many records, but each record projects only its
// own document, modules, subjects and findings. A shared CVE key, a conflicting
// document digest or a partial scan cannot transfer another record's coverage.
func TestGovulncheckRecordProjection(t *testing.T) {
	alpha, beta := projectionRecords(t)
	build := domain.ProductSnapshot{Repository: "/repo", Commit: "abc", GOOS: "linux", GOARCH: "amd64"}

	t.Run("each record projects only its own document and trace", func(t *testing.T) {
		res, err := Parse(projectionStream(osvMsg(alphaDoc), osvMsg(betaDoc), alphaFinding, betaFinding))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		pa := mustProject(t, res, alpha)
		if pa.Coverage.AdvisoryID != "GO-2099-1001" || pa.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("alpha coverage=%+v", pa.Coverage)
		}
		if want := []domain.SymbolRef{{Package: "example.com/alpha/vuln", Symbol: "AlphaSink"}}; len(pa.Coverage.Subjects) != 1 || pa.Coverage.Subjects[0] != want[0] {
			t.Fatalf("alpha subjects=%v", pa.Coverage.Subjects)
		}
		if len(pa.Coverage.Modules) != 1 || pa.Coverage.Modules[0] != "example.com/alpha" {
			t.Fatalf("alpha modules=%v", pa.Coverage.Modules)
		}
		if len(pa.Findings) != 1 || pa.Findings[0].OSV != "GO-2099-1001" {
			t.Fatalf("alpha findings=%+v", pa.Findings)
		}

		pb := mustProject(t, res, beta)
		if pb.Coverage.AdvisoryID != "GO-2099-1002" || pb.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("beta coverage=%+v", pb.Coverage)
		}
		if len(pb.Coverage.Subjects) != 1 || pb.Coverage.Subjects[0] != (domain.SymbolRef{Package: "example.com/beta/vuln", Symbol: "BetaSink"}) {
			t.Fatalf("beta subjects=%v", pb.Coverage.Subjects)
		}
		if len(pb.Coverage.Modules) != 1 || pb.Coverage.Modules[0] != "example.com/beta" {
			t.Fatalf("beta modules=%v", pb.Coverage.Modules)
		}
		if len(pb.Findings) != 1 || pb.Findings[0].OSV != "GO-2099-1002" {
			t.Fatalf("beta findings=%+v", pb.Findings)
		}

		// A record only claims emitted declarations its own document also
		// declares; widening the record's declaration set does not add
		// subjects the stream never bound to this document.
		widened := beta
		widenedVuln := *beta.Vuln
		widenedVuln.AffectedSymbols = append(widenedVuln.AffectedSymbols,
			domain.SymbolRef{Package: "example.com/beta/other", Symbol: "ExtraSink"})
		widened.Vuln = &widenedVuln
		if got := mustProject(t, res, widened).Coverage.Subjects; len(got) != 1 || got[0].Symbol != "BetaSink" {
			t.Fatalf("widened record inherited an unemitted subject: %v", got)
		}
	})

	t.Run("common CVE key never confers the other record's coverage", func(t *testing.T) {
		// The stream emitted only alpha's document and finding. Beta's
		// alias is the same CVE key, which the old union path treated as
		// covered; the exact projection must not.
		res, err := Parse(projectionStream(osvMsg(alphaDoc), alphaFinding))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !res.Covers(*beta.Vuln) {
			t.Fatal("test setup: the shared CVE key must register as known metadata")
		}
		pa := mustProject(t, res, alpha)
		if pa.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("alpha coverage=%+v", pa.Coverage)
		}
		pb := mustProject(t, res, beta)
		if pb.Coverage.Advisory != domain.GovulncheckCoverageNotInDB {
			t.Fatalf("shared CVE key turned not_in_db into %q", pb.Coverage.Advisory)
		}
		if len(pb.Coverage.Subjects) != 0 || len(pb.Coverage.Modules) != 0 {
			t.Fatalf("beta inherited alpha's record bindings: %+v", pb.Coverage)
		}
		if len(pb.Findings) != 0 {
			t.Fatalf("beta inherited alpha's finding: %+v", pb.Findings)
		}
	})

	t.Run("conflicting bytes for the same record id are rejected", func(t *testing.T) {
		runner := &recordRunner{raw: projectionStream(osvMsg(alphaDoc), alphaFinding), pattern: "./..."}
		ev, res := CollectGovulncheck(context.Background(), runner, build, alpha)
		if ev.Govulncheck == nil || ev.Govulncheck.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("run=%+v", ev.Govulncheck)
		}
		if ev.Govulncheck.Coverage.Record == nil || !ev.Govulncheck.Coverage.Record.Same(alpha.Pin) {
			t.Fatalf("coverage must stay pinned to the assessed bytes: %+v", ev.Govulncheck.Coverage.Record)
		}
		if _, err := res.ProjectRecord(alpha); err != nil {
			t.Fatalf("own record must project: %v", err)
		}

		// Conflicting bytes that claim alpha's own id are another document:
		// they may not reuse the run bound to alpha's digest.
		conflicting, err := vulnerability.LoadExactBytes(
			[]byte(`{"id":"GO-2099-1001","affected":[{"package":{"name":"example.com/alpha"},"ecosystem_specific":{"imports":[{"path":"example.com/alpha/vuln","symbols":["DifferentSink"]}]}}]}`),
			"GO-2099-1001", "elsewhere/GO-2099-1001.json")
		if err != nil {
			t.Fatalf("load conflicting record: %v", err)
		}
		if _, err := res.ProjectRecord(conflicting); err == nil {
			t.Fatal("a conflicting document digest must not inherit the measurement")
		} else if !strings.Contains(err.Error(), "assessed bytes") {
			t.Fatalf("error=%v", err)
		}

		// An unpinned target has no byte proof, so it cannot claim a run
		// that was collected for pinned bytes.
		unpinned := vulnerability.LoadedRecord{Vuln: &domain.Vulnerability{ID: "GO-2099-1001"}}
		if _, err := res.ProjectRecord(unpinned); err == nil {
			t.Fatal("unpinned record must not claim a pinned measurement")
		}
	})

	t.Run("partial scan keeps positives but never grants scope completeness", func(t *testing.T) {
		runner := &recordRunner{raw: projectionStream(osvMsg(alphaDoc), alphaFinding), pattern: "./cmd/..."}
		ev, res := CollectGovulncheck(context.Background(), runner, build, alpha)
		if ev.Govulncheck.Coverage.ScopeComplete {
			t.Fatal("narrowed scope must never grant full coverage")
		}
		projection := mustProject(t, res, alpha)
		if projection.Coverage.ScopeComplete {
			t.Fatal("projection must carry the run's partial scope")
		}
		if len(projection.Findings) != 1 {
			t.Fatalf("independently bound positive became unusable: %+v", projection.Findings)
		}
	})

	t.Run("finding without an OSV document covers only its own identity", func(t *testing.T) {
		res, err := Parse(projectionStream(alphaFinding))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		pa := mustProject(t, res, alpha)
		if pa.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("a finding for the record's own id must cover it: %+v", pa.Coverage)
		}
		if len(pa.Coverage.Subjects) != 0 {
			t.Fatalf("a finding declares no advisory subjects: %v", pa.Coverage.Subjects)
		}
		pb := mustProject(t, res, beta)
		if pb.Coverage.Advisory != domain.GovulncheckCoverageNotInDB || len(pb.Findings) != 0 {
			t.Fatalf("another record inherited the finding: %+v", pb)
		}
	})
}
