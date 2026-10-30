package goanalysis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/vulnerability"
)

func TestFindingHasCallPath(t *testing.T) {
	// Finding with function-level call path
	fWithFunc := Finding{
		OSV: "GO-2026-1234",
		Trace: []TraceFrame{
			{Package: "example.com/lib", Function: "VulnFunc"},
			{Package: "example.com/app", Function: "main"},
		},
	}
	if !fWithFunc.HasCallPath() {
		t.Fatalf("expected HasCallPath to be true for finding with functions")
	}
	cp := fWithFunc.CallPath()
	if len(cp.Frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(cp.Frames))
	}

	// Finding with only package/module level trace (no function)
	fWithoutFunc := Finding{
		OSV: "GO-2026-1234",
		Trace: []TraceFrame{
			{Package: "example.com/lib", Function: ""},
			{Module: "example.com/lib", Function: ""},
		},
	}
	if fWithoutFunc.HasCallPath() {
		t.Fatalf("expected HasCallPath to be false for package/module-only finding")
	}
	cpEmpty := fWithoutFunc.CallPath()
	if len(cpEmpty.Frames) != 0 {
		t.Fatalf("expected 0 frames for package/module-only finding, got %d", len(cpEmpty.Frames))
	}
}

// writeFakeGovulncheck installs a shell-script stand-in for the
// govulncheck binary. It echoes its args (one per line) to
// $GOVULN_FAKE_ARGS when set, prints a fixed -version report, and
// exits with FAKE_EXIT (default 0) after writing FAKE_STDOUT.
func writeFakeGovulncheck(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "govulncheck")
	script := `#!/bin/sh
if [ -n "$GOVULN_FAKE_ARGS" ]; then printf '%s\n' "$@" > "$GOVULN_FAKE_ARGS"; fi
if [ -n "$GOVULN_FAKE_ENV" ]; then env | sort > "$GOVULN_FAKE_ENV"; fi
for a in "$@"; do
  if [ "$a" = "-version" ]; then
    printf 'Scanner: govulncheck@fake\nDB: %s\nDB updated: 2026-01-02\n' "$GOVULN_FAKE_DB"
    exit 0
  fi
done
cat "$GOVULN_FAKE_STDOUT" 2>/dev/null
exit "${GOVULN_FAKE_EXIT:-0}"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func argsFile(t *testing.T) (string, func() []string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "args.txt")
	return f, func() []string {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}
}

// The -db flag must reach the subprocess as file:// URL so the strict
// profile's pinned root is the database actually scanned — GOVULNDB in
// env alone is not a govulncheck input.
func TestExecRunnerPassesPinnedDBFlag(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeGovulncheck(t, dir)
	dbRoot := filepath.Join(dir, "local-db")
	argsPath, readArgs := argsFile(t)
	t.Setenv("GOVULN_FAKE_ARGS", argsPath)

	r := ExecRunner{Bin: bin, DBRoot: dbRoot}
	if _, pattern, err := r.RunGovulncheck(context.Background(), dir, domain.ProductSnapshot{}); err != nil {
		t.Fatalf("run: %v", err)
	} else if pattern != "./..." {
		t.Fatalf("pattern=%q", pattern)
	}
	args := readArgs()
	want := "-db"
	found := ""
	for i, a := range args {
		if a == want && i+1 < len(args) {
			found = args[i+1]
		}
	}
	wantURL := "file://" + dbRoot
	if found != wantURL {
		t.Fatalf("-db arg = %q, want %q (args=%v)", found, wantURL, args)
	}
	if args[len(args)-1] != "./..." {
		t.Fatalf("last arg = %q, want ./... (args=%v)", args[len(args)-1], args)
	}

	// Without a pinned root the runner must not add -db at all.
	argsPath2, readArgs2 := argsFile(t)
	t.Setenv("GOVULN_FAKE_ARGS", argsPath2)
	r2 := ExecRunner{Bin: bin}
	if _, _, err := r2.RunGovulncheck(context.Background(), dir, domain.ProductSnapshot{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, a := range readArgs2() {
		if a == "-db" {
			t.Fatalf("unexpected -db in args %v", readArgs2())
		}
	}
}

// govulncheck exits 3 when it reports findings; that is a successful
// scan result, not an error, and the raw JSON stream must reach the
// caller unparsed.
func TestExecRunnerExitCode3IsSuccess(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeGovulncheck(t, dir)
	stream := filepath.Join(dir, "stream.json")
	finding := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n" +
		`{"osv":{"id":"GO-2099-0001"}}` + "\n" +
		`{"finding":{"osv":"GO-2099-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/prod","function":"main"}]}}` + "\n"
	if err := os.WriteFile(stream, []byte(finding), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOVULN_FAKE_STDOUT", stream)
	t.Setenv("GOVULN_FAKE_EXIT", "3")

	raw, pattern, err := (ExecRunner{Bin: bin}).RunGovulncheck(context.Background(), dir, domain.ProductSnapshot{})
	if err != nil {
		t.Fatalf("exit 3 must not error: %v", err)
	}
	if pattern != "./..." {
		t.Fatalf("pattern=%q", pattern)
	}
	res, perr := Parse(raw)
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if len(res.Findings) != 1 || res.Findings[0].OSV != "GO-2099-0001" {
		t.Fatalf("findings=%+v", res.Findings)
	}

	// A non-3 nonzero exit stays an error.
	t.Setenv("GOVULN_FAKE_EXIT", "2")
	if _, _, err := (ExecRunner{Bin: bin}).RunGovulncheck(context.Background(), dir, domain.ProductSnapshot{}); err == nil {
		t.Fatal("exit 2 must error")
	}
}

// DBInfo must describe the pinned database, not the binary's default —
// -db travels to -version too, and the db_info text carries the file://
// provenance the caller stores.
func TestExecRunnerDBInfoPinsDB(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeGovulncheck(t, dir)
	dbRoot := filepath.Join(dir, "local-db")
	argsPath, readArgs := argsFile(t)
	t.Setenv("GOVULN_FAKE_ARGS", argsPath)
	t.Setenv("GOVULN_FAKE_DB", "file://"+dbRoot)

	info, err := (ExecRunner{Bin: bin, DBRoot: dbRoot}).DBInfo(context.Background())
	if err != nil {
		t.Fatalf("DBInfo: %v", err)
	}
	args := readArgs()
	seenVersion, seenDB := false, ""
	for i, a := range args {
		if a == "-version" {
			seenVersion = true
		}
		if a == "-db" && i+1 < len(args) {
			seenDB = args[i+1]
		}
	}
	if !seenVersion || seenDB != "file://"+dbRoot {
		t.Fatalf("args=%v: want -version with -db file://%s", args, dbRoot)
	}
	// Provenance: the returned db_info carries the pinned root the fake
	// reported back.
	if !strings.Contains(info, "local-db") {
		t.Fatalf("db_info %q must name the pinned root", info)
	}

	// Provenance: CachingRunner must forward DBInfo so a shared runner
	// keeps the pinned-DB identity line instead of dropping it.
	cr := CachingRunner(ExecRunner{Bin: bin, DBRoot: dbRoot})
	informer, ok := cr.(DBInformer)
	if !ok {
		t.Fatal("CachingRunner must implement DBInformer")
	}
	if cinfo, err := informer.DBInfo(context.Background()); err != nil {
		t.Fatalf("cached DBInfo: %v", err)
	} else if cinfo != info {
		t.Fatalf("cached db_info %q != %q", cinfo, info)
	}
}

// The strict tool env reaches the govulncheck subprocess: GOPROXY=off
// keeps a missing module from ever reaching an ambient proxy, and the
// pinned GOMODCACHE/GOVULNDB are the only roots consulted.
func TestExecRunnerEnvPinsModuleEgress(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeGovulncheck(t, dir)
	envPath := filepath.Join(dir, "env.txt")
	t.Setenv("GOVULN_FAKE_ENV", envPath)

	strictEnv := []string{
		"GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly",
		"GOMODCACHE=" + filepath.Join(dir, "modcache"),
		"GOVULNDB=" + filepath.Join(dir, "local-db"),
	}
	if _, _, err := (ExecRunner{Bin: bin, Env: strictEnv}).RunGovulncheck(
		context.Background(), dir, domain.ProductSnapshot{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	b, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("fake did not record env: %v", err)
	}
	for _, want := range strictEnv {
		if !strings.Contains(string(b), want) {
			t.Fatalf("subprocess env missing %q\n%s", want, b)
		}
	}
}

const validConfig = `{"config":{"protocol_version":"v1.0.0","scan_mode":"source","scan_level":"symbol"}}` + "\n"

// identityRecord builds an unpinned projection target for tests that only
// need an advisory identity. No bytes are asserted.
func identityRecord(v domain.Vulnerability) vulnerability.LoadedRecord {
	return vulnerability.LoadedRecord{Vuln: &v}
}

// pinnedRecord loads exact OSV bytes into the digest-pinned projection target
// these tests assess.
func pinnedRecord(t *testing.T, id, body string) vulnerability.LoadedRecord {
	t.Helper()
	record, err := vulnerability.LoadExactBytes([]byte(body), id, "testdata/"+id+".json")
	if err != nil {
		t.Fatalf("load exact record %s: %v", id, err)
	}
	return record
}

// emittedSubjects returns the symbols the stream bound to one emitted
// document id (never to an alias).
func emittedSubjects(res Result, id string) []domain.SymbolRef {
	for _, e := range res.EmittedAdvisories {
		if e.Record.RecordID == id {
			return e.Subjects
		}
	}
	return nil
}

func TestParseGovulncheckStrictnessMatrix(t *testing.T) {
	validOSV := `{"osv":{"id":"GO-2099-0001","aliases":["CVE-2099-0001"],"affected":[{"package":{"name":"example.com/dep"},"ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse","Type.Method"]}]}}]}}` + "\n"
	validFinding := `{"finding":{"osv":"GO-2099-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/prod","package":"example.com/prod","function":"main"}]}}` + "\n"

	cases := []struct {
		name      string
		raw       string
		wantErr   bool
		findings  int
		covered   bool
		symbols   int
		scanMode  string
		scanLevel string
	}{
		{name: "empty", raw: "", wantErr: true},
		{name: "whitespace", raw: " \n\t ", wantErr: true},
		{name: "empty object", raw: "{}", wantErr: true},
		{name: "null", raw: "null", wantErr: true},
		{name: "array", raw: "[]", wantErr: true},
		{name: "bare top-level header", raw: `{"protocol_version":"v1.0.0"}`, wantErr: true},
		{name: "config without version", raw: `{"config":{"scan_mode":"source"}}`, wantErr: true},
		{name: "unsupported protocol", raw: `{"config":{"protocol_version":"v2.0.0"}}`, wantErr: true},
		{name: "non-string protocol", raw: `{"config":{"protocol_version":1}}`, wantErr: true},
		{name: "first message is not config", raw: `{"progress":{"message":"x"}}` + "\n" + validConfig, wantErr: true},
		{name: "config and progress in one object", raw: `{"config":{"protocol_version":"v1.0.0"},"progress":{"message":"x"}}`, wantErr: true},
		{name: "osv and finding in one object", raw: validConfig + `{"osv":{"id":"GO-1"},"finding":{"osv":"GO-1","trace":[{"function":"f"}]}}`, wantErr: true},
		{name: "malformed finding", raw: validConfig + `{"finding":"not-an-object"}`, wantErr: true},
		{name: "finding without osv", raw: validConfig + `{"finding":{"trace":[{"function":"f"}]}}`, wantErr: true},
		{name: "finding without trace", raw: validConfig + `{"finding":{"osv":"GO-1"}}`, wantErr: true},
		{name: "finding trace frame without identity", raw: validConfig + `{"finding":{"osv":"GO-1","trace":[{"position":{"filename":"x.go"}}]}}`, wantErr: true},
		{name: "malformed osv", raw: validConfig + `{"osv":[]}`, wantErr: true},
		{name: "osv without id", raw: validConfig + `{"osv":{"aliases":["x"]}}`, wantErr: true},
		{name: "osv import without path", raw: validConfig + `{"osv":{"id":"GO-1","affected":[{"ecosystem_specific":{"imports":[{"symbols":["X"]}]}}]}}`, wantErr: true},
		{name: "valid prefix then truncated finding", raw: validConfig + validOSV + `{"finding":`, wantErr: true},
		{name: "valid prefix then non-json suffix", raw: validConfig + validOSV + validFinding + "garbage", wantErr: true},
		{name: "valid prefix then trailing array", raw: validConfig + `[]`, wantErr: true},
		{name: "repeated config", raw: validConfig + validConfig, wantErr: true},
		{name: "unknown message type", raw: validConfig + `{"other":{}}`, wantErr: true},
		{name: "null progress", raw: validConfig + `{"progress":null}`, wantErr: true},
		{name: "config only", raw: validConfig, scanMode: "source", scanLevel: "symbol"},
		{name: "config and progress", raw: validConfig + `{"progress":{"message":"scanning"}}`, scanMode: "source", scanLevel: "symbol"},
		{name: "config and sbom", raw: validConfig + `{"SBOM":{"go_version":"go1.25.0","modules":[{"path":"example.com/prod"}]}}`, scanMode: "source", scanLevel: "symbol"},
		{name: "null sbom", raw: validConfig + `{"SBOM":null}`, wantErr: true},
		{name: "osv and finding", raw: validConfig + validOSV + validFinding, findings: 1, covered: true, symbols: 2, scanMode: "source", scanLevel: "symbol"},
	}
	vuln := domain.Vulnerability{ID: "GO-2099-0001", Aliases: []string{"CVE-2099-0001"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse([]byte(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a parse error, got result %+v", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(res.Findings) != tc.findings {
				t.Fatalf("findings=%d want %d", len(res.Findings), tc.findings)
			}
			if res.Covers(vuln) != tc.covered {
				t.Fatalf("covered=%v want %v", res.Covers(vuln), tc.covered)
			}
			if got := len(emittedSubjects(res, vuln.ID)); got != tc.symbols {
				t.Fatalf("emitted symbols=%d want %d (%v)", got, tc.symbols, emittedSubjects(res, vuln.ID))
			}
			if res.Config.ScanMode != tc.scanMode || res.Config.ScanLevel != tc.scanLevel {
				t.Fatalf("config=%+v want mode=%q level=%q", res.Config, tc.scanMode, tc.scanLevel)
			}
		})
	}
}

// TestParseGovulncheckAliasMetadataIsNotCoverage: the OSV document's aliases
// make the identity "known" for presentation, but a record requested by that
// alias inherits neither the document's subjects nor its coverage. Only the
// emitting document's own id projects.
func TestParseGovulncheckAliasMetadataIsNotCoverage(t *testing.T) {
	osv := `{"id":"GO-2099-0002","aliases":["GHSA-test"],"affected":[{"ecosystem_specific":{"imports":[{"path":"example.com/dep","symbols":["Run"]}]}}]}`
	res, err := Parse([]byte(validConfig + `{"osv":` + osv + "}\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	vuln := domain.Vulnerability{ID: "GHSA-test"}
	if !res.Covers(vuln) {
		t.Fatal("alias metadata must still name the identity as known")
	}
	if got := emittedSubjects(res, "GHSA-test"); len(got) != 0 {
		t.Fatalf("aliases must not carry subjects: %v", got)
	}
	aliasProjection, err := res.ProjectRecord(identityRecord(vuln))
	if err != nil {
		t.Fatalf("project alias: %v", err)
	}
	if aliasProjection.Coverage.Advisory != domain.GovulncheckCoverageNotInDB {
		t.Fatalf("alias key conferred coverage: %+v", aliasProjection.Coverage)
	}
	if len(aliasProjection.Coverage.Subjects) != 0 || len(aliasProjection.Findings) != 0 {
		t.Fatalf("alias key conferred record content: %+v", aliasProjection)
	}

	own, err := res.ProjectRecord(pinnedRecord(t, "GO-2099-0002", osv))
	if err != nil {
		t.Fatalf("project own record: %v", err)
	}
	if own.Coverage.Advisory != domain.GovulncheckCoverageCovered {
		t.Fatalf("own document must project coverage: %+v", own.Coverage)
	}
	want := domain.SymbolRef{Package: "example.com/dep", Symbol: "Run"}
	if len(own.Coverage.Subjects) != 1 || own.Coverage.Subjects[0] != want {
		t.Fatalf("own subjects=%v", own.Coverage.Subjects)
	}
}

type recordRunner struct {
	raw     []byte
	pattern string
	err     error
	dbInfo  string
	calls   int
}

func (r *recordRunner) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	r.calls++
	return r.raw, r.pattern, r.err
}

func (r *recordRunner) DBInfo(context.Context) (string, error) { return r.dbInfo, nil }

func TestCollectGovulncheckRecordsEveryPath(t *testing.T) {
	// The exact record the run is projected for: its own module, symbols and
	// digest, never another document sharing the CVE key.
	record := pinnedRecord(t, "GO-2099-0001",
		`{"id":"GO-2099-0001","aliases":["CVE-2099-0001"],"affected":[{"package":{"name":"example.com/dep"},"ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}]}`)
	build := domain.ProductSnapshot{Repository: "/repo", Commit: "abc", GOOS: "linux", GOARCH: "amd64"}
	validOSV := `{"osv":{"id":"GO-2099-0001","affected":[{"ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}]}}` + "\n"
	validFinding := `{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/prod","package":"example.com/prod","function":"main"}]}}` + "\n"

	t.Run("nil runner is not_run", func(t *testing.T) {
		ev, res := CollectGovulncheck(context.Background(), nil, build, record)
		if ev.Govulncheck == nil || ev.Govulncheck.Outcome != domain.GovulncheckNotRun {
			t.Fatalf("run=%+v", ev.Govulncheck)
		}
		if ev.Govulncheck.Error == "" || ev.Govulncheck.Pattern != "" {
			t.Fatalf("not_run record must carry a reason and no pattern: %+v", ev.Govulncheck)
		}
		if ev.Content != "" || len(res.Findings) != 0 {
			t.Fatalf("not_run must not claim content or findings: %+v", res)
		}
		if ev.BuildContext == nil || ev.BuildContext.Matches(domain.EffectiveBuildContext(build)) != nil {
			t.Fatalf("context=%+v", ev.BuildContext)
		}
	})

	t.Run("process error stays failed and drops the parseable prefix", func(t *testing.T) {
		raw := validConfig + validOSV + validFinding
		runner := &recordRunner{raw: []byte(raw), pattern: "./...", err: errors.New("boom")}
		ev, res := CollectGovulncheck(context.Background(), runner, build, record)
		if ev.Govulncheck == nil || ev.Govulncheck.Outcome != domain.GovulncheckFailed {
			t.Fatalf("run=%+v", ev.Govulncheck)
		}
		if !strings.Contains(ev.Govulncheck.Error, "boom") {
			t.Fatalf("error=%q", ev.Govulncheck.Error)
		}
		if ev.Content != raw {
			t.Fatal("raw prefix must remain in evidence for audit")
		}
		if len(res.Findings) != 0 {
			t.Fatalf("failed run leaked findings: %+v", res.Findings)
		}
		if ev.Govulncheck.Coverage.Advisory != domain.GovulncheckCoverageUnknown ||
			ev.Govulncheck.Coverage.ScopeComplete {
			t.Fatalf("failed coverage=%+v", ev.Govulncheck.Coverage)
		}
	})

	t.Run("cancellation stays failed", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runner := &recordRunner{raw: []byte(validConfig), pattern: "./...", err: ctx.Err()}
		ev, _ := CollectGovulncheck(ctx, runner, build, record)
		if ev.Govulncheck == nil || ev.Govulncheck.Outcome != domain.GovulncheckFailed ||
			!strings.Contains(ev.Govulncheck.Error, context.Canceled.Error()) {
			t.Fatalf("run=%+v", ev.Govulncheck)
		}
	})

	t.Run("undecodable output stays failed", func(t *testing.T) {
		runner := &recordRunner{raw: []byte("{}"), pattern: "./..."}
		ev, res := CollectGovulncheck(context.Background(), runner, build, record)
		if ev.Govulncheck == nil || ev.Govulncheck.Outcome != domain.GovulncheckFailed {
			t.Fatalf("run=%+v", ev.Govulncheck)
		}
		if !strings.HasPrefix(ev.Govulncheck.Error, "parse:") {
			t.Fatalf("error=%q", ev.Govulncheck.Error)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("parse failure leaked findings: %+v", res.Findings)
		}
	})

	t.Run("valid empty stream is completed_empty without coverage", func(t *testing.T) {
		runner := &recordRunner{raw: []byte(validConfig), pattern: "./..."}
		ev, _ := CollectGovulncheck(context.Background(), runner, build, record)
		run := ev.Govulncheck
		if run.Outcome != domain.GovulncheckCompletedEmpty {
			t.Fatalf("outcome=%s", run.Outcome)
		}
		if run.Coverage.Advisory != domain.GovulncheckCoverageNotInDB {
			t.Fatalf("coverage=%+v", run.Coverage)
		}
		if !run.Coverage.ScopeComplete || run.Pattern != "./..." {
			t.Fatalf("scope=%+v pattern=%q", run.Coverage, run.Pattern)
		}
		if run.Mode != "source" || run.ScanLevel != "symbol" {
			t.Fatalf("mode=%q level=%q", run.Mode, run.ScanLevel)
		}
	})

	t.Run("OSV document establishes advisory and subject coverage", func(t *testing.T) {
		runner := &recordRunner{raw: []byte(validConfig + validOSV), pattern: "./..."}
		ev, _ := CollectGovulncheck(context.Background(), runner, build, record)
		run := ev.Govulncheck
		if run.Outcome != domain.GovulncheckCompletedEmpty {
			t.Fatalf("outcome=%s", run.Outcome)
		}
		if run.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("coverage=%+v", run.Coverage)
		}
		want := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
		if len(run.Coverage.Subjects) != 1 || run.Coverage.Subjects[0] != want {
			t.Fatalf("subjects=%v", run.Coverage.Subjects)
		}
	})

	t.Run("findings establish completed_with_results", func(t *testing.T) {
		runner := &recordRunner{raw: []byte(validConfig + validOSV + validFinding), pattern: "./..."}
		ev, res := CollectGovulncheck(context.Background(), runner, build, record)
		if ev.Govulncheck.Outcome != domain.GovulncheckCompletedWithResults {
			t.Fatalf("outcome=%s", ev.Govulncheck.Outcome)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("findings=%d", len(res.Findings))
		}
		if ev.Govulncheck.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			t.Fatalf("coverage=%+v", ev.Govulncheck.Coverage)
		}
	})

	t.Run("finding for another advisory still sets the run outcome", func(t *testing.T) {
		other := `{"finding":{"osv":"GO-OTHER","trace":[{"module":"example.com/other","function":"main"}]}}` + "\n"
		runner := &recordRunner{raw: []byte(validConfig + other), pattern: "./..."}
		ev, _ := CollectGovulncheck(context.Background(), runner, build, record)
		if ev.Govulncheck.Outcome != domain.GovulncheckCompletedWithResults {
			t.Fatalf("outcome=%s (actual findings must decide)", ev.Govulncheck.Outcome)
		}
		if ev.Govulncheck.Coverage.Advisory != domain.GovulncheckCoverageNotInDB {
			t.Fatalf("coverage=%+v", ev.Govulncheck.Coverage)
		}
	})

	t.Run("narrowed fallback pattern is partial scope", func(t *testing.T) {
		runner := &recordRunner{raw: []byte(validConfig), pattern: "./cmd/..."}
		ev, _ := CollectGovulncheck(context.Background(), runner, build, record)
		if ev.Govulncheck.Coverage.ScopeComplete {
			t.Fatal("a narrowed fallback pattern must never grant full scope")
		}
		if ev.Govulncheck.Pattern != "./cmd/..." {
			t.Fatalf("pattern=%q", ev.Govulncheck.Pattern)
		}
	})

	t.Run("binary mode measures the artifact completely", func(t *testing.T) {
		binaryBuild := build
		binaryBuild.BinaryPath = "/out/prod"
		binaryConfig := `{"config":{"protocol_version":"v1.0.0","scan_mode":"binary"}}` + "\n"
		runner := &recordRunner{raw: []byte(binaryConfig), pattern: "/out/prod"}
		ev, _ := CollectGovulncheck(context.Background(), runner, binaryBuild, record)
		if ev.Govulncheck.Mode != "binary" || !ev.Govulncheck.Coverage.ScopeComplete {
			t.Fatalf("run=%+v", ev.Govulncheck)
		}
		if ev.BuildContext == nil || ev.BuildContext.BinaryPath != "/out/prod" {
			t.Fatalf("context=%+v", ev.BuildContext)
		}
	})

	t.Run("database identity is preserved", func(t *testing.T) {
		runner := &recordRunner{raw: []byte(validConfig), pattern: "./...", dbInfo: "db: file:///vulndb"}
		ev, _ := CollectGovulncheck(context.Background(), runner, build, record)
		if ev.ToolVersion != "db: file:///vulndb" {
			t.Fatalf("tool version=%q", ev.ToolVersion)
		}
	})

	t.Run("cached raw output still yields fresh metadata", func(t *testing.T) {
		raw := validConfig + validOSV
		runner := &recordRunner{raw: []byte(raw), pattern: "./..."}
		linux := build
		darwin := build
		darwin.GOOS, darwin.GOARCH = "darwin", "arm64"
		first, _ := CollectGovulncheck(context.Background(), runner, linux, record)
		second, _ := CollectGovulncheck(context.Background(), runner, darwin, record)
		if first.Govulncheck == second.Govulncheck {
			t.Fatal("each invocation must own its run record")
		}
		if first.BuildContext.GOOS != "linux" || second.BuildContext.GOOS != "darwin" {
			t.Fatalf("contexts=%+v / %+v", first.BuildContext, second.BuildContext)
		}
		if first.BuildContext == second.BuildContext {
			t.Fatal("each invocation must own its build context")
		}
	})
}
