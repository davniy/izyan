package reportcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pbdomain "github.com/davniy/izyan/internal/productb/domain"
)

// fixture snapshot:
//
//	go.mod                  module example.com/prod
//	main.go                 func main (lines 3-5)
//	dep/dep.go              func Parse (4-6), func parseInner (8-10), type Server + Serve method (13-19)
//	dep/other.go            func helper (4-6)
//	dep/dep_test.go         func TestParse (4-6)
//	docs/NOTES.md           prose file
//	go.sum                  lock file
var snapFiles = map[string]string{
	"go.mod": "module example.com/prod\n\ngo 1.22\n",
	"go.sum": "example.com/dep v1.0.0 h1:x=\n",
	"main.go": `package main

func main() {
	dep.Parse(nil)
}
`,
	"dep/dep.go": `package dep

// Parse is the vulnerable entry point.
func Parse(data []byte) error {
	return parseInner(data)
}

func parseInner(data []byte) error {
	return nil
}

// Server serves requests.
type Server struct{}

// Serve handles one request.
func (s *Server) Serve() error {
	return s.serveInner()
}

func (s *Server) serveInner() error {
	return nil
}
`,
	"dep/other.go": `package dep

// helper supports Parse.
func helper() int {
	return 0
}
`,
	"dep/single.go": `package dep

import "strings"

// Trim keeps the import referenced.
func Trim(s string) string {
	return strings.TrimSpace(s)
}
`,
	"dep/group.go": `package dep

import (
	"fmt"
	"os"
)

// UseGroup keeps the imports referenced.
func UseGroup() {
	fmt.Println(os.Args)
}
`,
	"testdata/data.go": `package data

func Load() {}
`,
	"dep/dep_test.go": `package dep

import "testing"

func TestParse(t *testing.T) {
	if err := Parse(nil); err != nil {
		t.Fatal(err)
	}
}
`,
	"docs/NOTES.md": "# Notes\n\nThe dep package parses input.\n",
	"vendor/example.com/vulnlib/v.go": `package vulnlib

// Vuln is the vendored vulnerable function.
func Vuln() {}
`,
}

func writeSnap(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range snapFiles {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// reportJSON builds a structured report.json mirror from analysis fields.
func reportJSON(t *testing.T, rootCause, mechanism, reasoning string, affected, usage []string) []byte {
	t.Helper()
	type claim struct {
		Text string `json:"text"`
	}
	var doc struct {
		Analysis struct {
			RootCause string  `json:"root_cause"`
			Mechanism string  `json:"mechanism"`
			Reasoning string  `json:"reasoning"`
			Affected  []claim `json:"affected_implementations"`
			Usage     []claim `json:"usage_paths"`
		} `json:"analysis"`
	}
	doc.Analysis.RootCause = rootCause
	doc.Analysis.Mechanism = mechanism
	doc.Analysis.Reasoning = reasoning
	for _, s := range affected {
		doc.Analysis.Affected = append(doc.Analysis.Affected, claim{Text: s})
	}
	for _, s := range usage {
		doc.Analysis.Usage = append(doc.Analysis.Usage, claim{Text: s})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ground(t *testing.T, o Options) *Report {
	t.Helper()
	rep, err := Ground(o)
	if err != nil {
		t.Fatalf("Ground: %v", err)
	}
	return rep
}

// locBy finds the first location matching path ("" = any) and symbol.
func locBy(rep *Report, path, symbol string) *Location {
	for i := range rep.Claims.Locations {
		l := &rep.Claims.Locations[i]
		if (path == "" || l.Path == path) && l.Symbol == symbol {
			return l
		}
	}
	return nil
}

func wantStatus(t *testing.T, l *Location, status, kind string) {
	t.Helper()
	if l == nil {
		t.Fatal("location missing")
	}
	if l.Status != status {
		t.Fatalf("status = %q, want %q (reason: %s)", l.Status, status, l.Reason)
	}
	if kind != "" && l.Kind != kind {
		t.Fatalf("kind = %q, want %q", l.Kind, kind)
	}
}

func TestGroundStatuses(t *testing.T) {
	snap := writeSnap(t)
	reasoning := "The defect sits at dep/dep.go:8 in dep.parseInner. " +
		"The product calls dep/dep.go:5 at main.go:4. " +
		"dep.Server.Serve is the handler."
	rep := ground(t, Options{
		CaseID:      "case-1",
		ReportJSON:  reportJSON(t, "Root cause is dep/dep.go:8 in dep.parseInner.", "", reasoning, nil, nil),
		SnapshotDir: snap,
		AdvisorySymbols: []pbdomain.SymbolRef{
			{Package: "example.com/prod/dep", Symbol: "Parse"},
			{Package: "example.com/prod/dep", Symbol: "Server.Serve"},
		},
	})
	if rep.Schema != SchemaID || rep.Parse.Source != "structured" {
		t.Fatalf("schema/source: %+v", rep.Parse)
	}

	// exact: line inside the claimed symbol's own declaration.
	l := locBy(rep, "dep/dep.go", "dep.parseInner")
	wantStatus(t, l, StatusExact, KindLocus)
	if l.Line != 8 || l.EndLine != 8 || l.Decl == nil || l.Decl.Line != 8 {
		t.Fatalf("exact decl/range: %+v", l)
	}
	if l.EnclosingSymbol != "example.com/prod/dep.parseInner" {
		t.Fatalf("enclosing = %q", l.EnclosingSymbol)
	}

	// usage kind: citation inside call-context sentence.
	l = locBy(rep, "dep/dep.go", "")
	wantStatus(t, l, StatusExact, KindUsage)

	// symbol-only claim resolves through the package index.
	l = locBy(rep, "", "dep.Server.Serve")
	wantStatus(t, l, StatusSymbol, "")
	if l.Decl == nil || l.Decl.Path != "dep/dep.go" {
		t.Fatalf("symbol decl: %+v", l.Decl)
	}
}

func TestOffByOne(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID: "case-off",
		ReportJSON: reportJSON(t,
			"The vulnerable dep.Parse is at dep/dep.go:9.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	l := locBy(rep, "dep/dep.go", "dep.Parse")
	wantStatus(t, l, StatusSymbol, KindLocus)
	if l.Decl == nil || l.Decl.Line != 4 || l.Decl.EndLine != 6 {
		t.Fatalf("decl = %+v, want dep.Parse at 4-6", l.Decl)
	}
}

func TestWrongFileAndMissing(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID: "case-wrong",
		ReportJSON: reportJSON(t,
			"dep.Parse lives at dep/other.go:5. dep.parseInner at missing/none.go:3.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	l := locBy(rep, "dep/other.go", "dep.Parse")
	wantStatus(t, l, StatusSymbol, KindLocus)
	l = locBy(rep, "missing/none.go", "dep.parseInner")
	wantStatus(t, l, StatusSymbol, KindLocus)
}

func TestFileOnlyAndNonGo(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID: "case-file",
		ReportJSON: reportJSON(t,
			"The defect is somewhere in docs/NOTES.md and dep/dep.go.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	l := locBy(rep, "docs/NOTES.md", "")
	wantStatus(t, l, StatusFile, KindMetadata)
	// A file-only citation with no symbol names no locus: unknown, and it
	// stays out of the locus/usage projections either way.
	l = locBy(rep, "dep/dep.go", "")
	wantStatus(t, l, StatusFile, KindUnknown)
}

func TestNonGoLineBounds(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID: "case-nongo",
		ReportJSON: reportJSON(t,
			"Config at go.mod:1 and go.sum:99.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	l := locBy(rep, "go.mod", "")
	wantStatus(t, l, StatusFile, KindMetadata)
	if l.Line != 1 {
		t.Fatalf("go.mod line = %d", l.Line)
	}
	l = locBy(rep, "go.sum", "")
	if l.Status != StatusFailed {
		t.Fatalf("go.sum:99 status = %q, want unverified (bounds)", l.Status)
	}
}

func TestMalformedAndEscape(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID: "case-mal",
		ReportJSON: reportJSON(t,
			"dep/dep.go:9-4 is wrong. dep/dep.go:0 too. ../escape/dep.go:1 out.",
			"", "", nil, nil),
		SnapshotDir: snap,
	})
	var zero, rev, esc bool
	for i := range rep.Claims.Locations {
		l := &rep.Claims.Locations[i]
		switch l.Raw {
		case "dep/dep.go:9-4":
			rev = l.Status == StatusFailed
		case "dep/dep.go:0":
			zero = l.Status == StatusFailed
		case "../escape/dep.go:1":
			esc = l.Status == StatusFailed
		}
	}
	if !rev || !zero || !esc {
		t.Fatalf("malformed/escape: rev=%v zero=%v esc=%v locs=%+v", rev, zero, esc, rep.Claims.Locations)
	}
}

func TestPrefixNormalization(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID: "case-prefix",
		ReportJSON: reportJSON(t,
			"Also <snapshot>/dep/dep.go:5 and /work/dep/dep.go:4-6 and ./dep/other.go:5.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	n := 0
	for i := range rep.Claims.Locations {
		l := &rep.Claims.Locations[i]
		if l.Status == StatusExact || l.Status == StatusFile || l.Status == StatusSymbol {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("normalized statuses: %+v", rep.Claims.Locations)
	}
	// <snapshot>/ and /work/ stripped to dep/dep.go
	l := locBy(rep, "dep/dep.go", "")
	if l == nil {
		t.Fatal("normalized dep/dep.go missing")
	}
}

func TestTestFileCitation(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID:      "case-test",
		ReportJSON:  reportJSON(t, "Coverage at dep/dep_test.go:5.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	l := locBy(rep, "dep/dep_test.go", "")
	wantStatus(t, l, StatusExact, KindMetadata)
}

func TestMechanismAtoms(t *testing.T) {
	snap := writeSnap(t)
	reasoning := "CWE-22 path traversal in dep.Parse; advisory also mentions " +
		"other.Frobnicate and CWE-400."
	rep := ground(t, Options{
		CaseID:      "case-mech",
		RawAnswer:   []byte(reasoning),
		SnapshotDir: snap,
		AdvisorySymbols: []pbdomain.SymbolRef{
			{Package: "example.com/prod/dep", Symbol: "Parse"},
		},
		AdvisoryKeys: []string{"CWE-22"},
	})
	if rep.Parse.Source != "raw_answer" {
		t.Fatalf("source = %q", rep.Parse.Source)
	}
	var sym, other, cwe, cweBad *MechanismAtom
	for i := range rep.Claims.MechanismAtoms {
		a := &rep.Claims.MechanismAtoms[i]
		switch {
		case a.Symbol == "dep.Parse":
			sym = a
		case a.Symbol == "other.Frobnicate":
			other = a
		case a.Key == "CWE-22":
			cwe = a
		case a.Key == "CWE-400":
			cweBad = a
		}
	}
	if sym == nil || sym.Status != StatusAtomOK {
		t.Fatalf("dep.Parse atom: %+v", sym)
	}
	if other == nil || other.Status != StatusAtomBad {
		t.Fatalf("other.Frobnicate atom: %+v", other)
	}
	if cwe == nil || cwe.Status != StatusAtomOK {
		t.Fatalf("CWE-22 atom: %+v", cwe)
	}
	if cweBad == nil || cweBad.Status != StatusAtomBad {
		t.Fatalf("CWE-400 atom must be unverified when not frozen: %+v", cweBad)
	}
}

func TestMechanismWildcard(t *testing.T) {
	reasoning := "Anything in dep.parseInner is suspect."
	rep := ground(t, Options{
		CaseID:    "case-wild",
		RawAnswer: []byte(reasoning),
		AdvisorySymbols: []pbdomain.SymbolRef{
			{Package: "example.com/prod/dep", Symbol: "*"},
		},
	})
	for _, a := range rep.Claims.MechanismAtoms {
		if a.Symbol == "dep.parseInner" && a.Status != StatusAtomOK {
			t.Fatalf("wildcard package atom unverified: %+v", a)
		}
	}
}

func TestLegacyMarkdown(t *testing.T) {
	snap := writeSnap(t)
	md := "# CVE research — CVE-X\n\n" +
		"## Root cause\n\nThe defect is dep/dep.go:8 in dep.parseInner.\n\n" +
		"## Usage paths\n\nThe product calls dep/dep.go:5.\n\n" +
		"## Agent reasoning (verbatim)\n\nmain.go:4 imports dep.\n"
	rep := ground(t, Options{
		CaseID:      "case-md",
		ReportMD:    []byte(md),
		SnapshotDir: snap,
	})
	if rep.Parse.Source != "legacy_md" {
		t.Fatalf("source = %q", rep.Parse.Source)
	}
	l := locBy(rep, "dep/dep.go", "dep.parseInner")
	wantStatus(t, l, StatusExact, KindLocus)
	l = locBy(rep, "dep/dep.go", "")
	wantStatus(t, l, StatusExact, KindUsage)
	l = locBy(rep, "main.go", "")
	wantStatus(t, l, StatusExact, KindUsage)
}

func TestNoContent(t *testing.T) {
	rep := ground(t, Options{CaseID: "case-none"})
	if rep.Parse.Source != "none" || len(rep.Parse.Errors) == 0 {
		t.Fatalf("empty input: %+v", rep.Parse)
	}
}

func TestDeterminism(t *testing.T) {
	snap := writeSnap(t)
	reasoning := "dep.Parse at dep/dep.go:8. dep.Server.Serve called at dep/dep.go:17. " +
		"CWE-22. Unknown stuff at zzz/x.go:1 and <snapshot>/main.go:4."
	o := Options{
		CaseID:      "case-det",
		RawAnswer:   []byte(reasoning),
		SnapshotDir: snap,
		AdvisorySymbols: []pbdomain.SymbolRef{
			{Package: "example.com/prod/dep", Symbol: "Parse"},
			{Package: "example.com/prod/dep", Symbol: "Server.Serve"},
		},
		AdvisoryKeys: []string{"CWE-22"},
	}
	b1, err := Marshal(ground(t, o))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Marshal(ground(t, o))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("repeated ground is not byte-identical")
	}
}

func TestReasonsStableAndInformative(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID:      "case-reason",
		ReportJSON:  reportJSON(t, "dep.Parse at dep/dep.go:9 and nofile/x.go:1.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	for i := range rep.Claims.Locations {
		l := &rep.Claims.Locations[i]
		if l.Reason == "" {
			t.Fatalf("empty reason: %+v", l)
		}
	}
}

// Manifests, lock/checksum files, docs, testdata and test-only code are
// metadata citations: presence/version references that never earn locus or
// usage credit. Classification is path-shape only — it holds even when the
// file is missing or the line is out of bounds.
func TestMetadataPaths(t *testing.T) {
	snap := writeSnap(t)
	cases := []struct {
		name string
		cite string
		want string
	}{
		{"go.mod", "go.mod:1", "go.mod"},
		{"go.sum", "go.sum:1", "go.sum"},
		{"docs", "docs/NOTES.md:1", "docs/NOTES.md"},
		{"testdata go", "testdata/data.go:3", "testdata/data.go"},
		{"test code", "dep/dep_test.go:5", "dep/dep_test.go"},
		{"lock file missing", "package-lock.json:1", "package-lock.json"},
		{"manifest missing", "Cargo.lock:2", "Cargo.lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := ground(t, Options{
				CaseID:      "case-meta",
				ReportJSON:  reportJSON(t, "The defect is at "+tc.cite+".", "", "", nil, nil),
				SnapshotDir: snap,
			})
			l := locBy(rep, tc.want, "")
			if l == nil {
				t.Fatalf("citation %q not extracted: %+v", tc.cite, rep.Claims.Locations)
			}
			if l.Kind != KindMetadata {
				t.Fatalf("kind = %q, want metadata (reason: %s)", l.Kind, l.Reason)
			}
		})
	}
}

// A citation landing inside an import declaration is presence-only: it is
// kind import even when the sentence uses call wording.
func TestImportLines(t *testing.T) {
	snap := writeSnap(t)
	cases := []struct {
		name string
		cite string
		path string
	}{
		{"single import", "The product calls dep/single.go:3.", "dep/single.go"},
		{"grouped import", "The product calls dep/group.go:4-5.", "dep/group.go"},
		{"import paren line", "The product calls dep/group.go:3.", "dep/group.go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := ground(t, Options{
				CaseID:      "case-import",
				ReportJSON:  reportJSON(t, "", "", "", nil, []string{tc.cite}),
				SnapshotDir: snap,
			})
			l := locBy(rep, tc.path, "")
			if l == nil {
				t.Fatalf("citation not extracted: %+v", rep.Claims.Locations)
			}
			if l.Kind != KindImport {
				t.Fatalf("kind = %q, want import (reason: %s)", l.Kind, l.Reason)
			}
		})
	}
}

// Usage credit requires a concrete site: the cited line must sit inside a
// function/method body. Package clauses, file-only and symbol-only claims
// and unresolvable files are not usage sites.
func TestUsageRequiresFunctionBody(t *testing.T) {
	snap := writeSnap(t)
	cases := []struct {
		name string
		cite string
		want string
	}{
		{"call inside function", "The product calls dep/dep.go:5.", KindUsage},
		{"call inside method", "The product calls dep/dep.go:17.", KindUsage},
		{"package clause", "The product calls dep/dep.go:1.", KindUnknown},
		{"file only", "The product calls dep/dep.go.", KindUnknown},
		{"symbol only", "The product calls dep.Parse.", KindUnknown},
		{"missing file", "The product calls missing/x.go:3.", KindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := ground(t, Options{
				CaseID:      "case-usage",
				ReportJSON:  reportJSON(t, "", "", "", nil, []string{tc.cite}),
				SnapshotDir: snap,
			})
			var l *Location
			if tc.want == KindUsage {
				l = locBy(rep, "dep/dep.go", "")
			}
			if l == nil {
				for i := range rep.Claims.Locations {
					if rep.Claims.Locations[i].Kind == tc.want {
						l = &rep.Claims.Locations[i]
						break
					}
				}
			}
			if l == nil {
				for i := range rep.Claims.Locations {
					if rep.Claims.Locations[i].Kind != tc.want {
						t.Fatalf("claim %q kind = %q, want %q", tc.cite, rep.Claims.Locations[i].Kind, tc.want)
					}
				}
				t.Fatalf("no claim for %q", tc.cite)
			}
		})
	}
}

// Locus credit comes from a root-cause/mechanism context on a code line or
// from a claimed symbol — never from a bare manifest/version citation.
func TestLocusRequiresCodeOrSymbol(t *testing.T) {
	snap := writeSnap(t)
	cases := []struct {
		name   string
		root   string
		path   string
		symbol string
		want   string
	}{
		{"code line", "The defect is at dep/dep.go:5.", "dep/dep.go", "", KindLocus},
		{"symbol", "The defect is in dep.parseInner.", "", "dep.parseInner", KindLocus},
		{"package clause", "The defect is at dep/dep.go:1.", "dep/dep.go", "", KindUnknown},
		{"file only", "The defect is at dep/dep.go.", "dep/dep.go", "", KindUnknown},
		{"manifest", "The defect is at go.mod:1.", "go.mod", "", KindMetadata},
		{"import line", "The defect is at dep/group.go:4.", "dep/group.go", "", KindImport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := ground(t, Options{
				CaseID:      "case-locus",
				ReportJSON:  reportJSON(t, tc.root, "", "", nil, nil),
				SnapshotDir: snap,
			})
			l := locBy(rep, tc.path, tc.symbol)
			if l == nil {
				t.Fatalf("claim not extracted: %+v", rep.Claims.Locations)
			}
			if l.Kind != tc.want {
				t.Fatalf("kind = %q, want %q (reason: %s)", l.Kind, tc.want, l.Reason)
			}
		})
	}
}

// Path polarity statements are extracted verbatim from the reasoning with
// a deterministic scope: named symbol → symbol, module wording → module,
// otherwise first_party.
func TestNegativeClaims(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		polarity string
		scope    string
		path     string
		symbol   string
	}{
		{
			name: "absence first party", text: "The sink is never used from first-party code.",
			polarity: PolarityAbsence, scope: ScopeFirstParty,
		},
		{
			name: "presence calls with path", text: "The product calls ServeAgent from pkg/x.go.",
			polarity: PolarityPresence, scope: ScopeFirstParty, path: "pkg/x.go",
		},
		{
			name: "absence symbol", text: "dep.Parse is not reachable from first-party code.",
			polarity: PolarityAbsence, scope: ScopeSymbol, symbol: "dep.Parse",
		},
		{
			name: "absence module", text: "The dep module is not imported.",
			polarity: PolarityAbsence, scope: ScopeModule,
		},
		{
			name: "presence used by", text: "example.com/dep is used by the product server.",
			polarity: PolarityPresence, scope: ScopeFirstParty,
		},
		{
			name: "no call path", text: "There is no call path from main.",
			polarity: PolarityAbsence, scope: ScopeFirstParty,
		},
		{
			name: "neither nor", text: "Neither this import nor any other first-party code path imports or calls the ssh/agent subpackage.",
			polarity: PolarityAbsence, scope: ScopeFirstParty,
		},
		{
			name: "imported but never used", text: "The package example.com/ssh/agent is imported but never used from first-party code.",
			polarity: PolarityAbsence, scope: ScopeFirstParty,
		},
		{
			name: "does not invoke", text: "The product does not invoke sshagent.NewClient.",
			polarity: PolarityAbsence, scope: ScopeSymbol, symbol: "sshagent.NewClient",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := ground(t, Options{CaseID: "case-neg", RawAnswer: []byte(tc.text)})
			if len(rep.Claims.Negative) != 1 {
				t.Fatalf("negative = %+v, want exactly one claim", rep.Claims.Negative)
			}
			c := rep.Claims.Negative[0]
			if c.Raw != tc.text || c.Polarity != tc.polarity || c.Scope != tc.scope {
				t.Fatalf("claim = %+v", c)
			}
			if c.Path != tc.path || c.Symbol != tc.symbol {
				t.Fatalf("claim path/symbol = %q/%q, want %q/%q", c.Path, c.Symbol, tc.path, tc.symbol)
			}
		})
	}
}

func TestNegativeClaimsEmpty(t *testing.T) {
	rep := ground(t, Options{
		CaseID:    "case-neg-empty",
		RawAnswer: []byte("The package parses configuration input."),
	})
	if len(rep.Claims.Negative) != 0 {
		t.Fatalf("negative = %+v, want none", rep.Claims.Negative)
	}
	if rep.Claims.Negative == nil {
		t.Fatal("negative must serialize as an empty array, not null")
	}
}

// The official answer context is carried verbatim: category from
// report.json and a sha256 digest of its reasoning.
func TestReportAnswerContext(t *testing.T) {
	snap := writeSnap(t)
	reasoning := "The sink is never used from first-party code."
	rep := ground(t, Options{
		CaseID: "case-ctx",
		ReportJSON: reportJSONWithAnswer(t, "code_not_reachable", reasoning,
			"The defect is at dep/dep.go:5."),
		SnapshotDir: snap,
	})
	if rep.Report.Category != "code_not_reachable" {
		t.Fatalf("report.category = %q", rep.Report.Category)
	}
	want := "sha256:" + fmt.Sprintf("%x", sha256.Sum256([]byte(reasoning)))
	if rep.Report.ReasoningSHA256 != want {
		t.Fatalf("reasoning_sha256 = %q, want %q", rep.Report.ReasoningSHA256, want)
	}
	var absent bool
	for _, c := range rep.Claims.Negative {
		if c.Polarity == PolarityAbsence && strings.Contains(c.Raw, "never used") {
			absent = true
		}
	}
	if !absent {
		t.Fatalf("absence claim missing: %+v", rep.Claims.Negative)
	}
}

func TestReportAnswerContextAbsent(t *testing.T) {
	snap := writeSnap(t)
	rep := ground(t, Options{
		CaseID:      "case-ctx-none",
		ReportJSON:  reportJSON(t, "The defect is at dep/dep.go:5.", "", "", nil, nil),
		SnapshotDir: snap,
	})
	if rep.Report.Category != "" || rep.Report.ReasoningSHA256 != "" {
		t.Fatalf("context invented without an answer block: %+v", rep.Report)
	}
}

// reportJSONWithAnswer builds the structured mirror including the official
// answer block, as the research pipeline emits it.
func reportJSONWithAnswer(t *testing.T, category, reasoning, rootCause string) []byte {
	t.Helper()
	doc := struct {
		Answer struct {
			Category  string `json:"category"`
			Reasoning string `json:"reasoning"`
		} `json:"answer"`
		Analysis struct {
			RootCause string `json:"root_cause"`
			Reasoning string `json:"reasoning"`
		} `json:"analysis"`
	}{}
	doc.Answer.Category = category
	doc.Answer.Reasoning = reasoning
	doc.Analysis.RootCause = rootCause
	doc.Analysis.Reasoning = reasoning
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNegativeClaimsRawJSONAnswer(t *testing.T) {
	raw := `{"category":"code_not_reachable","reasoning":"The sink is never used from first-party code."}`
	rep := ground(t, Options{CaseID: "case-raw-json", RawAnswer: []byte(raw)})
	if len(rep.Claims.Negative) != 1 {
		t.Fatalf("negative = %+v", rep.Claims.Negative)
	}
	if got := rep.Claims.Negative[0].Raw; got != "The sink is never used from first-party code." {
		t.Fatalf("raw = %q", got)
	}
	if rep.Claims.Negative[0].Polarity != PolarityAbsence {
		t.Fatalf("polarity = %q", rep.Claims.Negative[0].Polarity)
	}
}

// The podman failure shape: a negated sentence with presence verbs inside,
// and an "imported but never used" sentence. Both are absence, scoped to
// first-party code, and no presence claim may survive.
func TestNegativeClaimsPodmanShape(t *testing.T) {
	text := "Neither this import nor any other first-party code path imports or calls the ssh/agent subpackage. " +
		"The package example.com/ssh/agent is imported but never used from first-party code."
	rep := ground(t, Options{CaseID: "case-podman", RawAnswer: []byte(text)})
	if len(rep.Claims.Negative) != 2 {
		t.Fatalf("negative = %+v, want two absence claims", rep.Claims.Negative)
	}
	for _, c := range rep.Claims.Negative {
		if c.Polarity != PolarityAbsence {
			t.Fatalf("polarity = %q in %+v", c.Polarity, c)
		}
		if c.Scope != ScopeFirstParty {
			t.Fatalf("scope = %q in %+v", c.Scope, c)
		}
		if c.Symbol != "" {
			t.Fatalf("import path leaked into symbol: %+v", c)
		}
	}
}

// Import wording alone is package presence, not a usage claim: it yields
// no negative/presence claim at all.
func TestImportAloneIsNotPresenceClaim(t *testing.T) {
	rep := ground(t, Options{
		CaseID:    "case-import-only",
		RawAnswer: []byte("The ssh/agent package is imported by the product."),
	})
	if len(rep.Claims.Negative) != 0 {
		t.Fatalf("import wording produced a claim: %+v", rep.Claims.Negative)
	}
}

// Caddy phrasing: a negation about authentication is not a path absence,
// and a sentence about an unapplied fix is not a path claim at all.
func TestNegativeClaimsCaddyShape(t *testing.T) {
	text := "This attack surface is reachable via network input without any authentication or configuration. " +
		"The fix (v0.50.1) is not applied."
	rep := ground(t, Options{CaseID: "case-caddy", RawAnswer: []byte(text)})

	for _, c := range rep.Claims.Negative {
		if c.Polarity == PolarityAbsence {
			t.Fatalf("false absence claim: %+v", c)
		}
	}
	// The reachability sentence is a presence statement about the attack
	// surface, not an absence claim; the fix sentence yields nothing.
	var presence bool
	for _, c := range rep.Claims.Negative {
		if c.Polarity == PolarityPresence && strings.Contains(c.Raw, "reachable via network input") {
			presence = true
		}
	}
	if !presence {
		t.Fatalf("reachability statement not classified as presence: %+v", rep.Claims.Negative)
	}
}

// Negation about validation/authentication/fix must never become a path
// claim, even with strong cues present.
func TestNonPathNegationIgnored(t *testing.T) {
	for _, text := range []string{
		"SSH Agent servers do not validate message sizes.",
		"The fix (v0.50.1) is not applied.",
		"The endpoint is not configured for TLS.",
		"The handler works without authentication.",
	} {
		rep := ground(t, Options{CaseID: "case-nonpath", RawAnswer: []byte(text)})
		if len(rep.Claims.Negative) != 0 {
			t.Fatalf("%q produced claims: %+v", text, rep.Claims.Negative)
		}
	}
}

// Podman phrasing: negation bound to usage tokens is a genuine absence,
// scoped to first-party code, with no presence claims.
func TestNegativeClaimsPodmanPhrases(t *testing.T) {
	text := "The ssh/agent package is imported but never used from first-party code. " +
		"Neither this import nor any other first-party code path imports or calls the ssh/agent subpackage. " +
		"Server-side code handling agent messages is never executed."
	rep := ground(t, Options{CaseID: "case-podman-phrases", RawAnswer: []byte(text)})
	if len(rep.Claims.Negative) != 3 {
		t.Fatalf("negative = %+v, want three absence claims", rep.Claims.Negative)
	}
	for _, c := range rep.Claims.Negative {
		if c.Polarity != PolarityAbsence {
			t.Fatalf("presence claim survived: %+v", c)
		}
		if c.Scope != ScopeFirstParty {
			t.Fatalf("scope = %q in %+v", c.Scope, c)
		}
	}
}
