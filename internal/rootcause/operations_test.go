package rootcause

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fix"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/vulnerability"
)

// proseOperationDetails is the shape the requirement pins: the record's own
// prose names the vulnerable operation, while the document declares no
// structured symbols at all.
const proseOperationDetails = "An issue in the ParseBytes function can cause a program to panic when attempting to deserialize invalid input."

// proseOperationPatch is the competing fix-diff candidate: it changes a
// zero-argument internal method, which is exactly the candidate that used to
// displace the advisory's own operation.
const proseOperationPatch = `diff --git a/vuln/vuln.go b/vuln/vuln.go
index 111..222 100644
--- a/vuln/vuln.go
+++ b/vuln/vuln.go
@@ -10,3 +10,6 @@ func (d *decoder) peek() byte {
-	return d.buf[d.i]
+	if d.i >= len(d.buf) {
+		return 0
+	}
+	return d.buf[d.i]
`

type proseRecordOptions struct {
	id      string
	module  string
	details string
	imports []string
}

// proseOperationRecord builds an exact OSV document (CWE-502, no structured
// symbols) and decodes it through the exact-record decoder, returning the
// decoded record and its pin.
func proseOperationRecord(t *testing.T, opts proseRecordOptions) (domain.Vulnerability, *domain.RecordPin) {
	t.Helper()
	id := opts.id
	if id == "" {
		id = "GHSA-prose-operation"
	}
	module := opts.module
	if module == "" {
		module = "example.com/dep"
	}
	var imports []string
	for _, p := range opts.imports {
		imports = append(imports, fmt.Sprintf(`{"path":%q}`, p))
	}
	raw := []byte(fmt.Sprintf(`{
  "schema_version": "1.9.0",
  "id": %q,
  "aliases": ["CVE-2099-0001"],
  "summary": "example.com/dep Denial of Service",
  "details": %q,
  "affected": [{
    "package": {"name": %q, "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
    "ecosystem_specific": {"imports": [%s]}
  }],
  "database_specific": {"cwe_ids": ["CWE-502"]},
  "references": [{"type": "FIX", "url": "https://example.com/dep/commit/abc"}]
}`, id, opts.details, module, strings.Join(imports, ",")))
	rec, err := vulnerability.LoadExactBytes(raw, id, "file:test/"+id+".json")
	if err != nil {
		t.Fatalf("exact record decode: %v", err)
	}
	if len(rec.Vuln.AffectedSymbols) != 0 {
		t.Fatalf("fixture must declare no structured symbols: %+v", rec.Vuln.AffectedSymbols)
	}
	pin := rec.Pin
	return *rec.Vuln, &pin
}

func proseOperationIndex(t *testing.T) *goanalysis.Index {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	if err != nil {
		t.Fatal(err)
	}
	return &goanalysis.Index{Dir: abs}
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// duplicateOperationModule writes a module whose two packages each declare
// ParseBytes, so the declared name is genuinely ambiguous inside scope.
func duplicateOperationModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFixtureFile(t, filepath.Join(dir, "go.mod"), "module example.com/dupmod\n\ngo 1.23\n")
	writeFixtureFile(t, filepath.Join(dir, "main.go"), `package main

import (
	a "example.com/dupmod/a"
	b "example.com/dupmod/b"
)

func main() {
	_ = a.ParseBytes(nil)
	_ = b.ParseBytes(nil)
}
`)
	writeFixtureFile(t, filepath.Join(dir, "a", "a.go"), "package a\n\nfunc ParseBytes(p []byte) string { return string(p) }\n")
	writeFixtureFile(t, filepath.Join(dir, "b", "b.go"), "package b\n\nfunc ParseBytes(p []byte) string { return string(p) }\n")
	return dir
}

// TestOperationBindingResolvesProseOperationFromExactRecord is the required
// positive: an exact document with CWE-502 that names ParseBytes in prose and
// no structured symbols, whose fix changes a zero-argument internal method.
// The prose operation is uniquely bound; the fix-diff method stays an
// alternative; the raw advisory fields are untouched.
func TestOperationBindingResolvesProseOperationFromExactRecord(t *testing.T) {
	v, pin := proseOperationRecord(t, proseRecordOptions{
		details: proseOperationDetails,
		imports: []string{"example.com/dep/vuln"},
	})
	digest := pin.DocumentDigest
	c := &domain.AnalysisCase{ID: "CASE-PROSE-1", Vulnerability: v, RecordPin: pin}
	r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}

	m, evs, err := r.Resolve(context.Background(), c, v)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if m.Status != domain.RootCauseResolved {
		t.Fatalf("status=%s limitations=%v", m.Status, m.Limitations)
	}
	if len(m.RootCauses) != 1 {
		t.Fatalf("root causes=%+v", m.RootCauses)
	}
	rc := m.RootCauses[0]
	if rc.Package != "example.com/dep/vuln" || rc.Symbol != "ParseBytes" || rc.Role != domain.RootCauseSink {
		t.Fatalf("prose operation must be the modeled sink, got %+v", rc)
	}
	if len(m.OperationBindings) != 1 {
		t.Fatalf("operation bindings=%+v", m.OperationBindings)
	}
	b := m.OperationBindings[0]
	if b.RecordID != v.ID || b.DocumentDigest != digest {
		t.Fatalf("binding identity=%+v (record %s digest %s)", b, v.ID, digest)
	}
	if b.AffectedEntry != "example.com/dep" {
		t.Fatalf("binding affected entry=%q", b.AffectedEntry)
	}
	if b.Operation != "ParseBytes" || b.Symbol != "ParseBytes" || b.Package != "example.com/dep/vuln" {
		t.Fatalf("binding identity=%+v", b)
	}
	if b.Quotation != proseOperationDetails {
		t.Fatalf("quotation must be verbatim: %q", b.Quotation)
	}
	if !strings.HasSuffix(b.SourceFile, "vuln.go") || b.SourceLine <= 0 {
		t.Fatalf("source binding=%q:%d", b.SourceFile, b.SourceLine)
	}
	if len(m.OperationDeclarations) != 1 || m.OperationDeclarations[0].Resolution != domain.OperationBound {
		t.Fatalf("declarations=%+v", m.OperationDeclarations)
	}
	// The fix-diff candidate is kept as corroborating evidence, not promoted.
	var altSymbols []string
	for _, alt := range m.Alternatives {
		altSymbols = append(altSymbols, alt.Symbol)
	}
	if !strings.Contains(strings.Join(altSymbols, ","), "peek") {
		t.Fatalf("fix-changed zero-argument method must stay an alternative: %+v", m.Alternatives)
	}

	// The record's own bytes decide everything: nothing downstream of the
	// mosaic is populated or rewritten.
	if len(c.Vulnerability.AffectedSymbols) != 0 {
		t.Fatalf("raw advisory symbols were populated: %+v", c.Vulnerability.AffectedSymbols)
	}
	if len(c.Vulnerability.CWE) != 1 || c.Vulnerability.CWE[0] != "CWE-502" {
		t.Fatalf("raw CWE changed: %v", c.Vulnerability.CWE)
	}
	if len(c.Vulnerability.Aliases) != 1 || c.Vulnerability.Aliases[0] != "CVE-2099-0001" {
		t.Fatalf("raw aliases changed: %v", c.Vulnerability.Aliases)
	}
	if c.RecordPin == nil || c.RecordPin.DocumentDigest != digest {
		t.Fatalf("record pin changed: %+v", c.RecordPin)
	}

	// The verbatim quotation and the source declaration are evidence.
	var sawQuotation, sawSource bool
	for _, e := range evs {
		if e.Kind == domain.EvidenceAdvisory && strings.Contains(e.Content, proseOperationDetails) {
			sawQuotation = true
		}
		if e.Kind == domain.EvidenceSourceSnippet && strings.Contains(e.Content, "example.com/dep/vuln.ParseBytes") {
			sawSource = true
		}
	}
	if !sawQuotation || !sawSource {
		t.Fatalf("binding evidence missing: quotation=%v source=%v (%+v)", sawQuotation, sawSource, evs)
	}
}

// TestOperationBindingControls pins every boundary: only a unique,
// source-bound declaration inside the record's own scope admits a binding, and
// every other outcome preserves the declaration without producing one.
func TestOperationBindingControls(t *testing.T) {
	t.Run("structured advisory symbols outrank prose", func(t *testing.T) {
		v, pin := proseOperationRecord(t, proseRecordOptions{
			details: proseOperationDetails,
			imports: []string{"example.com/dep/vuln"},
		})
		v.AffectedSymbols = []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Parse"}}
		c := &domain.AnalysisCase{ID: "CASE-PROSE-2", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.RootCauses) != 1 || m.RootCauses[0].Symbol != "Parse" {
			t.Fatalf("structured symbol must win: %+v", m.RootCauses)
		}
		if len(m.OperationBindings) != 0 || len(m.OperationDeclarations) != 0 {
			t.Fatalf("prose must not be consulted when symbols exist: %+v %+v", m.OperationBindings, m.OperationDeclarations)
		}
	})

	t.Run("duplicate names are ambiguous", func(t *testing.T) {
		dir := duplicateOperationModule(t)
		v, pin := proseOperationRecord(t, proseRecordOptions{
			id:      "GHSA-prose-duplicate",
			module:  "example.com/dupmod",
			details: proseOperationDetails,
			imports: []string{"example.com/dupmod/a", "example.com/dupmod/b"},
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-3", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: &goanalysis.Index{Dir: dir}}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationBindings) != 0 {
			t.Fatalf("ambiguous name must not bind: %+v", m.OperationBindings)
		}
		if len(m.OperationDeclarations) != 1 || m.OperationDeclarations[0].Resolution != domain.OperationAmbiguous {
			t.Fatalf("declarations=%+v", m.OperationDeclarations)
		}
		if !strings.Contains(m.OperationDeclarations[0].Detail, "example.com/dupmod/a") ||
			!strings.Contains(m.OperationDeclarations[0].Detail, "example.com/dupmod/b") {
			t.Fatalf("ambiguity detail must name the competitors: %q", m.OperationDeclarations[0].Detail)
		}
	})

	t.Run("wrong module does not bind", func(t *testing.T) {
		v, pin := proseOperationRecord(t, proseRecordOptions{
			id:      "GHSA-prose-wrongmodule",
			module:  "example.com/other",
			details: proseOperationDetails,
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-4", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationBindings) != 0 {
			t.Fatalf("package outside the record's scope must not bind: %+v", m.OperationBindings)
		}
		if len(m.OperationDeclarations) != 1 || m.OperationDeclarations[0].Resolution != domain.OperationUnresolved {
			t.Fatalf("declarations=%+v", m.OperationDeclarations)
		}
		if len(m.RootCauses) == 0 || m.RootCauses[0].Symbol != "decoder.peek" {
			t.Fatalf("fix-diff fallback expected after a failed declaration: %+v", m.RootCauses)
		}
	})

	t.Run("non-resolving declaration does not bind", func(t *testing.T) {
		v, pin := proseOperationRecord(t, proseRecordOptions{
			id:      "GHSA-prose-missing",
			details: "An issue in the MissingBytes function can cause a program to panic when attempting to deserialize invalid input.",
			imports: []string{"example.com/dep/vuln"},
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-5", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationBindings) != 0 {
			t.Fatalf("unresolved name must not bind: %+v", m.OperationBindings)
		}
		if len(m.OperationDeclarations) != 1 || m.OperationDeclarations[0].Resolution != domain.OperationUnresolved {
			t.Fatalf("declarations=%+v", m.OperationDeclarations)
		}
		if !strings.Contains(m.OperationDeclarations[0].Detail, "example.com/dep/vuln") {
			t.Fatalf("detail must name the searched scope: %q", m.OperationDeclarations[0].Detail)
		}
	})

	t.Run("incidental mention is not a declaration", func(t *testing.T) {
		v, pin := proseOperationRecord(t, proseRecordOptions{
			id:      "GHSA-prose-mention",
			details: "The ParseBytes helper is unrelated to this defect, which concerns the decoder.",
			imports: []string{"example.com/dep/vuln"},
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-6", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationDeclarations) != 0 || len(m.OperationBindings) != 0 {
			t.Fatalf("a mention must not declare: %+v %+v", m.OperationDeclarations, m.OperationBindings)
		}
		if len(m.RootCauses) == 0 || m.RootCauses[0].Symbol != "decoder.peek" {
			t.Fatalf("fix-diff fallback expected: %+v", m.RootCauses)
		}
	})

	t.Run("contradictory declarations do not bind", func(t *testing.T) {
		v, pin := proseOperationRecord(t, proseRecordOptions{
			id: "GHSA-prose-conflict",
			details: proseOperationDetails +
				" A flaw in the Parse function allows an attacker to corrupt documents.",
			imports: []string{"example.com/dep/vuln"},
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-7", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationBindings) != 0 {
			t.Fatalf("conflicting declarations must not bind: %+v", m.OperationBindings)
		}
		if len(m.OperationDeclarations) != 2 {
			t.Fatalf("both declarations must be preserved: %+v", m.OperationDeclarations)
		}
		for _, d := range m.OperationDeclarations {
			if d.Resolution != domain.OperationConflicted || d.Detail == "" {
				t.Fatalf("conflicted declaration=%+v", d)
			}
		}
	})

	t.Run("loader failure leaves the declaration unresolved", func(t *testing.T) {
		v, pin := proseOperationRecord(t, proseRecordOptions{
			id:      "GHSA-prose-loader",
			details: proseOperationDetails,
			imports: []string{"example.com/dep/vuln"},
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-8", Vulnerability: v, RecordPin: pin}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: &goanalysis.Index{Dir: t.TempDir()}}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationBindings) != 0 {
			t.Fatalf("loader failure must not bind: %+v", m.OperationBindings)
		}
		if len(m.OperationDeclarations) != 1 || m.OperationDeclarations[0].Resolution != domain.OperationUnresolved {
			t.Fatalf("declarations=%+v", m.OperationDeclarations)
		}
	})

	t.Run("unpinned record leaves the declaration unresolved", func(t *testing.T) {
		v, _ := proseOperationRecord(t, proseRecordOptions{
			id:      "GHSA-prose-unpinned",
			details: proseOperationDetails,
			imports: []string{"example.com/dep/vuln"},
		})
		c := &domain.AnalysisCase{ID: "CASE-PROSE-9", Vulnerability: v}
		r := Resolver{Fix: fix.Resolver{}, Patch: &fakePatch{out: proseOperationPatch}, Source: proseOperationIndex(t)}
		m, _, err := r.Resolve(context.Background(), c, v)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.OperationBindings) != 0 {
			t.Fatalf("unpinned record must not bind: %+v", m.OperationBindings)
		}
		if len(m.OperationDeclarations) != 1 || m.OperationDeclarations[0].Resolution != domain.OperationUnresolved {
			t.Fatalf("declarations=%+v", m.OperationDeclarations)
		}
		if !strings.Contains(m.OperationDeclarations[0].Detail, "not pinned") {
			t.Fatalf("detail must name the missing pin: %q", m.OperationDeclarations[0].Detail)
		}
	})
}

// TestOperationBindingAdmissionRejectsStaleEvidence covers the persisted-model
// path: a binding that no longer matches the record's bytes, quotation, scope
// or affected entry is not re-admitted.
func TestOperationBindingAdmissionRejectsStaleEvidence(t *testing.T) {
	v, pin := proseOperationRecord(t, proseRecordOptions{
		id:      "GHSA-prose-admission",
		details: proseOperationDetails,
		imports: []string{"example.com/dep/vuln"},
	})
	base := domain.OperationBinding{
		RecordID:       v.ID,
		DocumentDigest: pin.DocumentDigest,
		AffectedEntry:  "example.com/dep",
		Operation:      "ParseBytes",
		Quotation:      proseOperationDetails,
		Package:        "example.com/dep/vuln",
		Symbol:         "ParseBytes",
		SourceFile:     "vuln/vuln.go",
		SourceLine:     17,
	}
	if _, err := domain.AdmitOperationBinding(base, v, pin); err != nil {
		t.Fatalf("baseline binding must admit: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*domain.OperationBinding)
		reason string
	}{
		{"stale-quotation", func(b *domain.OperationBinding) {
			b.Quotation = "A flaw in the ParseBytes function crashes callers."
		}, "quotation"},
		{"stale-digest", func(b *domain.OperationBinding) {
			b.DocumentDigest = "sha256:" + strings.Repeat("0", 64)
		}, "not this record"},
		{"wrong-record", func(b *domain.OperationBinding) { b.RecordID = "GHSA-other" }, "not this record"},
		{"outside-scope", func(b *domain.OperationBinding) { b.Package = "example.com/other/vuln" }, "outside"},
		{"stale-affected-entry", func(b *domain.OperationBinding) { b.AffectedEntry = "example.com/dep/vuln" }, "affected entry"},
		{"quotation-names-another-operation", func(b *domain.OperationBinding) {
			b.Operation = "Parse"
			b.Symbol = "Parse"
		}, "does not name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			tc.mutate(&b)
			_, err := domain.AdmitOperationBinding(b, v, pin)
			if err == nil {
				t.Fatalf("stale binding was re-admitted: %+v", b)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("rejection reason %q does not mention %q", err.Error(), tc.reason)
			}
		})
	}
}

// TestOperationBindingRealAdvisoryProse pins the declaration extractor on the
// record texts the defect was observed on. The YAML family names the operation
// in its own prose; the impact-only and project-name texts declare nothing, so
// a project or a consequence can never become a root cause.
func TestOperationBindingRealAdvisoryProse(t *testing.T) {
	cases := []struct {
		name    string
		summary string
		details string
		want    []string
	}{
		{
			name:    "ghsa-yaml-names-the-operation",
			summary: "gopkg.in/yaml.v3 Denial of Service",
			details: "An issue in the Unmarshal function in Go-Yaml v3 can cause a program to panic when attempting to deserialize invalid input.",
			want:    []string{"Unmarshal"},
		},
		{
			name:    "go-yaml-names-the-operation",
			summary: "Panic in gopkg.in/yaml.v3",
			details: "An issue in the Unmarshal function can cause a program to panic when attempting to deserialize invalid input.",
			want:    []string{"Unmarshal"},
		},
		{
			name:    "rapid-reset-names-no-operation",
			summary: "HTTP/2 rapid reset can cause excessive work in net/http",
			details: "A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive server resource consumption.",
		},
		{
			name:    "project-name-is-not-an-operation",
			summary: "Cilium policy bypass",
			details: "A vulnerability in Cilium's policy engine allows an attacker to bypass egress rules.",
		},
		{
			name:    "technology-parser-is-not-a-go-operation",
			details: "A security vulnerability has been identified in the GraphQL parser used by the API.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := domain.Vulnerability{ID: "GHSA-prose", Summary: tc.summary, Description: tc.details}
			decls := operationDeclarations(v)
			var got []string
			for _, d := range decls {
				got = append(got, d.Operation)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("declarations=%v, want %v (details %q)", got, tc.want, tc.details)
			}
			for _, d := range decls {
				if !strings.Contains(d.Quotation, d.Operation) {
					t.Fatalf("quotation must carry the name verbatim: %+v", d)
				}
			}
		})
	}
}
