package report

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// pathCase builds the canonical demo case: product checkout at
// /Users/dev/repo, gopkg.in/yaml.v2@v2.2.2 fetched to the module cache,
// a versionless local replace at /Users/dev/localmod, plus package-list
// metadata for a product and a stdlib package.
func pathCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		Product: domain.ProductSnapshot{Repository: "/Users/dev/repo"},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				{ID: "EV-MOD-1", Kind: domain.EvidenceModuleGraph, Content: `{"Path":"example.com/product","Main":true,"Dir":"/Users/dev/repo"}
{"Path":"gopkg.in/yaml.v2","Version":"v2.2.2","Dir":"/Users/dev/go/pkg/mod/gopkg.in/yaml.v2@v2.2.2"}
{"Path":"github.com/Big/mod","Version":"v1.0.0","Dir":"/cache/github.com/!big/mod@v1.0.0"}
{"Path":"example.com/lib","Replace":{"Path":"../localmod","Dir":"/Users/dev/localmod"}}
`},
				{ID: "EV-PKG-1", Kind: domain.EvidencePackageList, Content: `{"ImportPath":"example.com/product/sub","Dir":"/Users/dev/repo/sub"}
{"ImportPath":"net/http","Standard":true,"Dir":"/usr/local/go/src/net/http"}
`},
			},
		},
	}
}

func TestReportPathsFile(t *testing.T) {
	p := newReportPaths(pathCase())
	cases := []struct {
		name       string
		raw, pkg   string
		line       int
		want       string
		attributed bool
	}{
		{name: "product file", raw: "/Users/dev/repo/main.go", line: 39, want: "main.go:39", attributed: true},
		{name: "product nested", raw: "/Users/dev/repo/a/b/c.go", line: 2, want: "a/b/c.go:2", attributed: true},
		{name: "product root", raw: "/Users/dev/repo", want: ".", attributed: true},
		{name: "sibling prefix rejected", raw: "/Users/dev/repo-other/x.go", want: "x.go (unattributed)", attributed: false},
		{name: "dep module@version", raw: "/Users/dev/go/pkg/mod/gopkg.in/yaml.v2@v2.2.2/decode.go", line: 268, want: "gopkg.in/yaml.v2@v2.2.2/decode.go:268", attributed: true},
		{name: "escaped module path", raw: "/cache/github.com/!big/mod@v1.0.0/x.go", line: 5, want: "github.com/Big/mod@v1.0.0/x.go:5", attributed: true},
		{name: "versionless local replace", raw: "/Users/dev/localmod/lib.go", line: 7, want: "example.com/lib@local/lib.go:7 (local replace, version unavailable)", attributed: true},
		{name: "unknown absolute", raw: "/opt/other/x.go", line: 3, want: "x.go:3 (unattributed)", attributed: false},
		{name: "stdlib short frame", raw: "server.go", pkg: "net/http", line: 10, want: "net/http/server.go:10", attributed: true},
		{name: "short frame known pkg", raw: "h.go", pkg: "example.com/product/sub", line: 4, want: "sub/h.go:4", attributed: true},
		{name: "short frame unknown pkg keeps file", raw: "h.go", pkg: "example.com/unknown", line: 4, want: "h.go:4", attributed: true},
		{name: "relative product", raw: "main.go", line: 9, want: "main.go:9", attributed: true},
		{name: "dotdot escape unattributed", raw: "../outside/x.go", want: "../outside/x.go", attributed: false},
		{name: "windows abs unattributed", raw: `C:\src\other\x.go`, want: "x.go (unattributed)", attributed: false},
		{name: "unc unattributed", raw: `\\host\share\x.go`, want: "x.go (unattributed)", attributed: false},
		{name: "file url product", raw: "file:///Users/dev/repo/main.go", line: 1, want: "main.go:1", attributed: true},
		{name: "empty file", raw: "", line: 3, want: "", attributed: false},
		{name: "recorded line suffix kept", raw: "/Users/dev/repo/main.go:39", want: "main.go:39", attributed: true},
		{name: "recorded column suffix kept", raw: "/Users/dev/repo/main.go:39:7", want: "main.go:39:7", attributed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.location(tc.raw, tc.pkg, tc.line)
			if got.Text != tc.want {
				t.Fatalf("location(%q) = %q, want %q", tc.raw, got.Text, tc.want)
			}
			if got.Attributed != tc.attributed {
				t.Fatalf("location(%q).Attributed = %v, want %v", tc.raw, got.Attributed, tc.attributed)
			}
		})
	}
}

func TestReportPathsText(t *testing.T) {
	p := newReportPaths(pathCase())
	cases := []struct{ name, raw, want string }{
		{name: "product path embedded", raw: "open /Users/dev/repo/main.go:39 failed", want: "open main.go:39 failed"},
		{name: "dep path embedded", raw: "see /Users/dev/go/pkg/mod/gopkg.in/yaml.v2@v2.2.2/decode.go:268 now", want: "see gopkg.in/yaml.v2@v2.2.2/decode.go:268 now"},
		{name: "unknown abs marked", raw: "at /opt/other/x.go:3", want: "at x.go:3 (unattributed)"},
		{name: "http url preserved", raw: "fetch https://example.com/a/b/c/d", want: "fetch https://example.com/a/b/c/d"},
		{name: "route name preserved", raw: "route /api/v1/items ok", want: "route /api/v1/items ok"},
		{name: "import path preserved", raw: "import gopkg.in/yaml.v2 dep", want: "import gopkg.in/yaml.v2 dep"},
		{name: "quoted path", raw: `"file /Users/dev/repo/main.go"`, want: `"file main.go"`},
		{name: "windows json-escaped", raw: `C:\\Users\\dev\\repo\\main.go`, want: "main.go (unattributed)"},
		{name: "file url in text", raw: "see file:///Users/dev/repo/a.go", want: "see a.go"},
		{name: "option value", raw: "--dir=/Users/dev/repo/x", want: "--dir=x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.text(tc.raw); got != tc.want {
				t.Fatalf("text(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestReportRepositoryName(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"<VA_WORKSPACE>/eval/.gen/real-yaml-http", "real-yaml-http"},
		{"C:\\repo\\x", "x"},
		{"", "repository"},
		{"/", "repository"},
		{"C:\\", "repository"},
	}
	for _, tc := range cases {
		if got := reportRepositoryName(tc.raw); got != tc.want {
			t.Fatalf("reportRepositoryName(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
