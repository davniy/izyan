package triage

import (
	"strings"
	"testing"
)

func TestLocator(t *testing.T) {
	type span struct {
		path  string
		start int
		end   int
	}
	cases := []struct {
		name    string
		locator string
		want    span
		wantErr string
	}{
		{"bare path", "pkg/parse.go", span{path: "pkg/parse.go"}, ""},
		{"colon single line", "pkg/parse.go:42", span{"pkg/parse.go", 42, 42}, ""},
		{"colon range", "pkg/parse.go:42-57", span{"pkg/parse.go", 42, 57}, ""},
		{"hash single line", "pkg/parse.go#L42", span{"pkg/parse.go", 42, 42}, ""},
		{"hash range", "pkg/parse.go#L42-L57", span{"pkg/parse.go", 42, 57}, ""},
		{"single digit range", "x.go:1-2", span{"x.go", 1, 2}, ""},
		{"leading dot segment", "./pkg/parse.go", span{path: "pkg/parse.go"}, ""},
		{"redundant separators", "pkg//sub//parse.go", span{path: "pkg/sub/parse.go"}, ""},
		{"interior dot segment", "pkg/./parse.go", span{path: "pkg/parse.go"}, ""},
		{"empty locator", "", span{}, "empty"},
		{"blank locator", "   ", span{}, "empty"},
		{"absolute path", "/etc/passwd", span{}, "outside"},
		{"absolute path with line", "/etc/passwd:10", span{}, "outside"},
		{"parent escape", "../secret.go", span{}, "escapes"},
		{"embedded parent escape", "pkg/../../secret.go", span{}, "escapes"},
		{"root directory", ".", span{}, "no file"},
		{"empty path before line", ":42", span{}, "no path"},
		{"empty hash fragment", "pkg/parse.go#", span{}, "line spec"},
		{"hash without L", "pkg/parse.go#42", span{}, "line spec"},
		{"hash bare L", "pkg/parse.go#L", span{}, "line spec"},
		{"hash missing end L", "pkg/parse.go#L42-57", span{}, "line spec"},
		{"hash missing end number", "pkg/parse.go#L42-L", span{}, "line spec"},
		{"colon trailing dash", "pkg/parse.go:42-", span{}, "line spec"},
		{"colon leading dash", "pkg/parse.go:-57", span{}, "line spec"},
		{"colon double range", "pkg/parse.go:1-2-3", span{}, "line spec"},
		{"reversed colon range", "pkg/parse.go:57-42", span{}, "reversed"},
		{"reversed hash range", "pkg/parse.go#L57-L42", span{}, "reversed"},
		{"zero line", "pkg/parse.go:0", span{}, "1-based"},
		{"zero range end", "pkg/parse.go:1-0", span{}, "reversed"},
		{"hash zero line", "pkg/parse.go#L0", span{}, "1-based"},
		{"non-numeric suffix keeps colon", "pkg/parse.go:abc", span{}, "snapshot-relative"},
		{"drive letter path", "C:/work/file.go:10", span{}, "snapshot-relative"},
		{"colon inside filename", "weird:name.go", span{}, "snapshot-relative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFileLocator(tc.locator)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseFileLocator(%q) succeeded, want error containing %q", tc.locator, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseFileLocator(%q) error %q does not contain %q", tc.locator, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFileLocator(%q): %v", tc.locator, err)
			}
			if got.path != tc.want.path || got.start != tc.want.start || got.end != tc.want.end {
				t.Fatalf("parseFileLocator(%q) = %+v, want %+v", tc.locator, got, tc.want)
			}
			if got.abs {
				t.Fatalf("parseFileLocator(%q) marked absolute", tc.locator)
			}
		})
	}
}

func TestArtifactLocator(t *testing.T) {
	abs, err := parseArtifactLocator("/tmp/outside/sbom.json")
	if err != nil {
		t.Fatalf("parseArtifactLocator absolute: %v", err)
	}
	if !abs.abs || abs.path != "/tmp/outside/sbom.json" || abs.start != 0 {
		t.Fatalf("abs locator = %+v", abs)
	}
	rel, err := parseArtifactLocator("sbom/sbom.json:10-20")
	if err != nil {
		t.Fatalf("parseArtifactLocator relative: %v", err)
	}
	if rel.abs || rel.path != "sbom/sbom.json" || rel.start != 10 || rel.end != 20 {
		t.Fatalf("rel locator = %+v", rel)
	}
	if _, err := parseArtifactLocator("../sbom.json"); err == nil {
		t.Fatal("parent escape accepted for artifact locator")
	}
	if _, err := parseArtifactLocator(""); err == nil {
		t.Fatal("empty artifact locator accepted")
	}
}
