package fixbinding

import (
	"strings"
	"testing"
)

// TestPatchSourceFromSelectedAcceptsOnlyVerifiedPreimages pins the producer
// rule: a patch-side capture may be built from the selected implementation only
// where the complete before-image matches it exactly once. A changed or
// ambiguous before-image leaves the file out, so the inventory keeps a named
// obligation instead of resolving identifiers against another tree.
func TestPatchSourceFromSelectedAcceptsOnlyVerifiedPreimages(t *testing.T) {
	const path = "pkg/server/server.go"
	selected := []byte(`package server

import "os"

func Root(cfg string) error {
	return os.MkdirAll(cfg, 0o755)
}

func Other(cfg string) error {
	return nil
}
`)

	cases := []struct {
		name      string
		patch     string
		wantFiles int
		wantCause string
	}{
		{
			name: "replacement applies exactly once",
			patch: `diff --git a/pkg/server/server.go b/pkg/server/server.go
--- a/pkg/server/server.go
+++ b/pkg/server/server.go
@@ -5,3 +5,3 @@ import "os"
 func Root(cfg string) error {
-	return os.MkdirAll(cfg, 0o755)
+	return os.MkdirAll(cfg, 0o700)
 }
`,
			wantFiles: 1,
		},
		{
			name: "insertion-only hunk is located by its context",
			patch: `diff --git a/pkg/server/server.go b/pkg/server/server.go
--- a/pkg/server/server.go
+++ b/pkg/server/server.go
@@ -5,3 +5,6 @@ import "os"
 func Root(cfg string) error {
+	if cfg == "" {
+		return nil
+	}
 	return os.MkdirAll(cfg, 0o755)
 }
`,
			wantFiles: 1,
		},
		{
			name: "changed before-image does not apply",
			patch: `diff --git a/pkg/server/server.go b/pkg/server/server.go
--- a/pkg/server/server.go
+++ b/pkg/server/server.go
@@ -5,3 +5,3 @@ import "os"
 func Root(cfg string) error {
-	return os.MkdirAll(cfg, 0o711)
+	return os.MkdirAll(cfg, 0o700)
 }
`,
			wantCause: "occurs 0 times",
		},
		{
			name: "an unanchored path is left out",
			patch: `diff --git a/pkg/other/other.go b/pkg/other/other.go
new file mode 100644
--- /dev/null
+++ b/pkg/other/other.go
@@ -0,0 +1,2 @@
+package other
+
`,
			wantCause: "captured no file at this path",
		},
	}

	module := ModuleIdentity{Path: "example.com/dep", Version: "v1.0.0"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle, unmatched := PatchSourceFromSelected([]byte(tc.patch), module, map[string][]byte{path: selected})
			if tc.wantFiles == 0 {
				if bundle != nil {
					t.Fatalf("bundle = %+v, want no patch-side source", bundle)
				}
				if len(unmatched) == 0 {
					t.Fatal("no unmatched reason was reported")
				}
				if !strings.Contains(unmatched[0], tc.wantCause) {
					t.Fatalf("unmatched = %q, want it to contain %q", unmatched[0], tc.wantCause)
				}
				return
			}
			if bundle == nil || len(bundle.Files) != tc.wantFiles {
				t.Fatalf("bundle = %+v unmatched = %q, want %d file(s)", bundle, unmatched, tc.wantFiles)
			}
			file := bundle.Files[path]
			if string(file.Before) != string(selected) || string(file.Selected) != string(selected) {
				t.Fatalf("before/selected images are not the selected bytes:\n%s", file.Before)
			}
			if len(file.After) == 0 || string(file.After) == string(file.Before) {
				t.Fatalf("after image was not spliced:\n%s", file.After)
			}
			if bundle.Module != module {
				t.Fatalf("module = %+v, want %+v", bundle.Module, module)
			}
		})
	}
}
