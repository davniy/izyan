package fixbinding

import (
	"strings"
	"testing"
)

const f4Before = `package server

import (
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	Root    string
	State   string
	TempDir string
}

var buf []byte

func CreateTopLevelDirectories(config *Config) error {
	if config.Root == "" {
		return errors.New("root must be set")
	}
	if err := os.MkdirAll(config.Root, 0o711); err != nil {
		return err
	}
	return nil
}
`

const f4After = `package server

import (
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	Root    string
	State   string
	TempDir string
}

var buf []byte

func CreateTopLevelDirectories(config *Config) error {
	if config.Root == "" {
		return errors.New("root must be set")
	}
	if config.Root != config.State {
		return errors.New("root and state must be different")
	}
	if err := os.MkdirAll(config.Root, 0o700); err != nil {
		return err
	}
	root := filepath.Join(config.Root, "bound"); copy(buf, []byte(root))
	return nil
}
`

const f4Patch = `diff --git a/pkg/server/server.go b/pkg/server/server.go
--- a/pkg/server/server.go
+++ b/pkg/server/server.go
@@ -18,8 +18,12 @@ func CreateTopLevelDirectories(config *Config) error {
 	if config.Root == "" {
 		return errors.New("root must be set")
 	}
-	if err := os.MkdirAll(config.Root, 0o711); err != nil {
+	if config.Root != config.State {
+		return errors.New("root and state must be different")
+	}
+	if err := os.MkdirAll(config.Root, 0o700); err != nil {
 		return err
 	}
+	root := filepath.Join(config.Root, "bound"); copy(buf, []byte(root))
 	return nil
 }
`

func f4Source() *SourceBundle {
	return &SourceBundle{
		Module: ModuleIdentity{Path: "example.com/app", Version: "v1.0.0"},
		Files: map[string]FileSource{
			"pkg/server/server.go": {Before: []byte(f4Before), After: []byte(f4After)},
		},
	}
}

// TestMixedHunkRetainsEveryExecutableResidual pins F4: a hunk that changes a
// permission value and also changes a guard, a resource derivation and a copy
// keeps every executable change visible. Recognition consumes the permission
// token spans only; the other statements are blocking residual obligations.
func TestMixedHunkRetainsEveryExecutableResidual(t *testing.T) {
	t.Run("mode change plus residual statements", testMixedHunkResiduals)
	t.Run("truncated hunk", testTruncatedHunk)
	t.Run("malformed hunk header", testMalformedHunk)
	t.Run("semantic directive", testSemanticDirective)
	t.Run("ordinary comment", testOrdinaryComment)
	t.Run("unaccounted file forms", testUnaccountedFiles)
	t.Run("empty and non-diff bytes", testEmptyPatch)
}

func testMixedHunkResiduals(t *testing.T) {
	inv, err := InventoryPatch([]byte(f4Patch), InventoryOptions{Source: f4Source()})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("inventory is not internally consistent: %v", err)
	}

	// The changed permission value is consumed by a typed effect.
	var permission *Effect
	for i := range inv.Effects {
		if inv.Effects[i].Class == ClassDirCreate {
			permission = &inv.Effects[i]
		}
	}
	if permission == nil {
		t.Fatalf("the changed mode must be consumed as a dir-create effect: %+v", inv.Effects)
	}
	if permission.Before == nil || permission.After == nil {
		t.Fatalf("the mode change must be a value change: %+v", permission)
	}
	if permission.Before.Mode != "0711" || permission.After.Mode != "0700" {
		t.Fatalf("mode before/after = %q/%q", permission.Before.Mode, permission.After.Mode)
	}
	if permission.Before.Identity.ImportPath != "os" || permission.Before.Identity.Name != "MkdirAll" {
		t.Fatalf("resolved API = %+v", permission.Before.Identity)
	}
	if !permission.Before.Resource.Resolved() || !permission.After.Resource.Resolved() {
		t.Fatalf("resource identity must be resolved: %+v / %+v", permission.Before.Resource, permission.After.Resource)
	}
	if !permission.Before.Resource.Equal(permission.After.Resource) {
		t.Fatal("the resource identity must be equal across the mode change")
	}

	// Every other executable change is a residual; none may disappear.
	kinds := map[ResidualKind]int{}
	for _, r := range inv.Residuals {
		kinds[r.Kind]++
		if !r.Blocks {
			t.Fatalf("residual %s must block closure", r.ID)
		}
		if len(r.SpanIDs) == 0 {
			t.Fatalf("residual %s names no changed span", r.ID)
		}
	}
	for _, want := range []ResidualKind{ResidualGuard, ResidualDerivation, ResidualCopy} {
		if kinds[want] == 0 {
			t.Fatalf("residual kind %s is missing: %+v", want, kinds)
		}
	}
	if inv.Complete() {
		t.Fatal("a mixed hunk with unconsumed executable changes cannot be complete")
	}
	if got := len(inv.Obligations()); got < 3 {
		t.Fatalf("obligations = %d, want every residual represented", got)
	}

	// The two statements on the added derivation line are separate spans, not
	// one line-granular span.
	var lineSpans []Span
	for _, sp := range inv.Spans {
		if sp.Image == ImageAfter && sp.StartLine == 27 && sp.Disposition == SpanResidual {
			lineSpans = append(lineSpans, sp)
		}
	}
	if len(lineSpans) != 2 {
		t.Fatalf("line 27 must carry two separate residual spans, got %+v", lineSpans)
	}
	if lineSpans[0].Text == lineSpans[1].Text {
		t.Fatalf("the two statements were merged into one span: %+v", lineSpans)
	}
	if !strings.Contains(lineSpans[0].Text, "root") || !strings.Contains(lineSpans[1].Text, "copy") {
		t.Fatalf("the two statements were not separated: %+v", lineSpans)
	}
}

func testTruncatedHunk(t *testing.T) {
	patch := "diff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ -1,2 +1,3 @@\n package x\n+var y = 1\n"
	inv, err := InventoryPatch([]byte(patch), InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Defects) == 0 {
		t.Fatal("a truncated hunk must record a defect")
	}
	if len(inv.Residuals) == 0 {
		t.Fatal("a truncated hunk's changed lines must stay residual")
	}
	if inv.Complete() {
		t.Fatal("a truncated hunk cannot yield a complete inventory")
	}
}

func testMalformedHunk(t *testing.T) {
	patch := "diff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ nope @@\n+var y = 1\n"
	inv, err := InventoryPatch([]byte(patch), InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Defects) == 0 {
		t.Fatal("a malformed hunk header must record a defect")
	}
	if inv.Complete() {
		t.Fatal("a malformed hunk cannot yield a complete inventory")
	}
}

func testSemanticDirective(t *testing.T) {
	inv := inventoryCommentPatch(t, "//go:build linux")
	found := false
	for _, r := range inv.Residuals {
		if r.Kind == ResidualDirective {
			found = true
		}
	}
	if !found {
		t.Fatalf("a semantic directive must be a residual, got %+v", inv.Residuals)
	}
	if inv.Complete() {
		t.Fatal("a build directive change cannot be non-executable")
	}
}

func testOrdinaryComment(t *testing.T) {
	inv := inventoryCommentPatch(t, "// helper note")
	if len(inv.Residuals) != 0 {
		t.Fatalf("an ordinary comment is non-executable, got %+v", inv.Residuals)
	}
	if !inv.Complete() {
		t.Fatalf("an ordinary comment change is a complete, non-executable account: %v", inv.Validate())
	}
	found := false
	for _, sp := range inv.Spans {
		if sp.Disposition == SpanNonExecutable && sp.Rule == "ordinary-comment" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the ordinary comment must be accounted under the comment rule: %+v", inv.Spans)
	}
}

// inventoryCommentPatch adds one comment line in front of a small file and
// inventories it.
func inventoryCommentPatch(t *testing.T, added string) *Inventory {
	t.Helper()
	before := "package server\n\nvar x = 1\n"
	patch := "diff --git a/pkg/server/notes.go b/pkg/server/notes.go\n" +
		"--- a/pkg/server/notes.go\n+++ b/pkg/server/notes.go\n" +
		"@@ -1,3 +1,4 @@\n+" + added + "\n package server\n \n var x = 1\n"
	source := &SourceBundle{
		Module: ModuleIdentity{Path: "example.com/app"},
		Files: map[string]FileSource{
			"pkg/server/notes.go": {
				Before: []byte(before),
				After:  []byte(added + "\n" + before),
			},
		},
	}
	inv, err := InventoryPatch([]byte(patch), InventoryOptions{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func testUnaccountedFiles(t *testing.T) {
	cases := map[string]string{
		"binary":    "diff --git a/blob.bin b/blob.bin\nnew file mode 100644\nindex 0000000..1111111\nBinary files /dev/null and b/blob.bin differ\n",
		"mode-only": "diff --git a/x.go b/x.go\nold mode 100644\nnew mode 100755\n",
		"rename":    "diff --git a/old.go b/new.go\nsimilarity index 100%\nrename from old.go\nrename to new.go\n",
		"no hunk":   "diff --git a/x.go b/x.go\nindex 1111111..2222222 100644\n",
	}
	for name, patch := range cases {
		t.Run(name, func(t *testing.T) {
			inv, err := InventoryPatch([]byte(patch), InventoryOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if inv.Complete() {
				t.Fatalf("%s must block inventory completeness", name)
			}
			if len(inv.Defects) == 0 && len(inv.Residuals) == 0 {
				t.Fatalf("%s must record the unaccounted fact", name)
			}
		})
	}
}

func testEmptyPatch(t *testing.T) {
	if _, err := InventoryPatch([]byte("   \n"), InventoryOptions{}); err == nil {
		t.Fatal("empty patch bytes must be an error")
	}
	if inv, err := InventoryPatch([]byte("this is not a diff\n"), InventoryOptions{}); err != nil {
		t.Fatalf("unparseable bytes must be an inventory with defects, not an error: %v", err)
	} else if inv.Complete() {
		t.Fatal("unparseable bytes cannot be complete")
	}
}
