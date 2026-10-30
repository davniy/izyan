package fixbinding

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// sameLineSource is the selected version's own file the route matches against.
const sameLineSource = `package omitted

import "errors"

func Parse(s string) (string, error) {
	return s, nil
}
`

// sameLinePatch is an ordinary executable change with no permission or
// directory operation in it: an omission the fix repairs in place.
const sameLinePatch = `diff --git a/omitted/omitted.go b/omitted/omitted.go
index 1111111..2222222 100644
--- a/omitted/omitted.go
+++ b/omitted/omitted.go
@@ -4,4 +4,7 @@
 
 func Parse(s string) (string, error) {
-	return s, nil
+	if s == "" {
+		return "", errors.New("empty")
+	}
+	return s, nil
 }
`

const sameLineModule = "example.com/dep"

func sameLineInput() SameLineInput {
	return SameLineInput{
		Locator:          "https://example.com/dep/commit/abc",
		Path:             "omitted/omitted.go",
		Module:           sameLineModule,
		Patch:            []byte(sameLinePatch),
		Selected:         []byte(sameLineSource),
		DeclaredPackages: []string{sameLineModule + "/omitted"},
	}
}

// The route's positive shape: one unambiguous preimage match, the enclosing
// selected declaration as the subject, a postimage that parses, and a declared
// boundary that covers the declaration.
func TestSameLinePreimageCorrespondsToEnclosingSelectedDeclaration(t *testing.T) {
	rec := MatchSameLinePreimage(sameLineInput())

	if rec.Status != domain.SameLineCorresponded {
		t.Fatalf("status=%s detail=%q — want CORRESPONDED", rec.Status, rec.Detail)
	}
	if rec.OmissionSite.Package != sameLineModule+"/omitted" || rec.OmissionSite.Symbol != "Parse" {
		t.Fatalf("omission site=%+v — want the enclosing selected declaration", rec.OmissionSite)
	}
	if rec.StartLine != 4 || rec.EndLine != 7 {
		t.Fatalf("span=%d-%d — want the complete before-image span 4-7", rec.StartLine, rec.EndLine)
	}
	if rec.RemovedLines != 1 || rec.AddedLines != 4 {
		t.Fatalf("removed=%d added=%d — want the changed-region dimensions", rec.RemovedLines, rec.AddedLines)
	}
	if len(rec.Cover) != 1 || rec.Cover[0] != sameLineModule+"/omitted" {
		t.Fatalf("cover=%v — want the declared boundary", rec.Cover)
	}
	if rec.PreimageDigest == "" || rec.SelectedFileDigest == "" {
		t.Fatalf("record=%+v — a corresponded route pins both digests", rec)
	}
	if _, ok := domain.PreimageDigest([]byte(sameLinePatch), "omitted/omitted.go"); !ok {
		t.Fatal("the route's own preimage must be re-derivable from the captured bytes")
	}
}

// A hunk header's function name is not the subject, and neither is the patch's
// path: the subject is read from the selected source at the matched site.
func TestSameLinePreimageUsesSelectedDeclarationNotHeaderName(t *testing.T) {
	in := sameLineInput()
	in.Patch = []byte(strings.Replace(sameLinePatch,
		"@@ -4,4 +4,7 @@\n",
		"@@ -4,4 +4,7 @@ func RenamedElsewhere(cfg Config) error {\n", 1))

	rec := MatchSameLinePreimage(in)
	if rec.Status != domain.SameLineCorresponded {
		t.Fatalf("status=%s detail=%q — a stale header name must not decide the subject", rec.Status, rec.Detail)
	}
	if rec.OmissionSite.Symbol != "Parse" {
		t.Fatalf("symbol=%q — want the selected declaration, not the header name", rec.OmissionSite.Symbol)
	}
}

// A changed preimage is a different change: the file exists, the hunk names a
// function, and none of that is correspondence.
func TestSameLinePreimageUnmatchedWhenSelectedBytesDiffer(t *testing.T) {
	in := sameLineInput()
	in.Selected = []byte(strings.Replace(sameLineSource, "return s, nil", "return s, err", 1))

	rec := MatchSameLinePreimage(in)
	if rec.Status != domain.SameLinePreimageUnmatched {
		t.Fatalf("status=%s detail=%q — want PREIMAGE_UNMATCHED", rec.Status, rec.Detail)
	}
	if rec.Covers() {
		t.Fatal("an unmatched preimage established a subject")
	}
}

// Two identical bodies are two candidates for the site, so no single
// declaration is the change's subject.
func TestSameLinePreimageAmbiguousMatchIsRefused(t *testing.T) {
	const source = `package omitted

func A() {
	one()
	two()
	three()
}

func B() {
	one()
	two()
	three()
}
`
	const patch = `diff --git a/omitted/omitted.go b/omitted/omitted.go
index 1111111..2222222 100644
--- a/omitted/omitted.go
+++ b/omitted/omitted.go
@@ -4,3 +4,3 @@
 	one()
-	two()
+	two(1)
 	three()
`
	rec := MatchSameLinePreimage(SameLineInput{
		Locator: "L", Path: "omitted/omitted.go", Module: sameLineModule,
		Patch: []byte(patch), Selected: []byte(source),
		DeclaredPackages: []string{sameLineModule + "/omitted"},
	})
	if rec.Status != domain.SameLinePreimageAmbiguous {
		t.Fatalf("status=%s detail=%q — want PREIMAGE_AMBIGUOUS", rec.Status, rec.Detail)
	}
}

// A hunk that removes nothing replaces no pre-existing code, so it names no
// omission site however well it matches.
func TestSameLinePreimagePureAdditionNamesNoOmissionSite(t *testing.T) {
	const patch = `diff --git a/omitted/omitted.go b/omitted/omitted.go
index 1111111..2222222 100644
--- a/omitted/omitted.go
+++ b/omitted/omitted.go
@@ -1,3 +1,4 @@
 package omitted
 
+// Parsed documents the entry point.
 import "errors"
`
	rec := MatchSameLinePreimage(SameLineInput{
		Locator: "L", Path: "omitted/omitted.go", Module: sameLineModule,
		Patch: []byte(patch), Selected: []byte(sameLineSource),
		DeclaredPackages: []string{sameLineModule + "/omitted"},
	})
	if rec.Status != domain.SameLineNoChangedRegion {
		t.Fatalf("status=%s detail=%q — want NO_CHANGED_REGION", rec.Status, rec.Detail)
	}
}

// An added helper must be named by the repaired site. A declaration the changed
// code never refers to is the absence of the added function, not a repair.
func TestSameLinePreimageAddedHelperNeedsACarrier(t *testing.T) {
	const helperTail = `+
+func normalize(s string) string {
+	return s
+}
`
	withHelper := strings.Replace(sameLinePatch, " }\n", " }\n"+helperTail, 1)
	withHelper = strings.Replace(withHelper, "@@ -4,4 +4,7 @@", "@@ -4,4 +4,11 @@", 1)

	in := sameLineInput()
	in.Patch = []byte(withHelper)
	rec := MatchSameLinePreimage(in)
	if rec.Status != domain.SameLineAddedHelperWithoutCarrier {
		t.Fatalf("status=%s detail=%q — want ADDED_HELPER_WITHOUT_CARRIER", rec.Status, rec.Detail)
	}

	// The same helper is carried once the changed site names it.
	carried := strings.Replace(withHelper, "+	return s, nil", "+	return normalize(s), nil", 1)
	in.Patch = []byte(carried)
	rec = MatchSameLinePreimage(in)
	if rec.Status != domain.SameLineCorresponded {
		t.Fatalf("status=%s detail=%q — a called helper is carried by the changed site", rec.Status, rec.Detail)
	}
}

// Exact identity is not a completeness theorem: without a declared package
// boundary this route has no necessity cover, so the change stays identity-only.
func TestSameLinePreimageWithoutDeclaredBoundaryEstablishesNoCover(t *testing.T) {
	in := sameLineInput()
	in.DeclaredPackages = nil
	rec := MatchSameLinePreimage(in)
	if rec.Status != domain.SameLineCoverUnestablished {
		t.Fatalf("status=%s detail=%q — want COVER_UNESTABLISHED", rec.Status, rec.Detail)
	}

	in.DeclaredPackages = []string{sameLineModule + "/other"}
	rec = MatchSameLinePreimage(in)
	if rec.Status != domain.SameLineCoverUnestablished {
		t.Fatalf("status=%s detail=%q — a boundary that omits the declaration covers nothing", rec.Status, rec.Detail)
	}
}

// Only format normalisation is supported: layout differences inside the
// fragment still match, a changed comment or literal does not.
func TestSameLinePreimageNormalisesFormatOnly(t *testing.T) {
	reflowed := strings.Replace(sameLineSource,
		"func Parse(s string) (string, error) {\n\treturn s, nil\n}",
		"func Parse(s string) (string, error) {\n\treturn s, nil }", 1)
	in := sameLineInput()
	in.Selected = []byte(reflowed)
	if rec := MatchSameLinePreimage(in); rec.Status == domain.SameLineCorresponded {
		t.Fatalf("status=%s — a reflowed line count must not be spliced as a line-for-line match", rec.Status)
	}

	commented := strings.Replace(sameLineSource, "\treturn s, nil", "\t// parsed.\n\treturn s, nil", 1)
	in = sameLineInput()
	in.Selected = []byte(commented)
	if rec := MatchSameLinePreimage(in); rec.Status != domain.SameLinePreimageUnmatched {
		t.Fatalf("status=%s detail=%q — an added comment is a different preimage", rec.Status, rec.Detail)
	}
}

// A defective hunk is not a total changed region, so it cannot establish a
// correspondence even when its lines would have matched.
func TestSameLinePreimageRefusesDefectiveEntry(t *testing.T) {
	truncated := strings.Replace(sameLinePatch, "@@ -4,4 +4,7 @@", "@@ -4,9 +4,12 @@", 1)
	in := sameLineInput()
	in.Patch = []byte(truncated)
	rec := MatchSameLinePreimage(in)
	if rec.Status != domain.SameLineMalformedChange {
		t.Fatalf("status=%s detail=%q — want MALFORMED_CHANGE", rec.Status, rec.Detail)
	}

	renamed := strings.Replace(sameLinePatch,
		"diff --git a/omitted/omitted.go b/omitted/omitted.go",
		"diff --git a/omitted/old.go b/omitted/omitted.go\nrename from omitted/old.go\nrename to omitted/omitted.go", 1)
	in = sameLineInput()
	in.Patch = []byte(renamed)
	if rec := MatchSameLinePreimage(in); rec.Status != domain.SameLinePathNotInPatch && rec.Status != domain.SameLineMalformedChange {
		t.Fatalf("status=%s detail=%q — a renamed entry is not a same-line change", rec.Status, rec.Detail)
	}
}

// The preimage the route digests is the one the domain boundary re-derives from
// the captured bytes, hunk by hunk.
func TestSameLinePreimageDigestMatchesDomainRecovery(t *testing.T) {
	text, ok := domain.PreimageText([]byte(sameLinePatch), "omitted/omitted.go")
	if !ok {
		t.Fatal("the captured patch carries no before-image")
	}
	want := "\nfunc Parse(s string) (string, error) {\n\treturn s, nil\n}\n"
	if text != want {
		t.Fatalf("preimage=%q — want %q", text, want)
	}
	digest, ok := domain.PreimageDigest([]byte(sameLinePatch), "omitted/omitted.go")
	if !ok {
		t.Fatal("no preimage digest")
	}
	rec := MatchSameLinePreimage(sameLineInput())
	if rec.PreimageDigest != digest {
		t.Fatalf("route digest=%s, recovered digest=%s", rec.PreimageDigest, digest)
	}
}
