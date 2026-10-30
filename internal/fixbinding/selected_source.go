package fixbinding

import (
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// PatchSourceFromSelected builds the patch-side source bundle from the
// selected implementation itself, but only for a file whose complete
// before-image matches the selected source exactly once.
//
// This is the "verified same-line preimage" input the correspondence may
// resolve identifiers against. The bundle is anchored rather than asserted:
// every file in it carries the selected bytes as both the before image and the
// selected image, and an after image produced by splicing the patch's own hunks
// into those bytes. A file whose change does not apply that way is left out and
// reported in unmatched, so the inventory keeps a MISSING_PATCH_SOURCE
// obligation for it instead of resolving its identifiers against bytes that
// describe a different tree.
//
// It returns a nil bundle when no changed file applies to the selected source;
// the caller must then leave the patch side unresolved.
func PatchSourceFromSelected(patch []byte, module ModuleIdentity, selected map[string][]byte) (*SourceBundle, []string) {
	diff := ParseUnifiedDiff(patch)
	bundle := &SourceBundle{Module: module, Files: map[string]FileSource{}}
	var unmatched []string

	named := map[string]int{}
	for _, f := range diff.Files {
		named[strings.TrimSpace(f.Path)]++
	}
	for _, f := range diff.Files {
		rel := strings.TrimSpace(f.Path)
		switch {
		case rel == "":
			continue
		case f.Binary:
			unmatched = append(unmatched, rel+": the change is binary")
			continue
		case f.Renamed || (f.NewPath != "" && f.NewPath != f.Path):
			unmatched = append(unmatched, rel+": a rename carries no single patch-side path")
			continue
		case named[rel] > 1:
			unmatched = append(unmatched, rel+": named by more than one file entry")
			continue
		case len(f.Hunks) == 0:
			unmatched = append(unmatched, rel+": the change carries no hunk")
			continue
		}
		src, ok := selected[rel]
		if !ok {
			unmatched = append(unmatched, rel+": the selected source captured no file at this path")
			continue
		}
		text := normalizeLineEndings(string(src))
		toks, err := scanSourceTokens(text)
		if err != nil {
			unmatched = append(unmatched, rel+": the selected source does not tokenise as Go: "+err.Error())
			continue
		}
		lines := splitSourceLines(text)
		edits, detail := spliceMatches(f, toks, len(lines))
		if detail != "" {
			unmatched = append(unmatched, rel+": "+detail)
			continue
		}
		post := splicePostimage(lines, edits)
		if !strings.HasSuffix(text, "\n") {
			post = strings.TrimSuffix(post, "\n")
		}
		if _, err := parser.ParseFile(token.NewFileSet(), rel, post, parser.ParseComments); err != nil {
			unmatched = append(unmatched, rel+": the spliced postimage does not parse: "+err.Error())
			continue
		}
		bundle.Files[rel] = FileSource{
			Before: []byte(text), After: []byte(post), Selected: []byte(text),
		}
	}
	sort.Strings(unmatched)
	if len(bundle.Files) == 0 {
		return nil, unmatched
	}
	return bundle, unmatched
}

// firstOldLine is the patch-side line number of the first line the hunk's
// before image occupies. A hunk that adds only lines still consumes its
// context, so the first non-added line carries it.
func firstOldLine(h Hunk) int {
	for _, ln := range h.Lines {
		if ln.Kind != '+' {
			return ln.OldLine
		}
	}
	return 0
}

// spliceMatches maps every hunk of one file entry onto one unambiguous span of
// the selected source and returns the splice edits. Unlike the same-line
// route's matcher it also accepts a hunk that only adds lines: such a hunk is
// located by its captured context, and the insertion point is where that
// context ends. A hunk with no captured before-image context cannot be located
// and is refused.
func spliceMatches(file FilePatch, selToks []srcToken, selLineCount int) ([]spliceEdit, string) {
	var edits []spliceEdit
	for n, h := range file.Hunks {
		if h.Truncated || len(h.Defects) > 0 {
			return nil, fmt.Sprintf("hunk %d is incomplete", n+1)
		}
		before, after, _ := hunkImages(h)
		beforeToks, err := scanSourceTokens(before)
		if err != nil {
			return nil, fmt.Sprintf("hunk %d's before-image does not tokenise as Go: %v", n+1, err)
		}
		if len(beforeToks) == 0 {
			return nil, fmt.Sprintf("hunk %d has no captured before-image context to locate it", n+1)
		}
		runs := tokenRuns(selToks, beforeToks)
		if len(runs) != 1 {
			return nil, fmt.Sprintf("hunk %d's before-image occurs %d times in the selected source, so its span is not one change", n+1, len(runs))
		}
		first, last := runs[0], runs[0]+len(beforeToks)-1
		if !firstOnLine(selToks, first) || !lastOnLine(selToks, last) {
			return nil, fmt.Sprintf("hunk %d's before-image does not start and end on whole selected-source lines", n+1)
		}
		beforeLines := splitSourceLines(before)
		start := selToks[first].line - (beforeToks[0].line - 1)
		end := selToks[last].line + (len(beforeLines) - beforeToks[len(beforeToks)-1].line)
		if start < 1 || end > selLineCount || end-start+1 != len(beforeLines) {
			return nil, fmt.Sprintf("hunk %d's before-image is not a line-for-line match of the selected source", n+1)
		}
		// The bundle is the patch-side file, and the inventory checks every
		// hunk against it by the header's own line numbers. A match at another
		// offset would splice a coherent file that still disagrees with the
		// patch's declared positions, so only a line-aligned match is accepted:
		// the patch must have been authored against this exact file.
		if want := firstOldLine(h); want == 0 || start != want {
			return nil, fmt.Sprintf(
				"hunk %d's before-image matches selected lines %d-%d, not the patch's declared old lines starting at %d, so the selected file is not the patch's own base",
				n+1, start, end, want)
		}
		edits = append(edits, spliceEdit{start: start, end: end, lines: splitSourceLines(after)})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	for i := 1; i < len(edits); i++ {
		if edits[i].start <= edits[i-1].end {
			return nil, "the hunks map onto overlapping selected-source spans"
		}
	}
	return edits, ""
}
