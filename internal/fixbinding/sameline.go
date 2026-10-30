package fixbinding

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"path"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// This file implements the exact-preimage correspondence route: the only
// content-derived way a captured fix can name its subject in the selected
// version's own source.
//
// The route exists because the two shortcuts it replaces both established
// nothing. A module-relative path that exists says the file is there, not that
// the fix's changed code is; a hunk header's function name is the patch author's
// assertion about another release line. Neither can pick a declaration in the
// analysed version.
//
// So the route matches the *complete* old changed region and its context — the
// whole before-image of every hunk of the file — against the selected source,
// and requires exactly one occurrence. Only two normalisations are supported,
// and both are format-only: a hunk line's unified-diff prefix byte is removed,
// and the Go token stream is compared so that indentation, alignment and
// line breaks inside the fragment cannot decide the match. Comments, literals
// and every token are compared exactly, so a whitespace-only reflow of the code
// is not a different preimage while a changed identifier or comment is.
//
// The match then yields the enclosing declaration read from the *selected*
// source, which is the change's subject. The postimage is spliced into the
// matched span and must still parse, so a change whose added lines do not
// reconstruct a valid program at that site is not a same-line correspondence.
//
// Two further facts are required before the route may report CORRESPONDED,
// because exact identity is not a completeness theorem:
//
//   - every declaration the patch *introduces* must be named by the added
//     region of the repaired site. An added helper that the changed code never
//     names is the absence of the added function, which repairs nothing and
//     grounds nothing.
//   - the advisory-declared package boundary must be nonempty and must contain
//     the verified declaration's package. That boundary is the record's own
//     scope claim, so the necessity cover ranges over something the record
//     established rather than over whatever the patch happened to touch. This
//     route has no semantic classifier, so a record that declares no package
//     boundary leaves the change identity-only, and it stays unresolved.

// SameLineInput is the closed bundle one exact-preimage correspondence reads.
// Every field is captured input or a recorded declaration; nothing is a summary
// a producer may assert.
type SameLineInput struct {
	// Locator is the declared fix reference the bytes were captured for.
	Locator string
	// Path is the module-relative selected-source path the patch changes.
	Path string
	// Module is the declared module path, used to form the member's package
	// import path for Path.
	Module string
	// Patch is the complete captured bytes of that locator.
	Patch []byte
	// Selected is the complete selected-source bytes at Path.
	Selected []byte
	// DeclaredPackages is the record's own affected-package boundary for this
	// module, sorted or not. An empty set means the record declares no
	// boundary, which is not the same as declaring that nothing is affected.
	DeclaredPackages []string
}

// MatchSameLinePreimage measures one captured change against one selected-source
// file and returns the typed correspondence. It never panics, never reads I/O
// and never treats a partial observation as a match: every failure is a named
// status with the measured detail.
func MatchSameLinePreimage(in SameLineInput) domain.SameLineCorrespondence {
	rec := domain.SameLineCorrespondence{Locator: in.Locator, Path: in.Path, Status: domain.SameLineNoPatchBytes}
	if len(in.Patch) == 0 {
		rec.Detail = "the locator captured no bytes, so no changed region could be read"
		return rec
	}
	rec.Status = domain.SameLineNoSelectedSource
	if len(in.Selected) == 0 {
		rec.Detail = "no captured bytes of the selected version's own file were available to match the change against"
		return rec
	}

	selected := normalizeLineEndings(string(in.Selected))
	rec.SelectedFileDigest = DigestBytes([]byte(selected))

	diff := ParseUnifiedDiff(in.Patch)
	file, entries := patchedFile(diff, in.Path)
	if entries == 0 {
		rec.Status = domain.SameLinePathNotInPatch
		rec.Detail = "the captured patch changes no file at " + in.Path
		return rec
	}
	if entries > 1 {
		rec.Status = domain.SameLineMalformedChange
		rec.Detail = fmt.Sprintf(
			"the captured patch names %s in %d file entries, so its changed region is not one change", in.Path, entries)
		return rec
	}
	if reason := changeUnaccountable(file); reason != "" {
		rec.Status = domain.SameLineMalformedChange
		rec.Detail = reason
		return rec
	}

	preimage, ok := domain.PreimageText(in.Patch, in.Path)
	if !ok {
		rec.Status = domain.SameLineNoChangedRegion
		rec.Detail = "the file entry carries no before-image line, so no pre-existing region is replaced"
		return rec
	}
	rec.PreimageDigest = domain.EvidenceContentDigest(preimage)

	selToks, err := scanSourceTokens(selected)
	if err != nil {
		rec.Status = domain.SameLinePostimageRejected
		rec.Detail = "the selected source does not tokenise as Go: " + err.Error()
		return rec
	}
	selLines := splitSourceLines(selected)
	fset := token.NewFileSet()
	selAST, err := parser.ParseFile(fset, in.Path, selected, parser.ParseComments)
	if err != nil {
		rec.Status = domain.SameLinePostimageRejected
		rec.Detail = "the selected source does not parse as a Go file: " + err.Error()
		return rec
	}

	edits, removed, added, rendered, failure := matchHunks(file, selToks, len(selLines), rec)
	if failure != nil {
		return *failure
	}
	rec.RemovedLines, rec.AddedLines = removed, added
	rec.StartLine, rec.EndLine = edits[0].start, edits[len(edits)-1].end

	// The reconstructed postimage must be the same declaration at the same
	// site. A splice that does not parse measures that the change does not
	// apply here, so the preimage match cannot be a same-line correspondence.
	post := splicePostimage(selLines, edits)
	postAST, err := parser.ParseFile(token.NewFileSet(), in.Path, post, parser.ParseComments)
	if err != nil {
		rec.Status = domain.SameLinePostimageRejected
		rec.Detail = "the reconstructed postimage does not parse at the matched span: " + err.Error()
		return rec
	}

	decl := enclosingFunc(fset, selAST, edits[0].firstChanged)
	if decl == nil {
		rec.Status = domain.SameLineNoDeclaration
		rec.Detail = fmt.Sprintf(
			"no function or method declaration encloses the changed line %d of %s",
			edits[0].firstChanged, in.Path)
		return rec
	}
	symbol := funcSymbol(decl)
	declEnd := fset.Position(decl.End()).Line
	for _, e := range edits {
		if e.firstChanged < fset.Position(decl.Pos()).Line || e.lastChanged > declEnd {
			rec.Status = domain.SameLineMultipleDeclarations
			rec.Detail = fmt.Sprintf(
				"the changed region of %s spans lines %d-%d and %d-%d, which do not all fall inside %s",
				in.Path, edits[0].firstChanged, edits[0].lastChanged, e.firstChanged, e.lastChanged, symbol)
			return rec
		}
	}
	postDecl := enclosingFuncNamed(postAST, symbol)
	if postDecl == nil {
		rec.Status = domain.SameLinePostimageRejected
		rec.Detail = "the declaration that encloses the matched span does not survive the postimage splice"
		return rec
	}
	pkg := packageOf(in.Module, in.Path)
	rec.OmissionSite = domain.SymbolRef{Package: pkg, Symbol: symbol}

	// Every declaration the patch introduces must be carried by the repaired
	// site; a new declaration the changed code never names repairs nothing.
	if missing := uncarriedHelpers(selAST, postAST, file, rendered); missing != "" {
		rec.Status = domain.SameLineAddedHelperWithoutCarrier
		rec.Detail = missing
		return rec
	}

	cover, ok := declaredCover(in.DeclaredPackages, pkg)
	if !ok {
		rec.Status = domain.SameLineCoverUnestablished
		rec.Detail = declaredCoverDetail(in.DeclaredPackages, pkg)
		return rec
	}
	rec.Cover = cover
	rec.Status = domain.SameLineCorresponded
	rec.Detail = fmt.Sprintf(
		"the complete before-image of %s matched once at lines %d-%d, inside %s; %d added line(s) replace %d removed line(s) at a verified pre-existing omission site, and the declared boundary %s covers it",
		in.Path, rec.StartLine, rec.EndLine, symbol, added, removed, strings.Join(cover, ", "))
	return rec
}

// patchedFile returns the file entry the route is about and how many entries
// name the path. A path the diff names more than once is not a single change, so
// the caller refuses it rather than picking one.
func patchedFile(diff Patch, relPath string) (FilePatch, int) {
	var found FilePatch
	n := 0
	for _, f := range diff.Files {
		if f.Path == relPath || f.NewPath == relPath {
			if n == 0 {
				found = f
			}
			n++
		}
	}
	return found, n
}

// changeUnaccountable names why a file entry's changed region cannot be read as
// a complete same-line change, or "" when it can.
func changeUnaccountable(file FilePatch) string {
	switch {
	case file.Status != FileModified:
		return fmt.Sprintf("the diff entry records a %s change, not a modification of the selected file", file.Status)
	case file.Binary:
		return "the diff entry is a binary change, so no textual changed region exists"
	case file.Renamed:
		return "the diff entry renames the file, so its before-image belongs to another path"
	case len(file.Defects) > 0:
		return "the diff entry is defective: " + file.Defects[0].String()
	case len(file.Hunks) == 0:
		return "the diff entry carries no hunk"
	}
	return ""
}

// spliceEdit replaces one selected-source line range with the hunk's
// post-image lines. start and end are 1-based and inclusive; firstChanged and
// lastChanged are the selected lines the hunk actually removes from, which is
// where the change — not its surrounding context — sits.
type spliceEdit struct {
	start, end                int
	firstChanged, lastChanged int
	lines                     []string
}

// matchHunks maps every hunk of the entry onto one unambiguous span of the
// selected source and returns the splice edits, the changed-region dimensions
// and the added-region text the helper rule reads.
func matchHunks(file FilePatch, selToks []srcToken, selLineCount int, rec domain.SameLineCorrespondence,
) (edits []spliceEdit, removed, added int, rendered string, failure *domain.SameLineCorrespondence) {

	var addedText strings.Builder
	for n, h := range file.Hunks {
		if h.Truncated || len(h.Defects) > 0 {
			bad := rec
			bad.Status = domain.SameLineMalformedChange
			bad.Detail = "a hunk of the entry is incomplete: " + h.Defects[0].String()
			return nil, 0, 0, "", &bad
		}
		before, after, removedHere := hunkImages(h)
		if removedHere == 0 {
			bad := rec
			bad.Status = domain.SameLineNoChangedRegion
			bad.Detail = fmt.Sprintf(
				"hunk %d removes nothing from %s, so the change replaces no pre-existing code and names no omission site",
				n+1, file.Path)
			return nil, 0, 0, "", &bad
		}
		beforeToks, err := scanSourceTokens(before)
		if err != nil {
			bad := rec
			bad.Status = domain.SameLineMalformedChange
			bad.Detail = fmt.Sprintf("hunk %d's before-image does not tokenise as Go: %v", n+1, err)
			return nil, 0, 0, "", &bad
		}
		if len(beforeToks) == 0 {
			bad := rec
			bad.Status = domain.SameLineNoChangedRegion
			bad.Detail = fmt.Sprintf("hunk %d's before-image carries no Go token", n+1)
			return nil, 0, 0, "", &bad
		}
		runs := tokenRuns(selToks, beforeToks)
		switch len(runs) {
		case 0:
			bad := rec
			bad.Status = domain.SameLinePreimageUnmatched
			bad.Detail = fmt.Sprintf(
				"hunk %d's complete old region and context occurs nowhere in the selected source of %s",
				n+1, file.Path)
			return nil, 0, 0, "", &bad
		case 1:
		default:
			bad := rec
			bad.Status = domain.SameLinePreimageAmbiguous
			bad.Detail = fmt.Sprintf(
				"hunk %d's complete old region and context occurs %d times in the selected source of %s, so no single declaration is its subject",
				n+1, len(runs), file.Path)
			return nil, 0, 0, "", &bad
		}
		first, last := runs[0], runs[0]+len(beforeToks)-1
		if !firstOnLine(selToks, first) || !lastOnLine(selToks, last) {
			bad := rec
			bad.Status = domain.SameLinePostimageRejected
			bad.Detail = fmt.Sprintf(
				"hunk %d's before-image matches a span that does not start and end on whole selected-source lines, so the postimage cannot be spliced at it",
				n+1)
			return nil, 0, 0, "", &bad
		}
		// The span is the whole before-image, including its leading and
		// trailing context lines. Those lines carry no token, so they are
		// counted from the fragment's own line structure rather than from the
		// token positions.
		beforeLines := splitSourceLines(before)
		selStart := selToks[first].line - (beforeToks[0].line - 1)
		selEnd := selToks[last].line + (len(beforeLines) - beforeToks[len(beforeToks)-1].line)
		if selStart < 1 || selEnd > selLineCount {
			bad := rec
			bad.Status = domain.SameLinePostimageRejected
			bad.Detail = fmt.Sprintf(
				"hunk %d's before-image maps outside the selected source", n+1)
			return nil, 0, 0, "", &bad
		}
		// A same-line correspondence is a line-for-line one: the before-image
		// must occupy exactly the selected lines it mapped onto, or the splice
		// could not say which selected line each removed line came from.
		if selEnd-selStart+1 != len(beforeLines) {
			bad := rec
			bad.Status = domain.SameLinePostimageRejected
			bad.Detail = fmt.Sprintf(
				"hunk %d's before-image carries %d line(s) but matched %d selected-source line(s) (%d-%d), so it is not a line-for-line correspondence",
				n+1, len(beforeLines), selEnd-selStart+1, selStart, selEnd)
			return nil, 0, 0, "", &bad
		}
		firstChanged, lastChanged := changedLines(h, selStart)
		edits = append(edits, spliceEdit{
			start: selStart, end: selEnd,
			firstChanged: firstChanged, lastChanged: lastChanged,
			lines: splitSourceLines(after),
		})
		removed += removedHere
		added += countHunkKind(h, '+')
		for _, ln := range h.Lines {
			if ln.Kind == '+' {
				addedText.WriteString(ln.Text)
				addedText.WriteByte('\n')
			}
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	for i := 1; i < len(edits); i++ {
		if edits[i].start <= edits[i-1].end {
			bad := rec
			bad.Status = domain.SameLinePostimageRejected
			bad.Detail = "the entry's hunks map onto overlapping selected-source spans"
			return nil, 0, 0, "", &bad
		}
	}
	return edits, removed, added, addedText.String(), nil
}

// changedLines returns the selected-source lines a hunk removes, mapping its
// before-image line ordinal onto the matched span.
func changedLines(h Hunk, selStart int) (first, last int) {
	before := 0
	for _, ln := range h.Lines {
		if ln.Kind == '+' {
			continue
		}
		if ln.Kind == '-' {
			line := selStart + before
			if first == 0 {
				first = line
			}
			last = line
		}
		before++
	}
	return first, last
}

// hunkImages renders one hunk's before- and after-image text plus its removed
// line count.
func hunkImages(h Hunk) (before, after string, removed int) {
	var b, a strings.Builder
	for _, ln := range h.Lines {
		switch ln.Kind {
		case ' ':
			b.WriteString(ln.Text)
			b.WriteByte('\n')
			a.WriteString(ln.Text)
			a.WriteByte('\n')
		case '-':
			b.WriteString(ln.Text)
			b.WriteByte('\n')
			removed++
		case '+':
			a.WriteString(ln.Text)
			a.WriteByte('\n')
		}
	}
	return b.String(), a.String(), removed
}

// countHunkKind counts the hunk lines of one kind.
func countHunkKind(h Hunk, kind byte) int {
	n := 0
	for _, ln := range h.Lines {
		if ln.Kind == kind {
			n++
		}
	}
	return n
}

// splicePostimage rebuilds the file with every edit applied, in order.
func splicePostimage(lines []string, edits []spliceEdit) string {
	var b strings.Builder
	cur := 1
	for _, e := range edits {
		for ; cur < e.start && cur <= len(lines); cur++ {
			b.WriteString(lines[cur-1])
			b.WriteByte('\n')
		}
		for _, l := range e.lines {
			b.WriteString(l)
			b.WriteByte('\n')
		}
		cur = e.end + 1
	}
	for ; cur <= len(lines); cur++ {
		b.WriteString(lines[cur-1])
		b.WriteByte('\n')
	}
	return b.String()
}

// uncarriedHelpers names the first declaration the patch introduces that the
// repaired site's added region never refers to, or "" when every added
// declaration is carried.
func uncarriedHelpers(before, after *ast.File, file FilePatch, addedRegion string) string {
	existing := funcSymbols(before)
	introduced := funcSymbols(after)
	var names []string
	for symbol := range introduced {
		if !existing[symbol] {
			names = append(names, symbol)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	// The added region is searched without the helper's own declaration line:
	// a helper that only names itself is not carried by the repaired site.
	var kept []string
	for _, line := range strings.Split(addedRegion, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
	}
	for _, symbol := range names {
		ident := symbol
		if i := strings.LastIndexByte(symbol, '.'); i >= 0 {
			ident = symbol[i+1:]
		}
		var body []string
		for _, line := range kept {
			if funcNameOnLine(line) != ident {
				body = append(body, line)
			}
		}
		toks, err := scanSourceTokens(strings.Join(body, "\n"))
		if err != nil {
			toks = nil
		}
		if !namesIdent(toks, ident) {
			return fmt.Sprintf(
				"the patch introduces %s but the added region of the repaired site never names it: the addition is not a repair of a pre-existing pipeline in %s",
				symbol, file.Path)
		}
	}
	return ""
}

// namesIdent reports whether the token stream carries the identifier.
func namesIdent(toks []srcToken, name string) bool {
	for _, t := range toks {
		if t.tok == token.IDENT && t.lit == name {
			return true
		}
	}
	return false
}

// funcNameOnLine returns the identifier a line declares, when the line opens a
// function or method declaration, and "" otherwise.
func funcNameOnLine(line string) string {
	toks, err := scanSourceTokens(line)
	if err != nil || len(toks) == 0 || toks[0].tok != token.FUNC {
		return ""
	}
	i := 1
	// A method declaration carries its receiver in a parenthesised group before
	// the name. A function declaration with a type-parameter list does not, so
	// only a leading '(' is skipped and only its matching ')' ends the group.
	if i < len(toks) && toks[i].tok == token.LPAREN {
		depth := 0
		for ; i < len(toks); i++ {
			if toks[i].tok == token.LPAREN {
				depth++
			} else if toks[i].tok == token.RPAREN {
				depth--
			}
			if depth == 0 {
				break
			}
		}
		i++
	}
	if i < len(toks) && toks[i].tok == token.IDENT {
		return toks[i].lit
	}
	return ""
}

// funcSymbols is the set of function and method symbols one file declares, in
// the receiver-qualified form the candidate records use.
func funcSymbols(file *ast.File) map[string]bool {
	out := make(map[string]bool)
	if file == nil {
		return out
	}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			out[funcSymbol(fd)] = true
		}
	}
	return out
}

// enclosingFunc returns the innermost function or method declaration whose
// extent covers line.
func enclosingFunc(fset *token.FileSet, file *ast.File, line int) *ast.FuncDecl {
	if file == nil {
		return nil
	}
	var best *ast.FuncDecl
	bestSpan := 0
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fset.Position(fd.Pos()).Line
		end := fset.Position(fd.End()).Line
		if start > line || line > end {
			continue
		}
		if span := end - start; best == nil || span < bestSpan {
			best, bestSpan = fd, span
		}
	}
	return best
}

// enclosingFuncNamed returns the declaration with the given symbol.
func enclosingFuncNamed(file *ast.File, symbol string) *ast.FuncDecl {
	if file == nil {
		return nil
	}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && funcSymbol(fd) == symbol {
			return fd
		}
	}
	return nil
}

// funcSymbol renders one declaration the way candidate records name it.
func funcSymbol(fd *ast.FuncDecl) string {
	if fd == nil {
		return ""
	}
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return receiverTypeName(fd.Recv.List[0].Type) + "." + fd.Name.Name
}

// srcToken is one Go token with the position it occupies in the text it was
// scanned from.
type srcToken struct {
	tok       token.Token
	lit       string
	line, col int
}

// key renders the token so two streams compare exactly: a keyword or operator
// by its spelling, an identifier, literal or comment by its text.
func (t srcToken) key() string {
	if t.lit != "" {
		return t.tok.String() + " " + t.lit
	}
	return t.tok.String()
}

// scanSourceTokens tokenises a Go fragment. Automatic semicolons are dropped:
// they are a line-break artefact of the scanner, not a token of the program, so
// dropping them is the supported format normalisation and the only one.
func scanSourceTokens(src string) ([]srcToken, error) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var firstErr error
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, msg string) {
		if firstErr == nil {
			firstErr = fmt.Errorf("%s", msg)
		}
	}, scanner.ScanComments)
	var out []srcToken
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON && lit == "\n" {
			continue
		}
		p := fset.Position(pos)
		out = append(out, srcToken{tok: tok, lit: lit, line: p.Line, col: p.Column})
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// tokenRuns returns every offset at which needle occurs as a contiguous run of
// hay. The search is exhaustive: an ambiguous match must be reported as
// ambiguous, not resolved by taking the first hit.
func tokenRuns(hay, needle []srcToken) []int {
	if len(needle) == 0 || len(needle) > len(hay) {
		return nil
	}
	var out []int
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j].key() != needle[j].key() {
				match = false
				break
			}
		}
		if match {
			out = append(out, i)
		}
	}
	return out
}

// firstOnLine reports whether toks[i] is the first token of its line.
func firstOnLine(toks []srcToken, i int) bool { return i == 0 || toks[i-1].line != toks[i].line }

// lastOnLine reports whether toks[i] is the last token of its line.
func lastOnLine(toks []srcToken, i int) bool {
	return i == len(toks)-1 || toks[i+1].line != toks[i].line
}

// normalizeLineEndings applies the supported byte-format normalisation.
func normalizeLineEndings(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// splitSourceLines splits text into lines without terminators.
func splitSourceLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// packageOf maps one module-relative path to its package import path.
func packageOf(module, relPath string) string {
	dir := path.Dir(relPath)
	if dir == "." || dir == "" || dir == "/" {
		return module
	}
	if module == "" {
		return dir
	}
	return module + "/" + dir
}

// declaredCover normalises the record's package boundary and requires it to
// cover pkg. An empty boundary is not a cover: this route has no semantic
// classifier, so it cannot establish necessity from the change alone.
func declaredCover(declared []string, pkg string) ([]string, bool) {
	seen := make(map[string]bool, len(declared))
	cover := make([]string, 0, len(declared))
	covers := false
	for _, p := range declared {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		cover = append(cover, p)
		if p == pkg {
			covers = true
		}
	}
	if len(cover) == 0 || !covers {
		return nil, false
	}
	sort.Strings(cover)
	return cover, true
}

// declaredCoverDetail states why no cover exists for pkg.
func declaredCoverDetail(declared []string, pkg string) string {
	normalised := make([]string, 0, len(declared))
	for _, p := range declared {
		if p = strings.TrimSpace(p); p != "" {
			normalised = append(normalised, p)
		}
	}
	if len(normalised) == 0 {
		return "the record declares no affected-package boundary for this module, and this route has no semantic classifier, so an opaque change cannot establish a necessity cover"
	}
	sort.Strings(normalised)
	return fmt.Sprintf(
		"the record's declared package boundary %v does not contain the verified declaration's package %s, so no necessary cover ranges over it",
		normalised, pkg)
}
