package fixbinding

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
)

// tokenSite is where a changed token sits in the patch-side AST: inside a call
// argument, in the call's callee, in a statement, or in a declaration.
type tokenSite struct {
	call     *ast.CallExpr
	argIndex int // >=0 argument index; -1 callee; -2 outside any call
	stmt     ast.Stmt
	decl     ast.Decl
}

// tokenGroup is one changed AST unit: a statement, a declaration header, or one
// line of comments. Grouping by statement, not by line, is what keeps two
// statements on one source line separate while keeping one statement's changed
// tokens together.
type tokenGroup struct {
	image       Image
	view        *fileView
	tokens      []changedToken
	site        tokenSite
	comment     bool
	commentText string
}

// sideAccount is the per-image decision state: which changed token indexes a
// checked effect consumed and which are proved non-executable.
type sideAccount struct {
	image    Image
	tokens   tokenizedImage
	view     *fileView
	changed  map[int]bool
	consumed map[int]string
	nonExec  map[int]string
}

func newSideAccount(img Image, v *fileView, tokens tokenizedImage, changed map[int]bool) *sideAccount {
	return &sideAccount{
		image: img, tokens: tokens, view: v, changed: changed,
		consumed: map[int]string{}, nonExec: map[int]string{},
	}
}

func (s *sideAccount) markConsumed(ranges [][2]token.Pos, effectID string) int {
	n := 0
	for idx, t := range s.tokens.Tokens {
		if !s.changed[idx] || s.consumed[idx] != "" {
			continue
		}
		if tokenInAnyRange(s.view, t, ranges) {
			s.consumed[idx] = effectID
			n++
		}
	}
	return n
}

func (s *sideAccount) markNonExec(ranges [][2]token.Pos, rule string) int {
	n := 0
	for idx, t := range s.tokens.Tokens {
		if !s.changed[idx] || s.consumed[idx] != "" || s.nonExec[idx] != "" {
			continue
		}
		if tokenInAnyRange(s.view, t, ranges) {
			s.nonExec[idx] = rule
			n++
		}
	}
	return n
}

func (s *sideAccount) countChanged(ranges [][2]token.Pos) int {
	n := 0
	for idx, t := range s.tokens.Tokens {
		if s.changed[idx] && tokenInAnyRange(s.view, t, ranges) {
			n++
		}
	}
	return n
}

func tokenInAnyRange(v *fileView, t imageToken, ranges [][2]token.Pos) bool {
	if len(ranges) == 0 {
		return false
	}
	pos := posForToken(v, t)
	if pos == token.NoPos {
		return false
	}
	for _, r := range ranges {
		if r[0] <= pos && pos < r[1] {
			return true
		}
	}
	return false
}

func (s *inventorySequencer) malformedHunk(file FilePatch, h Hunk) {
	kind := ResidualTruncatedHunk
	var details []string
	for _, d := range h.Defects {
		if d.Kind == DefectMalformedHunkHeader {
			kind = ResidualMalformedHunk
		}
		details = append(details, d.Detail)
	}
	detail := strings.Join(details, "; ")
	if detail == "" {
		detail = "the hunk could not be parsed as a complete unified-diff hunk"
	}
	for _, img := range []Image{ImageBefore, ImageAfter} {
		for _, ln := range h.ImageLines(img) {
			if img == ImageBefore && ln.Kind != '-' {
				continue
			}
			if img == ImageAfter && ln.Kind != '+' {
				continue
			}
			s.residualForLine(file.Path, img, ln, kind, detail)
		}
	}
}

// residualForLine records one line-level residual and its span. Line
// granularity is the strictest account available when the hunk is incomplete.
func (s *inventorySequencer) residualForLine(path string, img Image, ln HunkLine,
	kind ResidualKind, detail string) {
	text := strings.TrimSpace(ln.Text)
	sp := s.span(Span{
		Path: path, Image: img,
		StartLine: ln.lineFor(img), StartCol: 1,
		EndLine: ln.lineFor(img), EndCol: len(text) + 1,
		Text: text, Disposition: SpanResidual,
	})
	s.inv.Spans[len(s.inv.Spans)-1].ResidualID = s.residual(Residual{
		Kind: kind, Path: path, Image: img, Line: ln.lineFor(img),
		Detail:  detail + ": " + truncate(text, 120),
		SpanIDs: []string{sp}, Blocks: true,
	})
}

// hunk accounts for one well-formed hunk.
func (s *inventorySequencer) hunk(a *analyzer, file FilePatch, h Hunk) {
	beforeImg, afterImg, beforeTokens, afterTokens := analyzeHunk(h)
	if beforeImg.Err != "" || afterImg.Err != "" {
		reason := beforeImg.Err
		if reason == "" {
			reason = afterImg.Err
		}
		for _, img := range []Image{ImageBefore, ImageAfter} {
			for _, ln := range h.ImageLines(img) {
				if img == ImageBefore && ln.Kind != '-' {
					continue
				}
				if img == ImageAfter && ln.Kind != '+' {
					continue
				}
				s.residualForLine(file.Path, img, ln, ResidualUntokenized,
					"the hunk's token stream could not be read completely ("+reason+")")
			}
		}
		return
	}
	if len(beforeTokens) == 0 && len(afterTokens) == 0 {
		s.inv.NonExecutableHunks++
		return
	}
	if allComments(beforeTokens) && allComments(afterTokens) {
		// A comment delta needs no identifier qualification: comments execute
		// nothing. Directives are still separated from ordinary comments.
		s.accountCommentGroups(file.Path, ImageBefore, beforeTokens)
		s.accountCommentGroups(file.Path, ImageAfter, afterTokens)
		return
	}

	var beforeView, afterView *fileView
	if len(h.ImageLines(ImageBefore)) > 0 {
		v, reason := s.view(a, file.Path, ImageBefore)
		if reason != "" {
			s.unqualifiedHunk(file.Path, beforeTokens, afterTokens, ResidualMissingSource, reason)
			return
		}
		if detail, ok := v.consistentWithHunk(h, ImageBefore); !ok {
			s.unqualifiedHunk(file.Path, beforeTokens, afterTokens, ResidualInconsistent, detail)
			return
		}
		beforeView = v
	}
	if len(h.ImageLines(ImageAfter)) > 0 {
		v, reason := s.view(a, file.Path, ImageAfter)
		if reason != "" {
			s.unqualifiedHunk(file.Path, beforeTokens, afterTokens, ResidualMissingSource, reason)
			return
		}
		if detail, ok := v.consistentWithHunk(h, ImageAfter); !ok {
			s.unqualifiedHunk(file.Path, beforeTokens, afterTokens, ResidualInconsistent, detail)
			return
		}
		afterView = v
	}
	if len(beforeTokens) > 0 && beforeView == nil {
		s.unqualifiedHunk(file.Path, beforeTokens, nil, ResidualMissingSource, "the before image has changed tokens but no captured source")
		return
	}
	if len(afterTokens) > 0 && afterView == nil {
		s.unqualifiedHunk(file.Path, nil, afterTokens, ResidualMissingSource, "the after image has changed tokens but no captured source")
		return
	}

	before := newSideAccount(ImageBefore, beforeView, beforeImg, changedIndexes(beforeTokens))
	after := newSideAccount(ImageAfter, afterView, afterImg, changedIndexes(afterTokens))
	beforeGroups := buildGroups(beforeView, beforeTokens)
	afterGroups := buildGroups(afterView, afterTokens)

	s.consumeCalls(a, file, before, after, beforeGroups, afterGroups)
	s.accountGroups(a, file, before, beforeGroups)
	s.accountGroups(a, file, after, afterGroups)
}

func (s *inventorySequencer) view(a *analyzer, file string, img Image) (*fileView, string) {
	if a.bundle == nil {
		return nil, fmt.Sprintf("no patch-side %s source was supplied for %s", img, file)
	}
	v, err := a.view(file, img)
	if err != nil {
		return nil, err.Error()
	}
	a.ensurePackage(v)
	return v, ""
}

// unqualifiedHunk records changed tokens whose identifiers cannot be resolved
// against the supplied patch-side source. No selected-source match is used.
func (s *inventorySequencer) unqualifiedHunk(path string, before, after []changedToken,
	kind ResidualKind, reason string) {
	for _, side := range []struct {
		img    Image
		tokens []changedToken
	}{{ImageBefore, before}, {ImageAfter, after}} {
		for _, lineGroup := range groupTokensByLine(side.tokens) {
			sp := s.span(spanFromTokens(path, side.img, lineGroup, SpanResidual))
			s.inv.Spans[len(s.inv.Spans)-1].ResidualID = s.residual(Residual{
				Kind: kind, Path: path, Image: side.img, Line: lineGroup[0].Token.Line,
				Detail: reason, SpanIDs: []string{sp}, Blocks: true,
			})
		}
	}
}

func spanFromTokens(path string, img Image, tokens []changedToken, disposition SpanDisposition) Span {
	first := tokens[0].Token
	last := tokens[len(tokens)-1].Token
	var texts []string
	for _, t := range tokens {
		texts = append(texts, t.Token.Text)
	}
	return Span{
		Path: path, Image: img,
		StartLine: first.Line, StartCol: first.Col,
		EndLine: last.Line, EndCol: last.Col + len(last.Text),
		Text: strings.Join(texts, " "), Disposition: disposition,
	}
}

func changedIndexes(tokens []changedToken) map[int]bool {
	out := make(map[int]bool, len(tokens))
	for _, t := range tokens {
		out[t.Index] = true
	}
	return out
}

func allComments(tokens []changedToken) bool {
	for _, t := range tokens {
		if t.Token.Kind != token.COMMENT {
			return false
		}
	}
	return true
}

func groupTokensByLine(tokens []changedToken) [][]changedToken {
	var out [][]changedToken
	for _, t := range tokens {
		if len(out) > 0 && out[len(out)-1][0].Token.Line == t.Token.Line {
			out[len(out)-1] = append(out[len(out)-1], t)
			continue
		}
		out = append(out, []changedToken{t})
	}
	return out
}

// buildGroups groups changed tokens by enclosing statement/declaration. A
// comment token becomes its own line group. No call is classified here; the
// effect units are built separately from the same tokens.
func buildGroups(v *fileView, tokens []changedToken) []*tokenGroup {
	type groupKey struct {
		stmt    ast.Stmt
		decl    ast.Decl
		comment bool
		line    int
	}
	index := map[groupKey]*tokenGroup{}
	var order []*tokenGroup
	for _, tok := range tokens {
		if tok.Token.Kind == token.COMMENT {
			key := groupKey{comment: true, line: tok.Token.Line}
			g, ok := index[key]
			if !ok {
				g = &tokenGroup{image: v.Image, comment: true}
				index[key] = g
				order = append(order, g)
			}
			g.tokens = append(g.tokens, tok)
			g.commentText += tok.Token.Text
			continue
		}
		site := locateSite(v, tok.Token)
		key := groupKey{stmt: site.stmt, decl: site.decl}
		g, ok := index[key]
		if !ok {
			g = &tokenGroup{image: v.Image, view: v, site: site}
			index[key] = g
			order = append(order, g)
		}
		g.tokens = append(g.tokens, tok)
	}
	sort.SliceStable(order, func(i, j int) bool {
		return order[i].tokens[0].Index < order[j].tokens[0].Index
	})
	return order
}

// buildCommentGroups is used for comment-only hunks that need no parsed source.
func buildCommentGroups(img Image, tokens []changedToken) []*tokenGroup {
	var out []*tokenGroup
	for _, t := range tokens {
		if len(out) > 0 && out[len(out)-1].tokens[0].Token.Line == t.Token.Line {
			out[len(out)-1].tokens = append(out[len(out)-1].tokens, t)
			out[len(out)-1].commentText += t.Token.Text
			continue
		}
		out = append(out, &tokenGroup{
			image: img, comment: true, tokens: []changedToken{t}, commentText: t.Token.Text,
		})
	}
	return out
}

// locateSite finds the innermost call, statement and declaration containing a
// token. It is the AST span the recogniser is allowed to consume: a token in
// another statement is not touched by the operation's accounting.
func locateSite(v *fileView, tok imageToken) tokenSite {
	pos := posForToken(v, tok)
	if pos == token.NoPos {
		return tokenSite{argIndex: -2}
	}
	site := tokenSite{argIndex: -2}
	ast.Inspect(v.File, func(n ast.Node) bool {
		if n == nil || !containsPos(n, pos) {
			return true
		}
		if x, ok := n.(*ast.CallExpr); ok {
			if site.call == nil || x.Pos() >= site.call.Pos() {
				site.call = x
			}
		}
		if st, ok := n.(ast.Stmt); ok {
			if site.stmt == nil || st.Pos() >= site.stmt.Pos() {
				site.stmt = st
			}
		}
		if d, ok := n.(ast.Decl); ok {
			if site.decl == nil || d.Pos() >= site.decl.Pos() {
				site.decl = d
			}
		}
		return true
	})
	if _, ok := site.stmt.(*ast.BlockStmt); ok {
		// A brace belongs to the statement whose body it delimits, not to the
		// block itself: `if … {` is one control statement, and its opening
		// brace must be accounted with its guard.
		ast.Inspect(v.File, func(n ast.Node) bool {
			if n == nil || !containsPos(n, pos) {
				return true
			}
			if st, ok := n.(ast.Stmt); ok {
				if _, isBlock := st.(*ast.BlockStmt); isBlock {
					return true
				}
				if site.stmt == nil || st.Pos() >= site.stmt.Pos() || isBlockStmt(site.stmt) {
					site.stmt = st
				}
			}
			return true
		})
	}
	if site.call != nil {
		switch {
		case containsPos(site.call.Fun, pos):
			site.argIndex = -1
		default:
			site.argIndex = -2
			for i, arg := range site.call.Args {
				if arg != nil && containsPos(arg, pos) {
					site.argIndex = i
					break
				}
			}
		}
	}
	return site
}

func isBlockStmt(s ast.Stmt) bool {
	_, ok := s.(*ast.BlockStmt)
	return ok
}

func containsPos(n ast.Node, pos token.Pos) bool {
	return n != nil && n.Pos() <= pos && pos < n.End()
}

func posForToken(v *fileView, tok imageToken) token.Pos {
	if v == nil {
		return token.NoPos
	}
	file := v.Fset.File(v.File.Pos())
	if file == nil || tok.Line < 1 || tok.Line > file.LineCount() || tok.Col < 1 {
		return token.NoPos
	}
	pos := file.LineStart(tok.Line) + token.Pos(tok.Col-1)
	if pos < token.Pos(file.Base()) || pos >= token.Pos(file.Base()+file.Size()) {
		return token.NoPos
	}
	return pos
}

// callUnit is one resolved supported-operation call in a hunk.
type callUnit struct {
	image        Image
	view         *fileView
	call         *ast.CallExpr
	op           Operation
	decl         DeclarationIdentity
	fullyChanged bool
}

// consumeCalls pairs the supported calls of both images and marks the changed
// tokens their checked arguments account for. Every unpaired supported call is
// recorded as an added or removed effect.
func (s *inventorySequencer) consumeCalls(a *analyzer, file FilePatch,
	before, after *sideAccount, beforeGroups, afterGroups []*tokenGroup) {
	beforeUnits := buildUnits(a, before)
	afterUnits := buildUnits(a, after)
	usedBefore := map[*callUnit]bool{}
	byIdentity := map[APIIdentity][]*callUnit{}
	for _, u := range beforeUnits {
		byIdentity[u.op.Identity] = append(byIdentity[u.op.Identity], u)
	}
	for _, au := range afterUnits {
		var match *callUnit
		for _, bu := range byIdentity[au.op.Identity] {
			if usedBefore[bu] || bu.decl.String() != au.decl.String() {
				continue
			}
			match = bu
			break
		}
		if match == nil {
			s.singleCallEffect(a, file, au, true, after)
			continue
		}
		usedBefore[match] = true
		s.pairedCallEffect(a, file, match, au, before, after)
	}
	for _, bu := range beforeUnits {
		if !usedBefore[bu] {
			s.singleCallEffect(a, file, bu, false, before)
		}
	}
}

func buildUnits(a *analyzer, side *sideAccount) []*callUnit {
	byCall := map[*ast.CallExpr]*callUnit{}
	var order []*callUnit
	for idx, tok := range side.tokens.Tokens {
		if !side.changed[idx] || tok.Kind == token.COMMENT {
			continue
		}
		site := locateSite(side.view, tok)
		if site.call == nil {
			continue
		}
		if _, seen := byCall[site.call]; seen {
			continue
		}
		op, reason := a.classifyOperation(side.view, site.call)
		if reason != "" {
			continue
		}
		u := &callUnit{
			image: side.image, view: side.view, call: site.call, op: op,
			decl: side.view.enclosingDeclaration(site.call.Pos()),
		}
		u.fullyChanged = nodeFullyChanged(side.tokens, side.view, site.call, side.changed)
		byCall[site.call] = u
		order = append(order, u)
	}
	return order
}

func nodeFullyChanged(img tokenizedImage, v *fileView, node ast.Node, changed map[int]bool) bool {
	if node == nil || v == nil || len(img.Tokens) == 0 {
		return false
	}
	start := v.Fset.Position(node.Pos())
	end := v.Fset.Position(node.End())
	minLine, maxLine := img.Tokens[0].Line, img.Tokens[len(img.Tokens)-1].Line
	if start.Line < minLine || end.Line > maxLine+1 {
		// The node extends beyond the hunk's own window; the hunk cannot prove
		// its complete token range was changed.
		return false
	}
	seen := 0
	for i, t := range img.Tokens {
		if !tokenInRange(t, start.Line, start.Column, end.Line, end.Column) {
			continue
		}
		seen++
		if !changed[i] {
			return false
		}
	}
	return seen > 0
}

func tokenInRange(t imageToken, startLine, startCol, endLine, endCol int) bool {
	if t.Line < startLine || t.Line > endLine {
		return false
	}
	if t.Line == startLine && t.Col < startCol {
		return false
	}
	if t.Line == endLine && endCol > 0 && t.Col >= endCol {
		return false
	}
	return true
}

// pairedCallEffect records one operation whose checked values changed between
// the images. Only checked argument spans (resource operand, permission
// literal) are consumed; a changed unchecked argument stays a residual.
func (s *inventorySequencer) pairedCallEffect(a *analyzer, file FilePatch,
	beforeUnit, afterUnit *callUnit, before, after *sideAccount) {
	beforeRanges := checkedArgRanges(beforeUnit)
	afterRanges := checkedArgRanges(afterUnit)
	if before.countChanged(beforeRanges) == 0 && after.countChanged(afterRanges) == 0 {
		return
	}
	if operationsEquivalent(beforeUnit.op, afterUnit.op) {
		before.markNonExec(beforeRanges, "resolved-operation-equivalent")
		after.markNonExec(afterRanges, "resolved-operation-equivalent")
		return
	}
	effectIndex := s.beginEffect(Effect{
		Path:        file.Path,
		Declaration: afterUnit.decl,
		Class:       afterUnit.op.Class,
		Before:      &beforeUnit.op,
		After:       &afterUnit.op,
		Branches:    guardsAround(a, afterUnit.view, afterUnit.call.Pos()),
	})
	effectID := s.inv.Effects[effectIndex].ID
	before.markConsumed(beforeRanges, effectID)
	after.markConsumed(afterRanges, effectID)
}

// checkedArgRanges returns the source ranges of the supported declaration's
// checked arguments (resource operand and permission literal).
func checkedArgRanges(u *callUnit) [][2]token.Pos {
	spec, ok := specFor(u.op.Identity)
	if !ok {
		return nil
	}
	var out [][2]token.Pos
	for idx, role := range spec.Args {
		if !isCheckedRole(role) || idx >= len(u.call.Args) || u.call.Args[idx] == nil {
			continue
		}
		out = append(out, [2]token.Pos{u.call.Args[idx].Pos(), u.call.Args[idx].End()})
	}
	return out
}

func isCheckedRole(role ArgRole) bool { return role == ArgResource || role == ArgMode }

func operationsEquivalent(a, b Operation) bool {
	return a.Mode == b.Mode && a.Resource.Equal(b.Resource)
}

// singleCallEffect records an added or removed operation. A call whose every
// token is new/old is consumed in full, including the standard error-check
// scaffold it is wrapped in; otherwise only its checked arguments are consumed.
func (s *inventorySequencer) singleCallEffect(a *analyzer, file FilePatch, u *callUnit,
	added bool, side *sideAccount) {
	ranges := checkedArgRanges(u)
	consumeAll := u.fullyChanged
	if !consumeAll && side.countChanged(ranges) == 0 {
		return
	}
	scaffold, scaffoldOK := errorScaffold(u.view, u.call)
	scaffoldConsumed := scaffoldOK && nodeFullyChanged(side.tokens, u.view, scaffold, side.changed)
	effectIndex := s.beginEffect(Effect{
		Path:        file.Path,
		Declaration: u.decl,
		Class:       u.op.Class,
		Added:       added,
		Removed:     !added,
		Branches:    guardsAround(a, u.view, u.call.Pos()),
		Scaffold:    scaffoldConsumed,
	})
	if added {
		s.inv.Effects[effectIndex].After = &u.op
	} else {
		s.inv.Effects[effectIndex].Before = &u.op
	}
	effectID := s.inv.Effects[effectIndex].ID
	marked := 0
	if consumeAll {
		marked += side.markConsumed([][2]token.Pos{{u.call.Pos(), u.call.End()}}, effectID)
	}
	if scaffoldConsumed {
		marked += side.markConsumed([][2]token.Pos{{scaffold.Pos(), scaffold.End()}}, effectID)
	}
	marked += side.markConsumed(ranges, effectID)
	if marked == 0 {
		s.inv.Effects = s.inv.Effects[:len(s.inv.Effects)-1]
	}
}

func (s *inventorySequencer) beginEffect(e Effect) int {
	e.ID = fmt.Sprintf("E-%02d", len(s.inv.Effects)+1)
	e.Spans = nil
	s.inv.Effects = append(s.inv.Effects, e)
	return len(s.inv.Effects) - 1
}

// accountCommentGroups handles a comment-only hunk.
func (s *inventorySequencer) accountCommentGroups(path string, img Image, tokens []changedToken) {
	for _, g := range buildCommentGroups(img, tokens) {
		s.accountCommentGroup(path, g)
	}
}

func (s *inventorySequencer) accountCommentGroup(path string, g *tokenGroup) {
	runs := spanRuns(g)
	if isSemanticDirective(g.commentText) {
		var ids []string
		for _, run := range runs {
			ids = append(ids, s.span(spanFromTokens(path, g.image, run, SpanResidual)))
		}
		rid := s.residual(Residual{
			Kind: ResidualDirective, Path: path, Image: g.image, Line: firstLine(g),
			Detail: "the changed comment is a build/runtime directive, not an ordinary comment: " +
				truncate(strings.TrimSpace(g.commentText), 120),
			SpanIDs: ids, Blocks: true,
		})
		for _, id := range ids {
			s.setSpanResidual(id, rid)
		}
		return
	}
	for _, run := range runs {
		s.span(spanFromTokens(path, g.image, run, SpanNonExecutable))
		s.inv.Spans[len(s.inv.Spans)-1].Rule = "ordinary-comment"
	}
}

// accountGroups emits span records for every group and turns every still
// unconsumed executable token into a blocking residual obligation. A group is
// partitioned token-by-token: the permission literal consumed by an effect and
// the guard in the same statement do not share a disposition.
func (s *inventorySequencer) accountGroups(a *analyzer, file FilePatch,
	side *sideAccount, groups []*tokenGroup) {
	for _, g := range groups {
		if g.comment {
			s.accountCommentGroup(file.Path, g)
			continue
		}
		for _, run := range spanRuns(g) {
			s.accountRun(a, file, side, g, run)
		}
	}
}

type tokenClass struct {
	consumed string
	nonExec  string
	residual bool
}

func (s *inventorySequencer) accountRun(a *analyzer, file FilePatch,
	side *sideAccount, g *tokenGroup, tokens []changedToken) {
	// Split the run into maximal sub-runs of equal disposition.
	var classes []tokenClass
	for _, t := range tokens {
		classes = append(classes, tokenClass{
			consumed: side.consumed[t.Index],
			nonExec:  side.nonExec[t.Index],
			residual: side.consumed[t.Index] == "" && side.nonExec[t.Index] == "",
		})
	}
	start := 0
	for start < len(tokens) {
		end := start + 1
		for end < len(tokens) && sameClass(classes[start], classes[end]) {
			end++
		}
		part := tokens[start:end]
		cls := classes[start]
		switch {
		case cls.consumed != "":
			sp := s.span(spanFromTokens(file.Path, g.image, part, SpanConsumed))
			idx := spanIndex(s.inv.Spans, sp)
			s.inv.Spans[idx].EffectID = cls.consumed
			s.inv.Spans[idx].Rule = "checked-effect"
			ei := effectIndex(s.inv.Effects, cls.consumed)
			s.inv.Effects[ei].Spans = append(s.inv.Effects[ei].Spans, sp)
		case cls.nonExec != "":
			s.span(spanFromTokens(file.Path, g.image, part, SpanNonExecutable))
			s.inv.Spans[len(s.inv.Spans)-1].Rule = cls.nonExec
		default:
			if allSeparators(part) {
				s.span(spanFromTokens(file.Path, g.image, part, SpanNonExecutable))
				s.inv.Spans[len(s.inv.Spans)-1].Rule = "statement-separator"
				start = end
				continue
			}
			kind, detail := residualForGroup(a, g)
			sp := s.span(spanFromTokens(file.Path, g.image, part, SpanResidual))
			decl := ""
			if g.view != nil {
				decl = g.view.enclosingDeclaration(posForToken(g.view, part[0].Token)).String()
			}
			s.inv.Spans[len(s.inv.Spans)-1].ResidualID = s.residual(Residual{
				Kind: kind, Path: file.Path, Image: g.image, Line: part[0].Token.Line,
				Declaration: decl, Detail: detail, SpanIDs: []string{sp}, Blocks: true,
			})
		}
		start = end
	}
}

func allSeparators(tokens []changedToken) bool {
	for _, t := range tokens {
		if t.Token.Kind != token.SEMICOLON {
			return false
		}
	}
	return len(tokens) > 0
}

func sameClass(a, b tokenClass) bool {
	return a.consumed == b.consumed && a.nonExec == b.nonExec && a.residual == b.residual
}

func (s *inventorySequencer) setSpanResidual(id, residualID string) {
	for i := range s.inv.Spans {
		if s.inv.Spans[i].ID == id {
			s.inv.Spans[i].ResidualID = residualID
			return
		}
	}
}

func firstLine(g *tokenGroup) int {
	if len(g.tokens) == 0 {
		return 0
	}
	return g.tokens[0].Token.Line
}

func spanRuns(g *tokenGroup) [][]changedToken {
	var out [][]changedToken
	for _, t := range g.tokens {
		if len(out) > 0 {
			prev := out[len(out)-1][len(out[len(out)-1])-1]
			if prev.Index+1 == t.Index && prev.Token.Line == t.Token.Line {
				out[len(out)-1] = append(out[len(out)-1], t)
				continue
			}
		}
		out = append(out, []changedToken{t})
	}
	return out
}

func spanIndex(spans []Span, id string) int {
	for i := range spans {
		if spans[i].ID == id {
			return i
		}
	}
	return -1
}

func effectIndex(effects []Effect, id string) int {
	for i := range effects {
		if effects[i].ID == id {
			return i
		}
	}
	return -1
}

// residualForGroup names why an unconsumed group is executable.
func residualForGroup(a *analyzer, g *tokenGroup) (ResidualKind, string) {
	if g.site.call != nil {
		if res := a.resolveCall(g.view, g.site.call); res.Resolved &&
			res.Identity.Source == "builtin" && res.Identity.Name == "copy" {
			return ResidualCopy, "the changed statement is a builtin copy, which this inventory does not consume as a checked operation"
		}
	}
	stmt := g.site.stmt
	if stmt == nil {
		if g.site.decl != nil {
			return ResidualDeclaration, "the changed span belongs to a declaration header, which is not consumed by an operation effect"
		}
		return ResidualStatement, "the changed span is outside every recognised statement"
	}
	switch x := stmt.(type) {
	case *ast.IfStmt:
		return ResidualGuard, "the patch changes a guard predicate or its control flow"
	case *ast.ForStmt:
		return ResidualGuard, "the patch changes a loop condition or its control flow"
	case *ast.RangeStmt:
		return ResidualGuard, "the patch changes a range iteration or its control flow"
	case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.CaseClause, *ast.CommClause, *ast.SelectStmt:
		return ResidualGuard, "the patch changes a branch/selection predicate or clause"
	case *ast.AssignStmt, *ast.DeclStmt:
		return ResidualDerivation, "the patch changes a value derivation that is not consumed by an operation effect"
	case *ast.ExprStmt:
		if call, ok := unwrapParen(x.X).(*ast.CallExpr); ok {
			if res := a.resolveCall(g.view, call); res.Resolved &&
				res.Identity.Source == "builtin" && res.Identity.Name == "copy" {
				return ResidualCopy, "the changed statement is a builtin copy, which is not consumed as a checked operation"
			}
			return ResidualCall, "the changed statement calls code this inventory does not classify"
		}
		return ResidualStatement, "the changed expression statement is not consumed by an operation effect"
	case *ast.GoStmt, *ast.DeferStmt:
		return ResidualCall, "the changed statement defers or starts a call this inventory does not classify"
	case *ast.ReturnStmt:
		return ResidualReturn, "the patch changes a return value outside any consumed operation"
	case *ast.IncDecStmt:
		return ResidualAssignment, "the patch changes an increment/decrement"
	case *ast.BranchStmt, *ast.LabeledStmt:
		return ResidualControl, "the patch changes control flow"
	}
	return ResidualStatement, "the patch changes an executable statement this inventory cannot classify"
}

func isSemanticDirective(text string) bool {
	t := strings.TrimSpace(text)
	switch {
	case strings.HasPrefix(t, "//go:"):
		return true
	case strings.HasPrefix(t, "// +build"):
		return true
	case strings.HasPrefix(t, "//line "), strings.HasPrefix(t, "/*line "):
		return true
	case strings.HasPrefix(t, "//export "):
		return true
	}
	return false
}

// guardsAround returns the enclosing branch predicates of an operation,
// outermost first. They are provenance the correspondence step rechecks; a
// changed guard is separately a residual.
func guardsAround(a *analyzer, v *fileView, pos token.Pos) []Guard {
	if v == nil {
		return nil
	}
	type entry struct {
		pos  token.Pos
		expr ast.Expr
		kind string
	}
	var entries []entry
	ast.Inspect(v.File, func(n ast.Node) bool {
		if n == nil || !containsPos(n, pos) {
			return true
		}
		switch x := n.(type) {
		case *ast.IfStmt:
			if ifStmtIsErrorCheckFor(x, pos) {
				return true
			}
			entries = append(entries, entry{pos: x.Pos(), expr: x.Cond, kind: "if"})
		case *ast.ForStmt:
			entries = append(entries, entry{pos: x.Pos(), expr: x.Cond, kind: "for"})
		case *ast.RangeStmt:
			entries = append(entries, entry{pos: x.Pos(), expr: x.X, kind: "range"})
		case *ast.SwitchStmt:
			entries = append(entries, entry{pos: x.Pos(), expr: x.Tag, kind: "switch"})
		case *ast.TypeSwitchStmt:
			entries = append(entries, entry{pos: x.Pos(), expr: nil, kind: "type-switch"})
		}
		return true
	})
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].pos < entries[j].pos })
	out := make([]Guard, 0, len(entries))
	for _, e := range entries {
		g := Guard{Kind: e.kind, Witness: v.witness(e.pos, e.pos, "")}
		if e.expr != nil {
			g.Condition = sourceText(v, e.expr)
			g.Witness = v.witness(e.expr.Pos(), e.expr.End(), "")
			if isSimpleOperand(e.expr) {
				resolved := a.resolveExpr(v, e.expr, 0)
				g.Tested = &resolved
			}
		}
		out = append(out, g)
	}
	return out
}

// ifStmtIsErrorCheckFor reports whether the if statement is the standard
// `if err := CALL; err != nil` error propagation around the operation at pos.
// It is the operation's own control form, not a resource policy guard.
func ifStmtIsErrorCheckFor(ifs *ast.IfStmt, pos token.Pos) bool {
	assign, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || !containsPos(call, pos) {
		return false
	}
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	if _, ok := cond.X.(*ast.Ident); !ok {
		return false
	}
	rhs, ok := cond.Y.(*ast.Ident)
	return ok && rhs.Name == "nil"
}

func isSimpleOperand(expr ast.Expr) bool {
	switch unwrapParen(expr).(type) {
	case *ast.Ident, *ast.SelectorExpr:
		return true
	}
	return false
}

// errorScaffold returns the innermost if statement that carries the standard
// `if err := CALL; err != nil { return …err }` propagation form around the
// call. Any other guard is not scaffolding: its changed tokens stay residual.
func errorScaffold(v *fileView, call *ast.CallExpr) (*ast.IfStmt, bool) {
	var best *ast.IfStmt
	ast.Inspect(v.File, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !containsPos(ifs, call.Pos()) {
			return true
		}
		if best == nil || ifs.Pos() >= best.Pos() {
			best = ifs
		}
		return true
	})
	if best == nil {
		return nil, false
	}
	assign, ok := best.Init.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil, false
	}
	errIdent, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || assign.Rhs[0] != call {
		return nil, false
	}
	cond, ok := best.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return nil, false
	}
	condLHS, ok := cond.X.(*ast.Ident)
	if !ok || condLHS.Name != errIdent.Name {
		return nil, false
	}
	condRHS, ok := cond.Y.(*ast.Ident)
	if !ok || condRHS.Name != "nil" {
		return nil, false
	}
	if len(best.Body.List) != 1 {
		return nil, false
	}
	ret, ok := best.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return nil, false
	}
	for _, result := range ret.Results {
		id, ok := result.(*ast.Ident)
		if !ok || id.Name != errIdent.Name {
			return nil, false
		}
	}
	return best, true
}
