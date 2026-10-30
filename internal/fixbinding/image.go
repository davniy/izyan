package fixbinding

import (
	"fmt"
	"go/scanner"
	"go/token"
	"sort"
	"strings"
)

// imageToken is one Go token of a hunk image, with the position it occupies in
// the source file the image belongs to (Line) and the byte column within that
// line (Col). Line numbers are file line numbers, not hunk-relative ones.
type imageToken struct {
	Kind token.Token
	Text string
	Line int
	Col  int
}

// changedToken is a token the patch changed. Image says which side it belongs
// to, Index locates it in that image's token stream, and Tokens carries the
// token itself.
type changedToken struct {
	Image Image
	Index int
	Token imageToken
}

// tokenizedImage is one side of a hunk, tokenized as a whole so a multi-line
// literal or comment is not split at a hunk boundary.
type tokenizedImage struct {
	Image  Image
	Tokens []imageToken
	byLine map[int][]int // file line -> token indexes
	Err    string
}

// tokenizeHunkImage scans the requested image of a hunk. It returns an error
// string when the fragment cannot be scanned completely; the caller turns every
// changed line into an explicit residual rather than guessing.
//
// Whitespace is not tokenized, so formatting-only changes compare equal. Only
// explicit semicolons participate: the automatically inserted ones carry no
// source identity and would make line joining/splitting look like a change.
func tokenizeHunkImage(h Hunk, img Image) tokenizedImage {
	lines := h.ImageLines(img)
	out := tokenizedImage{Image: img, byLine: map[int][]int{}}
	if len(lines) == 0 {
		return out
	}
	var src strings.Builder
	for i, ln := range lines {
		if i > 0 {
			src.WriteByte('\n')
		}
		src.WriteString(ln.Text)
	}
	fset := token.NewFileSet()
	file := fset.AddFile("", -1, src.Len())
	var scanErr string
	var s scanner.Scanner
	s.Init(file, []byte(src.String()), func(pos token.Position, msg string) {
		if scanErr == "" {
			scanErr = msg
		}
	}, scanner.ScanComments)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON && lit == "\n" {
			continue // automatically inserted; not source spelling
		}
		if tok == token.ILLEGAL && scanErr == "" {
			scanErr = fmt.Sprintf("illegal token %q", lit)
		}
		idx := len(out.Tokens)
		p := fset.Position(pos)
		line := p.Line
		if line < 1 || line > len(lines) {
			// A token position outside the assembled image cannot be mapped to
			// a file line. Refuse the image rather than guessing a line.
			if scanErr == "" {
				scanErr = fmt.Sprintf("token position %d:%d is outside the hunk image", p.Line, p.Column)
			}
			continue
		}
		text := lit
		if text == "" {
			text = tok.String()
		}
		out.Tokens = append(out.Tokens, imageToken{Kind: tok, Text: text, Line: lines[line-1].lineFor(img), Col: p.Column})
		out.byLine[lines[line-1].lineFor(img)] = append(out.byLine[lines[line-1].lineFor(img)], idx)
	}
	out.Err = scanErr
	return out
}

// lineFor returns the file line the hunk line occupies in the given image.
func (ln HunkLine) lineFor(img Image) int {
	if img == ImageBefore {
		return ln.OldLine
	}
	return ln.NewLine
}

// changedTokensInHunk computes the changed token sets of one hunk.
//
// Deleted and added lines of each contiguous change block are paired by token
// similarity, then the pair's token streams are aligned. Tokens outside the
// alignment are changed. A line left unpaired contributes all of its tokens as
// changed. Pairing only decides how much of a rewritten line is unchanged; an
// unpaired line is stricter, never laxer, so a mispairing cannot hide a token
// that the patch actually changed.
func analyzeHunk(h Hunk) (beforeImg, afterImg tokenizedImage, before, after []changedToken) {
	beforeImg = tokenizeHunkImage(h, ImageBefore)
	afterImg = tokenizeHunkImage(h, ImageAfter)
	if beforeImg.Err != "" || afterImg.Err != "" {
		return beforeImg, afterImg, nil, nil
	}

	beforeChanged := make(map[int]bool, len(beforeImg.Tokens))
	afterChanged := make(map[int]bool, len(afterImg.Tokens))

	type block struct {
		deleted []int // indexes into h.Lines
		added   []int
	}
	var blocks []block
	var cur *block
	for i, ln := range h.Lines {
		if ln.Kind == ' ' {
			cur = nil
			continue
		}
		if cur == nil {
			blocks = append(blocks, block{})
			cur = &blocks[len(blocks)-1]
		}
		if ln.Kind == '-' {
			cur.deleted = append(cur.deleted, i)
		} else {
			cur.added = append(cur.added, i)
		}
	}

	for _, b := range blocks {
		deletedTokens := make([][]imageToken, len(b.deleted))
		for k, li := range b.deleted {
			deletedTokens[k] = tokensOnImageLine(beforeImg, h.Lines[li].OldLine)
		}
		addedTokens := make([][]imageToken, len(b.added))
		for k, li := range b.added {
			addedTokens[k] = tokensOnImageLine(afterImg, h.Lines[li].NewLine)
		}

		pairs := pairLines(deletedTokens, addedTokens)
		pairedDeleted := make(map[int]bool, len(pairs))
		pairedAdded := make(map[int]bool, len(pairs))
		for _, p := range pairs {
			pairedDeleted[p[0]] = true
			pairedAdded[p[1]] = true
			beforeIdx := indexesOnImageLine(beforeImg, h.Lines[b.deleted[p[0]]].OldLine)
			afterIdx := indexesOnImageLine(afterImg, h.Lines[b.added[p[1]]].NewLine)
			matches, ok := alignTokens(deletedTokens[p[0]], addedTokens[p[1]])
			if !ok {
				// Too large to align exactly: treat every token of the pair as
				// changed rather than accepting an unverified equality.
				for _, idx := range beforeIdx {
					beforeChanged[idx] = true
				}
				for _, idx := range afterIdx {
					afterChanged[idx] = true
				}
				continue
			}
			matchedBefore := make(map[int]bool, len(matches))
			matchedAfter := make(map[int]bool, len(matches))
			for _, m := range matches {
				matchedBefore[m[0]] = true
				matchedAfter[m[1]] = true
			}
			for k, idx := range beforeIdx {
				if !matchedBefore[k] {
					beforeChanged[idx] = true
				}
			}
			for k, idx := range afterIdx {
				if !matchedAfter[k] {
					afterChanged[idx] = true
				}
			}
		}
		for k, li := range b.deleted {
			if pairedDeleted[k] {
				continue
			}
			for _, idx := range indexesOnImageLine(beforeImg, h.Lines[li].OldLine) {
				beforeChanged[idx] = true
			}
		}
		for k, li := range b.added {
			if pairedAdded[k] {
				continue
			}
			for _, idx := range indexesOnImageLine(afterImg, h.Lines[li].NewLine) {
				afterChanged[idx] = true
			}
		}
	}

	for i, t := range beforeImg.Tokens {
		if beforeChanged[i] {
			before = append(before, changedToken{Image: ImageBefore, Index: i, Token: t})
		}
	}
	for i, t := range afterImg.Tokens {
		if afterChanged[i] {
			after = append(after, changedToken{Image: ImageAfter, Index: i, Token: t})
		}
	}
	return beforeImg, afterImg, before, after
}

func tokensOnImageLine(img tokenizedImage, fileLine int) []imageToken {
	var out []imageToken
	for _, idx := range img.byLine[fileLine] {
		out = append(out, img.Tokens[idx])
	}
	return out
}

func indexesOnImageLine(img tokenizedImage, fileLine int) []int {
	return append([]int(nil), img.byLine[fileLine]...)
}

// pairLines pairs deleted and added lines of one change block greedily by
// shared-token count, highest similarity first. Lines with no token in common
// are left unpaired: there is no evidence they rewrite one another, so both
// sides stay wholly changed.
func pairLines(deleted, added [][]imageToken) [][2]int {
	type candidate struct {
		d, a  int
		score int
	}
	var cands []candidate
	for d := range deleted {
		dCount := tokenCounts(deleted[d])
		for a := range added {
			score := sharedTokenCount(dCount, added[a])
			if score == 0 {
				continue
			}
			// A single shared punctuation token is not evidence that one line
			// rewrites the other. Require either two shared tokens or at least
			// half of the shorter line; otherwise both lines stay wholly
			// changed, which is stricter, never laxer.
			smaller := len(deleted[d])
			if len(added[a]) < smaller {
				smaller = len(added[a])
			}
			if score < 2 && score*2 < smaller {
				continue
			}
			cands = append(cands, candidate{d: d, a: a, score: score})
		}
	}
	// Highest score first; ties keep source order so the result is stable.
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	usedD := make(map[int]bool, len(deleted))
	usedA := make(map[int]bool, len(added))
	var pairs [][2]int
	for _, c := range cands {
		if usedD[c.d] || usedA[c.a] {
			continue
		}
		usedD[c.d], usedA[c.a] = true, true
		pairs = append(pairs, [2]int{c.d, c.a})
	}
	return pairs
}

func tokenCounts(tokens []imageToken) map[string]int {
	out := make(map[string]int, len(tokens))
	for _, t := range tokens {
		out[tokenKey(t)]++
	}
	return out
}

func sharedTokenCount(counts map[string]int, tokens []imageToken) int {
	score := 0
	remaining := make(map[string]int, len(counts))
	for k, v := range counts {
		remaining[k] = v
	}
	for _, t := range tokens {
		k := tokenKey(t)
		if remaining[k] > 0 {
			remaining[k]--
			score++
		}
	}
	return score
}

// alignTokens computes the longest common subsequence of two token streams.
// The second result is false when the problem is too large to align exactly;
// callers must then treat the whole pair as changed.
func alignTokens(a, b []imageToken) ([][2]int, bool) {
	const maxCells = 4_000_000
	if len(a)*len(b) > maxCells {
		return nil, false
	}
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if tokenKey(a[i]) == tokenKey(b[j]) {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var pairs [][2]int
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case tokenKey(a[i]) == tokenKey(b[j]):
			pairs = append(pairs, [2]int{i, j})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return pairs, true
}

func tokenKey(t imageToken) string {
	return fmt.Sprintf("%d\x00%s", t.Kind, t.Text)
}
