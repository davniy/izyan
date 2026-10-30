package reportcheck

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Kind vocabulary. The first three are extraction contexts; metadata and
// import are resolved against the snapshot path/line after extraction and
// carry no locus or usage credit.
const (
	KindLocus    = "locus"
	KindUsage    = "usage"
	KindUnknown  = "unknown"
	KindMetadata = "metadata" // manifests, lock/checksum files, docs, testdata, test code
	KindImport   = "import"   // import declaration lines: presence-only
)

// extractUnit is one text fragment plus the claim kind its context
// assigns to every citation inside it.
type extractUnit struct {
	kind string
	text string
}

// citationRx matches one file citation: a path made of POSIX-ish segments
// ending in a known source/doc extension or a well-known basename, with an
// optional :line, :start-end, #Ln or #Ln-Lm suffix. The "<" characters in
// the directory class cover the <snapshot>/ prefix; Windows separators
// are not recognized as paths.
var citationRx = regexp.MustCompile(
	`(?:^|[\s("'<>` + "`" + `])((?:[A-Za-z0-9_./<>-]+/)?(?:[A-Za-z0-9_.-]+\.(?:go|mod|sum|work|yaml|yml|json|toml|lock|rst|sh|py|js|ts|md|txt|dockerfile)|Dockerfile|Makefile)(?::\d+(?:-\d+)?|#L\d+(?:-L\d+)?)?)\b`)

// symRecvRx matches receiver-form symbol claims: (*T).M or (T).M with an
// optional package qualifier — pkg.(*T).M, x.(*Server).Serve.
var symRecvRx = regexp.MustCompile(`[A-Za-z0-9_/]+\.\(\*?[A-Za-z_][A-Za-z0-9_]*\)\.[A-Za-z_][A-Za-z0-9_]*|\(\*?[A-Za-z_][A-Za-z0-9_]*\)\.[A-Za-z_][A-Za-z0-9_]*`)

// symDottedRx matches plain dotted symbol claims: pkg.Func, dep.T.M,
// golang.org/x/net/http2.readPreface. Lowercase single-segment dotted
// tokens (example.com) are filtered out after the match.
var symDottedRx = regexp.MustCompile(`[A-Za-z0-9_./]+\.[A-Za-z_][A-Za-z0-9_]*`)

// usageContextRx marks a sentence as usage context: the citation sits in
// call/reachability/import wording.
var usageContextRx = regexp.MustCompile(`(?i)\b(call|calls|called|invokes?|reaches?|reachable|reachability|imports?|usage|used by|call site|call chain|call graph|dial|wraps?)\b`)

// locusContextRx marks a sentence as locus context: the citation names
// where the defect lives.
var locusContextRx = regexp.MustCompile(`(?i)\b(root[ -]?cause|vulnerab\w+|defect|bug|flaw|panic|overflow|traversal|injection|escape|unmarshal|marshal|parse[rs]?|sink|affected (?:function|code|implementation))\b`)

// cweRx matches an advisory key claim.
var cweRx = regexp.MustCompile(`\bCWE-\d+\b`)

// domainSuffixRx filters out bare host tokens (example.com, osv.dev) that
// the dotted-symbol regex otherwise accepts. A single-segment dotted name
// ending in a common TLD-looking tail is not a symbol claim.
var domainSuffixRx = regexp.MustCompile(`^[a-z0-9-]+\.(?:com|org|net|io|dev|edu|gov|in|sh|app|me|co)$`)

// claimed is one extracted claim before verification.
type claimed struct {
	raw    string // verbatim citation or symbol token
	path   string // normalized path ("" for symbol-only claims)
	line   int
	end    int
	badLoc bool   // the captured location suffix was malformed
	symbol string // normalized symbol ("" when none attached)
	kind   string
}

// structuredContent is the projection of report.json's analysis block the
// grounder reads — decoded leniently so older reports still parse.
type structuredContent struct {
	rootCause []string
	mechanism []string
	affected  []string
	usage     []string
	exploit   []string
	reasoning string
	// answerCategory/answerReasoning mirror report.json's official answer
	// block: context for negative metrics, never a claim source.
	answerCategory  string
	answerReasoning string
	hasClaims       bool
}

// units maps the structured fields onto extraction contexts.
func (s structuredContent) units() []extractUnit {
	var u []extractUnit
	add := func(kind string, texts []string) {
		for _, t := range texts {
			for _, snt := range splitSentences(t) {
				u = append(u, extractUnit{kind: kind, text: snt})
			}
		}
	}
	add(KindLocus, s.rootCause)
	add(KindLocus, s.mechanism)
	add(KindLocus, s.affected)
	add(KindUsage, s.usage)
	add(KindUnknown, s.exploit)
	for _, snt := range splitSentences(s.reasoning) {
		u = append(u, extractUnit{kind: classifySentence(snt), text: snt})
	}
	return u
}

// the fields the grounder consumes are decoded; everything else passes.
func parseStructured(b []byte) (structuredContent, error) {
	var doc struct {
		Answer struct {
			Category  string `json:"category"`
			Reasoning string `json:"reasoning"`
		} `json:"answer"`
		Analysis struct {
			RootCause string `json:"root_cause"`
			Mechanism string `json:"mechanism"`
			Reasoning string `json:"reasoning"`
			Affected  []struct {
				Text string `json:"text"`
			} `json:"affected_implementations"`
			Usage []struct {
				Text string `json:"text"`
			} `json:"usage_paths"`
			Exploit []struct {
				Text string `json:"text"`
			} `json:"exploitation_conditions"`
		} `json:"analysis"`
	}
	var s structuredContent
	if err := json.Unmarshal(b, &doc); err != nil {
		return s, err
	}
	a := doc.Analysis
	if a.RootCause != "" {
		s.rootCause = []string{a.RootCause}
	}
	if a.Mechanism != "" {
		s.mechanism = []string{a.Mechanism}
	}
	for _, c := range a.Affected {
		s.affected = append(s.affected, c.Text)
	}
	for _, c := range a.Usage {
		s.usage = append(s.usage, c.Text)
	}
	for _, c := range a.Exploit {
		s.exploit = append(s.exploit, c.Text)
	}
	s.answerCategory = doc.Answer.Category
	s.answerReasoning = doc.Answer.Reasoning
	s.reasoning = a.Reasoning
	s.hasClaims = a.RootCause != "" || a.Mechanism != "" || a.Reasoning != "" ||
		len(s.affected)+len(s.usage)+len(s.exploit) > 0
	return s, nil
}

// parseMarkdown splits a legacy report.md into extraction units: each
// section is classified by its heading; the verbatim-reasoning section is
// split per sentence like raw text.
func parseMarkdown(md []byte) []extractUnit {
	var units []extractUnit
	sc := bufio.NewScanner(strings.NewReader(string(md)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	kind := KindUnknown
	var cur strings.Builder
	flush := func() {
		text := cur.String()
		cur.Reset()
		if strings.TrimSpace(text) == "" {
			return
		}
		if kind == "reasoning" {
			for _, snt := range splitSentences(text) {
				units = append(units, extractUnit{kind: classifySentence(snt), text: snt})
			}
			return
		}
		for _, snt := range splitSentences(text) {
			units = append(units, extractUnit{kind: kind, text: snt})
		}
	}
	for sc.Scan() {
		line := sc.Text()
		if h, ok := mdHeading(line); ok {
			flush()
			kind = classifyHeading(h)
			continue
		}
		cur.WriteString(line)
		cur.WriteByte(' ')
	}
	flush()
	return units
}

// mdHeading reports the lowercased heading text of a markdown "## …" line.
func mdHeading(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "#") {
		return "", false
	}
	t = strings.TrimLeft(t, "#")
	t = strings.TrimSpace(t)
	if t == "" {
		return "", false
	}
	return strings.ToLower(t), true
}

// classifyHeading maps a report.md section heading onto a claim kind. Only
// the sections the pipeline itself renders are attributed; every other
// section stays unknown so an incidental citation is not credited a role.
func classifyHeading(h string) string {
	switch {
	case strings.Contains(h, "agent reasoning"):
		return "reasoning"
	case strings.Contains(h, "root cause"),
		strings.Contains(h, "mechanism"),
		strings.Contains(h, "affected implementation"):
		return KindLocus
	case strings.Contains(h, "usage"),
		strings.Contains(h, "call"),
		strings.Contains(h, "reachab"),
		strings.Contains(h, "import"):
		return KindUsage
	default:
		return KindUnknown
	}
}

// mdSection returns the body of the first section whose heading contains
// needle — used to find the verbatim reasoning for mechanism extraction.
func mdSection(md []byte, needle string) string {
	var out strings.Builder
	in := false
	sc := bufio.NewScanner(strings.NewReader(string(md)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if h, ok := mdHeading(line); ok {
			if in && !strings.Contains(h, needle) {
				break
			}
			in = strings.Contains(h, needle)
			continue
		}
		if in {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// parseRawText treats the whole raw answer as prose: every sentence is
// classified by the usage/locus keyword rules.
func parseRawText(raw []byte) []extractUnit {
	var units []extractUnit
	for _, snt := range splitSentences(string(raw)) {
		units = append(units, extractUnit{kind: classifySentence(snt), text: snt})
	}
	return units
}

// classifySentence applies the deterministic context rules: usage wording
// wins over locus wording, otherwise unknown.
func classifySentence(s string) string {
	switch {
	case usageContextRx.MatchString(s):
		return KindUsage
	case locusContextRx.MatchString(s):
		return KindLocus
	default:
		return KindUnknown
	}
}

// splitSentences mirrors the research pipeline's display splitter: lines
// break at newlines and at ". " boundaries.
func splitSentences(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, frag := range strings.SplitAfter(line, ". ") {
			frag = strings.TrimSpace(frag)
			if frag != "" {
				out = append(out, frag)
			}
		}
	}
	return out
}

// extractLocations pulls every citation and standalone symbol claim out of
// the units, deduplicates on (path, range, symbol) and resolves kind
// precedence locus > usage > unknown.
func extractLocations(units []extractUnit) []claimed {
	order := map[string]int{KindLocus: 0, KindUsage: 1, KindUnknown: 2}
	seen := map[string]*claimed{}
	var out []*claimed
	merge := func(c claimed) {
		key := c.path + "|" + strconv.Itoa(c.line) + "|" + strconv.Itoa(c.end) + "|" + c.symbol
		if old, ok := seen[key]; ok {
			if order[c.kind] < order[old.kind] {
				old.kind = c.kind
			}
			return
		}
		cp := c
		seen[key] = &cp
		out = append(out, &cp)
	}
	for _, u := range units {
		for _, c := range extractUnitClaims(u) {
			merge(c)
		}
	}
	res := make([]claimed, 0, len(out))
	for _, c := range out {
		res = append(res, *c)
	}
	return res
}

// extractUnitClaims finds citations and symbol claims inside one unit. A
// symbol is attached to a citation when it is the only symbol in the unit
// or lies within 60 characters of it; a symbol far from any citation
// becomes a standalone (symbol-only) claim.
func extractUnitClaims(u extractUnit) []claimed {
	text := u.text
	var claims []claimed
	citIdx := citationRx.FindAllStringSubmatchIndex(text, -1)
	syms := unitSymbols(text, citIdx)

	for _, m := range citIdx {
		raw := text[m[2]:m[3]]
		c := claimed{kind: u.kind, raw: raw}
		c.path, c.line, c.end, c.badLoc = parseCitation(raw)
		if i := attachSymbol(syms, m[2], m[3]); i >= 0 {
			syms[i].attached = true
			c.symbol = normalizeSymbol(syms[i].raw)
		}
		claims = append(claims, c)
	}
	for _, s := range syms {
		if s.attached {
			continue
		}
		claims = append(claims, claimed{
			kind: u.kind, raw: s.raw, symbol: normalizeSymbol(s.raw),
		})
	}
	return claims
}

// symHit is one symbol token inside a unit.
type symHit struct {
	raw      string
	start    int
	end      int
	attached bool
}

// unitSymbols collects symbol candidates: receiver forms first, then plain
// dotted names, skipping matches that overlap a citation span or a
// hostname-looking token.
func unitSymbols(text string, citIdx [][]int) []symHit {
	overlaps := func(a, b int, spans [][]int) bool {
		for _, m := range spans {
			if a < m[3] && b > m[2] {
				return true
			}
		}
		return false
	}
	var hits []symHit
	taken := citIdx
	for _, m := range symRecvRx.FindAllStringIndex(text, -1) {
		if overlaps(m[0], m[1], taken) {
			continue
		}
		hits = append(hits, symHit{raw: text[m[0]:m[1]], start: m[0], end: m[1]})
		taken = append(taken, []int{-1, -1, m[0], m[1]})
	}
	for _, m := range symDottedRx.FindAllStringIndex(text, -1) {
		if overlaps(m[0], m[1], taken) {
			continue
		}
		tok := text[m[0]:m[1]]
		// An import path (example.com/ssh/agent) has its dots before the
		// last slash; a qualified symbol (golang.org/x/net/http2.F)
		// carries one after it.
		if strings.LastIndexByte(tok, '.') < strings.LastIndexByte(tok, '/') {
			continue
		}
		if domainSuffixRx.MatchString(tok) {
			continue
		}
		hits = append(hits, symHit{raw: tok, start: m[0], end: m[1]})
	}
	return hits
}

// attachSymbol picks the index of the symbol nearest to a citation span,
// or -1 when none qualifies. The single symbol of a unit always attaches;
// otherwise the closest symbol within 60 characters wins and ties resolve
// to the first (leftmost) one.
func attachSymbol(syms []symHit, citStart, citEnd int) int {
	if len(syms) == 0 {
		return -1
	}
	if len(syms) == 1 {
		return 0
	}
	best := -1
	bestDist := 61
	for i, s := range syms {
		d := citStart - s.end
		if d < 0 {
			d = s.start - citEnd
		}
		if d < 0 {
			d = 0
		}
		if d < bestDist {
			best, bestDist = i, d
		}
	}
	return best
}

// parseCitation splits a citation into normalized path and line range.
// Single-line citations carry end==line. badLoc marks a malformed captured
// suffix (:0, :9-4); a citation the grammar could not capture a suffix for
// arrives as path-only.
func parseCitation(raw string) (path string, line, end int, badLoc bool) {
	s := strings.TrimSpace(raw)
	if i := strings.LastIndex(s, "#L"); i > 0 {
		l, e, ok := parseLocSuffix(s[i+2:], true)
		return normalizePath(s[:i]), l, e, !ok
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		l, e, ok := parseLocSuffix(s[i+1:], false)
		return normalizePath(s[:i]), l, e, !ok
	}
	return normalizePath(s), 0, 0, false
}

// parseLocSuffix validates the digits the citation grammar captured:
// "N" or "N-M" in colon form, "N" or "N-LM" past "#L" in hash form.
// Zero lines, non-numeric tails and end<start are malformed.
func parseLocSuffix(tail string, hash bool) (line, end int, ok bool) {
	if hash && strings.HasPrefix(tail, "L") {
		return 0, 0, false
	}
	a, b, hasDash := strings.Cut(tail, "-")
	line, err1 := strconv.Atoi(a)
	if err1 != nil || line <= 0 {
		return 0, 0, false
	}
	if !hasDash {
		return line, line, true
	}
	if hash {
		b = strings.TrimPrefix(b, "L")
	}
	end, err2 := strconv.Atoi(b)
	if err2 != nil || end < line {
		return line, 0, false
	}
	return line, end, true
}

// normalizePath canonicalizes a cited path to a POSIX-relative form:
// forward slashes, no ./ or // segments, and the <snapshot>/ and /work/
// mount prefixes stripped. A leading work/ (work/tree layout) is kept —
// the verifier retries without it. .. segments are preserved for the
// escape check to report.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	for {
		switch {
		case strings.HasPrefix(p, "./"):
			p = p[2:]
		case strings.HasPrefix(p, "<snapshot>/"):
			p = strings.TrimPrefix(p, "<snapshot>/")
		case strings.HasPrefix(p, "<snapshot>"):
			p = strings.TrimPrefix(p, "<snapshot>")
		case strings.HasPrefix(p, "/work/"):
			p = strings.TrimPrefix(p, "/work/")
		default:
			goto done
		}
	}
done:
	for strings.HasPrefix(p, "/") {
		p = strings.TrimPrefix(p, "/")
	}
	parts := strings.Split(p, "/")
	clean := parts[:0]
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		clean = append(clean, seg)
	}
	return strings.Join(clean, "/")
}

// normalizeSymbol canonicalizes a claimed symbol: receiver forms
// "pkg.(*T).M" and "(*T).M" become "pkg.T.M" / "T.M"; everything else
// passes through verbatim.
func normalizeSymbol(raw string) string {
	s := strings.TrimSpace(raw)
	open := strings.Index(s, "(")
	if open < 0 {
		return s
	}
	closeIdx := strings.Index(s, ")")
	if closeIdx < open {
		return s
	}
	recv := strings.TrimPrefix(s[open+1:closeIdx], "*")
	return s[:open] + recv + s[closeIdx+1:]
}
