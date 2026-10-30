package reportcheck

import (
	"regexp"
	"strings"
)

// Polarity and scope vocabularies for path claims.
const (
	PolarityAbsence  = "absence"
	PolarityPresence = "presence"

	ScopeFirstParty = "first_party"
	ScopeModule     = "module"
	ScopeSymbol     = "symbol"
)

// standaloneAbsenceRx matches words that state absence of usage by
// themselves — no separate negation cue is needed.
var standaloneAbsenceRx = regexp.MustCompile(`(?i)\b(?:unused|unreachable|absent)\b|\bне\s+используется\b`)

// negationCueRx matches a negation cue. A cue alone is not enough for an
// absence claim: it must bind to a usage/path token (see clauseAbsence).
var negationCueRx = regexp.MustCompile(`(?i)\b(?:neither|nor|never|not|cannot|without|` +
	`doesn't|don't|didn't|isn't|aren't|wasn't|weren't|no)\b`)

// usageTokenRx matches the usage/path vocabulary a negation must attach to:
// "never used", "not imported", "no call path", "does not invoke".
var usageTokenRx = regexp.MustCompile(`(?i)\b(?:use|used|uses|using|call|calls|called|calling|` +
	`import|imports|imported|importing|reachable|reached|reaches|reaching|` +
	`path|paths|invoke|invokes|invoked|invoking|execute|executed|executes|executing|` +
	`reference|references|referenced|referencing)\b`)

// nonPathNegationRx matches the nouns a negation may be about without being
// a path statement: authentication, configuration, validation, a fix or a
// patch. When such a noun precedes the first usage token after the cue, the
// negation is not about the path.
var nonPathNegationRx = regexp.MustCompile(`(?i)\b(?:authenticat\w*|configur\w*|validat\w*|` +
	`fix(?:es|ed|ing)?|applied|patch\w*|credentials?|permissions?|settings?|mitigation\w*)\b`)

// presenceRx matches usage statements: a call/invocation, a reachability
// edge or a "used by" reference. Import wording is deliberately absent —
// an import is a package-presence fact, not a usage site.
var presenceRx = regexp.MustCompile(`(?i)(?:` +
	`\bcalls?\b|\bcalled\s+(?:from|by)\b` +
	`|\binvokes?\b|\binvoked\s+(?:from|by)\b` +
	`|\breachable\s+(?:from|via)\b` +
	`|\bused\s+by\b` +
	`)`)

// firstPartyRx marks explicitly first-party wording: the claim is about the
// product's own code, so it outranks module/package wording.
var firstPartyRx = regexp.MustCompile(`(?i)\bfirst[-\s]?party\b`)

// moduleScopeRx marks module-level wording: the claim names a module or a
// dependency rather than first-party code.
var moduleScopeRx = regexp.MustCompile(`(?i)\b(?:modules?|dependency|dependencies)\b`)

// extractNegative pulls path polarity statements out of the reasoning
// text. Each sentence yields at most one claim (absence wins over presence
// when both match); claims keep text order and duplicate
// (raw, polarity, scope, path, symbol) tuples collapse to the first.
func extractNegative(text string) []NegativeClaim {
	out := []NegativeClaim{}
	seen := map[string]bool{}
	for _, snt := range splitSentences(text) {
		polarity := ""
		switch {
		case absenceMatch(snt):
			polarity = PolarityAbsence
		case presenceRx.MatchString(snt):
			polarity = PolarityPresence
		default:
			continue
		}
		c := NegativeClaim{Raw: snt, Polarity: polarity, Scope: ScopeFirstParty}
		if m := citationRx.FindStringSubmatch(snt); m != nil {
			c.Path, _, _, _ = parseCitation(m[1])
		}
		for _, s := range unitSymbols(snt, citationRx.FindAllStringSubmatchIndex(snt, -1)) {
			c.Symbol = normalizeSymbol(s.raw)
			break
		}
		switch {
		case c.Symbol != "":
			c.Scope = ScopeSymbol
		case firstPartyRx.MatchString(snt):
			c.Scope = ScopeFirstParty
		case moduleScopeRx.MatchString(snt):
			c.Scope = ScopeModule
		}
		key := c.Polarity + "|" + c.Scope + "|" + c.Path + "|" + c.Symbol + "|" + strings.TrimSpace(c.Raw)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// absenceMatch reports a genuine absence statement: a standalone absence
// word, or a negation cue that binds to a usage/path token in the same
// clause. A cue followed first by an authentication/configuration/fix/
// validation noun is not about the path — "reachable via network input
// without any authentication" is presence, "the fix is not applied" is
// neither.
func absenceMatch(sentence string) bool {
	if standaloneAbsenceRx.MatchString(sentence) {
		return true
	}
	for _, clause := range splitClauses(sentence) {
		if clauseAbsence(clause) {
			return true
		}
	}
	return false
}

// clauseAbsence walks the negation cues of one clause: the first cue that
// has a usage/path token after it, with no non-path noun in between, makes
// the clause an absence statement.
func clauseAbsence(clause string) bool {
	if !usageTokenRx.MatchString(clause) {
		return false
	}
	for _, cue := range negationCueRx.FindAllStringIndex(clause, -1) {
		rest := clause[cue[1]:]
		u := usageTokenRx.FindStringIndex(rest)
		if u == nil {
			continue
		}
		if n := nonPathNegationRx.FindStringIndex(rest); n != nil && n[0] < u[0] {
			continue // negation about auth/config/validation/fix — not a path
		}
		return true
	}
	return false
}

// splitClauses splits a sentence on clause separators so a negation in one
// clause never binds to a usage token in another.
func splitClauses(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' })
}
