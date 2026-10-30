package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	reInvocation = regexp.MustCompile("(?i)\\b(?:is\\s+|are\\s+|was\\s+|were\\s+)?called\\s+with\\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\\s*(?:set\\s+to|==|=|to|as)\\s*`?([A-Za-z0-9_.+-]+)`?")
	reClaim      = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9_-]*)\s+claim\b`)
	reOmission   = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:is|are|was|were)\s+(?:never|not)\s+(?:called|invoked|executed)\b`),
		regexp.MustCompile(`(?i)\b(?:omits?|omitted|omission)\b`),
		regexp.MustCompile(`(?i)\bmissing\s+(?:call|invocation|check|check call)\b`),
		regexp.MustCompile(`(?i)\b(?:does|do|did)\s+not\s+(?:call|invoke|execute)\b`),
		regexp.MustCompile(`(?i)\bnever\s+(?:calls?|invokes?|executes?)\b`),
	}
)

// CheckMechanismStatements exposes the pure extraction results from advisory mechanism text:
// invocation, omission, quotations, argument name/value, payload claim/shapes, effect
// and conflict indicators.
type CheckMechanismStatements struct {
	Invocation            bool     `json:"invocation"`
	Omission              bool     `json:"omission"`
	Quote                 string   `json:"quote"`
	OmissionQuote         string   `json:"omission_quote,omitempty"`
	ArgName               string   `json:"arg_name,omitempty"`
	ArgValue              string   `json:"arg_value,omitempty"`
	ClaimWord             string   `json:"claim_word,omitempty"`
	Shapes                []string `json:"shapes,omitempty"`
	ExcludedShapes        []string `json:"excluded_shapes,omitempty"`
	Effect                string   `json:"effect,omitempty"`
	ConflictingInvocation bool     `json:"conflicting_invocation"`
	ConflictingPayload    bool     `json:"conflicting_payload"`
}

// CheckMechanismText extracts the authoritative advisory mechanism text, preferring
// Description over Summary.
func CheckMechanismText(v Vulnerability) string {
	if text := strings.TrimSpace(v.Description); text != "" {
		return text
	}
	return strings.TrimSpace(v.Summary)
}

// normalizeAdvisoryLiteral preserves the builder's literal normalization.
func normalizeAdvisoryLiteral(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "`'\""))
}

// ParseCheckMechanism extracts check mechanism statements for a candidate symbol from
// advisory text.
func ParseCheckMechanism(text string, check SymbolRef) CheckMechanismStatements {
	var statements CheckMechanismStatements
	_, name := splitSymbol(check.Symbol)
	sentences := splitAdvisorySentences(text)
	for _, sentence := range sentences {
		if !sentenceMentionsCheck(sentence, check, name) {
			continue
		}
		if m := reInvocation.FindStringSubmatch(sentence); m != nil {
			if statements.Invocation &&
				(!strings.EqualFold(statements.ArgName, m[1]) ||
					normalizeAdvisoryLiteral(statements.ArgValue) != normalizeAdvisoryLiteral(m[2])) {
				statements.ConflictingInvocation = true
			}
			statements.Invocation = true
			statements.ArgName = m[1]
			statements.ArgValue = m[2]
			statements.Quote = sentence
			statements.Effect = sentence
		}
		if !negatedOmission(sentence) {
			for _, re := range reOmission {
				if re.MatchString(sentence) {
					statements.Omission = true
					if statements.OmissionQuote == "" {
						statements.OmissionQuote = sentence
					}
					if statements.Quote == "" {
						statements.Quote = sentence
					}
					break
				}
			}
		}
		if len(statements.Shapes) == 0 {
			if claim, shapes, excluded, ok := payloadSignals(sentence); ok {
				statements.ClaimWord = claim
				statements.Shapes = shapes
				statements.ExcludedShapes = excluded
			}
		} else if claim, shapes, excluded, ok := payloadSignals(sentence); ok {
			if !strings.EqualFold(statements.ClaimWord, claim) ||
				!sameStringSliceSet(statements.Shapes, shapes) ||
				!sameStringSliceSet(statements.ExcludedShapes, excluded) {
				statements.ConflictingPayload = true
			}
		}
	}
	if len(statements.Shapes) == 0 {
		for _, sentence := range sentences {
			if claim, shapes, excluded, ok := payloadSignals(sentence); ok {
				statements.ClaimWord = claim
				statements.Shapes = shapes
				statements.ExcludedShapes = excluded
				break
			}
		}
	}
	return statements
}

// BindCheckArgumentPredicate maps an advisory argument to its declared formal
// name and index, preserving arbitrary normalized literals. Type-specific
// restrictions belong to the consuming checker, not the shared grammar.
func BindCheckArgumentPredicate(
	statements CheckMechanismStatements,
	formalNames []string,
) (CheckArgumentPredicate, error) {
	if statements.ConflictingInvocation {
		return CheckArgumentPredicate{}, errors.New("advisory names conflicting invocation arguments for the check")
	}
	argName := strings.TrimSpace(statements.ArgName)
	argValue := strings.TrimSpace(statements.ArgValue)
	if argName == "" || argValue == "" {
		return CheckArgumentPredicate{}, errors.New("advisory does not name defective argument and required literal")
	}
	for i, name := range formalNames {
		if strings.EqualFold(name, argName) {
			return CheckArgumentPredicate{
				Name:  name,
				Index: i,
				Value: normalizeAdvisoryLiteral(argValue),
			}, nil
		}
	}
	return CheckArgumentPredicate{}, fmt.Errorf("parameter %q is not declared by formal parameters", argName)
}

func splitSymbol(sym string) (typeName, name string) {
	s := strings.TrimPrefix(sym, "*")
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", sym
}

func sentenceMentionsCheck(sentence string, check SymbolRef, name string) bool {
	if check.Symbol != "" && strings.Contains(sentence, check.Symbol) {
		return true
	}
	if name == "" {
		return false
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	return re.MatchString(sentence)
}

func negatedOmission(sentence string) bool {
	lower := strings.ToLower(sentence)
	for _, phrase := range []string{
		"not omitted", "never omitted", "not missing", "not absent", "no omission",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func sameStringSliceSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[strings.ToLower(s)] = true
	}
	for _, s := range b {
		if !seen[strings.ToLower(s)] {
			return false
		}
	}
	return true
}

func payloadSignals(sentence string) (claimWord string, shapes, excluded []string, ok bool) {
	lower := strings.ToLower(sentence)
	if !strings.Contains(lower, "array") && !strings.Contains(lower, "[]string") && !strings.Contains(lower, "slice") {
		return "", nil, nil, false
	}
	if m := reClaim.FindStringSubmatch(sentence); m != nil {
		claimWord = strings.ToLower(m[1])
	}
	shapes = []string{"array"}
	if strings.Contains(lower, "rather than a single string") ||
		strings.Contains(lower, "rather than string") ||
		strings.Contains(lower, "instead of a string") ||
		strings.Contains(lower, "not a string") {
		excluded = []string{"string"}
	}
	return claimWord, shapes, excluded, true
}

func splitAdvisorySentences(text string) []string {
	var out []string
	rs := []rune(text)
	start := 0
	flush := func(end int) {
		s := strings.TrimSpace(string(rs[start:end]))
		if s != "" {
			out = append(out, s)
		}
		start = end
	}
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '.', '!', '?':
			if i+1 == len(rs) || unicode.IsSpace(rs[i+1]) {
				flush(i + 1)
				for i+1 < len(rs) && unicode.IsSpace(rs[i+1]) {
					i++
				}
				start = i + 1
			}
		case '\n', ';':
			flush(i)
			start = i + 1
		}
	}
	flush(len(rs))
	return out
}
