package research

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// validCategories is the official 12-category vocabulary of the frozen
// {category, reasoning} contract, in precedence order.
var validCategories = map[string]bool{
	"false_positive": true, "code_not_present": true, "code_not_reachable": true,
	"requires_configuration": true, "requires_dependency": true,
	"requires_environment": true, "compiler_protected": true,
	"runtime_protected": true, "perimeter_protected": true,
	"mitigating_control_protected": true, "uncertain": true, "vulnerable": true,
}

// fenceRx strips an enclosing ```json / ``` fence around the answer.
var fenceRx = regexp.MustCompile("(?s)^\\s*```(?:json)?\\s*\n?(.*?)\\s*```\\s*$")

// parseAnswer extracts the official {category, reasoning} object from the
// agent's final message: a bare JSON object, a fenced object, or the first
// balanced {...} span inside prose. An unparsed answer is never guessed:
// the raw text is kept and the category is marked unavailable.
func parseAnswer(raw string) (category, reasoning string, err error) {
	obj, perr := extractJSONObject(raw)
	if perr != nil {
		return "", "", perr
	}
	cat, _ := obj["category"].(string)
	if cat == "" || !validCategories[strings.ToLower(cat)] {
		return "", "", fmt.Errorf("answer carries no valid category (got %q)", cat)
	}
	reas, _ := obj["reasoning"].(string)
	return strings.ToLower(cat), strings.TrimSpace(reas), nil
}

// extractJSONObject returns the first balanced {...} span parseable as a
// JSON object — the official parser's tolerance for surrounding prose.
func extractJSONObject(text string) (map[string]any, error) {
	stripped := strings.TrimSpace(text)
	if m := fenceRx.FindStringSubmatch(stripped); m != nil {
		stripped = strings.TrimSpace(m[1])
	}
	if strings.HasPrefix(stripped, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(stripped), &obj); err == nil {
			return obj, nil
		}
	}
	depth, start := 0, -1
	for i := range len(stripped) {
		switch stripped[i] {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				var obj map[string]any
				if err := json.Unmarshal([]byte(stripped[start:i+1]), &obj); err == nil {
					return obj, nil
				}
				start = -1
			}
		}
	}
	return nil, fmt.Errorf("no parseable JSON object in agent answer")
}

// categoryLiteralRx matches a verbatim category literal anywhere in the
// raw answer — inside a truncated {category, reasoning} object, in prose,
// or escaped (\"category\": \"…\") inside a quoted JSON dump. The value is
// accepted only against the official 12-category vocabulary.
var categoryLiteralRx = regexp.MustCompile(`\\?"category\\?"\s*:\s*\\?"([A-Za-z_]+)`)

// salvageCategory deterministically recovers the category literal from an
// answer the structured parse could not handle. The LAST valid literal
// wins — mirroring the export rule that the last assistant text is the
// final answer, and the recurring failure shape is a truncated answer
// object whose category line survived. An absent or out-of-vocabulary
// literal is a miss: the category is never inferred or guessed.
func salvageCategory(raw string) (string, bool) {
	cat := ""
	for _, m := range categoryLiteralRx.FindAllStringSubmatch(raw, -1) {
		if c := strings.ToLower(m[1]); validCategories[c] {
			cat = c
		}
	}
	return cat, cat != ""
}

// fileRefRx matches code citations in the answer: a path with a source
// extension, optionally followed by :line, :start-end, #Lline or
// #Lstart-Lend.
var fileRefRx = regexp.MustCompile(
	`(?:^|[\s("'` + "`" + `])((?:[A-Za-z0-9_./-]+/)?[A-Za-z0-9_.-]+\.(?:go|mod|sum|work|yaml|yml|json|toml|sh|py|js|ts|dockerfile)(?::\d+(?:-\d+)?|#L\d+(?:-L\d+)?)?)\b`)

// refLocation is a parsed :line / :start-end / #Lx[-Ly] suffix. end is 0
// for a single-line ref.
type refLocation struct {
	raw       string // original suffix incl. separator (":42", "#L10-L20")
	startLine int
	endLine   int
}

// splitRef separates a citation into file path and location suffix. A
// malformed suffix stays attached to the path and is reported as a bad
// location, never silently dropped.
func splitRef(ref string) (file string, loc *refLocation, bad bool) {
	if i := strings.LastIndex(ref, "#L"); i > 0 {
		if parseLineLoc(ref[i+2:], 'L') != nil {
			return ref[:i], &refLocation{raw: ref[i:], startLine: locStart(ref[i+2:]), endLine: locEnd(ref[i+2:])}, false
		}
		return ref[:i], nil, true
	}
	if i := strings.LastIndex(ref, ":"); i > 0 {
		if loc := parseLineLoc(ref[i+1:], ':'); loc != nil {
			loc.raw = ref[i:]
			return ref[:i], loc, false
		}
		// Trailing ":" or ":text" — the whole tail might be the file's
		// own name (paths never contain ':'); treat as location only
		// when the tail is numeric-ish but invalid (e.g. ":0").
		if allDigitsOrDash(ref[i+1:]) {
			return ref[:i], nil, true
		}
		return ref, nil, false
	}
	return ref, nil, false
}

func allDigitsOrDash(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func locStart(tail string) int {
	if i := strings.IndexAny(tail, "-L"); i >= 0 {
		n, _ := parseUint(tail[:i])
		return n
	}
	n, _ := parseUint(tail)
	return n
}

func locEnd(tail string) int {
	if i := strings.Index(tail, "-L"); i >= 0 {
		n, _ := parseUint(tail[i+2:])
		return n
	}
	if i := strings.Index(tail, "-"); i >= 0 {
		n, _ := parseUint(tail[i+1:])
		return n
	}
	return 0
}

// parseLineLoc validates "N", "N-M" (colon form) or "N[-LM]" (hash form,
// tail already past #L). Returns nil on any malformed shape.
func parseLineLoc(tail string, _ byte) *refLocation {
	start := locStart(tail)
	end := locEnd(tail)
	if start <= 0 || (strings.Contains(tail, "-") && end <= 0) {
		return nil
	}
	return &refLocation{startLine: start, endLine: end}
}

// stripRefPrefixes normalises a citation path: the container mount point
// /work/, leading slashes and ./ are removed so the path can be resolved
// against the snapshot root.
func stripRefPrefixes(p string) string {
	p = strings.TrimSpace(p)
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	if strings.HasPrefix(p, "/work/") {
		p = strings.TrimPrefix(p, "/work/")
	} else {
		p = strings.TrimLeft(p, "/")
	}
	return p
}

// insideSnapshot reports whether rel resolves lexically inside root
// (symlink escapes are already excluded by snapshot verification).
func insideSnapshot(root, rel string) bool {
	joined := filepath.Join(root, filepath.FromSlash(rel))
	clean := filepath.Clean(joined)
	return clean == root || strings.HasPrefix(clean, root+string(filepath.Separator))
}

// refVerify resolves one citation against the snapshot and reports
// (normalized ref, status): status is "exists" | "missing" |
// "outside snapshot" | "bad location". The normalized ref keeps the
// location suffix so the reader can check it.
func refVerify(snapshotRoot, ref string) (string, string) {
	file, loc, badLoc := splitRef(strings.TrimSpace(ref))
	if badLoc {
		return stripRefPrefixes(ref), "bad location"
	}
	file = stripRefPrefixes(file)
	if file == "" {
		return ref, "missing"
	}
	suffix := ""
	if loc != nil {
		suffix = loc.raw
	}

	candidates := []string{file}
	if strings.HasPrefix(file, "work/") {
		candidates = append(candidates, strings.TrimPrefix(file, "work/"))
	}
	best := "missing"
	for _, cand := range candidates {
		if !insideSnapshot(snapshotRoot, cand) {
			if best == "missing" {
				best = "outside snapshot"
			}
			continue
		}
		fi, err := os.Stat(filepath.Join(snapshotRoot, filepath.FromSlash(cand)))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if loc != nil {
			b, rerr := os.ReadFile(filepath.Join(snapshotRoot, filepath.FromSlash(cand)))
			if rerr != nil {
				continue
			}
			lines := strings.Count(string(b), "\n") + 1
			end := loc.endLine
			if end == 0 {
				end = loc.startLine
			}
			if end < loc.startLine || end > lines {
				return cand + suffix, "bad location"
			}
		}
		return cand + suffix, "exists"
	}
	return file + suffix, best
}

func parseUint(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("not a number")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// claimBuckets classify reasoning sentences into the five research facets
// by domain keywords. The classification never rewrites the agent's
// wording — it only groups it; the verbatim reasoning is kept alongside.
var facetKeywords = map[string][]string{
	"mechanism": {
		"vulnerability", "vulnerable code", "vulnerable function", "the bug", "the flaw",
		"panic", "overflow", "traversal", "injection", "denial of service", "dos",
		"memory corruption", "race condition", "the cve describes", "the advisory",
		"affects the", "the cve", "impacts how", "allows an attacker",
	},
	"root_cause": {
		"root cause", "caused by", "because it", "missing check", "missing validation",
		"fails to", "does not validate", "does not verify", "does not sanitize",
		"does not check", "incorrect", "improper", "due to", "instead of",
	},
	"affected_implementations": {
		"affected package", "affected module", "affected symbol", "vulnerable package",
		"vulnerable module", "vulnerable function", "the function", "the package",
		"declared in go.mod", "declares", "in go.sum", "go.mod:", "go.sum:",
		"vendored", "version ",
	},
	"usage_paths": {
		"called from", "imported by", "imports", "reaches", "call chain", "call site",
		"invoked", "used by", "reachable", "unreachable", "code path", "execution path",
		"imported or executed", "first-party",
	},
	"exploitation_conditions": {
		"exploit", "attacker", "precondition", "requires", "condition",
		"authentication", "permission", "privilege", "crafted",
		"request", "header", "mitigation", "protected",
	},
}

var assumptionRx = regexp.MustCompile(`(?i)\b(assum\w+|likely|probably|appears to|seems to|presum\w+|typicall?y?)\b`)
var unknownRx = regexp.MustCompile(`(?i)\b(cannot determine|could not determine|unable to (?:determine|confirm|verify)|not verifiable|unclear|unknown|uncertain|no evidence|cannot confirm|unconfirmed|remains? open|not established)\b`)

// analyzeAnswer parses the raw agent answer into r.Answer and fills
// r.Analysis: verbatim reasoning, facet-grouped claims carrying their
// cited paths (each checked for presence inside the snapshot — a presence
// check only, never confirmation of the claim), and the extraction states
// of assumptions and unknowns. The reasoning is never rewritten; the
// bucketing is a reading aid, not a transformation.
func analyzeAnswer(o Options, r *Report, runDir string) {
	source := r.Answer.Source
	rawPath := filepath.Join(runDir, "raw_agent_output.txt")
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		// Nothing recoverable survived the run — the report must still say
		// WHY: which artifacts existed, sizes, exit code, stderr tail.
		diag := "raw answer unreadable: " + err.Error() +
			"; " + answerArtifactsDiag(r, runDir)
		r.Answer = AnswerInfo{
			CategoryLabel: "unavailable", Parsed: false,
			Source:     source,
			ParseError: diag,
		}
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"agent answer unreadable: "+diag)
		return
	}
	r.Answer.RawPath = "raw_agent_output.txt"
	cat, reasoning, perr := parseAnswer(string(raw))
	if perr != nil {
		// Deterministic salvage only: a verbatim `"category": "<one of the
		// 12 contract categories>"` literal inside the raw text (truncated
		// JSON, prose dump, escaped embedding) — never inferred, never
		// invented. Without that literal the answer stays unavailable.
		srcNote := ""
		if source == "opencode-stderr.log" || source == "session-list.json" {
			srcNote = "raw answer came from fallback source " + source + "; "
		}
		if salv, sok := salvageCategory(string(raw)); sok {
			r.Answer = AnswerInfo{
				Category:      salv,
				CategoryLabel: "research_judgement",
				Parsed:        true,
				Salvaged:      true,
				Source:        source,
				RawPath:       "raw_agent_output.txt",
				ParseError:    "structured parse failed (" + perr.Error() + "); category salvaged from verbatim category literal",
			}
			r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
				"agent answer failed the {category, reasoning} contract ("+perr.Error()+
					"); category `"+salv+"` was salvaged from a verbatim literal — no reasoning, facets or citations could be extracted")
			return
		}
		r.Answer = AnswerInfo{
			Category:      "",
			CategoryLabel: "unavailable",
			Parsed:        false,
			Source:        source,
			RawPath:       "raw_agent_output.txt",
			ParseError:    srcNote + perr.Error(),
		}
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"agent answer not parseable against the official {category, reasoning} contract: "+srcNote+perr.Error())
		return
	}
	r.Answer = AnswerInfo{
		Category:      cat,
		CategoryLabel: "research_judgement",
		Reasoning:     reasoning,
		Parsed:        true,
		Source:        source,
		RawPath:       "raw_agent_output.txt",
	}
	r.Analysis.Reasoning = reasoning

	sentences := splitSentences(reasoning)
	agentAssumptions, agentUnknowns := 0, 0
	for _, s := range sentences {
		low := strings.ToLower(s)
		claim := Claim{Text: s}
		seen := map[string]bool{}
		for _, m := range fileRefRx.FindAllStringSubmatch(s, -1) {
			norm, status := refVerify(o.SnapshotDir, m[1])
			if seen[norm+"|"+status] {
				continue
			}
			seen[norm+"|"+status] = true
			if status == "exists" {
				claim.PathsFound = append(claim.PathsFound, norm)
				r.Analysis.PresenceSummary.PathsFound++
			} else {
				claim.PathsNotFound = append(claim.PathsNotFound, norm+" ("+status+")")
				r.Analysis.PresenceSummary.PathsNotFound++
			}
		}
		switch {
		case matchesAny(low, facetKeywords["affected_implementations"]):
			r.Analysis.AffectedImplementations = append(r.Analysis.AffectedImplementations, claim)
		case matchesAny(low, facetKeywords["usage_paths"]):
			r.Analysis.UsagePaths = append(r.Analysis.UsagePaths, claim)
		case matchesAny(low, facetKeywords["exploitation_conditions"]):
			r.Analysis.ExploitationConditions = append(r.Analysis.ExploitationConditions, claim)
		case matchesAny(low, facetKeywords["root_cause"]):
			if r.Analysis.RootCause == "" {
				r.Analysis.RootCause = s
			} else {
				r.Analysis.AffectedImplementations = append(r.Analysis.AffectedImplementations, claim)
			}
		case matchesAny(low, facetKeywords["mechanism"]):
			if r.Analysis.Mechanism == "" {
				r.Analysis.Mechanism = s
			} else {
				r.Analysis.ExploitationConditions = append(r.Analysis.ExploitationConditions, claim)
			}
		}
		if assumptionRx.MatchString(s) {
			r.Analysis.Assumptions.Items = append(r.Analysis.Assumptions.Items, s)
			agentAssumptions++
		}
		if unknownRx.MatchString(s) {
			r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items, s)
			agentUnknowns++
		}
	}
	// The state reports what the answer extraction established — items
	// recorded by other stages (advisory gaps, run failures) never change
	// it: "not_established" means the parsed answer itself yielded nothing.
	if agentAssumptions > 0 {
		r.Analysis.Assumptions.State = "extracted"
	} else {
		r.Analysis.Assumptions.State = "not_established"
	}
	if agentUnknowns > 0 {
		r.Analysis.Unknowns.State = "extracted"
	} else {
		r.Analysis.Unknowns.State = "not_established"
	}
	if len(r.Analysis.AffectedImplementations) == 0 && len(r.Analysis.UsagePaths) == 0 &&
		len(r.Analysis.ExploitationConditions) == 0 &&
		r.Analysis.Mechanism == "" && r.Analysis.RootCause == "" && reasoning != "" {
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"agent reasoning could not be facet-classified; read the verbatim reasoning above")
	}
}

func matchesAny(s string, keys []string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// splitSentences breaks reasoning into sentence-ish fragments on ". " and
// newlines, keeping the order. The fragments are display units only.
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
