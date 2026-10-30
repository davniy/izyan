package research

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// frozenOfficialSHA256 is the sha256 of the stripped bytes of the frozen
// B1 prompt template this package embeds. The template ships verbatim as
// b1-plain.txt and is the same frozen document the V2 harness pinned
// (eval/agent7 prompts/b1-plain.txt): the render path refuses a drifted
// copy so a quiet edit of the embedded template can never change what the
// agent was actually instructed to answer.
const frozenOfficialSHA256 = "c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda"

// scanDataset carries the frozen benchmark identifiers the prompt must
// never leak: task ids, CVE ids, repo slugs, GT category names and smoke
// short names. The single {cve_id} placeholder is allowed and never
// flagged.
type scanDataset struct {
	TaskIDs         []string // full task ids
	CVEIDs          []string // CVE ids
	RepoSlugs       []string // repo slugs
	GTCategories    []string // GT category names
	SmokeShortNames []string // smoke short names
}

// prohibitedBlockPatterns are structural identifier patterns that apply
// only to the appended delta (everything past the frozen official prefix).
// A literal CVE/GHSA/GO-advisory id there would be a case hint; the
// official EXAMPLE already contains a GHSA id, so these patterns must not
// scan the frozen prefix.
var prohibitedBlockPatterns = []struct {
	rule string
	rx   *regexp.Regexp
}{
	{"cve_id", regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)},
	{"ghsa_id", regexp.MustCompile(`(?i)GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}`)},
	{"go_advisory_id", regexp.MustCompile(`GO-\d{4}-\d{4,}`)},
}

// prohibitedFullPatterns apply to the whole rendered template including
// the frozen official prefix: a benchmark task-id or a fix reference must
// not appear anywhere — if such a pattern matched inside the frozen
// prefix the freeze itself would be invalid.
var prohibitedFullPatterns = []struct {
	rule string
	rx   *regexp.Regexp
}{
	{"fix_reference", regexp.MustCompile(`(?i)fix[-_ ]?(?:commit|pr|patch|id)\b|pull/\d+|#\d{4,}\b`)},
}

// scanProhibited returns every offending occurrence of a prohibited
// identifier in text against the frozen dataset. The single {cve_id}
// placeholder is treated as allowed: before scanning, the literal
// "{cve_id}" is masked so that a CVE id rendered through it is not
// attributed to the template. Findings are returned as sorted
// "rule: match" strings; an empty slice means the text is clean.
//
// Two scopes, following the Task-5 convention:
//   - "block" patterns (CVE/GHSA/GO-advisory ids) apply only to the
//     appended delta past the frozen official prefix — the official
//     EXAMPLE legitimately carries a GHSA id;
//   - "full" patterns (fix references) and literal dataset identifiers
//     (task ids, repo slugs, GT categories, smoke short names) apply to
//     the whole masked text.
//
// CVE ids from the dataset are matched as literals so that a CVE
// appearing only inside the masked placeholder is not reported, while
// the same CVE appearing elsewhere in the prompt is flagged.
func scanProhibited(text string, ds scanDataset, officialPrefix string) []string {
	masked := strings.ReplaceAll(text, "{cve_id}", "")

	seen := make(map[string]struct{})

	add := func(rule, match string) {
		seen[fmt.Sprintf("%s: %s", rule, match)] = struct{}{}
	}

	for _, p := range prohibitedFullPatterns {
		for _, m := range p.rx.FindAllString(masked, -1) {
			add(p.rule, m)
		}
	}

	// Block-scope structural patterns applied to the delta past the
	// frozen official prefix (the official EXAMPLE has a GHSA id).
	maskedPrefix := strings.ReplaceAll(officialPrefix, "{cve_id}", "")
	delta := masked
	if maskedPrefix != "" && strings.HasPrefix(masked, maskedPrefix) {
		delta = masked[len(maskedPrefix):]
	}
	for _, p := range prohibitedBlockPatterns {
		for _, m := range p.rx.FindAllString(delta, -1) {
			add(p.rule, m)
		}
	}

	// Literal dataset identifiers: case-insensitive substring for compound
	// ids (task ids, repo slugs with hyphens), word-boundary for atomic
	// identifiers (GT categories, smoke short names) so that the official
	// category vocabulary in the template is not flagged by its own
	// schema.
	type literalNeedle struct {
		rule, needle string
	}
	literals := make([]literalNeedle, 0, 64)
	for _, id := range ds.TaskIDs {
		literals = append(literals, literalNeedle{"task_id", id})
	}
	for _, id := range ds.CVEIDs {
		literals = append(literals, literalNeedle{"cve_id", id})
	}
	for _, slug := range ds.RepoSlugs {
		literals = append(literals, literalNeedle{"repo_slug", slug})
	}
	for _, cat := range ds.GTCategories {
		literals = append(literals, literalNeedle{"gt_category", cat})
	}
	for _, sn := range ds.SmokeShortNames {
		literals = append(literals, literalNeedle{"smoke_short_name", sn})
	}

	for _, l := range literals {
		if l.needle == "" {
			continue
		}
		if isWordIdentifier(l.needle) {
			rx := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(l.needle) + `\b`)
			for _, m := range rx.FindAllString(masked, -1) {
				add(l.rule, m)
			}
		} else {
			lower := strings.ToLower(masked)
			needle := strings.ToLower(l.needle)
			start := 0
			for {
				idx := strings.Index(lower[start:], needle)
				if idx < 0 {
					break
				}
				pos := start + idx
				add(l.rule, masked[pos:pos+len(l.needle)])
				start = pos + len(l.needle)
			}
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isWordIdentifier reports whether s consists solely of letters, digits
// and underscores — i.e. it is a token that \b word boundaries can
// delimit.
func isWordIdentifier(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return s != ""
}
