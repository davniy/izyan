package research

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// b1Template is the frozen plain-agent prompt: byte-identical to
// eval/agent7/prompts/b1-plain.txt (sha256 c0a5c8458b77…) which in turn is
// byte-identical to the harness's built-in `vuln` prompt. The copy is
// embedded so an installed binary renders the pinned bytes, not whatever
// file happens to sit in the working directory.
//
//go:embed b1-plain.txt
var b1Template string

// cveIDPattern accepts the identifier families the template can carry —
// the prompt's single substitution point is a bare advisory id.
var cveIDPattern = regexp.MustCompile(`^[A-Za-z]+-[A-Za-z0-9][A-Za-z0-9-]*$`)

// useBasedVerdictRule is the additive <USE_BASED_VERDICT> block appended
// after the frozen template bytes — the same byte rule the R0 arms use
// (frozen prefix + "\n\n" + block + "\n"), so the pinned B1 template stays
// an unchanged prefix. It encodes the product verdict policy: a dependency
// pinned inside the advisory's affected range whose vulnerable code
// actually executes is "vulnerable" even when the only input-delivery path
// is node-local or same-user; restricted reachability is recorded in
// reasoning as a limitation, never promoted into a safe category. The
// block must carry no case-specific identifiers (no CVE/GHSA/GO ids, no
// package names, no fix references) — the tests scan it.
var useBasedVerdictRule = `<USE_BASED_VERDICT>
Category selection is use-based. The precedence list and the
{category, reasoning} output contract above are unchanged; the rules below
refine how execution and reachability map onto the categories.

1. If the version of the affected package pinned or resolved in this
   repository falls inside the advisory's affected range AND its vulnerable
   code executes — the vulnerable surface is imported, referenced or called
   from first-party (non-test) source — the category is "vulnerable", unless
   a concrete control from categories 4-10 genuinely applies.

2. Restricted reachability is still reachability, never a safe category. An
   attack surface reachable only from the local node — a unix-domain socket,
   a localhost-only listener, a same-user IPC channel, or a path requiring
   root or privileges the actor is assumed to already hold — still counts as
   reachable. Such restrictions are recorded inside "reasoning" as an
   exploitation limitation that lowers priority; they never justify
   "code_not_reachable", "perimeter_protected" or any other non-vulnerable
   category.

3. A non-vulnerable category applies only when the affected package is
   absent, the vulnerable code never executes (no first-party call path at
   all — not merely a hard-to-reach one), or a concrete in-repository
   control removes the attack surface entirely. "uncertain" remains the
   fallback for genuinely missing evidence, not for reachability that
   exists but looks narrow.
</USE_BASED_VERDICT>`

// renderPrompt produces the agent prompt: the frozen template with exactly
// one {cve_id} replaced by the requested id, plus the additive
// <USE_BASED_VERDICT> block appended after the template bytes
// (substituted + "\n\n" + useBasedVerdictRule + "\n"). Everything else in
// the template is byte-preserved; a template carrying a different
// placeholder count, a second placeholder family, or a hash drift is a
// hard error — the run must not send a prompt the freeze does not pin.
func renderPrompt(cve string) (rendered string, info PromptInfo, err error) {
	tpl := b1Template
	info = PromptInfo{
		Name:            "b1-plain+use-based-verdict",
		TemplatePath:    "internal/research/b1-plain.txt (embedded copy of eval/agent7/prompts/b1-plain.txt)",
		TemplateSHA256:  sha256Hex([]byte(tpl)),
		Placeholder:     "{cve_id}",
		RuleBlock:       "use-based-verdict",
		RuleBlockSHA256: sha256Hex([]byte(useBasedVerdictRule)),
	}
	if info.TemplateSHA256 != frozenOfficialSHA256 {
		return "", info, fmt.Errorf("embedded B1 template sha256 %s does not match the frozen pin %s",
			info.TemplateSHA256, frozenOfficialSHA256)
	}
	if n := strings.Count(tpl, "{cve_id}"); n != 1 {
		return "", info, fmt.Errorf("B1 template carries %d {cve_id} placeholders, expected exactly 1", n)
	}
	if !cveIDPattern.MatchString(cve) {
		return "", info, fmt.Errorf("--cve %q is not a plausible advisory id", cve)
	}
	if strings.Contains(useBasedVerdictRule, "{cve_id}") {
		return "", info, fmt.Errorf("use-based verdict rule block must not carry the {cve_id} placeholder")
	}
	substituted := strings.Replace(tpl, "{cve_id}", cve, 1)
	if strings.Contains(substituted, "{cve_id}") {
		return "", info, fmt.Errorf("rendered prompt still contains {cve_id} — substitution failed")
	}
	info.Substitutions = 1
	rendered = substituted + "\n\n" + useBasedVerdictRule + "\n"
	info.RenderedSHA256 = sha256Hex([]byte(rendered))
	return rendered, info, nil
}
