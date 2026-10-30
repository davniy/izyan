package research

import (
	"encoding/json"
	"fmt"
	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/reportcheck"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// writeOutputs persists report.json, report.md and the tool-execution
// audit trail into the run-scoped directory.
func writeOutputs(r *Report, runDir string, audit []pbdomain.ToolExecution) error {
	r.AuditLog = "audit.json"
	jb, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "report.json"), append(jb, '\n'), 0o644); err != nil {
		return fmt.Errorf("write report.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "report.md"), []byte(renderMarkdown(r)), 0o644); err != nil {
		return fmt.Errorf("write report.md: %w", err)
	}
	auditDoc := map[string]any{
		"schema":          "izyan-research-audit/1",
		"run_id":          r.RunID,
		"research_state":  r.ResearchState,
		"image":           r.Run.Image,
		"image_digest":    r.Run.ImageDigest,
		"model":           r.Run.Model,
		"prompt_sha256":   r.Prompt.RenderedSHA256,
		"config_sha256":   r.Run.ConfigSHA256,
		"snapshot_hash":   r.Snapshot.ContentHash,
		"advisory_sha256": r.Advisory.SHA256,
		"argv":            r.Run.Argv,
		"mounts":          r.Run.Mounts,
		"run_error":       r.Run.Error,
		"executed":        audit,
	}
	if len(r.Limitations) > 0 {
		auditDoc["limitations"] = r.Limitations
	}
	if r.RerenderOf != "" {
		auditDoc["rerender_of"] = r.RerenderOf
		auditDoc["replay"] = "no container, no network, no model call — answer text byte-identical to the stored raw answer"
	}
	ab, err := json.MarshalIndent(auditDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "audit.json"), append(ab, '\n'), 0o644); err != nil {
		return fmt.Errorf("write audit.json: %w", err)
	}
	return nil
}

// safeCategoryDisclaimer is the standing statement every report owes its
// reader: no non-vulnerable category is an established safety result.
const safeCategoryDisclaimer = "Every non-vulnerable category — `requires_configuration`, " +
	"`code_not_reachable`, `perimeter_protected` and the rest — is a research " +
	"judgement, not an established safety result: this report does not prove " +
	"the product safe, and the vulnerability stays open until a person settles it."

// renderMarkdown produces report.md: the disclaimer header with the run
// and snapshot identity, a substantive summary block, snapshot and
// advisory identities with digests, the host-fact consistency layer, the
// run metadata, the agent's research facets with cited paths, and the
// explicitly stated sections — confirmed facts, assumptions, unknowns —
// never mixed.
func renderMarkdown(r *Report) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# CVE research — %s\n\n", r.Request.CVE)
	w("> **Research judgement — not a verified safety conclusion.** %s\n\n", r.Disclaimer)
	w("- run id: `%s`\n", r.RunID)
	if r.RerenderOf != "" {
		w("- **re-render of run `%s` — no model call was made; the agent answer is the stored raw answer, byte-identical**\n", r.RerenderOf)
	}
	w("- mode: `%s` · research state: `%s`\n", r.Mode, r.ResearchState)
	w("- snapshot hash (%s): `%s`\n", r.Snapshot.ContentHashAlg, r.Snapshot.ContentHash)
	w("- generated: %s (izyan research)\n\n", r.GeneratedAt)
	writeSummary(&b, r)

	w("## Research category\n\n")
	if r.Answer.Parsed {
		w("`%s` — **research_judgement** (the agent's classification, shown verbatim; it does not close, clear or establish anything)\n\n", r.Answer.Category)
		if r.Answer.Salvaged {
			src := ""
			if r.Answer.Source != "" {
				src = " (raw source: `" + r.Answer.Source + "`)"
			}
			w("> **salvaged** — the {category, reasoning} object did not parse; this category is the verbatim `\"category\"` literal recovered from the raw answer%s. Reasoning, claims and citations are unavailable.\n\n", src)
		}
	} else {
		w("*unavailable* — the agent produced no usable category: %s\n\n", orReason(r.Answer.ParseError, "the run produced no parseable {category, reasoning} answer"))
	}
	w("> The agent's category above is the agent's own, shown verbatim. The presence and range status in the consistency section are facts about the installed version — they never establish, refute or substitute the category.\n\n")
	w("> %s\n\n", safeCategoryDisclaimer)

	w("## Snapshot\n\n")
	w("- path: `%s`\n", r.Snapshot.Path)
	w("- commit: `%s` (identity source: %s)\n", r.Snapshot.Commit, r.Snapshot.IdentitySource)
	w("- content hash (%s): `%s`\n", r.Snapshot.ContentHashAlg, r.Snapshot.ContentHash)
	if r.Snapshot.GoVersion != "" {
		w("- analysis go: `%s`\n", r.Snapshot.GoVersion)
	}
	if r.Snapshot.ReleaseGoVersion != "" {
		w("- release go: `%s` (evidence: %s)\n", r.Snapshot.ReleaseGoVersion, r.Snapshot.GoVersionSource)
	}
	mg := r.Snapshot.Module
	w("- module graph (%s):\n", mg.Method)
	if mg.GoModPresent {
		w("  - go.mod: module `%s`, go %s, %d requires, %d replaces\n", mg.ModulePath, mg.GoDirective, mg.RequireCount, mg.ReplaceCount)
	} else {
		w("  - go.mod: absent\n")
	}
	w("  - go.sum entries: %d; go.work: %t; vendor/modules.txt: %t (%d modules)\n",
		mg.GoSumEntries, mg.GoWorkPresent, mg.VendorModulesTxt, mg.VendorCount)
	for _, lr := range mg.LocalReplace {
		w("  - local replace: `%s`\n", lr)
	}
	w("\n")

	w("## Advisory\n\n")
	adv := r.Advisory
	switch adv.Status {
	case "resolved":
		w("- status: `resolved`\n")
		w("- id: `%s`", adv.ID)
		if len(adv.Aliases) > 0 {
			w(" (aliases: %s)", strings.Join(adv.Aliases, ", "))
		}
		w("\n")
		if adv.Module != "" {
			w("- module: `%s`", adv.Module)
			if adv.Package != "" {
				w(" package `%s`", adv.Package)
			}
			w("\n")
		}
		if adv.Summary != "" {
			w("- summary: %s\n", adv.Summary)
		}
		w("- document: `%s` sha256 `%s`\n", relDisplay(adv.Path), adv.SHA256)
		if adv.Source != "" {
			w("- source: %s\n", adv.Source)
		}
		if adv.DocumentURL != "" && adv.DocumentURL != adv.Source {
			w("- document url: %s\n", adv.DocumentURL)
		}
		if len(adv.FixedVersions) > 0 {
			w("- fixed versions: %s\n", strings.Join(adv.FixedVersions, ", "))
		}
		if len(adv.Affected) > 0 {
			w("- affected entries:\n")
			for _, e := range adv.Affected {
				w("  - `%s`", moduleLabel(e.Module))
				if len(e.Ranges) > 0 {
					w(" ranges %s", strings.Join(e.Ranges, ", "))
				}
				if len(e.Fixed) > 0 {
					w(" (fixed: %s)", strings.Join(e.Fixed, ", "))
				}
				if e.Document.ID != "" && e.Document.ID != adv.ID {
					w(" — from advisory %s", e.Document.ID)
				}
				w("\n")
			}
		}
		if adv.UncomparableEntries > 0 {
			w("- %d affected entries declare no Go module name — outside the Go module view, never checked against the graph\n", adv.UncomparableEntries)
		}
		if len(adv.Documents) > 1 {
			w("- advisory documents consulted:\n")
			for _, d := range adv.Documents {
				w("  - %s `%s` sha256 `%s` at `%s`\n", d.Role, d.ID, shortSHA(d.SHA256), relDisplay(d.Path))
			}
		}
	default:
		w("- status: `%s` — %s\n", adv.Status, adv.Reason)
	}
	w("\n")

	writeConsistency(&b, r)

	w("## Agent run\n\n")
	run := r.Run
	w("- status: `%s`", run.Status)
	if run.Reason != "" {
		w(" — %s", run.Reason)
	}
	if run.Error != "" {
		w(" — error: %s", run.Error)
	}
	w("\n")
	w("- attempt id: `%s`\n", run.AttemptID)
	w("- image: `%s`", run.Image)
	if run.ImageDigest != "" {
		w(" digest `%s`", run.ImageDigest)
	}
	w("\n")
	w("- model: `%s` (provider id `%s`)\n", run.Model, run.ProviderModel)
	w("- subagents: %s; MCP: %s; network: %s\n", run.Subagents, run.MCP, run.Network)
	w("- timeout: %ds; wall: %.1fs\n", run.TimeoutSeconds, run.WallSeconds)
	if run.ContainerExit != nil {
		w("- container exit code: %d\n", *run.ContainerExit)
	}
	if run.Tokens != nil {
		w("- tokens: in=%d out=%d reasoning=%d cache_read=%d cache_write=%d\n",
			run.Tokens.Input, run.Tokens.Output, run.Tokens.Reasoning, run.Tokens.CacheRead, run.Tokens.CacheWrite)
	}
	w("- mounts:\n")
	for _, m := range run.Mounts {
		w("  - `%s` → `%s` (%s)\n", m.Host, m.Container, m.Mode)
	}
	if run.EnvFile != "" {
		w("- env file: `%s`\n", run.EnvFile)
	}
	if len(run.EnvForwarded) > 0 {
		w("- forwarded env (names only): %s\n", strings.Join(run.EnvForwarded, ", "))
	}
	if len(run.EnvMissing) > 0 {
		w("- env declared but unset on host: %s\n", strings.Join(run.EnvMissing, ", "))
	}
	w("- config: `%s` sha256 `%s`\n", run.ConfigPath, run.ConfigSHA256)
	w("- prompt: sha256 `%s` (template `%s`)\n", r.Prompt.RenderedSHA256, shortSHA(r.Prompt.TemplateSHA256))
	w("\n### Container argv\n\n```\n%s\n```\n\n", strings.Join(run.Argv, " \\\n  "))

	a := r.Analysis
	writeMechanism(&b, r)
	w("## Root cause\n\n%s\n\n", orNone(a.RootCause))
	writeClaims(&b, "Affected implementations", a.AffectedImplementations)
	writeClaims(&b, "Usage paths", a.UsagePaths)
	writeClaims(&b, "Exploitation conditions", a.ExploitationConditions)

	w("## Citation presence check\n\n")
	w("_Each path the answer cited is checked for presence inside the snapshot. " +
		"Finding a path does not confirm the claim the agent made about it._\n\n")
	w("- paths found: %d\n- paths not found: %d\n\n",
		a.PresenceSummary.PathsFound, a.PresenceSummary.PathsNotFound)

	writeGrounded(&b, r)
	writePathClaims(&b, r)
	w("## Confirmed facts\n\n")
	w("_Host-produced and verifiable against the listed reference — no agent claim is promoted here. "+
		"Every fact is bound to attempt `%s` and snapshot hash `%s`._\n\n", r.RunID, r.Snapshot.ContentHash)
	for _, f := range a.ConfirmedFacts {
		w("- %s — %s (`%s`)\n", f.Statement, f.Reference, f.Source)
	}
	if len(a.ConfirmedFacts) == 0 {
		w("- none\n")
	}
	w("\n## Assumptions\n\n")
	writeExtractionList(&b, a.Assumptions, "statements the agent made that are not backed by a host-verified check")
	w("\n## Unknowns\n\n")
	writeExtractionList(&b, a.Unknowns, "gaps, unreadable inputs and open questions")

	w("\n## Agent reasoning (verbatim)\n\n")
	if a.Reasoning != "" {
		w("%s\n\n", a.Reasoning)
	} else {
		w("_No agent reasoning captured._\n\n")
	}

	w("## Artifacts\n\n")
	keys := make([]string, 0, len(r.Artifacts))
	for name := range r.Artifacts {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		w("- %s: `%s`\n", name, r.Artifacts[name])
	}
	if r.Answer.RawPath != "" {
		w("- raw agent answer: `%s`\n", r.Answer.RawPath)
	}
	w("- audit trail: `audit.json`\n")
	w("\n---\n%s\n%s\n", r.Disclaimer, safeCategoryDisclaimer)
	return b.String()
}

// writeSummary renders the substantive top block: mechanism, what the
// host found in this product, what is confirmed, what the agent claims
// unverified, the unknowns that could change the conclusion (critical
// first — those a host fact can decide), and concrete checks. It never
// paraphrases the agent's reasoning — it summarises the report's own
// records.
func writeSummary(b *strings.Builder, r *Report) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	a := r.Analysis
	cr := r.Consistency

	w("## Summary\n\n")

	// The mechanism shown to the reader is the advisory's own description —
	// the reference; the agent's mechanism text is a claim shown verbatim
	// in the Mechanism section, never substituted for the reference.
	if am := a.AdvisoryMechanism; am != nil && (am.Summary != "" || am.DetailsExcerpt != "") {
		w("- **Vulnerability mechanism (advisory).** %s\n", orSummary(am.Summary))
		if am.DetailsExcerpt != "" {
			w("  - details (%s): %s", am.Source, am.DetailsExcerpt)
			if am.DetailsCut {
				w(" …")
			}
			w("\n")
		}
	} else {
		w("- **Vulnerability mechanism (advisory).** _not established — no resolved advisory text_\n")
	}

	w("- **Found in this product.** ")
	switch {
	case cr.State != "assessed":
		w("not assessed — %s.\n", orReason(cr.Reason, "no advisory document was resolved"))
	case len(cr.Entries) == 0:
		w("the advisory lists no affected entries to check against.\n")
	default:
		w("\n")
		for _, e := range cr.Entries {
			w("  - %s\n", e.Statement)
		}
		w("  - these presence/version statuses are host facts about the installed version only — they do not establish, refute or substitute the agent's category\n")
	}

	w("- **Confirmed by host facts.**\n")
	w("  - snapshot identity verified: commit `%s`, content hash `%s`\n",
		r.Snapshot.Commit, shortHash(r.Snapshot.ContentHash))
	if r.Advisory.Status == "resolved" {
		w("  - advisory `%s` resolved, sha256 `%s`, stored at `%s`\n",
			r.Advisory.ID, shortHash(r.Advisory.SHA256), relDisplay(r.Advisory.Path))
	} else {
		w("  - no advisory resolved: %s\n", orReason(r.Advisory.Reason, "status "+r.Advisory.Status))
	}
	for _, e := range cr.Entries {
		switch e.Presence {
		case "present":
			w("  - module `%s` is present at `%s` (%s)", moduleLabel(e.Module), orNone2(e.ResolvedVersion), e.Evidence)
			switch e.RangeStatus {
			case "in_range":
				w(" — inside the advisory range\n")
			case "out_of_range":
				w(" — outside the advisory range\n")
			default:
				w(" — range check unverifiable\n")
			}
		case "absent_from_graph":
			w("  - module `%s` is not in the snapshot's module graph (%s) — **absence is not proof that no exploitation path exists**\n",
				moduleLabel(e.Module), e.Evidence)
		default:
			w("  - presence of module `%s` is undetermined (%s)\n", moduleLabel(e.Module), e.Evidence)
		}
	}

	w("- **Agent claims — unverified.** ")
	if r.Answer.Parsed {
		w("category `%s` (research judgement); %d affected-implementation, %d usage-path and %d exploitation-condition claims; %d cited paths found, %d not found.\n",
			r.Answer.Category,
			len(a.AffectedImplementations), len(a.UsagePaths), len(a.ExploitationConditions),
			a.PresenceSummary.PathsFound, a.PresenceSummary.PathsNotFound)
	} else {
		w("no parseable answer — nothing the agent may have claimed is on record (%s).\n",
			orReason(r.Answer.ParseError, "run status "+r.Run.Status))
	}
	if r.Answer.Parsed && safeCategories[r.Answer.Category] {
		w("  - the non-vulnerable category `%s` is a research judgement, not an established safety result — the host does not treat the advisory's affected list as exhaustive, and not finding a path is not proof that no exploitation path exists\n",
			r.Answer.Category)
	}
	for _, f := range cr.Findings {
		w("  - [%s] %s\n", f.Kind, f.Statement)
	}

	critical, secondary := splitUnknowns(r)
	w("- **Critical unknowns** (a host fact can decide these):\n")
	if len(critical) == 0 {
		w("  - none recorded\n")
	}
	for _, u := range critical {
		w("  - %s\n", u)
	}
	w("- **Secondary unknowns** (not assessed by host facts):\n")
	if len(secondary) == 0 {
		w("  - none recorded\n")
	}
	for _, u := range secondary {
		w("  - %s\n", u)
	}

	w("- **What to check or fix.**\n")
	for _, act := range recommendedActions(r) {
		w("  - %s\n", act)
	}
	w("\n> %s\n\n", safeCategoryDisclaimer)
}

// splitUnknowns separates the unknowns a host fact can decide (presence
// or version of an affected module, presence of a cited path) from
// everything the host never assessed.
func splitUnknowns(r *Report) (critical, secondary []string) {
	for _, e := range r.Consistency.Entries {
		switch {
		case e.Presence == "unknown" && e.Module == "":
			critical = append(critical,
				"whether the advisory's affected entries outside the Go module view affect the product — they declare no Go module name and cannot be checked against the graph ("+e.Evidence+")")
		case e.Presence == "unknown":
			critical = append(critical, fmt.Sprintf(
				"whether affected module `%s` is part of the product — no module-graph source could establish it (%s)",
				moduleLabel(e.Module), e.Evidence))
		case e.Presence == "absent_from_graph":
			critical = append(critical, fmt.Sprintf(
				"whether affected module `%s` truly reaches the product — it is absent from the file-level graph, which is not proof of absence",
				moduleLabel(e.Module)))
		case e.RangeStatus == "unverifiable" && e.Presence == "present":
			critical = append(critical, fmt.Sprintf(
				"whether `%s` (%s) is inside the advisory range — the version is undecidable from the graph (%s)",
				moduleLabel(e.Module), orNone2(e.ResolvedVersion), e.Evidence))
		}
	}
	seen := map[string]bool{}
	for _, claims := range [][]Claim{r.Analysis.AffectedImplementations, r.Analysis.UsagePaths, r.Analysis.ExploitationConditions} {
		for _, c := range claims {
			for _, p := range c.PathsNotFound {
				path, status := p, "absent"
				if i := strings.LastIndex(p, " ("); i >= 0 {
					path, status = p[:i], strings.TrimSuffix(p[i+2:], ")")
				}
				if seen[path] {
					continue
				}
				seen[path] = true
				critical = append(critical,
					"whether the claim citing `"+path+"` holds — the cited path is "+status+" in the snapshot, so the citation is unchecked")
			}
		}
	}
	secondary = append(secondary, r.Analysis.Unknowns.Items...)
	return critical, secondary
}

// recommendedActions derives the concrete check list from the consistency
// entries, findings and run state.
func recommendedActions(r *Report) []string {
	var acts []string
	if r.ResearchState == "incomplete" {
		acts = append(acts, fmt.Sprintf("the agent run ended `%s` (%s) — inspect `%s` and the audit trail before relying on any part of this report",
			r.Run.Status, orReason(r.Run.Error, r.Run.Reason), orReason(r.Answer.RawPath, "the run artifacts")))
	}
	for _, e := range r.Consistency.Entries {
		switch {
		case e.Presence == "present" && e.RangeStatus == "in_range":
			acts = append(acts, fmt.Sprintf("verify the claimed protection or reachability for `%s` at `%s` — presence inside the advisory range is established, everything beyond that is the agent's judgement",
				e.Module, e.ResolvedVersion))
		case e.Presence == "present" && e.RangeStatus == "out_of_range":
			acts = append(acts, fmt.Sprintf("confirm `%s` at `%s` is the version actually shipped; if so the advisory range does not cover it",
				e.Module, e.ResolvedVersion))
		case e.Presence != "present" || e.RangeStatus == "unverifiable":
			acts = append(acts, fmt.Sprintf("establish whether `%s` reaches the product and at what version (build manifest, lockfile, vendor tree) — the file-level module graph could not",
				moduleLabel(e.Module)))
		}
	}
	for _, f := range r.Consistency.Findings {
		switch f.Kind {
		case "category_absence_tension":
			acts = append(acts, "resolve the recorded scope tension: confirm whether the affected code is absent at package/import level — the host sees the module present but cannot check narrower scopes")
		case "reachability_not_established":
			acts = append(acts, "settle the reachability and exploitation-condition status — it stays UNKNOWN; module presence/version cannot decide it")
		case "mechanism_alignment_not_established":
			acts = append(acts, "check whether the agent's mechanism text actually describes the advisory's affected module/package before relying on it")
		case "coverage_incomplete":
			acts = append(acts, "assess every advisory affected entry the answer never named — coverage is incomplete")
		case "version_mismatch":
			acts = append(acts, "reconcile the fix version the answer asserts with the fixed versions the advisory declares")
		case "safe_category_unsupported":
			acts = append(acts, "treat the non-vulnerable category as unproven until the grounds listed in the finding are settled")
		}
	}
	if len(acts) == 0 {
		acts = append(acts, "no host-visible blocker — the agent's claims still need a human review; this report does not close anything")
	}
	return acts
}

// writeConsistency renders the host-fact consistency section: per affected
// entry the presence/version/range status with its evidence, the explicit
// findings, and the standing caveat that absence proves nothing.
func writeConsistency(b *strings.Builder, r *Report) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	cr := r.Consistency
	w("## Host-fact consistency\n\n")
	w("_Each advisory affected entry is checked against the snapshot's module graph " +
		"(go.mod, vendor/modules.txt, go.sum). Presence and range statuses are facts " +
		"about the installed version only — they never establish, refute or substitute " +
		"the agent's category; findings record tensions and gaps, never verdicts._\n\n")
	if cr.State != "assessed" {
		w("- state: `not_assessed` — %s\n\n", orReason(cr.Reason, "no advisory document was resolved"))
		return
	}
	for _, e := range cr.Entries {
		w("- `%s`: **%s**", moduleLabel(e.Module), e.Presence)
		if e.ResolvedVersion != "" {
			w(" at `%s`", e.ResolvedVersion)
		}
		w(" (%s)", e.Evidence)
		if len(e.AdvisoryRanges) > 0 {
			w("; advisory range %s → **%s**", strings.Join(e.AdvisoryRanges, ", "), e.RangeStatus)
		}
		if e.DocumentID != "" && e.DocumentID != r.Advisory.ID {
			w(" [advisory %s]", e.DocumentID)
		}
		w("\n")
	}
	w("\n### Findings\n\n")
	if len(cr.Findings) == 0 {
		w("- none — no tension between the answer and the host facts was detected " +
			"(this absence of a detected tension does not establish that the answer is right)\n")
	}
	for _, f := range cr.Findings {
		w("- **%s** — %s _(evidence: %s)_\n", f.Kind, f.Statement, f.Evidence)
	}
	w("\n> %s\n\n", cr.Caveat)
}

// writeExtractionList renders one assumptions/unknowns block with its
// explicit extraction state — never a bare empty list pretending "none".
func writeExtractionList(b *strings.Builder, list ExtractionList, what string) {
	switch list.State {
	case "extracted":
		fmt.Fprintf(b, "_State: `extracted` — %d %s._\n\n", len(list.Items), what)
	case "not_established":
		fmt.Fprintf(b, "_State: `not_established` — the parsed answer yielded no such items; their absence is recorded as not established, not as none existing. %s._\n\n", what)
	default:
		fmt.Fprintf(b, "_State: `not_assessed` — the agent answer could not be assessed for %s (unavailable or unparseable)._\n\n", what)
	}
	for _, s := range list.Items {
		fmt.Fprintf(b, "- %s\n", s)
	}
	if len(list.Items) == 0 {
		fmt.Fprintf(b, "- none recorded\n")
	}
}

// advisoryAffectedModules rebuilds the advisory's affected module set
// from the recorded advisory block — used by the mechanism alignment
// note in the rendered report.
func advisoryAffectedModules(r *Report) []pbdomain.AffectedModule {
	var out []pbdomain.AffectedModule
	for _, e := range r.Advisory.Affected {
		am := pbdomain.AffectedModule{Module: e.Module}
		for _, p := range e.Packages {
			am.AffectedPackages = append(am.AffectedPackages, pbdomain.AffectedPackage{Path: p})
		}
		out = append(out, am)
	}
	return out
}

// writeMechanism renders the mechanism section: the advisory's own
// mechanism as the reference (summary + bounded details excerpt), the
// agent's mechanism text verbatim as a claim, and the bounded lexical
// alignment note — no semantic verification.
func writeMechanism(b *strings.Builder, r *Report) {
	fmt.Fprintf(b, "## Mechanism\n\n")
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }

	if am := r.Analysis.AdvisoryMechanism; am != nil && (am.Summary != "" || am.DetailsExcerpt != "") {
		w("**Advisory reference** (%s)\n\n", am.Source)
		if am.Summary != "" {
			w("> %s\n\n", am.Summary)
		}
		if am.DetailsExcerpt != "" {
			w("> %s", am.DetailsExcerpt)
			if am.DetailsCut {
				w(" …")
			}
			w("\n\n")
		}
	} else {
		w("_No resolved advisory text — the mechanism reference is absent._\n\n")
	}

	w("**Agent's mechanism claim** (verbatim — a claim, not a reference)\n\n")
	w("%s\n\n", orNone(r.Analysis.Mechanism))

	if r.Answer.Parsed {
		switch {
		case len(advisoryAffectedModules(r)) == 0:
			w("_No comparable Go affected entries in the advisory — lexical alignment is not applicable._\n\n")
		case r.Analysis.Mechanism == "":
			w("_`mechanism_alignment_not_established`: the answer provides no mechanism description to compare with the advisory reference._\n\n")
		case mechanismNamesAffected(r.Analysis.Mechanism, advisoryAffectedModules(r)):
			w("_Lexical alignment: the mechanism text names an advisory-affected module/package — this is a name match only, not a semantic check._\n\n")
		default:
			w("_`mechanism_alignment_not_established`: the mechanism text does not name the advisory's affected module/package — it may describe a different component._\n\n")
		}
	}
}

// writePathClaims renders the extracted path polarity statements in
// their own section: absence/presence wording verbatim with the scope,
// path and symbol the grounder found. Context only — never a verdict and
// never a proof of absence.
func writePathClaims(b *strings.Builder, r *Report) {
	claims := r.Analysis.NegativeClaims
	if len(claims) == 0 {
		return
	}
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	w("## Path claims (negative / presence)\n\n")
	w("_Extracted verbatim from the agent's reasoning as context for negative " +
		"metrics. A claim is never a verdict, and an absence claim is never " +
		"proof that no path exists._\n\n")
	for _, c := range claims {
		line := fmt.Sprintf("- **%s** / `%s` — %s", c.Polarity, c.Scope, c.Raw)
		var extra []string
		if c.Path != "" {
			extra = append(extra, "path `"+c.Path+"`")
		}
		if c.Symbol != "" {
			extra = append(extra, "symbol `"+c.Symbol+"`")
		}
		if len(extra) > 0 {
			line += " (" + strings.Join(extra, ", ") + ")"
		}
		w("%s\n", line)
	}
	w("\n")
}

func writeClaims(b *strings.Builder, title string, claims []Claim) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(claims) == 0 {
		fmt.Fprintf(b, "_The answer provides no %s statements._\n\n", strings.ToLower(title))
		return
	}
	for _, c := range claims {
		fmt.Fprintf(b, "- %s\n", c.Text)
		for _, p := range c.PathsFound {
			fmt.Fprintf(b, "  - path: `%s` (present in snapshot)\n", p)
		}
		for _, p := range c.PathsNotFound {
			fmt.Fprintf(b, "  - path: `%s`\n", p)
		}
	}
	b.WriteString("\n")
}

// writeGrounded renders the deterministic grounding section: every
// location claim with its verification status and reason, then the
// mechanism atoms checked against the frozen advisory symbols. The
// section appears only when grounding produced claims — a report with no
// extracted locations or atoms keeps its legacy layout.
func writeGrounded(b *strings.Builder, r *Report) {
	a := r.Analysis
	if len(a.RootCauseLocations) == 0 && len(a.UsageSites) == 0 &&
		len(a.CitationMetadata) == 0 && len(a.MechanismAtoms) == 0 {
		return
	}
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	w("## Citation grounding\n\n")
	w("_Each claim is checked against the snapshot tree: a verified status means " +
		"the cited file/symbol resolves — it does not confirm what the agent said " +
		"about it. Claims are shown verbatim, never rewritten._\n\n")

	render := func(title string, locs []reportcheck.Location) {
		w("### %s\n\n", title)
		if len(locs) == 0 {
			w("- none\n\n")
			return
		}
		for _, l := range locs {
			w("- `%s`", l.Raw)
			var bits []string
			if l.Path != "" {
				ref := l.Path
				if l.Line > 0 {
					ref = fmt.Sprintf("%s:%d", l.Path, l.Line)
					if l.EndLine != l.Line {
						ref = fmt.Sprintf("%s-%d", ref, l.EndLine)
					}
				}
				bits = append(bits, "→ `"+ref+"`")
			}
			if l.EnclosingSymbol != "" {
				bits = append(bits, "in `"+l.EnclosingSymbol+"`")
			}
			bits = append(bits, "**"+l.Status+"**")
			if l.Kind != "locus" {
				bits = append(bits, "kind `"+l.Kind+"`")
			}
			bits = append(bits, "— "+l.Reason)
			w(" %s\n", strings.Join(bits, " "))
		}
		w("\n")
	}
	render("Root cause locations", a.RootCauseLocations)
	render("Usage sites", a.UsageSites)
	render("Metadata / import citations (presence only — never a locus or usage site)", a.CitationMetadata)

	if len(a.MechanismAtoms) > 0 {
		w("### Mechanism atoms\n\n")
		for _, at := range a.MechanismAtoms {
			name := at.Symbol
			if name == "" {
				name = at.Key
			}
			w("- `%s` → `%s` **%s**\n", at.Raw, name, at.Status)
		}
		w("\n")
	}
}

// orSummary renders an advisory summary; empty means the document
// carried none.
func orSummary(s string) string {
	if strings.TrimSpace(s) == "" {
		return "_the advisory carries no summary_"
	}
	return s
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "_Not provided by the agent answer._"
	}
	return s
}

func orReason(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	if s == "" {
		return "—"
	}
	return s
}

// shortHash shortens a hex hash for inline display (same as shortSHA but
// tolerant of the t1: style prefixes used in content hashes).
func shortHash(s string) string {
	return shortSHA(s)
}

// moduleLabel renders an advisory module name; an empty name is labelled
// as unnamed rather than rendered as a blank.
func moduleLabel(mod string) string {
	if mod == "" {
		return "(unnamed — no Go package in the advisory entry)"
	}
	return mod
}
