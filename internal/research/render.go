package research

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/flow"
)

// RenderJSON serializes the report as canonical indented JSON. The byte
// stream is stable for a given report.
func RenderJSON(r *Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// RenderMarkdown renders report.md purely from the assembled report
// object — no model calls, no independent inference. Rendering the same
// report twice produces byte-identical output. The Slice-2 layout (§4)
// leads with the operator summary; every audit table lives in the
// appendix. Counts of facts/conditions/questions are never rendered as
// a quality signal.
func RenderMarkdown(r *Report) ([]byte, error) {
	var b bytes.Buffer
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	pa := r.ProductApplicability
	// /3 render features (evidence-level block, appendix role) are gated
	// on the advertised marker, never on member presence: a /1 or /2
	// report carrying inert /3 members renders byte-identically to one
	// without them.
	isV3 := false
	for _, ext := range r.ContractExtensions {
		if ext == Slice2ExtensionV3 {
			isV3 = true
			break
		}
	}

	// ================= operator front matter =================
	w("# Research report — %s", r.Vulnerability.ID)
	w("")
	w("> **EXPERIMENTAL — REVIEW REQUIRED.** This report supports human triage only.")
	w("")

	// ---- Резюме (обязательный русский раздел во главе отчёта) ----
	w("## Резюме")
	w("")
	moduleLine := map[string]string{
		"TRUE":  "присутствует в resolved module graph",
		"FALSE": "отсутствует в resolved module graph (проверено по записанному контексту сборки)",
	}[pa.ModulePresent]
	if moduleLine == "" {
		moduleLine = "не определено (проверка не разрешила присутствие)"
	}
	modLabel := ""
	if pa.SelectedModule != nil {
		modLabel = *pa.SelectedModule
	}
	if modLabel == "" {
		for _, im := range r.AffectedImplementations {
			if im.Ecosystem == "Go" && implSelected(im, pa) {
				modLabel = implModule(im)
				break
			}
		}
	}
	if modLabel == "" {
		modLabel = "affected module"
	}
	w("- **Присутствие модуля:** `%s` — %s.", modLabel, moduleLine)
	entryLine := pa.AdvisoryEntryStatus
	if entryLine == "" {
		entryLine = "не указан (отчёт без slice2-fidelity/2)"
	} else {
		switch entryLine {
		case EntryFixed:
			entryLine = "FIXED — разрешённая версия вне уязвимых диапазонов каждой оценённой записи (ограничено оценёнными записями, не всеми реализациями CVE)"
		case EntryAffected:
			entryLine = "AFFECTED — разрешённая версия внутри уязвимых диапазонов оценённой записи"
		case EntryNotEvaluated:
			entryLine = "NOT_EVALUATED — статус исправления по записям advisory не оценивался"
		case EntryMixed:
			entryLine = "MIXED — оценённые записи имеют разные статусы (fixed/affected/unknown)"
		default:
			entryLine += " — статус записей не определён"
		}
	}
	evalLabel := "не указаны (отчёт без slice2-fidelity/2)"
	if pa.EvaluatedEntryIDs != nil {
		if len(pa.EvaluatedEntryIDs) == 0 {
			evalLabel = "нет (ни одна запись не проверялась)"
		} else {
			evalLabel = "`" + strings.Join(pa.EvaluatedEntryIDs, "`, `") + "`"
		}
	}
	w("- **Оценённые записи advisory:** %s; статус исправления: **%s**.", evalLabel, entryLine)
	vcrLine := map[string]string{
		VCRTrue:         "подтверждена: уязвимый пакет входит в замыкание импорта и релевантен сборке (по записанному контексту)",
		VCRFalse:        "опровергнута детерминистически (см. basis с verified refs)",
		VCRNotEvaluated: "не оценивалась (probe не запускался — см. advisory_entry_status)",
	}[pa.VulnerableCodeReachability]
	if vcrLine == "" {
		if pa.VulnerableCodeReachability == "" {
			vcrLine = "не указана (отчёт без slice2-fidelity/2)"
		} else {
			vcrLine = "не определена — probe выполнялся, но не решил вопрос"
		}
	}
	w("- **Достижимость уязвимого кода:** %s.", vcrLine)
	w("- **Область применимости:** conclusion_scope=`%s`, advisory_scope_status=`%s`.", pa.ConclusionScope, pa.AdvisoryScopeStatus)
	var blockers []string
	for _, u := range r.Unknowns {
		if u.Priority == UnknownPriorityDecisionChanging {
			blockers = append(blockers, u.ID+": "+u.Statement)
		}
	}
	for _, bs := range pa.Basis {
		if bs.Status == ABProvisional {
			blockers = append(blockers, "basis `"+bs.Kind+"` (PROVISIONAL/agent): "+bs.Statement)
		}
	}
	if len(blockers) > 0 {
		w("- **Оставшиеся препятствия для триажа:**")
		for _, bl := range blockers {
			w("  - %s", bl)
		}
	} else {
		w("- **Оставшиеся препятствия для триажа:** не записаны.")
	}
	w("")
	if r.Decision != nil && (r.Schema == ReportSchemaV2 || r.Schema == ReportSchemaV3 || r.Schema == ReportSchemaV4) {
		renderDecision(&b, r)
	}
	if (r.Schema == ReportSchemaV3 || r.Schema == ReportSchemaV4) && r.DecisionArtifact != nil {
		renderDecisionArtifact(&b, r)
	}
	if (r.Schema == ReportSchemaV4 || r.Schema == ReportSchemaV5) && r.RequestComposition != nil {
		renderRequestComposition(&b, r)
		if r.Schema == ReportSchemaV5 && r.Decision != nil {
			w("## Record-bound evidence detail")
			w("")
			w("The following decision is detail for the primary record, not an alternative answer to the requested finding above.")
			w("")
			renderDecision(&b, r)
		}
	}

	// ---- 1. CVE essence and mechanism ----
	w("## CVE essence and mechanism")
	w("")
	if r.Vulnerability.Summary != "" {
		w("**%s**", r.Vulnerability.Summary)
		w("")
	}
	if len(r.Vulnerability.Aliases) > 0 {
		w("- aliases: %s", strings.Join(r.Vulnerability.Aliases, ", "))
	}
	if d := singleLine(r.Vulnerability.Description); d != "" {
		w("- mechanism: %s", firstN(d, 900))
	}
	if r.VulnerabilityMechanism.Summary != "" {
		w("- assessed mechanism (%s): %s", r.VulnerabilityMechanism.Status, firstN(r.VulnerabilityMechanism.Summary, 400))
	}
	for _, c := range r.VulnerabilityMechanism.Claims {
		if c.Origin == OriginDeterm {
			w("- [deterministic] %s", c.Statement)
		}
	}
	w("")

	// ---- 2. What was actually found in the product ----
	w("## What was actually found in the product")
	w("")
	w("- applicability chain (%s): module_present=%s version_affected=%s package_present=%s build_relevant=%s",
		pa.Status, pa.ModulePresent, pa.VersionAffected, pa.PackagePresent, pa.BuildRelevant)
	if pa.VulnerableImplementationPresent != "" {
		w("- implementation axis: vulnerable_implementation_present=%s target_scope=%s target=%s",
			pa.VulnerableImplementationPresent, strOrZero(pa.ImplementationTargetScope, "unknown"), strOrZero(pa.ImplementationTarget, "unknown"))
		if pa.ImplementationLocus != "" {
			w("  - verified locus: %s", pa.ImplementationLocus)
		}
		if len(pa.AssumptionIDs) > 0 {
			w("  - assumption refs (policy/scope inputs, not evidence): %s", strings.Join(pa.AssumptionIDs, ", "))
		}
	}
	if r.Input.Snapshot.Target != nil {
		t := r.Input.Snapshot.Target
		w("- build target provenance: source=%s scope=%s platform=%s/%s tags=[%s] cgo=%v",
			t.Source, strOrZero(t.Scope, "none"), t.GOOS, t.GOARCH, strings.Join(t.BuildTags, ","), t.CGOEnabled)
	}
	if pa.VersionAxisBlocked {
		w("- **version axis blocked** (`%s`): the ticket declares a different package version than the analyzed build resolved — the out-of-range negative is refused, not refuted", pa.VersionAxisBlockReason)
		// The refusal must be actionable: name the distribution the
		// ticket itself identifies (recorded, never fetched) and the
		// explicit rerun channel. The source snapshot can never answer
		// the ticket's declared package version.
		loc := ""
		if r.Input.Ticket != nil {
			loc = r.Input.Ticket.DistributionURL
		}
		if loc != "" {
			w("- ticket distribution locator (recorded, not fetched): `%s` — next action: provide/acquire the exact ticket distribution, then rerun with `--artifact` or `--artifact-url`", loc)
		} else {
			w("- next action: provide/acquire the exact ticket distribution named by the ticket, then rerun with `--artifact` or `--artifact-url`")
		}
	}
	if tc := pa.TicketCheck; tc != nil {
		if tc.PackageVersionCheck != "" && tc.PackageVersionCheck != domain.TicketCheckNotChecked {
			w("- ticket package check: `%s` — declared `%s` vs resolved `%s`",
				tc.PackageVersionCheck, strOr(&tc.DeclaredVersion, "-"), strOr(&tc.ResolvedVersion, "-"))
		}
		if tc.ProductVersionCheck != "" && tc.ProductVersionCheck != domain.TicketCheckNotChecked {
			w("- ticket product check: `%s` — declared `%s` vs analyzed `%s`",
				tc.ProductVersionCheck, strOr(&tc.DeclaredProduct, "-"), strOr(&tc.AnalyzedProduct, "-"))
		}
	}
	if pa.AdvisoryEntryStatus != "" || pa.VulnerableCodeReachability != "" {
		w("- advisory entry status: `%s` | vulnerable code reachability: `%s`",
			strOr(&pa.AdvisoryEntryStatus, "-"), strOr(&pa.VulnerableCodeReachability, "-"))
	}
	if pa.ResolvedVersion != nil {
		w("- resolved version: `%s`", *pa.ResolvedVersion)
	}
	w("- conclusion scope: `%s` | advisory scope: `%s`", pa.ConclusionScope, pa.AdvisoryScopeStatus)
	for _, c := range r.ProductExposure.Claims {
		if c.Origin == OriginDeterm {
			w("- [deterministic] %s", c.Statement)
		}
	}
	for _, c := range r.RootCause.Claims {
		if c.Origin == OriginDeterm {
			w("- [deterministic] %s", c.Statement)
		}
	}
	for _, as := range r.AgentAssertions {
		if strings.HasPrefix(as.Statement, "category=") {
			continue
		}
		w("- [agent-only, unverified] %s", firstN(as.Statement, 300))
	}
	w("")

	// ---- 3. Affected, fixed, and unverified implementations ----
	w("## Affected, fixed, and unverified implementations")
	w("")
	if pa.AdvisoryEntryStatus != "" {
		ids := "-"
		if len(pa.EvaluatedEntryIDs) > 0 {
			ids = "`" + strings.Join(pa.EvaluatedEntryIDs, "`, `") + "`"
		}
		w("Evaluated advisory entries: %s — status `%s`.", ids, pa.AdvisoryEntryStatus)
		w("")
	}
	for _, im := range r.AffectedImplementations {
		label := "unverified"
		if st := entryStatus(im, pa); st != "" {
			label = st
		}
		w("- `%s` **%s** `%s` — **%s** (binding=`%s`, scope: advisory entry)",
			im.ID, implModule(im), im.Ecosystem, label, im.Binding)
		if im.Package != nil {
			w("  - package: `%s`", *im.Package)
		}
		if len(im.Symbols) > 0 {
			w("  - symbols: `%s`", strings.Join(im.Symbols, "`, `"))
		}
		for _, v := range im.AffectedVersions {
			w("  - range: introduced=%s fixed=%s last_affected=%s",
				strOr(v.Introduced, "-"), strOr(v.Fixed, "-"), strOr(v.LastAffected, "-"))
		}
	}
	w("")

	// ---- Implementation-locus proposals (agent, non-authoritative) ----
	// Retained verbatim from the agent answer. They are hypotheses only:
	// no deterministic verifier result is rendered here, and nothing in
	// this block may be read as an implementation-presence fact.
	if len(r.ImplementationLocusProposals) > 0 {
		w("## Implementation-locus proposals (LLM-inferred, non-authoritative)")
		w("")
		w("These are agent hypotheses retained for audit and deterministic verification. They are not evidence, not a verdict, and cannot establish implementation presence or absence by themselves.")
		w("")
		for _, p := range r.ImplementationLocusProposals {
			w("- `%s` — module `%s` version `%s`, package `%s`", p.ID, p.Module, p.Version, p.Package)
			expr := p.BuildExpression
			if expr == "" {
				expr = "(none)"
			}
			fn := p.Function
			if fn == "" {
				fn = "(binding locus — file declares no functions)"
			}
			w("  - file `%s`; function `%s`; marker `%s`; build expression `%s`", p.File, fn, p.Marker, expr)
			if len(p.GOOS) > 0 || len(p.GOARCH) > 0 {
				w("  - advisory platforms: goos `%s`, goarch `%s`",
					strings.Join(p.GOOS, "`, `"), strings.Join(p.GOARCH, "`, `"))
			}
			w("  - advisory ref `%s`; quoted span: \"%s\"", p.AdvisoryEvidenceRef, firstN(p.AdvisoryQuotedSpan, 240))
		}
		w("")
	}

	// ---- Evidence level (slice2-fidelity/3) ----
	// The derived ladder renders as its own block before the
	// exploitation axes; the renderer only displays the stored
	// EvidenceLevel and never recomputes it. Legacy /1 and /2 reports
	// carry no evidence_level, so the block is skipped entirely and
	// their rendering path stays byte-compatible.
	if isV3 {
		renderEvidenceLevel(&b, r.EvidenceLevel)
	}

	// ---- 4. Exploitation conditions — established vs unknown ----
	w("## Exploitation conditions — established vs unknown")
	w("")
	axes := []struct {
		name string
		ax   Axis
	}{
		{"code reachability", r.ExploitationAxes.CodeReachability},
		{"attack-surface availability", r.ExploitationAxes.AttackSurfaceAvailability},
		{"proven attacker exploitability", r.ExploitationAxes.ExploitationEstablished},
	}
	if isV3 && r.ExploitationAxes.BuildUsageScope != nil {
		axes = append(axes, struct {
			name string
			ax   Axis
		}{"build-closure usage scope", *r.ExploitationAxes.BuildUsageScope})
	}
	for _, a := range axes {
		w("- **%s:** **%s** (level `%s`, basis `%s`) — %s",
			a.name, a.ax.Status, a.ax.Level, a.ax.Basis, a.ax.Statement)
		for _, lim := range a.ax.Limitations {
			w("  - limit: %s", lim)
		}
	}
	// Three-valued transition semantics (slice2-fidelity/2, kept under
	// /3): confirmed deterministic facts, bounded refutations, agent
	// hypotheses (never confirming, even when a canonical path hypothesis
	// carries role=path), unknown conditions and conflicted/retracted
	// states are rendered as separate groups; an unproven transition
	// never displays as an established exploit path. Under /3 a REFUTED
	// deterministic condition gets its own group: it is a bounded path
	// refutation inside the recorded scope — never a «product is safe»
	// result — and its bounded-negative limitations render with the row.
	// The /3 role itself is shown only in the appendix listing of full
	// conditions.
	var confirmed, refuted, hypotheses, unknowns, other []ExploitationCondition
	for _, c := range r.ExploitationConditions {
		switch {
		case c.Origin == OriginDeterm && isV3 && c.State == StateRefuted:
			refuted = append(refuted, c)
		case c.Origin == OriginDeterm && (c.State == StateSupported || c.State == StateRefuted):
			confirmed = append(confirmed, c)
		case c.Origin == OriginAgent:
			hypotheses = append(hypotheses, c)
		case c.Origin == OriginDeterm && c.State == StateUnknown:
			unknowns = append(unknowns, c)
		default:
			other = append(other, c)
		}
	}
	if len(confirmed) > 0 {
		w("- **Подтверждённые факты:**")
		for _, c := range confirmed {
			w("  - `%s` [%s] %s", c.ID, c.State, c.Statement)
		}
	}
	if len(refuted) > 0 {
		w("- **REFUTED — опровергнуто в записанной области (bounded path refutation; не вывод о безопасности продукта):**")
		for _, c := range refuted {
			w("  - `%s` [%s] %s", c.ID, c.State, c.Statement)
			for _, lim := range c.Limitations {
				w("    - limit: %s", lim)
			}
		}
	}
	if len(hypotheses) > 0 {
		w("- **Гипотезы агента (PROVISIONAL — не подтверждают exploit path):**")
		for _, c := range hypotheses {
			w("  - `%s` [%s] %s", c.ID, c.State, c.Statement)
		}
	}
	if len(unknowns) > 0 {
		w("- **Неизвестные условия:**")
		for _, c := range unknowns {
			w("  - `%s` %s", c.ID, c.Statement)
			if isV3 {
				for _, lim := range c.Limitations {
					w("    - limit: %s", lim)
				}
			}
		}
	}
	if len(other) > 0 {
		w("- **Прочие состояния (conflicted/retracted):**")
		for _, c := range other {
			w("  - `%s` [%s/%s] %s", c.ID, c.Origin, c.State, c.Statement)
		}
	}
	w("")

	// ---- 5. Main justification ----
	w("## Main justification")
	w("")
	crev := r.ClassificationReview
	if crev.OriginalCategory != nil {
		w("- preserved agent category: `%s` (never rewritten)", *crev.OriginalCategory)
	}
	w("- classification review: class `%s`, status **%s**", crev.Class, crev.Status)
	for _, lim := range crev.Limitations {
		w("  - limit: %s", lim)
	}
	for _, bs := range pa.Basis {
		scope := ""
		if bs.CheckScope != "" {
			scope = " — scope: " + bs.CheckScope
		}
		refs := dedupe(append(append([]string{}, bs.VerifiedEvidenceRefs...), bs.EvidenceRefs...))
		w("- basis `%s` [%s/%s]: %s%s — refs: %s",
			bs.Kind, bs.Status, bs.Source, bs.Statement, scope,
			strings.Join(refs, ", "))
	}
	if len(crev.BasisRefs) > 0 {
		w("- evidence chain: %s", strings.Join(crev.BasisRefs, ", "))
	}
	w("")

	// ---- 6. Recommendation — what to check or fix next ----
	w("## Recommendation — what to check or fix next")
	w("")
	w("- triage action: **%s** — %s", r.TriageRecommendation.Action, r.TriageRecommendation.Reason)
	w("- bounds: %s", r.TriageRecommendation.Bounds)
	for _, rec := range r.Recommendations {
		w("- `%s` (%s) %s", rec.ID, rec.Owner, rec.Action)
	}
	w("")

	// ---- 7. Decision-changing unknowns ----
	w("## Decision-changing unknowns")
	w("")
	dc := 0
	for _, u := range r.Unknowns {
		if u.Priority != UnknownPriorityDecisionChanging {
			continue
		}
		dc++
		w("- `%s` %s", u.ID, u.Statement)
		w("  - could flip: %s", strOr(u.DecisionChangingFor, "?"))
		w("  - follow-up: %s", u.FollowUp)
	}
	if dc == 0 {
		w("_None — every recorded unknown is appendix-only._")
	}
	w("")

	// ================= audit sections =================
	// ---- 8. Scope, provenance, and disposition ----
	w("## Scope, provenance, and disposition")
	w("")
	w("- run_id: `%s` | mode `%s` / schema `%s`", r.Run.RunID, r.Mode, r.Schema)
	w("- contract_extensions: `%s`", strings.Join(r.ContractExtensions, "`, `"))
	w("- started: %s — finished: %s | deterministic_only=%v",
		r.Run.StartedAt, r.Run.FinishedAt, r.Run.DeterministicOnly)
	w("- timeouts (ms): overall=%d deterministic=%d agent=%d",
		r.Run.Timeouts.OverallMs, r.Run.Timeouts.DeterministicMs, r.Run.Timeouts.AgentMs)
	if r.Run.Outcome != "" {
		outcome := r.Run.Outcome
		if r.Run.OutcomeReason != "" {
			outcome += " (" + r.Run.OutcomeReason + ")"
		}
		conservative := "REVIEW_REQUIRED"
		if r.DecisionArtifact != nil {
			conservative = string(r.DecisionArtifact.ProposedDisposition)
		}
		w("- run outcome: `%s` — the deterministic lane completed; the agent/planner path never ran; conservative disposition %s", outcome, conservative)
	}
	s := r.Input.Snapshot
	w("- snapshot: `%s` @ `%s` (content_hash `%s`)", s.Path, s.CommitSHA, s.ContentHash)
	w("- build context: %s/%s tags=[%s] vendor=%v",
		s.GOOS, s.GOARCH, strings.Join(s.BuildTags, ", "), s.VendorMode)
	// The toolchain axes are rendered as separate lines so no report can
	// be read as if the analysis environment, the go.mod language minimum
	// and the shipped release toolchain were the same fact.
	w("- analysis toolchain: `%s`", s.GoVersion)
	if s.MinimumGoVersion != nil {
		w("- minimum go.mod version: `%s` (language minimum, never the release toolchain)", *s.MinimumGoVersion)
	} else {
		w("- minimum go.mod version: `UNKNOWN` (not recorded)")
	}
	switch {
	case s.ReleaseGoVersion != nil:
		w("- release toolchain: `%s`", *s.ReleaseGoVersion)
	case s.ReleaseEvidence != nil:
		line := "- release toolchain: `UNKNOWN`"
		if s.ReleaseEvidence.Status != "" {
			line += " — `" + s.ReleaseEvidence.Status + "`"
			if s.ReleaseEvidence.ReasonCode != "" {
				line += " / " + s.ReleaseEvidence.ReasonCode
			}
			line += "; go.mod minimum and the analysis toolchain are not release evidence"
		}
		w("%s", line)
	default:
		w("- release toolchain: `UNKNOWN` — no authoritative release toolchain recorded; go.mod minimum and the analysis toolchain are not release evidence")
	}
	if s.ReleaseEvidence != nil {
		re := s.ReleaseEvidence
		line := "- release evidence: `" + re.Status + "`"
		if re.ReasonCode != "" {
			line += " (" + re.ReasonCode + ")"
		}
		if re.SelectedVersion != "" {
			line += " selected `" + re.SelectedVersion + "` (" + re.SelectedSource + "/" + re.SelectedTrust + ")"
		}
		if re.ArtifactSHA256 != "" {
			line += " artifact_sha256 `" + re.ArtifactSHA256 + "`"
		}
		w("%s", line)
	}
	// Which module graph grounded third-party presence/version: the
	// authoritative release graph when the shipped artifact/metadata
	// supplied one, otherwise the source/vendor fallback (explicitly
	// labelled as provenance, never release evidence).
	switch {
	case s.ReleaseEvidence == nil:
		w("- release module graph: `source-snapshot` fallback — no release module graph recorded; source/vendor module versions are provenance, not release evidence")
	case s.ReleaseEvidence.VersionGraphSource == "release-artifact":
		graph := "- release module graph: `" + s.ReleaseEvidence.VersionGraphSource + "`"
		if s.ReleaseEvidence.VersionGraphTrust != "" {
			graph += " trust `" + s.ReleaseEvidence.VersionGraphTrust + "`"
		}
		if s.ReleaseEvidence.ModuleCount > 0 {
			graph += fmt.Sprintf(" modules=%d", s.ReleaseEvidence.ModuleCount)
		}
		w("%s", graph)
	case s.ReleaseEvidence.VersionGraphSource == "unavailable":
		w("- release module graph: `unavailable` — a required release-evidence channel failed closed; source/vendor versions cannot substitute")
	default:
		w("- release module graph: `source-snapshot` fallback — source/vendor module versions are provenance, not release evidence")
	}
	if tm := r.Input.Ticket; tm != nil {
		line := "- ticket: `" + tm.Path + "`"
		if tm.SHA256 != "" {
			line += " sha256 `" + tm.SHA256 + "`"
		}
		if tm.ParseError != "" {
			line += " | parse failed: `" + tm.ParseError + "` — identity check NOT_CHECKED"
		} else if tm.Claims != nil {
			var claims []string
			if tm.Claims.Product != "" || tm.Claims.ProductVersion != "" {
				claims = append(claims, fmt.Sprintf("product `%s` version `%s`",
					strOr(&tm.Claims.Product, "-"), strOr(&tm.Claims.ProductVersion, "-")))
			}
			if tm.Claims.Component != "" {
				claims = append(claims, "component `"+tm.Claims.Component+"`")
			}
			if tm.Claims.Package != "" || tm.Claims.PackageVersion != "" {
				claims = append(claims, fmt.Sprintf("package `%s` version `%s`",
					strOr(&tm.Claims.Package, "-"), strOr(&tm.Claims.PackageVersion, "-")))
			}
			if len(tm.Claims.AdvisoryIDs) > 0 {
				claims = append(claims, "advisory_ids `"+strings.Join(tm.Claims.AdvisoryIDs, ", ")+"`")
			}
			if len(claims) > 0 {
				line += " | " + strings.Join(claims, " | ")
			} else {
				line += " | no claims declared"
			}
		}
		w("%s", line)
	}
	ad := r.Input.Advisory
	w("- advisory: %s from %s (`%s`)", ad.ResolvedID, ad.SourceKind, ad.SourcePath)
	w("- advisory sha256: raw `%s` canonical `%s`", ad.RawSHA256, ad.CanonicalSHA256)
	h := r.Run.Harness
	if h.Path != nil {
		w("- harness: `%s` @ `%s`", *h.Path, strOr(h.Commit, "?"))
	}
	if h.ImageSHA256 != nil {
		w("- image: `%s` (%s)", strOr(h.Image, ""), *h.ImageSHA256)
	}
	if h.PromptSHA256 != nil {
		w("- prompt: `%s` sha256 `%s`", strOr(h.PromptPath, "?"), *h.PromptSHA256)
	}
	w("- disposition: `%s` (auto_close=%v) — %s",
		r.Disposition.Class, r.Disposition.AutoClose, r.Disposition.Reason)
	w("- forbidden classes: `%s`", strings.Join(r.Disposition.ForbiddenClasses, "`, `"))
	w("")

	// ---- 8b. Declared assumptions: policy/scope inputs, not evidence ----
	// Rendered in its own section, outside the evidence dossier and the
	// data-flow audit: a human-owned assertion must never read as a
	// measured code fact, and its ids never resolve through evidence ids.
	if da := r.Input.DeclaredAssumptions; da != nil {
		w("## Declared assumptions — policy/scope inputs, not deterministic evidence")
		w("")
		w("These are operator-declared policy and scope inputs. They are not evidence: no assumption statement is a claim or a code fact, none becomes `EvidenceKind.CONFIGURATION`, and an assumption alone produces no verdict — it can only satisfy the policy prerequisite of a deterministic proof. Only this intake record (path, digests, ids) joins the deterministic record.")
		w("")
		line := "- document: `" + da.Path + "`"
		if da.Schema != "" {
			line += " schema `" + da.Schema + "`"
		}
		if da.SHA256 != "" {
			line += " sha256 `" + da.SHA256 + "`"
		}
		if da.ContentDigest != "" {
			line += " content_digest `" + da.ContentDigest + "`"
		}
		w("%s", line)
		if da.LoadError != "" {
			w("- intake failed closed: `%s` — every assumption-dependent gate stays unclosed; no policy fact was inferred", da.LoadError)
		}
		for _, a := range da.Assumptions {
			w("- `%s` [%s, scope `%s`] %s", a.ID, a.Kind, a.Scope, a.Statement)
			meta := "authority `" + a.Authority + "` | owner `" + a.Owner + "` | source `" + a.SourceRef + "`"
			if a.ValidFrom != "" {
				meta += " | valid_from `" + a.ValidFrom + "`"
			}
			meta += " | review_date `" + a.ReviewDate + "` | digest `" + a.Digest + "`"
			w("  - %s", meta)
			if a.Targets != nil {
				t := "  - targets: goos `" + strings.Join(a.Targets.GOOS, "`, `") + "`"
				if len(a.Targets.GOARCH) > 0 {
					t += " goarch `" + strings.Join(a.Targets.GOARCH, "`, `") + "`"
				}
				if len(a.Targets.BuildTags) > 0 {
					t += " build_tags `" + strings.Join(a.Targets.BuildTags, "`, `") + "`"
				}
				w("%s", t)
			}
		}
		w("")
	}

	// ---- 8c. Implementation-locus proposal channel: hypotheses only ----
	// Rendered in its own intake section for the same reason as the
	// assumptions document: the proposals are LLM-inferred inputs the
	// deterministic axis re-checked — never evidence and never a
	// verdict, and their ids never resolve through evidence ids.
	if pi := r.Input.ImplementationLocusProposals; pi != nil {
		w("## Implementation-locus proposal channel — hypothesis inputs, not deterministic evidence")
		w("")
		w("These are machine-generated implementation-locus hypotheses supplied through a typed input channel (an `implementation-locus-proposals/1` artifact or a replayed agent answer). They are not evidence, not a verdict: only the deterministic verifier's re-check of each proposal can establish implementation presence or absence, and only the intake record (source, digests, proposal ids) joins the deterministic record.")
		w("")
		line := "- source: `" + pi.Source + "`"
		if pi.Path != "" {
			line += " path `" + pi.Path + "`"
		}
		if pi.SHA256 != "" {
			line += " sha256 `" + pi.SHA256 + "`"
		}
		if pi.AdvisorySHA256 != "" {
			line += " advisory_sha256 `" + pi.AdvisorySHA256 + "`"
		}
		if pi.RetainedAnswerSHA256 != "" {
			line += " retained_answer_sha256 `" + pi.RetainedAnswerSHA256 + "`"
		}
		w("%s", line)
		if pi.LoadError != "" {
			w("- intake failed closed: `%s` — no proposal was admitted; the implementation axis stayed undecidable", pi.LoadError)
		}
		for _, p := range pi.Proposals {
			w("- `%s` — module `%s` version `%s`, package `%s`, file `%s`, function `%s`", p.ID, p.Module, p.Version, p.Package, p.File, p.Function)
		}
		w("")
	}

	// ---- 9. Applicability basis ----
	w("## Applicability basis")
	w("")
	if len(pa.Basis) == 0 {
		w("_No named basis recorded._")
	}
	for _, bs := range pa.Basis {
		w("- `%s` [%s/%s] %s", bs.Kind, bs.Status, bs.Source, bs.Statement)
		if bs.CheckScope != "" {
			w("  - check scope: %s", bs.CheckScope)
		}
		if len(bs.VerifiedEvidenceRefs) > 0 {
			w("  - verified refs: %s", strings.Join(bs.VerifiedEvidenceRefs, ", "))
		}
		if len(bs.EvidenceRefs) > 0 {
			w("  - refs: %s", strings.Join(bs.EvidenceRefs, ", "))
		}
		for _, lim := range bs.Limitations {
			w("  - limit: %s", lim)
		}
	}
	w("")

	// ---- 10. Contradictions and limitations ----
	w("## Contradictions and limitations")
	w("")
	if len(r.Contradictions) == 0 {
		w("_No contradictions recorded._")
	}
	for _, c := range r.Contradictions {
		w("- `%s` **%s** on `%s` — resolution `%s`", c.ID, c.Kind, c.Subject, c.Resolution)
		w("  - %s", c.Summary)
		if c.AgentAssertionRef != nil {
			w("  - agent ref: `%s`", *c.AgentAssertionRef)
		}
		if len(c.DeterministicRefs) > 0 {
			w("  - deterministic refs: %s", strings.Join(c.DeterministicRefs, ", "))
		}
		for _, lim := range c.Limitations {
			w("  - limit: %s", lim)
		}
	}
	for _, sec := range []*Section{
		&r.VulnerabilityMechanism, &r.RootCause, &r.AttackScenario,
		&r.ProductExposure, &r.AlternativePaths,
	} {
		for _, lim := range sec.Limitations {
			w("- section limit: %s", lim)
		}
	}
	for _, lim := range pa.Limitations {
		w("- applicability limit: %s", lim)
	}
	w("")

	// ---- 11. Preserved agent statements (unverified) ----
	w("## Preserved agent statements (unverified)")
	w("")
	w("- agent_output.status: `%s`", r.AgentOutput.Status)
	if r.AgentOutput.Category != nil {
		w("- category (original, never rewritten): `%s`", *r.AgentOutput.Category)
	}
	if r.AgentOutput.AttemptID != nil {
		w("- attempt: `%s`", *r.AgentOutput.AttemptID)
	}
	if rf := r.AgentOutput.ReplayedFrom; rf != nil {
		w("- **replayed** from persisted artifacts: `%s` (original run `%s`, attempt `%s`) — no model call in this run", rf.Dir, rf.OriginalRunID, rf.OriginalAttemptID)
	}
	if r.AgentOutput.Reasoning != nil {
		w("- reasoning: %s", *r.AgentOutput.Reasoning)
	}
	if len(r.AgentAssertions) == 0 {
		w("_No agent assertions._")
	}
	for _, as := range r.AgentAssertions {
		w("- `%s` [%s/%s] %s", as.ID, as.Basis, as.State, as.Statement)
		if as.OriginalText != "" && as.OriginalText != as.Statement {
			w("  - original text: %s", firstN(as.OriginalText, 500))
		}
		if as.SourceSelector != "" {
			w("  - source: `%s` in retained answer", as.SourceSelector)
		}
		for _, lim := range as.Limitations {
			w("  - limit: %s", lim)
		}
	}
	w("")

	// ---- 12. Evidence register ----
	w("## Evidence register")
	w("")
	for _, ref := range r.EvidenceQuality.References {
		w("- ref `%s` (%s) `%s` %s", ref.Ref, ref.Kind, ref.Path, ref.Selector)
		if ref.Materiality != nil {
			m := ref.Materiality
			w("  - materiality: `%s`", m.Level)
			if m.RawBytes != nil {
				w("  - raw bytes: `%s` sha256 `%s` (%s)", m.RawBytes.Path, m.RawBytes.SHA256, m.RawBytes.Selector)
			}
			if m.ReproducibleSource != nil {
				rs := m.ReproducibleSource
				w("  - reproducible: %s `%s` in `%s` → sha256 `%s`",
					rs.Kind, strOr(rs.Command, strOr(rs.Path, "-")), strOr(rs.WorkingDir, "-"), rs.OutputSHA256)
			}
		}
	}
	w("")

	// ---- 13. Attempt and retry history ----
	w("## Attempt and retry history")
	w("")
	if len(r.Run.Attempts) == 0 {
		w("_Single implicit attempt (legacy record)._")
	}
	for _, at := range r.Run.Attempts {
		retry := ""
		if at.RetryOf != nil {
			retry = " retry_of=`" + *at.RetryOf + "`"
		}
		w("- `%s` (%s #%d) status `%s` reason `%s`%s — %s",
			at.ID, at.Kind, at.Ordinal, at.Status, at.ReasonCode, retry, at.Reason)
		w("  - %s → %s | original_preserved=%v", at.StartedAt, at.FinishedAt, at.OriginalPreserved)
		if at.ResultArtifact != nil {
			w("  - result: `%s` sha256 `%s`", at.ResultArtifact.Path, at.ResultArtifact.SHA256)
		}
		if at.Extraction != nil {
			ex := at.Extraction
			recovery := ""
			if ex.Recovery != "" {
				recovery = " recovery=`" + ex.Recovery + "`"
			}
			w("  - extraction: `%s` (%s), %d candidate(s), selected %d%s",
				ex.Status, ex.InvalidReason, ex.CandidateCount, ex.SelectedIndex, recovery)
			for _, cd := range ex.Candidates {
				w("    - candidate[%d] %s category=%s raw `%s`",
					cd.Index, cd.Status, strOr(cd.Category, "-"), cd.RawSHA256)
			}
		}
	}
	w("")

	// ================= appendix =================
	w("## Appendix")
	w("")
	w("### Detailed unknowns")
	w("")
	for _, u := range r.Unknowns {
		if u.Priority == UnknownPriorityDecisionChanging {
			continue
		}
		w("- `%s` %s", u.ID, u.Statement)
		w("  - reason: %s", u.Reason)
		w("  - follow-up: %s", u.FollowUp)
	}
	w("")
	w("### Full deterministic facts")
	w("")
	for _, f := range r.VerifiedFacts {
		w("- `%s` %s", f.ID, f.Statement)
		if isV3 {
			// The /3 fact row names the fact kind and claim — for a
			// bounded package-usage negative also the negative
			// verification status — so a FALSE/VERIFIED result can never
			// be mistaken for a positive or for a safety verdict.
			kind := f.Kind
			if kind == "" {
				kind = "-"
			}
			w("  - kind: `%s` | claim `%s`", kind, f.Claim)
			if f.UsageScope != "" {
				w("  - usage scope: `%s` (paired product/test closure classification; not a product-source usage verdict)", f.UsageScope)
			}
			if f.UsageSubject != nil {
				w("  - usage subject: module=`%s` package=`%s` symbol=`%s`", f.UsageSubject.Module, f.UsageSubject.Package, f.UsageSubject.Symbol)
			}
			if f.ProductAbsenceVerification != "" {
				w("  - product absence verification: `%s` (closed product-closure or vendor-inventory absence; bounded build-context statement only)", f.ProductAbsenceVerification)
			}
			if f.Kind == FactKindBuildUsageScope {
				w("  - limitation: build-closure classification is not a safety, runtime-use, exploitability, or not-affected conclusion")
			}
			if f.NegativeVerification != "" {
				w("  - negative verification: `%s` (bounded to the recorded check scope; not a safe conclusion)", f.NegativeVerification)
			}
			if f.UsageBasis != "" {
				w("  - usage basis: `%s` (the negative's closed basis; bounded to static analysis, not a runtime/dynamic claim)", f.UsageBasis)
			}
		}
		w("  - tool: `%s` (%s) | coverage `%s` | scope: %s", f.Tool, f.ToolVersion, f.Coverage, f.Scope)
		w("  - command: `%s`", f.Command)
		w("  - artifact: `%s` sha256 `%s` | data_digest `%s`",
			f.Artifact.Path, f.Artifact.SHA256, f.DataDigest)
		w("  - provenance: obs `%s` / %s", f.Provenance.ObservationID, f.Provenance.Source)
		if f.Materiality != nil {
			m := f.Materiality
			w("  - materiality: `%s`", m.Level)
			if m.RawBytes != nil {
				w("  - raw bytes: `%s` sha256 `%s`", m.RawBytes.Path, m.RawBytes.SHA256)
			}
			if m.ReproducibleSource != nil {
				rs := m.ReproducibleSource
				w("  - reproducible: %s `%s` → `%s`", rs.Kind, strOr(rs.Command, "-"), rs.OutputSHA256)
			}
		}
		for _, lim := range f.Limitations {
			w("  - limit: %s", lim)
		}
	}
	w("")
	w("### Full exploitation conditions")
	w("")
	for _, c := range r.ExploitationConditions {
		if isV3 {
			w("- `%s` [%s/%s/%s%s%s] %s", c.ID, c.Origin, c.Necessity, c.State,
				axisSuffix(c.Axis), roleSuffix(c.Role), c.Statement)
			if c.Scope != "" {
				w("  - check scope: %s", c.Scope)
			}
		} else {
			w("- `%s` [%s/%s/%s%s] %s", c.ID, c.Origin, c.Necessity, c.State,
				axisSuffix(c.Axis), c.Statement)
		}
		listRow(&b, "  - refs", c.EvidenceRefs)
		listRow(&b, "  - limits", c.Limitations)
	}
	w("")
	w("### Full assessment sections")
	w("")
	for _, s := range r.statusSections() {
		w("#### %s — %s", s.Name, s.Sec.Status)
		w("")
		w("%s", s.Sec.Summary)
		w("")
		for _, c := range s.Sec.Claims {
			w("- **[%s/%s]**", c.Origin, c.State)
			if c.Subject != "" {
				w("  - subject: `%s`", c.Subject)
			}
			w("  - statement: %s", c.Statement)
			w("  - scope: %s", c.Scope)
			listRow(&b, "  - refs", c.EvidenceRefs)
			listRow(&b, "  - limits", c.Limitations)
		}
		listRow(&b, "limits", s.Sec.Limitations)
		w("")
	}
	w("### Full open questions and residual questions")
	w("")
	for i, q := range r.OpenQuestions {
		w("- `%s` %s", q.ID, q.Question)
		w("  - subject/scope: %s / %s", q.Subject, q.Scope)
		w("  - next check: %s", q.NextCheck)
		if i < len(r.ResidualQuestions) && r.ResidualQuestions[i].ID == q.ID {
			w("  - why: %s", r.ResidualQuestions[i].Why)
		}
	}
	w("")
	w("### Legacy evidence-quality details")
	w("")
	eq := r.EvidenceQuality
	w("- status: `%s`", eq.Status)
	w("- summary: %s", eq.Summary)
	listRow(&b, "coverage", eq.Coverage)
	listRow(&b, "conflicts", eq.Conflicts)
	listRow(&b, "limitations", eq.Limitations)
	w("")
	return b.Bytes(), nil
}
func renderDecision(b *bytes.Buffer, r *Report) {
	d := r.Decision
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	w("## Evidence-based decision")
	w("")
	w("- **Decision:** `%s`", d.Verdict)
	w("- **Disposition:** `REVIEW_REQUIRED` — **no auto-close** (`auto_close=false`). The evidence decision is informational and does not authorize auto-close.")
	w("- **Agent hypothesis:** %s", valueOr(d.AgentHypothesis, "not provided"))
	w("- **Concrete falsifier/condition:** `%s` / `%s` — %s", d.Falsifier, d.ConditionID, valueOr(d.FalsifierStatement, "not independently specified"))
	if d.GroundBasis != "" {
		w("- **Verdict basis:** `%s` / `%s`", d.Falsifier, d.GroundBasis)
		if d.GroundBasis == domain.BasisConfigOrigin {
			w("  - administrator-managed configuration is outside the attacker model by declared assumption; the evidence is the exact sink/argument closure, not code-level unreachability")
		}
	}
	w("- **Evidence scope:** %s", valueOr(d.Scope, "not evaluated"))
	w("- **Coverage:** `%s`", valueOr(d.Coverage, "NOT_EVALUATED"))
	w("- **Checks actually executed:**")
	if len(d.Checks) == 0 {
		w("  - UNKNOWN — not evaluated; the relevant verification tool did not run")
	} else {
		for _, c := range d.Checks {
			w("  - `%s` (%s): status=`%s`, completeness=`%s`, scope=%s", c.ID, c.Tool, valueOr(c.Status, "UNKNOWN"), valueOr(c.Completeness, "UNKNOWN"), valueOr(c.Scope, "not evaluated"))
			if c.DerivedFrom != nil {
				w("    - derived_from: advisory %s — \"%s\"", c.DerivedFrom.Field, c.DerivedFrom.Quote)
			}
			if c.Coverage != "" {
				w("    - coverage: `%s`", c.Coverage)
			}
			if len(c.EvidenceRefs) > 0 {
				w("    - refs: %s", strings.Join(c.EvidenceRefs, ", "))
			}
			for _, lim := range c.Limitations {
				w("    - limitation: %s", lim)
			}
		}
	}
	w("- **Evidence refs:** %s", refsOr(d.EvidenceRefs))
	if len(d.AssumptionIDs) > 0 {
		w("- **Assumption refs (policy/scope inputs, not evidence):** %s", strings.Join(d.AssumptionIDs, ", "))
	}
	if d.Sufficiency != "" {
		w("- **Sufficiency:** %s", d.Sufficiency)
	}
	if len(d.Limitations) > 0 {
		w("- **Sufficiency/blocker:** %s", strings.Join(d.Limitations, "; "))
	} else if d.Sufficiency == "" {
		w("- **Sufficiency:** %s", valueOr(d.Reason, "not evaluated"))
	}
	if len(d.HumanQuestions) > 0 {
		w("- **Human follow-up:**")
		for _, q := range d.HumanQuestions {
			w("  - %s", q)
		}
	}
	w("- **Ticket-ready rationale:** %s", valueOr(d.TicketRationale, d.Reason))
	w("")
}

// renderDecisionArtifact renders the /3 decision-artifact/1 summary: the
// proposed disposition, the branch matrix with its explicit unknown
// branch, the bounded human contract (≤2 environment questions, ≤7
// mandatory first-screen facts) and the justification edges. It renders
// the stored artifact verbatim — it never derives a disposition, never
// promotes an environment assertion into a code-level premise and never
// offers a response outside Accept/Reject.
// renderDecisionArtifact renders the bounded human-facing first screen for
// decision-artifact/1. It prints only mandatory fact cards (the remainder is
// available in the report appendix), at most two declared environment
// questions, a deterministic branch matrix, one structured justification,
// contradiction/unknown state, and Accept/Reject controls. Environment
// mitigation is deliberately labelled as contextual and is never rendered as
// a code-grounded CLOSE_* disposition.
func renderDecisionArtifact(b *bytes.Buffer, r *Report) {
	a := r.DecisionArtifact
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	w("## Decision artifact — first screen")
	w("")
	w("### Proposed action")
	w("")
	w("- **Proposed disposition:** `%s`", a.ProposedDisposition)
	if a.ProposedDisposition == DispositionAcceptEnvironmentalMitigation {
		w("- **Contextual environment mitigation only:** this is not `CLOSE_NOT_AFFECTED` or `CLOSE_NO_EXPLOIT_PATH`; it rests on the declared environment premise shown on the selected branch.")
	}
	if a.ProposedDisposition == DispositionHoldUnknown {
		var actionable []string
		for _, br := range a.Branches {
			if br.Status != BranchComplete || br.ProposedDisposition == DispositionHoldUnknown || br.ProposedDisposition == ProposedDisposition("NOT_DECISION_READY") {
				continue
			}
			keys := make([]string, 0, len(br.Assignments))
			for k := range br.Assignments {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			assign := make([]string, 0, len(keys))
			for _, k := range keys {
				assign = append(assign, k+"="+br.Assignments[k])
			}
			if len(assign) == 0 {
				assign = []string{"declared branch premise"}
			}
			actionable = append(actionable, fmt.Sprintf("`%s` (%s) → `%s`", br.ID, strings.Join(assign, ", "), br.ProposedDisposition))
		}
		if len(actionable) > 0 {
			w("- **Branch-dependent outcome:** answer the declared environment question; the complete branches propose %s.", strings.Join(actionable, "; "))
		} else {
			w("- **Conservative outcome:** the case is not ready for code-level closure; the missing or unsupported conditions are listed on the unknown branch below.")
		}
	} else if a.ProposedDisposition == DispositionKeepOpenForRemediation || a.ProposedDisposition == ProposedDisposition("NOT_DECISION_READY") {
		w("- **Conservative outcome:** the case is not ready for code-level closure; the missing or unsupported conditions are listed on the unknown branch below.")
	}
	if j, want, ok := blockedCloseJustification(a); ok {
		// Verified deterministic facts satisfied a registered closure
		// rule, yet the artifact still proposes the conservative outcome:
		// the run was capped before a decision-ready state, so the
		// closure is intentionally not proposed. The reader is told why —
		// the stronger conclusion is prohibited, not missing.
		w("- **Why not `%s`:** recorded facts satisfy the registered closure rule `%s` (justification `%s`), but the run did not reach a decision-ready state, so the stronger conclusion is prohibited and the proposed action stays conservative.", want, j.RuleID, j.ID)
	}
	w("- **Human control:** select `Accept` or `Reject` only. No repository opening, tool rerun, falsifier construction, or free-form interpretation is required.")
	w("")
	w("### Mandatory facts (first screen; maximum %d)", MaxMandatoryFacts)
	facts := firstScreenFacts(a)
	if len(facts) == 0 {
		w("- none recorded; the proposed action is conservative")
	} else {
		for _, f := range facts {
			w("- **`%s`** [%s; coverage=%s] %s", f.ID, f.Status, f.Coverage, f.Proposition)
		}
	}
	w("")
	// Multi-entry advisories get a per-entry verdict line so mixed
	// fixed/affected splits are visible on the first screen instead of
	// only in the implementations table below.
	if len(a.AdvisoryBinding.SubjectRefs) > 1 {
		w("### Advisory entry status")
		implByID := make(map[string]AffectedImplementation, len(r.AffectedImplementations))
		for _, im := range r.AffectedImplementations {
			implByID[im.ID] = im
		}
		var kinds []string
		kindSet := map[string]bool{}
		for _, ref := range a.AdvisoryBinding.SubjectRefs {
			status := "unverified"
			label := ""
			if im, ok := implByID[ref]; ok {
				label = implModule(im)
				if st := entryStatus(im, r.ProductApplicability); st != "" {
					status = st
				}
			}
			if !kindSet[status] {
				kindSet[status] = true
				kinds = append(kinds, status)
			}
			if label != "" {
				w("- **`%s`** — **%s** (`%s`)", ref, status, label)
			} else {
				w("- **`%s`** — **%s**", ref, status)
			}
		}
		if len(kinds) > 1 {
			w("- aggregate: per-entry statuses differ — the conservative proposal covers the whole advisory, not a single entry")
		}
	}
	w("")
	w("### Environment questions (maximum %d)", MaxEnvironmentQuestions)
	if len(a.HumanAction.EnvironmentQuestionRefs) == 0 {
		w("- none; branch selection is already determined by recorded evidence")
	} else {
		vars := make(map[string]DecisionVariable, len(a.DecisionVariables))
		for _, v := range a.DecisionVariables {
			vars[v.ID] = v
		}
		for _, id := range a.HumanAction.EnvironmentQuestionRefs {
			if v, ok := vars[id]; ok {
				w("- **`%s`** %s (allowed: %s)", v.ID, v.Question, refsOr(v.AllowedValues))
			}
		}
	}
	for _, qs := range a.HumanAction.EnvironmentQuestions {
		w("- %s", qs)
	}
	w("")
	w("### Branch matrix")
	for _, br := range a.Branches {
		keys := make([]string, 0, len(br.Assignments))
		for k := range br.Assignments {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		assigns := make([]string, 0, len(keys))
		for _, k := range keys {
			assigns = append(assigns, k+"="+br.Assignments[k])
		}
		if len(assigns) == 0 {
			assigns = []string{"—"}
		}
		label := string(br.ProposedDisposition)
		if br.ProposedDisposition == DispositionAcceptEnvironmentalMitigation {
			label = "ACCEPT_ENVIRONMENTAL_MITIGATION (contextual; not CLOSE_*)"
		}
		w("- **`%s`** status=%s, coverage=`%s`, assignment=%s → `%s`", br.ID, branchStatusLabel(br.Status), br.Coverage, strings.Join(assigns, ", "), label)
		for _, as := range br.EnvironmentAssertions {
			w("  - **environment premise:** `%s`=`%s` (source=%s; principal=%s)", as.Variable, as.Value, as.Source, as.Principal)
		}
		for _, req := range br.RequiredEnvironmentInputs {
			w("  - answer required: `%s`", req)
		}
		for _, lim := range br.Limitations {
			w("  - missing/unsupported: %s", humanizeHoldReason(lim))
		}
	}
	w("")
	w("### Contradiction and unknown state")
	if len(a.Contradictions) == 0 {
		w("- contradictions: none recorded")
	} else {
		for _, c := range a.Contradictions {
			w("- `%s` [%s/%s] %s", c.ID, c.Kind, c.Resolution, c.Summary)
		}
	}
	for _, br := range a.Branches {
		if br.ProposedDisposition == DispositionHoldUnknown {
			for _, lim := range br.Limitations {
				w("- unknown: %s", humanizeHoldReason(lim))
			}
		}
	}
	w("")
	w("### Structured justification")
	if len(a.JustificationGraph) == 0 {
		w("- none; no deterministic closure is asserted")
	} else {
		for _, j := range a.JustificationGraph {
			w("- `%s`: rule=`%s`; facts=%s; conditions=%s; disposition=`%s`; basis=%s — %s", j.ID, j.RuleID, refsOr(j.PremiseFactRefs), refsOr(j.ConditionRefs), j.Disposition, j.CoverageBasis, j.Statement)
		}
	}
	w("")
	w("### Controls")
	w("- **Accept** the proposed action, or **Reject** it. Responses: %s.", refsOr(a.HumanAction.AllowedResponses))
	w("")
	w("> Full facts, raw agent output, tool records, source references, replay pins, and policy pins remain available in the appendix and sidecar; they are not required for a decision-ready case.")
	w("> `disposition.class` remains `REVIEW_REQUIRED` and `auto_close=false` regardless of the proposal.")
	w("")
}

// firstScreenFacts selects the fact cards rendered on the first screen.
// Declared mandatory refs are authoritative; when the human contract
// carries none — for example a run capped to HOLD_UNKNOWN before any
// branch could cite its premises — the renderer still shows the
// established VERIFIED facts the decision rests on, most
// decision-relevant first: justification premises, then branch-cited
// facts, then the remaining verified facts. The rendered set never
// exceeds MaxMandatoryFacts and never includes a non-verified fact.
func firstScreenFacts(a *DecisionArtifact) []Fact {
	byID := make(map[string]Fact, len(a.SharedFacts))
	for _, f := range a.SharedFacts {
		byID[f.ID] = f
	}
	seen := map[string]bool{}
	var out []Fact
	add := func(id string, requireVerified bool) {
		if len(out) >= MaxMandatoryFacts || seen[id] {
			return
		}
		f, ok := byID[id]
		if !ok || (requireVerified && f.Status != FactStatusVerified) {
			return
		}
		seen[id] = true
		out = append(out, f)
	}
	if len(a.HumanAction.MandatoryFactRefs) > 0 {
		for _, id := range a.HumanAction.MandatoryFactRefs {
			add(id, false)
		}
		return out
	}
	for _, j := range a.JustificationGraph {
		for _, id := range j.PremiseFactRefs {
			add(id, true)
		}
	}
	for _, br := range a.Branches {
		for _, id := range br.FactRefs {
			add(id, true)
		}
	}
	for _, f := range a.SharedFacts {
		add(f.ID, true)
	}
	return out
}

// blockedCloseJustification detects the intentionally prohibited
// stronger conclusion: a justification edge that names a registered
// closure rule but no longer carries the disposition that rule grants —
// the shape a non-ready run leaves after the proposal is capped at
// HOLD_UNKNOWN. It returns the edge plus the disposition the rule would
// have granted. An artifact already proposing CLOSE_* never reports a
// blocked close.
func blockedCloseJustification(a *DecisionArtifact) (Justification, ProposedDisposition, bool) {
	if isCloseDisposition(a.ProposedDisposition) {
		return Justification{}, "", false
	}
	for _, j := range a.JustificationGraph {
		for _, rule := range closeRules {
			if j.RuleID == rule.id && j.Disposition != rule.disp {
				return j, rule.disp, true
			}
		}
	}
	return Justification{}, "", false
}

// branchStatusLabel translates a branch status enum into the plain
// phrase the first screen shows; the machine enum stays in the sidecar
// JSON. An unknown value passes through so a future status is still
// visible rather than blank.
func branchStatusLabel(s BranchStatus) string {
	switch s {
	case BranchComplete:
		return "complete"
	case BranchAwaitingInput:
		return "awaiting a declared environment answer"
	case BranchContradicted:
		return "contradicted by recorded evidence"
	case BranchNotDecisionReady:
		return "not decision-ready"
	default:
		return string(s)
	}
}

// humanizeHoldReason rewrites the internal run/branch vocabulary that
// stored limitation strings can carry — the recorded flow termination
// phrase and the branch-status enum — into plain language for the first
// screen. Raw machine detail (step ids, planner error text) stays in
// flow-events.jsonl and the artifact sidecar; the human-facing line
// keeps only the consequence.
func humanizeHoldReason(lim string) string {
	if rest, ok := strings.CutPrefix(lim, "run terminated "); ok {
		return "the run stopped before reaching a decision-ready state: " +
			plainTerminationReason(rest)
	}
	return strings.ReplaceAll(lim, "NOT_DECISION_READY", "not decision-ready")
}

// plainTerminationReason maps the recorded termination name that trails
// "run terminated" onto a human-readable cause. The parenthesized
// machine reason that follows the termination name is dropped: raw
// error strings are audit material, not decision input. An unrecognized
// termination collapses to a generic stop — always a safe description
// of a non-ready run.
func plainTerminationReason(rest string) string {
	term := rest
	if i := strings.IndexByte(term, ' '); i >= 0 {
		term = term[:i]
	}
	switch flow.Termination(term) {
	case flow.TermDecisionReady, flow.TermBranchesComplete:
		// Unreachable inside a hold limitation; renders honestly anyway.
		return "the recorded outcome was not admitted as decision-ready"
	case flow.TermAwaitingEnvironment:
		return "the run still needs declared environment answers"
	case flow.TermTerminalContradiction:
		return "a recorded contradiction could not be resolved"
	case flow.TermBudgetExhausted:
		return "the step or action budget was exhausted"
	case flow.TermPlannerFailure:
		return "the planning step failed or produced no usable plan"
	case flow.TermReassessorFailure:
		return "the reassessment step failed or produced no usable assessment"
	case flow.TermUnsupported:
		return "a step referenced an unregistered check or condition"
	case flow.TermPolicyViolation:
		return "the safety policy rejected the run"
	case flow.TermNotDecisionReady:
		return "the evidence did not decide the finding"
	case flow.TermAborted:
		return "the run ended before completing"
	default:
		return "the run did not produce a usable outcome"
	}
}

func valueOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// implSelected reports whether the advisory entry is the one the
// applicability resolver evaluated.
func implSelected(im AffectedImplementation, pa ProductApplicability) bool {
	for _, m := range pa.CheckedModules {
		if m == im.Module {
			return true
		}
	}
	if pa.SelectedModule != nil && *pa.SelectedModule == im.Module {
		return true
	}
	for _, m := range pa.SelectedModules {
		if m == im.Module {
			return true
		}
	}
	return false
}

func implModule(im AffectedImplementation) string {
	if im.Module != "" {
		return im.Module
	}
	return "-"
}

func axisSuffix(axis string) string {
	if axis == "" {
		return ""
	}
	return "/" + axis
}

// renderEvidenceLevelDisclaimer is the permanent caption under every
// /3 evidence-level block (design §3 Render/UX): the level measures
// proof of the exploit path, never product safety. It is emitted
// unconditionally — it is not read from the stored limitations — so
// no report payload can remove it.
const renderEvidenceLevelDisclaimer = "Уровень описывает доказанность exploit path, а не безопасность продукта. Отсутствие L3 означает отсутствие динамического доказательства, но не означает `not exploitable`."

// renderEvidenceLevel prints the derived ladder as its own block for
// /3 reports (nil level means a legacy /1 or /2 document — nothing is
// rendered and the section heading is skipped). The block is display
// chrome only: it reads the stored EvidenceLevel verbatim, maps the
// level enum onto the three fixed labels and emits the permanent
// disclaimer. It never derives the level, never promotes an agent
// hypothesis and never phrases any level as a safety verdict.
func renderEvidenceLevel(b *bytes.Buffer, level *EvidenceLevel) {
	if level == nil {
		return
	}
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	w("## Evidence level (derived)")
	w("")
	w("- **level:** %s (`%s`)", evidenceLevelLabel(level.Level), level.Level)
	w("- **basis:** `%s`", level.Basis)
	w("- **statement:** %s", strOr(&level.Statement, "-"))
	w("- **scope:** %s", strOr(&level.Scope, "-"))
	w("- **condition refs:** %s", refsOr(level.ConditionRefs))
	w("- **evidence refs:** %s", refsOr(level.EvidenceRefs))
	w("- **blocking conditions (unclosed required applicability/path):** %s",
		refsOr(level.BlockingConditions))
	// The derivation embeds the disclaimer in limitations; it is
	// rendered once as the permanent caption below, so the exact
	// stored sentence is filtered here to avoid a duplicated line.
	var lims []string
	for _, lim := range level.Limitations {
		if lim == evidenceLevelDisclaimer || lim == renderEvidenceLevelDisclaimer {
			continue
		}
		lims = append(lims, lim)
	}
	if len(lims) == 0 {
		w("- **limitations:** none recorded")
	} else {
		w("- **limitations:**")
		for _, lim := range lims {
			w("  - limit: %s", lim)
		}
	}
	w("")
	w("> %s", renderEvidenceLevelDisclaimer)
	w("")
}

// evidenceLevelLabel maps the closed level enum onto the three stable
// labels; an unrecognized value passes through unchanged.
func evidenceLevelLabel(level string) string {
	switch level {
	case EvidenceLevelL1:
		return "L1 — статически подтверждённый путь"
	case EvidenceLevelL2:
		return "L2 — потенциальный путь"
	case EvidenceLevelL3:
		return "L3 — динамически подтверждённая эксплуатация"
	default:
		return level
	}
}

// refsOr renders an id list as backticked comma-separated ids or a
// fixed none-marker so empty fields stay visible instead of dropping
// the line.
func refsOr(refs []string) string {
	if len(refs) == 0 {
		return "none recorded"
	}
	return "`" + strings.Join(refs, "`, `") + "`"
}

// roleSuffix mirrors axisSuffix for the /3 condition role: the role
// joins the bracketed [origin/necessity/state/axis] fields in the
// appendix condition row without removing any of them.
func roleSuffix(role string) string {
	if role == "" {
		return ""
	}
	return "/role=" + role
}

func listRow(b *bytes.Buffer, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "- %s:\n", label)
	for _, it := range items {
		fmt.Fprintf(b, "  - %s\n", it)
	}
}

func strOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}

func strOrZero(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// renderRequestComposition renders the canonical /4 or /5 request answer.
// It is rendered from the re-admitted composition only: the record-bound decision,
// artifact's advisory binding and product_applicability above keep their own
// record scope, and a reader is told which of the two answers covers what.
func renderRequestComposition(b *bytes.Buffer, r *Report) {
	f := r.RequestComposition
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	w("## Requested finding")
	w("")
	w("This section is the answer to the request `%s` (%s, coverage `%s`), re-admitted from every independently assessed record.",
		f.RequestedID, f.RequestedKind, f.Coverage)
	w("")
	verdict := strOrZero(string(f.Verdict), "—")
	w("- **Assessment outcome:** `%s`", f.Outcome)
	w("- **Verdict:** `%s`", verdict)
	w("- **Profile:** `%s` (actual: %t) · build `%s@%s` %s/%s",
		f.Profile, f.IsTargetActual, strOrZero(f.Build.Repository, "unknown"),
		strOrZero(f.Build.Commit, "unknown"), f.Build.GOOS, f.Build.GOARCH)
	if f.ExploitabilityScope != "" {
		w("- **Exploitability scope:** `%s`", f.ExploitabilityScope)
	}
	w("- **Reason:** %s", f.Reason)
	if r.Schema == ReportSchemaV5 {
		w("- The applicability block and evidence decision remain record-bound details; only this canonical projection answers the request.")
	} else if !strings.HasPrefix(f.RequestedID, "CVE-") {
		w("- The decision, decision artifact and applicability block above remain bound to this exact record; a related record's positive is a separate finding.")
	}
	if len(f.ProofOrigins) > 0 {
		w("")
		w("### Admitted proof origins")
		w("")
		for _, origin := range f.ProofOrigins {
			w("- `%s` from `%s` (%s): entries %v, mechanism `%s`, attribution `%s`",
				origin.AssessmentID, origin.Record.RecordID, origin.Record.DocumentDigest,
				origin.EntryRefs, strOrZero(origin.MechanismID, "—"), strOrZero(origin.AttributionID, "—"))
			if len(origin.EvidenceRefs) > 0 {
				w("  - evidence: %s", qualifiedRefList(origin.EvidenceRefs))
			}
		}
	}
	if basis := f.CorpusNegativeBasis; basis != nil {
		w("")
		w("### Declared corpus completeness basis")
		w("")
		w("- Corpus: `%s`", basis.Reference)
		w("- Digests: declared `%s` · observed `%s` · manifest `%s`", basis.DeclaredDigest, basis.ObservedDigest, basis.ManifestDigest)
		w("- Captured: `%s` · enumeration `%s` · %d assessed record(s)",
			basis.CapturedAt, basis.Enumeration, len(basis.AssessedRecords))
		for _, assessed := range basis.AssessedRecords {
			w("  - `%s` (%s): `%s`, verdict `%s`", assessed.Record.RecordID,
				assessed.Record.DocumentDigest, assessed.Outcome, strOrZero(string(assessed.Verdict), "—"))
		}
		w("- %s", basis.BoundaryStatement)
		w("- Corpus completeness supplies this boundary only; it does not replace the semantic proof of any candidate.")
	}
	if len(f.ExternalDependencies) > 0 {
		w("")
		w("### External dependencies")
		w("")
		for _, dep := range f.ExternalDependencies {
			w("- **%s** (obligation `%s`): %s", dep.MissingFact, dep.AffectedObligation, dep.WhyArtifactCannotSupply)
			if len(dep.AlternativesChanging) > 0 {
				w("  - the answer changes with: %s", strings.Join(dep.AlternativesChanging, "; "))
			}
			if dep.ResolvingEvidence != "" {
				w("  - resolving evidence: %s", dep.ResolvingEvidence)
			}
		}
	}
	if len(f.Gaps) > 0 {
		w("")
		w("### Analysis gaps")
		w("")
		for _, gap := range f.Gaps {
			w("- `%s/%s` on `%s` in `%s`: %s", gap.Owner, gap.Code, gap.Obligation, gap.AssessmentID, gap.Message)
		}
	}
	if len(f.Limitations) > 0 {
		w("")
		w("### Request limitations")
		w("")
		for _, limitation := range f.Limitations {
			w("- %s", limitation)
		}
	}
	w("")
}

// qualifiedRefList renders assessment-qualified references as
// `assessment:ref` pairs so a reader can tell two records' evidence apart.
func qualifiedRefList(refs []domain.QualifiedRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("%s:%s", ref.AssessmentID, ref.Ref))
	}
	return strings.Join(parts, ", ")
}
