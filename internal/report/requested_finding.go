package report

// This file is the report-side cutover to the shared requested-finding
// projection. Every human and machine surface (report.json, Markdown, tracker
// rationale, remediation, OpenVEX and CycloneDX) renders the one projection
// finding.Project produces, so identity, outcome, verdict, proof origin,
// scope, severity and remediation cannot disagree between artifacts.
//
// Two rules decide the shape of everything below:
//
//   - The requested answer is never derived from whichever record happened to
//     be selected first. A composed positive names the witness that earned it
//     and its witness-bound remediation; the primary record's own assessment
//     is rendered unchanged, separately.
//   - External dependency and analysis failure are distinct propositions. They
//     may share an export state, but they never share an explanation, and a
//     failure never carries a safe or dismissed disposition.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/risk"
)

// publication is the report-side view of one persisted case: the re-admitted
// requested finding, the primary record, every independently assessed record
// and every witness behind a positive profile.
//
// A legacy case (no analysis-case/2 envelope) produces a publication with no
// requested finding: it has no request-level answer, no discovery record and no
// candidate assessments, so it keeps the historical single-assessment
// rendering. It is not reinterpreted as a requested outcome.
type publication struct {
	requested *domain.RequestedFinding
	primary   *domain.AnalysisCase
	records   []*domain.AnalysisCase
	witnesses []finding.WitnessView
	axes      finding.AssessmentAxes
	// refusal is set when a v2 case cannot be published at all: its saved
	// conclusion no longer re-admits against current admission. Nothing may
	// be exported from a refused case.
	refusal error
}

// publish runs the single publication gate. It is pure: finding.Project never
// mutates the case, and the returned publication shares only read-only data.
func publish(c *domain.AnalysisCase) publication {
	if c == nil {
		return publication{refusal: fmt.Errorf("project requested finding: nil analysis case")}
	}
	if c.Schema != domain.CaseSchemaV2 {
		return publication{primary: c, records: []*domain.AnalysisCase{c}}
	}
	view, err := finding.Project(c)
	if err != nil {
		return publication{primary: c, refusal: err}
	}
	requested := view.Requested
	records := make([]*domain.AnalysisCase, 0, len(view.Records))
	records = append(records, view.Primary)
	for _, related := range c.RelatedRecords {
		if related.Analysis == nil {
			continue
		}
		if record := view.Records[related.ID]; record != nil {
			records = append(records, record)
		}
	}
	return publication{
		requested: &requested,
		primary:   view.Primary,
		records:   records,
		witnesses: view.Witnesses,
		axes:      view.Axes,
	}
}

// legacy reports whether the case predates the requested-finding contract.
func (p publication) legacy() bool { return p.requested == nil && p.refusal == nil }

// RemediationTarget is one witness-bound fix recommendation: the proof origin
// that earned the positive, the module the witness record actually covers, its
// resolved version and that record's own published fix.
//
// It exists because a composed CVE answer is not the primary record's answer: a
// gRPC witness must recommend gRPC's fix, never the primary record's.
type RemediationTarget struct {
	Origin          domain.ProofOrigin
	Module          string
	ResolvedVersion string
	FixedVersion    string
}

// FixTargets returns every independently earned witness's remediation target
// for a published requested finding, deduplicated by origin and module.
//
// It refuses a case whose requested finding does not re-admit: a target derived
// from a conclusion current admission no longer supports would be a fabricated
// recommendation. An exact request with one witness yields one target, which is
// why single-record consumers may still use FixTarget on that exact assessment.
func FixTargets(c *domain.AnalysisCase) ([]RemediationTarget, error) {
	view, err := finding.Project(c)
	if err != nil {
		return nil, err
	}
	return targetsForWitnesses(view.Witnesses), nil
}

func targetsForWitnesses(witnesses []finding.WitnessView) []RemediationTarget {
	targets := make([]RemediationTarget, 0, len(witnesses))
	seen := make(map[string]bool, len(witnesses))
	for _, witness := range witnesses {
		module, fixed, ok := FixTarget(witness.Assessment)
		if !ok {
			continue
		}
		target := RemediationTarget{
			Origin:          witness.Origin,
			Module:          module,
			ResolvedVersion: resolvedVersion(witness.Assessment),
			FixedVersion:    fixed,
		}
		key := string(target.Origin.AssessmentID) + "\x00" + target.Module + "\x00" +
			target.ResolvedVersion + "\x00" + target.FixedVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, target)
	}
	return targets
}

func (p publication) targets() []RemediationTarget {
	return targetsForWitnesses(p.witnesses)
}

// ---- requested-level facts -------------------------------------------------

// actualAssessment returns the record's own target-actual profile result.
func actualAssessment(c *domain.AnalysisCase) (domain.ProfileAssessment, bool) {
	if c == nil {
		return domain.ProfileAssessment{}, false
	}
	for _, assessment := range c.ProfileAssessments {
		if assessment.IsTargetActual {
			return assessment, true
		}
	}
	return domain.ProfileAssessment{}, false
}

// recordOutcome reports a record's own terminal classification. A record with
// no target-actual assessment never reached evaluation, so it contributes no
// verdict.
func recordOutcome(c *domain.AnalysisCase) (domain.AssessmentOutcome, domain.Verdict, string, bool) {
	assessment, ok := actualAssessment(c)
	if !ok || assessment.Result.Verdict == nil {
		return domain.OutcomeFailed, "", "", false
	}
	return assessment.Result.Outcome, assessment.Result.Verdict.Verdict,
		assessment.Result.Verdict.Reason, true
}

// originLabel names where a proof origin was proved, so a composed positive
// never reads as the primary record's own finding.
func (p publication) originLabel(origin domain.ProofOrigin) string {
	if p.requested != nil && origin.AssessmentID == p.requested.PrimaryAssessmentID {
		return "proven in the primary record"
	}
	return "proven via related record `" + string(origin.AssessmentID) + "`"
}

func (p publication) originLabelRU(origin domain.ProofOrigin) string {
	if p.requested != nil && origin.AssessmentID == p.requested.PrimaryAssessmentID {
		return "доказано в первичной записи"
	}
	return "доказано через связанную запись `" + string(origin.AssessmentID) + "`"
}

func recordModule(c *domain.AnalysisCase) string {
	module, _ := moduleAndVersion(c)
	return module
}

func formatBuildContext(build domain.BuildContext, isRU bool) string {
	var parts []string
	if build.GOOS != "" || build.GOARCH != "" {
		parts = append(parts, strings.TrimPrefix(build.GOOS+"/"+build.GOARCH, "/"))
	}
	if build.GoVersion != "" {
		parts = append(parts, "Go "+build.GoVersion)
	}
	if len(build.BuildTags) > 0 {
		if isRU {
			parts = append(parts, "теги: "+strings.Join(build.BuildTags, ", "))
		} else {
			parts = append(parts, "tags: "+strings.Join(build.BuildTags, ", "))
		}
	}
	if build.CGOEnabled {
		parts = append(parts, "CGO on")
	} else {
		parts = append(parts, "CGO off")
	}
	if build.Commit != "" {
		parts = append(parts, "commit `"+shortCommit(build.Commit)+"`")
	}
	return strings.Join(parts, ", ")
}

// scopeBoundaryText states an exploitability scope's boundary without
// asserting deployment exposure.
func scopeBoundaryText(scope domain.ExploitabilityScope, isRU bool) string {
	switch scope {
	case domain.ScopeLibraryAPI:
		return libraryScopeBoundaryText(isRU)
	case domain.ScopeTransportPeer:
		if isRU {
			return "клиент затронутого транспорта продукта может подать срабатывающий ввод; доступность этого транспорта для атакующего (права на сокет, размещение, ingress, аутентификация) не установлена"
		}
		return "a client of the product's affected transport can supply the triggering input; whether an adversary can reach that transport—through socket permissions, placement, ingress or authentication—is not established"
	default:
		return ""
	}
}

// scopeStatement is the EN projection carried by VEX/CycloneDX documents.
func scopeStatement(scope domain.ExploitabilityScope) string {
	boundary := scopeBoundaryText(scope, false)
	if scope == "" || boundary == "" {
		return ""
	}
	return "Exploitability scope: " + string(scope) + " — " + boundary + "."
}

// localizeScopeLimitation maps a scope's mandatory limitation text to the
// report language. Only the library-API limitation has a localized projection;
// the transport-peer limitation is carried verbatim in every language, because
// its English text is the frozen machine-readable statement.
func localizeScopeLimitation(scope domain.ExploitabilityScope, isRU bool) string {
	switch scope {
	case domain.ScopeLibraryAPI:
		return libraryAPILimitationText(isRU)
	case domain.ScopeTransportPeer:
		return domain.TransportPeerScopeLimitation
	default:
		return ""
	}
}

// ---- Derived assessment axes ----------------------------------------------

// axisVulnerabilityText renders the vulnerability-axis fact for a human
// reader. UNKNOWN is never rendered as "no".
func axisVulnerabilityText(fact finding.AxisFact, isRU bool) string {
	switch fact {
	case finding.AxisTrue:
		return map[bool]string{true: "да", false: "yes"}[isRU]
	case finding.AxisFalse:
		return map[bool]string{true: "нет", false: "no"}[isRU]
	default:
		return map[bool]string{true: "неизвестно", false: "unknown"}[isRU]
	}
}

// axisExploitabilityText renders the exploitability-axis fact. A scoped
// positive always states its boundary: it never becomes an unqualified
// "exploitable in deployment: yes".
func axisExploitabilityText(row finding.AxisRow, isRU bool) string {
	switch row.Exploitable {
	case finding.AxisTrue:
		if row.ExploitabilityScope == "" {
			return map[bool]string{true: "да", false: "yes"}[isRU]
		}
		if isRU {
			return "да, на границе " + axisScopeName(row.ExploitabilityScope) +
				". Доступ атакующего в развёртывании не установлен."
		}
		return "yes, at the " + axisScopeName(row.ExploitabilityScope) +
			" boundary. Deployed attacker access is not established."
	case finding.AxisFalse:
		if isRU {
			return "нет (в записанных сборке, профиле и допущениях)"
		}
		return "no, under the recorded build/profile/assumptions"
	case finding.AxisNotApplicable:
		return map[bool]string{true: "неприменимо", false: "not applicable"}[isRU]
	default:
		return map[bool]string{true: "неизвестно", false: "unknown"}[isRU]
	}
}

func axisScopeName(scope domain.ExploitabilityScope) string {
	switch scope {
	case domain.ScopeLibraryAPI:
		return "library API"
	case domain.ScopeTransportPeer:
		return "transport-peer"
	default:
		return string(scope)
	}
}

// axisRowForRecord looks up one record's target-actual axis row, tolerating a
// legacy publication with no projection.
func axisRowForRecord(axes *finding.AssessmentAxes, c *domain.AnalysisCase) (finding.AxisRow, bool) {
	if axes == nil || c == nil {
		return finding.AxisRow{}, false
	}
	return axes.TargetRecord(c.ID)
}

// axisCell is the compact candidate-table projection. It keeps the enum value
// and appends the scope boundary so a positive cannot read as deployment-wide.
func axisCell(row finding.AxisRow) string {
	exploitable := string(row.Exploitable)
	if row.Exploitable == finding.AxisTrue && row.ExploitabilityScope != "" {
		exploitable += " (" + string(row.ExploitabilityScope) + "; deployed attacker access not established)"
	}
	return "vuln=" + string(row.VulnerableCodeInBuild) + "; exploitable=" + exploitable
}

// writeRequestedAxesSummary puts the two facts at the top of the requested
// answer, bound to the requested subject.
func writeRequestedAxesSummary(b *strings.Builder, pub publication, isRU bool) {
	row, ok := pub.axes.TargetRequested()
	if !ok {
		return
	}
	if isRU {
		fmt.Fprintf(b, "> Уязвимый код/версия в оцениваемой сборке: %s\n", axisVulnerabilityText(row.VulnerableCodeInBuild, true))
		fmt.Fprintf(b, "> Эксплуатируемость: %s\n\n", axisExploitabilityText(row, true))
		return
	}
	fmt.Fprintf(b, "> Vulnerable code/version in assessed build: %s\n", axisVulnerabilityText(row.VulnerableCodeInBuild, false))
	fmt.Fprintf(b, "> Exploitable: %s\n\n", axisExploitabilityText(row, false))
}

// ---- Markdown: requested finding ------------------------------------------

// writeRequestedMarkdown renders the request-level answer: identity and
// outcome, scope and proof origin, witness-bound remediation and severity,
// failure diagnostics or external dependencies, the candidate table and the
// discovery/corpus limitations.
func writeRequestedMarkdown(b *strings.Builder, pub publication, isRU bool) {
	req := pub.requested
	if req == nil {
		return
	}
	outcome := req.Outcome
	if isRU {
		fmt.Fprintf(b, "## Запрошенный результат: `%s`", outcome)
	} else {
		fmt.Fprintf(b, "## Requested finding: `%s`", outcome)
	}
	if req.Verdict != "" {
		fmt.Fprintf(b, " — `%s`\n\n", req.Verdict)
	} else {
		if isRU {
			b.WriteString(" — вердикт не вынесен\n\n")
		} else {
			b.WriteString(" — no verdict was earned\n\n")
		}
	}
	if reason := strings.TrimSpace(req.Reason); reason != "" {
		if isRU {
			fmt.Fprintf(b, "> **%s**\n\n", localizeVerdictReason(reason, true))
		} else {
			fmt.Fprintf(b, "> **%s**\n\n", reason)
		}
	}
	if scope := req.ExploitabilityScope; scope != "" {
		if isRU {
			fmt.Fprintf(b, "> **Область эксплуатации:** `%s` — %s\n\n", scope, scopeBoundaryText(scope, true))
		} else {
			fmt.Fprintf(b, "> **Exploitability scope:** `%s` — %s\n\n", scope, scopeBoundaryText(scope, false))
		}
	}
	writeRequestedAxesSummary(b, pub, isRU)
	writeRequestedFactsTable(b, pub, isRU)

	switch {
	case outcome == domain.OutcomeFailed:
		writeRequestedFailure(b, pub, isRU)
	case outcome == domain.OutcomeExternal:
		writeRequestedExternalDependencies(b, pub, isRU)
	}
	if basis := req.CorpusNegativeBasis; basis != nil {
		writeCorpusNegativeBasis(b, basis, isRU)
	}
	if len(pub.witnesses) > 0 {
		writeProofOrigins(b, pub, isRU)
		writeWitnessRemediation(b, pub, isRU)
	}
	writeCandidateAssessments(b, pub, isRU)
	writeDiscoveryLimitations(b, pub, isRU)
	writeRequestedLimitations(b, pub, isRU)
}

func writeRequestedFactsTable(b *strings.Builder, pub publication, isRU bool) {
	req := pub.requested
	if req == nil {
		return
	}
	if isRU {
		b.WriteString("| Поле | Значение |\n|---|---|\n")
		fmt.Fprintf(b, "| Запрошенная идентичность | `%s` (`%s`) |\n", req.RequestedID, req.RequestedKind)
		fmt.Fprintf(b, "| Полнота запроса | `%s` |\n", req.Coverage)
		fmt.Fprintf(b, "| Классификация анализа | `%s` |\n", req.Outcome)
		if req.Verdict != "" {
			fmt.Fprintf(b, "| Вердикт | `%s` |\n", req.Verdict)
		}
		fmt.Fprintf(b, "| Профиль угроз (целевой) | `%s` |\n", req.Profile)
		fmt.Fprintf(b, "| Сборка | %s |\n", formatBuildContext(req.Build, true))
		fmt.Fprintf(b, "| Первичная запись | `%s` |\n", req.PrimaryAssessmentID)
		if row, ok := pub.axes.TargetRequested(); ok {
			fmt.Fprintf(b, "| Уязвимый код/версия в оцениваемой сборке | %s |\n", axisVulnerabilityText(row.VulnerableCodeInBuild, true))
			fmt.Fprintf(b, "| Эксплуатируемость в оцениваемой области | %s |\n", axisExploitabilityText(row, true))
		}
	} else {
		b.WriteString("| field | value |\n|---|---|\n")
		fmt.Fprintf(b, "| requested identity | `%s` (`%s`) |\n", req.RequestedID, req.RequestedKind)
		fmt.Fprintf(b, "| request coverage | `%s` |\n", req.Coverage)
		fmt.Fprintf(b, "| assessment outcome | `%s` |\n", req.Outcome)
		if req.Verdict != "" {
			fmt.Fprintf(b, "| verdict | `%s` |\n", req.Verdict)
		}
		fmt.Fprintf(b, "| threat profile (target actual) | `%s` |\n", req.Profile)
		fmt.Fprintf(b, "| build | %s |\n", formatBuildContext(req.Build, false))
		fmt.Fprintf(b, "| primary assessment | `%s` |\n", req.PrimaryAssessmentID)
		if row, ok := pub.axes.TargetRequested(); ok {
			fmt.Fprintf(b, "| vulnerable code/version in assessed build | %s |\n", axisVulnerabilityText(row.VulnerableCodeInBuild, false))
			fmt.Fprintf(b, "| exploitable in assessed scope | %s |\n", axisExploitabilityText(row, false))
		}
	}
	hypothetical := map[bool]string{true: "| Гипотетические профили | ", false: "| hypothetical profiles | "}
	if len(req.Profiles) > 1 {
		var other []string
		for _, profile := range req.Profiles {
			if profile.IsTargetActual {
				continue
			}
			cell := "`" + string(profile.Profile) + "`: `" + string(profile.Outcome) + "`"
			if profile.Verdict != "" {
				cell += " / `" + string(profile.Verdict) + "`"
			}
			other = append(other, cell)
		}
		if len(other) > 0 {
			fmt.Fprintf(b, "%s%s |\n", hypothetical[isRU], strings.Join(other, "; "))
		}
	}
	b.WriteString("\n")
}

func writeRequestedFailure(b *strings.Builder, pub publication, isRU bool) {
	req := pub.requested
	if isRU {
		b.WriteString("### Диагностика незавершённого анализа (FAILED)\n\n")
		b.WriteString("Вердикт не вынесен: анализ не смог заработать ответ. Это не безопасное состояние и не внешняя зависимость.\n\n")
	} else {
		b.WriteString("### Analysis failure diagnostics (FAILED)\n\n")
		b.WriteString("No verdict was earned: the analysis could not produce one. This is neither a safe result nor an external dependency.\n\n")
	}
	if len(req.Gaps) == 0 {
		if isRU {
			b.WriteString("- Типизированные причины отказа не зафиксированы.\n\n")
		} else {
			b.WriteString("- No typed failure cause was recorded.\n\n")
		}
		return
	}
	for _, gap := range req.Gaps {
		fmt.Fprintf(b, "- `%s` / `%s` / `%s`", gap.Owner, gap.Code, gap.Obligation)
		if gap.AssessmentID != "" {
			fmt.Fprintf(b, " — %s `%s`", map[bool]string{true: "оценка", false: "assessment"}[isRU], gap.AssessmentID)
		}
		if gap.ConditionID != "" {
			fmt.Fprintf(b, " — %s `%s`", map[bool]string{true: "условие", false: "condition"}[isRU], gap.ConditionID)
		}
		fmt.Fprintf(b, ": %s\n", gap.Message)
		if len(gap.EvidenceRefs) > 0 {
			fmt.Fprintf(b, "  - %s: %s\n",
				map[bool]string{true: "доказательства", false: "evidence"}[isRU],
				qualifiedRefText(gap.EvidenceRefs))
		}
	}
	b.WriteString("\n")
}

func writeRequestedExternalDependencies(b *strings.Builder, pub publication, isRU bool) {
	req := pub.requested
	if isRU {
		b.WriteString("### Внешние зависимости (EXTERNAL_DEPENDENCY)\n\n")
		b.WriteString("Анализ остановлен на конкретном факте, лежащем вне артефакта и выбранного профиля угроз. Это не отказ анализа: при указанном свидетельстве ответ изменится.\n\n")
	} else {
		b.WriteString("### External dependencies (EXTERNAL_DEPENDENCY)\n\n")
		b.WriteString("The analysis stopped at a specific fact outside the artifact and the selected threat profile. This is not an analysis failure: the answer changes once the named evidence exists.\n\n")
	}
	for _, dep := range req.ExternalDependencies {
		fmt.Fprintf(b, "- **%s**: %s\n", map[bool]string{true: "Недостающий факт", false: "Missing fact"}[isRU], dep.MissingFact)
		fmt.Fprintf(b, "  - %s: `%s`\n", map[bool]string{true: "Обязательство", false: "Obligation"}[isRU], dep.AffectedObligation)
		fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "Почему артефакт не может ответить", false: "Why the artifact cannot supply it"}[isRU], dep.WhyArtifactCannotSupply)
		fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "Что решит вопрос", false: "Resolving evidence"}[isRU], dep.ResolvingEvidence)
		if len(dep.AlternativesChanging) > 0 {
			fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "Альтернативы, меняющие ответ", false: "Alternatives that change the answer"}[isRU],
				strings.Join(dep.AlternativesChanging, "; "))
		}
		if len(dep.BoundaryEvidenceRefs) > 0 {
			fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "Доказательства границы", false: "Boundary evidence"}[isRU],
				qualifiedRefText(dep.BoundaryEvidenceRefs))
		}
	}
	b.WriteString("\n")
}

func writeCorpusNegativeBasis(b *strings.Builder, basis *domain.CorpusNegativeBasis, isRU bool) {
	if isRU {
		b.WriteString("### Основание отрицательного ответа по корпусу (Addendum A)\n\n")
		fmt.Fprintf(b, "- Корпус: `%s`, digest `%s`, дата снимка `%s`\n", basis.Reference, basis.ObservedDigest, basis.CapturedAt)
		fmt.Fprintf(b, "- Перечисление: `%s`, digest манифеста `%s`\n", basis.Enumeration, basis.ManifestDigest)
	} else {
		b.WriteString("### Corpus negative basis (Addendum A)\n\n")
		fmt.Fprintf(b, "- Corpus: `%s`, digest `%s`, captured `%s`\n", basis.Reference, basis.ObservedDigest, basis.CapturedAt)
		fmt.Fprintf(b, "- Enumeration: `%s`, manifest digest `%s`\n", basis.Enumeration, basis.ManifestDigest)
	}
	for _, record := range basis.AssessedRecords {
		fmt.Fprintf(b, "- %s `%s` (%s) → `%s`\n",
			map[bool]string{true: "оценённая запись", false: "assessed record"}[isRU],
			record.Record.RecordID, record.Record.DocumentDigest, record.Verdict)
	}
	fmt.Fprintf(b, "\n> %s\n\n", basis.BoundaryStatement)
}

func writeProofOrigins(b *strings.Builder, pub publication, isRU bool) {
	if isRU {
		b.WriteString("### Происхождение доказательства\n\n")
	} else {
		b.WriteString("### Proof origin\n\n")
	}
	for _, witness := range pub.witnesses {
		origin := witness.Origin
		label := pub.originLabel(origin)
		if isRU {
			label = pub.originLabelRU(origin)
		}
		fmt.Fprintf(b, "- **%s** — `%s` (%s), %s `%s`, %s `%s`\n",
			label, origin.AssessmentID, witness.Assessment.Vulnerability.ID,
			map[bool]string{true: "профиль", false: "profile"}[isRU], origin.Profile,
			map[bool]string{true: "сборка", false: "build"}[isRU], formatBuildContext(origin.Build, isRU))
		fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "запись", false: "record"}[isRU], origin.Record.RecordID+" ("+origin.Record.DocumentDigest+")")
		if len(origin.EntryRefs) > 0 {
			refs := make([]string, 0, len(origin.EntryRefs))
			for _, ref := range origin.EntryRefs {
				refs = append(refs, fmt.Sprintf("%d", ref))
			}
			fmt.Fprintf(b, "  - affected[] %s: %s\n", map[bool]string{true: "entries", false: "entries"}[isRU], strings.Join(refs, ", "))
		}
		if origin.MechanismID != "" {
			fmt.Fprintf(b, "  - %s: `%s`\n", map[bool]string{true: "механизм", false: "mechanism"}[isRU], origin.MechanismID)
		}
		if origin.AttributionID != "" {
			fmt.Fprintf(b, "  - %s: `%s`\n", map[bool]string{true: "атрибуция", false: "attribution"}[isRU], origin.AttributionID)
		}
		if len(origin.ConditionRefs) > 0 {
			fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "условия", false: "conditions"}[isRU], qualifiedRefText(origin.ConditionRefs))
		}
		if len(origin.ClaimRefs) > 0 {
			fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "claims", false: "claims"}[isRU], qualifiedRefText(origin.ClaimRefs))
		}
		if len(origin.EvidenceRefs) > 0 {
			fmt.Fprintf(b, "  - %s: %s\n", map[bool]string{true: "доказательства", false: "evidence"}[isRU], qualifiedRefText(origin.EvidenceRefs))
		}
	}
	b.WriteString("\n")
}

func qualifiedRefText(refs []domain.QualifiedRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("`%s`/`%s`", ref.AssessmentID, ref.Ref))
	}
	return strings.Join(parts, ", ")
}

// writeWitnessRemediation renders remediation and severity from the witness
// records that earned the positive. The primary record's own fix never appears
// here: it did not earn this answer.
func writeWitnessRemediation(b *strings.Builder, pub publication, isRU bool) {
	targets := pub.targets()
	if len(targets) == 0 {
		return
	}
	if isRU {
		b.WriteString("### Устранение и критичность по свидетелю\n\n")
		b.WriteString("Цель исправления берётся из записи-свидетеля, доказавшей результат; версия из первичной записи здесь не применяется.\n\n")
	} else {
		b.WriteString("### Witness-bound remediation and severity\n\n")
		b.WriteString("The remediation target comes from the witness record that proved the result; the primary record's fixed version does not apply here.\n\n")
	}
	for _, target := range targets {
		label := pub.originLabel(target.Origin)
		if isRU {
			label = pub.originLabelRU(target.Origin)
		}
		if target.FixedVersion == "" {
			if isRU {
				fmt.Fprintf(b, "- `%s` — %s: опубликованной версии с исправлением нет (текущая `%s`); примените компенсирующие меры.\n",
					target.Module, label, target.ResolvedVersion)
			} else {
				fmt.Fprintf(b, "- `%s` — %s: no fixed version is published (current `%s`); apply a compensating control.\n",
					target.Module, label, target.ResolvedVersion)
			}
		} else {
			fmt.Fprintf(b, "- `%s` — %s: `%s` → `%s` (`go get %s@%s && go mod tidy`)\n",
				target.Module, label, target.ResolvedVersion, target.FixedVersion, target.Module, target.FixedVersion)
		}
	}
	for _, witness := range pub.witnesses {
		vuln := witness.Assessment.Vulnerability
		severity := strings.ToUpper(strings.TrimSpace(vuln.BaseSeverity))
		if severity == "" {
			continue
		}
		score := ""
		if vuln.BaseScore > 0 {
			score = fmt.Sprintf(" %.1f", vuln.BaseScore)
		}
		if isRU {
			fmt.Fprintf(b, "- Критичность записи-свидетеля `%s`: **%s**%s — это оценка записи `%s`, а не первичной.\n",
				witness.Origin.AssessmentID, severity, score, witness.Assessment.Vulnerability.ID)
		} else {
			fmt.Fprintf(b, "- Severity of witness assessment `%s`: **%s**%s — the record's own rating (`%s`), not the primary record's.\n",
				witness.Origin.AssessmentID, severity, score, witness.Assessment.Vulnerability.ID)
		}
	}
	if summary := pub.prioritySummary(isRU); summary != "" {
		fmt.Fprintf(b, "\n%s\n", summary)
	}
	b.WriteString("\n")
}

// prioritySummary states the request-level priority and names every candidate
// assessment it summarizes. It never presents a verdict-driven dismissal: it is
// emitted only for a decided positive.
func (p publication) prioritySummary(isRU bool) string {
	if p.requested == nil || p.requested.Verdict != domain.VerdictExploitable {
		return ""
	}
	var parts []string
	best := domain.PriorityDismissed
	for _, witness := range p.witnesses {
		verdict := witness.Profile.Result.Verdict
		if verdict == nil {
			continue
		}
		assessed := risk.Assess(witness.Assessment.Vulnerability, witness.Assessment, *verdict)
		if priorityRank(assessed.Priority) < priorityRank(best) {
			best = assessed.Priority
		}
		parts = append(parts, fmt.Sprintf("`%s`: %s / %s", witness.Origin.AssessmentID, assessed.Priority, assessed.ContextualLevel))
	}
	if len(parts) == 0 {
		return ""
	}
	if isRU {
		return "Приоритет запроса: **" + string(best) + "** — сводка по оценённым записям-свидетелям (" + strings.Join(parts, "; ") + ")."
	}
	return "Request priority: **" + string(best) + "** — summarized over the witness assessments (" + strings.Join(parts, "; ") + ")."
}

// priorityRank orders priorities from most to least urgent.
func priorityRank(p domain.TriagePriority) int {
	switch p {
	case domain.PriorityP0:
		return 0
	case domain.PriorityP1:
		return 1
	case domain.PriorityP2:
		return 2
	case domain.PriorityP3:
		return 3
	default:
		return 4
	}
}

// candidateRow is one assessed record in the request-level candidate table: the
// discovery relationship that nominated it, its attribution status, its own
// applicability/verdict and its unfinished obligations.
type candidateRow struct {
	Role        string
	Record      domain.RecordPin
	Identity    string
	Assessment  *domain.AnalysisCase
	Edges       []domain.DiscoveryEdge
	Disposition domain.CandidateDisposition
	Note        string
	Attribution *domain.CVEAttribution
	Result      domain.ProfileAssessment
	HasResult   bool
	Axes        finding.AxisRow
	HasAxes     bool
}

func (p publication) candidateRows() []candidateRow {
	if p.requested == nil || p.primary == nil {
		return nil
	}
	rows := make([]candidateRow, 0, len(p.records))
	if pin := p.primary.RecordPin; pin != nil {
		rows = append(rows, candidateRow{
			Role:        "primary",
			Record:      *pin,
			Assessment:  p.primary,
			Disposition: domain.DispositionEvaluated,
			Attribution: p.attributionForPin(*pin),
		})
	}
	if discovery := p.primary.RelatedDiscovery; discovery != nil {
		for _, candidate := range discovery.Candidates {
			pin := candidate.Record
			record := p.recordForPin(pin)
			rows = append(rows, candidateRow{
				Role:        "candidate",
				Record:      pin,
				Assessment:  record,
				Edges:       candidate.Edges,
				Disposition: candidate.Disposition,
				Note:        candidate.Note,
				Attribution: p.attributionForPin(pin),
			})
		}
	}
	for i := range rows {
		if rows[i].Assessment == nil {
			continue
		}
		rows[i].Identity = rows[i].Assessment.Vulnerability.ID
		if result, ok := actualAssessment(rows[i].Assessment); ok {
			rows[i].Result = result
			rows[i].HasResult = true
		}
		if axes, ok := p.axes.TargetRecord(rows[i].Assessment.ID); ok {
			rows[i].Axes = axes
			rows[i].HasAxes = true
		}
	}
	return rows
}

func (p publication) recordForPin(pin domain.RecordPin) *domain.AnalysisCase {
	for _, record := range p.records {
		if record.RecordPin != nil && record.RecordPin.Same(pin) {
			return record
		}
	}
	return nil
}

func (p publication) attributionForPin(pin domain.RecordPin) *domain.CVEAttribution {
	if p.primary == nil {
		return nil
	}
	for i := range p.primary.Attributions {
		if p.primary.Attributions[i].Candidate.Same(pin) {
			return &p.primary.Attributions[i]
		}
	}
	return nil
}

// writeCandidateAssessments renders the candidate table: discovery
// relationship, attribution status, applicability, verdict and unfinished
// obligations. Discovery establishes relatedness only; the table never turns a
// related id into an alias of the requested identity.
func writeCandidateAssessments(b *strings.Builder, pub publication, isRU bool) {
	rows := pub.candidateRows()
	if len(rows) == 0 {
		return
	}
	// An exact request has one record; the primary-assessment section already
	// publishes it, and a one-row "candidate" table would imply discovery that
	// never ran.
	if len(rows) == 1 && pub.primary != nil && pub.primary.RelatedDiscovery == nil {
		return
	}
	if isRU {
		b.WriteString("### Оценённые записи-кандидаты\n\n")
		b.WriteString("| Роль | Запись | Идентичность | Отношение обнаружения | Атрибуция | Применимость | Оси оценки | Классификация | Вердикт | Незавершённые обязательства |\n|---|---|---|---|---|---|---|---|---|---|\n")
	} else {
		b.WriteString("### Candidate assessments\n\n")
		b.WriteString("| role | record | identity | discovery relationship | attribution | applicability | axes | outcome | verdict | unfinished obligations |\n|---|---|---|---|---|---|---|---|---|---|\n")
	}
	for _, row := range rows {
		verdict := "—"
		if row.HasResult && row.Result.Result.Verdict != nil {
			verdict = "`" + string(row.Result.Result.Verdict.Verdict) + "`"
		}
		outcome := "`FAILED`"
		if row.HasResult {
			outcome = "`" + string(row.Result.Result.Outcome) + "`"
		}
		axes := "—"
		if row.HasAxes {
			axes = sanitizeTableString(axisCell(row.Axes), 120)
		}
		fmt.Fprintf(b, "| %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			row.Role, row.Record.RecordID, orDash(row.Identity),
			sanitizeTableString(edgesText(row.Edges), 90),
			attributionText(row.Attribution, isRU),
			applicabilityText(row.Assessment),
			axes, outcome, verdict,
			sanitizeTableString(unfinishedObligations(row), 120))
	}
	b.WriteString("\n")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func edgesText(edges []domain.DiscoveryEdge) string {
	if len(edges) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(edges))
	for _, edge := range edges {
		text := "`" + string(edge.Kind) + "`:`" + edge.ID + "`"
		if edge.FromID != "" {
			text += " (from `" + edge.FromID + "`)"
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, ", ")
}

func attributionText(attribution *domain.CVEAttribution, isRU bool) string {
	if attribution == nil {
		if isRU {
			return "нет записи об атрибуции"
		}
		return "no attribution recorded"
	}
	cell := "`" + string(attribution.Admission) + "` / `" + string(attribution.Basis) + "`"
	if attribution.PublisherAdvisory != "" {
		cell += " / `" + attribution.PublisherAdvisory + "`"
	}
	return cell
}

// applicabilityText names the record's own applicability facts, so a candidate
// is never read as covered by the primary's census.
func applicabilityText(c *domain.AnalysisCase) string {
	if c == nil || c.Affected == nil {
		return "—"
	}
	a := c.Affected
	parts := []string{
		"module=" + string(a.ModulePresent),
		"version=" + string(a.VersionAffected),
		"package=" + string(a.PackagePresent),
		"build=" + string(a.BuildRelevant),
		"impl=" + string(a.VulnerableImplementationPresent),
	}
	if a.ResolvedVersion != "" {
		parts = append(parts, "resolved=`"+a.ResolvedVersion+"`")
	}
	return sanitizeTableString(strings.Join(parts, "; "), 160)
}

func unfinishedObligations(row candidateRow) string {
	if row.Assessment == nil {
		return "assessment unavailable"
	}
	var out []string
	seen := map[string]bool{}
	add := func(gap domain.AnalysisGap) {
		key := string(gap.Owner) + "/" + string(gap.Code) + "/" + string(gap.Obligation)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, key)
	}
	if row.HasResult {
		for _, gap := range row.Result.Result.Gaps {
			add(gap)
		}
	}
	if row.Role == "primary" {
		for _, gap := range row.Assessment.AnalysisGaps {
			add(gap)
		}
	}
	if len(out) == 0 {
		return "—"
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

// writeDiscoveryLimitations renders what discovery could and could not
// enumerate. A configured feed or a finished scan is never closure authority,
// and implementations outside a declared corpus were not examined.
func writeDiscoveryLimitations(b *strings.Builder, pub publication, isRU bool) {
	if pub.primary == nil {
		return
	}
	discovery := pub.primary.RelatedDiscovery
	if discovery == nil {
		return
	}
	if isRU {
		b.WriteString("### Ограничения обнаружения и корпуса\n\n")
		fmt.Fprintf(b, "- Перечисление: `%s`, кандидатов: %d\n", discovery.Enumeration, len(discovery.Candidates))
		if discovery.Corpus != nil {
			fmt.Fprintf(b, "- Корпус: `%s`, digest `%s`, дата снимка `%s`\n",
				discovery.Corpus.Reference, discovery.Corpus.Digest, discovery.Corpus.CapturedAt)
		}
	} else {
		b.WriteString("### Discovery and corpus limitations\n\n")
		fmt.Fprintf(b, "- Enumeration: `%s`, nominated candidates: %d\n", discovery.Enumeration, len(discovery.Candidates))
		if discovery.Corpus != nil {
			fmt.Fprintf(b, "- Corpus: `%s`, digest `%s`, captured `%s`\n",
				discovery.Corpus.Reference, discovery.Corpus.Digest, discovery.Corpus.CapturedAt)
		}
	}
	for _, limitation := range discovery.Limitations {
		fmt.Fprintf(b, "- %s\n", limitation)
	}
	if !discovery.Enumeration.Complete() {
		if isRU {
			b.WriteString("- Перечисление корпуса не завершено: реализации за пределами перечисленного не проверялись, и незавершённое перечисление не является основанием отрицательного ответа.\n")
		} else {
			b.WriteString("- The corpus enumeration did not finish: implementations outside it were not examined, and an unfinished enumeration is not a negative-closure basis.\n")
		}
	}
	b.WriteString("\n")
}

func writeRequestedLimitations(b *strings.Builder, pub publication, isRU bool) {
	limitations := pub.requested.Limitations
	if len(limitations) == 0 {
		return
	}
	if isRU {
		b.WriteString("### Ограничения запрошенного результата\n\n")
	} else {
		b.WriteString("### Requested-finding limitations\n\n")
	}
	seen := make(map[string]bool, len(limitations))
	for _, limitation := range limitations {
		localized := localizeLimitation(limitation, isRU)
		if seen[localized] {
			continue
		}
		seen[localized] = true
		fmt.Fprintf(b, "- %s\n", localized)
	}
	b.WriteString("\n")
}

// writeRefusalMarkdown renders the diagnostic deliverable for a case whose
// saved conclusion no longer re-admits. It publishes no verdict and no
// remediation: an unadmitted conclusion is not re-projected as a claim.
func writeRefusalMarkdown(b *strings.Builder, c *domain.AnalysisCase, refusal error, isRU bool) {
	titleID := "requested advisory"
	caseID := "unknown"
	if c != nil {
		caseID = string(c.ID)
		if id, _, _ := domain.RequestedIdentity(c); id != "" {
			titleID = id
		}
	}
	if isRU {
		fmt.Fprintf(b, "# Публикация результата отклонена: %s\n\n", titleID)
		fmt.Fprintf(b, "- Кейс: `%s`\n", caseID)
		b.WriteString("\n## Причина отказа\n\n")
		fmt.Fprintf(b, "> %s\n\n", refusal.Error())
		b.WriteString("Сохранённый вывод не прошёл повторный допуск, поэтому вердикт, область эксплуатации, критичность и рекомендации по устранению не публикуются: отклонённое заключение нельзя переинтерпретировать как ответ на запрос.\n")
		return
	}
	fmt.Fprintf(b, "# Publication refused: %s\n\n", titleID)
	fmt.Fprintf(b, "- Case: `%s`\n", caseID)
	b.WriteString("\n## Refusal reason\n\n")
	fmt.Fprintf(b, "> %s\n\n", refusal.Error())
	b.WriteString("The saved conclusion did not re-admit, so no verdict, exploitability scope, severity or remediation is published: a refused conclusion must not be reinterpreted as an answer to the request.\n")
}

// ---- Tracker rationale -----------------------------------------------------

// requestedRationale renders the request-level rationale used by tracker
// sinks. It is Russian, matching TrackerRationale's existing contract, and it
// names the witness and the failure/external distinction explicitly. The
// derived axes are appended last so no existing tracker sentence changes.
func (p publication) requestedRationale() string {
	base := p.requestedRationaleBody()
	if base == "" {
		return base
	}
	if axes := p.requestedAxesRationale(); axes != "" {
		return base + "\n" + axes
	}
	return base
}

// requestedAxesRationale renders the projected pair and the independently
// assessed records beside it. A record-level negative never reads as closing a
// CVE subject.
func (p publication) requestedAxesRationale() string {
	var b strings.Builder
	row, hasRequested := p.axes.TargetRequested()
	if hasRequested {
		b.WriteString("Оси оценки запроса:\n")
		fmt.Fprintf(&b, "- уязвимый код/версия в оцениваемой сборке: %s\n",
			axisVulnerabilityText(row.VulnerableCodeInBuild, true))
		fmt.Fprintf(&b, "- эксплуатируемость: %s\n", axisExploitabilityText(row, true))
	}
	if len(p.axes.Records) > 0 {
		b.WriteString("Независимо оценённые записи:\n")
		for _, record := range p.axes.Records {
			fmt.Fprintf(&b, "- `%s` (`%s`, профиль `%s`): vulnerable_code_in_build=%s; exploitable=%s\n",
				record.SubjectID, record.AssessmentID, record.Profile,
				record.VulnerableCodeInBuild, record.Exploitable)
		}
		if req := p.requested; req != nil && req.RequestedKind == domain.ScopeCVE &&
			req.Outcome != domain.OutcomeDecided {
			b.WriteString("Отрицательный результат отдельной записи не закрывает запрошенный CVE.\n")
		}
	}
	return b.String()
}

func (p publication) requestedRationaleBody() string {
	req := p.requested
	if req == nil {
		return ""
	}
	var b strings.Builder
	switch req.Outcome {
	case domain.OutcomeFailed:
		b.WriteString("Результат запроса: FAILED (анализ не завершён, вердикт не вынесен).\n\n")
		fmt.Fprintf(&b, "Причина: %s\n\n", req.Reason)
		if len(req.Gaps) > 0 {
			b.WriteString("Незавершённые обязательства:\n")
			for _, gap := range req.Gaps {
				fmt.Fprintf(&b, "- `%s`/`%s`/`%s`: %s\n", gap.Owner, gap.Code, gap.Obligation, gap.Message)
			}
			b.WriteString("\n")
		}
		b.WriteString("Это не безопасное состояние: отрицательного вывода нет, Evidence и claims остаются UNKNOWN.\n")
		return b.String()
	case domain.OutcomeExternal:
		b.WriteString("Результат запроса: EXTERNAL_DEPENDENCY (вердикт `INCONCLUSIVE`).\n\n")
		fmt.Fprintf(&b, "Причина: %s\n\n", req.Reason)
		b.WriteString("Недостающие факты:\n")
		for _, dep := range req.ExternalDependencies {
			fmt.Fprintf(&b, "- %s (обязательство `%s`); что решит вопрос: %s\n",
				dep.MissingFact, dep.AffectedObligation, dep.ResolvingEvidence)
		}
		b.WriteString("\nЭто не отказ анализа: при указанном свидетельстве ответ изменится.\n")
		return b.String()
	}

	if req.Verdict == domain.VerdictExploitable {
		b.WriteString("Уязвимость подтверждена и эксплуатируема.\n\n")
		if len(p.witnesses) > 0 {
			b.WriteString("Происхождение доказательства:\n")
			for _, witness := range p.witnesses {
				fmt.Fprintf(&b, "- %s (`%s`, %s): запись `%s`\n",
					p.originLabelRU(witness.Origin), witness.Origin.AssessmentID,
					witness.Assessment.Vulnerability.ID, witness.Origin.Record.DocumentDigest)
			}
			b.WriteString("\n")
		}
		if scope := req.ExploitabilityScope; scope != "" {
			fmt.Fprintf(&b, "Область эксплуатации: `%s` — %s. Ограничение: %s\n\n",
				scope, scopeBoundaryText(scope, true), localizeScopeLimitation(scope, true))
		}
		targets := p.targets()
		if len(targets) > 0 {
			b.WriteString("Требуется исправление (по записи-свидетелю):\n")
			for _, target := range targets {
				if target.FixedVersion == "" {
					fmt.Fprintf(&b, "- `%s`: опубликованного исправления нет (текущая `%s`), примените компенсирующие меры.\n",
						target.Module, target.ResolvedVersion)
					continue
				}
				fmt.Fprintf(&b, "- `%s`: `%s` → `%s` (`go get %s@%s`).\n",
					target.Module, target.ResolvedVersion, target.FixedVersion, target.Module, target.FixedVersion)
			}
			b.WriteString("\n")
		}
		if summary := p.prioritySummary(true); summary != "" {
			b.WriteString(summary + "\n")
		}
		return b.String()
	}

	fmt.Fprintf(&b, "Результат запроса: %s.\n\n", req.Verdict)
	fmt.Fprintf(&b, "Причина: %s\n\n", req.Reason)
	if basis := req.CorpusNegativeBasis; basis != nil {
		b.WriteString(basis.BoundaryStatement + "\n")
	}
	return b.String()
}

// ---- exports: one identity table for both schemas -------------------------

// exportEntry is one vulnerability identity in an export document. The
// requested identity, the primary record and every candidate record are
// separate entries with separate facts; identical identities are deduplicated
// so a single record never appears twice with two different conclusions.
type exportEntry struct {
	// Identity is the vulnerability id this entry publishes. A related record's
	// id is never an alias of the requested identity: it stays its own entry.
	Identity string
	// Role is "requested", "primary" or "candidate".
	Role string
	// Record is the assessed record this entry publishes (the primary case for
	// the requested identity and for the primary role).
	Record      *domain.AnalysisCase
	Outcome     domain.AssessmentOutcome
	Verdict     domain.Verdict
	Reason      string
	Scope       domain.ExploitabilityScope
	Profile     domain.ThreatProfile
	Build       domain.BuildContext
	Limitations []string
	Corpus      *domain.CorpusNegativeBasis
	External    []domain.ExternalDependency
	Gaps        []domain.AnalysisGap
	Witnesses   []finding.WitnessView
}

func (e exportEntry) requested() bool { return e.Role == "requested" }

// exportEntries projects the requested finding into export identities. The
// requested identity comes first; the primary record and each candidate follow
// only when their own id is not already published.
func exportEntries(p publication) []exportEntry {
	if p.requested == nil {
		return nil
	}
	req := p.requested
	entries := []exportEntry{{
		Identity:    req.RequestedID,
		Role:        "requested",
		Record:      p.primary,
		Outcome:     req.Outcome,
		Verdict:     req.Verdict,
		Reason:      req.Reason,
		Scope:       req.ExploitabilityScope,
		Profile:     req.Profile,
		Build:       req.Build,
		Limitations: req.Limitations,
		Corpus:      req.CorpusNegativeBasis,
		External:    req.ExternalDependencies,
		Gaps:        req.Gaps,
		Witnesses:   p.witnesses,
	}}
	seen := map[string]bool{strings.ToUpper(req.RequestedID): true}
	addRecord := func(record *domain.AnalysisCase, role string) {
		if record == nil {
			return
		}
		identity := record.Vulnerability.ID
		if strings.TrimSpace(identity) == "" {
			return
		}
		key := strings.ToUpper(identity)
		if seen[key] {
			return
		}
		seen[key] = true
		entry := exportEntry{Identity: identity, Role: role, Record: record}
		if assessment, ok := actualAssessment(record); ok {
			entry.Outcome = assessment.Result.Outcome
			if assessment.Result.Verdict != nil {
				entry.Verdict = assessment.Result.Verdict.Verdict
				entry.Reason = assessment.Result.Verdict.Reason
				entry.Scope = assessment.Result.Verdict.ExploitabilityScope
			}
			entry.Profile = assessment.Profile
			entry.Build = assessment.Build
			entry.Gaps = assessment.Result.Gaps
			entry.Limitations = assessment.Result.Limitations
		}
		entries = append(entries, entry)
	}
	addRecord(p.primary, "primary")
	if p.primary != nil && p.primary.RelatedDiscovery != nil {
		for _, candidate := range p.primary.RelatedDiscovery.Candidates {
			addRecord(p.recordForPin(candidate.Record), "candidate")
		}
	}
	return entries
}

// exportState is the schema-neutral projection of one export entry's status,
// justification and explanation. Both exporters render from it, so the two
// documents cannot disagree about what was decided.
type exportState struct {
	// Status is the OpenVEX statement status.
	Status string
	// State is the CycloneDX analysis.state.
	State string
	// Justification is the OpenVEX justification vocabulary value.
	Justification string
	// CDXJustification is the CycloneDX justification vocabulary value.
	CDXJustification string
	// Explanation is the shared consumer-facing explanation.
	Explanation string
	// Impact is the OpenVEX impact_statement.
	Impact string
	// Action is the OpenVEX action_statement.
	Action string
}

// exportStateFor maps one entry's classified outcome to both schema
// vocabularies. A failure and an external dependency may share
// under_investigation/in_triage, but their Explanation and Action differ and
// neither ever becomes not_affected.
func (p publication) exportStateFor(entry exportEntry) exportState {
	metadata := p.exportMetadata(entry)
	switch entry.Outcome {
	case domain.OutcomeFailed:
		return exportState{
			Status:      "under_investigation",
			State:       "in_triage",
			Explanation: "analysis_failed: " + joinStatements(entry.Reason, p.failureCauses(entry), metadata),
			Action:      "analysis_failed: no verdict was published; resolve the named analysis gaps and re-run. Diagnostic report written for `" + entry.Identity + "`.",
		}
	case domain.OutcomeExternal:
		return exportState{
			Status:      "under_investigation",
			State:       "in_triage",
			Explanation: "external_dependency: " + joinStatements(entry.Reason, p.externalFacts(entry), metadata),
			Action:      "external_dependency: supply the named missing fact to decide — the analysis is not failed: " + p.externalFacts(entry),
		}
	}
	switch entry.Verdict {
	case domain.VerdictExploitable:
		state := exportState{
			Status:      "affected",
			State:       "exploitable",
			Explanation: joinStatements(entry.Reason, metadata),
			Impact:      joinStatements(entry.Reason, metadata),
		}
		if entry.requested() {
			state.Action = p.requestedAction(entry)
		} else {
			state.Action = affectedActionStatement(entry.Record)
			if scope := entry.Scope; scope != "" {
				state.Action += " (exploitability scope " + string(scope) + "; limitation: " + localizeScopeLimitation(scope, false) + ")"
			}
		}
		return state
	case domain.VerdictNotAffected:
		proof := p.notAffectedProof(entry)
		return exportState{
			Status:           "not_affected",
			State:            "not_affected",
			Justification:    proof.Vex,
			CDXJustification: proof.CDX,
			Explanation:      joinStatements(entry.Reason, p.corpusBoundary(entry), metadata),
			Impact:           joinStatements(entry.Reason, p.corpusBoundary(entry), metadata),
		}
	case domain.VerdictNoExploitPathFound:
		// The proof, not the verdict, selects the justification: NEPF is
		// also earned by configuration, environment, guard and input
		// falsifiers where vulnerable code still executes.
		proof := noExploitPathProof(entry.Record)
		impact := entry.Reason
		if basis := noExploitPathBasis(entry.Record); basis != "" {
			impact = entry.Reason + " (" + basis + ")"
		}
		return exportState{
			Status:           "not_affected",
			State:            "not_affected",
			Justification:    proof.Vex,
			CDXJustification: proof.CDX,
			Explanation:      joinStatements(impact, metadata),
			Impact:           joinStatements(impact, metadata),
		}
	default:
		return exportState{
			Status:      "under_investigation",
			State:       "in_triage",
			Explanation: joinStatements("no requested outcome was recorded", metadata),
			Action:      "analysis incomplete — manual review required",
		}
	}
}

// exportMetadata carries the profile, build, scope and limitations that the
// schema's text fields must state, because neither VEX vocabulary has a field
// for them. The structured companion is report.json.
func (p publication) exportMetadata(entry exportEntry) string {
	parts := []string{"requested identity: " + entry.Identity, "role: " + entry.Role}
	if entry.Profile != "" {
		parts = append(parts, "profile: "+string(entry.Profile))
	}
	if build := formatBuildContext(entry.Build, false); build != "" {
		parts = append(parts, "build: "+build)
	}
	if entry.Scope != "" {
		parts = append(parts, "exploitability scope: "+string(entry.Scope))
	}
	if entry.requested() {
		for _, witness := range entry.Witnesses {
			origin := p.originLabel(witness.Origin) + " (`" + string(witness.Origin.AssessmentID) + "`, record `" +
				witness.Origin.Record.RecordID + "` " + witness.Origin.Record.DocumentDigest + ")"
			parts = append(parts, "proof origin: "+origin)
			if witness.Origin.AttributionID != "" {
				if attribution := p.attributionForPin(witness.Origin.Record); attribution != nil {
					source := "attribution " + attribution.ID + " (" + string(attribution.Basis) +
						", " + string(attribution.Admission) + ")"
					if attribution.PublisherAdvisory != "" {
						source += ", publisher advisory " + attribution.PublisherAdvisory
					}
					if attribution.SourceURI != "" {
						source += ", source " + attribution.SourceURI
					}
					parts = append(parts, source)
				}
			}
		}
	} else if entry.Record != nil {
		parts = append(parts, "record-level assessment of `"+entry.Identity+"`")
		if pin := entry.Record.RecordPin; pin != nil {
			parts = append(parts, "record `"+pin.RecordID+"` ("+pin.DocumentDigest+")")
		}
	}
	if len(entry.Limitations) > 0 {
		parts = append(parts, "limitations: "+strings.Join(applyLocalization(entry.Limitations, false), "; "))
	}
	return strings.Join(parts, "; ")
}

func applyLocalization(values []string, isRU bool) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, localizeLimitation(value, isRU))
	}
	return out
}

// failureCauses renders a failed entry's typed causes so a consumer can act on
// them without parsing prose.
func (p publication) failureCauses(entry exportEntry) string {
	if len(entry.Gaps) == 0 {
		return "no typed failure cause was recorded"
	}
	parts := make([]string, 0, len(entry.Gaps))
	for _, gap := range entry.Gaps {
		cause := string(gap.Owner) + "/" + string(gap.Code) + "/" + string(gap.Obligation)
		if gap.Message != "" {
			cause += ": " + gap.Message
		}
		parts = append(parts, cause)
	}
	return "typed causes: " + strings.Join(parts, "; ")
}

// externalFacts renders an external entry's evidence-bound missing facts.
func (p publication) externalFacts(entry exportEntry) string {
	if len(entry.External) == 0 {
		return "the recorded external dependency carries no named missing fact"
	}
	parts := make([]string, 0, len(entry.External))
	for _, dependency := range entry.External {
		text := dependency.MissingFact + " (obligation " + string(dependency.AffectedObligation) + ")"
		if dependency.ResolvingEvidence != "" {
			text += "; resolving evidence: " + dependency.ResolvingEvidence
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "; ")
}

// corpusBoundary states the Addendum A boundary verbatim when the negative is
// corpus-bounded. It returns "" for an exact-record negative: a corpus boundary
// that was never declared must not be implied.
func (p publication) corpusBoundary(entry exportEntry) string {
	if entry.Corpus == nil {
		return ""
	}
	return entry.Corpus.BoundaryStatement
}

// proofJustification is the pair of schema justifications one admitted proof
// supports. An empty value means no vocabulary entry truthfully describes the
// proof; the exported explanation carries it instead of an invented claim.
type proofJustification struct {
	// Vex is the OpenVEX 0.2.0 justification.
	Vex string
	// CDX is the CycloneDX 1.5 justification.
	CDX string
}

// affectedProofJustification derives the justification from the affected-chain
// fact that closed applicability, not from the verdict alone. A module-graph
// absence is a component absence; every other proved negative — outside the
// affected version range, package/import exclusion, build restriction and
// verified implementation absence — means the component is present but the
// vulnerable code is not.
//
// A NOT_AFFECTED record whose affected facts prove nothing gets no enum: the
// explanation must not be replaced by an invented absence assertion.
func affectedProofJustification(c *domain.AnalysisCase) proofJustification {
	if c == nil || c.Affected == nil {
		return proofJustification{}
	}
	switch {
	case c.Affected.ModulePresent == domain.ClaimFalse:
		return proofJustification{Vex: "component_not_present", CDX: "code_not_present"}
	case c.Affected.VersionAffected == domain.ClaimFalse,
		c.Affected.PackagePresent == domain.ClaimFalse,
		c.Affected.BuildRelevant == domain.ClaimFalse,
		c.Affected.VulnerableImplementationPresent == domain.ClaimFalse:
		return proofJustification{Vex: "vulnerable_code_not_present", CDX: "code_not_present"}
	}
	return proofJustification{}
}

// groundingClaim returns the verified FALSE claim that grounded the case's
// NO_EXPLOIT_PATH_FOUND verdict. The verdict names the condition; the claim
// carries the falsifier, its explanation and its verification, none of which
// are reconstructed from the verdict text.
func groundingClaim(c *domain.AnalysisCase) (domain.Claim, bool) {
	if c == nil || c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		return domain.Claim{}, false
	}
	claims := c.Claims
	if assessment, ok := actualAssessment(c); ok && len(assessment.Claims) > 0 {
		claims = assessment.Claims
	}
	want := make(map[domain.ConditionID]bool, len(c.Verdict.ConditionIDs))
	for _, id := range c.Verdict.ConditionIDs {
		want[id] = true
	}
	for _, claim := range claims {
		if !want[claim.ConditionID] || claim.Result != domain.ClaimFalse {
			continue
		}
		// A FALSE claim without an independent VERIFIED re-derivation is a
		// candidate, not proof; no justification may be named from it.
		if claim.NegativeVerification == nil ||
			claim.NegativeVerification.Status != domain.NegativeVerified {
			continue
		}
		return claim, true
	}
	return domain.Claim{}, false
}

// noExploitPathProof selects the justification of a negative verdict from the
// proof that actually grounded it: the grounding claim's falsifier and the
// recorded trust basis. NEPF is earned by reachability, package/symbol
// absence, configuration, environment, guards, input provenance and trust
// falsifiers; defaulting all of them to unreachability overclaims.
func noExploitPathProof(c *domain.AnalysisCase) proofJustification {
	if c == nil || c.Verdict == nil {
		return proofJustification{}
	}
	claim, ok := groundingClaim(c)
	if !ok {
		// A persisted legacy verdict may carry only the recorded trust basis
		// (the claim itself was not preserved). The basis is authoritative
		// proof provenance, not an invented fact, so it still selects the
		// trust/perimeter entry. With no recorded basis there is no proof to
		// name: the explanation must not invent one.
		if c.Verdict.GroundBasis == "" {
			return proofJustification{}
		}
		return trustBasisProof(c.Verdict.GroundBasis)
	}
	return claimProofJustification(claim, c.Verdict.GroundBasis)
}

// trustBasisProof maps a recorded NEPF trust basis to the two vocabularies.
func trustBasisProof(basis string) proofJustification {
	switch basis {
	case "", domain.BasisDeclaredTrust, domain.BasisAutoPerimeter:
		// An unrecorded basis keeps its pre-existing declared-trust meaning:
		// this is an operator/deployment assumption, not a code-level
		// reachability proof.
		return proofJustification{
			Vex: "vulnerable_code_cannot_be_controlled_by_adversary",
			CDX: "protected_at_perimeter",
		}
	case domain.BasisConfigOrigin:
		return proofJustification{
			Vex: "vulnerable_code_cannot_be_controlled_by_adversary",
			CDX: "protected_by_mitigating_control",
		}
	default:
		return proofJustification{}
	}
}

// claimProofJustification maps one verified FALSE claim to the schema
// vocabularies. It never upgrades a proof a vocabulary entry does not describe:
// configuration and environment falsifiers keep an explanation-only OpenVEX
// statement, and an unrecognised falsifier gets no enum at all.
func claimProofJustification(claim domain.Claim, groundBasis string) proofJustification {
	if claim.Falsifier == domain.FalsifierTrustedInfrastructure {
		return trustBasisProof(groundBasis)
	}
	switch claim.Falsifier {
	case domain.FalsifierPackageAbsent, domain.FalsifierLocusPackageAbsent:
		// The component may still be in the module graph; the affected
		// code is not linked into the product build.
		return proofJustification{Vex: "vulnerable_code_not_present", CDX: "code_not_present"}
	case domain.FalsifierMissingSourceSymbol:
		return proofJustification{Vex: "vulnerable_code_not_present", CDX: "code_not_present"}
	case domain.FalsifierLocusFunctionUnreached,
		domain.FalsifierDeclaredSymbolUnreached,
		domain.FalsifierGovulncheckSilence,
		domain.FalsifierNoModuleUsage,
		domain.FalsifierUnreachedExportedSubject,
		domain.FalsifierNoProductReader,
		domain.FalsifierMissingPairMember:
		return proofJustification{Vex: "vulnerable_code_not_in_execute_path", CDX: "code_not_reachable"}
	case domain.FalsifierConfigGatedOff,
		domain.FalsifierSafeConfigAssignment,
		domain.FalsifierSafeConfigKey,
		domain.FalsifierZeroValueConfig:
		// The vulnerable code is present and may execute; the configuration
		// it requires is absent. OpenVEX has no exact entry, so the impact
		// statement must carry the proof.
		return proofJustification{CDX: "requires_configuration"}
	case domain.FalsifierProtocolRoleMismatch,
		domain.FalsifierSnapshotFactMismatch:
		return proofJustification{CDX: "requires_environment"}
	case domain.FalsifierLoopbackOnly:
		return proofJustification{
			Vex: "vulnerable_code_cannot_be_controlled_by_adversary",
			CDX: "protected_at_perimeter",
		}
	case domain.FalsifierGuards:
		// A bound guard prevents the adversary from controlling the value
		// that reaches the vulnerable operation. It is not OpenVEX's
		// stronger inline_mitigations_already_exist: the guard's coverage
		// is path-specific and could be subverted by a future call path.
		return proofJustification{
			Vex: "vulnerable_code_cannot_be_controlled_by_adversary",
			CDX: "protected_by_mitigating_control",
		}
	case domain.FalsifierConstantOrGeneratedInput:
		// Vulnerable code executes, but the triggering value has no
		// adversary-controlled origin. CycloneDX has no provenance entry
		// and this is not a mitigating control, so only the detail carries
		// the proof.
		return proofJustification{Vex: "vulnerable_code_cannot_be_controlled_by_adversary"}
	default:
		return proofJustification{}
	}
}

// noExploitPathBasis renders the admitted proof behind a negative verdict so an
// export that cannot select a vocabulary entry still states an accurate reason.
// The trust/perimeter basis keeps its policy wording; code-level falsifiers use
// the grounding claim's own explanation.
func noExploitPathBasis(c *domain.AnalysisCase) string {
	if c == nil || c.Verdict == nil {
		return ""
	}
	claim, ok := groundingClaim(c)
	if !ok {
		if c.Verdict.GroundBasis != "" {
			return groundBasisText(c.Verdict.GroundBasis)
		}
		return ""
	}
	if claim.Falsifier == domain.FalsifierTrustedInfrastructure {
		return groundBasisText(c.Verdict.GroundBasis)
	}
	if explanation := strings.TrimSpace(claim.Explanation); explanation != "" {
		return explanation
	}
	return "grounded by the verified `" + claim.Falsifier + "` falsifier"
}

// notAffectedProof selects the justification of a NOT_AFFECTED export entry.
// A corpus-bounded negative aggregates its candidates' actual absence proofs;
// an exact negative uses the record's own affected facts.
func (p publication) notAffectedProof(entry exportEntry) proofJustification {
	if entry.Corpus != nil {
		return p.corpusNegativeProof(entry.Corpus)
	}
	return affectedProofJustification(entry.Record)
}

// corpusNegativeProof aggregates the assessed candidates' actual absence
// proofs. Corpus completeness supplies a boundary, never a semantic reason: an
// empty corpus, a missing assessment, or a candidate whose proof is not an
// absence proof yields no justification at all, and the caller carries the
// admitted explanation plus the verbatim corpus boundary instead.
func (p publication) corpusNegativeProof(basis *domain.CorpusNegativeBasis) proofJustification {
	if basis == nil || len(basis.AssessedRecords) == 0 {
		return proofJustification{}
	}
	allComponentAbsent := true
	for _, assessed := range basis.AssessedRecords {
		if assessed.Verdict != domain.VerdictNotAffected {
			return proofJustification{}
		}
		record := p.recordForPin(assessed.Record)
		if record == nil {
			return proofJustification{}
		}
		proof := affectedProofJustification(record)
		switch proof.Vex {
		case "component_not_present":
			// Component absence a fortiori proves the vulnerable code
			// absent, so it does not weaken the aggregate.
		case "vulnerable_code_not_present":
			allComponentAbsent = false
		default:
			return proofJustification{}
		}
	}
	if allComponentAbsent {
		return proofJustification{Vex: "component_not_present", CDX: "code_not_present"}
	}
	return proofJustification{Vex: "vulnerable_code_not_present", CDX: "code_not_present"}
}

// requestedAction is the OpenVEX/CycloneDX action for a composed positive: the
// witness records' own published fixes, never the primary record's.
func (p publication) requestedAction(entry exportEntry) string {
	targets := p.targets()
	if len(targets) == 0 {
		return "apply a compensating control and update the affected dependency when a fix is available"
	}
	parts := make([]string, 0, len(targets))
	for _, target := range targets {
		origin := p.originLabel(target.Origin)
		if target.FixedVersion == "" {
			parts = append(parts, fmt.Sprintf("no fixed version is published for `%s` (%s; %s); apply a compensating control",
				target.Module, origin, target.Origin.Record.RecordID))
			continue
		}
		current := ""
		if target.ResolvedVersion != "" {
			current = " from `" + target.ResolvedVersion + "`"
		}
		parts = append(parts, fmt.Sprintf("upgrade `%s`%s to `%s` or later (`go get %s@%s && go mod tidy`), or apply a compensating control (%s)",
			target.Module, current, target.FixedVersion, target.Module, target.FixedVersion, origin))
	}
	return strings.Join(parts, "; ")
}

// exportComponent is one component identity an export document publishes.
type exportComponent struct {
	Name string
	PURL string
}

// componentsFor renders a record's own affected module as a component
// identity. A record without a named module contributes none.
func componentsFor(record *domain.AnalysisCase) []exportComponent {
	if record == nil {
		return nil
	}
	module := recordModule(record)
	if module == "" {
		return nil
	}
	purl := "pkg:golang/" + module
	if version := resolvedVersion(record); version != "" {
		purl += "@" + version
	}
	return []exportComponent{{Name: module, PURL: purl}}
}

// witnessComponents renders every witness record's own module, deduplicated.
func witnessComponents(witnesses []finding.WitnessView) []exportComponent {
	var out []exportComponent
	seen := make(map[string]bool, len(witnesses))
	for _, witness := range witnesses {
		for _, component := range componentsFor(witness.Assessment) {
			if seen[component.PURL] {
				continue
			}
			seen[component.PURL] = true
			out = append(out, component)
		}
	}
	return out
}

// writePrimaryRecordNote states the primary record's own recorded result. It
// exists so the primary's assessment, which is rendered unchanged below the
// requested finding, can never be mistaken for the request-level answer. Its
// projected axes are the record's own facts, never the requested answer's.
func writePrimaryRecordNote(b *strings.Builder, c *domain.AnalysisCase, axes *finding.AssessmentAxes, isRU bool) {
	if c == nil {
		return
	}
	assessment, ok := actualAssessment(c)
	if !ok {
		if isRU {
			fmt.Fprintf(b, "У первичной записи `%s` нет оценки целевого профиля: её анализ не завершён.\n\n", c.ID)
		} else {
			fmt.Fprintf(b, "Primary record `%s` carries no target-actual profile assessment: its own analysis did not finish.\n\n", c.ID)
		}
		return
	}
	if assessment.Result.Verdict == nil {
		if isRU {
			fmt.Fprintf(b, "Запись `%s`, профиль `%s`: `%s`, вердикт не вынесен.\n\n", c.ID, assessment.Profile, assessment.Result.Outcome)
		} else {
			fmt.Fprintf(b, "Record `%s`, profile `%s`: `%s`, no verdict was earned.\n\n", c.ID, assessment.Profile, assessment.Result.Outcome)
		}
		return
	}
	if isRU {
		fmt.Fprintf(b, "Запись `%s`, профиль `%s`: `%s` / `%s` — собственный результат записи, а не ответ на запрос.\n\n",
			c.ID, assessment.Profile, assessment.Result.Outcome, assessment.Result.Verdict.Verdict)
	} else {
		fmt.Fprintf(b, "Record `%s`, profile `%s`: `%s` / `%s` — the record's own result, not the requested answer.\n\n",
			c.ID, assessment.Profile, assessment.Result.Outcome, assessment.Result.Verdict.Verdict)
	}
	if reason := strings.TrimSpace(assessment.Result.Verdict.Reason); reason != "" {
		fmt.Fprintf(b, "> %s\n\n", reason)
	}
	if row, ok := axisRowForRecord(axes, c); ok {
		if isRU {
			fmt.Fprintf(b, "- уязвимый код/версия в оцениваемой сборке: %s\n", axisVulnerabilityText(row.VulnerableCodeInBuild, true))
			fmt.Fprintf(b, "- эксплуатируемость: %s\n\n", axisExploitabilityText(row, true))
		} else {
			fmt.Fprintf(b, "- vulnerable code/version in assessed build: %s\n", axisVulnerabilityText(row.VulnerableCodeInBuild, false))
			fmt.Fprintf(b, "- exploitable in assessed scope: %s\n\n", axisExploitabilityText(row, false))
		}
	}
}
