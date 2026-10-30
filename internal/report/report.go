// Package report renders the AnalysisCase into the persisted JSON artifact
// and a human-readable/tracker-ready markdown summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/finding"
	"github.com/davniy/izyan/internal/fixbinding"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/risk"
)

// Write stores report.json, report.md, openvex.json and cyclonedx.json
// inside dir. report.json is the companion structured record every VEX text
// field refers to: scope, profile, build, limitations, corpus boundary and the
// requested-finding envelope travel structurally there.
//
// A case carrying the requested-finding envelope is re-admitted by
// finding.Project before anything is written; a conclusion the current
// admission no longer supports is refused with an error rather than published.
// A legacy case keeps the historical single-assessment artifacts.
func Write(dir string, c *domain.AnalysisCase) error {
	if err := validateDeclaredAssumptionRefs(c); err != nil {
		return err
	}
	pub := publish(c)
	if pub.refusal != nil {
		return fmt.Errorf("write report: %w", pub.refusal)
	}
	// Persist the current conclusions, not refused historical ones: the
	// admission gates are replayed for a legacy single assessment so
	// report.json, the Markdown files and both VEX documents agree.
	// A projected case is already the re-admitted result and is never
	// rewritten here.
	persisted := c
	if pub.legacy() {
		populateUpgradeCompatibility(c)
		persisted = admitNegativeConclusions(c).Case
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jb, err := marshalReport(persisted, pub.axes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), jb, 0o644); err != nil {
		return err
	}
	vb, err := OpenVEX(persisted)
	if err != nil {
		return fmt.Errorf("openvex: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvex.json"), vb, 0o644); err != nil {
		return err
	}
	cb, err := CycloneDX(persisted)
	if err != nil {
		return fmt.Errorf("cyclonedx: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cyclonedx.json"), cb, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(persisted, "ru")), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.en.md"), []byte(Markdown(persisted, "en")), 0o644)
}

// reportDocument wraps the unchanged persisted case with the optional derived
// axes projection. The embedded case keeps its exact serialized shape; the
// projection is additive and the case's own schema never carries it.
type reportDocument struct {
	*domain.AnalysisCase
	AssessmentAxes *finding.AssessmentAxes `json:"assessment_axes,omitempty"`
}

// marshalReport serializes the case as before and appends the derived axes
// when the publication produced them. A legacy case has no projection and
// keeps its historical JSON exactly.
func marshalReport(c *domain.AnalysisCase, axes finding.AssessmentAxes) ([]byte, error) {
	document := reportDocument{AnalysisCase: c}
	if !axes.Empty() {
		document.AssessmentAxes = &axes
	}
	return json.MarshalIndent(document, "", "  ")
}

// validateDeclaredAssumptionRefs enforces the policy/evidence boundary of
// a finished case before any report artifact is written: every
// assumption id a claim, affected result or verdict cites must resolve to
// the loaded declared-assumptions document (a failed channel admits
// nothing), and an assumption id may never also be an evidence id.
func validateDeclaredAssumptionRefs(c *domain.AnalysisCase) error {
	if c == nil {
		return nil
	}
	admitted := map[string]bool{}
	if da := c.DeclaredAssumptions; da != nil && da.LoadError == "" {
		for _, a := range da.Assumptions {
			admitted[a.ID] = true
		}
	}
	evidence := map[string]bool{}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		evidence[string(e.ID)] = true
	}
	if c.Affected != nil {
		for _, id := range c.Affected.EvidenceIDs {
			evidence[string(id)] = true
		}
	}
	check := func(where string, ids []string) error {
		seen := map[string]bool{}
		for _, id := range ids {
			if id == "" || seen[id] {
				return fmt.Errorf("%s: empty or duplicate assumption id %q", where, id)
			}
			seen[id] = true
			if !admitted[id] {
				return fmt.Errorf("%s: assumption %q does not resolve to the loaded declared-assumptions document", where, id)
			}
			if evidence[id] {
				return fmt.Errorf("%s: assumption %q also resolves as evidence — assumptions are policy inputs, not evidence", where, id)
			}
		}
		return nil
	}
	if c.Affected != nil {
		if err := check("affected.assumption_ids", c.Affected.AssumptionIDs); err != nil {
			return err
		}
	}
	for _, cl := range c.Claims {
		if err := check("claims["+string(cl.ID)+"].assumption_ids", cl.AssumptionIDs); err != nil {
			return err
		}
	}
	if c.Verdict != nil {
		if err := check("verdict.assumption_ids", c.Verdict.AssumptionIDs); err != nil {
			return err
		}
	}
	return nil
}

func isRussian(lang ...string) bool {
	if len(lang) > 0 && strings.EqualFold(strings.TrimSpace(lang[0]), "en") {
		return false
	}
	return true
}

// scopeOpenNote is the one sentence every closure surface uses when a
// component-scoped negative fact cannot close the requested advisory.
const scopeOpenNote = "partial advisory scope: a component-level negative does not close the requested advisory identity"

// negativeClosureBlocked reports that the case asserts a negative
// conclusion its recorded advisory scope cannot close: a CVE/alias request
// bound to a partial record, a legacy COMPLETE coverage without structural
// evidence, or no scope at all. The component facts stay intact, but every
// closure surface — rationale, key facts, profiles and the VEX projections
// — must keep the requested scope open. A missing affected/scope metadata
// is not a rendering concern owned elsewhere: it cannot authorize a
// negative export for a non-nil case.
func negativeClosureBlocked(c *domain.AnalysisCase) bool {
	if c == nil || !caseAssertsNegative(c) {
		return false
	}
	return c.Affected == nil || c.Affected.Scope == nil || !c.Affected.Scope.AllowsNegativeClosure()
}

// caseAssertsNegative reports whether the case records a negative (safe)
// conclusion at any level: affected-chain facts, the case verdict, or a
// perimeter profile. Scope admission must re-check every one of them; a
// positive conclusion is not gated by advisory coverage.
func caseAssertsNegative(c *domain.AnalysisCase) bool {
	if c == nil {
		return false
	}
	if c.Affected != nil && c.Affected.HasNegative() {
		return true
	}
	if c.Verdict != nil && isNegativeVerdict(c.Verdict.Verdict) {
		return true
	}
	for _, p := range c.Profiles {
		if isNegativeVerdict(p.Verdict) {
			return true
		}
	}
	return false
}

// requestedAdvisoryID names the identity the run was asked about, for
// scope text that must not silently substitute the resolved record id.
func requestedAdvisoryID(c *domain.AnalysisCase) string {
	if c != nil && c.Affected != nil && c.Affected.Scope != nil && c.Affected.Scope.RequestedID != "" {
		return c.Affected.Scope.RequestedID
	}
	if c != nil && c.Vulnerability.ID != "" {
		return c.Vulnerability.ID
	}
	return "requested advisory"
}

// checkedScopeNames lists the components whose applicability facts were
// actually established, so a component-level negation never reads as
// CVE-wide coverage.
func checkedScopeNames(c *domain.AnalysisCase) string {
	if c == nil || c.Affected == nil {
		return ""
	}
	if len(c.Affected.CheckedModules) > 0 {
		return strings.Join(c.Affected.CheckedModules, ", ")
	}
	return strings.Join(c.Affected.CheckedPackages, ", ")
}

// advisoryScopeCell renders the recorded requested/resolved identity.
func advisoryScopeCell(c *domain.AnalysisCase, isRU bool) string {
	if c == nil || c.Affected == nil || c.Affected.Scope == nil {
		if isRU {
			return "не зафиксирована"
		}
		return "not recorded"
	}
	s := c.Affected.Scope
	cell := "`" + s.RequestedID + "`"
	if s.ResolvedID != "" && s.ResolvedID != s.RequestedID {
		cell += " → `" + s.ResolvedID + "`"
	}
	cell += " (`" + string(s.Kind) + "`, `" + string(s.Coverage) + "`)"
	if s.Basis != "" {
		cell += " — " + s.Basis
	}
	return cell
}

// advisoryExtentCell renders how much of the loaded advisory document the
// analysis actually represented. A missing legacy field reads as unknown
// even when the old coverage field says COMPLETE: legacy coverage is a
// claim, not structural evidence. A full-record claim contradicted by its
// own census (omissions or malformed refs) is flagged instead of trusted.
func advisoryExtentCell(c *domain.AnalysisCase, isRU bool) string {
	if c == nil || c.Affected == nil || c.Affected.Scope == nil || c.Affected.Scope.RecordExtent == "" {
		if isRU {
			return "`UNKNOWN` (структурные данные отсутствуют; legacy coverage не является доказательством)"
		}
		return "`UNKNOWN` (no structural evidence; legacy coverage is not proof)"
	}
	s := c.Affected.Scope
	extent := "`" + string(s.RecordExtent) + "`"
	if inv := s.RecordInventory; inv != nil {
		if err := inv.Validate(s.ResolvedID); err != nil {
			if isRU {
				return extent + " (перепись не проходит структурную проверку — не является доказательством)"
			}
			return extent + " (census fails structural validation — not proof)"
		}
		if s.RecordExtent == domain.RecordExtentFullRecord &&
			(len(inv.RepresentedRefs) != inv.AffectedEntryCount || len(inv.OmittedRefs) != 0) {
			if isRU {
				return extent + " (не согласуется с переписью: есть пропущенные entries)"
			}
			return extent + " (inconsistent with the census: entries are omitted)"
		}
	}
	return extent
}

// advisoryCensusCell renders the original affected[] census: how many
// entries the loaded record declared, how many the analysis represented,
// and how many it omitted. A missing, invalid or unbound inventory reads
// as unknown instead of being reconstructed from module lists.
func advisoryCensusCell(c *domain.AnalysisCase, isRU bool) string {
	if c == nil || c.Affected == nil || c.Affected.Scope == nil || c.Affected.Scope.RecordInventory == nil {
		if isRU {
			return "`unknown` (структурная перепись отсутствует)"
		}
		return "`unknown` (no structural census recorded)"
	}
	s := c.Affected.Scope
	inv := s.RecordInventory
	if err := inv.Validate(s.ResolvedID); err != nil {
		if isRU {
			return "`unknown` (перепись не проходит структурную проверку)"
		}
		return "`unknown` (census fails structural validation)"
	}
	if isRU {
		return fmt.Sprintf("всего %d, представлено %d, пропущено %d",
			inv.AffectedEntryCount, len(inv.RepresentedRefs), len(inv.OmittedRefs))
	}
	return fmt.Sprintf("%d entries: %d represented, %d omitted",
		inv.AffectedEntryCount, len(inv.RepresentedRefs), len(inv.OmittedRefs))
}

// negativeClosureCell states whether a negative fact may close the
// requested identity, and names the checked subset when it may not.
func negativeClosureCell(c *domain.AnalysisCase, isRU bool) string {
	if c == nil || c.Affected == nil || c.Affected.Scope == nil {
		if isRU {
			return "не зафиксировано — закрытие отрицательного вывода не подтверждено"
		}
		return "not recorded — negative closure is not established"
	}
	if !negativeClosureBlocked(c) {
		if isRU {
			return "разрешено: точная запись advisory с полным покрытием объявленных entries"
		}
		return "allowed: exact advisory entry with complete declared-entry coverage"
	}
	checked := checkedScopeNames(c)
	if isRU {
		if checked != "" {
			return fmt.Sprintf("запрещено: область неполная или неизвестная — проверено только `%s`; компонентный факт не закрывает `%s`",
				checked, requestedAdvisoryID(c))
		}
		return fmt.Sprintf("запрещено: область неполная или неизвестная — запрошенная область `%s` не закрыта",
			requestedAdvisoryID(c))
	}
	if checked != "" {
		return fmt.Sprintf("blocked: partial or unknown scope — only `%s` was checked; a component fact does not close `%s`",
			checked, requestedAdvisoryID(c))
	}
	return fmt.Sprintf("blocked: partial or unknown scope — requested scope `%s` is not closed",
		requestedAdvisoryID(c))
}

// componentFactText states the single affected-chain fact that is FALSE,
// without generalising it to the whole advisory.
func componentFactText(a *domain.AffectedResult) string {
	if a == nil {
		return "не подтверждает применимость уязвимости"
	}
	switch {
	case a.ModulePresent == domain.ClaimFalse:
		return "не входит в граф зависимостей продукта"
	case a.VersionAffected == domain.ClaimFalse:
		return "находится вне уязвимого диапазона"
	case a.PackagePresent == domain.ClaimFalse:
		return "уязвимый пакет отсутствует в сборке"
	case a.BuildRelevant == domain.ClaimFalse:
		return "пакеты ограничены другой платформой сборки"
	case a.VulnerableImplementationPresent == domain.ClaimFalse:
		return "уязвимая реализация отсутствует в целевой сборке"
	default:
		return "не подтверждает применимость уязвимости"
	}
}

// conditionNecessity names a condition's current role in the exploit
// model. A condition demoted by review keeps its verified claim but stops
// gating the verdict, so the report must never read that repair as a
// refutation of the underlying fact.
func conditionNecessity(c *domain.AnalysisCase, id domain.ConditionID, isRU bool) string {
	if c == nil || c.Exploit == nil {
		return "—"
	}
	for _, cond := range c.Exploit.MandatoryConditions {
		if cond.ID == id {
			if isRU {
				return "обязательное (mandatory)"
			}
			return "mandatory"
		}
	}
	for _, cond := range c.Exploit.SupportingFactors {
		if cond.ID == id {
			if isRU {
				return "сопутствующее (supporting)"
			}
			return "supporting"
		}
	}
	return "—"
}

var verdictReasonRU = map[string]string{
	"mandatory exploit condition is proven false":                               "Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)",
	"all mandatory exploit conditions are satisfied":                            "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
	"all mandatory conditions met":                                              "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
	"vulnerable module is not part of the product dependency graph":             "Уязвимый модуль не входит в граф зависимостей продукта",
	"resolved dependency version is outside affected range":                     "Разрешённая версия зависимости находится вне уязвимого диапазона",
	"resolved version outside affected range":                                   "Разрешённая версия библиотеки находится вне уязвимого диапазона",
	"affected package is not imported by the product build":                     "Уязвимый пакет не импортируется в сборке продукта",
	"package is not linked in build":                                            "Уязвимый пакет не слинкован в сборке продукта",
	"affected packages are constrained to other platforms/build configurations": "Уязвимые пакеты ограничены другими платформами или конфигурациями сборки",
	"no exploit conditions met":                                                 "Ни одно условие эксплуатации не выполнено",
	"locus packages absent from build graph":                                    "Уязвимый код физически не включён в сборку",
	"one or more mandatory exploit conditions remain unresolved":                "Одно или несколько обязательных условий эксплуатации не подтверждены",
}

func localizeVerdictReason(reason string, isRU bool) string {
	if !isRU {
		return reason
	}
	if s, ok := verdictReasonRU[reason]; ok {
		return s
	}

	if strings.HasPrefix(reason, "one or more mandatory exploit conditions remain unresolved:") {
		unresolved := strings.TrimSpace(strings.TrimPrefix(reason, "one or more mandatory exploit conditions remain unresolved:"))
		return "Одно или несколько обязательных условий эксплуатации не подтверждены: " + unresolved
	}
	if strings.HasPrefix(reason, "resolved version ") && strings.Contains(reason, " is outside the affected range") {
		ver := strings.TrimPrefix(reason, "resolved version ")
		ver = strings.TrimSuffix(ver, " is outside the affected range")
		return fmt.Sprintf("Разрешённая версия %s находится вне уязвимого диапазона", ver)
	}
	if strings.HasPrefix(reason, "none of the affected module(s) ") && strings.Contains(reason, " resolve to a product dependency") {
		parts := strings.Split(strings.TrimPrefix(reason, "none of the affected module(s) "), " resolve to a product dependency")
		mods := parts[0]
		return fmt.Sprintf("Ни один из уязвимых модулей %s не входит в зависимости продукта (go list -m all)", mods)
	}
	if strings.HasPrefix(reason, "affected package(s) ") && strings.Contains(reason, " are absent from the product's transitive import closure") {
		parts := strings.Split(strings.TrimPrefix(reason, "affected package(s) "), " are absent from the product's transitive import closure")
		pkgs := parts[0]
		return fmt.Sprintf("Уязвимый пакет(ы) %s отсутствует в транзитивном графе импортов сборки (go list -deps -test ./...) — код не скомпилирован в продукт", pkgs)
	}
	if strings.HasPrefix(reason, "all modeled mandatory conditions are satisfied, but ") {
		return "Все смоделированные обязательные условия выполнены, но часть дефектных точек сбоя (sinks) не разрешена или отсутствует в сборке: модель усечена и не может обосновать положительный вердикт"
	}
	if strings.HasPrefix(reason, "cluster-perimeter verdict rests on a declared trust boundary, but ") {
		return "Вердикт внутрикластерного периметра опирается на объявленную границу доверия, но часть заявленных в advisory функций не разрешена: утверждение оператора не может закрыть несмоделированный путь атаки"
	}
	if strings.HasPrefix(reason, "partial or unknown advisory scope: negative facts for ") {
		rest := strings.TrimPrefix(reason, "partial or unknown advisory scope: negative facts for ")
		parts := strings.Split(rest, " do not establish complete coverage of ")
		if len(parts) == 2 {
			requested := strings.TrimSuffix(parts[1], "; the remaining requested scope is unresolved")
			return fmt.Sprintf("Неполная или неизвестная область advisory: отрицательные факты для %s не покрывают всю запрошенную область %s; оставшаяся область не разрешена", parts[0], requested)
		}
		return "Неполная или неизвестная область advisory: компонентный отрицательный факт не закрывает запрошенную область уязвимости"
	}
	if strings.HasPrefix(reason, "mandatory exploit condition(s) ") &&
		strings.Contains(reason, " carry unresolved high-severity review criticism") {
		parts := strings.SplitN(strings.TrimPrefix(reason, "mandatory exploit condition(s) "), " carry unresolved high-severity review criticism", 2)
		return fmt.Sprintf("Обязательные условия %s содержат неразрешённую критику рецензента высокой важности: ни вердикт об отсутствии пути эксплуатации, ни вердикт об эксплуатации не может опираться на конъюнкцию", parts[0])
	}

	return reason
}

var conditionDescRU = map[string]string{
	"C-REACH":      "Достижимость символов: хотя бы одна из уязвимых функций вызывается в коде продукта",
	"C-PEER-INPUT": "Контроль ввода: параметры уязвимой функции контролируются удалённым клиентом",
	"C-CONSTRAINT": "Нарушение ограничений: удалённый клиент может передать входные данные, вызывающие сбой",
	"C-LOCUS":      "Выполнение уязвимого кода: пакеты дефектного кода входят в граф сборки приложения",
	"C-EXPOSURE":   "Сетевая доступность: наличие открытых сетевых портов или исходящих подключений",
	"C-TLS-VERIFY": "Проверка TLS: отключение проверки сертификатов позволяет передавать трафик без доверенного канала",
}

func localizeConditionDesc(id string, defaultDesc string, isRU bool) string {
	if !isRU {
		return defaultDesc
	}
	if s, ok := conditionDescRU[id]; ok {
		return s
	}
	return defaultDesc
}

func rootCauseRole(role domain.RootCauseRole, isRU bool) string {
	if !isRU {
		return string(role)
	}
	switch role {
	case domain.RootCauseSink:
		return "Точка сбоя / Sink"
	case domain.RootCauseEntrypoint:
		return "Точка входа / Entrypoint"
	case domain.RootCausePropagation:
		return "Распространение / Propagation"
	default:
		return string(role)
	}
}

func rootCauseStatus(status domain.RootCauseStatus, isRU bool) string {
	if !isRU {
		return fmt.Sprintf("`%s`", status)
	}
	switch status {
	case domain.RootCauseResolved:
		return "Определена"
	case domain.RootCauseAmbiguous:
		return "Неоднозначно"
	case domain.RootCauseNotFound:
		return "Не найдена"
	default:
		return fmt.Sprintf("`%s`", status)
	}
}

func localizeAffectedBool(r domain.ClaimResult, isRU bool) string {
	if !isRU {
		return string(r)
	}
	switch r {
	case domain.ClaimTrue:
		return "Да"
	case domain.ClaimFalse:
		return "Нет"
	case domain.ClaimUnknown:
		return "Не определено"
	default:
		if strings.EqualFold(string(r), "true") {
			return "Да"
		}
		if strings.EqualFold(string(r), "false") {
			return "Нет"
		}
		return string(r)
	}
}

func localizeClaimResult(r domain.ClaimResult, isRU bool) string {
	if !isRU {
		return string(r)
	}
	switch r {
	case domain.ClaimTrue:
		return "Подтверждено (TRUE)"
	case domain.ClaimFalse:
		return "Опровергнуто (FALSE)"
	case domain.ClaimUnknown:
		return "Не определено (UNKNOWN)"
	default:
		if strings.EqualFold(string(r), "true") {
			return "Подтверждено (TRUE)"
		}
		if strings.EqualFold(string(r), "false") {
			return "Опровергнуто (FALSE)"
		}
		return string(r)
	}
}

func localizeAddressSource(src string, isRU bool) string {
	if !isRU {
		return src
	}
	switch src {
	case "literal":
		return "литерал"
	case "const":
		return "константа"
	case "config":
		return "конфигурация"
	case "param":
		return "параметр функции"
	case "dynamic":
		return "динамический"
	default:
		if strings.HasPrefix(src, "env:") {
			return "переменная окружения " + strings.TrimPrefix(src, "env:")
		}
		if strings.HasPrefix(src, "flag:") {
			return "флаг " + strings.TrimPrefix(src, "flag:")
		}
		return src
	}
}

func localizeExposureScope(scope string, isRU bool) string {
	if !isRU {
		return scope
	}
	switch scope {
	case "all-interfaces":
		return "все интерфейсы (0.0.0.0)"
	case "loopback":
		return "локальный интерфейс (127.0.0.1)"
	case "static":
		return "статический адрес"
	case "configured":
		return "настроен оператором (configured)"
	case "cluster-internal":
		return "внутрикластерный"
	case "public":
		return "публичный"
	default:
		return scope
	}
}

// govulncheckMeasurement is the report's typed view of the case's
// govulncheck evidence. A run is only treated as a measurement when a typed
// run record with a completed outcome matches the effective build; evidence
// presence, a ToolExecution, or an empty call-path set alone is never read
// as a successful run.
type govulncheckMeasurement struct {
	Record *domain.Evidence
	// Typed is true when at least one govulncheck evidence record carries a
	// typed run outcome.
	Typed bool
	// EvidenceRecorded is true when any govulncheck evidence exists.
	EvidenceRecorded bool
	// ToolExecuted is true when the case's audit trail records a govulncheck
	// invocation. It does not imply that the invocation completed.
	ToolExecuted bool
	// Admitted is true only for a completed typed run whose build context
	// matches the analyzed build and whose output decoded.
	Admitted bool
	Outcome  domain.GovulncheckOutcome
	Coverage domain.GovulncheckCoverage
	// Problem names why no admitted measurement exists.
	Problem string
	// Findings about the analyzed advisory, classified by trace depth. A
	// package/module finding is not symbol reachability.
	FunctionFindings int
	PackageFindings  int
	ModuleFindings   int
	// BoundCallPaths counts recorded call paths bound to this measurement.
	BoundCallPaths int
}

// selectGovulncheckEvidence applies the evaluator's selection rule: among
// typed records whose build context matches the analyzed build, the latest
// completed run wins over failed/not-run records. When no typed record
// matches, the latest typed record is retained only to explain why it does
// not describe this build. A legacy record without a typed outcome is never
// treated as a measurement.
func selectGovulncheckEvidence(c *domain.AnalysisCase) govulncheckMeasurement {
	m := govulncheckMeasurement{}
	if c == nil {
		return m
	}
	effective := domain.EffectiveBuildContext(c.Product)
	var completed, latest, latestTyped *domain.Evidence
	evidence := c.EvidenceGraph.EvidenceList()
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != domain.EvidenceGovulncheck {
			continue
		}
		m.EvidenceRecorded = true
		if e.Govulncheck == nil {
			continue
		}
		m.Typed = true
		latestTyped = e
		if e.BuildContext == nil || e.BuildContext.Matches(effective) != nil {
			continue
		}
		latest = e
		switch e.Govulncheck.Outcome {
		case domain.GovulncheckCompletedEmpty, domain.GovulncheckCompletedWithResults:
			completed = e
		}
	}
	for i := range c.EvidenceGraph.ToolExecutions {
		if c.EvidenceGraph.ToolExecutions[i].Tool == "govulncheck" {
			m.ToolExecuted = true
			break
		}
	}
	m.Record = completed
	if m.Record == nil {
		m.Record = latest
	}
	if m.Record == nil {
		m.Record = latestTyped
	}
	if m.Record == nil {
		switch {
		case m.EvidenceRecorded:
			m.Problem = "govulncheck evidence has no typed run outcome"
		case m.ToolExecuted:
			m.Problem = "govulncheck was invoked but no run record was persisted"
		}
		return m
	}
	m.Outcome = m.Record.Govulncheck.Outcome
	m.Coverage = m.Record.Govulncheck.Coverage
	if m.Record.BuildContext == nil {
		m.Problem = "recorded run has no build context"
		return m
	}
	if err := m.Record.BuildContext.Matches(effective); err != nil {
		m.Problem = "recorded run describes a different build: " + err.Error()
		return m
	}
	switch m.Outcome {
	case domain.GovulncheckFailed:
		m.Problem = "run failed"
		if m.Record.Govulncheck.Error != "" {
			m.Problem += ": " + m.Record.Govulncheck.Error
		}
		return m
	case domain.GovulncheckNotRun:
		m.Problem = "run was not executed"
		if m.Record.Govulncheck.Error != "" {
			m.Problem += ": " + m.Record.Govulncheck.Error
		}
		return m
	case domain.GovulncheckCompletedEmpty, domain.GovulncheckCompletedWithResults:
	default:
		m.Problem = "recorded run outcome is unrecognized: " + string(m.Outcome)
		return m
	}
	res, err := goanalysis.Parse([]byte(m.Record.Content))
	if err != nil {
		m.Problem = "completed run output could not be decoded: " + err.Error()
		return m
	}
	m.Admitted = true
	for _, f := range res.ForVulnerability(c.Vulnerability) {
		function, pkg, module := false, false, false
		for _, frame := range f.Trace {
			switch {
			case frame.Function != "":
				function = true
			case frame.Package != "":
				pkg = true
			case frame.Module != "":
				module = true
			}
		}
		switch {
		case function:
			m.FunctionFindings++
		case pkg:
			m.PackageFindings++
		case module:
			m.ModuleFindings++
		}
	}
	for i := range c.EvidenceGraph.CallPaths {
		cp := &c.EvidenceGraph.CallPaths[i]
		if cp.EvidenceID == m.Record.ID && len(cp.Frames) > 0 {
			m.BoundCallPaths++
		}
	}
	return m
}

// silenceQualified reports the only completed shape that can carry a
// silence candidate: the advisory was covered and the run measured the whole
// analyzed build. It is still only a candidate — negative verification
// remains a separate gate.
func (m govulncheckMeasurement) silenceQualified() bool {
	return (m.Outcome == domain.GovulncheckCompletedEmpty ||
		m.Outcome == domain.GovulncheckCompletedWithResults) &&
		m.Coverage.Advisory == domain.GovulncheckCoverageCovered &&
		m.Coverage.ScopeComplete
}

// coverageNote states what the run actually covered, separately from what it
// found.
func (m govulncheckMeasurement) coverageNote() string {
	var parts []string
	switch m.Coverage.Advisory {
	case domain.GovulncheckCoverageCovered:
		parts = append(parts, "advisory covered by the scanned database")
	case domain.GovulncheckCoverageNotInDB:
		parts = append(parts, "advisory absent from the scanned database — silence is not evidence of no path")
	default:
		parts = append(parts, "advisory coverage unknown")
	}
	if m.Coverage.ScopeComplete {
		parts = append(parts, "whole analyzed build")
	} else {
		parts = append(parts, "narrowed scope: packages outside the pattern were not analyzed")
	}
	if n := len(m.Coverage.Subjects); n > 0 {
		parts = append(parts, fmt.Sprintf("%d declared subject(s)", n))
	}
	return strings.Join(parts, "; ")
}

// localizeCoverageNote renders a coverage note for the Russian report. The
// English note stays the export vocabulary.
func localizeCoverageNote(note string) string {
	return strings.NewReplacer(
		"advisory covered by the scanned database", "advisory покрыт базой сканирования",
		"advisory absent from the scanned database — silence is not evidence of no path", "advisory отсутствует в базе сканирования — молчание не доказывает отсутствие пути",
		"advisory coverage unknown", "охват advisory неизвестен",
		"whole analyzed build", "вся анализируемая сборка",
		"narrowed scope: packages outside the pattern were not analyzed", "суженная область: пакеты вне шаблона не анализировались",
		"declared subject(s)", "объявленных субъектов",
	).Replace(note)
}

// findingsForAdvisory reports whether the run emitted a finding for the
// analyzed advisory at any trace depth.
func (m govulncheckMeasurement) findingsForAdvisory() bool {
	return m.FunctionFindings+m.PackageFindings+m.ModuleFindings > 0
}

func govulncheckSummary(c *domain.AnalysisCase, isRU bool) string {
	m := selectGovulncheckEvidence(c)
	if len(c.EvidenceGraph.CallPaths) > 0 {
		n := len(c.EvidenceGraph.CallPaths)
		if isRU {
			return fmt.Sprintf("Обнаружены пути вызова к уязвимому коду (%d)", n)
		}
		return fmt.Sprintf("Call path(s) to vulnerable code detected (%d)", n)
	}
	if !m.Admitted {
		switch m.Outcome {
		case domain.GovulncheckFailed:
			if isRU {
				return "Прогон не удался — достижимость не измерена"
			}
			return "Run failed — reachability not measured"
		case domain.GovulncheckNotRun:
			if isRU {
				return "Прогон не выполнялся — достижимость не измерена"
			}
			return "Run not executed — reachability not measured"
		default:
			if isRU {
				return "Нет допущенной записи прогона — достижимость не измерена"
			}
			return "No admitted run record — reachability not measured"
		}
	}
	if m.Outcome == domain.GovulncheckCompletedWithResults && m.findingsForAdvisory() {
		if isRU {
			switch {
			case m.FunctionFindings > 0:
				return fmt.Sprintf("Обнаружены пути вызова к уязвимому коду (%d)", m.FunctionFindings)
			case m.PackageFindings > 0:
				return "Найдено только пакетное упоминание (не достижимость символов)"
			default:
				return "Найдено только модульное упоминание (не достижимость символов)"
			}
		}
		switch {
		case m.FunctionFindings > 0:
			return fmt.Sprintf("Call path(s) to vulnerable code detected (%d)", m.FunctionFindings)
		case m.PackageFindings > 0:
			return "Package-level finding only (not symbol reachability)"
		default:
			return "Module-level finding only (not symbol reachability)"
		}
	}
	note := m.coverageNote()
	if m.silenceQualified() {
		if isRU {
			return "Прогон завершён — находок в измеренной области нет (охват: " + localizeCoverageNote(note) + ")"
		}
		return "Run completed — no findings in the measured scope (coverage: " + note + ")"
	}
	if isRU {
		return "Прогон завершён без находок, но охват не подтверждает отсутствие путей (охват: " + localizeCoverageNote(note) + ")"
	}
	return "Run completed with no findings, but coverage does not establish absence (coverage: " + note + ")"
}

func rootCauseMechanism(mech string, isRU bool) string {
	if isRU {
		if mech == "advisory-listed affected symbol" {
			return "заявлена как уязвимая в базе (advisory)"
		}
		return strings.ReplaceAll(mech, "advisory-listed affected symbol", "заявлена как уязвимая в базе (advisory)")
	}
	return mech
}

func renderProvenanceBreakdown(b *strings.Builder, isRU bool) {
	if isRU {
		b.WriteString("### Источники и методы проверки (Методология)\n\n")
		b.WriteString("- ⚙️ **Детерминированные проверки компилятора Go:**\n")
		b.WriteString("  - Зависимости (`go.mod` / `go list -m`): фиксация версий библиотек в сборке.\n")
		b.WriteString("  - Граф пакетов сборки (`go list -deps`): проверка фактического включения скомпилированных пакетов в бинарный файл.\n")
		b.WriteString("  - Анализ графа вызовов (`govulncheck`): поиск статических путей вызова от приложения к функциям из advisory (проверка достижимости символов).\n")
		b.WriteString("  - Анализ точек входа (AST): инспекция конструкторов и инициализации сервисов в коде проекта.\n")
		b.WriteString("  - Анализ сетевого периметра и манифестов: инспекция сетевых слушателей и манифестов развёртывания (K8s/Helm).\n\n")
	} else {
		b.WriteString("### Verification Sources & Methods (Methodology)\n\n")
		b.WriteString("- ⚙️ **Go compiler deterministic checks:**\n")
		b.WriteString("  - Dependencies (`go.mod` / `go list -m`): module version pinned in build.\n")
		b.WriteString("  - Build package graph (`go list -deps`): verification of whether library packages are physically linked into the compiled binary.\n")
		b.WriteString("  - Call graph analysis (`govulncheck`): detection of static call paths from product code to advisory symbols (reachability check).\n")
		b.WriteString("  - Entrypoint analysis (AST): inspection of service initialization and constructors used in project code.\n")
		b.WriteString("  - Network perimeter & manifest analysis: inspection of listeners and deployment manifests (K8s/Helm).\n\n")
	}
}

func govulncheckProblemNote(m govulncheckMeasurement, isRU bool) string {
	if !isRU {
		if m.Problem == "" {
			return "no admitted govulncheck run record"
		}
		return m.Problem
	}
	switch m.Outcome {
	case domain.GovulncheckFailed:
		note := "прогон завершился ошибкой"
		if m.Record != nil && m.Record.Govulncheck.Error != "" {
			note += ": " + m.Record.Govulncheck.Error
		}
		return note
	case domain.GovulncheckNotRun:
		note := "прогон не выполнялся"
		if m.Record != nil && m.Record.Govulncheck.Error != "" {
			note += ": " + m.Record.Govulncheck.Error
		}
		return note
	}
	if m.Problem == "" {
		return "нет допущенной типизированной записи прогона"
	}
	return "запись прогона не допущена: " + m.Problem
}

// renderGovulncheckComparison renders what the recorded measurement actually
// supports. A completed run with no findings is never called "clean": the
// coverage is stated separately. A failed/not-run/legacy record is reported
// as unmeasured, never as a negative reachability result.
func renderGovulncheckComparison(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	m := selectGovulncheckEvidence(c)
	hasCallPaths := len(c.EvidenceGraph.CallPaths) > 0
	if !hasCallPaths && !m.EvidenceRecorded && !m.ToolExecuted {
		return
	}

	var targets []string
	seen := map[string]bool{}
	for _, cp := range c.EvidenceGraph.CallPaths {
		if len(cp.Frames) > 0 {
			f := cp.Frames[0]
			var name string
			if f.Package != "" && f.Function != "" {
				name = f.Package + "." + f.Function
			} else if f.Function != "" {
				name = f.Function
			} else if f.Package != "" {
				name = f.Package
			}
			if name != "" && !seen[name] {
				seen[name] = true
				targets = append(targets, name)
			}
		}
	}

	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)
	reachable := hasCallPaths || (m.Admitted &&
		m.Outcome == domain.GovulncheckCompletedWithResults && m.FunctionFindings > 0)
	findingOnly := !reachable && m.Admitted &&
		m.Outcome == domain.GovulncheckCompletedWithResults && m.findingsForAdvisory()
	completedSilent := !reachable && !findingOnly && m.Admitted &&
		(m.Outcome == domain.GovulncheckCompletedEmpty ||
			(m.Outcome == domain.GovulncheckCompletedWithResults && !m.findingsForAdvisory()))
	coverage := m.coverageNote()
	measurementNote := ""
	if !m.Admitted {
		measurementNote = govulncheckProblemNote(m, isRU)
	}

	if isRU {
		b.WriteString("### Сопоставление с govulncheck (Анализ расхождения)\n\n")
		switch {
		case reachable:
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Уязвимый код вызывается (Reachable)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова от приложения к коду библиотеки (в частности: `%s`).\n", strings.Join(targets, "`, `"))
			} else if hasCallPaths {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова к коду библиотеки (%d).\n", len(c.EvidenceGraph.CallPaths))
			} else {
				fmt.Fprintf(b, "  - Сканер обнаружил находки уровня функций (%d); отдельная запись пути вызова не приложена.\n", m.FunctionFindings)
			}
			if measurementNote != "" {
				fmt.Fprintf(b, "  - Запись измерения: %s.\n", measurementNote)
			}
		case findingOnly:
			if m.PackageFindings > 0 {
				b.WriteString("- 🔍 **Вердикт govulncheck:** **Найдено только пакетное упоминание (не достижимость символов)**\n")
				b.WriteString("  - Сканер отметил advisory на уровне импорта пакета; путь вызова функции не записан. Это не доказывает достижимость уязвимого символа и не опровергает её.\n")
			} else {
				b.WriteString("- 🔍 **Вердикт govulncheck:** **Найдено только модульное упоминание (не достижимость символов)**\n")
				b.WriteString("  - Сканер отметил advisory на уровне модуля; ни пакет, ни функция не привязаны к пути вызова. Это не доказывает достижимость уязвимого символа и не опровергает её.\n")
			}
			fmt.Fprintf(b, "  - Охват: %s.\n", localizeCoverageNote(coverage))
		case completedSilent:
			if m.silenceQualified() {
				b.WriteString("- 🔍 **Вердикт govulncheck:** **Прогон завершён — находок в измеренной области нет**\n")
			} else {
				b.WriteString("- 🔍 **Вердикт govulncheck:** **Прогон завершён без находок — охват не подтверждает отсутствие путей**\n")
			}
			fmt.Fprintf(b, "  - Охват: %s.\n", localizeCoverageNote(coverage))
			b.WriteString("  - Это измерение просканированной области, а не доказательство отсутствия пути во всех поддерживаемых вариантах сборки.\n")
		default:
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Достижимость не измерена**\n")
			fmt.Fprintf(b, "  - %s. Неудачный, невыполненный или недопущенный прогон не является чистым результатом достижимости.\n", measurementNote)
		}
		switch {
		case reachable && c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound:
			b.WriteString("- 🛡️ **Вердикт анализатора:** **`NO_EXPLOIT_PATH_FOUND` (Уязвимый путь исполнения отсутствует)**\n")
			b.WriteString("- ⚖️ **Обоснование опровержения (почему срабатывание govulncheck является ложной тревогой):**\n")
			b.WriteString("  - **Смешение ролей функций в базе advisory:** `govulncheck` считает все перечисленные в advisory функции одинаково уязвимыми и не анализирует коммит исправления.\n")
			if len(presentNotes) > 0 {
				var syms []string
				for _, pn := range presentNotes {
					syms = append(syms, fmt.Sprintf("`%s.%s`", pn.Symbol.Package, pn.Symbol.Symbol))
				}
				fmt.Fprintf(b, "  - **Безопасность вызываемых функций:** Вызовы приходят в функции %s, которые выполняют лишь вспомогательную диспетчеризацию и не содержат дефектной операции.\n", strings.Join(syms, ", "))
			} else {
				b.WriteString("  - **Безопасность вызываемых функций:** Вызовы приходят в функции, которые признаны безопасными диспетчерами.\n")
			}
			if len(absentPkgs) > 0 {
				fmt.Fprintf(b, "  - **Физическое отсутствие дефектного локуса:** Реальный сайт сбоя находится в пакетах `%s`, которые **не скомпилированы в бинарный файл** (`go list -deps`).\n", strings.Join(absentPkgs, "`, `"))
			}
			b.WriteString("  - **Итог:** Вызовы, зафиксированные `govulncheck`, не приводят к исполнению дефекта (reachability false positive).\n\n")
		case reachable && c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable:
			b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
			b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — трасса вызовов подтверждает достижимость дефектного локуса.\n\n")
		case reachable && c.Verdict != nil:
			fmt.Fprintf(b, "- ⚠️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
			b.WriteString("- ⚖️ **Сопоставление:** `govulncheck` обнаружил вызовы к библиотеке; условия эксплуатации требуют дальнейшей проверки.\n\n")
		case c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable:
			b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
			if hasMissingCall(c) {
				b.WriteString("- ⚖️ **Сопоставление (Расхождение с govulncheck):** `govulncheck` ищет вызовы функций из advisory, но дефект заключается в пропуске обязательной проверки (missing-call) на активном конвейере исполнения; условия эксплуатации подтверждены.\n\n")
			} else {
				b.WriteString("- ⚖️ **Сопоставление (Расхождение с govulncheck):** Сканер `govulncheck` не зафиксировал прямых вызовов функций из advisory, однако анализ подтвердил эксплуатируемость уязвимости.\n\n")
			}
		case c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound:
			b.WriteString("- 🛡️ **Вердикт анализатора:** **`NO_EXPLOIT_PATH_FOUND` (Уязвимый путь исполнения отсутствует)**\n")
			if completedSilent && m.silenceQualified() {
				b.WriteString("- ⚖️ **Сопоставление:** Находок для advisory в измеренной области нет; вывод анализатора опирается на отдельно проверенные отрицательные факты.\n\n")
			} else {
				b.WriteString("- ⚖️ **Сопоставление:** Этот прогон не является измерением достижимости; вывод анализатора опирается на отдельно проверенные отрицательные факты, а не на молчание сканера.\n\n")
			}
		case c.Verdict != nil:
			fmt.Fprintf(b, "- 🛡️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
			b.WriteString("- ⚖️ **Сопоставление:** Отрицательный вывод на этом прогоне не основан.\n\n")
		}
		return
	}

	b.WriteString("### Govulncheck Comparison & Divergence Analysis\n\n")
	switch {
	case reachable:
		b.WriteString("- 🔍 **Govulncheck Finding:** **Reachable (Vulnerable code is called)**\n")
		if len(targets) > 0 {
			fmt.Fprintf(b, "  - Scanner detected call paths from application code to library code (specifically: `%s`).\n", strings.Join(targets, "`, `"))
		} else if hasCallPaths {
			fmt.Fprintf(b, "  - Scanner detected %d call path(s) to library code.\n", len(c.EvidenceGraph.CallPaths))
		} else {
			fmt.Fprintf(b, "  - The run reported function-level finding(s) (%d); no separate call-path record was attached.\n", m.FunctionFindings)
		}
		if measurementNote != "" {
			fmt.Fprintf(b, "  - Measurement record: %s.\n", measurementNote)
		}
	case findingOnly:
		if m.PackageFindings > 0 {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Package-level mention only (not symbol reachability)**\n")
			b.WriteString("  - The run reported the advisory at package import level; no function-level call path was recorded. This neither proves nor refutes symbol reachability.\n")
		} else {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Module-level mention only (not symbol reachability)**\n")
			b.WriteString("  - The run reported the advisory at module level; neither a package nor a function was tied to a call path. This neither proves nor refutes symbol reachability.\n")
		}
		fmt.Fprintf(b, "  - Coverage: %s.\n", coverage)
	case completedSilent:
		if m.silenceQualified() {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Completed — no findings in the measured scope**\n")
		} else {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Completed with no findings — coverage does not establish absence**\n")
		}
		fmt.Fprintf(b, "  - Coverage: %s.\n", coverage)
		b.WriteString("  - This is a measurement of the scanned scope, not a proof of no path across every supported build variant.\n")
	default:
		b.WriteString("- 🔍 **Govulncheck Finding:** **Reachability not measured**\n")
		fmt.Fprintf(b, "  - %s. A failed, skipped, or inadmissible invocation is not a clean reachability result.\n", measurementNote)
	}
	switch {
	case reachable && c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound:
		b.WriteString("- 🛡️ **Analyzer Verdict:** **`NO_EXPLOIT_PATH_FOUND` (No exploit path exists)**\n")
		b.WriteString("- ⚖️ **Divergence Rationale (Why govulncheck's warning is refuted):**\n")
		b.WriteString("  - **Undifferentiated advisory symbols:** `govulncheck` treats all symbols in the advisory record as equally vulnerable without analyzing patch semantics.\n")
		if len(presentNotes) > 0 {
			var syms []string
			for _, pn := range presentNotes {
				syms = append(syms, fmt.Sprintf("`%s.%s`", pn.Symbol.Package, pn.Symbol.Symbol))
			}
			fmt.Fprintf(b, "  - **Safety of called functions:** Calls reach functions %s, which perform only helper dispatching and contain no defective operation.\n", strings.Join(syms, ", "))
		} else {
			b.WriteString("  - **Safety of called functions:** Calls reach helper functions verified to be non-defective.\n")
		}
		if len(absentPkgs) > 0 {
			fmt.Fprintf(b, "  - **Physical absence of defect locus:** The actual crash site resides in packages `%s`, which are **not linked into the binary** (`go list -deps`).\n", strings.Join(absentPkgs, "`, `"))
		}
		b.WriteString("  - **Conclusion:** Call paths detected by `govulncheck` do not execute defective code (reachability false positive).\n\n")
	case reachable && c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable:
		b.WriteString("- ⚠️ **Analyzer Verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
		b.WriteString("- ⚖️ **Comparison:** Findings agree — call paths reach the active defect locus.\n\n")
	case reachable && c.Verdict != nil:
		fmt.Fprintf(b, "- ⚠️ **Analyzer Verdict:** **`%s`**\n", c.Verdict.Verdict)
		b.WriteString("- ⚖️ **Comparison:** `govulncheck` detected library calls; exploit conditions require further evaluation.\n\n")
	case c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable:
		b.WriteString("- ⚠️ **Analyzer Verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
		if hasMissingCall(c) {
			b.WriteString("- ⚖️ **Divergence Rationale:** `govulncheck` checks for invocations of advisory functions, but the defect stems from omission of a security check (missing-call) along an active execution pipeline; exploit conditions are verified.\n\n")
		} else {
			b.WriteString("- ⚖️ **Divergence Rationale:** `govulncheck` detected no direct call paths to advisory functions, but comprehensive analysis confirmed vulnerability exploitability.\n\n")
		}
	case c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound:
		b.WriteString("- 🛡️ **Analyzer Verdict:** **`NO_EXPLOIT_PATH_FOUND` (No exploit path exists)**\n")
		if completedSilent && m.silenceQualified() {
			b.WriteString("- ⚖️ **Comparison:** No finding for the advisory in the measured scope; the verdict rests on separately verified negative facts.\n\n")
		} else {
			b.WriteString("- ⚖️ **Comparison:** This run is not a reachability measurement; the verdict rests on separately verified negative facts, not on scanner silence.\n\n")
		}
	case c.Verdict != nil:
		fmt.Fprintf(b, "- 🛡️ **Analyzer Verdict:** **`%s`**\n", c.Verdict.Verdict)
		b.WriteString("- ⚖️ **Comparison:** The negative conclusion does not rest on this run.\n\n")
	}
}

// hasMissingCall reports whether the case carries the typed omission
// observation. It reads the witness status, never an evidence-id prefix or a
// content substring: the renderer must describe the same typed record the
// evaluator consumes.
func hasMissingCall(c *domain.AnalysisCase) bool {
	if c == nil {
		return false
	}
	for _, e := range c.EvidenceGraph.Evidence {
		if e.MissingCall != nil && e.MissingCall.Status == domain.MissingCallOmitted {
			return true
		}
	}
	return false
}

// reportCaseCopy returns a render-only copy of the case. The copy shares
// read-only slices and maps with the original, but owns the claim, affected
// and verdict records so projecting refused conclusions cannot rewrite the
// historical case. EvidenceGraph carries an unexported lock, so its fields
// are copied one by one instead of copying the struct value.
//
// The requested-finding fields are carried too, even though the legacy path is
// the only caller that renders this copy: a manual field list silently drops
// whatever a later task adds, and a dropped envelope would turn a projected
// case into a legacy one.
func reportCaseCopy(c *domain.AnalysisCase) *domain.AnalysisCase {
	if c == nil {
		return nil
	}
	g := &c.EvidenceGraph
	return &domain.AnalysisCase{
		ID:              c.ID,
		TicketID:        c.TicketID,
		TicketComponent: c.TicketComponent,
		TicketRelease:   c.TicketRelease,
		Vulnerability:   c.Vulnerability,
		Product:         c.Product,
		Affected:        cloneAffectedResult(c.Affected),
		RootCause:       c.RootCause,
		Exploit:         c.Exploit,
		EvidenceGraph: domain.EvidenceGraph{
			Version:          g.Version,
			Evidence:         g.EvidenceList(),
			CallPaths:        g.CallPaths,
			DataFlows:        g.DataFlows,
			Entrypoints:      g.Entrypoints,
			ModuleUsages:     g.ModuleUsages,
			ModuleReachable:  g.ModuleReachable,
			SymbolRefs:       g.SymbolRefs,
			SymbolDecls:      g.SymbolDecls,
			Exposures:        g.Exposures,
			ConfigFlags:      g.ConfigFlags,
			ConfigFieldKinds: g.ConfigFieldKinds,
			IngressClosures:  g.IngressClosures,
			SinkClosures:     g.SinkClosures,
			Validations:      g.Validations,
			Configuration:    g.Configuration,
			Runtime:          g.Runtime,
			ToolExecutions:   g.ToolExecutions,
			ToolLimitations:  g.ToolLimitations,
			Limitations:      g.Limitations,
			Hash:             g.Hash,
		},
		Claims:              append([]domain.Claim(nil), c.Claims...),
		Hypotheses:          c.Hypotheses,
		Reviews:             c.Reviews,
		Verdict:             cloneVerdictResult(c.Verdict),
		NonLocusBasis:       c.NonLocusBasis,
		DeclaredAssumptions: c.DeclaredAssumptions,
		StrictLLM:           c.StrictLLM,
		PriorCase:           c.PriorCase,
		Workflow:            c.Workflow,
		CVEAnalysisProfile:  c.CVEAnalysisProfile,
		CVEAnalysisBundle:   c.CVEAnalysisBundle,
		CVEAnalysis:         c.CVEAnalysis,
		StrategyPlan:        c.StrategyPlan,
		SemanticReview:      c.SemanticReview,
		Justification:       c.Justification,
		ContextualRisk:      c.ContextualRisk,
		DetectedPerimeter:   c.DetectedPerimeter,
		PerimeterRationale:  c.PerimeterRationale,
		Profiles:            c.Profiles,
		Schema:              c.Schema,
		RequestedID:         c.RequestedID,
		RecordPin:           c.RecordPin,
		CorpusDeclaration:   c.CorpusDeclaration,
		CorpusManifest:      c.CorpusManifest,
		Attributions:        append([]domain.CVEAttribution(nil), c.Attributions...),
		RequestedFinding:    c.RequestedFinding,
		RelatedDiscovery:    c.RelatedDiscovery,
		RelatedRecords:      append([]domain.RelatedRecordAssessment(nil), c.RelatedRecords...),
		ProfileAssessments:  append([]domain.ProfileAssessment(nil), c.ProfileAssessments...),
		AnalysisGaps:        append([]domain.AnalysisGap(nil), c.AnalysisGaps...),
		PerimeterAssessment: c.PerimeterAssessment,
	}
}

func cloneAffectedResult(a *domain.AffectedResult) *domain.AffectedResult {
	if a == nil {
		return nil
	}
	out := *a
	out.TestOnlyScope = append([]string(nil), a.TestOnlyScope...)
	out.EvidenceIDs = append([]domain.EvidenceID(nil), a.EvidenceIDs...)
	out.Limitations = append([]string(nil), a.Limitations...)
	out.ImplementationModules = append([]string(nil), a.ImplementationModules...)
	out.SelectedModules = append([]string(nil), a.SelectedModules...)
	out.CheckedModules = append([]string(nil), a.CheckedModules...)
	out.CheckedPackages = append([]string(nil), a.CheckedPackages...)
	out.PendingModules = append([]string(nil), a.PendingModules...)
	out.UnresolvedModules = append([]string(nil), a.UnresolvedModules...)
	out.VersionAffectedModules = append([]string(nil), a.VersionAffectedModules...)
	out.AssumptionIDs = append([]string(nil), a.AssumptionIDs...)
	return &out
}

func cloneVerdictResult(v *domain.VerdictResult) *domain.VerdictResult {
	if v == nil {
		return nil
	}
	out := *v
	out.ConditionIDs = append([]domain.ConditionID(nil), v.ConditionIDs...)
	out.EvidenceIDs = append([]domain.EvidenceID(nil), v.EvidenceIDs...)
	out.Limitations = append([]string(nil), v.Limitations...)
	out.AssumptionIDs = append([]string(nil), v.AssumptionIDs...)
	return &out
}

// admissionProjection is the render-time view of a case plus the reasons its
// negative conclusions were refused.
type admissionProjection struct {
	Case     *domain.AnalysisCase
	Refusals []string
}

// conditionIndex maps the exploit model's conditions by id.
func conditionIndex(model *domain.ExploitModel) map[domain.ConditionID]domain.Condition {
	out := map[domain.ConditionID]domain.Condition{}
	if model == nil {
		return out
	}
	for _, cond := range model.MandatoryConditions {
		out[cond.ID] = cond
	}
	for _, cond := range model.SupportingFactors {
		out[cond.ID] = cond
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// absenceFalsifierName reports whether a FALSE claim rests on a subject's
// absence from the build graph or from the selected dependency source. Those
// are the negatives the shared absence admission governs.
func absenceFalsifierName(falsifier string) bool {
	switch falsifier {
	case domain.FalsifierPackageAbsent,
		domain.FalsifierLocusPackageAbsent,
		domain.FalsifierMissingSourceSymbol:
		return true
	}
	return false
}

// subjectText renders one absence subject for refusal text.
func subjectText(s domain.SymbolRef) string {
	if s.Symbol == "" {
		return s.Package
	}
	return s.Package + "." + s.Symbol
}

// isNegativeVerdict reports whether a verdict is a negative (safe) projection
// whose closure authority must be re-admitted before rendering.
func isNegativeVerdict(v domain.Verdict) bool {
	return v == domain.VerdictNotAffected || v == domain.VerdictNoExploitPathFound
}

// semanticClaim reports whether a claim's conclusion depends on the
// defect-semantics contract: the omission condition, the check-trigger and
// check-input obligations, and the defect-locus condition. Such a claim is
// not publishable when the contract is not admitted, regardless of its saved
// result or verification status.
func semanticClaim(cond domain.Condition) bool {
	return domain.IsOmissionCondition(cond) ||
		domain.IsCheckTriggerCondition(cond) ||
		domain.IsCheckInputCondition(cond) ||
		cond.Params[domain.ParamCheck] == domain.CheckLocus
}

// admissionRefusedBuildDependent reports whether the projection recorded a
// refusal of a build-dependent negative (the affected chain or a verified
// claim). Independent negatives never reach these gates, so a refusal always
// names a measurement of the analyzed build.
func admissionRefusedBuildDependent(c *domain.AnalysisCase) bool {
	if c == nil {
		return false
	}
	refused := func(l string) bool {
		return strings.HasPrefix(l, "affected negative refused:") ||
			strings.HasPrefix(l, "negative verification refused:")
	}
	for _, l := range c.EvidenceGraph.Limitations {
		if refused(l) {
			return true
		}
	}
	if c.Verdict != nil {
		for _, l := range c.Verdict.Limitations {
			if refused(l) {
				return true
			}
		}
	}
	return false
}

// admitNegativeConclusions replays the negative-admission gates for a case
// being rendered or exported. It returns a report-only copy whose current
// claim/affected/verdict/profile results reflect refused measurements and
// rejected advisory scope, plus the measurement refusal reasons. Historical
// evidence and NegativeVerification records stay verbatim: only the
// conclusions projected from them change.
func admitNegativeConclusions(c *domain.AnalysisCase) admissionProjection {
	if c == nil {
		return admissionProjection{}
	}
	out := reportCaseCopy(c)
	evidence := out.EvidenceGraph.EvidenceList()
	var refusals []string
	refusedConditions := map[domain.ConditionID]bool{}

	// Advisory-scope admission is independent of the measurement gates: a
	// component fact can be deterministically established and still not
	// cover the requested advisory identity. Replaying it here keeps
	// report.json, Markdown, tracker rationale and the VEX exports on the
	// same current conclusion.
	scopeRefused := negativeClosureBlocked(c)
	scopeRefusal := ""
	if scopeRefused {
		scopeRefusal = scopeRefusalReason(c)
	}

	// Defect-semantics replay admission: an omission or defect-locus
	// conclusion is publishable only under the admitted contract. Legacy
	// models (an omission conclusion with no contract), UNRESOLVED
	// contracts and stale or contradictory grounds are demoted here, so a
	// saved TRUE/VERIFIED claim cannot outlive the semantics that admitted
	// it. The model admission itself is Task 1's gate; this is the same
	// admission replayed on the publication path.
	conds := conditionIndex(out.Exploit)
	semanticsRefused := false
	semanticsRefusal := ""
	if out.Exploit != nil {
		if err := domain.ValidateDefectSemanticsModel(*out.Exploit, evidence); err != nil {
			semanticsRefused = true
			semanticsRefusal = "defect semantics admission: " + err.Error()
			refusals = append(refusals, semanticsRefusal)
			for i := range out.Claims {
				cl := &out.Claims[i]
				cond, ok := conds[cl.ConditionID]
				if !ok || !semanticClaim(cond) {
					continue
				}
				cl.Result = domain.ClaimUnknown
				refusedConditions[cl.ConditionID] = true
				msg := fmt.Sprintf("semantic conclusion for %s refused: %s", cl.ConditionID, err)
				refusals = append(refusals, msg)
				if !containsString(cl.Limitations, msg) {
					cl.Limitations = append(append([]string(nil), cl.Limitations...), msg)
				}
			}
		}
	}

	// Absence identity and the admitted necessary cover are replayed on this
	// path too. The schema-less rendering/export path is a publication surface
	// like any other: a saved absence conclusion whose subject identity, cover
	// equality or build-graph absence no longer re-derives is demoted here,
	// before it can be rendered as a negative. Only the projected conclusion
	// changes; historical records stay verbatim.
	proof := fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(out), out.RootCause)
	absenceAdmission := domain.AdmitAbsence(out, affected.AdmittedBuildGraph(out.Product, evidence), proof)
	if out.Exploit != nil {
		clone := *out.Exploit
		clone.AbsentSubjects = append([]domain.SymbolRef(nil), out.Exploit.AbsentSubjects...)
		out.Exploit = &clone
	}
	if out.Exploit != nil && len(out.Exploit.AbsentSubjects) > 0 {
		kept := make([]domain.SymbolRef, 0, len(out.Exploit.AbsentSubjects))
		for _, subject := range out.Exploit.AbsentSubjects {
			admission := absenceAdmission.Admits(subject)
			if !admission.Admitted {
				refusals = append(refusals, fmt.Sprintf(
					"absent subject %s refused: %s", subjectText(subject), admission.Reason))
				continue
			}
			kept = append(kept, subject)
		}
		out.Exploit.AbsentSubjects = kept
	}
	if len(out.Claims) > 0 {
		for i := range out.Claims {
			cl := &out.Claims[i]
			if cl.Result != domain.ClaimFalse || !absenceFalsifierName(cl.Falsifier) {
				continue
			}
			cond, ok := conds[cl.ConditionID]
			if !ok {
				continue
			}
			if _, typedConfig := domain.ConfigFlagSubject(cond); typedConfig {
				continue
			}
			if err := absenceAdmission.CheckClaim(cond, *cl); err != nil {
				cl.Result = domain.ClaimUnknown
				refusedConditions[cl.ConditionID] = true
				msg := fmt.Sprintf("absence negative for %s refused: %s", cl.ConditionID, err)
				refusals = append(refusals, msg)
				if !containsString(cl.Limitations, msg) {
					cl.Limitations = append(append([]string(nil), cl.Limitations...), msg)
				}
			}
		}
	}

	if out.Affected != nil {
		if err := domain.ValidateAffectedNegative(out.Product, *out.Affected, evidence); err != nil {
			if out.Affected.PackagePresent == domain.ClaimFalse {
				out.Affected.PackagePresent = domain.ClaimUnknown
			}
			if out.Affected.BuildRelevant == domain.ClaimFalse {
				out.Affected.BuildRelevant = domain.ClaimUnknown
			}
			if out.Affected.VulnerableImplementationPresent == domain.ClaimFalse {
				out.Affected.VulnerableImplementationPresent = domain.ClaimUnknown
			}
			refusals = append(refusals, "affected negative refused: "+err.Error())
		}
	}

	if len(out.Claims) > 0 {
		for i := range out.Claims {
			cl := &out.Claims[i]
			if cl.Result != domain.ClaimFalse || cl.NegativeVerification == nil ||
				cl.NegativeVerification.Status != domain.NegativeVerified {
				continue
			}
			cond, ok := conds[cl.ConditionID]
			if !ok {
				continue
			}
			err := goanalysis.ValidateVerifiedNegative(goanalysis.NegativeAdmissionInput{Product:out.Product,Vulnerability:out.Vulnerability,RecordPin:out.RecordPin,AdvisoryRecord:out.AdvisoryRecord,Model:out.Exploit,Evidence:evidence}, *cl, cond)
			if err == nil {
				continue
			}
			cl.Result = domain.ClaimUnknown
			refusedConditions[cl.ConditionID] = true
			msg := fmt.Sprintf("negative verification for %s refused: %s", cl.ConditionID, err)
			refusals = append(refusals, msg)
			if !containsString(cl.Limitations, msg) {
				cl.Limitations = append(append([]string(nil), cl.Limitations...), msg)
			}
		}
	}

	verdictRefused := false
	if out.Verdict != nil && (isNegativeVerdict(out.Verdict.Verdict) || semanticsRefused) {
		refused := scopeRefused || semanticsRefused
		if !refused {
			switch out.Verdict.Verdict {
			case domain.VerdictNotAffected:
				// Module-graph absence and an out-of-range version are
				// independent facts: the verdict still closes even when a
				// weaker build-dependent axis on the same record was refused.
				// They are not independent of advisory-scope admission,
				// which is why scopeRefused bypasses this latitude.
				independent := c.Affected != nil &&
					(c.Affected.ModulePresent == domain.ClaimFalse || c.Affected.VersionAffected == domain.ClaimFalse)
				if !independent && c.Affected != nil && out.Affected != nil {
					refused = (c.Affected.PackagePresent == domain.ClaimFalse && out.Affected.PackagePresent == domain.ClaimUnknown) ||
						(c.Affected.BuildRelevant == domain.ClaimFalse && out.Affected.BuildRelevant == domain.ClaimUnknown) ||
						(c.Affected.VulnerableImplementationPresent == domain.ClaimFalse && out.Affected.VulnerableImplementationPresent == domain.ClaimUnknown)
				}
			case domain.VerdictNoExploitPathFound:
				if len(out.Verdict.ConditionIDs) == 0 {
					refused = len(refusedConditions) > 0
				} else {
					for _, id := range out.Verdict.ConditionIDs {
						if refusedConditions[id] {
							refused = true
							break
						}
					}
				}
			}
		}
		if refused {
			verdictRefused = true
			parts := refusalParts(scopeRefusal, refusals)
			out.Verdict.Verdict = domain.VerdictInconclusive
			out.Verdict.Reason = "negative conclusion refused: " + strings.Join(parts, "; ")
			out.Verdict.GroundBasis = ""
			out.Verdict.ExploitabilityScope = ""
			for _, r := range parts {
				if !containsString(out.Verdict.Limitations, r) {
					out.Verdict.Limitations = append(out.Verdict.Limitations, r)
				}
			}
		}
	}

	// A profile is a flattened finding-level conclusion. A stale safe
	// profile would keep advertising "no action" in the perimeter matrix
	// after its verdict was refused, so every negative profile is
	// re-projected under the same admission outcome.
	if scopeRefused || verdictRefused {
		reason := scopeRefusal
		if reason == "" {
			reason = "negative conclusion refused: " + strings.Join(refusals, "; ")
		}
		projectRefusedProfiles(out, reason)
	}

	// A demoted verdict must not sit beside a stale DISMISSED contextual
	// assessment. Recompute the projection with the same risk.Assess pass
	// the evaluator uses, now over the inconclusive verdict.
	if verdictRefused {
		res := risk.Assess(out.Vulnerability, out, *out.Verdict)
		out.ContextualRisk = &res
	}

	notes := refusalParts(scopeRefusal, refusals)
	if len(notes) > 0 {
		existing := map[string]bool{}
		for _, l := range c.EvidenceGraph.Limitations {
			existing[l] = true
		}
		if c.Verdict != nil {
			for _, l := range c.Verdict.Limitations {
				existing[l] = true
			}
		}
		lims := append([]string(nil), c.EvidenceGraph.Limitations...)
		for _, r := range notes {
			if existing[r] {
				continue
			}
			existing[r] = true
			lims = append(lims, r)
		}
		out.EvidenceGraph.Limitations = lims
	}
	return admissionProjection{Case: out, Refusals: refusals}
}

// refusalParts orders the admission refusal notes for a projected
// conclusion: the advisory-scope refusal first, then the measurement
// refusals that shared the same negative conclusion.
func refusalParts(scopeRefusal string, refusals []string) []string {
	if scopeRefusal == "" {
		return refusals
	}
	return append([]string{scopeRefusal}, refusals...)
}

// scopeRefusalReason names what a refused negative did establish and which
// requested scope remains open. A component-level fact is named as such; a
// finding-level negative (e.g. a perimeter conclusion) is not misdescribed
// as a component fact. The text is display only, never closure policy.
func scopeRefusalReason(c *domain.AnalysisCase) string {
	scope := requestedAdvisoryID(c)
	if c != nil && c.Affected != nil && c.Affected.HasNegative() {
		if checked := checkedScopeNames(c); checked != "" {
			return fmt.Sprintf("component fact established for `%s` / requested scope `%s` not closed — %s",
				checked, scope, scopeOpenNote)
		}
		return fmt.Sprintf("component fact established / requested scope `%s` not closed — %s", scope, scopeOpenNote)
	}
	return fmt.Sprintf("finding-level negative conclusion refused / requested scope `%s` not closed — %s",
		scope, scopeOpenNote)
}

// projectRefusedProfiles demotes every negative profile whose closure the
// admission gates refused. The profile keeps its threat model and target
// marker, but loses the safe verdict and any falsifier/scope label that
// belonged to the refused conclusion; its triage priority is recomputed so
// a stale DISMISSED cannot survive beside an inconclusive profile.
func projectRefusedProfiles(c *domain.AnalysisCase, reason string) {
	if c == nil || len(c.Profiles) == 0 {
		return
	}
	profiles := append([]domain.ProfileVerdict(nil), c.Profiles...)
	var provisional *domain.ContextualRisk
	changed := false
	for i := range profiles {
		if !isNegativeVerdict(profiles[i].Verdict) {
			continue
		}
		if provisional == nil {
			res := risk.Assess(c.Vulnerability, c, domain.VerdictResult{Verdict: domain.VerdictInconclusive})
			provisional = &res
		}
		profiles[i].Verdict = domain.VerdictInconclusive
		profiles[i].Reason = reason
		profiles[i].Falsifier = ""
		profiles[i].ExploitabilityScope = ""
		profiles[i].Priority = provisional.Priority
		profiles[i].SLA = provisional.SLA
		changed = true
	}
	if changed {
		c.Profiles = profiles
	}
}

// negativeUsesBuildContext reports whether the case's current negative
// conclusion rests on a measurement of the analyzed build rather than on an
// independent product fact (module graph, version range, deployment policy).
func negativeUsesBuildContext(c *domain.AnalysisCase) bool {
	if c == nil {
		return false
	}
	conds := conditionIndex(c.Exploit)
	claimDependent := false
	for _, cl := range c.Claims {
		if cl.Result != domain.ClaimFalse {
			continue
		}
		cond, ok := conds[cl.ConditionID]
		if ok && domain.NegativeRequiresTarget(cl, cond) {
			claimDependent = true
			break
		}
	}
	if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		return claimDependent
	}
	if c.Affected != nil {
		// Module-graph absence and an out-of-range version close the
		// affected chain independently of the analyzed build; a refused
		// weaker axis on the same record does not change that.
		if c.Affected.ModulePresent == domain.ClaimFalse || c.Affected.VersionAffected == domain.ClaimFalse {
			return claimDependent
		}
		switch {
		case c.Affected.PackagePresent == domain.ClaimFalse,
			c.Affected.BuildRelevant == domain.ClaimFalse,
			c.Affected.VulnerableImplementationPresent == domain.ClaimFalse:
			return true
		}
	}
	return claimDependent
}

// buildScopeStatement names the single analyzed build a build-dependent
// negative describes: platform, tags, CGO, target provenance and the bounded
// scope. It never turns one analyzed build into a support matrix.
func buildScopeStatement(c *domain.AnalysisCase) string {
	return buildScopeSentence(c, false)
}

func buildScopeSentence(c *domain.AnalysisCase, isRU bool) string {
	if c == nil {
		return ""
	}
	p := c.Product
	platform := strings.TrimSpace(p.GOOS + "/" + p.GOARCH)
	if p.Target != nil && p.Target.Platform() != "" {
		platform = p.Target.Platform()
	}
	if platform == "" || platform == "/" {
		platform = "unrecorded"
	}
	tags := "none"
	if len(p.BuildTags) > 0 {
		tags = strings.Join(p.BuildTags, ", ")
	}
	cgo := "CGO_ENABLED=0"
	if p.CGOEnabled {
		cgo = "CGO_ENABLED=1"
	}
	provenance := "unrecorded"
	scope := ""
	if p.Target != nil {
		provenance = p.Target.Source
		scope = p.Target.Scope
	}
	admission := ""
	if err := domain.ValidateNegativeTarget(p); err != nil {
		admission = err.Error()
	}
	if isRU {
		var b strings.Builder
		b.WriteString("Отрицательный вывод описывает только анализируемую сборку (платформа ")
		b.WriteString(platform)
		b.WriteString("; теги сборки: ")
		b.WriteString(tags)
		b.WriteString("; ")
		b.WriteString(cgo)
		b.WriteString("; происхождение цели: ")
		b.WriteString(provenance)
		if scope != "" {
			b.WriteString("; область цели: ")
			b.WriteString(scope)
		}
		if admission != "" {
			b.WriteString("; цель не допущена: ")
			b.WriteString(admission)
		}
		b.WriteString("). Это не утверждение обо всех поддерживаемых вариантах GOOS/GOARCH/тегов/CGO.")
		return b.String()
	}
	var b strings.Builder
	b.WriteString("The negative describes only the analyzed build (platform ")
	b.WriteString(platform)
	b.WriteString("; build tags: ")
	b.WriteString(tags)
	b.WriteString("; ")
	b.WriteString(cgo)
	b.WriteString("; target provenance: ")
	b.WriteString(provenance)
	if scope != "" {
		b.WriteString("; target scope: ")
		b.WriteString(scope)
	}
	if admission != "" {
		b.WriteString("; target not admitted: ")
		b.WriteString(admission)
	}
	b.WriteString("). It does not assert that every supported GOOS/GOARCH/tag/CGO variant is unaffected.")
	return b.String()
}

// Markdown renders the human-readable report. A case carrying the
// analysis-case/2 requested-finding envelope renders that projection: the
// requested identity and outcome, proof origin, witness-bound remediation and
// severity, failure or external-dependency diagnostics, candidate assessments
// and discovery/corpus limitations, followed by the primary record's own
// unchanged assessment. A legacy case keeps the historical single-assessment
// report — it has no requested answer to project — and a case whose saved
// conclusion no longer re-admits renders only the refusal diagnostics.
func Markdown(c *domain.AnalysisCase, lang ...string) string {
	isRU := isRussian(lang...)
	pub := publish(c)
	var b strings.Builder
	switch {
	case pub.refusal != nil:
		writeRefusalMarkdown(&b, pub.primary, pub.refusal, isRU)
		return b.String()
	case pub.requested != nil:
		writeCaseHeader(&b, pub.primary, pub.requested.RequestedID, isRU)
		writeRequestedMarkdown(&b, pub, isRU)
		b.WriteString(writeCaseBody(pub.primary, isRU, pub.requested, &pub.axes))
		return b.String()
	default:
		// Legacy path: replay the negative-admission gates so the historical
		// single-assessment conclusion is the current one.
		admitted := admitNegativeConclusions(c).Case
		populateUpgradeCompatibility(admitted)
		writeCaseHeader(&b, admitted, admitted.Vulnerability.ID, isRU)
		b.WriteString(writeCaseBody(admitted, isRU, nil, nil))
		return b.String()
	}
}

// writeCaseHeader writes the case metadata header under the requested
// identity: the caller asked about the request, not about the record that
// happened to be resolved first.
func writeCaseHeader(b *strings.Builder, c *domain.AnalysisCase, titleID string, isRU bool) {
	if isRU {
		fmt.Fprintf(b, "# Анализ уязвимости: %s\n\n", titleID)
		fmt.Fprintf(b, "- Кейс: `%s`\n", c.ID)
		if c.TicketID != "" {
			fmt.Fprintf(b, "- Тикет: `%s`\n", c.TicketID)
		}
		if c.TicketComponent != "" {
			fmt.Fprintf(b, "- Компонент: `%s`\n", c.TicketComponent)
		}
		if c.TicketRelease != "" {
			fmt.Fprintf(b, "- Релиз: `%s`\n", c.TicketRelease)
		}
		fmt.Fprintf(b, "- Репозиторий: `%s`\n- Коммит: `%s`\n- Окружение Go: `%s` (%s/%s)\n\n",
			c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)
		return
	}
	fmt.Fprintf(b, "# Vulnerability analysis: %s\n\n", titleID)
	fmt.Fprintf(b, "- Case: `%s`\n", c.ID)
	if c.TicketID != "" {
		fmt.Fprintf(b, "- Ticket: `%s`\n", c.TicketID)
	}
	if c.TicketComponent != "" {
		fmt.Fprintf(b, "- Component: `%s`\n", c.TicketComponent)
	}
	if c.TicketRelease != "" {
		fmt.Fprintf(b, "- Release: `%s`\n", c.TicketRelease)
	}
	fmt.Fprintf(b, "- Repository: `%s`\n- Commit: `%s`\n- Go: `%s` (%s/%s)\n\n",
		c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)
}

// writeCaseBody renders one record's own assessment. When requested is nil this
// is the historical single-assessment report; otherwise it renders the primary
// record's extent, census, claims and evidence unchanged, below the requested
// finding, and leaves the request-level verdict, severity and remediation to
// that projection.
func writeCaseBody(c *domain.AnalysisCase, isRU bool, requested *domain.RequestedFinding,
	axes *finding.AssessmentAxes) string {
	var b strings.Builder

	if requested == nil && c.Verdict != nil {
		if isRU {
			fmt.Fprintf(&b, "## Вердикт: `%s`\n\n> **%s**\n\n", c.Verdict.Verdict, localizeVerdictReason(c.Verdict.Reason, true))
		} else {
			fmt.Fprintf(&b, "## Verdict: `%s`\n\n> **%s**\n\n", c.Verdict.Verdict, c.Verdict.Reason)
		}
		renderExploitabilityScope(&b, c, isRU)
		renderTriageAssessment(&b, c, isRU)
		if len(c.Verdict.AssumptionIDs) > 0 {
			if isRU {
				fmt.Fprintf(&b, "> Политические допущения (не доказательства): %s\n\n", strings.Join(c.Verdict.AssumptionIDs, ", "))
			} else {
				fmt.Fprintf(&b, "> Declared assumptions (policy inputs, not evidence): %s\n\n", strings.Join(c.Verdict.AssumptionIDs, ", "))
			}
		}
	}
	// The request-level answer already carries the summary, severity and
	// remediation; the primary record below contributes its own unchanged
	// extent/census/claims/evidence only.
	if requested == nil {
		if rat := rationale(c); rat != "" || len(c.Profiles) > 0 {
			if isRU {
				b.WriteString("## Резюме\n\n")
			} else {
				b.WriteString("## Executive Summary\n\n")
			}
			if rat != "" {
				fmt.Fprintf(&b, "%s\n\n", rat)
			}
			renderVulnerabilityDetails(&b, c, isRU)
			renderPerimeterMatrix(&b, c, isRU)
		}
		if r := remediation(c, isRU); r != "" {
			if isRU {
				fmt.Fprintf(&b, "## Рекомендации по устранению\n\n%s\n\n", r)
			} else {
				fmt.Fprintf(&b, "## Remediation\n\n%s\n\n", r)
			}
		}
	}
	if requested != nil {
		if isRU {
			b.WriteString("## Первичная запись: оценка без изменений\n\n")
		} else {
			b.WriteString("## Primary record: unchanged assessment\n\n")
		}
		writePrimaryRecordNote(&b, c, axes, isRU)
	}

	exps := c.EvidenceGraph.ExposuresList()
	hasEvidence := c.Affected != nil || len(c.Claims) > 0 || len(exps) > 0 || c.RootCause != nil || c.Exploit != nil
	if hasEvidence {
		if isRU {
			b.WriteString("## Доказательная база\n\n")
		} else {
			b.WriteString("## Evidence Dossier\n\n")
		}

		renderKeyVerificationFacts(&b, c, isRU)
		renderProvenanceBreakdown(&b, isRU)
		renderSemanticAnalysisSummary(&b, c, isRU)

		if c.Affected != nil {
			a := c.Affected
			if isRU {
				fmt.Fprintf(&b, "### Применимость (Affected Analysis)\n\n")
				fmt.Fprintf(&b, "| Проверка | Результат |\n|---|---|\n")
				fmt.Fprintf(&b, "| Наличие модуля в зависимостях | %s |\n", localizeAffectedBool(a.ModulePresent, true))
				fmt.Fprintf(&b, "| Разрешённая версия в go.mod | `%s` |\n", a.ResolvedVersion)
				fmt.Fprintf(&b, "| Запрошенная область advisory | %s |\n", advisoryScopeCell(c, true))
				fmt.Fprintf(&b, "| Полнота записи advisory (extent) | %s |\n", advisoryExtentCell(c, true))
				fmt.Fprintf(&b, "| Перепись affected[] (census) | %s |\n", advisoryCensusCell(c, true))
				fmt.Fprintf(&b, "| Закрытие по отрицательным фактам | %s |\n", negativeClosureCell(c, true))
				if row, ok := axisRowForRecord(axes, c); ok {
					fmt.Fprintf(&b, "| Уязвимый код/версия в оцениваемой сборке (проекция) | %s |\n", axisVulnerabilityText(row.VulnerableCodeInBuild, true))
					fmt.Fprintf(&b, "| Эксплуатируемость в оцениваемой области (проекция) | %s |\n", axisExploitabilityText(row, true))
				}
				fmt.Fprintf(&b, "| Версия входит в диапазон уязвимых | %s |\n", localizeAffectedBool(a.VersionAffected, true))
				fmt.Fprintf(&b, "| Уязвимый пакет входит в сборку | %s |\n", localizeAffectedBool(a.PackagePresent, true))
				fmt.Fprintf(&b, "| Код компилируется для целевой платформы | %s |\n", localizeAffectedBool(a.BuildRelevant, true))
				fmt.Fprintf(&b, "| Уязвимая реализация включена в целевую сборку | %s |\n", localizeAffectedBool(a.VulnerableImplementationPresent, true))
				if a.ImplementationLocus != "" {
					fmt.Fprintf(&b, "| Проверенный узел реализации | `%s` (цель `%s`, область `%s`) |\n", a.ImplementationLocus, a.ImplementationTarget, a.ImplementationTargetScope)
				}
				if len(a.AssumptionIDs) > 0 {
					fmt.Fprintf(&b, "| Политические допущения (входы, не доказательства) | %s |\n", strings.Join(a.AssumptionIDs, ", "))
				}
				fmt.Fprintf(&b, "| Статический анализ вызовов (govulncheck) | %s |\n", govulncheckSummary(c, true))
				if len(a.CheckedModules) > 0 {
					fmt.Fprintf(&b, "| Проверенные модули | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
				}
				if len(a.SelectedModules) > 0 {
					fmt.Fprintf(&b, "| Скомпилированные модули | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
				}
				if len(a.PendingModules) > 0 {
					fmt.Fprintf(&b, "| Модули с неопределённой версией | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
				}
				if len(a.CheckedPackages) > 0 {
					fmt.Fprintf(&b, "| Проверенные пакеты | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
				}
				if len(a.EvidenceIDs) > 0 {
					fmt.Fprintf(&b, "| Идентификаторы доказательств (Evidence IDs) | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
				}
				b.WriteString("\n")
			} else {
				fmt.Fprintf(&b, "### Affected Analysis\n\n")
				fmt.Fprintf(&b, "| check | result |\n|---|---|\n")
				fmt.Fprintf(&b, "| module present | %s |\n", a.ModulePresent)
				fmt.Fprintf(&b, "| resolved version | `%s` |\n", a.ResolvedVersion)
				fmt.Fprintf(&b, "| requested advisory scope | %s |\n", advisoryScopeCell(c, false))
				fmt.Fprintf(&b, "| advisory record extent | %s |\n", advisoryExtentCell(c, false))
				fmt.Fprintf(&b, "| advisory record census | %s |\n", advisoryCensusCell(c, false))
				fmt.Fprintf(&b, "| negative closure | %s |\n", negativeClosureCell(c, false))
				if row, ok := axisRowForRecord(axes, c); ok {
					fmt.Fprintf(&b, "| vulnerable code/version in assessed build (projection) | %s |\n", axisVulnerabilityText(row.VulnerableCodeInBuild, false))
					fmt.Fprintf(&b, "| exploitable in assessed scope (projection) | %s |\n", axisExploitabilityText(row, false))
				}
				fmt.Fprintf(&b, "| version affected | %s |\n", a.VersionAffected)
				fmt.Fprintf(&b, "| package present | %s |\n", a.PackagePresent)
				fmt.Fprintf(&b, "| build relevant | %s |\n", a.BuildRelevant)
				fmt.Fprintf(&b, "| vulnerable implementation present | %s |\n", a.VulnerableImplementationPresent)
				if a.ImplementationLocus != "" {
					fmt.Fprintf(&b, "| implementation locus probed | `%s` (target `%s`, scope `%s`) |\n", a.ImplementationLocus, a.ImplementationTarget, a.ImplementationTargetScope)
				}
				if len(a.AssumptionIDs) > 0 {
					fmt.Fprintf(&b, "| declared assumptions (inputs, not evidence) | %s |\n", strings.Join(a.AssumptionIDs, ", "))
				}
				fmt.Fprintf(&b, "| static call analysis (govulncheck) | %s |\n", govulncheckSummary(c, false))
				if len(a.CheckedModules) > 0 {
					fmt.Fprintf(&b, "| modules probed | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
				}
				if len(a.SelectedModules) > 0 {
					fmt.Fprintf(&b, "| modules linked | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
				}
				if len(a.PendingModules) > 0 {
					fmt.Fprintf(&b, "| modules version-unresolved | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
				}
				if len(a.CheckedPackages) > 0 {
					fmt.Fprintf(&b, "| packages probed | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
				}
				if len(a.EvidenceIDs) > 0 {
					fmt.Fprintf(&b, "| evidence | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
				}
				b.WriteString("\n")
			}
		}

		renderGovulncheckComparison(&b, c, isRU)

		if len(c.Claims) > 0 {
			if isRU {
				b.WriteString("### Статус условий эксплуатации (Claims)\n\n| Условие | Результат | Обоснование | Верификация | Доказательства | Роль условия |\n|---|---|---|---|---|---|\n")
				for _, cl := range c.Claims {
					expl := localizeClaimExplanation(cl.Explanation, true)
					if expl == "" {
						expl = "—"
					}
					verif := claimVerification(cl, true)
					if basis := claimControlBasis(cl, true); basis != "" {
						if verif == "" {
							verif = basis
						} else {
							verif += " / " + basis
						}
					}
					if proposal := claimProposalNote(cl, true); proposal != "" {
						if verif == "" {
							verif = proposal
						} else {
							verif += " / " + proposal
						}
					}
					if verif == "" {
						verif = "—"
					}
					evs := strings.Join(evidenceIDs(cl.EvidenceIDs), ", ")
					if evs == "" {
						evs = "—"
					}
					fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", cl.ConditionID, localizeClaimResult(cl.Result, true),
						expl, verif, evs, conditionNecessity(c, cl.ConditionID, true))
				}
				b.WriteString("\n")
			} else {
				b.WriteString("### Claims Status\n\n| condition | result | explanation | verification | evidence | necessity |\n|---|---|---|---|---|---|\n")
				for _, cl := range c.Claims {
					expl := cl.Explanation
					if expl == "" {
						expl = "-"
					}
					verif := claimVerification(cl, false)
					if basis := claimControlBasis(cl, false); basis != "" {
						if verif == "" {
							verif = basis
						} else {
							verif += " / " + basis
						}
					}
					if proposal := claimProposalNote(cl, false); proposal != "" {
						if verif == "" {
							verif = proposal
						} else {
							verif += " / " + proposal
						}
					}
					if verif == "" {
						verif = "-"
					}
					evs := strings.Join(evidenceIDs(cl.EvidenceIDs), ", ")
					if evs == "" {
						evs = "-"
					}
					fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", cl.ConditionID, cl.Result,
						expl, verif, evs, conditionNecessity(c, cl.ConditionID, false))
				}
				b.WriteString("\n")
			}
		}

		renderLibraryAPIWitness(&b, c, isRU)

		renderEvidenceRegister(&b, c, isRU)

		if len(exps) > 0 {
			if isRU {
				b.WriteString("### Точки входа (Exposure Facts)\n\n")
				for _, f := range exps {
					var dirDesc string
					if f.Direction == "inbound" {
						dirDesc = "Входящий слушатель"
					} else if f.Direction == "outbound" {
						dirDesc = "Исходящее подключение"
					} else {
						dirDesc = fmt.Sprintf("`%s` %s", f.Direction, f.Kind)
					}
					fmt.Fprintf(&b, "- %s через `%s`", dirDesc, f.Target)
					if f.Address != "" {
						fmt.Fprintf(&b, " — `%s`", f.Address)
					}
					var meta []string
					if f.AddressSource != "" {
						meta = append(meta, "источник: "+localizeAddressSource(f.AddressSource, true))
					}
					if f.Scope != "" {
						meta = append(meta, "область: "+localizeExposureScope(f.Scope, true))
					}
					if len(meta) > 0 {
						fmt.Fprintf(&b, " (%s)", strings.Join(meta, ", "))
					}
					fmt.Fprintf(&b, " — %s:%d\n", f.File, f.Line)
				}
				b.WriteString("\n")
			} else {
				b.WriteString("### Exposure Facts\n\n")
				for _, f := range exps {
					fmt.Fprintf(&b, "- `%s` %s via `%s`", f.Direction, f.Kind, f.Target)
					if f.Address != "" {
						fmt.Fprintf(&b, " — `%s`", f.Address)
					}
					var meta []string
					if f.AddressSource != "" {
						meta = append(meta, "source: "+f.AddressSource)
					}
					if f.Scope != "" {
						meta = append(meta, "scope: "+f.Scope)
					}
					if len(meta) > 0 {
						fmt.Fprintf(&b, " (%s)", strings.Join(meta, ", "))
					}
					fmt.Fprintf(&b, " — %s:%d\n", f.File, f.Line)
				}
				b.WriteString("\n")
			}
		}

		if c.RootCause != nil || c.Exploit != nil {
			if isRU {
				b.WriteString("### Модель эксплуатации и сайты дефекта\n\n")
			} else {
				b.WriteString("### Exploit Model & Defect Locus\n\n")
			}

			if c.RootCause != nil {
				if isRU {
					fmt.Fprintf(&b, "#### Первопричина дефекта (Root cause): %s\n\n", rootCauseStatus(c.RootCause.Status, true))
					for _, rc := range c.RootCause.RootCauses {
						fmt.Fprintf(&b, "- `%s.%s` (%s) — %s\n", rc.Package, rc.Symbol, rootCauseRole(rc.Role, true), rootCauseMechanism(rc.Mechanism, true))
					}
					b.WriteString("\n")
				} else {
					fmt.Fprintf(&b, "#### Root cause: `%s`\n\n", c.RootCause.Status)
					for _, rc := range c.RootCause.RootCauses {
						fmt.Fprintf(&b, "- `%s.%s` (%s) — %s\n", rc.Package, rc.Symbol, rc.Role, rc.Mechanism)
					}
					b.WriteString("\n")
				}
			}

			if c.Exploit != nil {
				if c.Exploit.Class != "" {
					if isRU {
						fmt.Fprintf(&b, "Класс дефекта: `%s`\n\n", c.Exploit.Class)
					} else {
						fmt.Fprintf(&b, "Class: `%s`\n\n", c.Exploit.Class)
					}
				}
				if c.Exploit.Impact != "" {
					if isRU {
						fmt.Fprintf(&b, "Последствия: %s\n\n", c.Exploit.Impact)
					} else {
						fmt.Fprintf(&b, "Impact: %s\n\n", c.Exploit.Impact)
					}
				}

				if isRU {
					writeConditions(&b, "Обязательные условия (Mandatory conditions)", c.Exploit.MandatoryConditions, true)
					writeConditions(&b, "Сопутствующие факторы (Supporting factors)", c.Exploit.SupportingFactors, true)
				} else {
					writeConditions(&b, "Mandatory conditions", c.Exploit.MandatoryConditions, false)
					writeConditions(&b, "Supporting factors", c.Exploit.SupportingFactors, false)
				}

				if len(c.Exploit.NonLocusBasis) > 0 {
					if isRU {
						b.WriteString("#### Функции без дефекта (исключены из анализа уязвимости)\n\n")
						b.WriteString("Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:\n\n")
						for _, d := range c.Exploit.NonLocusBasis {
							auth := d.Authority
							if auth == "" {
								auth = "эксперт"
							} else if auth == "accepted-machine-proposal" {
								auth = "принятая рекомендация анализатора"
							}
							basis := strings.ReplaceAll(d.Basis, "accepted-machine-proposal", "принятая рекомендация анализатора")
							fmt.Fprintf(&b, "- `%s.%s` — %s (%s)\n", d.Symbol.Package, d.Symbol.Symbol, basis, auth)
						}
						b.WriteString("\n")
					} else {
						b.WriteString("#### Expert decisions on non_locus\n\n")
						b.WriteString("Analysis adjusted for recorded expert decisions (manual confirmation, not automated deduction):\n\n")
						for _, d := range c.Exploit.NonLocusBasis {
							auth := d.Authority
							if auth == "" {
								auth = "expert"
							}
							fmt.Fprintf(&b, "- `%s.%s` — %s (%s)\n", d.Symbol.Package, d.Symbol.Symbol, d.Basis, auth)
						}
						b.WriteString("\n")
					}
				}

				if len(c.Exploit.ProposedNonLocus) > 0 || len(c.Exploit.LocusSubjects) > 0 {
					if isRU {
						b.WriteString("#### Оценка анализатора\n\n")
						b.WriteString(machineAssessment(c, true))
						b.WriteString("\n")
					} else {
						b.WriteString("#### Machine assessment\n\n")
						b.WriteString(machineAssessment(c, false))
						b.WriteString("\n")
					}
				}
			}
		}
	}

	// Declared assumptions render in their own section, outside the
	// evidence dossier and the data-flow audit: human-owned policy/scope
	// assertions must never read as measured code facts, and none of
	// them is an EvidenceKind member or evidence id.
	if da := c.DeclaredAssumptions; da != nil {
		b.WriteString("## Declared assumptions — policy/scope inputs, not deterministic evidence\n\n")
		if isRU {
			b.WriteString("Утверждения оператора о политике и области применения. Это не доказательства: ни одно утверждение не является claim или код-фактом, не является `EvidenceKind.CONFIGURATION`, и само по себе не даёт вердикта. В детерминированную запись входит только intake-запись документа (path, digest, ids).\n\n")
		} else {
			b.WriteString("Operator-declared policy and scope inputs. They are not evidence: no statement is a claim or a code fact, none is `EvidenceKind.CONFIGURATION`, and an assumption alone produces no verdict. Only the document's intake record (path, digests, ids) joins the deterministic record.\n\n")
		}
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
		b.WriteString(line + "\n")
		if da.LoadError != "" {
			fmt.Fprintf(&b, "- intake failed closed: `%s` — every assumption-dependent gate stays unclosed\n", da.LoadError)
		}
		for _, a := range da.Assumptions {
			fmt.Fprintf(&b, "- `%s` [%s, scope `%s`] %s\n", a.ID, a.Kind, a.Scope, a.Statement)
			meta := "authority `" + a.Authority + "` | owner `" + a.Owner + "` | source `" + a.SourceRef + "`"
			if a.ValidFrom != "" {
				meta += " | valid_from `" + a.ValidFrom + "`"
			}
			meta += " | review_date `" + a.ReviewDate + "`"
			fmt.Fprintf(&b, "  - %s\n", meta)
			if a.Targets != nil {
				b.WriteString("  - targets: goos `" + strings.Join(a.Targets.GOOS, "`, `") + "`")
				if len(a.Targets.GOARCH) > 0 {
					b.WriteString(" goarch `" + strings.Join(a.Targets.GOARCH, "`, `") + "`")
				}
				if len(a.Targets.BuildTags) > 0 {
					b.WriteString(" build_tags `" + strings.Join(a.Targets.BuildTags, "`, `") + "`")
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	var bt []domain.Evidence
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceBuild || e.Kind == domain.EvidenceTest {
			bt = append(bt, e)
		}
	}
	lims := allLimitations(c, isRU)
	texs := c.EvidenceGraph.ToolExecutions
	hasAudit := len(c.EvidenceGraph.DataFlows) > 0 ||
		len(texs) > 0 ||
		len(lims) > 0 ||
		len(c.Reviews) > 0 ||
		len(c.EvidenceGraph.Runtime) > 0 ||
		len(bt) > 0 ||
		len(c.Hypotheses) > 0

	if hasAudit {
		if isRU {
			b.WriteString("## Технические детали и аудит (Data Flows, Tool Executions, Limitations)\n\n")
		} else {
			b.WriteString("## Technical Details & Audit (Data Flows, Tool Executions, Limitations)\n\n")
		}

		if len(c.EvidenceGraph.DataFlows) > 0 {
			if isRU {
				b.WriteString("### Потоки данных (Data Flows)\n\n")
			} else {
				b.WriteString("### Data Flows\n\n")
			}
			for _, f := range c.EvidenceGraph.DataFlows {
				var tx []string
				for _, t := range f.Transformations {
					tx = append(tx, t.Callee)
				}
				fmt.Fprintf(&b, "- `%s` %s", f.Origin, f.Summary)
				if len(tx) > 0 {
					fmt.Fprintf(&b, " — via `%s`", strings.Join(tx, "`, `"))
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}

		if len(texs) > 0 {
			if isRU {
				b.WriteString("### Журнал инструментов (Tool Executions)\n\n| Инструмент | Аргументы | Код возврата | Длительность (мс) | SHA-256 вывода |\n|---|---|---|---|---|\n")
			} else {
				b.WriteString("### Tool Executions\n\n| tool | args | exit | ms | stdout sha256 |\n|---|---|---|---|---|\n")
			}
			for _, t := range texs {
				tool := t.Tool
				if t.Version != "" {
					tool += "@" + t.Version
				}
				hash := t.StdoutSHA256
				if len(hash) > 12 {
					hash = hash[:12] + "…"
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | %d | %d | `%s` |\n",
					tool, strings.Join(t.Args, " "), t.ExitCode, t.DurationMs, hash)
			}
			b.WriteString("\n")
		}

		if len(lims) > 0 {
			if isRU {
				b.WriteString("### Ограничения анализа (Limitations)\n\n")
			} else {
				b.WriteString("### Limitations\n\n")
			}
			for _, l := range lims {
				fmt.Fprintf(&b, "- %s\n", l)
			}
			b.WriteString("\n")
		}

		if len(c.Reviews) > 0 {
			if isRU {
				b.WriteString("### Рецензирование (Review Findings)\n\n")
			} else {
				b.WriteString("### Review Findings\n\n")
			}
			for _, rv := range c.Reviews {
				fmt.Fprintf(&b, "- `%s` → **%s**", rv.ID, rv.Result)
				if len(rv.Findings) > 0 {
					b.WriteString("\n")
					for _, f := range rv.Findings {
						if f.TargetID != "" {
							action := ""
							if f.Action != "" {
								action = " (action: " + string(f.Action) + ")"
							}
							fmt.Fprintf(&b, "  - [%s] %s `%s`%s: %s\n", f.Severity, f.TargetType, f.TargetID, action, f.Problem)
						} else {
							fmt.Fprintf(&b, "  - [%s] %s: %s\n", f.Severity, f.TargetType, f.Problem)
						}
					}
				} else {
					if isRU {
						b.WriteString(" — замечаний нет\n")
					} else {
						b.WriteString(" — no findings\n")
					}
				}
			}
			b.WriteString("\n")
		}

		if len(c.EvidenceGraph.Runtime) > 0 {
			if isRU {
				b.WriteString("### Факты среды (Runtime Facts)\n\n")
			} else {
				b.WriteString("### Runtime Facts\n\n")
			}
			for _, id := range c.EvidenceGraph.Runtime {
				if e := c.EvidenceGraph.EvidenceByID(id); e != nil {
					fmt.Fprintf(&b, "- %s: %s\n\n", e.Source, e.Content)
				}
			}
		}

		if len(bt) > 0 {
			if isRU {
				b.WriteString("### Сборка и тесты (Build & Test)\n\n")
			} else {
				b.WriteString("### Build & Test\n\n")
			}
			for _, e := range bt {
				name := e.Command
				if name == "" {
					name = e.Source
				}
				status := e.Content
				if i := strings.IndexByte(status, '\n'); i >= 0 {
					status = status[:i]
				}
				fmt.Fprintf(&b, "- `%s` — %s\n", name, status)
			}
			b.WriteString("\n")
		}

		if len(c.Hypotheses) > 0 {
			if isRU {
				b.WriteString("### Рабочие гипотезы (Hypotheses)\n\n")
			} else {
				b.WriteString("### Hypotheses\n\n")
			}
			for _, h := range c.Hypotheses {
				fmt.Fprintf(&b, "- `%s` %s → **%s**: %s", h.ID, h.ConditionID, h.Status, h.Statement)
				if h.Notes != "" {
					notes := h.Notes
					if isRU {
						notes = strings.ReplaceAll(notes, "accepted-machine-proposal", "принятая рекомендация анализатора")
					}
					fmt.Fprintf(&b, " — %s", notes)
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func writeConditions(b *strings.Builder, title string, conds []domain.Condition, isRU bool) {
	if len(conds) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n", title)
	for _, cond := range conds {
		desc := localizeConditionDesc(string(cond.ID), cond.Description, isRU)
		fmt.Fprintf(b, "- `%s` [%s]: %s%s\n", cond.ID, cond.Kind, desc, renderParams(cond.Params))
	}
	b.WriteString("\n")
}

func renderParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return " {" + strings.Join(parts, ", ") + "}"
}

// claimVerification renders the falsifier/NV status so a claim that was
// proven and then demoted by review stays auditable in the table —
// e.g. "guards / VERIFIED (demoted)" instead of a bare UNKNOWN.
func claimVerification(cl domain.Claim, isRU bool) string {
	if cl.NegativeVerification == nil && cl.Falsifier == "" {
		return ""
	}
	var s string
	if cl.Falsifier != "" {
		f := string(cl.Falsifier)
		if isRU {
			switch cl.Falsifier {
			case "locus-package-absent":
				f = "Пакет отсутствует в сборке"
			case "trusted-infrastructure":
				f = "Доверенная инфраструктура"
			}
		}
		s = f
	}
	if cl.NegativeVerification != nil {
		st := string(cl.NegativeVerification.Status)
		if isRU {
			switch cl.NegativeVerification.Status {
			case domain.NegativeVerified:
				st = "ПОДТВЕРЖДЕНО"
			case domain.NegativeInsufficientScope:
				st = "Недостаточный охват"
			}
		}
		if s != "" {
			s += " / "
		}
		s += st
	}
	if cl.Result == domain.ClaimUnknown && cl.NegativeVerification != nil &&
		cl.NegativeVerification.Status == domain.NegativeVerified {
		if isRU {
			s += " (демотировано)"
		} else {
			s += " (demoted)"
		}
	}
	return s
}

// claimProposalNote renders a model nomination as audit material, never as a
// claim result: the proposal is recorded beside the authoritative result and
// cannot gate the verdict or narrow the locus.
func claimProposalNote(cl domain.Claim, isRU bool) string {
	if cl.Proposal == "" {
		return ""
	}
	if isRU {
		return "предложение модели: " + string(cl.Proposal) + " (не авторитетно)"
	}
	return "model proposal: " + string(cl.Proposal) + " (non-authoritative)"
}

func evidenceIDs(ids []domain.EvidenceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// machineAssessment renders the case-level machine opinion: a proposed
// disposition for the defect-locus falsifier, the expert decisions it
// depends on, and the assumptions outside machine verification. The
// package-absent falsifier needs every locus subject in a linked package
// to carry a recorded expert exclusion — so the block lists, per declared
// symbol, its package status and what the expert still has to decide.
// Advisory text for review — never part of the verdict.
func machineAssessment(c *domain.AnalysisCase, isRUOpt ...bool) string {
	isRU := len(isRUOpt) == 0 || isRUOpt[0]
	if c.Exploit == nil || len(c.Exploit.LocusSubjects) == 0 {
		return ""
	}
	if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
		if libraryAPIScope(c) {
			if isRU {
				return "**Статус:** Уязвимость подтверждена в области публичного API библиотеки (`library-api`): полезная нагрузка, выбираемая потребителем библиотеки, достигает сайта дефекта через доказанную связку «публичный API → sink». Контроль со стороны атакующего в нижестоящем приложении не установлен; автоматическое отклонение по составу пакетов неприменимо.\n"
			}
			return "**Status:** Vulnerability is confirmed exploitable within the library public API (`library-api`): a consumer-selectable payload reaches the defect locus through a proven public-API → sink binding. Deployment-level attacker control in a consuming application is not established; automated package-absence dismissal is not applicable.\n"
		}
		if isRU {
			return "**Статус:** Уязвимость подтверждена и эксплуатируема: подтверждены пути вызова и передача внешних данных в уязвимый код. Автоматическое отклонение по составу пакетов неприменимо.\n"
		}
		return "**Status:** Vulnerability is confirmed exploitable: verified reachability and untrusted input paths reach the defect locus. Automated package-absence dismissal is not applicable.\n"
	}
	proposed := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.ProposedNonLocus {
		proposed[d.Symbol] = d
	}
	annotated := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.LocusAnnotations {
		annotated[d.Symbol] = d
	}

	var set map[string]bool
	if inv, ok := admittedPackageInventory(c); ok {
		set = inv.Paths
	}
	if set == nil {
		if isRU {
			return "Оценку по отсутствию пакетов выставить нельзя: нет допущенного полного состава сборки (`go list -deps`), соответствующего анализируемой сборке.\n"
		}
		return "Package-absence assessment unavailable: no admitted complete build inventory (`go list -deps`) matches the analyzed build.\n"
	}

	var b strings.Builder
	if isRU {
		b.WriteString("Отклонить уязвимость из-за отсутствия пакетов в сборке можно только при условии, что для каждой функции из advisory в *попавших в сборку* пакетах подтверждено решение о безопасности (код не содержит дефекта и признан безопасным):\n\n")
	} else {
		b.WriteString("Dismissal via package absence requires every advisory symbol in *compiled* packages to carry a confirmed safety decision (code lacks defect):\n\n")
	}
	var pending, proposedN, flagged int
	for _, s := range c.Exploit.LocusSubjects {
		name := "`" + s.Package + "." + s.Symbol + "`"
		if !set[s.Package] {
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет **отсутствует в сборке** (`go list -deps`) — код физически не скомпилирован\n", name)
			} else {
				fmt.Fprintf(&b, "- %s — package **absent from build** (`go list -deps`) — code not compiled\n", name)
			}
			continue
		}
		pending++
		if d, ok := proposed[s]; ok {
			proposedN++
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет входит в сборку — **рекомендуется исключить** (код безопасен): %s\n", name, d.Basis)
			} else {
				fmt.Fprintf(&b, "- %s — package included in build — **exclusion recommended** (code safe): %s\n", name, d.Basis)
			}
			continue
		}
		if d, ok := annotated[s]; ok {
			flagged++
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет входит в сборку — **исключение не рекомендуется**: %s — чтобы отклонить, эксперт должен опровергнуть этот вывод\n", name, d.Basis)
			} else {
				fmt.Fprintf(&b, "- %s — package included in build — **exclusion not recommended**: %s — to dismiss, an expert must refute this finding\n", name, d.Basis)
			}
		} else {
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет входит в сборку — **требуется решение эксперта** (автоматический анализ не дал результатов)\n", name)
			} else {
				fmt.Fprintf(&b, "- %s — package included in build — **expert decision required** (automated analysis inconclusive)\n", name)
			}
		}
	}
	b.WriteString("\n")
	switch {
	case pending == 0:
		if isRU {
			b.WriteString("**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ** — ни один из пакетов с уязвимым кодом не входит в граф сборки приложения.\n")
		} else {
			b.WriteString("**Proposed disposition: DISMISSIBLE** — none of the packages with vulnerable code are included in the build graph.\n")
		}
	case flagged == 0 && pending == proposedN:
		if isRU {
			fmt.Fprintf(&b,
				"**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ** — подтвердите %d рекомендаций об исключении как безопасных; остальные пакеты в сборку не входят → вердикт `NO_EXPLOIT_PATH_FOUND` (исключение принимается только как явное экспертное решение через `--non-locus-basis`).\n",
				pending)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: DISMISSIBLE PENDING APPROVAL** — approve %d safety exclusion recommendations; remaining packages are absent from build → verdict `NO_EXPLOIT_PATH_FOUND` (exclusions are accepted only as explicit expert decisions via `--non-locus-basis`).\n",
				pending)
		}
	case flagged == 0:
		if isRU {
			fmt.Fprintf(&b,
				"**Предлагаемая оценка: ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)** — чтобы отклонить уязвимость, необходимо подтвердить решение о безопасности по всем %d функциям в попавших в сборку пакетах (%d рекомендованы к исключению; по %d автоматических данных нет).\n",
				pending, proposedN, pending-proposedN)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: CONDITIONAL REVIEW** — dismissing requires safety approval for all %d functions in linked packages (%d recommended for exclusion; %d lack automated evidence).\n",
				pending, proposedN, pending-proposedN)
		}
	default:
		if isRU {
			fmt.Fprintf(&b,
				"**Предлагаемая оценка: ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)** — чтобы отклонить уязвимость, необходимо подтвердить решение о безопасности по всем %d функциям в попавших в сборку пакетах (%d рекомендованы к исключению; для %d найдены признаки уязвимости, требующие проверки экспертом).\n",
				pending, proposedN, flagged)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: CONDITIONAL REVIEW** — dismissing requires safety approval for all %d functions in linked packages (%d recommended for exclusion; %d show vulnerability signs requiring expert review).\n",
				pending, proposedN, flagged)
		}
	}
	if isRU {
		b.WriteString("\nДопущения (не проверяются автоматически, эксперт подтверждает их при согласовании):\n")
		b.WriteString("- Список уязвимых функций в базе (advisory) полон (если уязвимость затрагивает другие функции библиотеки, анализ их не увидит)\n")
		b.WriteString("- Внесённые решения о безопасности верны (система проверяет факт их наличия, а не правильность)\n")
	} else {
		b.WriteString("\nAssumptions (not checked automatically, confirmed by expert on review):\n")
		b.WriteString("- Advisory vulnerable symbol list is complete (if vulnerability affects other functions, analysis will not see them)\n")
		b.WriteString("- Recorded safety decisions are correct (the system checks presence, not correctness)\n")
	}
	goos, goarch := c.Product.GOOS, c.Product.GOARCH
	if goos == "" {
		goos = "?"
	}
	if goarch == "" {
		goarch = "?"
	}
	tags := strings.Join(c.Product.BuildTags, ", ")
	if tags == "" {
		if isRU {
			tags = "не указаны"
		} else {
			tags = "none"
		}
	}
	if isRU {
		fmt.Fprintf(&b, "- Параметры сборки (%s/%s, теги: %s) соответствуют целевому окружению развёртывания\n",
			goos, goarch, tags)
	} else {
		fmt.Fprintf(&b, "- Build parameters (%s/%s, tags: %s) match the target deployment environment\n",
			goos, goarch, tags)
	}
	if libraryAPIScope(c) {
		if isRU {
			fmt.Fprintf(&b, "\nОбласть вывода: `%s` — %s.\n", domain.ScopeLibraryAPI, libraryScopeBoundaryText(true))
		} else {
			fmt.Fprintf(&b, "\nExploitability scope: `%s` — %s.\n", domain.ScopeLibraryAPI, libraryScopeBoundaryText(false))
		}
	}
	return b.String()
}

func allLimitations(c *domain.AnalysisCase, isRU bool) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(l string) {
		l = localizeLimitation(l, isRU)
		if seen[l] {
			return
		}
		seen[l] = true
		out = append(out, l)
	}
	if c.Affected != nil {
		for _, l := range c.Affected.Limitations {
			add(l)
		}
	}
	if c.RootCause != nil {
		for _, l := range c.RootCause.Limitations {
			add(l)
		}
	}
	// Claim limitations are part of the case's limitation record: a claim
	// can carry a boundary its condition status alone does not show, and
	// dropping it from the export made the report claim more certainty
	// than the case recorded.
	for _, cl := range c.Claims {
		for _, l := range cl.Limitations {
			add(l)
		}
	}
	// The verdict copies graph limitations into its own record — dedupe,
	// or every limitation prints twice.
	for _, l := range c.EvidenceGraph.Limitations {
		add(l)
	}
	for _, l := range c.EvidenceGraph.ToolLimitations {
		add(l)
	}
	if c.Verdict != nil {
		for _, l := range c.Verdict.Limitations {
			add(l)
		}
	}
	// A library-API conclusion is only honest with its mandatory boundary:
	// the payload is consumer-selectable, not proven attacker-delivered.
	if libraryAPIScope(c) {
		add(libraryAPILimitationText(isRU))
	}
	return out
}

// TrackerRationale renders a human-readable, professional justification
// in Russian ready for issue trackers, detailing the verdict,
// product facts, build graph status, defect mechanism, and residual risks.
//
// A case carrying the requested-finding envelope renders the request-level
// answer: witness-bound remediation, or the failure/external-dependency
// distinction. Legacy cases keep the historical single-assessment rationale.
func TrackerRationale(c *domain.AnalysisCase) string {
	pub := publish(c)
	if pub.refusal != nil {
		return "Публикация запрошенного результата отклонена: " + pub.refusal.Error() +
			". Вердикт, критичность и рекомендации не публикуются."
	}
	if pub.requested != nil {
		return pub.requestedRationale()
	}
	c = admitNegativeConclusions(c).Case
	baseRationale := ""
	if c.Verdict == nil {
		baseRationale = "Анализ уязвимости не завершён (вердикт не вынесен)."
	} else {
		switch c.Verdict.Verdict {
		case domain.VerdictNoExploitPathFound:
			baseRationale = rationaleNoExploitPathFound(c)
		case domain.VerdictNotAffected:
			baseRationale = rationaleNotAffected(c)
		case domain.VerdictExploitable:
			baseRationale = rationaleExploitable(c)
		default:
			baseRationale = rationaleInconclusive(c)
		}
	}

	// Enrich with Justification dossier if available
	if c.Justification != nil {
		var b strings.Builder
		b.WriteString(baseRationale)
		if c.Justification.TechnicalMechanism != "" {
			b.WriteString(fmt.Sprintf("\n\n**Архитектурный контекст уязвимости:**\n%s", c.Justification.TechnicalMechanism))
		}
		if len(c.Justification.HumanRemainder) > 0 {
			b.WriteString("\n\n**Открытые вопросы для экспертного подтверждения (Human Remainder):**\n")
			for _, rem := range c.Justification.HumanRemainder {
				b.WriteString(fmt.Sprintf("- %s\n", rem.Question))
			}
		}
		return b.String()
	}

	return baseRationale
}

func rationale(c *domain.AnalysisCase) string {
	return TrackerRationale(c)
}

func shortRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "проекте"
	}
	base := filepath.Base(filepath.Clean(repo))
	if base == "." || base == "/" || base == "" {
		return repo
	}
	return base
}

func formatEnv(c *domain.AnalysisCase) string {
	var parts []string
	if c.Product.GoVersion != "" {
		parts = append(parts, "Go "+c.Product.GoVersion)
	}
	if c.Product.GOOS != "" && c.Product.GOARCH != "" {
		parts = append(parts, c.Product.GOOS+"/"+c.Product.GOARCH)
	}
	if len(c.Product.BuildTags) > 0 {
		parts = append(parts, "теги: "+strings.Join(c.Product.BuildTags, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func moduleAndVersion(c *domain.AnalysisCase) (string, string) {
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" && c.Affected != nil && len(c.Affected.CheckedModules) > 0 {
		mod = c.Affected.CheckedModules[0]
	}
	ver := ""
	if c.Affected != nil {
		ver = c.Affected.ResolvedVersion
	}
	return mod, ver
}

func defectDescription(c *domain.AnalysisCase) string {
	var mechanismDesc string
	if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		var parts []string
		for _, rc := range c.RootCause.RootCauses {
			if rc.Mechanism != "" && !strings.Contains(strings.ToLower(rc.Mechanism), "advisory") {
				parts = append(parts, fmt.Sprintf("%s (локализовано в `%s.%s`)", rootCauseMechanism(rc.Mechanism, true), rc.Package, rc.Symbol))
			}
		}
		if len(parts) > 0 {
			mechanismDesc = strings.Join(parts, "; ")
		}
	}
	if mechanismDesc != "" {
		return mechanismDesc
	}
	if c.Vulnerability.Description != "" {
		desc := strings.TrimSpace(c.Vulnerability.Description)
		if idx := strings.Index(desc, "\n\n"); idx > 0 {
			desc = desc[:idx]
		}
		if len(desc) > 300 {
			if idx := strings.Index(desc[200:], ". "); idx > 0 {
				desc = desc[:200+idx+1]
			}
		}
		if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
			rc := c.RootCause.RootCauses[0]
			return fmt.Sprintf("%s (локализовано в `%s.%s`)", desc, rc.Package, rc.Symbol)
		}
		return desc
	}
	if c.Vulnerability.Summary != "" {
		if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
			rc := c.RootCause.RootCauses[0]
			return fmt.Sprintf("%s (локализовано в `%s.%s`)", c.Vulnerability.Summary, rc.Package, rc.Symbol)
		}
		return c.Vulnerability.Summary
	}
	if c.Exploit != nil && c.Exploit.Impact != "" {
		return c.Exploit.Impact
	}
	if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		rc := c.RootCause.RootCauses[0]
		return fmt.Sprintf("дефект в реализации (локализовано в `%s.%s`)", rc.Package, rc.Symbol)
	}
	return "дефект в реализации библиотеки"
}

// admittedPackageInventory returns the package inventory the report may use
// for absence claims: a complete typed package-list record whose build
// context matches the analyzed build, admitted only under a scoped product
// target, decoded strictly. An untyped, partial or mismatched record never
// becomes an absence inference.
func admittedPackageInventory(c *domain.AnalysisCase) (affected.PackageInventory, bool) {
	if c == nil {
		return affected.PackageInventory{}, false
	}
	if err := domain.ValidateNegativeTarget(c.Product); err != nil {
		return affected.PackageInventory{}, false
	}
	e, err := domain.SelectCompletePackageList(c.Product, c.EvidenceGraph.EvidenceList())
	if err != nil {
		return affected.PackageInventory{}, false
	}
	inv, err := affected.CompletePackageInventory([]byte(e.Content), e.Command)
	if err != nil {
		return affected.PackageInventory{}, false
	}
	return inv, true
}

func linkedPackages(c *domain.AnalysisCase) map[string]bool {
	inv, ok := admittedPackageInventory(c)
	if !ok {
		return nil
	}
	return inv.Paths
}

type locusSymbolNote struct {
	Symbol domain.SymbolRef
	Basis  string
}

func splitAdvisoryPackages(c *domain.AnalysisCase) (absentPkgs, presentPkgs []string, presentNotes []locusSymbolNote) {
	linked := linkedPackages(c)
	advisoryPkgs := map[string]bool{}

	if c.Exploit != nil {
		for _, s := range c.Exploit.LocusSubjects {
			advisoryPkgs[s.Package] = true
		}
	}
	for _, ap := range c.Vulnerability.AffectedPackages {
		if ap.Path != "" {
			advisoryPkgs[ap.Path] = true
		}
	}

	for pkg := range advisoryPkgs {
		if linked != nil {
			if !linked[pkg] {
				absentPkgs = append(absentPkgs, pkg)
			} else {
				presentPkgs = append(presentPkgs, pkg)
			}
		}
	}
	sort.Strings(absentPkgs)
	sort.Strings(presentPkgs)

	seenSym := map[domain.SymbolRef]bool{}
	if c.Exploit != nil {
		for _, d := range c.Exploit.NonLocusBasis {
			if linked != nil && linked[d.Symbol.Package] && !seenSym[d.Symbol] {
				seenSym[d.Symbol] = true
				presentNotes = append(presentNotes, locusSymbolNote{Symbol: d.Symbol, Basis: d.Basis})
			}
		}
		for _, d := range c.Exploit.ProposedNonLocus {
			if linked != nil && linked[d.Symbol.Package] && !seenSym[d.Symbol] {
				seenSym[d.Symbol] = true
				presentNotes = append(presentNotes, locusSymbolNote{Symbol: d.Symbol, Basis: d.Basis})
			}
		}
	}
	return absentPkgs, presentPkgs, presentNotes
}

func formatExposureParagraph(c *domain.AnalysisCase, absentPkgs []string) string {
	var inbounds, outbounds []string
	for _, f := range c.EvidenceGraph.ExposuresList() {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		desc := fmt.Sprintf("`%s` (через `%s`)", loc, f.Target)
		if f.Direction == "inbound" {
			inbounds = append(inbounds, desc)
		} else if f.Direction == "outbound" {
			outbounds = append(outbounds, desc)
		}
	}
	var parts []string
	if len(inbounds) > 0 {
		parts = append(parts, fmt.Sprintf("В коде проекта сервер создаётся в: %s.", strings.Join(inbounds, ", ")))
	}
	if len(outbounds) > 0 {
		parts = append(parts, fmt.Sprintf("Клиентские подключения: %s.", strings.Join(outbounds, ", ")))
	}
	if len(absentPkgs) > 0 {
		parts = append(parts, fmt.Sprintf("Инициализация или вызовы через отсутствующие уязвимые пакеты (`%s`) в коде проекта не используются.",
			strings.Join(absentPkgs, "`, `")))
	}
	return strings.Join(parts, " ")
}

func formatExposureSummary(c *domain.AnalysisCase) string {
	var list []string
	for _, f := range c.EvidenceGraph.ExposuresList() {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		list = append(list, fmt.Sprintf("`%s` (`%s`)", loc, f.Target))
	}
	return strings.Join(list, ", ")
}

func formatPresentSymbolsParagraph(notes []locusSymbolNote) string {
	var b strings.Builder
	b.WriteString("То, что связанные пакеты входят в сборку, уязвимости не создаёт. Функции из advisory в скомпилированных пакетах:\n")
	for _, n := range notes {
		basis := n.Basis
		if basis == "" {
			basis = "дефектный код отсутствует"
		}
		basis = strings.ReplaceAll(basis, "accepted-machine-proposal", "принятая рекомендация анализатора")
		fmt.Fprintf(&b, "- `%s.%s`: %s\n", n.Symbol.Package, n.Symbol.Symbol, basis)
	}
	b.WriteString("Эти функции выполняют лишь диспетчеризацию или вспомогательную проверку, дефектная логика в них отсутствует, поэтому исполнение до дефекта не доходит.")
	return b.String()
}

func residualRisk(c *domain.AnalysisCase, absentPkgs []string) string {
	mod, _ := moduleAndVersion(c)
	_, best, ok := FixTarget(c)
	var fixNote string
	if ok && best != "" {
		fixNote = fmt.Sprintf(" Для устранения потребуется обновление `%s` до версии не ниже `%s`.", mod, best)
	} else if len(c.Vulnerability.FixedVersions) > 0 {
		fixNote = fmt.Sprintf(" Для устранения потребуется обновление до версии `%s`.", c.Vulnerability.FixedVersions[0])
	}

	if len(absentPkgs) > 0 {
		return fmt.Sprintf("Остаточный риск: если позже в проект будет добавлен импорт пакетов `%s` или сервер/клиент перейдёт на их использование, уязвимость станет применима.%s",
			strings.Join(absentPkgs, "`, `"), fixNote)
	}
	if fixNote != "" {
		return "Остаточный риск: при изменении конфигурации или пути вызовов уязвимость может стать активной." + fixNote
	}
	return ""
}

func rationaleNoExploitPathFound(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)

	b.WriteString("Not Exploitable (Уязвимость не эксплуатируется).\n\n")

	if mod != "" && ver != "" {
		if len(absentPkgs) > 0 {
			fmt.Fprintf(&b, "Библиотека в %s действительно `%s %s`, но код %s в сборку не входит и вызвать его нельзя. Это не ложное срабатывание (False Positive): сканер определил версию правильно, однако в данном снимке приложения уязвимый путь исполнения отсутствует.\n\n",
				repo, mod, ver, c.Vulnerability.ID)
		} else {
			fmt.Fprintf(&b, "Библиотека в %s действительно `%s %s`, но обязательное условие эксплуатации %s опровергнуто допущенным отрицательным доказательством. Это не ложное срабатывание (False Positive): сканер определил версию правильно, однако в записанной сборке, профиле и допущениях уязвимость не эксплуатируется. Код библиотеки при этом может присутствовать в сборке — вердикт не утверждает его отсутствие.\n\n",
				repo, mod, ver, c.Vulnerability.ID)
		}
	}

	if basis := groundBasisRationale(c); basis != "" {
		b.WriteString(basis)
		b.WriteString("\n\n")
	}

	env := formatEnv(c)
	if commit != "" {
		if mod != "" && ver != "" {
			fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s. В `go.mod` зависимость `%s` зафиксирована на версии `%s`.\n\n",
				c.Product.Repository, commit, env, mod, ver)
		} else {
			fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
				c.Product.Repository, commit, env)
		}
	}
	if negativeUsesBuildContext(c) {
		b.WriteString(buildScopeSentence(c, true))
		b.WriteString("\n\n")
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	if len(absentPkgs) > 0 {
		fmt.Fprintf(&b, "В графе зависимостей сборки (`go list -deps`) пакеты `%s` отсутствуют и в бинарный файл не попадают.\n\n",
			strings.Join(absentPkgs, "`, `"))
	}

	if expText := formatExposureParagraph(c, absentPkgs); expText != "" {
		b.WriteString(expText)
		b.WriteString("\n\n")
	}

	if len(presentNotes) > 0 {
		b.WriteString(formatPresentSymbolsParagraph(presentNotes))
		b.WriteString("\n\n")
	}

	if len(c.EvidenceGraph.CallPaths) > 0 {
		if len(absentPkgs) > 0 {
			b.WriteString("Сопоставление со сканером: `govulncheck` отмечает уязвимость как вызываемую (Reachable), обнаруживая пути вызова к вспомогательным функциям библиотеки. Однако углублённый анализ опровергает наличие уязвимости: вызываемые функции безопасны, а код с реальным дефектом в сборку не скомпилирован (ложная тревога govulncheck по достижимости).\n\n")
		} else {
			b.WriteString("Сопоставление со сканером: `govulncheck` отмечает уязвимость как вызываемую (Reachable), обнаруживая пути вызова к функциям библиотеки. Однако допущенное отрицательное доказательство опровергает обязательное условие эксплуатации: достижимые вызовы не позволяют эксплуатировать уязвимость в записанной сборке, профиле и допущениях. Отсутствие кода в сборке этим вердиктом не утверждается (ложная тревога govulncheck по достижимости).\n\n")
		}
	}

	if risk := residualRisk(c, absentPkgs); risk != "" {
		b.WriteString(risk)
	}

	return b.String()
}

// groundBasisRationale makes the trust basis of a NEPF verdict explicit
// in the human-readable report: a verdict resting on a declared or
// detected deployment trust boundary is an assumption, not a code-level
// proof, and must read as such in tracker-ready rationale.
func groundBasisRationale(c *domain.AnalysisCase) string {
	if c.Verdict == nil {
		return ""
	}
	switch c.Verdict.GroundBasis {
	case domain.BasisDeclaredTrust:
		return "Основание вердикта: заявленная граница доверия развертывания (`--trusted-peer`/`--perimeter`). Это допущение оператора о доверенности пиров и инфраструктуры, а не результат проверки кода — при смене условий деплоя вердикт требует пересмотра."
	case domain.BasisAutoPerimeter:
		return "Основание вердикта: автоматически определённый кластерный периметр по манифестам развертывания (ClusterIP/mesh-изоляция). Достоверность ограничена найденными манифестами — публичные маршруты вне сканированных файлов не учтены."
	case domain.BasisConfigOrigin:
		msg := "Основание вердикта: точный аргумент-триггер в каждом живом сайте объявленного sink'а разрешается в администраторскую конфигурацию; доверие к администраторской конфигурации — объявленное политическое допущение (`config-trust`), а не результат проверки кода."
		if c.Verdict != nil && len(c.Verdict.AssumptionIDs) > 0 {
			msg += " Политические допущения (не доказательства): " + strings.Join(c.Verdict.AssumptionIDs, ", ") + "."
		}
		return msg
	}
	return ""
}

func rationaleNotAffected(c *domain.AnalysisCase) string {
	// Defence in depth: a NOT_AFFECTED label without closure authority is
	// a component-scoped fact wearing a CVE-wide verdict. Render the
	// inconclusive rationale instead of advertising the whole advisory as
	// not applicable.
	if negativeClosureBlocked(c) {
		return rationaleInconclusive(c)
	}
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	env := formatEnv(c)

	b.WriteString("Not Affected (Уязвимость не применима к сервису).\n\n")

	if c.Affected != nil && c.Affected.VersionAffected == domain.ClaimFalse {
		fmt.Fprintf(&b, "Библиотека `%s` в %s используется в версии `%s`, которая не входит в диапазон уязвимых версий. Предупреждение сканера не применимо к текущей версии.\n\n",
			mod, repo, ver)
	} else if c.Affected != nil && c.Affected.ModulePresent == domain.ClaimFalse {
		fmt.Fprintf(&b, "Модуль `%s` не входит в граф зависимостей проекта %s (`go list -m all`). Код библиотеки в проекте отсутствует.\n\n",
			mod, repo)
	} else if c.Affected != nil && c.Affected.PackagePresent == domain.ClaimFalse {
		modDesc := mod
		if ver != "" {
			modDesc = fmt.Sprintf("%s %s", mod, ver)
		}
		isTestScope := false
		for _, lim := range c.Affected.Limitations {
			if strings.Contains(lim, "used only in test scope") {
				isTestScope = true
				break
			}
		}
		if isTestScope {
			fmt.Fprintf(&b, "Библиотека `%s` присутствует в `go.mod`, но используется исключительно во вспомогательном коде тестов и полностью отсутствует в графе зависимостей скомпилированных исполняемых файлов проекта %s. Код не попадает в релизные бинарники.\n\n",
				modDesc, repo)
		} else {
			fmt.Fprintf(&b, "Библиотека `%s` присутствует в `go.mod`, но ни один из уязвимых пакетов не импортируется кодом проекта %s (`go list -deps`). Код не скомпилирован в бинарный файл.\n\n",
				modDesc, repo)
		}
	} else {
		fmt.Fprintf(&b, "Уязвимость %s не применима к снимку %s: %s.\n\n",
			c.Vulnerability.ID, repo, localizeVerdictReason(c.Verdict.Reason, true))
	}

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	if negativeUsesBuildContext(c) {
		b.WriteString(buildScopeSentence(c, true))
		b.WriteString("\n\n")
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Изменений в коде или обновления зависимостей в данном снимке не требуется.\n")
	return b.String()
}

func rationaleExploitable(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	env := formatEnv(c)
	library := libraryAPIScope(c)

	if library {
		b.WriteString("Exploitable — область публичного API библиотеки (`library-api`).\n\n")
		fmt.Fprintf(&b, "В проекте %s подтверждена эксплуатация уязвимости %s в области публичного API библиотеки: полезная нагрузка, выбираемая потребителем библиотеки, достигает сайта дефекта через доказанную связку «публичный API → sink».\n\n",
			repo, c.Vulnerability.ID)
	} else {
		b.WriteString("Exploitable (Уязвимость подтверждена и эксплуатируема).\n\n")
		fmt.Fprintf(&b, "В проекте %s подтверждена возможность эксплуатации уязвимости %s (библиотека `%s %s`).\n\n",
			repo, c.Vulnerability.ID, mod, ver)
	}

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Факты проверки:\n")
	if library {
		for _, w := range libraryInputWitnesses(c) {
			fmt.Fprintf(&b, "- Привязка: %s.\n", witnessBindingText(w, true))
		}
		if c.Affected != nil && c.Affected.PackagePresent == domain.ClaimTrue {
			b.WriteString("- Пакет с уязвимой реализацией входит в граф зависимостей библиотеки (`go list -deps`); продуктовый бинарник в этой области не анализируется.\n")
		}
		b.WriteString("- Все обязательные условия эксплуатации в области публичного API библиотеки подтверждены.\n")
		fmt.Fprintf(&b, "- Область вывода: `%s` — %s.\n", domain.ScopeLibraryAPI, libraryScopeBoundaryText(true))
		b.WriteString("- Развёртывание: публичная доступность, наличие входящего сервиса и контроль входных данных со стороны атакующего в нижестоящем приложении не установлены и в область вывода не входят.\n")
		fmt.Fprintf(&b, "\nОграничение: %s\n\n", libraryAPILimitationText(true))
	} else {
		b.WriteString("- Уязвимый пакет входит в граф зависимостей сборки (`go list -deps`) и скомпилирован в бинарный файл.\n")
		if expText := formatExposureSummary(c); expText != "" {
			fmt.Fprintf(&b, "- Входные точки взаимодействия: %s.\n", expText)
		}
		b.WriteString("- Все обязательные условия эксплуатации дефекта подтверждены.\n\n")
	}

	_, best, ok := FixTarget(c)
	if ok && best != "" {
		fmt.Fprintf(&b, "Требуется исправление: обновите зависимость `%s` до версии `%s` (`go get %s@%s && go mod tidy`) либо примените компенсирующие меры защиты.\n",
			mod, best, mod, best)
	} else {
		b.WriteString("Требуется исправление или применение компенсирующих мер защиты.\n")
	}

	return b.String()
}

func rationaleInconclusive(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	env := formatEnv(c)
	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)

	b.WriteString("Требуется ручной анализ (Inconclusive).\n\n")

	fmt.Fprintf(&b, "Для уязвимости %s в проекте %s (библиотека `%s %s`) автоматический анализ не смог сделать однозначный вывод: %s.\n\n",
		c.Vulnerability.ID, repo, mod, ver, localizeVerdictReason(c.Verdict.Reason, true))

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Результаты проверки:\n")
	if a := c.Affected; a != nil && a.HasNegative() && negativeClosureBlocked(c) {
		checked := checkedScopeNames(c)
		if checked == "" {
			checked = "проверенные компоненты"
		}
		fmt.Fprintf(&b, "- Отрицательный факт относится только к проверенному компоненту (`%s`): версия `%s` %s. Это компонентный факт, а не закрытие всего CVE — исправленная версия частного компонента не доказывает отсутствие уязвимых реализаций в оставшейся области `%s`.\n",
			checked, a.ResolvedVersion, componentFactText(a), requestedAdvisoryID(c))
	}
	if len(absentPkgs) > 0 {
		fmt.Fprintf(&b, "- Пакеты `%s` отсутствуют в графе сборки (`go list -deps`) и физически не скомпилированы.\n",
			strings.Join(absentPkgs, "`, `"))
	}
	if len(presentNotes) > 0 {
		// A symbol the analysis proved REACHABLE (C-REACH/C-LOCUS TRUE) is
		// not an exclusion candidate: proposing to dismiss it as "not
		// touched by the fix" contradicts the case's own evidence. The
		// advisory label stays in the audit register, but it must not be
		// offered to the operator as an action here.
		var names []string
		for _, n := range presentNotes {
			if symbolReachProven(c, n.Symbol) {
				continue
			}
			names = append(names, fmt.Sprintf("`%s.%s` (%s)", n.Symbol.Package, n.Symbol.Symbol, n.Basis))
		}
		if len(names) > 0 {
			fmt.Fprintf(&b, "- Для функций в скомпилированных пакетах сформированы рекомендации об исключении: %s.\n",
				strings.Join(names, ", "))
			b.WriteString("  Машинные рекомендации не применяются автоматически: исключение становится авторитетным только как явное экспертное решение (`--non-locus-basis`).\n")
		}
	}
	// What the analysis DID establish, and the one gap that remains. Without
	// this the reader gets a verdict word and an empty "results" list.
	if admissionRefusedBuildDependent(c) {
		b.WriteString(buildScopeSentence(c, true))
		b.WriteString("\n")
	}
	writeEstablishedFacts(&b, c)
	if libraryAPIScope(c) {
		fmt.Fprintf(&b, "- Область вывода: `%s` — %s.\n", domain.ScopeLibraryAPI, libraryScopeBoundaryText(true))
		fmt.Fprintf(&b, "- Ограничение: %s\n", libraryAPILimitationText(true))
	}
	if expText := formatExposureSummary(c); expText != "" && !libraryAPIScope(c) {
		fmt.Fprintf(&b, "- Точки взаимодействия в коде: %s.\n", expText)
	}
	return b.String()
}

// FixTarget picks the smallest published fixed version above the
// resolved one. ok=false when the component is not affected or the
// module cannot be named; version="" with ok=true means no fix exists.
func FixTarget(c *domain.AnalysisCase) (module, version string, ok bool) {
	if c.Affected == nil || c.Affected.VersionAffected != domain.ClaimTrue {
		return "", "", false
	}
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" {
		return "", "", false
	}
	resolved := c.Affected.ResolvedVersion
	var best string
	for _, f := range c.Vulnerability.FixedVersions {
		fv := normalizeSemver(f)
		if fv == "" {
			continue
		}
		if resolved != "" && semver.Compare(fv, normalizeSemver(resolved)) <= 0 {
			continue
		}
		if best == "" || semver.Compare(fv, best) < 0 {
			best = fv
		}
	}
	return mod, best, true
}

// FixCompatibility checks whether upgrading from resolved to fixed version
// is a drop-in minor/patch replacement or requires a major version bump.
func FixCompatibility(resolved, fixed string) (dropIn bool, majorBump bool, ok bool) {
	r := normalizeSemver(resolved)
	f := normalizeSemver(fixed)
	if r == "" || f == "" {
		return false, false, false
	}
	majR := semver.Major(r)
	majF := semver.Major(f)
	if majF == majR {
		return true, false, true
	}
	return false, true, true
}

func populateUpgradeCompatibility(c *domain.AnalysisCase) {
	if c == nil || c.Affected == nil {
		return
	}
	_, fixed, ok := FixTarget(c)
	if !ok || fixed == "" {
		c.Affected.UpgradeDropIn = false
		c.Affected.UpgradeMajorBump = false
		return
	}
	dropIn, majorBump, compOk := FixCompatibility(c.Affected.ResolvedVersion, fixed)
	if compOk {
		c.Affected.UpgradeDropIn = dropIn
		c.Affected.UpgradeMajorBump = majorBump
	} else {
		c.Affected.UpgradeDropIn = false
		c.Affected.UpgradeMajorBump = false
	}
}

// remediation renders a deterministic fix recommendation: the smallest
// fixed version above the resolved one, plus the go command to apply it.
// Empty when the component is not affected or no fix is published.
func remediation(c *domain.AnalysisCase, langRU ...bool) string {
	isRU := len(langRU) > 0 && langRU[0]
	mod, best, ok := FixTarget(c)
	if !ok {
		return ""
	}
	populateUpgradeCompatibility(c)
	resolved := c.Affected.ResolvedVersion
	if best == "" {
		if isRU {
			return fmt.Sprintf("Для зависимости `%s` (текущая: `%s`) нет опубликованных версий с исправлением. "+
				"Рассмотрите возможность фиксации безопасной версии или наложения патча.", mod, resolved)
		}
		return fmt.Sprintf("No fixed version published for `%s` (current: `%s`). "+
			"Consider pinning an unaffected release or vendoring a patch.", mod, resolved)
	}

	var notice string
	if c.Affected != nil {
		if c.Affected.UpgradeDropIn {
			if isRU {
				notice = " (совместимо по SemVer: minor/patch, без изменения импортов)"
			} else {
				notice = " (SemVer drop-in: minor/patch, no import path changes)"
			}
		} else if c.Affected.UpgradeMajorBump {
			maj := semver.Major(normalizeSemver(best))
			if isRU {
				notice = fmt.Sprintf(" (Внимание: смена мажорной версии %s, требуются обновление путей импорта и адаптация API)", maj)
			} else {
				notice = fmt.Sprintf(" (Notice: major version bump to %s, import path changes and API adaptation required)", maj)
			}
		}
	}

	if isRU {
		return fmt.Sprintf("Обновите зависимость `%s` с `%s` до `%s`%s:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
			mod, resolved, best, notice, mod, best)
	}
	return fmt.Sprintf("Update `%s` from `%s` to `%s`%s:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
		mod, resolved, best, notice, mod, best)
}

// normalizeSemver maps "1.2.3"/"v1.2.3" onto canonical semver for compare.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func renderTriageAssessment(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	r := c.ContextualRisk
	if r == nil {
		if c.Verdict == nil {
			return
		}
		res := risk.Assess(c.Vulnerability, c, *c.Verdict)
		r = &res
		c.ContextualRisk = r
	}

	baseSev := r.BaseSeverity
	if baseSev == "" {
		baseSev = "CRITICAL"
	}
	baseScoreStr := fmt.Sprintf("%.1f", r.BaseScore)
	if r.BaseScore <= 0 {
		baseScoreStr = "N/A"
	}

	nominalPrio := nominalPriority(baseSev, r.BaseScore, isRU)

	contextualSevStr := formatContextualSeverity(r.ContextualLevel, r.ContextualScore, isRU)
	contextualPrioStr := formatTriagePriority(r.Priority, isRU)
	exposureStr := formatExposureTriage(r.Factors.Exposure, c, isRU)
	controlsStr := formatControlsTriage(r.Factors.Authentication, r.Factors.Exposure, isRU)

	nomPrioVal := risk.NominalPriority(baseSev, r.BaseScore)
	isDowngraded := r.ContextualScore < r.BaseScore || r.Priority != nomPrioVal

	if isRU {
		b.WriteString("## Контекстная критичность и триаж (Triage Assessment)\n\n")
		b.WriteString("| Параметр | Исходная оценка (CVE / NVD) | Контекстная оценка в продукте |\n")
		b.WriteString("|---|---|---|\n")
		fmt.Fprintf(b, "| **Критичность** | %s (CVSS %s) | %s |\n", formatSeverityBadge(baseSev), baseScoreStr, contextualSevStr)
		fmt.Fprintf(b, "| **Приоритет в очереди** | %s | %s |\n", nominalPrio, contextualPrioStr)
		fmt.Fprintf(b, "| **Сетевая доступность** | — | %s |\n", exposureStr)
		fmt.Fprintf(b, "| **Компенсирующие меры** | — | %s |\n\n", controlsStr)

		if r.AdjustmentReason != "" {
			if isDowngraded {
				fmt.Fprintf(b, "> ℹ️ **Обоснование переоценки (понижение):**\n> %s\n\n", r.AdjustmentReason)
			} else {
				fmt.Fprintf(b, "> ℹ️ **Обоснование оценки:**\n> %s\n\n", r.AdjustmentReason)
			}
		}
	} else {
		b.WriteString("## Contextual Severity & Triage Assessment\n\n")
		b.WriteString("| Parameter | Baseline (CVE / NVD) | Contextual Assessment in Product |\n")
		b.WriteString("|---|---|---|\n")
		fmt.Fprintf(b, "| **Severity** | %s (CVSS %s) | %s |\n", formatSeverityBadge(baseSev), baseScoreStr, contextualSevStr)
		fmt.Fprintf(b, "| **Triage Priority** | %s | %s |\n", nominalPrio, contextualPrioStr)
		fmt.Fprintf(b, "| **Network Exposure** | — | %s |\n", exposureStr)
		fmt.Fprintf(b, "| **Compensating Controls** | — | %s |\n\n", controlsStr)

		if r.AdjustmentReason != "" {
			if isDowngraded {
				fmt.Fprintf(b, "> ℹ️ **Score Downgrade Rationale:**\n> %s\n\n", r.AdjustmentReason)
			} else {
				fmt.Fprintf(b, "> ℹ️ **Assessment Rationale:**\n> %s\n\n", r.AdjustmentReason)
			}
		}
	}
}

func formatExposureTriage(exp string, c *domain.AnalysisCase, isRU bool) string {
	var addr string
	if c != nil {
		for _, f := range c.EvidenceGraph.ExposuresList() {
			if f.Direction == "inbound" && f.Kind == "listener" && f.Address != "" {
				addr = f.Address
				break
			}
		}
	}
	switch exp {
	case "PUBLIC":
		if isRU {
			if addr != "" {
				return fmt.Sprintf("Внешняя сеть (`%s`)", addr)
			}
			return "Внешняя сеть (все интерфейсы 0.0.0.0)"
		}
		if addr != "" {
			return fmt.Sprintf("External Network (`%s`)", addr)
		}
		return "External Network (0.0.0.0)"
	case "INTERNAL":
		if isRU {
			if addr != "" {
				return fmt.Sprintf("Локальный интерфейс (`%s`)", addr)
			}
			return "Локальный интерфейс (127.0.0.1)"
		}
		if addr != "" {
			return fmt.Sprintf("Local Interface (`%s`)", addr)
		}
		return "Local Interface (127.0.0.1)"
	case "UNKNOWN":
		// No exposure fact was resolved: neither public exposure nor its
		// absence is established.
		if isRU {
			return "Факты о сетевой экспозиции не установлены"
		}
		return "Exposure facts unresolved"
	default:
		if isRU {
			return "Слушатели не обнаружены"
		}
		return "No Listeners Detected"
	}
}

func formatControlsTriage(authn, exp string, isRU bool) string {
	if authn == "REQUIRED" {
		if isRU {
			return "Аутентификация / контроль доступа"
		}
		return "Authentication / Access Control"
	}
	if exp == "INTERNAL" {
		if isRU {
			return "Сетевая изоляция (localhost / loopback)"
		}
		return "Network Isolation (localhost / loopback)"
	}
	if exp == "UNKNOWN" {
		if isRU {
			return "Не установлены"
		}
		return "Not established"
	}
	if isRU {
		return "В кодовой базе не обнаружены"
	}
	return "None detected in codebase"
}

func formatSeverityBadge(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "BLOCKER":
		return "🔴 **CRITICAL**"
	case "HIGH":
		return "🟠 **HIGH**"
	case "MEDIUM", "MODERATE":
		return "🟡 **MEDIUM**"
	case "LOW":
		return "🟢 **LOW**"
	case "NONE":
		return "⚪ **NONE**"
	default:
		return "⚪ **" + sev + "**"
	}
}

func formatContextualSeverity(level domain.RiskLevel, score float64, isRU bool) string {
	badge := formatSeverityBadge(string(level))
	if level == domain.RiskLevelNone {
		return badge + " (Score 0.0)"
	}
	if score > 0 {
		return fmt.Sprintf("%s (Score %.1f)", badge, score)
	}
	return badge
}

func nominalPriority(baseSev string, baseScore float64, isRU bool) string {
	sev := strings.ToUpper(baseSev)
	if baseScore >= 9.0 || sev == "CRITICAL" || sev == "BLOCKER" {
		return "**P0 (Blocker)**"
	}
	if baseScore >= 7.0 || sev == "HIGH" {
		return "**P1 (Critical)**"
	}
	if baseScore >= 4.0 || sev == "MEDIUM" || sev == "MODERATE" {
		return "**P2 (Medium)**"
	}
	return "**P3 (Low)**"
}

func formatTriagePriority(p domain.TriagePriority, isRU bool) string {
	switch p {
	case domain.PriorityP0:
		return "**P0 (Blocker)**"
	case domain.PriorityP1:
		return "**P1 (Critical)**"
	case domain.PriorityP2:
		if isRU {
			return "**P2 (Плановый спринт)**"
		}
		return "**P2 (Scheduled Sprint)**"
	case domain.PriorityP3:
		if isRU {
			return "**P3 (Низкий приоритет)**"
		}
		return "**P3 (Low Priority)**"
	case domain.PriorityDismissed:
		if isRU {
			return "**DISMISSED (Снято)**"
		}
		return "**DISMISSED (No Action)**"
	default:
		return "**" + string(p) + "**"
	}
}

func formatRiskStatus(s domain.ContextualRiskStatus, isRU bool) string {
	switch s {
	case domain.RiskStatusAssessed:
		if isRU {
			return "**ASSESSED** (Подтверждено контекстом)"
		}
		return "**ASSESSED** (Confirmed by Context)"
	case domain.RiskStatusProvisional:
		if isRU {
			return "**PROVISIONAL** (Предварительно / Требуется триаж)"
		}
		return "**PROVISIONAL** (Provisional / Triage Required)"
	case domain.RiskStatusNotApplicable:
		if isRU {
			return "**NOT_APPLICABLE** (Не применимо к сборке)"
		}
		return "**NOT_APPLICABLE** (Not Applicable)"
	default:
		return "**" + string(s) + "**"
	}
}

func profileContourAndModel(p domain.ProfileVerdict, isRU bool) (string, string) {
	switch p.Profile {
	case domain.ProfileClusterPerimeter:
		if isRU {
			return "Внутренний кластер / Mesh", "Доверенная инфраструктура"
		}
		return "Internal Cluster / Mesh", "Trusted Infrastructure"
	case domain.ProfileZeroTrust:
		if isRU {
			return "Публичный интернет", "Zero Trust / Hostile Peer"
		}
		return "Public Internet", "Zero Trust / Hostile Peer"
	default:
		name := string(p.Profile)
		if p.Title != "" {
			name = p.Title
		}
		return name, string(p.Profile)
	}
}

func verdictBadge(v domain.Verdict) string {
	switch v {
	case domain.VerdictNoExploitPathFound, domain.VerdictNotAffected:
		return "🟢"
	case domain.VerdictExploitable:
		return "🔴"
	case domain.VerdictInconclusive:
		return "🟡"
	default:
		return "⚪"
	}
}

func perimeterActionRecommendation(p domain.TriagePriority, isActual, isRU bool) string {
	switch p {
	case domain.PriorityDismissed:
		if isActual {
			if isRU {
				return "Действий не требуется: уязвимость закрыта сетевым периметром."
			}
			return "No remediation required: vulnerability neutralized by network perimeter."
		}
		if isRU {
			return "Условие переоценки: если в целевой среде подтверждена изоляция (ClusterIP/Mesh), уязвимость может быть снята."
		}
		return "Re-evaluation condition: if cluster isolation (ClusterIP/Mesh) is confirmed in target environment, finding can be dismissed."
	case domain.PriorityP0:
		if isRU {
			return "Блокирующий приоритет: требуется первоочередное устранение (обновление зависимости или компенсирующий контроль)."
		}
		return "Blocker: immediate priority remediation required (dependency update or compensating control)."
	case domain.PriorityP1:
		if isRU {
			return "Высокий приоритет: требуется плановое устранение или аудит компенсирующих мер защиты."
		}
		return "High priority: planned remediation or compensating controls audit required."
	case domain.PriorityP2:
		if isRU {
			return "Плановый приоритет: устранение в рамках регулярного релизного цикла."
		}
		return "Scheduled priority: remediation within regular release cycle."
	default:
		if isRU {
			return "Внимание: при изменении сетевой конфигурации или выносе сервиса за пределы контура потребуется повторная оценка."
		}
		return "Notice: re-evaluation required if network configuration changes or service is exposed."
	}
}

func localizePerimeter(p string, isRU bool) string {
	if !isRU {
		return p
	}
	switch p {
	case domain.PerimeterPublic:
		return "Публичный (public)"
	case domain.PerimeterClusterInternal:
		return "Внутрикластерный (cluster-internal)"
	case domain.PerimeterUnknown:
		return "Не определён (unknown)"
	default:
		return p
	}
}

func localizePerimeterRationale(rationale string, isRU bool) string {
	if !isRU || rationale == "" || rationale == "-" {
		return rationale
	}
	switch rationale {
	case "no deployment exposure facts resolved; defaulting to zero-trust":
		return "Факты сетевой конфигурации не обнаружены; по умолчанию применяется модель нулевого доверия (zero-trust)"
	case "no structural cluster-isolation evidence (ClusterIP service or loopback/unix-only listeners); defaulting to zero-trust":
		return "Структурные свидетельства изоляции внутри кластера отсутствуют (ClusterIP или только loopback/unix слушатели); по умолчанию применяется модель нулевого доверия (zero-trust)"
	case "ClusterIP service found":
		return "Обнаружен сервис ClusterIP"
	}

	res := rationale
	if strings.HasPrefix(res, "public exposure detected: ") {
		res = "Обнаружен публичный доступ: " + strings.TrimPrefix(res, "public exposure detected: ")
	} else if strings.HasPrefix(res, "cluster-internal perimeter: ") {
		res = "Внутрикластерный периметр: " + strings.TrimPrefix(res, "cluster-internal perimeter: ")
	} else if strings.HasPrefix(res, "unattributed external-routing manifests may front the service: ") {
		res = "Внешние маршрутизирующие манифесты без атрибуции могут обслуживать сервис: " + strings.TrimPrefix(res, "unattributed external-routing manifests may front the service: ")
	} else if strings.HasPrefix(res, "loopback/unix listeners present but inbound exposure unresolved: ") {
		res = "Обнаружены loopback/unix слушатели, но входящий сетевой периметр полностью не разрешён: " + strings.TrimPrefix(res, "loopback/unix listeners present but inbound exposure unresolved: ")
	} else if strings.HasPrefix(res, "unresolved inbound exposure: ") {
		res = "Неразрешённый входящий сетевой периметр: " + strings.TrimPrefix(res, "unresolved inbound exposure: ")
	}

	res = strings.ReplaceAll(res, "; no public ingress found", "; публичный ingress не обнаружен")
	res = strings.ReplaceAll(res, "; unresolved inbound surfaces bounded by declared service scope: ", "; неразрешённые входящие интерфейсы ограничены областью сервиса: ")
	res = strings.ReplaceAll(res, "inbound listener ", "входящий слушатель ")
	return res
}

func renderPerimeterMatrix(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if len(c.Profiles) == 0 {
		return
	}

	detPerimeter := c.DetectedPerimeter
	if detPerimeter == "" {
		detPerimeter = domain.PerimeterUnknown
	}
	detRationale := c.PerimeterRationale
	if detRationale == "" {
		detRationale = "-"
	}

	if isRU {
		b.WriteString("### Матрица сетевых периметров угроз\n\n")
		fmt.Fprintf(b, "- **Обнаруженный периметр развёртывания:** `%s`\n", localizePerimeter(detPerimeter, true))
		fmt.Fprintf(b, "- **Обоснование периметра:** %s\n\n", localizePerimeterRationale(detRationale, true))
		if libraryAPIScope(c) {
			fmt.Fprintf(b, "- **Область вывода:** `%s` — %s\n", domain.ScopeLibraryAPI, libraryScopeBoundaryText(true))
			b.WriteString("- **Периметр развёртывания:** относится к нижестоящему приложению, а не к библиотеке; публичная доступность самой библиотеки не устанавливалась.\n\n")
		}
		b.WriteString("| Сетевой контур | Модель угроз | Вердикт анализатора | Приоритет триажа | Действие для команды |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, p := range c.Profiles {
			contour, model := profileContourAndModel(p, true)
			icon := verdictBadge(p.Verdict)
			verdictCell := fmt.Sprintf("%s **%s**", icon, p.Verdict)
			if p.ExploitabilityScope != "" {
				verdictCell += fmt.Sprintf(" (область: `%s`)", p.ExploitabilityScope)
			}
			action := perimeterActionRecommendation(p.Priority, p.IsTargetActual, true)
			if p.IsTargetActual {
				fmt.Fprintf(b, "| **%s** *(Фактический)* | %s | %s | **%s** | %s |\n",
					contour, model, verdictCell, p.Priority, action)
			} else {
				fmt.Fprintf(b, "| **%s** *(Гипотетический)* | %s | %s | **%s** | %s |\n",
					contour, model, verdictCell, p.Priority, action)
			}
		}
		b.WriteString("\n")

		if libraryAPIScope(c) {
			b.WriteString("#### Варианты защиты на уровне нижестоящего приложения (Consumer Deployment Mitigations)\n\n")
			b.WriteString("Если обновление библиотеки затруднено, нижестоящее приложение может компенсировать уязвимость на уровне своего периметра (применимость зависит от потребителя):\n\n")
		} else {
			b.WriteString("#### Варианты защиты и изоляции для различных сред (Deployment Mitigations)\n\n")
			b.WriteString("Если оперативное обновление библиотеки затруднено, уязвимость может быть компенсирована на уровне сетевого контура:\n\n")
		}
		b.WriteString("1. **Kubernetes / OpenShift:**\n")
		b.WriteString("   - Развёртывание сервиса только как `ClusterIP` (без создания внешних `Ingress`, `Gateway`, `NodePort` или `LoadBalancer`).\n")
		b.WriteString("   - Настройка `Istio Service Mesh`: включение строгого mTLS (`PeerAuthentication: STRICT`) и политик авторизации (`AuthorizationPolicy`) для ограничения доступа только доверенными сервисами.\n")
		b.WriteString("   - Использование `NetworkPolicy` для блокировки трафика от подов вне доверенного пространства имён.\n")
		b.WriteString("   *(Для автоматического учёта изоляции анализатором передайте путь к манифестам через `--deploy-manifests <каталог/архив>` или укажите целевой профиль `--perimeter cluster`)*.\n\n")
		b.WriteString("2. **Виртуальные машины и Bare-Metal:**\n")
		b.WriteString("   - Настройка межсетевого экрана (iptables / nftables / AWS Security Groups), разрешающего подключения к порту только с доверенных IP-адресов.\n")
		b.WriteString("   - Размещение сервиса за Reverse Proxy (Nginx / Envoy / HAProxy) с предварительной аутентификацией и ограничением размера/формата входящих тел запросов.\n\n")
		b.WriteString("3. **Локальный запуск и Sidecar-архитектура:**\n")
		b.WriteString("   - Привязка слушателя исключительно к локальному интерфейсу `127.0.0.1` или использование unix domain socket (`/var/run/...`).\n\n")
	} else {
		b.WriteString("### Security Perimeter Matrix\n\n")
		fmt.Fprintf(b, "- **Detected Deployment Perimeter:** `%s`\n", detPerimeter)
		fmt.Fprintf(b, "- **Perimeter Rationale:** %s\n\n", detRationale)
		if libraryAPIScope(c) {
			fmt.Fprintf(b, "- **Exploitability scope:** `%s` — %s\n", domain.ScopeLibraryAPI, libraryScopeBoundaryText(false))
			b.WriteString("- **Deployment perimeter:** describes a consuming application, not the library; public exposure of the library itself was not established.\n\n")
		}
		b.WriteString("| Security Perimeter | Threat Model | Analyzer Verdict | Triage Priority | Recommended Action |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, p := range c.Profiles {
			contour, model := profileContourAndModel(p, false)
			icon := verdictBadge(p.Verdict)
			verdictCell := fmt.Sprintf("%s **%s**", icon, p.Verdict)
			if p.ExploitabilityScope != "" {
				verdictCell += fmt.Sprintf(" (scope: `%s`)", p.ExploitabilityScope)
			}
			action := perimeterActionRecommendation(p.Priority, p.IsTargetActual, false)
			if p.IsTargetActual {
				fmt.Fprintf(b, "| **%s** *(Actual)* | %s | %s | **%s** | %s |\n",
					contour, model, verdictCell, p.Priority, action)
			} else {
				fmt.Fprintf(b, "| **%s** *(Hypothetical)* | %s | %s | **%s** | %s |\n",
					contour, model, verdictCell, p.Priority, action)
			}
		}
		b.WriteString("\n")

		if libraryAPIScope(c) {
			b.WriteString("#### Mitigation Options for a Consuming Application\n\n")
			b.WriteString("If the library upgrade is blocked, a consuming application can mitigate at its own perimeter (applicability depends on the consumer):\n\n")
		} else {
			b.WriteString("#### Mitigation Options Across Deployment Environments\n\n")
			b.WriteString("If immediate library upgrade is blocked, the vulnerability can be mitigated at the deployment perimeter:\n\n")
		}
		b.WriteString("1. **Kubernetes / OpenShift:**\n")
		b.WriteString("   - Deploy as `ClusterIP` service without public `Ingress`, `Gateway`, `NodePort`, or `LoadBalancer`.\n")
		b.WriteString("   - Configure `Istio Service Mesh`: enforce strict mTLS (`PeerAuthentication: STRICT`) and `AuthorizationPolicy` allowing only trusted workloads.\n")
		b.WriteString("   - Apply `NetworkPolicy` ingress rules restricting network traffic to authorized namespaces.\n")
		b.WriteString("   *(To evaluate in this mode, pass `--deploy-manifests <path/archive>` or `--perimeter cluster`)*.\n\n")
		b.WriteString("2. **Virtual Machines & Bare-Metal:**\n")
		b.WriteString("   - Configure host or cloud firewall (iptables / Security Groups) blocking external access to the port.\n")
		b.WriteString("   - Terminate traffic behind a reverse proxy (Nginx / Envoy) with pre-authentication and request body validation.\n\n")
		b.WriteString("3. **Local & Sidecar Workloads:**\n")
		b.WriteString("   - Bind listener exclusively to loopback (`127.0.0.1`) or a UNIX domain socket.\n\n")
	}
}

func extractFixSubject(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Subject: [PATCH] ") {
			return strings.TrimPrefix(trimmed, "Subject: [PATCH] ")
		}
		if strings.HasPrefix(trimmed, "Subject: ") {
			return strings.TrimPrefix(trimmed, "Subject: ")
		}
	}
	trimmed := strings.TrimSpace(content)
	if idx := strings.Index(trimmed, "\n"); idx > 0 {
		return trimmed[:idx]
	}
	return trimmed
}

// writeEstablishedFacts states positively what the run proved and names the
// single unresolved condition, so an INCONCLUSIVE summary is actionable
// instead of empty. Facts are read from the claims, never assumed.
func writeEstablishedFacts(b *strings.Builder, c *domain.AnalysisCase) {
	rc := ""
	if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		r := c.RootCause.RootCauses[0]
		rc = fmt.Sprintf("`%s.%s`", r.Package, r.Symbol)
	}
	library := libraryAPIControlProven(c)
	linked := ""
	if c.Affected != nil && c.Affected.PackagePresent == domain.ClaimTrue {
		if library {
			linked = "пакет с уязвимой реализацией входит в граф зависимостей библиотеки (`go list -deps`)"
		} else {
			linked = "пакет слинкован в продуктовую сборку"
		}
	}
	reached := false
	for _, cl := range c.Claims {
		if cl.ConditionID == "C-REACH" && cl.Result == domain.ClaimTrue {
			reached = true
			break
		}
	}
	var proven []string
	if linked != "" {
		proven = append(proven, linked)
	}
	if reached {
		where := "уязвимая функция"
		if rc != "" {
			where = rc
		}
		proven = append(proven, fmt.Sprintf("%s достижима из кода продукта", where))
	}
	if library {
		if ws := libraryInputWitnesses(c); len(ws) > 0 {
			binds := make([]string, 0, len(ws))
			for _, w := range ws {
				binds = append(binds, witnessBindingText(w, true))
			}
			proven = append(proven, "полезная нагрузка выбирается потребителем библиотеки и без изменения байтов достигает уязвимого вызова: "+strings.Join(binds, "; "))
		} else {
			proven = append(proven, "полезная нагрузка выбирается потребителем библиотеки через публичный API и достигает уязвимого вызова")
		}
	}
	if len(proven) > 0 {
		fmt.Fprintf(b, "- Доказано: %s.\n", strings.Join(proven, "; "))
	}
	if library {
		// A library-basis TRUE claim leaves deployment control unasked, not
		// "unresolved": name the remaining condition without reverting to
		// remote-delivery wording.
		for _, cl := range c.Claims {
			if cl.Result != domain.ClaimUnknown {
				continue
			}
			reason := "условие не разрешено"
			for _, lim := range cl.Limitations {
				reason = lim
				break
			}
			fmt.Fprintf(b, "- Не доказано (`%s`): %s — вывод остаётся ограниченным публичным API библиотеки; контроль со стороны атакующего в нижестоящем приложении не устанавливается.\n", cl.ConditionID, reason)
		}
		return
	}
	for _, cl := range c.Claims {
		if cl.Result == domain.ClaimUnknown && cl.ConditionID == "C-INPUT" {
			reason := "источник аргумента уязвимого вызова не разрешён"
			for _, lim := range cl.Limitations {
				reason = lim
				break
			}
			fmt.Fprintf(b, "- Не доказано (`C-INPUT`): %s — поэтому доставка вредоносного ввода извне не подтверждена.\n", reason)
			fmt.Fprintf(b, "- Что требуется: подтвердить или опровергнуть контроль входных данных в точке вызова (кто поставщик аргумента) либо задать модель периметра/доверенного пира для этого продукта.\n")
			return
		}
	}
}

// symbolReachProven reports whether the case's own reachability evidence
// covers this symbol — a positive C-REACH/C-LOCUS claim over it means the
// analysis proved the code is executed, so it cannot be recommended for
// exclusion.
func symbolReachProven(c *domain.AnalysisCase, s domain.SymbolRef) bool {
	for _, cl := range c.Claims {
		if cl.Result != domain.ClaimTrue {
			continue
		}
		if cl.ConditionID != "C-REACH" && cl.ConditionID != "C-LOCUS" {
			continue
		}
		if c.Exploit == nil {
			continue
		}
		for _, cond := range c.Exploit.MandatoryConditions {
			if cond.ID != cl.ConditionID {
				continue
			}
			for _, sub := range cond.Subjects {
				if sub.Package == s.Package && sub.Symbol == s.Symbol {
					return true
				}
			}
		}
	}
	return false
}

// attackerControlProven reports whether the case actually established that
// attacker-controlled data reaches the vulnerable call at deployment level.
// Only a TRUE C-INPUT claim grounds that statement; UNKNOWN leaves it
// unproven, and a library-public-api basis proves consumer selectability, not
// deployment exposure.
func attackerControlProven(c *domain.AnalysisCase) bool {
	for _, cl := range c.Claims {
		// A library-public-api basis proves consumer selectability, not
		// deployment attacker control. Reporting it here would fabricate a
		// remote-client fact; libraryInputControl is reported separately and
		// visible through the witness/scope surfaces.
		if cl.ConditionID == "C-INPUT" && cl.Result == domain.ClaimTrue &&
			cl.ControlBasis != domain.ControlBasisLibraryPublicAPI {
			return true
		}
		if cl.ConditionID == "C-PEER-INPUT" && cl.Result == domain.ClaimFalse {
			return false
		}
	}
	return false
}

// claimEvidenceRefs renders the evidence ids backing the condition's claim,
// so a verification row cites what actually grounded it instead of a fixed
// reference that may not exist in this case.
func claimEvidenceRefs(c *domain.AnalysisCase, cond domain.ConditionID) string {
	for _, cl := range c.Claims {
		if cl.ConditionID != cond {
			continue
		}
		if len(cl.EvidenceIDs) == 0 {
			return "—"
		}
		ids := make([]string, 0, len(cl.EvidenceIDs))
		for _, id := range cl.EvidenceIDs {
			ids = append(ids, string(id))
		}
		return strings.Join(ids, ", ")
	}
	return "—"
}

func renderVulnerabilityDetails(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.Verdict == nil || (c.Verdict.Verdict != domain.VerdictExploitable && c.Verdict.Verdict != domain.VerdictInconclusive) {
		return
	}

	mod, _ := moduleAndVersion(c)
	inputProven := attackerControlProven(c)
	library := libraryAPIScope(c)

	defectText := c.Vulnerability.Description
	if defectText == "" {
		defectText = c.Vulnerability.Summary
	}
	if defectText == "" && c.Exploit != nil {
		defectText = c.Exploit.Impact
	}
	if defectText == "" {
		defectText = "Дефект в обработке входных данных библиотекой."
	}

	var fixMsg string
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceFixDiff && e.Content != "" {
			fixMsg = extractFixSubject(e.Content)
			break
		}
	}

	var entryLoc, entryAddr string
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction == "inbound" && f.Kind == "listener" {
			entryLoc = fmt.Sprintf("`%s:%d` (`%s`)", filepath.Base(f.File), f.Line, f.Target)
			entryAddr = f.Address
			break
		}
	}

	var callLoc, callTarget string
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceSourceSnippet && e.File != "" {
			if e.StartLine > 0 {
				callLoc = fmt.Sprintf("`%s:%d`", filepath.Base(e.File), e.StartLine)
			} else {
				callLoc = fmt.Sprintf("`%s`", filepath.Base(e.File))
			}
			if e.Content != "" {
				callTarget = fmt.Sprintf("`%s`", strings.TrimSpace(e.Content))
			}
			break
		}
	}
	if callTarget == "" && c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		rc := c.RootCause.RootCauses[0]
		callTarget = fmt.Sprintf("`%s.%s`", rc.Package, rc.Symbol)
	}

	cweStr := strings.Join(c.Vulnerability.CWE, ", ")
	if cweStr == "" && c.Exploit != nil && c.Exploit.Class != "" {
		cweStr = c.Exploit.Class
	}
	if cweStr == "" {
		cweStr = "Resource Exhaustion / DoS"
	}

	if isRU {
		if library {
			b.WriteString("### Суть уязвимости и сценарий использования библиотеки\n\n")
		} else {
			b.WriteString("### Суть уязвимости и сценарий воздействия\n\n")
		}
		b.WriteString("#### Механизм дефекта в библиотеке\n\n")
		fmt.Fprintf(b, "%s\n\n", defectText)
		if cweStr != "" {
			fmt.Fprintf(b, "- **Класс дефекта:** `%s`\n", cweStr)
		}
		if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
			rc := c.RootCause.RootCauses[0]
			fmt.Fprintf(b, "- **Точка сбоя в библиотеке (Sink):** `%s.%s`\n", rc.Package, rc.Symbol)
		}
		if fixMsg != "" {
			fmt.Fprintf(b, "- **Суть исправляющего коммита:** %s\n", fixMsg)
		}
		b.WriteString("\n")

		if library {
			renderLibraryConsumerScenario(b, c, true)
		} else {
			b.WriteString("#### Сценарий атаки на сервис\n\n")
			if entryLoc != "" {
				if entryAddr != "" {
					fmt.Fprintf(b, "1. **Приём внешнего запроса:** сервис принимает входящее сетевое подключение на открытом порту `%s` (%s).\n", entryAddr, entryLoc)
				} else {
					fmt.Fprintf(b, "1. **Приём внешнего запроса:** сервис принимает входящее сетевое подключение (%s).\n", entryLoc)
				}
			} else {
				b.WriteString("1. **Приём внешнего запроса:** сетевой сервис принимает запрос от недоверенного источника.\n")
			}
			if callLoc != "" && callTarget != "" {
				fmt.Fprintf(b, "2. **Передача данных в уязвимую библиотеку:** обработчик в %s передаёт необработанные входные данные в %s.\n", callLoc, callTarget)
			} else if callTarget != "" {
				fmt.Fprintf(b, "2. **Передача данных в уязвимую библиотеку:** входные данные передаются аргументом в %s.\n", callTarget)
			} else {
				fmt.Fprintf(b, "2. **Передача данных в уязвимую библиотеку:** входные данные передаются в функции библиотеки `%s`.\n", mod)
			}
			b.WriteString("3. **Срабатывание дефекта:** некорректно сформированный ввод вызывает неконтролируемую панику/ошибку разбора (`panic`), которая не перехватывается приложением и приводит к аварийной остановке (Crash/DoS) процесса сервера.\n\n")
		}

		b.WriteString("#### Границы воздействия (Impact Boundaries)\n\n")
		if library {
			renderLibraryImpactBoundaries(b, c, true)
		} else {
			if inputProven {
				b.WriteString("- 💥 **Отказ в обслуживании (Denial of Service):** **Подтверждён** — падение процесса сервера при обработке вредоносного запроса.\n")
			} else {
				b.WriteString("- 💥 **Отказ в обслуживании (Denial of Service):** **Механизм подтверждён, эксплуатация не доказана** — паника при разборе достижима, но контроль входных данных не установлен, поэтому доставка вредоносного ввода не подтверждена.\n")
			}
			b.WriteString("- 🛡️ **Удалённое выполнение кода (RCE):** **Исключено** — дефект не позволяет повреждать память или выполнять произвольный код.\n")
			b.WriteString("- 🛡️ **Утечка конфиденциальных данных:** **Исключена** — дефект не приводит к чтению неинициализированной памяти или обходу прав доступа.\n\n")
		}
	} else {
		if library {
			b.WriteString("### Vulnerability Defect & Library Consumer Scenario\n\n")
		} else {
			b.WriteString("### Vulnerability Defect & Attack Scenario\n\n")
		}
		b.WriteString("#### Defect Mechanism in Library\n\n")
		fmt.Fprintf(b, "%s\n\n", defectText)
		if cweStr != "" {
			fmt.Fprintf(b, "- **Defect Class:** `%s`\n", cweStr)
		}
		if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
			rc := c.RootCause.RootCauses[0]
			fmt.Fprintf(b, "- **Vulnerable Sink Symbol:** `%s.%s`\n", rc.Package, rc.Symbol)
		}
		if fixMsg != "" {
			fmt.Fprintf(b, "- **Fix Commit Rationale:** %s\n", fixMsg)
		}
		b.WriteString("\n")

		if library {
			renderLibraryConsumerScenario(b, c, false)
		} else {
			b.WriteString("#### Product Attack Scenario\n\n")
			if entryLoc != "" {
				if entryAddr != "" {
					fmt.Fprintf(b, "1. **Inbound Request Ingestion:** service accepts network connections on listener `%s` (%s).\n", entryAddr, entryLoc)
				} else {
					fmt.Fprintf(b, "1. **Inbound Request Ingestion:** service accepts network connections (%s).\n", entryLoc)
				}
			} else {
				b.WriteString("1. **Inbound Request Ingestion:** service accepts input from untrusted network peers.\n")
			}
			if callLoc != "" && callTarget != "" {
				fmt.Fprintf(b, "2. **Forwarding to Vulnerable Library:** handler at %s passes input directly into %s.\n", callLoc, callTarget)
			} else if callTarget != "" {
				fmt.Fprintf(b, "2. **Forwarding to Vulnerable Library:** input is passed directly into %s.\n", callTarget)
			} else {
				fmt.Fprintf(b, "2. **Forwarding to Vulnerable Library:** input is passed into library `%s`.\n", mod)
			}
			b.WriteString("3. **Defect Trigger:** malformed payload triggers an unhandled parser panic, crashing the server process (Denial of Service).\n\n")
		}

		b.WriteString("#### Impact Boundaries\n\n")
		if library {
			renderLibraryImpactBoundaries(b, c, false)
		} else {
			if inputProven {
				b.WriteString("- 💥 **Denial of Service (DoS):** **Confirmed** — unhandled panic crashes the process on malicious input.\n")
			} else {
				b.WriteString("- 💥 **Denial of Service (DoS):** **Mechanism confirmed, exploitation not established** — the parser panic is reachable, but input control is unresolved, so delivery of a malicious payload is not proven.\n")
			}
			b.WriteString("- 🛡️ **Remote Code Execution (RCE):** **Ruled out** — no memory corruption or arbitrary command execution primitives.\n")
			b.WriteString("- 🛡️ **Data Exfiltration / Confidentiality:** **Ruled out** — no unauthorized data reads or access control bypass.\n\n")
		}
	}
}

// packageInclusionFact renders the build-graph inclusion claim from the
// affected package axis. Inclusion is stated only when that axis is TRUE: an
// UNKNOWN or unrecorded package membership is a fact the analysis did not
// establish, and the key-facts table must not upgrade it to "Included".
func packageInclusionFact(present domain.ClaimResult, library, isRU bool) (status, detail string) {
	switch present {
	case domain.ClaimTrue:
		switch {
		case library && isRU:
			return "🔴 Включена", "Пакет с уязвимой реализацией входит в граф зависимостей библиотеки (`go list -deps`); продуктовый бинарник не анализируется"
		case library:
			return "🔴 Included", "The vulnerable package is in the library dependency graph (`go list -deps`); no product binary is analyzed"
		case isRU:
			return "🔴 Включена", "Пакет скомпилирован в бинарный файл сборки (`go list -deps`)"
		default:
			return "🔴 Included", "The package is compiled into the build binary (`go list -deps`)"
		}
	case domain.ClaimFalse:
		switch {
		case library && isRU:
			return "🟢 Исключена", "Уязвимый пакет отсутствует в графе зависимостей библиотеки"
		case library:
			return "🟢 Excluded", "The vulnerable package is absent from the library dependency graph"
		case isRU:
			return "🟢 Исключена", "Уязвимый пакет отсутствует в бинарном файле сборки"
		default:
			return "🟢 Excluded", "The vulnerable package is absent from the build binary"
		}
	default:
		if isRU {
			return "🟡 Наличие не измерено", "Вхождение уязвимого пакета в граф сборки не установлено: включение не заявляется"
		}
		return "🟡 Presence not measured", "Package membership in the build graph was not established: inclusion is not claimed"
	}
}

func renderKeyVerificationFacts(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.Affected == nil && len(c.Claims) == 0 {
		return
	}

	mod, ver := moduleAndVersion(c)
	library := libraryAPIScope(c)
	scopeOpen := c.Affected != nil && c.Affected.HasNegative() && negativeClosureBlocked(c)
	checked := checkedScopeNames(c)
	if checked == "" {
		checked = "checked component"
		if isRU {
			checked = "проверенный компонент"
		}
	}

	fact1Status := "🔴 Уязвима"
	fact1Detail := fmt.Sprintf("`%s %s` (входит в уязвимый диапазон)", mod, ver)
	fact1Ref := "EV-AFFECTED-MODULES"
	if !isRU {
		fact1Status = "🔴 Affected"
		fact1Detail = fmt.Sprintf("`%s %s` (inside the affected range)", mod, ver)
	}
	if c.Affected != nil && c.Affected.VersionAffected == domain.ClaimFalse {
		if scopeOpen {
			if isRU {
				fact1Status = "🟡 Вне диапазона (частный компонент)"
				fact1Detail = fmt.Sprintf("`%s %s` (вне диапазона; отрицательный факт покрывает только `%s` — запрошенная область `%s` не закрыта)",
					mod, ver, checked, requestedAdvisoryID(c))
			} else {
				fact1Status = "🟡 Outside range (component only)"
				fact1Detail = fmt.Sprintf("`%s %s` (outside the range; the negative fact covers only `%s` — requested scope `%s` is not closed)",
					mod, ver, checked, requestedAdvisoryID(c))
			}
		} else {
			fact1Status = "🟢 Безопасна"
			fact1Detail = fmt.Sprintf("`%s %s` (вне диапазона)", mod, ver)
			if !isRU {
				fact1Status = "🟢 Safe"
				fact1Detail = fmt.Sprintf("`%s %s` (outside the affected range)", mod, ver)
			}
		}
	}

	fact2Ref := "EV-AFFECTED-PACKAGES"
	var pkgPresent domain.ClaimResult
	if c.Affected != nil {
		pkgPresent = c.Affected.PackagePresent
	}
	fact2Status, fact2Detail := packageInclusionFact(pkgPresent, false, isRU)
	if library {
		// A library has no product binary: state the package dependency
		// graph, never "compiled into the build binary".
		fact2Ref = "—"
		fact2Status, fact2Detail = packageInclusionFact(pkgPresent, true, isRU)
	}
	if scopeOpen && pkgPresent == domain.ClaimFalse {
		// The absence is a real local fact, but it covers only the checked
		// component: it must not read as a whole-finding safe result.
		if isRU {
			fact2Status = "🟡 Исключена (частный компонент)"
			fact2Detail += fmt.Sprintf(" — компонентный факт; запрошенная область `%s` не закрыта", requestedAdvisoryID(c))
		} else {
			fact2Status = "🟡 Excluded (component only)"
			fact2Detail += fmt.Sprintf(" — component-level fact; requested scope `%s` is not closed", requestedAdvisoryID(c))
		}
	}

	gc := selectGovulncheckEvidence(c)
	fact3Status := "🔴 Достижим"
	fact3Detail := "Трасса статических вызовов от точки входа достигает уязвимой функции"
	fact3Ref := "EV-006"
	if len(c.EvidenceGraph.CallPaths) == 0 {
		fact3Status = "🟡 Достижимость не измерена"
		fact3Detail = "Нет завершённого измерения govulncheck для этой сборки: отсутствие путей вызова не установлено"
		if gc.Admitted && gc.Outcome == domain.GovulncheckCompletedEmpty && gc.silenceQualified() {
			fact3Status = "🟡 Не обнаружена в измеренной области"
			fact3Detail = "Завершённый прогон govulncheck не обнаружил путей вызова в измеренной области; это не утверждение обо всех поддерживаемых вариантах сборки"
		}
	}
	if !isRU {
		fact3Status = "🔴 Reachable"
		fact3Detail = "A static call trace from an entry point reaches the vulnerable function"
		if len(c.EvidenceGraph.CallPaths) == 0 {
			fact3Status = "🟡 Reachability not measured"
			fact3Detail = "No completed govulncheck measurement for this build: the absence of call paths is not established"
			if gc.Admitted && gc.Outcome == domain.GovulncheckCompletedEmpty && gc.silenceQualified() {
				fact3Status = "🟡 Not found in the measured scope"
				fact3Detail = "A completed govulncheck run found no call path in the measured scope; this does not assert every supported build variant"
			}
		}
	}
	if library {
		// The library's entry surface is its public API, not a deployment
		// entry point, and C-REACH/C-LOCUS carry the proof.
		reached := false
		for _, cl := range c.Claims {
			if (cl.ConditionID == "C-REACH" || cl.ConditionID == "C-LOCUS") && cl.Result == domain.ClaimTrue {
				reached = true
				break
			}
		}
		if reached {
			if isRU {
				fact3Status = "🔴 Достижим"
				fact3Detail = "Доказана достижимость уязвимой функции из публичного API библиотеки"
			} else {
				fact3Status = "🔴 Reachable"
				fact3Detail = "A proven trace from the library public API reaches the vulnerable function"
			}
		} else if len(c.EvidenceGraph.CallPaths) == 0 {
			if isRU {
				fact3Status = "🟡 Не доказана"
				fact3Detail = "Достижимость уязвимой функции из публичного API библиотеки не доказана"
			} else {
				fact3Status = "🟡 Not proven"
				fact3Detail = "Reachability from the library public API to the vulnerable function was not proven"
			}
		}
		fact3Ref = claimEvidenceRefs(c, "C-REACH")
	}

	// Attacker control is a measured claim, not a default. An unresolved
	// C-INPUT means the analyzer did NOT establish who supplies the data —
	// reporting it as "Untrusted input" next to an INCONCLUSIVE verdict
	// states a fact the analysis explicitly failed to prove.
	fact4Status := "🟡 Контроль не установлен"
	fact4Detail := "Источник аргумента в уязвимом вызове не разрешён; контроль входных данных не доказан"
	fact4Ref := claimEvidenceRefs(c, "C-INPUT")
	trustedInput := false
	inputProven := attackerControlProven(c)
	for _, cl := range c.Claims {
		if cl.ConditionID == "C-PEER-INPUT" && cl.Result == domain.ClaimFalse {
			trustedInput = true
			break
		}
	}
	if inputProven && !trustedInput {
		fact4Status = "🔴 Недоверенный ввод"
		fact4Detail = "Входные данные от удалённого клиента передаются аргументом в уязвимый код"
	}
	if trustedInput {
		fact4Status = "🟢 Доверенный ввод"
		fact4Detail = "Входные данные контролируются доверенной конфигурацией хоста"
	}
	if !isRU {
		fact4Status = "🟡 Input control unresolved"
		fact4Detail = "The origin of the argument at the vulnerable call is unresolved; attacker control was not established"
		if inputProven && !trustedInput {
			fact4Status = "🔴 Untrusted input"
			fact4Detail = "Remote client input is passed as an argument into the vulnerable code"
		}
		if trustedInput {
			fact4Status = "🟢 Trusted input"
			fact4Detail = "Input is governed by trusted host configuration"
		}
	}
	if libraryAPIControlProven(c) {
		// Consumer selectability is a code fact; deployment attacker
		// control is not. This row must never read as remote client input.
		fact4Ref = claimEvidenceRefs(c, "C-INPUT")
		binding := ""
		if ws := libraryInputWitnesses(c); len(ws) > 0 {
			binding = witnessBindingText(ws[0], isRU)
		}
		if isRU {
			fact4Status = "🔴 Выбираемо потребителем"
			if binding != "" {
				fact4Detail = "Полезная нагрузка выбирается потребителем библиотеки: " + binding + "; контроль со стороны атакующего в нижестоящем приложении не установлен"
			} else {
				fact4Detail = "Полезная нагрузка выбирается потребителем библиотеки через публичный API и передаётся в уязвимый вызов; контроль со стороны атакующего в нижестоящем приложении не установлен"
			}
		} else {
			fact4Status = "🔴 Consumer-selectable"
			if binding != "" {
				fact4Detail = "The payload is selectable by a library consumer: " + binding + "; deployment-level attacker control in a consuming application is not established"
			} else {
				fact4Detail = "The payload is selectable by a library consumer through the public API and reaches the vulnerable call; deployment-level attacker control in a consuming application is not established"
			}
		}
	}

	fact5Status := "🔴 Открыт наружу"
	fact5Detail := "Сетевой слушатель привязан ко всем интерфейсам (0.0.0.0)"
	fact5Ref := "EV-022"
	if c.ContextualRisk != nil {
		switch c.ContextualRisk.Factors.Exposure {
		case "INTERNAL":
			fact5Status = "🟢 Локальный"
			fact5Detail = "Слушатель ограничен локальным интерфейсом (127.0.0.1)"
		case "UNKNOWN", "NONE":
			fact5Status = "⚪ Не установлено"
			fact5Detail = "Факты о сетевой экспозиции не установлены: слушатели не обнаружены, но отсутствие внешнего доступа не доказано"
		}
	}
	if !isRU {
		fact5Status = "🔴 Public"
		fact5Detail = "The network listener binds all interfaces (0.0.0.0)"
		if c.ContextualRisk != nil {
			switch c.ContextualRisk.Factors.Exposure {
			case "INTERNAL":
				fact5Status = "🟢 Local"
				fact5Detail = "The listener is bound to a local interface (127.0.0.1)"
			case "UNKNOWN", "NONE":
				fact5Status = "⚪ Unresolved"
				fact5Detail = "Exposure facts are unresolved: no listener was found, and the absence of external exposure is not established either"
			}
		}
	}
	if library {
		// The analyzed product is a library: deployment exposure is not a
		// property of it, and no 0.0.0.0/public fact may be implied.
		fact5Ref = "—"
		if isRU {
			fact5Status = "⚪ Вне области (библиотека)"
			fact5Detail = "Сетевой периметр развёртывания не анализируется: публичная доступность и привязка ко всем сетевым интерфейсам не установлены"
		} else {
			fact5Status = "⚪ Out of scope (library)"
			fact5Detail = "The deployment network perimeter is not analyzed: public exposure and an all-interfaces bind are not established"
		}
	}

	if isRU {
		b.WriteString("### Сводка ключевых фактов проверки (Key Verification Facts)\n\n")
		b.WriteString("| Проверка | Статус | Значение в продукте | Артефакт |\n")
		b.WriteString("|---|---|---|---|\n")
		fact2Label := "Наличие в сборке бинарника"
		fact3Label := "Достижимость в графе вызовов"
		fact4Label := "Контроль входных данных"
		fact5Label := "Сетевая доступность"
		if library {
			fact2Label = "Наличие в графе зависимостей библиотеки"
			fact3Label = "Достижимость из публичного API"
			fact4Label = "Выбираемость полезной нагрузки"
			fact5Label = "Сетевой периметр развёртывания"
		}
		fmt.Fprintf(b, "| **1. Зависимость и версия** | %s | %s | `%s` |\n", fact1Status, fact1Detail, fact1Ref)
		fmt.Fprintf(b, "| **2. %s** | %s | %s | `%s` |\n", fact2Label, fact2Status, fact2Detail, fact2Ref)
		fmt.Fprintf(b, "| **3. %s** | %s | %s | `%s` |\n", fact3Label, fact3Status, fact3Detail, fact3Ref)
		fmt.Fprintf(b, "| **4. %s** | %s | %s | `%s` |\n", fact4Label, fact4Status, fact4Detail, fact4Ref)
		fmt.Fprintf(b, "| **5. %s** | %s | %s | `%s` |\n\n", fact5Label, fact5Status, fact5Detail, fact5Ref)
		if c.Verdict != nil && isNegativeVerdict(c.Verdict.Verdict) && negativeUsesBuildContext(c) {
			fmt.Fprintf(b, "> %s\n\n", buildScopeSentence(c, true))
		}
		if scopeOpen {
			fmt.Fprintf(b, "> Примечание: зелёные и жёлтые статусы выше — компонентные факты для проверенной области `%s`; они не закрывают запрошенную область `%s`.\n\n",
				checked, requestedAdvisoryID(c))
		}
		if library {
			fmt.Fprintf(b, "> Область вывода: `%s` — %s.\n> Ограничение: %s\n\n",
				domain.ScopeLibraryAPI, libraryScopeBoundaryText(true), libraryAPILimitationText(true))
		}
	} else {
		b.WriteString("### Key Verification Facts\n\n")
		b.WriteString("| Verification Step | Status | Product Finding | Evidence Ref |\n")
		b.WriteString("|---|---|---|---|\n")
		fact2Label := "Compiled into Binary"
		fact3Label := "Reachable Call Path"
		fact4Label := "Untrusted Input Control"
		fact5Label := "Network Exposure"
		if library {
			fact2Label = "Library Dependency Graph"
			fact3Label = "Public API Reachability"
			fact4Label = "Payload Selectability"
			fact5Label = "Deployment Network Perimeter"
		}
		fmt.Fprintf(b, "| **1. Dependency & Version** | %s | %s | `%s` |\n", fact1Status, fact1Detail, fact1Ref)
		fmt.Fprintf(b, "| **2. %s** | %s | %s | `%s` |\n", fact2Label, fact2Status, fact2Detail, fact2Ref)
		fmt.Fprintf(b, "| **3. %s** | %s | %s | `%s` |\n", fact3Label, fact3Status, fact3Detail, fact3Ref)
		fmt.Fprintf(b, "| **4. %s** | %s | %s | `%s` |\n", fact4Label, fact4Status, fact4Detail, fact4Ref)
		fmt.Fprintf(b, "| **5. %s** | %s | %s | `%s` |\n\n", fact5Label, fact5Status, fact5Detail, fact5Ref)
		if c.Verdict != nil && isNegativeVerdict(c.Verdict.Verdict) && negativeUsesBuildContext(c) {
			fmt.Fprintf(b, "> %s\n\n", buildScopeStatement(c))
		}
		if scopeOpen {
			fmt.Fprintf(b, "> Note: the green and amber statuses above are component-level facts for the checked scope `%s`; they do not close the requested scope `%s`.\n\n",
				checked, requestedAdvisoryID(c))
		}
		if library {
			fmt.Fprintf(b, "> Exploitability scope: `%s` — %s.\n> Limitation: %s\n\n",
				domain.ScopeLibraryAPI, libraryScopeBoundaryText(false), libraryAPILimitationText(false))
		}
	}
}

func renderSemanticAnalysisSummary(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.SemanticReview != nil || c.CVEAnalysis != nil {
		if isRU {
			b.WriteString("### Семантический анализ кода и патча (Semantic Analysis)\n\n")
			if c.SemanticReview != nil {
				reviewer := c.SemanticReview.Reviewer
				if reviewer == "" {
					reviewer = "AI Reviewer"
				}
				fmt.Fprintf(b, "- **Рецензент:** `%s`\n", reviewer)
				if len(c.SemanticReview.Findings) > 0 {
					b.WriteString("- **Выводы анализа:**\n")
					for _, f := range c.SemanticReview.Findings {
						fmt.Fprintf(b, "  - %s\n", f)
					}
				}
			}
			if c.CVEAnalysis != nil && len(c.CVEAnalysis.Mechanisms) > 0 {
				b.WriteString("- **Смоделированные механизмы:**\n")
				for _, m := range c.CVEAnalysis.Mechanisms {
					fmt.Fprintf(b, "  - %s (sinks: `%s`)\n", m.Summary, strings.Join(m.FaultingSites, "`, `"))
				}
			}
			b.WriteString("\n")
		} else {
			b.WriteString("### Semantic Analysis & Code Review\n\n")
			if c.SemanticReview != nil {
				reviewer := c.SemanticReview.Reviewer
				if reviewer == "" {
					reviewer = "AI Reviewer"
				}
				fmt.Fprintf(b, "- **Reviewer:** `%s`\n", reviewer)
				if len(c.SemanticReview.Findings) > 0 {
					b.WriteString("- **Key Findings:**\n")
					for _, f := range c.SemanticReview.Findings {
						fmt.Fprintf(b, "  - %s\n", f)
					}
				}
			}
			if c.CVEAnalysis != nil && len(c.CVEAnalysis.Mechanisms) > 0 {
				b.WriteString("- **Modeled Mechanisms:**\n")
				for _, m := range c.CVEAnalysis.Mechanisms {
					fmt.Fprintf(b, "  - %s (sinks: `%s`)\n", m.Summary, strings.Join(m.FaultingSites, "`, `"))
				}
			}
			b.WriteString("\n")
		}
		return
	}

	inputProven := attackerControlProven(c)
	var fixSummary string
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceFixDiff && e.Content != "" {
			fixSummary = extractFixSubject(e.Content)
			break
		}
	}

	if isRU {
		b.WriteString("### Семантический анализ кода и патча (Semantic Analysis)\n\n")
		b.WriteString("- **Режим анализа:** Детерминированный статический анализ (LLM-адаптеры не подключались).\n")
		if fixSummary != "" {
			fmt.Fprintf(b, "- **Семантика патча (Fix Diff):** В коммите исправления («%s») добавлена проверка ошибок перед вызовом. В исследуемой версии библиотеки эта проверка отсутствует.\n", fixSummary)
		}
		b.WriteString("- **Семантика точки вызова:** Предварительная валидация или санитизация входных данных на трассированном пути к разбору не обнаружена.\n")
		if inputProven {
			b.WriteString("- **Обработка аварийных ситуаций (Panic Recovery):** Перехват `recover()` на трассированном пути отсутствует; необработанная паника библиотеки завершает процесс.\n\n")
		} else if libraryAPIScope(c) {
			b.WriteString("- **Обработка аварийных ситуаций (Panic Recovery):** Перехват `recover()` на доказанном пути «публичный API → sink» не обнаружен; доставка ввода на уровне нижестоящего приложения находится за пределами анализа.\n\n")
		} else {
			b.WriteString("- **Обработка аварийных ситуаций (Panic Recovery):** Проверка перехвата `recover()` не выполнялась — путь доставки ввода не установлен.\n\n")
		}
	} else {
		b.WriteString("### Semantic Analysis & Code Review\n\n")
		b.WriteString("- **Analysis Mode:** Deterministic static analysis (LLM adapters disabled).\n")
		if fixSummary != "" {
			fmt.Fprintf(b, "- **Patch Semantics (Fix Diff):** Upstream fix commit (\"%s\") introduced bounds/error checking before execution. The analyzed library version lacks this guard.\n", fixSummary)
		}
		b.WriteString("- **Call Site Semantics:** No pre-validation or sanitization was found on the traced path to the parser.\n")
		if inputProven {
			b.WriteString("- **Panic Recovery:** No `recover()` guard is present on the traced path; an unhandled library panic terminates the process.\n\n")
		} else if libraryAPIScope(c) {
			b.WriteString("- **Panic Recovery:** No `recover()` guard is present on the proven public-API → sink path; consumer-level delivery is outside the analysis.\n\n")
		} else {
			b.WriteString("- **Panic Recovery:** Not assessed — the input delivery path was not established.\n\n")
		}
	}
}

func renderEvidenceRegister(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	evList := c.EvidenceGraph.EvidenceList()
	if len(evList) == 0 {
		return
	}

	if isRU {
		b.WriteString("### Реестр доказательств (Evidence Register)\n\n")
		b.WriteString("| ID | Тип доказательства | Источник / Инструмент | Суть доказательства / Свидетельство |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, e := range evList {
			kindDesc := formatEvidenceKind(e.Kind, true)
			srcDesc := formatEvidenceSource(e, true)
			detail := formatEvidenceDetail(e, c, true)
			fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", e.ID, kindDesc, srcDesc, detail)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("### Evidence Register\n\n")
		b.WriteString("| ID | Kind | Source / Tool | Details / Findings |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, e := range evList {
			kindDesc := formatEvidenceKind(e.Kind, false)
			srcDesc := formatEvidenceSource(e, false)
			detail := formatEvidenceDetail(e, c, false)
			fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", e.ID, kindDesc, srcDesc, detail)
		}
		b.WriteString("\n")
	}
}

func formatEvidenceKind(k domain.EvidenceKind, isRU bool) string {
	if !isRU {
		switch k {
		case domain.EvidenceGovulncheck:
			return "Call Graph (govulncheck)"
		case domain.EvidenceModuleGraph:
			return "Module Graph (go.mod)"
		case domain.EvidencePackageList:
			return "Package Graph (deps)"
		case domain.EvidenceSourceSnippet:
			return "Source Snippet (AST)"
		case domain.EvidenceCallPath:
			return "Call Path"
		case domain.EvidenceDataFlow:
			return "Data Flow"
		case domain.EvidenceConfiguration:
			return "Network / Config"
		case domain.EvidenceEntrypoint:
			return "Entrypoint"
		case domain.EvidenceSearchResult:
			return "Symbol / Config"
		case domain.EvidenceAdvisory:
			return "Security Advisory"
		case domain.EvidenceFixDiff:
			return "Fix Patch (Diff)"
		case domain.EvidenceRuntime:
			return "Runtime Environment"
		default:
			return string(k)
		}
	}
	switch k {
	case domain.EvidenceGovulncheck:
		return "Анализ вызовов (govulncheck)"
	case domain.EvidenceModuleGraph:
		return "Граф модулей (go.mod)"
	case domain.EvidencePackageList:
		return "Граф пакетов сборки"
	case domain.EvidenceSourceSnippet:
		return "Исходный код (AST)"
	case domain.EvidenceCallPath:
		return "Путь вызова"
	case domain.EvidenceDataFlow:
		return "Поток данных (Taint/Flow)"
	case domain.EvidenceConfiguration:
		return "Сетевая конфигурация"
	case domain.EvidenceEntrypoint:
		return "Точка входа"
	case domain.EvidenceSearchResult:
		return "Символ / Конфиг"
	case domain.EvidenceAdvisory:
		return "База уязвимостей (Advisory)"
	case domain.EvidenceFixDiff:
		return "Патч исправления (Diff)"
	case domain.EvidenceRuntime:
		return "Среда выполнения"
	default:
		return string(k)
	}
}

func formatEvidenceSource(e domain.Evidence, isRU bool) string {
	if e.File != "" {
		base := filepath.Base(e.File)
		if e.StartLine > 0 {
			return fmt.Sprintf("`%s:%d`", base, e.StartLine)
		}
		return fmt.Sprintf("`%s`", base)
	}
	if e.Command != "" {
		return fmt.Sprintf("`%s`", sanitizeTableString(e.Command, 40))
	}
	if e.Tool != "" {
		return fmt.Sprintf("`%s`", sanitizeTableString(e.Tool, 35))
	}
	if e.Source != "" {
		return sanitizeTableString(e.Source, 40)
	}
	return "-"
}

// govulncheckCoverageText renders a typed coverage record for a table cell.
func govulncheckCoverageText(cov domain.GovulncheckCoverage, isRU bool) string {
	m := govulncheckMeasurement{Coverage: cov}
	note := m.coverageNote()
	if isRU {
		return localizeCoverageNote(note)
	}
	return note
}

// formatGovulncheckEvidenceDetail renders one govulncheck evidence record.
// A call path is shown only when a recorded CallPath is actually bound to
// this evidence id; evidence presence or a typed outcome never implies a
// call path. Failed and not-run records render as unmeasured, never clean.
func formatGovulncheckEvidenceDetail(e domain.Evidence, c *domain.AnalysisCase, isRU bool) string {
	var matched *domain.CallPath
	for i := range c.EvidenceGraph.CallPaths {
		cp := &c.EvidenceGraph.CallPaths[i]
		if cp.EvidenceID == e.ID && len(cp.Frames) > 0 {
			matched = cp
			break
		}
	}
	callPath := func(cp *domain.CallPath) string {
		first := cp.Frames[0].Function
		last := cp.Frames[len(cp.Frames)-1].Function
		if isRU {
			return fmt.Sprintf("Трасса вызова (%d кадров): `%s` → ... → `%s`", len(cp.Frames), first, last)
		}
		return fmt.Sprintf("Call path (%d frames): `%s` → ... → `%s`", len(cp.Frames), first, last)
	}
	buildNote := ""
	if e.BuildContext == nil {
		buildNote = "recorded run has no build context"
	} else if err := e.BuildContext.Matches(domain.EffectiveBuildContext(c.Product)); err != nil {
		buildNote = "recorded run describes a different build: " + err.Error()
	}
	withBuild := func(detail string) string {
		if buildNote == "" {
			return detail
		}
		if isRU {
			return detail + " (запись прогона не описывает анализируемую сборку)"
		}
		return detail + " (" + buildNote + ")"
	}

	r := e.Govulncheck
	if r == nil {
		// A legacy record without a typed outcome is not a measurement. A
		// call path bound to it is still recorded evidence, but the run's
		// completion is unknown.
		if matched != nil {
			if isRU {
				return callPath(matched) + " (запись прогона без типизированного исхода)"
			}
			return callPath(matched) + " (legacy record without a typed run outcome)"
		}
		if isRU {
			return "Запись govulncheck без типизированного исхода — статус неизвестен"
		}
		return "govulncheck record without a typed run outcome — status unknown"
	}
	switch r.Outcome {
	case domain.GovulncheckFailed:
		errText := r.Error
		if errText == "" {
			errText = "process failed"
		}
		if isRU {
			return withBuild("Прогон govulncheck не удался: " + sanitizeTableString(errText, 90) + " — измерение достижимости отсутствует")
		}
		return withBuild("govulncheck failed: " + sanitizeTableString(errText, 90) + " — no reachability measurement")
	case domain.GovulncheckNotRun:
		errText := r.Error
		if errText == "" {
			errText = "not executed"
		}
		if isRU {
			return withBuild("Прогон govulncheck не выполнялся: " + sanitizeTableString(errText, 90) + " — измерение достижимости отсутствует")
		}
		return withBuild("govulncheck not run: " + sanitizeTableString(errText, 90) + " — no reachability measurement")
	}
	coverage := govulncheckCoverageText(r.Coverage, isRU)
	if r.Outcome != domain.GovulncheckCompletedWithResults && r.Outcome != domain.GovulncheckCompletedEmpty {
		if isRU {
			return withBuild("Неизвестный исход прогона govulncheck — измерение достижимости отсутствует")
		}
		return withBuild("unrecognized govulncheck outcome — no reachability measurement")
	}
	if r.Outcome == domain.GovulncheckCompletedWithResults {
		if matched != nil {
			return withBuild(callPath(matched))
		}
		res, err := goanalysis.Parse([]byte(e.Content))
		if err != nil {
			if isRU {
				return withBuild("Прогон govulncheck сообщил о находках, но вывод не декодируется — достижимость неизвестна")
			}
			return withBuild("govulncheck reported findings but its output could not be decoded — reachability unknown")
		}
		function, pkg, module := false, false, false
		for _, f := range res.ForVulnerability(c.Vulnerability) {
			for _, frame := range f.Trace {
				switch {
				case frame.Function != "":
					function = true
				case frame.Package != "":
					pkg = true
				case frame.Module != "":
					module = true
				}
			}
		}
		switch {
		case function:
			if isRU {
				return withBuild("Govulncheck сообщил о находке уровня функции; отдельный путь вызова не записан")
			}
			return withBuild("govulncheck reported a function-level finding; no call-path record was attached")
		case pkg:
			if isRU {
				return withBuild("Найдено только пакетное упоминание — не достижимость символов")
			}
			return withBuild("package-level finding only — not symbol reachability")
		case module:
			if isRU {
				return withBuild("Найдено только модульное упоминание — не достижимость символов")
			}
			return withBuild("module-level finding only — not symbol reachability")
		}
	}
	if r.Coverage.Advisory == domain.GovulncheckCoverageCovered && r.Coverage.ScopeComplete {
		if isRU {
			return withBuild("Прогон завершён — находок в измеренной области нет (охват: " + coverage + ")")
		}
		return withBuild("completed — no findings in the measured scope (coverage: " + coverage + ")")
	}
	if isRU {
		return withBuild("Прогон завершён без находок, но охват не подтверждает отсутствие путей (охват: " + coverage + ")")
	}
	return withBuild("completed with no findings; coverage does not establish absence (coverage: " + coverage + ")")
}

func formatEvidenceDetail(e domain.Evidence, c *domain.AnalysisCase, isRU bool) string {
	if e.Kind == domain.EvidenceGovulncheck {
		return formatGovulncheckEvidenceDetail(e, c, isRU)
	}

	if e.Kind == domain.EvidenceModuleGraph {
		if isRU {
			return "Список зависимостей проекта и зафиксированных версий (go list -m)"
		}
		return "Project dependency list and resolved versions (go list -m)"
	}

	if e.Kind == domain.EvidencePackageList {
		if isRU {
			return "Граф пакетов, скомпилированных в приложение (go list -deps)"
		}
		return "Compiled package graph linked into application (go list -deps)"
	}

	if e.Kind == domain.EvidenceAdvisory {
		if isRU {
			return "Уязвимые функции и пакеты из advisory: " + sanitizeTableString(e.Content, 75)
		}
		return "Advisory declared affected symbols/packages: " + sanitizeTableString(e.Content, 75)
	}

	if e.Kind == domain.EvidenceFixDiff {
		firstLine := firstCommitLine(e.Content)
		if isRU {
			return "Коммит исправления: " + sanitizeTableString(firstLine, 80)
		}
		return "Upstream fix commit: " + sanitizeTableString(firstLine, 80)
	}

	if e.Kind == domain.EvidenceRuntime {
		if isRU {
			return "Параметры среды: " + sanitizeTableString(e.Content, 80)
		}
		return "Runtime parameters: " + sanitizeTableString(e.Content, 80)
	}

	if e.Kind == domain.EvidenceConfiguration {
		if isRU {
			return "Конфигурация сети / портов: " + sanitizeTableString(e.Content, 80)
		}
		return "Network / port configuration: " + sanitizeTableString(e.Content, 80)
	}

	if e.Kind == domain.EvidenceSourceSnippet {
		clean := sanitizeTableString(e.Content, 80)
		if isRU {
			return "Фрагмент кода: `" + clean + "`"
		}
		return "Code snippet: `" + clean + "`"
	}

	if e.Content != "" {
		return sanitizeTableString(e.Content, 85)
	}
	if e.Source != "" {
		return sanitizeTableString(e.Source, 85)
	}
	return "-"
}

func firstCommitLine(content string) string {
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Subject: [PATCH]") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Subject: [PATCH]"))
		}
		if strings.HasPrefix(l, "Subject:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Subject:"))
		}
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "From ") && !strings.HasPrefix(l, "Date:") && !strings.HasPrefix(l, "diff ") {
			return l
		}
	}
	return content
}

func sanitizeTableString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.Join(strings.Fields(s), " ")
	if maxLen > 3 && len([]rune(s)) > maxLen {
		runes := []rune(s)
		return string(runes[:maxLen-3]) + "..."
	}
	return s
}

func localizeClaimExplanation(expl string, isRU bool) string {
	if !isRU || expl == "" {
		return expl
	}
	switch expl {
	case "govulncheck produced call path(s) to the affected symbol(s)":
		return "Трасса вызовов govulncheck достигает уязвимых символов библиотеки"
	case "no call path from application to affected symbol(s)":
		return "Пути вызова от приложения к уязвимым символам отсутствуют"
	case "all mandatory exploit conditions are satisfied":
		return "Все обязательные условия эксплуатации выполнены"
	case "condition unresolved":
		return "Условие не определено (недостаточно данных)"
	case "outbound destination endpoints are statically configured or loaded from trusted configuration: remote backends are operator-managed",
		"outbound destination endpoints are statically configured or loaded from trusted configuration (config-origin)":
		return "Адреса исходящих подключений статически заданы в коде или конфигурации: удалённые сервисы доверены"
	case "vulnerability is server-side (requires incoming requests), but product has no inbound server listener for the vulnerable module (outbound clients only)":
		return "Уязвимость на стороне сервера (требует входящих запросов), но в продукте нет слушателей для уязвимого модуля (только клиенты)"
	case "vulnerability is client-side (requires outbound response parsing), but product operates purely as a server (inbound listeners present, no outbound client call sites into vulnerable module)":
		return "Уязвимость на стороне клиента (требует разбора ответов), но продукт работает исключительно как сервер (только слушатели)"
	case "deployment infrastructure declared trusted peer communication (--trusted-peer): network traffic and remote peers/brokers are authenticated and trusted":
		return "Инфраструктура объявлена доверенной: сетевой трафик и узлы кластера аутентифицированы и доверены"
	case "FALSE is decided by trusted cluster infrastructure / perimeter":
		return "Условие нейтрализовано доверенной сетевой инфраструктурой кластера"
	}

	res := expl
	if strings.HasPrefix(res, "govulncheck found no call path to any of ") {
		res = strings.Replace(res, "govulncheck found no call path to any of ", "govulncheck не обнаружил путей вызова к ", 1)
		res = strings.Replace(res, " affected symbol(s)", " уязвимым символам", 1)
	} else if strings.HasPrefix(res, "inbound surface wired behind auth check(s): ") {
		res = "Входящий интерфейс защищён проверкой аутентификации: " + strings.TrimPrefix(res, "inbound surface wired behind auth check(s): ")
	} else if strings.HasPrefix(res, "all call path(s) to affected symbol(s) are dead code under disabled feature gates") {
		res = "Все пути вызова к уязвимым символам находятся в мёртвом коде за отключёнными флагами"
	} else if strings.HasPrefix(res, "all resolved inbound network binds are loopback/cluster-internal; public network exposure falsified: ") {
		res = "Все входящие интерфейсы привязаны к локальным или кластерным адресам: " + strings.TrimPrefix(res, "all resolved inbound network binds are loopback/cluster-internal; public network exposure falsified: ")
	} else if strings.HasPrefix(res, "network exposure resolved: ") {
		res = "Сетевая доступность подтверждена: " + strings.TrimPrefix(res, "network exposure resolved: ")
	} else if strings.Contains(res, "call site(s) receive externally controlled input") {
		if strings.HasPrefix(res, "1 ") {
			res = strings.Replace(res, "1 call site(s) receive externally controlled input", "1 точка вызова принимает входные данные извне", 1)
		} else {
			res = strings.Replace(res, "call site(s) receive externally controlled input", "точек вызова принимают входные данные извне", 1)
		}
	} else if strings.Contains(res, "call site(s) receive non-external input") {
		if strings.HasPrefix(res, "1 ") {
			res = strings.Replace(res, "1 call site(s) receive non-external input", "1 точка вызова получает не-внешние данные", 1)
		} else {
			res = strings.Replace(res, "call site(s) receive non-external input", "точек вызова получают не-внешние данные", 1)
		}
	} else if strings.Contains(res, "never assigned in product code — Go zero value false is not") {
		res = "Параметр никогда не присваивается в коде (значение по умолчанию false)"
	} else if strings.Contains(res, "assigned only safe value(s)") {
		res = "Параметру присваиваются только безопасные значения"
	} else if strings.Contains(res, "set to insecure value") {
		res = "Параметр установлен в небезопасное значение"
	}

	return sanitizeTableString(res, 120)
}
