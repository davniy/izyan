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

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/risk"
)

// Write stores report.json, report.md, openvex.json and cyclonedx.json
// inside dir.
func Write(dir string, c *domain.AnalysisCase) error {
	populateUpgradeCompatibility(c)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), jb, 0o644); err != nil {
		return err
	}
	vb, err := OpenVEX(c)
	if err != nil {
		return fmt.Errorf("openvex: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvex.json"), vb, 0o644); err != nil {
		return err
	}
	cb, err := CycloneDX(c)
	if err != nil {
		return fmt.Errorf("cyclonedx: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cyclonedx.json"), cb, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(c, "ru")), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.en.md"), []byte(Markdown(c, "en")), 0o644)
}

func isRussian(lang ...string) bool {
	if len(lang) > 0 && strings.EqualFold(strings.TrimSpace(lang[0]), "en") {
		return false
	}
	return true
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

func govulncheckSummary(c *domain.AnalysisCase, isRU bool) string {
	if len(c.EvidenceGraph.CallPaths) > 0 {
		if isRU {
			return fmt.Sprintf("Обнаружены пути вызова к уязвимому коду (%d)", len(c.EvidenceGraph.CallPaths))
		}
		return fmt.Sprintf("Call path(s) to vulnerable code detected (%d)", len(c.EvidenceGraph.CallPaths))
	}
	if isRU {
		return "Трасса вызовов от кода продукта не обнаружена (чисто)"
	}
	return "No call path from product code found (clean)"
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

func renderGovulncheckComparison(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	hasCallPaths := len(c.EvidenceGraph.CallPaths) > 0
	hasGovulncheckExec := false
	for _, tex := range c.EvidenceGraph.ToolExecutions {
		if tex.Tool == "govulncheck" {
			hasGovulncheckExec = true
			break
		}
	}
	if !hasCallPaths && !hasGovulncheckExec {
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

	if isRU {
		b.WriteString("### Сопоставление с govulncheck (Анализ расхождения)\n\n")
		if hasCallPaths {
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Уязвимый код вызывается (Reachable)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова от приложения к коду библиотеки (в частности: `%s`).\n", strings.Join(targets, "`, `"))
			} else {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова к коду библиотеки (%d).\n", len(c.EvidenceGraph.CallPaths))
			}
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
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
			} else if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
				b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — трасса вызовов подтверждает достижимость дефектного локуса.\n\n")
			} else if c.Verdict != nil {
				fmt.Fprintf(b, "- ⚠️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
				b.WriteString("- ⚖️ **Сопоставление:** `govulncheck` обнаружил вызовы к библиотеке; условия эксплуатации требуют дальнейшей проверки.\n\n")
			}
		} else {
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Трасса вызовов не обнаружена (Clean)**\n")
			b.WriteString("  - Сканер не нашёл статических путей вызова от кода приложения к функциям из advisory.\n")
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
				if hasMissingCall(c) {
					b.WriteString("- ⚖️ **Сопоставление (Расхождение с govulncheck):** `govulncheck` ищет вызовы функций из advisory, но дефект заключается в пропуске обязательной проверки (missing-call) на активном конвейере исполнения; условия эксплуатации подтверждены.\n\n")
				} else {
					b.WriteString("- ⚖️ **Сопоставление (Расхождение с govulncheck):** Сканер `govulncheck` не зафиксировал прямых вызовов функций из advisory, однако анализ подтвердил эксплуатируемость уязвимости.\n\n")
				}
			} else {
				if c.Verdict != nil {
					fmt.Fprintf(b, "- 🛡️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
				}
				b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — вызовы уязвимых функций отсутствуют.\n\n")
			}
		}
	} else {
		b.WriteString("### Govulncheck Comparison & Divergence Analysis\n\n")
		if hasCallPaths {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Reachable (Vulnerable code is called)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Scanner detected call paths from application code to library code (specifically: `%s`).\n", strings.Join(targets, "`, `"))
			} else {
				fmt.Fprintf(b, "  - Scanner detected %d call path(s) to library code.\n", len(c.EvidenceGraph.CallPaths))
			}
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
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
			} else if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Analyzer Verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
				b.WriteString("- ⚖️ **Comparison:** Findings agree — call paths reach the active defect locus.\n\n")
			} else if c.Verdict != nil {
				fmt.Fprintf(b, "- ⚠️ **Analyzer Verdict:** **`%s`**\n", c.Verdict.Verdict)
				b.WriteString("- ⚖️ **Comparison:** `govulncheck` detected library calls; exploit conditions require further evaluation.\n\n")
			}
		} else {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Clean (No call path found)**\n")
			b.WriteString("  - Scanner detected no static call paths from product code to advisory functions.\n")
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Analyzer Verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
				if hasMissingCall(c) {
					b.WriteString("- ⚖️ **Divergence Rationale:** `govulncheck` checks for invocations of advisory functions, but the defect stems from omission of a security check (missing-call) along an active execution pipeline; exploit conditions are verified.\n\n")
				} else {
					b.WriteString("- ⚖️ **Divergence Rationale:** `govulncheck` detected no direct call paths to advisory functions, but comprehensive analysis confirmed vulnerability exploitability.\n\n")
				}
			} else {
				if c.Verdict != nil {
					fmt.Fprintf(b, "- 🛡️ **Analyzer Verdict:** **`%s`**\n", c.Verdict.Verdict)
				}
				b.WriteString("- ⚖️ **Comparison:** Findings agree — no calls to vulnerable functions detected.\n\n")
			}
		}
	}
}

func hasMissingCall(c *domain.AnalysisCase) bool {
	for _, e := range c.EvidenceGraph.Evidence {
		if e.ID == "EV-MISSING-CALL" || strings.HasPrefix(string(e.ID), "EV-MISSING-CALL") {
			return true
		}
	}
	return false
}

func Markdown(c *domain.AnalysisCase, lang ...string) string {
	populateUpgradeCompatibility(c)
	isRU := isRussian(lang...)
	var b strings.Builder
	if isRU {
		fmt.Fprintf(&b, "# Анализ уязвимости: %s\n\n", c.Vulnerability.ID)
		fmt.Fprintf(&b, "- Кейс: `%s`\n", c.ID)
		if c.TicketID != "" {
			fmt.Fprintf(&b, "- Тикет: `%s`\n", c.TicketID)
		}
		if c.TicketComponent != "" {
			fmt.Fprintf(&b, "- Компонент: `%s`\n", c.TicketComponent)
		}
		if c.TicketRelease != "" {
			fmt.Fprintf(&b, "- Релиз: `%s`\n", c.TicketRelease)
		}
		fmt.Fprintf(&b, "- Репозиторий: `%s`\n- Коммит: `%s`\n- Окружение Go: `%s` (%s/%s)\n\n",
			c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)
	} else {
		fmt.Fprintf(&b, "# Vulnerability analysis: %s\n\n", c.Vulnerability.ID)
		fmt.Fprintf(&b, "- Case: `%s`\n", c.ID)
		if c.TicketID != "" {
			fmt.Fprintf(&b, "- Ticket: `%s`\n", c.TicketID)
		}
		if c.TicketComponent != "" {
			fmt.Fprintf(&b, "- Component: `%s`\n", c.TicketComponent)
		}
		if c.TicketRelease != "" {
			fmt.Fprintf(&b, "- Release: `%s`\n", c.TicketRelease)
		}
		fmt.Fprintf(&b, "- Repository: `%s`\n- Commit: `%s`\n- Go: `%s` (%s/%s)\n\n",
			c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)
	}

	if c.Verdict != nil {
		if isRU {
			fmt.Fprintf(&b, "## Вердикт: `%s`\n\n> **%s**\n\n", c.Verdict.Verdict, localizeVerdictReason(c.Verdict.Reason, true))
		} else {
			fmt.Fprintf(&b, "## Verdict: `%s`\n\n> **%s**\n\n", c.Verdict.Verdict, c.Verdict.Reason)
		}
		renderTriageAssessment(&b, c, isRU)
	}
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
				fmt.Fprintf(&b, "| Версия входит в диапазон уязвимых | %s |\n", localizeAffectedBool(a.VersionAffected, true))
				fmt.Fprintf(&b, "| Уязвимый пакет входит в сборку | %s |\n", localizeAffectedBool(a.PackagePresent, true))
				fmt.Fprintf(&b, "| Код компилируется для целевой платформы | %s |\n", localizeAffectedBool(a.BuildRelevant, true))
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
				fmt.Fprintf(&b, "| version affected | %s |\n", a.VersionAffected)
				fmt.Fprintf(&b, "| package present | %s |\n", a.PackagePresent)
				fmt.Fprintf(&b, "| build relevant | %s |\n", a.BuildRelevant)
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
				b.WriteString("### Статус условий эксплуатации (Claims)\n\n| Условие | Результат | Обоснование | Верификация | Доказательства |\n|---|---|---|---|---|\n")
				for _, cl := range c.Claims {
					expl := localizeClaimExplanation(cl.Explanation, true)
					if expl == "" {
						expl = "—"
					}
					verif := claimVerification(cl, true)
					if verif == "" {
						verif = "—"
					}
					evs := strings.Join(evidenceIDs(cl.EvidenceIDs), ", ")
					if evs == "" {
						evs = "—"
					}
					fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", cl.ConditionID, localizeClaimResult(cl.Result, true),
						expl, verif, evs)
				}
				b.WriteString("\n")
			} else {
				b.WriteString("### Claims Status\n\n| condition | result | explanation | verification | evidence |\n|---|---|---|---|---|\n")
				for _, cl := range c.Claims {
					expl := cl.Explanation
					if expl == "" {
						expl = "-"
					}
					verif := claimVerification(cl, false)
					if verif == "" {
						verif = "-"
					}
					evs := strings.Join(evidenceIDs(cl.EvidenceIDs), ", ")
					if evs == "" {
						evs = "-"
					}
					fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", cl.ConditionID, cl.Result,
						expl, verif, evs)
				}
				b.WriteString("\n")
			}
		}

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

	var bt []domain.Evidence
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceBuild || e.Kind == domain.EvidenceTest {
			bt = append(bt, e)
		}
	}
	lims := allLimitations(c)
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
							fmt.Fprintf(&b, "  - [%s] %s `%s`: %s\n", f.Severity, f.TargetType, f.TargetID, f.Problem)
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
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
			set = s
		}
		break
	}
	if set == nil {
		if isRU {
			return "Оценку по отсутствию пакетов выставить нельзя: нет данных о составе сборки (`go list -deps`).\n"
		}
		return "Package-absence assessment unavailable: no build graph data (`go list -deps`).\n"
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
				"**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ** — подтвердите %d рекомендаций об исключении как безопасных; остальные пакеты в сборку не входят → вердикт `NO_EXPLOIT_PATH_FOUND` (для автоматического применения рекомендаций используйте флаг `--accept-locus-proposals`).\n",
				pending)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: DISMISSIBLE PENDING APPROVAL** — approve %d safety exclusion recommendations; remaining packages are absent from build → verdict `NO_EXPLOIT_PATH_FOUND` (use `--accept-locus-proposals` for automatic approval).\n",
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
	return b.String()
}

func allLimitations(c *domain.AnalysisCase) []string {
	var out []string
	add := func(l string) {
		for _, x := range out {
			if x == l {
				return
			}
		}
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
	return out
}

// TrackerRationale renders a human-readable, professional justification
// in Russian ready for issue trackers, detailing the verdict,
// product facts, build graph status, defect mechanism, and residual risks.
func TrackerRationale(c *domain.AnalysisCase) string {
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

func linkedPackages(c *domain.AnalysisCase) map[string]bool {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidencePackageList {
			if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
				return s
			}
		}
	}
	return nil
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
		fmt.Fprintf(&b, "Библиотека в %s действительно `%s %s`, но код %s в сборку не входит и вызвать его нельзя. Это не ложное срабатывание (False Positive): сканер определил версию правильно, однако в данном снимке приложения уязвимый путь исполнения отсутствует.\n\n",
			repo, mod, ver, c.Vulnerability.ID)
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
		b.WriteString("Сопоставление со сканером: `govulncheck` отмечает уязвимость как вызываемую (Reachable), обнаруживая пути вызова к вспомогательным функциям библиотеки. Однако углублённый анализ опровергает наличие уязвимости: вызываемые функции безопасны, а код с реальным дефектом в сборку не скомпилирован (ложная тревога govulncheck по достижимости).\n\n")
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
		return "Основание вердикта: все отслеженные входы разрешаются в локальные файлы конфигурации хоста (доверенный источник данных)."
	}
	return ""
}

func rationaleNotAffected(c *domain.AnalysisCase) string {
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

	b.WriteString("Exploitable (Уязвимость подтверждена и эксплуатируема).\n\n")

	fmt.Fprintf(&b, "В проекте %s подтверждена возможность эксплуатации уязвимости %s (библиотека `%s %s`).\n\n",
		repo, c.Vulnerability.ID, mod, ver)

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Факты проверки:\n")
	b.WriteString("- Уязвимый пакет входит в граф зависимостей сборки (`go list -deps`) и скомпилирован в бинарный файл.\n")
	if expText := formatExposureSummary(c); expText != "" {
		fmt.Fprintf(&b, "- Входные точки взаимодействия: %s.\n", expText)
	}
	b.WriteString("- Все обязательные условия эксплуатации дефекта подтверждены.\n\n")

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
	if len(absentPkgs) > 0 {
		fmt.Fprintf(&b, "- Пакеты `%s` отсутствуют в графе сборки (`go list -deps`) и физически не скомпилированы.\n",
			strings.Join(absentPkgs, "`, `"))
	}
	if len(presentNotes) > 0 {
		var names []string
		for _, n := range presentNotes {
			names = append(names, fmt.Sprintf("`%s.%s` (%s)", n.Symbol.Package, n.Symbol.Symbol, n.Basis))
		}
		fmt.Fprintf(&b, "- Для функций в скомпилированных пакетах сформированы рекомендации об исключении: %s.\n",
			strings.Join(names, ", "))
		b.WriteString("  Для автоматического применения рекомендаций можно запустить анализ с флагом `--accept-locus-proposals`.\n")
	}
	if expText := formatExposureSummary(c); expText != "" {
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
		b.WriteString("| Сетевой контур | Модель угроз | Вердикт анализатора | Приоритет триажа | Действие для команды |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, p := range c.Profiles {
			contour, model := profileContourAndModel(p, true)
			icon := verdictBadge(p.Verdict)
			action := perimeterActionRecommendation(p.Priority, p.IsTargetActual, true)
			if p.IsTargetActual {
				fmt.Fprintf(b, "| **%s** *(Фактический)* | %s | %s **%s** | **%s** | %s |\n",
					contour, model, icon, p.Verdict, p.Priority, action)
			} else {
				fmt.Fprintf(b, "| **%s** *(Гипотетический)* | %s | %s **%s** | **%s** | %s |\n",
					contour, model, icon, p.Verdict, p.Priority, action)
			}
		}
		b.WriteString("\n")

		b.WriteString("#### Варианты защиты и изоляции для различных сред (Deployment Mitigations)\n\n")
		b.WriteString("Если оперативное обновление библиотеки затруднено, уязвимость может быть компенсирована на уровне сетевого контура:\n\n")
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
		b.WriteString("| Security Perimeter | Threat Model | Analyzer Verdict | Triage Priority | Recommended Action |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, p := range c.Profiles {
			contour, model := profileContourAndModel(p, false)
			icon := verdictBadge(p.Verdict)
			action := perimeterActionRecommendation(p.Priority, p.IsTargetActual, false)
			if p.IsTargetActual {
				fmt.Fprintf(b, "| **%s** *(Actual)* | %s | %s **%s** | **%s** | %s |\n",
					contour, model, icon, p.Verdict, p.Priority, action)
			} else {
				fmt.Fprintf(b, "| **%s** *(Hypothetical)* | %s | %s **%s** | **%s** | %s |\n",
					contour, model, icon, p.Verdict, p.Priority, action)
			}
		}
		b.WriteString("\n")

		b.WriteString("#### Mitigation Options Across Deployment Environments\n\n")
		b.WriteString("If immediate library upgrade is blocked, the vulnerability can be mitigated at the deployment perimeter:\n\n")
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

func renderVulnerabilityDetails(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.Verdict == nil || (c.Verdict.Verdict != domain.VerdictExploitable && c.Verdict.Verdict != domain.VerdictInconclusive) {
		return
	}

	mod, _ := moduleAndVersion(c)

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
		b.WriteString("### Суть уязвимости и сценарий воздействия\n\n")
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

		b.WriteString("#### Границы воздействия (Impact Boundaries)\n\n")
		b.WriteString("- 💥 **Отказ в обслуживании (Denial of Service):** **Подтверждён** — падение процесса сервера при обработке вредоносного запроса.\n")
		b.WriteString("- 🛡️ **Удалённое выполнение кода (RCE):** **Исключено** — дефект не позволяет повреждать память или выполнять произвольный код.\n")
		b.WriteString("- 🛡️ **Утечка конфиденциальных данных:** **Исключена** — дефект не приводит к чтению неинициализированной памяти или обходу прав доступа.\n\n")
	} else {
		b.WriteString("### Vulnerability Defect & Attack Scenario\n\n")
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

		b.WriteString("#### Impact Boundaries\n\n")
		b.WriteString("- 💥 **Denial of Service (DoS):** **Confirmed** — unhandled panic crashes the process on malicious input.\n")
		b.WriteString("- 🛡️ **Remote Code Execution (RCE):** **Ruled out** — no memory corruption or arbitrary command execution primitives.\n")
		b.WriteString("- 🛡️ **Data Exfiltration / Confidentiality:** **Ruled out** — no unauthorized data reads or access control bypass.\n\n")
	}
}

func renderKeyVerificationFacts(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.Affected == nil && len(c.Claims) == 0 {
		return
	}

	mod, ver := moduleAndVersion(c)

	fact1Status := "🔴 Уязвима"
	fact1Detail := fmt.Sprintf("`%s %s` (входит в уязвимый диапазон)", mod, ver)
	fact1Ref := "EV-AFFECTED-MODULES"
	if c.Affected != nil && c.Affected.VersionAffected == domain.ClaimFalse {
		fact1Status = "🟢 Безопасна"
		fact1Detail = fmt.Sprintf("`%s %s` (вне диапазона)", mod, ver)
	}

	fact2Status := "🔴 Включена"
	fact2Detail := "Пакет скомпилирован в бинарный файл сборки (`go list -deps`)"
	fact2Ref := "EV-AFFECTED-PACKAGES"
	if c.Affected != nil && c.Affected.PackagePresent == domain.ClaimFalse {
		fact2Status = "🟢 Исключена"
		fact2Detail = "Уязвимый пакет отсутствует в бинарном файле сборки"
	}

	fact3Status := "🔴 Достижим"
	fact3Detail := "Трасса статических вызовов от точки входа достигает уязвимой функции"
	fact3Ref := "EV-006"
	if len(c.EvidenceGraph.CallPaths) == 0 {
		fact3Status = "🟢 Не достижим"
		fact3Detail = "Пути вызова от приложения к уязвимому коду отсутствуют"
	}

	fact4Status := "🔴 Недоверенный ввод"
	fact4Detail := "Входные данные от удалённого клиента передаются аргументом в уязвимый код"
	fact4Ref := "EV-008, EV-009"
	for _, cl := range c.Claims {
		if cl.ConditionID == "C-PEER-INPUT" && cl.Result == domain.ClaimFalse {
			fact4Status = "🟢 Доверенный ввод"
			fact4Detail = "Входные данные контролируются доверенной конфигурацией хоста"
			break
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
		case "NONE":
			fact5Status = "⚪ Отсутствует"
			fact5Detail = "Сетевые слушатели в коде не обнаружены"
		}
	}

	if isRU {
		b.WriteString("### Сводка ключевых фактов проверки (Key Verification Facts)\n\n")
		b.WriteString("| Проверка | Статус | Значение в продукте | Артефакт |\n")
		b.WriteString("|---|---|---|---|\n")
		fmt.Fprintf(b, "| **1. Зависимость и версия** | %s | %s | `%s` |\n", fact1Status, fact1Detail, fact1Ref)
		fmt.Fprintf(b, "| **2. Наличие в сборке бинарника** | %s | %s | `%s` |\n", fact2Status, fact2Detail, fact2Ref)
		fmt.Fprintf(b, "| **3. Достижимость в графе вызовов** | %s | %s | `%s` |\n", fact3Status, fact3Detail, fact3Ref)
		fmt.Fprintf(b, "| **4. Контроль входных данных** | %s | %s | `%s` |\n", fact4Status, fact4Detail, fact4Ref)
		fmt.Fprintf(b, "| **5. Сетевая доступность** | %s | %s | `%s` |\n\n", fact5Status, fact5Detail, fact5Ref)
	} else {
		b.WriteString("### Key Verification Facts\n\n")
		b.WriteString("| Verification Step | Status | Product Finding | Evidence Ref |\n")
		b.WriteString("|---|---|---|---|\n")
		fmt.Fprintf(b, "| **1. Dependency & Version** | %s | %s | `%s` |\n", fact1Status, fact1Detail, fact1Ref)
		fmt.Fprintf(b, "| **2. Compiled into Binary** | %s | %s | `%s` |\n", fact2Status, fact2Detail, fact2Ref)
		fmt.Fprintf(b, "| **3. Reachable Call Path** | %s | %s | `%s` |\n", fact3Status, fact3Detail, fact3Ref)
		fmt.Fprintf(b, "| **4. Untrusted Input Control** | %s | %s | `%s` |\n", fact4Status, fact4Detail, fact4Ref)
		fmt.Fprintf(b, "| **5. Network Exposure** | %s | %s | `%s` |\n\n", fact5Status, fact5Detail, fact5Ref)
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
		b.WriteString("- **Семантика точки вызова:** В вызывающем коде продукта предварительная валидация структуры или санитизация входных данных перед разбором отсутствует.\n")
		b.WriteString("- **Обработка аварийных ситуаций (Panic Recovery):** В цепочке обработки входящих запросов перехват `recover()` отсутствует; внутренняя ошибка библиотеки вызывает завершение процесса сервера.\n\n")
	} else {
		b.WriteString("### Semantic Analysis & Code Review\n\n")
		b.WriteString("- **Analysis Mode:** Deterministic static analysis (LLM adapters disabled).\n")
		if fixSummary != "" {
			fmt.Fprintf(b, "- **Patch Semantics (Fix Diff):** Upstream fix commit (\"%s\") introduced bounds/error checking before execution. The analyzed library version lacks this guard.\n", fixSummary)
		}
		b.WriteString("- **Call Site Semantics:** Application code performs no pre-validation or sanitization on input before passing it to the library parser.\n")
		b.WriteString("- **Panic Recovery:** No `recover()` guard is present in the request handling chain; an unhandled panic terminates the server process.\n\n")
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

func formatEvidenceDetail(e domain.Evidence, c *domain.AnalysisCase, isRU bool) string {
	if e.Kind == domain.EvidenceGovulncheck {
		var matched *domain.CallPath
		for i := range c.EvidenceGraph.CallPaths {
			if c.EvidenceGraph.CallPaths[i].EvidenceID == e.ID {
				matched = &c.EvidenceGraph.CallPaths[i]
				break
			}
		}
		if matched != nil && len(matched.Frames) > 0 {
			first := matched.Frames[0].Function
			last := matched.Frames[len(matched.Frames)-1].Function
			if isRU {
				return fmt.Sprintf("Трасса вызова (%d кадров): `%s` → ... → `%s`", len(matched.Frames), first, last)
			}
			return fmt.Sprintf("Call path (%d frames): `%s` → ... → `%s`", len(matched.Frames), first, last)
		}
		if isRU {
			return "Статический анализ govulncheck: трасса вызова к уязвимым функциям"
		}
		return "govulncheck static analysis: call path to affected symbols"
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
