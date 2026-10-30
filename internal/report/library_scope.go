package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// This file projects the library-API exploitability scope (Task 1's frozen
// domain contract) onto every human/machine surface of the report. The
// governing rule is asymmetry: a library-basis claim proves that a consumer
// can select the payload and that it reaches the defect locus unchanged. It
// never proves that a deployment exposes that payload to an attacker, that
// an inbound service or handler exists, that the package was linked into a
// product binary, or that public exposure (0.0.0.0) was established.

// libraryAPIControlProven reports whether an admitted TRUE attacker-control
// claim is grounded in the proven public-library-API → sink binding. The
// deployment attacker-control question stays unanswered, which is exactly why
// this is separate from attackerControlProven.
func libraryAPIControlProven(c *domain.AnalysisCase) bool {
	if c == nil {
		return false
	}
	for _, cl := range c.Claims {
		if cl.ConditionID == "C-INPUT" && cl.Result == domain.ClaimTrue &&
			cl.ControlBasis == domain.ControlBasisLibraryPublicAPI {
			return true
		}
	}
	return false
}

// libraryAPIScope reports whether the case carries an *admitted* library-API
// conclusion: a TRUE C-INPUT claim grounded in the public API, or the
// persisted verdict/profile scope. A raw DataFlow.LibraryInput witness is
// deliberately NOT a scope source: witnesses are structural and precede the
// class/CWE/condition admission gates, so rejected witnesses remain in the
// graph. They are rendered as structural evidence only
// (renderLibraryAPIWitness) and must never promote themselves into an active
// scope or control basis — in particular they must not override an external
// origin that won the claim.
func libraryAPIScope(c *domain.AnalysisCase) bool {
	if c == nil {
		return false
	}
	if libraryAPIControlProven(c) {
		return true
	}
	if c.Verdict != nil && c.Verdict.ExploitabilityScope == domain.ScopeLibraryAPI {
		return true
	}
	for _, p := range c.Profiles {
		if p.ExploitabilityScope == domain.ScopeLibraryAPI {
			return true
		}
	}
	return false
}

// libraryInputWitnesses returns the persisted public-API → sink witnesses in
// a deterministic order, dropping exact duplicates of the same binding.
func libraryInputWitnesses(c *domain.AnalysisCase) []domain.LibraryInputWitness {
	if c == nil {
		return nil
	}
	var out []domain.LibraryInputWitness
	seen := make(map[string]bool)
	for _, f := range c.EvidenceGraph.DataFlows {
		w := f.LibraryInput
		if w == nil {
			continue
		}
		key := strings.Join([]string{
			w.API.Package, w.API.Symbol, strconv.Itoa(w.FormalIndex),
			w.Sink.Package, w.Sink.Symbol, strconv.Itoa(w.Arg),
			w.Site.File, strconv.Itoa(w.Site.Line), strconv.Itoa(w.Site.Column),
		}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.API.Package != b.API.Package:
			return a.API.Package < b.API.Package
		case a.API.Symbol != b.API.Symbol:
			return a.API.Symbol < b.API.Symbol
		case a.FormalIndex != b.FormalIndex:
			return a.FormalIndex < b.FormalIndex
		case a.Sink.Package != b.Sink.Package:
			return a.Sink.Package < b.Sink.Package
		case a.Sink.Symbol != b.Sink.Symbol:
			return a.Sink.Symbol < b.Sink.Symbol
		case a.Arg != b.Arg:
			return a.Arg < b.Arg
		case a.Site.File != b.Site.File:
			return a.Site.File < b.Site.File
		case a.Site.Line != b.Site.Line:
			return a.Site.Line < b.Site.Line
		default:
			return a.Site.Column < b.Site.Column
		}
	})
	return out
}

// libraryAPILimitationText is the mandatory limitation attached to every
// library-API-scoped conclusion. The EN form is the frozen domain constant
// verbatim; the RU form is its localized projection.
func libraryAPILimitationText(isRU bool) string {
	if isRU {
		return "Область library-API: полезная нагрузка выбирается потребителем библиотеки; вопрос о том, предоставляет ли нижестоящее приложение эту нагрузку атакующему, находится за пределами анализируемого продукта и не установлен."
	}
	return domain.LibraryAPIScopeLimitation
}

// localizeLimitation maps a limitation recorded in the case to the report
// language. Only the shared library-scope constant has a RU projection;
// every other limitation is emitted verbatim (existing behavior).
func localizeLimitation(l string, isRU bool) string {
	if !isRU {
		return l
	}
	if l == domain.LibraryAPIScopeLimitation {
		return libraryAPILimitationText(true)
	}
	return l
}

// libraryScopeBoundaryText states what the library-API scope covers and what
// it leaves unestablished, without asserting any deployment fact.
func libraryScopeBoundaryText(isRU bool) string {
	if isRU {
		return "полезная нагрузка выбирается потребителем библиотеки через доказанную связку «публичный API → sink»; контроль со стороны атакующего на уровне нижестоящего приложения не установлен"
	}
	return "the payload is selectable by a library consumer through a proven public-API → sink binding; deployment-level attacker control in a consuming application is not established"
}

// libraryScopeStatement is the EN projection carried by VEX/CycloneDX
// documents for a library-API-scoped conclusion. It returns "" when the case
// is not library-scoped.
//
// The scope text is not library-specific: transport-peer is an orthogonal
// scope with its own mandatory boundary, and neither scope exempts a claim
// from the deployment/perimeter rules. Both render through scopeStatement.
func libraryScopeStatement(c *domain.AnalysisCase) string {
	if !libraryAPIScope(c) {
		return ""
	}
	return scopeStatement(domain.ScopeLibraryAPI)
}

func renderExploitabilityScope(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c == nil || c.Verdict == nil || c.Verdict.ExploitabilityScope == "" {
		return
	}
	if c.Verdict.ExploitabilityScope == domain.ScopeLibraryAPI {
		if isRU {
			fmt.Fprintf(b, "> **Область эксплуатации:** `%s` — %s\n\n", c.Verdict.ExploitabilityScope, libraryScopeBoundaryText(true))
		} else {
			fmt.Fprintf(b, "> **Exploitability scope:** `%s` — %s\n\n", c.Verdict.ExploitabilityScope, libraryScopeBoundaryText(false))
		}
		return
	}
	if isRU {
		fmt.Fprintf(b, "> **Область эксплуатации:** `%s`\n\n", c.Verdict.ExploitabilityScope)
	} else {
		fmt.Fprintf(b, "> **Exploitability scope:** `%s`\n\n", c.Verdict.ExploitabilityScope)
	}
}

// claimControlBasis renders a claim's recorded control basis independently
// of claimVerification's falsifier/negative-verification early return: a TRUE
// claim has neither record, and its basis must still be visible.
func claimControlBasis(cl domain.Claim, isRU bool) string {
	if cl.ControlBasis == "" {
		return ""
	}
	if isRU {
		return "Основание контроля: `" + string(cl.ControlBasis) + "`"
	}
	return "control basis: `" + string(cl.ControlBasis) + "`"
}

func symbolRefText(s domain.SymbolRef) string {
	switch {
	case s.Package != "" && s.Symbol != "":
		return "`" + s.Package + "." + s.Symbol + "`"
	case s.Symbol != "":
		return "`" + s.Symbol + "`"
	default:
		return "`" + s.Package + "`"
	}
}

func callSiteText(site domain.CallSite) string {
	if site.File == "" {
		return ""
	}
	if site.Line > 0 {
		return fmt.Sprintf("`%s:%d`", site.File, site.Line)
	}
	return "`" + site.File + "`"
}

func payloadStepText(s domain.LibraryPayloadStep, isRU bool) string {
	kind := string(s.Kind)
	if isRU {
		switch s.Kind {
		case domain.LibraryPayloadIdentity:
			kind = "передача без изменений"
		case domain.LibraryPayloadByteConversion:
			kind = "преобразование с сохранением байтов"
		case domain.LibraryPayloadPreservingCall:
			kind = "вызов с сохранением нагрузки"
		}
	} else {
		switch s.Kind {
		case domain.LibraryPayloadIdentity:
			kind = "identity"
		case domain.LibraryPayloadByteConversion:
			kind = "byte-preserving conversion"
		case domain.LibraryPayloadPreservingCall:
			kind = "payload-preserving call"
		}
	}
	if site := callSiteText(s.Site); site != "" {
		if isRU {
			return kind + " в " + site
		}
		return kind + " at " + site
	}
	return kind
}

// declarationText renders the API declaration suffix of a binding.
func declarationText(w domain.LibraryInputWitness, isRU bool) string {
	decl := callSiteText(w.Declaration)
	if decl == "" {
		return ""
	}
	if isRU {
		return " (объявлен в " + decl + ")"
	}
	return " (declared at " + decl + ")"
}

// formalText renders the public formal slot: index, name and type.
func formalText(w domain.LibraryInputWitness, isRU bool) string {
	var s string
	if isRU {
		s = fmt.Sprintf("формальный параметр №%d", w.FormalIndex)
	} else {
		s = fmt.Sprintf("formal #%d", w.FormalIndex)
	}
	if w.FormalName != "" {
		s += " `" + w.FormalName + "`"
	}
	if w.FormalType != "" {
		s += " (`" + w.FormalType + "`)"
	}
	return s
}

// sinkArgumentText renders the exact sink argument index and call site.
func sinkArgumentText(w domain.LibraryInputWitness, isRU bool) string {
	arg := strconv.Itoa(w.Arg)
	if isRU {
		if site := callSiteText(w.Site); site != "" {
			return "аргумент №" + arg + " в " + site
		}
		return "аргумент №" + arg
	}
	if site := callSiteText(w.Site); site != "" {
		return "argument #" + arg + " at " + site
	}
	return "argument #" + arg
}

// witnessBindingText renders one public-API formal → sink argument binding:
// API symbol and declaration, formal index/name/type, sink symbol and site,
// and the exact sink argument index.
func witnessBindingText(w domain.LibraryInputWitness, isRU bool) string {
	if isRU {
		return symbolRefText(w.API) + declarationText(w, true) + ", " +
			formalText(w, true) + " → " + symbolRefText(w.Sink) + ", " +
			sinkArgumentText(w, true)
	}
	return symbolRefText(w.API) + declarationText(w, false) + " " +
		formalText(w, false) + " → " + symbolRefText(w.Sink) + " " +
		sinkArgumentText(w, false)
}

// renderLibraryAPIWitness writes the witness block: the exact public formal,
// the sink argument, the preserving steps and the evidence references. An
// admitted library-scope case renders it as the proven binding; a raw,
// unadmitted witness is still shown, but under a structural heading that
// explicitly says it grounds neither the verdict nor the input-control claim.
func renderLibraryAPIWitness(b *strings.Builder, c *domain.AnalysisCase, isRU bool) bool {
	ws := libraryInputWitnesses(c)
	if len(ws) == 0 {
		return false
	}
	if libraryAPIScope(c) {
		if isRU {
			b.WriteString("### Привязка публичного API библиотеки к уязвимому вызову\n\n")
			b.WriteString("Полезная нагрузка выбирается потребителем библиотеки и без изменения байтов передаётся в уязвимый вызов:\n\n")
		} else {
			b.WriteString("### Library Public API → Vulnerable Sink Binding\n\n")
			b.WriteString("A library consumer selects the payload, which reaches the vulnerable call without altering its bytes:\n\n")
		}
	} else if isRU {
		b.WriteString("### Структурная привязка входа библиотеки (не является принятым выводом)\n\n")
		b.WriteString("В графе доказательств сохранена структурная связка «публичный формальный параметр библиотеки → аргумент уязвимого вызова», но допуск не преобразовал её в активную область вывода: вердикт и контроль входных данных этой связкой не обоснованы.\n\n")
	} else {
		b.WriteString("### Structural Library Input Witness (not an admitted conclusion)\n\n")
		b.WriteString("The evidence graph retains a structural public-library-formal → vulnerable-sink argument binding, but admission did not convert it into an active exploitability scope: it grounds neither the verdict nor the input-control claim.\n\n")
	}
	for _, w := range ws {
		fmt.Fprintf(b, "- %s\n", witnessBindingText(w, isRU))
		if len(w.Steps) > 0 {
			steps := make([]string, 0, len(w.Steps))
			for _, s := range w.Steps {
				steps = append(steps, payloadStepText(s, isRU))
			}
			if isRU {
				fmt.Fprintf(b, "  - Шаги без изменения нагрузки: %s\n", strings.Join(steps, "; "))
			} else {
				fmt.Fprintf(b, "  - Payload-preserving steps: %s\n", strings.Join(steps, "; "))
			}
		}
		if len(w.EvidenceIDs) > 0 {
			if isRU {
				fmt.Fprintf(b, "  - Доказательства: %s\n", strings.Join(evidenceIDs(w.EvidenceIDs), ", "))
			} else {
				fmt.Fprintf(b, "  - Evidence: %s\n", strings.Join(evidenceIDs(w.EvidenceIDs), ", "))
			}
		}
	}
	b.WriteString("\n")
	return true
}

// renderLibraryConsumerScenario replaces the deployment attack narrative for
// a library-basis claim. It describes only what the evidence proves: a
// consumer chooses the payload and the library forwards it to the sink
// unchanged. It never asserts an inbound handler, service, or deployment
// exposure.
func renderLibraryConsumerScenario(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	ws := libraryInputWitnesses(c)
	var witness domain.LibraryInputWitness
	haveWitness := len(ws) > 0
	if haveWitness {
		witness = ws[0]
	}
	if isRU {
		b.WriteString("#### Сценарий использования библиотеки потребителем\n\n")
		if haveWitness {
			fmt.Fprintf(b, "1. **Вызов публичного API:** потребитель библиотеки вызывает %s%s и передаёт полезную нагрузку в %s.\n",
				symbolRefText(witness.API), declarationText(witness, true), formalText(witness, true))
			fmt.Fprintf(b, "2. **Передача в уязвимый вызов:** значение без изменения байтов достигает %s (%s).\n",
				symbolRefText(witness.Sink), sinkArgumentText(witness, true))
		} else {
			b.WriteString("1. **Вызов публичного API:** потребитель библиотеки выбирает полезную нагрузку через публичный API.\n")
			b.WriteString("2. **Передача в уязвимый вызов:** полезная нагрузка без изменения байтов достигает уязвимого вызова библиотеки.\n")
		}
		b.WriteString("3. **Срабатывание дефекта:** некорректно сформированная полезная нагрузка вызывает неконтролируемую ошибку разбора в библиотеке; последствия для нижестоящего приложения определяются тем, как оно использует библиотеку.\n\n")
		return
	}
	b.WriteString("#### Library Consumer Scenario\n\n")
	if haveWitness {
		fmt.Fprintf(b, "1. **Public API Call:** a library consumer calls %s%s and passes the payload as %s.\n",
			symbolRefText(witness.API), declarationText(witness, false), formalText(witness, false))
		fmt.Fprintf(b, "2. **Forwarding to the Vulnerable Call:** the value reaches %s byte-for-byte (%s).\n",
			symbolRefText(witness.Sink), sinkArgumentText(witness, false))
	} else {
		b.WriteString("1. **Public API Call:** a library consumer selects the payload through the public API.\n")
		b.WriteString("2. **Forwarding to the Vulnerable Call:** the payload reaches the vulnerable library call without alteration.\n")
	}
	b.WriteString("3. **Defect Trigger:** a malformed payload triggers an unhandled parser error in the library; the downstream impact depends on how a consuming application uses it.\n\n")
}

// renderLibraryImpactBoundaries states the impact inside the library API and
// explicitly leaves deployment exposure unestablished. It never attributes
// impact to a server process or an inbound service.
func renderLibraryImpactBoundaries(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	confirmed := c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable
	if isRU {
		if confirmed {
			b.WriteString("- 💥 **Отказ в обслуживании (Denial of Service):** **Подтверждён в области публичного API** — полезная нагрузка, выбранная потребителем библиотеки, вызывает панику разбора; воздействие на нижестоящее приложение зависит от потребителя.\n")
		} else {
			b.WriteString("- 💥 **Отказ в обслуживании (Denial of Service):** **Механизм подтверждён в области публичного API, эксплуатация на уровне приложения не установлена** — полезная нагрузка потребителя библиотеки достигает дефекта разбора; воздействие на нижестоящее приложение зависит от потребителя.\n")
		}
		b.WriteString("- 🧭 **Развёртывание:** публичная доступность, наличие входящего сервиса и контроль входных данных со стороны атакующего в нижестоящем приложении **не установлены** и в область вывода не входят.\n")
		b.WriteString("- 🛡️ **Удалённое выполнение кода (RCE):** **Исключено** — дефект не позволяет повреждать память или выполнять произвольный код.\n")
		b.WriteString("- 🛡️ **Утечка конфиденциальных данных:** **Исключена** — дефект не приводит к чтению неинициализированной памяти или обходу прав доступа.\n\n")
		return
	}
	if confirmed {
		b.WriteString("- 💥 **Denial of Service (DoS):** **Confirmed within the library public API** — a consumer-selected payload triggers the parser panic; the downstream impact depends on the consumer.\n")
	} else {
		b.WriteString("- 💥 **Denial of Service (DoS):** **Mechanism confirmed within the library public API; application-level exploitation not established** — the consumer payload reaches the parsing defect; the downstream impact depends on the consumer.\n")
	}
	b.WriteString("- 🧭 **Deployment:** public exposure, an inbound service and deployment-level attacker control in a consuming application are **not established** and are outside this conclusion.\n")
	b.WriteString("- 🛡️ **Remote Code Execution (RCE):** **Ruled out** — no memory corruption or arbitrary command execution primitives.\n")
	b.WriteString("- 🛡️ **Data Exfiltration / Confidentiality:** **Ruled out** — no unauthorized data reads or access control bypass.\n\n")
}

// joinStatements joins non-empty statement fragments with a single space so
// a projection can add scope/limitation text without leaving doubled or
// leading separators.
func joinStatements(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// affectedActionStatement is the OpenVEX action for an affected finding. It
// uses the existing remediation target when one is published and otherwise
// recommends a compensating control/upgrade, so an affected statement is
// never left without an action.
func affectedActionStatement(c *domain.AnalysisCase) string {
	mod, fixed, ok := FixTarget(c)
	if ok && fixed != "" {
		current := ""
		if c.Affected != nil {
			current = c.Affected.ResolvedVersion
		}
		if current != "" {
			return fmt.Sprintf("upgrade `%s` from `%s` to `%s` or later (`go get %s@%s && go mod tidy`), or apply a compensating control", mod, current, fixed, mod, fixed)
		}
		return fmt.Sprintf("upgrade `%s` to `%s` or later (`go get %s@%s && go mod tidy`), or apply a compensating control", mod, fixed, mod, fixed)
	}
	if mod == "" {
		mod, _ = moduleAndVersion(c)
	}
	if mod != "" {
		return fmt.Sprintf("no fixed version is published for `%s`; apply a compensating control and update the dependency when a fix is available", mod)
	}
	return "apply a compensating control and update the affected dependency when a fix is available"
}
