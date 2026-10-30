package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// AuditPacket writes one markdown audit packet per signal-cleared case
// into dir: the grounding falsifier, its evidence IDs, any expert input,
// and a reproduction recipe an independent reviewer can follow without
// trusting the analyzer's pipeline (B29, added-value validation spec §3.3).
// genRoot is the corpus .gen directory; corpusPath feeds the re-run
// recipe. Only cases whose govulncheck signal was cleared get a packet —
// those are exactly the claimed added value under review.
func WriteAuditPackets(dir, corpusPath, genRoot string, rep Report, productDirs map[string]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, res := range rep.Results {
		if !signalCleared(res) {
			continue
		}
		name := sanitizeAuditName(res.Case.Label()) + ".md"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(auditPacket(res, corpusPath, genRoot, productDirs)), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// signalCleared mirrors the RecordBaseline predicate: a standalone
// reachable/package-level signal answered by a non-false-safe verdict.
func signalCleared(res Result) bool {
	if res.FalseSafe || res.Err != "" {
		return false
	}
	if res.Baseline != BaselineReachable && res.Baseline != BaselinePackageLevel {
		return false
	}
	return res.Verdict == string(domain.VerdictNotAffected) ||
		res.Verdict == string(domain.VerdictNoExploitPathFound)
}

func auditPacket(res Result, corpusPath, genRoot string, productDirs map[string]string) string {
	c := res.Case
	var b strings.Builder

	fmt.Fprintf(&b, "# Audit packet: %s\n\n", c.Label())
	fmt.Fprintf(&b, "| поле | значение |\n|---|---|\n")
	fmt.Fprintf(&b, "| advisory | `%s` |\n", c.Vuln)
	fmt.Fprintf(&b, "| вердикт | `%s` |\n", res.Verdict)
	fmt.Fprintf(&b, "| govulncheck baseline | `%s` |\n", res.Baseline)
	if res.Falsifier != "" {
		fmt.Fprintf(&b, "| falsifier | `%s` |\n", res.Falsifier)
	}
	if res.GroundBasis != "" {
		fmt.Fprintf(&b, "| ground_basis | `%s` |\n", res.GroundBasis)
	}
	fmt.Fprintf(&b, "| evidence class | `%s` |\n", clearedKind(res.Verdict, res.Falsifier))
	fmt.Fprintf(&b, "| expert input | `%v` |\n\n", res.ExpertAssisted)

	if len(res.EvidenceIDs) > 0 {
		b.WriteString("## Evidence IDs\n\n")
		for _, id := range res.EvidenceIDs {
			fmt.Fprintf(&b, "- `%s`\n", id)
		}
		b.WriteString("\n")
	}

	if len(c.NonLocus) > 0 {
		b.WriteString("## Экспертные решения (non_locus)\n\n")
		for _, d := range c.NonLocus {
			fmt.Fprintf(&b, "- `%s.%s` — %s (authority: %s)\n",
				d.Symbol.Package, d.Symbol.Symbol, d.Basis, d.Authority)
		}
		b.WriteString("\nВердикт зависит от истинности этих решений — они вне машинной проверки.\n\n")
	}
	if len(c.RootCauses) > 0 {
		b.WriteString("## Ручные root causes\n\n")
		for _, rc := range c.RootCauses {
			fmt.Fprintf(&b, "- `%s.%s`\n", rc.Package, rc.Symbol)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Воспроизведение\n\n")
	productDir := productDirs[c.Label()]
	if productDir != "" {
		fmt.Fprintf(&b, "Продукт кейса: `%s`\n\n", productDir)
		fmt.Fprintf(&b, "```bash\ncd %s\ngovulncheck -mode source -json ./...\n```\n\n", productDir)
		b.WriteString("Ожидаемый baseline: `")
		b.WriteString(res.Baseline)
		b.WriteString("` — именно этот сигнал снят вердиктом выше.\n\n")
	}
	fmt.Fprintf(&b, "Повторный прогон анализатора:\n\n```bash\nizyan eval --corpus %s --case %s --case-dir /tmp/va-cases\n```\n\n",
		corpusPath, c.Label())
	b.WriteString("Persisted `case.json` содержит полный audit trail (claims, evidence, tool_executions).\n\n")

	b.WriteString("## Что проверить для этого фальсификатора\n\n")
	for _, step := range verificationRecipe(res.Falsifier) {
		fmt.Fprintf(&b, "- %s\n", step)
	}
	return b.String()
}

// verificationRecipe returns falsifier-specific manual checks — what an
// independent reviewer verifies to confirm the negative claim holds.
func verificationRecipe(falsifier string) []string {
	switch falsifier {
	case domain.FalsifierLocusPackageAbsent, domain.FalsifierPackageAbsent:
		return []string{
			"выполнить `go list -deps -test ./...` в каталоге продукта и убедиться, что пакеты дефектных субъектов отсутствуют в графе сборки",
			"проверить, что множество локусов L в case.json покрывает declared subjects advisory",
		}
	case domain.FalsifierLocusFunctionUnreached:
		return []string{
			"убедиться, что пакеты локуса присутствуют в `go list -deps ./...`, но дефектные функции L не вызываются ни продуктом, ни зависимостями",
			"проверить dynamic markers в case.json: нет reflect/linkname/func-value путей к функциям L",
			"проверить ограничение `internal/`-инкапсуляции, если оно задействовано в обосновании",
		}
	case domain.FalsifierConstantOrGeneratedInput:
		return []string{
			"открыть site-файл(ы) из evidence и убедиться, что payload — компиляторная константа или сгенерированное значение без внешнего ввода",
			"проверить, что нет других сайтов передачи входа в affected sink (provenance coverage в case.json)",
		}
	case domain.FalsifierGovulncheckSilence:
		return []string{
			"повторить `govulncheck -mode source -json ./...` и убедиться в отсутствии finding для advisory",
			"учесть: echo-фальсификатор — снятие воспроизводит контракт govulncheck, а не новое доказательство",
		}
	case domain.FalsifierNoModuleUsage, domain.FalsifierUnreachedExportedSubject:
		return []string{
			"убедиться по call-graph evidence, что declared symbols не вызываются",
			"учесть: echo-фальсификатор — воспроизводит reachability-контракт govulncheck",
		}
	case domain.FalsifierTrustedInfrastructure:
		return []string{
			"проверить `ground_basis`: declared-trust — заявление оператора (не доказательство кода), auto-perimeter — структурные факты манифестов, config-origin — traced inputs в конфигурацию хоста",
			"при auto-perimeter проверить атрибуцию deploy-фактов продукту (owner-совпадение в case.json)",
		}
	case domain.FalsifierConfigGatedOff:
		return []string{
			"найти конфигурационный флаг в evidence и убедиться, что он статически выключен во всех вариантах сборки",
		}
	case domain.FalsifierLoopbackOnly:
		return []string{
			"проверить, что все resolved binds — loopback/unix, и нет неразрешённых inbound-поверхностей",
		}
	case domain.FalsifierSnapshotFactMismatch:
		return []string{
			"сверить snapshot-факт (версия toolchain, платформа) с условием дефекта в advisory",
		}
	default:
		return []string{
			"проверить перечисленные evidence IDs в persisted case.json",
		}
	}
}

func sanitizeAuditName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}
