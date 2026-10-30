# VEX-Bench External Baseline 1 — Current Izyan

Первый независимый прогон текущего детерминированного Izyan на внешнем
наборе VEX-Bench (Go-подмножество). Это **baseline A** из
[agent-first роадмапа](../../roadmaps/agent-first-analysis-roadmap.md) Этап 0:
он фиксирует отправную точку до любых benchmark-specific изменений.

План прогона: [`plans/2026-10-07-vexbench-baseline-plan.md`](../../plans/2026-10-07-vexbench-baseline-plan.md).
Спека: [`specs/shadow-analyzer-agent-spec.md`](../../specs/shadow-analyzer-agent-spec.md) §13–14, §25, §43–45.

## 1. Провенанс (pinned)

| Поле | Значение |
|---|---|
| VEX-Bench pin | `80cddeac3132826bfd47227ad59b2e6618a681bd` |
| `vex_bench.jsonl` SHA256 | `06c58010defd28a3165598072b36fd56e986bc4c39c91f3c0095dc82b2800ddf` |
| Go-subset (30 задач) SHA256 | `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3` |
| Izyan commit | `9c93054eabf33ffb2631c445ea8e42eb06adf942` (ветка `feat/shadow-analyzer-agent`) |
| Izyan binary SHA256 | `3e735de696bec43259308e5376ac453abd2865e3161c463c98818889f93b6088` |
| Analysis Go | `go1.26.1` (`/usr/local/go/bin/go`, sha256 `e22f7267b6aa79b1d460e509eff04806401b84e11c2cd772d967c93fc7bb556f`) |
| govulncheck | `v1.8.0`, DB `https://vuln.go.dev`, DB updated `2026-10-01 20:24:15Z` (**live_observed**, не frozen snapshot) |
| Adapter version | `2` |
| Профиль | `workers=3`, `execution_mode=case_isolated`, `cli_j=1`, `--mem-limit 8GiB`, deadline 7200 s, `GOOS/GOARCH=darwin/arm64`, `CGO_ENABLED=0` |
| Прогон | 2026-10-06T23:55:15Z → 2026-10-07T01:31:09Z (≈1 ч 36 мин), без resume |
| Manifest SHA256 | `f3f3e3e588212416d04296032260bc02f1a6ef325c8290f60cfca5bc1b3f805b` |

30 задач = 28 уникальных снапшотов / 15 репозиториев / 24 CVE. Все снапшоты
скачаны по полному SHA, без `.git`, immutable; 2 пары задач делят снапшоты
(`rancher@4dc4f53`, `rancher@8761419`).

## 2. Safety-aware метрики (основные)

Знаменатели фиксированы pinned-разметкой: 30 / 7 exploitable / 23 не-exploitable.

| Метрика | Значение |
|---|---:|
| **False-Safe count** | **1** |
| False-Safe rate | 1/7 = 14.3 % |
| Safe Clear Rate | 10/23 = 43.5 % |
| EXPLOITABLE recall | 2/7 = 28.6 % |
| INCONCLUSIVE rate | 12/30 = 40.0 % |
| Completion | 28/30 = 93.3 % |
| Status correct | 12/30 |
| Reason correct (status ∧ category) | 7/30 |

Исходы: `correct_safe` 10, `correct_exploitable` 2, `abstain` 12, `wrong` 4,
`failed` 2.

**Safety gate НЕ пройден:** `false_safe = 1`. Baseline сохранён как есть; ни
разметка, ни ожидания, ни first-attempt артефакты не пересчитывались.

### False-safe

`kubernetes-kubernetes-e196d24-CVE-2023-44487` (GT `exploitable`) → `NOT_AFFECTED`
(«resolved version v0.17.0 is outside the affected range»).

Причина: OSV `GHSA-qppj-fm5r-hxr3` для CVE-2023-44487 в Go-экосистеме
перечисляет **только** `golang.org/x/net`; в снапшоте k8s он на `v0.17.0`
(уже исправлен). Реальный уязвимый компонент — `google.golang.org/grpc v1.55.0`
(HTTP/2 Rapid Reset в grpc-go); reference PR `kubernetes#121273` обновляет
именно grpc. Advisory-scope не покрывает реальный уязвимый модуль, поэтому
детерминистический affected-разбор отработал корректно над **неполным**
advisory и выдал безопасный вердикт.

## 3. Compatibility-метрики (отдельно, НЕ safety)

Проекция на 12 официальных категорий; `uncertain → not_exploitable` действует
только здесь. Failed-предсказание учитывается как FAILED (официальная политика),
не как успешный negative.

| Метрика | Значение |
|---|---:|
| Accuracy | 0.667 |
| Binary precision / recall / F1 | 0.40 / 0.286 / 0.333 |
| Justification macro-F1 | 0.226 |
| Failed | 2 |

Per-class F1: `vulnerable` 0.333 (support 7), `code_not_reachable` 0.348 (18),
`code_not_present` 0.222 (3), `requires_configuration` (2).

## 4. Ослабляющие факторы (видны в метриках, не скрыты)

* **2 `failed`** — production panic в `internal/goanalysis/ingressScan`
  (nil `FuncDecl.Body` → SIGSEGV, exit 2) на `istio@8903f65` и `headscale@e172c29`.
  Исправлено отдельным generic-фиксом (`fix(goanalysis): tolerate bodyless
  function declarations in ingress scan`); fix **после** baseline — baseline
  зафиксировал дефект честно, пересчёта не делалось.
* **1 кейс без Go-advisory** (`minikube CVE-2019-5736`): прямой OSV-документ
  вырожденный, alias-fallback тоже не дал usable Go-записи → честный abstain.
* **12 abstain** — основной резерв Safe Clear Rate; часть на exploitable-GT
  (недобор recall). Разбор по причинам — в failure taxonomy.
* Тяжёлые монорепы (kubernetes ×4, cilium ×3, moby ×2) с вендорингом;
  `go list -m all` под vendor падает и штатно заменяется `vendor/modules.txt`.

## 5. Exposure

До baseline уже были просмотрены: 4 smoke-кейса
(`stretchr-testify-285adcc`, `labstack-echo-fdacff0`, `gitleaks-gitleaks-f487f85`,
`caddyserver-caddy-8dc7667`) и один подготовительный kubernetes-кейс. Полностью
«unseen» 30 кейсов не называются. Согласно спеке §49, после первого прогона
набор переходит в статус external regression benchmark.

## 6. Артефакты и где они лежат

Вне репозитория (объём/приватность — по контракту плана §11). Каталог прогона
задаётся переменной `$BASE` (напр. внешний volume); здесь `<OUT>`:

```
<OUT>/                       # = $BASE/runs/external-baseline-1
    run-manifest.json          # frozen config до анализа
    baseline-frozen.json       # freeze boundary + digest
    raw-checksums.json         # digest всех raw/aggregate файлов
    provenance.json            # полный actual provenance (schema_version 1)
    metrics.json               # safety-aware
    compatibility-metrics.json # compatibility (отдельно)
    ledger/<task>.json         # first attempt: state/exit/artifacts
    attempts/<task>/...
    scoring/cases.jsonl        # join prediction × hidden labels
    scoring/disagreements.jsonl/.md
    scoring/review-needed.jsonl
    scoring/failure-taxonomy.jsonl
```

В репозиторий не коммитятся: снапшоты, `.git` датасета, module/build кэши,
raw-артефакты, OSV-дампы, GT/review JSONL, локальные пути.
