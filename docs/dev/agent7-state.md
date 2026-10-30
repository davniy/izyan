# A-серия (agent7): состояние, исполнение плана, артефакты

Снимок состояния на 2026-10-13. Документ для последующего анализа и ревью: что заморожено, что сделано по плану,
где лежат артефакты тестов и результатов, что осталось открытым. Приватные абсолютные пути и имена приватных
репозиториев здесь не хранятся — они в приватном компаньоне `agent7-STATE-private-paths.md` (в `<VA_TMP>`);
ниже используются заполнители:

| Заполнитель | Значение |
|---|---|
| `<VA_REPO>` | корень репозитория (`vuln-analyzer-shadow`, ветка `feat/shadow-analyzer-agent`) |
| `<VA_TMP>` | приватный рабочий каталог прогонов (`…/vuln-analyzer/tmp`) |
| `<VA_PRODUCTS>` | каталог приватных продуктовых репозиториев |
| `<VA_VEXBENCH>` | приватный каталог harness и снапшотов VEX-Bench |
| `<VA_WS>` | `<VA_REPO>/.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2` (приватные драйверы и протоколы, gitignored) |

## 1. Заморозка контура (изменения запрещены)

| Что | Пин |
|---|---|
| Промпт исследователя | `eval/agent7/prompts/r0-v1.txt`, sha256 `55b01e9a505bd058cb7be568f08c0e58364b8048e5acea030a14534f7031a0ae` |
| Модель / провайдер | `custom-openai/Qwen/Qwen3.6-35B-A3B`, provider `custom-openai` (корпоративная сеть, хост `<corporate-provider-host>:443`) |
| Harness | `<VA_VEXBENCH>/agent-ctl`, commit `80cddeac3132826bfd47227ad59b2e6618a681bd`; патчи `e6-sandbox`/`task6` sha256 из `eval/agent7/freeze/manifest.json` |
| E6-образ | `vex-bench-go-opencode-e6:latest`, digest `sha256:1d7b3d3982a5a8948ed4f0219b385eaff8e472eb3a0849877b722cd14eafc90b` (linux/arm64, opencode 1.15.5) |
| E6-preflight | 29/29 PASS — `eval/agent7/freeze/e6/security-boundary-check.json` |
| Контракт отчёта | wire-схема `research-report/1` + расширение `slice2-fidelity/2` (`/1` читается legacy-веткой) |
| Вход агента | снапшот продукта, идентификатор CVE, замороженный advisory; allowlist `task_id/cve_id/repo_url/commit_sha`. Исторические решения трекера в контекст агента не передаются |

## 2. Исполнение плана

План: `docs/dev/plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md`. Решения — отдельные ADR в
`docs/dev/decisions/agent7-*.md`.

| Этап | Статус | Доказательство / артефакт |
|---|---|---|
| A0 — base/reuse audit | done | `docs/dev/decisions/agent7-base-and-reuse.md`; протокол `<VA_WS>/report-A0.md`, `evidence-a0.md` |
| A1 — freeze protocol | done | `eval/agent7/freeze/{manifest.json,protocol.md,research-rubric.md,security-boundary-check.md}` |
| A1.5 — proof feasibility (STOP proof) | done | `docs/dev/decisions/agent7-checkpoint-0.md`; `eval/agent7/proof-feasibility.{md,csv,raw.json}` |
| E1–E8 — environment hardening, E6 isolation | done | коммит `cda92c6`; `eval/agent7/freeze/e6/` (probe 29/29) |
| A2 — B1 vs R0 (Checkpoint A) | done, **A3 NO-GO** | `docs/dev/decisions/agent7-a2-checkpoint-a.md`; `eval/agent7/a2/`; коммиты `285e699`, `c114432` |
| E2E slice 1 — `izyan research` | done | коммит `a5ff859`; `docs/dev/decisions/agent7-research-slice-1.md`; `eval/agent7/e2e/*` |
| Slice 2 — достоверность и полезность отчёта | done | коммит `3d28af1` (+ фикс `070f49b`); `docs/dev/decisions/agent7-research-slice-2.md` |
| Slice 3 — корпоративные **отклонённые** findings (18) | done | коммиты `402ff20`, `4d4b100`; `docs/dev/decisions/agent7-corporate-validation.md` |
| Fidelity slice — `slice2-fidelity/2` | done | коммиты `8f1a45b`, `938b635`, `c380292`; `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md`; `eval/README.md §13.7` |
| Корпус **применимых** уязвимостей (31 запущен из 35) | done (прогон) | `<VA_TMP>/exploitable/` — отчёты, метрики, сводка; приватно |
| A3 / R1 / Proof Engine / правка промпта | **не начинались** (вне текущих задач) | — |

## 3. Верификация (чем воспроизводится)

| Проверка | Команда / артефакт | Результат |
|---|---|---|
| Форматирование/статика | `gofmt -l .`, `go vet ./...` | чисто |
| Полный набор тестов | `go test ./...` | зелёный (после `c380292`) |
| Автономный корпус | `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4` | `38/38`, `false-safe=0`, `inconclusive=2` |
| Live-корпус | `VA_PRODUCT_REPO=<r> go run ./cmd/izyan eval --corpus eval/live-corpus.json` | не перезапускался в этой сессии |
| Офлайн-регрессия `/2` (21 кейс, без LLM) | `<VA_WS>/agent7-regress.py --cases all` | `21/21 PASS` (затем 19/19 после финальной правки `c380292`) |
| Воспроизведение по манифесту | `<VA_WS>/agent7-corp-reproduce.py --case <c>` | `3/3 PASS` (`<VA_TMP>/agent7-corp/repro/verification.json`) |
| Приёмка E2E slice 2 | `<VA_WS>/e2e-accept.py` | 16/16 (приватный чекер) |
| Корпус применимых: детерминированная полоса | `<VA_WS>/exploitable-run.py` (31 кейс) | `31/31` OK |
| Корпус применимых: агентский turn | `<VA_WS>/exploitable-run.py --agent` | OK 20, `INVALID_FORMAT` 5, `FAILED` 6 (корпоративная сеть) |

## 4. Артефакты

### 4.1 В репозитории

| Путь | Содержимое |
|---|---|
| `eval/agent7/freeze/` | пин-манифест, протокол, рубрика, security-boundary-check, `e6/` |
| `eval/agent7/prompts/{r0.txt,r0-v1.txt,b1.txt}` | замороженные промпты |
| `eval/agent7/harness/*.patch` | патчи harness (E6-sandbox, single-case, slice2-attempts) |
| `eval/agent7/e2e/{k8s-44487,rancher-47914,trivy-32473}/` | E2E-отчёты + сохранённые `observations.jsonl`, `deterministic-facts.json`, `artifacts/`, `agent/attempt-*/`, `run-manifest.json`. `k8s-44487` перегенерирован в `/2`; `trivy-32473`/`rancher-47914` остались `/1` (их граф зависимостей не разрешается в текущем окружении) |
| `eval/agent7/{a2,advisories,results}/`, `proof-feasibility.*` | артефакты A2 и A1.5 |
| `eval/corpus-real.json`, `eval/live-corpus.json` | корпуса (`eval/README.md` — описание) |
| `eval/README.md §13` | журнал A-серии (13.1–13.8) |
| `docs/dev/decisions/agent7-*.md` | ADR по каждому этапу |
| `docs/dev/gap-analysis.md §2` | открытый бэклог, в т.ч. B41–B45 (оставшиеся препятствия триажа) |

### 4.2 Приватно (вне репозитория)

| Путь | Содержимое |
|---|---|
| `<VA_WS>/` | драйверы и протоколы сессий: `agent7-corp-{prep,run,metrics,compare,freeze,reproduce}.py`, `agent7-regress.py`, `exploitable-{prep,warm,run,rebuild,analyze,summary}.py`, `e2e-accept.py`, `briefs/reports`, `progress.md` |
| `<VA_TMP>/agent7-corp/` | Slice 3: `findings.json`, `selection.json`, `runs/<TICKET>/{det,agent,agent-v2}`, `repro/{manifest.json,human-decisions.json,results-summary.*,verification.json,README.md}`, `snapshots/`, `regress-v2.json` |
| `<VA_TMP>/exploitable/` | корпус применимых: `run-set.json`, `skipped.json`, `advisories/*.json` (замороженные байты OSV), `snapshots/`, `runs/<UNIT>/{det,agent,agent-preflight-failed,rebuilt}/`, `run-results-{det,agent,agent-pass1,rebuilt}.json`, `analysis.json`, `analysis-rebuilt.json`, `cache-warm.json`, `tracker-decisions.json`, `SUMMARY.md` |
| `<VA_TMP>/tracker_exploitable_raw.json`, `tracker_exploitable_tickets.{json,csv}`, `exploitable-inventory.json` | исходная выгрузка трекера и подготовленный inventory |
| `<VA_TMP>/reviewed-map.json`, `make_comparison.py`, `reviewed-eval*.json` | приватная карта «продукт/версия → репозиторий/ref» и прежние сравнения |
| `<VA_PRODUCTS>/<product-repo-*>` | приватные продуктовые репозитории: снапшоты материализуются `git archive` по закреплённым ref (конкретные репозитории и ref — в приватном компаньоне) |
| `<VA_VEXBENCH>/{agent-ctl,repos,agent7-caches,agent7-unseen-repos}` | harness, снапшоты VEX-Bench, кеши |

## 5. Открытые ограничения и риски

1. **Абсолютные локальные пути внутри закоммиченных research-артефактов** (`eval/agent7/e2e/*/report.json|md`,
   `eval/agent7/results/*`) — существовало до этой работы; санитайзинг не делался (артефакты должны оставаться
   байтовым выводом полосы).
2. **`trivy-32473` и `rancher-47914`** остаются `/1`: их модульные графы не разрешаются (`GOPROXY=off` + неполный
   кеш); пересборка требует кеша исходного прогона.
3. **Корпус применимых**: 4 кейса не запущены (у одного продуктового репозитория нет закреплённого ref, указанного
   в inventory). Агентские turn'ы при этом полностью usable: 6 `FAILED` (окно недоступности провайдера DNS,
   `<corporate-provider-host>` не резолвился) — повторённый живой прогон 6/6 OK; 5 `INVALID_FORMAT` — повтор 5/5 OK (один ответ
   восстановлен bounded recovery `BRACE_COMPLETION`, см. приложения к регрессии ниже).
4. **Системные пробелы evidence-контура** (по корпусу применимых; частично закрыты продолжением — см. ниже):
   `run_govulncheck` UNSUPPORTED 31/31 — закрыто: полоса идёт offline против pinned local DB (`-db file://<abs>`),
   регрессия `OK ×31`; `trace_argument`/`find_validations` ERROR «check not performed» — исправлено: declaration
   sites больше не доходят до call-site-only инструментов, регрессия `ERROR 0` (некорректная позиция — честный
   `UNSUPPORTED` с `call-site-only` limitation). Остаётся: в 24 кейсах достижимость пакета не решена, в ~22 из
   них — потому что advisory не называет пути затронутых пакетов.
5. **Требование к окружению**: полоса идёт с `-mod=readonly` (vendor-режим отключён), поэтому кеш модулей снапшота
   должен быть прогрет заранее, иначе `go list -deps` падает и достижимость недоступна целиком; для
   `run_govulncheck` дополнительно нужны подготовленный writable GOVULNDB root и module cache.
6. **Бэклог**: B41–B45 в `docs/dev/gap-analysis.md §2` (ось продукт/тесты, факты уровня пакета, контроллерские
   deployment/config-факты, единица привязки advisory, идентичность попыток на уровне команды; автоматический
   повтор transient preflight закрыт — B45 сужен до остатка).
7. A3, R1, Proof Engine, правка промпта — не начинались и в текущих задачах не требуются.

Продолжение (этап повышения работоспособности Shadow research lane, 2026-10-13): план —
`docs/dev/plans/2026-10-13-01-shadow-usability-plan.md`, базовое решение —
`docs/dev/decisions/agent7-shadow-base-decision.md`, регрессия по сохранённым кейсам и два операторски
разрешённых живых повтора — `docs/dev/reports/2026-10-13-shadow-usability-regression.md`.

## 6. Как продолжить

```bash
# состояние репозитория
git -C <VA_REPO> log --oneline -8            # 8f1a45b → 938b635 → c380292 (fidelity slice)
# проверки
gofmt -l . && go vet ./... && go test ./...
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4     # ожидается 38/38, false-safe=0
# офлайн-регрессия сохранённых кейсов (без LLM)
python3 <VA_WS>/agent7-regress.py --cases all
# корпус применимых: прогрев кеша → детерминированная полоса → (при доступной сети) агентский turn
python3 <VA_WS>/exploitable-warm.py && python3 <VA_WS>/exploitable-run.py --agent
python3 <VA_WS>/exploitable-analyze.py --pass-name agent && python3 <VA_WS>/exploitable-summary.py
```

Отчёты по кейсам — `<VA_TMP>/exploitable/runs/<UNIT>/{det,agent,rebuilt}/report.md` (русский `## Резюме` во главе,
группы условий «Подтверждённые факты / Гипотезы агента / Неизвестные условия»), сводка —
`<VA_TMP>/exploitable/SUMMARY.md`, метрики — `analysis*.json`.
