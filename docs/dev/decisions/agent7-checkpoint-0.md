# Agent-7 (A-series) — Checkpoint 0: STOP proof lane, ADJUST environment before A2

- **Статус:** accepted (Checkpoint 0, PR-0 + PR-1 завершены).
- **Дата:** 2026-10-11.
- **Спека:** [agent-driven-evidence-assessment-design-v2](../specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md) §7, §8, §9.3, §11.
- **План:** [agent-driven-evidence-assessment-plan-v2](../plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md) §A1.5, Checkpoint 0.
- **База и reuse:** [agent7-base-and-reuse.md](agent7-base-and-reuse.md) (REUSE shadow-ветки @ `a65056a`).
- **Артефакты решения:** `eval/agent7/baseline-proof-coverage.json`, `eval/agent7/proof-feasibility.csv`,
  `eval/agent7/proof-feasibility.raw.json`, `eval/agent7/proof-feasibility.md` (§5–§7),
  `eval/agent7/freeze/security-boundary-check.md`.
- **Коммиты:** PR-0 `d24b1cf`/`73e3d51`/`ff0fcb8`, PR-1 `38b9d1d` (ветка `feat/shadow-analyzer-agent`).

## 1. Решения

| # | Решение | Основание |
|---|---|---|
| D1 | **STOP proof lane** — не строить `ARTIFACT_FIXED` / `COMPONENT_ABSENT` / `BUILD_EXCLUDED` checkers, не строить proof engine | `possible_incremental_safe = 0` (план A1.5: stop-condition). Единственный eligible-safe кейс дублирует текущий B0; control-кейс показывает, что «истинный» локальный факт может сосуществовать с unsafe-глобальным выводом |
| D2 | **Research lane не закрывается**, но A2 допускается только после закрытия environment-гейта (§3) | План §9.4/§9.3: если выбранный runtime нельзя безопасно изолировать, A2 останавливается до решения security boundary; спека §8 — capability-граница обязательна |
| D3 | Пороговые значения Checkpoint A/B/C остаются `proposed` + `requires_operator_signoff` (sign-off перед соответствующим прогоном) | Решение оператора 2026-10-10; `run_gate` закрыт |
| D4 | `izyan analyze` и авторитетные verdicts не меняются; A-серия аддитивна | ADR-001/ADR-011, §10.1 спеки |

## 2. Доказательная база

### 2.1 B0 (текущий Izyan) на 30 dev-кейсах — детерминированный baseline

Профиль: `izyan eval vex-bench` (`detOnly`, `confineReads`, `envReplace`, `externalCommitSHA`),
`-j 3 --mem-limit 24GiB`, dataset sha256 `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3`;
три merged-сегмента (`b0-baseline` 19 + `b0-baseline-retry` 8 + `b0-baseline-retry2` 3), `--require-complete` проходит.

| Метрика | Значение |
|---|---:|
| Вердикты | EXPLOITABLE 5 / NO_EXPLOIT_PATH_FOUND 7 / NOT_AFFECTED 4 / INCONCLUSIVE 14 |
| Safe-clear | 10/23 (0.4348) |
| EXPLOITABLE recall | 2/7 (0.2857) |
| Known false-safe | 1 — `kubernetes-kubernetes-e196d24-CVE-2023-44487` → `NOT_AFFECTED` |
| Completion / infra | 30/30, infra-кейсов 0 |

### 2.2 Proof feasibility (независимая классификация, Task B)

| Метрика | Значение |
|---|---:|
| `upper_bound_eligible_safe` | 1/23 (`containers-podman-5ae6347-CVE-2025-47914`, `ARTIFACT_FIXED`) |
| `overlap_with_current_izyan` | 1 (тот же кейс уже `correct_safe` в B0) |
| `possible_incremental_safe` | **0** |
| Классы | 1 `deterministic_no_llm` / 0 `agent_candidate` / 8 `not_machine_checkable` / 15 `inconclusive` |
| Блокеры (23 GT-safe) | 9 `missing_data` / 7 `missing_algorithm` / 7 `none` (+1 `scope` на control) |
| Неизменяемые ограничения | все таргеты — `source_tree`: нет delivered artifact, build attestation, complete binary inventory |

Control-кейс `k8s-44487` отдельно: advisory фиксирует только `golang.org/x/net` (v0.17.0), реальный
уязвимый компонент — `google.golang.org/grpc`; наивный checker на `artifact_fixed=yes` мог бы выдать
unsafe-сертификат, корректный обязан упасть в applicability fail. Это усиливает D1.

### 2.3 Наблюдения о воспроизводимости (входят в environment-гейт)

1. **`--mem-limit` влияет на вердикты.** `cilium-cilium-3977f6a-CVE-2026-33186`:
   `INCONCLUSIVE` (C-LOCUS unresolved) под `-j 2 --mem-limit 8GiB`, `EXPLOITABLE` под `-j 3 --mem-limit 24GiB`
   и в двух одиночных повторах `-j 1 --mem-limit 24GiB`. Memguard (`cmd/izyan/memguard.go`) отменяет
   контекст/деградирует стадии при пересечении бюджета → потолок памяти является result-affecting
   параметром; деградация объявляется оператором (`--degraded`), а не выводится из артефактов.
2. **OSV нестабилен и не канонизирован.** Прогоны падали на `context deadline exceeded` / `503 Service
   Unavailable`; байтовые дайджесты одного и того же адвизори различаются порядком полей
   (`ecosystem_specific.imports`). Для сопоставимых arm'ов нужен frozen advisory-снапшот либо
   канонизация digest'ов.
3. **Устойчивость всего baseline не проверена**: repeat-стабильность доказана на одном кейсе.

## 3. Environment-гейт: что закрыть до A2

Источник: `eval/agent7/freeze/security-boundary-check.md` §6 + §2.3 выше. Каждый пункт — с проверяемым
критерием; статус на момент решения указан явно.

| # | Разрыв | Требуемое изменение | Критерий приёмки |
|---|---|---|---|
| E1 | `Index.Confine` — opt-in и выключен в production (`cmd/izyan/main.go:595`; включает только `cmd/izyan/vexbench.go:276`) | Агентские arm'ы запускаются только с включённым `Confine`; отсутствие confinement — hard error запуска, не warning | Запуск агентского arm'а без confine-профиля падает с явной ошибкой; тест на отказ |
| E2 | Module cache (`GOMODCACHE`) входит в allowed roots (`internal/goanalysis/source.go:229-234`) — читаются чужие проекты | Per-run изолированный cache либо исключение host-cache из roots для агентских arm'ов | Тест: файл вне snapshot и вне разрешённого per-run cache недоступен |
| E3 | `GOPROXY`/`GOSUMDB` egress go-подпроцессов не покрыт `AllowNet` (`service.go:240-249`) | Харденинг env для loader/exec (`GOPROXY=off`, `GONOSUMDB`, `GOFLAGS` фиксированы) + запрет сетевых module-операций в агентском профиле | Тест: subprocess не может инициировать сетевой module fetch (env/флаг зафиксированы в audit) |
| E4 | `run_govulncheck` и `go list -m -json all` выполняются без `AllowExec` (`dependencies.go:253-255`) | Отдельная явная политика для toolchain-команд: либо `AllowExec`-гейт, либо фиксированный allowlist команд в изолированном worker'е | Тест: без разрешения toolchain-команды возвращают `UNSUPPORTED`, не выполняются |
| E5 | Нет per-tool wall-clock timeout (`invoke` на caller-контексте; stdio-entrypoint передаёт `context.Background()`, `cmd/izyan-evidence-tools/main.go:77`) | Явный per-tool timeout с honest `TIMEOUT`-статусом (не «отсутствие вызовов») | Тест: искусственно медленный tool → `TIMEOUT` + limitation, не пустой результат |
| E6 | Shell/process-изоляция контейнера `opencode` не доказана (плана §9.4) | OS/container-level sandbox: запрет исполнения продукта и shell, отсутствие host secrets, read-only mount продукта | Зафиксированный прогон-проверка (как `eval/c1/synthetic.py` live-isolation probe) с negative-assertions |
| E7 | Advisory-входы не воспроизводимы (live OSV) | Frozen advisory snapshot (digest по канонизированным bytes) либо явное разделение «live_observed» в отчётах арм'ов | Дайджест адвизори одинаков между arm'ами при одинаковом входе |
| E8 | Протокол не пинит memory ceiling и не требует repeat-стабильности | В `eval/agent7/freeze/manifest.json`/`protocol.md`: пин непроходящего `--mem-limit`, `--degraded`/`--invalidated` как обязательная декларация, repeat-stability sample (≥3 кейса × 2 повтора) перед scoring arm'ов | Обновлённый manifest/protocol + прогон sample с совпадающими вердиктами |

Внешние (не в этом репозитории): E6 — harness/container; E7 частично — источник advisory.
Пункты E1–E5, E8 реализуемы в репозитории; E6/E7 фиксируются как предусловия запуска A2.

## 4. Что дальше

1. **PR-2 (environment hardening):** E1–E5 (Go, репозиторий) + E8 (пины протокола) с тестами; E6/E7 —
   проверяемые предусловия запуска A2, фиксируются в `security-boundary-check.md` с результатом проверки.
2. **После environment-гейта — A2 PoC** (8–12 dev-кейсов, R0↔B1, без MCP и без машинных доказательств),
   Checkpoint A по заранее зафиксированным (и подписанным) порогам.
3. **Proof lane остаётся остановленным** (D1). Возобновление возможно только при появлении данных/алгоритма,
   снимающего нулевой инкремент (новый A1.5-подобный preflight на новом наборе), а не по архитектурной эстетике.
4. **B39-остаток** (полный прогон `eval/corpus-real.json` и `eval/live-corpus.json` на текущем evaluator)
   остаётся отдельной задачей финальной валидации, не частью A-серии.

## 5. Остаточные риски

1. Repeat-стабильность B0 доказана на одном кейсе; до scoring arm'ов нужен sample (E8).
2. OSV-нестабильность и неканонизированные digest'ы (E7) могут искажать сопоставимость arm'ов.
3. Все 30 dev-кейсов — development/regression; blind holdout (A9) не выбран и не заморожен.
4. Отсутствие delivered artifacts/attestations/inventory у всех таргетов означает, что даже при появлении
   алгоритма любой сертификат останется source-tree-scoped, без release-wide auto-close.
