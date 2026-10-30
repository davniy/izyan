# Независимая перепроверка решения по консолидации Shadow/V2

**Назначение:** independent implementer verification решения [`2026-10-20-04-cross-solution-decision.md`](2026-10-20-04-cross-solution-decision.md): load-bearing claims, source inventory, port feasibility и provenance.
**Источник:** delegated `implementer` artifact `agent://ReVerifyArchDecision` (2026-10-20), сохранён дословно; файлы не изменялись, коммитов нет.
**Проверяемое решение:** база = Shadow (`118e10c`); V2 = reference/evaluation lane.
**Вердикт:** `DECISION STANDS`; найденные ошибки носят редакционный/port-scope характер.
**Смежные документы:** [`2026-10-20-03-architecture-decisions.md`](2026-10-20-03-architecture-decisions.md), [`2026-10-20-02-architecture-status.md`](2026-10-20-02-architecture-status.md), [`../plans/2026-10-20-01-remaining-work-roadmap.md`](../plans/2026-10-20-01-remaining-work-roadmap.md).

---

## Методика

Читал сырые JSON/отчёты, grep по source tree, прогнал focused `go test` и offline guard. Файлы не менял, коммитов нет.

## Таблица проверки

| # | Утверждение | Статус | Evidence | Материально? |
|---|---|---|---|---|
| 1 | Census `7/1/10`, 18 rows, без изменений baseline↔fresh | **PROVEN** | Пересчёт `census-artifacts-comparison.json`: 18 rows, baseline=fresh = 7 `NOT_AFFECTED` / 1 `NO_EXPLOIT_PATH_FOUND` / 10 `INCONCLUSIVE`, `changed=[]`, все `status=OK`; все 18 `fresh-artifacts/case-*/report.json` совпадают | yes |
| 2 | Corpus `38/38`, `false-safe=0`, `inconclusive=3` | **PROVEN** (артефакт не привязан к commit) | `corpus-final2.txt:79`: `cases=38 errors=0 expect pass=38 fail=0 claims-fail=0 false-safe=0 inconclusive=3`; имена 38/38 совпадают с `eval/corpus-real.json` | yes |
| 3 | `R6-GUARD PASS`, `deterministic_safe=7/18`, `false_safe=0` | **PROVEN** (воспроизвёл offline) | `python3 eval/decision_ready/regression_guard.py --baseline-manifest .../r6-guard-baseline.json` → `R6-GUARD PASS: baseline — cases=18 deterministic_safe=7/18 false_safe=0`, 0.24 s; guard проверяет 7 `run_dir`-отчётов + 11 summary-строк; `deterministic_safe` считает только `NOT_AFFECTED/COMPLETE` (case-10 не входит) | yes |
| 4 | Case-10: `NO_EXPLOIT_PATH_FOUND`, `declared-symbol-unreached`, `VERIFIED`, `COMPLETE` | **PROVEN** | `fresh-artifacts/case-10/report.json:3720,3723,3725,3735` — ровно эти значения | yes |
| 5 | Case-04: `NOT_AFFECTED/COMPLETE` через `vulnerable_implementation_present=FALSE`, Linux, product scope | **PROVEN** (locus — LLM-inferred, admission-checked) | `art-1103/case-04-final/report.json:869-875` (`FALSE`, `linux/amd64`, `product`), `:917-935` (`vulnerable_implementation_absent/ESTABLISHED`), `:4075-4104` (`NOT_AFFECTED/COMPLETE`, `ASM-TARGET-LINUX-001`) | yes |
| 6 | Case-03 остался `INCONCLUSIVE`, `may_call=127`, `dep_sites=3`, live `MoveNext` | **PROVEN** | `art-1103/case-03-final/report.json:19722-19723`: `INCONCLUSIVE`, `may_call=127 dep_sites=3`, `2 live call site(s) inside the dependency`; advisory = 39 symbols | yes |
| 7a | Cases 07/08 открыты, `may_call=1009`, `dispatch=14` | **PROVEN** | Оба отчёта: `INCONCLUSIVE/INSUFFICIENT_SCOPE`; `may_call=1009` и `dispatch=14` по 5 вхождений; `demo-mq-gateway/providers/ibm` не type-check: `undefined: ibmmq.MQObject` и т.п. | yes |
| 7b | Причина — отсутствие `cmqc.h`/IBM MQ SDK | **CLAIMED** | Строки `cmqc` в отчёте нет; это внешняя inference из cgo-падения `ibmmq.*` | no |
| 7c | «39 limitations» | **UNVERIFIABLE** | В отчёте: 18 limitations в `decision.checks[0]` + 27 `unknowns` + 3/4 `evidence_quality.limitations`; 39 — это число advisory-символов case-03, не limitations | no |
| 8 | V2 corpus `38/38` — CLAIMED; docs противоречат (`inconclusive=2` vs `3`); raw stdout отсутствует | **PROVEN** (как CLAIMED+противоречие) | Файла stdout нет (`grep -rln 'cases=38 errors=0'` — только docs/task-reports); 4 источника: `inconclusive=2` (`2026-10-17...:181-184`, `task-11-report.md:68`, `task-17-report.md:50`, cli-progress), 2: `inconclusive=3` (`architecture-status.md:596`, kernel `progress.md`); `task-11:66` прямо: «observed verbatim» | yes |
| 9 | VEX e2e `9/9`, `false_safe=0` | **PROVEN** | `join-rerun2/metrics.json`: attempts 9/scored 9, `false_safe_count=0`, `completion_rate=1.0`, `exploitable_recall=1.0`; `gt_has_official_outcome=false` | no (research) |
| 10 | Holdout `9/9`, `false_safe=0`, ~73 s vs ~901 s | **PROVEN** | `join2-usebased/metrics.json` 9/9, FS 0; `ABLATION.md:21,34`; реконструкция по mtime: plain медиана 902 s (6 из 9 — ~900 s), usebased 73 s | no (research) |
| 11 | Dev ablation `2/36 false-safe` в обоих arms; citation F1 хуже | **PROVEN** (нюанс метрики) | `rootcause-ablation/dev-comparison.json`: `false_safe=2` оба; `locus_symbol.micro_f1` 0.019 vs 0.006 (хуже); при этом `locus_span.macro_f1` 0.0486→0.0678 (лучше) | yes |
| 12 | Universal verifier: 6/85, FS 0, default-off, 92.9 %, all-NE, 0/39, lower bound 0.393 | **PROVEN** | `task-5-report.md:36-58` (6 dismissals, 0/39 eligible, 0.393), `progress.md:51`, `architecture-status.md:549` (92.9 %); `(85-6)/85=0.929` | yes |
| 13 | Kernel corporate: 0/39 closed, 45 applicable unchanged, FS 0, 3574 discarded | **PROVEN** | `kernel-reachability-filter-plan/progress.md` final gates; `eval/README.md:99-113`: 45/85 applicable, 0/39; 2149+1327+37+34+27 = 3574 | yes |
| 14 | V2 не содержит точных Shadow-контрактов; частичные эквиваленты есть | **PROVEN** | `grep -rin 'vulnerableimplementation\|postreach\|post_reach\|implementationaxis' internal/ cmd/` = 0; `internal/affected/` = resolver/golist/range; `internal/repository/` без `artifact.go`/`assumptions.go`; `internal/domain/` без implementation/target/assumptions; `build_expression` в V2 = 0. Частичные: `presence.go` (symbol_present), `locus.go` (package-absence falsifier), `provenance.go` (argument origin), `releaseevidence.go` (toolchain) | yes |
| 15 | Addendum: V2 repository не только `service.go`; V2 docs не заявляют G1/G2/sidecars; grep = 0 | **PROVEN** | V2 `internal/repository/`: `service.go`, `releaseevidence.go`, `preflight.go`, `contenthash.go`; V2 comparative docs — G1/G2/implementation-axis нет (эти claims в Shadow `architecture-status.md:355,383,463`); grep 0 | no (doc) |
| 16 | Shadow содержит поздние контракты и тесты | **PROVEN** | Есть `internal/affected/implementation.go`, `internal/evaluator/postreach.go`, `internal/domain/{implementation,target,assumptions}.go`, `internal/repository/artifact.go`, `internal/research/{deterministic,decision}.go`; focused tests PASS (ниже) | yes |
| 17 | Port list реален; flag interface mismatch | **PROVEN** + mismatch | Все 11 путей существуют. Mismatch: `evidencetools/verify_code_absence.go:142` вызывает `s.Source.EnumerateImportClosure`, тип/метод есть только в V2 (`goanalysis/toolscope.go:253,336`; V2 864 строки vs Shadow 194), в Shadow `EnumerateImportClosure` = 0; `agenttriage/falsifier.go` использует поля `ImportClosure` | yes (порт-план) |
| 18 | Shadow = worktree, V2 standalone; SHA pre-rewrite; headers stale | **PROVEN** | Shadow `.git`: `gitdir: .../vuln-analyzer/.git/worktrees/vuln-analyzer-shadow`; `git worktree list` → `118e10c [feat/shadow-analyzer-agent]`; V2 HEAD `6bcce89` standalone; headers `4b25b64`/`210de52` — ancestors текущих HEAD; `a65056a` нет в main, есть в V2; `c97fb92` не в `commit-map`; текущий main↔shadow merge-base = `787674f`, divergence `2/148` | no |
| 19 | Ядро вывода: Shadow зрелее как production deterministic analyzer; преимущества V2 — research/triage/eval | **PROVEN** | Синтез: Shadow имеет production identity/G1/G2/sidecars + 7/1/10 census + case-04/10 closures; V2 kernel 0/39, verifier default-off, dev 2/36; research-lane преимущества подтверждены, но не дают production authority | yes |

## Фактические ошибки/противоречия

1. **§3.1 (decision body, lines 95–111) — ложная атрибуция V2 docs.** Утверждение, что V2 `architecture-status.md:524-543` и `:650-661` заявляет implementation axis/G1/G2/sidecars, неверно: 524-543 — таблица root-cause ablation, 650-661 — anti-patterns. Реальные claims — в Shadow `2026-10-20-02-architecture-status.md:355 (G1), 383 (G2), 463 (sidecars)`. Addendum (п.2) это исправил, но тело документа осталось с ложным тезисом → внутреннее противоречие. **Материально для выбора базы: нет; для корректности decision record: да.**
2. **§2, line 76 — «текущий `internal/repository` — только `service.go`».** Неверно: есть также `releaseevidence.go`, `preflight.go`, `contenthash.go`. Addendum (п.1) исправил, тело — нет. **Для выбора базы: нет.**
3. **§1.1, line 42 — «отсутствие `cmqc.h`/SDK».** В отчёте нет ни `cmqc`, ни `.h`; есть `undefined: ibmmq.*` и failed type-check. Название заголовка — inference, не artifact-backed. **Для выбора базы: нет** (кейс всё равно открыт).
4. **§1.2/таблица — «0/45 closures».** Сырые данные: `0/39 groups closed`, `45 applicable tickets unchanged`; сам decision это оговаривает, но shorthand «0/45» в таблице может читаться как доля. **Нет.**
5. **§1.2, line 66 — «Shadow 7/18 — deterministic safe closure».** Guard считает `deterministic_safe` только по `NOT_AFFECTED/COMPLETE`; case-10 (`NO_EXPLOIT_PATH_FOUND`) не входит, т.е. фактических deterministic closures 8/18. **Нет** (семантика, не число census).
6. **Port list (§5A) неполон по зависимости.** `internal/evidencetools/verify_code_absence.go` требует V2 `goanalysis.ImportClosure`/`EnumerateImportClosure` (`toolscope.go`, ~570 строк), которых в Shadow нет; `agenttriage` falsifier также завязан на поля `ImportClosure`. Порт «shell» без этого не соберётся. **Материально для плана порта: да; для выбора базы: нет.**
7. **Addendum п.2 — формулировка «V2 documents этих механизмов не заявляют»** верна для трёх сравнительных docs, но `docs/dev/implementation-status.md:452` упоминает *свои* triage-sidecars (`falsifier-verification.json`, `observation-archive.json`) — это другой контракт. **Нет.**
8. **§4, line 179 — «точный текущий merge-base нельзя назвать».** Верно для Shadow↔V2 (cross-repo, lane `a65056a` отсутствует в main), но main↔Shadow merge-base вычисляется: `787674f`, divergence `2/148`. Старые объекты также доступны через `refs/remotes/origin/master` (`c97fb92` существует). **Нет.**
9. **Контекстный нюанс:** `census-comparison.json` (более ранний артефакт) фиксирует изменение case-05 (`INCONCLUSIVE` → `NOT_AFFECTED`, `safe_baseline=7`, `safe_fresh=8`). Финальный `census-artifacts-comparison.json` стабилен; decision цитирует именно его. **Нет.**
10. **V2 docs противоречат сами себе** по `inconclusive` (2 vs 3) — decision это корректно помечает как CONTRADICTORY; это ошибка V2-документации, не decision. **Нет** (но подтверждает CLAIMED-статус V2 corpus).

## Тесты

| Package | Команда | Результат | Время |
|---|---|---|---|
| Shadow `internal/affected`, `internal/domain` | `go test -count=1 ./internal/affected/ ./internal/domain/` | PASS | 1.188 s / 0.689 s |
| Shadow `internal/repository` | `go test -count=1 ./internal/repository/` | PASS | 7.003 s |
| Shadow `internal/research` (payload/sidecar) | `go test -count=1 -run 'TestSymbolProof\|TestPersistExternalizes\|TestLaneEvidenceView\|TestAffectedResolvePayload' ./internal/research/` | PASS | 5.775 s |
| Shadow G1/G2 | `go test -count=1 -run 'PostReach\|Postreach\|Implementation\|ImplementationAxis' ./internal/evaluator/ ./internal/research/ ./internal/affected/` | PASS | 0.364 / 11.181 / 0.729 s |
| Shadow `internal/evidencetools` | `go test -count=1 ./internal/evidencetools/` | PASS | 8.282 s |
| Shadow sidecar tamper (verbose) | `go test -count=1 -v -run 'TestSymbolProofSidecarTamperFailsClosed\|TestSymbolProofSidecarBindingFailsClosed\|TestPersistExternalizesAuthoritativeSymbolPayload' ./internal/research/` | PASS; subcases `missing_sidecar`, `altered_sidecar`, `undecodable_sidecar_under_a_forged_pin`, `selector`, `envelope_digest`, `envelope_size`, `scope_digest` | 6.86 s wall |
| R6 guard (offline) | `python3 eval/decision_ready/regression_guard.py --baseline-manifest <VA_TMP>/r6-final/r6-guard-baseline.json` | PASS: `cases=18 deterministic_safe=7/18 false_safe=0` | 0.240 s |

**Не запускалось:** `go test ./...`, `go vet ./...`; полный Shadow corpus (сохранённый прогон ~41 мин, 2459 s суммарно); полный census (сохранённый ~77 мин); V2 test suites и V2 corpus/eval reruns; guard C09/replay-output ветки. Причина: сохранённые артефакты дают те же измерения, полный прогон не добавляет доказательств к историческим claim'ам (и не был бы commit-pinned).

## Итог

Все несущие измерения подтверждены; source-асимметрия реальна и не зависит от документации: у Shadow есть production identity/G1/G2/sidecar-контракты и измеренные corporate closures, у V2 — kernel `0/39`, verifier `default-off`, dev `2/36 false-safe`; преимущества V2 лежат в research/triage/eval. Найденные ошибки — ложная атрибуция §3.1, неполный inventory `internal/repository` (обе уже исправлены addendum'ом, но не телом), `cmqc.h`-инференс и недописанная зависимость `ImportClosure` в port-list — не меняют выбор базы. Рекомендация: обновить тело decision record, чтобы оно не противоречило addendum'у, и добавить `goanalysis.ImportClosure`/`toolscope.go` в port scope.

**DECISION STANDS** — база Shadow подтверждена source-контрактами и независимо воспроизведённым census/guard; ошибки носят редакционный/port-scope характер и не опровергают решение.