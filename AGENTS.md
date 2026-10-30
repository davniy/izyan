# Izyan (Vuln Analyzer)

Go vulnerability analyzer. Определяет применимость и эксплуатируемость
уязвимости в конкретном снапшоте продукта, сохраняя неопределённость и
избегая небезопасных отрицательных выводов.

## Главные инварианты

* Отсутствие найденного exploit path не доказывает его отсутствие.
* `FALSE` допустим только при наличии `Falsifier` и успешной negative verification.
* `NO_EXPLOIT_PATH_FOUND` допустим только для VERIFIED falsifier на mandatory-условии.
* `NOT_AFFECTED` определяется только детерминистической affected-цепочкой.
* `UNKNOWN` — валидный терминальный результат; не дожимай claim ради определённого verdict.
* Детерминистические проверки авторитетнее LLM. LLM создаёт только structured proposals.
* `VERIFIED` означает, что конкретный falsifier проверен с учётом dynamic markers и coverage, а не что «проверено всё».
* VERIFIED-FALSE может быть демотирован в `UNKNOWN`; история проверки должна сохраняться в отчёте.

## Репозиторий

* Go-код: `internal/`.
* CLI: `cmd/izyan`.
* Модуль: `github.com/fedorovmv/izyan`.
* Тестовые mini-repo: `testdata/`.
* Канонический backlog: `docs/dev/gap-analysis.md`.
* Бенчмарки и корпуса: автономный `eval/corpus-real.json` (38 кейсов) и live-корпус `eval/live-corpus.json` (`eval/README.md`).
* Приватные локальные пути не коммитить.

## Правила изменения

Каждое функциональное изменение должно обновлять:

* `docs/dev/gap-analysis.md`: закрытое удаляется из §2 в коммите
  закрытия, оставшееся/новое → §2; историю в файле не храним;
* `eval/README.md`, если изменилось наблюдаемое поведение анализатора.

Для оформления коммитов и истории изменений следуй разделу 5 `CONTRIBUTING.md`.

Во время работы допускаются промежуточные локальные коммиты.
Не выполнять `git push` и не переписывать опубликованную историю без явного указания пользователя.

Не создавать временные `.md`, `.out` и другие рабочие артефакты в корне репозитория.

Перед завершением задачи:

```bash
gofmt
go vet ./...
go test ./...
```

Для изменений анализатора корпуса (`eval/corpus-real.json` и `eval/live-corpus.json`) должны проходить с `false-safe=0`.

## Экономия времени тестирования (запрет преждевременного полного эвала)

* На промежуточных шагах (TDD, микро-таски Task 1..N-1, исправление замечаний ревьюера) запускать **ТОЛЬКО** быстрые точечные юнит-тесты (`go test -run <Name> ./...` — секунды).
* Если требуется проверить поведение анализатора на кейсе из корпуса — использовать **строго точечный запуск** через флаг `--case <id>`: `go run ./cmd/izyan eval --corpus eval/corpus-real.json --case <id>`.
* Полный прогон корпусов (`eval/corpus-real.json` и `eval/live-corpus.json`) запускается **СТРОГО ОДИН РАЗ** — на этапе финальной валидации всей ветки/фичи перед сдачей работы.

## Дополнительные правила

Тематические инструкции находятся в `docs/agent-rules/`.
Читай только относящиеся к текущей задаче.

| Область                              | Правила                                          |
| ------------------------------------ | ------------------------------------------------ |
| архитектура и доменная модель        | `architecture.md`                                |
| изменение Go-кода                    | `coding.md`                                      |
| тесты, фикстуры, live corpus         | `testing.md`                                     |
| отрицательные выводы и безопасность  | `security.md`                                    |
| CLI, схемы и внешние интерфейсы      | `api.md`                                         |
| метрики, аудит и отчётность          | `observability.md`                               |
| генеральность: knowledge-base, case-specific хардкод | `generality.md`                    |
| правка `internal/goanalysis/knowledge.json`, `--knowledge` | `knowledge-base.md`                 |
| `internal/goanalysis`                | `provenance-and-bounds.md`, `dynamic-markers.md` |
| `internal/evaluator`, `cmd/izyan` | `evaluators.md`                                  |
| `internal/llm`, `internal/states`, `internal/cveanalysis` | `llm-layer.md`              |
| документация и закрытие backlog      | `docs-sync.md`                                   |

Если задача затрагивает несколько областей, прочитай все соответствующие правила.
Не загружай остальные без необходимости.

## Definitive verdicts (authoritative)

An analysis must earn a definitive verdict, name a specific external fact that
changes the answer, or report that it failed. An unfinished code analysis is not
a legitimate `INCONCLUSIVE`.

- `assessment_outcome` is `DECIDED` (verdict present), `EXTERNAL_DEPENDENCY`
  (`INCONCLUSIVE` + named, evidence-bound dependency) or `FAILED` (no verdict,
  typed `AnalysisGap`s, diagnostic report still written). `FAILED` is not a fifth
  verdict.
- Claims keep `TRUE`/`FALSE`/`UNKNOWN`; a failed measurement leaves its claim
  `UNKNOWN` and never fabricates evidence.
- Tool limits, budgets, timeouts, skipped packages, unresolved root causes,
  incomplete proofs, unverified mandatory `FALSE` and non-closing advisory scopes
  are `FAILED`, never environmental.
- Discovery, CVE attribution and product exploitability are three separate
  propositions. `related` only discovers: it is not an alias, it confers no fact
  inheritance and it never lifts a positive. Attribution requires the record's own
  id/alias or captured publisher/CNA material bound to the implementation and fix.
- Every assessment (including the primary) uses its own exact document bytes and
  its own ranges, subjects, census, conditions, claims, review, severity and
  remediation. Share immutable product measurements, never advisory conclusions.
- Compose only independently earned positives, per profile and build:
  `Positive(C,p) <=> exists R: Attributed(R,C) and IndependentlyExploitable(R,p)`.
  Candidate negatives never close a CVE.
- A CVE-wide negative requires a declared, digest-pinned, finished corpus and the
  verbatim corpus boundary; otherwise `FAILED / UNSUPPORTED_NEGATIVE_SCOPE`.
- `transport-peer` is an orthogonal scope set only from an admitted mandatory
  `TRUE` transport-input claim. Locality does not establish trust.
- Every publication surface renders the one `requested_finding` projection.
