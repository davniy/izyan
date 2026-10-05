# Валидация дополнительной ценности анализатора (B29): спецификация

Статус: согласованный объём; к реализации.

Определяет, *как измеряется и проверяется* дополнительная ценность
анализатора относительно standalone `govulncheck`. Что считается
ценностью — зафиксировано в
[`incremental-analysis-value-spec.md`](incremental-analysis-value-spec.md)
§3; этот документ не меняет критерии, а делает измерение разложимым,
аудируемым и проверяемым вторым человеком.

## 1. Проблема

`eval/README.md` фиксирует реальные расхождения с govulncheck
(`reachable`/`package-level` сигнал → `NO_EXPLOIT_PATH_FOUND`), но:

- cleared-rate — единое число: не видно, сколько снятий получено
  полностью автоматически, а сколько — ценой экспертного решения
  (`non_locus`, ручные `root_causes`);
- не видно, *каким* доказательством снят сигнал: глубоким
  (локус-недостижимость, константный payload, конфиг-гейтинг) или
  falsifier'ом, по сути переиздающим собственный анализ govulncheck
  под другим вызовом (`govulncheck-silence`, `no-module-usage`);
- ground truth размечен и оценён автором инструмента — замкнутый
  контур: ошибка в понимании кейса повторяется и в expect, и в вердикте;
- гарантия `false-safe=0` читается абсолютно, хотя известные
  непокрытые векторы (B11) делают её условной — скоуп должен быть
  зафиксирован явно;
- независимой проверке мешает отсутствие воспроизводимого рецепта:
  ревьюеру пришлось бы повторять рассуждение анализатора с нуля.

## 2. Что уже есть

- `internal/eval/baseline.go`: standalone govulncheck per-case,
  классификация `reachable`/`package-level`/`module-level`/`silent`/
  `not-in-db`/`error`, записывается в `Result.govulncheck_baseline`.
- `Metrics`: `signal_cleared`, `reachable_cleared`,
  `package_level_cleared`; `false_safe` — стоп-критерий.
- `eval/corpus-real.json`: 38 кейсов, экспертный ввод явно размечен
  (`non_locus` — 2 кейса; `root_causes` — 0; `exploit_model` — 0).
- `.gen/<id>` — материализованные продукты сохраняются между прогонами
  (wipe только по `--clean`) → продукт кейса доступен ревьюеру.
- `izyan eval --case <id>` — точечный повторный прогон.
- `eval/ground-truth.md` — ручная разметка истинности.
- `VerdictResult.ConditionIDs` + `Claim.Falsifier`/`FalsifierBasis` —
  grounding-claim вердикта идентифицируется детерминированно.

## 3. Артефакты

### 3.1. Разложение cleared по уровню экспертизы (D1)

Кейс помечается `expert_assisted`, если определение содержит
`non_locus` или `root_causes` — оба поля являются входом, который не
выводится машиной из advisory (экспертное исключение локуса /
ручная идентификация субъектов).

Метрики:

- `signal_cleared_auto` — cleared без экспертного ввода;
- `signal_cleared_expert` — cleared при наличии `non_locus`/`root_causes`;
- сумма равна `signal_cleared`; разложение видно в markdown-сводке и JSON.

Интерпретация: `signal_cleared_auto` — ценность инструмента в
режиме zero-touch; `signal_cleared_expert` — ценность инструмента
как проверяющего органа для экспертного решения. Смешивать их в одно
число запрещено: сравнение с govulncheck честно только по auto-числу
(govulncheck тоже не получает экспертный ввод).

### 3.2. Разложение cleared по типу доказательства (D2)

`Result` фиксирует grounding falsifier и `ground_basis` вердикта.
Cleared-кейсы раскладываются:

- **deeper** — доказательство вне контракта govulncheck:
  `locus-package-absent`, `locus-function-unreached`,
  `constant-or-generated-input`, `config-feature-disabled`,
  `loopback-only`, `snapshot-fact-*`, `trusted-infrastructure`
  (с `ground_basis` в выдаче — trust-основание видно отдельно);
- **echo** — falsifier, воспроизводящий собственный анализ govulncheck
  (silence под нашим вызовом, отсутствие module usage): ценность
  ниже — это disagreement между запусками, а не новое доказательство;
- **affectedness** — `NOT_AFFECTED` детерминистической цепочкой на
  сигнальном кейсе (редко, но легитимно: baseline-сигнал противоречит
  resolved-графу продукта).

Метрики `cleared_deeper` / `cleared_echo` / `cleared_affectedness`
выводятся рядом со сводкой. Кейсы, снятые одновременно несколькими
фальсификаторами, атрибутируются по grounding-claim вердикта
(`Verdict.ConditionIDs[0]` → claim) — тем же правилом, что решает
`cpFalsifier`.

### 3.3. Audit packet (D3)

Флаг `izyan eval --audit-dir <dir>`: для каждого кейса, у которого
сигнал снят safe-вердиктом, пишется `<dir>/<case-id>.md`:

- id кейса, advisory id, вердикт, baseline;
- grounding falsifier + `ground_basis` + evidence IDs;
- экспертный ввод, если был (`non_locus` decisions с authority);
- воспроизводимый рецепт:
  - путь к продукту (`eval/.gen/<id>` или repo-путь кейса);
  - `cd <dir> && govulncheck -mode source -json ./...` — baseline;
  - что проверить для данного фальсификатора (таблица falsifier→
    проверка: для `locus-*` — `go list -deps ./...` и grep вызовов;
    для `constant-*` — sites-файл аргумента; …);
  - повторный прогон: `izyan eval --corpus <corpus> --case <id>`
    с `--case-dir` для persisted `case.json`.

Пакет пишется только для signal-cleared кейсов (это и есть заявляемая
добавленная ценность — именно её проверяет ревьюер). Остальные кейсы
покрыты сводной таблицей.

### 3.4. Явный скоуп гарантии false-safe=0 (D4)

`eval/README.md` дополняется разделом «Границы гарантии»: список
векторов, при которых анализатор может выдать `NO_EXPLOIT_PATH_FOUND`,
не видя реального пути эксплуатации:

- dispatch через goroutine/channel;
- interface-реализация, существующая только внутри dep-кода;
- plugin-загрузка (`plugin.Open`), `unsafe`, reflect-вызовы вне
  детектируемых маркеров;
- неполнота `AffectedSymbols` в advisory (`KNOWN_ONLY`);
- экспертные решения (`non_locus` basis) — истинность основания
  вне машины.

Это не отменяет стоп-критерий, а делает его скоуп аудируемым:
`false-safe=0` верен *относительно заявленных границ анализа*.

### 3.5. Протокол слепой разметки (D5)

`docs/dev/independent-review-protocol.md`: инструкция второму
аннотатору — взять `.gen/<id>` (или repo кейса) + advisory без
вердиктов анализатора, ответить на вопрос «достижим ли дефектный
локус с attacker-controlled входом в этом продукте», зафиксировать
ответ + затраченное время; сверка с audit packet после разметки.
Метрика: доля согласия с анализатором и стоимость минуты проверки
на кейс (экономика триажа).

## 4. Не входит в срез

- Сама независимая разметка — выполняет человек; мы снижаем её
  стоимость до воспроизводимого пакета.
- Новые adversarial-фикстуры сверх существующих boundary-контролей
  (`testdata/locuslib`); создание отдельного adversarial-корпуса —
  отдельная задача.
- Изменения анализирующего движка (falsifiers, negative verification,
  evaluators) — работаем только на слое eval/отчётности.
- Парные положительные контроли уже покрыты expect-ом `EXPLOITABLE`
  и стоп-критерием false-safe.

## 5. Done-критерии

- `--json` отчёт содержит per-case `expert_assisted`, `falsifier`,
  `ground_basis`; метрики `signal_cleared_auto/expert`,
  `cleared_deeper/echo/affectedness`.
- Markdown-сводка показывает разложение cleared; per-case колонка
  falsifier.
- `--audit-dir` пишет пакет для каждого signal-cleared кейса;
  рецепт воспроизводится вручную по описанию.
- `eval/README.md` — раздел «Границы гарантии»; ссылка на протокол.
- `docs/dev/independent-review-protocol.md` создан.
- Юнит-тесты: классификация deeper/echo/affectedness, expert-флаг,
  рендер сводки; `go vet`/`go test ./...` зелёные.
- B29 обновлён в `gap-analysis.md` (остаток — только живая разметка).

## 6. Точки расширения

- `internal/eval/eval.go`: `Result` (+`ExpertAssisted`, `Falsifier`,
  `GroundBasis`), `Metrics` (+4 счётчика), `Markdown()` (+разложение,
  колонка falsifier).
- `internal/eval/audit.go` (новый): генерация audit packet.
- `cmd/izyan/eval.go`: `caseOutcome` (+falsifier/groundBasis/
  evidenceIDs/productDir из `cs`), `--audit-dir`, передача в Report.
- Grounding claim: `cs.Verdict.ConditionIDs` → claim по ConditionID →
  `Falsifier`/`FalsifierBasis`/`EvidenceIDs`.
