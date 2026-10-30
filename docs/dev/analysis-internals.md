# Analysis internals — механика реализации

Детали реализованного алгоритма по состоянию кода — продолжение
пользовательского [`how-it-works.md`](../../how-it-works.md). Истина — код
(`internal/`); спека [`dev/specs/governing-spec.md`](../specs/governing-spec.md) — цель.

Содержание: govulncheck-компенсации, pattern library, evaluators,
negative verification, review/repair, toolchain, LLM-слой, eval
harness, tool audit, экспорты, известные границы.

## Конвейер состояний — что делает каждая стадия

| Стадия | Источник истины | Выход |
|---|---|---|
| SNAPSHOT_PRODUCT | `go version`, `go.mod` (`GoModDirective`), флаги | `ProductSnapshot` — toolchain, GOOS/GOARCH, `--release-go-version`, `--binary` |
| RESOLVE_VULNERABILITY | OSV API / `--vuln-file` | `Vulnerability` + алиас-дотягивание GO-* документа |
| CHECK_AFFECTED | `go list -m all` + `vendor/modules.txt`, `go list -deps ./...`, `x/mod/semver` | `AffectedResult`: module/version/package/build — каждый факт с evidence; multi-module advisory: `SelectedModules` — все linked-модули, pending-entries (модуль в графе, версия нерезолвабельна) проходят package-пробу и попадают в `PendingModules`, а `VersionAffected`/`ResolvedVersion` атрибутятся только к подтверждённо-linked модулю. `AdvisoryScope` фиксирует requested/resolved identity, coverage и структурную перепись записи (`RecordExtent`/`RecordInventory`; §3b). Если `Scope.AllowsNegativeClosure()==false` (CVE/алиас-запрос, `KNOWN_ONLY`, `GO_PROJECTION`/`UNKNOWN`, отсутствующая или несовпадающая identity, legacy `COMPLETE` без структурной переписи), компонентный отрицательный факт **не завершает** конвейер: в `AffectedResult.Limitations` добавляется scope-limitation, переход идёт в `RESOLVE_ROOT_CAUSE`, а `VerdictEvaluator` не выдаёт `NOT_AFFECTED`/`NEPF` ни на одном отрицательном факте |
| RESOLVE_ROOT_CAUSE | advisory `affected_symbols` → fix-commit diff → LLM-retry | верифицированные sink-символы (каждый проверен `FindSymbol` в dep source). Кандидат, чей пакет отсутствует в допущенном полном `go list -deps` evidence, резолвится как `RootCause.Absent` — отсутствие кода дефекта в сборке это факт, а не провал верификации. Отсутствие допускается только для субъекта, чья идентичность установлена в исходниках выбранной версии (§ Candidate identity before candidate absence): fix-derived кандидат без admitted patch-coordinate binding — `UNMAPPED`, а не `Absent`, а кандидат с таким binding'ом получает только modelling-идентичность: coordinate binding не является absence authority, пока content-derived контракт отозван (§ Candidate identity before candidate absence). Отсутствие решается **до** source lookup: символ, найденный в module cache/vendor, но не входящий в продуктовый closure, всё равно `Absent`, и кандидат цитирует evidence id инвентаря. Символ в присутствующем пакете, который не находится, остаётся `Unverified`. Неразрешённая/неоднозначная корневая причина **не обрывает** кейс: limitation пишется в evidence graph, переход идёт в `EVALUATE_VERDICT` → `INCONCLUSIVE` + отчёты/экспорты; `--strict-llm` → `FAILED` |
| BUILD_EXPLOIT_MODEL | `Classify` → pattern из `exploit.Registry` → LLM → generic fallback | `ExploitModel` — класс + mandatory conditions с `Subjects`/`Params` |
| COLLECT_EVIDENCE | govulncheck + `goanalysis.Index` | `EvidenceGraph`: call paths, data flows, entrypoints, module usages, limitations |
| EVALUATE_CONDITIONS | evaluators chain | `Claim{TRUE/FALSE/UNKNOWN}` per condition |
| GAP_ANALYSIS | hypothesis loop | `Hypothesis` OPEN→CONFIRMED/REJECTED/UNRESOLVED; новые flows → re-evaluate |
| NEGATIVE_CHECK | `goanalysis.Verifier` | FALSE-кандидат → VERIFIED/CONTRADICTED/INSUFFICIENT_SCOPE |
| REVIEW | Structural + LLM reviewer | findings → bounded repair: high-severity claim findings demote to UNKNOWN; explicit `action=promote|demote` condition findings change necessity; action-less condition criticism against a mandatory condition is recorded as pending |
| REPAIR_ANALYSIS | repair по high-severity findings | explicit action меняет необходимость, не факты: `demote` физически переносит mandatory-условие в `SupportingFactors` и снимает `Mandatory`, `promote` возвращает существующее supporting-условие в конъюнкцию только при прохождении applicability-проверки и при отсутствии более раннего demote; claims/NV/evidence не переписываются. Demotion → re-REVIEW; action-less критика остаётся в `ExploitModel.PendingConditionReviews` и блокирует closure (`INCONCLUSIVE`). Claim demotion до UNKNOWN выполняется только по конкретному артефакту: VERIFIED-FALSE демотируется лишь по артефакту, названному в `problem` и записанному как ослабляющий для этого claim'а (dynamic-маркер/site `file.go:line` из nv.Limitations — не из notes, coverage-записей или rationale, traced origin из flows, claim-linked evidence-id), либо при dangling evidence-ссылке — иначе concern записывается advisory |
| EVALUATE_VERDICT | `VerdictEvaluator` | вердикт; `NOT_AFFECTED`/`NEPF` возможны только при `Scope.AllowsNegativeClosure()` (полная запись: §3b); `PendingConditionReviews` держат `INCONCLUSIVE`; при отказе scope вердикт `INCONCLUSIVE` с явной причиной, компонентные факты остаются |
| BUILD_REPORT | — | `report.json`, `report.md` (RU), `report.en.md` (EN), `openvex.json`, `cyclonedx.json`, `tracker_comment.md`. Partial/`KNOWN_ONLY` scope сохраняет requested/resolved identity в `report.json` и таблице применимости, различает компонентный факт и незакрытую CVE-область, а negative VEX-статус (`not_affected`) экспортируется только при закрывающем scope |

## 3a. Два гейта допуска отрицательного доказательства

Отрицательный вывод о сборке (`FALSE`/`NOT_AFFECTED`/`NEPF`) допускается
только при выполнении **двух независимых** условий. Провал любого даёт
`UNKNOWN`, а не `FALSE` с оговоркой.

**Гейт 1 — идентифицированная сборка продукта.** Нужен `ProductTarget`,
для которого `Validate()` успешен, `Scoped()` истинен, и чьи build-факты
совпадают с эффективным контекстом (`domain.EffectiveBuildContext`:
GOOS/GOARCH, tags, CGO, toolchain, vendor/workspace, replace-директивы,
commit). Приоритет источников:

```
artifact-build-info > release-metadata > operator-declared > host-default
```

* `--release` задаёт identity исходников, не target-факты;
  `--deploy-manifests` — perimeter-evidence, не build-provenance.
* `--goos`+`--goarch` вместе → `operator-declared`/`operator`. Только один
  из двух, либо только `--build-tags` → `host-default` **без scope**:
  host-заполненная пара никогда не повышается до операторской.
* Обычный `--binary` использует тот же digest-bound
  `artifact-build-info`: GOOS/GOARCH/`-tags`/`CGO_ENABLED` из встроенных
  `debug.BuildInfo.Settings`, `ArtifactSHA256 == BinarySHA256`, пустой
  `BinaryMember`. Дубли настроек, `GOFLAGS`-перенос тегов, непарсибельный
  `CGO_ENABLED` или невалидная платформа — fail closed (target = nil).
* `host-default` описывает анализатор, поэтому `ValidateNegativeTarget`
  для него всегда отказывает.

**Гейт 2 — завершённое измерение с нужным покрытием.** Измерение должно
быть выполнено и покрывать субъект/scope отрицания: типизированная запись
прогона govulncheck (§4), завершённый и полный package-inventory
(`go list -deps -test -json ./...`, граф без error/dangling/orphan-узлов)
для отсутствия пакета, завершённый, полный и не-opaque source-scan с
entry-символами для недостижимости, `VERIFIED` запись верификатора с тем
же `BuildContext`. Legacy-записи без типизированных метаданных
не допускаются: при загрузке успешные исходы не досочиняются.

**Где гейты применяются.** Producers (`evaluator.admitNegative`,
`affected`/`rootcause`), старт `Verifier.VerifyFalse`, допуск вердикта
(`VerdictEvaluator`, включая persisted `VERIFIED`), scan-prefilter и
экспорты отчёта. Носитель — структурный `ProductTarget` и типизированные
run-записи; строки explanation никогда не парсятся.

**Один эффективный build context.** Целевые факты резолвятся до загрузки
пакетов; affected-resolver, govulncheck, source-index и negative-verifier
используют один snapshot (identity, GOOS/GOARCH, tags, CGO, toolchain,
vendor/workspace). `Index.BindBuild` фиксирует контекст до первого
`packages.Load`; после загрузки несовпадающий bind или мутация публичного
`Build` возвращают `domain.ErrBuildContextMismatch` — уже загруженный
индекс не переименовывается. `CachingRunner`/`CachingTool` принимают один
контекст на сессию.

**Что остаётся независимым (гейт 1 не требуется):** отсутствие модуля в
графе зависимостей, версия вне диапазона, release-toolchain
(`go_version`), ключ репозиторной конфигурации, deployment-policy
(declared trust, auto perimeter, манифесты), явный out-of-range.
Независимость от гейта 1 **не** отменяет scope-гейт §3b: при неполной
записи advisory module/version-негатив остаётся компонентным фактом и не
закрывает finding.

**Scope одного вывода.** Отрицание описывает **только проанализированную
сборку**: платформа/tags/CGO/provenance/target-scope попадают в impact/
action statement VEX и в rationale отчёта. Это не матрица
поддерживаемых вариантов продукта: для product-wide вывода по-прежнему
нужен отдельный admitted supported-targets assumption.

## 3b. Scope записи advisory: `RecordExtent`, `RecordInventory` и закрытие

Гейты §3a допускают отрицание **о сборке**. Независимо от них
отрицательный вывод уровня finding обязан покрыть **область запроса**:
`AdvisoryScope` хранит requested/resolved identity и структурное
свидетельство того, сколько загруженного документа advisory реально
представлено в модели.

### Роли полей

| Поле | Роль | Не является |
|---|---|---|
| `Kind` | что запрошено: `CVE` (CVE-wide) или `ADVISORY_ENTRIES` (точная запись) | доказательством полноты |
| `Coverage` | полнота утверждения запроса (`COMPLETE`/`KNOWN_ONLY`) | структурным свидетельством |
| `RecordExtent` | полнота представления загруженного документа: `FULL_RECORD`/`GO_PROJECTION`/`UNKNOWN` | разрешением на закрытие само по себе |
| `RecordInventory` | census исходного `affected[]`: advisory identity, sha256 документа, entries (исходные ecosystem/module), represented/omitted refs | списком `AffectedModules` (entries сливаются по модулю) |
| `Basis` | человеческое объяснение | исполняемой политикой; гейт его никогда не читает |

### Перепись (census)

`internal/vulnerability` снимает перепись с декодированного документа
**до** фильтрации экосистем и **до** слияния entries по имени модуля.
`AffectedEntryCount` и `Entries` сохраняют исходный порядок и исходные
ecosystem/module каждой entry; `RepresentedRefs`/`OmittedRefs` —
строго возрастающие непересекающиеся списки, покрывающие каждый индекс
ровно один раз. `DocumentDigest` — `sha256:` + 64 lowercase hex по
точным загруженным байтам, поэтому file- и HTTP-intake одинаковых байтов
дают одну identity.

«Представлена» означает фактическое удержание в текущей version-модели,
а не «entry является Go»:

* non-Go entries — omitted;
* named Go entry представлена только если удержаны все её объявления: ≥1
  SEMVER range, нет explicit `versions`, только
  introduced/fixed/last_affected события;
* unnamed Go entry представлена только если её субъекты удержаны как
  явная unresolved (`Unnamed`) запись; отброшенные/слитые дубликаты
  остаются omitted, а удержанная unresolved entry не имеет module
  identity и закрывать не может.

Extent `GO_PROJECTION` — как только хотя бы одна исходная entry omitted;
документ без `affected[]` — `UNKNOWN` без переписи.

### Intake-матрица

| Вход | `Kind` | `Coverage` | `RecordExtent` |
|---|---|---|---|
| точная `GO-`/`GHSA-` запись, census полная и все entries — Go-модули | `ADVISORY_ENTRIES` | `COMPLETE` | `FULL_RECORD` |
| точная запись, есть omitted entries | `ADVISORY_ENTRIES` | `KNOWN_ONLY` | `GO_PROJECTION` |
| CVE-запрос (`CVE-…`) | `CVE` | `KNOWN_ONLY` | по документу (часто `FULL_RECORD`) |
| алиас/иной id, не совпадающий с id записи | `ADVISORY_ENTRIES` | `KNOWN_ONLY` | по документу; closure невозможен (`requested ≠ resolved`) |
| перепись отсутствует/невалидна/не связана с документом | — | `KNOWN_ONLY` | `UNKNOWN` |

CVE-wide запрос не становится закрывающим от того, что документ полностью
представлен: `Kind=CVE` структурно исключает closure. Отдельного
override-флага или producer'а CVE-полноты нет. Явный prior downgrade
(`KNOWN_ONLY`) сохраняется и не повышается обогащением.

### Гейт `AllowsNegativeClosure`

Помимо `RequestedID == ResolvedID`, точного `GO-`/`GHSA-` префикса,
`Kind=ADVISORY_ENTRIES` и `Coverage=COMPLETE`, требуется:

1. `RecordExtent == FULL_RECORD`;
2. `RecordInventory != nil` и `Validate(ResolvedID) == nil`;
3. непустой исходный набор entries;
4. все entries represented (`len(RepresentedRefs) ==
   AffectedEntryCount`), omitted пуст;
5. каждая represented entry — `Ecosystem == "Go"` с непустым `Module`.

`RecordInventory.Validate` проверяет только структурную целостность
(count/order/digest/partition) и привязку к записи. Частичная или пустая
перепись структурно валидна, но не является разрешением: решение
принимает исключительно `AllowsNegativeClosure`. `Basis` не читается.

### Legacy и fail closed

Старые persisted-кейсы декодируются (новые поля optional), но scope без
`RecordExtent`/`RecordInventory` не закрывает запрос, даже если записан
`Coverage=COMPLETE`: legacy coverage — утверждение, не структурное
свидетельство. Missing/malformed/inconsistent extent или inventory дают
`UNKNOWN`; поля не реконструируются из `AffectedModules`, `Basis`,
префиксов id, `AdvisoryRecord.Impls` или research-дайджестов.

### Где применяется

Один и тот же гейт стоит на всех поверхностях закрытия:
`CHECK_AFFECTED` (ранний переход), `VerdictEvaluator` (включая
persisted `VERIFIED`), research (`decision.go`: applicability, proposal,
symbol-authority, config routes; `branch_evaluator.go`;
`flow_adapter.go`), `report.go`, `openvex.go`, `cyclonedx.go`.
Экспорт `not_affected` требует того же допуска; иначе кейс
рендерится как `INCONCLUSIVE`/`under_investigation`/`in_triage`, даже
если загруженный case object содержал stale `NOT_AFFECTED`.

### Смешанная запись (измерено)

`GHSA-qppj-fm5r-hxr3` (CVE-2023-44487): 22 исходные entries — Go 1
(`golang.org/x/net`), Maven 20, SwiftURL 1. Перепись: `GO_PROJECTION`,
22/1/21, digest `sha256:803271be…56e7d2c7`. Резолвер сохраняет
`ModulePresent=TRUE`, `ResolvedVersion=v0.17.0`,
`VersionAffected=FALSE`; `PackagePresent`/`BuildRelevant` остаются
`UNKNOWN`; gRPC-entry не выдумывается, x/net reachability-проба не
форсируется. `CheckAffected` → `RESOLVE_ROOT_CAUSE`; корневая причина не
разрешается; `EVALUATE_VERDICT` → `INCONCLUSIVE`; OpenVEX
`under_investigation`, CycloneDX `in_triage`; `report.md`/`report.json`/
`openvex.json`/`cyclonedx.json` присутствуют.

### Контракт неразрешимого root cause

Неразрешённая или неоднозначная корневая причина — причина, по которой
mandatory-условия не могут быть установлены, а не повод бросить кейс без
вывода. Поэтому `RESOLVE_ROOT_CAUSE` пишет limitation в evidence graph и
уходит в `EVALUATE_VERDICT`: кейс получает записанный `INCONCLUSIVE` и
полный набор отчётов/экспортов. `--strict-llm` сохраняет прежний
fail-fast контракт (`FAILED`).

### Границы

Изменение не доказывает затронутость gRPC и не устраняет все ложные
тревоги Kubernetes/Podman. CVE-wide полнота не выводится из префикса id,
одного модуля/экосистемы, `github_reviewed`, алиасов, feed-обогащения
или отсутствия найденной альтернативы. `related`-записи остаются
внешним сигналом, а не доказательством: поиск связанных записей в этом
изменении не реализован, override-флага нет.

## 4. Роль govulncheck — что он умеет и чего не умеет

### Что делает

`-mode source ./...` строит call graph по коду продукта и находит трейсы
от product entry points до уязвимых символов зависимости. Это единственный
готовый оракул достижимости; его finding-трейсы — authoritative evidence.

### Ограничения (все наблюдались на живых прогонах)

1. **Только своя БД.** Сканирует advisories из vulndb (GO-* записи).
   Нет режима «проверь advisory X» и нет `-mode query` — спросить
   «знаешь ли ты GHSA-…» нельзя. Молчание структурно неотличимо:
   «нет в БД» vs «есть в БД, но пути нет» vs «версия не аффектнута».
2. **Статический call graph.** reflect/plugin/`go:linkname`/func-values
   не моделируются — «нет трейса» ≠ «не достижим».
3. **Символный формат.** Трейс идёт до символов, объявленных в
   advisory (`ecosystem_specific.imports`), которые могут не совпадать
   с теми, что мы вывели из fix-commit'а. Несовпадение множеств =
   ложный «нет пути».
4. **Не знает семантику.** «Достижим» не говорит, под каким входом и
   при какой конфигурации — peer-controlled сетевой ввод, аргумент из
   кода и константа для него одно и то же.
5. **Toolchain.** `-mode source` использует локальный Go; реальный
   toolchain релиза виден только в `-mode binary` (читается из
   встроенного build info). Мы поддерживаем `--binary` и
   `--release-go-version`.

### Как мы компенсируем

**`EvidenceGovulncheck.Govulncheck` — типизированная запись прогона.**
Кейсовый флаг покрытия (`AnalysisCase.GovulncheckCoverage`) удалён:
покрытие теперь факт конкретного запуска, а не свойство кейса. Каждый
вызов сборщика — включая `runner == nil` — оставляет ровно одну запись
`EvidenceGovulncheck` с полями `Outcome`, `Pattern`, `Mode`, `ScanLevel`,
`Error` и `Coverage`:

| `Outcome` | Что означает | Вклад в отрицания |
|---|---|---|
| `completed_with_results` | стрим декодирован, findings есть (exit code 3 — успех) | найденный путь доказывает TRUE; отсутствие пути к субъекту — не «нет пути» |
| `completed_empty` | стрим декодирован, findings нет | молчание — только **кандидат** FALSE, и только при полном покрытии |
| `failed` | процесс/таймаут/отмена/недекодируемый стрим (парсибельный префикс остаётся только в `Content` для аудита) | `UNKNOWN`; silence-derived falsifier не создаётся |
| `not_run` | раннер не сконфигурирован | `UNKNOWN`; то же |

`Coverage` фиксирует три независимых факта: `Advisory` (`covered` —
advisory (ID или алиас) подтверждённо встречается в стриме; `not_in_db` —
успешный прогон его не назвал; `unknown` — прогон не состоялся),
`Subjects` (символы, объявленные в OSV-документе стрима) и
`ScopeComplete` (бинарь либо фактический паттерн `./...`; любой суженный
fallback — частичное покрытие).

Молчание (`govulncheck-silence`) — FALSE-кандидат только когда выполнены
все условия: прогон `completed_empty`, `Advisory == covered`,
`ScopeComplete`, и каждый оцениваемый субъект входит в `Coverage.Subjects`.
Claim цитирует `Evidence.ID` именно этого прогона. Ноль findings при
`not_in_db`, суженном scope, необъявленных субъектах или незавершённом
прогоне отрицанием не является.

**Мэтчинг трейсов.** `reachabilitySubjects` = union(root-cause symbols,
advisory `affected_symbols`); `CallSite` хранит receiver, matching
понимает `Type.Method` ↔ `*T M`. OSVSource при пустых symbols
дотягивает GO-* алиас-документы (у GHSA symbols часто нет).

**Fallback без govulncheck.** Когда govulncheck не смог оценить advisory —
`not_in_db` **или прогон не состоялся** — reachability решается по
module-usage evidence (`libraryUsageVerdict`). Позитивные факты остаются
доказательствами при любом исходе прогона; отрицательные — нет.

| Случай | Завершённый прогон | `failed` / `not_run` / legacy-запись |
|---|---|---|
| все subjects unexported + продукт дёргает API модуля | TRUE — internals исполняются в peer-driven пути библиотеки | TRUE (позитив) |
| exported subject: есть vendor-цепочка `product-API → sink` или прямой вызов | TRUE по `ModuleInternalReach`/`Callee` | TRUE (позитив) |
| exported subjects: проверено — цепочек нет | FALSE-кандидат | **UNKNOWN** — positive-only |
| ноль вызовов в модуль субъектов | FALSE-кандидат (`no-module-usage`) | **UNKNOWN** — positive-only |
| все найденные вызовы мертвы под выключенным флагом | FALSE-кандидат (`config-gated-off`) | **UNKNOWN** — positive-only |
| проверка не выполнялась | UNKNOWN | UNKNOWN |

Positive-only — не осторожность «на всякий случай», а отсутствие
измерения: неудавшийся прогон не наблюдал ни графа вызовов, ни покрытия.
Поэтому `no-module-usage`, `unreached-exported-subject` и
`config-gated-off` из него не производятся никогда.

`ModuleUsage` собирает product call sites в API модуля с точным callee
(`pkg.Recv.Method`). Владелец callee берётся из `packages.Package.Module`
пакета в графе импортов продукта: вложенный модуль, даже если его нет в
affected-entries, не считается частью родителя. Сайт с неизвестным
владельцем или владельцем вне linked-модулей не доказывает использование
модуля и блокирует FALSE-кандидат (вложенный модуль может вызвать
родителя транзитивно).
Только сайты с подтверждённым владельцем становятся входами
`ModuleInternalReach` для этого модуля.
При multi-module advisory usage-сайты атрибутуются по модулю владельца
субъектов (`subjectModuleUsages`, owner = наибольший совпадающий префикс):
вызов API модуля A не является evidence для субъекта модуля B; сайты вне
всех linked-модулей (без атрибуции) не доказывают TRUE, но и блокируют
FALSE-кандидат. VersionFact аналогично ограничен `SelectedModule`:
проверяются и `Subject`, и `Subjects`; условие с субъектом в другом
linked-модуле (pending/confirmed) или без привязки к модулю при
multi-module advisory не наследует чужой version fact. Пакеты stdlib
атрибутуются к `std`/`stdlib`, когда такая запись есть среди linked-модулей.
`ModuleInternalReach` загружает vendored-пакет
`packages.Load` (с типами), строит внутримодульный call graph и BFS'ит
от используемых API до sink — реальные цепочки вроде
`DialTLS → DialConfig → Open → Connection.reader → ReadFrame → parseMethodFrame → readLongstr`
записываются в evidence.

## 5. Pattern library — класс-специфичные exploit models

`BUILD_EXPLOIT_MODEL` больше не сводится к generic-паре `C-REACH`+`C-INPUT`:

1. `Classify` (`internal/exploit/classify.go`) выбирает `Class`:
   CWE-маппинг → keyword-регексы по summary/description → keywords по
   уже собранному fix-diff (без новых tool calls) → `UNKNOWN`. Класс
   и источник классификации фиксируются (`ExploitModel.Class`, для
   keyword/patch-инференса — limitation).
2. `Registry` (`internal/exploit/patterns.go`) держит декларативные
   `Pattern` — набор `ConditionTmpl` (что проверять, не чему равно) +
   `SkipGenericReach/Input`. Шаблоны несут `Params`:
   `input_source=peer|arg|config`, `direction=read`, `sequence=a->b`,
   `bound=…`, `check=symbol_present`.
3. `Instantiate` привязывает шаблоны к subject-пулам по `Bind`-оси:
   `BindSinks` (root-cause sinks), `BindDatums` (чувствительные данные),
   `BindPair` (API-пара round-trip). `ExportedOnly`/`MinSubjects`
   применяются к выбранному пулу; неполный пул → limitation, условие
   остаётся непривязанным — никогда не деградирует в bind на sinks.
   Непокрытые generic-роли домердживаются — `C-REACH`/`C-INPUT` остаются
   fallback'ом всегда.
4. Пулы `Datums`/`Pairs` собираются до instantiate и верифицируются
   `FindSymbol` в dep source:
   - advisory-символы формы `Type.Field` и bare-имена, резолвящиеся в
     struct-типы (`IsStruct`);
   - `SensitiveFields(pkg)` — детерминистичный скан struct-полей dep
     package по credential-именам (password|secret|token|sasl|…);
   - pair-completion по stem-таблице (`String→Parse{T}`, `Marshal→
     Unmarshal{T}`, …) — `URI.String` достраивается `ParseURI`;
   - LLM-предложения (`datum_symbols`/`pair_symbols` в схеме exploit-
     модели) — только символы внутри advisory-модуля, только после
     FindSymbol-верификации.
5. LLM-условия дополняют модель; пустые pattern-параметры (`bound`)
   заполняются из LLM, непустые — не перезаписываются.
6. Условие принимается только при совпадении mechanism/identity:
   `TLSFloorBound` возвращает toolchain-floor лишь тогда, когда advisory
   сам объявляет TLS minimum-version boundary и resolved root cause не
   является SSH-механизмом; `ValidateConditionApplicability` отклоняет
   `PLATFORM`/`RUNTIME` условие с `go_version` для SSH и floor, не
   совпавший с объявленной границей. Поэтому legacy TLS `<1.18` больше
   не создаётся безусловно для `CRYPTO_DOWNGRADE`; настоящие platform
   requirements сохраняются, если граница объявлена advisory.
7. Необходимость предложения решается bucket'ом: `supporting_conditions`
   и явный `mandatory:false` всегда nonblocking; обязательный bucket может
   дополнить конъюнкцию, но не переписать necessity baseline, а совпадение
   id с baseline supporting не промоутится. Ручной `--exploit-model`
   загружается как есть и admission не проходит — он предназначен для
   воспроизведения/override, поэтому reviewer обязан снять нерелевантное
   mandatory-условие явным `demote`.

Собранные классы:

| Класс | Mandatory | Supporting |
|---|---|---|
| peer-driven (`WIRE_PARSER`, `OOB_WRITE`, `INTEGER_OVERFLOW`, `RESOURCE_EXHAUSTION`) | `C-REACH`, `C-PEER-INPUT`, `C-CONSTRAINT` (`input_source=peer`, `bound`) | `C-ENTRY` |
| `INFO_LEAK` | `C-DATA-PRESENT` (`check=symbol_present`), `C-EXPOSED` (`direction=read`) — оба `BindDatums`; generic-условия выключены | `C-USE` |
| `URI_CONFUSION`, `CONFIG_INJECTION` | `C-ROUNDTRIP` (`sequence=`, `BindPair`), `C-INPUT` | — |
| `NIL_DEREF` | `C-REACH`, `C-TRIGGER` | `C-HOT-PATH` |

`UNKNOWN`/непокрытые классы → прежняя generic-модель. `bound` — текстовая
аннотация: семантическое доказательство гарды осознанно отложено.

Params задают и сбор evidence, и evaluation: `check=symbol_present` →
`collectPresence` (`SymbolDecls` через `FindSymbol`, который умеет
резолвить поля структур); `direction=read` → `collectReaders`
(`SymbolRefs` через `SearchSymbol` — `Type.Field` селекторы и
composite-literal ключи матчатся по declaring struct); `sequence=` →
сверка членов пары с module-usage/`ModuleReachable`; `input_source` →
выбор ветки в `ServerTransportInput`.

## 6. Evaluators (condition → claim)

| Evaluator | Обрабатывает | Логика |
|---|---|---|
| `SymbolReachable` | `SYMBOL_REACHABLE` | До трейс-логики — presence split по `go list -deps`: все пакеты субъектов вне графа сборки → FALSE `package-absent`; часть отсутствует → отсутствующие субъекты FALSE-covered, решение по linked-пакетам; список не собран/не декодирован → unknown, не отсутствие. Далее: govulncheck-трейсы → TRUE; `ModuleReachable`-цепочка → TRUE; `completed_empty`+`Advisory=covered`+`ScopeComplete`+все субъекты в `Coverage.Subjects` → FALSE-кандидат `govulncheck-silence`; иначе (not_in_db/суженный scope/failed/not_run/undeclared subjects) → module-usage fallback, positive-only для `failed`/`not_run`/legacy. Каждый FALSE-маршрут проходит `admitNegative` (гейты §3a). Param-ветки: `direction=read` → product-refs из `SymbolRefs` (INFO_LEAK); `sequence=a->b` → все члены пары вызваны (URI_CONFUSION) |
| `ServerTransportInput` | `ATTACKER_CONTROL`, `INPUT_CONSTRAINT` | server-фреймы уязвимого модуля в трейсе + listener-entrypoints → TRUE; client-side: module usage + unexported subjects + peer-input → TRUE (`input_source=peer` в params или remote-input в тексте); `input_source=arg/config` — сразу `ArgumentOrigin` |
| `ArgumentOrigin` | `ATTACKER_CONTROL` | `DataFlows`: external origin → TRUE; допущенный library witness → TRUE с `control_basis=library-public-api` (см. §6a); все non-external → FALSE-кандидат (через `admitNegative`, §3a). Все пакеты subjects вне графа сборки → FALSE `package-absent` (поток в нелинкованный код невозможен) только при допущенном гейтами полном inventory; иначе UNKNOWN |
| `Validation` | `INPUT_CONSTRAINT` | `FindValidations` — guard-выражения до sink |
| `Presence` | `check=symbol_present` | `SymbolDecls`: subject объявлен в dep source → TRUE; проверен и отсутствует → FALSE-кандидат (INFO_LEAK) |
| `Exposure` | `check=exposure` | `Exposures`: факты есть → TRUE (перечисление + scope, caveat'ы в limitations); фактов нет или скан не запускался → UNKNOWN — FALSE не выдаётся никогда: отсутствие listener/dial-сайта в коде не доказывает недостижимость (proxy/ingress вне кода) |
| `ConfigFlag` | `check=config_flag` / `config_key` | code-knob: присваивания `Type.Field` из `ConfigFlags` (literal/const резолв) — insecure → TRUE, все safe → FALSE-кандидат; никогда не присвоен + тип bool + insecure≠zero → FALSE-кандидат по Go zero-value; file-key: `Configuration` items из `FindKey` |
| `VersionFact` | `BUILD_CONDITION`, `CONFIGURATION` | semver-сравнение («prior to X.Y.Z», «нет в vulnerable versions») по `AffectedResult` |

**Configuration checks** (`C-TLS-VERIFY` supporting в peer-driven
паттерне — `crypto/tls Config.InsecureSkipVerify`, insecure=true; LLM
может предлагать свои knob'ы через params — верифицируются `FindSymbol`):

- `FieldAssignments` собирает composite-literal ключи и `x.Field = v`
  присваивания; значение резолвится через `types.Info` (literal/const).
- `SymbolFieldType` даёт kind поля → zero-value семантика Go
  детерминистична: bool-knob без присваиваний = false.
- `exposure.FindKey` — поиск произвольного ключа в конфигах репо
  (та же walk+sanitize, что ScanRepo, без addr-фильтра).
- Живой результат: продукт-референс ставит `InsecureSkipVerify=true`
  в `pkg/tls/type.go` → `C-TLS-VERIFY` TRUE — факт «peer on the wire»
  для всех peer-driven кейсов подтверждён конфигурацией.

**Exposure facts** (`C-EXPOSURE`, supporting в peer-driven и NIL_DEREF
паттернах — не гейтит вердикт, но получает claim и попадает в отчёт):

- `ListenSites` — inbound surface: `net.Listen*`, `http.Server{Addr}`,
  `grpc.NewServer`/`Serve`. Аргумент адреса резолвится через literal/
  const/var/field/`os.Getenv`; server-shape вызовы (`srv.Serve(lis)`)
  трассируют receiver до определяющего вызова в той же функции.
- `DialSites` — outbound в уязвимый модуль (`amqp.Dial`, `grpc.Dial`…,
  имя по `dialNameRe`, пакет по префиксу advisory-модуля).
- `ExposureFact{Address, AddressSource, Scope}`: source = `literal`/
  `const`/`var:`/`field:`/`env:`/`config:`; scope = `static`/`configured`/
  `unknown` (`OutboundScope`: var/field/env/config → configured).
- `env:`-адреса дозрезолвляются через `exposure.ScanRepo` — walk
  yaml/env/toml/json конфигов репозитория по `(listen|bind|addr|host|
  port|dsn|url|endpoint)`-ключам.
- `_test.go`-файлы исключаются — тестовый код не deployed surface.
- Claim несёт caveat «endpoint операторски конфигурируем» — доверие
  настроенному сервису остаётся deployment-решением, факт лишь показывает
  где поверхность.

TRUE-claim обязан нести evidence ID — структурный ревьюер иначе
демотирует (provenance-инвариант).

## 6a. Library public-API scope (`library-api`)

**Гейт формы продукта.** `CollectEvidence.collectProductShape` вызывает
`Index.BuildProductShape` до source-анализа и сохраняет `product.shape`:
корневой модуль + workspace-модули (владение), census пакетов (включая
failed/skipped кандидаты и build-excluded файлы),
`ClauseComplete`/`Importable`, fingerprint и evidence ID. Библиотека — это
`Kind=LIBRARY && CensusComplete` при ≥1 импортируемом публичном пакете и
отсутствии принадлежащего продукту `package main`; вложенный чужой модуль
исключается по `OwnedModules`, а не по имени каталога. Бинарный режим,
неполный census и неизвестное владение → `UNKNOWN` (не библиотека).
`ShippingScope.Complete` не требуется: у библиотеки по построению нет
main-корней.

**Терминал трассировки.** В `traceParam` до кэша, рекурсии, depth-лимита и
перебора вызывающих стоит проверка `publicLibraryFormalLocked`: публичный
формальный параметр библиотеки останавливает трассу с `OriginUnknown`
(«consumer-selectable payload; deployment origin unknown»). Поэтому ноль
вызывающих, только тестовые вызывающие и константные вызывающие в том же
репозитории границу не закрывают — они ничего не говорят о другом
потребителе того же артефакта.

**Свидетель.** `attachLibraryInputLocked` (из `TraceArgument`/
`TraceAllArguments`) доказывает строгую связку формальный параметр → sink
и пишет `LibraryInput` в flow: API/объявление, formal index/name/type,
sink + точная позиция вызова (файл/строка/колонка `(`), arg, fingerprint
формы, шаги (`identity`, `byte-preserving-conversion`,
`payload-preserving-call`) и evidence ID. Разрешены только identity и
байт-сохраняющие конверсии, типизированный helper-forwarding,
formal-in→caller-argument forwarding для приватного helper'а,
`io.ReadAll` как единственный смоделированный complete-read и прямой
canonical `io.Reader`. Отклоняются константная подмена, срезы и числовые
конверсии, непрозрачные трансформации, composites/pointers/containers/
interface conversions, unresolved dispatch, перезапись формального
параметра или локальной переменной, guard/sanitization/recover на пути и
ineligible типы (включая похожие на `io.Reader` интерфейсы). `Origin`
никогда не переписывается; не-payload позиции (receiver, whole-args,
writer-only) остаются `PayloadUnproven` без свидетеля.

**Допуск.** `evaluator.ArgumentOrigin` проверяет
`admittedLibraryWitness(cond, c)` после package-absence и после genuine
external origin, но до unresolved-origin и constant-fallback веток:
внешний источник сохраняет приоритет (потребитель может сам передать
сетевые байты). Все гейты конъюнктивны: форма, `ATTACKER_CONTROL` +
`ArgIndex >= 0` + `input_source` отсутствует/`arg`, отсутствие
`direction`/`check`/`protocol_role`/`sequence`/`scope` параметров, класс
`DESERIALIZATION`, CWE-502, разрешённый SINK root cause с покрытием всех
subject'ов, текущий fingerprint формы, точное совпадение site/arg,
census-owned импортируемый пакет API с экспортируемым символом, разрешимые
evidence ID и отсутствие security-transform на пути.
`ServerTransportInput` сначала спрашивает тот же допуск и делегирует в
`ArgumentOrigin`, поэтому `--trusted-peer`, protocol-role и
server-transport эвристики не отменяют доказанный библиотечный путь.

**Вердикт.** `verdictExploitabilityScope` выбирает `library-api` только
для обязательного TRUE-claim с `control_basis: library-public-api`;
`VerdictEvaluator` добавляет обязательное ограничение и копирует
`ConditionIDs`/`EvidenceIDs` библиотечных claim'ов. `EvaluateVerdict`
исключает такие TRUE-claim из cluster-perimeter перезаписи peer-input и
копирует область в оба `ProfileVerdict`; демоция область не сохраняет.
Остальные вердикты область не получают.

**Отрицательные правила без изменений.** Свидетель не участвует в
negative verification; FALSE/unresolved пути, `KNOWN_ONLY`, package
absence, pending-review и unresolved-subject гейты прежние; неуспешный
допуск не создаёт FALSE-claim. `Claim.AssumptionIDs` не используется —
выбираемость нагрузки потребителем является код-фактом.

**Проекция.** Markdown (RU/EN) печатает область, обязательное ограничение,
witness-привязки и «Выбираемость нагрузки»/«Payload Selectability»;
`attackerControlProven` намеренно игнорирует `library-public-api`, поэтому
строка «Входные данные от удалённого клиента» не появляется. OpenVEX
остаётся `affected`, CycloneDX — `exploitable`; область, основание и
ограничение попадают в `impact_statement`/`action_statement`/
`analysis.detail`.

**Измеренные ограничения.**
* Постоянный фальсификатор (`constant-or-generated-input`) верифицируется
  по прямым call-site'ам субъекта в *продуктовых* пакетах. Если отдельный
  потребительский модуль вызывает библиотеку, а sink исполняется внутри
  библиотеки, прямых site'ов нет → `INSUFFICIENT_SCOPE` (честный
  `INCONCLUSIVE`), хотя sink-closure и записывает константные flow'ы.
* Triage/risk (`internal/risk`) по-прежнему оценивает deployment-экспозицию
  библиотечной формы (нет слушателей → P3). Это deployment-оценка, а не
  утверждение о контроле атакующего в потребителе.

## 7. Negative verification — защита FALSE

FALSE-кандидат проходит `Verifier` до того, как вердикт на него опирается:

- **Гейты до любой стратегии** (`VerifyFalse`): build-зависимый FALSE
  требует scoped `ProductTarget` (§3a), а сконфигурированный source index
  должен описывать ту же сборку (`BoundBuildContext` или эффективный
  контекст индекса). Отказ → `INSUFFICIENT_SCOPE` с названной причиной;
  любая запись NV штампуется эффективным `BuildContext`. Поэтому
  persisted `VERIFIED` из другой сборки не может ни обосновать, ни
  заблокировать вердикт.
- `SearchSymbol` — есть ли ещё ссылки на subject в продукте.
- `ScanDynamic` — `func_value`/`linkname`, целящий сам subject →
  CONTRADICTED → demote в UNKNOWN. `linkname` контрадиктит только
  если в detail упомянут subject (чужая прагма — игнорируется).
- `reflect`/`unsafe`/`plugin` — ослабляют FALSE **только для exported
  subjects**: unexported-символ рефлексией извне не достать, `unsafe`
  сам по себе ничего не вызывает (значим через func_value/linkname,
  которые проверяются адресно).
- Для `ATTACKER_CONTROL` — provenance всех call sites.
- `direction=read` — любая product-ссылка на subject это читатель →
  CONTRADICTED.
- `sequence=` — проверяются только **не вызванные** члены пары: ссылки
  на них → INSUFFICIENT_SCOPE, нет → VERIFIED.
- Параметрические check-условия (`config_flag`/`config_key`/`exposure`/
  `symbol_present`) NV не проверяет subject-escape правилами — их FALSE
  фальсифицируется собственным evidence; вердикт — INSUFFICIENT_SCOPE.
- `locus-package-absent` и `package-absent` проверяются по persisted
  `go list -deps` evidence (`verifyLocusAbsent`): все пакеты subjects
  должны отсутствовать в графе; найденный linked-пакет → CONTRADICTED;
  недекодируемый/отсутствующий список → INSUFFICIENT_SCOPE; файлы,
  импортирующие пакеты subjects, но исключённые текущим build-context
  (теги/GOOS/GOARCH/cgo) → INSUFFICIENT_SCOPE — отсутствие доказано
  только в границах записанной конфигурации сборки.
- **Scope-расширение** (после VERIFIED любой стратегией —
  `extendNegativeScope`): `GatedRefs` ищет ссылки на subject в файлах,
  исключённых текущими build tags (`pkg.IgnoredFiles`, без `_test.go`),
  синтаксически по импорту пакета; `InterfaceDispatchSites` ищет вызовы
  `x.Method()` по интерфейсному типу, который реализует тип субъекта
  (`types.Implements`). Находки → `INSUFFICIENT_SCOPE` (не CONTRADICTED:
  tag-файл может быть мёртвым кодом, interface-dispatch не доказывает
  конкретный impl) — FALSE остаётся, но вердикт/ревьюер на него не
  опираются.

VERIFIED FALSE → можно опираться; CONTRADICTED → claim демотируется в
UNKNOWN; INSUFFICIENT_SCOPE → claim остаётся FALSE, но вердикт на него
не опирается и ревьюер фиксирует medium-finding.

## 8. Review + repair

`review.Structural` (детерминистический) + `llm.Reviewer` (если включён)
→ merged findings. REVISE → bounded repair: демоция неподдержанных
claim'ов в UNKNOWN, бюджет `MaxReviewIterations`. Правила защиты:

- TRUE-claim от детерминистического evaluator'а (`Producer` =
  `evaluator.*`) с deterministic/authoritative evidence **не демотируется**
  — concern ревьюера записывается как caveat (LLM-ревьюер реально ловили
  на демоции валидного govulncheck-трейса).
- FALSE-claim демотируется всегда при найденных ограничениях — negative
  evidence по природе слабее.
- Structural демотирует FALSE при «widens the call graph»-limitation —
  детерминистично, не дожидаясь LLM.

## 9. Go toolchain — три уровня

| Источник | Когда | Что даёт |
|---|---|---|
| `--release-go-version` | версия из тикета/релиз-ноты | authoritative для stdlib-advisory |
| `--binary` + `go version -m` | собранный артефакт | реальный toolchain + модули дистрибутива; `govulncheck -mode binary` |
| release-evidence в снапшоте | `toolchain`-директива, Dockerfile `FROM golang:X`, CI `setup-go`, `.go-version`/mise/asdf | `ReleaseGoVersion` с `GoVersionSource` |
| локальный `go version` | analysis environment | НЕ является версией продукта — stdlib-applicability без `ReleaseGoVersion` остаётся UNKNOWN |

`go.mod` (`GoModDirective`/`MinimumGoVersion`) — **нижняя граница**, не факт
сборки; без `ReleaseGoVersion` stdlib-запись уходит в pending
(`VersionAffected=UNKNOWN`, `go_version`-условие → claim UNKNOWN) и вердикт
не может стать ни EXPLOITABLE, ни NEPF по фальсификатору — только
INCONCLUSIVE, с limitation «release toolchain unknown».

## 10. LLM-слой — строго поверх детерминистики

- LLM предлагает структуры: root-cause кандидаты, exploit-model
  conditions, review findings. Всё проходит детерминистическую
  верификацию до влияния на вердикт.
- Отказ/ошибка LLM → fallback на детерминистический путь + limitation
  в отчёте (видно в прогонах: `llm exploit model failed` → кейс всё
  равно дошёл до вердикта).
- `--deterministic-only` гасит слой полностью.
- LLM-агент работает через 17 typed tools (§17,
  `internal/llm/tools.go`): advisory/фикс-документы, module graph,
  govulncheck, source read/search, exec-инструменты. Каждый вызов
  ограничен `MaxToolCalls`, результат — evidence в графе; tool miss —
  ошибка модели, не «фактов нет». `run_build`/`run_tests` исполняют код
  репозитория и требуют явного `--allow-exec`; вызовы проходят через
  toolaudit и видны в `tool_executions`.

## 11. Eval harness — регрессионный корпус

`izyan eval --corpus eval/corpus.json` прогоняет кейсы через
полный пайплайн и считает метрики из спеки §9. Корпус — JSON:
`cases[]` с `vuln`/`vuln_file`, `repo`, `root_causes`, `expect`
(допустимые вердикты — диапазон легитимен, INCONCLUSIVE часто правильный
ответ) и `expect_claims` (per-condition утверждения).

| Метрика | Смысл |
|---|---|
| `false_safe` | safe-вердикт при недопускающем его ожидании — стоп-критерий, должен быть 0 |
| `expect_pass/fail` | вердикт в/вне допустимого списка |
| `claims_fail` | claim-ассерты не сошлись — регрессия внутри вердикта |
| `inconclusive` | доля неопределённости (распределение, не провал) |
| `errors` | кейсы, завершившиеся ошибкой пайплайна |

Exit code 1 при любом false-safe/expect-fail/claims-fail/error —
пригодно для CI. `--out`/`--json` пишут markdown/JSON-отчёт; case-state
по умолчанию уходит в temp dir (`--case-dir` для отладки падения).
Регрессионный прогон **детерминистичен**: eval по умолчанию работает в
`--deterministic-only` режиме, `--with-llm` — opt-in для замера
LLM-варианта (LLM-предложения недетерминированы и ломают
воспроизводимость corpus-метрик).
Пути в корпусе — относительно файла корпуса. Синтетические advisory
`eval/advisories/` покрывают механизмы фикстур `testdata/`; живой корпус
на реальных GHSA — следующий слой ([`gap-analysis.md`](gap-analysis.md) §3.7).

## 12. Target Go toolchain

Релизный бинарь собран конкретной версией Go — для `std`/`toolchain`/`cmd`
адвизори анализ обязан резолвить исходники **той** версии, а не локальной:

- Версия берётся по цепочке: build info бинаря (`--binary`) →
  `--release-go-version` → `corpus.go_version` (eval). Пусто → local.
- `internal/toolchain.Resolve`: local-match → `~/sdk/go<ver>` (dl SDK,
  оффлайн) → `GOTOOLCHAIN=go<ver>` (Go ≥1.21 скачивает в module cache).
  Недоступно → `Mismatch` + limitation; молчаливого чужого GOROOT нет.
- `Toolchain.Env` (PATH/GOTOOLCHAIN) протягивается во все subprocess'ы
  (`ExecGoTool`, `ExecRunner`) и `packages.Load` через `Index.Env` —
  stdlib-символы резолвятся под целевым GOROOT.
- Кейс фиксирует `analysis toolchain: go<ver> (<mode>)` в limitations.
- Docker — режим запуска, не toolchain: `eval/Dockerfile` собирает
  `golang:<target>` + бинарь анализатора; внутри `go` и есть целевая
  версия (toolchain сборки анализатора роли не играет).
- Важная граница: toolchain старше `go`-директивы модуля не загружает
  репо → честный `INCONCLUSIVE`, а не анализ по другой версии.

## 12a. Tool execution audit

Каждый внешний вызов инструмента пишется в
`EvidenceGraph.ToolExecutions` (спека §22): tool, version, dir, args,
exit_code (-1 = не стартовал/ctx kill), sha256 stdout+stderr,
duration_ms, error. Реализация — `internal/toolaudit`: рекордер
ездит в ctx (`WithRecorder` в `analyzeCase` сразу после создания кейса),
поэтому shared-обёртки из scan/eval (кэшированные runner'ы, созданные
до кейса) атрибутируют прогоны правильному кейсу. Все exec-точки —
`repository` (git, go version[-m]), `affected.runGo` (go list),
`goanalysis.ExecRunner` (govulncheck, `-version`), toolchain-пробы —
проходят через `toolaudit.Run`. Большие выводы не дублируются: хэш
привязывает запись к evidence.Content. Отчёт показывает таблицу
«Tool executions». `Evidence.ToolVersion` заполнен для govulncheck
(вывод `-version`/vulndb-строки). Не записываются: `packages.Load`
(in-process), env прогонов (секреты).

## 12b. OpenVEX-экспорт

Рядом с `report.{json,md}` каждый кейс пишет `openvex.json`
(`internal/report.OpenVEX`, openvex.dev/ns/v0.2.0). Маппинг вердиктов:

| Вердикт | VEX status | justification |
|---|---|---|
| EXPLOITABLE | affected | — (impact = reason) |
| NOT_AFFECTED | not_affected | `component_not_present` (модуль/билд) или `vulnerable_code_not_present` (версия/пакет) |
| NO_EXPLOIT_PATH_FOUND (code-grounded) | not_affected | `vulnerable_code_not_in_execute_path` — только после прошедшей negative-верификации |
| NO_EXPLOIT_PATH_FOUND (trust-grounded) | not_affected | `vulnerable_code_cannot_be_controlled_by_adversary` + `verdict.ground_basis` в impact: `declared-trust` (operator assertion), `auto-perimeter` (детектированная изоляция), `config-origin` (входы → конфигурация хоста) |
| INCONCLUSIVE | under_investigation | action_statement = reason |

Отрицательный вывод перед проекцией проходит повторный допуск (§3b):
`not_affected` достижим только при сохранённом
`AllowsNegativeClosure()`; CVE/алиас, `GO_PROJECTION` или legacy
`COMPLETE` без структурной переписи экспортируются как
`under_investigation` (OpenVEX) и `in_triage` (CycloneDX), даже если
загруженный case object содержал stale `NOT_AFFECTED`. Компонентные
факты при этом остаются в impact/action statement.

Продукт — `pkg:golang/<module>@<analyzed commit>`; уязвимая зависимость —
subcomponent `pkg:golang/<module>@<resolved_version>`. Рядом пишется и
CycloneDX-экспорт (`cyclonedx.json`): trust-grounded NEPF маппится в
`protected_at_perimeter` / `protected_by_mitigating_control`
(`config-origin`), code-grounded — в `code_not_reachable`.

Trust-grounded NEPF (`FalsifierTrustedInfrastructure`) дополнительно
гейтится полнотой модели: при operator-asserted основании и непустых
`UnresolvedSubjects` кластерный профиль понижается до INCONCLUSIVE —
заявление оператора покрывает только смоделированные условия.
Из подсчёта исключаются `AbsentSubjects` (⊆ `UnresolvedSubjects`):
субъекты, чьё отсутствие в графе сборки верифицировано package-list
evidence (`RootCause.Absent`), не несут «unmodeled exploit shape» —
их shape опровергнут нелинкованностью дефектного кода.
Диагностика сокращённой модели называет состояния кандидатов раздельно:
**source-verified** (покрыт условиями), **package-absent** (пакет вне
допущенного графа сборки), **source-absent** (пакет слинкован, но
выбранная версия источника не объявляет символ) и **unverified**
(проверка не дала ответа); для каждого указывается происхождение —
advisory-declared субъект или fix-derived кандидат. Верифицированное
отсутствие никогда не описывается как «unresolved in source» и не
делает модель «incomplete» только фактом своего присутствия в
positive-blocking списке: incomplete заявляется лишь при наличии
действительно неразрешённых кандидатов.
Основание `config-origin` (и любое non-perimeter) в `coversAllDeclared`
не участвует: provenance верифицирован против входов разрешённых
sink'ов и ничего не говорит о входах неразрешённого субъекта, поэтому
на неполной модели такой falsifier NEPF не обосновывает — как и
`constant-input`. Покрывают неполную модель только sink-агностичные
основания `declared-trust`/`auto-perimeter` (первое — с демоцией выше).

## 12c. Knowledge base — семантика экосистемы как данные

Таблицы, по которым provenance/exposure резолвят origins и
deployment-факты (какой вызов производит какой `DataOrigin`,
passthrough-индексы, populate-семейства, config-теги, auth-имена,
listener-примитивы + адрес-аргумент, db/service/http подсказки), живут
в `internal/goanalysis/knowledge.json` — embedded в бинарь,
`DefaultKnowledge()` парсит его тем же кодом, что и внешние файлы.

- `Index.KB` — эффективная база; nil → ленивые дефолты (`ix.kb()`).
- `--knowledge <json>` (analyze/scan/eval/remediate) — аддитивный мерж:
  повтор тем же значением — no-op, переопределение значения — ошибка,
  unknown key / невалидный origin / чужой `language` / свежая
  `schema_version` — ошибки загрузки.
- `izyan knowledge` — дамп эффективной базы в схеме файла
  (шаблон + валидатор).
- Провенанс: `Knowledge.Sources` собирает `name@data_version` файлов,
  `Digest()` — sha256 канонического содержимого; CollectEvidence пишет
  пару в RUNTIME evidence → вердикт привязан к ревизии базы.

Правила правки базы и версионирования — `agent-rules/knowledge-base.md`;
что допустимо класть в базу — `agent-rules/generality.md`.

## 13. Чего не хватает (известные границы)

- `ModuleInternalReach` работает по vendored-исходникам; без `vendor/`
  внутримодульные цепочки не проверяются → UNKNOWN вместо FALSE.
- `INPUT_CONSTRAINT` на формат данных («поле длиннее X») пока резолвится
  только по remote-input эвристике, не по реальным границам парсера.
- Deployment-факты резолвятся частично: listener/dial-сайты и
  provenance адреса собираются (`C-EXPOSURE`), но остаются supporting-
  уточнением, не гейтом; auth на entrypoint'ах, k8s/docker-манифесты и
  связывание var→config-значений без `env:`-источника не покрыты.
- NV-скоуп расширен (tag-excluded файлы + interface dispatch), но
  остаётся синтаксическим/типовым: компилируемость tag-варианта не
  проверяется, impl'ы интерфейса *внутри* dep-кода не перечисляются.
- gRPC-кейс (`GHSA-vp52`) проходит до `EXPLOITABLE`; RabbitMQ —
  4 EXPLOITABLE (unexported sinks + module usage + vendor-цепочки).
  Два бывших INCONCLUSIVE моделируются паттернами: credential retention
  → `INFO_LEAK` (`C-DATA-PRESENT` TRUE на реальных полях
  `PlainAuth.Password`/`Config.SASL`/`AMQPlainAuth.Password` из
  field-scan'а + `C-EXPOSED` VERIFIED FALSE), URI round-trip →
  `URI_CONFUSION` (`C-ROUNDTRIP` достроен stem'ом до `URI.String→
  ParseURI`, VERIFIED FALSE по паре). Оба FALSE демотируются ревьюером
  по `reflect`-маркеру → INCONCLUSIVE — корректно: `FieldByName`/
  `MethodByName` реально могут читать экспортируемые поля и вызывать
  экспортируемые методы, исключить их статически нельзя.
- Библиотечная область (`library-api`, §6a) доказывает выбираемость
  нагрузки потребителем, но не контроль атакующего в нижестоящем
  приложении; постоянный фальсификатор для потребителя, у которого sink
  исполняется только внутри потребляемой библиотеки, остаётся
  `INSUFFICIENT_SCOPE` (честный `INCONCLUSIVE`), а не `VERIFIED`.
- Без target-входов (`--goos`+`--goarch`, `--binary`/artifact,
  release-metadata) build-зависимые отрицания недоступны: кейс, который
  раньше закрывался как безопасный, становится `INCONCLUSIVE` (§3a). Это
  намеренное снижение recall на прогонах без target-входов, а не
  регрессия допуска.
- Отсутствие по `go list -deps` требует графа без error/dangling/orphan
  узлов; частичный вывод процесса (таймаут, обрыв, pid killed) не
  становится инвентарём отсутствия даже когда декодируется префикс —
  он годится только для witnessed presence.
- Scope записи advisory (§3b) не даёт CVE-wide полноты: OSV-документ
  может полностью представлять **свою** запись, но не весь продуктовый
  surface CVE. `related`-записи не проверяются и не доказывают
  исчерпывающность; не-Go реализации вне документа остаются вне модели.
  Поэтому projected-запись честно оставляет finding открытым, а не
  объявляет его безопасным.


## Definitive verdicts: outcome, requested finding and scope (2026-10-26)

The publication contract changed from "verdict or abstain" to three explicit
assessment outcomes. `assessment_outcome: DECIDED` publishes one of
`EXPLOITABLE` / `NOT_AFFECTED` / `NO_EXPLOIT_PATH_FOUND`;
`EXTERNAL_DEPENDENCY` publishes `INCONCLUSIVE` plus the named external facts that
would change the answer; `FAILED` publishes **no verdict** and carries typed
failure codes (`owner/code`) with a diagnostic report. `FAILED` is an analysis
refusal, not a vulnerability verdict. Claims keep `TRUE`/`FALSE`/`UNKNOWN`, so a
failed measurement leaves its claim `UNKNOWN` — the terminal classification
changes, the evidence does not.

The request pipeline is:

```text
CREATED -> SNAPSHOT_PRODUCT -> RESOLVE_VULNERABILITY (exact pin)
  -> DISCOVER_RECORDS -> per-record assessment (CHECK_AFFECTED ... EVALUATE_VERDICT)
  -> ASSESS_RELATED_RECORDS -> COMPOSE_REQUESTED_FINDING -> BUILD_REPORT
```

Discovery (`related`, aliases) nominates candidate records only. A directional
CVE attribution is a separate admitted proposition: the record's own id/alias, or
captured publisher/CNA material bound to the implementation, entry and fix.
Children are separate cases pinned to their own exact bytes; no claims, reviews,
proposals or conclusions cross the boundary. Composition is positive-only and
per profile/build; candidate negatives never close a CVE, and a CVE-wide negative
requires a declared, digest-pinned, completely enumerated corpus whose boundary
is stated verbatim.

`transport-peer` marks a witness-proved peer-input boundary and carries the
mandatory limitation that deployed adversary access is a separate question.
Listener locality (Unix/loopback binding, ClusterIP) no longer selects a trusted
profile: trust needs an operator assertion or an admitted deployment policy.

Every consumer (JSON, Markdown, CLI, scan/eval, tracker, justification,
remediation, research, OpenVEX, CycloneDX) renders the single `requested_finding`
projection; the FINAL envelope is the publish authority, not the workflow
position. See `docs/dev/plans/2026-10-26-02-definitive-verdict.md` (+ Addendum A)
and the measured calibration `docs/dev/reports/2026-10-26-definitive-verdict-calibration.md`.

## Candidate identity before candidate absence (2026-10-28)

Absence is evidence about **real subjects only**. A subject may ground an
absence claim only through an affirmative admitted basis — the record's own
declaration, an own-record operation binding re-admitted against the pinned
record, or an explicit operator assertion. A producer's origin label, a saved
`absent` flag, a patch-coordinate binding and the mere absence of a
contradicting candidate are not bases.

Measured defect (see `docs/dev/plans/2026-10-28-02-cross-line-binding.md`):
`GHSA-pwhc-rpq9-4c8w` at `containerd v1.7.27` produced four fix-derived
candidates from a v2/main-line patch (`cmd/containerd/server/server.go`,
`core/runtime/v2/task_manager.go`, `plugins/cri/runtime`, `plugins/sandbox`).
None of those packages exists in v1.7.27 at all (the daemon lives at
`services/server`). Their absence from the product closure was vacuous, yet they
grounded `RootCause.Absent` → `AbsentSubjects` → an exact-record
`NO_EXPLOIT_PATH_FOUND` that was accidentally right and unsound.

### The typed binding

`domain.CandidateBinding` records the derivation. It is a **diagnostic
observation**, not absence authority: an `ADMITTED` coordinate says only that
the module-relative path exists in the selected source, and absence authority is
a separate question re-derived at the shared boundary (see below).
`goanalysis.Index.SelectedModuleSource` / `SelectedModuleCoordinate` resolve the
source — the snapshot's `vendor/modules.txt` must declare that exact module at
that exact version, otherwise the module-cache entry for the escaped
`module@version` answers; an unresolvable coordinate is an error (unmeasured),
never "does not exist".
Nothing weaker than the same module-relative path is accepted: function-name
equality, suffix or path similarity and literal equality nominate candidates
only.

### The admitted bases

`domain.AbsenceAdmission` is the single shared result every consumer asks
(`domain.AdmitAbsence` / `domain.AdmitAbsenceFor` build it with explicit `*domain.ContentAdmission`; the
resolver, the exploit builder, the condition evaluators, the negative verifier,
the verdict boundary and publication all query the same object). It requires
one of:

| Basis | What establishes it |
|---|---|
| `RECORD_ENTRY` | the pinned record itself declares the subject: an affected symbol, an affected package, or an own-record operation binding re-admitted against the record id, the pinned document digest, the verbatim quotation and the affected scope |
| `OPERATOR_INPUT` | the operator supplied the subject explicitly and it is recorded as an operator assertion — not machine-proved source identity. A `MANUAL` candidate that duplicates or relabels a derived candidate is not a new operator input |
| `SAME_LINE_PREIMAGE` | the fix's complete old changed region matched exactly once in the exact selected version's source, the enclosing declaration read from that source is the omission site, the record's declared package boundary covers it, and the captured artifact bytes still reproduce the recorded preimage digest. Re-derived at every boundary; a stored status is not the premise |
| `CONTENT_BINDING` | the subject is a member of the necessary cover the persisted content proof re-derived from its captured input bundle at this boundary. Only a checker-created admission establishes it; a saved cover is never read as authority |

Nothing else admits. `FIX_DERIVED`, `LLM_PROPOSED`, an empty origin, an
`ADVISORY_DECLARED` label, a saved `CandidateBinding{Status: ADMITTED}`, a
stored `Absent` flag and an unmatched subject all confer nothing.
`ADVISORY_DECLARED` is a claim that the record declares the subject; the
declaration is what admits, never the label. A fix-derived coordinate binding —
including an `ADMITTED` one — is modelling identity only: it says the patch
path exists in the selected source, never that the advisory's defect lives
there or that its absence proves anything.

`domain.CandidateSubjectIdentity` answers the separate, weaker question "may
this candidate be modelled as a subject of the selected version at all?" — a
record-declared, operator-supplied or LLM-proposed candidate, or a fix-derived
candidate whose patch coordinate resolves. Modelling identity is not absence
authority.

### Withdrawal and the deliberate capability reduction

The original content-derived binding layer (the 2026-10-28 Slice B) was
**withdrawn** because its checker could not satisfy the proof contract
(`docs/dev/plans/2026-10-28-03-withdraw-and-reland-binding.md`). The re-landed
contract is now **active** (Tasks 6–9): a content binding is evidence only as
the checker-created reconstruction over a complete captured input bundle, and
the exact-preimage route is an explicit, re-derived identity/cover route.

The withdrawal-time capability reduction applied while only the identity gate
existed. It ends here for these routes:

- a stored coordinate binding — a saved `CandidateBinding{Status: ADMITTED}`, a
  patch path that merely resolves — still establishes nothing. A fix-derived
  candidate whose package is not linked stays a blocking obligation instead of
  becoming `RootCause.Absent`, and the case keeps the typed
  `FAILED / CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE` failure;
- an automatic patch-only same-line fix earns absence only through the
  exact-preimage basis: complete old changed region, one unambiguous selected
  source site, an enclosing selected declaration covered by the record's own
  declared package boundary, a re-derivable preimage digest and a nonempty
  necessary cover. A changed preimage, a missing selected source, a linked cover
  member or an added helper without an omission carrier stays unresolved;
- record-declared subjects and genuine operator inputs keep their own absence
  routes;
- config-flag conditions name their subject through typed params, so their
  package measurement keeps its own gate rather than the defect-subject rule.

A model that still carries a stored `fix_binding` keeps it as **withdrawn,
non-admitting historical evidence**: the payload is preserved verbatim (a
load/save cycle never rewrites history), the loader records the withdrawal on the
evaluation copy, and the shared admission refuses the subjects it named instead
of letting the payload decay into a weaker coordinate route. A duplicate or
relabelled candidate for one of those subjects is a dependent of withdrawn
evidence, not a new input. The new proof contract does not revive it.

### Where it is enforced

| Layer | Rule |
|---|---|
| `rootcause.Resolver.Resolve` | every distinct declared fix locator is requested from the configured provider and recorded in `FixArtifacts` — complete bytes with their digest, or a typed acquisition outcome; every captured artifact that changes a selected-source coordinate is inventoried, not just the first; fix-derived candidates record the patch coordinate (`Binding.PatchPath`) with the status deliberately unmeasured there |
| `rootcause.Verifier.Verify` | `establishBinding` decides whether the candidate may be modelled at all (`CandidateSubjectIdentity`); the package-absence branch asks the shared `domain.AdmitAbsenceFor` admission and refuses a coordinate-only subject with the typed gap |
| `exploit.Builder` | the absent flag and the source-absent lookup miss are copied into `AbsentSubjects` only for an admitted subject; an `Unverified` candidate's stored `Absent` flag is checked the same way instead of being copied, and an unadmitted candidate stays in `UnresolvedSubjects` |
| `goanalysis.Verifier.verifyLocusAbsent` | package absence is never `VERIFIED` for a subject whose identity is not established (contradiction still wins) |
| `evaluator.evaluateSymbolReachable` | the grouped all-absent FALSE is not proposed for an unadmitted subject |
| `evaluator.admitVerdictInput` | the shared deterministic boundary: persisted absence subjects are pruned, absence-falsifier claims are demoted on the same admission, a subject-less absence claim is refused, a stored withdrawn binding is reported as withdrawn, and the model's persisted proof is re-derived before any cover is used |

### Typed failure

An unadmitted candidate — unmapped in the selected source, measured against no
source, or backed only by a coordinate binding — stays a **positive-blocking
obligation** (`UnresolvedSubjects`, `Alternatives`, `Unverified`) and produces, at
assessment level:

```text
assessment_outcome: FAILED
verdict:            (none — FAILED publishes no verdict)
gap.owner:          CODE
gap.code:           ROOT_CAUSE_UNRESOLVED
gap.obligation:     ROOT_CAUSE
```

`INPUT / INPUT_RESOLUTION_FAILED / ROOT_CAUSE` is used when the selected source
or the resolved version cannot be resolved at all (a missing prerequisite rather
than a failed correspondence). `PROOF / PROOF_ARTIFACT_MISSING / ROOT_CAUSE` is
earned only by a fix artifact the configured provider was asked for and does not
hold; an unrequested locator is never reported missing, and the rest of the
artifact account maps to what was established: `INPUT / INPUT_RESOLUTION_FAILED`
for an acquisition form the provider does not implement or a provider that could
not answer at all, and `CODE / ROOT_CAUSE_UNRESOLVED` for captured bytes that map
onto no coordinate of the selected source or whose applicability stayed unknown.
Candidate absence never becomes `NOT_AFFECTED`, and the affected axes are
untouched.

### Replay

A saved fix-derived negative with no admitted absence basis does not re-admit at
the publication boundary. `finding.Project` recomputes the record's
classification through `finding.Assess`, which feeds the root-cause model and the
exact record into the verdict boundary; the demoted claim makes the recomputation
`FAILED`, and `admitProfileResult`/`compareSavedResult` refuse the saved
`NO_EXPLOIT_PATH_FOUND` with "saved … result is not supported by the current
record assessment". History is preserved: the case, its evidence, claims and
the saved result are never rewritten, and another independently sufficient proof
is unaffected. Missing basis means missing admission — there is no legacy
exemption and no grandfathering.

Controls that still earn absence:

- a record-declared subject absent from the admitted closure stays absence
  evidence (the declaration is the basis);
- an operator-supplied root cause (`--root-cause`, manual model, eval corpus) is
  recorded as `MANUAL` and keeps its explicit operator-trust route — unless the
  same subject is already a derived candidate, where the label is a relabel;
- an own-record operation binding re-admitted against the pinned record keeps
  `RECORD_ENTRY`.

A resolved patch coordinate alone does **not** earn absence. The automatic
patch-only same-line route earns it only through the exact-preimage basis
described above: a resolved coordinate is an observation about the selected
source, not a proof that the advisory's defect lives there. The same rule covers
the re-landed content proof: only the checker-created reconstruction over the
complete captured input bundle is authority.

### What this does not do

The identity gate alone establishes **identity** only: it does not prove
fixed-implementation equivalence, it does not enumerate alternative carriers,
and it does not close an operation census. Those are the persisted content
proof's job, and only a checker-created admission over the complete captured
input bundle establishes them. The generic name-miss non-counterpart proof
remains permanently deleted. With no admitted basis the correct outcome stays
`FAILED / CODE / ROOT_CAUSE_UNRESOLVED`, obligation `ROOT_CAUSE`.

## Re-land Task 5: diagnostic inventory and resource propagation

The admission layer was withdrawn at the time of this task; it has since been
re-landed (see Task 9 below). `goanalysis.Index.SelectedSourceCensus`
and `SelectedSourceCensusFor` acquire selected-source bytes, then use the pure
`fixbinding` census. They neither admit absence nor construct a necessary cover.

Four measured results are exposed separately: **input inventory**, **parsing/type
resolution**, **operation/resource analysis**, and **necessary cover**. A module
manifest, directory listing, successful parse, saved `Complete` flag or aggregate
digest cannot substitute for a stronger result. Necessary-cover completeness is
explicitly false (`NECESSITY_NOT_CHECKED`); Task 6 owns that proof.

The supported independent inventory anchors are an exact captured effective
module ZIP, reconstructed and checked with the captured product `go.sum` h1
checksum; or a complete captured product tree reconstructed against its recorded
t1 snapshot hash, with a confined local replacement/workspace subtree matching
Task 2's selected content digest. VCS labels alone are not supported anchors.
For vendor builds, the full anchored implementation is the discovery source,
including upstream alternative packages pruned from the product. Every retained
vendor byte must agree; modifications, extras, missing Go files in retained or
manifest-listed packages, unlisted retained packages and unsupported overlays
block input completeness. Missing capture/checksum evidence remains an explicit
input limitation, never whole-module proof from `vendor/modules.txt`.

Task5 adds contextual `/3` fix-proof admission: the checksum bytes themselves
must match the captured product t1 manifest under the current case ContentHash.
Current exact advisory/selection, build and cited inventory evidence are also
required. Saved source maps, inventory flags and proof-internal expected hashes
cannot substitute. A complete upstream/external tree carrier may be used only
when its exact file set equals an independently checked archive; `CheckTreeAnchor`
continues to establish product-selected local/workspace identity only.

The census uses Task 4's qualified declaration/resource primitives and bounded
may-sets through declarations, assignments, alias chains and branch joins.
Checked one-operation wrappers and exact parameter-return bodies support bounded
argument/return propagation. Unsupported calls, exported direct-entry
construction, pointer/field mutation, interface dispatch, containers, closures,
returns and loop-carried propagation produce blocking obligations; no generic
“read” disposition can hide a relevant use. Candidate resource keys deliberately
over-approximate instance identity and are **not** resource-equality certificates.
Build variants are inventoried independently of the linked package set; unresolved
variant typing, nested modules, generated inputs, cgo/native implementations and
other build-affecting material remain obligations. Type checking is pure and
closed: unavailable imported declarations do not fall back to ambient toolchain
or module-cache type data.

Pinning regressions: `TestLinkedAliasBypassCannotDisappearFromCover`,
`TestVendorSubsetCannotCertifyWholeSource`,
`TestUnsupportedPropagationBlocksCompletion`, and
`TestFourCompletenessResultsAreIndependent`.


## Re-land Task 6: re-derived correspondence, necessary cover and restricted non-counterpart certificates

This layer is a pure checker in `internal/fixbinding`: it reads no file, runs no
process and consults no cache. Task 8 wired one admission through every
consumer; Task 9 attached the persisted proof contract and activated it.

### One checker, two entry points

`Derive(Inputs)` reconstructs the canonical binding for one pinned input bundle.
`Admit(claimed, Inputs)` re-derives and then requires the claim to equal that
reconstruction, premise by premise, plus a condition/negative-verification
relationship that ranges over exactly the reconstructed subject set. Only
`Admit` returns an object whose status is `ADMITTED`, and that object is the one
the checker produced — the claimed value is never returned.

The input bundle is bytes and independently measured records only:

* the complete advisory document and its `RecordPin`;
* Task 2's per-entry effective-source descriptors and Task 5's anchored
  inventory of the implementation they select;
* Task 3's per-locator artifact records together with the complete captured
  bytes (directly or through a duplicate reference);
* one patch-side source per declared locator (locators are not a series, so two
  artifacts from different trees carry separate captures and never read each
  other's source);
* captured complete source of effective external implementation components.

### What is re-derived, never accepted

Record identity and the original `affected[]` entry (index, ecosystem, module,
declared packages/symbols/versions) are decoded from the pinned bytes. The
declared fix locator set is re-derived from those bytes with the same pure rule
the intake uses (`fix.Resolver`), and every declared locator must be accounted
for; an unrequested or undeclared locator is refused, and an unavailable
declared *commit* locator is a named `PROOF_ARTIFACT_MISSING` obligation. The
effective coordinate is compared with the **current** descriptor, including the
source kind and the stable source root, and the inventory must describe exactly
that source. The census is re-measured over the anchored implementation, never
over a product-linked subset. Patch effects, checked values, locations and
omission sites are re-extracted from the patch bytes and re-measured against that
census. Refusals are grouped (`RECORD_IDENTITY`, `ENTRY`, `SERIES`,
`ARTIFACTS`, `EFFECTIVE_COORDINATE`, `CENSUS`, `EFFECTS`, `LOCATIONS`,
`NON_COUNTERPART`, `SUBJECTS`, `COVER`, `CLAIM`, `OBLIGATIONS`), and each group is
compared in both directions, so adding, removing or editing any of effects,
alternative subjects, locators, entry indices, series membership, effective
coordinate, locations, census fields or non-counterpart records is refused while
the original input roots stay fixed.

### Correspondence identity

Task 4/5's resource key names one instance inside one source tree: owning module,
declaration and ordinal. A fix patch is written against another release line, so
`CorrespondenceKey` abstracts exactly the module coordinate and the instance
declaration, and keeps the package-qualified declared type of the base value,
every selector step with its package-qualified owner, and the complete
call/index/unary/binary chain. It is deliberately over-inclusive: an extra
candidate joins the cover, a dropped one would let a bypass escape. Rendered
expression text is never compared.

### The necessary cover

For each mechanism (a supported operation class) the checker establishes

    D(entry, mechanism) => Exec(s_1) or ... or Exec(s_n)

with `S` = every enumerated carrier of that class on the correspondence resource
key anywhere in the closed implementation boundary — the mapped alternatives and
the alternatives only the exhaustive enumeration finds. An empty set, a
narrowed set, an unresolved effect without a carrier, an unclosed boundary or any
non-entry census obligation refuses the cover. A mechanism every effect
discharged as `INAPPLICABLE` contributes nothing, so an all-`INAPPLICABLE`
inventory produces no subject set and therefore no absence-based NEPF. The cover
carries a cover identity and a subject-set digest; `CheckClaim` requires the
condition's subjects to equal the cover's subject set in both directions and the
negative verification to record the same cover identity and subject digest.

### Closed-boundary non-counterpart certificates

The generic declaration-name absence proof is deleted permanently. Missing
package/type/function names are diagnostic observations only.

The boundary is the selected implementation plus every effective external
implementation component a boundary file imports for side effects (blank imports
are always edges) or names as a registration initializer. Registration
constructions are enumerated independently of any patch path: a composite
literal carrying an initializer function is a registration, its identity must be
a literal or a resolvable constant, its named initializer must resolve inside the
boundary, and an inline initializer closure is analysed with its own parameter
bindings. Every function literal inside a scanned declaration is analysed the
same way, and the analysis is recorded on the census so a missing one is visible.

`INAPPLICABLE` requires the closed structural rule: every component independently
anchored, every edge and registration resolved, no blocking census obligation
(other than the accounted exported-entry reachability facts, which the boundary
accounts for by enumerating every declaration), one unambiguous mechanism, and
zero operations of that class on that resource anywhere in the boundary. A
candidate anywhere refuses the certificate, including a renamed, split, wrapped,
inline or externally supplied one. Opaque executable changes are never
discharged: an unclassified residual, a defect, a missing patch side or an
unresolved external edge blocks.

### Limits

* The route is deliberately narrow: any non-entry census obligation in any
  component refuses the cover and every certificate. Real modules with unknown
  calls therefore fail closed until a supported relevance rule narrows the
  obligations; no such rule is invented here.
* `ObligationEntry` is the only kind the closed boundary discharges, and only
  because the boundary enumerates every declaration in every component.
* A named initializer supplied by a captured external component is accepted as
  resolved only because that component's own declarations are scanned; no
  cross-component symbol resolution is claimed.
* The claim relationship is checked by `CheckClaim` at every boundary; the
  persisted proof records the canonical cover and the claim must equal it.

Pinning regressions: `TestAdmissionReconstructsAllPremises`,
`TestAllInapplicableInventoryEstablishesNoCover`,
`TestBindingRequiresAnchoredInventory`,
`TestBindingRefusesSubstitutedRecordAndArtifact`, and
`TestNonCounterpartRequiresClosedImplementationProof`.

## Re-land Task 7: the exact-preimage route through resolver and verifier

The exact-preimage route restores the same-line capability without path
existence as authority. `rootcause.Resolver` nominates a fix-derived candidate
from a captured artifact; `rootcause.Verifier.establishBinding` resolves the
module-relative patch coordinate in the exact selected version's source and then
runs `fixbinding.MatchSameLinePreimage` over the complete captured bytes.

`domain.SameLineCorrespondence` records the typed outcome and is evidence about
identity and necessity only — never about absence. A positive result requires:

- the complete old changed region and its context matched unambiguously in the
  selected file (only CRLF→LF and the diff prefix are normalised);
- the enclosing selected declaration is the omission site and is covered by the
  record's own declared package boundary (declared affected packages plus the
  affected chain's measured checked packages);
- the spliced postimage parses, every added helper is named by the changed site,
  and every hunk falls in one declaration;
- the captured artifact bytes still reproduce the recorded preimage digest at
  every boundary (see below).

`Cover` is the record's own boundary, not whatever the patch touched. The route
works without an operation classifier: an opaque same-line change has exact
identity even when it has no permission-operation classification, and no
operation/resource component is fabricated for it. `TestSameLineResolverVerifierEarnsAbsenceEndToEnd`
starts at `Resolver.Resolve` (not a hand-built model) and walks the verifier,
exploit builder, negative verifier, verdict evaluator and publication.

## Re-land Task 8: one admission result through every consumer

`domain.AbsenceAdmission` is the single question — "may this subject ground an
absence claim, and against which necessary cover?" — and it is derived from
persisted, re-checkable data only. `domain.AdmitAbsence` /
`domain.AdmitAbsenceFor` (consuming checker-created `ContentAdmission`) are the exported entry points; the resolver, the
exploit builder, the condition evaluators, the negative verifier, the verdict
gate, the sink-set contract, publication and every legacy render/export path
query the same object. Fresh analysis and replay reach the same subject and
cover decision from the same persisted inputs.

Two invariants dominate:

- **Refusal domination.** When a required content route is missing, refused or
  withdrawn, every dependent absence flag, absent-set membership and claim is
  non-admitting. A coordinate binding is a child observation; a duplicate or
  relabelled `MANUAL`/`LLM_PROPOSED` candidate cannot rescue it. Independent
  record declarations, re-admitted own-record operation bindings and
  independently re-derived content routes still close through their own
  evidence — dependency-specific refusal, not a global veto.
- **Exact nonempty cover equality.** `CheckClaim` refuses an empty condition
  subject set, an absent-only subset, a narrowed condition, a changed
  verification cover/digest, and any cover package the admitted build graph
  links. There is no fallback from empty condition subjects to
  `Model.RootCauses`.

## Re-land Task 9: the persisted proof contract is active

### The persisted record

`domain.FixProof` is the only form in which a full content binding may accompany
a root-cause model (`RootCauseModel.FixProof`). It stores the checker's canonical
binding and the exact immutable input bundle it was derived from, both verbatim,
plus a projected cover for diagnostics and load/save validation. The projection
is **not authority**: `fixbinding.Readmit` decodes the claimed binding and the
input bundle, re-runs `Derive`, requires the claim to equal the reconstruction
premise by premise, and returns the checker-created binding. `Persist` refuses to
record a binding the bundle does not reconstruct. The checker rejects an unsupported
contract, an empty cover, or a proof without its input bundle; a refused proof
demotes only its dependents, never the case's independent evidence.

The input bundle is bytes and independently measured records: the complete
advisory document and pin, per-entry effective-source descriptors, the anchored
selected-implementation inventory, every captured fix artifact, one patch-side
source capture **per declared locator**, and any effective external component. The inventory's
analysis-local file bytes are re-hydrated on replay from the persisted archive or
product-tree evidence and re-checked against the recorded digest; a listing that
disagrees in either direction is refused.

### The shared boundary

`AdmitModelProof` derives the model's proof, then hands the checker-created result to
`domain.AdmitAbsence{,For}` directly. The content proof's mechanism subjects join the
aggregate necessary cover alongside the exact-preimage route's declared
boundary; the aggregate identity binds the union, the subject-set digest and the
package set. A model that carries a proof but no re-derived admission is refused
rather than read through its saved projection. A refused proof preserves its
typed refusal and dominates operator/LLM labels over the subjects it claimed,
while independent record declarations and independent content routes stand.

The producer side is `fixbinding.Persist`; no other API can attach a proof. The
root-cause resolver is the production producer: it captures the advisory bytes,
the fix artifacts and the selected implementation, then builds each locator's
patch-side source from that implementation only where the captured change's
complete before-image is **line-aligned** with the selected file — the selected
file is the patch's own base, not merely similar. Every other locator keeps its
`MISSING_PATCH_SOURCE` obligation, so the binding refuses.

Two artifacts from different trees are valid separate premises: contract
`fixbinding/re-derivation/2` keys the sources by the exact declared locator, and
the cover identity hashes the `{series, artifacts, patch_sources}` association.
An artifact whose accounting is incomplete refuses the binding for the others
as well: an unresolved locator is not evidence that it is irrelevant.

Effective external components are still an explicit input obligation: the
pipeline does not capture them, so a boundary that reaches an external
implementation edge refuses the cover. The route is authoritative when a
complete proof exists and non-admitting otherwise.

### What is measured and what is not

Pinned by tests: the persisted proof re-derives through a JSON load/save cycle
and grounds the same cover; an edited projection adds no subject; a re-derived
proof whose captured inputs are replaced, removed, truncated or substituted with
another module's source is refused; a refused proof dominates duplicate
operator/LLM labels at the verdict boundary and publication refuses a saved
conclusion that rested on it; an independent exact-preimage route still stands;
a stored `fix_binding`-era payload stays withdrawn and non-admitting. The
independent `research.VerifyDecision` route supplies the lane's exact record and
names a module-level subject by its module, so package/module absence decisions
keep their own record-declaration basis without a nil-model exemption.

Not measured: a real-corpus NEPF through the full content proof. The repository
carries no captured upstream Helm advisory document, no exact `containerd v1.4.3`
source and no patch-side capture, so those acceptance cases cannot be earned
offline and are **not** claimed. The same-line route's end-to-end NEPF is
measured on a fixture with exact selected source and complete recorded inputs;
the real Helm record remains `FAILED / CODE / ROOT_CAUSE_UNRESOLVED` unless its
inputs are captured. `containerd v1.4.13` is never accepted as evidence for
`v1.4.3`: the effective coordinate comparison refuses another version's source,
and the exact `v1.4.3` support boundary must account for the effective external
CRI component (`github.com/containerd/cri`) or fail closed.

Existing controls are unchanged: target/inventory admission, declaration
resolution, omitted/defective-check semantics, mandatory review, library and
transport admission, independent proofs, and requested-CVE composition. This
layer never creates affected-chain `FALSE`, `NOT_AFFECTED` or CVE-wide negative
scope.

## Product B: LLM-first human result (Phase 1, 2026-10-28)

`internal/productb/triage` is a separate runtime from the Product A state
machine. It consumes `finding.v1` (compatibility transport) or the generic
Stage 0 intake, builds a read-only snapshot, runs the bounded agent loop and
the FactGate, optionally verifies falsifier proposals, derives support from
the decisive-premise graph, and persists a `decision-package.v4` from `assessment.v3`.

The captured `human_review_plan` contains the complete finite decision universe
for 0–2 declared environment questions (including unknown), ≤7 mandatory first-screen
premises and per-branch support. `environment-assertion.v1` is an append-only
human-owned premise with explicit supersession, never `domain.Claim{Result: FALSE}`
or a falsifier. Applying answers only selects a prepared branch; valid answers
are not reasked. Conflict is CONTRADICTED/KEEP_OPEN; bounds overflow or missing
branches are NOT_DECISION_READY, not hidden further research. `human-decision.v2`
binds package/branch/projection/assertion identities with optional comment and a
derived reason code. Replay copies both collections verbatim without new timestamps.
Two-step environment Accept/Reject carries the displayed `--projection-hash`;
the writer compares it under the review lock and rejects superseded presentation
pins without appending a decision. One-step answer+decision must supply the full
selected answer set and cannot also specify a prior projection pin. No unseen
inherited answer or latest-selection-wins behavior authorizes an acceptance.

Research is a separate deterministic lane: current `research-report/5` publishes
the canonical `finding.Project` requested composition plus `requested-case.json`.
Retained adapters and pure validators are not a second live investigator.
`eval research-replay` preserves `/3`/`/4`/slice2/flow originals and timestamps in
a history-only envelope with no current admission; publication freshly admits
persisted canonical inputs. B1 stays frozen/eval-only. Offline tracked controllers
produce indexes/summaries and reject failed/stale/foreign reports; CI supplies
immutable corpus inputs, not an executable from an external provisioned directory.

### Runtime loop and failures

`AgentRunner` issues the initial exchange loop up to `MaxSteps`, then one
bounded finalization exchange and the optional fact/falsifier feedback turns
under one total step counter. A malformed answer after the bounded repair,
an expired context, a transport failure and an artifact-write failure stay on
the technical-error channel (exit 2) — they never become a completed human
investigation. When the bounded finalization exchange produces the accepted
assessment, the selected `AgentRun` records `finalized_after_step_budget`; the
CLI stamps that value into `technical_assessment.budget_result`, and replay
recomposes from the same recorded value. The value is descriptive, not a
quality or completeness score.

`FactGate` re-derives each evidence reference against the snapshot and the
run's own observation archive. `VALID` means the reference is reproducible;
`UNREFERENCED`/`UNAVAILABLE`/`INVALID` remain recorded limitations, and a
decision-relevant non-`VALID` check blocks risk reduction without deleting the
human action. `det:`/`obs:` references resolve only against the selected
attempt's recorded observations; a foreign or tampered archive is a technical
error.

### Support and composition

`DeriveSupport` walks exactly the action's decisive claim closure. Each claim's
declared basis is replaced by the computed basis: `OBSERVATION_FACT` requires a
canonical locator, matching payload digest, snapshot binding, selected-attempt
ownership and complete coverage; `QUOTED_TEXT` establishes the presence of the
text, not its interpretation; `FALSIFIER_PROOF` requires a persisted
`VERIFIED` checker certificate bound to the proposal, condition, subject set,
snapshot and build context. Assumptions, unresolved/conflicting claims,
unresolved counterarguments, contradictory facts and semantic stability
disagreement cap support at `LIMITED`; missing identity/material yields
`INSUFFICIENT`; `PROVED_WITHIN_SCOPE` additionally requires a directly
decisive admitted proof and a record-bound scope. There is no default level and
no numeric confidence.

`Composer.ComposeWithEvidence` writes the machine disposition from the
authoritative baseline, providers, profiles, permitted rules, pre-package
checks and admitted proofs. It never reads the model judgment, the human
action, support or a human decision as a machine premise. Missing severity
leaves `machine_disposition.baseline` absent and withholds reductions; the
configured `baseline.default_severity` fallback names its source and is
recorded as a limitation. The package audit pins snapshot/build/advisory/
ruleset/prompt/limits and the Stage 0 provenance hashes.

### Persistence and review

`ArtifactWriter` atomically writes the input, snapshot, raw-agent transcript,
assessment, fact gate, observation archive, falsifier report, condition
catalog/binding, stability sidecar, `decision.json` and the action-first
`decision.md`. The card renders the recorded scope (boundary, records with
digests, open boundaries) and keeps provider facts and machine predicates in
a collapsed audit section.

Accept/Reject is a separate append-only collection: one immutable
`human-decisions/<record-id>.json` per decision, created under the portable
flock and bound to the canonical package hash. The record id is derived from
the record content; an identical repeat is refused, and no record rewrites the
package, the card or an earlier decision. The audit projection records the
decision, actor, reason and exact record hash under the run that produced it.

### Replay and offline evaluation

`PrepareReplay` verifies the recorded input/snapshot/raw-response/assessment
hashes, re-runs the FactGate and verifier against the recorded archive,
recomposes the package and compares the axes separately (`judgment`, `action`,
`premises`, `support`, `machine_disposition`). It copies verified review
records byte-for-byte. It never calls a model, the network or the original
repository, and refuses a superseded live schema instead of upgrading it.
`triage-evaluation.v1` (`izyan eval triage`) compares one saved package with an
explicit external control; absent control or expected judgment is `UNASSESSED`,
human and machine counters stay separate, and its exit 1 is an offline
comparison violation, not a live triage result.
