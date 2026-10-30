# Plan: VEX-Bench Plain Agent baseline (Task 3)

Ветка: `feat/shadow-analyzer-agent`, только выделенный shadow worktree.
Спека: [`shadow-analyzer-agent-spec.md`](../specs/shadow-analyzer-agent-spec.md) §7, §9, §11–16, §18, §26–27, §41–43, §49, §51.
Предшественник: [`2026-10-07-vexbench-baseline-plan.md`](2026-10-07-vexbench-baseline-plan.md).
Замороженная сторона A: [`external-baseline-1.md`](../../../eval/baselines/vexbench/external-baseline-1.md).

**Проектный шлюз: CONDITIONAL.** Минимальный дизайн определён, изменений harness не требуется. **Операционный шлюз: BLOCKED** до предоставления владельцем провайдера, ключа, точного имени модели и бюджета (§2). Наличие локальных CLI и proxy-key variables не доказывает пригодность провайдера для контейнерного harness.

Это исполнимый план при закрытии внешнего access gate, **не отчёт о выполненном Task 3**. В рамках подготовки плана не запускаются harness, paid APIs, `uv sync` или Docker build. Task 3 не считается выполненным после одного smoke/repeat. Baseline 1 не меняется. Имя файла задаёт дату плана; дату будущего выполнения записывать фактическую, в UTC.

Обозначения: **факт** — свидетельство; **решение** — контракт плана; **[INFERENCE]** — не измеренная оценка. `H/` ниже — файлы **официального VEX-Bench** на pin [`80cddeac3132826bfd47227ad59b2e6618a681bd`](https://github.com/steven1518/vex-bench/tree/80cddeac3132826bfd47227ad59b2e6618a681bd), относительно корня checkout. Например, `H/src/evaluate/common.py:12-14` означает [именно этот исходник и эти строки](https://github.com/steven1518/vex-bench/blob/80cddeac3132826bfd47227ad59b2e6618a681bd/src/evaluate/common.py#L12-L14), а не текущую upstream-ветку. Локальные абсолютные пути задаются переменными; приватные пути и имена внутренних провайдеров в Git не попадают.

---

## 0. Установленная территория

### 0.1 Официальный harness

| Факт | Свидетельство |
|---|---|
| Реальные стадии — `evaluate run`, `evaluate parse`, `evaluate metrics` | `H/src/cli.py:23-30` |
| Общие флаги: `--agent`, `--model`, `--benchmark`, `--prompt`, `--repeats`, `--timeout`, `--parallel`, `--repos-dir`, `--output-dir`; default timeout 600 s | `H/src/evaluate/common.py:113-175` |
| Benchmark — зарегистрированное имя, не путь: единственный ключ `vex_bench` связан с **относительным** `benchmark/tasks/vex_bench.jsonl` | `H/src/evaluate/common.py:12-14,43-48,78-80,121-126` |
| Evaluation не принимает tasks path и не фильтрует язык: читает все непустые строки, планирует Cartesian product tasks × repeats | `H/src/evaluate/common.py:105-110,113-160`; `H/src/evaluate/run.py:73-87` |
| Snapshot находится как `<repos-dir>/<owner>/<repo>/<full-sha>`; отсутствующий каталог/язык приводит к skip, не к успешному анализу | `H/src/evaluate/run.py:23-32`; `H/src/utils/repo.py:4-11` |
| Prompt — официальный `vuln`, в него подставляется только `cve_id` из task | `H/src/evaluate/prompts.py:1-106`; `H/src/evaluate/run.py:45-52` |
| Codex копирует дерево в disposable container, монтирует только config read-only, передаёт env-file, удаляет container; source не bind-mounted | `H/src/evaluate/agents/base.py:26-96`; `H/src/evaluate/agents/codex.py:17-59` |
| `docker create` не задаёт `--network`, host HOME или Docker socket mounts; Codex запускается с `danger-full-access` и `--skip-git-repo-check` | `H/src/evaluate/agents/base.py:50-67`; `H/src/evaluate/agents/codex.py:41-59` |
| Codex model передаётся CLI как есть; OpenCode constructor разрешает только пять ключей MODEL2NAME | `H/src/evaluate/agents/codex.py:30-31,43-53`; `H/src/evaluate/agents/opencode.py:18-24,37-40` |
| Valid-category cache переиспользуется; missing/unparseable result запускается заново, error.txt может быть удалён | `H/src/evaluate/run.py:34-42,54-63`; `H/src/evaluate/agents/codex.py:105-127` |
| Raw namespace не включает dataset hash, endpoint, timeout или CLI image identity | `H/src/evaluate/common.py:90-98` |
| Parse создаёт по строке на каждый task/repeat, включая `no_dir`, `no_result`, `parse_fail`; GT появляется в parsed output только на control plane | `H/src/evaluate/parse.py:18-53,56-105` |
| `uncertain` входит в valid categories и binary-mapped в `not_exploitable` | `H/src/evaluate/result_parser.py:6-22,90-99` |
| Missing prediction — FAILED, wrong для accuracy и miss для positive recall; completion — наличие parseable prediction, не RunStats.completed | `H/src/evaluate/metrics.py:88-120,172-181` |
| Quality metrics агрегируются по run_id как mean ± **sample** std; counts суммируются | `H/src/evaluate/metrics.py:30-52,188-243,287-304` |
| Tokens/cost агрегируются по наблюдённым case rows, исключая отсутствующие usage/price; это другая единица std | `H/src/evaluate/metrics.py:247-284`; `H/src/evaluate/pricing.py:57-88` |
| Python harness требует ≥3.12, `.python-version` = 3.12; entrypoint устанавливается как package | `H/pyproject.toml:1-13,18-32`; `H/.python-version:1` |

### 0.2 Данные, Baseline 1 и host facts

**Факт:** готовые acquisition-артефакты дают ровно 30 Go tasks / 28 immutable snapshots / 15 repositories / 24 CVE. Снапшоты без `.git`, layout совместим с `--repos-dir`; повторный download не нужен. Источники: `external-baseline-1.md:12-33`, приватный `$BASE/acquisition.json:12-29`; layout — `H/src/evaluate/run.py:28-32`.

Identity для обеих сторон:

* harness/dataset commit: `80cddeac3132826bfd47227ad59b2e6618a681bd`;
* full JSONL SHA256: `06c58010defd28a3165598072b36fd56e986bc4c39c91f3c0095dc82b2800ddf`;
* Go JSONL SHA256: `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3`;
* GT знаменатели: 30 total, 7 exploitable, 23 non-exploitable; category supports 7 vulnerable / 18 code_not_reachable / 3 code_not_present / 2 requires_configuration (`external-baseline-1.md:12-43`; `eval/vexbench_baseline.py:89-91`).

**Host facts, предоставленные исполнителем подготовки:** `uv 0.11.2`, `docker 29.5.3`, daemon доступен, host Python 3.9.6; установлены host CLI codex/claude/opencode. Образов `vex-bench-*` пока нет. Host CLI версии не являются версиями harness: агент будет установлен **внутри образа** (`H/README.md:105-106`; `H/docker/go.codex.Dockerfile:1-8`).

Измерение Docker, предоставленное main agent при подготовке: images **1.45 GB**, reclaimable 100%; build cache **2.13 GB**, reclaimable **2.06 GB**. На `/` свободно около **51 GiB**. Это не free-space measurement Docker Desktop VM или внешнего output volume. Reclaimable не означает разрешение удалить чужие данные. Предыдущий Task 2 plan описывал иное состояние диска; старые 10–11 GiB не переносить как актуальное измерение.

Реальные `env/<agent>/*` credentials/config без `.example` отсутствуют. В host environment есть только proxy/other-provider keys; их endpoint/model/API compatibility не подтверждены. Для одного внутреннего endpoint ранее наблюдался DNS ENOTFOUND: это известный внешний отказ, не повод запускать benchmark для повторного подтверждения.

---

## 1. Цель и наименьший дизайн

**Решение:** получить сторону **B — Plain Coding Agent** на тех же 30 Go tasks, **три независимых repeat**, `parallel=1`, официальный pinned harness, неизменённый официальный prompt. Freeze первый attempt каждого из 90 task/repeat pairs, сохранить raw/parsed/official metrics, дополнительно сделать **offline** safety-aware projection и read-only comparison с Baseline 1.

Границы:

| Компонент | Ответственность | Запрет |
|---|---|---|
| Изолированный control-directory | Неизменённые harness sources + Go-only registered task file + private provider configuration | Не копировать сюда Izyan verdicts как agent inputs; не мутировать pinned checkout |
| Официальный harness | Docker isolation, 90 attempts, raw outputs, parse, compatibility metrics | Не патчить runner, prompt, model mapping или scorer ради этого прогона |
| Внешний observer | Run log, Docker lifecycle events, UTC boundaries, disk/image/provenance capture | Не вмешиваться в model messages или decisions |
| Маленький offline reporter | Join по `(task_id, run_id)`, safety metrics, telemetry coverage, comparison table | Не вызывать модель, не изменять raw/official metrics/GT/Baseline 1 |
| Владелец | Provider/model/budget/access approvals | Не передавать ожидаемые verdicts через конфигурацию |

Для реализации отчётности достаточно одного небольшого `eval/vexbench_plain_report.py` и fixture tests по существующему Python 3/stdlib стилю `eval/vexbench_baseline.py`. Это **планируемый** offline interface, не существующая команда. Не создавать новый acquisition/runner framework и не менять Baseline 1 orchestrator. Сначала закрыть owner gate и reporter contract, затем оплачиваемый run.

**Non-goals:** запуск/сборка при написании плана; изменение Go-кода Izyan; исправление обнаруженных CVE outcomes; Shadow Agent core/typed tools (Task 4), Verification Kernel (Task 7); модельный leaderboard; подбор prompts; переоценка A на текущем изменённом Izyan SHA.

---

## 2. Что требуется от владельца — явный внешний блокер

Без следующего **не начинать paid execution**:

1. **Endpoint:** полный API base URL, протокол (`Responses` для основного Codex-профиля), допустимые DNS/VPN/TLS/proxy условия, подтверждённый маршрут **из Docker bridge**, доступ к публичным CVE/advisory источникам. «OpenAI-compatible» само по себе не достаточно: Chat Completions и Responses — разные API.
2. **Ключ:** через защищённый канал, отдельный least-privilege ключ/квота. Не просить вставлять ключ в Git, Markdown или stdout. Не выбирать автоматически один из существующих host proxy keys.
3. **Модель:** точное provider model/deployment name, backend model revision (либо явная невозможность pin revision), reasoning effort и доступные tool/streaming capabilities. Владелец закрепляет **тот же backend model/revision** для будущего сравнения со Shadow Agent (§26 спеки); Task 3 не проектирует сам Shadow Agent.
4. **Бюджет:** actual input/cache/output tariffs, максимальные доллары на 90 attempts и отдельный synthetic preflight, provider-side budget stop или оперативный способ остановки, временное окно и допустимые расходные ограничения. 600 s — local timeout, не billing cap (`H/README.md:137-140`).
5. **Хранилище:** одобренный внешний `$PLAIN`, доступный Docker Desktop для единственного config bind mount, quota/free space Docker VM и файловой системы результатов.

**Автоматически делает исполнитель:** проверяет identity/30-task subset/28 snapshots; готовит isolated control-directory; устанавливает locked Python environment; собирает только два выбранных image; создаёт private config/env из одобренных значений; выполняет synthetic connectivity/model preflight; фиксирует provenance; выполняет run → parse → metrics; замораживает результаты; генерирует две metric projections и comparison. Исполнитель не добывает cloud credentials и не подменяет недоступную модель другой.

### 2.1 Реестр неизвестных и закрытие

| Приоритет / тип | Что зависит | Закрытие / владелец / момент |
|---|---|---|
| P1, известный внешний блокер: endpoint/key/API/model отсутствуют | Допустимость Codex и честность B vs C | Владелец предоставляет approved Responses profile; synthetic check в том же image/network **до** benchmark |
| P1, модельная идентичность | Интерпретация преимущества tools | Владелец фиксирует backend revision/effort до первого attempt; при несовпадении с C — return to design |
| P1, бюджет/квота | Полные 90 attempts без скрытого censoring | Владелец утверждает tariffs/cap/time; исполнитель фиксирует до старта |
| P1, container route/DNS/TLS | Изоляция и возможность доступа | Исполнитель проверяет synthetic source, без benchmark CVE/labels; owner-only gateway при необходимости |
| P1, Docker VM free space и mutable base image tag | Воспроизводимость/ENOSPC | Ресурсный preflight и image content identity до run, без автоматического prune |
| P1, отсутствующая wall/tool telemetry в scorer | Заполнение §43 без выдуманных чисел | Non-invasive Docker event capture + raw trajectory extraction; coverage и N/A явно |
| P2, pricing table vs invoice | Долларовая efficiency metric | Сохранить official estimate и actual provider billing separately, включая missing coverage |

Открытых архитектурных P0 в принятом **Responses/Codex** контракте нет. Conditional не разрешает запуск без перечисленных gates. Chat-only endpoint, другой model API или необходимость harness patch опровергают этот контракт и требуют повторного design.

---

## 3. Агент и модель; provider configuration

### 3.1 Основной выбор

**Решение:** `--agent codex`; предпочтительный кандидат `--model gpt-5.5`, **только после подтверждения владельцем** его наличия и использования того же backend в C. Если deployment name другое, передать точное approved имя, а в provenance отдельно записать canonical backend/model revision. Не утверждать, что `gpt-5.5` уже доступна.

Обоснование: это прямой профиль примера §26; `CodexAgent` не имеет hardcoded model allowlist и передаёт `--model` провайдеру (`H/src/evaluate/agents/codex.py:30-31,43-53`). Azure example использует Responses и `xhigh` (`H/env/codex/config.toml.example:1-9`). Только equality display alias недостаточно: routing, revision, effort, model substitutions и provider defaults тоже фиксируются. Идентичность LLM уменьшает confounding; различия agent CLI, prompt/tool surface и Linux sandbox остаются ограничениям сравнения, не доказательством «отличались только typed tools».

Codex image pin = **0.131.0** (`H/docker/go.codex.Dockerfile:6`). Локально установленный codex не используется для paid baseline.

### 3.2 Private Codex конфигурация для Azure или внутреннего Responses endpoint

Создать только в `$CONTROL/env/codex/`, права env-file 0600. Не монтировать host `~/.codex`, auth stores или worktree `.env`.

`config.toml` — минимальный transport/model config:

```toml
model_provider = "baseline"
model = "<approved model or deployment name>"
model_reasoning_effort = "xhigh"

[model_providers.baseline]
name = "Baseline provider"
base_url = "<approved Responses API base URL>"
env_key = "MODEL_API_KEY"
wire_api = "responses"
```

`codex.env`:

```dotenv
MODEL_API_KEY=<key supplied through a secure channel>
```

`xhigh` принимается только если approved model поддерживает этот профиль; unsupported effort нельзя исправлять по отдельным CVE. До run закрепить другой общий supported effort и записать rationale. Endpoint, model, key и effort — конкретные owner inputs, а не значения для guessing.

Harness читает именно относительные `env/codex/codex.env` и `config.toml`, env передаёт `--env-file`, config монтирует в `/tmp/.codex/config.toml:ro`; host ambient key сам в container не попадает (`H/src/evaluate/agents/codex.py:17-19,33-59`; `H/src/evaluate/agents/base.py:50-55`). Azure sample не является обязательным hardcoded provider: runner не проверяет его имя (`H/src/evaluate/agents/codex.py:33-59`).

Current Codex docs: [custom provider fields / Responses](https://github.com/openai/codex/blob/main/codex-rs/model-provider-info/src/lib.rs). Данные актуальной документации не заменяют synthetic compatibility check CLI **0.131.0**. Не обещать, что Chat Completions-only endpoint работает с `wire_api="responses"`; не планировать protocol conversion как невидимую часть baseline.

### 3.3 Ограниченный fallback: OpenCode + OpenAI Chat Completions endpoint

Выбор только **до первого baseline attempt**, если owner утверждает Chat Completions-only provider и одну из реально поддержанных моделей. Это не автоматический fallback после плохих results.

Hardmap:

| `--model` | Фактический OpenCode model ID |
|---|---|
| `gpt-5.5` | `azure-cognitive-services/gpt-5.5` |
| `gpt-5.4-mini` | `azure-cognitive-services/gpt-5.4-mini` |
| `kimi-k2.6` | `Azure-Resource/Kimi-K2.6` |
| `deepseek-v4-flash` | `Azure-Resource/DeepSeek-V4-Flash` |
| `deepseek-v4-pro` | `Azure-Resource/DeepSeek-V4-Pro` |

Свидетельство: `H/src/evaluate/agents/opencode.py:18-24,37-40`. Новый `--model internal/foo` и новый provider ID не заработают простым config edit. Не переименовывать другую модель в один из этих alias: это ложная provenance и неверная pricing lookup (`H/src/evaluate/pricing.py:37-54,62-66`).

Пример **только если endpoint действительно обслуживает `DeepSeek-V4-Flash`**: сохранить ожидаемый provider/model ID, заменить transport/secret reference, убрать неиспользуемые providers. `$CONTROL/env/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "Azure-Resource": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Baseline provider",
      "options": {
        "baseURL": "<approved OpenAI Chat Completions base URL>",
        "apiKey": "{env:MODEL_API_KEY}"
      },
      "models": {
        "DeepSeek-V4-Flash": { "name": "DeepSeek-V4-Flash" }
      }
    }
  }
}
```

`opencode.env` содержит только `MODEL_API_KEY=<approved key>`. Не нужен выдуманный Azure resource name для такого custom provider: оставлен provider **identifier**, не Azure transport. Эта форма npm/baseURL/env expansion основана на `H/env/opencode/opencode.json.example:10-29` и [официальной OpenCode provider documentation](https://opencode.ai/docs/providers/#custom-provider). Оригинальный `.env.example` ожидает Azure variables (`H/env/opencode/opencode.env.example:1-2`), но runner проверяет наличие env-file/config, а не имена переменных (`H/src/evaluate/agents/opencode.py:42-60`).

OpenCode image pin = **1.15.5** (`H/docker/go.opencode.Dockerfile:3-8`), config bind target `/tmp/.config/opencode/opencode.json` (`H/src/evaluate/agents/opencode.py:14-16,157-178`). Если provider требует другое backend model name, версия CLI не принимает показанный config или модель не входит в hardmap — **вернуться к design**, не патчить MODEL2NAME и не скрывать remapping. Claude-профиль не выбран: sample требует отдельного Foundry resource/API key и deployments (`H/env/claude/claude.env.example:7-24`); их нет, а Claude не выполняет произвольную OpenAI-модель.

### 3.4 Сеть контейнера

**Решение:** оставить official default bridge, основной путь — напрямую доступный HTTPS API URL. Обе container implementations не передают `--network` (`H/src/evaluate/agents/base.py:50-55`; `H/src/evaluate/agents/opencode.py:157-178`). Проверить DNS/TLS/auth/реальный небольшой model request из **того же** образа и network profile на synthetic non-benchmark source, не на одном из 30 кейсов.

Если API доступен только через существующий одобренный сервис на host:

* на Docker Desktop использовать `http(s)://host.docker.internal:<port>/<base-path>` **для host gateway**, а не пытаться заменить этим именем адрес удалённого недоступного провайдера;
* gateway предоставляет только model API, не file access, benchmark answers, историю диалогов или Izyan reports; отдельный least-privilege credential, bind/firewall policy и gateway version фиксируются;
* проверить listener/VPN route и TLS hostname/CA. Не отключать TLS verification; не считать localhost контейнера localhost хоста.

Основание: [Docker Desktop host connectivity](https://docs.docker.com/desktop/features/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host). **Наименее рискованный host-only вариант:** owner-approved API-only gateway + `host.docker.internal`, без изменения harness и host filesystem mounts.

`--network host` не является существующим flag harness; потребует изменения docker-create logic, а Docker Desktop host networking дополнительно включается явно. Он расширяет network boundary и не решает неподдержанный API автоматически ([Docker host driver](https://docs.docker.com/engine/network/drivers/host/)). **Не выбран.** Запуск агента вне Docker разрушает официальный sandbox contract и увеличивает label leakage surface; **не выбран**. Если owner-approved маршрут недоступен, run остаётся blocked.

---

## 4. Go subset без правки harness

**Решение:** отдельный `$CONTROL` с копией неизменённых harness sources и локальным `benchmark/tasks/vex_bench.jsonl`, содержащим уже готовые 30 Go rows. Запускать все три стадии с **cwd `$CONTROL`** и `--benchmark vex_bench`. Это work-directory data overlay, не новая benchmark registration и не patch official Python code (`H/src/evaluate/common.py:12-14,78-80,105-110`).

Не передавать путь к JSONL в `--benchmark` и не путать evaluation с `download [TASKS.jsonl]`: у evaluation иной interface (`H/README.md:170-190`; `H/src/evaluate/common.py:121-126`). Не менять оригинальный pinned-checkout и не запускать его full task file: иначе будут Java/Python jobs и ошибки отсутствующих snapshots/images.

### 4.1 Переменные и подготовка control-directory

Все path variables — **абсолютные**. `WORKTREE` указывает только на approved shadow worktree, никогда на основной checkout. `BASE` — существующий acquisition root; в текущей установленной территории это `/tmp/vexbench-baseline`. `PLAIN` — отдельный output root на внешнем volume, вне обоих checkout и вне snapshot tree.

```bash
: "${WORKTREE:?absolute path to approved shadow worktree}"
: "${BASE:?absolute existing acquisition root}"
: "${PLAIN:?absolute external Plain Agent output root}"
: "${MODEL:?exact owner-approved model/deployment name}"
PIN=80cddeac3132826bfd47227ad59b2e6618a681bd
HARNESS="$BASE/dataset/vex-bench-$PIN"
REPOS="$BASE/repos"
GO_TASKS="$BASE/go-tasks.jsonl"
CONTROL="$PLAIN/control"
RESULTS="$PLAIN/results"
AGENT=codex

umask 077
mkdir -p "$PLAIN"
# Не использовать существующий CONTROL/RESULTS другого run.
test ! -e "$CONTROL"
test ! -e "$RESULTS"
mkdir -p "$CONTROL/benchmark/tasks" "$CONTROL/env/codex"
cp -R "$HARNESS/src" "$HARNESS/docker" "$CONTROL/"
for file in pyproject.toml uv.lock .python-version README.md; do
  cp "$HARNESS/$file" "$CONTROL/$file"
done
cp "$GO_TASKS" "$CONTROL/benchmark/tasks/vex_bench.jsonl"
cp "$HARNESS/env/codex/config.toml.example" "$CONTROL/env/codex/"
cp "$HARNESS/env/codex/codex.env.example" "$CONTROL/env/codex/"
```

Не копировать весь `$BASE`, acquisition GT/review files, оригинальный `.git`, host config dirs или Baseline 1 results в `$CONTROL`. Для заранее approved OpenCode profile заменить AGENT и создавать только `env/opencode` с соответствующими example files; source-copy contract тот же. `$RESULTS` уникален для experiment: namespace harness не содержит dataset/provider/timeout identity (`H/src/evaluate/common.py:90-98`).

### 4.2 Обязательный offline preflight

До build/paid execution проверить:

- pinned harness files и `uv.lock` соответствуют approved acquisition pin; сохранить file hashes оригинала и control copy;
- Go JSONL SHA256 совпадает с `60b553...384b3`, 30 уникальных task IDs и ровно тот же ID/SHA/CVE набор и порядок, что у A;
- выборка = **все** Go rows pinned full JSONL, не выбор по labels/verdicts; labels supports 7/18/3/2;
- 28 уникальных `(repo_url, commit_sha)` существуют в `$REPOS` с полным SHA, immutable, без `.git`; integrity/content-hash соответствует уже готовому acquisition manifest;
- не запускать `acquire`, `download`, повторные fetch или builds snapshot на host; модель получает container copy (`H/src/evaluate/run.py:28-32`; `H/src/evaluate/agents/base.py:60-67`);
- модельное имя не является абсолютным filesystem path и не содержит `..` path traversal: harness использует его прямо в `Path` namespace, без sanitizer (`H/src/evaluate/common.py:90-98`);
- CONTROL env/config содержит только transport/model profile и necessary secrets. Никаких instructions, plugins, MCP servers, CVE lists, GT/PR URLs или Izyan output mounts;
- перечислить **уже содержащиеся в snapshot** agent instruction/config files как native snapshot exposure; не внедрять host AGENTS/skills/config и не переписывать immutable source ради устранения возможного prompt injection.

Использовать существующий t1 integrity contract (`eval/vexbench_baseline.py:418-456,622-647,949-952`), не вводить новый digest с тем же именем ContentHash. Проверки являются будущим preflight, не повод повторно запускать анализ A.

---

## 5. Docker, Python, диск и бюджеты

### 5.1 Ровно два image, а не полный набор

Для Go/Codex:

1. `vex-bench-go:latest`: `golang:1.26-bookworm`, git/CA/curl, HOME=/tmp (`H/docker/base.go.Dockerfile:1-8`).
2. `vex-bench-go-codex:latest`: Go base + Node 22 + `@openai/codex@0.131.0` (`H/docker/go.codex.Dockerfile:1-8`).

Для approved OpenCode alternative второй image — `vex-bench-go-opencode:latest`, версия 1.15.5; Claude — отдельный profile, не строится (`H/docker/go.opencode.Dockerfile:1-10`; `H/docker/go.claude.Dockerfile:1-8`).

**Материальное расхождение README:** «all nine images» (`H/README.md:97-102`) — не количество tags, создаваемых текущим script. `LANGS=(go python java)` × (один base + три agent) = **12** images: 3 base + 9 agent (`H/docker/build.sh:17-18,23-43`). `build.sh go` даёт 4; `build.sh go codex` — только нужные **2**. Не строить остальные языки/агенты и не оценивать диск как 12 независимых копий base layers.

Будущие команды, после resource/access approvals:

```bash
cd "$CONTROL"
uv sync --locked --python 3.12 --no-dev
./docker/build.sh go "$AGENT"
```

`uv sync` — официальный setup (`H/README.md:80-89`); Python 3.12 нужен независимо от host Python 3.9 (`H/pyproject.toml:6`; `H/.python-version:1`). `--locked` не обновляет lockfile при несовпадении, а завершает с ошибкой; дальнейший `uv run --locked --no-sync` использует подготовленное окружение ([uv sync semantics](https://docs.astral.sh/uv/concepts/projects/sync/)). Не выполнять `uv lock --upgrade` ради исправления setup. Для install/build нужны сеть к Python/package/container registries, apt/NodeSource/npm: это видно по dependencies и RUN commands (`H/pyproject.toml:7-17`; `H/docker/base.go.Dockerfile:3-5`; `H/docker/go.codex.Dockerfile:3-6`).

### 5.2 Диск

**[INFERENCE], cold Go/Codex profile:** два image с shared layers ~2–4 GB, дополнительный build cache ~2–6 GiB, Python env/cache ~0.5–2 GiB. One-container transient writable layer с копией snapshot, module/build downloads может занимать ~2–10 GiB или больше; raw 90 trajectories/debug logs резервировать 1–5 GiB. Это оценки, не измеренные sizes готовых images. Снапшоты уже скачаны; повторно 28 деревьев не копируются на host. Disposable layer удаляется после задачи, но image/build cache сохраняется (`H/src/evaluate/agents/base.py:39-44,93-96`).

**Решение resource gate:** ≥25 GiB свободно на filesystem Docker data/disk-image и ≥10 GiB на output volume; когда это один volume — ≥35 GiB общего резерва, с учётом уже занятых snapshots/cache. Это плановый резерв, не гарантия: official runner не задаёт RAM/disk/container limits (`H/src/evaluate/agents/base.py:50-55`). Параллелизм 1 ограничивает concurrent layers, не build size каждой команды.

До build/run записать:

```bash
docker system df -v
docker info --format '{{.DockerRootDir}}'
df -h "$PLAIN" "$REPOS"
```

В Docker Desktop дополнительно записать disk-image location/maximum/free space. `.DockerRootDir` — путь **в Linux VM**, не доказательство, что image cache живёт на внешнем `$PLAIN`. `--output-dir` переносит results, **не Docker storage** (`H/src/evaluate/common.py:33-34,90-98`). Если Docker disk image нужно переносить, это отдельное согласованное действие владельца до build, не часть silently running harness.

Наблюдённые 1.45 GB images + 2.13 GB cache и 51 GiB host free позволяют рассматривать профиль как реалистичный, но не заменяют эти gates. Не выполнять `docker system prune`, не удалять чужие images/cache или frozen A. При low disk остановить admission оплачиваемой работы и записать partial outcome, не скрывать ENOSPC как uncertain и не делать невидимый retry.

### 5.3 Время и деньги, три repeat

**Решение:** фиксированный `--timeout 600`, `--repeats 3`, `--parallel 1` на 30 Go cases. Это 90 attempts, а не majority vote/выбор лучшего repeat (`H/src/evaluate/run.py:87-90`; спека §27).

**[INFERENCE]:** cold install/build ~10–40 min при нормальной сети; actual время не измерено, registries/VPN могут блокировать подготовку. Run reserve — до суток. Если средний agent wait 5–10 min, 90 attempts дают 7.5–15 h. `90 × 600 = 15 h` — верхняя сумма именно Codex `docker start -a` waits, **не строгая граница всего harness**: create/cp/cleanup не имеют этого timeout (`H/src/evaluate/agents/base.py:57-96`). OpenCode имеет внутренний `timeout 600s` и внешний guard `600+120s`, поэтому потолок внешних start waits 18 h плюс прочая работа (`H/src/evaluate/agents/opencode.py:186-200,222-247`).

Стоимость считать по disjoint buckets:

```
C = (fresh_input * p_input + cache_read * p_read
     + cache_write * p_write + (output + reasoning) * p_output) / 1e6
```

Источник: `H/src/evaluate/agents/base.py:147-167`; `H/src/evaluate/pricing.py:57-88`. Для **условного** GPT-5.5 official table: $5 fresh input / $0.50 cache read / $5 cache write / $30 output+reasoning за 1M (`H/src/evaluate/pricing.py:37-46`). При 100k uncached input + 10k output/reasoning на attempt: $0.80 ×90 = **$72**; при 1M input +50k output/reasoning: $6.50 ×90 = **$585**. Обе token envelopes — **[INFERENCE]**, не quotation и не cap. Внутренний тариф может отличаться; owner-approved budget обязателен.

Synthetic paid preflight имеет отдельный заранее одобренный cap, не использует benchmark CVE и не входит в 90 attempts. Unknown pricing нельзя выдавать за $0; missing/timeout trajectories могут всё равно быть billed (`H/README.md:137-140`; `H/src/evaluate/pricing.py:14-16,62-77`; `H/src/evaluate/metrics.py:270-284`). При provider-side cap exhaustion остановить/зафиксировать incomplete run и limitations; не уменьшать число повторов и не брать более дешёвую модель без нового design.

---

## 6. Provenance и execution в dependency order

### Шаг 1. Freeze inputs/profile до paid run

- [ ] Закрыть owner gates §2; зафиксировать AGENT/MODEL/backend revision/effort/API route/timeout/repeats/parallel/tariffs/budget.
- [ ] Выполнить offline preflight §4.2, resource gate §5.2, подготовку environment/images §5.1.
- [ ] Провести synthetic endpoint/CLI preflight в том же image/default bridge, без snapshots/tasks/GT/A reports. Проверить DNS/TLS/auth и один небольшой model/tool-compatible response. Не запускать benchmark как DNS probe.
- [ ] Создать приватный `$PLAIN/provenance.json` до первого attempt: dataset/harness pin; full/subset/source/lock/config hashes; acquisition reference и 28 snapshot hashes; prompt name/hash; model CLI alias, backend name/revision/effort; agent и фактическая container CLI version; Docker client/server/OS/arch; image identity; effective flags; UTC; approved budget/pricing; isolation/network/exposure policy. Credential **values** не записывать; сохранять имена env variables и redacted config.
- [ ] Присвоить уникальный logical run ID, использовать новый RESULTS. После synthetic setup не менять image tag/config/profile до конца 90 attempts.

Capture image/CLI evidence (будущие команды):

```bash
docker image inspect vex-bench-go:latest \
  --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}}'
docker image inspect "vex-bench-go-$AGENT:latest" \
  --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}}'
docker run --rm --entrypoint "$AGENT" "vex-bench-go-$AGENT:latest" --version
docker run --rm --entrypoint go vex-bench-go:latest version
```

Для locally built image `.RepoDigests` может быть пуст: обязательная воспроизводимая Docker identity — **`.Id` (sha256 content ID)**; registry digest сохраняется, если есть. Не выдумывать repo digest. Сохранить Dockerfiles/base image identity/build log: `golang:1.26-bookworm` и apt/NodeSource contents mutable, хотя CLI package version pinned (`H/docker/base.go.Dockerfile:1-5`; `H/docker/go.codex.Dockerfile:3-6`). Фактическая Go patch version/architecture измеряется, не выводится из tag и не приравнивается к native Go 1.26.1 у A.

### Шаг 2. Run — ровно первый attempt каждого pair

**Решение:** три команды ниже имеют один и тот же полный набор experiment flags. Timeout 600 не менять по CVE. Полный stdout/stderr сохраняется на private control plane. Внешний lifecycle observer нужен для time metric: official parsed rows не содержат wall duration (`H/src/evaluate/parse.py:61-104`; `H/src/evaluate/agents/base.py:147-167`).

До run включить filtered Docker events в отдельном процессе, после synthetic preflight. На время baseline не запускать другие containers того же image; иначе порядок нельзя достоверно связать с task/repeat. JSON events дают create/start/die/destroy и daemon nanosecond timestamps; [Docker events reference](https://docs.docker.com/reference/cli/docker/system/events/) описывает filters и ограничение history до 256, поэтому **live capture**, не только post-hoc history.

```bash
cd "$CONTROL"
START_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
docker events --since "$START_UTC" \
  --filter type=container --filter "image=vex-bench-go-$AGENT:latest" \
  --format '{{json .}}' > "$PLAIN/docker-events.jsonl" &
EVENTS_PID=$!

# Не терять exit code при выводе через pipeline.
set +e
/usr/bin/time -p uv run --locked --no-sync vex-bench evaluate run \
  --agent "$AGENT" --model "$MODEL" \
  --benchmark vex_bench --prompt vuln \
  --repeats 3 --timeout 600 --parallel 1 \
  --repos-dir "$REPOS" --output-dir "$RESULTS" \
  > "$PLAIN/run.log" 2>&1
RUN_EXIT=$?
set -e
printf '%s\n' "$RUN_EXIT" > "$PLAIN/run.exit-code"
kill -INT "$EVENTS_PID"
wait "$EVENTS_PID" || true
```

- [ ] Получить 90 `[RUN]` attempts/terminal records, либо явно объявить run incomplete. Process exit 0/progress 90/90 не доказывает 90 valid answers: per-job errors логируются и runner продолжает (`H/src/evaluate/run.py:54-58,90-102`).
- [ ] Сопоставить `[task/run_00N] [RUN]` log windows с последовательными container lifecycle IDs. При `parallel=1` и отсутствии других matching containers сохранять runtime window create→destroy (copy/cleanup included), отдельно start→die и total orchestration real time. Failed docker-create без container event получает observed log-boundary timing либо N/A с причиной, не 600 «по умолчанию».
- [ ] Сохранить error.txt/debug artifacts и raw files; зафиксировать raw checksums/UTC freeze **до любого повторного run**.

**Timeout policy:** `TimeoutExpired` → RuntimeError → `error.txt`; raw result обычно не пишется, parse даст no_result, metrics считает failure. Captured tails ограничены; это не полноценная сохранённая траектория (`H/src/evaluate/agents/base.py:70-92,131-133`; `H/src/evaluate/run.py:54-62`; `H/src/evaluate/parse.py:79-85`). OpenCode внутренний timeout останавливает script до session export (`H/src/evaluate/agents/opencode.py:232-247`), debug artifacts могут сохраниться (`H/src/evaluate/agents/opencode.py:346-357`). Не «спасать» partial reasoning как safe/uncertain answer для основного baseline.

**Resume limitation:** не запускать повторно ту же run command для улучшения completion. Harness повторит failed/unparseable attempts и может стереть error.txt; cache не проверяет `RunStats.completed` (`H/src/evaluate/run.py:34-42,54-63`; `H/src/evaluate/agents/codex.py:105-127`). При host interruption сохранить partial namespace. Если решено дозапустить **не начатые** pairs, сначала отдельный design для attempt-preserving admission: не требовать от штатного harness несуществующий безопасный resume selector. Повторение полного эксперимента допустимо лишь как **новый named run** в новом RESULTS с новой provenance; не заменяет ошибки первого.

### Шаг 3. Parse и metrics — offline, те же flags/cwd

```bash
cd "$CONTROL"
uv run --locked --no-sync vex-bench evaluate parse \
  --agent "$AGENT" --model "$MODEL" \
  --benchmark vex_bench --prompt vuln \
  --repeats 3 --timeout 600 --parallel 1 \
  --repos-dir "$REPOS" --output-dir "$RESULTS" \
  > "$PLAIN/parse.log" 2>&1

uv run --locked --no-sync vex-bench evaluate metrics \
  --agent "$AGENT" --model "$MODEL" \
  --benchmark vex_bench --prompt vuln \
  --repeats 3 --timeout 600 --parallel 1 \
  --repos-dir "$REPOS" --output-dir "$RESULTS" \
  > "$PLAIN/metrics.log" 2>&1
```

Parse/metrics не вызывают provider: читают saved results (`H/src/evaluate/parse.py:27-53,79-104`; `H/src/evaluate/metrics.py:55-82`). Provider config всё равно не публиковать. Перед этими стадиями не менять task file/repeats/model/profile; ни benchmark name, ни prompt hash не идентифицируют filtered task digest сами по себе (`H/src/evaluate/common.py:20-22,90-98`).

Фактические артефакты:

```
$RESULTS/<prompt_hash>/prompt.txt
$RESULTS/<prompt_hash>/$AGENT/$MODEL/<task_id>/run_001/{result.jsonl,error.txt}
$RESULTS/<prompt_hash>/$AGENT/$MODEL/<task_id>/run_002/...
$RESULTS/<prompt_hash>/$AGENT/$MODEL/<task_id>/run_003/...
$RESULTS/<prompt_hash>/$AGENT/$MODEL/vex_bench/parsed.jsonl
$RESULTS/<prompt_hash>/$AGENT/$MODEL/vex_bench/metrics.json
```

`prompt_hash` = первые 12 hex SHA256 **template**, не rendered CVE prompt (`H/src/evaluate/common.py:16-22,82-98`). Codex raw = `result.jsonl` (`H/src/evaluate/agents/codex.py:63-64`); OpenCode = `result.json`, дополнительные diagnostics в `artifacts/` (`H/src/evaluate/agents/opencode.py:64-65,346-357`). Не требовать artifacts directory от Codex: его run не передаёт artifacts capture в base runner (`H/src/evaluate/agents/codex.py:41-59`).

Получить experiment path без догадки о hash:

```bash
PROMPT_HASH=$(uv run --locked --no-sync python -c \
  'from evaluate.prompts import PROMPTS; import hashlib; print(hashlib.sha256(PROMPTS["vuln"].encode()).hexdigest()[:12])')
EXP="$RESULTS/$PROMPT_HASH/$AGENT/$MODEL"
```

- [ ] parsed.jsonl содержит **90 уникальных** `(task_id,run_id)` rows, по 30 на run_001/002/003, одинаковые GT supports для каждого; официальный metrics `n_runs=3`, completion.total=90 (`H/src/evaluate/parse.py:42-53`; `H/src/evaluate/metrics.py:30-52,233-243`).
- [ ] Сохранить official metrics unchanged, checksums raw/parsed/metrics/logs/events, finished UTC, actual attempts/failures/usage/billing coverage. Failed counts входят в метрики, не фильтруются перед summary.

---

## 7. Одинаковые метрики для A и B, разные названные policy projections

### 7.1 Основная safety-aware projection для Plain Agent

Не считать false_safe по `parsed.predicted == not_exploitable`: оно уже включает uncertain (`H/src/evaluate/parse.py:98-104`; `H/src/evaluate/result_parser.py:90-99`). Читать **predicted_category** и **status**.

Для каждого из 30 rows одного repeat:

| Input | Safety outcome |
|---|---|
| status != ok / отсутствующая valid category | failed |
| category = vulnerable | positive |
| category = uncertain | abstain / INCONCLUSIVE |
| любая из остальных десяти valid categories | safe claim |

Valid set — `H/src/evaluate/result_parser.py:6-22`. Это **scoring projection**, не добавление Izyan verification к Plain Agent: safe claim не становится VERIFIED falsifier. Assertion strength остаётся разной и называется в report.

Считать на **фиксированных знаменателях 30/7/23**:

```
FalseSafe_count = #(GT exploitable AND safety outcome safe)
FalseSafe_rate  = FalseSafe_count / 7
SafeClearRate  = #(GT non-exploitable AND safety outcome safe) / 23
Recall         = #(GT exploitable AND safety outcome positive) / 7
INCONCLUSIVE   = #abstain / 30
Completion     = #(valid parseable answers) / 30
TP             = #(GT exploitable AND positive)
FP             = #(GT non-exploitable AND positive)
FN             = 7 - TP                     # includes safe, abstain, failed
Precision      = TP/(TP+FP), or 0 if denominator is zero
Status_F1      = 2*Precision*Recall/(Precision+Recall), or 0
```

Parity sources: spec §7/§11–13/§41; `eval/vexbench_baseline.py:1509-1522,1604-1665`. INCONCLUSIVE и failed раздельные счётчики; не включать abstention в FalseSafe, correct_safe или Completion failure. Дополнительно сохранить confusion table с prediction rows positive/safe/abstain/failed × GT positive/negative, status_correct и `(status_correct AND category_correct)` reason_correct.

Repeat aggregation: три per-repeat vectors; для каждой quality metric `mean` и `statistics.stdev` (ddof=1), raw values отдельно. FalseSafe сообщать как `counts [x1,x2,x3], mean±std, total across 90 attempts`; дополнительно unique case IDs с false_safe хотя бы в одном repeat. Pooled ratio для 90 rows можно добавить как secondary, не выдавать pooled F1 или majority vote за official repeat mean. Три repeat — не три независимых датасета и не доказательство статистической значимости (spec §27; `H/src/evaluate/metrics.py:287-304`).

### 7.2 Отдельная compatibility projection

Официальный metrics.json остаётся **VEX-Bench compatibility metrics**. Для A использовать только frozen compatibility-metrics.json; B — official binary/multiclass scalars. Обе стороны: vulnerable→positive, все остальные valid categories, **включая uncertain**, →negative; missing/failed→FAILED, не successful negative (`external-baseline-1.md:65-81`; `eval/vexbench_baseline.py:1679-1725`; `H/src/evaluate/result_parser.py:90-107`; `H/src/evaluate/metrics.py:88-120`).

Justification macro-F1 — среднее per-class F1 только по **четырём GT-present classes** 7/18/3/2, не среднее по 12 taxonomy labels. Class-miss/failed учитывается как FN; category choice вне GT-present set не удаляется (`H/src/evaluate/metrics.py:123-169`; `eval/vexbench_baseline.py:1694-1725`).

Материальная особенность official confusion counts: `binary.totals.fn` суммирует только cell exploitable→not_exploitable, **не** cell exploitable→FAILED; scalar recall через sklearn учитывает оба (`H/src/evaluate/metrics.py:95-119,188-194`). Поэтому не пересчитывать recall как TP/(TP+official totals.fn) при failures. Offline report содержит missing-positive cell и раскрывает этот count/scalar distinction.

**Где явно назвать расхождение:** раздел `Metric policies and limitations` итогового report, caption comparison table, provenance `scoring_policy` и отдельные filenames `official metrics.json` / `safety-metrics.json`. Показать для обоих режимов два столбца про uncertain: `official compatibility negative` и `safety abstain`. Не прятать policy note в appendix и не интерпретировать compatibility accuracy как safety.

### 7.3 Offline reporter и §43 comparison

**Планируемый interface**, сначала реализовать/test fixtures, затем использовать:

```bash
python3 "$WORKTREE/eval/vexbench_plain_report.py" \
  --parsed "$EXP/vex_bench/parsed.jsonl" \
  --official-metrics "$EXP/vex_bench/metrics.json" \
  --raw-root "$EXP" \
  --baseline-dir "$BASE/runs/external-baseline-1" \
  --run-log "$PLAIN/run.log" \
  --docker-events "$PLAIN/docker-events.jsonl" \
  --provenance "$PLAIN/provenance.json" \
  --out "$PLAIN/report"
```

Outputs: safety-cases.jsonl (90 rows), safety-metrics.json (per-repeat + aggregate), telemetry.json with coverage, comparison.md, freeze-checksums.json. Baseline-dir read-only: брать pinned scoring/cases.jsonl и frozen metrics, не запускать A report/validate-review и не переписывать его taxonomy. Для pairing выводить A verdict/outcome vs B predicted_category/outcome по task ID для каждого repeat; не выбирать лучший B answer на кейс.

§43 report table:

| Metric | Current Izyan — frozen A | Plain Agent B | Shadow Agent | Hybrid |
|---|---:|---:|---:|---:|
| False-Safe | 1; rate 1/7 | per-repeat counts, mean±std, total/unique IDs | not run | not run |
| Safe Clear Rate | 10/23 = 43.5% | mean±std, denominator 23/repeat | not run | not run |
| Exploitable Recall | 2/7 = 28.6% | mean±std, denominator 7/repeat | not run | not run |
| INCONCLUSIVE | 12/30 = 40.0% | uncertain/30, mean±std | not run | not run |
| Status F1 | 0.333333 | safety positive F1, mean±std | not run | not run |
| Justification macro-F1 | 0.225845 | official four-class macro-F1, mean±std | not run | not run |
| Completion | 28/30 = 93.3% | answered/30 ×3, mean±std; answered/90 | not run | not run |
| Avg tool calls | frozen recorded counters + coverage | actual tool events, not steps; coverage | not run | not run |
| Avg tokens | N/A, deterministic profile | five disjoint buckets + measured coverage | not run | not run |
| Avg time | frozen recorded per-case wall + coverage | observed container wall + coverage | not run | not run |
| Avg cost | model API cost $0; excludes compute | provider estimate/invoice + coverage | not run | not run |

Source A: `external-baseline-1.md:35-81`; frozen `$BASE/runs/external-baseline-1/metrics.json` contains Status F1 0.333333, tool_calls=6, recorded wall mean 429.243 s over 28 predictions; cost/token caveats не переписывают A. Supplemental table может читать эти артефакты, но A файлы остаются unchanged. Не изображать single deterministic run как mean±std из трёх искусственно дублированных A rows.

Telemetry rules:

* `steps` не равен tools: Codex считает agent messages, command_execution и web_search в одной сумме (`H/src/evaluate/agents/codex.py:72-100`); OpenCode steps = model turns (`H/src/evaluate/agents/opencode.py:75-89,274-304`). Для Codex offline считать observed tool-type item.completed из raw, отдельно command_execution/web_search и other item-type coverage. Не объявлять все items tools; unknown event types = limitation, не ноль.
* Tokens = input + cached_input + cache_write + output + reasoning после disjoint normalization (`H/src/evaluate/agents/base.py:147-167`; `H/src/evaluate/agents/codex.py:77-100`). Сохранить отдельно LLM/tool event definitions; различие instrumentation A/B ограничивает efficiency comparison.
* Official token/cost std — case-level по measured/priced rows, **не** variation трёх repeat means (`H/src/evaluate/metrics.py:247-284`). Reporter дополнительно считает per-repeat mean с coverage, затем mean±std по трём repeat means. Missing usage/time/price не заменяется нулём.
* Time window для B create→destroy включает source copy/cleanup, A wall envelope имеет иной execution boundary. В таблице назвать обе границы; отдельно дать total elapsed B и observed attempts. Не объявлять такую time comparison apples-to-apples CPU benchmark.
* Failures/timeouts могут иметь billing без token stats. Official estimated total — только priced coverage; invoice/usage-export включать отдельно. Для отсутствующего тарифа/счётчика ячейка `N/A — reason, coverage` является честно заполненной, не fake value. Это не разрешение пропустить получение доступной telemetry.

Fixtures reporter проверяют uncertain на vulnerable GT (**не false-safe**), explicit safe на vulnerable GT (**false-safe**), uncertain на negative GT (**не correct_safe**), failed positive (FN), invalid category, одинаковые 30-ID sets ×3, различие pooled vs mean F1, ddof=1, missing tokens/prices и boundary coverage. Scoring logic не зависит от названий конкретных CVE/repositories.

---

## 8. Leakage, exposure и честность

**Установленная гарантия уже:** runner подставляет CVE в фиксированный prompt и копирует только snapshot, без task JSONL/GT/metadata.pr_url; config — единственный extra bind mount (`H/src/evaluate/run.py:45-52`; `H/src/evaluate/agents/base.py:50-67`; `H/src/evaluate/agents/codex.py:17-59`). OpenCode копирует также rendered prompt.txt, не labels (`H/src/evaluate/agents/opencode.py:144-149,181-183`). Original/download source tree и results не монтируются.

**Ограничение:** это filesystem isolation, не полный anti-leakage firewall. Container имеет исходящую сеть; agent может самостоятельно найти public CVE/upstream PR, а public benchmark labels теоретически доступны online. Original prompt содержит classification rules и unrelated example; «только CVE+snapshot» означает отсутствие case-specific labels/reference answers, а не отсутствие official prompt/toolchain/provider configuration (`H/src/evaluate/prompts.py:1-106`; spec §15–16). Не заявлять, что official harness сам блокирует public label retrieval.

До run зафиксировать explicit allowlist: snapshot `/work`, official prompt, минимальный provider config + credential env, image toolchain. Не монтировать `$BASE`, `$CONTROL`, `$RESULTS`, A results, worktree, host HOME, Git history, Docker socket; не давать MCP/tools, читающие control files. Не менять labels, не передавать `metadata.pr_url`, advisories/reference answers из review packet; public research найденное самим agent допустимо (spec §15–16/§18). Credentials необходимы в container environment, поэтому read-only config **не** означает, что агент не способен прочитать ключ: trajectory/logs private, перед publication обязательный secret review.

После freeze offline просмотреть trajectories на benchmark JSONL/reference-answer URLs и необоснованное воспроизведение GT. При evidence leakage — flag affected repeats и limitations; не «исправлять» answer. Если exposure invalidates baseline, new design/new named run, исходный результат сохраняется.

`prior_exposure` обязан включать:

1. Все 30 случаев уже оценены в Baseline 1; taxonomy/disagreement review 23/23 выполнен, текущие планировщики видели его результаты.
2. Предшествующие четыре smoke cases и подготовительный Kubernetes case из A report (`external-baseline-1.md:98-105`).
3. Synthetic setup preflight не использует один из 30 tasks; если benchmark smoke всё-таки одобрен отдельно, task/repeat/date/result отмечается и не подмешивается в first-attempt B baseline.
4. Fresh official-agent session **не получает** это обсуждение, A reports или reviewer conclusions. Это снижает conversational leakage, но не возвращает набору статус unseen.

Называть результат **architectural comparison на exposed external regression benchmark**, не новой independent unseen validation. Для итоговых claims понадобится новый holdout (spec §49). Не делать улучшения prompt/config на основании конкретных outcomes в ходе 90 attempts.

---

## 9. Blast radius и что коммитить

В этом задании — **только** `docs/dev/plans/2026-10-08-vexbench-plain-agent-plan.md`; commit `docs(eval): plan VEX-Bench plain-agent baseline (Task 3)` в выделенном worktree. Нет изменений AGENTS/spec/A report/production code.

При последующем исполнении Task 3 минимально affected:

* `eval/vexbench_plain_report.py` и fixture tests — offline scoring/telemetry, без model API/runner;
* `eval/README.md` — процедура и semantics двух projections;
* новый sanitised summary `eval/baselines/vexbench/plain-agent-baseline-1.md` с §43 table/provenance/limitations;
* временные private `$PLAIN/control`, `$PLAIN/results`, `$PLAIN/report`, env/config/logs/events и Docker image/cache вне Git.

Замороженный `external-baseline-1.md`, его raw/metrics/taxonomy и acquisition snapshots остаются read-only. Основной checkout не трогается. Report-helper tests используют synthetic fixtures, не копии секретных configs или raw benchmark traces.

Не коммитить: credentials/config без `.example`, internal provider names/URLs/private paths, snapshots/`.git`, dataset JSONL/GT/review files, raw result.jsonl/result.json, parsed.jsonl/official metrics с case content, debug artifacts, logs, invoice exports, env/cache, Docker tar layers. Official credential/output ignores — `H/.gitignore:12-25`; project privacy — `AGENTS.md:22-23`, `CONTRIBUTING.md:25`. Обязательные parsed.jsonl/metrics.json **сохраняются** во внешнем audit packet с SHA256; это не требование положить их в Git. В Git — summary, redacted provenance и hashes/логические artifact names. План после принятого Task 3 удаляется по `docs/dev/plans/README.md:5-10`.

---

## 10. Acceptance Task 3 и validation order

Критерии будущего benchmark, не заявление текущего выполнения:

- [ ] Owner endpoint/key/model/budget gates закрыты документированным synthetic preflight; model identity для B/C одобрена до первого attempt.
- [ ] Go subset совпадает с A по SHA256/30 IDs/full SHAs/CVEs; 28 snapshots не скачивались заново и не изменены. Official harness sources/prompt не патчены.
- [ ] Собраны только Go base + выбранный Go-agent image, container CLI version и Docker `.Id` sha256 записаны; registry digest сохранён если доступен; Go/Python/Docker versions/OS/arch и фактическая UTC дата присутствуют.
- [ ] Зафиксирована provenance: harness pin, full/subset/prompt/source/lock hashes, agent, exact CLI model и backend revision/effort, image identity, effective flags/network, tariff/budget, exposure и attempt policy. Secret values отсутствуют в публикуемом provenance.
- [ ] Запланированы **30 ×3=90** pairs и выполнен первый attempt каждого. Отдельно указаны scheduled / attempted / terminal / parseable counts, а не только process exit. При не начатых pairs статус **incomplete**, не done.
- [ ] `parsed.jsonl` сохранён и содержит 90 уникальных rows, run_001/002/003 по 30. `metrics.json` сохранён, `n_runs=3`, `completion.total=90`; completion **N/30 для каждого repeat** и N/90 суммарно. Цель — 90 valid answers, но любые реальные failures/timeout не удаляются ради 100% completion.
- [ ] Error.txt, original raw/partial diagnostics, live Docker events/run log и checksums сохранены. Все timeouts/parse_fail/no_result/no_dir и ограничения capture объяснены; нет outcome-driven retries/hidden overwrite.
- [ ] Official compatibility metrics неизменны; offline safety metrics проверяют uncertain отдельно от safe, знаменатели 30/7/23, mean±sample std по трём repeat. Показаны explicit false_safe case IDs и repeat counts.
- [ ] Table §43 заполнена для A и B: primary safety + отдельная official compatibility table; tools/tokens/time/cost с definitions/coverage и обоснованным N/A только где реально отсутствует telemetry. C/D помечены not run, не заполняются выдуманными результатами.
- [ ] Baseline 1 frozen summary/raw/metrics/GT/taxonomy unchanged; exposed/regression interpretation названа, свежие unseen claims не сделаны.
- [ ] Опубликован sanitised summary с raw artifact hashes и limitations: provider/API availability, revision pinning, network/public research leakage risk, failures, cost coverage, different agent/runtime/telemetry boundaries. «Не получилось» перечисляется по фактической причине, не сглаживается метриками.

Validation исполнителя в dependency order: offline reporter fixture tests → identity/resource/synthetic provider preflight → единственный baseline run → parse → official metrics → offline join/coverage/mean±std checks → secret/leakage review и summary. Не запускать модель повторно для проверки метрик. На этапе **этого документационного задания** paid run/build/checks не выполняются.

---

## 11. Условия возврата к design и контракт передачи

Остановить execution, сохранить безопасное partial state, если:

1. endpoint недоступен из default-bridge container, требует host networking, privileged mounts, TLS bypass или protocol translation вместо approved API-only route;
2. требуются правки official harness для Go subset, model mapping, timeout/cache policy или parser; approved cwd data-overlay не работает;
3. model/backend/revision/effort нельзя сопоставить с будущим Shadow Agent, provider делает silent model substitution или candidate не поддерживает Responses/tools;
4. расходы/квота/время/VM space недостаточны для 90 attempts; не уменьшать tasks/repeats и не менять модель молча;
5. snapshots/subset/prompt/source hash отличаются от frozen identity, появилось `.git`/GT/result exposure или model/session получил A reports;
6. run был прерван и штатный повторный `evaluate run` перезапишет first-attempt failures; нужен новый attempt-preserving admission design, не naive resume;
7. lifecycle/log/trajectory schema не позволяет получить требуемые time/tool observations, а заполнение §43 стало бы выдумыванием; определить честную измеримую boundary/coverage до новых attempts;
8. offline scoring обнаруживает drift official policies или A compatibility semantics; не исправлять A, показать discrepancy и пересогласовать comparison design.

**Контракт передачи исполнителю:** соблюдать решения, допущения и ограничители. Если новый факт меняет inputs/contracts/security/component boundaries или опровергает P1-допущение, остановить оплачиваемую работу, записать факт+file:line/measurement, затронутое решение, выполненные attempts и безопасное состояние OUT; вернуть на `design-unknowns`. Не исправлять расхождение скрытым patch, case-specific config или заменой модели. Локальные механические изменения, не затрагивающие этот контракт, записывать в deviation log.
