# Task 4 — Codex cohorts: partial state (frozen as-is)

Стоп по решению пользователя 2026-10-09: ждать полного прогона Codex не нужно,
в отчёте для Task 5 достаточно Qwen-данных. Прогоны остановлены на частичном
объёме; **результаты не переписываются задним числом** и в дальнейшем трактуются
как частичные (не как завершённый cohort).

## Что успело собраться

| Cohort | Agent | Prompt | Attempts (result.jsonl) | FAILED (error.txt) | Last progress |
|---|---|---|---:|---:|---|
| `results/task4-c1/c1-full` | `codex-c1` (Codex + MCP izyan) | `vuln_c1` | **6 / 90** | 0 | 6/90 |
| `results/task4-c1/b1p-full` | `codex-b1p` (Codex, без MCP) | `vuln_assess` | **8 / 90** | 0 | 8/90 |

Все собранные attempts завершились штатно (`turn.completed`); `error.txt` нет.

## Зафиксированные условия

- Модель: `gpt-6.1-sol`, reasoning effort `medium`; provider — localproxy (`wire_api=responses`).
- Attempt policy: `timeout=900s`, `repeats=3`, `parallel=1`, `retries=0`, cache admission forbidden.
- Harness: `/tmp/vexbench-agent-ctl` @ `c71f512a3304d1a0d0d9f5e19e8dbc06e9f1dc93` (clean tree);
  patch `eval/c1/harness/vexbench-agent-ctl-c1.patch`, sanitized patch sha256 `7c47f5c39b94b862cfc576f32540400a3001b64740d81667ba5dbc84c05b0840` (original execution pin retained privately; no rerun implied).
- izyan worktree commit на момент фриза манифеста: `0a9b404a…`.
- Frozen manifest: `eval/c1/freeze/manifest.json`.

## Отклонения, которые нельзя скрывать

1. **Timeout harness-дефект (2026-10-08).** `run_in_container` использовал
   `subprocess.run(..., timeout=)`, который при объёмном stdout `docker start -a`
   не завершался: контейнер держал pipe, прогон висел часами, `--timeout` не
   действовал (первый C1-прогон встал на 20/90). Исправлено kill-watchdog'ом;
   синтетический timeout-guard усилен (теперь контейнер «шумный»).
   **Один attempt из первого (отброшенного) прогона отработал 45 мин при
   `timeout=900` до исправления** — это прямое подтверждение дефекта.
2. Первый C1-прогон дополнительно пострадал от `at capacity` провайдера
   (сохранён как `results/task4-c1/c1-full-capacity-contaminated`, 37 attempts —
   **не использовать** как evidence).
3. Попытка `results/task4-c1/c1-full-timeout-bug` (20 attempts) — артефакт
   дефекта timeout; **не использовать** как evidence.

## Статус для Task 5

Codex-плечи (B1' = P0-подобный plain, C1 = T1-подобный tools) **не завершены**
и не являются валидным matched-сравнением. Task 5 §5.0 требует либо завершить
их на исправленном harness с фиксированным protocol, либо явно обозначить
сравнение как незавершённое. Основной вход Task 5 — Qwen-плечи
(`eval/baselines/vexbench/task4-qwen-plain-vs-tools.md`).
