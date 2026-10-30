# A1 — Security boundary check (agent7, PR-0)

Checkable precondition list the A2 runtime must satisfy before any agent
run. Derived from the evidence pack §4 audit and the spec §2/§8 trust
boundary.

## Threat model (explicit)

- The attempt container sees **only the product snapshot** (plus its own
  run output dir). The izyan repo, `eval/ground-truth*`, `eval/corpus*`,
  `benchmark/tasks/*.jsonl` and every other GT carrier are **never
  mounted** into the agent container.
- `gt_paths_denied` in `manifest.json` is therefore **not** the isolation
  boundary — it is the *policy list the future tool broker must enforce
  inside the sandbox* (belt-and-suspenders over the mount policy). Its
  matcher is a normalized, case-folded string policy check; symlink
  canonicalization is `internal/readgate`'s job (`readgate.go:26` `New`
  canonicalises roots via `EvalSymlinks`+`Abs`, `readgate.go:51`
  `EvalSymlinks` on the target, `readgate.go:47` fail-closed `Check`).
- `eval/products/**` and `eval/advisories/**` are **analysis inputs, not
  ground truth**: product source and public OSV advisory records are
  legitimately agent-visible and are deliberately *not* in
  `gt_paths_denied`. GT carriers are label stores (`expect[]`,
  `ground_truth*`, reference PR pointers, tasks JSONL) — those are denied.
- Smoke selection reads GT classes **host-side only**: the controller
  picks 2 safe + 2 exploitable + 1 forced infra failure; only the task id
  and the four allowlisted identity keys reach the agent.
- `freeze_status: protocol_frozen` + `run_gate`: prompt bytes, the ≤5 R1
  tool subset, the holdout manifest and checkpoint sign-offs are authored
  in later tasks (A2/A4/A9) and are enforced **arm-scoped** by
  `CheckRunGateForArm` / `CheckRunGateForBlindArm` — each arm's gate is
  CLOSED until *its own* pins are supplied (A2 `B1`/`R0` gate on
  `prompts.arm_prompts` + sign-offs); the E6 sandbox report is pinned
  (§8: PASS, 2026-10-11) and `CheckRunGate` remains the strict
  superset over every requirement for the full matrix.

Each item below is marked:
explicitly accepted DOCUMENTED-ONLY risk.

## 1. Capability policy

| # | Precondition | Status | Evidence |
|---|---|---|---|
| 1.1 | Sandbox denies shell/process execution by default | ENFORCED-IN-CODE (for the izyan evidence-tools path) | `internal/evidencetools/exec.go:32-35` — `runSubprocess` returns UNSUPPORTED unless `AllowExec`; default off (`cmd/izyan-evidence-tools/main.go:46`) |
| 1.2 | Sandbox denies execution of the analyzed product | DOCUMENTED-ONLY | Policy in manifest `tool_exposure`; exec gate above covers `run_build`/`run_tests`, but nothing yet stops a coding-agent runtime from running the product binary inside its container — A2 must enforce at OS/container level (spec §8) |
| 1.3 | `run_govulncheck` / `go list` subprocesses | ENFORCED-IN-CODE (opt-in `--strict`) | Under the strict profile these tools require the explicit toolchain permission: `internal/evidencetools/service.go:491-493` `toolchainDenied` + gates at `dependencies.go:139-142` (get_dependency_graph), `:207-210` (get_module_version), `:268-271` (run_govulncheck) → UNSUPPORTED naming `--allow-toolchain`; flag `cmd/izyan-evidence-tools/main.go:56`; test `TestStrictToolchainPermissionGate`. **Named exception:** the package loader (`go list -deps` driver) and `get_product_snapshot`'s fixed `go version` probe still run without the permission because the analysis contract cannot be satisfied otherwise; each is stamped as `scope_details.extra.toolchain_exception` (`scope.go:125-133`, `dependencies.go:84-85`; test `TestStrictToolchainExceptionsRecorded`). Default profile: unchanged (no gate) |
| 1.4 | Reads confined to snapshot + allowed roots | ENFORCED-IN-CODE (unconditional in the evidence lane) | `internal/readgate/readgate.go:26,47,81` (canonicalise, fail-closed `Check`, structural prefix). Confinement is unconditional for `izyan-evidence-tools`: there is no CLI or API opt-out — an explicit `Confine=false` config is a creation error in **every** profile and under `--strict` additionally names the missing prerequisite (`service.go:202-211`; tests `TestStrictProfileRequiresConfinement`, `TestDefaultProfileCannotRunUnconfined`, `TestNoUnconfinedFlag`). Still OFF for `izyan analyze` production (`cmd/izyan/main.go:595`, set only by `cmd/izyan/vexbench.go:276`) — unchanged by design |
| 1.5 | Allowed read roots = snapshot + declared roots (+ module cache) | ENFORCED-IN-CODE (opt-in `--strict`) | `internal/goanalysis/source.go:211-216,237-245` `ExcludeAmbientModCache` drops ambient `GOMODCACHE` (and the GOPATH-derived cache) from gate roots; `service.go:270-282` `--modcache` declares a per-run cache (exported as GOMODCACHE + added to `ConfineRoots`); resolved roots recorded per observation (`service.go:320,463`, `ScopeDetails.ReadRoots`). Tests `TestStrictModuleCacheIsNotAReadRoot`, `TestStrictGopathCacheIsNotAReadRoot`. Default profile keeps ambient cache as root — unchanged |
| 1.6 | No writes into snapshot / other runs / GT | ENFORCED-IN-CODE (negative) + DOCUMENTED-ONLY | No code path in `evidencetools`/`readgate` writes into the snapshot (evidence §4); run-output-dir-only writes are manifest policy pending A2 wiring |
| 1.7 | Network = advisory allowlist only | ENFORCED-IN-CODE (partial; module egress closed under `--strict`) | `service.go:330-336` advisory/fix HTTP only under `AllowNet`; `service.go:358-371` http/https with redirect cap 5. Under `--strict` toolchain subprocess env pins `GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly` and neutralizes `GONOSUMDB/GONOPROXY/GOPRIVATE` (`service.go:253-267`), and the observation scope records both the pinned env and the inherited ambient key names (`service.go:464-465`, `ScopeDetails.ToolchainEnv` + `InheritedEnvKeys`) — tests `TestStrictHardensToolchainEnv`, `TestStrictModuleFetchCannotReachNetwork`. Residual: govulncheck's own DB fetch is not pinned by these vars → precondition §8 |
| 1.8 | No arbitrary commands via tool payloads | ENFORCED-IN-CODE (typed args) | typed tool surface `internal/evidencetools` (31 fixed tools); prompt-injection cannot widen it (spec §8; ADR-010) |

## 2. GT isolation

| # | Precondition | Status | Evidence |
|---|---|---|---|
| 2.1 | GT keys never render into agent input | ENFORCED-IN-CODE (PR-0) | `internal/eval/agent7/manifest.go` `RenderAgentInput` fails closed on denied keys at ANY depth incl. `map[string]string`, folded for case+separators (`groundTruth`, `GROUND_TRUTH`, `referencePR`, `expected_result`, `pr_url`, `expect`, `hidden`); allowlisted values must be scalar strings; tests `TestAgentInputNeverLeaksGT` + `TestAgentInputStrictness` |
| 2.2 | GT paths denied inside the sandbox | ENFORCED-IN-CODE (policy list) + wiring gap | `manifest.gt_paths_denied` covers `eval/ground-truth.md`, `eval/ground-truth/**`, `eval/corpus*.json` (incl. `corpus-reviewed.json`), `eval/live-corpus.json`, `eval/agent7/freeze/gt*`, and `${VEXBENCH_HARNESS_DIR}/benchmark/tasks/*.jsonl`; `GTPathDenied` normalizes `./`, `..`, trailing slash, `\`, case; relative globs deny absolute candidates via `GTPathsDeniedResolved`; invalid globs are violations (`TestGTPathDeniedInvalidGlob`). A2 must mount the same deny-list into the container — UNKNOWN → verify in A2 |
| 2.3 | Smoke selection reads GT host-side only | ENFORCED-IN-CODE (PR-0 policy + tests) | `manifest.smoke` is a class-quota selection RULE (2+2+1), no committed case ids/classes; agent sees only the 4 identity keys (`TestSmokeSelectionRule`, `TestSmokeQuotaSatisfiable`) |
| 2.4 | Reference PR (`metadata.pr_url`) unreachable by the agent | ENFORCED-IN-CODE (projection) | denied-key list includes `pr_url`/`reference_pr` (folded); nested-key rejection tested |

## 3. Secrets & log hygiene

| # | Precondition | Status | Evidence |
|---|---|---|---|
| 3.1 | No credential/env files or API keys in prompts, logs, manifests | ENFORCED-IN-CODE (PR-0 scan) | `privatePathViolations` scans basenames case-insensitively (`.env`, `id_rsa`, `id_ed25519`, `credentials`, `password`, `token`, `api_key`, `secret`, `.npmrc`, `.aws`, `.pem`, `.git-credentials`) + `private_path_patterns` hits; prose strings skipped; test `TestNoPrivateProductPaths` injects and rejects |
| 3.2 | Private product path stays `${VA_PRODUCT_REPO}` | ENFORCED-IN-CODE (PR-0 scan) | `allowed_path_roots` must be a subset of the code-level approved set (repo root + resolved `${VEXBENCH_*}`); `..` escapes rejected; concrete absolute paths outside the approved set are violations; same test |
| 3.3 | Transcript redaction before artifacts are committed | DOCUMENTED-ONLY | Protocol §7 requires a redacted transcript; A2 must implement the redactor and prove it on a canary secret |

## 4. Evidence binding & run isolation

| # | Precondition | Status | Evidence |
|---|---|---|---|
| 4.1 | Anti-cross-run evidence binding (attempt key, snapshot hash on every observation) | ENFORCED-IN-CODE (partial) | `ScopeDetails` carries `SnapshotHash, SnapshotRoot, ExternalSHA` (`internal/evidencetools/observation.go:72-…`); attempt-key check in `Aggregate` (duplicate keys rejected) — the per-observation binding to attempt key is UNKNOWN → verify in A2 |
| 4.2 | Snapshot integrity at session open | ENFORCED-IN-CODE | `service.go:228-237` `VerifyContained` (symlink escapes), `CheckPathReplacements` (`go.mod replace`/`go.work use` escapes), `ContentHash` |
| 4.3 | Hardened env for subprocesses | ENFORCED-IN-CODE (extended under `--strict`) | `service.go` appends `GOENV=off GOEXPERIMENT= GOINSECURE= GOWORK=off` (+`GOFLAGS=`); under `--strict` additionally `GOPROXY=off GOSUMDB=off GONOSUMDB= GONOPROXY= GOPRIVATE= GOFLAGS=-mod=readonly` and `GOMODCACHE=`/inert pin; `GOCACHE` is pinned to `--build-cache-dir`/`IZYAN_BUILD_CACHE_DIR` or the platform default and is never inherited from the ambient env; loader env whitelist `internal/goanalysis/source.go` (`loaderEnvWhitelist`); applied env + inherited ambient key names recorded per observation |
| 4.4 | Per-tool wall-clock timeouts | ENFORCED-IN-CODE (strict + opt-in) | `service.go` `invoke` runs each handler under `context.WithTimeout(s.ToolTimeout)` in its own goroutine **when a bound is set**: under `--strict` it defaults to 15m (controller-measured: a 60s bound timed out a ~1700-package vendored govulncheck scan that completed under 15m), under the default profile the bound stays 0 = unbounded (byte-equivalent to pre-E5 behaviour) unless `--tool-timeout` is set explicitly. Expiry → `StatusTimeout` (`observation.go:45-47`) + limitation + audit record; test `TestToolTimeoutHonestTimeout` (hang-handler, default-unbounded, strict-defaulted). A corrupted inherited build cache fails closed separately as `BUILD_CACHE_CORRUPT` |

## 5. Fail-closed behaviour

| # | Precondition | Status | Evidence |
|---|---|---|---|
| 5.1 | Fail-closed applies only to automatic negative decisions | ENFORCED-IN-CODE (PR-0 semantics) | refusal/tool failure leaves a partial dossier (`ABSTAIN`/`PROVIDER_REFUSED`/`INFRA_ERROR` classes exist and never merge into safe); `ClassifyAttempt` precedence tested in `TestClassifyAttemptTable` |
| 5.2 | Infra failure never becomes a verdict | ENFORCED-IN-CODE | `INFRA_ERROR` excluded from case denominators, reported separately — `TestInfraFailureClassification` |
| 5.3 | No best-of / unreported retries | ENFORCED-IN-CODE | `ClassifyAttempt` rejects `retry`/`best_of`; `Aggregate` rejects duplicate keys and run indices beyond declared repeats — `TestBestOfRetryRejected` |
| 5.4 | Manifest/validate fail closed | ENFORCED-IN-CODE | `Load` errors on missing/invalid fields; `Validate` fails on pin mismatch, unrecorded repeats deviation, undenied GT path, private path — `TestLoadFailClosed`, `TestPinnedFileHashes`, `TestArmRepeatsDeviationsRecorded` |

## 6. Known residual risks (carried to A2)

PR-2 (2026-10-11) closed E1–E5 in code under the **opt-in `--strict`
profile** of `izyan-evidence-tools`. The default `izyan analyze`
profile is unchanged — no `cmd/izyan` flag or behaviour was touched.

1. `Confine` remains opt-in for `izyan analyze` itself (off in
   production, on only in `eval vex-bench`) — unchanged by design; for
   the agent lane `--strict` now refuses to start unconfined.
2. Dep-internal source reads (`find_dep_callers`, `search_source`
   dep coverage) are narrower under `--strict` unless a per-run cache
   is declared via `--modcache` — honest scoping, not a gap.
3. govulncheck's own vulnerability-DB egress is not pinned by
   `GOPROXY=off`; a frozen local vulndb (see precondition E7b) is the
   intended feed for comparable arm runs.
4. The coding-agent runtime itself (opencode container) is now proven at
   OS/container level: E6 CLOSED/PROVEN 2026-10-11 — see §8 E6 (network
   none, uid 10001, caps dropped, Landlock exec guard, read-only mounts,
   live denial turn, permission matrix resolved in-container).
5. Advisory inputs are still fetched live (OSV) — reproducibility
   across arms needs the frozen advisory snapshot → precondition E7.
6. E8 is pinned by this PR-2 lane: `manifest.json` `run_profile`
   (`--mem-limit 24GiB`, `-j ≤ 3`, degraded/invalidated declaration,
   repeat-stability ≥3 cases × 2 repeats) + `protocol.md` §10. Its
   *execution* (the stability sample run) remains a launch precondition.
7. `readgate.New` with zero usable roots yields a gate that allows
   everything (same as nil) — deliberate: the gate is opt-in
   confinement, so "no roots" means "not configured", not "deny all".
   Defensive depth only: the evidence lane always passes its snapshot
   dir, so a zero-root gate is unreachable there; semantics pinned by
   `TestGate_ZeroRootsAllowsEverything` (`internal/readgate`).

## 7. Review response (2026-10-10)

| Review item | Response | Proof |
|---|---|---|
| products/advisories wrongly classed as GT | kept **out** of `gt_paths_denied`; rationale stated in Threat model §2 | `TestGTPathDenial` `mustAllow` covers `eval/products/…` and `eval/advisories/…` |
| manifest treated as isolation boundary | threat model rewritten: mount policy is the boundary; `gt_paths_denied` is the broker policy list | Threat model above |
| `gt_paths_denied` coverage | now covers `corpus-reviewed.json`, `eval/agent7/freeze/gt*`, `${VEXBENCH_HARNESS_DIR}/benchmark/tasks/*.jsonl` + relative form | `TestGTPathDenial` mustDeny set |
| matcher normalization | `filepath.Clean` + ToSlash + `\`→`/` + case-fold; `/**` denies the dir itself; relative globs deny absolute candidates; invalid globs are violations | `TestGTPathDenial`, `TestGTPathDeniedInvalidGlob` |
| secrets scan | basename scan, case-insensitive, expanded marker set, prose skipped | `TestNoPrivateProductPaths` (uppercase `.env`/`API_KEY`/`.aws`/`.npmrc` cases) |
| `allowed_path_roots` authority | subset of code-level approved roots (repo + `${VEXBENCH_*}`), `..` rejected | same test |
| GT labels committed | `gt_safe_case_ids`/`smoke.case_classes` removed; `Validate` flags any folded GT/reference key | `TestManifestIsGTFree` |
| run gate | `freeze_status` + `run_gate` + arm-scoped `CheckRunGateForArm`/`CheckRunGateForBlindArm` (strict `CheckRunGate` as superset); each arm's gate closed until its own pins are supplied — B1/R0: `prompts.arm_prompts` + `environment.e6` PASS + `checkpoint_0`/`checkpoint_a`; R1/R2: + tool subset + `checkpoint_b`; blind: + holdout | `TestRunGateForArm`, `TestRunGate`, `TestFreezeStatusAndScorer` |
| scorer/version + enums | `outcomes.scorer_version` = `agent7-scorer/1`; unknown execution/parse/reason are errors; order-independent case precedence; `certificate_source ∈ {baseline_b0, pr1}` | `TestUnknownEnumsRejected`, `TestCaseOutcomeOrderIndependent`, `TestCertificateProvenance` |

## 8. A2 launch preconditions (outside this repository)

These cannot be closed by repo code. A2 (and any arm run under
`--strict`) must verify them before launch and record the result.

### E6 — OS/container-level shell/process sandbox (opencode container)

**Status: CLOSED / PROVEN (2026-10-11).** The real E6 preflight ran against
the real built image, the real model and the real provider: **29/29 checks
PASS**. The verbatim probe report (schema `agent7-e6-probe/1`) is committed
at `eval/agent7/freeze/e6/security-boundary-check.json`, sha256
`16ec40baafd4a0a77fb7861c83a7aa235400b4797acaa7910cc482e58ed6c4f4`, and
pinned in `manifest.json` `environment.e6` (`status: "PASS"` +
`report_path`/`report_sha256`). `status_contract`: `PASS` opens the arm
gate; `ENV_FAIL` (environment/precondition failure, e.g. provider
unreachable while the VPN was down — fail-closed, NOT an isolation
violation) and `FAIL` (an isolation assertion violated) both close it.

**Egress model (implemented and proven):** the container runs with
`--network none` — loopback only, no DNS, no route. The model provider is
the **single allowlisted egress destination**: a host-side Unix-socket
forwarder accepts only HTTP requests for `<corporate-provider-host>` (path prefix
`/openai/v1/`), connects to the host-resolved pinned IP `<corporate-provider-ip>:443`
with TLS SNI/certificate verification, and injects the real API key
host-side — the container carries only the dummy literal `e6-forwarder`,
and no key appears in the container env, the synthesized config, the
report, or exported artifacts (`no_key_in_report_or_artifacts` PASS).
Probe: TCP to `1.1.1.1:443`/`8.8.8.8:443` → `ENETUNREACH`, DNS lookup and
raw UDP:53 → unreachable, every non-loopback interface absent;
forwarder rejects `foreign_host`/`CONNECT`/absolute-form/disallowed
path/disallowed method/traversal → 403 (oversize → 431);
`GET /openai/v1/models` → 200 via the relay. Forwarder stats:
accepted 30 / forwarded 21 / rejected 8; destinations contacted:
`<corporate-provider-host>:443 via <corporate-provider-ip>` only.

**Exact docker create policy (asserted by inspect-before-start on every
container, live turns inspected with identical policy — `inspect_parity`
PASS):**

```text
--network none  --user 10001:10001  --group-add 0  --read-only
--cap-drop ALL  --security-opt no-new-privileges:true
--pids-limit 256  --memory 4g  --memory-swap 4g
--tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=1777
--tmpfs /run-output:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700
--mount type=bind,src=<realpath(snapshot)>,dst=/work,readonly
--mount type=bind,src=<per-attempt-input>,dst=/run-input,readonly
--mount type=bind,src=<provider-socket>,dst=/run/provider.sock,readonly
--env HOME=/tmp --env XDG_CONFIG_HOME=/tmp/.config  (no env-file, cleared proxies)
--entrypoint /usr/local/bin/e6-exec-guard   (wraps the fixed controller script)
```

**User/capability posture:** uid=gid=10001 in-container
(`probe.runtime_identity` PASS), `CapEff=0000000000000000`, pids.max=256,
memory.max=4294967296, `/work` + `/run-input` read-only binds (every
create/truncate/rename/unlink on the snapshot → `EROFS`), the only
writable paths the two `noexec` tmpfs mounts, and a static
`e6-exec-guard` installing a Landlock `LANDLOCK_ACCESS_FS_EXECUTE`
policy — exec allowed under image system paths only, denied under
`/work`, `/tmp`, `/run-output` (`probe.exec_denied_work`/`exec_denied_tmpfs`
→ `fork/exec(EACCES)`; `probe.product_exec` → `go build`/`go run` denied).
Symlink policy matches the analyzer's own `VerifyContained` semantics:
an escaping symlink (canonical target outside the snapshot root) is
rejected host-side (`snapshot_hygiene` PASS; escape-symlink read →
`ENOENT`), while an inside-root dangling/unresolvable link is inert —
recorded (`dangling_symlinks`) but not rejected, matching normal repo
testdata content. Non-regular nodes (FIFO/device/socket) and
setuid/setgid files are rejected host-side. Refined 2026-10-11 (design
§2 wording refined): plain exec bits are normal git-checkout content and
are accepted by the host check — the runtime Landlock `e6-exec-guard`
denies their execution regardless of mode bits
(`exec_denied_work`/`exec_denied_tmpfs` → `EACCES`), so the host check
rejects only what can escape or escalate.

**opencode permission matrix (deterministic, resolved in-container via
`opencode debug config` — no model call):** catch-all `"*": "deny"`;
`read`/`glob`/`grep` `allow`; `edit`, `bash`, `webfetch`, `websearch`,
`task`, `skill`, `lsp`, `todowrite`, `question`, `external_directory`,
`repo_clone`, `repo_overview` all `deny`. No MCP block; no
`--dangerously-skip-permissions` (removed). Live-turn proof: positive
turn — `read`, `glob`, `grep` each completed; negative turn — the four
denied action classes were attempted and produced denials with **0
completions**: `shell_exec` 1 attempt/1 denied, `file_write` 1/1,
`network_access` 3/3, `subagent` 1/1. Denied tools are unregistered from
the model's toolset, so an error event is the enforced denial;
`resolved_permission_matrix` proves the per-tool config deterministically.

**Check list (all PASS, verbatim ids):**

- host: `image_pin`, `config_synthesis` (exact permission object, dummy
  key, relay baseURL, no mcp, no `{env:}` indirection),
  `provider_reachable` (DNS + TLS to pinned IPs), `snapshot_hygiene`,
  `inspect_policy`, `inspect_parity`, `forwarder_destinations`,
  `no_key_in_report_or_artifacts`;
- container script (`e6-probe`, self-hash == image pin == host build):
  `helper_hash_pin`, `runtime_identity`, `mount_flags`, `runtime_limits`,
  `exec_denied_work`, `exec_denied_tmpfs`, `snapshot_write`,
  `closed_path_read` (`/eval`, `/benchmark`, `/results`,
  `/eval/ground-truth`, `/harness`, `/agent-ctl`, `/root` →
  `ENOENT`/`EACCES`), `symlink_escape`, `secret_exposure`,
  `interfaces_loopback_only`, `egress_tcp`, `egress_host`, `dns`,
  `forwarder_rejects`, `provider_models` (200), `product_exec`,
  `opencode_version` (exactly `1.15.5`);
- container opencode: `resolved_permission_matrix`;
- live opencode: `live_positive_tools`, `live_negative_denials`.

**Pins** (also in `manifest.json` `images.opencode_e6` / `sandbox` /
`harness`): image `vex-bench-go-opencode-e6:latest` =
`sha256:c85bc1df0f7e89b370c5ef552cd624bba1e49c2cb07005c8946be557b7379ba1`
(linux/arm64, opencode 1.15.5), built from base
`vex-bench-go-opencode-gw:latest` =
`sha256:91629799d07a08fc56e36fe1d51589cf3a1f24ff73ed9e09bad0331161703c13`;
helpers `e6-relay` `a1c6460a8320647557eec50b39784918af145ccf319de64828ecf7f4c50d413f`,
`e6-exec-guard` `a5cbf68724626cd660f7e14657016b96515b6a24646d3f18a4d5de965487e585`,
`e6-probe` `2ea73ca96e9ea9913bd922b3c0db2271de14f7cf4e9e391beeae4d30bcaf09dc`,
`e6-exec-test` `74f84eb44e6492be244c61e8c693de4e82ec7e084b4b105e774bba9c1d93ac58`,
helpers_src `d14bd98099f22c62186a1ef598714d39bc5f2764b5243ab779527d90a91d799a`;
config sha256 `e9658f9766e104f579512dbe5aa32fca11344a049b4d9b2009622367b7a56763`,
permission object `2a5e9ad67681f998b8fae67e89373a806b62e3098a18353a9a7a4884b9af8f9a`,
create-argv `1c1d5f2d420c541d1098be217fdc1722ae7ce230855b2edd494240e4e770249b`.
Harness delta: `eval/agent7/harness/e6-sandbox.patch`, sha256
`a8bb258cf7b0b958af92a19235373f8fe3b113605235e3ae5de3f32eb35a9d8f` (19
files; baseline = harness HEAD `80cddeac` + C1 patch; the working tree
already carries the changes, so `git apply --check` reports "already
exists" — the patch is the record).

**Rerun (external harness `agent-ctl`):**

```bash
docker/build-e6.sh                       # rebuild image + stamp (required once)
uv run pytest tests/ -q                  # 34 unit tests
uv run vex-bench evaluate e6-preflight --output-dir results-e6
# report: results-e6/e6/security-boundary-check.json (schema agent7-e6-probe/1)
```

Any success on a negative assertion = A2 STOP (plan §9 risk 4); a changed
provider IP set, image, helper, or config hash invalidates the report and
requires a new probe and a new pin.

### E7 — Frozen advisory snapshot / digest canonicalisation

**Requirement:** comparable arms consume identical advisory inputs. The
benchmark runner now enforces this with `izyan eval vex-bench --osv-dir
<dir>`: it reads `<dir>/<CVE-or-OSV-id>.json` with no network fallback and
records `advisory_source`, raw `advisory_sha256`, and canonical
`advisory_canonical_sha256` in each prediction/provenance record.

**In-repo enforcement:** `internal/eval/vexbench/advisory.go:65-93,169-178`
(`FrozenFetcher`, `PrepareFrozenAdvisory`, `CanonicalSHA256`) and
`cmd/izyan/vexbench.go:39,223-247` (`--osv-dir`). Missing/unreadable records
are preparation failures naming the requested CVE.

**Remaining external precondition:** operators must provision the frozen
directory and pin per-case canonical digests before arm launch; any live fetch
in a matched frozen arm is a protocol violation.

### E7b — Frozen govulncheck database (companion to E7)

**In-repo enforcement:** `izyan-evidence-tools --strict --govulndb <path>`
is required by `internal/evidencetools/dependencies.go:268-275`; absent the
flag, `run_govulncheck` returns `UNSUPPORTED` naming `--govulndb`. The path is
exported as `GOVULNDB` and recorded in the audited toolchain environment by
`internal/evidencetools/service.go:273-289`.

**Remaining external precondition:** provision an identical local vulndb
artifact and assert `db_info` equality across arm run manifests.

### 8.1 Environment rebuild (2026-10-12)

Локальные Docker-образы были пересобраны внешним образом (базовый `vex-bench-go-opencode-gw` получил новый
id), из-за чего E6-образ и его пин перестали совпадать с зафиксированными. Восстановление: E6-образ пересобран
из нового базового (`docker/build-e6.sh`, BASE_ID перепинен), E6-probe прогнан заново — **PASS 29/29** на новом
образе (`sha256:1d7b3d39…c90b`), хэши helper'ов, config/permission/create-argv и провайдерские пины пересчитаны и
перезаписаны в `manifest.json` (`environment.e6`, `images.opencode_e6`, `sandbox`). Политика песочницы не
менялась: `--network none`, uid 10001, `--cap-drop ALL`, `no-new-privileges`, read-only binds, Landlock
exec-guard, allowlist только на провайдера. Прогоны Slice 1/2 выполнялись на прежнем образе; корпоративная
валидация (Slice 3) — на новом, что отмечено в её отчёте.
