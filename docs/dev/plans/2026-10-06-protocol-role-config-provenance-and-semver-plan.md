# Protocol Role, Config Provenance, and SemVer Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement protocol role distinction (server vs client), code-level config provenance grounding for outbound dials, and SemVer fix compatibility analysis without hardcoding company SLAs or violating the `false-safe = 0` safety invariant.

**Architecture:**
1. **Task 1 (Protocol Role Distinction):** Add `ProtocolRole` (`server`, `client`, `symmetric`) to domain models and exploit classification. In `ServerTransportInput` and condition evaluation, falsify server-side conditions when product acts solely as a client (outbound only), and client-side conditions when product has no outbound calls into the module (`FalsifierProtocolRoleMismatch`).
2. **Task 2 (Config Provenance for Outbound Dials):** Link `ScopeStatic` / `ScopeConfigured` from `exposure.OutboundScope` to `BasisConfigOrigin` in `cluster_perimeter` evaluations, grounding trusted-infrastructure falsifications in code-level provenance facts rather than purely generic operator assertions.
3. **Task 3 (SemVer Fix Compatibility Analysis):** Calculate whether a target fixed version is a drop-in replacement (`semver.Major(fixed) == semver.Major(current)`) or a breaking major upgrade, exposing structured flags and actionable remediation guidance in reports.

**Tech Stack:** Go 1.25+, `golang.org/x/mod/semver`, `go/ast`, `go/types`.

## Global Constraints
- Generality rule: NO case-specific hardcoded strings, repo names, or package paths (docs/agent-rules/generality.md).
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe = 0`).
- SLA isolation: Do NOT hardcode company-specific SLA time windows as core analyzer truths.
- Testing rule: On intermediate steps run ONLY fast targeted unit tests (`go test -run <Name> ./...`). Full corpus evaluation (`eval/corpus-real.json`) is run STRICTLY ONCE at final branch validation.
- Git rule: Commits are STRICTLY local (`git commit`). Do NOT run `git push`.
- All code must pass `gofmt`, `go vet ./...`, and `go test ./...`.

---

### Task 1: Protocol Role Distinction (Server vs Client)

**Files:**
- Modify: `internal/domain/domain.go`
- Modify: `internal/exploit/classify.go`
- Modify: `internal/exploit/builder.go`
- Modify: `internal/evaluator/transport.go`
- Test: `internal/exploit/classify_test.go`
- Test: `internal/evaluator/transport_test.go`

**Interfaces:**
- `domain.ProtocolRole`: `"server"` | `"client"` | `"symmetric"` | `""`
- `domain.FalsifierProtocolRoleMismatch`: `"protocol-role-mismatch"`
- `domain.ParamProtocolRole`: `"protocol_role"`
- `exploit.DetectProtocolRole(v domain.Vulnerability, patch fix.Patch) domain.ProtocolRole`
- `evaluator.ServerTransportInput`: checks protocol role against product exposure directions (`ListenSites` vs `DialSites`).

- [x] **Step 1: Define `ProtocolRole` constants in `internal/domain/domain.go`**
  Add `ProtocolRole` type, `ProtocolRoleServer`, `ProtocolRoleClient`, `ProtocolRoleSymmetric`, `ParamProtocolRole`, `FalsifierProtocolRoleMismatch`, and add `ProtocolRole` field to `ExploitModel`.

- [x] **Step 2: Write unit test for `DetectProtocolRole` in `internal/exploit/classify_test.go`**
  Test classification of server-focused advisories (HTTP/gRPC server handlers) as `ProtocolRoleServer`, and client-focused advisories (HTTP/gRPC client responses, TLS server flights) as `ProtocolRoleClient`.
  Verify test fails (RED).

- [x] **Step 3: Implement `DetectProtocolRole` in `internal/exploit/classify.go` and wire into `builder.go`**
  Use generic protocol keywords (server listeners, server request handling vs client responses, server flights, client connections).
  Verify test passes (GREEN).

- [x] **Step 4: Write unit test in `internal/evaluator/transport_test.go` for `ServerTransportInput` role mismatch**
  Test case A: Vulnerability is `ProtocolRoleServer`, product has only outbound `Dial` sites and no inbound listeners $\to$ returns `ClaimFalse` with `falsifier: protocol-role-mismatch`.
  Test case B: Vulnerability is `ProtocolRoleClient`, product has only inbound listeners and zero `Dial` sites into the module $\to$ returns `ClaimFalse` with `falsifier: protocol-role-mismatch`.
  Verify test fails (RED).

- [x] **Step 5: Implement role mismatch gating in `internal/evaluator/transport.go`**
  In `ServerTransportInput.Evaluate`, check `cond.Params[domain.ParamProtocolRole]` or `c.Exploit.ProtocolRole`.
  When a role mismatch is detected, return `ClaimFalse` with `FalsifierProtocolRoleMismatch`.
  Verify test passes (GREEN).

- [x] **Step 6: Run tests, fmt, vet, and commit Task 1**
  `go test -v -run "TestDetectProtocolRole|TestServerTransportInputRole" ./internal/exploit ./internal/evaluator`
  `git commit -am "feat(exploit,evaluator): add protocol role distinction and protocol-role-mismatch falsifier"`

---

### Task 2: Config Provenance Grounding for Outbound Dials

**Files:**
- Modify: `internal/evaluator/transport.go`
- Modify: `internal/states/states.go`
- Test: `internal/evaluator/transport_test.go`
- Test: `internal/states/perimeter_eval_test.go`

**Interfaces:**
- `f.Scope == domain.ScopeConfigured || f.Scope == domain.ScopeStatic`
- `domain.BasisConfigOrigin = "config-origin"`
- Grounding `FalsifierTrustedInfrastructure` with `BasisConfigOrigin` when outbound peer addresses are proven operator-configured or static.

- [x] **Step 1: Write failing test in `internal/evaluator/transport_test.go`**
  Assert that when client-side peer input is evaluated with `c.Product.TrustedPeer` or cluster perimeter, and outbound exposure facts have `ScopeConfigured` or `ScopeStatic`, `claim.FalsifierBasis` is `domain.BasisConfigOrigin`.
  Verify test fails (RED).

- [x] **Step 2: Update `ServerTransportInput.Evaluate` in `internal/evaluator/transport.go`**
  When grounding `FalsifierTrustedInfrastructure` for client-side transport calls, inspect `c.EvidenceGraph.ExposuresList()`. If all outbound dials for the module have `ScopeConfigured` or `ScopeStatic`, set `claim.FalsifierBasis = domain.BasisConfigOrigin`.
  Verify test passes (GREEN).

- [x] **Step 3: Update `claimsCP` rewriting in `internal/states/states.go`**
  In `EvaluateVerdict.Run`, when rewriting claims to `FalsifierTrustedInfrastructure`, check if the condition is backed by configured outbound facts. If so, preserve or set `profileBasis = domain.BasisConfigOrigin`.

- [x] **Step 4: Write test in `internal/states/perimeter_eval_test.go`**
  Verify that an outbound client case whose endpoint comes from a repository config file yields `GroundBasis == domain.BasisConfigOrigin`.

- [x] **Step 5: Run tests, fmt, vet, and commit Task 2**
  `go test -v -run "TestServerTransport|TestPerimeter" ./internal/evaluator ./internal/states`
  `git commit -am "feat(evaluator,states): ground trusted infrastructure in config-origin for configured outbound endpoints"`

---

### Task 3: SemVer Drop-In vs Breaking Upgrade Compatibility Flag

**Files:**
- Modify: `internal/domain/domain.go`
- Modify: `internal/report/report.go`
- Test: `internal/report/report_test.go`

**Interfaces:**
- `report.FixCompatibility(resolved, fixed string) (dropIn bool, majorBump bool, ok bool)`
- `domain.AnalysisCase` / `domain.AffectedResult`: `UpgradeDropIn bool`, `UpgradeMajorBump bool`
- Markdown rendering in `report.md` / `report.en.md` displaying SemVer compatibility guidance.

- [x] **Step 1: Write failing test in `internal/report/report_test.go`**
  Test `FixCompatibility("v1.2.0", "v1.2.4")` $\to$ `dropIn=true, majorBump=false`.
  Test `FixCompatibility("v1.2.0", "v2.0.1")` $\to$ `dropIn=false, majorBump=true`.
  Verify test fails (RED).

- [x] **Step 2: Implement `FixCompatibility` and update `remediation` in `internal/report/report.go`**
  Use `semver.Major(fixed) == semver.Major(resolved)` from `golang.org/x/mod/semver`.
  In `remediation(...)`:
  - When `dropIn`: render "Совместимо по SemVer (minor/patch, без breaking changes API)" / "SemVer drop-in upgrade (no breaking changes)".
  - When `majorBump`: render "Внимание: обновление требует перехода на мажорную версию (%s, возможны breaking changes API)" / "Notice: upgrade requires a major version bump (%s, breaking changes possible)".
  Verify test passes (GREEN).

- [x] **Step 3: Run tests, fmt, vet, and commit Task 3**
  `go test -v -run "TestFixCompatibility|TestReport" ./internal/report`
  `git commit -am "feat(report): add SemVer drop-in vs major breaking upgrade compatibility analysis"`

---

### Task 4: Full Validation & Documentation Synchronization

**Files:**
- Modify: `docs/dev/gap-analysis.md`
- Modify: `eval/README.md` (if behavioral reports changed)

- [x] **Step 1: Run code hygiene checks**
  `gofmt -w internal/ cmd/`
  `go vet ./...`
  `go test ./...`

- [x] **Step 2: Run single full corpus verification**
  `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4`
  Confirm 38/38 cases pass, `false-safe = 0`.

- [x] **Step 3: Update `docs/dev/gap-analysis.md`**
  Record closed items and findings.

- [x] **Step 4: Commit documentation and clean up plan**
  `git commit -am "docs: record protocol role, config provenance, and SemVer compatibility enhancements"`
