# Comprehensive Utility & Precision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore and maximize analyzer real-world utility across 65 human-reviewed benchmark tickets by resolving 6 root causes of conservative `INCONCLUSIVE` verdicts without violating the `false-safe = 0` invariant.

**Architecture:** 
1. Prune patch-added sanitizer functions (`+func`) from pre-patch defect locus candidates and unresolvable sinks from differing library versions.
2. Verify constructor/server requirements (`xds.NewGRPCServer`) statically via AST/package graph rather than deferring to unmodeled runtime facts.
3. Recognize `./cmd/...` as complete production deliverable scope when all `package main` binaries reside in `./cmd`.
4. Classify struct fields in `config` packages loaded via YAML as `OriginConfiguration` with `config-origin` ground basis.
5. Follow Go VulnDB `GO-...` aliases for advisories lacking symbols/commits to extract authoritative imports.
6. Isolate the specific defect locus modified by fix commits in multi-symbol advisories (`Iter.Next` vs generic `Form.Bytes`).

**Tech Stack:** Go 1.25+, `go/ast`, `go/types`, `golang.org/x/tools/go/packages`, `govulncheck`.

## Global Constraints
- Generality rule: NO case-specific hardcoded strings or package paths (amqp091, URI, String, DialConfig, xds, fasthttp, etc.) in `internal/goanalysis/`, `internal/evaluator/`, `internal/exposure/`, etc. (docs/agent-rules/generality.md).
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe = 0`).
- Testing rule: On intermediate steps run ONLY fast targeted unit tests (`go test -run <Name> ./...`). Do NOT run full corpus evaluation until final branch validation.
- Git rule: Commits are STRICTLY local (`git commit`). Do NOT run `git push`.
- All code must pass `gofmt`, `go vet ./...`, and `go test ./...`.

---

### Task 1: Fix Patch Sanitizer Misclassification in Diff Parsing & Candidate Pruning

**Files:**
- Modify: `internal/fix/patch.go`
- Modify: `internal/rootcause/rootcause.go`
- Test: `internal/fix/fix_test.go`
- Test: `internal/rootcause/rootcause_test.go`

**Interfaces:**
- `fix.Parse(patch string) Patch`
- `fix.File`: add field or tag indicating whether a symbol was newly introduced in added lines (`+func`) vs modified in pre-existing code.
- `rootcause.Resolver`: ignore purely added functions as pre-patch candidate sinks.
- `rootcause.Verifier`: prune candidate sinks not present in the analyzed library version from `model.UnresolvedSubjects` when all present sinks are covered.

- [ ] **Step 1: Write failing test in `internal/fix/fix_test.go`**
  Assert that when a patch adds a new function `+func (c *Client) validateArgs(...)` inside an existing file, `fix.Parse` marks it as `Added: true` or does not report it as a pre-patch modified symbol.
- [ ] **Step 2: Run test to verify RED failure**
- [ ] **Step 3: Implement minimal change in `internal/fix/patch.go` and `internal/rootcause/rootcause.go`**
- [ ] **Step 4: Run test to verify GREEN**
- [ ] **Step 5: Write test in `internal/rootcause/rootcause_test.go`**
  Verify that when an advisory has a candidate sink from a newer library version not present in the current dependency version, it does not linger in `UnresolvedSubjects` to block verified falsifiers.
- [ ] **Step 6: Run tests and commit locally**
  `git commit -m "fix(fix,rootcause): do not treat patch-added functions or version-absent symbols as pre-patch sinks"`

---

### Task 2: AST Verification for Constructor Entrypoint Gates

**Files:**
- Modify: `internal/evaluator/locus.go`
- Modify: `internal/evaluator/evaluator.go`
- Test: `internal/evaluator/locus_test.go`

**Interfaces:**
- When an advisory or exploit model requires a specific entrypoint constructor (e.g. `New...Server` or server variant), evaluate it as a symbol reachability check against `c.EvidenceGraph`.
- If the symbol is not reached in the call graph and/or its package is absent from the build graph, evaluate to `ClaimFalse` with `FalsifierLocusFunctionUnreached` or `FalsifierPackageAbsent`.

- [ ] **Step 1: Write failing test in `internal/evaluator/locus_test.go`**
  Assert that when a mandatory condition specifies an uncalled constructor/entrypoint symbol, `SymbolReachable.Evaluate` yields `ClaimFalse` with `FalsifierLocusFunctionUnreached`.
- [ ] **Step 2: Run test to verify RED failure**
- [ ] **Step 3: Implement minimal change in `internal/evaluator/locus.go`**
- [ ] **Step 4: Run test to verify GREEN**
- [ ] **Step 5: Run tests and commit locally**
  `git commit -m "feat(evaluator): verify entrypoint constructor conditions via static call graph and package absence"`

---

### Task 3: Support Production Scope Recognition for `./cmd/...` Fallback

**Files:**
- Modify: `internal/goanalysis/negative.go`
- Test: `internal/goanalysis/negative_test.go`

**Interfaces:**
- In `internal/goanalysis/negative.go`: when checking if `pattern != "./..."` (e.g. `./cmd/...`), inspect `analyzeCompiledScope` or product mains.
- If all `package main` executables of the product reside within `cmd/`, and non-cmd packages are not imported by any main, treat `./cmd/...` as complete production deliverable scope rather than degrading to `INSUFFICIENT_SCOPE`.

- [ ] **Step 1: Write failing test in `internal/goanalysis/negative_test.go`**
  Assert that a product with all `main` packages under `cmd/` retains `NegativeVerified` for `govulncheck-silence` when the scan pattern was `./cmd/...`.
- [ ] **Step 2: Run test to verify RED failure**
- [ ] **Step 3: Implement minimal change in `internal/goanalysis/negative.go`**
- [ ] **Step 4: Run test to verify GREEN**
- [ ] **Step 5: Run tests and commit locally**
  `git commit -m "fix(goanalysis): recognize ./cmd/... as complete production scope when all mains reside in cmd"`

---

### Task 4: Configuration Provenance for Config Structs and YAML

**Files:**
- Modify: `internal/goanalysis/provenance.go`
- Test: `internal/goanalysis/source_test.go`

**Interfaces:**
- In `internal/goanalysis/provenance.go`: `fieldConfigTaggedScan` / `classify`.
- When a struct field belongs to a package named `config` or ending in `/config`, or carries `yaml:` tags in a configuration loading context, classify its origin as `domain.OriginConfiguration`.

- [ ] **Step 1: Write failing test in `internal/goanalysis/source_test.go`**
  Assert that a struct field with `yaml:"..."` declared in a package named `config` resolves to `OriginConfiguration`.
- [ ] **Step 2: Run test to verify RED failure**
- [ ] **Step 3: Implement minimal change in `internal/goanalysis/provenance.go`**
- [ ] **Step 4: Run test to verify GREEN**
- [ ] **Step 5: Run tests and commit locally**
  `git commit -m "feat(goanalysis): classify fields in config packages as OriginConfiguration"`

---

### Task 5: Follow Go VulnDB Aliases for Advisories Lacking Symbols or Commits

**Files:**
- Modify: `internal/vulnerability/source.go`
- Modify: `internal/states/states.go`
- Test: `internal/vulnerability/source_test.go`

**Interfaces:**
- In `internal/vulnerability/`: when an OSV record has no `affected[].ecosystem_specific.imports` and no commit references, check `aliases` for a `GO-...` identifier.
- Merge symbols and references from the alias record when available.

- [ ] **Step 1: Write failing test in `internal/vulnerability/source_test.go`**
  Assert that an advisory with an empty symbols list inherits symbols from its `GO-...` alias.
- [ ] **Step 2: Run test to verify RED failure**
- [ ] **Step 3: Implement minimal change in `internal/vulnerability/source.go`**
- [ ] **Step 4: Run test to verify GREEN**
- [ ] **Step 5: Run tests and commit locally**
  `git commit -m "feat(vulnerability): populate symbols from GO-... aliases when primary advisory lacks imports"`

---

### Task 6: True Defect Locus Isolation for Coarse Multi-Symbol Advisories

**Files:**
- Modify: `internal/rootcause/rootcause.go`
- Modify: `internal/evaluator/locus.go`
- Test: `internal/rootcause/rootcause_test.go`
- Test: `internal/evaluator/locus_test.go`

**Interfaces:**
- In `rootcause.Resolver`: when an authoritative fix commit is parsed, mark the specific functions modified by the fix as the primary `LocusSymbols`.
- In `evaluator`: evaluate `C-LOCUS` against the narrowed fix-modified locus symbols rather than the broad union of all exported package symbols.

- [ ] **Step 1: Write failing test in `internal/evaluator/locus_test.go`**
  Assert that when `C-LOCUS` has narrowed fix-modified symbols that are uncalled, while unrelated package utilities are called, `C-LOCUS` evaluates to `ClaimFalse` with `FalsifierLocusFunctionUnreached`.
- [ ] **Step 2: Run test to verify RED failure**
- [ ] **Step 3: Implement minimal change in `internal/evaluator/locus.go`**
- [ ] **Step 4: Run test to verify GREEN**
- [ ] **Step 5: Run tests and commit locally**
  `git commit -m "feat(evaluator,rootcause): isolate fix-modified defect locus in multi-symbol advisories"`

---

### Task 7: Benchmark Verification & Documentation Sync

**Files:**
- Update: `docs/dev/gap-analysis.md`
- Update: `eval/README.md`
- Run hygiene checks: `gofmt`, `go vet ./...`, fast tests `go test ./...`
- Verify against the reviewed tickets

- [ ] **Step 1: Run hygiene checks (`gofmt`, `go vet ./...`, `go test ./...`)**
- [ ] **Step 2: Run targeted verification on reviewed tickets**
- [ ] **Step 3: Update documentation and gap analysis**
- [ ] **Step 4: Final local commit**
