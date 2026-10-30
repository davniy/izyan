# Case fix 3: test-scope exclusion semantics

**Date:** 2026-10-24. Branch `consolidation/shadow-base`. Commit `e8e66ff`.

## Rule (user decision)

Two independent axes, decided separately:

| Product under measurement | Vulnerable code reachable only from tests | Result |
|---|---|---|
| A consumer application / any product with a real `main` | yes — the affected package is only in test roots | **NOT_AFFECTED** |
| The library itself (e.g. testify as the analyzed product) | yes — the sink sits in non-test library source | **may be affected**; keep the honest open verdict |

Rationale: a library ships the code in its final build (testify's `assert/assertions.go`
is a non-test file); a consumer's final binary never links a test-only dependency.

## What was already correct

- `internal/affected/analyzeCompiledScope` separates product mains from library
  packages and from synthetic `.test` drivers.
- `internal/affected/resolver.go` marks a subject found only via test roots as
  `testOnly`, which drives `PackagePresent=FALSE` / `BuildRelevant=FALSE`.
- Covered by `TestReviewedPackageTestOnlyAbsentFromMains`.

## Defect found and fixed

`PackagePresent=FALSE` carried two different facts through one reason string:

> affected package(s) are absent from the product's transitive import closure
> (go list -deps -test ./...) — the code is not linked into the product

For a test-only subject that statement is **false about its own evidence**: the
`-test` closure is exactly where the package WAS found. The exclusion is real,
the wording was not.

Fix:
- `AffectedResult.TestOnlyScope []string` — typed basis naming the subjects
  observed only through test roots.
- `resolver.go` records each such subject at the point the `testOnly` flag is set.
- `evaluator.VerdictEvaluator` emits a distinct reason for that case:
  "are linked only into the product's test scope (go list -deps -test ./...
  test roots) — the code is not linked into any product binary".
  The plain-absence path keeps its original closure wording.

## Verification

Real code, `deterministic-only`, no LLM.

| Case | Product | Result |
|---|---|---|
| `GHSA-hp87-p4gw-j4gq` | fixture `bench/libfix/prod`: `package main`, `assert.YAMLEq` only in `main_test.go`, `gopkg.in/yaml.v3 v3.0.0` | `NOT_AFFECTED`, reason names test scope; 0.5 s |
| `CVE-2022-28948` on testify itself | testify snapshot `285adcc5` | `INCONCLUSIVE` on `C-INPUT` — unchanged, yaml code is non-test library source |

Regression test: `TestVerdictTestOnlyReasonNamesTestScopeNotAbsence` asserts the
test-only reason names test scope and does NOT claim closure absence, while the
plain-absence path keeps the closure wording.

Full `./internal/...` suite green. `internal/affected`, `internal/evaluator`,
`internal/domain` green after gofmt.

## Scope note

A CVE-keyed advisory (`scope.kind=CVE`, `coverage=KNOWN_ONLY`) still keeps the
case `INCONCLUSIVE` on the scope gate even when the package axis is FALSE. That
is the pre-existing advisory-scope policy, unrelated to this fix; the GHSA-keyed
run of the same advisory closes the case. Any change there is a separate
decision.

## Not done, deliberately

The `library-consumer-assumption` admission from
`2026-10-24-03-library-input-policy.md` was **not** implemented. The user's
clarification makes the library axis explicitly open ("может быть"), so
recovering `stretchr` to `EXPLOITABLE` is out of scope.
