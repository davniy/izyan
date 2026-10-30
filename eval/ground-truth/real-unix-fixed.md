# real-unix-fixed — GO-2022-0493 (fixed pin)

- Same product as `real-unix-access`, dep pinned to the fix
  pseudo-version `v0.0.0-20220412211240-33da011f77ad`.
- **Advisory shape**: multi-module — `stdlib` plus `golang.org/x/sys`.
- **Truth**: INCONCLUSIVE. The `x/sys` entry is deterministically fixed
  (its own falsifiers, `C-LOCUS`/`C-REACH`, are FALSE), but the `stdlib`
  entry is version-undecidable: the synthetic fixture carries only a
  `go 1.23` minimum, and the release toolchain is not evidenced, so the
  stdlib range cannot be applied. With one applicable entry unresolved the
  case abstains rather than returning a safe negative. A product pinning
  its release toolchain resolves the stdlib entry and yields NOT_AFFECTED
  (module absent after fix, or version outside range).

The plain fixed-pin single-module expectation is `real-unix-stat`
(`NO_EXPLOIT_PATH_FOUND`) and the other `*-fixed` cases, whose advisories
carry only dependency modules.
