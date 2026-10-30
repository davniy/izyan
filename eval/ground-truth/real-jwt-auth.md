# real-jwt-auth — GO-2020-0017 (jwt-go audience check) — DEFECTIVE-CHECK case

- **Mechanism (advisory):** GO-2020-0017 is a *defective check*, not a missing
  call. `MapClaims.VerifyAudience` reads `m["aud"].(string)`; when the claim
  is an array of strings the assertion yields `""`, and `verifyAud` accepts
  it because `required=false`. Exploitation requires the check to be invoked
  with `req=false` and an array `aud`.
- **Product:** `products/jwt-auth` calls
  `jwt.ParseWithClaims(raw, MapClaims{}, kf)` on a Bearer token and relies on
  library validation. It never calls `MapClaims.VerifyAudience`, so the
  advisory's affected operation does not execute.
- **Mechanism (product):** because the product performs no audience check of
  its own either, a token minted for another audience is accepted. That is a
  product-level audience-validation omission; it is **not** GO-2020-0017's
  defective invocation and must not be modeled as `C-OMISSION` for this
  advisory.
- **Advisory answer:** the exact-record result, after full negative
  verification under an admitted product target, is
  `DECIDED / NO_EXPLOIT_PATH_FOUND` grounded in affected-operation
  unreachability (`FalsifierLocusFunctionUnreached`, verified). It is not
  `NOT_AFFECTED`: jwt-go v3.2.0 is present, affected, linked and
  build-relevant.
- **Corpus label:** the `expect: [EXPLOITABLE, INCONCLUSIVE]` list in
  `eval/corpus-real.json` is the historical missing-call label. It is
  retained as a historical contract, not re-derived from the corrected
  model and not used to assert a verdict.
- **Measured 2026-10-26 (fixed pipeline):**
  - host-default target: model `DEFECTIVE_CHECK`, no `C-OMISSION`; the run is
    `FAILED` with `CODE/REACHABILITY_PROOF_INCOMPLETE` (C-REACH, C-LOCUS) and
    `CODE/TRIGGER_PROOF_INCOMPLETE` (C-INPUT, C-CHECK-TRIGGER). The
    build-dependent negative is refused because host defaults cannot ground
    it.
  - operator-declared `darwin/arm64` target matching the effective build:
    record assessment `DECIDED / NO_EXPLOIT_PATH_FOUND` with `C-REACH` and
    `C-LOCUS` `FALSE`/`VERIFIED`; `C-INPUT`/`C-CHECK-TRIGGER` remain
    `UNKNOWN` (no typed trigger-witness producer), which does not block the
    dead-operation negative. The eval harness still reports `false-safe=1`
    only because the retained historical label says EXPLOITABLE; under the
    corrected advisory semantics that comparison is obsolete.
- **Historical note:** earlier runs under the removed missing-call heuristic
  reported `EXPLOITABLE`/`INCONCLUSIVE` for this case. Those measurements
  are historical; the model that produced them was wrong.
