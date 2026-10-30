# Task 5 checker fixture migration

Status: DONE

## Files changed

- `internal/fixbinding/proof_test.go`: baseline and two-reference inputs carry real source captures; exact ctx-first direct admission, persistence and replay; forged source projections cannot replace captures; per-locator associations and captured-byte replay mutation controls.
- `internal/fixbinding/admit_test.go`: independent current context at each admission; source mismatch uses independently acquired changed-product premises, preserving canonical CLAIM refusal rather than failing on incomplete fixture provenance.
- `internal/fixbinding/activation_test.go`: every persisted/model admission uses independent own-record current context, including dependent-label, historical, substituted-source, unsupported semantic-proof, reuse and changed-proof tests.
- `internal/fixbinding/noncounterpart_test.go`: variant source observations reconstructed from complete bytes; imported components use independently checksummed captures, product-authenticated selection metadata and strictly decoded raw inventory evidence. Existing renamed/split/wrapped/direct-constructor/registration/counterpart behavior retained.
- `internal/fixbinding/capture_test.go`: shared acquisition helpers and dedicated authority regression coverage.

No production files or other package tests changed. No commits, reset, full-suite runs, lint or formatters.

## Capture/context premises

Helpers write product metadata, use `repository.CaptureContentManifest` and `repository.ContentHash`, and hold advisory pin/document, affected selection and current product independently from mutable proof inputs. ZIP h1 lines are authenticated by that product manifest. Source observations preserve complete file bytes. Captured module archives include genuine root module declarations. External inventory run/completeness comes from `affected.RecordPackageInventory` strict decoding of full raw inventory bytes, not asserted completion flags; current evidence retains the exact payload, hash, run and build.

Product fixture directories are removed before replay. The selected product-tree test also captures actual executable mode bits and product entries and removes its source tree before Persist/Readmit.

Added controls cover:

- missing/current foreign product, build, record and affected selection;
- proof-internal product repinning and substituted authenticated metadata;
- historical `/2` refusal without auto-upgrade;
- independently captured cross-release patch base with a selected-fork preimage that differs in exact bytes;
- exact locator/artifact/checksum/preimage binding;
- complete archive-equivalent tree carrier success, wrong/missing/extra/tree-only refusal;
- independent fix locators never becoming a series;
- external anchor, effective owner, raw evidence, missing/current foreign evidence and direct asserted projection refusal;
- capture-scope changes changing both CaptureDigest and cover identity;
- source-free serialized proof replay;
- product-anchored local selected-tree splice without independent archive authority;
- existing unsupported residual and noncounterpart/registration/selected-source mismatch behavior.

## Verification

Core API readiness was communicated before checks. Final focused command, after core's strict independent-archive module declaration validation landed:

```sh
go test ./internal/fixbinding -run 'Test(CaptureContext|PersistedProof|Refused|NonCounterpart|SelectedSource|Binding|Admission|AllInapplicable|PerLocator|PatchBase|CompleteTree|CaptureReplay|ExternalCapture|TwoFixLocators|AssertedProof|WithdrawnHistorical|ThirdPartyFix|AnotherVersionSource|MissingExactSource|GuessedV2|UnsupportedFix|ChangedProof)' -count=1
```

Result: PASS (`ok github.com/fedorovmv/izyan/internal/fixbinding 0.885s`).

The separately exercised product-tree regression passed before the final combined command as well.

Follow-up requested by core: added `TestExternalCaptureCheckedWrapperReachesCounterpartAnalysis`, using an independently captured imported component whose `EnsureStateDir` entry calls the existing supported `chmodRoot` wrapper structure. The test asserts a mapped effect with external-component provenance and the wrapper entry in the necessary cover, then verifies Persist/source-free Readmit preserve it. Focused command `go test ./internal/fixbinding -run 'TestExternalCaptureCheckedWrapperReachesCounterpartAnalysis' -count=1` passed (`0.619s`).

After core added strict external observed module/version/kind/root equality with the effective selection, `go test ./internal/fixbinding -run 'Test(ExternalCapture|NonCounterpart)' -count=1` passed (`0.611s`). Existing fixture builders already supply matching observation identities; no test changes were necessary.

After core added vendor carrier/product-manifest reconciliation, added `TestCaptureContextVendorObservationMatchesProductSnapshot`: genuine vendor files and acquired manifest/hash; matching source-free positive plus changed bytes, missing/extra member and foreign-root refusals. This targets `checkProductObservation` directly, not an end-to-end positive vendor admission claim. `go test ./internal/fixbinding -run 'Test(CaptureContextVendorObservationMatchesProductSnapshot|BindingRequiresAnchoredInventory)' -count=1` passed (`0.459s`).

Earlier runs exposed fixture migration issues (remaining ctx arguments, missing variant observations, obsolete asserted-map authority expectations, directory executable modes). They were corrected without disabling security checks. Core's initial INPUT refusal precedence for missing entry/selection was reported; core restored historical ENTRY/EFFECTIVE_COORDINATE ordering and the final focused command passes those expectations. Two experimental selected-source variants legitimately failed ARTIFACTS/VALUE_CORRESPONDENCE; the final cross-release fixture keeps semantically matching selected operations while differing in exact patch preimage bytes. No security failure was hidden as unsupported.

## Unresolved issues

None in the assigned checker fixtures. Consumer-package and full repository verification remain the parent's responsibility; they were not run here.
