// Package triage is the Product B triage runtime adapted into Shadow as an
// adapter layer (target §14.3.2–§14.3.3, backlog S-06/S-06b/S-07/S-08/S-09/
// S-17).
//
// The code is ported from V2 internal/agenttriage. It keeps the Product B
// contract only: findings (finding.v1), the Stage 0 intake/catalog/ref/
// snapshot/site-config surface, agent assessments (assessment.v3) with
// proposal-only falsifier ingress, the deterministic-tools broker over
// Shadow internal/evidencetools, the observation archive
// (observation-archive.v1), the FactGate that resolves evidence locators —
// det:/obs: ids of recorded tool observations, snapshot file/artifact
// paths, advisory ids, component identity and revision identity — into
// reproducibility statuses, the deterministic falsifier verifier and the
// decision composer.
//
// One run produces decision-package.v4. The package carries four
// structurally separate axes:
//
//   - judgment — the model's own conclusion and mechanism, preserved
//     verbatim as an investigation opinion;
//   - proposed_action — the concrete action a person is asked to take
//     (CLOSE, LOWER_PRIORITY, REMEDIATE, KEEP_OPEN, OBTAIN_EVIDENCE or contextual
//     ACCEPT_ENVIRONMENTAL_MITIGATION in an explicitly prepared branch), with
//     its decisive claim closure and the observations that would change it;
//   - premises + support — the decisive-premise graph re-derived from the
//     recorded claims, observations, quotations and admitted proofs, and
//     its deterministic support level (INSUFFICIENT, LIMITED,
//     SUBSTANTIATED or PROVED_WITHIN_SCOPE). Support is a property of the
//     recorded grounds, never a probability and never an admission signal;
//   - machine_disposition — everything the deterministic layer establishes
//     on its own: the one recommendation (DISMISSED, LOWERED, UNCHANGED)
//     the baseline, rules, checks and admitted proofs permit, the
//     demotion record, residual assumptions, reassessment triggers and the
//     machine-only automation outcome (ALLOW/WARN/BLOCK).
//
// The deterministic half of assessment.json (FactValidation, its detail
// and the audit block) is composed by code and rejected from model replies.
// Falsifier proposals are optional: an unsupported or incomplete proof
// capability limits the machine result, never the model's right to propose
// a human action. The composer never reads the model judgment or the human
// action as a machine premise, and no human action, support level or
// Accept/Reject record becomes a Product A verdict, an admitted proof, an
// automatic reduction or permission to auto-close.
//
// Presentation and persistence: decision.json and the action-first
// decision.md card (action → rationale/judgment → scope → facts →
// interpretations → assumptions/support → what would change the
// recommendation → Accept/Reject → machine disposition → audit). The card
// renders the recorded decision scope, including its CVE-wide boundary.
// Raw-agent transcripts, the fact gate, the observation archive, the
// falsifier report, the condition-catalog binding and stability-runs.v2 are
// persisted with deterministic hashes and atomic writes. Human Accept/Reject
// is a separate append-only human-decision.v2 collection binding canonical
// package hash, branch ID, projection hash and assertion IDs; comment is optional.
// Two-step environment review must present the displayed --projection-hash;
// the locked writer rejects a stale pin after another reviewer supersedes an
// answer, rather than accepting an unseen branch. One-step answer+review binds
// the selected projection through the same locked comparison.
// A captured human_review_plan prepares all finite branches for zero to two
// environment questions, including unknown, with at most seven mandatory premises.
// environment-assertion.v1 records human-owned answers with explicit supersession.
// Valid answers are not reasked. Contradiction keeps open; overflow or incomplete
// branches are NOT_DECISION_READY, never an instruction for more investigation.
//
// Replay (replay.v2) verifies captured hashes, re-derives support and machine
// admissibility and reselects the prepared branch without model/network/source
// investigation. Assertions and Accept/Reject history are copied verbatim: replay
// creates neither a new Accept nor a timestamp. Older assessment/package/review
// schemas use version-specific historical playback, never an authority upgrade.
//
// CI policy stays outside the package: PackagePolicyHit/ExitCode evaluate
// the package against the explicitly requested thresholds, so exit 0 means
// a decision package was delivered — not that a machine reduction or VEX
// statement was established. External control comparison is the separate
// offline triage-evaluation.v1 surface (izyan eval triage): live triage and
// replay never load a baseline or require ground truth. The optional
// triage-vex-projection.v1 stays default-off, derived from the machine
// disposition alone and non-authoritative for Product A.
//
// Authority boundary: nothing in this package may mint a Product A
// authority object. The Product B Verdict enum deliberately rejects the
// Product A verdict spellings, FalsifierProposal decoding rejects every
// self-declared verification field, FactGate VALID means "the reference is
// reproducible" — never semantic truth — and there is no assessment →
// Claim/NegativeVerification/VerdictResult mapping. Product A and its VEX
// authority are unchanged by anything in this package.
//
// Type mapping follows the §14.3.2 table: V2 internal/domain,
// internal/affected and internal/evaluator are not imported. Surfaces that
// need a V2 domain shape carry adapter-local DTOs; checks whose semantics
// require canonical Shadow evidence (e.g. obs: resolution) bind to the
// observation archive adapter recorded by this package, not to a fake.
package triage
