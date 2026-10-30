// Package productb owns the Product B (V2 triage runtime) schema registry
// required by S-17 (target §14.3.3): a code-level, mechanically testable
// declaration of every Product B artifact schema — its version, owner,
// producer, consumer, artifact path, compatibility and replay rule.
//
// The registry is a declaration surface only. It pins the ownership
// boundary — Product B artifacts are non-authoritative for Product A — but
// it does not load, validate or emit artifacts itself. Schemas whose
// runtime is already ported live in the triage adapter package; schemas
// whose producer/consumer belongs to a later slice (composer, policy,
// intake, metrics, replay) are declared with Ported=false so the
// completeness gate can distinguish "owned and implemented" from "owned
// and pending".
package productb

import "fmt"

// SchemaDecl is one Product B schema declaration.
type SchemaDecl struct {
	// Version is the exact schema_version string the artifact carries.
	Version string
	// Owner names the single authority for the schema per §14.3.3.
	Owner string
	// Producer is the component that writes the artifact.
	Producer string
	// Consumers are the components allowed to read the artifact.
	Consumers []string
	// Artifact is the canonical artifact file name or path fragment.
	Artifact string
	// Compatibility states the acceptance rule for other versions.
	Compatibility string
	// ReplayRule states how replay treats the artifact.
	ReplayRule string
	// Phase is the roadmap phase that owns the surface.
	Phase string
	// Ported is true when the producing/consuming runtime exists in this
	// repository; false marks a declared-but-pending schema.
	Ported bool
}

// registry is the complete Product B schema surface. Every entry is
// additive over the V2 schema constants; order is deterministic.
var registry = []SchemaDecl{
	{
		Version: "finding.v1", Owner: "product-b-intake",
		Producer: "external scanner/finding source", Consumers: []string{"triage.ParseFindings", "triage.LocalSnapshotBuilder", "triage.FactGate"},
		Artifact:      "finding record (stdin/intake)",
		Compatibility: "exact match; any other schema_version is rejected at decode",
		ReplayRule:    "raw bytes and sha256 preserved verbatim for replay",
		Phase:         "3", Ported: true,
	},
	{
		Version: "assessment.v3", Owner: "product-b-triage",
		Producer: "triage agent response + deterministic annotation", Consumers: []string{"triage.DecodeAssessment", "triage.FactGate", "triage.DeriveSupport", "triage.Composer", "triage.PrepareReplay"},
		Artifact:      "assessment.json",
		Compatibility: "exact live match; assessment.v2 is version-specific historical replay only, never upgraded; finite environment nominations carry no answer or authority",
		ReplayRule:    "fact_validation/automation/audit fields are deterministic-only; conditional proposal assignments are checked against the code-owned universe; agent text stored verbatim",
		Phase:         "3", Ported: true,
	},
	{
		Version: "intake-record.v1", Owner: "product-b-intake",
		Producer: "stage0 intake", Consumers: []string{"stage0", "intake audit"},
		Artifact:      "intake-record.json",
		Compatibility: "exact match", ReplayRule: "raw intake bytes and hash retained",
		Phase: "3 (S-06b)", Ported: true,
	},
	{
		Version: "intake-proposal.v1", Owner: "product-b-intake",
		Producer: "LLM intake extractor", Consumers: []string{"stage0 proposal validation"},
		Artifact:      "intake-proposal.json",
		Compatibility: "exact match", ReplayRule: "proposal only; every field revalidated deterministically",
		Phase: "3 (S-06b)", Ported: true,
	},
	{
		Version: "intake-audit.v1", Owner: "product-b-intake",
		Producer: "stage0 intake audit", Consumers: []string{"run audit"},
		Artifact:      "intake-audit.json",
		Compatibility: "exact match", ReplayRule: "audit retained verbatim",
		Phase: "3 (S-06b)", Ported: true,
	},
	{
		Version: "stage0.v1", Owner: "product-b-intake",
		Producer: "stage0 resolution", Consumers: []string{"runner", "checks"},
		Artifact:      "stage0.json",
		Compatibility: "exact match", ReplayRule: "deterministic re-resolution after proposal extraction",
		Phase: "3 (S-06b)", Ported: true,
	},
	{
		Version: "investigation-inputs.v1", Owner: "product-b-investigation-inputs",
		Producer: "operator-supplied strict manifest loader (triage.LoadInvestigationInputs)", Consumers: []string{"triage.ReadOnlyTools.read_material", "triage.PrepareReplay", "triage.DeriveSupport record scope"},
		Artifact:      "investigation-inputs.json + materials/<sha256>",
		Compatibility: "exact match; strict manifest with DisallowUnknownFields; duplicate identities, undeclared fix ownership, absolute/traversal/symlink-escape paths, wrong digest or size are rejected before any run",
		ReplayRule:    "the metadata projection and every digest-addressed archived blob are re-verified offline; original manifest paths are never read during replay",
		Phase:         "2 (investigation inputs)", Ported: true,
	},
	{
		Version: "prompt-input.v1", Owner: "product-b-runtime",
		Producer: "triage runner prompt sink, before the first investigator exchange", Consumers: []string{"triage.PrepareReplay", "audit"},
		Artifact:      "prompt-input.json",
		Compatibility: "exact match; the stored prompt_hash must reproduce from the recorded system text and initial messages",
		ReplayRule:    "replay verifies the persisted system text, initial data messages and advertised tool definitions; it never rebuilds the surface from today's tool definitions. A historical run without the artifact is read by the history-only reconstruction reader, which grants no new proof authority",
		Phase:         "2 (investigation inputs)", Ported: true,
	},
	{
		Version: "triage-site.v1", Owner: "product-b-runtime",
		Producer: "operator site config", Consumers: []string{"triage runtime config loader"},
		Artifact:      "site config (triage-site.yaml)",
		Compatibility: "strict schema; config hash recorded", ReplayRule: "config hash binds the run",
		Phase: "3 (S-06b)", Ported: true,
	},
	{
		Version: "ref-selection.v1", Owner: "product-b-intake",
		Producer: "ref-selection agent step", Consumers: []string{"stage0 ref resolution"},
		Artifact:      "ref-selection.json",
		Compatibility: "exact match", ReplayRule: "bounded candidate ids only; unresolved selection fails closed",
		Phase: "3 (S-06b)", Ported: true,
	},
	{
		Version: "snapshot.v1", Owner: "product-b-snapshot",
		Producer: "triage.LocalSnapshotBuilder", Consumers: []string{"triage.FactGate", "triage.ReadOnlyTools", "triage.PrepareReplay"},
		Artifact:      "snapshot.json",
		Compatibility: "exact match", ReplayRule: "content/input hashes pin the tree; mutation is a technical error",
		Phase: "3", Ported: true,
	},
	{
		Version: "observation-archive.v1", Owner: "product-b-evidence-adapter",
		Producer: "triage observation store", Consumers: []string{"triage.FactGate (via ObservationIndex)", "triage.FalsifierVerifier", "triage.PrepareReplay"},
		Artifact:      "observation-archive.json",
		Compatibility: "exact match; per-observation data_sha256 verified on read",
		ReplayRule:    "obs:<id>/det:<id> resolve only to archived, hash-valid, run-bound observations",
		Phase:         "3", Ported: true,
	},
	{
		Version: "fact-gate.v1", Owner: "product-b-evidence-adapter",
		Producer: "triage.FactGate", Consumers: []string{"runner", "feedback loop", "triage.DeriveSupport", "triage.Composer", "triage.PrepareReplay"},
		Artifact:      "fact-gate.json",
		Compatibility: "exact match", ReplayRule: "offline replay replays recorded validation after internal-consistency re-check",
		Phase: "3", Ported: true,
	},
	{
		Version: "falsifier-verification.v1", Owner: "product-b-deterministic-verifier",
		Producer: "deterministic falsifier verifier", Consumers: []string{"triage.DeriveSupport", "triage.Composer", "triage.PrepareReplay", "report"},
		Artifact:      "falsifier.json",
		Compatibility: "exact match", ReplayRule: "proof generated only by owning deterministic tool; recomputed on replay",
		Phase: "2–3 (S-03b)", Ported: true,
	},
	{
		Version: "condition-catalog.v1", Owner: "product-a-checker (produced) / product-b (read-only consumer)",
		Producer: "Product A deterministic exploit-model/checker path or approved registry — no in-repo producer yet; the live falsifier path loads it via --condition-catalog and rejects every proposal when absent", Consumers: []string{"triage.AdmitFalsifierProposal", "replay"},
		Artifact:      "condition-catalog.json",
		Compatibility: "exact match; unknown condition ids are UNSUPPORTED, never guessed",
		ReplayRule:    "catalog_hash is part of run identity; a hash/content mismatch fails the run closed",
		Phase:         "2-3 (S-16)", Ported: false,
	},
	{
		Version: "catalog-binding.v1", Owner: "product-b-runtime (produced) / product-b (replay consumer)",
		Producer: "triage.ArtifactWriter.WriteConditionCatalog — records the run-side catalog binding (advisory, digest, case, expected hash, catalog presence)", Consumers: []string{"triage.PrepareReplay", "audit"},
		Artifact:      "catalog-binding.json",
		Compatibility: "exact match; a partial binding is non-admitting, never completed by guessing",
		ReplayRule:    "re-enforced on replay: the persisted binding gates proposal admission; a run without it derives the binding from run artifacts (legacy path, catalog hash unverifiable)",
		Phase:         "2-3 (S-16)", Ported: true,
	},
	{
		Version: "proposal-ingest.v1", Owner: "product-a-verifier (boundary) / product-b (producer)",
		Producer: "Product B adapter emitting untrusted proposals", Consumers: []string{"triage.IngestProposal", "deterministic verifier", "AnalysisCase provenance"},
		Artifact:      "proposal-ingest.jsonl",
		Compatibility: "exact match; foreign/stale envelopes rejected at the boundary",
		ReplayRule:    "payload_digest verified before identity; provenance only — never mints Claim/NV/Verdict",
		Phase:         "2-3 (S-16)", Ported: true,
	},
	{
		Version: "decision-package.v4", Owner: "product-b-policy",
		Producer: "triage.Composer", Consumers: []string{"triage.RenderDecisionMarkdown", "triage.EvaluateMachineAutomation", "triage.PrepareReplay", "triage.WriteHumanDecision", "triage.ProjectVEX", "triage.EvaluateDecisionPackage"},
		Artifact:      "decision.json",
		Compatibility: "exact live match; judgment, action, support, human review plan and machine disposition are separate; decision-package.v3 with assessment.v2 has explicit historical playback only, no upgrade",
		ReplayRule:    "branch universe and per-branch support recomputed from captured inputs; bounded questions and premise closure; historical bytes/schema retained; no Product A verdict mutation",
		Phase:         "3 (S-08)", Ported: true,
	},
	{
		Version: "human-decision.v2", Owner: "product-b-human-decision",
		Producer: "triage.ArtifactWriter.WriteHumanDecision", Consumers: []string{"triage.ReadHumanDecisions", "replay", "audit"},
		Artifact:      "human-decisions/<record-id>.json",
		Compatibility: "exact live v2 binding package, branch, projection and assertion IDs; optional comment and system reason code; original v1 decoder retained for historical records",
		ReplayRule:    "review history copied verbatim; replay never creates a new Accept/Reject or applies a latest-record-wins policy",
		Phase:         "3 (phase 1 human result)", Ported: true,
	},
	{
		Version: "human-decision.v1", Owner: "product-b-human-decision",
		Producer: "historical review writer only", Consumers: []string{"triage.ReadHumanDecisions", "replay"},
		Artifact: "human-decisions/<record-id>.json",
		Compatibility: "historical original hash and required reason validation only beside historical packages; forbidden beside current v4; cannot carry v2 branch semantics",
		ReplayRule: "copy original bytes without upgrading authority or timestamps",
		Phase: "3 (historical phase 1 human result)", Ported: true,
	},
	{
		Version: "environment-assertion.v1", Owner: "product-b-human-decision",
		Producer: "triage.ArtifactWriter.WriteEnvironmentAnswers", Consumers: []string{"triage.ApplyEnvironmentAssertions", "triage.ReadHumanDecisions", "replay"},
		Artifact: "environment-assertions/<id>.json",
		Compatibility: "strict package-bound content-addressed human premises; explicit supersession; never code claims or machine authority",
		ReplayRule: "validate captured contract, reselect prepared branch offline, copy original bytes verbatim without new timestamps",
		Phase: "3 (phase 1 human result)", Ported: true,
	},
	{
		Version: "triage-baselines.v1", Owner: "product-b-policy",
		Producer: "operator/CI external controls", Consumers: []string{"offline evaluator (izyan eval triage)"},
		Artifact:      "triage-baselines.json",
		Compatibility: "exact match; expected_judgment is optional",
		ReplayRule:    "consumed only by offline evaluation; live triage and replay never load a baseline and never require external ground truth",
		Phase:         "3 (phase 1 human result)", Ported: true,
	},
	{
		Version: "triage-metrics.v3", Owner: "product-b-observability",
		Producer: "triage runner", Consumers: []string{"metrics aggregation"},
		Artifact:      "metrics.json",
		Compatibility: "exact match",
		ReplayRule:    "observational only: technical errors, drift, replay, stability, tool volume and separate human/machine distributions stay separate; no external-control comparison or false-safe claim",
		Phase:         "3 (S-08b)", Ported: true,
	},
	{
		Version: "triage-evaluation.v1", Owner: "product-b-observability",
		Producer: "offline evaluator (izyan eval triage)", Consumers: []string{"offline evaluation lane", "release decision"},
		Artifact:      "evaluation.json",
		Compatibility: "exact match; strict field set; ASSESSED/UNASSESSED coverage distinguishes measured from absent comparison",
		ReplayRule:    "offline only: compares one verified saved package with external controls; never read by live triage/replay and never feeds labels back into the product",
		Phase:         "3 (phase 1 human result)", Ported: true,
	},
	{
		Version: "triage-vex-projection.v1", Owner: "product-b-policy",
		Producer: "VEX projection", Consumers: []string{"reports (non-authoritative only)"},
		Artifact:      "triage-vex.json",
		Compatibility: "exact match; triage_only=true required", ReplayRule: "default-off; never authoritative for Product A VEX",
		Phase: "3 (S-08)", Ported: true,
	},
	{
		Version: "raw-agent.v1", Owner: "product-b-runtime",
		Producer: "triage runner", Consumers: []string{"replay", "audit"},
		Artifact:      "raw-agent.json",
		Compatibility: "exact match", ReplayRule: "transcript stored verbatim; refusal/technical error persisted separately",
		Phase: "3", Ported: true,
	},
	{
		Version: "triage-error.v1", Owner: "product-b-runtime",
		Producer: "triage runner error path", Consumers: []string{"report", "metrics"},
		Artifact:      "error.json",
		Compatibility: "exact match", ReplayRule: "technical failure marker; never substitutes for assessment.json",
		Phase: "3", Ported: true,
	},
	{
		Version: "replay.v2", Owner: "product-b-replay",
		Producer: "replay manifest writer", Consumers: []string{"replay runner"},
		Artifact:      "replay manifest",
		Compatibility: "exact match; replay.v1 is history-only and is rejected by the live replay path with an unsupported-version error",
		ReplayRule:    "no network/LLM replay; the recorded judgment and proposed action are preserved, the premise/support and machine-admissibility axes are re-derived and compared separately, and no attempt is selected best-of",
		Phase:         "3 (S-09)", Ported: true,
	},
	{
		Version: "stability-runs.v2", Owner: "product-b-replay",
		Producer: "stability runner", Consumers: []string{"replay", "metrics"},
		Artifact:      "stability-runs.json",
		Compatibility: "exact match; stability-runs.v1 is history-only and is rejected by the live replay path with an unsupported-version error",
		ReplayRule:    "judgment, human action, decisive-premise/support and machine disposition project on separate axes; every attempt is retained and attempt ids isolate observation id spaces",
		Phase:         "3 (S-09)", Ported: true,
	},
	// --- S-11 heldout gate: offline validation artifact only; the gate
	// measures, never enables — capability stays default-off. ---
	{
		Version: "heldout-gate.v1", Owner: "product-b-validation",
		Producer: "heldout gate runner", Consumers: []string{"eval/heldout lane", "release decision"},
		Artifact:      "heldout-gate.json",
		Compatibility: "exact match", ReplayRule: "offline corpus replay only; exit 1 on any hard-gate violation, 2 on input/config error",
		Phase: "4 (S-11)", Ported: true,
	},
	// --- S-13 deployment/assumption adapter: projection artifact; the
	// lane records basis disjointness, never enables a verdict. ---
	{
		Version: "deployment-projection.v1", Owner: "product-b-deployment-adapter",
		Producer: "deployment projection builder", Consumers: []string{"composer", "policy", "report"},
		Artifact:      "deployment-projection.json",
		Compatibility: "exact match", ReplayRule: "disjoint basis lanes; missing manifests leave perimeter unknown; declared-trust admission is the canonical gate",
		Phase: "4 (S-13)", Ported: true,
	},
	// --- S-12 research lane: non-authoritative artifacts; the lane's
	// outputs never feed Product A verdict/case/VEX state. ---
	{
		Version: "izyan-refindex/1", Owner: "product-b-research",
		Producer: "refindex builder / izyan-refindex", Consumers: []string{"research/eval lane"},
		Artifact:      "refindex.json",
		Compatibility: "exact match", ReplayRule: "canonical marshaling: re-run on unchanged inputs is byte-identical",
		Phase: "4 (S-12)", Ported: true,
	},
	{
		Version: "izyan-reportcheck/1", Owner: "product-b-research",
		Producer: "reportcheck grounding verifier", Consumers: []string{"research/eval lane", "root-cause scorer"},
		Artifact:      "reportcheck.json",
		Compatibility: "exact match", ReplayRule: "grounding failure is a limitation/error, never a safe-negative",
		Phase: "4 (S-12)", Ported: true,
	},
	{
		Version: "izyan-research-audit/1", Owner: "product-b-research",
		Producer: "research lane audit writer", Consumers: []string{"research/eval lane"},
		Artifact:      "research-audit.json",
		Compatibility: "exact match", ReplayRule: "frozen prompt/model/identity hashes retained; replay is offline",
		Phase: "4 (S-12)", Ported: true,
	},
	{
		Version: "vex-triage-run.v1", Owner: "product-b-measurement",
		Producer: "eval vex-triage execute", Consumers: []string{"offline evaluation lane", "scorer"},
		Artifact:      "vex-triage-run.json",
		Compatibility: "exact match; input-bundle hash, exact prompt and tool surface, versioned pins and observed usage required",
		ReplayRule:    "offline replay reproduces provenance pins without executing model arm",
		Phase:         "5 (measurement lane)", Ported: true,
	},
	{
		Version: "triage-review-event.v1", Owner: "product-b-measurement",
		Producer: "blinded review study / reviewer interface", Consumers: []string{"scorer", "metrics evaluator"},
		Artifact:      "review-events.jsonl",
		Compatibility: "exact match; bound to canonical decision-package hash",
		ReplayRule:    "blinded human review events are immutable audit evidence",
		Phase:         "5 (measurement lane)", Ported: true,
	},
	{
		Version: "triage-score.v1", Owner: "product-b-measurement",
		Producer: "eval vex-triage score", Consumers: []string{"offline evaluation lane", "scorer"},
		Artifact:      "triage-score.json",
		Compatibility: "exact match; separate authority, recommendation and automation axes",
		ReplayRule:    "deterministic projection over verified artifacts and review events",
		Phase:         "5 (measurement lane)", Ported: true,
	},
}

// Schemas returns every declared Product B schema in registry order.
func Schemas() []SchemaDecl {
	return append([]SchemaDecl(nil), registry...)
}

// Lookup returns the declaration for an exact schema version.
func Lookup(version string) (SchemaDecl, bool) {
	for _, d := range registry {
		if d.Version == version {
			return d, true
		}
	}
	return SchemaDecl{}, false
}

// MustLookup is Lookup that fails the process on an undeclared version:
// an adapter that emits an undeclared schema is a defect, not a fallback.
func MustLookup(version string) SchemaDecl {
	d, ok := Lookup(version)
	if !ok {
		panic(fmt.Sprintf("productb: schema %q is not in the S-17 registry", version))
	}
	return d
}
