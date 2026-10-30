// Package verification implements the generic capability and observation
// contract of docs/dev/plans/universal-verifier-plan.md §5/§5.1 (Task 2).
//
// The package turns `claim → capability → observation` into deterministic
// mechanics: a closed capability registry declares, per claim shape, which
// observation results a capability may produce, which direction requires a
// closed scope, which dynamic gaps block admission and which provenance
// fields are mandatory. Recorded tool observations are interpreted into the
// contract's Observation shape — hash-bound to run, snapshot, build
// context, scope and tool version — and an observation is never a proof:
// admission is decided by the generic contract, not by the producing tool.
//
// Hard boundaries, per the plan's Global Constraints:
//
//   - no rule names a package, advisory, symbol or symptom — capabilities
//     are keyed on claim shapes and tool result structure only;
//   - PARTIAL/UNKNOWN completeness never admits the universal direction
//     of a predicate (no closed-scope absence/unreachability/closure
//     conclusion on partial evidence);
//   - a claim without admitted observations stays UNKNOWN;
//   - replay over a persisted run reproduces the identical report without
//     any LLM call — evaluation is a pure function of the recorded
//     artifacts;
//   - the adversarial reviewer channel contributes only challenge
//     proposals: each is normalized into a canonical claim and passes
//     through the identical capability/observation/entailment cycle —
//     a reviewer can never mint a proof, an outcome or a verdict, and
//     the ordering of proposals can never change the graph hash or
//     the decision (plan §3, §6.4);
//   - a falsifier never stands while admitted evidence in its own
//     provenance context establishes the opposite value or an
//     unresolved conflict on a covering claim — conflicts are
//     recorded and contested, never resolved by vote (plan §6.4);
//   - reduction (DISMISSED/LOWERED) is permitted only when the
//     decisive surface — conditions, falsifiers, rules, decision,
//     proof certificates, conflict state — is identical across
//     bounded re-derivations sharing the same provenance pins;
//     provenance drift demotes unconditionally, decisive instability
//     demotes to UNCHANGED, and no best attempt is ever selected
//     (plan §6.5);
//   - the package emits the deterministic graph decision for audit and
//     replay; production capability admission stays default-off — nothing
//     wires the compiled disposition into the live decision path.
package verify

import (
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
)

// ContractSchemaVersion identifies the persisted observation/report schema.
const ContractSchemaVersion = "verification-contract.v1"

// Result is the value one observation reports for the queried predicate,
// as produced by the capability that ran the check — before any admission
// rule is applied. ResultUNKNOWN covers checks that ran but cannot
// adjudicate the predicate (open search space, context-only data).
type Result string

const (
	ResultSupports    Result = "SUPPORTS"
	ResultRefutes     Result = "REFUTES"
	ResultUnknown     Result = "UNKNOWN"
	ResultConflicting Result = "CONFLICTING"
)

// Outcome is the per-claim value the deterministic evaluation assigns.
// ClaimOutcomeTrue/False compare the established predicate value with the
// polarity the claim asserted; the *predicate* outcome travels separately
// (PredicateOutcome) so a decision layer can never confuse "the claim was
// wrong" with "the unsafe fact holds".
type Outcome string

const (
	OutcomeTrue        Outcome = "TRUE"
	OutcomeFalse       Outcome = "FALSE"
	OutcomeUnknown     Outcome = "UNKNOWN"
	OutcomeConflicting Outcome = "CONFLICTING"
)

// PredicateOutcome is the established value of the claim's predicate over
// admitted observations: Holds (SUPPORTS admitted), Disproved (REFUTES
// admitted), unknown (nothing admitted) or conflicting.
type PredicateOutcome string

const (
	PredicateHolds       PredicateOutcome = "HOLDS"
	PredicateDisproved   PredicateOutcome = "DISPROVED"
	PredicateUnknown     PredicateOutcome = "UNKNOWN"
	PredicateConflicting PredicateOutcome = "CONFLICTING"
)

// Query records what a capability was asked: the shape predicate, the
// claim's canonical subject and the parameters the capability needed to
// form the check (never claim prose). Replay compares answers on the
// query tuple, not on free text.
type Query struct {
	Shape   claimshape.Shape   `json:"shape"`
	Subject claimshape.Subject `json:"subject,omitempty"`
	Tool    string             `json:"tool,omitempty"`
	// Params carries structured query parameters (module, site, origin
	// class) — sorted, hashable content only.
	Params map[string]string `json:"params,omitempty"`
}

// Observation is the contract object of plan §5.1. It binds a capability
// answer to its provenance: run identity, snapshot hash, build-context
// hash, the hash of the closed scope it claims, the producing tool's
// version and the payload hash of the recorded tool result it interprets.
// An Observation is evidence, never a proof; admission is decided by the
// capability contract plus the generic admission rule.
type Observation struct {
	ID           string                     `json:"id"`
	Capability   string                     `json:"capability"`
	Query        Query                      `json:"query"`
	Result       Result                     `json:"result"`
	Completeness evidencetools.Completeness `json:"completeness"`
	// ClosedScope marks observations whose producing check enumerated a
	// closed universe (import-closure membership, resolved package
	// declarations, dependency-graph membership). Universal-direction
	// admission requires Completeness COMPLETE *and* ClosedScope — a
	// local COMPLETE (one file, one function) is never a closed universe.
	ClosedScope      bool   `json:"closed_scope,omitempty"`
	ScopeHash        string `json:"scope_hash,omitempty"`
	SnapshotHash     string `json:"snapshot_hash,omitempty"`
	BuildContextHash string `json:"build_context_hash,omitempty"`
	ToolVersion      string `json:"tool_version"`
	RunID            string `json:"run_id,omitempty"`
	Attempt          int    `json:"attempt,omitempty"`
	SourceID         string `json:"source_id,omitempty"`
	PayloadHash      string `json:"payload_hash,omitempty"`
	// CoveredSubjects are the canonical subjects the observation's
	// structured payload provably covers (checked symbols, resolved
	// module, call site, traced origin).
	CoveredSubjects []claimshape.Subject `json:"covered_subjects,omitempty"`
	// SubjectRoles carries the role vocabulary the payload assigns to
	// covered subjects (e.g. the falsifier-subject role field): the
	// capability-level discriminator between a plain declaration absence
	// and a control/guard absence without reading prose.
	SubjectRoles []string `json:"subject_roles,omitempty"`
	// OpenGaps names dynamic/scope gaps the check itself recorded —
	// unresolved dispatch, open exceptions, skipped packages, unbounded
	// surfaces. Admission matches them against the contract's gap
	// blockers for the direction being established.
	OpenGaps     []string `json:"open_gaps,omitempty"`
	Limitations  []string `json:"limitations,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// ProvenanceField names one required provenance binding of an
// observation. The set is closed: admission checks fields by name.
type ProvenanceField string

const (
	ProvRunID        ProvenanceField = "run_id"
	ProvSnapshotHash ProvenanceField = "snapshot_hash"
	ProvBuildContext ProvenanceField = "build_context_hash"
	ProvScopeHash    ProvenanceField = "scope_hash"
	ProvToolVersion  ProvenanceField = "tool_version"
)

// provValue returns the observation's value for a provenance field.
func (o Observation) provValue(f ProvenanceField) string {
	switch f {
	case ProvRunID:
		return o.RunID
	case ProvSnapshotHash:
		return o.SnapshotHash
	case ProvBuildContext:
		return o.BuildContextHash
	case ProvScopeHash:
		return o.ScopeHash
	case ProvToolVersion:
		return o.ToolVersion
	}
	return ""
}
