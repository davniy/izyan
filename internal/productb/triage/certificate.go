package triage

import (
	"fmt"
)

// certificate contract. The set is closed so callers can map classes onto
// their own reason vocabulary (a check gate renders text; the entailment
// graph maps classes onto admission gap names).
type ProofViolationClass string

const (
	ViolationIdentity        ProofViolationClass = "identity_incomplete"
	ViolationKind            ProofViolationClass = "kind_invalid"
	ViolationNoProposal      ProofViolationClass = "proposal_missing"
	ViolationBindingMismatch ProofViolationClass = "binding_mismatch"
	ViolationBasis           ProofViolationClass = "basis_not_checker"
	ViolationMandatory       ProofViolationClass = "condition_not_mandatory"
	ViolationCompleteness    ProofViolationClass = "coverage_incomplete"
	ViolationSubjectSet      ProofViolationClass = "subject_set_mismatch"
	ViolationOpenScope       ProofViolationClass = "scope_open"
	ViolationEvidence        ProofViolationClass = "evidence_missing"
	ViolationBuildContext    ProofViolationClass = "build_context_missing"
	ViolationForeignSnapshot ProofViolationClass = "snapshot_foreign"
	ViolationCapability      ProofViolationClass = "capability_contract"
	ViolationTransition      ProofViolationClass = "transition_invalid"
	ViolationReportSchema    ProofViolationClass = "report_schema"
	ViolationReportHash      ProofViolationClass = "report_hash"
)

// ProofViolation records one concrete breach of the certificate contract.
// Reason and Repair carry the audit-facing text; Class carries the
// machine-stable category.
type ProofViolation struct {
	Class  ProofViolationClass
	Reason string
	Repair string
}

// CheckerMintedProof reports whether a proof carries no agent proposal by
// construction: the certificate was minted by a deterministic checker that
// recorded its own rule identity. The predicate is generic — any
// checker-verified proof with an empty proposal id and a named rule —
// because the admission contract asks "who vouches for this certificate",
// not "which tool emitted it". A proposal-less proof without basis and
// rule identity is not checker-minted: it is an orphaned certificate.
func CheckerMintedProof(p FalsifierProof) bool {
	return p.ProposalID == "" && p.Basis == BasisCheckerVerified && p.RuleID != ""
}

// capabilityCoverageValidators is the closed registry of capability-
// specific admission validators of the certificate contract, keyed by the
// falsifier kind the capability answers. The generic contract (binding,
// hash, provenance, transitions) is capability-independent; the coverage
// record of a VERIFIED proof must additionally satisfy the contract of
// the capability that minted it. Kinds without an entry have no extra
// capability requirements today.
var capabilityCoverageValidators = map[FalsifierKind]func(FalsifierCoverage) error{
	FalsifierCodeAbsent: validateAdmittingCodeAbsenceCoverage,
}

// ValidateProofCertificate enforces the generic proof certificate
// contract on one persisted proof: certificate identity, binding to the
// proposal it answers (or the checker-minted exemption), the VERIFIED
// admission contract (checker basis, mandatory condition, complete
// coverage over the full subject set, closed scope, evidence and
// provenance pins), valid status transitions and the capability-specific
// coverage validator of the proof's kind.
//
// proposals maps proposal id → the proposal the run persisted; it may be
// nil when the caller cannot enumerate proposals (a checker-minted proof
// is then the only proposal-less shape that can pass). snap is the
// snapshot identity the certificate must be bound to; an empty snap skips
// the cross-snapshot check exactly like the gate does.
//
// The returned violations carry the same reason/repair text the C14 gate
// reports; the check consumes them verbatim so both layers enforce one
// contract.
func ValidateProofCertificate(p FalsifierProof, proposals map[string]FalsifierProposal, snap string) []ProofViolation {
	var out []ProofViolation
	add := func(class ProofViolationClass, reason, repair string) {
		out = append(out, ProofViolation{Class: class, Reason: reason, Repair: repair})
	}
	if p.ID == "" || p.ConditionID == "" {
		add(ViolationIdentity, "proof certificate has an incomplete identity (id/condition)", "re-issue the certificate with its full identity")
	}
	if !p.Kind.Valid() {
		add(ViolationKind, fmt.Sprintf("proof %s has invalid kind %q", p.ID, p.Kind), "re-issue the certificate under a declared falsifier kind")
	}

	// Binding: a certificate answers either a persisted proposal or is
	// minted by a deterministic checker. A checker-minted proof has no
	// LLM proposal by construction; its authority is the rule identity.
	if proposals != nil {
		proposal, ok := proposals[p.ID]
		if !ok && !CheckerMintedProof(p) {
			add(ViolationNoProposal,
				fmt.Sprintf("proof %s has no persisted proposal", p.ID),
				"persist exactly the proposals the verifier answered")
			return out
		}
		if !ok {
			proposal = FalsifierProposal{ID: p.ID, ClaimID: p.ClaimID, ConditionID: p.ConditionID, Kind: p.Kind}
		}
		if proposal.ClaimID != p.ClaimID || proposal.ConditionID != p.ConditionID || proposal.Kind != p.Kind {
			add(ViolationBindingMismatch,
				fmt.Sprintf("proof %s does not bind proposal %s (claim/condition/kind)", p.ID, proposal.ID),
				"re-run the verifier over the persisted proposal")
		}
	} else if p.ProposalID != "" && !CheckerMintedProof(p) {
		// Without a proposal index a proposal-bound certificate cannot
		// be bound at all — the binding check stays open and the
		// certificate fails closed.
		add(ViolationNoProposal,
			fmt.Sprintf("proof %s names proposal %s but no proposal index is available", p.ID, p.ProposalID),
			"verify the certificate against the persisted proposals")
	}

	if p.Status == FalsifierVerified {
		if p.Basis != BasisCheckerVerified {
			add(ViolationBasis,
				fmt.Sprintf("proof %s is VERIFIED with basis %q", p.ID, p.Basis),
				"VERIFIED may only come from the deterministic checker")
		}
		if !p.Mandatory {
			add(ViolationMandatory,
				fmt.Sprintf("proof %s is VERIFIED but not bound to a mandatory condition", p.ID),
				"resolve the condition through the deterministic mandatory source")
		}
		if p.Coverage.Completeness != "COMPLETE" {
			add(ViolationCompleteness,
				fmt.Sprintf("proof %s is VERIFIED with completeness %q", p.ID, p.Coverage.Completeness),
				"a partial scope can never be VERIFIED")
		}
		if !sameSubjects(p.Coverage.ExpectedSubjects, p.Coverage.CheckedSubjects) {
			add(ViolationSubjectSet,
				fmt.Sprintf("proof %s has a subject set that does not match the checked set", p.ID),
				"re-check every expected subject before admitting")
		}
		if len(p.Coverage.SkippedPackages) > 0 || len(p.Coverage.UnresolvedDispatch) > 0 || len(p.Coverage.DynamicMarkers) > 0 {
			add(ViolationOpenScope,
				fmt.Sprintf("proof %s is VERIFIED with unresolved scope or dynamic markers", p.ID),
				"close the scope gaps before admitting")
		}
		if len(p.EvidenceRefs) == 0 {
			add(ViolationEvidence,
				fmt.Sprintf("proof %s is VERIFIED without evidence references", p.ID),
				"cite the validated evidence the checker consumed")
		}
		if p.Coverage.BuildContextHash == "" {
			add(ViolationBuildContext,
				fmt.Sprintf("proof %s is VERIFIED without a build-context binding", p.ID),
				"bind the proof to the snapshot's build context")
		}
		if snap != "" && p.Coverage.SnapshotHash != "" && p.Coverage.SnapshotHash != snap {
			add(ViolationForeignSnapshot,
				fmt.Sprintf("proof %s is bound to snapshot %s, not the package snapshot", p.ID, p.Coverage.SnapshotHash),
				"re-run the verifier against this snapshot")
		}
		if validator, ok := capabilityCoverageValidators[p.Kind]; ok {
			if err := validator(p.Coverage); err != nil {
				add(ViolationCapability,
					fmt.Sprintf("proof %s has non-admitting %s coverage: %v", p.ID, p.Kind, err),
					"re-run the capability's check under its admission contract")
			}
		}
	}
	for j, tr := range p.History {
		if tr.From == "" || tr.To != p.Status {
			add(ViolationTransition,
				fmt.Sprintf("proof %s history[%d] is not a valid transition", p.ID, j),
				"record every status change with its source status")
		}
	}
	return out
}

// ValidateProofReport checks the report-level certificate bindings: the
// persisted schema and the canonical content hash. Proof-level checks
// live in ValidateProofCertificate; admitted-fact and package bindings
// stay with the caller (they are decision-layer relations, not
// certificate integrity).
func ValidateProofReport(r FalsifierReport) []ProofViolation {
	var out []ProofViolation
	if r.SchemaVersion != FalsifierVerificationSchemaVersion {
		out = append(out, ProofViolation{
			Class:  ViolationReportSchema,
			Reason: fmt.Sprintf("falsifier report schema_version %q is not %s", r.SchemaVersion, FalsifierVerificationSchemaVersion),
			Repair: "persist the report in the verifier's own schema",
		})
	}
	if r.Hash == "" || r.Hash != reportHash(r) {
		out = append(out, ProofViolation{
			Class:  ViolationReportHash,
			Reason: "falsifier report hash does not match its content",
			Repair: "recompute the report hash from the persisted proofs",
		})
	}
	return out
}

// CanonicalFalsifierReportHash recomputes the canonical content hash of a
// falsifier report: the hash field itself is excluded so recomputation is
// idempotent. Exported so proof consumers outside the package — the
// entailment graph's certificate capability — can verify persisted
// reports instead of trusting the stored value.
func CanonicalFalsifierReportHash(r FalsifierReport) string {
	return reportHash(r)
}
