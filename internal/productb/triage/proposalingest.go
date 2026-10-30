package triage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// ProposalIngestSchemaVersion is the only accepted ingest envelope schema.
const ProposalIngestSchemaVersion = "proposal-ingest.v1"

// ProposalKind names the family of payload the envelope carries. The set
// is deliberately open-ended: kinds the deterministic verifier does not
// consume are stored as provenance and rejected downstream — the ingest
// layer identifies them, it does not interpret them.
type ProposalKind string

const (
	// ProposalKindFalsifier carries a falsifier verification request
	// (falsifier-verification.v1 payload) for the deterministic verifier.
	ProposalKindFalsifier ProposalKind = "falsifier"
	// ProposalKindTriage carries a Product B recommendation/projection
	// payload kept for provenance; it is never an authority input.
	ProposalKindTriage ProposalKind = "triage"
	// ProposalKindObservation carries an observation/artifact reference
	// proposal (e.g. a ref-selection or intake record).
	ProposalKindObservation ProposalKind = "observation"
)

// ProposalIngest is the B→A proposal envelope (§14.3.5). Product B emits
// proposals untrusted: the envelope binds them to the run they claim to
// belong to — case, advisory, snapshot and the exact condition catalog
// hash — before anything downstream sees the payload.
type ProposalIngest struct {
	SchemaVersion        string          `json:"schema_version"`
	ProposalID           string          `json:"proposal_id"`
	ProposalKind         string          `json:"proposal_kind"`
	CaseIdentityRef      string          `json:"case_identity_ref"`
	AdvisoryDigest       string          `json:"advisory_digest"`
	SnapshotDigest       string          `json:"snapshot_digest"`
	ConditionCatalogHash string          `json:"condition_catalog_hash"`
	Payload              json.RawMessage `json:"payload"`
	// Source names the producing surface (adapter component, run stage)
	// for provenance — never for trust.
	Source string `json:"source"`
	// PayloadDigest is the lowercase hex sha256 of payload. A tampered
	// payload invalidates the envelope before identity is checked.
	PayloadDigest string `json:"payload_digest"`
}

// RunIdentity is the run-side binding the ingest checks every proposal
// against: the case/advisory/snapshot the run is bound to plus the exact
// condition catalog hash that is part of run identity and replay.
// Every field is required — a zero or partial binding disables the check
// and admits nothing: the boundary always sets all four before ingest.
type RunIdentity struct {
	CaseIdentityRef      string
	AdvisoryDigest       string
	SnapshotDigest       string
	ConditionCatalogHash string
}

// validateRunIdentity enforces the complete binding: a run that cannot
// name its case, advisory, snapshot and catalog hash cannot check a
// proposal's foreign status at all, so ingest fails closed.
func validateRunIdentity(run RunIdentity) error {
	missing := []string{}
	for _, c := range []struct{ field, value string }{
		{"case_identity_ref", run.CaseIdentityRef},
		{"advisory_digest", run.AdvisoryDigest},
		{"snapshot_digest", run.SnapshotDigest},
		{"condition_catalog_hash", run.ConditionCatalogHash},
	} {
		if strings.TrimSpace(c.value) == "" {
			missing = append(missing, c.field)
		}
	}
	if len(missing) > 0 {
		return ingestReject("run_identity", "run binding is incomplete (missing %s); a partial binding cannot verify foreign status", strings.Join(missing, ","))
	}
	return nil
}

// ProposalProvenance is what ingestion produces: the verified identity
// binding and the payload bytes. It is stored as provenance on the case
// and handed — only — to the deterministic verifier. It never carries
// authority: no Claim.FALSE, no NegativeVerification.VERIFIED and no
// Verdict is ever constructed here.
type ProposalProvenance struct {
	ProposalID           string          `json:"proposal_id"`
	ProposalKind         string          `json:"proposal_kind"`
	CaseIdentityRef      string          `json:"case_identity_ref"`
	AdvisoryDigest       string          `json:"advisory_digest"`
	SnapshotDigest       string          `json:"snapshot_digest"`
	ConditionCatalogHash string          `json:"condition_catalog_hash"`
	Source               string          `json:"source"`
	Payload              json.RawMessage `json:"-"`
	PayloadDigest        string          `json:"payload_digest"`
}

// IngestError is a typed ingest rejection: Field names the identity or
// integrity field that failed. Every ingest failure is non-admitting —
// ErrNonAdmitting unwraps so callers classify without parsing text.
type IngestError struct {
	Field  string
	Reason string
}

func (e *IngestError) Error() string {
	return fmt.Sprintf("proposal ingest rejected: %s", e.Reason)
}

// Unwrap exposes ErrNonAdmitting: a rejected proposal is not admissible
// input for the run.
func (e *IngestError) Unwrap() error { return ErrNonAdmitting }

func ingestReject(field, format string, args ...any) *IngestError {
	return &IngestError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// Validate checks the envelope contract: exact schema version and every
// binding/identity field present. Empty payloads are rejected — a proposal
// without a payload has nothing to verify.
func (p ProposalIngest) Validate() error {
	if p.SchemaVersion != ProposalIngestSchemaVersion {
		return ingestReject("schema_version", "schema_version %q is not %s", p.SchemaVersion, ProposalIngestSchemaVersion)
	}
	checks := []struct {
		field, value string
	}{
		{"proposal_id", p.ProposalID},
		{"proposal_kind", p.ProposalKind},
		{"case_identity_ref", p.CaseIdentityRef},
		{"advisory_digest", p.AdvisoryDigest},
		{"snapshot_digest", p.SnapshotDigest},
		{"condition_catalog_hash", p.ConditionCatalogHash},
		{"source", p.Source},
		{"payload_digest", p.PayloadDigest},
	}
	for _, c := range checks {
		if strings.TrimSpace(c.value) == "" {
			return ingestReject(c.field, "%s is required", c.field)
		}
	}
	if len(bytes.TrimSpace(p.Payload)) == 0 {
		return ingestReject("payload", "payload is empty")
	}
	return nil
}

// VerifyPayloadDigest reports whether the recorded digest matches the
// payload bytes.
func (p ProposalIngest) VerifyPayloadDigest() bool {
	sum := sha256.Sum256(p.Payload)
	return strings.EqualFold(hex.EncodeToString(sum[:]), p.PayloadDigest)
}

// DecodeProposalIngest strictly decodes a proposal-ingest.v1 envelope:
// unknown fields, a wrong schema version or missing bindings all fail
// before the run-side identity check ever runs.
func DecodeProposalIngest(data []byte) (ProposalIngest, error) {
	var p ProposalIngest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, ingestReject("decode", "malformed envelope: %v", err)
	}
	if dec.More() {
		return p, ingestReject("decode", "trailing JSON values after the envelope")
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

// SignPayloadDigest recomputes and pins the payload digest — the
// producer-side counterpart of VerifyPayloadDigest.
func (p *ProposalIngest) SignPayloadDigest() {
	sum := sha256.Sum256(p.Payload)
	p.PayloadDigest = hex.EncodeToString(sum[:])
}

// IngestProposal verifies an untrusted proposal envelope against the run
// identity it claims to belong to. Every mismatch is a rejection:
//
//   - a tampered payload (digest mismatch) is rejected before identity;
//   - a foreign case/advisory/snapshot binding is a foreign proposal;
//   - a condition catalog hash that differs from the run's pin is stale.
//
// A verified envelope yields ProposalProvenance only — the deterministic
// verifier consumes the payload, the case stores the record. Ingest never
// touches authority: nothing here can mint a Claim, a negative
// verification or a verdict.
func IngestProposal(raw json.RawMessage, run RunIdentity) (*ProposalProvenance, error) {
	var p ProposalIngest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, ingestReject("decode", "malformed envelope: %v", err)
	}
	if dec.More() {
		return nil, ingestReject("decode", "trailing JSON values after the envelope")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !p.VerifyPayloadDigest() {
		return nil, ingestReject("payload_digest", "payload digest does not match the payload bytes")
	}
	if err := validateRunIdentity(run); err != nil {
		return nil, err
	}
	// Case identity is an exact reference; digests compare
	// case-insensitively because producers may emit either hex case.
	if p.CaseIdentityRef != run.CaseIdentityRef {
		return nil, ingestReject("case_identity_ref", "case_identity_ref %q does not match the run binding %q", p.CaseIdentityRef, run.CaseIdentityRef)
	}
	digests := []struct {
		field, got, want string
	}{
		{"advisory_digest", p.AdvisoryDigest, run.AdvisoryDigest},
		{"snapshot_digest", p.SnapshotDigest, run.SnapshotDigest},
		{"condition_catalog_hash", p.ConditionCatalogHash, run.ConditionCatalogHash},
	}
	for _, id := range digests {
		if !strings.EqualFold(id.got, id.want) {
			return nil, ingestReject(id.field, "%s %q does not match the run binding %q", id.field, id.got, id.want)
		}
	}
	return &ProposalProvenance{
		ProposalID:           p.ProposalID,
		ProposalKind:         p.ProposalKind,
		CaseIdentityRef:      p.CaseIdentityRef,
		AdvisoryDigest:       p.AdvisoryDigest,
		SnapshotDigest:       p.SnapshotDigest,
		ConditionCatalogHash: p.ConditionCatalogHash,
		Source:               p.Source,
		Payload:              p.Payload,
		PayloadDigest:        p.PayloadDigest,
	}, nil
}
