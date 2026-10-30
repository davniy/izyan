package research

// This file carries the implementation-locus proposal intake channel:
// --implementation-locus-proposal <path> reads a typed
// implementation-locus-proposals/1 artifact and --replay-agent-turn
// reuses the proposals retained inside a persisted answer. Both feed
// the same ImplementationProposalsInput record: provenance, pinned
// digest, the admitted members or the fail-closed load error.
// Proposals are LLM-inferred hypotheses only — never evidence, never a
// verdict; the deterministic affected.VerifyImplementationLocus
// verifier remains the sole route to an implementation-presence fact.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/repository"
)

// ImplementationProposalsSchema is the proposal artifact's closed
// schema marker. The document carries only the machine-generated
// proposals themselves: binding to the frozen advisory happens through
// the declared advisory_sha256 member plus each proposal's own
// advisory reference and quoted span.
const ImplementationProposalsSchema = "implementation-locus-proposals/1"

// MaxImplementationProposalBytes bounds the artifact file: an operator
// supplies the few hypotheses the verifier can re-check, not an
// unbounded assertion set.
const MaxImplementationProposalBytes = 1 << 20 // 1 MiB

// Implementation proposal intake source labels. The persisted input
// record names exactly one: the operator-supplied artifact file or the
// proposals retained inside a replayed agent answer.
const (
	ImplementationProposalsSourceArtifact = "artifact-file"
	ImplementationProposalsSourceReplayed = "replayed-agent-turn"
)

// Proposal intake load errors. A failed channel admits nothing: the
// record keeps the typed outcome so every consumer sees the identical
// fail-closed result.
const (
	ImplementationProposalsLoadUnreadable = "UNREADABLE"
	ImplementationProposalsLoadOversized  = "OVERSIZED"
	ImplementationProposalsLoadInvalid    = "INVALID"
	ImplementationProposalsLoadMismatch   = "ADVISORY_MISMATCH"
)

// ImplementationProposalsInput is the implementation-locus proposal
// channel record carried on LaneResult and projected into
// input.implementation_locus_proposals. nil when the channel was never
// requested (no artifact flag and no retained replayed proposals) —
// lanes and reports stay exactly as before.
type ImplementationProposalsInput struct {
	// Source names where the proposals came from: artifact-file or
	// replayed-agent-turn.
	Source string `json:"source"`
	// Path is the sanitized local:<basename> provenance ref of the
	// operator-supplied artifact file. Empty for a replayed channel —
	// there is no operator file to name.
	Path string `json:"path,omitempty"`
	// SHA256 pins the exact artifact bytes for an artifact-file intake;
	// for a replayed intake it pins the retained answer the proposals
	// were re-admitted from. Empty for an unreadable artifact file.
	SHA256 string `json:"sha256,omitempty"`
	// AdvisorySHA256 pins the frozen advisory document the artifact
	// declared (and the lane verified). A mismatch is fail-closed:
	// LoadError=ADVISORY_MISMATCH and no member is admitted.
	AdvisorySHA256 string `json:"advisory_sha256,omitempty"`
	// RetainedAnswerSHA256 is the replayed channel's answer pin.
	RetainedAnswerSHA256 string `json:"retained_answer_sha256,omitempty"`
	// Proposals are the admitted members (agent quality, advisory-bound
	// quote). On a load failure the members stay for audit but must
	// never be consumed — LoadError non-empty means zero admissions.
	Proposals []domain.ImplementationLocusProposal `json:"proposals,omitempty"`
	// LoadError is the typed fail-closed intake outcome.
	LoadError string `json:"load_error,omitempty"`
}

// implementationProposalArtifact is the on-disk artifact document.
// Members outside the closed set fail decode — the channel contract is
// exact, not forgiving.
type implementationProposalArtifact struct {
	Schema         string                               `json:"schema"`
	AdvisorySHA256 string                               `json:"advisory_sha256"`
	Proposals      []domain.ImplementationLocusProposal `json:"proposals"`
}

// loadImplementationProposalArtifact reads and binds one
// implementation-locus-proposals/1 document: size bound, closed member
// set, exact schema, the pinned advisory digest, shape validation, and
// the same admission gate the agent path applies — advisory reference
// resolvable to the frozen document and a verbatim recorded quote.
// Every failure is a typed LoadError on the returned record; nil is
// returned only for an empty path (channel never requested).
func loadImplementationProposalArtifact(path string, adv *AdvisoryRecord) *ImplementationProposalsInput {
	if path == "" {
		return nil
	}
	rec := &ImplementationProposalsInput{
		Source: ImplementationProposalsSourceArtifact,
		Path:   repository.ProvenanceLocalRef(path),
	}
	fail := func(code string) *ImplementationProposalsInput {
		rec.LoadError = code
		return rec
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return fail(ImplementationProposalsLoadUnreadable)
	}
	if st.Size() > MaxImplementationProposalBytes {
		return fail(ImplementationProposalsLoadOversized)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(ImplementationProposalsLoadUnreadable)
	}
	sum := sha256.Sum256(raw)
	rec.SHA256 = hex.EncodeToString(sum[:])
	var doc implementationProposalArtifact
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fail(ImplementationProposalsLoadInvalid)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		// Trailing content: the document is not the closed artifact.
		return fail(ImplementationProposalsLoadInvalid)
	}
	rec.AdvisorySHA256 = doc.AdvisorySHA256
	if doc.Schema != ImplementationProposalsSchema {
		return fail(ImplementationProposalsLoadInvalid)
	}
	if adv == nil || doc.AdvisorySHA256 == "" ||
		(doc.AdvisorySHA256 != adv.Input.RawSHA256 && doc.AdvisorySHA256 != adv.Input.CanonicalSHA256) {
		// The artifact pins exactly the frozen advisory it was generated
		// against; a mismatched artifact admits nothing.
		return fail(ImplementationProposalsLoadMismatch)
	}
	if len(doc.Proposals) == 0 || len(doc.Proposals) > maxImplementationLocusProposals {
		return fail(ImplementationProposalsLoadInvalid)
	}
	for _, p := range doc.Proposals {
		if err := AdmitImplementationLocusProposal(p, adv); err != nil {
			return fail(ImplementationProposalsLoadInvalid)
		}
	}
	rec.Proposals = doc.Proposals
	return rec
}

// replayedImplementationProposals builds the channel record for
// proposals retained inside a replayed agent answer: they were
// extracted from the persisted answer bytes, so the pin is that
// answer's sha256 and re-admission at the dispatch point is identical
// to a live turn's — the replayed channel never weakens the gate.
func replayedImplementationProposals(proposals []domain.ImplementationLocusProposal, answerSHA256 string) *ImplementationProposalsInput {
	if len(proposals) == 0 {
		return nil
	}
	return &ImplementationProposalsInput{
		Source:               ImplementationProposalsSourceReplayed,
		SHA256:               answerSHA256,
		RetainedAnswerSHA256: answerSHA256,
		Proposals:            append([]domain.ImplementationLocusProposal(nil), proposals...),
	}
}
