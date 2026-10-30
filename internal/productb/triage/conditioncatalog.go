package triage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ConditionCatalogSchemaVersion is the only accepted catalog schema.
const ConditionCatalogSchemaVersion = "condition-catalog.v1"

// ErrUnsupported marks a condition (or a check kind) the catalog does not
// declare: unknown condition ids and falsifier kinds not allowed by the
// owning entry stay UNSUPPORTED — they are never guessed or mapped.
var ErrUnsupported = errors.New("unsupported")

// ErrNonAdmitting marks input that cannot be admitted at all: no catalog,
// a stale/tampered catalog, or a catalog bound to another advisory or
// case. Everything in the run fails closed.
var ErrNonAdmitting = errors.New("non-admitting")

// CatalogSubject is one package/symbol pair a catalog condition may be
// checked on. Role carries the deterministic binding context (e.g.
// "mandatory-control"); it never carries semantic force on its own.
type CatalogSubject struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol,omitempty"`
	Role    string `json:"role,omitempty"`
}

// CatalogCondition is one deterministic condition entry of the catalog:
// the stable condition_id the exploit-model/checker path minted, the
// subjects it binds, the checker identity that owns it, and the closed
// set of falsifier kinds allowed to verify it.
type CatalogCondition struct {
	ConditionID string `json:"condition_id"`
	// Kind names the condition family the checker owns (signal presence,
	// guard shape, missing call...). Opaque to this layer: the checker
	// universe belongs to Product A; unknown kinds stay bound to their
	// declared checker rather than being reinterpreted here.
	Kind                  string           `json:"kind"`
	Mandatory             bool             `json:"mandatory"`
	Subjects              []CatalogSubject `json:"subjects,omitempty"`
	ArgumentOrRoleBinding string           `json:"argument_or_role_binding,omitempty"`
	CheckerID             string           `json:"checker_id"`
	CheckerVersion        string           `json:"checker_version"`
	AllowedFalsifierKinds []FalsifierKind  `json:"allowed_falsifier_kinds"`
	CoverageRule          string           `json:"coverage_rule"`
}

// ConditionCatalog is the A→B mandatory-condition artifact (§14.3.4): the
// canonical, hash-pinned condition universe one advisory exposes to
// Product B. Product A's deterministic exploit-model/checker path (or an
// approved registry) produces it; Product B consumes it read-only.
// Advisory prose and LLM reasoning never create catalog entries.
type ConditionCatalog struct {
	SchemaVersion   string             `json:"schema_version"`
	CatalogID       string             `json:"catalog_id"`
	AdvisoryID      string             `json:"advisory_id"`
	AdvisoryDigest  string             `json:"advisory_digest"`
	CaseIdentityRef string             `json:"case_identity_ref"`
	Conditions      []CatalogCondition `json:"conditions"`
	// CatalogHash is the lowercase hex sha256 of the canonical catalog
	// encoding (every field except the hash itself). It is part of run
	// identity and replay: a catalog whose content drifted from its pin
	// is stale and admits nothing.
	CatalogHash string `json:"catalog_hash"`
}

// canonicalCatalog is the hash preimage: every catalog field except the
// hash itself, in declared order. Condition order is significant — the
// producer signs the order it ships.
type canonicalCatalog struct {
	SchemaVersion   string             `json:"schema_version"`
	CatalogID       string             `json:"catalog_id"`
	AdvisoryID      string             `json:"advisory_id"`
	AdvisoryDigest  string             `json:"advisory_digest"`
	CaseIdentityRef string             `json:"case_identity_ref"`
	Conditions      []CatalogCondition `json:"conditions"`
}

func (c ConditionCatalog) canonical() canonicalCatalog {
	return canonicalCatalog{
		SchemaVersion:   c.SchemaVersion,
		CatalogID:       c.CatalogID,
		AdvisoryID:      c.AdvisoryID,
		AdvisoryDigest:  c.AdvisoryDigest,
		CaseIdentityRef: c.CaseIdentityRef,
		Conditions:      c.Conditions,
	}
}

// ComputeHash returns the canonical catalog hash: sha256 over the
// deterministic marshal of every field except catalog_hash itself.
func (c ConditionCatalog) ComputeHash() string {
	b, err := json.Marshal(c.canonical())
	if err != nil {
		// The catalog is marshal-safe by construction; a failure is a
		// defect, and a defect must never produce a usable hash.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Sign recomputes and pins the catalog hash. The producing checker path
// calls it after building the catalog; consumers verify rather than sign.
func (c *ConditionCatalog) Sign() {
	c.CatalogHash = c.ComputeHash()
}

// VerifyHash reports whether the recorded hash matches the canonical
// content. A catalog with no pin, or a pin that does not match, fails.
func (c ConditionCatalog) VerifyHash() bool {
	want := c.ComputeHash()
	return want != "" && strings.EqualFold(c.CatalogHash, want)
}

// Validate checks the catalog contract: exact schema version, identity
// fields present, and every condition carrying the fields its checker
// needs — condition_id, kind, checker identity, a coverage rule and a
// non-empty allowed falsifier-kind set drawn from the closed enum.
// An empty condition list is valid: it admits nothing, which is the
// strictest possible catalog.
func (c ConditionCatalog) Validate() error {
	if c.SchemaVersion != ConditionCatalogSchemaVersion {
		return fmt.Errorf("condition catalog schema_version %q is not %s", c.SchemaVersion, ConditionCatalogSchemaVersion)
	}
	if strings.TrimSpace(c.CatalogID) == "" {
		return errors.New("condition catalog requires catalog_id")
	}
	if strings.TrimSpace(c.AdvisoryID) == "" {
		return errors.New("condition catalog requires advisory_id")
	}
	if strings.TrimSpace(c.AdvisoryDigest) == "" {
		return errors.New("condition catalog requires advisory_digest")
	}
	if strings.TrimSpace(c.CaseIdentityRef) == "" {
		return errors.New("condition catalog requires case_identity_ref")
	}
	seen := map[string]bool{}
	for i, cond := range c.Conditions {
		if strings.TrimSpace(cond.ConditionID) == "" {
			return fmt.Errorf("condition catalog entry %d has no condition_id", i)
		}
		if seen[cond.ConditionID] {
			return fmt.Errorf("condition catalog has duplicate condition_id %q", cond.ConditionID)
		}
		seen[cond.ConditionID] = true
		if strings.TrimSpace(cond.Kind) == "" {
			return fmt.Errorf("condition %q has no kind", cond.ConditionID)
		}
		if strings.TrimSpace(cond.CheckerID) == "" {
			return fmt.Errorf("condition %q has no checker_id", cond.ConditionID)
		}
		if strings.TrimSpace(cond.CheckerVersion) == "" {
			return fmt.Errorf("condition %q has no checker_version", cond.ConditionID)
		}
		if strings.TrimSpace(cond.CoverageRule) == "" {
			return fmt.Errorf("condition %q has no coverage_rule", cond.ConditionID)
		}
		if len(cond.AllowedFalsifierKinds) == 0 {
			return fmt.Errorf("condition %q allows no falsifier kinds", cond.ConditionID)
		}
		for _, k := range cond.AllowedFalsifierKinds {
			if !k.Valid() {
				return fmt.Errorf("condition %q declares unknown falsifier kind %q", cond.ConditionID, k)
			}
		}
	}
	return nil
}

// DecodeConditionCatalog strictly decodes a condition-catalog.v1 document:
// unknown fields, a wrong schema version, structural violations or a hash
// that does not match the canonical content all fail — a catalog that
// cannot verify admits nothing downstream either.
func DecodeConditionCatalog(data []byte) (ConditionCatalog, error) {
	var c ConditionCatalog
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("condition catalog decode: %w", err)
	}
	if dec.More() {
		return c, errors.New("condition catalog: trailing JSON values after the document")
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	if strings.TrimSpace(c.CatalogHash) == "" {
		return c, errors.New("condition catalog has no catalog_hash pin")
	}
	if !c.VerifyHash() {
		return c, errors.New("condition catalog hash does not match the canonical content")
	}
	return c, nil
}

// Lookup returns the catalog entry for an exact condition_id.
func (c ConditionCatalog) Lookup(conditionID string) (CatalogCondition, bool) {
	for _, cond := range c.Conditions {
		if cond.ConditionID == conditionID {
			return cond, true
		}
	}
	return CatalogCondition{}, false
}

// AllowsFalsifierKind reports whether the entry permits the check kind —
// the closed allowed set is the contract: a kind the catalog does not
// name is unsupported, never defaulted to the kind's own validity.
func (cond CatalogCondition) AllowsFalsifierKind(k FalsifierKind) bool {
	for _, allowed := range cond.AllowedFalsifierKinds {
		if allowed == k {
			return true
		}
	}
	return false
}

// CatalogBinding is the run-side identity the catalog must match: the
// advisory and case it was produced for, plus the catalog hash pinned in
// run identity and replay. Every field is required — a zero or partial
// binding disables the foreign/stale checks it claims to perform, so the
// boundary always sets all four before admission.
type CatalogBinding struct {
	AdvisoryID          string
	AdvisoryDigest      string
	CaseIdentityRef     string
	ExpectedCatalogHash string
}

// validate enforces the complete binding: an empty case/advisory/digest or
// catalog-hash pin cannot detect a foreign or stale catalog — the check
// it skipped is the one an attacker would need.
func (b CatalogBinding) validate() error {
	missing := []string{}
	for _, c := range []struct{ field, value string }{
		{"advisory_id", b.AdvisoryID},
		{"advisory_digest", b.AdvisoryDigest},
		{"case_identity_ref", b.CaseIdentityRef},
		{"expected_catalog_hash", b.ExpectedCatalogHash},
	} {
		if strings.TrimSpace(c.value) == "" {
			missing = append(missing, c.field)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: catalog binding is incomplete (missing %s); a partial binding cannot detect a foreign or stale catalog", ErrNonAdmitting, strings.Join(missing, ","))
	}
	return nil
}

// CheckCatalog verifies the catalog is the one this run binds to: a nil or
// unverifiable catalog is non-admitting, an incomplete binding is
// non-admitting, an advisory or case mismatch is a foreign catalog, and a
// hash differing from the run's pin is stale. The catalog's own hash must
// verify in every case.
func (b CatalogBinding) CheckCatalog(c *ConditionCatalog) error {
	if err := b.validate(); err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("%w: no condition catalog is bound to this run", ErrNonAdmitting)
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: condition catalog is not well-formed: %v", ErrNonAdmitting, err)
	}
	if !c.VerifyHash() {
		return fmt.Errorf("%w: condition catalog hash does not match its content (stale or tampered)", ErrNonAdmitting)
	}
	if !strings.EqualFold(b.ExpectedCatalogHash, c.CatalogHash) {
		return fmt.Errorf("%w: condition catalog hash %q is not the run-pinned %q", ErrNonAdmitting, c.CatalogHash, b.ExpectedCatalogHash)
	}
	if b.AdvisoryID != c.AdvisoryID {
		return fmt.Errorf("%w: condition catalog advisory %q is not the run advisory %q", ErrNonAdmitting, c.AdvisoryID, b.AdvisoryID)
	}
	if !strings.EqualFold(b.AdvisoryDigest, c.AdvisoryDigest) {
		return fmt.Errorf("%w: condition catalog advisory digest does not match the run", ErrNonAdmitting)
	}
	if b.CaseIdentityRef != c.CaseIdentityRef {
		return fmt.Errorf("%w: condition catalog case %q is not the run case %q", ErrNonAdmitting, c.CaseIdentityRef, b.CaseIdentityRef)
	}
	return nil
}

// AdmitFalsifierProposal binds a decoded falsifier proposal to the
// catalog: the run must carry a verifiable catalog, the proposal's
// condition_id must name a catalog entry, and the proposal's kind must be
// in that entry's allowed set. The returned entry is the deterministic
// binding the verifier checks — never the proposal's own claims.
//
// Unknown condition ids and disallowed kinds return ErrUnsupported:
// structurally admissible run, unsupported condition. Every catalog-level
// failure returns ErrNonAdmitting: nothing in the run can be checked.
func AdmitFalsifierProposal(c *ConditionCatalog, bind CatalogBinding, p FalsifierProposal) (CatalogCondition, error) {
	if err := bind.CheckCatalog(c); err != nil {
		return CatalogCondition{}, err
	}
	cond, ok := c.Lookup(p.ConditionID)
	if !ok {
		return CatalogCondition{}, fmt.Errorf("%w: condition_id %q is not in condition-catalog.v1 %q", ErrUnsupported, p.ConditionID, c.CatalogID)
	}
	// A falsifier that fails a non-mandatory condition can never block a
	// negative recommendation, so admitting it would mint verification
	// credit the run cannot use. Only mandatory conditions admit.
	if !cond.Mandatory {
		return CatalogCondition{}, fmt.Errorf("%w: condition %q is not mandatory; a falsifier for it can never discharge a mandatory claim", ErrUnsupported, p.ConditionID)
	}
	if !cond.AllowsFalsifierKind(p.Kind) {
		return CatalogCondition{}, fmt.Errorf("%w: falsifier kind %q is not allowed for condition %q", ErrUnsupported, p.Kind, p.ConditionID)
	}
	return cond, nil
}

// CatalogBindingSchemaVersion names the persisted binding artifact: the
// run-side identity the catalog was checked against. Replay and audit
// load this document instead of guessing the run's catalog expectation.
const CatalogBindingSchemaVersion = "catalog-binding.v1"

// CatalogBindingDocument is the persisted form of the run's catalog
// binding (catalog-binding.v1). `catalog_present` records whether a
// condition-catalog.v1 document rode the run at all: an absent catalog
// with a recorded binding still fails admission closed on replay —
// never an empty gate.
type CatalogBindingDocument struct {
	SchemaVersion       string `json:"schema_version"`
	AdvisoryID          string `json:"advisory_id"`
	AdvisoryDigest      string `json:"advisory_digest"`
	CaseIdentityRef     string `json:"case_identity_ref"`
	ExpectedCatalogHash string `json:"expected_catalog_hash"`
	CatalogPresent      bool   `json:"catalog_present"`
}

// Document renders the run binding into its persisted form.
func (b CatalogBinding) Document(catalogPresent bool) CatalogBindingDocument {
	return CatalogBindingDocument{
		SchemaVersion:       CatalogBindingSchemaVersion,
		AdvisoryID:          b.AdvisoryID,
		AdvisoryDigest:      b.AdvisoryDigest,
		CaseIdentityRef:     b.CaseIdentityRef,
		ExpectedCatalogHash: b.ExpectedCatalogHash,
		CatalogPresent:      catalogPresent,
	}
}

// Binding decodes a persisted document back into the run-side binding.
// An absent catalog (`catalog_present=false`) keeps the binding fields —
// CheckCatalog then fails closed on the missing catalog exactly the way
// the live run did.
func (d CatalogBindingDocument) Binding() CatalogBinding {
	return CatalogBinding{
		AdvisoryID:          d.AdvisoryID,
		AdvisoryDigest:      d.AdvisoryDigest,
		CaseIdentityRef:     d.CaseIdentityRef,
		ExpectedCatalogHash: d.ExpectedCatalogHash,
	}
}

// CatalogAdmission is the partition of the agent's falsifier proposals
// the run-pinned catalog produced: Admitted goes to the deterministic
// verifier, Rejected already carries the recorded non-admitted proof for
// the report. Live and replay must produce byte-identical rejections, so
// both call GateFalsifierProposals — never their own rejection spelling.
type CatalogAdmission struct {
	Admitted []FalsifierProposal
	Rejected []FalsifierProof
}

// GateFalsifierProposals is the single catalog-admission point for live
// and replay paths: the run's binding must check against the catalog,
// then every proposal must name a mandatory catalog condition whose
// allowed kinds cover the proposal's. A catalog-level failure rejects
// every proposal with the binding's reason; a per-proposal failure
// rejects just that one. Rejections mint an explicit non-admitted proof
// so the falsifier report records the refusal — admission never drops a
// proposal silently.
func GateFalsifierProposals(c *ConditionCatalog, bind CatalogBinding, proposals []FalsifierProposal) CatalogAdmission {
	out := CatalogAdmission{
		Admitted: make([]FalsifierProposal, 0, len(proposals)),
		Rejected: make([]FalsifierProof, 0, len(proposals)),
	}
	reject := func(p FalsifierProposal, reason string) {
		pr := FalsifierProof{
			ID: p.ID, ProposalID: p.ID, ClaimID: p.ClaimID, ConditionID: p.ConditionID,
			Kind: p.Kind, Status: FalsifierUnknown, Basis: BasisUnsupported,
			Reason: "falsifier proposal not admitted: " + reason,
		}
		pr.History = []FalsifierTransition{{From: FalsifierUnknown, To: FalsifierUnknown, Reason: pr.Reason}}
		out.Rejected = append(out.Rejected, pr)
	}
	if catErr := bind.CheckCatalog(c); catErr != nil {
		for _, p := range proposals {
			reject(p, catErr.Error())
		}
		return out
	}
	for _, p := range proposals {
		if _, aerr := AdmitFalsifierProposal(c, bind, p); aerr != nil {
			reject(p, aerr.Error())
			continue
		}
		out.Admitted = append(out.Admitted, p)
	}
	return out
}

// ProposalCapabilities is the agent-facing answer to "which machine
// falsifier proposals can this run admit?". It is derived only from a
// successfully bound, supplied condition-catalog.v1: a missing, stale,
// foreign or unverifiable catalog yields no conditions and the exact
// reason, never an advisory-derived guess. The agent may omit proposals
// entirely; an empty or unavailable capability is a proof-capability
// limitation, not a contract defect in the assessment.
type ProposalCapabilities struct {
	CatalogHash       string             `json:"catalog_hash,omitempty"`
	Conditions        []CatalogCondition `json:"conditions,omitempty"`
	UnavailableReason string             `json:"unavailable_reason,omitempty"`
}

// Specified reports whether the capabilities describe a real catalog
// answer. The zero value means "not reported" (a historical replay
// reconstruction); live runs always report either conditions or a reason.
func (p ProposalCapabilities) Specified() bool {
	return p.CatalogHash != "" || len(p.Conditions) > 0 || p.UnavailableReason != ""
}

// BuildProposalCapabilities projects the catalog only after the run-side
// binding accepts it. An absent or non-admitting catalog returns the
// post-filter capability set — empty conditions plus the honest reason —
// so prompt and tool surfaces can state that machine falsifier proposals
// are unavailable instead of advertising an advisory-derived condition
// that admission would reject. Only mandatory entries are projected: the
// gate never admits a proposal for a non-mandatory condition.
func BuildProposalCapabilities(c *ConditionCatalog, bind CatalogBinding) ProposalCapabilities {
	if c == nil {
		return ProposalCapabilities{UnavailableReason: "no condition catalog is bound to this run"}
	}
	if err := bind.CheckCatalog(c); err != nil {
		return ProposalCapabilities{UnavailableReason: err.Error()}
	}
	caps := ProposalCapabilities{CatalogHash: c.CatalogHash}
	for _, cond := range c.Conditions {
		if !cond.Mandatory {
			continue
		}
		caps.Conditions = append(caps.Conditions, cond)
	}
	if len(caps.Conditions) == 0 {
		caps.UnavailableReason = fmt.Sprintf("condition catalog %q declares no mandatory condition", c.CatalogID)
	}
	return caps
}
