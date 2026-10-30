package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// sha256Sum returns the lowercase hex sha256 of b — the digest form the
// "sha256:<hex>" member pins carry.
func sha256Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DeclaredAssumptionsSchema is the only schema a declared-assumptions
// document may carry. The channel holds human-owned policy/scope
// assertions — administrator configuration trust and the supported
// product target matrix — that deterministic code evidence cannot
// decide. Assumptions are typed inputs: they never enter the evidence
// graph, never become EvidenceKind members or verified facts, and an
// admitted assumption alone never produces a verdict. A policy gate may
// require an admissible assumption, but the gate's own deterministic
// proof does the closing; a missing, malformed, expired,
// digest-mismatched or scope-mismatched assumption fails closed.
const DeclaredAssumptionsSchema = "declared-assumptions/1"

// MaxDeclaredAssumptions bounds the members of one document — a run
// needs the policy assertions the operator actually declared, not an
// unbounded assertion list.
const MaxDeclaredAssumptions = 64

type DeclaredAssumptionKind string

const (
	// AssumptionConfigTrust asserts that administrator-managed
	// configuration is outside the attacker model for the declared
	// scope. Without an admitted config-trust assumption a
	// configuration-origin falsifier may not ground a negative verdict:
	// Origin=CONFIGURATION stays a provenance fact, not the policy.
	AssumptionConfigTrust DeclaredAssumptionKind = "config-trust"
	// AssumptionSupportedTargets declares the target platform matrix a
	// product or artifact supports. Only the "product" scope states the
	// complete supported-target set — an artifact-scoped declaration
	// describes one build and can never close a product-wide claim.
	AssumptionSupportedTargets DeclaredAssumptionKind = "supported-targets"
)

// Scope vocabulary. An assumption's Scope names what its statement
// applies to; admission requires the declared scope to cover the scope
// a consumer asks for. "product" is the widest scope and covers every
// narrower one; narrower scopes never widen to cover "product".
const (
	AssumptionScopeProduct    = "product"    // the whole product: every artifact, deployment and config surface
	AssumptionScopeArtifact   = "artifact"   // one analyzed artifact only — never product-wide
	AssumptionScopeDeployment = "deployment" // one deployment/installation
	// AssumptionScopeConfigPrefix scopes an assumption to a named
	// configuration surface, e.g. "config:app-settings.yaml".
	AssumptionScopeConfigPrefix = "config:"
)

var (
	assumptionIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	assumptionRefRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	assumptionGOOSRe   = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)
	assumptionGOARCHRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,31}$`)
	assumptionTagRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._=-]{0,63}$`)
	// AssumptionDigestRe is the digest pin shape every declared member
	// and the document content digest must carry.
	AssumptionDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	assumptionDateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// ValidAssumptionScope reports whether s is a well-formed scope string:
// one of the named scopes or a "config:<ref>" surface.
func ValidAssumptionScope(s string) bool {
	switch s {
	case AssumptionScopeProduct, AssumptionScopeArtifact, AssumptionScopeDeployment:
		return true
	}
	return strings.HasPrefix(s, AssumptionScopeConfigPrefix) &&
		assumptionRefRe.MatchString(strings.TrimPrefix(s, AssumptionScopeConfigPrefix))
}

// ScopeCovers reports whether a declared scope satisfies a required
// scope. "product" covers every narrower scope — a product-wide
// statement applies to each of its artifacts, deployments and config
// surfaces. Every other scope covers only itself: an artifact-only or
// deployment-scoped declaration can never satisfy a product-wide
// requirement, and a named config surface covers only that exact
// surface.
func ScopeCovers(scope, required string) bool {
	if scope == required {
		return true
	}
	return scope == AssumptionScopeProduct
}

// ProductTargetScope is the closed target matrix a supported-targets
// assumption declares. Under "product" scope the member set is the
// complete supported matrix — every supported product artifact targets
// one of these GOOS values; under "artifact" scope it is the single
// build target of one artifact.
type ProductTargetScope struct {
	GOOS      []string `json:"goos"`
	GOARCH    []string `json:"goarch,omitempty"`
	BuildTags []string `json:"build_tags,omitempty"`
}

// DeclaredAssumption is one typed policy/scope assertion. Every member
// is explicit: an assumption without a bound statement, scope,
// authority, owner, source reference, digest pin or review date is
// malformed and fails closed.
type DeclaredAssumption struct {
	ID        string                 `json:"id"`
	Kind      DeclaredAssumptionKind `json:"kind"`
	Statement string                 `json:"statement"`
	Scope     string                 `json:"scope"`
	Authority string                 `json:"authority"`
	Owner     string                 `json:"owner"`
	SourceRef string                 `json:"source_ref"`
	// Digest pins this assumption's canonical form (sha256 of the member
	// without its digest). The document's content_digest and the intake
	// sha256 pin the bytes around it.
	Digest     string `json:"digest"`
	ValidFrom  string `json:"valid_from,omitempty"`
	ReviewDate string `json:"review_date"`
	// Targets is required for supported-targets and forbidden for
	// config-trust — kind/scope/member consistency is part of the
	// document contract.
	Targets *ProductTargetScope `json:"targets,omitempty"`
}

// DeclaredAssumptionsDocument is the strict declared-assumptions/1
// shape. The member set is closed: unknown keys are rejected at intake.
type DeclaredAssumptionsDocument struct {
	Schema string `json:"schema"`
	// ContentDigest pins the canonical content (schema + every declared
	// member): an edited statement with a stale digest is a
	// digest-mismatch rejection, not a new assertion.
	ContentDigest string               `json:"content_digest"`
	Assumptions   []DeclaredAssumption `json:"assumptions"`
}

// DeclaredAssumptionsInput is the persisted channel record: provenance
// (sanitized path + sha256 of the exact file bytes), the validated
// members when intake accepted the document, or the typed LoadError
// when it failed closed. It is carried on AnalysisCase and projected
// into research input — never into EvidenceGraph.Evidence.
type DeclaredAssumptionsInput struct {
	Path   string `json:"path"` // provenance only: local:<basename>
	SHA256 string `json:"sha256,omitempty"`
	Schema string `json:"schema,omitempty"`
	// ContentDigest is the document's declared digest pin, recorded for
	// audit; LoadError is the typed channel outcome (ASSUMPTIONS_*) when
	// intake rejected the document — the members are still carried for
	// the audit record but admission never reaches them.
	ContentDigest string               `json:"content_digest,omitempty"`
	Assumptions   []DeclaredAssumption `json:"assumptions,omitempty"`
	LoadError     string               `json:"load_error,omitempty"`
}

// Document projects the record back into the loaded-document view;
// nil when the channel failed closed or declared nothing.
func (in *DeclaredAssumptionsInput) Document() *DeclaredAssumptionsDocument {
	if in == nil || in.LoadError != "" || len(in.Assumptions) == 0 {
		return nil
	}
	return &DeclaredAssumptionsDocument{
		Schema:        in.Schema,
		ContentDigest: in.ContentDigest,
		Assumptions:   in.Assumptions,
	}
}

// AssumptionIDs lists the declared ids in document order — the
// reference space AssumptionIDs members resolve against.
func (in *DeclaredAssumptionsInput) AssumptionIDs() []string {
	var ids []string
	for _, a := range in.Assumptions {
		ids = append(ids, a.ID)
	}
	return ids
}

// assumptionContentWire is the canonical content the document's
// content_digest pins: every member except the digest itself.
type assumptionContentWire struct {
	Schema      string               `json:"schema"`
	Assumptions []DeclaredAssumption `json:"assumptions"`
}

// CanonicalAssumptionDigest recomputes a member's declared digest: the
// sha256 of its canonical JSON with the digest member blanked.
func CanonicalAssumptionDigest(a DeclaredAssumption) string {
	a.Digest = ""
	b, _ := json.Marshal(a)
	sum := sha256Sum(b)
	return "sha256:" + sum
}

// DeclaredAssumptionsContentDigest recomputes the document's declared
// content digest: the sha256 of the canonical {schema, assumptions}
// form — member order is significant.
func DeclaredAssumptionsContentDigest(schema string, assumptions []DeclaredAssumption) string {
	b, _ := json.Marshal(assumptionContentWire{Schema: schema, Assumptions: assumptions})
	return "sha256:" + sha256Sum(b)
}

// assumptionDate parses a strict YYYY-MM-DD date; timestamps and
// other layouts are rejected.
func assumptionDate(s string) (time.Time, bool) {
	if !assumptionDateRe.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// boundedAssumptionText requires non-empty UTF-8 text within the
// member bound and free of control characters — members render into
// reports, so no embedded markup/control material is admitted.
func boundedAssumptionText(v string, max int) bool {
	if v == "" || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidateDeclaredAssumption checks one member: id/kind/scope shape,
// required fields, date members, kind↔scope↔targets consistency and
// the digest pin. It returns *AssumptionRejection.
func ValidateDeclaredAssumption(a DeclaredAssumption) error {
	reject := func(detail string) error {
		return &AssumptionRejection{Reason: AssumptionRejectMalformed, ID: a.ID, Detail: detail}
	}
	if !assumptionIDRe.MatchString(a.ID) {
		return reject("id must match " + assumptionIDRe.String())
	}
	if a.Kind != AssumptionConfigTrust && a.Kind != AssumptionSupportedTargets {
		return reject(fmt.Sprintf("kind %q is unsupported", a.Kind))
	}
	for _, f := range []struct {
		name, v string
		max     int
	}{
		{"statement", a.Statement, 2048},
		{"authority", a.Authority, 256},
		{"owner", a.Owner, 256},
		{"source_ref", a.SourceRef, 512},
	} {
		if !boundedAssumptionText(f.v, f.max) {
			return reject(f.name + " must be non-empty bounded text")
		}
	}
	if !ValidAssumptionScope(a.Scope) {
		return reject(fmt.Sprintf("scope %q is not a valid assumption scope", a.Scope))
	}
	switch a.Kind {
	case AssumptionConfigTrust:
		if a.Scope == AssumptionScopeArtifact {
			return reject("config-trust cannot be scoped to a single artifact: one build is not a deployment trust boundary")
		}
		if a.Targets != nil {
			return reject("config-trust carries no target matrix — targets belongs to supported-targets")
		}
	case AssumptionSupportedTargets:
		if strings.HasPrefix(a.Scope, AssumptionScopeConfigPrefix) {
			return reject("supported-targets cannot be scoped to a configuration surface")
		}
		if a.Targets == nil {
			return reject("supported-targets requires a targets member")
		}
		if err := validateProductTargetScope(a.Scope, *a.Targets); err != nil {
			return err
		}
	}
	if a.ValidFrom != "" {
		if _, ok := assumptionDate(a.ValidFrom); !ok {
			return reject("valid_from must be a YYYY-MM-DD date")
		}
	}
	rev, ok := assumptionDate(a.ReviewDate)
	if !ok {
		return reject("review_date must be a YYYY-MM-DD date")
	}
	if from, fromOK := assumptionDate(a.ValidFrom); a.ValidFrom != "" && fromOK && from.After(rev) {
		return reject("valid_from is after review_date")
	}
	if !AssumptionDigestRe.MatchString(a.Digest) ||
		CanonicalAssumptionDigest(a) != a.Digest {
		return &AssumptionRejection{Reason: AssumptionRejectDigestMismatch, ID: a.ID,
			Detail: "digest does not match the assumption's canonical form"}
	}
	return nil
}

// validateProductTargetScope enforces the closed target matrix: a
// non-empty bounded enumeration of valid platform names, and exactly
// one GOOS under artifact scope (one build has one target).
func validateProductTargetScope(scope string, t ProductTargetScope) error {
	reject := func(detail string) error {
		return &AssumptionRejection{Reason: AssumptionRejectMalformed, Detail: detail}
	}
	if len(t.GOOS) == 0 {
		return reject("targets.goos must name at least one supported OS — an empty enumeration is never a closed target set")
	}
	if len(t.GOOS) > 16 || len(t.GOARCH) > 16 || len(t.BuildTags) > 32 {
		return reject("targets member exceeds the closed enumeration bound")
	}
	seen := map[string]bool{}
	for _, g := range t.GOOS {
		if !assumptionGOOSRe.MatchString(g) || seen[g] {
			return reject(fmt.Sprintf("targets.goos entry %q is invalid or duplicated", g))
		}
		seen[g] = true
	}
	for _, g := range t.GOARCH {
		if !assumptionGOARCHRe.MatchString(g) {
			return reject(fmt.Sprintf("targets.goarch entry %q is invalid", g))
		}
	}
	for _, tg := range t.BuildTags {
		if !assumptionTagRe.MatchString(tg) {
			return reject(fmt.Sprintf("targets.build_tags entry %q is invalid", tg))
		}
	}
	if scope == AssumptionScopeArtifact && len(t.GOOS) != 1 {
		return reject("an artifact-scoped target set names exactly one GOOS — one build has one target")
	}
	return nil
}

// ValidateDeclaredAssumptions checks a whole document: schema, member
// bound, unique ids, per-member validity and the content digest pin.
// It returns *AssumptionRejection.
func ValidateDeclaredAssumptions(doc *DeclaredAssumptionsDocument) error {
	if doc == nil {
		return &AssumptionRejection{Reason: AssumptionRejectDocumentAbsent,
			Detail: "no assumptions document"}
	}
	if doc.Schema != DeclaredAssumptionsSchema {
		return &AssumptionRejection{Reason: AssumptionRejectMalformed,
			Detail: fmt.Sprintf("schema %q != %q", doc.Schema, DeclaredAssumptionsSchema)}
	}
	if len(doc.Assumptions) == 0 || len(doc.Assumptions) > MaxDeclaredAssumptions {
		return &AssumptionRejection{Reason: AssumptionRejectMalformed,
			Detail: fmt.Sprintf("assumptions must declare 1..%d members, got %d",
				MaxDeclaredAssumptions, len(doc.Assumptions))}
	}
	seen := map[string]bool{}
	for _, a := range doc.Assumptions {
		if err := ValidateDeclaredAssumption(a); err != nil {
			return err
		}
		if seen[a.ID] {
			return &AssumptionRejection{Reason: AssumptionRejectMalformed, ID: a.ID,
				Detail: "duplicate assumption id"}
		}
		seen[a.ID] = true
	}
	if !AssumptionDigestRe.MatchString(doc.ContentDigest) ||
		DeclaredAssumptionsContentDigest(doc.Schema, doc.Assumptions) != doc.ContentDigest {
		return &AssumptionRejection{Reason: AssumptionRejectDigestMismatch,
			Detail: "content_digest does not match the document's canonical content"}
	}
	return nil
}

// AssumptionRejection is the typed fail-closed admission/validation
// outcome: a named reason plus the assumption id and the rejected
// requirement when known. Rejections are audit material — never a
// silent pass.
type AssumptionRejection struct {
	Reason string                 `json:"reason"`
	Kind   DeclaredAssumptionKind `json:"kind,omitempty"`
	Scope  string                 `json:"scope,omitempty"`
	ID     string                 `json:"id,omitempty"`
	Detail string                 `json:"detail,omitempty"`
}

func (e *AssumptionRejection) Error() string {
	s := e.Reason
	if e.ID != "" {
		s += " (" + e.ID + ")"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// AssumptionRejectionReason extracts the named rejection reason; ""
// for a non-rejection error.
func AssumptionRejectionReason(err error) string {
	var rej *AssumptionRejection
	if errors.As(err, &rej) {
		return rej.Reason
	}
	return ""
}

// Rejection reasons.
const (
	AssumptionRejectDocumentAbsent  = "ASSUMPTION_DOCUMENT_ABSENT"
	AssumptionRejectDocumentInvalid = "ASSUMPTION_DOCUMENT_INVALID"
	AssumptionRejectAbsent          = "ASSUMPTION_ABSENT"
	AssumptionRejectScopeMismatch   = "ASSUMPTION_SCOPE_MISMATCH"
	AssumptionRejectMalformed       = "ASSUMPTION_MALFORMED"
	AssumptionRejectDigestMismatch  = "ASSUMPTION_DIGEST_MISMATCH"
	AssumptionRejectNotYetValid     = "ASSUMPTION_NOT_YET_VALID"
	AssumptionRejectExpired         = "ASSUMPTION_EXPIRED"
)

// Load-error codes recorded on DeclaredAssumptionsInput.LoadError —
// the intake channel's own fail-closed taxonomy.
const (
	AssumptionsLoadUnreadable = "ASSUMPTIONS_UNREADABLE"
	AssumptionsLoadOversized  = "ASSUMPTIONS_OVERSIZED"
	AssumptionsLoadInvalid    = "ASSUMPTIONS_INVALID"
)

// AdmitAssumption is the policy gate for consuming a declared
// assumption: the record must have loaded, an assumption of the
// required kind must declare a scope covering requiredScope, and the
// member must still validate and be within its validity window at now.
// Every failure path returns a named *AssumptionRejection — admission
// is how an assumption enters a decision, so nothing inadmissible may
// silently satisfy a policy requirement.
func AdmitAssumption(in *DeclaredAssumptionsInput, kind DeclaredAssumptionKind, requiredScope string, now time.Time) (DeclaredAssumption, error) {
	if in == nil {
		return DeclaredAssumption{}, &AssumptionRejection{
			Reason: AssumptionRejectDocumentAbsent, Kind: kind, Scope: requiredScope,
			Detail: "no declared-assumptions document was supplied"}
	}
	if in.LoadError != "" {
		return DeclaredAssumption{}, &AssumptionRejection{
			Reason: AssumptionRejectDocumentInvalid, Kind: kind, Scope: requiredScope,
			Detail: "declared-assumptions document failed intake: " + in.LoadError}
	}
	if !ValidAssumptionScope(requiredScope) {
		return DeclaredAssumption{}, &AssumptionRejection{
			Reason: AssumptionRejectMalformed, Kind: kind, Scope: requiredScope,
			Detail: fmt.Sprintf("required scope %q is not a valid assumption scope", requiredScope)}
	}
	today := now.UTC().Truncate(24 * time.Hour)
	var expired, pending *AssumptionRejection
	kindPresent := false
	for _, a := range in.Assumptions {
		if a.Kind != kind {
			continue
		}
		kindPresent = true
		if !ScopeCovers(a.Scope, requiredScope) {
			continue
		}
		if err := ValidateDeclaredAssumption(a); err != nil {
			var rej *AssumptionRejection
			if errors.As(err, &rej) {
				r := *rej
				r.Kind, r.Scope = kind, requiredScope
				return DeclaredAssumption{}, &r
			}
			return DeclaredAssumption{}, err
		}
		if vf, ok := assumptionDate(a.ValidFrom); a.ValidFrom != "" && ok && today.Before(vf) {
			if pending == nil {
				pending = &AssumptionRejection{Reason: AssumptionRejectNotYetValid,
					Kind: kind, Scope: requiredScope, ID: a.ID,
					Detail: "valid_from " + a.ValidFrom + " is in the future"}
			}
			continue
		}
		if rd, _ := assumptionDate(a.ReviewDate); today.After(rd) {
			if expired == nil {
				expired = &AssumptionRejection{Reason: AssumptionRejectExpired,
					Kind: kind, Scope: requiredScope, ID: a.ID,
					Detail: "review_date " + a.ReviewDate + " has passed"}
			}
			continue
		}
		return a, nil
	}
	switch {
	case expired != nil:
		return DeclaredAssumption{}, expired
	case pending != nil:
		return DeclaredAssumption{}, pending
	case kindPresent:
		return DeclaredAssumption{}, &AssumptionRejection{
			Reason: AssumptionRejectScopeMismatch, Kind: kind, Scope: requiredScope,
			Detail: fmt.Sprintf("no %s assumption covers required scope %q", kind, requiredScope)}
	default:
		return DeclaredAssumption{}, &AssumptionRejection{
			Reason: AssumptionRejectAbsent, Kind: kind, Scope: requiredScope,
			Detail: fmt.Sprintf("no %s assumption is declared", kind)}
	}
}
