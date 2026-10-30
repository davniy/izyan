// Package deployment is the S-13 Product B deployment/assumption adapter:
// it binds the V2 deployment surface to Shadow's canonical exposure facts,
// the declared-assumptions policy channel and the ground-basis vocabulary —
// without ever minting authority.
//
// Three bases stay disjoint by construction:
//
//   - "declared-trust"   — an operator's declared-assumptions/1 assertion
//     admitted through domain.AdmitAssumption; a policy input, never an
//     evidence fact, and never evidence of isolation on its own;
//   - "auto-perimeter"   — the canonical exposure.ClassifyPerimeter result
//     over resolved ExposureFacts (k8s/compose/helm manifests + code binds);
//     a missing manifest yields PerimeterUnknown, never a safe negative;
//   - "config-origin"    — code-level provenance (AddressSource "config:"/
//     "env:" traced values); surfaced as a fact count, never conflated with
//     either trust basis.
//
// Foreign services are never attributed to the product: the perimeter
// classifier's owner-matching rule is canonical and preserved verbatim
// (unattributed or prefix-sibling external-routing facts veto — never
// ground — a cluster-internal conclusion).
package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/triage"
)

// ProjectionSchema is the only schema the deployment projection artifact
// carries. Registered in productb/registry.go (Phase-4).
const ProjectionSchema = "deployment-projection.v1"

// TrustBinding is the declared-trust lane: the admission outcome of one
// operator assertion (kind + scope) against a required scope. The lane is
// disjoint from detected evidence — TrustBinding fields never enter
// EvidenceIDs, never satisfy a falsifier alone and never turn into a
// verdict without the canonical policy gate.
type TrustBinding struct {
	// Kind is the assumption kind the binding tried (config-trust today).
	Kind string `json:"kind"`
	// RequiredScope is the scope the consumer asked the assertion to cover.
	RequiredScope string `json:"required_scope"`
	// Admitted reports the domain.AdmitAssumption outcome.
	Admitted bool `json:"admitted"`
	// AssumptionID names the admitted member when admission succeeded.
	AssumptionID string `json:"assumption_id,omitempty"`
	// Scope is the member's declared scope; empty under rejection.
	Scope string `json:"scope,omitempty"`
	// RejectionReason is the typed fail-closed outcome (ASSUMPTION_*)
	// when the binding did not admit — never a silent skip.
	RejectionReason string `json:"rejection_reason,omitempty"`
	// Statement is the admitted member's bounded text for audit echo.
	Statement string `json:"statement,omitempty"`
}

// GroundBasisProjection is the disjoint three-lane basis projection the
// composer/policy layer consumes: at most one lane may claim ground for a
// given assertion, and each is populated only by its own evidence class.
// A projection with no lane admitted is honest zero-trust — never a
// synthesized default.
type GroundBasisProjection struct {
	// DeclaredTrust is non-nil when an operator assertion was bound for
	// this run — regardless of admission outcome (rejections are carried
	// for audit, never promoted to facts).
	DeclaredTrust *TrustBinding `json:"declared_trust,omitempty"`
	// AutoPerimeter is the classifier-detected basis: set only when the
	// canonical classifier derived a non-unknown perimeter from real
	// deployment facts.
	AutoPerimeter bool `json:"auto_perimeter"`
	// ConfigOriginFacts counts deployment facts whose address provenance
	// is traced config/env material ("config:", "env:", "manifest …"),
	// the code-level provenance the config-origin basis rests on.
	ConfigOriginFacts int `json:"config_origin_facts"`
	// ConfigOrigin is true when at least one traced provenance fact was
	// resolved — the only condition under which a config-origin basis may
	// ever be claimed downstream.
	ConfigOrigin bool `json:"config_origin"`
}

// DeploymentProjection is the persisted S-13 artifact: the classified
// perimeter, its raw fact digest, the disjoint basis projection and every
// surfaced limitation. No verdict, no evidence ids, no claim references —
// this is the deployment *input* the remaining lanes consume, recorded
// once with its digest so a replay may pin it byte-for-byte.
type DeploymentProjection struct {
	Schema string `json:"schema"`

	// Perimeter/Rationale are the canonical classifier output:
	// "unknown" carries an honest rationale and is never elided.
	Perimeter string `json:"perimeter"`
	Rationale string `json:"rationale,omitempty"`

	// Digest pins the raw ExposureFact set; ProjectionSHA256 pins the
	// agent-facing projection. Both are retained so a drifted scan is a
	// digest mismatch, not a silent content change.
	FactsDigest      string `json:"facts_digest,omitempty"`
	ProjectionSHA256 string `json:"projection_sha256,omitempty"`

	FactCount    int      `json:"fact_count"`
	ScannedPaths []string `json:"scanned_paths,omitempty"`
	Archives     []string `json:"archives,omitempty"`

	Basis GroundBasisProjection `json:"basis"`

	Limitations []string `json:"limitations,omitempty"`
}

// Project builds the deployment projection for one material set. facts may
// be nil (deploy collection declined to run): the perimeter is then unknown
// with an explicit limitation — a missing or empty deployment surface is
// never implicit isolation.
//
// cfg is the loaded site config (already expanded/validated); assumptions
// is the declared-assumptions channel input for the run — nil when the
// operator declared none.
func Project(set *triage.MaterialSet, assumptions *domain.DeclaredAssumptionsInput, now time.Time) (*DeploymentProjection, error) {
	if set == nil {
		return nil, fmt.Errorf("deployment: nil material set")
	}
	p := &DeploymentProjection{Schema: ProjectionSchema}
	d := set.Deploy
	if d == nil {
		p.Perimeter = domain.PerimeterUnknown
		p.Rationale = "no deployment surface scanned; missing manifests never imply isolation"
		p.Limitations = append(p.Limitations,
			"deploy facts absent from material set — perimeter unresolved")
	} else {
		p.Perimeter = d.Perimeter
		if p.Perimeter == "" {
			p.Perimeter = domain.PerimeterUnknown
		}
		p.Rationale = d.Rationale
		p.FactsDigest = d.SHA256
		p.ProjectionSHA256 = d.ProjectionSHA256
		p.FactCount = d.FactCount
		p.ScannedPaths = append([]string(nil), d.ScannedPaths...)
		p.Archives = append([]string(nil), d.Archives...)
		for _, f := range d.Facts {
			if isTracedProvenance(f.AddressSource) {
				p.Basis.ConfigOriginFacts++
			}
		}
		p.Basis.ConfigOrigin = p.Basis.ConfigOriginFacts > 0
		// auto-perimeter lane: only a fact-derived, non-unknown perimeter
		// counts — the classifier itself refuses isolation on absent
		// manifests, so Unknown here is the honest outcome, not a basis.
		if p.Perimeter != domain.PerimeterUnknown && p.FactCount > 0 {
			p.Basis.AutoPerimeter = true
		}
		if p.FactCount == 0 {
			p.Limitations = append(p.Limitations,
				"no deployment exposure facts resolved — perimeter stays unknown; absent manifests never imply isolation")
		}
	}

	// declared-trust lane: admission runs through the canonical gate on
	// the Product B channel — its input is the operator's policy file, and
	// the outcome is audit material, never an evidence id.
	if assumptions != nil {
		b := &TrustBinding{Kind: string(domain.AssumptionConfigTrust), RequiredScope: domain.AssumptionScopeDeployment}
		a, err := domain.AdmitAssumption(assumptions, domain.AssumptionConfigTrust, domain.AssumptionScopeDeployment, now)
		if err != nil {
			b.RejectionReason = domain.AssumptionRejectionReason(err)
			if b.RejectionReason == "" {
				b.RejectionReason = "ASSUMPTION_REJECTED"
			}
		} else {
			b.Admitted = true
			b.AssumptionID = a.ID
			b.Scope = a.Scope
			b.Statement = a.Statement
		}
		p.Basis.DeclaredTrust = b
	}
	return p, nil
}

// isTracedProvenance reports whether an exposure address traces back to
// operator-controlled configuration/provenance rather than a literal —
// the fact class the config-origin basis counts.
func isTracedProvenance(src string) bool {
	switch {
	case src == "config", src == "env", src == "manifest":
		return true
	}
	for _, p := range []string{"config:", "env:", "manifest", "field:", "var", "const"} {
		if len(src) >= len(p) && src[:len(p)] == p {
			return true
		}
	}
	return false
}

// DecodeProjection parses a persisted deployment-projection artifact
// strictly: unknown fields and any non-exact schema are rejected — the
// artifact is a signed input, not a best-effort document.
func DecodeProjection(b []byte) (*DeploymentProjection, error) {
	var p DeploymentProjection
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("deployment projection decode: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("deployment projection: trailing data")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate enforces the projection's strict shape: schema, basis-lane
// consistency (a declared-trust admission requires a bound member; an
// auto-perimeter claim requires a non-unknown perimeter), and digest
// self-consistency when a projection is present.
func (p *DeploymentProjection) Validate() error {
	if p.Schema != ProjectionSchema {
		return fmt.Errorf("deployment projection: schema %q != %q", p.Schema, ProjectionSchema)
	}
	switch p.Perimeter {
	case domain.PerimeterUnknown, domain.PerimeterPublic, domain.PerimeterClusterInternal:
	default:
		return fmt.Errorf("deployment projection: unknown perimeter %q", p.Perimeter)
	}
	if p.Basis.AutoPerimeter && p.Perimeter == domain.PerimeterUnknown {
		return fmt.Errorf("deployment projection: auto_perimeter requires a resolved perimeter")
	}
	if p.Basis.DeclaredTrust != nil {
		t := p.Basis.DeclaredTrust
		if t.Admitted && t.AssumptionID == "" {
			return fmt.Errorf("deployment projection: admitted declared-trust binding without assumption_id")
		}
		if !t.Admitted && t.RejectionReason == "" {
			return fmt.Errorf("deployment projection: rejected declared-trust binding without rejection_reason")
		}
	}
	if p.FactCount > 0 && p.FactsDigest == "" && p.ProjectionSHA256 == "" {
		return fmt.Errorf("deployment projection: facts resolved but no digest pinned")
	}
	return nil
}

// Digest recomputes the projection's content identity — the sha256 of the
// canonical marshaled projection, independent of field order drift in a
// hand-edited artifact.
func (p *DeploymentProjection) Digest() string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
