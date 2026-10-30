package domain

import "fmt"

// PerimeterBasis classifies what an exposure classification rests on. It exists
// because an exposure shape is not a trust statement: a Unix socket, a loopback
// bind or a ClusterIP service describes where a listener sits, not whether its
// peers are adversary-controlled. Only a deployment policy or an explicit
// operator declaration can establish that peers are trusted.
type PerimeterBasis string

const (
	// PerimeterBasisUnknown means no basis was established.
	PerimeterBasisUnknown PerimeterBasis = "unknown"
	// PerimeterBasisListenerLocality means the classification rests on the
	// resolved listener addresses (loopback/Unix/local) alone.
	PerimeterBasisListenerLocality PerimeterBasis = "listener-locality"
	// PerimeterBasisDeploymentTopology means the classification rests on
	// deployment manifests and topology (ClusterIP, namespace, mesh) alone.
	PerimeterBasisDeploymentTopology PerimeterBasis = "deployment-topology"
	// PerimeterBasisDeploymentPolicy means an admitted deployment policy
	// establishes the trust boundary.
	PerimeterBasisDeploymentPolicy PerimeterBasis = "deployment-policy"
	// PerimeterBasisOperatorDeclared means the operator explicitly selected the
	// perimeter or the trusted-peer policy.
	PerimeterBasisOperatorDeclared PerimeterBasis = "operator-declared"
)

// Valid reports whether the basis is one of the frozen typed bases.
func (b PerimeterBasis) Valid() bool {
	switch b {
	case PerimeterBasisUnknown, PerimeterBasisListenerLocality, PerimeterBasisDeploymentTopology,
		PerimeterBasisDeploymentPolicy, PerimeterBasisOperatorDeclared:
		return true
	default:
		return false
	}
}

// AdmitsTrust reports whether the basis can establish that peers are trusted.
// Locality and topology describe exposure and never ground trust.
func (b PerimeterBasis) AdmitsTrust() bool {
	return b == PerimeterBasisDeploymentPolicy || b == PerimeterBasisOperatorDeclared
}

// PerimeterLocalityNotTrustLimitation is the mandatory limitation attached when
// a cluster-internal classification rests on exposure shape alone.
const PerimeterLocalityNotTrustLimitation = "Perimeter basis is exposure shape only: Unix/loopback binding or cluster topology does not establish that peers are trusted, so no trusted-peer actual profile may be selected from it."

// PerimeterAssessment is one exposure classification together with its typed
// basis. The classification says which perimeter the facts describe; the basis
// says whether that description may also select a trusted-peer actual profile.
// A hypothetical profile result must stay conditional and distinct from the
// actual deployment assessment.
type PerimeterAssessment struct {
	Perimeter   string         `json:"perimeter"`
	Basis       PerimeterBasis `json:"basis"`
	Rationale   string         `json:"rationale,omitempty"`
	Limitations []string       `json:"limitations,omitempty"`
}

// NewPerimeterAssessment builds the typed assessment and attaches the mandatory
// locality-not-trust limitation when the basis cannot ground trust, so a
// cluster-internal classification can never quietly read as a trust decision.
func NewPerimeterAssessment(perimeter string, basis PerimeterBasis, rationale string) PerimeterAssessment {
	assessment := PerimeterAssessment{Perimeter: perimeter, Basis: basis, Rationale: rationale}
	if perimeter == PerimeterClusterInternal && !basis.AdmitsTrust() {
		assessment.Limitations = append(assessment.Limitations, PerimeterLocalityNotTrustLimitation)
	}
	return assessment
}

// AllowsTrustedPeerSelection reports whether this assessment may select a
// trusted-peer actual profile or stamp automatic perimeter trust. Both a
// cluster-internal classification and an admitted trust basis are required; a
// listener-locality or topology basis is never sufficient.
func (a *PerimeterAssessment) AllowsTrustedPeerSelection() bool {
	if a == nil {
		return false
	}
	return a.Perimeter == PerimeterClusterInternal && a.Basis.AdmitsTrust()
}

// Validate enforces the typed basis, a known classification, and the mandatory
// limitation whenever a cluster-internal result rests on exposure shape alone.
func (a *PerimeterAssessment) Validate() error {
	if a == nil {
		return fmt.Errorf("perimeter assessment: nil assessment")
	}
	switch a.Perimeter {
	case PerimeterClusterInternal, PerimeterPublic, PerimeterUnknown:
	default:
		return fmt.Errorf("perimeter assessment: unknown perimeter %q", a.Perimeter)
	}
	if !a.Basis.Valid() {
		return fmt.Errorf("perimeter assessment: unknown basis %q", a.Basis)
	}
	if a.Perimeter == PerimeterClusterInternal && !a.Basis.AdmitsTrust() &&
		!hasLimitation(a.Limitations, PerimeterLocalityNotTrustLimitation) {
		return fmt.Errorf("perimeter assessment: a %q basis must carry the locality-not-trust limitation",
			a.Basis)
	}
	return nil
}
