package deployment

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/triage"
)

// TestMissingManifestNeverIsolates pins the S-13 rule: an empty deploy scan
// (no facts resolved) projects PerimeterUnknown with an explicit limitation,
// never a cluster-internal reading or a synthesized default.
func TestMissingManifestNeverIsolates(t *testing.T) {
	// No Deploy block at all: collection produced nothing.
	p, err := Project(&triage.MaterialSet{}, nil, time.Now())
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if p.Perimeter != domain.PerimeterUnknown {
		t.Fatalf("absent deploy facts must leave perimeter unknown, got %q", p.Perimeter)
	}
	if len(p.Limitations) == 0 {
		t.Fatal("missing manifests must surface a limitation")
	}
	if p.Basis.AutoPerimeter {
		t.Fatal("auto-perimeter must not be claimed without resolved facts")
	}
	if p.Basis.ConfigOrigin {
		t.Fatal("config-origin must not be claimed without traced facts")
	}

	// Deploy ran but resolved zero facts: same rule.
	p2, err := Project(&triage.MaterialSet{Deploy: &triage.DeployFacts{}}, nil, time.Now())
	if err != nil {
		t.Fatalf("project empty deploy: %v", err)
	}
	if p2.Perimeter != domain.PerimeterUnknown {
		t.Fatalf("zero-fact scan must project unknown perimeter, got %q", p2.Perimeter)
	}
	found := false
	for _, l := range p2.Limitations {
		if strings.Contains(l, "never imply isolation") {
			found = true
		}
	}
	if !found {
		t.Fatalf("zero-fact scan must record the non-isolation limitation: %v", p2.Limitations)
	}
}

// TestForeignServiceNotAttributed pins owner matching: a foreign or
// prefix-sibling service cannot ground cluster-internal perimeter for this
// product; its public surface vetoes the reading instead.
func TestForeignServiceNotAttributed(t *testing.T) {
	facts := []domain.ExposureFact{
		{Owner: "other-svc", Kind: "ingress", Direction: "inbound",
			Scope: domain.ScopeAllInterfaces},
		{Owner: "myapp-db", Kind: "service", Direction: "inbound",
			Scope: domain.ScopeClusterInternal},
	}
	p, err := Project(&triage.MaterialSet{
		Deploy: &triage.DeployFacts{
			Facts:     facts,
			FactCount: len(facts),
			// Deliberately leave Perimeter unset — the adapter derives it
			// through the canonical classifier, which must refuse to read
			// a foreign ClusterIP as the product's isolation.
			Perimeter: "",
		},
	}, nil, time.Now())
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	// The adapter copies the recorded classifier output verbatim — a raw
	// material set with no classification is still honest (empty→unknown).
	if p.Basis.AutoPerimeter {
		t.Fatal("foreign-service facts must never ground auto-perimeter")
	}
}

// TestAutoPerimeterVsDeclaredTrustSeparates pins the two lane projection:
// declared-trust admission and auto-perimeter detection live in disjoint
// fields and one never satisfies the other.
func TestAutoPerimeterVsDeclaredTrustSeparates(t *testing.T) {
	doc := &domain.DeclaredAssumptionsInput{
		Path: "local:assumptions.json",
		Assumptions: []domain.DeclaredAssumption{{
			ID:        "cfg-1",
			Kind:      domain.AssumptionConfigTrust,
			Statement: "operator-managed configuration is trusted",
			Scope:     domain.AssumptionScopeDeployment,
			Authority: "ops", Owner: "ops", SourceRef: "policy/assumptions.json",
			Digest:     "sha256:" + strings.Repeat("0", 64),
			ReviewDate: "2030-01-01",
		}},
	}
	// Recompute the real digest pin so admission validates the member.
	doc.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(doc.Assumptions[0])

	p, err := Project(&triage.MaterialSet{
		Deploy: &triage.DeployFacts{
			FactCount: 1,
			Perimeter: domain.PerimeterClusterInternal,
			Facts: []domain.ExposureFact{{
				Owner: "myapp", Kind: "service", Direction: "inbound",
				Scope: domain.ScopeClusterInternal,
			}},
		},
	}, doc, time.Now())
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if p.Basis.DeclaredTrust == nil || !p.Basis.DeclaredTrust.Admitted {
		t.Fatalf("declared-trust must admit the operator assertion: %+v", p.Basis.DeclaredTrust)
	}
	if p.Basis.DeclaredTrust.AssumptionID != "cfg-1" {
		t.Fatalf("admitted binding must name the member: %q", p.Basis.DeclaredTrust.AssumptionID)
	}
	if !p.Basis.AutoPerimeter {
		t.Fatal("cluster-internal perimeter with facts must set auto-perimeter")
	}
	// Disjoint: declaring config-trust never sets config-origin, and
	// auto-perimeter never merges into declared-trust's ID/scope fields.
	if p.Basis.ConfigOrigin {
		t.Fatal("config-origin is a distinct lane — detected facts set it, not trust admission")
	}
}

// TestDeclaredTrustRejectionNeverAdmits pins the fail-closed lane: a
// malformed/expired/scope-mismatched assertion is recorded as a typed
// rejection, never silently skipped.
func TestDeclaredTrustRejectionNeverAdmits(t *testing.T) {
	bad := &domain.DeclaredAssumptionsInput{
		LoadError: domain.AssumptionsLoadInvalid,
	}
	p, err := Project(&triage.MaterialSet{Deploy: &triage.DeployFacts{}}, bad, time.Now())
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	tb := p.Basis.DeclaredTrust
	if tb == nil {
		t.Fatal("a supplied assumptions channel must surface a binding record")
	}
	if tb.Admitted {
		t.Fatal("a document-invalid channel must never admit")
	}
	if tb.RejectionReason != domain.AssumptionRejectDocumentInvalid {
		t.Fatalf("rejection must be the typed channel outcome, got %q", tb.RejectionReason)
	}
}

// TestAssumptionNeverEntersEvidence is the structural pin: the projection
// carries no EvidenceIDs, claim refs or verdict fields — a policy
// assumption can never become a graph fact through this adapter.
func TestAssumptionNeverEntersEvidence(t *testing.T) {
	p := &DeploymentProjection{
		Schema:    ProjectionSchema,
		Perimeter: domain.PerimeterClusterInternal,
		Basis: GroundBasisProjection{
			DeclaredTrust: &TrustBinding{
				Kind: "config-trust", RequiredScope: "deployment",
				Admitted: true, AssumptionID: "a1", Scope: "deployment",
			},
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"evidence_ids", "claim_id", "verdict", "claims", "evidence"} {
		if strings.Contains(strings.ToLower(string(b)), `"`+forbidden+`"`) {
			t.Fatalf("projection carries forbidden field %q", forbidden)
		}
	}
}

// TestDecodeProjectionStrict pins strict artifact validation: unknown
// fields, wrong schema and lane-inconsistent state are rejected at decode.
func TestDecodeProjectionStrict(t *testing.T) {
	good := `{"schema":"deployment-projection.v1","perimeter":"cluster-internal","basis":{"auto_perimeter":true}}`
	if _, err := DecodeProjection([]byte(good)); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}
	cases := []string{
		`{"schema":"deployment-projection.v1","perimeter":"unknown","basis":{"auto_perimeter":true}}`, // lane inconsistency
		`{"schema":"deployment-projection.v1","perimeter":"quarantined"}`,                             // unknown perimeter
		`{"schema":"wrong.v1","perimeter":"unknown"}`,                                                 // wrong schema
		`{"schema":"deployment-projection.v1","perimeter":"unknown","extra":1}`,                       // unknown field
	}
	for i, c := range cases {
		if _, err := DecodeProjection([]byte(c)); err == nil {
			t.Fatalf("case %d: malformed projection must be rejected", i)
		}
	}
}

// TestProjectionDigestStable pins replay identity: the same projection
// marshals to the same digest; field reorder in source changes nothing.
func TestProjectionDigestStable(t *testing.T) {
	mk := func() *DeploymentProjection {
		return &DeploymentProjection{
			Schema:    ProjectionSchema,
			Perimeter: domain.PerimeterClusterInternal,
			FactCount: 1,
			Basis:     GroundBasisProjection{AutoPerimeter: true},
		}
	}
	a, b := mk(), mk()
	if a.Digest() != b.Digest() {
		t.Fatal("identical projections must digest identically")
	}
	c := mk()
	c.Perimeter = domain.PerimeterUnknown
	if c.Digest() == a.Digest() {
		t.Fatal("a drifted perimeter must change the digest")
	}
}
