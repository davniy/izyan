package exposure

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestClassifyPerimeter_ClusterIPOnly(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/service.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
		},
		{
			CallSite:  domain.CallSite{File: "cmd/server/main.go", Line: 42},
			Direction: "inbound",
			Kind:      "listener",
			Target:    "net.Listen",
			Address:   "127.0.0.1:8080",
			Scope:     domain.ScopeLoopback,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
	if rationale == "" {
		t.Fatalf("expected non-empty rationale")
	}
}

func TestClassifyPerimeter_PublicIngress(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/service.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
		},
		{
			CallSite:  domain.CallSite{File: "deploy/ingress.yaml", Line: 8},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Ingress",
			Address:   "api.example.com",
			Scope:     domain.ScopeAllInterfaces,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterPublic {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterPublic, scope, rationale)
	}
	if !strings.Contains(rationale, "k8s:Ingress") && !strings.Contains(rationale, "public") {
		t.Fatalf("expected rationale to mention ingress or public, got: %s", rationale)
	}
}

func TestClassifyPerimeter_PublicListener(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "cmd/server/main.go", Line: 30},
			Direction: "inbound",
			Kind:      "listener",
			Target:    "net.Listen",
			Address:   "0.0.0.0:8080",
			Scope:     domain.ScopeAllInterfaces,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterPublic {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterPublic, scope, rationale)
	}
	if !strings.Contains(rationale, "0.0.0.0:8080") {
		t.Fatalf("expected rationale to mention address 0.0.0.0:8080, got: %s", rationale)
	}
}

func TestClassifyPerimeter_IstioMesh(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/authz.yaml", Line: 4},
			Direction: "inbound",
			Kind:      "auth-middleware",
			Target:    "istio:AuthorizationPolicy",
			Scope:     domain.ScopeLoopback,
		},
		{
			CallSite:  domain.CallSite{File: "deploy/service.yaml", Line: 6},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
	if !strings.Contains(rationale, "ClusterIP") && !strings.Contains(rationale, "istio") {
		t.Fatalf("expected rationale to mention mesh or ClusterIP, got: %s", rationale)
	}
}

func TestClassifyPerimeter_Empty(t *testing.T) {
	scope, rationale := classifyPerimeter(nil, nil)
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
	expectedRationale := "no deployment exposure facts resolved; defaulting to zero-trust"
	if rationale != expectedRationale {
		t.Fatalf("expected rationale %q, got %q", expectedRationale, rationale)
	}
}

func TestClassifyPerimeter_ServiceLoadBalancer(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/service.yaml", Line: 10},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:LoadBalancer",
			Address:   "LoadBalancer",
			Scope:     domain.ScopeAllInterfaces,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterPublic {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterPublic, scope, rationale)
	}
}

func TestClassifyPerimeter_ServiceNodePort(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/service.yaml", Line: 12},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:NodePort",
			Address:   "NodePort",
			Scope:     domain.ScopeAllInterfaces,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterPublic {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterPublic, scope, rationale)
	}
}

func TestClassifyPerimeter_UnixAndConfiguredDial(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "cmd/daemon/main.go", Line: 15},
			Direction: "inbound",
			Kind:      "listener",
			Target:    "net.Listen",
			Address:   "/var/run/app.sock",
			Scope:     domain.ScopeUnix,
		},
		{
			CallSite:      domain.CallSite{File: "internal/client/queue.go", Line: 20},
			Direction:     "outbound",
			Kind:          "dial",
			Target:        "client.DialTLS",
			AddressSource: "config:broker.url",
			Scope:         domain.ScopeConfigured,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
}

func TestClassifyPerimeter_IPv6Loopback(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "server.go", Line: 10},
			Direction: "inbound",
			Kind:      "listener",
			Target:    "net.Listen",
			Address:   "::1:8080",
			Scope:     domain.ScopeLoopback,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
}

func TestClassifyPerimeter_OutboundDialOnlyIsUnknown(t *testing.T) {
	// A configured outbound dial proves nothing about inbound exposure or
	// peer topology — an env-sourced endpoint can point anywhere.
	facts := []domain.ExposureFact{
		{
			CallSite:      domain.CallSite{File: "internal/client/queue.go", Line: 20},
			Direction:     "outbound",
			Kind:          "dial",
			Target:        "client.DialTLS",
			AddressSource: "env:AMQP_URL",
			Scope:         domain.ScopeConfigured,
		},
	}

	scope, _ := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

func TestClassifyPerimeter_MeshOnlyIsUnknown(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/authz.yaml", Line: 4},
			Direction: "inbound",
			Kind:      "auth-middleware",
			Target:    "istio:AuthorizationPolicy",
			Scope:     domain.ScopeLoopback,
		},
	}

	scope, _ := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

func TestClassifyPerimeter_UnresolvedListenerBlocksListenerTier(t *testing.T) {
	// Without deployment manifests an unresolved listener address cannot be
	// bounded — loopback siblings do not rescue the cluster reading.
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "cmd/server/main.go", Line: 30},
			Direction: "inbound",
			Kind:      "listener",
			Target:    "net.Listen",
			Address:   "127.0.0.1:8080",
			Scope:     domain.ScopeLoopback,
		},
		{
			CallSite:      domain.CallSite{File: "cmd/server/main.go", Line: 41},
			Direction:     "inbound",
			Kind:          "listener",
			Target:        "net.Listen",
			AddressSource: "env:METRICS_ADDR",
			Scope:         domain.ScopeUnknown,
		},
	}

	scope, _ := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

func TestClassifyPerimeter_UnresolvedListenerBoundedByClusterIP(t *testing.T) {
	// A declared ClusterIP service authoritatively scopes inbound
	// reachability; an unresolved listener address does not veto it.
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/service.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
		},
		{
			CallSite:      domain.CallSite{File: "cmd/server/main.go", Line: 41},
			Direction:     "inbound",
			Kind:          "listener",
			Target:        "net.Listen",
			AddressSource: "env:METRICS_ADDR",
			Scope:         domain.ScopeUnknown,
		},
	}

	scope, rationale := classifyPerimeter(facts, nil)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
}

func TestClassifyPerimeter_ForeignClusterIPIgnored(t *testing.T) {
	// A sibling service's ClusterIP does not scope OUR inbound
	// reachability — bundle manifests routinely describe the whole stack.
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/svc.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
			Owner:     "billing-api",
		},
	}

	scope, _ := classifyPerimeter(facts, []string{"myapp"})
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

func TestClassifyPerimeter_AttributedClusterIP(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/svc.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
			Owner:     "myapp",
		},
	}

	scope, _ := classifyPerimeter(facts, []string{"myapp"})
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterClusterInternal, scope)
	}
}

func TestClassifyPerimeter_SiblingPrefixClusterIPNotCredited(t *testing.T) {
	// "myapp-db" shares our name prefix but is a sibling service: its
	// ClusterIP must not ground OUR cluster-internal perimeter.
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/svc.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
			Owner:     "myapp-db",
		},
	}

	scope, _ := classifyPerimeter(facts, []string{"myapp"})
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

func TestClassifyPerimeter_SiblingPrefixIngressVetoesCluster(t *testing.T) {
	// An Ingress owned by a same-prefix sibling may or may not front us —
	// backends are not parsed — so it blocks a cluster reading without
	// establishing public exposure.
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/svc.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
			Owner:     "myapp",
		},
		{
			CallSite:  domain.CallSite{File: "deploy/ingress.yaml", Line: 1},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Ingress",
			Address:   "db.example.com",
			Scope:     domain.ScopeAllInterfaces,
			Owner:     "myapp-db",
		},
	}

	scope, _ := classifyPerimeter(facts, []string{"myapp"})
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

func TestClassifyPerimeter_ForeignIngressIgnored(t *testing.T) {
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/ingress.yaml", Line: 1},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Ingress",
			Address:   "api.example.com",
			Scope:     domain.ScopeAllInterfaces,
			Owner:     "public-web",
		},
		{
			CallSite:  domain.CallSite{File: "deploy/svc.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
			Owner:     "myapp",
		},
	}

	scope, _ := classifyPerimeter(facts, []string{"myapp"})
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterClusterInternal, scope)
	}
}

func TestClassifyPerimeter_UnattributedDeployFactBlocksCluster(t *testing.T) {
	// A deploy surface we cannot attribute is not proof of isolation —
	// it holds the perimeter at unknown even beside an owned ClusterIP.
	facts := []domain.ExposureFact{
		{
			CallSite:  domain.CallSite{File: "deploy/svc.yaml", Line: 5},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Service:ClusterIP",
			Address:   "ClusterIP",
			Scope:     domain.ScopeLoopback,
			Owner:     "myapp",
		},
		{
			CallSite:  domain.CallSite{File: "deploy/ingress.yaml", Line: 1},
			Direction: "inbound",
			Kind:      "deployment",
			Target:    "k8s:Ingress",
			Address:   "x.example.com",
			Scope:     domain.ScopeAllInterfaces,
		},
	}

	scope, _ := classifyPerimeter(facts, []string{"myapp"})
	if scope != domain.PerimeterUnknown {
		t.Fatalf("expected scope %q, got %q", domain.PerimeterUnknown, scope)
	}
}

// classifyPerimeter keeps the exposure-classification tests focused on the
// exposure answer; the typed basis (and the trust gate that reads it) is
// asserted by TestPerimeterTrustBasis.
func classifyPerimeter(facts []domain.ExposureFact, productNames []string) (string, string) {
	assessment := ClassifyPerimeter(facts, productNames)
	return assessment.Perimeter, assessment.Rationale
}

// TestPerimeterTrustBasis: the classifier observes exposure shape only.
// Loopback/unix listeners and ClusterIP topology describe where a listener
// sits; they never establish that peers are trusted and never select a
// trusted-peer actual profile. Only independently admitted deployment policy
// or an explicit operator declaration can do that.
func TestPerimeterTrustBasis(t *testing.T) {
	cases := []struct {
		name          string
		facts         []domain.ExposureFact
		wantPerimeter string
		wantBasis     domain.PerimeterBasis
		wantTrust     bool
	}{
		{
			name: "loopback listener alone is exposure shape",
			facts: []domain.ExposureFact{{
				Direction: "inbound", Kind: "listener", Target: "net.Listen",
				Address: "127.0.0.1:8080", Scope: domain.ScopeLoopback,
			}},
			wantPerimeter: domain.PerimeterClusterInternal,
			wantBasis:     domain.PerimeterBasisListenerLocality,
		},
		{
			name: "unix socket alone is exposure shape",
			facts: []domain.ExposureFact{{
				Direction: "inbound", Kind: "listener", Target: "net.Listen",
				Address: "/run/product.sock", Scope: domain.ScopeUnix,
			}},
			wantPerimeter: domain.PerimeterClusterInternal,
			wantBasis:     domain.PerimeterBasisListenerLocality,
		},
		{
			name: "ClusterIP service alone is topology",
			facts: []domain.ExposureFact{{
				Direction: "inbound", Kind: "deployment", Target: "k8s:Service:ClusterIP",
				Address: "ClusterIP", Owner: "myapp",
			}},
			wantPerimeter: domain.PerimeterClusterInternal,
			wantBasis:     domain.PerimeterBasisDeploymentTopology,
		},
		{
			name: "public ingress is exposure",
			facts: []domain.ExposureFact{{
				Direction: "inbound", Kind: "deployment", Target: "k8s:Ingress", Owner: "myapp",
			}},
			wantPerimeter: domain.PerimeterPublic,
			wantBasis:     domain.PerimeterBasisDeploymentTopology,
		},
		{
			name:          "no facts stays unknown",
			wantPerimeter: domain.PerimeterUnknown,
			wantBasis:     domain.PerimeterBasisUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessment := ClassifyPerimeter(tc.facts, []string{"myapp"})
			if assessment.Perimeter != tc.wantPerimeter {
				t.Fatalf("perimeter=%s want %s (%s)", assessment.Perimeter, tc.wantPerimeter, assessment.Rationale)
			}
			if assessment.Basis != tc.wantBasis {
				t.Fatalf("basis=%s want %s", assessment.Basis, tc.wantBasis)
			}
			if assessment.AllowsTrustedPeerSelection() {
				t.Fatalf("classifier basis %s selected a trusted-peer actual profile", assessment.Basis)
			}
			if err := assessment.Validate(); err != nil {
				t.Fatalf("assessment invalid: %v", err)
			}
		})
	}

	// Independent admitted bases are the only trust route.
	for _, basis := range []domain.PerimeterBasis{domain.PerimeterBasisDeploymentPolicy, domain.PerimeterBasisOperatorDeclared} {
		assessment := domain.NewPerimeterAssessment(domain.PerimeterClusterInternal, basis, "explicit policy")
		if !assessment.AllowsTrustedPeerSelection() {
			t.Fatalf("admitted basis %s did not select a trusted-peer profile", basis)
		}
		if err := assessment.Validate(); err != nil {
			t.Fatalf("admitted assessment invalid: %v", err)
		}
	}
	for _, basis := range []domain.PerimeterBasis{domain.PerimeterBasisListenerLocality, domain.PerimeterBasisDeploymentTopology, domain.PerimeterBasisUnknown} {
		assessment := domain.NewPerimeterAssessment(domain.PerimeterClusterInternal, basis, "shape only")
		if assessment.AllowsTrustedPeerSelection() {
			t.Fatalf("exposure-shape basis %s selected trust", basis)
		}
		if !hasLimitation(assessment.Limitations, domain.PerimeterLocalityNotTrustLimitation) {
			t.Fatalf("basis %s lacks the locality-not-trust limitation: %v", basis, assessment.Limitations)
		}
	}
}

func hasLimitation(limitations []string, want string) bool {
	for _, l := range limitations {
		if l == want {
			return true
		}
	}
	return false
}
