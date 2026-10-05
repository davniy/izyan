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

	scope, rationale := ClassifyPerimeter(facts)
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

	scope, rationale := ClassifyPerimeter(facts)
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

	scope, rationale := ClassifyPerimeter(facts)
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

	scope, rationale := ClassifyPerimeter(facts)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
	if !strings.Contains(rationale, "ClusterIP") && !strings.Contains(rationale, "istio") {
		t.Fatalf("expected rationale to mention mesh or ClusterIP, got: %s", rationale)
	}
}

func TestClassifyPerimeter_Empty(t *testing.T) {
	scope, rationale := ClassifyPerimeter(nil)
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

	scope, rationale := ClassifyPerimeter(facts)
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

	scope, rationale := ClassifyPerimeter(facts)
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

	scope, rationale := ClassifyPerimeter(facts)
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

	scope, rationale := ClassifyPerimeter(facts)
	if scope != domain.PerimeterClusterInternal {
		t.Fatalf("expected scope %q, got %q (rationale: %s)", domain.PerimeterClusterInternal, scope, rationale)
	}
}
