package exposure

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// ClassifyPerimeter analyzes resolved exposure facts from code and deployment manifests
// to determine whether the product operates strictly in a cluster-internal perimeter,
// is exposed publicly, or is unknown.
func ClassifyPerimeter(facts []domain.ExposureFact) (string, string) {
	if len(facts) == 0 {
		return domain.PerimeterUnknown, "no deployment exposure facts resolved; defaulting to zero-trust"
	}

	var publicReasons []string
	var clusterReasons []string

	for _, f := range facts {
		if isPublic, reason := checkPublic(f); isPublic {
			publicReasons = appendUnique(publicReasons, reason)
		}
		if isCluster, reason := checkCluster(f); isCluster {
			clusterReasons = appendUnique(clusterReasons, reason)
		}
	}

	if len(publicReasons) > 0 {
		return domain.PerimeterPublic, "public exposure detected: " + strings.Join(publicReasons, "; ")
	}

	if len(clusterReasons) > 0 {
		return domain.PerimeterClusterInternal, "cluster-internal perimeter: " + strings.Join(clusterReasons, ", ") + "; no public ingress found"
	}

	return domain.PerimeterUnknown, "unresolved exposure perimeter: no conclusive exposure indicators found"
}

func checkPublic(f domain.ExposureFact) (bool, string) {
	// 1. Ingress and Gateway objects
	if f.Kind == "k8s:Ingress" || f.Target == "k8s:Ingress" ||
		f.Kind == "gateway-api:Gateway" || f.Target == "gateway-api:Gateway" ||
		f.Kind == "openshift:Route" || f.Target == "openshift:Route" ||
		f.Kind == "traefik:IngressRoute" || f.Target == "traefik:IngressRoute" {
		target := f.Target
		if target == "" {
			target = f.Kind
		}
		if f.Address != "" {
			return true, fmt.Sprintf("%s (%s)", target, f.Address)
		}
		return true, target
	}

	// 2. Service types: LoadBalancer, NodePort
	if strings.Contains(f.Target, "LoadBalancer") || strings.Contains(f.Address, "LoadBalancer") || f.Kind == "LoadBalancer" {
		return true, "service LoadBalancer"
	}
	if strings.Contains(f.Target, "NodePort") || strings.Contains(f.Address, "NodePort") || f.Kind == "NodePort" {
		return true, "service NodePort"
	}

	// 3. Inbound listener address with 0.0.0.0 or :port
	if (f.Direction == "inbound" || f.Kind == "listener") && f.Scope != domain.ScopeLoopback && f.Scope != domain.ScopeUnix {
		addr := f.Address
		isIPv6Loopback := strings.HasPrefix(addr, "::1") || strings.HasPrefix(addr, "[::1]") || strings.Contains(addr, "localhost") || strings.Contains(addr, "127.0.0.1")
		if !isIPv6Loopback {
			if strings.Contains(addr, "0.0.0.0") || (strings.HasPrefix(addr, ":") && !strings.HasPrefix(addr, "::")) {
				return true, fmt.Sprintf("inbound listener %s", f.Address)
			}
		}
	}

	// 4. Istio mesh facts are cluster isolation unless bound to an ingress/gateway
	if isMeshFact(f) {
		return false, ""
	}

	// 5. General public scopes (all-interfaces or host-specific) on non-outbound
	if f.Direction != "outbound" && (f.Scope == domain.ScopeAllInterfaces || f.Scope == domain.ScopeHostSpecific) {
		desc := f.Target
		if desc == "" {
			desc = f.Kind
		}
		if f.Address != "" {
			desc += " " + f.Address
		}
		if desc == "" {
			desc = f.Scope
		}
		return true, fmt.Sprintf("exposure scope %s (%s)", f.Scope, strings.TrimSpace(desc))
	}

	return false, ""
}

func checkCluster(f domain.ExposureFact) (bool, string) {
	// 1. K8s Service: ClusterIP
	if strings.Contains(f.Target, "ClusterIP") || strings.Contains(f.Address, "ClusterIP") {
		return true, "service ClusterIP"
	}
	if f.Kind == "k8s:Service" && (f.Scope == domain.ScopeClusterInternal || f.Scope == domain.ScopeLoopback || f.Address == "ClusterIP") {
		return true, "service ClusterIP"
	}

	// 2. Listeners: loopback, unix, 127.0.0.1, localhost, ::1
	if f.Direction != "outbound" {
		if f.Scope == domain.ScopeLoopback || f.Scope == domain.ScopeUnix ||
			strings.Contains(f.Address, "127.0.0.1") || strings.Contains(f.Address, "localhost") ||
			strings.Contains(f.Address, "::1") || strings.Contains(f.Address, "[::1]") ||
			strings.HasPrefix(f.Address, "/") || strings.HasSuffix(f.Address, ".sock") {
			addr := f.Address
			if addr == "" {
				addr = f.Scope
			}
			return true, fmt.Sprintf("listener %s", addr)
		}
	}

	// 3. Mesh objects
	if f.Kind == "istio:AuthorizationPolicy" || f.Target == "istio:AuthorizationPolicy" ||
		f.Kind == "istio:RequestAuthentication" || f.Target == "istio:RequestAuthentication" ||
		f.Kind == "istio:VirtualService" || f.Target == "istio:VirtualService" {
		name := f.Target
		if name == "" {
			name = f.Kind
		}
		return true, fmt.Sprintf("mesh %s", name)
	}

	// 4. Outbound configured dials
	if (f.Direction == "outbound" || f.Kind == "dial") && f.Scope == domain.ScopeConfigured {
		target := f.Target
		if target == "" {
			target = f.AddressSource
		}
		if target != "" {
			return true, fmt.Sprintf("configured dial %s", target)
		}
		return true, "configured outbound dial"
	}

	return false, ""
}

func isMeshFact(f domain.ExposureFact) bool {
	return f.Kind == "istio:AuthorizationPolicy" || f.Target == "istio:AuthorizationPolicy" ||
		f.Kind == "istio:RequestAuthentication" || f.Target == "istio:RequestAuthentication" ||
		((f.Kind == "istio:VirtualService" || f.Target == "istio:VirtualService") && f.Address == "")
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
