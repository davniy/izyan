package exposure

import (
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// clusterTier ranks cluster-isolation evidence. tierDeploy is structural:
// a deployment manifest scopes inbound reachability regardless of the
// process's own bind address. tierListener is structural only when every
// observed listener is loopback/unix — a product with no reachable inbound
// surface confines its input plane to the cluster. tierCorroborating
// (mesh objects, auth middleware, configured outbound dials) supports a
// cluster reading but never establishes it alone: a configured endpoint
// can point anywhere, and an Istio policy's rules are not interpreted.
const (
	tierNone = iota
	tierCorroborating
	tierListener
	tierDeploy
)

// ClassifyPerimeter analyzes resolved exposure facts from code and deployment
// manifests to determine whether the product operates strictly in a
// cluster-internal perimeter, is exposed publicly, or is unknown. It returns a
// typed assessment that separates the exposure classification from its basis:
// the classifier only ever observes exposure shape, so its basis is listener
// locality or deployment topology — never trust. Only independent
// deployment-policy evidence or an explicit operator declaration can establish
// that peers are trusted.
//
// Attribution: productNames identifies the analyzed product (module
// basename, binary name, repo basename). Deployment facts carry an
// Owner — a manifest resource grounds this product's perimeter only when
// its owner matches the product name *exactly*: a foreign or same-prefix
// sibling's ClusterIP must not scope our inbound reachability, and its
// Ingress must not mark us public. Unattributed deploy facts
// (templated/missing names) and prefix-matched siblings neither count as
// cluster evidence nor as public evidence — external-routing objects
// among them veto a cluster reading and hold the perimeter at unknown.
// With no productNames supplied, deploy facts count as before
// (unattributed = accepted).
//
// Conservative direction: public evidence wins over everything; unknown or
// unresolved inbound surfaces block a cluster-internal conclusion unless a
// deployment manifest authoritatively scopes the workload (ClusterIP). An
// absent manifest is never evidence of isolation.
func ClassifyPerimeter(facts []domain.ExposureFact, productNames []string) domain.PerimeterAssessment {
	if len(facts) == 0 {
		return domain.NewPerimeterAssessment(domain.PerimeterUnknown, domain.PerimeterBasisUnknown,
			"no deployment exposure facts resolved; defaulting to zero-trust")
	}

	var (
		publicReasons, clusterReasons, unexplained, unattributedPublic []string
		publicFromDeploy                                               bool
		publicFromListener                                             bool
	)
	maxTier := tierNone

	for _, f := range facts {
		if len(productNames) > 0 && isDeployFact(f) {
			if f.Owner == "" {
				// An unattributed external-routing object may front our
				// ClusterIP service — that is exactly what Ingress is for.
				// It cannot prove public exposure, but it vetoes a
				// cluster-internal reading. Non-routing facts carry no
				// weight either way.
				if isPublic, _ := checkPublic(f); isPublic {
					unattributedPublic = appendUnique(unattributedPublic, describeFact(f))
				}
				continue
			}
			if !exactMatchProduct(f.Owner, productNames) {
				// Foreign or same-prefix sibling resource ("myapp-db" for
				// product "myapp"): its ClusterIP must not ground our
				// isolation — sibling services routinely share the
				// product-name prefix. A prefix-matched external-routing
				// object cannot be proven to front us either (ingress
				// backends are not parsed), so it vetoes a cluster
				// reading instead of establishing public exposure.
				if isPublic, _ := checkPublic(f); isPublic && prefixMatchProduct(f.Owner, productNames) {
					unattributedPublic = appendUnique(unattributedPublic, describeFact(f)+" (sibling resource "+f.Owner+")")
				}
				continue
			}
		}
		if isPublic, reason := checkPublic(f); isPublic {
			publicReasons = appendUnique(publicReasons, reason)
			if isDeployFact(f) {
				publicFromDeploy = true
			} else {
				publicFromListener = true
			}
			continue
		}
		if tier, reason := checkCluster(f); tier > tierNone {
			clusterReasons = appendUnique(clusterReasons, reason)
			if tier > maxTier {
				maxTier = tier
			}
			continue
		}
		if isInboundSurface(f) {
			unexplained = appendUnique(unexplained, describeFact(f))
		}
	}

	if len(publicReasons) > 0 {
		basis := domain.PerimeterBasisListenerLocality
		if publicFromDeploy {
			basis = domain.PerimeterBasisDeploymentTopology
		}
		return domain.NewPerimeterAssessment(domain.PerimeterPublic, basis,
			"public exposure detected: "+strings.Join(publicReasons, "; "))
	}

	switch maxTier {
	case tierDeploy:
		if len(unattributedPublic) > 0 {
			return domain.NewPerimeterAssessment(domain.PerimeterUnknown, domain.PerimeterBasisDeploymentTopology,
				"unattributed external-routing manifests may front the service: "+strings.Join(unattributedPublic, "; "))
		}
		rationale := "cluster-internal perimeter: " + strings.Join(clusterReasons, ", ") + "; no public ingress found"
		if len(unexplained) > 0 {
			rationale += "; unresolved inbound surfaces bounded by declared service scope: " + strings.Join(unexplained, "; ")
		}
		return domain.NewPerimeterAssessment(domain.PerimeterClusterInternal, domain.PerimeterBasisDeploymentTopology, rationale)
	case tierListener:
		if len(unexplained) == 0 && len(unattributedPublic) == 0 {
			return domain.NewPerimeterAssessment(domain.PerimeterClusterInternal, domain.PerimeterBasisListenerLocality,
				"cluster-internal perimeter: "+strings.Join(clusterReasons, ", ")+"; no public ingress found")
		}
		blockers := append(append([]string{}, unexplained...), unattributedPublic...)
		return domain.NewPerimeterAssessment(domain.PerimeterUnknown, domain.PerimeterBasisListenerLocality,
			"loopback/unix listeners present but inbound exposure unresolved: "+strings.Join(blockers, "; "))
	default:
		blockers := append(append([]string{}, unexplained...), unattributedPublic...)
		basis := domain.PerimeterBasisUnknown
		if publicFromListener || len(clusterReasons) > 0 || len(blockers) > 0 {
			basis = domain.PerimeterBasisListenerLocality
		}
		if len(blockers) > 0 {
			return domain.NewPerimeterAssessment(domain.PerimeterUnknown, basis,
				"unresolved inbound exposure: "+strings.Join(blockers, "; "))
		}
		return domain.NewPerimeterAssessment(domain.PerimeterUnknown, basis,
			"no structural cluster-isolation evidence (ClusterIP service or loopback/unix-only listeners); defaulting to zero-trust")
	}
}

// isInboundSurface reports whether the fact describes an inbound network
// surface whose classification matters — listeners and manifest-declared
// objects. Corroborating kinds (auth middleware) never block a verdict.
func isInboundSurface(f domain.ExposureFact) bool {
	return f.Direction == "inbound" && (f.Kind == "listener" || f.Kind == "deployment")
}

// isDeployFact reports whether the fact was emitted by a deployment
// manifest scan rather than the product's own code.
func isDeployFact(f domain.ExposureFact) bool {
	return f.Kind == "deployment" || f.Kind == "auth-middleware"
}

// exactMatchProduct reports whether a manifest owner names the analyzed
// product exactly (case-insensitive). Only an exact-named resource may
// ground this product's cluster isolation: same-prefix siblings like
// "myapp-db" are routine in deployment bundles and their ClusterIP says
// nothing about our inbound reachability.
func exactMatchProduct(owner string, productNames []string) bool {
	owner = strings.ToLower(strings.TrimSpace(owner))
	for _, n := range productNames {
		if owner == strings.ToLower(strings.TrimSpace(n)) && owner != "" {
			return true
		}
	}
	return false
}

// prefixMatchProduct reports whether the owner begins with a product
// name at a separator boundary ("myapp-svc" for product "myapp").
// A prefix match marks a *sibling* resource: it can veto a cluster
// reading when it is external-routing, but never establishes our
// isolation nor our public exposure.
func prefixMatchProduct(owner string, productNames []string) bool {
	owner = strings.ToLower(strings.TrimSpace(owner))
	for _, n := range productNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if strings.HasPrefix(owner, n+"-") || strings.HasPrefix(owner, n+".") {
			return true
		}
	}
	return false
}

func describeFact(f domain.ExposureFact) string {
	d := f.Target
	if d == "" {
		d = f.Kind
	}
	if f.Address != "" {
		d += " " + f.Address
	}
	if d == "" {
		d = f.AddressSource
	}
	if d == "" {
		d = "unresolved inbound surface"
	}
	return strings.TrimSpace(d)
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

// checkCluster classifies a fact as cluster-isolation evidence and returns
// its tier. Only tierDeploy and tierListener can establish a
// cluster-internal perimeter; corroborating facts never do.
func checkCluster(f domain.ExposureFact) (int, string) {
	// 1. K8s Service: ClusterIP — the manifest scopes reachability.
	if strings.Contains(f.Target, "ClusterIP") || strings.Contains(f.Address, "ClusterIP") {
		return tierDeploy, "service ClusterIP"
	}
	if f.Kind == "k8s:Service" && (f.Scope == domain.ScopeClusterInternal || f.Scope == domain.ScopeLoopback || f.Address == "ClusterIP") {
		return tierDeploy, "service ClusterIP"
	}

	// 2. Loopback/unix-bound inbound surfaces: code listeners and
	// manifest-declared binds (e.g. compose "127.0.0.1:8080:80").
	if isInboundSurface(f) {
		if f.Scope == domain.ScopeLoopback || f.Scope == domain.ScopeUnix ||
			strings.Contains(f.Address, "127.0.0.1") || strings.Contains(f.Address, "localhost") ||
			strings.Contains(f.Address, "::1") || strings.Contains(f.Address, "[::1]") ||
			strings.HasPrefix(f.Address, "/") || strings.HasSuffix(f.Address, ".sock") {
			addr := f.Address
			if addr == "" {
				addr = f.Scope
			}
			return tierListener, fmt.Sprintf("listener %s", addr)
		}
	}

	// 3. Mesh objects — corroborating: presence implies a mesh, but the
	// policy's rules are not evaluated.
	if f.Kind == "istio:AuthorizationPolicy" || f.Target == "istio:AuthorizationPolicy" ||
		f.Kind == "istio:RequestAuthentication" || f.Target == "istio:RequestAuthentication" ||
		f.Kind == "istio:VirtualService" || f.Target == "istio:VirtualService" {
		name := f.Target
		if name == "" {
			name = f.Kind
		}
		return tierCorroborating, fmt.Sprintf("mesh %s", name)
	}

	// 4. Outbound configured dials — corroborating: the endpoint is
	// operator-configured, which says nothing about its topology.
	if (f.Direction == "outbound" || f.Kind == "dial") && f.Scope == domain.ScopeConfigured {
		target := f.Target
		if target == "" {
			target = f.AddressSource
		}
		if target != "" {
			return tierCorroborating, fmt.Sprintf("configured dial %s", target)
		}
		return tierCorroborating, "configured outbound dial"
	}

	// 5. Auth middleware wiring — corroborating deployment hint.
	if f.Kind == "auth-middleware" {
		return tierCorroborating, "auth middleware"
	}

	return tierNone, ""
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
