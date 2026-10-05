package exposure

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Deployment manifests declare exposure the source tree cannot express —
// including surfaces that belong to sibling services in the same bundle
// (a compose file publishing the AMQP broker is deployment context for a
// client-side parser vulnerability, not the product's own listener).
// Facts record what the manifest declares; whether a published surface
// fronts the analyzed process is a deployment question.
// a Service of type LoadBalancer, an Ingress/Route/Gateway, a published
// compose port or hostPort/hostNetwork all open surfaces beyond what the
// code's bind address says. ScanDeploy is a line-level scan — it reads
// kind/type/port markers without a YAML parser, so it survives Helm
// templates; templated values are flagged "template" rather than
// interpreted.
var (
	// deployDirRe scopes the scan to deployment-ish directories — config
	// YAML elsewhere (CI, tests) must not inflate the exposure surface.
	deployDirRe = regexp.MustCompile(`(?i)^(helm|deploy|deployments?|k8s|kubernetes|charts?|manifests?|openshift|istio|infra|docker|compose|gitops|argocd|environments?)$`)
	// deploySkipDirs never count as deployment scope — fixture trees.
	deploySkipDirs = map[string]bool{
		"vendor": true, ".git": true, "node_modules": true,
		"testdata": true, "test": true, "tests": true,
	}
	composeFileRe = regexp.MustCompile(`(?i)^(?:docker-)?compose[^/]*\.ya?ml$`)
	dockerfileRe  = regexp.MustCompile(`(?i)^Dockerfile[^/]*$`)
	kindRe        = regexp.MustCompile(`^\s*kind:\s*"?([A-Za-z]+)"?\s*$`)
	svcTypeRe     = regexp.MustCompile(`^\s*type:\s*"?([A-Za-z]+)"?\s*$`)
	hostRe        = regexp.MustCompile(`^\s*-?\s*host:\s*"?([^"'\s]+)"?\s*$`)
	hostPortRe    = regexp.MustCompile(`^\s*-?\s*hostPort:\s*(\d+)\s*$`)
	hostNetRe     = regexp.MustCompile(`^\s*hostNetwork:\s*true\s*$`)
	nodePortRe    = regexp.MustCompile(`^\s*-?\s*nodePort:\s*(\d+)\s*$`)
	publishRe     = regexp.MustCompile(`^\s*-\s*"?(?:(\S+):)?(\d+):(\d+)"?\s*$`) // compose "[BIND:]HOST:CONTAINER"
	publishedRe   = regexp.MustCompile(`^\s*-?\s*published:\s*"?(\d+)"?\s*$`)    // compose long syntax
)

// ingressKinds are Kubernetes-adjacent objects that publish inbound
// traffic beyond a Service.
var ingressKinds = map[string]string{
	"Ingress":        "k8s:Ingress",
	"Route":          "openshift:Route",
	"Gateway":        "gateway-api:Gateway",
	"VirtualService": "istio:VirtualService",
	"IngressRoute":   "traefik:IngressRoute",
}

var authPolicyKinds = map[string]string{
	"AuthorizationPolicy":   "istio:AuthorizationPolicy",
	"RequestAuthentication": "istio:RequestAuthentication",
}

// DeployScanOptions configures deployment manifest discovery and scanning.
type DeployScanOptions struct {
	RootPath    string
	ExtraPaths  []string
	ArchivePath string
}

// ScanDeploy walks root for deployment manifests in deploy-scoped paths
// and returns one fact per published surface it can statically describe.
// It delegates to ScanDeployWithOptions for backward compatibility.
func ScanDeploy(root string) ([]domain.ExposureFact, error) {
	return ScanDeployWithOptions(DeployScanOptions{RootPath: root})
}

// ScanDeployWithOptions scans deployment manifests using provided root, extra paths,
// archive files, and auto-discovery of sibling repositories and root archives.
func ScanDeployWithOptions(opts DeployScanOptions) ([]domain.ExposureFact, error) {
	var allFacts []domain.ExposureFact

	// 1. Explicit archive path
	if opts.ArchivePath != "" {
		facts, err := scanArchive(opts.ArchivePath)
		if err != nil {
			return nil, err
		}
		allFacts = append(allFacts, facts...)
	}

	// 2. Root path scan (deploy-scoped)
	if opts.RootPath != "" {
		facts, err := scanDeployRepo(opts.RootPath)
		if err != nil {
			return nil, err
		}
		allFacts = append(allFacts, facts...)
	}

	// 3. Extra paths
	if len(opts.ExtraPaths) > 0 {
		for _, extraPath := range opts.ExtraPaths {
			facts, err := scanDeployDir(extraPath)
			if err != nil {
				return nil, err
			}
			allFacts = append(allFacts, facts...)
		}
	} else if opts.RootPath != "" {
		// 4. Auto-Discovery (only when ExtraPaths is empty and RootPath is set)
		// 4a. Archives in root (*.tgz, *.tar.gz, *.zip)
		for _, pattern := range []string{"*.tgz", "*.tar.gz", "*.zip"} {
			matches, err := filepath.Glob(filepath.Join(opts.RootPath, pattern))
			if err == nil {
				for _, match := range matches {
					if match == opts.ArchivePath {
						continue
					}
					facts, err := scanArchive(match)
					if err == nil {
						allFacts = append(allFacts, facts...)
					}
				}
			}
		}

		// 4b. Sibling directories (repoName-deploy, repoName-helm, etc.)
		rootAbs := opts.RootPath
		if abs, err := filepath.Abs(rootAbs); err == nil {
			rootAbs = abs
		}
		repoName := filepath.Base(rootAbs)
		parentDir := filepath.Dir(rootAbs)
		siblingSuffixes := []string{"-deploy", "-helm", "-manifests", "-gitops", "-infra"}
		for _, suffix := range siblingSuffixes {
			siblingPath := filepath.Join(parentDir, repoName+suffix)
			if fi, err := os.Stat(siblingPath); err == nil && fi.IsDir() {
				facts, err := scanDeployDir(siblingPath)
				if err == nil {
					allFacts = append(allFacts, facts...)
				}
			}
		}
	}

	return dedupeFacts(allFacts), nil
}

func scanArchive(archivePath string) ([]domain.ExposureFact, error) {
	tmpDir, err := os.MkdirTemp("", "deploy-archive-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := extractArchive(archivePath, tmpDir); err != nil {
		return nil, err
	}

	return scanDeployDir(tmpDir)
}

func scanDeployRepo(root string) ([]domain.ExposureFact, error) {
	var out []domain.ExposureFact
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if deploySkipDirs[e.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !deployPath(root, path) {
			return nil
		}
		if info, err := e.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		facts, err := scanDeployFile(root, path)
		if err != nil {
			return nil
		}
		out = append(out, facts...)
		return nil
	})
	return out, err
}

func scanDeployDir(dir string) ([]domain.ExposureFact, error) {
	var out []domain.ExposureFact
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if deploySkipDirs[e.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		lowerBase := strings.ToLower(base)
		isYAML := strings.HasSuffix(lowerBase, ".yaml") || strings.HasSuffix(lowerBase, ".yml")
		isCompose := composeFileRe.MatchString(base)
		isDocker := dockerfileRe.MatchString(base)
		if !isYAML && !isCompose && !isDocker {
			return nil
		}
		if info, err := e.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		facts, err := scanDeployFile(dir, path)
		if err != nil {
			return nil
		}
		out = append(out, facts...)
		return nil
	})
	return out, err
}

func dedupeFacts(facts []domain.ExposureFact) []domain.ExposureFact {
	seen := make(map[string]bool, len(facts))
	var out []domain.ExposureFact
	for _, f := range facts {
		key := f.Direction + "|" + f.Kind + "|" + f.Target + "|" + f.Address + "|" + f.Scope
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// deployPath reports whether path lives under a deploy-scoped directory
// or is a compose/Dockerfile at any depth.
func deployPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	base := filepath.Base(rel)
	if composeFileRe.MatchString(base) || dockerfileRe.MatchString(base) {
		return true
	}
	if !strings.HasSuffix(strings.ToLower(base), ".yaml") &&
		!strings.HasSuffix(strings.ToLower(base), ".yml") {
		return false
	}
	for _, part := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
		if deployDirRe.MatchString(part) {
			return true
		}
	}
	return false
}

func scanDeployFile(root, path string) ([]domain.ExposureFact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(root, path)
	if rel == "." || rel == "" {
		rel = filepath.Base(path)
	}
	var out []domain.ExposureFact
	kind := ""
	line := 0
	svcLine := 0
	sawSvcType := false

	flushService := func() {
		if kind == "Service" && !sawSvcType && svcLine > 0 {
			out = append(out, deployFactWithScope("k8s:Service:ClusterIP", "ClusterIP", rel, svcLine, domain.ScopeLoopback))
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line++
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "---" {
			flushService()
			kind = ""
			svcLine = 0
			sawSvcType = false
			continue
		}
		if m := kindRe.FindStringSubmatch(text); m != nil {
			flushService()
			kind = m[1]
			svcLine = line
			sawSvcType = false
			if t, ok := ingressKinds[kind]; ok {
				out = append(out, deployFact(t, "", rel, line))
			} else if t, ok := authPolicyKinds[kind]; ok {
				out = append(out, deployAuthFact(t, rel, line))
			}
			continue
		}
		if m := hostPortRe.FindStringSubmatch(text); m != nil {
			out = append(out, deployFact("k8s:hostPort", "hostPort="+m[1], rel, line))
			continue
		}
		if hostNetRe.MatchString(text) {
			out = append(out, deployFact("k8s:hostNetwork", "hostNetwork=true", rel, line))
			continue
		}
		if kind == "Service" {
			if m := svcTypeRe.FindStringSubmatch(text); m != nil {
				sawSvcType = true
				switch m[1] {
				case "LoadBalancer", "NodePort", "ExternalName":
					out = append(out, deployFact("k8s:Service:"+m[1], m[1], rel, line))
				case "ClusterIP":
					out = append(out, deployFactWithScope("k8s:Service:ClusterIP", m[1], rel, line, domain.ScopeLoopback))
				}
				continue
			}
			if m := nodePortRe.FindStringSubmatch(text); m != nil {
				sawSvcType = true
				out = append(out, deployFact("k8s:Service:NodePort", "nodePort="+m[1], rel, line))
			}
			continue
		}
		if m := hostRe.FindStringSubmatch(text); m != nil && kind != "" &&
			ingressKinds[kind] != "" && len(out) > 0 {
			last := &out[len(out)-1]
			if last.Address == "" {
				last.Address = m[1]
			}
		}
		// Compose published ports: "- \"[BIND:]HOST:CONTAINER\"" entries and
		// long-syntax "published:" keys. A loopback bind (127.0.0.1:8080:80)
		// is internal evidence; any other or absent bind exposes the port.
		if composeFileRe.MatchString(filepath.Base(path)) {
			if m := publishRe.FindStringSubmatch(text); m != nil {
				addr := m[2] + ":" + m[3]
				fact := deployFact("compose:published-port", addr, rel, line)
				if m[1] != "" {
					addr = m[1] + ":" + m[2] + ":" + m[3]
					fact.Address = addr
					fact.Scope = Scope(m[1] + ":" + m[2])
				}
				out = append(out, fact)
			} else if m := publishedRe.FindStringSubmatch(text); m != nil {
				out = append(out, deployFact("compose:published-port",
					"published="+m[1], rel, line))
			}
		}
	}
	flushService()
	return out, sc.Err()
}

func deployFact(target, addr, file string, line int) domain.ExposureFact {
	src := "manifest"
	if strings.Contains(addr, "{{") {
		addr = ""
		src = "template"
	}
	return domain.ExposureFact{
		CallSite:      domain.CallSite{File: file, Line: line},
		Direction:     "inbound",
		Kind:          "deployment",
		Target:        target,
		Address:       addr,
		AddressSource: src + " " + file,
		Scope:         domain.ScopeAllInterfaces,
	}
}

func deployFactWithScope(target, addr, file string, line int, scope string) domain.ExposureFact {
	fact := deployFact(target, addr, file, line)
	fact.Scope = scope
	return fact
}

func deployAuthFact(target, file string, line int) domain.ExposureFact {
	return domain.ExposureFact{
		CallSite:      domain.CallSite{File: file, Line: line},
		Direction:     "inbound",
		Kind:          "auth-middleware",
		Target:        target,
		AddressSource: "manifest " + file,
		Scope:         domain.ScopeLoopback,
	}
}
