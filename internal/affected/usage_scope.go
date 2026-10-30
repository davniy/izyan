package affected

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// UsageScope classifies where a package/module is reachable in the recorded
// build closures. It is a bounded build-graph statement, never a safety
// verdict.
type UsageScope string

const (
	UsageScopeProduct  UsageScope = "product"
	UsageScopeTestOnly UsageScope = "test-only"
	UsageScopeMixed    UsageScope = "mixed"
	UsageScopeUnknown  UsageScope = "unknown"
)

// UsageScopeSourceGoList names the paired `go list` derivation — the
// recorded streams are the closure evidence.
const UsageScopeSourceGoList = "go list -deps -json ./..."

// ProductAbsenceVerificationVerified marks that a test-only classification
// rested on two complete, edge-closed `go list` streams — i.e. the product
// closure was actually computed and checked, not assumed.
const ProductAbsenceVerificationVerified = "VERIFIED"

// ProductAbsenceVerificationVendorInventory marks that an
// absent-from-both classification under the offline derivation rested on
// a complete, consistency-checked vendor inventory (vendor/modules.txt
// reconciled with go.mod requires/replaces and the vendor tree): the
// exact advisory-bound subject is absent from the product build closure
// under the recorded closed inventory. It is valid only with
// usage_scope=unknown under a vendor_mode=true build context — never a
// runtime, deployment or safety claim and never a substitution for B42
// negative_verification.
const ProductAbsenceVerificationVendorInventory = "VERIFIED_VENDOR_INVENTORY"

// ClosureSemanticsProductAllPackages names the fixed B41 product-root
// semantics both derivations implement: the product closure is the
// transitive build closure of every applicable first-party package
// directory matched by ./... under the recorded build context — not a
// selected shipped binary and not narrowed by directory names.
const ClosureSemanticsProductAllPackages = "product_all_packages"

// UsageScopeResult is the outcome of ClassifyUsageScope or the offline
// DeriveVendorUsageScope. Source records which derivation produced it —
// "go list -deps -json ./..." or VendorClosureSource — the auditor's
// evidence source. On error the partial result is returned with
// Usage=UsageScopeUnknown; callers must not treat any field of an
// errored result as a closed negative.
type UsageScopeResult struct {
	Module  string
	Package string

	ProductLinked bool
	TestLinked    bool
	Usage         UsageScope
	Source        string

	ProductAbsenceVerification string

	ProductPackageCount int
	TestPackageCount    int
	ProductRootCount    int
	TestRootCount       int

	CheckScope  string
	Limitations []string
}

// packageGraph is one decoded `go list -deps [-test] -json` stream with its
// root partition and edge-closed reachability sets.
type packageGraph struct {
	nodes     map[string]*Package // keyed by exact ImportPath (variants keep brackets)
	hasDeps   bool                // stream carries Deps fields at all
	prodRoots []string            // sorted exact paths of product roots
	testRoots []string            // sorted exact paths of test roots
	prodSet   map[string]bool     // canonical paths reachable from product roots
	testSet   map[string]bool     // canonical paths reachable from test roots
	allRaw    map[string]bool     // exact-path reachability union (coverage check)
}

// canonicalImportPath strips the synthetic ` [x.test]` variant suffix: a
// test-variant node shares the build identity of its base package. Import
// paths cannot contain spaces, so the first space delimits the annotation.
func canonicalImportPath(p string) string {
	if i := strings.IndexByte(p, ' '); i >= 0 {
		return p[:i]
	}
	return p
}

// isTestDriverPath reports whether p is a synthetic test binary main
// (`ImportPath` ends in `.test` and the package name is `main`).
func isTestDriverPath(p *Package) bool {
	return p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test")
}

// isProductRoot identifies non-test `./...` roots: real packages the pattern
// matched, never dependency-only nodes, test variants or synthetic drivers.
func isProductRoot(p *Package) bool {
	return !p.DepOnly && p.ForTest == "" && !isTestDriverPath(p)
}

// isTestRoot identifies recognised test reachability roots: `ForTest`
// variants (test-augmented and external test packages) and synthetic `.test`
// driver mains. Plain presence in the merged `-test` stream is NOT a test
// root — a product-only dep listed there is not test-reachable.
func isTestRoot(p *Package) bool {
	return p.ForTest != "" || isTestDriverPath(p)
}

// buildPackageGraph decodes one raw stream and applies the completeness
// rules below. Any decode failure, package-error node, duplicate node,
// dangling edge or node unreachable from every root makes the stream
// incomplete — an error, never a closed negative.
func buildPackageGraph(raw []byte, cmd string) (*packageGraph, error) {
	pkgs, err := decodePackages(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: decode package stream: %w", cmd, err)
	}
	return buildPackageGraphPackages(pkgs, cmd)
}

// buildPackageGraphPackages applies the completeness rules to an already
// decoded stream. It is the single graph validator shared by
// ClassifyUsageScope, buildPackageGraph and CompletePackageInventory — no
// caller may restate a weaker version of these rules.
func buildPackageGraphPackages(pkgs []Package, cmd string) (*packageGraph, error) {
	// An empty stream — empty stdout or an empty array — is a missing
	// enumeration, not evidence of an empty scope. `go list` never
	// succeeds with zero packages for a matching ./... pattern.
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s: stream decoded zero packages (missing enumeration, not a closed negative)", cmd)
	}
	g := &packageGraph{nodes: make(map[string]*Package, len(pkgs))}
	var errNodes []string
	for i := range pkgs {
		p := &pkgs[i]
		if p.ImportPath == "" {
			return nil, fmt.Errorf("%s: package node with empty ImportPath", cmd)
		}
		if _, dup := g.nodes[p.ImportPath]; dup {
			return nil, fmt.Errorf("%s: duplicate package node %q", cmd, p.ImportPath)
		}
		g.nodes[p.ImportPath] = p
		if len(p.Deps) > 0 {
			g.hasDeps = true
		}
		if p.Incomplete || p.Error != nil || len(p.DepsErrors) > 0 {
			errNodes = append(errNodes, p.ImportPath)
		}
		if isProductRoot(p) {
			g.prodRoots = append(g.prodRoots, p.ImportPath)
		}
		if isTestRoot(p) {
			g.testRoots = append(g.testRoots, p.ImportPath)
		}
	}
	if len(errNodes) > 0 {
		sort.Strings(errNodes)
		return nil, fmt.Errorf("%s: stream carries package errors (incomplete), e.g. %s", cmd, strings.Join(errNodes, ", "))
	}
	sort.Strings(g.prodRoots)
	sort.Strings(g.testRoots)

	// Edges: Deps is authoritative; Imports is the traversal fallback only
	// when the stream explicitly provides no Deps anywhere.
	edges := func(p *Package) []string {
		if g.hasDeps {
			return p.Deps
		}
		return p.Imports
	}
	var dangling, inconsistent []string
	for path, p := range g.nodes {
		if g.hasDeps && p.Deps == nil && len(p.Imports) > 0 {
			// The stream carries dependency inventories elsewhere, so an
			// omitted Deps field here is a missing inventory — its Imports
			// are unverified edges that must not silently read as empty.
			inconsistent = append(inconsistent, path+" (omitted Deps with non-empty Imports)")
			continue
		}
		for _, dep := range edges(p) {
			if _, ok := g.nodes[dep]; !ok && !isPseudoImport(dep) {
				dangling = append(dangling, path+" -> "+dep)
			}
		}
		if g.hasDeps && p.Deps != nil {
			// When Deps is authoritative, Imports still describes the same
			// resolved dependencies: a real go list stream always satisfies
			// Imports ⊆ Deps. Any deviation is an inconsistent inventory.
			deps := make(map[string]bool, len(p.Deps))
			for _, d := range p.Deps {
				deps[d] = true
			}
			for _, imp := range p.Imports {
				if !deps[imp] && !isPseudoImport(imp) {
					inconsistent = append(inconsistent, path+" -> "+imp+" (in Imports but not in Deps)")
				}
			}
		}
	}
	if len(inconsistent) > 0 {
		sort.Strings(inconsistent)
		return nil, fmt.Errorf("%s: inconsistent dependency inventory (incomplete), e.g. %s", cmd, strings.Join(inconsistent, ", "))
	}
	if len(dangling) > 0 {
		sort.Strings(dangling)
		return nil, fmt.Errorf("%s: unresolved dependency edges (incomplete), e.g. %s", cmd, strings.Join(dangling, ", "))
	}

	walk := func(roots []string) map[string]bool {
		seen := make(map[string]bool, len(g.nodes))
		stack := append([]string(nil), roots...)
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[n] {
				continue
			}
			seen[n] = true
			p, ok := g.nodes[n]
			if !ok {
				continue // pseudo-import edge target — never a package node
			}
			for _, dep := range edges(p) {
				// Pseudo-imports are exempt from edge checks and must never
				// be traversed: they have no package node to dereference.
				if !isPseudoImport(dep) {
					stack = append(stack, dep)
				}
			}
		}
		return seen
	}
	prodVisited := walk(g.prodRoots)
	testVisited := walk(g.testRoots)
	g.prodSet = canonicalSet(prodVisited)
	g.testSet = canonicalSet(testVisited)
	g.allRaw = make(map[string]bool, len(prodVisited)+len(testVisited))
	for p := range prodVisited {
		g.allRaw[p] = true
	}
	for p := range testVisited {
		g.allRaw[p] = true
	}
	var orphans []string
	for path := range g.nodes {
		if !g.allRaw[path] {
			orphans = append(orphans, path)
		}
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		return nil, fmt.Errorf("%s: packages unreachable from any root (inconsistent stream): %s", cmd, strings.Join(orphans, ", "))
	}
	return g, nil
}

// isPseudoImport reports toolchain pseudo-imports that go list may record
// in Imports/Deps but that are not package nodes ("C" for cgo). They are
// exempt from edge/inventory checks, never evidence of package absence.
func isPseudoImport(p string) bool {
	return p == "C"
}

func canonicalSet(raw map[string]bool) map[string]bool {
	out := make(map[string]bool, len(raw))
	for p := range raw {
		out[canonicalImportPath(p)] = true
	}
	return out
}

// moduleMatches reports whether a node belongs to the target module: by
// declared module identity when present, else by the exact module-prefix
// rule. EffectivePath is deliberately NOT used: a replace directive changes
// where bytes come from, not which module the package is a member of. The
// module path is never promoted into a package path — this only selects
// already-declared package nodes for a module-level aggregate.
func moduleMatches(p *Package, module string) bool {
	if p.Module != nil {
		return p.Module.Path == module
	}
	path := canonicalImportPath(p.ImportPath)
	return path == module || strings.HasPrefix(path, module+"/")
}

// usageCheckScope records exactly what the classification checked.
func usageCheckScope(build domain.ProductSnapshot, module, packagePath string) string {
	target := "module " + module + " (module-level aggregate, not a package claim)"
	if packagePath != "" {
		target = "package " + packagePath + " in module " + module
	}
	tags := "(none)"
	if len(build.BuildTags) > 0 {
		tags = strings.Join(build.BuildTags, ",")
	}
	cgo := "0"
	if build.CGOEnabled {
		cgo = "1"
	}
	return fmt.Sprintf(
		"product closure: `go list -deps -json ./...` (no -test), roots = non-DepOnly packages matched by ./...; "+
			"test closure: `go list -deps -test -json ./...`, restricted to packages reachable from ForTest variants and synthetic .test driver mains; "+
			"build context: GOOS=%s GOARCH=%s CGO_ENABLED=%s build tags=%s; "+
			"target: %s; scope: static build/linker dependency graph only — runtime, deployment, reflection, plugin and generated loading are out of scope",
		build.GOOS, build.GOARCH, cgo, tags, target)
}

// ClassifyUsageScope computes the deterministic dual build-closure
// classification for an advisory-declared package (or module-only) target.
//
// Semantics:
//   - product closure P: `go list -deps -json ./...`, reachable from
//     non-DepOnly roots;
//   - test closure T: `go list -deps -test -json ./...`, reachable only from
//     ForTest variants and .test driver mains;
//   - P∧¬T → product, ¬P∧T → test-only, P∧T → mixed, ¬P∧¬T → unknown.
//
// Fail-closed: any command error, decode failure, package-error node,
// dangling edge, inconsistent stream or absent-from-both target yields
// `unknown` (or an error) — never `test-only`. `test-only` additionally
// requires both closures complete, recorded as
// ProductAbsenceVerification=VERIFIED.
func ClassifyUsageScope(
	ctx context.Context,
	tool GoTool,
	dir string,
	build domain.ProductSnapshot,
	module string,
	packagePath string,
) (UsageScopeResult, error) {
	res := UsageScopeResult{
		Module:     module,
		Package:    packagePath,
		Usage:      UsageScopeUnknown,
		Source:     UsageScopeSourceGoList,
		CheckScope: usageCheckScope(build, module, packagePath),
	}
	if packagePath == "" {
		res.Limitations = []string{
			"module-level aggregate over package nodes matching the module identity; not a claim about an affected package and not package-level proof",
		}
	}

	const prodCmd = "go list -deps -json ./..."
	const testCmd = "go list -deps -test -json ./..."
	prodRaw, err := tool.ListPackagesScope(ctx, dir, build, false)
	if err != nil {
		return res, fmt.Errorf("%s: %w", prodCmd, err)
	}
	testRaw, err := tool.ListPackagesScope(ctx, dir, build, true)
	if err != nil {
		return res, fmt.Errorf("%s: %w", testCmd, err)
	}
	prod, err := buildPackageGraph(prodRaw, prodCmd)
	if err != nil {
		return res, err
	}
	test, err := buildPackageGraph(testRaw, testCmd)
	if err != nil {
		return res, err
	}
	// Absence claims need a resolved product-root inventory: a stream whose
	// `./...` roots are absent or unresolved cannot distinguish an empty
	// scope from a failed enumeration. Zero test roots, by contrast, are a
	// legitimate "no test binaries" outcome of a complete stream.
	if len(prod.prodRoots) == 0 {
		return res, fmt.Errorf("%s: stream resolved no product roots (missing enumeration, not a closed negative)", prodCmd)
	}
	if len(test.prodRoots) == 0 {
		return res, fmt.Errorf("%s: stream resolved no product roots (missing enumeration, not a closed negative)", testCmd)
	}

	classifyClosures(prod, test, module, packagePath, &res)
	return res, nil
}

// classifyClosures fills the classification fields of res from a pair of
// root-partitioned package graphs — the same tail both derivations
// share. prod carries the product roots/reachability, test the test
// roots/reachability; when one unified graph carries both (offline
// derivation) the caller passes it twice.
func classifyClosures(prod, test *packageGraph, module, packagePath string, res *UsageScopeResult) {
	res.ProductPackageCount = len(prod.prodSet)
	res.TestPackageCount = len(test.testSet)
	res.ProductRootCount = len(prod.prodRoots)
	res.TestRootCount = len(test.testRoots)

	if packagePath != "" {
		res.ProductLinked = prod.prodSet[packagePath]
		res.TestLinked = test.testSet[packagePath]
	} else {
		// Module-only target: aggregate over nodes whose module identity
		// matches. No package subject is manufactured.
		for _, p := range prod.nodes {
			if moduleMatches(p, module) && prod.prodSet[canonicalImportPath(p.ImportPath)] {
				res.ProductLinked = true
				break
			}
		}
		for _, p := range test.nodes {
			if moduleMatches(p, module) && test.testSet[canonicalImportPath(p.ImportPath)] {
				res.TestLinked = true
				break
			}
		}
	}

	switch {
	case res.ProductLinked && res.TestLinked:
		res.Usage = UsageScopeMixed
	case res.ProductLinked:
		res.Usage = UsageScopeProduct
	case res.TestLinked:
		res.Usage = UsageScopeTestOnly
		res.ProductAbsenceVerification = ProductAbsenceVerificationVerified
	default:
		res.Usage = UsageScopeUnknown
	}
}
