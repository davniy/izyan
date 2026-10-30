package affected

import (
	"context"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// VendorClosureSource names the offline closure derivation: vendor
// inventory plus source imports, never a `go list` subprocess.
const VendorClosureSource = "vendor/modules.txt+source-imports"

// DeriveVendorUsageScope computes the same dual product/test build-closure
// classification as ClassifyUsageScope but derives it offline from the
// vendored snapshot: vendor/modules.txt supplies the dependency package
// inventory, go.mod supplies module identity/requires/replaces, and the
// recorded GOOS/GOARCH/CGO/build-tag context selects applicable source
// files whose parsed imports form the graph edges. It mirrors
// `go list -deps -json ./...` semantics: product roots are the
// first-party package dirs matched by ./... under the build context;
// test roots are the internal/external test variants and the synthetic
// .test driver mains; standard library packages resolve as opaque leaf
// nodes (stdlib-internal edges are outside the model), so a stdlib-shaped
// target not directly product-linked classifies unknown with a named
// limitation, never test-only.
//
// Fail-closed: unreadable/unparsable files, malformed or undecidable
// build constraints, applicable cgo imports, unresolved imports, illegal
// internal/vendor path traversal, package-name conflicts, unsupported
// build inputs (.swig/.syso), incomplete or inconsistent
// vendor/modules.txt, a go.work composition and import cycles all
// return an error — never a closed negative.
//
// When the closed derivation finds the subject absent from both
// closures (usage=unknown) under a recorded vendor_mode=true context,
// the result additionally carries
// ProductAbsenceVerificationVendorInventory: the exact advisory-bound
// subject is absent from the product build closure under the recorded
// closed vendor inventory — a bounded build-graph statement, never a
// runtime, deployment or safety claim. A package-level subject is
// absent at exact package identity; a module-level subject
// additionally requires the module absent from go.mod
// requires/replaces, the modules.txt inventory, the vendor tree
// contents and the first-party package set — nothing manufactures a
// package path from a module path.
func DeriveVendorUsageScope(
	ctx context.Context,
	dir string,
	build domain.ProductSnapshot,
	module, packagePath string,
) (UsageScopeResult, error) {
	res := UsageScopeResult{
		Module:     module,
		Package:    packagePath,
		Usage:      UsageScopeUnknown,
		Source:     VendorClosureSource,
		CheckScope: vendorCheckScope(build, module, packagePath),
	}
	if packagePath == "" {
		res.Limitations = []string{
			"module-level aggregate over package nodes matching the module identity; not a claim about an affected package and not package-level proof",
		}
	}
	g, d, err := buildVendorGraph(ctx, dir, build)
	if err != nil {
		return res, err
	}
	classifyClosures(g, g, module, packagePath, &res)
	stdlibShaped := packagePath != "" && isStdlibImportPath(packagePath)
	if packagePath == "" {
		stdlibShaped = isStdlibModule(module)
	}
	if stdlibShaped && !res.ProductLinked {
		// A stdlib-shaped target absent from the product set may still be
		// reachable through stdlib-internal edges the model does not
		// enumerate: verified product absence degrades to undetermined,
		// never to test-only.
		res.Usage = UsageScopeUnknown
		res.ProductAbsenceVerification = ""
		res.Limitations = append(res.Limitations,
			"stdlib-internal edges are opaque to this derivation: a target not directly product-linked cannot be verified absent, only unclassified")
	}
	if res.Usage == UsageScopeUnknown && res.ProductAbsenceVerification == "" &&
		!stdlibShaped && build.VendorMode &&
		(packagePath != "" || d.moduleInventoryAbsent(module)) {
		res.ProductAbsenceVerification = ProductAbsenceVerificationVendorInventory
	}
	return res, nil
}

// moduleInventoryAbsent reports whether the advisory module is absent
// from every inventory the closed derivation trusts: go.mod requires
// and replace left-hand sides, the modules.txt module headers, the
// vendor tree contents attributable to that exact module identity, and
// the first-party package set. Descendant or sibling modules sharing a
// path prefix (a vendored `…/v2` tree is not `…`) never count — module
// identity is exact.
func (d *vendorDeriver) moduleInventoryAbsent(module string) bool {
	if _, ok := d.reqs[module]; ok {
		return false
	}
	for _, r := range d.reps {
		if r.Old.Path == module {
			return false
		}
	}
	if d.vendoredMods[module] {
		return false
	}
	if dirHasGoFile(filepath.Join(d.root, "vendor", filepath.FromSlash(module))) {
		return false
	}
	for _, m := range d.pkgMod {
		if m.Path == module {
			return false
		}
	}
	for _, n := range d.nodes {
		if moduleMatches(n, module) {
			return false
		}
	}
	return true
}

// vendorCheckScope records exactly what the offline derivation checked.
func vendorCheckScope(build domain.ProductSnapshot, module, packagePath string) string {
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
		"closed vendor/source build closure: product closure = packages reachable by source-import edges from first-party dirs matched by ./...; "+
			"test closure = packages reachable from internal/external test variants and synthetic .test driver mains; "+
			"dependency resolution through vendor/modules.txt (consistency-checked against go.mod), stdlib as opaque leaves; "+
			"build context: GOOS=%s GOARCH=%s CGO_ENABLED=%s build tags=%s; "+
			"target: %s; scope: static build/linker import graph only — runtime, deployment, reflection, plugin, generated and linkname-assisted loading are out of scope",
		build.GOOS, build.GOARCH, cgo, tags, target)
}

// dirScan is one package directory evaluated under the recorded build
// context: the applicable non-test file set, the internal and external
// test import sets, and the package name each class resolves to.
type dirScan struct {
	prodImports  []string
	prodName     string
	hasProd      bool
	intImports   []string
	hasIntTest   bool
	extImports   []string
	hasExtTest   bool
	testBaseName string
}

// nodeKind enumerates the lazily-expanded package node classes.
type nodeKind int

const (
	kindStd nodeKind = iota // opaque stdlib leaf — no edges
	kindProd
	kindVendor
	kindIntVariant
	kindExtVariant
	kindDriver
)

// vendorDeriver carries the parsed manifests and the lazily-expanded
// package graph for one snapshot root.
type vendorDeriver struct {
	ctx    context.Context
	root   string
	bctx   build.Context
	build  domain.ProductSnapshot
	main   string
	reqs   map[string]*modfile.Require
	reps   []*modfile.Replace
	pkgDir map[string]string
	pkgMod map[string]Module
	// vendoredMods records every module header modules.txt carried —
	// including zero-package headers pkgMod can never see.
	vendoredMods map[string]bool
	relSet       map[string]bool
	relExact     bool // floor pinned by a toolchain version, not just the go.mod directive
	scans        map[string]*dirScan
	nodes        map[string]*Package
	kinds        map[string]nodeKind
	dirs         map[string]string // node key -> package dir for edge expansion
	drvDeps      map[string][]string
	edges        map[string][]string
	done         map[string]bool
}

// buildVendorGraph assembles the node universe, expands edges lazily per
// reachability and returns a packageGraph whose prod/test roots and sets
// carry the offline-derived closures, plus the deriver whose parsed
// manifests back the module-level inventory-absence check.
func buildVendorGraph(ctx context.Context, dir string, build domain.ProductSnapshot) (*packageGraph, *vendorDeriver, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("vendor/source closure: snapshot root: %w", err)
	}
	if canon, cerr := filepath.EvalSymlinks(root); cerr == nil {
		root = canon
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err == nil {
		return nil, nil, fmt.Errorf("vendor/source closure: go.work present — workspace module composition is outside the supported model")
	}
	d := &vendorDeriver{
		ctx:          ctx,
		root:         root,
		build:        build,
		pkgDir:       map[string]string{},
		pkgMod:       map[string]Module{},
		vendoredMods: map[string]bool{},
		scans:        map[string]*dirScan{},
		nodes:        map[string]*Package{},
		kinds:        map[string]nodeKind{},
		dirs:         map[string]string{},
		drvDeps:      map[string][]string{},
		edges:        map[string][]string{},
		done:         map[string]bool{},
	}
	if err := d.loadManifests(); err != nil {
		return nil, nil, err
	}
	if err := d.enumerateFirstParty(); err != nil {
		return nil, nil, err
	}
	g := &packageGraph{nodes: d.nodes}
	for path := range d.nodes {
		p := d.nodes[path]
		if isProductRoot(p) {
			g.prodRoots = append(g.prodRoots, path)
		}
		if isTestRoot(p) {
			g.testRoots = append(g.testRoots, path)
		}
	}
	sort.Strings(g.prodRoots)
	sort.Strings(g.testRoots)
	if len(g.prodRoots) == 0 {
		return nil, nil, fmt.Errorf("vendor/source closure: ./... matched no first-party packages under the recorded build context (missing enumeration, not a closed negative)")
	}
	// Edge expansion happens inside the closure walks; an expansion
	// error is collected first, never truncated into a partial set.
	var edgeErr error
	walkE := func(roots []string) map[string]bool {
		seen := make(map[string]bool, len(d.nodes))
		stack := append([]string(nil), roots...)
		for len(stack) > 0 && edgeErr == nil {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[n] {
				continue
			}
			seen[n] = true
			edges, err := d.edgesOf(n)
			if err != nil {
				edgeErr = err
				break
			}
			stack = append(stack, edges...)
		}
		return seen
	}
	prodVisited := walkE(g.prodRoots)
	if edgeErr != nil {
		return nil, nil, edgeErr
	}
	testVisited := walkE(g.testRoots)
	if edgeErr != nil {
		return nil, nil, edgeErr
	}
	g.prodSet = canonicalSet(prodVisited)
	g.testSet = canonicalSet(testVisited)
	if cyc := findCycle(g.prodRoots, d.edges); cyc != "" {
		return nil, nil, fmt.Errorf("vendor/source closure: import cycle through %s — the build graph is not compilable, never a closed negative", cyc)
	}
	if cyc := findCycle(g.testRoots, d.edges); cyc != "" {
		return nil, nil, fmt.Errorf("vendor/source closure: import cycle through %s — the build graph is not compilable, never a closed negative", cyc)
	}
	return g, d, nil
}

// edgesOf returns (memoized, cycle-safely) the resolved import paths of
// one node. done is set before expansion so a self-referential chain
// records the edge without recursing forever; findCycle reports it.
func (d *vendorDeriver) edgesOf(key string) ([]string, error) {
	if d.done[key] {
		return d.edges[key], nil
	}
	d.done[key] = true
	var out []string
	switch d.kinds[key] {
	case kindStd:
	case kindDriver:
		out = append(out, d.drvDeps[key]...)
	case kindProd, kindVendor:
		scan, err := d.scanDir(d.dirs[key])
		if err != nil {
			return nil, err
		}
		imports, err := d.resolveAll(scan.prodImports, d.dirs[key])
		if err != nil {
			return nil, err
		}
		out = append(out, imports...)
	case kindIntVariant, kindExtVariant:
		scan, err := d.scanDir(d.dirs[key])
		if err != nil {
			return nil, err
		}
		var raw []string
		if d.kinds[key] == kindIntVariant {
			raw = append(append([]string(nil), scan.prodImports...), scan.intImports...)
		} else {
			raw = scan.extImports
		}
		imports, err := d.resolveAll(raw, d.dirs[key])
		if err != nil {
			return nil, err
		}
		out = append(out, imports...)
	}
	d.edges[key] = out
	return out, nil
}

// buildContextFor renders the recorded build context as a go/build
// context; an unrecorded GOOS/GOARCH defaults to the host pair, exactly
// the fallback the toolchain itself applies. Recorded product targets
// always carry explicit values; callers that must not accept a host
// fallback (a product-wide platform conclusion) check the snapshot before
// calling this helper.
func buildContextFor(snap domain.ProductSnapshot) build.Context {
	b := build.Context{
		GOOS:       snap.GOOS,
		GOARCH:     snap.GOARCH,
		Compiler:   "gc",
		CgoEnabled: snap.CGOEnabled,
		BuildTags:  append([]string(nil), snap.BuildTags...),
	}
	if b.GOOS == "" {
		b.GOOS = runtime.GOOS
	}
	if b.GOARCH == "" {
		b.GOARCH = runtime.GOARCH
	}
	return b
}

// recordedBuild is the rendered go/build context plus the go1.* release
// floor it was pinned to. The verifier and the vendor closure consume the
// same value so build-constraint selection cannot diverge between the
// usage-scope derivation and an implementation-locus proof.
type recordedBuild struct {
	ctx      build.Context
	relSet   map[string]bool
	relExact bool
}

// newRecordedBuild renders the recorded build context and pins
// ReleaseTags to the recorded toolchain floor: with a recorded toolchain
// version (analysis GoVersion or the release toolchain) go1.N at or below
// it is satisfied and above it is deterministically excluded; with only
// the go.mod directive as floor, higher tags stay undecidable and callers
// must fail closed. See releaseFloor for the full contract.
func newRecordedBuild(snap domain.ProductSnapshot, gomod *modfile.File) (recordedBuild, error) {
	rb := recordedBuild{ctx: buildContextFor(snap)}
	dirMinor := 0
	if gomod != nil && gomod.Go != nil {
		dirMinor = goMinor(gomod.Go.Version)
	}
	toolMinor := goMinor(snap.GoVersion)
	if toolMinor == 0 {
		toolMinor = goMinor(snap.ReleaseGoVersion)
	}
	rb.relExact = toolMinor != 0
	minor := toolMinor
	if minor == 0 {
		minor = dirMinor
	}
	if toolMinor != 0 && dirMinor != 0 && toolMinor < dirMinor {
		return rb, fmt.Errorf("recorded toolchain go1.%d is below the go.mod directive go %s — the recorded build cannot exist",
			toolMinor, gomod.Go.Version)
	}
	if minor == 0 {
		return rb, nil
	}
	rb.relSet = map[string]bool{}
	for i := 1; i <= minor; i++ {
		rb.relSet[fmt.Sprintf("go1.%d", i)] = true
	}
	rb.ctx.ReleaseTags = make([]string, 0, len(rb.relSet))
	for tag := range rb.relSet {
		rb.ctx.ReleaseTags = append(rb.ctx.ReleaseTags, tag)
	}
	sort.Strings(rb.ctx.ReleaseTags)
	return rb, nil
}

// loadManifests parses go.mod and vendor/modules.txt and enforces their
// mutual consistency: every vendored module header must be required in
// go.mod, marked ## explicit with a matching version and replace, list
// at least one package inside its own path space that exists on disk;
// every vendor dir carrying .go files must be listed. Anything else is
// incomplete or inconsistent vendor metadata and fails closed.
func (d *vendorDeriver) loadManifests() error {
	modBytes, err := os.ReadFile(filepath.Join(d.root, "go.mod"))
	if err != nil {
		return fmt.Errorf("vendor/source closure: read go.mod: %w", err)
	}
	gomod, err := modfile.Parse("go.mod", modBytes, nil)
	if err != nil {
		return fmt.Errorf("vendor/source closure: parse go.mod: %w", err)
	}
	if gomod.Module == nil || gomod.Module.Mod.Path == "" {
		return fmt.Errorf("vendor/source closure: go.mod carries no module directive")
	}
	d.main = gomod.Module.Mod.Path
	d.reqs = map[string]*modfile.Require{}
	for _, r := range gomod.Require {
		d.reqs[r.Mod.Path] = r
	}
	d.reps = gomod.Replace
	if err := d.releaseFloor(gomod); err != nil {
		return err
	}
	mtBytes, err := os.ReadFile(filepath.Join(d.root, "vendor", "modules.txt"))
	if err != nil {
		return fmt.Errorf("vendor/source closure: read vendor/modules.txt: %w", err)
	}
	return d.parseVendorModules(mtBytes)
}

// releaseFloor establishes how go1.* constraint tags decide under the
// recorded build context. With a recorded toolchain version (analysis
// GoVersion or the release toolchain) the floor is exact: go1.N at or
// below it is satisfied, above it is deterministically excluded — the
// same evaluation `go list` performs. With only the go.mod directive as
// floor, tags at or below it hold for every buildable toolchain while
// any higher tag stays undecidable and must fail closed.
func (d *vendorDeriver) releaseFloor(gomod *modfile.File) error {
	rb, err := newRecordedBuild(d.build, gomod)
	if err != nil {
		return fmt.Errorf("vendor/source closure: %w", err)
	}
	d.bctx = rb.ctx
	d.relSet = rb.relSet
	d.relExact = rb.relExact
	return nil
}

// goMinor extracts the N of a go version like "go1.25.0", "1.25" or
// "go1.26rc1"; 0 when unparseable.
func goMinor(v string) int {
	v = strings.TrimPrefix(v, "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0
	}
	m := parts[1]
	for i, r := range m {
		if r < '0' || r > '9' {
			m = m[:i]
			break
		}
	}
	n, err := strconv.Atoi(m)
	if err != nil {
		return 0
	}
	return n
}

// parseVendorModules parses modules.txt strictly: module headers, ##
// annotations, package lines and the trailing replace mirror.
func (d *vendorDeriver) parseVendorModules(b []byte) error {
	type header struct {
		mod      Module
		explicit bool
		pkgs     int
	}
	var mods []*header
	byPath := map[string]*header{}
	var cur *header
	trailer := false
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "## ") {
			if cur == nil || trailer {
				return fmt.Errorf("vendor/source closure: vendor/modules.txt annotation out of place: %q", line)
			}
			for _, tok := range strings.Split(line[3:], ";") {
				tok = strings.TrimSpace(tok)
				switch {
				case tok == "explicit":
					cur.explicit = true
				case strings.HasPrefix(tok, "go "):
				default:
					return fmt.Errorf("vendor/source closure: vendor/modules.txt carries unrecognized annotation %q", line)
				}
			}
			continue
		}
		if strings.HasPrefix(line, "# ") {
			fields := strings.Fields(line[2:])
			switch {
			case len(fields) >= 3 && fields[1] == "=>":
				trailer = true // replace mirror — verified via go.mod below
			case len(fields) == 1:
				trailer = true
			case fields[0] == "go" || fields[0] == "toolchain":
				// Toolchain metadata emitted by newer go mod vendor —
				// informational only, never a module header.
			case trailer:
				return fmt.Errorf("vendor/source closure: module header %q after trailer section", line)
			case len(fields) < 2:
				return fmt.Errorf("vendor/source closure: malformed modules.txt header %q", line)
			default:
				h := &header{mod: Module{Path: fields[0], Version: fields[1]}}
				if len(fields) >= 4 && fields[2] == "=>" {
					h.mod.Replace = &Module{Path: fields[3]}
					if len(fields) >= 5 {
						h.mod.Replace.Version = fields[4]
					}
				}
				if prev, dup := byPath[h.mod.Path]; dup {
					return fmt.Errorf("vendor/source closure: duplicate modules.txt header for %s (first seen with %d packages)", h.mod.Path, prev.pkgs)
				}
				mods = append(mods, h)
				byPath[h.mod.Path] = h
				d.vendoredMods[h.mod.Path] = true
				cur = h
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			return fmt.Errorf("vendor/source closure: malformed modules.txt line %q", line)
		}
		// Package line: must belong to the current header's module and
		// exist as a vendored directory.
		if cur == nil || trailer {
			return fmt.Errorf("vendor/source closure: package line %q outside any module section", line)
		}
		if err := module.CheckImportPath(line); err != nil {
			return fmt.Errorf("vendor/source closure: malformed vendored package path %q", line)
		}
		if line != cur.mod.Path && !strings.HasPrefix(line, cur.mod.Path+"/") {
			return fmt.Errorf("vendor/source closure: package %q outside its module %s", line, cur.mod.Path)
		}
		if _, dup := d.pkgDir[line]; dup {
			return fmt.Errorf("vendor/source closure: duplicate package line %q", line)
		}
		d.pkgDir[line] = filepath.Join(d.root, "vendor", filepath.FromSlash(line))
		d.pkgMod[line] = cur.mod
		cur.pkgs++
	}
	for _, h := range mods {
		// A header may legitimately list zero packages (the module is
		// required but contributes no vendored source); it still must be
		// required, explicit and version/replace-consistent.
		req, ok := d.reqs[h.mod.Path]
		if !ok {
			return fmt.Errorf("vendor/source closure: vendored module %s is not required in go.mod (inconsistent vendoring)", h.mod.Path)
		}
		// `go mod vendor` marks `## explicit` exactly when the module is
		// in go.mod's require list — requiredness itself is the check,
		// not indirectness (a require may carry `// indirect` and still
		// be marked explicit).
		if !h.explicit {
			return fmt.Errorf("vendor/source closure: vendored module %s is not marked explicit in modules.txt (inconsistent vendoring)", h.mod.Path)
		}
		if req.Mod.Version != h.mod.Version {
			return fmt.Errorf("vendor/source closure: vendored module %s is version %s but go.mod requires %s (inconsistent vendoring)",
				h.mod.Path, h.mod.Version, req.Mod.Version)
		}
		if err := d.checkReplace(h.mod); err != nil {
			return err
		}
	}
	var listed []string
	for p := range d.pkgDir {
		listed = append(listed, p)
	}
	sort.Strings(listed)
	for _, p := range listed {
		dir := d.pkgDir[p]
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			return fmt.Errorf("vendor/source closure: vendored package %s missing at %s (incomplete vendor metadata)", p, dir)
		}
		if !dirHasGoFile(dir) {
			return fmt.Errorf("vendor/source closure: vendored package %s lists no Go source at %s (incomplete vendor metadata)", p, dir)
		}
	}
	vendorRoot := filepath.Join(d.root, "vendor")
	var stray []string
	err := filepath.WalkDir(vendorRoot, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !de.IsDir() {
			return nil
		}
		if de.Name() == "testdata" || strings.HasPrefix(de.Name(), ".") || strings.HasPrefix(de.Name(), "_") {
			return fs.SkipDir
		}
		if dirHasGoFile(path) {
			rel, rerr := filepath.Rel(vendorRoot, path)
			if rerr != nil {
				return rerr
			}
			ip := filepath.ToSlash(rel)
			if _, ok := d.pkgDir[ip]; !ok {
				stray = append(stray, ip)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("vendor/source closure: walk vendor tree: %w", err)
	}
	if len(stray) > 0 {
		sort.Strings(stray)
		return fmt.Errorf("vendor/source closure: vendored package dir(s) %s exist in vendor/ but are unlisted in modules.txt (incomplete vendor metadata)", strings.Join(stray, ", "))
	}
	return nil
}

// checkReplace verifies a header's => target equals the matching go.mod
// replace: an unversioned LHS matches the required version, a versioned
// LHS must equal it, and a header without => requires no matching
// replace at all.
func (d *vendorDeriver) checkReplace(m Module) error {
	// An exact versioned replace wins over an unversioned one, matching
	// the toolchain's precedence for the vendored version.
	var want *modfile.Replace
	for _, r := range d.reps {
		if r.Old.Path == m.Path && r.Old.Version == m.Version {
			want = r
			break
		}
	}
	if want == nil {
		for _, r := range d.reps {
			if r.Old.Path == m.Path && r.Old.Version == "" {
				want = r
				break
			}
		}
	}
	if want == nil {
		if m.Replace != nil {
			return fmt.Errorf("vendor/source closure: modules.txt replaces %s but go.mod has no matching replace (inconsistent vendoring)", m.Path)
		}
		return nil
	}
	if m.Replace == nil {
		return fmt.Errorf("vendor/source closure: go.mod replaces %s but modules.txt lists no replacement (inconsistent vendoring)", m.Path)
	}
	if m.Replace.Path != want.New.Path || m.Replace.Version != want.New.Version {
		return fmt.Errorf("vendor/source closure: modules.txt replaces %s => %s@%s but go.mod replaces with %s@%s (inconsistent vendoring)",
			m.Path, m.Replace.Path, m.Replace.Version, want.New.Path, want.New.Version)
	}
	return nil
}

// dirHasGoFile reports whether dir contains at least one .go file.
func dirHasGoFile(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			return true
		}
	}
	return false
}

// enumerateFirstParty walks the main module tree the way ./... does —
// skipping vendor/, testdata/, dot and underscore dirs and nested
// modules — scans each package dir under the build context and creates
// the product package node plus its test variants and driver. Edges
// expand lazily through edgesOf.
func (d *vendorDeriver) enumerateFirstParty() error {
	var roots []string
	err := filepath.WalkDir(d.root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !de.IsDir() {
			return nil
		}
		name := de.Name()
		if path != d.root {
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return fs.SkipDir
			}
			if _, serr := os.Stat(filepath.Join(path, "go.mod")); serr == nil {
				return fs.SkipDir
			}
		}
		if dirHasGoFile(path) {
			roots = append(roots, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("vendor/source closure: walk module tree: %w", err)
	}
	sort.Strings(roots)
	mod := &Module{Path: d.main, Main: true}
	for _, dir := range roots {
		if err := d.ctx.Err(); err != nil {
			return fmt.Errorf("vendor/source closure: %w", err)
		}
		scan, err := d.scanDir(dir)
		if err != nil {
			return err
		}
		// A package exists under ./... only when at least one source
		// file is applicable under the recorded build context — a dir
		// whose files are all excluded is not a package at all.
		if !scan.hasProd && !scan.hasIntTest && !scan.hasExtTest {
			continue
		}
		rel, err := filepath.Rel(d.root, dir)
		if err != nil {
			return err
		}
		ip := d.main
		if rel != "." {
			ip += "/" + filepath.ToSlash(rel)
		}
		d.addFirstParty(ip, dir, scan, mod)
	}
	return nil
}

// addFirstParty creates the package node for one first-party dir plus
// its internal/external test variants and the synthetic .test driver.
// The node id for an imported-but-not-enumerated dir is identical, so
// lazy edge expansion sees one node either way.
func (d *vendorDeriver) addFirstParty(ip, dir string, scan *dirScan, mod *Module) {
	pkgName := scan.prodName
	if pkgName == "" {
		pkgName = scan.testBaseName
	}
	if _, ok := d.nodes[ip]; !ok {
		d.nodes[ip] = &Package{ImportPath: ip, Name: pkgName, Dir: dir, Module: mod}
		d.kinds[ip] = kindProd
		d.dirs[ip] = dir
	}
	if scan.hasIntTest {
		variant := ip + " [" + ip + ".test]"
		d.nodes[variant] = &Package{ImportPath: variant, Name: pkgName, ForTest: ip, Dir: dir, Module: mod}
		d.kinds[variant] = kindIntVariant
		d.dirs[variant] = dir
	}
	if scan.hasExtTest {
		variant := ip + "_test [" + ip + ".test]"
		d.nodes[variant] = &Package{ImportPath: variant, Name: pkgName + "_test", ForTest: ip, Dir: dir, Module: mod}
		d.kinds[variant] = kindExtVariant
		d.dirs[variant] = dir
	}
	if scan.hasIntTest || scan.hasExtTest {
		driver := ip + ".test"
		d.nodes[driver] = &Package{ImportPath: driver, Name: "main", DepOnly: true}
		d.kinds[driver] = kindDriver
		var deps []string
		if scan.hasIntTest {
			deps = append(deps, ip+" ["+ip+".test]")
		}
		if scan.hasExtTest {
			deps = append(deps, ip+"_test ["+ip+".test]")
		}
		for _, std := range []string{"os", "testing", "testing/internal/testdeps"} {
			d.stdLeaf(std)
			deps = append(deps, std)
		}
		d.drvDeps[driver] = deps
	}
}

// scanDir evaluates one package directory under the recorded build
// context: file-name and constraint filtering, full parses of the
// applicable files, package-name agreement and the unsupported-feature
// gate. Dependency test files are skipped — the build never compiles
// vendored package tests.
func (d *vendorDeriver) scanDir(dir string) (*dirScan, error) {
	if s, ok := d.scans[dir]; ok {
		return s, nil
	}
	if err := d.ctx.Err(); err != nil {
		return nil, fmt.Errorf("vendor/source closure: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("vendor/source closure: read dir %s: %w", dir, err)
	}
	scan := &dirScan{}
	inVendor := d.inVendor(dir)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(name, ".swig") || strings.HasSuffix(name, ".swigcxx") {
			return nil, fmt.Errorf("vendor/source closure: %s carries a SWIG input — generated cgo builds are outside the supported model", filepath.Join(dir, name))
		}
		if strings.HasSuffix(name, ".syso") {
			return nil, fmt.Errorf("vendor/source closure: %s carries a .syso object — externally linked objects are outside the supported model", filepath.Join(dir, name))
		}
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		isTest := strings.HasSuffix(name, "_test.go")
		if isTest && inVendor {
			continue
		}
		if err := d.checkGo1(dir, name); err != nil {
			return nil, err
		}
		file := filepath.Join(dir, name)
		match, err := d.bctx.MatchFile(dir, name)
		if err != nil {
			return nil, fmt.Errorf("vendor/source closure: build constraint on %s: %w", file, err)
		}
		if !match {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("vendor/source closure: read %s: %w", file, err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.AllErrors)
		if err != nil {
			return nil, fmt.Errorf("vendor/source closure: parse %s: %w", file, err)
		}
		var imports []string
		cgo := false
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				return nil, fmt.Errorf("vendor/source closure: imports of %s: %w", file, uerr)
			}
			if p == "C" {
				cgo = true
				continue
			}
			imports = append(imports, p)
		}
		if cgo {
			if !d.bctx.CgoEnabled {
				// CGO_ENABLED=0 excludes cgo files exactly as the
				// toolchain does — an excluded file contributes nothing.
				continue
			}
			return nil, fmt.Errorf("vendor/source closure: %s imports \"C\" — generated cgo builds are outside the supported model", file)
		}
		if !isTest {
			if scan.prodName == "" {
				scan.prodName = f.Name.Name
			} else if scan.prodName != f.Name.Name {
				return nil, fmt.Errorf("vendor/source closure: %s mixes package %s and %s — ambiguous package composition", dir, scan.prodName, f.Name.Name)
			}
			scan.hasProd = true
			scan.prodImports = append(scan.prodImports, imports...)
			continue
		}
		base := f.Name.Name
		external := strings.HasSuffix(base, "_test")
		if external {
			base = strings.TrimSuffix(base, "_test")
		}
		if scan.testBaseName == "" {
			scan.testBaseName = base
		} else if scan.testBaseName != base {
			return nil, fmt.Errorf("vendor/source closure: %s mixes test package %s and %s — ambiguous package composition", dir, scan.testBaseName, base)
		}
		if scan.prodName != "" && base != scan.prodName {
			return nil, fmt.Errorf("vendor/source closure: %s test file declares package %s, product files declare %s — ambiguous package composition", file, f.Name.Name, scan.prodName)
		}
		if external {
			scan.hasExtTest = true
			scan.extImports = append(scan.extImports, imports...)
		} else {
			scan.hasIntTest = true
			scan.intImports = append(scan.intImports, imports...)
		}
	}
	d.scans[dir] = scan
	return scan, nil
}

// checkGo1 rejects a file whose build-constraint expression mentions a
// go1.* tag outside the decidable release floor — an undecidable
// constraint can never be guessed in either direction. A //go:build
// line takes precedence over // +build lines, exactly as the toolchain
// treats them.
func (d *vendorDeriver) checkGo1(dir, name string) error {
	file := filepath.Join(dir, name)
	if err := checkGo1Constraints(file, d.relSet, d.relExact); err != nil {
		return fmt.Errorf("vendor/source closure: %w", err)
	}
	return nil
}

// parseFileConstraints parses the pre-package //go:build and // +build
// comment lines of one Go file. The returned expressions are the parsed
// constraint nodes; //go:build takes precedence over // +build exactly as
// the toolchain treats them.
func parseFileConstraints(file string) (goBuild, plusBuild []constraint.Expr, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("parse constraints of %s: %w", file, err)
	}
	for _, cg := range f.Comments {
		if cg.End() >= f.Package {
			continue
		}
		for _, c := range cg.List {
			var expr constraint.Expr
			switch {
			case strings.HasPrefix(c.Text, "//go:build"):
				if expr, err = constraint.Parse(c.Text); err != nil {
					return nil, nil, fmt.Errorf("malformed build constraint %q in %s", c.Text, file)
				}
				goBuild = append(goBuild, expr)
			case strings.HasPrefix(c.Text, "// +build"):
				if expr, err = constraint.Parse(c.Text); err != nil {
					return nil, nil, fmt.Errorf("malformed build constraint %q in %s", c.Text, file)
				}
				plusBuild = append(plusBuild, expr)
			}
		}
	}
	return goBuild, plusBuild, nil
}

// checkGo1Constraints fails when a file's selected constraint expression
// mentions a go1.* tag the recorded release floor cannot decide in either
// direction.
func checkGo1Constraints(file string, relSet map[string]bool, relExact bool) error {
	goBuild, plusBuild, err := parseFileConstraints(file)
	if err != nil {
		return err
	}
	exprs := goBuild
	if len(exprs) == 0 {
		exprs = plusBuild
	}
	for _, expr := range exprs {
		for _, tag := range constraintTags(expr) {
			if strings.HasPrefix(tag, "go1.") && !relSet[tag] && !relExact {
				return fmt.Errorf("%s carries a %s constraint outside the decidable release floor — the recorded build context cannot select it either way", file, tag)
			}
		}
	}
	return nil
}

// explicitBuildExpression returns the canonical explicit build expression
// of one file (the //go:build line when present, else the AND of every
// // +build line) plus the syntax kind it came from. An empty expression
// means the file carries no explicit constraint; filename constraints are
// evaluated separately by go/build.Context.MatchFile.
func explicitBuildExpression(file string) (string, string, error) {
	goBuild, plusBuild, err := parseFileConstraints(file)
	if err != nil {
		return "", "", err
	}
	if len(goBuild) > 1 {
		return "", "", fmt.Errorf("%s carries %d //go:build lines; the toolchain permits one", file, len(goBuild))
	}
	if len(goBuild) == 1 {
		return goBuild[0].String(), "go:build", nil
	}
	if len(plusBuild) == 0 {
		return "", "", nil
	}
	expr := plusBuild[0]
	for _, next := range plusBuild[1:] {
		expr = &constraint.AndExpr{X: expr, Y: next}
	}
	return expr.String(), "+build", nil
}

// constraintTags enumerates every tag in a parsed build-constraint
// expression — the go/build API has no exported walker.
func constraintTags(e constraint.Expr) []string {
	var out []string
	switch x := e.(type) {
	case *constraint.TagExpr:
		out = append(out, x.Tag)
	case *constraint.NotExpr:
		out = append(out, constraintTags(x.X)...)
	case *constraint.AndExpr:
		out = append(out, constraintTags(x.X)...)
		out = append(out, constraintTags(x.Y)...)
	case *constraint.OrExpr:
		out = append(out, constraintTags(x.X)...)
		out = append(out, constraintTags(x.Y)...)
	}
	return out
}

// inVendor reports whether dir sits under the snapshot's vendor tree.
func (d *vendorDeriver) inVendor(dir string) bool {
	return strings.HasPrefix(dir, filepath.Join(d.root, "vendor")+string(filepath.Separator))
}

// resolveAll resolves every raw import of one package.
func (d *vendorDeriver) resolveAll(imports []string, importerDir string) ([]string, error) {
	var out []string
	for _, imp := range imports {
		key, err := d.resolveImport(imp, importerDir)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

// isStdlibImportPath reports whether an import path belongs to the Go
// standard library. This is the compiler's own rule for import paths — the
// first path element contains no dot ("fmt", "net/http", "internal/cpu") —
// and it applies to package import paths only. Advisory module identity is
// classified by isStdlibModule, which must not reuse this shape test: a
// dot-less module element is not evidence of stdlib.
func isStdlibImportPath(path string) bool {
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return first != "" && !strings.Contains(first, ".")
}

// resolveImport maps an import path to a package node exactly the way
// the recorded build does: first-party paths resolve inside the main
// module, vendored paths through the modules.txt inventory, dot-less
// leading segments to stdlib leaf nodes; everything else is an
// unresolved import — never a silent absence.
func (d *vendorDeriver) resolveImport(path, importerDir string) (string, error) {
	if err := module.CheckImportPath(path); err != nil {
		return "", fmt.Errorf("vendor/source closure: malformed import path %q imported under %s", path, importerDir)
	}
	if strings.HasPrefix(path, "internal/") || strings.HasPrefix(path, "vendor/") {
		return "", fmt.Errorf("vendor/source closure: import %q names a toolchain-reserved path space (illegal under this composition)", path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." || seg == "testdata" || strings.HasPrefix(seg, ".") || strings.HasPrefix(seg, "_") {
			return "", fmt.Errorf("vendor/source closure: import %q traverses a directory the build tools ignore", path)
		}
	}
	if path == d.main || strings.HasPrefix(path, d.main+"/") {
		rel := strings.TrimPrefix(path, d.main)
		rel = strings.TrimPrefix(rel, "/")
		dir := filepath.Join(d.root, filepath.FromSlash(rel))
		if d.inVendor(dir) {
			return "", fmt.Errorf("vendor/source closure: import %q traverses the vendor tree — not a first-party package", path)
		}
		if err := d.checkInternal(dir, importerDir); err != nil {
			return "", err
		}
		return d.firstPartyNode(path, dir)
	}
	if dir, ok := d.pkgDir[path]; ok {
		if err := d.checkInternal(dir, importerDir); err != nil {
			return "", err
		}
		return d.vendorNode(path, dir)
	}
	if st, err := os.Stat(filepath.Join(d.root, "vendor", filepath.FromSlash(path))); err == nil && st.IsDir() {
		return "", fmt.Errorf("vendor/source closure: %q is present in vendor/ but unlisted in modules.txt (incomplete vendor metadata)", path)
	}
	if isStdlibImportPath(path) {
		return d.stdLeaf(path), nil
	}
	return "", fmt.Errorf("vendor/source closure: import %q resolves through no first-party dir, vendored package or stdlib leaf — module lookup is disabled in this derivation (unresolved import)", path)
}

// checkInternal enforces the internal-directory import rule: an import
// path containing an "internal" element may only be imported by code
// inside the tree rooted at that element's parent directory.
func (d *vendorDeriver) checkInternal(targetDir, importerDir string) error {
	rel, err := filepath.Rel(d.root, targetDir)
	if err != nil {
		return err
	}
	seg := strings.Split(filepath.ToSlash(rel), "/")
	for i, s := range seg {
		if s != "internal" {
			continue
		}
		boundary := filepath.Join(append([]string{d.root}, seg[:i]...)...)
		impRel, err := filepath.Rel(boundary, importerDir)
		if err != nil || impRel == ".." || strings.HasPrefix(impRel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("vendor/source closure: %s imports an internal package outside %s — illegal internal visibility", importerDir, boundary)
		}
	}
	return nil
}

// firstPartyNode materializes (or returns) the main-module package node
// for an imported path — the same node enumeration creates for roots.
func (d *vendorDeriver) firstPartyNode(path, dir string) (string, error) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("vendor/source closure: first-party import %q resolves to no package directory (unresolved import)", path)
	}
	// An import into a nested module is not part of this module's
	// package space — the composition is ambiguous and fails closed.
	for up := dir; ; up = filepath.Dir(up) {
		if up == d.root {
			break
		}
		if _, err := os.Stat(filepath.Join(up, "go.mod")); err == nil {
			return "", fmt.Errorf("vendor/source closure: import %q enters a nested module at %s — ambiguous module composition", path, up)
		}
		if up == filepath.Dir(up) {
			break
		}
	}
	scan, err := d.scanDir(dir)
	if err != nil {
		return "", err
	}
	if !scan.hasProd {
		return "", fmt.Errorf("vendor/source closure: import %q resolves to no applicable source files under the recorded build context (build constraints exclude all files)", path)
	}
	if _, ok := d.nodes[path]; !ok {
		d.nodes[path] = &Package{ImportPath: path, Name: scan.prodName, Dir: dir, Module: &Module{Path: d.main, Main: true}}
		d.kinds[path] = kindProd
		d.dirs[path] = dir
	}
	return path, nil
}

// vendorNode materializes a vendored package: its applicable source
// files are scanned under the same build context, dependency tests are
// ignored and its module identity comes from the modules.txt header.
func (d *vendorDeriver) vendorNode(path, dir string) (string, error) {
	scan, err := d.scanDir(dir)
	if err != nil {
		return "", err
	}
	if !scan.hasProd {
		return "", fmt.Errorf("vendor/source closure: vendored package %s has no applicable source files under the recorded build context (build constraints exclude all files)", path)
	}
	if _, ok := d.nodes[path]; !ok {
		mod := d.pkgMod[path]
		d.nodes[path] = &Package{ImportPath: path, Name: scan.prodName, DepOnly: true, Dir: dir, Module: &mod}
		d.kinds[path] = kindVendor
		d.dirs[path] = dir
	}
	return path, nil
}

// stdLeaf returns the opaque stdlib leaf node for a standard import.
func (d *vendorDeriver) stdLeaf(path string) string {
	if _, ok := d.nodes[path]; ok {
		return path
	}
	name := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		name = path[i+1:]
	}
	d.nodes[path] = &Package{ImportPath: path, Name: name, Standard: true, DepOnly: true}
	d.kinds[path] = kindStd
	return path
}

// findCycle detects an import cycle reachable from roots — an
// unbuildable graph is not a closed negative.
func findCycle(roots []string, edges map[string][]string) string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string
	var visit func(n string) bool
	visit = func(n string) bool {
		switch color[n] {
		case gray:
			stack = append(stack, n)
			return true
		case black:
			return false
		}
		color[n] = gray
		stack = append(stack, n)
		for _, m := range edges[n] {
			if visit(m) {
				return true
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
		return false
	}
	for _, r := range roots {
		if visit(r) {
			return strings.Join(stack, " -> ")
		}
	}
	return ""
}
