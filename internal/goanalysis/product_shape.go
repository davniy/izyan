package goanalysis

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"

	"github.com/davniy/izyan/internal/domain"
)

// productCensusMaxLoadErrors bounds the loader diagnostics retained per
// inventoried package — evidence detail, never scope.
const productCensusMaxLoadErrors = 8

// productCensus is the immutable result of one product-shape census: the
// proven shape, the deterministic evidence that supports it, and the identity
// of the inputs it was derived from. EvidenceIDs are deliberately absent —
// they are case-scoped and assigned by the collector, never cached.
type productCensus struct {
	shape    domain.ProductShape
	evidence []domain.Evidence
	identity string
}

// shapeCopy returns a deep copy so a caller can attach case-scoped evidence
// ids without mutating the cached census.
func (c *productCensus) shapeCopy() *domain.ProductShape {
	if c == nil {
		return nil
	}
	out := c.shape
	out.EvidenceIDs = append([]domain.EvidenceID(nil), c.shape.EvidenceIDs...)
	out.Limitations = append([]string(nil), c.shape.Limitations...)
	out.OwnedModules = append([]domain.ProductModuleShape(nil), c.shape.OwnedModules...)
	out.ExcludedModules = append([]domain.ProductModuleShape(nil), c.shape.ExcludedModules...)
	out.Packages = make([]domain.ProductPackageShape, len(c.shape.Packages))
	for i, p := range c.shape.Packages {
		q := p
		q.PackageNames = append([]string(nil), p.PackageNames...)
		q.Files = append([]string(nil), p.Files...)
		q.LoadErrors = append([]string(nil), p.LoadErrors...)
		out.Packages[i] = q
	}
	return &out
}

func (c *productCensus) evidenceCopy() []domain.Evidence {
	if c == nil {
		return nil
	}
	return append([]domain.Evidence(nil), c.evidence...)
}

// BuildProductShape proves the shape of the analyzed product: which modules
// the product owns, which non-test source directories they contain, and
// whether an owned package main exists.
//
// Module ownership decides product membership: the root module and every
// effective-workspace member inside the analyzed tree are owned; a nested
// module with its own go.mod that is neither is a different module and is
// excluded by identity, never by its directory name. The census is
// filesystem/manifest based, so build-excluded source and directories the
// loader could not enter are still inventoried; typed roots and the loader's
// skipped-package records are reconciled against it.
// A complete build/package inventory cannot replace this source census:
// ./... omits build-excluded files, hidden directories and nested modules,
// and successful listing does not establish successful typed loading.
//
// The result is LIBRARY only when ownership and the census are complete, at
// least one importable product package exists and no owned main does.
// A proven product-owned main yields APPLICATION. Everything else — missing
// or ambiguous ownership, unreadable clauses, an unavailable workspace
// member, an incomplete census, a failed index load or binary analysis —
// yields UNKNOWN with the reason recorded. Failed admission is not safety:
// an UNKNOWN shape never closes a negative conclusion.
//
// The census is memoized per index and revalidated against the source and
// inventory identity on every call; a snapshot that changed after the load
// fails closed with ErrSnapshotMutated instead of publishing a stale proof.
func (ix *Index) BuildProductShape(ctx context.Context) (*domain.ProductShape, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if ix.Build.BinaryPath != "" {
		census := binaryProductCensus()
		return census.shapeCopy(), census.evidenceCopy(), nil
	}
	// A failed load is not fatal to the shape proof: the census is
	// manifest/filesystem based, and a loader failure is recorded as a
	// limitation rather than swallowed. Typed-root reconciliation simply has
	// nothing to reconcile, and LIBRARY stays unreachable (UNKNOWN), while a
	// proven owned main can still classify as APPLICATION.
	_ = ix.load(ctx)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return ix.buildProductShapeLocked(ctx)
}

// buildProductShapeLocked builds or reuses the product census. Callers MUST
// hold ix.mu with the index load attempted; a construction interrupted by the
// caller's context is never published.
func (ix *Index) buildProductShapeLocked(ctx context.Context) (*domain.ProductShape, []domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	source, loaderKey := ix.snapshotKeysLocked()
	if ix.loadedFingerprint != "" && source != ix.loadedFingerprint {
		// The loaded AST, typed roots and skipped census describe the
		// pre-mutation bytes. A census built over the new bytes could not
		// reconcile with them, and one built over the old bytes would
		// publish a proof over sources nobody analyzed: fail closed.
		ix.productShapeCache = nil
		ix.productShapeIdentity = ""
		return nil, nil, fmt.Errorf("%w: product source inventory or content changed after the index load; the loaded AST is stale — reload the snapshot before proving its product shape", ErrSnapshotMutated)
	}
	census, err := ix.scanProductCensusLocked(ctx, ix.loadErr, loaderKey)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if ix.productShapeCache != nil && ix.productShapeIdentity == census.identity {
		return ix.productShapeCache.shapeCopy(), ix.productShapeCache.evidenceCopy(), nil
	}
	ix.productShapeBuilds++
	ix.productShapeCache = census
	ix.productShapeIdentity = census.identity
	return census.shapeCopy(), census.evidenceCopy(), nil
}

// binaryProductCensus is the ineligible shape of a binary-only case: no
// product source census exists, so no library proof can be published.
func binaryProductCensus() *productCensus {
	shape := domain.ProductShape{
		Kind: domain.ProductShapeUnknown,
		Limitations: []string{
			"binary-mode analysis: no product source census exists, so the product shape is UNKNOWN",
		},
	}
	return &productCensus{
		shape: shape,
		evidence: []domain.Evidence{{
			Kind:    domain.EvidenceBuild,
			Quality: domain.QualityDeterministic,
			Source:  "source index: product shape",
			Tool:    "goanalysis.Index.BuildProductShape",
			Content: "product-shape proof unavailable: binary-mode analysis has no product source census",
		}},
		identity: "binary",
	}
}

// scanProductCensusLocked resolves ownership, walks the product tree and
// reconciles the result with the loader's package records. Callers MUST hold
// ix.mu.
func (ix *Index) scanProductCensusLocked(ctx context.Context, loadErr error, loaderKey string) (*productCensus, error) {
	dir, err := filepath.Abs(ix.Dir)
	if err != nil {
		return nil, fmt.Errorf("product shape: resolve product directory: %w", err)
	}
	dir = evalSymlinksBestEffort(dir)
	own := ix.resolveProductOwnershipLocked(dir)
	scan := &productCensusScan{
		ix:             ix,
		ctx:            ctx,
		dir:            dir,
		fset:           token.NewFileSet(),
		complete:       true,
		fileHashes:     map[string]string{},
		pkgIndex:       map[string]int{},
		visitedModules: map[string]bool{},
	}
	if loadErr != nil {
		scan.limitations = append(scan.limitations,
			"source index load failed, so typed-root reconciliation was unavailable: "+loadErr.Error())
	}
	if err := scan.walkProductTree(ctx, own); err != nil {
		return nil, err
	}
	scan.reconcileLoadedPackages()
	return scan.finalize(own, loadErr, loaderKey), nil
}

// productModuleManifest is one resolved module manifest. Directory in shape
// is product-relative; dir and goMod are absolute canonical paths.
type productModuleManifest struct {
	shape  domain.ProductModuleShape
	dir    string
	goMod  string
	digest string
}

// productOwnership is the resolved module ownership of the product: the
// module whose manifest governs the product directory plus every
// effective-workspace member inside the analyzed tree. complete=false means
// the composition could not be proven, which can only yield UNKNOWN.
type productOwnership struct {
	rootModule    string
	rootDir       string
	workspaceFile string
	workspaceHash string
	owned         []productModuleManifest
	rootDirs      map[string]string // absolute module dir -> module path
	complete      bool
	limitations   []string
}

// resolveProductOwnershipLocked resolves the governing module and the
// effective workspace using the same directory and environment as
// loadConfig. Ownership is decided by manifests, never by import-path
// prefixes or directory names. Callers MUST hold ix.mu.
func (ix *Index) resolveProductOwnershipLocked(dir string) productOwnership {
	own := productOwnership{complete: true, rootDirs: map[string]string{}}
	fail := func(format string, args ...any) {
		own.complete = false
		own.limitations = append(own.limitations, fmt.Sprintf(format, args...))
	}

	// Effective workspace: GOWORK=off disables workspace mode, a GOWORK path
	// names the file directly, and the default is the go command's upward
	// search from the product directory.
	workFile, workNote, workOK := ix.effectiveProductWorkspaceFileLocked(dir)
	if workNote != "" {
		fail("%s", workNote)
	}
	if !workOK {
		own.complete = false
	}
	var members []productModuleManifest
	if workFile != "" {
		own.workspaceFile = productRelPath(dir, workFile)
		resolved, hash, limitations, memOK := resolveProductWorkspaceMembers(dir, workFile)
		members = resolved
		own.workspaceHash = hash
		for _, l := range limitations {
			own.limitations = append(own.limitations, l)
		}
		if !memOK {
			own.complete = false
		}
	}

	// The governing module is the nearest go.mod at or above the product
	// directory — the same one `go list` resolves the package pattern under.
	moduleDir, modulePath, moduleDigest, modErr := nearestModuleManifest(dir)
	if modErr != nil {
		fail("module ownership is unresolved: %v", modErr)
	} else {
		own.rootModule = modulePath
		own.rootDir = moduleDir
		own.owned = append(own.owned, productModuleManifest{
			shape:  domain.ProductModuleShape{Path: modulePath, Directory: productRelPath(dir, moduleDir)},
			dir:    moduleDir,
			goMod:  filepath.Join(moduleDir, "go.mod"),
			digest: moduleDigest,
		})
		if workFile != "" {
			member := false
			for _, m := range members {
				if m.dir == moduleDir {
					member = true
					break
				}
			}
			if !member {
				fail("module %s at %s is not a member of workspace %s",
					modulePath, productRelPath(dir, moduleDir), own.workspaceFile)
			}
		}
	}

	// Workspace members inside the analyzed tree are product-owned too. A
	// member outside the tree is part of the workspace build but not of the
	// analyzed product, so it is not inventoried.
	for _, m := range members {
		if own.rootDir != "" && m.dir == own.rootDir {
			continue
		}
		if !pathWithin(dir, m.dir) {
			continue
		}
		own.owned = append(own.owned, m)
	}

	// Ownership must be unambiguous: a directory cannot belong to two
	// modules and one module path cannot denote two directories.
	seenDir := map[string]string{}
	seenPath := map[string]string{}
	for _, m := range own.owned {
		if prev, ok := seenDir[m.dir]; ok {
			fail("module directory %s is claimed by both %s and %s", m.shape.Directory, prev, m.shape.Path)
			continue
		}
		seenDir[m.dir] = m.shape.Path
		if prev, ok := seenPath[m.shape.Path]; ok {
			fail("module path %s is claimed by both %s and %s", m.shape.Path, prev, m.shape.Directory)
			continue
		}
		seenPath[m.shape.Path] = m.shape.Directory
	}
	sort.Slice(own.owned, func(i, j int) bool { return own.owned[i].dir < own.owned[j].dir })
	for _, m := range own.owned {
		own.rootDirs[m.dir] = m.shape.Path
	}
	return own
}

// effectiveProductWorkspaceFileLocked resolves the workspace file the loader
// would use for the product directory. It mirrors the go command: GOWORK=off
// disables workspace mode, any other explicit path is used as given, and the
// default searches the product directory and its parents for go.work.
// Callers MUST hold ix.mu.
func (ix *Index) effectiveProductWorkspaceFileLocked(dir string) (file, note string, complete bool) {
	env := ix.loadEnv()
	gowork, set := envValue(env, "GOWORK")
	if set {
		switch gowork {
		case "off":
			return "", "", true
		case "", "auto":
			// The go command searches upward for go.work.
		default:
			p := gowork
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			p = evalSymlinksBestEffort(filepath.Clean(p))
			if !fileExists(p) {
				return "", fmt.Sprintf("GOWORK=%s does not name a readable workspace file", gowork), false
			}
			return p, "", true
		}
	}
	for cur := dir; ; {
		p := filepath.Join(cur, "go.work")
		if fileExists(p) {
			return evalSymlinksBestEffort(p), "", true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", "", true
		}
		cur = parent
	}
}

// resolveProductWorkspaceMembers parses the effective workspace and resolves
// every use entry to an owned module. A member that does not resolve to a
// directory with its own go.mod makes the workspace composition
// unverifiable: ownership then fails closed rather than guessing.
func resolveProductWorkspaceMembers(dir, workFile string) (members []productModuleManifest, hash string, limitations []string, complete bool) {
	b, err := os.ReadFile(workFile)
	if err != nil {
		return nil, "", []string{"workspace file " + productRelPath(dir, workFile) + " is unreadable: " + err.Error()}, false
	}
	hash = sha256Hex(b)
	f, err := modfile.ParseWork(workFile, b, nil)
	if err != nil {
		return nil, hash, []string{"workspace file " + productRelPath(dir, workFile) + " is unparseable: " + err.Error()}, false
	}
	complete = true
	if len(f.Use) == 0 {
		complete = false
		limitations = append(limitations, "workspace "+productRelPath(dir, workFile)+" lists no use entries: module composition is unprovable")
	}
	workDir := filepath.Dir(workFile)
	seen := map[string]bool{}
	for _, use := range f.Use {
		memberDir := use.Path
		if !filepath.IsAbs(memberDir) {
			memberDir = filepath.Join(workDir, memberDir)
		}
		memberDir = evalSymlinksBestEffort(filepath.Clean(memberDir))
		if seen[memberDir] {
			continue
		}
		seen[memberDir] = true
		modDir, modPath, digest, merr := nearestModuleManifest(memberDir)
		if merr == nil && modDir != memberDir {
			merr = fmt.Errorf("%s is a subdirectory of module %s, not a workspace module root", memberDir, modPath)
		}
		if merr != nil {
			complete = false
			limitations = append(limitations, "workspace member "+use.Path+" is unavailable: "+merr.Error())
			continue
		}
		members = append(members, productModuleManifest{
			shape:  domain.ProductModuleShape{Path: modPath, Directory: productRelPath(dir, memberDir)},
			dir:    memberDir,
			goMod:  filepath.Join(memberDir, "go.mod"),
			digest: digest,
		})
	}
	return members, hash, limitations, complete
}

// nearestModuleManifest returns the governing module of dir: the nearest
// go.mod at or above it. A manifest that exists but cannot be parsed is an
// error — the module then has no provable identity.
func nearestModuleManifest(dir string) (moduleDir, modulePath, digest string, err error) {
	cur := dir
	for {
		p := filepath.Join(cur, "go.mod")
		if fileExists(p) {
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return "", "", "", fmt.Errorf("read %s: %w", p, rerr)
			}
			f, perr := modfile.Parse(p, b, nil)
			if perr != nil {
				return "", "", "", fmt.Errorf("parse %s: %w", p, perr)
			}
			if f.Module == nil || f.Module.Mod.Path == "" {
				return "", "", "", fmt.Errorf("%s declares no module path", p)
			}
			return cur, f.Module.Mod.Path, sha256Hex(b), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", "", "", fmt.Errorf("no go.mod at or above %s", dir)
		}
		cur = parent
	}
}

// productCensusScan accumulates one walk of the product tree. complete is
// true only while every owned directory and every non-test source file the
// proof relies on was read and its package clause recovered.
type productCensusScan struct {
	ix   *Index
	ctx  context.Context
	dir  string // canonical product root
	fset *token.FileSet

	packages   []domain.ProductPackageShape
	pkgIndex   map[string]int // product-relative directory -> packages index
	fixtures   []domain.ProductPackageShape
	fileHashes map[string]string
	importable bool
	mainFiles  []string // product-relative files whose clause is package main
	// fixtureMainFiles lists package main sources found under a testdata
	// subtree. Test fixture data is not buildable product source, so such a
	// source cannot be classified as either an owned command or a fixture
	// package: the census stays incomplete until a human or a narrower rule
	// decides. It must never be silently ignored — that would authorize a
	// LIBRARY proof for a module that owns a command.
	fixtureMainFiles []string
	excluded         []productModuleManifest
	visitedModules   map[string]bool // owned module roots the walk entered
	complete         bool
	limitations      []string
}

// walkProductTree inventories the product tree. The walk starts at the
// product directory and carries the module that owns it; nested module
// boundaries switch the owning module (workspace members inside the tree) or
// end the walk at an excluded module. Hidden directories are product source
// too: the loader's `./...` pattern cannot see them, so only this census can
// prove whether they contain an owned command. After the tree walk, every
// owned module root is checked to have been entered — an owned workspace
// member hidden under a pruned ancestor (e.g. `vendor/gen`) is walked
// explicitly.
func (s *productCensusScan) walkProductTree(ctx context.Context, own productOwnership) error {
	if own.rootDir == "" {
		// No manifest governs the tree: no directory is owned, but the walk
		// still inventories clauses so a proven main can yield APPLICATION.
		if err := s.walkDir(ctx, s.dir, "", "", own, false); err != nil {
			return err
		}
	} else if err := s.walkDir(ctx, s.dir, own.rootModule, own.rootDir, own, false); err != nil {
		return err
	}
	return s.walkUnvisitedOwnedModules(ctx, own)
}

// walkUnvisitedOwnedModules enters every owned module root the tree walk
// skipped because an ancestor was pruned as dependency or VCS metadata. The
// walk itself never descends into `vendor`; an owned workspace member located
// there is still product source and must be accounted for.
func (s *productCensusScan) walkUnvisitedOwnedModules(ctx context.Context, own productOwnership) error {
	dirs := make([]string, 0, len(own.rootDirs))
	for dir := range own.rootDirs {
		if !pathWithin(s.dir, dir) {
			continue // the governing module may sit above the analyzed subtree
		}
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		if s.visitedModules[dir] {
			continue
		}
		if err := s.walkDir(ctx, dir, own.rootDirs[dir], dir, own, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *productCensusScan) walkDir(ctx context.Context, dir, modulePath, moduleRoot string, own productOwnership, fixture bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, owned := own.rootDirs[dir]; owned {
		s.visitedModules[dir] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.complete = false
		s.limitations = append(s.limitations,
			"product directory "+s.rel(dir)+" is unreadable: "+err.Error())
		return nil
	}
	// os.ReadDir sorts entries by name, so the traversal and every digest
	// derived from it are deterministic.
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		files = append(files, e.Name())
	}
	if len(files) > 0 {
		s.addPackage(dir, modulePath, moduleRoot, files, fixture)
	}
	for _, e := range entries {
		if !e.IsDir() {
			// Symlinked directories are not followed: a link can escape the
			// snapshot or form a cycle, and neither is product source.
			continue
		}
		name := e.Name()
		child := filepath.Join(dir, name)
		// Nested module boundaries are identified before directory-name
		// pruning: a generator directory (e.g. testify's `_codegen`) must be
		// excluded or owned by module identity, never by its name. An owned
		// workspace member is product source wherever it lives, so its walk
		// leaves the fixture context.
		if fileExists(filepath.Join(child, "go.mod")) {
			if path, ok := own.rootDirs[child]; ok {
				if err := s.walkDir(ctx, child, path, child, own, false); err != nil {
					return err
				}
				continue
			}
			s.recordExcludedModule(child)
			continue
		}
		switch {
		case vcsMetadataDir(name), name == "vendor":
			// VCS metadata is not part of the source tree; vendor is
			// dependency source. Neither can carry a product package. Owned
			// workspace members below them are picked up by
			// walkUnvisitedOwnedModules.
			continue
		case name == "testdata":
			// Test fixture data: inventoried to prove whether it hides an
			// owned command, but never counted as product packages.
			if err := s.walkDir(ctx, child, modulePath, moduleRoot, own, true); err != nil {
				return err
			}
		default:
			if err := s.walkDir(ctx, child, modulePath, moduleRoot, own, fixture); err != nil {
				return err
			}
		}
	}
	return nil
}

// vcsMetadataDir reports whether a directory is version-control metadata. It
// is not tracked source and can never be built into the product, so it is the
// only dot-directory pruning the census keeps.
func vcsMetadataDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".bzr":
		return true
	}
	return false
}

// addPackage inventories one package directory: every non-test source file,
// every recovered package clause and the importability of the directory. The
// loader's single declared name is not taken as proof that no sibling file
// declares main.
//
// fixture marks a directory under a testdata ancestor: its source is
// inventoried (and its content fingerprinted) so it can be audited, but it is
// not a product package and can never count toward importability. A package
// main there is recorded separately and makes the census incomplete — test
// fixture data must not silently mask an owned command.
func (s *productCensusScan) addPackage(dir, modulePath, moduleRoot string, files []string, fixture bool) {
	sort.Strings(files)
	pkg := domain.ProductPackageShape{
		Module:         modulePath,
		Directory:      s.rel(dir),
		ClauseComplete: true,
	}
	if modulePath != "" && moduleRoot != "" {
		if rel, err := filepath.Rel(moduleRoot, dir); err == nil && rel != "." {
			pkg.Path = modulePath + "/" + filepath.ToSlash(rel)
		} else {
			pkg.Path = modulePath
		}
	}
	names := map[string]bool{}
	for _, name := range files {
		full := filepath.Join(dir, name)
		rel := s.rel(full)
		pkg.Files = append(pkg.Files, rel)
		data, rerr := os.ReadFile(full)
		if rerr != nil {
			pkg.ClauseComplete = false
			s.complete = false
			s.fileHashes[rel] = "!unreadable"
			s.limitations = append(s.limitations, "product source "+rel+" is unreadable: "+rerr.Error())
			continue
		}
		s.fileHashes[rel] = sha256Hex(data)
		clause, cerr := productFileClause(s.fset, full, data)
		if cerr != nil {
			pkg.ClauseComplete = false
			s.complete = false
			s.limitations = append(s.limitations, "product source "+rel+": "+cerr.Error())
			continue
		}
		names[clause] = true
		if clause == "main" {
			if fixture {
				s.fixtureMainFiles = append(s.fixtureMainFiles, rel)
			} else {
				s.mainFiles = append(s.mainFiles, rel)
			}
		}
	}
	if len(names) == 0 {
		// The directory holds non-test Go source but no recoverable clause:
		// its package identity — and whether it is a command — is unknown.
		pkg.ClauseComplete = false
		s.complete = false
	}
	for n := range names {
		pkg.PackageNames = append(pkg.PackageNames, n)
	}
	sort.Strings(pkg.PackageNames)
	if fixture {
		// Fixture packages stay out of the product package census: they are
		// not importable product API and must not satisfy the
		// importable-package requirement.
		s.fixtures = append(s.fixtures, pkg)
		return
	}
	pkg.Importable = pkg.ClauseComplete && len(pkg.PackageNames) > 0 &&
		!names["main"] && !productInternalDir(pkg.Directory)
	if pkg.Importable {
		s.importable = true
	}
	s.pkgIndex[pkg.Directory] = len(s.packages)
	s.packages = append(s.packages, pkg)
}

// recordExcludedModule records a nested module that the product does not
// own. Its entire subtree belongs to that module, so the walk stops here —
// the reason is module identity, independent of the directory name.
func (s *productCensusScan) recordExcludedModule(dir string) {
	rel := s.rel(dir)
	manifest := filepath.Join(dir, "go.mod")
	b, err := os.ReadFile(manifest)
	if err != nil {
		s.complete = false
		s.limitations = append(s.limitations,
			"nested module manifest "+s.rel(manifest)+" is unreadable: "+err.Error())
		return
	}
	f, err := modfile.Parse(manifest, b, nil)
	if err != nil || f.Module == nil || f.Module.Mod.Path == "" {
		s.complete = false
		msg := "unparseable module manifest"
		if err != nil {
			msg = err.Error()
		}
		s.limitations = append(s.limitations,
			"nested module in "+rel+" has no provable identity: "+msg)
		return
	}
	s.excluded = append(s.excluded, productModuleManifest{
		shape:  domain.ProductModuleShape{Path: f.Module.Mod.Path, Directory: rel},
		dir:    dir,
		goMod:  manifest,
		digest: sha256Hex(b),
	})
	s.limitations = append(s.limitations,
		"nested module "+f.Module.Mod.Path+" at "+rel+" is not owned by the product's module composition; its source is excluded from the census")
}

// reconcileLoadedPackages ties the census to the loader's records. A typed
// product root must appear in the census with the same path and declared
// name; a skipped product package must appear with a recoverable clause
// inventory. Anything the loader saw but the census cannot account for is a
// census gap, so no LIBRARY proof may be published from it.
func (s *productCensusScan) reconcileLoadedPackages() {
	for _, p := range s.ix.pkgs {
		if p == nil || p.ForTest != "" || syntheticTestMain(p) {
			continue // test variants and their generated driver are not product packages
		}
		dir := s.loaderPackageDir(p)
		if dir == "" {
			s.complete = false
			s.limitations = append(s.limitations,
				"typed product package "+p.PkgPath+" has no resolvable source directory")
			continue
		}
		if !pathWithin(s.dir, dir) {
			s.complete = false
			s.limitations = append(s.limitations,
				"typed product package "+p.PkgPath+" at "+dir+" is outside the analyzed product directory")
			continue
		}
		idx, ok := s.pkgIndex[s.loaderRel(dir)]
		if !ok {
			s.complete = false
			s.limitations = append(s.limitations,
				"typed product package "+p.PkgPath+" at "+s.loaderRel(dir)+" is missing from the source census")
			continue
		}
		pkg := &s.packages[idx]
		if p.PkgPath != "" && pkg.Path != "" && p.PkgPath != pkg.Path {
			s.complete = false
			s.limitations = append(s.limitations,
				"typed product package path "+p.PkgPath+" disagrees with the module-owned census path "+pkg.Path)
		}
		if p.Name != "" && !containsString(pkg.PackageNames, p.Name) {
			s.complete = false
			s.limitations = append(s.limitations,
				"typed product package "+p.PkgPath+" declares "+p.Name+" but the source census recovered "+strings.Join(pkg.PackageNames, ", "))
		}
	}

	skippedPaths := make([]string, 0, len(s.ix.skippedPkgs))
	for path := range s.ix.skippedPkgs {
		skippedPaths = append(skippedPaths, path)
	}
	sort.Strings(skippedPaths)
	for _, path := range skippedPaths {
		p := s.ix.skippedPkgs[path]
		if p == nil {
			s.complete = false
			s.limitations = append(s.limitations,
				"skipped product package "+path+" has no loader record; its package clause cannot be verified")
			continue
		}
		if p.ForTest != "" || syntheticTestMain(p) {
			continue
		}
		dir := s.loaderPackageDir(p)
		if dir == "" {
			s.complete = false
			s.limitations = append(s.limitations,
				"skipped product package "+path+" has no recoverable source directory; its package clause cannot be verified")
			continue
		}
		idx, ok := s.pkgIndex[s.loaderRel(dir)]
		if !ok {
			s.complete = false
			s.limitations = append(s.limitations,
				"skipped product package "+path+" at "+s.loaderRel(dir)+" is missing from the source census")
			continue
		}
		pkg := &s.packages[idx]
		// A failed package can still link a main. The clause proof scans
		// every source the loader retained; the directory census above covers
		// the rest. The loader's single Name is a positive main proof but
		// never proof of its absence.
		hasMain, _ := skippedClauseProof(s.ix.fset, p)
		if hasMain {
			s.mainFiles = append(s.mainFiles, s.loaderRel(dir)+"/<skipped package clause>")
		}
		for _, e := range p.Errors {
			if len(pkg.LoadErrors) >= productCensusMaxLoadErrors {
				break
			}
			pkg.LoadErrors = append(pkg.LoadErrors, e.Error())
		}
	}
}

// rel renders a path the census walk built itself relative to the product
// root. The walk starts at the canonical root, so no normalization is needed.
func (s *productCensusScan) rel(p string) string {
	return productRelPath(s.dir, p)
}

// loaderRel renders a loader-reported path relative to the product root after
// symlink normalization (the loader may report the physical spelling of a
// symlinked temp or module directory).
func (s *productCensusScan) loaderRel(p string) string {
	return s.rel(evalSymlinksBestEffort(p))
}

// loaderPackageDir resolves the source directory of a loader package record:
// the reported Dir, else the directory of any listed or parsed source file.
func (s *productCensusScan) loaderPackageDir(p *packages.Package) string {
	if p.Dir != "" {
		return evalSymlinksBestEffort(p.Dir)
	}
	for _, list := range [][]string{p.GoFiles, p.CompiledGoFiles, p.OtherFiles} {
		for _, f := range list {
			if f != "" {
				return evalSymlinksBestEffort(filepath.Dir(f))
			}
		}
	}
	if s.ix.fset != nil {
		for _, f := range p.Syntax {
			if f == nil {
				continue
			}
			if pos := s.ix.fset.Position(f.Pos()); pos.Filename != "" {
				return evalSymlinksBestEffort(filepath.Dir(pos.Filename))
			}
		}
	}
	return ""
}

// syntheticTestMain reports whether p is the generated test-driver main
// package rather than product source.
func syntheticTestMain(p *packages.Package) bool {
	return p.Name == "main" && strings.HasSuffix(p.PkgPath, ".test")
}

// finalize classifies the census and renders the deterministic evidence.
func (s *productCensusScan) finalize(own productOwnership, loadErr error, loaderKey string) *productCensus {
	sort.Slice(s.packages, func(i, j int) bool { return s.packages[i].Directory < s.packages[j].Directory })
	sort.Slice(s.fixtures, func(i, j int) bool { return s.fixtures[i].Directory < s.fixtures[j].Directory })
	sort.Strings(s.mainFiles)
	sort.Strings(s.fixtureMainFiles)
	sort.Slice(s.excluded, func(i, j int) bool { return s.excluded[i].dir < s.excluded[j].dir })

	limitations := append([]string(nil), own.limitations...)
	limitations = append(limitations, s.limitations...)
	// Test fixture data is not buildable product source, so a package main
	// there cannot be classified as an owned command; it also must not be
	// silently ignored, because that would authorize a LIBRARY proof for a
	// module that owns a command. The owned-command set is unproven: keep the
	// census incomplete instead.
	complete := own.complete && s.complete
	if len(s.fixtureMainFiles) > 0 {
		complete = false
		limitations = append(limitations,
			"testdata source declares package main ("+strings.Join(s.fixtureMainFiles, ", ")+
				"): test fixture data cannot be classified as product command source, so the owned-command set is unproven")
	}
	limitations = sortedUniqueStrings(limitations)

	shape := domain.ProductShape{
		RootModule:     own.rootModule,
		WorkspaceFile:  own.workspaceFile,
		Kind:           domain.ProductShapeUnknown,
		CensusComplete: complete,
		Packages:       append([]domain.ProductPackageShape(nil), s.packages...),
	}
	for _, m := range own.owned {
		shape.OwnedModules = append(shape.OwnedModules, m.shape)
	}
	for _, m := range s.excluded {
		shape.ExcludedModules = append(shape.ExcludedModules, m.shape)
	}

	switch {
	case len(s.mainFiles) > 0:
		// A product-owned main is a proven property of the analyzed tree,
		// independent of build selection or loader failure.
		shape.Kind = domain.ProductShapeApplication
	case loadErr != nil, !complete:
		// The source index failed, so typed-root reconciliation was
		// unavailable, or ownership/inventory has a recorded gap.
		shape.Kind = domain.ProductShapeUnknown
	case s.importable:
		shape.Kind = domain.ProductShapeLibrary
	default:
		shape.Kind = domain.ProductShapeUnknown
		limitations = append(limitations,
			"no importable product package was proven; the product shape is UNKNOWN")
	}
	shape.Limitations = sortedUniqueStrings(limitations)
	shape.Fingerprint = s.fingerprint(own, loaderKey)
	return &productCensus{
		shape:    shape,
		evidence: s.censusEvidence(shape),
		identity: shape.Fingerprint + "|" + loaderKey,
	}
}

// fingerprint renders the identity of every input the proof used: build
// context, module manifests and ownership, the inventoried file set and the
// source content the clauses were read from.
func (s *productCensusScan) fingerprint(own productOwnership, loaderKey string) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	write("product-dir", s.dir)
	write("goos", s.ix.Build.GOOS, "goarch", s.ix.Build.GOARCH,
		"cgo", strconv.FormatBool(s.ix.Build.CGOEnabled),
		"vendor", strconv.FormatBool(s.ix.Build.VendorMode),
		"tags", strings.Join(s.ix.Build.BuildTags, ","))
	write("env", strings.Join(s.ix.Env, "\x00"),
		"replaceenv", strconv.FormatBool(s.ix.ReplaceEnv))
	write("workspace", own.workspaceFile, own.workspaceHash)
	for _, m := range own.owned {
		write("owned-module", m.shape.Path, m.shape.Directory, m.digest)
	}
	for _, m := range s.excluded {
		write("excluded-module", m.shape.Path, m.shape.Directory, m.digest)
	}
	for _, pkg := range s.packages {
		write("package", pkg.Directory, pkg.Path, pkg.Module,
			strings.Join(pkg.PackageNames, ","),
			strconv.FormatBool(pkg.Importable), strconv.FormatBool(pkg.ClauseComplete))
		for _, f := range pkg.Files {
			write("file", f, s.fileHashes[f])
		}
	}
	// Testdata fixture source is not product packages, but it participates in
	// the proof (a package main there makes the census incomplete), so its
	// inventory and content must move the fingerprint too.
	for _, pkg := range s.fixtures {
		write("fixture-package", pkg.Directory, pkg.Path, pkg.Module,
			strings.Join(pkg.PackageNames, ","), strconv.FormatBool(pkg.ClauseComplete))
		for _, f := range pkg.Files {
			write("file", f, s.fileHashes[f])
		}
	}
	write("loader", loaderKey)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// censusEvidence renders the deterministic, content-addressed evidence
// records behind the proof. The fingerprint pins the same inputs.
func (s *productCensusScan) censusEvidence(shape domain.ProductShape) []domain.Evidence {
	var build strings.Builder
	fmt.Fprintf(&build, "product-shape proof: kind=%s census_complete=%t root_module=%q workspace_file=%q\n",
		shape.Kind, shape.CensusComplete, shape.RootModule, shape.WorkspaceFile)
	fmt.Fprintf(&build, "build context: GOOS=%q GOARCH=%q CGO_ENABLED=%t vendor=%t tags=%q\n",
		s.ix.Build.GOOS, s.ix.Build.GOARCH, s.ix.Build.CGOEnabled,
		s.ix.Build.VendorMode, strings.Join(s.ix.Build.BuildTags, ","))
	for _, m := range shape.OwnedModules {
		fmt.Fprintf(&build, "owned module: path=%q directory=%q\n", m.Path, m.Directory)
	}
	for _, m := range shape.ExcludedModules {
		fmt.Fprintf(&build, "excluded module: path=%q directory=%q (not owned by the product module composition)\n", m.Path, m.Directory)
	}
	if len(s.mainFiles) > 0 {
		fmt.Fprintf(&build, "owned main sources: %s\n", strings.Join(s.mainFiles, ", "))
	} else {
		fmt.Fprintf(&build, "owned main sources: none\n")
	}
	if len(s.fixtureMainFiles) > 0 {
		fmt.Fprintf(&build, "testdata main sources (census incomplete): %s\n", strings.Join(s.fixtureMainFiles, ", "))
	} else {
		fmt.Fprintf(&build, "testdata main sources: none\n")
	}
	fmt.Fprintf(&build, "testdata fixture packages inventoried (not product source): %d\n", len(s.fixtures))
	fmt.Fprintf(&build, "fingerprint=%s\n", shape.Fingerprint)
	for _, l := range shape.Limitations {
		fmt.Fprintf(&build, "limitation: %s\n", l)
	}

	var census strings.Builder
	if len(shape.Packages) == 0 {
		census.WriteString("no non-test product package source was inventoried\n")
	}
	for _, p := range shape.Packages {
		fmt.Fprintf(&census, "%s module=%q directory=%q names=%q files=%d importable=%t clause_complete=%t\n",
			p.Path, p.Module, p.Directory, strings.Join(p.PackageNames, ","),
			len(p.Files), p.Importable, p.ClauseComplete)
		for _, e := range p.LoadErrors {
			fmt.Fprintf(&census, "  load_error: %s\n", e)
		}
	}
	if len(s.fixtures) > 0 {
		fmt.Fprintf(&census, "testdata fixture packages (not product source): %d\n", len(s.fixtures))
		for _, p := range s.fixtures {
			fmt.Fprintf(&census, "  %s module=%q directory=%q names=%q files=%d clause_complete=%t\n",
				p.Path, p.Module, p.Directory, strings.Join(p.PackageNames, ","),
				len(p.Files), p.ClauseComplete)
		}
	}
	return []domain.Evidence{
		{
			Kind:    domain.EvidenceBuild,
			Quality: domain.QualityDeterministic,
			Source:  "source index: product-shape ownership, build context and proof identity",
			Tool:    "goanalysis.Index.BuildProductShape",
			Content: build.String(),
		},
		{
			Kind:    domain.EvidencePackageList,
			Quality: domain.QualityDeterministic,
			Source:  "source index: product-shape non-test package census",
			Tool:    "goanalysis.Index.BuildProductShape",
			Content: census.String(),
		},
	}
}

// productFileClause recovers a source file's package clause. The parser reads
// only the clause, so a broken body still yields the declared package.
func productFileClause(fset *token.FileSet, name string, src []byte) (string, error) {
	f, err := parser.ParseFile(fset, name, src, parser.PackageClauseOnly)
	if err != nil {
		return "", err
	}
	if f == nil || f.Name == nil {
		return "", fmt.Errorf("source has no package clause")
	}
	return f.Name.Name, nil
}

// productInternalDir reports whether a product-relative directory is inside
// an `internal` element, i.e. not importable by an external module.
func productInternalDir(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "internal" {
			return true
		}
	}
	return false
}

// productRelPath renders target relative to the product root (slash
// separated); targets outside the root keep their `..` prefix.
func productRelPath(root, target string) string {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return filepath.ToSlash(target)
	}
	return filepath.ToSlash(rel)
}

// pathWithin reports whether target is root or lives under it.
func pathWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// evalSymlinksBestEffort canonicalizes a path when the symlink-free form is
// resolvable; otherwise the cleaned path stays as given. Comparing loader
// paths with the product root needs this on hosts whose temp/module roots are
// symlinked (e.g. /var -> /private/var).
func evalSymlinksBestEffort(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

// envValue returns the effective value of an environment key: later entries
// win, mirroring how a child process resolves duplicate keys.
func envValue(env []string, key string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(env[i], "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// sortedUniqueStrings sorts and deduplicates limitation text so the persisted
// record and its evidence are order-stable regardless of discovery order.
func sortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return dedupStrings(out)
}
