package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	canonicalrepository "github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/exposure"
	"github.com/fedorovmv/izyan/internal/productb/affected"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/repository"
)

// MaterialAvailability is the deterministic availability verdict for one
// collected material. UNAVAILABLE is a neutral limitation — never a
// negative fact — and INVALID marks material that was rejected (unreadable,
// unsafe) rather than absent.
type MaterialAvailability string

const (
	MaterialAvailable   MaterialAvailability = "AVAILABLE"
	MaterialUnavailable MaterialAvailability = "UNAVAILABLE"
	MaterialInvalid     MaterialAvailability = "INVALID"
)

// Material kinds produced by CollectMaterials.
const (
	MaterialModuleManifest = "module_manifest"
	MaterialModuleGraph    = "module_graph"
	MaterialBuildGraph     = "build_graph"
	MaterialSBOM           = "sbom"
	MaterialBinary         = "binary"
	MaterialDeployScan     = "deploy_scan"
	MaterialDeployPath     = "deploy_path"
	MaterialDeployArchive  = "deploy_archive"
)

// Material is one provenance-bound item of the Stage 0 material set. It
// carries identity, hash/size and status only — never content and never
// credential material.
type Material struct {
	ID           string               `json:"material_id"`
	Kind         string               `json:"kind"`
	Source       string               `json:"source"`
	Scope        string               `json:"scope"`
	SHA256       string               `json:"sha256,omitempty"`
	Size         int64                `json:"size,omitempty"`
	Availability MaterialAvailability `json:"availability"`
	Provenance   []string             `json:"provenance,omitempty"`
	Limitations  []string             `json:"limitations,omitempty"`
}

// ModuleVersion is one resolved module edge of the snapshot's dependency
// graph: the version that actually lands in the build (replace-resolved).
type ModuleVersion struct {
	Path       string `json:"path"`
	DeclaredPath string `json:"declared_path,omitempty"`
	Version    string `json:"version,omitempty"`
	Main       bool   `json:"main,omitempty"`
	ReplacedBy string `json:"replaced_by,omitempty"`
}

// ModuleGraph is the deterministic module-resolution fact derived from the
// snapshot. Source names the evidence surface the modules were read from
// (go list -m, vendor/modules.txt, go.mod or go.sum); Complete reports
// whether that surface is a closed build graph — absence claims are only
// meaningful against a complete graph.
type ModuleGraph struct {
	Source   string          `json:"source"`
	Complete bool            `json:"complete"`
	Modules  []ModuleVersion `json:"modules,omitempty"`
	Linked   map[string]bool `json:"linked,omitempty"`
	// Paired inventories retain their own raw/run/build bindings.
	PackageInventory      *affected.PackageInventoryMeasurement `json:"package_inventory,omitempty"`
	BuildPackageInventory *affected.PackageInventoryMeasurement `json:"build_package_inventory,omitempty"`
	// TestOnly is the collection-time module projection. It never authorizes
	// an absence fact without replaying both retained inventories.
	TestOnly map[string]bool `json:"test_only,omitempty"`
	SHA256   string          `json:"sha256,omitempty"`
}

// ModulePath returns the module that effectively owns path: an exact match
// wins, then the longest module prefix covering it.
func (g ModuleGraph) ModulePath(path string) (ModuleVersion, bool) {
	best := -1
	bestLength := -1
	for i := range g.Modules {
		p := g.Modules[i].Path
		if declared := g.Modules[i].DeclaredPath; declared != "" && (path == declared || strings.HasPrefix(path, declared+"/")) {
			p = declared
		}
		if p == path {
			return g.Modules[i], true
		}
		if strings.HasPrefix(path, p+"/") && len(p) > bestLength {
			best, bestLength = i, len(p)
		}
	}
	if best >= 0 {
		return g.Modules[best], true
	}
	return ModuleVersion{}, false
}

// moduleAt is like ModulePath but matches either the declared path or the
// replace-resolved path.
func (g ModuleGraph) moduleAt(path string) (ModuleVersion, bool) {
	for _, m := range g.Modules {
		if m.Path == path || (m.ReplacedBy != "" && strings.SplitN(m.ReplacedBy, "@", 2)[0] == path) {
			return m, true
		}
	}
	return g.ModulePath(path)
}

// DeployFacts is the deterministic deployment-exposure projection over the
// snapshot and configured deployment paths. Facts are the raw
// exposure-domain records; an empty scan leaves Perimeter unknown — an
// absent manifest is never evidence of isolation.
type DeployFacts struct {
	Facts              []domain.ExposureFact `json:"-"`
	ExposureProjection []AgentExposureFact   `json:"exposure_projection,omitempty"`
	ProjectionSHA256   string                `json:"projection_sha256,omitempty"`
	FactCount          int                   `json:"fact_count"`
	SHA256             string                `json:"sha256,omitempty"`
	Perimeter          string                `json:"perimeter"`
	Rationale          string                `json:"rationale,omitempty"`
	ScannedPaths       []string              `json:"scanned_paths,omitempty"`
	Archives           []string              `json:"archives,omitempty"`
}

// MaterialSet is the materialized-fact bundle Stage 0 hands to the
// remaining stages: provenance-bound material records plus the derived
// module graph and deployment facts the checks consume.
type MaterialSet struct {
	Materials   []Material   `json:"materials"`
	Limitations []string     `json:"limitations,omitempty"`
	ModuleGraph *ModuleGraph `json:"module_graph,omitempty"`
	// PackageBuild is the independently probed build used for package listing.
	// A missing compiler/build identity keeps inventory facts non-admitting.
	PackageBuild *domain.BuildContext `json:"package_build,omitempty"`
	Deploy      *DeployFacts `json:"deploy,omitempty"`
	// Toolchain is populated by Stage 0 after ResolveReleaseToolchain; the
	// package check consumes it for stdlib claims.
	Toolchain *ReleaseToolchainFact `json:"toolchain,omitempty"`
}

// moduleManifests are the dependency-manifest files collected from the
// snapshot root.
var moduleManifests = []string{"go.mod", "go.sum", "vendor/modules.txt", "go.work"}

// CollectMaterials assembles the deterministic material set for one
// snapshotted finding: declared artifact availability, the module graph
// (go list -m via the injected GoTool, else vendor/modules.txt, go.mod or
// go.sum in that order) and deployment-exposure facts from the snapshot
// and the configured deployment paths. Optional absences are UNAVAILABLE
// limitations; every failure to read required evidence is a technical
// error.
func CollectMaterials(ctx context.Context, m SnapshotManifest, cfg SiteConfig, tool affected.GoTool) (MaterialSet, error) {
	return collectMaterialsForTarget(ctx, m, cfg, tool, nil)
}

func collectMaterialsForTarget(ctx context.Context, m SnapshotManifest, cfg SiteConfig, tool affected.GoTool, target *domain.ProductTarget) (MaterialSet, error) {
	var set MaterialSet
	root := m.Repository

	for _, rel := range moduleManifests {
		set.Materials = append(set.Materials, manifestMaterial(m, root, rel))
	}
	for _, a := range m.Artifacts {
		set.Materials = append(set.Materials, artifactMaterial(a))
	}

	var build domain.ProductSnapshot
	if tool != nil {
		opts := canonicalrepository.SnapshotOptions{ExternalCommitSHA: firstNonEmpty(m.ResolvedRevision, "content-"+m.ContentHash)}
		if target != nil {
			opts.GOOS, opts.GOARCH, opts.BuildTags, opts.CGO = target.GOOS, target.GOARCH, target.BuildTags, &target.CGOEnabled
		}
		bin, env, identifiedTool := affected.ToolchainEnvironment(tool)
		opts.GoBin, opts.Env = bin, env
		var err error
		build, err = (canonicalrepository.Service{}).Snapshot(ctx, root, opts)
		if err != nil { set.Limitations = append(set.Limitations, "package build identity: "+err.Error()) } else {
			if m.ContentHash != "" && build.ContentHash != m.ContentHash {
				return set, fmt.Errorf("package inventory snapshot changed: measured %s, expected %s", build.ContentHash, m.ContentHash)
			}
			// A content-addressed snapshot is not a claimed git revision.
			build.Commit, build.ExternalCommitSHA = m.ResolvedRevision, m.ResolvedRevision
			identity := domain.EffectiveBuildContext(build)
			if identifiedTool { set.PackageBuild = &identity } else {
				set.Limitations = append(set.Limitations, "package inventory compiler identity unavailable for injected backend")
			}
		}
	}
	graph, gmats, glims := collectModuleGraph(ctx, root, tool, build)
	set.ModuleGraph = graph
	set.Materials = append(set.Materials, gmats...)
	set.Limitations = append(set.Limitations, glims...)

	deploy, dmats, dlims := collectDeployFacts(m, cfg, graph)
	set.Deploy = &deploy
	set.Materials = append(set.Materials, dmats...)
	set.Limitations = append(set.Limitations, dlims...)

	return set, nil
}

// manifestMaterial resolves one module manifest: the file list recorded by
// the snapshot supplies hash and size; a file absent from both the manifest
// and the tree is UNAVAILABLE, never a negative fact.
func manifestMaterial(m SnapshotManifest, root, rel string) Material {
	mat := Material{
		ID:           rel,
		Kind:         MaterialModuleManifest,
		Source:       rel,
		Scope:        "source",
		Availability: MaterialUnavailable,
	}
	if f := declaredFile(m, rel); f != nil {
		mat.Availability = MaterialAvailable
		mat.SHA256 = f.SHA256
		mat.Size = f.Size
		mat.Provenance = []string{"snapshot:" + rel}
		return mat
	}
	if root == "" {
		return mat
	}
	// Manifests built by other builders may omit the file list; read
	// directly rather than losing the material.
	sum, size, err := hashFileSHA256(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return mat
	}
	mat.Availability = MaterialAvailable
	mat.SHA256 = sum
	mat.Size = size
	mat.Provenance = []string{"snapshot_root:" + rel}
	return mat
}

// artifactMaterial projects a snapshot artifact record (sbom or binary) into
// a material. Roles come from SnapshotFile.Role.
func artifactMaterial(a SnapshotFile) Material {
	role := a.Role
	if role == "" {
		role = "artifact"
	}
	return Material{
		ID:           role,
		Kind:         role,
		Source:       a.Path,
		Scope:        "artifact",
		SHA256:       a.SHA256,
		Size:         a.Size,
		Availability: MaterialAvailable,
		Provenance:   []string{"snapshot_artifact:" + a.Path},
	}
}

// collectModuleGraph resolves the snapshot's module graph. The injected
// GoTool is authoritative when it produces a module list; otherwise the
// tree's own declarations are read in strict precedence order:
// vendor/modules.txt (authoritative for vendored builds), then go.mod
// requires (declared, not closed), then go.sum (hash presence only —
// never closed).
func collectModuleGraph(ctx context.Context, root string, tool affected.GoTool, build domain.ProductSnapshot) (*ModuleGraph, []Material, []string) {
	var mats []Material
	var lims []string

	if tool != nil && root != "" {
		if raw, source, err := tool.ListModules(ctx, root, build); err != nil {
			lims = append(lims, shortErr(fmt.Sprintf("module graph via %s failed: %v", source, err)))
			if len(raw) > 0 {
				if g, ok := decodeModuleList(raw, source); ok {
					mats = append(mats, moduleGraphMaterial(raw, source))
					return g, mats, lims
				}
			}
		} else if g, ok := decodeModuleList(raw, source); ok {
			mats = append(mats, moduleGraphMaterial(raw, source))
			// Linked import paths are an optional completeness signal:
			// go list -deps failure is a limitation, not a lost fact.
			if pkgRaw, perr := tool.ListPackages(ctx, root, build); perr != nil {
				lims = append(lims, shortErr(fmt.Sprintf("go list -deps failed: %v", perr)))
			} else if inventory, derr := affected.CompletePackageInventory(pkgRaw, "go list -deps -test -json ./..."); derr != nil {
				lims = append(lims, shortErr(fmt.Sprintf("decode package list: %v", derr)))
			} else {
				g.Linked = inventory.Paths
				m := affected.RecordPackageInventory(pkgRaw, nil, build, true)
				g.PackageInventory = &m
				mats = append(mats, Material{
					ID:           "build-graph",
					Kind:         MaterialBuildGraph,
					Source:       "go list -deps -test -json ./...",
					Scope:        "source",
					SHA256:       sha256hex(pkgRaw),
					Size:         int64(len(pkgRaw)),
					Availability: MaterialAvailable,
					Provenance:   []string{"go_list_deps"},
				})
				// The non-test closure makes the test-only distinction
				// deterministic: a module whose packages never appear there
				// exists for tests alone and cannot execute in the product.
				if buildRaw, berr := tool.ListBuildPackages(ctx, root, build); berr != nil {
					lims = append(lims, shortErr(fmt.Sprintf("go list -deps (non-test) failed: %v", berr)))
				} else if testOnly, terr := testOnlyModules(g, pkgRaw, buildRaw); terr != nil {
					lims = append(lims, shortErr(fmt.Sprintf("decode non-test package list: %v", terr)))
				} else {
					g.TestOnly = testOnly
					m := affected.RecordPackageInventory(buildRaw, nil, build, false)
					g.BuildPackageInventory = &m
					mats = append(mats, Material{
						ID:           "test-graph",
						Kind:         MaterialBuildGraph,
						Source:       "go list -deps -json ./...",
						Scope:        "source",
						SHA256:       sha256hex(buildRaw),
						Size:         int64(len(buildRaw)),
						Availability: MaterialAvailable,
						Provenance:   []string{"go_list_deps_nontest"},
					})
				}
			}
			return g, mats, lims
		} else {
			lims = append(lims, "module graph output undecodable")
		}
	}

	if root == "" {
		return nil, mats, lims
	}
	// vendor/modules.txt is authoritative when the repository vendors.
	if b, err := os.ReadFile(filepath.Join(root, "vendor", "modules.txt")); err == nil {
		mods := affected.ParseVendorModules(b)
		if len(mods) > 0 {
			return &ModuleGraph{
				Source:   "vendor/modules.txt",
				Complete: true,
				Modules:  moduleVersions(mods),
				SHA256:   sha256hex(b),
			}, mats, lims
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		if mods, merr := goModModules(b); merr == nil && len(mods) > 0 {
			lims = append(lims,
				"module list derived from go.mod declarations; resolved build list unavailable")
			return &ModuleGraph{
				Source:  "go.mod",
				Modules: mods,
				SHA256:  sha256hex(b),
			}, mats, lims
		} else if merr != nil {
			lims = append(lims, shortErr(fmt.Sprintf("go.mod parse failed: %v", merr)))
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
		if mods := goSumModules(b); len(mods) > 0 {
			lims = append(lims,
				"module list derived from go.sum; hash presence is not proof of build linkage")
			return &ModuleGraph{
				Source:  "go.sum",
				Modules: mods,
				SHA256:  sha256hex(b),
			}, mats, lims
		}
	}
	return nil, mats, lims
}

// decodeModuleList decodes a `go list -m -json` stream into a complete
// module graph.
func decodeModuleList(raw []byte, source string) (*ModuleGraph, bool) {
	mods, err := affected.DecodeModules(raw)
	if err != nil {
		return nil, false
	}
	return &ModuleGraph{
		Source:   source,
		Complete: true,
		Modules:  moduleVersions(mods),
		SHA256:   sha256hex(raw),
	}, true
}

func moduleGraphMaterial(raw []byte, source string) Material {
	return Material{
		ID:           "module-graph",
		Kind:         MaterialModuleGraph,
		Source:       source,
		Scope:        "source",
		SHA256:       sha256hex(raw),
		Size:         int64(len(raw)),
		Availability: MaterialAvailable,
		Provenance:   []string{source},
	}
}

// moduleVersions projects affected.Module onto the deterministic version
// record: effective (replace-resolved) path and version.
func moduleVersions(mods []affected.Module) []ModuleVersion {
	out := make([]ModuleVersion, 0, len(mods))
	for _, m := range mods {
		mv := ModuleVersion{
			DeclaredPath: m.Path,
			Path:    m.EffectivePath(),
			Version: m.EffectiveVersion(),
			Main:    m.Main,
		}
		if m.Replace != nil {
			mv.ReplacedBy = m.Replace.Path
			if m.Replace.Version != "" {
				mv.ReplacedBy += "@" + m.Replace.Version
			}
		}
		out = append(out, mv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// goModModules extracts require directives from go.mod (ParseLax tolerates
// incomplete manifests); the result is a declared set, not a resolved graph.
func goModModules(b []byte) ([]ModuleVersion, error) {
	f, err := modfile.ParseLax("go.mod", b, nil)
	if err != nil {
		return nil, err
	}
	repl := map[string]module.Version{}
	for _, r := range f.Replace {
		repl[r.Old.Path] = r.New
	}
	var mods []ModuleVersion
	if f.Module != nil {
		mods = append(mods, ModuleVersion{Path: f.Module.Mod.Path, Main: true})
	}
	for _, r := range f.Require {
		mv := ModuleVersion{Path: r.Mod.Path, Version: r.Mod.Version}
		if nv, ok := repl[r.Mod.Path]; ok {
			mv.ReplacedBy = nv.Path
			if nv.Version != "" {
				mv.ReplacedBy += "@" + nv.Version
			}
			if nv.Version != "" {
				mv.Version = nv.Version
			}
		}
		mods = append(mods, mv)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

// goSumModules collects module@version pairs recorded in go.sum. Multiple
// versions of one module stay ambiguous: Version is emptied so range checks
// refuse to claim a resolved version.
func goSumModules(b []byte) []ModuleVersion {
	vers := map[string]map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ver := strings.TrimSuffix(f[1], "/go.mod")
		if vers[f[0]] == nil {
			vers[f[0]] = map[string]bool{}
		}
		vers[f[0]][ver] = true
	}
	out := make([]ModuleVersion, 0, len(vers))
	for path, vs := range vers {
		mv := ModuleVersion{Path: path}
		if len(vs) == 1 {
			for v := range vs {
				mv.Version = v
			}
		}
		out = append(out, mv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// deploySiblingSuffixes mirror the sibling-repo suffixes ScanDeployWithOptions
// auto-discovers; they are re-listed here so allow_external_sources can
// suppress the implicit discovery deterministically.
var deploySiblingSuffixes = []string{"-deploy", "-helm", "-manifests", "-gitops", "-infra"}

// deploySuppressMarker names a non-deploy path used to hold ExtraPaths
// non-empty (which turns off ScanDeployWithOptions' implicit archive and
// sibling auto-discovery) without scanning anything: .git and vendor are
// skip-dirs, and a missing path is ignored.
const deploySuppressMarker = ".git"

// collectDeployFacts scans deployment surfaces: the snapshot root's
// deploy-scoped paths, every configured deployment path, archives inside
// the snapshot and (only with allow_external_sources) sibling repositories.
// Scans run through exposure.ScanDeployWithOptions so archive extraction is
// Zip-Slip-bounded; an unreadable archive becomes an INVALID material with
// a limitation, never a silent skip.
func collectDeployFacts(m SnapshotManifest, cfg SiteConfig, graph *ModuleGraph) (DeployFacts, []Material, []string) {
	var df DeployFacts
	var mats []Material
	var lims []string
	root := m.Repository

	var paths []string
	for _, p := range cfg.Deployment.Paths {
		if s := strings.TrimSpace(p); s != "" {
			paths = append(paths, s)
		}
	}
	// Archives inside the snapshot are contained material; they are always
	// admissible, scanned explicitly so rejections surface as limitations.
	var archives []string
	if root != "" {
		for _, pattern := range []string{"*.tgz", "*.tar.gz", "*.zip"} {
			matches, _ := filepath.Glob(filepath.Join(root, pattern))
			archives = append(archives, matches...)
		}
		sort.Strings(archives)
	}

	var allFacts []domain.ExposureFact
	var scanned []string
	add := func(f []domain.ExposureFact) { allFacts = append(allFacts, f...) }

	scan := func(opts exposure.DeployScanOptions) ([]domain.ExposureFact, error) {
		return exposure.ScanDeployWithOptions(opts)
	}

	if root != "" {
		scanned = append(scanned, root)
		switch {
		case cfg.Deployment.AllowExternalSources && len(paths) == 0 && len(archives) == 0:
			// Full auto-discovery: root scan plus sibling trees and root
			// archives inside exposure itself.
			if facts, err := scan(exposure.DeployScanOptions{RootPath: root}); err != nil {
				lims = append(lims, shortErr(fmt.Sprintf("deployment scan failed: %v", err)))
			} else {
				add(facts)
			}
		case cfg.Deployment.AllowExternalSources:
			// External sources allowed: cover sibling deploy trees
			// explicitly so failures stay visible; a non-deploy marker
			// keeps ExtraPaths non-empty so the opaque archive/sibling
			// auto-discovery inside exposure stays off.
			extras := append([]string{filepath.Join(root, deploySuppressMarker)}, siblingDeployDirs(root)...)
			facts, err := scan(exposure.DeployScanOptions{RootPath: root, ExtraPaths: extras})
			if err == nil {
				add(facts)
			} else {
				lims = append(lims, shortErr(fmt.Sprintf("deployment scan failed: %v", err)))
			}
		default:
			// External discovery disabled: the marker alone keeps
			// ExtraPaths non-empty — no sibling tree or unconfigured
			// archive is scanned implicitly.
			facts, err := scan(exposure.DeployScanOptions{
				RootPath:   root,
				ExtraPaths: []string{filepath.Join(root, deploySuppressMarker)},
			})
			if err == nil {
				add(facts)
			} else {
				lims = append(lims, shortErr(fmt.Sprintf("deployment scan failed: %v", err)))
			}
		}
	} else if len(paths) > 0 {
		facts, err := scan(exposure.DeployScanOptions{ExtraPaths: paths})
		if err == nil {
			add(facts)
		} else {
			lims = append(lims, shortErr(fmt.Sprintf("deployment scan failed: %v", err)))
		}
	}

	// Configured paths: one material record each — invalid on error,
	// available on a clean scan (an empty clean scan is still usable
	// material: the path exists and yielded no surface).
	for _, p := range paths {
		scanned = append(scanned, p)
		facts, err := scan(exposure.DeployScanOptions{ExtraPaths: []string{p}})
		mat := Material{
			ID:         "deploy-path:" + filepath.Base(p),
			Kind:       MaterialDeployPath,
			Source:     "deployment.paths",
			Scope:      "deployment",
			Provenance: []string{"site_config"},
		}
		if err != nil {
			mat.Availability = MaterialInvalid
			mat.Limitations = []string{shortErr(fmt.Sprintf("deployment path scan failed: %v", err))}
			lims = append(lims, mat.Limitations[0])
		} else {
			mat.Availability = MaterialAvailable
			add(facts)
		}
		mats = append(mats, mat)
	}

	// Explicit archive scans: Zip-Slip-safe inside exposure; rejection is an
	// INVALID material plus limitation — never silently dropped.
	for _, ap := range archives {
		scanned = append(scanned, ap)
		sum, size, herr := hashFileSHA256(ap)
		mat := Material{
			ID:         "deploy-archive:" + filepath.Base(ap),
			Kind:       MaterialDeployArchive,
			Source:     filepath.Base(ap),
			Scope:      "deployment",
			Provenance: []string{"snapshot_root:" + filepath.Base(ap)},
		}
		facts, err := scan(exposure.DeployScanOptions{ArchivePath: ap})
		switch {
		case herr != nil:
			mat.Availability = MaterialInvalid
			mat.Limitations = []string{"archive unreadable"}
		case err != nil:
			mat.Availability = MaterialInvalid
			mat.SHA256, mat.Size = sum, size
			mat.Limitations = []string{shortErr(fmt.Sprintf("archive rejected: %v", err))}
			lims = append(lims, mat.Limitations[0])
		default:
			mat.Availability = MaterialAvailable
			mat.SHA256, mat.Size = sum, size
			add(facts)
		}
		mats = append(mats, mat)
	}

	df.Facts = dedupeExposureFacts(allFacts)
	df.FactCount = len(df.Facts)
	df.ScannedPaths = scanned
	df.Archives = archives
	if df.FactCount > 0 {
		sortExposureFacts(df.Facts)
	}
	df.ExposureProjection = exposureProjection(df.Facts)
	df.ProjectionSHA256 = exposureProjectionHash(df.ExposureProjection)
	if df.FactCount > 0 {
		if enc, err := json.Marshal(df.Facts); err == nil {
			df.SHA256 = sha256hex(enc)
		}
	}
	perimeterAssessment := exposure.ClassifyPerimeter(df.Facts, productNames(m, graph, root))
	df.Perimeter, df.Rationale = perimeterAssessment.Perimeter, perimeterAssessment.Rationale

	dmat := Material{
		ID:         "deploy-scan",
		Kind:       MaterialDeployScan,
		Source:     "exposure.ScanDeployWithOptions",
		Scope:      "deployment",
		SHA256:     df.SHA256,
		Provenance: []string{"perimeter:" + df.Perimeter},
	}
	if df.FactCount == 0 {
		// An empty deployment scan is UNAVAILABLE material — the perimeter
		// stays unknown and must never read as isolated.
		dmat.Availability = MaterialUnavailable
		dmat.Limitations = []string{"no deployment exposure facts resolved"}
	} else {
		dmat.Availability = MaterialAvailable
	}
	mats = append(mats, dmat)
	return df, mats, lims
}

// siblingDeployDirs lists existing sibling deployment trees of the snapshot
// root (repoName-deploy, -helm, ...) — the same set exposure auto-discovers,
// enumerated here so the scan stays explicit and error-visible.
func siblingDeployDirs(root string) []string {
	parent := filepath.Dir(root)
	base := filepath.Base(root)
	var out []string
	for _, suffix := range deploySiblingSuffixes {
		p := filepath.Join(parent, base+suffix)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// productNames names the analyzed product for perimeter attribution: the
// catalog source id, the main module basename, then the root basename.
func productNames(m SnapshotManifest, graph *ModuleGraph, root string) []string {
	var names []string
	add := func(s string) {
		if s != "" {
			for _, n := range names {
				if n == s {
					return
				}
			}
			names = append(names, s)
		}
	}
	add(m.Materialization.SourceID)
	if graph != nil {
		for _, mv := range graph.Modules {
			if mv.Main {
				add(filepath.Base(mv.Path))
			}
		}
	}
	if root != "" {
		add(filepath.Base(root))
	}
	return names
}

func dedupeExposureFacts(facts []domain.ExposureFact) []domain.ExposureFact {
	seen := make(map[string]bool, len(facts))
	var out []domain.ExposureFact
	for _, f := range facts {
		key := f.Direction + "|" + f.Kind + "|" + f.Target + "|" + f.Address + "|" + f.Scope + "|" + f.Owner + "|" + f.File
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func sortExposureFacts(facts []domain.ExposureFact) {
	sort.SliceStable(facts, func(i, j int) bool {
		a, b := facts[i], facts[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Target+a.Address < b.Target+b.Address
	})
}

// ReleaseToolchainFact is the resolved release-toolchain evidence: the
// version that built the product (never the analysis environment and never
// the go.mod language minimum), its source and the intake claim when it
// disagrees.
type ReleaseToolchainFact struct {
	Version     string                 `json:"version,omitempty"`
	Source      domain.GoVersionSource `json:"source,omitempty"`
	Location    string                 `json:"location,omitempty"`
	Claimed     string                 `json:"claimed,omitempty"`
	Conflict    bool                   `json:"conflict,omitempty"`
	Limitations []string               `json:"limitations,omitempty"`
}

// goModGoDirective returns the go.mod `go` directive — the declared minimum
// language version. It is deliberately kept out of release evidence.
func goModGoDirective(root string) string {
	if root == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	f, err := modfile.ParseLax("go.mod", b, nil)
	if err != nil || f.Go == nil {
		return ""
	}
	return f.Go.Version
}

// buildInfoGoVersion extracts the embedded toolchain version from
// `go version -m` output ("path: go1.x.y" on the first line).
func buildInfoGoVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, ": go"); i >= 0 {
			return strings.TrimSpace(line[i+2:])
		}
	}
	return ""
}

// binaryArtifact resolves the manifest's binary artifact to a filesystem
// path under the snapshot root (absolute paths are already contained).
func binaryArtifact(m SnapshotManifest) (string, bool) {
	root := m.Repository
	for _, a := range m.Artifacts {
		if a.Role != "binary" {
			continue
		}
		if filepath.IsAbs(a.Path) {
			if _, err := os.Stat(a.Path); err == nil {
				return a.Path, true
			}
			continue
		}
		if root == "" {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(a.Path))
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// DiscoverReleaseToolchain assembles the release-toolchain fact for the
// snapshot: embedded binary build info wins, then snapshot-local release
// evidence (go.mod `toolchain` directive, Dockerfile, CI, version files,
// release scripts), then — recorded as an unverified claim, never as
// evidence — the intake proposal's go_version. The go.mod `go` directive is
// a language minimum and cannot prove the release toolchain.
func DiscoverReleaseToolchain(ctx context.Context, proposal IntakeProposal, m SnapshotManifest) ReleaseToolchainFact {
	var fact ReleaseToolchainFact
	if bin, ok := binaryArtifact(m); ok {
		if out, err := repository.BinaryBuildInfo(ctx, bin); err == nil {
			if v := buildInfoGoVersion(out); v != "" {
				fact.Version = v
				fact.Source = domain.GoVersionSourceBinary
				fact.Location = aRel(m.Repository, bin)
			}
		} else {
			fact.Limitations = append(fact.Limitations,
				shortErr(fmt.Sprintf("binary build info unavailable: %v", err)))
		}
	}
	if fact.Version == "" {
		if ev := repository.DiscoverReleaseEvidence(m.Repository); ev.Version != "" {
			fact.Version = ev.Version
			fact.Source = ev.Source
			fact.Location = ev.Location
		}
	}
	claim := strings.TrimSpace(proposal.GoVersion)
	if claim != "" {
		fact.Claimed = claim
		if fact.Version == "" {
			fact.Version = claim
			fact.Source = "intake"
			fact.Limitations = append(fact.Limitations,
				"release toolchain taken from unverified intake claim")
		} else if !strings.EqualFold(strings.TrimPrefix(fact.Version, "go"), strings.TrimPrefix(claim, "go")) {
			fact.Conflict = true
			fact.Limitations = append(fact.Limitations,
				fmt.Sprintf("intake go_version %q conflicts with %s evidence %q", claim, fact.Source, fact.Version))
		}
	}
	if min := goModGoDirective(m.Repository); min != "" {
		fact.Limitations = append(fact.Limitations,
			fmt.Sprintf("go.mod go directive %q is a language minimum, not release-toolchain evidence", min))
	}
	if fact.Version == "" {
		fact.Limitations = append(fact.Limitations,
			"release toolchain unknown: no binary build info, snapshot release evidence or intake claim")
	}
	return fact
}

func aRel(root, path string) string {
	if root == "" {
		return path
	}
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return path
}

// MaterialSetHash is the canonical identity of the collected material set:
// sha256 over the JSON projection of materials, module graph and deploy
// facts — hash/size/status only, no content.
func MaterialSetHash(set MaterialSet) string {
	type projection struct {
		Materials   []Material   `json:"materials"`
		ModuleGraph *ModuleGraph `json:"module_graph,omitempty"`
		Deploy      *DeployFacts `json:"deploy,omitempty"`
	}
	b, err := json.Marshal(projection{Materials: set.Materials, ModuleGraph: set.ModuleGraph, Deploy: set.Deploy})
	if err != nil {
		return ""
	}
	return sha256hex(b)
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// shortErr bounds limitation strings: credentials are redacted first (an
// error echoing a token never reaches stage0.json, materials or the audit
// trail), then paths and variable content are truncated, never dropped
// wholesale.
func shortErr(s string) string {
	s = redactSecrets(s)
	const max = 200
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// testOnlyModules maps the test-inclusive package closure minus the non-test
// closure onto module ownership. A module qualifies only when it owns at
// least one package and none of its packages is reachable from a non-test
// build; an empty or undecodable non-test set yields an error (the caller
// keeps the distinction unset rather than guessing).
func testOnlyModules(g *ModuleGraph, testRaw, buildRaw []byte) (map[string]bool, error) {
	testInventory, err := affected.CompletePackageInventory(testRaw, "go list -deps -test -json ./...")
	if err != nil {
		return nil, err
	}
	buildInventory, err := affected.CompletePackageInventory(buildRaw, "go list -deps -json ./...")
	if err != nil {
		return nil, err
	}
	testPkgs, buildPkgs := testInventory.Paths, buildInventory.Paths
	return testOnlyModulesForPaths(g, testPkgs, buildPkgs)
}

func testOnlyModulesForPaths(g *ModuleGraph, testPkgs, buildPkgs map[string]bool) (map[string]bool, error) {
	if len(buildPkgs) == 0 {
		return nil, fmt.Errorf("non-test package closure is empty")
	}
	owned := map[string]bool{}
	testOnly := map[string]bool{}
	for pkg := range testPkgs {
		if strings.HasSuffix(pkg, ".test") || strings.HasSuffix(pkg, "_test") {
			continue
		}
		m, ok := g.ModulePath(pkg)
		if !ok {
			continue
		}
		owned[m.Path] = true
		if !buildPkgs[pkg] {
			testOnly[m.Path] = true
		}
	}
	for pkg := range buildPkgs {
		if m, ok := g.ModulePath(pkg); ok {
			delete(testOnly, m.Path)
		}
	}
	if len(owned) == 0 {
		return map[string]bool{}, nil
	}
	return testOnly, nil
}
