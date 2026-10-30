package goanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/davniy/izyan/internal/domain"
)

// Selected-source carriers. The canonical names live on the domain descriptor
// so a persisted selection and an analysis-local one cannot drift apart.
const (
	ModuleSourceVendor           = string(domain.ModuleSourceVendor)
	ModuleSourceModuleCache      = string(domain.ModuleSourceModuleCache)
	ModuleSourceLocalReplacement = string(domain.ModuleSourceLocalReplacement)
	ModuleSourceWorkspace        = string(domain.ModuleSourceWorkspace)
)

// SelectedModuleSource resolves modulePath@version — the coordinate the
// affected chain selected — to the source the recorded build actually uses.
//
// The recorded build, not the advisory, decides: a replace directive selects
// the replacement module's bytes, a confined local replacement or workspace
// member selects the captured local bytes, the vendor manifest's replacement
// header selects the vendored bytes, and only an unreplaced dependency falls
// back to the module cache entry for the exact coordinate. A missing
// replacement source is a typed input failure; the published original's bytes
// are never substituted.
func (ix *Index) SelectedModuleSource(modulePath, version string) (domain.ResolvedModuleSource, error) {
	modulePath = strings.TrimSpace(modulePath)
	version = strings.TrimSpace(version)
	if ix == nil {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, modulePath, version, "no source index")
	}
	if modulePath == "" {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, modulePath, version, "empty module path")
	}
	// An empty version is not rejected up front: a local replacement or
	// workspace module is identified by its captured content, not by an
	// invented version. The selection still fails closed when neither exists.
	return ix.ResolveModuleSource(modulePath, "", version)
}

// ResolveModuleSource resolves one declared module coordinate against the
// recorded build and returns the persistable selection together with the
// analysis-local directory its bytes were read from.
//
// declaredVersion is the build graph's declared coordinate when the caller has
// it (the affected resolver does). It is required to establish that a
// version-pinned replace directive applies; without it only unpinned rules are
// applied, so an unestablished rule is never guessed. expectedEffectiveVersion
// is the coordinate the affected chain selected — a divergence from what the
// recorded build selects is a typed contradiction, never a substitution.
func (ix *Index) ResolveModuleSource(declaredModule, declaredVersion, expectedEffectiveVersion string) (domain.ResolvedModuleSource, error) {
	if ix == nil {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, declaredModule, expectedEffectiveVersion, "no source index")
	}
	declaredModule = strings.TrimSpace(declaredModule)
	declaredVersion = strings.TrimSpace(declaredVersion)
	expectedEffectiveVersion = strings.TrimSpace(expectedEffectiveVersion)
	if declaredModule == "" {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, declaredModule, expectedEffectiveVersion, "empty module path")
	}
	plan, err := ix.planModuleSource(declaredModule, declaredVersion, expectedEffectiveVersion)
	if err != nil {
		return domain.ResolvedModuleSource{}, err
	}
	return ix.locateModuleSource(plan)
}

// moduleSourcePlan is the declared-to-effective selection before its bytes are
// located. Exactly one of vendored/localDir/workspaceDir/effectiveVersion
// carries the source identity.
type moduleSourcePlan struct {
	selection domain.EffectiveSourceSelection

	vendored     bool
	localDir     string
	workspaceDir string

	// effectiveVersion is the module-cache coordinate to read. It is empty for
	// a local or workspace source: those carry no invented version.
	effectiveVersion string
}

// planModuleSource derives the effective selection from the recorded build
// evidence. Resolution order follows the build: a vendored build's manifest
// replaces the module list, then workspace membership, then the recorded
// replace directives, then the unreplaced declared coordinate.
func (ix *Index) planModuleSource(declaredModule, declaredVersion, expectedEffectiveVersion string) (moduleSourcePlan, error) {
	plan := moduleSourcePlan{
		selection: domain.EffectiveSourceSelection{
			DeclaredModule:   declaredModule,
			DeclaredVersion:  declaredVersion,
			EffectiveModule:  declaredModule,
			EffectiveVersion: expectedEffectiveVersion,
		},
	}

	// 1. vendor/modules.txt is the identity authority for a vendored build. It
	// records both the declared coordinate and any replacement the build
	// actually used, so no other evidence may override it.
	header, vendored, err := ix.vendorHeader(declaredModule)
	if err != nil {
		return moduleSourcePlan{}, err
	}
	if vendored {
		plan.vendored = true
		if declaredVersion != "" && !sameModuleVersion(declaredVersion, header.declaredVersion) {
			return moduleSourcePlan{}, domain.NewModuleSourceError(
				domain.ModuleSourceContradiction, declaredModule, declaredVersion,
				"vendor/modules.txt declares %s %s, not the recorded %s",
				declaredModule, header.declaredVersion, declaredVersion)
		}
		plan.selection.DeclaredVersion = header.declaredVersion
		return ix.planVendoredReplacement(plan, header, expectedEffectiveVersion)
	}

	// 2. Workspace membership: a go.work member is a main module of the build,
	// not a published dependency. Its identity is the captured local bytes.
	member, err := ix.workspaceMember(declaredModule)
	if err != nil {
		return moduleSourcePlan{}, err
	}
	if member != nil {
		plan.workspaceDir = member.dir
		plan.selection.Workspace = &domain.WorkspaceSelection{
			Module:    declaredModule,
			Directory: member.rel,
		}
		plan.selection.EffectiveModule = declaredModule
		plan.selection.EffectiveVersion = ""
		plan.effectiveVersion = ""
		return plan, nil
	}

	// 3. Recorded replace directives select the replacement module or a
	// confined local directory. A local replacement carries no version.
	directive := ix.recordedReplacement(declaredModule, declaredVersion)
	if directive != nil {
		plan.selection.Replacements = []domain.ReplaceDirective{*directive}
		if isLocalModulePath(directive.New) {
			plan.selection.EffectiveModule = declaredModule
			plan.selection.EffectiveVersion = ""
			plan.effectiveVersion = ""
			if expectedEffectiveVersion != "" && declaredVersion != "" &&
				!sameModuleVersion(expectedEffectiveVersion, declaredVersion) {
				return moduleSourcePlan{}, domain.NewModuleSourceError(
					domain.ModuleSourceContradiction, declaredModule, declaredVersion,
					"the recorded build replaces %s with the local directory %s (declared %s), not the selected %s",
					declaredModule, directive.New, declaredVersion, expectedEffectiveVersion)
			}
			dir, rel, err := ix.confinedReplacementDir(declaredModule, declaredVersion, directive.New)
			if err != nil {
				return moduleSourcePlan{}, err
			}
			plan.localDir = dir
			plan.selection.LocalReplacement = &domain.LocalReplacementSelection{
				Module:    declaredModule,
				Directory: rel,
			}
			// The provenance keeps the recorded rule's shape but names the
			// captured directory, not a host path.
			plan.selection.Replacements[0].New = rel
			return plan, nil
		}
		newPath, newVersion := splitModuleCoordinate(directive.New)
		if newVersion == "" {
			return moduleSourcePlan{}, domain.NewModuleSourceError(
				domain.ModuleSourceUnreadable, declaredModule, declaredVersion,
				"replace directive for %s names %q, which is neither a versioned module nor a local path",
				declaredModule, directive.New)
		}
		if expectedEffectiveVersion != "" && !sameModuleVersion(expectedEffectiveVersion, newVersion) {
			return moduleSourcePlan{}, domain.NewModuleSourceError(
				domain.ModuleSourceContradiction, declaredModule, declaredVersion,
				"the recorded build replaces %s with %s@%s, not the selected %s",
				declaredModule, newPath, newVersion, expectedEffectiveVersion)
		}
		plan.selection.EffectiveModule = newPath
		plan.selection.EffectiveVersion = newVersion
		plan.effectiveVersion = newVersion
		return plan, nil
	}

	// 4. Unreplaced dependency: the exact declared coordinate is the selected
	// source. The expected effective version must agree with the recorded
	// declared version when both are known.
	if declaredVersion != "" && expectedEffectiveVersion != "" &&
		!sameModuleVersion(expectedEffectiveVersion, declaredVersion) {
		return moduleSourcePlan{}, domain.NewModuleSourceError(
			domain.ModuleSourceContradiction, declaredModule, declaredVersion,
			"the recorded build selects %s %s, not the resolved %s",
			declaredModule, declaredVersion, expectedEffectiveVersion)
	}
	if plan.selection.EffectiveVersion == "" {
		plan.selection.EffectiveVersion = declaredVersion
	}
	plan.effectiveVersion = plan.selection.EffectiveVersion
	return plan, nil
}

// planVendoredReplacement applies a vendor/modules.txt header. Import paths
// stay unchanged under a replacement, so the bytes remain under the declared
// module's vendored directory while the effective identity comes from the
// header's replacement.
func (ix *Index) planVendoredReplacement(plan moduleSourcePlan, header vendorRecord, expectedEffectiveVersion string) (moduleSourcePlan, error) {
	if header.replacementPath == "" {
		if expectedEffectiveVersion != "" && !sameModuleVersion(expectedEffectiveVersion, header.declaredVersion) {
			return moduleSourcePlan{}, domain.NewModuleSourceError(
				domain.ModuleSourceContradiction, plan.selection.DeclaredModule, header.declaredVersion,
				"vendor/modules.txt declares %s %s, not the selected %s",
				plan.selection.DeclaredModule, header.declaredVersion, expectedEffectiveVersion)
		}
		plan.selection.EffectiveModule = plan.selection.DeclaredModule
		plan.selection.EffectiveVersion = header.declaredVersion
		plan.effectiveVersion = header.declaredVersion
		return plan, nil
	}
	provenance := domain.ReplaceDirective{
		Old: plan.selection.DeclaredModule + "@" + header.declaredVersion,
		New: header.replacementPath,
	}
	if isLocalModulePath(header.replacementPath) {
		if expectedEffectiveVersion != "" && !sameModuleVersion(expectedEffectiveVersion, header.declaredVersion) {
			return moduleSourcePlan{}, domain.NewModuleSourceError(
				domain.ModuleSourceContradiction, plan.selection.DeclaredModule, header.declaredVersion,
				"vendor/modules.txt replaces %s %s with the local directory %s, not the selected %s",
				plan.selection.DeclaredModule, header.declaredVersion, header.replacementPath, expectedEffectiveVersion)
		}
		rel, confined := ix.snapshotRelativeTarget(header.replacementPath)
		if !confined {
			return moduleSourcePlan{}, domain.NewModuleSourceError(
				domain.ModuleSourceUnconfined, plan.selection.DeclaredModule, header.declaredVersion,
				"local replacement %q escapes the captured snapshot tree", header.replacementPath)
		}
		plan.selection.EffectiveModule = plan.selection.DeclaredModule
		plan.selection.EffectiveVersion = ""
		plan.effectiveVersion = ""
		plan.selection.LocalReplacement = &domain.LocalReplacementSelection{
			Module:    plan.selection.DeclaredModule,
			Directory: rel,
		}
		// The provenance names the captured directory, not a host path.
		provenance.New = rel
		plan.selection.Replacements = []domain.ReplaceDirective{provenance}
		return plan, nil
	}
	if header.replacementVersion == "" {
		return moduleSourcePlan{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnreadable, plan.selection.DeclaredModule, header.declaredVersion,
			"vendor/modules.txt replaces %s with %q, which names no version and is not a local path",
			plan.selection.DeclaredModule, header.replacementPath)
	}
	if expectedEffectiveVersion != "" && !sameModuleVersion(expectedEffectiveVersion, header.replacementVersion) {
		return moduleSourcePlan{}, domain.NewModuleSourceError(
			domain.ModuleSourceContradiction, plan.selection.DeclaredModule, header.declaredVersion,
			"vendor/modules.txt replaces %s with %s@%s, not the selected %s",
			plan.selection.DeclaredModule, header.replacementPath, header.replacementVersion, expectedEffectiveVersion)
	}
	provenance.New = header.replacementPath + "@" + header.replacementVersion
	plan.selection.EffectiveModule = header.replacementPath
	plan.selection.EffectiveVersion = header.replacementVersion
	plan.effectiveVersion = header.replacementVersion
	plan.selection.Replacements = []domain.ReplaceDirective{provenance}
	return plan, nil
}

// locateModuleSource binds the planned selection to the bytes it names. A
// selected root that does not exist is a typed failure: the declared module's
// published bytes are never read in its place.
func (ix *Index) locateModuleSource(plan moduleSourcePlan) (domain.ResolvedModuleSource, error) {
	sel := plan.selection
	switch {
	case plan.vendored:
		rel := "vendor/" + sel.DeclaredModule
		dir := filepath.Join(ix.Dir, "vendor", filepath.FromSlash(sel.DeclaredModule))
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
				domain.ModuleSourceUnavailable, sel.DeclaredModule, sel.DeclaredVersion,
				"the vendored directory %s for %s is missing", rel, sel.DeclaredModule)
		}
		sel.SourceKind = domain.ModuleSourceVendor
		sel.SourceRoot = rel
		return domain.ResolvedModuleSource{Selection: sel, Dir: dir}, nil
	case plan.workspaceDir != "":
		digest, err := moduleTreeDigest(plan.workspaceDir)
		if err != nil {
			return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
				domain.ModuleSourceUnreadable, sel.DeclaredModule, sel.DeclaredVersion,
				"hash the captured workspace module at %s: %v", sel.SourceRoot, err)
		}
		sel.SourceKind = domain.ModuleSourceWorkspace
		sel.SourceRoot = sel.Workspace.Directory
		sel.ContentDigest = digest
		return domain.ResolvedModuleSource{Selection: sel, Dir: plan.workspaceDir}, nil
	case plan.localDir != "":
		digest, err := moduleTreeDigest(plan.localDir)
		if err != nil {
			return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
				domain.ModuleSourceUnreadable, sel.DeclaredModule, sel.DeclaredVersion,
				"hash the captured local replacement at %s: %v", sel.LocalReplacement.Directory, err)
		}
		sel.SourceKind = domain.ModuleSourceLocalReplacement
		sel.SourceRoot = sel.LocalReplacement.Directory
		sel.ContentDigest = digest
		return domain.ResolvedModuleSource{Selection: sel, Dir: plan.localDir}, nil
	}
	if sel.EffectiveModule == "" || plan.effectiveVersion == "" {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, sel.DeclaredModule, sel.DeclaredVersion,
			"no versioned effective coordinate and no local source is recorded for %s", sel.DeclaredModule)
	}
	cache := ix.modCacheDir()
	if cache == "" {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, sel.DeclaredModule, sel.DeclaredVersion,
			"no module cache path is resolvable for %s@%s", sel.EffectiveModule, plan.effectiveVersion)
	}
	escapedPath, err := module.EscapePath(sel.EffectiveModule)
	if err != nil {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnreadable, sel.DeclaredModule, sel.DeclaredVersion,
			"%s is not a valid module path: %v", sel.EffectiveModule, err)
	}
	escapedVersion, err := module.EscapeVersion(plan.effectiveVersion)
	if err != nil {
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnreadable, sel.DeclaredModule, sel.DeclaredVersion,
			"%s is not a valid version of %s: %v", plan.effectiveVersion, sel.EffectiveModule, err)
	}
	dir := filepath.Join(cache, escapedPath+"@"+escapedVersion)
	if st, statErr := os.Stat(dir); statErr != nil || !st.IsDir() {
		// Never fall back to the declared module, the published original or
		// another version: the replacement is unavailable, which is an input
		// failure and an unmeasured prerequisite.
		return domain.ResolvedModuleSource{}, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, sel.DeclaredModule, sel.DeclaredVersion,
			"the module cache does not hold the selected replacement source %s@%s", sel.EffectiveModule, plan.effectiveVersion)
	}
	sel.SourceKind = domain.ModuleSourceModuleCache
	sel.SourceRoot = sel.EffectiveModule + "@" + plan.effectiveVersion
	return domain.ResolvedModuleSource{Selection: sel, Dir: dir}, nil
}

// SelectedModuleCoordinate reports whether relPath exists at exactly that
// module-relative location in the selected version's own source.
//
// exists is false only when the source was actually read and does not carry the
// path; an unresolvable source is returned as an error so the caller records an
// unmeasured prerequisite instead of a non-existence fact. No suffix, basename
// or similarity match is attempted: only the same module-relative path counts.
func (ix *Index) SelectedModuleCoordinate(modulePath, version, relPath string) (domain.ResolvedModuleSource, bool, error) {
	src, err := ix.SelectedModuleSource(modulePath, version)
	if err != nil {
		return domain.ResolvedModuleSource{}, false, err
	}
	return coordinateInSource(src, relPath)
}

// SelectedModuleCoordinateFor resolves the same coordinate in one recorded
// effective selection. It carries both the declared and the effective
// coordinate the descriptor captured, so a version-pinned replace directive is
// applied exactly as the recorded build applied it.
func (ix *Index) SelectedModuleCoordinateFor(selection domain.EffectiveSourceSelection, relPath string) (domain.ResolvedModuleSource, bool, error) {
	src, err := ix.ResolveModuleSource(selection.DeclaredModule, selection.DeclaredVersion, selection.EffectiveVersion)
	if err != nil {
		return domain.ResolvedModuleSource{}, false, err
	}
	return coordinateInSource(src, relPath)
}

// coordinateInSource reports whether relPath exists at exactly that
// module-relative location in one resolved source root.
func coordinateInSource(src domain.ResolvedModuleSource, relPath string) (domain.ResolvedModuleSource, bool, error) {
	clean, ok := moduleRelativePath(relPath)
	if !ok {
		return domain.ResolvedModuleSource{}, false, fmt.Errorf("selected module coordinate: %q is not a module-relative path", relPath)
	}
	st, statErr := os.Stat(filepath.Join(src.Dir, filepath.FromSlash(clean)))
	if statErr != nil || !st.Mode().IsRegular() {
		return src, false, nil
	}
	return src, true, nil
}

// SelectedModuleFile reads one module-relative file from a resolved selected
// source root. The read goes through the index's confinement gate when one is
// configured, so a bench-scoped index cannot answer from outside its roots.
//
// It is the read half of the same coordinate rule SelectedModuleCoordinate
// applies: only the same module-relative path counts, and a path that is not
// module-relative is refused rather than cleaned into something that is.
func (ix *Index) SelectedModuleFile(src domain.ResolvedModuleSource, relPath string) ([]byte, error) {
	clean, ok := moduleRelativePath(relPath)
	if !ok {
		return nil, fmt.Errorf("selected module file: %q is not a module-relative path", relPath)
	}
	full := filepath.Join(src.Dir, filepath.FromSlash(clean))
	if g := ix.gate(); g != nil {
		return g.ReadFile(full)
	}
	return os.ReadFile(full)
}

// VerifyModuleSource re-resolves a persisted descriptor against the recorded
// build and refuses a root whose bytes changed (or disappeared). A local
// replacement or workspace module is identified by its content digest, so
// mutating the captured bytes invalidates the previously recorded root.
func (ix *Index) VerifyModuleSource(recorded domain.EffectiveSourceSelection) error {
	if err := recorded.Validate(); err != nil {
		return err
	}
	if recorded.Failure != nil || recorded.SourceKind == "" {
		return nil
	}
	resolved, err := ix.ResolveModuleSource(recorded.DeclaredModule, recorded.DeclaredVersion, recorded.EffectiveVersion)
	if err != nil {
		return domain.NewModuleSourceError(
			domain.ModuleSourceStale, recorded.DeclaredModule, recorded.DeclaredVersion,
			"the recorded source is no longer resolvable: %v", err)
	}
	current := resolved.Selection
	if current.SourceKind != recorded.SourceKind || current.SourceRoot != recorded.SourceRoot {
		return domain.NewModuleSourceError(
			domain.ModuleSourceStale, recorded.DeclaredModule, recorded.DeclaredVersion,
			"the recorded build now selects %s at %s, not the recorded %s at %s",
			current.SourceKind, current.SourceRoot, recorded.SourceKind, recorded.SourceRoot)
	}
	if recorded.ContentDigest != "" && current.ContentDigest != recorded.ContentDigest {
		return domain.NewModuleSourceError(
			domain.ModuleSourceStale, recorded.DeclaredModule, recorded.DeclaredVersion,
			"the bytes at %s changed: recorded %s, current %s",
			recorded.SourceRoot, recorded.ContentDigest, current.ContentDigest)
	}
	return nil
}

// vendorRecord is one vendor/modules.txt header for a module path.
type vendorRecord struct {
	declaredVersion    string
	replacementPath    string
	replacementVersion string
}

// vendorHeader returns the single modules.txt header for modulePath. A missing
// manifest or a manifest without the module reports vendored=false so the
// module-cache path answers; a duplicated header is an ambiguity, never a
// first-match pick.
func (ix *Index) vendorHeader(modulePath string) (vendorRecord, bool, error) {
	if strings.TrimSpace(ix.Dir) == "" {
		return vendorRecord{}, false, nil
	}
	manifest := filepath.Join(ix.Dir, "vendor", "modules.txt")
	st, err := os.Stat(manifest)
	if err != nil || st.IsDir() {
		return vendorRecord{}, false, nil
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return vendorRecord{}, false, domain.NewModuleSourceError(
			domain.ModuleSourceUnreadable, modulePath, "", "read vendor/modules.txt: %v", err)
	}
	var found []vendorRecord
 var mirrors []vendorRecord
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) < 2 || fields[0] != modulePath {
			continue
		}
  // Go emits an unversioned replacement mirror after package membership.
  // It corroborates a versioned header; it cannot select a module on its own.
  if fields[1]=="=>" {
   if len(fields)<3 || len(fields)>4{return vendorRecord{},false,domain.NewModuleSourceError(domain.ModuleSourceUnreadable,modulePath,"","malformed vendor replacement mirror")}
   mirror:=vendorRecord{replacementPath:fields[2]};if len(fields)==4{mirror.replacementVersion=fields[3]};mirrors=append(mirrors,mirror);continue
  }
		h := vendorRecord{declaredVersion: fields[1]}
		if len(fields) >= 3 {
			if fields[2] != "=>" || len(fields) < 4 {
				return vendorRecord{}, false, domain.NewModuleSourceError(
					domain.ModuleSourceUnreadable, modulePath, "",
					"vendor/modules.txt carries a malformed replacement header for %s", modulePath)
			}
			h.replacementPath = fields[3]
			if len(fields) >= 5 {
				h.replacementVersion = fields[4]
			}
			if len(fields) > 5 {
				return vendorRecord{}, false, domain.NewModuleSourceError(
					domain.ModuleSourceUnreadable, modulePath, "",
					"vendor/modules.txt carries a malformed replacement header for %s", modulePath)
			}
		}
		found = append(found, h)
	}
	switch len(found) {
	case 0:
  if len(mirrors)>0{return vendorRecord{},false,domain.NewModuleSourceError(domain.ModuleSourceUnavailable,modulePath,"","vendor replacement mirror has no versioned source header")}
		return vendorRecord{}, false, nil
	case 1:
  if len(mirrors)>1{return vendorRecord{},false,domain.NewModuleSourceError(domain.ModuleSourceAmbiguous,modulePath,"","duplicate vendor replacement mirrors")}
  if len(mirrors)==1 && (mirrors[0].replacementPath!=found[0].replacementPath || mirrors[0].replacementVersion!=found[0].replacementVersion){return vendorRecord{},false,domain.NewModuleSourceError(domain.ModuleSourceContradiction,modulePath,"","vendor replacement mirror differs from versioned header")}
		return found[0], true, nil
	default:
		return vendorRecord{}, false, domain.NewModuleSourceError(
			domain.ModuleSourceAmbiguous, modulePath, "",
			"vendor/modules.txt carries %d headers for %s — module identity is ambiguous", len(found), modulePath)
	}
}

// workspaceMember reports the go.work member whose own module path is
// modulePath. A member outside the captured snapshot tree is refused: its
// bytes are not part of the snapshot and must not be read as a host path. The
// returned directory is analysis-local; rel is its stable snapshot-relative
// identity.
func (ix *Index) workspaceMember(modulePath string) (*workspaceMember, error) {
	if strings.TrimSpace(ix.Build.GoWorkFile) == "" || ix.Build.GoWorkFile == domain.GoWorkOff {
		return nil, nil
	}
	if strings.TrimSpace(ix.Dir) == "" {
		return nil, domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, modulePath, "",
			"the recorded workspace %q has no snapshot root to resolve against", ix.Build.GoWorkFile)
	}
	workFile := ix.Build.GoWorkFile
	if !filepath.IsAbs(workFile) {
		workFile = filepath.Join(ix.Dir, workFile)
	}
	raw, err := os.ReadFile(workFile)
	if err != nil {
		return nil, domain.NewModuleSourceError(
			domain.ModuleSourceUnreadable, modulePath, "",
			"read the recorded go.work %s: %v", workFile, err)
	}
	wf, err := modfile.ParseWork(filepath.Base(workFile), raw, nil)
	if err != nil {
		return nil, domain.NewModuleSourceError(
			domain.ModuleSourceUnreadable, modulePath, "",
			"parse the recorded go.work %s: %v", workFile, err)
	}
	base := filepath.Dir(workFile)
	for _, use := range wf.Use {
		dir := use.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(base, dir)
		}
		rel, confined := confinedRel(ix.Dir, dir)
		if !confined {
			return nil, domain.NewModuleSourceError(
				domain.ModuleSourceUnconfined, modulePath, "",
				"workspace member %q escapes the captured snapshot tree", use.Path)
		}
		memberMod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			return nil, domain.NewModuleSourceError(
				domain.ModuleSourceUnreadable, modulePath, "",
				"workspace member %q has no readable go.mod: %v", use.Path, err)
		}
		file, err := modfile.Parse("go.mod", memberMod, nil)
		if err != nil {
			return nil, domain.NewModuleSourceError(
				domain.ModuleSourceUnreadable, modulePath, "",
				"parse workspace member %q go.mod: %v", use.Path, err)
		}
		if file.Module != nil && file.Module.Mod.Path == modulePath {
			return &workspaceMember{dir: absPath(dir), rel: rel}, nil
		}
	}
	return nil, nil
}

type workspaceMember struct {
	dir string
	rel string
}

// recordedReplacement returns the last recorded replace directive that applies
// to declaredModule@declaredVersion, or nil when the build leaves the module
// unreplaced. Manifest order is preserved on the snapshot (go.mod rules, then
// the effective workspace's rules), so the last match is the one the build
// applies. A rule pinned to a different version is not applied for a known
// declared version.
func (ix *Index) recordedReplacement(declaredModule, declaredVersion string) *domain.ReplaceDirective {
	var applied *domain.ReplaceDirective
	for i := range ix.Build.ReplaceDirectives {
		directive := ix.Build.ReplaceDirectives[i]
		oldPath, oldVersion := splitModuleCoordinate(directive.Old)
		if oldPath != declaredModule {
			continue
		}
		if oldVersion != "" {
			if declaredVersion == "" || !sameModuleVersion(oldVersion, declaredVersion) {
				continue
			}
		}
		copied := directive
		applied = &copied
	}
	return applied
}

// confinedReplacementDir resolves a local replace target inside the captured
// snapshot tree. It returns the analysis-local directory and its stable
// snapshot-relative identity. A target outside the tree is refused: the
// snapshot cannot vouch for a host path.
func (ix *Index) confinedReplacementDir(declaredModule, declaredVersion, target string) (string, string, error) {
	if strings.TrimSpace(ix.Dir) == "" {
		return "", "", domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, declaredModule, declaredVersion,
			"local replacement %q has no snapshot root to resolve against", target)
	}
	dir := target
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(ix.Dir, filepath.FromSlash(target))
	}
	rel, confined := confinedRel(ix.Dir, dir)
	if !confined {
		return "", "", domain.NewModuleSourceError(
			domain.ModuleSourceUnconfined, declaredModule, declaredVersion,
			"local replacement %q escapes the captured snapshot tree", target)
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", "", domain.NewModuleSourceError(
			domain.ModuleSourceUnavailable, declaredModule, declaredVersion,
			"the local replacement directory %q for %s is missing", target, declaredModule)
	}
	return absPath(dir), rel, nil
}

// snapshotRelativeTarget maps a recorded local replace target to its stable
// snapshot-relative identity. Replace targets resolve against the module root;
// a target outside the captured tree is refused, because the snapshot cannot
// vouch for a host path.
func (ix *Index) snapshotRelativeTarget(target string) (string, bool) {
	if strings.TrimSpace(ix.Dir) == "" {
		return "", false
	}
	dir := target
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(ix.Dir, filepath.FromSlash(target))
	}
	return confinedRel(ix.Dir, dir)
}

// moduleTreeDigest hashes the captured files of one source root by relative
// path and content, in the deterministic walk order. It is the identity of a
// versionless source and the witness that a recorded root still holds the same
// bytes.
func moduleTreeDigest(dir string) (string, error) {
	digest := sha256.New()
	err := filepath.WalkDir(dir, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		digest.Write([]byte(filepath.ToSlash(rel)))
		digest.Write([]byte{0})
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(digest, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		digest.Write([]byte{0})
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// splitModuleCoordinate splits "path" or "path@version" at its version
// separator. Module paths never contain '@'.
func splitModuleCoordinate(coordinate string) (string, string) {
	coordinate = strings.TrimSpace(coordinate)
	if i := strings.LastIndex(coordinate, "@"); i > 0 {
		return coordinate[:i], coordinate[i+1:]
	}
	return coordinate, ""
}

// isLocalModulePath reports whether a replace target names a filesystem
// directory instead of a module coordinate.
func isLocalModulePath(p string) bool {
	return filepath.IsAbs(p) || p == "." || p == ".." ||
		strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") ||
		strings.HasPrefix(p, ".\\") || strings.HasPrefix(p, "..\\")
}

// confinedRel reports whether dir lies inside root and returns its stable
// slash-separated relative identity.
func confinedRel(root, dir string) (string, bool) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(absRoot, absDir)
	if err != nil || filepath.IsAbs(rel) {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// sameModuleVersion compares two recorded version spellings. A bare version and
// its v-prefixed form are the same coordinate; anything else must match exactly.
func sameModuleVersion(a, b string) bool {
	norm := func(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "v") }
	na := norm(a)
	return na != "" && na == norm(b)
}

// moduleRelativePath normalizes a module-relative path and refuses anything that
// could escape the module root.
func moduleRelativePath(p string) (string, bool) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, ":") {
		return "", false
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}
