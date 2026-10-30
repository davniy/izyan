package affected

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

// Resolver performs the cheap deterministic checks from the governing spec
// (dependency exists? -> affected version? -> package present? -> build
// relevant?) and produces evidence for each step.
type Resolver interface {
	Resolve(ctx context.Context, vuln domain.Vulnerability, product domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error)
}

type GoResolver struct {
	Tool GoTool
	// Ticket, when non-nil, carries the tracker ticket's declared
	// product/package version claims (parsed by the tracker intake).
	// The resolver compares them against the analyzed build identity
	// and the resolved package version: a declared package version that
	// differs from the resolved one blocks the version axis — no
	// "outside the affected range" negative may describe a build the
	// ticket is not about. TicketErr, when set, names why a supplied
	// ticket could not be consumed; the check degrades to NOT_CHECKED
	// with that reason recorded — never a silent pass.
	Ticket    *domain.TicketClaims
	TicketErr string
	// Sources resolves the source the recorded build actually selects for each
	// advisory entry, so the effective-source descriptor can be persisted with
	// the affected result. Nil records no descriptor: the applicability chain
	// still runs, but no source identity is claimed.
	Sources EffectiveSourceResolver
}

func (r GoResolver) Resolve(ctx context.Context, vuln domain.Vulnerability, product domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	tool := r.Tool
	if tool == nil {
		tool = ExecGoTool{}
	}
	res := domain.AffectedResult{
		Scope:                           vuln.Scope,
		ModulePresent:                   domain.ClaimUnknown,
		VersionAffected:                 domain.ClaimUnknown,
		PackagePresent:                  domain.ClaimUnknown,
		BuildRelevant:                   domain.ClaimUnknown,
		VulnerableImplementationPresent: domain.ClaimUnknown,
	}
	var ev []domain.Evidence
	add := func(e domain.Evidence) {
		e = withAudit(e, product)
		res.EvidenceIDs = append(res.EvidenceIDs, e.ID)
		ev = append(ev, e)
	}

	// The release-version axis is grounded by the snapshot's release
	// module graph (the shipped artifact's build info) when present; the
	// source go list/vendor graph is the lower-trust fallback and the
	// only graph a package/build closure probe ever uses. An explicitly
	// requested release channel that failed blocks the fallback — a
	// source version is not evidence of what shipped.
	relMods, relAuth, relStatus := ReleaseModulesFor(product)
	releaseBlocked := ReleaseVersionAxisBlocked(product)
	if re := product.ReleaseEvidence; re != nil || releaseBlocked || relAuth {
		res.ReleaseEvidenceStatus, res.ReleaseEvidenceReason = releaseStatusParts(relStatus)
		switch {
		case relAuth:
			res.VersionGraphSource = "release-artifact"
			res.VersionGraphTrust = string(domain.ReleaseTrustAuthoritative)
		case releaseBlocked:
			res.VersionGraphSource = "unavailable"
		default:
			res.VersionGraphSource = "source-snapshot"
		}
	}

	modRaw, modSource, err := tool.ListModules(ctx, product.Repository, product)
	if err != nil {
		res.ModulePresent = domain.ClaimUnknown
		message := fmt.Sprintf("go list -m failed: %v", err)
		res.Limitations = append(res.Limitations, message)
		if !relAuth {
			// A failed source module list is an input-resolution failure for
			// an artifact-owned axis; only an authoritative release graph
			// makes the failure non-blocking.
			res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerInput,
				domain.GapInputResolutionFailed, domain.ObligationModuleMembership, message))
		}
		if len(modRaw) == 0 && !relAuth {
			return res, ev, nil
		}
	}
	if len(modRaw) > 0 {
		add(domain.Evidence{
			ID:      "EV-AFFECTED-MODULES",
			Kind:    domain.EvidenceModuleGraph,
			Quality: domain.QualityDeterministic,
			Source:  modSource,
			Tool:    "go",
			Command: modSource,
			Content: string(modRaw),
		})
	}
	mods, err := DecodeModules(modRaw)
	if err != nil {
		message := fmt.Sprintf("decode module list: %v", err)
		res.Limitations = append(res.Limitations, message)
		if !relAuth {
			res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerInput,
				domain.GapInputResolutionFailed, domain.ObligationModuleMembership, message))
		}
		if !relAuth {
			return res, ev, nil
		}
	}
	if relAuth {
		content, jerr := json.Marshal(product.ReleaseModules)
		if jerr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf("encode release module graph: %v", jerr))
		} else {
			add(domain.Evidence{
				ID:      "EV-RELEASE-MODULES",
				Kind:    domain.EvidenceModuleGraph,
				Quality: domain.QualityAuthoritative,
				Source:  "release artifact build info (debug/buildinfo deps)",
				Tool:    "debug/buildinfo",
				Command: "debug/buildinfo deps",
				Content: string(content),
			})
		}
	}

	// Multi-module advisories carry alternative entries (e.g. stdlib plus
	// the vendored module shipping the same fix); the applicable one is
	// whichever module the product actually resolves. Evaluate every
	// entry's presence+version, then continue with the affected entry —
	// an unaffected alternative does not shield an affected one.
	entries := AffectedModuleEntries(vuln)
	unnamedEntries := 0
	for i := range entries {
		if isUnnamedEntry(entries[i]) {
			unnamedEntries++
			continue
		}
		res.CheckedModules = append(res.CheckedModules, entries[i].Module)
	}
	if unnamedEntries > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d advisory affected entries carry no module name: those subjects remain explicit unresolved data — they are never resolved as a module dependency, a stdlib entry, or a release toolchain subject",
			unnamedEntries))
	}
	if relAuth {
		// The release graph governs only module entries; a stdlib-only
		// advisory resolves on the toolchain axis and never touches it.
		moduleEntries := 0
		for i := range entries {
			if isUnnamedEntry(entries[i]) || isStdlibModule(entries[i].Module) {
				continue
			}
			moduleEntries++
		}
		if moduleEntries > 0 {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module-version applicability resolved against the authoritative release module graph (%d modules); the source checkout's module resolution is build/package provenance only",
				len(relMods)))
		}
	}
	var selected []*domain.AffectedModule
	var selectedModules []string
	verUnknown := false
	var pending []*domain.AffectedModule
	entryVer := map[*domain.AffectedModule]string{} // resolved version per entry
	// entryModules records the module graph entry each advisory entry was
	// resolved against, so the effective-source descriptor is built from the
	// recorded build rather than re-derived from the advisory.
	entryModules := map[*domain.AffectedModule]Module{}
	for i := range entries {
		e := &entries[i]
		if isUnnamedEntry(*e) {
			// No module identity: never resolved against a module graph,
			// the release toolchain, or a named-module field. The entry's
			// subjects are probed only to learn whether the product links
			// them; a linked subject keeps the result non-admitting below.
			pending = append(pending, e)
			continue
		}
		if isStdlibModule(e.Module) {
			// Standard library: the vulnerable version is the toolchain
			// that compiled the release — release/toolchain wins over the
			// local go, go.mod is only a minimum.
			res.ModulePresent = domain.ClaimTrue
			ver, lims := toolchainVersion(product, res.Limitations)
			res.Limitations = lims
			entryVer[e] = ver
			if normalizeVersion(ver) == "" {
				if ver != "" {
					res.Limitations = append(res.Limitations,
						fmt.Sprintf("cannot apply version ranges to toolchain version %q", ver))
				}
				verUnknown = true
				pending = append(pending, e)
				continue
			}
			selectedModules = append(selectedModules, e.Module+"@"+ver)
			if affectedByRanges(ver, e.AffectedVersions) {
				selected = append(selected, e)
			}
			continue
		}
		switch {
		case relAuth:
			// Authoritative release module graph: version membership is
			// decided by what the shipped artifact actually carries.
			mod, vers, conflict := releaseModuleVersions(relMods, e.Module)
			switch {
			case len(vers) == 0:
				continue
			case conflict:
				// Conflicting authoritative versions resolve nothing —
				// never the first or newest value. Presence itself is
				// undisputed: the graph lists the module.
				res.ModulePresent = domain.ClaimTrue
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"release module graph records conflicting versions for %s (%s); version undecidable (%s)",
					e.Module, strings.Join(vers, ", "), domain.ReleaseReasonConflict))
				verUnknown = true
				pending = append(pending, e)
				continue
			}
			res.ModulePresent = domain.ClaimTrue
			ver := vers[0]
			entryVer[e] = ver
			entryModules[e] = mod
			if mod.Replace != nil {
				res.Limitations = append(res.Limitations,
					fmt.Sprintf("module %s replaced by %s@%s in the release build", mod.Path, mod.Replace.Path, mod.Replace.Version))
			}
			selectedModules = append(selectedModules, e.Module+"@"+ver)
			if normalizeVersion(ver) == "" {
				res.Limitations = append(res.Limitations,
					fmt.Sprintf("cannot apply version ranges to unresolved version %q", ver))
				verUnknown = true
				pending = append(pending, e)
				continue
			}
			if affectedByRanges(ver, e.AffectedVersions) {
				selected = append(selected, e)
			}
		case releaseBlocked:
			// A requested release channel failed: the source graph can
			// still attest presence, but its versions are not release
			// facts, and an absent module cannot be asserted gone from
			// the release — the entry stays version-undecidable either
			// way so its packages still join the probe.
			if _, found := findModule(mods, e.Module); found {
				res.ModulePresent = domain.ClaimTrue
			}
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module %s: release version undecidable — a required release-evidence channel did not resolve (%s); the source module graph cannot substitute",
				e.Module, relStatus))
			selectedModules = append(selectedModules, e.Module+"@unresolved")
			verUnknown = true
			pending = append(pending, e)
		default:
			mod, found := findModule(mods, e.Module)
			if !found {
				continue
			}
			res.ModulePresent = domain.ClaimTrue
			entryVer[e] = mod.EffectiveVersion()
			entryModules[e] = mod
			if mod.Replace != nil {
				res.Limitations = append(res.Limitations,
					fmt.Sprintf("module %s replaced by %s@%s", mod.Path, mod.Replace.Path, mod.Replace.Version))
			}
			selectedModules = append(selectedModules, e.Module+"@"+mod.EffectiveVersion())
			if normalizeVersion(mod.EffectiveVersion()) == "" {
				res.Limitations = append(res.Limitations,
					fmt.Sprintf("cannot apply version ranges to unresolved version %q", mod.EffectiveVersion()))
				verUnknown = true
				pending = append(pending, e)
				continue
			}
			if affectedByRanges(mod.EffectiveVersion(), e.AffectedVersions) {
				selected = append(selected, e)
			}
		}
	}
	// Ticket-build identity check: runs on every path once the per-entry
	// versions are resolved (the module-absent route keeps it as
	// observability only). A declared package version that differs from
	// the resolved one refuses the "outside the affected range" negative
	// below; a product-version mismatch alone is an informational
	// ANALYZED_BUILD_MISMATCH limitation.
	ticketCheck, ticketLims := checkTicketClaims(
		vuln.ID, r.Ticket, r.TicketErr, entries, entryVer, relMods, mods)
	res.Limitations = append(res.Limitations, ticketLims...)
	res.TicketCheck = ticketCheck
	res.EffectiveSources = r.effectiveSources(entries, entryModules, entryVer)
	for _, p := range pending {
		if isUnnamedEntry(*p) {
			// Explicit unresolved data, not a module named "". It never
			// enters a module-name field; linkage is reported through the
			// package probe and the limitation above.
			continue
		}
		res.UnresolvedModules = append(res.UnresolvedModules, p.Module)
	}

	if res.ModulePresent == domain.ClaimUnknown && len(entries) > 0 && !releaseBlocked && unnamedEntries == 0 {
		// Every entry was either a module absent from the graph or a
		// stdlib check that resolved — absence of all module entries is
		// deterministic evidence of non-applicability. When a required
		// release channel is blocked, source-graph absence is not a
		// release fact: ModulePresent stays UNKNOWN. An entry without a
		// module name has no module identity to resolve, so it also keeps
		// the aggregate direction undecided.
		res.ModulePresent = domain.ClaimFalse
	}
	if res.ModulePresent == domain.ClaimFalse {
		res.VersionAffected = domain.ClaimFalse
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		return res, ev, nil
	}
	if len(selected) == 0 && !verUnknown && unnamedEntries == 0 {
		if ticketCheck != nil && len(ticketCheck.BlockedModules) > 0 {
			// The ticket declares a package version the analyzed build
			// does not resolve: the "outside the affected range" negative
			// would describe a different build than the ticket's. The
			// version axis refuses — UNKNOWN plus the named reason — and
			// the module/package-absence routes above stay untouched.
			res.VersionAffected = domain.ClaimUnknown
			res.VersionAxisBlocked = true
			res.Limitations = append(res.Limitations,
				"version axis blocked: the resolved version answers the analyzed build, not the ticket's declared package version — re-run against the build the ticket describes before an out-of-range conclusion may close")
			res.Limitations = append(res.Limitations,
				"package/build reachability was not evaluated: the version axis is blocked on the ticket's declared package version")
			for i := range entries {
				if v := entryVer[&entries[i]]; v != "" {
					res.ResolvedVersion = v
					break
				}
			}
			if len(selectedModules) > 0 {
				res.Limitations = append(res.Limitations,
					"evaluated affected-module entries: "+strings.Join(selectedModules, ", "))
			}
			return res, ev, nil
		}
		res.VersionAffected = domain.ClaimFalse
		// No package/build probe ran on this path: the resolved version is
		// outside the affected ranges of every evaluated entry, so nothing
		// about reachability was checked. ClaimFalse here would assert "the
		// affected package is absent from the import closure" — a fact that
		// was never established — and would read a fixed version as
		// component absence. Both claims stay UNKNOWN, with the reason.
		res.Limitations = append(res.Limitations,
			"package/build reachability was not evaluated: the resolved version is outside the affected ranges of every evaluated advisory entry")
		// Report the resolved version of the evaluated module — here it
		// is attributable: no pending entry exists on this path.
		for i := range entries {
			if v := entryVer[&entries[i]]; v != "" {
				res.ResolvedVersion = v
				break
			}
		}
		if len(selectedModules) > 0 {
			res.Limitations = append(res.Limitations,
				"evaluated affected-module entries: "+strings.Join(selectedModules, ", "))
		}
		return res, ev, nil
	}
	// Pending entries are module-present but version-undecidable: their
	// packages still join the probe. A pending entry's package absent
	// refutes it deterministically; present keeps the case open.
	probe := append(append([]*domain.AffectedModule{}, selected...), pending...)
	if len(selected) == 0 {
		res.VersionAffected = domain.ClaimUnknown
	} else {
		// Every version-affected entry applies to the product — probe all
		// of them: an unaffected first entry must not shield an affected
		// second one (e.g. stdlib fixed but vendored module vulnerable
		// AND imported).
		res.SelectedModule = selected[0].Module
		for _, s := range selected {
			res.SelectedModules = append(res.SelectedModules, s.Module)
			// Version-side membership survives the probe: the package
			// probe may drop an entry from SelectedModules (package
			// absent), which is a reachability result and must not be
			// read back as "version not affected".
			if !slices.Contains(res.VersionAffectedModules, s.Module) {
				res.VersionAffectedModules = append(res.VersionAffectedModules, s.Module)
			}
		}
		for _, p := range pending {
			if isUnnamedEntry(*p) {
				continue
			}
			res.SelectedModules = append(res.SelectedModules, p.Module)
		}
		res.VersionAffected = domain.ClaimTrue
	}
	if len(entries) > 1 {
		var names []string
		for _, s := range selected {
			names = append(names, s.Module)
		}
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("multi-module advisory: %d affected entries (%s; entries evaluated: %s)",
				len(probe), strings.Join(names, ", "), strings.Join(selectedModules, ", ")))
	}

	pendingSet := map[*domain.AffectedModule]bool{}
	for _, p := range pending {
		pendingSet[p] = true
	}
	// Every evaluated named entry has a settled version — none is in range
	// and none is version-undecidable — and at least one named entry's
	// version was actually resolved. A probe forced by Unnamed entries can
	// then still close the version axis as FALSE once those subjects are
	// proven unlinked; the resolved version is reported for parity with
	// the no-Unnamed path. A named entry that is merely absent from the
	// module graph resolves nothing and must not satisfy this: an advisory
	// with no resolved named version stays UNKNOWN.
	versionSettled := len(selected) == 0 && !verUnknown
	if versionSettled {
		resolvedNamedVersion := ""
		for i := range entries {
			if isUnnamedEntry(entries[i]) {
				continue
			}
			if v := entryVer[&entries[i]]; v != "" {
				resolvedNamedVersion = v
				break
			}
		}
		if resolvedNamedVersion == "" {
			versionSettled = false
		} else {
			res.ResolvedVersion = resolvedNamedVersion
		}
	}
	return resolvePackages(ctx, tool, probe, pendingSet, entryVer, versionSettled, product, res, ev)
}

// withAudit stamps the evidence with the product identity and a content
// hash — shared by every evidence-producing step of the resolver.
func withAudit(e domain.Evidence, product domain.ProductSnapshot) domain.Evidence {
	e.Repository = product.Repository
	e.Commit = product.Commit
	if e.ArtifactHash == "" && e.Content != "" {
		sum := sha256.Sum256([]byte(e.Content))
		e.ArtifactHash = hex.EncodeToString(sum[:])
	}
	return e
}

// AffectedModuleEntries returns the advisory's per-module affected entries,
// synthesizing a single entry from the flat fields for non-OSV intakes.
// Exported so the deterministic lane enumerates package-usage subjects
// from exactly the same projection the resolver probes.
func AffectedModuleEntries(vuln domain.Vulnerability) []domain.AffectedModule {
	if len(vuln.AffectedModules) > 0 {
		return vuln.AffectedModules
	}
	if vuln.Module == "" {
		return nil
	}
	pkgs := vuln.AffectedPackages
	if len(pkgs) == 0 && vuln.Package != "" {
		// Flat intake may name only the vulnerable package.
		pkgs = []domain.AffectedPackage{{Path: vuln.Package}}
	}
	return []domain.AffectedModule{{
		Module:           vuln.Module,
		AffectedVersions: vuln.AffectedVersions,
		FixedVersions:    vuln.FixedVersions,
		AffectedPackages: pkgs,
		AffectedSymbols:  vuln.AffectedSymbols,
	}}
}

// AffectedPackagesForEntry returns the entry's package-level subjects:
// the explicitly declared affected packages merged with the package
// identities carried by its affected symbols. Package presence/build
// relevance stays a linked/build-scope fact — a symbol naming a package
// only nominates it for the probe; it never asserts the product uses the
// symbol, and a symbol without a package path adds nothing.
func AffectedPackagesForEntry(
	entry domain.AffectedModule,
) []domain.AffectedPackage {
	return mergeAffectedSymbolPackages(entry.AffectedPackages, entry.AffectedSymbols)
}

// mergeAffectedSymbolPackages folds symbol package identities into the
// declared package set. A symbol whose package is already declared joins
// that package's Symbols (without duplicating it); a symbol whose package
// is absent adds a bounded package candidate. Advisory order is preserved:
// declared packages first, symbol-derived candidates in symbol order, and
// no path is ever repeated.
func mergeAffectedSymbolPackages(
	packages []domain.AffectedPackage,
	symbols []domain.SymbolRef,
) []domain.AffectedPackage {
	out := make([]domain.AffectedPackage, len(packages))
	for i, p := range packages {
		// Symbols are cloned so folding a symbol in can never write into
		// the advisory record's backing array.
		p.Symbols = append([]string(nil), p.Symbols...)
		out[i] = p
	}
	indexByPath := make(map[string]int, len(out))
	for i, p := range out {
		// The first occurrence keeps the slot — declared duplicates are
		// preserved, later symbols join that one package.
		if _, ok := indexByPath[p.Path]; !ok {
			indexByPath[p.Path] = i
		}
	}
	for _, s := range symbols {
		if s.Package == "" {
			// No package identity — never substitute the module path.
			continue
		}
		if i, ok := indexByPath[s.Package]; ok {
			if s.Symbol != "" && !slices.Contains(out[i].Symbols, s.Symbol) {
				out[i].Symbols = append(out[i].Symbols, s.Symbol)
			}
			continue
		}
		indexByPath[s.Package] = len(out)
		candidate := domain.AffectedPackage{Path: s.Package}
		if s.Symbol != "" {
			candidate.Symbols = []string{s.Symbol}
		}
		out = append(out, candidate)
	}
	return out
}

// resolvePackages finishes the affected chain: is any affected package
// imported? build relevant for the snapshot's platform? affected is the
// union of every version-affected entry's package set — a present
// package in any of them grounds presence.
func resolvePackages(ctx context.Context, tool GoTool, selected []*domain.AffectedModule,
	pendingSet map[*domain.AffectedModule]bool, entryVer map[*domain.AffectedModule]string,
	versionSettled bool, product domain.ProductSnapshot, res domain.AffectedResult,
	ev []domain.Evidence) (domain.AffectedResult, []domain.Evidence, error) {
	// Local add: res/ev here are copies — appending through the caller's
	// closure would land evidence on values that never get returned.
	add := func(e domain.Evidence) {
		e = withAudit(e, product)
		res.EvidenceIDs = append(res.EvidenceIDs, e.ID)
		ev = append(ev, e)
	}
	// pathOwner maps each probed package path back to its advisory entry —
	// a hit selects the module the downstream pipeline narrows to. A named
	// entry always owns a shared subject: duplicate subjects were merged
	// into that owner upstream, and an Unnamed entry must never re-claim
	// them even when it is probed later. Package paths are probed once.
	var affectedPaths []string
	pathOwner := map[string]*domain.AffectedModule{}
	var affectedPkgs []domain.AffectedPackage
	seenPath := map[string]bool{}
	for _, e := range selected {
		for _, p := range AffectedPackagesForEntry(*e) {
			if !seenPath[p.Path] {
				seenPath[p.Path] = true
				affectedPkgs = append(affectedPkgs, p)
				affectedPaths = append(affectedPaths, p.Path)
			}
			if prev, ok := pathOwner[p.Path]; ok {
				// Only an Unnamed owner can be displaced, and only by a
				// named entry; two named entries never trade ownership.
				if isUnnamedEntry(*prev) && !isUnnamedEntry(*e) {
					pathOwner[p.Path] = e
				}
				continue
			}
			pathOwner[p.Path] = e
		}
	}
	res.CheckedPackages = affectedPaths
	const pkgCommand = "go list -deps -test -json ./..."
	pkgRaw, listErr := tool.ListPackages(ctx, product.Repository, product)
	inventory, inventoryErr := CompletePackageInventory(pkgRaw, pkgCommand)
	completed := listErr == nil
	complete := completed && inventoryErr == nil
	buildContext := domain.EffectiveBuildContext(product)
	pkgListRun := &domain.PackageListRun{
		Completed: completed,
		Complete:  complete,
		WithTests: true,
		Pattern:   "./...",
	}
	if listErr != nil {
		pkgListRun.Error = listErr.Error()
		res.PackagePresent = domain.ClaimUnknown
		res.BuildRelevant = domain.ClaimUnknown
		message := fmt.Sprintf("go list -deps failed: %v", listErr)
		res.Limitations = append(res.Limitations, message)
		gap := affectedGap(domain.GapOwnerInput,
			domain.GapInputResolutionFailed, domain.ObligationPackagePresence, message)
		// A product whose files are all excluded by the selected build is
		// not an analysis failure: the target/build configuration that
		// decides the answer was never identified. Classify it as the
		// external fact it is, so the request reports an unresolved
		// dependency instead of a broken analyzer.
		if targetErr := domain.ValidateNegativeTarget(product); targetErr != nil &&
			isBuildExclusionError(listErr) {
			gap = affectedGap(domain.GapOwnerExternal,
				domain.GapExternalDependencyUnresolved, domain.ObligationPackagePresence,
				"the analyzed build excludes every file of the product: "+message)
			gap.External = &domain.ExternalDependency{
				MissingFact:        "the product's build target and build tags",
				AffectedObligation: domain.ObligationPackagePresence,
				BoundaryEvidenceRefs: []domain.QualifiedRef{{
					AssessmentID: domain.CaseID(pkgCommand),
					Ref:          "EV-AFFECTED-PACKAGES",
				}},
				WhyArtifactCannotSupply: "the analyzer host default is not a product build: the " +
					"artifact cannot say which supported target and tags the shipped binary uses",
				AlternativesChanging: []string{
					"a different target or tag set selects the product's files and changes every package/build measurement",
				},
				ResolvingEvidence: "declare the analyzed build (--goos/--goarch/--build-tags) or analyze the shipped binary",
			}
		}
		res.AnalysisGaps = append(res.AnalysisGaps, gap)
	} else if inventoryErr != nil {
		pkgListRun.Error = inventoryErr.Error()
	}
	if inventoryErr != nil && (listErr == nil || len(pkgRaw) > 0) {
		message := fmt.Sprintf(
			"package inventory is not a complete measurement and cannot establish absence: %v", inventoryErr)
		res.Limitations = append(res.Limitations, message)
		res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerProof,
			domain.GapMeasurementNotCompleted, domain.ObligationPackagePresence, message))
	}
	// The package list is recorded on error as well as success: downstream
	// admission reads the typed run record, never the presence of evidence.
	add(domain.Evidence{
		ID:           "EV-AFFECTED-PACKAGES",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Source:       pkgCommand,
		Tool:         "go",
		Command:      pkgCommand,
		Content:      string(pkgRaw),
		BuildContext: &buildContext,
		PackageList:  pkgListRun,
	})
	// A partial stdout may still witness a package's presence, but only a
	// completed, edge-closed inventory can ground the absence of one.
	pkgs := inventory.Packages
	if !complete {
		res.PackagePresent = domain.ClaimUnknown
		res.BuildRelevant = domain.ClaimUnknown
	}
	// The resolved version of the pre-selected entry is a module-graph
	// fact, independent of the package probe: report it even when the
	// inventory carries no usable data. Linkage-specific attribution
	// below may overwrite it.
	if res.ResolvedVersion == "" && len(selected) > 0 && !isUnnamedEntry(*selected[0]) {
		res.ResolvedVersion = entryVer[selected[0]]
	}
	if len(pkgs) == 0 {
		return res, ev, nil
	}
	var compiled map[string]bool
	var mains []string
	var isApp bool
	if complete {
		compiled, mains, isApp = analyzeCompiledScope(pkgs)
	}
	// Two independent gates for every build-dependent absence below: a
	// complete measurement and an identified product build.
	targetErr := domain.ValidateNegativeTarget(product)
	absenceAdmitted := complete && targetErr == nil

	if len(affectedPaths) == 0 {
		// The advisory declares module + version range only: no package or
		// symbol identifies a package-level subject, and the module path
		// must never be promoted into a package candidate. Absence cannot
		// normally be asserted; the only legitimate negative is the
		// existing module-level check — when the compiled scope is known,
		// the module having zero packages in it bounds the claim to that
		// recorded scope.
		res.Limitations = append(res.Limitations,
			"advisory declares module/version only; no package or symbol identifies a package-level subject")
		if versionSettled {
			// Every evaluated version is resolved and outside its range;
			// a residual Unnamed entry with no subject cannot link.
			res.VersionAffected = domain.ClaimFalse
		}
		if compiled != nil {
			pkgByPath := make(map[string]Package, len(pkgs))
			for _, p := range pkgs {
				pkgByPath[p.ImportPath] = p
			}
			moduleCompiled := false
			namedSelected := false
			namedModule := ""
			for _, sel := range selected {
				if isUnnamedEntry(*sel) {
					// No module identity and no package subject: nothing
					// to check, and no module name to report.
					continue
				}
				namedSelected = true
				if namedModule == "" {
					namedModule = sel.Module
				}
				for d := range compiled {
					if pkg, ok := pkgByPath[d]; ok && pkg.Module != nil && pkg.Module.Path == sel.Module {
						moduleCompiled = true
						break
					}
					if d == sel.Module || strings.HasPrefix(d, sel.Module+"/") {
						moduleCompiled = true
						break
					}
				}
				if moduleCompiled {
					break
				}
			}
			if namedSelected && !moduleCompiled {
				// The module has 0 packages in the compiled product
				// deliverables — but only an admitted measurement may say so.
				if !absenceAdmitted {
					res.PackagePresent = domain.ClaimUnknown
					res.BuildRelevant = domain.ClaimUnknown
					res.Limitations = append(res.Limitations,
						"module-level absence not admitted: "+absenceGateReason(targetErr, complete, inventoryErr))
					return res, ev, nil
				}
				res.PackagePresent = domain.ClaimFalse
				res.BuildRelevant = domain.ClaimFalse
				if isApp && len(mains) > 0 {
					res.Limitations = append(res.Limitations, fmt.Sprintf(
						"module %s is absent from compiled product executables (%s); used only in test scope",
						namedModule, strings.Join(mains, ", ")))
				} else {
					res.Limitations = append(res.Limitations, fmt.Sprintf(
						"module %s is absent from compiled product library packages; used only in test scope",
						namedModule))
				}
				return res, ev, nil
			}
		}

		// Compiled scope contains module packages or is unknown — package
		// presence stays undecidable rather than guessed.
		res.PackagePresent = domain.ClaimUnknown
		res.BuildRelevant = domain.ClaimUnknown
		return res, ev, nil
	}

	present := false
	testOnly := false
	confirmedLinked := false // a version-affected named entry's package is linked
	pendingLinked := false   // a version-undecidable named entry's package is linked
	unnamedLinked := false   // a linked subject owned by an Unnamed entry
	namedPathAbsent := false // an absent subject path owned by a named entry
	var confirmedOwner *domain.AffectedModule
	seenMod := map[string]bool{}
	res.SelectedModules = nil
	for _, want := range affectedPaths {
		isLinked := false
		testLinked := false
		if compiled != nil {
			if compiled[want] {
				isLinked = true
			} else if packageImported(pkgs, want) {
				testOnly = true
				testLinked = true
			}
		} else {
			if packageImported(pkgs, want) {
				isLinked = true
			}
		}
		if testLinked && !slices.Contains(res.TestOnlyScope, want) {
			res.TestOnlyScope = append(res.TestOnlyScope, want)
		}

		owner := pathOwner[want]
		if isLinked {
			present = true
			switch {
			case owner == nil:
			case isUnnamedEntry(*owner):
				unnamedLinked = true
			case pendingSet[owner]:
				pendingLinked = true
			default:
				confirmedLinked = true
				if confirmedOwner == nil {
					confirmedOwner = owner
				}
			}
			if owner == nil || isUnnamedEntry(*owner) {
				// No module name to report/index; linkage is carried by
				// the unnamedLinked decision only.
				continue
			}
			if pendingSet[owner] && !slices.Contains(res.PendingModules, owner.Module) {
				res.PendingModules = append(res.PendingModules, owner.Module)
			}
			if !seenMod[owner.Module] {
				seenMod[owner.Module] = true
				res.SelectedModules = append(res.SelectedModules, owner.Module)
			}
			continue
		}
		if owner != nil && !isUnnamedEntry(*owner) {
			// Absence of a named owner's subject is a grounded negative;
			// absence of an Unnamed subject is unresolved data.
			namedPathAbsent = true
		}
	}
	if present {
		res.PackagePresent = domain.ClaimTrue
		if unnamedLinked {
			// The linked advisory subject is in the product build even
			// though its module identity is unresolved. Asserting
			// presence here (with VersionAffected=UNKNOWN below) keeps the
			// existing version-unknown precedence in force: an unnamed
			// entry must never be admitted as a resolved module fact.
			res.ModulePresent = domain.ClaimTrue
		}
		// SelectedModule must name a linked named module; when the probe
		// links only Unnamed subjects (or none), the field stays unset
		// rather than echoing an entry that was never linked.
		res.SelectedModule = ""
		if len(res.SelectedModules) > 0 {
			res.SelectedModule = res.SelectedModules[0]
		}
		switch {
		case unnamedLinked:
			// A linked subject with no module identity cannot be resolved:
			// no module graph and no release toolchain supplies its
			// version. A named entry's verdict must not stand in for it,
			// so the case stays non-admitting. The version fields still
			// describe the selected linked named module when one exists.
			res.VersionAffected = domain.ClaimUnknown
			if confirmedLinked {
				res.SelectedModule = confirmedOwner.Module
				res.ResolvedVersion = entryVer[confirmedOwner]
			} else {
				res.ResolvedVersion = ""
			}
			res.Limitations = append(res.Limitations,
				"linked affected package(s) belong to an advisory entry with no module name; module/version applicability for those subjects cannot be resolved — VersionAffected stays UNKNOWN")
		case pendingLinked && !confirmedLinked:
			// Only version-undecidable entries are linked: the affected
			// version found on a DIFFERENT, unlinked module must not be
			// presented as proof — re-scope the version fields to what
			// was actually selected.
			res.VersionAffected = domain.ClaimUnknown
			res.ResolvedVersion = ""
			res.Limitations = append(res.Limitations,
				"linked affected package(s) belong to module(s) whose version could not be resolved; "+
					"version applicability undecided for the linked code")
		case confirmedLinked:
			// VersionAffected/ResolvedVersion describe a confirmed entry —
			// pin SelectedModule and ResolvedVersion to it so the pair
			// cannot be read as facts about a co-linked pending module.
			res.SelectedModule = confirmedOwner.Module
			res.ResolvedVersion = entryVer[confirmedOwner]
		}
	} else {
		// Package absent: keep the resolved version of the (pre-selected)
		// affected entry for reporting — SelectedModule already names it.
		// An Unnamed probed entry carries no version and must not blank a
		// version the settled-version path already reported.
		if len(selected) > 0 && !isUnnamedEntry(*selected[0]) {
			res.ResolvedVersion = entryVer[selected[0]]
		}
		// A package absent from this build can still be imported by
		// build-tag-excluded files — "not imported" then holds only for
		// the analyzed configuration, which cannot ground NOT_AFFECTED.
		// The same applies when an excluded file could not be read:
		// an unchecked file is unknown evidence, not evidence of absence.
		gated, incomplete := gatedImports(pkgs, affectedPaths)
		if len(gated) > 0 {
			res.PackagePresent = domain.ClaimUnknown
			res.BuildRelevant = domain.ClaimUnknown
			message := fmt.Sprintf(
				"affected package imported by build-constraint-excluded file(s) %s; package presence depends on build tags",
				strings.Join(gated, ", "))
			res.Limitations = append(res.Limitations, message)
			res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerInput,
				domain.GapInputResolutionFailed, domain.ObligationBuildInclusion, message))
			return res, ev, nil
		}
		if incomplete {
			res.PackagePresent = domain.ClaimUnknown
			res.BuildRelevant = domain.ClaimUnknown
			message := "build-constraint-excluded file(s) could not be parsed; affected-package presence unverified"
			res.Limitations = append(res.Limitations, message)
			res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerInput,
				domain.GapInputResolutionFailed, domain.ObligationBuildInclusion, message))
			return res, ev, nil
		}
		if namedPathAbsent && absenceAdmitted {
			res.PackagePresent = domain.ClaimFalse
			res.BuildRelevant = domain.ClaimFalse
		} else if namedPathAbsent {
			res.PackagePresent = domain.ClaimUnknown
			res.BuildRelevant = domain.ClaimUnknown
			message := "affected-package absence not admitted: " + absenceGateReason(targetErr, complete, inventoryErr)
			res.Limitations = append(res.Limitations, message)
			res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerInput,
				domain.GapInputResolutionFailed, domain.ObligationBuildInclusion, message))
			if testOnly {
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"affected package(s) %s were observed only in test scope; a test-only exclusion requires an identified product build",
					strings.Join(affectedPaths, ", ")))
			}
		} else {
			// Only Unnamed subjects were probed and none linked. That is
			// unresolved subject data, not a component-absence negative —
			// and an incomplete inventory establishes no linkage at all.
			res.PackagePresent = domain.ClaimUnknown
			res.BuildRelevant = domain.ClaimUnknown
			if complete {
				// A versionSettled named entry can still close the version
				// axis below on its own resolved version.
				res.Limitations = append(res.Limitations,
					"advisory subject(s) with no module name are absent from the compiled product scope; because the entry carries no module identity, that absence does not ground a deterministic component negative")
			} else {
				res.Limitations = append(res.Limitations,
					"advisory subject(s) with no module name could not be located: the package inventory is not a completed, complete measurement, so their linkage is unverified")
			}
		}
		if versionSettled {
			// No named entry is version-affected or version-undecidable,
			// and the probe proved every remaining (Unnamed) subject
			// unlinked: no applicable subject exists in this build. That
			// closure depends on the probe's absence finding, so it is
			// admitted only with a complete inventory under an identified
			// product build — a resolved out-of-range version alone stays
			// independent (handled on the early-return paths above).
			if absenceAdmitted {
				res.VersionAffected = domain.ClaimFalse
			} else {
				message := "version-unaffected conclusion withheld: it depends on affected-subject absence that this measurement cannot establish (" +
					absenceGateReason(targetErr, complete, inventoryErr) + ")"
				res.Limitations = append(res.Limitations, message)
				res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerProof,
					domain.GapMeasurementNotCompleted, domain.ObligationVersionRange, message))
			}
		}
		if namedPathAbsent && absenceAdmitted {
			if testOnly {
				if isApp && len(mains) > 0 {
					res.Limitations = append(res.Limitations, fmt.Sprintf(
						"affected package(s) %s absent from compiled product executables (%s); used only in test scope",
						strings.Join(affectedPaths, ", "), strings.Join(mains, ", ")))
				} else {
					res.Limitations = append(res.Limitations, fmt.Sprintf(
						"affected package(s) %s absent from compiled product scope; used only in test scope",
						strings.Join(affectedPaths, ", ")))
				}
			} else {
				res.Limitations = append(res.Limitations,
					"package set derived from go list -deps; dynamically loaded plugins are not covered")
			}
		}
		return res, ev, nil
	}

	res.BuildRelevant = buildRelevant(affectedPkgs, product)
	if res.BuildRelevant == domain.ClaimFalse && targetErr != nil {
		// A platform-restriction FALSE compares the advisory's declared
		// GOOS/GOARCH with the analyzed build: under a host default that is
		// a statement about the analyzer, not the product.
		res.BuildRelevant = domain.ClaimUnknown
		message := fmt.Sprintf("build relevance withheld: %v", targetErr)
		res.Limitations = append(res.Limitations, message)
		res.AnalysisGaps = append(res.AnalysisGaps, affectedGap(domain.GapOwnerInput,
			domain.GapInputResolutionFailed, domain.ObligationBuildInclusion, message))
	}
	return res, ev, nil
}

// affectedGap records a producer-side typed cause. The assessment id is bound
// by the workflow once the case identity is known; classification never reads
// the message text.
// isBuildExclusionError reports whether the loader rejected the product
// because the selected build selects no files for it — a target/configuration
// mismatch, not a defect in the product or the analyzer.
func isBuildExclusionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "build constraints exclude all Go files") ||
		strings.Contains(msg, "no Go files in")
}

func affectedGap(owner domain.GapOwner, code domain.GapCode, obligation domain.Obligation,
	message string) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:      owner,
		Code:       code,
		Obligation: obligation,
		Message:    message,
	}
}

// absenceGateReason names exactly which admission gate a build-dependent
// absence conclusion failed. The measurement gate comes first (a completed,
// edge-closed inventory); the target gate follows (a valid, scoped product
// target matching the effective build).
func absenceGateReason(targetErr error, complete bool, inventoryErr error) string {
	if !complete {
		if inventoryErr != nil {
			return fmt.Sprintf("the package inventory is not a completed, complete measurement: %v", inventoryErr)
		}
		return "the package list did not complete"
	}
	if targetErr != nil {
		return "the measurement does not describe an identified product build: " + targetErr.Error()
	}
	return "measurement admission failed"
}

// analyzeCompiledScope discovers the production scope of the product:
// 1. If real production `package main` executables exist, the compiled scope is
// the union of their transitive dependencies (.Deps) + the mains themselves.
// 2. If no `package main` exists, the product is a library. Its compiled scope is
// the union of dependencies of all non-test packages belonging to the product.
func analyzeCompiledScope(pkgs []Package) (map[string]bool, []string, bool) {
	var mains []string
	pkgByPath := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		pkgByPath[p.ImportPath] = p
		// Production main: Name == "main", not DepOnly, not a synthetic test binary ending in ".test", and ForTest == "".
		if p.Name == "main" && !p.DepOnly && !strings.HasSuffix(p.ImportPath, ".test") && p.ForTest == "" {
			mains = append(mains, p.ImportPath)
		}
	}
	if len(mains) > 0 {
		compiled := make(map[string]bool)
		for _, m := range mains {
			compiled[m] = true
			if p, ok := pkgByPath[m]; ok {
				for _, d := range p.Deps {
					compiled[d] = true
				}
			}
		}
		return compiled, mains, true
	}
	// Library module: check non-test product packages that have Deps populated
	libPkgs := make([]string, 0)
	hasDepsInfo := false
	for _, p := range pkgs {
		if !p.DepOnly && !strings.HasSuffix(p.ImportPath, ".test") && p.ForTest == "" && !isTestPath(p.ImportPath) {
			libPkgs = append(libPkgs, p.ImportPath)
			if len(p.Deps) > 0 {
				hasDepsInfo = true
			}
		}
	}
	if len(libPkgs) > 0 && hasDepsInfo {
		compiled := make(map[string]bool)
		for _, lp := range libPkgs {
			compiled[lp] = true
			if p, ok := pkgByPath[lp]; ok {
				for _, d := range p.Deps {
					compiled[d] = true
				}
			}
		}
		return compiled, nil, false
	}
	return nil, nil, false
}

func isTestPath(path string) bool {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "test" || part == "tests" || part == "testdata" || strings.HasSuffix(part, "test-helpers") {
			return true
		}
	}
	return false
}

// isUnnamedEntry reports whether an advisory entry lacks a module identity.
// The parser's contract is Module == "" iff Unnamed, but the resolver
// refuses an empty name even without the marker: an empty string is never a
// module path, so it must never reach findModule, releaseModuleVersions, the
// stdlib branch, or any result module-name field.
func isUnnamedEntry(e domain.AffectedModule) bool {
	return e.Unnamed || e.Module == ""
}

// isStdlibModule reports whether the advisory's module is one of the
// explicitly supported Go standard-library/toolchain pseudo-modules — such
// advisories apply to the release toolchain version, not to a module
// dependency. Classification is exact identity: an empty module name or a
// dot-less third-party path ("example", "example/module") is never stdlib,
// because a broad shape heuristic would route unnamed or malformed entries
// into the release-toolchain branch.
func isStdlibModule(module string) bool {
	switch module {
	case "std", "stdlib", "toolchain", "cmd":
		return true
	}
	return false
}

// toolchainVersion picks the version the stdlib advisory applies to — the
// toolchain that built the release (--release-go-version, --binary build
// info or discovered release evidence). go.mod declares only a minimum and
// the local toolchain is the analysis environment, not the artifact: when
// no release version is recorded the entry stays unresolved ("") instead
// of silently adopting either one.
func toolchainVersion(product domain.ProductSnapshot, lims []string) (string, []string) {
	if v := product.ReleaseGoVersion; v != "" {
		return v, lims
	}
	if product.ReleaseEvidence != nil || product.ReleaseEvidenceRequired {
		// A recorded release-evidence outcome names why no authoritative
		// toolchain exists (supporting-only, conflicted, or a failed
		// requested channel) — keep the named toolchain-axis status rather
		// than a bare unknown. The module-axis status must not be reused
		// here: an authoritative release module graph leaves the toolchain
		// UNKNOWN and that outcome must stay readable.
		return "", append(lims, fmt.Sprintf(
			"release toolchain unresolved (%s): no authoritative toolchain version; supporting declarations and go.mod cannot ground stdlib applicability",
			releaseToolchainStatus(product)))
	}
	return "", append(lims,
		"release toolchain unknown: stdlib applicability cannot be resolved from go.mod or the analysis toolchain; pass --release-go-version or --binary")
}

// releaseStatusParts splits a composed "STATUS/REASON" axis string into
// its status and reason components.
func releaseStatusParts(composed string) (status, reason string) {
	if i := strings.IndexByte(composed, '/'); i >= 0 {
		return composed[:i], composed[i+1:]
	}
	return composed, ""
}

func findModule(mods []Module, path string) (Module, bool) {
	for _, m := range mods {
		if m.Path == path || m.EffectivePath() == path {
			return m, true
		}
	}
	return Module{}, false
}

func affectedPackagePaths(pkgs []domain.AffectedPackage) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Path)
	}
	return out
}

func packageImported(pkgs []Package, path string) bool {
	for _, p := range pkgs {
		if p.ImportPath == path {
			return true
		}
	}
	return false
}

// gatedImports returns the product files excluded by build constraints
// whose import lists name an affected package, plus whether any excluded
// file could not be inspected (unreadable/unparseable — an unknown, not
// an absence). Only non-DepOnly (product root) packages carry
// IgnoredGoFiles; dependency internals are irrelevant — a dep's own gated
// files do not change whether the product links the affected package.
func gatedImports(pkgs []Package, affected []string) ([]string, bool) {
	var found []string
	incomplete := false
	for _, p := range pkgs {
		if p.DepOnly || p.Dir == "" || len(p.IgnoredGoFiles) == 0 {
			continue
		}
		for _, f := range p.IgnoredGoFiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := parser.ParseFile(token.NewFileSet(),
				filepath.Join(p.Dir, f), nil, parser.ImportsOnly)
			if err != nil {
				incomplete = true
				continue
			}
			for _, imp := range src.Imports {
				path, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					incomplete = true
					continue
				}
				for _, want := range affected {
					if path == want {
						found = append(found, p.ImportPath+":"+f)
					}
				}
			}
		}
	}
	return found, incomplete
}

// buildRelevant checks GOOS/GOARCH restrictions declared per affected import.
// A package constrained to other platforms cannot ship vulnerable code in
// this snapshot's binaries.
func buildRelevant(pkgs []domain.AffectedPackage, product domain.ProductSnapshot) domain.ClaimResult {
	relevant := false
	constrained := false
	for _, p := range pkgs {
		if len(p.GOOS) == 0 && len(p.GOARCH) == 0 {
			relevant = true
			continue
		}
		constrained = true
		if matchPlatform(product.GOOS, p.GOOS) && matchPlatform(product.GOARCH, p.GOARCH) {
			relevant = true
		}
	}
	if !constrained {
		return domain.ClaimTrue
	}
	if relevant {
		return domain.ClaimTrue
	}
	return domain.ClaimFalse
}

func matchPlatform(have string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == have {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Implementation-presence axis (G2)
// ---------------------------------------------------------------------------

// ImplementationAxisInput is the deterministic input set for the affected
// chain's implementation-presence dimension. Every member except the
// proposals is a recorded fact; the proposals are admitted LLM hypotheses
// whose only role is to name a locus the verifier can prove or fail to
// prove.
type ImplementationAxisInput struct {
	// Proposals are the admitted (shape/quality/advisory-bound)
	// implementation-locus proposals for this advisory. The axis NEVER
	// consumes unadmitted agent output.
	Proposals []domain.ImplementationLocusProposal
	// Entries are the advisory's per-module affected entries; the
	// proposal's module selects exactly one.
	Entries []domain.AffectedModule
	// Affected is the resolver's chain result. ModulePresent and
	// VersionAffected must already be TRUE; PackagePresent and
	// BuildRelevant are established for the proposal's package by this
	// axis when they are still UNKNOWN.
	Affected domain.AffectedResult
	// Build is the recorded snapshot, including Target provenance.
	Build domain.ProductSnapshot
	// SnapshotRoot and SnapshotContentHash bind the verifier to the exact
	// source tree.
	SnapshotRoot        string
	SnapshotContentHash string
	// AdvisoryID and its digests/bytes bind the proposal's advisory
	// reference and verbatim quote to the frozen advisory.
	AdvisoryID              string
	AdvisorySHA256          string
	AdvisoryCanonicalSHA256 string
	AdvisoryBytes           []byte
	// Assumptions is the declared-assumptions/1 channel record. The
	// axis requires an admissible supported-targets member covering the
	// product scope; no other input can substitute.
	Assumptions *domain.DeclaredAssumptionsInput
	// Tool runs the product package probe that establishes the proposed
	// package's presence and build relevance. Required.
	Tool GoTool
	// Now is the assumption-admission clock (zero means time.Now).
	Now time.Time
}

// ImplementationAxisResult is the axis decision plus everything the
// caller needs to record it: the finalized affected result (axis,
// established package/build facts, target provenance, assumption ids,
// limitations), the deterministic evidence, and every per-proposal
// verification for the audit trail.
type ImplementationAxisResult struct {
	Present       domain.ClaimResult
	Reason        string
	Affected      domain.AffectedResult
	Target        *domain.ProductTarget
	TargetScope   string
	AssumptionIDs []string
	Modules       []string
	Locus         string
	Verifications []ImplementationVerification
	Evidence      []domain.Evidence
	Limitations   []string
}

// EvaluateImplementationAxis decides the affected chain's
// vulnerable_implementation_present dimension. The axis may be FALSE only
// when all of the following hold:
//
//   - module presence and version-in-range are established;
//   - the recorded build target is authoritative artifact/release
//     evidence or an explicit operator declaration — never the host
//     default;
//   - an admitted supported-targets assumption covers the product scope
//     and names exactly the recorded GOOS/GOARCH/build-tag set;
//   - the proposed package is in the compiled product scope and is build
//     relevant under that target;
//   - every admitted proposal verifies VERIFIED_ABSENT (a selected
//     proposed/alternate implementation carrying the marker, or any
//     unknown check, blocks closure).
//
// A FALSE here is an affected-chain applicability result, not an
// exploit-path falsifier: the vulnerable implementation is not part of
// the product build.
func EvaluateImplementationAxis(ctx context.Context, in ImplementationAxisInput) ImplementationAxisResult {
	out := ImplementationAxisResult{
		Present:  domain.ClaimUnknown,
		Affected: in.Affected,
	}
	fail := func(reason string, lims ...string) ImplementationAxisResult {
		out.Reason = reason
		out.Limitations = append(out.Limitations, lims...)
		out.Affected.Limitations = append(out.Affected.Limitations, lims...)
		out.Affected.VulnerableImplementationPresent = domain.ClaimUnknown
		return out
	}
	if len(in.Proposals) == 0 {
		return fail("implementation presence is undecidable: no admitted implementation-locus proposal was supplied")
	}
	if in.Affected.ModulePresent != domain.ClaimTrue || in.Affected.VersionAffected != domain.ClaimTrue {
		return fail(fmt.Sprintf(
			"implementation presence is undecidable: module_present=%s version_affected=%s — the proposal verifier requires an established affected component",
			in.Affected.ModulePresent, in.Affected.VersionAffected))
	}
	if ctx == nil {
		return fail("implementation presence is undecidable: no execution context")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	target, scope, assumptionIDs, gateReason, gateLims := implementationTargetScope(in.Build, in.Assumptions, now)
	out.AssumptionIDs = assumptionIDs
	out.Limitations = append(out.Limitations, gateLims...)
	if gateReason != "" {
		out.Affected.AssumptionIDs = mergeAssumptionIDs(out.Affected.AssumptionIDs, assumptionIDs)
		out.Affected.Limitations = append(out.Affected.Limitations, gateLims...)
		out.Affected.VulnerableImplementationPresent = domain.ClaimUnknown
		out.Reason = gateReason
		return out
	}
	out.Target = target
	out.TargetScope = scope
	effectiveBuild := domain.BuildTargetSnapshot(in.Build, *target)

	if in.Tool == nil {
		return fail("implementation presence is undecidable: no package probe tool is configured")
	}
	dir := effectiveBuild.Repository
	if dir == "" {
		dir = in.SnapshotRoot
	}
	raw, err := in.Tool.ListPackages(ctx, dir, effectiveBuild)
	if err != nil {
		return fail("implementation presence is undecidable: the product package probe failed: " + err.Error())
	}
	pkgs, err := CompletePackageInventory(raw, "go list -deps -test -json ./...")
	if err != nil {
		return fail("implementation presence is undecidable: the product package probe is not a complete inventory: " + err.Error())
	}
	probeBuildContext := domain.EffectiveBuildContext(effectiveBuild)
	probeEvidence := withAudit(domain.Evidence{
		ID:           "EV-IMPL-AXIS-PACKAGES",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Source:       "go list -deps -test -json ./... (implementation-axis package probe)",
		Tool:         "go",
		Command:      "go list -deps -test -json ./...",
		Content:      string(raw),
		BuildContext: &probeBuildContext,
		PackageList: &domain.PackageListRun{
			Completed: true,
			Complete:  true,
			WithTests: true,
			Pattern:   "./...",
		},
	}, in.Build)
	out.Evidence = append(out.Evidence, probeEvidence)

	compiled, _, _ := analyzeCompiledScope(pkgs.Packages)
	probes := map[string]implementationPackageProbe{}
	probe := func(pkgPath string) implementationPackageProbe {
		if p, ok := probes[pkgPath]; ok {
			return p
		}
		p := implementationPackageProbe{Package: pkgPath}
		present := false
		if compiled != nil {
			present = compiled[pkgPath]
		} else {
			present = packageImported(pkgs.Packages, pkgPath)
		}
		if present {
			// go list ran under the recorded target's environment, so a
			// package in the compiled product closure has selected build
			// inputs. The verifier re-checks the package directory and
			// fails closed to UNKNOWN if no selected source exists.
			p.Present = true
			p.BuildRelevant = true
			p.Detail = "package is in the compiled product closure under the recorded target"
		} else {
			p.Detail = "package is not in the compiled product closure under the recorded target"
		}
		probes[pkgPath] = p
		return p
	}

	absent, present, unknownCount := 0, 0, 0
	for _, proposal := range in.Proposals {
		entry, ok := implementationEntryForModule(in.Entries, proposal.Module)
		if !ok {
			unknownCount++
			out.Verifications = append(out.Verifications, ImplementationVerification{
				Status:          ImplementationVerificationUnknown,
				Reason:          fmt.Sprintf("proposal module %q does not resolve to exactly one advisory affected entry", proposal.Module),
				ProposalID:      proposal.ID,
				ProposalQuality: proposal.Quality,
				Module:          proposal.Module,
				Version:         proposal.Version,
				Package:         proposal.Package,
			})
			continue
		}
		p := probe(proposal.Package)
		af := in.Affected
		if p.Present && p.BuildRelevant {
			// Establish the proposed package's presence/build relevance
			// for the verifier. BuildRelevant keeps its advisory/package
			// platform-restriction meaning: the probe established that
			// this package is part of the recorded build, not that a
			// vulnerable implementation is present.
			af.PackagePresent = domain.ClaimTrue
			af.BuildRelevant = domain.ClaimTrue
			if !slices.Contains(af.CheckedPackages, proposal.Package) {
				af.CheckedPackages = append(af.CheckedPackages, proposal.Package)
			}
			probeLim := fmt.Sprintf(
				"advisory subject was proposal-derived: package %s presence/build relevance was established by the implementation-axis probe, not by an advisory-declared package entry", proposal.Package)
			af.Limitations = append(af.Limitations, probeLim)
			out.Affected.Limitations = append(out.Affected.Limitations, probeLim)
			out.Affected.PackagePresent = domain.ClaimTrue
			out.Affected.BuildRelevant = domain.ClaimTrue
			if !slices.Contains(out.Affected.CheckedPackages, proposal.Package) {
				out.Affected.CheckedPackages = append(out.Affected.CheckedPackages, proposal.Package)
			}
		}
		v := VerifyImplementationLocus(ctx, ImplementationVerificationInput{
			Proposal:                proposal,
			AffectedEntry:           entry,
			Affected:                af,
			Build:                   effectiveBuild,
			SnapshotRoot:            in.SnapshotRoot,
			SnapshotContentHash:     in.SnapshotContentHash,
			AdvisoryID:              in.AdvisoryID,
			AdvisorySHA256:          in.AdvisorySHA256,
			AdvisoryCanonicalSHA256: in.AdvisoryCanonicalSHA256,
			AdvisoryBytes:           in.AdvisoryBytes,
		})
		out.Verifications = append(out.Verifications, v)
		out.Evidence = append(out.Evidence, v.Evidence...)
		if !slices.Contains(out.Modules, proposal.Module) {
			out.Modules = append(out.Modules, proposal.Module)
		}
		switch v.Status {
		case ImplementationVerifiedPresent:
			present++
		case ImplementationVerifiedAbsent:
			absent++
			if out.Locus == "" {
				out.Locus = implementationLocusLabel(v)
			}
		default:
			unknownCount++
		}
	}

	out.Affected.AssumptionIDs = mergeAssumptionIDs(out.Affected.AssumptionIDs, assumptionIDs)
	out.Affected.ImplementationTarget = target.Platform()
	out.Affected.ImplementationTargetScope = scope
	out.Affected.ImplementationTargetSource = target.Source
	out.Affected.ImplementationModules = append([]string(nil), out.Modules...)
	out.Affected.Limitations = append(out.Affected.Limitations, out.Limitations...)
	out.Affected.Limitations = append(out.Affected.Limitations,
		"vulnerable_implementation_present is derived from admitted LLM-inferred locus proposals re-checked deterministically; the proposals themselves are never evidence and never a verdict")

	switch {
	case present > 0:
		out.Present = domain.ClaimTrue
		out.Reason = fmt.Sprintf(
			"a selected implementation under the recorded target %s carries the vulnerable marker — absence is blocked", target.Platform())
	case unknownCount > 0 || absent == 0:
		out.Present = domain.ClaimUnknown
		out.Reason = "implementation presence is undecidable: at least one admitted proposal did not verify deterministically"
	default:
		out.Present = domain.ClaimFalse
		out.Reason = fmt.Sprintf(
			"vulnerable implementation %s is deterministically absent from the product build target %s under the product supported-target scope (assumption %s)",
			out.Locus, target.Platform(), strings.Join(assumptionIDs, ", "))
	}
	out.Affected.VulnerableImplementationPresent = out.Present
	if out.Present == domain.ClaimFalse {
		out.Affected.ImplementationLocus = out.Locus
	} else {
		out.Affected.ImplementationLocus = ""
	}
	return out
}

// implementationPackageProbe records the product-closure probe for one
// proposal package.
type implementationPackageProbe struct {
	Package       string
	Present       bool
	BuildRelevant bool
	Detail        string
}

// implementationEntryForModule selects the single advisory entry a
// proposal names. Zero or multiple matches fail closed.
func implementationEntryForModule(entries []domain.AffectedModule, module string) (domain.AffectedModule, bool) {
	var found domain.AffectedModule
	n := 0
	for _, e := range entries {
		if e.Module == module {
			found = e
			n++
		}
	}
	return found, n == 1
}

// implementationTargetScope enforces the target-scope gate. It returns the
// effective recorded target and the scope the conclusion may claim.
// Product-wide closure requires an admitted supported-targets assumption
// whose complete matrix names exactly the recorded single target; an
// artifact-scoped member is reported but can never close the axis.
func implementationTargetScope(build domain.ProductSnapshot, assumptions *domain.DeclaredAssumptionsInput, now time.Time) (target *domain.ProductTarget, scope string, assumptionIDs []string, reason string, lims []string) {
	rec := build.Target
	if rec == nil {
		return nil, "", nil, "implementation presence is undecidable: the snapshot carries no recorded build target", nil
	}
	if err := rec.Validate(); err != nil {
		return nil, "", nil, "implementation presence is undecidable: the recorded build target is malformed: " + err.Error(), nil
	}
	if !rec.Scoped() {
		return nil, "", nil, fmt.Sprintf(
				"implementation presence is undecidable: the build target is the analyzer host default (%s); host facts never ground an implementation conclusion",
				rec.Platform()), []string{
				"a host-default target is analysis context only — acquire the artifact build info, release-metadata target facts, or explicit --goos/--goarch operator facts",
			}
	}
	admitted, err := domain.AdmitAssumption(assumptions, domain.AssumptionSupportedTargets,
		domain.AssumptionScopeProduct, now)
	if err != nil {
		lims = append(lims, "product-scope supported-targets admission failed: "+err.Error())
		if a, aerr := domain.AdmitAssumption(assumptions, domain.AssumptionSupportedTargets,
			domain.AssumptionScopeArtifact, now); aerr == nil {
			assumptionIDs = []string{a.ID}
			lims = append(lims, fmt.Sprintf(
				"artifact-scoped supported-targets assumption %s describes one artifact and cannot close a product-wide implementation conclusion", a.ID))
		}
		return nil, "", assumptionIDs, "implementation presence is undecidable: an admissible product-scope supported-targets assumption is required", lims
	}
	assumptionIDs = []string{admitted.ID}
	if admitted.Targets == nil {
		return nil, "", assumptionIDs, "implementation presence is undecidable: the admitted supported-targets assumption carries no target matrix", lims
	}
	ts := *admitted.Targets
	if len(ts.GOOS) != 1 {
		return nil, "", assumptionIDs, fmt.Sprintf(
			"implementation presence is undecidable: the product target matrix names %d GOOS values; this bounded axis verifies one recorded build target and cannot close a multi-target product scope",
			len(ts.GOOS)), lims
	}
	if len(ts.GOARCH) != 1 {
		return nil, "", assumptionIDs, fmt.Sprintf(
			"implementation presence is undecidable: the product target matrix must name exactly one GOARCH (found %d); per-architecture implementation verification is outside this bound",
			len(ts.GOARCH)), lims
	}
	if err := domain.TargetScopeMatch(*rec, ts); err != nil {
		return nil, "", assumptionIDs, "implementation presence is undecidable: the recorded build target does not match the declared product target scope: " + err.Error(), lims
	}
	if rec.Source == domain.ProductTargetSourceOperatorDeclared {
		lims = append(lims,
			"operator-declared target carries no build-info CGO_ENABLED fact; CGO_ENABLED=false is the declared analysis build configuration")
	}
	return rec, domain.AssumptionScopeProduct, assumptionIDs, "", lims
}

// implementationLocusLabel renders the verified locus for the verdict
// reason. Every component comes from the deterministic verification
// result, never from the raw proposal.
func implementationLocusLabel(v ImplementationVerification) string {
	label := v.Package + "/" + v.File
	if v.Function != "" {
		label += " " + v.Function
	}
	label += fmt.Sprintf(" (marker %q, //go:build %s)", v.Marker, v.BuildExpression)
	return label
}

// mergeAssumptionIDs appends ids not already present, preserving order.
func mergeAssumptionIDs(dst, ids []string) []string {
	for _, id := range ids {
		if id != "" && !slices.Contains(dst, id) {
			dst = append(dst, id)
		}
	}
	return dst
}
