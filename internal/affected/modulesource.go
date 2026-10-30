package affected

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
)

// EffectiveSourceResolver resolves the source the recorded build actually
// selects for one advisory entry. The analysis source index implements it: it
// owns the bound build context, the snapshot's vendor tree and the module cache
// environment, so one resolution path serves the affected chain and every
// downstream source reader.
type EffectiveSourceResolver interface {
	// ResolveModuleSource resolves one declared module coordinate against the
	// recorded build. declaredVersion is the build graph's declared coordinate
	// (needed to establish that a version-pinned replace rule applies);
	// expectedVersion is the coordinate the affected chain selected, and any
	// divergence from what the build selects is a typed contradiction.
	ResolveModuleSource(declaredModule, declaredVersion, expectedVersion string) (domain.ResolvedModuleSource, error)
}

// effectiveSources records one effective-source descriptor per advisory entry
// the recorded module graph resolved. It is the persisted input a later
// checker re-derives from, so it is built from the graph entry the chain
// actually used and then reconciled with the source resolver's answer: a
// divergence is a typed contradiction, never a silent substitution.
func (r GoResolver) effectiveSources(
	entries []domain.AffectedModule,
	modules map[*domain.AffectedModule]Module,
	versions map[*domain.AffectedModule]string,
) []domain.EffectiveSourceSelection {
	if r.Sources == nil || len(modules) == 0 {
		return nil
	}
	out := make([]domain.EffectiveSourceSelection, 0, len(modules))
	for i := range entries {
		entry := &entries[i]
		if isUnnamedEntry(*entry) || isStdlibModule(entry.Module) {
			continue
		}
		mod, ok := modules[entry]
		if !ok {
			continue
		}
		expected := versions[entry]
		if expected == "" && !mod.Main {
			// The entry stayed version-undecidable: no recorded build fact
			// selected one source. The affected chain already reports the
			// unresolved version; inventing a source here would be a new
			// claim rather than an input capture.
			continue
		}
		declared := domain.EffectiveSourceSelection{
			EntryRef:         i,
			DeclaredModule:   entry.Module,
			DeclaredVersion:  mod.Version,
			EffectiveModule:  mod.EffectivePath(),
			EffectiveVersion: expected,
		}
		if mod.Replace != nil {
			declared.Replacements = []domain.ReplaceDirective{sourceReplacement(mod)}
			if isLocalModulePath(mod.Replace.Path) {
				// A local replacement has no effective version; its identity
				// is the captured content and the replacement directory.
				declared.EffectiveModule = entry.Module
				declared.EffectiveVersion = ""
			}
		}
		resolved, err := r.Sources.ResolveModuleSource(entry.Module, mod.Version, expected)
		if err != nil {
			out = append(out, failureFallback(declared, mod, domain.ModuleSourceFailureOf(err)))
			continue
		}
		selection := resolved.Selection
		selection.EntryRef = i
		if conflict := reconcileEffectiveSource(selection, mod); conflict != "" {
			out = append(out, failureFallback(declared, mod, &domain.ModuleSourceFailure{
				Kind:   domain.ModuleSourceContradiction,
				Detail: conflict,
			}))
			continue
		}
		out = append(out, selection)
	}
	return out
}

// failureFallback renders the descriptor for an entry whose source could not be
// established. The declared/effective coordinates and the applied replacement
// stay visible; a local target is dropped because without a resolved captured
// directory it is only a filesystem location, and the typed failure already
// names the cause.
func failureFallback(declared domain.EffectiveSourceSelection, mod Module, failure *domain.ModuleSourceFailure) domain.EffectiveSourceSelection {
	declared.Failure = failure
	if mod.Replace != nil && isLocalModulePath(mod.Replace.Path) {
		declared.Replacements = nil
	}
	return declared
}

// sourceReplacement renders the graph's applied replacement in the same
// directive form the snapshot records.
func sourceReplacement(mod Module) domain.ReplaceDirective {
	old := mod.Path
	if mod.Version != "" {
		old += "@" + mod.Version
	}
	replacement := mod.Replace.Path
	if mod.Replace.Version != "" {
		replacement += "@" + mod.Replace.Version
	}
	return domain.ReplaceDirective{Old: old, New: replacement}
}

// reconcileEffectiveSource checks the resolver's selection against the recorded
// module graph entry the affected chain used. The graph — not the resolver —
// decided which implementation the advisory entry refers to, so a disagreement
// is reported as a contradiction instead of being written down as a selection.
func reconcileEffectiveSource(selection domain.EffectiveSourceSelection, mod Module) string {
	effectiveModule := mod.EffectivePath()
	wantVersion := mod.EffectiveVersion()
	if mod.Replace != nil && isLocalModulePath(mod.Replace.Path) {
		// A local replacement keeps the declared module's import paths; there
		// is no replacement version to compare against.
		effectiveModule = mod.Path
		wantVersion = ""
	}
	if mod.Main && mod.Version == "" {
		wantVersion = ""
	}
	if selection.EffectiveModule != effectiveModule {
		return fmt.Sprintf("the recorded build selects module %s, but the resolved source records %s",
			effectiveModule, selection.EffectiveModule)
	}
	if !sameEffectiveVersion(selection.EffectiveVersion, wantVersion) {
		return fmt.Sprintf("the recorded build selects %s@%s, but the resolved source records %s@%s",
			effectiveModule, wantVersion, selection.EffectiveModule, selection.EffectiveVersion)
	}
	if (mod.Replace != nil) != (len(selection.Replacements) > 0) {
		applied := "applies no replacement"
		if mod.Replace != nil {
			applied = "applies a replacement"
		}
		return fmt.Sprintf("the recorded build %s for %s, but the resolved source records %d directive(s)",
			applied, mod.Path, len(selection.Replacements))
	}
	return ""
}

// sameEffectiveVersion compares two effective coordinates; an empty version is
// only equal to another empty version.
func sameEffectiveVersion(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return sameImplementationVersion(a, b)
}
