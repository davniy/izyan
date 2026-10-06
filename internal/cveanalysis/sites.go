package cveanalysis

import (
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// AffectedPackagePaths returns every package path the advisory names —
// the primary AffectedPackages plus all per-module entries — deduplicated.
// It is the known-package set NormalizeSite splits legacy dotted site
// references against.
func AffectedPackagePaths(v domain.Vulnerability) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range v.AffectedPackages {
		add(p.Path)
	}
	for _, am := range v.AffectedModules {
		for _, p := range am.AffectedPackages {
			add(p.Path)
		}
	}
	return out
}

// NormalizeSite converts a raw LLM site reference into a typed symbol.
// Two spellings are accepted:
//
//	"<package> <symbol>"            — the space-separated form the
//	                                 researcher emits (trusted directly);
//	"<package>.<symbol>"            — legacy dotted form, split ONLY at a
//	                                 known package prefix, longest first.
//
// The symbol part may be "Func", "Type.Method" or "(*Type).Method".
// Anything else — a bare dotted string whose prefix is not a declared
// package, extra whitespace-separated tokens, an empty side — is
// ambiguous and reported as unresolved: a last-dot split of an import
// path containing dots ("gopkg.in/yaml.v2.Decoder.Decode" with no known
// package) would fabricate a package boundary that never existed.
func NormalizeSite(raw string, packages []string) (domain.SymbolRef, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return domain.SymbolRef{}, false
	}
	if !strings.ContainsAny(raw, " \t") {
		if ref, ok := splitAtPackage(raw, packages); ok {
			return ref, true
		}
		return domain.SymbolRef{}, false
	}
	parts := strings.Fields(raw)
	if len(parts) == 2 && validSymbolPart(parts[1]) {
		return domain.SymbolRef{Package: parts[0], Symbol: parts[1]}, true
	}
	if ref, ok := splitAtPackage(raw, packages); ok {
		return ref, true
	}
	return domain.SymbolRef{}, false
}

// splitAtPackage resolves "<pkg>.<rest>" only when pkg is exactly one of
// the known package paths — longest match wins so nested packages are
// not truncated at a parent prefix.
func splitAtPackage(raw string, packages []string) (domain.SymbolRef, bool) {
	best := domain.SymbolRef{}
	found := false
	for _, pkg := range packages {
		if pkg == "" || !strings.HasPrefix(raw, pkg+".") {
			continue
		}
		rest := strings.TrimPrefix(raw, pkg+".")
		if !validSymbolPart(rest) {
			continue
		}
		if !found || len(pkg) > len(best.Package) {
			best = domain.SymbolRef{Package: pkg, Symbol: rest}
			found = true
		}
	}
	return best, found
}

// validSymbolPart reports whether s looks like a Go symbol reference:
// non-empty, no spaces, no "/" (a slash would mean the package boundary
// landed inside the symbol — never a valid normalization).
func validSymbolPart(s string) bool {
	return s != "" && !strings.ContainsAny(s, " \t/")
}
