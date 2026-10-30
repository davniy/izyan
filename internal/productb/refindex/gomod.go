package refindex

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// moduleBinding captures the go.mod/vendor facts the usage strata need:
// the product's own module path, the required module set and the replace
// directives that rewrite binding to ambiguous or forked code.
type moduleBinding struct {
	// ModulePath is the product's primary module path ("" = not a Go
	// module root — every binding check then degrades honestly).
	ModulePath string
	// Requires maps required module path -> declared version.
	Requires map[string]string
	// Replaces lists replace directives in go.mod order.
	Replaces []replaceRule
	// VendorMode is true when vendor/modules.txt exists and lists the
	// module — the build links the checked-in vendor copy.
	VendorMode bool
	// Vendored maps vendored module path -> vendored annotation ("" or
	// the "=> <target>" spelling modules.txt records for replaces).
	Vendored map[string]string
	// ParseErr records a go.mod read/parse failure; callers surface it as
	// a limitation and treat every module as unverifiable.
	ParseErr error
	// Dir is the snapshot root, used for fork-copy directory probes.
	Dir string
}

// replaceRule is one parsed `replace old [v] => new [v]` directive.
type replaceRule struct {
	oldPath string
	oldVer  string
	newPath string
	newVer  string
}

// local reports whether the replacement target is a filesystem path
// (./, ../ or /…) rather than another module version.
func (r replaceRule) local() bool {
	return isFilesystemPath(r.newPath)
}

// isFilesystemPath mirrors go.mod semantics: replacement targets starting
// with a dot or a path separator are directories, not module paths.
func isFilesystemPath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") ||
		strings.HasPrefix(p, "/") || strings.HasPrefix(p, ".\\") ||
		strings.HasPrefix(p, "..\\") || strings.HasPrefix(p, `\`) ||
		p == "." || p == ".."
}

// readModuleBinding parses the snapshot's go.mod and vendor/modules.txt.
// Missing go.mod yields an empty binding (not an error): the snapshot may
// be a GOPATH-era tree; every check then degrades to its unknown branch.
func readModuleBinding(dir string) moduleBinding {
	mb := moduleBinding{
		Requires: map[string]string{},
		Vendored: map[string]string{},
		Dir:      dir,
	}
	gomod := filepath.Join(dir, "go.mod")
	b, err := os.ReadFile(gomod)
	if err != nil {
		if !os.IsNotExist(err) {
			mb.ParseErr = err
		}
		return mb
	}
	f, err := modfile.Parse(gomod, b, nil)
	if err != nil {
		mb.ParseErr = err
		return mb
	}
	if f.Module != nil {
		mb.ModulePath = f.Module.Mod.Path
	}
	for _, r := range f.Require {
		mb.Requires[r.Mod.Path] = r.Mod.Version
	}
	for _, r := range f.Replace {
		mb.Replaces = append(mb.Replaces, replaceRule{
			oldPath: r.Old.Path, oldVer: r.Old.Version,
			newPath: r.New.Path, newVer: r.New.Version,
		})
	}
	mb.readVendorModules(dir)
	return mb
}

// readVendorModules parses vendor/modules.txt: "# <path> <version>" lines
// name vendored modules; "## explicit" markers and "=>" annotations carry
// replace information. Only module presence matters for the strata.
func (mb *moduleBinding) readVendorModules(dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "vendor", "modules.txt"))
	if err != nil {
		return
	}
	// modules.txt exists: the build links the vendor tree (`go` auto-
	// selects -mod=vendor for go >= 1.14 modules), regardless of how many
	// module entries we can parse out of it.
	mb.VendorMode = true
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "# "))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		path := fields[0]
		// modules.txt replace annotations: "# old v1 => new v2" and
		// "# old => ./dir" forms — the vendored module is the new side.
		if i := indexOf(fields, "=>"); i > 0 {
			if i+1 < len(fields) {
				mb.Vendored[fields[i+1]] = line
				mb.Vendored[fields[0]] = line
			}
			continue
		}
		mb.Vendored[path] = line
	}
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// moduleInGraph reports whether the advisory module is bound by the
// product's module graph: a go.mod require, a vendor/modules.txt entry, or
// a replace directive naming it. This — not ProductUsage.Present — is the
// only admissible basis for a not_present verdict: Present reflects the
// loaded source closure, which can omit transitive dependency-internal
// packages whose module is very much in the build.
func (mb moduleBinding) moduleInGraph(m, ver string) bool {
	if _, ok := mb.Requires[m]; ok {
		return true
	}
	if mb.VendorMode {
		if _, ok := mb.Vendored[m]; ok {
			return true
		}
	}
	return mb.replacementFor(m, ver) != nil
}

// requiredVersion returns the required version of module path m.
func (mb moduleBinding) requiredVersion(m string) (string, bool) {
	v, ok := mb.Requires[m]
	return v, ok
}

// replacementFor returns the replace rule binding module path m (with
// required version ver), or nil. Unversioned replaces match every
// version; versioned replaces match only that version of the left side.
func (mb moduleBinding) replacementFor(m, ver string) *replaceRule {
	for i := range mb.Replaces {
		r := &mb.Replaces[i]
		if r.oldPath != m {
			continue
		}
		if r.oldVer == "" || r.oldVer == ver {
			return r
		}
	}
	return nil
}

// isStdlibModule mirrors affected.isStdlibModule: standard-library and
// toolchain pseudo-modules bind to the toolchain, never to go.mod.
func isStdlibModule(m string) bool {
	switch m {
	case "std", "stdlib", "toolchain", "cmd":
		return true
	}
	first := m
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	return !strings.Contains(first, ".")
}

// shipsPackageUnderModule reports whether a path pkgPath could live
// inside the product's own module: pkgPath is modulePath or a
// modulePath-prefixed import path, and the snapshot directory for it
// actually contains Go sources.
func (mb moduleBinding) shipsPackageUnderModule(pkgPath string) bool {
	if mb.ModulePath == "" || pkgPath == "" {
		return false
	}
	if pkgPath != mb.ModulePath && !strings.HasPrefix(pkgPath, mb.ModulePath+"/") {
		return false
	}
	rel := strings.TrimPrefix(pkgPath, mb.ModulePath)
	rel = strings.TrimPrefix(rel, "/")
	dir := filepath.Join(mb.Dir, filepath.FromSlash(rel))
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") &&
			!strings.HasSuffix(e.Name(), "_test.go") {
			return true
		}
	}
	return false
}
