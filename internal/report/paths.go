// Path presentation policy for human and audit reports: host-absolute
// paths never render as-is — a product file is shown relative to the
// product checkout, a dependency file as `<module>@<version>/<file>`.
// report.json keeps raw paths; this file only affects Markdown output.
//
// Ownership is proven exclusively from persisted case data: the product
// root is Product.Repository and dependency roots come from MODULE_GRAPH
// evidence (go list -m -json Dir fields, via the shared affected wire
// decoder). The renderer never consults the process cwd, the output
// directory, the filesystem, or the current module cache.
package report

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/module"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
)

// reportLocation is one rendered location: Text is the display string and
// Attributed reports whether the owning root (product or dependency) was
// proven from persisted case data — false marks the rendered name as a
// fallback that deliberately avoids masquerading as a product-relative path.
type reportLocation struct {
	Text       string
	Attributed bool
}

// depRoot is one proven dependency source root: a canonical absolute
// directory plus the display label the contained files are rendered with.
// note carries an explicit qualifier for local replaces — a versionless
// one says "(local replace, version unavailable)" instead of inventing a
// version.
type depRoot struct {
	dir   string // canonical absolute directory (slash-separated)
	label string // "<path>@<version>" or "<path>@local"
	note  string // e.g. " (local replace, version unavailable)"
}

// reportPaths is the immutable per-render index of proven source roots.
type reportPaths struct {
	product string // canonical absolute product checkout root, "" when absent
	roots   []depRoot
	// mods retains every persisted non-main module so paths under an
	// escaped module-cache directory (…/<path>@<version>) can be
	// attributed even when the module record carried no Dir (legacy
	// snapshots, hand-built fixtures).
	mods []affected.Module
	// pkgDirs maps a package import path to its canonical directory and
	// pkgStd flags standard-library packages — both sourced from
	// PACKAGE_LIST evidence. They disambiguate short frame files; a
	// subdirectory is never reconstructed without them.
	pkgDirs map[string]string
	pkgStd  map[string]bool
}

// newReportPaths builds the root index once per render.
func newReportPaths(c *domain.AnalysisCase) reportPaths {
	p := reportPaths{
		pkgDirs: map[string]string{},
		pkgStd:  map[string]bool{},
	}
	if c == nil {
		return p
	}
	if prod := canonicalPath(c.Product.Repository); prod.abs && prod.clean != "/" {
		p.product = prod.clean
	}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		switch e.Kind {
		case domain.EvidenceModuleGraph:
			if mods, err := affected.DecodeModules([]byte(e.Content)); err == nil {
				for _, m := range mods {
					p.addModule(m)
				}
			}
		case domain.EvidencePackageList:
			if pkgs, err := affected.DecodePackages([]byte(e.Content)); err == nil {
				for _, pkg := range pkgs {
					if pkg.ImportPath == "" {
						continue
					}
					if dir := canonicalPath(pkg.Dir); dir.abs && dir.clean != "/" {
						if _, seen := p.pkgDirs[pkg.ImportPath]; !seen {
							p.pkgDirs[pkg.ImportPath] = dir.clean
						}
					}
					if pkg.Standard {
						p.pkgStd[pkg.ImportPath] = true
					}
				}
			}
		}
	}
	// Longest directory first so nested module roots beat their parents.
	sort.SliceStable(p.roots, func(i, j int) bool {
		return len(p.roots[i].dir) > len(p.roots[j].dir)
	})
	return p
}

// addModule indexes one module record. Local replaces are indexed at the
// replacement directory; a replacement dir inside the product checkout is
// skipped because the product-root match already renders those files
// correctly relative.
func (p *reportPaths) addModule(m affected.Module) {
	if m.Main {
		return
	}
	if m.Path != "" {
		p.mods = append(p.mods, m)
	}
	dir := canonicalPath(m.EffectiveDir())
	if !dir.abs || dir.clean == "/" {
		return
	}
	if p.product != "" && (dir.clean == p.product || strings.HasPrefix(dir.clean, p.product+"/")) {
		return
	}
	// The label uses the effective identity: the replacement module path
	// for a versioned replace, the requirement path for a local one. A
	// versionless local replace gets an explicit unavailable-version note
	// instead of an invented version.
	path, ver, note := m.EffectivePath(), m.EffectiveVersion(), ""
	if m.Replace != nil && m.Replace.Path != "" && !modulePathShape(m.Replace.Path) {
		path = m.Path
		if ver == "" {
			ver, note = "local", " (local replace, version unavailable)"
		} else {
			note = " (local replace)"
		}
	}
	if path == "" || ver == "" {
		return
	}
	label := path + "@" + ver
	for _, r := range p.roots {
		if r.dir == dir.clean {
			return
		}
	}
	p.roots = append(p.roots, depRoot{dir: dir.clean, label: label, note: note})
}

// modulePathShape reports whether s looks like a module path rather than a
// filesystem location: module paths are slash-separated and carry no
// drive letter, leading separator or dot-dot segment.
func modulePathShape(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.Contains(s, "\\") {
		return false
	}
	if len(s) >= 2 && s[1] == ':' {
		return false
	}
	return true
}

// canon is a canonicalized path: separators normalized to '/', lexical
// cleaning applied, and the absolute flag distinguishing POSIX roots,
// Windows drives and UNC shares from relative text.
type canon struct {
	clean string // cleaned path, '/'-separated; "" when unusable
	abs   bool
}

var winDriveRe = regexp.MustCompile(`^[A-Za-z]:`)

// canonicalPath normalizes a raw recorded path for comparison and
// rendering. file:// URIs are mapped to their path component (a non-empty
// host becomes a UNC share); backslashes become '/'. No symlink or case
// folding: comparison is purely lexical.
func canonicalPath(raw string) canon {
	s := strings.TrimSpace(raw)
	if s == "" {
		return canon{}
	}
	if strings.HasPrefix(strings.ToLower(s), "file://") {
		rest := s[len("file://"):]
		if strings.HasPrefix(rest, "/") {
			s = rest // file:///x or file:///c|/x
		} else {
			s = "//" + rest // file://host/share → UNC
		}
	}
	s = strings.ReplaceAll(s, "\\", "/")
	s = strings.TrimSuffix(s, "/")
	abs := strings.HasPrefix(s, "/") || winDriveRe.MatchString(s)
	clean := cleanSlashes(s)
	if clean == "" {
		return canon{}
	}
	return canon{clean: clean, abs: abs}
}

// cleanSlashes lexically cleans a '/'-separated path: '.' segments drop,
// '..' pops one segment, and leading '..' of a relative path is kept (the
// caller marks it unattributed). Multiple slashes collapse.
func cleanSlashes(s string) string {
	abs := strings.HasPrefix(s, "/") || winDriveRe.MatchString(s)
	var head string
	switch {
	case winDriveRe.MatchString(s):
		head = s[:2]
		s = s[2:]
	case strings.HasPrefix(s, "/"):
		head = "/"
		s = s[1:]
	}
	var segs []string
	for _, seg := range strings.Split(s, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if n := len(segs); n > 0 {
				segs = segs[:n-1]
				continue
			}
			if abs {
				continue // clamp: cannot escape the root
			}
			segs = append(segs, seg)
		default:
			segs = append(segs, seg)
		}
	}
	if head == "" && len(segs) == 0 {
		return ""
	}
	joined := strings.Join(segs, "/")
	if head != "" {
		if joined == "" {
			return head // "/" or "C:"
		}
		return head + joined
	}
	return joined
}

// containsRel reports whether file canonical-clean lives under root: an
// exact match returns ".", a contained path returns its relative form,
// and anything else reports false — sibling-prefix strings like
// "/repo-other" never match root "/repo".
func containsRel(root, file string) (string, bool) {
	if root == "" || file == "" {
		return "", false
	}
	if file == root {
		return ".", true
	}
	if strings.HasPrefix(file, root+"/") {
		return file[len(root)+1:], true
	}
	return "", false
}

// locSuffixRe keeps recorded ":line[:column]" suffixes attached to their
// file when a raw path or a free-text token carries them.
var locSuffixRe = regexp.MustCompile(`^(.*?)(?::(\d+))?(?::(\d+))?$`)

// file renders a recorded file reference. Order: product root first, then
// the longest proven dependency root, then package metadata for short
// frames; anything unresolved degrades to a marked basename and never
// impersonates a product-relative path.
func (p reportPaths) file(raw, pkg string) reportLocation {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return reportLocation{}
	}
	c := canonicalPath(raw)
	if c.clean == "" {
		return reportLocation{Text: raw}
	}
	if c.abs {
		// Split a recorded :line/:column tail so containment never sees it.
		base := c.clean
		suffix := ""
		if m := locSuffixRe.FindStringSubmatch(base); m != nil && m[2] != "" {
			base, suffix = m[1], ":"+m[2]
			if m[3] != "" {
				suffix += ":" + m[3]
			}
		}
		if rel, ok := containsRel(p.product, base); ok {
			return reportLocation{Text: rel + suffix, Attributed: true}
		}
		for _, r := range p.roots {
			if rel, ok := containsRel(r.dir, base); ok {
				if rel == "." {
					return reportLocation{Text: r.label + r.note + suffix, Attributed: true}
				}
				return reportLocation{Text: r.label + "/" + rel + suffix + r.note, Attributed: true}
			}
		}
		if lab, rel, ok := p.escapedModuleOwner(base); ok {
			if rel == "" {
				return reportLocation{Text: lab + suffix, Attributed: true}
			}
			return reportLocation{Text: lab + "/" + rel + suffix, Attributed: true}
		}
		// A package known to the persisted build graph contributes its
		// name to the fallback label — the module/version stays absent.
		if pkg != "" {
			if _, known := p.pkgDirs[pkg]; known || p.pkgStd[pkg] {
				return reportLocation{Text: pkg + "/" + lastSegment(base) + suffix, Attributed: false}
			}
		}
		return reportLocation{Text: lastSegment(base) + suffix + " (unattributed)"}
	}
	// Relative text: it is already a repository-relative reference — kept
	// verbatim unless it escapes the root. With persisted package metadata
	// the proven package directory attributes it exactly.
	if pkg != "" {
		if dir, ok := p.pkgDirs[pkg]; ok {
			if j := canonicalPath(dir + "/" + c.clean); j.abs {
				if rel, ok2 := containsRel(p.product, j.clean); ok2 {
					return reportLocation{Text: rel, Attributed: true}
				}
				for _, r := range p.roots {
					if rel, ok2 := containsRel(r.dir, j.clean); ok2 {
						if rel == "." {
							return reportLocation{Text: r.label + r.note, Attributed: true}
						}
						return reportLocation{Text: r.label + "/" + rel + r.note, Attributed: true}
					}
				}
				if p.pkgStd[pkg] {
					return reportLocation{Text: pkg + "/" + c.clean, Attributed: true}
				}
				return reportLocation{Text: pkg + "/" + lastSegment(c.clean) + " (unattributed)"}
			}
		}
		if p.pkgStd[pkg] {
			// stdlib package dir equals its import path — an identity, not
			// a reconstructed subdirectory.
			return reportLocation{Text: pkg + "/" + c.clean, Attributed: true}
		}
	}
	return reportLocation{Text: c.clean, Attributed: !strings.HasPrefix(c.clean, "..")}
}

// location appends a positive recorded line; :0 stays bare.
func (p reportPaths) location(raw, pkg string, line int) reportLocation {
	loc := p.file(raw, pkg)
	if line > 0 && loc.Text != "" {
		if idx := strings.Index(loc.Text, " ("); idx >= 0 {
			loc.Text = loc.Text[:idx] + ":" + strconv.Itoa(line) + loc.Text[idx:]
		} else {
			loc.Text += ":" + strconv.Itoa(line)
		}
	}
	return loc
}

func lastSegment(clean string) string {
	if i := strings.LastIndex(clean, "/"); i >= 0 {
		return clean[i+1:]
	}
	return clean
}

// escapedModuleOwner attributes a path whose directory names a persisted
// module in escaped module-cache form "<path>@<version>". The module cache
// location itself is never assumed — only the proven (path, version) pair
// from MODULE_GRAPH evidence can claim the directory.
// escapedModuleOwner attributes a path whose directory names a persisted
// module in escaped module-cache form "<path>@<version>". The module path
// may start at any segment after the (never assumed) cache prefix, so each
// segment bearing '@' is tried with every possible path start. Only the
// proven (path, version) pair from MODULE_GRAPH evidence can claim the
// directory — "@v1.2.3" alone never marks a module.
func (p reportPaths) escapedModuleOwner(clean string) (label, rel string, ok bool) {
	segs := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for i := range len(segs) - 1 {
		tail := segs[i]
		at := strings.LastIndex(tail, "@")
		if at <= 0 {
			continue
		}
		verEsc := tail[at+1:]
		for j := 0; j <= i; j++ {
			pathEsc := tail[:at]
			if j < i {
				pathEsc = strings.Join(segs[j:i], "/") + "/" + tail[:at]
			}
			for _, m := range p.mods {
				mpath, mver := m.Path, m.EffectiveVersion()
				if m.Replace != nil && m.Replace.Path != "" && modulePathShape(m.Replace.Path) {
					mpath = m.Replace.Path
				}
				if mver == "" {
					mver = "local"
				}
				up, err1 := module.UnescapePath(pathEsc)
				uv, err2 := module.UnescapeVersion(verEsc)
				if err1 != nil || err2 != nil || up != mpath || uv != mver {
					continue
				}
				rest := strings.Join(segs[i+1:], "/")
				return mpath + "@" + mver, rest, true
			}
		}
	}
	return "", "", false
}

// text rewrites host-absolute paths inside free text: proven roots render
// their attributed form longest-first, and unrecognized host paths degrade
// to a marked basename. URLs (http/https), file:// locations, import
// paths, route names and quoted tokens are preserved; recorded :line and
// :column suffixes survive. Whitespace is preserved verbatim and the
// input is never mutated — the original Evidence.Content stays raw.
func (p reportPaths) text(raw string) string {
	if raw == "" {
		return raw
	}
	var b strings.Builder
	b.Grow(len(raw))
	i := 0
	for i < len(raw) {
		j := i
		for j < len(raw) && !isTextSpace(raw[j]) {
			j++
		}
		b.WriteString(p.textToken(raw[i:j]))
		for i = j; i < len(raw) && isTextSpace(raw[i]); i++ {
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

func isTextSpace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// textToken maps one whitespace-delimited token. Leading punctuation
// (quotes, parens, flag prefixes up to '=') is carried through so
// "--dir=/x" redacts its value part.
func (p reportPaths) textToken(tok string) string {
	core := tok
	var lead, prefix string
	// Split off an option-style prefix only when the left side contains no
	// path characters — "--dir=/a/b" redacts, "C:/a=b" stays whole.
	if i := strings.Index(core, "="); i > 0 {
		l := core[:i]
		if !strings.ContainsAny(l, `/\:`) {
			prefix, core = l+"=", core[i+1:]
		}
	}
	for len(core) > 0 {
		ch := core[0]
		if strings.ContainsRune(`"'(<[{`, rune(ch)) {
			lead += string(ch)
			core = core[1:]
			continue
		}
		break
	}
	trail := ""
	for len(core) > 0 {
		ch := core[len(core)-1]
		if strings.ContainsRune(`"')>].,;}!`, rune(ch)) {
			trail = string(ch) + trail
			core = core[:len(core)-1]
			continue
		}
		break
	}
	if core == "" {
		return tok
	}
	// A trailing :line[:column] belongs to the location, not the path.
	suffix := ""
	if m := locSuffixRe.FindStringSubmatch(core); m != nil && m[2] != "" && strings.ContainsAny(m[1], `/\`) {
		core = m[1]
		suffix = ":" + m[2]
		if m[3] != "" {
			suffix += ":" + m[3]
		}
	}
	if !p.looksPathLike(core) {
		return tok
	}
	loc := p.file(core, "")
	if !loc.Attributed {
		// The marker rides the basename; the recorded :line stays between.
		base := strings.TrimSuffix(loc.Text, " (unattributed)")
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		return prefix + lead + base + suffix + " (unattributed)" + trail
	}
	return prefix + lead + loc.Text + suffix + trail
}

// looksPathLike conservatively decides whether a token is a host path
// rather than a URL, route, import path or version string. POSIX paths
// need enough structure to not eat route names like "/api/v1/items".
func (p reportPaths) looksPathLike(s string) bool {
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return false
	}
	if strings.HasPrefix(low, "file://") {
		return true
	}
	if strings.HasPrefix(s, "//") { // UNC share
		return true
	}
	if winDriveRe.MatchString(s) {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	segs := strings.Split(strings.TrimPrefix(s, "/"), "/")
	last := segs[len(segs)-1]
	if i := strings.Index(last, ":"); i >= 0 {
		last = last[:i]
	}
	switch {
	case len(segs) >= 4:
		return true
	case strings.Contains(last, "."):
		// A file-like leaf on a shallow path ("/usr/lib/libc.so").
		return len(segs) >= 2
	case strings.ContainsAny(s, "~$%"):
		return true
	}
	return false
}

// reportRepositoryName renders the product repository for metadata: an
// absolute checkout contributes its basename, a usable relative name is
// kept cleaned, and unusable input degrades to a neutral name — never a
// bare "/", drive letter or UNC host.
func reportRepositoryName(raw string) string {
	c := canonicalPath(raw)
	if c.clean == "" || c.clean == "/" {
		return "repository"
	}
	if c.abs {
		name := lastSegment(strings.TrimSuffix(c.clean, "/"))
		if name == "" || strings.HasSuffix(name, ":") { // drive root "C:"
			return "repository"
		}
		return name
	}
	return c.clean
}
