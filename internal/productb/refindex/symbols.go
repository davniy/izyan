package refindex

import (
	"regexp"
	"sort"
	"strings"

	pbdomain "github.com/davniy/izyan/internal/productb/domain"
)

// atomSource is the raw material one atom is built from: the declaring
// document and the module the affected entry belongs to.
type atomSource struct {
	module     string
	pkg        string
	symbol     string // normalized; "" for package atoms
	wildcard   bool   // symbol was an explicit "*" wildcard
	advisoryID string
}

// buildAtoms flattens the selected advisory plus the family corpus into
// deduplicated atoms. The selected document declares the (module, package)
// entries; a family document may contribute symbol names for entries the
// selected document left symbol-less (mirroring FileSource's sibling
// enrichment). Every atom records the document id its symbol material came
// from; atoms are sorted by (module, package, symbol) for canonical output.
// hadWildcard reports that at least one package atom was spelled "*".
func buildAtoms(la *loadedAdvisory) (atoms []Atom, hadWildcard, hadPlainPackage bool) {
	sources := atomSources(la)
	seen := map[string]bool{}
	for _, s := range sources {
		key := s.module + "\x00" + s.pkg + "\x00" + s.symbol
		if s.wildcard {
			hadWildcard = true
			key += "\x00*"
		} else if s.symbol == "" {
			hadPlainPackage = true
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		atoms = append(atoms, Atom{
			Module:     s.module,
			Package:    s.pkg,
			Symbol:     s.symbol,
			SymbolKind: atomSymbolKind(s),
			Role:       atomRole(s.symbol),
			AdvisoryID: s.advisoryID,
		})
	}
	sort.Slice(atoms, func(i, j int) bool {
		if atoms[i].Module != atoms[j].Module {
			return atoms[i].Module < atoms[j].Module
		}
		if atoms[i].Package != atoms[j].Package {
			return atoms[i].Package < atoms[j].Package
		}
		return atoms[i].Symbol < atoms[j].Symbol
	})
	return atoms, hadWildcard, hadPlainPackage
}

// atomSources enumerates the raw atom declarations of the selected
// document. When the selected document declares no affected
// (module, package) entry at all — the CVE-wrapper shape, where aliases
// point at a GO-* sibling that carries the real affected material — the
// family documents' affected entries are promoted wholesale (union,
// deduplicated, each atom attributed to its source document). Otherwise
// family material only fills symbol-less entries the selected document
// declared itself.
func atomSources(la *loadedAdvisory) []atomSource {
	v := la.vuln
	declared := moduleEntries(v)
	if len(declared) == 0 {
		return familyAtomSources(la)
	}
	var out []atomSource
	// per-entry symbol presence keyed module+"\x00"+package.
	named := map[string]bool{}
	adopt := func(mod, pkg, sym, docID string) {
		raw := strings.TrimSpace(sym)
		if raw == "" {
			return
		}
		key := mod + "\x00" + pkg
		if raw == "*" {
			out = append(out, atomSource{module: mod, pkg: pkg, wildcard: true, advisoryID: docID})
			named[key] = true
			return
		}
		sym = normalizeSymbol(sym)
		if sym == "" {
			return
		}
		out = append(out, atomSource{module: mod, pkg: pkg, symbol: sym, advisoryID: docID})
		named[key] = true
	}
	for _, e := range declared {
		for _, s := range e.symbols {
			adopt(e.module, e.pkg, s, v.ID)
		}
		if len(e.symbols) == 0 {
			// Symbol-less import: a package atom now; family documents may
			// still contribute named atoms for the same entry below.
			out = append(out, atomSource{module: e.module, pkg: e.pkg, advisoryID: v.ID})
		}
	}
	// Family adoption: for entries the selected document left symbol-less,
	// take symbol names from family documents claiming the same module.
	// Documents are processed in sorted id order for determinism.
	for _, d := range sortedFamily(la) {
		if d.vuln == nil || d.id == v.ID {
			continue
		}
		for _, e := range moduleEntries(d.vuln) {
			if len(e.symbols) == 0 {
				continue
			}
			for _, s := range e.symbols {
				sym := normalizeSymbol(s)
				if sym == "" || sym == "*" {
					continue
				}
				key := e.module + "\x00" + e.pkg
				if named[key] {
					continue
				}
				// Only adopt when the selected document declared this
				// (module, package) entry symbol-less — family material
				// fills gaps, it does not widen the declared surface.
				if !declaredPackage(declared, e.module, e.pkg) {
					continue
				}
				out = append(out, atomSource{module: e.module, pkg: e.pkg, symbol: sym, advisoryID: d.id})
				named[key] = true
			}
		}
	}
	return out
}

// familyAtomSources promotes the affected entries of every family
// document when the selected document declares none. A named atom wins
// over a package atom for the same (module, package): the package atom is
// emitted only when no document names a symbol for it. Documents are
// visited in sorted id order; atoms are deduplicated by
// (module, package, symbol) and each is attributed to the document that
// supplied it.
func familyAtomSources(la *loadedAdvisory) []atomSource {
	var out []atomSource
	seen := map[string]bool{}
	namedPkg := map[string]bool{}
	var pkgAtoms []atomSource
	for _, d := range sortedFamily(la) {
		if d.vuln == nil {
			continue
		}
		for _, e := range moduleEntries(d.vuln) {
			key := e.module + "\x00" + e.pkg
			if len(e.symbols) == 0 {
				if seen["pkg\x00"+key] {
					continue
				}
				seen["pkg\x00"+key] = true
				pkgAtoms = append(pkgAtoms, atomSource{
					module: e.module, pkg: e.pkg, advisoryID: d.id,
				})
				continue
			}
			for _, s := range e.symbols {
				raw := strings.TrimSpace(s)
				if raw == "" {
					continue
				}
				src := atomSource{module: e.module, pkg: e.pkg, advisoryID: d.id}
				dedupe := key
				if raw == "*" {
					src.wildcard = true
					dedupe += "\x00*"
				} else {
					src.symbol = normalizeSymbol(raw)
					if src.symbol == "" {
						continue
					}
					dedupe += "\x00" + src.symbol
					namedPkg[key] = true
				}
				if seen[dedupe] {
					continue
				}
				seen[dedupe] = true
				out = append(out, src)
			}
		}
	}
	for _, p := range pkgAtoms {
		if namedPkg[p.module+"\x00"+p.pkg] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// sortedFamily returns the family documents in deterministic id order.
func sortedFamily(la *loadedAdvisory) []familyDoc {
	fam := append([]familyDoc{}, la.family...)
	sort.Slice(fam, func(i, j int) bool { return fam[i].id < fam[j].id })
	return fam
}

// modEntry is one (module, package, symbols) declaration of a document.
type modEntry struct {
	module  string
	pkg     string
	symbols []string
}

// moduleEntries flattens a Vulnerability's affected material into
// (module, package, symbols) entries in document order. The same
// (module, package) declared through several fields accumulates the union
// of its symbol lists (deduplicated, first-seen order). Entries without a
// package path carry no locus and are dropped — a document whose affected[]
// material never names a package is exactly the "no (module, package)
// entry" shape the family promotion path handles.
func moduleEntries(v *pbdomain.Vulnerability) []modEntry {
	var out []modEntry
	idx := map[string]int{}
	add := func(mod, pkg string, syms []string) {
		if pkg == "" {
			return
		}
		key := mod + "\x00" + pkg
		i, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, modEntry{module: mod, pkg: pkg})
			i = len(out) - 1
		}
		for _, s := range syms {
			if !contains(out[i].symbols, s) {
				out[i].symbols = append(out[i].symbols, s)
			}
		}
	}
	for _, am := range v.AffectedModules {
		for _, p := range am.AffectedPackages {
			add(am.Module, p.Path, p.Symbols)
		}
		for _, s := range am.AffectedSymbols {
			// AffectedSymbols repeats the package's symbol list; entries
			// here cover packages declared only through symbol refs.
			add(am.Module, s.Package, []string{s.Symbol})
		}
	}
	for _, p := range v.AffectedPackages {
		add(v.Module, p.Path, p.Symbols)
	}
	for _, s := range v.AffectedSymbols {
		add(v.Module, s.Package, []string{s.Symbol})
	}
	return out
}

// declaredPackage reports whether the entries list declares (mod, pkg).
func declaredPackage(entries []modEntry, mod, pkg string) bool {
	for _, e := range entries {
		if e.module == mod && e.pkg == pkg {
			return true
		}
	}
	return false
}

// normalizeSymbol canonicalizes an advisory symbol spelling: receiver
// parens/stars fold away ("(*T).M" == "T.M" == "(T).M"), whitespace and a
// leading package-type qualifier dot are trimmed.
func normalizeSymbol(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if i := strings.Index(s, "."); i > 0 {
		recv := strings.TrimSpace(s[:i])
		recv = strings.TrimPrefix(recv, "(")
		recv = strings.TrimSuffix(recv, ")")
		recv = strings.TrimPrefix(recv, "*")
		recv = strings.TrimSpace(recv)
		name := strings.TrimSpace(s[i+1:])
		if recv != "" && name != "" {
			return recv + "." + name
		}
		return s
	}
	s = strings.TrimPrefix(s, "*")
	return strings.TrimSpace(s)
}

// atomSymbolKind derives the contract kind: package atoms are "package",
// dotted names resolve to "method" unless declaration inspection proves a
// type/field (handled later by resolveDecls); unresolved bare names are
// "func" by convention.
func atomSymbolKind(s atomSource) string {
	if s.pkg != "" && s.symbol == "" {
		return KindPackage
	}
	if _, name := splitSymbol(s.symbol); name == "" {
		return KindFunc
	}
	if strings.Contains(s.symbol, ".") {
		return KindMethod
	}
	return KindFunc
}

// splitSymbol mirrors goanalysis.splitSymbol: "T.M" -> ("T","M"),
// "F" -> ("","F").
func splitSymbol(sym string) (typeName, name string) {
	s := strings.TrimPrefix(sym, "*")
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", sym
}

// parseRoleNames matches advisory symbol names that declare a
// parse/decode surface — the atom's role is "parse" rather than "sink".
var parseRoleNames = regexp.MustCompile(`(?i)(^|[^a-z])(parse|unmarshal|decode|unserialize|deserialize|scan|lex|tokenize)`)

// atomRole assigns the advisory-derived role: parse-named symbols are
// "parse"; everything else (including whole-package atoms) defaults to
// "sink" — the advisory names the defect site.
func atomRole(sym string) string {
	_, name := splitSymbol(sym)
	if name == "" {
		name = sym
	}
	if name != "" && parseRoleNames.MatchString(name) {
		return RoleParse
	}
	return RoleSink
}

// locusStatus computes the document-level locus status over resolved
// atoms: no atoms -> "na"; package atoms only -> "package_only"
// ("wildcard" when the advisory spelled them as "*"); any unresolved
// named atom -> "unresolved"; all named atoms resolved -> "resolved".
func locusStatus(atoms []Atom, hadWildcard, hadPlainPackage bool) LocusStatus {
	if len(atoms) == 0 {
		return LocusNA
	}
	named, unresolved := 0, 0
	for _, a := range atoms {
		if a.Symbol == "" {
			continue
		}
		named++
		if a.Decl == nil {
			unresolved++
		}
	}
	if named == 0 {
		// Wildcard only when every package atom was spelled "*".
		if hadWildcard && !hadPlainPackage {
			return LocusWildcard
		}
		return LocusPackageOnly
	}
	if unresolved > 0 {
		return LocusUnresolved
	}
	return LocusResolved
}
