package reportcheck

import (
	"fmt"
	"sort"
	"strings"

	pbdomain "github.com/davniy/izyan/internal/productb/domain"
)

// Status vocabulary.
const (
	StatusExact   = "verified_exact"
	StatusSymbol  = "verified_symbol"
	StatusFile    = "verified_file"
	StatusFailed  = "unverified"
	StatusAtomOK  = "verified"
	StatusAtomBad = "unverified"
)

// verify runs one extracted claim through the verification ladder. The
// claim itself is carried through verbatim — only status and reason are
// attached.
func verify(idx *snapshotIndex, c claimed) Location {
	loc := Location{
		Raw: c.raw, Path: c.path, Kind: KindUnknown, Symbol: c.symbol,
		Status: StatusFailed,
	}
	if c.line > 0 {
		loc.Line = c.line
		loc.EndLine = c.end
		if loc.EndLine == 0 {
			loc.EndLine = c.line
		}
	}
	if c.badLoc {
		if isMetadataPath(c.path) {
			loc.Kind = KindMetadata
		}
		loc.Reason = "malformed location in citation " + c.raw
		return loc
	}
	if escapesRoot(c.path) {
		if isMetadataPath(c.path) {
			loc.Kind = KindMetadata
		}
		loc.Reason = "path escapes snapshot root"
		return loc
	}
	if idx == nil {
		if isMetadataPath(c.path) {
			loc.Kind = KindMetadata
		}
		loc.Reason = "snapshot unavailable: not verified"
		return loc
	}

	qual, name := splitSymbol(c.symbol)

	f, resolvedPath, found := idx.resolvePath(c.path)
	loc.Path = resolvedOr(c.path, resolvedPath, found)

	// The enclosing function/method is both the exact-match anchor and the
	// evidence a usage claim points at a concrete site.
	var enc *declInfo
	if found && f.isGo && c.line > 0 {
		if e := f.enclosing(c.line); e != nil && loc.EndLine <= e.end {
			enc = e
		}
	}
	loc.Kind = classify(c.kind, c, f, found, c.line, loc.EndLine, enc)

	if !found {
		if c.symbol != "" {
			if d := idx.findDecl(qual, name, nil); d != nil {
				loc.Status = StatusSymbol
				loc.Decl = declOf(d)
				loc.Reason = fmt.Sprintf("cited file missing; symbol resolves at %s:%d", d.file.rel, d.line)
				return loc
			}
		}
		loc.Reason = "file not found in snapshot"
		return loc
	}
	idx.fillLines(f)

	// Claimed-symbol resolution: the cited file's own package is tried
	// before the global index so unqualified-looking quals bind locally.
	var decl *declInfo
	if c.symbol != "" {
		decl = idx.findDecl(qual, name, f.pkg)
	}

	if c.line > 0 {
		if f.lines < 0 {
			loc.Status = StatusFile
			loc.Reason = "file unreadable: line bounds unchecked"
			return loc
		}
		if c.line > f.lines || loc.EndLine > f.lines {
			loc.Reason = fmt.Sprintf("line range %d-%d exceeds file bounds (%d lines)", c.line, loc.EndLine, f.lines)
			return loc
		}
		if !f.isGo {
			loc.Status = StatusFile
			loc.Reason = "line range within file bounds; not a Go file — no symbol check"
			return loc
		}
		enclosed := enc != nil
		if decl != nil {
			// A claimed symbol that resolves governs the verdict:
			// exact only when the cited range sits inside ITS
			// declaration — an enclosing-but-wrong decl earns symbol
			// credit, never line credit.
			if decl.file == f && c.line >= decl.line && loc.EndLine <= decl.end {
				loc.Status = StatusExact
				loc.Decl = declOf(decl)
				loc.EnclosingSymbol = decl.qualifiedName()
				loc.Reason = "cited range lies inside the claimed symbol's declaration"
				return loc
			}
			loc.Status = StatusSymbol
			loc.Decl = declOf(decl)
			if enclosed {
				loc.EnclosingSymbol = enc.qualifiedName()
			}
			loc.Reason = fmt.Sprintf("claimed symbol declared at %s:%d-%d; cited range does not fall inside it",
				decl.file.rel, decl.line, decl.end)
			return loc
		}
		if enclosed {
			loc.Status = StatusExact
			loc.Decl = declOf(enc)
			loc.EnclosingSymbol = enc.qualifiedName()
			if c.symbol != "" {
				loc.Reason = fmt.Sprintf("cited range inside %s; claimed symbol not resolved in snapshot", enc.qualifiedName())
			} else {
				loc.Reason = "cited range lies inside an enclosing declaration"
			}
			return loc
		}
		loc.Status = StatusFile
		if c.symbol != "" {
			loc.Reason = "line range within bounds; claimed symbol not resolved in snapshot"
		} else {
			loc.Reason = "line range within file bounds; no enclosing declaration"
		}
		return loc
	}

	// File-only or symbol-only claims.
	switch {
	case c.path == "" && decl != nil:
		loc.Status = StatusSymbol
		loc.Decl = declOf(decl)
		loc.Reason = fmt.Sprintf("symbol resolves at %s:%d", decl.file.rel, decl.line)
	case decl != nil && decl.file == f:
		loc.Status = StatusExact
		loc.Decl = declOf(decl)
		loc.EnclosingSymbol = decl.qualifiedName()
		loc.Reason = "file cites the declared symbol's file without a line"
	case decl != nil:
		loc.Status = StatusSymbol
		loc.Decl = declOf(decl)
		loc.Reason = fmt.Sprintf("claimed symbol declared in %s, not in the cited file", decl.file.rel)
	case c.symbol != "":
		loc.Status = StatusFile
		loc.Reason = "file exists; claimed symbol not resolved in snapshot"
	default:
		loc.Status = StatusFile
		loc.Reason = "file exists in snapshot"
	}
	return loc
}

func resolvedOr(norm, resolved string, found bool) string {
	if found {
		return resolved
	}
	return norm
}

func declOf(d *declInfo) *Decl {
	return &Decl{Path: d.file.rel, Line: d.line, EndLine: d.end}
}

// splitSymbol divides a normalized claim into package/type qualifier and
// symbol name. With three or more dot segments the qualifier greedily
// takes all but the last segment (dep.Server.Serve → dep.Server / Serve);
// the verifier's package lookup falls back to type resolution when the
// qualifier is a capitalized identifier.
func splitSymbol(sym string) (qual, name string) {
	if sym == "" {
		return "", ""
	}
	i := strings.LastIndex(sym, ".")
	if i <= 0 {
		return "", sym
	}
	return sym[:i], sym[i+1:]
}

// extractMechanism pulls mechanism atoms — explicit Go symbols and CWE
// keys — out of the reasoning text and verifies each against the frozen
// advisory references. A symbol atom verifies when it matches an advisory
// symbol (exact symbol name plus compatible package, or an advisory
// package wildcard); a CWE atom verifies when the key is frozen in the
// advisory's CWE list. Everything else is unverified.
func extractMechanism(text string, syms []pbdomain.SymbolRef, keys []string) []MechanismAtom {
	if strings.TrimSpace(text) == "" {
		return []MechanismAtom{}
	}
	seen := map[string]bool{}
	var atoms []MechanismAtom
	add := func(raw, symbol, key string) {
		k := symbol + "|" + key
		if seen[k] {
			return
		}
		seen[k] = true
		at := MechanismAtom{Raw: raw, Symbol: symbol, Key: key, Status: StatusAtomBad}
		switch {
		case key != "":
			for _, k := range keys {
				if k == key {
					at.Status = StatusAtomOK
					break
				}
			}
		case symbol != "":
			if advisorySymbolMatch(symbol, syms) {
				at.Status = StatusAtomOK
			}
		}
		atoms = append(atoms, at)
	}

	citIdx := citationRx.FindAllStringSubmatchIndex(text, -1)
	for _, s := range unitSymbols(text, citIdx) {
		add(s.raw, normalizeSymbol(s.raw), "")
	}
	for _, m := range cweRx.FindAllString(text, -1) {
		add(m, "", m)
	}
	sort.Slice(atoms, func(i, j int) bool {
		a, b := atoms[i], atoms[j]
		if a.Symbol != b.Symbol {
			return a.Symbol < b.Symbol
		}
		return a.Key < b.Key
	})
	return atoms
}

// advisorySymbolMatch reports whether a claimed symbol is one of the
// frozen advisory symbols. The name side matches on the full normalized
// symbol or its last segment (a claim "dep.Serve" matches advisory
// "Server.Serve" only when the claim's qualifier is the advisory's
// receiver part). The package side requires a compatible qualifier:
// none, the advisory package path/name, or a path ending in it. An empty
// or "*" advisory symbol is a package-level wildcard.
func advisorySymbolMatch(claimed string, syms []pbdomain.SymbolRef) bool {
	qual, name := splitSymbol(claimed)
	for _, s := range syms {
		if s.Symbol == "" || s.Symbol == "*" {
			// Package wildcard: a qualified claim inside the advisory
			// package counts.
			if qual != "" && pkgCompatible(qual, s) {
				return true
			}
			continue
		}
		if claimed == s.Symbol {
			return true
		}
		if name == s.Symbol && pkgCompatible(qual, s) {
			return true
		}
		if i := strings.Index(s.Symbol, "."); i > 0 && name == s.Symbol[i+1:] && qual == s.Symbol[:i] {
			return true
		}
	}
	return false
}

// pkgCompatible decides whether a claim's qualifier matches the advisory
// symbol's package: no qualifier is a weak match, an import path compares
// exactly or by suffix, a bare package name compares to the advisory
// package basename, and a capitalized qualifier is treated as a type name
// compared against the advisory symbol's receiver segment.
func pkgCompatible(qual string, s pbdomain.SymbolRef) bool {
	if qual == "" {
		return true
	}
	pkg := s.Package
	if qual == pkg || strings.HasSuffix(pkg, "/"+qual) || strings.HasSuffix(qual, "/"+pkg) {
		return true
	}
	if base := pkg[strings.LastIndex(pkg, "/")+1:]; base == qual {
		return true
	}
	// Type-style qualifier: dep.Server.Serve arrives as qual "dep.Server"
	// already handled above; a bare "Server" compares against the
	// advisory symbol's own "Server.Serve" receiver segment.
	if i := strings.Index(s.Symbol, "."); i > 0 && s.Symbol[:i] == qual {
		return true
	}
	return false
}
