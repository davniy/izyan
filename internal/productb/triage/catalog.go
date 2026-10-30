package triage

import (
	"strings"
)

// MatchComponent resolves an intake proposal to exactly one catalog entry
// with the deterministic precedence the source catalog admits: the proposed
// component name first, then the product name, then explicit catalog-entry
// references carried in source_hints. A lower tier is consulted only when
// every higher tier found no match; a CONFLICTING higher tier is terminal —
// an ambiguous component is never rescued by a product or hint fallback.
// Nothing resolving keeps the result UNVERIFIED, never an invented entry.
func (c Catalog) MatchComponent(proposal IntakeProposal) (CatalogEntry, IntakeFieldStatus, error) {
	for _, cand := range []string{proposal.Component, proposal.Product} {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		e, st, err := c.matchName(cand)
		if err != nil || st != IntakeUnverified {
			return e, st, err
		}
	}
	return c.matchHints(proposal.SourceHints)
}

// matchHints resolves the explicit catalog references a proposal carries.
// Every hint that resolves must resolve to the same entry; hints naming
// different entries are CONFLICTING, a hint that is itself ambiguous is
// CONFLICTING, and hints matching nothing are ignored — an unresolvable
// hint is LLM-only, never a negative fact.
func (c Catalog) matchHints(hints []string) (CatalogEntry, IntakeFieldStatus, error) {
	var found []CatalogEntry
	for _, h := range hints {
		if strings.TrimSpace(h) == "" {
			continue
		}
		e, st, err := c.matchName(h)
		if err != nil {
			return CatalogEntry{}, "", err
		}
		switch st {
		case IntakeValid:
			dup := false
			for _, f := range found {
				if f.ID == e.ID {
					dup = true
					break
				}
			}
			if !dup {
				found = append(found, e)
			}
		case IntakeConflicting:
			return CatalogEntry{}, IntakeConflicting, nil
		}
	}
	switch {
	case len(found) > 1:
		return CatalogEntry{}, IntakeConflicting, nil
	case len(found) == 1:
		return found[0], IntakeValid, nil
	default:
		return CatalogEntry{}, IntakeUnverified, nil
	}
}

// MatchReference resolves an external reference — typically a repository
// path or URL produced by a repo map — against the bounded catalog. The
// result is a catalog entry, never the raw reference: a caller must not
// adopt a repo-map path as a repository root directly. Exact root matches
// win, then exact locator matches, then name matching of the reference's
// last path segment; multiple entries at the best tier are CONFLICTING, and
// an unmatched reference is UNVERIFIED, not a fabricated repository.
func (c Catalog) MatchReference(ref string) (CatalogEntry, IntakeFieldStatus, error) {
	ref = strings.TrimRight(strings.TrimSpace(ref), "/")
	if ref == "" {
		return CatalogEntry{}, IntakeUnverified, nil
	}
	var byRoot, byLocator []CatalogEntry
	for _, e := range c.Entries {
		if e.Root != "" && e.Root == ref {
			byRoot = append(byRoot, e)
		}
		if e.Locator != "" && e.Locator == ref {
			byLocator = append(byLocator, e)
		}
	}
	best := byRoot
	if len(best) == 0 {
		best = byLocator
	}
	switch {
	case len(best) > 1:
		return CatalogEntry{}, IntakeConflicting, nil
	case len(best) == 1:
		return best[0], IntakeValid, nil
	}
	tail := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		tail = ref[i+1:]
	}
	return c.matchName(tail)
}

// matchName applies the deterministic precedence within one candidate: exact
// canonical id, then exact normalized locator/PURL name, then unique alias.
// Several entries at the best tier mean CONFLICTING — never a silent pick.
func (c Catalog) matchName(candidate string) (CatalogEntry, IntakeFieldStatus, error) {
	idNorm := normalizeMatchID(candidate)
	names := candidateMatchNames(candidate)
	var byID, byName, byAlias []CatalogEntry
	for _, e := range c.Entries {
		if normalizeMatchID(e.ID) == idNorm {
			byID = append(byID, e)
			continue
		}
		if namesIntersect(names, entryMatchNames(e)) {
			byName = append(byName, e)
			continue
		}
		for _, a := range e.Aliases {
			if normalizeMatchID(a) == idNorm {
				byAlias = append(byAlias, e)
				break
			}
		}
	}
	best := byID
	if len(best) == 0 {
		best = byName
	}
	if len(best) == 0 {
		best = byAlias
	}
	switch {
	case len(best) > 1:
		return CatalogEntry{}, IntakeConflicting, nil
	case len(best) == 1:
		return best[0], IntakeValid, nil
	default:
		return CatalogEntry{}, IntakeUnverified, nil
	}
}

// entryMatchNames are the normalized names an entry answers to: the last
// path segment of locator/root (".git" stripped) and, for PURL locators,
// the package name and namespace/name pair.
func entryMatchNames(e CatalogEntry) map[string]bool {
	names := map[string]bool{}
	add := func(s string) {
		s = normalizeMatchName(s)
		if s != "" {
			names[s] = true
		}
	}
	for _, ref := range []string{e.Locator, e.Root} {
		if ref == "" {
			continue
		}
		if p, ok := parsePURL(ref); ok {
			add(p.Name)
			if p.Namespace != "" {
				add(p.Namespace + "/" + p.Name)
			}
			continue
		}
		segs := strings.Split(strings.TrimRight(ref, "/"), "/")
		add(segs[len(segs)-1])
	}
	return names
}

// candidateMatchNames are the normalized forms a proposal candidate may
// carry: the plain name plus, for PURL candidates, name and namespace/name.
func candidateMatchNames(candidate string) map[string]bool {
	names := map[string]bool{}
	if p, ok := parsePURL(candidate); ok {
		if n := normalizeMatchName(p.Name); n != "" {
			names[n] = true
		}
		if p.Namespace != "" {
			if n := normalizeMatchName(p.Namespace + "/" + p.Name); n != "" {
				names[n] = true
			}
		}
		return names
	}
	if n := normalizeMatchName(candidate); n != "" {
		names[n] = true
	}
	return names
}

func namesIntersect(a, b map[string]bool) bool {
	for n := range a {
		if b[n] {
			return true
		}
	}
	return false
}

// normalizeMatchID canonicalizes an id/alias for comparison: lowercase with
// non-alphanumeric runs collapsed to a dash, so "ACME Example Service" and
// "acme-example-service" denote the same canonical id.
func normalizeMatchID(s string) string {
	return strings.Trim(normalizeMatchName(s), "-")
}

// normalizeMatchName lowercases, strips ".git", and maps every
// non-alphanumeric character to a dash.
func normalizeMatchName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".git")
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
