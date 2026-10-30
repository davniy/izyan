package affected

import (
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// ticketSubjectMatch reports whether the ticket's declared package path
// names the given advisory entry's version subject: the module itself,
// a package inside the module, or a package path the entry explicitly
// declares or projects from its affected symbols. A ticket package that
// matches no entry cannot be compared — the claim degrades to
// NOT_CHECKED, never to a silent pass.
func ticketSubjectMatch(claim string, e *domain.AffectedModule) bool {
	if domain.PackageInModule(claim, e.Module) {
		return true
	}
	for _, p := range e.AffectedPackages {
		if p.Path == claim {
			return true
		}
	}
	for _, s := range e.AffectedSymbols {
		if s.Package == claim {
			return true
		}
	}
	return false
}

// versionsEqual compares two version strings: canonical semver when both
// sides parse, verbatim equality otherwise (release trains carry
// non-semver spellings like "2.6.0-release").
func versionsEqual(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return a == b
	}
	na, nb := normalizeVersion(a), normalizeVersion(b)
	if na != "" && nb != "" {
		return na == nb
	}
	return a == b
}

// versionToken extracts the trailing version-shaped token of a declared
// version string ("Demo Mesh 2.5.2" -> "2.5.2") for comparison against
// a bare analyzed version. Returns "" when no token qualifies.
func versionToken(s string) string {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) == 0 {
		return ""
	}
	t := fields[len(fields)-1]
	if !strings.ContainsAny(t, "0123456789") {
		return ""
	}
	return t
}

// productVersionsEqual compares the ticket's declared product version
// against the analyzed build's product version. Declared strings may
// embed the product name ("Demo Mesh 2.5.2"); the comparison is equal
// when either the whole strings or their version tokens agree.
func productVersionsEqual(declared, analyzed string) bool {
	if versionsEqual(declared, analyzed) {
		return true
	}
	dt, at := versionToken(declared), versionToken(analyzed)
	if dt == "" || at == "" {
		return false
	}
	return versionsEqual(dt, at)
}

// analyzedProductIdentity names the product release the analyzed build
// carries. The authoritative release graph's main-module entry is the
// primary source (release artifact build info); an operator-supplied
// release module graph carries no main marker, so the fallback matches
// the product module by the source snapshot's own main-module path —
// the same identity the artifact channel prefers. A non-semver or
// devel-shaped version records nothing: it is not a release identity.
// ok=false means the analyzed build's product version is unknown and
// the product axis stays NOT_CHECKED.
func analyzedProductIdentity(relMods, mods []Module) (path, version string, ok bool) {
	productPath := ""
	for _, m := range relMods {
		if m.Main {
			productPath = m.Path
			if v := m.EffectiveVersion(); normalizeVersion(v) != "" {
				return productPath, v, true
			}
		}
	}
	if productPath == "" {
		for _, m := range mods {
			if m.Main {
				productPath = m.Path
				break
			}
		}
	}
	if productPath == "" {
		return "", "", false
	}
	for _, m := range relMods {
		if m.Path != productPath {
			continue
		}
		if v := m.EffectiveVersion(); normalizeVersion(v) != "" {
			return productPath, v, true
		}
	}
	return "", "", false
}

// checkTicketClaims compares the ticket's declared product/package
// versions against what the analysis resolved. It returns the recorded
// check, the limitations to append, and the advisory modules whose
// version-axis conclusion the package-version mismatch refuses (the
// caller blocks the aggregate FALSE only on that path).
//
// Fail-closed for the version axis only: a package-version mismatch
// means the resolved "outside the affected range" conclusion would
// describe a build the ticket is not about, so it may not close. A
// product-version mismatch alone is informational — the version-range
// comparison of an identical package version stays valid.
func checkTicketClaims(vulnID string, ticket *domain.TicketClaims, ticketErr string,
	entries []domain.AffectedModule, entryVer map[*domain.AffectedModule]string,
	relMods, mods []Module) (*domain.TicketCheck, []string) {
	if ticket == nil && ticketErr == "" {
		return nil, nil
	}
	tc := &domain.TicketCheck{
		PackageVersionCheck: domain.TicketCheckNotChecked,
		ProductVersionCheck: domain.TicketCheckNotChecked,
	}
	var lims []string

	if ticketErr != "" || ticket == nil {
		tc.ParseError = domain.TicketReasonInvalid
		detail := ticketErr
		if detail == "" {
			detail = "no claims could be read from the supplied ticket"
		}
		lims = append(lims, fmt.Sprintf(
			"the supplied ticket could not be consumed (%s): %s — the ticket-build identity check degraded to NOT_CHECKED",
			domain.TicketReasonInvalid, detail))
		return tc, lims
	}
	reason := func(r string) {
		for _, s := range tc.Reasons {
			if s == r {
				return
			}
		}
		tc.Reasons = append(tc.Reasons, r)
	}

	// Provenance note: the ticket's advisory ids versus the analyzed
	// advisory. Informational only — a scanner alias list can name
	// aliases the frozen document does not use.
	if len(ticket.AdvisoryIDs) > 0 {
		found := false
		for _, id := range ticket.AdvisoryIDs {
			if strings.EqualFold(strings.TrimSpace(id), vulnID) {
				found = true
				break
			}
		}
		if !found {
			lims = append(lims, fmt.Sprintf(
				"ticket advisory ids %v do not name the analyzed advisory %s — the identity check still ran on the ticket's package/product claims",
				ticket.AdvisoryIDs, vulnID))
		}
	}

	// ---- package-version axis ----
	declaredPkg := strings.TrimSpace(ticket.Package)
	declaredVer := strings.TrimSpace(ticket.PackageVersion)
	tc.Package = declaredPkg
	tc.DeclaredVersion = declaredVer
	switch {
	case declaredPkg == "":
		// No package claim: the axis is silent — nothing to compare.
	case declaredVer == "":
		lims = append(lims, fmt.Sprintf(
			"ticket declares package %q without a version — the package-version identity check cannot run (not checked, not evidence of agreement)",
			declaredPkg))
	default:
		var matched, resolved []*domain.AffectedModule
		for i := range entries {
			e := &entries[i]
			if !ticketSubjectMatch(declaredPkg, e) {
				continue
			}
			matched = append(matched, e)
			if ver := entryVer[e]; ver != "" {
				resolved = append(resolved, e)
			}
		}
		switch {
		case len(matched) == 0:
			lims = append(lims, fmt.Sprintf(
				"ticket package %q matches no evaluated advisory entry — the package-version identity check cannot run (not checked, not evidence of agreement)",
				declaredPkg))
		case len(resolved) == 0:
			lims = append(lims, fmt.Sprintf(
				"ticket declares %s@%s but the analyzed build resolved no version for the matching advisory entr%s — the package-version identity check cannot run (not checked, not evidence of agreement)",
				declaredPkg, declaredVer, plural(len(matched), "y", "ies")))
		default:
			e := resolved[0]
			resVer := entryVer[e]
			tc.ResolvedVersion = resVer
			nt, nr := normalizeVersion(declaredVer), normalizeVersion(resVer)
			switch {
			case nt == "":
				lims = append(lims, fmt.Sprintf(
					"ticket declares %s@%s but %q is not a comparable version — the package-version identity check cannot run (not checked, not evidence of agreement)",
					declaredPkg, declaredVer, declaredVer))
			case nr == "":
				lims = append(lims, fmt.Sprintf(
					"ticket declares %s@%s but the analyzed version %q is not comparable — the package-version identity check cannot run (not checked, not evidence of agreement)",
					declaredPkg, declaredVer, resVer))
			case nt != nr:
				tc.PackageVersionCheck = domain.TicketCheckMismatch
				reason(domain.TicketReasonPackageVersionMismatch)
				for _, m := range resolved {
					tc.BlockedModules = append(tc.BlockedModules, m.Module)
				}
				lims = append(lims, fmt.Sprintf(
					"%s: the ticket declares %s@%s but the analyzed build resolved %s — the version-axis conclusion describes a different build than the ticket's and cannot close for this subject",
					domain.TicketReasonPackageVersionMismatch, declaredPkg, declaredVer, resVer))
			default:
				tc.PackageVersionCheck = domain.TicketCheckMatch
			}
			if nt != "" {
				inside := affectedByRanges(declaredVer, e.AffectedVersions)
				tc.DeclaredVersionInRanges = &inside
				where := "outside"
				if inside {
					where = "inside"
				}
				lims = append(lims, fmt.Sprintf(
					"the ticket declares %s@%s, which is %s the affected ranges of the matching advisory entry — a supporting ticket claim, never a verdict input",
					declaredPkg, declaredVer, where))
			}
		}
	}

	// ---- product-version axis ----
	declaredProdVer := strings.TrimSpace(ticket.ProductVersion)
	tc.DeclaredProduct = declaredProdVer
	switch {
	case declaredProdVer == "":
		// No product claim: silent, like the package axis.
	default:
		pPath, pVer, ok := analyzedProductIdentity(relMods, mods)
		if !ok {
			lims = append(lims, fmt.Sprintf(
				"ticket declares product version %q but the analyzed build's product identity is unknown (no release main module in the release graph or release metadata) — the product-version check cannot run (not checked, not evidence of agreement)",
				declaredProdVer))
			break
		}
		tc.AnalyzedProduct = pPath + "@" + pVer
		if !productVersionsEqual(declaredProdVer, pVer) {
			tc.ProductVersionCheck = domain.TicketCheckMismatch
			reason(domain.TicketReasonAnalyzedBuildMismatch)
			lims = append(lims, fmt.Sprintf(
				"%s: the ticket declares product version %q but the analyzed build identifies as %s@%s — informational only: an identical package version keeps the version-range comparison valid, and the product axis alone never blocks the version axis",
				domain.TicketReasonAnalyzedBuildMismatch, declaredProdVer, pPath, pVer))
		} else {
			tc.ProductVersionCheck = domain.TicketCheckMatch
		}
	}
	return tc, lims
}

// plural picks the singular/plural suffix for an entry count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
