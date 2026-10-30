package triage

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CatalogEntry is one admitted repository or material source. It is the
// deterministic component/product match surface for intake validation; the
// triage-site.v1 loader populates it from site config.
type CatalogEntry struct {
	ID                    string   `json:"id" yaml:"id"`
	Kind                  string   `json:"kind" yaml:"kind"`
	Locator               string   `json:"locator,omitempty" yaml:"locator,omitempty"`
	Root                  string   `json:"root,omitempty" yaml:"root,omitempty"`
	CredentialRef         string   `json:"credential_ref,omitempty" yaml:"credential_ref,omitempty"`
	ReleasePolicy         string   `json:"release_policy,omitempty" yaml:"release_policy,omitempty"`
	Ecosystem             string   `json:"ecosystem,omitempty" yaml:"ecosystem,omitempty"`
	Aliases               []string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	AvailabilityPolicy    string   `json:"availability_policy,omitempty" yaml:"availability_policy,omitempty"`
	MaterializationPolicy string   `json:"materialization_policy,omitempty" yaml:"materialization_policy,omitempty"`
}

// Catalog is the bounded set of admitted sources. Intake validation only
// reads it; it never mutates or extends it. Lookup and the component →
// product → hint precedence match live in catalog.go.
type Catalog struct {
	Entries []CatalogEntry `json:"entries" yaml:"entries"`
}

// Lookup finds an entry by exact id.
func (c Catalog) Lookup(id string) (CatalogEntry, bool) {
	for _, e := range c.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

var (
	reIntakeGO   = regexp.MustCompile(`(?i)\bGO-\d{4}-\d+\b`)
	reIntakeCVE  = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	reIntakeGHSA = regexp.MustCompile(`(?i)\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b`)
	reIntakeBDU  = regexp.MustCompile(`(?i)\bBDU:\d{4}-\d+\b`)

	reIntakeVersion  = regexp.MustCompile(`^[vV]?\d[\w.\-+]*$`)
	reIntakeRelease  = regexp.MustCompile(`^[vV]?\d[\w.\-+]*$`)
	reIntakeGoVer    = regexp.MustCompile(`^go1\.\d+(\.\d+)?([-.][0-9A-Za-z.]+)?$`)
	reIntakeSeverity = regexp.MustCompile(`(?i)(?:severity|priority|критичность|приоритет)[\s"']*[:=][\s"']*([a-zA-Z]+)`)
)

// canonicalVulnID normalizes an identifier to its canonical spelling —
// uppercase, except the GHSA suffix which is lowercase per GHSA convention.
func canonicalVulnID(s string) string {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "GHSA-") && len(s) > 5 {
		return "GHSA-" + strings.ToLower(s[5:])
	}
	return upper
}

func isVulnIDFormat(s string) bool {
	return reIntakeGO.MatchString(s) || reIntakeCVE.MatchString(s) ||
		reIntakeGHSA.MatchString(s) || reIntakeBDU.MatchString(s)
}

// extractVulnIDs deterministically scans the raw document for identifiers —
// the provenance baseline every proposed ID is checked against.
func extractIntakeVulnIDs(s string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(matches []string) {
		for _, m := range matches {
			c := canonicalVulnID(m)
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	add(reIntakeGO.FindAllString(s, -1))
	add(reIntakeCVE.FindAllString(s, -1))
	add(reIntakeGHSA.FindAllString(s, -1))
	add(reIntakeBDU.FindAllString(s, -1))
	return out
}

// normalizedContains reports whether needle appears in haystack after
// stripping everything but alphanumerics — so "CVE-2099-0001" matches
// "cve_2099_0001", "CVE 2099 0001" and a JSON-escaped occurrence alike.
func normalizedContains(haystack, needle string) bool {
	return strings.Contains(alnumLower(haystack), alnumLower(needle))
}

func alnumLower(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}

// versionMentioned reports whether the raw document states this version for
// the given package name or on its own — "<pkg>@<ver>", "v<ver>" and bare
// tokens all count, with or without the leading "v".
func versionMentioned(rawText, pkgName, version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	core := strings.TrimPrefix(strings.ToLower(v), "v")
	rawLow := strings.ToLower(rawText)
	if pkgName != "" {
		re := regexp.MustCompile(regexp.QuoteMeta(strings.ToLower(pkgName)) + `@v?([0-9][\w.\-+]*)`)
		for _, m := range re.FindAllStringSubmatch(rawLow, -1) {
			if strings.TrimPrefix(m[1], "v") == core {
				return true
			}
		}
	}
	ver := regexp.MustCompile(`\bv?` + regexp.QuoteMeta(core) + `\b`)
	return ver.MatchString(rawLow)
}

// textVersionOfPackage returns the version pinned to pkgName verbatim in
// the raw document ("<pkg>@<ver>", including inside a PURL), or "".
func textVersionOfPackage(rawText, pkgName string) string {
	if pkgName == "" {
		return ""
	}
	re := regexp.MustCompile(regexp.QuoteMeta(strings.ToLower(pkgName)) + `@v?([0-9][\w.\-+]*)`)
	if m := re.FindStringSubmatch(strings.ToLower(rawText)); m != nil {
		return m[1]
	}
	return ""
}

type purlParts struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers string
	Subpath    string
}

// parsePURL parses a strict subset of the Package URL spec enough for
// consistency checks: pkg:type/namespace/name@version?qualifiers#subpath.
func parsePURL(s string) (purlParts, bool) {
	var p purlParts
	rest := strings.TrimSpace(s)
	if !strings.HasPrefix(rest, "pkg:") {
		return p, false
	}
	rest = rest[len("pkg:"):]
	if i := strings.Index(rest, "#"); i >= 0 {
		p.Subpath = rest[i+1:]
		rest = rest[:i]
		if p.Subpath == "" {
			return p, false
		}
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		p.Qualifiers = rest[i+1:]
		rest = rest[:i]
		if p.Qualifiers == "" {
			return p, false
		}
	}
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return p, false
	}
	p.Type = strings.ToLower(rest[:slash])
	rest = rest[slash+1:]
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		p.Version = rest[at+1:]
		rest = rest[:at]
		if p.Version == "" {
			return p, false
		}
	}
	segs := strings.Split(rest, "/")
	if len(segs) == 0 || segs[len(segs)-1] == "" {
		return p, false
	}
	p.Name = segs[len(segs)-1]
	if len(segs) > 1 {
		p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	}
	if p.Name == "" {
		return p, false
	}
	return p, true
}

var intakeSeverityRank = map[string]int{
	"none": 0, "negligible": 0,
	"low":    1,
	"medium": 2, "moderate": 2,
	"high":     3,
	"critical": 4,
}

// textSeverity returns the highest severity claimed by a labeled
// "severity|priority|критичность" mention in the document — the only
// authoritative severity baseline available at intake time.
func textSeverity(rawText string) (string, int) {
	best, bestRank := "", -1
	for _, m := range reIntakeSeverity.FindAllStringSubmatch(rawText, -1) {
		token := strings.ToLower(m[1])
		if rank, ok := intakeSeverityRank[token]; ok && rank > bestRank {
			best, bestRank = token, rank
		}
	}
	return best, bestRank
}

// purlEcosystem maps a PURL type to the ecosystem naming used by catalog
// entries; the second result reports whether the type is known.
func purlEcosystem(purlType string) (string, bool) {
	switch purlType {
	case "golang":
		return "go", true
	case "godep", "gomod":
		return "go", true
	}
	return purlType, true
}

// ValidateIntakeProposal is the deterministic §4.2 gate: it confirms or
// rejects every extracted field against the raw record, the supplied
// advisory IDs and the catalog — never trusting the LLM output itself.
// Non-VALID statuses on decision-relevant fields forbid DISMISSED/LOWERED
// downstream; absent optional fields are UNAVAILABLE limitations, not
// negative facts.
var trailingProductVersion = regexp.MustCompile(`(?i)\s+(v?\d+(?:\.\d+)+(?:[-+][[:alnum:]._-]+)?)\s*$`)

func normalizeNameVersion(value string) (name, version string, changed bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	m := trailingProductVersion.FindStringSubmatch(value)
	if len(m) == 0 {
		return value, "", false
	}
	name = strings.TrimSpace(value[:len(value)-len(m[0])])
	if name == "" {
		return value, "", false
	}
	return name, m[1], true
}

func normalizeIntakeProposal(p IntakeProposal) IntakeProposal {
	if p.ComponentVersion == "" {
		if name, version, changed := normalizeNameVersion(p.Component); changed {
			p.Component, p.ComponentVersion = name, version
		}
	}
	if p.ProductVersion == "" {
		if name, version, changed := normalizeNameVersion(p.Product); changed {
			p.Product, p.ProductVersion = name, version
		}
	}
	if len(p.VulnerabilityIDs) == 0 {
		var ids []string
		for _, a := range p.Aliases {
			c := canonicalVulnID(a)
			if isVulnIDFormat(c) {
				ids = append(ids, c)
			}
		}
		sort.SliceStable(ids, func(i, j int) bool { return vulnIDRank(ids[i]) < vulnIDRank(ids[j]) })
		p.VulnerabilityIDs = ids
	}
	return p
}

func vulnIDRank(id string) int {
	u := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(u, "CVE-"):
		return 0
	case strings.HasPrefix(u, "GHSA-"):
		return 1
	case strings.HasPrefix(u, "GO-"):
		return 2
	case strings.HasPrefix(u, "BDU:"):
		return 3
	default:
		return 4
	}
}

func ValidateIntakeProposal(
	raw RawIntake,
	proposal IntakeProposal,
	advisoryIDs []string,
	catalog Catalog,
) IntakeValidation {
	var v IntakeValidation
	proposal = normalizeIntakeProposal(proposal)
	rawText := string(raw.Raw)
	if len(raw.Raw) == 0 {
		v.Errors = append(v.Errors, "empty intake record")
	}
	if len(proposal.VulnerabilityIDs) == 0 {
		v.Errors = append(v.Errors, "no vulnerability identifier available")
	}
	if strings.TrimSpace(proposal.Component) == "" && strings.TrimSpace(proposal.Product) == "" {
		v.Errors = append(v.Errors, "no component or product target available")
	}
	advisorySet := map[string]bool{}
	for _, id := range advisoryIDs {
		advisorySet[canonicalVulnID(id)] = true
	}
	textIDSet := map[string]bool{}
	for _, id := range extractIntakeVulnIDs(rawText) {
		textIDSet[id] = true
	}

	v.Fields = append(v.Fields, validateIDField(rawText, proposal.VulnerabilityIDs, textIDSet, advisorySet)...)
	v.Fields = append(v.Fields, validateAliasFields(rawText, proposal, textIDSet, advisorySet)...)

	purl, purlOK := parsePURL(proposal.Package)
	v.Fields = append(v.Fields, validatePackageField(rawText, proposal, purl, purlOK))
	v.Fields = append(v.Fields, validateVersionField(rawText, proposal, purl, purlOK))

	compFV, compEntry := validateCatalogField("component", proposal.Component, catalog)
	prodFV, _ := validateCatalogField("product", proposal.Product, catalog)
	// PURL consistency: a package PURL ecosystem must agree with the matched
	// component entry's ecosystem.
	if compFV.Status == IntakeValid && purlOK && compEntry.Ecosystem != "" {
		if eco, _ := purlEcosystem(purl.Type); !strings.EqualFold(eco, compEntry.Ecosystem) {
			compFV.Status = IntakeConflicting
			compFV.Reason = fmt.Sprintf("package PURL ecosystem %q disagrees with catalog entry %q ecosystem %q", purl.Type, compEntry.ID, compEntry.Ecosystem)
		}
	}
	v.Fields = append(v.Fields, compFV, prodFV)
	v.Fields = append(v.Fields, normalizedVersionField("component_version", proposal.ComponentVersion))
	v.Fields = append(v.Fields, normalizedVersionField("product_version", proposal.ProductVersion))
	v.Fields = append(v.Fields, validateReleaseField(rawText, proposal.Release))
	v.Fields = append(v.Fields, validateGoVersionField(rawText, proposal.GoVersion))
	v.Fields = append(v.Fields, validateSeverityField(rawText, proposal.Severity))
	v.Fields = append(v.Fields, validateSummaryField(proposal.Summary))
	v.Fields = append(v.Fields, validateSourceHints(proposal.SourceHints, catalog)...)
	v.Fields = append(v.Fields, validateRefHint(proposal.RefHint))

	for i := range v.Fields {
		fv := &v.Fields[i]
		// Only fields that can ground a decision fact may block a risk
		// reduction. Hint fields — an LLM summary, source/ref hints, a
		// version split out of a component name, an absent severity — are
		// never authoritative by construction, so an unverified hint is a
		// recorded limitation, not a gate.
		fv.BlocksRiskReduction = fv.Status != IntakeValid && fv.Status != IntakeUnavailable && !hintField(fv.Field)
		if fv.Field == "vulnerability_ids" && fv.Status == IntakeUnavailable {
			fv.BlocksRiskReduction = true
		}
		// A severity that conflicts with the raw record must never be
		// accepted as a downgrade: it would loosen the false-safe
		// tolerance ladder. An absent or merely unverified severity is a
		// hint the baseline resolves from the advisory or the configured
		// default instead.
		if fv.Field == "severity" && fv.Status == IntakeConflicting {
			fv.BlocksRiskReduction = true
		}
		switch fv.Status {
		case IntakeInvalid:
			if fv.Field == "vulnerability_ids" {
				v.Errors = append(v.Errors, fmt.Sprintf("field %s invalid: %s", fv.Field, fv.Reason))
			} else {
				v.Limitations = append(v.Limitations, fmt.Sprintf("field %s invalid: %s", fv.Field, fv.Reason))
			}
		case IntakeConflicting:
			v.Limitations = append(v.Limitations, fmt.Sprintf("field %s conflicting: %s", fv.Field, fv.Reason))
		case IntakeUnverified:
			v.Limitations = append(v.Limitations, fmt.Sprintf("field %s unverified: %s", fv.Field, fv.Reason))
		case IntakeUnavailable:
			v.Limitations = append(v.Limitations, fmt.Sprintf("field %s unavailable", fv.Field))
		}
	}
	return v
}

func validateIDField(rawText string, ids []string, textIDSet, advisorySet map[string]bool) []FieldValidation {
	if len(ids) == 0 {
		return []FieldValidation{{
			Field:  "vulnerability_ids",
			Status: IntakeUnavailable,
			Reason: "no vulnerability identifier proposed",
		}}
	}
	canonical := map[string]int{}
	var order []string
	malformed := ""
	for _, id := range ids {
		c := canonicalVulnID(id)
		if !isVulnIDFormat(c) {
			malformed = strings.TrimSpace(id)
			continue
		}
		if _, ok := canonical[c]; !ok {
			order = append(order, c)
		}
		canonical[c]++
	}
	if malformed != "" {
		return []FieldValidation{{
			Field:  "vulnerability_ids",
			Status: IntakeInvalid,
			Value:  malformed,
			Reason: "malformed vulnerability identifier",
		}}
	}
	if len(order) > 1 {
		var confirmed []string
		for _, id := range order {
			if textIDSet[id] || normalizedContains(rawText, id) || advisorySet[id] {
				confirmed = append(confirmed, id)
			}
		}
		if len(confirmed) == 1 {
			order = confirmed
		} else if len(confirmed) == len(order) {
			bestRank := 99
			for _, id := range confirmed {
				if r := vulnIDRank(id); r < bestRank {
					bestRank = r
				}
			}
			var top []string
			for _, id := range confirmed {
				if vulnIDRank(id) == bestRank {
					top = append(top, id)
				}
			}
			if len(top) == 1 {
				primary := top[0]
				var aliases []string
				for _, id := range confirmed {
					if id != primary {
						aliases = append(aliases, id)
					}
				}
				var provenance []string
				if textIDSet[primary] || normalizedContains(rawText, primary) {
					provenance = append(provenance, "raw_text")
				}
				if advisorySet[primary] {
					provenance = append(provenance, "advisory")
				}
				return []FieldValidation{{Field: "vulnerability_ids", Status: IntakeValid, Value: primary, Reason: fmt.Sprintf("primary chosen by class priority from confirmed aliases: %s", strings.Join(aliases, ", ")), Provenance: provenance, Aliases: aliases}}
			}
		}
	}
	if len(order) > 1 {
		return []FieldValidation{{
			Field:  "vulnerability_ids",
			Status: IntakeConflicting,
			Value:  strings.Join(order, ","),
			Reason: "multiple distinct vulnerability IDs; primary is ambiguous",
		}}
	}
	c := order[0]
	if canonical[c] > 1 {
		return []FieldValidation{{
			Field:  "vulnerability_ids",
			Status: IntakeConflicting,
			Value:  c,
			Reason: "duplicate vulnerability identifier in proposal",
		}}
	}
	var provenance []string
	if textIDSet[c] || normalizedContains(rawText, c) {
		provenance = append(provenance, "raw_text")
	}
	if advisorySet[c] {
		provenance = append(provenance, "advisory")
	}
	if len(provenance) > 0 {
		return []FieldValidation{{
			Field:      "vulnerability_ids",
			Status:     IntakeValid,
			Value:      c,
			Provenance: provenance,
		}}
	}
	return []FieldValidation{{
		Field:      "vulnerability_ids",
		Status:     IntakeUnverified,
		Value:      c,
		Reason:     "id absent from raw document and supplied advisories",
		Provenance: []string{"llm"},
	}}
}

func validateAliasFields(rawText string, proposal IntakeProposal, textIDSet, advisorySet map[string]bool) []FieldValidation {
	if len(proposal.Aliases) == 0 {
		return []FieldValidation{{
			Field:  "aliases",
			Status: IntakeUnavailable,
			Reason: "no aliases proposed",
		}}
	}
	primarySet := map[string]bool{}
	for _, id := range proposal.VulnerabilityIDs {
		primarySet[canonicalVulnID(id)] = true
	}
	var out []FieldValidation
	for _, a := range proposal.Aliases {
		c := canonicalVulnID(a)
		fv := FieldValidation{Field: "aliases", Value: c}
		switch {
		case !isVulnIDFormat(c):
			fv.Status = IntakeInvalid
			fv.Reason = "malformed alias identifier"
		case primarySet[c]:
			fv.Status = IntakeConflicting
			fv.Reason = "alias restates the canonical vulnerability id"
		default:
			if textIDSet[c] || normalizedContains(rawText, c) {
				fv.Provenance = append(fv.Provenance, "raw_text")
			}
			if advisorySet[c] {
				fv.Provenance = append(fv.Provenance, "advisory")
			}
			if len(fv.Provenance) > 0 {
				fv.Status = IntakeValid
			} else {
				fv.Status = IntakeUnverified
				fv.Reason = "alias absent from raw document and supplied advisories"
				fv.Provenance = []string{"llm"}
			}
		}
		out = append(out, fv)
	}
	return out
}

func normalizeIntakePackage(rawText, pkg string) string {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" || strings.HasPrefix(pkg, "pkg:") || strings.Contains(pkg, "/") {
		return pkg
	}
	lower := strings.ToLower(rawText)
	re := regexp.MustCompile(`\b([a-z0-9][a-z0-9.-]*(?:\.[a-z0-9-]+)+/[a-z0-9./_-]+/` + regexp.QuoteMeta(strings.ToLower(pkg)) + `)\b`)
	paths := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(lower, -1) {
		paths[strings.TrimSuffix(m[1], "/")] = struct{}{}
	}
	var candidates []string
	for path := range paths {
		candidates = append(candidates, path)
	}
	sort.Strings(candidates)
	switch len(candidates) {
	case 1:
		return candidates[0]
	case 0:
		return pkg
	default:
		return "ambiguous:" + strings.Join(candidates, ",")
	}
}

func validatePackageField(rawText string, proposal IntakeProposal, purl purlParts, purlOK bool) FieldValidation {
	fv := FieldValidation{Field: "package", Value: proposal.Package}
	pkg := strings.TrimSpace(proposal.Package)
	if pkg == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no package context proposed"
		return fv
	}
	if strings.HasPrefix(pkg, "pkg:") {
		if !purlOK {
			fv.Status = IntakeInvalid
			fv.Reason = "malformed package URL"
			return fv
		}
		if purl.Version != "" && proposal.Version != "" &&
			strings.TrimPrefix(strings.ToLower(purl.Version), "v") != strings.TrimPrefix(strings.ToLower(proposal.Version), "v") {
			fv.Status = IntakeConflicting
			fv.Reason = fmt.Sprintf("PURL version %q disagrees with version field %q", purl.Version, proposal.Version)
			return fv
		}
		if normalizedContains(rawText, purl.Name) || normalizedContains(rawText, purl.Namespace+"/"+purl.Name) {
			fv.Status = IntakeValid
			fv.Provenance = []string{"raw_text"}
			return fv
		}
		fv.Status = IntakeUnverified
		fv.Reason = "PURL package name absent from raw document"
		fv.Provenance = []string{"llm"}
		return fv
	}
	normalized := normalizeIntakePackage(rawText, pkg)
	if normalized != pkg {
		fv.Value = normalized
		if strings.HasPrefix(normalized, "ambiguous:") {
			fv.Status = IntakeUnverified
			fv.Reason = "short package name is ambiguous in raw document"
			return fv
		}
		fv.Provenance = []string{"raw_text"}
		fv.Status = IntakeValid
		fv.Reason = "package name normalized to a full module path from raw document"
		return fv
	}
	if normalizedContains(rawText, pkg) {
		fv.Status = IntakeValid
		fv.Provenance = []string{"raw_text"}
		return fv
	}
	fv.Status = IntakeUnverified
	fv.Reason = "package absent from raw document and advisories"
	fv.Provenance = []string{"llm"}
	return fv
}

func validateVersionField(rawText string, proposal IntakeProposal, purl purlParts, purlOK bool) FieldValidation {
	fv := FieldValidation{Field: "version", Value: proposal.Version}
	version := strings.TrimSpace(proposal.Version)
	if version == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no version proposed"
		return fv
	}
	if !reIntakeVersion.MatchString(version) {
		fv.Status = IntakeInvalid
		fv.Reason = "malformed version syntax"
		return fv
	}
	pkgNames := []string{""}
	if purlOK {
		if purl.Namespace != "" {
			pkgNames = append(pkgNames, purl.Namespace+"/"+purl.Name)
		}
		pkgNames = append(pkgNames, purl.Name)
		if purl.Version != "" &&
			canonicalSemver(strings.TrimPrefix(strings.ToLower(purl.Version), "v")) != canonicalSemver(strings.TrimPrefix(strings.ToLower(version), "v")) {
			fv.Status = IntakeConflicting
			fv.Reason = fmt.Sprintf("version %q conflicts with package PURL version %q", version, purl.Version)
			return fv
		}
	} else if proposal.Package != "" {
		pkgNames = append(pkgNames, proposal.Package)
	}
	for _, name := range pkgNames[1:] {
		if tv := textVersionOfPackage(rawText, name); tv != "" &&
			canonicalSemver(strings.TrimPrefix(strings.ToLower(tv), "v")) != canonicalSemver(strings.TrimPrefix(strings.ToLower(version), "v")) {
			fv.Status = IntakeConflicting
			fv.Reason = fmt.Sprintf("version %q conflicts with %s@%s in raw document", version, name, tv)
			return fv
		}
	}
	for _, name := range pkgNames {
		if versionMentioned(rawText, name, version) {
			fv.Status = IntakeValid
			fv.Provenance = []string{"raw_text"}
			return fv
		}
	}
	if normalizedContains(rawText, version) {
		fv.Status = IntakeValid
		fv.Provenance = []string{"raw_text"}
		return fv
	}
	fv.Status = IntakeUnverified
	fv.Reason = "version absent from raw document and advisories"
	fv.Provenance = []string{"llm"}
	return fv
}

func validateCatalogField(field, candidate string, catalog Catalog) (FieldValidation, CatalogEntry) {
	fv := FieldValidation{Field: field, Value: candidate}
	cand := strings.TrimSpace(candidate)
	if cand == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no candidate proposed"
		return fv, CatalogEntry{}
	}
	entry, status, _ := catalog.matchName(cand)
	fv.Status = status
	switch status {
	case IntakeValid:
		fv.Reason = fmt.Sprintf("matched catalog entry %q", entry.ID)
		fv.Provenance = []string{"catalog"}
	case IntakeConflicting:
		fv.Reason = "candidate matches multiple catalog entries at the same precedence"
	default:
		fv.Reason = "no catalog entry matches the proposed candidate"
		fv.Provenance = []string{"llm"}
	}
	return fv, entry
}

func validateReleaseField(rawText, release string) FieldValidation {
	fv := FieldValidation{Field: "release", Value: release}
	rel := strings.TrimSpace(release)
	if rel == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no release proposed"
		return fv
	}
	if !reIntakeRelease.MatchString(rel) {
		fv.Status = IntakeUnverified
		fv.Reason = "release value is a type marker or free text, not a release version"
		fv.Provenance = []string{"llm"}
		return fv
	}
	if normalizedContains(rawText, rel) {
		fv.Status = IntakeValid
		fv.Provenance = []string{"raw_text"}
		return fv
	}
	fv.Status = IntakeUnverified
	fv.Reason = "release absent from raw document"
	fv.Provenance = []string{"llm"}
	return fv
}

func normalizedVersionField(field, value string) FieldValidation {
	fv := FieldValidation{Field: field, Value: value}
	if strings.TrimSpace(value) == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no version suffix proposed"
		return fv
	}
	if !reIntakeVersion.MatchString(value) {
		fv.Status = IntakeInvalid
		fv.Reason = "malformed version suffix"
		return fv
	}
	fv.Status = IntakeUnverified
	fv.Reason = "version separated from base name by deterministic normalization"
	fv.Provenance = []string{"llm_normalization"}
	return fv
}

func validateGoVersionField(rawText, goVersion string) FieldValidation {
	fv := FieldValidation{Field: "go_version", Value: goVersion}
	gv := strings.TrimSpace(goVersion)
	if gv == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no go version proposed"
		return fv
	}
	if !reIntakeGoVer.MatchString(gv) {
		fv.Status = IntakeInvalid
		fv.Reason = "malformed go version; want go1.x[.y]"
		return fv
	}
	if normalizedContains(rawText, gv) {
		fv.Status = IntakeValid
		fv.Provenance = []string{"raw_text"}
		return fv
	}
	fv.Status = IntakeUnverified
	fv.Reason = "go version absent from raw document"
	fv.Provenance = []string{"llm"}
	return fv
}

// validateSeverityField enforces the §4.2 severity rule: a claimed severity
// must be a known token and must not contradict the document's labeled
// severity — raising it above the stated value is impossible, and silently
// lowering it conflicts too. Without a stated severity the LLM value stays
// UNVERIFIED; an absent severity is UNAVAILABLE, never a negative fact.
func validateSeverityField(rawText, severity string) FieldValidation {
	fv := FieldValidation{Field: "severity", Value: severity}
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no severity proposed"
		return fv
	}
	rank, known := intakeSeverityRank[sev]
	if !known {
		fv.Status = IntakeInvalid
		fv.Reason = "unknown severity token"
		return fv
	}
	textSev, textRank := textSeverity(rawText)
	if textRank < 0 {
		fv.Status = IntakeUnverified
		fv.Reason = "no labeled severity in raw document"
		fv.Provenance = []string{"llm"}
		return fv
	}
	if rank != textRank {
		dir := "above"
		if rank < textRank {
			dir = "below"
		}
		fv.Status = IntakeConflicting
		fv.Reason = fmt.Sprintf("severity %q is %s the severity %q stated in the document", sev, dir, textSev)
		return fv
	}
	fv.Status = IntakeValid
	fv.Provenance = []string{"raw_text"}
	return fv
}

func validateSummaryField(summary string) FieldValidation {
	fv := FieldValidation{Field: "summary", Value: summary}
	if strings.TrimSpace(summary) == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no summary proposed"
		return fv
	}
	fv.Status = IntakeUnverified
	fv.Reason = "LLM prose is not self-confirming"
	fv.Provenance = []string{"llm"}
	return fv
}

func validateSourceHints(hints []string, catalog Catalog) []FieldValidation {
	if len(hints) == 0 {
		return []FieldValidation{{
			Field:  "source_hints",
			Status: IntakeUnavailable,
			Reason: "no source hints proposed",
		}}
	}
	var out []FieldValidation
	for _, h := range hints {
		h = strings.TrimSpace(h)
		fv := FieldValidation{Field: "source_hints", Value: h}
		if h == "" {
			continue
		}
		if _, ok := catalog.Lookup(h); ok {
			fv.Status = IntakeValid
			fv.Provenance = []string{"catalog"}
		} else {
			fv.Status = IntakeUnverified
			fv.Reason = "hint is not a catalog entry id"
			fv.Provenance = []string{"llm"}
		}
		out = append(out, fv)
	}
	return out
}

func validateRefHint(refHint string) FieldValidation {
	fv := FieldValidation{Field: "ref_hint", Value: refHint}
	if strings.TrimSpace(refHint) == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no ref hint proposed"
		return fv
	}
	// Bounded ref lists do not exist at intake time; a hint stays a hint.
	fv.Status = IntakeUnverified
	fv.Reason = "ref hint needs the bounded candidate list (ref enumeration)"
	fv.Provenance = []string{"llm"}
	return fv
}

// hintFields are the proposal fields that can never ground a decision fact:
// they are hints the deterministic checks confirm or discard elsewhere, so
// their validation status is a limitation, never a gate.
var hintFields = map[string]bool{
	"aliases":           true,
	"summary":           true,
	"source_hints":      true,
	"ref_hint":          true,
	"go_version":        true,
	"component_version": true,
	"product_version":   true,
	"release":           true,
	"severity":          true,
}

func hintField(name string) bool { return hintFields[name] }

// canonicalSemver strips the semver build-metadata suffix (+incompatible,
// +<build>) before comparing versions: build metadata never changes
// precedence, and a Go module's +incompatible marker is not a different
// upstream version from the same release without a go.mod.
func canonicalSemver(v string) string {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		return v[:i]
	}
	return v
}
