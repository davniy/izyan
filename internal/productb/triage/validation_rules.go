package triage

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/toolchain"
)

// AdvisoryProjection is the deterministic view of the frozen advisory the
// material checks need: which modules it affects and over which version
// ranges. It carries no prose and no unbounded document.
type AdvisoryProjection struct {
	Module           string                   `json:"module,omitempty"`
	Package          string                   `json:"package,omitempty"`
	AffectedVersions []domain.VersionRange    `json:"affected_versions,omitempty"`
	FixedVersions    []string                 `json:"fixed_versions,omitempty"`
	AffectedPackages []domain.AffectedPackage `json:"affected_packages,omitempty"`
	AffectedModules  []domain.AffectedModule  `json:"affected_modules,omitempty"`
	// AffectedSymbols carries the advisory's declared vulnerable symbols
	// (bounded extraction: see vulnerability doc bounds) — an agent hint
	// only, never an applicability fact.
	AffectedSymbols []domain.SymbolRef `json:"affected_symbols,omitempty"`
}

// AdvisoryProjectionFromVulnerability projects a domain vulnerability record
// onto the check surface.
func AdvisoryProjectionFromVulnerability(v domain.Vulnerability) AdvisoryProjection {
	return AdvisoryProjection{
		Module:           v.Module,
		Package:          v.Package,
		AffectedVersions: v.AffectedVersions,
		FixedVersions:    v.FixedVersions,
		AffectedPackages: v.AffectedPackages,
		AffectedModules:  v.AffectedModules,
		AffectedSymbols:  v.AffectedSymbols,
	}
}

// moduleEntries returns the advisory's per-module affected entries,
// synthesizing a single entry from the flat fields — same contract as
// affected.affectedModuleEntries.
func (a AdvisoryProjection) moduleEntries() []domain.AffectedModule {
	if len(a.AffectedModules) > 0 {
		return a.AffectedModules
	}
	if a.Module == "" {
		return nil
	}
	pkgs := a.AffectedPackages
	if len(pkgs) == 0 && a.Package != "" {
		pkgs = []domain.AffectedPackage{{Path: a.Package}}
	}
	return []domain.AffectedModule{{
		Module:           a.Module,
		AffectedVersions: a.AffectedVersions,
		FixedVersions:    a.FixedVersions,
		AffectedPackages: pkgs,
	}}
}

// rangesFor merges the affected version ranges of every advisory entry that
// names module path (effective path or basename).
func (a AdvisoryProjection) rangesFor(path string) []domain.VersionRange {
	var out []domain.VersionRange
	for _, e := range a.moduleEntries() {
		if e.Module == path {
			out = append(out, e.AffectedVersions...)
		}
	}
	return out
}

// namesModule reports whether the advisory names this module at all — for
// claims, basename equality counts (the advisory's path is authoritative).
func (a AdvisoryProjection) namesModule(claim string) (string, bool) {
	for _, e := range a.moduleEntries() {
		if e.Module == claim {
			return e.Module, true
		}
		if i := strings.LastIndex(e.Module, "/"); i >= 0 && e.Module[i+1:] == claim {
			return e.Module, true
		}
	}
	return "", false
}

// PackageCheckClass is the deterministic classification of a claimed
// package/version against the snapshot's module graph. MODULE_ABSENT and
// VERSION_MISMATCH are facts about the graph — never proof the product is
// unaffected.
type PackageCheckClass string

const (
	// CheckVersionConfirmed: the claim resolved and the claimed version
	// matches the snapshot's resolved version (outside declared advisory
	// ranges or with none declared).
	CheckVersionConfirmed PackageCheckClass = "VERSION_CONFIRMED"
	// CheckAffectedRange: the resolved version falls inside an advisory
	// affected range for that module.
	CheckAffectedRange PackageCheckClass = "VERSION_IN_AFFECTED_RANGE"
	// CheckVersionMismatch: the module resolves at a different version than
	// claimed — a conflict, not an absence.
	CheckVersionMismatch PackageCheckClass = "VERSION_MISMATCH"
	// CheckModuleAbsent: the module is absent from a complete build graph —
	// a fact about this build, never a safety proof.
	CheckModuleAbsent PackageCheckClass = "MODULE_ABSENT"
	// CheckUnresolved: presence or version is undecidable (no module data,
	// incomplete graph, ambiguous or non-attributable claim).
	CheckUnresolved PackageCheckClass = "UNRESOLVED"
)

// PackageCheckResult is the deterministic fact record of
// CheckPackageVersion.
type PackageCheckResult struct {
	Class           PackageCheckClass `json:"class"`
	ClaimedPath     string            `json:"claimed_path,omitempty"`
	ClaimedVersion  string            `json:"claimed_version,omitempty"`
	ResolvedPath    string            `json:"resolved_path,omitempty"`
	ResolvedVersion string            `json:"resolved_version,omitempty"`
	EvidenceSource  string            `json:"evidence_source,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Provenance      []string          `json:"provenance,omitempty"`
	Limitations     []string          `json:"limitations,omitempty"`
}

// packageClaim is the normalized package claim extracted from an intake
// proposal: a Go module/package path plus the claimed version. Malformed
// claims and PURL-internal version disagreements are recorded, never
// silently repaired.
type packageClaim struct {
	Path            string
	Version         string
	Malformed       bool
	VersionConflict bool
	Ecosystem       string
}

// parsePackageClaim normalizes proposal.Package: PURL inputs decode to
// namespace/name@version; anything else is a module path or a bare module
// name (a hint, resolved conservatively downstream).
func parsePackageClaim(p IntakeProposal) packageClaim {
	var c packageClaim
	c.Version = strings.TrimSpace(p.Version)
	raw := strings.TrimSpace(p.Package)
	if raw == "" {
		return c
	}
	if !strings.HasPrefix(raw, "pkg:") {
		c.Path = raw
		return c
	}
	purl, ok := parsePURL(raw)
	if !ok {
		c.Malformed = true
		return c
	}
	c.Ecosystem = purl.Type
	c.Path = purl.Name
	if purl.Namespace != "" {
		c.Path = purl.Namespace + "/" + purl.Name
	}
	if purl.Version != "" {
		if c.Version != "" &&
			strings.TrimPrefix(strings.ToLower(purl.Version), "v") != strings.TrimPrefix(strings.ToLower(c.Version), "v") {
			c.VersionConflict = true
		} else {
			c.Version = purl.Version
		}
	}
	return c
}

// isStdlibClaim reports whether the claimed path denotes the Go standard
// library or toolchain pseudo-module — such advisories resolve against the
// release toolchain, not a module dependency.
func isStdlibClaim(path string) bool {
	switch path {
	case "std", "stdlib", "toolchain", "cmd":
		return true
	}
	first := path
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	return !strings.Contains(first, ".")
}

// resolveClaim maps the claim to a module of the graph: an exact path match
// or the longest module prefix owning a package path wins; the advisory's
// own module naming is consulted for bare names; a unique basename match is
// the last resort. Nothing resolving leaves the claim unresolved.
func resolveClaim(claim string, g *ModuleGraph, adv AdvisoryProjection) (ModuleVersion, string, bool) {
	if g != nil {
		if mv, ok := g.moduleAt(claim); ok {
			return mv, "module_graph", true
		}
	}
	// The advisory names the module authoritatively; a claim equal to the
	// advisory module (or its basename) resolves to that path when present.
	if advPath, ok := adv.namesModule(claim); ok && advPath != claim {
		if g != nil {
			if mv, found := g.moduleAt(advPath); found {
				return mv, "advisory:module_graph", true
			}
		}
	}
	if g != nil {
		base := claim
		if i := strings.LastIndex(claim, "/"); i >= 0 {
			base = claim[i+1:]
		}
		var hits []ModuleVersion
		for _, mv := range g.Modules {
			modBase := mv.Path
			if i := strings.LastIndex(modBase, "/"); i >= 0 {
				modBase = modBase[i+1:]
			}
			if modBase == base && mv.Path != claim {
				hits = append(hits, mv)
			}
		}
		if len(hits) == 1 {
			return hits[0], "module_graph:basename", true
		}
	}
	return ModuleVersion{}, "", false
}

// CheckPackageVersion is the deterministic package/version fact check: the
// claim is resolved against the snapshot's module graph and the advisory's
// affected ranges. Absence from the build graph and version mismatch are
// facts with provenance — never safety conclusions — and undecidable checks
// stay UNRESOLVED with limitations.
func CheckPackageVersion(proposal IntakeProposal, set MaterialSet, adv AdvisoryProjection, toolchainVer string) PackageCheckResult {
	claim := parsePackageClaim(proposal)
	res := PackageCheckResult{
		ClaimedPath:    claim.Path,
		ClaimedVersion: claim.Version,
	}
	switch {
	case claim.Malformed:
		res.Class = CheckUnresolved
		res.Reason = "malformed package URL"
		res.Limitations = append(res.Limitations, "package claim could not be parsed")
		return res
	case claim.Path == "":
		res.Class = CheckUnresolved
		res.Reason = "no package claim"
		res.Limitations = append(res.Limitations, "package/version check skipped: proposal carries no package")
		return res
	case claim.Ecosystem != "":
		if eco, _ := purlEcosystem(claim.Ecosystem); !strings.EqualFold(eco, "go") {
			res.Class = CheckUnresolved
			res.Reason = fmt.Sprintf("PURL ecosystem %q is not resolvable against a Go module graph", claim.Ecosystem)
			res.Limitations = append(res.Limitations, res.Reason)
			return res
		}
	}

	// stdlib/toolchain claims resolve against the release toolchain version,
	// never the module graph.
	if isStdlibClaim(claim.Path) {
		res.Provenance = []string{"advisory"}
		if strings.TrimSpace(toolchainVer) == "" {
			res.Class = CheckUnresolved
			res.Reason = "stdlib claim requires the release toolchain version"
			res.Limitations = append(res.Limitations,
				"release toolchain unknown: stdlib applicability undecidable (go.mod minimum and local go are not evidence)")
			return res
		}
		res.ResolvedPath = claim.Path
		res.ResolvedVersion = toolchain.Normalize(toolchainVer)
		res.EvidenceSource = "release_toolchain"
		return res.classifyVersion(claim, adv.rangesFor(claim.Path))
	}

	g := set.ModuleGraph
	if g == nil || len(g.Modules) == 0 {
		res.Class = CheckUnresolved
		res.Reason = "no module graph available"
		res.Limitations = append(res.Limitations,
			"module graph unavailable: package presence and version undecidable")
		return res
	}
	res.Provenance = []string{"module_graph:" + g.Source}

	mv, src, ok := resolveClaim(claim.Path, g, adv)
	if !ok {
		if !g.Complete {
			res.Class = CheckUnresolved
			res.Reason = fmt.Sprintf("package %q not found in %s; module list is not a closed build graph", claim.Path, g.Source)
			res.Limitations = append(res.Limitations,
				fmt.Sprintf("module list derived from %s; absence undecidable", g.Source))
			return res
		}
		res.Class = CheckModuleAbsent
		res.EvidenceSource = g.Source
		res.Reason = fmt.Sprintf("module for %q absent from the snapshot build graph (%s)", claim.Path, g.Source)
		res.Limitations = append(res.Limitations,
			"module absence is a fact about this build graph, not proof the product is unaffected")
		return res
	}
	res.ResolvedPath = mv.Path
	res.ResolvedVersion = mv.Version
	res.EvidenceSource = g.Source
	res.Provenance = []string{"module_graph:" + src}

	// Package-level absence is decidable only when the claim names an
	// import path strictly inside the resolved module and the linked
	// import set is known; a basename-resolved module shorthand is a
	// module claim, not an import path.
	claimIsPkg := strings.HasPrefix(claim.Path, mv.Path+"/")
	if claimIsPkg && g.Linked != nil {
		if !g.Linked[claim.Path] {
			res.Class = CheckModuleAbsent
			res.Reason = fmt.Sprintf("package %q absent from the linked import set (module %s present at %s)",
				claim.Path, mv.Path, mv.Version)
			res.Limitations = append(res.Limitations,
				"package absence covers this build's import set only; build-tag-excluded files and plugins are not covered")
			return res
		}
	} else if claimIsPkg && g.Linked == nil {
		res.Limitations = append(res.Limitations,
			"package-level linkage unverified: no import list; version reflects the owning module")
	}
	if mv.ReplacedBy != "" {
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("module %s replaced by %s", mv.Path, mv.ReplacedBy))
	}
	return res.classifyVersion(claim, adv.rangesFor(mv.Path))
}

// classifyVersion completes the check once a resolved version exists:
// mismatched claims are conflicts, advisory ranges decide affected facts,
// and undecidable versions stay unresolved.
func (res PackageCheckResult) classifyVersion(claim packageClaim, ranges []domain.VersionRange) PackageCheckResult {
	if res.ResolvedVersion == "" {
		res.Class = CheckUnresolved
		res.Reason = fmt.Sprintf("module %s present but its version is undecidable", res.ResolvedPath)
		res.Limitations = append(res.Limitations, "resolved version undecidable for "+res.ResolvedPath)
		return res
	}
	if claim.Version != "" &&
		!strings.EqualFold(strings.TrimPrefix(res.ResolvedVersion, "v"), strings.TrimPrefix(claim.Version, "v")) {
		res.Class = CheckVersionMismatch
		res.Reason = fmt.Sprintf("claimed version %s conflicts with resolved %s@%s",
			claim.Version, res.ResolvedPath, res.ResolvedVersion)
		return res
	}
	if normalizeModVersion(res.ResolvedVersion) == "" {
		res.Class = CheckUnresolved
		res.Reason = fmt.Sprintf("resolved version %q is not comparable to advisory ranges", res.ResolvedVersion)
		res.Limitations = append(res.Limitations, "cannot apply version ranges to "+res.ResolvedVersion)
		return res
	}
	if len(ranges) == 0 {
		res.Class = CheckVersionConfirmed
		res.Reason = fmt.Sprintf("%s resolved at %s", res.ResolvedPath, res.ResolvedVersion)
		return res
	}
	if affectedByRanges(res.ResolvedVersion, ranges) {
		res.Class = CheckAffectedRange
		res.Reason = fmt.Sprintf("%s@%s is inside an advisory affected range", res.ResolvedPath, res.ResolvedVersion)
	} else {
		res.Class = CheckVersionConfirmed
		res.Reason = fmt.Sprintf("%s@%s resolved outside the advisory's affected ranges", res.ResolvedPath, res.ResolvedVersion)
	}
	return res
}

// normalizeModVersion maps OSV/Go version spellings onto canonical semver —
// the same semantics internal/affected applies (introduced "0" matches all,
// empty is not a version).
func normalizeModVersion(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "", "0":
		return ""
	}
	s = strings.TrimPrefix(s, "go")
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return ""
	}
	return semver.Canonical(s)
}

// affectedByRanges reports whether version falls inside any range —
// [introduced, fixed) or [introduced, last_affected] per the OSV spec.
func affectedByRanges(version string, ranges []domain.VersionRange) bool {
	v := normalizeModVersion(version)
	if v == "" {
		return false
	}
	for _, r := range ranges {
		if inModRange(v, r) {
			return true
		}
	}
	return false
}

func inModRange(v string, r domain.VersionRange) bool {
	if r.Introduced != "" {
		lo := normalizeModVersion(r.Introduced)
		if lo != "" && semver.Compare(v, lo) < 0 {
			return false
		}
	}
	if r.Fixed != "" {
		hi := normalizeModVersion(r.Fixed)
		if hi == "" || semver.Compare(v, hi) >= 0 {
			return false
		}
		return true
	}
	if r.LastAffected != "" {
		hi := normalizeModVersion(r.LastAffected)
		if hi == "" {
			return false
		}
		return semver.Compare(v, hi) <= 0
	}
	return true
}

// ValidationInput carries everything a deterministic Stage 0 validation
// rule may consult: the intake proposal under review, the collected
// material set, the advisory projection and the resolved release-toolchain
// fact.
type ValidationInput struct {
	Proposal  IntakeProposal
	Materials MaterialSet
	Advisory  AdvisoryProjection
	Toolchain *ReleaseToolchainFact
}

// ValidationRule is one deterministic field-level check of the Stage 0
// validation surface. It emits a single FieldValidation — a fact verdict
// with provenance, never a recommendation.
type ValidationRule interface {
	ID() string
	Validate(context.Context, ValidationInput) FieldValidation
}

// PackageVersionRule records the deterministic package/version check as a
// field-level fact.
type PackageVersionRule struct{}

// ID implements ValidationRule.
func (PackageVersionRule) ID() string { return "package_version" }

// Validate implements ValidationRule.
func (PackageVersionRule) Validate(_ context.Context, in ValidationInput) FieldValidation {
	toolchainVer := ""
	if in.Toolchain != nil {
		toolchainVer = in.Toolchain.Version
	}
	res := CheckPackageVersion(in.Proposal, in.Materials, in.Advisory, toolchainVer)
	return packageCheckField(res)
}

// packageCheckField projects the check result into a FieldValidation named
// "package_check": the check itself is a deterministic fact (VALID with
// provenance); a claim that could not be evaluated stays UNAVAILABLE.
func packageCheckField(res PackageCheckResult) FieldValidation {
	fv := FieldValidation{
		Field:      "package_check",
		Value:      string(res.Class),
		Reason:     res.Reason,
		Provenance: res.Provenance,
	}
	if res.Class == CheckUnresolved {
		fv.Status = IntakeUnavailable
	} else {
		fv.Status = IntakeValid
	}
	return fv
}

// ReleaseToolchainRule records the release-toolchain fact as a field-level
// verdict: VALID when evidence exists, UNAVAILABLE when unknown.
type ReleaseToolchainRule struct {
	Manifest SnapshotManifest
}

// ID implements ValidationRule.
func (ReleaseToolchainRule) ID() string { return "release_toolchain" }

// Validate implements ValidationRule.
func (r ReleaseToolchainRule) Validate(ctx context.Context, in ValidationInput) FieldValidation {
	fact := DiscoverReleaseToolchain(ctx, in.Proposal, r.Manifest)
	fv := FieldValidation{
		Field:  "release_toolchain",
		Value:  fact.Version,
		Reason: strings.Join(fact.Limitations, "; "),
	}
	if fact.Version == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "release toolchain unknown"
		return fv
	}
	fv.Status = IntakeValid
	fv.Provenance = []string{string(fact.Source)}
	if fact.Location != "" {
		fv.Provenance = append(fv.Provenance, fact.Location)
	}
	return fv
}

// ValidationRules lists the deterministic rules covering the materialized
// fact fields. The release-toolchain rule needs the snapshot manifest.
func ValidationRules(m SnapshotManifest) []ValidationRule {
	return []ValidationRule{
		PackageVersionRule{},
		ReleaseToolchainRule{Manifest: m},
	}
}

// ValidatePackageVersion is the §4.2 package/version gate over the
// materialized snapshot: it validates the claimed package and version
// against the module graph and the advisory, and records the deterministic
// check classification as a provenance-bound field. Absence from the build
// graph conflicts the claim without becoming a safety proof; a package
// that is the only source locator and cannot be resolved is a technical
// error.
func ValidatePackageVersion(ctx context.Context, proposal IntakeProposal, materials MaterialSet, advisory AdvisoryProjection) IntakeValidation {
	var v IntakeValidation
	var toolchainVer string
	if materials.Toolchain != nil {
		toolchainVer = materials.Toolchain.Version
	}
	claim := parsePackageClaim(proposal)
	res := CheckPackageVersion(proposal, materials, advisory, toolchainVer)

	v.Fields = append(v.Fields, packageFieldValidation(proposal, claim, res, advisory))
	v.Fields = append(v.Fields, versionFieldValidation(claim, res))
	v.Fields = append(v.Fields, packageCheckField(res))

	// The package claim is required for materialization only when nothing
	// else can locate the source: a finding with neither package nor
	// component/product cannot be bound to a catalog entry at all.
	if strings.TrimSpace(proposal.Package) == "" &&
		strings.TrimSpace(proposal.Component) == "" &&
		strings.TrimSpace(proposal.Product) == "" {
		v.Errors = append(v.Errors,
			"no package, component or product: the finding cannot be bound to a source for materialization")
	}
	for i := range v.Fields {
		fv := &v.Fields[i]
		if fv.Field == "package_check" {
			continue // a fact record; decision fields carry the gate
		}
		fv.BlocksRiskReduction = fv.Status != IntakeValid && fv.Status != IntakeUnavailable && !hintField(fv.Field)
		switch fv.Status {
		case IntakeInvalid:
			v.Errors = append(v.Errors, fmt.Sprintf("field %s invalid: %s", fv.Field, fv.Reason))
		case IntakeConflicting:
			v.Limitations = append(v.Limitations, fmt.Sprintf("field %s conflicting: %s", fv.Field, fv.Reason))
		case IntakeUnverified:
			v.Limitations = append(v.Limitations, fmt.Sprintf("field %s unverified: %s", fv.Field, fv.Reason))
		case IntakeUnavailable:
			v.Limitations = append(v.Limitations, fmt.Sprintf("field %s unavailable", fv.Field))
		}
	}
	v.Limitations = append(v.Limitations, res.Limitations...)
	return v
}

// packageFieldValidation maps the deterministic check onto the package
// field verdict: confirmed by the snapshot or the advisory is VALID,
// absence from a complete graph conflicts the claim, and an advisory match
// without graph data stays VALID-on-advisory (presence is unresolved, not
// absent).
func packageFieldValidation(proposal IntakeProposal, claim packageClaim, res PackageCheckResult, adv AdvisoryProjection) FieldValidation {
	fv := FieldValidation{Field: "package", Value: proposal.Package}
	switch {
	case strings.TrimSpace(proposal.Package) == "":
		fv.Status = IntakeUnavailable
		fv.Reason = "no package context proposed"
		return fv
	case claim.Malformed:
		fv.Status = IntakeInvalid
		fv.Reason = "malformed package URL"
		return fv
	case claim.VersionConflict:
		fv.Status = IntakeConflicting
		fv.Reason = "package PURL version disagrees with the version field"
		return fv
	}
	switch res.Class {
	case CheckVersionConfirmed, CheckAffectedRange:
		fv.Status = IntakeValid
		fv.Reason = res.Reason
		fv.Provenance = res.Provenance
	case CheckVersionMismatch:
		fv.Status = IntakeConflicting
		fv.Reason = res.Reason
		fv.Provenance = res.Provenance
	case CheckModuleAbsent:
		// A complete graph is authoritative for the finding's claimed
		// package: the intake claim remains valid, while the graph fact
		// supplies the package-absent falsifier. Absence is not a malformed
		// or contradictory ticket claim.
		fv.Status = IntakeValid
		fv.Reason = res.Reason
		fv.Provenance = res.Provenance
	default:
		if mod, ok := adv.namesModule(claim.Path); ok {
			fv.Status = IntakeValid
			fv.Reason = fmt.Sprintf("advisory names module %s; snapshot presence unresolved", mod)
			fv.Provenance = []string{"advisory"}
			return fv
		}
		fv.Status = IntakeUnverified
		fv.Reason = res.Reason
		if fv.Reason == "" {
			fv.Reason = "package claim could not be confirmed deterministically"
		}
		fv.Provenance = []string{"llm"}
	}
	return fv
}

// versionFieldValidation maps the check onto the version field: the
// snapshot's resolved version is the ground truth — a mismatch is a
// conflict, an advisory-confirmed or graph-confirmed version is VALID, and
// an undecidable version stays UNVERIFIED.
func versionFieldValidation(claim packageClaim, res PackageCheckResult) FieldValidation {
	fv := FieldValidation{Field: "version", Value: claim.Version}
	if strings.TrimSpace(claim.Version) == "" {
		fv.Status = IntakeUnavailable
		fv.Reason = "no version proposed"
		return fv
	}
	if claim.VersionConflict {
		fv.Status = IntakeConflicting
		fv.Reason = "version field disagrees with the package PURL version"
		return fv
	}
	if !reIntakeVersion.MatchString(strings.TrimSpace(claim.Version)) {
		fv.Status = IntakeInvalid
		fv.Reason = "malformed version syntax"
		return fv
	}
	switch res.Class {
	case CheckVersionMismatch:
		fv.Status = IntakeConflicting
		fv.Reason = res.Reason
		fv.Provenance = res.Provenance
	case CheckVersionConfirmed, CheckAffectedRange:
		fv.Status = IntakeValid
		fv.Reason = res.Reason
		fv.Provenance = res.Provenance
	case CheckModuleAbsent:
		// A complete graph proves the package absence; the claimed version
		// cannot conflict with a package that is not present.
		fv.Status = IntakeValid
		fv.Reason = res.Reason
		fv.Provenance = res.Provenance
	default:
		fv.Status = IntakeUnverified
		fv.Reason = res.Reason
		fv.Provenance = []string{"llm"}
	}
	return fv
}

// ResolveReleaseToolchain resolves the analysis toolchain for the release
// the snapshot represents. The release-toolchain fact is discovered from
// binary build info, snapshot-local release evidence and — as a recorded
// claim, never as evidence — the intake go_version. An unknown release
// toolchain is a limitation (stdlib applicability stays unresolved); it is
// never substituted by the go.mod minimum or the local Go. When the
// toolchain rule forbids local fallback and the required version cannot be
// provisioned, the local toolchain is still returned, flagged Mismatch,
// with a limitation stating the restriction — analysis may continue but no
// toolchain-dependent fact may count as resolved.
func ResolveReleaseToolchain(ctx context.Context, proposal IntakeProposal, m SnapshotManifest, cfg SiteConfig) (toolchain.Toolchain, []string, error) {
	fact := DiscoverReleaseToolchain(ctx, proposal, m)
	lims := append([]string{}, fact.Limitations...)

	var rule *ToolchainRule
	for i := range cfg.Toolchain.Rules {
		if strings.EqualFold(cfg.Toolchain.Rules[i].Ecosystem, "go") {
			rule = &cfg.Toolchain.Rules[i]
			break
		}
	}
	if fact.Version == "" {
		if rule != nil && rule.RequireReleaseToolchainForStdlib {
			lims = append(lims,
				"release toolchain unknown while require_release_toolchain_for_stdlib is set: stdlib applicability stays unresolved")
		}
		tc, notes := toolchain.Resolve(ctx, "")
		return tc, append(lims, notes...), nil
	}
	tc, notes := toolchain.Resolve(ctx, fact.Version)
	lims = append(lims, notes...)
	if tc.Mismatch && rule != nil && !rule.AllowLocalToolchainFallback {
		lims = append(lims,
			fmt.Sprintf("release toolchain %s unavailable and local fallback is disallowed: Go-dependent checks remain unresolved", fact.Version))
	}
	return tc, lims, nil
}
