package domain

import (
	"errors"
	"fmt"
	"strings"
)

// BasisDeployment marks a loopback-only exposure falsification derived from
// deployment manifests (the declared contract of the deployment) rather than
// from product code loaded under the analyzed build. Deployment policy is an
// independent product fact: it does not change with the analyzer's platform
// or build tags.
const BasisDeployment = "deployment"

// EvidenceSourceScan is the evidence kind carrying a typed SourceScanRun —
// one source-level measurement (module usage or module-internal
// reachability) with its exact subjects, entries, census completeness and
// build context.
const EvidenceSourceScan EvidenceKind = "SOURCE_SCAN"

// absenceFalsifierKind reports whether a falsifier asserts that a subject is
// absent — from the product's build graph or from the selected dependency
// source. Such a negative is evidence about the subjects it names, so it must
// name a nonempty subject set; a subject-less absence claim covers nothing.
func absenceFalsifierKind(falsifier string) bool {
	switch falsifier {
	case FalsifierPackageAbsent, FalsifierLocusPackageAbsent, FalsifierMissingSourceSymbol:
		return true
	}
	return false
}

// ConfigFlagSubject returns the package a config-flag condition names through
// its typed params. Such a condition measures whether a configuration package
// is linked into the build; it names no defect subject, so the defect-subject
// absence rule does not apply to it, but its claim still names a concrete
// package rather than an empty subject set.
func ConfigFlagSubject(cond Condition) (SymbolRef, bool) {
	if cond.Params[ParamCheck] != CheckConfigFlag {
		return SymbolRef{}, false
	}
	pkg := cond.Params[ParamConfigPackage]
	if pkg == "" {
		return SymbolRef{}, false
	}
	return SymbolRef{Package: pkg, Symbol: cond.Params[ParamConfigSymbol]}, true
}

// NegativeRequiresTarget classifies a FALSE claim by its actual basis: does
// the negative rest on a measurement taken under the analyzed product build
// (target-dependent), or on an independent product fact that no build
// selection can change?
//
// Target-dependent: govulncheck silence, module/source absence and
// unreachability, reader/pair/symbol proofs, code-selected
// configuration/guards/input proofs, and code-selected protocol-role or
// listener inventories. Independent: complete module-graph/version facts,
// release-toolchain-only platform facts, repository config-key facts, and
// deployment-policy evidence (declared trust, auto perimeter, manifests).
//
// The classification never reads explanation text. A trusted-infrastructure
// claim is independent only for its legitimate declared-trust/auto-perimeter
// bases; the config-origin basis is build-selected (a code trace). Missing or
// unknown bases default to requiring a target — the conservative direction
// that cannot turn host measurement into a product negative.
func NegativeRequiresTarget(claim Claim, cond Condition) bool {
	switch claim.Falsifier {
	case "":
		// Not a falsifier-based negative.
		return false
	case FalsifierSafeConfigKey:
		// Repository configuration-key facts: read from checked-in config
		// files, independent of the built artifact.
		return false
	case FalsifierTrustedInfrastructure:
		switch claim.FalsifierBasis {
		case BasisDeclaredTrust, BasisAutoPerimeter:
			return false
		default:
			// config-origin is a traced code fact; an unrecorded basis is
			// conservative.
			return true
		}
	case FalsifierLoopbackOnly:
		return claim.FalsifierBasis != BasisDeployment
	case FalsifierSnapshotFactMismatch:
		// GOOS/GOARCH checks compare the analyzer's build selection;
		// a release-version bound is an independently measured release
		// fact and stays usable without a product target.
		for _, name := range []string{"goos", "goarch"} {
			if cond.Params[name] != "" {
				return true
			}
		}
		return false
	default:
		// Every other falsifier is a build-dependent measurement or proof.
		return true
	}
}

// ValidateNegativeEvidence checks the candidate prerequisites of a FALSE
// claim: when its basis is target-dependent, an identified product build
// must exist and the measurement the falsifier cites must have completed
// with the coverage the negative needs. It performs no source analysis and
// does not require verification status or full kernel proof admission — those
// are the additional gates of goanalysis.ValidateVerifiedNegative.
func ValidateNegativeEvidence(product ProductSnapshot, claim Claim, cond Condition, evidence []Evidence) error {
	// An absence claim must name the subject it is about. A subject-less
	// absence negative is a vacuous closure: no subject can have been proved
	// absent, and neither the grouped all-absent rules nor replay may treat
	// it as covering anything.
	if absenceFalsifierKind(claim.Falsifier) && len(negativeSubjects(cond)) == 0 {
		if _, typedConfig := ConfigFlagSubject(cond); !typedConfig {
			return errors.New("negative evidence refused: the absence claim names no evaluated subject, so no measurement can establish that absence")
		}
	}
	if !NegativeRequiresTarget(claim, cond) {
		return nil
	}
	if err := ValidateNegativeTarget(product); err != nil {
		return fmt.Errorf("negative evidence refused: %w", err)
	}
	switch claim.Falsifier {
	case FalsifierGovulncheckSilence:
		return validateGovulncheckSilence(product, claim, cond, evidence)
	case FalsifierPackageAbsent, FalsifierLocusPackageAbsent:
		if _, err := SelectCompletePackageList(product, evidence); err != nil {
			return fmt.Errorf("negative evidence refused: package absence has no completed, complete build inventory matching the effective context: %w", err)
		}
		return nil
	case FalsifierNoModuleUsage, FalsifierUnreachedExportedSubject:
		// The live producer makes these branches positive-only when the
		// govulncheck measurement is failed/not-run/untyped. A persisted
		// claim must meet the same completed-run prerequisite; independent
		// source proofs and locus proofs are deliberately not gated here.
		if err := validateCompletedRunPrerequisite(product, evidence); err != nil {
			return err
		}
		if claim.Falsifier == FalsifierNoModuleUsage {
			return validateSourceScanMeasurement(product, cond, evidence, false)
		}
		return validateSourceScanMeasurement(product, cond, evidence, true)
	case FalsifierLocusFunctionUnreached:
		return validateSourceScanMeasurement(product, cond, evidence, true)
	}
	// Source-index proofs carry coverage in the verification record. Configuration
	// assignment safety additionally requires a captured necessary-use certificate;
	// this target gate remains only the candidate prerequisite. The shared
	// goanalysis.ValidateVerifiedNegative gate replays the verified proof.
	return nil
}


// ValidateAffectedNegative checks the affected chain's build-dependent
// FALSE axes. Module-graph absence and version facts are independent and
// deliberately not checked here. Package presence, build relevance and
// implementation presence describe one build: they require an identified
// scoped target, and package absence additionally requires a complete
// inventory matching the effective context.
func ValidateAffectedNegative(product ProductSnapshot, affected AffectedResult, evidence []Evidence) error {
	var dependent []string
	if affected.PackagePresent == ClaimFalse {
		dependent = append(dependent, "package-present")
	}
	if affected.BuildRelevant == ClaimFalse {
		dependent = append(dependent, "build-relevant")
	}
	if affected.VulnerableImplementationPresent == ClaimFalse {
		dependent = append(dependent, "vulnerable-implementation-present")
	}
	if len(dependent) == 0 {
		return nil
	}
	if err := ValidateNegativeTarget(product); err != nil {
		return fmt.Errorf("affected negative (%s) refused: %w", strings.Join(dependent, ", "), err)
	}
	if affected.PackagePresent == ClaimFalse {
		if _, err := SelectCompletePackageList(product, evidence); err != nil {
			return fmt.Errorf("affected package absence refused: no completed, complete build inventory matches the effective context: %w", err)
		}
	}
	if affected.VulnerableImplementationPresent == ClaimFalse && affected.ImplementationTarget != "" {
		if target := product.Target; target != nil && target.Platform() != affected.ImplementationTarget {
			return fmt.Errorf("affected implementation-persistence refused: recorded verification target %q does not match the effective product target %q",
				affected.ImplementationTarget, target.Platform())
		}
	}
	return nil
}

// validateGovulncheckSilence requires the cited govulncheck measurement:
// a completed-empty run, of a covered advisory, over the whole analyzed
// build, whose declared-symbol set contains every evaluated subject. An
// uncited or merely present evidence record never qualifies.
func validateGovulncheckSilence(product ProductSnapshot, claim Claim, cond Condition, evidence []Evidence) error {
	subjects := negativeSubjects(cond)
	effective := EffectiveBuildContext(product)
	cited := make(map[EvidenceID]bool, len(claim.EvidenceIDs))
	for _, id := range claim.EvidenceIDs {
		cited[id] = true
	}
	if len(cited) == 0 {
		return errors.New("negative evidence refused: govulncheck silence cites no measurement evidence")
	}
	var problem string
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != EvidenceGovulncheck || e.Govulncheck == nil || !cited[e.ID] {
			continue
		}
		if e.BuildContext == nil {
			problem = "cited govulncheck measurement has no build context"
			continue
		}
		if err := e.BuildContext.Matches(effective); err != nil {
			problem = "cited govulncheck measurement: " + err.Error()
			continue
		}
		r := e.Govulncheck
		if r.Outcome != GovulncheckCompletedEmpty {
			problem = fmt.Sprintf("cited govulncheck outcome is %q, not %q", r.Outcome, GovulncheckCompletedEmpty)
			continue
		}
		if r.Coverage.Advisory != GovulncheckCoverageCovered {
			problem = fmt.Sprintf("cited govulncheck run did not cover the advisory (%q)", r.Coverage.Advisory)
			continue
		}
		if !r.Coverage.ScopeComplete {
			problem = "cited govulncheck run covered a narrowed scope, not the analyzed build"
			continue
		}
		if len(r.Coverage.Subjects) == 0 {
			problem = "cited govulncheck run declares no affected symbols; silence cannot falsify anything"
			continue
		}
		if missing := uncoveredSymbols(r.Coverage.Subjects, subjects); len(missing) > 0 {
			problem = "cited govulncheck run declares no coverage for " + strings.Join(missing, ", ")
			continue
		}
		return nil
	}
	if problem == "" {
		problem = "no cited govulncheck measurement matches the effective build context"
	}
	return fmt.Errorf("negative evidence refused: govulncheck silence is not a completed, coverage-qualified measurement: %s", problem)
}

func validateCompletedRunPrerequisite(product ProductSnapshot, evidence []Evidence) error {
	effective := EffectiveBuildContext(product)
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != EvidenceGovulncheck || e.Govulncheck == nil || e.BuildContext == nil {
			continue
		}
		if e.BuildContext.Matches(effective) != nil {
			continue
		}
		switch e.Govulncheck.Outcome {
		case GovulncheckCompletedEmpty, GovulncheckCompletedWithResults:
			return nil
		}
	}
	return errors.New("negative evidence refused: module-usage/unreachability negatives require an applicable completed govulncheck run; failed, not-run and untyped runs are positive-only")
}

// validateSourceScanMeasurement requires, for every evaluated subject, a
// recorded source scan whose context matches the effective build, that
// completed over a complete census, covers the exact subject, and — when
// the negative is an unreachability proof — carries the entry symbols and
// did not run opaque. Positive chains recorded by the same scan remain
// usable even when this gate refuses the negative.
func validateSourceScanMeasurement(product ProductSnapshot, cond Condition, evidence []Evidence, requireEntries bool) error {
	subjects := negativeSubjects(cond)
	effective := EffectiveBuildContext(product)
	usable := func(e *Evidence, r *SourceScanRun) bool {
		if e.Kind != EvidenceSourceScan || r == nil {
			return false
		}
		if e.BuildContext == nil || e.BuildContext.Matches(effective) != nil {
			return false
		}
		if !r.Completed || !r.Complete {
			return false
		}
		if requireEntries && (r.Opaque || len(r.EntrySymbols) == 0) {
			return false
		}
		return true
	}
	if len(subjects) == 0 {
		// The condition names no subject: its evaluated set came from the
		// advisory (declared symbols / fix-diff root causes). Subject
		// coverage cannot be reconstructed here, but the measurement must
		// still exist, have completed over a complete census, match the
		// build, and — for an unreachability proof — be non-opaque with
		// product-used entries.
		for i := range evidence {
			e := &evidence[i]
			if usable(e, e.SourceScan) {
				return nil
			}
		}
		return errors.New("negative evidence refused: no completed source measurement matches the effective build context")
	}
	for _, s := range subjects {
		found := false
		var problem string
		for i := range evidence {
			e := &evidence[i]
			if e.Kind != EvidenceSourceScan || e.SourceScan == nil {
				continue
			}
			r := e.SourceScan
			if !PackageInModule(s.Package, r.Module) {
				continue
			}
			if !containsRef(r.Subjects, s) {
				problem = fmt.Sprintf("source scan of module %q does not cover %s.%s", r.Module, s.Package, s.Symbol)
				continue
			}
			if err := func() error {
				if e.BuildContext == nil {
					return errors.New("source scan record has no build context")
				}
				if err := e.BuildContext.Matches(effective); err != nil {
					return fmt.Errorf("source scan record: %w", err)
				}
				if !r.Completed {
					return fmt.Errorf("source scan of module %q did not complete", r.Module)
				}
				if !r.Complete {
					return fmt.Errorf("source scan of module %q ran over an incomplete census", r.Module)
				}
				if requireEntries {
					if r.Opaque {
						return fmt.Errorf("source scan of module %q is opaque (func values/dynamic dispatch)", r.Module)
					}
					if len(r.EntrySymbols) == 0 {
						return fmt.Errorf("source scan of module %q records no product-used entry symbols", r.Module)
					}
				}
				return nil
			}(); err != nil {
				problem = err.Error()
				continue
			}
			found = true
			break
		}
		if !found {
			if problem == "" {
				problem = "no source scan record covers " + s.Package + "." + s.Symbol
			}
			return fmt.Errorf("negative evidence refused: %s", problem)
		}
	}
	return nil
}

// negativeSubjects returns the subject set a falsifier must cover: the
// grouped subjects plus the singular subject, deduplicated.
func negativeSubjects(cond Condition) []SymbolRef {
	var out []SymbolRef
	add := func(s SymbolRef) {
		// A package-level absence claim names a package without a symbol; it
		// is a real subject identity, not an empty set. Only a subject with no
		// package at all names nothing.
		if s.Package == "" {
			return
		}
		if containsRef(out, s) {
			return
		}
		out = append(out, s)
	}
	for _, s := range cond.Subjects {
		add(s)
	}
	if cond.Subject != nil {
		add(*cond.Subject)
	}
	return out
}

func containsRef(list []SymbolRef, s SymbolRef) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// uncoveredSymbols names the subjects absent from a declared-coverage set.
func uncoveredSymbols(declared, subjects []SymbolRef) []string {
	var missing []string
	for _, s := range subjects {
		if !containsRef(declared, s) {
			missing = append(missing, s.Package+"."+s.Symbol)
		}
	}
	return missing
}

// CheckClaim validates one FALSE absence claim against the single admitted
// absence result. It is the shared §3.4 gate: the claim must name a nonempty
// subject set, every subject must have an admitted identity, and — when the
// content route established a necessary cover — the claim's subject set must
// equal that canonical set exactly, the negative verification must record the
// same cover identity and subject-set digest, and every cover package must be
// absent from the admitted build graph.
//
// There is no fallback from an empty condition to whatever happens to remain in
// Model.RootCauses, and no accepted absent subset while another alternative is
// linked or unresolved.
func (a AbsenceAdmission) CheckClaim(cond Condition, claim Claim) error {
	subjects := negativeSubjects(cond)
	if len(subjects) == 0 {
		return fmt.Errorf("the claim binds no subject: an absence negative must name the exact subject set it measures")
	}
	for _, s := range subjects {
		admission := a.Admits(s)
		if !admission.Admitted {
			return fmt.Errorf("subject %s: %s", absenceSubjectLabel(s), admission.Reason)
		}
	}
	if a.cover == nil {
		return nil
	}
	if !sameSubjectSet(subjects, a.cover.Subjects) {
		return fmt.Errorf(
			"claim subjects %s do not equal the admitted necessary cover %s",
			AbsenceSubjectsLabel(subjects), AbsenceSubjectsLabel(a.cover.Subjects))
	}
	if nv := claim.NegativeVerification; nv != nil && nv.Status == NegativeVerified {
		if nv.CoverID != a.cover.ID {
			return fmt.Errorf(
				"negative verification records cover %q, not the admitted cover %q",
				nv.CoverID, a.cover.ID)
		}
		if nv.SubjectDigest != a.cover.SubjectDigest {
			return fmt.Errorf(
				"negative verification records subject-set digest %q, not the admitted %q",
				nv.SubjectDigest, a.cover.SubjectDigest)
		}
	}
	return a.checkCoverAbsent(claim.ConditionID)
}

// Stamp records the admitted cover identity and subject-set digest on a
// negative verification produced for cond. A producer that cannot stamp the
// claim does not produce a verified absence: the claim would not re-admit.
func (a AbsenceAdmission) Stamp(cond Condition, nv *NegativeVerification) error {
	if nv == nil {
		return fmt.Errorf("no negative verification record is available to carry the cover identity")
	}
	if a.cover == nil {
		return nil
	}
	subjects := negativeSubjects(cond)
	if len(subjects) == 0 {
		return fmt.Errorf("the condition binds no subject, so it does not range over the admitted necessary cover")
	}
	if !sameSubjectSet(subjects, a.cover.Subjects) {
		return fmt.Errorf(
			"condition subjects %s do not equal the admitted necessary cover %s",
			AbsenceSubjectsLabel(subjects), AbsenceSubjectsLabel(a.cover.Subjects))
	}
	nv.CoverID = a.cover.ID
	nv.SubjectDigest = a.cover.SubjectDigest
	return nil
}

// CoverBuildRefusal states why the necessary cover behind subject s is not
// satisfied by the admitted build graph, or "" when it is (or when s rests on
// no content cover). A linked cover member contradicts the absence conclusion
// instead of supporting it; an unmeasured graph shows no member absent.
func (a AbsenceAdmission) CoverBuildRefusal(s SymbolRef) string {
	if a.cover == nil || !a.cover.Covers(s) {
		return ""
	}
	if !a.build.Admitted {
		return "no admitted complete build inventory is available, so no member of the necessary cover is shown absent"
	}
	if len(a.build.Paths) == 0 {
		return "the admitted build graph measured no package, so no member of the necessary cover was shown absent"
	}
	for _, pkg := range a.cover.Packages {
		if a.build.Links(pkg) {
			return fmt.Sprintf(
				"the necessary cover also names %s, which the admitted product build graph links, so the absence of %s cannot establish the defect's absence",
				pkg, s.Package)
		}
	}
	return ""
}

// checkCoverAbsent requires every cover member's package to be absent from the
// admitted build graph.
func (a AbsenceAdmission) checkCoverAbsent(conditionID ConditionID) error {
	if a.cover == nil {
		return nil
	}
	if !a.build.Admitted {
		return fmt.Errorf(
			"negative for %s refused: no admitted complete build inventory is available, so no member of the necessary cover is shown absent",
			conditionID)
	}
	for _, pkg := range a.cover.Packages {
		if a.build.Links(pkg) {
			return fmt.Errorf(
				"negative for %s refused: the necessary cover also names %s, which the admitted product build graph links, so the cover's packages are not all absent",
				conditionID, pkg)
		}
	}
	return nil
}
