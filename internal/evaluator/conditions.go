package evaluator

import (
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fixbinding"
)

// ConditionEvaluator assigns a TRUE/FALSE/UNKNOWN claim to a condition using
// only deterministic evidence already present in the graph.
type ConditionEvaluator interface {
	CanEvaluate(cond domain.Condition) bool
	Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim
}

// admitNegative applies the build-context gate to a FALSE candidate before it
// leaves an evaluator. A build-dependent negative requires an identified,
// scoped product build and the measurement its falsifier cites; when either
// prerequisite is missing the claim degrades to UNKNOWN with the refusal
// recorded, never to FALSE plus a caveat. Independent bases (declared trust,
// auto perimeter, repository config keys, deployment manifests, release
// toolchain bounds) pass through untouched.
//
// It is applied by every evaluator entry point — direct calls receive the
// same behavior as workflow dispatch.
func admitNegative(c *domain.AnalysisCase, cond domain.Condition, claim domain.Claim) domain.Claim {
	if c == nil || claim.Result != domain.ClaimFalse || claim.Falsifier == "" {
		return claim
	}
	if err := domain.ValidateNegativeEvidence(c.Product, claim, cond, c.EvidenceGraph.EvidenceList()); err != nil {
		claim.Result = domain.ClaimUnknown
		claim.Limitations = append(claim.Limitations, "FALSE refused: "+err.Error())
		return claim
	}
	// A verification record produced by the evaluator itself (trusted
	// infrastructure, protocol-role inventories) did not pass through
	// Verifier.VerifyFalse; stamp its measurement identity here so a later
	// persisted-verdict admission can bind it to this build.
	if claim.NegativeVerification != nil &&
		claim.NegativeVerification.Status == domain.NegativeVerified &&
		domain.NegativeRequiresTarget(claim, cond) {
		build := domain.EffectiveBuildContext(c.Product)
		claim.NegativeVerification.BuildContext = &build
	}
	return claim
}

// SymbolReachable evaluates SYMBOL_REACHABLE conditions from govulncheck
// call paths stored in the EvidenceGraph.
//
// Semantics per spec: a found call path to the root-cause symbol is a TRUE.
// A completed govulncheck run without such a path yields a FALSE *candidate*
// that still requires negative verification. A failed/absent run yields
// UNKNOWN — tool failure is never negative evidence.
type SymbolReachable struct{}

func (SymbolReachable) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionSymbolReachable
}

func (SymbolReachable) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evaluateSymbolReachable(cond, c))
}

func evaluateSymbolReachable(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	// Pattern-parametrized reachability shapes are decided by their own
	// rules before the govulncheck path runs.
	if cond.Params[domain.ParamDirection] == domain.DirectionRead {
		return evalReadDirectionRaw(cond, c)
	}
	if cond.Params[domain.ParamSequence] != "" {
		return evalSequencePairRaw(cond, c)
	}
	if cond.Params[domain.ParamCheck] == domain.CheckLocus {
		return evalLocusRaw(cond, c)
	}
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.SymbolReachable",
	}
	// Omission-pipeline reach: TRUE only through the typed missing-call
	// witness bound to the admitted OMITTED_CHECK contract. A matching
	// evidence id or a symbol appearing in evidence content never decides
	// this condition. A witness that records the check invoked does not
	// reach here as TRUE; the omission claim itself turns FALSE.
	if cond.Params["pipeline"] != "" {
		if c.Exploit != nil {
			if match, reasons := domain.MatchOmissionWitness(c.Exploit.DefectSemantics, cond,
				c.EvidenceGraph.EvidenceList(), c.Product, domain.MissingCallOmitted); match != nil {
				claim.Result = domain.ClaimTrue
				claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, match.EvidenceID)
				claim.Explanation = "the anchored omission pipeline is reached from product code; the contracted check is absent on that path (typed missing-call observation " +
					string(match.EvidenceID) + ")"
				return claim
			} else {
				claim.Limitations = append(claim.Limitations, reasons...)
			}
		} else {
			claim.Limitations = append(claim.Limitations,
				"omission-pipeline reach requires an admitted defect-semantics contract; the condition stays UNKNOWN")
		}
	}
	symbols := reachabilitySubjects(cond, c)
	if len(symbols) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no subject symbol: set condition.subject or resolve root cause first")
		return claim
	}

	// Package absence is the strongest negative basis: a subject whose
	// package never entered `go list -deps` cannot be reached through any
	// path — no trace, dispatch, or wrapper can execute code that is not
	// linked in. Split presence before any trace/module-usage logic so an
	// absent subject cannot produce a FALSE-positive TRUE (e.g. inferred
	// reach via a used sibling package) nor drown a proven negative.
	//
	// Identity comes first. A package missing from the build graph is absence
	// evidence only for a subject the selected version actually contains: a
	// fix-derived candidate whose coordinate does not resolve in that
	// version's own source names nothing there, so its missing package proves
	// nothing and the grouped all-absent FALSE may not be proposed.
	if set, ids, err := packageImportSet(c); err == nil {
		var evidenceID domain.EvidenceID
		if len(ids) > 0 {
			evidenceID = ids[0]
		}
		var proof *domain.ContentAdmission
		if c != nil {
			proof = fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), c.RootCause)
		}
		absenceAdmission := domain.AdmitAbsence(c, domain.AbsenceBuildGraph{
			Paths: set, EvidenceID: evidenceID, Admitted: true,
		}, proof)
		var present, unmapped []domain.SymbolRef
		var absentPkgs []string
		unmappedWhy := ""
		for _, s := range symbols {
			if s.Package == "" || set[s.Package] {
				present = append(present, s)
				continue
			}
			if admission := absenceAdmission.Admits(s); !admission.Admitted {
				unmapped = append(unmapped, s)
				if unmappedWhy == "" {
					unmappedWhy = admission.Reason
				}
				continue
			}
			absentPkgs = appendUnique(absentPkgs, s.Package)
		}
		if len(present) == 0 && len(unmapped) > 0 {
			claim.Limitations = append(claim.Limitations,
				"package absence is not evidence here: "+unmappedWhy)
			return claim
		}
		if len(present) == 0 {
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierPackageAbsent
			claim.EvidenceIDs = ids
			claim.Explanation = fmt.Sprintf(
				"all %d subject package(s) (%s) are absent from the product's build graph (go list -deps); defect code is not linked in",
				len(symbols), strings.Join(absentPkgs, ", "))
			return claim
		}
		if len(absentPkgs) > 0 {
			claim.Limitations = append(claim.Limitations, fmt.Sprintf(
				"%d subject(s) resolved absent from the build graph (%s); reachability decided over linked packages only",
				len(symbols)-len(present), strings.Join(absentPkgs, ", ")))
			symbols = present
		}
		if len(unmapped) > 0 {
			claim.Limitations = append(claim.Limitations, fmt.Sprintf(
				"%d subject(s) name no established subject of the selected version and stay unresolved: %s",
				len(unmapped), unmappedWhy))
		}
	}

	measurement := govulncheckEvidence(c)
	var run *domain.GovulncheckRun
	why, positiveOnly := "govulncheck did not run or its outcome is unknown", true
	if measurement != nil {
		run = measurement.Govulncheck
		switch run.Outcome {
		case domain.GovulncheckFailed:
			why = "govulncheck failed"
		case domain.GovulncheckNotRun:
			why = "govulncheck did not run"
		case domain.GovulncheckCompletedWithResults:
			why = "govulncheck completed with findings; absence of a path to the subject(s) is not evidence of no path"
			positiveOnly = false
		case domain.GovulncheckCompletedEmpty:
			positiveOnly = false
		default:
			why = "govulncheck run outcome is unknown"
		}
	}

	matched := map[string]bool{}
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			for _, sym := range symbols {
				if frameMatches(fr, sym) {
					matched[sym.Package+"."+sym.Symbol] = true
					if cp.EvidenceID != "" {
						claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, cp.EvidenceID)
					}
				}
			}
		}
	}
	if len(matched) > 0 {
		allPathsDead := true
		var gatedDetail string
		hasUsages := false
		for _, cp := range c.EvidenceGraph.CallPaths {
			if len(cp.Frames) > 0 {
				rootFrame := cp.Frames[0]
				for _, u := range c.EvidenceGraph.ModuleUsages {
					if u.File == rootFrame.File && u.Line == rootFrame.Line {
						hasUsages = true
						if !u.DeadCode {
							allPathsDead = false
						}
						if u.GatedBy != "" && gatedDetail == "" {
							gatedDetail = u.GatedBy
						}
					}
				}
			}
		}
		if hasUsages && allPathsDead && gatedDetail != "" {
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierConfigGatedOff
			claim.Explanation = fmt.Sprintf("all call path(s) to affected symbol(s) are dead code under disabled feature gates (%s)", gatedDetail)
			return claim
		}
		claim.Result = domain.ClaimTrue
		if gatedDetail != "" {
			claim.Limitations = append(claim.Limitations,
				"conditional-reachability (guarded by config: "+gatedDetail+")")
		}
		claim.Explanation = "govulncheck produced call path(s) to the affected symbol(s)"
		return claim
	}

	// A recorded intra-module chain from a product-used API is positive
	// reachability evidence and outranks govulncheck silence: for advisories
	// without declared symbols govulncheck only emits package-level traces,
	// which never reach the sink internals.
	for _, subj := range symbols {
		want := subj.Package + "." + subj.Symbol
		if chain, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
			entry := chain[0]
			var entryUsages []domain.CallSite
			for _, u := range c.EvidenceGraph.ModuleUsages {
				if u.Callee == entry {
					entryUsages = append(entryUsages, u)
				}
			}
			if len(entryUsages) > 0 {
				allDead := true
				var gatedDetail string
				for _, eu := range entryUsages {
					if !eu.DeadCode {
						allDead = false
					}
					if eu.GatedBy != "" && gatedDetail == "" {
						gatedDetail = eu.GatedBy
					}
				}
				if allDead {
					claim.Result = domain.ClaimFalse
					claim.Falsifier = domain.FalsifierConfigGatedOff
					claim.Explanation = fmt.Sprintf(
						"call chain to %s originates from %s which is dead code under disabled feature gate (%s)",
						want, entry, gatedDetail)
					return claim
				}
				if gatedDetail != "" {
					claim.Limitations = append(claim.Limitations,
						"conditional-reachability (guarded by config: "+gatedDetail+")")
				}
			}
			claim.Result = domain.ClaimTrue
			claim.EvidenceIDs = append(moduleReachEvidence(c), moduleUsageEvidence(c)...)
			claim.Explanation = fmt.Sprintf(
				"%s reachable through module internals: %s",
				want, strings.Join(chain, " -> "))
			return claim
		}
	}

	// Failed, not-run, and legacy-untyped measurements fall back
	// positive-only: a tool failure is never negative evidence, and an
	// unknown outcome cannot suppress a measured absence.
	if run == nil || run.Outcome == domain.GovulncheckFailed || run.Outcome == domain.GovulncheckNotRun {
		claim.Limitations = append(claim.Limitations,
			why+"; reachability inferred from module-usage evidence only")
		return libraryUsageVerdict(claim, c, symbols, why, true)
	}
	if run.Outcome == domain.GovulncheckCompletedEmpty {
		// Silence is a candidate only when this completed run actually
		// evaluated the advisory, the advisory's OSV entry declared the
		// subject symbols, and the scan pattern covered the whole build.
		if run.Coverage.Advisory != domain.GovulncheckCoverageCovered {
			return libraryUsageVerdict(claim, c, symbols,
				"advisory absent from the govulncheck DB this run scanned", false)
		}
		if !run.Coverage.ScopeComplete {
			return libraryUsageVerdict(claim, c, symbols,
				"govulncheck scan scope was narrowed; packages outside it were not evaluated", false)
		}
		if !allDeclared(symbols, run.Coverage.Subjects) {
			return libraryUsageVerdict(claim, c, symbols,
				"govulncheck entry declares no affected symbols covering the subject(s); silence is not evidence of no path", false)
		}
		claim.EvidenceIDs = []domain.EvidenceID{measurement.ID}
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierGovulncheckSilence
		claim.Explanation = fmt.Sprintf("govulncheck found no call path to any of %d affected symbol(s)", len(symbols))
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: interfaces/reflection/plugins may bypass static reachability")
		return claim
	}
	// A completed-with-results run, or a typed record with an unknown
	// outcome, cannot ground silence: the run's missing subject paths do not
	// prove other subjects unreachable.
	return libraryUsageVerdict(claim, c, symbols, why, positiveOnly)
}

// libraryUsageVerdict decides reachability when govulncheck could not
// evaluate the advisory; `why` states which situation applies — the DB lacks
// the advisory or the tool never ran — and is embedded into explanations so a
// reader does not confuse "ran and silent" with "did not run".
// positiveOnly suppresses every negative conclusion: with a failed, not-run,
// or untyped measurement, zero usage and dead call sites are UNKNOWN, never
// no-module-usage/unreached-exported-subject/config-gated-off.
// A positive requires a traced path: a direct call to an exported subject or a
// recorded intra-module chain from a product-used API. Product calls into the
// owning module are an observation — unexported internals execute inside the
// module, but module API usage does not establish that the sink ran, so an
// unexported subject without a traced chain stays UNKNOWN.
func libraryUsageVerdict(claim domain.Claim, c *domain.AnalysisCase, subjects []domain.SymbolRef, why string, positiveOnly bool) domain.Claim {
	// Attribute usage sites to the modules owning the subjects — under a
	// multi-module advisory a call into module A says nothing about a
	// subject in module B.
	usages, stray := subjectModuleUsages(c, subjects)
	if len(usages) == 0 {
		if !moduleUsageChecked(c, subjects) {
			claim.Limitations = append(claim.Limitations,
				"module-usage scan did not run; absence of call sites is no evidence")
			return claim
		}
		if stray > 0 {
			claim.Limitations = append(claim.Limitations, fmt.Sprintf(
				"%d module-usage site(s) could not be attributed to any linked module; absence in the subject-owning module(s) is unproven",
				stray))
			return claim
		}
		if positiveOnly {
			claim.Limitations = append(claim.Limitations,
				why+"; positive-only fallback: zero module usage cannot falsify reachability without a completed, coverage-qualified govulncheck run")
			return claim
		}
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierNoModuleUsage
		claim.Explanation = why + " and product makes no calls into the module(s) owning the subjects"
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: module API usage is measured from product call sites, not vendored internals")
		return claim
	}
	if allUnexported(subjects) {
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"product calls the subject-owning module's API at %d site(s), but unexported sink(s) %s can only be reached through a traced intra-module path and none is recorded (%s)",
			len(usages), joinSymbolNames(subjects), why))
		return claim
	}
	// Exported sinks: TRUE when proven reachable — either directly invoked by
	// product code, or through a traced intra-module call chain from an API
	// the product uses.
	for _, subj := range subjects {
		want := subj.Package + "." + subj.Symbol
		if chain, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
			entry := chain[0]
			var entryUsages []domain.CallSite
			for _, u := range usages {
				if u.Callee == entry {
					entryUsages = append(entryUsages, u)
				}
			}
			if len(entryUsages) > 0 {
				allDead := true
				var gatedDetail string
				for _, eu := range entryUsages {
					if !eu.DeadCode {
						allDead = false
					}
					if eu.GatedBy != "" && gatedDetail == "" {
						gatedDetail = eu.GatedBy
					}
				}
				if allDead {
					if !positiveOnly {
						claim.Result = domain.ClaimFalse
						claim.Falsifier = domain.FalsifierConfigGatedOff
						claim.Explanation = fmt.Sprintf(
							"%s; call chain to %s originates from %s which is dead code under disabled feature gate (%s)",
							why, want, entry, gatedDetail)
						return claim
					}
					claim.Limitations = append(claim.Limitations, fmt.Sprintf(
						"%s; call chain to %s originates only from dead code under disabled feature gate (%s); positive-only fallback cannot falsify",
						why, want, gatedDetail))
				} else {
					if gatedDetail != "" {
						claim.Limitations = append(claim.Limitations,
							"conditional-reachability (guarded by config: "+gatedDetail+")")
					}
					claim.Result = domain.ClaimTrue
					claim.EvidenceIDs = append(moduleReachEvidence(c), moduleUsageEvidence(c)...)
					claim.Explanation = fmt.Sprintf(
						"%s; %s reachable through module internals: %s",
						why, want, strings.Join(chain, " -> "))
					return claim
				}
			}
		}
		var matchingUsages []domain.CallSite
		for _, u := range usages {
			if u.Callee == want {
				matchingUsages = append(matchingUsages, u)
			}
		}
		if len(matchingUsages) > 0 {
			allDead := true
			var gatedDetail string
			for _, mu := range matchingUsages {
				if !mu.DeadCode {
					allDead = false
				}
				if mu.GatedBy != "" && gatedDetail == "" {
					gatedDetail = mu.GatedBy
				}
			}
			if allDead {
				if !positiveOnly {
					claim.Result = domain.ClaimFalse
					claim.Falsifier = domain.FalsifierConfigGatedOff
					claim.Explanation = fmt.Sprintf(
						"%s; all direct calls to %s are dead code under disabled feature gate (%s)",
						why, want, gatedDetail)
					return claim
				}
				claim.Limitations = append(claim.Limitations, fmt.Sprintf(
					"%s; all direct calls to %s are dead code under disabled feature gate (%s); positive-only fallback cannot falsify",
					why, want, gatedDetail))
			} else {
				claim.Result = domain.ClaimTrue
				claim.EvidenceIDs = moduleUsageEvidence(c)
				if gatedDetail != "" {
					claim.Limitations = append(claim.Limitations,
						"conditional-reachability (guarded by config: "+gatedDetail+")")
				}
				claim.Explanation = fmt.Sprintf(
					"%s; product directly calls %s at %s:%d",
					why, want, matchingUsages[0].File, matchingUsages[0].Line)
				return claim
			}
		}
	}
	if positiveOnly {
		claim.Limitations = append(claim.Limitations,
			why+"; positive-only fallback: module usage cannot ground a negative without a completed, coverage-qualified govulncheck run")
		return claim
	}
	// FALSE only when the intra-module call graph was actually checked —
	// without it, absence is unknown, not negative.
	if !moduleReachChecked(c, subjects) {
		claim.Limitations = append(claim.Limitations,
			why+"; module is used but exported sinks were not reachability-checked")
		return claim
	}
	if moduleReachOpaque(c, subjects) {
		claim.Limitations = append(claim.Limitations,
			why+"; module dispatch is opaque (func values/dynamic dispatch) — unreached subjects are not disproven")
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = domain.FalsifierUnreachedExportedSubject
	claim.Explanation = fmt.Sprintf(
		"%s; none of %d exported subject(s) is invoked by product code nor reachable through the module API it uses",
		why, len(subjects))
	claim.Limitations = append(claim.Limitations,
		"FALSE is a candidate: implicit interface dispatch (e.g. fmt.Stringer) may hide calls",
		"module-internal reachability was checked in vendored source only")
	return claim
}

// evalReadDirection evaluates direction=read reachability (INFO_LEAK
// class): the question is whether product code *references* the sensitive
// subject — any product reader can observe the exposed data. Readers are
// collected by the read-scope scan into EvidenceGraph.SymbolRefs.
//
//	TRUE  — at least one subject has product-code references.
//	FALSE candidate — the scan ran and found no references; requires
//	  negative verification like any other absence claim.
//	UNKNOWN — the scan never ran (source index unavailable) or the
//	  condition carries no subjects.
func evalReadDirection(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evalReadDirectionRaw(cond, c))
}

func evalReadDirectionRaw(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.SymbolReachable",
	}
	subjects := condSubjects(cond)
	if len(subjects) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no subject symbol: read-direction conditions bind the exposed datum, not root causes")
		return claim
	}
	var evIDs []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Tool == "goanalysis.Index.SearchSymbol" && strings.HasPrefix(e.Source, "read-scope check ") {
			evIDs = appendUniqueID(evIDs, e.ID)
		}
	}
	if len(evIDs) == 0 {
		claim.Limitations = append(claim.Limitations,
			"read-scope scan did not run for this condition's subjects")
		return claim
	}
	var readers []string
	for _, s := range subjects {
		refs := c.EvidenceGraph.SymbolRefsFor(s.Package + "." + s.Symbol)
		if len(refs) > 0 {
			readers = append(readers, fmt.Sprintf("%s.%s (%s:%d)",
				s.Package, s.Symbol, refs[0].File, refs[0].Line))
		}
	}
	claim.EvidenceIDs = evIDs
	if len(readers) > 0 {
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf(
			"product code references %d of %d subject(s): %s — data is observable outside the owning package",
			len(readers), len(subjects), strings.Join(readers, ", "))
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = domain.FalsifierNoProductReader
	claim.Explanation = fmt.Sprintf(
		"no product-code reference to any of %d subject(s); the sensitive data has no observed reader",
		len(subjects))
	claim.Limitations = append(claim.Limitations,
		"FALSE is a candidate: readers inside other dependencies or through interface dispatch are not scanned")
	return claim
}

// evalSequencePair evaluates sequence reachability (URI_CONFUSION class):
// the product must invoke the full API pair that forms the vulnerable
// round-trip — a member counts as invoked when the product calls it
// directly or reaches it through a module API it uses.
//
//	TRUE  — every subject is invoked (direct callee or module-internal chain).
//	FALSE candidate — module usage was checked and at least one member is
//	  never invoked.
//	UNKNOWN — module usage was never collected.
func evalSequencePair(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evalSequencePairRaw(cond, c))
}

func evalSequencePairRaw(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.SymbolReachable",
	}
	subjects := condSubjects(cond)
	if len(subjects) < 2 {
		claim.Limitations = append(claim.Limitations,
			"sequence condition needs a pair of subject symbols")
		return claim
	}
	if !moduleUsageChecked(c, subjects) {
		claim.Limitations = append(claim.Limitations,
			"module usage was not collected; the API pair cannot be verified")
		return claim
	}
	var missing []string
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		if !memberInvoked(key, c) {
			missing = append(missing, key)
		}
	}
	claim.EvidenceIDs = moduleUsageEvidence(c)
	if len(missing) == 0 {
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf(
			"product invokes the full round-trip pair (%s)",
			cond.Params[domain.ParamSequence])
		claim.Limitations = append(claim.Limitations,
			"pair presence is proven; call order/dataflow between members is not verified")
		return claim
	}
	// Missing members disprove the pair only when the module-internal
	// graph is complete — opaque dispatch hides invocations.
	if moduleReachOpaque(c, subjects) {
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"pair member(s) %s not statically reached; module dispatch is opaque (func values/dynamic dispatch), so absence is unknown, not disproven",
			strings.Join(missing, ", ")))
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = domain.FalsifierMissingPairMember
	claim.Explanation = fmt.Sprintf(
		"round-trip pair incomplete: product never invokes %s",
		strings.Join(missing, ", "))
	claim.Limitations = append(claim.Limitations,
		"FALSE is a candidate: pair members may be invoked via interface dispatch or reflection")
	return claim
}

// memberInvoked reports whether the product invokes key ("pkg.Symbol") —
// directly at a call site into the module, or through a used module API
// whose intra-module call chain reaches it.
func memberInvoked(key string, c *domain.AnalysisCase) bool {
	if _, ok := c.EvidenceGraph.ModuleReachable[key]; ok {
		return true
	}
	for _, u := range c.EvidenceGraph.ModuleUsages {
		if u.Callee == key {
			return true
		}
	}
	return false
}

// linkedModules returns every module the resolver linked into the case —
// SelectedModules when the multi-module resolver ran, else the advisory
// module.
func linkedModules(c *domain.AnalysisCase) []string {
	if c.Affected != nil && len(c.Affected.SelectedModules) > 0 {
		return c.Affected.SelectedModules
	}
	if c.Vulnerability.Module != "" {
		return []string{c.Vulnerability.Module}
	}
	return nil
}

func inCaseModules(pkgPath string, mods []string) bool {
	for _, m := range mods {
		if domain.PackageInModule(pkgPath, m) {
			return true
		}
	}
	return false
}

// subjectModules returns the linked modules owning the subjects — the
// longest matching module per subject, so a nested module is not absorbed
// by its parent's prefix. A subject matching none of them widens the
// answer to all linked modules rather than zeroing the usage set.
func subjectModules(c *domain.AnalysisCase, subjects []domain.SymbolRef) []string {
	linked := linkedModules(c)
	own := map[string]bool{}
	var out []string
	for _, s := range subjects {
		if m := domain.OwnerModule(s.Package, linked); m != "" && !own[m] {
			own[m] = true
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return linked
	}
	return out
}

// subjectModuleUsages filters module-usage call sites to those whose callee
// lives in a module owning at least one subject. Sites attributable to a
// different linked module are excluded outright; sites that cannot be
// attributed at all are counted separately — they cannot prove use, but
// they also prevent claiming absence.
func subjectModuleUsages(c *domain.AnalysisCase, subjects []domain.SymbolRef) (relevant []domain.CallSite, unattributable int) {
	linked := linkedModules(c)
	if len(linked) == 0 {
		// No module context (flat intake) — keep all sites relevant.
		return c.EvidenceGraph.ModuleUsages, 0
	}
	ownSet := map[string]bool{}
	for _, m := range subjectModules(c, subjects) {
		ownSet[m] = true
	}
	for _, u := range c.EvidenceGraph.ModuleUsages {
		switch m := u.ModuleOwner; {
		case m != "" && ownSet[m]:
			relevant = append(relevant, u)
		case m == "" || !containsModule(linked, m):
			unattributable++
		}
	}
	return relevant, unattributable
}

func containsModule(mods []string, target string) bool {
	for _, m := range mods {
		if m == target {
			return true
		}
	}
	return false
}

// sourceScanRecords returns the typed source-level measurements bound to the
// case's effective build context, in recording order. Records for another
// build are measurements of something else and never answer a negative.
func sourceScanRecords(c *domain.AnalysisCase) []*domain.Evidence {
	if c == nil {
		return nil
	}
	effective := domain.EffectiveBuildContext(c.Product)
	evidence := c.EvidenceGraph.EvidenceList()
	var out []*domain.Evidence
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != domain.EvidenceSourceScan || e.SourceScan == nil {
			continue
		}
		if e.BuildContext == nil || e.BuildContext.Matches(effective) != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// sourceScanForSubject returns the latest completed measurement covering the
// subject's package. Nil means no measurement — absence of a record is never
// a completed scan.
func sourceScanForSubject(c *domain.AnalysisCase, s domain.SymbolRef) *domain.SourceScanRun {
	var selected *domain.SourceScanRun
	for _, e := range sourceScanRecords(c) {
		r := e.SourceScan
		if !r.Completed || !domain.PackageInModule(s.Package, r.Module) {
			continue
		}
		selected = r
	}
	return selected
}

// moduleUsageChecked reports whether a completed source scan covers every
// subject — its check record is written even when zero call sites were found.
func moduleUsageChecked(c *domain.AnalysisCase, subjects []domain.SymbolRef) bool {
	if len(subjects) == 0 {
		return false
	}
	for _, s := range subjects {
		if sourceScanForSubject(c, s) == nil {
			return false
		}
	}
	return true
}

// moduleReachChecked reports whether a completed source reachability
// measurement with product-used entry symbols covers every subject.
func moduleReachChecked(c *domain.AnalysisCase, subjects []domain.SymbolRef) bool {
	if len(subjects) == 0 {
		return false
	}
	for _, s := range subjects {
		r := sourceScanForSubject(c, s)
		if r == nil || len(r.EntrySymbols) == 0 {
			return false
		}
	}
	return true
}

// moduleReachOpaque reports whether the applicable source reachability
// measurement for the subjects recorded unresolvable dispatch. An unreached
// subject is then UNKNOWN — absence cannot falsify reachability.
func moduleReachOpaque(c *domain.AnalysisCase, subjects []domain.SymbolRef) bool {
	for _, s := range subjects {
		if r := sourceScanForSubject(c, s); r != nil && len(r.EntrySymbols) > 0 && r.Opaque {
			return true
		}
	}
	return false
}

// condSubjects returns the condition's bound subjects (Subjects plus the
// singular Subject, deduplicated) — unlike reachabilitySubjects it does
// not union in advisory symbols: param-directed conditions bind exactly
// what the pattern declared.
func condSubjects(cond domain.Condition) []domain.SymbolRef {
	var out []domain.SymbolRef
	for _, s := range cond.Subjects {
		if !containsSymbol(out, s) {
			out = append(out, s)
		}
	}
	if cond.Subject != nil && !containsSymbol(out, *cond.Subject) {
		out = append(out, *cond.Subject)
	}
	return out
}

// moduleUsageEvidence returns the IDs of the module-usage evidence collected
// during evidence collection, so derived claims satisfy provenance.
func moduleUsageEvidence(c *domain.AnalysisCase) []domain.EvidenceID {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Tool == "goanalysis.Index.ModuleUsage" {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// moduleReachEvidence returns the IDs of the ModuleInternalReach evidence —
// the records documenting the intra-module reachability check and the chains
// stored in ModuleReachable.
func moduleReachEvidence(c *domain.AnalysisCase) []domain.EvidenceID {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Tool == "goanalysis.Index.ModuleInternalReach" {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// SymbolExported reports whether the subject can be named by product code —
// the inverse of the unexported check used to decide whether a caller can
// invoke the subject symbol directly.
func SymbolExported(s domain.SymbolRef) bool {
	return !allUnexported([]domain.SymbolRef{s})
}

// allUnexported reports whether every subject symbol is package-internal —
// product code (and reflect/plugin lookups) cannot name them directly. That
// only rules out a direct call; it does not make a call into the owning
// module evidence of execution inside the package.
func allUnexported(subjects []domain.SymbolRef) bool {
	if len(subjects) == 0 {
		return false
	}
	for _, s := range subjects {
		name := s.Symbol
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || name[0] < 'a' || name[0] > 'z' {
			return false
		}
	}
	return true
}

func reachabilitySubjects(cond domain.Condition, c *domain.AnalysisCase) []domain.SymbolRef {
	var out []domain.SymbolRef
	switch {
	case len(cond.Subjects) > 0:
		out = append(out, cond.Subjects...)
	case cond.Subject != nil:
		out = append(out, *cond.Subject)
	default:
		if c.Exploit != nil {
			out = append(out, c.Exploit.RootCauses...)
		}
		if len(out) == 0 && c.RootCause != nil {
			for _, rc := range c.RootCause.RootCauses {
				out = append(out, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
			}
		}
	}
	// govulncheck traces to advisory-declared vulnerable symbols, which need
	// not coincide with the fix-commit-derived root causes (e.g. a network-
	// driven library sink). The advisory symbol set defines the vulnerable
	// code, so a trace reaching any of them proves reachability.
	for _, s := range c.Vulnerability.AffectedSymbols {
		if !containsSymbol(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// linkedOnly drops subjects whose packages are absent from the persisted
// build-graph evidence. When the package list is missing or undecodable the
// input is returned unchanged — a measurement failure is never absence.
func linkedOnly(c *domain.AnalysisCase, subjects []domain.SymbolRef) []domain.SymbolRef {
	set, _, err := packageImportSet(c)
	if err != nil {
		return subjects
	}
	out := subjects[:0]
	for _, s := range subjects {
		if s.Package == "" || set[s.Package] {
			out = append(out, s)
		}
	}
	return out
}

// joinSymbolNames renders the subject set for explanations and limitations.
func joinSymbolNames(subjects []domain.SymbolRef) string {
	names := make([]string, len(subjects))
	for i, s := range subjects {
		names[i] = s.Package + "." + s.Symbol
	}
	return strings.Join(names, ", ")
}

func containsSymbol(list []domain.SymbolRef, s domain.SymbolRef) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// allDeclared reports whether every evaluated subject is among the
// advisory's declared affected symbols — the set govulncheck actually
// traces call paths to. Subjects outside it (fix-diff root causes of a
// symbol-less entry) were never evaluated, so silence cannot falsify them.
func allDeclared(subjects, declared []domain.SymbolRef) bool {
	if len(declared) == 0 {
		return false
	}
	for _, s := range subjects {
		if !containsSymbol(declared, s) {
			return false
		}
	}
	return true
}

// govulncheckEvidence selects the case's applicable typed govulncheck
// measurement: the latest completed, context-matching run when one exists —
// a failed auxiliary invocation must not veto a completed collector
// measurement — otherwise the latest context-matching typed record. Nil
// means no usable measurement: legacy untyped evidence or no run at all,
// both of which can only support positive conclusions.
func govulncheckEvidence(c *domain.AnalysisCase) *domain.Evidence {
	effective := domain.EffectiveBuildContext(c.Product)
	evidence := c.EvidenceGraph.EvidenceList()
	var completed, latest *domain.Evidence
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != domain.EvidenceGovulncheck || e.Govulncheck == nil {
			continue
		}
		if e.BuildContext == nil || e.BuildContext.Matches(effective) != nil {
			continue
		}
		latest = e
		switch e.Govulncheck.Outcome {
		case domain.GovulncheckCompletedEmpty, domain.GovulncheckCompletedWithResults:
			completed = e
		}
	}
	if completed != nil {
		return completed
	}
	return latest
}

func appendUniqueID(ids []domain.EvidenceID, id domain.EvidenceID) []domain.EvidenceID {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

func frameMatches(cs domain.CallSite, sym domain.SymbolRef) bool {
	if cs.Package != sym.Package {
		return false
	}
	// Symbols may be receiver-qualified ("Type.Method"); call sites carry the
	// receiver separately ("*Type" + "Method").
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv, fn := sym.Symbol[:i], sym.Symbol[i+1:]
		return cs.Function == fn && normalizeReceiver(cs.Receiver) == recv
	}
	return cs.Function == sym.Symbol
}

func normalizeReceiver(r string) string {
	r = strings.TrimPrefix(r, "(")
	r = strings.TrimSuffix(r, ")")
	return strings.TrimPrefix(r, "*")
}
