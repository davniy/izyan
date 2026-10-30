package research

import (
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// slice2.go derives every Slice-2 contract extension field
// (slice2-fidelity/2 plus the slice2-fidelity/3 ladder) deterministically
// from the assembled report: the k8s-style category/component-scope
// contradiction, applicability basis with check scopes and agent-origin
// provisional grounds, evaluated advisory-entry status, vulnerable-code
// reachability, the three exploitation axes plus the optional
// non-carrier build_usage_scope audit axis (B41), condition roles, the
// attack_scenario status under semantics B, the derived evidence_level,
// unknown prioritisation, evidence materiality and the attempt ledger.
// Agent statements are never rewritten — contradictions and
// classification_review are additive.

// applySlice2 is the single Slice-2 entry point, called once per
// Assemble after all Slice-1 merge steps have run.
func (a *assembler) applySlice2(r *Report, in AssembleInput) {
	a.captureOutput(r, in)
	r.ContractExtensions = []string{Slice2ExtensionV3}
	a.slice2Contradictions(r)
	a.slice2Applicability(r)
	a.slice2GroundUnknowns(r)
	// The /4 request answer joins the question ledger as its own group, so an
	// analysis failure is never presented as environmental uncertainty and an
	// external dependency always names the fact that would resolve it. It
	// never widens product_applicability, the decision or the artifact.
	a.slice2RequestComposition(r)
	a.slice2Axes(r)
	// The optional B41 build-usage axis derives from the verified-fact
	// ledger only (never conditions, never agent output) and stays
	// nil when no BUILD_USAGE_SCOPE fact exists. Its companion
	// unknown/follow-up entries are emitted here — after the generic
	// obs unknowns already recorded by a.unknowns — so slice2Unknowns
	// can still group them; they never touch a condition.
	a.slice2BuildUsageScope(r)
	a.slice2UsageScopeUnknowns(r)
	// Roles are assigned before attack_scenario/evidence_level: both
	// derivations read role, and canonical agent path hypotheses must be
	// normalized (subject/necessity/state) before axis tagging.
	a.slice2ConditionRoles(r)
	a.slice2ECAxis(r)
	a.slice2Classification(r)
	a.slice2AttackStatus(r)
	a.slice2Downgrade(r)
	// evidence_level is derived last among the status fields: it reads
	// the final attack_scenario status (post-downgrade), the assigned
	// roles and the verified-fact ledger, never agent output.
	a.slice2EvidenceLevel(r)
	a.slice2Unknowns(r)
	a.slice2Recommendations(r)
	a.slice2Materiality(r)
	a.applyAttempts(r, in)
}

// ---- helpers ----

// agentCategory returns the preserved agent classification, or "".
func agentCategory(r *Report) string {
	if r.AgentOutput.Category != nil {
		return *r.AgentOutput.Category
	}
	return ""
}

// goImplModules returns the module names of the advisory's Go entries.
func (a *assembler) goImplModules() []string {
	var out []string
	for _, im := range a.lane.Advisory.Impls {
		if im.Ecosystem == "Go" && im.Module != "" {
			out = append(out, im.Module)
		}
	}
	return out
}

// cveLabel prefers a CVE-* alias over the internal advisory id.
func cveLabel(r *Report) string {
	for _, al := range r.Vulnerability.Aliases {
		if strings.HasPrefix(al, "CVE-") {
			return al
		}
	}
	return r.Vulnerability.ID
}

// advisoryRef is the resolvable ref for the frozen advisory document.
func (a *assembler) advisoryRef() string {
	return "adv:" + a.lane.Advisory.Input.ResolvedID
}

// factIDs returns the fact ids inside a ref list (order preserved).
func (a *assembler) factIDs(refs []string) []string {
	var out []string
	for _, ref := range refs {
		if a.factByID[ref] {
			out = append(out, ref)
		}
	}
	return out
}

// obsIDs returns the obs: refs inside a ref list (order preserved).
func (a *assembler) obsIDs(refs []string) []string {
	var out []string
	for _, ref := range refs {
		if strings.HasPrefix(ref, "obs:") && a.obsByID[ref] {
			out = append(out, ref)
		}
	}
	return out
}

// refsForTools returns fact ids (else obs ids) of observations made by
// the named tools, in observation order, regardless of tool status —
// used where even a failed check is cited as evidence the check ran.
func (a *assembler) refsForTools(tools ...string) []string {
	want := map[string]bool{}
	for _, t := range tools {
		want[t] = true
	}
	var out []string
	for _, o := range a.lane.Observations {
		if !want[o.Tool] {
			continue
		}
		if fid := a.lane.FactRef(o.ID); fid != "" {
			out = append(out, fid)
		} else {
			out = append(out, "obs:"+o.ID)
		}
	}
	return out
}

// okRefsForTools is refsForTools restricted to OK observations.
// Establishing evidence (the dynamic exploitation axis) may only come
// from a check that ran and returned a positive record — a failed or
// refused runtime observation is a limitation, never proof.
func (a *assembler) okRefsForTools(tools ...string) []string {
	want := map[string]bool{}
	for _, t := range tools {
		want[t] = true
	}
	var out []string
	for _, o := range a.lane.Observations {
		if !want[o.Tool] || o.ToolStatus != evidencetools.StatusOK {
			continue
		}
		if fid := a.lane.FactRef(o.ID); fid != "" {
			out = append(out, fid)
		} else {
			out = append(out, "obs:"+o.ID)
		}
	}
	return out
}

// paFactRefs returns the verified-fact ids backing the applicability
// chain: fact refs already in product_applicability.evidence_refs, else
// facts produced by the applicability tools (affected-resolve /
// get_module_version) — matched on the fact's own tool so observations
// without a recorded tool still resolve.
func (a *assembler) paFactRefs(pa ProductApplicability) []string {
	if ids := a.factIDs(pa.EvidenceRefs); len(ids) > 0 {
		return ids
	}
	var out []string
	for _, f := range a.lane.Facts {
		if f.Tool == "affected-resolve" || f.Tool == "get_module_version" {
			out = append(out, f.ID)
		}
	}
	return out
}

// firstGoModule is the first advisory Go module (the entry the
// applicability resolver evaluated for the single-module advisories in
// scope). Falls back to the resolved selected module.
func (a *assembler) firstGoModule(pa ProductApplicability) string {
	mods := a.goImplModules()
	if len(mods) > 0 {
		return mods[0]
	}
	if pa.SelectedModule != nil && *pa.SelectedModule != "" {
		return *pa.SelectedModule
	}
	if len(pa.SelectedModules) > 0 {
		return pa.SelectedModules[0]
	}
	return "the affected module"
}

// implPackageLabel is the advisory package (or module) name for prose.
func (a *assembler) implPackageLabel() string {
	for _, im := range a.lane.Advisory.Impls {
		if im.Ecosystem == "Go" && im.Package != nil && *im.Package != "" {
			return *im.Package
		}
	}
	if m := a.goImplModules(); len(m) > 0 {
		return m[0]
	}
	return "the affected package"
}

// implSymbolLabel is the first advisory symbol name for prose.
func (a *assembler) implSymbolLabel() string {
	for _, im := range a.lane.Advisory.Impls {
		if im.Ecosystem == "Go" && len(im.Symbols) > 0 {
			return im.Symbols[0]
		}
	}
	return "the vulnerable symbol"
}

// assertionsNaming returns ids of agent assertions whose text names m.
func assertionsNaming(r *Report, m string) []string {
	var out []string
	for _, as := range r.AgentAssertions {
		if strings.Contains(as.Statement, m) || strings.Contains(as.OriginalText, m) {
			out = append(out, as.ID)
		}
	}
	return out
}

func (a *assembler) nextContradiction() string {
	a.contraSeq++
	return fmt.Sprintf("C-%04d", a.contraSeq)
}

// ---- §3.1 contradictions ----

// slice2Contradictions emits contradiction records (§2.2, §3.1): the
// category/component-scope conflict when a safe category meets a fixed
// covered component, the advisory-scope gap for agent-named unbound
// components, and the applicability conflicts the Slice-1 merge already
// detected. Agent output is never mutated.
func (a *assembler) slice2Contradictions(r *Report) {
	cat := agentCategory(r)
	safe := safeCategories[cat]
	pa := r.ProductApplicability
	mod := a.firstGoModule(pa)
	fixed := pa.ModulePresent == "TRUE" && pa.VersionAffected == "FALSE" && pa.ResolvedVersion != nil
	paFacts := a.paFactRefs(pa)
	// Rule 2+3: safe category vs fixed covered component.
	if safe && fixed {
		var agRef *string
		if a.classAssertID != "" {
			agRef = strPtr(a.classAssertID)
		}
		r.Contradictions = append(r.Contradictions, Contradiction{
			ID:                a.nextContradiction(),
			Kind:              ContradictionCategoryVsComponentScope,
			Subject:           mod,
			AgentAssertionRef: agRef,
			DeterministicRefs: append(append([]string{}, paFacts...), a.obsIDs(pa.EvidenceRefs)...),
			Summary: fmt.Sprintf("the original category is retained for the evaluated fixed %s@%s entry, but the deterministic result does not establish that the CVE is absent from every implementation",
				mod, strOr(pa.ResolvedVersion, "?")),
			Resolution: ResolutionScopeLimits,
			Limitations: []string{fmt.Sprintf(
				"a fixed version for the evaluated %s entry is not a CVE-wide conclusion; advisory completeness for %s is unverified",
				mod, cveLabel(r))},
		})
	}
	// Rule 4: advisory scope gap per agent-named unbound component.
	for _, m := range a.scopeGapModules {
		var agRef *string
		if ids := assertionsNaming(r, m); len(ids) > 0 {
			agRef = strPtr(ids[0])
		}
		r.Contradictions = append(r.Contradictions, Contradiction{
			ID:                a.nextContradiction(),
			Kind:              ContradictionAdvisoryScopeGap,
			Subject:           m,
			AgentAssertionRef: agRef,
			DeterministicRefs: []string{a.advisoryRef()},
			Summary: fmt.Sprintf(
				"agent names product-relevant component %s outside the advisory's affected entries; the deterministic scope is bounded to the frozen entries",
				m),
			Resolution: ResolutionUnresolved,
			Limitations: []string{
				"a detected scope gap, not a proof that the frozen advisory is globally complete or incomplete",
			},
		})
	}
	// §7.6 classification conflicts already detected during the merge.
	for _, cf := range a.conflicts {
		var agRef *string
		if a.classAssertID != "" {
			agRef = strPtr(a.classAssertID)
		}
		r.Contradictions = append(r.Contradictions, Contradiction{
			ID:                a.nextContradiction(),
			Kind:              ContradictionCategoryVsApplicability,
			Subject:           cveLabel(r),
			AgentAssertionRef: agRef,
			DeterministicRefs: paFacts,
			Summary:           cf,
			Resolution:        ResolutionDeterministicPrevails,
		})
	}
}

// ---- §2.4 / §3.2 applicability basis ----

// slice2Applicability fills conclusion_scope, advisory_scope_status, the
// named basis list (each basis carries its check_scope) and
// vulnerable_code_reachability. Only the allowed non-applicability basis
// set can carry a NON_APPLICABLE classification, and only with verified
// refs; agent-origin grounds stay PROVISIONAL forever.
func (a *assembler) slice2Applicability(r *Report) {
	pa := &r.ProductApplicability
	// Advisory-scope status: GAP_DETECTED when preserved agent
	// assertions name product-relevant components outside the frozen
	// affected entries; UNKNOWN otherwise — no completeness oracle.
	if len(a.scopeGapModules) > 0 {
		pa.AdvisoryScopeStatus = ScopeGapDetected
	} else {
		pa.AdvisoryScopeStatus = ScopeUnknown
	}
	// Conclusion scope: CVE_WIDE is forbidden without deterministic
	// completeness evidence, which this lane cannot produce. ADVISORY_SET
	// applies when the frozen advisory holds several Go entries and no
	// gap was detected; AFFECTED_ENTRY_ONLY is the default.
	goEntries := len(a.goImplModules())
	switch {
	case pa.AdvisoryScopeStatus == ScopeComplete:
		pa.ConclusionScope = ScopeCVEWide
	case goEntries > 1 && pa.AdvisoryScopeStatus != ScopeGapDetected:
		pa.ConclusionScope = ScopeAdvisorySet
	default:
		pa.ConclusionScope = ScopeAffectedEntryOnly
	}
	paFacts := a.paFactRefs(*pa)
	paObs := a.obsIDs(pa.EvidenceRefs)
	mod := a.firstGoModule(*pa)
	scopeResolved := fmt.Sprintf("resolved module graph for %s (affected-resolve under the recorded snapshot build context)", mod)
	scopeImport := fmt.Sprintf("transitive import closure via go list -deps -test ./... under the recorded GOOS/GOARCH/build tags for %s", mod)
	agentScope := "agent-read product source scope (statements as preserved; runtime and configuration were not independently verified)"
	addBasis := func(kind, status, source, stmt, scope string, refs, vrefs, lims []string) {
		pa.Basis = append(pa.Basis, ApplicabilityBasis{
			Kind: kind, Status: status, Source: source, Statement: stmt,
			EvidenceRefs:         refs,
			VerifiedEvidenceRefs: vrefs,
			Limitations:          lims,
			CheckScope:           scope,
		})
	}
	refs := append(append([]string{}, paFacts...), paObs...)
	switch {
	case pa.ModulePresent == "FALSE":
		addBasis(ABComponentAbsent, ABEstablished, ABSourceDeterministic,
			fmt.Sprintf("the affected module %s is absent from the resolved module graph", mod),
			scopeResolved, refs, paFacts, nil)
	case pa.ModulePresent == "TRUE" && pa.VersionAffected == "FALSE" && pa.ResolvedVersion != nil:
		addBasis(ABVersionFixed, ABEstablished, ABSourceDeterministic,
			fmt.Sprintf("the advisory-covered %s entry resolves to fixed version %s under the recorded context", mod, *pa.ResolvedVersion),
			fmt.Sprintf("resolved version %s vs the evaluated entry's affected ranges (affected-resolve under the recorded snapshot build context)", strOr(pa.ResolvedVersion, "?")),
			refs, paFacts, []string{
				"bounded to the evaluated advisory entry; it does not establish the CVE is absent from every implementation",
			})
	case pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE" &&
		(pa.PackagePresent == "FALSE" || pa.BuildRelevant == "FALSE"):
		addBasis(ABNotInImportClosure, ABEstablished, ABSourceDeterministic,
			"the affected package is not in the product import closure / build scope under the recorded context",
			scopeImport, refs, paFacts, []string{
				"absence is asserted only for the recorded build context (build tags, GOOS/GOARCH)",
			})
	case pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE" &&
		pa.VulnerableImplementationPresent == "FALSE" &&
		pa.ImplementationTargetScope == "product":
		addBasis(ABImplementationAbsent, ABEstablished, ABSourceDeterministic,
			fmt.Sprintf("the advisory's vulnerable implementation %s is deterministically absent from the product build under the admitted %s supported-target scope",
				strOr(&pa.ImplementationLocus, "locus"), strOr(&pa.ImplementationTarget, "recorded")),
			fmt.Sprintf("deterministic implementation-locus verifier: file/function/marker + exact //go:build expression under the recorded target %s; every selected alternate scanned",
				strOr(&pa.ImplementationTarget, "recorded")),
			refs, paFacts, []string{
				"the locus is proposal-derived (LLM-inferred, admission-checked); only the deterministic verification result carries the absence",
				"the conclusion is bounded to the declared product target matrix",
			})
	case pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE":
		addBasis(ABComponentPresentAff, ABEstablished, ABSourceDeterministic,
			fmt.Sprintf("the affected component %s is present at an advisory-affected version%s", mod,
				func() string {
					if pa.ResolvedVersion != nil {
						return " (" + *pa.ResolvedVersion + ")"
					}
					return ""
				}()),
			scopeResolved, refs, paFacts, nil)
	}
	// §3.2.4: agent-named grounds stay PROVISIONAL — agent evidence, no
	// verified refs. Each independent ground keeps its own basis kind;
	// they are never merged into a deterministic basis.
	if refs := a.agentSDKBasisRefs(r); len(refs) > 0 {
		addBasis(ABSDKVsDaemon, ABProvisional, ABSourceAgent,
			"agent-named basis: the product uses the component's client/SDK surface while the advisory defect lives in the daemon/server implementation",
			agentScope, refs, nil, []string{
				"agent-stated only; no deterministic source bytes or reproducible recipe currently proves the SDK-vs-daemon distinction",
			})
	}
	if refs := a.agentConfigBasisRefs(r); len(refs) > 0 {
		addBasis(ABRequiredConfigAbsent, ABProvisional, ABSourceAgent,
			"agent-named basis: exploitation requires a configuration (feature flag/option/listener) the agent did not find enabled in the product",
			agentScope, refs, nil, []string{
				"agent-stated only; runtime configuration was not independently verified — absence of a config reference in source is not proof of absence in deployment",
			})
	}
	if refs := a.agentUnreachableBasisRefs(r); len(refs) > 0 {
		addBasis(ABVulnCodeNotReachable, ABProvisional, ABSourceAgent,
			"agent-named basis: the vulnerable code surface is claimed not reachable from product code",
			agentScope, refs, nil, []string{
				"agent-stated only; the deterministic lane did not independently verify the reachability claim",
			})
	}
	// vulnerable_code_reachability derives strictly from deterministic
	// data. FALSE requires an ESTABLISHED deterministic negative basis
	// (component_absent for a missing module, package_not_in_import_closure
	// for a probed package) with verified refs — an agent statement can
	// never produce FALSE, and a fixed evaluated entry forbids it. TRUE
	// likewise requires the verified applicability-probe refs behind the
	// enum fields (the same refs that carry the ESTABLISHED basis);
	// without them TRUE stays UNKNOWN rather than asserting a reachability
	// the record cannot support.
	negBasis := false
	for _, b := range pa.Basis {
		if b.Status != ABEstablished || b.Source != ABSourceDeterministic ||
			len(b.VerifiedEvidenceRefs) == 0 {
			continue
		}
		if pa.ModulePresent == "FALSE" && b.Kind == ABComponentAbsent {
			negBasis = true
		}
		if pa.ModulePresent == "TRUE" && b.Kind == ABNotInImportClosure &&
			(pa.PackagePresent == "FALSE" || pa.BuildRelevant == "FALSE") {
			negBasis = true
		}
		if pa.VulnerableImplementationPresent == "FALSE" && b.Kind == ABImplementationAbsent {
			negBasis = true
		}
	}
	switch {
	case pa.AdvisoryEntryStatus == EntryAffected &&
		pa.VulnerableImplementationPresent == "FALSE" &&
		pa.ImplementationTargetScope == "product" && len(paFacts) > 0:
		// The advisory's vulnerable implementation is not part of the
		// product build under the declared target matrix: the vulnerable
		// code is absent, not merely unreached.
		pa.VulnerableCodeReachability = VCRFalse
	case pa.AdvisoryEntryStatus == EntryAffected &&
		pa.PackagePresent == "TRUE" && pa.BuildRelevant == "TRUE" &&
		len(paFacts) > 0:
		pa.VulnerableCodeReachability = VCRTrue
	case pa.AdvisoryEntryStatus == EntryAffected &&
		(pa.PackagePresent == "FALSE" || pa.BuildRelevant == "FALSE") && negBasis:
		pa.VulnerableCodeReachability = VCRFalse
	case pa.ModulePresent == "FALSE" && negBasis:
		pa.VulnerableCodeReachability = VCRFalse
	case pa.ModulePresent == "TRUE" &&
		(pa.AdvisoryEntryStatus == EntryFixed || pa.AdvisoryEntryStatus == EntryNotEvaluated ||
			pa.AdvisoryEntryStatus == EntryMixed):
		pa.VulnerableCodeReachability = VCRNotEvaluated
	default:
		// The probe ran but did not decide (or no verified negative basis
		// backs a negative value) — reachability stays UNKNOWN.
		pa.VulnerableCodeReachability = VCRUnknown
	}
}

// agentSDKBasisRefs returns agent assertion ids asserting an
// SDK/client-vs-daemon distinction (§3.2): statements that contrast the
// daemon/server implementation with client-side use.
func (a *assembler) agentSDKBasisRefs(r *Report) []string {
	var out []string
	for _, as := range r.AgentAssertions {
		l := strings.ToLower(as.Statement + " " + as.OriginalText)
		if strings.Contains(l, "daemon") &&
			(strings.Contains(l, "sdk") || strings.Contains(l, "client") ||
				strings.Contains(l, "api")) {
			out = append(out, as.ID)
		}
	}
	return out
}

// agentConfigBasisRefs returns agent assertion ids asserting a required
// configuration is absent/disabled — a config term plus an absence
// marker. The preserved requires_configuration classification counts on
// its own.
func (a *assembler) agentConfigBasisRefs(r *Report) []string {
	var out []string
	if agentCategory(r) == "requires_configuration" && a.classAssertID != "" {
		out = append(out, a.classAssertID)
	}
	configToks := []string{"config", "flag", "setting", "option", "parameter", "property", "env var", "listener"}
	absentToks := []string{" not ", " no ", "never", "not set", "disabled", "absent", "missing", "without"}
	for _, as := range r.AgentAssertions {
		l := " " + strings.ToLower(as.Statement+" "+as.OriginalText) + " "
		cfg, neg := false, false
		for _, tk := range configToks {
			if strings.Contains(l, tk) {
				cfg = true
			}
		}
		for _, tk := range absentToks {
			if strings.Contains(l, tk) {
				neg = true
			}
		}
		if cfg && neg {
			out = append(out, as.ID)
		}
	}
	return dedupe(out)
}

// agentUnreachableBasisRefs returns agent assertion ids claiming the
// vulnerable code surface is not reachable — a reachability term plus a
// negation marker. The preserved code_not_reachable classification
// counts on its own.
func (a *assembler) agentUnreachableBasisRefs(r *Report) []string {
	var out []string
	if agentCategory(r) == "code_not_reachable" && a.classAssertID != "" {
		out = append(out, a.classAssertID)
	}
	negToks := []string{"not reachable", "unreachable", "not invoked", "never calls",
		"does not call", "do not call", "doesn't call", "does not reach", "never reaches",
		"not called", "never called", "not used", "never used", "dead code",
		"not compiled", "not linked", "cannot be reached"}
	for _, as := range r.AgentAssertions {
		l := strings.ToLower(as.Statement + " " + as.OriginalText)
		for _, tk := range negToks {
			if strings.Contains(l, tk) {
				out = append(out, as.ID)
				break
			}
		}
	}
	return dedupe(out)
}

// ---- §2.5 provisional-ground unknowns ----

// slice2GroundUnknowns emits one DECISION_CHANGING unknown per
// provisional applicability basis, with a concrete follow-up, plus the
// paired open/residual questions so question ids stay one-to-one.
func (a *assembler) slice2GroundUnknowns(r *Report) {
	pa := r.ProductApplicability
	cve := cveLabel(r)
	emit := func(stmt, reason, followUp, flips string, refs []string) {
		u := UnknownEntry{
			ID: a.nextUnknown(), Statement: stmt, Reason: reason,
			FollowUp: followUp, EvidenceRefs: refs,
			Group: "applicability", Priority: UnknownPriorityDecisionChanging,
			DecisionChangingFor: strPtr(flips),
		}
		r.Unknowns = append(r.Unknowns, u)
		id := a.nextQuestion()
		r.OpenQuestions = append(r.OpenQuestions, OpenQuestion{
			ID: id, Question: strings.TrimPrefix(u.Statement, "UNKNOWN: "),
			Subject: u.ID, Scope: "report scope", NextCheck: u.FollowUp,
			EvidenceRefs: u.EvidenceRefs,
		})
		r.ResidualQuestions = append(r.ResidualQuestions, ResidualQuestion{
			ID: id, Question: strings.TrimPrefix(u.Statement, "UNKNOWN: "),
			Why: "left unresolved by the lanes' stated scope", NextCheck: u.FollowUp,
			EvidenceRefs: u.EvidenceRefs,
		})
	}
	for _, b := range pa.Basis {
		if b.Status != ABProvisional || b.Source != ABSourceAgent {
			continue
		}
		switch b.Kind {
		case ABSDKVsDaemon:
			emit(
				"UNKNOWN: the agent's client/SDK-vs-daemon basis for "+cve+" is not independently verified",
				"agent-stated basis with no deterministic source bytes or reproducible recipe in verified_facts",
				"capture the exact product call sites (or a reproducible static recipe) showing only the client/SDK surface is used, then adjudicate the non-applicability basis",
				"classification_review status (a verified basis could lift the NON_APPLICABLE class from UNKNOWN to SUPPORTED)",
				b.EvidenceRefs)
		case ABRequiredConfigAbsent:
			emit(
				"UNKNOWN: the required configuration the agent reports absent for "+cve+" was not independently verified",
				"agent-stated basis; runtime configuration was outside the lane's check scope",
				"inspect the deployment/runtime configuration (feature flags, options, listeners) and confirm whether the named required configuration is enabled",
				"classification_review status (a verified absent configuration could lift the UNCERTAIN class)",
				b.EvidenceRefs)
		case ABVulnCodeNotReachable:
			emit(
				"UNKNOWN: the agent's vulnerable-code-not-reachable claim for "+cve+" is not independently verified",
				"agent-stated basis; the deterministic lane did not reproduce the reachability check",
				"run module_usage/go list -deps and caller scans under the full build context, then adjudicate the reachability basis",
				"classification_review status (a verified reachability basis could lift the NON_APPLICABLE class)",
				b.EvidenceRefs)
		}
	}
}

// ---- §2.3 / §3.3 axes ----

// slice2Axes populates the three exploitation axes strictly from
// deterministic facts. No agent assertion can raise an axis.
func (a *assembler) slice2Axes(r *Report) {
	pa := r.ProductApplicability
	pkg := a.implPackageLabel()
	sym := a.implSymbolLabel()
	mod := a.firstGoModule(pa)
	// code_reachability
	cr := Axis{
		Basis:        AxisBasisDeterministic,
		Scope:        "resolved module graph / snapshot build context",
		EvidenceRefs: append(append([]string{}, a.paFactRefs(pa)...), a.obsIDs(pa.EvidenceRefs)...),
	}
	symbolFacts := a.symbolLevelFacts()
	// The axis reads vulnerable_code_reachability, not the raw
	// package/build fields: a fixed evaluated entry (or any
	// NOT_EVALUATED reachability) must never state that the vulnerable
	// code is absent — only that reachability was not evaluated.
	switch {
	case pa.VulnerableCodeReachability == VCRTrue:
		cr.Status = AxisEstablished
		cr.Level = LevelPackageBuild
		cr.Statement = fmt.Sprintf(
			"the advisory package %s is in the product import closure and build-relevant under the recorded context", pkg)
		cr.Limitations = []string{fmt.Sprintf(
			"this does not establish a %s call, symbol execution, runtime configuration, or attacker reachability", sym)}
		if len(symbolFacts) > 0 {
			cr.Level = LevelSymbol
			cr.Statement += fmt.Sprintf("; a deterministic symbol/call fact exists (%s)", strings.Join(symbolFacts, ", "))
			cr.EvidenceRefs = append(cr.EvidenceRefs, symbolFacts...)
		}
	case pa.VulnerableCodeReachability == VCRFalse:
		cr.Status = AxisNotEstablished
		cr.Level = LevelModule
		if pa.ModulePresent == "FALSE" {
			cr.Level = LevelNone
			cr.Statement = fmt.Sprintf(
				"the affected module %s is absent from the resolved module graph; vulnerable-code reachability is not established", mod)
		} else {
			cr.Statement = fmt.Sprintf(
				"the affected package of %s is not in the product import closure / build scope under the recorded context; vulnerable-code reachability is not established", mod)
		}
	case pa.VulnerableCodeReachability == VCRNotEvaluated && pa.AdvisoryEntryStatus == EntryFixed:
		cr.Status = AxisNotEstablished
		cr.Level = LevelModule
		cr.Statement = fmt.Sprintf(
			"the evaluated advisory entry for %s resolves to fixed version %s; vulnerable-code reachability was not evaluated for it under the recorded context",
			mod, strOr(pa.ResolvedVersion, "?"))
		cr.Limitations = []string{
			"reachability not evaluated: the package/build probe did not run because the evaluated entry is fixed",
			"a fixed version is not evidence of code absence — the module may still be compiled into the product",
		}
	case pa.VulnerableCodeReachability == VCRNotEvaluated:
		cr.Status = AxisUnknown
		cr.Level = LevelModule
		cr.Statement = fmt.Sprintf(
			"the affected module %s is present, but the evaluated advisory entries carry no fix/affected verdict; vulnerable-code reachability was not evaluated", mod)
		cr.Limitations = []string{
			"reachability not evaluated: module presence alone does not establish or exclude that the advisory package is compiled in",
		}
	case pa.ModulePresent == "TRUE":
		cr.Status = AxisUnknown
		cr.Level = LevelModule
		cr.Statement = fmt.Sprintf(
			"the affected module %s is present, but package-level reachability of the vulnerable code is undecided at the recorded scope", mod)
		cr.Limitations = []string{
			"module presence alone does not establish that the advisory package is compiled in",
		}
	default:
		cr.Status = AxisUnknown
		cr.Level = LevelNone
		cr.Statement = "vulnerable-code reachability is undecided at the recorded scope"
		cr.Limitations = []string{
			"the applicability chain did not resolve module presence/affectedness; rerun the applicability checks under the full build context",
		}
	}
	if pa.VulnerableCodeReachability == VCRNotEvaluated {
		notEval := false
		for _, lim := range cr.Limitations {
			if strings.Contains(lim, "not evaluated") {
				notEval = true
			}
		}
		if !notEval {
			cr.Limitations = append(cr.Limitations,
				"vulnerable-code reachability not evaluated under the recorded scope")
		}
	}
	r.ExploitationAxes.CodeReachability = cr
	// attack_surface_availability — only from deterministic facts with a
	// relevant inbound-surface scope.
	surf := Axis{
		Scope: "product source tree (static scan scope)",
	}
	if facts, stmt, n := a.surfaceFacts(); n > 0 {
		surf.Status = AxisEstablished
		surf.Level = LevelStaticCapability
		surf.Basis = AxisBasisDeterministic
		surf.EvidenceRefs = facts
		surf.Statement = stmt
		surf.Limitations = []string{
			"static source capability is not runtime availability; a source listener is not a runtime-available socket",
		}
	} else {
		surf.Status = AxisUnknown
		surf.Level = LevelNone
		surf.Basis = AxisBasisNone
		surf.Statement = "no deterministic listener/socket fact at this scope — runtime attack-surface availability is unknown"
		surf.Limitations = []string{
			"bounded static scans do not prove absence; runtime availability requires runtime evidence (level RUNTIME_AVAILABLE)",
		}
		if failed := a.refsForTools("listen-sites", "find_entrypoints", "inbound-auth-facts"); len(failed) > 0 {
			surf.EvidenceRefs = failed
		}
	}
	r.ExploitationAxes.AttackSurfaceAvailability = surf
	// exploitation_established — never ESTABLISHED without dynamic
	// evidence (§2.3): at least one OK runtime/dynamic observation that
	// was promoted to a verified fact. The axis cites every OK dynamic
	// record, but an unverifiable or failed check can never carry the
	// ESTABLISHED status on its own.
	ex := Axis{
		Scope: "whole report scope",
	}
	dyn := a.okRefsForTools(dynamicAxisToolOrder...)
	dynFacts := 0
	for _, ref := range dyn {
		if a.factByID[ref] {
			dynFacts++
		}
	}
	if dynFacts > 0 {
		ex.Status = AxisEstablished
		ex.Level = LevelDynamicReproduction
		ex.Basis = AxisBasisDynamic
		ex.EvidenceRefs = dyn
		ex.Statement = "a retained dynamic/runtime observation establishes attacker exploitability at the recorded scope"
	} else {
		ex.Status = AxisNotEstablished
		ex.Level = LevelNone
		ex.Basis = AxisBasisNone
		ex.EvidenceRefs = dyn
		ex.Statement = "attacker exploitability is not established: package reachability and an agent-described scenario do not prove socket availability, attacker access, malformed-message delivery, or a resulting panic"
		ex.Limitations = []string{
			"NOT_ESTABLISHED means not proven, never proven impossible; it requires a retained dynamic trace, runtime observation, or reproduction",
		}
	}
	r.ExploitationAxes.ExploitationEstablished = ex
}

// ---- §2.3 optional build-usage axis (B41) ----

// buildUsageScopeAxisLimitations are the fixed interpretation bounds
// the build_usage_scope axis always carries: the classification is a
// package/module build-closure statement only — no source-use,
// runtime, deployment or safety conclusion — and a test-only product
// absence stays bounded to the recorded no-test closure.
var buildUsageScopeAxisLimitations = []string{
	"the classification is package/module build-closure membership under the recorded build context only",
	"no source-level use, runtime execution, reflection/plugin/generated loading, deployment or safety conclusion is implied by any class",
	"a test-only product absence is verified only inside the recorded `go list -deps -json ./...` closure under the recorded build context — never a runtime, deployment or other-build-configuration claim",
}

// slice2BuildUsageScope fills the optional /3 audit axis through the
// same pure helper the validator recomputes (fail-closed compare).
// The assembler receiver is intentionally unused — the axis reads only
// the report's verified-fact ledger, never lane internals, and no
// agent assertion can populate it.
func (a *assembler) slice2BuildUsageScope(r *Report) {
	r.ExploitationAxes.BuildUsageScope = deriveBuildUsageScopeAxis(r)
}

// deriveBuildUsageScopeAxis computes the optional audit axis purely
// from r.VerifiedFacts: with no BUILD_USAGE_SCOPE fact there is no
// axis (nil — /1 and /2 documents never carry the member); with at
// least one, the axis is ESTABLISHED when every recorded class is
// known (product, test-only, mixed) and UNKNOWN when any recorded
// class is the undetermined absent-from-both class or unclassifiable.
// Level is always PACKAGE_BUILD, basis always deterministic, and
// evidence refs are exactly the BUILD_USAGE_SCOPE fact ids in sorted
// order — the axis is strictly non-carrier: it names no condition,
// closes nothing, and never feeds evidence_level.
func deriveBuildUsageScopeAxis(r *Report) *Axis {
	var refs []string
	classes := map[UsageScope]int{}
	unknown := 0
	for _, f := range r.VerifiedFacts {
		if f.Kind != FactKindBuildUsageScope {
			continue
		}
		refs = append(refs, f.ID)
		switch UsageScope(f.UsageScope) {
		case UsageScopeProduct, UsageScopeTestOnly, UsageScopeMixed:
			classes[UsageScope(f.UsageScope)]++
		default:
			unknown++
		}
	}
	if len(refs) == 0 {
		return nil
	}
	sort.Strings(refs)
	ax := &Axis{
		Status:       AxisEstablished,
		Level:        LevelPackageBuild,
		Basis:        AxisBasisDeterministic,
		Scope:        "paired `go list -deps -json ./...` (no -test) and `go list -deps -test -json ./...` build closures under the recorded build context",
		EvidenceRefs: refs,
		Limitations:  append([]string{}, buildUsageScopeAxisLimitations...),
	}
	var parts []string
	for _, c := range []UsageScope{UsageScopeProduct, UsageScopeTestOnly, UsageScopeMixed} {
		if n := classes[c]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, string(c)))
		}
	}
	if unknown > 0 {
		ax.Status = AxisUnknown
		ax.Statement = fmt.Sprintf(
			"build-closure classification is undetermined for %d of %d checked subject(s) — a subject absent from both recorded closures or an unclassifiable record is undetermined, never a non-use or safety claim",
			unknown, len(refs))
	} else {
		ax.Statement = fmt.Sprintf(
			"build-closure classification complete for %d checked subject(s): %s — membership in the recorded product and/or test build closures only",
			len(refs), strings.Join(parts, ", "))
	}
	return ax
}

// buildUsageScopeConflicts returns {B41, B42} fact-id pairs where a
// package-level BUILD_USAGE_SCOPE fact with usage_scope=test-only
// coexists with a carrier kind=PACKAGE_USAGE fact for the same
// {Module,Package} subject — an incompatible pair the validator
// rejects as forged (B41 says the package is absent from the closed
// product build closure while B42 asserts a product-source verdict for
// it). A module-level aggregate (empty package) never participates,
// PACKAGE_USAGE_LOWER_BOUND stays non-carrier and is not
// reinterpreted, and the package-usage fact's own symbol component is
// ignored: subject equality is {Module,Package} only.
func buildUsageScopeConflicts(r *Report) [][2]string {
	type modPkg struct{ mod, pkg string }
	carriers := map[modPkg]string{}
	for _, f := range r.VerifiedFacts {
		if f.Kind != FactKindPackageUsage || f.UsageSubject == nil || f.UsageSubject.Package == "" {
			continue
		}
		// Only a fact that asserts USE contradicts a test-only scope. A
		// package-usage fact recording a verified NON-use (claim FALSE)
		// agrees with it: both say the product closure does not use the
		// package, so flagging that pair would reject a consistent report.
		if f.Claim != "TRUE" {
			continue
		}
		k := modPkg{f.UsageSubject.Module, f.UsageSubject.Package}
		if carriers[k] == "" || f.ID < carriers[k] {
			carriers[k] = f.ID
		}
	}
	var out [][2]string
	for _, f := range r.VerifiedFacts {
		if f.Kind != FactKindBuildUsageScope || f.UsageSubject == nil ||
			f.UsageSubject.Package == "" ||
			UsageScope(f.UsageScope) != UsageScopeTestOnly {
			continue
		}
		k := modPkg{f.UsageSubject.Module, f.UsageSubject.Package}
		if other := carriers[k]; other != "" {
			out = append(out, [2]string{f.ID, other})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// ---- B41 unknown/follow-up entries ----

// slice2UsageScopeUnknowns emits the explicit B41 unknown entries the
// generic non-OK pass cannot word: a degraded paired stream (OK but
// below COMPLETE — skipped packages, truncation or a downgraded
// coverage claim) that must never promote, an undecodable payload, and
// the auditable absent-from-both class itself — a closed check whose
// target is in neither recorded closure is recorded as undetermined,
// never as a non-use or safety claim. Tool ERROR/TIMEOUT/UNSUPPORTED
// rows already carry the generic "check did not produce a result"
// unknown; every entry cites only its own observation (plus the
// promoted unknown-class fact where one exists), never a condition.
func (a *assembler) slice2UsageScopeUnknowns(r *Report) {
	emit := func(u UnknownEntry) {
		u.ID = a.nextUnknown()
		r.Unknowns = append(r.Unknowns, u)
		id := a.nextQuestion()
		r.OpenQuestions = append(r.OpenQuestions, OpenQuestion{
			ID: id, Question: strings.TrimPrefix(u.Statement, "UNKNOWN: "),
			Subject: u.ID, Scope: "report scope", NextCheck: u.FollowUp,
			EvidenceRefs: u.EvidenceRefs,
		})
		r.ResidualQuestions = append(r.ResidualQuestions, ResidualQuestion{
			ID: id, Question: strings.TrimPrefix(u.Statement, "UNKNOWN: "),
			Why: "left unresolved by the lanes' stated scope", NextCheck: u.FollowUp,
			EvidenceRefs: u.EvidenceRefs,
		})
	}
	for _, o := range a.lane.Observations {
		if o == nil || o.Tool != evidencetools.UsageScopeTool {
			continue
		}
		if o.ToolStatus != evidencetools.StatusOK {
			// ERROR / TIMEOUT / UNSUPPORTED: the generic unknown entry
			// already names the check and its status; nothing here
			// would add a second statement for the same row.
			continue
		}
		if o.Completeness != evidencetools.CompletenessComplete {
			emit(UnknownEntry{
				Statement: fmt.Sprintf(
					"UNKNOWN: the usage-scope check did not close the paired build-closure stream for its subject (%s)",
					o.Completeness),
				Reason: "a degraded paired stream — skipped packages, truncation or a downgraded coverage claim — is never a verified build-closure classification and never negative proof",
				FollowUp: fmt.Sprintf(
					"re-run usage-scope under the recorded build context so both `go list -deps` streams decode and edge-close completely (the incomplete stream cannot classify the subject; %s)",
					firstN(o.Error, 200)),
				EvidenceRefs: []string{"obs:" + o.ID},
				Group:        "build_usage_scope",
				Priority:     UnknownPriorityAppendix,
			})
			continue
		}
		d, ok := usageScopeDataOf(o)
		if !ok {
			emit(UnknownEntry{
				Statement:    "UNKNOWN: the usage-scope payload is undecodable; no build-closure classification was recorded",
				Reason:       "an OK observation without a decodable usage_scope payload is never a classification and never negative proof",
				FollowUp:     "re-run usage-scope under the recorded build context; an undecodable result is auditable evidence of failure only",
				EvidenceRefs: []string{"obs:" + o.ID},
				Group:        "build_usage_scope",
				Priority:     UnknownPriorityAppendix,
			})
			continue
		}
		if UsageScope(d.UsageScope) == UsageScopeUnknown {
			target := d.Module
			if d.Package != "" {
				target = d.Module + " | " + d.Package
			}
			emit(UnknownEntry{
				Statement: fmt.Sprintf(
					"UNKNOWN: %s is absent from both recorded build closures (usage_scope=unknown)",
					target),
				Reason:       "the paired go list streams closed completely but the target appears in neither the product nor the test closure — the result is undetermined, never a non-use or safety claim",
				FollowUp:     "no follow-up inside the recorded scope can raise this class; if the subject must resolve, capture a different build context or an advisory-declared package inside either closure",
				EvidenceRefs: factRefs(a.lane, o),
				Group:        "build_usage_scope",
				Priority:     UnknownPriorityAppendix,
			})
		}
	}
}

// ---- §/3 condition roles and the deterministic evidence ladder ----

// staticCarrierTools is the closed allowlist of deterministic tools
// whose verified facts may close a required applicability/path
// condition for L1 (design: only OK static evidence can carry a
// source-scope transition; run_govulncheck is supporting evidence, and
// advisory-load is advisory scope, not a path carrier). Membership is
// looked up, never iterated for output.
var staticCarrierTools = map[string]bool{
	// applicability and version
	"affected-resolve":     true,
	"get_module_version":   true,
	"get_dependency_graph": true,
	// import/call chain
	"module_usage":          true,
	"module_internal_reach": true,
	"find_symbol":           true,
	"find_callers":          true,
	"find_may_callers":      true,
	"find_dep_callers":      true,
	"ingress-inventory":     true,
	"package-usage":         true,
	// static surface and inbound entry
	"find_entrypoints":         true,
	"listen-sites":             true,
	"inbound-auth-facts":       true,
	"interface_dispatch_sites": true,
	"gated_refs":               true,
	"scan_dynamic":             true,
	"dial-sites":               true,
	// transition/guard checks
	"trace_argument":        true,
	"find_validations":      true,
	"check_call_site_guard": true,
	"dep_invocation_state":  true,
}

// conditionRoleForSubject maps a canonical condition subject to its
// fixed role (slice2-fidelity/3). The table is closed: module presence
// and version-in-use are applicability preconditions, package
// reachability and build relevance are exploit-path transitions,
// runtime/deployment posture and inbound listeners are deployment scope
// facts that never block L1, and every other subject is supporting
// material. Agent-supplied role values are never read — the role is
// always recomputed here.
func conditionRoleForSubject(subject string) string {
	switch subject {
	case subjModulePresence, subjVersionInUse:
		return ConditionRoleApplicability
	case subjPackageReach, subjBuildRelevant, subjProductPackageUsage:
		return ConditionRolePath
	case subjRuntimePosture, subjInboundListener:
		return ConditionRoleDeployment
	default:
		return ConditionRoleSupporting
	}
}

// canonicalPathSubject reports the canonical path-transition subject
// for an agent claim subject, or "" when the claim is not a canonical
// path predicate. Normalization is deliberately narrow — surrounding
// whitespace and letter case only — so that arbitrary scenario prose
// can never be silently reclassified into a required condition.
func canonicalPathSubject(subject string) string {
	n := strings.ToLower(strings.TrimSpace(subject))
	switch n {
	case subjPackageReach, subjBuildRelevant, subjProductPackageUsage:
		return n
	}
	return ""
}

// slice2ConditionRoles assigns the /3 role to every exploitation
// condition (§3.2.3/semantics B). Deterministic conditions take the
// fixed subject table. An agent-origin hypothesis is never trusted as
// evidence: when its subject canonicalizes into a required path
// predicate the condition is marked required and stays OPEN — an
// unconfirmed hypothesis that blocks L1 — while a non-canonical claim
// becomes supporting material that the ladder ignores.
func (a *assembler) slice2ConditionRoles(r *Report) {
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Origin == OriginAgent {
			if canonicalPathSubject(c.Subject) != "" {
				c.Role = ConditionRolePath
				c.Necessity = "required"
				c.State = StateOpen
			} else {
				c.Role = ConditionRoleSupporting
			}
			continue
		}
		c.Role = conditionRoleForSubject(c.Subject)
	}
}

// slice2EvidenceLevel derives and stores report.evidence_level through
// the same pure helper the validator recomputes (fail-closed compare).
// The assembler receiver is intentionally unused — derivation must not
// consult lane or agent internals beyond what the report carries.
func (a *assembler) slice2EvidenceLevel(r *Report) {
	el := deriveEvidenceLevel(r)
	r.EvidenceLevel = &el
}

// evidenceLevelDisclaimer is the permanent caveat emitted on every
// level: the ladder describes the proven state of the exploit path,
// never product safety, and the absence of L3 only means dynamic proof
// was not recorded.
const evidenceLevelDisclaimer = "Уровень описывает доказанность exploit path, а не безопасность продукта; отсутствие L3 означает отсутствие динамического доказательства, но не означает «неэксплуатируемо» (not exploitable)."

// deriveEvidenceLevel computes the /3 evidence ladder purely from the
// report's condition ledger, verified facts, axes and attack_scenario —
// it never reads r.EvidenceLevel and never consults agent assertions or
// lane internals. Priority is L3 → L1 → L2:
//   - L3 requires the established dynamic axis (ESTABLISHED + basis
//     dynamic + level DYNAMIC_REPRODUCTION) backed by at least one
//     verified fact from the closed dynamic tool set, plus
//     attack_scenario=SUPPORTED.
//   - L1 requires a non-empty required applicability/path set where
//     every such condition is deterministic, SUPPORTED and backed by an
//     OK verified fact from the static carrier allowlist, while the
//     dynamic axis is not ESTABLISHED and attack_scenario is neither
//     SUPPORTED nor PARTIAL. Deployment-role conditions (runtime
//     posture, inbound listener) are never blockers.
//   - L2 is the remainder: the path chain is still open.
func deriveEvidenceLevel(r *Report) EvidenceLevel {
	el := EvidenceLevel{Scope: "whole report scope"}
	// Index verified facts once; refs resolve only into this set —
	// agent-src refs, assertion ids, advisory refs and obs-only ids can
	// never be carriers.
	facts := make(map[string]*VerifiedFact, len(r.VerifiedFacts))
	for i := range r.VerifiedFacts {
		facts[r.VerifiedFacts[i].ID] = &r.VerifiedFacts[i]
	}
	// closedStaticCondition reports whether a required applicability/
	// path condition is proven: deterministic origin, SUPPORTED state
	// and at least one evidence ref resolving to an OK verified fact
	// from the static carrier allowlist. The package-usage path
	// predicate additionally binds the carrier: only a kind=
	// PACKAGE_USAGE fact whose usage_subject equals the condition's
	// advisory-declared candidate closes it — a different candidate's
	// fact, a kind=PACKAGE_USAGE_LOWER_BOUND fact (an open-scope
	// positive, never a USED verdict) or an unbound condition never
	// closes the path.
	closedStaticCondition := func(c *ExploitationCondition) bool {
		if c.Origin != OriginDeterm || c.State != StateSupported {
			return false
		}
		usageBound := c.Subject == subjProductPackageUsage
		for _, ref := range c.EvidenceRefs {
			f := facts[ref]
			if f == nil || f.Status != "OK" || !staticCarrierTools[f.Tool] {
				continue
			}
			if usageBound {
				if f.Kind != FactKindPackageUsage || f.UsageSubject == nil || c.UsageSubject == nil ||
					*f.UsageSubject != *c.UsageSubject {
					continue
				}
			}
			return true
		}
		return false
	}
	// Ledger pass: required applicability/path conditions gate L1 and
	// populate blocking_conditions; evidence refs accumulate in
	// condition order; condition_refs accumulate in ledger order.
	// Trust boundary: only deterministic-origin conditions contribute
	// refs — an agent hypothesis is never a carrier, and a verified-fact
	// id attached to an agent condition must never leak into the ladder.
	var blocking []string
	requiredApplPath := 0
	refutedPath := false
	seenCond, seenRef := map[string]bool{}, map[string]bool{}
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if !seenCond[c.ID] {
			seenCond[c.ID] = true
			el.ConditionRefs = append(el.ConditionRefs, c.ID)
		}
		if c.Origin == OriginDeterm {
			for _, ref := range c.EvidenceRefs {
				f := facts[ref]
				// A BUILD_USAGE_SCOPE fact is strictly non-carrier:
				// attached to a condition it still never enters the
				// ladder's evidence_refs.
				if f != nil && f.Status == "OK" && f.Kind != FactKindBuildUsageScope && !seenRef[ref] {
					seenRef[ref] = true
					el.EvidenceRefs = append(el.EvidenceRefs, ref)
				}
			}
		}
		if c.Necessity != "required" ||
			(c.Role != ConditionRoleApplicability && c.Role != ConditionRolePath) {
			continue
		}
		requiredApplPath++
		if c.Role == ConditionRolePath && c.State == StateRefuted {
			refutedPath = true
		}
		if !closedStaticCondition(c) {
			blocking = append(blocking, c.ID)
		}
	}
	el.BlockingConditions = blocking
	// L3: dynamic carrier facts are the exploitation_established axis
	// refs that resolve to OK verified facts from the closed dynamic
	// tool set, kept in axis order so evidence_refs stays byte-stable.
	ex := r.ExploitationAxes.ExploitationEstablished
	var dynRefs []string
	seenRef = map[string]bool{}
	for _, ref := range ex.EvidenceRefs {
		f := facts[ref]
		if f != nil && f.Status == "OK" && dynamicAxisTools[f.Tool] && !seenRef[ref] {
			seenRef[ref] = true
			dynRefs = append(dynRefs, ref)
		}
	}
	switch {
	case ex.Status == AxisEstablished &&
		ex.Basis == AxisBasisDynamic &&
		ex.Level == LevelDynamicReproduction &&
		len(dynRefs) > 0 &&
		r.AttackScenario.Status == StatusSupported:
		el.Level = EvidenceLevelL3
		el.Basis = EvidenceBasisDynamic
		el.EvidenceRefs = dynRefs
		el.Statement = "Динамическая эксплуатация подтверждена: зафиксированы execution/reproduction/runtime observation evidence в записанной области."
		el.Limitations = []string{
			"L3 подтверждён только в записанной области (recorded scope): динамическое доказательство относится к зафиксированным наблюдениям и не обобщается за их пределы",
			evidenceLevelDisclaimer,
		}
	case requiredApplPath > 0 &&
		len(blocking) == 0 &&
		ex.Status != AxisEstablished &&
		r.AttackScenario.Status != StatusSupported &&
		r.AttackScenario.Status != StatusPartial:
		el.Level = EvidenceLevelL1
		el.Basis = EvidenceBasisDeterministic
		el.Statement = "Статический exploit path подтверждён детерминистическими фактами в записанной области; runtime exploitation не проверена."
		el.Limitations = []string{
			"L1 означает только завершённость статического доказательства пути в записанной области: он не означает безопасность конфигурации и не подтверждает runtime exploitation",
			"динамическое выполнение не наблюдалось: для подтверждения фактической эксплуатации требуется verified dynamic fact (runtime-observation, dynamic-trace или reproduction)",
			evidenceLevelDisclaimer,
		}
	default:
		el.Level = EvidenceLevelL2
		// L2 basis: deterministic when at least one relevant verified
		// deterministic carrier exists (static carrier tool or a
		// recorded dynamic observation); otherwise none. Agent material
		// never contributes a basis.
		el.Basis = EvidenceBasisNone
		for i := range r.VerifiedFacts {
			f := &r.VerifiedFacts[i]
			if f.Status == "OK" && (staticCarrierTools[f.Tool] || dynamicAxisTools[f.Tool]) {
				el.Basis = EvidenceBasisDeterministic
				break
			}
		}
		el.Statement = "Потенциальный exploit path: цепочка обязательных applicability/path условий не замкнута — доказательство кандидатного пути не завершено."
		el.Limitations = []string{
			"L2 означает незавершённое доказательство кандидатного пути: открытые условия перечислены в blocking_conditions",
		}
		if refutedPath {
			el.Limitations = append(el.Limitations,
				"blocking_conditions включает REFUTED path condition — path refuted in bounded scope: опровержение ограничено записанной областью и никогда не является заключением о безопасности продукта, auto-close, VEX или not-affected disposition")
		}
		el.Limitations = append(el.Limitations, evidenceLevelDisclaimer)
	}
	return el
}

// symbolLevelFacts returns fact refs of OK symbol/call observations
// that actually found a declaration or call site (level SYMBOL).
func (a *assembler) symbolLevelFacts() []string {
	var out []string
	for _, o := range a.lane.Observations {
		if o.ToolStatus != "OK" {
			continue
		}
		switch o.Tool {
		case "find_symbol":
			if dataHas(o, "found", true) {
				if fid := a.lane.FactRef(o.ID); fid != "" {
					out = append(out, fid)
				}
			}
		case "find_callers", "find_dep_callers":
			if len(callSitesOf(o, 1)) > 0 {
				if fid := a.lane.FactRef(o.ID); fid != "" {
					out = append(out, fid)
				}
			}
		}
	}
	return out
}

// surfaceFacts returns fact refs + a statement when a deterministic
// inbound-surface observation recorded actual listener/socket sites.
func (a *assembler) surfaceFacts() ([]string, string, int) {
	for _, o := range a.lane.Observations {
		if o.ToolStatus != "OK" {
			continue
		}
		switch o.Tool {
		case "listen-sites", "inbound-auth-facts", "find_entrypoints":
			if n := factCount(o); n > 0 {
				var refs []string
				if fid := a.lane.FactRef(o.ID); fid != "" {
					refs = append(refs, fid)
				} else {
					refs = append(refs, "obs:"+o.ID)
				}
				return refs, fmt.Sprintf(
					"static source capability: %s records %d inbound listener/endpoint site(s) in product source at the recorded scope",
					o.Tool, n), n
			}
		}
	}
	return nil, "", 0
}

// ---- §2.4 classification review ----

// slice2Classification fills classification_review. The original agent
// category is preserved verbatim; the review only reconciles it.
func (a *assembler) slice2Classification(r *Report) {
	cr := &r.ClassificationReview
	cat := agentCategory(r)
	if cat != "" {
		cr.OriginalCategory = strPtr(cat)
	}
	pa := r.ProductApplicability
	// basis_refs: verified fact ids + agent assertion ids that carry a
	// basis (design example mixes fact and A-* refs).
	for _, b := range pa.Basis {
		cr.BasisRefs = append(cr.BasisRefs, b.VerifiedEvidenceRefs...)
		for _, ref := range b.EvidenceRefs {
			if strings.HasPrefix(ref, "A-") {
				cr.BasisRefs = append(cr.BasisRefs, ref)
			}
		}
	}
	cr.BasisRefs = dedupe(cr.BasisRefs)
	switch {
	case cat == "":
		cr.Class = ClassNotEvaluated
		cr.Status = "NOT_EVALUATED"
	case safeCategories[cat]:
		cr.Class = ClassNonApplicable
	case cat == "vulnerable":
		cr.Class = ClassApplicable
	default:
		cr.Class = ClassUncertain
	}
	hasScopeContra := false
	for _, c := range r.Contradictions {
		if c.Kind == ContradictionCategoryVsComponentScope {
			hasScopeContra = true
		}
	}
	// Only the deterministic non-applicability bases that actually prove
	// absence (§3.2.1) can carry a NON_APPLICABLE/SUPPORTED review:
	// component_absent (module missing from the graph) and
	// package_not_in_import_closure (probed package absent). A
	// version_fixed basis is evidence of a fix, never of absence, and
	// agent-origin grounds stay PROVISIONAL — neither supports the class.
	// The validator independently re-checks that the basis is ESTABLISHED,
	// deterministic, verified, and cited in basis_refs.
	hasEstablishedBasis := false
	for _, b := range pa.Basis {
		if b.Status == ABEstablished && b.Source == ABSourceDeterministic &&
			len(b.VerifiedEvidenceRefs) > 0 &&
			(b.Kind == ABComponentAbsent || b.Kind == ABNotInImportClosure ||
				(b.Kind == ABImplementationAbsent && pa.VulnerableImplementationPresent == "FALSE")) {
			hasEstablishedBasis = true
		}
	}
	switch cr.Class {
	case ClassNonApplicable:
		switch {
		case hasScopeContra:
			cr.Status = StatusConflicted
			cr.Limitations = append(cr.Limitations,
				"the category is retained for the evaluated fixed entry only; the deterministic result does not establish the CVE is absent from every implementation")
		case hasEstablishedBasis:
			cr.Status = StatusSupported
		default:
			cr.Status = StatusUnknown
			cr.Limitations = append(cr.Limitations,
				"no verified non-applicability basis (component_absent|package_not_in_import_closure|vulnerable_implementation_absent) resolves in verified_facts — a fixed version is evidence of a fix, not of absence; the preserved category is retained but not established")
		}
	case ClassApplicable:
		switch {
		case pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE":
			cr.Status = StatusSupported
		case pa.ModulePresent == "FALSE" || pa.VersionAffected == "FALSE":
			cr.Status = StatusConflicted
		default:
			cr.Status = StatusUnknown
		}
	case ClassUncertain:
		cr.Status = StatusUnknown
	}
}

// ---- §5 attack_scenario status ----

// transitionSubjects enumerates the subjects the /2 validator treats as
// exploit-path predicates for the legacy PARTIAL check; module presence
// and version-in-use are applicability preconditions and never count as
// confirmed transitions on their own. Under semantics B the assembler
// itself reasons over condition roles (slice2ConditionRoles): only
// role=path transitions count, and role=deployment conditions —
// runtime/deployment posture and inbound listener — can never create
// PARTIAL.
var transitionSubjects = map[string]bool{
	subjPackageReach:        true,
	subjBuildRelevant:       true,
	subjProductPackageUsage: true,
	subjRuntimePosture:      true,
	subjInboundListener:     true,
}

// slice2AttackStatus recomputes the attack_scenario section status
// under semantics B: a section whose material is agent hypotheses is
// UNKNOWN, never PARTIAL; PARTIAL requires at least one confirmed
// deterministic role=path transition (deterministic origin, SUPPORTED
// state, backed by a resolvable verified fact) plus a still-open
// required role=path transition — an open deployment posture alone
// never yields PARTIAL; SUPPORTED requires established exploitation.
// CONFLICTED would require an explicit unresolved contradiction of the
// scenario material — none of the emitted contradiction kinds
// contradicts it, so it is never used to mask an unknown.
func (a *assembler) slice2AttackStatus(r *Report) {
	sec := &r.AttackScenario
	ex := r.ExploitationAxes.ExploitationEstablished
	detTransitions, reqUnknown := 0, 0
	// BUILD_USAGE_SCOPE facts are strictly non-carrier: cited on a
	// SUPPORTED path predicate they never count as a confirmed
	// transition toward PARTIAL.
	b41 := map[string]bool{}
	for i := range r.VerifiedFacts {
		if r.VerifiedFacts[i].Kind == FactKindBuildUsageScope {
			b41[r.VerifiedFacts[i].ID] = true
		}
	}
	for _, c := range r.ExploitationConditions {
		if c.Origin != OriginDeterm || c.Role != ConditionRolePath {
			continue
		}
		switch c.State {
		case StateSupported:
			// A confirmed transition is a deterministic SUPPORTED
			// exploit-path (role=path) predicate backed by a non-B41
			// verified fact — an applicability precondition, a
			// deployment scope fact, a build-usage audit fact or an
			// obs-only result does not count.
			for _, ref := range a.factIDs(c.EvidenceRefs) {
				if !b41[ref] {
					detTransitions++
					break
				}
			}
		case StateUnknown:
			if c.Necessity == "required" {
				reqUnknown++
			}
		}
	}
	switch {
	case ex.Status == AxisEstablished:
		sec.Status = StatusSupported
	case detTransitions >= 1 && reqUnknown >= 1:
		sec.Status = StatusPartial
		if !strings.Contains(sec.Summary, "exploit path is not established") {
			base := "deterministic transitions are partially confirmed, but the exploit path is not established — required predicates remain unknown"
			if isUnknownSummary(sec.Summary) || sec.Summary == "" {
				sec.Summary = "PARTIAL: " + base
				if agentSum := a.agentSummary["attack"]; agentSum != "" {
					sec.Summary += "; agent-stated: " + firstN(agentSum, 400)
				}
			} else {
				sec.Summary += "; the exploit path is not established — required predicates remain unknown"
			}
		}
	default:
		sec.Status = StatusUnknown
		if !isUnknownSummary(sec.Summary) {
			old := sec.Summary
			sec.Summary = unknownSummary(
				"the exploit path is not established — the available material does not confirm a required transition chain",
				"verify each recorded predicate: re-run the deterministic reachability/surface checks under the full build context and obtain dynamic evidence if exploitability must be established")
			if old != "" {
				sec.Summary += "; agent-stated: " + firstN(old, 400)
			}
		}
	}
	sec.Limitations = append(sec.Limitations,
		"agent-described transitions are hypotheses (origin=agent/OPEN): a potential call chain alone does not establish the exploit path")
}

// ---- §3.2.3 dependent-section downgrade ----

// slice2Downgrade forces dependent non-applicability sections to UNKNOWN
// when a safe classification lacks an established basis.
func (a *assembler) slice2Downgrade(r *Report) {
	cr := r.ClassificationReview
	if cr.Class != ClassNonApplicable || cr.Status != StatusUnknown {
		return
	}
	down := func(sec *Section, what string) {
		old := sec.Summary
		sec.Status = StatusUnknown
		fu := "capture exact source bytes or a reproducible static recipe for the agent's named applicability basis, then adjudicate the non-applicability conclusion"
		sec.Summary = fmt.Sprintf("UNKNOWN: %s is not established (no verified applicability basis); follow-up: %s", what, fu)
		if old != "" && !isUnknownSummary(old) {
			sec.Summary += "; agent-stated: " + firstN(old, 400)
		}
		sec.Limitations = append(sec.Limitations,
			"downgraded per §3.2: classification_review is UNKNOWN — preserved agent statements remain unverified agent assertions")
	}
	down(&r.AttackScenario, "a non-applicability attack conclusion")
	down(&r.ProductExposure, "a non-applicability exposure conclusion")
}

// ---- §2.3 EC axis tags ----

// slice2ECAxis tags each exploitation condition with its axis.
func (a *assembler) slice2ECAxis(r *Report) {
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		switch c.Subject {
		case subjModulePresence, subjVersionInUse, subjPackageReach, subjBuildRelevant, subjProductPackageUsage:
			c.Axis = ECAxisCodeReachability
		case subjRuntimePosture, subjInboundListener:
			c.Axis = ECAxisAttackSurface
		default:
			c.Axis = ECAxisOther
		}
	}
}

// ---- §2.5 unknown prioritisation ----

// slice2Unknowns assigns group/priority/decision_changing_for to every
// unknown. DECISION_CHANGING is reserved for unknowns whose resolution
// could flip a named conclusion; everything else is APPENDIX.
func (a *assembler) slice2Unknowns(r *Report) {
	pa := r.ProductApplicability
	cve := cveLabel(r)
	mod := a.firstGoModule(pa)
	fixedDesc := "affected entry"
	if pa.ResolvedVersion != nil {
		fixedDesc = fmt.Sprintf("fixed %s@%s", mod, *pa.ResolvedVersion)
	}
	axCR := r.ExploitationAxes.CodeReachability
	axSurf := r.ExploitationAxes.AttackSurfaceAvailability
	// obs unknowns are recognized by their obs: evidence ref / reason.
	obsTool := map[string]string{}
	for _, o := range a.lane.Observations {
		obsTool["obs:"+o.ID] = o.Tool
	}
	toolGroup := func(tool string) string {
		switch tool {
		case "module_usage", "find_symbol", "find_callers", "find_may_callers",
			"find_dep_callers", "module_internal_reach", "get_module_version",
			"get_dependency_graph", "ingress-inventory":
			return "code_reachability"
		case "usage-scope":
			return "build_usage_scope"
		case "listen-sites", "dial-sites", "find_entrypoints", "inbound-auth-facts",
			"interface_dispatch_sites", "gated_refs", "scan_dynamic":
			return "attack_surface"
		case "affected-resolve":
			return "applicability"
		case "run_govulncheck", "trace_argument", "find_validations",
			"check_call_site_guard", "dep_invocation_state":
			return "evidence"
		case "advisory-load":
			return "advisory_scope"
		default:
			return "other"
		}
	}
	for i := range r.Unknowns {
		u := &r.Unknowns[i]
		if u.Group != "" {
			// Pre-grouped entries (provisional-ground unknowns) already
			// carry group/priority/decision_changing_for.
			continue
		}
		switch {
		case strings.Contains(u.Reason, "not a resolved dependency module"):
			// Agent-named non-dependency token: informational only —
			// never decision-changing, never a contradiction.
			u.Group = "advisory_scope"
			u.Priority = UnknownPriorityAppendix
			u.DecisionChangingFor = nil
		case strings.Contains(u.Reason, "advisory scope gap") ||
			strings.Contains(u.Reason, "binding failed"):
			u.Group = "advisory_scope"
			u.Priority = UnknownPriorityDecisionChanging
			u.DecisionChangingFor = strPtr(fmt.Sprintf(
				"whether the %s entry can be generalized to the %s conclusion", fixedDesc, cve))
		case strings.Contains(u.Statement, "no usable Go package"):
			u.Group = "advisory_scope"
			u.Priority = UnknownPriorityDecisionChanging
			u.DecisionChangingFor = strPtr(
				"the applicability of the incomplete advisory entry (it could add affected scope)")
		case strings.Contains(u.Statement, "release toolchain"):
			u.Group = "other"
			u.Priority = UnknownPriorityAppendix
		case strings.Contains(u.Statement, "agent assessment did not complete"):
			u.Group = "exploitability"
			u.Priority = UnknownPriorityDecisionChanging
			u.DecisionChangingFor = strPtr(
				"classification_review class/status (no agent classification was produced)")
		case strings.Contains(u.Statement, "resolved version of module"):
			u.Group = "applicability"
			if pa.VersionAffected == "UNKNOWN" {
				u.Priority = UnknownPriorityDecisionChanging
				u.DecisionChangingFor = strPtr(
					"product_applicability.version_affected for that module (its resolved version is undecided)")
			} else {
				u.Priority = UnknownPriorityAppendix
			}
		case strings.HasPrefix(u.Statement, "UNKNOWN: residual correctness"):
			u.Group = "other"
			u.Priority = UnknownPriorityAppendix
		default:
			// Non-OK observation unknowns: group by tool; priority only
			// when resolving could flip a currently-undecided conclusion.
			tool := ""
			for _, ref := range u.EvidenceRefs {
				if t, ok := obsTool[ref]; ok {
					tool = t
					break
				}
			}
			u.Group = toolGroup(tool)
			switch u.Group {
			case "code_reachability":
				if axCR.Status != AxisEstablished {
					u.Priority = UnknownPriorityDecisionChanging
					u.DecisionChangingFor = strPtr(fmt.Sprintf(
						"code_reachability status (the %s check that could decide it did not complete)", tool))
				} else {
					u.Priority = UnknownPriorityAppendix
				}
			case "attack_surface":
				if axSurf.Status != AxisEstablished {
					u.Priority = UnknownPriorityDecisionChanging
					u.DecisionChangingFor = strPtr(fmt.Sprintf(
						"attack_surface_availability status (the %s check that could decide it did not complete)", tool))
				} else {
					u.Priority = UnknownPriorityAppendix
				}
			case "applicability":
				u.Priority = UnknownPriorityDecisionChanging
				u.DecisionChangingFor = strPtr(
					"product_applicability status (the applicability chain did not resolve)")
			default:
				u.Priority = UnknownPriorityAppendix
			}
		}
		if u.Priority == UnknownPriorityAppendix {
			u.DecisionChangingFor = nil
		}
	}
}

// ---- §6 recommendations ----

// slice2Recommendations appends the next-check recommendations the
// Slice-2 findings imply. Human-owned; never authoritative.
func (a *assembler) slice2Recommendations(r *Report) {
	cr := r.ClassificationReview
	if cr.Class == ClassNonApplicable && cr.Status == StatusUnknown {
		r.Recommendations = append(r.Recommendations, Recommendation{
			ID: a.nextRec(), Owner: "operator",
			Action: "capture exact source bytes or a reproducible static recipe proving the agent's named applicability basis (e.g. client/SDK-only use vs the daemon/server defect surface), then adjudicate the basis",
			Reason: "the non-applicability classification is UNKNOWN: no verified evidence ref currently proves the agent's named basis",
		})
	}
	if len(a.scopeGapModules) > 0 {
		r.Recommendations = append(r.Recommendations, Recommendation{
			ID: a.nextRec(), Owner: "human",
			Action: fmt.Sprintf(
				"adjudicate the advisory scope (whether %s belong to this CVE's affected set) before treating any local fixed-version fact as a CVE conclusion",
				strings.Join(a.scopeGapModules, ", ")),
			Reason: "advisory_scope_status is GAP_DETECTED; conclusion_scope stays AFFECTED_ENTRY_ONLY",
		})
	}
	if agentCategory(r) == "vulnerable" &&
		r.ExploitationAxes.AttackSurfaceAvailability.Status == AxisUnknown {
		r.Recommendations = append(r.Recommendations, Recommendation{
			ID: a.nextRec(), Owner: "operator",
			Action: "verify deployment attack-surface availability (listener/socket lifetime and permissions, credential configuration) and obtain runtime/dynamic evidence if exploitability must be established",
			Reason: "the attack-surface axis is UNKNOWN and exploitation_established stays NOT_ESTABLISHED without dynamic evidence",
		})
	}
}

// ---- §2.6 materiality ----

// materialTools are the deterministic tools whose facts directly drive
// applicability, contradictions, axes or the recommendation (§2.6).
var materialTools = map[string]bool{
	"affected-resolve": true, "advisory-load": true,
	"listen-sites": true, "dial-sites": true, "inbound-auth-facts": true,
	"find_entrypoints": true, "ingress-inventory": true,
	"module_usage": true, "find_symbol": true, "find_callers": true,
	"find_dep_callers": true, "find_may_callers": true,
	"module_internal_reach": true, "package-usage": true,
	"get_module_version": true, "get_dependency_graph": true,
	"get_product_snapshot": true, "get_vulnerability": true,
}

// slice2Materiality attaches raw-bytes and reproducible-source records
// to verified facts and evidence references.
func (a *assembler) slice2Materiality(r *Report) {
	var env map[string]string
	for _, kv := range a.lane.ToolEnv {
		if strings.HasPrefix(kv, "GO") || strings.HasPrefix(kv, "PATH=") ||
			strings.HasPrefix(kv, "HOME=") {
			if env == nil {
				env = map[string]string{}
			}
			if i := strings.Index(kv, "="); i > 0 {
				env[kv[:i]] = kv[i+1:]
			}
		}
	}
	for i := range r.VerifiedFacts {
		f := &r.VerifiedFacts[i]
		level := MaterialitySupporting
		if materialTools[f.Tool] {
			level = MaterialityMaterial
		}
		m := &Materiality{Level: level}
		if f.Artifact.Path != "" {
			m.RawBytes = &MaterialityRaw{
				Path: f.Artifact.Path, SHA256: f.Artifact.SHA256,
				SizeBytes: f.Artifact.SizeBytes, Selector: "observation",
			}
		}
		m.ReproducibleSource = &ReproducibleSource{
			Kind:                "COMMAND",
			Command:             strPtr(f.Command),
			WorkingDir:          strPtr(a.lane.SnapshotRoot),
			Tool:                strPtr(f.Tool),
			ToolVersion:         strPtr(f.ToolVersion),
			SnapshotContentHash: strPtr(f.SnapshotContentHash),
			InputDigest:         strPtr(f.InputDigest),
			Env:                 env,
			Selector:            "observation JSON payload",
			OutputSHA256:        f.DataDigest,
		}
		f.Materiality = m
	}
	// Evidence references.
	for i := range r.EvidenceQuality.References {
		e := &r.EvidenceQuality.References[i]
		switch e.Kind {
		case "advisory":
			e.Materiality = &Materiality{
				Level: MaterialityMaterial,
				RawBytes: &MaterialityRaw{
					Path:     a.lane.Advisory.Input.SourcePath,
					SHA256:   a.lane.Advisory.Input.RawSHA256,
					Selector: "frozen advisory document",
				},
				ReproducibleSource: &ReproducibleSource{
					Kind: "FILE", Path: strPtr(a.lane.Advisory.Input.SourcePath),
					Selector:     "canonical OSV projection",
					OutputSHA256: a.lane.Advisory.Input.CanonicalSHA256,
				},
			}
		case "agent-source":
			if e.SHA256 != "" {
				e.Materiality = &Materiality{
					Level: MaterialityMaterial,
					RawBytes: &MaterialityRaw{
						Path: e.Path, SHA256: e.SHA256,
						Selector: "retained agent answer bytes",
					},
				}
			}
		default: // observation
			if e.SHA256 != "" {
				e.Materiality = &Materiality{
					Level: MaterialityMaterial,
					RawBytes: &MaterialityRaw{
						Path: e.Path, SHA256: e.SHA256,
						Selector: e.Selector,
					},
				}
			}
		}
	}
}

// slice2RequestComposition records the /4 request answer in the report's own
// unknown/question ledger. The distinction the ledger must preserve is the
// terminal-policy one: an analysis FAILURE names its typed cause and never reads
// as an environmental abstention, and an EXTERNAL_DEPENDENCY names the one fact
// that would settle it. A DECIDED request adds nothing: the answer is already
// the requested-finding section, and a decided request must not manufacture
// decision-changing unknowns.
//
// The function is deliberately additive. It never touches
// product_applicability, the record-bound decision, the decision artifact or
// its advisory binding: corpus enumeration and cross-record composition confer
// no authority on those record-bound surfaces.
func (a *assembler) slice2RequestComposition(r *Report) {
	composition := r.RequestComposition
	if (r.Schema != ReportSchemaV4 && r.Schema != ReportSchemaV5) || composition == nil {
		return
	}
	emit := func(statement, reason, followUp string) {
		entry := UnknownEntry{
			ID:        a.nextUnknown(),
			Statement: "UNKNOWN: " + statement,
			Reason:    reason,
			FollowUp:  followUp,
			// "other" is the contract's catch-all group; the request
			// answer has no dedicated group and inventing one would make
			// the document invalid. DECISION_CHANGING must name the
			// conclusion it could flip.
			Group:               "other",
			Priority:            UnknownPriorityDecisionChanging,
			DecisionChangingFor: strPtr("the requested finding's outcome for " + composition.RequestedID),
		}
		r.Unknowns = append(r.Unknowns, entry)
		id := a.nextQuestion()
		r.OpenQuestions = append(r.OpenQuestions, OpenQuestion{
			ID: id, Question: statement, Subject: entry.ID,
			Scope: "requested finding scope", NextCheck: followUp,
		})
		r.ResidualQuestions = append(r.ResidualQuestions, ResidualQuestion{
			ID: id, Question: statement, Why: reason, NextCheck: followUp,
		})
	}
	switch composition.Outcome {
	case domain.OutcomeFailed:
		for _, gap := range composition.Gaps {
			emit(
				fmt.Sprintf("the requested analysis of %s failed on %s/%s (%s); no verdict is published",
					composition.RequestedID, gap.Owner, gap.Code, gap.Obligation),
				gap.Message,
				"complete the named proof obligation; an unfinished analysis is a failure, not an environmental answer")
		}
	case domain.OutcomeExternal:
		for _, dep := range composition.ExternalDependencies {
			emit(
				fmt.Sprintf("the requested analysis of %s depends on an external fact: %s",
					composition.RequestedID, dep.MissingFact),
				dep.WhyArtifactCannotSupply,
				dep.ResolvingEvidence)
		}
	}
}
