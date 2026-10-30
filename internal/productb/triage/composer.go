package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/risk"
)

// DecisionRule is one versioned risk rule: when its Applicability
// predicate evaluates SATISFIED over the collected facts, the rule permits
// its Recommendation. A rule that evaluates UNKNOWN stays undecided — it
// cannot fire, and its undecided premise is recorded as a residual
// assumption that blocks weaker reductions.
type DecisionRule struct {
	ID             string         `json:"id"`
	Recommendation Recommendation `json:"recommendation"`
	Applicability  Predicate      `json:"applicability"`
	Reason         string         `json:"reason,omitempty"`
}

// DecisionProfile is the machine contract of one recommendation profile
// (spec §11.4): an applicability predicate over the fact set, the fact
// kinds the profile's decisions require to be decisive, conditions whose
// non-SATISFIED state blocks risk reduction, and the disposition this
// profile would support if it were selected — used only to populate
// conditional_profiles, never to change the main recommendation.
type DecisionProfile struct {
	ID            string         `json:"id"`
	DisplayName   string         `json:"display_name,omitempty"`
	Applicability Predicate      `json:"applicability"`
	RequiredFacts []string       `json:"required_facts,omitempty"`
	Conditions    []Condition    `json:"conditions,omitempty"`
	Expected      Recommendation `json:"expected_disposition,omitempty"`
}

// Composer is the deterministic machine-disposition writer (spec §6.5): it
// combines the authoritative baseline, provider facts, the selected
// profile, the permitted rules and the check results into exactly one
// machine recommendation. Nothing outside the composer writes the machine
// recommendation, residual assumptions, triggers or conditional profiles,
// and nothing here reads the model judgment or the proposed human action as
// a machine premise. Human-work bounds can replace the published action with
// KEEP_OPEN; the original assessment and judgment remain unchanged.
type Composer struct {
	// Rules is the admitted risk ruleset; nil selects DefaultRules.
	Rules []DecisionRule
	// Profiles is the admitted profile set in selection order; nil selects
	// DefaultProfiles. The first profile whose applicability is SATISFIED
	// wins; a non-applicable profile never grounds a reduction.
	Profiles []DecisionProfile
	// Providers feed the fact collection; nil selects DefaultProviders.
	Providers []FactProvider
	// Checks is the pre-package check set evaluated over the collected
	// facts when the caller did not pass CheckResults to Compose.
	Checks []Check
	// RunID, ExecutionMode and the audit hashes bind the package to this
	// run; empty RunID falls back to a deterministic finding-bound id.
	RunID         string
	ExecutionMode string
	RulesetHash   string
	Limits        BudgetConfig
	BudgetResult  string
	// StabilityResult stamps a precomputed stability_result verbatim —
	// replay uses it to reproduce a recorded package whose stability
	// document is absent. A live run leaves it empty and supplies the
	// report through Stability instead.
	StabilityResult string
	// Stability is the retry report evaluated over this run (spec §2.4).
	// A report carrying drift is a technical error — composition fails
	// closed and no package exists. Semantic instability demotes: the
	// recommendation collapses to UNCHANGED (DISMISSED/LOWERED are
	// forbidden without a stable basis), support drops and the
	// divergence reasons enter limitations and residual_assumptions.
	// The composer never selects a preferred attempt.
	Stability *StabilityReport
	// DefaultBaselineSeverity is the configured baseline severity the
	// composer falls back to when neither the advisory nor the intake
	// supplies one (site config baseline.default_severity). An empty value
	// leaves the package without baseline metadata — the human result is
	// still delivered, the machine disposition records the withheld
	// reduction. A configured fallback is never recorded as derived
	// evidence — the package names its source and carries the limitation.
	DefaultBaselineSeverity string
	// historicalReplay is set only by the version-specific replay adapter.
	historicalReplay bool
}

// ComposeDecision composes the decision package with the default composer
// configuration. Configured runs use Composer.Compose for run id, ruleset
// and budget binding.
func ComposeDecision(
	ctx context.Context,
	s0 Stage0Result,
	assessment Assessment,
	validation FactValidation,
	checks []CheckResult,
	providers []FactProvider,
) (DecisionPackage, error) {
	c := Composer{Providers: providers}
	return c.Compose(ctx, s0, assessment, validation, checks)
}

// Compose is the no-observation entry point: it runs the §6.5 machine
// precedence over the collected facts and derives support from the premise
// graph without a recorded observation archive. Callers that carry
// observations and a verifier report use ComposeWithEvidence.
func (c Composer) Compose(
	ctx context.Context,
	s0 Stage0Result,
	assessment Assessment,
	validation FactValidation,
	checks []CheckResult,
) (DecisionPackage, error) {
	return c.ComposeWithEvidence(ctx, s0, assessment, validation, EvidenceInput{Checks: checks})
}

// EvidenceInput carries the deterministic evidence a package is composed
// from: the check results, the recorded tool observations and the falsifier
// verification report. A nil report means the run produced no falsifier
// proposals at all — a structural fact, never a safety claim.
type EvidenceInput struct {
	Checks       []CheckResult
	Observations []RecordedObservation
	Falsifiers   *FalsifierReport
	// SelectedAttempt binds premise support to the selected observation
	// archive: only observations recorded by that attempt may ground a
	// premise. Zero accepts every recorded attempt, which is correct for a
	// run without a retry series.
	SelectedAttempt int
}

// ComposeWithEvidence composes one decision package from the full evidence
// set: it preserves the model judgment, bounds the published human action,
// computes the machine disposition from the deterministic path and derives
// support from the decisive premise graph. Human readiness grants no authority.
func (c Composer) ComposeWithEvidence(
	ctx context.Context,
	s0 Stage0Result,
	assessment Assessment,
	validation FactValidation,
	evidence EvidenceInput,
) (DecisionPackage, error) {
	checks := evidence.Checks
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return DecisionPackage{}, err
	}
	fail := func(format string, args ...any) (DecisionPackage, error) {
		return DecisionPackage{}, fmt.Errorf("compose decision: "+format, args...)
	}

	// The agent's structured result is a mandatory input: a malformed
	// verdict means the package cannot be honestly built — this is a
	// technical error channel, never an UNCHANGED recommendation.
	if !assessment.Verdict.Valid() {
		return fail("assessment verdict %q is not a valid assessment.v2 verdict", assessment.Verdict)
	}
	findingID := s0.Input.Finding.FindingID
	if findingID == "" {
		return fail("stage0 result carries no finding_id")
	}
	if a := strings.TrimSpace(assessment.FindingID); a != "" && a != findingID {
		return fail("assessment finding_id %q does not match stage0 finding %q", a, findingID)
	}
	assessmentVersion := AssessmentSchemaVersion
	if c.historicalReplay { assessmentVersion = "assessment.v2" }
	if assessment.SchemaVersion != "" && assessment.SchemaVersion != assessmentVersion {
		return fail("assessment schema_version %q is not %s", assessment.SchemaVersion, assessmentVersion)
	}

	// Provenance drift between stability retries is a technical error
	// (spec §2.4): a package composed over inputs that drifted is never
	// emitted — the caller's error channel carries it as exit 2.
	if c.Stability != nil && c.Stability.Drift {
		return fail("provenance drift between stability attempts: %s", strings.Join(c.Stability.Limitations, "; "))
	}

	// 1. Baseline metadata. It is optional: a ticket without a severity
	// still yields a complete human package. When it is absent no machine
	// reduction is admitted — the entitlement it started from is unknown.
	baseline, baselineDefaulted, err := composeBaseline(s0, c.DefaultBaselineSeverity)
	if err != nil {
		return fail("baseline: %w", err)
	}

	// 2. Validated facts: providers first, then the deterministic fact set.
	providers := c.Providers
	if providers == nil {
		providers = DefaultProviders()
	}
	falsifierProofs := []FalsifierProof(nil)
	falsifierHash := ""
	if evidence.Falsifiers != nil {
		falsifierProofs = append(falsifierProofs, evidence.Falsifiers.Proofs...)
		falsifierHash = evidence.Falsifiers.Hash
	}
	facts, providerErrs := collectFacts(ctx, providers, ProviderInput{
		Stage0:         s0,
		Assessment:     assessment,
		FactValidation: validation,
		Recorded:       evidence.Observations,
		Falsifiers:     evidence.Falsifiers,
	})
	factSet := decisionFactSet(facts)

	// 3. Selected profile.
	profiles := c.Profiles
	if profiles == nil {
		profiles = DefaultProfiles()
	}
	profile, profDef := selectProfile(profiles, factSet)

	// 4. Permitted rules: the first SATISFIED rule wins; an UNKNOWN premise
	// on a stronger rule is recorded and blocks weaker reductions.
	rules := c.Rules
	if rules == nil {
		rules = DefaultRules()
	}
	candidate, fired := evaluateDecisionRules(rules, factSet)
	undecided := undecidedRuleConditions(rules, candidate, factSet)

	// 5. Checks: caller-supplied results win; a nil slice evaluates the
	// default pre-package set over the collected facts.
	var checkResults []CheckResult
	if checks != nil {
		checkResults = checks
	} else {
		checkSet := c.Checks
		if checkSet == nil {
			checkSet = PrePackageChecks()
		}
		checkResults = RunChecks(ctx, checkSet, CheckInput{
			Stage0:     s0,
			Assessment: assessment,
			Validation: validation,
			Facts:      facts,
			Profiles:   profiles,
			Rules:      rules,
		})
	}
	byID := CheckResultsByID(checkResults)

	// 6. Demotion: anything short of a complete, verified basis forbids
	// DISMISSED/LOWERED. Integrity violations that make an honest package
	// impossible stay technical errors.
	rec := candidate
	var demotions, limitations []string
	demote := func(reason string) {
		if rec != RecommendationUnchanged {
			demotions = append(demotions,
				fmt.Sprintf("rule %s permitted %s; demoted to UNCHANGED: %s", fired.ID, candidate, reason))
		}
		rec = RecommendationUnchanged
	}
	if len(providerErrs) > 0 {
		limitations = append(limitations, providerErrs...)
		demote("a fact provider failed; missing context is not a negative fact")
	}
	if baselineDefaulted {
		limitations = append(limitations, "baseline severity is a configured default, not derived from the ticket")
	}
	if baseline == nil {
		limitations = append(limitations,
			"no authoritative severity baseline is recorded for this finding; the machine disposition withholds every reduction")
		demote("no authoritative severity baseline is available")
	}
	for _, cid := range prePackageCheckIDs {
		res, ok := byID[cid]
		if !ok {
			demote(fmt.Sprintf("check %s was not executed", cid))
			continue
		}
		switch res.Status {
		case CheckPass:
		case CheckLimitation:
			limitations = append(limitations, res.Reasons...)
		case CheckUnavailable:
			limitations = append(limitations, res.Reasons...)
			demote(fmt.Sprintf("check %s is UNAVAILABLE", cid))
		case CheckUnverified:
			limitations = append(limitations, res.Reasons...)
			demote(fmt.Sprintf("check %s is UNVERIFIED: %s", cid, firstReason(res)))
		case CheckConflicting, CheckInvalid:
			limitations = append(limitations, res.Reasons...)
			if integrityCheckID(cid) {
				return fail("check %s is %s: %s", cid, res.Status, firstReason(res))
			}
			demote(fmt.Sprintf("check %s is %s: %s", cid, res.Status, firstReason(res)))
		case CheckError:
			return fail("check %s failed: %s", cid, firstReason(res))
		default:
			limitations = append(limitations, res.Reasons...)
			demote(fmt.Sprintf("check %s returned unknown status %q", cid, res.Status))
		}
	}
	// Post-package checks that ran early report UNAVAILABLE for a missing
	// package — a caller-supplied C12/C13 result is still honored, but a
	// never-run one is not a demotion: the composer verifies the package
	// contract itself below.
	for _, cid := range []string{CheckIDRiskPolicy, CheckIDPackageStability} {
		res, ok := byID[cid]
		if !ok {
			continue
		}
		switch res.Status {
		case CheckPass, CheckUnavailable:
		case CheckError:
			return fail("check %s failed: %s", cid, firstReason(res))
		default:
			demote(fmt.Sprintf("check %s is %s: %s", cid, res.Status, firstReason(res)))
		}
	}

	// Decision-relevant intake fields that never reached VALID block
	// reduction (spec §4.2); absent optional fields do not.
	for _, fv := range s0.Validation.Fields {
		if fv.BlocksRiskReduction && fv.Status != IntakeValid {
			demote(fmt.Sprintf("intake field %s is %s", fv.Field, fv.Status))
			limitations = append(limitations, fieldReason(fv.Field, fv))
		}
	}

	// Two-track arbitration. The LLM verdict and the deterministic
	// recommendation are independent opinions: a deterministic reduction is
	// only applied when the LLM agrees the finding is not exploitable, and
	// a negative LLM verdict the deterministic layer cannot confirm is
	// escalated to a human. Divergence never silently becomes EXPLOITABLE
	// or an unexplained UNCHANGED — the package carries both opinions and
	// the NEEDS_ARBITRATION status.
	llmVerdict := strings.TrimSpace(string(assessment.Verdict))
	arbitration := ArbitrationAgreeKeep
	arbitrationNeeded := false
	llmNegative := assessment.Verdict == VerdictNotExploitable
	switch {
	case candidate == RecommendationDismissed && llmNegative:
		arbitration = ArbitrationAgreeDismiss
	case candidate == RecommendationLowered && llmNegative:
		arbitration = ArbitrationAgreeLower
	case candidate != RecommendationUnchanged:
		arbitration = ArbitrationDivergeHuman
		arbitrationNeeded = true
		demote(fmt.Sprintf("LLM verdict %s and the deterministic reduction %s diverge; the machine layer withholds the reduction", orDash(llmVerdict), candidate))
	case llmNegative:
		// An unproved negative opinion is a machine limitation, never a
		// substitute for the proposal: the human action stands unchanged
		// and only the machine disposition records the disagreement.
		arbitration = ArbitrationDivergeHuman
		arbitrationNeeded = true
		limitations = append(limitations,
			"LLM judgment NOT_EXPLOITABLE is not confirmed by the deterministic layer; the machine disposition stays UNCHANGED and the proposed action is unaffected")
	}

	// A fact-gate reference blocking risk reduction demotes the candidate;
	// the agent's claims can never rest on unverifiable evidence.
	for _, rc := range validation.References {
		if rc.Effect == EffectBlocksRiskReduction {
			name := rc.EvidenceID
			if name == "" {
				name = rc.Subject
			}
			demote(fmt.Sprintf("evidence reference %s is %s and blocks risk reduction", name, rc.Status))
		}
	}
	limitations = append(limitations, validation.Limitations...)
	limitations = append(limitations, s0.Limitations...)

	// Undecided premises of a stronger rule block the weaker outcome; the
	// absence of the locus being undecidable can never ground LOWERED.
	for _, u := range undecided {
		demote(fmt.Sprintf("premise %s of rule %s is undecided", predicateLabel(u.predicate), u.id))
	}

	// Undecisive required facts of the selected profile and non-SATISFIED
	// blocking conditions forbid reduction (spec §8.3).
	for _, kind := range profDef.RequiredFacts {
		if !factDecisive(facts, kind) {
			demote(fmt.Sprintf("required fact %s is not decisively established", kind))
		}
	}
	for _, cond := range profDef.Conditions {
		if cond.Status != ConditionSatisfied && strings.HasPrefix(cond.Effect, "blocks_") {
			demote(fmt.Sprintf("profile condition %s is %s", cond.ID, cond.Status))
		}
	}
	// CONFLICTING facts bearing on the decision block reduction.
	for _, f := range facts {
		if f.Status == ObsConflicting {
			demote(fmt.Sprintf("fact %s (%s) is conflicting", f.ID, f.Kind))
		}
	}

	// Semantic instability after the stability retries are exhausted is a
	// limitation, never a provenance error and never a license to pick the
	// preferred attempt: DISMISSED/LOWERED lose their basis, the
	// divergence reasons become limitations and support drops. A drifted
	// report already failed closed above; only stable=false lands here.
	instabilityDemoted := false
	if c.Stability != nil && !c.Stability.Stable {
		limitations = append(limitations, c.Stability.Limitations...)
		if rec != RecommendationUnchanged {
			instabilityDemoted = true
		}
		demote("stability retries disagreed on the canonical decision fields; no attempt may be preferred")
	}

	// The recommendation never outruns the baseline disposition: nothing
	// the composer emits may raise risk above what the baseline recorded.
	// Without a baseline there is no recorded disposition to outrun, and
	// the absent-severity demotion above already withheld every reduction.
	if baseline != nil && strengthOf(baseline.Disposition) > strengthOf(rec) {
		rec = baseline.Disposition
	}

	// 7. Residual assumptions and reassessment triggers.
	assumptions := residualAssumptions(profDef, undecided, facts)
	if c.Stability != nil && !c.Stability.Stable {
		// The retry disagreement is itself a machine-checkable assumption:
		// a decision resting on an unstable basis cannot support a
		// reduction, so the UNKNOWN premise blocks it like any other.
		assumptions = append(assumptions, Condition{
			ID:        "assumption-agent-stability",
			Predicate: Predicate{Op: "exists", Path: "agent.stability"},
			Status:    ConditionUnknown,
			Scope:     "stability",
			Effect:    "blocks_lowered_and_dismissed",
		})
	}
	triggers := reassessmentTriggers(factSet)

	// 8. Conditional profiles: only alternatives that would change the
	// recommendation and whose applicability stayed UNKNOWN are listed.
	conditionals := conditionalProfiles(profiles, profile.ID, factSet, rec)

	// Support is derived from the decisive premise graph, never from the
	// machine candidate, the demotion record or the baseline: a human action
	// is supported by its recorded grounds, not by what the rules allowed.
	support, serr := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      validation,
		Observations:    evidence.Observations,
		Facts:           facts,
		Falsifiers:      evidence.Falsifiers,
		SelectedAttempt: evidence.SelectedAttempt,
		Stability:       c.Stability,
	})
	if serr != nil {
		return fail("support: %w", serr)
	}
	var reviewPlan *HumanReviewPlan
	publishedAction := assessment.ProposedAction
	if !c.historicalReplay {
		plan, rerr := buildHumanReviewPlan(HumanBranchInput{SupportInput: SupportInput{
			Stage0: s0, Assessment: assessment, Validation: validation,
			Observations: evidence.Observations, Facts: facts, Falsifiers: evidence.Falsifiers,
			SelectedAttempt: evidence.SelectedAttempt, Stability: c.Stability,
		}}, support)
		if rerr != nil { return fail("human review plan: %w", rerr) }
		reviewPlan = &plan
		if plan.Readiness == string(HumanBranchNotDecisionReady) {
			publishedAction = conservativeBranchAction(publishedAction)
		}
	}

	// stability_result stamps what the retry report established: drift
	// never reaches this point (it failed closed above), a stable series
	// records "stable", and an unstable one records whether instability
	// cost a permitted reduction. The verbatim field stays an override
	// for replay reproduction of recorded packages.
	stabilityResult := c.StabilityResult
	if c.Stability != nil {
		switch {
		case c.Stability.Stable:
			stabilityResult = "stable"
		case instabilityDemoted:
			stabilityResult = "unstable_demoted"
		default:
			stabilityResult = "unstable"
		}
	}

	techStatus := TechStatusReady
	if len(limitations) > 0 || len(demotions) > 0 || validation.Status != ValidationComplete {
		techStatus = TechStatusReadyWithLimits
	}
	if arbitrationNeeded {
		techStatus = TechStatusNeedsArbitration
	}

	runID := c.RunID
	if runID == "" {
		runID = composeRunID(findingID, s0.Raw.TicketHash)
	}
	mode := c.ExecutionMode
	if mode == "" {
		mode = "ci"
	}

	pkg := DecisionPackage{
		SchemaVersion: DecisionPackageSchemaVersion,
		RunID:         runID,
		FindingID:     findingID,
		ExecutionMode: mode,
		Scope:         support.Scope,
		Judgment: LLMJudgment{
			Verdict:   assessment.Verdict,
			Summary:   assessment.Summary,
			Mechanism: assessment.Mechanism,
		},
		ProposedAction:   publishedAction,
		Premises:         support.Premises,
		Counterarguments: assessment.Counterarguments,
		Unknowns:         assessment.Unknowns,
		Support:          support.Support,
		HumanReviewPlan: reviewPlan,
		TechnicalAssessment: TechnicalAssessment{
			Status:          techStatus,
			FactValidation:  string(validation.Status),
			Limitations:     dedupeStrings(limitations),
			BudgetResult:    c.BudgetResult,
			StabilityResult: stabilityResult,
		},
		MachineDisposition: MachineDisposition{
			Recommendation:       rec,
			Baseline:             baseline,
			RecommendedProfile:   profile,
			Rationale:            composeRationale(rec, candidate, fired, demotions, facts),
			ResidualAssumptions:  assumptions,
			ReassessmentTriggers: triggers,
			ConditionalProfiles:  conditionals,
			Demotions:            demotions,
			Arbitration:          arbitration,
		},
		Facts:           facts,
		FalsifierProofs: falsifierProofs,
		Audit: DecisionAudit{
			TicketHash:     s0.Raw.TicketHash,
			ConfigHash:     s0.ConfigHash,
			SelectedRef:    s0.SelectedRef.Name,
			ResolvedCommit: firstNonEmpty(s0.RefResolution.ResolvedCommit, s0.SelectedRef.Commit),
			SnapshotHash:   s0.Snapshot.ContentHash,
			AdvisorySource: string(s0.Advisory.Source),
			AdvisoryHash:   s0.Advisory.SHA256,
			Toolchain: ToolchainAudit{
				ReleaseVersion: s0.ReleaseToolchain.Version,
				ReleaseSource:  string(s0.ReleaseToolchain.Source),
				ReleaseLoc:     s0.ReleaseToolchain.Location,
				Claimed:        s0.ReleaseToolchain.Claimed,
				Conflict:       s0.ReleaseToolchain.Conflict,
				Mode:           string(s0.Toolchain.Mode),
				Version:        s0.Toolchain.Version,
				GoBin:          s0.Toolchain.GoBin,
				Mismatch:       s0.Toolchain.Mismatch,
			},
			RulesetHash:   c.RulesetHash,
			FalsifierHash: falsifierHash,
			PromptHash:    assessmentPromptHash(assessment),
			Limits:        c.Limits,
			Stage0: Stage0Provenance{
				InputHash:    s0.Input.SHA256,
				ProposalHash: proposalHash(s0.Proposal),
				SourceID:     s0.CatalogEntry.ID,
				Ref:          s0.SelectedRef.Name,
				Commit:       firstNonEmpty(s0.RefResolution.ResolvedCommit, s0.SelectedRef.Commit),
				SnapshotHash: s0.Snapshot.ContentHash,
				AdvisoryHash: s0.Advisory.SHA256,
			},
		},
	}
	if c.historicalReplay { pkg.SchemaVersion = "decision-package.v3" }
	pkg.MachineDisposition.Automation = EvaluateMachineAutomation(pkg.MachineDisposition, validation.Status)
	if err := pkg.validateSchema(pkg.SchemaVersion); err != nil {
		return pkg, fmt.Errorf("compose decision: assembled package violates the contract: %w", err)
	}
	return pkg, nil
}

// composeBaseline derives the authoritative baseline: severity comes from
// the frozen advisory first and the deterministically confirmed intake
// severity second — an unconfirmed proposal severity is never a baseline.
// The finding.v1 compatibility transport has neither an advisory
// resolution nor an intake proposal; there the scanner's declared severity
// is the only baseline source (spec §4.2 severity precedence), and an
// explicitly configured default is the last resort. Priority derives
// deterministically from severity/score via the existing risk ladder;
// disposition starts UNCHANGED — the finding exists and no rule has fired
// yet.
//
// Severity metadata is optional. When no source supplies a value the
// baseline is nil and the machine disposition withholds reductions; no
// severity, priority or disposition is invented to fill the schema. The
// configured-default flag reports a fallback that was applied so the caller
// records it as a limitation.
func composeBaseline(s0 Stage0Result, defaultSeverity string) (*Baseline, bool, error) {
	severity, source, score := "", "", 0.0
	if s0.Resolution != nil && s0.Resolution.Vulnerability != nil && s0.Resolution.Vulnerability.BaseSeverity != "" {
		v := s0.Resolution.Vulnerability
		severity = v.BaseSeverity
		source = firstNonEmpty(v.SeveritySource, string(s0.Resolution.Record.Source))
		score = v.BaseScore
	}
	if severity == "" {
		if fv, ok := s0.Validation.Field("severity"); ok && fv.Status == IntakeValid {
			severity = s0.Proposal.Severity
			source = "intake"
		}
	}
	if severity == "" && s0.Proposal.Severity == "" {
		// Compatibility transport: the finding.v1 record is the intake
		// document and scanner.severity is its declared baseline; there is
		// no proposal whose severity could stay unconfirmed.
		severity = strings.TrimSpace(s0.Input.Finding.Scanner.Severity)
		source = "scanner"
	}
	if severity == "" {
		// Operator-configured fallback: the ticket lane carries no severity
		// (tracker attributes are not intake text). The default names its
		// source and is recorded as a limitation — never as derived
		// evidence. An unset or unadmitted value leaves no baseline.
		if d := strings.ToUpper(strings.TrimSpace(defaultSeverity)); d != "" && baselineSeverities[d] {
			return &Baseline{
				Severity:    d,
				Priority:    string(risk.NominalPriority(d, 0)),
				Disposition: RecommendationUnchanged,
				Source:      "config:baseline.default_severity",
			}, true, nil
		}
		return nil, false, nil
	}
	priority := string(risk.NominalPriority(severity, score))
	if priority == "" {
		return nil, false, fmt.Errorf("severity %q yields no nominal priority", severity)
	}
	return &Baseline{
		Severity:    severity,
		Priority:    priority,
		Disposition: RecommendationUnchanged,
		Source:      source,
	}, false, nil
}

// collectFacts runs every provider in order and concatenates facts.
// A provider failure is recorded as an UNAVAILABLE fact plus a limitation —
// missing context is never a negative fact — and returned to the composer
// as a demotion signal.
func collectFacts(ctx context.Context, providers []FactProvider, in ProviderInput) ([]DecisionFact, []string) {
	var facts []DecisionFact
	var errs []string
	for _, p := range providers {
		if p == nil {
			continue
		}
		got, err := p.Collect(ctx, in)
		if err != nil {
			name := p.Name()
			errs = append(errs, fmt.Sprintf("fact provider %s failed: %v", name, err))
			facts = append(facts, newFact(name, FactProviderError, ObsUnavailable, name, "provider", nil))
			continue
		}
		facts = append(facts, got...)
	}
	return facts, errs
}

// factKey maps a decision-fact kind onto the canonical predicate path.
// Only kinds the composer understands receive a path.
func factKey(kind string) string {
	switch kind {
	case FactVulnerabilityID:
		return "vulnerability.id"
	case FactComponentIdentity:
		return "component.verified"
	case FactSource:
		return "source.id"
	case FactRef:
		return "ref.name"
	case FactCommit:
		return "ref.commit"
	case FactSnapshotIntegrity:
		return "snapshot.content_hash"
	case FactAdvisory:
		return "advisory.hash"
	case FactBaseline:
		return "baseline.severity"
	case FactPackageClaim:
		return "package.claim"
	case FactPackagePresence:
		return "package.present"
	case FactPackageAffected:
		return "package.affected"
	case FactModuleGraph:
		return "module_graph.complete"
	case FactTestOnlyDependency:
		return "test_only"
	case FactReleaseToolchain:
		return "release.toolchain"
	case FactAnalysisToolchain:
		return "toolchain.match"
	case FactDeploymentExposure:
		return "deployment.exposure"
	case FactFalsifierProposalPresent:
		return "falsifier.proposal_present"
	case FactFalsifierKernelPresent:
		return "falsifier.kernel_present"
	case FactFalsifierAdmitted:
		return "falsifier.admitted"
	case FactLLMVerdict:
		return "llm.verdict"
	}
	return ""
}

// decisionFactSet projects the collected facts onto the predicate fact
// set. Only decisive (SUPPORTS/REFUTES) facts resolve a key; UNAVAILABLE,
// LIMITATION and CONFLICTING facts leave the path missing, so predicates
// evaluate UNKNOWN — never UNSATISFIED.
func decisionFactSet(facts []DecisionFact) FactSet {
	out := FactSet{}
	for _, f := range facts {
		key := factKey(f.Kind)
		if key == "" {
			continue
		}
		switch f.Status {
		case ObsSupports:
			switch {
			case f.Kind == FactComponentNotPresent:
				out["package.present"] = false
			case key == "package.present" || key == "package.affected" || key == "module_graph.complete" || key == "toolchain.match" || key == "component.verified" || key == "falsifier.proposal_present" || key == "falsifier.kernel_present" || key == "falsifier.admitted" || key == "test_only":
				out[key] = true
			default:
				out[key] = f.Subject
			}
		case ObsRefutes:
			switch key {
			case "package.present", "package.affected", "module_graph.complete", "toolchain.match", "component.verified", "falsifier.proposal_present", "falsifier.kernel_present", "falsifier.admitted", "test_only":
				out[key] = false
			default:
				out[key] = "refuted:" + f.Subject
			}
		}
	}
	return out
}

// factDecisive reports whether a required fact kind was decisively
// established — SUPPORTS or REFUTES; UNAVAILABLE, LIMITATION and
// CONFLICTING never count.
func factDecisive(facts []DecisionFact, kind string) bool {
	for _, f := range facts {
		if f.Kind == kind && (f.Status == ObsSupports || f.Status == ObsRefutes) {
			return true
		}
	}
	return false
}

// selectProfile picks the first profile whose applicability is SATISFIED
// and returns the application record plus the definition with every
// condition evaluated. When no admitted profile applies, the conservative
// baseline fallback selects itself — the package always names the profile
// its decision was composed under.
func selectProfile(profiles []DecisionProfile, facts FactSet) (ProfileApplication, DecisionProfile) {
	for _, p := range profiles {
		status := EvaluatePredicate(p.Applicability, facts)
		if status != ConditionSatisfied {
			continue
		}
		for i := range p.Conditions {
			p.Conditions[i].Status = EvaluatePredicate(p.Conditions[i].Predicate, facts)
		}
		return ProfileApplication{
			ID:          p.ID,
			DisplayName: p.DisplayName,
			Applicability: Condition{
				ID:        "profile-applicability-" + p.ID,
				Predicate: p.Applicability,
				Status:    status,
				Scope:     "profile",
				Effect:    "select_profile",
			},
		}, p
	}
	// No admitted profile applies — the baseline profile does not depend
	// on any fact and therefore always selects conservatively.
	fallback := DecisionProfile{ID: "baseline", DisplayName: "Baseline (no profile admitted)"}
	return ProfileApplication{
		ID:          fallback.ID,
		DisplayName: fallback.DisplayName,
		Applicability: Condition{
			ID:        "profile-applicability-" + fallback.ID,
			Predicate: Predicate{Op: "exists", Path: "baseline.severity"},
			Status:    ConditionSatisfied,
			Scope:     "profile",
			Effect:    "select_profile",
		},
	}, fallback
}

// evaluateDecisionRules evaluates the admitted rules deterministically —
// ordered by recommendation strength then id — and returns the
// recommendation of the first rule whose applicability is SATISFIED. An
// empty ruleset yields UNCHANGED: without an admitted rule nothing may be
// reduced.
func evaluateDecisionRules(rules []DecisionRule, facts FactSet) (Recommendation, DecisionRule) {
	ordered := append([]DecisionRule(nil), rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ri, rj := strengthOf(ordered[i].Recommendation), strengthOf(ordered[j].Recommendation); ri != rj {
			return ri > rj
		}
		return ordered[i].ID < ordered[j].ID
	})
	for _, r := range ordered {
		if !r.Recommendation.Valid() {
			continue
		}
		if EvaluatePredicate(r.Applicability, facts) == ConditionSatisfied {
			return r.Recommendation, r
		}
	}
	return RecommendationUnchanged, DecisionRule{ID: "default", Recommendation: RecommendationUnchanged}
}

// undecidedRule is one rule premise that evaluated UNKNOWN; the composer
// records it as a residual assumption and blocks weaker reductions.
type undecidedRule struct {
	id             string
	recommendation Recommendation
	predicate      Predicate
}

// undecidedRuleConditions collects UNKNOWN premises of rules stronger than
// the current candidate — an undecidable falsifier forbids LOWERED, an
// undecidable lowering condition forbids nothing below it.
func undecidedRuleConditions(rules []DecisionRule, current Recommendation, facts FactSet) []undecidedRule {
	var out []undecidedRule
	for _, r := range rules {
		if !r.Recommendation.Valid() || r.Recommendation == RecommendationUnchanged {
			continue
		}
		if strengthOf(r.Recommendation) <= strengthOf(current) {
			continue
		}
		if EvaluatePredicate(r.Applicability, facts) == ConditionUnknown {
			out = append(out, undecidedRule{id: r.ID, recommendation: r.Recommendation, predicate: r.Applicability})
		}
	}
	return out
}

// strengthOf orders recommendations by how far they reduce the baseline:
// DISMISSED is the strongest reduction, UNCHANGED the weakest.
func strengthOf(r Recommendation) int {
	switch r {
	case RecommendationDismissed:
		return 3
	case RecommendationLowered:
		return 2
	default:
		return 1
	}
}

// residualAssumptions records the machine assumptions the decision still
// rests on: undecided stronger-rule premises, non-SATISFIED blocking
// profile conditions and every required-fact kind whose value could not be
// decisively established.
func residualAssumptions(profile DecisionProfile, undecided []undecidedRule, facts []DecisionFact) []Condition {
	var out []Condition
	seen := map[string]bool{}
	for _, u := range undecided {
		id := "assumption-rule-" + u.id
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Condition{
			ID:        id,
			Predicate: u.predicate,
			Status:    ConditionUnknown,
			Scope:     "rule",
			Effect:    "blocks_lowered_and_dismissed",
		})
	}
	for _, cond := range profile.Conditions {
		if cond.Status == ConditionSatisfied || !strings.HasPrefix(cond.Effect, "blocks_") {
			continue
		}
		if seen[cond.ID] {
			continue
		}
		seen[cond.ID] = true
		out = append(out, cond)
	}
	for _, kind := range profile.RequiredFacts {
		if factDecisive(facts, kind) {
			continue
		}
		key := factKey(kind)
		id := "assumption-fact-" + kind
		if key == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Condition{
			ID:        id,
			Predicate: Predicate{Op: "exists", Path: key},
			Status:    ConditionUnknown,
			Scope:     "fact",
			Effect:    "blocks_lowered_and_dismissed",
		})
	}
	return out
}

// reassessmentTriggers names the machine conditions under which the
// decision must be recomputed: any provenance input changing invalidates
// the package. Their state is UNKNOWN — the current package cannot know
// future values.
func reassessmentTriggers(facts FactSet) []Trigger {
	paths := []string{
		"snapshot.content_hash",
		"advisory.hash",
		"ref.commit",
		"deployment.exposure",
		"release.toolchain",
		"package.present",
	}
	out := make([]Trigger, 0, len(paths))
	for _, p := range paths {
		out = append(out, Trigger{
			ID:     "trigger-" + strings.ReplaceAll(p, ".", "-"),
			When:   Predicate{Op: "changed", Path: p},
			Effect: "recompute_decision",
			State:  ConditionUnknown,
		})
	}
	return out
}

// conditionalProfiles lists admitted profiles that were not selected,
// whose applicability stayed UNKNOWN and whose declared outcome would
// change the final recommendation — spec §8.4 forbids applying them and
// the same-disposition filter keeps the list meaningful.
func conditionalProfiles(profiles []DecisionProfile, selected string, facts FactSet, current Recommendation) []ConditionalProfile {
	var out []ConditionalProfile
	for _, p := range profiles {
		if p.ID == selected || !p.Expected.Valid() {
			continue
		}
		status := EvaluatePredicate(p.Applicability, facts)
		if status != ConditionUnknown {
			continue
		}
		cp := ConditionalProfile{
			Profile: p.ID,
			Applicability: Condition{
				ID:        "profile-applicability-" + p.ID,
				Predicate: p.Applicability,
				Status:    status,
				Scope:     "profile",
				Effect:    "conditional_applicability",
			},
			ExpectedDisposition: p.Expected,
		}
		out = AddConditionalProfile(out, cp, current)
	}
	return out
}

// composeRationale renders the deterministic basis of the recommendation —
// rule id, demotion reasons and the fact basis; the agent's prose is never
// copied here.
func composeRationale(rec Recommendation, candidate Recommendation, fired DecisionRule, demotions []string, facts []DecisionFact) Rationale {
	r := Rationale{Basis: []string{}}
	source := ""
	for _, f := range facts {
		if f.Kind == FactFalsifierAdmitted && f.Status == ObsSupports {
			for _, p := range f.Provenance {
				if strings.HasPrefix(p, "source:") {
					source = strings.TrimPrefix(p, "source:")
					break
				}
			}
		}
	}
	switch rec {
	case RecommendationDismissed:
		r.Summary = fmt.Sprintf("Rule %s permits dismissal: every required fact is established and the profile applies.", fired.ID)
		r.Basis = append(r.Basis, "rule "+fired.ID+" satisfied")
		if source != "" {
			r.Basis = append(r.Basis, "falsifier proof source: "+source)
		}
	case RecommendationLowered:
		r.Summary = fmt.Sprintf("Rule %s permits lowering under the selected profile.", fired.ID)
		r.Basis = append(r.Basis, "rule "+fired.ID+" satisfied")
	default:
		if candidate != RecommendationUnchanged && len(demotions) > 0 {
			r.Summary = fmt.Sprintf("Rule %s permitted %s but the basis is incomplete; the baseline disposition is retained.", fired.ID, candidate)
		} else {
			r.Summary = "The available facts do not establish a permitted risk reduction; the baseline disposition is retained."
		}
	}
	r.Basis = append(r.Basis, demotions...)
	return r
}

// integrityCheckID marks the checks whose INVALID/CONFLICTING status makes
// an honest package impossible — provenance violations are technical
// errors, never silent UNCHANGED results.
func integrityCheckID(id string) bool {
	switch id {
	case CheckIDIntakeIdentity, CheckIDSourceResolution, CheckIDRefResolution,
		CheckIDSnapshotIntegrity, CheckIDAdvisory:
		return true
	}
	return false
}

func firstReason(r CheckResult) string {
	if len(r.Reasons) > 0 {
		return r.Reasons[0]
	}
	return string(r.Status)
}

// predicateLabel renders a short deterministic label of one predicate for
// demotion reasons — operator plus the touched fact path, never values.
func predicateLabel(p Predicate) string {
	path := p.Path
	if path == "" {
		if l, ok := p.Left.(map[string]any); ok {
			if f, ok := l["fact"].(string); ok {
				path = f
			}
		}
	}
	if path == "" {
		return p.Op
	}
	return p.Op + "(" + path + ")"
}

// composeRunID derives a deterministic run id bound to the finding and the
// intake record hash; two compositions of the same record agree, and the
// artifact writer's run id stays independent.
func composeRunID(findingID, ticketHash string) string {
	token := shortHashToken(findingID + "\x00" + ticketHash)
	return fmt.Sprintf("compose-%s-%s", findingID, token)
}

func proposalHash(p IntakeProposal) string {
	if p.SchemaVersion == "" {
		return ""
	}
	if b, err := json.Marshal(p); err == nil {
		return hashBytes(b)
	}
	return ""
}

// assessmentPromptHash surfaces the prompt hash recorded by the agent run;
// the assessment audit block is the only channel carrying it into the
// package.
func assessmentPromptHash(a Assessment) string {
	if a.Audit != nil {
		return a.Audit.PromptHash
	}
	return ""
}

func dedupeStrings(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// DefaultProfiles returns the conservative profile set of the generic
// triage line. public-hostile applies only to proven public exposure;
// internal-service applies to a proven cluster-internal perimeter and
// requires package identity plus the deployment fact to be decisive. No
// admitted profile satisfied leaves the implicit baseline fallback — a
// profile is always named.
func DefaultProfiles() []DecisionProfile {
	return []DecisionProfile{
		{
			ID:          "public-hostile",
			DisplayName: "Public hostile peer",
			Applicability: Predicate{
				Op:    "eq",
				Left:  map[string]any{"fact": "deployment.exposure"},
				Right: "public",
			},
			RequiredFacts: []string{FactPackageClaim},
		},
		{
			ID:          "internal-service",
			DisplayName: "Cluster-internal service",
			Applicability: Predicate{
				Op:    "eq",
				Left:  map[string]any{"fact": "deployment.exposure"},
				Right: "cluster-internal",
			},
			RequiredFacts: []string{FactPackageClaim, FactDeploymentExposure},
			Expected:      RecommendationLowered,
		},
	}
}

// DefaultRules returns the deterministic risk rules of the generic triage
// line. The dismissal rule is the module/locus falsifier: the vulnerable
// module proven absent from the closed build graph cannot be exploited.
// The lowering rule requires the package proven present and affected plus
// a proven cluster-internal or loopback perimeter — exposure alone never
// dismisses, and an undecidable presence never lowers.
func DefaultRules() []DecisionRule {
	return []DecisionRule{
		{
			ID:             "module-absent-falsifier",
			Recommendation: RecommendationDismissed,
			Applicability: Predicate{
				Op:    "eq",
				Left:  map[string]any{"fact": "package.present"},
				Right: false,
			},
			Reason: "the vulnerable module is absent from the closed build graph — the defect locus cannot execute",
		},
		{
			ID:             "verified-mandatory-code-falsifier",
			Recommendation: RecommendationDismissed,
			Applicability: Predicate{
				Op:    "eq",
				Left:  map[string]any{"fact": "falsifier.admitted"},
				Right: true,
			},
			Reason: "a deterministic verifier established a checker-verified falsifier for a mandatory exploit condition with complete scoped coverage and no unresolved dynamic or provenance gap; provenance identifies whether the source was an agent proposal or checker kernel",
		},
		{
			ID:             "version-outside-affected-range",
			Recommendation: RecommendationDismissed,
			Applicability: Predicate{
				Op: "all",
				Args: []Predicate{
					{Op: "eq", Left: map[string]any{"fact": "package.present"}, Right: true},
					{Op: "eq", Left: map[string]any{"fact": "package.affected"}, Right: false},
					// Only a full, hash-pinned advisory record may ground an
					// applicability claim: a partial ticket projection leaves
					// this path missing, so the rule stays undecided there.
					{Op: "exists", Path: "advisory.hash"},
				},
			},
			Reason: "the resolved module version lies outside every affected range the full advisory declares — the defect does not apply to this build",
		},
		{
			ID:             "test-only-dependency",
			Recommendation: RecommendationDismissed,
			Applicability: Predicate{
				Op: "all",
				Args: []Predicate{
					{Op: "eq", Left: map[string]any{"fact": "package.present"}, Right: true},
					{Op: "eq", Left: map[string]any{"fact": "module_graph.complete"}, Right: true},
					{Op: "eq", Left: map[string]any{"fact": "test_only"}, Right: true},
					{Op: "exists", Path: "advisory.hash"},
				},
			},
			Reason: "the vulnerable module is reachable only from the test closure — the product binary cannot execute it",
		},
		{
			ID:             "cluster-perimeter-lowering",
			Recommendation: RecommendationLowered,
			Applicability: Predicate{
				Op: "all",
				Args: []Predicate{
					{Op: "eq", Left: map[string]any{"fact": "package.present"}, Right: true},
					{Op: "eq", Left: map[string]any{"fact": "package.affected"}, Right: true},
					{Op: "in", Left: map[string]any{"fact": "deployment.exposure"}, Right: []any{"cluster-internal", "internal", "loopback"}},
				},
			},
			Reason: "the affected module is present but the deployment perimeter confines inbound reachability to the cluster",
		},
	}
}
