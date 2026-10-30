package triage

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderDecisionMarkdown renders decision.md — the human action card of a
// decision-package.v3. The card is ordered for a person, not for a CI job:
// the proposed action and its instruction come first, then the causal
// rationale and the model's judgment, the decisive measured/proved facts,
// the explicitly labelled interpretations, the assumptions, unknowns and
// computed support, what would change the recommendation, the Accept/Reject
// instructions, and only then the separately labelled deterministic machine
// disposition. The full audit detail — every provider fact, machine
// predicate, proof, policy evaluation and provenance pin — stays inside a
// collapsed section so the main body never requires reading it.
//
// The card is a pure function of the package: it never invents or repairs
// values and never mixes the axes — a machine dismissal is never presented
// as a human action, and a human proposal is never presented as a machine
// result or a machine-safe verdict.
func RenderDecisionMarkdown(pkg DecisionPackage) []byte {
	if plan := pkg.HumanReviewPlan; plan != nil && (len(plan.Variables) > 0 || plan.Readiness == string(HumanBranchNotDecisionReady)) {
		return renderHumanBranchMarkdown(pkg)
	}
	return renderPhase1DecisionMarkdown(pkg)
}

// renderPhase1DecisionMarkdown is frozen for version-specific v3 playback.
func renderPhase1DecisionMarkdown(pkg DecisionPackage) []byte {
	var b strings.Builder
	m := pkg.MachineDisposition
	action := pkg.ProposedAction
	fmt.Fprintf(&b, "# Triage action package: %s\n\n", orDash(pkg.FindingID))
	fmt.Fprintf(&b, "- Execution mode: %s\n", orDash(pkg.ExecutionMode))
	fmt.Fprintf(&b, "- Run: %s\n", orDash(pkg.RunID))
	fmt.Fprintf(&b, "- Support level: %s\n", orDash(string(pkg.Support.Level)))

	b.WriteString("\n## Proposed action (human)\n\n")
	fmt.Fprintf(&b, "**Proposed action:** %s\n\n", orDash(string(action.Kind)))
	fmt.Fprintf(&b, "**Instruction:** %s\n\n", orDash(action.Instruction))
	fmt.Fprintf(&b, "- Applies to: %s\n", orDash(action.Scope))
	if len(action.RecordIDs) > 0 {
		fmt.Fprintf(&b, "- Records considered: %s\n", strings.Join(action.RecordIDs, ", "))
	}

	b.WriteString("\n## Why this action\n\n")
	if action.Rationale != "" {
		fmt.Fprintf(&b, "%s\n\n", action.Rationale)
	} else {
		b.WriteString("No causal rationale was recorded for this action.\n\n")
	}
	if len(action.DecisiveClaimIDs) > 0 {
		fmt.Fprintf(&b, "- Decisive premises: %s\n", strings.Join(action.DecisiveClaimIDs, ", "))
	}

	b.WriteString("\n### Model judgment (investigation opinion, not a machine verdict)\n\n")
	fmt.Fprintf(&b, "- Verdict: %s\n", orDash(string(pkg.Judgment.Verdict)))
	if pkg.Judgment.Summary != "" {
		fmt.Fprintf(&b, "- Summary: %s\n", pkg.Judgment.Summary)
	}
	if pkg.Judgment.Mechanism != "" {
		fmt.Fprintf(&b, "- Mechanism: %s\n", pkg.Judgment.Mechanism)
	}

	// The recorded scope is what the conclusion actually covers. It is
	// rendered from the package scope, never from the model's record_ids:
	// a model-named record that the run never captured cannot widen it.
	b.WriteString("\n## Decision scope\n\n")
	switch pkg.Scope.Boundary {
	case DecisionBoundaryExactRecords:
		fmt.Fprintf(&b, "- Scope boundary: %s — the conclusion is bound to the captured record(s) below and makes no CVE-wide statement.\n", pkg.Scope.Boundary)
	default:
		fmt.Fprintf(&b, "- Scope boundary: %s — no advisory record with a recorded digest was captured; the conclusion rests on the input material only and makes no record-scoped or CVE-wide claim.\n", orDash(pkg.Scope.Boundary))
	}
	if pkg.Scope.SnapshotHash != "" {
		fmt.Fprintf(&b, "- Pinned snapshot: %s\n", pkg.Scope.SnapshotHash)
	} else {
		b.WriteString("- Pinned snapshot: none recorded; the source snapshot is not pinned.\n")
	}
	if len(pkg.Scope.RequestedIDs) > 0 {
		fmt.Fprintf(&b, "- Requested ids: %s\n", strings.Join(pkg.Scope.RequestedIDs, ", "))
	}
	if len(pkg.Scope.Records) == 0 {
		b.WriteString("- Captured records: none with a recorded digest.\n")
	} else {
		b.WriteString("- Captured records:\n")
		for _, rec := range pkg.Scope.Records {
			fmt.Fprintf(&b, "  - `%s` (sha256 `%s`)\n", orDash(rec.ID), orDash(rec.SHA256))
		}
	}
	if len(pkg.Scope.OpenBoundaries) == 0 {
		b.WriteString("- Open boundaries: none recorded.\n")
	} else {
		b.WriteString("- Open boundaries:\n")
		for _, boundary := range pkg.Scope.OpenBoundaries {
			fmt.Fprintf(&b, "  - %s\n", boundary)
		}
	}

	b.WriteString("\n## Decisive measured and proved facts\n\n")
	measured := 0
	for _, pr := range pkg.Premises {
		if pr.Basis == PremiseMeasured || pr.Basis == PremiseProved {
			measured++
			writePremiseMarkdown(&b, pr)
		}
	}
	if measured == 0 {
		b.WriteString("None recorded: no decisive premise was established as measured or proved.\n")
	}

	b.WriteString("\n## Interpretations (model reasoning, not measured facts)\n\n")
	interpreted := 0
	for _, pr := range pkg.Premises {
		if pr.Basis == PremiseInterpreted {
			interpreted++
			writePremiseMarkdown(&b, pr)
		}
	}
	if interpreted == 0 {
		b.WriteString("None recorded.\n")
	}

	b.WriteString("\n## Assumptions, unknowns and support\n\n")
	fmt.Fprintf(&b, "- **Support level:** %s\n", orDash(string(pkg.Support.Level)))
	if len(pkg.Support.ProofIDs) > 0 {
		fmt.Fprintf(&b, "- Admitted proofs grounding the action: %s\n", strings.Join(pkg.Support.ProofIDs, ", "))
	}
	for _, r := range pkg.Support.Reasons {
		fmt.Fprintf(&b, "- %s\n", r)
	}

	b.WriteString("\n### Assumptions and unresolved premises\n\n")
	open := 0
	for _, pr := range pkg.Premises {
		switch pr.Basis {
		case PremiseAssumed, PremiseUnresolved, PremiseConflicting:
			open++
			writePremiseMarkdown(&b, pr)
		}
	}
	if open == 0 {
		b.WriteString("None recorded.\n")
	}

	b.WriteString("\n### Recorded unknowns\n\n")
	if len(pkg.Unknowns) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, u := range pkg.Unknowns {
		if u.ID != "" {
			fmt.Fprintf(&b, "- `%s` — %s\n", u.ID, orDash(u.Description))
		} else {
			fmt.Fprintf(&b, "- %s\n", orDash(u.Description))
		}
		if u.Reason != "" {
			fmt.Fprintf(&b, "  - reason: %s\n", u.Reason)
		}
	}

	b.WriteString("\n### Counterarguments considered\n\n")
	if len(pkg.Counterarguments) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, ca := range pkg.Counterarguments {
		fmt.Fprintf(&b, "- `%s` — %s\n", orDash(ca.ID), orDash(ca.Statement))
		if ca.Response != "" {
			fmt.Fprintf(&b, "  - response: %s\n", ca.Response)
		} else {
			b.WriteString("  - response: none recorded; the objection stays open.\n")
		}
	}

	b.WriteString("\n## What changes this recommendation\n\n")
	if len(action.ReconsiderWhen) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, r := range action.ReconsiderWhen {
		fmt.Fprintf(&b, "- %s\n", r)
	}

	b.WriteString("## Accept or reject this proposal (human decision)\n\n")
	b.WriteString("The decision applies to the exact proposal above and binds to this package's canonical hash. It is recorded as its own immutable entry and never rewrites this card, the recorded judgment or the machine disposition. Recording needs no model credentials and no network access.\n\n")
	comment := ""
	if pkg.SchemaVersion != DecisionPackageSchemaVersion { comment = " --reason <text>" }
	fmt.Fprintf(&b, "- Accept:\n\n    izyan triage --record-decision <run-directory> --decision accept --actor <identity>%s\n\n", comment)
	fmt.Fprintf(&b, "- Reject:\n\n    izyan triage --record-decision <run-directory> --decision reject --actor <identity>%s\n\n", comment)
	if pkg.SchemaVersion == DecisionPackageSchemaVersion { b.WriteString("An optional --reason comment may be supplied; no technical narrative is required.\n\n") }
	b.WriteString("Accepting records a person's decision and nothing more: it never becomes a machine verdict, an admitted proof, an automatic reduction, a Product A authority decision or a negative VEX statement.\n")

	b.WriteString("\n## Machine disposition (deterministic)\n\n")
	fmt.Fprintf(&b, "**Machine recommendation:** %s\n\n", orDash(string(m.Recommendation)))
	fmt.Fprintf(&b, "- Automation: %s\n", orDash(string(m.Automation)))
	fmt.Fprintf(&b, "- Arbitration: %s\n", orDash(m.Arbitration))
	if m.Arbitration == ArbitrationDivergeHuman {
		b.WriteString("- The model judgment and the machine rules diverge; the machine layer withholds the reduction and the proposed action above stands unchanged.\n")
	}
	if m.Baseline == nil {
		b.WriteString("- Baseline: none recorded (no severity metadata was available; no severity or priority is synthesized).\n")
	} else {
		fmt.Fprintf(&b, "- Baseline severity: %s\n", orDash(m.Baseline.Severity))
		fmt.Fprintf(&b, "- Baseline priority: %s\n", orDash(m.Baseline.Priority))
		fmt.Fprintf(&b, "- Baseline disposition: %s\n", orDash(string(m.Baseline.Disposition)))
		fmt.Fprintf(&b, "- Baseline source: %s\n", orDash(m.Baseline.Source))
	}
	fmt.Fprintf(&b, "- Profile id: %s\n", orDash(m.RecommendedProfile.ID))
	if m.RecommendedProfile.DisplayName != "" {
		fmt.Fprintf(&b, "- Profile name: %s\n", m.RecommendedProfile.DisplayName)
	}
	if len(m.Demotions) > 0 {
		b.WriteString("- Machine demotion record:\n")
		for _, d := range m.Demotions {
			fmt.Fprintf(&b, "  - %s\n", d)
		}
	}

	b.WriteString("\n### Machine rationale\n\n")
	if m.Rationale.Summary != "" {
		fmt.Fprintf(&b, "%s\n", m.Rationale.Summary)
	}
	for _, r := range m.Rationale.Reasoning {
		fmt.Fprintf(&b, "- %s\n", r)
	}
	for _, basis := range m.Rationale.Basis {
		fmt.Fprintf(&b, "- basis: %s\n", basis)
	}
	if m.Rationale.Summary == "" && len(m.Rationale.Reasoning) == 0 && len(m.Rationale.Basis) == 0 {
		b.WriteString("None recorded.\n")
	}

	b.WriteString("\n## Audit detail\n\n")
	b.WriteString("<details>\n<summary>Expand for the full recorded detail: verified facts, proofs, machine predicates, technical assessment, CI policy and provenance</summary>\n\n")

	b.WriteString("### Verified facts\n\n")
	if len(pkg.Facts) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, f := range pkg.Facts {
		fmt.Fprintf(&b, "- `%s` — %s %s — `%s` (scope: %s)\n",
			orDash(f.ID), orDash(f.Kind), orDash(f.Status), orDash(f.Subject), orDash(f.Scope))
		if len(f.Provenance) > 0 {
			fmt.Fprintf(&b, "  - provenance: %s\n", strings.Join(f.Provenance, ", "))
		}
		for _, ref := range f.EvidenceRefs {
			fmt.Fprintf(&b, "  - evidence: %s\n", ref)
		}
	}

	if len(pkg.FalsifierProofs) > 0 {
		b.WriteString("\n### Falsifier proofs (deterministic checkers)\n\n")
		fmt.Fprintf(&b, "Report hash: %s\n\n", orDash(pkg.Audit.FalsifierHash))
		for _, pr := range pkg.FalsifierProofs {
			fmt.Fprintf(&b, "- **%s** — %s\n", orDash(pr.ID), orDash(string(pr.Status)))
			fmt.Fprintf(&b, "  - Kind: %s\n", orDash(string(pr.Kind)))
			fmt.Fprintf(&b, "  - Basis: %s (mandatory: %t)\n", orDash(string(pr.Basis)), pr.Mandatory)
			fmt.Fprintf(&b, "  - Condition: %s\n", orDash(pr.ConditionID))
			if pr.RuleID != "" {
				fmt.Fprintf(&b, "  - Rule: %s@%s\n", orDash(pr.RuleID), orDash(pr.RuleVersion))
			}
			fmt.Fprintf(&b, "  - Coverage: %s\n", orDash(pr.Coverage.Completeness))
			if pr.Reason != "" {
				fmt.Fprintf(&b, "  - Reason: %s\n", pr.Reason)
			}
			if len(pr.EvidenceRefs) > 0 {
				fmt.Fprintf(&b, "  - Evidence: %s\n", strings.Join(pr.EvidenceRefs, ", "))
			}
			for _, tr := range pr.History {
				fmt.Fprintf(&b, "  - Transition: %s -> %s (%s)\n", orDash(string(tr.From)), orDash(string(tr.To)), orDash(tr.Reason))
			}
		}
	}

	b.WriteString("\n### Machine residual assumptions\n\n")
	if len(m.ResidualAssumptions) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, c := range m.ResidualAssumptions {
		fmt.Fprintf(&b, "- `%s` — status %s — `%s` — scope %s — effect %s\n",
			orDash(c.ID), orDash(string(c.Status)), predicateJSON(c.Predicate), orDash(c.Scope), orDash(c.Effect))
		for _, p := range c.Provenance {
			fmt.Fprintf(&b, "  - provenance: %s\n", p)
		}
	}

	b.WriteString("\n### Machine reassessment triggers\n\n")
	if len(m.ReassessmentTriggers) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, tr := range m.ReassessmentTriggers {
		fmt.Fprintf(&b, "- `%s` — state %s — when `%s` — effect %s\n",
			orDash(tr.ID), orDash(string(tr.State)), predicateJSON(tr.When), orDash(tr.Effect))
	}

	b.WriteString("\n### Conditional profiles (recorded, not applied)\n\n")
	if len(m.ConditionalProfiles) == 0 {
		b.WriteString("None recorded.\n")
	}
	for _, cp := range m.ConditionalProfiles {
		fmt.Fprintf(&b, "- `%s` — applicability %s — `%s` — expected disposition %s\n",
			orDash(cp.Profile), orDash(string(cp.Applicability.Status)),
			predicateJSON(cp.Applicability.Predicate), orDash(string(cp.ExpectedDisposition)))
	}

	b.WriteString("\n### Technical assessment\n\n")
	fmt.Fprintf(&b, "- Status: %s\n", orDash(pkg.TechnicalAssessment.Status))
	fmt.Fprintf(&b, "- Fact validation: %s\n", orDash(pkg.TechnicalAssessment.FactValidation))
	if pkg.TechnicalAssessment.BudgetResult != "" {
		fmt.Fprintf(&b, "- Budget result: %s\n", pkg.TechnicalAssessment.BudgetResult)
	}
	if pkg.TechnicalAssessment.StabilityResult != "" {
		fmt.Fprintf(&b, "- Stability result: %s\n", pkg.TechnicalAssessment.StabilityResult)
	}
	if len(pkg.TechnicalAssessment.Limitations) > 0 {
		b.WriteString("- Limitations:\n")
		for _, lim := range pkg.TechnicalAssessment.Limitations {
			fmt.Fprintf(&b, "  - %s\n", lim)
		}
	}

	b.WriteString("\n### CI policy evaluation\n\n")
	for _, f := range []FailOn{FailOnUnchanged, FailOnLowSupport, FailOnConditional, FailOnUnverifiedDisposition} {
		state := "clear"
		if PackagePolicyHit(pkg, f) {
			state = "trips"
		}
		fmt.Fprintf(&b, "- --fail-on %s → %s\n", f, state)
	}

	b.WriteString("\n### Provenance (audit)\n\n")
	fmt.Fprintf(&b, "- ticket_hash: %s\n", orDash(pkg.Audit.TicketHash))
	fmt.Fprintf(&b, "- config_hash: %s\n", orDash(pkg.Audit.ConfigHash))
	fmt.Fprintf(&b, "- selected_ref: %s\n", orDash(pkg.Audit.SelectedRef))
	fmt.Fprintf(&b, "- resolved_commit: %s\n", orDash(pkg.Audit.ResolvedCommit))
	fmt.Fprintf(&b, "- snapshot_hash: %s\n", orDash(pkg.Audit.SnapshotHash))
	fmt.Fprintf(&b, "- advisory_source: %s\n", orDash(pkg.Audit.AdvisorySource))
	fmt.Fprintf(&b, "- advisory_hash: %s\n", orDash(pkg.Audit.AdvisoryHash))
	fmt.Fprintf(&b, "- ruleset_hash: %s\n", orDash(pkg.Audit.RulesetHash))
	fmt.Fprintf(&b, "- prompt_hash: %s\n", orDash(pkg.Audit.PromptHash))
	if tc := pkg.Audit.Toolchain; tc != (ToolchainAudit{}) {
		fmt.Fprintf(&b, "- toolchain: version=%s mode=%s release_version=%s release_source=%s\n",
			orDash(tc.Version), orDash(tc.Mode), orDash(tc.ReleaseVersion), orDash(tc.ReleaseSource))
	}
	if l := pkg.Audit.Limits; l != (BudgetConfig{}) {
		fmt.Fprintf(&b, "- limits: max_llm_steps=%d max_tool_calls=%d max_source_bytes=%d timeout_seconds=%d max_output_tokens=%d\n",
			l.MaxLLMSteps, l.MaxToolCalls, l.MaxSourceBytes, l.TimeoutSeconds, l.MaxOutputTokens)
	}
	if s := pkg.Audit.Stage0; s != (Stage0Provenance{}) {
		fmt.Fprintf(&b, "- stage0: input_hash=%s proposal_hash=%s source=%s ref=%s commit=%s snapshot_hash=%s advisory_hash=%s\n",
			orDash(s.InputHash), orDash(s.ProposalHash), orDash(s.SourceID), orDash(s.Ref),
			orDash(s.Commit), orDash(s.SnapshotHash), orDash(s.AdvisoryHash))
	}

	b.WriteString("\n</details>\n")
	return []byte(b.String())
}

func renderHumanBranchMarkdown(pkg DecisionPackage) []byte {
	var b strings.Builder
	p := pkg.HumanReviewPlan
	fmt.Fprintf(&b, "# Triage prepared decisions: %s\n\n**Human review readiness:** %s\n\n", pkg.FindingID, p.Readiness)
	if p.Readiness == string(HumanBranchNotDecisionReady) {
		b.WriteString("**Proposed action: KEEP_OPEN.** This package does not supply a complete decision within the human-work bounds. Do not perform additional investigation to repair it.\n\n")
	} else {
		b.WriteString("Answer the declared environment questions, select the matching prepared branch, then Accept or Reject. No source reading, tool run or new investigation is required. These are human-owned deployment premises, never code facts or machine-safe verdicts.\n\n")
	}
	b.WriteString("## Environment questions (verbatim)\n\n")
	for _, v := range p.Variables {
		if v.Required { fmt.Fprintf(&b, "- **%s:** %s Allowed answers: %s.\n", v.ID, v.Question, strings.Join(v.AllowedValues, ", ")) } else { fmt.Fprintf(&b, "- Recorded dimension %s: %s (not a human question).\n", v.ID, strings.Join(v.AllowedValues, ", ")) }
	}
	b.WriteString("\nRecord answers offline (at most two distinct --answer variables); valid recorded answers are retained and are not asked again:\n\n    izyan triage --record-decision <run-directory> --actor <identity>")
	for _, v := range p.Variables { if v.Required { fmt.Fprintf(&b, " --answer %s=<allowed-value>", v.ID) } }
	b.WriteString("\n\nThe CLI selects the prepared branch automatically and prints copy-safe Accept/Reject commands containing --projection-hash <presented-hash>. Use that hash for a later --decision accept or --decision reject: a changed answer selection is rejected instead of silently accepting an unseen proposal. Alternatively, name every answer explicitly together with --decision in one invocation (without --projection-hash). --reason is an optional comment. No model credentials or additional technical provenance are needed.\n")
	b.WriteString("\n## Mandatory first-screen premises\n\n")
	if len(p.MandatoryPremiseIDs) > MaxMandatoryPremises {
		fmt.Fprintf(&b, "The decisive closure requires %d premises, exceeding the bound of seven. No decisive facts were trimmed; see full recorded detail below.\n", len(p.MandatoryPremiseIDs))
	} else {
		premises := map[string]DecisionPremise{}
		for _, branch := range p.Branches { for _, pr := range branch.Premises { premises[pr.ClaimID] = pr } }
		for _, id := range p.MandatoryPremiseIDs {
			if pr, ok := premises[id]; ok { fmt.Fprintf(&b, "- `%s` [%s]: %s\n", id, pr.Basis, pr.Statement) } else { fmt.Fprintf(&b, "- `%s`: branch-local human-owned environment condition; unknown keeps the finding open.\n", id) }
		}
	}
	b.WriteString("\n## Prepared conditional decisions\n\n")
	for _, branch := range p.Branches {
		fmt.Fprintf(&b, "### %s — %s\n\n- Assignments: `%s`\n- Judgment (opinion): %s — %s\n- Proposed action (human): **%s**\n- Instruction: %s\n- Rationale: %s\n- Support: %s (not machine authority)\n", branch.ID, branch.Status, assignmentKey(branch.Assignments), branch.Judgment.Verdict, branch.Judgment.Summary, branch.Action.Kind, branch.Action.Instruction, branch.Action.Rationale, branch.Support.Level)
		for _, l := range branch.Limitations { fmt.Fprintf(&b, "- Limitation: %s\n", l) }
		fmt.Fprintf(&b, "- Reconsider when: %s\n\n", strings.Join(branch.Action.ReconsiderWhen, "; "))
	}
	b.WriteString("## Human decision\n\nAccept or Reject the matching prepared branch. ACCEPT_ENVIRONMENTAL_MITIGATION is contextual only: it never means CLOSE_NOT_AFFECTED or CLOSE_NO_EXPLOIT_PATH and never changes Product A, necessity, completeness, corpus closure or VEX.\n\n<details>\n<summary>Full recorded premises and machine diagnostics (not additional mandatory human work)</summary>\n\n")
	b.Write(renderPhase1DecisionMarkdown(pkg))
	for _, branch := range p.Branches {
		fmt.Fprintf(&b, "\n### %s premise closure\n\n", branch.ID)
		for _, pr := range branch.Premises { writePremiseMarkdown(&b, pr) }
	}
	b.WriteString("\n</details>\n")
	return []byte(b.String())
}

// writePremiseMarkdown renders one decisive premise with its computed
// basis, the proposition the record itself establishes, and the source
// metadata that travels with it. The model statement is echoed verbatim.
func writePremiseMarkdown(b *strings.Builder, pr DecisionPremise) {
	fmt.Fprintf(b, "- **`%s`** (%s) — %s\n", orDash(pr.ClaimID), orDash(string(pr.Basis)), orDash(pr.Statement))
	if pr.EstablishedProposition != "" {
		fmt.Fprintf(b, "  - established by the record: %s\n", pr.EstablishedProposition)
	}
	fmt.Fprintf(b, "  - subject: %s; scope: %s\n", orDash(pr.Subject), orDash(pr.Scope))
	if pr.Completeness != "" {
		fmt.Fprintf(b, "  - completeness: %s\n", pr.Completeness)
	}
	if pr.Owner != "" {
		fmt.Fprintf(b, "  - owner: %s\n", pr.Owner)
	}
	if len(pr.SourceRefs) > 0 {
		fmt.Fprintf(b, "  - sources: %s\n", strings.Join(pr.SourceRefs, ", "))
	}
	if len(pr.SourceDigests) > 0 {
		fmt.Fprintf(b, "  - source digests: %s\n", strings.Join(pr.SourceDigests, ", "))
	}
	if len(pr.OpenBoundaries) > 0 {
		fmt.Fprintf(b, "  - open boundaries: %s\n", strings.Join(pr.OpenBoundaries, ", "))
	}
	for _, r := range pr.Reasons {
		fmt.Fprintf(b, "  - %s\n", r)
	}
}

// predicateJSON renders a machine predicate as canonical compact JSON —
// the same encoding decision.json stores, so the card stays machine-diffable.
func predicateJSON(p Predicate) string {
	data, err := json.Marshal(p)
	if err != nil {
		return p.Op
	}
	return string(data)
}
