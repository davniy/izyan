package triage

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/llm"
)

// StabilitySchemaVersion is the schema of stability.json, the per-finding
// record of the stabilization retries a run executed. v2 projects the four
// result axes separately — the model judgment, the proposed human action,
// the derived support and the deterministic machine disposition — so a
// retry series can never report human agreement while the machine result
// drifted (or vice versa). stability-runs.v1 is history: it carries no
// human decision axis and is rejected by the live replay path.
const StabilitySchemaVersion = "stability-runs.v2"

// StabilityAttempt is the canonical projection of one agent run used by the
// stability comparison (spec §2.4). The semantic surface is split into the
// human axis — judgment, proposed action kind/scope, the decisive premise
// closure and the derived support, with the recorded text pinned by
// judgment/action hashes — and the machine axis — recommendation, profile,
// readiness, policy outcome and the machine-condition/proof hashes. The
// provenance pins the retry is bound to (input, snapshot, advisory freeze,
// config, ruleset, prompt, toolchain, selected ref and resolved commit) sit
// apart from both. A retry may only differ in the semantic halves; any
// provenance change is drift, not instability.
//
// The premise/support surface is recorded twice. PremisesSemanticHash and
// SupportSemanticHash are the attempt-independent projections the comparison
// uses: propositions, computed bases and scope metadata, never the
// attempt-local observation ids a retry intentionally renames
// (det-0001 -> det-a2-0001). PremisesHash and SupportHash pin the exact
// recorded values for audit and are never compared — coverage/identity
// metadata stays inspectable without deciding stability.
type StabilityAttempt struct {
	Attempt int `json:"attempt"`
	// Human axis: what the investigation concluded and what a person is
	// asked to do, plus the computed grounds of that action.
	Judgment             string `json:"judgment"`
	JudgmentHash         string `json:"judgment_hash"`
	ActionKind           string `json:"action_kind"`
	ActionScope          string `json:"action_scope"`
	ActionHash           string `json:"action_hash"`
	PremisesSemanticHash string `json:"premises_semantic_hash"`
	PremisesHash         string `json:"premises_hash"`
	SupportLevel         string `json:"support_level"`
	SupportSemanticHash  string `json:"support_semantic_hash"`
	SupportHash          string `json:"support_hash"`
	// Machine axis: the deterministic reduction and its evidence surface.
	Recommendation   Recommendation        `json:"recommendation"`
	MachineHash      string                `json:"machine_disposition_hash"`
	ProfileID        string                `json:"profile_id"`
	DecisiveFacts    []string              `json:"decisive_facts,omitempty"`
	Readiness        string                `json:"readiness,omitempty"`
	PolicyOutcome    string                `json:"policy_outcome,omitempty"`
	FalsifierHash    string                `json:"falsifier_hash,omitempty"`
	FalsifierHistory []FalsifierTransition `json:"falsifier_history,omitempty"`
	// Provenance pins.
	SelectedRef     string `json:"selected_ref,omitempty"`
	ResolvedCommit  string `json:"resolved_commit,omitempty"`
	AssumptionsHash string `json:"assumptions_hash"`
	TriggersHash    string `json:"triggers_hash"`
	InputHash       string `json:"input_hash"`
	SnapshotHash    string `json:"snapshot_hash"`
	AdvisoryHash    string `json:"advisory_hash"`
	ConfigHash      string `json:"config_hash"`
	RuleSetHash     string `json:"ruleset_hash"`
	PromptHash      string `json:"prompt_hash"`
	ToolchainHash   string `json:"toolchain_hash"`
}

// StabilityReport is the deterministic verdict over a full attempt series:
// Retries counts the additional runs after the first, Attempts preserves
// every projection verbatim (a preferred response is never selected),
// Drift marks a provenance change — always a technical error — and Stable
// marks semantic agreement on both the human and the machine axis.
// Limitations carry the recorded divergences; they feed
// technical_assessment.limitations verbatim so a replay recomposes the
// identical package.
type StabilityReport struct {
	Retries  int                `json:"retries"`
	Attempts []StabilityAttempt `json:"attempts"`
	// SelectedAttempt is the 1-based index of the attempt the decision
	// package composed from (1 = the primary transcript, N>1 = retry
	// N-1). It is the unambiguous replay pin: the assessment audit's
	// response_hash cross-checks it, never replaces it.
	SelectedAttempt int      `json:"selected_attempt"`
	Stable          bool     `json:"stable"`
	Drift           bool     `json:"drift"`
	Limitations     []string `json:"limitations,omitempty"`
}

// StabilityDocument is stability.json: the report plus the run and finding
// identity it belongs to.
type StabilityDocument struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	FindingID     string `json:"finding_id"`
	StabilityReport
}

// StabilityRunDocument is one retry transcript pinned inside
// raw-agent.json under stability_runs: the verbatim messages plus the run
// metadata needed to audit that the retry consumed the same frozen inputs
// (identical prompt hash) and to re-derive its response hash. The accepted
// assessment itself stays in Messages — retries are never distilled into
// a preferred semantic answer.
type StabilityRunDocument struct {
	Attempt      int               `json:"attempt"`
	PromptHash   string            `json:"prompt_hash,omitempty"`
	ResponseHash string            `json:"response_hash,omitempty"`
	Steps        int               `json:"steps,omitempty"`
	ToolCalls    int               `json:"tool_calls,omitempty"`
	ErrorClass   string            `json:"error_class,omitempty"`
	FactPasses   []FactGatePass    `json:"fact_passes,omitempty"`
	Messages     []llm.ChatMessage `json:"messages"`
}

// ProjectStabilityAttempt projects one composed decision package onto its
// canonical stability record. The machine policy outcome is read from the
// package's own machine disposition, so the attempt record and the package
// cannot disagree. Every provenance pin comes from the package's audit
// block, so a drifted retry is detected on the same values the package is
// bound to. The human axis (judgment, action, premises and support) is
// projected separately from the machine axis, and both are pinned by
// canonical hashes so a text-only change cannot hide behind equal labels.
func ProjectStabilityAttempt(attempt int, pkg DecisionPackage) StabilityAttempt {
	m := pkg.MachineDisposition
	at := StabilityAttempt{
		Attempt:              attempt,
		Judgment:             string(pkg.Judgment.Verdict),
		JudgmentHash:         projectionHash(pkg.Judgment),
		ActionKind:           string(pkg.ProposedAction.Kind),
		ActionScope:          pkg.ProposedAction.Scope,
		ActionHash:           stabilityActionHash(pkg),
		PremisesSemanticHash: projectionHash(stabilityPremises(pkg.Premises)),
		PremisesHash:         projectionHash(pkg.Premises),
		SupportLevel:         string(pkg.Support.Level),
		SupportSemanticHash:  projectionHash(stabilitySupportOf(pkg.Support)),
		SupportHash:          projectionHash(pkg.Support),
		Recommendation:       m.Recommendation,
		MachineHash:          projectionHash(m),
		ProfileID:            m.RecommendedProfile.ID,
		Readiness:            pkg.TechnicalAssessment.Status,
		PolicyOutcome:        string(m.Automation),
		FalsifierHash:        pkg.Audit.FalsifierHash,
		SelectedRef:          pkg.Audit.SelectedRef,
		ResolvedCommit:       pkg.Audit.ResolvedCommit,
		InputHash:            firstNonEmpty(pkg.Audit.Stage0.InputHash, pkg.Audit.TicketHash),
		SnapshotHash:         pkg.Audit.SnapshotHash,
		AdvisoryHash:         pkg.Audit.AdvisoryHash,
		ConfigHash:           pkg.Audit.ConfigHash,
		RuleSetHash:          pkg.Audit.RulesetHash,
		PromptHash:           pkg.Audit.PromptHash,
		ToolchainHash:        projectionHash(pkg.Audit.Toolchain),
		// The machine condition hashes are derived from the machine
		// disposition, never from the human axes.
		AssumptionsHash: projectionHash(m.ResidualAssumptions),
		TriggersHash:    projectionHash(m.ReassessmentTriggers),
	}
	for _, proof := range pkg.FalsifierProofs {
		at.FalsifierHistory = append(at.FalsifierHistory, proof.History...)
	}
	for _, f := range pkg.Facts {
		if f.Status == ObsSupports || f.Status == ObsRefutes {
			at.DecisiveFacts = append(at.DecisiveFacts, decisiveFactID(f)+"="+f.Status)
		}
	}
	return at
}

// projectionHash is the canonical sha256 of one projected value; an
// encoding failure can only mean a non-serializable value was recorded, so
// it leaves the pin empty rather than inventing a digest.
func projectionHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return hashBytes(b)
}

// stabilityPremise is the attempt-independent projection of one decisive
// premise: what was claimed, the computed basis it actually has, the narrow
// proposition the record establishes, the owning party, the dependency edges
// and the subject/scope/coverage metadata. Attempt-local identity stays in
// the exact PremisesHash: the source refs and digests, which carry the
// observation ids a retry renames (det-0001 -> det-a2-0001). The premise
// structure itself is semantic: the owner and the sorted dependency edges
// are compared (the support and action projections already compare claim
// ids), so changing who owns an assumption or which premises support which
// is never silently treated as agreement.
type stabilityPremise struct {
	Statement              string       `json:"statement"`
	Basis                  PremiseBasis `json:"basis"`
	EstablishedProposition string       `json:"established_proposition,omitempty"`
	Subject                string       `json:"subject"`
	Scope                  string       `json:"scope"`
	Owner                  string       `json:"owner,omitempty"`
	DependsOn              []string     `json:"depends_on,omitempty"`
	Completeness           string       `json:"completeness,omitempty"`
	OpenBoundaries         []string     `json:"open_boundaries,omitempty"`
}

// stabilitySupport is the attempt-independent projection of the derived
// support: the level, the decisive claim closure and the admitted proofs.
// Support reasons are diagnostics and may quote attempt-local observation
// ids, so they stay in the exact SupportHash instead of deciding stability.
type stabilitySupport struct {
	Level          SupportLevel `json:"level"`
	DecisiveClaims []string     `json:"decisive_claim_ids"`
	ProofIDs       []string     `json:"proof_ids,omitempty"`
}

// stabilityPremises projects the premise closure canonically: the same
// propositions in the same scope always produce the same projection, and
// the order does not depend on the model's claim labels.
func stabilityPremises(premises []DecisionPremise) []stabilityPremise {
	out := make([]stabilityPremise, 0, len(premises))
	for _, pr := range premises {
		deps := append([]string(nil), pr.DependsOn...)
		sort.Strings(deps)
		out = append(out, stabilityPremise{
			Statement:              pr.Statement,
			Basis:                  pr.Basis,
			EstablishedProposition: pr.EstablishedProposition,
			Subject:                pr.Subject,
			Scope:                  pr.Scope,
			Owner:                  pr.Owner,
			DependsOn:              deps,
			Completeness:           pr.Completeness,
			OpenBoundaries:         pr.OpenBoundaries,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return stabilityPremiseKey(out[i]) < stabilityPremiseKey(out[j])
	})
	return out
}

// stabilityPremiseKey is the canonical ordering key of one semantic
// premise. It orders by meaning and structure, never by attempt-local
// identity.
func stabilityPremiseKey(p stabilityPremise) string {
	boundaries := append([]string(nil), p.OpenBoundaries...)
	sort.Strings(boundaries)
	return strings.Join([]string{
		p.Statement, string(p.Basis), p.EstablishedProposition,
		p.Subject, p.Scope, p.Owner, strings.Join(p.DependsOn, "\x00"),
		p.Completeness, strings.Join(boundaries, "\x00"),
	}, "\x00")
}

// stabilitySupportOf projects the support surface canonically without the
// diagnostic reason text.
func stabilitySupportOf(s DecisionSupport) stabilitySupport {
	claims := append([]string(nil), s.DecisiveClaimIDs...)
	sort.Strings(claims)
	proofs := append([]string(nil), s.ProofIDs...)
	sort.Strings(proofs)
	return stabilitySupport{Level: s.Level, DecisiveClaims: claims, ProofIDs: proofs}
}

func decisiveFactID(f DecisionFact) string {
	if f.ID != "" {
		return f.ID
	}
	return f.Kind + ":" + f.Subject
}

// CheckStability evaluates an attempt series (spec §2.4, §13.3): every
// attempt after the first must agree with attempt 1 on the human axis, the
// machine axis and every provenance pin. A provenance divergence sets Drift
// — a technical-error channel that callers surface instead of a package.
// A semantic divergence sets Stable=false; after retries are exhausted that
// is a limitation that forbids DISMISSED/LOWERED, never a reason to pick the
// preferred attempt. The report echoes every attempt verbatim.
func CheckStability(attempts []StabilityAttempt) StabilityReport {
	report := StabilityReport{Attempts: attempts}
	if len(attempts) > 0 {
		report.Retries = len(attempts) - 1
	}
	report.Stable = true
	if len(attempts) < 2 {
		return report
	}
	base := attempts[0]
	// Provenance pins that must be byte-identical across attempts: the
	// frozen inputs every retry is bound to.
	pins := []struct {
		name string
		get  func(StabilityAttempt) string
	}{
		{"input_hash", func(a StabilityAttempt) string { return a.InputHash }},
		{"snapshot_hash", func(a StabilityAttempt) string { return a.SnapshotHash }},
		{"advisory_hash", func(a StabilityAttempt) string { return a.AdvisoryHash }},
		{"config_hash", func(a StabilityAttempt) string { return a.ConfigHash }},
		{"ruleset_hash", func(a StabilityAttempt) string { return a.RuleSetHash }},
		{"prompt_hash", func(a StabilityAttempt) string { return a.PromptHash }},
		{"toolchain_hash", func(a StabilityAttempt) string { return a.ToolchainHash }},
		{"selected_ref", func(a StabilityAttempt) string { return a.SelectedRef }},
		{"resolved_commit", func(a StabilityAttempt) string { return a.ResolvedCommit }},
	}
	// The human axis: what the investigation concluded, what a person is
	// asked to do and how those grounds were computed. The compared
	// premise/support fields are the attempt-independent projections; the
	// exact hashes stay on the attempt for audit.
	human := []struct {
		name string
		get  func(StabilityAttempt) string
	}{
		{"judgment", func(a StabilityAttempt) string { return a.Judgment }},
		{"judgment_hash", func(a StabilityAttempt) string { return a.JudgmentHash }},
		{"action_kind", func(a StabilityAttempt) string { return a.ActionKind }},
		{"action_scope", func(a StabilityAttempt) string { return a.ActionScope }},
		{"action_hash", func(a StabilityAttempt) string { return a.ActionHash }},
		{"premises_semantics", func(a StabilityAttempt) string { return a.PremisesSemanticHash }},
		{"support_level", func(a StabilityAttempt) string { return a.SupportLevel }},
		{"support_representation", func(a StabilityAttempt) string { return a.SupportSemanticHash }},
	}
	// The machine axis: the deterministic reduction and its evidence
	// surface. A change here is machine instability, never human drift.
	machine := []struct {
		name string
		get  func(StabilityAttempt) string
	}{
		{"recommendation", func(a StabilityAttempt) string { return string(a.Recommendation) }},
		{"machine_disposition_hash", func(a StabilityAttempt) string { return a.MachineHash }},
		{"profile_id", func(a StabilityAttempt) string { return a.ProfileID }},
		{"readiness", func(a StabilityAttempt) string { return a.Readiness }},
		{"policy_outcome", func(a StabilityAttempt) string { return a.PolicyOutcome }},
		{"falsifier_hash", func(a StabilityAttempt) string { return a.FalsifierHash }},
		{"assumptions_hash", func(a StabilityAttempt) string { return a.AssumptionsHash }},
		{"triggers_hash", func(a StabilityAttempt) string { return a.TriggersHash }},
	}
	for _, at := range attempts[1:] {
		n := at.Attempt
		if n == 0 {
			n = -1
		}
		for _, p := range pins {
			if p.get(at) != p.get(base) {
				report.Drift = true
				report.Limitations = append(report.Limitations,
					fmt.Sprintf("attempt %d: provenance drift: %s changed", n, p.name))
			}
		}
		compareSemantics := func(axis string, fields []struct {
			name string
			get  func(StabilityAttempt) string
		}) {
			for _, f := range fields {
				if f.get(at) != f.get(base) {
					report.Stable = false
					report.Limitations = append(report.Limitations,
						fmt.Sprintf("attempt %d: %s %s changed (%s -> %s)", n, axis, f.name, f.get(base), f.get(at)))
				}
			}
		}
		compareSemantics("human", human)
		compareSemantics("machine", machine)
		if !slices.Equal(at.DecisiveFacts, base.DecisiveFacts) {
			report.Stable = false
			report.Limitations = append(report.Limitations,
				fmt.Sprintf("attempt %d: machine decisive facts changed", n))
		}
	}
	return report
}

// stabilityRunDocument projects one retry run into its raw-agent.json
// record; the verbatim transcript is preserved unmodified.
func stabilityRunDocument(attempt int, run AgentRun) StabilityRunDocument {
	return StabilityRunDocument{
		Attempt:      attempt,
		PromptHash:   run.PromptHash,
		ResponseHash: run.ResponseHash,
		Steps:        run.Steps,
		ToolCalls:    run.ToolCalls,
		ErrorClass:   run.ErrorClass,
		FactPasses:   run.FactPasses,
		Messages:     run.RawMessages,
	}
}
