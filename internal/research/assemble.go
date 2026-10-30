package research

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// AssembleInput is everything the merge authority consumes.
type AssembleInput struct {
	Lane     *LaneResult
	Turn     *AgentTurn        // nil => NOT_REQUESTED
	Decision *EvidenceDecision // independently verified evidence result
	// DecisionArtifact, when non-nil, carries the R6 decision-artifact/1
	// contract: the assembled report is emitted as research-report/3 and
	// the artifact stays authoritative for the human-facing contract
	// (Decision remains only the /2-compatible projection).
	DecisionArtifact *DecisionArtifact
	// Trace is the executed bounded verification plan (nil when no valid
	// plan ran). It populates decision.checks and grounds the report's
	// decision evidence refs in the persisted verification records.
	Trace *VerificationTrace
	// VerifArtifacts maps renumbered trace-observation ids to the
	// persisted verification-artifacts/ pins the CLI wrote; used only to
	// register evidence_quality.references rows for those observations.
	VerifArtifacts map[string]ArtifactRef
	// RequestComposition is the request-level answer the caller wants
	// published. It is never trusted on its own: assembly re-admits it
	// against the lane's own composed value, and a lane that never composed
	// one publishes none. A supplied composition selects the /4 contract.
	RequestComposition *domain.RequestedFinding
	DeterministicOnly  bool
	RunID              string
	StartedAt          time.Time
	FinishedAt         time.Time
	Timeouts           TimeoutInfo
	Harness            HarnessInfo
	// LaneStartedAt/LaneFinishedAt bound the deterministic attempt;
	// zero values fall back to StartedAt/FinishedAt.
	LaneStartedAt  time.Time
	LaneFinishedAt time.Time
}

// Assemble builds the research report. It is the only merge authority:
// deterministic facts first, agent output never promoted, disposition
// unconditionally review-required.
func Assemble(in AssembleInput) *Report {
	a := &assembler{
		lane:         in.Lane,
		factByID:     map[string]bool{},
		obsByID:      map[string]bool{},
		bindSet:      map[string]bool{},
		agentSummary: map[string]string{},
	}
	for _, f := range in.Lane.Facts {
		a.factByID[f.ID] = true
	}
	for _, o := range in.Lane.Observations {
		a.obsByID["obs:"+o.ID] = true
	}
	r := &Report{
		Schema: ReportSchema,
		Mode:   ReportMode,
	}
	if in.DecisionArtifact != nil {
		r.Schema = ReportSchemaV3
		// Publication re-gate: a supplied artifact never reaches the report
		// carrying a CLOSE_* the current lane scope does not authorize.
		r.DecisionArtifact = scopeBoundArtifact(in.Lane, in.DecisionArtifact)
	}
	// /4 adds the one authoritative request answer. The lane's own
	// re-admitted composition is authoritative; a supplied value is
	// published only when it is that value. A composition offered but not
	// re-admissible keeps the /4 contract with the member withheld, so
	// validation refuses the document by name instead of silently
	// downgrading it to a schema that never carried the authority.
	if composition, offered := assembleRequestComposition(in); composition != nil {
		copied := *composition
		r.RequestComposition = &copied
		r.Schema = ReportSchemaV4
	} else if offered {
		r.Schema = ReportSchemaV4
	}
	if in.DecisionArtifact == nil && (r.RequestComposition != nil || in.Lane.ExactRecordIntake || in.Lane.RequestedCase != nil) {
		r.Schema = ReportSchemaV5
		r.RequestedCaseSHA256 = requestedCaseDigest(in.Lane.RequestedCase)
	}
	// Lists are always arrays in the contract (never null).
	r.AffectedImplementations = []AffectedImplementation{}
	r.ExploitationConditions = []ExploitationCondition{}
	r.ResidualQuestions = []ResidualQuestion{}
	r.VerifiedFacts = []VerifiedFact{}
	r.AgentAssertions = []AgentAssertion{}
	r.Unknowns = []UnknownEntry{}
	r.OpenQuestions = []OpenQuestion{}
	r.Recommendations = []Recommendation{}
	r.Run = RunInfo{
		RunID:             in.RunID,
		StartedAt:         in.StartedAt.UTC().Format(time.RFC3339),
		FinishedAt:        in.FinishedAt.UTC().Format(time.RFC3339),
		DeterministicOnly: in.DeterministicOnly,
		Timeouts:          in.Timeouts,
		Harness:           in.Harness,
	}
	// A fail-closed release-evidence channel marks the run NOT_RUN: the
	// model/planner path never ran, and the named reason is the channel's
	// own code — never a synthesized success.
	if notRun, reason := LaneReleaseNotRun(in.Lane); notRun {
		r.Run.Outcome = "NOT_RUN"
		r.Run.OutcomeReason = reason
	}
	a.fillInput(r)
	a.fillAdvisory(r)
	a.fillApplicability(r)
	r.VerifiedFacts = in.Lane.Facts
	a.detClaims(r)
	if in.Turn != nil {
		a.agentClaims(r, in.Turn)
	}
	a.sections(r, in.Turn)
	a.implementationLocusProposals(r, in.Turn)
	a.exploitLocusProposals(r, in.Turn)
	a.unknowns(r, in.Turn)
	a.questions(r, in.Turn)
	a.triage(r, in.Turn)
	a.recommendations(r, in.Turn)
	a.applySlice2(r, in)
	if in.Turn != nil {
		a.emitAgentSourceIndex(r)
	}
	// Publication re-gate: the supplied decision is only a candidate, so a
	// negative whose resolved scope does not cover the requested advisory
	// identity is projected to INCONCLUSIVE here — never copied verbatim.
	// When a request composition is published, the record-bound decision may
	// not contradict it either: a definitive record verdict beside a failed
	// or external request, or a positive/negative disagreement, is projected
	// to INCONCLUSIVE with the request's own cause. Neither lane may report a
	// different failure/external classification than the composition.
	decision := compositionBoundDecision(in.Lane, scopeBoundDecision(in.Lane, in.Decision), r.RequestComposition)
	r.Decision = reportDecision(decision, in.Turn, a.envDerived)
	a.attachVerification(r, in)
	a.exploitLocusBinding(r)
	r.Disposition = Disposition{
		Class:     "REVIEW_REQUIRED",
		AutoClose: false,
		Reason: "research lane output supports human triage only: evidence is " +
			"scope-bounded, agent claims are unverified hypotheses, and the " +
			"contract forbids VERIFIED/FALSE/AUTO_CLOSE dispositions",
		ForbiddenClasses: []string{"VERIFIED", "FALSE", "AUTO_CLOSE"},
	}
	normalizeEmpty(r)
	return r
}

// assembleRequestComposition decides which request composition assembly may
// publish. The lane's own re-admitted value is authoritative: a supplied value
// is published only when it equals that value, and a lane that never composed
// one has nothing to re-admit against. offered reports whether any composition
// was proposed, which keeps the /4 contract (and therefore a named validation
// refusal) instead of silently downgrading the document.
func assembleRequestComposition(in AssembleInput) (composition *domain.RequestedFinding, offered bool) {
	if in.RequestComposition == nil && (in.Lane == nil || in.Lane.RequestComposition == nil) {
		return nil, false
	}
	if in.Lane == nil || in.Lane.RequestComposition == nil {
		return nil, true
	}
	admitted, err := in.Lane.AdmitRequestComposition(in.RequestComposition)
	if err != nil {
		return nil, true
	}
	if admitted.Status != domain.FindingFinal {
		return nil, true
	}
	if err := admitted.Validate(); err != nil {
		return nil, true
	}
	return admitted, true
}

func reportDecision(in *EvidenceDecision, turn *AgentTurn, envDerived []string) *EvidenceDecision {
	if in == nil {
		return &EvidenceDecision{
			Verdict:         domain.VerdictInconclusive,
			Reason:          "no independently verified decision was provided",
			Scope:           "independent verification scope",
			Coverage:        "NOT_EVALUATED",
			Limitations:     []string{"the verification decision was not evaluated in this report"},
			HumanQuestions:  mergeDerivedQuestions(envDerived, []string{"which deterministic check should be executed to evaluate the proposed exploit condition?"}),
			TicketRationale: "Decision not evaluated; follow-up: execute the relevant deterministic verification tool before ticket disposition.",
		}
	}
	out := *in
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	out.Limitations = append([]string(nil), in.Limitations...)
	out.Checks = append([]DecisionCheck(nil), in.Checks...)
	out.HumanQuestions = append([]string(nil), in.HumanQuestions...)
	if len(envDerived) > 0 {
		// Derived deployment questions lead human_questions: they name the
		// recorded environment ask the human must answer before the generic
		// "which check resolves the unknown" prompt.
		out.HumanQuestions = mergeDerivedQuestions(envDerived, in.HumanQuestions)
	}
	if out.AgentHypothesis == "" && turn != nil && turn.Answer != nil {
		out.AgentHypothesis = turn.Answer.Reasoning
	}
	if out.AgentHypothesis == "" {
		out.AgentHypothesis = "no agent hypothesis was retained"
	}
	if out.Verdict == domain.VerdictInconclusive && len(out.HumanQuestions) == 0 {
		out.HumanQuestions = []string{"which deterministic check should resolve the recorded unknown?"}
	}
	if out.TicketRationale == "" {
		out.TicketRationale = out.Reason
	}
	return &out
}

// mergeDerivedQuestions prepends the derived environment questions to
// an existing human-question list, deduplicated and capped at the R6
// bound so no surface ever shows more than two asks.
func mergeDerivedQuestions(derived, base []string) []string {
	out := dedupeStrings(append(append([]string(nil), derived...), base...))
	if len(out) > MaxEnvironmentQuestions {
		out = out[:MaxEnvironmentQuestions]
	}
	return out
}

// attachVerification grounds the report's decision in the persisted
// verification records. The decision object's refs live in the session's
// evidence space (sha256: payload digests, src: locators, ev: pins, and —
// for the applicability early-exit — resolver EV-* ids); report refs must
// resolve to recorded entities, so every decision ref is translated to
// the persisted observation(s) that carried it (obs:<id> of the
// renumbered verification record, or the lane's own observation ids for
// lane-side refs). A ref nothing recorded stays verbatim and fails
// validation loudly — refs are never dropped to look resolvable.
// decision.checks rows describe each actually executed request/observation
// pair verbatim.
func (a *assembler) attachVerification(r *Report, in AssembleInput) {
	if r.Decision == nil {
		return
	}
	t := in.Trace
	// A config-origin decision is the lane-owned post-reach proof: its
	// executed check is the lane observation, not whatever agent
	// verification trace the same run happened to record. Showing the
	// agent's unrelated checks beside that verdict would misstate what
	// executed.
	if r.Decision.GroundBasis == domain.BasisConfigOrigin &&
		a.lane.ConfigProof != nil && a.lane.ConfigProof.Trace != nil {
		t = a.lane.ConfigProof.Trace
	}
	axisCarrier := ""
	axisEV := map[string]bool{}
	if ax := a.lane.ImplementationAxis; ax != nil {
		axisCarrier = ax.ObservationID
		for _, id := range ax.EvidenceIDs {
			axisEV[id] = true
		}
	}
	axisClosed := axisCarrier != "" &&
		a.lane.Affected.VulnerableImplementationPresent == domain.ClaimFalse
	if t == nil && !axisClosed {
		return
	}
	// ref -> the renumbered verification observation ids that emitted it.
	byRef := map[string][]string{}
	if t != nil {
		for _, o := range t.Observations {
			if o == nil {
				continue
			}
			for _, ref := range o.EvidenceRefs {
				byRef[ref] = append(byRef[ref], o.ID)
			}
		}
	}
	// resolver evidence ids (EV-*) ground in the lane's affected-resolve
	// observation record — the persisted record of that chain.
	var affectedResolveIDs []string
	for _, o := range in.Lane.Observations {
		if o.Tool == "affected-resolve" {
			affectedResolveIDs = append(affectedResolveIDs, o.ID)
		}
	}
	evIDs := map[string]bool{}
	for _, ev := range in.Lane.AffectedEvidence {
		evIDs[string(ev.ID)] = true
	}
	translate := func(ref string) []string {
		if ids, ok := byRef[ref]; ok {
			out := make([]string, 0, len(ids))
			for _, id := range ids {
				out = append(out, "obs:"+id)
			}
			return out
		}
		// The implementation-axis carrier is distinct: verifier evidence
		// ids ground in the lane's own implementation-axis observation —
		// the dedicated record of that check — never in the resolver's.
		if axisCarrier != "" && axisEV[ref] {
			return []string{"obs:" + axisCarrier}
		}
		if evIDs[ref] && len(affectedResolveIDs) > 0 {
			out := make([]string, 0, len(affectedResolveIDs))
			for _, id := range affectedResolveIDs {
				out = append(out, "obs:"+id)
			}
			return out
		}
		return []string{ref}
	}
	out := r.Decision
	var refs []string
	seen := map[string]bool{}
	for _, ref := range out.EvidenceRefs {
		for _, tr := range translate(ref) {
			if !seen[tr] {
				seen[tr] = true
				refs = append(refs, tr)
			}
		}
	}
	out.EvidenceRefs = refs
	// Checks mirror the executed prefix of the trace: one row per
	// dispatched request, bound to its persisted observation.
	out.Checks = nil
	if t != nil && !axisClosed {
		for i, o := range t.Observations {
			if o == nil {
				continue
			}
			c := DecisionCheck{
				ID:           t.Requests[i].ID,
				Tool:         o.Tool,
				Status:       string(o.ToolStatus),
				Completeness: string(o.Completeness),
				Scope:        o.Scope,
				EvidenceRefs: []string{"obs:" + o.ID},
				Limitations:  append([]string(nil), o.Limitations...),
				DerivedFrom:  t.Requests[i].DerivedFrom,
			}
			if c.ID == "" {
				c.ID = o.ID
			}
			out.Checks = append(out.Checks, c)
		}
	}
	// An axis-closed NOT_AFFECTED carries no verification trace: the
	// executed check is the lane's own implementation-axis observation.
	// Mirror the config route's convention — one check row bound to the
	// persisted lane record — so decision.checks reports what ran.
	if axisClosed {
		for _, o := range in.Lane.Observations {
			if o == nil || o.ID != axisCarrier {
				continue
			}
			out.Checks = append(out.Checks, DecisionCheck{
				ID:           "lane-implementation-axis",
				Tool:         implementationAxisTool,
				Status:       string(o.ToolStatus),
				Completeness: string(o.Completeness),
				Scope:        o.Scope,
				EvidenceRefs: []string{"obs:" + o.ID},
				Limitations:  append([]string(nil), o.Limitations...),
			})
		}
	}
	// Register the persisted verification observations in the report's
	// reference index so the obs: citations above resolve to pinned
	// artifacts on disk.
	present := map[string]bool{}
	for _, er := range r.EvidenceQuality.References {
		present[er.Ref] = true
	}
	ids := make([]string, 0, len(in.VerifArtifacts))
	for id := range in.VerifArtifacts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ref := "obs:" + id
		if present[ref] {
			continue
		}
		present[ref] = true
		art := in.VerifArtifacts[id]
		r.EvidenceQuality.References = append(r.EvidenceQuality.References,
			EvidenceReference{Ref: ref, Kind: "observation", Path: art.Path,
				Selector: art.Selector, SHA256: art.SHA256})
	}
	sort.SliceStable(r.EvidenceQuality.References,
		func(i, j int) bool { return r.EvidenceQuality.References[i].Ref < r.EvidenceQuality.References[j].Ref })
}

// normalizeEmpty converts every nil slice in the contract into [] so the
// rendered JSON never carries null where a list is expected. Scalar
// optionals stay pointer-null by design.
func normalizeEmpty(r *Report) {
	fixStrs := func(ss *[]string) {
		if *ss == nil {
			*ss = []string{}
		}
	}
	fixStrs(&r.ProductApplicability.SelectedModules)
	fixStrs(&r.ProductApplicability.CheckedModules)
	fixStrs(&r.ProductApplicability.CheckedPackages)
	fixStrs(&r.ProductApplicability.PendingModules)
	fixStrs(&r.ProductApplicability.UnresolvedModules)
	fixStrs(&r.ProductApplicability.VersionAffectedModules)
	fixStrs(&r.ProductApplicability.Limitations)
	fixStrs(&r.ProductApplicability.EvidenceRefs)
	fixStrs(&r.ProductApplicability.EvaluatedEntryIDs)
	if r.ProductApplicability.Basis == nil {
		r.ProductApplicability.Basis = []ApplicabilityBasis{}
	}
	for i := range r.ProductApplicability.Basis {
		fixStrs(&r.ProductApplicability.Basis[i].EvidenceRefs)
		fixStrs(&r.ProductApplicability.Basis[i].VerifiedEvidenceRefs)
		fixStrs(&r.ProductApplicability.Basis[i].Limitations)
	}
	if r.ContractExtensions == nil {
		r.ContractExtensions = []string{}
	}
	if r.Contradictions == nil {
		r.Contradictions = []Contradiction{}
	}
	for i := range r.Contradictions {
		fixStrs(&r.Contradictions[i].DeterministicRefs)
		fixStrs(&r.Contradictions[i].Limitations)
	}
	for _, ax := range []*Axis{
		&r.ExploitationAxes.CodeReachability,
		&r.ExploitationAxes.AttackSurfaceAvailability,
		&r.ExploitationAxes.ExploitationEstablished,
	} {
		fixStrs(&ax.EvidenceRefs)
		fixStrs(&ax.Limitations)
	}
	// The optional B41 audit axis keeps the same never-null list shape
	// whenever a /3 report carries it.
	if ax := r.ExploitationAxes.BuildUsageScope; ax != nil {
		fixStrs(&ax.EvidenceRefs)
		fixStrs(&ax.Limitations)
	}
	fixStrs(&r.ClassificationReview.BasisRefs)
	fixStrs(&r.ClassificationReview.Limitations)
	if el := r.EvidenceLevel; el != nil {
		fixStrs(&el.ConditionRefs)
		fixStrs(&el.EvidenceRefs)
		fixStrs(&el.BlockingConditions)
		fixStrs(&el.Limitations)
	}
	if r.Run.Attempts == nil {
		r.Run.Attempts = []Attempt{}
	}
	for i := range r.Run.Attempts {
		if ex := r.Run.Attempts[i].Extraction; ex != nil && ex.Candidates == nil {
			ex.Candidates = []ExtractionCandidate{}
		}
	}
	for i := range r.AffectedImplementations {
		im := &r.AffectedImplementations[i]
		fixStrs(&im.Symbols)
		fixStrs(&im.GOOS)
		fixStrs(&im.GOARCH)
		fixStrs(&im.FixedVersions)
		if im.AffectedVersions == nil {
			im.AffectedVersions = []VersionBounds{}
		}
	}
	for i := range r.ExploitationConditions {
		fixStrs(&r.ExploitationConditions[i].EvidenceRefs)
		fixStrs(&r.ExploitationConditions[i].Limitations)
	}
	for _, sec := range []*Section{
		&r.VulnerabilityMechanism, &r.RootCause, &r.AttackScenario,
		&r.ProductExposure, &r.AlternativePaths,
	} {
		if sec.Claims == nil {
			sec.Claims = []Claim{}
		}
		fixStrs(&sec.Limitations)
		for i := range sec.Claims {
			fixStrs(&sec.Claims[i].EvidenceRefs)
			fixStrs(&sec.Claims[i].Limitations)
		}
	}
	if r.EvidenceQuality.References == nil {
		r.EvidenceQuality.References = []EvidenceReference{}
	}
	fixStrs(&r.EvidenceQuality.Coverage)
	fixStrs(&r.EvidenceQuality.Conflicts)
	fixStrs(&r.EvidenceQuality.Limitations)
	for i := range r.ResidualQuestions {
		fixStrs(&r.ResidualQuestions[i].EvidenceRefs)
	}
	fixStrs(&r.TriageRecommendation.EvidenceRefs)
	for i := range r.VerifiedFacts {
		fixStrs(&r.VerifiedFacts[i].Limitations)
	}
	for i := range r.AgentAssertions {
		fixStrs(&r.AgentAssertions[i].EvidenceRefs)
		fixStrs(&r.AgentAssertions[i].Limitations)
	}
	for i := range r.Unknowns {
		fixStrs(&r.Unknowns[i].EvidenceRefs)
	}
	for i := range r.OpenQuestions {
		fixStrs(&r.OpenQuestions[i].EvidenceRefs)
	}
	for i := range r.Recommendations {
		fixStrs(&r.Recommendations[i].EvidenceRefs)
	}
	if r.Decision != nil {
		fixStrs(&r.Decision.EvidenceRefs)
		fixStrs(&r.Decision.Limitations)
		fixStrs(&r.Decision.HumanQuestions)
		for i := range r.Decision.Checks {
			fixStrs(&r.Decision.Checks[i].EvidenceRefs)
			fixStrs(&r.Decision.Checks[i].Limitations)
		}
	}
}

type assembler struct {
	lane     *LaneResult
	factByID map[string]bool
	obsByID  map[string]bool
	bindSet  map[string]bool // advisory-bound component names

	detClaimSeq int
	agtClaimSeq int
	assertSeq   int
	unkSeq      int
	qSeq        int
	condSeq     int
	recSeq      int
	conflicts   []string
	contraSeq   int

	// Slice-2 derivation state.
	scopeGapModules []string // agent-named unbound components (advisory_scope_gap)
	ownModule       string
	depModules      map[string]bool
	modSetLoaded    bool
	classAssertID   string // id of the classification assertion

	agentSummary    map[string]string
	agentQuestions  []any
	agentTriage     map[string]any
	agentSrcRefs    []string
	pendingUnknowns []UnknownEntry

	// envDerived carries the residual deployment/config questions
	// envQuestions produced during questions(); triage and the decision
	// projection read them so every human-facing surface names the same
	// specific ask.
	envDerived []string
}

func (a *assembler) nextDetClaim(sec string) string {
	a.detClaimSeq++
	return fmt.Sprintf("dc-%s-%02d", sec, a.detClaimSeq)
}
func (a *assembler) nextAgtClaim(sec string) string {
	a.agtClaimSeq++
	return fmt.Sprintf("ac-%s-%02d", sec, a.agtClaimSeq)
}
func (a *assembler) nextAssertion() string {
	a.assertSeq++
	return fmt.Sprintf("A-%04d", a.assertSeq)
}
func (a *assembler) nextUnknown() string {
	a.unkSeq++
	return fmt.Sprintf("U-%04d", a.unkSeq)
}
func (a *assembler) nextQuestion() string {
	a.qSeq++
	return fmt.Sprintf("Q-%04d", a.qSeq)
}
func (a *assembler) nextCondition() string {
	a.condSeq++
	return fmt.Sprintf("EC-%04d", a.condSeq)
}
func (a *assembler) nextRec() string {
	a.recSeq++
	return fmt.Sprintf("R-%04d", a.recSeq)
}

func (a *assembler) fillInput(r *Report) {
	s := a.lane.Snapshot
	r.Input.Snapshot = SnapshotInput{
		Path:              a.lane.SnapshotRoot,
		CommitSHA:         s.Commit,
		ExternalCommitSHA: nilStr(s.ExternalCommitSHA),
		ContentHash:       a.lane.ContentHash,
		GoVersion:         s.GoVersion,
		ReleaseGoVersion:  nilStr(s.ReleaseGoVersion),
		GoVersionSource:   nilStr(string(s.GoVersionSource)),
		MinimumGoVersion:  nilStr(s.MinimumGoVersion),
		GOOS:              s.GOOS,
		GOARCH:            s.GOARCH,
		BuildTags:         s.BuildTags,
		Target:            s.Target,
		VendorMode:        s.VendorMode,
		GoWorkFile:        nilStr(s.GoWorkFile),
	}
	r.Input.Snapshot.ReleaseEvidence = LaneReleaseEvidence(a.lane)
	r.Input.Advisory = a.lane.Advisory.Input
	r.Input.Ticket = a.lane.Ticket
	r.Input.DeclaredAssumptions = a.lane.Assumptions
	r.Input.ImplementationLocusProposals = a.lane.ImplementationProposals
	r.Input.ExploitLocusProposals = a.lane.ExploitProposals
}

// exploitLocusBinding projects the lane's COMPLETE exploit-locus binding
// (when the post-reach route attempted the symbol-less advisory) into its
// own report member. Only a binding whose every deterministic check
// closed appears: incomplete attempts stay in the lane observation and
// never enter the report as a usable record. The condition subjects are
// the verified product-facing sinks, never the advisory's symbol set.
func (a *assembler) exploitLocusBinding(r *Report) {
	lb := a.lane.ExploitBinding
	if lb == nil || !lb.Complete || lb.Binding == nil || lb.Condition == nil {
		return
	}
	b := lb.Binding
	cond := lb.Condition
	rec := &ExploitLocusBindingReport{
		ProposalID:           b.ProposalID,
		AdvisoryID:           b.AdvisoryID,
		Module:               b.Module,
		Version:              b.Version,
		Vulnerable:           Vulnerable{Package: b.VulnerablePackage, Symbol: b.VulnerableSymbol},
		Sinks:                append([]domain.ExploitLocusSink(nil), b.Sinks...),
		TriggerArgumentName:  b.TriggerArgumentName,
		TriggerArgumentIndex: b.TriggerArgIndex,
		RelationEvidence:     append([]string(nil), b.RelationEvidence...),
		Condition: ExploitLocusConditionReport{
			ID:        string(cond.ID),
			Kind:      string(cond.Kind),
			Mandatory: cond.Mandatory,
			Subjects:  append([]domain.SymbolRef(nil), cond.Subjects...),
			ArgIndex:  cond.ArgIndex,
			Statement: cond.Description,
		},
		AssumptionIDs: append([]string(nil), lb.AssumptionIDs...),
		Complete:      b.Complete,
		Blockers:      append([]string(nil), b.Blockers...),
		Limitations:   append([]string(nil), b.Limitations...),
	}
	for _, id := range []string{lb.ObservationID, lb.PostReachObservationID} {
		if id != "" {
			rec.EvidenceRefs = append(rec.EvidenceRefs, "obs:"+id)
		}
	}
	r.ExploitLocusBinding = rec
}

func (a *assembler) fillAdvisory(r *Report) {
	v := a.lane.Advisory.Vuln
	r.Vulnerability = VulnerabilityInfo{
		ID:          v.ID,
		Aliases:     v.Aliases,
		Summary:     v.Summary,
		Description: v.Description,
		References:  v.References,
	}
	// Advisory digest ref: the verified fact produced by the advisory load.
	for _, o := range a.lane.Observations {
		if o.Tool == "advisory-load" && o.ToolStatus == evidencetools.StatusOK {
			if fid := a.lane.FactRef(o.ID); fid != "" {
				r.Vulnerability.AdvisoryDigestRef = fid
			}
		}
	}
	if r.Vulnerability.AdvisoryDigestRef == "" {
		r.Vulnerability.AdvisoryDigestRef = "adv:" + a.lane.Advisory.Input.ResolvedID
	}
	r.AffectedImplementations = a.lane.Advisory.Impls
	// Advisory-bound component set for §7.5 binding.
	for _, im := range a.lane.Advisory.Impls {
		if im.Module != "" {
			a.bindSet[im.Module] = true
		}
		if im.Package != nil && *im.Package != "" {
			a.bindSet[*im.Package] = true
		}
		for _, s := range im.Symbols {
			a.bindSet[s] = true
			if im.Package != nil {
				a.bindSet[*im.Package+"."+s] = true
			}
		}
	}
}

func (a *assembler) fillApplicability(r *Report) {
	res := a.lane.Affected
	pa := ProductApplicability{
		ModulePresent:   claimResultString(res.ModulePresent),
		VersionAffected: claimResultString(res.VersionAffected),
		PackagePresent:  claimResultString(res.PackagePresent),
		BuildRelevant:   claimResultString(res.BuildRelevant),
		// The implementation axis is optional: legacy lane results leave
		// it empty, and legacy reports stay byte-identical.
		VulnerableImplementationPresent: optionalClaimResultString(res.VulnerableImplementationPresent),
		ImplementationLocus:             res.ImplementationLocus,
		ImplementationTarget:            res.ImplementationTarget,
		ImplementationTargetScope:       res.ImplementationTargetScope,
		AssumptionIDs:                   res.AssumptionIDs,
		ResolvedVersion:                 nilStr(res.ResolvedVersion),
		SelectedModule:                  nilStr(res.SelectedModule),
		SelectedModules:                 res.SelectedModules,
		CheckedModules:                  res.CheckedModules,
		CheckedPackages:                 res.CheckedPackages,
		PendingModules:                  res.PendingModules,
		UnresolvedModules:               res.UnresolvedModules,
		// Ticket-build identity: a package-version mismatch refused the
		// version axis — the named reason travels so no consumer can read
		// UNKNOWN as "out of range".
		VersionAxisBlocked: res.VersionAxisBlocked,
		TicketCheck:        res.TicketCheck,
		// Version-side membership, kept even when the package probe
		// narrowed SelectedModules to the linked subset.
		VersionAffectedModules: res.VersionAffectedModules,
		Limitations:            res.Limitations,
	}
	if res.VersionAxisBlocked {
		pa.VersionAxisBlockReason = domain.TicketReasonPackageVersionMismatch
	}
	for _, o := range a.lane.Observations {
		if o.Tool == "affected-resolve" || o.Tool == implementationAxisTool {
			pa.EvidenceRefs = append(pa.EvidenceRefs, "obs:"+o.ID)
			if fid := a.lane.FactRef(o.ID); fid != "" {
				pa.EvidenceRefs = append(pa.EvidenceRefs, fid)
			}
		}
	}
	pa.EvaluatedEntryIDs = evaluatedEntryIDs(r.AffectedImplementations, pa)
	// advisory_entry_status aggregates the per-entry fix verdicts. The
	// NOT_EVALUATED branch also covers the module-absent case: presence
	// was checked (the entries stay in evaluated_entry_ids), but no
	// fix/affected verdict was reached.
	pa.AdvisoryEntryStatus = aggregateEntryStatus(r.AffectedImplementations, pa)
	trues, unknowns := 0, 0
	axes := []string{pa.ModulePresent, pa.VersionAffected, pa.PackagePresent, pa.BuildRelevant}
	// The implementation axis is additive: only a decided value (TRUE or
	// FALSE) participates in the status — an UNKNOWN implementation axis
	// on an otherwise resolved chain does not degrade it, because the
	// axis is evaluated only when admitted proposals exist.
	if pa.VulnerableImplementationPresent == "TRUE" || pa.VulnerableImplementationPresent == "FALSE" {
		axes = append(axes, pa.VulnerableImplementationPresent)
	}
	for _, c := range axes {
		switch c {
		case "TRUE", "FALSE":
			trues++
		default:
			unknowns++
		}
	}
	switch {
	case a.lane.ResolveErr != nil || trues == 0:
		pa.Status = StatusUnknown
	case unknowns > 0:
		pa.Status = StatusPartial
	default:
		pa.Status = StatusSupported
	}
	r.ProductApplicability = pa
}

// detClaims converts the deterministic evidence that maps onto
// assessment sections — location/exposure/usage facts only; the lane
// never claims a mechanism, root cause or exploit path.
func (a *assembler) detClaims(r *Report) {
	detWith := func(name string, sec *Section, statement, subject, scope string, obs *evidencetools.Observation, assumptionIDs []string) {
		refs := []string{"obs:" + obs.ID}
		if fid := a.lane.FactRef(obs.ID); fid != "" {
			refs = []string{fid}
		}
		sec.Claims = append(sec.Claims, Claim{
			ID: a.nextDetClaim(name), Statement: statement, Subject: subject,
			Scope: scope, State: StateSupported, EvidenceRefs: refs,
			Origin: OriginDeterm, Limitations: obs.Limitations,
			// Policy references travel beside the evidence refs, never
			// inside them: a declared assumption is not a measured fact.
			AssumptionIDs: assumptionIDs,
		})
	}
	det := func(name string, sec *Section, statement, subject, scope string, obs *evidencetools.Observation) {
		detWith(name, sec, statement, subject, scope, obs, nil)
	}
	// Advisory-statement claim: the advisory says X — a fact about the
	// record, not about the product.
	if advFact := a.findObs("advisory-load"); advFact != nil && advFact.ToolStatus == evidencetools.StatusOK {
		v := a.lane.Advisory.Vuln
		det("mechanism", &r.VulnerabilityMechanism,
			"advisory "+v.ID+" states: "+singleLine(v.Summary),
			v.ID, "frozen advisory document", advFact)
	}
	for _, o := range a.lane.Observations {
		if o.ToolStatus != evidencetools.StatusOK {
			continue
		}
		// An open-enumeration observation with no recorded finding never
		// produces a deterministic claim: it is routed to unknowns, and
		// its empty result must not be readable as a supported absence.
		if o.Completeness == evidencetools.CompletenessUnknown && a.lane.FactRef(o.ID) == "" {
			continue
		}
		subj := ""
		if o.ScopeDetails != nil {
			subj = o.ScopeDetails.Subject
		}
		switch o.Tool {
		case "find_symbol":
			if dataHas(o, "found", true) {
				det("rootcause", &r.RootCause, "advisory-named symbol "+o.Fact, subj, o.Scope, o)
			}
		case "module_usage":
			det("exposure", &r.ProductExposure, o.Fact, subj, o.Scope, o)
		case "find_callers", "find_may_callers", "find_dep_callers":
			det("exposure", &r.ProductExposure, o.Fact, subj, o.Scope, o)
		case "listen-sites":
			if factCount(o) > 0 {
				det("exposure", &r.ProductExposure, o.Fact, "inbound listeners", o.Scope, o)
				r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
					ID: a.nextCondition(), Subject: subjInboundListener, Scope: o.Scope,
					Necessity: "unknown", Origin: OriginDeterm, State: StateSupported,
					Statement:    o.Fact + " — a listening socket exists in source; attacker reachability is not established by source alone",
					EvidenceRefs: factRefs(a.lane, o), Limitations: o.Limitations,
				})
			}
		case "dial-sites":
			if factCount(o) > 0 {
				det("exposure", &r.ProductExposure, o.Fact, subj, o.Scope, o)
			}
		case "inbound-auth-facts":
			if factCount(o) > 0 {
				det("exposure", &r.ProductExposure, o.Fact, "inbound auth posture", o.Scope, o)
			}
		case "ingress-inventory":
			det("exposure", &r.ProductExposure, o.Fact, subj, o.Scope, o)
		case evidencetools.PackageUsageTool:
			// Only a USED verdict corroborates product-source use of the
			// advisory-declared package/symbol — the single claim shape
			// the check can underwrite. A bounded negative never claims
			// exposure either way and an unclosed scope claims nothing,
			// so only a promoted fact may carry the claim.
			d, dok := packageUsageDataOf(o)
			if dok && packageUsageConditionState(d) == StateSupported && a.lane.FactRef(o.ID) != "" {
				det("exposure", &r.ProductExposure, o.Fact, subj, o.Scope, o)
			}
		case "interface_dispatch_sites", "gated_refs", "scan_dynamic":
			if factCount(o) > 0 {
				det("altpaths", &r.AlternativePaths, o.Fact, subj, o.Scope, o)
			}
		case "module_internal_reach":
			det("altpaths", &r.AlternativePaths, o.Fact, subj, o.Scope, o)
		case postReachConfigTool:
			// The post-reach configuration check states two separate
			// things: the deterministic exact-sink evidence (carried by
			// the fact id / observation ref) and the policy assumption
			// the verdict rests on (assumption_ids). Only a closed
			// NO_EXPLOIT_PATH_FOUND attempt becomes a supported claim; a
			// blocked attempt stays on the unknowns side.
			var d struct {
				Verdict       string   `json:"verdict"`
				ConditionID   string   `json:"condition_id"`
				AssumptionIDs []string `json:"assumption_ids"`
			}
			if !decodeData(o.Data, &d) || d.Verdict != string(domain.VerdictNoExploitPathFound) {
				continue
			}
			detWith("exploit", &r.AttackScenario, o.Fact, d.ConditionID, o.Scope, o, d.AssumptionIDs)
		}
	}
	a.detConditions(r)
}

// applicabilityEvidenceRefs returns the shared citation set the
// deterministic applicability conditions fall back on: the resolver's
// own evidence refs, else the affected-resolve observations, else the
// advisory itself.
func (a *assembler) applicabilityEvidenceRefs(r *Report) []string {
	refs := append([]string{}, r.ProductApplicability.EvidenceRefs...)
	if len(refs) == 0 {
		// The resolver observation was absent or failed: conditions
		// still cite the advisory scope they were derived under.
		for _, o := range a.lane.Observations {
			if o.Tool == "affected-resolve" {
				refs = append(refs, "obs:"+o.ID)
			}
		}
		if len(refs) == 0 {
			refs = []string{"advisory"}
		}
	}
	return refs
}

// detConditions derives exploitation_conditions from the deterministic
// applicability result and the lane's recorded checks. Every condition
// either cites an existing verified fact or is recorded as an explicit
// UNKNOWN carrying a follow-up limitation; nothing is invented. Agent
// conditions remain additive (origin=agent) when the agent runs.
func (a *assembler) detConditions(r *Report) {
	pa := r.ProductApplicability
	refs := a.applicabilityEvidenceRefs(r)
	stateFor := func(v string) string {
		switch v {
		case "TRUE":
			return StateSupported
		case "FALSE":
			return StateRefuted
		default:
			return StateUnknown
		}
	}
	mod := "the advisory-affected component"
	if pa.SelectedModule != nil && *pa.SelectedModule != "" {
		mod = *pa.SelectedModule
	}
	add := func(subj, necessity string, claim string, stmt string, lims ...string) {
		r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
			ID: a.nextCondition(), Subject: subj, Scope: "resolved module graph / snapshot build context",
			Necessity: necessity, Statement: stmt, Origin: OriginDeterm,
			State: stateFor(claim), EvidenceRefs: refs, Limitations: lims,
		})
	}
	// Presence chain — the same predicates product_applicability reports.
	switch pa.ModulePresent {
	case "TRUE":
		add(subjModulePresence, "required", "TRUE",
			fmt.Sprintf("the affected component (%s) is present in the resolved module graph", mod))
	case "FALSE":
		add(subjModulePresence, "required", "FALSE",
			fmt.Sprintf("the affected component (%s) is absent from the resolved module graph", mod),
			"a required predicate fails deterministically; no product-side exploit path through this component exists in the snapshot")
	default:
		add(subjModulePresence, "required", pa.ModulePresent,
			fmt.Sprintf("whether the affected component (%s) is present in the resolved module graph is undecided", mod),
			"follow-up: resolve the module graph under the recorded build context (the affected-resolve check did not establish presence)")
	}
	switch pa.VersionAffected {
	case "TRUE":
		add(subjVersionInUse, "required", "TRUE",
			fmt.Sprintf("the deployed product uses %s at a version inside the advisory's affected ranges", mod))
	case "FALSE":
		add(subjVersionInUse, "required", "FALSE",
			fmt.Sprintf("the deployed product uses %s outside the advisory's affected ranges", mod),
			"a required predicate fails deterministically on version evidence")
	default:
		add(subjVersionInUse, "required", pa.VersionAffected,
			fmt.Sprintf("whether %s resolves to a version inside the advisory's affected ranges is undecided", mod),
			"follow-up: pin the effective module version (build info, go.sum, or release evidence) and re-check the affected ranges")
	}
	// A fixed evaluated entry means the package/build probe never ran:
	// the raw field values would map to UNKNOWN anyway, but the statement
	// must name the real reason — the probe was skipped — never
	// "the affected package is absent".
	fixedEntry := pa.AdvisoryEntryStatus == EntryFixed
	switch {
	case pa.PackagePresent == "TRUE" && !fixedEntry:
		add(subjPackageReach, "required", "TRUE",
			"product code reaches the affected package — the vulnerable code path is compiled in")
	case pa.PackagePresent == "FALSE" && !fixedEntry:
		add(subjPackageReach, "required", "FALSE",
			"no product package depends on the affected package; the vulnerable code is not compiled into the product",
			"absence is asserted only for the recorded build context (build tags, GOOS/GOARCH)")
	case fixedEntry:
		add(subjPackageReach, "required", "UNKNOWN",
			fmt.Sprintf("whether product code reaches the affected package was not evaluated: the evaluated advisory entry for %s resolves to fixed version %s, so the package reachability probe did not run", mod, strOr(pa.ResolvedVersion, "?")),
			"package reachability not evaluated — the resolved version is outside the affected ranges of every evaluated entry; a fixed version is not evidence of package absence",
			"follow-up: run module_usage/go list -deps under the recorded build context if package presence must be established independently")
	default:
		add(subjPackageReach, "required", pa.PackagePresent,
			"whether product code reaches the affected package is undecided",
			"follow-up: the advisory names no affected package for this module, or go list coverage was partial; run module_usage/symbol scans under the full build context")
	}
	switch {
	case pa.BuildRelevant == "TRUE" && !fixedEntry:
		add(subjBuildRelevant, "required", "TRUE",
			"the affected package compiles into at least one product deliverable under the recorded build context")
	case pa.BuildRelevant == "FALSE" && !fixedEntry:
		add(subjBuildRelevant, "required", "FALSE",
			"the affected package is excluded from the recorded build context",
			"platform-gated packages are excluded only under the recorded GOOS/GOARCH/tags")
	case fixedEntry:
		add(subjBuildRelevant, "required", "UNKNOWN",
			fmt.Sprintf("whether the affected code is build-relevant was not evaluated: the evaluated advisory entry for %s resolves to fixed version %s, so the build-relevance probe did not run", mod, strOr(pa.ResolvedVersion, "?")),
			"build relevance not evaluated — the resolved version is outside the affected ranges of every evaluated entry",
			"follow-up: run go list -deps -test ./... under the recorded GOOS/GOARCH/tags if build relevance must be established independently")
	default:
		add(subjBuildRelevant, "required", pa.BuildRelevant,
			"whether the affected code is build-relevant under the recorded context is undecided",
			"follow-up: resolve package presence/build relevance (requires go list -deps coverage)")
	}
	a.appendPackageUsageConditions(r)

	// Runtime predicate: always honest UNKNOWN — deployment/runtime
	// posture is out of the lane's scope by contract.
	rtRefs := refs
	var rtObs []string
	for _, o := range a.lane.Observations {
		if o.Tool == "listen-sites" || o.Tool == "dial-sites" || o.Tool == "find_entrypoints" || o.Tool == "ingress-inventory" {
			rtObs = append(rtObs, "obs:"+o.ID)
		}
	}
	if len(rtObs) > 0 {
		rtRefs = rtObs
	}
	r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
		ID: a.nextCondition(), Subject: subjRuntimePosture,
		Scope:     "runtime configuration and deployment environment",
		Necessity: "required",
		Statement: "a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it",
		Origin:    OriginDeterm, State: StateUnknown, EvidenceRefs: rtRefs,
		Limitations: []string{"follow-up: confirm deployment posture (listeners, auth, network exposure, config) against the recorded entry-point facts"},
	})
}

// packageUsageDataOf decodes a package-usage observation payload into
// its typed data. Lane observations carry the decoded map while the
// audit record carries the tool's typed struct; non-struct payloads are
// normalized through the same JSON the persisted artifact uses. ok=false
// means the payload is absent or undecodable — never a verdict either way.
func packageUsageDataOf(o *evidencetools.Observation) (evidencetools.PackageUsageData, bool) {
	if o == nil || o.Data == nil {
		return evidencetools.PackageUsageData{}, false
	}
	if d, ok := o.Data.(evidencetools.PackageUsageData); ok {
		return d, true
	}
	b, err := json.Marshal(o.Data)
	if err != nil {
		return evidencetools.PackageUsageData{}, false
	}
	var d evidencetools.PackageUsageData
	if err := json.Unmarshal(b, &d); err != nil {
		return evidencetools.PackageUsageData{}, false
	}
	return d, true
}

// packageUsageConditionState maps one decoded package-usage verdict to
// the required path condition's state: USED supports the predicate; a
// VERIFIED NOT_USED refutes it inside the recorded scope; every other
// payload — an open gap, a missing declaration, an undecodable shape —
// stays UNKNOWN. The caller still gates REFUTED on the observation's
// final completeness: a degraded negative scope is never a REFUTED.
func packageUsageConditionState(data evidencetools.PackageUsageData) string {
	switch data.Usage {
	case string(goanalysis.PackageUsageUsed):
		return StateSupported
	case string(goanalysis.PackageUsageNotUsed):
		if data.NegativeVerification == string(goanalysis.PackageUsageNegativeVerified) {
			return StateRefuted
		}
	}
	return StateUnknown
}

// appendPackageUsageConditions emits the required path condition
// «affected package/symbol used by product code» — one per sorted
// advisory-declared package/symbol candidate, never collapsed into a
// single boolean and never invented for a module-only advisory. The
// deterministic mapping is: USED → SUPPORTED; NOT_USED + VERIFIED under
// a COMPLETE recorded scope → REFUTED; every other outcome — UNKNOWN,
// ERROR, TIMEOUT, UNSUPPORTED, a missing observation or an undecodable
// payload — stays UNKNOWN and blocking. A SUPPORTED condition closes
// the path predicate for L1 only through its promoted static-carrier
// fact; a REFUTED condition always blocks L1 and is never a safe
// conclusion (it never feeds vulnerable_code_reachability=FALSE —
// only the applicability probe's own absence basis can produce that).
func (a *assembler) appendPackageUsageConditions(r *Report) {
	pa := r.ProductApplicability
	goModules := make(map[string]bool)
	for _, im := range goImplementations(a.lane.Advisory.Impls) {
		if im.Module != "" {
			goModules[im.Module] = true
		}
	}
	if a.lane.Advisory.Vuln == nil {
		return
	}
	candidates := packageUsageCandidates(*a.lane.Advisory.Vuln, goModules)
	if len(candidates) == 0 {
		// Module-only advisory: no package/symbol names a package-level
		// subject, so no condition is emitted and no package path is
		// guessed from the module. Where a bounded check could still
		// change the path conditions, the gap is recorded as a
		// decision-changing unknown instead.
		if len(goModules) > 0 && pa.ModulePresent == "TRUE" && pa.PackagePresent != "FALSE" {
			reason := "no advisory-declared package/symbol: the lane ran no package-usage check and the module path is never substituted for a package"
			if fr := a.lane.Advisory.Input.FeedResolution; fr != nil && fr.Reason != "" {
				// A configured feed declined to supply the missing
				// subjects — the named reason joins the existing UNKNOWN.
				reason += fmt.Sprintf("; advisory feed: %s (status %s)", fr.Reason, fr.Status)
			}
			a.addUnknown(&UnknownEntry{
				Statement: "UNKNOWN: the advisory declares only module + version range; no package or symbol identifies a package-level subject, so package-usage is not decidable",
				Reason:    reason,
				FollowUp:  "obtain a package/symbol-bounded check (a richer advisory record or an explicit package-usage run over the recorded product source scope)",
				Group:     "code_reachability",
				Priority:  UnknownPriorityDecisionChanging,
				DecisionChangingFor: strPtr(
					"the «affected package/symbol used by product code» path condition and evidence_level (a bounded package/symbol check could close or refute it)"),
			})
		}
		return
	}
	// Index the lane's package-usage observations by the candidate they
	// checked: audit records bind through their args (kept even when the
	// observation's own payload is empty or failed); a recordless
	// observation binds through its decoded payload.
	bySubject := map[packageUsageSubject]*evidencetools.Observation{}
	for i := range a.lane.Records {
		rec := &a.lane.Records[i]
		if rec.Tool != evidencetools.PackageUsageTool || rec.Observation == nil {
			continue
		}
		var ar struct {
			Module  string `json:"module"`
			Package string `json:"package"`
			Symbol  string `json:"symbol"`
		}
		if err := json.Unmarshal(rec.Args, &ar); err != nil || ar.Package == "" {
			continue
		}
		k := packageUsageSubject{Module: ar.Module, Package: ar.Package, Symbol: ar.Symbol}
		if _, seen := bySubject[k]; !seen {
			bySubject[k] = rec.Observation
		}
	}
	for _, o := range a.lane.Observations {
		if o == nil || o.Tool != evidencetools.PackageUsageTool {
			continue
		}
		d, ok := packageUsageDataOf(o)
		if !ok || d.Package == "" {
			continue
		}
		k := packageUsageSubject{Module: d.Module, Package: d.Package, Symbol: d.Symbol}
		if _, seen := bySubject[k]; !seen {
			bySubject[k] = o
		}
	}
	mergeLimits := func(ss ...[]string) []string {
		var out []string
		for _, s := range ss {
			out = append(out, s...)
		}
		return dedupe(out)
	}
	for _, cand := range candidates {
		// UsageSubject pins the advisory-declared candidate this
		// condition covers on every outcome — SUPPORTED, REFUTED and
		// UNKNOWN alike — so a cited PACKAGE_USAGE fact can never be
		// read for a different candidate. Copy: cand is the range var.
		subj := cand
		cond := ExploitationCondition{
			ID:           a.nextCondition(),
			Subject:      subjProductPackageUsage,
			Necessity:    "required",
			Origin:       OriginDeterm,
			UsageSubject: &subj,
		}
		target := cand.Package
		if cand.Symbol != "" {
			target += "." + cand.Symbol
		}
		o := bySubject[cand]
		switch {
		case o == nil:
			cond.Scope = "advisory-declared package/symbol candidate under the recorded product source scope"
			cond.State = StateUnknown
			cond.EvidenceRefs = a.applicabilityEvidenceRefs(r)
			cond.Statement = fmt.Sprintf(
				"whether product code uses the advisory-declared subject %s is undecided: the package-usage check produced no observation for it",
				target)
			cond.Limitations = []string{
				"a missing check result is never negative proof",
				"follow-up: run a package/symbol-bounded usage check under the recorded product source scope",
			}
		case o.ToolStatus != evidencetools.StatusOK:
			cond.Scope = o.Scope
			if cond.Scope == "" {
				cond.Scope = "check not completed under the recorded product source scope"
			}
			cond.State = StateUnknown
			cond.EvidenceRefs = []string{"obs:" + o.ID}
			cond.Statement = fmt.Sprintf(
				"whether product code uses %s is undecided: the package-usage check did not produce a result (%s)",
				target, o.ToolStatus)
			cond.Limitations = mergeLimits(o.Limitations, []string{
				"a failed or incomplete check is never negative proof",
				"follow-up: re-run the package-usage check under the recorded product source scope",
			})
		default:
			d, ok := packageUsageDataOf(o)
			if !ok {
				cond.Scope = o.Scope
				cond.State = StateUnknown
				cond.EvidenceRefs = []string{"obs:" + o.ID}
				cond.Statement = fmt.Sprintf(
					"whether product code uses %s is undecided: the package-usage payload is undecodable", target)
				cond.Limitations = mergeLimits(o.Limitations, []string{
					"an undecodable result is never negative proof",
					"follow-up: re-run the package-usage check under the recorded product source scope",
				})
				break
			}
			cond.Scope = d.CheckScope
			if cond.Scope == "" {
				cond.Scope = o.Scope
			}
			cond.EvidenceRefs = factRefs(a.lane, o)
			state := packageUsageConditionState(d)
			switch state {
			case StateSupported:
				cond.State = StateSupported
				if d.Symbol == "" {
					cond.Statement = fmt.Sprintf(
						"package %s is used by product source: %d import site(s), %d reference site(s) in the recorded scope",
						target, len(d.ImportSites), len(d.ProductSites))
				} else {
					cond.Statement = fmt.Sprintf(
						"symbol %s is used by product source: %d reference/call site(s) in the recorded scope",
						target, len(d.ProductSites))
				}
				cond.Limitations = mergeLimits(o.Limitations, d.Limitations)
			case StateRefuted:
				negScope := d.CheckScope
				if negScope == "" {
					negScope = o.Scope
				}
				cond.Limitations = mergeLimits(o.Limitations, d.Limitations, []string{
					"negative verification=VERIFIED: " + negScope,
					"no runtime/reflection/plugin/generated/deployment conclusion",
					"a REFUTED path condition blocks L1 and is not a safe conclusion",
				})
				if o.Completeness == evidencetools.CompletenessComplete {
					cond.State = StateRefuted
					if d.Present {
						cond.Statement = fmt.Sprintf(
							"%s is present in the recorded dependency/build scope, but no product-source use was found in the bounded static scope (%s)",
							target, negScope)
					} else {
						cond.Statement = fmt.Sprintf(
							"%s is provably absent from the complete product import closure, so no product source can use it (negative verification bounded to static analysis: %s)",
							target, negScope)
					}
				} else {
					// The primitive verified the negative, but the
					// recorded scope degraded: an incomplete scope is
					// never negative proof — REFUTED stays out.
					cond.State = StateUnknown
					cond.Statement = fmt.Sprintf(
						"whether product code uses %s is undecided: the VERIFIED negative's recorded scope is not closed (%s)",
						target, o.Completeness)
					cond.Limitations = mergeLimits(cond.Limitations, []string{
						"the negative scope is not closed; a VERIFIED payload under degraded completeness is never negative proof",
						"follow-up: re-run the package-usage check under the full product source scope",
					})
					a.addUnknown(&UnknownEntry{
						Statement: fmt.Sprintf(
							"UNKNOWN: the package-usage negative for %s is bounded only by a degraded scope (%s)", target, o.Completeness),
						Reason:       "VERIFIED negative payload under a non-COMPLETE recorded scope; the check is auditable but is never negative proof",
						FollowUp:     "re-run the package-usage check under the full product source scope (skipped packages or truncated output degraded the recorded scope)",
						EvidenceRefs: []string{"obs:" + o.ID},
						Group:        "code_reachability",
						Priority:     UnknownPriorityDecisionChanging,
						DecisionChangingFor: strPtr(
							"the «affected package/symbol used by product code» path condition and evidence_level (a closed-scope negative would refute it)"),
					})
				}
			default:
				cond.State = StateUnknown
				cond.Statement = fmt.Sprintf(
					"whether product code uses %s is undecided in the recorded scope", target)
				cond.Limitations = mergeLimits(o.Limitations, d.Limitations, []string{
					"an undecided usage check is never negative proof",
					"follow-up: close the recorded scope gaps (build context, skipped packages, dispatch/dynamic material) and re-run the package-usage check",
				})
			}
		}
		r.ExploitationConditions = append(r.ExploitationConditions, cond)
	}
}

func (a *assembler) findObs(tool string) *evidencetools.Observation {
	for _, o := range a.lane.Observations {
		if o.Tool == tool {
			return o
		}
	}
	return nil
}

func factRefs(l *LaneResult, o *evidencetools.Observation) []string {
	if fid := l.FactRef(o.ID); fid != "" {
		return []string{fid}
	}
	return []string{"obs:" + o.ID}
}

func dataHas(o *evidencetools.Observation, key string, want bool) bool {
	m, ok := o.Data.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m[key].(bool)
	return ok && v == want
}

func factCount(o *evidencetools.Observation) int {
	m, ok := o.Data.(map[string]any)
	if !ok {
		return 0
	}
	if c, ok := m["count"].(float64); ok {
		return int(c)
	}
	return 0
}

// ---- agent merge ----

// agentClaims parses the agent's assessment object, converts section
// content into claims + agent_assertions, applies the §7.5 advisory
// binding rule and the §7.6 conflict rule.
func (a *assembler) agentClaims(r *Report, t *AgentTurn) {
	if t.Output.Status != AgentOK || t.Answer == nil {
		return
	}
	ans := t.Answer
	// The classification itself is an assertion; deterministic
	// applicability wins any disagreement.
	classState, classBasis := StateOpen, BasisHypothesis
	conflict := classificationConflict(ans.Category, r.ProductApplicability)
	if conflict != "" {
		classState = StateConflicted
		classBasis = BasisContradicted
		a.conflicts = append(a.conflicts, conflict)
	}
	classID := a.nextAssertion()
	a.classAssertID = classID
	a.agentSrcRefs = append(a.agentSrcRefs, "agent-src:final-answer")
	r.AgentAssertions = append(r.AgentAssertions, AgentAssertion{
		ID: classID, Subject: r.Vulnerability.ID,
		Scope:     "final classification",
		Statement: "category=" + ans.Category + ": " + firstN(ans.Reasoning, 800),
		State:     classState, Basis: classBasis,
		EvidenceRefs:   []string{classID},
		Limitations:    conflictLim(conflict),
		OriginalText:   "category=" + ans.Category + ": " + ans.Reasoning,
		SourceSelector: "$.category + $.reasoning",
	})
	var asm agentAssessment
	if len(ans.Assessment) > 0 {
		_ = json.Unmarshal(ans.Assessment, &asm)
	}
	type secDef struct {
		name string
		raw  json.RawMessage
		sec  *Section
		bind bool // mechanism/root-cause claims need advisory binding
	}
	defs := []secDef{
		{"mechanism", asm.VulnerabilityMechanism, &r.VulnerabilityMechanism, true},
		{"rootcause", asm.RootCause, &r.RootCause, true},
		{"attack", asm.AttackScenario, &r.AttackScenario, false},
		{"exposure", asm.ProductExposure, &r.ProductExposure, false},
		{"altpaths", asm.AlternativePaths, &r.AlternativePaths, false},
	}
	for _, d := range defs {
		a.mergeAgentSection(r, d.name, d.raw, d.sec, d.bind)
	}
	// Attack-scenario claims double as exploitation conditions
	// (slice2-fidelity/3): a claim whose subject canonicalizes into a
	// required path predicate is normalized to the canonical subject and
	// marked required — it still stays an OPEN hypothesis that blocks
	// L1 — while every other agent claim lands as supporting material
	// (slice2ConditionRoles assigns the roles below). No verified fact
	// is ever created from an agent condition.
	for _, c := range r.AttackScenario.Claims {
		if c.Origin != OriginAgent {
			continue
		}
		necessity := "unknown"
		subject := c.Subject
		if canonical := canonicalPathSubject(subject); canonical != "" {
			subject = canonical
			necessity = "required"
		}
		r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
			ID: a.nextCondition(), Subject: subject, Scope: c.Scope,
			Necessity: necessity, Origin: OriginAgent, State: StateOpen,
			Statement:    c.Statement,
			EvidenceRefs: c.EvidenceRefs, Limitations: c.Limitations,
		})
	}
	a.mergeEvidenceQuality(r, asm.EvidenceQuality)
	a.agentQuestions = append(a.agentQuestions, parseRawList(asm.ResidualQuestions)...)
	a.agentTriage = parseRawObject(asm.TriageRecommendation)
	a.advisoryScopeGap(r, string(t.AnswerJSON))
}

// advisoryScopeGap scans the retained agent answer for module-path-like
// tokens that are (a) not covered by the advisory's affected modules and
// (b) genuinely "outside the advisory" — i.e. resolved dependency modules
// of this snapshot (module-graph observation, vendor/modules.txt or
// go.sum). The product's own module and its subpackages, plain file
// names, and tokens that are not resolved dependencies can never be an
// outside-advisory component: the product module names the product
// itself, and a non-dependency token is free text, not a component.
// Real dependency gaps record an explicit unknown plus mechanism/
// root_cause limitations and feed the advisory_scope_gap contradictions;
// non-dependency tokens are recorded only as informational appendix
// unknowns so the audit trail keeps the agent's own words without
// promoting them to decision-changing questions.
func (a *assembler) advisoryScopeGap(r *Report, text string) {
	mods := goModuleCandidates(text, a.lane.SnapshotRoot)
	a.loadModuleSets()
	var named []string
	for _, m := range mods {
		if a.componentBound(m) {
			continue
		}
		// The product's own module names the product itself, not an
		// outside component.
		if a.ownModule != "" && (m == a.ownModule || strings.HasPrefix(m, a.ownModule+"/")) {
			continue
		}
		if !a.isResolvedDep(m) {
			// Free-text mention of a non-dependency (Kubernetes API/type
			// strings, doc paths, vendor-style prose): appendix note only.
			a.addUnknown(&UnknownEntry{
				Statement: fmt.Sprintf("UNKNOWN: token %s named by the agent is not a resolved dependency module of the snapshot", m),
				Reason:    "agent-named token is not a resolved dependency module",
				FollowUp:  "no action needed: the token does not name a product dependency, so it cannot be an advisory scope gap",
				Group:     "advisory_scope",
				Priority:  UnknownPriorityAppendix,
			})
			continue
		}
		named = append(named, m)
	}
	if len(named) == 0 {
		return
	}
	sort.Strings(named)
	// Collapse parent/child tokens: one unknown per unbound module root
	// suffices (go.etcd.io/etcd covers go.etcd.io/etcd/server).
	kept := named[:0]
	for _, m := range named {
		child := false
		for _, k := range kept {
			if strings.HasPrefix(m, k+"/") {
				child = true
				break
			}
		}
		if !child {
			kept = append(kept, m)
		}
	}
	named = kept
	a.scopeGapModules = append(a.scopeGapModules, named...)
	for _, m := range named {
		a.addUnknown(&UnknownEntry{
			Statement: fmt.Sprintf("UNKNOWN: component %s is named by the agent but is not in the advisory affected entries", m),
			Reason:    "advisory scope gap: the frozen advisory does not name this dependency module; a local fixed-version fact for a covered component cannot be extended to it",
			FollowUp:  "verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion",
		})
	}
	note := fmt.Sprintf("agent-named component(s) outside the advisory scope: %s — conclusions remain bounded to the advisory's affected entries", strings.Join(named, ", "))
	r.VulnerabilityMechanism.Limitations = append(r.VulnerabilityMechanism.Limitations, note)
	r.RootCause.Limitations = append(r.RootCause.Limitations, note)
	// Advisory-scope limitation: a single-module advisory plus agent-named
	// alternative implementations of the mechanism.
	goModules := 0
	for _, im := range a.lane.Advisory.Impls {
		if im.Ecosystem == "Go" {
			goModules++
		}
	}
	if goModules == 1 {
		r.EvidenceQuality.Limitations = append(r.EvidenceQuality.Limitations,
			fmt.Sprintf("the frozen advisory names exactly one Go module while the agent's answer names other dependency module(s) of the same mechanism (%s); the advisory's completeness for this CVE is unverified", strings.Join(named, ", ")))
	}
}

// loadModuleSets resolves the product's own module (root go.mod `module`
// directive) and the snapshot's resolved dependency module set — the
// union of the get_dependency_graph observation's module list,
// vendor/modules.txt headers and go.sum entries (each go.sum line is
// module-path/version, covering modules fetched but not listed in
// modules.txt).
func (a *assembler) loadModuleSets() {
	if a.modSetLoaded {
		return
	}
	a.modSetLoaded = true
	a.depModules = map[string]bool{}
	// Prefer the module list captured at call time — the observation
	// payload itself may have been truncated by the payload cap.
	for _, p := range a.lane.GraphModules {
		a.depModules[p] = true
	}
	for _, o := range a.lane.Observations {
		if o.Tool != "get_dependency_graph" || o.Data == nil {
			continue
		}
		data, ok := o.Data.(map[string]any)
		if !ok {
			continue
		}
		if mods, ok := data["modules"].([]any); ok {
			for _, mv := range mods {
				if mm, ok := mv.(map[string]any); ok {
					if p, ok := mm["path"].(string); ok && p != "" {
						a.depModules[p] = true
					}
				}
			}
		}
	}
	root := a.lane.SnapshotRoot
	if root == "" {
		return
	}
	if body, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module") {
				a.ownModule = strings.TrimSpace(strings.TrimPrefix(line, "module"))
				break
			}
		}
	}
	if body, err := os.ReadFile(filepath.Join(root, "vendor", "modules.txt")); err == nil {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "# ") {
				if fields := strings.Fields(line[2:]); len(fields) > 0 && fields[0] != "" {
					a.depModules[fields[0]] = true
				}
			}
		}
	}
	if body, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
		for _, line := range strings.Split(string(body), "\n") {
			if fields := strings.Fields(line); len(fields) >= 1 && strings.Contains(fields[0], "/") {
				a.depModules[fields[0]] = true
			}
		}
	}
}

// isResolvedDep reports whether token names a resolved dependency module:
// an exact graph entry, a package path under one (dep + "/"), or a module
// path that is a strict prefix of a recorded dependency (go.etcd.io/etcd
// covers go.etcd.io/etcd/server/v3).
func (a *assembler) isResolvedDep(token string) bool {
	if a.depModules[token] {
		return true
	}
	for d := range a.depModules {
		if strings.HasPrefix(token, d+"/") || strings.HasPrefix(d, token+"/") {
			return true
		}
	}
	return false
}

// mergeAgentSection normalizes one agent section member (string or
// object) into the report section, applying binding for mechanism/root
// cause.
func (a *assembler) mergeAgentSection(r *Report, name string, raw json.RawMessage, sec *Section, bind bool) {
	if len(raw) == 0 {
		return
	}
	fields, str := parseSectionRaw(raw)
	if str != "" {
		fields["summary"] = str
	}
	summary, _ := fields["summary"].(string)
	if summary != "" {
		a.agentSummary[secKey(sec, r)] = summary
	}
	var rawClaims []any
	if arr, ok := fields["claims"].([]any); ok {
		rawClaims = arr
	}
	// An object section without claims: keep its narrative as one claim.
	if len(rawClaims) == 0 {
		if txt, ok := fields["text"].(string); ok && txt != "" {
			rawClaims = append(rawClaims, txt)
		} else if summary != "" && !strings.HasPrefix(strings.TrimSpace(summary), "UNKNOWN") {
			rawClaims = append(rawClaims, summary)
		}
	}
	for i, rc := range rawClaims {
		sel := fmt.Sprintf("$.assessment.%s.claims[%d]", memberName(name), i)
		if _, isStr := rc.(string); isStr {
			sel = fmt.Sprintf("$.assessment.%s", memberName(name))
		}
		cl := a.agentClaim(r, name, rc, bind, sel)
		if cl != nil {
			sec.Claims = append(sec.Claims, *cl)
		}
	}
}

// memberName maps the internal section key to the JSON member name in
// the agent's assessment object (for source selectors).
func memberName(sec string) string {
	switch sec {
	case "mechanism":
		return "vulnerability_mechanism"
	case "rootcause":
		return "root_cause"
	case "attack":
		return "attack_scenario"
	case "exposure":
		return "product_exposure"
	case "altpaths":
		return "alternative_paths"
	default:
		return sec
	}
}

// agentClaim converts one raw agent claim into the contract shape,
// creating the matching agent_assertions entry. sel is the source
// selector of the claim inside the retained answer.
func (a *assembler) agentClaim(r *Report, sec string, raw any, bind bool, sel string) *Claim {
	var statement, subject, scope string
	var refs []string
	switch v := raw.(type) {
	case string:
		statement = v
	case map[string]any:
		statement = strField(v, "statement", "text", "claim")
		subject = strField(v, "subject", "component", "target")
		scope = strField(v, "scope", "context")
		refs = strList(v["evidence_refs"], v["refs"], v["sources"])
	default:
		return nil
	}
	if strings.TrimSpace(statement) == "" {
		return nil
	}
	if scope == "" {
		scope = "agent assessment (snapshot-read scope as stated)"
	}
	state, basis := StateOpen, BasisHypothesis
	var lims []string
	// Agent-cited sources never enter evidence_refs (they are not
	// deterministic refs); they are recorded in a.agentSrcRefs and land
	// in the evidence_quality agent-source index pinned to the retained
	// answer. The claim/assertion's evidence_refs point at the paired
	// agent assertion instead.
	a.agentSrcRefs = append(a.agentSrcRefs, "agent-src:assessment."+sec)
	for _, ref := range refs {
		if !strings.HasPrefix(ref, "agent-src:") {
			ref = "agent-src:" + ref
		}
		a.agentSrcRefs = append(a.agentSrcRefs, ref)
	}
	assertID := a.nextAssertion()
	refs = []string{assertID}
	if bind {
		bound, candidates := a.bindClaim(subject, statement)
		switch {
		case bound:
			basis = BasisSupported
		case len(candidates) == 0:
			// No named component — stays a hypothesis.
		default:
			state = StateUnknown
			basis = BasisUnknown
			note := fmt.Sprintf("component(s) %s not named by any advisory affected entry — retained as UNKNOWN per binding rule", strings.Join(candidates, ", "))
			lims = append(lims, note)
			a.addUnknown(&UnknownEntry{
				Statement:    "UNKNOWN: " + note,
				Reason:       "advisory-entry binding failed for an agent " + sec + " claim",
				FollowUp:     "verify whether the frozen advisory omits this component; if so, provision the advisory that names it before treating the claim",
				EvidenceRefs: refs,
			})
		}
	}
	r.AgentAssertions = append(r.AgentAssertions, AgentAssertion{
		ID: assertID, Statement: statement, Subject: subject, Scope: scope,
		State: state, Basis: basis, EvidenceRefs: refs, Limitations: lims,
		OriginalText: statement, SourceSelector: sel,
	})
	return &Claim{
		ID: a.nextAgtClaim(sec), Statement: statement, Subject: subject,
		Scope: scope, State: state, EvidenceRefs: refs,
		Limitations: lims, Origin: OriginAgent,
	}
}

// bindClaim implements §7.5: a claim's named components must match an
// advisory affected entry (module/package/symbol) to be bound.
func (a *assembler) bindClaim(subject, statement string) (bool, []string) {
	var candidates []string
	if subject != "" {
		candidates = append(candidates, subject)
	}
	candidates = append(candidates, componentCandidates(statement)...)
	if len(candidates) == 0 {
		return false, nil
	}
	var unbound []string
	for _, c := range dedupe(candidates) {
		if a.componentBound(c) {
			return true, nil
		}
		unbound = append(unbound, c)
	}
	return false, unbound
}

// modulePathRe matches module-path-like tokens (path segments with a
// dot in the first segment — domain-ish, or well-known go paths) and
// `pkg.Symbol`-like tokens for symbol binding.
var modulePathRe = regexp.MustCompile(`[A-Za-z0-9_.~-]+\.[A-Za-z0-9_.~-]+/[A-Za-z0-9_./~\-]+`)

func componentCandidates(s string) []string {
	return dedupe(modulePathRe.FindAllString(s, -1))
}

func (a *assembler) componentBound(c string) bool {
	if a.bindSet[c] {
		return true
	}
	// A candidate under an advisory module/package path binds (e.g.
	// golang.org/x/net/http2 under golang.org/x/net).
	for b := range a.bindSet {
		if strings.HasPrefix(c, b+"/") || strings.HasPrefix(c, b+".") {
			return true
		}
	}
	return false
}

func (a *assembler) mergeEvidenceQuality(r *Report, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	fields, str := parseSectionRaw(raw)
	if str != "" {
		fields["summary"] = str
	}
	if s, ok := fields["summary"].(string); ok {
		a.agentSummary["evidence_quality"] = s
	}
	if refs, ok := fields["references"].([]any); ok {
		for _, rv := range refs {
			switch v := rv.(type) {
			case string:
				a.agentSrcRefs = append(a.agentSrcRefs, "agent-src:"+v)
				r.EvidenceQuality.References = append(r.EvidenceQuality.References,
					EvidenceReference{Ref: "agent-src:" + v, Kind: "agent-source", Path: v, Selector: "agent-stated"})
			case map[string]any:
				path := strField(v, "path", "file", "source")
				sel := strField(v, "selector", "lines", "symbol")
				ref := "agent-src:" + path
				a.agentSrcRefs = append(a.agentSrcRefs, ref)
				r.EvidenceQuality.References = append(r.EvidenceQuality.References,
					EvidenceReference{Ref: ref, Kind: "agent-source", Path: path, Selector: sel})
			}
		}
	}
}

// classificationConflict implements §7.6: deterministic product facts win.
func classificationConflict(category string, pa ProductApplicability) string {
	switch category {
	case "vulnerable":
		if pa.ModulePresent == "FALSE" || pa.VersionAffected == "FALSE" || pa.PackagePresent == "FALSE" {
			return fmt.Sprintf("agent classified %q but deterministic applicability is module_present=%s version_affected=%s package_present=%s — the deterministic result prevails for product fields",
				category, pa.ModulePresent, pa.VersionAffected, pa.PackagePresent)
		}
	case "code_not_present", "false_positive", "code_not_reachable":
		if pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE" && pa.PackagePresent == "TRUE" {
			return fmt.Sprintf("agent classified %q but the deterministic chain resolved an affected component (module_present=TRUE, version_affected=TRUE, package_present=TRUE) — the claim remains attributed, never promoted",
				category)
		}
	}
	return ""
}

func conflictLim(conflict string) []string {
	if conflict == "" {
		return nil
	}
	return []string{conflict}
}

// ---- sections / unknowns / questions ----

func (a *assembler) sections(r *Report, t *AgentTurn) {
	// Deterministic default: everything the agent would answer stays
	// UNKNOWN with a concrete follow-up when no claim exists.
	agentRan := t != nil && t.Output.Status == AgentOK
	set := func(sec *Section, unknownWhat, followUp string) {
		if len(sec.Claims) == 0 {
			sec.Status = StatusUnknown
			if !isUnknownSummary(sec.Summary) {
				sec.Summary = unknownSummary(unknownWhat, followUp)
			}
		} else {
			// Claims exist but none establish the section's question
			// conclusively — PARTIAL is the honest ceiling here.
			sec.Status = StatusPartial
			if sec.Summary == "" {
				sec.Summary = fmt.Sprintf("%d claim(s) recorded; section remains bounded — see claims and limitations", len(sec.Claims))
			}
		}
	}
	if s := a.agentSummary["mechanism"]; s != "" {
		r.VulnerabilityMechanism.Summary = s
	}
	set(&r.VulnerabilityMechanism,
		"the defect mechanism is not established by deterministic facts"+agentSuffix(agentRan),
		"inspect the advisory-named symbols' declarations (observations above) and confirm the defect shape in the bound component's source")
	if s := a.agentSummary["rootcause"]; s != "" {
		r.RootCause.Summary = s
	}
	set(&r.RootCause,
		"the precise defect location is not established"+agentSuffix(agentRan),
		"read the bound component source at the declaration sites in the verified facts")
	if s := a.agentSummary["attack"]; s != "" {
		r.AttackScenario.Summary = s
	}
	set(&r.AttackScenario,
		"no attacker path is established"+agentSuffix(agentRan),
		"trace each recorded inbound listener/dial site to the affected component or mark the predicate open")
	if s := a.agentSummary["exposure"]; s != "" {
		r.ProductExposure.Summary = s
	}
	set(&r.ProductExposure,
		"product use of the affected component is not established"+agentSuffix(agentRan),
		"review the module_usage/call-site facts above against deployment intent")
	if s := a.agentSummary["altpaths"]; s != "" {
		r.AlternativePaths.Summary = s
	}
	set(&r.AlternativePaths,
		"alternative paths were not fully explored (bounded scans only)"+agentSuffix(agentRan),
		"extend gated/dynamic/dispatch scans or accept the stated bound explicitly")

	// evidence_quality: computed evidence base + limitations/conflicts.
	eq := &r.EvidenceQuality
	eq.Status = StatusSupported
	var covered, failed int
	for _, o := range a.lane.Observations {
		if o.ToolStatus == evidencetools.StatusOK {
			covered++
			eq.Coverage = append(eq.Coverage, fmt.Sprintf("%s: %s", o.Tool, o.Scope))
		} else {
			failed++
			eq.Limitations = append(eq.Limitations,
				fmt.Sprintf("%s %s: %s", o.Tool, o.ToolStatus, o.Error))
		}
	}
	eq.Conflicts = a.conflicts
	eq.Summary = fmt.Sprintf("evidence base: %d deterministic check(s) OK, %d non-OK; evidence is scope-bounded per each observation's scope/limitations", covered, failed)
	if s := a.agentSummary["evidence_quality"]; s != "" && agentRan {
		eq.Summary += "; agent stated: " + s
	}
	for _, o := range a.lane.Observations {
		if art, ok := a.lane.ArtifactByObs[o.ID]; ok {
			kind := "observation"
			eq.References = append(eq.References, EvidenceReference{
				Ref: "obs:" + o.ID, Kind: kind, Path: art.Path, Selector: "observation", SHA256: art.SHA256,
			})
		}
	}
	eq.References = append(eq.References, EvidenceReference{
		Ref: "adv:" + a.lane.Advisory.Input.ResolvedID, Kind: "advisory",
		Path: a.lane.Advisory.Input.SourcePath, Selector: "frozen document",
		SHA256: a.lane.Advisory.Input.RawSHA256,
	})
	sort.SliceStable(eq.References, func(i, j int) bool { return eq.References[i].Ref < eq.References[j].Ref })
	for _, lim := range a.lane.Affected.Limitations {
		eq.Limitations = append(eq.Limitations, "applicability: "+lim)
	}
}

// implementationLocusProposals projects the agent's admitted
// implementation-locus hypotheses into their own non-authoritative report
// member. A proposal whose shape, advisory reference or advisory quote does
// not bind to the frozen advisory is rejected with a named limitation and
// never enters the report; nothing here performs a source lookup.
func (a *assembler) implementationLocusProposals(r *Report, t *AgentTurn) {
	if t == nil || t.Answer == nil || t.Output.Status != AgentOK {
		return
	}
	for _, lim := range t.Answer.proposalLimitations {
		r.EvidenceQuality.Limitations = append(r.EvidenceQuality.Limitations,
			"implementation locus proposal rejected: "+lim)
	}
	for _, p := range t.Answer.ImplementationLocusProposals {
		if err := AdmitImplementationLocusProposal(p, &a.lane.Advisory); err != nil {
			r.EvidenceQuality.Limitations = append(r.EvidenceQuality.Limitations,
				fmt.Sprintf("implementation locus proposal %q rejected: %v", p.ID, err))
			continue
		}
		r.ImplementationLocusProposals = append(r.ImplementationLocusProposals, p)
	}
}

// exploitLocusProposals projects the agent's admitted exploit-locus
// hypotheses into their own non-authoritative report member, applying the
// same advisory-reference and verbatim-quote gate as the intake channel.
// Nothing here performs a source lookup.
func (a *assembler) exploitLocusProposals(r *Report, t *AgentTurn) {
	if t == nil || t.Answer == nil || t.Output.Status != AgentOK {
		return
	}
	for _, p := range t.Answer.ExploitLocusProposals {
		if err := AdmitExploitLocusProposal(p, &a.lane.Advisory); err != nil {
			r.EvidenceQuality.Limitations = append(r.EvidenceQuality.Limitations,
				fmt.Sprintf("exploit locus proposal %q rejected: %v", p.ID, err))
			continue
		}
		r.ExploitLocusProposals = append(r.ExploitLocusProposals, p)
	}
}

// emitAgentSourceIndex records every agent-src: ref used anywhere in the
// report as an evidence_quality.references row pinned to the retained raw
// answer artifact (path + sha256). §9 check 7: an agent-src ref resolves
// only through this index.
func (a *assembler) emitAgentSourceIndex(r *Report) {
	raw := r.AgentOutput.RawArtifact
	rawPath, rawSHA := "", ""
	if raw.Path != nil {
		rawPath = *raw.Path
	}
	if raw.SHA256 != nil {
		rawSHA = *raw.SHA256
	}
	// Index rows are emitted even without a retained artifact: the
	// agent-src citation (e.g. agent-src:attempt on a failed turn) stays
	// recorded and resolvable; an empty path+sha256 honestly means the
	// answer bytes were never produced.
	used := []string{}
	have := map[string]bool{}
	add := func(refs []string) {
		for _, ref := range refs {
			if strings.HasPrefix(ref, "agent-src:") && !have[ref] {
				have[ref] = true
				used = append(used, ref)
			}
		}
	}
	for _, as := range r.AgentAssertions {
		add(as.EvidenceRefs)
	}
	for _, c := range r.ExploitationConditions {
		add(c.EvidenceRefs)
	}
	for _, sec := range []*Section{
		&r.VulnerabilityMechanism, &r.RootCause, &r.AttackScenario,
		&r.ProductExposure, &r.AlternativePaths,
	} {
		for _, c := range sec.Claims {
			add(c.EvidenceRefs)
		}
	}
	for _, u := range r.Unknowns {
		add(u.EvidenceRefs)
	}
	for _, q := range r.OpenQuestions {
		add(q.EvidenceRefs)
	}
	for _, q := range r.ResidualQuestions {
		add(q.EvidenceRefs)
	}
	add(r.TriageRecommendation.EvidenceRefs)
	for _, rec := range r.Recommendations {
		add(rec.EvidenceRefs)
	}
	add(a.agentSrcRefs)
	for _, e := range r.EvidenceQuality.References {
		if e.Kind == "agent-source" {
			add([]string{e.Ref})
		}
	}
	// Existing agent-source rows get the retained-answer pin; refs never
	// seen become new rows.
	present := map[string]bool{}
	for i := range r.EvidenceQuality.References {
		e := &r.EvidenceQuality.References[i]
		if e.Kind != "agent-source" {
			continue
		}
		present[e.Ref] = true
		e.Path = rawPath
		e.SHA256 = rawSHA
		if e.Selector == "" {
			e.Selector = "agent-stated"
		}
	}
	for _, ref := range used {
		if !present[ref] {
			r.EvidenceQuality.References = append(r.EvidenceQuality.References,
				EvidenceReference{Ref: ref, Kind: "agent-source",
					Path: rawPath, Selector: "retained final answer", SHA256: rawSHA})
		}
	}
	sort.SliceStable(r.EvidenceQuality.References,
		func(i, j int) bool { return r.EvidenceQuality.References[i].Ref < r.EvidenceQuality.References[j].Ref })
}

func agentSuffix(ran bool) string {
	if ran {
		return ""
	}
	return " (no successful agent assessment)"
}

func (a *assembler) addUnknown(u *UnknownEntry) {
	if u.ID == "" {
		u.ID = a.nextUnknown()
	}
	a.pendingUnknowns = append(a.pendingUnknowns, *u)
}

func (a *assembler) unknowns(r *Report, t *AgentTurn) {
	for _, o := range a.lane.Observations {
		// OK but open-ended with no recorded finding: the result is not
		// a fact (empty in an unbounded scope ≠ absence), so it is
		// recorded as an unknown with a follow-up naming the check.
		if o.ToolStatus == evidencetools.StatusOK {
			if o.Completeness == evidencetools.CompletenessUnknown && a.lane.FactRef(o.ID) == "" {
				a.addUnknown(&UnknownEntry{
					Statement:    fmt.Sprintf("UNKNOWN: %s did not establish bounded coverage — %s", o.Tool, firstN(o.Fact, 200)),
					Reason:       firstN(strings.Join(o.Limitations, "; "), 400),
					FollowUp:     fmt.Sprintf("rerun %s with a bounded scope or treat the result as unresolved; an open enumeration is never an absence proof", o.Tool),
					EvidenceRefs: []string{"obs:" + o.ID},
				})
			}
			continue
		}
		a.addUnknown(&UnknownEntry{
			Statement:    fmt.Sprintf("UNKNOWN: %s check did not produce a result (%s)", o.Tool, o.ToolStatus),
			Reason:       firstN(o.Error, 300),
			FollowUp:     "rerun or scope-down the check; its status is " + string(o.ToolStatus) + ", never an absence proof",
			EvidenceRefs: []string{"obs:" + o.ID},
		})
	}
	// Advisory entries without usable Go shape.
	for _, im := range a.lane.Advisory.Impls {
		if im.Binding == BindIncomplete {
			a.addUnknown(&UnknownEntry{
				Statement:    fmt.Sprintf("UNKNOWN: advisory entry %s (%s/%s) has no usable Go package or SEMVER range", im.ID, im.Ecosystem, im.Module),
				Reason:       "entry shape is incomplete; nothing deterministic can be claimed for it",
				FollowUp:     "provision a richer advisory record or treat this entry's applicability as unresolved",
				EvidenceRefs: []string{im.SourceRef},
			})
		}
	}
	s := a.lane.Snapshot
	if s.ReleaseGoVersion == "" {
		a.addUnknown(&UnknownEntry{
			Statement: "UNKNOWN: the release toolchain version is not pinned by snapshot-local evidence",
			Reason:    "no binary build info or static version pin found; go.mod is a minimum, not the release version",
			FollowUp:  "supply --release-go-version evidence or a release binary to re-resolve stdlib/toolchain applicability",
		})
	}
	for _, pm := range a.lane.Affected.UnresolvedModules {
		a.addUnknown(&UnknownEntry{
			Statement: fmt.Sprintf("UNKNOWN: resolved version of module %s is undecidable", pm),
			Reason:    "module present but its effective version could not be resolved",
			FollowUp:  "pin the module version (vendor manifest or explicit version evidence)",
		})
	}
	if t != nil && t.Output.Status != AgentOK {
		a.agentSrcRefs = append(a.agentSrcRefs, "agent-src:attempt")
		a.addUnknown(&UnknownEntry{
			Statement:    fmt.Sprintf("UNKNOWN: agent assessment did not complete (%s)", t.Output.Status),
			Reason:       firstN(t.Err, 400),
			FollowUp:     "re-run the single attempt after resolving the recorded harness/model precondition",
			EvidenceRefs: nil,
		})
	}
	r.Unknowns = append(r.Unknowns, a.pendingUnknowns...)
	if len(r.Unknowns) == 0 {
		r.Unknowns = append(r.Unknowns, UnknownEntry{
			ID:        a.nextUnknown(),
			Statement: "UNKNOWN: residual correctness of this report is not established — deterministic scope bounds and any agent hypotheses still need human verification",
			Reason:    "the contract requires an explicit unknown set; none was generated by checks, so the residual review duty is recorded",
			FollowUp:  "human review of every claim against the cited artifacts",
		})
	}
}

func (a *assembler) questions(r *Report, t *AgentTurn) {
	// open_questions mirrors the unknowns (research model) and the
	// agent's residual_questions; IDs are one-to-one with
	// residual_questions.
	type q struct {
		question, subject, scope, next, why string
		refs                                []string
	}
	// Derived deployment/config questions sit first: when the only
	// unresolved layer is runtime/deployment posture, the specific ask
	// the environment must answer precedes the mirrored unknown rows —
	// that ordering is the whole point of surfacing it.
	var qs []q
	a.envDerived = a.envQuestions(r)
	for _, dq := range a.envDerived {
		qs = append(qs, q{
			question: dq,
			subject:  subjRuntimePosture,
			scope:    "deployed environment / runtime configuration",
			next:     "confirm the deployment/config surface the recorded statement names — source of the affected input/parameters and who controls them (operator or attacker)",
			why:      "the only open layer is runtime/deployment posture, which static source evidence cannot decide; the question names the recorded condition to confirm",
			refs:     []string{a.advisoryRef()},
		})
	}
	if len(a.agentQuestions) > 0 {
		a.agentSrcRefs = append(a.agentSrcRefs, "agent-src:residual_questions")
	}
	for _, u := range r.Unknowns {
		qs = append(qs, q{
			question: strings.TrimPrefix(u.Statement, "UNKNOWN: "),
			subject:  u.ID, scope: "report scope",
			next: u.FollowUp, refs: u.EvidenceRefs,
		})
	}
	for _, rq := range a.agentQuestions {
		if m, ok := rq.(map[string]any); ok {
			qs = append(qs, q{
				question: strField(m, "question", "q"),
				subject:  strField(m, "subject", "component"),
				scope:    strField(m, "scope", "context"),
				next:     strField(m, "next_check", "follow_up", "action"),
			})
		} else if s, ok := rq.(string); ok && s != "" {
			qs = append(qs, q{question: s, scope: "agent assessment",
				next: "agent-stated follow-up"})
		}
	}
	if len(qs) == 0 {
		qs = append(qs, q{question: "no open questions were generated; is any claim load-bearing for triage without further checks?",
			scope: "report scope", next: "human review"})
	}
	for _, qq := range qs {
		id := a.nextQuestion()
		r.OpenQuestions = append(r.OpenQuestions, OpenQuestion{
			ID: id, Question: qq.question, Subject: qq.subject, Scope: qq.scope,
			NextCheck: qq.next, EvidenceRefs: qq.refs,
		})
		r.ResidualQuestions = append(r.ResidualQuestions, ResidualQuestion{
			ID: id, Question: qq.question,
			Why:       orDefault(qq.why, "left unresolved by the lanes' stated scope"),
			NextCheck: qq.next, EvidenceRefs: qq.refs,
		})
	}
}

func (a *assembler) triage(r *Report, t *AgentTurn) {
	action, reason, bounds := "needs review",
		"the research contract forbids authoritative dispositions; a human must adjudicate the recorded claims and unknowns",
		"all findings are scoped to the snapshot tree and the stated build context; no runtime, delivery or deployment claim is made"
	if len(a.envDerived) > 0 {
		// The only open layer is deployment posture and a recorded
		// statement names the specific ask — the reason carries it so a
		// reviewer sees the real question, not just "needs review".
		reason = "the only unresolved layer is runtime/deployment posture; answer the derived environment question(s): " +
			strings.Join(a.envDerived, " | ")
	}
	if f, ok := a.agentTriage["action"].(string); ok && f != "" {
		switch f {
		case "fix", "verify", "low confirmed risk", "needs review":
			action = f
		}
		if s, ok2 := a.agentTriage["reason"].(string); ok2 && s != "" {
			reason = "agent-stated: " + s
		}
		if s, ok2 := a.agentTriage["bounds"].(string); ok2 && s != "" {
			bounds = "agent-stated: " + s
		}
	}
	r.TriageRecommendation = TriageRecommendation{
		Action: action, Reason: reason, Bounds: bounds,
		EvidenceRefs: []string{"adv:" + a.lane.Advisory.Input.ResolvedID},
	}
}

func (a *assembler) recommendations(r *Report, t *AgentTurn) {
	r.Recommendations = append(r.Recommendations, Recommendation{
		ID: a.nextRec(), Owner: "human",
		Action: "review every verified_fact against its persisted artifact, then adjudicate agent assertions and unknowns",
		Reason: "disposition is review-required by contract",
	})
	if t == nil || t.Output.Status != AgentOK {
		r.Recommendations = append(r.Recommendations, Recommendation{
			ID: a.nextRec(), Owner: "operator",
			Action: "obtain an agent assessment (or a manual one) for the UNKNOWN sections before triage",
			Reason: "deterministic facts alone cannot resolve mechanism/root cause/exploit path",
		})
	}
	if len(a.conflicts) > 0 {
		r.Recommendations = append(r.Recommendations, Recommendation{
			ID: a.nextRec(), Owner: "human",
			Action: "adjudicate recorded agent/deterministic conflicts",
			Reason: strings.Join(a.conflicts, "; "),
		})
	}
}

// orDefault returns s when non-empty, else fallback.
func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// helpers shared with the parser bits of the assembler.
func secKey(sec *Section, r *Report) string {
	switch sec {
	case &r.VulnerabilityMechanism:
		return "mechanism"
	case &r.RootCause:
		return "rootcause"
	case &r.AttackScenario:
		return "attack"
	case &r.ProductExposure:
		return "exposure"
	case &r.AlternativePaths:
		return "altpaths"
	default:
		return "section"
	}
}

// parseSectionRaw accepts a JSON string or object section member.
func parseSectionRaw(raw json.RawMessage) (map[string]any, string) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return map[string]any{}, s
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{}, ""
	}
	return m, ""
}

func parseRawList(raw json.RawMessage) []any {
	if len(raw) == 0 {
		return nil
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return []any{s}
		}
		return nil
	}
	return arr
}

func parseRawObject(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return map[string]any{"action": s}
		}
		return nil
	}
	return m
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func strList(vs ...any) []string {
	var out []string
	for _, v := range vs {
		if arr, ok := v.([]any); ok {
			for _, it := range arr {
				if s, ok := it.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func firstN(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
