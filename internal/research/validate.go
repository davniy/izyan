package research

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// ValidationError is a fail-closed contract violation list.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("research report contract violations (%d):\n - %s",
		len(e.Problems), strings.Join(e.Problems, "\n - "))
}

func (e *ValidationError) add(format string, args ...any) {
	e.Problems = append(e.Problems, fmt.Sprintf(format, args...))
}

// refSpace is the resolvable-reference universe: fact ids, observation
// ids, advisory refs, and agent-source refs as emitted by the assembler.
// factTool maps a fact id back to the tool that produced it so
// basis-level rules can demand evidence of a specific kind (e.g. a
// dynamic observation behind the exploitation axis, an
type refSpace struct {
	facts       map[string]bool
	factByID    map[string]*VerifiedFact
	factTool    map[string]string
	obs         map[string]bool
	adv         map[string]bool
	advSubjects map[string]bool
	agent       map[string]bool
	agentSrc    map[string]bool
	// assumptions is the declared-assumptions/1 id space. It is
	// deliberately disjoint from facts/obs: an assumption id resolves
	// only here, and nothing in the evidence space can stand in for it.
	assumptions map[string]bool
}

// assumptionSHA256Re matches the intake byte-digest member (sha256 of the
// exact document bytes, unprefixed like the other channel digests).
var assumptionSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate enforces the research-report/1 contract (design §4 + §9
// per-case checks). It never repairs; it only rejects. dir, when
// non-empty, additionally verifies persisted artifacts exist and match
// their recorded sha256.
func Validate(r *Report, dir string) error {
	e := &ValidationError{}
	refs := refSpace{
		facts: map[string]bool{}, factByID: map[string]*VerifiedFact{}, factTool: map[string]string{},
		obs: map[string]bool{}, adv: map[string]bool{}, advSubjects: map[string]bool{}, agent: map[string]bool{}, agentSrc: map[string]bool{},
		assumptions: map[string]bool{},
	}
	if r.Schema != ReportSchemaV1 && r.Schema != ReportSchemaV2 && r.Schema != ReportSchemaV3 &&
		r.Schema != ReportSchemaV4 && r.Schema != ReportSchemaV5 {
		e.add("schema %q is unsupported", r.Schema)
	}
	if r.Mode != ReportMode {
		e.add("mode %q != %q", r.Mode, ReportMode)
	}
	if r.Run.RunID == "" || r.Run.StartedAt == "" || r.Run.FinishedAt == "" {
		e.add("run identity/timestamps incomplete")
	}
	in := &r.Input
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	obsIDRe := regexp.MustCompile(`^OBS-\d+$`)
	if !hex64.MatchString(in.Snapshot.ContentHash) {
		e.add("input.snapshot.content_hash must be 64-hex, got %q", in.Snapshot.ContentHash)
	}
	if in.Snapshot.Path == "" || in.Snapshot.CommitSHA == "" {
		e.add("input.snapshot path/commit_sha required")
	}
	ad := &in.Advisory
	if ad.SourceKind != "frozen_dir" && ad.SourceKind != "frozen_file" {
		e.add("advisory.source_kind %q not in {frozen_dir,frozen_file}", ad.SourceKind)
	}
	if !hex64.MatchString(ad.RawSHA256) || !hex64.MatchString(ad.CanonicalSHA256) {
		e.add("advisory raw/canonical sha256 must be 64-hex")
	}
	refs.adv["adv:"+ad.ResolvedID] = true
	refs.adv["advisory"] = true
	// The /1-compatible advisory-feed provenance block: additive, present
	// only when a feed source was configured. It must name a known status
	// and may never carry credential material.
	if fr := ad.FeedResolution; fr != nil {
		switch fr.Status {
		case "resolved", "not_required", "not_found", "no_imports",
			"ambiguous", "osv_missing", "feed_error", "partial":
		default:
			e.add("advisory.feed_resolution.status %q invalid", fr.Status)
		}
		if fr.DumpSHA256 != "" && !hex64.MatchString(fr.DumpSHA256) {
			e.add("advisory.feed_resolution.dump_sha256 must be 64-hex")
		}
		if strings.Contains(fr.FeedRef, "@") || strings.Contains(fr.FeedRef, "?") ||
			strings.Contains(fr.FeedRef, "#") {
			e.add("advisory.feed_resolution.feed_ref must not carry userinfo/query material")
		}
	}
	// The /3 release-evidence provenance block: when present it must be
	// self-consistent — a RESOLVED status alone may carry a selection, and
	// no member may carry credential material.
	validateReleaseEvidence(e, in.Snapshot.ReleaseEvidence)
	validateSnapshotTarget(e, in.Snapshot)
	// The declared-assumptions channel: additive, present only when the
	// operator supplied a document. When present it must be
	// self-consistent — provenance shape, pinned digest, schema, typed
	// members and the content digest — and it carries no evidence
	// semantics of its own.
	validateDeclaredAssumptionsInput(e, in.DeclaredAssumptions)
	validateImplementationProposalsInput(e, in.ImplementationLocusProposals, ad)
	validateImplementationLocusProposals(e, r, &in.Advisory)
	validateExploitProposalsInput(e, in.ExploitLocusProposals, ad)
	validateExploitLocusProposals(e, r, &in.Advisory)
	// run.outcome is reserved for the fail-closed lane outcome: NOT_RUN
	// exists only together with a release_evidence NOT_RUN block, and the
	// recorded reason must be the channel's own reason code.
	switch r.Run.Outcome {
	case "":
		if r.Run.OutcomeReason != "" {
			e.add("run.outcome_reason requires run.outcome")
		}
	case "NOT_RUN":
		if in.Snapshot.ReleaseEvidence == nil ||
			domain.ReleaseEvidenceStatus(in.Snapshot.ReleaseEvidence.Status) != domain.ReleaseStatusNotRun {
			e.add("run.outcome NOT_RUN requires release_evidence status NOT_RUN")
		} else if r.Run.OutcomeReason != in.Snapshot.ReleaseEvidence.ReasonCode {
			e.add("run.outcome_reason %q != release_evidence.reason_code %q",
				r.Run.OutcomeReason, in.Snapshot.ReleaseEvidence.ReasonCode)
		}
	default:
		e.add("run.outcome %q invalid (empty|NOT_RUN)", r.Run.Outcome)
	}
	for _, im := range r.AffectedImplementations {
		refs.adv[im.SourceRef] = true
		refs.advSubjects[im.ID] = true
		if im.Module != "" {
			if im.Package != nil && *im.Package != "" {
				if len(im.Symbols) == 0 {
					refs.advSubjects[subjectRefName(im.Module, *im.Package, "")] = true
				} else {
					for _, sym := range im.Symbols {
						refs.advSubjects[subjectRefName(im.Module, *im.Package, sym)] = true
					}
				}
			} else {
				refs.advSubjects[subjectRefName(im.Module, "", "")] = true
			}
		}
	}
	for i := range r.VerifiedFacts {
		f := &r.VerifiedFacts[i]
		refs.facts[f.ID] = true
		refs.factByID[f.ID] = f
		refs.factTool[f.ID] = f.Tool
	}
	for _, as := range r.AgentAssertions {
		refs.agent[as.ID] = true
	}
	// The agent-source index: every evidence_quality.references row with
	// kind=agent-source registers its ref. An agent-src ref resolves only
	// through this index — a missing index entry is the failure.
	for _, er := range r.EvidenceQuality.References {
		if er.Kind == "agent-source" {
			refs.agentSrc[er.Ref] = true
		}
	}
	// The declared-assumptions id space: ids resolve only against the
	// successfully loaded document — a failed channel admits nothing, so
	// its audit members never become citable policy inputs.
	if da := in.DeclaredAssumptions; da != nil && da.LoadError == "" {
		for _, a := range da.Assumptions {
			refs.assumptions[a.ID] = true
		}
	}
	// obs: refs resolve against persisted observation ids when dir is
	// known, else against provenance of recorded facts plus obs refs
	// already appearing inside unknowns/questions (self-consistent
	// in-memory mode). Decision refs and evidence_quality rows never
	// seed this space — a reference the report merely lists is not
	// evidence of anything.
	for _, f := range r.VerifiedFacts {
		refs.obs["obs:"+f.Provenance.ObservationID] = true
	}
	if dir != "" {
		for id := range persistedObservationIDs(dir) {
			refs.obs["obs:"+id] = true
		}
	} else {
		for _, q := range r.OpenQuestions {
			for _, ref := range q.EvidenceRefs {
				if strings.HasPrefix(ref, "obs:") {
					refs.obs[ref] = true
				}
			}
		}
		for _, u := range r.Unknowns {
			for _, ref := range u.EvidenceRefs {
				if strings.HasPrefix(ref, "obs:") {
					refs.obs[ref] = true
				}
			}
		}
	}

	aCheck := func(ref, where string) {
		if ref == "" {
			return
		}
		if strings.HasPrefix(ref, "agent-src:") {
			if refs.agentSrc[ref] {
				return
			}
			e.add("%s: agent-source ref %q has no evidence_quality.references index entry", where, ref)
			return
		}
		if refs.facts[ref] || refs.obs[ref] || refs.adv[ref] || refs.agent[ref] {
			return
		}
		e.add("%s: evidence_ref %q does not resolve", where, ref)
	}

	validateExploitLocusBinding(e, r, &refs, aCheck)

	// ---- verified_facts invariants ----
	for _, f := range r.VerifiedFacts {
		where := "verified_facts[" + f.ID + "]"
		if f.Statement == "" || f.Tool == "" || f.Command == "" || f.Scope == "" || f.ToolVersion == "" {
			e.add("%s: statement/tool/tool_version/command/scope must be non-empty", where)
		}
		if f.Status != "OK" {
			e.add("%s: status %q must be OK", where, f.Status)
		}
		if f.Coverage != "COMPLETE" && f.Coverage != "PARTIAL" {
			e.add("%s: coverage %q must be COMPLETE|PARTIAL", where, f.Coverage)
		}
		if !hex64.MatchString(f.SnapshotContentHash) {
			e.add("%s: snapshot_content_hash must be 64-hex", where)
		}
		if !hex64.MatchString(f.InputDigest) || !hex64.MatchString(f.DataDigest) {
			e.add("%s: input_digest/data_digest must be 64-hex", where)
		}
		if f.Artifact.Path == "" || !hex64.MatchString(f.Artifact.SHA256) {
			e.add("%s: artifact path+sha256 required", where)
		}
		if !obsIDRe.MatchString(f.Provenance.ObservationID) {
			e.add("%s: provenance.observation_id %q must be OBS-*", where, f.Provenance.ObservationID)
		}
		if f.Provenance.Source != "deterministic-lane" {
			e.add("%s: provenance.source %q must be deterministic-lane", where, f.Provenance.Source)
		}
		if f.Provenance.GeneratedAt == "" {
			e.add("%s: provenance.generated_at required", where)
		}
		if f.Claim != "TRUE" && f.Claim != "FALSE" {
			e.add("%s: claim %q must be TRUE|FALSE", where, f.Claim)
		}
		validatePackageUsageFact(e, f, where)
		// No agent-origin data in verified facts.
		blob, _ := json.Marshal(f)
		if strings.Contains(string(blob), "agent-src:") || strings.Contains(string(blob), "agent_assertion") {
			e.add("%s: contains agent-origin reference", where)
		}
		if dir != "" && f.Artifact.Path != "" {
			full := filepath.Join(dir, f.Artifact.Path)
			b, err := os.ReadFile(full)
			if err != nil {
				e.add("%s: artifact %s unreadable: %v", where, f.Artifact.Path, err)
			} else {
				sum := sha256.Sum256(b)
				got := hex.EncodeToString(sum[:])
				if got != f.Artifact.SHA256 {
					// artifact.sha256 is the digest of the file bytes exactly
					// as written — no tolerance for alternate encodings.
					e.add("%s: artifact %s sha256 mismatch: file %s recorded %s",
						where, f.Artifact.Path, got, f.Artifact.SHA256)
				}
			}
		}
	}

	// ---- B41/B42 cross-fact consistency ----
	// A package-level usage_scope=test-only fact can never coexist
	// with a carrier PACKAGE_USAGE fact for the same {Module,Package}
	// subject; the pairing is a forged report, never reconcilable.
	validateBuildUsageScopeConsistency(e, r)

	// ---- claim origins / deterministic evidence_refs ----
	checkClaims := func(name string, claims []Claim) {
		for _, c := range claims {
			where := name + ".claims[" + c.ID + "]"
			switch c.Origin {
			case OriginDeterm:
				okRef := false
				for _, ref := range c.EvidenceRefs {
					if refs.facts[ref] {
						okRef = true
					}
				}
				if !okRef {
					e.add("%s: origin=deterministic requires an evidence_ref to a verified fact", where)
				}
			case OriginAgent:
			default:
				e.add("%s: origin %q must be deterministic|agent", where, c.Origin)
			}
			for _, ref := range c.EvidenceRefs {
				aCheck(ref, where)
			}
		}
	}
	for _, s := range r.statusSections() {
		if s.Sec.Status == "" {
			e.add("%s.status is required", s.Name)
		} else if !enumStatus[s.Sec.Status] {
			e.add("%s.status %q invalid", s.Name, s.Sec.Status)
		}
		if s.Sec.Status == StatusUnknown && !isUnknownSummary(s.Sec.Summary) {
			e.add("%s: status=UNKNOWN requires summary starting `UNKNOWN:` with a concrete `follow-up:` (got %q)",
				s.Name, firstN(s.Sec.Summary, 120))
		}
		if s.Sec.Summary == "" {
			e.add("%s: summary required", s.Name)
		}
		checkClaims(s.Name, s.Sec.Claims)
	}
	for _, c := range r.ExploitationConditions {
		where := "exploitation_conditions[" + c.ID + "]"
		for _, ref := range c.EvidenceRefs {
			aCheck(ref, where)
			// A BUILD_USAGE_SCOPE fact is strictly non-carrier on every
			// exploitation condition — not only the B42 usage predicate.
			// Citing it would let a build-closure audit result enter the
			// ladder's evidence_refs and count as a confirmed transition.
			if f := refs.factByID[ref]; f != nil && f.Kind == FactKindBuildUsageScope {
				e.add("%s: cites BUILD_USAGE_SCOPE fact %q; a build-closure audit fact can never carry an exploitation condition", where, ref)
			}
		}
		if c.Origin != OriginDeterm && c.Origin != OriginAgent {
			e.add("%s: origin %q invalid", where, c.Origin)
		}
		switch c.Necessity {
		case "required", "supporting", "unknown":
		default:
			e.add("%s: necessity %q invalid", where, c.Necessity)
		}
		if c.Subject == subjProductPackageUsage {
			validatePackageUsageCondition(e, r, c, &refs)
		}
	}
	for _, ref := range r.ProductApplicability.EvidenceRefs {
		aCheck(ref, "product_applicability")
		if f := refs.factByID[ref]; f != nil && f.Kind == FactKindBuildUsageScope {
			e.add("product_applicability: evidence_ref %q is a BUILD_USAGE_SCOPE fact; a build-closure audit fact can never carry applicability", ref)
		}
	}
	for _, u := range r.Unknowns {
		for _, ref := range u.EvidenceRefs {
			aCheck(ref, "unknowns["+u.ID+"]")
		}
	}
	for _, q := range r.OpenQuestions {
		for _, ref := range q.EvidenceRefs {
			aCheck(ref, "open_questions["+q.ID+"]")
		}
	}
	for _, q := range r.ResidualQuestions {
		for _, ref := range q.EvidenceRefs {
			aCheck(ref, "residual_questions["+q.ID+"]")
		}
	}
	// open_questions ↔ residual_questions one-to-one ids.
	if len(r.OpenQuestions) != len(r.ResidualQuestions) {
		e.add("open_questions (%d) and residual_questions (%d) must be one-to-one",
			len(r.OpenQuestions), len(r.ResidualQuestions))
	} else {
		for i := range r.OpenQuestions {
			if r.OpenQuestions[i].ID != r.ResidualQuestions[i].ID {
				e.add("open_questions[%d].id %q != residual_questions[%d].id %q",
					i, r.OpenQuestions[i].ID, i, r.ResidualQuestions[i].ID)
			}
		}
	}
	for _, as := range r.AgentAssertions {
		for _, ref := range as.EvidenceRefs {
			aCheck(ref, "agent_assertions["+as.ID+"]")
		}
	}
	for _, ref := range r.EvidenceQuality.References {
		aCheck(ref.Ref, "evidence_quality.references")
	}
	for _, rec := range r.Recommendations {
		switch rec.Owner {
		case "human", "operator", "engineering":
		default:
			e.add("recommendations[%s]: owner %q invalid", rec.ID, rec.Owner)
		}
		for _, ref := range rec.EvidenceRefs {
			aCheck(ref, "recommendations["+rec.ID+"]")
		}
	}
	for _, ref := range r.TriageRecommendation.EvidenceRefs {
		aCheck(ref, "triage_recommendation")
	}
	switch r.TriageRecommendation.Action {
	case "fix", "verify", "low confirmed risk", "needs review":
	default:
		e.add("triage_recommendation.action %q invalid", r.TriageRecommendation.Action)
	}

	// ---- agent output ----
	switch r.AgentOutput.Status {
	case AgentNotRequested, AgentOK, AgentTimeout, AgentFailed, AgentProviderRefused, AgentInvalidFormat:
	default:
		e.add("agent_output.status %q invalid", r.AgentOutput.Status)
	}
	if r.AgentOutput.Status == AgentOK {
		if r.AgentOutput.Category == nil {
			e.add("agent_output.category required when status=OK")
		}
		if r.AgentOutput.RawArtifact.Path == nil || r.AgentOutput.RawArtifact.SHA256 == nil {
			e.add("agent_output.raw_artifact path+sha256 required when status=OK")
		}
	}

	switch r.Schema {
	case ReportSchemaV2:
		validateDecision(e, r, &refs)
	case ReportSchemaV3:
		if r.DecisionArtifact == nil {
			e.add("research-report/3 requires a decision_artifact member")
		} else {
			validateDecisionArtifact(e, r.DecisionArtifact, &refs, r)
		}
		if r.Decision != nil {
			// Decision stays a /2-compatible projection derived from the
			// artifact; when present it must still satisfy its own gates.
			validateDecision(e, r, &refs)
		}
	case ReportSchemaV4:
		// /4 extends /3: the decision artifact stays the record-bound
		// contract and the request composition is added beside it. Neither
		// member substitutes for the other.
		if r.DecisionArtifact == nil {
			e.add("research-report/4 requires a decision_artifact member")
		} else {
			validateDecisionArtifact(e, r.DecisionArtifact, &refs, r)
		}
		if r.Decision != nil {
			validateDecision(e, r, &refs)
		}
		if r.RequestComposition == nil {
			e.add("research-report/4 requires a request_composition member")
		} else {
			validateRequestComposition(e, r)
		}
	case ReportSchemaV5:
		if !assumptionSHA256Re.MatchString(r.RequestedCaseSHA256) {
			e.add("research-report/5 requires a pinned requested_case_sha256")
		}
		if r.RequestComposition == nil {
			e.add("research-report/5 requires a request_composition member")
		} else {
			validateRequestComposition(e, r)
		}
		if r.Decision != nil {
			validateDecision(e, r, &refs)
		}
		if dir != "" {
			if err := validateRequestedCase(r, dir); err != nil {
				e.add("requested-case.json: %v", err)
			}
		}
	default:
		if r.Decision != nil {
			e.add("decision is not valid in research-report/1")
		}
	}
	if r.DecisionArtifact != nil && r.Schema != ReportSchemaV3 && r.Schema != ReportSchemaV4 {
		e.add("decision_artifact is only valid in research-report/3 or /4")
	}
	if r.RequestComposition != nil && r.Schema != ReportSchemaV4 && r.Schema != ReportSchemaV5 {
		e.add("request_composition is only valid in research-report/4 or /5")
	}
	// A /3 or /4 run persists the same canonical artifact as a sidecar.
	// Re-read and validate it so report.json and decision-artifact.json
	// cannot drift.
	if (r.Schema == ReportSchemaV3 || r.Schema == ReportSchemaV4) &&
		r.DecisionArtifact != nil && dir != "" {
		path := filepath.Join(dir, "decision-artifact.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			e.add("decision-artifact.json: %v", err)
		} else {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var sidecar DecisionArtifact
			if err := dec.Decode(&sidecar); err != nil {
				e.add("decision-artifact.json: decode: %v", err)
			} else if err := ValidateDecisionArtifact(&sidecar); err != nil {
				e.add("decision-artifact.json: %v", err)
			} else {
				want, _ := json.Marshal(r.DecisionArtifact)
				got, _ := json.Marshal(&sidecar)
				if !bytes.Equal(want, got) {
					e.add("decision-artifact.json: sidecar differs from embedded decision_artifact")
				}
			}
		}
	}
	if dir != "" {
		bindPersistedObservations(e, r, dir)
	}

	// ---- disposition (fixed) ----
	if r.Disposition.Class != "REVIEW_REQUIRED" {
		e.add("disposition.class %q must be REVIEW_REQUIRED", r.Disposition.Class)
	}
	if r.Disposition.AutoClose {
		e.add("disposition.auto_close must be false")
	}
	forbidden := map[string]bool{"VERIFIED": true, "FALSE": true, "AUTO_CLOSE": true,
		"NOT_AFFECTED": true, "NO_EXPLOIT_PATH_FOUND": true}
	for _, fc := range r.Disposition.ForbiddenClasses {
		if forbidden[fc] {
			continue
		}
		e.add("disposition.forbidden_classes entry %q is not a forbidden class", fc)
	}

	// ---- deterministic-claim purity (slice-2 invariant D) ----
	for _, s := range r.statusSections() {
		for _, c := range s.Sec.Claims {
			if c.Origin != OriginDeterm {
				continue
			}
			for _, ref := range c.EvidenceRefs {
				if refs.agent[ref] || strings.HasPrefix(ref, "agent-src:") {
					e.add("%s.claims[%s]: deterministic claim references agent-origin %q", s.Name, c.ID, ref)
				}
			}
		}
	}
	for _, c := range r.ExploitationConditions {
		if c.Origin != OriginDeterm {
			continue
		}
		for _, ref := range c.EvidenceRefs {
			if refs.agent[ref] || strings.HasPrefix(ref, "agent-src:") {
				e.add("exploitation_conditions[%s]: deterministic condition references agent-origin %q", c.ID, ref)
			}
		}
	}
	validateRetainedTicket(r, e)
	validateRetainedConditions(r, e)
	validateRetainedImplementation(r, e)

	// ---- slice-2 extension (only when advertised) ----
	v1, v2, v3 := false, false, false
	markerSeen := map[string]bool{}
	for _, x := range r.ContractExtensions {
		switch x {
		case Slice2ExtensionV1:
			v1 = true
		case Slice2Extension:
			v2 = true
		case Slice2ExtensionV3:
			v3 = true
		default:
			continue
		}
		// A report carries exactly one extension marker (types.go):
		// the same marker listed twice is a violation, not a no-op.
		if markerSeen[x] {
			e.add("contract_extensions: marker %q listed twice", x)
		}
		markerSeen[x] = true
	}
	// The three markers are mutually exclusive; each pair plus the
	// triple combination must be rejected.
	if v1 && v2 {
		e.add("contract_extensions: %q and %q are mutually exclusive", Slice2ExtensionV1, Slice2Extension)
	}
	if v1 && v3 {
		e.add("contract_extensions: %q and %q are mutually exclusive", Slice2ExtensionV1, Slice2ExtensionV3)
	}
	if v2 && v3 {
		e.add("contract_extensions: %q and %q are mutually exclusive", Slice2Extension, Slice2ExtensionV3)
	}
	// The B41 audit axis is /3-only: a /1, /2 or unmarked document can
	// never carry the member at all.
	if !v3 && r.ExploitationAxes.BuildUsageScope != nil {
		e.add("exploitation_axes.build_usage_scope is only valid under %q", Slice2ExtensionV3)
	}
	if !v3 {
		for _, f := range r.VerifiedFacts {
			if f.Kind == FactKindBuildUsageScope || f.UsageScope != "" || f.ProductAbsenceVerification != "" {
				e.add("verified_facts[%s]: B41 fields are only valid under %q", f.ID, Slice2ExtensionV3)
			}
		}
	}
	if v1 || v2 || v3 {
		e.validateSlice2(r, &refs)
	}
	// slice2-fidelity/3 is an additive revision: it carries every /2
	// requirement plus the mandatory role/evidence_level ladder checks.
	if v2 || v3 {
		e.validateSlice2V2(r, &refs)
	}
	if v3 {
		e.validateSlice2V3(r, &refs)
	}
	if len(e.Problems) > 0 {
		return e
	}
	return nil
}

func validateDecision(e *ValidationError, r *Report, refs *refSpace) {
	d := r.Decision
	if d == nil {
		e.add("research-report/2 requires decision")
		return
	}
	if d.Reason == "" || d.Scope == "" || d.Coverage == "" || d.TicketRationale == "" {
		e.add("decision reason/scope/coverage/ticket_rationale are required")
	}
	if d.Verdict == domain.VerdictInconclusive {
		if len(d.HumanQuestions) == 0 {
			e.add("decision INCONCLUSIVE requires a concrete human question and follow-up")
		}
		if !strings.Contains(strings.ToLower(d.TicketRationale), "follow-up") && len(d.Limitations) == 0 {
			e.add("decision INCONCLUSIVE requires a follow-up")
		}
	}
	for i, c := range d.Checks {
		where := fmt.Sprintf("decision.checks[%d]", i)
		if c.ID == "" || c.Tool == "" || c.Status == "" || c.Completeness == "" || c.Scope == "" {
			e.add("%s: id/tool/status/completeness/scope required", where)
		}
		if df := c.DerivedFrom; df != nil {
			switch df.Field {
			case "summary", "description", "raw_body":
			default:
				e.add("%s: derived_from.field %q must name an advisory text field", where, df.Field)
			}
			if df.Quote == "" {
				e.add("%s: derived_from.quote is required when the member is present", where)
			}
		}
		for _, ref := range c.EvidenceRefs {
			validateDecisionRef(e, refs, ref, where)
		}
	}
	for _, ref := range d.EvidenceRefs {
		validateDecisionRef(e, refs, ref, "decision.evidence_refs")
	}
	// Assumption references are policy/scope citations, resolved only
	// against the declared-assumptions document and kept disjoint from
	// the evidence space: an assumption id may never double as evidence.
	seenAssumptions := map[string]bool{}
	for _, id := range d.AssumptionIDs {
		if id == "" {
			e.add("decision.assumption_ids: empty assumption ref")
			continue
		}
		if seenAssumptions[id] {
			e.add("decision.assumption_ids: assumption %q listed twice", id)
			continue
		}
		seenAssumptions[id] = true
		if !refs.assumptions[id] {
			e.add("decision.assumption_ids: assumption %q does not resolve to input.declared_assumptions", id)
			continue
		}
		if refs.facts[id] || refs.obs[id] {
			e.add("decision.assumption_ids: %q also resolves as evidence — an assumption is never evidence", id)
		}
	}
	switch d.Verdict {
	case domain.VerdictNoExploitPathFound:
		switch d.Falsifier {
		case domain.FalsifierPackageAbsent, domain.FalsifierLocusPackageAbsent,
			domain.FalsifierDeclaredSymbolUnreached:
		case domain.FalsifierTrustedInfrastructure:
			// The post-reach configuration route is the only
			// trusted-infrastructure negative a decision may carry. Its
			// basis and policy assumption are prerequisites, not
			// annotations: a decision without the config-origin basis or
			// without the declared assumption id would read as a
			// code-level proof.
			if d.GroundBasis != domain.BasisConfigOrigin {
				e.add("decision NO_EXPLOIT_PATH_FOUND with FalsifierTrustedInfrastructure requires ground_basis=%q, got %q",
					domain.BasisConfigOrigin, d.GroundBasis)
			}
			if len(d.AssumptionIDs) == 0 {
				e.add("decision NO_EXPLOIT_PATH_FOUND with FalsifierTrustedInfrastructure requires assumption_ids (the config-trust policy is a declared input)")
			}
		default:
			e.add("decision NO_EXPLOIT_PATH_FOUND requires a recognized negative-proof falsifier")
		}
		if d.NegativeVerification == nil || d.NegativeVerification.Status != domain.NegativeVerified {
			e.add("decision NO_EXPLOIT_PATH_FOUND requires NegativeVerification=VERIFIED")
		}
		if d.Coverage != "COMPLETE" {
			e.add("decision NO_EXPLOIT_PATH_FOUND requires closed COMPLETE coverage")
		}
		if len(d.EvidenceRefs) == 0 {
			e.add("decision NO_EXPLOIT_PATH_FOUND requires evidence refs")
		}
		// Under /3 the lane's terminal decision dominates the recorded
		// run: a supporting layer's failure rides in limitations as an
		// annotation of the standing verdict (the run record itself and
		// the artifact still carry the failure in full). The older
		// shapes keep the terminal-negative gate verbatim: no /2
		// production path emits a NEP decision with limitations.
		if len(d.Limitations) != 0 && r.Schema != ReportSchemaV3 && r.Schema != ReportSchemaV4 {
			e.add("decision NO_EXPLOIT_PATH_FOUND cannot carry unresolved limitations")
		}
	case domain.VerdictExploitable:
		if d.ConditionID == "" || d.Coverage != "COMPLETE" || len(d.EvidenceRefs) == 0 || len(d.Limitations) != 0 {
			e.add("decision EXPLOITABLE requires complete positive conditions, evidence refs and no blocker")
		}
	case domain.VerdictNotAffected, domain.VerdictInconclusive:
	default:
		e.add("decision verdict %q is invalid", d.Verdict)
	}
}

// validateRequestComposition enforces the /4 requested-finding member: it is
// the same re-admitted composition every other consumer publishes, it names
// this report's request, and the corpus completeness basis stays inside it.
//
// The old product_applicability block is deliberately not consulted for
// authority: corpus enumeration may never upgrade it to CVE_WIDE/COMPLETE.
// That combination stays governed by the record's own census, which is why a
// CVE request carrying a corpus basis must not carry it here.
func validateRequestComposition(e *ValidationError, r *Report) {
	composition := r.RequestComposition
	if err := composition.Validate(); err != nil {
		e.add("request_composition: %v", err)
	}
	if composition.Status != domain.FindingFinal {
		e.add("request_composition.status %q is not publishable", composition.Status)
	}
	requested := r.Input.Advisory.RequestedID
	if requested != "" && composition.RequestedID != requested {
		e.add("request_composition names request %q, the report analysed %q",
			composition.RequestedID, requested)
	}
	if composition.CorpusNegativeBasis != nil && composition.RequestedKind != domain.ScopeCVE {
		e.add("request_composition carries a corpus negative basis for the %q request %q; corpus completeness only bounds a CVE-wide negative",
			composition.RequestedKind, composition.RequestedID)
	}
	if composition.RequestedKind == domain.ScopeCVE &&
		r.ProductApplicability.ConclusionScope == ScopeCVEWide &&
		r.ProductApplicability.AdvisoryScopeStatus == ScopeComplete {
		e.add("product_applicability cannot claim %s/%s for the CVE request %q: corpus enumeration never widens the record-bound block",
			ScopeCVEWide, ScopeComplete, composition.RequestedID)
	}
}

func validateDecisionRef(e *ValidationError, refs *refSpace, ref, where string) {
	if ref == "" {
		e.add("%s: empty evidence ref", where)
		return
	}
	// A decision ref resolves only against genuinely recorded spaces —
	// lane/verification observation ids, lane facts and their digests —
	// never against the report's own self-listed strings.
	if refs.facts[ref] || refs.obs[ref] {
		return
	}
	if strings.HasPrefix(ref, "sha256:") {
		for _, f := range refs.factByID {
			if "sha256:"+f.DataDigest == ref || "sha256:"+f.Artifact.SHA256 == ref || "sha256:"+f.InputDigest == ref {
				return
			}
		}
	}
	e.add("%s: evidence ref %q does not resolve to a verification observation or lane fact", where, ref)
}

// releaseCredentialRe rejects credential material inside the release
// provenance block: credential-bearing JSON keys and URL userinfo. The
// channel contract forbids secrets in any persisted or rendered surface.
var releaseCredentialRe = regexp.MustCompile(`(?i)"[^"]*(credential|password|passwd|secret|api_?key|authorization|bearer|access_?token)[^"]*"\s*:|://[^\s"']+@`)

// validateReleaseEvidence enforces the /3 release-evidence provenance
// contract: status belongs to the domain taxonomy, a selection exists
// only under RESOLVED, every digest is 64-hex, item trust classes are
// exhaustive, and no member may carry credential material.
func validateReleaseEvidence(e *ValidationError, rev *ReleaseEvidenceReport) {
	if rev == nil {
		return
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	switch domain.ReleaseEvidenceStatus(rev.Status) {
	case domain.ReleaseStatusNotRequested, domain.ReleaseStatusResolved,
		domain.ReleaseStatusUnknown, domain.ReleaseStatusConflicted, domain.ReleaseStatusNotRun:
	default:
		e.add("input.snapshot.release_evidence.status %q invalid", rev.Status)
	}
	if rev.SelectedVersion != "" || rev.SelectedSource != "" || rev.SelectedTrust != "" {
		if domain.ReleaseEvidenceStatus(rev.Status) != domain.ReleaseStatusResolved {
			e.add("release_evidence.selected_* present under status %q (RESOLVED only)", rev.Status)
		}
	}
	if rev.SelectedTrust != "" && rev.SelectedTrust != string(domain.ReleaseTrustAuthoritative) &&
		rev.SelectedTrust != string(domain.ReleaseTrustSupporting) {
		e.add("release_evidence.selected_trust %q invalid", rev.SelectedTrust)
	}
	for _, dg := range []struct{ name, v string }{
		{"artifact_sha256", rev.ArtifactSHA256},
		{"build_info_sha256", rev.BuildInfoSHA256},
	} {
		if dg.v != "" && !hex64.MatchString(dg.v) {
			e.add("release_evidence.%s must be 64-hex, got %q", dg.name, dg.v)
		}
	}
	for i, it := range rev.Items {
		if it.TrustClass != string(domain.ReleaseTrustAuthoritative) &&
			it.TrustClass != string(domain.ReleaseTrustSupporting) {
			e.add("release_evidence.items[%d].trust_class %q invalid", i, it.TrustClass)
		}
		for _, dg := range []struct{ name, v string }{
			{"artifact_sha256", it.ArtifactSHA256},
			{"build_info_sha256", it.BuildInfoSHA256},
		} {
			if dg.v != "" && !hex64.MatchString(dg.v) {
				e.add("release_evidence.items[%d].%s must be 64-hex, got %q", i, dg.name, dg.v)
			}
		}
	}
	if rev.VersionGraphTrust != "" && rev.VersionGraphTrust != string(domain.ReleaseTrustAuthoritative) {
		e.add("release_evidence.version_graph_trust %q invalid (AUTHORITATIVE only)", rev.VersionGraphTrust)
	}
	blob, _ := json.Marshal(rev)
	if releaseCredentialRe.Match(blob) {
		e.add("release_evidence contains credential-looking material")
	}
}

// validateDeclaredAssumptionsInput enforces the declared-assumptions/1
// channel contract in a report: sanitized provenance, the pinned intake
// digest, the exact schema, the typed members and their content digest.
// The members are re-validated from the persisted report — a hand-edited
// document fails closed exactly like a bad intake.
func validateDeclaredAssumptionsInput(e *ValidationError, da *domain.DeclaredAssumptionsInput) {
	if da == nil {
		return
	}
	if da.Path == "" {
		e.add("input.declared_assumptions.path is required when the block is present")
	} else if !strings.HasPrefix(da.Path, "local:") || strings.ContainsAny(da.Path, "/\\\n\r") {
		e.add("input.declared_assumptions.path must be a sanitized local:<basename> provenance ref, got %q", da.Path)
	}
	if da.SHA256 != "" && !assumptionSHA256Re.MatchString(da.SHA256) {
		e.add("input.declared_assumptions.sha256 must be 64-hex, got %q", da.SHA256)
	}
	if da.LoadError != "" {
		switch da.LoadError {
		case domain.AssumptionsLoadUnreadable, domain.AssumptionsLoadOversized, domain.AssumptionsLoadInvalid:
		default:
			e.add("input.declared_assumptions.load_error %q invalid", da.LoadError)
		}
		// A failed channel admits nothing: the members may remain for
		// audit, but no gate may consume them.
		return
	}
	if da.SHA256 == "" {
		e.add("input.declared_assumptions.sha256 is required for a loaded document")
	}
	if da.Schema != domain.DeclaredAssumptionsSchema {
		e.add("input.declared_assumptions.schema %q != %q", da.Schema, domain.DeclaredAssumptionsSchema)
	}
	doc := da.Document()
	if doc == nil {
		e.add("input.declared_assumptions carries no loaded assumptions")
		return
	}
	if err := domain.ValidateDeclaredAssumptions(doc); err != nil {
		e.add("input.declared_assumptions: %v", err)
	}
}

// validateImplementationProposalsInput enforces the
// implementation-locus-proposals/1 channel contract in a report:
// sanitized provenance, a known source, the pinned advisory digest
// matching the recorded frozen advisory, a bounded member set, and a
// fail-closed load outcome that admits nothing. The members are
// re-validated from the persisted report — a hand-edited proposal
// fails closed exactly like a bad intake.
func validateImplementationProposalsInput(e *ValidationError, pi *ImplementationProposalsInput, ad *AdvisoryInput) {
	if pi == nil {
		return
	}
	switch pi.Source {
	case ImplementationProposalsSourceArtifact:
		if pi.Path == "" {
			e.add("input.implementation_locus_proposals.path is required for an artifact-file channel")
		} else if !strings.HasPrefix(pi.Path, "local:") || strings.ContainsAny(pi.Path, "/\\\n\r") {
			e.add("input.implementation_locus_proposals.path must be a sanitized local:<basename> provenance ref, got %q", pi.Path)
		}
	case ImplementationProposalsSourceReplayed:
		if pi.Path != "" {
			e.add("input.implementation_locus_proposals.path must be empty for a replayed-agent-turn channel, got %q", pi.Path)
		}
	default:
		e.add("input.implementation_locus_proposals.source %q invalid", pi.Source)
	}
	if pi.SHA256 != "" && !assumptionSHA256Re.MatchString(pi.SHA256) {
		e.add("input.implementation_locus_proposals.sha256 must be 64-hex, got %q", pi.SHA256)
	}
	if pi.AdvisorySHA256 != "" && !assumptionSHA256Re.MatchString(pi.AdvisorySHA256) {
		e.add("input.implementation_locus_proposals.advisory_sha256 must be 64-hex, got %q", pi.AdvisorySHA256)
	}
	if pi.RetainedAnswerSHA256 != "" && !assumptionSHA256Re.MatchString(pi.RetainedAnswerSHA256) {
		e.add("input.implementation_locus_proposals.retained_answer_sha256 must be 64-hex, got %q", pi.RetainedAnswerSHA256)
	}
	if pi.Source == ImplementationProposalsSourceArtifact && pi.AdvisorySHA256 != "" && ad != nil &&
		pi.AdvisorySHA256 != ad.RawSHA256 && pi.AdvisorySHA256 != ad.CanonicalSHA256 {
		e.add("input.implementation_locus_proposals.advisory_sha256 %q pins a different advisory than the frozen document (raw %s, canonical %s)",
			pi.AdvisorySHA256, ad.RawSHA256, ad.CanonicalSHA256)
	}
	switch pi.LoadError {
	case "":
	case ImplementationProposalsLoadUnreadable, ImplementationProposalsLoadOversized,
		ImplementationProposalsLoadInvalid, ImplementationProposalsLoadMismatch:
	default:
		e.add("input.implementation_locus_proposals.load_error %q invalid", pi.LoadError)
	}
	if pi.LoadError != "" {
		// A failed channel admits nothing: the members may remain for
		// audit, but no gate may consume them.
		return
	}
	if pi.Source == ImplementationProposalsSourceArtifact && pi.AdvisorySHA256 == "" {
		e.add("input.implementation_locus_proposals.advisory_sha256 is required for a loaded artifact channel")
	}
	if pi.SHA256 == "" {
		e.add("input.implementation_locus_proposals.sha256 is required for a loaded channel")
	}
	if len(pi.Proposals) == 0 || len(pi.Proposals) > maxImplementationLocusProposals {
		e.add("input.implementation_locus_proposals carries %d proposals; the channel requires 1..%d", len(pi.Proposals), maxImplementationLocusProposals)
	}
	seen := map[string]bool{}
	for i, p := range pi.Proposals {
		where := fmt.Sprintf("input.implementation_locus_proposals.proposals[%d]", i)
		if err := p.Validate(); err != nil {
			e.add("%s: %v", where, err)
			continue
		}
		if seen[p.ID] {
			e.add("%s: duplicate proposal id %q", where, p.ID)
		}
		seen[p.ID] = true
	}
}

// validateImplementationLocusProposals enforces the non-authoritative
// proposal contract: typed shape and LLM-inferred quality, unique ids, an
// advisory reference that resolves to the frozen advisory identity/digest,
// and — when the pinned frozen advisory source is still readable and its
// bytes match the recorded raw digest — an exact recorded advisory quote.
// A proposal that fails here is a report-contract violation, never a
// degraded proposal.
func validateImplementationLocusProposals(e *ValidationError, r *Report, ad *AdvisoryInput) {
	ps := r.ImplementationLocusProposals
	if len(ps) == 0 {
		return
	}
	if len(ps) > maxImplementationLocusProposals {
		e.add("implementation_locus_proposals carries %d entries; maximum is %d", len(ps), maxImplementationLocusProposals)
	}
	var raw []byte
	if ad.SourcePath != "" {
		if b, err := os.ReadFile(ad.SourcePath); err == nil {
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) == ad.RawSHA256 {
				raw = b
			}
		}
	}
	seen := map[string]bool{}
	for i, p := range ps {
		where := fmt.Sprintf("implementation_locus_proposals[%d]", i)
		if err := p.Validate(); err != nil {
			e.add("%s: %v", where, err)
			continue
		}
		if seen[p.ID] {
			e.add("%s: duplicate proposal id %q", where, p.ID)
		}
		seen[p.ID] = true
		if err := domain.ValidateImplementationAdvisoryRef(p.AdvisoryEvidenceRef,
			ad.ResolvedID, ad.RawSHA256, ad.CanonicalSHA256); err != nil {
			e.add("%s: %v", where, err)
		}
		field := domain.ImplementationAdvisoryQuoteField(p.AdvisoryQuotedSpan,
			r.Vulnerability.Summary, r.Vulnerability.Description, raw)
		if field == "" {
			e.add("%s: advisory_quoted_span is not an exact recorded substring of the frozen advisory summary/details/raw body", where)
		}
	}
}

// validateExploitProposalsInput checks the exploit-locus proposal
// channel record: closed source label, sanitized provenance path, pinned
// digests, typed load outcome, and — for a loaded channel — the admitted
// members with their own closed shape. A failed channel admits nothing,
// so its audit members are never validated as consumable inputs.
func validateExploitProposalsInput(e *ValidationError, pi *ExploitProposalsInput, ad *AdvisoryInput) {
	if pi == nil {
		return
	}
	switch pi.Source {
	case ExploitProposalsSourceArtifact:
		if pi.Path == "" {
			e.add("input.exploit_locus_proposals.path is required for an artifact-file channel")
		} else if !strings.HasPrefix(pi.Path, "local:") || strings.ContainsAny(pi.Path, "/\\\n\r") {
			e.add("input.exploit_locus_proposals.path must be a sanitized local:<basename> provenance ref, got %q", pi.Path)
		}
	case ExploitProposalsSourceReplayed:
		if pi.Path != "" {
			e.add("input.exploit_locus_proposals.path must be empty for a replayed-agent-turn channel, got %q", pi.Path)
		}
	default:
		e.add("input.exploit_locus_proposals.source %q invalid", pi.Source)
	}
	if pi.SHA256 != "" && !assumptionSHA256Re.MatchString(pi.SHA256) {
		e.add("input.exploit_locus_proposals.sha256 must be 64-hex, got %q", pi.SHA256)
	}
	if pi.AdvisorySHA256 != "" && !assumptionSHA256Re.MatchString(pi.AdvisorySHA256) {
		e.add("input.exploit_locus_proposals.advisory_sha256 must be 64-hex, got %q", pi.AdvisorySHA256)
	}
	if pi.RetainedAnswerSHA256 != "" && !assumptionSHA256Re.MatchString(pi.RetainedAnswerSHA256) {
		e.add("input.exploit_locus_proposals.retained_answer_sha256 must be 64-hex, got %q", pi.RetainedAnswerSHA256)
	}
	if pi.Source == ExploitProposalsSourceArtifact && pi.AdvisorySHA256 != "" && ad != nil &&
		pi.AdvisorySHA256 != ad.RawSHA256 && pi.AdvisorySHA256 != ad.CanonicalSHA256 {
		e.add("input.exploit_locus_proposals.advisory_sha256 %q pins a different advisory than the frozen document (raw %s, canonical %s)",
			pi.AdvisorySHA256, ad.RawSHA256, ad.CanonicalSHA256)
	}
	switch pi.LoadError {
	case "":
	case ExploitProposalsLoadUnreadable, ExploitProposalsLoadOversized,
		ExploitProposalsLoadInvalid, ExploitProposalsLoadMismatch:
	default:
		e.add("input.exploit_locus_proposals.load_error %q invalid", pi.LoadError)
	}
	if pi.LoadError != "" {
		return
	}
	if pi.Source == ExploitProposalsSourceArtifact && pi.AdvisorySHA256 == "" {
		e.add("input.exploit_locus_proposals.advisory_sha256 is required for a loaded artifact channel")
	}
	if pi.SHA256 == "" {
		e.add("input.exploit_locus_proposals.sha256 is required for a loaded channel")
	}
	if len(pi.Proposals) == 0 || len(pi.Proposals) > maxExploitLocusProposals {
		e.add("input.exploit_locus_proposals carries %d proposals; the channel requires 1..%d", len(pi.Proposals), maxExploitLocusProposals)
	}
	seen := map[string]bool{}
	for i, p := range pi.Proposals {
		where := fmt.Sprintf("input.exploit_locus_proposals.proposals[%d]", i)
		if err := p.Validate(); err != nil {
			e.add("%s: %v", where, err)
			continue
		}
		if seen[p.ID] {
			e.add("%s: duplicate proposal id %q", where, p.ID)
		}
		seen[p.ID] = true
	}
}

// validateExploitLocusProposals re-checks every retained exploit-locus
// proposal against the report's frozen advisory: closed shape, the
// advisory reference resolving to the frozen id/digest, and the verbatim
// quoted span. The proposals are hypotheses and stay non-authoritative.
func validateExploitLocusProposals(e *ValidationError, r *Report, ad *AdvisoryInput) {
	for i, p := range r.ExploitLocusProposals {
		where := fmt.Sprintf("exploit_locus_proposals[%d]", i)
		if err := p.Validate(); err != nil {
			e.add("%s: %v", where, err)
			continue
		}
		if err := domain.ValidateImplementationAdvisoryRef(p.AdvisoryEvidenceRef,
			ad.ResolvedID, ad.RawSHA256, ad.CanonicalSHA256); err != nil {
			e.add("%s: %v", where, err)
		}
		var raw []byte
		if ad.SourcePath != "" {
			if b, err := os.ReadFile(ad.SourcePath); err == nil {
				sum := sha256.Sum256(b)
				if hex.EncodeToString(sum[:]) == ad.RawSHA256 {
					raw = b
				}
			}
		}
		if field := domain.ImplementationAdvisoryQuoteField(p.AdvisoryQuotedSpan,
			r.Vulnerability.Summary, r.Vulnerability.Description, raw); field == "" {
			e.add("%s: advisory_quoted_span is not an exact recorded substring of the frozen advisory summary/details/raw body", where)
		}
	}
}

// validateExploitLocusBinding checks the deterministic binding record:
// it may appear only when its proposal artifact was loaded (a failed
// channel admits nothing and cannot back a binding), the proposal id
// resolves to an admitted member with identical identities, the record
// is complete with no blocker, the condition subjects equal the verified
// sink set exactly at the record's trigger index, the vulnerable symbol
// never leaks into the advisory's affected symbol set, evidence refs
// resolve, and assumption ids resolve only in the declared-assumptions
// space — an assumption id is a policy input, never an evidence id.
func validateExploitLocusBinding(e *ValidationError, r *Report, refs *refSpace,
	aCheck func(ref, where string)) {
	b := r.ExploitLocusBinding
	if b == nil {
		return
	}
	const where = "exploit_locus_binding"
	pi := r.Input.ExploitLocusProposals
	if pi == nil || pi.LoadError != "" {
		e.add("%s: a binding record requires its loaded exploit-locus proposal artifact", where)
		return
	}
	var proposal *domain.ExploitLocusProposal
	for i := range pi.Proposals {
		if pi.Proposals[i].ID == b.ProposalID {
			proposal = &pi.Proposals[i]
			break
		}
	}
	if proposal == nil {
		e.add("%s: proposal id %q does not resolve to an admitted input proposal", where, b.ProposalID)
	} else {
		if b.AdvisoryID != "" && proposal.AdvisoryEvidenceRef == "" {
			e.add("%s: proposal %q carries no advisory reference", where, b.ProposalID)
		}
		if b.Module != proposal.Module || b.Version != proposal.Version ||
			b.Vulnerable.Package != proposal.VulnerablePackage ||
			b.Vulnerable.Symbol != proposal.VulnerableSymbol ||
			b.TriggerArgumentName != proposal.TriggerArgumentName ||
			b.TriggerArgumentIndex != proposal.TriggerArgumentIndex {
			e.add("%s: binding identity/proposal members disagree with input proposal %q", where, b.ProposalID)
		}
	}
	if adID := r.Input.Advisory.ResolvedID; adID != "" && b.AdvisoryID != adID {
		e.add("%s: advisory_id %q does not match the frozen advisory %q", where, b.AdvisoryID, adID)
	}
	if !b.Complete || len(b.Blockers) > 0 {
		e.add("%s: only a COMPLETE binding with no blocker may appear", where)
	}
	if b.Vulnerable.Package == "" || b.Vulnerable.Symbol == "" {
		e.add("%s: vulnerable package/symbol required", where)
	}
	for _, im := range r.AffectedImplementations {
		for _, sym := range im.Symbols {
			if sym == b.Vulnerable.Symbol || strings.HasSuffix(sym, "."+b.Vulnerable.Symbol) {
				e.add("%s: the LLM locus symbol %q must not be fabricated into the advisory's affected symbol set", where, sym)
			}
		}
		if im.Module == b.Module && len(im.Symbols) > 0 {
			e.add("%s: the advisory entry %s declares structured symbols — the symbol-less binding route does not apply", where, im.Module)
		}
	}
	if len(b.Sinks) == 0 {
		e.add("%s: the verified product sink set is empty", where)
	}
	bound := map[string]bool{}
	for _, s := range b.Sinks {
		key := s.Package + "." + s.Symbol
		if s.Package == "" || s.Symbol == "" || s.Module == "" || bound[key] {
			e.add("%s: sink %q requires package/symbol/module identity and no duplicate", where, key)
		}
		bound[key] = true
	}
	if b.TriggerArgumentIndex < 0 {
		e.add("%s: trigger_argument_index must be nonnegative", where)
	}
	if b.Condition.ID != "C-INPUT" || b.Condition.Kind != string(domain.ConditionAttackerControl) {
		e.add("%s: condition must be the mandatory C-INPUT attacker-control condition", where)
	}
	if !b.Condition.Mandatory || b.Condition.ArgIndex != b.TriggerArgumentIndex {
		e.add("%s: condition must be mandatory at the binding's exact trigger index", where)
	}
	if len(b.Condition.Subjects) != len(bound) {
		e.add("%s: condition subjects (%d) must equal the verified sink set (%d)", where, len(b.Condition.Subjects), len(bound))
	}
	for _, s := range b.Condition.Subjects {
		key := s.Package + "." + s.Symbol
		if !bound[key] {
			e.add("%s: condition subject %q is not a verified binding sink", where, key)
		}
	}
	if b.Condition.Statement == "" {
		e.add("%s: condition statement required", where)
	}
	for _, ref := range b.EvidenceRefs {
		aCheck(ref, where+".evidence_refs")
	}
	for _, id := range b.AssumptionIDs {
		if refs.facts[id] || refs.obs[id] || refs.adv[id] || refs.agent[id] || strings.Contains(id, ":") {
			e.add("%s: assumption id %q must not be an evidence/fact reference", where, id)
			continue
		}
		if !refs.assumptions[id] {
			e.add("%s: assumption id %q does not resolve to input.declared_assumptions", where, id)
		}
	}
}

var enumStatus = map[string]bool{
	StatusSupported: true, StatusPartial: true, StatusUnknown: true, StatusConflicted: true,
}

// ParseReport decodes a report.json, rejecting unknown fields at every
// level — the schema's member set is closed.
func ParseReport(b []byte) (*Report, error) {
	var envelope struct { Schema string `json:"schema"` }
	if json.Unmarshal(b, &envelope) == nil && envelope.Schema == HistoricalReplaySchema {
		return nil, ErrHistoricalAuthority
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("report.json decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("report.json has trailing content")
	}
	return &r, nil
}

// ValidateFile loads report.json from dir and validates it including
// artifact checks.
func ValidateFile(dir string) (*Report, error) {
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		return nil, err
	}
	r, err := ParseReport(b)
	if err != nil {
		return nil, err
	}
	if err := Validate(r, dir); err != nil {
		return r, err
	}
	return r, nil
}

func bytesTrimRightNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// persistedObservationIDs reads the persisted observation ledgers under
// dir — the deterministic lane's observations.jsonl and the verification
// phase's verification-observations.jsonl — and returns the recorded
// observation ids. Missing files yield nil (lenient).
func persistedObservationIDs(dir string) map[string]bool {
	ids := map[string]bool{}
	for _, name := range []string{"observations.jsonl", "verification-observations.jsonl"} {
		readObservationIDs(filepath.Join(dir, name), ids)
	}
	return ids
}

// readObservationIDs decodes one audit-record ledger file into ids.
func readObservationIDs(path string, ids map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		// Rows are evidencetools.AuditRecord; the observation id is
		// nested under observation.id. Tolerate a flat observation_id
		// field too in case the record shape changes.
		var row struct {
			ObservationID string `json:"observation_id"`
			Observation   *struct {
				ID string `json:"id"`
			} `json:"observation"`
		}
		if err := dec.Decode(&row); err != nil {
			break
		}
		if row.ObservationID != "" {
			ids[row.ObservationID] = true
		}
		if row.Observation != nil && row.Observation.ID != "" {
			ids[row.Observation.ID] = true
		}
	}
}

// bindPersistedObservations binds the report's observation references
// to what is actually persisted under dir. An evidence_quality.references
// row of kind=observation pins its payload by path+sha256 — the file
// must exist and hash to the recorded digest. A row pinning a
// verification-artifacts/obs-*.json payload is additionally bound to
// the session audit ledger: the cited observation id must appear in
// exactly one verification-observations.jsonl row and that row's
// observation payload must equal the pinned artifact byte-for-byte in
// canonical form. A mutated artifact, a missing/duplicated/edited
// ledger row, or a decision citation with no pinned row all fail.
//
// An observation carrying payload_ref is additionally bound to its
// externalized sidecar: the reference must be well-formed (the
// content-addressed path, selector, sha256 and size all present), the
// data envelope must be the externalization shape that reference
// implies — never a prefix offered as the result — the scope-limit
// pins must agree with the reference, and the sidecar bytes must
// exist, hash to the recorded digest and decode. Missing, altered or
// undecodable sidecars fail closed.
func bindPersistedObservations(e *ValidationError, r *Report, dir string) {
	cited := map[string]bool{}
	if r.Decision != nil {
		for _, ref := range r.Decision.EvidenceRefs {
			if strings.HasPrefix(ref, "obs:") {
				cited[ref] = true
			}
		}
		for _, c := range r.Decision.Checks {
			for _, ref := range c.EvidenceRefs {
				if strings.HasPrefix(ref, "obs:") {
					cited[ref] = true
				}
			}
		}
	}
	// Ledger rows keyed by their embedded observation id; malformed
	// rows are recorded, not tolerated — a changed ledger must not
	// validate. Any payload_ref a row carries is bound to its sidecar
	// under dir here.
	ledger := map[string][]*evidencetools.AuditRecord{}
	ledgerPath := filepath.Join(dir, "verification-observations.jsonl")
	if f, err := os.Open(ledgerPath); err == nil {
		defer f.Close()
		dec := json.NewDecoder(f)
		row := 0
		for {
			var rec evidencetools.AuditRecord
			err := dec.Decode(&rec)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					e.add("verification-observations.jsonl row %d does not decode: %v", row, err)
				}
				break
			}
			row++
			validateObservationPayloadRef(e, dir, "verification-observations.jsonl", row, rec.Observation)
			if rec.Observation != nil && rec.Observation.ID != "" {
				ledger[rec.Observation.ID] = append(ledger[rec.Observation.ID], &rec)
			}
		}
	}
	// The deterministic lane's own ledger gets the same row discipline:
	// a row that does not decode or carries an unverifiable payload
	// reference is corruption, never lenient input. An absent ledger
	// stays tolerated for reports validated without a run directory.
	lanePath := filepath.Join(dir, "observations.jsonl")
	if f, err := os.Open(lanePath); err == nil {
		defer f.Close()
		dec := json.NewDecoder(f)
		row := 0
		for {
			var rec evidencetools.AuditRecord
			err := dec.Decode(&rec)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					e.add("observations.jsonl row %d does not decode: %v", row, err)
				}
				break
			}
			row++
			validateObservationPayloadRef(e, dir, "observations.jsonl", row, rec.Observation)
		}
	}
	pinned := map[string]bool{}
	for i := range r.EvidenceQuality.References {
		er := &r.EvidenceQuality.References[i]
		if er.Kind != "observation" || !strings.HasPrefix(er.Ref, "obs:") {
			continue
		}
		pinned[er.Ref] = true
		if er.Path == "" {
			e.add("evidence_quality.references[%s]: observation reference carries no pinned artifact path", er.Ref)
			continue
		}
		if !strings.HasPrefix(er.Path, "verification-artifacts/") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, er.Path))
		if err != nil {
			e.add("evidence_quality.references[%s]: pinned artifact %s unreadable: %v", er.Ref, er.Path, err)
			continue
		}
		sum := sha256.Sum256(b)
		if er.SHA256 == "" {
			e.add("evidence_quality.references[%s]: observation reference carries no sha256 pin", er.Ref)
		} else if got := hex.EncodeToString(sum[:]); got != er.SHA256 {
			e.add("evidence_quality.references[%s]: artifact %s sha256 mismatch: file %s recorded %s",
				er.Ref, er.Path, got, er.SHA256)
			continue
		}
		var artObs evidencetools.Observation
		if err := json.Unmarshal(b, &artObs); err != nil || artObs.ID == "" {
			e.add("evidence_quality.references[%s]: artifact %s is not an observation payload", er.Ref, er.Path)
			continue
		}
		if !strings.HasSuffix(er.Ref, ":"+artObs.ID) {
			e.add("evidence_quality.references[%s]: artifact payload carries observation id %s", er.Ref, artObs.ID)
			continue
		}
		rows := ledger[artObs.ID]
		if len(rows) > 1 {
			e.add("evidence_quality.references[%s]: %d ledger rows claim observation id %s", er.Ref, len(rows), artObs.ID)
			continue
		}
		if len(rows) == 0 {
			if cited[er.Ref] {
				e.add("decision cites observation %s with no matching verification-observations.jsonl row", er.Ref)
			}
			continue
		}
		recObs := rows[0].Observation
		if recObs == nil {
			e.add("evidence_quality.references[%s]: ledger row for %s carries no observation payload", er.Ref, artObs.ID)
			continue
		}
		lb, _ := json.Marshal(recObs)
		ab, _ := json.Marshal(&artObs)
		if !bytes.Equal(lb, ab) {
			e.add("evidence_quality.references[%s]: ledger row for %s does not match the pinned artifact payload", er.Ref, artObs.ID)
		}
	}
	for ref := range cited {
		if !pinned[ref] {
			e.add("decision cites observation %s with no pinned evidence_quality.references row", ref)
		}
	}
}

// validateSlice2 enforces the slice2-fidelity/1 extension contract
// (design §2, §3, §5). It runs only when the report advertises the
// extension; legacy reports omitting every extension field are
// unaffected.
// invalidReasonSet is the closed enum of extraction invalid_reason
// values (§2.7); shared by the attempts ledger and agent_output checks.
var invalidReasonSet = map[string]bool{
	InvalidNone: true, InvalidNoCandidate: true, InvalidMalformedJSON: true,
	InvalidAmbiguous: true, InvalidSchema: true,
	InvalidMissingCategory: true, InvalidMissingReasoning: true,
}

func (e *ValidationError) validateSlice2(r *Report, refs *refSpace) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	// Every new reference must resolve in the existing ref space.
	resolve := func(ref, where string) {
		if ref == "" || refs.agentSrc[ref] || refs.facts[ref] || refs.obs[ref] ||
			refs.adv[ref] || refs.agent[ref] {
			return
		}
		e.add("%s: ref %q does not resolve", where, ref)
	}

	// ---- contradictions (§2.2) ----
	kinds := map[string]bool{
		ContradictionCategoryVsComponentScope: true,
		ContradictionCategoryVsApplicability:  true,
		ContradictionCategoryVsAxis:           true,
		ContradictionAdvisoryScopeGap:         true,
		ContradictionAgentVsDeterministic:     true,
		ContradictionEvidenceScopeMismatch:    true,
	}
	resolutions := map[string]bool{
		ResolutionDeterministicPrevails: true,
		ResolutionScopeLimits:           true,
		ResolutionUnresolved:            true,
	}
	contraIDs := map[string]bool{}
	for _, c := range r.Contradictions {
		where := "contradictions[" + c.ID + "]"
		if contraIDs[c.ID] {
			e.add("%s: duplicate contradiction id", where)
		}
		contraIDs[c.ID] = true
		if !kinds[c.Kind] {
			e.add("%s: kind %q invalid", where, c.Kind)
		}
		if !resolutions[c.Resolution] {
			e.add("%s: resolution %q invalid", where, c.Resolution)
		}
		if c.AgentAssertionRef != nil {
			if !refs.agent[*c.AgentAssertionRef] {
				e.add("%s: agent_assertion_ref %q does not resolve", where, *c.AgentAssertionRef)
			}
		}
		for _, ref := range c.DeterministicRefs {
			resolve(ref, where+".deterministic_refs")
		}
	}
	// Invariant C: safe category + fixed covered component requires the
	// category_vs_component_scope record.
	pa := r.ProductApplicability
	if r.AgentOutput.Category != nil && safeCategories[*r.AgentOutput.Category] &&
		pa.ModulePresent == "TRUE" && pa.ResolvedVersion != nil && pa.VersionAffected == "FALSE" {
		found := false
		for _, c := range r.Contradictions {
			if c.Kind == ContradictionCategoryVsComponentScope {
				found = true
			}
		}
		if !found {
			e.add("contradictions: category_vs_component_scope required (safe category vs fixed covered component)")
		}
	}

	// ---- axes (§2.3) ----
	axisStatus := map[string]bool{
		AxisEstablished: true, AxisNotEstablished: true,
		AxisUnknown: true, AxisConflicted: true,
	}
	axisLevel := map[string]bool{
		LevelNone: true, LevelModule: true, LevelPackageBuild: true,
		LevelSymbol: true, LevelStaticCapability: true,
		LevelRuntimeAvailable: true, LevelDynamicReproduction: true,
	}
	axisBasis := map[string]bool{
		AxisBasisDeterministic: true, AxisBasisDynamic: true, AxisBasisNone: true,
	}
	for name, ax := range map[string]Axis{
		"code_reachability":           r.ExploitationAxes.CodeReachability,
		"attack_surface_availability": r.ExploitationAxes.AttackSurfaceAvailability,
		"exploitation_established":    r.ExploitationAxes.ExploitationEstablished,
	} {
		where := "exploitation_axes." + name
		if !axisStatus[ax.Status] {
			e.add("%s: status %q invalid", where, ax.Status)
		}
		if !axisLevel[ax.Level] {
			e.add("%s: level %q invalid", where, ax.Level)
		}
		if !axisBasis[ax.Basis] {
			e.add("%s: basis %q invalid", where, ax.Basis)
		}
		if ax.Basis == "agent" {
			e.add("%s: basis must never be agent", where)
		}
		if ax.Statement == "" {
			e.add("%s: statement required", where)
		}
		for _, ref := range ax.EvidenceRefs {
			resolve(ref, where+".evidence_refs")
		}
	}
	ex := r.ExploitationAxes.ExploitationEstablished
	if ex.Status == AxisEstablished && ex.Basis != AxisBasisDynamic {
		e.add("exploitation_axes.exploitation_established: ESTABLISHED requires dynamic basis")
	}
	// ESTABLISHED also requires ≥1 resolvable dynamic evidence ref: a
	// verified fact produced by a runtime/dynamic tool. A dynamic basis
	// label with empty, unresolvable, or purely static refs carries no
	// establishing evidence.
	if ex.Status == AxisEstablished {
		dynRef := false
		for _, ref := range ex.EvidenceRefs {
			if dynamicAxisTools[refs.factTool[ref]] {
				dynRef = true
			}
		}
		if !dynRef {
			e.add("exploitation_axes.exploitation_established: ESTABLISHED requires at least one evidence_ref resolving to a verified dynamic fact (runtime-observation|dynamic-trace|reproduction)")
		}
	}
	if ex.Basis == AxisBasisNone && ex.Status != AxisNotEstablished && ex.Status != AxisUnknown {
		e.add("exploitation_axes.exploitation_established: basis=none requires NOT_ESTABLISHED|UNKNOWN")
	}
	cr := r.ExploitationAxes.CodeReachability
	if cr.Basis == AxisBasisDeterministic && (cr.Level == LevelRuntimeAvailable || cr.Level == LevelDynamicReproduction) {
		e.add("exploitation_axes.code_reachability: level %s requires non-deterministic evidence", cr.Level)
	}

	// ---- applicability basis + conclusion scope (§2.4) ----
	paKinds := map[string]bool{
		ABComponentAbsent: true, ABVersionFixed: true, ABNotInImportClosure: true,
		ABImplementationAbsent: true,
		ABSDKVsDaemon:          true, ABComponentPresentAff: true, ABUnknownKind: true,
		ABRequiredConfigAbsent: true, ABVulnCodeNotReachable: true,
	}
	paStatus := map[string]bool{
		ABEstablished: true, ABProvisional: true, ABUnknown: true, ABContradicted: true,
	}
	paSource := map[string]bool{
		ABSourceDeterministic: true, ABSourceAgent: true,
		ABSourceMixed: true, ABSourceNone: true,
	}
	for _, b := range pa.Basis {
		where := "product_applicability.basis[" + b.Kind + "]"
		if !paKinds[b.Kind] {
			e.add("%s: kind invalid", where)
		}
		if !paStatus[b.Status] {
			e.add("%s: status %q invalid", where, b.Status)
		}
		if !paSource[b.Source] {
			e.add("%s: source %q invalid", where, b.Source)
		}
		for _, ref := range b.EvidenceRefs {
			resolve(ref, where+".evidence_refs")
		}
		for _, ref := range b.VerifiedEvidenceRefs {
			if !refs.facts[ref] {
				e.add("%s: verified_evidence_refs %q is not a verified fact", where, ref)
			}
			if f := refs.factByID[ref]; f != nil && f.Kind == FactKindBuildUsageScope {
				e.add("%s: verified_evidence_refs %q is a BUILD_USAGE_SCOPE fact; a build-closure audit fact can never carry an applicability basis", where, ref)
			}
		}
		if b.Status == ABEstablished && len(b.VerifiedEvidenceRefs) == 0 {
			e.add("%s: ESTABLISHED basis requires verified_evidence_refs", where)
		}
	}
	switch pa.ConclusionScope {
	case ScopeAffectedEntryOnly, ScopeAdvisorySet, ScopeCVEWide:
	default:
		e.add("product_applicability.conclusion_scope %q invalid", pa.ConclusionScope)
	}
	if pa.ConclusionScope == ScopeCVEWide && pa.AdvisoryScopeStatus != ScopeComplete {
		e.add("product_applicability: CVE_WIDE conclusion requires advisory_scope_status=COMPLETE")
	}
	switch pa.AdvisoryScopeStatus {
	case ScopeComplete, ScopeGapDetected, ScopeUnknown:
	default:
		e.add("product_applicability.advisory_scope_status %q invalid", pa.AdvisoryScopeStatus)
	}

	// ---- classification review (§2.4) ----
	crev := r.ClassificationReview
	switch crev.Class {
	case ClassNonApplicable, ClassApplicable, ClassUncertain, ClassNotEvaluated:
	default:
		e.add("classification_review.class %q invalid", crev.Class)
	}
	switch crev.Status {
	case StatusSupported, StatusUnknown, StatusConflicted, "NOT_EVALUATED":
	default:
		e.add("classification_review.status %q invalid", crev.Status)
	}
	for _, ref := range crev.BasisRefs {
		resolve(ref, "classification_review.basis_refs")
	}

	// ---- unknown prioritisation (§2.5) ----
	unkGroups := map[string]bool{
		"advisory_scope": true, "applicability": true, "code_reachability": true,
		"attack_surface": true, "exploitability": true, "runtime": true,
		"delivery": true, "evidence": true, "other": true,
		"build_usage_scope": true,
	}
	for _, u := range r.Unknowns {
		where := "unknowns[" + u.ID + "]"
		if !unkGroups[u.Group] {
			e.add("%s: group %q invalid", where, u.Group)
		}
		switch u.Priority {
		case UnknownPriorityDecisionChanging:
			if u.DecisionChangingFor == nil || strings.TrimSpace(*u.DecisionChangingFor) == "" {
				e.add("%s: DECISION_CHANGING requires decision_changing_for naming the conclusion", where)
			}
		case UnknownPriorityAppendix:
			if u.DecisionChangingFor != nil {
				e.add("%s: APPENDIX unknown must have decision_changing_for=null", where)
			}
		default:
			e.add("%s: priority %q invalid", where, u.Priority)
		}
	}

	// ---- exploitation-condition axis tags (§2.3) ----
	for _, c := range r.ExploitationConditions {
		switch c.Axis {
		case ECAxisCodeReachability, ECAxisAttackSurface, ECAxisExploitationEstablished, ECAxisOther:
		default:
			e.add("exploitation_conditions[%s]: axis %q invalid", c.ID, c.Axis)
		}
	}

	// ---- materiality (§2.6) ----
	checkMat := func(m *Materiality, where string) {
		if m == nil {
			return
		}
		switch m.Level {
		case MaterialityMaterial, MaterialitySupporting, MaterialityContext:
		default:
			e.add("%s: materiality.level %q invalid", where, m.Level)
		}
		if m.Level == MaterialityMaterial && m.RawBytes == nil && m.ReproducibleSource == nil {
			e.add("%s: MATERIAL requires raw_bytes or reproducible_source", where)
		}
		if m.RawBytes != nil && !hex64.MatchString(m.RawBytes.SHA256) {
			e.add("%s: materiality.raw_bytes.sha256 must be 64-hex", where)
		}
		if m.ReproducibleSource != nil {
			rs := m.ReproducibleSource
			switch rs.Kind {
			case "FILE", "COMMAND", "SNAPSHOT":
			default:
				e.add("%s: reproducible_source.kind %q invalid", where, rs.Kind)
			}
			if rs.OutputSHA256 != "" && !hex64.MatchString(rs.OutputSHA256) {
				e.add("%s: reproducible_source.output_sha256 must be 64-hex", where)
			}
		}
	}
	for _, f := range r.VerifiedFacts {
		checkMat(f.Materiality, "verified_facts["+f.ID+"].materiality")
	}
	for _, ref := range r.EvidenceQuality.References {
		checkMat(ref.Materiality, "evidence_quality.references["+ref.Ref+"].materiality")
	}

	// ---- attempts (§2.7) ----
	attemptStatus := map[string]bool{
		"OK": true, AgentTimeout: true, AgentFailed: true,
		AgentProviderRefused: true, AgentInvalidFormat: true, AgentNotRequested: true,
	}
	reasonCodes := map[string]bool{
		AttemptReasonInitial: true, AttemptReasonOperatorRetry: true,
		AttemptReasonInvalidExtraction: true, AttemptReasonTimeout: true,
		AttemptReasonProviderRefused: true, AttemptReasonInfrastructureFailure: true,
		AttemptReasonManualRecheck: true, AttemptReasonOther: true,
	}
	seenOrd := map[int]bool{}
	attemptIDs := map[string]bool{}
	for _, at := range r.Run.Attempts {
		where := "run.attempts[" + at.ID + "]"
		if attemptIDs[at.ID] {
			e.add("%s: duplicate attempt id", where)
		}
		attemptIDs[at.ID] = true
		if at.Kind != "deterministic" && at.Kind != "agent" {
			e.add("%s: kind %q invalid", where, at.Kind)
		}
		if seenOrd[at.Ordinal] {
			e.add("%s: duplicate ordinal %d", where, at.Ordinal)
		}
		seenOrd[at.Ordinal] = true
		if !attemptStatus[at.Status] {
			e.add("%s: status %q invalid", where, at.Status)
		}
		if !reasonCodes[at.ReasonCode] {
			e.add("%s: reason_code %q invalid", where, at.ReasonCode)
		}
		if at.RetryOf != nil && !attemptIDs[*at.RetryOf] {
			e.add("%s: retry_of %q does not resolve to an earlier attempt", where, *at.RetryOf)
		}
		if at.RetryOf != nil && !at.OriginalPreserved {
			e.add("%s: retries must set original_preserved=true", where)
		}
		if at.Extraction != nil {
			ex := at.Extraction
			e.checkExtraction(ex, where+".extraction")
		}
	}
	// agent_output attempt linkage.
	if r.AgentOutput.AttemptID != nil && !attemptIDs[*r.AgentOutput.AttemptID] {
		e.add("agent_output.attempt_id %q does not resolve to a recorded attempt", *r.AgentOutput.AttemptID)
	}
	if r.AgentOutput.Extraction != nil {
		e.checkExtraction(r.AgentOutput.Extraction, "agent_output.extraction")
	}
}

// checkExtraction validates the shared extraction record (§2.7). The
// optional recovery marker is restricted to the bounded repairs and is
// only meaningful on a VALID selection; legacy reports omit it.
func (e *ValidationError) checkExtraction(ex *Extraction, where string) {
	switch ex.Status {
	case ExtractionValid, ExtractionInvalid, ExtractionNotApplicable:
	default:
		e.add("%s: extraction.status %q invalid", where, ex.Status)
	}
	if !invalidReasonSet[ex.InvalidReason] {
		e.add("%s: extraction.invalid_reason %q invalid", where, ex.InvalidReason)
	}
	switch ex.Recovery {
	case "", RecoveryBraceCompletion, RecoveryMemberSalvage:
	default:
		e.add("%s: extraction.recovery %q invalid", where, ex.Recovery)
	}
	if ex.Recovery != "" && ex.Status != ExtractionValid {
		e.add("%s: extraction.recovery %q on a non-VALID extraction", where, ex.Recovery)
	}
}

// validateSnapshotTarget enforces the typed target provenance: a record
// must validate on its own, and its GOOS/GOARCH/build-tag facts must be
// exactly the snapshot fields they describe (a target that disagrees with
// the recorded build context would make every platform conclusion
// unreproducible).
func validateSnapshotTarget(e *ValidationError, in SnapshotInput) {
	t := in.Target
	if t == nil {
		return
	}
	if err := t.Validate(); err != nil {
		e.add("input.snapshot.target: %v", err)
		return
	}
	if t.GOOS != in.GOOS || t.GOARCH != in.GOARCH {
		e.add("input.snapshot.target %s/%s disagrees with snapshot goos/goarch %s/%s", t.GOOS, t.GOARCH, in.GOOS, in.GOARCH)
	}
	if !slices.Equal(t.BuildTags, in.BuildTags) {
		e.add("input.snapshot.target build_tags %v disagree with snapshot build_tags %v", t.BuildTags, in.BuildTags)
	}
}

// validateSlice2V2 enforces the slice2-fidelity/2 contract on top of the
// shared slice-2 checks: per-entry evaluation bookkeeping, the
// fixed-vs-absent separation, check scopes on every basis, the
// three-valued transition semantics, and the attack_scenario status
// rules. It runs only when the /2 marker is advertised.
func (e *ValidationError) validateSlice2V2(r *Report, refs *refSpace) {
	pa := r.ProductApplicability

	// (a) required /2 fields; every emitted basis names its check scope.
	entryStatusEnum := map[string]bool{
		EntryAffected: true, EntryFixed: true, EntryUnknown: true,
		EntryNotEvaluated: true, EntryMixed: true,
	}
	vcrEnum := map[string]bool{
		VCRTrue: true, VCRFalse: true, VCRUnknown: true, VCRNotEvaluated: true,
	}
	if !entryStatusEnum[pa.AdvisoryEntryStatus] {
		e.add("product_applicability.advisory_entry_status %q missing or invalid under slice2-fidelity/2", pa.AdvisoryEntryStatus)
	}
	if !vcrEnum[pa.VulnerableCodeReachability] {
		e.add("product_applicability.vulnerable_code_reachability %q missing or invalid under slice2-fidelity/2", pa.VulnerableCodeReachability)
	}
	for _, b := range pa.Basis {
		where := "product_applicability.basis[" + b.Kind + "]"
		if strings.TrimSpace(b.CheckScope) == "" {
			e.add("%s: check_scope is required under slice2-fidelity/2", where)
		}
	}

	// (b) evaluated_entry_ids is optional on the wire (omitempty): an
	// absent/empty list means an empty evaluated set — an advisory with
	// no evaluable Go entries is legitimate, not a contract violation.
	// Every listed id must resolve into affected_implementations, and the
	// list must equal the per-entry evaluation set the checked/selected/
	// pending module sets imply — evaluated_entry_ids and the per-entry
	// table can never drift apart.
	implIDs := map[string]bool{}
	for _, im := range r.AffectedImplementations {
		implIDs[im.ID] = true
	}
	for _, id := range pa.EvaluatedEntryIDs {
		if !implIDs[id] {
			e.add("product_applicability.evaluated_entry_ids: %q does not resolve to an affected_implementations id", id)
		}
	}
	wantIDs := map[string]bool{}
	for _, id := range evaluatedEntryIDs(r.AffectedImplementations, pa) {
		wantIDs[id] = true
	}
	seenEval := map[string]bool{}
	for _, id := range pa.EvaluatedEntryIDs {
		if seenEval[id] {
			e.add("product_applicability.evaluated_entry_ids: duplicate id %q", id)
		}
		seenEval[id] = true
		if !wantIDs[id] {
			e.add("product_applicability.evaluated_entry_ids: %q is not an evaluated entry under the recorded module sets", id)
		}
	}
	for id := range wantIDs {
		if !seenEval[id] {
			e.add("product_applicability.evaluated_entry_ids: evaluated entry %q is missing from the list", id)
		}
	}
	// An empty evaluated set carries no fix/affected verdict: the only
	// consistent aggregate is NOT_EVALUATED.
	if len(pa.EvaluatedEntryIDs) == 0 && len(wantIDs) == 0 &&
		entryStatusEnum[pa.AdvisoryEntryStatus] &&
		pa.AdvisoryEntryStatus != EntryNotEvaluated {
		e.add("product_applicability.advisory_entry_status=%q requires NOT_EVALUATED when no advisory entry was evaluated", pa.AdvisoryEntryStatus)
	}
	// The aggregate is recomputed from the per-entry verdicts; a forged
	// status (e.g. MIXED without both a fixed and an affected entry, or
	// FIXED while the aggregate data decides otherwise) is rejected.
	if want := aggregateEntryStatus(r.AffectedImplementations, pa); pa.AdvisoryEntryStatus != want {
		e.add("product_applicability.advisory_entry_status=%q inconsistent with the per-entry verdicts implied by checked/selected/pending modules (aggregate %q)", pa.AdvisoryEntryStatus, want)
	}

	// (c) FIXED requires the fixed-entry evidence shape.
	if pa.AdvisoryEntryStatus == EntryFixed {
		if pa.ModulePresent != "TRUE" || pa.VersionAffected != "FALSE" || pa.ResolvedVersion == nil {
			e.add("product_applicability: advisory_entry_status=FIXED requires module_present=TRUE, version_affected=FALSE and a resolved_version")
		}
	}

	// (d) FALSE on package/build/vulnerable-code fields is forbidden on
	// the fixed branch and whenever the fix status was not evaluated for
	// a present module — those values were never checked. A genuinely
	// absent module may still carry FALSE via the component_absent
	// basis.
	// The ban targets the defect: an entry whose version/fix status decided
	// the outcome, or one that was never evaluated, has no package/build
	// probe behind it — FALSE there would claim absence without a check.
	// A present module with an undecidable version (UNKNOWN) or a mixture
	// (MIXED) did run the package probe, so a FALSE result is legitimate
	// and stays governed by rule (e).
	forbidFalse := pa.ModulePresent == "TRUE" &&
		(pa.AdvisoryEntryStatus == EntryFixed || pa.AdvisoryEntryStatus == EntryNotEvaluated)
	if forbidFalse {
		if pa.PackagePresent == "FALSE" {
			e.add("product_applicability.package_present=FALSE forbidden while advisory_entry_status=%s (module present, probe not decisive)", pa.AdvisoryEntryStatus)
		}
		if pa.BuildRelevant == "FALSE" {
			e.add("product_applicability.build_relevant=FALSE forbidden while advisory_entry_status=%s (module present, probe not decisive)", pa.AdvisoryEntryStatus)
		}
		if pa.VulnerableCodeReachability == VCRFalse {
			e.add("product_applicability.vulnerable_code_reachability=FALSE forbidden while advisory_entry_status=%s (module present, probe not decisive)", pa.AdvisoryEntryStatus)
		}
	}

	// isProbeFact reports whether ref resolves to a verified fact produced
	// by an applicability-probe tool — the only evidence class that can
	// back product_applicability conclusions (reachability TRUE and the
	// APPLICABLE classification).
	isProbeFact := func(ref string) bool {
		t := refs.factTool[ref]
		return t == "affected-resolve" || t == "get_module_version"
	}

	// (e)/(f) vulnerable_code_reachability evidence rules. The negative
	// basis must not merely exist — it must be consistent with the
	// applicability fields it grounds: component_absent supports FALSE
	// only when the module is genuinely absent; package_not_in_import_closure
	// only when a present module's package/build probe evaluated FALSE.
	// Verified refs are additionally required to resolve into
	// verified_facts (forged ids never underwrite a negative).
	verifiedNeg := false
	for _, b := range pa.Basis {
		if b.Status != ABEstablished || b.Source != ABSourceDeterministic {
			continue
		}
		resolves := false
		for _, ref := range b.VerifiedEvidenceRefs {
			if refs.facts[ref] {
				resolves = true
			}
		}
		if !resolves {
			continue
		}
		switch b.Kind {
		case ABComponentAbsent:
			if pa.ModulePresent == "FALSE" {
				verifiedNeg = true
			}
		case ABNotInImportClosure:
			if pa.ModulePresent == "TRUE" &&
				(pa.PackagePresent == "FALSE" || pa.BuildRelevant == "FALSE") {
				verifiedNeg = true
			}
		case ABImplementationAbsent:
			if pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE" &&
				pa.VulnerableImplementationPresent == "FALSE" &&
				pa.ImplementationTargetScope == "product" {
				verifiedNeg = true
			}
		}
	}
	if pa.VulnerableCodeReachability == VCRFalse && !verifiedNeg {
		e.add("product_applicability.vulnerable_code_reachability=FALSE requires an ESTABLISHED deterministic component_absent (module_present=FALSE) or package_not_in_import_closure (module_present=TRUE with package_present/build_relevant=FALSE) basis with verified refs consistent with the applicability fields")
	}
	// A PACKAGE_USAGE fact is a bounded product-source usage result: it
	// can never underwrite vulnerable_code_reachability=FALSE — not as a
	// reachability evidence ref and not inside a negative basis (a
	// no-product-source-use negative is not a component-absence or
	// import-closure result, and a degraded scope is never negative
	// proof at all). The fact may exist elsewhere in the report; it is
	// rejected only where it is cited to carry the reachability FALSE.
	if pa.VulnerableCodeReachability == VCRFalse {
		isUsageRef := func(ref string) bool {
			f := refs.factByID[ref]
			return f != nil && f.Kind == FactKindPackageUsage
		}
		isBuildUsageRef := func(ref string) bool {
			f := refs.factByID[ref]
			return f != nil && f.Kind == FactKindBuildUsageScope
		}
		for _, ref := range pa.EvidenceRefs {
			if isUsageRef(ref) {
				e.add("product_applicability.evidence_refs %q is a PACKAGE_USAGE fact; a bounded product-source usage result can never underwrite vulnerable_code_reachability=FALSE", ref)
			}
			if isBuildUsageRef(ref) {
				e.add("product_applicability.evidence_refs %q is a BUILD_USAGE_SCOPE fact; a build-closure classification can never underwrite vulnerable_code_reachability=FALSE", ref)
			}
		}
		for _, b := range pa.Basis {
			for _, ref := range b.EvidenceRefs {
				if isUsageRef(ref) {
					e.add("product_applicability.basis[%s].evidence_refs %q is a PACKAGE_USAGE fact; a bounded usage result can never carry a reachability FALSE", b.Kind, ref)
				}
				if isBuildUsageRef(ref) {
					e.add("product_applicability.basis[%s].evidence_refs %q is a BUILD_USAGE_SCOPE fact; a build-closure classification can never carry a reachability FALSE", b.Kind, ref)
				}
			}
			for _, ref := range b.VerifiedEvidenceRefs {
				if isUsageRef(ref) {
					e.add("product_applicability.basis[%s].verified_evidence_refs %q is a PACKAGE_USAGE fact; a bounded usage result can never carry a reachability FALSE", b.Kind, ref)
				}
				if isBuildUsageRef(ref) {
					e.add("product_applicability.basis[%s].verified_evidence_refs %q is a BUILD_USAGE_SCOPE fact; a build-closure classification can never carry a reachability FALSE", b.Kind, ref)
				}
			}
		}
	}
	// TRUE asserts the package/build probe actually ran and linked the
	// affected code: the enum triple is necessary but not sufficient —
	// at least one resolved verified fact from an applicability probe
	// tool (affected-resolve / get_module_version) must back the claim,
	// either directly in evidence_refs or via an ESTABLISHED basis.
	if pa.VulnerableCodeReachability == VCRTrue {
		if pa.AdvisoryEntryStatus != EntryAffected || pa.PackagePresent != "TRUE" || pa.BuildRelevant != "TRUE" {
			e.add("product_applicability.vulnerable_code_reachability=TRUE requires advisory_entry_status=AFFECTED and package_present/build_relevant=TRUE")
		}
		probeFact := false
		for _, ref := range pa.EvidenceRefs {
			if isProbeFact(ref) {
				probeFact = true
			}
		}
		for _, b := range pa.Basis {
			if b.Status != ABEstablished {
				continue
			}
			for _, ref := range b.VerifiedEvidenceRefs {
				if isProbeFact(ref) {
					probeFact = true
				}
			}
		}
		if !probeFact {
			e.add("product_applicability.vulnerable_code_reachability=TRUE requires a resolved verified fact from an applicability probe (affected-resolve|get_module_version) in evidence_refs or an ESTABLISHED basis")
		}
	}

	// (g)/(h) basis provenance rules.
	for _, b := range pa.Basis {
		where := "product_applicability.basis[" + b.Kind + "]"
		if b.Status == ABEstablished {
			if b.Source != ABSourceDeterministic {
				e.add("%s: ESTABLISHED basis requires source=deterministic", where)
			}
			if len(b.VerifiedEvidenceRefs) == 0 {
				e.add("%s: ESTABLISHED basis requires non-empty verified_evidence_refs", where)
			}
			for _, ref := range b.VerifiedEvidenceRefs {
				if !refs.facts[ref] {
					e.add("%s: verified_evidence_refs %q is not a verified fact", where, ref)
				}
			}
		}
		if b.Status == ABProvisional {
			if b.Source != ABSourceAgent {
				e.add("%s: PROVISIONAL basis requires source=agent", where)
			}
			if len(b.VerifiedEvidenceRefs) != 0 {
				e.add("%s: PROVISIONAL basis must not carry verified_evidence_refs", where)
			}
		}
	}

	// (k)/(l) attack_scenario status rules.
	ex := r.ExploitationAxes.ExploitationEstablished
	switch r.AttackScenario.Status {
	case StatusSupported:
		if ex.Status != AxisEstablished {
			e.add("attack_scenario.status=SUPPORTED requires exploitation_axes.exploitation_established=ESTABLISHED")
		}
	case StatusPartial:
		detTransitions, reqUnknown := 0, 0
		for _, c := range r.ExploitationConditions {
			if c.Origin != OriginDeterm {
				continue
			}
			switch c.State {
			case StateSupported:
				// Only exploit-path predicates backed by a verified fact
				// count as confirmed transitions.
				if transitionSubjects[c.Subject] {
					hasFact := false
					for _, ref := range c.EvidenceRefs {
						if refs.facts[ref] {
							hasFact = true
						}
					}
					if hasFact {
						detTransitions++
					}
				}
			case StateUnknown:
				if c.Necessity == "required" {
					reqUnknown++
				}
			}
		}
		if detTransitions == 0 || reqUnknown == 0 {
			e.add("attack_scenario.status=PARTIAL requires at least one confirmed deterministic path transition and at least one required UNKNOWN transition")
		}
		if !strings.Contains(r.AttackScenario.Summary, "exploit path is not established") {
			e.add("attack_scenario.status=PARTIAL requires the summary marker 'exploit path is not established'")
		}
	}

	// (m) a not-evaluated reachability axis must say so.
	if pa.VulnerableCodeReachability == VCRNotEvaluated {
		axis := r.ExploitationAxes.CodeReachability
		marked := false
		for _, lim := range axis.Limitations {
			if strings.Contains(lim, "not evaluated") {
				marked = true
			}
		}
		if !marked {
			e.add("exploitation_axes.code_reachability: vulnerable_code_reachability=NOT_EVALUATED requires a limitation stating the reachability check was not evaluated")
		}
	}

	// (n) replay provenance: a replayed agent_output must name its source
	// directory, carry the retained-answer digest whenever the persisted
	// record pins an answer artifact, resolve to exactly one kind=agent
	// ledger row recorded as a manual recheck, and must not co-exist with
	// live-run harness pins (run.harness stays null on a replay).
	if rf := r.AgentOutput.ReplayedFrom; rf != nil {
		hex64v := regexp.MustCompile(`^[0-9a-f]{64}$`)
		if strings.TrimSpace(rf.Dir) == "" {
			e.add("agent_output.replayed_from.dir is required when replayed_from is present")
		}
		if rf.AnswerSHA256 != "" && !hex64v.MatchString(rf.AnswerSHA256) {
			e.add("agent_output.replayed_from.answer_sha256 %q must be 64-hex", rf.AnswerSHA256)
		}
		if rf.ResultSHA256 != "" && !hex64v.MatchString(rf.ResultSHA256) {
			e.add("agent_output.replayed_from.result_sha256 %q must be 64-hex", rf.ResultSHA256)
		}
		var resolved, theAgent *Attempt
		agentRows := 0
		for i := range r.Run.Attempts {
			at := &r.Run.Attempts[i]
			if r.AgentOutput.AttemptID != nil && at.ID == *r.AgentOutput.AttemptID {
				resolved = at
			}
			if at.Kind == "agent" {
				agentRows++
				theAgent = at
			}
		}
		if agentRows != 1 {
			e.add("agent_output.replayed_from requires exactly one kind=agent attempt row (the replayed one), got %d", agentRows)
		}
		saved := resolved
		if saved == nil {
			saved = theAgent
		}
		if resolved != nil && resolved.Kind != "agent" {
			e.add("agent_output.attempt_id %q resolves to a kind=%q row, expected the replayed agent attempt", *r.AgentOutput.AttemptID, resolved.Kind)
		}
		if resolved != nil && resolved.ReasonCode != AttemptReasonManualRecheck {
			e.add("run.attempts[%s]: the attempt a replayed agent_output resolves to must carry reason_code=manual_recheck, got %q", resolved.ID, resolved.ReasonCode)
		}
		answerPinned := r.AgentOutput.AnswerArtifact != nil ||
			(saved != nil && saved.Extraction != nil && saved.Extraction.AnswerArtifact != nil)
		if answerPinned && rf.AnswerSHA256 == "" {
			e.add("agent_output.replayed_from.answer_sha256 is required when the persisted attempt pins an answer artifact")
		}
		live := r.Run.Harness
		if live.Path != nil || live.Commit != nil || live.PatchSHA256 != nil ||
			live.E6PreflightReport != nil || live.E6PreflightSHA256 != nil ||
			live.Image != nil || live.ImageSHA256 != nil ||
			live.PromptPath != nil || live.PromptSHA256 != nil {
			e.add("agent_output.replayed_from is incompatible with live agent-turn harness pins: a replayed run performs no model call")
		}
	}

	// classification_review class/status matrix (closed under /2):
	// SUPPORTED is allowed only where the assembler can emit it, and each
	// allowed class requires its own deterministic carrier —
	//   APPLICABLE+SUPPORTED:     module_present=TRUE + version_affected=TRUE
	//                             plus ≥1 applicability-probe fact cited in
	//                             basis_refs;
	//   NON_APPLICABLE+SUPPORTED: an ESTABLISHED deterministic
	//                             component_absent or
	//                             package_not_in_import_closure basis whose
	//                             verified refs are cited in basis_refs
	//                             (version_fixed proves a fix, never
	//                             absence; provisional bases and unrelated
	//                             verified facts do not count);
	//   UNCERTAIN / NOT_EVALUATED: never SUPPORTED (nothing was decided or
	//                             established).
	if r.ClassificationReview.Status == StatusSupported {
		cited := map[string]bool{}
		for _, ref := range r.ClassificationReview.BasisRefs {
			cited[ref] = true
		}
		switch r.ClassificationReview.Class {
		case ClassApplicable:
			if pa.ModulePresent != "TRUE" || pa.VersionAffected != "TRUE" {
				e.add("classification_review: APPLICABLE+SUPPORTED requires module_present=TRUE and version_affected=TRUE")
			}
			probeCited := false
			for ref := range cited {
				if isProbeFact(ref) {
					probeCited = true
				}
			}
			if !probeCited {
				e.add("classification_review: APPLICABLE+SUPPORTED requires basis_refs to cite a verified fact from an applicability probe (affected-resolve|get_module_version)")
			}
		case ClassNonApplicable:
			// The carrier basis must be consistent with the fields it
			// grounds — the same consistency the reachability rule
			// demands — so a stray component_absent basis under
			// module_present=TRUE cannot carry the class.
			carrier := false
			for _, b := range pa.Basis {
				if b.Status != ABEstablished || b.Source != ABSourceDeterministic {
					continue
				}
				consistent := false
				switch b.Kind {
				case ABComponentAbsent:
					consistent = pa.ModulePresent == "FALSE"
				case ABNotInImportClosure:
					consistent = pa.ModulePresent == "TRUE" &&
						(pa.PackagePresent == "FALSE" || pa.BuildRelevant == "FALSE")
				case ABImplementationAbsent:
					consistent = pa.ModulePresent == "TRUE" && pa.VersionAffected == "TRUE" &&
						pa.VulnerableImplementationPresent == "FALSE" &&
						pa.ImplementationTargetScope == "product"
				}
				if !consistent {
					continue
				}
				for _, ref := range b.VerifiedEvidenceRefs {
					if f := refs.factByID[ref]; f != nil && (f.Kind == FactKindPackageUsage || f.Kind == FactKindBuildUsageScope) {
						// B42 usage and B41 build-closure facts are bounded
						// audit results, never non-applicability carriers.
						continue
					}
					if refs.facts[ref] && cited[ref] {
						carrier = true
					}
				}
			}
			if !carrier {
				e.add("classification_review: NON_APPLICABLE+SUPPORTED requires an ESTABLISHED deterministic component_absent, package_not_in_import_closure or vulnerable_implementation_absent basis whose verified refs are cited in basis_refs (version_fixed never supports a non-applicability class)")
			}
		case ClassUncertain, ClassNotEvaluated:
			e.add("classification_review: class %s can never be SUPPORTED under slice2-fidelity/2",
				r.ClassificationReview.Class)
		}
	}
}

// validateSlice2V3 enforces the slice2-fidelity/3 ladder contract on top
// of the shared /1 and /2 checks: a mandatory evidence_level object,
// closed level/basis/role enums, the condition-role matrix, ref-space
// restrictions, the attack_scenario status cross-rules, and a verbatim
// recomputation of the ladder through the same pure helper the
// assembler runs. The stored value is never trusted: any deviation
// between the asserted object and the recomputed one — a forged level,
// a stale list, a missing ref — is a contract violation, never a silent
// downgrade.
func (e *ValidationError) validateSlice2V3(r *Report, refs *refSpace) {
	el := r.EvidenceLevel
	if el == nil {
		e.add("evidence_level is required under slice2-fidelity/3")
	}

	// Condition-role matrix. The role is a derived field: deterministic
	// conditions must carry exactly the fixed subject-table role, an
	// agent canonical path hypothesis must stay role=path + OPEN +
	// required (it blocks L1), and a non-normalizable agent claim must
	// stay role=supporting (never a path blocker, never an evidence
	// carrier). Any other role is not a value the assembler produces.
	roleSet := map[string]bool{
		ConditionRoleApplicability: true, ConditionRolePath: true,
		ConditionRoleDeployment: true, ConditionRoleSupporting: true,
	}
	condIDs := map[string]bool{}
	for _, c := range r.ExploitationConditions {
		if condIDs[c.ID] {
			e.add("exploitation_conditions[%s]: duplicate condition id", c.ID)
		}
		condIDs[c.ID] = true
		where := "exploitation_conditions[" + c.ID + "]"
		if c.Origin == OriginAgent {
			// An agent condition is an unevaluated hypothesis: it may
			// cite only its own agent material — the paired assertion id
			// or an indexed agent-src: ref. A resolvable verified fact,
			// observation or advisory ref would let agent material act
			// as a deterministic evidence carrier, so it is rejected
			// outright (the derivation-side ref exclusion lives in
			// slice2.go).
			for _, ref := range c.EvidenceRefs {
				if !refs.agent[ref] && !strings.HasPrefix(ref, "agent-src:") {
					e.add("%s: agent condition evidence_ref %q must reference agent material (agent assertion or agent-src); deterministic/observation/advisory refs are forbidden", where, ref)
				}
			}
		}
		if !roleSet[c.Role] {
			e.add("%s: role %q invalid under slice2-fidelity/3", where, c.Role)
			continue
		}
		switch c.Origin {
		case OriginDeterm:
			if want := conditionRoleForSubject(c.Subject); c.Role != want {
				e.add("%s: role=%s on deterministic subject %q invalid (requires %s)",
					where, c.Role, c.Subject, want)
			}
		case OriginAgent:
			if canonicalPathSubject(c.Subject) != "" {
				if c.Role != ConditionRolePath || c.State != StateOpen || c.Necessity != "required" {
					e.add("%s: agent canonical path claim requires role=path state=OPEN necessity=required (got %s/%s/%s)",
						where, c.Role, c.State, c.Necessity)
				}
			} else if c.Role != ConditionRoleSupporting {
				e.add("%s: non-canonical agent claim requires role=supporting, got %q", where, c.Role)
			}
		}
	}

	if el == nil {
		return
	}

	// Closed enums and required members.
	switch el.Level {
	case EvidenceLevelL1, EvidenceLevelL2, EvidenceLevelL3:
	default:
		e.add("evidence_level.level %q invalid", el.Level)
	}
	switch el.Basis {
	case EvidenceBasisNone, EvidenceBasisDeterministic, EvidenceBasisDynamic:
	default:
		e.add("evidence_level.basis %q invalid", el.Basis)
	}
	if strings.TrimSpace(el.Statement) == "" {
		e.add("evidence_level.statement is required")
	}
	if strings.TrimSpace(el.Scope) == "" {
		e.add("evidence_level.scope is required")
	}

	// condition_refs: non-empty when the ledger is non-empty, duplicate-
	// free, and every id must resolve into exploitation_conditions.
	if len(r.ExploitationConditions) > 0 && len(el.ConditionRefs) == 0 {
		e.add("evidence_level.condition_refs must be non-empty while exploitation_conditions is non-empty")
	}
	seenRef := map[string]bool{}
	for _, id := range el.ConditionRefs {
		if seenRef[id] {
			e.add("evidence_level.condition_refs: duplicate id %q", id)
		}
		seenRef[id] = true
		if !condIDs[id] {
			e.add("evidence_level.condition_refs %q does not resolve to an exploitation_conditions id", id)
		}
	}

	// evidence_refs resolve only into verified_facts: agent-source refs,
	// agent assertion ids, observation-only refs and advisory refs can
	// never carry the ladder.
	for _, ref := range el.EvidenceRefs {
		if strings.HasPrefix(ref, "agent-src:") || refs.agent[ref] {
			e.add("evidence_level.evidence_refs %q is an agent-origin ref; agent material is never ladder evidence", ref)
			continue
		}
		if !refs.facts[ref] {
			e.add("evidence_level.evidence_refs %q is not a verified fact", ref)
		}
		if f := refs.factByID[ref]; f != nil && f.Kind == FactKindBuildUsageScope {
			e.add("evidence_level.evidence_refs %q is a BUILD_USAGE_SCOPE fact; a build-closure audit fact is strictly non-carrier and never ladder evidence", ref)
		}
	}

	// blocking_conditions ⊆ condition_refs.
	for _, id := range el.BlockingConditions {
		if !seenRef[id] {
			e.add("evidence_level.blocking_conditions %q is not listed in condition_refs", id)
		}
	}

	// Per-level carrier rules. Under L1 every required applicability/
	// path condition must be closed by an OK verified fact from the
	// static carrier allowlist. Under L3 the evidence list is exactly
	// the dynamic carriers: each ref must resolve to an OK fact from the
	// closed dynamic tool set, and at least one must exist.
	switch el.Level {
	case EvidenceLevelL1:
		for _, c := range r.ExploitationConditions {
			if c.Necessity != "required" ||
				(c.Role != ConditionRoleApplicability && c.Role != ConditionRolePath) {
				continue
			}
			closed := false
			for _, ref := range c.EvidenceRefs {
				if refs.facts[ref] && staticCarrierTools[refs.factTool[ref]] {
					closed = true
				}
			}
			if !closed {
				e.add("evidence_level.level=L1 requires every required applicability/path condition closed by an OK verified fact from the static carrier tool set; %s is unresolved", c.ID)
			}
		}
	case EvidenceLevelL3:
		dyn := 0
		for _, ref := range el.EvidenceRefs {
			if refs.facts[ref] && dynamicAxisTools[refs.factTool[ref]] {
				dyn++
			}
		}
		if dyn == 0 {
			e.add("evidence_level.level=L3 requires at least one evidence_ref resolving to a verified fact from a dynamic tool (runtime-observation|dynamic-trace|reproduction)")
		}
		for _, ref := range el.EvidenceRefs {
			if refs.facts[ref] && !dynamicAxisTools[refs.factTool[ref]] {
				e.add("evidence_level.evidence_refs %q is not a dynamic-carrier fact (tool %q); L3 evidence is dynamic proof only", ref, refs.factTool[ref])
			}
		}
	}

	// attack_scenario cross-rules. SUPPORTED and PARTIAL pin the level;
	// a level can never carry a status the ladder contradicts.
	ex := r.ExploitationAxes.ExploitationEstablished
	if el.Level == EvidenceLevelL3 &&
		(ex.Status != AxisEstablished || ex.Basis != AxisBasisDynamic || ex.Level != LevelDynamicReproduction) {
		e.add("evidence_level.level=L3 requires exploitation_axes.exploitation_established status=ESTABLISHED basis=dynamic level=DYNAMIC_REPRODUCTION")
	}
	if el.Level == EvidenceLevelL3 && r.AttackScenario.Status != StatusSupported {
		e.add("evidence_level.level=L3 requires attack_scenario.status=SUPPORTED")
	}
	if r.AttackScenario.Status == StatusSupported && el.Level != EvidenceLevelL3 {
		e.add("attack_scenario.status=SUPPORTED requires evidence_level.level=L3_DYNAMIC_EXPLOITATION")
	}
	if r.AttackScenario.Status == StatusPartial {
		if el.Level != EvidenceLevelL2 {
			e.add("attack_scenario.status=PARTIAL requires evidence_level.level=L2_POTENTIAL_PATH")
		}
		// PARTIAL requires a path-role gap: at least one confirmed
		// deterministic role=path transition plus at least one required
		// role=path condition still unresolved. Deployment and
		// supporting gaps — and agent-origin OPEN hypotheses — can never
		// create PARTIAL on their own.
		detTransitions, reqUnknown := 0, 0
		for _, c := range r.ExploitationConditions {
			if c.Origin != OriginDeterm || c.Role != ConditionRolePath {
				continue
			}
			switch c.State {
			case StateSupported:
				for _, ref := range c.EvidenceRefs {
					// A B41 build-closure fact is non-carrier: it can never
					// count as a confirmed path transition.
					if f := refs.factByID[ref]; f != nil && f.Kind != FactKindBuildUsageScope {
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
		if detTransitions == 0 || reqUnknown == 0 {
			e.add("attack_scenario.status=PARTIAL requires at least one confirmed deterministic role=path transition and at least one unresolved required role=path condition")
		}
	}
	switch {
	case el.Level == EvidenceLevelL3:
		if el.Basis != EvidenceBasisDynamic {
			e.add("evidence_level.level=L3 requires basis=dynamic")
		}
	case el.Basis == EvidenceBasisDynamic:
		e.add("evidence_level.basis=dynamic is only valid with level=L3_DYNAMIC_EXPLOITATION")
	}

	// Fail-closed recomputation: the stored evidence_level must equal
	// the object the same pure helper derives from this report,
	// member for member — level, basis, statement, scope, refs,
	// blockers and limitations. Any forged, stale or hand-edited value
	// is a violation, never a downgrade.
	want := deriveEvidenceLevel(r)
	if el.Level != want.Level {
		e.add("evidence_level.level=%q does not match recomputed %q", el.Level, want.Level)
	}
	if el.Basis != want.Basis {
		e.add("evidence_level.basis=%q does not match recomputed %q", el.Basis, want.Basis)
	}
	if el.Statement != want.Statement {
		e.add("evidence_level.statement %q does not match recomputed %q", el.Statement, want.Statement)
	}
	if el.Scope != want.Scope {
		e.add("evidence_level.scope %q does not match recomputed %q", el.Scope, want.Scope)
	}
	if !slices.Equal(el.ConditionRefs, want.ConditionRefs) {
		e.add("evidence_level.condition_refs %v do not match recomputed %v", el.ConditionRefs, want.ConditionRefs)
	}
	if !slices.Equal(el.EvidenceRefs, want.EvidenceRefs) {
		e.add("evidence_level.evidence_refs %v do not match recomputed %v", el.EvidenceRefs, want.EvidenceRefs)
	}
	if !slices.Equal(el.BlockingConditions, want.BlockingConditions) {
		e.add("evidence_level.blocking_conditions %v do not match recomputed %v", el.BlockingConditions, want.BlockingConditions)
	}
	if !slices.Equal(el.Limitations, want.Limitations) {
		e.add("evidence_level.limitations %v do not match recomputed %v", el.Limitations, want.Limitations)
	}

	// Optional B41 audit axis: presence tracks the BUILD_USAGE_SCOPE
	// fact ledger, and the stored object must equal the recomputed one
	// — fail-closed, the same helper the assembler ran.
	validateBuildUsageScopeAxis(e, r)
}

// validatePackageUsageFact enforces the package-usage fact contract.
// An empty kind stays valid for legacy facts; a package-usage fact is
// marked on both sides (a package-usage kind ⇔ tool=package-usage),
// carries a structured usage_subject binding, and claims exactly what
// the promotion path can emit: a genuine verdict (kind=PACKAGE_USAGE:
// TRUE product-source usage, or a FALSE bounded negative that is
// VERIFIED and was recorded under a COMPLETE check scope — a PARTIAL
// or unverified negative scope is never negative proof) or a positive
// lower bound (kind=PACKAGE_USAGE_LOWER_BOUND: claim=TRUE and
// coverage=PARTIAL only — never a USED verdict and never negative
// proof). negative_verification on a positive or non-package fact is
// meaningless and is rejected. usage_basis names the FALSE claim's
// closed negative basis (present_unused for a linked-but-unused
// target, absent_from_closure for a package provably absent from the
// complete product closure — package-level subjects only); it is
// meaningless on a positive or non-package fact, and a legacy fact
// without it reads as the bounded present-unused basis.
func validatePackageUsageFact(e *ValidationError, f VerifiedFact, where string) {
	// B41 is a closed family of its own: a usage-scope fact never
	// passes through the B42 rules below — its own validator decides
	// every shape question (including the module-level empty package,
	// which B42 can never accept).
	if f.Kind == FactKindBuildUsageScope || f.Tool == "usage-scope" {
		validateBuildUsageScopeFact(e, f, where)
		return
	}
	isPkg := f.Kind == FactKindPackageUsage ||
		f.Kind == FactKindPackageUsageLowerBound || f.Tool == "package-usage"
	switch f.Kind {
	case "":
		if f.Tool == "package-usage" {
			e.add("%s: tool=package-usage requires a package-usage fact kind", where)
		}
	case FactKindPackageUsage:
		if f.Tool != "package-usage" {
			e.add("%s: kind=PACKAGE_USAGE requires tool=package-usage, got %q", where, f.Tool)
		}
		if f.Scope == "" {
			e.add("%s: kind=PACKAGE_USAGE requires a non-empty scope", where)
		}
		if slices.Contains(f.Limitations, openEnumerationLimitation) {
			e.add("%s: kind=PACKAGE_USAGE fact carries the open-enumeration lower-bound marker; a positive lower bound is not a USED verdict and can never close the path", where)
		}
	case FactKindPackageUsageLowerBound:
		if f.Tool != "package-usage" {
			e.add("%s: kind=PACKAGE_USAGE_LOWER_BOUND requires tool=package-usage, got %q", where, f.Tool)
		}
		if f.Scope == "" {
			e.add("%s: kind=PACKAGE_USAGE_LOWER_BOUND requires a non-empty scope", where)
		}
		// A lower-bound positive is not a USED verdict and can never
		// underwrite a negative: its shape is fixed.
		if f.Claim != "TRUE" {
			e.add("%s: kind=PACKAGE_USAGE_LOWER_BOUND requires claim=TRUE, got %q (a lower-bound fact is not a verdict)", where, f.Claim)
		}
		if f.Coverage != "PARTIAL" {
			e.add("%s: kind=PACKAGE_USAGE_LOWER_BOUND requires coverage=PARTIAL, got %q (the positive lower bound lives in an open scope)", where, f.Coverage)
		}
	default:
		e.add("%s: kind %q invalid", where, f.Kind)
	}
	if isPkg {
		if f.UsageSubject == nil || f.UsageSubject.Package == "" {
			e.add("%s: package-usage fact requires usage_subject with a non-empty package (an unbound fact could be cited for any subject)", where)
		}
	} else if f.UsageSubject != nil {
		e.add("%s: usage_subject is only meaningful on a package-usage fact", where)
	}
	if f.NegativeVerification != "" {
		switch {
		case !isPkg:
			e.add("%s: negative_verification %q is only meaningful on a PACKAGE_USAGE fact", where, f.NegativeVerification)
		case f.Claim != "FALSE":
			e.add("%s: negative_verification %q must not appear on a claim=%s package-usage fact", where, f.NegativeVerification, f.Claim)
		case f.NegativeVerification != NegativeVerificationVerified:
			e.add("%s: negative_verification %q invalid, requires %s", where, f.NegativeVerification, NegativeVerificationVerified)
		}
	}
	if f.UsageBasis != "" {
		// usage_basis names the closed negative-verification basis of a
		// FALSE package-usage claim; it is meaningless anywhere else.
		// The closure-absence basis is package-level only — the lane's
		// symbol negative keeps the linked-package premise, so a
		// symbol-subject fact can never carry it. A legacy fact without
		// the member reads as the bounded present-unused basis.
		switch {
		case !isPkg || f.Claim != "FALSE":
			e.add("%s: usage_basis %q is only meaningful on a claim=FALSE PACKAGE_USAGE fact", where, f.UsageBasis)
		case f.UsageBasis != UsageBasisPresentUnused && f.UsageBasis != UsageBasisAbsentFromClosure:
			e.add("%s: usage_basis %q invalid (requires present_unused|absent_from_closure)", where, f.UsageBasis)
		case f.UsageBasis == UsageBasisAbsentFromClosure && f.UsageSubject != nil && f.UsageSubject.Symbol != "":
			e.add("%s: usage_basis=absent_from_closure requires a package-level subject; a symbol negative keeps the linked-package premise", where)
		}
	}
	if isPkg && f.Kind != FactKindPackageUsageLowerBound && f.Claim == "FALSE" {
		if f.NegativeVerification != NegativeVerificationVerified {
			e.add("%s: claim=FALSE PACKAGE_USAGE fact requires negative_verification=%s (an unverified negative is never proof)", where, NegativeVerificationVerified)
		}
		if f.Coverage != "COMPLETE" {
			e.add("%s: claim=FALSE PACKAGE_USAGE fact requires coverage=COMPLETE, got %q (a degraded scope is never negative proof)", where, f.Coverage)
		}
	}
	if f.UsageScope != "" || f.ProductAbsenceVerification != "" {
		e.add("%s: usage_scope/product_absence_verification are only meaningful on a BUILD_USAGE_SCOPE fact", where)
	}
}

// validateBuildUsageScopeFact enforces the B41 fact contract on a
// usage-scope row: the closed pairing kind=BUILD_USAGE_SCOPE ⇔
// tool=usage-scope, a claim that is always TRUE (the fact records a
// build-closure classification, including the auditable
// absent-from-both unknown class — never a negative, so claim=FALSE
// and negative_verification are impossible by construction), a
// non-empty closed usage_scope enum, COMPLETE coverage over the
// closed paired stream, and the exact subject shape: a package check
// carries a non-empty package, a module-level aggregate carries an
// empty one (legal only here — never a package-level proof and never
// a module path standing in for a package), and the symbol component
// is always empty. product_absence_verification=VERIFIED is allowed
// only with usage_scope=test-only — bounded to the recorded no-test
// closure — and is required there; VERIFIED_VENDOR_INVENTORY is
// allowed only with usage_scope=unknown under the closed
// vendor-inventory derivation; every other marker/class combination
// is a forged negative marker.
func validateBuildUsageScopeFact(e *ValidationError, f VerifiedFact, where string) {
	if f.Kind != FactKindBuildUsageScope {
		e.add("%s: tool=usage-scope requires kind=BUILD_USAGE_SCOPE, got %q", where, f.Kind)
	}
	if f.Kind == FactKindBuildUsageScope && f.Tool != "usage-scope" {
		e.add("%s: kind=BUILD_USAGE_SCOPE requires tool=usage-scope, got %q", where, f.Tool)
	}
	switch UsageScope(f.UsageScope) {
	case UsageScopeProduct, UsageScopeTestOnly, UsageScopeMixed, UsageScopeUnknown:
	default:
		e.add("%s: usage_scope %q invalid (requires product|test-only|mixed|unknown)", where, f.UsageScope)
	}
	if f.Claim != "TRUE" {
		e.add("%s: BUILD_USAGE_SCOPE requires claim=TRUE, got %q (a build-closure class is never a negative claim)", where, f.Claim)
	}
	if f.NegativeVerification != "" {
		e.add("%s: negative_verification %q must never appear on a BUILD_USAGE_SCOPE fact (product absence travels in product_absence_verification)", where, f.NegativeVerification)
	}
	if f.Coverage != "COMPLETE" {
		e.add("%s: BUILD_USAGE_SCOPE requires coverage=COMPLETE, got %q (a degraded paired stream can never promote)", where, f.Coverage)
	}
	if f.Scope == "" {
		e.add("%s: kind=BUILD_USAGE_SCOPE requires a non-empty scope", where)
	}
	// Subject shape: module required, symbol always empty, package
	// empty only for the module-level aggregate.
	if f.UsageSubject == nil {
		e.add("%s: BUILD_USAGE_SCOPE fact requires a usage_subject binding (an unbound fact could be cited for any subject)", where)
	} else {
		if f.UsageSubject.Module == "" {
			e.add("%s: BUILD_USAGE_SCOPE usage_subject requires a non-empty module", where)
		}
		if f.UsageSubject.Symbol != "" {
			e.add("%s: BUILD_USAGE_SCOPE usage_subject must not carry a symbol (the check classifies package/build-closure membership, not symbol usage)", where)
		}
	}
	// The product-absence marker is the test-only signature or the
	// closed vendor-inventory signature: VERIFIED is required and
	// permitted only on test-only, VERIFIED_VENDOR_INVENTORY is
	// permitted only on unknown (the absent-from-both class whose
	// vendor inventory proved exact subject absence), and every other
	// marker/class combination is a forged negative marker — never a
	// substitute for the B42 negative_verification.
	switch UsageScope(f.UsageScope) {
	case UsageScopeTestOnly:
		if f.ProductAbsenceVerification != ProductAbsenceVerificationVerified {
			e.add("%s: usage_scope=test-only requires product_absence_verification=VERIFIED (the product-side closure must be closed before absence is recorded)", where)
		}
	case UsageScopeUnknown:
		if f.ProductAbsenceVerification != "" && f.ProductAbsenceVerification != ProductAbsenceVerificationVendorInventory {
			e.add("%s: product_absence_verification=%q is forbidden with usage_scope=unknown (only VERIFIED_VENDOR_INVENTORY under the closed vendor-inventory derivation may mark it)", where, f.ProductAbsenceVerification)
		}
	case UsageScopeProduct, UsageScopeMixed:
		if f.ProductAbsenceVerification != "" {
			e.add("%s: product_absence_verification=%q is forbidden with usage_scope=%q (only test-only may carry VERIFIED and only unknown may carry VERIFIED_VENDOR_INVENTORY)", where, f.ProductAbsenceVerification, f.UsageScope)
		}
	default:
		if f.ProductAbsenceVerification != "" {
			e.add("%s: product_absence_verification=%q invalid on unrecognized usage_scope %q", where, f.ProductAbsenceVerification, f.UsageScope)
		}
	}
}

// validatePackageUsageCondition enforces the /3 contract of the required
// path predicate «affected package/symbol used by product code». The
// deterministic condition stays role=path + necessity=required +
// axis=code_reachability and carries the structured usage_subject of the
// advisory candidate it covers; a cited package-usage fact binds only to
// the condition whose usage_subject equals its own, so a fact for one
// candidate can never be cited for another. SUPPORTED rests on a TRUE
// PACKAGE_USAGE fact, REFUTED only on a verified negative PACKAGE_USAGE
// fact (claim=FALSE, negative_verification=VERIFIED,
// coverage=COMPLETE) — a degraded or UNKNOWN scope is never negative
// proof — and UNKNOWN cites auditable refs (including a
// PACKAGE_USAGE_LOWER_BOUND positive) but never a resolved negative. A
// REFUTED path is a bounded refutation: it can never accompany an
// auto_close disposition, and it may accompany
// vulnerable_code_reachability=FALSE or a SUPPORTED NON_APPLICABLE
// classification only when the cited verified negative carries the
// closure-absence basis (usage_basis=absent_from_closure — a package
// provably absent from the complete product closure cannot be
// statically reached) and the condition names the runtime/dynamic
// boundary; the bounded basis (including a legacy fact with no basis)
// keeps both prohibitions. An agent usage condition
// stays an OPEN hypothesis that cites only agent material and carries
// no usage_subject; a verified fact attached to it is rejected
// outright (the generic agent-ref rule fires first).
func validatePackageUsageCondition(e *ValidationError, r *Report, c ExploitationCondition, refs *refSpace) {
	where := "exploitation_conditions[" + c.ID + "]"

	if c.Origin == OriginAgent {
		// Agent material can never carry the usage predicate: the
		// canonical claim stays OPEN, is never bound to a lane
		// candidate, and a deterministic ref attached to the condition
		// is a deterministic-evidence forgery.
		if c.State != StateOpen {
			e.add("%s: agent usage condition must stay state=OPEN (agent claims are unevaluated hypotheses, got %s)", where, c.State)
		}
		if c.UsageSubject != nil {
			e.add("%s: agent usage condition must not carry usage_subject (it is bound to no lane candidate)", where)
		}
		for _, ref := range c.EvidenceRefs {
			if refs.factByID[ref] != nil {
				e.add("%s: agent usage condition cites verified fact %q; agent material can never carry the usage predicate", where, ref)
			}
		}
		return
	}

	if c.Origin != OriginDeterm {
		// The generic origin-enum rule already reports this row.
		return
	}

	// The deterministic usage condition is a required path predicate on
	// the code-reachability axis — the fixed subject table pins all
	// three; any other value is not a state the assembler produces.
	if c.Role != ConditionRolePath {
		e.add("%s: deterministic usage condition requires role=path, got %q", where, c.Role)
	}
	if c.Necessity != "required" {
		e.add("%s: deterministic usage condition requires necessity=required, got %q", where, c.Necessity)
	}
	if c.Axis != ECAxisCodeReachability {
		e.add("%s: usage condition requires axis=code_reachability, got %q", where, c.Axis)
	}

	// Subject binding: the condition names exactly one advisory-declared
	// candidate, and a package-usage fact may be cited only for the
	// candidate it checked — a fact for subject A can never close or
	// refute the condition for subject B (cross-subject citation is a
	// deterministic-evidence forgery). The fact-level rule additionally
	// requires a usage subject on every package-usage fact; the check
	// here keeps it from binding to the wrong candidate.
	if c.UsageSubject == nil || c.UsageSubject.Package == "" {
		e.add("%s: deterministic usage condition requires usage_subject with a non-empty package", where)
	}
	for _, ref := range c.EvidenceRefs {
		f := refs.factByID[ref]
		if f == nil ||
			(f.Kind != FactKindPackageUsage && f.Kind != FactKindPackageUsageLowerBound) {
			continue
		}
		if f.UsageSubject == nil || f.UsageSubject.Package == "" {
			e.add("%s: cited package-usage fact %s carries no usage_subject; an unbound fact cannot be tied to a candidate", where, ref)
			continue
		}
		if c.UsageSubject == nil {
			continue
		}
		if *f.UsageSubject != *c.UsageSubject {
			e.add("%s: cited package-usage fact %s is bound to a different usage_subject {%s, %s, %s} than the condition's {%s, %s, %s}; a fact for one candidate can never be cited for another",
				where, ref,
				f.UsageSubject.Module, f.UsageSubject.Package, f.UsageSubject.Symbol,
				c.UsageSubject.Module, c.UsageSubject.Package, c.UsageSubject.Symbol)
		}
	}

	usageFacts := func(wantClaim string) (cited []string, other bool) {
		for _, ref := range c.EvidenceRefs {
			f := refs.factByID[ref]
			if f == nil || f.Kind != FactKindPackageUsage {
				continue
			}
			if f.Claim == wantClaim {
				cited = append(cited, ref)
			} else {
				other = true
			}
		}
		return cited, other
	}

	switch c.State {
	case StateSupported:
		cited, other := usageFacts("TRUE")
		if len(cited) == 0 {
			e.add("%s: state=SUPPORTED on the usage subject requires an evidence_ref to a PACKAGE_USAGE fact with claim=TRUE", where)
		}
		if other {
			e.add("%s: SUPPORTED usage condition must not cite a claim=FALSE PACKAGE_USAGE fact", where)
		}
		for _, ref := range c.EvidenceRefs {
			f := refs.factByID[ref]
			if f == nil {
				continue
			}
			if f.Kind == FactKindPackageUsageLowerBound {
				e.add("%s: SUPPORTED usage condition cites the PACKAGE_USAGE_LOWER_BOUND fact %s; a positive lower bound in an open scope is not a USED verdict and cannot close the path", where, ref)
			}
			if f.Kind == FactKindPackageUsage && slices.Contains(f.Limitations, openEnumerationLimitation) {
				e.add("%s: SUPPORTED usage condition cites the open-scope lower-bound fact %s relabelled as a USED verdict; a lower bound cannot close the path", where, ref)
			}
		}
	case StateRefuted:
		verifiedNeg, sawFalse, sawTrue, sawBound, absentNeg := false, false, false, false, false
		for _, ref := range c.EvidenceRefs {
			f := refs.factByID[ref]
			if f == nil {
				continue
			}
			if f.Kind == FactKindPackageUsageLowerBound {
				sawBound = true
				continue
			}
			if f.Kind != FactKindPackageUsage {
				continue
			}
			switch {
			case f.Claim == "TRUE":
				sawTrue = true
			case f.NegativeVerification == NegativeVerificationVerified && f.Coverage == "COMPLETE":
				verifiedNeg = true
				if f.UsageBasis == UsageBasisAbsentFromClosure {
					absentNeg = true
				}
			default:
				sawFalse = true
			}
		}
		if sawBound {
			e.add("%s: REFUTED usage condition cites a PACKAGE_USAGE_LOWER_BOUND fact; a positive lower bound in an open scope is never negative proof", where)
		}
		if !verifiedNeg {
			e.add("%s: state=REFUTED on the usage subject requires an evidence_ref to a PACKAGE_USAGE fact with claim=FALSE, negative_verification=VERIFIED and coverage=COMPLETE (a degraded or unverified scope is never negative proof)", where)
		}
		if sawFalse {
			e.add("%s: REFUTED usage condition cites a PACKAGE_USAGE negative that is not a verified negative under a complete scope", where)
		}
		if sawTrue {
			e.add("%s: REFUTED usage condition must not cite a claim=TRUE PACKAGE_USAGE fact", where)
		}
		negLim, safeLim, runtimeBound := false, false, false
		for _, lim := range c.Limitations {
			if strings.HasPrefix(lim, "negative verification=VERIFIED") {
				negLim = true
			}
			if strings.Contains(lim, "not a safe conclusion") {
				safeLim = true
			}
			if namesRuntimeBoundary(lim) {
				runtimeBound = true
			}
		}
		if !negLim {
			e.add("%s: REFUTED usage condition requires a limitation naming the bounded negative verification (negative verification=VERIFIED: <check scope>)", where)
		}
		if !safeLim {
			e.add("%s: REFUTED usage condition requires a limitation stating the bounded refutation is not a safe conclusion", where)
		}
		// A REFUTED path predicate is bounded: it never yields a safe
		// conclusion or an automatic close-out, and a negative
		// applicability/reachability result may accompany it only
		// through the closure-absence basis — a package provably absent
		// from the complete product closure cannot be statically
		// reached by any product source. The bounded basis (a fact
		// carrying no basis is read as the bounded basis) proves only
		// non-use inside the link set, never reachability. Either way
		// the negative stays bounded to static analysis, so the relaxed
		// combination additionally requires a limitation naming the
		// runtime/dynamic boundary.
		if r.Disposition.AutoClose {
			e.add("%s: REFUTED usage condition can never accompany an auto_close disposition", where)
		}
		if r.ProductApplicability.VulnerableCodeReachability == VCRFalse && !(absentNeg && runtimeBound) {
			if absentNeg {
				e.add("%s: REFUTED usage condition may accompany vulnerable_code_reachability=FALSE under the closure-absence basis only with a limitation naming the runtime/dynamic boundary (the negative is bounded to static analysis; reflection, plugins and dynamic loading are not covered)", where)
			} else {
				e.add("%s: REFUTED usage condition can never accompany vulnerable_code_reachability=FALSE (a bounded usage negative does not prove reachability)", where)
			}
		}
		if r.ClassificationReview.Status == StatusSupported && r.ClassificationReview.Class == ClassNonApplicable && !(absentNeg && runtimeBound) {
			if absentNeg {
				e.add("%s: REFUTED usage condition may accompany a SUPPORTED NON_APPLICABLE classification under the closure-absence basis only with a limitation naming the runtime/dynamic boundary (the negative is bounded to static analysis; reflection, plugins and dynamic loading are not covered)", where)
			} else {
				e.add("%s: REFUTED usage condition can never accompany a SUPPORTED NON_APPLICABLE classification", where)
			}
		}
	case StateUnknown:
		for _, ref := range c.EvidenceRefs {
			f := refs.factByID[ref]
			if f == nil || f.Kind != FactKindPackageUsage {
				continue
			}
			if f.Claim == "FALSE" &&
				f.NegativeVerification == NegativeVerificationVerified && f.Coverage == "COMPLETE" {
				e.add("%s: UNKNOWN usage condition cites the verified negative PACKAGE_USAGE fact %q; a closed negative refutes the path, it does not leave it unresolved", where, ref)
			} else if f.Claim == "FALSE" {
				e.add("%s: UNKNOWN usage condition cites the claim=FALSE PACKAGE_USAGE fact %q; a negative fact cannot accompany an unresolved path", where, ref)
			}
		}
		negProof := false
		for _, lim := range c.Limitations {
			if strings.Contains(lim, "never negative proof") {
				negProof = true
			}
		}
		if !negProof {
			e.add("%s: UNKNOWN usage condition requires a limitation stating the unresolved check is never negative proof", where)
		}
	case StateOpen, StateConflicted, StateRetracted:
		e.add("%s: deterministic usage condition state=%s invalid; the usage predicate is decided as SUPPORTED|REFUTED|UNKNOWN only", where, c.State)
	}
}

// namesRuntimeBoundary reports whether a limitation names the
// runtime/dynamic boundary of a static negative: the clause bounds the
// result to static analysis by disclaiming runtime execution and at
// least one dynamic channel (reflection, plugins, dynamic or generated
// loading). A REFUTED usage condition may sit beside
// vulnerable_code_reachability=FALSE or a SUPPORTED NON_APPLICABLE
// classification only while carrying it — the closure-absence negative
// proves no static reachability, not the absence of a dynamic load
// path.
func namesRuntimeBoundary(lim string) bool {
	if !strings.Contains(lim, "runtime") {
		return false
	}
	for _, marker := range []string{"reflection", "plugin", "dynamic", "generated"} {
		if strings.Contains(lim, marker) {
			return true
		}
	}
	return false
}

// validateBuildUsageScopeAxis enforces the optional B41 audit-axis
// contract under slice2-fidelity/3: the member exists exactly when at
// least one BUILD_USAGE_SCOPE fact does, and its content must equal —
// member for member — the axis the same pure helper the assembler ran
// derives from this report's verified-fact ledger. Any forged status,
// forged fact reference or hand-edited statement is a violation,
// never a downgrade. The axis is strictly non-carrier: nothing here
// reads it into evidence_level — that ladder is recomputed
// independently and ignores the member.
func validateBuildUsageScopeAxis(e *ValidationError, r *Report) {
	ax := r.ExploitationAxes.BuildUsageScope
	want := deriveBuildUsageScopeAxis(r)
	switch {
	case ax == nil && want == nil:
		return
	case ax == nil:
		e.add("exploitation_axes.build_usage_scope: required when BUILD_USAGE_SCOPE facts exist")
		return
	case want == nil:
		e.add("exploitation_axes.build_usage_scope: present without BUILD_USAGE_SCOPE facts (the axis can only summarize promoted usage-scope facts)")
		return
	}
	if ax.Status != want.Status {
		e.add("exploitation_axes.build_usage_scope.status=%q does not match recomputed %q", ax.Status, want.Status)
	}
	if ax.Level != want.Level {
		e.add("exploitation_axes.build_usage_scope.level=%q does not match recomputed %q", ax.Level, want.Level)
	}
	if ax.Basis != want.Basis {
		e.add("exploitation_axes.build_usage_scope.basis=%q does not match recomputed %q", ax.Basis, want.Basis)
	}
	if ax.Basis == "agent" {
		e.add("exploitation_axes.build_usage_scope: basis must never be agent")
	}
	if ax.Statement != want.Statement {
		e.add("exploitation_axes.build_usage_scope.statement %q does not match recomputed %q", ax.Statement, want.Statement)
	}
	if ax.Scope != want.Scope {
		e.add("exploitation_axes.build_usage_scope.scope %q does not match recomputed %q", ax.Scope, want.Scope)
	}
	if !slices.Equal(ax.EvidenceRefs, want.EvidenceRefs) {
		e.add("exploitation_axes.build_usage_scope.evidence_refs %v do not match recomputed %v (exactly the BUILD_USAGE_SCOPE fact ids in sorted order)", ax.EvidenceRefs, want.EvidenceRefs)
	}
	if !slices.Equal(ax.Limitations, want.Limitations) {
		e.add("exploitation_axes.build_usage_scope.limitations %v do not match recomputed %v", ax.Limitations, want.Limitations)
	}
}

// validateBuildUsageScopeConsistency enforces the B41/B42 cross-fact
// boundary (§constraint 22): a package-level usage_scope=test-only
// fact — "the target is absent from the closed product build closure"
// — cannot coexist with a carrier kind=PACKAGE_USAGE fact asserting a
// product-source verdict for the same {Module,Package} subject.
// Module-level aggregates never participate, and
// PACKAGE_USAGE_LOWER_BOUND stays non-carrier and uninvolved. Any
// pairing is a forged report, never a reconciliation signal.
func validateBuildUsageScopeConsistency(e *ValidationError, r *Report) {
	for _, pair := range buildUsageScopeConflicts(r) {
		e.add("verified_facts[%s]: usage_scope=test-only for a package subject cannot coexist with the carrier PACKAGE_USAGE fact %s for the same {Module,Package} — the report is inconsistent",
			pair[0], pair[1])
	}
}

// validateObservationPayloadRef enforces the externalized-payload
// contract on a persisted observation row: when payload_ref is
// present it must be a complete content-addressed reference whose
// sidecar exists under dir, hashes to the recorded digest and decodes
// — and data must be the bounded externalization envelope agreeing
// with the reference, never a prefix presented as the result. A row
// claiming the envelope shape without a matching payload_ref is a
// forged record: the marker means the complete payload exists as the
// named artifact, and without the pin there is nothing to bind it to.
// Missing, altered, undecodable or digest-mismatched sidecars all add
// problems — the persisted proof record stays fail-closed.
func validateObservationPayloadRef(e *ValidationError, dir, ledger string, row int, o *evidencetools.Observation) {
	if o == nil {
		return
	}
	where := fmt.Sprintf("%s row %d (observation %s)", ledger, row, o.ID)
	env, isEnvelope := o.Data.(map[string]any)
	externalized := isEnvelope && env["externalized_payload"] == true
	if o.PayloadRef == nil {
		if externalized {
			e.add("%s: data carries the externalization envelope but no payload_ref binds the complete payload", where)
		}
		return
	}
	ref := o.PayloadRef
	if _, err := loadExternalizedPayload(dir, o); err != nil {
		e.add("%s: %v", where, err)
		return
	}
	if o.Tool == evidencetools.SymbolUnreachabilityTool {
		b, err := verifyObservationPayloadRef(dir, ref)
		if err != nil {
			e.add("%s: %v", where, err)
			return
		}
		var typed evidencetools.SymbolUnreachabilityData
		if err := json.Unmarshal(b, &typed); err != nil || typed.Result.Module == "" || len(typed.Result.Subjects) == 0 {
			if err == nil {
				err = fmt.Errorf("symbol-unreachability payload is not a complete typed result")
			}
			e.add("%s: sidecar payload is not a decodable typed symbol proof: %v", where, err)
		}
	}
}

// Retained report fields are checked even without a historical extension marker.
func validateRetainedTicket(r *Report, e *ValidationError) {
	pa := r.ProductApplicability
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	// ---- ticket-build identity ----
	// The ticket_check/ticket members are self-consistent or
	// absent: a version-axis refusal requires its named reason, a named
	// mismatch requires the check that produced it, and a refused axis
	// can never read as a version decision.
	if tm := r.Input.Ticket; tm != nil {
		if tm.Path == "" {
			e.add("input.ticket.path is required when the block is present")
		}
		if tm.SHA256 != "" && !hex64.MatchString(tm.SHA256) {
			e.add("input.ticket.sha256 must be 64-hex")
		}
		if tm.ParseError == "" && tm.Claims == nil {
			e.add("input.ticket requires claims or a parse_error")
		}
		if tm.DistributionURL != "" {
			// The persisted locator is sanitized provenance: intake strips
			// userinfo/query/fragment, and a recorded value carrying any of
			// them (or quote/bracket markup) violates the channel contract —
			// never echo credential material or markdown breakers.
			if u, uerr := url.Parse(tm.DistributionURL); uerr != nil ||
				u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				strings.ContainsAny(tm.DistributionURL, "`\"'<>") {
				e.add("input.ticket.distribution_url must be a sanitized locator (no userinfo/query/fragment)")
			}
		}
	}
	{
		tc := pa.TicketCheck
		if pa.VersionAxisBlocked {
			if pa.VersionAxisBlockReason != domain.TicketReasonPackageVersionMismatch {
				e.add("product_applicability: version_axis_blocked requires block reason %q, got %q",
					domain.TicketReasonPackageVersionMismatch, pa.VersionAxisBlockReason)
			}
			if pa.VersionAffected == "FALSE" {
				e.add("product_applicability: version_axis_blocked forbids version_affected=FALSE — a refusal is never an out-of-range verdict")
			}
			if tc == nil {
				e.add("product_applicability: version_axis_blocked requires a ticket_check")
			} else if tc.PackageVersionCheck != domain.TicketCheckMismatch {
				e.add("product_applicability: version_axis_blocked requires ticket_check.package_version_check=MISMATCH, got %q",
					tc.PackageVersionCheck)
			}
		} else if pa.VersionAxisBlockReason != "" {
			e.add("product_applicability: version_axis_block_reason %q requires version_axis_blocked", pa.VersionAxisBlockReason)
		}
		if tc != nil {
			if r.Input.Ticket == nil {
				e.add("product_applicability.ticket_check requires input.ticket")
			}
			checks := map[string]bool{
				"":                           true,
				domain.TicketCheckMatch:      true,
				domain.TicketCheckMismatch:   true,
				domain.TicketCheckNotChecked: true,
			}
			if !checks[tc.PackageVersionCheck] {
				e.add("product_applicability.ticket_check.package_version_check %q invalid", tc.PackageVersionCheck)
			}
			if !checks[tc.ProductVersionCheck] {
				e.add("product_applicability.ticket_check.product_version_check %q invalid", tc.ProductVersionCheck)
			}
			reasonHas := func(want string) bool {
				for _, s := range tc.Reasons {
					if s == want {
						return true
					}
				}
				return false
			}
			if tc.PackageVersionCheck == domain.TicketCheckMismatch && !reasonHas(domain.TicketReasonPackageVersionMismatch) {
				e.add("product_applicability.ticket_check: package_version_check=MISMATCH requires reason %s", domain.TicketReasonPackageVersionMismatch)
			}
			if tc.ProductVersionCheck == domain.TicketCheckMismatch && !reasonHas(domain.TicketReasonAnalyzedBuildMismatch) {
				e.add("product_applicability.ticket_check: product_version_check=MISMATCH requires reason %s", domain.TicketReasonAnalyzedBuildMismatch)
			}
			if tc.ParseError != "" && tc.ParseError != domain.TicketReasonInvalid {
				e.add("product_applicability.ticket_check.parse_error %q invalid", tc.ParseError)
			}
			if tc.ParseError != "" && (tc.PackageVersionCheck == domain.TicketCheckMismatch || tc.ProductVersionCheck == domain.TicketCheckMismatch) {
				e.add("product_applicability.ticket_check: a parse failure can never produce a MISMATCH axis")
			}
			if len(tc.BlockedModules) > 0 && tc.PackageVersionCheck != domain.TicketCheckMismatch {
				e.add("product_applicability.ticket_check.blocked_modules requires package_version_check=MISMATCH")
			}
			if pa.VersionAffected == "FALSE" && tc.PackageVersionCheck == domain.TicketCheckMismatch && !pa.VersionAxisBlocked {
				e.add("product_applicability: version_affected=FALSE cannot stand beside ticket_check.package_version_check=MISMATCH — the refusal must be recorded")
			}
		}
	}
}

func validateRetainedConditions(r *Report, e *ValidationError) {
	pa := r.ProductApplicability
	// (i)/(j) three-valued transition semantics: every condition carries
	// a state from the closed enum; agent conditions are always exactly
	// OPEN hypotheses — UNKNOWN/CONFLICTED/RETRACTED are as forbidden as
	// SUPPORTED/REFUTED because an agent step is never evaluated at all.
	// For the four deterministic applicability subjects the state must
	// mirror the applicability field it records: SUPPORTED↔TRUE,
	// REFUTED↔FALSE, UNKNOWN↔UNKNOWN — a fabricated SUPPORTED or REFUTED
	// that the fields do not back (or an UNKNOWN masking a decided field)
	// is rejected rather than counted as a confirmed/open transition.
	subjectField := map[string]string{
		subjModulePresence: pa.ModulePresent,
		subjVersionInUse:   pa.VersionAffected,
		subjPackageReach:   pa.PackagePresent,
		subjBuildRelevant:  pa.BuildRelevant,
	}
	stateForField := func(v string) string {
		switch v {
		case "TRUE":
			return StateSupported
		case "FALSE":
			return StateRefuted
		default:
			return StateUnknown
		}
	}
	condStates := map[string]bool{
		StateSupported: true, StateOpen: true, StateRefuted: true,
		StateConflicted: true, StateUnknown: true, StateRetracted: true,
	}
	for _, c := range r.ExploitationConditions {
		where := "exploitation_conditions[" + c.ID + "]"
		if !condStates[c.State] {
			e.add("%s: state %q invalid", where, c.State)
			continue
		}
		switch c.Origin {
		case OriginAgent:
			if c.State != StateOpen {
				e.add("%s: agent condition must be state=OPEN (agent steps are unevaluated hypotheses, got %s)", where, c.State)
			}
		case OriginDeterm:
			if want, ok := subjectField[c.Subject]; ok && c.State != stateForField(want) {
				e.add("%s: state=%s on %q is inconsistent with the corresponding applicability field %q (requires %s)", where, c.State, c.Subject, want, stateForField(want))
			}
		}
	}
}

func validateRetainedImplementation(r *Report, e *ValidationError) {
	pa := r.ProductApplicability
	// The implementation-presence axis is additive/optional. A decided
	// value must be internally consistent: FALSE is a product-scope
	// conclusion reached only after module+version+package+build
	// relevance, carried by an admitted product-scope supported-targets
	// assumption; TRUE only records that a selected implementation
	// carries the marker. The policy ids resolve against the declared
	// assumptions, never against evidence.
	if axis := pa.VulnerableImplementationPresent; axis != "" {
		if axis != "TRUE" && axis != "FALSE" && axis != "UNKNOWN" {
			e.add("product_applicability.vulnerable_implementation_present %q not in {TRUE,FALSE,UNKNOWN}", axis)
		}
	}
	if pa.ImplementationTargetScope != "" {
		switch pa.ImplementationTargetScope {
		case "product", "artifact", "release", "operator":
		default:
			e.add("product_applicability.implementation_target_scope %q not in {product,artifact,release,operator}", pa.ImplementationTargetScope)
		}
		if pa.VulnerableImplementationPresent == "" {
			e.add("product_applicability.implementation_target_scope requires vulnerable_implementation_present")
		}
	}
	if pa.VulnerableImplementationPresent == "FALSE" {
		if pa.ModulePresent != "TRUE" || pa.VersionAffected != "TRUE" ||
			pa.PackagePresent != "TRUE" || pa.BuildRelevant != "TRUE" {
			e.add("product_applicability.vulnerable_implementation_present=FALSE requires module_present/version_affected/package_present/build_relevant all TRUE (found %s/%s/%s/%s)",
				pa.ModulePresent, pa.VersionAffected, pa.PackagePresent, pa.BuildRelevant)
		}
		if pa.ImplementationTargetScope != "product" {
			e.add("product_applicability.vulnerable_implementation_present=FALSE requires implementation_target_scope=product (found %q) — artifact-scoped target evidence cannot close a product-wide conclusion", pa.ImplementationTargetScope)
		}
		if strings.TrimSpace(pa.ImplementationLocus) == "" {
			e.add("product_applicability.vulnerable_implementation_present=FALSE requires implementation_locus naming the verified implementation")
		}
		if len(pa.AssumptionIDs) == 0 {
			e.add("product_applicability.vulnerable_implementation_present=FALSE requires the admitted product-scope supported-targets assumption id")
		}
	}
	if pa.VulnerableImplementationPresent == "TRUE" &&
		(pa.ModulePresent != "TRUE" || pa.VersionAffected != "TRUE") {
		e.add("product_applicability.vulnerable_implementation_present=TRUE requires module_present=TRUE and version_affected=TRUE")
	}
	knownAssumptions := map[string]bool{}
	if in := r.Input.DeclaredAssumptions; in != nil && in.LoadError == "" {
		for _, id := range in.AssumptionIDs() {
			knownAssumptions[id] = true
		}
	}
	for _, id := range pa.AssumptionIDs {
		if !knownAssumptions[id] {
			e.add("product_applicability.assumption_ids: %q does not resolve to a declared assumption id", id)
		}
	}
}
