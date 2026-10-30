package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"errors"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

type MandatoryConditionLookup struct {
	AdvisoryID      string
	Module          string
	ResolvedVersion string
	SnapshotHash    string
	Proposal        FalsifierProposal
}
type MandatoryCondition struct {
	ID               string
	Kind             FalsifierKind
	Mandatory        bool
	RuleID           string
	RuleVersion      string
	ExpectedSubjects []FalsifierSubject
	SnapshotHash     string
	BuildContextHash string
	DefectSemantics  *domain.DefectSemanticsContract
}
type MandatoryConditionSource interface {
	Resolve(context.Context, MandatoryConditionLookup) (MandatoryCondition, error)
	RuleSetHash() string
}

type FalsifierVerificationInput struct {
	Stage0              Stage0Result
	Assessment          Assessment
	FactValidation      FactValidation
	Proposals           []FalsifierProposal
	Observations        []RecordedObservation
	RulesetHash         string
	ExpectedRulesetHash string
	RunID               string
	Attempt             int
	Previous            *FalsifierProof
}
type FalsifierVerifier interface {
	Verify(context.Context, FalsifierVerificationInput) FalsifierReport
}

type FalsifierVerificationStatus string

const (
	FalsifierVerified          FalsifierVerificationStatus = "VERIFIED"
	FalsifierUnknown           FalsifierVerificationStatus = "UNKNOWN"
	FalsifierInsufficientScope FalsifierVerificationStatus = "INSUFFICIENT_SCOPE"
	FalsifierContradicted      FalsifierVerificationStatus = "CONTRADICTED"
)

type FalsifierBasis string

const (
	BasisCheckerVerified FalsifierBasis = "CHECKER_VERIFIED"
	BasisLLMProposed     FalsifierBasis = "LLM_PROPOSED"
	BasisUnsupported     FalsifierBasis = "UNSUPPORTED"
)

type FalsifierCoverage struct {
	Scope                    string             `json:"scope"`
	Completeness             string             `json:"completeness"`
	SnapshotHash             string             `json:"snapshot_hash,omitempty"`
	BuildContextHash         string             `json:"build_context_hash,omitempty"`
	ClosureHash              string             `json:"closure_hash,omitempty"`
	ClosureComplete          bool               `json:"closure_complete,omitempty"`
	CoverageRuleVersion      string             `json:"coverage_rule_version,omitempty"`
	Inventory *evidencetools.ImportClosureReport `json:"inventory,omitempty"`
	UnreachabilityPayloads []json.RawMessage `json:"unreachability_payloads,omitempty"`
	UnreachabilityBuild *domain.BuildContext           `json:"unreachability_build,omitempty"`
	DeadnessContract    *domain.DefectSemanticsContract `json:"deadness_contract,omitempty"`
	ScopeRule                string             `json:"scope_rule,omitempty"`
	ScopeComplete            bool               `json:"scope_complete,omitempty"`
	ScopeHash                string             `json:"scope_hash,omitempty"`
	ShippingRoots            []string           `json:"shipping_roots,omitempty"`
	PackageStates            map[string]string  `json:"package_states,omitempty"`
	ScopeUnknown             []string           `json:"scope_unknown,omitempty"`
	DiscardedUnreachable     []string           `json:"discarded_unreachable,omitempty"`
	DynamicRelevanceRule     string             `json:"dynamic_relevance_rule,omitempty"`
	DynamicRelevanceComplete bool               `json:"dynamic_relevance_complete,omitempty"`
	ObservedDynamicMarkers   []string           `json:"observed_dynamic_markers,omitempty"`
	IgnoredDynamicMarkers    []string           `json:"ignored_dynamic_markers,omitempty"`
	ExpectedSubjects         []FalsifierSubject `json:"expected_subjects,omitempty"`
	CheckedSubjects          []FalsifierSubject `json:"checked_subjects,omitempty"`
	AbsentSubjects           []FalsifierSubject `json:"absent_subjects,omitempty"`
	PresentSubjects          []FalsifierSubject `json:"present_subjects,omitempty"`
	SkippedPackages          []string           `json:"skipped_packages,omitempty"`
	OpenExceptions           []string           `json:"open_exceptions,omitempty"`
	ClosedExceptions         []string           `json:"closed_exceptions,omitempty"`
	UnresolvedDispatch       []string           `json:"unresolved_dispatch,omitempty"`
	DynamicMarkers           []string           `json:"dynamic_markers,omitempty"`
}

func validateAdmittingCodeAbsenceCoverage(c FalsifierCoverage) error {
	if c.CoverageRuleVersion != evidencetools.CodeAbsenceCoverageRuleVersion {
		return fmt.Errorf("coverage rule must be %q", evidencetools.CodeAbsenceCoverageRuleVersion)
	}
	if err := evidencetools.ValidateCodeAbsenceInventory(c.Inventory, c.SnapshotHash, c.BuildContextHash); err != nil {
		return fmt.Errorf("package inventory: %w", err)
	}
	if c.Completeness != string(evidencetools.CompletenessComplete) {
		return errors.New("coverage is not COMPLETE")
	}
	if !c.ClosureComplete || c.ClosureHash == "" {
		return errors.New("closure is incomplete")
	}
	if c.ScopeRule != evidencetools.CodeAbsenceScopeRule || !c.ScopeComplete || c.ScopeHash == "" {
		return errors.New("shipping scope contract is incomplete")
	}
	if len(c.ShippingRoots) == 0 || len(c.ScopeUnknown) != 0 {
		return errors.New("shipping roots or scope unknown")
	}
	for p, state := range c.PackageStates {
		if state != "LIVE" && state != "DEAD" {
			return fmt.Errorf("package %q has unknown state", p)
		}
	}
	for _, p := range c.DiscardedUnreachable {
		if c.PackageStates[p] != "DEAD" {
			return fmt.Errorf("discarded package %q is not DEAD", p)
		}
	}
	if c.DynamicRelevanceRule != evidencetools.CodeAbsenceDynamicRule || !c.DynamicRelevanceComplete {
		return errors.New("dynamic relevance contract is incomplete")
	}
	if len(c.OpenExceptions) != 0 || len(c.DynamicMarkers) != 0 || len(c.UnresolvedDispatch) != 0 || len(c.SkippedPackages) != 0 {
		return errors.New("coverage contains open exceptions")
	}
	if !sameSubjects(c.ExpectedSubjects, c.CheckedSubjects) || !sameSubjects(c.ExpectedSubjects, c.AbsentSubjects) {
		return errors.New("subject sets are incomplete")
	}
	if len(c.PresentSubjects) != 0 {
		return errors.New("present subjects contradict absence")
	}
	return nil
}

type FalsifierTransition struct {
	From         FalsifierVerificationStatus `json:"from"`
	To           FalsifierVerificationStatus `json:"to"`
	Reason       string                      `json:"reason"`
	RuleID       string                      `json:"rule_id,omitempty"`
	RuleVersion  string                      `json:"rule_version,omitempty"`
	SnapshotHash string                      `json:"snapshot_hash,omitempty"`
	EvidenceHash string                      `json:"evidence_hash,omitempty"`
}
type FalsifierProof struct {
	ID           string                      `json:"id"`
	ProposalID   string                      `json:"proposal_id"`
	ClaimID      string                      `json:"claim_id"`
	ConditionID  string                      `json:"condition_id"`
	Kind         FalsifierKind               `json:"kind"`
	Status       FalsifierVerificationStatus `json:"status"`
	Basis        FalsifierBasis              `json:"basis"`
	Mandatory    bool                        `json:"mandatory"`
	RuleID       string                      `json:"rule_id,omitempty"`
	RuleVersion  string                      `json:"rule_version,omitempty"`
	Falsifier    string                      `json:"falsifier,omitempty"`
	EvidenceRefs []string                    `json:"evidence_refs,omitempty"`
	Coverage     FalsifierCoverage           `json:"coverage"`
	Reason       string                      `json:"reason"`
	History      []FalsifierTransition       `json:"history,omitempty"`
}
type FalsifierReport struct {
	SchemaVersion string           `json:"schema_version"`
	RuleSetHash   string           `json:"ruleset_hash"`
	Proofs        []FalsifierProof `json:"proofs"`
	Hash          string           `json:"hash"`
}

// FalsifierVerificationSchemaVersion is the schema of the persisted
// verifier report (falsifier-verification.json) and of the in-memory report
// the verifier emits — one schema, so a persisted report never needs a
// translation layer.
const FalsifierVerificationSchemaVersion = "falsifier-verification.v1"

type deterministicFalsifierVerifier struct{ source MandatoryConditionSource }

func NewFalsifierVerifier(source MandatoryConditionSource) FalsifierVerifier {
	return &deterministicFalsifierVerifier{source: source}
}
func (v *deterministicFalsifierVerifier) Verify(ctx context.Context, in FalsifierVerificationInput) FalsifierReport {
	r := FalsifierReport{SchemaVersion: FalsifierVerificationSchemaVersion, RuleSetHash: in.RulesetHash}
	ps := append([]FalsifierProposal(nil), in.Proposals...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	seen := map[string]bool{}
	for _, p := range ps {
		r.Proofs = append(r.Proofs, v.verifyOne(ctx, in, p, seen))
	}
	r.Hash = reportHash(r)
	return r
}

// NewFalsifierReport builds a canonical report from proofs the deterministic
// track minted itself (no LLM proposal involved) and pins its hash.
func NewFalsifierReport(ruleSetHash string, proofs ...FalsifierProof) FalsifierReport {
	r := FalsifierReport{SchemaVersion: FalsifierVerificationSchemaVersion, RuleSetHash: ruleSetHash, Proofs: proofs}
	r.Hash = reportHash(r)
	return r
}

// reportHash is the canonical identity of a report: the stored Hash field is
// excluded, so recomputing the hash of a persisted report is idempotent and
// a mismatch can only mean the content changed.
func reportHash(r FalsifierReport) string {
	r.Hash = ""
	return hashCanonical(canonicalReport(r))
}

// canonicalReport returns the order-insensitive projection of a report: the
// proof hash must depend on the semantic content only, never on the order in
// which proposals, observations, evidence references or coverage entries
// happened to arrive.
func canonicalReport(r FalsifierReport) FalsifierReport {
	c := r
	c.Proofs = append([]FalsifierProof(nil), r.Proofs...)
	sort.Slice(c.Proofs, func(i, j int) bool { return c.Proofs[i].ID < c.Proofs[j].ID })
	for i := range c.Proofs {
		p := &c.Proofs[i]
		p.EvidenceRefs = sortedStrings(p.EvidenceRefs)
		p.Coverage.ExpectedSubjects = sortedSubjects(p.Coverage.ExpectedSubjects)
		p.Coverage.CheckedSubjects = sortedSubjects(p.Coverage.CheckedSubjects)
		p.Coverage.AbsentSubjects = sortedSubjects(p.Coverage.AbsentSubjects)
		p.Coverage.PresentSubjects = sortedSubjects(p.Coverage.PresentSubjects)
		p.Coverage.ShippingRoots = sortedStrings(p.Coverage.ShippingRoots)
		p.Coverage.ScopeUnknown = sortedStrings(p.Coverage.ScopeUnknown)
		p.Coverage.DiscardedUnreachable = sortedStrings(p.Coverage.DiscardedUnreachable)
		p.Coverage.SkippedPackages = sortedStrings(p.Coverage.SkippedPackages)
		p.Coverage.OpenExceptions = sortedStrings(p.Coverage.OpenExceptions)
		p.Coverage.ClosedExceptions = sortedStrings(p.Coverage.ClosedExceptions)
		p.Coverage.ObservedDynamicMarkers = sortedStrings(p.Coverage.ObservedDynamicMarkers)
		p.Coverage.IgnoredDynamicMarkers = sortedStrings(p.Coverage.IgnoredDynamicMarkers)
		p.Coverage.UnresolvedDispatch = sortedStrings(p.Coverage.UnresolvedDispatch)
		p.Coverage.DynamicMarkers = sortedStrings(p.Coverage.DynamicMarkers)
		p.History = sortedTransitions(p.History)
	}
	return c
}

func sortedStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedSubjects(in []FalsifierSubject) []FalsifierSubject {
	if len(in) == 0 {
		return in
	}
	out := append([]FalsifierSubject(nil), in...)
	canonSubjects(out)
	return out
}

func sortedTransitions(in []FalsifierTransition) []FalsifierTransition {
	if len(in) <= 1 {
		return in
	}
	out := append([]FalsifierTransition(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a := string(out[i].From) + "\x00" + string(out[i].To) + "\x00" + out[i].Reason + "\x00" + out[i].RuleID + "\x00" + out[i].RuleVersion
		b := string(out[j].From) + "\x00" + string(out[j].To) + "\x00" + out[j].Reason + "\x00" + out[j].RuleID + "\x00" + out[j].RuleVersion
		return a < b
	})
	return out
}
func (v *deterministicFalsifierVerifier) verifyOne(ctx context.Context, in FalsifierVerificationInput, p FalsifierProposal, seen map[string]bool) FalsifierProof {
	refs := append([]string(nil), p.EvidenceRefs...)
	sort.Strings(refs)
	pr := FalsifierProof{ID: p.ID, ProposalID: p.ID, ClaimID: p.ClaimID, ConditionID: p.ConditionID, Kind: p.Kind, Basis: BasisLLMProposed, Status: FalsifierUnknown, EvidenceRefs: refs}
	// subjectNote records, in every terminal Reason and History entry written
	// after the authoritative subject set was substituted for the proposal's
	// own list, that the check ran on the authoritative set — so audit and
	// replay can see the substitution instead of a silent override.
	subjectNote := ""
	fail := func(reason string, status FalsifierVerificationStatus, basis FalsifierBasis) {
		pr.Status = status
		pr.Basis = basis
		pr.Reason = reason + subjectNote
		from := FalsifierUnknown
		if in.Previous != nil && in.Previous.ID == p.ID && in.Previous.ClaimID == p.ClaimID && in.Previous.ConditionID == p.ConditionID {
			from = in.Previous.Status
		}
		pr.History = []FalsifierTransition{{From: from, To: status, Reason: reason + subjectNote, RuleID: pr.RuleID, RuleVersion: pr.RuleVersion}}
	}
	if v.source == nil || in.ExpectedRulesetHash == "" || in.RulesetHash != in.ExpectedRulesetHash || v.source.RuleSetHash() == "" || v.source.RuleSetHash() != in.RulesetHash {
		fail("ruleset hash mismatch", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	if in.RunID != "" {
		for _, o := range in.Observations {
			if o.RunID != "" && o.RunID != in.RunID {
				fail("observation belongs to another run", FalsifierUnknown, BasisUnsupported)
				return pr
			}
		}
	}
	if p.ID == "" || seen[p.ID] {
		fail("proposal id is not unique", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	seen[p.ID] = true
	var claim *Claim
	for i := range in.Assessment.Claims {
		if in.Assessment.Claims[i].ID == p.ClaimID {
			claim = &in.Assessment.Claims[i]
			break
		}
	}
	if claim == nil {
		fail("claim does not exist", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	if !claim.DecisionRelevant {
		fail("claim is not decision-relevant", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	declared := map[string]bool{}
	for _, x := range claim.EvidenceRefs {
		declared[x] = true
	}
	checks := map[string]ReferenceCheck{}
	for _, x := range in.FactValidation.References {
		checks[x.EvidenceID] = x
	}
	snap := in.Stage0.Snapshot.ContentHash
	observationIDs, ok := proposalObservationIDs(in.Assessment, p.EvidenceRefs)
	if !ok {
		fail("evidence reference has no canonical observation locator", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	for i, id := range p.EvidenceRefs {
		if !declared[id] {
			fail("evidence reference is not owned by claim", FalsifierUnknown, BasisUnsupported)
			return pr
		}
		c, ok := checks[id]
		if !ok {
			fail("evidence reference was not validated", FalsifierUnknown, BasisUnsupported)
			return pr
		}
		if c.Status != FactValid {
			fail("evidence reference is not VALID", FalsifierUnknown, BasisUnsupported)
			return pr
		}
		if c.SnapshotHash != "" && snap != "" && c.SnapshotHash != snap {
			fail("foreign snapshot", FalsifierUnknown, BasisUnsupported)
			return pr
		}
		if i >= len(observationIDs) {
			fail("evidence reference has no canonical observation locator", FalsifierUnknown, BasisUnsupported)
			return pr
		}
	}
	if in.FactValidation.Status != ValidationComplete {
		fail("fact validation is not COMPLETE", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	advisory := ""
	if len(in.Stage0.Input.Finding.Vulnerability.IDs) > 0 {
		advisory = in.Stage0.Input.Finding.Vulnerability.IDs[0]
	}
	// The proof binds to the module identity the snapshot actually resolved:
	// an intake that names no version still has one — the module graph's
	// resolved version of the vulnerable package — and that is the identity
	// the deterministic tools recorded.
	module := in.Stage0.Input.Finding.Component.Package
	if module == "" {
		module = in.Stage0.Input.Finding.Component.Name
	}
	if module == "" {
		module = in.Stage0.PackageCheck.ResolvedPath
	}
	version := in.Stage0.Input.Finding.Component.Version
	if version == "" {
		version = in.Stage0.PackageCheck.ResolvedVersion
	}
	if v.source == nil {
		fail("mandatory condition source unsupported", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	cond, err := v.source.Resolve(ctx, MandatoryConditionLookup{AdvisoryID: advisory, Module: module, ResolvedVersion: version, SnapshotHash: snap, Proposal: p})
	if err != nil || !cond.Mandatory {
		fail("mandatory condition source unsupported", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	if cond.SnapshotHash != "" && snap != "" && cond.SnapshotHash != snap {
		fail("mandatory condition snapshot mismatch", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	if cond.ID != p.ConditionID || cond.Kind != p.Kind {
		fail("mandatory condition binding mismatch", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	// The snapshot and build-context bindings are proven before any
	// subject-set decision: auto-substitution below may only run once the
	// authoritative condition, snapshot, build context and ruleset are all
	// bound to this run.
	if snap == "" || cond.SnapshotHash == "" || cond.SnapshotHash != snap {
		fail("snapshot binding incomplete", FalsifierUnknown, BasisUnsupported)
		return pr
	}
	// cond.ExpectedSubjects is the authoritative subject set — the
	// advisory's declared affected symbols — and it is the only set the
	// verifier checks. A proposal whose own subject list diverges no longer
	// dies on the mismatch alone: when the authoritative bindings are
	// complete the check proceeds against cond.ExpectedSubjects and the
	// proposal's list is ignored for coverage, absence and final proof.
	// Without a complete binding there is no trustworthy authoritative set
	// to substitute, so the mismatch keeps its refusal.
	if !sameSubjects(cond.ExpectedSubjects, p.Subjects) {
		if !(cond.Mandatory && len(cond.ExpectedSubjects) > 0 && cond.BuildContextHash != "") {
			fail("proposal subject set mismatch", FalsifierUnknown, BasisUnsupported)
			return pr
		}
		subjectNote = " (authoritative subject set used)"
	}
	pr.Mandatory = true
	pr.Basis = BasisCheckerVerified
	pr.RuleID = cond.RuleID
	pr.RuleVersion = cond.RuleVersion
	pr.Coverage.ExpectedSubjects = append([]FalsifierSubject(nil), cond.ExpectedSubjects...)
	pr.Coverage.SnapshotHash = snap
	obs := selectObservations(in.Observations, observationIDs)
	cov := coverageFor(obs, cond.ExpectedSubjects, coverageToolFor(p.Kind))
	if p.Kind == FalsifierLocusFunctionAbsent {
		cov.UnreachabilityBuild = in.Stage0.Materials.PackageBuild
		cov.DeadnessContract = cond.DefectSemantics
	}
	pr.Coverage = cov
	if p.Kind == FalsifierLocusFunctionAbsent {
		if err := validateAdmittingUnreachabilityCoverage(cov); err != nil {
			fail("function unreached requires complete inventory and semantic payload: " + err.Error(), FalsifierInsufficientScope, BasisCheckerVerified)
			pr.Coverage = cov
			return pr
		}
		// The unreachability kind is admissible only through the
		// deterministic kernel's own observation: a complete
		// symbol-unreachability proof over the declared subjects.
		approved := false
		var why string
		for _, o := range obs {
			if ok, reason := UnreachabilityObservationApproved(o, in.Stage0); ok {
				approved = true
				break
			} else if why == "" {
				why = reason
			}
		}
		if !approved {
			if why == "" {
				why = "no symbol-unreachability observation was recorded"
			}
			fail("function unreached requires the kernel proof: "+why, FalsifierInsufficientScope, BasisCheckerVerified)
			pr.Coverage = cov
			return pr
		}
	}
	if p.Kind == FalsifierCodeAbsent {
		// Coverage comes only from verify_code_absence observations now;
		// an absent-tools run or a foreign-tool citation leaves the proof
		// unsupported — UNKNOWN, never a scope claim on borrowed data.
		closureObs := false
		for _, o := range obs {
			if o.Tool == "verify_code_absence" {
				closureObs = true
				break
			}
		}
		if !closureObs {
			fail("approved deterministic absence observation missing", FalsifierUnknown, BasisUnsupported)
			pr.Coverage = cov
			return pr
		}
	}
	if len(cov.ExpectedSubjects) > 0 && !sameSubjects(cov.ExpectedSubjects, cov.CheckedSubjects) {
		fail("subject set incomplete", FalsifierUnknown, BasisCheckerVerified)
		pr.Coverage = cov
		return pr
	}
	if p.Kind == FalsifierCodeAbsent && (cov.ClosureHash == "" || !cov.ClosureComplete) {
		fail("code_absent requires complete import-closure metadata; subject set incomplete", FalsifierInsufficientScope, BasisCheckerVerified)
		pr.Coverage = cov
		return pr
	}
	if cov.Completeness != "COMPLETE" {
		fail("coverage is not COMPLETE", FalsifierInsufficientScope, BasisCheckerVerified)
		pr.Coverage = cov
		return pr
	}
	if p.Kind == FalsifierCodeAbsent {
		if err := validateAdmittingCodeAbsenceCoverage(cov); err != nil {
			status := FalsifierInsufficientScope
			if len(cov.PresentSubjects) > 0 {
				status = FalsifierContradicted
			}
			fail("code_absent coverage rejected: "+err.Error(), status, BasisCheckerVerified)
			pr.Coverage = cov
			return pr
		}
	}
	if in.RunID == "" || in.Attempt <= 0 {
		fail("run provenance incomplete", FalsifierUnknown, BasisUnsupported)
		pr.Coverage = cov
		return pr
	}
	for _, o := range obs {
		if o.RunID == "" || o.RunID != in.RunID {
			fail("observation run provenance mismatch", FalsifierUnknown, BasisUnsupported)
			pr.Coverage = cov
			return pr
		}
		if o.Attempt <= 0 || o.Attempt != in.Attempt {
			fail("observation attempt provenance mismatch", FalsifierUnknown, BasisUnsupported)
			pr.Coverage = cov
			return pr
		}
		if o.SnapshotHash == "" || snap == "" || o.SnapshotHash != snap {
			fail("cross-run or foreign snapshot evidence", FalsifierUnknown, BasisUnsupported)
			pr.Coverage = cov
			return pr
		}
		if o.BuildContextHash == "" || o.BuildContextHash != cond.BuildContextHash {
			fail("build context provenance mismatch", FalsifierUnknown, BasisUnsupported)
			pr.Coverage = cov
			return pr
		}
	}
	if len(obs) == 0 {
		fail("no run-owned observations", FalsifierUnknown, BasisUnsupported)
		pr.Coverage = cov
		return pr
	}
	if cov.BuildContextHash == "" || cond.BuildContextHash != cov.BuildContextHash {
		fail("build context binding incomplete", FalsifierUnknown, BasisUnsupported)
		pr.Coverage = cov
		return pr
	}
	if len(cov.SkippedPackages) > 0 || len(cov.UnresolvedDispatch) > 0 || len(cov.DynamicMarkers) > 0 {
		fail("coverage contains unresolved scope or dynamic markers", FalsifierInsufficientScope, BasisCheckerVerified)
		pr.Coverage = cov
		return pr
	}
	if p.Kind == FalsifierLocusPackageAbsent {
		g := in.Stage0.Materials.ModuleGraph
		if g == nil || !g.Complete || len(g.Modules) == 0 {
			fail("module graph incomplete", FalsifierInsufficientScope, BasisCheckerVerified)
			pr.Coverage = cov
			return pr
		}
		for _, s := range cond.ExpectedSubjects {
			for _, m := range g.Modules {
				if m.Path == s.Package {
					fail("locus package present", FalsifierContradicted, BasisCheckerVerified)
					pr.Coverage = cov
					return pr
				}
			}
		}
	}
	if p.Kind == FalsifierCodeAbsent {
		for _, o := range obs {
			if o.Tool == "verify_code_absence" && (o.Status != ToolStatusOK || o.Completeness != evidencetools.CompletenessComplete || len(o.Limitations) > 0) {
				fail("code_absent owning observation is not a successful COMPLETE check", FalsifierInsufficientScope, BasisCheckerVerified)
				pr.Coverage = cov
				return pr
			}
		}
	}
	approved := false
	for _, o := range obs {
		if p.Kind == FalsifierLocusFunctionAbsent {
			// The unreachability kind is approved by the kernel's own
			// closure record, never by an absence scan.
			if ok, _ := UnreachabilityObservationApproved(o, in.Stage0); ok {
				approved = true
			}
			continue
		}
		if p.Kind == FalsifierCodeAbsent && o.Tool == "verify_code_absence" && o.Status == ToolStatusOK && o.Completeness == evidencetools.CompletenessComplete && len(o.Limitations) == 0 && o.SnapshotHash == snap {
			approved = true
		}
		if p.Kind == FalsifierLocusPackageAbsent && o.Status == ToolStatusOK && o.Completeness == evidencetools.CompletenessComplete && len(o.Limitations) == 0 {
			approved = true
		}
	}
	if !approved {
		fail("approved deterministic absence observation missing", FalsifierUnknown, BasisUnsupported)
		pr.Coverage = cov
		return pr
	}
	pr.Status = FalsifierVerified
	pr.Falsifier = string(p.Kind)
	pr.Reason = "deterministic checker verified complete absence" + subjectNote
	if p.Kind == FalsifierLocusFunctionAbsent {
		pr.Reason = "the unreachability kernel closed every subcheck over the declared symbol set inside the recorded product scope" + subjectNote
	}
	pr.History = []FalsifierTransition{{From: FalsifierUnknown, To: FalsifierVerified, Reason: pr.Reason, RuleID: pr.RuleID, RuleVersion: pr.RuleVersion, SnapshotHash: snap}}
	pr.Coverage = cov
	return pr
}

// proposalObservationIDs resolves each proposal evidence id through the
// assessment's canonical locator. It intentionally does not consult
// RecordedObservation.EvidenceRefs: those payload refs describe facts
// produced by an observation and must never let a decoy observation claim
// another evidence id. Current assessment proposals use det:<id>; obs:<id>
// is accepted here for read-only observations and legacy/replay inputs.
func proposalObservationIDs(a Assessment, refs []string) ([]string, bool) {
	if len(a.Evidence) == 0 {
		// Older in-memory/replay fixtures predate assessment.evidence locators;
		// retain their exact observation-ID binding, never EvidenceRefs overlap.
		return append([]string(nil), refs...), len(refs) > 0
	}
	entries := make(map[string]EvidenceRef, len(a.Evidence))
	for _, ev := range a.Evidence {
		entries[ev.ID] = ev
	}
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		ev, ok := entries[ref]
		if !ok {
			return nil, false
		}
		id, ok := canonicalObservationIDForVerifier(ev.Locator)
		if !ok {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, len(ids) == len(refs) && len(ids) > 0
}

func canonicalObservationIDForVerifier(locator string) (string, bool) {
	if id, ok := canonicalObservationID(locator, "det:"); ok {
		return id, true
	}
	return canonicalObservationID(locator, "obs:")
}

func selectObservations(all []RecordedObservation, ids []string) []RecordedObservation {
	set := make(map[string]bool, len(ids))
	for _, x := range ids {
		set[x] = true
	}
	var out []RecordedObservation
	for _, o := range all {
		if set[o.ID] {
			out = append(out, o)
		}
	}
	return out
}

// informationalLimitations reports whether an observation's limitation list is
// the check's fixed interpretation bounds rather than a set of gaps. The
// unreachability kernel states its proof bounds on every COMPLETE result —
// scope, alternate build configurations, unmodeled dynamic mechanisms — while
// its actual gaps ride in the status and the payload's own limitation list. A
// list of bounds is never a coverage downgrade.
func informationalLimitations(o RecordedObservation) bool {
	if o.Tool != evidencetools.SymbolUnreachabilityTool || o.Completeness != evidencetools.CompletenessComplete {
		return false
	}
	payload, ok := parseUnreachabilityPayload(o.Payload)
	if !ok {
		return false
	}
	return payload.Data.Result.ValidateComplete(payload.Data.Result.Build) == nil
}

// coverageToolFor maps a falsifier kind to the deterministic tool that
// owns its coverage claim. An observation produced by any other tool may
// accompany the proof — provenance and evidence binding still apply to
// it — but it can never supply checked subjects, absent subjects or the
// closure record the admission checks read.
func coverageToolFor(kind FalsifierKind) string {
	switch kind {
	case FalsifierCodeAbsent:
		return "verify_code_absence"
	case FalsifierLocusPackageAbsent:
		return "verify_package_absence"
	case FalsifierLocusFunctionAbsent:
		return evidencetools.SymbolUnreachabilityTool
	default:
		return ""
	}
}

// coverageFor builds the proof's coverage record exclusively from the
// observations whose tool owns the falsifier kind: a foreign-tool
// observation cited beside the absence check can never contribute
// checked or absent subjects to a code_absent coverage — only the
// closure-backed verify_code_absence record may. Two admitting
// observations carrying different closure hashes describe different
// inventories; the conflict is recorded as an open exception so the
// proof can never claim a single closed scope.
func coverageFor(obs []RecordedObservation, expected []FalsifierSubject, tool string) FalsifierCoverage {
	c := FalsifierCoverage{ExpectedSubjects: append([]FalsifierSubject(nil), expected...)}
	for _, o := range obs {
		if tool != "" && o.Tool != tool {
			continue
		}
		if o.Status != ToolStatusOK {
			c.Completeness = string(evidencetools.CompletenessPartial)
			c.SkippedPackages = append(c.SkippedPackages, o.Tool+": status "+string(o.Status))
			continue
		}
		if c.Scope == "" {
			c.Scope = o.Scope
		}
		if c.Completeness == "" {
			c.Completeness = string(o.Completeness)
		} else if o.Completeness != evidencetools.CompletenessComplete {
			c.Completeness = string(o.Completeness)
		}
		if len(o.Limitations) > 0 && !informationalLimitations(o) {
			c.Completeness = string(evidencetools.CompletenessPartial)
			c.SkippedPackages = append(c.SkippedPackages, o.Limitations...)
		}
		if o.SnapshotHash != "" {
			c.SnapshotHash = o.SnapshotHash
		}
		var d struct {
			CheckedSubjects     []FalsifierSubject `json:"checked_subjects"`
			Subjects            []FalsifierSubject `json:"subjects"`
			AbsentSubjects      []FalsifierSubject `json:"absent_subjects"`
			PresentSubjects     []FalsifierSubject `json:"present_subjects"`
			DynamicMarkers      []string           `json:"dynamic_markers"`
			UnresolvedDispatch  []string           `json:"unresolved_dispatch"`
			BuildContextHash    string             `json:"build_context_hash"`
			CoverageRuleVersion string             `json:"coverage_rule_version"`
			ImportClosure *evidencetools.ImportClosureReport `json:"import_closure"`
		}
		if c.BuildContextHash == "" {
			c.BuildContextHash = o.BuildContextHash
		}
		// The archived payload is the serialized Observation: typed tool
		// output (checked/absent subjects, import-closure metadata) lives in
		// its `data` member, while the observation's own fields
		// (tool_status, scope_details) stay inert to this parse.
		if err := json.Unmarshal(o.Payload, &d); err != nil {
			c.Completeness = string(evidencetools.CompletenessPartial)
			c.SkippedPackages = append(c.SkippedPackages, o.Tool+": malformed payload")
			continue
		}
		var wrapped struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(o.Payload, &wrapped) == nil && len(wrapped.Data) > 0 {
			if err := json.Unmarshal(wrapped.Data, &d); err != nil {
				c.Completeness = string(evidencetools.CompletenessPartial)
				c.SkippedPackages = append(c.SkippedPackages, o.Tool+": malformed payload")
				continue
			}
		}
		if o.Tool == "verify_code_absence" {
			if err := evidencetools.ValidateCodeAbsenceInventory(d.ImportClosure, o.SnapshotHash, o.BuildContextHash); err != nil {
				c.OpenExceptions = append(c.OpenExceptions, "package inventory: "+err.Error())
			}
		}
		c.CheckedSubjects = append(c.CheckedSubjects, d.CheckedSubjects...)
		if len(d.CheckedSubjects) == 0 {
			c.CheckedSubjects = append(c.CheckedSubjects, d.Subjects...)
		}
		c.AbsentSubjects = append(c.AbsentSubjects, d.AbsentSubjects...)
		c.PresentSubjects = append(c.PresentSubjects, d.PresentSubjects...)
		c.DynamicMarkers = append(c.DynamicMarkers, d.DynamicMarkers...)
		c.UnresolvedDispatch = append(c.UnresolvedDispatch, d.UnresolvedDispatch...)
		if c.CoverageRuleVersion == "" {
			c.CoverageRuleVersion = d.CoverageRuleVersion
		} else if d.CoverageRuleVersion != c.CoverageRuleVersion {
			c.OpenExceptions = append(c.OpenExceptions, "observations disagree on coverage_rule_version")
		}
		if d.ImportClosure != nil {
			if c.Inventory != nil && (c.Inventory.InventoryReference != d.ImportClosure.InventoryReference || c.BuildContextHash != d.BuildContextHash && d.BuildContextHash != "") {
				c.OpenExceptions = append(c.OpenExceptions, "observations disagree on package inventory")
			} else {
				c.Inventory = d.ImportClosure
			}
			if c.ClosureHash != "" && d.ImportClosure.Hash != "" && d.ImportClosure.Hash != c.ClosureHash {
				c.ClosureComplete = false
				c.OpenExceptions = append(c.OpenExceptions, "observations describe different import-closure hashes")
			} else {
				if c.ClosureHash != "" && c.ClosureComplete != d.ImportClosure.Complete {
					c.ClosureComplete = false
					c.OpenExceptions = append(c.OpenExceptions, "observations disagree on import-closure completeness")
				} else {
					c.ClosureComplete = d.ImportClosure.Complete
				}
				if c.ClosureHash == "" {
					c.ClosureHash = d.ImportClosure.Hash
				}
			}
			c.OpenExceptions = append(c.OpenExceptions, d.ImportClosure.OpenExceptions...)
			c.ClosedExceptions = append(c.ClosedExceptions, d.ImportClosure.ClosedExceptions...)
			if c.ScopeRule == "" {
				c.ScopeRule, c.ScopeComplete, c.ScopeHash = d.ImportClosure.ScopeRule, d.ImportClosure.ScopeComplete, d.ImportClosure.ScopeHash
				c.DynamicRelevanceRule, c.DynamicRelevanceComplete = d.ImportClosure.DynamicRelevanceRule, d.ImportClosure.DynamicRelevanceComplete
			} else if c.ScopeRule != d.ImportClosure.ScopeRule || c.ScopeComplete != d.ImportClosure.ScopeComplete || c.ScopeHash != d.ImportClosure.ScopeHash || c.DynamicRelevanceRule != d.ImportClosure.DynamicRelevanceRule || c.DynamicRelevanceComplete != d.ImportClosure.DynamicRelevanceComplete {
				c.ScopeComplete, c.DynamicRelevanceComplete = false, false
				c.OpenExceptions = append(c.OpenExceptions, "observations disagree on scope or dynamic relevance contract")
			}
			c.ShippingRoots = append(c.ShippingRoots, d.ImportClosure.ShippingRoots...)
			c.ScopeUnknown = append(c.ScopeUnknown, d.ImportClosure.ScopeUnknown...)
			c.DiscardedUnreachable = append(c.DiscardedUnreachable, d.ImportClosure.DiscardedUnreachable...)
			if c.PackageStates == nil {
				c.PackageStates = map[string]string{}
			}
			for p, state := range d.ImportClosure.PackageStates {
				if old, ok := c.PackageStates[p]; ok && old != state {
					c.ScopeComplete = false
					c.OpenExceptions = append(c.OpenExceptions, "observations disagree on package state")
				}
				c.PackageStates[p] = state
			}
			if c.DynamicRelevanceRule == "" {
				c.DynamicRelevanceRule = d.ImportClosure.DynamicRelevanceRule
			}
			c.DynamicRelevanceComplete = c.DynamicRelevanceComplete || d.ImportClosure.DynamicRelevanceComplete
			c.ObservedDynamicMarkers = append(c.ObservedDynamicMarkers, d.ImportClosure.ObservedDynamicMarkers...)
			c.IgnoredDynamicMarkers = append(c.IgnoredDynamicMarkers, d.ImportClosure.IgnoredDynamicMarkers...)
		} else if tool == "verify_code_absence" {
			c.Completeness = string(evidencetools.CompletenessPartial)
			c.SkippedPackages = append(c.SkippedPackages, "verify_code_absence: import closure missing")
		}
		if d.BuildContextHash != "" {
			c.BuildContextHash = d.BuildContextHash
		}
		if o.Tool == evidencetools.SymbolUnreachabilityTool {
			if payload, ok := parseUnreachabilityPayload(o.Payload); ok {
				c.UnreachabilityPayloads = append(c.UnreachabilityPayloads, append(json.RawMessage(nil), o.Payload...))
				for _, sub := range payload.Data.Result.Subjects {
					c.CheckedSubjects = append(c.CheckedSubjects, FalsifierSubject{Package: sub.Package, Symbol: sub.Symbol})
				}
				for _, marker := range payload.Data.Result.DynamicMarkers { c.DynamicMarkers = append(c.DynamicMarkers, marker.Kind) }
				if err := payload.Data.Result.ValidateComplete(payload.Data.Result.Build); err != nil {
					c.Completeness = string(evidencetools.CompletenessPartial)
					c.SkippedPackages = append(c.SkippedPackages, err.Error())
				}
			}
		}
	}
	canonSubjects(c.ExpectedSubjects)
	canonSubjects(c.CheckedSubjects)
	sort.Strings(c.SkippedPackages)
	sort.Strings(c.UnresolvedDispatch)
	sort.Strings(c.DynamicMarkers)
	return c
}
func canonSubjects(x []FalsifierSubject) {
	sort.Slice(x, func(i, j int) bool {
		a := x[i].Package + "\x00" + x[i].Symbol + "\x00" + x[i].Role
		b := x[j].Package + "\x00" + x[j].Symbol + "\x00" + x[j].Role
		return a < b
	})
}
func sameSubjects(a, b []FalsifierSubject) bool {
	ca := func(x []FalsifierSubject) []string {
		r := []string{}
		for _, s := range x {
			r = append(r, s.Package+"\x00"+s.Symbol)
		}
		sort.Strings(r)
		return r
	}
	x, y := ca(a), ca(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
func hashCanonical(x interface{}) string {
	b, _ := json.Marshal(x)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// MaxFalsifierFeedbackPasses is the hard bound on proposal-repair turns the
// verifier may hand back to the agent: after the fact gate stands, at most
// two bounded repair passes run, then the last report stands whatever it
// concludes. Configured values are clamped to it — a larger limit never
// buys a third turn, and a non-positive one means the default bound.
const MaxFalsifierFeedbackPasses = 2

// clampFalsifierFeedbackPasses enforces the spec bound regardless of the
// configured value: non-positive means the default
// MaxFalsifierFeedbackPasses, anything larger is clamped down — a third
// repair pass is never run.
func clampFalsifierFeedbackPasses(configured int) int {
	switch {
	case configured <= 0:
		return MaxFalsifierFeedbackPasses
	case configured > MaxFalsifierFeedbackPasses:
		return MaxFalsifierFeedbackPasses
	default:
		return configured
	}
}

// FalsifierFeedbackItem is the deterministic repair entry for one
// unsuccessful proof: the proposal id, the verifier status and its exact
// reason, plus — for agent-repairable contract failures — the binding fix
// the agent is allowed to make. Retryable marks the classes a repair turn
// can actually change; source/ruleset/snapshot/run/build-context failures
// are external bindings the agent cannot fix, so they are reported for
// diagnostics only and never buy another model round.
type FalsifierFeedbackItem struct {
	ProposalID string                      `json:"proposal_id"`
	Status     FalsifierVerificationStatus `json:"status"`
	Reason     string                      `json:"reason"`
	Repair     string                      `json:"repair,omitempty"`
	Retryable  bool                        `json:"retryable"`
}

// FalsifierFeedback is one falsifier-repair pass handed to the agent: the
// pass number and the per-proposal verifier outcomes. It carries only
// contract reasons and binding repairs — never claim prose, the raw
// assessment, a verdict or a recommendation.
type FalsifierFeedback struct {
	Pass  int                     `json:"pass"`
	Items []FalsifierFeedbackItem `json:"items"`
}

// Retryable reports whether the pass carries at least one failure an agent
// repair turn is allowed to attempt: proposal-contract bindings only. A
// report whose failures are all external (ruleset, snapshot, run or build
// context provenance, an unsupported condition source, a semantic verdict
// like CONTRADICTED) is terminal — reporting it back would only burn model
// rounds on bindings the agent cannot change.
func (f FalsifierFeedback) Retryable() bool {
	for _, it := range f.Items {
		if it.Retryable {
			return true
		}
	}
	return false
}

// falsifierRepairable maps the verifier's failure reasons (matched as
// prefixes, after the "(authoritative subject set used)" substitution note
// is stripped) to the contract repair the agent may perform. Anything not
// listed is an external binding or a semantic outcome: it is still reported,
// but never triggers another repair round.
var falsifierRepairable = []struct {
	reason string
	repair string
}{
	{"proposal id is not unique",
		"give the proposal a unique id"},
	{"claim does not exist",
		"set claim_id to the id of a claim declared in claims"},
	{"claim is not decision-relevant",
		"bind the proposal to a decision-relevant claim or drop the proposal"},
	{"evidence reference is not owned by claim",
		"cite in evidence_refs only evidence ids that claim.evidence_refs of the bound claim declares, or add the id to that claim"},
	{"evidence reference has no canonical observation locator",
		"cite an evidence entry whose locator is the canonical observation id — det:<id> for evidence-tools observations, obs:<id> for snapshot observations"},
	{"evidence reference was not validated",
		"cite evidence entries the fact gate validated (VALID); an evidence id the gate never checked cannot bind a proposal"},
	{"evidence reference is not VALID",
		"cite an evidence entry the fact gate reports VALID — repair the fact binding first or choose a different declared evidence id"},
	{"mandatory condition binding mismatch",
		"set condition_id and kind to a mandatory condition the bound condition catalog declares; no other condition is accepted"},
	{"proposal subject set mismatch",
		"copy subjects verbatim from lookup_advisory affected_symbols by package and symbol — role is context only"},
	{"subject set incomplete",
		"cite observation evidence that checks every authoritative subject; an observation covering a different or partial set is not accepted"},
	{"coverage is not COMPLETE",
		"record and cite a deterministic observation whose coverage is COMPLETE over the whole authoritative subject set"},
	{"coverage contains unresolved scope or dynamic markers",
		"only an observation free of skipped packages, unresolved dispatch and dynamic markers is accepted; cite the complete observation id"},
	{"function unreached requires the kernel proof",
		"a locus_function_unreached proposal may cite only an approved symbol-unreachability kernel observation; record it via the symbol-unreachability tool and cite its det:<id>"},
	{"approved deterministic absence observation missing",
		"record the matching deterministic observation (verify_code_absence, verify_package_absence or the symbol-unreachability kernel) with det-tools and cite its observation id as det:<id> in evidence_refs"},
}

// falsifierRepair classifies one verifier reason: known proposal-contract
// failures return their binding repair, everything else is diagnostic only.
// Catalog admission failures split by cause: a non-admitting catalog (no
// catalog, a stale/foreign one, an incomplete run binding) is an external
// run fact the agent cannot repair, while an unsupported condition id or
// falsifier kind is malformed proposal ownership the agent can fix by
// naming a condition the bound catalog declares.
func falsifierRepair(reason string) (repair string, retryable bool) {
	base := strings.TrimSuffix(reason, " (authoritative subject set used)")
	if strings.HasPrefix(base, "falsifier proposal not admitted: ") {
		if strings.Contains(base, ErrNonAdmitting.Error()) {
			return "", false
		}
		return "set condition_id and kind to a mandatory condition the bound condition catalog declares (see the falsifier proposal capability block); no other condition is accepted", true
	}
	for _, r := range falsifierRepairable {
		if base == r.reason || strings.HasPrefix(base, r.reason+":") || strings.HasPrefix(base, r.reason+" ") {
			return r.repair, true
		}
	}
	return "", false
}

// BuildFalsifierFeedback derives the deterministic repair pass for one
// verifier report: one item per non-VERIFIED proof, carrying the proposal
// id, the status and the exact verifier reason, plus the contract repair
// when the failure class is agent-repairable. Proofs the verifier never
// traced to an agent proposal are skipped — the agent can neither repair
// nor resend them. A catalog-level refusal (no bound catalog, a stale or
// foreign one) is reported for diagnostics only: the agent cannot supply
// the missing run binding, so it never buys a repair turn.
func BuildFalsifierFeedback(report *FalsifierReport, pass int) FalsifierFeedback {
	fb := FalsifierFeedback{Pass: pass}
	if report == nil {
		return fb
	}
	for _, p := range report.Proofs {
		if p.Status == FalsifierVerified || p.ProposalID == "" {
			continue
		}
		item := FalsifierFeedbackItem{ProposalID: p.ProposalID, Status: p.Status, Reason: p.Reason}
		item.Repair, item.Retryable = falsifierRepair(p.Reason)
		fb.Items = append(fb.Items, item)
	}
	return fb
}

// FalsifierFeedbackMessage renders one falsifier-repair pass as the single
// user message sent back to the agent. The report is embedded as JSON; the
// instruction bounds the repair to proposal bindings and never names a
// verdict, a recommendation or claim semantics.
func FalsifierFeedbackMessage(fb FalsifierFeedback) string {
	report, err := json.Marshal(fb)
	if err != nil {
		// FalsifierFeedback is marshal-safe; the fallback still carries the
		// per-proposal ids and never the raw assessment.
		var b strings.Builder
		fmt.Fprintf(&b, "falsifier verifier pass %d items:", fb.Pass)
		for _, it := range fb.Items {
			fmt.Fprintf(&b, " %s=%s", it.ProposalID, it.Status)
		}
		report = []byte(b.String())
	}
	return fmt.Sprintf(
		"The deterministic falsifier verifier checked the falsifier_proposals of the previous assessment. "+
			"Repair only the proposal bindings listed below — subjects, evidence references, condition binding — "+
			"then return a complete "+AssessmentSchemaVersion+" JSON object. Do not restate reasoning; report: %s",
		report)
}
