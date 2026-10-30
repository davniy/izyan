package claimshape

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	triage "github.com/fedorovmv/izyan/internal/productb/triage"
	"golang.org/x/mod/semver"
)

// runFiles are the persisted artifacts extraction reads. Every file is
// optional: a run without an assessment simply has no claims to
// normalize (a technical-failure channel, reported as such), and the
// observation artifacts enrich signals when present.
type runFiles struct {
	Assessment   string
	Observations string
	Falsifier    string
	Stage0       string
	Decision     string
}

func findRun(dir string) runFiles {
	j := func(name string) string {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	return runFiles{
		Assessment:   j("assessment.json"),
		Observations: j("observation-archive.json"),
		Falsifier:    j("falsifier-verification.json"),
		Stage0:       j("stage0.json"),
		Decision:     j("decision.json"),
	}
}

// stage0Projection is the subset of stage0.json the extraction consumes:
// the deterministic advisory resolution (authoritative subjects,
// ranges), source identity and selected ref. Everything else stays
// unread — extraction binds to the authoritative projection, not to
// intake prose.
type stage0Projection struct {
	FindingID string `json:"finding_id"`
	Advisory  struct {
		ResolvedID string `json:"resolved_id"`
	} `json:"advisory"`
	ResolutionVulnerability struct {
		ID              string   `json:"id"`
		Aliases         []string `json:"aliases"`
		Module          string   `json:"module"`
		Package         string   `json:"package"`
		AffectedSymbols []struct {
			Package string   `json:"package"`
			Symbol  string   `json:"symbol"`
			GOOS    []string `json:"goos"`
		} `json:"affected_symbols"`
		AffectedVersions []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
			Limit        string `json:"limit"`
		} `json:"affected_versions"`
	} `json:"resolution_vulnerability"`
	Materialization struct {
		SourceID    string `json:"source_id"`
		SelectedRef string `json:"selected_ref"`
	} `json:"materialization"`
}

// decisionProjection is the subset of decision.json carried as provenance
// labels. The fields are outcomes of the recorded pipeline; extraction
// reports them, it does not consume them. The current shape is
// decision-package.v3 — the model judgment and the machine disposition are
// separate labels. The top-level Recommendation and
// TechnicalAssessment.InternalStatus fields are the explicitly historical
// decision-package.v2 projection: offline extraction still reads old
// artifacts, and neither shape is ever re-admitted or re-derived here.
type decisionProjection struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	FindingID     string `json:"finding_id"`
	// Current (decision-package.v3) labels.
	Judgment struct {
		Verdict string `json:"verdict"`
	} `json:"judgment"`
	MachineDisposition struct {
		Recommendation string `json:"recommendation"`
	} `json:"machine_disposition"`
	// Historical decision-package.v2 projection.
	TechnicalAssessment struct {
		InternalStatus string `json:"internal_status"`
	} `json:"technical_assessment"`
	Recommendation string `json:"recommendation"`
}

// lenientAssessment mirrors the persisted assessment wire form without the
// runtime validation hooks: extraction reads history, it does not
// re-admit it. Claims stay raw until the recorded schema version selects
// the explicitly historical assessment.v1 DTO or the current assessment.v2
// premise DTO.
type lenientAssessment struct {
	SchemaVersion        string                 `json:"schema_version"`
	FindingID            string                 `json:"finding_id"`
	Verdict              string                 `json:"verdict"`
	FactValidation       string                 `json:"fact_validation"`
	FactValidationDetail *triage.FactValidation `json:"fact_validation_detail"`
	Claims               []json.RawMessage      `json:"claims"`
	Evidence             []triage.EvidenceRef   `json:"evidence"`
	FalsifierProposals   []lenientProposal      `json:"falsifier_proposals"`
}

// assessmentClaim is the schema-neutral claim extraction consumes: the
// current assessment.v2 premise fields plus the historical assessment.v1
// status. It is a local DTO so offline extraction never inherits live
// ingress validation, which would reject an older record after a schema
// change.
type assessmentClaim struct {
	ID               string        `json:"id"`
	Statement        string        `json:"statement"`
	Status           string        `json:"status,omitempty"`
	Basis            string        `json:"basis,omitempty"`
	Subject          string        `json:"subject,omitempty"`
	Scope            string        `json:"scope,omitempty"`
	DecisionRelevant bool          `json:"decision_relevant"`
	EvidenceRefs     []string      `json:"evidence_refs,omitempty"`
	DependsOn        []string      `json:"depends_on,omitempty"`
	Binding          *claimBinding `json:"binding,omitempty"`
	Owner            string        `json:"owner,omitempty"`
	Reason           string        `json:"reason,omitempty"`
	ConflictsWith    []string      `json:"conflicts_with,omitempty"`
}

// claimBinding is the offline wire form of a premise binding; the kind is
// kept as a string so an unknown historical value never blocks extraction.
type claimBinding struct {
	Kind        string `json:"kind"`
	ReferenceID string `json:"reference_id"`
}

// historicalClaim is the assessment.v1 claim wire form, including its
// previous bare-string normalization: a string claim was stored as an
// unstated decision-relevant claim. This reader exists only for offline
// history extraction; live ingress never accepts it.
type historicalClaim assessmentClaim

func (c *historicalClaim) UnmarshalJSON(data []byte) error {
	var statement string
	if err := json.Unmarshal(data, &statement); err == nil {
		*c = historicalClaim(assessmentClaim{Statement: statement, Status: "unstated", DecisionRelevant: true})
		return nil
	}
	type plain historicalClaim
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*c = historicalClaim(p)
	return nil
}

// decodeAssessmentClaims reads the recorded claims with the DTO that
// matches the persisted schema version: assessment.v2 keeps the current
// premise fields, every older record keeps the historical lenient shape.
func decodeAssessmentClaims(schemaVersion string, raw []json.RawMessage) ([]assessmentClaim, error) {
	out := make([]assessmentClaim, 0, len(raw))
	for i, r := range raw {
		if schemaVersion == triage.AssessmentSchemaVersion {
			var c assessmentClaim
			if err := json.Unmarshal(r, &c); err != nil {
				return nil, fmt.Errorf("claims[%d]: %w", i, err)
			}
			out = append(out, c)
			continue
		}
		var c historicalClaim
		if err := json.Unmarshal(r, &c); err != nil {
			return nil, fmt.Errorf("claims[%d]: %w", i, err)
		}
		out = append(out, assessmentClaim(c))
	}
	return out, nil
}

// lenientProposal is the falsifier-proposal wire form minus the runtime
// validation: same fields, no mandatory-field enforcement.
type lenientProposal struct {
	ID           string                    `json:"id"`
	ClaimID      string                    `json:"claim_id"`
	ConditionID  string                    `json:"condition_id"`
	Kind         triage.FalsifierKind      `json:"kind"`
	Subjects     []triage.FalsifierSubject `json:"subjects"`
	EvidenceRefs []string                  `json:"evidence_refs"`
}

func decodeAssessment(b []byte) (lenientAssessment, error) {
	var a lenientAssessment
	if err := json.Unmarshal(b, &a); err != nil {
		return a, err
	}
	return a, nil
}

// ExtractRun normalizes every claim of one persisted intake run into
// canonical claims. The assessment's verdict, summary, mechanism and
// recommendation are copied into the run record verbatim as labels; the
// claim statements are copied into Source verbatim for audit. Neither
// text nor verdict influences any shape, polarity or subject —
// classification reads structured artifacts only.
func ExtractRun(runDir, ticket string) (*RunExtraction, error) {
	files := findRun(runDir)
	out := &RunExtraction{
		SchemaVersion: ExtractionSchemaVersion,
		Ticket:        ticket,
		RunDir:        runDir,
	}

	var stage0 stage0Projection
	if files.Stage0 != "" {
		if b, err := os.ReadFile(files.Stage0); err == nil {
			_ = json.Unmarshal(b, &stage0)
		}
	}
	out.Advisory = advisoryFacts(stage0)
	out.SourceID = stage0.Materialization.SourceID
	out.SelectedRef = stage0.Materialization.SelectedRef

	var decision decisionProjection
	if files.Decision != "" {
		if b, err := os.ReadFile(files.Decision); err == nil {
			_ = json.Unmarshal(b, &decision)
		}
	}
	switch decision.SchemaVersion {
	case "decision-package.v3":
		out.Judgment = decision.Judgment.Verdict
		out.Recommendation = decision.MachineDisposition.Recommendation
	default:
		// Historical decision-package.v2 (or a pre-versioned record): the
		// top-level recommendation and the removed internal status are the
		// only labels such a record carries. It is read as history and is
		// never re-validated or upgraded.
		out.InternalStatus = decision.TechnicalAssessment.InternalStatus
		out.Recommendation = decision.Recommendation
	}
	out.FindingID = firstNonEmpty(decision.FindingID, stage0.FindingID)
	out.RunID = decision.RunID

	var archive triage.ObservationArchive
	if files.Observations != "" {
		a, err := triage.ReadObservationArchive(files.Observations)
		if err != nil {
			return nil, fmt.Errorf("%s: observation-archive: %w", runDir, err)
		}
		archive = a
	}
	ix := newObservationIndex(archive.Observations)
	out.BuildContext = consensusBuildContext(archive.Observations)
	if ids := ix.ambiguousIDs(); len(ids) > 0 {
		sort.Strings(ids)
		out.Limitations = append(out.Limitations,
			"ambiguous recorded observation ids (normalized duplicates): "+strings.Join(ids, ", "))
	}

	var report triage.FalsifierReport
	if files.Falsifier != "" {
		if b, err := os.ReadFile(files.Falsifier); err == nil {
			_ = json.Unmarshal(b, &report)
		}
	}
	proofs := map[string]triage.FalsifierProof{}
	for _, p := range report.Proofs {
		proofs[p.ProposalID] = p
	}

	if files.Assessment == "" {
		out.HasAssessment = false
		out.Limitations = append(out.Limitations,
			"no assessment.json: run produced no parseable assessment (technical-failure channel); zero claims extracted")
		return out, nil
	}
	out.HasAssessment = true

	raw, err := os.ReadFile(files.Assessment)
	if err != nil {
		return nil, fmt.Errorf("%s: assessment: %w", runDir, err)
	}

	var assessment lenientAssessment
	assessment, err = decodeAssessment(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: assessment decode: %w", runDir, err)
	}
	claims, err := decodeAssessmentClaims(assessment.SchemaVersion, assessment.Claims)
	if err != nil {
		return nil, fmt.Errorf("%s: assessment claims: %w", runDir, err)
	}
	out.FindingID = assessment.FindingID
	out.Verdict = assessment.Verdict
	out.FactValidation = assessment.FactValidation

	evidence := map[string]triage.EvidenceRef{}
	for _, e := range assessment.Evidence {
		evidence[e.ID] = e
	}
	proposalsByClaim := map[string][]lenientProposal{}
	for _, p := range assessment.FalsifierProposals {
		proposalsByClaim[p.ClaimID] = append(proposalsByClaim[p.ClaimID], p)
	}
	factStatus := map[string]string{}
	if assessment.FactValidationDetail != nil {
		for _, r := range assessment.FactValidationDetail.References {
			factStatus[r.EvidenceID] = string(r.Status)
		}
	}

	unclassifiedTools := map[string]bool{}
	for i, c := range claims {
		claim := extractClaim(claimInput{
			run:       out,
			index:     i,
			claim:     c,
			evidence:  evidence,
			proposals: proposalsByClaim[c.ID],
			proofs:    proofs,
			factGate:  factStatus,
			ix:        ix,
			advisory:  out.Advisory,
		})
		for _, f := range claimFacets(claim) {
			if f.Family == string(famUnclassified) && f.Tool != "" {
				unclassifiedTools[f.Tool] = true
			}
		}
		out.Claims = append(out.Claims, claim)
	}
	for t := range unclassifiedTools {
		out.UnclassifiedTools = append(out.UnclassifiedTools, t)
	}
	sort.Strings(out.UnclassifiedTools)
	return out, nil
}

type claimInput struct {
	run       *RunExtraction
	index     int
	claim     assessmentClaim
	evidence  map[string]triage.EvidenceRef
	proposals []lenientProposal
	proofs    map[string]triage.FalsifierProof
	factGate  map[string]string
	ix        *observationIndex
	advisory  AdvisoryFacts
}

// claimFacets reaches the stored facet list of a canonical claim.
func claimFacets(c CanonicalClaim) []Facet {
	if v, ok := c.Parameters["facets"].([]Facet); ok {
		return v
	}
	return nil
}

// extractClaim normalizes one assessment claim. Effective evidence is the
// claim's own refs, extended with the bound proposals' refs when the
// claim cites nothing — a proposal-only claim keeps no invented refs
// otherwise. Each cited artifact yields exactly one facet; the claim's
// shape is a deterministic rollup of facet families.
func extractClaim(in claimInput) CanonicalClaim {
	src := in.claim
	id := src.ID
	if id == "" {
		id = fmt.Sprintf("claim-%04d", in.index+1)
	}
	out := CanonicalClaim{
		ID:       id,
		Shape:    ShapeUnsupported,
		Polarity: PolarityUnknown,
		Subject:  Subject{Kind: SubjectUnknown},
		Source: ClaimSource{
			Ticket:           in.run.Ticket,
			FindingID:        in.run.FindingID,
			RunID:            in.run.RunID,
			ClaimID:          src.ID,
			ClaimStatus:      src.Status,
			DecisionRelevant: src.DecisionRelevant,
			Statement:        src.Statement,
		},
	}

	refs := append([]string(nil), src.EvidenceRefs...)
	if len(refs) == 0 {
		for _, p := range in.proposals {
			refs = append(refs, p.EvidenceRefs...)
		}
	}
	refs = dedupe(refs)

	var facets []Facet
	var sigs []signal
	for _, ref := range refs {
		ev, ok := in.evidence[ref]
		if !ok {
			// A claim may cite an observation id directly without an
			// evidence entry: treat the ref itself as the locator.
			ev = triage.EvidenceRef{ID: ref, Kind: "observation", Locator: ref}
		}
		s := classifyEvidence(ev, in.ix)
		sigs = append(sigs, s)
		facets = append(facets, Facet{
			EvidenceID:    ref,
			Locator:       ev.Locator,
			Kind:          ev.Kind,
			Family:        string(s.family),
			Sign:          string(s.sign),
			Weight:        string(s.weight),
			Predicate:     s.predicate,
			Tool:          s.tool,
			ObservationID: s.observationID,
			Status:        s.status,
			Completeness:  s.completeness,
			FactStatus:    in.factGate[ref],
			Canonical:     s.canonical,
		})
	}
	out.EvidenceRefs = refs
	out.Parameters = map[string]any{}
	if len(facets) > 0 {
		out.Parameters["facets"] = facets
	}
	if len(in.proposals) > 0 {
		out.Parameters["bound_proposals"] = boundProposals(in.proposals, in.proofs)
	}

	decisional, contextual := partitionSignals(sigs)
	var unresolved, unclassified, weak int
	for _, s := range sigs {
		switch s.family {
		case famUnresolved:
			unresolved++
		case famUnclassified:
			unclassified++
		}
		if s.weight == weightWeak {
			weak++
		}
	}

	switch {
	case len(sigs) == 0:
		out.UnsupportedReason = ReasonNoEvidenceRefs
	case len(decisional) == 1:
		for f := range decisional {
			applyFamily(&out, f, sigs)
		}
	case usageCluster(decisional):
		applyUsageCluster(&out, sigs)

	case len(decisional) > 1:
		applyDerived(&out, sigs)
	case hasFamily(contextual, famApplicability):
		applyApplicability(&out, sigs, in.advisory)
	case hasFamily(contextual, famProvenance):
		applyProvenance(&out, sigs)
	case unclassified+unresolved > 0:
		out.UnsupportedReason = ReasonUnclassifiedEvidence
		if unclassified == 0 {
			out.UnsupportedReason = ReasonUnresolvableReference
		}
	default:
		out.UnsupportedReason = ReasonWeakEvidenceOnly
	}

	out.Subject = claimSubject(&out, sigs, in.proposals)
	out.Scope = claimScope(sigs)
	out.RequiredCapabilities = RequiredCapabilities(out.Shape)
	out.Predicate = ShapePredicate(out.Shape)

	// Structured caveats: recorded, never read from prose.
	var lims []string
	if unresolved > 0 {
		lims = append(lims, fmt.Sprintf("%d cited observation reference(s) do not resolve to a recorded observation of this run", unresolved))
	}
	if unclassified > 0 {
		lims = append(lims, fmt.Sprintf("%d cited artifact(s) have no canonical signal class", unclassified))
	}
	if weak > 0 && len(decisional) > 0 {
		lims = append(lims, fmt.Sprintf("%d cited artifact(s) are display-level locators contributing no predicate", weak))
	}
	if out.Shape != ShapeUnsupported && len(decisional) == 0 && len(sigs) > 0 {
		lims = append(lims, "claim binds no decisional observation; shape derives from contextual records only")
	}
	if len(lims) > 0 {
		out.Parameters["limitations"] = lims
	}
	if len(out.Parameters) == 0 {
		out.Parameters = nil
	}
	return out
}

// partitionSignals splits signals into decisional families (a named
// check with a checkable predicate) and contextual families
// (authoritative records the claim references). Weak and
// unclassified/unresolved signals belong to neither.
func partitionSignals(sigs []signal) (decisional map[signalFamily]bool, contextual map[signalFamily]bool) {
	decisional = map[signalFamily]bool{}
	contextual = map[signalFamily]bool{}
	for _, s := range sigs {
		switch s.weight {
		case weightDecisional:
			decisional[s.family] = true
		case weightContext:
			contextual[s.family] = true
		}
	}
	return decisional, contextual
}

func hasFamily(m map[signalFamily]bool, f signalFamily) bool { return m[f] }

// familySigns returns the set of reported signs within one decisional
// family.
func familySigns(sigs []signal, f signalFamily) map[sign]bool {
	out := map[sign]bool{}
	for _, s := range sigs {
		if s.weight == weightDecisional && s.family == f {
			out[s.sign] = true
		}
	}
	return out
}

// applyFamily assigns the canonical shape of a single decisional family
// together with the witnessed polarity. Paired families pick their
// negative spelling when every decisional signal reports the negative
// result; pair-less families keep one spelling and express the negative
// result as FALSE polarity. Mixed or undetermined signs keep the
// presence spelling with UNKNOWN polarity — never a guess.
func applyFamily(out *CanonicalClaim, fam signalFamily, sigs []signal) {
	signs := familySigns(sigs, fam)
	onlyNeg := signs[signNegative] && !signs[signPositive] && !signs[signUnknown]
	onlyPos := signs[signPositive] && !signs[signNegative] && !signs[signUnknown]
	switch fam {
	case famSubject, famPath, famControl:
		if onlyNeg {
			out.Shape = negativeShape(fam)
			out.Polarity = PolarityTrue
		} else {
			out.Shape = familyShape(fam)
			if onlyPos {
				out.Polarity = PolarityTrue
			}
		}
	case famEnvironment, famConfiguration, famInput, famPerimeter, famClosure:
		out.Shape = familyShape(fam)
		switch {
		case onlyPos:
			out.Polarity = PolarityTrue
		case onlyNeg:
			out.Polarity = PolarityFalse
		}
	default:
		out.UnsupportedReason = ReasonUnclassifiedEvidence
		return
	}
	out.Parameters["signal_family"] = string(fam)
	list := make([]string, 0, len(signs))
	for s := range signs {
		list = append(list, string(s))
	}
	sort.Strings(list)
	out.Parameters["decisional_signs"] = list
}

func familyShape(f signalFamily) Shape {
	switch f {
	case famSubject:
		return ShapeSubjectDeclared
	case famPath:
		return ShapePathReachable
	case famControl:
		return ShapeControlPresent
	case famEnvironment:
		return ShapeEnvironmentBuildGate
	case famConfiguration:
		return ShapeConfigurationPredicate
	case famInput:
		return ShapeInputOrigin
	case famPerimeter:
		return ShapePerimeterExposure
	case famClosure:
		return ShapeClosureComplete
	}
	return ShapeUnsupported
}

// negativeShape returns the absence/unreachable member of a family
// pair, used when every decisional signal of the family reports the
// negative result.
func negativeShape(f signalFamily) Shape {
	switch f {
	case famSubject:
		return ShapeSubjectAbsent
	case famPath:
		return ShapePathUnreachable
	case famControl:
		return ShapeControlAbsent
	}
	return familyShape(f)
}

// applyDerived marks a claim binding several decisional families as a
// derived claim: its asserted content is a conjunction or conclusion
// over the premise facets. The premise families are recorded so the
// entailment graph can rebuild the dependency edges; polarity stays
// UNKNOWN because a conjunction's asserted truth is a graph question,
// not a signal rollup.
func applyDerived(out *CanonicalClaim, sigs []signal) {
	out.Shape = ShapeDerivedMandatoryCondition
	fams := map[string]bool{}
	for _, s := range sigs {
		if s.weight == weightDecisional {
			fams[string(s.family)] = true
		}
	}
	list := make([]string, 0, len(fams))
	for f := range fams {
		list = append(list, f)
	}
	sort.Strings(list)
	out.Parameters["premise_families"] = list
}

// usageCluster reports whether the decisional families are exactly the
// usage cluster {subject, path}: both families describe occurrences of
// the subject (declarations, references, call sites), so a uniform sign
// across them is one usage fact, not a conjunction.
func usageCluster(decisional map[signalFamily]bool) bool {
	for f := range decisional {
		if f != famSubject && f != famPath {
			return false
		}
	}
	return len(decisional) == 2
}

// applyUsageCluster resolves a claim whose decisional evidence spans
// {subject, path}. Uniform signs collapse to the cluster member: the
// path spelling wins when a path probe is present (it is the stronger
// predicate — absence of invocation implies absence of use, never the
// reverse), otherwise the subject spelling. Mixed signs stay a derived
// claim: presence and absence signals for overlapping subjects are a
// conjunction the graph must evaluate, not a single usage fact.
func applyUsageCluster(out *CanonicalClaim, sigs []signal) {
	signs := map[sign]bool{}
	hasPath := false
	for _, s := range sigs {
		if s.weight != weightDecisional {
			continue
		}
		signs[s.sign] = true
		if s.family == famPath {
			hasPath = true
		}
	}
	onlyNeg := signs[signNegative] && !signs[signPositive] && !signs[signUnknown]
	onlyPos := signs[signPositive] && !signs[signNegative] && !signs[signUnknown]
	out.Parameters["signal_family"] = "usage"
	switch {
	case onlyNeg:
		if hasPath {
			out.Shape = ShapePathUnreachable
		} else {
			out.Shape = ShapeSubjectAbsent
		}
		out.Polarity = PolarityTrue
	case onlyPos:
		if hasPath {
			out.Shape = ShapePathReachable
		} else {
			out.Shape = ShapeSubjectDeclared
		}
		out.Polarity = PolarityTrue
	default:
		applyDerived(out, sigs)
	}
}

// applyApplicability shapes a claim that cites the module/version
// resolution context without any decisional check. The structured
// in_range fact is computed against the authoritative advisory ranges —
// the claim's polarity then records that witnessed value.
func applyApplicability(out *CanonicalClaim, sigs []signal, adv AdvisoryFacts) {
	out.Shape = ShapeApplicabilityVersionInRange
	module := adv.Module
	version := ""
	present := false
	presentKnown := false
	for _, s := range sigs {
		if s.tool == "get_module_version" {
			module = s.subject.Name
			version = s.version
			switch s.sign {
			case signPositive:
				present, presentKnown = true, true
			case signNegative:
				presentKnown = true
			}
		}
	}
	if module == "" {
		for _, s := range sigs {
			if s.family == famApplicability && s.subject.Name != "" {
				module = s.subject.Name
				break
			}
		}
	}
	if module != "" {
		out.Parameters["module"] = module
	}
	if version != "" {
		out.Parameters["resolved_version"] = version
	}
	if len(adv.AffectedRanges) > 0 {
		out.Parameters["affected_ranges"] = adv.AffectedRanges
	}
	out.Parameters["module_present"] = present
	out.Parameters["module_present_known"] = presentKnown
	if version != "" && len(adv.AffectedRanges) > 0 {
		if inRange, ok := VersionInRange(version, adv.AffectedRanges); ok {
			out.Parameters["in_range"] = inRange
			if inRange {
				out.Polarity = PolarityTrue
			} else {
				out.Polarity = PolarityFalse
			}
		}
	} else if presentKnown && !present {
		// The resolved module is absent: version applicability cannot
		// hold regardless of ranges.
		out.Polarity = PolarityFalse
		out.Parameters["in_range"] = false
	}
}

// VersionInRange deterministically evaluates the resolved module version
// against the authoritative affected ranges — the same fact a later
// capability would re-derive. It returns ok=false when the version is
// unparsable. Exported for the verification layer's advisory_range_matcher
// capability so both layers evaluate identically.
func VersionInRange(version string, ranges []VersionRange) (bool, bool) {
	v := canonicalVersion(version)
	if v == "" {
		return false, false
	}
	for _, r := range ranges {
		if iv := canonicalVersion(r.Introduced); iv != "" && semver.Compare(v, iv) < 0 {
			continue
		}
		if fv := canonicalVersion(r.Fixed); fv != "" && semver.Compare(v, fv) >= 0 {
			continue
		}
		if lv := canonicalVersion(r.LastAffected); lv != "" && semver.Compare(v, lv) > 0 {
			continue
		}
		if lv := canonicalVersion(r.Limit); lv != "" && semver.Compare(v, lv) < 0 {
			continue
		}
		return true, true
	}
	return false, true
}

func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

// applyProvenance shapes a claim bound only to authoritative records.
func applyProvenance(out *CanonicalClaim, sigs []signal) {
	out.Shape = ShapeProvenanceBound
	out.Polarity = PolarityTrue
	for _, s := range sigs {
		if s.family == famProvenance && s.subject.Name != "" {
			out.Parameters["bound_to"] = s.subject.Name
			break
		}
	}
}

// claimSubject picks the claim's canonical subject: the subject of its
// decisional signals when unique, else the bound proposal's subjects,
// else the family's natural subject. Multiple decisional subjects are
// preserved under parameters.subjects.
func claimSubject(out *CanonicalClaim, sigs []signal, proposals []lenientProposal) Subject {
	var subs []Subject
	seen := map[string]bool{}
	for _, s := range sigs {
		if s.weight != weightDecisional || s.subject.Name == "" {
			continue
		}
		key := string(s.subject.Kind) + "|" + s.subject.Name
		if !seen[key] {
			seen[key] = true
			subs = append(subs, s.subject)
		}
	}
	switch len(subs) {
	case 0:
		for _, s := range sigs {
			if s.weight == weightContext && s.subject.Name != "" {
				return s.subject
			}
		}
		for _, p := range proposals {
			for _, ps := range p.Subjects {
				return Subject{Kind: SubjectSymbol, Package: ps.Package, Symbol: ps.Symbol, Name: ps.Package + "." + ps.Symbol}
			}
		}
		return Subject{Kind: SubjectUnknown}
	case 1:
		return subs[0]
	}
	names := make([]string, 0, len(subs))
	for _, s := range subs {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	out.Parameters["subjects"] = subs
	return Subject{Kind: subs[0].Kind, Name: strings.Join(names, ", ")}
}

// claimScope aggregates the coverage envelope of the cited observations:
// worst completeness wins, and hashes are kept only when every cited
// observation agrees — a claim spanning two provenance contexts carries
// no single binding hash.
func claimScope(sigs []signal) Scope {
	rank := map[string]int{"": 0, "COMPLETE": 1, "PARTIAL": 2, "UNKNOWN": 3}
	worst := ""
	descriptors := map[string]bool{}
	obsIDs := map[string]bool{}
	var snap, bctx string
	snapOK, bctxOK := true, true
	for _, s := range sigs {
		if s.observationID == "" {
			// Agent-synthesized locators carry no recorded scope: they
			// can never read better than UNKNOWN.
			if s.weight == weightDecisional {
				if rank["UNKNOWN"] > rank[worst] {
					worst = "UNKNOWN"
				}
			}
			continue
		}
		obsIDs[s.observationID] = true
		c := s.completeness
		if s.status != "" && s.status != "OK" {
			c = "UNKNOWN"
		}
		if rank[c] > rank[worst] {
			worst = c
		}
		if s.scope != "" {
			descriptors[s.scope] = true
		}
		if snap == "" {
			snap = s.snapshotHash
		} else if s.snapshotHash != "" && s.snapshotHash != snap {
			snapOK = false
		}
		if bctx == "" {
			bctx = s.buildCtxHash
		} else if s.buildCtxHash != "" && s.buildCtxHash != bctx {
			bctxOK = false
		}
	}
	if worst == "" {
		worst = "UNKNOWN"
	}
	out := Scope{Completeness: worst}
	for d := range descriptors {
		out.Descriptors = append(out.Descriptors, d)
	}
	sort.Strings(out.Descriptors)
	for id := range obsIDs {
		out.ObservationIDs = append(out.ObservationIDs, id)
	}
	sort.Strings(out.ObservationIDs)
	if snapOK {
		out.SnapshotHash = snap
	}
	if bctxOK {
		out.BuildContextHash = bctx
	}
	return out
}

// boundProposals records the falsifier proposals attached to a claim,
// with the persisted proof outcome when the verifier report exists.
func boundProposals(proposals []lenientProposal, proofs map[string]triage.FalsifierProof) []BoundProposal {
	out := make([]BoundProposal, 0, len(proposals))
	for _, p := range proposals {
		bp := BoundProposal{
			ID:           p.ID,
			Kind:         string(p.Kind),
			ConditionID:  p.ConditionID,
			CheckShape:   CheckShapeForFalsifierKind(p.Kind),
			EvidenceRefs: append([]string(nil), p.EvidenceRefs...),
		}
		for _, s := range p.Subjects {
			bp.Subjects = append(bp.Subjects, Subject{
				Kind:    SubjectSymbol,
				Package: s.Package,
				Symbol:  s.Symbol,
				Name:    s.Package + "." + s.Symbol,
			})
		}
		if proof, ok := proofs[p.ID]; ok {
			bp.ProofStatus = string(proof.Status)
			bp.ProofBasis = string(proof.Basis)
			m := proof.Mandatory
			bp.ProofMandatory = &m
		}
		out = append(out, bp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// advisoryFacts projects the deterministic advisory context out of the
// stage0 resolution record.
func advisoryFacts(s stage0Projection) AdvisoryFacts {
	rv := s.ResolutionVulnerability
	out := AdvisoryFacts{
		ResolvedID: firstNonEmpty(s.Advisory.ResolvedID, rv.ID),
		Module:     firstNonEmpty(rv.Module, rv.Package),
		Package:    rv.Package,
	}
	ids := map[string]bool{}
	for _, id := range append([]string{rv.ID, s.Advisory.ResolvedID}, rv.Aliases...) {
		if id != "" && !ids[id] {
			ids[id] = true
			out.IDs = append(out.IDs, id)
		}
	}
	sort.Strings(out.IDs)
	envs := map[string]bool{}
	for _, a := range rv.AffectedSymbols {
		out.AffectedSymbols = append(out.AffectedSymbols, Subject{
			Kind:    SubjectSymbol,
			Package: a.Package,
			Symbol:  a.Symbol,
			Name:    a.Package + "." + a.Symbol,
		})
		for _, g := range a.GOOS {
			envs["goos="+g] = true
		}
	}
	for e := range envs {
		out.Environments = append(out.Environments, e)
	}
	sort.Strings(out.Environments)
	for _, r := range rv.AffectedVersions {
		out.AffectedRanges = append(out.AffectedRanges, VersionRange{
			Introduced:   r.Introduced,
			Fixed:        r.Fixed,
			LastAffected: r.LastAffected,
			Limit:        r.Limit,
		})
	}
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// consensusBuildContext returns the build-context key/value pairs every
// recorded observation agrees on — the run's build-context provenance,
// reported once instead of per claim.
func consensusBuildContext(obs []triage.RecordedObservation) map[string]string {
	var merged map[string]string
	seen := map[string]bool{}
	for _, o := range obs {
		var pl struct {
			ScopeDetails struct {
				BuildContext map[string]any `json:"build_context"`
			} `json:"scope_details"`
		}
		if json.Unmarshal(o.Payload, &pl) != nil || pl.ScopeDetails.BuildContext == nil {
			continue
		}
		for k, v := range pl.ScopeDetails.BuildContext {
			key := k + "=" + fmt.Sprint(v)
			if seen[key] {
				continue
			}
			seen[key] = true
			if merged == nil {
				merged = map[string]string{}
			}
			merged[k] = fmt.Sprint(v)
		}
	}
	return merged
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := xs[:0]
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
