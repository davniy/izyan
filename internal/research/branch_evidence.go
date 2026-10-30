package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// FactBuildInput carries the evidence an R6 fact may be built from:
// the deterministic lane result and the bounded verification trace —
// plus the session audit records of the verification phase. The audit
// ledger is authoritative for what the session executed and observed:
// lane facts bind through LaneResult.Records, verification facts
// through VerificationAudit, and a trace mutation can never create or
// alter a fact because nothing in the trace is trusted without its
// audit-recorded counterpart.
type FactBuildInput struct {
	Lane  *LaneResult
	Trace *VerificationTrace
	// VerificationAudit is the drained session audit for the
	// verification phase (EvidenceSession.DrainAudit), renumbered into
	// the lane's OBS-#### space by the caller exactly like the trace.
	VerificationAudit []evidencetools.AuditRecord
}

// factRow is one promoted observation: the R6 Fact plus the typed
// predicate rows the rule adapters evaluate. The Fact is complete on
// its own; rule facts are per-subject views of the same recorded
// payload and always reference the fact's id.
type factRow struct {
	fact  Fact
	rules []evaluator.RuleFact
}

// BuildDecisionFacts projects promoted observations into the R6 fact
// envelope (decision-artifact/1 shared_facts). Promotion is fail-closed:
// only OK observations with an explicit scope, a recorded completeness
// the fact can carry, digest-bearing evidence pins, a snapshot binding
// equal to the lane's content hash and a session audit record that
// binds tool, arguments and observation id become facts. Degraded
// (ERROR/TIMEOUT/UNSUPPORTED), unbound, undigested or stale records
// never promote — they stay where the trace and the lane already record
// them as limitations. Agent assertions, categories and bare evidence
// ids are never inputs here, so they can never become facts.
func BuildDecisionFacts(in FactBuildInput) ([]Fact, error) {
	rows, err := buildFactRows(in)
	if err != nil {
		return nil, err
	}
	out := make([]Fact, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.fact)
	}
	return out, nil
}

// BuildRuleFacts derives the evaluator-side view of the same promoted
// facts: one RuleFact per (subject, predicate) the recorded payload
// supports, each referencing its fact's id and digest. Because rule
// facts are built in the same pass as Facts, a rule input can never
// exist for an observation that failed promotion — an agent assertion
// or a pre-filled negative has no recorded payload and produces no
// rows.
func BuildRuleFacts(in FactBuildInput) ([]evaluator.RuleFact, error) {
	rows, err := buildFactRows(in)
	if err != nil {
		return nil, err
	}
	var out []evaluator.RuleFact
	for _, r := range rows {
		out = append(out, r.rules...)
	}
	return out, nil
}

func buildFactRows(in FactBuildInput) ([]factRow, error) {
	if in.Lane == nil {
		return nil, errors.New("fact envelope requires the deterministic lane result")
	}
	if strings.TrimSpace(in.Lane.ContentHash) == "" {
		return nil, errors.New("fact envelope requires the lane's snapshot content hash")
	}
	var rows []factRow
	seenID := map[string]bool{}
	// Lane facts: the persisted verified_facts list is the lane's own
	// promotion record — each must re-bind to the audit ledger before it
	// becomes an R6 fact.
	for i := range in.Lane.Facts {
		vf := &in.Lane.Facts[i]
		row, ok := promoteLaneFact(in.Lane, vf)
		if !ok {
			continue
		}
		if seenID[row.fact.ID] {
			continue
		}
		seenID[row.fact.ID] = true
		rows = append(rows, row)
	}
	// Lane-internal affected-resolve is discharged by the deterministic lane
	// itself. Its persisted observation is already canonical-pinned and
	// passes the complete closed-scope gate, but older lane records do not
	// carry evidence_refs. Promote that exact pinned copy here rather than
	// synthesizing a fact from the flow's summary. This exception is narrow:
	// only affected-resolve records that discharge and have a canonical digest
	// can contribute typed rule facts.
	for i := range in.Lane.Records {
		rec := &in.Lane.Records[i]
		if rec.Tool != "affected-resolve" || rec.Observation == nil || rec.Observation.ID == "" || rec.Tool != rec.Observation.Tool {
			continue
		}
		o := pinnedLaneObservation(in.Lane, rec.Observation.ID)
		pinned, ok := in.Lane.CanonicalByObs[rec.Observation.ID]
		if !ok || pinned == "" || o == nil || !laneRecordDischarges(in.Lane, o) {
			continue
		}
		digest, derr := canonicalObservationDigest(o)
		if derr != nil || digest != pinned {
			continue
		}
		factID := "fact-" + strings.ToLower(o.ID)
		if seenID[factID] || rec.RecordTime.IsZero() {
			continue
		}
		subject := observationSubject(in.Lane, o)
		if subject == "" {
			continue
		}
		trust := ""
		if rec.Tool == "affected-resolve" {
			// Version-axis facts carry the trust class of the module
			// graph the resolver actually used: AUTHORITATIVE only when
			// release evidence (artifact build info or operator metadata)
			// grounded them; empty for the source-snapshot fallback.
			trust = in.Lane.Affected.VersionGraphTrust
		}
		rules := ruleFactsForRecord(factID, subject, ruleFactKindOf(rec.Tool), FactCoverageComplete, rec, digest, in.Lane.DefectSemantics)
		for i := range rules {
			rules[i].TrustClass = trust
		}
		rows = append(rows, factRow{
			fact: Fact{
				ID: factID, Proposition: o.Fact, Subject: subject, Scope: o.Scope,
				SourceTool: rec.Tool, ToolVersion: toolVersionFor(rec.Tool, in.Lane),
				ObservationRefs: []string{"obs:" + o.ID}, DataDigest: digest,
				Coverage: FactCoverageComplete, Freshness: rec.RecordTime.UTC().Format(time.RFC3339),
				Limitations: append([]string(nil), o.Limitations...), Status: FactStatusVerified,
				TrustClass: trust,
			}, rules: rules,
		})
		seenID[factID] = true
	}
	if in.Trace != nil {
		auditByObs := map[string]*evidencetools.AuditRecord{}
		for i := range in.VerificationAudit {
			rec := &in.VerificationAudit[i]
			if rec.Observation == nil || rec.Observation.ID == "" {
				continue
			}
			if _, dup := auditByObs[rec.Observation.ID]; dup {
				continue
			}
			auditByObs[rec.Observation.ID] = rec
		}
		for i, o := range in.Trace.Observations {
			if o == nil || i >= len(in.Trace.Requests) {
				continue
			}
			req := in.Trace.Requests[i]
			rec := auditByObs[o.ID]
			if rec == nil {
				continue
			}
			if callAuditMismatch(req, o, rec) != "" {
				continue
			}
			row, ok := promoteTraceObservation(in.Lane, rec)
			if !ok || seenID[row.fact.ID] {
				continue
			}
			seenID[row.fact.ID] = true
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// canonicalObservationDigest pins the recorded observation bytes — the
// same canonical encoding (MarshalIndent payload without trailing LF)
// the persistence layer digests into CanonicalByObs.
func canonicalObservationDigest(o *evidencetools.Observation) (string, error) {
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// promotableObservation enforces the observation-level gates every
// promotion shares: OK status, an explicit scope, explicit scope
// details bound to this lane's snapshot, a coverage the fact envelope
// can state, and at least one digest-bearing evidence pin while every
// ref carries a hash-bearing or source-locating shape. An observation
// failing any gate stays a recorded limitation source, never a fact.
func promotableObservation(lane *LaneResult, o *evidencetools.Observation) bool {
	if o == nil || o.ToolStatus != evidencetools.StatusOK {
		return false
	}
	if o.Completeness != evidencetools.CompletenessComplete &&
		o.Completeness != evidencetools.CompletenessPartial {
		return false
	}
	if strings.TrimSpace(o.Scope) == "" || o.ScopeDetails == nil {
		return false
	}
	sd := o.ScopeDetails
	if sd.SnapshotHash == "" || sd.SnapshotHash != lane.ContentHash {
		return false
	}
	digestable := false
	for _, ref := range o.EvidenceRefs {
		if !evidenceRefRe.MatchString(ref) {
			return false
		}
		if strings.HasPrefix(ref, "sha256:") || strings.HasPrefix(ref, "ev:") {
			digestable = true
		}
	}
	return digestable
}

// promoteLaneFact re-derives an R6 fact from a lane verified fact by
// binding it back to the session ledger: the fact's provenance
// observation id must name an audit record whose tool, arguments
// (input digest), observation bytes (canonical digest), scope fields
// and snapshot hash all agree with what the fact claims. Any
// disagreement means the ledger does not carry what the fact asserts —
// promotion is refused, never repaired.
func promoteLaneFact(lane *LaneResult, vf *VerifiedFact) (factRow, bool) {
	if vf.Provenance.ObservationID == "" || vf.Status != "OK" {
		return factRow{}, false
	}
	// A bare FALSE claim is never promotable: only a recorded VERIFIED
	// negative verification may carry a negative fact.
	if vf.Claim == "FALSE" && vf.NegativeVerification != NegativeVerificationVerified {
		return factRow{}, false
	}
	var rec *evidencetools.AuditRecord
	for i := range lane.Records {
		r := &lane.Records[i]
		if r.Observation != nil && r.Observation.ID == vf.Provenance.ObservationID {
			rec = r
			break
		}
	}
	if rec == nil || rec.Observation == nil || rec.Tool != vf.Tool {
		return factRow{}, false
	}
	o := pinnedLaneObservation(lane, vf.Provenance.ObservationID)
	if o == nil {
		o = rec.Observation // compatibility for synthetic lanes without persisted pins
	}
	if !promotableObservation(lane, o) {
		return factRow{}, false
	}
	// Coverage maps the pinned recorded copy; the audit record is used
	// only for tool/argument binding because its pre-wire payload bytes
	// may marshal differently from the persisted canonical observation.
	var coverage string
	switch vf.Coverage {
	case "COMPLETE":
		if o.Completeness != evidencetools.CompletenessComplete {
			return factRow{}, false
		}
		coverage = FactCoverageComplete
	case "PARTIAL":
		coverage = FactCoveragePartial
	default:
		return factRow{}, false
	}
	digest, err := canonicalObservationDigest(o)
	if err != nil || digest != vf.DataDigest {
		return factRow{}, false
	}
	if pinned, ok := lane.CanonicalByObs[o.ID]; ok && pinned != digest {
		return factRow{}, false
	}
	inputSum := sha256.Sum256(rec.Args)
	if vf.InputDigest != hex.EncodeToString(inputSum[:]) {
		return factRow{}, false
	}
	if vf.SnapshotContentHash != lane.ContentHash {
		return factRow{}, false
	}
	freshness := vf.Provenance.GeneratedAt
	if freshness == "" && !rec.RecordTime.IsZero() {
		freshness = rec.RecordTime.UTC().Format(time.RFC3339)
	}
	if freshness == "" {
		return factRow{}, false
	}
	subject := ""
	if vf.UsageSubject != nil {
		s := vf.UsageSubject
		subject = subjectRefName(s.Module, s.Package, s.Symbol)
	} else {
		subject = observationSubject(lane, o)
	}
	if subject == "" {
		return factRow{}, false
	}
	if rec.Tool == evidencetools.SymbolUnreachabilityTool {
		var data evidencetools.SymbolUnreachabilityData
		if o.PayloadRef != nil || !decodeData(o.Data, &data) { return factRow{}, false }
		if data.Result.Complete && data.Result.ValidateComplete(domain.EffectiveBuildContext(lane.Snapshot)) != nil { return factRow{}, false }
	}
	rules := ruleFactsForRecord(vf.ID, subject, vf.Kind, coverageOf(vf), rec, digest, lane.DefectSemantics)
	trust := ""
	if rec.Tool == "affected-resolve" {
		trust = lane.Affected.VersionGraphTrust
	}
	for i := range rules {
		rules[i].TrustClass = trust
	}
	return factRow{
		fact: Fact{
			ID: vf.ID, Proposition: vf.Statement, Subject: subject, Scope: o.Scope,
			SourceTool: rec.Tool, ToolVersion: toolVersionFor(rec.Tool, lane),
			ObservationRefs: []string{"obs:" + o.ID}, DataDigest: digest,
			Coverage: coverage, Freshness: freshness, Limitations: append([]string{}, vf.Limitations...),
			Status: FactStatusVerified, TrustClass: trust,
		}, rules: rules,
	}, true
}

// promoteTraceObservation re-derives an R6 fact from one verification
// trace position: the audit-recorded copy is authoritative, the request
// was already bound to the record by callAuditMismatch, and the trace's
// own observation is used for nothing but pairing — a mutated trace
// cannot create or alter the fact the record carries.
func promoteTraceObservation(lane *LaneResult, rec *evidencetools.AuditRecord) (factRow, bool) {
	o := rec.Observation
	if !promotableObservation(lane, o) {
		return factRow{}, false
	}
	symbolOK := true
	if rec.Tool == evidencetools.SymbolUnreachabilityTool {
		// A symbol-unreachability observation promotes only when its
		// payload answers the check's question definitively, either way:
		// the closed proof (COMPLETE, every inventory closed, no reach
		// evidence anywhere) or the disproven finding (concrete product
		// references or a module-internal chain reaching a declared
		// subject — the positive-answer record, promoted as a PARTIAL-
		// coverage verified fact like package-usage USED). An open-scope
		// or undecodable payload promotes nothing: absence is never
		// claimed and a reach answer is never fabricated.
		var d evidencetools.SymbolUnreachabilityData
		if !decodeData(o.Data, &d) {
			return factRow{}, false
		}
		r := d.Result
		switch {
		case r.Complete:
			if o.PayloadRef != nil || r.ValidateComplete(domain.EffectiveBuildContext(lane.Snapshot)) != nil {
				return factRow{}, false
			}
		case len(r.ProductReferences) > 0 || len(r.ModuleReachable) > 0:
			symbolOK = o.Completeness == evidencetools.CompletenessPartial
		default:
			return factRow{}, false
		}
	}
	coverage := FactCoveragePartial
	if o.Completeness == evidencetools.CompletenessComplete {
		coverage = FactCoverageComplete
	}
	if !symbolOK {
		return factRow{}, false
	}
	digest, err := canonicalObservationDigest(o)
	if err != nil || rec.RecordTime.IsZero() {
		return factRow{}, false
	}
	freshness := rec.RecordTime.UTC().Format(time.RFC3339)
	subject, rules := traceFactSubjectAndRules(lane, rec, digest)
	if subject == "" {
		return factRow{}, false
	}
	return factRow{fact: Fact{ID: "fact-" + strings.ToLower(o.ID), Proposition: o.Fact, Subject: subject, Scope: o.Scope, SourceTool: rec.Tool, ToolVersion: evidencetools.AdapterVersion, ObservationRefs: []string{"obs:" + o.ID}, DataDigest: digest, Coverage: coverage, Freshness: freshness, Limitations: append([]string{}, o.Limitations...), Status: FactStatusVerified}, rules: rules}, true
}

// traceFactSubjectAndRules resolves the canonical subject binding for a
// verification fact: structured subjects are decoded from the
// audit-recorded arguments (usage-scope, package-usage), otherwise the
// recorded scope subject applies. The unbound fallback names the
// snapshot itself — never an advisory subject it cannot claim.
func traceFactSubjectAndRules(lane *LaneResult, rec *evidencetools.AuditRecord, digest string) (string, []evaluator.RuleFact) {
	o := rec.Observation
	var subject string
	switch rec.Tool {
	case evidencetools.UsageScopeTool:
		if s := usageScopeSubjectOf(rec.Args); s != nil {
			subject = subjectRefName(s.Module, s.Package, s.Symbol)
		}
	case evidencetools.PackageUsageTool:
		if s := packageUsageSubjectOf(rec.Args); s != nil {
			subject = subjectRefName(s.Module, s.Package, s.Symbol)
		}
	case evidencetools.SymbolUnreachabilityTool:
		var a evidencetools.SymbolUnreachabilityArgs
		if json.Unmarshal(rec.Args, &a) == nil && len(a.Subjects) == 1 {
			subject = subjectRefName(a.Module, a.Subjects[0].Package, a.Subjects[0].Symbol)
		}
	}
	if subject == "" {
		subject = observationSubject(lane, o)
	}
	factID := "fact-" + strings.ToLower(o.ID)
	return subject, ruleFactsForRecord(factID, subject, ruleFactKindOf(rec.Tool), coverageOfObs(o), rec, digest, lane.DefectSemantics)
}

// observationSubject names the canonical subject a recorded observation
// is bound to when no structured usage subject exists: the scope
// details' recorded subject when present (advisory ids become
// advisory:<id>), else the snapshot binding itself.
func observationSubject(lane *LaneResult, o *evidencetools.Observation) string {
	if o.ScopeDetails != nil && o.ScopeDetails.Subject != "" {
		s := o.ScopeDetails.Subject
		if strings.HasPrefix(s, "module:") || strings.HasPrefix(s, "package:") ||
			strings.HasPrefix(s, "symbol:") || strings.HasPrefix(s, "advisory:") ||
			strings.HasPrefix(s, "snapshot:") {
			return s
		}
		if lane.Advisory.Vuln != nil && s == lane.Advisory.Vuln.ID {
			return "advisory:" + s
		}
		// Anything else stays an opaque tool-declared subject name;
		// it never aliases a module/package/symbol grammar member.
		return s
	}
	return "snapshot:" + lane.ContentHash
}

// coverageOf maps the lane fact's recorded coverage onto the R6
// envelope vocabulary.
func coverageOf(vf *VerifiedFact) string {
	switch vf.Coverage {
	case "COMPLETE":
		return "COMPLETE"
	case "PARTIAL":
		return "PARTIAL"
	default:
		return "NOT_EVALUATED"
	}
}

func coverageOfObs(o *evidencetools.Observation) string {
	switch o.Completeness {
	case evidencetools.CompletenessComplete:
		return "COMPLETE"
	case evidencetools.CompletenessPartial:
		return "PARTIAL"
	default:
		return "NOT_EVALUATED"
	}
}

// ruleFactKindOf names the fact family a recorded tool's observations
// belong to, so rule results can report which evidence class grounded
// them. Generic observations carry no typed verdict — the predicates
// do the semantic work, not the kind label.
func ruleFactKindOf(tool string) string {
	switch tool {
	case "affected-resolve", implementationAxisTool:
		return evaluator.RuleFactKindApplicability
	case "get_module_version", "get_dependency_graph":
		return evaluator.RuleFactKindModuleGraph
	case evidencetools.UsageScopeTool:
		return evaluator.RuleFactKindUsageScope
	case evidencetools.PackageUsageTool:
		return evaluator.RuleFactKindPackageUsage
	case evidencetools.SymbolUnreachabilityTool:
		return evaluator.RuleFactKindSymbolUnreachability
	default:
		return evaluator.RuleFactKindObservation
	}
}

// ruleFactsForRecord decodes the audit-recorded payload into typed
// (subject, predicate, value) rows. Interpretation lives here — in the
// research lane — while the evaluator adapters stay generic
// predicate/value machinery. An undecodable or unrecognized payload
// still contributes the generic "recorded" row so fact provenance
// chains can reference it; it can never satisfy a typed rule.
func ruleFactsForRecord(factID, subject, kind, coverage string, rec *evidencetools.AuditRecord, digest string,
	contract *domain.DefectSemanticsContract) []evaluator.RuleFact {
	mk := func(subj, pred, value string) evaluator.RuleFact {
		return evaluator.RuleFact{
			ID:        factID,
			Subject:   subj,
			Kind:      kind,
			Predicate: pred,
			Value:     value,
			Scope:     rec.Observation.Scope,
			Status:    FactStatusVerified,
			Coverage:  coverage,
			Digest:    digest,
		}
	}
	var out []evaluator.RuleFact
	appendTyped := func(subj, pred, value string) {
		if subj == "" {
			return
		}
		out = append(out, mk(subj, pred, value))
	}
	switch rec.Tool {
	case evidencetools.SymbolUnreachabilityTool:
		appendSymbolUnreachabilityRuleFacts(appendTyped, rec, contract)
	case evidencetools.UsageScopeTool:
		appendUsageScopeRuleFact(appendTyped, subject, rec.Observation)
	case evidencetools.PackageUsageTool:
		appendPackageUsageRuleFact(appendTyped, subject, rec.Observation)
	case "affected-resolve", implementationAxisTool:
		appendApplicabilityRuleFacts(appendTyped, rec.Observation)
	case "get_module_version":
		var d struct {
			Module  string `json:"module"`
			Present bool   `json:"present"`
		}
		if decodeData(rec.Observation.Data, &d) && d.Module != "" {
			v := "false"
			if d.Present {
				v = "true"
			}
			appendTyped("module:"+d.Module, evaluator.PredicateModulePresent, v)
		}
	}
	if subject != "" {
		out = append(out, mk(subject, evaluator.PredicateRecorded, "recorded"))
	}
	return out
}

// appendSymbolUnreachabilityRuleFacts projects one kernel payload into rule
// facts. The "reached" answer is a positive observation and needs no premise.
// The "unreached" answer is a deadness conclusion: it may only become a rule
// fact when an admitted defect-semantics contract yields a deadness premise
// covered by the proof's own subject set. Without that premise the facts stay
// unprojected, so rule.declared-symbols-unreached can never establish on a
// proof the semantics do not support (genuine omission included).
func appendSymbolUnreachabilityRuleFacts(add func(string, string, string), rec *evidencetools.AuditRecord,
	contract *domain.DefectSemanticsContract) {
	var d evidencetools.SymbolUnreachabilityData
	if rec == nil || rec.Observation == nil || rec.Observation.PayloadRef != nil || !decodeData(rec.Observation.Data, &d) {
		return
	}
	r := d.Result
	if r.Complete {
		// The closed negative: every declared subject unreachable under
		// the full-closed inventory — the same premise
		// promoteTraceObservation enforces, so a malformed complete
		// record emits nothing.
		if r.ValidateComplete(r.Build) != nil {
			return
		}
		refs := make([]domain.SymbolRef, 0, len(r.Subjects))
		for _, s := range r.Subjects {
			if s.Package == "" || s.Symbol == "" {
				return
			}
			refs = append(refs, domain.SymbolRef{Package: s.Package, Symbol: s.Symbol})
		}
		if _, err := domain.RequireDeadnessPremise(contract, refs); err != nil {
			return
		}
		for _, s := range r.Subjects {
			if s.Package == "" || s.Symbol == "" || r.Module == "" {
				return
			}
			add(subjectRefName(r.Module, s.Package, s.Symbol), evaluator.PredicateDeclaredSymbolReachability, "unreached")
		}
		return
	}
	// The answered positive: concrete reach evidence contradicts the
	// unreachability close for exactly the subjects the record proves
	// reached. ModuleReachable keys are per-subject (pkg.Symbol);
	// product references pool across subjects, so they attribute a
	// subject only when the check ran on a single subject — the same
	// granularity the trace subject binding uses. Evidence that cannot
	// name its subject never claims reach for one.
	reached := map[string]bool{}
	for key := range r.ModuleReachable {
		reached[key] = true
	}
	if len(r.Subjects) == 1 && len(r.ProductReferences) > 0 {
		s := r.Subjects[0]
		reached[s.Package+"."+s.Symbol] = true
	}
	for _, s := range r.Subjects {
		if s.Package == "" || s.Symbol == "" || r.Module == "" {
			continue
		}
		if reached[s.Package+"."+s.Symbol] {
			add(subjectRefName(r.Module, s.Package, s.Symbol), evaluator.PredicateDeclaredSymbolReachability, "reached")
		}
	}
}

// appendUsageScopeRuleFact classifies a usage-scope payload into the
// product-closure-membership predicate. The verified-absence value is
// emitted only for the accepted marker pairs — the same gate
// VerifyDecision applies: test-only+VERIFIED, or unknown+
// VERIFIED_VENDOR_INVENTORY with the vendor-inventory conditions
// corroborated by the recorded payload and scope details.
func appendUsageScopeRuleFact(add func(subj, pred, value string), subject string, o *evidencetools.Observation) {
	var d absencePayload
	if !decodeData(o.Data, &d) || d.Module == "" {
		return
	}
	switch {
	case d.UsageScope == string(UsageScopeProduct), d.UsageScope == string(UsageScopeMixed):
		add(subject, evaluator.PredicateProductClosureMembership, "linked")
	case d.UsageScope == string(UsageScopeTestOnly) &&
		d.ProductAbsenceVerification == ProductAbsenceVerificationVerified:
		add(subject, evaluator.PredicateProductClosureMembership, "absent-verified")
	case d.UsageScope == string(UsageScopeUnknown) &&
		d.ProductAbsenceVerification == ProductAbsenceVerificationVendorInventory &&
		vendorInventoryProven(o, d):
		add(subject, evaluator.PredicateProductClosureMembership, "absent-verified")
	default:
		add(subject, evaluator.PredicateProductClosureMembership, "unclassified")
	}
}

// appendPackageUsageRuleFact classifies a package-usage payload into
// the product-source-usage predicate: a closed-scope VERIFIED negative
// carries not-used-verified, a USED verdict or a positive lower bound
// carries the positive values, anything else stays undetermined.
func appendPackageUsageRuleFact(add func(subj, pred, value string), subject string, o *evidencetools.Observation) {
	verdict, negVer, ok := packageUsageVerdict(o)
	if !ok {
		return
	}
	symbolSubject := strings.HasPrefix(subject, "symbol:")
	switch {
	case verdict == goanalysis.PackageUsageUsed:
		add(subject, evaluator.PredicateProductSourceUsage, "used")
	case !symbolSubject && verdict == goanalysis.PackageUsageNotUsed && negVer == goanalysis.PackageUsageNegativeVerified && o.Completeness == evidencetools.CompletenessComplete:
		add(subject, evaluator.PredicateProductSourceUsage, "not-used-verified")
	case packageUsagePositive(o):
		add(subject, evaluator.PredicateProductSourceUsage, "positive-lowerbound")
	default:
		add(subject, evaluator.PredicateProductSourceUsage, "undetermined")
	}
}

// appendApplicabilityRuleFacts projects the recorded affected-resolve
// payload into per-subject applicability predicates. Only the values
// the resolver recorded are emitted: a module the resolver never
// checked or whose version stayed undecidable gets an explicit
// "unknown", never a synthesized negative — absence of an emitted row
// means the lane did not resolve it.
func appendApplicabilityRuleFacts(add func(subj, pred, value string), o *evidencetools.Observation) {
	var d struct {
		Affected domain.AffectedResult `json:"affected_result"`
	}
	if !decodeData(o.Data, &d) {
		return
	}
	ar := d.Affected
	selected := map[string]bool{}
	for _, m := range ar.SelectedModules {
		selected[m] = true
	}
	if ar.SelectedModule != "" {
		selected[ar.SelectedModule] = true
	}
	pending := map[string]bool{}
	for _, m := range ar.PendingModules {
		pending[m] = true
	}
	for _, m := range ar.UnresolvedModules {
		pending[m] = true
	}
	// versionAffectedByModule is the per-entry version verdict. The
	// aggregate ar.VersionAffected is TRUE when ANY advisory entry is
	// affected, so projecting it per module would mark a fixed or pending
	// entry of a multi-entry advisory as in-range.
	versionAffectedByModule := map[string]bool{}
	for _, m := range ar.VersionAffectedModules {
		versionAffectedByModule[m] = true
	}
	for _, m := range ar.CheckedModules {
		subj := "module:" + m
		switch {
		case pending[m] && !selected[m]:
			add(subj, evaluator.PredicateModulePresent, "unknown")
		case selected[m]:
			add(subj, evaluator.PredicateModulePresent, "true")
		case ar.ModulePresent == domain.ClaimFalse:
			add(subj, evaluator.PredicateModulePresent, "false")
		default:
			add(subj, evaluator.PredicateModulePresent, "unknown")
		}
		switch {
		case versionAffectedByModule[m]:
			add(subj, evaluator.PredicateVersionInRange, "true")
		case ar.VersionAffected == domain.ClaimFalse:
			add(subj, evaluator.PredicateVersionInRange, "false")
		case pending[m]:
			// PendingModules ∪ UnresolvedModules is exactly the set of
			// entries whose version could not be resolved; a checked entry
			// that merely missed SelectedModules must never be read as
			// fixed (see AffectedResult.UnresolvedModules).
			add(subj, evaluator.PredicateVersionInRange, "unknown")
		case ar.VersionAffected == domain.ClaimTrue:
			// Selected and resolved, but not in the affected-version set:
			// the aggregate axis resolved TRUE for a different advisory
			// entry, so this module's version is out of range.
			add(subj, evaluator.PredicateVersionInRange, "false")
		default:
			add(subj, evaluator.PredicateVersionInRange, "unknown")
		}
		switch {
		case !selected[m]:
			add(subj, evaluator.PredicateBuildRelevant, "unknown")
		case ar.BuildRelevant == domain.ClaimTrue:
			add(subj, evaluator.PredicateBuildRelevant, "true")
		case ar.BuildRelevant == domain.ClaimFalse:
			add(subj, evaluator.PredicateBuildRelevant, "false")
		default:
			add(subj, evaluator.PredicateBuildRelevant, "unknown")
		}
		// The implementation axis is emitted only for the module(s) the
		// deterministic verifier actually covered; a module outside the
		// checked set keeps an open axis rather than inheriting another
		// module's result.
		covered := false
		for _, im := range ar.ImplementationModules {
			if im == m {
				covered = true
				break
			}
		}
		if covered {
			switch ar.VulnerableImplementationPresent {
			case domain.ClaimTrue:
				add(subj, evaluator.PredicateVulnerableImplementationPresent, "true")
			case domain.ClaimFalse:
				add(subj, evaluator.PredicateVulnerableImplementationPresent, "false")
			default:
				add(subj, evaluator.PredicateVulnerableImplementationPresent, "unknown")
			}
		}
	}
}
