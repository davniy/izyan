package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// factAudit is decisionAudit with record times stamped — the freshness
// pin a promoted fact requires.
func factAudit(tr *VerificationTrace) []evidencetools.AuditRecord {
	recs := decisionAudit(tr)
	for i := range recs {
		recs[i].RecordTime = time.Date(2026, 10, 16, 2, 0, 0, 0, time.UTC)
	}
	return recs
}

// factLane builds a lane carrying one persisted verified fact whose
// digests bind its audit record: the promotion path must re-derive
// exactly these pins or refuse.
func factLane(t *testing.T, tool string, obs *evidencetools.Observation, fact VerifiedFact) *LaneResult {
	t.Helper()
	lane := decisionLane(domain.ClaimTrue)
	lane.ContentHash = obs.ScopeDetails.SnapshotHash
	lane.Observations = []*evidencetools.Observation{obs}
	raw := testArgs()
	rec := evidencetools.AuditRecord{
		Tool: tool, Args: raw, Observation: obs,
		RecordTime: time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC),
	}
	lane.Records = []evidencetools.AuditRecord{rec}
	payload, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	inSum := sha256.Sum256(raw)
	if fact.ID == "" {
		fact.ID = "fact-obs-0001"
	}
	fact.Tool = tool
	fact.Statement = obs.Fact
	fact.Scope = obs.Scope
	fact.Status = "OK"
	fact.SnapshotContentHash = lane.ContentHash
	fact.DataDigest = hex.EncodeToString(sum[:])
	fact.InputDigest = hex.EncodeToString(inSum[:])
	fact.Provenance = FactProvenance{ObservationID: obs.ID, Source: "deterministic-lane",
		GeneratedAt: "2026-10-16T01:00:00Z"}
	lane.Facts = []VerifiedFact{fact}
	return lane
}

// usageFactLane is the positive fixture: a verified BUILD_USAGE_SCOPE
// fact over the accepted test-only proof shape.
func usageFactLane(t *testing.T) *LaneResult {
	t.Helper()
	obs := decisionObservation(evidencetools.UsageScopeTool, absentData())
	obs.ID = "OBS-0007"
	return factLane(t, evidencetools.UsageScopeTool, obs, VerifiedFact{
		Kind:                       FactKindBuildUsageScope,
		UsageSubject:               &FactUsageSubject{Module: testModule, Package: testPackage},
		UsageScope:                 string(UsageScopeTestOnly),
		ProductAbsenceVerification: ProductAbsenceVerificationVerified,
		Claim:                      "TRUE", Coverage: "COMPLETE",
	})
}

// TestFactBuildPromotesBoundObservations covers the positive envelope:
// an OK, digest-pinned, scope-bound, audit-recorded lane fact becomes
// an R6 Fact with independent provenance — tool, version, obs ref,
// data digest, coverage, freshness — plus its typed rule-fact view.
func TestFactBuildPromotesBoundObservations(t *testing.T) {
	lane := usageFactLane(t)
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("facts=%d want 1", len(facts))
	}
	f := facts[0]
	if f.ID != "fact-obs-0001" || f.SourceTool != evidencetools.UsageScopeTool ||
		f.ToolVersion == "" || f.Proposition == "" || f.Status != FactStatusVerified ||
		f.Coverage != FactCoverageComplete || f.Freshness == "" {
		t.Fatalf("fact=%+v", f)
	}
	if f.Subject != "package:"+testModule+"|"+testPackage {
		t.Fatalf("subject=%q", f.Subject)
	}
	if len(f.ObservationRefs) != 1 || f.ObservationRefs[0] != "obs:OBS-0007" {
		t.Fatalf("observation_refs=%v", f.ObservationRefs)
	}
	if !decisionHex64Re.MatchString(f.DataDigest) {
		t.Fatalf("data_digest %q is not 64-hex", f.DataDigest)
	}
	rules, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}

	var absent *evaluator.RuleFact
	for i := range rules {
		if rules[i].Predicate == evaluator.PredicateProductClosureMembership {
			absent = &rules[i]
		}
	}
	if absent == nil || absent.Value != "absent-verified" ||
		absent.Subject != "package:"+testModule+"|"+testPackage || absent.Digest != f.DataDigest {
		t.Fatalf("rule facts=%+v", rules)
	}
}

// TestFactTrustClassReleaseGraph proves affected-resolve facts carry the
// trust class of the version graph the resolver recorded: AUTHORITATIVE
// when the release module graph grounded them, absent for the
// source-snapshot fallback. The class is provenance only — it can never
// upgrade a fact — but it must be exact.
func TestFactTrustClassReleaseGraph(t *testing.T) {
	newResolveLane := func(trust string) *LaneResult {
		obs := decisionObservation("affected-resolve", map[string]any{
			"affected_result": domain.AffectedResult{
				ModulePresent:   domain.ClaimTrue,
				CheckedModules:  []string{testModule},
				CheckedPackages: []string{testPackage},
			},
		})
		obs.ID = "OBS-0009"
		obs.ScopeDetails.SnapshotHash = testContentHash
		lane := factLane(t, "affected-resolve", obs, VerifiedFact{
			Kind: "APPLICABILITY", Claim: "TRUE", Coverage: "COMPLETE",
		})
		lane.Affected.VersionGraphTrust = trust
		return lane
	}

	// Authoritative release graph: both fact paths (promoted lane fact
	// and the discharge-path record) carry AUTHORITATIVE.
	lane := newResolveLane(string(domain.ReleaseTrustAuthoritative))
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	trusted := 0
	for _, f := range facts {
		if f.SourceTool != "affected-resolve" {
			continue
		}
		trusted++
		if f.TrustClass != string(domain.ReleaseTrustAuthoritative) {
			t.Fatalf("fact %s trust_class %q", f.ID, f.TrustClass)
		}
	}
	if trusted == 0 {
		t.Fatal("no affected-resolve fact promoted")
	}

	// Source-snapshot fallback: the same fact carries no trust class —
	// a lower-trust graph must never masquerade as release evidence.
	facts2, err := BuildDecisionFacts(FactBuildInput{Lane: newResolveLane("")})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range facts2 {
		if f.TrustClass != "" {
			t.Fatalf("source-graph fact %s gained trust_class %q", f.ID, f.TrustClass)
		}
	}
}

// TestFactSubjectGranularity pins granularity as part of fact identity:
// a package-bound usage fact promotes under package:<m>|<p> and never
// under module:<m>, and the module-level aggregate promotes only under
// module:<m> — the evaluator's exact-subject matching then keeps a
// package fact from satisfying a module-only subject (and vice versa).
func TestFactSubjectGranularity(t *testing.T) {
	pkgLane := usageFactLane(t)
	pkgFacts, err := BuildDecisionFacts(FactBuildInput{Lane: pkgLane})
	if err != nil || len(pkgFacts) != 1 {
		t.Fatalf("facts=%v err=%v", pkgFacts, err)
	}
	if pkgFacts[0].Subject != "package:"+testModule+"|"+testPackage {
		t.Fatalf("package fact subject=%q", pkgFacts[0].Subject)
	}
	// Module-level aggregate: usage-scope recorded for the module alone
	// (module-only advisory subject) binds to module:<m>, and no
	// package-level fact is synthesized from it.
	obs := decisionObservation(evidencetools.UsageScopeTool, absentDataFor(testModule, ""))
	obs.ID = "OBS-0007"
	modLane := factLane(t, evidencetools.UsageScopeTool, obs, VerifiedFact{
		Kind:                       FactKindBuildUsageScope,
		UsageSubject:               &FactUsageSubject{Module: testModule},
		UsageScope:                 string(UsageScopeTestOnly),
		ProductAbsenceVerification: ProductAbsenceVerificationVerified,
		Claim:                      "TRUE", Coverage: "COMPLETE",
	})
	modFacts, err := BuildDecisionFacts(FactBuildInput{Lane: modLane})
	if err != nil || len(modFacts) != 1 {
		t.Fatalf("facts=%v err=%v", modFacts, err)
	}
	if modFacts[0].Subject != "module:"+testModule {
		t.Fatalf("module fact subject=%q", modFacts[0].Subject)
	}
	// Rule facts inherit the same granularity — no cross-level alias.
	rules, err := BuildRuleFacts(FactBuildInput{Lane: modLane})
	if err != nil {
		t.Fatal(err)
	}
	for _, rf := range rules {
		if strings.HasPrefix(rf.Subject, "package:") || strings.HasPrefix(rf.Subject, "symbol:") {
			t.Fatalf("module fact leaked a package/symbol rule row: %+v", rf)
		}
	}
}

// TestFactBuildFailClosed enumerates the promotion refusals: every
// tampering with the ledger↔fact binding — missing record, wrong tool,
// stale digests, snapshot drift, degraded observation, unbound subject,
// bare FALSE claim — prevents promotion.
func TestFactBuildFailClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(l *LaneResult)
	}{
		{"missing-audit-record", func(l *LaneResult) { l.Records = nil }},
		{"tool-mismatch", func(l *LaneResult) { l.Records[0].Tool = "find_callers" }},
		{"stale-data-digest", func(l *LaneResult) {
			l.Facts[0].DataDigest = strings.Repeat("0", 64)
		}},
		{"stale-canonical-pin", func(l *LaneResult) {
			l.CanonicalByObs = map[string]string{"OBS-0007": strings.Repeat("1", 64)}
		}},
		{"input-digest-mismatch", func(l *LaneResult) {
			l.Facts[0].InputDigest = strings.Repeat("2", 64)
		}},
		{"snapshot-mismatch", func(l *LaneResult) {
			l.Facts[0].SnapshotContentHash = "other-hash"
		}},
		{"degraded-observation", func(l *LaneResult) {
			l.Records[0].Observation.ToolStatus = evidencetools.StatusError
			l.Records[0].Observation.Completeness = evidencetools.CompletenessUnknown
		}},
		{"partial-coverage-claim", func(l *LaneResult) {
			l.Records[0].Observation.Completeness = evidencetools.CompletenessPartial
		}},
		{"undigested-observation", func(l *LaneResult) {
			l.Records[0].Observation.EvidenceRefs = []string{"src:main.go#L1"}
		}},
		{"unbound-observation-id", func(l *LaneResult) {
			l.Facts[0].Provenance.ObservationID = "OBS-9999"
		}},
		{"bare-false-claim", func(l *LaneResult) {
			l.Facts[0].Kind = FactKindPackageUsage
			l.Facts[0].Claim = "FALSE"
			l.Facts[0].NegativeVerification = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lane := usageFactLane(t)
			tc.mut(lane)
			facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
			if err != nil {
				t.Fatal(err)
			}
			if len(facts) != 0 {
				t.Fatalf("tampered lane promoted %d facts", len(facts))
			}
		})
	}
}

// TestFactBuildAgentAssertionNeverPromotes proves the envelope only
// reads the audit ledger: a lane carrying an agent assertion and
// agent-shaped evidence refs produces zero facts — provenance is
// structural, not textual.
func TestFactBuildAgentAssertionNeverPromotes(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Observations = []*evidencetools.Observation{{
		ID: "OBS-9000", Tool: "agent-assertion", Fact: "agent says: not exploitable",
		Scope: "agent prose", Completeness: evidencetools.CompletenessComplete,
		ToolStatus: evidencetools.StatusOK, EvidenceRefs: []string{"ev:agent:claim@0123456789abcdef"},
		ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: lane.ContentHash},
	}}
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 0 {
		t.Fatalf("agent material produced facts: %+v", facts)
	}
}

// TestFactBuildTracePromotion promotes a verification-phase observation
// through the drained session audit: the record binds tool, arguments
// and observation id, the fact is built from the recorded copy.
func TestFactBuildTracePromotion(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	obs := decisionObservation(evidencetools.UsageScopeTool, absentData())
	tr := decisionTrace(obs)
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane, Trace: tr, VerificationAudit: factAudit(tr)})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("facts=%d want 1", len(facts))
	}
	f := facts[0]
	if f.SourceTool != evidencetools.UsageScopeTool || f.ToolVersion != evidencetools.AdapterVersion ||
		f.Subject != "package:"+testModule+"|"+testPackage || f.Coverage != FactCoverageComplete {
		t.Fatalf("fact=%+v", f)
	}
}

// TestFactBuildDisprovenUnreachability pins the artifact-visible side
// of the answered-reach contract: a symbol-unreachability record whose
// payload carries concrete reach evidence promotes a verified,
// PARTIAL-coverage fact (the disproven finding — never an
// unreachability claim) and emits declared-symbol-reachability=reached
// for the attributed subject, so rule.declared-symbols-unreached is
// contradicted downstream. An open proof promotes nothing.
func TestFactBuildDisprovenUnreachability(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	result := goanalysis.UnreachabilityResult{
		Module:   testModule,
		Subjects: []goanalysis.UnreachabilitySubject{{Package: testPackage, Symbol: "Sink"}},
		ProductReferences: []domain.CallSite{{
			File: "main.go", Function: "main", Package: "example.com/product",
			Callee: "vuln.Sink"}},
	}
	obs := decisionObservation(evidencetools.SymbolUnreachabilityTool,
		evidencetools.SymbolUnreachabilityData{Result: result})
	obs.Completeness = evidencetools.CompletenessPartial
	obs.Fact = "symbol-unreachability disproven: 1 product reference(s) reach the declared subject(s)"
	tr := decisionTrace(obs)

	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane, Trace: tr, VerificationAudit: factAudit(tr)})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].Coverage != FactCoveragePartial ||
		facts[0].Status != FactStatusVerified {
		t.Fatalf("disproven record promoted %+v — want one PARTIAL verified fact", facts)
	}
	rules, err := BuildRuleFacts(FactBuildInput{Lane: lane, Trace: tr, VerificationAudit: factAudit(tr)})
	if err != nil {
		t.Fatal(err)
	}
	var reached, unreached bool
	for _, rf := range rules {
		if rf.Predicate != evaluator.PredicateDeclaredSymbolReachability {
			continue
		}
		switch rf.Value {
		case "reached":
			reached = true
			if rf.Subject != "symbol:"+testModule+"|"+testPackage+".Sink" {
				t.Fatalf("reached rule fact subject = %q", rf.Subject)
			}
		case "unreached":
			unreached = true
		}
	}
	if !reached || unreached {
		t.Fatalf("rule facts reached=%v unreached=%v — want reached only", reached, unreached)
	}

	// Module-internal reach evidence attributes by its recorded key.
	chain := result
	chain.ProductReferences = nil
	chain.ModuleReachable = map[string][]string{testPackage + ".Sink": {"dep.Entry", "vuln.Sink"}}
	obs2 := decisionObservation(evidencetools.SymbolUnreachabilityTool,
		evidencetools.SymbolUnreachabilityData{Result: chain})
	obs2.Completeness = evidencetools.CompletenessPartial
	tr2 := decisionTrace(obs2)
	rules2, err := BuildRuleFacts(FactBuildInput{Lane: lane, Trace: tr2, VerificationAudit: factAudit(tr2)})
	if err != nil {
		t.Fatal(err)
	}
	var chainReached bool
	for _, rf := range rules2 {
		if rf.Predicate == evaluator.PredicateDeclaredSymbolReachability && rf.Value == "reached" {
			chainReached = true
		}
	}
	if !chainReached {
		t.Fatalf("module-internal chain emitted no reached fact: %+v", rules2)
	}

	// An open proof — no reach evidence — promotes nothing and claims
	// neither reached nor unreached.
	open := decisionObservation(evidencetools.SymbolUnreachabilityTool,
		evidencetools.SymbolUnreachabilityData{Result: goanalysis.UnreachabilityResult{
			Module: testModule, Subjects: []goanalysis.UnreachabilitySubject{{Package: testPackage, Symbol: "Sink"}},
		}})
	open.Completeness = evidencetools.CompletenessPartial
	tr3 := decisionTrace(open)
	facts3, err := BuildDecisionFacts(FactBuildInput{Lane: lane, Trace: tr3, VerificationAudit: factAudit(tr3)})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts3) != 0 {
		t.Fatalf("open proof promoted %+v", facts3)
	}
	rules3, err := BuildRuleFacts(FactBuildInput{Lane: lane, Trace: tr3, VerificationAudit: factAudit(tr3)})
	if err != nil {
		t.Fatal(err)
	}
	for _, rf := range rules3 {
		if rf.Predicate == evaluator.PredicateDeclaredSymbolReachability {
			t.Fatalf("open proof emitted reachability fact %+v", rf)
		}
	}
}

// TestFactBuildTraceFailClosed: every break in the request↔audit
// binding — missing record, argument mismatch, tool mismatch,
// degraded status, missing record time, cross-snapshot record — keeps
// the observation out of the fact envelope.
func TestFactBuildTraceFailClosed(t *testing.T) {
	newPair := func() (*VerificationTrace, []evidencetools.AuditRecord) {
		obs := decisionObservation(evidencetools.UsageScopeTool, absentData())
		tr := decisionTrace(obs)
		return tr, factAudit(tr)
	}
	t.Run("missing-audit-record", func(t *testing.T) {
		tr, _ := newPair()
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr})
		if err != nil || len(facts) != 0 {
			t.Fatalf("facts=%v err=%v", facts, err)
		}
	})
	t.Run("argument-mismatch", func(t *testing.T) {
		tr, audit := newPair()
		audit[0].Args = json.RawMessage(`{"module":"other/mod"}`)
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: audit})
		if err != nil || len(facts) != 0 {
			t.Fatalf("facts=%v err=%v", facts, err)
		}
	})
	t.Run("tool-mismatch", func(t *testing.T) {
		tr, audit := newPair()
		audit[0].Tool = "read_source"
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: audit})
		if err != nil || len(facts) != 0 {
			t.Fatalf("facts=%v err=%v", facts, err)
		}
	})
	for _, st := range []evidencetools.ToolStatus{evidencetools.StatusError, evidencetools.StatusTimeout, evidencetools.StatusUnsupported} {
		t.Run("degraded-"+string(st), func(t *testing.T) {
			tr, audit := newPair()
			audit[0].Observation.ToolStatus = st
			facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: audit})
			if err != nil || len(facts) != 0 {
				t.Fatalf("facts=%v err=%v", facts, err)
			}
		})
	}
	t.Run("no-record-time", func(t *testing.T) {
		tr, audit := newPair()
		audit[0].RecordTime = time.Time{}
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: audit})
		if err != nil || len(facts) != 0 {
			t.Fatalf("un-dated record promoted: %v", facts)
		}
	})
	t.Run("partial-observation", func(t *testing.T) {
		tr, audit := newPair()
		audit[0].Observation.Completeness = evidencetools.CompletenessPartial
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: audit})
		if err != nil || len(facts) != 1 || facts[0].Coverage != FactCoveragePartial {
			t.Fatalf("facts=%v err=%v", facts, err)
		}
	})
	t.Run("empty-observation", func(t *testing.T) {
		obs := decisionObservation(evidencetools.UsageScopeTool, absentData())
		obs.EvidenceRefs = nil
		tr := decisionTrace(obs)
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: factAudit(tr)})
		if err != nil || len(facts) != 0 {
			t.Fatalf("undigested observation promoted: %v", facts)
		}
	})
	t.Run("snapshot-mismatch", func(t *testing.T) {
		tr, audit := newPair()
		audit[0].Observation.ScopeDetails.SnapshotHash = "other-snapshot"
		facts, err := BuildDecisionFacts(FactBuildInput{Lane: decisionLane(domain.ClaimTrue), Trace: tr, VerificationAudit: audit})
		if err != nil || len(facts) != 0 {
			t.Fatalf("cross-snapshot observation promoted: %v", facts)
		}
	})
}

// TestFactBuildTraceMutationCannotForge is the envelope's core
// isolation property: mutating the trace after the audit was recorded
// — a forged negative payload, a silent downgrade — can never create
// or alter a fact, because facts are built from the audit-recorded
// copy and every mutation breaks the request↔record binding.
func TestFactBuildTraceMutationCannotForge(t *testing.T) {
	// A degraded check the session actually ran: ERROR is what the audit
	// records carry; the agent-side trace copy is later mutated to look
	// like a verified negative. Promotion must follow the record.
	real := decisionObservation(evidencetools.UsageScopeTool, absentData())
	real.ToolStatus = evidencetools.StatusError
	real.Completeness = evidencetools.CompletenessUnknown
	real.Error = "closure decode failed"
	tr := decisionTrace(real)
	audit := factAudit(tr)
	// Agent-side mutation: relabel the failed check as an OK+COMPLETE
	// negative and swap in a forged payload.
	tr.Observations[0].ToolStatus = evidencetools.StatusOK
	tr.Observations[0].Completeness = evidencetools.CompletenessComplete
	tr.Observations[0].Error = ""
	tr.Observations[0].Data = absentData()
	facts, err := BuildDecisionFacts(FactBuildInput{
		Lane: decisionLane(domain.ClaimTrue), Trace: tr,
		VerificationAudit: audit})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 0 {
		t.Fatalf("forged trace produced facts: %+v", facts)
	}
	// The reverse direction: mutating a verified observation into a
	// failure cannot alter the promoted fact, which binds the record.
	good := decisionObservation(evidencetools.UsageScopeTool, absentData())
	tr2 := decisionTrace(good)
	audit2 := factAudit(tr2)
	tr2.Observations[0].ToolStatus = evidencetools.StatusTimeout
	tr2.Observations[0].Completeness = evidencetools.CompletenessUnknown
	facts, err = BuildDecisionFacts(FactBuildInput{
		Lane: decisionLane(domain.ClaimTrue), Trace: tr2,
		VerificationAudit: audit2})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].Coverage != FactCoverageComplete {
		t.Fatalf("record-bound fact not preserved: %+v", facts)
	}
}

// A multi-entry advisory resolves per entry: the aggregate
// VersionAffected is TRUE when one entry is affected, so a fixed or
// pending entry must not inherit version-in-range=true from it.
func TestApplicabilityRuleFactsVersionInRangePerModule(t *testing.T) {
	ar := domain.AffectedResult{
		ModulePresent:          domain.ClaimTrue,
		VersionAffected:        domain.ClaimTrue,
		SelectedModule:         "synthetic.test/affected",
		SelectedModules:        []string{"synthetic.test/affected"},
		CheckedModules:         []string{"synthetic.test/affected", "synthetic.test/fixed", "synthetic.test/pending"},
		VersionAffectedModules: []string{"synthetic.test/affected"},
		UnresolvedModules:      []string{"synthetic.test/pending"},
	}
	obs := decisionObservation("affected-resolve", map[string]any{"affected_result": ar})
	obs.ID = "OBS-0042"
	lane := factLane(t, "affected-resolve", obs, VerifiedFact{Kind: "APPLICABILITY", Claim: "TRUE", Coverage: "COMPLETE"})
	lane.Affected = ar
	rules, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, rf := range rules {
		if rf.Predicate == evaluator.PredicateVersionInRange {
			got[rf.Subject] = rf.Value
		}
	}
	if got["module:synthetic.test/affected"] != "true" {
		t.Fatalf("affected entry must be in range: %v", got)
	}
	if got["module:synthetic.test/fixed"] != "false" {
		t.Fatalf("a resolved out-of-range entry must not inherit the aggregate TRUE: %v", got)
	}
	if got["module:synthetic.test/pending"] != "unknown" {
		t.Fatalf("a pending entry must stay unknown: %v", got)
	}
}

// The implementation axis is projected into the decision-ready branch
// facts under its own predicate and grounds rule.implementation-absent —
// never build-relevant. Only modules the verifier covered receive a fact.
func TestApplicabilityRuleFactsImplementationAxis(t *testing.T) {
	obs := &evidencetools.Observation{Data: map[string]any{
		"affected_result": domain.AffectedResult{
			ModulePresent:                   domain.ClaimTrue,
			VersionAffected:                 domain.ClaimTrue,
			PackagePresent:                  domain.ClaimTrue,
			BuildRelevant:                   domain.ClaimTrue,
			VulnerableImplementationPresent: domain.ClaimFalse,
			CheckedModules:                  []string{"example.com/dep", "example.com/other"},
			SelectedModules:                 []string{"example.com/dep"},
			ImplementationModules:           []string{"example.com/dep"},
		},
	}}
	type row struct{ subject, pred, value string }
	var rows []row
	appendApplicabilityRuleFacts(func(subj, pred, value string) {
		rows = append(rows, row{subj, pred, value})
	}, obs)
	var found, leaked bool
	for _, r := range rows {
		if r.pred != evaluator.PredicateVulnerableImplementationPresent {
			continue
		}
		if r.subject == "module:example.com/dep" && r.value == "false" {
			found = true
		}
		if r.subject == "module:example.com/other" {
			leaked = true
		}
	}
	if !found {
		t.Fatalf("implementation fact missing: %+v", rows)
	}
	if leaked {
		t.Fatalf("implementation fact leaked to an uncovered module: %+v", rows)
	}

	reg := evaluator.DefaultAdapterRegistry()
	ctx := context.Background()
	facts := []evaluator.RuleFact{{
		ID: "fact-impl", Subject: "module:example.com/dep",
		Kind:      evaluator.RuleFactKindApplicability,
		Predicate: evaluator.PredicateVulnerableImplementationPresent, Value: "false",
		Status: "VERIFIED", Coverage: "COMPLETE", Digest: strings.Repeat("ab", 32),
	}}
	rc := evaluator.RuleContext{
		Conditions: []evaluator.ConditionInput{{ID: "C", SubjectRefs: []string{"module:example.com/dep"}}},
		Facts:      facts,
	}
	res, err := reg.EvaluateRule(ctx, "rule.implementation-absent", rc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != evaluator.RuleEstablished {
		t.Fatalf("rule status = %s (%v)", res.Status, res.Limitations)
	}
	// A selected implementation carrying the marker contradicts the close.
	facts[0].Value = "true"
	res, err = reg.EvaluateRule(ctx, "rule.implementation-absent", rc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != evaluator.RuleContradicted {
		t.Fatalf("marker-present rule status = %s, want CONTRADICTED", res.Status)
	}
}

// A partial advisory scope never rewrites the recorded per-module
// applicability facts: the module the lane actually checked keeps its
// local version-in-range=false row, while a CVE implementation the
// loaded record never checked gets no such row at all. The scope gate
// refuses the global close; it never deletes the local evidence.
func TestApplicabilityRuleFactsRemainPerModuleUnderPartialScope(t *testing.T) {
	const xnet = "golang.org/x/net"
	const grpc = "google.golang.org/grpc"
	ar := domain.AffectedResult{
		Scope:           partialCVEScope(),
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimFalse,
		SelectedModule:  xnet,
		SelectedModules: []string{xnet},
		CheckedModules:  []string{xnet},
	}
	obs := decisionObservation("affected-resolve", map[string]any{"affected_result": ar})
	obs.ID = "OBS-0021"
	obs.ScopeDetails.SnapshotHash = testContentHash
	lane := factLane(t, "affected-resolve", obs, VerifiedFact{Kind: "APPLICABILITY", Claim: "TRUE", Coverage: "COMPLETE"})
	lane.Affected.Scope = partialCVEScope()
	lane.Facts = nil
	payload, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	lane.CanonicalByObs = map[string]string{obs.ID: hex.EncodeToString(sum[:])}
	rules, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	local := versionFalseRuleFact(rules, "module:"+xnet)
	if local == nil || local.Coverage != "COMPLETE" {
		t.Fatalf("x/net must keep its recorded version-in-range=false fact: %+v", rules)
	}
	for _, rf := range rules {
		if rf.Subject == "module:"+grpc && rf.Predicate == evaluator.PredicateVersionInRange {
			t.Fatalf("grpc must not inherit a version fact it never recorded: %+v", rf)
		}
	}
}
