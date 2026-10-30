package research

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// usageLane builds a lane fixture whose advisory declares one package
// candidate and (optionally) symbol candidates under the same module.
// obs/facts supply the package-usage observations and their promoted
// facts; ids must line up (fact-<obsid lowercase>) for FactRef to bind.
// The caller may override lane.Advisory.Vuln.AffectedModules before
// Assemble to change the declared candidates.
func usageLane(t *testing.T, module, pkg string, symbols []string,
	obs []*evidencetools.Observation, facts []VerifiedFact) *LaneResult {
	t.Helper()
	lane := laneFor(t, module, domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  module,
		SelectedModules: []string{module},
		CheckedModules:  []string{module},
	}, obs, facts)
	lane.Advisory.Vuln.AffectedModules = []domain.AffectedModule{{
		Module: module,
		AffectedPackages: []domain.AffectedPackage{{
			Path:    pkg,
			Symbols: symbols,
		}},
	}}
	// Production binds every package-usage observation to its call args
	// in the audit ledger — including ERROR rows with no payload — so
	// mirror that here. The payload also carries module/package/symbol
	// for recordless binding; the record keeps failed rows matched.
	for _, o := range obs {
		if o == nil || o.Tool != evidencetools.PackageUsageTool {
			continue
		}
		args := map[string]any{"module": module, "package": pkg}
		if d, ok := packageUsageDataOf(o); ok {
			if d.Module != "" {
				args["module"] = d.Module
			}
			if d.Package != "" {
				args["package"] = d.Package
			}
			if d.Symbol != "" {
				args["symbol"] = d.Symbol
			}
		}
		raw, _ := json.Marshal(args)
		lane.Records = append(lane.Records, evidencetools.AuditRecord{
			Tool: o.Tool, Args: raw, Observation: o,
		})
	}
	return lane
}

// usageObs mints a package-usage observation row for the given subject.
func usageObs(id, module, pkg, symbol, usage, negVer string, comp evidencetools.Completeness) *evidencetools.Observation {
	return &evidencetools.Observation{
		ID: id, Tool: evidencetools.PackageUsageTool, ToolStatus: evidencetools.StatusOK,
		Fact:         "package-usage over " + pkg,
		Scope:        "bounded product source scope for " + pkg,
		Completeness: comp,
		Data: map[string]any{
			"module": module, "package": pkg, "symbol": symbol,
			"present": true, "usage": usage,
			"negative_verification": negVer,
			"check_scope":           "closed product-source import/reference scan (GOOS=linux GOARCH=amd64) for " + pkg,
			"limitations":           []any{},
		},
	}
}

// usageFact mints the promoted verified fact for a package-usage
// observation id, bound to the same advisory-declared subject the
// observation checked (module, package, symbol — mirroring the
// production promotion, which fails closed when the subject is
// undecodable). claim is TRUE for USED payloads and FALSE for a
// VERIFIED negative.
func usageFact(obsID, module, pkg, symbol, claim, negVer, stmt string) VerifiedFact {
	f := factFor(obsID, "package-usage", stmt)
	f.Kind = FactKindPackageUsage
	f.UsageSubject = &FactUsageSubject{Module: module, Package: pkg, Symbol: symbol}
	f.Claim = claim
	if negVer != "" {
		f.NegativeVerification = negVer
		f.Coverage = "COMPLETE"
	}
	return f
}

// usageLowerBoundFact mints the promoted verified fact for an
// undetermined usage check that still recorded positive content: a
// PACKAGE_USAGE_LOWER_BOUND claim=TRUE fact under PARTIAL coverage —
// never a USED verdict, never a carrier for a path condition.
func usageLowerBoundFact(obsID, module, pkg, symbol, stmt string) VerifiedFact {
	f := usageFact(obsID, module, pkg, symbol, "TRUE", "", stmt)
	f.Kind = FactKindPackageUsageLowerBound
	f.Coverage = "PARTIAL"
	// The production promotion always tags the open-scope lower bound;
	// the marker is the machine distinguisher between a genuine
	// lower-bound fact and a relabelled USED verdict.
	f.Limitations = []string{openEnumerationLimitation}
	return f
}

// usageConditions returns every condition on the canonical
// package/symbol-usage subject, in ledger order.
func usageConditions(r *Report) []ExploitationCondition {
	var out []ExploitationCondition
	for _, c := range r.ExploitationConditions {
		if c.Subject == subjProductPackageUsage {
			out = append(out, c)
		}
	}
	return out
}

func hasLim(c *ExploitationCondition, part string) bool {
	for _, l := range c.Limitations {
		if strings.Contains(l, part) {
			return true
		}
	}
	return false
}

// TestPackageUsageConditionState pins the deterministic verdict→state
// mapping: USED → SUPPORTED, NOT_USED + VERIFIED → REFUTED, everything
// else → UNKNOWN.
func TestPackageUsageConditionState(t *testing.T) {
	cases := []struct {
		name string
		data evidencetools.PackageUsageData
		want string
	}{
		{"used package", evidencetools.PackageUsageData{Usage: "USED"}, StateSupported},
		{"used symbol", evidencetools.PackageUsageData{Usage: "USED", Symbol: "Parse"}, StateSupported},
		{"not used verified", evidencetools.PackageUsageData{Usage: "NOT_USED", NegativeVerification: "VERIFIED"}, StateRefuted},
		{"not used insufficient scope", evidencetools.PackageUsageData{Usage: "NOT_USED", NegativeVerification: "INSUFFICIENT_SCOPE"}, StateUnknown},
		{"not used no verification", evidencetools.PackageUsageData{Usage: "NOT_USED"}, StateUnknown},
		{"not used contradicted", evidencetools.PackageUsageData{Usage: "NOT_USED", NegativeVerification: "CONTRADICTED"}, StateUnknown},
		{"unknown verdict", evidencetools.PackageUsageData{Usage: "UNKNOWN"}, StateUnknown},
		{"empty verdict", evidencetools.PackageUsageData{}, StateUnknown},
		{"garbage verdict", evidencetools.PackageUsageData{Usage: "SUPPORTED"}, StateUnknown},
	}
	for _, tc := range cases {
		if got := packageUsageConditionState(tc.data); got != tc.want {
			t.Fatalf("%s: state=%s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestPackageUsageCondition covers the deterministic emission of the
// required path condition «affected package/symbol used by product
// code»: one per sorted advisory candidate, SUPPORTED only on a USED
// verdict with a promoted fact, REFUTED only on a VERIFIED negative
// under a COMPLETE scope, UNKNOWN and blocking for every other shape.
func TestPackageUsageCondition(t *testing.T) {
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"

	t.Run("package used closes the path predicate and yields L1", func(t *testing.T) {
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
				usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used by product source"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-used",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 1 {
			t.Fatalf("usage conditions = %d, want 1", len(cs))
		}
		c := cs[0]
		if c.State != StateSupported || c.Role != ConditionRolePath ||
			c.Necessity != "required" || c.Origin != OriginDeterm {
			t.Fatalf("condition = %+v, want SUPPORTED required path deterministic", c)
		}
		if len(c.EvidenceRefs) != 1 || c.EvidenceRefs[0] != "fact-obs-0020" {
			t.Fatalf("evidence_refs = %v, want [fact-obs-0020]", c.EvidenceRefs)
		}
		if c.Axis != ECAxisCodeReachability {
			t.Fatalf("axis = %q, want code_reachability", c.Axis)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
			t.Fatalf("evidence_level = %+v, want L1", r.EvidenceLevel)
		}
		if containsStr(r.EvidenceLevel.BlockingConditions, c.ID) {
			t.Fatalf("SUPPORTED usage condition in blocking: %v", r.EvidenceLevel.BlockingConditions)
		}
		// The corroborating exposure claim is deterministic and cites
		// the promoted fact.
		found := false
		for _, cl := range r.ProductExposure.Claims {
			if containsStr(cl.EvidenceRefs, "fact-obs-0020") {
				found = true
			}
		}
		if !found {
			t.Fatal("no product_exposure claim citing the usage fact")
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("symbol used is SUPPORTED via its own condition", func(t *testing.T) {
		lane := usageLane(t, module, pkg, []string{"ServeConn"},
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
				usageObs("OBS-0021", module, pkg, "ServeConn", "USED", "", evidencetools.CompletenessPartial),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
				usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used"),
				usageFact("OBS-0021", module, pkg, "ServeConn", "TRUE", "", "symbol "+pkg+".ServeConn used"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-sym-used",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 2 {
			t.Fatalf("usage conditions = %d, want 2 (one per candidate, never collapsed)", len(cs))
		}
		for _, c := range cs {
			if c.State != StateSupported {
				t.Fatalf("condition %s state=%s, want SUPPORTED", c.ID, c.State)
			}
		}
		if !strings.Contains(cs[1].Statement, "ServeConn") {
			t.Fatalf("symbol condition statement does not name the symbol: %q", cs[1].Statement)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
			t.Fatalf("evidence_level = %+v, want L1", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("package present but not used is REFUTED and blocks L1", func(t *testing.T) {
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
				usageFact("OBS-0020", module, pkg, "", "FALSE", NegativeVerificationVerified, "no product-source use of "+pkg),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-refuted",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 1 {
			t.Fatalf("usage conditions = %d, want 1", len(cs))
		}
		c := cs[0]
		if c.State != StateRefuted || c.Role != ConditionRolePath || c.Necessity != "required" {
			t.Fatalf("condition = %+v, want REFUTED required path", c)
		}
		for _, part := range []string{"negative verification=VERIFIED",
			"runtime", "not a safe conclusion"} {
			if !hasLim(&c, part) {
				t.Fatalf("REFUTED limitations lack %q: %v", part, c.Limitations)
			}
		}
		if !strings.Contains(c.Statement, pkg) ||
			!strings.Contains(c.Statement, "present in the recorded dependency/build scope") ||
			!strings.Contains(c.Statement, "no product-source use") {
			t.Fatalf("REFUTED statement incomplete: %q", c.Statement)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
			// L1 must never be reachable over a REFUTED path condition.
		} else {
			t.Fatal("REFUTED path condition produced L1")
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if !containsStr(r.EvidenceLevel.BlockingConditions, c.ID) {
			t.Fatalf("REFUTED condition not in blocking_conditions: %v", r.EvidenceLevel.BlockingConditions)
		}
		// The refuted path never reads as safe: the L2 limitations must
		// distinguish bounded refutation from product safety.
		safeDistinction := false
		for _, l := range r.EvidenceLevel.Limitations {
			if strings.Contains(l, "bounded scope") &&
				(strings.Contains(l, "не является заключением о безопасности") ||
					strings.Contains(l, "not a safe conclusion") ||
					strings.Contains(l, "безопасности продукта")) {
				safeDistinction = true
			}
		}
		if !safeDistinction {
			t.Fatalf("L2 limitations do not distinguish refuted-path from safety: %v", r.EvidenceLevel.Limitations)
		}
		// A negative usage fact never sets vulnerable_code_reachability=FALSE.
		if r.ProductApplicability.VulnerableCodeReachability == VCRFalse {
			t.Fatal("vulnerable_code_reachability=FALSE from a usage negative")
		}
		if r.Disposition.AutoClose {
			t.Fatal("auto-close disposition over a REFUTED path condition")
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("symbol present but not used is REFUTED on its own condition", func(t *testing.T) {
		lane := usageLane(t, module, pkg, []string{"Unused"},
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
				usageObs("OBS-0021", module, pkg, "Unused", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
				usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used"),
				usageFact("OBS-0021", module, pkg, "Unused", "FALSE", NegativeVerificationVerified, "no product-source use of "+pkg+".Unused"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-sym-refuted",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 2 {
			t.Fatalf("usage conditions = %d, want 2", len(cs))
		}
		if cs[0].State != StateSupported || cs[1].State != StateRefuted {
			t.Fatalf("states = %s/%s, want SUPPORTED/REFUTED", cs[0].State, cs[1].State)
		}
		if !strings.Contains(cs[1].Statement, "Unused") {
			t.Fatalf("REFUTED statement does not name the symbol: %q", cs[1].Statement)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2 (refuted symbol path blocks L1)", r.EvidenceLevel)
		}
		if !containsStr(r.EvidenceLevel.BlockingConditions, cs[1].ID) {
			t.Fatalf("symbol REFUTED condition not blocking: %v", r.EvidenceLevel.BlockingConditions)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("open-scope verdicts stay UNKNOWN and blocking", func(t *testing.T) {
		// A symbol whose declaration is absent and a package whose
		// negative verification is INSUFFICIENT_SCOPE (gated /
		// interface-dispatch / dynamic gap) — both UNKNOWN, both blocking.
		lane := usageLane(t, module, pkg, []string{"Nope"},
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
				usageObs("OBS-0021", module, pkg, "Nope", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-unknown",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 2 {
			t.Fatalf("usage conditions = %d, want 2", len(cs))
		}
		for _, c := range cs {
			if c.State != StateUnknown {
				t.Fatalf("condition %s state=%s, want UNKNOWN", c.ID, c.State)
			}
			if !hasLim(&c, "never negative proof") {
				t.Fatalf("condition %s lacks the no-negative-proof limitation: %v", c.ID, c.Limitations)
			}
			if !containsStr(r.EvidenceLevel.BlockingConditions, c.ID) {
				t.Fatalf("UNKNOWN condition %s not blocking", c.ID)
			}
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		// UNKNOWN usages were audited but never promoted: no
		// PACKAGE_USAGE fact may exist.
		for _, f := range r.VerifiedFacts {
			if f.Kind == FactKindPackageUsage {
				t.Fatalf("UNKNOWN usage promoted to fact %s", f.ID)
			}
		}
		// The undecided checks are recorded as unknowns carrying obs refs.
		unkByRef := map[string]bool{}
		for _, u := range r.Unknowns {
			for _, ref := range u.EvidenceRefs {
				unkByRef[ref] = true
			}
		}
		for _, id := range []string{"obs:OBS-0020", "obs:OBS-0021"} {
			if !unkByRef[id] {
				t.Fatalf("no unknown cites %s", id)
			}
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("module-only advisory emits no usage condition and a decision-changing unknown", func(t *testing.T) {
		lane := laneFor(t, module, domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimUnknown,
			BuildRelevant:   domain.ClaimUnknown,
			ResolvedVersion: "v0.10.0",
			SelectedModule:  module,
			SelectedModules: []string{module},
			CheckedModules:  []string{module},
		}, nil, []VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
		})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-modonly",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if n := len(usageConditions(r)); n != 0 {
			t.Fatalf("module-only advisory produced %d usage conditions", n)
		}
		var unknown *UnknownEntry
		for i := range r.Unknowns {
			if strings.Contains(r.Unknowns[i].Statement, "no package or symbol identifies a package-level subject") {
				unknown = &r.Unknowns[i]
			}
		}
		if unknown == nil {
			t.Fatal("no module-only package-usage unknown")
		}
		if unknown.Priority != UnknownPriorityDecisionChanging || unknown.DecisionChangingFor == nil {
			t.Fatalf("module-only unknown = %+v, want DECISION_CHANGING", unknown)
		}
		// No guessed package facts: no PACKAGE_USAGE fact and the
		// package/build conditions stay UNKNOWN, never REFUTED.
		for _, f := range r.VerifiedFacts {
			if f.Kind == FactKindPackageUsage {
				t.Fatalf("synthetic package-usage fact %s on a module-only advisory", f.ID)
			}
		}
		for _, subj := range []string{subjPackageReach, subjBuildRelevant} {
			c := conditionOf(r, subj)
			if c == nil || c.State != StateUnknown {
				t.Fatalf("module-only %s condition = %+v, want UNKNOWN", subj, c)
			}
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("failed usage check stays UNKNOWN citing its observation", func(t *testing.T) {
		errObs := &evidencetools.Observation{
			ID: "OBS-0020", Tool: evidencetools.PackageUsageTool,
			ToolStatus: evidencetools.StatusError,
			Fact:       "package-usage failed", Scope: "check not performed",
			Completeness: evidencetools.CompletenessUnknown,
			Error:        "product source index load failed",
		}
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{errObs},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-error",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 1 || cs[0].State != StateUnknown {
			t.Fatalf("condition = %+v, want one UNKNOWN", cs)
		}
		if len(cs[0].EvidenceRefs) != 1 || cs[0].EvidenceRefs[0] != "obs:OBS-0020" {
			t.Fatalf("evidence_refs = %v, want [obs:OBS-0020]", cs[0].EvidenceRefs)
		}
		if !hasLim(&cs[0], "never negative proof") {
			t.Fatalf("failed-check limitation missing: %v", cs[0].Limitations)
		}
		if !containsStr(r.EvidenceLevel.BlockingConditions, cs[0].ID) {
			t.Fatalf("ERROR-derived condition not blocking: %v", r.EvidenceLevel.BlockingConditions)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("missing observation for a declared candidate stays UNKNOWN", func(t *testing.T) {
		lane := usageLane(t, module, pkg, nil, nil,
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-missing",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 1 || cs[0].State != StateUnknown {
			t.Fatalf("condition = %+v, want one UNKNOWN", cs)
		}
		if !hasLim(&cs[0], "missing check result is never negative proof") {
			t.Fatalf("missing-observation limitation absent: %v", cs[0].Limitations)
		}
		if !containsStr(r.EvidenceLevel.BlockingConditions, cs[0].ID) {
			t.Fatalf("missing-result condition not blocking: %v", r.EvidenceLevel.BlockingConditions)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("VERIFIED negative under degraded completeness is never REFUTED", func(t *testing.T) {
		// The primitive verified the negative but finishObservation
		// degraded the recorded scope (skipped packages/truncation):
		// incomplete scope is never negative proof.
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "NOT_USED", "VERIFIED", evidencetools.CompletenessPartial),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-degraded",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 1 || cs[0].State != StateUnknown {
			t.Fatalf("degraded negative condition = %+v, want UNKNOWN", cs)
		}
		for _, f := range r.VerifiedFacts {
			if f.Kind == FactKindPackageUsage && f.Claim == "FALSE" {
				t.Fatalf("degraded negative produced FALSE fact %s", f.ID)
			}
		}
		var unknown *UnknownEntry
		for i := range r.Unknowns {
			if strings.Contains(r.Unknowns[i].Statement, "package-usage negative") {
				unknown = &r.Unknowns[i]
			}
		}
		if unknown == nil || unknown.Priority != UnknownPriorityDecisionChanging {
			t.Fatalf("no decision-changing unknown for the degraded negative: %+v", r.Unknowns)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("agent usage claim stays OPEN and never decides the condition", func(t *testing.T) {
		turn := turnWith(t, "vulnerable", "the product clearly calls the vulnerable symbol",
			map[string]any{
				"attack_scenario": map[string]any{
					"claims": []any{
						map[string]any{
							"statement": "the product invokes the vulnerable entrypoint",
							"subject":   "Affected Package/Symbol Used By Product Code",
						},
					},
				},
			})
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "pu-agent",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		var det, agent *ExploitationCondition
		for i := range r.ExploitationConditions {
			c := &r.ExploitationConditions[i]
			if c.Subject != subjProductPackageUsage {
				continue
			}
			switch c.Origin {
			case OriginDeterm:
				det = c
			case OriginAgent:
				agent = c
			}
		}
		if det == nil || det.State != StateUnknown {
			t.Fatalf("deterministic usage condition = %+v, want UNKNOWN", det)
		}
		if agent == nil {
			t.Fatal("agent canonical usage claim did not become a path condition")
		}
		if agent.Role != ConditionRolePath || agent.Necessity != "required" ||
			agent.State != StateOpen {
			t.Fatalf("agent usage condition = %+v, want required OPEN path", agent)
		}
		// Agent material can never carry evidence: the condition must
		// cite no deterministic refs and no fact may answer for it.
		for _, ref := range agent.EvidenceRefs {
			for _, f := range r.VerifiedFacts {
				if f.ID == ref {
					t.Fatalf("agent usage condition cites verified fact %s", ref)
				}
			}
		}
		for _, f := range r.VerifiedFacts {
			if f.Kind == FactKindPackageUsage {
				t.Fatalf("agent statement produced a PACKAGE_USAGE fact %s", f.ID)
			}
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level == EvidenceLevelL1 {
			t.Fatalf("agent hypothesis closed L1: %+v", r.EvidenceLevel)
		}
		for _, id := range []string{det.ID, agent.ID} {
			if !containsStr(r.EvidenceLevel.BlockingConditions, id) {
				t.Fatalf("condition %s missing from blocking_conditions: %v", id, r.EvidenceLevel.BlockingConditions)
			}
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("every emitted usage condition carries its advisory candidate identity", func(t *testing.T) {
		lane := usageLane(t, module, pkg, []string{"ServeConn"},
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
				usageObs("OBS-0021", module, pkg, "ServeConn", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
				usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used"),
				usageFact("OBS-0021", module, pkg, "ServeConn", "FALSE", NegativeVerificationVerified, "no product-source use of "+pkg+".ServeConn"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-identity",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		cs := usageConditions(r)
		if len(cs) != 2 {
			t.Fatalf("usage conditions = %d, want 2", len(cs))
		}
		want := []FactUsageSubject{
			{Module: module, Package: pkg},
			{Module: module, Package: pkg, Symbol: "ServeConn"},
		}
		// One condition per sorted advisory candidate, each bound to
		// exactly its own module/package/symbol — this is the identity
		// the validator matches cited PACKAGE_USAGE facts against.
		for i, c := range cs {
			if c.UsageSubject == nil {
				t.Fatalf("condition %s (%s) carries no usage_subject", c.ID, c.State)
			}
			if *c.UsageSubject != want[i] {
				t.Fatalf("condition %d usage_subject=%+v, want %+v", i, *c.UsageSubject, want[i])
			}
		}
		// Agent-originated usage rows never carry the candidate
		// identity — they are not bound to a lane candidate.
		for _, c := range r.ExploitationConditions {
			if c.Origin == OriginAgent && c.UsageSubject != nil {
				t.Fatalf("agent condition %s carries usage_subject %+v", c.ID, *c.UsageSubject)
			}
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("condition ledger stays byte-stable across derivations", func(t *testing.T) {
		build := func() *Report {
			lane := usageLane(t, module, pkg, []string{"ServeConn"},
				[]*evidencetools.Observation{
					usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
					usageObs("OBS-0021", module, pkg, "ServeConn", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
				},
				[]VerifiedFact{
					factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
					usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used"),
					usageFact("OBS-0021", module, pkg, "ServeConn", "FALSE", NegativeVerificationVerified, "no product-source use of "+pkg+".ServeConn"),
				})
			lane.SnapshotRoot = t.TempDir()
			return Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pu-stable",
				StartedAt: time.Now(), FinishedAt: time.Now()})
		}
		r1, r2 := build(), build()
		if len(usageConditions(r1)) != len(usageConditions(r2)) {
			t.Fatal("condition count differs across runs")
		}
		for i := range usageConditions(r1) {
			a, b := usageConditions(r1)[i], usageConditions(r2)[i]
			if a.ID != b.ID || a.State != b.State ||
				strings.Join(a.EvidenceRefs, "|") != strings.Join(b.EvidenceRefs, "|") ||
				strings.Join(a.Limitations, "|") != strings.Join(b.Limitations, "|") ||
				a.Statement != b.Statement {
				t.Fatalf("condition %d unstable:\n%+v\n%+v", i, a, b)
			}
		}
		el1 := deriveEvidenceLevel(r1)
		el2 := deriveEvidenceLevel(r2)
		if el1.Level != el2.Level ||
			strings.Join(el1.BlockingConditions, "|") != strings.Join(el2.BlockingConditions, "|") {
			t.Fatalf("derivation unstable: %+v vs %+v", el1, el2)
		}
	})
}

// TestEvidenceLevelPackageUsage covers the pure ladder against
// package-usage conditions: a SUPPORTED condition backed by the
// static-carrier fact closes L1; a REFUTED or UNKNOWN required path
// condition is always blocking and keeps the level at L2 — and a
// refuted path is never a safe conclusion.
func TestEvidenceLevelPackageUsage(t *testing.T) {
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	candPkg := FactUsageSubject{Module: module, Package: pkg}
	candSym := FactUsageSubject{Module: module, Package: pkg, Symbol: "Parse"}
	resolve := derivationFact("fact-obs-0002", "affected-resolve")
	usageTrue := derivationFact("fact-obs-0020", "package-usage")
	usageTrue.Kind = FactKindPackageUsage
	usageTrue.UsageSubject = &candPkg
	usageFalse := derivationFact("fact-obs-0021", "package-usage")
	usageFalse.Claim = "FALSE"
	usageFalse.Kind = FactKindPackageUsage
	usageFalse.NegativeVerification = NegativeVerificationVerified
	usageFalse.UsageSubject = &candPkg
	// usageCond mints a deterministic usage path condition bound to its
	// advisory-declared candidate — the shape the assembler emits.
	usageCond := func(id, state string, subj FactUsageSubject, refs ...string) ExploitationCondition {
		c := derivationCondition(id, subjProductPackageUsage, ConditionRolePath, OriginDeterm, "required", state, refs...)
		s := subj
		c.UsageSubject = &s
		return c
	}

	base := func() []ExploitationCondition {
		return []ExploitationCondition{
			derivationCondition("EC-0001", subjModulePresence, ConditionRoleApplicability, OriginDeterm, "required", StateSupported, resolve.ID),
			derivationCondition("EC-0002", subjVersionInUse, ConditionRoleApplicability, OriginDeterm, "required", StateSupported, resolve.ID),
			derivationCondition("EC-0003", subjPackageReach, ConditionRolePath, OriginDeterm, "required", StateSupported, resolve.ID),
			derivationCondition("EC-0004", subjBuildRelevant, ConditionRolePath, OriginDeterm, "required", StateSupported, resolve.ID),
			derivationCondition("EC-0005", subjRuntimePosture, ConditionRoleDeployment, OriginDeterm, "required", StateUnknown),
		}
	}
	mkReport := func() *Report {
		return &Report{
			Schema: ReportSchema, Mode: ReportMode,
			ContractExtensions: []string{Slice2ExtensionV3},
			ExploitationAxes: ExploitationAxes{
				ExploitationEstablished: Axis{Status: AxisNotEstablished, Basis: AxisBasisNone, Level: LevelNone},
			},
			AttackScenario: Section{Status: StatusUnknown},
		}
	}

	t.Run("SUPPORTED usage fact closes the path at L1", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, usageTrue}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateSupported, candPkg, usageTrue.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL1 || el.Basis != EvidenceBasisDeterministic {
			t.Fatalf("level = %s/%s, want L1/deterministic", el.Level, el.Basis)
		}
		if len(el.BlockingConditions) != 0 {
			t.Fatalf("blocking = %v, want none", el.BlockingConditions)
		}
		if !containsStr(el.EvidenceRefs, usageTrue.ID) {
			t.Fatalf("usage fact missing from evidence_refs: %v", el.EvidenceRefs)
		}
	})

	t.Run("SUPPORTED usage without its fact stays L2", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateSupported, candPkg, "obs:OBS-0020"))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2 (obs-only ref cannot close)", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})

	t.Run("REFUTED usage path keeps L2 and enters blocking", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, usageFalse}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateRefuted, candPkg, usageFalse.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
		refutedLim := false
		for _, l := range el.Limitations {
			if strings.Contains(l, "REFUTED path condition") &&
				strings.Contains(l, "bounded scope") {
				refutedLim = true
			}
		}
		if !refutedLim {
			t.Fatalf("L2 limitations do not name the bounded refutation: %v", el.Limitations)
		}
	})

	t.Run("UNKNOWN usage path is blocking", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateUnknown, candPkg, "obs:OBS-0020"))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})

	t.Run("agent OPEN usage hypothesis blocks L1 without evidence", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, usageTrue}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateSupported, candPkg, usageTrue.ID),
			derivationCondition("EC-0007", subjProductPackageUsage, ConditionRolePath, OriginAgent, "required", StateOpen, "A-0001", usageFalse.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2 (agent hypothesis blocks)", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0007") {
			t.Fatalf("blocking = %v, want EC-0007", el.BlockingConditions)
		}
		// The fact id an agent condition cites never leaks into the ladder.
		if containsStr(el.EvidenceRefs, usageFalse.ID) {
			t.Fatalf("agent-cited fact leaked into evidence_refs: %v", el.EvidenceRefs)
		}
	})

	t.Run("lower-bound usage fact never closes the path", func(t *testing.T) {
		// A PACKAGE_USAGE_LOWER_BOUND fact records positive content under
		// an open scope — it is never a USED verdict, so it can never
		// carry a SUPPORTED usage condition into L1 even when the
		// advisory-declared subject matches.
		lb := derivationFact("fact-obs-0022", "package-usage")
		lb.Kind = FactKindPackageUsageLowerBound
		lb.UsageSubject = &candPkg
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, lb}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateSupported, candPkg, lb.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2 (lower bound never closes)", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})

	t.Run("symbol-scoped fact never closes the package-level condition", func(t *testing.T) {
		// Same module and package, different symbol: the subject match
		// is exact on all three fields, so a symbol-bounded fact is no
		// carrier for the package-level candidate.
		symFact := derivationFact("fact-obs-0024", "package-usage")
		symFact.Kind = FactKindPackageUsage
		symFact.UsageSubject = &candSym
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, symFact}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateSupported, candPkg, symFact.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2 (symbol-scoped fact never closes the package candidate)", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})

	t.Run("usage fact for a different candidate never closes the path", func(t *testing.T) {
		// The cited fact's usage_subject binds it to a different
		// advisory-declared candidate than the condition covers: a
		// cross-subject citation is no carrier.
		other := derivationFact("fact-obs-0023", "package-usage")
		other.Kind = FactKindPackageUsage
		other.UsageSubject = &FactUsageSubject{Module: module, Package: "golang.org/x/net/quic"}
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, other}
		r.ExploitationConditions = append(base(),
			usageCond("EC-0006", StateSupported, candPkg, other.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2 (cross-subject citation never closes)", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})

	t.Run("unbound usage condition never closes the path", func(t *testing.T) {
		// A usage condition with no usage_subject cites a matching
		// PACKAGE_USAGE fact but carries no advisory-declared candidate:
		// the derivation stays open (fail-closed; the validator also
		// rejects the missing candidate identity outright).
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, usageTrue}
		r.ExploitationConditions = append(base(),
			derivationCondition("EC-0006", subjProductPackageUsage, ConditionRolePath, OriginDeterm, "required", StateSupported, usageTrue.ID))
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2 (unbound condition never closes)", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})
}

// TestAttackStatusPackageUsage covers the semantics-B attack_scenario
// derivation for package-usage conditions: only deterministic role=path
// transitions count, REFUTED never confirms a transition, and UNKNOWN
// usage produces PARTIAL only when another path transition is confirmed.
func TestAttackStatusPackageUsage(t *testing.T) {
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	resolveFact := factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected")
	turn := turnWith(t, "vulnerable", "the malformed frame path may be exploitable", nil)

	t.Run("UNKNOWN usage plus confirmed path transitions yields PARTIAL", func(t *testing.T) {
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
			},
			[]VerifiedFact{resolveFact})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "as-pu-partial",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status != StatusPartial {
			t.Fatalf("attack_scenario = %s, want PARTIAL (confirmed package/build transitions + open usage)", r.AttackScenario.Status)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("REFUTED usage never counts as a transition", func(t *testing.T) {
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
			},
			[]VerifiedFact{
				resolveFact,
				usageFact("OBS-0020", module, pkg, "", "FALSE", NegativeVerificationVerified, "no product-source use of "+pkg),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "as-pu-refuted",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status == StatusPartial {
			t.Fatal("REFUTED usage counted as a confirmed transition (PARTIAL)")
		}
		if r.AttackScenario.Status != StatusUnknown {
			t.Fatalf("attack_scenario = %s, want UNKNOWN", r.AttackScenario.Status)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("SUPPORTED usage transition enables PARTIAL over an open path gap", func(t *testing.T) {
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
			},
			[]VerifiedFact{
				resolveFact,
				usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used"),
			})
		lane.Affected.BuildRelevant = domain.ClaimUnknown
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "as-pu-transition",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status != StatusPartial {
			t.Fatalf("attack_scenario = %s, want PARTIAL (usage transition confirmed, build gap open)", r.AttackScenario.Status)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("agent usage claim contributes no transitions", func(t *testing.T) {
		agentTurn := turnWith(t, "vulnerable", "the product reaches the vulnerable code",
			map[string]any{
				"attack_scenario": map[string]any{
					"claims": []any{
						map[string]any{
							"statement": "product code calls the vulnerable package",
							"subject":   "Affected Package/Symbol Used By Product Code",
						},
					},
				},
			})
		lane := usageLane(t, module, pkg, nil,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
			},
			[]VerifiedFact{resolveFact})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: agentTurn, RunID: "as-pu-agent",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status != StatusPartial {
			t.Fatalf("attack_scenario = %s, want PARTIAL via confirmed package/build transitions only", r.AttackScenario.Status)
		}
		// The agent hypothesis contributes no transition and no
		// evidence: dropping it must not change the derivation inputs.
		for _, c := range r.ExploitationConditions {
			if c.Origin == OriginAgent && c.Subject == subjProductPackageUsage {
				if c.State != StateOpen {
					t.Fatalf("agent usage hypothesis state=%s, want OPEN", c.State)
				}
			}
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})
}
