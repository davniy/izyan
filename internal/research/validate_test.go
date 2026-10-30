package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// fakeLane builds a self-consistent deterministic lane result over a
// synthetic advisory: one OK observation + its verified fact.
func fakeLane(t *testing.T) *LaneResult {
	t.Helper()
	hash := strings.Repeat("ab", 32)
	obs := &evidencetools.Observation{
		ID:           "OBS-0001",
		Tool:         "advisory-load",
		Fact:         "frozen advisory GO-TEST-0001 resolved",
		Scope:        "single frozen advisory document load",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: hash, Subject: "GO-TEST-0001"},
	}
	lane := &LaneResult{
		SnapshotRoot: "/snap",
		ContentHash:  hash,
		Snapshot: domain.ProductSnapshot{
			Repository: "/snap", Commit: "deadbeef", GoVersion: "go version go1.25.0 darwin/arm64",
			GOOS: "linux", GOARCH: "amd64", ReleaseGoVersion: "1.25.0",
			MinimumGoVersion: "1.23",
		},
		Advisory: AdvisoryRecord{
			Input: AdvisoryInput{
				RequestedID: "GO-TEST-0001", ResolvedID: "GO-TEST-0001",
				SourceKind: "frozen_file", SourcePath: "/adv/GO-TEST-0001.json",
				RawSHA256: hash, CanonicalSHA256: hash,
			},
			Vuln: &domain.Vulnerability{
				ID: "GO-TEST-0001", Summary: "test advisory",
				AffectedModules: []domain.AffectedModule{{Module: "golang.org/x/net"}},
			},
			Impls: []AffectedImplementation{{
				ID: "adv-01", Ecosystem: "Go", Module: "golang.org/x/net",
				Package: strPtr("golang.org/x/net/http2"), Symbols: []string{"ServeConn"},
				Binding:   BindExact,
				SourceRef: "adv:GO-TEST-0001",
				AffectedVersions: []VersionBounds{{
					Introduced: strPtr("0"), Fixed: strPtr("v0.37.0"),
				}},
			}},
		},
		Observations: []*evidencetools.Observation{obs, {
			ID: "OBS-0002", Tool: "affected-resolve", ToolStatus: evidencetools.StatusOK, Completeness: evidencetools.CompletenessPartial,
			Fact: "affected-resolve over golang.org/x/net", Scope: "go module graph",
			ScopeDetails: &evidencetools.ScopeDetails{Profile: "strict", Subject: "golang.org/x/net"},
		}},
		ArtifactByObs:  map[string]ArtifactRef{"OBS-0001": {Path: "artifacts/obs-0001.json", SHA256: hash}, "OBS-0002": {Path: "artifacts/obs-0002.json", SHA256: hash}},
		CanonicalByObs: map[string]string{"OBS-0001": hash, "OBS-0002": hash},
		Facts:          nil,
		Affected: domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
			SelectedModule:  "golang.org/x/net",
			SelectedModules: []string{"golang.org/x/net"},
			CheckedModules:  []string{"golang.org/x/net"},
		},
	}
	lane.Facts = []VerifiedFact{{
		ID: "fact-obs-0001", Statement: obs.Fact, Claim: "TRUE",
		Tool: "advisory-load", ToolVersion: "test", Command: "advisory-load {}",
		Scope: obs.Scope, Status: "OK", Coverage: "COMPLETE",
		SnapshotContentHash: hash,
		InputDigest:         hash, DataDigest: hash,
		Artifact:   ArtifactRef{Path: "artifacts/obs-0001.json", SHA256: hash},
		Provenance: FactProvenance{ObservationID: "OBS-0001", Source: "deterministic-lane", GeneratedAt: "2026-01-01T00:00:00Z"},
	}, {
		ID: "fact-obs-0002", Statement: "affected-resolve over golang.org/x/net", Claim: "TRUE",
		Tool: "affected-resolve", ToolVersion: "test", Command: "affected-resolve {}",
		Scope: "go module graph", Status: "OK", Coverage: "PARTIAL",
		SnapshotContentHash: hash,
		InputDigest:         hash, DataDigest: hash,
		Artifact:   ArtifactRef{Path: "artifacts/obs-0002.json", SHA256: hash},
		Provenance: FactProvenance{ObservationID: "OBS-0002", Source: "deterministic-lane", GeneratedAt: "2026-01-01T00:00:00Z"},
	}}
	return lane
}

// validReport assembles a contract-valid deterministic-only report.
func validReport(t *testing.T) *Report {
	t.Helper()
	r := Assemble(AssembleInput{
		Lane:              fakeLane(t),
		DeterministicOnly: true,
		RunID:             "research-test",
		StartedAt:         time.Now(), FinishedAt: time.Now(),
	})
	return r
}

func TestValidate_AcceptsDeterministicOnly(t *testing.T) {
	if err := Validate(validReport(t), ""); err != nil {
		t.Fatalf("valid report rejected:\n%v", err)
	}
}

func TestValidate_RejectsBadDisposition(t *testing.T) {
	for _, cls := range []string{"VERIFIED", "FALSE", "AUTO_CLOSE", "NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"} {
		r := validReport(t)
		r.Disposition.Class = cls
		if err := Validate(r, ""); err == nil {
			t.Fatalf("class %q accepted", cls)
		}
	}
	r := validReport(t)
	r.Disposition.AutoClose = true
	if err := Validate(r, ""); err == nil {
		t.Fatal("auto_close=true accepted")
	}
}

func TestValidate_RejectsBareUnknown(t *testing.T) {
	r := validReport(t)
	r.RootCause = Section{Status: StatusUnknown, Summary: "UNKNOWN"}
	if err := Validate(r, ""); err == nil {
		t.Fatal("bare UNKNOWN accepted")
	}
	r = validReport(t)
	r.RootCause = Section{Status: StatusUnknown, Summary: "UNKNOWN: no data"}
	if err := Validate(r, ""); err == nil {
		t.Fatal("UNKNOWN without follow-up accepted")
	}
	r = validReport(t)
	r.RootCause = Section{Status: StatusUnknown, Summary: unknownSummary("no data", "run X")}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("proper unknown summary rejected: %v", err)
	}
}

func TestValidate_RejectsAgentDataInFacts(t *testing.T) {
	r := validReport(t)
	r.VerifiedFacts[0].Limitations = append(r.VerifiedFacts[0].Limitations,
		"see agent-src:session-export")
	if err := Validate(r, ""); err == nil {
		t.Fatal("agent-origin ref inside verified_facts accepted")
	}
	r = validReport(t)
	r.VerifiedFacts[0].Provenance.Source = "agent-turn"
	if err := Validate(r, ""); err == nil {
		t.Fatal("agent provenance in verified_facts accepted")
	}
	r = validReport(t)
	r.VerifiedFacts[0].Status = "PARTIAL"
	if err := Validate(r, ""); err == nil {
		t.Fatal("non-OK fact status accepted")
	}
}

func TestValidate_RejectsBrokenRefs(t *testing.T) {
	r := validReport(t)
	r.Unknowns[0].EvidenceRefs = append(r.Unknowns[0].EvidenceRefs, "fact-does-not-exist")
	if err := Validate(r, ""); err == nil {
		t.Fatal("broken evidence ref accepted")
	}
	r = validReport(t)
	r.ProductApplicability.EvidenceRefs = []string{"obs:OBS-9999"}
	if err := Validate(r, ""); err == nil {
		t.Fatal("unresolvable obs ref accepted")
	}
}

func TestValidate_DeterministicClaimNeedsFactRef(t *testing.T) {
	r := validReport(t)
	r.RootCause.Claims = append(r.RootCause.Claims, Claim{
		ID: "dc-x", Statement: "x", Origin: OriginDeterm, State: StateSupported,
		EvidenceRefs: []string{"agent-src:foo"},
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("deterministic claim without fact ref accepted")
	}
	r = validReport(t)
	r.RootCause.Claims = append(r.RootCause.Claims, Claim{
		ID: "dc-y", Statement: "y", Origin: OriginDeterm, State: StateSupported,
		EvidenceRefs: []string{r.VerifiedFacts[0].ID},
	})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("deterministic claim with fact ref rejected: %v", err)
	}
}

func TestValidate_FactFieldCompleteness(t *testing.T) {
	mutate := func(f func(*VerifiedFact)) *Report {
		r := validReport(t)
		f(&r.VerifiedFacts[0])
		return r
	}
	cases := []struct {
		name string
		mut  func(*VerifiedFact)
	}{
		{"empty tool", func(f *VerifiedFact) { f.Tool = "" }},
		{"empty command", func(f *VerifiedFact) { f.Command = "" }},
		{"empty scope", func(f *VerifiedFact) { f.Scope = "" }},
		{"bad hash", func(f *VerifiedFact) { f.SnapshotContentHash = "zz" }},
		{"missing digests", func(f *VerifiedFact) { f.InputDigest, f.DataDigest = "", "" }},
		{"missing artifact", func(f *VerifiedFact) { f.Artifact = ArtifactRef{} }},
		{"bad obs id", func(f *VerifiedFact) { f.Provenance.ObservationID = "X-1" }},
		{"bad coverage", func(f *VerifiedFact) { f.Coverage = "UNKNOWN" }},
	}
	for _, c := range cases {
		if err := Validate(mutate(c.mut), ""); err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
	}
}

func TestValidate_QuestionIDPairing(t *testing.T) {
	r := validReport(t)
	r.ResidualQuestions = r.ResidualQuestions[:len(r.ResidualQuestions)-1]
	if err := Validate(r, ""); err == nil {
		t.Fatal("diverged question lists accepted")
	}
}

func TestParseReport_RejectsUnknownFields(t *testing.T) {
	jb, err := RenderJSON(validReport(t))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(jb, &m); err != nil {
		t.Fatal(err)
	}
	m["surprise"] = true
	bad, _ := json.Marshal(m)
	if _, err := ParseReport(bad); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
	// Nested unknown member rejected too.
	if err := json.Unmarshal(jb, &m); err != nil {
		t.Fatal(err)
	}
	m["run"].(map[string]any)["extra"] = 1
	bad, _ = json.Marshal(m)
	if _, err := ParseReport(bad); err == nil {
		t.Fatal("unknown nested field accepted")
	}
	if _, err := ParseReport(jb); err != nil {
		t.Fatalf("canonical report rejected: %v", err)
	}
}

func TestValidate_AgentOutputContract(t *testing.T) {
	r := validReport(t)
	r.AgentOutput = AgentOutput{Status: "GIBBERISH"}
	if err := Validate(r, ""); err == nil {
		t.Fatal("invalid agent status accepted")
	}
	r = validReport(t)
	r.AgentOutput = AgentOutput{Status: AgentOK}
	if err := Validate(r, ""); err == nil {
		t.Fatal("OK agent output without category/artifact accepted")
	}
}

func TestIsUnknownSummary(t *testing.T) {
	for s, want := range map[string]bool{
		"UNKNOWN":                         false,
		"UNKNOWN: x":                      false,
		"UNKNOWN: x; follow-up: y":        true,
		"  UNKNOWN: x; follow-up: do Y  ": true,
		"UNKNOWN: component grpc-go absent; follow-up: check advisory": true,
		"partial: x": false,
	} {
		if got := isUnknownSummary(s); got != want {
			t.Errorf("isUnknownSummary(%q)=%v want %v", s, got, want)
		}
	}
}

func TestArtifactDigestVerification(t *testing.T) {
	dir := t.TempDir()
	// artifact.sha256 must equal sha256 of the file bytes exactly as
	// written (including the trailing newline the lane appends).
	written1 := append([]byte(`{"id":"OBS-0001"}`), '\n')
	sum1 := sha256.Sum256(written1)
	written2 := append([]byte(`{"id":"OBS-0002"}`), '\n')
	sum2 := sha256.Sum256(written2)
	r := validReport(t)
	sums := map[string]string{
		"artifacts/obs-0001.json": hex.EncodeToString(sum1[:]),
		"artifacts/obs-0002.json": hex.EncodeToString(sum2[:]),
	}
	r.VerifiedFacts[0].Artifact = ArtifactRef{
		Path: "artifacts/obs-0001.json", SHA256: sums["artifacts/obs-0001.json"]}
	r.VerifiedFacts[1].Artifact = ArtifactRef{
		Path: "artifacts/obs-0002.json", SHA256: sums["artifacts/obs-0002.json"]}
	for i := range r.EvidenceQuality.References {
		if s, ok := sums[r.EvidenceQuality.References[i].Path]; ok {
			r.EvidenceQuality.References[i].SHA256 = s
		}
	}
	writeFile(t, dir, "artifacts/obs-0001.json", written1)
	writeFile(t, dir, "artifacts/obs-0002.json", written2)
	if err := Validate(r, dir); err != nil {
		t.Fatalf("matching artifact rejected: %v", err)
	}
	r.VerifiedFacts[0].Artifact.SHA256 = strings.Repeat("00", 32)
	if err := Validate(r, dir); err == nil {
		t.Fatal("sha mismatch accepted")
	}
}

// slice2-fidelity/2 negative invariants: the validator rejects (j) a
// REFUTED reachability predicate that was never evaluated FALSE, (i) an
// agent condition promoted to SUPPORTED, (d) a FALSE reachability claim
// under a fixed evaluated entry, (h) an agent basis carrying a verified
// ref, and (a) a basis without a check_scope.
func TestSlice2V2_ValidatorRejects(t *testing.T) {
	// (j) REFUTED on a predicate the lane never evaluated.
	r := validReport(t)
	for i := range r.ExploitationConditions {
		if r.ExploitationConditions[i].Subject == subjPackageReach {
			r.ExploitationConditions[i].State = StateRefuted
		}
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("REFUTED on an evaluated-TRUE predicate accepted")
	}
	// FIXED + reachability FALSE is impossible: FIXED never refutes.
	r = validReport(t)
	r.ProductApplicability.VersionAffected = "FALSE"
	r.ProductApplicability.PackagePresent = "FALSE"
	r.ProductApplicability.AdvisoryEntryStatus = EntryFixed
	r.ProductApplicability.VulnerableCodeReachability = VCRFalse
	for i := range r.ExploitationConditions {
		if r.ExploitationConditions[i].Subject == subjPackageReach {
			r.ExploitationConditions[i].State = StateRefuted
		}
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("FIXED + reachability FALSE accepted")
	}
	// (i) an agent-origin condition may never be SUPPORTED/REFUTED.
	r = validReport(t)
	r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
		ID: "EC-X", Subject: "attacker delivers malformed frame",
		Necessity: "unknown", Origin: OriginAgent, State: StateSupported,
		EvidenceRefs: []string{"adv:GO-TEST-0001"},
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("agent SUPPORTED condition accepted")
	}
	// (h) an agent/provisional basis must not carry verified refs.
	r = validReport(t)
	r.ProductApplicability.Basis = append(r.ProductApplicability.Basis, ApplicabilityBasis{
		Kind: ABVulnCodeNotReachable, Status: ABProvisional, Source: ABSourceAgent,
		Statement: "x", EvidenceRefs: []string{"A-0001"},
		VerifiedEvidenceRefs: []string{"fact-obs-0002"},
		CheckScope:           "agent-read product source scope",
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("provisional basis with verified refs accepted")
	}
	// (a) every emitted basis must name its check scope.
	r = validReport(t)
	for i := range r.ProductApplicability.Basis {
		r.ProductApplicability.Basis[i].CheckScope = ""
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("basis without check_scope accepted under /2")
	}
	// (e) reachability FALSE without a verified deterministic negative basis.
	r = validReport(t)
	r.ProductApplicability.VulnerableCodeReachability = VCRFalse
	r.ProductApplicability.Basis = nil
	if err := Validate(r, ""); err == nil {
		t.Fatal("reachability FALSE without a negative basis accepted")
	}
	// (k) attack_scenario SUPPORTED without ESTABLISHED exploitation.
	r = validReport(t)
	r.AttackScenario.Status = StatusSupported
	if err := Validate(r, ""); err == nil {
		t.Fatal("attack_scenario SUPPORTED without established exploitation accepted")
	}
	// (l) PARTIAL without the not-established marker.
	r = validReport(t)
	r.AttackScenario.Status = StatusPartial
	r.AttackScenario.Summary = "agent chain confirmed"
	if err := Validate(r, ""); err == nil {
		t.Fatal("PARTIAL without the exploit-path marker accepted")
	}
}

// Review fix — finding 1: advisory_entry_status must equal the aggregate
// of the per-entry verdicts implied by checked/selected/pending module
// sets. A forged MIXED with no fixed evaluated entry, a forged FIXED
// under version_affected=TRUE, and drifted evaluated_entry_ids are all
// rejected.
func TestSlice2V2_EntryStatusAggregateConsistency(t *testing.T) {
	// Forged MIXED: the single checked+selected entry is affected, so the
	// aggregate can only be AFFECTED.
	r := validReport(t)
	r.ProductApplicability.AdvisoryEntryStatus = EntryMixed
	if err := Validate(r, ""); err == nil {
		t.Fatal("advisory_entry_status=MIXED without a fixed evaluated entry accepted")
	}
	// Forged FIXED under version_affected=TRUE.
	r = validReport(t)
	r.ProductApplicability.AdvisoryEntryStatus = EntryFixed
	r.ProductApplicability.ResolvedVersion = strPtr("v9.9.9")
	if err := Validate(r, ""); err == nil {
		t.Fatal("advisory_entry_status=FIXED with a selected (affected) entry accepted")
	}
	// An entry that was never probed cannot be listed as evaluated.
	r = validReport(t)
	r.ProductApplicability.EvaluatedEntryIDs = append(
		append([]string{}, r.ProductApplicability.EvaluatedEntryIDs...), "adv-99")
	if err := Validate(r, ""); err == nil {
		t.Fatal("evaluated_entry_ids carrying a non-resolving id accepted")
	}
	// Dropping an evaluated entry drifts the table away from the module sets.
	r = validReport(t)
	r.ProductApplicability.EvaluatedEntryIDs = []string{}
	if err := Validate(r, ""); err == nil {
		t.Fatal("evaluated_entry_ids missing the probed entry accepted")
	}
	// The legitimate report stays valid.
	if err := Validate(validReport(t), ""); err != nil {
		t.Fatalf("legitimate report rejected:\n%v", err)
	}
}

// Review fix — finding 2: vulnerable_code_reachability=FALSE requires a
// verified negative basis CONSISTENT with the applicability fields, and
// TRUE requires a resolved applicability-probe fact behind it.
func TestSlice2V2_ReachabilityNeedsConsistentBasis(t *testing.T) {
	// component_absent on a module that is present proves nothing about
	// this report's reachability.
	r := validReport(t)
	r.ProductApplicability.VulnerableCodeReachability = VCRFalse
	r.ProductApplicability.Basis = append(r.ProductApplicability.Basis, ApplicabilityBasis{
		Kind: ABComponentAbsent, Status: ABEstablished, Source: ABSourceDeterministic,
		Statement:            "module absent",
		VerifiedEvidenceRefs: []string{"fact-obs-0002"},
		CheckScope:           "resolved module graph",
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("VCR=FALSE on an inconsistent component_absent basis accepted")
	}
	// package_not_in_import_closure while the probe fields say the
	// package is present and build-relevant is inconsistent too.
	r = validReport(t)
	r.ProductApplicability.VulnerableCodeReachability = VCRFalse
	r.ProductApplicability.Basis = append(r.ProductApplicability.Basis, ApplicabilityBasis{
		Kind: ABNotInImportClosure, Status: ABEstablished, Source: ABSourceDeterministic,
		Statement:            "package not imported",
		VerifiedEvidenceRefs: []string{"fact-obs-0002"},
		CheckScope:           "import closure",
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("VCR=FALSE on a package_not_in_import_closure basis contradicted by the fields accepted")
	}
	// TRUE without a resolved applicability-probe fact: evidence_refs and
	// every basis carry only an unrelated verified fact.
	r = validReport(t)
	r.ProductApplicability.EvidenceRefs = []string{"fact-obs-0001"}
	for i := range r.ProductApplicability.Basis {
		r.ProductApplicability.Basis[i].VerifiedEvidenceRefs = []string{"fact-obs-0001"}
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("VCR=TRUE without an applicability-probe fact ref accepted")
	}
	// Legitimate VCR=TRUE passes (probe fact present).
	if err := Validate(validReport(t), ""); err != nil {
		t.Fatalf("legitimate VCR=TRUE report rejected:\n%v", err)
	}
}

// Review fix — finding 3: NON_APPLICABLE+SUPPORTED may only rest on an
// ESTABLISHED deterministic component_absent/package_not_in_import_closure
// basis cited in basis_refs. version_fixed, provisional bases, and stray
// verified facts cannot carry the class.
func TestSlice2V2_ClassificationSupportedNeedsNegativeBasis(t *testing.T) {
	// A version_fixed ESTABLISHED basis never supports NON_APPLICABLE.
	r := validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassNonApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"fact-obs-0002"},
	}
	r.ProductApplicability.Basis = []ApplicabilityBasis{{
		Kind: ABVersionFixed, Status: ABEstablished, Source: ABSourceDeterministic,
		Statement:            "module resolves to a fixed version",
		EvidenceRefs:         []string{"fact-obs-0002"},
		VerifiedEvidenceRefs: []string{"fact-obs-0002"},
		CheckScope:           "resolved version vs affected ranges",
	}}
	if err := Validate(r, ""); err == nil {
		t.Fatal("NON_APPLICABLE+SUPPORTED on a version_fixed basis accepted")
	}
	// A verified fact cited in basis_refs that no allowed negative basis
	// carries is a stray ref, not a supporting basis.
	r = validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassNonApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"fact-obs-0001"},
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("NON_APPLICABLE+SUPPORTED on a stray verified fact accepted")
	}
	// A provisional basis is never a carrier even when a stray fact is
	// cited alongside it.
	r = validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassNonApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"adv:GO-TEST-0001", "fact-obs-0001"},
	}
	r.ProductApplicability.Basis = []ApplicabilityBasis{{
		Kind: ABVulnCodeNotReachable, Status: ABProvisional, Source: ABSourceAgent,
		Statement:  "agent claims the code is unreachable",
		CheckScope: "agent-read product source scope",
	}}
	if err := Validate(r, ""); err == nil {
		t.Fatal("NON_APPLICABLE+SUPPORTED on a provisional basis accepted")
	}
	// An ESTABLISHED component_absent basis contradicted by the
	// applicability fields (module_present=TRUE) cannot carry the class
	// even when its verified ref is cited.
	r = validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassNonApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"fact-obs-0002"},
	}
	r.ProductApplicability.Basis = append(r.ProductApplicability.Basis, ApplicabilityBasis{
		Kind: ABComponentAbsent, Status: ABEstablished, Source: ABSourceDeterministic,
		Statement:            "module absent",
		VerifiedEvidenceRefs: []string{"fact-obs-0002"},
		CheckScope:           "resolved module graph",
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("NON_APPLICABLE+SUPPORTED on a field-inconsistent component_absent basis accepted")
	}
	// The matrix is closed: UNCERTAIN and NOT_EVALUATED can never be
	// SUPPORTED regardless of the cited refs.
	for _, cls := range []string{ClassUncertain, ClassNotEvaluated} {
		r = validReport(t)
		r.ClassificationReview = ClassificationReview{
			Class:     cls,
			Status:    StatusSupported,
			BasisRefs: []string{"fact-obs-0002"},
		}
		if err := Validate(r, ""); err == nil {
			t.Fatalf("%s+SUPPORTED accepted", cls)
		}
	}
	// APPLICABLE+SUPPORTED requires module_present=TRUE +
	// version_affected=TRUE and a cited applicability-probe fact —
	// neither a non-probe fact nor an absent version verdict carries it.
	r = validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"fact-obs-0002"},
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("legitimate APPLICABLE+SUPPORTED rejected:\n%v", err)
	}
	r = validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"fact-obs-0001"},
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("APPLICABLE+SUPPORTED without a cited probe fact accepted")
	}
	r = validReport(t)
	r.ClassificationReview = ClassificationReview{
		Class:     ClassApplicable,
		Status:    StatusSupported,
		BasisRefs: []string{"fact-obs-0002"},
	}
	r.ProductApplicability.ModulePresent = "FALSE"
	if err := Validate(r, ""); err == nil {
		t.Fatal("APPLICABLE+SUPPORTED under module_present=FALSE accepted")
	}
}

// Review fix — finding 4: exploitation_established=ESTABLISHED requires
// at least one evidence ref resolving to a verified dynamic fact, and
// attack_scenario=SUPPORTED rides on the same requirement.
func TestSlice2V2_EstablishedAxisNeedsDynamicRef(t *testing.T) {
	forgeAxis := func(refs []string) *Report {
		r := validReport(t)
		r.ExploitationAxes.ExploitationEstablished = Axis{
			Status:       AxisEstablished,
			Level:        LevelDynamicReproduction,
			Basis:        AxisBasisDynamic,
			Statement:    "dynamic proof",
			Scope:        "whole report scope",
			EvidenceRefs: refs,
		}
		r.AttackScenario.Status = StatusSupported
		return r
	}
	// Empty evidence refs.
	if err := Validate(forgeAxis(nil), ""); err == nil {
		t.Fatal("ESTABLISHED dynamic axis with no evidence refs accepted")
	}
	// A resolvable but static fact is not dynamic evidence.
	if err := Validate(forgeAxis([]string{"fact-obs-0001"}), ""); err == nil {
		t.Fatal("ESTABLISHED dynamic axis on a non-dynamic fact accepted")
	}
	// Positive: a verified fact from a dynamic tool carries the axis and
	// the SUPPORTED attack_scenario.
	r := validReport(t)
	r.VerifiedFacts = append(r.VerifiedFacts, factFor("OBS-0042", "reproduction",
		"attacker input reproduced the crash"))
	r.ExploitationAxes.ExploitationEstablished = Axis{
		Status:       AxisEstablished,
		Level:        LevelDynamicReproduction,
		Basis:        AxisBasisDynamic,
		Statement:    "a retained reproduction establishes attacker exploitability",
		Scope:        "whole report scope",
		EvidenceRefs: []string{"fact-obs-0042"},
	}
	r.AttackScenario.Status = StatusSupported
	// slice2-fidelity/3: evidence_level is a derived field — a forged
	// report body must carry the recomputed value the assembler would
	// emit for this data (dynamic axis + SUPPORTED → L3).
	el := deriveEvidenceLevel(r)
	r.EvidenceLevel = &el
	if err := Validate(r, ""); err != nil {
		t.Fatalf("ESTABLISHED axis with a verified dynamic ref rejected:\n%v", err)
	}
}

// Review fix — finding 7: the condition-state enum is closed, agent
// conditions must be exactly OPEN, and deterministic applicability
// conditions must mirror their field (SUPPORTED↔TRUE, REFUTED↔FALSE,
// UNKNOWN↔UNKNOWN).
func TestSlice2V2_ConditionStateEnforcement(t *testing.T) {
	// Agent conditions: every non-OPEN state is rejected.
	for _, st := range []string{StateUnknown, StateConflicted, StateRetracted, ""} {
		r := validReport(t)
		r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
			ID: "EC-BAD", Subject: "attacker delivers a malformed frame",
			Necessity: "unknown", Origin: OriginAgent, State: st,
			Statement:    "agent hypothesis",
			EvidenceRefs: []string{"adv:GO-TEST-0001"},
		})
		if err := Validate(r, ""); err == nil {
			t.Fatalf("agent condition with state %q accepted", st)
		}
	}
	// A fabricated deterministic SUPPORTED for "affected package
	// reachable" while package_present=UNKNOWN is rejected — before the
	// fix it counted as a confirmed transition.
	r := validReport(t)
	r.ProductApplicability.PackagePresent = "UNKNOWN"
	r.ProductApplicability.VulnerableCodeReachability = VCRUnknown
	for i := range r.ExploitationConditions {
		if r.ExploitationConditions[i].Subject == subjPackageReach {
			r.ExploitationConditions[i].State = StateSupported
		}
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("deterministic SUPPORTED on an UNKNOWN package predicate accepted")
	}
	// An UNKNOWN state masking a decided (TRUE) field is rejected too.
	r = validReport(t)
	for i := range r.ExploitationConditions {
		if r.ExploitationConditions[i].Subject == subjBuildRelevant {
			r.ExploitationConditions[i].State = StateUnknown
		}
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("deterministic UNKNOWN on a TRUE build predicate accepted")
	}
	// An invalid state value is rejected outright.
	r = validReport(t)
	for i := range r.ExploitationConditions {
		if r.ExploitationConditions[i].Subject == subjRuntimePosture {
			r.ExploitationConditions[i].State = "BOGUS"
		}
	}
	if err := Validate(r, ""); err == nil {
		t.Fatal("condition with invalid state accepted")
	}
	// The legitimate report stays valid.
	if err := Validate(validReport(t), ""); err != nil {
		t.Fatalf("legitimate report rejected:\n%v", err)
	}
}

func writeFile(t *testing.T, dir, rel string, b []byte) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- decision-ref strictness (C1) ---
// A decision ref can never stand on the report's own self-listed strings:
// it must resolve to a persisted ledger observation, a lane fact (or its
// digests), or the advisory/agent-source spaces. Anything else is reported.

// decisionReport returns a contract-valid /2 report whose INCONCLUSIVE
// decision carries the given evidence refs.
func decisionReport(t *testing.T, refs ...string) *Report {
	t.Helper()
	r := validReport(t)
	r.Decision = &EvidenceDecision{
		Verdict: domain.VerdictInconclusive, Reason: "verification did not close the scope",
		Scope: "independent verification scope", Coverage: "INSUFFICIENT_SCOPE",
		EvidenceRefs:    refs,
		HumanQuestions:  []string{"which deterministic check closes the named scope?"},
		TicketRationale: "independent verification did not close the scope; follow-up: provide a complete deterministic check",
	}
	return r
}

// writeLaneArtifacts pins the fakeLane facts' artifact files so dir-mode
// validation's byte-for-byte artifact check passes — both the fact's own
// artifact.sha256 and the evidence_quality.references rows that pin the
// same observations.
func writeLaneArtifacts(t *testing.T, r *Report, dir string) {
	t.Helper()
	sums := map[string]string{}
	for _, f := range r.VerifiedFacts {
		if f.Artifact.Path == "" {
			continue
		}
		b := []byte(`{"id":"` + f.Provenance.ObservationID + `"}` + "\n")
		sum := sha256.Sum256(b)
		sums[f.Artifact.Path] = hex.EncodeToString(sum[:])
		for i := range r.VerifiedFacts {
			if r.VerifiedFacts[i].ID == f.ID {
				r.VerifiedFacts[i].Artifact.SHA256 = sums[f.Artifact.Path]
			}
		}
		writeFile(t, dir, f.Artifact.Path, b)
	}
	for i := range r.EvidenceQuality.References {
		if sum, ok := sums[r.EvidenceQuality.References[i].Path]; ok {
			r.EvidenceQuality.References[i].SHA256 = sum
		}
	}
}

// A decision ref that exists only because the report lists it in
// evidence_quality.references — and in no persisted ledger — must fail:
// the marker the analyzer wrote cannot be the marker it reads back.
func TestValidateDecisionRefSelfListing(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "agent-src:answer.txt")
	writeLaneArtifacts(t, r, dir)
	// The self-listed marker: an agent-source index row that only exists
	// because this report lists it.
	r.EvidenceQuality.References = append(r.EvidenceQuality.References,
		EvidenceReference{Ref: "agent-src:answer.txt", Kind: "agent-source",
			Path: "agent/attempt-0002/answer.txt"})
	writeFile(t, dir, "observations.jsonl", []byte(`{"observation":{"id":"OBS-0001"}}`+"\n"))
	err := Validate(r, dir)
	if err == nil {
		t.Fatal("decision ref backed only by the report's own reference list validated")
	}
	if !strings.Contains(err.Error(), "decision.evidence_refs") {
		t.Fatalf("expected a decision.evidence_refs failure, got: %v", err)
	}
}

// With no directory the fallback must stay strict: a decision ref that
// appears nowhere in recorded evidence is reported, not self-accepted.
func TestValidateDecisionRefNoDirectory(t *testing.T) {
	err := Validate(decisionReport(t, "obs:OBS-9999"), "")
	if err == nil {
		t.Fatal("unresolvable decision ref validated with no directory")
	}
	if !strings.Contains(err.Error(), "decision.evidence_refs") {
		t.Fatalf("expected a decision.evidence_refs failure, got: %v", err)
	}
}

// The legitimate path: a decision ref naming an id persisted in
// verification-observations.jsonl resolves — but only while the
// ledger row, the pinned artifact and the evidence_quality.references
// pin all describe the same bytes.
func TestValidateDecisionRefVerificationLedger(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "obs:OBS-0100")
	writeLaneArtifacts(t, r, dir)
	writeVerificationPin(t, r, dir, verificationObs())
	if err := Validate(r, dir); err != nil {
		t.Fatalf("verification-ledger decision ref rejected: %v", err)
	}
}

// verificationObs is the persisted verification observation the
// artifact and the ledger row both describe verbatim.
func verificationObs() *evidencetools.Observation {
	return &evidencetools.Observation{
		ID: "OBS-0100", Tool: "usage-scope", Fact: "paired closures classified",
		Scope:        "product vs test build closures",
		Completeness: evidencetools.CompletenessComplete, ToolStatus: evidencetools.StatusOK,
		EvidenceRefs: []string{"sha256:" + strings.Repeat("cd", 32)},
		Data:         map[string]any{"usage_scope": "test-only", "product_absence_verification": "verified"},
		ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: strings.Repeat("ab", 32), CoverageRule: "paired go list closures"},
	}
}

// writeVerificationPin persists obs exactly as the CLI does: the
// canonical artifact under verification-artifacts/, one audit row in
// verification-observations.jsonl, and the evidence_quality.references
// row pinning path+sha256.
func writeVerificationPin(t *testing.T, r *Report, dir string, obs *evidencetools.Observation) {
	t.Helper()
	payload, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	written := append(payload, '\n')
	name := strings.ToLower(obs.ID) + ".json"
	writeFile(t, dir, "verification-artifacts/"+name, written)
	sum := sha256.Sum256(written)
	r.EvidenceQuality.References = append(r.EvidenceQuality.References,
		EvidenceReference{Ref: "obs:" + obs.ID, Kind: "observation",
			Path: "verification-artifacts/" + name, Selector: "verification-observation",
			SHA256: hex.EncodeToString(sum[:])})
	rec := evidencetools.AuditRecord{Tool: obs.Tool, Observation: obs}
	row, err := json.Marshal(&rec)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "verification-observations.jsonl", append(row, '\n'))
}

// Mutating the pinned artifact after emission must invalidate the
// report: the recorded sha256 no longer matches the file bytes.
func TestValidateDecisionRefMutatedArtifact(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "obs:OBS-0100")
	writeLaneArtifacts(t, r, dir)
	writeVerificationPin(t, r, dir, verificationObs())
	writeFile(t, dir, "verification-artifacts/obs-0100.json", []byte(`{"id":"OBS-0100","fact":"forged"}`+"\n"))
	err := Validate(r, dir)
	if err == nil {
		t.Fatal("mutated verification artifact still validates")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected a sha256 mismatch failure, got: %v", err)
	}
}

// Removing the ledger row must invalidate the cited observation even
// though the artifact itself is intact.
func TestValidateDecisionRefMissingLedgerRow(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "obs:OBS-0100")
	writeLaneArtifacts(t, r, dir)
	writeVerificationPin(t, r, dir, verificationObs())
	if err := os.Remove(filepath.Join(dir, "verification-observations.jsonl")); err != nil {
		t.Fatal(err)
	}
	err := Validate(r, dir)
	if err == nil {
		t.Fatal("decision ref validates with the cited ledger row removed")
	}
	if !strings.Contains(err.Error(), "no matching verification-observations.jsonl row") {
		t.Fatalf("expected a missing-ledger-row failure, got: %v", err)
	}
}

// A ledger row whose id matches but whose payload was edited must not
// validate — the audit trail and the pinned artifact disagree.
func TestValidateDecisionRefChangedLedgerRow(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "obs:OBS-0100")
	writeLaneArtifacts(t, r, dir)
	writeVerificationPin(t, r, dir, verificationObs())
	edited := verificationObs()
	edited.Fact = "forged ledger payload"
	rec := evidencetools.AuditRecord{Tool: edited.Tool, Observation: edited}
	row, _ := json.Marshal(&rec)
	writeFile(t, dir, "verification-observations.jsonl", append(row, '\n'))
	err := Validate(r, dir)
	if err == nil {
		t.Fatal("edited ledger row still validates")
	}
	if !strings.Contains(err.Error(), "does not match the pinned artifact payload") {
		t.Fatalf("expected a ledger/artifact mismatch failure, got: %v", err)
	}
}

// Duplicating the cited ledger row is corruption, not redundancy.
func TestValidateDecisionRefDuplicateLedgerRow(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "obs:OBS-0100")
	writeLaneArtifacts(t, r, dir)
	writeVerificationPin(t, r, dir, verificationObs())
	rec := evidencetools.AuditRecord{Tool: "usage-scope", Observation: verificationObs()}
	row, _ := json.Marshal(&rec)
	writeFile(t, dir, "verification-observations.jsonl", append(append(row, '\n'), row...))
	err := Validate(r, dir)
	if err == nil {
		t.Fatal("duplicated ledger row still validates")
	}
	if !strings.Contains(err.Error(), "ledger rows claim observation id") {
		t.Fatalf("expected a duplicate-ledger-row failure, got: %v", err)
	}
}

// A cited observation id that resolves in the ledger but was never
// pinned to an artifact is a dangling citation.
func TestValidateDecisionRefUnpinnedObservation(t *testing.T) {
	dir := t.TempDir()
	r := decisionReport(t, "obs:OBS-0100")
	writeLaneArtifacts(t, r, dir)
	rec := evidencetools.AuditRecord{Tool: "usage-scope", Observation: verificationObs()}
	row, _ := json.Marshal(&rec)
	writeFile(t, dir, "verification-observations.jsonl", append(row, '\n'))
	err := Validate(r, dir)
	if err == nil {
		t.Fatal("unpinned cited observation validates")
	}
	if !strings.Contains(err.Error(), "no pinned evidence_quality.references row") {
		t.Fatalf("expected an unpinned-citation failure, got: %v", err)
	}
}

// The proposal quote is checked against the pinned frozen advisory bytes
// when the report's advisory source is still readable and digest-matching;
// a paraphrase is a contract violation, not a degraded proposal.
func TestValidate_ImplementationLocusQuoteAgainstPinnedAdvisory(t *testing.T) {
	adv := []byte(`{"id":"GO-TEST-0001","summary":"BSD helper","details":"the implementation calls ` + "`kenv`" + ` with a bare name"}`)
	dir := t.TempDir()
	writeFile(t, dir, "advisory.json", adv)
	sum := sha256.Sum256(adv)
	digest := hex.EncodeToString(sum[:])

	base := func(t *testing.T) *Report {
		r := validReport(t)
		r.Input.Advisory.SourcePath = filepath.Join(dir, "advisory.json")
		r.Input.Advisory.RawSHA256 = digest
		r.Input.Advisory.CanonicalSHA256 = digest
		r.Vulnerability.Summary = "BSD helper"
		r.Vulnerability.Description = "the implementation calls `kenv` with a bare name"
		r.ImplementationLocusProposals = []domain.ImplementationLocusProposal{{
			ID:                  "locus-1",
			Quality:             domain.QualityLLMInferred,
			Module:              "golang.org/x/net",
			Version:             "v0.36.0",
			Package:             "golang.org/x/net/http2",
			File:                "frame.go",
			Function:            "ServeConn",
			Marker:              "kenv",
			BuildExpression:     "",
			AdvisoryEvidenceRef: "sha256:" + digest,
			AdvisoryQuotedSpan:  "calls `kenv`",
		}}
		return r
	}
	if err := Validate(base(t), ""); err != nil {
		t.Fatalf("pinned advisory quote rejected:\n%v", err)
	}
	r := base(t)
	r.ImplementationLocusProposals[0].AdvisoryQuotedSpan = "invokes a command by bare name"
	if err := Validate(r, ""); err == nil {
		t.Fatal("paraphrased quote accepted against pinned advisory bytes")
	}
}
