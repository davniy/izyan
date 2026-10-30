package research

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/vulnerability"
)

// recordedApplicabilityFixture is a sanitized extract of the recorded
// resolver payload; it contains no private paths or ticket identifiers.
//
//go:embed testdata/r6-recorded-applicability.json
var recordedApplicabilityFixture embed.FS

//go:embed testdata/r6-recorded-symbol-unreachable.json
var recordedSymbolUnreachableFixture embed.FS

//go:embed testdata/r6-recorded-release-artifact.json
var recordedReleaseArtifactFixture embed.FS

//go:embed testdata/r6-recorded-docker-contradiction.json
var recordedDockerContradictionFixture embed.FS

const testContentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testAdvisoryDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testPinDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// artifactLane is the minimal lane the decision-artifact builder needs:
// a pinned advisory, a snapshot commit and at least one audit-recorded
// record time so recorded environment premises can be stamped.
func artifactLane() *LaneResult {
	lane := decisionLane(domain.ClaimTrue)
	lane.Advisory.Vuln.ID = "GO-TEST-ART-0001"
	lane.ContentHash = testContentHash
	lane.Snapshot.Commit = "0123456789abcdef0123456789abcdef01234567"
	lane.Advisory.Input.CanonicalSHA256 = testAdvisoryDigest
	lane.Records = []evidencetools.AuditRecord{{
		Tool:       "advisory-load",
		RecordTime: time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC),
	}}
	return lane
}

// artifactCatalogs declares the deployment_perimeter answer set and the
// catalog condition the environment branches premise on.
func artifactCatalogs() *Catalogs {
	return &Catalogs{
		Conditions: []ConditionSpec{{
			ID: "deployment-perimeter", Role: ConditionRoleDeployment,
			Polarity: "POSITIVE", Description: "the declared deployment perimeter posture",
		}},
		Variables: []VariableSpec{{
			ID:            variableDeploymentPerimeter,
			AllowedValues: []string{domain.PerimeterClusterInternal, domain.PerimeterPublic},
		}},
	}
}

func artifactInput(lane *LaneResult) ArtifactInput {
	return ArtifactInput{
		Lane:     lane,
		Policy:   BaselineSafetyPolicy(),
		Catalogs: artifactCatalogs(),
		Pins: ReplayAndPolicyPins{
			PromptDigest: testPinDigest,
			PolicyDigest: testPinDigest,
			CatalogDigests: map[string]string{
				"conditions": testPinDigest, "checks": testPinDigest, "dispositions": testPinDigest,
			},
		},
	}
}

func branchByID(a *DecisionArtifact, id string) *DecisionBranch {
	for i := range a.Branches {
		if a.Branches[i].ID == id {
			return &a.Branches[i]
		}
	}
	return nil
}

func operatorAnswer(variable, value string) EnvironmentAssertion {
	return EnvironmentAssertion{
		Variable: variable, Value: value,
		Principal: "operator@example.com", Timestamp: "2026-10-16T04:00:00Z",
		Source: "operator-assertion", Freshness: "answered at review time",
	}
}

// TestArtifactEnumeratesDeclaredValues: a machine-silent lane yields the
// full declared branch set — one complete branch per enumerated value,
// the non-recorded build variant bound, the mandatory unknown branch —
// and the single declared question while HOLD_UNKNOWN stays proposed.
func TestArtifactEnumeratesDeclaredValues(t *testing.T) {
	a, err := BuildDecisionArtifact(context.Background(), artifactInput(artifactLane()))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if branchByID(&a, "B-PERIMETER-CLUSTER-INTERNAL") == nil ||
		branchByID(&a, "B-PERIMETER-PUBLIC") == nil ||
		branchByID(&a, "B-BUILD-VARIANT-OTHER") == nil ||
		branchByID(&a, "B-UNKNOWN") == nil {
		t.Fatalf("branches=%v", a.Branches)
	}
	trusted := branchByID(&a, "B-PERIMETER-CLUSTER-INTERNAL")
	if trusted.Status != BranchComplete ||
		trusted.ProposedDisposition != DispositionAcceptEnvironmentalMitigation {
		t.Fatalf("trusted branch %+v", trusted)
	}
	public := branchByID(&a, "B-PERIMETER-PUBLIC")
	if public.Status != BranchComplete ||
		public.ProposedDisposition != DispositionKeepOpenForRemediation {
		t.Fatalf("public branch %+v", public)
	}
	other := branchByID(&a, "B-BUILD-VARIANT-OTHER")
	if other.Status != BranchNotDecisionReady ||
		other.Assignments[variableBuildVariant] != buildVariantOther {
		t.Fatalf("other-variant branch %+v", other)
	}
	if a.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("unanswered artifact proposed %q", a.ProposedDisposition)
	}
	if a.HumanAction.Mode != HumanActionAnswerThenAcceptReject ||
		len(a.HumanAction.EnvironmentQuestionRefs) != 1 ||
		a.HumanAction.EnvironmentQuestionRefs[0] != variableDeploymentPerimeter {
		t.Fatalf("human action %+v", a.HumanAction)
	}
	if len(a.DecisionVariables) != 2 {
		t.Fatalf("variables=%v", a.DecisionVariables)
	}
}

// TestArtifactRecordedTrustedPremise: a recorded trusted-peer flag is a
// machine premise — it binds the trusted branch, refutes the public
// branch, and proposes only the contextual mitigation, never a close.
func TestArtifactRecordedTrustedPremise(t *testing.T) {
	lane := artifactLane()
	lane.Snapshot.TrustedPeer = true
	a, err := BuildDecisionArtifact(context.Background(), artifactInput(lane))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.ProposedDisposition != DispositionAcceptEnvironmentalMitigation {
		t.Fatalf("proposed %q", a.ProposedDisposition)
	}
	if len(a.HumanAction.EnvironmentQuestionRefs) != 0 ||
		a.HumanAction.Mode != HumanActionAcceptReject {
		t.Fatalf("recorded premise still asks: %+v", a.HumanAction)
	}
	trusted := branchByID(&a, "B-PERIMETER-CLUSTER-INTERNAL")
	if len(trusted.EnvironmentAssertions) != 1 ||
		trusted.EnvironmentAssertions[0].Source != "trusted-peer-declaration" {
		t.Fatalf("trusted branch premise %+v", trusted.EnvironmentAssertions)
	}
	public := branchByID(&a, "B-PERIMETER-PUBLIC")
	if public.Status != BranchContradicted ||
		public.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("public branch %+v", public)
	}
	for _, br := range a.Branches {
		if isCloseDisposition(br.ProposedDisposition) {
			t.Fatalf("trusted premise produced a close: %+v", br)
		}
	}
}

// TestArtifactUnmappedValueFailsClosed: a catalog value with no
// registered class is enumerated but never interpreted — its branch is
// NOT_DECISION_READY.
func TestArtifactUnmappedValueFailsClosed(t *testing.T) {
	in := artifactInput(artifactLane())
	in.Catalogs.Variables[0].AllowedValues = append(
		in.Catalogs.Variables[0].AllowedValues, "edge")
	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	edge := branchByID(&a, "B-PERIMETER-EDGE")
	if edge == nil || edge.Status != BranchNotDecisionReady ||
		edge.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("unmapped branch %+v", edge)
	}
}

// TestArtifactCloseBranch: a verified module-absent fact establishes
// CLOSE_NOT_AFFECTED through the registered rule — code-grounded
// closure from deterministic facts, with a backing justification.
func TestArtifactCloseBranch(t *testing.T) {
	obs := decisionObservation("affected-resolve", map[string]any{
		"affected_result": domain.AffectedResult{
			ModulePresent:   domain.ClaimFalse,
			CheckedModules:  []string{testModule},
			CheckedPackages: []string{testPackage},
		},
	})
	obs.ID = "OBS-0009"
	obs.ScopeDetails.SnapshotHash = testContentHash
	lane := factLane(t, "affected-resolve", obs, VerifiedFact{
		Kind: "APPLICABILITY", Claim: "TRUE", Coverage: "COMPLETE",
	})
	lane.Snapshot.Commit = "0123456789abcdef0123456789abcdef01234567"
	lane.Advisory = artifactLane().Advisory
	lane.Affected.ModulePresent = domain.ClaimFalse

	in := artifactInput(lane)
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	ruleFacts, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	in.Facts, in.RuleFacts = facts, ruleFacts

	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.ProposedDisposition != DispositionCloseNotAffected {
		t.Fatalf("proposed %q, branches %+v", a.ProposedDisposition, a.Branches)
	}
	closeBr := branchByID(&a, "B-MODULE-ABSENT-FROM-GRAPH")
	if closeBr == nil || closeBr.Status != BranchComplete ||
		len(closeBr.FactRefs) == 0 {
		t.Fatalf("close branch %+v", closeBr)
	}
	backed := false
	for _, j := range a.JustificationGraph {
		if j.Disposition == DispositionCloseNotAffected && len(j.PremiseFactRefs) > 0 {
			backed = true
		}
	}
	if !backed {
		t.Fatal("close without backing justification")
	}
	for _, j := range a.JustificationGraph {
		if j.Disposition == DispositionCloseNotAffected && len(j.PremiseFactRefs) > 0 &&
			!strings.Contains(j.Statement, j.PremiseFactRefs[0]) {
			t.Fatalf("close justification is not derived from cited fact: %q", j.Statement)
		}
	}
	d := decisionForArtifactWithAuthority(&a, nil, lane)
	if d.Verdict != domain.VerdictNotAffected || d.Coverage != "COMPLETE" {
		t.Fatalf("projection = %+v", d)
	}
}

// recordedVersionFalseLane replays the recorded resolver shape where an
// out-of-range version is checked but SelectedModules is empty. The
// canonical module subject must still receive a complete, digest-bound
// version-in-range=false RuleFact. scope is the advisory scope the
// intake bound for the run — nil is the legacy recorded evidence, whose
// payload predates scope binding and therefore carries none.
func recordedVersionFalseLane(t *testing.T, scope *domain.AdvisoryScope) *LaneResult {
	t.Helper()
	raw, err := recordedApplicabilityFixture.ReadFile("testdata/r6-recorded-applicability.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AffectedResult domain.AffectedResult `json:"affected_result"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	obs := decisionObservation("affected-resolve", map[string]any{"affected_result": fixture.AffectedResult})
	obs.ID = "OBS-0011"
	obs.ScopeDetails.SnapshotHash = testContentHash
	lane := factLane(t, "affected-resolve", obs, VerifiedFact{Kind: "APPLICABILITY", Claim: "TRUE", Coverage: "COMPLETE"})
	lane.Advisory = artifactLane().Advisory
	lane.Snapshot.Commit = "0123456789abcdef0123456789abcdef01234567"
	lane.Affected.VersionAffected = domain.ClaimFalse
	lane.Affected.Scope = scope
	// Reproduce the live flow-side shape: the complete affected-resolve
	// observation is discharged from the lane audit, but carries no
	// evidence_refs. Its persisted canonical copy is the only input to the
	// applicability rule-fact derivation.
	lane.Facts = nil
	payload, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	lane.CanonicalByObs = map[string]string{obs.ID: hex.EncodeToString(sum[:])}
	return lane
}

// versionFalseRuleFact returns the recorded per-module out-of-range row
// for subject, or nil when the fact envelope carries none.
func versionFalseRuleFact(rules []evaluator.RuleFact, subject string) *evaluator.RuleFact {
	for i := range rules {
		if rules[i].Subject == subject &&
			rules[i].Predicate == evaluator.PredicateVersionInRange && rules[i].Value == "false" {
			return &rules[i]
		}
	}
	return nil
}

// limitationNaming reports whether one recorded limitation names want.
func limitationNaming(lims []string, want string) bool {
	for _, l := range lims {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

// requireNoGlobalClose asserts the artifact proposes and carries no
// CLOSE_* disposition.
func requireNoGlobalClose(t *testing.T, a *DecisionArtifact) {
	t.Helper()
	if isCloseDisposition(a.ProposedDisposition) {
		t.Fatalf("scope-limited artifact still proposes %q", a.ProposedDisposition)
	}
	for _, br := range a.Branches {
		if isCloseDisposition(br.ProposedDisposition) {
			t.Fatalf("scope-limited artifact carries close branch %s (%s)", br.ID, br.ProposedDisposition)
		}
	}
}

// exactEntryScopeFromIntake binds the scope through the production intake:
// loading the exact GO-/GHSA- advisory identifier is what makes the record's
// declared entries complete for the requested identity. The document is a
// Go-only OSV record with a supported SEMVER range, so the parser retains
// every original affected[] entry and the census reports a full record.
func exactEntryScopeFromIntake(t *testing.T, id string) *domain.AdvisoryScope {
	t.Helper()
	doc := `{
	  "id": "` + id + `",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "` + testModule + `"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]
	  }]
	}`
	path := filepath.Join(t.TempDir(), id+".json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := (vulnerability.FileSource{Path: path, NoAliasEnrichment: true}).Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if v.Scope == nil || !v.Scope.AllowsNegativeClosure() {
		t.Fatalf("intake did not bind a closable exact-entry scope: %+v", v.Scope)
	}
	return v.Scope
}

// Legacy control: the recorded applicability fixture carries no advisory
// scope, so it predates the intake binding. Its version-out-of-range
// fact stays recorded evidence, but it never becomes an artifact-level
// close — no close branch, no close proposal, and the scoped gap is a
// named limitation on the unknown branch.
func TestArtifactRecordedVersionFalseLegacyScopeCannotClose(t *testing.T) {
	lane := recordedVersionFalseLane(t, nil)
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatal(err)
	}
	completed, discharged := dischargedLaneChecks(lane, cats)
	if !containsStr(completed, "affected-resolve") || len(discharged) != 1 || discharged[0].ID != "OBS-0011" {
		t.Fatalf("discharge completed=%v evidence=%+v", completed, discharged)
	}
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	if versionFalseRuleFact(rules, "module:"+testModule) == nil {
		t.Fatalf("legacy per-module version-in-range=false fact was dropped: %+v", rules)
	}
	in := artifactInput(lane)
	in.Facts, in.RuleFacts = facts, rules
	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	requireNoGlobalClose(t, &a)
	unknown := branchByID(&a, "B-UNKNOWN")
	if unknown == nil || !limitationNaming(unknown.Limitations, "scoped applicability gap") {
		t.Fatalf("unknown branch must name the scoped gap: %+v", unknown)
	}
	d := decisionForArtifactWithAuthority(&a, nil, lane)
	if d.Verdict != domain.VerdictInconclusive || !strings.Contains(d.Reason, "scoped applicability gap") {
		t.Fatalf("legacy scope must not project a close: %+v", d)
	}
}

// Exact-entry counterpart: the same recorded negative, with the scope
// bound through the production intake for the exact advisory id, keeps
// today's closing.
func TestArtifactExactEntryVersionFalseClosesNotAffected(t *testing.T) {
	lane := recordedVersionFalseLane(t, exactEntryScopeFromIntake(t, "GO-TEST-ART-0001"))
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	in := artifactInput(lane)
	in.Facts, in.RuleFacts = facts, rules
	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	br := branchByID(&a, "B-VERSION-OUT-OF-RANGE")
	if br == nil || br.Status != BranchComplete || br.Coverage != "COMPLETE" || len(br.FactRefs) == 0 {
		t.Fatalf("version close branch = %+v", br)
	}
	if a.ProposedDisposition != DispositionCloseNotAffected {
		t.Fatalf("proposed disposition = %q", a.ProposedDisposition)
	}
	d := decisionForArtifactWithAuthority(&a, nil, lane)
	if d.Verdict != domain.VerdictNotAffected || d.Coverage != "COMPLETE" {
		t.Fatalf("projection = %+v", d)
	}
}

// Under a non-closing scope the per-module version-out-of-range rule may
// stay ESTABLISHED with its fact refs, but the artifact never turns that
// local fact into a global CLOSE_NOT_AFFECTED / CLOSE_NO_EXPLOIT_PATH: the
// proposal stays HOLD_UNKNOWN, no branch closes, and the local establishment
// is named in the unknown branch so the evidence remains visible. The scope
// refusals cover a CVE request bound to one record, an exact GO- identity
// whose record is only a Go projection (the mixed-record version rule), and
// the missing/inconsistent census shapes.
func TestArtifactPartialScopeCannotProposeGlobalClose(t *testing.T) {
	scopes := extentRefusalScopes("GO-TEST-ART-0001")
	scopes["cve-request"] = partialCVEScope()
	for name, scope := range scopes {
		t.Run(name, func(t *testing.T) {
			lane := recordedVersionFalseLane(t, scope)
			facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
			if err != nil {
				t.Fatal(err)
			}
			rules, err := BuildRuleFacts(FactBuildInput{Lane: lane})
			if err != nil {
				t.Fatal(err)
			}
			local := versionFalseRuleFact(rules, "module:"+testModule)
			if local == nil {
				t.Fatalf("the local version-in-range=false fact must stay recorded: %+v", rules)
			}
			results, close := verifyArtifactClosure(context.Background(), evaluator.DefaultAdapterRegistry(),
				rules, factByIDOf(facts), canonicalSubjects(lane), moduleSubjects(lane), false, false)
			if results["rule.version-out-of-range"].Status != evaluator.RuleEstablished {
				t.Fatalf("the local rule must stay established: %+v", results["rule.version-out-of-range"])
			}
			if len(results["rule.version-out-of-range"].FactRefs) == 0 {
				t.Fatalf("the local rule lost its fact refs: %+v", results["rule.version-out-of-range"])
			}
			if close != nil {
				t.Fatalf("a non-closing scope selected a global close: %+v", close)
			}
			in := artifactInput(lane)
			in.Facts, in.RuleFacts = facts, rules
			a, err := BuildDecisionArtifact(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			requireNoGlobalClose(t, &a)
			if a.ProposedDisposition != DispositionHoldUnknown {
				t.Fatalf("proposed disposition = %q, want HOLD_UNKNOWN", a.ProposedDisposition)
			}
			unknown := branchByID(&a, "B-UNKNOWN")
			if unknown == nil ||
				!limitationNaming(unknown.Limitations, "scoped applicability gap") ||
				!limitationNaming(unknown.Limitations, "version-out-of-range") ||
				!limitationNaming(unknown.Limitations, local.ID) {
				t.Fatalf("unknown branch must name the scoped local establishment: %+v", unknown)
			}
			// The local component fact stays established and visible: only
			// the advisory-wide closure is refused.
			if versionFalseRuleFact(rules, "module:"+testModule) == nil {
				t.Fatalf("the recorded local fact disappeared: %+v", rules)
			}
		})
	}
}

// TestArtifactRecordedDockerContradictionFailsClosed replays a sanitized
// extract of the recorded multi-module run. The applicability payload says
// the declared subjects are present at affected versions; neither the
// module-absent nor version-out-of-range close rule may establish, and the
// artifact must remain conservative.
func TestArtifactRecordedDockerContradictionFailsClosed(t *testing.T) {
	raw, err := recordedDockerContradictionFixture.ReadFile("testdata/r6-recorded-docker-contradiction.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AffectedResult domain.AffectedResult `json:"affected_result"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	lane := artifactLane()
	lane.Advisory.Vuln = &domain.Vulnerability{
		ID:              "GO-TEST-DOCKER-0001",
		AffectedModules: []domain.AffectedModule{{Module: "module-a"}, {Module: "module-b"}, {Module: "module-c"}},
	}
	lane.Advisory.Impls = []AffectedImplementation{
		{ID: "adv-01", Module: "module-a", Binding: BindExact},
		{ID: "adv-02", Module: "module-b", Binding: BindExact},
		{ID: "adv-03", Module: "module-c", Binding: BindExact},
	}
	lane.Affected = fixture.AffectedResult
	var facts []Fact
	var rules []evaluator.RuleFact
	for i, module := range []string{"module-a", "module-b", "module-c"} {
		id := fmt.Sprintf("F-%d", i+1)
		facts = append(facts, Fact{
			ID: id, Proposition: module + " is present at an affected version",
			Subject: "module:" + module, Scope: "recorded dependency graph",
			SourceTool: "affected-resolve", ToolVersion: "fixture",
			ObservationRefs: []string{"obs:OBS-0001"}, DataDigest: testDigest,
			Coverage: FactCoverageComplete, Freshness: "fixture", Status: FactStatusVerified,
		})
		rules = append(rules,
			evaluator.RuleFact{ID: id, Subject: "module:" + module, Predicate: evaluator.PredicateModulePresent, Value: "true", Status: FactStatusVerified, Coverage: FactCoverageComplete, Digest: testDigest},
			evaluator.RuleFact{ID: id, Subject: "module:" + module, Predicate: evaluator.PredicateVersionInRange, Value: "true", Status: FactStatusVerified, Coverage: FactCoverageComplete, Digest: testDigest},
		)
	}
	in := artifactInput(lane)
	in.Facts, in.RuleFacts = facts, rules
	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if isCloseDisposition(a.ProposedDisposition) {
		t.Fatalf("contradicting applicability payload produced close: %s", a.ProposedDisposition)
	}
	for _, id := range []string{"B-MODULE-ABSENT-FROM-GRAPH", "B-VERSION-OUT-OF-RANGE"} {
		if br := branchByID(&a, id); br != nil && isCloseDisposition(br.ProposedDisposition) {
			t.Fatalf("contradicting payload produced close branch %s: %+v", id, br)
		}
	}
	if len(a.Contradictions) == 0 {
		t.Fatal("contradicting applicability facts were not recorded")
	}
}

func TestCloseAuthorityRejectsEmptyPremiseRefs(t *testing.T) {
	res := trustCheckResult(evaluator.RuleResult{
		RuleID: "rule.module-absent-from-graph", Status: evaluator.RuleEstablished,
	}, nil)
	if res.Status != evaluator.RuleUnknown || len(res.FactRefs) != 0 {
		t.Fatalf("empty premise refs must fail closed: %+v", res)
	}
}

// TestArtifactAnswerSelectsAndConflicts: operator answers attach to the
// matching enumerated branch only; an answer that conflicts with a
// recorded machine premise is CONTRADICTED and holds the artifact.
func TestArtifactAnswerSelectsAndConflicts(t *testing.T) {
	a, err := BuildDecisionArtifact(context.Background(), artifactInput(artifactLane()))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Operator answers trusted: the mitigation branch carries the
	// premise and the artifact proposes the contextual mitigation.
	out, err := ApplyEnvironmentAssertions(a, []EnvironmentAssertion{
		operatorAnswer(variableDeploymentPerimeter, domain.PerimeterClusterInternal),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.ProposedDisposition != DispositionAcceptEnvironmentalMitigation {
		t.Fatalf("after trusted answer proposed %q", out.ProposedDisposition)
	}
	trusted := branchByID(&out, "B-PERIMETER-CLUSTER-INTERNAL")
	if len(trusted.EnvironmentAssertions) != 1 ||
		trusted.EnvironmentAssertions[0].Principal != "operator@example.com" {
		t.Fatalf("answer not recorded on trusted branch")
	}
	if len(out.HumanAction.EnvironmentQuestionRefs) != 0 {
		t.Fatalf("answered variable still asked: %+v", out.HumanAction)
	}
	// Input artifact is untouched.
	if len(a.Branches[0].EnvironmentAssertions) != 0 ||
		a.ProposedDisposition != DispositionHoldUnknown {
		t.Fatal("apply mutated the input artifact")
	}

	// Machine-recorded public + operator answer cluster => conflict:
	// the operator branch is CONTRADICTED and the artifact holds.
	lane := artifactLane()
	lane.Snapshot.PerimeterOverride = domain.PerimeterPublic
	a2, err := BuildDecisionArtifact(context.Background(), artifactInput(lane))
	if err != nil {
		t.Fatalf("build public: %v", err)
	}
	out2, err := ApplyEnvironmentAssertions(a2, []EnvironmentAssertion{
		operatorAnswer(variableDeploymentPerimeter, domain.PerimeterClusterInternal),
	})
	if err != nil {
		t.Fatalf("apply conflict: %v", err)
	}
	if out2.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("conflict proposed %q", out2.ProposedDisposition)
	}
	trusted2 := branchByID(&out2, "B-PERIMETER-CLUSTER-INTERNAL")
	if trusted2.Status != BranchContradicted {
		t.Fatalf("conflicted branch status %q", trusted2.Status)
	}
	found := false
	for _, c := range out2.Contradictions {
		if c.Kind == ContradictionEnvironmentVsMachine {
			found = true
		}
	}
	if !found {
		t.Fatal("no environment_vs_machine contradiction recorded")
	}
}

// TestArtifactAnswerRejectsInvalid: only declared variables, declared
// values and fully stamped assertions may be applied — everything else
// is an error, never a silent skip.
func TestArtifactAnswerRejectsInvalid(t *testing.T) {
	a, err := BuildDecisionArtifact(context.Background(), artifactInput(artifactLane()))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, as := range []EnvironmentAssertion{
		operatorAnswer("no_such_variable", domain.PerimeterPublic),
		operatorAnswer(variableDeploymentPerimeter, "invented-value"),
		operatorAnswer(variableBuildVariant, buildVariantOther),
		{Variable: variableDeploymentPerimeter, Value: domain.PerimeterPublic},
	} {
		if _, err := ApplyEnvironmentAssertions(a, []EnvironmentAssertion{as}); err == nil {
			t.Fatalf("accepted invalid answer %+v", as)
		}
	}
}

// TestArtifactForgedRuleResult: caller-supplied results are never
// authoritative — an unregistered id fails closed into the unknown
// branch's limitations and the proposal stays HOLD_UNKNOWN.
func TestArtifactForgedRuleResult(t *testing.T) {
	in := artifactInput(artifactLane())
	in.RuleResults = []evaluator.RuleResult{{
		RuleID: "rule.forged-close", Status: evaluator.RuleEstablished,
	}}
	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("forged result proposed %q", a.ProposedDisposition)
	}
	unk := branchByID(&a, "B-UNKNOWN")
	joined := strings.Join(unk.Limitations, "\n")
	if !strings.Contains(joined, "rule.forged-close") {
		t.Fatalf("overlay missing forged rule: %v", unk.Limitations)
	}
}

// TestArtifactSupersession: a later operator answer to the same
// variable replaces the earlier premise — the new branch carries the
// answer with Supersedes history, the replaced branch loses its
// operator assertion, and the proposal follows the latest answer.
func TestArtifactSupersession(t *testing.T) {
	a, err := BuildDecisionArtifact(context.Background(), artifactInput(artifactLane()))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	out, err := ApplyEnvironmentAssertions(a, []EnvironmentAssertion{
		operatorAnswer(variableDeploymentPerimeter, domain.PerimeterPublic),
		operatorAnswer(variableDeploymentPerimeter, domain.PerimeterClusterInternal),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.ProposedDisposition != DispositionAcceptEnvironmentalMitigation {
		t.Fatalf("superseded proposal %q", out.ProposedDisposition)
	}
	pub := branchByID(&out, "B-PERIMETER-PUBLIC")
	if len(pub.EnvironmentAssertions) != 0 {
		t.Fatalf("superseded answer still binds public branch: %+v", pub.EnvironmentAssertions)
	}
	trusted := branchByID(&out, "B-PERIMETER-CLUSTER-INTERNAL")
	if len(trusted.EnvironmentAssertions) != 1 ||
		len(trusted.EnvironmentAssertions[0].Supersedes) == 0 {
		t.Fatalf("superseding answer missing history: %+v", trusted.EnvironmentAssertions)
	}
}

func TestArtifactRecordedSymbolFixtureCoverage(t *testing.T) {
	raw, err := recordedSymbolUnreachableFixture.ReadFile("testdata/r6-recorded-symbol-unreachable.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Subjects []struct {
			Module  string `json:"module"`
			Package string `json:"package"`
			Symbol  string `json:"symbol"`
		} `json:"subjects"`
		Partial struct {
			CoveredSubjects     []string `json:"covered_subjects"`
			ExpectedDisposition string   `json:"expected_disposition"`
		} `json:"partial"`
		Complete struct {
			CoveredSubjects     []string `json:"covered_subjects"`
			ExpectedDisposition string   `json:"expected_disposition"`
			ExpectedVerdict     string   `json:"expected_verdict"`
			ExpectedCoverage    string   `json:"expected_coverage"`
			ExpectedAutoClose   bool     `json:"expected_auto_close"`
		} `json:"complete"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Subjects) != 2 || len(f.Partial.CoveredSubjects) != 1 || f.Partial.ExpectedDisposition != string(DispositionHoldUnknown) {
		t.Fatalf("partial fixture coverage = %+v", f.Partial)
	}
	if len(f.Complete.CoveredSubjects) != 2 || f.Complete.ExpectedDisposition != string(DispositionCloseNoExploitPath) || f.Complete.ExpectedVerdict != string(domain.VerdictNoExploitPathFound) || f.Complete.ExpectedCoverage != "COMPLETE" || f.Complete.ExpectedAutoClose {
		t.Fatalf("complete fixture contract = %+v", f.Complete)
	}
}

func TestArtifactRecordedReleaseFixtureProvenance(t *testing.T) {
	raw, err := recordedReleaseArtifactFixture.ReadFile("testdata/r6-recorded-release-artifact.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Release struct {
			Status          string `json:"status"`
			SelectedVersion string `json:"selected_version"`
			SelectedTrust   string `json:"selected_trust"`
			ArtifactSHA256  string `json:"artifact_sha256"`
			BinaryMember    string `json:"binary_member"`
			BuildInfoSHA256 string `json:"build_info_sha256"`
			Items           []struct {
				TrustClass      string `json:"trust_class"`
				ArtifactSHA256  string `json:"artifact_sha256"`
				BinaryMember    string `json:"binary_member"`
				BuildInfoSHA256 string `json:"build_info_sha256"`
			} `json:"items"`
		} `json:"release_evidence"`
		Supporting struct {
			Status              string `json:"status"`
			ReasonCode          string `json:"reason_code"`
			DockerVersion       string `json:"docker_version"`
			StdlibApplicability string `json:"stdlib_applicability"`
		} `json:"supporting_only"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Release.Status != "RESOLVED" || f.Release.SelectedVersion != "go1.25.10" || f.Release.SelectedTrust != string(domain.ReleaseTrustAuthoritative) || f.Release.ArtifactSHA256 == "" || f.Release.BinaryMember == "" || f.Release.BuildInfoSHA256 == "" {
		t.Fatalf("release provenance = %+v", f.Release)
	}
	if len(f.Release.Items) != 2 || f.Release.Items[0].TrustClass != string(domain.ReleaseTrustAuthoritative) || f.Release.Items[1].TrustClass != string(domain.ReleaseTrustSupporting) {
		t.Fatalf("release trust items = %+v", f.Release.Items)
	}
	if f.Supporting.Status != "UNKNOWN" || f.Supporting.ReasonCode != domain.ReleaseReasonSupportingOnly || f.Supporting.StdlibApplicability != "UNKNOWN" {
		t.Fatalf("supporting-only stdlib contract = %+v", f.Supporting)
	}
}

// TestArtifactAdvisoryConditionVariable: an advisory whose frozen text
// states exactly one deployment/config-shaped precondition keys the
// environment decision on that recorded statement — the declared
// variable asks the advisory's own question verbatim with derived_from
// provenance, the three-valued branch set replaces the generic
// perimeter enumeration, and the recorded build-variant bound stays.
func TestArtifactAdvisoryConditionVariable(t *testing.T) {
	lane := artifactLane()
	lane.Advisory.Vuln.Description = envTestCondition
	in := artifactInput(lane)
	in.RuleFacts = []evaluator.RuleFact{{
		Subject:   "symbol:example.com/dep/vuln.Sink",
		Predicate: evaluator.PredicateProductSourceUsage, Value: "used",
		Status: "VERIFIED", Digest: strings.Repeat("ab", 32),
	}}

	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	wantQuote := strings.TrimSuffix(envTestCondition, ".")
	if len(a.DecisionVariables) != 2 {
		t.Fatalf("variables=%+v", a.DecisionVariables)
	}
	v := a.DecisionVariables[1]
	if v.ID != variableAdvisoryPrecondition || !v.Required ||
		v.DerivedFrom == nil || v.DerivedFrom.Field != "description" ||
		v.DerivedFrom.Quote != wantQuote {
		t.Fatalf("derived variable %+v", v)
	}
	wantVals := []string{"holds", "does_not_hold", "unknown"}
	if len(v.AllowedValues) != len(wantVals) {
		t.Fatalf("allowed_values=%v", v.AllowedValues)
	}
	for i, w := range wantVals {
		if v.AllowedValues[i] != w {
			t.Fatalf("allowed_values=%v, want %v", v.AllowedValues, wantVals)
		}
	}
	if !strings.Contains(v.Question, wantQuote) ||
		!strings.Contains(v.Question, "attacker-influenced or operator-controlled") {
		t.Fatalf("question does not quote the advisory statement: %q", v.Question)
	}
	if a.DecisionVariables[0].ID != variableBuildVariant {
		t.Fatalf("first variable %+v", a.DecisionVariables[0])
	}
	for _, vv := range a.DecisionVariables {
		if vv.ID == variableDeploymentPerimeter {
			t.Fatal("generic perimeter dimension declared alongside the advisory condition")
		}
	}

	holds := branchByID(&a, "B-ADVISORY-PRECONDITION-HOLDS")
	notHolds := branchByID(&a, "B-ADVISORY-PRECONDITION-DOES-NOT-HOLD")
	unk := branchByID(&a, "B-ADVISORY-PRECONDITION-UNKNOWN")
	if holds == nil || notHolds == nil || unk == nil ||
		branchByID(&a, "B-BUILD-VARIANT-OTHER") == nil ||
		branchByID(&a, "B-UNKNOWN") == nil {
		t.Fatalf("branches=%v", a.Branches)
	}
	if holds.Status != BranchComplete ||
		holds.ProposedDisposition != DispositionKeepOpenForRemediation ||
		holds.Assignments[variableAdvisoryPrecondition] != "holds" {
		t.Fatalf("holds branch %+v", holds)
	}
	if notHolds.Status != BranchComplete ||
		notHolds.ProposedDisposition != DispositionAcceptEnvironmentalMitigation ||
		notHolds.Assignments[variableAdvisoryPrecondition] != "does_not_hold" {
		t.Fatalf("does_not_hold branch %+v", notHolds)
	}
	if unk.Status != BranchNotDecisionReady ||
		unk.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("unknown branch %+v", unk)
	}
	for _, br := range a.Branches {
		if strings.HasPrefix(br.ID, "B-PERIMETER-") {
			t.Fatalf("perimeter branch enumerated under the advisory key: %+v", br)
		}
	}
	if len(holds.Conditions) != 1 || holds.Conditions[0].ID != "advisory-precondition" ||
		holds.Conditions[0].Statement != wantQuote {
		t.Fatalf("branch does not premise on the recorded statement: %+v", holds.Conditions)
	}

	envJust := false
	for _, j := range a.JustificationGraph {
		if j.RuleID == ruleIDEnvironmentalMitigation &&
			j.Disposition == DispositionAcceptEnvironmentalMitigation {
			envJust = true
		}
	}
	if !envJust {
		t.Fatalf("no mitigation justification: %+v", a.JustificationGraph)
	}

	if a.HumanAction.Mode != HumanActionAnswerThenAcceptReject ||
		len(a.HumanAction.EnvironmentQuestionRefs) != 1 ||
		a.HumanAction.EnvironmentQuestionRefs[0] != variableAdvisoryPrecondition {
		t.Fatalf("human action %+v", a.HumanAction)
	}
	if len(a.HumanAction.EnvironmentQuestions) != 1 ||
		!strings.Contains(a.HumanAction.EnvironmentQuestions[0], wantQuote) {
		t.Fatalf("derived environment questions %+v", a.HumanAction.EnvironmentQuestions)
	}
	if a.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("unanswered artifact proposed %q", a.ProposedDisposition)
	}
	for _, br := range a.Branches {
		if isCloseDisposition(br.ProposedDisposition) {
			t.Fatalf("advisory-keyed branch proposes a code-level close: %+v", br)
		}
	}

	// The operator's answer selects the matching branch only, and the
	// artifact proposal follows it — never a close.
	out, err := ApplyEnvironmentAssertions(a, []EnvironmentAssertion{
		operatorAnswer(variableAdvisoryPrecondition, "does_not_hold"),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.ProposedDisposition != DispositionAcceptEnvironmentalMitigation {
		t.Fatalf("does_not_hold answer proposed %q", out.ProposedDisposition)
	}
	out, err = ApplyEnvironmentAssertions(a, []EnvironmentAssertion{
		operatorAnswer(variableAdvisoryPrecondition, "holds"),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.ProposedDisposition != DispositionKeepOpenForRemediation {
		t.Fatalf("holds answer proposed %q", out.ProposedDisposition)
	}
	out, err = ApplyEnvironmentAssertions(a, []EnvironmentAssertion{
		operatorAnswer(variableAdvisoryPrecondition, "unknown"),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("unknown answer proposed %q", out.ProposedDisposition)
	}
}

// TestArtifactNoAdvisoryConditionKeepsPerimeter: an advisory stating no
// environment-shaped precondition keeps the generic dimension —
// byte-identical to the same artifact built over an empty description.
func TestArtifactNoAdvisoryConditionKeepsPerimeter(t *testing.T) {
	base := artifactLane()
	a0, err := BuildDecisionArtifact(context.Background(), artifactInput(base))
	if err != nil {
		t.Fatalf("baseline build: %v", err)
	}
	lane := artifactLane()
	lane.Advisory.Vuln.Description = "The server mishandles reset frames sent by peers."
	a1, err := BuildDecisionArtifact(context.Background(), artifactInput(lane))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b0, err := json.Marshal(a0)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := json.Marshal(a1)
	if err != nil {
		t.Fatal(err)
	}
	if string(b0) != string(b1) {
		t.Fatalf("artifact without an advisory condition diverged:\n%s\n%s", b0, b1)
	}
	if len(a1.DecisionVariables) != 2 ||
		a1.DecisionVariables[1].ID != variableDeploymentPerimeter ||
		a1.DecisionVariables[1].DerivedFrom != nil {
		t.Fatalf("generic dimension changed without a recorded condition: %+v", a1.DecisionVariables)
	}
}

// envTestSecondCondition is a second sentence restating the same
// exploitation precondition — the shape of the real case that derives
// two environment questions.
const envTestSecondCondition = "The server must also run behind a trusted proxy when deployed."

// TestArtifactMultiStatementAdvisoryCondition: when the advisory states
// the precondition across several recorded sentences, the first (in the
// deterministic extraction order) grounds the declared variable and its
// derived_from provenance; the remaining statements stay as additional
// derived questions — nothing is merged or invented.
func TestArtifactMultiStatementAdvisoryCondition(t *testing.T) {
	lane := artifactLane()
	lane.Advisory.Vuln.Description = envTestCondition + " " + envTestSecondCondition
	in := artifactInput(lane)
	in.RuleFacts = []evaluator.RuleFact{{
		Subject:   "symbol:example.com/dep/vuln.Sink",
		Predicate: evaluator.PredicateProductSourceUsage, Value: "used",
		Status: "VERIFIED", Digest: strings.Repeat("ab", 32),
	}}

	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	first := strings.TrimSuffix(envTestCondition, ".")
	second := strings.TrimSuffix(envTestSecondCondition, ".")
	var adv *DecisionVariable
	for i := range a.DecisionVariables {
		if a.DecisionVariables[i].ID == variableAdvisoryPrecondition {
			adv = &a.DecisionVariables[i]
		}
		if a.DecisionVariables[i].ID == variableDeploymentPerimeter {
			t.Fatal("generic perimeter dimension declared alongside the advisory condition")
		}
	}
	if adv == nil {
		t.Fatalf("multi-sentence advisory condition did not derive the variable: %+v", a.DecisionVariables)
	}
	if adv.DerivedFrom == nil || adv.DerivedFrom.Field != "description" ||
		adv.DerivedFrom.Quote != first {
		t.Fatalf("provenance must name the first recorded statement: %+v", adv.DerivedFrom)
	}
	if !strings.Contains(adv.Question, first) ||
		strings.Contains(adv.Question, second) {
		t.Fatalf("variable question must quote only the first statement: %q", adv.Question)
	}
	if branchByID(&a, "B-ADVISORY-PRECONDITION-DOES-NOT-HOLD") == nil ||
		branchByID(&a, "B-PERIMETER-CLUSTER-INTERNAL") != nil {
		t.Fatalf("branch set not keyed on the advisory condition: %v", a.Branches)
	}
	// The remaining recorded statements stay as additional derived
	// questions — advisory-first order, both verbatim.
	if len(a.HumanAction.EnvironmentQuestions) != 2 ||
		!strings.Contains(a.HumanAction.EnvironmentQuestions[0], first) ||
		!strings.Contains(a.HumanAction.EnvironmentQuestions[1], second) {
		t.Fatalf("remaining statements must stay as questions: %+v", a.HumanAction.EnvironmentQuestions)
	}
	if len(a.HumanAction.EnvironmentQuestionRefs) != 1 ||
		a.HumanAction.EnvironmentQuestionRefs[0] != variableAdvisoryPrecondition {
		t.Fatalf("question refs %+v", a.HumanAction.EnvironmentQuestionRefs)
	}
}

// TestArtifactAdvisoryConditionNeverOverridesClose: a code-grounded
// close still decides the finding outright — the derived environment
// variable is never declared when a CLOSE_* already stands.
func TestArtifactAdvisoryConditionNeverOverridesClose(t *testing.T) {
	obs := decisionObservation("affected-resolve", map[string]any{
		"affected_result": domain.AffectedResult{
			ModulePresent:   domain.ClaimFalse,
			CheckedModules:  []string{testModule},
			CheckedPackages: []string{testPackage},
		},
	})
	obs.ID = "OBS-0009"
	obs.ScopeDetails.SnapshotHash = testContentHash
	lane := factLane(t, "affected-resolve", obs, VerifiedFact{
		Kind: "APPLICABILITY", Claim: "TRUE", Coverage: "COMPLETE",
	})
	lane.Snapshot.Commit = "0123456789abcdef0123456789abcdef01234567"
	lane.Advisory = artifactLane().Advisory
	lane.Advisory.Vuln.Description = envTestCondition
	lane.Affected.ModulePresent = domain.ClaimFalse

	in := artifactInput(lane)
	facts, err := BuildDecisionFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	ruleFacts, err := BuildRuleFacts(FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	in.Facts, in.RuleFacts = facts, ruleFacts

	a, err := BuildDecisionArtifact(context.Background(), in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.ProposedDisposition != DispositionCloseNotAffected {
		t.Fatalf("close displaced by the advisory condition: %q", a.ProposedDisposition)
	}
	for _, v := range a.DecisionVariables {
		if v.ID != variableBuildVariant {
			t.Fatalf("closed artifact declared environment variables: %+v", a.DecisionVariables)
		}
	}
	for _, br := range a.Branches {
		if strings.HasPrefix(br.ID, "B-ADVISORY-PRECONDITION-") {
			t.Fatalf("advisory branch emitted alongside a close: %+v", br)
		}
	}
	if len(a.HumanAction.EnvironmentQuestionRefs) != 0 {
		t.Fatalf("closed artifact asks environment questions: %+v", a.HumanAction)
	}
}
