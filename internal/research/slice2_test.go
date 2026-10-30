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

// laneFor builds a lane fixture over a single Go advisory entry with a
// caller-supplied applicability result and extra observations/facts.
func laneFor(t *testing.T, module string, ar domain.AffectedResult,
	obs []*evidencetools.Observation, facts []VerifiedFact) *LaneResult {
	t.Helper()
	base := fakeLane(t)
	// The second fixture observation is the affected-resolve record;
	// keep its Tool in sync so applicability evidence refs resolve (the
	// persistedLane helper does the same).
	base.Observations[1].Tool = "affected-resolve"
	base.Advisory.Impls = []AffectedImplementation{{
		ID: "adv-01", Ecosystem: "Go", Module: module,
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v1.0.0"),
		}},
	}}
	base.Affected = ar
	base.Observations = append(base.Observations, obs...)
	base.Facts = append(base.Facts, facts...)
	return base
}

// factFor mints a verified fact bound to an observation id.
func factFor(obsID, tool, stmt string) VerifiedFact {
	hash := strings.Repeat("ab", 32)
	return VerifiedFact{
		ID: "fact-" + strings.ToLower(obsID), Statement: stmt, Claim: "TRUE",
		Tool: tool, ToolVersion: "test", Command: tool + " {}",
		Scope: "go module graph", Status: "OK", Coverage: "PARTIAL",
		SnapshotContentHash: hash,
		InputDigest:         hash, DataDigest: hash,
		Artifact:   ArtifactRef{Path: "artifacts/" + strings.ToLower(obsID) + ".json", SHA256: hash},
		Provenance: FactProvenance{ObservationID: obsID, Source: "deterministic-lane", GeneratedAt: "2026-01-01T00:00:00Z"},
	}
}

func turnWith(t *testing.T, category, reasoning string, assessment map[string]any) *AgentTurn {
	t.Helper()
	ans := map[string]any{"category": category, "reasoning": reasoning}
	if assessment != nil {
		ans["assessment"] = assessment
	}
	return turnFor(t, ans)
}

// k8s-shaped lane: safe category, module present at the fixed version.
// The resolver reports package/build UNKNOWN here (not FALSE): the probe
// never ran because the resolved version is outside the affected ranges.
func k8sLane(t *testing.T) *LaneResult {
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimFalse,
		PackagePresent:  domain.ClaimUnknown,
		BuildRelevant:   domain.ClaimUnknown,
		ResolvedVersion: "v0.17.0",
		SelectedModule:  "golang.org/x/net",
		CheckedModules:  []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net resolves to v0.17.0 (fixed)"),
	})
	return lane
}

// §3.1: safe category vs fixed covered component → contradiction +
// GAP_DETECTED + CONFLICTED classification; original category preserved.
func TestSlice2_K8sConflictAndScopeGap(t *testing.T) {
	turn := turnWith(t, "code_not_present",
		"golang.org/x/net v0.17.0 is the fixed version; go.etcd.io/etcd may also be vulnerable",
		map[string]any{
			"vulnerability_mechanism": map[string]any{
				"claims": []any{map[string]any{
					"statement": "x/net is fixed; go.etcd.io/etcd and k8s.io/apiserver/pkg need checking",
					"subject":   "golang.org/x/net",
				}},
			},
		})
	lane := k8sLane(t)
	lane.SnapshotRoot = t.TempDir()
	// go.mod names the product's own module; go.sum records etcd +
	// apiserver as resolved deps so they are real scope gaps.
	os.WriteFile(filepath.Join(lane.SnapshotRoot, "go.mod"),
		[]byte("module k8s.io/kubernetes\n\ngo 1.21\n"), 0644)
	os.WriteFile(filepath.Join(lane.SnapshotRoot, "go.sum"),
		[]byte("go.etcd.io/etcd v3.5.9 h1:x\nk8s.io/apiserver v0.28.0 h1:y\n"), 0644)
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "k8s",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	// Original category preserved verbatim.
	if r.AgentOutput.Category == nil || *r.AgentOutput.Category != "code_not_present" {
		t.Fatalf("category rewritten: %+v", r.AgentOutput.Category)
	}
	// category_vs_component_scope contradiction present and resolvable.
	var scope *Contradiction
	for i := range r.Contradictions {
		if r.Contradictions[i].Kind == ContradictionCategoryVsComponentScope {
			scope = &r.Contradictions[i]
		}
	}
	if scope == nil {
		t.Fatal("no category_vs_component_scope contradiction")
	}
	if scope.AgentAssertionRef == nil {
		t.Fatal("scope contradiction lacks agent_assertion_ref")
	}
	if !a2ContainsFactRef(r, scope.DeterministicRefs) {
		t.Fatalf("scope contradiction lacks deterministic fact refs: %v", scope.DeterministicRefs)
	}
	if scope.Resolution != ResolutionScopeLimits {
		t.Fatalf("resolution = %s", scope.Resolution)
	}
	// advisory scope gap for the agent-named unbound components.
	gap := 0
	for _, c := range r.Contradictions {
		if c.Kind == ContradictionAdvisoryScopeGap {
			gap++
		}
	}
	if gap == 0 {
		t.Fatal("no advisory_scope_gap contradiction")
	}
	if r.ProductApplicability.AdvisoryScopeStatus != ScopeGapDetected {
		t.Fatalf("advisory_scope_status = %s", r.ProductApplicability.AdvisoryScopeStatus)
	}
	if r.ProductApplicability.ConclusionScope != ScopeAffectedEntryOnly {
		t.Fatalf("conclusion_scope = %s", r.ProductApplicability.ConclusionScope)
	}
	// classification review: NON_APPLICABLE + CONFLICTED.
	if r.ClassificationReview.Class != ClassNonApplicable {
		t.Fatalf("class = %s", r.ClassificationReview.Class)
	}
	if r.ClassificationReview.Status != StatusConflicted {
		t.Fatalf("classification status = %s", r.ClassificationReview.Status)
	}
	// version_fixed basis established by deterministic refs.
	var vf *ApplicabilityBasis
	for i := range r.ProductApplicability.Basis {
		if r.ProductApplicability.Basis[i].Kind == ABVersionFixed {
			vf = &r.ProductApplicability.Basis[i]
		}
	}
	if vf == nil || vf.Status != ABEstablished || len(vf.VerifiedEvidenceRefs) == 0 {
		t.Fatalf("version_fixed basis = %+v", vf)
	}
	// Scope-gap unknowns are DECISION_CHANGING and name the conclusion.
	dc := 0
	for _, u := range r.Unknowns {
		if u.Priority == UnknownPriorityDecisionChanging {
			dc++
			if u.DecisionChangingFor == nil || *u.DecisionChangingFor == "" {
				t.Fatalf("DECISION_CHANGING unknown without named conclusion: %s", u.ID)
			}
		}
	}
	if dc == 0 {
		t.Fatal("no DECISION_CHANGING unknowns for the scope gap")
	}
	// code_reachability for the fixed entry is NOT_ESTABLISHED.
	if r.ExploitationAxes.CodeReachability.Status != AxisNotEstablished {
		t.Fatalf("code_reachability = %+v", r.ExploitationAxes.CodeReachability)
	}
	if r.ExploitationAxes.ExploitationEstablished.Status != AxisNotEstablished {
		t.Fatal("exploitation_established must be NOT_ESTABLISHED")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("k8s-shaped report invalid:\n%v", err)
	}
}

func a2ContainsFactRef(r *Report, refs []string) bool {
	have := map[string]bool{}
	for _, f := range r.VerifiedFacts {
		have[f.ID] = true
	}
	for _, ref := range refs {
		if have[ref] {
			return true
		}
	}
	return false
}

// §3.2: safe category with no established non-applicability basis →
// classification UNKNOWN, agent's sdk_vs_daemon basis stays PROVISIONAL,
// dependent sections downgraded.
func TestSlice2_TrivyApplicabilityBasis(t *testing.T) {
	turn := turnWith(t, "code_not_reachable",
		"github.com/docker/docker is present but Trivy only uses the Docker client/SDK",
		map[string]any{
			"product_exposure": map[string]any{
				"claims": []any{map[string]any{
					"statement": "Trivy connects to the Docker daemon via the Docker API client solely to load images; it never creates networks",
					"subject":   "github.com/docker/docker",
				}},
			},
		})
	lane := laneFor(t, "github.com/docker/docker", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimUnknown,
		BuildRelevant:   domain.ClaimUnknown,
		SelectedModules: []string{"github.com/docker/docker"},
		CheckedModules:  []string{"github.com/docker/docker"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "github.com/docker/docker@v26.0.1 in affected range"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "trivy",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if *r.AgentOutput.Category != "code_not_reachable" {
		t.Fatal("category rewritten")
	}
	var sdk *ApplicabilityBasis
	for i := range r.ProductApplicability.Basis {
		if r.ProductApplicability.Basis[i].Kind == ABSDKVsDaemon {
			sdk = &r.ProductApplicability.Basis[i]
		}
	}
	if sdk == nil {
		t.Fatal("no sdk_vs_daemon_distinction basis")
	}
	if sdk.Status != ABProvisional || sdk.Source != ABSourceAgent {
		t.Fatalf("sdk basis status/source = %s/%s", sdk.Status, sdk.Source)
	}
	if len(sdk.VerifiedEvidenceRefs) != 0 {
		t.Fatal("provisional agent basis carries verified refs")
	}
	if r.ClassificationReview.Class != ClassNonApplicable ||
		r.ClassificationReview.Status != StatusUnknown {
		t.Fatalf("classification = %s/%s", r.ClassificationReview.Class, r.ClassificationReview.Status)
	}
	// §3.2.3: dependent non-applicability sections downgraded.
	if r.AttackScenario.Status != StatusUnknown || !isUnknownSummary(r.AttackScenario.Summary) {
		t.Fatalf("attack_scenario not downgraded: %s %q", r.AttackScenario.Status, r.AttackScenario.Summary)
	}
	if r.ProductExposure.Status != StatusUnknown || !isUnknownSummary(r.ProductExposure.Summary) {
		t.Fatalf("product_exposure not downgraded: %s %q", r.ProductExposure.Status, r.ProductExposure.Summary)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("trivy-shaped report invalid:\n%v", err)
	}
}

// §3.3: full applicability chain + vulnerable → PACKAGE_BUILD axis,
// attack surface UNKNOWN from failed listener checks, exploitation
// NOT_ESTABLISHED; original assertions preserved.
func TestSlice2_RancherAxes(t *testing.T) {
	lane := laneFor(t, "golang.org/x/crypto", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.43.0",
		SelectedModule:  "golang.org/x/crypto",
		SelectedModules: []string{"golang.org/x/crypto"},
		CheckedModules:  []string{"golang.org/x/crypto"},
		CheckedPackages: []string{"golang.org/x/crypto/ssh/agent"},
	}, []*evidencetools.Observation{{
		ID: "OBS-0050", Tool: "listen-sites", ToolStatus: evidencetools.StatusTimeout,
		Fact: "listener scan timed out", Completeness: evidencetools.CompletenessUnknown,
		Error: "budget exceeded",
	}}, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/crypto/ssh/agent build-relevant at v0.43.0"),
	})
	turn := turnWith(t, "vulnerable",
		"ServeAgent reachable via a temporary Unix socket",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{map[string]any{
					"statement": "attacker connects to the temporary Unix socket and sends a malformed constraint",
					"subject":   "golang.org/x/crypto/ssh/agent",
				}},
			},
		})
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "rancher",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	cr := r.ExploitationAxes.CodeReachability
	if cr.Status != AxisEstablished || cr.Level != LevelPackageBuild {
		t.Fatalf("code_reachability = %s/%s", cr.Status, cr.Level)
	}
	if !strings.Contains(strings.Join(cr.Limitations, " "), "does not establish") {
		t.Fatal("PACKAGE_BUILD axis missing the no-symbol limitation")
	}
	surf := r.ExploitationAxes.AttackSurfaceAvailability
	if surf.Status != AxisUnknown {
		t.Fatalf("attack_surface = %s (listener check timed out)", surf.Status)
	}
	ex := r.ExploitationAxes.ExploitationEstablished
	if ex.Status != AxisNotEstablished || ex.Level != LevelNone || ex.Basis != AxisBasisNone {
		t.Fatalf("exploitation = %+v", ex)
	}
	if !strings.Contains(ex.Statement, "attacker exploitability is not established") {
		t.Fatalf("exploitation statement not literal: %q", ex.Statement)
	}
	// Fully supported vulnerable agent + TRUE chain: APPLICABLE+SUPPORTED.
	if r.ClassificationReview.Class != ClassApplicable ||
		r.ClassificationReview.Status != StatusSupported {
		t.Fatalf("classification = %s/%s, want APPLICABLE/SUPPORTED",
			r.ClassificationReview.Class, r.ClassificationReview.Status)
	}
	if *r.AgentOutput.Category != "vulnerable" {
		t.Fatal("category rewritten")
	}
	// The failed listener check is a decision-changing unknown for the
	// surface axis.
	found := false
	for _, u := range r.Unknowns {
		if u.Priority == UnknownPriorityDecisionChanging && u.DecisionChangingFor != nil &&
			strings.Contains(*u.DecisionChangingFor, "attack_surface_availability") {
			found = true
		}
	}
	if !found {
		t.Fatal("listener-check unknown not prioritized as decision-changing")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("rancher-shaped report invalid:\n%v", err)
	}
}

// §5-A: no observation substitution — every fact's artifact sha256
// matches the bytes actually written, and deterministic claims resolve
// to verified facts, never agent refs.
func TestSlice2_InvariantA_NoObservationSubstitution(t *testing.T) {
	dir := t.TempDir()
	r := validReport(t)
	for _, f := range r.VerifiedFacts {
		payload, _ := json.Marshal(map[string]any{"obs": f.Provenance.ObservationID})
		written := append(payload, '\n')
		sum := sha256.Sum256(written)
		f2 := f
		f2.Artifact.SHA256 = hex.EncodeToString(sum[:])
		f2.Artifact.SizeBytes = int64(len(written))
		writeFile(t, dir, f.Artifact.Path, written)
		for i := range r.VerifiedFacts {
			if r.VerifiedFacts[i].ID == f.ID {
				r.VerifiedFacts[i] = f2
			}
		}
		for i := range r.EvidenceQuality.References {
			if r.EvidenceQuality.References[i].Path == f.Artifact.Path {
				r.EvidenceQuality.References[i].SHA256 = f2.Artifact.SHA256
			}
		}
	}
	if err := Validate(r, dir); err != nil {
		t.Fatalf("fact artifacts rejected: %v", err)
	}
	// Substituted payload (different bytes, same path shape) must fail.
	p, _ := os.ReadFile(filepath.Join(dir, r.VerifiedFacts[0].Artifact.Path))
	p = append(p, ' ')
	writeFile(t, dir, r.VerifiedFacts[0].Artifact.Path, p)
	if err := Validate(r, dir); err == nil {
		t.Fatal("substituted artifact bytes accepted")
	}
}

// §5-B: evidence scopes — deterministic claims/bases/axes reference
// facts in the declared snapshot scope; PACKAGE_BUILD is the highest
// reachability level obtainable from affected-resolve alone.
func TestSlice2_InvariantB_EvidenceScopes(t *testing.T) {
	r := validReport(t)
	for _, f := range r.VerifiedFacts {
		if f.SnapshotContentHash != r.Input.Snapshot.ContentHash {
			t.Fatalf("fact %s snapshot hash %s != input %s",
				f.ID, f.SnapshotContentHash, r.Input.Snapshot.ContentHash)
		}
	}
	cr := r.ExploitationAxes.CodeReachability
	if cr.Status == AxisEstablished && (cr.Level == LevelRuntimeAvailable ||
		cr.Level == LevelDynamicReproduction || cr.Level == LevelSymbol) &&
		cr.Basis == AxisBasisDeterministic {
		t.Fatalf("deterministic basis over-claimed level %s", cr.Level)
	}
	// A deterministic claim referencing an agent ref is rejected.
	r.AttackScenario.Claims = append(r.AttackScenario.Claims, Claim{
		ID: "dc-bad", Statement: "x", Origin: OriginDeterm, State: StateSupported,
		EvidenceRefs: []string{r.VerifiedFacts[0].ID, "agent-src:foo.go:1"},
	})
	if err := Validate(r, ""); err == nil {
		t.Fatal("deterministic claim with agent-src ref accepted")
	}
}

// §5-C is covered by TestSlice2_K8sConflictAndScopeGap (contradiction
// detection present where required).

// §5-D: agent assertions can never become verified facts.
func TestSlice2_InvariantD_NoAgentPromotion(t *testing.T) {
	turn := turnWith(t, "vulnerable", "grpc-go is exploitable",
		map[string]any{
			"vulnerability_mechanism": "google.golang.org/grpc mishandles resets",
		})
	lane := fakeLane(t)
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "x",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	factIDs := map[string]bool{}
	for _, f := range r.VerifiedFacts {
		factIDs[f.ID] = true
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), "agent-src:") {
			t.Fatalf("agent-src inside verified fact %s", f.ID)
		}
		if f.Provenance.Source != "deterministic-lane" {
			t.Fatalf("fact %s provenance = %s", f.ID, f.Provenance.Source)
		}
	}
	for _, as := range r.AgentAssertions {
		if factIDs[as.ID] {
			t.Fatalf("assertion %s also a verified fact", as.ID)
		}
	}
	for _, b := range r.ProductApplicability.Basis {
		for _, ref := range b.VerifiedEvidenceRefs {
			if !factIDs[ref] {
				t.Fatalf("basis %s verified ref %s not a fact", b.Kind, ref)
			}
		}
	}
	for name, ax := range map[string]Axis{
		"code_reachability":           r.ExploitationAxes.CodeReachability,
		"attack_surface_availability": r.ExploitationAxes.AttackSurfaceAvailability,
		"exploitation_established":    r.ExploitationAxes.ExploitationEstablished,
	} {
		if ax.Basis == "agent" {
			t.Fatalf("axis %s basis=agent", name)
		}
	}
}

// Legacy compatibility: a report that omits every extension field is a
// valid Slice-1 report (§1): no slice2-fidelity marker means all the
// extension fields may be absent; persisted /1 reports take the legacy
// validation branch.
func TestSlice2_LegacyReportStillValidates(t *testing.T) {
	r := validReport(t)
	// Strip every extension field (including /3 role/evidence_level) to
	// simulate a Slice-1 document.
	r.ContractExtensions = nil
	r.EvidenceLevel = nil
	r.Contradictions = nil
	r.ExploitationAxes = ExploitationAxes{}
	r.ClassificationReview = ClassificationReview{}
	r.Run.Attempts = nil
	r.ProductApplicability.ConclusionScope = ""
	r.ProductApplicability.AdvisoryScopeStatus = ""
	r.ProductApplicability.Basis = nil
	r.ProductApplicability.EvaluatedEntryIDs = nil
	r.ProductApplicability.AdvisoryEntryStatus = ""
	r.ProductApplicability.VulnerableCodeReachability = ""
	for i := range r.Unknowns {
		r.Unknowns[i].Group = ""
		r.Unknowns[i].Priority = ""
		r.Unknowns[i].DecisionChangingFor = nil
	}
	for i := range r.VerifiedFacts {
		r.VerifiedFacts[i].Materiality = nil
	}
	for i := range r.EvidenceQuality.References {
		r.EvidenceQuality.References[i].Materiality = nil
	}
	for i := range r.ExploitationConditions {
		r.ExploitationConditions[i].Axis = ""
		r.ExploitationConditions[i].Role = ""
	}
	r.AgentOutput.AttemptID = nil
	r.AgentOutput.Extraction = nil
	r.AgentOutput.ResultArtifact = nil
	r.AgentOutput.AnswerArtifact = nil
	if err := Validate(r, ""); err != nil {
		t.Fatalf("legacy report rejected:\n%v", err)
	}
	// And the emitted legacy documents on disk still parse+validate.
	for _, caseDir := range []string{
		"../../eval/agent7/e2e/k8s-44487",
		"../../eval/agent7/e2e/trivy-32473",
		"../../eval/agent7/e2e/rancher-47914",
	} {
		b, err := os.ReadFile(filepath.Join(caseDir, "report.json"))
		if err != nil {
			t.Skipf("legacy report %s unreadable: %v", caseDir, err)
		}
		lr, err := ParseReport(b)
		if err != nil {
			t.Fatalf("legacy %s does not parse: %v", caseDir, err)
		}
		if err := Validate(lr, ""); err != nil {
			t.Fatalf("legacy %s rejected:\n%v", caseDir, err)
		}
	}
}

// §2.7: attempts carry ids/reasons/ordinals and the agent_output links
// to its attempt; artifacts are never shared across attempts.
func TestSlice2_AttemptLedger(t *testing.T) {
	r := validReport(t)
	if len(r.Run.Attempts) < 1 {
		t.Fatal("no attempts recorded")
	}
	det := r.Run.Attempts[0]
	if det.Kind != "deterministic" || det.ReasonCode != AttemptReasonInitial {
		t.Fatalf("det attempt = %+v", det)
	}
	// deterministic-only run still records a NOT_REQUESTED agent row.
	var ag *Attempt
	for i := range r.Run.Attempts {
		if r.Run.Attempts[i].Kind == "agent" {
			ag = &r.Run.Attempts[i]
		}
	}
	if ag == nil || ag.Status != AgentNotRequested {
		t.Fatal("no NOT_REQUESTED agent attempt row")
	}
	// OK agent run links agent_output to the agent attempt.
	r2 := Assemble(AssembleInput{
		Lane: fakeLane(t), RunID: "x2",
		Turn:      turnWith(t, "uncertain", "not enough evidence", nil),
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r2.AgentOutput.AttemptID == nil {
		t.Fatal("agent_output.attempt_id missing")
	}
	ok := false
	for _, at := range r2.Run.Attempts {
		if at.ID == *r2.AgentOutput.AttemptID && at.Kind == "agent" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("attempt_id does not resolve to the agent attempt")
	}
}

// §2.7 strict extraction: multiple conflicting VALID candidates →
// INVALID with AMBIGUOUS_CONFLICTING_CANDIDATES; identical duplicates
// collapse.
func TestSlice2_StrictExtraction(t *testing.T) {
	// conflicting candidates
	ans, ext := strictExtract(`{"category":"vulnerable","reasoning":"a"}
{"category":"false_positive","reasoning":"b"}`)
	if ans != nil || ext.Status != ExtractionInvalid || ext.InvalidReason != InvalidAmbiguous {
		t.Fatalf("conflicting candidates: ans=%v ext=%+v", ans, ext)
	}
	if ext.CandidateCount != 2 {
		t.Fatalf("candidates = %d", ext.CandidateCount)
	}
	// identical semantic duplicates collapse to one selection
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"r"} {"reasoning":"r","category":"vulnerable"}`)
	if ans == nil || ext.Status != ExtractionValid {
		t.Fatalf("duplicate candidates: ans=%v ext=%+v", ans, ext)
	}
	// no candidate
	ans, ext = strictExtract("prose with no json")
	if ans != nil || ext.InvalidReason != InvalidNoCandidate {
		t.Fatalf("no-candidate: ext=%+v", ext)
	}
	// non-candidate JSON is ignored, not a conflict
	ans, ext = strictExtract(`{"note":1} {"category":"uncertain","reasoning":"r"}`)
	if ans == nil || ext.Status != ExtractionValid || ext.CandidateCount != 1 {
		t.Fatalf("non-candidate mixing: ext=%+v", ext)
	}
	// invalid category = invalid candidate, not a second valid one
	ans, ext = strictExtract(`{"category":"nope","reasoning":"r"} {"category":"vulnerable","reasoning":"r"}`)
	if ans == nil || ext.Status != ExtractionValid || ext.SelectedIndex != 1 {
		t.Fatalf("invalid+valid mix: ext=%+v", ext)
	}
	// missing reasoning only → INVALID with MISSING_REASONING
	ans, ext = strictExtract(`{"category":"vulnerable"}`)
	if ans != nil || ext.InvalidReason != InvalidMissingReasoning {
		t.Fatalf("missing reasoning: ext=%+v", ext)
	}
}

// §3.1 refinement: advisory-scope gaps are dependency-bound. A token only
// counts as a component outside the advisory when it names a resolved
// dependency module of the snapshot; the product's own module, file
// names/pairs, and non-dependency tokens produce no contradiction and no
// decision-changing unknown.
func TestSlice2_ScopeGapRequiresDependency(t *testing.T) {
	lane := k8sLane(t)
	lane.SnapshotRoot = t.TempDir()
	os.WriteFile(filepath.Join(lane.SnapshotRoot, "go.mod"),
		[]byte("module k8s.io/kubernetes\n\ngo 1.21\n"), 0644)
	// grpc is a real dependency (not advisory-bound); ssh-auth is not.
	os.WriteFile(filepath.Join(lane.SnapshotRoot, "go.sum"),
		[]byte("google.golang.org/grpc v1.58.0 h1:x\n"), 0644)
	turn := turnWith(t, "code_not_present",
		"golang.org/x/net v0.17.0 is fixed; check go.mod/go.sum, README.md, "+
			"k8s.io/kubernetes, kubernetes.io/ssh-auth and google.golang.org/grpc",
		nil)
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "gap",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	var gaps []string
	for _, c := range r.Contradictions {
		if c.Kind == ContradictionAdvisoryScopeGap {
			gaps = append(gaps, c.Subject)
		}
	}
	if len(gaps) != 1 || gaps[0] != "google.golang.org/grpc" {
		t.Fatalf("scope-gap contradictions = %v (want [google.golang.org/grpc])", gaps)
	}
	var dcForGap []string
	info := 0
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "not a resolved dependency") {
			info++
			if u.Priority != UnknownPriorityAppendix || u.DecisionChangingFor != nil {
				t.Fatalf("informational token unknown got priority %v", u.Priority)
			}
		}
		if u.Priority == UnknownPriorityDecisionChanging &&
			strings.Contains(u.Reason, "advisory scope gap") {
			dcForGap = append(dcForGap, u.Statement)
		}
	}
	if info != 1 {
		// kubernetes.io/ssh-auth is the only non-dependency module token.
		t.Fatalf("informational non-dependency unknowns = %d (want 1)", info)
	}
	if len(dcForGap) != 1 || !strings.Contains(dcForGap[0], "google.golang.org/grpc") {
		t.Fatalf("decision-changing gap unknowns = %v", dcForGap)
	}
	// Product module, file pairs and non-deps never contradict.
	for _, banned := range []string{"k8s.io/kubernetes", "go.mod", "kubernetes.io/ssh-auth", "README"} {
		for _, g := range gaps {
			if strings.Contains(g, banned) {
				t.Fatalf("banned scope-gap subject %q", g)
			}
		}
	}
}

// ---- slice2-fidelity/2 ----

func basisOf(r *Report, kind string) *ApplicabilityBasis {
	for i := range r.ProductApplicability.Basis {
		if r.ProductApplicability.Basis[i].Kind == kind {
			return &r.ProductApplicability.Basis[i]
		}
	}
	return nil
}

func conditionOf(r *Report, subj string) *ExploitationCondition {
	for i := range r.ExploitationConditions {
		if r.ExploitationConditions[i].Subject == subj {
			return &r.ExploitationConditions[i]
		}
	}
	return nil
}

// /2: the evaluated-entry status is bound to the evaluated entries, and a
// fixed entry never asserts absence: package/build conditions stay
// UNKNOWN (probe not run), vulnerable_code_reachability is NOT_EVALUATED,
// and the reachability axis names the evaluation gap — not code absence.
func TestSlice2V2_FixedEntryIsNotAbsence(t *testing.T) {
	lane := k8sLane(t)
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "fx",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryFixed {
		t.Fatalf("advisory_entry_status = %q", pa.AdvisoryEntryStatus)
	}
	if len(pa.EvaluatedEntryIDs) != 1 || pa.EvaluatedEntryIDs[0] != "adv-01" {
		t.Fatalf("evaluated_entry_ids = %v", pa.EvaluatedEntryIDs)
	}
	if pa.VulnerableCodeReachability != VCRNotEvaluated {
		t.Fatalf("vulnerable_code_reachability = %q", pa.VulnerableCodeReachability)
	}
	for _, subj := range []string{subjPackageReach, subjBuildRelevant} {
		c := conditionOf(r, subj)
		if c == nil {
			t.Fatalf("no condition for %q", subj)
		}
		if c.State != StateUnknown {
			t.Fatalf("%q = %s: a fixed evaluated entry must not refute reachability", subj, c.State)
		}
	}
	if c := conditionOf(r, subjModulePresence); c == nil || c.State != StateSupported {
		t.Fatalf("module presence = %+v", c)
	}
	if c := conditionOf(r, subjVersionInUse); c == nil || c.State != StateRefuted {
		t.Fatalf("version in use = %+v", c)
	}
	ax := r.ExploitationAxes.CodeReachability
	if ax.Status != AxisNotEstablished {
		t.Fatalf("code_reachability = %s", ax.Status)
	}
	for _, phrase := range []string{"no advisory-affected code version", "not compiled in", "is absent"} {
		if strings.Contains(ax.Statement, phrase) {
			t.Fatalf("fixed axis reads as code absence: %q", ax.Statement)
		}
	}
	marked := false
	for _, lim := range ax.Limitations {
		if strings.Contains(lim, "not evaluated") {
			marked = true
		}
	}
	if !marked {
		t.Fatalf("axis lacks the not-evaluated marker: %v", ax.Limitations)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("fixed-entry report invalid:\n%v", err)
	}
}

// /2: a module absent from the resolved graph keeps its deterministic
// negative (component_absent) and produces vulnerable_code_reachability
// FALSE with verified refs — presence was evaluated, the fix status was
// not.
func TestSlice2V2_ModuleAbsentKeepsDeterministicNegative(t *testing.T) {
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:  domain.ClaimFalse,
		PackagePresent: domain.ClaimFalse,
		BuildRelevant:  domain.ClaimFalse,
		CheckedModules: []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net absent from module graph"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "abs",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryNotEvaluated {
		t.Fatalf("advisory_entry_status = %q", pa.AdvisoryEntryStatus)
	}
	if len(pa.EvaluatedEntryIDs) != 1 {
		t.Fatalf("evaluated_entry_ids = %v", pa.EvaluatedEntryIDs)
	}
	if pa.VulnerableCodeReachability != VCRFalse {
		t.Fatalf("vulnerable_code_reachability = %q", pa.VulnerableCodeReachability)
	}
	b := basisOf(r, ABComponentAbsent)
	if b == nil || b.Status != ABEstablished || b.Source != ABSourceDeterministic ||
		len(b.VerifiedEvidenceRefs) == 0 || b.CheckScope == "" {
		t.Fatalf("component_absent basis = %+v", b)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("module-absent report invalid:\n%v", err)
	}
}

// /2: the agent's required_configuration ground gets its own PROVISIONAL
// agent basis with a decision-changing unknown, and the classification
// review stays UNCERTAIN/UNKNOWN — never SUPPORTED.
func TestSlice2V2_ConfigurationGround(t *testing.T) {
	turn := turnWith(t, "requires_configuration",
		"the vulnerable path needs the experimental API flag enabled; the flag is not set anywhere in this product",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{map[string]any{
					"statement": "an attacker could reach the handler if the experimental config option were enabled",
					"subject":   "golang.org/x/net",
				}},
			},
		})
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 in affected range"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "cfg",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	b := basisOf(r, ABRequiredConfigAbsent)
	if b == nil {
		t.Fatal("no required_configuration_absent basis")
	}
	if b.Status != ABProvisional || b.Source != ABSourceAgent {
		t.Fatalf("config basis status/source = %s/%s", b.Status, b.Source)
	}
	if len(b.VerifiedEvidenceRefs) != 0 {
		t.Fatal("provisional basis carries verified refs")
	}
	if b.CheckScope == "" {
		t.Fatal("provisional basis lacks check_scope")
	}
	if r.ClassificationReview.Class != ClassUncertain ||
		r.ClassificationReview.Status != StatusUnknown {
		t.Fatalf("classification = %s/%s", r.ClassificationReview.Class, r.ClassificationReview.Status)
	}
	found := false
	for _, u := range r.Unknowns {
		if u.Priority == UnknownPriorityDecisionChanging &&
			strings.Contains(u.Statement, "required configuration") {
			found = true
		}
	}
	if !found {
		t.Fatal("no DECISION_CHANGING unknown for the configuration ground")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("config-ground report invalid:\n%v", err)
	}
}

// /2: the agent's unreachable-code claim gets the
// vulnerable_code_not_reachable basis as PROVISIONAL/agent, and the
// NON_APPLICABLE class stays UNKNOWN — a provisional basis never
// supports the classification.
func TestSlice2V2_ReachabilityGroundProvisional(t *testing.T) {
	turn := turnWith(t, "code_not_reachable",
		"the vulnerable parser path is not reachable from any product entry point",
		map[string]any{
			"product_exposure": map[string]any{
				"claims": []any{map[string]any{
					"statement": "the vulnerable http2 handler is never called by product code",
					"subject":   "golang.org/x/net/http2",
				}},
			},
		})
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 in affected range"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "unr",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	b := basisOf(r, ABVulnCodeNotReachable)
	if b == nil {
		t.Fatal("no vulnerable_code_not_reachable basis")
	}
	if b.Status != ABProvisional || b.Source != ABSourceAgent || len(b.VerifiedEvidenceRefs) != 0 {
		t.Fatalf("reachability basis = %+v", b)
	}
	if b.CheckScope == "" {
		t.Fatal("provisional basis lacks check_scope")
	}
	if r.ClassificationReview.Class != ClassNonApplicable ||
		r.ClassificationReview.Status != StatusUnknown {
		t.Fatalf("classification = %s/%s", r.ClassificationReview.Class, r.ClassificationReview.Status)
	}
	found := false
	for _, u := range r.Unknowns {
		if u.Priority == UnknownPriorityDecisionChanging &&
			strings.Contains(u.Statement, "not-reachable") {
			found = true
		}
	}
	if !found {
		t.Fatal("no DECISION_CHANGING unknown for the reachability ground")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("reachability-ground report invalid:\n%v", err)
	}
}

// /2: a deterministic package-negative (affected version, package absent
// from the import closure) yields vulnerable_code_reachability=FALSE with
// an ESTABLISHED negative basis, and may carry NON_APPLICABLE/SUPPORTED.
func TestSlice2V2_DeterministicPackageNegative(t *testing.T) {
	turn := turnWith(t, "code_not_present", "the package is absent", nil)
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimFalse,
		BuildRelevant:   domain.ClaimFalse,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		CheckedModules:  []string{"golang.org/x/net"},
		CheckedPackages: []string{"golang.org/x/net/http2"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected; http2 not imported"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "neg",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryAffected {
		t.Fatalf("advisory_entry_status = %q", pa.AdvisoryEntryStatus)
	}
	if pa.VulnerableCodeReachability != VCRFalse {
		t.Fatalf("vulnerable_code_reachability = %q", pa.VulnerableCodeReachability)
	}
	b := basisOf(r, ABNotInImportClosure)
	if b == nil || b.Status != ABEstablished || b.Source != ABSourceDeterministic ||
		len(b.VerifiedEvidenceRefs) == 0 {
		t.Fatalf("package-negative basis = %+v", b)
	}
	if r.ClassificationReview.Class != ClassNonApplicable ||
		r.ClassificationReview.Status != StatusSupported {
		t.Fatalf("classification = %s/%s", r.ClassificationReview.Class, r.ClassificationReview.Status)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("package-negative report invalid:\n%v", err)
	}
}

// /2: when every scenario transition is an agent hypothesis, the section
// is UNKNOWN — a call chain alone never upgrades it to PARTIAL. With one
// confirmed deterministic path transition plus an open required
// predicate the section is PARTIAL and names the unestablished path.
func TestSlice2V2_AgentOnlyScenarioIsUnknown(t *testing.T) {
	// Module present + affected version, but the package probe is
	// undecided: only applicability preconditions are confirmed.
	turn := turnWith(t, "vulnerable",
		"a potential call chain exists",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{map[string]any{
					"statement": "attacker reaches the handler through the service listener",
					"subject":   "golang.org/x/net",
				}},
			},
		})
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimUnknown,
		BuildRelevant:   domain.ClaimUnknown,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 in affected range"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "sc",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.AttackScenario.Status != StatusUnknown {
		t.Fatalf("agent-only scenario status = %s", r.AttackScenario.Status)
	}
	if !isUnknownSummary(r.AttackScenario.Summary) {
		t.Fatalf("scenario summary not contract-shaped: %q", r.AttackScenario.Summary)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("agent-only scenario report invalid:\n%v", err)
	}
	// One confirmed path transition (package reachable) + an open
	// required PATH predicate (build relevance undecided) → PARTIAL with
	// the not-established marker; the still-open deployment posture does
	// not create PARTIAL on its own under semantics B.
	lane2 := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimUnknown,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 in affected range, http2 imported"),
	})
	lane2.SnapshotRoot = t.TempDir()
	r2 := Assemble(AssembleInput{Lane: lane2, Turn: turn, RunID: "sc2",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r2.AttackScenario.Status != StatusPartial {
		t.Fatalf("confirmed-transition scenario status = %s", r2.AttackScenario.Status)
	}
	if !strings.Contains(r2.AttackScenario.Summary, "exploit path is not established") {
		t.Fatalf("PARTIAL summary lacks the marker: %q", r2.AttackScenario.Summary)
	}
	if err := Validate(r2, ""); err != nil {
		t.Fatalf("partial scenario report invalid:\n%v", err)
	}
}

// /2 render: the conditions section separates confirmed facts, agent
// hypotheses and unknown conditions; the Russian Резюме heads the report
// and never reads a fixed entry as code absence.
func TestSlice2V2_RenderGroupsAndSummary(t *testing.T) {
	lane := k8sLane(t)
	lane.SnapshotRoot = t.TempDir()
	os.WriteFile(filepath.Join(lane.SnapshotRoot, "go.mod"),
		[]byte("module k8s.io/kubernetes\n\ngo 1.21\n"), 0644)
	turn := turnWith(t, "code_not_present",
		"golang.org/x/net v0.17.0 is the fixed version",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{map[string]any{
					"statement": "a hypothetical attacker could exercise the parser",
					"subject":   "golang.org/x/net",
				}},
			},
		})
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "rnd",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	head := s[:strings.Index(s, "## CVE essence")]
	if !strings.Contains(head, "## Резюме") {
		t.Fatal("Резюме not at the head of the report")
	}
	for _, marker := range []string{
		"Подтверждённые факты", "Гипотезы агента", "Неизвестные условия",
	} {
		if !strings.Contains(s, marker) {
			t.Fatalf("conditions section lacks the %q group", marker)
		}
	}
	if strings.Contains(s, "no advisory-affected code version is compiled in") {
		t.Fatal("render still reads fixed as compiled-in absence")
	}
}

// /2 review fix — finding 1 (positive): a multi-module advisory where
// one evaluated entry resolves fixed and another stays affected must
// aggregate MIXED and label each entry per its own verdict — the
// affected entry's version_affected=TRUE must not mark the fixed one.
func TestSlice2V2_MultiModuleMixedEntryStatus(t *testing.T) {
	lane := laneFor(t, "modules.test/fixed", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v1.2.3",
		SelectedModule:  "modules.test/vuln",
		SelectedModules: []string{"modules.test/vuln"},
		CheckedModules:  []string{"modules.test/fixed", "modules.test/vuln"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve",
			"modules.test/fixed@v1.0.0 outside affected ranges; modules.test/vuln@v1.2.3 affected"),
	})
	lane.Advisory.Impls = []AffectedImplementation{{
		ID: "adv-01", Ecosystem: "Go", Module: "modules.test/fixed",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v0.9.0"),
		}},
	}, {
		ID: "adv-02", Ecosystem: "Go", Module: "modules.test/vuln",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v2.0.0"),
		}},
	}}
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "mix",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryMixed {
		t.Fatalf("advisory_entry_status = %q, want MIXED", pa.AdvisoryEntryStatus)
	}
	if len(pa.EvaluatedEntryIDs) != 2 {
		t.Fatalf("evaluated_entry_ids = %v, want both entries", pa.EvaluatedEntryIDs)
	}
	// Per-entry labels: the fixed entry is fixed, the selected one affected.
	labels := map[string]string{}
	for _, im := range r.AffectedImplementations {
		labels[im.ID] = entryStatus(im, pa)
	}
	if labels["adv-01"] != "fixed" || labels["adv-02"] != "affected" {
		t.Fatalf("per-entry labels = %v, want adv-01=fixed adv-02=affected", labels)
	}
	// The rendered table shows the same split — never "affected" for both.
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	if !strings.Contains(s, "`adv-01` **modules.test/fixed** `Go` — **fixed**") {
		t.Fatalf("fixed entry mislabeled in the table:\n%s", s)
	}
	if !strings.Contains(s, "`adv-02` **modules.test/vuln** `Go` — **affected**") {
		t.Fatalf("affected entry mislabeled in the table:\n%s", s)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("mixed multi-module report invalid:\n%v", err)
	}
}

// /2 review fix — finding 3 (positive): a genuinely absent module with a
// preserved safe category earns NON_APPLICABLE+SUPPORTED on the
// ESTABLISHED deterministic component_absent basis cited in basis_refs.
func TestSlice2V2_ModuleAbsentSupportsNonApplicable(t *testing.T) {
	turn := turnWith(t, "code_not_present", "the affected module is not a dependency", nil)
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimFalse,
		VersionAffected: domain.ClaimFalse,
		PackagePresent:  domain.ClaimFalse,
		BuildRelevant:   domain.ClaimFalse,
		CheckedModules:  []string{"golang.org/x/net"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "golang.org/x/net absent from module graph"),
	})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "abs-sup",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	cr := r.ClassificationReview
	if cr.Class != ClassNonApplicable || cr.Status != StatusSupported {
		t.Fatalf("classification = %s/%s, want NON_APPLICABLE/SUPPORTED",
			cr.Class, cr.Status)
	}
	b := basisOf(r, ABComponentAbsent)
	if b == nil || b.Status != ABEstablished || len(b.VerifiedEvidenceRefs) == 0 {
		t.Fatalf("component_absent basis = %+v", b)
	}
	cited := false
	for _, ref := range cr.BasisRefs {
		for _, vr := range b.VerifiedEvidenceRefs {
			if ref == vr {
				cited = true
			}
		}
	}
	if !cited {
		t.Fatalf("basis_refs %v do not cite the component_absent verified refs %v",
			cr.BasisRefs, b.VerifiedEvidenceRefs)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("supported module-absent report invalid:\n%v", err)
	}
}

// /2 review fix — finding 4 (generator side): a verified dynamic fact
// (reproduction) raises exploitation_established to ESTABLISHED and
// attack_scenario to SUPPORTED; a dynamic observation that failed (or
// never became a verified fact) can never carry ESTABLISHED.
func TestSlice2V2_DynamicEvidenceEstablishesExploitation(t *testing.T) {
	ar := domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	}
	// Positive: an OK reproduction observation promoted to a verified fact.
	lane := laneFor(t, "golang.org/x/net", ar,
		[]*evidencetools.Observation{{
			ID: "OBS-0060", Tool: "reproduction", ToolStatus: evidencetools.StatusOK,
			Fact:         "malformed frame reproduced the panic under the recorded build context",
			Scope:        "dynamic reproduction run",
			Completeness: evidencetools.CompletenessComplete,
		}},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected and linked"),
			factFor("OBS-0060", "reproduction", "malformed frame reproduced the panic"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turnWith(t, "vulnerable",
		"the malformed frame path is exploitable", nil), RunID: "dyn",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	ex := r.ExploitationAxes.ExploitationEstablished
	if ex.Status != AxisEstablished || ex.Basis != AxisBasisDynamic ||
		ex.Level != LevelDynamicReproduction {
		t.Fatalf("exploitation_established = %+v, want ESTABLISHED/dynamic", ex)
	}
	if len(ex.EvidenceRefs) == 0 {
		t.Fatal("ESTABLISHED axis carries no evidence refs")
	}
	if r.AttackScenario.Status != StatusSupported {
		t.Fatalf("attack_scenario = %s, want SUPPORTED", r.AttackScenario.Status)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("dynamic-evidence report invalid:\n%v", err)
	}
	// Negative generator side: a failed reproduction check is a limitation,
	// never ESTABLISHED (the old code would have raised the axis on its
	// obs ref alone).
	lane = laneFor(t, "golang.org/x/net", ar,
		[]*evidencetools.Observation{{
			ID: "OBS-0061", Tool: "reproduction", ToolStatus: evidencetools.StatusError,
			Fact:         "reproduction harness failed",
			Scope:        "dynamic reproduction run",
			Completeness: evidencetools.CompletenessUnknown,
			Error:        "harness exited non-zero",
		}},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected and linked"),
		})
	lane.SnapshotRoot = t.TempDir()
	r = Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "dyn-fail",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	ex = r.ExploitationAxes.ExploitationEstablished
	if ex.Status != AxisNotEstablished || ex.Basis != AxisBasisNone {
		t.Fatalf("failed dynamic check raised the axis: %+v", ex)
	}
	if r.AttackScenario.Status == StatusSupported {
		t.Fatal("attack_scenario SUPPORTED without established exploitation")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("failed-dynamic report invalid:\n%v", err)
	}
}

// /1↔/2 dispatch: both markers advertised is an error; a /1-marked report
// validates under the legacy rules.
func TestSlice2V2_ExtensionDispatch(t *testing.T) {
	r := validReport(t)
	r.ContractExtensions = []string{Slice2ExtensionV1, Slice2Extension}
	if err := Validate(r, ""); err == nil {
		t.Fatal("report advertising both slice2 markers accepted")
	}
	r2 := validReport(t)
	r2.ContractExtensions = []string{Slice2ExtensionV1}
	if err := Validate(r2, ""); err != nil {
		t.Fatalf("/1-advertised report rejected by the legacy branch:\n%v", err)
	}
}

// Payload cap: an oversized observation payload is truncated on persist,
// flagged with the full digest + size and a cap limitation, COMPLETE
// downgrades to PARTIAL, and data_digest keeps matching the stored
// (truncated) bytes. A small payload is untouched.
func TestPersist_TruncatesOversizedPayload(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", maxObservationPayloadBytes*2)
	bigObs := &evidencetools.Observation{
		ID: "OBS-0001", Tool: "listen-sites", Fact: "f", Scope: "s",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		Data:         map[string]any{"sites": big},
	}
	smallObs := &evidencetools.Observation{
		ID: "OBS-0002", Tool: "find_symbol", Fact: "f2", Scope: "s",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		Data:         map[string]any{"small": true},
	}
	full, _ := json.Marshal(bigObs.Data)
	fullSum := sha256.Sum256(full)
	lane := &LaneResult{
		SnapshotRoot: dir, ContentHash: strings.Repeat("ab", 32),
		Observations:   []*evidencetools.Observation{bigObs, smallObs},
		CanonicalByObs: map[string]string{},
		ArtifactByObs:  map[string]ArtifactRef{},
	}
	lane.Records = []evidencetools.AuditRecord{
		{Tool: "listen-sites", Args: json.RawMessage(`{}`), Observation: bigObs},
		{Tool: "find_symbol", Args: json.RawMessage(`{}`), Observation: smallObs},
	}
	if err := lane.persist(dir); err != nil {
		t.Fatal(err)
	}
	// Oversized: truncated marker + full pins + limitation + downgrade.
	m, ok := bigObs.Data.(map[string]any)
	if !ok || m["truncated_payload"] != true {
		t.Fatalf("payload not marked truncated: %T %v", bigObs.Data, m)
	}
	if m["full_payload_sha256"] != hex.EncodeToString(fullSum[:]) {
		t.Fatalf("full_payload_sha256 mismatch: %v", m["full_payload_sha256"])
	}
	if m["full_payload_size_bytes"] != len(full) {
		t.Fatalf("full_payload_size_bytes = %v want %d", m["full_payload_size_bytes"], len(full))
	}
	if len(m["stored_payload_json"].(string)) > maxObservationPayloadBytes {
		t.Fatal("stored payload exceeds cap")
	}
	if bigObs.ScopeDetails == nil || bigObs.ScopeDetails.Limits == nil ||
		!bigObs.ScopeDetails.Limits.OutputTruncated ||
		bigObs.ScopeDetails.Limits.FullPayloadSHA256 != hex.EncodeToString(fullSum[:]) ||
		bigObs.ScopeDetails.Limits.FullPayloadSizeBytes != int64(len(full)) {
		t.Fatalf("scope limits missing truncation pins: %+v", bigObs.ScopeDetails)
	}
	if bigObs.Completeness != evidencetools.CompletenessPartial {
		t.Fatalf("completeness = %s want PARTIAL", bigObs.Completeness)
	}
	foundLim := false
	for _, l := range bigObs.Limitations {
		if strings.Contains(l, "truncated") && strings.Contains(l, "262144") {
			foundLim = true
		}
	}
	if !foundLim {
		t.Fatalf("no cap limitation: %v", bigObs.Limitations)
	}
	// Digest honesty: data_digest digests the stored (truncated) bytes.
	payload, _ := json.MarshalIndent(bigObs, "", "  ")
	csum := sha256.Sum256(payload)
	if lane.CanonicalByObs["OBS-0001"] != hex.EncodeToString(csum[:]) {
		t.Fatal("canonical digest no longer matches stored payload")
	}
	artBytes, err := os.ReadFile(filepath.Join(dir, "artifacts", "obs-0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	asum := sha256.Sum256(artBytes)
	if lane.ArtifactByObs["OBS-0001"].SHA256 != hex.EncodeToString(asum[:]) {
		t.Fatal("artifact sha mismatch")
	}
	// Small payload untouched, COMPLETE preserved.
	if sm, ok := smallObs.Data.(map[string]any); !ok || sm["small"] != true {
		t.Fatalf("small payload mutated: %v", smallObs.Data)
	}
	if smallObs.Completeness != evidencetools.CompletenessComplete {
		t.Fatal("small observation downgraded")
	}
	// observations.jsonl bounded: no line may embed the megabyte payload.
	raw, err := os.ReadFile(filepath.Join(dir, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxObservationPayloadBytes*2 {
		t.Fatalf("observations.jsonl still unbounded: %d bytes", len(raw))
	}
}

// /2 review fix — finding 1-C (positive): a multi-module advisory where
// the confirmed entry's version resolves affected and a second present
// module stays version-undecidable (unlinked pending) yields
// adv-01=affected, adv-02=unknown and aggregate MIXED — the pending
// entry is never read as fixed merely because it is absent from
// selected_modules.
func TestSlice2V2_PendingUnlinkedModuleMixedEntryStatus(t *testing.T) {
	lane := laneFor(t, "modules.test/vuln", domain.AffectedResult{
		ModulePresent:     domain.ClaimTrue,
		VersionAffected:   domain.ClaimTrue,
		PackagePresent:    domain.ClaimFalse,
		BuildRelevant:     domain.ClaimFalse,
		ResolvedVersion:   "v1.2.3",
		SelectedModule:    "modules.test/vuln",
		CheckedModules:    []string{"modules.test/pending", "modules.test/vuln"},
		UnresolvedModules: []string{"modules.test/pending"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve",
			"modules.test/vuln@v1.2.3 affected; modules.test/pending version undecidable, package unlinked"),
	})
	lane.Advisory.Impls = []AffectedImplementation{{
		ID: "adv-01", Ecosystem: "Go", Module: "modules.test/vuln",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v2.0.0"),
		}},
	}, {
		ID: "adv-02", Ecosystem: "Go", Module: "modules.test/pending",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v3.0.0"),
		}},
	}}
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "mix-pend",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryMixed {
		t.Fatalf("advisory_entry_status = %q, want MIXED", pa.AdvisoryEntryStatus)
	}
	if len(pa.EvaluatedEntryIDs) != 2 {
		t.Fatalf("evaluated_entry_ids = %v, want both entries", pa.EvaluatedEntryIDs)
	}
	labels := map[string]string{}
	for _, im := range r.AffectedImplementations {
		labels[im.ID] = entryStatus(im, pa)
	}
	if labels["adv-01"] != "affected" || labels["adv-02"] != "unknown" {
		t.Fatalf("per-entry labels = %v, want adv-01=affected adv-02=unknown", labels)
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	if !strings.Contains(s, "`adv-02` **modules.test/pending** `Go` — **unknown**") {
		t.Fatalf("pending entry mislabeled in the table:\n%s", s)
	}
	// The undecidable version surfaces as an explicit unknown.
	found := false
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "modules.test/pending") {
			found = true
		}
	}
	if !found {
		t.Fatal("pending module version unknown not recorded")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("mixed pending report invalid:\n%v", err)
	}
}

// /2 review fix — finding 1-B (positive): an advisory whose entries are
// all non-Go has an empty evaluated set, so the only consistent
// aggregate is NOT_EVALUATED and evaluated_entry_ids may be omitted.
func TestSlice2V2_NonGoAdvisoryEntryStatusNotEvaluated(t *testing.T) {
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimUnknown,
		VersionAffected: domain.ClaimUnknown,
		PackagePresent:  domain.ClaimUnknown,
		BuildRelevant:   domain.ClaimUnknown,
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve", "no Go modules named by the advisory"),
	})
	lane.Advisory.Impls = []AffectedImplementation{{
		ID: "adv-01", Ecosystem: "npm", Module: "lodash",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
	}}
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "nongo",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryNotEvaluated {
		t.Fatalf("advisory_entry_status = %q, want NOT_EVALUATED", pa.AdvisoryEntryStatus)
	}
	if len(pa.EvaluatedEntryIDs) != 0 {
		t.Fatalf("evaluated_entry_ids = %v, want empty", pa.EvaluatedEntryIDs)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("non-Go advisory report invalid:\n%v", err)
	}
	// The marshalled report omits evaluated_entry_ids; re-parsing must
	// still satisfy the /2 aggregate rules (absent list = empty set).
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "evaluated_entry_ids") {
		t.Fatal("empty evaluated_entry_ids must stay omitted on the wire")
	}
	r2, err := ParseReport(b)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ProductApplicability.AdvisoryEntryStatus != EntryNotEvaluated {
		t.Fatalf("round-trip aggregate = %q", r2.ProductApplicability.AdvisoryEntryStatus)
	}
	if err := Validate(r2, ""); err != nil {
		t.Fatalf("round-tripped non-Go report invalid:\n%v", err)
	}
}

// Two advisory entries can both be version-affected while only one of them
// has its package linked into the product. Package absence is a reachability
// result and must not be read back as a version result: the unlinked entry
// stays "affected" (never "fixed"), and the aggregate stays AFFECTED.
func TestSlice2V2_VersionAffectedSiblingStaysAffected(t *testing.T) {
	lane := laneFor(t, "modules.test/vuln", domain.AffectedResult{
		ModulePresent:          domain.ClaimTrue,
		VersionAffected:        domain.ClaimTrue,
		PackagePresent:         domain.ClaimTrue,
		BuildRelevant:          domain.ClaimTrue,
		ResolvedVersion:        "v1.2.3",
		SelectedModule:         "modules.test/sibling",
		SelectedModules:        []string{"modules.test/sibling"},
		VersionAffectedModules: []string{"modules.test/vuln", "modules.test/sibling"},
		CheckedModules:         []string{"modules.test/sibling", "modules.test/vuln"},
	}, nil, []VerifiedFact{
		factFor("OBS-0002", "affected-resolve",
			"modules.test/vuln@v1.2.3 and modules.test/sibling@v1.4.0 are inside their entries' affected ranges"),
	})
	lane.Advisory.Impls = []AffectedImplementation{{
		ID: "adv-01", Ecosystem: "Go", Module: "modules.test/vuln",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v2.0.0"),
		}},
	}, {
		ID: "adv-02", Ecosystem: "Go", Module: "modules.test/sibling",
		Binding:   BindExact,
		SourceRef: "adv:GO-TEST-0001",
		AffectedVersions: []VersionBounds{{
			Introduced: strPtr("0"), Fixed: strPtr("v3.0.0"),
		}},
	}}
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "va-sibling",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	pa := r.ProductApplicability
	if pa.AdvisoryEntryStatus != EntryAffected {
		t.Fatalf("advisory_entry_status = %q, want AFFECTED", pa.AdvisoryEntryStatus)
	}
	for _, im := range r.AffectedImplementations {
		if got := entryStatus(im, pa); got != "affected" {
			t.Fatalf("entry %s status = %q, want affected (package linkage is not a version fact)", im.ID, got)
		}
	}
}

// §2.7 bounded recovery: strict candidates still win, recovery only runs
// on zero strict candidates, brace completion is capped at two missing
// closers, member salvage requires complete depth-1 category+reasoning,
// and conflicting/unterminated damage stays INVALID.
func TestSlice2_ExtractorRecovery(t *testing.T) {
	// Recovery never fires while the strict pass retained candidates.
	ans, ext := strictExtract(`{"category":"vulnerable","reasoning":"a"}
{"category":"false_positive","reasoning":"b"}`)
	if ans != nil || ext.InvalidReason != InvalidAmbiguous || ext.Recovery != "" {
		t.Fatalf("ambiguous strict result must stay INVALID with no recovery: %+v", ext)
	}
	// A strictly-valid object plus a dangling copy: strict candidates
	// exist, so the unclosed region is ignored rather than recovered.
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"a"} {"category":"vulnerable","re`)
	if ans == nil || ext.Recovery != "" || ext.CandidateCount != 1 {
		t.Fatalf("strict candidate must suppress recovery: ans=%v ext=%+v", ans, ext)
	}

	// BRACE_COMPLETION: one missing closer at EOF.
	ans, ext = strictExtract(`note: {"category":"vulnerable","reasoning":"within affected range"`)
	if ans == nil || ext.Recovery != RecoveryBraceCompletion {
		t.Fatalf("one unclosed brace: ans=%v ext=%+v", ans, ext)
	}
	// Fence-wrapped answer, two missing closers — the dangling member is
	// not assessment, so completion still applies and the intact
	// assessment is preserved verbatim.
	ans, ext = strictExtract("```json\n{\"category\":\"code_not_reachable\",\"reasoning\":\"entrypoint never invoked\",\"assessment\":{\"k\":1},\"extra\":{\"x\":2")
	if ans == nil || ext.Recovery != RecoveryBraceCompletion || ans.Category != "code_not_reachable" {
		t.Fatalf("two unclosed braces: ans=%v ext=%+v", ans, ext)
	}
	if string(ans.Assessment) != `{"k":1}` {
		t.Fatalf("intact assessment not preserved: %s", ans.Assessment)
	}
	// A truncated assessment is never brace-repaired: the unmatched
	// braces sit inside assessment, completion is refused, and member
	// salvage drops the assessment because its original bytes do not
	// parse on their own.
	ans, ext = strictExtract("```json\n{\"category\":\"code_not_reachable\",\"reasoning\":\"entrypoint never invoked\",\"assessment\":{\"k\":1")
	if ans == nil || ext.Recovery != RecoveryMemberSalvage || ans.Category != "code_not_reachable" {
		t.Fatalf("truncated assessment: ans=%v ext=%+v", ans, ext)
	}
	if len(ans.Assessment) != 0 {
		t.Fatalf("truncated assessment must be dropped, not completed: %s", ans.Assessment)
	}
	// A parseable value prefix followed by stray bytes is a damaged
	// member, not an intact one: assessment is dropped rather than kept
	// on its decodable prefix, and a tainted member is never revived by
	// a later repetition.
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"kept reasoning","assessment":{"k":1}trailing-junk`)
	if ans == nil || ext.Recovery != RecoveryMemberSalvage {
		t.Fatalf("prefix+junk assessment: ans=%v ext=%+v", ans, ext)
	}
	if len(ans.Assessment) != 0 {
		t.Fatalf("assessment with trailing garbage kept: %s", ans.Assessment)
	}
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"kept reasoning","assessment":{"k":1} garbage }`)
	if ans == nil || ext.Recovery != RecoveryMemberSalvage || len(ans.Assessment) != 0 {
		t.Fatalf("closed region, junk after assessment: ans=%v ext=%+v assess=%s", ans, ext, ans.Assessment)
	}
	ans, ext = strictExtract(`{"category":"vulnerable"junk,"reasoning":"real reasoning","category":"vulnerable"}`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("tainted category then clean repeat must stay INVALID: ans=%v ext=%+v", ans, ext)
	}
	// A deeply-truncated object exceeds the brace bound; the intact
	// depth-1 members are still salvageable (the bound limits brace
	// completion, not member salvage).
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"r","assessment":{"a":{"b":{"c":1`)
	if ans == nil || ext.Recovery != RecoveryMemberSalvage {
		t.Fatalf("over-bound but salvageable: ans=%v ext=%+v", ans, ext)
	}
	// ...but when nothing depth-1 is salvageable, an over-bound object
	// stays INVALID rather than being repaired.
	ans, ext = strictExtract(`{"a":{"b":{"category":"vulnerable","reasoning":"r"`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("over-bound unsalvageable must stay INVALID: ans=%v ext=%+v", ans, ext)
	}
	// EOF inside a quoted string is never brace-completed, and the
	// truncated member value is never salvaged by prefix.
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"cut off mid-sent`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("unterminated reasoning must stay INVALID: ans=%v ext=%+v", ans, ext)
	}
	// A completed object that fails schema stays INVALID (recovery
	// re-runs the strict rules instead of trusting the repair).
	ans, ext = strictExtract(`{"category":"nope","reasoning":"r"`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("schema-invalid completion must not pass: ans=%v ext=%+v", ans, ext)
	}

	// MEMBER_SALVAGE: interior corruption the strict pass rejects, but
	// depth-1 category/reasoning are intact (invalid escape inside
	// assessment, stray closer at EOF — the saved C19 shape).
	broken := `{"category":"vulnerable","reasoning":"affected module vendored at v1.10.0","assessment":{"refs":"bad \x escape"}}}`
	ans, ext = strictExtract(broken)
	if ans == nil || ext.Recovery != RecoveryMemberSalvage || ans.Category != "vulnerable" {
		t.Fatalf("member salvage: ans=%v ext=%+v", ans, ext)
	}
	if len(ans.Assessment) != 0 {
		t.Fatal("unparseable assessment must be dropped, not repaired")
	}
	// Salvageable assessment survives verbatim.
	broken = `{"category":"uncertain","reasoning":"needs runtime check","assessment":{"refs":["a"]},"tail":`
	ans, ext = strictExtract(broken)
	if ans == nil || ext.Recovery != RecoveryMemberSalvage {
		t.Fatalf("salvage with assessment: ans=%v ext=%+v", ans, ext)
	}
	if string(ans.Assessment) != `{"refs":["a"]}` {
		t.Fatalf("assessment not preserved verbatim: %s", ans.Assessment)
	}
	// Salvage refuses ambiguity: two top-level regions with divergent
	// depth-1 pairs (each individually unparseable, so strict sees none).
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"a","x": {bad}} {"category":"false_positive","reasoning":"b","y":`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("divergent salvaged pairs must stay INVALID: ans=%v ext=%+v", ans, ext)
	}
	// Two regions agreeing on one pair collapse to a single recovery.
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":"same conclusion","a": {bad}} {"category":"vulnerable","reasoning":"same conclusion","b":`)
	if ans == nil || ext.Recovery != RecoveryMemberSalvage {
		t.Fatalf("identical salvaged pairs must collapse: ans=%v ext=%+v", ans, ext)
	}
	// No depth-1 reasoning (it lives inside the truncated assessment,
	// or the member value never decodes) → nothing to salvage.
	ans, ext = strictExtract(`{"category":"vulnerable","assessment":{"reasoning":"nested only"`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("nested-only reasoning must stay INVALID: ans=%v ext=%+v", ans, ext)
	}
	ans, ext = strictExtract(`{"category":"vulnerable","reasoning":`)
	if ans != nil || ext.Recovery != "" {
		t.Fatalf("empty reasoning slot must stay INVALID: ans=%v ext=%+v", ans, ext)
	}
	// Prose with no object at all: recovery has nothing to bind to.
	ans, ext = strictExtract("plain prose, still no answer object")
	if ans != nil || ext.InvalidReason != InvalidNoCandidate || ext.Recovery != "" {
		t.Fatalf("prose must stay NO_CANDIDATE: ext=%+v", ext)
	}

	// Saved answers from the recorded corrupt-answer corpus: the three
	// recoverable ones come back VALID with a recovery marker, the two
	// unrecoverable ones stay INVALID. The corpus lives outside the
	// module tree and the saved-case directory names are private, so
	// the sub-checks run only when IZYAN_RECOVERY_CASES points to a
	// JSON manifest mapping the pinned case labels to corpus dir names;
	// unset, missing or unreadable manifests skip.
	savedRoot := filepath.Join("..", "..", "..", "vuln-analyzer", "tmp", "exploitable", "runs")
	manifest := os.Getenv("IZYAN_RECOVERY_CASES")
	if manifest == "" {
		t.Skip("IZYAN_RECOVERY_CASES unset: saved-answer corpus cases unavailable")
	}
	mb, err := os.ReadFile(manifest)
	if err != nil {
		t.Skipf("saved-answer manifest unavailable: %v", err)
	}
	var caseDirs map[string]string
	if err := json.Unmarshal(mb, &caseDirs); err != nil {
		t.Fatalf("saved-answer manifest %s is not a label->dir JSON object: %v", manifest, err)
	}
	if _, err := os.Stat(savedRoot); err != nil {
		t.Skipf("saved-answer corpus unavailable: %v", err)
	}
	for _, tc := range []struct {
		label    string
		wantOK   bool
		recovery string
	}{
		{"C08", true, RecoveryMemberSalvage}, // object spliced into unclosed array
		{"C19", true, RecoveryMemberSalvage}, // invalid escape + stray closer
		{"C25", true, ""},                    // either marker, must be VALID
		{"C26", false, ""},                   // reasoning unterminated at EOF
		{"C27", false, ""},                   // no object at all
	} {
		dir, ok := caseDirs[tc.label]
		if !ok {
			t.Fatalf("%s: case dir missing from manifest %s", tc.label, manifest)
		}
		p := filepath.Join(savedRoot, dir, "agent", "agent", "attempt-0002", "answer.txt")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: saved answer unreadable: %v", tc.label, err)
		}
		ans, ext := strictExtract(string(b))
		if !tc.wantOK {
			if ans != nil || ext.Status != ExtractionInvalid {
				t.Fatalf("%s must stay INVALID: ans=%v ext=%+v", tc.label, ans, ext)
			}
			if ext.Recovery != "" {
				t.Fatalf("%s: INVALID record carries a recovery marker", tc.label)
			}
			continue
		}
		if ans == nil || ext.Status != ExtractionValid {
			t.Fatalf("%s must recover to VALID: ans=%v ext=%+v", tc.label, ans, ext)
		}
		if ext.Recovery != RecoveryBraceCompletion && ext.Recovery != RecoveryMemberSalvage {
			t.Fatalf("%s: missing recovery marker: %+v", tc.label, ext)
		}
		if tc.recovery != "" && ext.Recovery != tc.recovery {
			t.Fatalf("%s: recovery=%s want %s", tc.label, ext.Recovery, tc.recovery)
		}
		if ans.Category == "" || strings.TrimSpace(ans.Reasoning) == "" {
			t.Fatalf("%s: recovered answer incomplete: %+v", tc.label, ans)
		}
	}
}

// Recovered extractions validate: the marker enum is closed, recovery
// is only legal on VALID records, and reports predating the field keep
// validating.
func TestSlice2_ExtractionRecoveryFieldValidation(t *testing.T) {
	r := validReport(t)
	ag := replayAgentRow(r)
	if ag == nil || ag.Extraction == nil {
		t.Skip("fixture has no agent extraction row")
	}
	// VALID + a real marker is accepted.
	ag.Extraction.Status = ExtractionValid
	ag.Extraction.Recovery = RecoveryMemberSalvage
	if err := Validate(r, ""); err != nil {
		t.Fatalf("recovery marker rejected:\n%v", err)
	}
	// Unknown marker rejected.
	ag.Extraction.Recovery = "WILDCARD_REPAIR"
	if err := Validate(r, ""); err == nil {
		t.Fatal("unknown recovery marker accepted")
	}
	// Marker on a non-VALID extraction rejected.
	ag.Extraction.Recovery = RecoveryBraceCompletion
	ag.Extraction.Status = ExtractionInvalid
	if err := Validate(r, ""); err == nil {
		t.Fatal("recovery marker on INVALID extraction accepted")
	}
	// Field absent (legacy shape) keeps validating.
	ag.Extraction.Status = ExtractionValid
	ag.Extraction.Recovery = ""
	if err := Validate(r, ""); err != nil {
		t.Fatalf("extraction without recovery field rejected:\n%v", err)
	}
}
