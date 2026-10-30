package research

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// turn builds an OK agent turn from a raw answer object.
func turnFor(t *testing.T, ans map[string]any) *AgentTurn {
	t.Helper()
	b, err := json.Marshal(ans)
	if err != nil {
		t.Fatal(err)
	}
	var a agentAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return &AgentTurn{
		Answer:     &a,
		AnswerJSON: b,
		Output: AgentOutput{
			Status:    AgentOK,
			Category:  strPtr(a.Category),
			Reasoning: strPtr(a.Reasoning),
			RawArtifact: AgentRawArtifact{
				Path: strPtr("agent/result.json"), SHA256: strPtr(strings.Repeat("cd", 32))},
		},
	}
}

func TestDeterministicOnly_AssembleValidates(t *testing.T) {
	r := Assemble(AssembleInput{
		Lane:              fakeLane(t),
		DeterministicOnly: true,
		RunID:             "research-det",
		StartedAt:         time.Now(), FinishedAt: time.Now(),
	})
	if r.AgentOutput.Status != AgentNotRequested {
		t.Fatalf("agent status = %s", r.AgentOutput.Status)
	}
	if len(r.AgentAssertions) != 0 {
		t.Fatalf("agent assertions present without agent")
	}
	if r.Disposition.Class != "REVIEW_REQUIRED" || r.Disposition.AutoClose {
		t.Fatalf("disposition = %+v", r.Disposition)
	}
	for name, ok := range map[string]*Section{
		"mechanism":  &r.VulnerabilityMechanism,
		"root_cause": &r.RootCause,
		"attack":     &r.AttackScenario,
		"exposure":   &r.ProductExposure,
		"altpaths":   &r.AlternativePaths,
	} {
		if ok.Status == StatusUnknown && !isUnknownSummary(ok.Summary) {
			t.Fatalf("%s UNKNOWN summary not contract-shaped: %q", name, ok.Summary)
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("deterministic-only report invalid:\n%v", err)
	}
}

// §7.5: an agent mechanism claim about a component absent from the
// advisory lands in unknowns, keeps state=UNKNOWN, and never reaches a
// verified mechanism.
func TestUnboundAgentComponent_RoutesToUnknowns(t *testing.T) {
	lane := fakeLane(t)
	turn := turnFor(t, map[string]any{
		"category":  "vulnerable",
		"reasoning": "grpc-go is the defect",
		"assessment": map[string]any{
			"vulnerability_mechanism": map[string]any{
				"claims": []any{map[string]any{
					"statement": "google.golang.org/grpc Server.ServeStreams mishandles RST_STREAM",
					"subject":   "google.golang.org/grpc",
				}},
			},
			"triage_recommendation": map[string]any{"action": "needs review"},
		},
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-bind",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	foundUnbound := false
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "google.golang.org/grpc") {
			foundUnbound = true
		}
	}
	if !foundUnbound {
		t.Fatalf("unbound component not in unknowns: %+v", r.Unknowns)
	}
	for _, c := range r.VulnerabilityMechanism.Claims {
		if c.Origin == OriginAgent && strings.Contains(c.Statement, "grpc") {
			if c.State != StateUnknown {
				t.Fatalf("unbound mechanism claim state = %s", c.State)
			}
		}
		if c.Origin == OriginDeterm && strings.Contains(c.Statement, "grpc") {
			t.Fatal("agent component promoted into a deterministic claim")
		}
	}
	// The assertion stays attributed; the unbound mechanism claim
	// specifically is UNKNOWN (the classification assertion may carry
	// its own state).
	foundAssertion, foundUnknown := false, false
	for _, a := range r.AgentAssertions {
		if strings.Contains(a.Statement, "grpc") {
			foundAssertion = true
			if a.State == StateUnknown {
				foundUnknown = true
			}
		}
	}
	if !foundAssertion {
		t.Fatal("agent assertion about grpc missing")
	}
	if !foundUnknown {
		t.Fatal("no UNKNOWN-state agent assertion for the unbound component")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report with unbound component invalid:\n%v", err)
	}
}

// §7.5: a bound component earns EVIDENCE_SUPPORTED, not just a claim.
func TestBoundAgentComponent_Supported(t *testing.T) {
	lane := fakeLane(t)
	turn := turnFor(t, map[string]any{
		"category":  "vulnerable",
		"reasoning": "x/net http2 rapid reset",
		"assessment": map[string]any{
			"vulnerability_mechanism": "golang.org/x/net/http2 mishandles rapid RST_STREAM frames",
		},
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-bound",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	var bound *AgentAssertion
	for i, a := range r.AgentAssertions {
		if strings.Contains(a.Statement, "x/net/http2") {
			bound = &r.AgentAssertions[i]
		}
	}
	if bound == nil {
		t.Fatal("bound mechanism assertion missing")
	}
	if bound.Basis != BasisSupported {
		t.Fatalf("bound assertion basis = %s", bound.Basis)
	}
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "x/net") {
			t.Fatalf("bound component routed to unknowns: %s", u.Statement)
		}
	}
}

// §7.6: deterministic facts win the product field; the conflicting agent
// classification is CONFLICTED and never changes product_applicability.
func TestConflict_DeterministicWins(t *testing.T) {
	lane := fakeLane(t)
	lane.Affected.ModulePresent = "FALSE"
	lane.Affected.VersionAffected = "FALSE"
	lane.Affected.PackagePresent = "FALSE"
	lane.Affected.BuildRelevant = "FALSE"
	turn := turnFor(t, map[string]any{
		"category":  "vulnerable",
		"reasoning": "the product is exploitable",
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-conflict",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.ProductApplicability.ModulePresent != "FALSE" {
		t.Fatal("agent changed product_applicability")
	}
	var classAssert *AgentAssertion
	for i, a := range r.AgentAssertions {
		if strings.HasPrefix(a.Statement, "category=") {
			classAssert = &r.AgentAssertions[i]
		}
	}
	if classAssert == nil || classAssert.State != StateConflicted {
		t.Fatalf("classification assertion state = %+v", classAssert)
	}
	if len(r.EvidenceQuality.Conflicts) == 0 {
		t.Fatal("conflict not recorded")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("conflicted report invalid:\n%v", err)
	}
}

func TestAgentClaimsNeverPromoted(t *testing.T) {
	lane := fakeLane(t)
	turn := turnFor(t, map[string]any{
		"category":  "vulnerable",
		"reasoning": "x/net http2",
		"assessment": map[string]any{
			"root_cause": "golang.org/x/net/http2 server.go:432 drops frames",
		},
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-promote",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	for _, f := range r.VerifiedFacts {
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), "agent") {
			t.Fatalf("agent-origin content inside verified fact: %s", f.ID)
		}
		if f.Tool == "agent" || f.Provenance.Source != "deterministic-lane" {
			t.Fatal("agent claim promoted to verified fact")
		}
	}
}

// Non-OK observations become unknowns, never FALSE/absent/safe.
func TestNonOKObservations_BecomeUnknowns(t *testing.T) {
	lane := fakeLane(t)
	lane.Observations = append(lane.Observations, &evidencetools.Observation{
		ID: "OBS-0099", Tool: "find_callers", ToolStatus: evidencetools.StatusTimeout,
		Fact: "timed out", Completeness: evidencetools.CompletenessUnknown,
		Error: "budget exceeded",
	})
	r := Assemble(AssembleInput{
		Lane: lane, RunID: "research-to", StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	found := false
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "find_callers") && strings.Contains(u.Statement, "TIMEOUT") {
			found = true
		}
	}
	if !found {
		t.Fatal("timeout observation did not become an unknown")
	}
	for _, f := range r.VerifiedFacts {
		if f.Provenance.ObservationID == "OBS-0099" {
			t.Fatal("non-OK observation became a verified fact")
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

func TestOpenAndResidualQuestionsShareIDs(t *testing.T) {
	r := validReport(t)
	if len(r.OpenQuestions) != len(r.ResidualQuestions) {
		t.Fatalf("question lists diverge: %d vs %d",
			len(r.OpenQuestions), len(r.ResidualQuestions))
	}
	for i := range r.OpenQuestions {
		if r.OpenQuestions[i].ID != r.ResidualQuestions[i].ID {
			t.Fatalf("id mismatch at %d", i)
		}
	}
}

func TestAgentTriageActionAdopted(t *testing.T) {
	lane := fakeLane(t)
	turn := turnFor(t, map[string]any{
		"category":  "uncertain",
		"reasoning": "not enough evidence",
		"assessment": map[string]any{
			"triage_recommendation": map[string]any{
				"action": "fix", "reason": "bound component confirmed affected",
				"bounds": "snapshot scope only",
			},
		},
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-triage",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.TriageRecommendation.Action != "fix" {
		t.Fatalf("triage action = %q", r.TriageRecommendation.Action)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

func TestAgentFailedLeavesUnknowns(t *testing.T) {
	lane := fakeLane(t)
	turn := &AgentTurn{
		Output: AgentOutput{Status: AgentTimeout},
		Err:    "e6 preflight timed out",
	}
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-to2",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.AgentOutput.Status != AgentTimeout {
		t.Fatal("agent status lost")
	}
	found := false
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "TIMEOUT") {
			found = true
		}
	}
	if !found {
		t.Fatal("agent timeout not represented as an unknown")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

func TestRender_ByteStable(t *testing.T) {
	lane := fakeLane(t)
	turn := turnFor(t, map[string]any{
		"category":  "uncertain",
		"reasoning": "cannot determine",
		"assessment": map[string]any{
			"product_exposure": "golang.org/x/net used at http2.go:10",
		},
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-render",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	a, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("render not byte-stable")
	}
	// JSON round-trip: marshal → unmarshal → marshal is identical.
	j1, _ := RenderJSON(r)
	r2, err := ParseReport(j1)
	if err != nil {
		t.Fatal(err)
	}
	j2, _ := RenderJSON(r2)
	if string(j1) != string(j2) {
		t.Fatal("JSON render not byte-stable")
	}
	// Markdown re-render of the round-tripped report is byte-identical
	// too: the /3 evidence_level block must survive marshal/unmarshal.
	a2, err := RenderMarkdown(r2)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(a2) {
		t.Fatal("markdown re-render after JSON round-trip not byte-stable")
	}
	md := string(a)
	for _, marker := range []string{
		"## Резюме",
		"## CVE essence and mechanism",
		"## Evidence level (derived)",
		"## Exploitation conditions — established vs unknown",
		"## Preserved agent statements (unverified)",
		"## Decision-changing unknowns",
		"REVIEW REQUIRED",
		"## Attempt and retry history",
		renderEvidenceLevelDisclaimer,
	} {
		if !strings.Contains(md, marker) {
			t.Fatalf("rendered markdown missing %q", marker)
		}
	}
}

func TestSectionStatusOrder(t *testing.T) {
	r := validReport(t)
	var names []string
	for _, s := range r.statusSections() {
		names = append(names, s.Name)
	}
	want := "vulnerability_mechanism,root_cause,attack_scenario,product_exposure,alternative_paths,evidence_quality"
	if fmt.Sprint(names) != fmt.Sprint(strings.Split(want, ",")) {
		t.Fatalf("section order = %v", names)
	}
}

// §9 check 7: agent-src refs (file:line citations and generic refs) are
// accepted and resolve through the agent-source index — never through
// deterministic artifacts.
func TestAgentSrcRefsResolve(t *testing.T) {
	turn := turnFor(t, map[string]any{
		"category": "vulnerable", "reasoning": "r",
		"assessment": map[string]any{
			"vulnerability_mechanism": map[string]any{
				"summary": "grpc-go h2 flood",
				"claims": []any{map[string]any{
					"statement":     "grpc-go's HTTP/2 transport mishandles RST storms",
					"subject":       "google.golang.org/grpc",
					"scope":         "transport",
					"evidence_refs": []any{"pkg/transport/http2_server.go:412-430", "pkg/server.go"},
				}},
			},
			"residual_questions": []any{"is the h2 server enabled in this deployment?"},
		},
	})
	r := Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "x",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("agent-src report invalid:\n%v", err)
	}
	// every used agent-src ref has an index row pinned to the raw answer
	idx := map[string]EvidenceReference{}
	for _, e := range r.EvidenceQuality.References {
		if e.Kind == "agent-source" {
			idx[e.Ref] = e
		}
	}
	var used []string
	collect := func(refs []string) {
		for _, ref := range refs {
			if strings.HasPrefix(ref, "agent-src:") {
				used = append(used, ref)
			}
		}
	}
	for _, a := range r.AgentAssertions {
		collect(a.EvidenceRefs)
	}
	for _, q := range r.OpenQuestions {
		collect(q.EvidenceRefs)
	}
	// The citations the agent carried must be indexed even though they
	// no longer appear in evidence_refs.
	for _, ref := range []string{
		"agent-src:assessment.mechanism",
		"agent-src:pkg/transport/http2_server.go:412-430",
		"agent-src:pkg/server.go",
		"agent-src:residual_questions",
		"agent-src:final-answer",
	} {
		row, ok := idx[ref]
		if !ok {
			t.Fatalf("agent-src %s missing index entry", ref)
		}
		if row.Path == "" || row.SHA256 == "" {
			t.Fatalf("agent-src %s index row lacks retained pin", ref)
		}
	}
	if len(used) != 0 {
		t.Fatalf("agent-src leaked into evidence_refs: %v", used)
	}
	// a fabricated agent-src ref with no index entry fails
	r2 := Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "x2",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	r2.AgentAssertions = append(r2.AgentAssertions, AgentAssertion{
		ID: "A-9999", Statement: "x", Subject: "y", Scope: "z",
		State: StateOpen, EvidenceRefs: []string{"agent-src:fabricated.go:1"},
	})
	if err := Validate(r2, ""); err == nil || !strings.Contains(err.Error(), "fabricated") {
		t.Fatalf("unindexed agent-src accepted: %v", err)
	}
}

// Advisory scope gap (round-3 fix): an agent answer naming a module path
// outside the advisory's affected entries must yield an explicit unknown
// plus mechanism/root_cause limitations.
func TestAdvisoryScopeGap_UnboundModuleToken(t *testing.T) {
	turn := turnFor(t, map[string]any{
		"category": "code_not_present", "reasoning": "x/net is fixed",
		"assessment": map[string]any{
			"vulnerability_mechanism": map[string]any{
				"summary": "grpc-go's HTTP/2 transport may also be vulnerable via google.golang.org/grpc",
				"claims": []any{map[string]any{
					"statement": "x/net is patched; other HTTP/2 impls like google.golang.org/grpc need checking",
					"subject":   "golang.org/x/net",
				}},
			},
		},
	})
	lane := fakeLane(t)
	lane.SnapshotRoot = t.TempDir() // empty snapshot: no file-path collisions
	// grpc is a resolved dependency of the snapshot (outside-advisory
	// components must be real dependency modules per the §3.1 refinement).
	if err := os.WriteFile(filepath.Join(lane.SnapshotRoot, "go.sum"),
		[]byte("google.golang.org/grpc v1.58.0 h1:x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "x",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	found := false
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "google.golang.org/grpc") && strings.Contains(u.Statement, "not in the advisory") {
			found = true
		}
	}
	if !found {
		t.Fatal("no advisory-scope unknown for google.golang.org/grpc")
	}
	mechLim, rcLim := false, false
	for _, l := range r.VulnerabilityMechanism.Limitations {
		if strings.Contains(l, "google.golang.org/grpc") {
			mechLim = true
		}
	}
	for _, l := range r.RootCause.Limitations {
		if strings.Contains(l, "google.golang.org/grpc") {
			rcLim = true
		}
	}
	if !mechLim || !rcLim {
		t.Fatalf("section limitations missing scope note: mech=%v rc=%v",
			r.VulnerabilityMechanism.Limitations, r.RootCause.Limitations)
	}
	eqLim := false
	for _, l := range r.EvidenceQuality.Limitations {
		if strings.Contains(l, "exactly one Go module") && strings.Contains(l, "google.golang.org/grpc") {
			eqLim = true
		}
	}
	if !eqLim {
		t.Fatalf("evidence_quality.scope limitation missing: %v", r.EvidenceQuality.Limitations)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

func TestAdvisoryScopeGap_OnlyAdvisoryModules(t *testing.T) {
	turn := turnFor(t, map[string]any{
		"category": "uncertain", "reasoning": "only golang.org/x/net is involved",
		"assessment": map[string]any{
			"vulnerability_mechanism": map[string]any{
				"summary": "the defect is in golang.org/x/net http2",
				"claims":  []any{map[string]any{"statement": "x/net h2 reset handling", "subject": "golang.org/x/net"}},
			},
		},
	})
	lane := fakeLane(t)
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "x",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "not in the advisory affected entries") {
			t.Fatalf("false-positive scope unknown: %s", u.Statement)
		}
	}
	for _, l := range r.VulnerabilityMechanism.Limitations {
		if strings.Contains(l, "outside the advisory scope") {
			t.Fatalf("false-positive limitation: %s", l)
		}
	}
}

// A file path inside the snapshot (and extension-less plain paths like
// /work/go.mod) are never treated as module tokens.
func TestGoModuleCandidates_FilePathsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "github.com/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "github.com/docker/docker.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// a path that exists as a file inside the snapshot
	fileTok := "github.com/docker/docker.txt"
	out := goModuleCandidates("uses "+fileTok+" and google.golang.org/grpc plus /work/go.mod:43", dir)
	for _, m := range out {
		if m == fileTok {
			t.Fatalf("file path treated as module: %v", out)
		}
	}
	found := false
	for _, m := range out {
		if m == "google.golang.org/grpc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("grpc token missed: %v", out)
	}
	// .go-file tokens cap to the module prefix (golang.org/x/net/http2/server.go -> golang.org/x/net)
	out2 := goModuleCandidates("see golang.org/x/net/http2/server.go for details", "")
	for _, m := range out2 {
		if strings.HasSuffix(m, ".go") {
			t.Fatalf("file-like token emitted: %v", out2)
		}
	}
}

// report.json is a wire contract: empty lists serialize as [] and never as
// null, so an external reader never has to treat "absent" and "empty" alike.
func TestRenderJSON_EmptyListsAreArrays(t *testing.T) {
	lane := laneFor(t, "modules.test/vuln", domain.AffectedResult{
		ModulePresent:   domain.ClaimFalse,
		VersionAffected: domain.ClaimFalse,
		PackagePresent:  domain.ClaimFalse,
		BuildRelevant:   domain.ClaimFalse,
	}, nil, nil)
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "empty-lists",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	b, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, key := range []string{`"limitations":null`, `"evidence_refs":null`, `"basis":null`, `"unknowns":null`} {
		if strings.Contains(s, key) {
			t.Fatalf("report.json contains %s (empty lists must serialize as [])", key)
		}
	}
}

// A config-origin decision keeps its verdict basis and policy assumption
// in dedicated fields: the JSON carries ground_basis and assumption_ids
// beside (never inside) evidence_refs, the executed-check row names the
// lane's post-reach check, and the report still validates.
func TestAssembleConfigOriginDecisionSeparatesPolicy(t *testing.T) {
	lane, out := configLaneOpts(t, "", true)
	if lane.ConfigProof == nil {
		t.Fatal("fixture produced no config proof")
	}
	d := lane.ConfigProof.Decision
	r := Assemble(AssembleInput{
		Lane: lane, Decision: &d, DeterministicOnly: true, RunID: "assemble-config",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if err := Validate(r, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
	jb, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Decision struct {
			GroundBasis   string   `json:"ground_basis"`
			AssumptionIDs []string `json:"assumption_ids"`
			EvidenceRefs  []string `json:"evidence_refs"`
			Checks        []struct {
				Tool string `json:"tool"`
			} `json:"checks"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(jb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Decision.GroundBasis != domain.BasisConfigOrigin {
		t.Fatalf("ground_basis = %q", doc.Decision.GroundBasis)
	}
	if len(doc.Decision.AssumptionIDs) != 1 || doc.Decision.AssumptionIDs[0] != "ASM-CONFIG-TRUST" {
		t.Fatalf("assumption_ids = %v", doc.Decision.AssumptionIDs)
	}
	for _, ev := range doc.Decision.EvidenceRefs {
		for _, id := range doc.Decision.AssumptionIDs {
			if ev == id {
				t.Fatalf("assumption id %q also cited as evidence", id)
			}
		}
	}
	if len(doc.Decision.Checks) != 1 || doc.Decision.Checks[0].Tool != postReachConfigTool {
		t.Fatalf("decision checks = %+v", doc.Decision.Checks)
	}
}

// The implementation-presence axis is projected into
// product_applicability with its target scope, verified locus and policy
// assumption ids, and is validated end to end. BuildRelevant stays TRUE:
// the axis is not a package/platform-restriction replacement.
func TestAssembleImplementationAxisProjection(t *testing.T) {
	lane := fakeLane(t)
	lane.Snapshot.Target = &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source: domain.ProductTargetSourceArtifactBuildInfo, Scope: domain.ProductTargetScopeArtifact,
		ArtifactSHA256: strings.Repeat("cd", 32), BuildInfoSHA256: strings.Repeat("ef", 32),
	}
	targets := assumptionsUnit("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	lane.Assumptions = assumptionsInputForTest(assumptionsUnitDoc(targets))
	lane.Affected.VulnerableImplementationPresent = domain.ClaimFalse
	lane.Affected.ImplementationLocus = "golang.org/x/net/http2/h2_bundle.go ServeConn (marker \"x\", //go:build linux)"
	lane.Affected.ImplementationTarget = "linux/amd64"
	lane.Affected.ImplementationTargetScope = domain.AssumptionScopeProduct
	lane.Affected.ImplementationModules = []string{"golang.org/x/net"}
	lane.Affected.AssumptionIDs = []string{targets.ID}

	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "implementation-axis",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	pa := r.ProductApplicability
	if pa.VulnerableImplementationPresent != "FALSE" {
		t.Fatalf("axis = %q", pa.VulnerableImplementationPresent)
	}
	if pa.ImplementationTargetScope != "product" || pa.ImplementationTarget != "linux/amd64" {
		t.Fatalf("target projection = %q/%q", pa.ImplementationTargetScope, pa.ImplementationTarget)
	}
	if len(pa.AssumptionIDs) != 1 || pa.AssumptionIDs[0] != targets.ID {
		t.Fatalf("assumption ids = %v", pa.AssumptionIDs)
	}
	if pa.BuildRelevant != "TRUE" {
		t.Fatalf("BuildRelevant changed by the implementation axis: %q", pa.BuildRelevant)
	}
	if r.Input.Snapshot.Target == nil || r.Input.Snapshot.Target.Source != domain.ProductTargetSourceArtifactBuildInfo {
		t.Fatalf("snapshot target not projected: %+v", r.Input.Snapshot.Target)
	}
	var basis *ApplicabilityBasis
	for i := range pa.Basis {
		if pa.Basis[i].Kind == ABImplementationAbsent {
			basis = &pa.Basis[i]
		}
	}
	if basis == nil || basis.Status != ABEstablished || basis.Source != ABSourceDeterministic {
		t.Fatalf("implementation basis = %+v", basis)
	}
	if pa.VulnerableCodeReachability != VCRFalse {
		t.Fatalf("vulnerable code reachability = %q, want FALSE", pa.VulnerableCodeReachability)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report with implementation axis invalid:\n%v", err)
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vulnerable_implementation_present=FALSE", "build target provenance", targets.ID} {
		if !strings.Contains(string(md), want) {
			t.Fatalf("rendered report lacks %q", want)
		}
	}
}

// An artifact-scoped implementation axis cannot claim a product-wide
// conclusion: report validation fails closed even when the record is
// otherwise well-formed.
func TestAssembleImplementationAxisArtifactScopeRejected(t *testing.T) {
	lane := fakeLane(t)
	targets := assumptionsUnit("ASM-ARTIFACT", domain.AssumptionSupportedTargets, domain.AssumptionScopeArtifact)
	lane.Assumptions = assumptionsInputForTest(assumptionsUnitDoc(targets))
	lane.Affected.VulnerableImplementationPresent = domain.ClaimFalse
	lane.Affected.ImplementationLocus = "golang.org/x/net/http2/h2_bundle.go ServeConn"
	lane.Affected.ImplementationTarget = "linux/amd64"
	lane.Affected.ImplementationTargetScope = domain.AssumptionScopeArtifact
	lane.Affected.ImplementationModules = []string{"golang.org/x/net"}
	lane.Affected.AssumptionIDs = []string{targets.ID}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "implementation-artifact-scope",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	err := Validate(r, "")
	if err == nil || !strings.Contains(err.Error(), "implementation_target_scope=product") {
		t.Fatalf("artifact-scoped axis was not rejected: %v", err)
	}
}

// A target record that disagrees with the snapshot's own build fields is
// rejected: platform conclusions would be unreproducible.
func TestValidate_SnapshotTargetMismatchRejected(t *testing.T) {
	lane := fakeLane(t)
	lane.Snapshot.Target = &domain.ProductTarget{
		GOOS: "darwin", GOARCH: "arm64",
		Source: domain.ProductTargetSourceArtifactBuildInfo, Scope: domain.ProductTargetScopeArtifact,
		ArtifactSHA256: strings.Repeat("cd", 32), BuildInfoSHA256: strings.Repeat("ef", 32),
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "target-mismatch",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	err := Validate(r, "")
	if err == nil || !strings.Contains(err.Error(), "disagrees with snapshot") {
		t.Fatalf("mismatched target was not rejected: %v", err)
	}
}

// Assemble is a publication surface, not a copy service: a caller-supplied
// negative is only a candidate. Under a non-closing lane scope it is projected
// to INCONCLUSIVE while every recorded part — evidence refs, executed checks,
// limitations and the hypothesis history — survives, and the scope refusal is
// named. The complete-record control publishes the same decision verbatim.
func TestAssembleRefusesUngatedNegativeDecision(t *testing.T) {
	negative := EvidenceDecision{
		Verdict:              domain.VerdictNotAffected,
		Reason:               "the recorded applicability chain resolved version_affected=FALSE",
		Scope:                "deterministic applicability chain",
		Coverage:             "COMPLETE",
		EvidenceRefs:         []string{"obs:OBS-0001"},
		Limitations:          []string{"recorded before the structural scope binding"},
		Falsifier:            domain.FalsifierPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		Checks: []DecisionCheck{{
			ID: "check-1", Tool: "affected-resolve", Status: "OK",
			Completeness: "COMPLETE", Scope: "go module graph",
		}},
		HumanQuestions:  []string{"does the ticket declare the same package version?"},
		TicketRationale: "the component check completed",
		AgentHypothesis: "the dependency is unused by product code",
	}

	// The guard projects the conclusion and preserves everything recorded.
	refused := scopeBoundDecision(&LaneResult{}, &negative)
	if refused.Verdict != domain.VerdictInconclusive || refused.Coverage != "INSUFFICIENT_SCOPE" {
		t.Fatalf("guard projected %+v", refused)
	}
	if refused.NegativeVerification != nil || refused.Falsifier != "" || refused.GroundBasis != "" {
		t.Fatalf("a refused negative kept its proof annotation: %+v", refused)
	}
	if !strings.Contains(refused.Reason, "scoped applicability gap") {
		t.Fatalf("refusal must name the gap: %q", refused.Reason)
	}
	if len(refused.EvidenceRefs) != 1 || refused.EvidenceRefs[0] != "obs:OBS-0001" {
		t.Fatalf("evidence refs lost: %+v", refused.EvidenceRefs)
	}
	if len(refused.Checks) != 1 || refused.Checks[0].ID != "check-1" {
		t.Fatalf("executed checks lost: %+v", refused.Checks)
	}
	if !containsStr(refused.Limitations, "recorded before the structural scope binding") {
		t.Fatalf("recorded limitations lost: %+v", refused.Limitations)
	}
	if refused.AgentHypothesis != negative.AgentHypothesis {
		t.Fatalf("hypothesis history lost: %+v", refused)
	}

	// Publication: the report carries the projected decision and a concrete ask.
	lane := fakeLane(t)
	lane.Affected.Scope = projectionScope("GO-TEST-0001")
	r := Assemble(AssembleInput{
		Lane: lane, Decision: &negative, DeterministicOnly: true, RunID: "assemble-ungated",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Decision.Verdict != domain.VerdictInconclusive || r.Decision.Coverage != "INSUFFICIENT_SCOPE" ||
		!strings.Contains(r.Decision.Reason, "scoped applicability gap") {
		t.Fatalf("published decision = %+v", r.Decision)
	}
	if r.Decision.AgentHypothesis != negative.AgentHypothesis {
		t.Fatalf("published hypothesis history lost: %+v", r.Decision)
	}
	if !containsStr(r.Decision.Limitations, "recorded before the structural scope binding") {
		t.Fatalf("published limitations lost: %+v", r.Decision.Limitations)
	}
	if len(r.Decision.HumanQuestions) == 0 {
		t.Fatalf("published refusal needs a concrete ask: %+v", r.Decision)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report with the re-gated decision rejected:\n%v", err)
	}

	// Control: the complete-record scope publishes the supplied negative.
	exact := fakeLane(t)
	exact.Affected.Scope = exactAdvisoryScope("GO-TEST-0001")
	control := Assemble(AssembleInput{
		Lane: exact, Decision: &negative, DeterministicOnly: true, RunID: "assemble-admissible",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if control.Decision.Verdict != domain.VerdictNotAffected ||
		control.Decision.NegativeVerification == nil {
		t.Fatalf("admissible scope must keep the negative: %+v", control.Decision)
	}
}

// Assemble re-gates a supplied decision artifact at publication: under a
// non-closing scope every CLOSE_* branch is demoted, the closing dispositions
// leave the justification graph, the unknown branch names the refusal and the
// artifact-level proposal becomes HOLD_UNKNOWN — while the caller's artifact is
// left untouched and the shared facts keep their verification status. A
// non-closing artifact and an admissible scope are never rewritten.
func TestAssembleRefusesUngatedCloseArtifact(t *testing.T) {
	closeArtifact := func() *DecisionArtifact {
		a := validArtifact(t)
		a.ProposedDisposition = DispositionCloseNotAffected
		a.Branches[0].ProposedDisposition = DispositionCloseNotAffected
		a.JustificationGraph[0].Disposition = DispositionCloseNotAffected
		return a
	}

	lane := fakeLane(t)
	lane.Affected.Scope = projectionScope("GO-TEST-0001")
	caller := closeArtifact()
	r := Assemble(AssembleInput{
		Lane: lane, DecisionArtifact: caller, DeterministicOnly: true, RunID: "assemble-close",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Schema != ReportSchemaV3 {
		t.Fatalf("artifact report schema = %q", r.Schema)
	}
	published := r.DecisionArtifact
	if published == nil || published == caller {
		t.Fatal("published artifact must be a guarded copy, not the caller's value")
	}
	if caller.ProposedDisposition != DispositionCloseNotAffected ||
		caller.Branches[0].ProposedDisposition != DispositionCloseNotAffected {
		t.Fatalf("the caller's artifact was mutated: %+v", caller)
	}
	if published.ProposedDisposition != DispositionHoldUnknown {
		t.Fatalf("published proposal = %q, want HOLD_UNKNOWN", published.ProposedDisposition)
	}
	demoted := branchByID(published, caller.Branches[0].ID)
	if demoted == nil || demoted.ProposedDisposition != DispositionHoldUnknown ||
		demoted.Status != BranchNotDecisionReady {
		t.Fatalf("close branch not demoted: %+v", demoted)
	}
	if !limitationNaming(demoted.Limitations, "scoped applicability gap") {
		t.Fatalf("demoted branch must name the refusal: %+v", demoted)
	}
	unknown := branchByID(published, "B-UNKNOWN")
	if unknown == nil || !limitationNaming(unknown.Limitations, "scoped applicability gap") {
		t.Fatalf("unknown branch must name the refusal: %+v", unknown)
	}
	if len(published.JustificationGraph) != len(caller.JustificationGraph) {
		t.Fatalf("justification edges dropped: %d", len(published.JustificationGraph))
	}
	for _, j := range published.JustificationGraph {
		if isCloseDisposition(j.Disposition) {
			t.Fatalf("justification edge %s kept an active close: %+v", j.ID, j)
		}
	}
	if len(published.SharedFacts) != len(caller.SharedFacts) {
		t.Fatalf("shared facts dropped: %d", len(published.SharedFacts))
	}
	for i := range published.SharedFacts {
		if published.SharedFacts[i].ID != caller.SharedFacts[i].ID ||
			published.SharedFacts[i].Status != caller.SharedFacts[i].Status {
			t.Fatalf("shared fact %d changed: %+v", i, published.SharedFacts[i])
		}
	}
	if err := ValidateDecisionArtifact(published); err != nil {
		t.Fatalf("guarded artifact is not contract-valid:\n%v", err)
	}

	// A non-closing artifact is published as supplied.
	hold := validArtifact(t)
	hold.Branches[0].ProposedDisposition = DispositionHoldUnknown
	hold.JustificationGraph[0].Disposition = DispositionHoldUnknown
	if artifactProposesClose(hold) {
		t.Fatalf("fixture still proposes a close: %+v", hold)
	}
	if got := scopeBoundArtifact(lane, hold); got != hold {
		t.Fatalf("non-closing artifact was rewritten: %+v", got)
	}
	// An admissible scope keeps the supplied close.
	admissible := fakeLane(t)
	admissible.Affected.Scope = exactAdvisoryScope("GO-TEST-0001")
	if got := scopeBoundArtifact(admissible, closeArtifact()); got == nil ||
		got.ProposedDisposition != DispositionCloseNotAffected {
		t.Fatalf("admissible scope demoted a closed artifact: %+v", got)
	}
}
