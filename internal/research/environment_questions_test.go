package research

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// envLane clones fakeLane and adds the two observations a real lane
// produces when the advisory-declared package and symbol are USED: the
// static/reachability layer fully resolves (module, version, reach,
// build and both usage conditions SUPPORTED) so the only open layer is
// the always-present runtime/deployment posture predicate.
func envLane(t *testing.T) *LaneResult {
	t.Helper()
	l := fakeLane(t)
	hash := l.ContentHash
	l.Advisory.Vuln.AffectedModules[0].AffectedPackages = []domain.AffectedPackage{{
		Path:    "golang.org/x/net/http2",
		Symbols: []string{"ServeConn"},
	}}
	usageObs := func(id, sym, fact string, sites []domain.CallSite) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: id, Tool: evidencetools.PackageUsageTool, ToolStatus: evidencetools.StatusOK,
			Completeness: evidencetools.CompletenessPartial,
			Fact:         fact, Scope: "product source closure under the recorded build context",
			ScopeDetails: &evidencetools.ScopeDetails{Profile: "strict", Subject: "golang.org/x/net/http2"},
			Data: evidencetools.PackageUsageData{
				Module: "golang.org/x/net", Package: "golang.org/x/net/http2", Symbol: sym,
				Present: true, Usage: string(goanalysis.PackageUsageUsed),
				ProductSites: sites, CheckScope: "product source closure",
			},
		}
	}
	o3 := usageObs("OBS-0003", "ServeConn",
		"symbol golang.org/x/net/http2.ServeConn used by product source: 1 reference/call site(s)",
		[]domain.CallSite{{File: "srv/h2.go", Line: 42, Function: "run"}})
	o4 := usageObs("OBS-0004", "",
		"package golang.org/x/net/http2 used by product source: 1 import site(s), 1 reference site(s)",
		[]domain.CallSite{{File: "srv/h2.go", Line: 42, Function: "run"}})
	l.Observations = append(l.Observations, o3, o4)
	l.ArtifactByObs["OBS-0003"] = ArtifactRef{Path: "artifacts/obs-0003.json", SHA256: hash}
	l.ArtifactByObs["OBS-0004"] = ArtifactRef{Path: "artifacts/obs-0004.json", SHA256: hash}
	l.CanonicalByObs["OBS-0003"] = hash
	l.CanonicalByObs["OBS-0004"] = hash
	sym := "ServeConn"
	subjOf := func(sym string) *FactUsageSubject {
		return &FactUsageSubject{Module: "golang.org/x/net", Package: "golang.org/x/net/http2", Symbol: sym}
	}
	l.Facts = append(l.Facts,
		VerifiedFact{
			ID: "fact-obs-0003", Kind: FactKindPackageUsage, UsageSubject: subjOf(sym),
			Statement: o3.Fact, Claim: "TRUE", Tool: evidencetools.PackageUsageTool,
			ToolVersion: "test", Command: "package-usage {}", Scope: o3.Scope,
			Status: "OK", Coverage: "PARTIAL", SnapshotContentHash: hash,
			InputDigest: hash, DataDigest: hash,
			Artifact:   ArtifactRef{Path: "artifacts/obs-0003.json", SHA256: hash},
			Provenance: FactProvenance{ObservationID: "OBS-0003", Source: "deterministic-lane", GeneratedAt: "2026-01-01T00:00:00Z"},
		},
		VerifiedFact{
			ID: "fact-obs-0004", Kind: FactKindPackageUsage, UsageSubject: subjOf(""),
			Statement: o4.Fact, Claim: "TRUE", Tool: evidencetools.PackageUsageTool,
			ToolVersion: "test", Command: "package-usage {}", Scope: o4.Scope,
			Status: "OK", Coverage: "PARTIAL", SnapshotContentHash: hash,
			InputDigest: hash, DataDigest: hash,
			Artifact:   ArtifactRef{Path: "artifacts/obs-0004.json", SHA256: hash},
			Provenance: FactProvenance{ObservationID: "OBS-0004", Source: "deterministic-lane", GeneratedAt: "2026-01-01T00:00:00Z"},
		})
	return l
}

const envTestCondition = "Exploitation requires the prefetch parameters to carry negative values; the parameters come from deployment configuration."

// envAssemble assembles a deterministic-only report over a lane whose
// advisory description carries the supplied text.
func envAssemble(t *testing.T, description string) *Report {
	t.Helper()
	l := envLane(t)
	l.Advisory.Vuln.Description = description
	return Assemble(AssembleInput{
		Lane: l, DeterministicOnly: true, RunID: "env-q",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
}

// (b) A config-shaped advisory statement plus a reached-symbol
// observation puts a specific, actionable question on every
// human-facing surface — never a bare "needs review".
func TestEnvDerivedQuestionSurfaces(t *testing.T) {
	r := envAssemble(t, envTestCondition)
	var derived []OpenQuestion
	for _, q := range r.OpenQuestions {
		if q.Subject == subjRuntimePosture {
			derived = append(derived, q)
		}
	}
	if len(derived) != 1 {
		t.Fatalf("derived environment questions=%d, want 1: %+v", len(derived), r.OpenQuestions)
	}
	q := derived[0]
	wantStmt := strings.TrimSuffix(envTestCondition, ".")
	if !strings.Contains(q.Question, wantStmt) {
		t.Fatalf("question does not quote the recorded condition: %q", q.Question)
	}
	if !strings.Contains(q.Question, "golang.org/x/net/http2") {
		t.Fatalf("question does not name the reached subject: %q", q.Question)
	}
	if q.EvidenceRefs[0] != "adv:GO-TEST-0001" {
		t.Fatalf("question evidence refs=%v, want the advisory ref", q.EvidenceRefs)
	}
	var residual *ResidualQuestion
	for i := range r.ResidualQuestions {
		if r.ResidualQuestions[i].ID == q.ID {
			residual = &r.ResidualQuestions[i]
		}
	}
	if residual == nil {
		t.Fatal("residual question one-to-one with open_questions missing")
	}
	if !strings.Contains(residual.Why, "deployment") {
		t.Fatalf("residual why not specific: %q", residual.Why)
	}
	if !strings.Contains(r.TriageRecommendation.Reason, wantStmt) {
		t.Fatalf("triage reason does not carry the specific ask: %q", r.TriageRecommendation.Reason)
	}
	if r.Decision == nil || len(r.Decision.HumanQuestions) == 0 ||
		!strings.Contains(r.Decision.HumanQuestions[0], wantStmt) {
		t.Fatalf("decision human_questions missing the derived question: %+v", r.Decision)
	}
	if len(r.Decision.HumanQuestions) > MaxEnvironmentQuestions {
		t.Fatalf("human_questions=%d exceeds the R6 bound", len(r.Decision.HumanQuestions))
	}
	// The derived question leads the list — the mirrored UNKNOWN rows
	// follow it.
	if r.OpenQuestions[0].ID != q.ID {
		t.Fatalf("derived question must lead open_questions, got %+v", r.OpenQuestions[0])
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report with derived question invalid:\n%v", err)
	}
}

// (c) The same resolved lane without any recorded deployment statement
// keeps the generic surface byte-for-byte.
func TestEnvGenericWhenNoStatement(t *testing.T) {
	r := envAssemble(t, "The server mishandles reset frames.")
	for _, q := range r.OpenQuestions {
		if q.Subject == subjRuntimePosture {
			t.Fatalf("derived question with no recorded statement: %+v", q)
		}
	}
	if !strings.Contains(r.TriageRecommendation.Reason, "forbids authoritative dispositions") {
		t.Fatalf("triage reason changed without a driver: %q", r.TriageRecommendation.Reason)
	}
	if r.Decision != nil {
		for _, hq := range r.Decision.HumanQuestions {
			if strings.Contains(hq, "advisory declares") {
				t.Fatalf("derived question leaked into decision: %q", hq)
			}
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// (d) When nothing new applies, the human-facing surfaces marshal
// byte-identically: no environment questions exist anywhere and the
// reason/why strings are the legacy text.
func TestEnvSurfacesLegacyShape(t *testing.T) {
	a := envAssemble(t, "The server mishandles reset frames.")
	b := envAssemble(t, "A different generic description without conditions.")
	ta, err := json.Marshal(a.TriageRecommendation)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := json.Marshal(b.TriageRecommendation)
	if err != nil {
		t.Fatal(err)
	}
	if string(ta) != string(tb) {
		t.Fatalf("triage surface diverged without drivers:\n%s\n%s", ta, tb)
	}
	oa, err := json.Marshal(a.OpenQuestions)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := json.Marshal(b.OpenQuestions)
	if err != nil {
		t.Fatal(err)
	}
	if string(oa) != string(ob) {
		t.Fatalf("open_questions diverged without drivers:\n%s\n%s", oa, ob)
	}
	ha := HumanAction{Mode: HumanActionAcceptReject,
		EnvironmentQuestionRefs: nil,
		AllowedResponses:        []string{HumanResponseAccept, HumanResponseReject}}
	hb, err := json.Marshal(ha)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hb), "environment_questions") {
		t.Fatalf("legacy human_action gained a new member: %s", hb)
	}
}

// A REFUTED applicability/path predicate makes every deployment
// question moot — nothing is derived.
func TestEnvNoQuestionWhenPathRefuted(t *testing.T) {
	r := envAssemble(t, envTestCondition)
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Subject == subjProductPackageUsage && c.Origin == OriginDeterm {
			c.State = StateRefuted
		}
	}
	a := &assembler{lane: envLane(t)}
	l := envLane(t)
	l.Advisory.Vuln.Description = envTestCondition
	a.lane = l
	if got := a.envQuestions(r); got != nil {
		t.Fatalf("refuted path still derived questions: %v", got)
	}
}

// An open agent hypothesis over a required path predicate keeps the
// generic surface: deployment questions derive only when the *only*
// unresolved layer is deployment posture.
func TestEnvNoQuestionWhenPathStillOpen(t *testing.T) {
	l := envLane(t)
	l.Advisory.Vuln.Description = envTestCondition
	r := Assemble(AssembleInput{
		Lane: l, DeterministicOnly: true, RunID: "env-q2",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	a := &assembler{lane: l}
	r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
		ID: "ec-x", Subject: subjProductPackageUsage, Necessity: "required",
		Origin: OriginAgent, State: StateOpen,
		Statement: "product code may call the affected symbol",
	})
	if got := a.envQuestions(r); got != nil {
		t.Fatalf("open path layer derived deployment questions: %v", got)
	}
}

// The artifact-level derivation asks the declared variable's question
// plus the recorded case-specific one, gated on an open environment
// dimension and positive linkage evidence.
func TestArtifactEnvQuestions(t *testing.T) {
	l := envLane(t)
	l.Advisory.Vuln.Description = envTestCondition
	b := &branchBuilder{
		lane: l,
		conditions: []Condition{{
			ID: "inbound-listener", Role: ConditionRoleDeployment,
			Statement: "a listening socket exists in source at srv/h2.go:7 — attacker reachability is not established by source alone",
		}},
		in: ArtifactInput{
			RuleFacts: []evaluator.RuleFact{{
				Subject:   "symbol:golang.org/x/net/http2.ServeConn",
				Predicate: evaluator.PredicateProductSourceUsage, Value: "used",
				Status: "VERIFIED", Digest: strings.Repeat("ab", 32),
			}},
		},
	}
	qs := artifactEnvQuestions(b, []string{variableDeploymentPerimeter})
	if len(qs) != 2 {
		t.Fatalf("artifact questions=%v, want the listener fact + the advisory statement", qs)
	}
	if !strings.Contains(qs[0], "advisory declares") || !strings.Contains(qs[1], "listening socket") {
		t.Fatalf("advisory statement must lead, then the recorded fact: %v", qs)
	}
	if !strings.Contains(qs[0], "symbol:golang.org/x/net/http2.ServeConn") {
		t.Fatalf("question does not bind the reached subject: %q", qs[0])
	}
	// No open dimension → nothing.
	if got := artifactEnvQuestions(b, nil); got != nil {
		t.Fatalf("closed environment dimension still derived: %v", got)
	}
	// No linkage anchor → nothing.
	b2 := *b
	b2.in = ArtifactInput{Conditions: b.in.Conditions}
	if got := artifactEnvQuestions(&b2, []string{variableDeploymentPerimeter}); got != nil {
		t.Fatalf("missing anchor still derived: %v", got)
	}
	// A code-grounded close → nothing.
	b3 := *b
	b3.closeEstablished = &closeResult{}
	if got := artifactEnvQuestions(&b3, []string{variableDeploymentPerimeter}); got != nil {
		t.Fatalf("closed finding still derived: %v", got)
	}
}
