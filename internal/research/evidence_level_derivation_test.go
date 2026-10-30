package research

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// ---- role inference (slice2-fidelity/3) ----

// TestConditionRole pins the fixed subject→role table: module presence
// and version-in-use are applicability, package reachability and build
// relevance are path transitions, runtime posture and inbound listeners
// are deployment scope facts, everything else is supporting.
func TestConditionRole(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{subjModulePresence, ConditionRoleApplicability},
		{subjVersionInUse, ConditionRoleApplicability},
		{subjPackageReach, ConditionRolePath},
		{subjBuildRelevant, ConditionRolePath},
		{subjRuntimePosture, ConditionRoleDeployment},
		{subjInboundListener, ConditionRoleDeployment},
		{"attacker delivers a malformed frame", ConditionRoleSupporting},
		{"golang.org/x/net", ConditionRoleSupporting},
		{"", ConditionRoleSupporting},
	}
	for _, tc := range cases {
		if got := conditionRoleForSubject(tc.subject); got != tc.want {
			t.Fatalf("conditionRoleForSubject(%q) = %q, want %q", tc.subject, got, tc.want)
		}
	}
}

// TestConditionRoleAssignment exercises the assembler path: every
// emitted condition carries a role; a canonical agent path hypothesis is
// normalized into a required OPEN path blocker; a non-canonical agent
// claim stays a supporting hypothesis; runtime posture is always
// deployment and never a blocker.
func TestConditionRoleAssignment(t *testing.T) {
	turn := turnWith(t, "vulnerable", "the malformed frame path may be exploitable",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{
					map[string]any{
						"statement": "the affected package is imported and reachable",
						"subject":   "Affected Package Reachable ", // canonical modulo case/space
					},
					map[string]any{
						"statement": "an attacker could craft a frame through the listener",
						"subject":   "malformed frame delivery", // non-canonical
					},
				},
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
	},
		[]*evidencetools.Observation{{
			ID: "OBS-0040", Tool: "listen-sites", ToolStatus: evidencetools.StatusOK,
			Fact: "one listener site", Scope: "inbound surface",
			Completeness: evidencetools.CompletenessPartial,
			Data:         map[string]any{"count": float64(1)},
		}},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected"),
			factFor("OBS-0040", "listen-sites", "one listener site recorded"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "roles",
		StartedAt: time.Now(), FinishedAt: time.Now()})

	// Marker + every condition carries a role.
	if len(r.ContractExtensions) != 1 || r.ContractExtensions[0] != Slice2ExtensionV3 {
		t.Fatalf("contract_extensions = %v, want [slice2-fidelity/3]", r.ContractExtensions)
	}
	for _, c := range r.ExploitationConditions {
		if c.Role == "" {
			t.Fatalf("condition %s (%q) has no role", c.ID, c.Subject)
		}
	}

	// Deterministic subjects follow the table.
	for _, want := range []struct {
		subject string
		role    string
	}{
		{subjModulePresence, ConditionRoleApplicability},
		{subjVersionInUse, ConditionRoleApplicability},
		{subjPackageReach, ConditionRolePath},
		{subjBuildRelevant, ConditionRolePath},
		{subjRuntimePosture, ConditionRoleDeployment},
		{subjInboundListener, ConditionRoleDeployment},
	} {
		c := conditionOf(r, want.subject)
		if c == nil {
			t.Fatalf("no condition for %q", want.subject)
		}
		if c.Role != want.role {
			t.Fatalf("condition %q role = %q, want %q", want.subject, c.Role, want.role)
		}
	}

	// Canonical agent path hypothesis: normalized subject, required,
	// still OPEN — it blocks L1 even though the deterministic side is
	// fully closed.
	var agentPath *ExploitationCondition
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Origin == OriginAgent && c.Role == ConditionRolePath {
			agentPath = c
		}
	}
	if agentPath == nil {
		t.Fatal("agent canonical path claim did not become a path condition")
	}
	if agentPath.Subject != subjPackageReach {
		t.Fatalf("agent path subject not canonicalized: %q", agentPath.Subject)
	}
	if agentPath.Necessity != "required" || agentPath.State != StateOpen {
		t.Fatalf("agent path condition = necessity %q state %q, want required/OPEN",
			agentPath.Necessity, agentPath.State)
	}
	if el := r.EvidenceLevel; el == nil || el.Level == EvidenceLevelL1 {
		t.Fatalf("open canonical agent path hypothesis did not block L1: %+v", el)
	}

	// Non-canonical agent claim: supporting, never a carrier, and the
	// original hypothesis stays in agent_assertions.
	var agentSupporting *ExploitationCondition
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Origin == OriginAgent && c.Role == ConditionRoleSupporting {
			agentSupporting = c
		}
	}
	if agentSupporting == nil {
		t.Fatal("non-canonical agent claim missing or not role=supporting")
	}
	for _, ref := range agentSupporting.EvidenceRefs {
		for _, f := range r.VerifiedFacts {
			if f.ID == ref {
				t.Fatalf("agent condition ref %q resolves to a verified fact", ref)
			}
		}
	}

	// Runtime posture never blocks L1: it must not appear in
	// blocking_conditions even though it stays UNKNOWN.
	rt := conditionOf(r, subjRuntimePosture)
	if rt.Role != ConditionRoleDeployment {
		t.Fatalf("runtime posture role = %q", rt.Role)
	}
	for _, b := range r.EvidenceLevel.BlockingConditions {
		if b == rt.ID {
			t.Fatal("runtime/deployment posture in blocking_conditions")
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("role-assigned report invalid:\n%v", err)
	}
}

// ---- pure derivation ladder ----

// derivationFact mints a verified fact row for pure-derivation fixtures.
func derivationFact(id, tool string) VerifiedFact {
	return VerifiedFact{ID: id, Statement: tool + " observation", Claim: "TRUE",
		Tool: tool, Status: "OK"}
}

// derivationCondition builds one condition; refs must name verified
// facts (or stay empty) — derivation never resolves agent refs.
func derivationCondition(id, subject, role, origin, necessity, state string, refs ...string) ExploitationCondition {
	return ExploitationCondition{
		ID: id, Subject: subject, Role: role, Origin: origin,
		Necessity: necessity, State: state, EvidenceRefs: refs,
	}
}

// TestEvidenceLevelDerivation exercises the pure ladder L3 → L1 → L2 on
// synthetic reports (no assembler, no lane): a fully closed static path
// is L1, any unclosed required path/applicability condition is L2, a
// verified dynamic fact under an established axis is L3, and agent
// material can never raise the level.
func TestEvidenceLevelDerivation(t *testing.T) {
	resolve := derivationFact("fact-obs-0002", "affected-resolve")
	moduleObs := derivationFact("fact-obs-0010", "module_usage")
	dynFact := derivationFact("fact-obs-0060", "reproduction")

	closedRequired := []ExploitationCondition{
		derivationCondition("EC-0001", subjModulePresence, ConditionRoleApplicability, OriginDeterm, "required", StateSupported, resolve.ID),
		derivationCondition("EC-0002", subjVersionInUse, ConditionRoleApplicability, OriginDeterm, "required", StateSupported, resolve.ID),
		derivationCondition("EC-0003", subjPackageReach, ConditionRolePath, OriginDeterm, "required", StateSupported, moduleObs.ID),
		derivationCondition("EC-0004", subjBuildRelevant, ConditionRolePath, OriginDeterm, "required", StateSupported, moduleObs.ID),
		derivationCondition("EC-0005", subjRuntimePosture, ConditionRoleDeployment, OriginDeterm, "required", StateUnknown),
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

	t.Run("closed static path with open deployment posture is L1", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs}
		r.ExploitationConditions = append([]ExploitationCondition{}, closedRequired...)
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL1 || el.Basis != EvidenceBasisDeterministic {
			t.Fatalf("level = %s/%s, want L1/deterministic", el.Level, el.Basis)
		}
		if len(el.BlockingConditions) != 0 {
			t.Fatalf("blocking = %v, want none (deployment gap is not a blocker)", el.BlockingConditions)
		}
		if len(el.ConditionRefs) != len(closedRequired) {
			t.Fatalf("condition_refs = %v, want every ledger id", el.ConditionRefs)
		}
		if el.Scope == "" || el.Statement == "" || len(el.Limitations) == 0 {
			t.Fatalf("incomplete level object: %+v", el)
		}
	})

	t.Run("agent condition carrying a fact id never leaks into evidence_refs", func(t *testing.T) {
		r := mkReport()
		// A fact that no deterministic condition cites: only the forged
		// agent-origin condition references it.
		orphan := derivationFact("fact-obs-0099", "trace_argument")
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs, orphan}
		conds := append([]ExploitationCondition{}, closedRequired...)
		// An agent-origin condition that cites an existing verified-fact
		// id (forged or externally supplied) is still not a carrier: the
		// ref must stay out of evidence_level.evidence_refs, and the OPEN
		// required path hypothesis keeps blocking L1.
		conds = append(conds,
			derivationCondition("EC-0006", subjPackageReach, ConditionRolePath, OriginAgent, "required", StateOpen, orphan.ID))
		r.ExploitationConditions = conds
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
		for _, ref := range el.EvidenceRefs {
			if ref == orphan.ID {
				t.Fatal("verified-fact id cited by an agent condition leaked into evidence_refs")
			}
		}
		if !containsStr(el.ConditionRefs, "EC-0006") {
			t.Fatalf("condition_refs = %v, want the ledger to list EC-0006", el.ConditionRefs)
		}
	})

	t.Run("open required path transition is L2", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs}
		conds := append([]ExploitationCondition{}, closedRequired...)
		conds[3].State = StateUnknown // build relevance undecided
		r.ExploitationConditions = conds
		r.AttackScenario.Status = StatusPartial
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
		if len(el.BlockingConditions) != 1 || el.BlockingConditions[0] != "EC-0004" {
			t.Fatalf("blocking = %v, want [EC-0004]", el.BlockingConditions)
		}
	})

	t.Run("refuted required applicability is L2", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs}
		conds := append([]ExploitationCondition{}, closedRequired...)
		conds[1].State = StateRefuted // version outside affected ranges
		r.ExploitationConditions = conds
		if el := deriveEvidenceLevel(r); el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
	})

	t.Run("SUPPORTED condition without an allowlisted fact is L2", func(t *testing.T) {
		r := mkReport()
		gv := derivationFact("fact-obs-0020", "run_govulncheck")
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs, gv}
		conds := append([]ExploitationCondition{}, closedRequired...)
		// govulncheck is supporting evidence, never an L1 path carrier.
		conds[3].EvidenceRefs = []string{gv.ID}
		r.ExploitationConditions = conds
		if el := deriveEvidenceLevel(r); el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
	})

	t.Run("verified dynamic fact with established axis is L3", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs, dynFact}
		r.ExploitationConditions = append([]ExploitationCondition{}, closedRequired...)
		r.ExploitationAxes.ExploitationEstablished = Axis{
			Status:       AxisEstablished,
			Basis:        AxisBasisDynamic,
			Level:        LevelDynamicReproduction,
			EvidenceRefs: []string{dynFact.ID},
		}
		r.AttackScenario.Status = StatusSupported
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL3 || el.Basis != EvidenceBasisDynamic {
			t.Fatalf("level = %s/%s, want L3/dynamic", el.Level, el.Basis)
		}
		if len(el.EvidenceRefs) != 1 || el.EvidenceRefs[0] != dynFact.ID {
			t.Fatalf("L3 evidence_refs = %v, want the dynamic carrier", el.EvidenceRefs)
		}
	})

	t.Run("dynamic axis without the verified fact ref is not L3", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs, dynFact}
		r.ExploitationConditions = append([]ExploitationCondition{}, closedRequired...)
		r.ExploitationAxes.ExploitationEstablished = Axis{
			Status:       AxisEstablished,
			Basis:        AxisBasisDynamic,
			Level:        LevelDynamicReproduction,
			EvidenceRefs: []string{"obs:0060"}, // observation ref only
		}
		r.AttackScenario.Status = StatusSupported
		if el := deriveEvidenceLevel(r); el.Level == EvidenceLevelL3 {
			t.Fatal("L3 without a resolvable dynamic fact ref")
		}
	})

	t.Run("established axis with static tool ref is not L3", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs}
		r.ExploitationConditions = append([]ExploitationCondition{}, closedRequired...)
		r.ExploitationAxes.ExploitationEstablished = Axis{
			Status:       AxisEstablished,
			Basis:        AxisBasisDynamic,
			Level:        LevelDynamicReproduction,
			EvidenceRefs: []string{moduleObs.ID}, // static tool, not dynamic
		}
		r.AttackScenario.Status = StatusSupported
		if el := deriveEvidenceLevel(r); el.Level == EvidenceLevelL3 {
			t.Fatal("L3 from a non-dynamic tool ref")
		}
	})

	t.Run("agent-only material is never above L2", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = nil
		r.ExploitationConditions = []ExploitationCondition{
			derivationCondition("EC-0001", subjModulePresence, ConditionRoleApplicability, OriginDeterm, "required", StateUnknown),
			derivationCondition("EC-0002", subjPackageReach, ConditionRolePath, OriginAgent, "required", StateOpen, "A-0001"),
		}
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 || el.Basis != EvidenceBasisNone {
			t.Fatalf("level = %s/%s, want L2/none", el.Level, el.Basis)
		}
		for _, ref := range el.EvidenceRefs {
			if ref == "A-0001" {
				t.Fatal("agent assertion ref leaked into evidence_refs")
			}
		}
	})

	t.Run("open agent path hypothesis blocks L1", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs}
		conds := append([]ExploitationCondition{}, closedRequired...)
		conds = append(conds,
			derivationCondition("EC-0006", subjPackageReach, ConditionRolePath, OriginAgent, "required", StateOpen, "A-0002"))
		r.ExploitationConditions = conds
		el := deriveEvidenceLevel(r)
		if el.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want L2", el.Level)
		}
		if !containsStr(el.BlockingConditions, "EC-0006") {
			t.Fatalf("blocking = %v, want EC-0006", el.BlockingConditions)
		}
	})

	t.Run("derivation is byte-stable and ignores the stored level", func(t *testing.T) {
		r := mkReport()
		r.VerifiedFacts = []VerifiedFact{resolve, moduleObs}
		r.ExploitationConditions = append([]ExploitationCondition{}, closedRequired...)
		first := deriveEvidenceLevel(r)
		r.EvidenceLevel = &first // a stored/forged value must never feed back
		second := deriveEvidenceLevel(r)
		b1, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		b2, err := json.Marshal(second)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, second) || string(b1) != string(b2) {
			t.Fatalf("derivation not deterministic:\n%s\n%s", b1, b2)
		}
	})
}

// TestAttackStatus covers the semantics-B attack_scenario derivation on
// assembled reports: deployment-only gaps leave the scenario UNKNOWN,
// only path-role transitions can produce PARTIAL, and SUPPORTED tracks
// exploitation_established — which implies L3.
func TestAttackStatus(t *testing.T) {
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
	resolveFact := factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected")
	turn := turnWith(t, "vulnerable", "the malformed frame path may be exploitable", nil)

	t.Run("deployment-only gap stays UNKNOWN with L1", func(t *testing.T) {
		lane := laneFor(t, "golang.org/x/net", ar, nil,
			[]VerifiedFact{resolveFact})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "as-l1",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status == StatusPartial {
			t.Fatal("deployment-only unknown produced PARTIAL")
		}
		if r.AttackScenario.Status != StatusUnknown {
			t.Fatalf("attack_scenario = %s, want UNKNOWN", r.AttackScenario.Status)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
			t.Fatalf("evidence_level = %+v, want L1", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("deployment-gap report invalid:\n%v", err)
		}
	})

	t.Run("open required path transition with a confirmed one is PARTIAL+L2", func(t *testing.T) {
		gap := ar
		gap.BuildRelevant = domain.ClaimUnknown
		lane := laneFor(t, "golang.org/x/net", gap, nil,
			[]VerifiedFact{resolveFact})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "as-l2",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status != StatusPartial {
			t.Fatalf("attack_scenario = %s, want PARTIAL", r.AttackScenario.Status)
		}
		if !strings.Contains(r.AttackScenario.Summary, "exploit path is not established") {
			t.Fatalf("PARTIAL summary lacks marker: %q", r.AttackScenario.Summary)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("path-gap report invalid:\n%v", err)
		}
	})

	t.Run("verified dynamic fact yields SUPPORTED+L3", func(t *testing.T) {
		lane := laneFor(t, "golang.org/x/net", ar,
			[]*evidencetools.Observation{{
				ID: "OBS-0060", Tool: "reproduction", ToolStatus: evidencetools.StatusOK,
				Fact:         "malformed frame reproduced the panic under the recorded build context",
				Scope:        "dynamic reproduction run",
				Completeness: evidencetools.CompletenessComplete,
			}},
			[]VerifiedFact{
				resolveFact,
				factFor("OBS-0060", "reproduction", "malformed frame reproduced the panic"),
			})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "as-l3",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.AttackScenario.Status != StatusSupported {
			t.Fatalf("attack_scenario = %s, want SUPPORTED", r.AttackScenario.Status)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL3 ||
			r.EvidenceLevel.Basis != EvidenceBasisDynamic {
			t.Fatalf("evidence_level = %+v, want L3/dynamic", r.EvidenceLevel)
		}
		if !containsStr(r.EvidenceLevel.EvidenceRefs, "fact-obs-0060") {
			t.Fatalf("L3 evidence_refs = %v, want fact-obs-0060", r.EvidenceLevel.EvidenceRefs)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("dynamic-evidence report invalid:\n%v", err)
		}
	})

	t.Run("failed dynamic observation is never L3", func(t *testing.T) {
		lane := laneFor(t, "golang.org/x/net", ar,
			[]*evidencetools.Observation{{
				ID: "OBS-0061", Tool: "reproduction", ToolStatus: evidencetools.StatusError,
				Fact:         "reproduction harness failed",
				Scope:        "dynamic reproduction run",
				Completeness: evidencetools.CompletenessUnknown,
				Error:        "harness exited non-zero",
			}},
			[]VerifiedFact{resolveFact})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "as-fail",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level == EvidenceLevelL3 {
			t.Fatalf("failed dynamic observation produced %+v", r.EvidenceLevel)
		}
		if r.EvidenceLevel.Level != EvidenceLevelL1 {
			t.Fatalf("evidence_level = %+v, want L1 (closed static path, no dynamic proof)", r.EvidenceLevel)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("failed-dynamic report invalid:\n%v", err)
		}
	})

	t.Run("agent category and status never raise the level", func(t *testing.T) {
		// Same lane: OK turn, then a failed turn — the ladder is
		// identical because derivation never reads agent output.
		lane := laneFor(t, "golang.org/x/net", ar, nil, []VerifiedFact{resolveFact})
		lane.SnapshotRoot = t.TempDir()
		rOK := Assemble(AssembleInput{Lane: lane, Turn: turnWith(t, "code_not_present",
			"the defect looks unreachable", nil), RunID: "as-ok",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		lane2 := laneFor(t, "golang.org/x/net", ar, nil, []VerifiedFact{resolveFact})
		lane2.SnapshotRoot = t.TempDir()
		rFailed := Assemble(AssembleInput{Lane: lane2,
			Turn:  &AgentTurn{Output: AgentOutput{Status: AgentFailed}},
			RunID: "as-failed", StartedAt: time.Now(), FinishedAt: time.Now()})
		for _, r := range []*Report{rOK, rFailed} {
			if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
				t.Fatalf("run %s: evidence_level = %+v, want L1", r.Run.RunID, r.EvidenceLevel)
			}
		}
	})
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
