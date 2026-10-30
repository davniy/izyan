package research

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// ---- /3 validator fixtures ----

// v3ApplicableResult is the fully-confirmed applicability chain shared
// by the /3 validator fixtures: every deterministic applicability/path
// predicate is TRUE, so the only open required condition is the
// deployment-scope runtime posture (which never blocks L1).
func v3ApplicableResult() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	}
}

// v3ResolveFact is the affected-resolve carrier every fixture cites.
func v3ResolveFact() VerifiedFact {
	return factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected")
}

// v3Turn is a benign OK agent turn: it contributes a classification
// assertion but no attack-scenario claims.
func v3Turn(t *testing.T) *AgentTurn {
	return turnWith(t, "vulnerable", "the malformed frame path may be exploitable", nil)
}

// v3L1Report assembles a valid /3 report at L1: the deterministic
// applicability/path conditions are closed by static carrier facts and
// the runtime posture stays an open deployment gap.
func v3L1Report(t *testing.T) *Report {
	t.Helper()
	lane := laneFor(t, "golang.org/x/net", v3ApplicableResult(), nil,
		[]VerifiedFact{v3ResolveFact()})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: v3Turn(t), RunID: "v3-l1",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
		t.Fatalf("fixture: evidence_level = %+v, want L1", r.EvidenceLevel)
	}
	return r
}

// v3L2Report assembles a valid /3 report at L2 with a genuine path-role
// gap: build relevance stays UNKNOWN, so one confirmed deterministic
// path transition plus one open required path transition yields
// PARTIAL + L2.
func v3L2Report(t *testing.T) *Report {
	t.Helper()
	ar := v3ApplicableResult()
	ar.BuildRelevant = domain.ClaimUnknown
	lane := laneFor(t, "golang.org/x/net", ar, nil,
		[]VerifiedFact{v3ResolveFact()})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: v3Turn(t), RunID: "v3-l2",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.AttackScenario.Status != StatusPartial ||
		r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
		t.Fatalf("fixture: attack=%s evidence_level=%+v, want PARTIAL+L2",
			r.AttackScenario.Status, r.EvidenceLevel)
	}
	return r
}

// v3L3Report assembles a valid /3 report at L3: an OK reproduction
// observation promoted to a verified fact establishes the dynamic axis
// and the SUPPORTED scenario.
func v3L3Report(t *testing.T) *Report {
	t.Helper()
	lane := laneFor(t, "golang.org/x/net", v3ApplicableResult(),
		[]*evidencetools.Observation{{
			ID: "OBS-0060", Tool: "reproduction", ToolStatus: evidencetools.StatusOK,
			Fact:         "malformed frame reproduced the panic under the recorded build context",
			Scope:        "dynamic reproduction run",
			Completeness: evidencetools.CompletenessComplete,
		}},
		[]VerifiedFact{
			v3ResolveFact(),
			factFor("OBS-0060", "reproduction", "malformed frame reproduced the panic"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: v3Turn(t), RunID: "v3-l3",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL3 ||
		r.AttackScenario.Status != StatusSupported {
		t.Fatalf("fixture: attack=%s evidence_level=%+v, want SUPPORTED+L3",
			r.AttackScenario.Status, r.EvidenceLevel)
	}
	return r
}

// v3AgentPathReport assembles a valid /3 report at L2 whose only gap is
// an agent canonical path hypothesis: normalized to role=path,
// necessity=required, state=OPEN — a hypothesis that blocks L1 but can
// never produce PARTIAL or carry evidence.
func v3AgentPathReport(t *testing.T) *Report {
	t.Helper()
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
	lane := laneFor(t, "golang.org/x/net", v3ApplicableResult(), nil,
		[]VerifiedFact{v3ResolveFact()})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "v3-agent-path",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 ||
		len(r.EvidenceLevel.BlockingConditions) == 0 {
		t.Fatalf("fixture: evidence_level = %+v, want L2 with blockers", r.EvidenceLevel)
	}
	return r
}

// agentPathCondition returns the normalized agent-origin path condition
// of a v3AgentPathReport fixture.
func agentPathCondition(t *testing.T, r *Report) *ExploitationCondition {
	t.Helper()
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Origin == OriginAgent && c.Role == ConditionRolePath {
			return c
		}
	}
	t.Fatal("fixture: no agent path condition")
	return nil
}

// assertV3Rejected validates r and requires a violation containing
// wantSub — the specific /3 rule must fire, not just any error.
func assertV3Rejected(t *testing.T, r *Report, wantSub string) {
	t.Helper()
	err := Validate(r, "")
	if err == nil {
		t.Fatalf("forged report accepted; expected violation containing %q", wantSub)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("violation %q not found in:\n%v", wantSub, err)
	}
}

// ---- positive cases ----

// TestSlice2V3_Validator proves the assembled ladder at every level
// passes the /3 branch, and that a /3 report survives a full JSON
// round-trip without drift.
func TestSlice2V3_Validator(t *testing.T) {
	t.Run("assembled L1 validates", func(t *testing.T) {
		if err := Validate(v3L1Report(t), ""); err != nil {
			t.Fatalf("L1 report rejected:\n%v", err)
		}
	})

	t.Run("assembled L2 validates", func(t *testing.T) {
		if err := Validate(v3L2Report(t), ""); err != nil {
			t.Fatalf("L2 report rejected:\n%v", err)
		}
	})

	t.Run("assembled L3 validates", func(t *testing.T) {
		if err := Validate(v3L3Report(t), ""); err != nil {
			t.Fatalf("L3 report rejected:\n%v", err)
		}
	})

	t.Run("L2 with agent path hypothesis validates", func(t *testing.T) {
		if err := Validate(v3AgentPathReport(t), ""); err != nil {
			t.Fatalf("agent-path L2 report rejected:\n%v", err)
		}
	})

	t.Run("/3 report round-trips through JSON and validates", func(t *testing.T) {
		b, err := json.Marshal(v3L3Report(t))
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(b)
		if err != nil {
			t.Fatalf("/3 report rejected by ParseReport: %v", err)
		}
		if err := Validate(r2, ""); err != nil {
			t.Fatalf("round-tripped /3 report rejected:\n%v", err)
		}
	})
}

// ---- negative cases (design §7.5) ----

// TestEvidenceLevelValidator exercises the fail-closed /3 branch: every
// forged or inconsistent ladder state is rejected with the specific
// rule that catches it — a mismatch, never a silent downgrade.
func TestEvidenceLevelValidator(t *testing.T) {
	t.Run("/3 requires evidence_level", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel = nil
		assertV3Rejected(t, r, "evidence_level is required under slice2-fidelity/3")
	})

	t.Run("forged L1 over an open required path transition", func(t *testing.T) {
		r := v3L2Report(t) // required path condition stays UNKNOWN
		el := deriveEvidenceLevel(r)
		el.Level = EvidenceLevelL1
		r.EvidenceLevel = &el
		assertV3Rejected(t, r, "does not match recomputed")
	})

	t.Run("forged L1 with unresolved evidence ref", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel.EvidenceRefs = append(r.EvidenceLevel.EvidenceRefs, "fact-obs-9999")
		assertV3Rejected(t, r, `evidence_level.evidence_refs "fact-obs-9999" is not a verified fact`)
	})

	t.Run("forged L1 with agent-source ref", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel.EvidenceRefs = append(r.EvidenceLevel.EvidenceRefs, "agent-src:final-answer")
		assertV3Rejected(t, r, "agent-origin ref")
	})

	t.Run("forged L1 with agent assertion ref", func(t *testing.T) {
		r := v3L1Report(t)
		if len(r.AgentAssertions) == 0 {
			t.Fatal("fixture: no agent assertions")
		}
		r.EvidenceLevel.EvidenceRefs = append(r.EvidenceLevel.EvidenceRefs, r.AgentAssertions[0].ID)
		assertV3Rejected(t, r, "agent-origin ref")
	})

	t.Run("forged L3 without a dynamic verified fact", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel.Level = EvidenceLevelL3
		r.EvidenceLevel.Basis = EvidenceBasisDynamic
		assertV3Rejected(t, r, "not a dynamic-carrier fact")
	})

	t.Run("forged L3 with empty evidence refs", func(t *testing.T) {
		r := v3L3Report(t)
		r.EvidenceLevel.EvidenceRefs = nil
		assertV3Rejected(t, r, "at least one evidence_ref resolving to a verified fact from a dynamic tool")
	})

	t.Run("forged L3 on a failed dynamic observation", func(t *testing.T) {
		lane := laneFor(t, "golang.org/x/net", v3ApplicableResult(),
			[]*evidencetools.Observation{{
				ID: "OBS-0061", Tool: "reproduction", ToolStatus: evidencetools.StatusError,
				Fact:         "reproduction harness failed",
				Scope:        "dynamic reproduction run",
				Completeness: evidencetools.CompletenessUnknown,
				Error:        "harness exited non-zero",
			}},
			[]VerifiedFact{v3ResolveFact()})
		lane.SnapshotRoot = t.TempDir()
		r := Assemble(AssembleInput{Lane: lane, Turn: v3Turn(t), RunID: "v3-l3-fail",
			StartedAt: time.Now(), FinishedAt: time.Now()})
		// Forge the whole L3 surface around the failed observation: an
		// obs: ref is never a verified fact, so it cannot carry L3.
		r.ExploitationAxes.ExploitationEstablished = Axis{
			Status: AxisEstablished, Basis: AxisBasisDynamic,
			Level:        LevelDynamicReproduction,
			Statement:    "forged",
			EvidenceRefs: []string{"obs:OBS-0061"},
		}
		r.AttackScenario.Status = StatusSupported
		r.EvidenceLevel.Level = EvidenceLevelL3
		r.EvidenceLevel.Basis = EvidenceBasisDynamic
		r.EvidenceLevel.EvidenceRefs = []string{"obs:OBS-0061"}
		assertV3Rejected(t, r, `evidence_level.evidence_refs "obs:OBS-0061" is not a verified fact`)
	})

	t.Run("forged L3 with deterministic axis basis", func(t *testing.T) {
		r := v3L3Report(t)
		r.ExploitationAxes.ExploitationEstablished.Basis = AxisBasisDeterministic
		assertV3Rejected(t, r, "level=L3 requires exploitation_axes.exploitation_established status=ESTABLISHED basis=dynamic level=DYNAMIC_REPRODUCTION")
	})

	t.Run("L3 without attack_scenario SUPPORTED", func(t *testing.T) {
		r := v3L3Report(t)
		r.AttackScenario.Status = StatusUnknown
		r.AttackScenario.Summary = unknownSummary("forged scenario gap", "re-run the dynamic check")
		assertV3Rejected(t, r, "level=L3 requires attack_scenario.status=SUPPORTED")
	})

	t.Run("SUPPORTED at L1", func(t *testing.T) {
		r := v3L1Report(t)
		r.AttackScenario.Status = StatusSupported
		assertV3Rejected(t, r, "attack_scenario.status=SUPPORTED requires evidence_level.level=L3_DYNAMIC_EXPLOITATION")
	})

	t.Run("SUPPORTED at L2", func(t *testing.T) {
		r := v3L2Report(t)
		r.AttackScenario.Status = StatusSupported
		assertV3Rejected(t, r, "attack_scenario.status=SUPPORTED requires evidence_level.level=L3_DYNAMIC_EXPLOITATION")
	})

	t.Run("PARTIAL at L1", func(t *testing.T) {
		r := v3L1Report(t)
		r.AttackScenario.Status = StatusPartial
		r.AttackScenario.Summary = "PARTIAL: the exploit path is not established — forged"
		assertV3Rejected(t, r, "attack_scenario.status=PARTIAL requires evidence_level.level=L2_POTENTIAL_PATH")
	})

	t.Run("PARTIAL at L3", func(t *testing.T) {
		r := v3L3Report(t)
		r.AttackScenario.Status = StatusPartial
		r.AttackScenario.Summary = "PARTIAL: the exploit path is not established — forged"
		assertV3Rejected(t, r, "attack_scenario.status=PARTIAL requires evidence_level.level=L2_POTENTIAL_PATH")
	})

	t.Run("PARTIAL cannot rest on a deployment gap alone", func(t *testing.T) {
		// The only unresolved required condition is the deployment-scope
		// runtime posture: PARTIAL demands a role=path gap.
		r := v3L1Report(t)
		r.AttackScenario.Status = StatusPartial
		r.AttackScenario.Summary = "PARTIAL: the exploit path is not established — forged"
		assertV3Rejected(t, r, "unresolved required role=path condition")
	})

	t.Run("PARTIAL cannot rest on an agent hypothesis", func(t *testing.T) {
		// The only open path condition is an agent-origin OPEN
		// hypothesis — never a confirmed-transition gap for PARTIAL.
		r := v3AgentPathReport(t)
		r.AttackScenario.Status = StatusPartial
		r.AttackScenario.Summary = "PARTIAL: the exploit path is not established — forged"
		assertV3Rejected(t, r, "unresolved required role=path condition")
	})

	t.Run("unknown level/basis/role values rejected", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel.Level = "L4_TOTAL_PROOF"
		assertV3Rejected(t, r, `evidence_level.level "L4_TOTAL_PROOF" invalid`)

		r = v3L1Report(t)
		r.EvidenceLevel.Basis = "agent"
		assertV3Rejected(t, r, `evidence_level.basis "agent" invalid`)

		r = v3L1Report(t)
		r.ExploitationConditions[0].Role = "carrier"
		assertV3Rejected(t, r, `role "carrier" invalid`)
	})

	t.Run("mismatch between recomputed and asserted evidence_level", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel.Statement = "forged narrative"
		assertV3Rejected(t, r, "evidence_level.statement")

		r = v3L1Report(t)
		r.EvidenceLevel.BlockingConditions = []string{"EC-0001"}
		assertV3Rejected(t, r, "evidence_level.blocking_conditions")

		// Dropping one fact ref is a violation, never a downgrade.
		r = v3L1Report(t)
		r.EvidenceLevel.EvidenceRefs = nil
		assertV3Rejected(t, r, "evidence_level.evidence_refs")

		// Substituting one fact ref for another resolving fact is still
		// a mismatch — the recomputed list is verbatim.
		r = v3L1Report(t)
		r.EvidenceLevel.EvidenceRefs[0] = "fact-obs-0001"
		assertV3Rejected(t, r, "do not match recomputed")

		r = v3L3Report(t)
		r.EvidenceLevel.Limitations = []string{"forged"}
		assertV3Rejected(t, r, "evidence_level.limitations")
	})

	t.Run("condition_refs duplicates and dangling ids rejected", func(t *testing.T) {
		r := v3L1Report(t)
		r.EvidenceLevel.ConditionRefs = append(r.EvidenceLevel.ConditionRefs,
			r.EvidenceLevel.ConditionRefs[0])
		assertV3Rejected(t, r, "duplicate id")

		r = v3L1Report(t)
		r.EvidenceLevel.ConditionRefs = append(r.EvidenceLevel.ConditionRefs, "EC-9999")
		assertV3Rejected(t, r, "does not resolve to an exploitation_conditions id")

		r = v3L1Report(t)
		r.EvidenceLevel.ConditionRefs = nil
		assertV3Rejected(t, r, "condition_refs must be non-empty")

		r = v3L1Report(t)
		r.EvidenceLevel.BlockingConditions = []string{"EC-9999"}
		assertV3Rejected(t, r, "not listed in condition_refs")
	})
	t.Run("agent condition citing non-agent material rejected", func(t *testing.T) {
		// An agent hypothesis may only reference its own assertion
		// material — never a resolvable verified fact, observation or
		// advisory ref, which would let it act as a carrier.
		for _, ref := range []string{"fact-obs-0001", "obs:OBS-0001", "adv:GO-TEST-0001"} {
			r := v3L1Report(t)
			r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
				ID: "EC-9001", Subject: "attacker delivers a malformed frame",
				Role: ConditionRoleSupporting, Origin: OriginAgent,
				Necessity: "unknown", State: StateOpen,
				Statement:    "forged agent hypothesis citing deterministic evidence",
				EvidenceRefs: []string{ref},
			})
			assertV3Rejected(t, r, "must reference agent material")
			// The deterministic ref never reaches the ladder refs.
			for _, elRef := range r.EvidenceLevel.EvidenceRefs {
				if elRef == ref {
					t.Fatalf("ref %q present in evidence_level.evidence_refs", ref)
				}
			}
		}
		// A legitimate agent condition citing its paired assertion stays
		// accepted (v3AgentPathReport already carries such conditions).
		if err := Validate(v3AgentPathReport(t), ""); err != nil {
			t.Fatalf("agent-material refs rejected:\n%v", err)
		}
	})

	t.Run("role matrix rejects forged roles", func(t *testing.T) {
		// Deterministic condition with a wrong role.
		r := v3L1Report(t)
		conditionOf(r, subjPackageReach).Role = ConditionRoleApplicability
		assertV3Rejected(t, r, "invalid (requires path)")

		// Agent canonical path hypothesis must stay path/OPEN/required.
		r = v3AgentPathReport(t)
		agentPathCondition(t, r).Role = ConditionRoleDeployment
		assertV3Rejected(t, r, "requires role=path state=OPEN necessity=required")

		r = v3AgentPathReport(t)
		agentPathCondition(t, r).State = StateSupported
		assertV3Rejected(t, r, "requires role=path state=OPEN necessity=required")

		r = v3AgentPathReport(t)
		agentPathCondition(t, r).Necessity = "supporting"
		assertV3Rejected(t, r, "requires role=path state=OPEN necessity=required")

		// Non-canonical agent claim must stay role=supporting.
		r = v3AgentPathReport(t)
		for i := range r.ExploitationConditions {
			c := &r.ExploitationConditions[i]
			if c.Origin == OriginAgent && c.Role == ConditionRoleSupporting {
				c.Role = ConditionRolePath
			}
		}
		assertV3Rejected(t, r, "requires role=supporting")

		// A missing role is not a valid /3 role.
		r = v3L1Report(t)
		r.ExploitationConditions[0].Role = ""
		assertV3Rejected(t, r, `role "" invalid`)
	})

	t.Run("basis cross-rules", func(t *testing.T) {
		// L1/L2 can never claim a dynamic basis.
		r := v3L1Report(t)
		r.EvidenceLevel.Basis = EvidenceBasisDynamic
		assertV3Rejected(t, r, "basis=dynamic is only valid with level=L3_DYNAMIC_EXPLOITATION")

		r = v3L2Report(t)
		r.EvidenceLevel.Basis = EvidenceBasisDynamic
		assertV3Rejected(t, r, "basis=dynamic is only valid with level=L3_DYNAMIC_EXPLOITATION")

		// L3 demands the dynamic basis.
		r = v3L3Report(t)
		r.EvidenceLevel.Basis = EvidenceBasisDeterministic
		assertV3Rejected(t, r, "level=L3 requires basis=dynamic")
	})
}

// ---- dispatch ----

// TestSlice2V3_ExtensionDispatch pins three-way marker exclusivity and
// proves the /3 rules never leak into the /1 or /2 branches: reports
// advertising only the older markers keep validating byte-for-byte
// under their own rules, even when /3 members are present.
func TestSlice2V3_ExtensionDispatch(t *testing.T) {
	t.Run("every marker combination is rejected", func(t *testing.T) {
		for _, combo := range [][]string{
			{Slice2ExtensionV1, Slice2Extension},
			{Slice2ExtensionV1, Slice2ExtensionV3},
			{Slice2Extension, Slice2ExtensionV3},
			{Slice2ExtensionV1, Slice2Extension, Slice2ExtensionV3},
		} {
			r := v3L1Report(t)
			r.ContractExtensions = combo
			if err := Validate(r, ""); err == nil {
				t.Fatalf("marker combination %v accepted", combo)
			}
		}
	})

	t.Run("a duplicated marker is rejected", func(t *testing.T) {
		// The contract carries exactly one marker: listing the same
		// recognized marker twice is a violation, not a no-op.
		for _, marker := range []string{Slice2ExtensionV1, Slice2Extension, Slice2ExtensionV3} {
			r := v3L1Report(t)
			r.ContractExtensions = []string{marker, marker}
			assertV3Rejected(t, r, "listed twice")
		}
	})

	t.Run("/3-marked reports run the v3 branch", func(t *testing.T) {
		r := v3L1Report(t)
		if err := Validate(r, ""); err != nil {
			t.Fatalf("/3 report rejected:\n%v", err)
		}
		// The same report re-marked /3 without evidence_level fails —
		// the v3 branch, not /2, produces this error.
		r.EvidenceLevel = nil
		assertV3Rejected(t, r, "evidence_level is required")
	})

	t.Run("/3 rules do not leak into /1 or /2", func(t *testing.T) {
		// Reports advertising only the legacy markers validate under
		// their own rules; /3 members on them are inert data.
		for _, marker := range []string{Slice2ExtensionV1, Slice2Extension} {
			r := v3L1Report(t)
			r.ContractExtensions = []string{marker}
			if err := Validate(r, ""); err != nil {
				t.Fatalf("%s-marked report rejected:\n%v", marker, err)
			}
		}
		// And stripped back to persisted /1//2 shape they still pass.
		for _, marker := range []string{Slice2ExtensionV1, Slice2Extension} {
			r := v3L1Report(t)
			r.EvidenceLevel = nil
			for i := range r.ExploitationConditions {
				r.ExploitationConditions[i].Role = ""
			}
			r.ContractExtensions = []string{marker}
			if err := Validate(r, ""); err != nil {
				t.Fatalf("%s-marked stripped report rejected:\n%v", marker, err)
			}
		}
	})
}
