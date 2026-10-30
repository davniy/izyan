package research

import (
	"encoding/json"
	"reflect"
	"testing"
)

// stripToLegacyShape removes every extension field so the report reads
// as a legacy Slice-1 document (mirrors TestSlice2_LegacyReportStillValidates).
// The /3 members (evidence_level, condition role) must go too.
func stripToLegacyShape(r *Report) {
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
		// The package-usage fact members (kind, usage_subject,
		// negative_verification, usage_basis) postdate the legacy
		// shape: stripping them keeps a legacy fixture free of fields
		// it never produced.
		r.VerifiedFacts[i].Kind = ""
		r.VerifiedFacts[i].UsageSubject = nil
		r.VerifiedFacts[i].NegativeVerification = ""
		r.VerifiedFacts[i].UsageBasis = ""
	}
	for i := range r.EvidenceQuality.References {
		r.EvidenceQuality.References[i].Materiality = nil
	}
	for i := range r.ExploitationConditions {
		r.ExploitationConditions[i].Axis = ""
		r.ExploitationConditions[i].Role = ""
		r.ExploitationConditions[i].UsageSubject = nil
	}
	r.AgentOutput.AttemptID = nil
	r.AgentOutput.Extraction = nil
	r.AgentOutput.ResultArtifact = nil
	r.AgentOutput.AnswerArtifact = nil
}

// marshalMap returns the report as a raw JSON object for key-presence
// assertions.
func marshalMap(t *testing.T, r *Report) map[string]any {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// assertNoNewWireMembers fails if the marshaled object carries any of
// the /3 or package-usage members: top-level evidence_level, a role or
// usage_subject key inside exploitation_conditions, or a
// kind/usage_subject/negative_verification key inside verified_facts.
func assertNoNewWireMembers(t *testing.T, m map[string]any) {
	t.Helper()
	if _, present := m["evidence_level"]; present {
		t.Fatal("omitempty emitted evidence_level")
	}
	for _, raw := range m["exploitation_conditions"].([]any) {
		cond, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("exploitation_conditions entry is %T", raw)
		}
		for _, k := range []string{"role", "usage_subject"} {
			if _, present := cond[k]; present {
				t.Fatalf("omitempty emitted %s on condition %v", k, cond["id"])
			}
		}
	}
	for _, raw := range m["verified_facts"].([]any) {
		fact, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("verified_facts entry is %T", raw)
		}
		for _, k := range []string{"kind", "usage_subject", "negative_verification"} {
			if _, present := fact[k]; present {
				t.Fatalf("omitempty emitted %s on verified fact %v", k, fact["id"])
			}
		}
	}
}

// TestEvidenceLevelContract pins the slice2-fidelity/3 contract surface:
// the marker value, the closed enums, three-way marker mutual
// exclusion, and the role/evidence_level wire shape.
func TestEvidenceLevelContract(t *testing.T) {
	t.Run("marker value", func(t *testing.T) {
		if Slice2ExtensionV3 != "slice2-fidelity/3" {
			t.Fatalf("Slice2ExtensionV3 = %q, want %q", Slice2ExtensionV3, "slice2-fidelity/3")
		}
	})

	t.Run("closed enums", func(t *testing.T) {
		for got, want := range map[string]string{
			EvidenceLevelL1:            "L1_STATIC_PATH",
			EvidenceLevelL2:            "L2_POTENTIAL_PATH",
			EvidenceLevelL3:            "L3_DYNAMIC_EXPLOITATION",
			EvidenceBasisNone:          "none",
			EvidenceBasisDeterministic: "deterministic",
			EvidenceBasisDynamic:       "dynamic",
			ConditionRoleApplicability: "applicability",
			ConditionRolePath:          "path",
			ConditionRoleDeployment:    "deployment",
			ConditionRoleSupporting:    "supporting",
		} {
			if got != want {
				t.Fatalf("enum constant = %q, want %q", got, want)
			}
		}
	})

	t.Run("markers mutually exclusive", func(t *testing.T) {
		for _, combo := range [][]string{
			{Slice2ExtensionV1, Slice2ExtensionV3},
			{Slice2Extension, Slice2ExtensionV3},
			{Slice2ExtensionV1, Slice2Extension, Slice2ExtensionV3},
		} {
			r := validReport(t)
			r.ContractExtensions = combo
			if err := Validate(r, ""); err == nil {
				t.Fatalf("marker combination %v accepted", combo)
			}
		}
		// Each marker alone stays valid through its own branch.
		for _, single := range [][]string{
			{Slice2ExtensionV1},
			{Slice2Extension},
			{Slice2ExtensionV3},
		} {
			r := validReport(t)
			r.ContractExtensions = single
			if err := Validate(r, ""); err != nil {
				t.Fatalf("single marker %v rejected:\n%v", single, err)
			}
		}
	})

	t.Run("evidence_level round-trip", func(t *testing.T) {
		r := validReport(t)
		r.ContractExtensions = []string{Slice2ExtensionV3}
		factRef := r.VerifiedFacts[0].ID
		r.EvidenceLevel = &EvidenceLevel{
			Level:              EvidenceLevelL2,
			Basis:              EvidenceBasisDeterministic,
			Statement:          "path chain still open",
			Scope:              "whole report scope",
			ConditionRefs:      []string{"EC-0001"},
			EvidenceRefs:       []string{factRef},
			BlockingConditions: []string{"EC-0001"},
			Limitations:        []string{"no dynamic proof"},
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(b)
		if err != nil {
			t.Fatalf("/3 report rejected by ParseReport: %v", err)
		}
		if r2.EvidenceLevel == nil {
			t.Fatal("evidence_level lost in round-trip")
		}
		if !reflect.DeepEqual(*r2.EvidenceLevel, *r.EvidenceLevel) {
			t.Fatalf("evidence_level mismatch after round-trip:\ngot  %+v\nwant %+v",
				*r2.EvidenceLevel, *r.EvidenceLevel)
		}
	})

	t.Run("empty evidence_level slices render as arrays", func(t *testing.T) {
		r := validReport(t)
		r.ContractExtensions = []string{Slice2ExtensionV3}
		r.EvidenceLevel = &EvidenceLevel{
			Level:     EvidenceLevelL2,
			Basis:     EvidenceBasisNone,
			Statement: "path chain still open",
			Scope:     "whole report scope",
		}
		normalizeEmpty(r)
		el, ok := marshalMap(t, r)["evidence_level"].(map[string]any)
		if !ok {
			t.Fatal("evidence_level missing from marshaled /3 report")
		}
		for _, k := range []string{"condition_refs", "evidence_refs", "blocking_conditions", "limitations"} {
			v, present := el[k]
			if !present {
				t.Fatalf("evidence_level.%s absent; want []", k)
			}
			arr, isArr := v.([]any)
			if !isArr || len(arr) != 0 {
				t.Fatalf("evidence_level.%s = %v; want []", k, v)
			}
		}
	})

	t.Run("condition role round-trip", func(t *testing.T) {
		r := validReport(t)
		if len(r.ExploitationConditions) == 0 {
			t.Fatal("fixture report has no exploitation_conditions")
		}
		r.ContractExtensions = []string{Slice2ExtensionV3}
		r.ExploitationConditions[0].Role = ConditionRoleDeployment
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(b)
		if err != nil {
			t.Fatalf("report with role rejected by ParseReport: %v", err)
		}
		if r2.ExploitationConditions[0].Role != ConditionRoleDeployment {
			t.Fatalf("role = %q, want %q",
				r2.ExploitationConditions[0].Role, ConditionRoleDeployment)
		}
	})
}

// TestEvidenceLevelLegacyJSON proves the additive change does not alter
// the legacy wire shape: /1 and /2 reports keep parsing and validating
// without evidence_level or role, and omitempty never emits the new
// members on them.
func TestEvidenceLevelLegacyJSON(t *testing.T) {
	t.Run("slice-1 json without new fields parses and validates", func(t *testing.T) {
		r := validReport(t)
		stripToLegacyShape(r)
		r.ContractExtensions = nil
		m := marshalMap(t, r)
		assertNoNewWireMembers(t, m)
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(b)
		if err != nil {
			t.Fatalf("legacy report rejected by ParseReport: %v", err)
		}
		if r2.EvidenceLevel != nil {
			t.Fatal("legacy parse produced evidence_level")
		}
		for _, c := range r2.ExploitationConditions {
			if c.Role != "" {
				t.Fatalf("legacy parse produced role %q on %s", c.Role, c.ID)
			}
		}
		if err := Validate(r2, ""); err != nil {
			t.Fatalf("legacy report rejected:\n%v", err)
		}
	})

	t.Run("/1-advertised json without new fields parses and validates", func(t *testing.T) {
		// /1 reports carry the shared slice-2 fields (axes, basis,
		// condition axis tags) but no /3 members: role and
		// evidence_level are stripped to simulate a persisted /1
		// document, then the marker is swapped to /1.
		r := validReport(t)
		r.EvidenceLevel = nil
		for i := range r.ExploitationConditions {
			r.ExploitationConditions[i].Role = ""
			r.ExploitationConditions[i].UsageSubject = nil
		}
		r.ContractExtensions = []string{Slice2ExtensionV1}
		m := marshalMap(t, r)
		assertNoNewWireMembers(t, m)
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(b)
		if err != nil {
			t.Fatalf("/1 report rejected by ParseReport: %v", err)
		}
		if r2.EvidenceLevel != nil {
			t.Fatal("/1 parse produced evidence_level")
		}
		if err := Validate(r2, ""); err != nil {
			t.Fatalf("/1-advertised report rejected:\n%v", err)
		}
	})

	t.Run("/2 report without new fields still validates", func(t *testing.T) {
		r := validReport(t)
		// Simulate a persisted /2 report: the assembler now emits /3
		// members, so strip them and re-mark as /2.
		r.EvidenceLevel = nil
		for i := range r.ExploitationConditions {
			r.ExploitationConditions[i].Role = ""
			r.ExploitationConditions[i].UsageSubject = nil
		}
		r.ContractExtensions = []string{Slice2Extension}
		if r.EvidenceLevel != nil {
			t.Fatal("assembled /2 report already has evidence_level")
		}
		for i := range r.ExploitationConditions {
			if r.ExploitationConditions[i].Role != "" {
				t.Fatalf("assembled /2 condition %s already has role", r.ExploitationConditions[i].ID)
			}
		}
		m := marshalMap(t, r)
		assertNoNewWireMembers(t, m)
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(b)
		if err != nil {
			t.Fatalf("/2 report rejected by ParseReport: %v", err)
		}
		if err := Validate(r2, ""); err != nil {
			t.Fatalf("/2 report without new fields rejected:\n%v", err)
		}
	})
}
