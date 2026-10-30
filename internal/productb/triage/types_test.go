package triage

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAssessmentRoundTrip(t *testing.T) {
	original := Assessment{
		SchemaVersion: AssessmentSchemaVersion,
		FindingID:      "scanner-123",
		Verdict:        VerdictNotExploitable,
		VerdictSubtype: "no_exploit_path_found",
		VerdictSource:  "agent",
		Summary:        "module is not imported",
		Mechanism:      "vulnerable function is never reached",
		FactValidation: ValidationPartial,
		FactValidationDetail: &FactValidation{
			Status:      ValidationPartial,
			References:  []ReferenceCheck{{EvidenceID: "ev-1", Status: FactValid, Locator: "pkg/parser/parse.go:42-57"}},
			Limitations: []string{"sbom absent"},
		},
		Claims: []Claim{
			{
				ID:               "claim-1",
				Statement:        "vulnerable symbol is not present",
				Basis:            PremiseMeasured,
				Subject:          "symbol presence",
				Scope:            "pkg/parser",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1", "ev-2"},
				DependsOn:        []string{"claim-2"},
				Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-1"},
			},
			{
				ID:               "claim-2",
				Statement:        "advisory lists version 1.4.2",
				Basis:            PremiseAssumed,
				Subject:          "advisory version",
				Scope:            "advisory record",
				DecisionRelevant: true,
				Owner:            "security-team",
			},
		},
		Evidence: []EvidenceRef{
			{
				ID:      "ev-1",
				Kind:    "source_span",
				Locator: "pkg/parser/parse.go:42-57",
				Quote:   "func Parse()",
				SHA256:  strings.Repeat("a", 64),
			},
			{ID: "ev-2", Kind: "advisory_id"},
		},
		Unknowns: []Unknown{
			{ID: "u-1", Description: "no SBOM provided", Reason: "artifact absent"},
		},
		Counterarguments: []Counterargument{
			{ID: "ca-1", Statement: "dependency could be vendored", Response: "the module graph names the resolved artifact", PremiseIDs: []string{"claim-1"}},
		},
		ProposedAction: HumanAction{
			Kind:             HumanActionClose,
			Instruction:      "close as not exploitable",
			Rationale:        "the vulnerable symbol is absent from the captured build",
			Scope:            "captured build",
			RecordIDs:        []string{"CVE-2099-0001"},
			DecisiveClaimIDs: []string{"claim-1"},
			ReconsiderWhen:   []string{"a vendored copy of the symbol is captured"},
		},
		Audit: &AssessmentAudit{
			FindingHash:    "in-hash",
			SnapshotHash:   "snap-hash",
			PromptHash:     "prompt-hash",
			ResponseHash:   "resp-hash",
			AssessmentHash: "assess-hash",
			Model:          "model-x",
			ToolVersions:   map[string]string{"read_file": "1"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Assessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v", decoded, original)
	}
}

func TestFindingContractToolchain(t *testing.T) {
	filled, err := json.Marshal(Finding{Target: Target{Toolchain: "go1.25.8"}})
	if err != nil {
		t.Fatalf("marshal filled: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(filled, &doc); err != nil {
		t.Fatalf("unmarshal filled: %v", err)
	}
	target, ok := doc["target"].(map[string]any)
	if !ok {
		t.Fatalf("target missing in marshaled finding: %s", filled)
	}
	if got := target["toolchain"]; got != "go1.25.8" {
		t.Fatalf("toolchain = %v, want %q", got, "go1.25.8")
	}

	empty, err := json.Marshal(Finding{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	var emptyDoc map[string]any
	if err := json.Unmarshal(empty, &emptyDoc); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if target, ok := emptyDoc["target"].(map[string]any); ok {
		if _, present := target["toolchain"]; present {
			t.Fatalf("empty toolchain must be omitted, got %s", empty)
		}
	}

	var parsed Finding
	const record = `{"schema_version":"finding.v1","finding_id":"f-1","target":{"toolchain":"go1.25.8"}}`
	if err := json.Unmarshal([]byte(record), &parsed); err != nil {
		t.Fatalf("parse finding.v1: %v", err)
	}
	if parsed.Target.Toolchain != "go1.25.8" {
		t.Fatalf("parsed toolchain = %q", parsed.Target.Toolchain)
	}
}

func TestVerdictRoundTrip(t *testing.T) {
	for _, v := range []Verdict{VerdictExploitable, VerdictNotExploitable, VerdictInconclusive} {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %q: %v", v, err)
		}
		var decoded Verdict
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal %q: %v", v, err)
		}
		if decoded != v {
			t.Fatalf("round trip: got %q, want %q", decoded, v)
		}
	}
}

func TestFactStatusRoundTrip(t *testing.T) {
	all := []FactStatus{
		FactValid, FactUnavailable, FactUnreferenced, FactInvalid, FactConflicting,
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 fact statuses, got %d", len(all))
	}
	for _, s := range all {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %q: %v", s, err)
		}
		var decoded FactStatus
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal %q: %v", s, err)
		}
		if decoded != s {
			t.Fatalf("round trip: got %q, want %q", decoded, s)
		}
	}
}

func TestStatusEnumsRoundTrip(t *testing.T) {
	for _, s := range []FactValidationStatus{ValidationComplete, ValidationPartial, ValidationFailed} {
		var decoded FactValidationStatus
		roundTripString(t, s, &decoded)
		if decoded != s {
			t.Fatalf("got %q, want %q", decoded, s)
		}
	}
	for _, s := range []AutomationStatus{AutomationAllow, AutomationWarn, AutomationBlock} {
		var decoded AutomationStatus
		roundTripString(t, s, &decoded)
		if decoded != s {
			t.Fatalf("got %q, want %q", decoded, s)
		}
	}
}

func roundTripString(t *testing.T, in any, out any) {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestInvalidEnumRejected(t *testing.T) {
	t.Run("legacy verdict not accepted", func(t *testing.T) {
		for _, legacy := range []string{"NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND", "FALSE", "UNKNOWN"} {
			var a Assessment
			err := json.Unmarshal([]byte(`{"verdict":"`+legacy+`"}`), &a)
			if err == nil {
				t.Fatalf("verdict %q must be rejected", legacy)
			}
		}
	})
	t.Run("unknown fact status rejected", func(t *testing.T) {
		var v struct {
			S FactStatus `json:"s"`
		}
		if err := json.Unmarshal([]byte(`{"s":"FALSE"}`), &v); err == nil {
			t.Fatal("FactStatus FALSE must be rejected")
		}
	})
	t.Run("unknown fact validation rejected", func(t *testing.T) {
		var a Assessment
		if err := json.Unmarshal([]byte(`{"fact_validation":"GREEN"}`), &a); err == nil {
			t.Fatal("invalid fact_validation must be rejected")
		}
	})
	t.Run("retired automation fields rejected by live ingress", func(t *testing.T) {
		// The CI policy outcome moved to the decision package's machine
		// disposition; a model that still supplies it is rejected rather
		// than silently accepted as an unknown field.
		for _, field := range []string{"automation", "automation_reason"} {
			body := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f","verdict":"INCONCLUSIVE","` + field + `":"APPROVE"}`
			if _, err := DecodeAssessment(body, "f"); err == nil {
				t.Fatalf("the retired %s field must be rejected by live ingress", field)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Falsifier proposals (assessment.v2 ingress)
// ---------------------------------------------------------------------------

// falsifierAssessmentHead/Tail wrap a falsifier_proposals array in a minimal
// valid assessment: one declared claim (c1) citing declared evidence (e1),
// plus declared evidence entries for multi-ref proposals — e1/e2 are
// file citation that a proposal evidence_ref must not accept, and e4 carries
// a sha256-suffixed det: locator, which is equally off-contract.
const falsifierAssessmentHead = `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s","claims":[{"id":"c1","statement":"vulnerable interceptor never registered","basis":"INTERPRETED","subject":"interceptor registration","scope":"captured snapshot","decision_relevant":true,"evidence_refs":["e1"]}],"evidence":[{"id":"e1","kind":"observation","locator":"det:det-0003"},{"id":"e2","kind":"observation","locator":"det:det-0004"},{"id":"e3","kind":"file","locator":"go.mod"},{"id":"e4","kind":"observation","locator":"det:det-0005@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"proposed_action":{"kind":"KEEP_OPEN","instruction":"keep the ticket open pending verification","rationale":"the proposal would let the verifier settle the absence question","scope":"captured snapshot","decisive_claim_ids":["c1"],"reconsider_when":["the verifier admits or rejects the proposal"]},"falsifier_proposals":[`
const falsifierAssessmentTail = `]}`

const validFalsifierProposalJSON = `{"id":"fp-1","claim_id":"c1","condition_id":"C-AUTHZ-MANDATORY","kind":"code_absent","subjects":[{"package":"example.org/product/auth","symbol":"PathAuthorizationInterceptor","role":"mandatory-control"}],"evidence_refs":["e1","e2"]}`

// TestFalsifierProposalAccepted: a well-formed proposal — several subjects
// with roles, evidence_refs bound to declared evidence — survives the
// assessment ingress and is stored verbatim as a proposal only: no
// verification state is created or inferred from it.
func TestFalsifierProposalAccepted(t *testing.T) {
	twoSubjects := `{"id":"fp-1","claim_id":"c1","condition_id":"C-AUTHZ-MANDATORY","kind":"code_absent","subjects":[{"package":"example.org/product/auth","symbol":"PathAuthorizationInterceptor","role":"mandatory-control"},{"package":"example.org/product/auth","symbol":"RegisterPathAuthorizationInterceptor"}],"evidence_refs":["e1","e2"]}`
	second := `{"id":"fp-2","claim_id":"c1","condition_id":"C-CALL-MANDATORY","kind":"locus_function_unreached","subjects":[{"package":"example.org/product/core","symbol":"Dispatch"}],"evidence_refs":["e1"]}`
	a, err := decodeAssessment(falsifierAssessmentHead+twoSubjects+","+second+falsifierAssessmentTail, "scanner-123")
	if err != nil {
		t.Fatalf("valid falsifier proposals must decode: %v", err)
	}
	if len(a.FalsifierProposals) != 2 {
		t.Fatalf("proposals = %+v", a.FalsifierProposals)
	}
	fp := a.FalsifierProposals[0]
	if fp.ID != "fp-1" || fp.ClaimID != "c1" || fp.ConditionID != "C-AUTHZ-MANDATORY" || fp.Kind != FalsifierCodeAbsent {
		t.Fatalf("proposal identity not preserved: %+v", fp)
	}
	if len(fp.Subjects) != 2 ||
		fp.Subjects[0].Package != "example.org/product/auth" ||
		fp.Subjects[0].Symbol != "PathAuthorizationInterceptor" ||
		fp.Subjects[0].Role != "mandatory-control" ||
		fp.Subjects[1].Symbol != "RegisterPathAuthorizationInterceptor" ||
		fp.Subjects[1].Role != "" {
		t.Fatalf("subjects not preserved: %+v", fp.Subjects)
	}
	if len(fp.EvidenceRefs) != 2 || fp.EvidenceRefs[0] != "e1" || fp.EvidenceRefs[1] != "e2" {
		t.Fatalf("evidence refs not preserved: %v", fp.EvidenceRefs)
	}
	if a.FalsifierProposals[1].Kind != FalsifierLocusFunctionAbsent {
		t.Fatalf("second proposal kind = %q", a.FalsifierProposals[1].Kind)
	}

	// A proposal round-trips through assessment.json unchanged.
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Assessment
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if !reflect.DeepEqual(a.FalsifierProposals, back.FalsifierProposals) {
		t.Fatalf("proposal round trip mismatch:\n got: %+v\nwant: %+v", back.FalsifierProposals, a.FalsifierProposals)
	}
}

// TestFalsifierProposalRejected pins the strict proposal boundary at the
// assessment ingress: malformed or underspecified proposals fail decode,
// and every self-declared verification field (status, verified, mandatory,
// coverage, negative_verification, recommendation, verdict) is refused —
// never normalized into a trusted value.
func TestFalsifierProposalRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		proposals string
		want      string
	}{
		{
			"duplicate proposal id",
			validFalsifierProposalJSON + `,` + validFalsifierProposalJSON,
			`duplicate`,
		},
		{
			"unknown kind",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"module_absent","subjects":[{"package":"p","symbol":"s"}]}`,
			`kind`,
		},
		{
			"missing id",
			`{"claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}]}`,
			`"id"`,
		},
		{
			"missing claim_id",
			`{"id":"fp-1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}]}`,
			`claim_id`,
		},
		{
			"empty claim_id",
			`{"id":"fp-1","claim_id":" ","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}]}`,
			`claim_id`,
		},
		{
			"missing condition_id",
			`{"id":"fp-1","claim_id":"c1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}]}`,
			`condition_id`,
		},
		{
			"empty subjects",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[]}`,
			`subjects`,
		},
		{
			"subject without package",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"symbol":"s"}]}`,
			`package`,
		},
		{
			"subject without symbol",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p"}]}`,
			`symbol`,
		},
		{
			"unknown proposal field",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"commentary":"trust me"}`,
			`commentary`,
		},
		{
			"agent-supplied status",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"status":"VERIFIED"}`,
			`"status"`,
		},
		{
			"agent-supplied verified",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"verified":true}`,
			`"verified"`,
		},
		{
			"agent-supplied mandatory",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"mandatory":true}`,
			`"mandatory"`,
		},
		{
			"agent-supplied coverage",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"coverage":{"completeness":"COMPLETE"}}`,
			`"coverage"`,
		},
		{
			"agent-supplied negative_verification",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"negative_verification":{"status":"VERIFIED"}}`,
			`"negative_verification"`,
		},
		{
			"agent-supplied recommendation",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"recommendation":"DISMISSED"}`,
			`"recommendation"`,
		},
		{
			"agent-supplied verdict",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"verdict":"NOT_EXPLOITABLE"}`,
			`"verdict"`,
		},
		{
			"unknown claim",
			`{"id":"fp-1","claim_id":"c-ghost","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"evidence_refs":["e1"]}`,
			`"c-ghost"`,
		},
		{
			"undeclared evidence ref",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"evidence_refs":["e-ghost"]}`,
			`"e-ghost"`,
		},
		{
			"missing evidence refs",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}]}`,
			`evidence_refs`,
		},
		{
			"empty evidence refs",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"evidence_refs":[]}`,
			`evidence_refs`,
		},
		{
			"evidence without det locator",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"evidence_refs":["e1","e3"]}`,
			`det:`,
		},
		{
			"evidence with sha-suffixed det locator",
			`{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent","subjects":[{"package":"p","symbol":"s"}],"evidence_refs":["e1","e4"]}`,
			`det:`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAssessment(falsifierAssessmentHead+tc.proposals+falsifierAssessmentTail, "scanner-123")
			if err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s error %q must name %s", tc.name, err, tc.want)
			}
		})
	}
}

// TestFalsifierProposalProseClaimIsNotProof: a prose claim stating absence —
// even decision-relevant and evidence-backed — never creates a falsifier
// proposal; the proposal list stays empty until the agent emits the
// structured form.
func TestFalsifierProposalProseClaimIsNotProof(t *testing.T) {
	a, err := decodeAssessment(
		`{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"NOT_EXPLOITABLE","summary":"s",`+
			`"claims":[{"id":"c1","statement":"the authorization interceptor is absent from the snapshot","basis":"INTERPRETED","subject":"authorization interceptor","scope":"captured snapshot","decision_relevant":true,"evidence_refs":["e1"]}],`+
			`"evidence":[{"id":"e1","kind":"file","locator":"go.mod"}],`+
			`"proposed_action":{"kind":"CLOSE","instruction":"close as not exploitable","rationale":"no interceptor registration was found","scope":"captured snapshot","decisive_claim_ids":["c1"],"reconsider_when":["registration is captured"]}}`,
		"scanner-123")
	if err != nil {
		t.Fatalf("prose claims must decode: %v", err)
	}
	if len(a.FalsifierProposals) != 0 {
		t.Fatalf("prose claim must not create a falsifier proposal: %+v", a.FalsifierProposals)
	}
	if a.Claims[0].Statement == "" || a.Claims[0].Basis != PremiseInterpreted {
		t.Fatalf("claims not preserved verbatim: %+v", a.Claims)
	}
}

// TestFalsifierProposalHistoricalV1Rejected: assessment.v1 is history.
// Live ingress accepts only assessment.v2, so an old record — even one
// without proposals — is rejected rather than re-admitted under the current
// contract.
func TestFalsifierProposalHistoricalV1Rejected(t *testing.T) {
	const legacy = `{"schema_version":"assessment.v1","finding_id":"scanner-123","verdict":"EXPLOITABLE","summary":"s","mechanism":"m","claims":[{"id":"c1","statement":"x","decision_relevant":true}],"unknowns":[{"id":"u1","description":"d"}],"counterarguments":["vendored?"]}`
	if _, err := decodeAssessment(legacy, "scanner-123"); err == nil {
		t.Fatal("assessment.v1 must not pass live ingress")
	}
	if _, err := DecodeAssessment(legacy, "scanner-123"); err == nil {
		t.Fatal("DecodeAssessment must reject assessment.v1")
	}
}

func TestFalsifierKindRoundTrip(t *testing.T) {
	for _, k := range []FalsifierKind{FalsifierCodeAbsent, FalsifierLocusPackageAbsent, FalsifierLocusFunctionAbsent} {
		var decoded FalsifierKind
		roundTripString(t, k, &decoded)
		if decoded != k {
			t.Fatalf("got %q, want %q", decoded, k)
		}
	}
	var bad FalsifierKind
	if err := json.Unmarshal([]byte(`"bogus_kind"`), &bad); err == nil {
		t.Fatal("unknown falsifier kind must be rejected")
	}
}
