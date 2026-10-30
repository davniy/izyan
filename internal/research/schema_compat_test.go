package research

import (
	"strings"
	"testing"
)

// TestReportSchemaEnum guards the closed schema set: /1, /2, /3 and /4
// are the only accepted report schemas.
func TestReportSchemaEnum(t *testing.T) {
	for _, schema := range []string{ReportSchemaV1, ReportSchemaV2, ReportSchemaV3, ReportSchemaV4} {
		r := validReport(t)
		r.Schema = schema
		switch schema {
		case ReportSchemaV1:
			r.Decision = nil
		case ReportSchemaV3:
			r.DecisionArtifact = validArtifact(t)
		case ReportSchemaV4:
			r.DecisionArtifact = validArtifact(t)
			r.RequestComposition = validRequestComposition(t)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("schema %q rejected: %v", schema, err)
		}
	}
	r := validReport(t)
	r.Schema = "research-report/5"
	if err := Validate(r, ""); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

// TestLegacyReportCompatibility proves /1 and /2 reports remain
// byte-compatible: they parse, validate and render identically before
// and after a round trip, and never grow R6 members.
func TestLegacyReportCompatibility(t *testing.T) {
	t.Run("research-report/1", func(t *testing.T) {
		r := validReport(t)
		r.Schema = ReportSchemaV1
		r.Decision = nil // /1 has no decision member
		beforeJSON := mustMarshalJSON(t, r)
		beforeMD, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseReport(beforeJSON)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.DecisionArtifact != nil {
			t.Fatal("/1 report gained a decision artifact")
		}
		if err := Validate(parsed, ""); err != nil {
			t.Fatalf("legacy /1 rejected: %v", err)
		}
		afterJSON := mustMarshalJSON(t, parsed)
		if string(beforeJSON) != string(afterJSON) {
			t.Fatal("/1 JSON round trip is not byte-stable")
		}
		afterMD, err := RenderMarkdown(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if string(beforeMD) != string(afterMD) {
			t.Fatal("/1 rendering changed after parse/validate round trip")
		}
		if strings.Contains(string(afterMD), "Decision artifact") {
			t.Fatal("/1 rendered the R6 decision-artifact section")
		}
	})

	t.Run("research-report/2", func(t *testing.T) {
		r := validReport(t)
		if r.Schema != ReportSchemaV2 {
			t.Fatalf("fixture schema %q", r.Schema)
		}
		beforeJSON := mustMarshalJSON(t, r)
		beforeMD, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseReport(beforeJSON)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.DecisionArtifact != nil {
			t.Fatal("/2 report gained a decision artifact")
		}
		if err := Validate(parsed, ""); err != nil {
			t.Fatalf("legacy /2 rejected: %v", err)
		}
		afterJSON := mustMarshalJSON(t, parsed)
		if string(beforeJSON) != string(afterJSON) {
			t.Fatal("/2 JSON round trip is not byte-stable")
		}
		afterMD, err := RenderMarkdown(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if string(beforeMD) != string(afterMD) {
			t.Fatal("/2 rendering changed after parse/validate round trip")
		}
		if strings.Contains(string(afterMD), "Decision artifact") {
			t.Fatal("/2 rendered the R6 decision-artifact section")
		}
		// A decision_artifact member on a /1 or /2 document is rejected.
		doc := map[string]any{}
		unmarshalJSON(t, mustMarshalJSON(t, r), &doc)
		doc["decision_artifact"] = map[string]any{"schema": DecisionArtifactSchemaV1}
		forged := mustMarshalJSON(t, doc)
		parsedForged, err := ParseReport(forged)
		if err != nil {
			t.Fatal(err) // the member decodes; the schema binding rejects it
		}
		parsedForged.Schema = ReportSchemaV2
		if err := Validate(parsedForged, ""); err == nil {
			t.Fatal("decision_artifact accepted on research-report/2")
		}
		parsedForged.Schema = ReportSchemaV1
		parsedForged.Decision = nil
		if err := Validate(parsedForged, ""); err == nil {
			t.Fatal("decision_artifact accepted on research-report/1")
		}
	})
}

// TestReportSchemaV3RequiresArtifact proves the /3 contract: the
// decision artifact is mandatory, must carry decision-artifact/1, and
// the report keeps validating after a parse round trip.
func TestReportSchemaV3RequiresArtifact(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	if err := Validate(r, ""); err == nil {
		t.Fatal("research-report/3 without decision_artifact accepted")
	}

	r = validReport(t)
	r.Schema = ReportSchemaV3
	a := validArtifact(t)
	r.DecisionArtifact = a
	if err := Validate(r, ""); err != nil {
		t.Fatalf("valid /3 rejected: %v", err)
	}
	// The artifact's pins are bound to the report: a mismatched snapshot
	// hash or advisory id is rejected.
	bad := validReport(t)
	bad.Schema = ReportSchemaV3
	badA := validArtifact(t)
	badA.TargetScope.SnapshotContentHash = strings.Repeat("cd", 32)
	bad.DecisionArtifact = badA
	if err := Validate(bad, ""); err == nil {
		t.Fatal("/3 artifact with foreign snapshot hash accepted")
	}
	bad = validReport(t)
	bad.Schema = ReportSchemaV3
	badA = validArtifact(t)
	badA.FindingIdentity.AdvisoryID = "GO-OTHER-9999"
	badA.AdvisoryBinding.AdvisoryID = "GO-OTHER-9999"
	bad.DecisionArtifact = badA
	if err := Validate(bad, ""); err == nil {
		t.Fatal("/3 artifact bound to a different advisory accepted")
	}
	bad = validReport(t)
	bad.Schema = ReportSchemaV3
	badA = validArtifact(t)
	badA.AdvisoryBinding.SubjectRefs = []string{"adv-not-declared"}
	bad.DecisionArtifact = badA
	if err := Validate(bad, ""); err == nil {
		t.Fatal("/3 artifact citing a non-advisory subject accepted")
	}
	bad = validReport(t)
	bad.Schema = ReportSchemaV3
	badA = validArtifact(t)
	badA.SharedFacts[0].ObservationRefs = []string{"obs:OBS-9999"}
	bad.DecisionArtifact = badA
	if err := Validate(bad, ""); err == nil {
		t.Fatal("/3 fact citing an unrecorded observation accepted")
	}

	// Parse/validate/render round trip keeps the artifact and renders the
	// R6 section; the human contract bounds survive serialization.
	b := mustMarshalJSON(t, r)
	parsed, err := ParseReport(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DecisionArtifact == nil || parsed.DecisionArtifact.Schema != DecisionArtifactSchemaV1 {
		t.Fatal("/3 artifact lost on parse")
	}
	if err := Validate(parsed, ""); err != nil {
		t.Fatalf("/3 round-trip report rejected: %v", err)
	}
	md, err := RenderMarkdown(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "Decision artifact") {
		t.Fatal("/3 report did not render the decision-artifact section")
	}
	if !strings.Contains(string(md), "HOLD_UNKNOWN") {
		t.Fatal("/3 render lost the explicit unknown branch")
	}
}
