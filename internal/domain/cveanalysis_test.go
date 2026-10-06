package domain_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestLegacyCaseDoesNotInventProof(t *testing.T) {
	var c domain.AnalysisCase
	legacyJSON := `{"id":"legacy-001","vulnerability":{"id":"GO-2099-0001"}}`
	if err := json.Unmarshal([]byte(legacyJSON), &c); err != nil {
		t.Fatalf("failed to unmarshal legacy case: %v", err)
	}
	if c.CVEAnalysisBundle != nil || c.CVEAnalysis != nil || c.Justification != nil {
		t.Fatal("legacy case unmarshaling invented unexpected CVE analysis artifacts")
	}
}

func TestCVEAnalysisDomainSerialization(t *testing.T) {
	bundle := domain.CVESourceBundle{
		Binding: domain.AnalysisBinding{
			AdvisoryID:      "GO-2026-6443",
			AdvisoryHash:    "sha256-adv",
			Module:          "google.golang.org/grpc",
			ResolvedVersion: "v1.80.0",
		},
		Artifacts: []domain.SourceArtifact{
			{
				ID:     "patch-01",
				Side:   "patch",
				URI:    "https://github.com/grpc/grpc-go/pull/9365.patch",
				Hash:   "sha256-patch",
				Status: "FETCHED",
			},
		},
		ManifestStatus: domain.ManifestComplete,
		FetchedAt:      time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle failed: %v", err)
	}

	var restored domain.CVESourceBundle
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal bundle failed: %v", err)
	}

	if restored.Binding.AdvisoryID != bundle.Binding.AdvisoryID {
		t.Errorf("got %q, want %q", restored.Binding.AdvisoryID, bundle.Binding.AdvisoryID)
	}
	if restored.ManifestStatus != domain.ManifestComplete {
		t.Errorf("got status %v, want COMPLETE", restored.ManifestStatus)
	}
}

func TestContextualRiskLegacyJSONRoundTrip(t *testing.T) {
	// Legacy JSON produced before triage provenance fields existed must
	// still parse, and re-marshaling must not invent values for them.
	legacy := `{
		"status": "ASSESSED",
		"base_severity": "CRITICAL",
		"base_score": 10.0,
		"contextual_level": "MEDIUM",
		"contextual_score": 5.0,
		"priority": "P2",
		"sla": "Scheduled",
		"adjustment_reason": "listener bound to loopback",
		"factors": {
			"verdict": "EXPLOITABLE",
			"exposure": "INTERNAL",
			"authentication": "UNKNOWN",
			"payload_control": "UNKNOWN",
			"blast_radius": "PROCESS_CRASH_DOS"
		}
	}`
	var r domain.ContextualRisk
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatalf("legacy risk json failed to unmarshal: %v", err)
	}
	if r.TriageDisposition != "" || r.BasePriority != "" || r.SeveritySource != "" || r.ScoreSource != "" {
		t.Fatalf("legacy risk json invented triage fields: %+v", r)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("marshal produced invalid json: %v", err)
	}
	for _, k := range []string{"triage_disposition", "base_priority", "severity_source", "score_source"} {
		if _, present := keys[k]; present {
			t.Errorf("omitempty field %q emitted for empty value", k)
		}
	}

	// New fields round-trip when populated.
	r.TriageDisposition = domain.TriageLowered
	r.BasePriority = domain.PriorityP0
	r.SeveritySource = "OSV"
	r.ScoreSource = "OSV"
	data, err = json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var back domain.ContextualRisk
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if back != r {
		t.Fatalf("round-trip mismatch: %+v vs %+v", back, r)
	}
}

func TestVulnerabilitySeveritySourceJSON(t *testing.T) {
	// Empty provenance fields are omitted from the vulnerability payload.
	v := domain.Vulnerability{ID: "GO-1", BaseSeverity: "HIGH", BaseScore: 7.5}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("marshal produced invalid json: %v", err)
	}
	if _, present := keys["severity_source"]; present {
		t.Error("severity_source emitted for empty value")
	}
	if _, present := keys["score_source"]; present {
		t.Error("score_source emitted for empty value")
	}

	v.SeveritySource = "OSV"
	v.ScoreSource = "OSV"
	data, err = json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var back domain.Vulnerability
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if back.SeveritySource != "OSV" || back.ScoreSource != "OSV" {
		t.Fatalf("provenance lost in round-trip: %+v", back)
	}
}
