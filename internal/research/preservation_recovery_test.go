package research

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Retained condition and ticket fields must not become unchecked just because
// a saved report does not advertise the historical overlay.
func TestRetainedResearchInvariantsAfterRecovery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Report)
		want   string
	}{
		{"invalid-state", func(r *Report) { r.ExploitationConditions[0].State = "FORGED" }, "state"},
		{"agent-supported", func(r *Report) {
			r.ExploitationConditions[0].Origin = OriginAgent
			r.ExploitationConditions[0].State = StateSupported
		}, "agent condition"},
		{"agent-refuted", func(r *Report) {
			r.ExploitationConditions[0].Origin = OriginAgent
			r.ExploitationConditions[0].State = StateRefuted
		}, "agent condition"},
		{"applicability-mismatch", func(r *Report) {
			r.ExploitationConditions[0].Subject = subjModulePresence
			r.ExploitationConditions[0].Origin = OriginDeterm
			r.ExploitationConditions[0].State = StateRefuted
			r.ProductApplicability.ModulePresent = "TRUE"
		}, "inconsistent"},
		{"ticket-refusal", func(r *Report) {
			r.ProductApplicability.VersionAxisBlocked = true
			r.ProductApplicability.VersionAffected = "FALSE"
		}, "version_axis_blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validReport(t)
			r.ContractExtensions = nil
			r.ExploitationAxes.BuildUsageScope = nil
			if len(r.ExploitationConditions) == 0 {
				t.Fatal("fixture has no conditions")
			}
			tc.mutate(r)
			err := Validate(r, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("lost retained invariant %s: %v", tc.want, err)
			}
			dir := t.TempDir()
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "report.json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPersistedAgentTurn(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("persisted retained invariant %s was not checked: %v", tc.want, err)
			}
		})
	}
	t.Run("persisted-artifact", TestReplayEvidenceLevel_V3ArtifactPinsStillFailClosed)
	t.Run("persisted-foreign-subject", TestReplayPackageUsage_TamperedSubjectAborts)
	t.Run("scope-projection", func(t *testing.T) {
		r := validReport(t)
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		pa := r.ProductApplicability
		if pa.ConclusionScope == "" || pa.AdvisoryScopeStatus == "" {
			t.Fatal("scope projection is empty")
		}
		if !strings.Contains(string(md), "conclusion_scope=`"+pa.ConclusionScope+"`") {
			t.Fatal("rendered scope projection disappeared")
		}
	})
}
