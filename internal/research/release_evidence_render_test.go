package research

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// releaseAxesReport builds a contract-valid report whose snapshot carries
// the release-evidence axes under test.
func releaseAxesReport(t *testing.T, re *ReleaseEvidenceReport, releaseGo *string) *Report {
	t.Helper()
	r := validReport(t)
	minimum := "1.23"
	r.Input.Snapshot.GoVersion = "go version go1.25.2 linux/amd64"
	r.Input.Snapshot.MinimumGoVersion = &minimum
	r.Input.Snapshot.ReleaseGoVersion = releaseGo
	r.Input.Snapshot.ReleaseEvidence = re
	return r
}

func renderReleaseAxes(t *testing.T, r *Report) string {
	t.Helper()
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(md)
}

// TestReleaseEvidenceAxesRender pins the human report's axis distinction:
// the analysis toolchain, the go.mod language minimum, the authoritative
// release toolchain, the authoritative release module graph and the
// source/vendor fallback are separate lines using the existing report
// fields. No axis may be implied by another.
func TestReleaseEvidenceAxesRender(t *testing.T) {
	t.Run("all axes authoritative", func(t *testing.T) {
		rel := "go1.22.3"
		src := string(domain.GoVersionSourceExplicit)
		r := releaseAxesReport(t, &ReleaseEvidenceReport{
			Status:             "RESOLVED",
			SelectedVersion:    rel,
			SelectedSource:     src,
			SelectedTrust:      "AUTHORITATIVE",
			VersionGraphSource: "release-artifact",
			VersionGraphTrust:  "AUTHORITATIVE",
			ModuleCount:        1,
		}, &rel)
		md := renderReleaseAxes(t, r)
		for _, want := range []string{
			"- analysis toolchain: `go version go1.25.2 linux/amd64`",
			"- minimum go.mod version: `1.23` (language minimum, never the release toolchain)",
			"- release toolchain: `go1.22.3`",
			"- release evidence: `RESOLVED`",
			"- release module graph: `release-artifact` trust `AUTHORITATIVE` modules=1",
		} {
			if !strings.Contains(md, want) {
				t.Fatalf("human report missing %q:\n%s", want, md)
			}
		}
		if strings.Contains(md, "release toolchain: `UNKNOWN`") {
			t.Fatalf("resolved release toolchain rendered as UNKNOWN:\n%s", md)
		}
	})

	t.Run("unknown toolchain with source fallback", func(t *testing.T) {
		r := releaseAxesReport(t, &ReleaseEvidenceReport{
			Status:             "UNKNOWN",
			ReasonCode:         "RELEASE_EVIDENCE_SUPPORTING_ONLY",
			VersionGraphSource: "source-snapshot",
		}, nil)
		md := renderReleaseAxes(t, r)
		for _, want := range []string{
			"- analysis toolchain: `go version go1.25.2 linux/amd64`",
			"- minimum go.mod version: `1.23`",
			"- release toolchain: `UNKNOWN` — `UNKNOWN` / RELEASE_EVIDENCE_SUPPORTING_ONLY",
			"- release module graph: `source-snapshot` fallback",
		} {
			if !strings.Contains(md, want) {
				t.Fatalf("human report missing %q:\n%s", want, md)
			}
		}
		if strings.Contains(md, "release module graph: `release-artifact`") {
			t.Fatalf("fallback report claims a release module graph:\n%s", md)
		}
	})

	t.Run("failed channel blocks the module graph", func(t *testing.T) {
		r := releaseAxesReport(t, &ReleaseEvidenceReport{
			Status:             "NOT_RUN",
			ReasonCode:         "ARTIFACT_PATH_MISSING",
			VersionGraphSource: "unavailable",
		}, nil)
		md := renderReleaseAxes(t, r)
		for _, want := range []string{
			"- release toolchain: `UNKNOWN` — `NOT_RUN` / ARTIFACT_PATH_MISSING",
			"- release module graph: `unavailable` — a required release-evidence channel failed closed",
		} {
			if !strings.Contains(md, want) {
				t.Fatalf("human report missing %q:\n%s", want, md)
			}
		}
	})
}
