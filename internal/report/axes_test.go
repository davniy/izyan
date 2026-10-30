package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// axisReportDocument is the report.json envelope: the unchanged persisted case
// plus the optional derived projection.
type axisReportDocument struct {
	Schema           string `json:"schema"`
	RequestedFinding struct {
		RequestedID string `json:"requested_id"`
		Outcome     string `json:"assessment_outcome"`
		Verdict     string `json:"verdict"`
	} `json:"requested_finding"`
	AssessmentAxes struct {
		Requested []axisReportRow `json:"requested"`
		Records   []axisReportRow `json:"records"`
	} `json:"assessment_axes"`
}

type axisReportRow struct {
	SubjectID             string            `json:"subject_id"`
	AssessmentID          string            `json:"assessment_id"`
	Profile               string            `json:"profile"`
	IsTargetActual        bool              `json:"is_target_actual"`
	Record                *domain.RecordPin `json:"record"`
	ExploitabilityScope   string            `json:"exploitability_scope"`
	VulnerableCodeInBuild string            `json:"vulnerable_code_in_build"`
	Exploitable           string            `json:"exploitable"`
}

func axisReportRows(t *testing.T, rows []axisReportRow, assessmentID string) axisReportRow {
	t.Helper()
	for _, row := range rows {
		if row.AssessmentID == assessmentID && row.IsTargetActual {
			return row
		}
	}
	t.Fatalf("no target-actual axes row for assessment %q in %+v", assessmentID, rows)
	return axisReportRow{}
}

func readAxisReport(t *testing.T, c *domain.AnalysisCase) ([]byte, axisReportDocument) {
	t.Helper()
	dir := t.TempDir()
	if err := Write(dir, c); err != nil {
		t.Fatalf("write report: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var document axisReportDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode report.json: %v", err)
	}
	return raw, document
}

// TestAssessmentAxesReportAdditive proves the projection is a pure report
// wrapper: the persisted case keeps its schema and requested finding, while the
// top-level assessment_axes carries the derived rows.
func TestAssessmentAxesReportAdditive(t *testing.T) {
	c := reportComposedPositive(t)
	raw, document := readAxisReport(t, c)

	if document.Schema != string(domain.CaseSchemaV2) {
		t.Fatalf("report schema = %q", document.Schema)
	}
	if document.RequestedFinding.RequestedID != reportCVE ||
		document.RequestedFinding.Outcome != string(domain.OutcomeDecided) ||
		document.RequestedFinding.Verdict != string(domain.VerdictExploitable) {
		t.Fatalf("requested finding changed: %+v", document.RequestedFinding)
	}

	if len(document.AssessmentAxes.Requested) != 1 {
		t.Fatalf("requested axes rows = %d, want one", len(document.AssessmentAxes.Requested))
	}
	requested := document.AssessmentAxes.Requested[0]
	if !requested.IsTargetActual || requested.SubjectID != reportCVE ||
		requested.VulnerableCodeInBuild != "TRUE" || requested.Exploitable != "TRUE" ||
		requested.ExploitabilityScope != string(domain.ScopeLibraryAPI) {
		t.Fatalf("requested axis row = %+v", requested)
	}
	if requested.Record != nil {
		t.Fatalf("requested row acquired a record pin: %+v", requested.Record)
	}

	failedPrimary := axisReportRows(t, document.AssessmentAxes.Records, string(reportPrimaryCase))
	if failedPrimary.VulnerableCodeInBuild != "UNKNOWN" || failedPrimary.Exploitable != "UNKNOWN" {
		t.Fatalf("primary axis row = %+v", failedPrimary)
	}
	if failedPrimary.Record == nil || failedPrimary.Record.RecordID != reportPrimaryRecord {
		t.Fatalf("primary row carries no exact pin: %+v", failedPrimary.Record)
	}
	witness := axisReportRows(t, document.AssessmentAxes.Records, string(reportChildCase))
	if witness.VulnerableCodeInBuild != "TRUE" || witness.Exploitable != "TRUE" ||
		witness.ExploitabilityScope != string(domain.ScopeLibraryAPI) {
		t.Fatalf("witness axis row = %+v", witness)
	}
	if witness.Record == nil || witness.Record.RecordID != reportChildRecord {
		t.Fatalf("witness row carries no exact pin: %+v", witness.Record)
	}

	// The persisted case fields are untouched: decoding the report and
	// re-marshaling it reproduces the case exactly, without the axes.
	base, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal case: %v", err)
	}
	var decoded domain.AnalysisCase
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode case from report: %v", err)
	}
	reencoded, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("marshal decoded case: %v", err)
	}
	if !bytes.Equal(base, reencoded) {
		t.Fatal("the report wrapper changed the persisted case fields")
	}
}

// TestAssessmentAxesLegacyReportHasNoProjection proves a legacy report stays
// byte-shape compatible: no derived member is inferred for a case without the
// analysis-case/2 projection.
func TestAssessmentAxesLegacyReportHasNoProjection(t *testing.T) {
	c := reportFailedPrimary(t)
	raw, document := readAxisReport(t, c)
	if bytes.Contains(raw, []byte(`"assessment_axes"`)) {
		t.Fatalf("legacy report acquired an assessment_axes member: %s", raw)
	}
	if len(document.AssessmentAxes.Requested) > 0 || len(document.AssessmentAxes.Records) > 0 {
		t.Fatal("legacy report decoded axes rows")
	}
}

// TestAssessmentAxesHumanSurfaces exercises the summary, facts table, candidate
// rows, record summary and tracker rationale.
func TestAssessmentAxesHumanSurfaces(t *testing.T) {
	t.Run("scoped positive carries its boundary everywhere", func(t *testing.T) {
		c := reportComposedPositive(t)
		en := Markdown(c, "en")
		ru := Markdown(c, "ru")

		for _, want := range []string{
			"Vulnerable code/version in assessed build: yes",
			"Exploitable: yes, at the library API boundary. Deployed attacker access is not established.",
			"| vulnerable code/version in assessed build | yes |",
			"| axes |",
			"library-api; deployed attacker access not established",
			"(projection)",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN report is missing %q:\n%s", want, en)
			}
		}
		if strings.Contains(en, "exploitable in deployment: yes") {
			t.Fatalf("EN report states unqualified deployment exploitability:\n%s", en)
		}
		for _, want := range []string{
			"Уязвимый код/версия в оцениваемой сборке: да",
			"Эксплуатируемость: да, на границе library API. Доступ атакующего в развёртывании не установлен.",
		} {
			if !strings.Contains(ru, want) {
				t.Fatalf("RU report is missing %q:\n%s", want, ru)
			}
		}

		tracker := TrackerRationale(c)
		for _, want := range []string{
			"Оси оценки запроса:",
			"эксплуатируемость: да, на границе library API. Доступ атакующего в развёртывании не установлен.",
			"Независимо оценённые записи:",
		} {
			if !strings.Contains(tracker, want) {
				t.Fatalf("tracker rationale is missing %q:\n%s", want, tracker)
			}
		}
	})

	t.Run("exact negative renders false / not applicable", func(t *testing.T) {
		en := Markdown(reportExactNegative(t), "en")
		for _, want := range []string{
			"Vulnerable code/version in assessed build: no",
			"Exploitable: not applicable",
			"| vulnerable code/version in assessed build | no |",
			"| exploitable in assessed scope | not applicable |",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN exact negative is missing %q:\n%s", want, en)
			}
		}
	})

	t.Run("corpus negative renders the requested axes and candidate facts", func(t *testing.T) {
		c := reportCorpusNegative(t)
		en := Markdown(c, "en")
		for _, want := range []string{
			"Vulnerable code/version in assessed build: no",
			"Exploitable: not applicable",
			"vuln=FALSE; exploitable=NOT_APPLICABLE",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN corpus negative is missing %q:\n%s", want, en)
			}
		}
	})

	t.Run("failed and external requests keep unknown axes", func(t *testing.T) {
		for name, c := range map[string]*domain.AnalysisCase{
			"failed":   reportFailedRequest(t),
			"external": reportExternalRequest(t),
		} {
			en := Markdown(c, "en")
			for _, want := range []string{
				"Vulnerable code/version in assessed build: unknown",
				"Exploitable: unknown",
			} {
				if !strings.Contains(en, want) {
					t.Fatalf("%s EN report is missing %q:\n%s", name, want, en)
				}
			}
			if strings.Contains(en, "Vulnerable code/version in assessed build: no") {
				t.Fatalf("%s request rendered unavailable applicability as false:\n%s", name, en)
			}
		}
	})
}
