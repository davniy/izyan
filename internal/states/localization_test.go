package states

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// fakeTranslator records every Translate input and renders "RU:<src>";
// entries in fail produce errors.
type fakeTranslator struct {
	calls []string
	fail  map[string]string
}

func (f *fakeTranslator) Translate(_ context.Context, text string) (string, error) {
	f.calls = append(f.calls, text)
	if msg, ok := f.fail[text]; ok {
		return "", errors.New(msg)
	}
	return "RU:" + text, nil
}

func (f *fakeTranslator) ModelName() string { return "fake-model" }

func localizationCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: "case-loc",
		Vulnerability: domain.Vulnerability{
			ID:      "GO-2099-0001",
			Summary: "advisory summary",
			// Same text as the summary below on purpose: dedup.
			Description: "advisory summary",
		},
		CVEAnalysis: &domain.CVEAnalysisProposal{
			Mechanisms: []domain.DefectMechanism{
				{ID: "m1", Summary: "yaml.Unmarshal panic on crafted input"},
				{ID: "m2", Summary: "yaml.Unmarshal panic on crafted input"},
				{ID: "m3", Summary: ""},
			},
		},
		SemanticReview: &domain.SemanticReview{
			Findings: []string{
				"proposal misreads the patch",
				"уже на русском",
			},
		},
	}
}

func runBuildReport(t *testing.T, c *domain.AnalysisCase, h BuildReport) {
	t.Helper()
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "report.json")); err != nil {
		t.Fatalf("report.json not written: %v", err)
	}
}

func TestBuildReportLocalizesProse(t *testing.T) {
	c := localizationCase()
	ft := &fakeTranslator{}
	dir := t.TempDir()
	runBuildReport(t, c, BuildReport{Dir: dir, Translator: ft, TranslateToRussian: true})

	loc := c.Localization
	if loc == nil {
		t.Fatal("localization not populated")
	}
	if loc.SummaryRU != "RU:advisory summary" || loc.DescriptionRU != "RU:advisory summary" {
		t.Fatalf("summary_ru=%q description_ru=%q", loc.SummaryRU, loc.DescriptionRU)
	}
	wantTexts := map[string]string{
		"yaml.Unmarshal panic on crafted input": "RU:yaml.Unmarshal panic on crafted input",
		"proposal misreads the patch":           "RU:proposal misreads the patch",
	}
	if len(loc.TextRU) != len(wantTexts) {
		t.Fatalf("text_ru=%+v", loc.TextRU)
	}
	for k, v := range wantTexts {
		if loc.TextRU[k] != v {
			t.Fatalf("text_ru[%q]=%q", k, loc.TextRU[k])
		}
	}
	if loc.Model != "fake-model" {
		t.Fatalf("model=%q", loc.Model)
	}
	if len(loc.Limitations) != 0 {
		t.Fatalf("unexpected limitations: %v", loc.Limitations)
	}
	// Dedup: summary==description and two identical mechanism summaries
	// collapse; Cyrillic finding and empty summary are skipped.
	if len(ft.calls) != 3 {
		t.Fatalf("translate calls=%v", ft.calls)
	}
	for _, call := range ft.calls {
		if containsCyrillic(call) {
			t.Fatalf("cyrillic text must not be translated: %q", call)
		}
	}
	if c.Workflow.Usage.LLMCalls != 3 {
		t.Fatalf("llm_calls=%d, want 3", c.Workflow.Usage.LLMCalls)
	}
	// The localization must be persisted into report.json.
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Localization *domain.Localization `json:"localization"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Localization == nil || stored.Localization.SummaryRU != "RU:advisory summary" {
		t.Fatalf("persisted localization=%+v", stored.Localization)
	}
}

func TestBuildReportLocalizationFailureIsLimitation(t *testing.T) {
	c := localizationCase()
	ft := &fakeTranslator{fail: map[string]string{"advisory summary": "boom"}}
	runBuildReport(t, c, BuildReport{Dir: t.TempDir(), Translator: ft, TranslateToRussian: true})

	loc := c.Localization
	if loc == nil {
		t.Fatal("localization not populated")
	}
	if loc.SummaryRU != "" || loc.DescriptionRU != "" {
		t.Fatalf("failed fields must stay empty: %+v", loc)
	}
	// The deduplicated failure is recorded once even though the same
	// string fed two fields.
	if len(loc.Limitations) != 1 || !strings.Contains(loc.Limitations[0], "advisory summary") || !strings.Contains(loc.Limitations[0], "boom") {
		t.Fatalf("limitations=%v", loc.Limitations)
	}
	// Successful translations still land.
	if loc.TextRU["yaml.Unmarshal panic on crafted input"] == "" || loc.TextRU["proposal misreads the patch"] == "" {
		t.Fatalf("text_ru=%+v", loc.TextRU)
	}
	if c.Workflow.Usage.LLMCalls != 2 {
		t.Fatalf("llm_calls=%d, want 2 (only successful calls count)", c.Workflow.Usage.LLMCalls)
	}
}

func TestBuildReportSkipsTranslationWithoutGate(t *testing.T) {
	c := localizationCase()
	ft := &fakeTranslator{}
	runBuildReport(t, c, BuildReport{Dir: t.TempDir(), Translator: ft})
	if c.Localization != nil {
		t.Fatalf("localization must stay nil without TranslateToRussian: %+v", c.Localization)
	}
	if len(ft.calls) != 0 {
		t.Fatalf("translator called %d times", len(ft.calls))
	}
	if c.Workflow.Usage.LLMCalls != 0 {
		t.Fatalf("llm_calls=%d", c.Workflow.Usage.LLMCalls)
	}
}

func TestBuildReportNilTranslator(t *testing.T) {
	c := localizationCase()
	runBuildReport(t, c, BuildReport{Dir: t.TempDir(), TranslateToRussian: true})
	if c.Localization != nil {
		t.Fatalf("nil translator must not produce localization: %+v", c.Localization)
	}
}
