package domain_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestLocalizationRoundTrip(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-loc",
		Localization: &domain.Localization{
			SummaryRU:     "Краткое описание",
			DescriptionRU: "Полное описание",
			TextRU: map[string]string{
				"mechanism summary": "сводка механизма",
				"review finding":    "замечание ревью",
			},
			Model:       "test-model",
			Limitations: []string{"translation failed for advisory description: boom"},
		},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back domain.AnalysisCase
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	loc := back.Localization
	if loc == nil {
		t.Fatal("localization dropped on round-trip")
	}
	if loc.SummaryRU != "Краткое описание" || loc.DescriptionRU != "Полное описание" {
		t.Fatalf("localized fields=%+v", loc)
	}
	if loc.TextRU["mechanism summary"] != "сводка механизма" || loc.TextRU["review finding"] != "замечание ревью" {
		t.Fatalf("text_ru=%+v", loc.TextRU)
	}
	if loc.Model != "test-model" || len(loc.Limitations) != 1 {
		t.Fatalf("model=%q limitations=%v", loc.Model, loc.Limitations)
	}
}

func TestLocalizationOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(domain.AnalysisCase{ID: "case-none"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "localization") {
		t.Fatalf("empty localization must be omitted: %s", raw)
	}
	raw, err = json.Marshal(domain.Localization{})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Fatalf("empty Localization must marshal to {}: %s", raw)
	}
}

func TestLegacyCaseWithoutLocalizationParses(t *testing.T) {
	var c domain.AnalysisCase
	if err := json.Unmarshal([]byte(`{"id":"legacy","vulnerability":{"id":"GO-2099-0001"}}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Localization != nil {
		t.Fatal("legacy case must not invent localization")
	}
}
