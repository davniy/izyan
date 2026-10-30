package claimshape

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ReportSchemaVersion identifies the offline report document.
const ReportSchemaVersion = "claimshape-report.v1"

// CorpusReport is the offline measurement of plan §8.1: how the
// canonical taxonomy covers every persisted run, crossed with the human
// reason classes and observation completeness. It carries no verdicts —
// verdicts travel as labels inside per-run records only.
type CorpusReport struct {
	SchemaVersion         string                    `json:"schema_version"`
	CorpusDir             string                    `json:"corpus_dir"`
	Runs                  []RunRecord               `json:"runs"`
	Summary               ReportSummary             `json:"summary"`
	ByShape               map[string]int            `json:"claims_by_shape"`
	ByReason              map[string]int            `json:"unsupported_by_reason"`
	ByHumanClass          map[string]int            `json:"claims_by_human_reason_class"`
	ShapeMatrix           map[string]map[string]int `json:"shape_x_human_reason_class"`
	CompletenessMatrix    map[string]map[string]int `json:"shape_x_completeness"`
	UnclassifiedSignals   map[string]int            `json:"unclassified_signal_forms"`
	RunsWithoutAssessment []string                  `json:"runs_without_assessment"`
	Declarations          []string                  `json:"taxonomy"`
}

// RunRecord is the per-run row of the report.
type RunRecord struct {
	Ticket             string            `json:"ticket"`
	RunDir             string            `json:"run_dir"`
	RunID              string            `json:"run_id,omitempty"`
	FindingID          string            `json:"finding_id,omitempty"`
	HasAssessment      bool              `json:"has_assessment"`
	SourceID           string            `json:"source_id,omitempty"`
	AdvisoryIDs        []string          `json:"advisory_ids,omitempty"`
	AdvisoryFamily     string            `json:"advisory_family,omitempty"`
	BuildContext       map[string]string `json:"build_context,omitempty"`
	Verdict            string            `json:"verdict,omitempty"`
	InternalStatus     string            `json:"internal_status,omitempty"`
	Judgment           string            `json:"judgment,omitempty"`
	Recommendation     string            `json:"recommendation,omitempty"`
	FactValidation     string            `json:"fact_validation,omitempty"`
	HumanReasonClass   string            `json:"human_reason_class,omitempty"`
	Claims             int               `json:"claims"`
	DecisionClaims     int               `json:"decision_relevant_claims"`
	ShapeCounts        map[string]int    `json:"shape_counts"`
	CompletenessCounts map[string]int    `json:"completeness_counts"`
	Unsupported        []UnsupportedRow  `json:"unsupported_claims,omitempty"`
	Limitations        []string          `json:"limitations,omitempty"`
}

// UnsupportedRow lists one claim that received no canonical shape, with
// the explicit reason and the evidence forms it cited — the report's
// answer to "what does the taxonomy not reduce".
type UnsupportedRow struct {
	ClaimID          string   `json:"claim_id"`
	Reason           string   `json:"reason"`
	DecisionRelevant bool     `json:"decision_relevant"`
	Families         []string `json:"families"`
	Locators         []string `json:"locators,omitempty"`
	ClaimStatus      string   `json:"claim_status,omitempty"`
}

// ReportSummary are the headline numbers.
type ReportSummary struct {
	RunsTotal             int     `json:"runs_total"`
	RunsWithAssessment    int     `json:"runs_with_assessment"`
	RunsWithoutAssessment int     `json:"runs_without_assessment"`
	ClaimsTotal           int     `json:"claims_total"`
	DecisionRelevantTotal int     `json:"decision_relevant_total"`
	ShapedClaims          int     `json:"shaped_claims"`
	UnsupportedClaims     int     `json:"unsupported_claims"`
	CoveragePercent       float64 `json:"coverage_percent"`
}

// reasonRow is the external human reason-class label, read from the
// divergence/comparison summaries. Keys are ticket ids.
type ReasonIndex map[string]string

// LoadReasonIndex reads a comparison-pass*.json or divergence-pass*.json
// summary and returns ticket → human_reason_class.
func LoadReasonIndex(path string) (ReasonIndex, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Ticket           string `json:"ticket"`
		HumanReasonClass string `json:"human_reason_class"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	out := ReasonIndex{}
	for _, r := range rows {
		if strings.TrimSpace(r.HumanReasonClass) != "" {
			out[r.Ticket] = r.HumanReasonClass
		}
	}
	return out, nil
}

var runDirRE = regexp.MustCompile(`^intake-\d+-.+$`)

// ListRuns enumerates the corpus layout (<corpus>/<ticket>/intake-*/).
func ListRuns(corpus string) ([][2]string, error) {
	entries, err := os.ReadDir(corpus)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		subs, err := os.ReadDir(filepath.Join(corpus, e.Name()))
		if err != nil {
			continue
		}
		for _, s := range subs {
			if s.IsDir() && runDirRE.MatchString(s.Name()) {
				out = append(out, [2]string{e.Name(), filepath.Join(corpus, e.Name(), s.Name())})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][1] < out[j][1] })
	return out, nil
}

// BuildReport extracts every run of the corpus and aggregates the §8.1
// matrices. Deterministic: input order is sorted, every map is emitted
// sorted by the caller.
func BuildReport(corpus string, reasons ReasonIndex) (*CorpusReport, error) {
	runs, err := ListRuns(corpus)
	if err != nil {
		return nil, err
	}
	rep := &CorpusReport{
		SchemaVersion:       ReportSchemaVersion,
		CorpusDir:           corpus,
		ByShape:             map[string]int{},
		ByReason:            map[string]int{},
		ByHumanClass:        map[string]int{},
		ShapeMatrix:         map[string]map[string]int{},
		CompletenessMatrix:  map[string]map[string]int{},
		UnclassifiedSignals: map[string]int{},
	}
	for _, s := range CanonicalShapes() {
		rep.Declarations = append(rep.Declarations, string(s))
	}
	for _, r := range runs {
		ex, err := ExtractRun(r[1], r[0])
		if err != nil {
			return nil, err
		}
		rec := recordRun(ex, reasons[r[0]])
		rep.Runs = append(rep.Runs, rec)
		accumulate(rep, rec, ex)
	}
	s := &rep.Summary
	s.RunsTotal = len(rep.Runs)
	s.RunsWithAssessment = countIf(rep.Runs, func(r RunRecord) bool { return r.HasAssessment })
	s.RunsWithoutAssessment = s.RunsTotal - s.RunsWithAssessment
	s.ClaimsTotal = sumShape(rep.ByShape)
	s.DecisionRelevantTotal = 0
	for _, r := range rep.Runs {
		s.DecisionRelevantTotal += r.DecisionClaims
	}
	s.ShapedClaims = s.ClaimsTotal - rep.ByShape[string(ShapeUnsupported)]
	s.UnsupportedClaims = rep.ByShape[string(ShapeUnsupported)]
	if s.ClaimsTotal > 0 {
		s.CoveragePercent = float64(s.ShapedClaims) / float64(s.ClaimsTotal) * 100
	}
	return rep, nil
}

func countIf(xs []RunRecord, f func(RunRecord) bool) int {
	n := 0
	for _, x := range xs {
		if f(x) {
			n++
		}
	}
	return n
}

func sumShape(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func recordRun(ex *RunExtraction, humanClass string) RunRecord {
	rec := RunRecord{
		Ticket:             ex.Ticket,
		RunDir:             ex.RunDir,
		RunID:              ex.RunID,
		FindingID:          ex.FindingID,
		HasAssessment:      ex.HasAssessment,
		SourceID:           ex.SourceID,
		AdvisoryIDs:        ex.Advisory.IDs,
		AdvisoryFamily:     advisoryFamily(ex.Advisory),
		BuildContext:       ex.BuildContext,
		Verdict:            ex.Verdict,
		InternalStatus:     ex.InternalStatus,
		Judgment:           ex.Judgment,
		Recommendation:     ex.Recommendation,
		FactValidation:     ex.FactValidation,
		HumanReasonClass:   humanClass,
		ShapeCounts:        map[string]int{},
		CompletenessCounts: map[string]int{},
		Limitations:        ex.Limitations,
	}
	for _, c := range ex.Claims {
		rec.Claims++
		if c.Source.DecisionRelevant {
			rec.DecisionClaims++
		}
		rec.ShapeCounts[string(c.Shape)]++
		rec.CompletenessCounts[c.Scope.Completeness]++
		if c.Shape == ShapeUnsupported {
			row := UnsupportedRow{
				ClaimID:          c.Source.ClaimID,
				Reason:           string(c.UnsupportedReason),
				DecisionRelevant: c.Source.DecisionRelevant,
				ClaimStatus:      c.Source.ClaimStatus,
			}
			fams := map[string]bool{}
			var locs []string
			for _, f := range claimFacets(c) {
				fams[f.Family+":"+f.Predicate] = true
				if f.Locator != "" {
					locs = append(locs, f.Locator)
				}
			}
			for f := range fams {
				row.Families = append(row.Families, f)
			}
			sort.Strings(row.Families)
			sort.Strings(locs)
			row.Locators = locs
			rec.Unsupported = append(rec.Unsupported, row)
		}
	}
	return rec
}

// advisoryFamily derives the package-level family a run belongs to — the
// grouped hold-out key of §8.2 — from the authoritative module/package
// name, never from the ticket.
func advisoryFamily(a AdvisoryFacts) string {
	if a.Package != "" {
		return a.Package
	}
	return a.Module
}

func accumulate(rep *CorpusReport, rec RunRecord, ex *RunExtraction) {
	if !rec.HasAssessment {
		rep.RunsWithoutAssessment = append(rep.RunsWithoutAssessment, rec.Ticket)
	}
	hc := rec.HumanReasonClass
	if hc == "" {
		hc = "unlabeled"
	}
	rep.ByHumanClass[hc] += rec.Claims
	for _, t := range ex.UnclassifiedTools {
		rep.UnclassifiedSignals["tool:"+t]++
	}
	for _, c := range ex.Claims {
		rep.ByShape[string(c.Shape)]++
		if rep.ShapeMatrix[hc] == nil {
			rep.ShapeMatrix[hc] = map[string]int{}
		}
		rep.ShapeMatrix[hc][string(c.Shape)]++
		comp := c.Scope.Completeness
		if comp == "" {
			comp = "UNKNOWN"
		}
		if rep.CompletenessMatrix[string(c.Shape)] == nil {
			rep.CompletenessMatrix[string(c.Shape)] = map[string]int{}
		}
		rep.CompletenessMatrix[string(c.Shape)][comp]++
		if c.Shape == ShapeUnsupported {
			rep.ByReason[string(c.UnsupportedReason)]++
			for _, f := range claimFacets(c) {
				key := f.Family + ":" + f.Predicate
				rep.UnclassifiedSignals[key]++
			}
		}
	}
}

// Marshal emits the report with deterministic key ordering.
func (r *CorpusReport) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
