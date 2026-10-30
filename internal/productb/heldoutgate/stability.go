package heldoutgate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	"github.com/fedorovmv/izyan/internal/productb/verify"
)

// AssessVariance replays every recorded attempt of the variance corpus
// (<varianceDir>/<ticket>-r<N>/intake-*/) through the deterministic
// cycle, then applies the stability controller per ticket. The recorded
// variance.json verdicts travel only as LLM-surface labels: instability
// the controller reports is measured on the decisive surface, never on
// the verdicts.
func AssessVariance(varianceDir string, recorded []VarianceRecord) ([]StabilityRow, error) {
	runs, err := claimshape.ListRuns(varianceDir)
	if err != nil {
		return nil, fmt.Errorf("heldout gate: variance list: %w", err)
	}
	// Map recorded verdicts: ticket -> run -> verdict.
	llm := map[string]map[int]string{}
	for _, v := range recorded {
		if llm[v.Ticket] == nil {
			llm[v.Ticket] = map[int]string{}
		}
		llm[v.Ticket][v.Run] = v.Verdict
	}
	attemptsByTicket := map[string][]verify.Attempt{}
	llmByTicket := map[string][]string{}
	var order []string
	for _, rr := range runs {
		dir := rr[0] // <ticket>-r<N>
		ticket, n, err := splitAttempt(dir)
		if err != nil {
			return nil, err
		}
		rep, pins, _, err := ReplayRun(rr[1], ticket, true)
		if err != nil {
			return nil, fmt.Errorf("heldout gate: %s: %w", dir, err)
		}
		if _, seen := attemptsByTicket[ticket]; !seen {
			order = append(order, ticket)
		}
		attemptsByTicket[ticket] = append(attemptsByTicket[ticket], verify.Attempt{
			Attempt: n, Pins: pins, Report: *rep,
		})
		if llm[ticket] != nil {
			llmByTicket[ticket] = append(llmByTicket[ticket], llm[ticket][n])
		}
	}
	sort.Strings(order)
	var rows []StabilityRow
	for _, ticket := range order {
		row := StabilityRow{Ticket: ticket, LLMVerdicts: llmByTicket[ticket]}
		verdicts := map[string]bool{}
		for _, v := range row.LLMVerdicts {
			verdicts[v] = true
		}
		row.LLMUnstable = len(verdicts) > 1
		atts := attemptsByTicket[ticket]
		row.Attempts = len(atts)
		v := verify.Assess(atts)
		row.Stable = v.Stable
		row.SemanticDrift = v.SemanticDrift
		row.Drift = v.Drift
		row.Disposition = v.Disposition
		row.DemotedFrom = v.DemotedFrom
		for _, a := range v.Attempts {
			row.Dispositions = append(row.Dispositions, a.Disposition)
		}
		row.Reduction = v.Disposition == "DISMISSED" || v.Disposition == "LOWERED"
		rows = append(rows, row)
	}
	return rows, nil
}

// splitAttempt splits the "<ticket>-r<N>" variance directory name.
func splitAttempt(dir string) (string, int, error) {
	i := strings.LastIndex(dir, "-r")
	if i <= 0 {
		return "", 0, fmt.Errorf("heldout gate: malformed variance dir %q", dir)
	}
	var n int
	if _, err := fmt.Sscanf(dir[i+2:], "%d", &n); err != nil {
		return "", 0, fmt.Errorf("heldout gate: malformed variance dir %q: %w", dir, err)
	}
	return dir[:i], n, nil
}
