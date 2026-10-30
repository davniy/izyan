// heldout-gate is the offline held-out validation tool of
// docs/dev/plans/universal-verifier-plan.md §8 and Task 5.
//
// It replays the persisted corporate corpus through the canonical
// claim-shape extraction and the verification entailment graph — no LLM
// call anywhere — re-derives the deterministic absence probes on the
// pinned snapshot worktrees (deterministic tool execution only), applies
// the stability controller to the recorded 5×3 variance series, runs the
// §8.4 generic mutations and emits the §8.3 metric report:
// hard gates, proof soundness, admission coverage, human alignment,
// stability and the precision bound.
//
// This binary is the held-out *reporter*: it emits the §8.3 metric report
// and its exit code reflects report pass/fail. The case-level *admission
// check* is the separate `izyan triage check --case <id>` path — it exits
// non-zero when a cited mandatory condition lacks a VERIFIED falsifier
// proof and names the check that failed. Do not conflate the two: this
// tool's admission metrics are observational, `triage check` enforces.
//
//	heldout-gate -corpus <out-full> -comparison <comparison-pass6.json>
//	  -kernel-spec <kernel-spec.json> -absence-matrix <absence-matrix-after.json>
//	  -worktrees <worktrees.json> -variance <out-variance> [-variance-json variance.json]
//	  [-probe-limit N] [-out report.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/davniy/izyan/internal/productb/heldoutgate"
	agenttriage "github.com/davniy/izyan/internal/productb/triage"
)

// run executes the gate and returns the process exit code: 0 when every
// hard check passed (or only the expected reporting gate failed), 1 on a
// failed report check or processing error, 2 on input/flag errors.
// Factored out of main so tests can exercise the exit contract.
func run(args []string) int {
	fs := flag.NewFlagSet("izyan-heldout-gate", flag.ContinueOnError)
	corpus := fs.String("corpus", "", "corpus directory (<corpus>/<ticket>/intake-*/)")
	comparison := fs.String("comparison", "", "comparison-pass*.json (human labels)")
	kernelSpec := fs.String("kernel-spec", "", "deterministic probe spec JSON")
	absenceMatrix := fs.String("absence-matrix", "", "recorded absence matrix JSON")
	worktrees := fs.String("worktrees", "", "pinned worktree map JSON")
	variance := fs.String("variance", "", "variance corpus dir (<dir>/<ticket>-rN/intake-*/)")
	varianceJSON := fs.String("variance-json", "", "recorded variance.json (default <variance>/variance.json)")
	probeLimit := fs.Int("probe-limit", 0, "limit absence groups (smoke runs)")
	foldK := fs.Int("folds", 5, "grouped hold-out fold count")
	out := fs.String("out", "", "output path (stdout when empty)")
	probeOut := fs.String("probe-out", "", "optional per-group re-derived observation dump")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *corpus == "" {
		fmt.Fprintln(os.Stderr, "heldout-gate: -corpus is required")
		return 2
	}

	human := map[string]heldoutgate.ComparisonRow{}
	if *comparison != "" {
		rows, err := loadComparison(*comparison)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: comparison: %v\n", err)
			return 2
		}
		human = rows
	}

	runs, err := heldoutgate.RunCorpus(*corpus, human)
	if err != nil {
		fmt.Fprintf(os.Stderr, "heldout-gate: %v\n", err)
		return 1
	}
	folds := heldoutgate.HoldoutFolds(runs, *foldK)

	foreign, foreignDetail, err := heldoutgate.CrossRunAdmissions(*corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "heldout-gate: cross-run: %v\n", err)
		return 1
	}

	var defects []string
	var probeRows []heldoutgate.AbsenceGroupRow
	var mutationRows []heldoutgate.MutationRow
	if *kernelSpec != "" && *absenceMatrix != "" && *worktrees != "" {
		spec, err := loadKernelSpec(*kernelSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: kernel spec: %v\n", err)
			return 2
		}
		matrix, err := loadAbsenceMatrix(*absenceMatrix)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: absence matrix: %v\n", err)
			return 2
		}
		wts, err := loadWorktrees(*worktrees)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: worktrees: %v\n", err)
			return 2
		}
		rows2, recs, d := heldoutgate.DeriveAbsenceProbe(spec, wts, matrix, *probeLimit)
		probeRows = rows2
		defects = append(defects, d...)
		mutationRows = heldoutgate.Mutations(probeRows, recs)
		if *probeOut != "" {
			if err := dumpProbe(*probeOut, probeRows, recs); err != nil {
				fmt.Fprintf(os.Stderr, "heldout-gate: probe-out: %v\n", err)
				return 1
			}
		}
	} else {
		defects = append(defects, "absence probe skipped: -kernel-spec/-absence-matrix/-worktrees incomplete")
	}

	var stabRows []heldoutgate.StabilityRow
	if *variance != "" {
		vj := *varianceJSON
		if vj == "" {
			vj = filepath.Join(*variance, "variance.json")
		}
		rec, err := loadVariance(vj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: variance json: %v\n", err)
			return 2
		}
		stabRows, err = heldoutgate.AssessVariance(*variance, rec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: variance: %v\n", err)
			return 1
		}
	}

	rep := heldoutgate.BuildReport(runs, probeRows, mutationRows, stabRows, folds, foreign, foreignDetail, defects)
	b, err := rep.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "heldout-gate: marshal: %v\n", err)
		return 1
	}
	if *out == "" {
		fmt.Println(string(b))
	} else {
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "heldout-gate: write %s: %v\n", *out, err)
			return 1
		}
	}
	for _, c := range rep.Checks {
		status := "PASS"
		if !c.Pass {
			status = "FAIL"
		}
		fmt.Fprintf(os.Stderr, "%-46s %s  required=%s observed=%s\n", c.Name, status, c.Required, c.Observed)
	}
	fmt.Fprintf(os.Stderr, "capability_gate: %s\n", rep.CapabilityGate)
	// Hard-gate failures are exit 1 — a green process on a failing safety
	// report would lie to the merge gate that consumes it. The
	// "precision_95_proven" reporting gate stays non-blocking: the plan
	// prescribes default-off until the corpus supplies >=59 eligible
	// admissions.
	for _, c := range rep.Checks {
		if c.Name == "precision_95_proven" {
			continue
		}
		if !c.Pass {
			return 1
		}
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func loadComparison(path string) (map[string]heldoutgate.ComparisonRow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []heldoutgate.ComparisonRow
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	out := map[string]heldoutgate.ComparisonRow{}
	for _, r := range rows {
		out[r.Ticket] = r
	}
	return out, nil
}

func loadKernelSpec(path string) (heldoutgate.KernelSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return heldoutgate.KernelSpec{}, err
	}
	var spec heldoutgate.KernelSpec
	return spec, json.Unmarshal(b, &spec)
}

func loadAbsenceMatrix(path string) ([]heldoutgate.AbsenceGroupRow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Repo            string   `json:"repo"`
		Ref             string   `json:"ref"`
		Advisory        string   `json:"advisory"`
		Module          string   `json:"module"`
		Tickets         []string `json:"tickets"`
		Status          string   `json:"status"`
		Completeness    string   `json:"completeness"`
		Checked         int      `json:"checked"`
		Absent          int      `json:"absent"`
		Present         int      `json:"present"`
		ClosureComplete bool     `json:"closure_complete"`
		OpenExceptions  int      `json:"open_exceptions"`
		Limitations     []string `json:"limitations"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var out []heldoutgate.AbsenceGroupRow
	for _, r := range raw {
		out = append(out, heldoutgate.AbsenceGroupRow{
			GroupKey: r.Repo + "|" + r.Ref + "|" + r.Advisory + "|" + r.Module,
			MatrixRecorded: heldoutgate.ProbeSummary{
				Status: r.Status, Completeness: r.Completeness,
				Checked: r.Checked, Absent: r.Absent, Present: r.Present,
				ClosureComplete: r.ClosureComplete, OpenExceptions: r.OpenExceptions,
				Limitations: r.Limitations,
			},
		})
	}
	return out, nil
}

func loadWorktrees(path string) (heldoutgate.WorktreeMap, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m heldoutgate.WorktreeMap
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
func dumpProbe(dir string, rows []heldoutgate.AbsenceGroupRow, recs map[string]agenttriage.RecordedObservation) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	rb, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "rows.json"), append(rb, '\n'), 0o644); err != nil {
		return err
	}
	for key, rec := range recs {
		name := "probe-" + heldoutgate.ShortKey(key) + ".observation.json"
		b, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func loadVariance(path string) ([]heldoutgate.VarianceRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []heldoutgate.VarianceRecord
	return rows, json.Unmarshal(b, &rows)
}
