package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	triage "github.com/davniy/izyan/internal/productb/triage"
)

const triageEvalUsage = `usage:
  izyan eval triage --run <run-directory> --baseline <triage-baselines.json> --out <directory>

Offline comparison of one saved triage run against external controls.

The run is verified first (input/snapshot/raw-agent/assessment hashes and
the recorded decision package) with no model call, no network access and no
mutation of the source run. The verified package is then evaluated against
the triage-baselines.v1 entry named by its finding_id. The report is written
as <out>/evaluation.json, outside the source run.

evaluation.json (triage-evaluation.v1) keeps package identity, comparison
coverage and separate human/machine counters:
  - human recommendation errors (CLOSE/LOWER_PRIORITY against the control,
    incorrect negative judgments and CLOSE against an externally labelled
    exploitable case);
  - machine false-safe reductions (machine disposition beyond the control);
  - unverified reductions and UNASSESSED coverage when the control or the
    optional expected_judgment is absent — never a fabricated zero error.

Exit codes: 0 completed comparison without measured violations; 1 at least
one measured comparison violation; 2 malformed inputs/provenance or a
missing requested comparison coverage.
`

// Offline evaluation exit codes, distinct from the live triage policy
// status: a measured comparison violation is a completed evaluation, not a
// failed run.
const (
	triageEvalExitViolation = 1
	triageEvalExitError     = 2
)

// runTriageEval implements `izyan eval triage`: a read-only offline check
// of one saved decision package against external controls. It never loads
// an LLM configuration and never feeds a label back into the product.
func runTriageEval(args []string) error {
	fs := flag.NewFlagSet("eval triage", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, triageEvalUsage) }
	runDir := fs.String("run", "", "saved triage run directory to verify and evaluate")
	baselinePath := fs.String("baseline", "", "triage-baselines.v1 JSON with the external control for this finding")
	outDir := fs.String("out", "", "directory for the evaluation report; must be outside the source run")
	if err := fs.Parse(args); err != nil {
		return exitErr(triageEvalExitError, err)
	}
	if fs.NArg() != 0 {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: unexpected positional arguments: %s", strings.Join(fs.Args(), " ")))
	}
	if strings.TrimSpace(*runDir) == "" || strings.TrimSpace(*baselinePath) == "" || strings.TrimSpace(*outDir) == "" {
		fs.Usage()
		return exitErr(triageEvalExitError, errors.New("eval triage: --run, --baseline and --out are required"))
	}

	sourceRun, err := canonicalOutDir(*runDir)
	if err != nil {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: --run: %w", err))
	}
	outAbs, err := canonicalOutDir(*outDir)
	if err != nil {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: --out: %w", err))
	}
	if dirContains(sourceRun, outAbs) {
		return exitErr(triageEvalExitError, fmt.Errorf(
			"eval triage: --out %s resolves inside the source run directory %s; the evaluation report is never written into the source run", *outDir, sourceRun))
	}

	ctx := context.Background()
	rep, err := triage.PrepareReplayWithOptions(ctx, sourceRun, triage.ReplayOptions{})
	if err != nil {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: cannot verify saved run %s: %w", sourceRun, err))
	}
	if rep.Decision == nil {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: saved run %s carries no decision package", sourceRun))
	}
	baselines, err := triage.LoadBaselines(*baselinePath)
	if err != nil {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: %w", err))
	}
	baseline, ok := baselines[rep.FindingID]
	if !ok {
		return exitErr(triageEvalExitError, fmt.Errorf(
			"eval triage: baseline %s has no entry for finding %s; requested comparison coverage is missing",
			*baselinePath, rep.FindingID))
	}

	evaluation := triage.EvaluateDecisionPackage(*rep.Decision, &baseline)
	path, err := triage.WriteDecisionEvaluation(ctx, outAbs, evaluation)
	if err != nil {
		return exitErr(triageEvalExitError, fmt.Errorf("eval triage: %w", err))
	}
	fmt.Fprintf(os.Stdout,
		"eval triage finding=%s package=%s control=%s expected_judgment=%s human_mismatch=%d incorrect_negative=%d close_on_exploitable=%d machine_false_safe=%d unverified_reductions=%d -> %s\n",
		evaluation.FindingID, evaluation.DecisionPackageHash,
		evaluation.Coverage.ControlDisposition, evaluation.Coverage.ExpectedJudgment,
		evaluation.Human.ReductionControlMismatches, evaluation.Human.IncorrectNegativeJudgments,
		evaluation.Human.CloseOnExploitable, evaluation.Machine.FalseSafe,
		evaluation.Machine.UnverifiedReductions, path)
	if len(evaluation.Violations) > 0 {
		return exitErr(triageEvalExitViolation, fmt.Errorf(
			"eval triage: %d measured comparison violation(s); see %s", len(evaluation.Violations), path))
	}
	return nil
}
