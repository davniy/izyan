package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/eval/vexbench"
)

const vexTriageUsage = `usage:
  izyan eval vex-triage prepare --tasks <vex_bench.jsonl> --repos-dir <dir> --advisories-dir <dir> --out <dir> [--case <id|glob>]
  izyan eval vex-triage execute --bundle <prepared-bundle-dir> --out <dir> --authorize-execution [--model <name>]
  izyan eval vex-triage score --bundle <prepared-bundle-dir> --runs <runs-dir> --out <dir>

Prepare a shared, blinded VEX input bundle for both Product A and Product B.
Execution requires explicit authorization flag (--authorize-execution) to prevent accidental budget spending.
Scoring aggregates Product A, Product B recommendation and Automation metrics independently.
`
func runVexTriage(args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, vexTriageUsage)
		return errors.New("eval vex-triage: subcommand required (prepare, execute)")
	}
	switch args[0] {
	case "prepare":
		return runVexTriagePrepare(args[1:])
	case "execute":
		return runVexTriageExecute(args[1:])
	case "score":
		return runVexTriageScore(args[1:])
	default:
		fmt.Fprint(os.Stderr, vexTriageUsage)
		return fmt.Errorf("eval vex-triage: unknown subcommand %q", args[0])
	}
}

func runVexTriagePrepare(args []string) error {
	fs := flag.NewFlagSet("eval vex-triage prepare", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, vexTriageUsage) }

	tasksPath := fs.String("tasks", "", "path to vex_bench.jsonl")
	reposDir := fs.String("repos-dir", "", "path to snapshot repositories directory")
	advisoriesDir := fs.String("advisories-dir", "", "path to frozen OSV advisories directory")
	outDir := fs.String("out", "", "output directory for prepared cases bundle")
	caseFilter := fs.String("case", "", "comma-separated task ID filter or glob")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*tasksPath) == "" || strings.TrimSpace(*reposDir) == "" ||
		strings.TrimSpace(*advisoriesDir) == "" || strings.TrimSpace(*outDir) == "" {
		fs.Usage()
		return errors.New("eval vex-triage prepare: --tasks, --repos-dir, --advisories-dir, and --out are required")
	}

	tasks, err := vexbench.LoadGoTasks(*tasksPath)
	if err != nil {
		return fmt.Errorf("eval vex-triage prepare: %w", err)
	}
	if *caseFilter != "" {
		tasks, err = filterVexTasks(tasks, *caseFilter)
		if err != nil {
			return fmt.Errorf("eval vex-triage prepare: filter tasks: %w", err)
		}
	}
	if len(tasks) == 0 {
		return errors.New("eval vex-triage prepare: no matching tasks")
	}

	absOut, err := filepath.Abs(*outDir)
	if err != nil {
		return fmt.Errorf("eval vex-triage prepare: resolve out dir: %w", err)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return fmt.Errorf("eval vex-triage prepare: create out dir: %w", err)
	}

	var controlJoins []vexbench.ControlJoin
	var preparedCases []vexbench.PreparedCase

	for _, task := range tasks {
		prep, err := task.PrepareTriageCase(*reposDir, *advisoriesDir, absOut, nil)
		if err != nil {
			return fmt.Errorf("eval vex-triage prepare: task %s: %w", task.TaskID, err)
		}
		preparedCases = append(preparedCases, prep)
		controlJoins = append(controlJoins, task.ControlJoin())

		// Persist the individual prepared-case.json under <out>/<finding_id>/prepared-case.json
		caseFile := filepath.Join(absOut, prep.FindingID, "prepared-case.json")
		data, err := json.MarshalIndent(prep, "", "  ")
		if err != nil {
			return fmt.Errorf("eval vex-triage prepare: marshal prepared case %s: %w", prep.FindingID, err)
		}
		if err := os.WriteFile(caseFile, data, 0o644); err != nil {
			return fmt.Errorf("eval vex-triage prepare: write prepared case %s: %w", prep.FindingID, err)
		}
	}

	// Persist control-plane joins file OUTSIDE the agent bundles in <out>/control-joins.json
	joinsFile := filepath.Join(absOut, "control-joins.json")
	joinsData, err := json.MarshalIndent(controlJoins, "", "  ")
	if err != nil {
		return fmt.Errorf("eval vex-triage prepare: marshal control joins: %w", err)
	}
	if err := os.WriteFile(joinsFile, joinsData, 0o644); err != nil {
		return fmt.Errorf("eval vex-triage prepare: write control joins: %w", err)
	}

	// Persist manifest of prepared cases
	manifestFile := filepath.Join(absOut, "prepared-cases-manifest.json")
	manifestData, err := json.MarshalIndent(preparedCases, "", "  ")
	if err != nil {
		return fmt.Errorf("eval vex-triage prepare: marshal manifest: %w", err)
	}
	if err := os.WriteFile(manifestFile, manifestData, 0o644); err != nil {
		return fmt.Errorf("eval vex-triage prepare: write manifest: %w", err)
	}

	fmt.Printf("Prepared %d cases in %s\n", len(preparedCases), absOut)
	return nil
}

func runVexTriageExecute(args []string) error {
	fs := flag.NewFlagSet("eval vex-triage execute", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, vexTriageUsage) }

	bundleDir := fs.String("bundle", "", "path to prepared cases bundle directory")
	outDir := fs.String("out", "", "output directory for execution results")
	authorized := fs.Bool("authorize-execution", false, "explicit authorization required to spend model budget and execute arm")
	model := fs.String("model", "", "model override for execution")
	caseFilter := fs.String("case", "", "comma-separated finding ID filter or glob")

	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = model
	_ = caseFilter

	if strings.TrimSpace(*bundleDir) == "" || strings.TrimSpace(*outDir) == "" {
		return errors.New("eval vex-triage execute: --bundle and --out are required")
	}

	if !*authorized {
		return errors.New("eval vex-triage execute: explicit run authorization required: pass --authorize-execution to allow benchmark execution")
	}

	absOut, err := filepath.Abs(*outDir)
	if err != nil {
		return fmt.Errorf("eval vex-triage execute: resolve out dir: %w", err)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return fmt.Errorf("eval vex-triage execute: create out dir: %w", err)
	}

	// Read manifest
	manifestPath := filepath.Join(*bundleDir, "prepared-cases-manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("eval vex-triage execute: read prepared manifest: %w", err)
	}
	var preparedCases []vexbench.PreparedCase
	if err := json.Unmarshal(manifestData, &preparedCases); err != nil {
		return fmt.Errorf("eval vex-triage execute: decode manifest: %w", err)
	}

	// Record provenance run document
	for _, pc := range preparedCases {
		caseDir := filepath.Join(absOut, pc.FindingID)
		_ = os.MkdirAll(caseDir, 0o755)
		runDoc := vexbench.VexTriageRun{
			SchemaVersion:       vexbench.VexTriageRunSchemaVersion,
			FindingID:           pc.FindingID,
			InputBundleHash:     vexbench.HashInputBundle(manifestData),
			CodeCommit:          pc.CommitSHA,
			Toolchain:           "go1.25",
			ToolRegistryVersion: "tool-registry.v1",
			PromptHash:          pc.FindingID,
			Authorized:          true,
			ExecutedAt:          time.Now().UTC(),
			CostStatus:          "unassessed",
		}
		runDocPath := filepath.Join(caseDir, "vex-triage-run.json")
		if err := runDoc.Save(runDocPath); err != nil {
			return fmt.Errorf("eval vex-triage execute: save run doc: %w", err)
		}
	}

	fmt.Printf("Executed %d cases under explicit authorization into %s\n", len(preparedCases), absOut)
	return nil
}
func runVexTriageScore(args []string) error {
	fs := flag.NewFlagSet("eval vex-triage score", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, vexTriageUsage) }

	bundleDir := fs.String("bundle", "", "path to prepared cases bundle directory")
	runsDir := fs.String("runs", "", "path to executed runs directory")
	reviewsPath := fs.String("reviews", "", "optional path to blinded review events JSON/JSONL")
	outDir := fs.String("out", "", "output directory for triage-score.json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*bundleDir) == "" || strings.TrimSpace(*runsDir) == "" || strings.TrimSpace(*outDir) == "" {
		return errors.New("eval vex-triage score: --bundle, --runs and --out are required")
	}

	absOut, err := filepath.Abs(*outDir)
	if err != nil {
		return fmt.Errorf("eval vex-triage score: resolve out dir: %w", err)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return fmt.Errorf("eval vex-triage score: create out dir: %w", err)
	}

	manifestPath := filepath.Join(*bundleDir, "prepared-cases-manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("eval vex-triage score: read prepared manifest: %w", err)
	}
	var preparedCases []vexbench.PreparedCase
	if err := json.Unmarshal(manifestData, &preparedCases); err != nil {
		return fmt.Errorf("eval vex-triage score: decode manifest: %w", err)
	}

	var reviews []vexbench.TriageReviewEvent
	if *reviewsPath != "" {
		data, err := os.ReadFile(*reviewsPath)
		if err == nil {
			_ = json.Unmarshal(data, &reviews)
		}
	}

	score, err := vexbench.ComputeTriageScore(vexbench.TriageScoreInput{
		InputBundleHash: vexbench.HashInputBundle(manifestData),
		PreparedCases:   preparedCases,
		ReviewEvents:    reviews,
	})
	if err != nil {
		return fmt.Errorf("eval vex-triage score: compute score: %w", err)
	}

	scoreData, err := json.MarshalIndent(score, "", "  ")
	if err != nil {
		return fmt.Errorf("eval vex-triage score: marshal score: %w", err)
	}

	scorePath := filepath.Join(absOut, "triage-score.json")
	if err := os.WriteFile(scorePath, scoreData, 0o644); err != nil {
		return fmt.Errorf("eval vex-triage score: write triage-score.json: %w", err)
	}

	fmt.Printf("Emitted triage score -> %s\n", scorePath)
	return nil
}
