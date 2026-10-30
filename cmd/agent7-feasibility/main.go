// agent7-feasibility is the A1.5 controller-side generator (PR-1). It runs
// the deterministic fact collector over the pinned VEX-Bench dataset, the
// resolved snapshots and one B0 run directory, and writes the committed
// artifacts:
//
//	proof-feasibility.raw.json     — full collector output, one record per case
//	proof-feasibility.csv          — 23 GT-safe rows + known-FS control row,
//	                                fact columns filled, classification
//	                                columns empty (Task B does the classify)
//	baseline-proof-coverage.json   — B0 coverage: per-case verdict, the
//	                                deterministic fact classes the analyzer
//	                                already evaluated, aggregates, provenance
//
// GT labels are controller-side by frozen policy (manifest gt_policy): the
// CSV/JSON artifacts they land in are committed controller artifacts, never
// mounted into any sandbox. Run outputs stay under the gitignored
// eval/agent7/results/.
//
//	agent7-feasibility --tasks <vex_bench.jsonl> --repos-dir <dir> \
//	    --run <b0 run dir> --manifest <freeze/manifest.json> \
//	    --out-dir eval/agent7 [--head <sha>] [--control-case <task_id>] \
//	    [--require-complete] [--diagnostics <path>] \
//	    [--invalidated "<dir>|<profile>|<cases>|<cause>"]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/davniy/izyan/internal/eval/agent7"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agent7-feasibility:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("agent7-feasibility", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tasksPath := fs.String("tasks", "", "VEX-Bench tasks JSONL (frozen dataset)")
	var runDirs []string
	fs.Func("run", "B0 run directory (case dirs, metrics.json, scoring/); repeatable — "+
		"later segments override earlier ones per task_id (retry merge)",
		func(s string) error { runDirs = append(runDirs, s); return nil })
	reposDir := fs.String("repos-dir", "", "snapshot root (<owner>/<repo>/<sha>)")
	manifestPath := fs.String("manifest", "", "frozen manifest.json (snapshot hash pins)")
	outDir := fs.String("out-dir", "", "output directory for the committed artifacts")
	head := fs.String("head", "", "izyan repo HEAD sha at run time (provenance)")
	controlCase := fs.String("control-case", "kubernetes-kubernetes-e196d24-CVE-2023-44487",
		"GT-exploitable control row (known B0 false-safe)")
	diagPath := fs.String("diagnostics", "", "optional path for per-case collection notes JSON")
	requireComplete := fs.Bool("require-complete", false,
		"fail non-zero if any case is infra_error or lacks prediction.json (use for the final baseline artifacts)")
	var invalidated []string
	fs.Func("invalidated", "record an invalidated prior attempt: <run_dir>|<profile>|<affected_cases>|<cause> (repeatable)",
		func(s string) error { invalidated = append(invalidated, s); return nil })
	var degradedFlag []string
	fs.Func("degraded", "declare a case_id degraded by operator judgement (repeatable); --require-complete rejects the merged set when a declared case is present — degradation is declared, never inferred from limitations",
		func(s string) error { degradedFlag = append(degradedFlag, s); return nil })
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tasksPath == "" || *reposDir == "" || len(runDirs) == 0 || *manifestPath == "" || *outDir == "" {
		return fmt.Errorf("--tasks, --repos-dir, --run (≥1), --manifest and --out-dir are required")
	}

	ctx := context.Background()
	tasks, err := agent7.LoadTaskRecords(*tasksPath)
	if err != nil {
		return err
	}
	man, err := agent7.Load(*manifestPath)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	snapHashes := man.GetStringMap("dataset.snapshot_hashes")

	// Advisory completeness overrides are externally verified facts, never
	// inferred: the historical B0 analysis (eval/baselines/vexbench/
	// external-baseline-1.md §2) proved GHSA-qppj-fm5r-hxr3's Go manifest
	// incomplete — it lists only golang.org/x/net while the vulnerable
	// component is google.golang.org/grpc.
	manifestComplete := map[string]string{
		"kubernetes-kubernetes-e196d24-CVE-2023-44487": "no",
	}

	// A directory listed as invalidated is evidence only — it must never
	// be merged into the baseline, even if also passed via --run.
	invDirs, invErr := parseInvalidated(invalidated)
	if invErr != nil {
		return invErr
	}
	excluded := map[string]bool{}
	for _, inv := range invDirs {
		excluded[filepath.Clean(inv.RunDir)] = true
	}
	var effectiveRuns []string
	for _, d := range runDirs {
		if excluded[filepath.Clean(d)] {
			continue
		}
		effectiveRuns = append(effectiveRuns, d)
	}
	if len(effectiveRuns) == 0 {
		return fmt.Errorf("no usable run segments after excluding invalidated directories")
	}

	// Artifact path roots are resolved once so every committed file
	// scrubs operator-private paths to portable placeholders.
	initPathSubs(*tasksPath, *reposDir, effectiveRuns)

	var records []agent7.FactRecord
	for _, t := range tasks {
		// Multi-segment merge: the LAST segment that produced an envelope
		// for the case wins (retry semantics); a segment without the case
		// contributes nothing.
		var pred, adv, seg string
		for _, d := range effectiveRuns {
			cd := filepath.Join(d, sanitize(t.TaskID))
			p := filepath.Join(cd, "prediction.json")
			if _, err := os.Stat(p); err == nil {
				pred, seg = p, d
				if a := findAdvisory(cd); a != "" {
					adv = a
				}
			}
		}
		in := agent7.FeasibilityInputs{
			Task:                     t,
			SnapshotDir:              snapshotPath(*reposDir, t),
			PredictionPath:           pred,
			AdvisoryPath:             adv,
			ExpectedContentHash:      snapHashes[snapshotKeyOf(t)],
			AdvisoryManifestComplete: manifestComplete[t.TaskID],
		}
		rec := agent7.CollectCase(ctx, in)
		if len(effectiveRuns) > 1 {
			rec.RunSegment = seg
		}
		records = append(records, rec)
	}

	if *requireComplete {
		// Degradation is an operator declaration, never inferred: no
		// per-case artifact reliably separates a memory-degraded attempt
		// from a legitimate abstain (the same limitation strings appear
		// in both). --degraded names the cases the operator excludes.
		declared := map[string]bool{}
		for _, id := range degradedFlag {
			declared[id] = true
		}
		var bad []string
		for _, r := range records {
			switch {
			case r.InfraError || !r.RunEnvelopePresent:
				bad = append(bad, r.TaskID+" (infra/missing)")
			case declared[r.TaskID]:
				bad = append(bad, r.TaskID+" (declared degraded)")
			}
		}
		if len(bad) > 0 {
			return fmt.Errorf("--require-complete: %d case(s) are infra_error, missing or declared degraded: %s",
				len(bad), strings.Join(bad, ", "))
		}
	}

	if *diagPath != "" {
		if err := writeDiagnostics(*diagPath, records); err != nil {
			return err
		}
	}
	rawPath := filepath.Join(*outDir, "proof-feasibility.raw.json")
	if err := writeRaw(rawPath, records); err != nil {
		return err
	}
	csvPath := filepath.Join(*outDir, "proof-feasibility.csv")
	if err := writeCSV(csvPath, records, *controlCase); err != nil {
		return err
	}
	covPath := filepath.Join(*outDir, "baseline-proof-coverage.json")
	if err := writeCoverage(covPath, effectiveRuns, tasks, *head, invDirs); err != nil {
		return err
	}
	printSummary(records, *controlCase)
	return nil
}

// sanitize mirrors cmd/izyan sanitizeCaseName (case dir names).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// parseInvalidated converts repeated --invalidated values
// "run_dir|profile|affected_cases|cause" into structured records.
func parseInvalidated(vals []string) ([]InvalidatedAttempt, error) {
	var out []InvalidatedAttempt
	for _, v := range vals {
		parts := strings.SplitN(v, "|", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("--invalidated %q: want run_dir|profile|affected_cases|cause", v)
		}
		n, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("--invalidated %q: affected_cases not a number: %w", v, err)
		}
		out = append(out, InvalidatedAttempt{
			RunDir:        strings.TrimSpace(parts[0]),
			Profile:       strings.TrimSpace(parts[1]),
			AffectedCases: n,
			Cause:         strings.TrimSpace(parts[3]),
		})
	}
	return out, nil
}

// snapshotPath resolves repos_dir/<owner>/<repo>/<sha>; unresolvable repo
// URLs return "" so the collector fails closed.
func snapshotPath(reposDir string, t agent7.TaskRecord) string {
	owner, repo := ownerRepo(t.RepoURL)
	if owner == "" || t.CommitSHA == "" {
		return ""
	}
	return filepath.Join(reposDir, owner, repo, t.CommitSHA)
}

func snapshotKeyOf(t agent7.TaskRecord) string {
	owner, repo := ownerRepo(t.RepoURL)
	if owner == "" {
		return ""
	}
	return owner + "/" + repo + "/" + t.CommitSHA
}

func ownerRepo(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if i := strings.Index(s, "@"); i >= 0 {
		if j := strings.Index(s[i:], ":"); j >= 0 {
			s = s[i+j+1:]
		}
	}
	s = strings.TrimSuffix(strings.Trim(s, "/"), ".git")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

// pathSubs are the ordered substitutions that make committed artifacts
// portable: no operator-private or ephemeral absolute path may land in
// eval/agent7/** (frozen protocol: artifacts are controller documents).
// The gitignored results/ dir is exempt — only committed files pass here.
var pathSubs [][2]string

func initPathSubs(tasksPath, reposDir string, runDirs []string) {
	abs := func(p string) string {
		if a, err := filepath.Abs(p); err == nil {
			return filepath.Clean(a)
		}
		return filepath.Clean(p)
	}
	subs := [][2]string{}
	// Longest-first so nested roots win.
	if reposDir != "" {
		subs = append(subs, [2]string{abs(reposDir), "${VEXBENCH_REPOS_DIR}"})
	}
	if tasksPath != "" {
		subs = append(subs, [2]string{abs(tasksPath), "${VEXBENCH_HARNESS_DIR}/benchmark/tasks/vex_bench.jsonl"})
		subs = append(subs, [2]string{filepath.Dir(abs(tasksPath)), "${VEXBENCH_HARNESS_DIR}/benchmark/tasks"})
	}
	if wd, err := os.Getwd(); err == nil {
		subs = append(subs, [2]string{filepath.Clean(wd) + string(os.PathSeparator), ""})
	}
	// The throwaway run binary's path is dropped; its sha256 (in
	// provenance) keeps identity.
	subs = append(subs, [2]string{"/tmp/izyan-agent7", "izyan"})
	pathSubs = subs
}

// scrubPaths applies pathSubs plus a generic last-resort sweep for any
// remaining absolute operator path — a committed artifact must never
// leak /Users/… or /tmp/… regardless of how it was computed.
var localPathRe = regexp.MustCompile(`(?:/Users/[^\s"':,\]}]+|/tmp/[^\s"':,\]}]+|/private/[^\s"':,\]}]+)`)

func scrubPaths(s string) string {
	for _, sub := range pathSubs {
		if sub[0] != "" {
			s = strings.ReplaceAll(s, sub[0], sub[1])
		}
	}
	return localPathRe.ReplaceAllString(s, "<local-path>")
}

// findAdvisory locates the single prepared OSV document under
// <case>/advisory/; zero or ambiguous → "" (fail closed — never pick a
// winner from several candidates, that would silently bind a record to
// the wrong document).
func findAdvisory(caseDir string) string {
	matches, _ := filepath.Glob(filepath.Join(caseDir, "advisory", "*.json"))
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

// writeRaw persists the full collector output — the evidence behind the CSV.
func writeRaw(path string, records []agent7.FactRecord) error {
	doc := struct {
		Schema  string              `json:"schema"`
		Kind    string              `json:"kind"`
		Records []agent7.FactRecord `json:"records"`
	}{Schema: agent7.FeasibilitySchema, Kind: "a1.5-proof-feasibility-facts", Records: records}
	return writeJSON(path, doc)
}

// writeDiagnostics dumps per-case collection notes outside the committed
// fact artifacts (diagnostics only — facts are in the records).
func writeDiagnostics(path string, records []agent7.FactRecord) error {
	type diag struct {
		TaskID string   `json:"task_id"`
		Notes  []string `json:"notes,omitempty"`
	}
	var out []diag
	for _, r := range records {
		if len(r.CollectionNotes) > 0 {
			out = append(out, diag{TaskID: r.TaskID, Notes: r.CollectionNotes})
		}
	}
	return writeJSON(path, out)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte(scrubPaths(string(b))), '\n'), 0o644)
}
