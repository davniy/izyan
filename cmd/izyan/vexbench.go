package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

// runVexBench executes the VEX-Bench Go subset against the analyzer under a
// benchmark profile: the analysis sees only the CVE id and an immutable
// snapshot, expert inputs are refused, and the label side (ground truth,
// reference PR) never reaches the analyzer.
//
//	izyan eval vex-bench --tasks <vex_bench.jsonl> --repos-dir <dir> [--case <id|glob>]
//	    [-j <n>] [--out <dir>] [--analysis-go <version>] [--mem-limit <size>]
//
// Exit code is 1 only for preparation/scorer errors (unreadable tasks,
// missing snapshot, empty selection); per-case failures are recorded in the
// results so a baseline run can still be inspected.
func runVexBench(args []string) error {
	fs := flag.NewFlagSet("vex-bench", flag.ExitOnError)
	tasksPath := fs.String("tasks", "", "path to vex_bench.jsonl")
	reposDir := fs.String("repos-dir", "", "directory of downloaded snapshots")
	caseFilter := fs.String("case", "", "comma-separated list or glob of task IDs")
	jobs := fs.Int("j", 4, "number of parallel case evaluations")
	outDir := fs.String("out", "vexbench-out", "output directory for results")
	analysisGo := fs.String("analysis-go", "", "pin the analysis toolchain version (default: local Go)")
	memLimit := fs.String("mem-limit", "4GiB", "analyzer memory ceiling")
	osvDir := fs.String("osv-dir", "", "frozen OSV advisory directory; disables network advisory fetches")
	selfBinary := fs.String("self-binary", "", "path to this izyan binary for provenance hashing (default: os.Executable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tasksPath == "" || *reposDir == "" {
		usage()
	}

	tasks, err := vexbench.LoadGoTasks(*tasksPath)
	if err != nil {
		return fmt.Errorf("vex-bench tasks: %w", err)
	}
	if len(tasks) == 0 {
		return fmt.Errorf("vex-bench: no Go tasks in %s", *tasksPath)
	}
	if *caseFilter != "" {
		tasks, err = filterVexTasks(tasks, *caseFilter)
		if err != nil {
			return err
		}
	}

	// Pin the analysis toolchain: a requested version that cannot be
	// provided is a preparation error, never a silent local fallback.
	tc, lims := resolveAnalysisToolchain(context.Background(), *analysisGo)
	if *analysisGo != "" && (tc.Mismatch || toolchain.Normalize(tc.Version) != toolchain.Normalize(*analysisGo)) {
		return fmt.Errorf("vex-bench: analysis toolchain go%s unavailable: %s",
			toolchain.Normalize(*analysisGo), strings.Join(lims, "; "))
	}
	absOut, err := filepath.Abs(*outDir)
	if err != nil {
		return err
	}
	absRepos, err := filepath.Abs(*reposDir)
	if err != nil {
		return err
	}

	budget, err := parseMemLimit(*memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()

	concurrency := *jobs
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(tasks) {
		concurrency = len(tasks)
	}

	// One shared Go tool/cache per snapshot would be ideal, but the
	// benchmark keeps per-case isolation; each worker builds its own
	// analysisCase inputs.
	results := make([]vexbench.Prediction, len(tasks))
	envelopes := make([]vexEnvelope, len(tasks))
	taskCh := make(chan int, len(tasks))
	for i := range tasks {
		taskCh <- i
	}
	close(taskCh)

	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range taskCh {
				t := tasks[idx]
				pred, env := runVexCase(ctx, t, absRepos, absOut, tc, *osvDir)
				results[idx] = pred
				envelopes[idx] = env
				fmt.Printf("[%d/%d] %-52s %-38s %s\n", idx+1, len(tasks), t.TaskID,
					vexPredictionLabel(pred), env.Reason)
			}
		}()
	}
	wg.Wait()

	metrics := vexbench.Compute(results, tasks)
	if err := writeVexArtifacts(absOut, *tasksPath, tasks, results, envelopes, metrics, tc, *selfBinary, *jobs); err != nil {
		return err
	}

	fmt.Printf("\nvex-bench: cases=%d decided=%d external=%d failed=%d false-safe=%d false-positive=%d safe-clear=%.0f%% inconclusive=%.0f%%\n",
		metrics.Total, metrics.Decided, metrics.ExternalDependency, metrics.AnalysisFailed,
		metrics.FalseSafe, metrics.FalsePositive, metrics.SafeClearRate*100, metrics.InconclusiveRate*100)
	return nil
}

// vexPredictionLabel renders the prediction's terminal classification for the
// progress stream: a failed analysis prints FAILED and never a verdict.
func vexPredictionLabel(p vexbench.Prediction) string {
	if p.AssessmentOutcome == string(domain.OutcomeFailed) || p.Verdict == "" {
		return "FAILED"
	}
	if p.AssessmentOutcome != "" {
		return p.AssessmentOutcome + " " + p.Verdict
	}
	return p.Verdict
}

// resolveAnalysisToolchain resolves the toolchain used for analysis. With
// want == "" it uses the local Go; otherwise it requests the exact version.
func resolveAnalysisToolchain(ctx context.Context, want string) (toolchain.Toolchain, []string) {
	if want == "" {
		if v, err := toolchain.LocalVersion(ctx); err == nil {
			want = v
		}
	}
	return toolchain.Resolve(ctx, want)
}

// vexClaimRef is the calibration-visible condition record: the current
// result, the falsifier that produced it, the negative-verification state
// and the evidence/limitation references. It never carries ground truth.
type vexClaimRef struct {
	ID                string   `json:"id,omitempty"`
	ConditionID       string   `json:"condition_id"`
	Result            string   `json:"result"`
	Falsifier         string   `json:"falsifier,omitempty"`
	FalsifierBasis    string   `json:"falsifier_basis,omitempty"`
	Verification      string   `json:"negative_verification,omitempty"`
	VerificationNotes string   `json:"negative_verification_notes,omitempty"`
	Explanation       string   `json:"explanation,omitempty"`
	EvidenceIDs       []string `json:"evidence_ids,omitempty"`
	Limitations       []string `json:"limitations,omitempty"`
}

// vexOriginRef is one admitted witness behind a positive: which independent
// assessment earned it, from which exact record bytes, for which entry/mechanism
// and under which attribution. It never carries ground truth.
type vexOriginRef struct {
	AssessmentID   string `json:"assessment_id"`
	RecordID       string `json:"record_id"`
	DocumentDigest string `json:"record_digest,omitempty"`
	EntryRefs      []int  `json:"entry_refs,omitempty"`
	MechanismID    string `json:"mechanism_id,omitempty"`
	AttributionID  string `json:"attribution_id,omitempty"`
	Profile        string `json:"profile,omitempty"`
}

// vexEnvelope is the per-case result record: the analyzer's raw output plus
// the snapshot/advisory identity the run was performed against. It never
// carries ground truth.
type vexEnvelope struct {
	TaskID         string `json:"task_id"`
	RequestedCVE   string `json:"requested_cve"`
	ResolvedVulnID string `json:"resolved_vulnerability_id,omitempty"`
	TerminalState  string `json:"terminal_state"`
	// AssessmentOutcome is the requested finding's terminal classification:
	// DECIDED, EXTERNAL_DEPENDENCY or FAILED. Verdict is empty for a FAILED
	// result and INCONCLUSIVE for an external dependency.
	AssessmentOutcome string   `json:"assessment_outcome,omitempty"`
	FailureCodes      []string `json:"failure_codes,omitempty"`
	RequestedKind     string   `json:"requested_kind,omitempty"`
	Coverage          string   `json:"coverage,omitempty"`
	// PrimaryRecord/PrimaryDigest pin the request's primary record bytes;
	// ProofOrigins name the witnesses that actually earned a positive.
	PrimaryRecord       string         `json:"primary_record,omitempty"`
	PrimaryDigest       string         `json:"primary_record_digest,omitempty"`
	CandidateIDs        []string       `json:"candidate_ids,omitempty"`
	AttributionOutcomes []string       `json:"attribution_outcomes,omitempty"`
	ProofOrigins        []vexOriginRef `json:"proof_origins,omitempty"`
	// Profile/Build are the provenance of the admitted result; CorpusDigest
	// pins the corpus a declared negative rests on.
	Profile              string   `json:"profile,omitempty"`
	Build                string   `json:"build,omitempty"`
	ExploitabilityScope  string   `json:"exploitability_scope,omitempty"`
	CorpusDigest         string   `json:"corpus_digest,omitempty"`
	ExternalDependencies []string `json:"external_dependencies,omitempty"`
	// ProjectionError reports a case whose requested finding is not
	// publishable. It is a returned-answer failure, never a verdict.
	ProjectionError string   `json:"projection_error,omitempty"`
	Verdict         string   `json:"verdict,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	GroundingCond   []string `json:"grounding_condition_ids,omitempty"`
	Falsifier       string   `json:"falsifier,omitempty"`
	GroundBasis     string   `json:"ground_basis,omitempty"`
	// Claims retains the condition-level projection (result, falsifier,
	// negative-verification state and evidence references) so calibration
	// can inspect why a label was or was not admitted, not only the final
	// verdict word.
	Claims            []vexClaimRef `json:"claims,omitempty"`
	Limitations       []string      `json:"limitations,omitempty"`
	Error             string        `json:"error,omitempty"`
	ScoringOutcome    string        `json:"scoring_outcome"`
	CompatibilityCat  string        `json:"compatibility_category"`
	EvidenceIDs       []string      `json:"evidence_ids,omitempty"`
	CaseDir           string        `json:"case_dir,omitempty"`
	ReportPath        string        `json:"report_path,omitempty"`
	LLMCalls          int           `json:"llm_calls"`
	ToolCalls         int           `json:"tool_calls"`
	SnapshotRepo      string        `json:"snapshot_repo,omitempty"`
	ExternalCommitSHA string        `json:"external_commit_sha,omitempty"`
	ContentHash       string        `json:"content_hash,omitempty"`
	AdvisorySource    string        `json:"advisory_source,omitempty"`
	AdvisorySHA256    string        `json:"advisory_sha256,omitempty"`
	AdvisoryCanonical string        `json:"advisory_canonical_sha256,omitempty"`
	AdvisoryResolved  string        `json:"advisory_resolved,omitempty"`
	AdvisoryModified  string        `json:"advisory_modified,omitempty"`
	// OSVFetches is the count of recorded OSV fetch records for this task;
	// OSVFetchLog names the control-plane JSONL file they were written to.
	OSVFetches  int    `json:"osv_fetches"`
	OSVFetchLog string `json:"osv_fetch_log,omitempty"`
	// Snapshot-local product facts captured after the analysis (adapter
	// version 2 provenance): the discovered release toolchain and its
	// source, minimum go directive, build platform and module mode.
	ReleaseGoVersion string   `json:"release_go_version,omitempty"`
	GoVersionSource  string   `json:"go_version_source,omitempty"`
	MinimumGoVersion string   `json:"minimum_go_version,omitempty"`
	VendorMode       bool     `json:"vendor_mode"`
	CGOEnabled       bool     `json:"cgo_enabled"`
	GOOS             string   `json:"goos,omitempty"`
	GOARCH           string   `json:"goarch,omitempty"`
	BuildTags        []string `json:"build_tags,omitempty"`
	WallSeconds      float64  `json:"wall_seconds"`
}

// runVexCase analyses one task and returns its prediction plus result
// envelope. Envelope errors are per-case failures, not fatal.
func runVexCase(ctx context.Context, t vexbench.Task, reposDir, outDir string, tc toolchain.Toolchain, osvDir string) (vexbench.Prediction, vexEnvelope) {
	start := time.Now()
	env := vexEnvelope{
		TaskID:           t.TaskID,
		RequestedCVE:     t.CVEID,
		TerminalState:    "FAILED",
		CompatibilityCat: vexbench.CategoryUncertain,
		AdvisorySource:   "",
		ScoringOutcome:   string(vexbench.OutcomeFailed),
	}
	pred := vexbench.Prediction{TaskID: t.TaskID, RequestedCVE: t.CVEID, Failed: true}

	repoPath, err := vexbench.LocateSnapshot(reposDir, t)
	if err != nil {
		env.Error = err.Error()
		env.Reason = "snapshot not found"
		env.WallSeconds = time.Since(start).Seconds()
		pred.Category = vexbench.CategoryUncertain
		return pred, env
	}
	env.SnapshotRepo = repoPath
	env.ExternalCommitSHA = t.CommitSHA

	caseDir := filepath.Join(outDir, sanitizeCaseName(t.TaskID))
	advisoryDir := filepath.Join(caseDir, "advisory")
	// Benchmark provenance: record every OSV fetch (direct, alias,
	// rejected) with exact UTC times and byte-identical bodies, outside
	// the advisory dir. The wrapped fetcher changes nothing about
	// resolution order or outcome.
	var adv vexbench.AdvisoryResult
	var aerr error
	if osvDir != "" {
		adv, aerr = vexbench.PrepareFrozenAdvisory(ctx, t.CVEID, advisoryDir, osvDir)
		adv.Source = "frozen_dir"
		if aerr == nil && adv.Outcome == vexbench.AdvisoryError {
			aerr = fmt.Errorf("frozen advisory for %s: %s", t.CVEID, adv.Reason)
		}
	} else {
		// Benchmark provenance records every live OSV fetch.
		osvRec := vexbench.NewFetchRecorder(t.TaskID, t.CVEID, filepath.Join(outDir, "provenance"), nil)
		adv, aerr = vexbench.PrepareAdvisory(ctx, t.CVEID, advisoryDir, osvRec.Fetch)
		env.OSVFetchLog = "provenance/osv-fetches.jsonl"
		env.OSVFetches = osvRec.Count()
		osvRec.MarkChosen(adv.SHA256)
		if ferr := osvRec.Flush(); ferr != nil {
			aerr = ferr
			env.Reason = "provenance capture failed"
		}
	}
	if osvDir == "" {
		adv.Source = "live_osv"
	}
	env.AdvisorySource = adv.Source
	env.AdvisorySHA256 = adv.SHA256
	env.AdvisoryCanonical = adv.CanonicalSHA256
	env.AdvisoryResolved = adv.Resolved
	env.AdvisoryModified = adv.Modified
	if aerr != nil {
		env.Error = "advisory: " + aerr.Error()
		env.Reason = "advisory not prepared"
		env.WallSeconds = time.Since(start).Seconds()
		return pred, env
	}
	switch adv.Outcome {
	case vexbench.AdvisoryError, vexbench.AdvisoryUnsupported, vexbench.AdvisoryPartial:
		// A document the analyzer cannot safely consume is an input-capability
		// failure, not an abstention: feeding an unusable Go entry (no valid
		// version range) would make the affected resolver report
		// VersionAffected=FALSE for a module that is actually present — a
		// false-safe. Until the entry can be carried as pending, such a
		// document is not fed to the analysis, the case publishes no verdict
		// and is scored as a failed analysis.
		env.TerminalState = string(domain.StateFailed)
		env.AssessmentOutcome = string(domain.OutcomeFailed)
		env.FailureCodes = []string{"INPUT/INPUT_RESOLUTION_FAILED"}
		env.Reason = "advisory " + adv.Outcome.String() + ": " + adv.Reason
		env.Limitations = []string{env.Reason}
		env.ScoringOutcome = string(vexbench.Classify(t, vexbench.Prediction{
			TaskID: t.TaskID, RequestedCVE: t.CVEID,
			AssessmentOutcome: string(domain.OutcomeFailed), Failed: true,
			Category: vexbench.CategoryUncertain,
		}))
		env.CompatibilityCat = vexbench.CategoryUncertain
		env.WallSeconds = time.Since(start).Seconds()
		return vexbench.Prediction{
			TaskID: t.TaskID, RequestedCVE: t.CVEID,
			AssessmentOutcome: string(domain.OutcomeFailed),
			Category:          vexbench.CategoryUncertain,
			Failed:            true,
		}, env
	}

	o := analyzeOpts{
		repo:              repoPath,
		vulnID:            t.CVEID,
		vulnFile:          adv.Path,
		externalCommitSHA: t.CommitSHA,
		detOnly:           true,
		suppressEnvFile:   true,
		envReplace:        true,
		confineReads:      true,
		advisoryDir:       advisoryDir,
		caseDir:           caseDir,
		perimeterMode:     "auto",
		cveAnalysis:       "off",
		toolchain:         tc,
	}
	c, err := analyzeCase(ctx, o)
	if err != nil {
		env.Error = err.Error()
		env.Reason = "analysis failed"
		env.WallSeconds = time.Since(start).Seconds()
		return pred, env
	}

	env.TerminalState = string(c.Workflow.State)
	env.CaseDir = caseDir
	env.ReportPath = filepath.Join(caseDir, string(c.ID), "report.json")
	if c.Product.ExternalCommitSHA != "" {
		env.ContentHash = c.Product.ContentHash
	}
	env.ToolCalls = c.Workflow.Usage.ToolCalls
	env.LLMCalls = c.Workflow.Usage.LLMCalls
	if c.Vulnerability.ID != "" {
		env.ResolvedVulnID = c.Vulnerability.ID
	}
	env.ReleaseGoVersion = c.Product.ReleaseGoVersion
	env.GoVersionSource = string(c.Product.GoVersionSource)
	env.MinimumGoVersion = c.Product.MinimumGoVersion
	env.VendorMode = c.Product.VendorMode
	env.CGOEnabled = c.Product.CGOEnabled
	env.GOOS = c.Product.GOOS
	env.GOARCH = c.Product.GOARCH
	env.BuildTags = c.Product.BuildTags

	// The benchmark envelope carries the requested answer, projected and
	// re-admitted by the same gate reports and exports use.
	view, perr := projectRequested(c)
	if perr != nil {
		env.ProjectionError = perr.Error()
		env.AssessmentOutcome = string(domain.OutcomeFailed)
		env.Reason = "requested finding is not publishable"
		env.WallSeconds = time.Since(start).Seconds()
		env.ScoringOutcome = string(vexbench.OutcomeFailed)
		return vexbench.Prediction{
			TaskID: t.TaskID, RequestedCVE: t.CVEID,
			AssessmentOutcome: string(domain.OutcomeFailed),
			Category:          vexbench.CategoryUncertain,
			Failed:            true,
		}, env
	}
	pred = vexOutcomeFromView(view, &env, t)
	env.ScoringOutcome = string(vexbench.Classify(t, pred))
	env.WallSeconds = time.Since(start).Seconds()
	return pred, env
}

// vexOutcomeFromView projects the requested answer into the benchmark envelope
// and the scorer's prediction. It is the only place the benchmark turns a case
// into a conclusion. A record-scoped answer to a CVE-scoped task is refused: it
// must never be scored against CVE-wide ground truth.
func vexOutcomeFromView(view requestedView, env *vexEnvelope, t vexbench.Task) vexbench.Prediction {
	requested := view.Finding
	if isCVETask(t.CVEID) && requested.RequestedKind != domain.ScopeCVE {
		env.RequestedKind = string(requested.RequestedKind)
		env.Coverage = string(requested.Coverage)
		env.AssessmentOutcome = string(domain.OutcomeFailed)
		env.FailureCodes = []string{"SCOPE/UNSUPPORTED_NEGATIVE_SCOPE"}
		env.Reason = "requested kind " + string(requested.RequestedKind) + " cannot answer a CVE-scoped benchmark task"
		env.Limitations = append([]string(nil), requested.Limitations...)
		env.CompatibilityCat = vexbench.CategoryUncertain
		return vexbench.Prediction{
			TaskID: t.TaskID, RequestedCVE: t.CVEID,
			AssessmentOutcome: string(domain.OutcomeFailed),
			Category:          vexbench.CategoryUncertain,
			Failed:            true,
		}
	}
	env.RequestedKind = string(requested.RequestedKind)
	env.Coverage = string(requested.Coverage)
	env.AssessmentOutcome = string(requested.Outcome)
	env.Verdict = string(requested.Verdict)
	env.Reason = requested.Reason
	env.FailureCodes = projectedFailureCodes(requested.FindingProfile)
	env.ExternalDependencies = projectedExternalFacts(requested.FindingProfile)
	env.ExploitabilityScope = string(requested.ExploitabilityScope)
	env.Profile = string(requested.Profile)
	env.Build = buildLabel(requested.Build)
	env.CorpusDigest = projectedCorpusDigest(view.View.Primary, requested.FindingProfile)
	env.CandidateIDs = projectedCandidates(view.View.Primary)
	env.AttributionOutcomes = projectedAttributions(view.View.Primary)
	if primary := view.View.Primary; primary != nil && primary.RecordPin != nil {
		env.PrimaryRecord = primary.RecordPin.RecordID
		env.PrimaryDigest = primary.RecordPin.DocumentDigest
	}
	for _, origin := range requested.ProofOrigins {
		env.ProofOrigins = append(env.ProofOrigins, vexOriginRef{
			AssessmentID:   string(origin.AssessmentID),
			RecordID:       origin.Record.RecordID,
			DocumentDigest: origin.Record.DocumentDigest,
			EntryRefs:      append([]int(nil), origin.EntryRefs...),
			MechanismID:    origin.MechanismID,
			AttributionID:  origin.AttributionID,
			Profile:        string(origin.Profile),
		})
	}

	// The claim/falsifier projection comes from the record that grounds the
	// answer, so a composed CVE positive shows its witness's conditions.
	grounding := view.groundingRecord()
	var limitations []string
	if grounding != nil {
		_, _, conditions, falsifier, groundBasis, evidenceIDs, groundingLimitations := vexVerdict(grounding)
		env.GroundingCond = conditions
		env.Falsifier = falsifier
		env.GroundBasis = groundBasis
		env.EvidenceIDs = evidenceIDs
		env.Claims = vexClaims(grounding)
		limitations = groundingLimitations
	}
	env.Limitations = mergeLimitations(requested.Limitations, limitations)

	disc := ""
	if grounding != nil {
		disc = vexDiscriminator(grounding, env.Verdict, env.Falsifier, env.GroundBasis)
	}
	if requested.CorpusNegativeBasis != nil {
		// A corpus-bounded CVE negative is a boundary statement plus candidate
		// negatives, not a component-absence proof; no official compatibility
		// category represents it, so it projects to uncertain.
		disc = ""
	}
	env.CompatibilityCat = vexbench.CompatibilityCategory(env.Verdict, disc)
	return vexbench.Prediction{
		TaskID:            t.TaskID,
		RequestedCVE:      t.CVEID,
		AssessmentOutcome: string(requested.Outcome),
		Verdict:           env.Verdict,
		Category:          env.CompatibilityCat,
		Failed:            requested.Outcome == domain.OutcomeFailed,
	}
}

// isCVETask reports whether the benchmark task's request is CVE-scoped. A
// CVE-scoped task is answered only by a CVE-scoped requested finding; an exact
// record answer must never be scored against CVE-wide ground truth.
func isCVETask(id string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-")
}

// mergeLimitations concatenates limitation sets, dropping duplicates and empty
// entries while preserving the first occurrence.
func mergeLimitations(sets ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, set := range sets {
		for _, limitation := range set {
			if limitation == "" || seen[limitation] {
				continue
			}
			seen[limitation] = true
			out = append(out, limitation)
		}
	}
	return out
}

// vexVerdict extracts the authoritative verdict plus its grounding claim
// from a finished case. A case that ended without a verdict record is an
// abstention if the workflow reached INCONCLUSIVE, otherwise a failure.
func vexVerdict(c *domain.AnalysisCase) (verdict, reason string, conditionIDs []string, falsifier, groundBasis string, evidenceIDs, limitations []string) {
	if c.Verdict == nil {
		if c.Workflow.State == domain.StateInconclusive {
			return string(domain.VerdictInconclusive), "workflow ended inconclusive", nil, "", "", nil, c.EvidenceGraph.Limitations
		}
		return "", "workflow ended without a verdict", nil, "", "", nil, c.EvidenceGraph.Limitations
	}
	verdict = string(c.Verdict.Verdict)
	reason = c.Verdict.Reason
	groundBasis = c.Verdict.GroundBasis
	limitations = c.Verdict.Limitations
	for _, id := range c.Verdict.ConditionIDs {
		conditionIDs = append(conditionIDs, string(id))
	}
	// The verdict's grounding claim carries the falsifier that cleared the
	// case (eval.go does the same extraction).
	if len(c.Verdict.ConditionIDs) > 0 {
		for _, cl := range c.Claims {
			if cl.ConditionID == c.Verdict.ConditionIDs[0] {
				falsifier = cl.Falsifier
				for _, id := range cl.EvidenceIDs {
					evidenceIDs = append(evidenceIDs, string(id))
				}
				break
			}
		}
	}
	return verdict, reason, conditionIDs, falsifier, groundBasis, evidenceIDs, limitations
}

// vexClaims projects the case's condition records into the benchmark
// envelope. It keeps the negative-verification state and limitation
// references, so calibration can tell an admitted negative from one that was
// demoted or refused before the verdict was rendered.
func vexClaims(c *domain.AnalysisCase) []vexClaimRef {
	if c == nil || len(c.Claims) == 0 {
		return nil
	}
	out := make([]vexClaimRef, 0, len(c.Claims))
	for _, cl := range c.Claims {
		ref := vexClaimRef{
			ID:             string(cl.ID),
			ConditionID:    string(cl.ConditionID),
			Result:         string(cl.Result),
			Falsifier:      cl.Falsifier,
			FalsifierBasis: cl.FalsifierBasis,
			Explanation:    cl.Explanation,
			Limitations:    append([]string(nil), cl.Limitations...),
		}
		for _, id := range cl.EvidenceIDs {
			ref.EvidenceIDs = append(ref.EvidenceIDs, string(id))
		}
		if cl.NegativeVerification != nil {
			ref.Verification = string(cl.NegativeVerification.Status)
			ref.VerificationNotes = cl.NegativeVerification.Notes
		}
		out = append(out, ref)
	}
	return out
}

// vexDiscriminator supplies the compatibility discriminator: for
// NOT_AFFECTED it is the AffectedResult field that closed the case; for
// NO_EXPLOIT_PATH_FOUND it is the grounding falsifier, with the trust basis
// appended when the falsifier is trusted-infrastructure.
func vexDiscriminator(c *domain.AnalysisCase, verdict, falsifier, groundBasis string) string {
	switch verdict {
	case string(domain.VerdictNotAffected):
		if c.Affected == nil {
			return ""
		}
		switch {
		case c.Affected.ModulePresent == domain.ClaimFalse:
			return vexbench.AffectedModuleAbsent
		case c.Affected.VersionAffected == domain.ClaimFalse:
			return vexbench.AffectedVersionFixed
		case c.Affected.PackagePresent == domain.ClaimFalse:
			return vexbench.AffectedPackageAbsent
		case c.Affected.BuildRelevant == domain.ClaimFalse:
			return vexbench.AffectedBuildExcluded
		case c.Affected.VulnerableImplementationPresent == domain.ClaimFalse:
			return vexbench.AffectedImplementationAbsent
		}
		return ""
	case string(domain.VerdictNoExploitPathFound):
		if falsifier == domain.FalsifierTrustedInfrastructure && groundBasis != "" {
			return falsifier + ":" + groundBasis
		}
		return falsifier
	}
	return ""
}

// writeVexArtifacts persists the per-case envelopes, the aggregate metrics
// and the safety-aware case list. Ground truth is never written to the
// envelope files.
func writeVexArtifacts(outDir, tasksPath string, tasks []vexbench.Task, preds []vexbench.Prediction, envs []vexEnvelope, m vexbench.Metrics, tc toolchain.Toolchain, selfBinary string, cliJ int) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, env := range envs {
		dir := filepath.Join(outDir, sanitizeCaseName(env.TaskID))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		data, _ := json.MarshalIndent(env, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "prediction.json"), append(data, '\n'), 0o644); err != nil {
			return err
		}
	}

	metricsDoc := struct {
		vexbench.Metrics
		Provenance vexProvenance `json:"provenance"`
	}{Metrics: m, Provenance: collectVexProvenance(tasksPath, tasks, envs, tc, selfBinary, cliJ)}
	data, _ := json.MarshalIndent(metricsDoc, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "metrics.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}

	// cases.jsonl joins prediction to hidden ground truth — the only
	// artifact that carries labels, kept in the scorer's directory.
	scoringDir := filepath.Join(outDir, "scoring")
	if err := os.MkdirAll(scoringDir, 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	byID := map[string]vexbench.Prediction{}
	for _, p := range preds {
		byID[p.TaskID] = p
	}
	envsByID := map[string]vexEnvelope{}
	for _, env := range envs {
		envsByID[env.TaskID] = env
	}
	for _, t := range tasks {
		p := byID[t.TaskID]
		env := envsByID[t.TaskID]
		row := struct {
			TaskID              string   `json:"task_id"`
			CVEID               string   `json:"cve_id"`
			AssessmentOutcome   string   `json:"assessment_outcome,omitempty"`
			Verdict             string   `json:"verdict"`
			FailureCodes        []string `json:"failure_codes,omitempty"`
			Category            string   `json:"compatibility_category"`
			ScoringOutcome      string   `json:"scoring_outcome"`
			GroundTruth         string   `json:"ground_truth"`
			GroundTruthCategory string   `json:"ground_truth_category"`
		}{
			TaskID: t.TaskID, CVEID: t.CVEID,
			AssessmentOutcome:   env.AssessmentOutcome,
			Verdict:             p.Verdict,
			FailureCodes:        env.FailureCodes,
			Category:            p.Category,
			ScoringOutcome:      string(vexbench.Classify(t, p)),
			GroundTruth:         t.GroundTruth,
			GroundTruthCategory: t.GroundTruthCategory,
		}
		line, _ := json.Marshal(row)
		sb.Write(line)
		sb.WriteByte('\n')
	}
	return os.WriteFile(filepath.Join(scoringDir, "cases.jsonl"), []byte(sb.String()), 0o644)
}

// filterVexTasks keeps tasks whose ID matches one of the comma-separated
// exact IDs or globs.
func filterVexTasks(tasks []vexbench.Task, filter string) ([]vexbench.Task, error) {
	patterns := strings.Split(filter, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}
	var out []vexbench.Task
	for _, t := range tasks {
		for _, pat := range patterns {
			if pat == "" {
				continue
			}
			if pat == t.TaskID {
				out = append(out, t)
				break
			}
			if m, _ := filepath.Match(pat, t.TaskID); m {
				out = append(out, t)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("vex-bench: no tasks matching --case %q", filter)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TaskID < out[j].TaskID })
	return out, nil
}
