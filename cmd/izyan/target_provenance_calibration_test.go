package main

// Opt-in end-to-end calibration for the two negative-admission gates on real
// VEX-Bench snapshots. The deterministic regressions live in
// internal/states/target_provenance_e2e_test.go; this test only exists to
// restate the pinned real cases:
//
//   - cilium-cilium-1228cbc-CVE-2026-35469: host-default cannot type-check a
//     Linux-only product, so the same snapshot measured under an explicit
//     linux/amd64 target keeps the positive. Everything except the target
//     inputs is identical between the pair.
//   - containers-podman-38ccfa2-CVE-2024-37298: a false alarm whose positive
//     comes from a module chain; the provenance fix must NOT remove it to
//     improve calibration. Its measured claims are recorded verbatim.
//   - kubernetes-kubernetes-6d4b94f-CVE-2022-41717: a timeout/incomplete
//     measurement. It is recorded as an infrastructure outcome and must never
//     read as a corrected safe result.
//
// It needs the external corpus, and skips with named prerequisites when any
// asset is missing — never a silent pass:
//
//	VA_VEX_TASKS   vex_bench_go.jsonl
//	VA_SNAPSHOTS   snapshot root (<owner>/<repo>/<commit>)
//	VA_FROZEN_OSV  frozen OSV advisory directory
//	VA_CASES       output root for case directories
//
// Snapshots carry no .git: put the benchmark git shim first on PATH and set
// IZYAN_SNAPSHOT_SHA per run (see the calibration report).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
)

const (
	calibrationCiliumTask     = "cilium-cilium-1228cbc-CVE-2026-35469"
	calibrationPodmanTask     = "containers-podman-38ccfa2-CVE-2024-37298"
	calibrationKubernetesTask = "kubernetes-kubernetes-6d4b94f-CVE-2022-41717"
)

// calibrationLedger is the tested, human-readable record of one run: the
// snapshot/advisory identity, the target provenance and effective build, the
// tool-run outcome with its actual scan pattern and coverage, the claim-level
// projection, and the terminal verdict. It never carries ground truth into
// the analysis — the label is recorded separately for the calibration report.
type calibrationLedger struct {
	TaskID           string   `json:"task_id"`
	CVE              string   `json:"cve"`
	Commit           string   `json:"commit"`
	SnapshotRepo     string   `json:"snapshot_repo"`
	GroundTruthLabel string   `json:"ground_truth_category,omitempty"`
	TargetRequest    string   `json:"target_request"`
	TargetSource     string   `json:"target_source,omitempty"`
	TargetScope      string   `json:"target_scope,omitempty"`
	GOOS             string   `json:"goos"`
	GOARCH           string   `json:"goarch"`
	BuildTags        []string `json:"build_tags,omitempty"`
	CGOEnabled       bool     `json:"cgo_enabled"`
	TerminalState    string   `json:"terminal_state"`
	Verdict          string   `json:"verdict,omitempty"`
	VerdictReason    string   `json:"verdict_reason,omitempty"`
	GroundingIDs     []string
	Falsifier        string `json:"falsifier,omitempty"`
	GroundBasis      string `json:"ground_basis,omitempty"`
	RunOutcome       string `json:"govulncheck_outcome,omitempty"`
	RunPattern       string `json:"govulncheck_pattern,omitempty"`
	RunMode          string `json:"govulncheck_mode,omitempty"`
	RunError         string `json:"govulncheck_error,omitempty"`
	AdvisoryCoverage string `json:"advisory_coverage,omitempty"`
	DeclaredSubjects []string
	ScopeComplete    bool
	Claims           []vexClaimRef `json:"claims,omitempty"`
	EvidenceIDs      []string
	Limitations      []string
	Error            string  `json:"error,omitempty"`
	Outcome          string  `json:"outcome"`
	WallSeconds      float64 `json:"wall_seconds"`
}

// calibrationRun is one executed analysis plus its recording.
type calibrationRun struct {
	ledger *calibrationLedger
	c      *domain.AnalysisCase
	err    error
}

func TestTargetProvenanceCalibration(t *testing.T) {
	tasksPath := strings.TrimSpace(os.Getenv("VA_VEX_TASKS"))
	reposDir := strings.TrimSpace(os.Getenv("VA_SNAPSHOTS"))
	osvDir := strings.TrimSpace(os.Getenv("VA_FROZEN_OSV"))
	casesDir := strings.TrimSpace(os.Getenv("VA_CASES"))

	var missing []string
	for _, in := range []struct {
		name  string
		value string
		kind  string
	}{
		{"VA_VEX_TASKS", tasksPath, "file"},
		{"VA_SNAPSHOTS", reposDir, "dir"},
		{"VA_FROZEN_OSV", osvDir, "dir"},
		{"VA_CASES", casesDir, "dir"},
	} {
		if in.value == "" {
			missing = append(missing, in.name+" (unset)")
			continue
		}
		info, err := os.Stat(in.value)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s=%s (%v)", in.name, in.value, err))
			continue
		}
		if in.kind == "dir" && !info.IsDir() {
			missing = append(missing, fmt.Sprintf("%s=%s (not a directory)", in.name, in.value))
		}
		if in.kind == "file" && info.IsDir() {
			missing = append(missing, fmt.Sprintf("%s=%s (not a file)", in.name, in.value))
		}
	}
	if len(missing) > 0 {
		t.Skipf("target-provenance calibration requires the external VEX-Bench corpus: %s", strings.Join(missing, "; "))
	}
	if err := os.MkdirAll(casesDir, 0o755); err != nil {
		t.Fatalf("prepare VA_CASES: %v", err)
	}

	tasks, err := vexbench.LoadGoTasks(tasksPath)
	if err != nil {
		t.Fatalf("load tasks: %v", err)
	}
	byID := make(map[string]vexbench.Task, len(tasks))
	for _, task := range tasks {
		byID[task.TaskID] = task
	}
	for _, id := range []string{calibrationCiliumTask, calibrationPodmanTask, calibrationKubernetesTask} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("pinned calibration case %s is absent from %s", id, tasksPath)
		}
	}

	ctx := context.Background()
	budget, err := parseMemLimit(firstNonEmpty(os.Getenv("VA_MEM_LIMIT"), "24GiB"))
	if err != nil {
		t.Fatalf("VA_MEM_LIMIT: %v", err)
	}
	ctx, stop := applyMemoryLimit(ctx, budget)
	defer stop()

	tc, lims := resolveAnalysisToolchain(ctx, "")
	if tc.GoBin == "" {
		t.Fatalf("analysis toolchain unresolved: %s", strings.Join(lims, "; "))
	}
	t.Logf("analysis toolchain: go%s (%s); memory budget: %s", tc.Version, tc.Mode, firstNonEmpty(os.Getenv("VA_MEM_LIMIT"), "24GiB"))

	// The frozen corpus is keyed by OSV id (GO-*/GHSA-*); the benchmark asks
	// by CVE. Resolve each pinned CVE to its aliased document up front and
	// fail loudly when one is missing, rather than turning a corpus gap into
	// an analysis result.
	frozenIndex := indexFrozenAdvisories(t, osvDir, []string{
		byID[calibrationCiliumTask].CVEID,
		byID[calibrationPodmanTask].CVEID,
		byID[calibrationKubernetesTask].CVEID,
	})

	// run analyses one pinned task under the given target request. Every
	// other input is held constant: snapshot, external commit, advisory,
	// toolchain, isolation profile, and execution settings.
	run := func(t *testing.T, taskID, target string, goos, goarch string) calibrationRun {
		t.Helper()
		task := byID[taskID]
		snapshot, err := vexbench.LocateSnapshot(reposDir, task)
		if err != nil {
			t.Fatalf("%s: %v", taskID, err)
		}
		caseDir := filepath.Join(casesDir, sanitizeCaseName(taskID), sanitizeCaseName(target))
		advisoryDir := filepath.Join(caseDir, "advisory")
		fetchDir := materializeCVEAdvisory(t, osvDir, frozenIndex, task.CVEID, caseDir)
		adv, err := vexbench.PrepareFrozenAdvisory(ctx, task.CVEID, advisoryDir, fetchDir)
		if err != nil {
			t.Fatalf("%s: frozen advisory: %v", taskID, err)
		}
		switch adv.Outcome {
		case vexbench.AdvisoryError, vexbench.AdvisoryUnsupported, vexbench.AdvisoryPartial:
			t.Fatalf("%s: frozen advisory for %s is %s: %s", taskID, task.CVEID, adv.Outcome, adv.Reason)
		}
		t.Setenv("IZYAN_SNAPSHOT_SHA", task.CommitSHA)

		opts := analyzeOpts{
			repo:              snapshot,
			vulnID:            task.CVEID,
			vulnFile:          adv.Path,
			externalCommitSHA: task.CommitSHA,
			goos:              goos,
			goarch:            goarch,
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
		start := time.Now()
		c, err := analyzeCase(ctx, opts)
		wall := time.Since(start)

		ledger := &calibrationLedger{
			TaskID:           taskID,
			CVE:              task.CVEID,
			Commit:           task.CommitSHA,
			SnapshotRepo:     snapshot,
			GroundTruthLabel: task.GroundTruthCategory,
			TargetRequest:    target,
			WallSeconds:      wall.Seconds(),
			Outcome:          "completed",
		}
		if err != nil {
			ledger.Outcome = "infrastructure"
			ledger.Error = err.Error()
			return calibrationRun{ledger: ledger, err: err}
		}
		ledger.TerminalState = string(c.Workflow.State)
		ledger.GOOS = c.Product.GOOS
		ledger.GOARCH = c.Product.GOARCH
		ledger.BuildTags = c.Product.BuildTags
		ledger.CGOEnabled = c.Product.CGOEnabled
		if c.Product.Target != nil {
			ledger.TargetSource = c.Product.Target.Source
			ledger.TargetScope = c.Product.Target.Scope
		}
		for _, e := range c.EvidenceGraph.Evidence {
			if e.Kind != domain.EvidenceGovulncheck || e.Govulncheck == nil {
				continue
			}
			run := e.Govulncheck
			ledger.RunOutcome = string(run.Outcome)
			ledger.RunPattern = run.Pattern
			ledger.RunMode = run.Mode
			ledger.RunError = run.Error
			ledger.AdvisoryCoverage = string(run.Coverage.Advisory)
			ledger.ScopeComplete = run.Coverage.ScopeComplete
			for _, s := range run.Coverage.Subjects {
				ledger.DeclaredSubjects = append(ledger.DeclaredSubjects, s.Package+"."+s.Symbol)
			}
		}
		verdict, reason, grounding, falsifier, groundBasis, evidenceIDs, limitations := vexVerdict(c)
		ledger.Verdict = verdict
		ledger.VerdictReason = reason
		for _, id := range grounding {
			ledger.GroundingIDs = append(ledger.GroundingIDs, string(id))
		}
		ledger.Falsifier = falsifier
		ledger.GroundBasis = groundBasis
		for _, id := range evidenceIDs {
			ledger.EvidenceIDs = append(ledger.EvidenceIDs, string(id))
		}
		ledger.Limitations = limitations
		ledger.Claims = vexClaims(c)
		return calibrationRun{ledger: ledger, c: c}
	}

	// logRun emits the ledger in the calibration report's format and fails
	// when a retained FALSE is not an admitted, verified negative.
	logRun := func(t *testing.T, r calibrationRun) {
		t.Helper()
		raw, err := json.MarshalIndent(r.ledger, "", "  ")
		if err != nil {
			t.Fatalf("encode ledger: %v", err)
		}
		t.Logf("calibration ledger %s [%s]:\n%s", r.ledger.TaskID, r.ledger.TargetRequest, raw)
		if r.c != nil {
			assertAdmittedNegatives(t, r.c)
		}
	}

	t.Run("cilium host-default vs explicit linux/amd64", func(t *testing.T) {
		// Host default: no target inputs at all. Cilium is Linux-only, so the
		// host build selection cannot type-check the product and no
		// build-dependent negative may close.
		defaultRun := run(t, calibrationCiliumTask, "host-default", "", "")
		logRun(t, defaultRun)
		if defaultRun.err != nil {
			t.Fatalf("host-default analysis failed: %v", defaultRun.err)
		}
		if got := defaultRun.ledger.TargetSource; got != domain.ProductTargetSourceHostDefault && got != "" {
			t.Fatalf("target source=%q, want host-default (no other target input was supplied)", got)
		}
		if defaultRun.c.Verdict == nil || defaultRun.c.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("host-default verdict=%+v, want INCONCLUSIVE", defaultRun.c.Verdict)
		}
		for _, id := range []domain.ConditionID{"C-REACH", "C-LOCUS"} {
			assertNotProven(t, defaultRun.c, id)
		}

		// The paired run keeps every other input; only the target changes.
		targetRun := run(t, calibrationCiliumTask, "linux/amd64", "linux", "amd64")
		logRun(t, targetRun)
		if targetRun.err != nil {
			t.Fatalf("linux/amd64 analysis failed: %v", targetRun.err)
		}
		if got := targetRun.ledger.TargetSource; got != domain.ProductTargetSourceOperatorDeclared {
			t.Fatalf("target source=%q, want operator-declared", got)
		}
		reach := findCalibrationClaim(t, targetRun.c, "C-REACH")
		if reach == nil || reach.Result != domain.ClaimTrue {
			t.Fatalf("linux/amd64 C-REACH=%+v, want the measured positive", reach)
		}
		if targetRun.c.Verdict == nil || targetRun.c.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("linux/amd64 verdict=%+v, want EXPLOITABLE", targetRun.c.Verdict)
		}
	})

	t.Run("podman false alarm is recorded unchanged", func(t *testing.T) {
		// The harness supplies no target inputs, so this is the host-default
		// path. Its module-chain positive is independent evidence: the
		// provenance fix must neither remove it nor manufacture a safe result.
		r := run(t, calibrationPodmanTask, "host-default", "", "")
		logRun(t, r)
		if r.err != nil {
			t.Fatalf("podman analysis failed: %v", r.err)
		}
		if r.c.Verdict == nil {
			t.Fatal("podman analysis produced no verdict")
		}
		if reach := findCalibrationClaim(t, r.c, "C-REACH"); reach != nil && reach.Result == domain.ClaimTrue {
			// Recorded, not removed: a module-chain positive must cite its
			// evidence and carry no falsifier.
			if reach.Falsifier != "" {
				t.Fatalf("podman C-REACH TRUE carries falsifier %q", reach.Falsifier)
			}
			if len(reach.EvidenceIDs) == 0 {
				t.Fatal("podman C-REACH TRUE cites no evidence")
			}
			t.Logf("podman module-chain positive survives: %s", reach.Explanation)
		}
		if r.c.Verdict.Verdict == domain.VerdictNotAffected ||
			r.c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
			t.Logf("podman false alarm remains: verdict=%s falsifier=%s basis=%s",
				r.c.Verdict.Verdict, r.ledger.Falsifier, r.c.Verdict.GroundBasis)
		}
	})

	t.Run("kubernetes incomplete measurement is never a corrected safe result", func(t *testing.T) {
		r := run(t, calibrationKubernetesTask, "host-default", "", "")
		logRun(t, r)
		if r.err != nil {
			// An aborted run is an infrastructure outcome. Only a
			// deadline/cancellation/kill class may pass as such: any other
			// error is a real failure of the calibration.
			if !infrastructureError(r.err) {
				t.Fatalf("kubernetes analysis failed for a non-infrastructure reason: %v", r.err)
			}
			t.Logf("kubernetes outcome=infrastructure (not a measurement, not a safe result): %v", r.err)
			return
		}
		if r.c.Verdict == nil {
			t.Fatalf("kubernetes reached %s without a verdict: %s", r.c.Workflow.State, r.c.Workflow.Reason)
		}
		switch r.c.Verdict.Verdict {
		case domain.VerdictNotAffected, domain.VerdictNoExploitPathFound:
			t.Fatalf("kubernetes produced the safe verdict %s from an incomplete measurement: %s",
				r.c.Verdict.Verdict, r.c.Verdict.Reason)
		}
		if r.c.Verdict.Verdict != domain.VerdictInconclusive {
			t.Logf("kubernetes verdict=%s (recorded verbatim; ground truth %s)",
				r.c.Verdict.Verdict, r.ledger.GroundTruthLabel)
		}
	})
}

// indexFrozenAdvisories maps every requested CVE to the frozen OSV document
// that lists it (by id or alias). The scan stops once every CVE is found.
// Documents are only read; the corpus is never modified.
func indexFrozenAdvisories(t *testing.T, osvDir string, cves []string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(osvDir)
	if err != nil {
		t.Fatalf("read frozen OSV dir: %v", err)
	}
	want := make(map[string]bool, len(cves))
	for _, cve := range cves {
		want[cve] = true
	}
	found := map[string]string{}
	// Both *_all.jsonl-style dumps and per-document files are absent here:
	// the corpus is one JSON document per OSV record.
	type docIdentity struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	}
	for _, entry := range entries {
		if len(found) == len(want) && allGoRecords(found) {
			break
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(osvDir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var doc docIdentity
		if err := json.Unmarshal(raw, &doc); err != nil || doc.ID == "" {
			continue
		}
		ids := append([]string{doc.ID}, doc.Aliases...)
		for _, cve := range cves {
			for _, id := range ids {
				if id != cve {
					continue
				}
				// Prefer the Go-database record: it carries the declared
				// import symbols, which the analysis consumes.
				prev, seen := found[cve]
				if seen && strings.HasPrefix(filepath.Base(prev), "GO-") {
					continue
				}
				found[cve] = path
			}
		}
	}
	var missing []string
	for _, cve := range cves {
		if _, ok := found[cve]; !ok {
			missing = append(missing, cve)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("frozen OSV corpus %s has no document aliasing %s", osvDir, strings.Join(missing, ", "))
	}
	for _, cve := range cves {
		t.Logf("frozen advisory for %s: %s", cve, found[cve])
	}
	return found
}

// allGoRecords reports whether every resolved document is a Go-database
// record, which is the preferred and most informative form.
func allGoRecords(found map[string]string) bool {
	for _, path := range found {
		if !strings.HasPrefix(filepath.Base(path), "GO-") {
			return false
		}
	}
	return len(found) > 0
}

// materializeCVEAdvisory returns a directory from which the frozen fetcher can
// answer <cve>.json. The original corpus is left untouched; a CVE-keyed copy
// is written into the case directory.
func materializeCVEAdvisory(t *testing.T, osvDir string, index map[string]string, cve, workDir string) string {
	t.Helper()
	direct := filepath.Join(osvDir, cve+".json")
	if _, err := os.Stat(direct); err == nil {
		return osvDir
	}
	path, ok := index[cve]
	if !ok {
		t.Fatalf("no frozen advisory resolved for %s", cve)
	}
	dir := filepath.Join(workDir, "frozen")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("prepare frozen fetch dir: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen advisory %s: %v", path, err)
	}
	dst := filepath.Join(dir, cve+".json")
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatalf("write frozen advisory %s: %v", dst, err)
	}
	return dir
}

// infrastructureError reports whether err is an abort class (timeout,
// cancellation, killed subprocess, memory guard) rather than an analysis
// failure.
func infrastructureError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"timeout", "timed out", "deadline", "context canceled", "signal: killed", "memory"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// findCalibrationClaim returns the case's claim for id, or nil when the model
// never carried that condition.
func findCalibrationClaim(t *testing.T, c *domain.AnalysisCase, id domain.ConditionID) *domain.Claim {
	t.Helper()
	for i := range c.Claims {
		if c.Claims[i].ConditionID == id {
			return &c.Claims[i]
		}
	}
	return nil
}

// assertNotProven requires the condition to be absent or UNKNOWN with no
// falsifier: never TRUE (a positive the host build cannot justify) and never
// FALSE (a negative the host build cannot admit).
func assertNotProven(t *testing.T, c *domain.AnalysisCase, id domain.ConditionID) {
	t.Helper()
	claim := findCalibrationClaim(t, c, id)
	if claim == nil {
		t.Logf("%s is absent from the model: nothing was proven", id)
		return
	}
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("%s=%s falsifier=%q, want UNKNOWN under a host-default build (%s)",
			id, claim.Result, claim.Falsifier, claim.Explanation)
	}
	if claim.Falsifier != "" {
		t.Fatalf("%s UNKNOWN carries falsifier %q", id, claim.Falsifier)
	}
}

// assertAdmittedNegatives is the design invariant restated on real evidence:
// every retained FALSE claim and every build-dependent affected FALSE must
// pass the verification gate against the case's own product snapshot and
// measurement records. A host-default artifact cannot survive it.
func assertAdmittedNegatives(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	evidence := c.EvidenceGraph.EvidenceList()
	conds := map[domain.ConditionID]domain.Condition{}
	if c.Exploit != nil {
		for _, cond := range append(append([]domain.Condition{}, c.Exploit.MandatoryConditions...), c.Exploit.SupportingFactors...) {
			conds[cond.ID] = cond
		}
	}
	for _, cl := range c.Claims {
		if cl.Result != domain.ClaimFalse {
			continue
		}
		cond, ok := conds[cl.ConditionID]
		if !ok {
			continue
		}
		if err := goanalysis.ValidateVerifiedNegative(goanalysis.ConfigAdmissionForCase(c), cl, cond); err != nil {
			t.Errorf("%s retains an unadmitted FALSE claim: %v", cl.ConditionID, err)
		}
	}
	if c.Affected != nil {
		if err := domain.ValidateAffectedNegative(c.Product, *c.Affected, evidence); err != nil {
			t.Errorf("affected chain retains an unadmitted negative: %v", err)
		}
	}
}
