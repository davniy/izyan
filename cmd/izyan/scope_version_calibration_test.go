package main

// Opt-in end-to-end calibration for the advisory-scope gate on real VEX-Bench
// snapshots. The deterministic regressions live in
// internal/states/scope_version_integration_test.go and the governance notes in
// docs/dev/plans/2026-10-25-05-scope-bound-version-negatives.md; this test only
// restates the pinned real cases and records a claim-level ledger.
//
// Primary pair: the recorded kubernetes snapshot e196d24 with the exact frozen
// GHSA-qppj-fm5r-hxr3 document (22 affected entries: 1 Go, 20 Maven, 1
// SwiftURL), requested twice — as CVE-2023-44487 and as the exact GHSA id. Both
// requests use identical snapshot, document bytes, target, toolchain and
// analysis settings. The x/net v0.17.0 fact stays established; the requested
// scope does not close.
//
// Named controls (invariants only — never historical "correct-safe" labels):
// helm, rancher, istio, podman, kubernetes CVE-2022-41717, a library
// non-admission group (labstack/echo plus the Podman and Kubernetes application
// controls), and the cilium host-default vs explicit linux/amd64 target pair.
// The ledger records requested/resolved identity, raw advisory digest, extent,
// census, component claims, target provenance, tool outcomes, verdict, export
// states and the infrastructure classification. Ground-truth provenance is
// recorded for the report only and is never passed into analysis.
//
// It needs the external corpus and skips with named prerequisites when any
// asset is missing — never a silent pass:
//
//	VA_VEX_TASKS   vex_bench_go.jsonl
//	VA_SNAPSHOTS   snapshot root (<owner>/<repo>/<commit>)
//	VA_FROZEN_OSV  frozen OSV advisory directory
//	VA_CASES       output root for case directories
//
// Snapshots carry no .git: put the benchmark git shim first on PATH. The test
// sets IZYAN_SNAPSHOT_SHA per task.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/eval/vexbench"
	"github.com/davniy/izyan/internal/report"
)

const (
	scopeVersionPrimaryTask  = "kubernetes-kubernetes-e196d24-CVE-2023-44487"
	scopeVersionPrimaryCVE   = "CVE-2023-44487"
	scopeVersionPrimaryGHSA  = "GHSA-qppj-fm5r-hxr3"
	scopeVersionPrimarySHA   = "e196d2491087e93bd29f0e5a538aab60667021e3"
	scopeVersionPrimaryPR    = "https://github.com/kubernetes/kubernetes/pull/121273"
	scopeVersionCanonicalSHA = "83b852adcd9c692f0712f070359449161ac7883ff4b292d6a8d18b3873da1599"

	scopeVersionTargetTask = "cilium-cilium-1228cbc-CVE-2026-35469"
	scopeVersionK8sTask    = "kubernetes-kubernetes-6d4b94f-CVE-2022-41717"
	scopeVersionPodmanTask = "containers-podman-38ccfa2-CVE-2024-37298"
	scopeVersionEchoTask   = "labstack-echo-fdacff0-CVE-2020-26160"
)

// scopeVersionControlGroups are the named control groups. The library
// non-admission group reuses the Podman and Kubernetes application controls
// recorded above; the target pair runs its task under two target requests.
var scopeVersionControlGroups = []struct {
	Name  string
	Tasks []string
}{
	{"helm", []string{
		"helm-helm-b76a950-CVE-2024-25621",
		"helm-helm-fbb24fe-CVE-2021-21334",
	}},
	{"rancher", []string{
		"rancher-rancher-4dc4f53-CVE-2025-47914",
		"rancher-rancher-4dc4f53-CVE-2025-58181",
		"rancher-rancher-8761419-CVE-2026-24051",
		"rancher-rancher-8761419-CVE-2026-39883",
	}},
	{"istio", []string{
		"istio-istio-042afc3-CVE-2023-48795",
		"istio-istio-8903f65-CVE-2024-45338",
	}},
	{"podman", []string{
		"containers-podman-6a65597-CVE-2023-48795",
		scopeVersionPodmanTask,
		"containers-podman-5ae6347-CVE-2025-47914",
	}},
	{"kubernetes-41717", []string{scopeVersionK8sTask}},
	{"library-non-admission", []string{scopeVersionEchoTask}},
	{"target-pair", []string{scopeVersionTargetTask}},
}

// scopeVersionLedger is the claim-level record of one real analysis. It never
// carries ground truth into the analysis: the label and PR provenance are
// recorded after the run for the calibration report.
type scopeVersionLedger struct {
	Group            string `json:"group"`
	TaskID           string `json:"task_id"`
	RequestedID      string `json:"requested_id"`
	ResolvedID       string `json:"resolved_id,omitempty"`
	CVE              string `json:"cve"`
	Commit           string `json:"commit"`
	SnapshotRepo     string `json:"snapshot_repo"`
	ExpectedCommit   string `json:"expected_commit,omitempty"`
	CommitMatches    bool   `json:"commit_matches,omitempty"`
	GroundTruthCat   string `json:"ground_truth_category,omitempty"`
	GroundTruthProof string `json:"ground_truth_provenance,omitempty"`

	AdvisorySource    string `json:"advisory_source,omitempty"`
	AdvisoryRawSHA256 string `json:"advisory_raw_sha256,omitempty"`
	AdvisoryCanonSHA  string `json:"advisory_canonical_sha256,omitempty"`
	CensusDigest      string `json:"census_document_digest,omitempty"`

	Extent         string         `json:"extent,omitempty"`
	Coverage       string         `json:"coverage,omitempty"`
	ScopeKind      string         `json:"scope_kind,omitempty"`
	OriginalCount  int            `json:"original_entries,omitempty"`
	Represented    int            `json:"represented_entries,omitempty"`
	Omitted        int            `json:"omitted_entries,omitempty"`
	CensusEcosys   map[string]int `json:"census_ecosystems,omitempty"`
	CensusGoMods   []string       `json:"census_go_modules,omitempty"`
	ScopeCloses    bool           `json:"scope_closes"`
	ModulePresent  string         `json:"module_present,omitempty"`
	ResolvedVer    string         `json:"resolved_version,omitempty"`
	VersionAffect  string         `json:"version_affected,omitempty"`
	PackagePresent string         `json:"package_present,omitempty"`
	BuildRelevant  string         `json:"build_relevant,omitempty"`
	CheckedModules []string       `json:"checked_modules,omitempty"`
	SelectedMods   []string       `json:"selected_modules,omitempty"`
	VersionAffMods []string       `json:"version_affected_modules,omitempty"`
	Limitations    []string       `json:"limitations,omitempty"`

	TargetRequest string   `json:"target_request"`
	TargetSource  string   `json:"target_source,omitempty"`
	TargetScope   string   `json:"target_scope,omitempty"`
	GOOS          string   `json:"goos,omitempty"`
	GOARCH        string   `json:"goarch,omitempty"`
	BuildTags     []string `json:"build_tags,omitempty"`
	CGOEnabled    bool     `json:"cgo_enabled"`
	Toolchain     string   `json:"toolchain,omitempty"`

	TerminalState   string        `json:"terminal_state,omitempty"`
	WorkflowReason  string        `json:"workflow_reason,omitempty"`
	Verdict         string        `json:"verdict,omitempty"`
	VerdictRecorded bool          `json:"verdict_recorded"`
	VerdictReason   string        `json:"verdict_reason,omitempty"`
	ExploitScope    string        `json:"exploitability_scope,omitempty"`
	Falsifier       string        `json:"falsifier,omitempty"`
	GroundBasis     string        `json:"ground_basis,omitempty"`
	Claims          []vexClaimRef `json:"claims,omitempty"`
	EvidenceIDs     []string      `json:"evidence_ids,omitempty"`

	RunOutcome       string   `json:"govulncheck_outcome,omitempty"`
	RunPattern       string   `json:"govulncheck_pattern,omitempty"`
	RunMode          string   `json:"govulncheck_mode,omitempty"`
	RunError         string   `json:"govulncheck_error,omitempty"`
	AdvisoryCoverage string   `json:"advisory_coverage,omitempty"`
	ScopeComplete    bool     `json:"scope_complete"`
	PackageLists     []string `json:"package_list_runs,omitempty"`

	OpenVEXStatus   string   `json:"openvex_status,omitempty"`
	CycloneDXState  string   `json:"cyclonedx_state,omitempty"`
	ExportProjected bool     `json:"exports_projected"`
	ReportWritten   bool     `json:"report_written"`
	ExportFiles     []string `json:"export_files,omitempty"`

	Outcome              string  `json:"outcome"`
	Infrastructure       bool    `json:"infrastructure"`
	InfrastructureReason string  `json:"infrastructure_reason,omitempty"`
	Error                string  `json:"error,omitempty"`
	WallSeconds          float64 `json:"wall_seconds"`

	reportDir string
}

// scopeVersionRun is one executed analysis plus its recording.
type scopeVersionRun struct {
	ledger *scopeVersionLedger
	c      *domain.AnalysisCase
	err    error
}

func TestScopeVersionCalibration(t *testing.T) {
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
		t.Skipf("scope-version calibration requires the external VEX-Bench corpus: %s", strings.Join(missing, "; "))
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
	pinned := []string{scopeVersionPrimaryTask}
	for _, group := range scopeVersionControlGroups {
		pinned = append(pinned, group.Tasks...)
	}
	for _, id := range pinned {
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

	// The primary pair must use the exact frozen GHSA document, not the generic
	// helper's preferred GO alias. Verify its identity before any analysis.
	exactAdvisory, advisoryRaw, advisoryCanonical := scopeVersionExactAdvisory(t, osvDir)

	// run executes one analysis with every input held constant except the ones
	// named by the arguments.
	run := func(t *testing.T, group string, task vexbench.Task, requestID, advisoryPath string,
		target, goos, goarch string) scopeVersionRun {
		t.Helper()
		snapshot, err := vexbench.LocateSnapshot(reposDir, task)
		if err != nil {
			t.Fatalf("%s: %v", task.TaskID, err)
		}
		caseDir := filepath.Join(casesDir, "scope-version", sanitizeCaseName(group),
			sanitizeCaseName(task.TaskID), sanitizeCaseName(target))
		advisoryDir := filepath.Dir(advisoryPath)
		t.Setenv("IZYAN_SNAPSHOT_SHA", task.CommitSHA)

		opts := analyzeOpts{
			repo:              snapshot,
			vulnID:            requestID,
			vulnFile:          advisoryPath,
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

		ledger := &scopeVersionLedger{
			Group:            group,
			TaskID:           task.TaskID,
			RequestedID:      requestID,
			CVE:              task.CVEID,
			Commit:           task.CommitSHA,
			SnapshotRepo:     snapshot,
			GroundTruthCat:   task.GroundTruthCategory,
			GroundTruthProof: task.PRURL,
			TargetRequest:    target,
			AdvisorySource:   advisoryPath,
			Outcome:          "completed",
			WallSeconds:      wall.Seconds(),
		}
		if task.TaskID == scopeVersionPrimaryTask {
			ledger.ExpectedCommit = scopeVersionPrimarySHA
			ledger.CommitMatches = task.CommitSHA == scopeVersionPrimarySHA
		}
		if raw, readErr := os.ReadFile(advisoryPath); readErr == nil {
			ledger.AdvisoryRawSHA256 = "sha256:" + hexDigest(raw)
			if canonical, canonicalErr := vexbench.CanonicalSHA256(raw); canonicalErr == nil {
				ledger.AdvisoryCanonSHA = canonical
			}
		}
		if advisoryPath == exactAdvisory {
			// The primary pair must have consumed exactly the verified bytes.
			ledger.AdvisoryRawSHA256 = advisoryRaw
			ledger.AdvisoryCanonSHA = advisoryCanonical
		}
		if err != nil {
			if scopeVersionInfrastructureError(err) {
				ledger.Outcome = "infrastructure"
				ledger.Infrastructure = true
				ledger.InfrastructureReason = err.Error()
			} else {
				ledger.Outcome = "failed"
			}
			ledger.Error = err.Error()
			return scopeVersionRun{ledger: ledger, err: err}
		}
		scopeVersionFillLedger(ledger, c, caseDir)
		return scopeVersionRun{ledger: ledger, c: c}
	}

	logRun := func(t *testing.T, r scopeVersionRun) {
		t.Helper()
		raw, err := json.MarshalIndent(r.ledger, "", "  ")
		if err != nil {
			t.Fatalf("encode ledger: %v", err)
		}
		t.Logf("scope-version ledger %s [%s/%s]:\n%s",
			r.ledger.TaskID, r.ledger.Group, r.ledger.TargetRequest, raw)
	}

	t.Run("primary", func(t *testing.T) {
		task := byID[scopeVersionPrimaryTask]
		if task.CVEID != scopeVersionPrimaryCVE {
			t.Fatalf("primary task CVE = %s, want %s", task.CVEID, scopeVersionPrimaryCVE)
		}
		if task.CommitSHA != scopeVersionPrimarySHA {
			t.Fatalf("primary task commit = %s, want the pinned %s", task.CommitSHA, scopeVersionPrimarySHA)
		}
		if task.PRURL != scopeVersionPrimaryPR {
			t.Fatalf("primary ground-truth provenance = %s, want %s", task.PRURL, scopeVersionPrimaryPR)
		}
		cveRun := run(t, "primary", task, scopeVersionPrimaryCVE, exactAdvisory, "host-default", "", "")
		logRun(t, cveRun)
		ghsaRun := run(t, "primary", task, scopeVersionPrimaryGHSA, exactAdvisory, "host-default", "", "")
		logRun(t, ghsaRun)

		scopeVersionAssertPrimaryPair(t, cveRun, ghsaRun, exactAdvisory, advisoryRaw, advisoryCanonical)
	})

	for _, group := range scopeVersionControlGroups {
		group := group
		t.Run(group.Name, func(t *testing.T) {
			cves := make([]string, 0, len(group.Tasks))
			for _, id := range group.Tasks {
				cves = append(cves, byID[id].CVEID)
			}
			// Controls keep the existing convention: the frozen corpus is keyed
			// by OSV id, so resolve each requested CVE to its aliased document
			// (the helper prefers the Go-database record).
			frozenIndex := indexFrozenAdvisories(t, osvDir, cves)
			runTask := func(target, goos, goarch string) scopeVersionRun {
				task := byID[group.Tasks[0]]
				caseDir := filepath.Join(casesDir, "scope-version", sanitizeCaseName(group.Name),
					sanitizeCaseName(task.TaskID), sanitizeCaseName(target))
				fetchDir := materializeCVEAdvisory(t, osvDir, frozenIndex, task.CVEID, caseDir)
				advisoryDir := filepath.Join(caseDir, "advisory")
				adv, err := vexbench.PrepareFrozenAdvisory(ctx, task.CVEID, advisoryDir, fetchDir)
				if err != nil {
					t.Fatalf("%s: frozen advisory: %v", task.TaskID, err)
				}
				switch adv.Outcome {
				case vexbench.AdvisoryError, vexbench.AdvisoryUnsupported, vexbench.AdvisoryPartial:
					t.Fatalf("%s: frozen advisory for %s is %s: %s", task.TaskID, task.CVEID, adv.Outcome, adv.Reason)
				}
				return run(t, group.Name, task, task.CVEID, adv.Path, target, goos, goarch)
			}

			if group.Name == "target-pair" {
				// Host default vs explicit linux/amd64: every other input is
				// identical.
				hostRun := runTask("host-default", "", "")
				logRun(t, hostRun)
				targetRun := runTask("linux/amd64", "linux", "amd64")
				logRun(t, targetRun)
				scopeVersionAssertRun(t, hostRun)
				scopeVersionAssertRun(t, targetRun)
				scopeVersionAssertTargetPair(t, hostRun, targetRun)
				return
			}

			for _, id := range group.Tasks {
				task := byID[id]
				caseDir := filepath.Join(casesDir, "scope-version", sanitizeCaseName(group.Name),
					sanitizeCaseName(task.TaskID), "host-default")
				fetchDir := materializeCVEAdvisory(t, osvDir, frozenIndex, task.CVEID, caseDir)
				advisoryDir := filepath.Join(caseDir, "advisory")
				adv, err := vexbench.PrepareFrozenAdvisory(ctx, task.CVEID, advisoryDir, fetchDir)
				if err != nil {
					t.Fatalf("%s: frozen advisory: %v", task.TaskID, err)
				}
				switch adv.Outcome {
				case vexbench.AdvisoryError, vexbench.AdvisoryUnsupported, vexbench.AdvisoryPartial:
					t.Fatalf("%s: frozen advisory for %s is %s: %s", task.TaskID, task.CVEID, adv.Outcome, adv.Reason)
				}
				r := run(t, group.Name, task, task.CVEID, adv.Path, "host-default", "", "")
				logRun(t, r)
				scopeVersionAssertRun(t, r)
			}
		})
	}
}

// scopeVersionExactAdvisory selects <VA_FROZEN_OSV>/GHSA-qppj-fm5r-hxr3.json,
// verifies its canonical digest and census against the recorded primary
// document, and returns its path, raw digest and canonical digest.
func scopeVersionExactAdvisory(t *testing.T, osvDir string) (path, rawDigest, canonicalDigest string) {
	t.Helper()
	path = filepath.Join(osvDir, scopeVersionPrimaryGHSA+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("frozen corpus %s has no exact %s document (the primary pair must not use a GO alias): %v",
			osvDir, scopeVersionPrimaryGHSA, err)
	}
	canonical, err := vexbench.CanonicalSHA256(raw)
	if err != nil {
		t.Fatalf("canonical digest of %s: %v", path, err)
	}
	if canonical != scopeVersionCanonicalSHA {
		t.Fatalf("%s canonical digest = %s, want the recorded %s", path, canonical, scopeVersionCanonicalSHA)
	}
	var doc struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if doc.ID != scopeVersionPrimaryGHSA {
		t.Fatalf("%s document id = %q, want %q", path, doc.ID, scopeVersionPrimaryGHSA)
	}
	if !slices.Contains(doc.Aliases, scopeVersionPrimaryCVE) {
		t.Fatalf("%s does not alias %s: %v", path, scopeVersionPrimaryCVE, doc.Aliases)
	}
	if len(doc.Affected) != 22 {
		t.Fatalf("%s declares %d affected[] entries, want the recorded 22", path, len(doc.Affected))
	}
	ecosystems := map[string]int{}
	goModule, goFixed := "", ""
	for i, entry := range doc.Affected {
		ecosystems[entry.Package.Ecosystem]++
		if entry.Package.Ecosystem != "Go" {
			continue
		}
		if i != 1 {
			t.Fatalf("%s Go entry index = %d, want the recorded 1", path, i)
		}
		goModule = entry.Package.Name
		for _, r := range entry.Ranges {
			if r.Type != "SEMVER" {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					goFixed = ev.Fixed
				}
			}
		}
	}
	if !reflect.DeepEqual(ecosystems, map[string]int{"Go": 1, "Maven": 20, "SwiftURL": 1}) {
		t.Fatalf("%s ecosystems = %v, want Go=1 Maven=20 SwiftURL=1", path, ecosystems)
	}
	if goModule != "golang.org/x/net" || goFixed != "0.17.0" {
		t.Fatalf("%s Go entry = %q fixed %q, want golang.org/x/net fixed 0.17.0", path, goModule, goFixed)
	}
	t.Logf("primary advisory %s: canonical %s, raw sha256:%s, census 22 (Go=1 Maven=20 SwiftURL=1), Go entry golang.org/x/net fixed 0.17.0",
		path, canonical, hexDigest(raw))
	return path, "sha256:" + hexDigest(raw), canonical
}

// scopeVersionFillLedger records one completed analysis: scope census,
// component claims, target provenance, tool outcomes, verdict and export
// projection.
func scopeVersionFillLedger(ledger *scopeVersionLedger, c *domain.AnalysisCase, casesDir string) {
	if c == nil {
		ledger.Outcome = "failed"
		ledger.Error = "analysis returned no case"
		return
	}
	ledger.ResolvedID = c.Vulnerability.ID
	ledger.Toolchain = strings.TrimSpace(c.Product.GoVersion)
	ledger.TerminalState = string(c.Workflow.State)
	ledger.WorkflowReason = c.Workflow.Reason
	ledger.GOOS = c.Product.GOOS
	ledger.GOARCH = c.Product.GOARCH
	ledger.BuildTags = c.Product.BuildTags
	ledger.CGOEnabled = c.Product.CGOEnabled
	if c.Product.Target != nil {
		ledger.TargetSource = c.Product.Target.Source
		ledger.TargetScope = c.Product.Target.Scope
	}
	if c.Affected != nil {
		ledger.ModulePresent = string(c.Affected.ModulePresent)
		ledger.ResolvedVer = c.Affected.ResolvedVersion
		ledger.VersionAffect = string(c.Affected.VersionAffected)
		ledger.PackagePresent = string(c.Affected.PackagePresent)
		ledger.BuildRelevant = string(c.Affected.BuildRelevant)
		ledger.CheckedModules = c.Affected.CheckedModules
		ledger.SelectedMods = c.Affected.SelectedModules
		ledger.VersionAffMods = c.Affected.VersionAffectedModules
		ledger.Limitations = c.Affected.Limitations
		if scope := c.Affected.Scope; scope != nil {
			ledger.Extent = string(scope.RecordExtent)
			ledger.Coverage = string(scope.Coverage)
			ledger.ScopeKind = string(scope.Kind)
			ledger.ScopeCloses = scope.AllowsNegativeClosure()
			if inv := scope.RecordInventory; inv != nil {
				ledger.CensusDigest = inv.DocumentDigest
				ledger.OriginalCount = inv.AffectedEntryCount
				ledger.Represented = len(inv.RepresentedRefs)
				ledger.Omitted = len(inv.OmittedRefs)
				ledger.CensusEcosys = map[string]int{}
				for _, entry := range inv.Entries {
					ledger.CensusEcosys[entry.Ecosystem]++
					if entry.Ecosystem == "Go" && entry.Module != "" {
						ledger.CensusGoMods = append(ledger.CensusGoMods, entry.Module)
					}
				}
			}
		} else if c.Vulnerability.Scope != nil {
			ledger.Extent = string(c.Vulnerability.Scope.RecordExtent)
			ledger.Coverage = string(c.Vulnerability.Scope.Coverage)
		}
	}
	for _, e := range c.EvidenceGraph.Evidence {
		switch {
		case e.Kind == domain.EvidenceGovulncheck && e.Govulncheck != nil:
			ledger.RunOutcome = string(e.Govulncheck.Outcome)
			ledger.RunPattern = e.Govulncheck.Pattern
			ledger.RunMode = e.Govulncheck.Mode
			ledger.RunError = e.Govulncheck.Error
			ledger.AdvisoryCoverage = string(e.Govulncheck.Coverage.Advisory)
			ledger.ScopeComplete = e.Govulncheck.Coverage.ScopeComplete
			var subjects []string
			for _, s := range e.Govulncheck.Coverage.Subjects {
				subjects = append(subjects, s.Package+"."+s.Symbol)
			}
			if len(subjects) > 0 {
				ledger.AdvisoryCoverage = fmt.Sprintf("%s (%s)", ledger.AdvisoryCoverage, strings.Join(subjects, ", "))
			}
		case e.Kind == domain.EvidencePackageList && e.PackageList != nil:
			ledger.PackageLists = append(ledger.PackageLists, fmt.Sprintf(
				"with_tests=%t completed=%t complete=%t pattern=%q error=%q",
				e.PackageList.WithTests, e.PackageList.Completed, e.PackageList.Complete,
				e.PackageList.Pattern, e.PackageList.Error))
		}
	}
	verdict, reason, _, falsifier, groundBasis, evidenceIDs, _ := vexVerdict(c)
	ledger.Verdict = verdict
	ledger.VerdictRecorded = c.Verdict != nil
	ledger.VerdictReason = reason
	if c.Verdict != nil {
		ledger.ExploitScope = string(c.Verdict.ExploitabilityScope)
	}
	ledger.Falsifier = falsifier
	ledger.GroundBasis = groundBasis
	ledger.EvidenceIDs = evidenceIDs
	ledger.Claims = vexClaims(c)

	// The export states are the admission projection of the terminal case;
	// on-disk report files are recorded when the pipeline wrote them.
	ledger.reportDir = filepath.Join(casesDir, string(c.ID))
	scopeVersionProjectExports(ledger, c, ledger.reportDir)
}

// scopeVersionProjectExports records the OpenVEX/CycloneDX projection of the
// terminal case, preferring the persisted documents when they exist.
func scopeVersionProjectExports(ledger *scopeVersionLedger, c *domain.AnalysisCase, reportDir string) {
	for _, name := range []string{"report.json", "openvex.json", "cyclonedx.json"} {
		if _, err := os.Stat(filepath.Join(reportDir, name)); err == nil {
			ledger.ExportFiles = append(ledger.ExportFiles, name)
		}
	}
	ledger.ReportWritten = slices.Contains(ledger.ExportFiles, "report.json")
	if raw, err := report.OpenVEX(c); err == nil {
		var doc struct {
			Statements []struct {
				Status string `json:"status"`
			} `json:"statements"`
		}
		if json.Unmarshal(raw, &doc) == nil && len(doc.Statements) > 0 {
			ledger.OpenVEXStatus = doc.Statements[0].Status
			ledger.ExportProjected = true
		}
	}
	if raw, err := report.CycloneDX(c); err == nil {
		var doc struct {
			Vulnerabilities []struct {
				Analysis struct {
					State string `json:"state"`
				} `json:"analysis"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal(raw, &doc) == nil && len(doc.Vulnerabilities) > 0 {
			ledger.CycloneDXState = doc.Vulnerabilities[0].Analysis.State
			ledger.ExportProjected = true
		}
	}
}

// scopeVersionAssertRun applies the control invariants: unexpected errors fail;
// recognized infrastructure aborts are recorded separately and never counted as
// a successful analysis; admitted negatives pass the existing target and
// measurement gates; no negative conclusion closes on a non-closing scope; a
// proven positive survives the publication projection.
func scopeVersionAssertRun(t *testing.T, r scopeVersionRun) {
	t.Helper()
	label := fmt.Sprintf("%s/%s", r.ledger.Group, r.ledger.TaskID)
	if r.err != nil {
		if r.ledger.Infrastructure {
			t.Logf("%s outcome=infrastructure (not a successful analysis): %v", label, r.err)
			return
		}
		t.Fatalf("%s failed for a non-infrastructure reason: %v", label, r.err)
	}
	if r.c == nil {
		t.Fatalf("%s returned no case", label)
	}
	// Every retained negative claim and every build-dependent affected FALSE
	// must pass the existing admission gates.
	assertAdmittedNegatives(t, r.c)

	if r.c.Verdict != nil && scopeVersionNegativeVerdict(r.c.Verdict.Verdict) {
		scopeVersionRequireAdmittedClose(t, label, r.c)
	}

	// A published report may not close a scope the case itself cannot close.
	var published *domain.AnalysisCase
	if r.ledger.ReportWritten {
		published = scopeVersionReadReport(t, filepath.Join(r.ledger.reportDir, "report.json"))
		if published.Verdict != nil && scopeVersionNegativeVerdict(published.Verdict.Verdict) {
			scopeVersionRequireAdmittedClose(t, label+" (report.json)", published)
		}
	}

	// A proven positive is not erased by advisory incompleteness: an
	// EXPLOITABLE verdict and its TRUE claims stay published.
	if r.c.Verdict != nil && r.c.Verdict.Verdict == domain.VerdictExploitable {
		if published != nil {
			if published.Verdict == nil || published.Verdict.Verdict != domain.VerdictExploitable {
				t.Errorf("%s: the proven positive was demoted in report.json to %+v", label, published.Verdict)
			}
		}
		for _, claim := range r.c.Claims {
			if claim.Result != domain.ClaimTrue || len(claim.EvidenceIDs) == 0 {
				continue
			}
			if published == nil {
				continue
			}
			found := false
			for _, pc := range published.Claims {
				if pc.ConditionID == claim.ConditionID && pc.Result == domain.ClaimTrue && len(pc.EvidenceIDs) > 0 {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: the proven positive claim %s was erased from report.json", label, claim.ConditionID)
			}
		}
	}

	// A library public-API positive carries its scope through publication: the
	// advisory's incompleteness never erases it or relabels its exploitability
	// scope.
	if r.c.Verdict != nil && r.c.Verdict.ExploitabilityScope == domain.ScopeLibraryAPI {
		if published != nil {
			if published.Verdict == nil || published.Verdict.Verdict != domain.VerdictExploitable ||
				published.Verdict.ExploitabilityScope != domain.ScopeLibraryAPI {
				t.Errorf("%s: the library-API positive was erased or relabelled: %+v", label, published.Verdict)
			}
		}
	}

	// The exports are the same admission projection: a not_affected status is
	// only admissible when the case scope closes.
	if r.ledger.OpenVEXStatus == "not_affected" || r.ledger.CycloneDXState == "not_affected" {
		scopeVersionRequireAdmittedClose(t, label+" (export)", r.c)
	}
	if r.ledger.ExportProjected && r.c.Verdict == nil &&
		(r.ledger.OpenVEXStatus != "under_investigation" || r.ledger.CycloneDXState != "in_triage") {
		t.Errorf("%s: a case without a verdict exported %s/%s, want under_investigation/in_triage",
			label, r.ledger.OpenVEXStatus, r.ledger.CycloneDXState)
	}
}

// scopeVersionRequireAdmittedClose requires a negative conclusion to rest on a
// valid full-record scope (the component exclusion is separate evidence, not an
// exception to finding-scope coverage).
func scopeVersionRequireAdmittedClose(t *testing.T, label string, c *domain.AnalysisCase) {
	t.Helper()
	if c.Affected == nil || c.Affected.Scope == nil {
		t.Errorf("%s: negative conclusion without a recorded advisory scope", label)
		return
	}
	if !c.Affected.Scope.AllowsNegativeClosure() {
		t.Errorf("%s: negative conclusion on a non-closing scope (extent=%s coverage=%s kind=%s)",
			label, c.Affected.Scope.RecordExtent, c.Affected.Scope.Coverage, c.Affected.Scope.Kind)
	}
}

// scopeVersionReadReport decodes the persisted report.json of one run.
func scopeVersionReadReport(t *testing.T, path string) *domain.AnalysisCase {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out domain.AnalysisCase
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &out
}

// scopeVersionAssertPrimaryPair asserts the measured primary outcome on both
// request identities and the identity of the pair.
func scopeVersionAssertPrimaryPair(t *testing.T, cveRun, ghsaRun scopeVersionRun, advisoryPath, rawDigest, canonicalDigest string) {
	t.Helper()
	cases := []struct {
		name string
		run  scopeVersionRun
		want string
	}{
		{"CVE request", cveRun, scopeVersionPrimaryCVE},
		{"GHSA request", ghsaRun, scopeVersionPrimaryGHSA},
	}
	for _, tc := range cases {
		r := tc.run
		if r.err != nil {
			if r.ledger.Infrastructure {
				t.Fatalf("%s primary run is an infrastructure abort, not the measured abstention: %v", tc.name, r.err)
			}
			t.Fatalf("%s primary run failed: %v", tc.name, r.err)
		}
		l := r.ledger
		if l.RequestedID != tc.want {
			t.Fatalf("%s requested id = %q", tc.name, l.RequestedID)
		}
		if l.ResolvedID != scopeVersionPrimaryGHSA {
			t.Fatalf("%s resolved id = %q, want %q", tc.name, l.ResolvedID, scopeVersionPrimaryGHSA)
		}
		if !l.CommitMatches {
			t.Fatalf("%s commit = %q, want the pinned %q", tc.name, l.Commit, scopeVersionPrimarySHA)
		}
		if l.AdvisoryRawSHA256 != rawDigest || l.AdvisoryCanonSHA != canonicalDigest {
			t.Fatalf("%s advisory digests = %s/%s, want %s/%s",
				tc.name, l.AdvisoryRawSHA256, l.AdvisoryCanonSHA, rawDigest, canonicalDigest)
		}
		if l.Extent != string(domain.RecordExtentGoProjection) || l.Coverage != string(domain.CoverageKnownOnly) {
			t.Fatalf("%s extent/coverage = %s/%s, want GO_PROJECTION/KNOWN_ONLY", tc.name, l.Extent, l.Coverage)
		}
		if l.OriginalCount != 22 || l.Represented != 1 || l.Omitted != 21 {
			t.Fatalf("%s census = %d/%d/%d, want 22 original / 1 represented / 21 omitted",
				tc.name, l.OriginalCount, l.Represented, l.Omitted)
		}
		if len(l.CensusEcosys) != 3 || l.CensusEcosys["Go"] != 1 || l.CensusEcosys["Maven"] != 20 || l.CensusEcosys["SwiftURL"] != 1 {
			t.Fatalf("%s census ecosystems = %v", tc.name, l.CensusEcosys)
		}
		if !slices.Equal(l.CensusGoMods, []string{"golang.org/x/net"}) {
			t.Fatalf("%s census Go modules = %v, want [golang.org/x/net]", tc.name, l.CensusGoMods)
		}
		wantKind := domain.ScopeAdvisoryEntries
		if tc.want != scopeVersionPrimaryGHSA {
			wantKind = domain.ScopeCVE
		}
		if l.ScopeKind != string(wantKind) {
			t.Fatalf("%s scope kind = %q, want %q", tc.name, l.ScopeKind, wantKind)
		}
		if l.ScopeCloses {
			t.Fatalf("%s scope closes, want a refused finding-level closure", tc.name)
		}
		if l.ModulePresent != string(domain.ClaimTrue) ||
			l.ResolvedVer != "v0.17.0" ||
			l.VersionAffect != string(domain.ClaimFalse) ||
			l.PackagePresent != string(domain.ClaimUnknown) ||
			l.BuildRelevant != string(domain.ClaimUnknown) {
			t.Fatalf("%s component facts = module=%s version=%s resolved=%q package=%s build=%s",
				tc.name, l.ModulePresent, l.VersionAffect, l.ResolvedVer, l.PackagePresent, l.BuildRelevant)
		}
		for _, list := range [][]string{l.CheckedModules, l.SelectedMods, l.VersionAffMods} {
			for _, module := range list {
				if strings.Contains(module, "grpc") {
					t.Fatalf("%s invented gRPC module %q", tc.name, module)
				}
			}
		}
		if r.c != nil {
			for _, m := range r.c.Vulnerability.AffectedModules {
				if strings.Contains(m.Module, "grpc") {
					t.Fatalf("%s invented a gRPC affected module: %+v", tc.name, m)
				}
			}
			if r.c.Verdict != nil && scopeVersionNegativeVerdict(r.c.Verdict.Verdict) {
				t.Fatalf("%s verdict = %s, want no safe conclusion", tc.name, r.c.Verdict.Verdict)
			}
		}
		if l.VerdictRecorded && l.Verdict != string(domain.VerdictInconclusive) {
			t.Fatalf("%s recorded verdict = %s, want INCONCLUSIVE", tc.name, l.Verdict)
		}
		if !l.VerdictRecorded && l.TerminalState != string(domain.StateInconclusive) {
			t.Fatalf("%s reached %s without a verdict; want a recorded INCONCLUSIVE verdict or the INCONCLUSIVE terminal state",
				tc.name, l.TerminalState)
		}
		if !l.ExportProjected {
			t.Fatalf("%s produced no VEX export projection", tc.name)
		}
		if l.OpenVEXStatus != "under_investigation" || l.CycloneDXState != "in_triage" {
			t.Fatalf("%s exports = %s/%s, want under_investigation/in_triage",
				tc.name, l.OpenVEXStatus, l.CycloneDXState)
		}
	}

	// Pair identity: everything except the requested identity is constant.
	first, second := cveRun.ledger, ghsaRun.ledger
	if first.Commit != second.Commit || first.SnapshotRepo != second.SnapshotRepo {
		t.Fatalf("primary pair used different snapshots: %s/%s vs %s/%s",
			first.Commit, first.SnapshotRepo, second.Commit, second.SnapshotRepo)
	}
	if first.AdvisoryCanonSHA != second.AdvisoryCanonSHA || first.AdvisoryRawSHA256 != second.AdvisoryRawSHA256 {
		t.Fatalf("primary pair used different documents: %s vs %s", first.AdvisoryCanonSHA, second.AdvisoryCanonSHA)
	}
	if first.TargetRequest != second.TargetRequest || first.TargetSource != second.TargetSource ||
		first.GOOS != second.GOOS || first.GOARCH != second.GOARCH ||
		!slices.Equal(first.BuildTags, second.BuildTags) || first.CGOEnabled != second.CGOEnabled ||
		first.Toolchain != second.Toolchain {
		t.Fatalf("primary pair analysis settings differ:\n first: %+v\nsecond: %+v", first, second)
	}
	if !strings.HasPrefix(first.AdvisorySource, filepath.Dir(advisoryPath)) ||
		!strings.HasPrefix(second.AdvisorySource, filepath.Dir(advisoryPath)) {
		t.Fatalf("primary pair did not analyse the verified document: %s / %s", first.AdvisorySource, second.AdvisorySource)
	}
}

// scopeVersionAssertTargetPair asserts the target provenance of the cilium pair
// without claiming a historical label: the host-default run records no
// operator/artifact target, the explicit run is operator-declared and measured
// for linux/amd64, and every other input is identical.
func scopeVersionAssertTargetPair(t *testing.T, hostRun, targetRun scopeVersionRun) {
	t.Helper()
	if hostRun.err != nil || targetRun.err != nil {
		return
	}
	host, target := hostRun.ledger, targetRun.ledger
	if host.TargetSource != "" && host.TargetSource != domain.ProductTargetSourceHostDefault {
		t.Errorf("host-default run target source = %q, want host-default", host.TargetSource)
	}
	if target.TargetSource != domain.ProductTargetSourceOperatorDeclared {
		t.Errorf("linux/amd64 run target source = %q, want operator-declared", target.TargetSource)
	}
	if target.GOOS != "linux" || target.GOARCH != "amd64" {
		t.Errorf("linux/amd64 run measured %s/%s", target.GOOS, target.GOARCH)
	}
	if host.Commit != target.Commit || host.SnapshotRepo != target.SnapshotRepo ||
		host.AdvisoryCanonSHA != target.AdvisoryCanonSHA ||
		!slices.Equal(host.CheckedModules, target.CheckedModules) ||
		host.Toolchain != target.Toolchain {
		t.Errorf("target pair changed inputs other than the target:\n host: %+v\n target: %+v", host, target)
	}
}

// scopeVersionInfrastructureError classifies run aborts that are environment
// infrastructure rather than analysis results: the shared deadline/cancel/kill/
// memory classes plus storage exhaustion (a full disk aborts the engine's
// persistence, not the analysis). An infrastructure row is recorded verbatim
// and is never counted as a successful analysis.
func scopeVersionInfrastructureError(err error) bool {
	if infrastructureError(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"no space left on device", "disk quota exceeded", "enospc"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func hexDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// scopeVersionNegativeVerdict reports the verdicts that assert a negative
// finding-level conclusion.
func scopeVersionNegativeVerdict(v domain.Verdict) bool {
	return v == domain.VerdictNotAffected || v == domain.VerdictNoExploitPathFound
}
