// Artifact emitters for the A1.5 generator: the GT-safe CSV (facts filled,
// classification columns intentionally empty for Task B) and the B0
// baseline-proof-coverage document (per-case verdict + evaluated
// deterministic fact classes + aggregates + run provenance).
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/eval/agent7"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
)

// factColumns is the frozen A1.5 column order (brief): every row carries a
// concrete value or an explicit "unknown".
var factColumns = []string{
	"task_id", "cve_id", "gt_class", "gt_category", "repo_url", "commit_sha",
	"snapshot_dir", "target_kind", "vulnerable_module", "vulnerable_package",
	"resolved_version", "affected_range", "fix_version",
	"component_is_first_party", "component_in_module_graph",
	"component_vendored", "multi_module", "go_work",
	"generated_code_present", "build_tag_gated", "release_go_version",
	"go_version_source", "minimum_go_version", "vendor_mode", "goos",
	"goarch", "build_tags", "content_hash", "advisory_source",
	"advisory_sha256", "advisory_modified", "delivered_artifact_available",
	"build_attestation_available", "binary_inventory_complete",
	"advisory_manifest_complete", "izyan_verdict", "izyan_falsifier",
	"izyan_grounding_conditions", "izyan_limitations", "izyan_error",
	"proof_artifact_fixed", "proof_component_absent", "proof_build_excluded",
	"blocker_kind",
}

// classificationColumns stay EMPTY in Task A — the independent expert
// (Task B) fills them.
var classificationColumns = []string{
	"candidate_class", "classification_confidence", "classification_reason",
	"incremental_safe_candidate", "expected_data_collection_cost",
}

// csvHeaderComment documents the column contract as a #-prefixed note.
var csvHeaderComment = []string{
	"# A1.5 proof-feasibility facts (agent7-feasibility/1). One row per GT-safe case (23) + 1 known-FS control row.",
	"# Fact columns: concrete value | 'unknown' (+ blocker_kind) | 'none' (determinable absence).",
	"# Multi-entry advisories align vulnerable_module/vulnerable_package/resolved_version/affected_range/fix_version by '|'.",
	"# proof_* = deterministic feasibility of the candidate's fact pattern (yes|no|unknown), NOT a certificate.",
	"# blocker_kind ∈ none|missing_data|missing_algorithm|scope|integrity — dominant reason a candidate/certificate is blocked.",
	"# classification columns are empty by design: Task A does not classify; the independent expert fills them (existing cells are preserved verbatim on regeneration).",
	"# GT columns are controller-side data (frozen gt_policy): this CSV is a controller artifact, never agent-visible.",
}

// priorClassifications preserves the expert's Task-B cells across
// regeneration: values are looked up by task_id and copied verbatim —
// never recomputed, never cleared.
func priorClassifications(path string) map[string][]string {
	out := map[string][]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return out
	}
	var hdr []string
	for _, row := range rows {
		if len(row) > 0 && row[0] == "task_id" {
			hdr = row
			continue
		}
		if hdr == nil || len(row) == 0 || strings.HasPrefix(row[0], "#") {
			continue
		}
		vals := make([]string, len(classificationColumns))
		for i, c := range classificationColumns {
			for j, hc := range hdr {
				if hc == c && j < len(row) {
					vals[i] = row[j]
				}
			}
		}
		out[row[0]] = vals
	}
	return out
}

// writeCSV emits the GT-safe rows (dataset order) plus the control row.
// Classification cells are preserved from the previous file when present
// (the expert's merged Task-B input); otherwise empty.
func writeCSV(path string, records []agent7.FactRecord, control string) error {
	prior := priorClassifications(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	for _, line := range csvHeaderComment {
		if err := w.Write([]string{line}); err != nil {
			return err
		}
	}
	if err := w.Write(append(append([]string{}, factColumns...), classificationColumns...)); err != nil {
		return err
	}
	emit := func(r agent7.FactRecord) error {
		row := scrubRow(factRow(r))
		vals := prior[r.TaskID]
		if vals == nil {
			vals = make([]string, len(classificationColumns))
		}
		return w.Write(append(row, vals...))
	}
	safe := 0
	var controlRec *agent7.FactRecord
	for i := range records {
		r := records[i]
		if r.TaskID == control {
			c := r
			controlRec = &c
		}
		if r.GTClass != "not_exploitable" {
			continue
		}
		if err := emit(r); err != nil {
			return err
		}
		safe++
	}
	if controlRec != nil {
		// The control row is the known B0 false-safe exploitable case; it
		// is marked by its own gt_class (exploitable) so it can never be
		// mistaken for a safe row.
		if err := emit(*controlRec); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	if controlRec == nil {
		fmt.Fprintf(os.Stderr, "agent7-feasibility: warning: control case %s not in records; control row omitted\n", control)
	}
	if safe != 23 {
		fmt.Fprintf(os.Stderr, "agent7-feasibility: warning: %d GT-safe rows (want 23) — partial run?\n", safe)
	}
	return nil
}

// factRow projects a FactRecord onto factColumns (same order).
func factRow(r agent7.FactRecord) []string {
	join := func(xs []string) string {
		if len(xs) == 0 {
			return "none"
		}
		return strings.Join(xs, ";")
	}
	return []string{
		r.TaskID, r.CVEID, r.GTClass, r.GTCategory, r.RepoURL, r.CommitSHA,
		r.SnapshotDir, r.TargetKind, r.VulnerableModule, r.VulnerablePackage,
		r.ResolvedVersion, r.AffectedRange, r.FixVersion,
		r.ComponentIsFirstParty, r.ComponentInModuleGraph,
		r.ComponentVendored, r.MultiModule, r.GoWork,
		r.GeneratedCodePresent, r.BuildTagGated, r.ReleaseGoVersion,
		r.GoVersionSource, r.MinimumGoVersion, r.VendorMode, r.GOOS,
		r.GOARCH, join(r.BuildTags), r.ContentHash, r.AdvisorySource,
		r.AdvisorySHA256, r.AdvisoryModified, r.DeliveredArtifact,
		r.BuildAttestation, r.BinaryInventoryComplete,
		r.AdvisoryManifestComplete, r.IzyanVerdict, r.IzyanFalsifier,
		join(r.IzyanGroundingConditions), join(r.IzyanLimitations), r.IzyanError,
		r.ProofArtifactFixed, r.ProofComponentAbsent, r.ProofBuildExcluded,
		r.BlockerKind,
	}
}

// scrubRow applies the same path scrubbing as writeJSON so committed
// CSV cells never leak operator-local paths.
func scrubRow(cells []string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = scrubPaths(c)
	}
	return out
}

// ---------- baseline-proof-coverage ----------

// reportAffected/reportProduct/reportEvidence are the report.json subsets
// the coverage pass reads — the analyzer's own deterministic claim fields.
type reportDoc struct {
	Affected struct {
		ModulePresent   string   `json:"module_present"`
		ResolvedVersion string   `json:"resolved_version"`
		VersionAffected string   `json:"version_affected"`
		PackagePresent  string   `json:"package_present"`
		BuildRelevant   string   `json:"build_relevant"`
		CheckedModules  []string `json:"checked_modules"`
		CheckedPackages []string `json:"checked_packages"`
	} `json:"affected"`
	Product struct {
		ReleaseGoVersion string   `json:"release_go_version"`
		GoVersionSource  string   `json:"go_version_source"`
		MinimumGoVersion string   `json:"minimum_go_version"`
		VendorMode       bool     `json:"vendor_mode"`
		GOOS             string   `json:"goos"`
		GOARCH           string   `json:"goarch"`
		BuildTags        []string `json:"build_tags"`
	} `json:"product"`
	EvidenceGraph struct {
		Evidence []struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Source string `json:"source"`
		} `json:"evidence"`
	} `json:"evidence_graph"`
}

// factClass records whether the analyzer already evaluates one
// deterministic fact class for the case, and the observed value/source.
type factClass struct {
	Evaluated bool   `json:"evaluated"`
	Value     string `json:"value,omitempty"`
	Source    string `json:"source,omitempty"`
}

type coverageCase struct {
	TaskID           string `json:"task_id"`
	Verdict          string `json:"verdict"`
	InfraError       bool   `json:"infra_error"`
	InfraReason      string `json:"infra_reason,omitempty"`
	CompatibilityCat string `json:"compatibility_category"`
	// Segment names the run dir this case's envelope was merged from.
	Segment          string               `json:"segment,omitempty"`
	ScoringOutcome   string               `json:"scoring_outcome"`
	Falsifier        string               `json:"falsifier,omitempty"`
	Error            string               `json:"error,omitempty"`
	ReleaseGoVersion string               `json:"release_go_version,omitempty"`
	GoVersionSource  string               `json:"go_version_source,omitempty"`
	FactClasses      map[string]factClass `json:"fact_classes"`
}

type coverageAggregates struct {
	VerdictDistribution map[string]int `json:"verdict_distribution"`
	OutcomeDistribution map[string]int `json:"scoring_outcome_distribution"`
	Total               int            `json:"total_cases"`
	// Attempted = cases that produced a real analyzer attempt (excludes
	// infra failures); denominators for rates use it, never total.
	Attempted       int      `json:"attempted_cases"`
	Completed       int      `json:"completed"`
	CompletionRate  float64  `json:"completion_rate"`
	InfraErrors     []string `json:"infra_errors"`
	InfraErrorCount int      `json:"infra_error_count"`
	CorrectSafe     []string `json:"correct_safe"`
	SafeClearCount  int      `json:"safe_clear_count"`
	SafeClearRate   float64  `json:"safe_clear_rate"`
	KnownFalseSafe  []string `json:"known_false_safe"`
	FalseSafeCount  int      `json:"false_safe_count"`
	// Metrics is the safety-aware aggregate recomputed over the merged
	// per-case predictions by internal/eval/vexbench.Compute — never a
	// copied metrics.json (segments may each carry partial numbers).
	Metrics vexbench.Metrics `json:"metrics"`
}

// coverageSegment records per-segment provenance for merged runs.
type coverageSegment struct {
	RunDir       string          `json:"run_dir"`
	CasesPresent int             `json:"cases_present"`
	InfraErrors  int             `json:"infra_errors"`
	Provenance   json.RawMessage `json:"provenance,omitempty"`
}

// InvalidatedAttempt records a run-profile failure kept as evidence but
// excluded from the baseline (e.g. the j2/8GiB memguard-cancellation run).
type InvalidatedAttempt struct {
	RunDir        string `json:"run_dir"`
	Profile       string `json:"profile"`
	AffectedCases int    `json:"affected_cases"`
	Cause         string `json:"cause"`
}

// coverageDoc is the committed baseline-proof-coverage.json shape.
type coverageDoc struct {
	Schema              string               `json:"schema"`
	Kind                string               `json:"kind"`
	RunDir              string               `json:"run_dir"`
	Segments            []coverageSegment    `json:"segments,omitempty"`
	Head                string               `json:"izyan_head"`
	InvalidatedAttempts []InvalidatedAttempt `json:"invalidated_attempts,omitempty"`
	Cases               []coverageCase       `json:"cases"`
	Aggregates          coverageAggregates   `json:"aggregates"`
	Provenance          json.RawMessage      `json:"provenance"`
	Notes               []string             `json:"notes"`
}

// writeCoverage builds baseline-proof-coverage.json from the run
// segment(s): prediction.json per case (verdict/envelope), report.json for
// the deterministic fact classes the analyzer evaluated, per-segment
// metrics.json for provenance, scoring/cases.jsonl for the GT join
// (controller-side). With multiple runDirs the LAST segment containing an
// envelope for a case wins (retry merge); aggregates are recomputed over
// the merged set via internal/eval/vexbench.Compute.
func writeCoverage(path string, runDirs []string, tasks []agent7.TaskRecord, head string, invalidated []InvalidatedAttempt) error {
	if len(runDirs) == 0 {
		return fmt.Errorf("writeCoverage: at least one run directory required")
	}
	doc := coverageDoc{
		Schema:              "agent7-baseline-proof-coverage/1",
		Kind:                "b0-deterministic-fact-coverage",
		RunDir:              runDirs[0],
		Head:                orDash(head),
		InvalidatedAttempts: invalidated,
		Aggregates: coverageAggregates{
			VerdictDistribution: map[string]int{},
			OutcomeDistribution: map[string]int{},
		},
		Notes: []string{
			"fact classes: whether the B0 analyzer already evaluates this deterministic fact class for the case",
			"binary_inventory is never evaluated: B0 inspects source snapshots, not delivered binaries",
			"GT labels are controller-side (frozen gt_policy); this artifact is committed as a controller document",
			"INFRA_ERROR cases (advisory fetch failures, context cancellation, missing envelopes) are excluded from every aggregate and listed under infra_errors — an infra failure is never a result",
			"protocol caveat: the memory guard's GC pressure degrades evidence collection — the same case returned INCONCLUSIVE under -j2/8GiB and EXPLOITABLE under -j3/24GiB (cilium-cilium-3977f6a); the frozen protocol must pin a non-tripping ceiling",
		},
	}

	// scoring/cases.jsonl (merged across segments, last segment wins)
	// supplies the scorer's GT join — the run's own labels artifact.
	outcomesByID := map[string]string{}
	gtExploitable := map[string]bool{}
	// segEnvs collects per-segment envelopes for provenance + merge.
	segEnvs := make([]map[string]predictionLike, len(runDirs))
	segInfra := make([]int, len(runDirs))
	for i, d := range runDirs {
		segEnvs[i] = map[string]predictionLike{}
		// per-segment provenance from its own metrics.json (never trusted
		// for aggregates — those are recomputed over the merged set).
		seg := coverageSegment{RunDir: d}
		if b, err := os.ReadFile(filepath.Join(d, "metrics.json")); err == nil {
			var mdoc struct {
				Provenance json.RawMessage `json:"provenance"`
			}
			if json.Unmarshal(b, &mdoc) == nil {
				seg.Provenance = mdoc.Provenance
			}
		}
		for _, t := range tasks {
			var env predictionLike
			if b, err := os.ReadFile(filepath.Join(d, sanitize(t.TaskID), "prediction.json")); err == nil &&
				json.Unmarshal(b, &env) == nil {
				segEnvs[i][t.TaskID] = env
				seg.CasesPresent++
				if ok, _ := agent7.IsInfraEnvelope(env.TerminalState, env.Verdict, env.Reason, env.Error); ok {
					segInfra[i]++
				}
			}
		}
		seg.InfraErrors = segInfra[i]
		doc.Segments = append(doc.Segments, seg)
		casesPath := filepath.Join(d, "scoring", "cases.jsonl")
		if b, err := os.ReadFile(casesPath); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var row struct {
					TaskID         string `json:"task_id"`
					ScoringOutcome string `json:"scoring_outcome"`
					GroundTruth    string `json:"ground_truth"`
				}
				if json.Unmarshal([]byte(line), &row) == nil && row.TaskID != "" {
					outcomesByID[row.TaskID] = row.ScoringOutcome
					gtExploitable[row.TaskID] = strings.EqualFold(row.GroundTruth, "exploitable")
				}
			}
		}
	}

	for _, t := range tasks {
		// Merge: the last segment that produced an envelope wins.
		var env predictionLike
		var envErr error
		var caseDir string
		for i, d := range runDirs {
			if e, ok := segEnvs[i][t.TaskID]; ok {
				env, envErr, caseDir = e, nil, filepath.Join(d, sanitize(t.TaskID))
			}
		}
		if caseDir == "" {
			envErr = os.ErrNotExist
		}
		cc := coverageCase{TaskID: t.TaskID, Verdict: "none", FactClasses: map[string]factClass{}}
		if len(runDirs) > 1 && caseDir != "" {
			cc.Segment = filepath.Dir(caseDir)
		}
		if envErr != nil {
			// Missing/unparseable envelope = completeness failure, never a result.
			cc.Verdict = "infra_error"
			cc.InfraError = true
			cc.InfraReason = "prediction.json unreadable"
		} else {
			cc.Verdict = orDash(env.Verdict)
			cc.CompatibilityCat = env.CompatibilityCat
			cc.ScoringOutcome = env.ScoringOutcome
			cc.Falsifier = env.Falsifier
			cc.Error = env.Error
			cc.ReleaseGoVersion = env.ReleaseGoVersion
			cc.GoVersionSource = env.GoVersionSource
			if out, ok := outcomesByID[t.TaskID]; ok {
				cc.ScoringOutcome = out
			}
			if ok, why := agent7.IsInfraEnvelope(env.TerminalState, env.Verdict, env.Reason, env.Error); ok {
				cc.Verdict = "infra_error"
				cc.InfraError = true
				cc.InfraReason = why
			}
		}

		// Fact classes from the analyzer's own report.json.
		var rep reportDoc
		repOK := false
		if envErr == nil && env.ReportPath != "" {
			if b, err := os.ReadFile(env.ReportPath); err == nil && json.Unmarshal(b, &rep) == nil {
				repOK = true
			}
		}
		if !repOK && envErr == nil {
			if b, err := os.ReadFile(findReport(caseDir)); err == nil && json.Unmarshal(b, &rep) == nil {
				repOK = true
			}
		}
		if repOK {
			modSrc := ""
			for _, e := range rep.EvidenceGraph.Evidence {
				if e.ID == "EV-AFFECTED-MODULES" {
					modSrc = e.Source
				}
			}
			cc.FactClasses["module_graph_presence"] = factClass{
				Evaluated: claimDecided(rep.Affected.ModulePresent),
				Value:     rep.Affected.ModulePresent, Source: orDash(modSrc)}
			cc.FactClasses["version_affected"] = factClass{
				Evaluated: claimDecided(rep.Affected.VersionAffected),
				Value:     joinSep("@", rep.Affected.VersionAffected, rep.Affected.ResolvedVersion)}
			pkgVal := rep.Affected.PackagePresent
			if len(rep.Affected.CheckedPackages) > 0 {
				pkgVal += ":" + strings.Join(rep.Affected.CheckedPackages, "+")
			}
			cc.FactClasses["package_presence"] = factClass{
				Evaluated: claimDecided(rep.Affected.PackagePresent), Value: pkgVal}
			bv := rep.Affected.BuildRelevant
			ctxStr := rep.Product.GOOS + "/" + rep.Product.GOARCH
			if len(rep.Product.BuildTags) > 0 {
				ctxStr += "+" + strings.Join(rep.Product.BuildTags, ",")
			}
			if rep.Product.VendorMode {
				ctxStr += " vendor"
			}
			cc.FactClasses["build_variant_facts"] = factClass{
				Evaluated: claimDecided(rep.Affected.BuildRelevant),
				Value:     bv + ":" + ctxStr, Source: "product build context"}
			cc.FactClasses["release_toolchain"] = factClass{
				Evaluated: rep.Product.ReleaseGoVersion != "",
				Value:     joinSep("/", rep.Product.ReleaseGoVersion, rep.Product.GoVersionSource)}
		} else {
			for _, k := range []string{"module_graph_presence", "version_affected",
				"package_presence", "build_variant_facts", "release_toolchain"} {
				cc.FactClasses[k] = factClass{Evaluated: false}
			}
			if envErr == nil {
				// Envelope facts still stand even without report.json.
				if env.ReleaseGoVersion != "" {
					cc.FactClasses["release_toolchain"] = factClass{
						Evaluated: true, Value: joinSep("/", env.ReleaseGoVersion, env.GoVersionSource)}
				}
			}
		}
		cc.FactClasses["binary_inventory"] = factClass{Evaluated: false, Source: "not analyzed: source snapshot only"}

		if cc.InfraError {
			// INFRA_ERROR taxonomy: reported separately, never counted in
			// verdict/outcome distributions or any denominator.
			doc.Aggregates.InfraErrors = append(doc.Aggregates.InfraErrors, t.TaskID)
			doc.Cases = append(doc.Cases, cc)
			continue
		}
		doc.Aggregates.Attempted++
		doc.Aggregates.VerdictDistribution[cc.Verdict]++
		out := cc.ScoringOutcome
		if out == "" {
			out = "none"
		}
		doc.Aggregates.OutcomeDistribution[out]++
		switch out {
		case "correct_safe":
			doc.Aggregates.CorrectSafe = append(doc.Aggregates.CorrectSafe, t.TaskID)
		case "wrong":
			if gtExploitable[t.TaskID] {
				doc.Aggregates.KnownFalseSafe = append(doc.Aggregates.KnownFalseSafe, t.TaskID)
			}
		}
		if cc.Verdict != "" && cc.Verdict != "none" {
			doc.Aggregates.Completed++
		}
		doc.Cases = append(doc.Cases, cc)
	}

	doc.Aggregates.Total = len(tasks)
	doc.Aggregates.InfraErrorCount = len(doc.Aggregates.InfraErrors)
	doc.Aggregates.SafeClearCount = len(doc.Aggregates.CorrectSafe)
	doc.Aggregates.FalseSafeCount = len(doc.Aggregates.KnownFalseSafe)
	// Denominators exclude infra failures: attempted cases only.
	doc.Aggregates.CompletionRate = rate(doc.Aggregates.Completed, doc.Aggregates.Attempted)
	// Denominator is the frozen GT-safe count (23), not case count.
	doc.Aggregates.SafeClearRate = rate(doc.Aggregates.SafeClearCount, 23)
	sort.Strings(doc.Aggregates.CorrectSafe)
	sort.Strings(doc.Aggregates.KnownFalseSafe)
	sort.Strings(doc.Aggregates.InfraErrors)
	// The safety-aware metrics are recomputed over the MERGED non-infra
	// case set — never copied from a segment's metrics.json, and infra
	// cases enter NO denominator (they are reported separately under
	// infra_errors).
	var preds []vexbench.Prediction
	var vtasks []vexbench.Task
	for _, c := range doc.Cases {
		if c.InfraError {
			continue // infra is never a result and never a denominator
		}
		preds = append(preds, vexbench.Prediction{
			TaskID: c.TaskID, Verdict: c.Verdict, Category: c.CompatibilityCat,
		})
		for _, t := range tasks {
			if t.TaskID == c.TaskID {
				vtasks = append(vtasks, vexbench.Task{
					TaskID: t.TaskID, GroundTruth: t.GroundTruth,
					GroundTruthCategory: t.GroundTruthCategory,
				})
				break
			}
		}
	}
	doc.Aggregates.Metrics = vexbench.Compute(preds, vtasks)

	// Primary segment's metrics.json provenance embedded verbatim — pins
	// command, dataset sha256, binary sha256, toolchain. Per-segment
	// provenance lives under "segments".
	doc.Provenance = doc.Segments[0].Provenance
	if len(doc.Provenance) == 0 {
		doc.Notes = append(doc.Notes, "metrics.json provenance unavailable")
	}
	return writeJSON(path, doc)
}

// predictionLike is the envelope subset read by the coverage pass.
type predictionLike struct {
	Verdict          string `json:"verdict"`
	TerminalState    string `json:"terminal_state"`
	Reason           string `json:"reason"`
	CompatibilityCat string `json:"compatibility_category"`
	ScoringOutcome   string `json:"scoring_outcome"`
	Falsifier        string `json:"falsifier"`
	Error            string `json:"error"`
	ReportPath       string `json:"report_path"`
	ReleaseGoVersion string `json:"release_go_version"`
	GoVersionSource  string `json:"go_version_source"`
}

// findReport locates <case>/<run-id>/report.json when the envelope's
// report_path is unusable.
func findReport(caseDir string) string {
	matches, _ := filepath.Glob(filepath.Join(caseDir, "*", "report.json"))
	if len(matches) > 0 {
		sort.Strings(matches)
		return matches[0]
	}
	return ""
}

// claimDecided reports whether an AffectedResult claim reached a
// deterministic TRUE/FALSE decision (UNKNOWN means the class was not
// evaluated to a conclusion).
func claimDecided(v string) bool {
	return v == "TRUE" || v == "FALSE"
}

// joinSep joins non-empty values with sep (skips empty parts).
func joinSep(sep string, vals ...string) string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, sep)
}

func orDash(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func rate(n, d int) float64 {
	if d == 0 {
		return 0
	}
	f, _ := strconv.ParseFloat(fmt.Sprintf("%.4f", float64(n)/float64(d)), 64)
	return f
}

// printSummary writes the collection roll-up to stdout for the operator.
func printSummary(records []agent7.FactRecord, control string) {
	count := map[string]int{}
	unknown := map[string]int{}
	for _, r := range records {
		for _, p := range [][2]string{
			{"proof_artifact_fixed", r.ProofArtifactFixed},
			{"proof_component_absent", r.ProofComponentAbsent},
			{"proof_build_excluded", r.ProofBuildExcluded},
			{"blocker_kind", r.BlockerKind},
		} {
			count[p[0]+"="+p[1]]++
			if p[1] == "unknown" {
				unknown[p[0]]++
			}
		}
	}
	var keys []string
	for k := range count {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("agent7-feasibility: records=", len(records))
	for _, k := range keys {
		fmt.Printf("  %-42s %d\n", k, count[k])
	}
}
