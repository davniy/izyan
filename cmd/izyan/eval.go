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

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// runEval executes a corpus of cases through the full pipeline and
// reports the spec's quality metrics — the false-safe count above all.
//
//	izyan eval --corpus eval/corpus.json [--repo <path>]
//	    [--case <id|glob>] [-j <jobs>] [--clean]
//	    [--out report.md] [--json report.json] [common flags]
//
// Exit code is 1 when any case is false-safe or fails its expectation;
// informational cases never fail the run.
func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	corpusPath := fs.String("corpus", "", "evaluation corpus JSON")
	caseFilter := fs.String("case", "", "comma-separated list or pattern of case IDs to run (e.g. 'real-yaml*', 'real-yaml-const')")
	jobs := fs.Int("j", 4, "number of parallel case evaluations (default 4; 1 for sequential)")
	clean := fs.Bool("clean", false, "force re-materialization of generated product modules (wipe .gen)")
	outMD := fs.String("out", "", "write markdown report to file")
	outJSON := fs.String("json", "", "write JSON report to file")
	auditDir := fs.String("audit-dir", "", "write one audit packet per signal-cleared case to this directory (B29 added-value validation)")
	// Regression runs must be reproducible: LLM proposals are
	// nondeterministic, so the corpus is deterministic-only by default.
	withLLM := fs.Bool("with-llm", false, "enable LLM proposals (nondeterministic)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" {
		usage()
	}
	kb, err := loadKnowledgeBase(o.knowledge)
	if err != nil {
		return err
	}
	o.kb = kb
	// Case state defaults to a temp dir for eval runs — persisted cases stay
	// available via --case-dir for debugging a failure.
	caseDirSet := false
	fs.Visit(func(f *flag.Flag) { caseDirSet = caseDirSet || f.Name == "case-dir" })
	raw, err := os.ReadFile(*corpusPath)
	if err != nil {
		return fmt.Errorf("corpus: %w", err)
	}
	var corpus eval.Corpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return fmt.Errorf("corpus: %w", err)
	}
	if len(corpus.Cases) == 0 {
		return fmt.Errorf("corpus: no cases")
	}
	// Relative paths in the corpus resolve against the corpus file's
	// directory, not the caller's cwd.
	absCorpus, err := filepath.Abs(*corpusPath)
	if err != nil {
		return err
	}
	base := filepath.Dir(absCorpus)
	resolve := func(p string) string {
		p = os.ExpandEnv(p)
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	corpus.Repo = resolve(corpus.Repo)
	for i := range corpus.Cases {
		corpus.Cases[i].Repo = resolve(corpus.Cases[i].Repo)
		corpus.Cases[i].VulnFile = resolve(corpus.Cases[i].VulnFile)
		corpus.Cases[i].ExploitModel = resolve(corpus.Cases[i].ExploitModel)
		corpus.Cases[i].Product = resolve(corpus.Cases[i].Product)
	}

	if *caseFilter != "" {
		patterns := strings.Split(*caseFilter, ",")
		for i := range patterns {
			patterns[i] = strings.TrimSpace(patterns[i])
		}
		var filtered []eval.Case
		for _, c := range corpus.Cases {
			lbl := c.Label()
			matched := false
			for _, pat := range patterns {
				if pat == "" {
					continue
				}
				if pat == lbl {
					matched = true
					break
				}
				if m, _ := filepath.Match(pat, lbl); m {
					matched = true
					break
				}
			}
			if matched {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no cases matching --case %q", *caseFilter)
		}
		corpus.Cases = filtered
	}

	repo := o.repo
	if repo == "" {
		repo = corpus.Repo
	}
	if repo == "" {
		for _, c := range corpus.Cases {
			if c.Repo == "" && c.Product == "" {
				return fmt.Errorf("no repository: set --repo, corpus.repo, or per-case repo")
			}
		}
	}

	// Corpus-level toolchain: case go_version is a per-case override;
	// the shared toolchain serves cases without one.
	o.toolchain, o.tcLims = resolveToolchain(context.Background(), o)

	o.goTool = affected.CachingTool(affected.ExecGoTool{Bin: o.toolchain.GoBin, Env: o.toolchain.Env})
	o.gvRunner = goanalysis.CachingRunner(goanalysis.ExecRunner{Env: o.toolchain.Env})
	var absRepo string
	if repo != "" {
		// A shared repo lets cases reuse one source index, like scan mode.
		absRepo, err = filepath.Abs(repo)
		if err != nil {
			return err
		}
		o.repo = absRepo
		o.srcIndex = &goanalysis.Index{
			Dir: absRepo,
			Env: o.toolchain.Env,
			KB:  o.kb,
			Build: domain.ProductSnapshot{
				GOOS: o.goos, GOARCH: o.goarch, BuildTags: splitCSV(o.tags),
			},
		}
	}
	if *withLLM {
		loadLLMEnv(o.llmEnv, absRepo)
	} else {
		o.detOnly = true
	}
	if !caseDirSet {
		o.caseDir = filepath.Join(os.TempDir(), fmt.Sprintf("izyan-eval-%d", os.Getpid()))
	}
	fmt.Fprintf(os.Stderr, "corpus=%s cases=%d repo=%s case-dir=%s\n",
		*corpusPath, len(corpus.Cases), absRepo, o.caseDir)

	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()
	// One pinned corpus serves every case: discovery is request-scoped, the
	// corpus bytes are not. Invalid operator input fails here, before any case
	// runs.
	if err := resolveAdvisorySources(ctx, &o); err != nil {
		return err
	}
	gen := eval.Gen{GoBin: o.toolchain.GoBin, Env: o.toolchain.Env, Force: *clean}
	genRoot := filepath.Join(base, ".gen")

	total := len(corpus.Cases)
	outcomes := make([]caseOutcome, total)

	concurrency := *jobs
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > total {
		concurrency = total
	}

	tasks := make(chan int, total)
	results := make(chan caseOutcome, total)

	for i := 0; i < total; i++ {
		tasks <- i
	}
	close(tasks)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range tasks {
				c := corpus.Cases[idx]
				outcomes := runCase(ctx, idx, total, c, o, base, genRoot, gen)
				results <- outcomes
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var rep eval.Report
	completed := 0
	for outcome := range results {
		completed++
		outcomes[outcome.idx] = outcome

		mark := "  "
		if outcome.err != nil {
			mark = "??"
		} else {
			ok := false
			published := outcome.published()
			for _, want := range outcome.c.Expect {
				if published == want {
					ok = true
					break
				}
			}
			if len(outcome.c.Expect) > 0 && !ok {
				mark = "!!"
			}
		}
		errStr := ""
		if outcome.err != nil {
			errStr = outcome.err.Error()
		}
		fmt.Printf("%s [%d/%d] %-28s %-22s %s (%.0fs)\n", mark, completed, total, outcome.c.Label(),
			firstNonEmpty(outcome.display(), errStr), outcome.reason, outcome.duration.Seconds())
		if outcome.topTimingsStr != "" {
			fmt.Fprintf(os.Stderr, "  states: %s\n", outcome.topTimingsStr)
		}
	}

	// Record in original corpus order
	productDirs := map[string]string{}
	for _, outcome := range outcomes {
		rep.Record(outcome.c, outcome.verdict, outcome.reason, outcome.claims,
			outcome.falsifier, outcome.groundBasis, outcome.evidenceIDs, outcome.err,
			outcome.projection)
		if outcome.baseline != "" {
			rep.RecordBaseline(outcome.baseline)
		}
		if outcome.productDir != "" {
			productDirs[outcome.c.Label()] = outcome.productDir
		}
	}

	m := rep.Metrics
	fmt.Printf("\ncases=%d errors=%d expect pass=%d fail=%d claims-fail=%d false-safe=%d inconclusive=%d\n",
		m.Total, m.Errors, m.ExpectPass, m.ExpectFail, m.ClaimsFail, m.FalseSafe, m.Inconclusive)
	// Three separate populations: reclassifying tool limitations as failures
	// must not be presented as increased successful completion, and an external
	// dependency is not a definitive answer.
	fmt.Printf("requested outcomes: decided=%d external=%d failed=%d false-positive=%d\n",
		m.Decided, m.ExternalDependency, m.AnalysisFailed, m.FalsePositive)
	if m.GovulncheckSignals > 0 {
		fmt.Printf("signal-cleared=%d/%d (auto=%d expert=%d)\n",
			m.SignalCleared, m.GovulncheckSignals, m.SignalClearedAuto, m.SignalClearedExpert)
		fmt.Printf("reachable-cleared=%d/%d package-level-cleared=%d/%d\n",
			m.ReachableCleared, m.ReachableSignals, m.PackageLevelCleared, m.PackageLevelSignals)
		fmt.Printf("cleared by evidence class: deeper=%d echo=%d affectedness=%d\n",
			m.ClearedDeeper, m.ClearedEcho, m.ClearedAffectedness)
	}
	if *outMD != "" {
		if err := os.WriteFile(*outMD, []byte(rep.Markdown()), 0o644); err != nil {
			return err
		}
	}
	if *outJSON != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*outJSON, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	if *auditDir != "" {
		if err := eval.WriteAuditPackets(*auditDir, *corpusPath, genRoot, rep, productDirs); err != nil {
			return fmt.Errorf("audit packets: %w", err)
		}
	}
	if m.FalseSafe > 0 || m.ExpectFail > 0 || m.ClaimsFail > 0 || m.Errors > 0 {
		return fmt.Errorf("evaluation failed: false-safe=%d expect-fail=%d claims-fail=%d errors=%d",
			m.FalseSafe, m.ExpectFail, m.ClaimsFail, m.Errors)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// topTimings renders the n workflow states that consumed the most case
// time — the eval progress diagnostic answering "where is it spending
// the minutes" without digging through the persisted case.
func topTimings(timings map[string]float64, n int) string {
	type kv struct {
		k string
		v float64
	}
	var sorted []kv
	for k, v := range timings {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	parts := make([]string, 0, len(sorted))
	for _, s := range sorted {
		parts = append(parts, fmt.Sprintf("%s=%.0fs", s.k, s.v))
	}
	return strings.Join(parts, " ")
}

// baselineVuln resolves the advisory identity for the standalone
// govulncheck baseline: the pipeline's parsed document when available,
// else the case's vuln file, else the bare id.
func baselineVuln(ctx context.Context, c eval.Case, cs *domain.AnalysisCase) domain.Vulnerability {
	if cs != nil && cs.Vulnerability.ID != "" {
		return cs.Vulnerability
	}
	if c.VulnFile != "" {
		if v, err := (vulnerability.FileSource{Path: c.VulnFile}).Get(ctx, c.Vuln); err == nil && v != nil {
			return *v
		}
	}
	return domain.Vulnerability{ID: c.Vuln}
}

type caseOutcome struct {
	idx           int
	c             eval.Case
	verdict       domain.Verdict
	reason        string
	claims        map[string]string
	falsifier     string
	groundBasis   string
	evidenceIDs   []string
	productDir    string
	err           error
	baseline      string
	duration      time.Duration
	topTimingsStr string
	// projection is the case's requested-finding projection: the one
	// authoritative classification the harness scores.
	projection eval.Projection
}

// published is the token the harness scores: the requested verdict, or the
// explicit FAILED token when the analysis published no verdict. An external
// dependency publishes INCONCLUSIVE and is therefore never a definitive answer.
func (o caseOutcome) published() string {
	if o.projection.Available && o.projection.Outcome == domain.OutcomeFailed {
		return failedResultToken
	}
	return string(o.verdict)
}

// display renders the progress-stream classification.
func (o caseOutcome) display() string {
	if o.err != nil {
		return ""
	}
	if !o.projection.Available {
		return string(o.verdict)
	}
	parts := []string{string(o.projection.Outcome)}
	if o.projection.Verdict != "" {
		parts = append(parts, string(o.projection.Verdict))
	}
	if len(o.projection.FailureCodes) > 0 {
		parts = append(parts, strings.Join(o.projection.FailureCodes, ","))
	}
	if len(o.projection.ExternalDependencies) > 0 {
		parts = append(parts, strings.Join(o.projection.ExternalDependencies, ", "))
	}
	return strings.Join(parts, " ")
}

const failedResultToken = "FAILED"

// evalProjection projects one requested finding into the harness's result
// fields. Every value comes from the publication projection: no heuristic here
// re-reads the primary record's conclusion.
func evalProjection(view requestedView) eval.Projection {
	f := view.Finding
	projection := eval.Projection{
		Available:            true,
		RequestedID:          f.RequestedID,
		RequestedKind:        string(f.RequestedKind),
		Coverage:             string(f.Coverage),
		Outcome:              f.Outcome,
		Verdict:              f.Verdict,
		Reason:               f.Reason,
		ExploitabilityScope:  string(f.ExploitabilityScope),
		Profile:              string(f.Profile),
		Build:                buildLabel(f.Build),
		CandidateIDs:         projectedCandidates(view.View.Primary),
		AttributionOutcomes:  projectedAttributions(view.View.Primary),
		CorpusDigest:         projectedCorpusDigest(view.View.Primary, f.FindingProfile),
		FailureCodes:         projectedFailureCodes(f.FindingProfile),
		ExternalDependencies: projectedExternalFacts(f.FindingProfile),
	}
	if primary := view.View.Primary; primary != nil && primary.RecordPin != nil {
		projection.PrimaryRecord = primary.RecordPin.RecordID
		projection.PrimaryDigest = primary.RecordPin.DocumentDigest
	}
	for _, origin := range f.ProofOrigins {
		projection.ProofOrigins = append(projection.ProofOrigins, eval.ProofOriginRef{
			AssessmentID:   string(origin.AssessmentID),
			RecordID:       origin.Record.RecordID,
			DocumentDigest: origin.Record.DocumentDigest,
			EntryRefs:      append([]int(nil), origin.EntryRefs...),
			MechanismID:    origin.MechanismID,
			AttributionID:  origin.AttributionID,
			Profile:        string(origin.Profile),
		})
	}
	return projection
}

func runCase(ctx context.Context, idx, total int, c eval.Case, o analyzeOpts, base, genRoot string, gen eval.Gen) caseOutcome {
	caseStart := time.Now()
	co := o
	co.vulnID = c.Vuln
	co.vulnFile = c.VulnFile
	co.exploitModel = c.ExploitModel
	platformOverride := false
	if c.GOOS != "" {
		co.goos = c.GOOS
		platformOverride = true
	}
	if c.GOARCH != "" {
		co.goarch = c.GOARCH
		platformOverride = true
	}
	if len(c.BuildTags) > 0 {
		co.tags = strings.Join(c.BuildTags, ",")
		platformOverride = true
	}
	if c.GoVersion != "" {
		co.releaseGo = c.GoVersion
		co.toolchain = toolchain.Toolchain{}
		co.srcIndex = nil
		co.goTool = nil
		co.gvRunner = nil
	}
	co.manualRC = nil
	for _, rc := range c.RootCauses {
		co.manualRC = append(co.manualRC, rc.RootCause)
	}
	// The corpus non_locus field is an explicit expert-input channel;
	// stamping keeps its provenance distinct from machine proposals.
	co.nonLocusBasis = domain.ExpertLocusDecisions(c.NonLocus)
	if c.TrustedPeer {
		co.trustedPeer = true
	}
	if c.Perimeter != "" {
		co.perimeterMode = c.Perimeter
	}
	if c.DeployManifests != "" {
		co.deployManifests = c.DeployManifests
	}
	var productDir string
	switch {
	case c.Product != "" && c.Repo != "":
		return caseOutcome{idx: idx, c: c, err: fmt.Errorf("case sets both repo and product — they are mutually exclusive"), duration: time.Since(caseStart)}
	case c.Product == "" && (c.Module != "" || len(c.Deps) > 0):
		return caseOutcome{idx: idx, c: c, err: fmt.Errorf("module/deps declared without a product"), duration: time.Since(caseStart)}
	case c.Product != "":
		dir, err := gen.Materialize(ctx, c, base, genRoot)
		if err != nil {
			return caseOutcome{idx: idx, c: c, err: err, duration: time.Since(caseStart)}
		}
		productDir = dir
		co.repo = dir
	}
	if c.Repo != "" {
		absCase, err := filepath.Abs(c.Repo)
		if err != nil {
			return caseOutcome{idx: idx, c: c, err: err, duration: time.Since(caseStart)}
		}
		if c.Ref != "" {
			dir, err := gen.MaterializeRef(ctx, absCase, c.Ref, genRoot, c.Label())
			if err != nil {
				return caseOutcome{idx: idx, c: c, err: err, duration: time.Since(caseStart)}
			}
			co.repo = dir
			productDir = dir
		} else {
			co.repo = absCase
		}
	}
	if co.repo != o.repo || platformOverride {
		co.srcIndex = nil
		co.goTool = nil
		co.gvRunner = nil
	}
	if o.caseDir != "" {
		co.caseDir = filepath.Join(o.caseDir, sanitizeCaseName(c.Label()))
	}
	cs, err := analyzeCase(ctx, co)
	var projection eval.Projection
	var verdict domain.Verdict
	var reason string
	var falsifier, groundBasis string
	var evidenceIDs []string
	claims := map[string]string{}
	var topTimingsStr string
	if err == nil {
		// A workflow error is an execution error; a FAILED requested
		// assessment is an ordinary result and is scored as such below.
		view, perr := projectRequested(cs)
		if perr != nil {
			err = fmt.Errorf("requested finding projection: %w", perr)
		} else {
			projection = evalProjection(view)
			verdict = projection.Verdict
			reason = projection.Reason
			// The claim and falsifier projection comes from the record that
			// grounds the answer, so a composed CVE positive reports its
			// witness's conditions rather than the primary record's.
			grounding := view.groundingRecord()
			claims = claimResults(grounding)
			falsifier, groundBasis, evidenceIDs = groundingClaim(grounding)
		}
	}
	if cs != nil {
		topTimingsStr = topTimings(cs.Workflow.Timings, 3)
	}

	var baseline string
	if productDir != "" {
		vuln := baselineVuln(ctx, c, cs)
		if got, ok := recordedBaseline(cs, vuln); ok {
			baseline = got
		} else {
			// No collected run record exists at all: this is the only case
			// that may start a second, standalone baseline execution.
			baseline = eval.Baseline(ctx,
				goanalysis.ExecRunner{Env: co.toolchain.Env}, productDir,
				vuln, domain.ProductSnapshot{
					GOOS: co.goos, GOARCH: co.goarch, BuildTags: splitCSV(co.tags),
				})
		}
	}

	return caseOutcome{
		idx:           idx,
		c:             c,
		verdict:       verdict,
		reason:        reason,
		claims:        claims,
		falsifier:     falsifier,
		groundBasis:   groundBasis,
		evidenceIDs:   evidenceIDs,
		productDir:    productDir,
		err:           err,
		baseline:      baseline,
		duration:      time.Since(caseStart),
		topTimingsStr: topTimingsStr,
		projection:    projection,
	}
}

// selectRecordedGovulncheck returns the govulncheck evidence the case
// already collected. The latest completed typed run wins over failed/not-run
// records (the same rule the evaluator applies). A legacy record without a
// typed outcome is returned as-is so it is classified as unknown instead of
// triggering a second, unreported baseline execution.
func selectRecordedGovulncheck(cs *domain.AnalysisCase) *domain.Evidence {
	if cs == nil {
		return nil
	}
	evidence := cs.EvidenceGraph.EvidenceList()
	var completed, latest *domain.Evidence
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != domain.EvidenceGovulncheck {
			continue
		}
		latest = e
		if e.Govulncheck != nil &&
			(e.Govulncheck.Outcome == domain.GovulncheckCompletedEmpty ||
				e.Govulncheck.Outcome == domain.GovulncheckCompletedWithResults) {
			completed = e
		}
	}
	if completed != nil {
		return completed
	}
	return latest
}

// recordedBaseline classifies the case's collected govulncheck record. ok is
// false only when no govulncheck record exists at all — the sole condition
// for a standalone baseline execution. A record from a different build is
// reported as an error, never reclassified as this build's measurement and
// never silently re-run.
func recordedBaseline(cs *domain.AnalysisCase, v domain.Vulnerability) (baseline string, ok bool) {
	ev := selectRecordedGovulncheck(cs)
	if ev == nil {
		return "", false
	}
	if ev.BuildContext != nil {
		if err := ev.BuildContext.Matches(domain.EffectiveBuildContext(cs.Product)); err != nil {
			return eval.BaselineError + ": recorded govulncheck run describes a different build: " + err.Error(), true
		}
	}
	return eval.BaselineFromEvidence(*ev, v), true
}

func sanitizeCaseName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

const evalCompareUsage = `usage:
  izyan eval compare --before <report.json> --after <report.json> --out <delta.json>

  Compare two saved Product A evaluation runs and quantify what an authority
  change did to the answers. The comparison is offline: it reads the two
  recorded reports, never re-analyzes a case, and never consults an LLM.

  The runs are paired by case, input and build identity. A case present on one
  side only, or one identity recorded twice, refuses the comparison: a delta
  over unmatched material measures nothing. Every direction is reported
  separately — lost and gained definitive positives, lost and gained negatives,
  new and cleared failures, and each condition's own result transition — so a
  lost weak positive is stated as a loss rather than netted away.

Exit codes: 0 compared without a new false-safe; 1 the comparison gained a
false-safe; 2 malformed inputs or unmatched material.
`

// Offline authority-delta exit codes. A measured loss is a completed
// comparison; only a new false-safe is a stop-the-line outcome.
const (
	evalCompareExitFalseSafe = 1
	evalCompareExitError     = 2
)

// runEvalCompare implements `izyan eval compare`.
func runEvalCompare(args []string) error {
	fs := flag.NewFlagSet("eval compare", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, evalCompareUsage) }
	beforePath := fs.String("before", "", "saved JSON report of the pre-change run")
	afterPath := fs.String("after", "", "saved JSON report of the post-change run")
	outPath := fs.String("out", "", "file to write the authority delta JSON to")
	if err := fs.Parse(args); err != nil {
		return exitErr(evalCompareExitError, err)
	}
	if fs.NArg() != 0 {
		return exitErr(evalCompareExitError, fmt.Errorf(
			"eval compare: unexpected positional arguments: %v", fs.Args()))
	}
	if *beforePath == "" || *afterPath == "" || *outPath == "" {
		fs.Usage()
		return exitErr(evalCompareExitError, fmt.Errorf(
			"eval compare: --before, --after and --out are required"))
	}

	before, err := loadEvalReport(*beforePath)
	if err != nil {
		return exitErr(evalCompareExitError, fmt.Errorf("eval compare: --before: %w", err))
	}
	after, err := loadEvalReport(*afterPath)
	if err != nil {
		return exitErr(evalCompareExitError, fmt.Errorf("eval compare: --after: %w", err))
	}

	delta, err := eval.CompareAuthorityResults(before.Results, after.Results)
	if err != nil {
		return exitErr(evalCompareExitError, fmt.Errorf("eval compare: %w", err))
	}
	delta.Before = absPath(*beforePath)
	delta.After = absPath(*afterPath)

	raw, err := json.MarshalIndent(delta, "", "  ")
	if err != nil {
		return exitErr(evalCompareExitError, fmt.Errorf("eval compare: encode delta: %w", err))
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		return exitErr(evalCompareExitError, fmt.Errorf("eval compare: write delta: %w", err))
	}

	fmt.Fprint(os.Stdout, delta.Summary())
	if len(delta.FalseSafeGained) > 0 {
		return exitErr(evalCompareExitFalseSafe, fmt.Errorf(
			"eval compare: %d case(s) became false-safe under the authority change; see %s",
			len(delta.FalseSafeGained), *outPath))
	}
	return nil
}

// loadEvalReport decodes one saved report. Only the results are authoritative
// for a comparison: the recorded metrics describe the run, not the pairing.
func loadEvalReport(path string) (eval.Report, error) {
	var report eval.Report
	raw, err := os.ReadFile(path)
	if err != nil {
		return report, err
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return report, fmt.Errorf("decode %s: %w", path, err)
	}
	if len(report.Results) == 0 {
		return report, fmt.Errorf("%s carries no results", path)
	}
	return report, nil
}

// absPath renders a path for the record so the delta names the runs it
// compared even when the caller used a relative path.
func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
