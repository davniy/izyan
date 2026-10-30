package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/exploit"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/persistence/filesystem"
	"github.com/fedorovmv/izyan/internal/report"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/review"
	"github.com/fedorovmv/izyan/internal/rootcause"
	"github.com/fedorovmv/izyan/internal/states"
	"github.com/fedorovmv/izyan/internal/toolaudit"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/tracker"
	"github.com/fedorovmv/izyan/internal/vulnerability"
	"github.com/fedorovmv/izyan/internal/workflow"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "analyze":
		err = runAnalyze(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "eval":
		if len(os.Args) > 2 && os.Args[2] == "vex-bench" {
			err = runVexBench(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "vex-triage" {
			err = runVexTriage(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "triage" {
			err = runTriageEval(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "compare" {
			err = runEvalCompare(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "research-replay" {
			err = runResearchHistory(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "research-b1" {
			// The frozen B1 arm is an evaluation control, never a product
			// runtime: it lives under `eval` so no top-level command
			// advertises a second live investigator.
			err = runResearchB(os.Args[3:])
		} else {
			err = runEval(os.Args[2:])
		}
	case "remediate":
		err = runRemediate(os.Args[2:])
	case "triage":
		err = runTriage(os.Args[2:])
	case "research":
		err = runResearch(os.Args[2:])
	case "knowledge":
		err = runKnowledge(os.Args[2:])
	case "version", "-version", "--version", "-v":
		printVersion()
		return
	default:
		usage()
	}
	if err != nil {
		var ee *cliExitError
		code := 1
		if errors.As(err, &ee) {
			code = ee.code
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(code)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  izyan analyze --repo <path> --vuln <GO-/CVE-/GHSA-id> [options]
  izyan scan    --repo <path> [options]   # all advisories for all modules
  izyan eval    --corpus <path> [--repo <path>] [--case <id|glob>] [-j <n>] [--clean] [options]  # corpus regression run
  izyan eval vex-bench --tasks <vex_bench.jsonl> --repos-dir <dir> [--case <id|glob>] [-j <n>] [--out <dir>]  # VEX-Bench baseline
  izyan eval vex-triage prepare --tasks <vex_bench.jsonl> --repos-dir <dir> --advisories-dir <dir> --out <dir>  # prepare blinded case bundle
  izyan eval triage --run <run-directory> --baseline <triage-baselines.json> --out <directory>  # offline saved-run comparison
  izyan eval compare --before <report.json> --after <report.json> --out <delta.json>  # offline authority-delta comparison of two saved runs
  izyan eval research-replay --run <saved-run> --out <new-directory>  # offline historical playback; no current admission
  izyan remediate --repo <path> --vuln <id> [--apply] [--run-tests]  # plan/apply fix + re-analyze
  izyan research --snapshot <path> --cve <id> (--advisory-dir <dir>|--advisory-file <json>) --output-dir <dir> [options]  # deterministic evidence/proof lane + saved-turn replay
  izyan triage --input <finding.json|findings.jsonl|-> --out <dir> [options]  # LLM-first triage (the one live Product B investigator; non-authoritative)
  izyan eval research-b1 --snapshot <path> --cve <id> (--advisory <file|dir>) --out <dir> [--allow-agent|--dry-run]  # frozen B1 evaluation arm (evaluation-only)
  izyan knowledge [--knowledge <path>]  # dump the effective ecosystem knowledge base
  izyan version                           # show version information

options:
  --vuln-file <path>     load advisory from local OSV JSON instead of api.osv.dev
  --ticket <path>        tracker ticket JSON, arbitrary text, or '-' for stdin
  --ticket-id <id>       ticket key to select when input contains multiple tickets
  --repo-map <path>      path to JSON mapping component/ticket keys to repo paths
  --osv-url <url>        override OSV API base URL
  --case-dir <dir>       analysis state directory (default .izyan)
  --case <id|glob>       filter cases to run in eval (comma-separated or glob)
  -j <n>                 parallel worker pool concurrency for eval (default: 4)
  --clean                force re-materialization of generated modules in eval
  --goos/--goarch        target platform (default: host)
  --build-tags a,b       build tags
  --binary <path>        release-built Go binary: embedded build info is authoritative release evidence
  --release-go-version <ver> toolchain that built the release (authoritative for stdlib advisories; go.mod is only a minimum)
  --root-cause p.Sym     manual root cause symbol (repeatable, comma-separated)
  --exploit-model <path> manual exploit model JSON
  --knowledge <path>     extend the ecosystem knowledge base (JSON, additive)
  --non-locus-basis <path> JSON file with expert non-locus basis decisions
  --declared-assumptions <path> declared-assumptions/1 policy/scope inputs (config-trust, supported-targets; never evidence)
  --deploy-manifests <path> path to deployment manifests (directory or .tgz/.tar.gz/.zip archive)
  --perimeter <auto|cluster|public> deployment perimeter context (default: auto)
  --cve-analysis <off|assist|verified>  LLM CVE analysis profile (default: off)
  --llm-intake           use LLM to extract vulnerability and metadata from unstructured ticket text
  --checkout-release     resolve release/tag and analyze in an isolated git worktree
  --release <tag|ref>    explicit release tag or git ref to analyze (or --git-ref)
  --lang <ru|en>         report and output language (default: ru)
  --deterministic-only   disable all LLM-backed states

advisory corpus (discovery + Addendum A negative authority):
  --osv-feed <path>        offline OSV dump: a directory of OSV JSON documents or one zip archive
  --osv-cache-dir <dir>    cache directory for a corpus fetched from IZYAN_OSV_URL
  --osv-dump-ttl <dur>     max age of a cached corpus dump (default 168h; 0 = length probe only)
  --osv-no-proxy           fetch the corpus dump without http_proxy/https_proxy
  --corpus-digest <sha256> declared corpus digest; with --corpus-captured-at it forms the
                           declared boundary a CVE-wide negative requires (without it a CVE
                           negative stays FAILED / UNSUPPORTED_NEGATIVE_SCOPE)
  --corpus-captured-at <RFC3339> declared corpus capture date (requires --corpus-digest)
  --record-pin <id>=<sha256> choose exact bytes when one record id has conflicting documents (repeatable)
  --attribution-file <path> capture manifest (attribution-captures/1) of publisher/CNA documents

note: --osv-url addresses the OSV API for one advisory (and scan queries); it is not a corpus
dump source. A remote corpus is configured through the IZYAN_OSV_URL environment variable.
A configured feed alone grants no negative authority; a finished, declared and digest-pinned
corpus does, and only together with an independently admitted negative for every candidate.`)
	os.Exit(2)
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type analyzeOpts struct {
	repo          string
	vulnID        string
	vulnFile      string
	osvURL        string
	caseDir       string
	goos          string
	goarch        string
	tags          string
	cgo           string
	binary        string
	releaseGo     string
	ticketID      string
	ticketComp    string
	ticketRel     string
	ticketKey     string
	llmIntake     bool
	checkoutRel   bool
	releaseRef    string
	worktreeRef   string
	worktreeSHA   string
	repoMap       string
	cveAnalysis   string
	lang          string
	exploitModel  string
	llmEnv        string
	knowledge     string
	detOnly       bool
	allowExec     bool
	strictLLM     bool
	memLimit      string
	rootCauseArgs []string
	// manualRC carries already-parsed root causes (eval corpus entries
	// support the object form, which rootCauseArgs strings cannot express).
	manualRC []domain.RootCause
	// nonLocusBasis carries expert necessity decisions — declared symbols
	// asserted not to be defect loci — into the case. Loaded from the
	// -non-locus-basis JSON file or from an eval corpus entry.
	nonLocusBasis []domain.LocusDecision
	nonLocusFile  string
	// declaredAssumptions is the path of an optional
	// declared-assumptions/1 document: typed operator policy/scope
	// inputs. It is an input channel, never evidence; an intake failure
	// is recorded as a limitation and admits nothing.
	declaredAssumptions string
	trustedPeer         bool
	deployManifests     string
	perimeterMode       string
	// toolchain is the resolved target Go toolchain; zero value = local.
	toolchain toolchain.Toolchain
	// tcLims carries resolution notes into the case's limitations.
	tcLims []string
	// Shared across advisories in scan mode; nil in single analyze.
	srcIndex *goanalysis.Index
	goTool   affected.GoTool
	gvRunner goanalysis.Runner
	// snapshot is the scan's single resolved build snapshot, shared by every
	// case. Single-analyze leaves it nil and SnapshotProduct resolves its own.
	snapshot *domain.ProductSnapshot
	// kb is the resolved ecosystem knowledge base (default + --knowledge
	// extension); nil = built-in defaults.
	kb *goanalysis.Knowledge
	// externalCommitSHA supplies the snapshot identity from an external
	// controller (benchmark); when set, no git history is consulted and the
	// snapshot is analysed as an immutable tree.
	externalCommitSHA string
	// suppressEnvFile disables .env auto-loading (benchmark isolation).
	suppressEnvFile bool
	// envReplace makes every Go subprocess use only the resolved toolchain
	// environment instead of the ambient one (benchmark isolation).
	envReplace bool
	// confineReads routes source reads through a canonical read-gate that
	// rejects targets outside the allowed roots (benchmark isolation).
	confineReads bool
	// advisoryDir is the prepared advisory directory allowed under
	// confineReads (benchmark isolation).
	advisoryDir string
	// corpus is the pre-acquired, pinned advisory corpus used for request
	// discovery. Nil means no corpus is configured; discovery then records
	// DiscoveryNotConfigured and a CVE request cannot close negatively.
	corpus states.RelatedRecordSource
	// corpusDeclaration is the operator-declared corpus boundary applied to
	// every case in this run. Without it a complete enumeration still cannot
	// ground a CVE-wide negative (Addendum A).
	corpusDeclaration *domain.CorpusDeclaration
	// attributionMaterials maps captured publisher/CNA material URIs to local
	// normalized JSON captures. Empty leaves only each record's own
	// identity/alias admission available.
	attributionMaterials map[string]string
	// Corpus discovery source configuration. --osv-url is deliberately absent:
	// it stays the single-record OSV API base and is never a dump source.
	osvFeed          string
	osvCacheDir      string
	osvDumpTTL       time.Duration
	osvNoProxy       bool
	corpusDigest     string
	corpusCapturedAt string
	recordPins       stringList
	attributionFile  string
 fixSourceCaptures string
 sourceCaptures *rootcause.SourceCaptureSet
}

// parseCGO turns the --cgo selector into the tri-state the resolver needs:
// nil keeps the analyzer default (off), true/false is an explicit operator
// choice recorded on the resolved target.
func parseCGO(v string) *bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1":
		b := true
		return &b
	case "off", "false", "0":
		b := false
		return &b
	default:
		return nil
	}
}

// validateCGOFlag rejects an unusable --cgo value instead of silently
// falling back to the default: a typo must not change which files are
// analysed without saying so.
func validateCGOFlag(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	if parseCGO(v) == nil {
		return fmt.Errorf("--cgo must be on or off, got %q", v)
	}
	return nil
}

// cgoEnabled is the effective cgo mode for a build context: an explicit
// --cgo selector wins, the analyzer default is off.
func cgoEnabled(v string) bool {
	if b := parseCGO(v); b != nil {
		return *b
	}
	return false
}

// commonFlags registers the flags shared by analyze and scan.
func commonFlags(fs *flag.FlagSet, o *analyzeOpts) {
	fs.StringVar(&o.repo, "repo", "", "path to Go repository")
	fs.StringVar(&o.osvURL, "osv-url", "", "OSV API base URL for single-record resolution and scan queries (never a corpus dump source)")
	advisorySourceFlags(fs, o)
 fs.StringVar(&o.fixSourceCaptures,"fix-source-captures","","strict fix-source-captures.v1 local manifest (captured-only artifacts)")
	fs.StringVar(&o.caseDir, "case-dir", ".izyan", "case state directory")
	fs.StringVar(&o.goos, "goos", "", "target GOOS")
	fs.StringVar(&o.goarch, "goarch", "", "target GOARCH")
	fs.StringVar(&o.tags, "build-tags", "", "comma-separated build tags")
	fs.StringVar(&o.cgo, "cgo", "", "cgo build mode for an operator-declared target: on|off (default off); the analyzer does not build the product, but this selects which files are analysed")
	fs.StringVar(&o.binary, "binary", "", "release-built Go binary: govulncheck -mode binary + embedded toolchain")
	fs.StringVar(&o.releaseGo, "release-go-version", "", "toolchain version that built the release (e.g. from the ticket)")
	fs.StringVar(&o.cveAnalysis, "cve-analysis", "off", "LLM CVE analysis profile: off, assist, verified")
	fs.BoolVar(&o.detOnly, "deterministic-only", false, "disable LLM-backed states")
	fs.BoolVar(&o.allowExec, "allow-exec", false, "permit executing repository code for build/test evidence (run_build/run_tests)")
	fs.BoolVar(&o.strictLLM, "strict-llm", false, "fail fast on LLM errors/refusals without fallback to deterministic code")
	fs.StringVar(&o.llmEnv, "llm-env", "", "path to LLM .env file (default: .env in cwd or repo)")
	fs.StringVar(&o.knowledge, "knowledge", "", "extend the ecosystem knowledge base with a JSON file (see internal/goanalysis/knowledge.go)")
	fs.StringVar(&o.memLimit, "mem-limit", "4GiB", "analyzer memory ceiling (e.g. 4GiB, 512MiB; 0 disables) — real products can pull very large dependency graphs into the index")
	fs.StringVar(&o.nonLocusFile, "non-locus-basis", "", "JSON file with expert non-locus decisions: [{\"symbol\":{\"package\":\"pkg\",\"symbol\":\"Type.Name\"},\"basis\":\"why it is not a defect site\",\"authority\":\"review ref\"}]")
	fs.BoolVar(&o.trustedPeer, "trusted-peer", false, "declare deployment in trusted infrastructure / communication with trusted peers only (falsifies untrusted peer/network input)")
	fs.StringVar(&o.declaredAssumptions, "declared-assumptions", "", "declared-assumptions/1 JSON document with operator policy/scope inputs (config-trust, supported-targets); never a substitute for evidence")
	fs.BoolVar(&o.checkoutRel, "checkout-release", false, "resolve release/tag from ticket or --release and run analysis in an isolated git worktree")
	fs.StringVar(&o.releaseRef, "release", "", "explicit release tag, branch, or commit to analyze (overrides ticket release)")
	fs.StringVar(&o.releaseRef, "git-ref", "", "alias for --release")
	deployDefault := o.deployManifests
	if deployDefault == "" {
		deployDefault = os.Getenv("VA_DEPLOY_MANIFESTS")
	}
	fs.StringVar(&o.deployManifests, "deploy-manifests", deployDefault, "comma-separated paths to deployment manifests (directories or .tgz/.tar.gz/.zip archive)")
	perimeterDefault := o.perimeterMode
	if perimeterDefault == "" {
		perimeterDefault = os.Getenv("VA_PERIMETER")
	}
	if perimeterDefault == "" {
		perimeterDefault = "auto"
	}
	fs.StringVar(&o.perimeterMode, "perimeter", perimeterDefault, "deployment perimeter context: auto, cluster, public")
	fs.StringVar(&o.lang, "lang", "ru", "report and output language: ru (default) or en")
}

func buildSnapshotOptions(o analyzeOpts) (repository.SnapshotOptions, error) {
	perimeter, err := normalizePerimeter(o.perimeterMode)
	if err != nil {
		return repository.SnapshotOptions{}, err
	}
	opts := repository.SnapshotOptions{
		GOOS:              o.goos,
		GOARCH:            o.goarch,
		BuildTags:         splitCSV(o.tags),
		CGO:               parseCGO(o.cgo),
		BinaryPath:        o.binary,
		ReleaseGoVersion:  o.releaseGo,
		TrustedPeer:       o.trustedPeer,
		PerimeterOverride: perimeter,
		ExternalCommitSHA: o.externalCommitSHA,
		GoBin:             o.toolchain.GoBin,
		Env:               o.toolchain.Env,
	}
	path := strings.TrimSpace(o.deployManifests)
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".zip") {
		opts.DeployArchive = path
	} else if path != "" {
		for _, part := range strings.Split(path, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				opts.DeployManifests = append(opts.DeployManifests, trimmed)
			}
		}
	}
	return opts, nil
}

func normalizePerimeter(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "cluster", "cluster-internal":
		return domain.PerimeterClusterInternal, nil
	case "public":
		return domain.PerimeterPublic, nil
	case "auto", "":
		return "auto", nil
	default:
		return "", fmt.Errorf("invalid --perimeter value %q: expected auto, cluster, or public", p)
	}
}

// loadKnowledgeBase resolves the --knowledge extension: built-in
// defaults plus the additive entries from the JSON file. Empty path —
// nil, the index falls back to DefaultKnowledge().
func loadKnowledgeBase(path string) (*goanalysis.Knowledge, error) {
	if path == "" {
		return nil, nil
	}
	f, err := goanalysis.LoadKnowledgeFile(path)
	if err != nil {
		return nil, fmt.Errorf("knowledge: %w", err)
	}
	// Files without a declared name identify in reports by their path.
	if f.Name == "" {
		f.Name = filepath.Base(path)
	}
	kb := goanalysis.DefaultKnowledge()
	if err := kb.Merge(f); err != nil {
		return nil, fmt.Errorf("knowledge: %w", err)
	}
	return kb, nil
}

// runKnowledge prints the effective ecosystem knowledge base in the
// extension-file schema: the embedded defaults by themselves, or
// defaults merged with a --knowledge extension. Users copy the output
// as the starting point for their own extension files; the command also
// doubles as a validator — a bad extension file fails here.
func runKnowledge(args []string) error {
	fs := flag.NewFlagSet("knowledge", flag.ExitOnError)
	var o analyzeOpts
	fs.StringVar(&o.knowledge, "knowledge", "", "extension JSON merged over the embedded defaults")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCGOFlag(o.cgo); err != nil {
		return err
	}
	kb, err := loadKnowledgeBase(o.knowledge)
	if err != nil {
		return err
	}
	if kb == nil {
		kb = goanalysis.DefaultKnowledge()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(kb.AsFile())
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	fs.StringVar(&o.vulnID, "vuln", "", "vulnerability id (GO-/CVE-/GHSA-)")
	fs.StringVar(&o.vulnFile, "vuln-file", "", "local OSV JSON file")
	fs.StringVar(&o.exploitModel, "exploit-model", "", "manual exploit model JSON")
	ticketPath := fs.String("ticket", "", "tracker ticket JSON, arbitrary text, or '-' for stdin")
	ticketKey := fs.String("ticket-id", "", "ticket key/id to select if ticket input contains multiple tickets")
	repoMapPath := fs.String("repo-map", "", "path to JSON mapping component/ticket keys to local repo paths")
	llmIntake := fs.Bool("llm-intake", false, "use LLM to extract vulnerability and metadata from unstructured ticket text")
	var rootCauseFlags stringList
	fs.Var(&rootCauseFlags, "root-cause", "manual root cause as pkg/path.Symbol (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
 if o.fixSourceCaptures!="" {var err error;o.sourceCaptures,err=rootcause.LoadSourceCaptures(o.fixSourceCaptures);if err!=nil{return fmt.Errorf("fix-source captures: %w",err)}}
	if err := validateCGOFlag(o.cgo); err != nil {
		return err
	}
	o.rootCauseArgs = rootCauseFlags
	if *ticketKey != "" {
		o.ticketKey = *ticketKey
	}
	if *repoMapPath != "" {
		o.repoMap = *repoMapPath
	}
	o.llmIntake = *llmIntake
	if *ticketPath != "" {
		loadLLMEnv(o.llmEnv, o.repo)
		llmCfg := llm.ConfigFromEnv()
		var completer tracker.TextCompleter
		if o.llmIntake {
			if !llmCfg.Enabled || o.detOnly {
				return fmt.Errorf("--llm-intake: cannot use --llm-intake when LLM is disabled or --deterministic-only is set")
			}
			completer = llmCompleterAdapter{client: llm.NewClient(llmCfg), role: llm.Build}
		} else if llmCfg.Enabled && !o.detOnly {
			completer = llmCompleterAdapter{client: llm.NewClient(llmCfg), role: llm.Build}
		}
		if err := applyTicket(&o, *ticketPath, completer); err != nil {
			return err
		}
	}
	if o.vulnID == "" && o.vulnFile != "" {
		if b, err := os.ReadFile(o.vulnFile); err == nil {
			var doc struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(b, &doc); err == nil && doc.ID != "" {
				o.vulnID = doc.ID
			}
		}
	}
	if o.repo == "" || o.vulnID == "" {
		usage()
	}
	var err error
	if o.kb, err = loadKnowledgeBase(o.knowledge); err != nil {
		return err
	}
	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()
	// The corpus and capture inputs are resolved once, before any analysis
	// exists: invalid operator input (a declaration without a source, a
	// malformed manifest, a digest that does not match the captured bytes) is
	// a usage error, while an unreadable source becomes the corpus manifest's
	// explicit unavailable outcome.
	if err := resolveAdvisorySources(ctx, &o); err != nil {
		return err
	}
	wtCleanup, err := prepareReleaseWorktree(ctx, &o)
	if err != nil {
		return err
	}
	if wtCleanup != nil {
		defer func() {
			// Fail-closed cleanup never mutates .git/worktrees unlocked;
			// a skipped removal leaves only a stale registration for
			// git's own prune. Record the named error on stderr.
			if cerr := wtCleanup(); cerr != nil {
				fmt.Fprintf(os.Stderr, "worktree cleanup: %v\n", cerr)
			}
		}()
	}
	c, err := analyzeCase(ctx, o)
	if err != nil {
		return err
	}
	// A FAILED requested assessment is an ordinary persisted result, not an
	// execution error: the case and its report path are printed first, and only
	// then does the command exit nonzero.
	if perr := printCase(c, o.caseDir, o.lang); perr != nil {
		return perr
	}
	if o.strictLLM && c.Workflow.State == domain.StateFailed {
		return fmt.Errorf("strict-llm: analysis failed in state %s", c.Workflow.State)
	}
	return nil
}

// applyTicket folds a generic tracker ticket or extracted ticket metadata into analyze options:
// explicit CLI flags win over ticket fields (ticket is the default, not an override).
// If repo is unset, repo-map or default repos.json resolution is attempted against component/product/ticket.
func applyTicket(o *analyzeOpts, path string, completer tracker.TextCompleter) error {
	t, err := tracker.LoadTicketWithOptions(path, o.ticketKey, completer)
	if err != nil {
		return err
	}
	if o.vulnID == "" {
		o.vulnID = t.Vulnerability
	}
	if o.ticketID == "" && t.ID != "" {
		o.ticketID = t.ID
	}
	if o.ticketComp == "" && t.Component != "" {
		o.ticketComp = t.Component
	}
	if o.ticketRel == "" && t.Release != "" {
		o.ticketRel = t.Release
	}
	if o.releaseGo == "" {
		if t.GoVersion != "" {
			o.releaseGo = t.GoVersion
		} else if t.Toolchain != "" {
			o.releaseGo = t.Toolchain
		}
	}

	// Resolve repo if not explicitly provided
	if o.repo == "" {
		var rm *tracker.RepoMap
		if o.repoMap != "" {
			var err error
			rm, err = tracker.LoadRepoMap(o.repoMap)
			if err != nil {
				return fmt.Errorf("load repo-map %s: %w", o.repoMap, err)
			}
		} else {
			// Look for default repos.json or .izyan-repos.json in current directory
			for _, candidate := range []string{"repos.json", ".izyan-repos.json"} {
				if _, err := os.Stat(candidate); err == nil {
					if loaded, err := tracker.LoadRepoMap(candidate); err == nil {
						rm = loaded
						break
					}
				}
			}
		}

		if rm != nil {
			if resolved := rm.Resolve(t); resolved != "" {
				o.repo = resolved
			}
		}
		if o.repo == "" && t.Repo != "" {
			o.repo = t.Repo
		}
	}

	if o.vulnFile == "" && (len(t.OSV) > 0 || (t.Module != "" && len(t.FixedVersions) > 0)) {
		dir := filepath.Join(o.caseDir, "intake")
		f, err := t.AdvisoryFile(dir, o.vulnID)
		if err != nil {
			return fmt.Errorf("ticket advisory: %w", err)
		}
		if f != "" {
			o.vulnFile = f
		}
	}
	return nil
}

func prepareReleaseWorktree(ctx context.Context, o *analyzeOpts) (func() error, error) {
	if o.releaseRef != "" {
		o.ticketRel = o.releaseRef
	}
	if !o.checkoutRel {
		return nil, nil
	}
	if o.ticketRel == "" {
		return nil, fmt.Errorf("--checkout-release: no release specified (provide via --release or --ticket)")
	}
	if o.repo == "" {
		return nil, fmt.Errorf("--checkout-release: repository path (--repo) is required")
	}

	resolvedRef, sha, err := repository.ResolveRef(ctx, o.repo, o.ticketRel)
	if err != nil {
		return nil, fmt.Errorf("checkout release %q: %w", o.ticketRel, err)
	}

	o.worktreeRef = resolvedRef
	o.worktreeSHA = sha

	// Check if current clean HEAD already points to the resolved commit
	_, headSHA, headErr := repository.ResolveRef(ctx, o.repo, "HEAD")
	if headErr == nil && headSHA == sha {
		dirtyOut, _ := exec.CommandContext(ctx, "git", "-C", o.repo, "status", "--porcelain").Output()
		if len(bytes.TrimSpace(dirtyOut)) == 0 {
			return nil, nil
		}
	}

	wtPath, cleanup, err := repository.NewWorktree(ctx, o.repo, sha)
	if err != nil {
		return nil, fmt.Errorf("create worktree for release %s (%s): %w", resolvedRef, sha, err)
	}

	o.repo = wtPath
	return cleanup, nil
}

// analyzeCase runs the full pipeline for one vulnerability id.
func analyzeCase(ctx context.Context, o analyzeOpts) (*domain.AnalysisCase, error) {
	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return nil, err
	}

	var src vulnerability.Source
	if o.vulnFile != "" {
		src = vulnerability.FileSource{Path: o.vulnFile, NoAliasEnrichment: o.confineReads}
	} else {
		src = vulnerability.OSVSource{BaseURL: o.osvURL}
	}

	store := filesystem.New(o.caseDir)
	prior := store.PriorCase(ctx, o.vulnID, absRepo, "")
	caseID := domain.CaseID(fmt.Sprintf("%s-%d", sanitizeID(o.vulnID), time.Now().Unix()))
	c := &domain.AnalysisCase{
		ID:              caseID,
		RequestedID:     o.vulnID,
		TicketID:        o.ticketID,
		TicketComponent: o.ticketComp,
		TicketRelease:   o.ticketRel,
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCreated,
			StartedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			Limits: domain.AnalysisLimits{
				MaxIterations:       64,
				MaxToolCalls:        128,
				MaxLLMCalls:         32,
				MaxSourceReads:      256,
				MaxReviewIterations: 2,
			},
		},
	}
	c.EvidenceGraph.Version = "1"
	if prior != nil {
		c.PriorCase = prior.ID
	}
	c.NonLocusBasis = domain.ExpertLocusDecisions(o.nonLocusBasis)
	c.StrictLLM = o.strictLLM
	if o.corpusDeclaration != nil {
		declaration := *o.corpusDeclaration
		c.CorpusDeclaration = &declaration
	}
	// The declared-assumptions channel is loaded once per case: the
	// typed policy inputs (or the fail-closed intake outcome) are
	// persisted with the case, and an intake failure is surfaced as a
	// limitation so no consumer can read the missing policy as a pass.
	if strings.TrimSpace(o.declaredAssumptions) != "" {
		c.DeclaredAssumptions = repository.LoadDeclaredAssumptions(o.declaredAssumptions)
		if c.DeclaredAssumptions != nil && c.DeclaredAssumptions.LoadError != "" {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"declared assumptions %s failed closed (%s): no policy/scope assumption was admitted",
				c.DeclaredAssumptions.Path, c.DeclaredAssumptions.LoadError))
		}
	}
	if o.cveAnalysis != "" {
		c.CVEAnalysisProfile = domain.AnalysisProfile(o.cveAnalysis)
	} else {
		c.CVEAnalysisProfile = domain.ProfileOff
	}
	if o.nonLocusFile != "" {
		b, err := os.ReadFile(o.nonLocusFile)
		if err != nil {
			return nil, fmt.Errorf("read non-locus basis: %w", err)
		}
		var basis []domain.LocusDecision
		if err := json.Unmarshal(b, &basis); err != nil {
			return nil, fmt.Errorf("non-locus basis file is invalid: %w", err)
		}
		// This file is the explicit expert-input channel: stamp it so a
		// machine-origin decision cannot be smuggled in under an expert
		// Authority string and a saved machine decision is never promoted.
		c.NonLocusBasis = domain.ExpertLocusDecisions(basis)
	}
	if err := store.Create(ctx, c); err != nil {
		return nil, err
	}
	// Every external tool run under this ctx lands in the case's audit
	// trail — including toolchain probes and the product snapshot below.
	ctx = toolaudit.WithRecorder(ctx, &toolaudit.Recorder{Sink: c.EvidenceGraph.AddToolExecution})

	tc := o.toolchain
	if tc.GoBin == "" {
		var lims []string
		tc, lims = resolveToolchain(ctx, o)
		o.tcLims = lims
	}
	for _, l := range o.tcLims {
		c.EvidenceGraph.AddLimitation(l)
	}
	c.EvidenceGraph.AddLimitation(fmt.Sprintf(
		"analysis toolchain: go%s (%s)", tc.Version, tc.Mode))
	if o.worktreeRef != "" && o.checkoutRel {
		shortSHA := o.worktreeSHA
		if len(shortSHA) > 8 {
			shortSHA = shortSHA[:8]
		}
		c.EvidenceGraph.AddLimitation(fmt.Sprintf(
			"checkout release: %s (%s)", o.worktreeRef, shortSHA))
	}

	srcIndex := o.srcIndex
	if srcIndex == nil {
		srcIndex = &goanalysis.Index{
			Dir:        absRepo,
			Env:        tc.Env,
			KB:         o.kb,
			Confine:    o.confineReads,
			ReplaceEnv: o.envReplace,
			Build: domain.ProductSnapshot{
				GOOS: o.goos, GOARCH: o.goarch, BuildTags: splitCSV(o.tags), CGOEnabled: cgoEnabled(o.cgo),
			},
		}
	}
	if o.confineReads && o.advisoryDir != "" {
		srcIndex.ConfineRoots = append(srcIndex.ConfineRoots, o.advisoryDir)
	}
	goTool := o.goTool
	if goTool == nil {
		goTool = affected.ExecGoTool{Bin: tc.GoBin, Env: tc.Env, Version: tc.Version}
	}
	gvRunner := o.gvRunner
	if gvRunner == nil {
		gvRunner = goanalysis.ExecRunner{Env: tc.Env}
	}

	// LLM layer: env file auto-load (explicit --llm-env, else .env in
	// cwd or repo). LLM adapters only propose; verification stays
	// deterministic. Without LLM_ENABLED the pure deterministic path runs.
	if !o.suppressEnvFile {
		loadLLMEnv(o.llmEnv, absRepo)
	}
	llmCfg := llm.ConfigFromEnv()
	if o.strictLLM && (!llmCfg.Enabled || o.detOnly) {
		return nil, fmt.Errorf("strict-llm: cannot use --strict-llm when LLM is disabled or --deterministic-only is set")
	}
 captures := o.sourceCaptures
 var patchProvider fix.ArtifactProvider = fix.HTTPProvider{}
 if o.fixSourceCaptures!="" { if captures==nil {var err error;captures,err=rootcause.LoadSourceCaptures(o.fixSourceCaptures);if err!=nil{return nil,fmt.Errorf("fix source captures: %w",err)}};patchProvider=captures.PatchProvider() }
 var rcResolver states.RootCauseResolver = &rootcause.Resolver{Fix: fix.Resolver{}, Patch: patchProvider, Source: srcIndex, GoTool:goTool, Captures:captures}
	var builder states.ExploitBuilder = &exploit.Builder{Source: srcIndex}
	reviewers := review.Multi{review.Structural{}}
	// The deterministic evaluator chain — shared by EVALUATE_CONDITIONS
	// and the gap-analysis loop's re-evaluation pass.
	conditionEvaluators := []evaluator.ConditionEvaluator{
		evaluator.SymbolReachable{},
		evaluator.ServerTransportInput{},
		evaluator.ArgumentOrigin{},
		evaluator.CheckTrigger{},
		evaluator.Validation{},
		evaluator.MissingCall{},
		evaluator.Exposure{},
		evaluator.Authentication{},
		evaluator.ConfigFlag{},
		evaluator.Presence{},
		evaluator.VersionFact{},
		evaluator.Platform{},
		// Last resort: unrouted CUSTOM conditions (check= shapes are
		// claimed by their own evaluators above).
		evaluator.Custom{},
	}
	var fallbackEval evaluator.ConditionEvaluator
	var gapPlanner states.HypothesisPlanner
	var llmClient *llm.Client
	if llmCfg.Enabled && !o.detOnly {
		client := llm.NewClient(llmCfg)
		llmClient = client
		tools := llm.Tools{
			Source:      srcIndex,
			Vuln:        src,
			Patch:       fix.HTTPProvider{},
			Govulncheck: gvRunner,
			GoTool:      goTool,
			AllowExec:   o.allowExec,
		}
		rcResolver = &llm.RootCauseResolver{Client: client, Fallback: rcResolver}
		builder = llm.ExploitModelBuilder{Client: client, Fallback: builder}
		reviewers = append(reviewers, llm.Reviewer{Client: client})
		fallbackEval = llm.ClaimEvaluator{Client: client, Tools: tools}
		gapPlanner = llm.Planner{Client: client, Tools: tools}
	} else if o.detOnly {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"deterministic-only mode: LLM adapters disabled")
	} else if llmCfg.BaseURL != "" {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"llm configured but LLM_ENABLED is off")
	}

	snapOpts, err := buildSnapshotOptions(o)
	if err != nil {
		return nil, err
	}
	pipeline := recordPipeline{
		store:       store,
		source:      src,
		sourceIndex: srcIndex,

		repoPath:        absRepo,
		snapshotOptions: snapOpts,
		snapshotProduct: o.snapshot,
		vulnID:          o.vulnID,

		affectedResolver:  affected.GoResolver{Tool: goTool, Sources: srcIndex},
		rootCause:         rcResolver,
		rootCauseVerifier: &rootcause.Verifier{Source: srcIndex},
		builder:           builder,
		reviewers:         reviewers,
		evaluators:        conditionEvaluators,
		fallback:          fallbackEval,
		planner:           gapPlanner,
		llmClient:         llmClient,
		govulncheck:       gvRunner,
		negativeVerifier:  &goanalysis.Verifier{Source: srcIndex},

		reportDir: filepath.Join(o.caseDir, string(caseID)),
		tracker:   tracker.FileSink{Dir: filepath.Join(o.caseDir, string(caseID))},
		prior:     prior,

		corpus:     o.corpus,
		attributor: attributionResolver(o.attributionMaterials),
		intake:     &states.RecordIntake{},

		manualRC:  append(o.manualRC, parseRootCauses(o.rootCauseArgs)...),
		modelPath: o.exploitModel,
		allowExec: o.allowExec,
	}
	engine := workflow.New(store, pipeline.rootHandlers()...)
	// A recoverable primary failure must still reach candidate assessment and
	// composition; only the record-level FAILED state stops before them.
	engine.FailureState = domain.StateAssessRelatedRecords
	if err := engine.Run(ctx, c); err != nil {
		return c, fmt.Errorf("workflow: %w", err)
	}
	return c, nil
}

// requestedView is the CLI's one extraction of a case's publication projection.
// Every consumer renders the requested answer from it; no consumer re-derives a
// conclusion from the primary record.
type requestedView struct {
	View    finding.View
	Finding domain.RequestedFinding
}

// projectRequested re-admits the case's requested finding. A legacy case, a
// pending (never composed) case and a saved conclusion the current admission
// refuses all return an error: none of them may be rendered as a requested
// answer.
func projectRequested(c *domain.AnalysisCase) (requestedView, error) {
	if c == nil {
		return requestedView{}, fmt.Errorf("no analysis case was produced")
	}
	view, err := finding.Project(c)
	if err != nil {
		return requestedView{}, err
	}
	return requestedView{View: view, Finding: view.Requested}, nil
}

// decidingAssessment returns the record whose independent assessment grounds the
// requested answer: the first admitted witness behind a positive, otherwise the
// primary record. It never invents a record.
func (v requestedView) decidingAssessment() *domain.AnalysisCase {
	if len(v.View.Witnesses) > 0 {
		return v.View.Witnesses[0].Assessment
	}
	return v.View.Primary
}

// groundingRecord returns the record whose own verdict and falsifier explain the
// requested answer, or nil for a corpus-bounded negative: that negative rests on
// the candidate records and on the declared boundary, never on the primary's own
// verdict.
func (v requestedView) groundingRecord() *domain.AnalysisCase {
	if v.Finding.CorpusNegativeBasis != nil {
		return nil
	}
	return v.decidingAssessment()
}

// gapCodes renders typed gap causes as OWNER/CODE in producer order, without
// duplicates.
func gapCodes(gaps []domain.AnalysisGap) []string {
	var out []string
	seen := map[string]bool{}
	for _, gap := range gaps {
		code := string(gap.Owner) + "/" + string(gap.Code)
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

// projectedFailureCodes is the FAILED result's published causes. A decided or
// external answer may retain record-level diagnostics (an unrelated candidate
// failure does not veto a positive), but those are not the answer's failure
// codes and must not be published as such.
func projectedFailureCodes(f domain.FindingProfile) []string {
	if f.Outcome != domain.OutcomeFailed {
		return nil
	}
	return gapCodes(f.Gaps)
}

// projectedDiagnostics names the retained gap causes of a non-failed answer.
func projectedDiagnostics(f domain.FindingProfile) []string {
	if f.Outcome == domain.OutcomeFailed {
		return nil
	}
	return gapCodes(f.Gaps)
}

// projectedExternalFacts names the decision-changing facts behind an
// EXTERNAL_DEPENDENCY outcome.
func projectedExternalFacts(f domain.FindingProfile) []string {
	var out []string
	for _, dep := range f.ExternalDependencies {
		out = append(out, dep.MissingFact)
	}
	return out
}

// projectedCandidates lists the independently nominated discovery candidates in
// record-id order.
func projectedCandidates(c *domain.AnalysisCase) []string {
	if c == nil || c.RelatedDiscovery == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, candidate := range c.RelatedDiscovery.Candidates {
		id := candidate.Record.RecordID
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// projectedAttributions reports every directional CVE attribution attempt as
// "<id>=<admission>". A related-only attempt stays visible as such.
func projectedAttributions(c *domain.AnalysisCase) []string {
	if c == nil || len(c.Attributions) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Attributions))
	for _, attr := range c.Attributions {
		out = append(out, string(attr.ID)+"="+string(attr.Admission))
	}
	sort.Strings(out)
	return out
}

// projectedCorpusDigest pins the corpus the run enumerated: the declared basis
// digest when the answer rests on it, else the observed manifest digest.
func projectedCorpusDigest(c *domain.AnalysisCase, f domain.FindingProfile) string {
	if f.CorpusNegativeBasis != nil {
		return f.CorpusNegativeBasis.ObservedDigest
	}
	if c != nil && c.CorpusManifest != nil {
		return c.CorpusManifest.ObservedDigest
	}
	return ""
}

// buildLabel renders the build provenance of an admitted result.
func buildLabel(b domain.BuildContext) string {
	var parts []string
	switch {
	case b.GOOS != "" && b.GOARCH != "":
		parts = append(parts, b.GOOS+"/"+b.GOARCH)
	case b.GOOS != "":
		parts = append(parts, b.GOOS)
	case b.GOARCH != "":
		parts = append(parts, b.GOARCH)
	}
	if len(b.BuildTags) > 0 {
		parts = append(parts, "tags="+strings.Join(b.BuildTags, ","))
	} else {
		parts = append(parts, "tags=<none>")
	}
	// The analysed configuration is the operator's evidence that the right
	// program was measured, so cgo is always shown rather than implied.
	if b.CGOEnabled {
		parts = append(parts, "cgo=on")
	} else {
		parts = append(parts, "cgo=off")
	}
	if b.GoVersion != "" {
		parts = append(parts, b.GoVersion)
	}
	if b.ExternalCommitSHA != "" {
		parts = append(parts, b.ExternalCommitSHA)
	} else if b.Commit != "" {
		parts = append(parts, b.Commit)
	}
	return strings.Join(parts, " ")
}

// claimResults projects a record's condition results for the harness.
func claimResults(c *domain.AnalysisCase) map[string]string {
	out := map[string]string{}
	if c == nil {
		return out
	}
	for _, cl := range c.Claims {
		out[string(cl.ConditionID)] = string(cl.Result)
	}
	return out
}

// groundingClaim returns the falsifier, ground basis and evidence of the verdict's
// grounding claim on the deciding record. A record whose verdict names no
// condition contributes nothing.
func groundingClaim(c *domain.AnalysisCase) (falsifier, groundBasis string, evidenceIDs []string) {
	if c == nil || c.Verdict == nil || len(c.Verdict.ConditionIDs) == 0 {
		return "", "", nil
	}
	groundBasis = c.Verdict.GroundBasis
	for _, cl := range c.Claims {
		if cl.ConditionID != c.Verdict.ConditionIDs[0] {
			continue
		}
		falsifier = cl.Falsifier
		for _, id := range cl.EvidenceIDs {
			evidenceIDs = append(evidenceIDs, string(id))
		}
		break
	}
	return falsifier, groundBasis, evidenceIDs
}

// printCase renders one finished case and reports whether the command must exit
// nonzero. A FAILED requested assessment is reported as such — no verdict line —
// and only after the case id, state, failure codes and report path are printed.
func printCase(c *domain.AnalysisCase, caseDir string, lang ...string) error {
	isRU := len(lang) == 0 || lang[0] != "en"
	fmt.Printf("case: %s\n", c.ID)
	if c.TicketID != "" {
		fmt.Printf("ticket: %s\n", c.TicketID)
	}
	if c.TicketComponent != "" {
		fmt.Printf("component: %s\n", c.TicketComponent)
	}
	fmt.Printf("state: %s\n", c.Workflow.State)

	view, projectErr := projectRequested(c)
	var exit error
	claimsSource := c
	if projectErr == nil {
		claimsSource = view.decidingAssessment()
		exit = printRequestedFinding(view)
	} else {
		fmt.Printf("requested: none (%v)\n", projectErr)
		printLegacyVerdict(c)
		exit = exitErr(1, projectErr)
	}
	for _, cl := range claimsSource.Claims {
		if cl.ControlBasis != "" {
			fmt.Printf("control_basis: %s=%s\n", cl.ConditionID, cl.ControlBasis)
		}
	}
	if c.ContextualRisk != nil && (projectErr != nil || view.Finding.Outcome == domain.OutcomeDecided) {
		fmt.Printf("priority: %s (Contextual: %s, Score: %.1f, SLA: %s)\n",
			c.ContextualRisk.Priority, c.ContextualRisk.ContextualLevel, c.ContextualRisk.ContextualScore, c.ContextualRisk.SLA)
		if c.ContextualRisk.AdjustmentReason != "" {
			fmt.Printf("triage_reason: %s\n", c.ContextualRisk.AdjustmentReason)
		}
	}
	if projectErr == nil {
		printProjectedProfiles(c, view.Finding.FindingProfile)
	} else {
		printLegacyProfiles(c)
	}
	if len(c.Workflow.Timings) > 0 {
		var parts []string
		var total float64
		for _, k := range sortedKeys(c.Workflow.Timings) {
			total += c.Workflow.Timings[k]
			parts = append(parts, fmt.Sprintf("%s=%.1fs", k, c.Workflow.Timings[k]))
		}
		fmt.Printf("timings: %s | total=%.1fs llm_calls=%d\n",
			strings.Join(parts, " "), total, c.Workflow.Usage.LLMCalls)
	}
	repName := "report.md"
	if !isRU {
		repName = "report.en.md"
	}
	fmt.Printf("report: %s\n", filepath.Join(caseDir, string(c.ID), repName))
	if r := report.TrackerRationale(c); r != "" {
		if isRU {
			fmt.Printf("\n--- Резюме ---\n%s\n--------------\n", r)
		} else {
			fmt.Printf("\n--- Executive Summary ---\n%s\n-------------------------\n", r)
		}
	}
	return exit
}

// printRequestedFinding renders the authoritative requested answer. A FAILED
// result has no verdict line; an EXTERNAL_DEPENDENCY names the missing fact.
func printRequestedFinding(view requestedView) error {
	f := view.Finding
	fmt.Printf("requested: %s (%s, %s coverage)\n", f.RequestedID, f.RequestedKind, f.Coverage)
	fmt.Printf("assessment_outcome: %s\n", f.Outcome)
	for _, code := range projectedFailureCodes(f.FindingProfile) {
		fmt.Printf("failure_code: %s\n", code)
	}
	for _, code := range projectedDiagnostics(f.FindingProfile) {
		fmt.Printf("diagnostic: %s\n", code)
	}
	if f.Verdict != "" {
		fmt.Printf("verdict: %s\n", f.Verdict)
	}
	fmt.Printf("reason: %s\n", f.Reason)
	if f.ExploitabilityScope != "" {
		fmt.Printf("exploitability_scope: %s\n", f.ExploitabilityScope)
	}
	actual := "hypothetical profile"
	if f.IsTargetActual {
		actual = "actual profile"
	}
	fmt.Printf("profile: %s (%s, build %s)\n", f.Profile, actual, buildLabel(f.Build))
	for _, origin := range f.ProofOrigins {
		entries := "none"
		if len(origin.EntryRefs) > 0 {
			var refs []string
			for _, ref := range origin.EntryRefs {
				refs = append(refs, fmt.Sprintf("%d", ref))
			}
			entries = strings.Join(refs, ",")
		}
		attribution := origin.AttributionID
		if attribution == "" {
			attribution = "own identity"
		}
		mechanism := origin.MechanismID
		if mechanism == "" {
			mechanism = "none"
		}
		fmt.Printf("proof_origin: %s %s (entries: %s; mechanism: %s; attribution: %s; profile %s; build %s)\n",
			origin.Record.RecordID, origin.Record.DocumentDigest, entries, mechanism,
			attribution, origin.Profile, buildLabel(origin.Build))
	}
	if f.CorpusNegativeBasis != nil {
		fmt.Printf("corpus_boundary: %s\n", f.CorpusNegativeBasis.BoundaryStatement)
	}
	for _, dep := range f.ExternalDependencies {
		fmt.Printf("external_dependency: %s (obligation %s; resolves with %s)\n",
			dep.MissingFact, dep.AffectedObligation, dep.ResolvingEvidence)
	}
	for _, limitation := range f.Limitations {
		fmt.Printf("limitation: %s\n", limitation)
	}
	printAssessmentAxes(view.View.Axes)
	if f.Outcome != domain.OutcomeFailed {
		return nil
	}
	codes := projectedFailureCodes(f.FindingProfile)
	message := "requested assessment FAILED; no verdict was published"
	if len(codes) > 0 {
		message += ": " + strings.Join(codes, ", ")
	}
	return exitErr(1, fmt.Errorf("%s", message))
}

// printAssessmentAxes appends the derived two-question projection to the CLI
// output. Existing keys are unchanged; a scoped positive keeps its boundary on
// the same line, so "exploitable=TRUE" is never read as deployment-wide.
func printAssessmentAxes(axes finding.AssessmentAxes) {
	for _, row := range axes.Requested {
		printAssessmentAxis("requested", row)
	}
	for _, row := range axes.Records {
		printAssessmentAxis("record", row)
	}
}

func printAssessmentAxis(kind string, row finding.AxisRow) {
	scope := string(row.ExploitabilityScope)
	if scope == "" {
		scope = "<none>"
	}
	line := fmt.Sprintf(
		"assessment_axis: subject_kind=%s subject=%s assessment_id=%s profile=%s target_actual=%t build=%q vulnerable_code_in_build=%s exploitable=%s exploitability_scope=%s",
		kind, row.SubjectID, row.AssessmentID, row.Profile, row.IsTargetActual,
		buildLabel(row.Build), row.VulnerableCodeInBuild, row.Exploitable, scope)
	if row.Record != nil {
		line += " record=" + row.Record.RecordID
	}
	fmt.Println(line)
}

// printProjectedProfiles renders the actual profile result from the projection,
// so a hypothetical profile can never be read as the deployment's answer.
func printProjectedProfiles(c *domain.AnalysisCase, f domain.FindingProfile) {
	if c.DetectedPerimeter != "" {
		fmt.Printf("perimeter: %s\n", c.DetectedPerimeter)
	}
	verdict := string(f.Verdict)
	if verdict == "" {
		verdict = "no verdict"
	}
	scope := ""
	if f.ExploitabilityScope != "" {
		scope = fmt.Sprintf(", Scope: %s", f.ExploitabilityScope)
	}
	fmt.Printf("target_profile: %s (%s, Verdict: %s%s)\n", f.Profile, f.Outcome, verdict, scope)
}

// printLegacyVerdict and printLegacyProfiles preserve the historical rendering
// for a case with no requested-finding projection. Such a case is not
// publishable; the CLI has already reported the refusal.
func printLegacyVerdict(c *domain.AnalysisCase) {
	if c.Verdict == nil {
		return
	}
	fmt.Printf("verdict: %s\nreason: %s\n", c.Verdict.Verdict, c.Verdict.Reason)
	if c.Verdict.ExploitabilityScope != "" {
		fmt.Printf("exploitability_scope: %s\n", c.Verdict.ExploitabilityScope)
	}
}

func printLegacyProfiles(c *domain.AnalysisCase) {
	if len(c.Profiles) == 0 {
		return
	}
	if c.DetectedPerimeter != "" {
		fmt.Printf("perimeter: %s\n", c.DetectedPerimeter)
	}
	for _, p := range c.Profiles {
		if p.IsTargetActual {
			scope := ""
			if p.ExploitabilityScope != "" {
				scope = fmt.Sprintf(", Scope: %s", p.ExploitabilityScope)
			}
			fmt.Printf("target_profile: %s (Verdict: %s, Priority: %s%s)\n", p.Profile, p.Verdict, p.Priority, scope)
			break
		}
	}
}

type llmCompleterAdapter struct {
	client *llm.Client
	role   llm.ModelRole
}

func (a llmCompleterAdapter) Complete(ctx context.Context, system, user string) (string, error) {
	content, _, err := a.client.Complete(ctx, a.role, system, user)
	return content, err
}

// loadLLMEnv loads the LLM dotenv file: explicit --llm-env wins, else it
// probes .env in the working directory and the analyzed repo.
// Missing files are ignored; malformed lines are skipped. Guarded by
// llmEnvMu: concurrent os.Setenv from parallel scan workers would race.
var (
	llmEnvMu     sync.Mutex
	llmEnvLoaded = make(map[string]bool)
)

func loadLLMEnv(explicit, repo string) {
	llmEnvMu.Lock()
	defer llmEnvMu.Unlock()

	candidates := []string{explicit}
	if explicit == "" {
		candidates = []string{".env"}
		if repo != "" {
			candidates = append(candidates, filepath.Join(repo, ".env"))
		}
	}
	for _, p := range candidates {
		if p == "" || llmEnvLoaded[p] {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = llm.LoadDotEnv(p)
		llmEnvLoaded[p] = true
		return
	}
}

func sanitizeID(id string) string {
	return strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(id)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// resolveToolchain picks the analysis toolchain for this run. The release
// binary's embedded build info wins (it is the ground truth of what
// compiled the artifact), then --release-go-version; empty means local.
func resolveToolchain(ctx context.Context, o analyzeOpts) (toolchain.Toolchain, []string) {
	want := ""
	if o.binary != "" {
		if v, err := repository.BinaryGoVersion(ctx, o.binary); err == nil {
			want = v
		}
	}
	if want == "" {
		want = o.releaseGo
	}
	return toolchain.Resolve(ctx, want)
}

// parseRootCauses accepts "pkg/path.Symbol" entries; the last dot separates
// the symbol from its package path.
func parseRootCauses(flags []string) []domain.RootCause {
	var out []domain.RootCause
	for _, f := range flags {
		for _, item := range strings.Split(f, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			i := strings.LastIndex(item, ".")
			if i <= 0 {
				continue
			}
			out = append(out, domain.RootCause{
				Package:   item[:i],
				Symbol:    item[i+1:],
				Role:      domain.RootCauseSink,
				Mechanism: "provided manually via --root-cause",
			})
		}
	}
	return out
}

// runScan enumerates the module graph, queries OSV for every dependency
// module, and deep-analyzes each discovered advisory.
func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	maxVulns := fs.Int("max-vulns", 50, "cap on advisories to deep-analyze")
	if err := fs.Parse(args); err != nil {
		return err
	}
 if o.fixSourceCaptures!="" {var err error;o.sourceCaptures,err=rootcause.LoadSourceCaptures(o.fixSourceCaptures);if err!=nil{return fmt.Errorf("fix-source captures: %w",err)}}
	if err := validateCGOFlag(o.cgo); err != nil {
		return err
	}
	if o.repo == "" {
		usage()
	}
	var err error
	if o.kb, err = loadKnowledgeBase(o.knowledge); err != nil {
		return err
	}
	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()
	if err := resolveAdvisorySources(ctx, &o); err != nil {
		return err
	}

	wtCleanup, err := prepareReleaseWorktree(ctx, &o)
	if err != nil {
		return err
	}
	if wtCleanup != nil {
		defer func() {
			// Fail-closed cleanup never mutates .git/worktrees unlocked;
			// a skipped removal leaves only a stale registration for
			// git's own prune. Record the named error on stderr.
			if cerr := wtCleanup(); cerr != nil {
				fmt.Fprintf(os.Stderr, "worktree cleanup: %v\n", cerr)
			}
		}()
	}

	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return err
	}

	// Resolve the single build context before any package load: the shared
	// index, go-list tool and govulncheck runner are all constructed from the
	// resolved snapshot, and the module listing below runs through the
	// affected tool under that same snapshot instead of a raw `go list` with
	// an unrelated environment.
	snap, mods, err := prepareScanShared(ctx, &o, absRepo)
	if err != nil {
		return err
	}
	var modulePaths []string
	for _, m := range mods {
		if m.Main {
			continue
		}
		modulePaths = append(modulePaths, m.Path)
	}
	fmt.Printf("modules: %d\n", len(modulePaths))

	var vulnIDs []string
	for _, m := range modulePaths {
		ids, err := vulnerability.QueryOSV(ctx, o.osvURL, m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "osv query %s: %v\n", m, err)
			continue
		}
		vulnIDs = dedupeAppend(vulnIDs, ids)
	}
	if len(vulnIDs) > *maxVulns {
		vulnIDs = vulnIDs[:*maxVulns]
	}
	fmt.Printf("advisories found: %d\n", len(vulnIDs))

	// Cheap deterministic pre-filter: resolve affectedness without the
	// full engine. Deterministically-not-affected advisories are recorded
	// and skipped; survivors get the full pipeline.
	resolver := affected.GoResolver{Tool: o.goTool}
	src := vulnerability.OSVSource{BaseURL: o.osvURL}

	var rows []scanRow
	var survivors []string
	for _, id := range vulnIDs {
		v, err := src.Get(ctx, id)
		if err != nil {
			rows = append(rows, scanRow{ID: id, State: "ERROR", Reason: "advisory fetch: " + err.Error()})
			continue
		}
		res, resEvidence, err := resolver.Resolve(ctx, *v, snap)
		if err == nil {
			// The prefilter is the same verdict evaluator the pipeline
			// uses: an advisory is skipped only when that evaluation
			// returns NOT_AFFECTED from admitted evidence. A private or
			// host-default negative stays a survivor. The prefilter never
			// grounds CVE closure: it only decides which advisories skip the
			// full pipeline.
			vr := scanPrefilter(snap, res, resEvidence)
			if vr.Verdict == domain.VerdictNotAffected {
				rows = append(rows, scanRow{ID: id, State: "FILTERED", Verdict: "NOT_AFFECTED", Priority: "DISMISSED",
					Reason: vr.Reason})
				fmt.Printf("%-18s NOT_AFFECTED [DISMISSED] (prefilter)\n", id)
				continue
			}
		}
		survivors = append(survivors, id)
	}

	// Deep-analyze survivors in parallel: the shared index/tool/runner are
	// mutex/once-guarded, and each case keeps its own evidence and budget.
	loadLLMEnv(o.llmEnv, absRepo) // resolved once, before workers read env
	const workers = 4
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range survivors {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			co := o
			co.vulnID = id
			c, err := analyzeCase(ctx, co)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", id, err)
				rows = append(rows, scanRow{ID: id, State: "ERROR", Reason: err.Error()})
				return
			}
			r := scanRowFromCase(id, c, nil)
			prioStr := ""
			if r.Priority != "" {
				prioStr = fmt.Sprintf(" [%s]", r.Priority)
			}
			rows = append(rows, r)
			var tm string
			var total float64
			for _, sec := range c.Workflow.Timings {
				total += sec
			}
			if total > 0 {
				tm = fmt.Sprintf(" (%.0fs, %d llm calls)", total, c.Workflow.Usage.LLMCalls)
			}
			fmt.Printf("%-18s %s%s %s%s\n", id, r.display(), prioStr, r.Reason, tm)
		}(id)
	}
	wg.Wait()
	b, _ := json.MarshalIndent(rows, "", "  ")
	out := filepath.Join(o.caseDir, "scan.json")
	if err := os.MkdirAll(o.caseDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("scan report: %s\n", out)
	return nil
}

// prepareScanShared resolves the scan's one build context before any package
// load and wires the shared resources from it in dependency order:
// toolchain → snapshot options → snapshot → index/tool/runner → module
// listing through the affected tool under the resolved snapshot.
func prepareScanShared(ctx context.Context, o *analyzeOpts, absRepo string) (domain.ProductSnapshot, []affected.Module, error) {
	o.toolchain, o.tcLims = resolveToolchain(ctx, *o)
	snapOpts, err := buildSnapshotOptions(*o)
	if err != nil {
		return domain.ProductSnapshot{}, nil, err
	}
	snap, err := repository.Service{}.Snapshot(ctx, absRepo, snapOpts)
	if err != nil {
		return domain.ProductSnapshot{}, nil, fmt.Errorf("snapshot: %w", err)
	}
	o.snapshot = &snap
	o.goTool = affected.CachingTool(affected.ExecGoTool{
		Bin: o.toolchain.GoBin, Env: o.toolchain.Env, Version: o.toolchain.Version,
	})
	o.gvRunner = goanalysis.CachingRunner(goanalysis.ExecRunner{Env: o.toolchain.Env})
	o.srcIndex = &goanalysis.Index{
		Dir:   absRepo,
		Env:   o.toolchain.Env,
		KB:    o.kb,
		Build: snap,
	}
	raw, _, err := o.goTool.ListModules(ctx, absRepo, snap)
	if err != nil {
		return domain.ProductSnapshot{}, nil, fmt.Errorf("list modules: %w", err)
	}
	mods, err := affected.DecodeModules(raw)
	if err != nil {
		return domain.ProductSnapshot{}, nil, fmt.Errorf("list modules: %w", err)
	}
	return snap, mods, nil
}

// dedupeAppend adds ids not already present, preserving order.
func dedupeAppend(dst, ids []string) []string {
	seen := map[string]bool{}
	for _, id := range dst {
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			dst = append(dst, id)
		}
	}
	return dst
}

// scanPrefilter evaluates the resolved affected evidence through the common
// verdict evaluator. The scan removes an advisory from the deep pipeline only
// when that evaluation returns NOT_AFFECTED; there is no second,
// prefilter-specific negative rule that could admit evidence the evaluator
// refuses.
func scanPrefilter(snap domain.ProductSnapshot, res domain.AffectedResult, evidence []domain.Evidence) domain.VerdictResult {
	return evaluator.VerdictEvaluator{}.Evaluate(evaluator.VerdictInput{
		Product:  snap,
		Affected: res,
		Evidence: evidence,
	})
}

// scanRow is one scan result row. Its conclusion comes from the requested-finding
// projection, never from the primary record's verdict.
type scanRow struct {
	ID           string   `json:"id"`
	State        string   `json:"state"`
	Outcome      string   `json:"assessment_outcome,omitempty"`
	Verdict      string   `json:"verdict,omitempty"`
	FailureCodes []string `json:"failure_codes,omitempty"`
	ProofOrigin  string   `json:"proof_origin,omitempty"`
	Priority     string   `json:"priority,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// scanRowFromCase classifies one deep-analysed advisory from its requested
// projection. A refused projection is an execution error row, never a verdict; a
// FAILED outcome is a result row with no verdict and its typed failure codes.
func scanRowFromCase(id string, c *domain.AnalysisCase, runErr error) scanRow {
	if runErr != nil {
		return scanRow{ID: id, State: "ERROR", Reason: runErr.Error()}
	}
	row := scanRow{ID: id}
	if c != nil {
		row.State = string(c.Workflow.State)
	}
	view, err := projectRequested(c)
	if err != nil {
		return scanRow{ID: id, State: "ERROR", Outcome: "UNPUBLISHABLE", Reason: "requested finding: " + err.Error()}
	}
	f := view.Finding
	row.Outcome = string(f.Outcome)
	row.Verdict = string(f.Verdict)
	row.Reason = f.Reason
	row.FailureCodes = projectedFailureCodes(f.FindingProfile)
	if len(f.ProofOrigins) > 0 {
		row.ProofOrigin = f.ProofOrigins[0].Record.RecordID
	}
	// A failure or an external dependency must never inherit a risk
	// disposition: only an earned decision carries one.
	if c != nil && f.Outcome == domain.OutcomeDecided && c.ContextualRisk != nil {
		row.Priority = string(c.ContextualRisk.Priority)
	}
	return row
}

// display renders the row's classification for the progress stream.
func (r scanRow) display() string {
	parts := []string{r.Outcome}
	if r.Verdict != "" {
		parts = append(parts, r.Verdict)
	}
	out := strings.Join(parts, " ")
	if len(r.FailureCodes) > 0 {
		out += " " + strings.Join(r.FailureCodes, ",")
	}
	return out
}

func sortedKeys(m map[string]float64) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
