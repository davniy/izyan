package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/llm"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
	pbvuln "github.com/fedorovmv/izyan/internal/productb/vulnerability"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// cliExitError carries the process exit code a CLI error must produce.
// main() maps it via errors.As; plain errors keep exit code 1.
type cliExitError struct {
	code int
	err  error
}

func (e *cliExitError) Error() string { return e.err.Error() }
func (e *cliExitError) Unwrap() error { return e.err }

func exitErr(code int, err error) error { return &cliExitError{code: code, err: err} }

const triageUsage = `usage:
  izyan triage --input <finding.json|findings.jsonl|-> --out <directory> [options]
  izyan triage --ticket <ticket.txt|tickets.json[.jsonl]|-> --config <triage-site.yaml> --out <directory> [options]
  izyan triage --replay-run <run-directory> --out <directory> [--fail-on <policy>]
  izyan triage --record-decision <run-directory> --actor <identity> [--answer variable=value] [--decision accept|reject] [--projection-hash <presented-hash>] [--reason <comment>]

  LLM-first triage for CI. Input, replay and human review modes:

  --input  consumes schema-validated finding.v1 records (compatibility
           transport): each finding names its repository and revision and
           gets an isolated agent run over a read-only snapshot, a fact
           gate over the cited evidence and a decision package that carries
           the model judgment, the proposed human action, the derived
           support and the machine disposition as separate axes; the
           machine automation outcome is part of that machine disposition.
           The agent verdict is never rewritten by deterministic code, and
           a triage assessment is not an authoritative verdict of
           'izyan analyze'.

  --ticket consumes generic intake — plain text, a JSON object, a JSON
           array or JSONL, file or stdin — with no tracker assumptions.
           Stage 0 resolves intake fields, the catalog source, the ref,
           materializes an immutable snapshot, freezes the advisory and
           collects material/toolchain facts before the same bounded
           agent run. A triage-site.v1 --config is required: it defines
           the admitted sources, release policies, advisory freeze and
           budgets. Ambiguity is a limitation or a technical error —
           the tool never asks questions.

  --replay-run re-renders one recorded run directory (input.json,
  snapshot.json, raw-agent.json, assessment.json): it verifies the
  recorded hashes against the snapshot as it exists now, re-runs the
  fact gate and report composition and writes a NEW report directory
  with a replay.json (rerender_of) link. No LLM call and no network
  access; the source run directory is never modified. LLM/budget
  flags do not apply to replay.

  --record-decision appends one person's Accept or Reject of the exact
  proposal delivered in an existing run directory. It reads
  decision.json, binds the record to that package's canonical hash and
  writes an immutable human-decisions/<record-id>.json under the
  collection lock. It needs no --out, model credentials or network
  access and never rewrites decision.json, decision.md, the assessment,
  proofs, VEX or policy material. A person's decision is not a machine
  verdict, an admitted proof, an automatic reduction or Product A
  authority. Exit 0 after the record is persisted; exit 2 on invalid
  input, a missing/foreign package or a persistence failure.

  Live triage and replay never require an external baseline or ground
  truth. To compare a saved run with external controls offline, use
  izyan eval triage --run <run-directory> --baseline <file> --out <dir>.

options:
  --ticket <path|->       generic intake: text, JSON object/array or JSONL;
                          requires --config
  --input <path|->        finding.v1 JSON/JSONL input file, or '-' for stdin
  --replay-run <dir>      re-render a recorded run directory; mutually exclusive with --input/--ticket.
                          A proof-bearing legacy run that persisted
                          condition-catalog.json but not catalog-binding.json
                          refuses by default — the catalog hash pin is
                          unverifiable, so drift since the run would be
                          silently accepted.
  --replay-legacy-unbound opt-in for that legacy case: replay proceeds under
                          a derived pin (catalog self-hash) and the limitation
                          is recorded in replay.json + the audit trail
  --record-decision <dir> record a human Accept/Reject of the exact proposal
                          delivered in this run directory; mutually exclusive
                          with --input/--ticket/--replay-run and requires no
                          --out or LLM configuration
  --decision <accept|reject>  the person's decision (with --record-decision)
  --actor <identity>      who made the decision; required and nonempty
  --reason <text>         optional comment; no technical narrative required
  --answer <var=value>    captured environment answer; repeat for at most two variables
  --projection-hash <hash> bind Accept/Reject to the projection shown by answer/review
                          mode; required for a later environment decision without
                          --answer. Copy the emitted command; a changed selection
                          is rejected. One-step answers+decision must name all answers.
  --config <path>         triage-site.v1 site config (YAML or JSON): admitted
                          sources, policies and budgets; required for --ticket;
                          budget flags override config budgets
  --investigation-inputs <manifest>
                          investigation-inputs.v1 captured advisory/fix set
                          exposed to the investigator for both --input and
                          --ticket; referenced files resolve relative to the
                          manifest and every declared digest is verified.
                          Captured bytes are archived by digest under the run
                          directory and read through the bounded read_material
                          tool; they are always untrusted data
  --osv-url <url>         override the OSV API base for advisory resolution
                          (--ticket; only with freeze off and an allowed domain)
  --model <model>         override LLM_ANALYZE_MODEL/LLM_BUILD_MODEL for this run
  --llm-env <path>        dotenv file with LLM_* variables; loaded only for this run
  --timeout <sec>         per-finding agent timeout (default 600)
  --max-steps <n>         agent step budget for the INITIAL exchange loop per
                          finding (default 8) — not the whole run: the run's
                          single step counter additionally reserves one
                          finalization round plus the bounded feedback
                          repair turns (see triage.totalStepBudget), so a
                          run's total model exchanges can exceed --max-steps
                          and are still hard-capped
  --max-tool-calls <n>    read-only tool call budget per finding (default 64)
  --max-source-bytes <n>  source read budget per finding in bytes (default 1048576)
  --fail-on <policy>      CI policy threshold, repeatable:
                          unchanged|low-support|conditional|unverified-disposition.
                          With no flag, policy.fail_on from --config applies;
                          otherwise no threshold. Policy evaluation never
                          changes the decision package.
  policy.stability_retries (config)  extra agent runs per finding on the
                          same frozen inputs; all attempts are persisted in
                          stability.json and audited. Provenance drift
                          between attempts is a technical error
                          (policy.on_drift: error); semantic instability
                          demotes the package to UNCHANGED with reduced
                          support — no attempt is ever preferred.
  --allow-external-artifacts  allow target.sbom/target.binary paths outside the
                          source repository into the snapshot (off by default:
                          a finding could otherwise exfiltrate arbitrary local
                          files into the agent transcript and artifacts)
  --det-tools <on|off>    expose the deterministic evidence tools (dependency
                          graph, symbols, callers, govulncheck, guards) to the
                          agent (default on; a per-finding session failure
                          degrades to off for that finding, never aborts)
  --vex-projection        write the optional triage-scoped VEX projection as
                          vex.json next to decision.json (off by default;
                          non-authoritative, never changes the decision or
                          the exit code; inadmissible packages record a denial
                          in the audit log)
          The falsifier-proof final gate is the *admission check*: when a
          decision cites a mandatory condition the run must carry a
          VERIFIED falsifier proof or the run exits non-zero and names
          the failed check. The izyan-heldout-gate binary is a different,
          offline reporter tool — it emits held-out metric reports; it is
          not the admission-check path and its exit code does not enforce
          case admission.


exit codes: 0 all findings produced decision packages that pass policy, or
the human decision was persisted; 1 a decision package hit a --fail-on
threshold; 2 technical failure (bad input, unresolvable source/ref, snapshot
drift, stability provenance drift, snapshot/agent/artifact or composition
error, invalid/hostile human-decision input or a failed review-record write).
One finding's failure never stops the batch.
`

// triageDefaultMaxTokens is the response-token budget applied to the triage
// run when neither budgets.max_output_tokens nor an explicit LLM_MAX_TOKENS
// sets one: the inherited 4000-token default truncates assessment replies
// (finish_reason=length), which surfaces as a technical failure instead of
// a decision package.
const triageDefaultMaxTokens = 16000

// runTriage executes the agent triage pipeline per finding:
// snapshot → read-only tools → agent → fact gate → decision package →
// artifacts. One failed finding never stops the others: its technical error
// is recorded in <out>/<finding-id>/error.json together with the partial
// raw-agent.json transcript and audit trail, and reported as exit code 2.
// Output never lands inside a finding's source repository.
func runTriage(args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, triageUsage) }
	// External control comparison is offline-only. Keep the old live flag
	// name from decaying into a generic "flag not defined" error: name the
	// evaluation command instead of silently ignoring a comparison the
	// operator asked for.
	for _, arg := range args {
		if arg == "--baseline" || arg == "-baseline" ||
			strings.HasPrefix(arg, "--baseline=") || strings.HasPrefix(arg, "-baseline=") {
			return exitErr(triage.ExitCodeError, errors.New(
				"triage: --baseline is offline evaluation only; run `izyan eval triage --run <run-directory> --baseline <triage-baselines.json> --out <directory>`"))
		}
	}
	var input, ticket, outDir, model, llmEnv, replayDir, detTools, siteConfig, osvURL, condCatalogPath, condCatalogHash, investigationInputs string
	var recordDecisionDir, decisionValue, actor, reason, presentedProjectionHash string
	var answers triageAnswerFlags
	var timeoutSec, maxSteps, maxToolCalls int
	var maxSourceBytes int64
	var allowExternal, vexProjection, legacyUnbound bool
	var failOnFlag stringList
	fs.StringVar(&input, "input", "", "finding.v1 JSON/JSONL input file, or '-' for stdin (compatibility transport)")
	fs.StringVar(&ticket, "ticket", "", "generic ticket text/JSON/JSONL file, or '-' for stdin (requires --config)")
	fs.StringVar(&outDir, "out", "", "output directory (required); must be outside every source repository")
	fs.StringVar(&replayDir, "replay-run", "", "re-render a recorded run directory; mutually exclusive with --input/--ticket")
	fs.StringVar(&recordDecisionDir, "record-decision", "", "record a human accept/reject of the exact proposal delivered in this run directory; no --out or LLM configuration required")
	fs.StringVar(&decisionValue, "decision", "", "the person's decision for --record-decision: accept|reject")
	fs.StringVar(&actor, "actor", "", "who made the human decision (required with --record-decision)")
	fs.StringVar(&reason, "reason", "", "optional comment on the human decision")
	fs.Var(&answers, "answer", "captured environment variable=value (at most two distinct variables)")
	fs.StringVar(&presentedProjectionHash, "projection-hash", "", "expected projection from the presented review; required for a subsequent environment decision")
	fs.StringVar(&model, "model", "", "override LLM_ANALYZE_MODEL and LLM_BUILD_MODEL for this run")
	fs.StringVar(&llmEnv, "llm-env", "", "dotenv file with LLM_* variables; loaded only for this run")
	fs.BoolVar(&allowExternal, "allow-external-artifacts", false, "allow target.sbom/target.binary outside the source repository into the snapshot (off by default; a finding can then point at arbitrary local files)")
	fs.IntVar(&timeoutSec, "timeout", 600, "per-finding agent timeout in seconds")
	fs.IntVar(&maxSteps, "max-steps", 8, "agent step budget for the initial exchange loop per finding (the run's total counter adds finalization + feedback turns on top)")
	fs.IntVar(&maxToolCalls, "max-tool-calls", 64, "read-only tool call budget per finding")
	fs.Int64Var(&maxSourceBytes, "max-source-bytes", 1<<20, "source read budget per finding in bytes")
	fs.StringVar(&siteConfig, "config", "", "triage-site.v1 site config (YAML or JSON); its budgets apply unless the matching flag is set")
	fs.StringVar(&investigationInputs, "investigation-inputs", "", "investigation-inputs.v1 manifest of captured advisory records and exact fix locators supplied to the investigator (both --input and --ticket)")
	fs.StringVar(&osvURL, "osv-url", "", "override OSV API base for --ticket advisory resolution")
	fs.Var(&failOnFlag, "fail-on", "CI policy threshold, repeatable: unchanged|low-support|conditional|unverified-disposition (default: policy.fail_on from --config)")
	fs.StringVar(&detTools, "det-tools", "on", "deterministic evidence tools for the agent: on|off (default on; failures degrade per finding, never abort)")
	fs.BoolVar(&vexProjection, "vex-projection", false, "write the optional triage-scoped VEX projection (vex.json) next to decision.json; off by default")
	fs.StringVar(&condCatalogPath, "condition-catalog", "", "condition-catalog.v1 JSON binding the advisory's mandatory conditions for falsifier admission; with --condition-catalog-hash it is required for the falsifier path to admit any proposal")
	fs.StringVar(&condCatalogHash, "condition-catalog-hash", "", "expected SHA-256 pin for --condition-catalog; required together with --condition-catalog")
	fs.BoolVar(&legacyUnbound, "replay-legacy-unbound", false, "--replay-run only: opt-in for a proof-bearing legacy run that persisted condition-catalog.json but not catalog-binding.json — replay proceeds under the derived-pin limitation instead of refusing")
	if err := fs.Parse(args); err != nil {
		return exitErr(triage.ExitCodeError, err)
	}
	if fs.NArg() != 0 {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: unexpected positional arguments: %s", strings.Join(fs.Args(), " ")))
	}
	// Record mode is a standalone human action: it runs before every LLM,
	// site-config, output and analysis check and never performs a model or
	// network call.
	if recordDecisionDir != "" {
		if input != "" || ticket != "" || replayDir != "" {
			return exitErr(triage.ExitCodeError, errors.New("triage: --record-decision is mutually exclusive with --input, --ticket and --replay-run"))
		}
		var unrelated []string
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "record-decision", "decision", "actor", "reason", "answer", "projection-hash":
			default:
				unrelated = append(unrelated, "--"+f.Name)
			}
		})
		if len(unrelated) > 0 {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: %s does not apply to --record-decision", strings.Join(unrelated, ", ")))
		}
		return runTriageReview(recordDecisionDir, decisionValue, actor, reason, presentedProjectionHash, answers)
	}
	if decisionValue != "" || actor != "" || reason != "" || presentedProjectionHash != "" || len(answers) != 0 {
		return exitErr(triage.ExitCodeError, errors.New("triage: --decision, --actor, --reason, --answer and --projection-hash require --record-decision"))
	}
	if input != "" && ticket != "" {
		return exitErr(triage.ExitCodeError, errors.New("triage: --input and --ticket are mutually exclusive"))
	}
	if replayDir != "" && (input != "" || ticket != "") {
		return exitErr(triage.ExitCodeError, errors.New("triage: --input/--ticket and --replay-run are mutually exclusive"))
	}
	if siteConfig != "" && replayDir != "" {
		return exitErr(triage.ExitCodeError, errors.New("triage: --config does not apply to --replay-run"))
	}
	if investigationInputs != "" && replayDir != "" {
		return exitErr(triage.ExitCodeError, errors.New("triage: --investigation-inputs does not apply to --replay-run; replay reads the captured material archived with the run"))
	}
	if ticket != "" && siteConfig == "" {
		return exitErr(triage.ExitCodeError, errors.New("triage: --config is required with --ticket"))
	}
	if (input == "" && ticket == "" && replayDir == "") || outDir == "" {
		fs.Usage()
		missing := "--input, --ticket or --replay-run"
		if outDir == "" {
			missing = "--out"
		}
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: %s is required", missing))
	}
	switch detTools {
	case "on", "off":
	default:
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --det-tools must be \"on\" or \"off\", got %q", detTools))
	}

	// --investigation-inputs is strict and resolved before any agent work:
	// duplicate identities, wrong digests/sizes, undeclared fix ownership,
	// traversal and symlink escapes fail the operator input, never a run.
	var investigation triage.InvestigationInputs
	if investigationInputs != "" {
		loaded, ierr := triage.LoadInvestigationInputs(investigationInputs)
		if ierr != nil {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --investigation-inputs: %w", ierr))
		}
		investigation = loaded
	}

	// --config is strict: an unreadable, malformed or invalid triage-site.v1
	// document is a configuration error (exit 2) before any LLM traffic. Its
	// budget block supplies the agent limits the operator did not pin with
	// an explicit flag.
	var siteBudgets triage.BudgetConfig
	var siteCfg triage.SiteConfig
	var siteCfgHash string
	if siteConfig != "" {
		loaded, hash, err := triage.LoadSiteConfig(siteConfig)
		if err != nil {
			return exitErr(triage.ExitCodeError, err)
		}
		siteCfg, siteBudgets, siteCfgHash = loaded, loaded.Budgets, hash
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "timeout":
				siteBudgets.TimeoutSeconds = 0
			case "max-steps":
				siteBudgets.MaxLLMSteps = 0
			case "max-tool-calls":
				siteBudgets.MaxToolCalls = 0
			case "max-source-bytes":
				siteBudgets.MaxSourceBytes = 0
			}
		})
	}
	// --fail-on flags replace policy.fail_on wholesale (deterministic
	// precedence, never a union); without flags the config list is the
	// default. Unknown values are a configuration error, never ignored.
	var failOn []triage.FailOn
	failOnRaw := []string(failOnFlag)
	if len(failOnRaw) == 0 {
		failOnRaw = siteCfg.Policy.FailOn
	}
	for _, raw := range failOnRaw {
		f, err := triage.ParseFailOn(raw)
		if err != nil {
			return exitErr(triage.ExitCodeError, err)
		}
		failOn = append(failOn, f)
	}

	absOut, err := canonicalOutDir(outDir)
	if err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --out: %w", err))
	}

	if replayDir != "" && (condCatalogPath != "" || condCatalogHash != "") {
		return exitErr(triage.ExitCodeError, errors.New("triage: --condition-catalog flags do not apply to --replay-run"))
	}
	// --condition-catalog and --condition-catalog-hash are a pair: the
	// catalog is the run-pinned admission contract for the falsifier path,
	// and the hash pins which catalog the run expects. Both together are a
	// hard requirement for that path; neither alone is a meaningful pin.
	var catalog *triage.ConditionCatalog
	if condCatalogPath != "" || condCatalogHash != "" {
		if condCatalogPath == "" || condCatalogHash == "" {
			return exitErr(triage.ExitCodeError, errors.New("triage: --condition-catalog and --condition-catalog-hash are required together"))
		}
		catRaw, cerr := os.ReadFile(condCatalogPath)
		if cerr != nil {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: read --condition-catalog: %w", cerr))
		}
		c, cerr := triage.DecodeConditionCatalog(catRaw)
		if cerr != nil {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: %w", cerr))
		}
		if !strings.EqualFold(c.CatalogHash, condCatalogHash) {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --condition-catalog-hash %q does not match the loaded catalog hash %q", condCatalogHash, c.CatalogHash))
		}
		catalog = &c
	}
	if replayDir != "" {
		return runTriageReplay(replayDir, absOut, failOn, vexProjection, legacyUnbound)
	}

	// Only an explicit --llm-env is loaded here; the implicit .env probing
	// of loadLLMEnv stays scoped to analyze/scan.
	if llmEnv != "" {
		if err := llm.LoadDotEnv(llmEnv); err != nil {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --llm-env: %w", err))
		}
	}
	cfg := llm.ConfigFromEnv()
	if model != "" {
		cfg.AnalyzeModel, cfg.BuildModel = model, model
	}
	// Output budget: an explicit positive LLM_MAX_TOKENS wins, then
	// budgets.max_output_tokens, then the triage default — the inherited
	// 4000-token floor truncates assessments into technical failures.
	if v, verr := strconv.Atoi(os.Getenv("LLM_MAX_TOKENS")); verr != nil || v <= 0 {
		cfg.MaxTokens = triageDefaultMaxTokens
		if siteBudgets.MaxOutputTokens > 0 {
			cfg.MaxTokens = siteBudgets.MaxOutputTokens
		}
	}
	if !cfg.Enabled {
		return exitErr(triage.ExitCodeError, errors.New("triage: LLM is not enabled (LLM_ENABLED is not truthy); set LLM_* variables or pass --llm-env"))
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return exitErr(triage.ExitCodeError, errors.New("triage: LLM_BASE_URL is empty"))
	}
	client := llm.NewClient(cfg)

	limits := triage.AgentLimits{MaxSteps: maxSteps, MaxToolCalls: maxToolCalls, MaxSourceBytes: maxSourceBytes, Timeout: time.Duration(timeoutSec) * time.Second}
	if siteBudgets.MaxLLMSteps > 0 {
		limits.MaxSteps = siteBudgets.MaxLLMSteps
	}
	if siteBudgets.MaxToolCalls > 0 {
		limits.MaxToolCalls = siteBudgets.MaxToolCalls
	}
	if siteBudgets.MaxSourceBytes > 0 {
		limits.MaxSourceBytes = siteBudgets.MaxSourceBytes
	}
	if siteBudgets.TimeoutSeconds > 0 {
		limits.Timeout = time.Duration(siteBudgets.TimeoutSeconds) * time.Second
	}
	// The package audit records the effective budgets after flag overrides —
	// provenance binds to the limits the run actually used, and replay pins
	// the recorded ruleset hash so recomposed packages are identical.
	// MaxOutputTokens is the effective response budget (LLM_MAX_TOKENS >
	// budgets.max_output_tokens > triage default) resolved above — the
	// recorded value is what stability retries and replay compare.
	comp := triage.Composer{
		Limits: triage.BudgetConfig{
			MaxLLMSteps:     limits.MaxSteps,
			MaxToolCalls:    limits.MaxToolCalls,
			MaxSourceBytes:  limits.MaxSourceBytes,
			TimeoutSeconds:  int(limits.Timeout / time.Second),
			MaxOutputTokens: cfg.MaxTokens,
		},
	}
	comp.DefaultBaselineSeverity = siteCfg.Baseline.DefaultSeverity
	if ticket != "" {
		return runTriageTicket(context.Background(), ticket, absOut, siteCfg, client, allowExternal, detTools == "on", vexProjection, limits, comp, failOn, osvURL, os.Stdout, cfg.AnalyzeModel, catalog, condCatalogHash, investigation)
	}
	var r io.Reader = os.Stdin
	if input != "-" {
		f, err := os.Open(input)
		if err != nil {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: open --input: %w", err))
		}
		defer f.Close()
		r = f
	}
	findings, err := triage.ParseFindings(r)
	if err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --input: %w", err))
	}

	for _, in := range findings {
		repo := strings.TrimSpace(in.Finding.Target.Repository)
		if repo == "" {
			continue
		}
		root, rerr := filepath.EvalSymlinks(repo)
		if rerr != nil {
			continue // a missing/unreadable repo is that finding's own technical error
		}
		if dirContains(root, absOut) {
			return exitErr(triage.ExitCodeError, fmt.Errorf(
				"triage: --out %s resolves inside repository %q of finding %q; output is never written into a source repository",
				outDir, repo, in.Finding.FindingID))
		}
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: create --out: %w", err))
	}

	ctx := context.Background()
	builder := triage.LocalSnapshotBuilder{AllowExternalArtifacts: allowExternal}
	gate := triage.FactGate{}
	writer := triage.ArtifactWriter{
		Stdout:       os.Stdout,
		Model:        cfg.AnalyzeModel,
		ToolVersions: map[string]string{"izyan": Version},
	}

	if siteCfgHash != "" {
		fmt.Fprintf(os.Stderr, "triage: site config %s (sha256 %s)\n", siteConfig, siteCfgHash)
	}

	var assessments []triage.Assessment
	var decisions []triage.DecisionPackage
	var records []triage.RunRecord
	var failures int
	for _, in := range findings {
		assessment, decision, rec, err := runTriageFinding(ctx, in, builder, client, limits, gate, writer, absOut, detTools == "on", vexProjection, comp, siteCfg.Policy, triage.Stage0Result{ConfigHash: siteCfgHash}, catalog, condCatalogHash, true, investigation)
		records = append(records, rec)
		if err != nil {
			failures++
			// Failure artifacts — error.json plus the run's accumulated
			// transcript — are already persisted inside runTriageFinding;
			// an outer WriteFailure with an empty AgentRun would only
			// duplicate error.json and risks shadowing the real record.
			continue
		}
		assessments = append(assessments, assessment)
		decisions = append(decisions, decision)
	}
	if _, mpath, merr := triage.WriteMetrics(ctx, absOut, records); merr != nil {
		fmt.Fprintf(os.Stderr, "triage: cannot write metrics artifact: %v\n", merr)
	} else {
		fmt.Fprintf(os.Stderr, "triage: metrics -> %s\n", mpath)
	}
	fmt.Fprintf(os.Stderr, "triage: %d finding(s) assessed, %d technical failure(s) -> %s\n", len(assessments), failures, absOut)

	switch code := triage.ExitCode(assessments, decisions, failures, failOn); code {
	case triage.ExitCodePolicy:
		return exitErr(triage.ExitCodePolicy, errors.New("triage: --fail-on policy threshold hit; see decision.json under --out"))
	case triage.ExitCodeError:
		if failures > 0 {
			return exitErr(triage.ExitCodeError,
				fmt.Errorf("triage: %d finding(s) failed technically; see error.json in their output directories", failures))
		}
		return exitErr(triage.ExitCodeError, errors.New("triage: invalid --fail-on threshold or missing decision package"))
	}
	return nil
}

// runTriageRecordDecision appends one human Accept/Reject to an existing
// run directory. It reads only decision.json, writes the immutable review
// record (and its audit projection) and prints the recorded decision plus
// the artifact path. It never prints a machine result and never needs --out,
// an LLM endpoint or network access.
type triageAnswerFlags []string
func (a *triageAnswerFlags) String() string { return strings.Join(*a, ",") }
func (a *triageAnswerFlags) Set(value string) error {
	if len(*a) >= 2 { return errors.New("at most two --answer variables are allowed") }
	variable, _, ok := strings.Cut(value, "=")
	if !ok || variable == "" { return errors.New("--answer requires variable=value") }
	for _, old := range *a { previous, _, _ := strings.Cut(old, "="); if previous == variable { return fmt.Errorf("duplicate --answer variable %s", variable) } }
	*a = append(*a, value); return nil
}

func runTriageReview(runDir, decision, actor, reason, presentedProjectionHash string, answers []string) error {
	if presentedProjectionHash != "" && (decision == "" || len(answers) != 0) {
		return exitErr(triage.ExitCodeError, errors.New("triage: --projection-hash requires --decision and cannot accompany new --answer values; copy the presented decision command"))
	}
	w := triage.ArtifactWriter{}
	projection, err := w.WriteEnvironmentAnswers(context.Background(), runDir, actor, answers)
	if err != nil { return exitErr(triage.ExitCodeError, err) }
	if decision == "" {
		fmt.Fprintf(os.Stdout, "review branch=%s status=%s action=%s projection=%s\n", projection.BranchID, projection.Status, projection.Action.Kind, projection.ProjectionHash)
		if projection.Status != triage.HumanBranchAwaitingInput {
			quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
			for _, choice := range []string{"accept", "reject"} {
				fmt.Fprintf(os.Stdout, "izyan triage --record-decision %s --actor %s --decision %s --projection-hash %s\n", quote(runDir), quote(actor), choice, projection.ProjectionHash)
			}
		}
		return nil
	}
	if presentedProjectionHash == "" {
		if len(projection.AssertionIDs) != 0 && len(answers) == 0 {
			return exitErr(triage.ExitCodeError, errors.New("triage: environment decision requires --projection-hash from the presented review; run review mode and copy its Accept/Reject command"))
		}
		if len(answers) != 0 && len(answers) != len(projection.AssertionIDs) {
			return exitErr(triage.ExitCodeError, errors.New("triage: one-step answers+decision must explicitly name every selected answer; otherwise review first and use --projection-hash"))
		}
		presentedProjectionHash = projection.ProjectionHash
	}
	return runTriageRecordDecision(runDir, decision, actor, reason, presentedProjectionHash)
}

func runTriageRecordDecision(runDir, decision, actor, reason, projectionHash string) error {
	parsed, err := triage.ParseHumanDecision(decision)
	if err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: %w", err))
	}
	writer := triage.ArtifactWriter{}
	rec, path, err := writer.WriteHumanDecision(context.Background(), runDir, triage.HumanDecisionInput{
		Decision: parsed, Actor: actor, Reason: reason, ProjectionHash: projectionHash,
	})
	if path != "" {
		// The immutable record is the primary result. When only the audit
		// append failed, the decision and path are still printed below
		// before the honest exit-2 error.
		fmt.Fprintf(os.Stdout, "triage %s decision=%s actor=%s package=%s branch=%s projection=%s record=%s\n",
			rec.FindingID, rec.Decision, rec.Actor, rec.DecisionPackageHash, rec.BranchID, rec.ProjectionHash, path)
	}
	if err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: record decision: %w", err))
	}
	return nil
}

// runTriageTicket executes the generic Stage 0 path for every intake record
// in a file or stdin. Each record gets its own normalized finding and run
// directory; a technical failure is written to that record's error channel
// and processing continues with the remaining records. Exit 2 wins over any
// policy status, matching the CI contract.
func runTriageTicket(
	ctx context.Context,
	ticketPath, outDir string,
	cfg triage.SiteConfig,
	client triage.ChatClient,
	allowExternal, detOn, vex bool,
	limits triage.AgentLimits,
	comp triage.Composer,
	failOn []triage.FailOn,
	osvURL string,
	stdout io.Writer,
	model string,
	catalog *triage.ConditionCatalog,
	catalogHash string,
	investigation triage.InvestigationInputs,
) error {
	var r io.Reader = os.Stdin
	var f *os.File
	var err error
	if ticketPath != "-" {
		f, err = os.Open(ticketPath)
		if err != nil {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: open --ticket: %w", err))
		}
		defer f.Close()
		r = f
	}
	raws, err := triage.ParseIntake(r)
	if err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --ticket: %w", err))
	}
	// Containment is checked before creating --out: a rejected path must not
	// leave even an empty directory inside a configured source checkout.
	for _, entry := range cfg.Sources.Repositories {
		if strings.TrimSpace(entry.Root) == "" {
			continue
		}
		root, rerr := filepath.EvalSymlinks(entry.Root)
		if rerr == nil && dirContains(root, outDir) {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: --out %s resolves inside configured source repository %q; output is never written into a source repository", outDir, entry.Root))
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return exitErr(triage.ExitCodeError, fmt.Errorf("triage: create --out: %w", err))
	}
	writer := triage.ArtifactWriter{Stdout: stdout, Model: model, ToolVersions: map[string]string{"izyan": Version}}
	gate := triage.FactGate{}
	var assessments []triage.Assessment
	var decisions []triage.DecisionPackage
	var records []triage.RunRecord
	failures := 0
	for _, raw := range raws {
		stageStarted := time.Now()
		stageIn := triage.Stage0Input{
			Raw: raw, Config: cfg, Catalog: cfg.Catalog(), ChatClient: client,
			FreezeDir: filepath.Join(outDir, "_advisory-freeze"), FrozenDir: cfg.Sources.Advisory.FrozenDir,
			OSVBaseURL: osvURL, Investigation: investigation,
		}
		res, stageErr := triage.ResolveStage0(ctx, stageIn)
		if stageErr != nil {
			failures++
			errPath, werr := writer.WriteStage0Failure(ctx, outDir, res, stageErr)
			if werr != nil {
				fmt.Fprintf(os.Stderr, "triage %s: cannot write Stage 0 failure artifacts: %v\n", triage.IntakeFindingID(raw), werr)
			} else if werr := triage.WriteIntakeAudit(ctx, filepath.Dir(errPath), res); werr != nil {
				fmt.Fprintf(os.Stderr, "triage %s: cannot write intake audit: %v\n", triage.IntakeFindingID(raw), werr)
			}
			records = append(records, triage.RunRecord{
				FindingID: triage.IntakeFindingID(raw), IntakeAttempted: true,
				Stage0: &res, Failed: true, ErrorClass: triage.RunStageIntake,
				WallTimeMS: time.Since(stageStarted).Milliseconds(),
			})
			fmt.Fprintf(os.Stderr, "triage %s: %v\n", triage.IntakeFindingID(raw), stageErr)
			continue
		}
		if res.Source.Root != "" {
			root, rerr := filepath.EvalSymlinks(res.Source.Root)
			if rerr != nil {
				failures++
				errPath, _ := writer.WriteStage0Failure(ctx, outDir, res, fmt.Errorf("source root: %w", rerr))
				if errPath != "" {
					_ = triage.WriteIntakeAudit(ctx, filepath.Dir(errPath), res)
				}
				records = append(records, triage.RunRecord{
					FindingID: res.Input.Finding.FindingID, IntakeAttempted: true,
					Stage0: &res, Failed: true, ErrorClass: triage.RunStageSource,
					WallTimeMS: time.Since(stageStarted).Milliseconds(),
				})
				continue
			}
			if dirContains(root, outDir) {
				failures++
				errPath, _ := writer.WriteStage0Failure(ctx, outDir, res, fmt.Errorf("--out %s resolves inside source repository %q", outDir, res.Source.Root))
				if errPath != "" {
					_ = triage.WriteIntakeAudit(ctx, filepath.Dir(errPath), res)
				}
				records = append(records, triage.RunRecord{
					FindingID: res.Input.Finding.FindingID, IntakeAttempted: true,
					Stage0: &res, Failed: true, ErrorClass: triage.RunStageSource,
					WallTimeMS: time.Since(stageStarted).Milliseconds(),
				})
				continue
			}
		}
		runDir, err := writer.WriteStage0Artifacts(ctx, outDir, res)
		if err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "triage %s: cannot write Stage 0 artifacts: %v\n", res.Input.Finding.FindingID, err)
			if cerr := res.Source.Cleanup(); cerr != nil {
				// Fail-closed cleanup never touches .git/worktrees
				// unlocked; the skipped removal is recorded here so the
				// stale registration is an explained limitation, not a
				// silent leak.
				fmt.Fprintf(os.Stderr, "triage %s: worktree cleanup skipped (stale registration reconciled by a later prune): %v\n", res.Input.Finding.FindingID, cerr)
			}
			records = append(records, triage.RunRecord{
				FindingID: res.Input.Finding.FindingID, IntakeAttempted: true,
				Stage0: &res, Failed: true, ErrorClass: triage.RunStageArtifacts,
				WallTimeMS: time.Since(stageStarted).Milliseconds(),
			})
			continue
		}
		if werr := triage.WriteIntakeAudit(ctx, runDir, res); werr != nil {
			fmt.Fprintf(os.Stderr, "triage %s: cannot write intake audit: %v\n", res.Input.Finding.FindingID, werr)
		}
		runWriter := writer
		runWriter.RunDir = runDir
		assessment, decision, rec, runErr := runTriageFinding(ctx, res.Input, stage0SnapshotBuilder{manifest: res.Snapshot}, client, limits, gate, runWriter, outDir, detOn, vex, comp, cfg.Policy, res, catalog, catalogHash, false, investigation)
		rec.WallTimeMS += time.Since(stageStarted).Milliseconds()
		records = append(records, rec)
		if runErr != nil {
			failures++
			fmt.Fprintf(os.Stderr, "triage %s: %v\n", res.Input.Finding.FindingID, runErr)
			// Failure artifacts are already persisted inside
			// runTriageFinding together with the run's transcript; an
			// outer WriteFailure with an empty AgentRun would only
			// duplicate error.json.
			continue
		}
		assessments = append(assessments, assessment)
		decisions = append(decisions, decision)
	}
	if _, mpath, merr := triage.WriteMetrics(ctx, outDir, records); merr != nil {
		fmt.Fprintf(os.Stderr, "triage: cannot write metrics artifact: %v\n", merr)
	} else {
		fmt.Fprintf(os.Stderr, "triage: metrics -> %s\n", mpath)
	}
	fmt.Fprintf(os.Stderr, "triage: %d finding(s) assessed, %d technical failure(s) -> %s\n", len(assessments), failures, outDir)
	switch code := triage.ExitCode(assessments, decisions, failures, failOn); code {
	case triage.ExitCodePolicy:
		return exitErr(triage.ExitCodePolicy, errors.New("triage: --fail-on policy threshold hit; see decision.json under --out"))
	case triage.ExitCodeError:
		if failures > 0 {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: %d finding(s) failed technically; see error.json in their output directories", failures))
		}
		return exitErr(triage.ExitCodeError, errors.New("triage: invalid --fail-on threshold or missing decision package"))
	}
	return nil
}

type stage0SnapshotBuilder struct{ manifest triage.SnapshotManifest }

func (b stage0SnapshotBuilder) Build(context.Context, triage.FindingInput) (triage.SnapshotManifest, error) {
	return b.manifest, nil
}

// runTriageFinding runs one isolated finding through the pipeline:
// snapshot → tools → agent → fact gate → artifacts → decision composition
// → final gate → decision.json/decision.md. s0 carries the Stage 0
// resolution result for --ticket runs; on the compatibility transport
// (compat=true) s0 is replaced by a record bound to the finding and the
// built snapshot, since no Stage 0 resolution ran. It returns the
// assessment, the composed decision package and the run record the batch
// metrics aggregate — the record is observability only and never feeds
// back into the decision. A failed agent run leaves its partial
// transcript and audit trail in the finding's directory via WriteFailure;
// failures after the run (composition, decision write, final gate) land
// in error.json through the same channel — the deferred path always
// passes the last recorded run (failureRun), never an empty AgentRun, and
// never overwrites a completed raw-agent.json.
func runTriageFinding(
	ctx context.Context,
	in triage.FindingInput,
	builder triage.SnapshotBuilder,
	client triage.ChatClient,
	limits triage.AgentLimits,
	gate triage.FactGate,
	writer triage.ArtifactWriter,
	outDir string,
	detOn, vex bool,
	comp triage.Composer,
	policy triage.PolicyConfig,
	s0 triage.Stage0Result,
	catalog *triage.ConditionCatalog,
	catalogHash string,
	compat bool,
	investigation triage.InvestigationInputs,
) (assessment triage.Assessment, pkg triage.DecisionPackage, rec triage.RunRecord, err error) {
	started := time.Now()
	rec = triage.RunRecord{FindingID: in.Finding.FindingID, IntakeAttempted: !compat}
	failurePersisted := false
	var failureRun triage.AgentRun
	defer func() {
		if err != nil && !failurePersisted {
			if _, werr := writer.WriteFailure(ctx, outDir, in, failureRun, err, nil); werr != nil {
				fmt.Fprintf(os.Stderr, "triage %s: cannot write failure artifacts: %v\n", in.Finding.FindingID, werr)
			}
		}
	}()
	defer func() { rec.WallTimeMS = time.Since(started).Milliseconds() }()
	var prologue []llm.ChatMessage
	var stageEvents []triage.AuditEvent
	if !compat {
		prologue = s0.Transcript
		stageEvents = s0.Events
	}
	manifest, err := builder.Build(ctx, in)
	if err != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageAnalysis
		rec.Stage0 = &s0
		return assessment, pkg, rec, fmt.Errorf("snapshot: %w", err)
	}
	s0.Snapshot = manifest
	s0.Input = in
	if compat {
		s0 = compatStage0(in, manifest, s0.ConfigHash)
		// The record-bound scope names the captured finding bytes that
		// WriteStage0Artifacts persists as input.json. The path is
		// run-relative, so a copied run replays against its own input
		// bytes; replay resolves it against the directory being replayed.
		if s0.Advisory.SHA256 != "" {
			s0.Advisory.Path = "input.json"
		}
		if collected, cerr := triage.CollectMaterials(ctx, manifest, triage.SiteConfig{}, nil); cerr == nil {
			s0.Materials = collected
		} else {
			s0.Materials.Limitations = []string{"compatibility material collection unavailable"}
		}
		// The compatibility transport captures no frozen advisory document;
		// the supplied set plus the pinned finding bytes are the exact
		// material the decision may be bound to.
		s0.Investigation = investigation
		if s0.Advisory.SHA256 != "" {
			captured, cerr := triage.CapturedRecordFromFrozen(s0.Advisory, s0.Raw.Raw)
			if cerr != nil {
				rec.Failed, rec.ErrorClass = true, triage.RunStageAnalysis
				rec.Stage0 = &s0
				return assessment, pkg, rec, fmt.Errorf("captured advisory: %w", cerr)
			}
			s0.Investigation, cerr = s0.Investigation.WithRecord(captured)
			if cerr != nil {
				rec.Failed, rec.ErrorClass = true, triage.RunStageAnalysis
				rec.Stage0 = &s0
				return assessment, pkg, rec, fmt.Errorf("captured advisory: %w", cerr)
			}
		}
	}
	// The product build is resolved once, before any evidence session is
	// constructed, from the finding's declared target/build and the
	// supplied investigation build input. Conflicting declarations fail
	// here; an absent target stays absent and is never replaced by the
	// analyzer host. Every stability attempt shares this one selection.
	buildSet := investigation
	if !compat {
		buildSet = s0.Investigation
	}
	buildTarget, buildErr := triage.ResolveBuildTarget(in, buildSet, manifest)
	if buildErr != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageAnalysis
		rec.Stage0 = &s0
		return assessment, pkg, rec, fmt.Errorf("product build target: %w", buildErr)
	}
	s0.BuildTarget = buildTarget
	s0.Investigation.BuildTarget = buildTarget
	if compat && buildTarget == nil {
		s0.Limitations = append(s0.Limitations, triage.BuildTargetAbsentLimitation)
	}
	rec.Stage0 = &s0
	// The run directory is reserved before the first model exchange so the
	// exact prompt surface and the captured material archive are durable
	// even when the run dies mid-investigation.
	if strings.TrimSpace(writer.RunDir) == "" {
		dir, derr := triage.ReserveRunDir(outDir, in.Finding.FindingID)
		if derr != nil {
			rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
			rec.Stage0 = &s0
			return assessment, pkg, rec, fmt.Errorf("reserve run directory: %w", derr)
		}
		writer.RunDir = dir
	}
	if werr := writer.WriteInvestigationInputs(ctx, writer.RunDir, s0.Investigation); werr != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
		rec.Stage0 = &s0
		return assessment, pkg, rec, fmt.Errorf("captured material archive: %w", werr)
	}
	promptSink := func(pi triage.PromptInput) error {
		return writer.WritePromptInput(ctx, writer.RunDir, pi)
	}
	// agentIn is what the model sees (prompt + lookup_advisory + fact gate):
	// the normalized intake finding enriched with the resolved advisory's
	// prose, aliases and severity. Artifacts and decision composition keep
	// the intake-normalized input — res.Input/s0.Input is never the view.
	agentIn := triage.Stage0AgentFinding(in, s0.AdvisoryVulnerability())
	// The agent and the fact gate see the same resolved product build the
	// evidence session and artifacts describe; nil keeps the build absent.
	if s0.BuildTarget != nil {
		agentIn.Finding.Target.Build = s0.BuildTarget
	}
	// The catalog binding pins the run's advisory identity, case identity
	// and catalog-hash expectation so a foreign or stale catalog is
	// non-admitting — never a skipped check. AdvisoryID prefers the
	// resolved advisory id; the catalog producer declares the same name.
	// The derived capabilities are the only condition ids prompt and tool
	// surfaces may advertise: a missing or non-admitting catalog yields an
	// explicit unavailable reason, never an advisory-derived condition.
	binding := triage.CatalogBinding{
		CaseIdentityRef:     in.Finding.FindingID,
		ExpectedCatalogHash: catalogHash,
	}
	if s0.Advisory.SHA256 != "" || s0.Advisory.ID != "" {
		binding.AdvisoryDigest = s0.Advisory.SHA256
		if s0.Advisory.ResolvedID != "" {
			binding.AdvisoryID = s0.Advisory.ResolvedID
		} else {
			binding.AdvisoryID = s0.Advisory.ID
		}
	}
	proposalCapabilities := triage.BuildProposalCapabilities(catalog, binding)
	// buildAttemptTools constructs the read-only tool executor one
	// stability attempt consumes. Every attempt gets a fresh executor —
	// and a fresh deterministic-evidence session — on identical inputs:
	// the same snapshot manifest, the same budgets, the same catalog.
	// A fresh instance also keeps each attempt's observation ids and tool
	// audit trail isolated, so the fact gate of retry k can never resolve
	// evidence against an observation a sibling attempt recorded. Each
	// attempt's observations land in its own run-stamped archive, which is
	// what the falsifier verifier later binds proofs to.
	buildAttemptTools := func(attempt int) (triage.ToolExecutor, triage.DetToolsAudit, func()) {
		obsStore := triage.NewRunObservationStore(triage.AttemptRunID(in.Finding.FindingID, attempt), attempt)
		ro := &triage.ReadOnlyTools{
			Snapshot:             manifest,
			Finding:              agentIn,
			Advisory:             s0.AdvisoryProjection(),
			Investigation:        s0.Investigation,
			ProposalCapabilities: proposalCapabilities,
			ObservationStore:     obsStore,
			Budget: triage.ToolBudget{
				MaxToolCalls:   limits.MaxToolCalls,
				MaxSourceBytes: limits.MaxSourceBytes,
			},
		}
		tools := triage.ToolExecutor(ro)
		detAudit := triage.DetToolsAudit{}
		closeFn := func() {}
		if detOn {
			det, da, detClose := detToolExecutor(ctx, agentIn, manifest, s0, s0.BuildTarget)
			detAudit = da
			if det != nil {
				det.ObservationStore = obsStore
				closeFn = detClose
				tools = &triage.ToolSet{
					ObservationStore: obsStore,
					Parts:            []triage.ToolExecutor{ro, det},
				}
			}
		}
		return tools, detAudit, closeFn
	}
	tools, detAuditV, toolsClose := buildAttemptTools(1)
	defer toolsClose()
	detAudit := &detAuditV
	if compat && detAudit.Toolchain != "" {
		// The compatibility transport has no Stage 0 toolchain facts;
		// record the local analysis toolchain honestly so stage0.json and
		// the package audit pin the same one.
		s0.Toolchain = toolchain.Toolchain{Mode: toolchain.ModeLocal, Version: detAudit.Toolchain}
	}
	if comp.RulesetHash == "" {
		comp.RulesetHash = rulesetHash(comp.Rules)
	}
	// composeAttempt deterministically composes one stability attempt on
	// the frozen inputs and projects its canonical record: the same Stage
	// 0 result, snapshot, advisory freeze, ruleset, profiles, providers
	// and budgets as the primary package — only the agent response
	// varies. A retry never rewrites its inputs and no attempt is ever
	// selected as the preferred answer.
	composeAttempt := func(attempt int, runK triage.AgentRun, fvK triage.FactValidation, detK triage.DetToolsAudit, proofK *triage.FalsifierReport) (triage.StabilityAttempt, error) {
		aK := runK.Assessment
		aK.FactValidation = fvK.Status
		aK.FactValidationDetail = &fvK
		caK := aK
		caK.Audit = &triage.AssessmentAudit{PromptHash: runK.PromptHash}
		pkgK, err := comp.ComposeWithEvidence(ctx, s0, caK, fvK, triage.EvidenceInput{
			Observations:    runK.Observations,
			Falsifiers:      proofK,
			SelectedAttempt: attempt,
		})
		if err != nil {
			return triage.StabilityAttempt{}, err
		}
		at := triage.ProjectStabilityAttempt(attempt, pkgK)
		// The toolchain pin covers what actually ran: the package audit's
		// frozen toolchain plus this attempt's resolved det-tools session.
		tcSurface, _ := json.Marshal(struct {
			Pkg triage.ToolchainAudit `json:"pkg"`
			Det triage.DetToolsAudit  `json:"det"`
		}{Pkg: pkgK.Audit.Toolchain, Det: detK})
		tcSum := sha256.Sum256(tcSurface)
		at.ToolchainHash = hex.EncodeToString(tcSum[:])
		return at, nil
	}
	// falsifierTracker holds the deterministic verifier report for the last
	// accepted assessment of the current attempt: the runner calls the
	// feedback callback after every accepted (possibly repaired)
	// assessment, so the composed package, falsifier-verification.json and
	// the audit event never bind to a superseded one. Each attempt gets a
	// fresh callback bound to its own attempt number and observation set;
	// the tracker passes the previous attempt's report in as verification
	// history once, then chains its own passes.
	falsifierTracker := &falsifierFeedbackTracker{
		catalog: catalog,
		binding: binding,
		verify: func(ctx context.Context, a triage.Assessment, fv triage.FactValidation, obs []triage.RecordedObservation, attempt int, previous *triage.FalsifierReport) *triage.FalsifierReport {
			return verifyFalsifiersWithPrevious(ctx, s0, a, fv,
				triage.AgentRun{Observations: obs}, comp.RulesetHash, in.Finding.FindingID, attempt, previous, catalog, binding)
		},
	}
	runner := triage.AgentRunner{Client: client, Tools: tools, Limits: limits, Materials: triage.BuildAgentMaterials(s0.Materials, s0.Investigation), PromptSink: promptSink, ProposalCapabilities: proposalCapabilities}
	runner.Prologue = prologue
	run, fv, err := runner.RunWithFactGateAndFalsifierFeedback(ctx, agentIn, manifest, gate, triage.MaxFactFeedbackPasses, falsifierTracker.callbackFor(1), triage.MaxFalsifierFeedbackPasses)
	failureRun = run
	if err != nil {
		// Preserve whatever the run accumulated — transcript, budgets,
		// failure class and the audit events recorded so far — so the
		// technical failure is diagnosable, not just recorded.
		events := append([]triage.AuditEvent(nil), stageEvents...)
		events = append(events, triage.AuditEvent{Type: triage.AuditEventRunStarted, Status: "error"})
		events = append(events, detAuditEvent(detAudit, 0)...)
		if a, ok := tools.(interface {
			AuditEvents() []triage.ToolAuditEvent
		}); ok {
			events = append(events, triage.ToolAuditEvents(a.AuditEvents(), time.Now().UTC())...)
		}
		failurePersisted = true
		if _, werr := writer.WriteFailure(ctx, outDir, in, run, err, events); werr != nil {
			fmt.Fprintf(os.Stderr, "triage %s: cannot write failure artifacts: %v\n", in.Finding.FindingID, werr)
		}
		rec.Failed, rec.ErrorClass = true, triage.RunStageAnalysis
		rec.LLMSteps, rec.ToolCalls = int64(run.Steps), int64(run.ToolCalls)
		rec.FactPasses = run.FactPasses
		return assessment, pkg, rec, err
	}
	if err := ctx.Err(); err != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageAnalysis
		return assessment, pkg, rec, fmt.Errorf("fact gate: %w", err)
	}
	assessment = run.Assessment
	assessment.FactValidation = fv.Status
	assessment.FactValidationDetail = &fv
	rec.Assessment = &assessment
	rec.LLMSteps, rec.ToolCalls = int64(run.Steps), int64(run.ToolCalls)
	rec.FactPasses = run.FactPasses
	events := append([]triage.AuditEvent(nil), stageEvents...)
	events = append(events, triage.AuditEvent{Type: triage.AuditEventRunStarted, Status: "ok"})
	events = append(events, triage.FactFeedbackAuditEvents(run.FactPasses, time.Now().UTC())...)
	events = append(events, detAuditEvent(detAudit, 0)...)
	if a, ok := tools.(interface {
		AuditEvents() []triage.ToolAuditEvent
	}); ok {
		events = append(events, triage.ToolAuditEvents(a.AuditEvents(), time.Now().UTC())...)
	}
	// Stability retries (spec §2.4): policy.stability_retries extra runs on
	// exactly the same frozen inputs — input, snapshot, selected ref,
	// resolved commit, advisory freeze, ruleset, prompt, toolchain and
	// budgets are all held constant by construction. Every attempt is
	// persisted (raw-agent.json stability_runs, stability.json, audit
	// events); the report is evaluated, never used to pick a preferred
	// response. policy.on_drift admits only "error", so provenance drift
	// always lands on the technical-error channel (exit 2).
	retries := policy.StabilityRetries
	if retries < 0 {
		retries = 0
	}
	var attempts []triage.StabilityAttempt
	var report triage.StabilityReport
	finalRun := run
	finalFV := fv
	finalAssessment := assessment
	// selectedAttempt numbers the attempt the decision composes from:
	// 1 is the primary transcript, N>1 the N-1th stability retry.
	selectedAttempt := 1
	if comp.RulesetHash == "" {
		comp.RulesetHash = rulesetHash(comp.Rules)
	}
	if falsifierTracker.report != nil {
		events = append(events, triage.FalsifierAuditEvent(*falsifierTracker.report, "", 1, time.Now().UTC()))
	}
	failAttempt := func(cls string, cerr error) (triage.Assessment, triage.DecisionPackage, triage.RunRecord, error) {
		failurePersisted = true
		failureRun = run
		if _, werr := writer.WriteFailure(ctx, outDir, in, failureRun, cerr, events); werr != nil {
			fmt.Fprintf(os.Stderr, "triage %s: cannot write failure artifacts: %v\n", in.Finding.FindingID, werr)
		}
		rec.Failed, rec.ErrorClass = true, cls
		return assessment, pkg, rec, cerr
	}
	if retries > 0 {
		at, aerr := composeAttempt(1, run, fv, *detAudit, falsifierTracker.report)
		if aerr != nil {
			return failAttempt(triage.RunStageAnalysis, fmt.Errorf("stability attempt 1 composition: %w", aerr))
		}
		attempts = append(attempts, at)
	}
	for k := range retries {
		attemptN := k + 2
		toolsK, detAuditK, toolsKClose := buildAttemptTools(attemptN)
		runnerK := triage.AgentRunner{Client: client, Tools: toolsK, Limits: limits, Materials: triage.BuildAgentMaterials(s0.Materials, s0.Investigation), PromptSink: promptSink, ProposalCapabilities: proposalCapabilities}
		runK, fvK, rerr := runnerK.RunWithFactGateAndFalsifierFeedback(ctx, agentIn, manifest, gate, triage.MaxFactFeedbackPasses, falsifierTracker.callbackFor(attemptN), triage.MaxFalsifierFeedbackPasses)
		failureRun = run
		for _, fev := range triage.FactFeedbackAuditEvents(runK.FactPasses, time.Now().UTC()) {
			fev.Attempt = attemptN
			events = append(events, fev)
		}
		events = append(events, detAuditEvent(&detAuditK, attemptN)...)
		if a, ok := toolsK.(interface {
			AuditEvents() []triage.ToolAuditEvent
		}); ok {
			for _, tev := range triage.ToolAuditEvents(a.AuditEvents(), time.Now().UTC()) {
				tev.Attempt = attemptN
				events = append(events, tev)
			}
		}
		if rerr != nil {
			run.Attempts = append(run.Attempts, runK)
			rec.LLMSteps += int64(runK.Steps)
			rec.ToolCalls += int64(runK.ToolCalls)
			toolsKClose()
			return failAttempt(triage.RunStageAnalysis, fmt.Errorf("stability attempt %d: %w", attemptN, rerr))
		}
		rec.LLMSteps += int64(runK.Steps)
		rec.ToolCalls += int64(runK.ToolCalls)
		run.Attempts = append(run.Attempts, runK)
		finalRun = runK
		finalFV = fvK
		finalAssessment = runK.Assessment
		selectedAttempt = attemptN
		if falsifierTracker.report != nil {
			events = append(events, triage.FalsifierAuditEvent(*falsifierTracker.report, "", attemptN, time.Now().UTC()))
		}
		at, aerr := composeAttempt(attemptN, finalRun, finalFV, detAuditK, falsifierTracker.report)
		if aerr != nil {
			toolsKClose()
			return failAttempt(triage.RunStageAnalysis, fmt.Errorf("stability attempt %d composition: %w", attemptN, aerr))
		}
		attempts = append(attempts, at)
		toolsKClose()
	}
	if retries > 0 {
		report = triage.CheckStability(attempts)
		report.SelectedAttempt = selectedAttempt
		reportCopy := report
		rec.Stability = &reportCopy
	}
	if compat {
		// Write the Stage 0 provenance stub (stage0.json + intake.json)
		// before the run artifacts claim the directory: a decision package
		// requires stage0.json provenance for offline replay.
		if _, werr := writer.WriteStage0Artifacts(ctx, outDir, s0); werr != nil {
			rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
			return assessment, pkg, rec, fmt.Errorf("stage0 artifacts: %w", werr)
		}
	}
	// Persist: the PRIMARY transcript stays attempt 1 (retries are recorded
	// separately in stability_runs via run.Attempts — never duplicated as
	// the primary); `selected` pins the attempt the package composed from
	// so the assessment audit names the answer the verdict depends on and
	// the observation archive merges attempt-1 + retry observations.
	sel := &finalRun
	art, err := writer.Write(ctx, outDir, in, manifest, run, finalAssessment, events, sel)
	if err != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
		return assessment, pkg, rec, fmt.Errorf("artifacts: %w", err)
	}
	writer.RunDir = ""
	if retries > 0 {
		if werr := writer.WriteStability(ctx, art.RootDir, in.Finding.FindingID, art.RunID, report); werr != nil {
			rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
			return assessment, pkg, rec, fmt.Errorf("stability artifacts: %w", werr)
		}
		// on_drift is validated to "error" only, so any drifted provenance
		// pin is a technical failure here — never a new package.
		if report.Drift {
			rec.Failed, rec.ErrorClass = true, triage.RunStageDrift
			return assessment, pkg, rec,
				fmt.Errorf("provenance drift between stability attempts: %s", strings.Join(report.Limitations, "; "))
		}
		comp.Stability = &report
	}

	// The composer reads the agent's verdict plus the deterministic gate —
	// the audit-stamped copy carries the prompt hash into the package so
	// WriteDecision's provenance check matches assessment.json.
	ca := finalAssessment
	ca.Audit = &triage.AssessmentAudit{PromptHash: finalRun.PromptHash}
	comp.RunID = art.RunID
	// The selected attempt's budget outcome is a recorded run fact, not a
	// completeness claim: a finalization after the step budget is visible
	// in the human package, and replay recomposes from the same value.
	comp.BudgetResult = finalRun.BudgetResult()
	pkg, err = comp.ComposeWithEvidence(ctx, s0, ca, finalFV, triage.EvidenceInput{
		Observations:    finalRun.Observations,
		Falsifiers:      falsifierTracker.report,
		SelectedAttempt: selectedAttempt,
	})
	if err != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageDecision
		return assessment, pkg, rec, fmt.Errorf("decision: %w", err)
	}
	// Final gate (spec §6.4): C12/C13 verify the composed package — a
	// non-PASS outcome is a technical error, never a different package.
	rules := comp.Rules
	if rules == nil {
		rules = triage.DefaultRules()
	}
	profiles := comp.Profiles
	if profiles == nil {
		profiles = triage.DefaultProfiles()
	}
	for _, res := range triage.RunChecks(ctx, finalGateChecks(), triage.CheckInput{
		Stage0: s0, Assessment: ca, Validation: finalFV,
		Facts: pkg.Facts, Package: &pkg, Profiles: profiles, Rules: rules,
		Falsifiers: falsifierTracker.report,
	}) {
		if !fatalFinalGateResult(res.ID, res.Status) {
			continue
		}
		rec.Failed, rec.ErrorClass = true, triage.RunStageDecision
		return assessment, pkg, rec,
			fmt.Errorf("decision: final gate check %s is %s: %s", res.ID, res.Status, strings.Join(res.Reasons, "; "))
	}
	if falsifierTracker.report != nil {
		if err := writer.WriteFalsifierReport(ctx, art.RootDir, *falsifierTracker.report); err != nil {
			rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
			return assessment, pkg, rec, fmt.Errorf("decision: falsifier report: %w", err)
		}
	}
	if err := writer.WriteConditionCatalog(ctx, art.RootDir, catalog, binding); err != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
		return assessment, pkg, rec, fmt.Errorf("decision: condition catalog: %w", err)
	}
	if err := writer.WriteDecision(ctx, art.RootDir, pkg); err != nil {
		rec.Failed, rec.ErrorClass = true, triage.RunStageArtifacts
		return assessment, pkg, rec, fmt.Errorf("decision: %w", err)
	}
	if vex {
		writeVEXProjection(ctx, writer, art.RootDir, pkg)
	}
	rec.Falsifiers = falsifierTracker.report
	rec.Decision = &pkg
	return assessment, pkg, rec, nil
}

// fatalFinalGateResult draws the boundary the falsifier contract depends on.
// C14's UNVERIFIED outcome is a limitation the package already records
// (UNCHANGED plus a residual assumption), never a technical failure; every
// other non-PASS result — including a malformed, forged or cross-run proof —
// is fatal, because a package resting on such evidence must not be emitted.
func fatalFinalGateResult(checkID string, status triage.CheckStatus) bool {
	if status == triage.CheckPass {
		return false
	}
	if checkID == triage.CheckIDFalsifierProof && status == triage.CheckUnverified {
		return false
	}
	return true
}

// writeVEXProjection emits the optional triage-scoped VEX statement for one
// persisted decision package (spec §10.2). The projection is strictly
// non-authoritative: a package the boundary does not admit is recorded as a
// denial in the run's audit log, and any projection failure lands on stderr —
// neither changes the decision, the recommendation or the exit code.
func writeVEXProjection(ctx context.Context, writer triage.ArtifactWriter, outDir string, pkg triage.DecisionPackage) {
	proj, err := triage.ProjectVEX(pkg)
	if err != nil {
		if werr := writer.RecordVEXProjectionDenial(ctx, outDir, pkg, err); werr != nil {
			fmt.Fprintf(os.Stderr, "triage %s: cannot record VEX projection denial: %v\n", pkg.FindingID, werr)
		}
		fmt.Fprintf(os.Stderr, "triage %s: VEX projection not written: %v\n", pkg.FindingID, err)
		return
	}
	if err := writer.WriteVEXProjection(ctx, outDir, proj); err != nil {
		fmt.Fprintf(os.Stderr, "triage %s: VEX projection failed: %v\n", pkg.FindingID, err)
	}
}

// firstVulnerabilityID returns the first non-empty vulnerability id, or "".
func firstVulnerabilityID(ids []string) string {
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			return id
		}
	}
	return ""
}

// compatStage0 projects the compatibility finding.v1 transport onto the
// Stage 0 result the composer and replay consume. No Stage 0 resolution ran
// for --input: the finding record itself is the intake document (so
// ticket_hash binds to it), the declared repository is the materialized
// source and the snapshot manifest is the pinned source identity. The
// captured finding record is also the record-bound scope identity: its raw
// bytes and sha256 are the exact material the decision is bound to, so a
// substantive human action remains deliverable without inventing an advisory
// document. Everything else — catalog entry, candidate refs, advisory
// resolution, package check — stays absent, and the checks report that
// honestly as UNAVAILABLE.
func compatStage0(in triage.FindingInput, manifest triage.SnapshotManifest, configHash string) triage.Stage0Result {
	raw := in.Raw
	if len(raw) == 0 {
		raw, _ = json.MarshalIndent(in.Finding, "", "  ")
	}
	ticketHash := in.SHA256
	if ticketHash == "" && len(raw) > 0 {
		sum := sha256.Sum256(raw)
		ticketHash = hex.EncodeToString(sum[:])
	}
	s0 := triage.Stage0Result{
		Raw: triage.RawIntake{
			Raw:        raw,
			TicketHash: ticketHash,
			Format:     triage.IntakeJSON,
		},
		Input:      in,
		Snapshot:   manifest,
		Source:     triage.MaterializedSource{Root: manifest.Repository, Cleanup: func() error { return nil }},
		ConfigHash: configHash,
	}
	// The compatibility transport has no frozen advisory document. The
	// captured finding record is the exact material this decision can be
	// bound to; its digest is the finding's own sha256, never synthesized.
	if id := firstVulnerabilityID(in.Finding.Vulnerability.IDs); id != "" && ticketHash != "" {
		s0.Advisory = pbvuln.FrozenAdvisory{
			SchemaVersion: pbvuln.FrozenAdvisorySchemaVersion,
			ID:            id,
			ResolvedID:    id,
			Source:        pbvuln.AdvisoryTicket,
			SHA256:        ticketHash,
			Size:          int64(len(raw)),
		}
	}
	if manifest.Revision != "" || manifest.ResolvedRevision != "" {
		s0.SelectedRef = triage.RefCandidate{Name: manifest.Revision, Commit: manifest.ResolvedRevision}
		s0.RefResolution = triage.RefResolution{
			SelectedRef:    manifest.Revision,
			ResolvedCommit: manifest.ResolvedRevision,
			ResolutionRule: triage.RefRuleExact,
		}
	}
	if tc := strings.TrimSpace(in.Finding.Target.Toolchain); tc != "" {
		s0.ReleaseToolchain = triage.ReleaseToolchainFact{Claimed: tc}
	}
	return s0
}

func verifyFalsifiersWithPrevious(
	ctx context.Context,
	s0 triage.Stage0Result,
	assessment triage.Assessment,
	fv triage.FactValidation,
	run triage.AgentRun,
	rulesetHash string,
	findingID string,
	attempt int,
	previous *triage.FalsifierReport,
	catalog *triage.ConditionCatalog,
	binding triage.CatalogBinding,
) *triage.FalsifierReport {
	dbg := func(format string, args ...any) {
		if os.Getenv("IZYAN_DEBUG_FALSIFIER") != "" {
			fmt.Fprintf(os.Stderr, "falsifier-debug: "+format+"\n", args...)
		}
	}
	if len(assessment.FalsifierProposals) == 0 {
		return nil
	}
	projection := s0.AdvisoryProjection()
	if projection == nil {
		dbg("no advisory projection")
		return nil
	}
	advisoryIDs := s0.Input.Finding.Vulnerability.IDs
	if len(advisoryIDs) == 0 || len(projection.AffectedSymbols) == 0 {
		dbg("ids=%v symbols=%d", advisoryIDs, len(projection.AffectedSymbols))
		return nil
	}
	var symbols []triage.FalsifierSubject
	for _, sym := range projection.AffectedSymbols {
		symbols = append(symbols, triage.FalsifierSubject{Package: sym.Package, Symbol: sym.Symbol})
	}
	// The condition id is a pure function of the resolved advisory's own id
	// (the same id the agent reads from lookup_advisory); the advisory's
	// aliases and the intake-declared ids are equally authoritative names of
	// the same advisory, so a proposal may cite any of them.
	primary := advisoryIDs[0]
	allAdvisoryIDs := append([]string(nil), advisoryIDs...)
	if adv := s0.AdvisoryVulnerability(); adv != nil {
		if adv.ID != "" {
			primary = adv.ID
			allAdvisoryIDs = append([]string{adv.ID}, allAdvisoryIDs...)
		}
		allAdvisoryIDs = append(allAdvisoryIDs, adv.Aliases...)
	}
	buildContext := ""
	var observedTools []string
	for _, o := range run.Observations {
		observedTools = append(observedTools, o.Tool+"|"+o.ID+"|bc="+o.BuildContextHash[:min(8, len(o.BuildContextHash))])
		if o.BuildContextHash != "" && buildContext == "" {
			buildContext = o.BuildContextHash
		}
	}
	dbg("observations=%d tools=%v", len(run.Observations), observedTools)
	module := projection.Module
	if module == "" {
		module = s0.Input.Finding.Component.Package
		if module == "" {
			module = s0.Input.Finding.Component.Name
		}
		if module == "" {
			module = s0.PackageCheck.ResolvedPath
		}
	}
	resolvedVersion := firstNonEmpty(s0.Input.Finding.Component.Version, s0.PackageCheck.ResolvedVersion)
	source, err := triage.NewAdvisoryConditionSource(triage.AdvisoryConditionOptions{
		AdvisoryID:       primary,
		AdvisoryIDs:      allAdvisoryIDs,
		Module:           module,
		ResolvedVersion:  resolvedVersion,
		SnapshotHash:     s0.Snapshot.ContentHash,
		BuildContextHash: buildContext,
		RuleID:           "advisory-code-absence",
		RuleVersion:      "1",
		RuleSetHash:      rulesetHash,
		Symbols:          symbols,
	})
	if err != nil {
		dbg("source error: %v", err)
		return nil
	}
	dbg("source bound: advisory=%s module=%s version=%s symbols=%d observations=%d build=%s previous=%v",
		primary, module, resolvedVersion, len(symbols), len(run.Observations), buildContext, previous != nil)
	var previousProof *triage.FalsifierProof
	if previous != nil && len(assessment.FalsifierProposals) > 0 {
		for i := range previous.Proofs {
			if previous.Proofs[i].ID == assessment.FalsifierProposals[0].ID {
				p := previous.Proofs[i]
				previousProof = &p
				break
			}
		}
	}
	// Catalog admission is the run-side binding the §14.3.4 contract
	// requires: a proposal never reaches the verifier unless the catalog is
	// bound to this run and admits the proposal's condition/kind. Every
	// failure is a report of non-admitted proofs — never a silent pass and
	// never a silent drop: the audit trail records the rejection reason.
	// The gate itself lives in the triage package so replay re-enforces the
	// identical partition and rejection spelling.
	admission := triage.GateFalsifierProposals(catalog, binding, assessment.FalsifierProposals)
	admitted := admission.Admitted
	rejected := admission.Rejected

	report := triage.NewFalsifierVerifier(source).Verify(ctx, triage.FalsifierVerificationInput{
		Stage0:              s0,
		Assessment:          assessment,
		FactValidation:      fv,
		Proposals:           admitted,
		Observations:        run.Observations,
		RulesetHash:         rulesetHash,
		ExpectedRulesetHash: rulesetHash,
		RunID:               triage.AttemptRunID(findingID, attempt),
		Attempt:             attempt,
		Previous:            previousProof,
	})
	if len(rejected) > 0 {
		report.Proofs = append(report.Proofs, rejected...)
		report = triage.NewFalsifierReport(report.RuleSetHash, report.Proofs...)
	}
	dbg("report: proofs=%d statuses=%v", len(report.Proofs), func() []string {
		var out []string
		for _, p := range report.Proofs {
			out = append(out, p.ID+":"+string(p.Status)+":"+p.Reason)
		}
		return out
	}())
	return &report
}

// falsifierFeedbackTracker carries the falsifier repair loop through one
// stability attempt: the runner calls back after each accepted assessment,
// the tracker re-verifies it and decides whether the failures are
// agent-repairable contract bindings worth another model round. report is
// always the report of the last accepted assessment — the value the
// package composition, falsifier-verification.json and audit consume.
// No second independent verifier pass runs afterwards, so report can never
// describe a superseded assessment.
type falsifierFeedbackTracker struct {
	report *triage.FalsifierReport
	// catalog+binding gate the live falsifier path: proposals are admitted
	// against the run-pinned condition catalog before the verifier sees
	// them, and a missing/foreign/stale catalog rejects every proposal with
	// an honest non-admitting reason. The fields are intentionally part of
	// the tracker so each attempt's callback binds to the same catalog.
	catalog *triage.ConditionCatalog
	binding triage.CatalogBinding
	verify  func(
		ctx context.Context,
		a triage.Assessment,
		fv triage.FactValidation,
		obs []triage.RecordedObservation,
		attempt int,
		previous *triage.FalsifierReport,
	) *triage.FalsifierReport
}

// callbackFor binds the feedback protocol to one stability attempt: the
// previous attempt's report (if any) supplies the proof history for the
// first pass, afterwards the tracker chains its own stored report. The
// runner calls it once per accepted assessment — pass numbers above
// MaxFalsifierFeedbackPasses are the terminal verification after the last
// repair and never retry; only agent-repairable proposal bindings earn a
// message, since source/ruleset/snapshot/run/build-context failures are
// external bindings that stay on the report as diagnostics. Proposals are
// optional: an assessment that submits none produces no feedback items and
// therefore no repair turn — a missed proposal is a limitation of the
// machine result, never a contract defect.
func (t *falsifierFeedbackTracker) callbackFor(attempt int) triage.FalsifierFeedbackFunc {
	return func(ctx context.Context, a triage.Assessment, fv triage.FactValidation, obs []triage.RecordedObservation, pass int) (string, bool, error) {
		t.report = t.verify(ctx, a, fv, obs, attempt, t.report)
		fb := triage.BuildFalsifierFeedback(t.report, pass)
		if pass > triage.MaxFalsifierFeedbackPasses || !fb.Retryable() {
			return "", false, nil
		}
		return triage.FalsifierFeedbackMessage(fb), true, nil
	}
}

// finalGateChecks returns the post-package checks C12/C13 — they verify the
// composed package once it exists, where C01–C11 ran inside the composer.
func finalGateChecks() []triage.Check {
	var out []triage.Check
	for _, c := range triage.DefaultChecks() {
		if c.ID() == triage.CheckIDRiskPolicy || c.ID() == triage.CheckIDPackageStability || c.ID() == triage.CheckIDFalsifierProof {
			out = append(out, c)
		}
	}
	return out
}

// rulesetHash pins the admitted ruleset identity into the package audit: a
// deterministic sha256 over the canonical encoding of the effective rules,
// so a replay that re-derives the package reproduces the identical hash.
func rulesetHash(rules []triage.DecisionRule) string {
	if rules == nil {
		rules = triage.DefaultRules()
	}
	sum := sha256.Sum256(mustJSON(rules))
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// detToolExecutor builds the deterministic evidence surface for one
// finding: it resolves the release toolchain named by the finding (local
// toolchain with a recorded limitation when the target version cannot be
// provided) and opens an evidencetools session over the snapshot root with
// no exec and no network permission. Advisory and fix research are served
// from the run's verified captured material set only — every record the
// loader or Stage 0 admitted, regardless of whether acquisition originally
// came from a ticket, a local freeze or an API — and there is never a
// network fallback.
//
// The session is configured from the one resolved product target — platform,
// build tags and CGO — never from runtime.GOOS/runtime.GOARCH as a product
// declaration. With no identified target the session records its effective
// analysis platform, the audit states that it is host context only, and
// build-dependent negative admission still rejects the snapshot because the
// target is absent.
//
// Shadow sessions expose tools only through an audited in-memory client:
// CallTool crosses the MCP boundary inside the session, so the broker's
// own deadline/catalog-gate/audit wraps the same Observation contract an
// external caller would see. The broker advertises the session-resolved
// check catalog, so a capability the session holds is available without a
// second list. The returned cleanup closes the client and must run when the
// attempt's tool executor is retired.
func detToolExecutor(ctx context.Context, in triage.FindingInput, manifest triage.SnapshotManifest, s0 triage.Stage0Result, target *domain.ProductTarget) (*triage.DeterministicTools, triage.DetToolsAudit, func()) {
	audit := triage.DetToolsAudit{}
	if manifest.Repository == "" {
		audit.Limitations = append(audit.Limitations, triage.BuildTargetAuditLine(target))
		audit.SessionError = "finding has no snapshot repository"
		return nil, audit, func() {}
	}
	tc, tcLims := toolchain.Resolve(ctx, in.Finding.Target.Toolchain)
	audit.Toolchain = tc.Version
	audit.Limitations = append(audit.Limitations, tcLims...)
	cve := ""
	if len(in.Finding.Vulnerability.IDs) > 0 {
		cve = in.Finding.Vulnerability.IDs[0]
	}
	var vulnSource vulnerability.Source
	if len(s0.Investigation.Records) > 0 {
		vulnSource = triage.CapturedAdvisorySource{Inputs: s0.Investigation}
	} else {
		audit.Limitations = append(audit.Limitations,
			"advisory research is captured-only: this run has no verified captured advisory record")
	}
	var patchSource fix.Provider
	if len(s0.Investigation.Fixes) > 0 {
		patchSource = triage.CapturedFixProvider{Inputs: s0.Investigation}
	} else {
		audit.Limitations = append(audit.Limitations,
			"fix research is captured-only: this run has no captured fix artifact")
	}
	cfg := evidencetools.SessionConfig{
		CVEID:        cve,
		SnapshotRoot: manifest.Repository,
		ExternalSHA:  manifest.ResolvedRevision,
		ToolchainBin: tc.GoBin,
		ToolchainEnv: tc.Env,
		ToolchainVer: tc.Version,
		AllowExec:    false,
		AllowNet:     false,
		VulnSource:   vulnSource,
		PatchSource:  patchSource,
	}
	if target != nil {
		bound := *target
		bound.BuildTags = append([]string(nil), target.BuildTags...)
		cfg.GOOS = bound.GOOS
		cfg.GOARCH = bound.GOARCH
		cfg.BuildTags = append([]string(nil), bound.BuildTags...)
		cfg.CGOEnabled = bound.CGOEnabled
		cfg.Target = &bound
	}
	sess, err := evidencetools.NewSession(cfg)
	if err != nil {
		audit.Limitations = append(audit.Limitations, triage.BuildTargetAuditLine(target))
		audit.SessionError = err.Error()
		return nil, audit, func() {}
	}
	// Audit the build the session actually configured, not merely the
	// argument: an absent target stays absent and the analysis platform is
	// never presented as a product declaration.
	audit.Limitations = append(audit.Limitations, triage.BuildTargetAuditLine(sess.Build.Target))
	client, err := sess.Connect(ctx)
	if err != nil {
		audit.SessionError = fmt.Sprintf("evidence session client: %v", err)
		return nil, audit, func() {}
	}
	// The catalog the agent sees is the session's own check table: the
	// session resolves each entry's availability from the configured
	// permissions (no exec, no net, captured sources only), so definitions
	// never advertise a tool the session cannot execute.
	det := &triage.DeterministicTools{
		Caller:  triage.ClientCaller{Client: client},
		Catalog: triage.CatalogFromCheckCatalog(sess.CheckCatalog()),
	}
	audit.Enabled = true
	audit.ToolCount = len(det.Definitions())
	return det, audit, func() { _ = client.Close() }
}

// detAuditEvent renders the per-finding det_tools audit event:
// {enabled, toolchain, tool_count, session_error, limitations} — nil when
// no audit record was produced (defensive; runTriageFinding always sets
// one). attempt numbers the event when it belongs to a stability retry;
// the primary run passes 0 and keeps the field absent.
func detAuditEvent(a *triage.DetToolsAudit, attempt int) []triage.AuditEvent {
	if a == nil {
		return nil
	}
	return []triage.AuditEvent{{Type: triage.AuditEventDetTools, DetTools: a, Attempt: attempt}}
}

// classifyReplayErr maps a replay failure onto the metrics error class:
// drift is a provenance-drift error, anything else a generic replay
// failure — the same channel runTriageFinding's drift class records.
func classifyReplayErr(err error) string {
	if err != nil && strings.Contains(err.Error(), "drift") {
		return triage.RunStageDrift
	}
	return triage.RunStageReplay
}

// runTriageReplay re-renders one recorded run directory without any LLM
// call or network access — and never reads the repository the snapshot
// names; drift against a live tree is the separate VerifySnapshotDrift
// opt-in. Verification (recorded hashes, response decode) and composition
// live in PrepareReplay; a technical error means the replay failed, never
// a different verdict. The new report lands in a fresh directory under
func runTriageReplay(dir, outDir string, failOn []triage.FailOn, vex bool, legacyUnbound bool) error {
	ctx := context.Background()
	started := time.Now()
	rep, err := triage.PrepareReplayWithOptions(ctx, dir, triage.ReplayOptions{AllowLegacyUnboundBinding: legacyUnbound})
	rec := triage.RunRecord{FindingID: rep.FindingID, ReplayAttempted: true, WallTimeMS: time.Since(started).Milliseconds()}
	if err != nil {
		rec.Failed, rec.ErrorClass = true, classifyReplayErr(err)
		_, _, _ = triage.WriteMetrics(ctx, outDir, []triage.RunRecord{rec})
		if errors.Is(err, triage.ErrUnsupportedLiveSchema) {
			return exitErr(triage.ExitCodeError, fmt.Errorf("triage: replay refused a historical live artifact: %w; historical extraction remains available only through the offline readers — re-record the run with the current schemas to replay it", err))
		}
		return exitErr(triage.ExitCodeError, err)
	}
	rec.ReplayOK = true
	rec.Assessment = &rep.Assessment
	if rep.Decision != nil {
		rec.Decision = rep.Decision
	}
	if rep.Stability != nil {
		rec.Stability = &rep.Stability.StabilityReport
	}
	writer := triage.ArtifactWriter{Stdout: os.Stdout}
	rart, err := writer.WriteReplay(ctx, outDir, rep)
	if err != nil {
		return exitErr(triage.ExitCodeError, err)
	}
	if vex && rep.Decision != nil {
		writeVEXProjection(ctx, writer, rart.RootDir, *rep.Decision)
	}
	if _, mpath, merr := triage.WriteMetrics(ctx, outDir, []triage.RunRecord{rec}); merr != nil {
		fmt.Fprintf(os.Stderr, "triage: cannot write metrics artifact: %v\n", merr)
	} else {
		fmt.Fprintf(os.Stderr, "triage: metrics -> %s\n", mpath)
	}
	fmt.Fprintf(os.Stderr, "triage: replayed %s -> %s\n", rep.SourceDir, outDir)
	var decisions []triage.DecisionPackage
	if rep.Decision != nil {
		decisions = append(decisions, *rep.Decision)
	}
	switch code := triage.ExitCode(nil, decisions, 0, failOn); code {
	case triage.ExitCodePolicy:
		return exitErr(triage.ExitCodePolicy, errors.New("triage: --fail-on policy threshold hit; see the replay report under --out"))
	case triage.ExitCodeError:
		return exitErr(triage.ExitCodeError, errors.New("triage: invalid --fail-on threshold"))
	}
	return nil
}

// canonicalOutDir resolves out to an absolute path with every existing
// ancestor symlink expanded, so containment checks against canonical
// repository roots cannot be dodged by a symlinked --out parent.
func canonicalOutDir(out string) (string, error) {
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	var rest []string
	for dir := abs; ; {
		resolved, rerr := filepath.EvalSymlinks(dir)
		if rerr == nil {
			for i := len(rest) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, rest[i])
			}
			return resolved, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs, nil
		}
		rest = append(rest, filepath.Base(dir))
		dir = parent
	}
}

// dirContains reports whether dir is root itself or a descendant of it.
// Both arguments are canonical absolute paths.
func dirContains(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
