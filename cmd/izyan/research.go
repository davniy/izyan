package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/advfeed"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/research"
 "github.com/fedorovmv/izyan/internal/rootcause"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// researchOpts mirrors the `izyan research` flag surface (design §3).
type researchOpts struct {
	snapshot                     string
	cve                          string
	advisoryDir                  string
	advisoryFile                 string
	outputDir                    string
	detTimeout                   time.Duration
	overall                      time.Duration
	extSHA                       string
	analysisGo                   string
	goos                         string
	goarch                       string
	buildTags                    stringList
	modcache                     string
	buildCacheDir                string
	govulndb                     string
	decisionReady                bool
	replayDecisionDir            string
	detOnly                      bool
	replayDir                    string
	artifactPath                 string
	artifactURL                  string
	artifactCredsEnv             string
	artifactCache                string
	artifactTimeout              time.Duration
	artifactDownload             int64
	artifactExtracted            int64
	artifactMaxEntries           int
	releaseMetadata              string
	declaredAssumptions          string
	implementationLocusProposals string
	exploitLocusProposals        string
	ticket                       string
	ticketID                     string
	osvFeed                      string
	osvURL                       string
	osvURLSet                    bool
	osvCacheDir                  string
	osvDumpTTL                   time.Duration
	osvNoProxy                   bool
	corpusDigest                 string
	corpusCapturedAt             string
	recordPins                   stringList
	attributionFile              string
 fixSourceCaptures string
}

func researchFlags(fs *flag.FlagSet, o *researchOpts) {
	fs.StringVar(&o.snapshot, "snapshot", "", "path to the source snapshot (required)")
	fs.StringVar(&o.cve, "cve", "", "CVE-/GO-/GHSA- id to research (required)")
	fs.StringVar(&o.advisoryDir, "advisory-dir", "", "frozen advisory directory (<dir>/<id>.json)")
	fs.StringVar(&o.advisoryFile, "advisory-file", "", "frozen advisory JSON file (exactly one of --advisory-dir/--advisory-file required)")
	fs.StringVar(&o.outputDir, "output-dir", "", "report/artifact destination (required; the only writable location)")
	fs.DurationVar(&o.detTimeout, "deterministic-timeout", 15*time.Minute, "per-tool wall-clock bound inside the strict session (default covers a measured govulncheck source-scan of a ~1700-package vendored closure)")
	fs.DurationVar(&o.overall, "overall-timeout", 20*time.Minute, "wall-clock bound for the whole run")
	fs.StringVar(&o.extSHA, "external-commit-sha", "", "controller-supplied snapshot identity; absent = local git rev-parse HEAD")
	fs.StringVar(&o.analysisGo, "analysis-go", "", "analysis toolchain version (empty = local go)")
	fs.StringVar(&o.goos, "goos", "", "target platform GOOS (default: host)")
	fs.StringVar(&o.goarch, "goarch", "", "target platform GOARCH (default: host)")
	fs.Var(&o.buildTags, "build-tags", "comma-separated build tags")
	fs.StringVar(&o.modcache, "modcache", "", "per-run confined module cache root (omitted = dep source reads may be UNSUPPORTED/UNKNOWN)")
	fs.StringVar(&o.buildCacheDir, "build-cache-dir", "", "per-run confined Go build cache root exported as GOCACHE (omitted = the platform default cache is pinned; keep it warm across runs — a cold cache rebuilds the whole dependency closure)")
	fs.StringVar(&o.govulndb, "govulndb", "", "frozen govulndb root (omitted = govulncheck is UNSUPPORTED)")
	fs.BoolVar(&o.detOnly, "deterministic-only", false, "select the historical deterministic decision-artifact probe (requires --decision-ready)")
	fs.StringVar(&o.replayDir, "replay-agent-turn", "", "rebuild the agent turn from a persisted run directory instead of calling the model")
	fs.BoolVar(&o.decisionReady, "decision-ready", false, "historical decision-artifact probe; requires --deterministic-only (no model)")
	fs.StringVar(&o.replayDecisionDir, "replay-decision-run", "", "replay a persisted decision-ready run directory (flow-result.json + verification-observations.jsonl) without any model call")
	fs.StringVar(&o.artifactPath, "artifact", "", "release artifact (Go binary or ZIP distribution) whose embedded build info is AUTHORITATIVE release evidence; mutually exclusive with --artifact-url")
	fs.StringVar(&o.artifactURL, "artifact-url", "", "HTTPS URL of the release artifact; credentials come only from --artifact-credentials-env (Basic auth, never logged or persisted)")
	fs.StringVar(&o.artifactCredsEnv, "artifact-credentials-env", repository.DefaultArtifactCredentialsEnv, "environment variable holding username:password for --artifact-url (Basic auth; its value is never printed or persisted)")
	fs.StringVar(&o.artifactCache, "artifact-cache-dir", "", "content-addressed artifact cache directory (default OS temp cache; never inside --output-dir or the snapshot)")
	fs.DurationVar(&o.artifactTimeout, "artifact-timeout", 0, "release-artifact acquisition bound (default 10m ceiling; 0 = default)")
	fs.Int64Var(&o.artifactDownload, "artifact-max-download-bytes", 0, "download size cap (default 2 GiB; 0 = default)")
	fs.Int64Var(&o.artifactExtracted, "artifact-max-extracted-bytes", 0, "archive extraction cap (default 8 GiB; 0 = default)")
	fs.IntVar(&o.artifactMaxEntries, "artifact-max-entries", 0, "archive entry-count cap (default 20000; 0 = default)")
	fs.StringVar(&o.releaseMetadata, "release-metadata", "", "release-metadata/1 JSON document (ticket/SBOM release facts: go_version, modules, artifact_sha256)")
	fs.StringVar(&o.declaredAssumptions, "declared-assumptions", "", "declared-assumptions/1 JSON document carrying operator policy/scope inputs (config-trust, supported-targets); assumptions are inputs, not evidence")
	fs.StringVar(&o.implementationLocusProposals, "implementation-locus-proposal", "", "implementation-locus-proposals/1 JSON artifact carrying LLM-inferred implementation-locus hypotheses the deterministic axis re-checks (never evidence, never a verdict)")
	fs.StringVar(&o.exploitLocusProposals, "exploit-locus-proposal", "", "exploit-locus-proposals/1 JSON artifact carrying LLM-inferred vulnerable-locus/sink/trigger hypotheses for a symbol-less advisory; the deterministic binder re-checks every member (never evidence, never a verdict)")
	fs.StringVar(&o.ticket, "ticket", "", "tracker ticket (JSON ticket/array or plain text, '-' for stdin) carrying the ticket's claims (package, version, component, product, release); enables the ticket-build identity check")
	fs.StringVar(&o.ticketID, "ticket-id", "", "ticket key/id to select when --ticket input contains multiple tickets")
	fs.StringVar(&o.osvFeed, "osv-feed", "", "offline OSV dump (directory of OSV JSON or a zip archive) used to complete advisories that declare no package/symbol subjects")
	fs.StringVar(&o.osvURL, "osv-url", "", "OSV dump source base URL (<base>/<ecosystem>/all.zip + <base>/ecosystems.txt; env IZYAN_OSV_URL; empty value = the public OSV dump host)")
	fs.StringVar(&o.osvCacheDir, "osv-cache-dir", "", "cached dump directory for --osv-url (default per-user cache; never inside --output-dir)")
	fs.DurationVar(&o.osvDumpTTL, "osv-dump-ttl", 7*24*time.Hour, "max age of a cached OSV dump before a forced re-download (0 = freshness by length probe only)")
	fs.BoolVar(&o.osvNoProxy, "osv-no-proxy", false, "fetch the OSV dump without http_proxy/https_proxy (default honours the environment)")
	fs.StringVar(&o.corpusDigest, "corpus-digest", "", "declared sha256 of the advisory corpus (requires --corpus-captured-at)")
	fs.StringVar(&o.corpusCapturedAt, "corpus-captured-at", "", "declared RFC3339 corpus capture date")
	fs.Var(&o.recordPins, "record-pin", "select exact record bytes as <record-id>=<sha256> (repeatable)")
	fs.StringVar(&o.attributionFile, "attribution-file", "", "pinned attribution-captures/1 manifest")
 fs.StringVar(&o.fixSourceCaptures,"fix-source-captures","","strict fix-source-captures.v1 local manifest (captured-only artifacts)")
}

// artifactOptionsFromFlags validates the release-artifact flag set and
// builds the bounded channel options. Mutual exclusion and negative
// bounds are CLI usage errors — they fail before any output exists,
// exactly like the advisory source flags; every channel-level failure
// (bad URL, missing credentials, unsafe archive, unreadable build info)
// stays inside the lane and records a named NOT_RUN reason.
func artifactOptionsFromFlags(o *researchOpts) (repository.ArtifactOptions, error) {
	if o.artifactPath != "" && o.artifactURL != "" {
		return repository.ArtifactOptions{}, fmt.Errorf("--artifact and --artifact-url are mutually exclusive")
	}
	if o.artifactURL != "" {
		u, err := url.Parse(o.artifactURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return repository.ArtifactOptions{}, fmt.Errorf("--artifact-url must be an HTTPS URL without userinfo")
		}
		if o.artifactCredsEnv == "" {
			return repository.ArtifactOptions{}, fmt.Errorf("--artifact-url requires --artifact-credentials-env")
		}
	}
	if o.artifactTimeout < 0 || o.artifactDownload < 0 || o.artifactExtracted < 0 || o.artifactMaxEntries < 0 {
		return repository.ArtifactOptions{}, fmt.Errorf("--artifact-* bounds must be non-negative (0 = channel default)")
	}
	return repository.ArtifactOptions{
		Path: o.artifactPath, URL: o.artifactURL, CredentialsEnv: o.artifactCredsEnv,
		CacheDir: o.artifactCache, Timeout: o.artifactTimeout,
		MaxDownloadBytes: o.artifactDownload, MaxExtractedBytes: o.artifactExtracted,
		MaxArchiveEntries: o.artifactMaxEntries,
	}, nil
}

// DefaultOSVDumpURL is the public OSV export serving the standard dump
// layout (<base>/<ecosystem>/all.zip + <base>/ecosystems.txt). It is the
// default base for a remote feed, never hardcoded into requests: the
// remote feed is consulted only when --osv-url or IZYAN_OSV_URL
// configures it, and a deployment points either at its own mirror.
const DefaultOSVDumpURL = "https://osv-vulnerabilities.storage.googleapis.com"

// osvURLEnv names the environment variable carrying the OSV dump source
// base URL for the research lane.
const osvURLEnv = "IZYAN_OSV_URL"

// feedOptionsFromFlags resolves the advisory-feed flag set into lane
// options. The feed is disabled entirely unless --osv-feed, an explicit
// --osv-url, or IZYAN_OSV_URL names a source; the deterministic lane
// stays offline by default. Mutual exclusion and negative bounds fail
// before any output exists, exactly like the advisory source flags.
func feedOptionsFromFlags(o *researchOpts) (*advfeed.Options, error) {
	if o.osvDumpTTL < 0 {
		return nil, fmt.Errorf("--osv-dump-ttl must be non-negative (0 = freshness by length probe only)")
	}
	envURL := strings.TrimSpace(os.Getenv(osvURLEnv))
	switch {
	case o.osvFeed != "" && o.osvURLSet:
		return nil, fmt.Errorf("--osv-feed and --osv-url are mutually exclusive")
	case o.osvFeed != "":
		return &advfeed.Options{LocalPath: o.osvFeed, Ecosystem: advfeed.EcosystemGo}, nil
	case o.osvURLSet || envURL != "":
		base := o.osvURL
		if base == "" {
			base = envURL
		}
		if base == "" {
			base = DefaultOSVDumpURL
		}
		return &advfeed.Options{
			BaseURL:   base,
			Ecosystem: advfeed.EcosystemGo,
			CacheDir:  o.osvCacheDir,
			DumpTTL:   o.osvDumpTTL,
			NoProxy:   o.osvNoProxy,
		}, nil
	}
	if o.osvCacheDir != "" || o.osvNoProxy {
		return nil, fmt.Errorf("--osv-cache-dir/--osv-no-proxy require --osv-url or " + osvURLEnv)
	}
	return nil, nil
}

// releaseEvidenceManifest projects the lane's resolved release evidence
// into the run manifest. nil when no channel ran — legacy manifests stay
// byte-identical. The projection carries digests, statuses, and items
// only: URLs and credential values can never appear in it by shape.
func releaseEvidenceManifest(lane *research.LaneResult) any {
	return research.LaneReleaseEvidence(lane)
}

// sanitizeURL strips userinfo, query and fragment so a recorded option
// can never carry credential material even if a caller embeds it.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func runResearch(args []string) error {
	fs := flag.NewFlagSet("research", flag.ExitOnError)
	var o researchOpts
	researchFlags(fs, &o)
	rest := args
	// stringList needs the comma form too: `--build-tags a,b`.
	fs.Parse(rest)
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "osv-url" {
			o.osvURLSet = true
		}
	})
	if o.snapshot == "" || o.cve == "" || o.outputDir == "" {
		return fmt.Errorf("--snapshot, --cve and --output-dir are required")
	}
	if (o.advisoryDir == "") == (o.advisoryFile == "") {
		return fmt.Errorf("exactly one of --advisory-dir and --advisory-file is required")
	}
	if o.replayDir != "" && o.detOnly {
		return fmt.Errorf("--replay-agent-turn cannot be combined with --deterministic-only")
	}
	if o.detOnly && !o.decisionReady {
		return fmt.Errorf("--deterministic-only selects the historical --decision-ready probe; ordinary research is already offline")
	}
	if o.decisionReady && !o.detOnly && o.replayDecisionDir == "" {
		return fmt.Errorf("--decision-ready requires --deterministic-only or --replay-decision-run; live research is retired")
	}
	artOpts, aerr := artifactOptionsFromFlags(&o)
	if aerr != nil {
		return aerr
	}
	feedOpts, ferr := feedOptionsFromFlags(&o)
	if ferr != nil {
		return ferr
	}
	corpusOptions, materials, err := researchCorpusOptions(&o, feedOpts)
	if err != nil {
		return err
	}
	// The strict evidence session reads its build-cache declaration from
	// BuildCacheDirEnv (lane options carry no field): set it once for the
	// whole process so every route — legacy, replay and decision-ready —
	// pins the same GOCACHE root.
	if o.buildCacheDir != "" {
		if err := os.Setenv(evidencetools.BuildCacheDirEnv, o.buildCacheDir); err != nil {
			return fmt.Errorf("--build-cache-dir: %w", err)
		}
	}
	if o.decisionReady || o.replayDecisionDir != "" {
  if o.fixSourceCaptures!="" {return fmt.Errorf("--fix-source-captures requires canonical research, not historical decision routes")}
		if o.corpusDigest != "" || o.corpusCapturedAt != "" || len(o.recordPins) != 0 || o.attributionFile != "" {
			return fmt.Errorf("corpus declaration, record selection and attribution flags require current canonical research, not the historical decision-artifact probe")
		}
		return runDecisionResearch(o, artOpts, feedOpts)
	}

	// ---- replay: verify the persisted turn before any other work so a
	// corrupt or unreadable replay dir fails closed — nothing is emitted.
	var replayTurn *research.AgentTurn
	if o.replayDir != "" {
		var rerr error
		replayTurn, rerr = research.LoadPersistedAgentTurn(o.replayDir)
		if rerr != nil {
			return fmt.Errorf("replay-agent-turn: %w", rerr)
		}
	}
	outAbs, err := filepath.Abs(o.outputDir)
	if err != nil {
		return fmt.Errorf("output dir: %w", err)
	}
	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return fmt.Errorf("output dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.overall)
	defer cancel()
	started := time.Now()
	runID := fmt.Sprintf("research-%s-%d", sanitizeID(o.cve), started.Unix())

	// ---- deterministic lane (always runs first) ----
	laneStarted := started
 var captures *rootcause.SourceCaptureSet
 if o.fixSourceCaptures!="" {captures,err=rootcause.LoadSourceCaptures(o.fixSourceCaptures);if err!=nil{return fmt.Errorf("fix-source captures: %w",err)}}
	laneOptions := research.LaneOptions{
  FixSourceCaptures: captures,
		CVE:                          o.cve,
		SnapshotPath:                 o.snapshot,
		AdvisoryFile:                 o.advisoryFile,
		AdvisoryDir:                  o.advisoryDir,
		OutputDir:                    outAbs,
		ExternalCommitSHA:            o.extSHA,
		AnalysisGo:                   o.analysisGo,
		GOOS:                         o.goos,
		GOARCH:                       o.goarch,
		BuildTags:                    o.buildTags,
		ModCache:                     o.modcache,
		GovulnDB:                     o.govulndb,
		Timeout:                      o.detTimeout,
		ArtifactOptions:              artOpts,
		ReleaseMetadata:              o.releaseMetadata,
		DeclaredAssumptions:          o.declaredAssumptions,
		Ticket:                       o.ticket,
		TicketID:                     o.ticketID,
		AdvisoryFeed:                 feedOpts,
		Corpus:                       corpusOptions,
		RequestContract:              true,
		ImplementationLocusProposals: o.implementationLocusProposals,
		ExploitLocusProposals:        o.exploitLocusProposals,
		RetainedProposals:            retainedProposals(replayTurn),
		RetainedExploitProposals:     retainedExploitProposals(replayTurn),
		RetainedAnswerSHA256:         retainedAnswerSHA(replayTurn),
	}
	lane, es, err := research.RunDeterministicSession(ctx, laneOptions)
	if err != nil {
		return fmt.Errorf("deterministic lane: %w", err)
	}
	// The strict confined session stays open across the agent turn and
	// the bounded verification phase; it is closed exactly once, after
	// report assembly. defer guarantees close-on-error on every path.
	sessionClosed := false
	closeSession := func() {
		if !sessionClosed && es != nil {
			_ = es.Close()
			sessionClosed = true
		}
	}
	defer closeSession()
	laneFinished := time.Now()

	// A retained turn is the only agent-material source; no harness is launched.
	releaseNotRun, releaseReason := research.LaneReleaseNotRun(lane)
	var turn *research.AgentTurn
	if replayTurn != nil {
		// Rebuild from persisted artifacts: the recorded agent_output and
		// attempt ledger row are preserved verbatim; run.harness stays
		// null — no harness/model call happened in this run.
		turn = replayTurn
	}
	finished := time.Now()

	// ---- bounded verification phase over the same strict session ----
	// Runs only when the (live or replayed) answer carries a plan that
	// validates against the session's real confinement roots. Everything
	// else stays INCONCLUSIVE via VerifyDecision — an absent, malformed
	// or rejected proposal is never promoted and never executed.
	var trace *research.VerificationTrace
	var obsIndex map[string][]string
	var verifArts map[string]research.ArtifactRef
	var verifPlan *research.VerificationPlan
	planStatus := "no agent turn"
	if releaseNotRun {
		planStatus = "release evidence channel failed closed: NOT_RUN (" + releaseReason + ")"
	}
	if turn != nil && turn.Answer != nil {
		verifPlan = turn.Answer.VerificationPlan
	}
	if verifPlan == nil && turn != nil {
		planStatus = "no verification plan in the retained answer"
	}
	if verifPlan != nil {
		if verr := research.ValidateVerificationPlan(*verifPlan,
			es.Session().SnapshotRoot, es.AdvisoryRoots()); verr != nil {
			planStatus = "verification plan rejected by confinement validation: " + verr.Error()
			// The falsifier is preserved but never executed; the decision
			// records the missing trace rather than the rejection string.
			verifPlan = nil
		}
	}
	if verifPlan != nil {
		planStatus = "executed"
		var terr error
		trace, terr = research.RunVerificationPlanAudited(ctx, es.CallWithAudit, *verifPlan, len(verifPlan.Checks))
		if terr != nil {
			return fmt.Errorf("verification plan execution: %w", terr)
		}
	}
	// Drain the session audit for exactly this phase: the lane already
	// consumed its own records, so what remains is the verification
	// call provenance (empty when no plan ran).
	audit := es.DrainAudit()
	if trace != nil && len(trace.Observations) > 0 {
		// Trace observations carry session-minted ids in the same
		// OBS-#### space the lane uses; renumber them past the lane's
		// sequence before persistence so persisted ids stay unique
		// (the same convention the lane applies to session results).
		renumberVerification(trace, audit, lane)
		obsIndex = research.VerificationObservationIndex(trace, audit)
		var perr error
		verifArts, perr = writeVerificationArtifacts(outAbs, trace, audit)
		if perr != nil {
			return fmt.Errorf("verification artifacts: %w", perr)
		}
	}
	if err := writeVerificationFacts(outAbs, verifPlan, planStatus, trace, obsIndex, verifArts); err != nil {
		return fmt.Errorf("verification facts: %w", err)
	}

	var proposal *research.FalsifierProposal
	if verifPlan != nil {
		proposal = &verifPlan.Falsifier
	}
	decision, derr := research.VerifyDecision(ctx, research.DecisionInput{
		Lane:             lane,
		Proposal:         proposal,
		Trace:            trace,
		Audit:            audit,
		AgentTurn:        turn,
		ObservationIndex: obsIndex,
	})
	if derr != nil {
		return fmt.Errorf("verification decision: %w", derr)
	}
	// The deterministic lane's own bounded symbol-unreachability attempt
	// is a proposal-free authority evaluation over the lane-recorded
	// observations: a complete proof's decision stands on its own, and
	// when the proposal route stayed INCONCLUSIVE the lane's decision is
	// the better record — it names the reachable symbol or the open gap
	// the primitive reported. A proposal-path terminal decision is never
	// suppressed by the lane's INCONCLUSIVE.
	if lane.SymbolProof != nil {
		if lp := lane.SymbolProof.Decision; lp.Verdict != domain.VerdictInconclusive || decision.Verdict == domain.VerdictInconclusive {
			decision = lp
			trace = lane.SymbolProof.Trace
		}
	}
	if err := publishResearchRequest(ctx, lane, laneOptions, materials); err != nil {
		return fmt.Errorf("requested finding publication: %w", err)
	}
	report := research.Assemble(research.AssembleInput{
		Lane:              lane,
		Turn:              turn,
		Decision:          &decision,
		Trace:             trace,
		VerifArtifacts:    verifArts,
		DeterministicOnly: true,
		RunID:             runID,
		StartedAt:         started,
		FinishedAt:        finished,
		Timeouts: research.TimeoutInfo{
			OverallMs:       o.overall.Milliseconds(),
			DeterministicMs: o.detTimeout.Milliseconds(),
			AgentMs:         0,
		},
		LaneStartedAt:  laneStarted,
		LaneFinishedAt: laneFinished,
	})
	// All session work is done: verification consumed the confined
	// session and the report holds only its persisted records.
	closeSession()
	// ---- emit ----
	jb, err := research.RenderJSON(report)
	if err != nil {
		return fmt.Errorf("render report.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outAbs, "report.json"), append(jb, '\n'), 0o644); err != nil {
		return err
	}
	md, err := research.RenderMarkdown(report)
	if err != nil {
		return fmt.Errorf("render report.md: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outAbs, "report.md"), md, 0o644); err != nil {
		return err
	}
	if err := writeRunManifest(outAbs, o, runID, started, finished, lane, turn, verifPlan, planStatus, &decision); err != nil {
		return fmt.Errorf("run manifest: %w", err)
	}
	if err := research.Validate(report, outAbs); err != nil {
		fmt.Fprintln(os.Stderr, "warning: emitted report failed self-validation:")
		fmt.Fprintln(os.Stderr, err)
		// The caller must see why validation failed: a bare "failed" hides
		// the problems list the validator produced.
		return fmt.Errorf("report self-validation failed: %w", err)
	}
	fmt.Printf("research %s: report.json + report.md written to %s (disposition %s, agent %s)\n",
		o.cve, outAbs, report.Disposition.Class, report.AgentOutput.Status)
	return nil
}

func nilStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func retainedProposals(turn *research.AgentTurn) []domain.ImplementationLocusProposal {
	if turn == nil {
		return nil
	}
	return turn.ImplementationLocusProposals()
}

func retainedExploitProposals(turn *research.AgentTurn) []domain.ExploitLocusProposal {
	if turn == nil {
		return nil
	}
	return turn.ExploitLocusProposals()
}

func retainedAnswerSHA(turn *research.AgentTurn) string {
	if turn == nil || turn.Output.ReplayedFrom == nil {
		return ""
	}
	return turn.Output.ReplayedFrom.AnswerSHA256
}

// writeRunManifest records the run's pins: snapshot/advisory digests,
// prompt file + sha, harness environment facts, and the agent record —
// the audit trail the design requires (§2 harness patch record, §8
// prompt pin).
func writeRunManifest(outAbs string, o researchOpts, runID string, started, finished time.Time,
	lane *research.LaneResult, turn *research.AgentTurn,
	plan *research.VerificationPlan, planStatus string, decision *research.EvidenceDecision) error {
	m := map[string]any{
		"schema":   "research-run-manifest/1",
		"run_id":   runID,
		"started":  started.UTC().Format(time.RFC3339),
		"finished": finished.UTC().Format(time.RFC3339),
		"snapshot": snapshotManifest(o, lane),
		"advisory": advisoryManifest(lane),
		"agent":    agentManifest(o, turn, lane),
		"options":  optionsManifest(o),
	}
	// The release-evidence provenance member is absent entirely when no
	// channel ran — the manifest schema stays research-run-manifest/1 and
	// legacy manifests keep their exact byte shape.
	if rev := releaseEvidenceManifest(lane); rev != nil {
		m["release_evidence"] = rev
	}
	if turn != nil {
		m["agent_manifest"] = turn.Manifest
	}
	m["verification"] = verificationManifest(plan, planStatus, decision)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outAbs, "run-manifest.json"), append(b, '\n'), 0o644)
}

// verificationManifest records the bounded verification phase: whether a
// plan ran, why not when it did not, and the decision it produced. It
// pins names, never verdicts — the report's decision object is the
// authoritative record.
func verificationManifest(plan *research.VerificationPlan, planStatus string,
	decision *research.EvidenceDecision) map[string]any {
	v := map[string]any{
		"plan_status": planStatus,
		"executed":    plan != nil,
		"artifacts":   []string{"verification-observations.jsonl", "verification-facts.json"},
	}
	if plan != nil {
		v["falsifier_kind"] = string(plan.Falsifier.Kind)
		v["condition_id"] = plan.Falsifier.ConditionID
		v["checks"] = len(plan.Checks)
	}
	if decision != nil {
		v["decision_verdict"] = string(decision.Verdict)
		v["decision_reason"] = decision.Reason
	}
	return v
}

func snapshotManifest(o researchOpts, lane *research.LaneResult) map[string]any {
	return map[string]any{
		"path":                lane.SnapshotRoot,
		"content_hash":        lane.ContentHash,
		"commit_sha":          lane.Snapshot.Commit,
		"external_commit_sha": o.extSHA,
	}
}

func advisoryManifest(lane *research.LaneResult) map[string]any {
	in := lane.Advisory.Input
	m := map[string]any{
		"requested_id":     in.RequestedID,
		"resolved_id":      in.ResolvedID,
		"source_kind":      in.SourceKind,
		"source_path":      in.SourcePath,
		"raw_sha256":       in.RawSHA256,
		"canonical_sha256": in.CanonicalSHA256,
		"outcome":          lane.Advisory.Outcome,
	}
	if in.FeedResolution != nil {
		m["feed_resolution"] = in.FeedResolution
	}
	return m
}

func agentManifest(o researchOpts, turn *research.AgentTurn, lane *research.LaneResult) map[string]any {
	// Replayed identity comes only from the saved turn.
	model, provider := "", ""
	if turn != nil {
		if turn.Model != "" {
			model = turn.Model
		}
		if turn.Provider != "" {
			provider = turn.Provider
		}
	}
	out := map[string]any{
		"model":    model,
		"provider": provider,
	}
	if turn != nil {
		out["status"] = turn.Output.Status
		out["error"] = turn.Err
		out["manifest"] = turn.Manifest
	} else {
		out["status"] = research.AgentNotRequested
		// A fail-closed release-evidence channel is an explicit skip, not
		// an absent turn: the manifest names the channel's own reason.
		if notRun, reason := research.LaneReleaseNotRun(lane); notRun {
			out["skipped_reason"] = "release evidence channel failed closed: NOT_RUN (" + reason + ")"
		}
	}
	if o.replayDir != "" {
		out["replayed_from"] = o.replayDir
	}
	return out
}

func optionsManifest(o researchOpts) map[string]any {
	m := map[string]any{
		"goos": o.goos, "goarch": o.goarch, "build_tags": []string(o.buildTags),
		"analysis_go": o.analysisGo, "modcache": o.modcache, "govulndb": o.govulndb,
		"build_cache_dir":       o.buildCacheDir,
		"deterministic_only":    true,
		"deterministic_timeout": o.detTimeout.String(),
		"overall_timeout":       o.overall.String(),
		"replay_agent_turn":     o.replayDir,
	}
	if o.corpusDigest != "" {
		m["corpus_digest"] = o.corpusDigest
		m["corpus_captured_at"] = o.corpusCapturedAt
	}
	if len(o.recordPins) != 0 {
		m["record_pins"] = []string(o.recordPins)
	}
	if o.attributionFile != "" {
		m["attribution_file"] = repository.ProvenanceLocalRef(o.attributionFile)
	}
	if o.decisionReady {
		m["decision_ready"] = true
	}
	if o.replayDecisionDir != "" {
		m["replay_decision_run"] = o.replayDecisionDir
	}
	// Release-evidence channel options: provenance only — the artifact
	// URL is sanitized of userinfo/query/fragment and the credentials
	// entry names the env var, never its value.
	if o.artifactPath != "" {
		// Only the basename is recorded: the operator's absolute path is
		// machine-specific and must not leak into the run manifest. The
		// artifact SHA-256, recorded with the release evidence, anchors
		// reproducibility instead.
		m["artifact_path"] = repository.ProvenanceLocalRef(o.artifactPath)
	}
	if o.artifactURL != "" {
		m["artifact_url"] = sanitizeURL(o.artifactURL)
		m["artifact_credentials_env"] = o.artifactCredsEnv
		if o.artifactCredsEnv == "" {
			m["artifact_credentials_env"] = repository.DefaultArtifactCredentialsEnv
		}
	}
	// The cache directory path is deliberately not recorded: it is
	// machine-specific ground, and no consumer needs it.

	if o.artifactTimeout != 0 {
		m["artifact_timeout"] = o.artifactTimeout.String()
	}
	if o.artifactDownload != 0 {
		m["artifact_max_download_bytes"] = o.artifactDownload
	}
	if o.artifactExtracted != 0 {
		m["artifact_max_extracted_bytes"] = o.artifactExtracted
	}
	if o.artifactMaxEntries != 0 {
		m["artifact_max_entries"] = o.artifactMaxEntries
	}
	if o.releaseMetadata != "" {
		m["release_metadata"] = repository.ProvenanceLocalRef(o.releaseMetadata)
	}
	if o.declaredAssumptions != "" {
		// Provenance only: the document's own sha256/ids travel with the
		// lane observation and the report input, never its full text.
		m["declared_assumptions"] = repository.ProvenanceLocalRef(o.declaredAssumptions)
	}
	if o.implementationLocusProposals != "" {
		// Provenance only: the artifact's own sha256 travels with the
		// lane observation and the report input, never its full text.
		m["implementation_locus_proposal"] = repository.ProvenanceLocalRef(o.implementationLocusProposals)
	}
	if o.exploitLocusProposals != "" {
		// Provenance only: the artifact's own sha256 travels with the
		// lane observation and the report input, never its full text.
		m["exploit_locus_proposal"] = repository.ProvenanceLocalRef(o.exploitLocusProposals)
	}
	if o.ticket != "" {
		m["ticket"] = repository.ProvenanceLocalRef(o.ticket)
		if o.ticketID != "" {
			m["ticket_id"] = o.ticketID
		}
	}
	// Advisory-feed options: provenance only — the feed path records its
	// basename, the remote URL is sanitized of userinfo/query/fragment,
	// and the cache directory path is never recorded (machine-specific).
	if o.osvFeed != "" {
		m["osv_feed"] = repository.ProvenanceLocalRef(o.osvFeed)
	}
	if o.osvURLSet || strings.TrimSpace(os.Getenv(osvURLEnv)) != "" {
		base := o.osvURL
		if base == "" {
			base = strings.TrimSpace(os.Getenv(osvURLEnv))
		}
		if base == "" {
			base = DefaultOSVDumpURL
		}
		m["osv_url"] = sanitizeURL(base)
		m["osv_dump_ttl"] = o.osvDumpTTL.String()
		if o.osvNoProxy {
			m["osv_no_proxy"] = true
		}
	}
	return m
}

// ---- bounded verification phase: persistence ----

// renumberVerification moves trace observations (and their audit-record
// copies) out of the session-minted OBS-#### sequence into ids past the
// lane's own numbering — the same convention the deterministic lane
// applies to session results — so every persisted observation id stays
// unique across observations.jsonl and verification-observations.jsonl.
func renumberVerification(trace *research.VerificationTrace, audit []evidencetools.AuditRecord,
	lane *research.LaneResult) {
	maxSeq := 0
	for _, o := range lane.Observations {
		if n, err := strconv.Atoi(strings.TrimPrefix(o.ID, "OBS-")); err == nil && n > maxSeq {
			maxSeq = n
		}
	}
	idmap := map[string]string{}
	for _, o := range trace.Observations {
		if o == nil {
			continue
		}
		maxSeq++
		nid := fmt.Sprintf("OBS-%04d", maxSeq)
		if o.ID != "" {
			idmap[o.ID] = nid
		}
		o.ID = nid
	}
	for _, rec := range audit {
		if rec.Observation != nil {
			if nid, ok := idmap[rec.Observation.ID]; ok {
				rec.Observation.ID = nid
			}
		}
	}
}

// writeVerificationArtifacts persists the verification phase's sibling
// artifacts without touching the deterministic lane's files:
// verification-observations.jsonl carries the session audit records of
// the executed checks, and verification-artifacts/obs-*.json pins each
// observation's canonical payload exactly like the lane's artifacts/.
// It returns the artifact pins keyed by renumbered observation id.
func writeVerificationArtifacts(outAbs string, trace *research.VerificationTrace,
	audit []evidencetools.AuditRecord) (map[string]research.ArtifactRef, error) {
	artDir := filepath.Join(outAbs, "verification-artifacts")
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		return nil, err
	}
	pins := map[string]research.ArtifactRef{}
	for _, o := range trace.Observations {
		if o == nil {
			continue
		}
		payload, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("verification artifact encode %s: %w", o.ID, err)
		}
		name := strings.ToLower(o.ID) + ".json"
		written := append(payload, '\n')
		if err := os.WriteFile(filepath.Join(artDir, name), written, 0o644); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(written)
		pins[o.ID] = research.ArtifactRef{
			Path:   filepath.Join("verification-artifacts", name),
			SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(written)),
			Selector: "verification-observation",
		}
	}
	f, err := os.Create(filepath.Join(outAbs, "verification-observations.jsonl"))
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	for _, rec := range audit {
		if err := enc.Encode(rec); err != nil {
			f.Close()
			return nil, fmt.Errorf("verification-observations.jsonl: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return pins, nil
}

// writeVerificationFacts records what the verification phase did and the
// persistence pins it produced: the executed plan, every check's
// renumbered observation id, and the digest refs pinned for each
// observation — the on-disk mirror of DecisionInput.ObservationIndex so a
// re-run can audit which persistence pins grounded (or refused) the
// decision. It is written on every run that reached the agent stage —
// including no-plan runs — so the audit trail never silently omits the
// phase.
func writeVerificationFacts(outAbs string, plan *research.VerificationPlan, planStatus string,
	trace *research.VerificationTrace, obsIndex map[string][]string,
	arts map[string]research.ArtifactRef) error {
	type checkRec struct {
		ID            string   `json:"id"`
		Tool          string   `json:"tool"`
		ObservationID string   `json:"observation_id,omitempty"`
		Status        string   `json:"status,omitempty"`
		Completeness  string   `json:"completeness,omitempty"`
		Pins          []string `json:"pins,omitempty"`
		Artifact      string   `json:"artifact,omitempty"`
	}
	doc := map[string]any{
		"schema":      "verification-facts/1",
		"executed":    plan != nil,
		"plan_status": planStatus,
	}
	if plan != nil {
		doc["falsifier"] = plan.Falsifier
	}
	if trace != nil {
		checks := []checkRec{}
		for i, req := range trace.Requests {
			c := checkRec{ID: req.ID, Tool: req.Tool}
			if i < len(trace.Observations) && trace.Observations[i] != nil {
				o := trace.Observations[i]
				c.ObservationID = o.ID
				c.Status = string(o.ToolStatus)
				c.Completeness = string(o.Completeness)
				c.Pins = obsIndex[o.ID]
				if a, ok := arts[o.ID]; ok {
					c.Artifact = a.Path
				}
			}
			checks = append(checks, c)
		}
		doc["checks"] = checks
		doc["complete"] = trace.Complete
		if len(trace.Limitations) > 0 {
			doc["limitations"] = trace.Limitations
		}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outAbs, "verification-facts.json"), append(b, '\n'), 0o644)
}

// ---- decision-ready (R6) opt-in route ----

// runDecisionResearch is the --decision-ready entry point: the same
// deterministic lane, then the bounded planner/reassessor flow over the
// same confined evidence session, then the /3 report + decision
// artifact. The legacy route above is untouched; the flag surface only
// gains two opt-in switches. Every failure inside the adapter is a
// recorded, explicit termination — never a silent success.
func runDecisionResearch(o researchOpts, artOpts repository.ArtifactOptions, feedOpts *advfeed.Options) error {
	if o.replayDir != "" {
		return fmt.Errorf("--replay-agent-turn cannot be combined with --decision-ready/--replay-decision-run")
	}
	if o.replayDecisionDir != "" && o.detOnly {
		return fmt.Errorf("--replay-decision-run cannot be combined with --deterministic-only")
	}
	outAbs, err := filepath.Abs(o.outputDir)
	if err != nil {
		return fmt.Errorf("output dir: %w", err)
	}
	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return fmt.Errorf("output dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.overall)
	defer cancel()
	started := time.Now()
	runID := fmt.Sprintf("research-%s-%d", sanitizeID(o.cve), started.Unix())

	configFS := os.DirFS(".")
	report, rec, err := research.RunDecisionReady(ctx, research.DecisionReadyOptions{
		LaneOptions: research.LaneOptions{
			CVE:                          o.cve,
			SnapshotPath:                 o.snapshot,
			AdvisoryFile:                 o.advisoryFile,
			AdvisoryDir:                  o.advisoryDir,
			ExternalCommitSHA:            o.extSHA,
			AnalysisGo:                   o.analysisGo,
			GOOS:                         o.goos,
			GOARCH:                       o.goarch,
			BuildTags:                    o.buildTags,
			ModCache:                     o.modcache,
			GovulnDB:                     o.govulndb,
			Timeout:                      o.detTimeout,
			ArtifactOptions:              artOpts,
			ReleaseMetadata:              o.releaseMetadata,
			DeclaredAssumptions:          o.declaredAssumptions,
			Ticket:                       o.ticket,
			TicketID:                     o.ticketID,
			AdvisoryFeed:                 feedOpts,
			ImplementationLocusProposals: o.implementationLocusProposals,
			ExploitLocusProposals:        o.exploitLocusProposals,
		},
		ConfigFS:          configFS,
		OutputDir:         outAbs,
		DeterministicOnly: o.detOnly,
		ReplayDir:         o.replayDecisionDir,
		RunID:             runID,
		StartedAt:         started,
	})
	if err != nil {
		return err
	}

	// ---- emit (same file contract as the legacy route) ----
	jb, err := research.RenderJSON(report)
	if err != nil {
		return fmt.Errorf("render report.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outAbs, "report.json"), append(jb, '\n'), 0o644); err != nil {
		return err
	}
	md, err := research.RenderMarkdown(report)
	if err != nil {
		return fmt.Errorf("render report.md: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outAbs, "report.md"), md, 0o644); err != nil {
		return err
	}
	if err := writeDecisionRunManifest(outAbs, o, runID, started, report, rec); err != nil {
		return fmt.Errorf("run manifest: %w", err)
	}
	if err := research.Validate(report, outAbs); err != nil {
		fmt.Fprintln(os.Stderr, "warning: emitted report failed self-validation:")
		fmt.Fprintln(os.Stderr, err)
		// The caller must see why validation failed: a bare "failed" hides
		// the problems list the validator produced.
		return fmt.Errorf("report self-validation failed: %w", err)
	}
	fmt.Printf("research %s: decision-ready report written to %s (termination %s, disposition %s)\n",
		o.cve, outAbs, rec.Result.Termination, report.DecisionArtifact.ProposedDisposition)
	return nil
}

// writeDecisionRunManifest records the decision-ready run's pins: the
// standard snapshot/advisory/options members plus decision_ready —
// flow termination, every driver turn's prompt/harness pins, the
// flow-facts artifact pin and the replay source when present. The
// manifest schema stays research-run-manifest/1.
func writeDecisionRunManifest(outAbs string, o researchOpts, runID string, started time.Time,
	report *research.Report, rec *research.DecisionRunRecord) error {
	m := map[string]any{
		"schema":   "research-run-manifest/1",
		"run_id":   runID,
		"started":  started.UTC().Format(time.RFC3339),
		"finished": time.Now().UTC().Format(time.RFC3339),
		"snapshot": snapshotManifest(o, rec.Lane),
		"advisory": advisoryManifest(rec.Lane),
		"options":  optionsManifest(o),
	}
	// Same gating as the legacy manifest: the member exists only when a
	// release-evidence channel ran.
	if rev := releaseEvidenceManifest(rec.Lane); rev != nil {
		m["release_evidence"] = rev
	}
	dr := map[string]any{
		"schema":      "decision-ready-run/1",
		"objective":   rec.Objective,
		"termination": string(rec.Result.Termination),
		"reason":      rec.Result.Reason,
		"ready":       rec.Result.Ready,
		"turns":       rec.Turns,
		"artifacts":   []string{"flow-result.json", "flow-events.jsonl", "flow-facts.json", "decision-artifact.json", "verification-observations.jsonl"},
	}
	if rec.FactsArtifact.SHA256 != "" {
		dr["flow_facts"] = rec.FactsArtifact
	}
	if rec.ReplayedFrom != "" {
		dr["replayed_from"] = rec.ReplayedFrom
	}
	if report.DecisionArtifact != nil {
		dr["proposed_disposition"] = report.DecisionArtifact.ProposedDisposition
		dr["prompt_digest"] = report.DecisionArtifact.ReplayAndPolicyPins.PromptDigest
		dr["catalog_digests"] = report.DecisionArtifact.ReplayAndPolicyPins.CatalogDigests
	}
	m["decision_ready"] = dr
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outAbs, "run-manifest.json"), append(b, '\n'), 0o644)
}

// researchCorpusOptions reuses the authoritative corpus declaration and byte-selection contracts.
func researchCorpusOptions(o *researchOpts, feed *advfeed.Options) (*advfeed.CorpusOptions, map[string]string, error) {
	materials, err := attributionMaterials(o.attributionFile)
	if err != nil {
		return nil, nil, err
	}
	if feed == nil {
		if o.corpusDigest != "" || o.corpusCapturedAt != "" || len(o.recordPins) != 0 {
			return nil, nil, fmt.Errorf("corpus declaration and --record-pin require an OSV corpus source")
		}
		return nil, materials, nil
	}
	declaration, err := corpusDeclarationFromOptions(advisorySourceOptions{
		CorpusDigest: o.corpusDigest, CorpusCapturedAt: o.corpusCapturedAt,
	}, *feed)
	if err != nil {
		return nil, nil, err
	}
	selections, err := recordSelections(o.recordPins)
	if err != nil {
		return nil, nil, err
	}
	return &advfeed.CorpusOptions{Feed: *feed, Declaration: declaration, Selections: selections}, materials, nil
}

func publishResearchRequest(ctx context.Context, lane *research.LaneResult, options research.LaneOptions, materials map[string]string) error {
	admit := attributionResolver(materials)
	attribute := func(record vulnerability.LoadedRecord) error {
		if !strings.HasPrefix(strings.ToUpper(lane.RequestedID), "CVE-") {
			return nil
		}
		attrs, err := admit(ctx, lane.RequestedID, record)
		if err != nil {
			return err
		}
		lane.Attributions = append(lane.Attributions, attrs...)
		return nil
	}
	if lane.RecordPin != nil {
		record := vulnerability.LoadedRecord{Pin: *lane.RecordPin, Raw: lane.Advisory.RawBytes, Vuln: lane.Advisory.Vuln}
		if err := attribute(record); err != nil {
			return err
		}
		if err := persistResearchRecord(options.OutputDir, record); err != nil {
			return err
		}
	}
	if options.Corpus != nil && lane.Discovery != nil {
		corpus, err := advfeed.AcquireCorpus(ctx, *options.Corpus)
		if err != nil {
			return err
		}
		for i := range lane.Discovery.Candidates {
			candidate := &lane.Discovery.Candidates[i]
			if candidate.Disposition != domain.DispositionNotEvaluated {
				continue
			}
			if ctx.Err() != nil {
				candidate.Disposition = domain.DispositionTimedOut
				candidate.Note = ctx.Err().Error()
				continue
			}
			record, err := corpus.Document(ctx, candidate.Record)
			if err != nil {
				candidate.Disposition = domain.DispositionLoadFailed
				candidate.Note = err.Error()
				continue
			}
			if lane.RecordPin != nil && record.Pin.Same(*lane.RecordPin) {
				continue
			}
			if err := attribute(record); err != nil {
				return err
			}
			if err := persistResearchRecord(options.OutputDir, record); err != nil {
				return err
			}
			childOptions := options
			childOptions.CVE = record.Pin.RecordID
			childOptions.AdvisoryFile = researchRecordPath(options.OutputDir, record.Pin)
			childOptions.AdvisoryDir = ""
			childOptions.OutputDir = filepath.Join(options.OutputDir, "records", strings.TrimPrefix(record.Pin.DocumentDigest, "sha256:"))
			childOptions.Corpus = nil
			childOptions.RecordOnly = true
			childOptions.AdvisoryFeed = nil
			childOptions.DefectSemantics = nil
			childOptions.RetainedProposals = nil
			childOptions.RetainedExploitProposals = nil
			childOptions.RetainedAnswerSHA256 = ""
			childOptions.ImplementationLocusProposals = ""
			childOptions.ExploitLocusProposals = ""
			childLane, err := research.RunDeterministic(ctx, childOptions)
			if err != nil {
				candidate.Disposition = domain.DispositionUnsupported
				candidate.Note = err.Error()
				continue
			}
			childLane.RecordPin = &record.Pin
			child, err := research.RecordCase(childLane)
			if err == nil {
				err = research.FinalizeRecordCase(child)
			}
			if err != nil {
				candidate.Disposition = domain.DispositionUnsupported
				candidate.Note = err.Error()
				continue
			}
			candidate.Disposition = domain.DispositionEvaluated
			lane.RelatedAssessments = append(lane.RelatedAssessments, domain.RelatedRecordAssessment{
				ID: child.ID, Record: record.Pin, Analysis: child,
			})
		}
	}
	primary, err := research.RecordCase(lane)
	if err != nil {
		return err
	}
	if err := lane.PublishRequest(primary); err != nil {
		return err
	}
	return lane.PersistRequestedCase(options.OutputDir)
}

func researchRecordPath(dir string, pin domain.RecordPin) string {
	return filepath.Join(dir, "records", strings.TrimPrefix(pin.DocumentDigest, "sha256:")+".json")
}

func persistResearchRecord(dir string, record vulnerability.LoadedRecord) error {
	if err := record.Pin.Validate(); err != nil {
		return err
	}
	sum := sha256.Sum256(record.Raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != record.Pin.DocumentDigest {
		return fmt.Errorf("exact record bytes differ from pin %s", record.Pin.RecordID)
	}
	if err := os.MkdirAll(filepath.Join(dir, "records"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(researchRecordPath(dir, record.Pin), record.Raw, 0o644)
}
