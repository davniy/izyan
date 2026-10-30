// Package research implements the `izyan research` pipeline: verify a
// pinned product snapshot, resolve the CVE advisory, render the frozen
// plain-agent (B1) prompt, optionally launch one containerized coding-agent
// run against the snapshot, and produce report.md / report.json.
//
// The output is a RESEARCH judgement — an investigation record for a
// developer or an AppSec reviewer. It is never a verified safety
// conclusion and the command never closes a vulnerability: the agent's
// {category, reasoning} answer is carried as data, never converted into
// a verdict.
package research

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/reportcheck"
	"github.com/fedorovmv/izyan/internal/toolaudit"
)

// DefaultAgentImage is the frozen opencode container used by the B1 arm
// (eval/agent7/harness/README.md): no MCP, no izyan tools inside.
const DefaultAgentImage = "vex-bench-go-opencode-custom:latest"

// DefaultModel is the model key used by the B1 experiment runs.
const DefaultModel = "qwen3.6-35b"

// DefaultTimeout bounds one agent run, seconds.
const DefaultTimeout = 900

// DefaultOSVURL is the public OSV API base used when no local advisory
// is supplied.
const DefaultOSVURL = "https://api.osv.dev"

// ContainerWorkdir is where the snapshot is bind-mounted (read-only).
const ContainerWorkdir = "/work"

// Options carries the resolved CLI flags.
type Options struct {
	SnapshotDir string
	CVE         string
	// CaseID is the --case-id controller-side case key (VEX-Bench task id
	// and the like). It becomes report.request.case_id and the
	// reportcheck.json case_id the scorer joins on; empty falls back to
	// the run id.
	CaseID       string
	OutDir       string
	AdvisoryPath string // --advisory: file or dir of OSV JSON documents
	OSVURL       string // advisory fetch base URL; DefaultOSVURL when empty
	NoNet        bool
	Commit       string // --commit override for snapshots without .git
	// SkipContentHash is the eval-only controller escape for snapshots the
	// content-hash tree walk cannot afford (slow VEX-Bench trees).
	// verifySnapshot then runs no repository.Service{}.Snapshot call —
	// no containment walk and no content hash; identity stays
	// commit + path, SnapshotInfo records content_hash "skipped" with
	// algorithm "none" and the run carries a limitation. Default off is
	// byte-identical to the t1-hashed behaviour. --replay-run ignores
	// it: the stored snapshot block is copied verbatim.
	SkipContentHash bool
	Model           string
	AgentImage      string
	AgentEnvFile    string   // optional docker --env-file with provider secrets
	AgentEnv        []string // host env var names forwarded to the container (-e NAME)
	AgentConfig     string   // optional base opencode.json to extend
	Timeout         int      // seconds; 0 → DefaultTimeout
	AllowAgent      bool     // explicit opt-in to launch the container
	DryRun          bool
	// ReplayRun is the --replay-run input: a stored run directory whose
	// dossier is re-rendered with the current consistency code — no
	// container, no network, no model call.
	ReplayRun     string
	DockerBin     string                                                  // docker executable (tests may stub)
	DigestFetcher func(ctx context.Context, image string) (string, error) // tests stub docker inspect
}

// Report is the persisted report.json schema ("izyan-research/2").
type Report struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generated_at"`
	Tool        string `json:"tool"`
	Command     string `json:"command"`
	Mode        string `json:"mode"` // dry_run | planned | executed | failed
	RunID       string `json:"run_id"`
	// RerenderOf names the run this report re-renders: set only by
	// --replay-run, never by a live run.
	RerenderOf    string            `json:"rerender_of,omitempty"`
	ResearchState string            `json:"research_state"` // not_started | incomplete | complete
	Disclaimer    string            `json:"disclaimer"`
	Request       RequestInfo       `json:"request"`
	Snapshot      SnapshotInfo      `json:"snapshot"`
	Advisory      AdvisoryInfo      `json:"advisory"`
	Prompt        PromptInfo        `json:"prompt"`
	Run           RunInfo           `json:"run"`
	Answer        AnswerInfo        `json:"answer"`
	Consistency   ConsistencyReport `json:"consistency"`
	Analysis      Analysis          `json:"analysis"`
	Artifacts     map[string]string `json:"artifacts"`
	AuditLog      string            `json:"audit_log"`
	Limitations   []string          `json:"limitations,omitempty"`
}

// RequestInfo echoes the operator input. CaseID is the optional
// controller-side case key (--case-id); empty means the run id stands in.
type RequestInfo struct {
	SnapshotDir string `json:"snapshot_dir"`
	CVE         string `json:"cve"`
	CaseID      string `json:"case_id,omitempty"`
}

// SnapshotInfo records the verified snapshot identity and file-level
// module-graph facts.
type SnapshotInfo struct {
	Path             string      `json:"path"`
	Commit           string      `json:"commit"`
	IdentitySource   string      `json:"identity_source"` // git_rev_parse | --commit | directory_basename
	ContentHash      string      `json:"content_hash"`
	ContentHashAlg   string      `json:"content_hash_algorithm"`
	GoVersion        string      `json:"go_version,omitempty"`
	GoModDirective   string      `json:"go_mod_directive,omitempty"`
	ReleaseGoVersion string      `json:"release_go_version,omitempty"`
	GoVersionSource  string      `json:"go_version_source,omitempty"`
	Module           ModuleGraph `json:"module_graph"`
}

// ModuleGraph is the file-level (no go command run against the snapshot)
// module-graph summary.
type ModuleGraph struct {
	ModulePath       string   `json:"module_path,omitempty"`
	GoModPresent     bool     `json:"go_mod_present"`
	GoDirective      string   `json:"go_directive,omitempty"`
	Toolchain        string   `json:"toolchain,omitempty"`
	RequireCount     int      `json:"require_count"`
	ReplaceCount     int      `json:"replace_count"`
	LocalReplace     []string `json:"local_replace,omitempty"`
	GoSumEntries     int      `json:"go_sum_entries"`
	GoWorkPresent    bool     `json:"go_work_present"`
	GoWorkUseCount   int      `json:"go_work_use_count,omitempty"`
	VendorModulesTxt bool     `json:"vendor_modules_txt"`
	VendorCount      int      `json:"vendor_module_count,omitempty"`
	Method           string   `json:"method"`
}

// AdvisoryInfo records the resolved advisory identity, digests and the
// affected Go entries the consistency layer checks against.
type AdvisoryInfo struct {
	Status              string             `json:"status"` // resolved | unavailable | skipped_no_net | error
	Source              string             `json:"source,omitempty"`
	Path                string             `json:"path,omitempty"` // stored copy inside the run dossier
	SHA256              string             `json:"sha256,omitempty"`
	DocumentURL         string             `json:"document_url,omitempty"`
	ID                  string             `json:"id,omitempty"`
	Aliases             []string           `json:"aliases,omitempty"`
	Module              string             `json:"module,omitempty"`
	Package             string             `json:"package,omitempty"`
	Summary             string             `json:"summary,omitempty"`
	Modified            string             `json:"modified,omitempty"`
	FixedVersions       []string           `json:"fixed_versions,omitempty"`
	Affected            []AffectedEntry    `json:"affected,omitempty"`
	Documents           []AdvisoryDocument `json:"documents,omitempty"`
	UncomparableEntries int                `json:"uncomparable_entries,omitempty"`
	Reason              string             `json:"reason,omitempty"`
}

// AdvisoryDocument identifies one stored advisory document: the primary
// document and every ecosystem document consulted for Go affected
// entries. Affected entries and consistency entries link back to it.
type AdvisoryDocument struct {
	Role   string `json:"role"` // primary | ecosystem
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Path   string `json:"path"` // stored copy inside the run dossier
	URL    string `json:"url,omitempty"`
	Source string `json:"source,omitempty"` // file:/osv: provenance of the read
}

// AffectedEntry is one advisory affected[] entry reduced to what the
// host-fact consistency layer needs: the module path, its version ranges
// and the declared fixed versions — plus the document it came from.
type AffectedEntry struct {
	Module   string           `json:"module"`
	Packages []string         `json:"packages,omitempty"`
	Ranges   []string         `json:"ranges,omitempty"` // "[introduced, fixed)" notation
	Fixed    []string         `json:"fixed,omitempty"`
	Document AdvisoryDocument `json:"document"` // id + sha256 + path of the source document
}

// PromptInfo records the frozen template identity, the additive rule block
// and the rendered prompt. RuleBlock/RuleBlockSHA256 identify the
// <USE_BASED_VERDICT> block appended after the frozen bytes; they are
// additive-only fields so a report written before the block existed still
// reads cleanly.
type PromptInfo struct {
	Name            string `json:"name"`
	TemplatePath    string `json:"template_path"`
	TemplateSHA256  string `json:"template_sha256"`
	RenderedSHA256  string `json:"rendered_sha256"`
	Placeholder     string `json:"placeholder"`
	Substitutions   int    `json:"substitutions"`
	RuleBlock       string `json:"rule_block,omitempty"`
	RuleBlockSHA256 string `json:"rule_block_sha256,omitempty"`
	Path            string `json:"path,omitempty"`
}

// Mount records one host→container bind mount.
type Mount struct {
	Host      string `json:"host"`
	Container string `json:"container"`
	Mode      string `json:"mode"`
}

// RunInfo records the single container launch (or the planned launch).
type RunInfo struct {
	Status         string      `json:"status"` // planned | skipped | ok | timeout | invalid_answer | error
	Reason         string      `json:"reason,omitempty"`
	AttemptID      string      `json:"attempt_id"`
	Image          string      `json:"image"`
	ImageDigest    string      `json:"image_digest,omitempty"`
	Model          string      `json:"model"`
	ProviderModel  string      `json:"provider_model,omitempty"`
	Argv           []string    `json:"argv"`
	Mounts         []Mount     `json:"mounts"`
	EnvFile        string      `json:"env_file,omitempty"`
	EnvForwarded   []string    `json:"env_forwarded,omitempty"`
	EnvMissing     []string    `json:"env_missing,omitempty"`
	ConfigPath     string      `json:"config_path,omitempty"`
	ConfigSHA256   string      `json:"config_sha256,omitempty"`
	Network        string      `json:"network"`
	Subagents      string      `json:"subagents"`
	MCP            string      `json:"mcp"`
	TimeoutSeconds int         `json:"timeout_seconds"`
	StartedAt      string      `json:"started_at,omitempty"`
	FinishedAt     string      `json:"finished_at,omitempty"`
	WallSeconds    float64     `json:"wall_seconds,omitempty"`
	ContainerExit  *int        `json:"container_exit_code,omitempty"`
	Tokens         *TokenUsage `json:"tokens,omitempty"`
	Error          string      `json:"error,omitempty"`
}

// TokenUsage carries the opencode session token counters when the export
// provides them.
type TokenUsage struct {
	Input      int `json:"input,omitempty"`
	Output     int `json:"output,omitempty"`
	Reasoning  int `json:"reasoning,omitempty"`
	CacheRead  int `json:"cache_read,omitempty"`
	CacheWrite int `json:"cache_write,omitempty"`
}

// AnswerInfo is the official {category, reasoning} contract result.
// Source names the container artifact the raw answer text came from;
// Salvaged marks a category recovered by the deterministic literal scan
// after the structured parse failed — the literal is verbatim agent
// output, never invented, but the {category, reasoning} contract was not
// satisfied (reasoning is empty then).
type AnswerInfo struct {
	Category      string `json:"category"` // research category, never a verdict
	CategoryLabel string `json:"category_label"`
	Reasoning     string `json:"reasoning,omitempty"`
	Parsed        bool   `json:"parsed"`
	Salvaged      bool   `json:"salvaged,omitempty"`
	Source        string `json:"source,omitempty"`
	RawPath       string `json:"raw_answer_path,omitempty"`
	ParseError    string `json:"parse_error,omitempty"`
	AttemptID     string `json:"attempt_id,omitempty"`
}

// Claim is one agent statement bucketed under a research facet.
// PathsFound lists the cited paths that exist in the snapshot — a
// presence check only, never confirmation of what the claim says about
// them; PathsNotFound carries the rest with the failure reason.
type Claim struct {
	Text          string   `json:"text"`
	PathsFound    []string `json:"paths_found,omitempty"`
	PathsNotFound []string `json:"paths_not_found,omitempty"`
}

// PresenceSummary counts the citation presence checks across the whole
// analysis. A found path means the citation resolves inside the snapshot
// — it does not confirm the claim made about that path.
type PresenceSummary struct {
	PathsFound    int    `json:"paths_found"`
	PathsNotFound int    `json:"paths_not_found"`
	Note          string `json:"note"`
}

// ExtractionList carries the extraction state of one claim facet plus the
// recorded items. State is "extracted" when the answer was parsed and
// produced items, "not_established" when the answer was parsed but nothing
// could be extracted, and "not_assessed" when the answer could not be
// assessed at all (no run, failed run or an unparseable answer). An empty
// list is never rendered as "none exist".
type ExtractionList struct {
	State string   `json:"state"` // extracted | not_established | not_assessed
	Items []string `json:"items"`
}

// Fact is a host-confirmed fact bound to this attempt and snapshot.
type Fact struct {
	Statement    string `json:"statement"`
	Reference    string `json:"reference"`
	Source       string `json:"source"` // snapshot | advisory | prompt | run
	Attempt      string `json:"attempt"`
	SnapshotHash string `json:"snapshot_hash"`
}

// AdvisoryMechanism carries the advisory's own description of the
// vulnerability — the reference the agent's mechanism claim is shown
// against. Summary is the advisory's one-line statement; DetailsExcerpt
// is a bounded prefix of the advisory details (never the agent's
// wording). Source names the document the text came from.
type AdvisoryMechanism struct {
	Source         string `json:"source"` // advisory document id
	Summary        string `json:"summary,omitempty"`
	DetailsExcerpt string `json:"details_excerpt,omitempty"`
	DetailsCut     bool   `json:"details_truncated,omitempty"`
}

// Analysis separates confirmed facts, agent claims, assumptions and
// unknowns. Agent claims are never promoted into confirmed facts.
type Analysis struct {
	AdvisoryMechanism       *AdvisoryMechanism `json:"advisory_mechanism,omitempty"`
	Mechanism               string             `json:"mechanism,omitempty"`
	RootCause               string             `json:"root_cause,omitempty"`
	AffectedImplementations []Claim            `json:"affected_implementations,omitempty"`
	UsagePaths              []Claim            `json:"usage_paths,omitempty"`
	ExploitationConditions  []Claim            `json:"exploitation_conditions,omitempty"`
	ConfirmedFacts          []Fact             `json:"confirmed_facts"`
	Assumptions             ExtractionList     `json:"assumptions"`
	Unknowns                ExtractionList     `json:"unknowns"`
	Reasoning               string             `json:"reasoning,omitempty"`
	PresenceSummary         PresenceSummary    `json:"citation_presence"`
	// Grounded claims are additive research-only fields: the deterministic
	// reportcheck grounder verifies each cited location against the
	// snapshot and each mechanism atom against the frozen advisory
	// symbols. They never affect the {category, reasoning} contract.
	RootCauseLocations []reportcheck.Location `json:"root_cause_locations,omitempty"`
	UsageSites         []reportcheck.Location `json:"usage_sites,omitempty"`
	// CitationMetadata carries presence-only citations: manifests, lock/
	// checksum files, docs/testdata, test code and import lines. They are
	// not product loci and not usage sites, so they live apart from both.
	CitationMetadata []reportcheck.Location      `json:"citation_metadata,omitempty"`
	MechanismAtoms   []reportcheck.MechanismAtom `json:"mechanism_atoms,omitempty"`
	// NegativeClaims carries the path polarity statements the grounder
	// extracted from the reasoning (absence/presence, scope, path, symbol)
	// — context for negative metrics, never a verdict.
	NegativeClaims []reportcheck.NegativeClaim `json:"negative_claims,omitempty"`
}

// disclaimer is the fixed header text: the category is a research
// judgement, never a verified safety conclusion, and nothing is closed.
const disclaimer = "The research_category below is a RESEARCH judgement produced by an " +
	"ordinary coding agent reading the snapshot. It is NOT a verified safety " +
	"conclusion, does not establish that the product is affected or unaffected, " +
	"and automatic closure of the vulnerability is not performed. Every " +
	"deterministic finding (snapshot identity, advisory digest, module-graph " +
	"facts) is host-produced and verifiable; agent statements are reported as " +
	"claims, assumptions and unknowns."

// Run executes the pipeline: verify snapshot → resolve advisory → render
// prompt → (optionally) launch the agent → assess consistency → render
// the report. Every invocation writes its dossier into a fresh
// run-scoped directory <out>/runs/<run_id>/ and appends it to
// <out>/index.json — a repeat run never overwrites a previous dossier.
// A failed or unparseable agent run still produces the full report with
// research_state "incomplete"; structural failures (bad snapshot,
// unwritable out dir) are returned as errors.
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.ReplayRun != "" {
		return ReplayRun(ctx, o.ReplayRun, o.CaseID)
	}
	if o.SnapshotDir == "" {
		return nil, fmt.Errorf("--snapshot is required")
	}
	if o.CVE == "" {
		return nil, fmt.Errorf("--cve is required")
	}
	if o.OutDir == "" {
		return nil, fmt.Errorf("--out is required")
	}
	if o.Model == "" {
		o.Model = DefaultModel
	}
	if o.AgentImage == "" {
		o.AgentImage = DefaultAgentImage
	}
	if o.OSVURL == "" {
		o.OSVURL = DefaultOSVURL
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if len(o.AgentEnv) == 0 && o.AgentEnvFile == "" {
		o.AgentEnv = []string{"OPENAI_API_KEY", "OPENAI_BASE_URL"}
	}
	if o.DockerBin == "" {
		o.DockerBin = "docker"
	}
	if o.DigestFetcher == nil {
		o.DigestFetcher = imageDigest
	}
	// Docker bind mounts require absolute host paths: a relative --out,
	// --advisory or env/config file is rejected by docker create as an
	// invalid volume name. Resolve every host path up front so the
	// recorded argv is the exact, launchable command.
	for _, p := range []*string{&o.SnapshotDir, &o.OutDir, &o.AdvisoryPath, &o.AgentEnvFile, &o.AgentConfig} {
		if *p == "" {
			continue
		}
		abs, err := filepath.Abs(*p)
		if err != nil {
			return nil, fmt.Errorf("resolve path %q: %w", *p, err)
		}
		*p = abs
	}

	var audit []pbdomain.ToolExecution
	ctx = toolaudit.WithRecorder(ctx, &toolaudit.Recorder{
		Sink: func(t pbdomain.ToolExecution) { audit = append(audit, t) },
	})

	r := &Report{
		Schema:      "izyan-research/2",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tool:        "izyan",
		Command:     "research",
		Disclaimer:  disclaimer,
		Request:     RequestInfo{SnapshotDir: o.SnapshotDir, CVE: o.CVE, CaseID: o.CaseID},
		Artifacts:   map[string]string{},
		Analysis: Analysis{
			ConfirmedFacts: []Fact{},
			Assumptions:    ExtractionList{State: "not_assessed", Items: []string{}},
			Unknowns:       ExtractionList{State: "not_assessed", Items: []string{}},
		},
	}

	snap, facts, err := verifySnapshot(ctx, o)
	if err != nil {
		return nil, err
	}
	r.Snapshot = snap
	r.Analysis.ConfirmedFacts = append(r.Analysis.ConfirmedFacts, facts...)
	if o.SkipContentHash {
		r.Limitations = append(r.Limitations,
			"content hash skipped by controller flag (--skip-content-hash): "+
				"snapshot identity is commit + path only; no containment check and no "+
				"t1 content hash bound this run's evidence to the bytes in the tree")
	}

	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("create --out dir: %w", err)
	}
	runID, runDir, err := allocateRunDir(o.OutDir)
	if err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}
	r.RunID = runID
	r.Run.AttemptID = runID

	ares := resolveAdvisory(ctx, o, runDir)
	audit = append(audit, ares.audit...)
	r.Advisory = ares.info
	if ares.info.Path != "" {
		if rel, rerr := filepath.Rel(runDir, ares.info.Path); rerr == nil && !strings.HasPrefix(rel, "..") {
			r.Artifacts["advisory_document"] = rel
		}
	}
	r.Analysis.ConfirmedFacts = append(r.Analysis.ConfirmedFacts, ares.facts...)
	r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items, ares.unknowns...)
	r.Analysis.AdvisoryMechanism = advisoryMechanismOf(ares.info, ares)

	rendered, pinf, err := renderPrompt(o.CVE)
	if err != nil {
		return nil, err
	}
	r.Prompt = pinf
	r.Analysis.ConfirmedFacts = append(r.Analysis.ConfirmedFacts, Fact{
		Statement: "rendered prompt is the frozen B1 template (sha256 " + pinf.TemplateSHA256[:12] + "…) with exactly one {cve_id} substitution plus the appended <USE_BASED_VERDICT> rule block (sha256 " + pinf.RuleBlockSHA256[:12] + "…)",
		Reference: "prompt.txt",
		Source:    "prompt",
	})
	promptPath := filepath.Join(runDir, "prompt.txt")
	if err := os.WriteFile(promptPath, []byte(rendered), 0o644); err != nil {
		return nil, fmt.Errorf("write prompt.txt: %w", err)
	}
	r.Prompt.Path = "prompt.txt"
	r.Artifacts["prompt"] = "prompt.txt"

	if err := buildRunPlan(ctx, o, r, runDir); err != nil {
		return nil, err
	}

	switch {
	case o.DryRun:
		r.Mode = "dry_run"
		r.Run.Status = "planned"
		r.Run.Reason = "--dry-run: nothing launched"
	case !o.AllowAgent:
		r.Mode = "planned"
		r.Run.Status = "skipped"
		r.Run.Reason = "--allow-agent not given: the container launch was refused; run.* records the exact plan"
	default:
		launchAgent(ctx, o, r, runDir)
		if r.Run.Status == "ok" {
			r.Mode = "executed"
		} else {
			r.Mode = "failed"
		}
	}

	if r.Run.Status == "ok" {
		analyzeAnswer(o, r, runDir)
		if !r.Answer.Parsed {
			// The container ran but produced no usable {category, reasoning}
			// answer — an incomplete research result, not a clean run.
			r.Run.Status = "invalid_answer"
			r.Run.Reason = orReason(r.Answer.ParseError, "no parseable {category, reasoning} answer")
		}
	} else {
		r.Answer = AnswerInfo{CategoryLabel: "unavailable", Source: r.Answer.Source, AttemptID: r.RunID}
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"agent answer unavailable: run status "+r.Run.Status)
	}

	r.ResearchState = researchStateOf(r)
	r.Consistency = assessConsistency(o, r, ares)
	groundAnswer(o.SnapshotDir, runDir, r, ares, nil)
	bindEvidence(r)

	if err := writeOutputs(r, runDir, audit); err != nil {
		return nil, err
	}
	if err := appendRunIndex(o.OutDir, r); err != nil {
		return nil, fmt.Errorf("update run index: %w", err)
	}
	return r, nil
}

// advisoryMechanismOf builds the advisory-side mechanism reference for
// the report: the advisory summary verbatim plus a bounded excerpt of
// the advisory's details text. nil when no advisory resolved — the
// mechanism section then shows that the reference is absent.
func advisoryMechanismOf(info AdvisoryInfo, ares advisoryResult) *AdvisoryMechanism {
	if info.Status != "resolved" {
		return nil
	}
	am := &AdvisoryMechanism{Summary: info.Summary}
	src := info.ID
	if ares.detailsSrc != "" {
		src = ares.detailsSrc
	}
	if src == "" {
		src = ares.primaryDoc.ID
	}
	am.Source = src
	am.DetailsExcerpt, am.DetailsCut = detailsExcerpt(ares.details, 600)
	return am
}

// detailsExcerpt bounds the advisory details to at most limit bytes at a
// paragraph or word boundary — a display excerpt, never a rewrite.
func detailsExcerpt(details string, limit int) (excerpt string, cut bool) {
	d := strings.TrimSpace(details)
	if len(d) <= limit {
		return d, false
	}
	cutAt := -1
	// Prefer a paragraph break inside the window.
	if i := strings.Index(d[:limit], "\n\n"); i > limit/4 {
		cutAt = i
	} else {
		// Otherwise end at the last space inside the window.
		cutAt = strings.LastIndex(d[:limit], " ")
	}
	if cutAt <= 0 {
		cutAt = limit
	}
	return strings.TrimSpace(d[:cutAt]), true
}

// allocateRunDir reserves a fresh run-scoped output directory. The id is
// timestamp-based for sortability; a numeric suffix breaks same-second
// collisions so no run can ever overwrite another's dossier.
func allocateRunDir(outDir string) (id, dir string, err error) {
	base := time.Now().UTC().Format("20060102T150405Z")
	runsRoot := filepath.Join(outDir, "runs")
	if err := os.MkdirAll(runsRoot, 0o755); err != nil {
		return "", "", err
	}
	for i := range 1000 {
		id = base
		if i > 0 {
			id = fmt.Sprintf("%s-%d", base, i+1)
		}
		dir = filepath.Join(runsRoot, id)
		// Mkdir is atomic — it fails if the directory already exists, so
		// two runs racing inside the same second can never share a dir.
		if merr := os.Mkdir(dir, 0o755); merr == nil {
			return id, dir, nil
		} else if !os.IsExist(merr) {
			return "", "", merr
		}
	}
	return "", "", fmt.Errorf("could not allocate a fresh run id under %s", runsRoot)
}

// researchStateOf maps the run outcome onto the research-state vocabulary:
// not_started (nothing attempted), incomplete (attempted but no parseable
// answer), complete (a parsed answer exists — still a judgement, not a
// conclusion).
func researchStateOf(r *Report) string {
	switch r.Run.Status {
	case "ok":
		return "complete"
	case "planned", "skipped":
		return "not_started"
	default:
		return "incomplete"
	}
}

// bindEvidence stamps every host fact, finding and entry with the attempt
// id and the snapshot content hash so evidence is bound to this specific
// run and tree, never to "the snapshot" in the abstract.
func bindEvidence(r *Report) {
	for i := range r.Analysis.ConfirmedFacts {
		r.Analysis.ConfirmedFacts[i].Attempt = r.RunID
		r.Analysis.ConfirmedFacts[i].SnapshotHash = r.Snapshot.ContentHash
	}
	for i := range r.Consistency.Entries {
		r.Consistency.Entries[i].Attempt = r.RunID
		r.Consistency.Entries[i].SnapshotHash = r.Snapshot.ContentHash
	}
	for i := range r.Consistency.Findings {
		r.Consistency.Findings[i].Attempt = r.RunID
		r.Consistency.Findings[i].SnapshotHash = r.Snapshot.ContentHash
	}
	r.Answer.AttemptID = r.RunID
	if r.Analysis.PresenceSummary.Note == "" {
		r.Analysis.PresenceSummary.Note = presenceNote
	}
}

// IndexEntry is one row of <out>/index.json: the run directory and the
// facts needed to pick which dossier to read.
type IndexEntry struct {
	RunID          string `json:"run_id"`
	GeneratedAt    string `json:"generated_at"`
	Mode           string `json:"mode"`
	ResearchState  string `json:"research_state"`
	RunStatus      string `json:"run_status"`
	Category       string `json:"category,omitempty"`
	SnapshotCommit string `json:"snapshot_commit"`
	SnapshotHash   string `json:"snapshot_hash"`
	AdvisorySHA256 string `json:"advisory_sha256,omitempty"`
	ReportDir      string `json:"report_dir"`
	RerenderOf     string `json:"rerender_of,omitempty"`
}

type runIndex struct {
	Schema string       `json:"schema"`
	Runs   []IndexEntry `json:"runs"`
}

// appendRunIndex registers this run in <out>/index.json. The index
// accumulates: existing entries are preserved verbatim and the write is
// atomic (temp file + rename) so a crashed run never corrupts the list.
func appendRunIndex(outDir string, r *Report) error {
	path := filepath.Join(outDir, "index.json")
	idx := runIndex{Schema: "izyan-research-index/1", Runs: []IndexEntry{}}
	if b, err := os.ReadFile(path); err == nil {
		if jerr := json.Unmarshal(b, &idx); jerr != nil {
			return fmt.Errorf("existing %s unreadable (%v) — refusing to lose it", path, jerr)
		}
	}
	idx.Runs = append(idx.Runs, IndexEntry{
		RunID:          r.RunID,
		GeneratedAt:    r.GeneratedAt,
		Mode:           r.Mode,
		ResearchState:  r.ResearchState,
		RunStatus:      r.Run.Status,
		Category:       r.Answer.Category,
		SnapshotCommit: r.Snapshot.Commit,
		SnapshotHash:   r.Snapshot.ContentHash,
		AdvisorySHA256: r.Advisory.SHA256,
		ReportDir:      filepath.Join("runs", r.RunID),
		RerenderOf:     r.RerenderOf,
	})
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
