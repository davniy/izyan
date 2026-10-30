package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/eval/vexbench"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/toolchain"
)

// vexAdapterVersion marks the benchmark envelope/provenance schema. Bump on
// any change to the fields a baseline consumer may rely on; adapter version
// 1 had a four-field string provenance block and no OSV fetch records.
const vexAdapterVersion = "2"

// vexProvenance is the benchmark-only provenance block of metrics.json —
// every fact the runner can obtain automatically, or an explicit missing
// reason. It is populated at artifact-write time and never invents values:
// absent data is null plus a reason in Missing, not a fabricated fallback.
type vexProvenance struct {
	SchemaVersion  string            `json:"schema_version"`
	AdapterVersion string            `json:"adapter_version"`
	GeneratedAtUTC string            `json:"generated_at"`
	Argv           []string          `json:"argv"`
	CLIJ           int               `json:"cli_j"`
	TasksPath      string            `json:"tasks_path"`
	TasksSHA256    string            `json:"tasks_sha256,omitempty"`
	TaskIDs        []string          `json:"selected_task_ids"`
	TotalTasks     int               `json:"total_tasks"`
	UniqueCVEs     int               `json:"unique_cves"`
	UniqueRepos    int               `json:"unique_repos"`
	UniqueSnaps    int               `json:"unique_snapshots"`
	IzyanCommitSHA string            `json:"izyan_commit_sha,omitempty"`
	IzyanDirty     *bool             `json:"izyan_dirty"`
	IzyanBinSHA256 string            `json:"izyan_binary_sha256,omitempty"`
	IzyanBuildInfo map[string]any    `json:"izyan_build_info,omitempty"`
	VexbenchSHA    string            `json:"vexbench_commit_sha,omitempty"`
	AnalysisGo     string            `json:"analysis_go"`
	AnalysisMode   string            `json:"analysis_mode"`
	GoBinSHA256    string            `json:"go_binary_sha256,omitempty"`
	GoBuildInfo    string            `json:"go_build_info,omitempty"`
	GVVersion      string            `json:"govulncheck_version,omitempty"`
	GVBinSHA256    string            `json:"govulncheck_binary_sha256,omitempty"`
	GVBuildInfo    string            `json:"govulncheck_build_info,omitempty"`
	GVVersionOut   string            `json:"govulncheck_version_output,omitempty"`
	GVDBURL        string            `json:"govulncheck_db_url,omitempty"`
	GVDBModified   string            `json:"govulncheck_db_last_modified,omitempty"`
	GVDBMode       string            `json:"govulncheck_db_mode"`
	HostOS         string            `json:"host_os"`
	HostArch       string            `json:"host_arch"`
	TargetGOOS     string            `json:"target_goos"`
	TargetGOARCH   string            `json:"target_goarch"`
	CGOEnabled     bool              `json:"cgo_enabled"`
	CGOEnv         string            `json:"cgo_env,omitempty"`
	BuildTags      []string          `json:"build_tags"`
	Env            map[string]string `json:"env"`
	// Knowledge digest of the effective built-in knowledge base; the
	// benchmark profile never loads --knowledge extensions.
	KnowledgeSHA256 string `json:"knowledge_digest,omitempty"`
	OSVFetches      int    `json:"osv_fetches"`
	OSVFetchLog     string `json:"osv_fetch_log,omitempty"`
	LLMCalls        int    `json:"llm_calls"`
	ToolCalls       int    `json:"tool_calls"`
	Tokens          int    `json:"tokens"`
	LLMCost         int    `json:"llm_cost"`
	// Model/endpoint/prompt are null in the deterministic profile; the
	// reason lives in Missing.
	Model                 *string           `json:"model"`
	ModelEndpointRevision *string           `json:"model_endpoint_revision"`
	PromptVersion         *string           `json:"prompt_version"`
	Missing               map[string]string `json:"missing,omitempty"`
}

// collectVexProvenance gathers every provenance fact the benchmark runner
// can observe automatically. Subprocess probes use short timeouts and are
// best-effort: failures land in Missing, never silently dropped.
func collectVexProvenance(tasksPath string, tasks []vexbench.Task, envs []vexEnvelope, tc toolchain.Toolchain, selfBinary string, cliJ int) vexProvenance {
	p := vexProvenance{
		SchemaVersion:  vexAdapterVersion,
		AdapterVersion: vexAdapterVersion,
		GeneratedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Argv:           append([]string{}, os.Args...),
		CLIJ:           cliJ,
		TasksPath:      tasksPath,
		AnalysisGo:     tc.Version,
		AnalysisMode:   string(tc.Mode),
		GVDBMode:       "live_observed",
		HostOS:         runtime.GOOS,
		HostArch:       runtime.GOARCH,
		TargetGOOS:     runtime.GOOS, // the vex profile never overrides the target platform
		TargetGOARCH:   runtime.GOARCH,
		BuildTags:      []string{},
		Env:            map[string]string{},
		Missing:        map[string]string{},
	}
	miss := func(field, reason string) { p.Missing[field] = reason }

	// Task identity set and input digest.
	seenCVE, seenRepo, seenSnap := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, t := range tasks {
		p.TaskIDs = append(p.TaskIDs, t.TaskID)
		seenCVE[t.CVEID] = true
		seenRepo[t.RepoURL] = true
		seenSnap[t.RepoURL+"@"+t.CommitSHA] = true
	}
	p.TotalTasks = len(tasks)
	p.UniqueCVEs = len(seenCVE)
	p.UniqueRepos = len(seenRepo)
	p.UniqueSnaps = len(seenSnap)
	if sum, err := hashFileSHA256(tasksPath); err == nil {
		p.TasksSHA256 = sum
	} else {
		miss("tasks_sha256", err.Error())
	}
	if sha, err := gitRevParse(filepath.Dir(tasksPath)); err == nil {
		p.VexbenchSHA = sha
	} else {
		miss("vexbench_commit_sha", err.Error())
	}

	// This binary's own identity: build info first, flag/executable digest.
	self := selfBinary
	if self == "" {
		if exe, err := os.Executable(); err == nil {
			self = exe
		}
	}
	if self != "" {
		if sum, err := hashFileSHA256(self); err == nil {
			p.IzyanBinSHA256 = sum
		} else {
			miss("izyan_binary_sha256", err.Error())
		}
	} else {
		miss("izyan_binary_sha256", "no self binary path (os.Executable failed, --self-binary unset)")
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		settings := map[string]string{}
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}
		p.IzyanBuildInfo = map[string]any{
			"go_version": bi.GoVersion,
			"settings":   settings,
		}
		if rev := settings["vcs.revision"]; rev != "" {
			p.IzyanCommitSHA = rev
		} else {
			miss("izyan_commit_sha", "no vcs.revision in build info")
		}
		if mod, ok := settings["vcs.modified"]; ok {
			dirty := mod == "true"
			p.IzyanDirty = &dirty
		} else {
			miss("izyan_dirty", "no vcs.modified in build info")
		}
	} else {
		miss("izyan_build_info", "debug.ReadBuildInfo unavailable")
		miss("izyan_commit_sha", "no build info")
		miss("izyan_dirty", "no build info")
	}

	// The analysis toolchain binary as actually resolved.
	if bin := goBinPath(tc); bin != "" {
		if sum, err := hashFileSHA256(bin); err == nil {
			p.GoBinSHA256 = sum
		}
		if out, err := toolOutput(tc.GoBin, tc.Env, 15*time.Second, "version", "-m", bin); err == nil {
			p.GoBuildInfo = out
		}
	}
	if p.GoBinSHA256 == "" {
		miss("go_binary_sha256", "go binary path unresolved")
	}

	// govulncheck: resolve exactly like goanalysis.ExecRunner does (ambient
	// PATH, then `go env` GOBIN/GOPATH[0]/bin, then ~/go/bin), so the
	// recorded binary is the one the analysis subprocesses would use.
	if bin := vexGovulnBin(); bin != "" && bin != "govulncheck" {
		if sum, err := hashFileSHA256(bin); err == nil {
			p.GVBinSHA256 = sum
		}
		if out, err := toolOutput(bin, nil, 30*time.Second, "-version"); err == nil {
			p.GVVersionOut = out
			p.GVVersion, p.GVDBURL, p.GVDBModified = parseGovulnVersion(out)
		} else {
			miss("govulncheck_version", err.Error())
		}
		if out, err := toolOutput(tc.GoBin, tc.Env, 15*time.Second, "version", "-m", bin); err == nil {
			p.GVBuildInfo = out
		}
	} else {
		miss("govulncheck_version", "govulncheck not found in PATH/GOBIN/GOPATH/bin/~/go/bin")
		miss("govulncheck_binary_sha256", "govulncheck not found")
	}

	// Effective knowledge digest: the built-in base the deterministic
	// benchmark profile runs against (no --knowledge extension exists).
	if kb := goanalysis.DefaultKnowledge(); kb != nil {
		if b, err := json.Marshal(kb.AsFile()); err == nil {
			sum := sha256.Sum256(b)
			p.KnowledgeSHA256 = hex.EncodeToString(sum[:])
		}
	}

	// Effective environment facts: raw operator env plus the toolchain
	// overrides the analyzer actually applies to its subprocesses.
	for _, k := range []string{"CGO_ENABLED", "GOENV", "GOTOOLCHAIN", "GOWORK", "GOFLAGS", "GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY"} {
		if v, ok := os.LookupEnv(k); ok {
			p.Env[k] = v
		}
	}
	p.CGOEnv = os.Getenv("CGO_ENABLED")
	// govulncheck and package loading always force CGO_ENABLED=0 in the
	// benchmark build snapshot; record the effective value, not the host's.
	p.CGOEnabled = p.CGOEnv == "1" || strings.EqualFold(p.CGOEnv, "true")
	for _, kv := range tc.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			p.Env[k] = v
		}
	}

	for _, e := range envs {
		p.LLMCalls += e.LLMCalls
		p.ToolCalls += e.ToolCalls
		p.OSVFetches += e.OSVFetches
	}
	if p.OSVFetches > 0 {
		p.OSVFetchLog = "provenance/osv-fetches.jsonl"
	}
	miss("tokens", "no token accounting in the deterministic profile")
	miss("llm_cost", "no LLM usage in the deterministic profile")
	miss("model", "not_applicable: deterministic profile, no LLM configured")
	miss("model_endpoint_revision", "not_applicable: deterministic profile")
	miss("prompt_version", "not_applicable: deterministic profile")
	miss("orchestrator_version", "recorded by eval/vexbench_baseline.py in run-manifest.json")
	return p
}

// parseGovulnVersion extracts Scanner version, DB url and DB timestamp from
// `govulncheck -version` output. Fields absent from the output stay empty —
// a missing line is honest absence, not an invented version.
func parseGovulnVersion(out string) (version, dbURL, dbModified string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Scanner:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Scanner:"))
			if at := strings.Index(version, "@"); at >= 0 && at+1 < len(version) {
				version = version[at+1:]
			}
		case strings.HasPrefix(line, "DB:"):
			dbURL = strings.TrimSpace(strings.TrimPrefix(line, "DB:"))
		case strings.HasPrefix(line, "DB Updated:"):
			dbModified = strings.TrimSpace(strings.TrimPrefix(line, "DB Updated:"))
		}
	}
	return version, dbURL, dbModified
}

// vexGovulnBin mirrors goanalysis.resolveGovulnBin: PATH first, then the
// `go env` install destinations, then ~/go/bin. It must stay in sync —
// this is eval-scope code that reports which binary the analyzer would
// resolve, never a second resolver for the analyzer itself.
func vexGovulnBin() string {
	if p, err := exec.LookPath("govulncheck"); err == nil {
		return p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, key := range []string{"GOBIN", "GOPATH"} {
		out, err := exec.CommandContext(ctx, "go", "env", key).Output()
		if err != nil {
			continue
		}
		for _, d := range filepath.SplitList(strings.TrimSpace(string(out))) {
			if d == "" {
				continue
			}
			if key == "GOPATH" {
				d = filepath.Join(d, "bin")
			}
			if cand := filepath.Join(d, "govulncheck"); vexFileExists(cand) {
				return cand
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if cand := filepath.Join(home, "go", "bin", "govulncheck"); vexFileExists(cand) {
			return cand
		}
	}
	return ""
}

func vexFileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// goBinPath resolves the absolute path of the toolchain's go binary under
// its own PATH override (SDK/GOTOOLCHAIN env may prepend directories).
func goBinPath(tc toolchain.Toolchain) string {
	if tc.GoBin == "" || tc.GoBin == "go" {
		path := os.Getenv("PATH")
		for _, kv := range tc.Env {
			if v, ok := strings.CutPrefix(kv, "PATH="); ok && v != "" {
				path = v
			}
		}
		for _, dir := range filepath.SplitList(path) {
			if dir == "" {
				dir = "."
			}
			cand := filepath.Join(dir, "go")
			if vexFileExists(cand) {
				if abs, err := filepath.Abs(cand); err == nil {
					return abs
				}
				return cand
			}
		}
		return ""
	}
	return tc.GoBin
}

// hashFileSHA256 returns the lowercase hex digest of a file's bytes.
func hashFileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// gitRevParse returns HEAD of the repository containing dir, or an error —
// the dataset checkout may legitimately be absent when tasks JSONL comes
// from elsewhere; the caller records the reason instead of guessing.
func gitRevParse(dir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD in %s: %w", dir, err)
	}
	sha := strings.TrimSpace(string(out))
	if len(sha) != 40 {
		return "", fmt.Errorf("unexpected rev-parse output %q", sha)
	}
	return sha, nil
}

// toolOutput runs bin args with a bounded timeout and returns trimmed
// combined output. env additions extend the ambient environment like the
// analyzer's subprocess calls do.
func toolOutput(bin string, env []string, timeout time.Duration, args ...string) (string, error) {
	if bin == "" {
		bin = "go"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %.200s", bin, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}
