package research

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/toolaudit"
)

// modelToProvider mirrors the harness MODEL2NAME map
// (agents/opencode.py): the key the operator passes is resolved to the
// provider-side model id sent verbatim to the API. A value already in
// "provider/model" form passes through unchanged.
var modelToProvider = map[string]string{
	"gpt-5.5":               "azure-cognitive-services/gpt-5.5",
	"gpt-5.4-mini":          "azure-cognitive-services/gpt-5.4-mini",
	"kimi-k2.6":             "Azure-Resource/Kimi-K2.6",
	"deepseek-v4-flash":     "Azure-Resource/DeepSeek-V4-Flash",
	"deepseek-v4-pro":       "Azure-Resource/DeepSeek-V4-Pro",
	"qwen3.6-35b":           "custom-openai/Qwen/Qwen3.6-35B-A3B",
	"gemini-3.8-flash-high": "antigravity/gemini-3.8-flash-high",
}

// providerSnippets are the provider blocks merged into the synthesized
// opencode.json when the base config does not define them — the same
// blocks the B1' adapter injects (opencode_c1._PROVIDERS). apiKey is never
// a literal secret: it is interpolated from a container env var at start.
var providerSnippets = map[string]map[string]any{
	"custom-openai": {
		"npm":  "@ai-sdk/openai-compatible",
		"name": "OpenAI-compatible gateway",
		"options": map[string]any{
			"baseURL": "{env:OPENAI_BASE_URL}",
			"apiKey":  "{env:OPENAI_API_KEY}",
		},
		"models": map[string]any{
			"Qwen/Qwen3.6-35B-A3B": map[string]any{
				"name":  "Qwen3.6-35B-A3B",
				"limit": map[string]any{"context": 262144, "output": 16384},
			},
		},
	},
	"antigravity": {
		"npm":  "@ai-sdk/anthropic",
		"name": "antigravity",
		"options": map[string]any{
			"baseURL": "http://host.docker.internal:8045/v1",
			"apiKey":  "opencode-c1",
		},
		"models": map[string]any{
			"gemini-3.8-flash-high": map[string]any{"name": "Gemini 3.8 Flash High"},
		},
	},
}

// resolveModel maps --model to the provider-side model id.
func resolveModel(key string) (string, error) {
	if v, ok := modelToProvider[key]; ok {
		return v, nil
	}
	if strings.Contains(key, "/") {
		return key, nil
	}
	known := make([]string, 0, len(modelToProvider))
	for k := range modelToProvider {
		known = append(known, k)
	}
	return "", fmt.Errorf("unknown --model %q (known keys: %s; or pass provider/model verbatim)",
		key, strings.Join(known, ", "))
}

// synthesizeConfig builds the per-run opencode.json: the optional base
// file plus the provider block for the resolved model, with the two
// capability restrictions of the B1 arm pinned — no `mcp` block and the
// `task` subagent tool disabled.
func synthesizeConfig(o Options, providerModel string) (cfg map[string]any, raw []byte, err error) {
	cfg = map[string]any{}
	if o.AgentConfig != "" {
		b, rerr := os.ReadFile(o.AgentConfig)
		if rerr != nil {
			return nil, nil, fmt.Errorf("read --agent-config %s: %w", o.AgentConfig, rerr)
		}
		if jerr := json.Unmarshal(b, &cfg); jerr != nil {
			return nil, nil, fmt.Errorf("parse --agent-config %s: %w", o.AgentConfig, jerr)
		}
	}
	if cfg["$schema"] == nil {
		cfg["$schema"] = "https://opencode.ai/config.json"
	}

	provider, _ := cfg["provider"].(map[string]any)
	if provider == nil {
		provider = map[string]any{}
		cfg["provider"] = provider
	}
	providerName, modelKey, _ := strings.Cut(providerModel, "/")
	if snippet, ok := providerSnippets[providerName]; ok {
		entry, _ := provider[providerName].(map[string]any)
		if entry == nil {
			entry = map[string]any{}
			provider[providerName] = entry
		}
		for _, k := range []string{"npm", "name"} {
			if _, has := entry[k]; !has {
				entry[k] = snippet[k]
			}
		}
		options, _ := entry["options"].(map[string]any)
		if options == nil {
			options = map[string]any{}
			entry["options"] = options
		}
		if snipOpts, ok := snippet["options"].(map[string]any); ok {
			for k, v := range snipOpts {
				if _, has := options[k]; !has {
					options[k] = v
				}
			}
		}
		models, _ := entry["models"].(map[string]any)
		if models == nil {
			models = map[string]any{}
			entry["models"] = models
		}
		if _, has := models[modelKey]; !has {
			if snipModels, ok := snippet["models"].(map[string]any); ok {
				if m, ok := snipModels[modelKey]; ok {
					models[modelKey] = m
				} else {
					models[modelKey] = map[string]any{"name": modelKey}
				}
			} else {
				models[modelKey] = map[string]any{"name": modelKey}
			}
		}
	}

	// Capability pins — identical to the B1 arm's synthesized config.
	delete(cfg, "mcp")
	tools, _ := cfg["tools"].(map[string]any)
	if tools == nil {
		tools = map[string]any{}
		cfg["tools"] = tools
	}
	tools["task"] = false

	raw, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return cfg, append(raw, '\n'), nil
}

// containerScript is the in-container command, mirroring the harness
// export pipeline: run opencode, capture stdout/stderr, export the latest
// session as JSON for the raw-answer extraction. The opencode run itself
// is also bounded by coreutils timeout inside the container.
func containerScript(providerModel string, timeout int) string {
	return fmt.Sprintf(`set -e
cd /work
timeout %[2]ds opencode run --model %[1]s --thinking --dangerously-skip-permissions "$(cat /tmp/prompt.txt)" > /tmp/opencode-stdout.txt 2> /tmp/opencode-stderr.log || echo $? > /tmp/opencode-exit
opencode session list --max-count 1 --format json > /tmp/session-list.json 2> /tmp/session-list.stderr
SID=$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/session-list.json | head -n1)
opencode export "$SID" > /tmp/opencode-export.json 2> /tmp/opencode-export.stderr
`,
		shellQuote(providerModel), timeout)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildRunPlan resolves the model, synthesizes the config file, queries
// the image digest and records the exact docker argv, mounts and env the
// launch will use. In --dry-run the files are still written (they are the
// plan) but nothing is executed.
func buildRunPlan(ctx context.Context, o Options, r *Report, runDir string) error {
	providerModel, err := resolveModel(o.Model)
	if err != nil {
		return err
	}
	r.Run.ProviderModel = providerModel
	r.Run.Model = o.Model
	r.Run.Image = o.AgentImage
	r.Run.TimeoutSeconds = o.Timeout
	r.Run.Network = "default (docker bridge; no explicit network flag — provider API must be reachable)"
	r.Run.Subagents = "disabled (tools.task=false in the mounted config)"
	r.Run.MCP = "none (no mcp block in the mounted config)"

	cfgPath := filepath.Join(runDir, "opencode-config.json")
	_, raw, err := synthesizeConfig(o, providerModel)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		return fmt.Errorf("write opencode-config.json: %w", err)
	}
	r.Run.ConfigPath = "opencode-config.json"
	r.Run.ConfigSHA256 = sha256Hex(raw)
	r.Artifacts["opencode_config"] = "opencode-config.json"

	// Env: an explicit env file wins; otherwise the named host variables
	// are forwarded by name only (values never enter argv).
	if o.AgentEnvFile != "" {
		if _, err := os.Stat(o.AgentEnvFile); err != nil {
			return fmt.Errorf("--agent-env-file %s: %w", o.AgentEnvFile, err)
		}
		r.Run.EnvFile = o.AgentEnvFile
	}
	for _, name := range o.AgentEnv {
		if _, ok := os.LookupEnv(name); ok {
			r.Run.EnvForwarded = append(r.Run.EnvForwarded, name)
		} else {
			r.Run.EnvMissing = append(r.Run.EnvMissing, name)
		}
	}

	digest, derr := o.DigestFetcher(ctx, o.AgentImage)
	if derr != nil {
		r.Limitations = append(r.Limitations, "image digest lookup failed: "+derr.Error())
	} else {
		r.Run.ImageDigest = digest
	}

	promptPath := filepath.Join(runDir, "prompt.txt")
	r.Run.Mounts = []Mount{
		{Host: o.SnapshotDir, Container: ContainerWorkdir, Mode: "ro"},
		{Host: cfgPath, Container: "/tmp/.config/opencode/opencode.json", Mode: "ro"},
		{Host: promptPath, Container: "/tmp/prompt.txt", Mode: "ro"},
	}
	r.Run.Argv = dockerCreateArgv(o, r.Run)
	return nil
}

// dockerCreateArgv is the exact argv of `docker create` for the run. It is
// recorded verbatim into the report before anything launches.
func dockerCreateArgv(o Options, run RunInfo) []string {
	argv := []string{
		o.DockerBin, "create",
		"--workdir", ContainerWorkdir,
	}
	if o.AgentEnvFile != "" {
		argv = append(argv, "--env-file", o.AgentEnvFile)
	}
	for _, name := range run.EnvForwarded {
		argv = append(argv, "-e", name)
	}
	for _, m := range run.Mounts {
		argv = append(argv, "-v", m.Host+":"+m.Container+":"+m.Mode)
	}
	argv = append(argv,
		"--entrypoint", "sh",
		o.AgentImage, "-lc", containerScript(run.ProviderModel, run.TimeoutSeconds))
	return argv
}

// imageDigest returns the local image id for image (RepoDigests are
// preferred when present, the .Id otherwise).
func imageDigest(ctx context.Context, image string) (string, error) {
	out, _, err := runTool(ctx, "docker", "", "", "docker", nil,
		"inspect", image, "--format", "{{json .RepoDigests}} {{.Id}}")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return "", fmt.Errorf("docker inspect %s returned empty output", image)
	}
	if d := fields[0]; d != "null" && d != "[]" && d != "" {
		var digs []string
		if json.Unmarshal([]byte(d), &digs) == nil && len(digs) > 0 {
			return digs[0], nil
		}
	}
	if len(fields) > 1 {
		return fields[len(fields)-1], nil
	}
	return "", fmt.Errorf("docker inspect %s: no digest", image)
}

// runTool executes one external command through toolaudit so every
// subprocess lands in the audit trail.
func runTool(ctx context.Context, tool, version, dir, name string, env []string, args ...string) (stdout, stderr []byte, err error) {
	return toolaudit.Run(ctx, tool, version, dir, name, env, args...)
}

// launchAgent performs the single container run: docker create → start
// (with a host-side kill watchdog) → copy artifacts out → rm -f. The
// verdict-relevant state lands in r.Run / r.Answer; the function never
// fails the whole run for an agent-side problem — it records it. Partial
// artifacts are pulled even on timeout: whatever the agent produced is
// part of the research record.
func launchAgent(ctx context.Context, o Options, r *Report, runDir string) {
	r.Run.StartedAt = time.Now().UTC().Format(time.RFC3339)
	t0 := time.Now()
	defer func() {
		r.Run.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		r.Run.WallSeconds = time.Since(t0).Seconds()
		// No agent-side or launch failure may leave run.reason empty:
		// every technical refusal must be diagnosable from the report.
		switch r.Run.Status {
		case "", "ok", "planned", "skipped":
		default:
			if r.Run.Reason == "" {
				r.Run.Reason = orReason(r.Run.Error, "container run failed without a captured diagnostic")
			}
		}
	}()
	out, stderr, err := runTool(ctx, "docker", r.Run.ImageDigest, "", o.DockerBin, nil, r.Run.Argv[1:]...)
	if err != nil {
		r.Run.Status = "error"
		r.Run.Error = "docker create: " + cmdErrText(err, stderr)
		return
	}
	cid := strings.TrimSpace(string(out))
	if cid == "" {
		r.Run.Status = "error"
		r.Run.Error = "docker create returned empty container id"
		return
	}
	defer func() {
		// The container and its writable layer are always removed —
		// success, timeout and failure alike.
		_, _, _ = runTool(context.Background(), "docker", "", "", o.DockerBin, nil, "rm", "-f", cid)
	}()

	watchCtx, cancel := context.WithTimeout(ctx, time.Duration(o.Timeout+120)*time.Second)
	defer cancel()
	_, stderr, err = runTool(watchCtx, "docker", r.Run.ImageDigest, "", o.DockerBin, nil, "start", "-a", cid)
	if err != nil {
		ec := exitCode(err)
		r.Run.ContainerExit = &ec
		if watchCtx.Err() == context.DeadlineExceeded || ctx.Err() == context.DeadlineExceeded {
			r.Run.Status = "timeout"
			r.Run.Error = fmt.Sprintf("container exceeded %ds (host watchdog)", o.Timeout+120)
			_, _, _ = runTool(context.Background(), "docker", "", "", o.DockerBin, nil, "kill", cid)
		} else {
			r.Run.Status = "error"
			r.Run.Error = fmt.Sprintf("docker start: exit %d: %s", ec, cmdErrText(err, stderr))
		}
	}

	// Artifacts out — always attempted, even after a failed or timed-out
	// run, and on a bounded context detached from the (possibly spent)
	// launch context: partial agent output is part of the record.
	cpCtx, cpCancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	copyArtifacts(cpCtx, o, r, cid, runDir)
	cpCancel()

	if r.Run.ContainerExit == nil {
		if n := readOpencodeExit(runDir); n >= 0 {
			r.Run.ContainerExit = &n
		}
	}

	if r.Run.Status == "" {
		r.Run.Status = "ok"
		if r.Run.ContainerExit == nil {
			zero := 0
			r.Run.ContainerExit = &zero
		}
	}
	recoverAgentAnswer(r, runDir)
	enrichRunError(r, runDir)
}

// copyArtifacts pulls the diagnostic files out of the container. Missing
// files are tolerated: their absence is itself recorded by the report's
// artifacts map. The two *.stderr captures belong to the session-list and
// export commands inside the container script — when the export pipeline
// breaks, they are the only record of why.
func copyArtifacts(ctx context.Context, o Options, r *Report, cid, runDir string) {
	for _, name := range []string{
		"opencode-export.json",
		"opencode-export.stderr",
		"opencode-stdout.txt",
		"opencode-stderr.log",
		"session-list.json",
		"session-list.stderr",
		"opencode-exit",
	} {
		dest := filepath.Join(runDir, name)
		_, _, err := runTool(ctx, "docker", "", "", o.DockerBin, nil,
			"cp", cid+":/tmp/"+name, dest)
		if err != nil {
			os.Remove(dest)
			continue
		}
		r.Artifacts[artifactKey(name)] = name
	}
}

func artifactKey(name string) string {
	return strings.NewReplacer(".", "_", "-", "_").Replace(name)
}

// recoverAgentAnswer materializes raw_agent_output.txt from the artifacts
// copied out of the container, trying every channel the agent's final
// message can survive on, in trust order:
//
//  1. opencode-export.json — the session export (authoritative; also
//     yields token counters);
//  2. opencode-stdout.txt — the stdout capture of `opencode run`;
//  3. session-list.json — only when it embeds export-shaped message
//     content (some formats carry messages; a bare session listing
//     contributes nothing and is skipped);
//  4. opencode-stderr.log — last resort: the run log, which at minimum
//     keeps the agent's dying words (provider/TLS errors, crashes) in the
//     dossier as the recorded answer text.
//
// The first source yielding non-empty text wins; its name is recorded in
// answer.source. When no source yields text, run.reason is filled with a
// diagnostic summary (present artifacts + sizes, exit code, stderr tail)
// so a lost answer is never a bare read error.
func recoverAgentAnswer(r *Report, runDir string) {
	exportPath := filepath.Join(runDir, "opencode-export.json")
	if fileExists(exportPath) {
		if answer, stats, perr := extractExport(exportPath); perr == nil {
			r.Answer.Source = "opencode-export.json"
			r.Run.Tokens = stats
			_ = os.WriteFile(filepath.Join(runDir, "raw_agent_output.txt"), []byte(answer), 0o644)
			r.Artifacts["raw_answer"] = "raw_agent_output.txt"
			return
		}
	}
	for _, fb := range []struct {
		name    string
		extract func(string) (string, error)
	}{
		{"opencode-stdout.txt", extractRawText},
		{"session-list.json", extractSessionListText},
		{"opencode-stderr.log", extractRawText},
	} {
		path := filepath.Join(runDir, fb.name)
		if !fileExists(path) {
			continue
		}
		text, terr := fb.extract(path)
		if terr != nil || strings.TrimSpace(text) == "" {
			continue
		}
		_ = os.WriteFile(filepath.Join(runDir, "raw_agent_output.txt"), []byte(text), 0o644)
		r.Artifacts["raw_answer"] = "raw_agent_output.txt"
		r.Answer.Source = fb.name
		return
	}
	if r.Run.Reason == "" {
		r.Run.Reason = "no agent answer recoverable from container artifacts (" +
			answerArtifactsDiag(r, runDir) + ")"
	}
}

// extractRawText is the verbatim fallback: the whole file content,
// whitespace-trimmed. Used for opencode-stdout.txt (second choice) and
// opencode-stderr.log (last resort).
func extractRawText(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// extractSessionListText pulls answer text out of session-list.json when
// the session listing embeds export-shaped message content — a "messages"
// array (export form, or a session object carrying one) or a nested
// "export" object. A bare session listing (id/title/created only, the
// observed `opencode session list --format json` output) yields nothing;
// the session title is never treated as the agent's answer.
func extractSessionListText(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var probe any
	if jerr := json.Unmarshal(b, &probe); jerr != nil {
		return "", fmt.Errorf("parse session list: %w", jerr)
	}
	var entries []any
	switch v := probe.(type) {
	case []any:
		entries = v
	case map[string]any:
		entries = []any{v}
	default:
		return "", fmt.Errorf("session list has unexpected shape %T", probe)
	}
	for _, e := range entries {
		obj, _ := e.(map[string]any)
		if obj == nil {
			continue
		}
		for _, key := range []string{"messages", "export"} {
			raw, ok := obj[key]
			if !ok {
				continue
			}
			jb, merr := json.Marshal(map[string]any{"messages": raw})
			if key == "export" {
				jb, merr = json.Marshal(raw)
			}
			if merr != nil {
				continue
			}
			answer, _, perr := parseExport(jb)
			if perr == nil && strings.TrimSpace(answer) != "" {
				return answer, nil
			}
		}
	}
	return "", fmt.Errorf("session list carries no message content")
}

// answerArtifactsDiag renders the failure diagnostic for a lost answer:
// which container artifacts were pulled and their sizes, the container or
// opencode exit code, and the tails of the opencode stderr/stdout captures.
// Everything is bounded — the report stays a report, not a log dump.
func answerArtifactsDiag(r *Report, runDir string) string {
	var names []string
	for _, name := range []string{
		"opencode-export.json", "opencode-export.stderr", "opencode-stdout.txt",
		"opencode-stderr.log", "session-list.json", "session-list.stderr", "opencode-exit",
	} {
		if st, err := os.Stat(filepath.Join(runDir, name)); err == nil {
			names = append(names, fmt.Sprintf("%s(%dB)", name, st.Size()))
		}
	}
	if len(names) == 0 {
		names = append(names, "none")
	}
	d := "artifacts: " + strings.Join(names, ", ")
	if r.Run.ContainerExit != nil {
		d += fmt.Sprintf("; container exit %d", *r.Run.ContainerExit)
	}
	if n := readOpencodeExit(runDir); n >= 0 && (r.Run.ContainerExit == nil || *r.Run.ContainerExit != n) {
		d += fmt.Sprintf("; opencode exit %d", n)
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "opencode-stderr.log")); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			d += "; stderr tail: " + tail(s, 400)
		}
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "opencode-stdout.txt")); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			d += "; stdout tail: " + tail(s, 400)
		}
	}
	return d
}

// enrichRunError augments a failed/timed-out run's error with what the
// pulled artifacts show: the opencode exit file, the tails of opencode's
// stderr and stdout, and the export command's own stderr when it broke.
// docker's CLI stderr alone has repeatedly proven too thin to diagnose
// container-side failures ("docker start: exit 1" says nothing).
func enrichRunError(r *Report, runDir string) {
	if r.Run.Status != "error" && r.Run.Status != "timeout" {
		return
	}
	var extra []string
	if n := readOpencodeExit(runDir); n >= 0 {
		extra = append(extra, fmt.Sprintf("opencode exit %d", n))
	}
	for _, spec := range []struct{ name, label string }{
		{"opencode-stderr.log", "opencode stderr"},
		{"opencode-stdout.txt", "opencode stdout"},
		{"opencode-export.stderr", "export stderr"},
		{"session-list.stderr", "session-list stderr"},
	} {
		b, rerr := os.ReadFile(filepath.Join(runDir, spec.name))
		if rerr != nil {
			continue
		}
		if s := strings.TrimSpace(string(b)); s != "" {
			extra = append(extra, spec.label+" tail: "+tail(s, 800))
		}
	}
	if len(extra) == 0 {
		return
	}
	if r.Run.Error == "" {
		r.Run.Error = strings.Join(extra, "; ")
	} else {
		r.Run.Error += "; " + strings.Join(extra, "; ")
	}
}

// readOpencodeExit parses the opencode-exit artifact written by the
// container script when `opencode run` itself failed. -1 when absent or
// unparsable — the file is best-effort diagnostics, never authoritative.
func readOpencodeExit(runDir string) int {
	b, err := os.ReadFile(filepath.Join(runDir, "opencode-exit"))
	if err != nil {
		return -1
	}
	n, cerr := strconv.Atoi(strings.TrimSpace(string(b)))
	if cerr != nil {
		return -1
	}
	return n
}

// extractExport reads the opencode session export: the last assistant text
// is the agent's final answer; step-finish token counters are summed.
func extractExport(path string) (string, *TokenUsage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	return parseExport(b)
}

// parseExport is the byte-level core of extractExport, shared with the
// session-list fallback: the last non-empty text part of the last
// assistant message is the agent's final answer.
func parseExport(b []byte) (string, *TokenUsage, error) {
	var export struct {
		Messages []struct {
			Info struct {
				Role string `json:"role"`
			} `json:"info"`
			Parts []struct {
				Type   string `json:"type"`
				Text   string `json:"text"`
				Tokens *struct {
					Input     int `json:"input"`
					Output    int `json:"output"`
					Reasoning int `json:"reasoning"`
					Cache     *struct {
						Read  int `json:"read"`
						Write int `json:"write"`
					} `json:"cache"`
				} `json:"tokens"`
			} `json:"parts"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(b, &export); err != nil {
		return "", nil, fmt.Errorf("parse opencode export: %w", err)
	}
	answer := ""
	usage := &TokenUsage{}
	anyTokens := false
	for i := len(export.Messages) - 1; i >= 0; i-- {
		m := export.Messages[i]
		if m.Info.Role != "assistant" {
			continue
		}
		for j := len(m.Parts) - 1; j >= 0; j-- {
			p := m.Parts[j]
			if p.Type == "text" && strings.TrimSpace(p.Text) != "" && answer == "" {
				answer = strings.TrimSpace(p.Text)
			}
			if p.Type == "step-finish" && p.Tokens != nil {
				anyTokens = true
				usage.Input += p.Tokens.Input
				usage.Output += p.Tokens.Output
				usage.Reasoning += p.Tokens.Reasoning
				if p.Tokens.Cache != nil {
					usage.CacheRead += p.Tokens.Cache.Read
					usage.CacheWrite += p.Tokens.Cache.Write
				}
			}
		}
	}
	if !anyTokens {
		usage = nil
	}
	if answer == "" {
		return "", usage, fmt.Errorf("no assistant text in export")
	}
	return answer, usage, nil
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// cmdErrText renders an exec failure with the tool's stderr — docker's
// own message is the diagnostic, never just "exit status 1".
func cmdErrText(err error, stderr []byte) string {
	s := strings.TrimSpace(string(stderr))
	if s == "" {
		return err.Error()
	}
	return tail(s, 2000) + " (" + err.Error() + ")"
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
