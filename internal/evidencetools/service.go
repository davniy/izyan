package evidencetools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/toolaudit"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// AdapterVersion is stamped into every Observation's evidence metadata
// and the MCP server identity.
const AdapterVersion = "izyan-evidence-tools/0.1.0"

// DefaultToolTimeout bounds one tool invocation when SessionConfig does
// not set one (spec §8 memory/timeouts; checkpoint-0 E5). The value is
// the controller-measured bound at which a source-mode govulncheck over
// a ~1700-package vendored closure completes; it mirrors the
// --deterministic-timeout default so both strict entry points agree.
const DefaultToolTimeout = 15 * time.Minute

// Session profiles recorded on every observation's scope details.
const (
	profileDefault = "default"
	profileStrict  = "strict"
)

// AuditRecord is one evidence-tool invocation, recorded verbatim by the
// session's audit sink. The sink is attempt-local: records from one
// attempt never feed another attempt or any production store.
type AuditRecord struct {
	Tool        string                 `json:"tool"`
	Args        json.RawMessage        `json:"args,omitempty"`
	Observation *Observation           `json:"observation"`
	DurationMs  int64                  `json:"duration_ms"`
	Executions  []domain.ToolExecution `json:"executions,omitempty"`
	RecordTime  time.Time              `json:"record_time"`
}

// AuditSink receives the real execution record of every tool call.
// Implementations must be safe for sequential use; calls are serialized
// by the session.
type AuditSink interface {
	RecordToolCall(ctx context.Context, rec AuditRecord)
}

// AuditFunc adapts a plain function to AuditSink.
type AuditFunc func(ctx context.Context, rec AuditRecord)

// RecordToolCall implements AuditSink.
func (f AuditFunc) RecordToolCall(ctx context.Context, rec AuditRecord) { f(ctx, rec) }

// NopAudit drops audit records (used only in tests that do not inspect
// the trail; the server default is a JSONL sink).
type NopAudit struct{}

// RecordToolCall implements AuditSink.
func (NopAudit) RecordToolCall(context.Context, AuditRecord) {}

// JSONLAuditSink appends each record as one JSON line to w. A mutex
// serializes writes; records are flushed by the caller's writer.
type JSONLAuditSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLAuditSink wraps an io.Writer (file or stderr).
func NewJSONLAuditSink(w interface {
	Write([]byte) (int, error)
}) *JSONLAuditSink {
	return &JSONLAuditSink{enc: json.NewEncoder(w)}
}

// RecordToolCall implements AuditSink; encode errors are ignored because
// the audit trail must not break tool execution, but a marshal failure is
// impossible in practice (all fields are JSON-safe).
func (s *JSONLAuditSink) RecordToolCall(_ context.Context, rec AuditRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(rec)
}

// SessionConfig carries everything the tool server is allowed to know:
// the CVE identifier, the canonical snapshot root plus its externally
// supplied identity, the build context, the exec permission and the
// attempt-local audit sink. It deliberately has no slot for a benchmark
// task record, a production analysis case, ground truth or prior results
// — isolation is enforced by the type's shape, not by convention.
type SessionConfig struct {
	CVEID        string
	SnapshotRoot string
	ExternalSHA  string
	GOOS         string
	GOARCH       string
	// DeclaredGOOS/DeclaredGOARCH are the platform axes the caller actually
	// declared. The lazy snapshot probe may treat only these as target
	// facts; effective GOOS/GOARCH below describe the loaded build and must
	// never be reinterpreted as a fresh operator declaration.
	DeclaredGOOS   string
	DeclaredGOARCH string
	BuildTags      []string
	// Target is the resolved product-target provenance the lane bound before
	// loading. It is copied onto Session.Build verbatim so every
	// build-dependent negative the session's verifier produces can be
	// admitted against the analyzed build. Nil/host-default stays
	// non-admitting.
	Target        *domain.ProductTarget
	CGOEnabled    bool
	ToolchainBin  string   // resolved go binary ("go" = PATH lookup)
	ToolchainEnv  []string // PATH/GOTOOLCHAIN of the resolved toolchain
	ToolchainVer  string
	AllowExec     bool   // permits run_build / run_tests (repository code executes)
	AllowNet      bool   // permits advisory/fix HTTP research
	OSVBaseURL    string // OSV-compatible API; empty = https://api.osv.dev
	AdvisoryRoots []string
	Audit         AuditSink
	// Strict enables the hardened agent-arm profile (spec §8, checkpoint-0
	// environment gate): confinement is mandatory, the ambient module
	// cache is not a read root unless declared via ModCacheRoot, toolchain
	// subprocesses run under module-egress-hardened env, and exec-backed
	// tools additionally require AllowToolchain.
	Strict bool
	// Confine pins the confinement intent. Confinement is unconditional
	// in the evidence lane — this binary never runs unconfined; the knob
	// exists so callers and tests can express (and have refused) an
	// unconfined configuration. nil or true = confined; an explicit
	// false is a configuration error in every profile, and under strict
	// it additionally names the missing prerequisite.
	Confine *bool
	// AllowToolchain permits exec-backed toolchain tools (module graph
	// listing, run_govulncheck) under the strict profile; without it they
	// return UNSUPPORTED naming the missing permission.
	AllowToolchain bool
	// GovulnDBRoot pins the vulnerability database for strict govulncheck.
	// An empty value is rejected by run_govulncheck under strict.
	GovulnDBRoot string
	// ModCacheRoot declares a per-run module cache root: exported to the
	// toolchain env as GOMODCACHE and added to the confinement roots —
	// the only way a cache path stays readable under the strict profile.
	ModCacheRoot string
	// BuildCacheRoot declares a per-run Go build cache root: exported to
	// the toolchain env as GOCACHE so tool subprocesses and package
	// loading share one pinned cache instead of silently inheriting the
	// operator's ambient one. It is canonicalized like ModCacheRoot,
	// added to the confinement roots, and refused when it resolves
	// inside the snapshot root or a forbidden output directory.
	// Reuse the same directory across runs — a fresh cold cache costs a
	// full rebuild of the dependency closure. When neither this field
	// nor BuildCacheDirEnv declares a root, the session pins the
	// platform default and a corrupted inherited cache fails closed
	// with BuildCacheCorruptReason.
	BuildCacheRoot string
	// ToolTimeout bounds one tool invocation wall-clock. Under strict a
	// zero value resolves to DefaultToolTimeout; under the default
	// profile a zero keeps today's unbounded behaviour — the timeout
	// applies only when explicitly set or when strict requests it.
	// Expiry produces a TIMEOUT observation, never an empty result.
	ToolTimeout time.Duration
	// VulnSource overrides advisory research (tests inject a static
	// source); nil means network OSV under AllowNet.
	VulnSource vulnerability.Source
	// PatchSource overrides fix-diff fetching; nil = HTTPProvider.
	PatchSource fix.Provider
	// GoTool overrides module listing; nil = ExecGoTool.
	GoTool affected.GoTool
	// GVRunner overrides govulncheck execution; nil = ExecRunner.
	GVRunner goanalysis.Runner
	// Artifact requests the bounded release-artifact channel for the
	// session's snapshot probe so release-evidence observations see the
	// same graph the lane-level snapshot resolved. Path and URL are
	// mutually exclusive; empty means no artifact channel.
	Artifact repository.ArtifactOptions
	// ReleaseMetadata is the caller-parsed ticket/SBOM release-metadata
	// channel outcome (--release-metadata): a ReleaseEvidenceSummary
	// whose items join authoritative precedence and whose module graph
	// supplies ReleaseModules, or a NOT_RUN/RELEASE_METADATA_INVALID
	// failure summary.
	ReleaseMetadata *domain.ReleaseEvidenceSummary
}

// Session is one attempt's evidence-tool context: a single confined
// Index over the snapshot, the resolved build context, the audit sink
// and lazy backends. All handlers run under the caller's
// context.Context; backend queries are serialized inside Index.
type Session struct {
	// Immutable inputs.
	CVEID        string
	SnapshotRoot string // canonicalized
	SnapshotHash string // content hash of the snapshot tree
	ExternalSHA  string
	Build        domain.ProductSnapshot // build context only; no verdict state
	AllowExec    bool
	AllowNet     bool
	Audit        AuditSink
	// Strict / AllowToolchain / ToolTimeout carry the environment-hardening
	// profile this session was created under; ReadRoots records the
	// confinement roots resolved at creation (scope/audit evidence).
	Strict         bool
	AllowToolchain bool
	// GovulnDBRoot and ModCacheRoot carry the canonicalized pins the
	// session actually enforces — provenance must equal the scanned
	// roots, never the caller's raw spelling.
	// GovulnDBRoot, ModCacheRoot and BuildCacheRoot carry the
	// canonicalized pins the session actually enforces — provenance must
	// equal the scanned roots, never the caller's raw spelling.
	GovulnDBRoot   string
	ModCacheRoot   string
	BuildCacheRoot string
	ToolTimeout    time.Duration
	ReadRoots      []string
	// InheritedEnvKeys names the ambient variables subprocesses inherit
	// alongside ToolEnv (recorded so the audit scope is truthful about
	// the effective env, not just the appended overrides).
	InheritedEnvKeys []string

	// Backends (constructed once per session).
	Source        *goanalysis.Index
	VulnSource    vulnerability.Source
	PatchSource   fix.Provider
	GoTool        affected.GoTool
	GVRunner      goanalysis.Runner
	ToolBin       string
	ToolEnv       []string
	ToolVer       string
	GoWorkPresent bool
	// declaredGOOS/declaredGOARCH are the platform axes the caller actually
	// declared (empty when not). The snapshot probe passes only these: the
	// host-filled analysis defaults in Build must never be promoted to an
	// operator-declared product target.
	declaredGOOS   string
	declaredGOARCH string
	// Artifact / ReleaseMetadata forward the release-evidence channels to
	// the lazy snapshot probe; never read before probeSnapshot.
	Artifact        repository.ArtifactOptions
	ReleaseMetadata *domain.ReleaseEvidenceSummary

	mu      sync.Mutex
	seq     int
	vuln    *domain.Vulnerability // cached result of get_vulnerability
	vulnErr error
	vulnGot bool
	snap    *domain.ProductSnapshot
}

// NewSession validates the snapshot containment, canonicalizes the root
// and wires the backends. It does not load packages eagerly — that cost
// lands on the first source query.
func NewSession(cfg SessionConfig) (*Session, error) {
	// Confinement is unconditional in this lane: the default profile
	// must stay byte-equivalent to the always-confined behaviour, and
	// for strict it is a hard prerequisite, not a warning-level default.
	confine := cfg.Confine == nil || *cfg.Confine
	if !confine {
		if cfg.Strict {
			return nil, errors.New("strict profile requires read confinement: the Confine knob must stay enabled")
		}
		return nil, errors.New("read confinement is mandatory in the evidence lane: the Confine knob must stay enabled")
	}
	if cfg.SnapshotRoot == "" {
		return nil, errors.New("snapshot root is required")
	}
	root, err := filepath.Abs(cfg.SnapshotRoot)
	if err != nil {
		return nil, fmt.Errorf("snapshot root: %w", err)
	}
	if canon, cerr := filepath.EvalSymlinks(root); cerr == nil {
		root = canon
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("snapshot root %s is not a directory", root)
	}
	// Isolation gates run before any backend sees the tree: a snapshot
	// must not pull foreign bytes through escapes or external replaces.
	if err := repository.VerifyContained(root); err != nil {
		return nil, fmt.Errorf("snapshot containment: %w", err)
	}
	if err := repository.CheckPathReplacements(root); err != nil {
		return nil, fmt.Errorf("snapshot preflight: %w", err)
	}
	hash, err := repository.ContentHash(root)
	if err != nil {
		return nil, fmt.Errorf("snapshot content hash: %w", err)
	}
	sha := cfg.ExternalSHA
	if sha == "" {
		sha = "content-" + hash
	}

	// Hardened env additions: ambient GOFLAGS/GOWORK/GOENV overlays can
	// retarget the build or the workspace outside the snapshot — the
	// session overrides them even when a caller leaks them into the
	// process environment.
	vendorMode := repository.VendorModeInEffect(root)
	hardening := []string{
		"GOENV=off",
		"GOEXPERIMENT=",
		"GOINSECURE=",
		"GOWORK=off",
	}
	if cfg.Strict {
		// Agent-arm subprocesses must not fetch or verify modules over the
		// network. Vendored snapshots must consume their on-disk tree before
		// any module-cache resolution; non-vendored snapshots remain read-only.
		modMode := "-mod=readonly"
		if vendorMode {
			modMode = "-mod=vendor"
		}
		hardening = append(hardening,
			"GOPROXY=off",
			"GOSUMDB=off",
			"GONOSUMDB=",
			"GONOPROXY=",
			"GOPRIVATE=",
			"GOFLAGS="+modMode,
		)
		if cfg.ModCacheRoot == "" {
			// Without a declared cache the ambient GOMODCACHE/GOPATH cache
			// must not serve modules either: pin GOMODCACHE to a path that
			// can never resolve a module so go list/govulncheck fail closed
			// instead of reading a cache outside the declared read roots.
			// The path lives under the snapshot root so the pin is honest
			// provenance, and nothing may create it inside a snapshot.
			hardening = append(hardening,
				"GOMODCACHE="+filepath.Join(root, ".izyan-empty-modcache"))
		}
	} else {
		hardening = append(hardening, "GOFLAGS=")
	}
	// The pinned DB root resolves once: the canonical path feeds the
	// GOVULNDB env pin (audit evidence), the confinement roots, and the
	// runner's -db flag so the scanned database is exactly the one the
	// observation claims.
	var govulnDB string
	if cfg.GovulnDBRoot != "" {
		path, err := filepath.Abs(cfg.GovulnDBRoot)
		if err != nil {
			return nil, fmt.Errorf("govulndb: %w", err)
		}
		if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
			path = resolved
		}
		govulnDB = path
		hardening = append(hardening, "GOVULNDB="+path)
	}
	toolEnv := append(append([]string(nil), cfg.ToolchainEnv...), hardening...)
	confineRoots := append([]string(nil), cfg.AdvisoryRoots...)
	if govulnDB != "" {
		confineRoots = append(confineRoots, govulnDB)
	}
	var modCache string
	if cfg.ModCacheRoot != "" {
		// A declared per-run module cache is both exported to the
		// toolchain and added to the confinement roots; under strict this
		// is the only cache location the agent may read. Canonicalize like
		// the DB root (readgate canonicalises roots anyway): session,
		// GOMODCACHE, read roots and provenance must name one identity.
		// A genuinely missing root keeps the lexical Abs path so the error
		// message shows what the caller wrote.
		mcAbs, err := filepath.Abs(cfg.ModCacheRoot)
		if err != nil {
			return nil, fmt.Errorf("module cache root: %w", err)
		}
		if resolved, rerr := filepath.EvalSymlinks(mcAbs); rerr == nil {
			mcAbs = resolved
		}
		modCache = mcAbs
		confineRoots = append(confineRoots, mcAbs)
		toolEnv = append(toolEnv, "GOMODCACHE="+mcAbs)
	}
	// The build cache follows the declared-or-default rule: a caller may
	// pin a reusable root (field or BuildCacheDirEnv), otherwise the
	// platform default is pinned explicitly so a leaked ambient GOCACHE
	// can never reach a subprocess — the env entry itself is the guard.
	buildCache, err := resolveBuildCacheRoot(cfg.BuildCacheRoot, root, cfg.Artifact.ForbidDirs)
	if err != nil {
		return nil, err
	}
	confineRoots = append(confineRoots, buildCache)
	toolEnv = append(toolEnv, "GOCACHE="+buildCache)

	// Toolchain identity: the version recorded by the caller when known;
	// otherwise the resolved binary reports its own version under the
	// pinned env. An unresolvable toolchain keeps ToolVer empty — the
	// build context can then never claim a pinned compiler.
	toolBin := cfg.ToolchainBin
	if toolBin == "" {
		toolBin = "go"
	}
	toolVer := cfg.ToolchainVer
	if toolVer == "" {
		toolVer = probeToolchainVersion(toolBin, toolEnv)
	}

	// Effective build context: an unset GOOS/GOARCH means the toolchain's
	// own default — the loader env strips GOOS/GOARCH overrides, so the
	// effective target is the host the resolved toolchain runs on. The
	// recorded context must name real values: an empty string would hash
	// a different platform than the one the packages were loaded with.
	goos, goarch := cfg.GOOS, cfg.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	ix := &goanalysis.Index{
		Dir:                    root,
		Env:                    toolEnv,
		Confine:                confine,
		ReplaceEnv:             true,
		ConfineRoots:           confineRoots,
		ExcludeAmbientModCache: cfg.Strict,
		Build: domain.ProductSnapshot{
			Repository:        root,
			Commit:            sha,
			ExternalCommitSHA: sha,
			ContentHash:       hash,
			GoVersion:         "go version go" + toolVer + " " + goos + "/" + goarch,
			GoModDirective:    repository.GoModDirective(root),
			MinimumGoVersion:  repository.GoModDirective(root),
			GOOS:              goos,
			GOARCH:            goarch,
			BuildTags:         append([]string(nil), cfg.BuildTags...),
			CGOEnabled:        cfg.CGOEnabled,
			VendorMode:        vendorMode,
			// The hardened policy pins workspace mode off and an explicit
			// module mode; recording them here makes the session build
			// context describe what every subprocess actually receives.
			GoWorkFile:        domain.GoWorkOff,
			GoFlags:           domain.EffectiveGoFlags(envLastValue(toolEnv, "GOFLAGS"), vendorMode),
			ReplaceDirectives: repository.ReplaceDirectives(root, domain.GoWorkOff),
		},
	}
	if cfg.Target != nil {
		target := *cfg.Target
		ix.Build.Target = &target
	}

	s := &Session{
		CVEID:           cfg.CVEID,
		SnapshotRoot:    root,
		SnapshotHash:    hash,
		ExternalSHA:     sha,
		Build:           ix.Build,
		AllowExec:       cfg.AllowExec,
		AllowNet:        cfg.AllowNet,
		Strict:          cfg.Strict,
		AllowToolchain:  cfg.AllowToolchain,
		GovulnDBRoot:    govulnDB,
		ModCacheRoot:    modCache,
		BuildCacheRoot:  buildCache,
		ToolTimeout:     cfg.ToolTimeout,
		Source:          ix,
		ToolBin:         toolBin,
		ToolEnv:         toolEnv,
		ToolVer:         toolVer,
		declaredGOOS:    cfg.DeclaredGOOS,
		declaredGOARCH:  cfg.DeclaredGOARCH,
		Artifact:        cfg.Artifact,
		ReleaseMetadata: cfg.ReleaseMetadata,
	}
	if s.ToolTimeout <= 0 && cfg.Strict {
		s.ToolTimeout = DefaultToolTimeout
	}
	s.ReadRoots = ix.GateRoots()
	s.InheritedEnvKeys = envKeyNames(os.Environ())
	if s.Audit = cfg.Audit; s.Audit == nil {
		s.Audit = NewJSONLAuditSink(os.Stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err == nil {
		s.GoWorkPresent = true
	}

	// Advisory research backend.
	s.VulnSource = cfg.VulnSource
	if s.VulnSource == nil && cfg.AllowNet {
		s.VulnSource = vulnerability.OSVSource{
			BaseURL:    cfg.OSVBaseURL,
			HTTPClient: safeHTTPClient(),
		}
	}
	s.PatchSource = cfg.PatchSource
	if s.PatchSource == nil && cfg.AllowNet {
		s.PatchSource = fix.HTTPProvider{Client: safeHTTPClient()}
	}
	if cfg.GoTool != nil {
		s.GoTool = cfg.GoTool
	} else {
		s.GoTool = affected.ExecGoTool{Bin: toolBin, Env: toolEnv, Version: toolVer}
	}
	// One attempt reuses each matching product/test inventory across tools.
	s.GoTool = affected.CachingTool(s.GoTool)
	if cfg.GVRunner != nil {
		s.GVRunner = cfg.GVRunner
	} else {
		s.GVRunner = goanalysis.ExecRunner{Env: toolEnv, DBRoot: govulnDB}
	}
	return s, nil
}

// safeHTTPClient is the shared client for advisory/patch fetches: no
// file: scheme can reach http.NewRequest, but redirects are still capped
// and the default transport's env proxies are honored (egress is the
// harness's decision via AllowNet).
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-HTTP scheme %q refused", req.URL.Scheme)
			}
			return nil
		},
	}
}

// checkFetchURL rejects non-HTTP fix references — a tool argument must
// never turn the patch fetcher into a local file reader.
func checkFetchURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad fix reference URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("fix reference scheme %q is not allowed (http/https only)", u.Scheme)
	}
}

// nextID mints the session-local observation ID.
func (s *Session) nextID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("OBS-%04d", s.seq)
}

// invoke runs one tool handler, mints the Observation and writes the
// audit record. Errors inside fn become ERROR observations; a handler
// that outlives the session's per-tool timeout becomes TIMEOUT — the
// Observation contract is the only thing that reaches the caller, and a
// failed or expired check is never an empty result.
func (s *Session) invoke(ctx context.Context, tool string, args json.RawMessage,
	fn func(ctx context.Context) (*Observation, error)) *Observation {
	start := time.Now()
	var execs []domain.ToolExecution
	var mu sync.Mutex
	rec := &toolaudit.Recorder{Sink: func(t domain.ToolExecution) {
		mu.Lock()
		defer mu.Unlock()
		execs = append(execs, t)
	}}
	execsSnapshot := func() []domain.ToolExecution {
		mu.Lock()
		defer mu.Unlock()
		return append([]domain.ToolExecution(nil), execs...)
	}
	// The handler runs under a per-tool wall-clock bound in its own
	// goroutine when the session carries one (strict default or explicit
	// ToolTimeout): a backend that stops honouring ctx must not stall the
	// caller or emit a silent empty result — the abandoned call is
	// recorded as TIMEOUT.
	actx := toolaudit.WithRecorder(ctx, rec)
	if s.ToolTimeout > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(actx, s.ToolTimeout)
		defer cancel()
	}
	type result struct {
		obs *Observation
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		obs, err := fn(actx)
		resCh <- result{obs, err}
	}()
	var obs *Observation
	select {
	case res := <-resCh:
		if res.err != nil {
			obs = s.errorObs(tool, buildCacheCorruptErr(res.err, s.BuildCacheRoot))
		} else {
			obs = res.obs
		}
	case <-actx.Done():
		if errors.Is(actx.Err(), context.DeadlineExceeded) {
			obs = s.timeoutObs(tool)
		} else {
			obs = s.errorObs(tool, fmt.Errorf("caller context ended: %w", actx.Err()))
		}
	}
	if obs == nil {
		obs = s.errorObs(tool, errors.New("handler returned no observation"))
	}
	obs.ID = s.nextID()
	obs.Tool = tool
	if obs.ScopeDetails == nil {
		obs.ScopeDetails = &ScopeDetails{}
	}
	// Every observation carries the isolation boundary it ran under: the
	// profile, the resolved confinement roots and the env applied to
	// toolchain subprocesses land in the audit trail with the record.
	obs.ScopeDetails.Profile = s.profile()
	obs.ScopeDetails.ReadRoots = append([]string(nil), s.ReadRoots...)
	obs.ScopeDetails.ToolchainEnv = append([]string(nil), s.ToolEnv...)
	obs.ScopeDetails.InheritedEnvKeys = append([]string(nil), s.InheritedEnvKeys...)
	finishObservation(obs)
	if s.Audit != nil {
		// The audit is an immutable snapshot: never retain the pointer returned
		// to the caller, whose trace may be edited after this call returns.
		snapshot := cloneObservation(obs)
		s.Audit.RecordToolCall(ctx, AuditRecord{
			Tool:        tool,
			Args:        append(json.RawMessage(nil), args...),
			Observation: snapshot,
			DurationMs:  time.Since(start).Milliseconds(),
			Executions:  execsSnapshot(),
			RecordTime:  time.Now().UTC(),
		})
	}
	return obs
}

// cloneObservation makes an ownership-safe audit snapshot, including the
// typed payload and nested scope metadata. JSON is the wire contract, so this
// also avoids retaining mutable maps/slices hidden behind Data.
func cloneObservation(obs *Observation) *Observation {
	if obs == nil {
		return nil
	}
	b, err := json.Marshal(obs)
	if err != nil {
		return nil
	}
	var cp Observation
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil
	}
	return &cp
}

// profile names the hardening profile stamped into every observation.
func (s *Session) profile() string {
	if s.Strict {
		return profileStrict
	}
	return profileDefault
}

// toolchainDenied reports whether an exec-backed tool is unavailable:
// under the strict profile toolchain subprocesses (module graph listing,
// govulncheck) require the explicit AllowToolchain permission.
func (s *Session) toolchainDenied() bool {
	return s.Strict && !s.AllowToolchain
}

// timeoutObs builds a TIMEOUT observation — the check outlived its
// wall-clock bound; completeness is UNKNOWN, never PARTIAL.
func (s *Session) timeoutObs(tool string) *Observation {
	reason := fmt.Sprintf("tool exceeded its %s wall-clock timeout", s.ToolTimeout)
	return &Observation{
		Fact:         "tool execution timed out: " + reason,
		Scope:        "check abandoned",
		Completeness: CompletenessUnknown,
		ToolStatus:   StatusTimeout,
		Error:        reason,
		Limitations: []string{
			"the handler was abandoned at its deadline and may not have produced a result; a TIMEOUT observation is a failed check, not an empty or negative result",
		},
		ScopeDetails: &ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			ExternalSHA:  s.ExternalSHA,
		},
	}
}

// ok builds an OK observation; empty results stay honest through the
// completeness the caller assigns.
func (s *Session) ok(tool, fact, scope string, c Completeness, data any, sd *ScopeDetails, lims []string) *Observation {
	o := &Observation{
		Fact:         fact,
		Scope:        scope,
		Completeness: c,
		ToolStatus:   StatusOK,
		ScopeDetails: sd,
		Limitations:  lims,
	}
	if data != nil {
		d, ref, err := marshalData(data)
		if err != nil {
			return s.errorObs(tool, err)
		}
		o.Data = d
		if ref != "" {
			o.EvidenceRefs = append(o.EvidenceRefs, ref)
		}
	}
	return o
}

// errorObs builds an ERROR observation — the check did not produce a
// result; completeness is UNKNOWN, never PARTIAL.
func (s *Session) errorObs(tool string, err error) *Observation {
	return &Observation{
		Fact:         "tool execution failed: " + err.Error(),
		Scope:        "check not performed",
		Completeness: CompletenessUnknown,
		ToolStatus:   StatusError,
		Error:        err.Error(),
		ScopeDetails: &ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			ExternalSHA:  s.ExternalSHA,
		},
	}
}

// unsupported builds an UNSUPPORTED observation — the capability is not
// available in this session (missing backend or exec permission).
func (s *Session) unsupported(tool, reason string) *Observation {
	return &Observation{
		Fact:         "capability unavailable: " + reason,
		Scope:        "capability not provided",
		Completeness: CompletenessUnknown,
		ToolStatus:   StatusUnsupported,
		Error:        reason,
		ScopeDetails: &ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			ExternalSHA:  s.ExternalSHA,
		},
	}
}

// envLastValue returns the last value recorded for key in env — the value
// exec actually applies when an environment slice carries duplicates.
func envLastValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], prefix); ok {
			return v
		}
	}
	return ""
}

// probeToolchainVersion resolves the version of the go binary the
// session loads packages with. The loader env strips toolchain
// overrides, so `<bin> version` under the pinned env is the only
// trustworthy identity; "" means unresolvable — the build context then
// cannot pin the compiler that produced the inventory.
func probeToolchainVersion(bin string, env []string) string {
	if bin == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "version")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	// "go version go1.23.4 darwin/arm64" — the token after "version".
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "version" && i+1 < len(fields) {
			return strings.TrimPrefix(fields[i+1], "go")
		}
	}
	return ""
}
