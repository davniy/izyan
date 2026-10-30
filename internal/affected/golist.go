package affected

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/toolaudit"
)

// Module mirrors the `go list -m -json` output subset we rely on.
type Module struct {
	Path     string  `json:"Path"`
	Version  string  `json:"Version"`
	Main     bool    `json:"Main"`
	Indirect bool    `json:"Indirect"`
	Replace  *Module `json:"Replace"`
}

// EffectivePath/EffectiveVersion unwrap replace directives: the version that
// actually lands in the build is what matters for range matching.
func (m Module) EffectivePath() string {
	if m.Replace != nil && m.Replace.Path != "" {
		return m.Replace.Path
	}
	return m.Path
}

func (m Module) EffectiveVersion() string {
	if m.Replace != nil && m.Replace.Version != "" {
		return m.Replace.Version
	}
	return m.Version
}

// Package mirrors `go list -json` subset.
type Package struct {
	ImportPath string `json:"ImportPath"`
	Name       string `json:"Name"`
	Standard   bool   `json:"Standard"`
	DepOnly    bool   `json:"DepOnly"`
	Dir        string `json:"Dir"`
	GoFiles []string `json:"GoFiles"`
	CompiledGoFiles []string `json:"CompiledGoFiles"`
	CgoFiles []string `json:"CgoFiles"`
	SFiles []string `json:"SFiles"`
	SysoFiles []string `json:"SysoFiles"`
	// IgnoredGoFiles are source files excluded by the current build
	// constraints — they can import the affected package under another
	// tag set, so package absence is a claim about this configuration only.
	IgnoredGoFiles []string `json:"IgnoredGoFiles"`
	Module         *Module  `json:"Module"`
	Imports        []string `json:"Imports"`
	Deps           []string `json:"Deps"`
	ForTest        string   `json:"ForTest"`
	// Incomplete/Error/DepsErrors mirror `go list` package-error fields. A
	// node carrying them (or one whose deps failed to resolve) is evidence
	// the stream is not a closed graph — never a proof of absence.
	Incomplete bool            `json:"Incomplete"`
	Error      *PackageError   `json:"Error"`
	DepsErrors []*PackageError `json:"DepsErrors"`
}

// PackageError mirrors `go list`'s error object.
type PackageError struct {
	ImportStack []string `json:"ImportStack"`
	Pos         string   `json:"Pos"`
	Err         string   `json:"Err"`
}

// GoTool runs the go toolchain inside the analyzed repository. Implementations
// must return raw stdout; callers persist it as evidence. The string result
// names the actual evidence source (go list output vs vendor/modules.txt).
type GoTool interface {
	ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) (raw []byte, source string, err error)
	// ListPackages is the existing resolver entry point: the merged
	// `go list -deps -test -json ./...` stream. It delegates to
	// ListPackagesScope(..., true).
	ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
	// ListPackagesScope returns the package stream for one build-closure
	// scope: withTests=false runs `go list -deps -json ./...` (product
	// closure), withTests=true runs `go list -deps -test -json ./...`
	// (merged stream the test closure is derived from).
	ListPackagesScope(ctx context.Context, dir string, build domain.ProductSnapshot, withTests bool) ([]byte, error)
}

// ExecGoTool runs `go` subprocesses. Bin overrides the go binary and Env
// carries toolchain env (PATH/GOTOOLCHAIN) so checks execute under the
// target toolchain, not whatever happens to be in PATH. Version tags
// audit records with the resolved toolchain version.
type ExecGoTool struct {
	Bin     string
	Env     []string
	Version string
}

func (t ExecGoTool) bin() string {
	if t.Bin != "" {
		return t.Bin
	}
	return "go"
}

func (t ExecGoTool) ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, string, error) {
	const goList = "go list -m -json all"
	raw, err := runGo(ctx, t.bin(), t.Version, dir, buildToolEnv(build, t.Env), "list", "-m", "-json", "all")
	if err == nil {
		return raw, goList, nil
	}
	// Vendor mode: `go list -m all` refuses to run. modules.txt is the
	// authoritative record of what is actually vendored.
	mods, vErr := loadVendorModules(dir)
	if vErr != nil {
		return raw, goList, err
	}
	var buf bytes.Buffer
	for _, m := range mods {
		b, mErr := json.Marshal(m)
		if mErr != nil {
			return nil, goList, mErr
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), "vendor/modules.txt", nil
}

func (t ExecGoTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return t.ListPackagesScope(ctx, dir, build, true)
}

func (t ExecGoTool) ListPackagesScope(ctx context.Context, dir string, build domain.ProductSnapshot, withTests bool) ([]byte, error) {
	args := []string{"list", "-deps"}
	if withTests {
		args = append(args, "-test")
	}
	args = append(args, "-json")
	if len(build.BuildTags) > 0 {
		args = append(args, "-tags", strings.Join(build.BuildTags, ","))
	}
	args = append(args, "./...")
	return runGo(ctx, t.bin(), t.Version, dir, buildToolEnv(build, t.Env), args...)
}

// buildToolEnv orders the subprocess environment: the toolchain policy env
// first, then the snapshot's resolved build selection (GOOS/GOARCH/CGO,
// workspace mode, effective GOFLAGS) so the snapshot is the last word.
func buildToolEnv(build domain.ProductSnapshot, policyEnv []string) []string {
	env := make([]string, 0, len(policyEnv)+5)
	env = append(env, policyEnv...)
	env = append(env, domain.BuildEnv(build)...)
	return env
}

func runGo(ctx context.Context, bin, version, dir string, env []string, args ...string) ([]byte, error) {
	stdout, stderr, err := toolaudit.Run(ctx, "go", version, dir, bin, env, args...)
	if err != nil {
		return stdout, fmt.Errorf("go %v: %w: %s", args, err, stderr)
	}
	return stdout, nil
}

// DecodeModules parses the `go list -m -json` stream into modules.
func DecodeModules(b []byte) ([]Module, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var out []Module
	for dec.More() {
		var m Module
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// decodePackages parses one `go list -json` stream (or the legacy array
// form) and consumes the input through EOF: a valid prefix followed by a
// truncated value, a stray token or trailing junk is a decode error, never
// a complete stream. On error the successfully decoded prefix is returned
// for positive-only observations — callers must not read it as a closed
// inventory.
func decodePackages(b []byte) ([]Package, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		// The array form is a single JSON value; Unmarshal already rejects
		// trailing content. It is all-or-nothing, so no prefix survives.
		var out []Package
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var out []Package
	for {
		var p Package
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		out = append(out, p)
	}
}

// PackageInventory is one decoded `go list -deps [-test] -json` inventory.
// Packages and Paths are populated even when the completeness check fails
// so callers can preserve a witnessed positive observation; an errored
// inventory MUST NOT ground an absence conclusion.
type PackageInventory struct {
	Packages []Package
	Paths    map[string]bool
}

// CompletePackageInventory decodes a package stream and admits it only when
// buildPackageGraph accepts it as a complete, edge-closed inventory. It
// reuses that validator instead of restating its completeness rules: decode
// failures, package-error nodes, duplicate nodes, dangling edges,
// inconsistent dependency inventories and orphan nodes all return an error.
func CompletePackageInventory(raw []byte, command string) (PackageInventory, error) {
	if command == "" {
		command = "go list -deps -json"
	}
	pkgs, err := decodePackages(raw)
	if err != nil {
		inv := packageInventoryOf(pkgs)
		return inv, fmt.Errorf("%s: decode package stream: %w", command, err)
	}
	inv := packageInventoryOf(pkgs)
	if _, err := buildPackageGraphPackages(pkgs, command); err != nil {
		return inv, err
	}
	return inv, nil
}

// PackageInventoryMeasurement preserves the full Go stdout, not a display
// prefix. Run.Complete covers only the declared build package graph; it says
// nothing about source/load coverage, module graphs or upstream source trees.
type PackageInventoryMeasurement struct {
	RawStream    string                `json:"raw_stream"`
	RawSHA256    string                `json:"raw_sha256"`
	RawReference string                `json:"raw_reference"`
	RawSize      int                   `json:"raw_size"`
	Run          domain.PackageListRun `json:"run"`
	Packages     []Package             `json:"packages"`
	Build        domain.BuildContext   `json:"build"`
	Scope        string                `json:"scope"`
}

// MeasurePackageInventory is the shared command-success and strict decoding
// decision. Even failed commands retain witnessed nodes, never a closed empty
// universe. A vendor module derivation cannot enter this package-stream path.
func MeasurePackageInventory(ctx context.Context, tool GoTool, dir string, build domain.ProductSnapshot, withTests bool) PackageInventoryMeasurement {
	raw, runErr := tool.ListPackagesScope(ctx, dir, build, withTests)
	return RecordPackageInventory(raw, runErr, build, withTests)
}

// RecordPackageInventory binds already captured stdout to its actual command
// outcome and effective build, using the same admission decision as live calls.
func RecordPackageInventory(raw []byte, runErr error, build domain.ProductSnapshot, withTests bool) PackageInventoryMeasurement {
	inv, decodeErr := CompletePackageInventory(raw, "go list -deps [-test] -json ./...")
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	run := domain.PackageListRun{Completed: runErr == nil, Complete: runErr == nil && decodeErr == nil, WithTests: withTests, Pattern: "./...", RawSHA256: digest}
	if runErr != nil {
		run.Error = runErr.Error()
	}
	if decodeErr != nil {
		if run.Error != "" {
			run.Error += "; "
		}
		run.Error += decodeErr.Error()
	}
	return PackageInventoryMeasurement{
		RawStream: string(raw), RawSHA256: digest, RawReference: "sha256:" + digest,
		RawSize: len(raw), Run: run, Packages: inv.Packages,
		Build: domain.EffectiveBuildContext(build),
		Scope: "./... plus transitive dependencies; one effective build; tests selected explicitly",
	}
}

// Admit replays the exact stream and effective build. Neither serialized
// completeness nor a caller-supplied decoded package list grants admission.
func (d PackageInventoryMeasurement) Admit(product domain.ProductSnapshot) (PackageInventory, error) {
	return d.AdmitBuild(domain.EffectiveBuildContext(product))
}

// AdmitBuild checks persisted inventory against an independently recorded build.
func (d PackageInventoryMeasurement) AdmitBuild(build domain.BuildContext) (PackageInventory, error) {
	sum := sha256.Sum256([]byte(d.RawStream))
	if d.RawSize != len(d.RawStream) || d.RawSHA256 != hex.EncodeToString(sum[:]) || d.RawReference != "sha256:"+d.RawSHA256 || d.Run.RawSHA256 != d.RawSHA256 {
		return PackageInventory{}, fmt.Errorf("inventory raw stream binding mismatch")
	}
	if err := d.Build.Matches(build); err != nil {
		return PackageInventory{}, err
	}
	if !d.Run.Completed || !d.Run.Complete || d.Run.Pattern != "./..." || d.Run.Error != "" {
		return PackageInventory{}, fmt.Errorf("inventory did not complete the declared build scope")
	}
	return CompletePackageInventory([]byte(d.RawStream), "go list -deps [-test] -json ./...")
}

// packageInventoryOf projects decoded package nodes onto their import-path
// set. Empty paths (a `null` stream value) are not package identities.
func packageInventoryOf(pkgs []Package) PackageInventory {
	inv := PackageInventory{
		Packages: pkgs,
		Paths:    make(map[string]bool, len(pkgs)),
	}
	for i := range pkgs {
		if pkgs[i].ImportPath != "" {
			inv.Paths[pkgs[i].ImportPath] = true
		}
	}
	return inv
}

// PackageImportPaths decodes a `go list -deps -json` stream (already
// persisted as package-list evidence) into the set of import paths the
// snapshot's build graph links — under the build context (GOOS/GOARCH/
// tags) the list was produced with. It is the absence check of the
// defect-locus contract, so the stream must be a complete, edge-closed
// inventory: a partial stdout, package-error node or inconsistent graph is
// an error, and callers must not treat it as evidence of absence.
func PackageImportPaths(b []byte) (map[string]bool, error) {
	inv, err := CompletePackageInventory(b, "go list -deps -json")
	if err != nil {
		return nil, err
	}
	return inv.Paths, nil
}

// AdmittedBuildGraph is the single decoder every absence consumer uses to turn
// persisted evidence into the admitted build graph the shared absence admission
// is measured against. It selects only a completed, complete package-list
// inventory whose recorded build context matches the snapshot; a missing,
// context-mismatched or undecodable inventory is reported as not admitted and
// never degrades into an empty graph that would read as universal absence.
func AdmittedBuildGraph(product domain.ProductSnapshot, evidence []domain.Evidence) domain.AbsenceBuildGraph {
	e, err := domain.SelectCompletePackageList(product, evidence)
	if err != nil {
		return domain.AbsenceBuildGraph{Reason: err.Error()}
	}
	set, derr := PackageImportPaths([]byte(e.Content))
	if derr != nil {
		return domain.AbsenceBuildGraph{
			EvidenceID: e.ID,
			Reason:     fmt.Sprintf("package list %s is not a complete inventory: %v", e.ID, derr),
		}
	}
	return domain.AbsenceBuildGraph{Paths: set, EvidenceID: e.ID, Admitted: true}
}

// loadVendorModules parses vendor/modules.txt — the authoritative
// module list when the repository builds in vendor mode.
func loadVendorModules(dir string) ([]Module, error) {
	b, err := os.ReadFile(filepath.Join(dir, "vendor", "modules.txt"))
	if err != nil {
		return nil, err
	}
	return ParseVendorModules(b), nil
}

// ParseVendorModules extracts module entries from vendor/modules.txt.
// Header lines look like:
//
//	# example.com/mod v1.2.3
//	# old.com/mod v1.0.0 => fork.com/mod v1.5.0
//	# old.com/mod v1.0.0 => ./local/dir
func ParseVendorModules(b []byte) []Module {
	var mods []Module
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "# ") {
			continue // package line, meta line (##) or blank
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) < 2 {
			continue
		}
		m := Module{Path: fields[0], Version: fields[1]}
		if len(fields) >= 4 && fields[2] == "=>" {
			m.Replace = &Module{Path: fields[3]}
			if len(fields) >= 5 {
				m.Replace.Version = fields[4]
			}
		}
		mods = append(mods, m)
	}
	return mods
}

// CachingTool memoizes GoTool results for one (repo, build) pair — in
// scan mode the same module/package listing serves every advisory.
func CachingTool(inner GoTool) GoTool { return &cachingTool{inner: inner} }

type cachingTool struct {
	inner GoTool
	// The cache serves exactly one build. The first call captures its
	// repository directory and effective build context; a later call for a
	// different one is refused instead of returning output produced under
	// another build. Kept single-build by design — no multi-key cache.
	mu       sync.Mutex
	bound    bool
	boundDir string
	boundCtx domain.BuildContext
	mOnce    sync.Once
	mRaw     []byte
	mSrc     string
	mErr     error
	// The two package streams are cached separately: a cached `-test`
	// result must never answer a no-test request.
	pOnce     sync.Once
	pRaw      []byte
	pErr      error
	pTestOnce sync.Once
	pTestRaw  []byte
	pTestErr  error
}

// admit locks the cache to one (dir, build) pair. Callers must not hold the
// cache mutex around the inner call: the inner tool may be slow, but the
// binding decision is made before any cached value can be served.
func (t *cachingTool) admit(dir string, build domain.ProductSnapshot) error {
	ctx := domain.EffectiveBuildContext(build)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.bound {
		t.bound, t.boundDir, t.boundCtx = true, dir, ctx
		return nil
	}
	if t.boundDir != dir {
		return fmt.Errorf("go tool cache: repository %q != %q: %w", dir, t.boundDir, domain.ErrBuildContextMismatch)
	}
	if err := t.boundCtx.Matches(ctx); err != nil {
		return fmt.Errorf("go tool cache: %w", err)
	}
	return nil
}

func (t *cachingTool) ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, string, error) {
	if err := t.admit(dir, build); err != nil {
		return nil, "", err
	}
	t.mOnce.Do(func() {
		t.mRaw, t.mSrc, t.mErr = t.inner.ListModules(ctx, dir, build)
	})
	return t.mRaw, t.mSrc, t.mErr
}

func (t *cachingTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return t.ListPackagesScope(ctx, dir, build, true)
}

func (t *cachingTool) ListPackagesScope(ctx context.Context, dir string, build domain.ProductSnapshot, withTests bool) ([]byte, error) {
	if err := t.admit(dir, build); err != nil {
		return nil, err
	}
	if !withTests {
		t.pOnce.Do(func() {
			t.pRaw, t.pErr = t.inner.ListPackagesScope(ctx, dir, build, false)
		})
		return t.pRaw, t.pErr
	}
	t.pTestOnce.Do(func() {
		t.pTestRaw, t.pTestErr = t.inner.ListPackagesScope(ctx, dir, build, true)
	})
	return t.pTestRaw, t.pTestErr
}

// ReleaseModulesFor selects the module graph that grounds release-version
// applicability for this snapshot. The release binary's build-info module
// list — recorded on the snapshot as ReleaseModules — is the authoritative
// graph: a released artifact may carry dependency versions the checkout's
// own go list/vendor resolution never produced. The returned bool reports
// whether such a graph was present; the string names its status, or the
// reason the release graph is unavailable (a fail-closed
// ARTIFACT_*/RELEASE_* code when an explicitly requested channel did not
// resolve, ARTIFACT_NOT_REQUESTED when none was asked for). A nil summary
// under an explicit request is treated as a failed channel: the evidence
// contract requires a recorded outcome. Callers that need the status
// without the module list may use releaseAxisStatus.
func ReleaseModulesFor(product domain.ProductSnapshot) ([]Module, bool, string) {
	if len(product.ReleaseModules) > 0 {
		return releaseModulesToModules(product.ReleaseModules), true, "RESOLVED"
	}
	return nil, false, releaseAxisStatus(product)
}

// releaseAxisStatus composes the "STATUS" or "STATUS/REASON" name for the
// release evidence axis of a snapshot.
func releaseAxisStatus(product domain.ProductSnapshot) string {
	re := product.ReleaseEvidence
	if re == nil {
		if product.ReleaseEvidenceRequired {
			return string(domain.ReleaseStatusNotRun) + "/" + domain.ReleaseReasonAbsent
		}
		return string(domain.ReleaseStatusNotRequested) + "/" + domain.ReleaseReasonArtifactNotRequested
	}
	if len(re.RequiredChannelFailures) > 0 {
		return string(domain.ReleaseStatusNotRun) + "/" + re.RequiredChannelFailures[0]
	}
	status := re.Status
	if status == "" {
		status = domain.ReleaseStatusUnknown
	}
	if re.ReasonCode != "" {
		return string(status) + "/" + re.ReasonCode
	}
	return string(status)
}

// releaseToolchainStatus composes the toolchain axis's own "STATUS" or
// "STATUS/REASON" name. Unlike releaseAxisStatus it is never upgraded to
// RESOLVED by the presence of an authoritative release module graph: the
// toolchain and module axes are independent, so a SUPPORTING-only or
// failed toolchain outcome keeps naming itself even when the module graph
// is authoritative. A CONFLICTED toolchain outcome outranks a competing
// module-channel failure — the conflict is what leaves the toolchain
// undecided.
func releaseToolchainStatus(product domain.ProductSnapshot) string {
	re := product.ReleaseEvidence
	if re == nil {
		if product.ReleaseEvidenceRequired {
			return string(domain.ReleaseStatusNotRun) + "/" + domain.ReleaseReasonAbsent
		}
		return string(domain.ReleaseStatusNotRequested) + "/" + domain.ReleaseReasonArtifactNotRequested
	}
	status := re.Status
	if status == "" {
		status = domain.ReleaseStatusUnknown
	}
	if len(re.RequiredChannelFailures) > 0 &&
		status != domain.ReleaseStatusResolved &&
		status != domain.ReleaseStatusConflicted {
		return string(domain.ReleaseStatusNotRun) + "/" + re.RequiredChannelFailures[0]
	}
	if re.ReasonCode != "" {
		return string(status) + "/" + re.ReasonCode
	}
	return string(status)
}

// ReleaseVersionAxisBlocked reports whether an explicitly requested
// release-evidence channel failed to produce an authoritative module
// graph. In that state the source checkout's own module resolution must
// NOT substitute for release-version facts: the product's declared
// dependency versions are provenance, not evidence of what shipped.
// A RESOLVED channel that legitimately produced no module list (a plain
// --binary toolchain read) keeps the historical source-graph fallback.
func ReleaseVersionAxisBlocked(product domain.ProductSnapshot) bool {
	if len(product.ReleaseModules) > 0 || !product.ReleaseEvidenceRequired {
		return false
	}
	re := product.ReleaseEvidence
	if re == nil {
		return true
	}
	if len(re.RequiredChannelFailures) > 0 {
		return true
	}
	if re.Status == domain.ReleaseStatusResolved {
		return false
	}
	return true
}

// releaseModulesToModules converts release build-info modules into the
// resolver's internal module representation. Replace is preserved —
// effective coordinates, not declared ones, decide range matching.
func releaseModulesToModules(rms []domain.ReleaseModule) []Module {
	mods := make([]Module, 0, len(rms))
	for _, rm := range rms {
		mods = append(mods, releaseModuleToModule(rm))
	}
	return mods
}

func releaseModuleToModule(rm domain.ReleaseModule) Module {
	m := Module{Path: rm.Path, Version: rm.Version, Main: rm.Main}
	if rm.Replace != nil {
		r := releaseModuleToModule(*rm.Replace)
		m.Replace = &r
	}
	return m
}

// releaseModuleVersions returns the first module entry matching path plus
// the distinct effective versions the release module graph records for
// it, in graph order. Duplicates with one effective version are a single
// observation; more than one distinct effective version is a conflict —
// release evidence that disagrees with itself resolves nothing.
func releaseModuleVersions(mods []Module, path string) (Module, []string, bool) {
	var first Module
	foundFirst := false
	var versions []string
	for _, m := range mods {
		if m.Path != path && m.EffectivePath() != path {
			continue
		}
		if !foundFirst {
			first, foundFirst = m, true
		}
		v := m.EffectiveVersion()
		found := false
		for _, seen := range versions {
			if seen == v {
				found = true
				break
			}
		}
		if !found {
			versions = append(versions, v)
		}
	}
	return first, versions, len(versions) > 1
}
