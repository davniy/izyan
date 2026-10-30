package affected

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	canonicalaffected "github.com/fedorovmv/izyan/internal/affected"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/toolaudit"
)

// Module mirrors the `go list -m -json` output subset we rely on.
type Module struct {
	Path     string  `json:"Path"`
	Version  string  `json:"Version"`
	Main     bool    `json:"Main"`
	Indirect bool    `json:"Indirect"`
	Replace  *Module `json:"Replace"`
	// Dir is the on-disk directory holding the module source — the module
	// cache for fetched modules or the replacement directory for a local
	// replace. Persisted module-graph evidence carries it so reports can
	// attribute recorded source files offline.
	Dir string `json:"Dir,omitempty"`
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

// EffectiveDir is the directory the effective module source was read from.
// For a local replace it is the replacement's Dir; otherwise the module's
// own cache directory.
func (m Module) EffectiveDir() string {
	if m.Replace != nil && m.Replace.Dir != "" {
		return m.Replace.Dir
	}
	return m.Dir
}

// Package mirrors `go list -json` subset.
type Package struct {
	ImportPath string `json:"ImportPath"`
	Name       string `json:"Name"`
	Standard   bool   `json:"Standard"`
	DepOnly    bool   `json:"DepOnly"`
	Dir        string `json:"Dir"`
	// IgnoredGoFiles are source files excluded by the current build
	// constraints — they can import the affected package under another
	// tag set, so package absence is a claim about this configuration only.
	IgnoredGoFiles []string `json:"IgnoredGoFiles"`
	Module         *Module  `json:"Module"`
	Imports        []string `json:"Imports"`
	Deps           []string `json:"Deps"`
	ForTest        string   `json:"ForTest"`
}

// GoTool runs the go toolchain inside the analyzed repository. Implementations
// must return raw stdout; callers persist it as evidence. The string result
// names the actual evidence source (go list output vs vendor/modules.txt).
type GoTool interface {
	ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) (raw []byte, source string, err error)
	ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
	// ListBuildPackages is the non-test package closure: the same `go list
	// -deps` surface without `-test`, so a caller can diff the two sets and
	// decide which packages exist only for tests.
	ListBuildPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
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

// ToolchainEnvironment exposes the execution policy of the real Go backend,
// including through its cache. Unknown backends cannot pin a compiler identity.
func ToolchainEnvironment(tool GoTool) (string, []string, bool) {
	switch t := tool.(type) {
	case ExecGoTool:
		return t.Bin, t.Env, true
	case *ExecGoTool:
		return t.Bin, t.Env, true
	case *cachingTool:
		return ToolchainEnvironment(t.inner)
	default:
		return "", nil, false
	}
}

func (t ExecGoTool) bin() string {
	if t.Bin != "" {
		return t.Bin
	}
	return "go"
}

func (t ExecGoTool) ListModules(ctx context.Context, dir string, _ domain.ProductSnapshot) ([]byte, string, error) {
	const goList = "go list -m -json all"
	raw, err := runGo(ctx, t.bin(), t.Version, dir, t.Env, "list", "-m", "-json", "all")
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

func (t ExecGoTool) ListBuildPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return (canonicalaffected.ExecGoTool{Bin:t.Bin, Env:t.Env, Version:t.Version}).ListPackagesScope(ctx, dir, build, false)
}

func (t ExecGoTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return (canonicalaffected.ExecGoTool{Bin:t.Bin, Env:t.Env, Version:t.Version}).ListPackagesScope(ctx, dir, build, true)
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

// DecodePackages parses the `go list -json` stream into packages — the
// shared wire decoder for persisted package-list evidence.

func DecodePackages(b []byte) ([]Package, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var out []Package
		if err := json.Unmarshal(trimmed, &out); err == nil {
			return out, nil
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var out []Package
	for dec.More() {
		var p Package
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// PackageImportPaths uses the canonical strict, edge-closed inventory
// decision. Failed or partial streams never become an empty closed universe.
func PackageImportPaths(b []byte) (map[string]bool, error) {
	return canonicalaffected.PackageImportPaths(b)
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
	mOnce sync.Once
	mRaw  []byte
	mSrc  string
	mErr  error
	pOnce sync.Once
	pRaw  []byte
	pErr  error
	bOnce sync.Once
	bRaw  []byte
	bErr  error
}

func (t *cachingTool) ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, string, error) {
	t.mOnce.Do(func() {
		t.mRaw, t.mSrc, t.mErr = t.inner.ListModules(ctx, dir, build)
	})
	return t.mRaw, t.mSrc, t.mErr
}

func (t *cachingTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	t.pOnce.Do(func() {
		t.pRaw, t.pErr = t.inner.ListPackages(ctx, dir, build)
	})
	return t.pRaw, t.pErr
}

func (t *cachingTool) ListBuildPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	t.bOnce.Do(func() {
		t.bRaw, t.bErr = t.inner.ListBuildPackages(ctx, dir, build)
	})
	return t.bRaw, t.bErr
}

// Package inventory types and functions re-exported for adapter consumers
type PackageInventoryMeasurement = canonicalaffected.PackageInventoryMeasurement

var (
	CompletePackageInventory = canonicalaffected.CompletePackageInventory
	RecordPackageInventory   = canonicalaffected.RecordPackageInventory
)
