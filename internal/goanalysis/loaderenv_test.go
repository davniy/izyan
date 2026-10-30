package goanalysis

import (
	"context"
	"go/token"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/fedorovmv/izyan/internal/domain"
)

func lastEnvValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], prefix); ok {
			return v, true
		}
	}
	return "", false
}

// Under ReplaceEnv an ambient GOCACHE must not reach the loader: the
// session pins the declared/default root through Index.Env, and that
// pin — not a caller-leaked value — is what the go subprocess sees.
func TestLoadEnvExcludesAmbientGOCACHE(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	pin := t.TempDir()

	ix := &Index{Dir: t.TempDir(), ReplaceEnv: true, Env: []string{"GOCACHE=" + pin}}
	if v, _ := lastEnvValue(ix.loadEnv(), "GOCACHE"); v != pin {
		t.Fatalf("pinned GOCACHE lost: env=%v", ix.loadEnv())
	}
	ix2 := &Index{Dir: t.TempDir(), ReplaceEnv: true}
	if _, ok := lastEnvValue(ix2.loadEnv(), "GOCACHE"); ok {
		t.Fatal("ambient GOCACHE must not be inherited under ReplaceEnv")
	}
}

// Product-root loads and dependency-extra loads must run under one shared
// build context: GOOS/GOARCH/CGO_ENABLED, build flags (tags), the
// toolchain/build env (vendor mode, GOCACHE, toolchain pins) and the
// caller's cancellation context. loadConfig is the single construction
// site — this test pins the contract so a future call site cannot
// silently diverge.
func TestLoadConfigSharedBuildContext(t *testing.T) {
	ix := &Index{
		Dir: t.TempDir(),
		Build: domain.ProductSnapshot{
			GOOS: "linux", GOARCH: "arm64", CGOEnabled: true,
			BuildTags:  []string{"beta", "db"},
			VendorMode: true,
			GoWorkFile: domain.GoWorkOff,
		},
		ReplaceEnv: true,
		Env:        []string{"GOCACHE=/tmp/izyan-buildcache"},
	}
	fset := token.NewFileSet()
	ctx := context.WithValue(context.Background(), struct{ k string }{"k"}, "v")

	roots := ix.loadConfig(loadMode, fset, ctx)
	extra := ix.loadConfig(loadMode, fset, ctx)
	census := ix.loadConfig(packages.NeedName|packages.NeedImports|packages.NeedModule, nil, ctx)

	if roots.Dir != ix.Dir || roots.Fset != fset {
		t.Fatalf("loadConfig lost dir/fset: %+v", roots)
	}
	if census.Fset != nil {
		t.Fatal("census load must not attach the index fileset")
	}
	for _, kv := range []string{
		"GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=1", "GOFLAGS=-mod=vendor",
		"GOWORK=off", "GOCACHE=/tmp/izyan-buildcache",
	} {
		key, _, _ := strings.Cut(kv, "=")
		for name, env := range map[string][]string{"roots": roots.Env, "extra": extra.Env, "census": census.Env} {
			if v, ok := lastEnvValue(env, key); !ok || v != kv[len(key)+1:] {
				t.Fatalf("%s env missing %s: %v", name, kv, env)
			}
		}
	}
	wantFlags := []string{"-tags", "beta,db"}
	for name, cfg := range map[string]*packages.Config{"roots": roots, "extra": extra, "census": census} {
		if !slices.Equal(cfg.BuildFlags, wantFlags) {
			t.Fatalf("%s BuildFlags=%v, want %v", name, cfg.BuildFlags, wantFlags)
		}
		if cfg.Context != ctx {
			t.Fatalf("%s lost the caller cancellation context", name)
		}
	}
}

// Under VendorMode the dependency-extra load must inherit the same
// GOFLAGS=-mod=vendor (and the rest of the pinned env) as the product-root
// load: GOPROXY=off makes any module-cache resolution attempt fail loudly,
// so a divergent extra load cannot silently fall back to another source.
func TestLoadEnvSharedContextVendoredExtras(t *testing.T) {
	dir := usageModuleGomod(t,
		"module example.com/vendprod\n\ngo 1.23\n\nrequire example.com/vdep v1.0.0\n",
		map[string]string{
			"main.go": `package main

import "example.com/vdep"

func main() { println(vdep.V) }
`,
			"vendor/example.com/vdep/v.go": `package vdep

var V = 1
`,
			"vendor/example.com/vdep/go.mod": "module example.com/vdep\n\ngo 1.23\n",
			"vendor/modules.txt": `# example.com/vdep v1.0.0
## explicit; go 1.23
example.com/vdep
`,
		})
	ix := &Index{
		Dir:   dir,
		Build: domain.ProductSnapshot{VendorMode: true},
		Env:   []string{"GOPROXY=off"},
	}
	if err := ix.load(context.Background()); err != nil {
		t.Fatalf("product load under vendor mode failed: %v", err)
	}
	pkgs, err := ix.loadExtra(context.Background(), "example.com/vdep")
	if err != nil {
		t.Fatalf("extras load diverged from the shared load context: %v", err)
	}
	var target *packages.Package
	for _, p := range pkgs {
		if p.PkgPath == "example.com/vdep" {
			target = p
		}
	}
	if target == nil || target.Types == nil {
		t.Fatalf("vendored dep did not load with types under the shared context: %+v", pkgs)
	}
	if len(ix.skipped) != 0 {
		t.Fatalf("a fully type-checked closure must report no skipped packages: %+v", ix.skipped)
	}
}
