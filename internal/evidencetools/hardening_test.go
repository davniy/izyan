package evidencetools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// envValue reports the last KEY=value entry of env — the one a
// subprocess actually sees (exec.Cmd honours later duplicates).
func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], prefix); ok {
			return v, true
		}
	}
	return "", false
}

// canonical renders p the way readgate.New canonicalises roots.
func canonical(t *testing.T, p string) string {
	t.Helper()
	c, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := filepath.Abs(c)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(a)
}

func hasRoot(roots []string, canon string) bool {
	for _, r := range roots {
		if r == canon {
			return true
		}
	}
	return false
}

func readFile(s *Session, file string) *Observation {
	return s.invoke(context.Background(), "read_source", nil,
		func(c context.Context) (*Observation, error) {
			return s.readSource(c, readSourceArgs{File: file})
		})
}

// E1: the strict profile refuses to start without confinement — a
// missing prerequisite is a hard error naming the knob, not a warning.
func TestStrictProfileRequiresConfinement(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))

	off := false
	_, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, Confine: &off, Audit: NopAudit{}})
	if err == nil {
		t.Fatal("strict session without confinement must refuse to start")
	}
	if !strings.Contains(err.Error(), "confin") && !strings.Contains(err.Error(), "Confine") {
		t.Fatalf("error must name the confinement knob: %v", err)
	}

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	if len(s.ReadRoots) == 0 {
		t.Fatal("confined strict session must record its read roots")
	}
}

// F1: the default profile cannot run unconfined either — confinement is
// unconditional in the evidence lane, so an explicit opt-out is a
// configuration error everywhere, not only under strict.
func TestDefaultProfileCannotRunUnconfined(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	off := false
	if _, err := NewSession(SessionConfig{
		SnapshotRoot: root, Confine: &off, Audit: NopAudit{}}); err == nil {
		t.Fatal("default session with confinement off must refuse to start")
	} else if !strings.Contains(err.Error(), "confin") {
		t.Fatalf("error must name the confinement knob: %v", err)
	}
}

// E2: under strict the ambient host module cache is not a read root;
// only an explicitly declared per-run cache may be read.
func TestStrictModuleCacheIsNotAReadRoot(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	hostCache := filepath.Join(parent, "hostcache")
	must(t, os.MkdirAll(hostCache, 0o755))
	must(t, os.WriteFile(filepath.Join(hostCache, "dep.go"),
		[]byte("package dep\n"), 0o644))
	target := filepath.Join(hostCache, "dep.go")
	t.Setenv("GOMODCACHE", hostCache)

	// Default profile keeps today's behaviour: the ambient module cache
	// stays a read root.
	def, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)
	if o := readFile(def, target); o.ToolStatus != StatusOK {
		t.Fatalf("default profile must still read the module cache: %s", o.Error)
	}

	// Strict: a file inside the host GOMODCACHE is denied.
	strict, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	if o := readFile(strict, target); o.ToolStatus != StatusError {
		t.Fatalf("strict profile must deny host module-cache reads, got %s", o.ToolStatus)
	}
	if hasRoot(strict.ReadRoots, canonical(t, hostCache)) {
		t.Fatalf("host module cache leaked into strict read roots: %v", strict.ReadRoots)
	}

	// Strict + declared per-run cache: the declared root is readable;
	// the ambient cache and everything else outside the snapshot stays
	// denied.
	perRun := filepath.Join(parent, "perrun-cache")
	must(t, os.MkdirAll(perRun, 0o755))
	must(t, os.WriteFile(filepath.Join(perRun, "dep.go"),
		[]byte("package dep\n"), 0o644))
	outside := filepath.Join(parent, "outside.go")
	must(t, os.WriteFile(outside, []byte("package x\n"), 0o644))

	declared, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, ModCacheRoot: perRun, Audit: NopAudit{}})
	must(t, err)
	if !hasRoot(declared.ReadRoots, canonical(t, perRun)) {
		t.Fatalf("declared cache missing from read roots: %v", declared.ReadRoots)
	}
	if o := readFile(declared, filepath.Join(perRun, "dep.go")); o.ToolStatus != StatusOK {
		t.Fatalf("declared per-run cache must be readable: %s", o.Error)
	}
	if o := readFile(declared, target); o.ToolStatus != StatusError {
		t.Fatalf("ambient cache must stay denied once a per-run cache is declared: %s", o.ToolStatus)
	}
	if o := readFile(declared, outside); o.ToolStatus != StatusError {
		t.Fatalf("files outside snapshot + declared cache must be denied: %s", o.ToolStatus)
	}
}

// E7: with no declared --modcache a strict session must not fall back to
// the ambient host cache from a toolchain subprocess either — ToolEnv
// pins GOMODCACHE to a path that can never resolve a module, so
// go list / govulncheck fail closed instead of silently reading a cache
// that stays outside the declared read roots. A declared cache keeps
// its own pin.
func TestStrictOmittedModCacheBlocksAmbientFallback(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	ambient := filepath.Join(parent, "ambient-cache")
	must(t, os.MkdirAll(ambient, 0o755))
	t.Setenv("GOMODCACHE", ambient)
	// A GOPATH-derived ambient cache must be unreachable too: the
	// GOMODCACHE pin wins over any inherited GOPATH.
	t.Setenv("GOPATH", filepath.Join(parent, "ambient-gopath"))

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	v, ok := envValue(s.ToolEnv, "GOMODCACHE")
	if !ok || v == ambient {
		t.Fatalf("strict ToolEnv must pin GOMODCACHE away from the ambient cache, got %q ok=%v", v, ok)
	}
	if filepath.Dir(v) != s.SnapshotRoot || filepath.Base(v) != ".izyan-empty-modcache" {
		t.Fatalf("blocked-cache pin must be the inert path under the snapshot root, got %q", v)
	}
	if hasRoot(s.ReadRoots, canonical(t, ambient)) {
		t.Fatalf("ambient cache leaked into strict read roots: %v", s.ReadRoots)
	}
	if o := readFile(s, filepath.Join(ambient, "dep.go")); o.ToolStatus != StatusError {
		t.Fatalf("ambient cache read must stay denied, got %s", o.ToolStatus)
	}

	// A declared cache keeps its own pin — no blocked path contaminates it.
	perRun := filepath.Join(parent, "declared-mc")
	must(t, os.MkdirAll(perRun, 0o755))
	d, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, ModCacheRoot: perRun, Audit: NopAudit{}})
	must(t, err)
	if v, _ := envValue(d.ToolEnv, "GOMODCACHE"); v != canonical(t, perRun) {
		t.Fatalf("declared cache pin must win, got %q", v)
	}
}

// E3a: strict pins module-egress env for every toolchain subprocess and
// the applied env is recorded on the observation scope; the default
// profile's env is unchanged.
func TestStrictHardensToolchainEnv(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))

	def, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)
	for _, k := range []string{"GOPROXY", "GOSUMDB"} {
		if v, ok := envValue(def.ToolEnv, k); ok {
			t.Fatalf("default profile must not pin %s, got %q", k, v)
		}
	}
	if v, _ := envValue(def.ToolEnv, "GOFLAGS"); v != "" {
		t.Fatalf("default profile keeps GOFLAGS empty override, got %q", v)
	}

	strict, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	for k, want := range map[string]string{
		"GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "-mod=readonly",
		"GONOSUMDB": "", "GONOPROXY": "", "GOPRIVATE": "",
	} {
		if v, _ := envValue(strict.ToolEnv, k); v != want {
			t.Fatalf("strict ToolEnv %s=%q, want %q", k, v, want)
		}
	}
	// The session build context records the selection the hardened env
	// actually applies: workspace mode off, and the resolved module mode.
	if def.Build.GoWorkFile != domain.GoWorkOff || def.Build.GoFlags != "" {
		t.Fatalf("default session build selection = workspace %q flags %q",
			def.Build.GoWorkFile, def.Build.GoFlags)
	}
	if strict.Build.GoWorkFile != domain.GoWorkOff || strict.Build.GoFlags != "-mod=readonly" {
		t.Fatalf("strict session build selection = workspace %q flags %q",
			strict.Build.GoWorkFile, strict.Build.GoFlags)
	}

	// The hardened env, the resolved read roots and the inherited ambient
	// keys reach the audit trail on every observation's scope details.
	o := readFile(strict, "main.go")
	if o.ScopeDetails == nil {
		t.Fatal("scope details missing")
	}
	if o.ScopeDetails.Profile != "strict" {
		t.Fatalf("profile=%q", o.ScopeDetails.Profile)
	}
	if v, _ := envValue(o.ScopeDetails.ToolchainEnv, "GOPROXY"); v != "off" {
		t.Fatalf("audit scope must carry GOPROXY=off, got %q", v)
	}
	if !hasRoot(o.ScopeDetails.ReadRoots, canonical(t, root)) {
		t.Fatalf("audit scope must carry the resolved read roots: %v", o.ScopeDetails.ReadRoots)
	}
	if v, _ := envValue(o.ScopeDetails.ToolchainEnv, "GOSUMDB"); v != "off" {
		t.Fatalf("audit scope must carry GOSUMDB=off, got %q", v)
	}
	if len(o.ScopeDetails.InheritedEnvKeys) == 0 {
		t.Fatal("audit scope must name the ambient keys subprocesses inherit")
	}
	if !hasRoot(o.ScopeDetails.InheritedEnvKeys, "PATH") {
		t.Fatalf("inherited keys must include PATH (names only): %v", o.ScopeDetails.InheritedEnvKeys)
	}
}

func TestStrictVendorModeUsesVendoredTreeOffline(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "vendored"))
	must(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte(
		"module example.com/isolated\n\ngo 1.23\n\nrequire example.com/dep v1.0.0\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "main.go"), []byte(
		"package main\n\nimport _ \"example.com/dep\"\n\nfunc main() {}\n"), 0o644))
	must(t, os.MkdirAll(filepath.Join(root, "vendor", "example.com", "dep"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "vendor", "example.com", "dep", "dep.go"), []byte("package dep\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte(
		"# example.com/dep v1.0.0\n## explicit; go 1.23\nexample.com/dep\n"), 0o644))
	t.Setenv("GOPROXY", "https://proxy.invalid.test")
	t.Setenv("GOSUMDB", "sum.invalid.test")
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, AllowToolchain: true, Audit: NopAudit{}})
	must(t, err)
	if got, _ := envValue(s.ToolEnv, "GOFLAGS"); got != "-mod=vendor" {
		t.Fatalf("vendored strict GOFLAGS=%q, want -mod=vendor", got)
	}
	for _, entry := range s.ToolEnv {
		if entry == "GOFLAGS=-mod=readonly" {
			t.Fatal("vendored strict environment must not contain -mod=readonly")
		}
	}
	if got, _ := envValue(s.ToolEnv, "GOMODCACHE"); filepath.Base(got) != ".izyan-empty-modcache" {
		t.Fatalf("vendored strict GOMODCACHE=%q, want empty-cache pin", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o := s.invoke(ctx, "get_dependency_graph", nil, func(c context.Context) (*Observation, error) {
		return s.getDependencyGraph(c)
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("vendored graph must resolve offline: %s (%s)", o.ToolStatus, o.Error)
	}
	if strings.Contains(o.Error, "proxy.invalid.test") || strings.Contains(o.Error, "sum.invalid.test") {
		t.Fatalf("vendored resolution reached ambient module services: %s", o.Error)
	}
}

func TestStrictNonVendorModeKeepsReadonly(t *testing.T) {
	root := writeProductSnapshot(t, filepath.Join(t.TempDir(), "plain"))
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	got, _ := envValue(s.ToolEnv, "GOFLAGS")
	if got != "-mod=readonly" {
		t.Fatalf("non-vendored strict GOFLAGS=%q, want -mod=readonly", got)
	}
}

// E3b: with a bogus ambient proxy and a module absent from the local
// cache, a strict module lookup fails closed with GOPROXY=off — it never
// reaches the proxy.
func TestStrictModuleFetchCannotReachNetwork(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	must(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte(
		"module example.com/isolated\n\ngo 1.23\n\nrequire example.com/no-such-module v1.0.0\n"), 0o644))
	t.Setenv("GOPROXY", "https://proxy.invalid.test")
	t.Setenv("GOSUMDB", "sum.invalid.test")

	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, AllowToolchain: true,
		// Explicit generous bound so load can't stall the real subprocess
		// into the strict default timeout.
		ToolTimeout: 2 * time.Minute,
		Audit:       NopAudit{}})
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o := s.invoke(ctx, "get_dependency_graph", nil, func(c context.Context) (*Observation, error) {
		return s.getDependencyGraph(c)
	})
	if o.ToolStatus != StatusError {
		t.Fatalf("a missing module must fail closed under strict, got %s (%s)", o.ToolStatus, o.Fact)
	}
	if strings.Contains(o.Error, "proxy.invalid.test") || strings.Contains(o.Error, "sum.invalid.test") {
		t.Fatalf("module fetch reached the ambient proxy despite strict env: %s", o.Error)
	}
	if !strings.Contains(o.Error, "GOPROXY=off") && !strings.Contains(o.Error, "disabled") {
		t.Fatalf("error should show the fetch was disabled locally, not a network failure: %s", o.Error)
	}
}

// stubGVRunner lets the E4 "with permission executes" leg run offline.
type stubGVRunner struct{}

func (stubGVRunner) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n"), "./...", nil
}

// writeVulnDBEntry materializes a minimal flat-layout vulndb root: one
// <GO-ID>.json entry is enough for the readability probe to accept the
// pinned database.
func writeVulnDBEntry(t *testing.T, dir string) {
	t.Helper()
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "GO-TEST-0001.json"),
		[]byte(`{"id":"GO-TEST-0001","modified":"2026-01-01T00:00:00Z"}`), 0o644))
}

// E4: under strict, exec-backed toolchain tools need the explicit
// toolchain permission; without it they are UNSUPPORTED naming the
// missing knob. The default profile is unchanged.
func TestStrictToolchainPermissionGate(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	ctx := context.Background()

	calls := map[string]func(*Session) func(context.Context) (*Observation, error){
		"get_dependency_graph": func(s *Session) func(context.Context) (*Observation, error) {
			return s.getDependencyGraph
		},
		"get_module_version": func(s *Session) func(context.Context) (*Observation, error) {
			return func(c context.Context) (*Observation, error) {
				return s.getModuleVersion(c, getModuleVersionArgs{Module: "example.com/isolated"})
			}
		},
		"run_govulncheck": func(s *Session) func(context.Context) (*Observation, error) {
			return s.runGovulncheck
		},
	}
	cfg := func(strict, allow bool) SessionConfig {
		// run_govulncheck needs a real declared DB root and module cache
		// under strict; materialize both so the permission gate (not a
		// missing prerequisite) is what each leg exercises.
		db := filepath.Join(parent, "vulndb")
		mc := filepath.Join(parent, "modcache")
		writeVulnDBEntry(t, db)
		must(t, os.MkdirAll(mc, 0o755))
		return SessionConfig{
			SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: strict, AllowToolchain: allow,
			GovulnDBRoot: db, ModCacheRoot: mc, GVRunner: stubGVRunner{},
			VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
			Audit:      NopAudit{},
		}
	}

	strict, err := NewSession(cfg(true, false))
	must(t, err)
	for name, mk := range calls {
		o := strict.invoke(ctx, name, nil, mk(strict))
		if o.ToolStatus != StatusUnsupported {
			t.Fatalf("%s without toolchain permission: got %s, want UNSUPPORTED", name, o.ToolStatus)
		}
		if !strings.Contains(o.Error, "toolchain") || !strings.Contains(o.Error, "allow-toolchain") {
			t.Fatalf("%s denial must name the missing permission: %q", name, o.Error)
		}
	}

	// With the permission the same tools execute (offline: the fixture
	// module has no external deps, the runner is stubbed).
	permitted, err := NewSession(cfg(true, true))
	must(t, err)
	for name, mk := range calls {
		o := permitted.invoke(ctx, name, nil, mk(permitted))
		if o.ToolStatus != StatusOK {
			t.Fatalf("%s with toolchain permission: got %s (%s)", name, o.ToolStatus, o.Error)
		}
	}

	// The default profile is unaffected: no toolchain permission needed.
	def, err := NewSession(cfg(false, false))
	must(t, err)
	o := def.invoke(ctx, "get_dependency_graph", nil, func(c context.Context) (*Observation, error) {
		return def.getDependencyGraph(c)
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("default profile get_dependency_graph must run: %s (%s)", o.ToolStatus, o.Error)
	}
}
func TestStrictGovulnDBGateAndAuditEnv(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, AllowToolchain: true, GVRunner: stubGVRunner{}, Audit: NopAudit{}})
	must(t, err)
	o := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
	if o.ToolStatus != StatusUnsupported || !strings.Contains(o.Error, "--govulndb") {
		t.Fatalf("strict missing DB: %s %s", o.ToolStatus, o.Error)
	}
	def, err := NewSession(SessionConfig{SnapshotRoot: root, CVEID: "GO-TEST-0001", GVRunner: stubGVRunner{}, VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}}, Audit: NopAudit{}})
	must(t, err)
	if got := def.invoke(context.Background(), "run_govulncheck", nil, def.runGovulncheck); got.ToolStatus != StatusOK {
		t.Fatalf("default changed: %s %s", got.ToolStatus, got.Error)
	}
	db := filepath.Join(parent, "db")
	writeVulnDBEntry(t, db)
	s, err = NewSession(SessionConfig{SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true, AllowToolchain: true, GovulnDBRoot: db, ModCacheRoot: filepath.Join(parent, "mc"), GVRunner: stubGVRunner{}, VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}}, Audit: NopAudit{}})
	must(t, err)
	want := canonical(t, db)
	if got, ok := envValue(s.ToolEnv, "GOVULNDB"); !ok || got != want {
		t.Fatalf("GOVULNDB=%q want %q", got, want)
	}
	var rec AuditRecord
	s.Audit = AuditFunc(func(_ context.Context, r AuditRecord) { rec = r })
	got := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
	if got.ToolStatus != StatusOK {
		t.Fatalf("pinned govulndb: %s %s", got.ToolStatus, got.Error)
	}
	if v, ok := envValue(rec.Observation.ScopeDetails.ToolchainEnv, "GOVULNDB"); !ok || v != want {
		t.Fatalf("audit GOVULNDB=%q", v)
	}
}

// E3c: a strict session wires the pinned DB root into the default
// govulncheck runner's -db flag and confines the DB + module-cache
// roots; the fake binary sees the strict egress pins (GOPROXY=off) so a
// missing module can never leak to an ambient proxy mid-scan.
func TestStrictGovulnDBWiresRunnerAndConfinement(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	db := filepath.Join(parent, "db")
	mc := filepath.Join(parent, "modcache")
	writeVulnDBEntry(t, db)
	if err := os.MkdirAll(mc, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(SessionConfig{
		SnapshotRoot:   root,
		Strict:         true,
		AllowToolchain: true,
		GovulnDBRoot:   db,
		ModCacheRoot:   mc,
		Audit:          NopAudit{},
	})
	must(t, err)

	runner, ok := s.GVRunner.(goanalysis.ExecRunner)
	if !ok {
		t.Fatalf("default runner is %T, want ExecRunner", s.GVRunner)
	}
	if runner.DBRoot != canonical(t, db) {
		t.Fatalf("runner.DBRoot=%q want %q", runner.DBRoot, canonical(t, db))
	}
	for _, canon := range []string{canonical(t, db), canonical(t, mc)} {
		if !hasRoot(s.ReadRoots, canon) {
			t.Fatalf("read roots %v missing %s", s.ReadRoots, canon)
		}
	}

	// Drive the session's real runner against a fake binary: the strict
	// env (module egress off, pinned roots) and the -db flag must all
	// reach the subprocess.
	bin := filepath.Join(parent, "govulncheck")
	must(t, os.WriteFile(bin, []byte(`#!/bin/sh
printf '%s\n' "$@" > "$GOVULN_FAKE_ARGS"
env | sort > "$GOVULN_FAKE_ENV"
for a in "$@"; do
  if [ "$a" = "-json" ]; then
    printf '%s\n' '{"config":{"protocol_version":"v1.0.0"}}'
  fi
done
`), 0o755))
	argsPath := filepath.Join(parent, "args.txt")
	envPath := filepath.Join(parent, "env.txt")
	t.Setenv("GOVULN_FAKE_ARGS", argsPath)
	t.Setenv("GOVULN_FAKE_ENV", envPath)

	runner.Bin = bin
	if _, _, err := runner.RunGovulncheck(context.Background(), root, domain.ProductSnapshot{}); err != nil {
		t.Fatalf("fake run: %v", err)
	}
	argsB, _ := os.ReadFile(argsPath)
	if !strings.Contains(string(argsB), "-db\nfile://"+canonical(t, db)+"\n") &&
		!strings.Contains(string(argsB), "-db file://"+canonical(t, db)) {
		t.Fatalf("args missing pinned -db:\n%s", argsB)
	}
	envB, _ := os.ReadFile(envPath)
	// Both exported pins are canonical: GOVULNDB and GOMODCACHE name the
	// same identities as the confined read roots.
	for _, want := range []string{
		"GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly",
		"GOVULNDB=" + canonical(t, db), "GOMODCACHE=" + canonical(t, mc),
	} {
		if !strings.Contains(string(envB), want) {
			t.Fatalf("subprocess env missing %q\n%s", want, envB)
		}
	}

	// The observation records the pinned root even before any scan runs.
	s.CVEID = "GO-TEST-0001"
	s.VulnSource = vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}}
	o := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
	if o.ToolStatus != StatusOK {
		t.Fatalf("pinned run: %s %s", o.ToolStatus, o.Error)
	}
	// Provenance: the recorded root is the canonical path the runner
	// scanned (equals ExecRunner.DBRoot), not the caller's spelling.
	if o.ScopeDetails == nil || o.ScopeDetails.Extra["govulndb_root"] != canonical(t, db) {
		t.Fatalf("scope extra govulndb_root=%v, want %q", o.ScopeDetails, canonical(t, db))
	}
	if s.GovulnDBRoot != canonical(t, db) {
		t.Fatalf("session GovulnDBRoot=%q, want canonical %q", s.GovulnDBRoot, canonical(t, db))
	}
	if s.ModCacheRoot == "" {
		t.Fatal("session ModCacheRoot must carry the declared cache")
	}
}

// E6a: strict govulncheck without a declared module cache is
// UNSUPPORTED — the subprocess would otherwise read the ambient cache
// outside every declared read root. Scrubbing GOMODCACHE is not a fix:
// the go tool falls back to the GOPATH default cache either way, so the
// only honest state is refusal.
func TestStrictGovulnCheckRequiresDeclaredModCache(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	db := filepath.Join(parent, "db")
	writeVulnDBEntry(t, db)

	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true, AllowToolchain: true,
		GovulnDBRoot: db, GVRunner: stubGVRunner{},
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      NopAudit{},
	})
	must(t, err)
	o := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
	if o.ToolStatus != StatusUnsupported || !strings.Contains(o.Error, "--modcache") {
		t.Fatalf("strict pinned DB but no modcache: %s %s", o.ToolStatus, o.Error)
	}

	// The same gap under the default profile stays runnable — the pin
	// contract is a strict-profile requirement.
	def, err := NewSession(SessionConfig{
		SnapshotRoot: root, CVEID: "GO-TEST-0001",
		GovulnDBRoot: db, GVRunner: stubGVRunner{},
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      NopAudit{},
	})
	must(t, err)
	if got := def.invoke(context.Background(), "run_govulncheck", nil, def.runGovulncheck); got.ToolStatus != StatusOK {
		t.Fatalf("default profile with pinned DB must run: %s %s", got.ToolStatus, got.Error)
	}
}

// E6b: provenance canonicalization — a symlinked --govulndb arg must be
// stored and reported as the canonical path the runner actually scans.
func TestGovulnDBRootProvenanceIsCanonical(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	real := filepath.Join(parent, "real-db")
	writeVulnDBEntry(t, real)
	link := filepath.Join(parent, "link-db")
	must(t, os.Symlink(real, link))
	mc := filepath.Join(parent, "mc")
	must(t, os.MkdirAll(mc, 0o755))

	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true, AllowToolchain: true,
		GovulnDBRoot: link, ModCacheRoot: mc, GVRunner: stubGVRunner{},
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      NopAudit{},
	})
	must(t, err)
	want := canonical(t, real)
	if s.GovulnDBRoot != want {
		t.Fatalf("session GovulnDBRoot=%q want canonical %q", s.GovulnDBRoot, want)
	}
	// The default runner (no override) must pin -db at the canonical
	// root — a second session proves it without invoking a real binary.
	s2, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, AllowToolchain: true,
		GovulnDBRoot: link, ModCacheRoot: mc, Audit: NopAudit{},
	})
	must(t, err)
	runner, ok := s2.GVRunner.(goanalysis.ExecRunner)
	if !ok || runner.DBRoot != want {
		t.Fatalf("default runner DBRoot=%v want %q", s2.GVRunner, want)
	}
	o := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
	if o.ToolStatus != StatusOK {
		t.Fatalf("pinned run: %s %s", o.ToolStatus, o.Error)
	}
	if o.ScopeDetails.Extra["govulndb_root"] != want {
		t.Fatalf("provenance govulndb_root=%q want %q (scanned root)", o.ScopeDetails.Extra["govulndb_root"], want)
	}
	if !hasRoot(s.ReadRoots, want) {
		t.Fatalf("canonical db root missing from read roots: %v", s.ReadRoots)
	}
}

// E6c: a configured-but-missing DB root is an absent capability —
// UNSUPPORTED, not an execution ERROR. Applies in both profiles: a pin
// that names nothing cannot be honored at all.
func TestGovulnDBMissingRootIsUnsupported(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	missing := filepath.Join(parent, "no-such-db")
	mc := filepath.Join(parent, "mc")
	must(t, os.MkdirAll(mc, 0o755))
	vulnSrc := vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}}

	for _, cfg := range []SessionConfig{
		{SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true, AllowToolchain: true,
			GovulnDBRoot: missing, ModCacheRoot: mc, GVRunner: stubGVRunner{}, VulnSource: vulnSrc, Audit: NopAudit{}},
		{SnapshotRoot: root, CVEID: "GO-TEST-0001",
			GovulnDBRoot: missing, GVRunner: stubGVRunner{}, VulnSource: vulnSrc, Audit: NopAudit{}},
	} {
		s, err := NewSession(cfg)
		must(t, err)
		o := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
		if o.ToolStatus != StatusUnsupported || !strings.Contains(o.Error, "govulndb root") {
			t.Fatalf("missing DB root (strict=%v): %s %s", cfg.Strict, o.ToolStatus, o.Error)
		}
	}
}

// E6d: an existing-but-unreadable DB root (unlistable directory) and an
// empty-but-readable one are both UNSUPPORTED: the pinned capability is
// absent, a scan-level ERROR would misreport it as an execution fault.
func TestGovulnDBUnreadableOrEmptyIsUnsupported(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	mc := filepath.Join(parent, "mc")
	must(t, os.MkdirAll(mc, 0o755))
	vulnSrc := vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}}

	// Unreadable: list operation denied.
	unreadable := filepath.Join(parent, "unreadable-db")
	writeVulnDBEntry(t, unreadable)
	must(t, os.Chmod(unreadable, 0o000))
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o755) })

	// Readable but contentless: no v1 index and no <GO-ID>.json entries.
	empty := filepath.Join(parent, "empty-db")
	must(t, os.MkdirAll(empty, 0o755))

	for _, dbRoot := range []string{unreadable, empty} {
		s, err := NewSession(SessionConfig{
			SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true, AllowToolchain: true,
			GovulnDBRoot: dbRoot, ModCacheRoot: mc, GVRunner: stubGVRunner{},
			VulnSource: vulnSrc, Audit: NopAudit{},
		})
		must(t, err)
		o := s.invoke(context.Background(), "run_govulncheck", nil, s.runGovulncheck)
		if o.ToolStatus != StatusUnsupported || !strings.Contains(o.Error, "govulndb root") {
			t.Fatalf("%s: %s %s", dbRoot, o.ToolStatus, o.Error)
		}
	}
}

// E6e: a symlinked --modcache arg resolves to the canonical identity for
// session state, the exported GOMODCACHE and the confined roots — and
// reads through the caller's lexical spelling keep working because the
// module-cache gate compares canonical forms too.
func TestStrictModCacheRootIsCanonical(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	real := filepath.Join(parent, "real-mc")
	must(t, os.MkdirAll(real, 0o755))
	must(t, os.WriteFile(filepath.Join(real, "dep.go"), []byte("package dep\n"), 0o644))
	link := filepath.Join(parent, "link-mc")
	must(t, os.Symlink(real, link))
	db := filepath.Join(parent, "db")
	writeVulnDBEntry(t, db)

	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true, AllowToolchain: true,
		GovulnDBRoot: db, ModCacheRoot: link, GVRunner: stubGVRunner{},
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      NopAudit{},
	})
	must(t, err)
	want := canonical(t, real)
	if s.ModCacheRoot != want {
		t.Fatalf("session ModCacheRoot=%q want %q", s.ModCacheRoot, want)
	}
	if v, ok := envValue(s.ToolEnv, "GOMODCACHE"); !ok || v != want {
		t.Fatalf("GOMODCACHE=%q want %q", v, want)
	}
	if !hasRoot(s.ReadRoots, want) {
		t.Fatalf("canonical cache root missing from read roots: %v", s.ReadRoots)
	}
	// Reads are allowed under BOTH spellings of the declared cache.
	for _, spelling := range []string{
		filepath.Join(link, "dep.go"),
		filepath.Join(real, "dep.go"),
	} {
		if o := readFile(s, spelling); o.ToolStatus != StatusOK {
			t.Fatalf("read through %q denied: %s", spelling, o.Error)
		}
	}
}

// E5: a handler that outlives the per-tool timeout produces TIMEOUT +
// limitation + audit record — never an empty result; a normal handler
// under the same bound is unaffected. The bound is strict-only by
// default: a non-strict session with no explicit timeout keeps today's
// unbounded behaviour.
func TestToolTimeoutHonestTimeout(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))

	// Default profile, no explicit timeout: unbounded (byte-equivalent to
	// the pre-timeout behaviour — a handler past 15m is not TIMEOUT).
	def, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)
	if def.ToolTimeout != 0 {
		t.Fatalf("default profile must keep the unbounded default, got %s", def.ToolTimeout)
	}
	// Strict profile with no explicit timeout: bound defaults to 15m.
	strict, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	if strict.ToolTimeout != DefaultToolTimeout {
		t.Fatalf("strict profile must default to %s, got %s", DefaultToolTimeout, strict.ToolTimeout)
	}

	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, ToolTimeout: 80 * time.Millisecond, Audit: NopAudit{}})
	must(t, err)

	var recs []AuditRecord
	s.Audit = AuditFunc(func(_ context.Context, r AuditRecord) { recs = append(recs, r) })

	// A handler that ignores ctx entirely — invoke itself must still
	// return TIMEOUT at the wall-clock bound, never hang. It blocks on a
	// channel released only after the invoke returns, so the timeout
	// outcome cannot depend on the machine's scheduling: the handler can
	// never produce a result before the bound, even if its goroutine is
	// descheduled for the whole window.
	release := make(chan struct{})
	defer close(release) // let the abandoned handler goroutine exit
	hang := func(c context.Context) (*Observation, error) {
		<-release
		return s.ok("hang_tool", "done", "scope", CompletenessPartial, nil, nil, nil), nil
	}
	o := s.invoke(context.Background(), "hang_tool", nil, hang)
	if o.ToolStatus != StatusTimeout {
		t.Fatalf("unresponsive handler: got %s, want TIMEOUT", o.ToolStatus)
	}
	if o.Completeness != CompletenessUnknown {
		t.Fatalf("timeout completeness: got %s, want UNKNOWN", o.Completeness)
	}
	if len(o.Limitations) == 0 {
		t.Fatal("timeout must carry an honest limitation")
	}
	if len(recs) != 1 || recs[0].Observation == nil || recs[0].Observation.ToolStatus != StatusTimeout {
		t.Fatalf("timeout must land in the audit trail: %+v", recs)
	}

	// Success case: a separate session with a bound orders of magnitude
	// larger than the handler's work — an instantly-returning stub under
	// a 5s bound cannot flake on scheduling, unlike racing a real file
	// read against a sub-second bound.
	okSess, err := NewSession(SessionConfig{
		SnapshotRoot: root, ToolTimeout: 5 * time.Second, Audit: NopAudit{}})
	must(t, err)
	o = okSess.invoke(context.Background(), "read_source", nil, func(c context.Context) (*Observation, error) {
		return okSess.ok("read_source", "done", "scope", CompletenessPartial, nil, nil, nil), nil
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("normal handler under a generous bound: got %s (%s)", o.ToolStatus, o.Error)
	}
}

// F4: toolchain subprocesses the analysis contract needs (package
// loader, the go version probe) are recorded as named exceptions in the
// observation scope when the strict toolchain permission is absent.
func TestStrictToolchainExceptionsRecorded(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true,
		ToolTimeout: 2 * time.Minute, Audit: NopAudit{}})
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := s.invoke(ctx, "get_product_snapshot", nil, func(c context.Context) (*Observation, error) {
		return s.getProductSnapshot(c)
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("get_product_snapshot: %s", o.Error)
	}
	if o.ScopeDetails.Extra["toolchain_exception"] == "" {
		t.Fatalf("go version probe must be a named exception under strict: %+v", o.ScopeDetails.Extra)
	}

	o = s.invoke(ctx, "find_symbol", nil, func(c context.Context) (*Observation, error) {
		return s.findSymbol(c, symbolRefArgs{Package: "example.com/isolated", Symbol: "main"})
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("find_symbol: %s", o.Error)
	}
	if !strings.Contains(o.ScopeDetails.Extra["toolchain_exception"], "go list") {
		t.Fatalf("loader subprocess must be a named exception under strict: %+v", o.ScopeDetails.Extra)
	}
}

// E2 variant: the ambient cache derived from GOPATH (not GOMODCACHE) is
// also excluded from the strict read roots.
func TestStrictGopathCacheIsNotAReadRoot(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	gopath := filepath.Join(parent, "gopath")
	cache := filepath.Join(gopath, "pkg", "mod")
	must(t, os.MkdirAll(cache, 0o755))
	must(t, os.WriteFile(filepath.Join(cache, "dep.go"),
		[]byte("package dep\n"), 0o644))
	t.Setenv("GOPATH", gopath)
	// Clear an ambient GOMODCACHE so the cache is derived from GOPATH —
	// modCacheDir skips empty values and falls through to GOPATH.
	t.Setenv("GOMODCACHE", "")

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	if hasRoot(s.ReadRoots, canonical(t, cache)) {
		t.Fatalf("GOPATH-derived cache leaked into strict read roots: %v", s.ReadRoots)
	}
	if o := readFile(s, filepath.Join(cache, "dep.go")); o.ToolStatus != StatusError {
		t.Fatalf("GOPATH-derived cache read must be denied under strict, got %s", o.ToolStatus)
	}
}
