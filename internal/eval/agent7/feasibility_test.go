package agent7_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/agent7"
)

// writeFile creates one fixture file inside t.TempDir-style dirs.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// advisoryJSON renders a minimal OSV document for the collector. Every
// Go-ecosystem affected entry becomes one affected-module record in the
// analyzer's conversion (vulnerability.FileSource).
func advisoryJSON(t *testing.T, entries string) string {
	t.Helper()
	return fmt.Sprintf(`{"id":"GO-2099-0001","aliases":["CVE-2099-0001"],
"modified":"2026-01-02T03:04:05Z",
"affected":[%s]}`, entries)
}

func affectedEntry(module, imports, events string) string {
	return fmt.Sprintf(`{"package":{"name":%q,"ecosystem":"Go"},
"ranges":[{"type":"SEMVER","events":[%s]}],
"ecosystem_specific":{"imports":[%s]}}`, module, events, imports)
}

func importPath(path string, symbols ...string) string {
	ss, _ := json.Marshal(symbols)
	return fmt.Sprintf(`{"path":%q,"symbols":%s}`, path, ss)
}

func event(k, v string) string { return fmt.Sprintf(`{%q:%q}`, k, v) }

// envelopeJSON renders the B0 per-case envelope fields the collector reads.
func envelopeJSON(t *testing.T, kv map[string]any) string {
	t.Helper()
	base := map[string]any{
		"task_id":                "examplecom-prod-deadbeef-CVE-2099-0001",
		"terminal_state":         "COMPLETED",
		"verdict":                "NOT_AFFECTED",
		"reason":                 "resolved version is outside the affected range",
		"compatibility_category": "code_not_present",
		"scoring_outcome":        "correct_safe",
		"content_hash":           strings.Repeat("a", 64),
		"advisory_source":        "osv:vulns/GO-2099-0001",
		"advisory_sha256":        "",
		"advisory_modified":      "2026-01-02T03:04:05Z",
		"release_go_version":     "go1.21.0",
		"go_version_source":      "toolchain",
		"minimum_go_version":     "1.21",
		"vendor_mode":            false,
		"cgo_enabled":            false,
		"goos":                   "darwin",
		"goarch":                 "arm64",
	}
	for k, v := range kv {
		base[k] = v
	}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(b)
}

// sha256Hex computes the lowercase hex sha256 of a file.
func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read for sha256: %v", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// writeEnvelopeFor binds an envelope to the advisory file actually on
// disk — advisory_sha256 must match what CollectCase hashes or the
// integrity gate fails the record closed.
func writeEnvelopeFor(t *testing.T, envPath, advPath string, kv map[string]any) {
	t.Helper()
	if kv == nil {
		kv = map[string]any{}
	}
	if advPath != "" {
		kv["advisory_sha256"] = sha256Hex(t, advPath)
	}
	writeFile(t, envPath, envelopeJSON(t, kv))
}

func baseTask() agent7.TaskRecord {
	return agent7.TaskRecord{
		TaskID:              "examplecom-prod-deadbeef-CVE-2099-0001",
		RepoURL:             "https://github.com/examplecom/prod",
		CommitSHA:           strings.Repeat("d", 40),
		CVEID:               "CVE-2099-0001",
		GroundTruth:         "not_exploitable",
		GroundTruthCategory: "code_not_present",
	}
}

// TestCollectArtifactFixedCandidate covers the ARTIFACT_FIXED fact
// scenario: the vulnerable module resolves to a version pinned above the
// advisory's fix version → the fixed-fact pattern is deterministically
// present.
func TestCollectArtifactFixedCandidate(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/lib v1.3.0\n")
	writeFile(t, filepath.Join(snap, "go.sum"),
		"dep.example/lib v1.3.0 h1:x=\ndep.example/lib v1.3.0/go.mod h1:y=\n")
	writeFile(t, filepath.Join(snap, "main.go"), "package main\n\nfunc main() {}\n")

	adv := filepath.Join(dir, "advisory", "GO-2099-0001.json")
	writeFile(t, adv, advisoryJSON(t, affectedEntry(
		"dep.example/lib",
		importPath("dep.example/lib/sub", "Do"),
		event("introduced", "0")+","+event("fixed", "1.2.3"))))

	envPath := filepath.Join(dir, "prediction.json")
	writeEnvelopeFor(t, envPath, adv, nil)

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: envPath,
		AdvisoryPath:   adv,
	})

	if got := rec.VulnerableModule; got != "dep.example/lib" {
		t.Errorf("vulnerable_module = %q", got)
	}
	if got := rec.VulnerablePackage; got != "dep.example/lib/sub" {
		t.Errorf("vulnerable_package = %q", got)
	}
	if got := rec.ResolvedVersion; got != "v1.3.0" {
		t.Errorf("resolved_version = %q", got)
	}
	if got := rec.FixVersion; got != "1.2.3" {
		t.Errorf("fix_version = %q", got)
	}
	if got := rec.ComponentInModuleGraph; got != agent7.FactYes {
		t.Errorf("component_in_module_graph = %q", got)
	}
	if got := rec.ComponentVendored; got != agent7.FactNo {
		t.Errorf("component_vendored = %q", got)
	}
	if got := rec.ProofArtifactFixed; got != agent7.FactYes {
		t.Errorf("proof_artifact_fixed = %q, want yes", got)
	}
	if got := rec.ProofComponentAbsent; got != agent7.FactNo {
		t.Errorf("proof_component_absent = %q, want no", got)
	}
	if got := rec.ProofBuildExcluded; got != agent7.FactUnknown {
		t.Errorf("proof_build_excluded = %q, want unknown (external package not in snapshot)", got)
	}
	if got := rec.IzyanVerdict; got != "NOT_AFFECTED" {
		t.Errorf("izyan_verdict = %q", got)
	}
	if got := rec.MultiModule; got != agent7.FactNo {
		t.Errorf("multi_module = %q", got)
	}
	if got := rec.GoWork; got != agent7.FactNo {
		t.Errorf("go_work = %q", got)
	}
	if got := rec.GeneratedCodePresent; got != agent7.FactNo {
		t.Errorf("generated_code_present = %q", got)
	}
	if got := rec.TargetKind; got != "source_tree" {
		t.Errorf("target_kind = %q", got)
	}
	if rec.DeliveredArtifact != agent7.FactNo || rec.BuildAttestation != agent7.FactNo {
		t.Errorf("delivered artifact facts = %q/%q", rec.DeliveredArtifact, rec.BuildAttestation)
	}
}

// TestCollectComponentAbsentCandidate covers COMPONENT_ABSENT: the
// advisory module is absent from every module record → the absent-fact
// pattern is deterministically present while the version candidate is
// inapplicable (scope).
func TestCollectComponentAbsentCandidate(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/other v0.2.0\n")
	writeFile(t, filepath.Join(snap, "main.go"), "package main\n\nfunc main() {}\n")

	adv := filepath.Join(dir, "advisory", "GO-2099-0001.json")
	writeFile(t, adv, advisoryJSON(t, affectedEntry(
		"dep.example/missing",
		importPath("dep.example/missing/vuln"),
		event("introduced", "0")+","+event("fixed", "1.0.0"))))

	envPath := filepath.Join(dir, "prediction.json")
	writeEnvelopeFor(t, envPath, adv, nil)

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: envPath,
		AdvisoryPath:   adv,
	})

	if got := rec.ComponentInModuleGraph; got != agent7.FactNo {
		t.Errorf("component_in_module_graph = %q, want no", got)
	}
	if got := rec.ProofComponentAbsent; got != agent7.FactYes {
		t.Errorf("proof_component_absent = %q, want yes", got)
	}
	if got := rec.ProofArtifactFixed; got != agent7.FactUnknown {
		t.Errorf("proof_artifact_fixed = %q, want unknown (inapplicable to absent component)", got)
	}
	if got := rec.ResolvedVersion; got != agent7.FactUnknown {
		t.Errorf("resolved_version = %q, want unknown", got)
	}
}

// TestCollectVendoredMultiModuleFacts covers the generated-code +
// vendored + multi-module scenario: facts must come from the file-level
// snapshot records (nested go.mod, vendor/modules.txt, generated marker,
// build constraints), never from `go list`.
func TestCollectVendoredMultiModuleFacts(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")

	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/lib v0.9.0\n")
	// A nested module makes the snapshot multi-module.
	writeFile(t, filepath.Join(snap, "sub", "go.mod"),
		"module example.com/prod/sub\n\ngo 1.21\n")
	// Vendored build: modules.txt is the authoritative record.
	writeFile(t, filepath.Join(snap, "vendor", "modules.txt"),
		"# dep.example/lib v0.9.0\n## explicit; go 1.20\ndep.example/lib/sub\ndep.example/lib/winonly\n")
	// One included vendored package and one fully windows-gated package.
	writeFile(t, filepath.Join(snap, "vendor", "dep.example", "lib", "sub", "sub.go"),
		"package sub\n\nfunc Do() {}\n")
	writeFile(t, filepath.Join(snap, "vendor", "dep.example", "lib", "winonly", "w.go"),
		"//go:build windows\n\npackage winonly\n\nfunc W() {}\n")
	// Generated first-party code (vendor is skipped by the marker scan).
	writeFile(t, filepath.Join(snap, "gen", "gen.go"),
		"// Code generated by tool. DO NOT EDIT.\n\npackage gen\n")

	adv := filepath.Join(dir, "advisory", "GO-2099-0001.json")
	writeFile(t, adv, advisoryJSON(t, affectedEntry(
		"dep.example/lib",
		importPath("dep.example/lib/winonly")+","+importPath("dep.example/lib/sub"),
		event("introduced", "0")+","+event("fixed", "1.0.0"))))

	envPath := filepath.Join(dir, "prediction.json")
	writeFile(t, envPath, envelopeJSON(t, map[string]any{
		"vendor_mode": true, "goos": "darwin", "goarch": "arm64",
	}))

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: envPath,
		AdvisoryPath:   adv,
	})

	if got := rec.ComponentVendored; got != agent7.FactYes {
		t.Errorf("component_vendored = %q, want yes", got)
	}
	if got := rec.MultiModule; got != agent7.FactYes {
		t.Errorf("multi_module = %q, want yes", got)
	}
	if got := rec.GeneratedCodePresent; got != agent7.FactYes {
		t.Errorf("generated_code_present = %q, want yes", got)
	}
	if got := rec.VendorMode; got != agent7.FactYes {
		t.Errorf("vendor_mode = %q, want yes", got)
	}
	if got := rec.BuildTagGated; got != agent7.FactYes {
		t.Errorf("build_tag_gated = %q, want yes (windows-gated vendored file)", got)
	}
	// winonly is fully excluded under darwin, sub is not → not every
	// affected package is excluded.
	if got := rec.ProofBuildExcluded; got != agent7.FactNo {
		t.Errorf("proof_build_excluded = %q, want no", got)
	}
	if got := rec.ResolvedVersion; got != "v0.9.0" {
		t.Errorf("resolved_version = %q", got)
	}
}

// TestCollectFailsClosed covers malformed/missing inputs: the collector
// must degrade every dependent fact to "unknown" and record blocker
// kinds — never panic, never invent values.
func TestCollectFailsClosed(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n")

	// Malformed prediction.json and a non-JSON advisory body.
	badEnv := filepath.Join(dir, "prediction.json")
	writeFile(t, badEnv, `{"task_id":`)
	badAdv := filepath.Join(dir, "advisory", "broken.json")
	writeFile(t, badAdv, "this is not json")

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: badEnv,
		AdvisoryPath:   badAdv,
	})
	assertUnknown := func(name, got string) {
		t.Helper()
		if got != agent7.FactUnknown {
			t.Errorf("%s = %q, want unknown (fail-closed)", name, got)
		}
	}
	assertUnknown("izyan_verdict", rec.IzyanVerdict)
	assertUnknown("vulnerable_module", rec.VulnerableModule)
	assertUnknown("resolved_version", rec.ResolvedVersion)
	assertUnknown("release_go_version", rec.ReleaseGoVersion)
	assertUnknown("goos", rec.GOOS)
	assertUnknown("component_in_module_graph", rec.ComponentInModuleGraph)
	assertUnknown("proof_artifact_fixed", rec.ProofArtifactFixed)
	assertUnknown("proof_component_absent", rec.ProofComponentAbsent)
	assertUnknown("proof_build_excluded", rec.ProofBuildExcluded)
	assertUnknown("advisory_manifest_complete", rec.AdvisoryManifestComplete)
	assertUnknown("binary_inventory_complete", rec.BinaryInventoryComplete)
	if rec.IzyanError == "" || rec.IzyanError == "none" {
		t.Errorf("izyan_error = %q, want a recorded failure", rec.IzyanError)
	}
	if rec.BlockerKind == "" {
		t.Errorf("blocker_kind empty; want a recorded blocker")
	}
	if len(rec.CollectionNotes) == 0 {
		t.Errorf("collection_notes empty; malformed inputs must be explained")
	}

	// Missing snapshot + missing prediction: still a record, all unknown.
	rec2 := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:        baseTask(),
		SnapshotDir: filepath.Join(dir, "does-not-exist"),
	})
	assertUnknown("izyan_verdict", rec2.IzyanVerdict)
	assertUnknown("multi_module", rec2.MultiModule)
	assertUnknown("generated_code_present", rec2.GeneratedCodePresent)
	assertUnknown("vulnerable_module", rec2.VulnerableModule)
	if rec2.TaskID != baseTask().TaskID {
		t.Errorf("task_id = %q", rec2.TaskID)
	}
}

// TestFeasibilityHelpers pins the deterministic helper semantics that the
// fact columns rely on (snapshot identity, release tags, range matching).
func TestFeasibilityHelpers(t *testing.T) {
	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{})
	if rec.GTClass != agent7.FactUnknown || rec.VulnerableModule != agent7.FactUnknown {
		t.Errorf("empty input must still emit a fail-closed record: %+v", rec)
	}
	if rec.SnapshotDir != agent7.FactUnknown {
		t.Errorf("snapshot_dir = %q, want unknown without repo_url/commit", rec.SnapshotDir)
	}
}

// TestCollectCaseTableDriven drives the four required scenarios through a
// single table: ARTIFACT_FIXED pinned version, COMPONENT_ABSENT outside
// the module graph, vendored/multi-module/generated facts, and malformed
// input failing closed. Each row sets up its own fixture and asserts a
// field expectation table — deterministic, std-lib fixtures only.
func TestCollectCaseTableDriven(t *testing.T) {
	type check struct {
		field string
		want  string
	}
	type scenario struct {
		name   string
		inputs func(t *testing.T, dir string) agent7.FeasibilityInputs
		checks []check
	}

	writeSnap := func(t *testing.T, dir, gomod string, extra map[string]string) string {
		t.Helper()
		snap := filepath.Join(dir, "snap")
		writeFile(t, filepath.Join(snap, "go.mod"), gomod)
		for rel, body := range extra {
			writeFile(t, filepath.Join(snap, filepath.FromSlash(rel)), body)
		}
		return snap
	}
	writeAdv := func(t *testing.T, dir, module string) string {
		t.Helper()
		p := filepath.Join(dir, "advisory", "GO-2099-0001.json")
		writeFile(t, p, advisoryJSON(t, affectedEntry(
			module, importPath(module+"/vuln"),
			event("introduced", "0")+","+event("fixed", "1.0.0"))))
		return p
	}
	writeEnv := func(t *testing.T, dir string) string {
		t.Helper()
		p := filepath.Join(dir, "prediction.json")
		writeEnvelopeFor(t, p, "", nil)
		return p
	}
	writeEnvAdv := func(t *testing.T, dir, advPath string) string {
		t.Helper()
		p := filepath.Join(dir, "prediction.json")
		writeEnvelopeFor(t, p, advPath, nil)
		return p
	}

	scenarios := []scenario{
		{
			name: "artifact_fixed pinned version",
			inputs: func(t *testing.T, dir string) agent7.FeasibilityInputs {
				snap := writeSnap(t, dir,
					"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/lib v1.5.0\n",
					map[string]string{})
				adv := writeAdv(t, dir, "dep.example/lib")
				return agent7.FeasibilityInputs{
					Task:           baseTask(),
					SnapshotDir:    snap,
					PredictionPath: writeEnvAdv(t, dir, adv),
					AdvisoryPath:   adv,
				}
			},
			checks: []check{
				{"proof_artifact_fixed", "yes"},
				{"proof_component_absent", "no"},
				{"resolved_version", "v1.5.0"},
				{"fix_version", "1.0.0"},
				{"component_in_module_graph", "yes"},
			},
		},
		{
			name: "component_absent outside module graph",
			inputs: func(t *testing.T, dir string) agent7.FeasibilityInputs {
				return agent7.FeasibilityInputs{
					Task: baseTask(),
					SnapshotDir: writeSnap(t, dir,
						"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/other v1.0.0\n",
						map[string]string{}),
					PredictionPath: writeEnv(t, dir),
					AdvisoryPath:   writeAdv(t, dir, "dep.example/missing"),
				}
			},
			checks: []check{
				{"proof_component_absent", "yes"},
				{"proof_artifact_fixed", "unknown"},
				{"component_in_module_graph", "no"},
				{"resolved_version", "unknown"},
			},
		},
		{
			name: "generated vendored multi-module",
			inputs: func(t *testing.T, dir string) agent7.FeasibilityInputs {
				snap := writeSnap(t, dir,
					"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/lib v0.5.0\n",
					map[string]string{
						"sub/go.mod":                       "module example.com/prod/sub\n\ngo 1.21\n",
						"vendor/modules.txt":               "# dep.example/lib v0.5.0\n## explicit; go 1.20\ndep.example/lib/vuln\n",
						"vendor/dep.example/lib/vuln/v.go": "package vuln\n\nfunc V() {}\n",
						"gen/gen.go":                       "// Code generated by tool. DO NOT EDIT.\n\npackage gen\n",
					})
				env := filepath.Join(dir, "prediction.json")
				writeFile(t, env, envelopeJSON(t, map[string]any{"vendor_mode": true}))
				return agent7.FeasibilityInputs{
					Task:           baseTask(),
					SnapshotDir:    snap,
					PredictionPath: env,
					AdvisoryPath:   writeAdv(t, dir, "dep.example/lib"),
				}
			},
			checks: []check{
				{"component_vendored", "yes"},
				{"multi_module", "yes"},
				{"generated_code_present", "yes"},
				{"vendor_mode", "yes"},
				{"proof_artifact_fixed", "no"},
			},
		},
		{
			name: "malformed inputs fail closed",
			inputs: func(t *testing.T, dir string) agent7.FeasibilityInputs {
				badEnv := filepath.Join(dir, "prediction.json")
				writeFile(t, badEnv, "{not json")
				badAdv := filepath.Join(dir, "advisory", "x.json")
				writeFile(t, badAdv, "not json either")
				return agent7.FeasibilityInputs{
					Task:           baseTask(),
					SnapshotDir:    filepath.Join(dir, "absent-snapshot"),
					PredictionPath: badEnv,
					AdvisoryPath:   badAdv,
				}
			},
			checks: []check{
				{"izyan_verdict", "unknown"},
				{"vulnerable_module", "unknown"},
				{"resolved_version", "unknown"},
				{"proof_artifact_fixed", "unknown"},
				{"proof_component_absent", "unknown"},
				{"proof_build_excluded", "unknown"},
				{"component_in_module_graph", "unknown"},
				{"generated_code_present", "unknown"},
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			rec := agent7.CollectCase(context.Background(), sc.inputs(t, t.TempDir()))
			got := map[string]string{
				"izyan_verdict":             rec.IzyanVerdict,
				"vulnerable_module":         rec.VulnerableModule,
				"resolved_version":          rec.ResolvedVersion,
				"fix_version":               rec.FixVersion,
				"component_in_module_graph": rec.ComponentInModuleGraph,
				"component_vendored":        rec.ComponentVendored,
				"multi_module":              rec.MultiModule,
				"generated_code_present":    rec.GeneratedCodePresent,
				"vendor_mode":               rec.VendorMode,
				"proof_artifact_fixed":      rec.ProofArtifactFixed,
				"proof_component_absent":    rec.ProofComponentAbsent,
				"proof_build_excluded":      rec.ProofBuildExcluded,
			}
			for _, c := range sc.checks {
				if got[c.field] != c.want {
					t.Errorf("%s = %q, want %q", c.field, got[c.field], c.want)
				}
			}
		})
	}
}

// TestBlockerKindIncompleteManifestScope pins the control-case roll-up:
// an advisory manifest externally verified as incomplete turns the
// blocker of any still-live or undecidable candidate row into "scope" —
// data cannot close an applicability gap (the k8s-44487 false-safe
// pattern). A fully refuted row keeps "none".
func TestBlockerKindIncompleteManifestScope(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/lib v1.5.0\n")
	writeFile(t, filepath.Join(snap, "main.go"), "package main\n\nfunc main() {}\n")
	adv := filepath.Join(dir, "advisory", "GO-2099-0001.json")
	writeFile(t, adv, advisoryJSON(t, affectedEntry(
		"dep.example/lib", importPath("dep.example/lib/vuln"),
		event("introduced", "0")+","+event("fixed", "1.0.0"))))
	env := filepath.Join(dir, "prediction.json")
	writeFile(t, env, envelopeJSON(t, nil))

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:                     baseTask(),
		SnapshotDir:              snap,
		PredictionPath:           env,
		AdvisoryPath:             adv,
		AdvisoryManifestComplete: "no",
	})
	// artifact_fixed=yes (resolved v1.5.0 outside [0,1.0.0)); the manifest
	// is proven incomplete → the certificate blocker is scope.
	if rec.ProofArtifactFixed != agent7.FactYes {
		t.Fatalf("proof_artifact_fixed = %q, want yes", rec.ProofArtifactFixed)
	}
	if rec.BlockerKind != agent7.BlockerScope {
		t.Errorf("blocker_kind = %q, want scope (manifest proven incomplete)", rec.BlockerKind)
	}
	if rec.AdvisoryManifestComplete != agent7.FactNo {
		t.Errorf("advisory_manifest_complete = %q, want no", rec.AdvisoryManifestComplete)
	}
}

// TestInfraEnvelopeClassification pins the INFRA_ERROR rule: envelopes
// whose content is an infrastructure failure (context cancellation,
// advisory fetch error, FAILED terminal state, non-empty error field)
// are marked infra_error and never keep a verdict — the memguard
// cancellation class that masquerades as INCONCLUSIVE+abstain.
func TestInfraEnvelopeClassification(t *testing.T) {
	cases := []struct {
		name    string
		kv      map[string]any
		infra   bool
		verdict string
	}{
		{"clean not_affected keeps verdict", nil, false, "NOT_AFFECTED"},
		{"advisory error context canceled", map[string]any{
			"terminal_state": "INCONCLUSIVE", "verdict": "INCONCLUSIVE",
			"reason":          `advisory error: osv get https://api.osv.dev/v1/vulns/CVE-2099-0001: context canceled`,
			"scoring_outcome": "abstain", "compatibility_category": "uncertain"},
			true, "infra_error"},
		{"plain advisory error", map[string]any{
			"terminal_state": "INCONCLUSIVE", "verdict": "INCONCLUSIVE",
			"reason": "advisory error: upstream timeout"},
			true, "infra_error"},
		{"terminal FAILED", map[string]any{
			"terminal_state": "FAILED", "verdict": "INCONCLUSIVE",
			"reason": "analyzer crashed"},
			true, "infra_error"},
		{"explicit error field", map[string]any{
			"error": "snapshot not found"},
			true, "infra_error"},
		{"advisory unsupported is a real outcome", map[string]any{
			"terminal_state": "INCONCLUSIVE", "verdict": "INCONCLUSIVE",
			"reason":          "advisory unsupported: no usable Go entry",
			"scoring_outcome": "abstain"},
			false, "INCONCLUSIVE"},
		{"inconclusive unresolved conditions is a real outcome", map[string]any{
			"terminal_state": "INCONCLUSIVE", "verdict": "INCONCLUSIVE",
			"reason": "one or more mandatory exploit conditions remain unresolved: C-LOCUS"},
			false, "INCONCLUSIVE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			env := filepath.Join(dir, "prediction.json")
			writeFile(t, env, envelopeJSON(t, c.kv))
			rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
				Task:           baseTask(),
				PredictionPath: env,
			})
			if rec.InfraError != c.infra {
				t.Fatalf("infra_error = %v, want %v (reason %q)", rec.InfraError, c.infra, rec.InfraReason)
			}
			if rec.IzyanVerdict != c.verdict {
				t.Fatalf("izyan_verdict = %q, want %q", rec.IzyanVerdict, c.verdict)
			}
			if !rec.RunEnvelopePresent {
				t.Error("run_envelope_present = false, want true")
			}
			if c.infra && rec.InfraReason == "" {
				t.Error("infra_reason empty on infra case")
			}
		})
	}

	// Missing envelope = completeness failure, never a result.
	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		PredictionPath: filepath.Join(t.TempDir(), "missing.json"),
	})
	if !rec.InfraError || rec.RunEnvelopePresent {
		t.Errorf("missing envelope: infra_error=%v envelope_present=%v, want true/false",
			rec.InfraError, rec.RunEnvelopePresent)
	}
}

// TestIntegrityGateFailsClosed is the regression for expert-found
// defect #1: when the envelope's recorded advisory_sha256 differs from
// the advisory file actually consumed, every advisory- and
// snapshot-derived fact must collapse to unknown and blocker_kind must
// be "integrity" — a run must never certificate on tainted inputs.
func TestIntegrityGateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/lib v1.5.0\n")
	writeFile(t, filepath.Join(snap, "main.go"), "package main\n\nfunc main() {}\n")
	adv := filepath.Join(dir, "advisory", "GO-2099-0001.json")
	writeFile(t, adv, advisoryJSON(t, affectedEntry(
		"dep.example/lib", importPath("dep.example/lib/vuln"),
		event("introduced", "0")+","+event("fixed", "1.0.0"))))
	env := filepath.Join(dir, "prediction.json")
	// Deliberately wrong advisory hash — the tainted-input case.
	writeFile(t, env, envelopeJSON(t, map[string]any{
		"advisory_sha256": strings.Repeat("0", 64)}))

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: env,
		AdvisoryPath:   adv,
	})

	if rec.BlockerKind != agent7.BlockerIntegrity {
		t.Fatalf("blocker_kind = %q, want integrity", rec.BlockerKind)
	}
	if rec.ProofArtifactFixed != agent7.FactUnknown ||
		rec.ProofComponentAbsent != agent7.FactUnknown ||
		rec.ProofBuildExcluded != agent7.FactUnknown {
		t.Errorf("proof candidates = (%q,%q,%q), want all unknown under integrity failure",
			rec.ProofArtifactFixed, rec.ProofComponentAbsent, rec.ProofBuildExcluded)
	}
	if rec.VulnerableModule != agent7.FactUnknown || rec.ResolvedVersion != agent7.FactUnknown {
		t.Errorf("advisory-derived facts leaked: module=%q version=%q, want unknown",
			rec.VulnerableModule, rec.ResolvedVersion)
	}
}

// TestBuildExcludedAbsentSiblingCannotCertify is the regression for the
// expert-found false positive (echo/jwt-go shape): an advisory with two
// entries — one module PRESENT in the graph (imported, non-vendored) and
// one module ABSENT (a different version track) — must never produce
// build_excluded=yes. The absent sibling cannot exclude the affected
// component; the present external module's build-closure membership is
// undecidable from file reads.
func TestBuildExcludedAbsentSiblingCannotCertify(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/echo\n\ngo 1.21\n\nrequire dep.example/jwt v3.2.0+incompatible\n")
	writeFile(t, filepath.Join(snap, "middleware", "jwt.go"),
		"package middleware\n\nimport _ \"dep.example/jwt\"\n")
	adv := filepath.Join(dir, "advisory", "GO-2099-0017.json")
	writeFile(t, adv, advisoryJSON(t,
		affectedEntry("dep.example/jwt", importPath("dep.example/jwt"),
			event("introduced", "0")+","+event("fixed", "3.2.1"))+","+
			affectedEntry("dep.example/jwt/v4", importPath("dep.example/jwt/v4"),
				event("introduced", "0")+","+event("fixed", "4.0.0"))))
	env := filepath.Join(dir, "prediction.json")
	writeFile(t, env, envelopeJSON(t, map[string]any{
		"verdict": "INCONCLUSIVE", "scoring_outcome": "abstain",
		"reason": "conditions unresolved"}))

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: env,
		AdvisoryPath:   adv,
	})
	if rec.ProofBuildExcluded == agent7.FactYes {
		t.Fatalf("proof_build_excluded=yes is the expert-found false positive")
	}
	if rec.ProofBuildExcluded != agent7.FactUnknown && rec.ProofBuildExcluded != agent7.FactNo {
		t.Fatalf("proof_build_excluded = %q, want unknown|no", rec.ProofBuildExcluded)
	}
	if rec.ProofComponentAbsent != agent7.FactNo {
		t.Errorf("proof_component_absent = %q, want no (jwt present)", rec.ProofComponentAbsent)
	}
}

// TestComponentAbsentModuleOutsideGraph pins candidate (b): every
// advisory module deterministically outside the resolved graph →
// component_absent=yes (scope: module graph, stated via the fact row).
func TestComponentAbsentModuleOutsideGraph(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n\nrequire dep.example/other v1.0.0\n")
	writeFile(t, filepath.Join(snap, "main.go"), "package main\n\nfunc main() {}\n")
	adv := filepath.Join(dir, "advisory", "GO-2099-0002.json")
	writeFile(t, adv, advisoryJSON(t,
		affectedEntry("dep.example/missing", importPath("dep.example/missing/vuln"),
			event("introduced", "0")+","+event("fixed", "1.0.0"))))
	env := filepath.Join(dir, "prediction.json")
	writeFile(t, env, envelopeJSON(t, nil))

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: env,
		AdvisoryPath:   adv,
	})
	if rec.ProofComponentAbsent != agent7.FactYes {
		t.Fatalf("proof_component_absent = %q, want yes (module absent)", rec.ProofComponentAbsent)
	}
	// Absence alone can never certify build exclusion.
	if rec.ProofBuildExcluded != agent7.FactUnknown {
		t.Errorf("proof_build_excluded = %q, want unknown", rec.ProofBuildExcluded)
	}
}

// TestBuildExcludedIncompleteVariantCoverage pins candidate (c): with no
// usable build context in the envelope (no GOOS/GOARCH), even a package
// whose files sit inside the snapshot cannot be proven excluded —
// incomplete variant coverage → unknown + missing_data.
func TestBuildExcludedIncompleteVariantCoverage(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	writeFile(t, filepath.Join(snap, "go.mod"),
		"module example.com/prod\n\ngo 1.21\n")
	writeFile(t, filepath.Join(snap, "vuln", "v.go"),
		"package vuln\n\nfunc F() {}\n")
	adv := filepath.Join(dir, "advisory", "GO-2099-0003.json")
	writeFile(t, adv, advisoryJSON(t,
		affectedEntry("example.com/prod", importPath("example.com/prod/vuln"),
			event("introduced", "0"))))
	env := filepath.Join(dir, "prediction.json")
	writeFile(t, env, envelopeJSON(t, map[string]any{
		"goos": "", "goarch": ""}))

	rec := agent7.CollectCase(context.Background(), agent7.FeasibilityInputs{
		Task:           baseTask(),
		SnapshotDir:    snap,
		PredictionPath: env,
		AdvisoryPath:   adv,
	})
	if rec.ProofBuildExcluded != agent7.FactUnknown {
		t.Fatalf("proof_build_excluded = %q, want unknown (coverage incomplete)", rec.ProofBuildExcluded)
	}
	if rec.BlockerKind != agent7.BlockerMissingData {
		t.Errorf("blocker_kind = %q, want missing_data", rec.BlockerKind)
	}
}
