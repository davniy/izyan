package agent7_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/agent7"
)

// repoRoot resolves the repository root from the package dir
// (internal/eval/agent7 → ../../..).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

// frozenManifest loads the pinned eval/agent7/freeze/manifest.json — the
// artifact under test. It must exist for every A1 check.
func frozenManifest(t *testing.T) agent7.Manifest {
	t.Helper()
	m, err := agent7.Load(filepath.Join(
		repoRoot(t), "eval", "agent7", "freeze", "manifest.json"))
	if err != nil {
		t.Fatalf("frozen manifest must load fail-closed-clean: %v", err)
	}
	return m
}

// mutated returns a deep copy of the frozen manifest with fn applied —
// used to prove validation is fail-closed rather than advisory.
func mutated(t *testing.T, fn func(m map[string]any)) agent7.Manifest {
	t.Helper()
	raw, err := json.Marshal(map[string]any(frozenManifest(t)))
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	fn(m)
	return agent7.Manifest(m)
}

// mutatedManifest clones an existing manifest and applies fn.
func mutatedManifest(t *testing.T, base agent7.Manifest, fn func(m map[string]any)) agent7.Manifest {
	t.Helper()
	raw, err := json.Marshal(map[string]any(base))
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	fn(m)
	return agent7.Manifest(m)
}

// writeTemp serialises a manifest to a temp file for Load tests.
func writeTemp(t *testing.T, m agent7.Manifest) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatalf("write temp manifest: %v", err)
	}
	return p
}

func hasViolation(violations []string, needle string) bool {
	for _, v := range violations {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

// tasksFileOrSkip resolves dataset.tasks_file through path_resolution;
// the test skips explicitly (never fails) when the file is absent.
func tasksFileOrSkip(t *testing.T, m agent7.Manifest) string {
	t.Helper()
	tasksFile := agent7.ResolvedPath(m, repoRoot(t), "dataset.tasks_file")
	if !filepath.IsAbs(tasksFile) {
		t.Skipf("dataset.tasks_file unresolved (%s): external harness vars unset; dataset pin check skipped", tasksFile)
	}
	if _, err := os.Stat(tasksFile); err != nil {
		t.Skipf("external harness dataset absent at %s; dataset pin check skipped (explicit skip, not a failure)", tasksFile)
	}
	return tasksFile
}

// Brief test 1a: Load is fail-closed — unreadable file, invalid JSON,
// wrong schema and each missing required field are errors.
func TestLoadFailClosed(t *testing.T) {
	if _, err := agent7.Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("Load must fail on a missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := agent7.Load(bad); err == nil {
		t.Fatal("Load must fail on invalid JSON")
	}
	wrong := mutated(t, func(m map[string]any) { m["schema"] = "task6-manifest/1" })
	if _, err := agent7.Load(writeTemp(t, wrong)); err == nil ||
		!strings.Contains(err.Error(), "schema") {
		t.Fatalf("Load must reject a wrong schema, got %v", err)
	}
	for _, field := range []string{
		"frozen_at_utc", "goal", "implementation_language",
		"gt_paths_denied", "allowed_path_roots", "checkpoints",
		"freeze_status", "run_gate", "path_resolution", "outcomes",
	} {
		m := mutated(t, func(mm map[string]any) { delete(mm, field) })
		if _, err := agent7.Load(writeTemp(t, m)); err == nil {
			t.Fatalf("Load must fail closed on missing %q", field)
		}
	}
	// A null inside a required nested field is also missing.
	m := mutated(t, func(mm map[string]any) {
		mm["model"] = map[string]any{"id": nil}
	})
	if _, err := agent7.Load(writeTemp(t, m)); err == nil {
		t.Fatal("Load must fail closed on model.id == null")
	}
}

// Review C1: Validate is type/shape-strict — a wrong JSON type for a
// required field is a violation, not a silent skip.
func TestValidateTypeStrict(t *testing.T) {
	cases := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"files_sha256 not a map", func(m map[string]any) {
			m["freeze"] = map[string]any{"files_sha256": "not-a-map"}
		}},
		{"gt_paths_denied not a list", func(m map[string]any) {
			m["gt_paths_denied"] = "eval/ground-truth.md"
		}},
		{"repeats not a number", func(m map[string]any) {
			m["attempt_policy"] = map[string]any{
				"timeout_seconds": 900.0, "repeats": "3",
				"parallel": 1.0, "retries": 0.0,
				"attempt_key": "k",
			}
		}},
		{"freeze_required not bool", func(m map[string]any) {
			m["prompts"] = map[string]any{
				"freeze_required_before_run": "true", "files": map[string]any{},
			}
		}},
	}
	for _, tc := range cases {
		m := mutated(t, tc.mut)
		// Load itself must already refuse the mistyped manifest…
		if _, err := agent7.Load(writeTemp(t, m)); err == nil {
			// …but when it does not (field optional shape), Validate must.
			vs, _, err := agent7.Validate(m, repoRoot(t))
			if err != nil {
				t.Fatalf("%s: Validate: %v", tc.name, err)
			}
			if !hasViolation(vs, "wrong type") && !hasViolation(vs, "not a string map") {
				t.Fatalf("%s: expected a type violation, got %v", tc.name, vs)
			}
		}
	}
}

// Brief test 1b: every sha256 pinned in the manifest matches the real file
// bytes in the repo, and tampering with a pin is a violation.
func TestPinnedFileHashes(t *testing.T) {
	root := repoRoot(t)
	m := frozenManifest(t)
	violations, _, err := agent7.Validate(m, root)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, v := range violations {
		if strings.Contains(v, "sha256 mismatch") || strings.Contains(v, "unreadable pinned file") {
			t.Fatalf("pinned hash violation: %s", v)
		}
	}
	groups := []string{
		"spec.files_sha256", "spec.plan_sha256",
		"freeze.files_sha256", "controller.files_sha256",
		"prompts.files",
	}
	for _, g := range groups {
		pins := m.GetStringMap(g)
		if len(pins) == 0 {
			t.Fatalf("%s must pin at least one file", g)
		}
		for rel := range pins {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
				t.Fatalf("%s pins missing file %s", g, rel)
			}
		}
	}
	tampered := mutated(t, func(mm map[string]any) {
		fs := mm["freeze"].(map[string]any)["files_sha256"].(map[string]any)
		for k := range fs {
			fs[k] = strings.Repeat("0", 64)
			return
		}
	})
	vs, _, err := agent7.Validate(tampered, root)
	if err != nil {
		t.Fatalf("Validate tampered: %v", err)
	}
	if !hasViolation(vs, "sha256 mismatch") {
		t.Fatal("tampered pinned sha256 must produce a violation")
	}
	// A non-64-hex pin is rejected, not skipped.
	badPin := mutated(t, func(mm map[string]any) {
		fs := mm["freeze"].(map[string]any)["files_sha256"].(map[string]any)
		for k := range fs {
			fs[k] = "abc123"
			return
		}
	})
	vs, _, err = agent7.Validate(badPin, root)
	if err != nil {
		t.Fatalf("Validate badPin: %v", err)
	}
	if !hasViolation(vs, "not a 64-hex sha256") {
		t.Fatalf("short pin must be a violation, got %v", vs)
	}
}

// Brief test 2: when the external tasks file resolves its sha256 and all
// 30 task ids match the manifest; when it does not, the test skips
// explicitly — never fails on machines without the harness.
func TestDatasetPin(t *testing.T) {
	m := frozenManifest(t)
	tasksFile := tasksFileOrSkip(t, m)
	tasks, err := agent7.LoadTaskRecords(tasksFile)
	if err != nil {
		t.Fatalf("LoadTaskRecords: %v", err)
	}
	pinned := m.GetStringSlice("dataset.task_ids")
	if len(tasks) != 30 || len(pinned) != 30 {
		t.Fatalf("dataset must carry 30 tasks; file=%d manifest=%d", len(tasks), len(pinned))
	}
	for i, task := range tasks {
		if task.TaskID != pinned[i] {
			t.Fatalf("task_ids[%d]: file %q != manifest %q", i, task.TaskID, pinned[i])
		}
	}
	sum, err := agent7.SHA256File(tasksFile)
	if err != nil {
		t.Fatalf("sha256 tasks file: %v", err)
	}
	if sum != agent7.ExpectedDatasetSHA256 || sum != m.GetString("dataset.tasks_sha256") {
		t.Fatalf("dataset sha256 %s does not match the pin %s", sum, agent7.ExpectedDatasetSHA256)
	}
	violations, present, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !present {
		t.Fatal("Validate must report the dataset as present when the file resolves")
	}
	if hasViolation(violations, "dataset") {
		t.Fatalf("dataset violations on the pinned file: %v", violations)
	}
}

// Absent-dataset behaviour: a manifest whose tasks file resolves nowhere
// must report present=false and no dataset-hash violation.
func TestDatasetPinAbsentIsNotFailure(t *testing.T) {
	m := mutated(t, func(mm map[string]any) {
		mm["dataset"].(map[string]any)["tasks_file"] =
			filepath.Join(t.TempDir(), "no-such-tasks.jsonl")
	})
	vs, present, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if present {
		t.Fatal("present must be false for an absent tasks file")
	}
	if hasViolation(vs, "dataset.tasks_sha256 mismatch") || hasViolation(vs, "dataset.tasks_file unreadable") {
		t.Fatalf("absent dataset must not produce hash violations: %v", vs)
	}
}

// Review A3/C3: the committed manifest is GT-free — no per-case labels,
// expectations or reference keys anywhere; injected ones are flagged.
func TestManifestIsGTFree(t *testing.T) {
	m := frozenManifest(t)
	vs, _, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if hasViolation(vs, "GT/reference key") {
		t.Fatalf("frozen manifest must be GT-free: %v", vs)
	}
	// Every denied key spelling, injected at top level and nested, is
	// flagged — folded for case and separators.
	injections := []struct {
		path string
		key  string
	}{
		{"dataset", "gt_safe_case_ids"},
		{"smoke", "case_classes"},
		{"dataset", "ground_truth"},
		{"dataset", "groundTruth"},
		{"smoke", "expected_result"},
		{"smoke", "reference"},
		{"smoke", "reference_pr"},
		{"smoke", "expect"},
	}
	for _, inj := range injections {
		m := mutated(t, func(mm map[string]any) {
			mm[inj.path].(map[string]any)[inj.key] = "x"
		})
		vs, _, err := agent7.Validate(m, repoRoot(t))
		if err != nil {
			t.Fatalf("Validate %s.%s: %v", inj.path, inj.key, err)
		}
		if !hasViolation(vs, "GT/reference key") {
			t.Fatalf("injected %s.%s must be flagged as committed GT", inj.path, inj.key)
		}
	}
	// Allowed policy fields are not flagged.
	for _, k := range []string{"gt_policy", "gt_paths_denied", "gt_class_counts"} {
		if hasViolation(m.MissingFields(), k) {
			t.Fatalf("policy field %s must not count as a GT key", k)
		}
	}
}

// Brief test 3: for every task in the frozen dataset the rendered agent
// input carries only the allowlisted scalar identity keys; a record with
// GT keys — at any depth or folded spelling — is rejected.
func TestAgentInputNeverLeaksGT(t *testing.T) {
	m := frozenManifest(t)
	records := datasetOrFixture(t, m)
	for _, rec := range records {
		src := map[string]any{
			"task_id":    rec.TaskID,
			"cve_id":     rec.CVEID,
			"repo_url":   rec.RepoURL,
			"commit_sha": rec.CommitSHA,
		}
		in, err := agent7.RenderAgentInput(src)
		if err != nil {
			t.Fatalf("render %s: %v", rec.TaskID, err)
		}
		if len(in) != len(src) {
			t.Fatalf("render %s: unexpected keys %v", rec.TaskID, in)
		}
		for k, v := range in {
			if _, ok := v.(string); !ok {
				t.Fatalf("render %s: key %s is not a scalar string", rec.TaskID, k)
			}
		}
		raw := map[string]any{
			"task_id":      rec.TaskID,
			"cve_id":       rec.CVEID,
			"ground_truth": rec.GroundTruth,
			"metadata":     map[string]any{"language": "go"},
		}
		if _, err := agent7.RenderAgentInput(raw); err == nil {
			t.Fatalf("render %s must reject a record carrying ground_truth", rec.TaskID)
		}
	}
}

// datasetOrFixture returns the 30 real task records when the external
// dataset resolves, otherwise a synthetic fixture with the same shape.
func datasetOrFixture(t *testing.T, m agent7.Manifest) []agent7.TaskRecord {
	t.Helper()
	tasksFile := agent7.ResolvedPath(m, repoRoot(t), "dataset.tasks_file")
	if filepath.IsAbs(tasksFile) {
		if recs, err := agent7.LoadTaskRecords(tasksFile); err == nil {
			return recs
		}
	}
	return []agent7.TaskRecord{
		{TaskID: "acme-foo-aaaaaaa-CVE-2000-0001", CVEID: "CVE-2000-0001",
			RepoURL: "https://example.invalid/foo", CommitSHA: "aaaaaaa",
			GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
		{TaskID: "acme-bar-bbbbbbb-CVE-2000-0002", CVEID: "CVE-2000-0002",
			RepoURL: "https://example.invalid/bar", CommitSHA: "bbbbbbb",
			GroundTruth: "not_exploitable", GroundTruthCategory: "code_not_reachable"},
	}
}

// Review C4: RenderAgentInput is strict — denied keys fold for case and
// separators at any depth; allowlisted values must be scalar strings.
func TestAgentInputStrictness(t *testing.T) {
	// Folded denied spellings, nested and inside arrays/map[string]string.
	deniedRecords := []map[string]any{
		{"task_id": "t", "metadata": map[string]any{"groundTruth": "safe"}},
		{"task_id": "t", "metadata": map[string]any{"GROUND_TRUTH": "safe"}},
		{"task_id": "t", "metadata": map[string]any{"Ground_Truth": "safe"}},
		{"task_id": "t", "extra": []any{map[string]any{"expect": []string{"x"}}}},
		{"task_id": "t", "hidden": true},
		{"task_id": "t", "reference": "https://example.invalid/pr/1"},
		{"task_id": "t", "referencePR": "https://example.invalid/pr/1"},
		{"task_id": "t", "expected_result": "safe"},
		{"task_id": "t", "inner": map[string]string{"pr_url": "x"}}, // map[string]string depth
	}
	for i, c := range deniedRecords {
		if _, err := agent7.RenderAgentInput(c); err == nil {
			t.Fatalf("denied case %d must fail the render", i)
		}
	}
	// Non-scalar allowlisted values are rejected.
	for _, v := range []any{
		123.0, true, []any{"x"}, map[string]any{"k": "v"}, nil,
	} {
		rec := map[string]any{"task_id": v, "cve_id": "CVE-1"}
		if _, err := agent7.RenderAgentInput(rec); err == nil {
			t.Fatalf("non-scalar allowlisted value %T must fail", v)
		}
	}
	// A clean projection serializes to exactly the allowlisted scalars.
	in, err := agent7.RenderAgentInput(map[string]any{
		"task_id": "t1", "cve_id": "CVE-1",
		"repo_url": "https://x", "commit_sha": "deadbeef",
		"extra_field": "dropped",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 4 {
		t.Fatalf("projection must carry exactly 4 keys, got %v", back)
	}
	for k, v := range back {
		if _, ok := v.(string); !ok {
			t.Fatalf("key %s is not a scalar string: %v", k, back)
		}
	}
}

// Brief test 4 / review C5: gt_paths_denied covers the in-repo GT
// carriers and the external tasks file; normalization handles relative,
// './', '..', trailing-slash, backslash, uppercase and relative-vs-
// absolute forms.
func TestGTPathDenial(t *testing.T) {
	m := frozenManifest(t)
	denied := m.GetStringSlice("gt_paths_denied")
	if len(denied) == 0 {
		t.Fatal("manifest must pin gt_paths_denied")
	}
	mustDeny := []string{
		"eval/ground-truth.md",
		"eval/ground-truth/real-yaml-http.md",
		"eval/ground-truth/real-ssh-callback.md",
		"eval/corpus.json",
		"eval/corpus-real.json",
		"eval/corpus-reviewed.json",
		"eval/live-corpus.json",
		"./eval/ground-truth/../ground-truth.md",
		"eval/ground-truth/",
		`eval\ground-truth\real-yaml-http.md`,
		"EVAL/GROUND-TRUTH.MD",
		"eval/agent7/freeze/gt-extra.json",
	}
	for _, p := range mustDeny {
		if !agent7.GTPathDenied(p, denied) {
			t.Fatalf("GT path %q must be denied by gt_paths_denied", p)
		}
	}
	// The external tasks carrier must be denied in template and resolved
	// form (relative glob covering an absolute candidate).
	resolved := agent7.ResolvedPath(m, repoRoot(t), "dataset.tasks_file")
	if filepath.IsAbs(resolved) && !agent7.GTPathDenied(resolved, agent7.GTPathsDeniedResolved(m, repoRoot(t))) {
		t.Fatalf("resolved external tasks file %q must be denied", resolved)
	}
	if !agent7.GTPathDenied("benchmark/tasks/vex_bench.jsonl", denied) {
		t.Fatal("relative external-tasks path must be denied")
	}
	mustAllow := []string{
		"eval/agent7/freeze/manifest.json",
		"eval/products/yaml-http/go.mod",
		"internal/eval/agent7/manifest.go",
		"eval/advisories/real/x.json",
	}
	for _, p := range mustAllow {
		if agent7.GTPathDenied(p, denied) {
			t.Fatalf("non-GT path %q must not be denied", p)
		}
	}
	vs, _, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if hasViolation(vs, "gt_paths_denied") {
		t.Fatalf("frozen manifest fails its own GT-denial coverage check: %v", vs)
	}
}

// An invalid deny glob is a violation, never silently ignored.
func TestGTPathDeniedInvalidGlob(t *testing.T) {
	m := mutated(t, func(mm map[string]any) {
		mm["gt_paths_denied"] = []any{"eval/ground-truth/[unclosed"}
	})
	vs, _, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !hasViolation(vs, "invalid glob") {
		t.Fatalf("invalid glob must be a violation, got %v", vs)
	}
}

// Brief test 5 / review C6: approved-root set is code-level; manifest
// allowed_path_roots must be a subset; '..' escapes, out-of-root paths,
// and secret basenames are rejected case-insensitively.
func TestNoPrivateProductPaths(t *testing.T) {
	m := frozenManifest(t)
	raw, err := json.Marshal(map[string]any(m))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "${VA_PRODUCT_REPO}") {
		t.Fatal("expected the ${VA_PRODUCT_REPO} placeholder convention to appear")
	}
	vs, _, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if hasViolation(vs, "approved root") || hasViolation(vs, "private_path_patterns") ||
		hasViolation(vs, "secret-like") {
		t.Fatalf("frozen manifest must not contain private/secret paths: %v", vs)
	}

	// Mutated allowed_path_roots is a violation.
	for _, roots := range [][]any{
		{"/totally/other/root"},
		{"${IZYAN_WORKTREE}/../outside"},
		{"${IZYAN_WORKTREE}", "${VEXBENCH_DURABLE_DIR}", "/etc"},
	} {
		inj := mutated(t, func(mm map[string]any) {
			mm["allowed_path_roots"] = roots
		})
		vs, _, err := agent7.Validate(inj, repoRoot(t))
		if err != nil {
			t.Fatalf("Validate roots %v: %v", roots, err)
		}
		if !hasViolation(vs, "approved root set") {
			t.Fatalf("mutated allowed_path_roots %v must be rejected", roots)
		}
	}

	injections := map[string]string{
		"private product path":  "/srv/company/vuln-analyzer-product/tree",
		"secret file":           "/home/ci/.env",
		"ssh key":               "/root/.ssh/id_rsa_backup",
		"other unapproved root": "/opt/secret-corpus/tasks.jsonl",
		"api key file":          "/etc/svc/api_key.txt",
		"uppercase secret":      "/home/ci/API_KEY",
		"aws dir":               "/home/ci/.aws/credentials",
		"npmrc":                 "/home/ci/.npmrc",
		"dotdot escape":         "${IZYAN_WORKTREE}/../outside/x.json",
	}
	for name, path := range injections {
		inj := mutated(t, func(mm map[string]any) {
			mm["smoke"].(map[string]any)["injected"] = path
		})
		vs, _, err := agent7.Validate(inj, repoRoot(t))
		if err != nil {
			t.Fatalf("Validate injected %q: %v", name, err)
		}
		violated := hasViolation(vs, "approved root set") ||
			hasViolation(vs, "private_path_patterns") || hasViolation(vs, "secret-like") ||
			hasViolation(vs, "'..' escape")
		if !violated {
			t.Fatalf("injected %s %q must be rejected", name, path)
		}
	}
}

// Arms repeats consistency: B0/PR1 run deterministically once; the
// deviation must be recorded in limitations (Task-6 precedent).
func TestArmRepeatsDeviationsRecorded(t *testing.T) {
	m := frozenManifest(t)
	vs, _, err := agent7.Validate(m, repoRoot(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if hasViolation(vs, "attempt_policy.repeats") {
		t.Fatalf("recorded repeats deviations must validate clean: %v", vs)
	}
	stripped := mutated(t, func(mm map[string]any) {
		mm["limitations"] = []any{}
	})
	if _, err := agent7.Load(writeTemp(t, stripped)); err == nil {
		// empty limitations is a required-field violation at Load; if it
		// loads anyway, Validate must still flag the unrecorded deviation.
		vs, _, err := agent7.Validate(stripped, repoRoot(t))
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !hasViolation(vs, "attempt_policy.repeats") {
			t.Fatal("unrecorded arm repeats deviation must be a violation")
		}
	}
}

// Path resolution: IZYAN_WORKTREE falls back to the repo root; VEXBENCH_*
// derive only when VEXBENCH_DURABLE_DIR is set; nothing resolves to a
// committed operator-local path.
func TestPathResolution(t *testing.T) {
	root := repoRoot(t)
	m := frozenManifest(t)

	// With env vars blanked, only IZYAN_WORKTREE resolves (to repoRoot);
	// VEXBENCH_* stay unset and dataset-dependent checks skip.
	for _, v := range []string{
		"IZYAN_WORKTREE", "VEXBENCH_DURABLE_DIR",
		"VEXBENCH_HARNESS_DIR", "VEXBENCH_REPOS_DIR",
	} {
		t.Setenv(v, "")
	}
	vars := agent7.ResolvePathVars(m, root)
	if got := vars["IZYAN_WORKTREE"].Resolved(); got != root {
		t.Fatalf("IZYAN_WORKTREE must fall back to repo root %s, got %q", root, got)
	}
	for _, v := range []string{"VEXBENCH_DURABLE_DIR", "VEXBENCH_HARNESS_DIR", "VEXBENCH_REPOS_DIR"} {
		if vars[v].Set() {
			t.Fatalf("%s must be unset without env/derivation, got %q", v, vars[v].Resolved())
		}
	}
	if resolved := agent7.ResolvedPath(m, root, "dataset.tasks_file"); filepath.IsAbs(resolved) {
		t.Fatalf("tasks_file must not resolve without VEXBENCH_DURABLE_DIR, got %q", resolved)
	}

	// With VEXBENCH_DURABLE_DIR set, the derived vars resolve under it.
	durable := t.TempDir()
	t.Setenv("VEXBENCH_DURABLE_DIR", durable)
	vars = agent7.ResolvePathVars(m, root)
	wantHarness := filepath.Join(durable, "agent-ctl")
	if got := vars["VEXBENCH_HARNESS_DIR"].Resolved(); got != wantHarness {
		t.Fatalf("VEXBENCH_HARNESS_DIR = %q, want %q", got, wantHarness)
	}
	if got := vars["VEXBENCH_REPOS_DIR"].Resolved(); got != filepath.Join(durable, "repos") {
		t.Fatalf("VEXBENCH_REPOS_DIR = %q", got)
	}
	resolved := agent7.ResolvedPath(m, root, "dataset.tasks_file")
	wantTasks := filepath.Join(durable, "agent-ctl", "benchmark", "tasks", "vex_bench.jsonl")
	if resolved != wantTasks {
		t.Fatalf("dataset.tasks_file = %q, want %q", resolved, wantTasks)
	}
	// The resolved external carrier must be denied by the resolved
	// deny list.
	if !agent7.GTPathDenied(resolved, agent7.GTPathsDeniedResolved(m, root)) {
		t.Fatalf("resolved tasks file %q must be denied", resolved)
	}
	// The manifest commits no concrete operator path anywhere.
	raw, err := json.Marshal(map[string]any(m))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), durable) {
		t.Fatal("manifest must never contain a concrete operator path")
	}
}

// Review C2: the strict run gate stays closed on the remaining later-phase
// pins — A2 supplied the B1/R0 prompt hashes and checkpoint_a sign-off
// (2026-10-11), so what still closes it is the R1/R2 prompt pins, the
// selected tool subset, the A9 holdout and checkpoint_b/c. It opens only
// when every pin is supplied. The arm-scoped gate has its own test
// (TestRunGateForArm); the A2-open frozen state is covered by
// TestRunGateForArmA2Open.
func TestRunGate(t *testing.T) {
	m := frozenManifest(t)
	if closed := agent7.CheckRunGate(m); len(closed) == 0 {
		t.Fatal("strict run gate must be CLOSED on the remaining A4/A9 pins")
	} else {
		for _, want := range []string{
			"arm_prompts", "selected_tool_names", "holdout", "sign-off",
		} {
			found := false
			for _, c := range closed {
				if strings.Contains(c, want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("run gate must report missing %s; closed=%v", want, closed)
			}
		}
		// The A2 pins are supplied — none of them may appear in the
		// closed list (no prompts.files-empty, no B1/R0 arm prompt, no
		// checkpoint_a sign-off reason).
		for _, c := range closed {
			if strings.Contains(c, "prompts.files") ||
				strings.Contains(c, `arm_prompts["B1"]`) ||
				strings.Contains(c, `arm_prompts["R0"]`) ||
				strings.Contains(c, "checkpoint_a") {
				t.Fatalf("strict gate must not report an already-pinned A2 input: %v", c)
			}
		}
	}

	// Supply every pin → the gate opens.
	open := mutated(t, func(mm map[string]any) {
		pinArmPrompts(mm)
		pinE6Pass(mm)
		mm["tool_exposure"].(map[string]any)["R1"].(map[string]any)["selected_tool_names"] =
			[]any{"get_module_version", "get_advisory"}
		mm["holdout"].(map[string]any)["manifest_file"] = "eval/agent7/holdout/manifest.json"
		mm["holdout"].(map[string]any)["manifest_sha256"] = strings.Repeat("b", 64)
		for name, raw := range mm["checkpoints"].(map[string]any) {
			if c, ok := raw.(map[string]any); ok {
				if req, _ := c["requires_operator_signoff"].(bool); req {
					c["operator_signoff"] = true
					_ = name
				}
			}
		}
	})
	if closed := agent7.CheckRunGate(open); len(closed) != 0 {
		t.Fatalf("run gate must open when all pins are supplied: %v", closed)
	}

	// A >5 selected tool subset stays closed.
	tooMany := mutated(t, func(mm map[string]any) {
		mm["tool_exposure"].(map[string]any)["R1"].(map[string]any)["selected_tool_names"] =
			[]any{"a", "b", "c", "d", "e", "f"}
	})
	// keep other pins missing — the violation we check is specific.
	closed := agent7.CheckRunGate(tooMany)
	if !hasViolation(closed, "cap is 5") {
		t.Fatalf("over-cap tool subset must keep the gate closed: %v", closed)
	}

	// A malformed prompt hash is rejected by the gate.
	badPrompt := mutated(t, func(mm map[string]any) {
		mm["prompts"] = map[string]any{
			"freeze_required_before_run": true,
			"files":                      map[string]any{"research_v1": "not-hex"},
		}
	})
	closed = agent7.CheckRunGate(badPrompt)
	if !hasViolation(closed, "64-hex") {
		t.Fatalf("malformed prompt pin must keep the gate closed: %v", closed)
	}
}

// pinArmPrompts fills every prompt pin the gates know: prompts.files (the
// prompt-artifact map) and prompts.arm_prompts (the per-arm hash map).
func pinArmPrompts(mm map[string]any) {
	p := mm["prompts"].(map[string]any)
	p["files"] = map[string]any{
		"b1_plain_v1":   strings.Repeat("a", 64),
		"research_v1":   strings.Repeat("b", 64),
		"research_r1v1": strings.Repeat("d", 64),
	}
	p["arm_prompts"] = map[string]any{
		"B1": strings.Repeat("a", 64),
		"R0": strings.Repeat("b", 64),
		"R1": strings.Repeat("d", 64),
		"R2": strings.Repeat("d", 64),
	}
}

// pinE6Pass marks the E6 sandbox report as verified: PASS status plus a
// pinned path and sha256.
func pinE6Pass(mm map[string]any) {
	e6 := mm["environment"].(map[string]any)["e6"].(map[string]any)
	e6["status"] = "PASS"
	e6["report_sha256"] = strings.Repeat("c", 64)
}

// signCheckpoint sets operator_signoff on one checkpoint.
func signCheckpoint(mm map[string]any, name string) {
	mm["checkpoints"].(map[string]any)[name].(map[string]any)["operator_signoff"] = true
}

// E6 sandbox design §0 option 1: the run gate is arm-scoped. B1/R0 need
// only their own prompt hash + the shared environment/reproducibility
// pins + the applicable checkpoint sign-offs; they are NOT blocked on the
// A4 tool list or the A9 holdout. R1/R2 keep their extra requirements and
// blind runs keep the holdout pin.
func TestRunGateForArm(t *testing.T) {
	// Frozen state (2026-10-11): the A2 pins have landed — the dev-dataset
	// gate is OPEN for B1, R0 and B0. Arm ids are case-insensitive.
	m := frozenManifest(t)
	for _, arm := range []string{"B0", "B1", "R0", "b1", "r0"} {
		if closed := agent7.CheckRunGateForArm(m, arm); len(closed) != 0 {
			t.Fatalf("%s gate must be OPEN — prompts pinned + checkpoint_a signed: %v", arm, closed)
		}
	}
	// Later-phase arms stay CLOSED on their own pins.
	for arm, want := range map[string][]string{
		"R1":  {"prompts.arm_prompts", "selected_tool_names", "checkpoint_b"},
		"R2":  {"prompts.arm_prompts", "selected_tool_names", "checkpoint_b"},
		"PR1": {"checkpoint_c"},
	} {
		closed := agent7.CheckRunGateForArm(m, arm)
		if len(closed) == 0 {
			t.Fatalf("%s gate must be CLOSED — later-phase pins are not supplied", arm)
		}
		for _, w := range want {
			if !hasViolation(closed, w) {
				t.Fatalf("%s gate must report %s; closed=%v", arm, w, closed)
			}
		}
	}
	// An unknown arm fails closed.
	if !hasViolation(agent7.CheckRunGateForArm(m, "A9"), "not defined") {
		t.Fatal("unknown arm must fail closed")
	}

	// Blind scope (A9): the holdout pin is additional — an open dev gate
	// is still closed blind until the holdout manifest is pinned.
	if closed := agent7.CheckRunGateForBlindArm(m, "B1"); !hasViolation(closed, "holdout") {
		t.Fatalf("blind B1 gate must require the holdout pin: %v", closed)
	}
	blind := mutated(t, func(mm map[string]any) {
		mm["holdout"].(map[string]any)["manifest_file"] = "eval/agent7/holdout/manifest.json"
		mm["holdout"].(map[string]any)["manifest_sha256"] = strings.Repeat("e", 64)
	})
	if closed := agent7.CheckRunGateForBlindArm(blind, "B1"); len(closed) != 0 {
		t.Fatalf("blind B1 gate must open with the holdout pinned: %v", closed)
	}
	if closed := agent7.CheckRunGateForArm(blind, "B1"); len(closed) != 0 {
		t.Fatalf("dev B1 gate must not be affected by the holdout pin: %v", closed)
	}

	// R1 needs its own extra pins even when every B1/R0 pin is present.
	r1 := mutatedManifest(t, blind, func(mm map[string]any) {
		pinArmPrompts(mm)
		mm["tool_exposure"].(map[string]any)["R1"].(map[string]any)["selected_tool_names"] =
			[]any{"get_module_version", "get_advisory"}
		signCheckpoint(mm, "checkpoint_b")
	})
	if closed := agent7.CheckRunGateForArm(r1, "R1"); len(closed) != 0 {
		t.Fatalf("R1 gate must open on prompt+tools+checkpoint_b: %v", closed)
	}
	r1over := mutatedManifest(t, r1, func(mm map[string]any) {
		mm["tool_exposure"].(map[string]any)["R1"].(map[string]any)["selected_tool_names"] =
			[]any{"a", "b", "c", "d", "e", "f"}
	})
	if closed := agent7.CheckRunGateForArm(r1over, "R1"); !hasViolation(closed, "cap is 5") {
		t.Fatalf("over-cap tool subset must keep the R1 gate closed: %v", closed)
	}

	// Malformed and missing pins fail closed per arm.
	badSHA := mutatedManifest(t, r1, func(mm map[string]any) {
		mm["prompts"].(map[string]any)["arm_prompts"].(map[string]any)["B1"] = "not-hex"
	})
	if closed := agent7.CheckRunGateForArm(badSHA, "B1"); !hasViolation(closed, "64-hex") {
		t.Fatalf("malformed arm_prompts pin must close the B1 gate: %v", closed)
	}
	envFail := mutatedManifest(t, r1, func(mm map[string]any) {
		mm["environment"].(map[string]any)["e6"].(map[string]any)["status"] = "ENV_FAIL"
	})
	if closed := agent7.CheckRunGateForArm(envFail, "B1"); !hasViolation(closed, "environment.e6.status") {
		t.Fatalf("ENV_FAIL report must keep the gate closed (fail-closed, not an isolation pass): %v", closed)
	}
	noProfile := mutatedManifest(t, r1, func(mm map[string]any) {
		mm["run_profile"] = map[string]any{}
	})
	if closed := agent7.CheckRunGateForArm(noProfile, "B0"); !hasViolation(closed, "run_profile.mem_limit") {
		t.Fatalf("missing run-profile pins must keep the gate closed: %v", closed)
	}
}

// A2 pins landed (2026-10-11): the frozen manifest satisfies every B1/R0
// gate input — shared pins (scorer, run_profile, environment.e6 PASS,
// checkpoint_0), the per-arm prompt hashes in prompts.arm_prompts and
// prompts.files, and checkpoint_a sign-off — so the development-dataset
// gate is OPEN for both arms (arm ids are case-insensitive). Removing the
// prompt pin or unsigning checkpoint_a is the only per-arm close reason;
// the blind scope adds the holdout requirement on the same manifest. The
// pinned hashes are verified against the committed prompt bytes and the
// byte-additive treatment delta is re-checked.
func TestRunGateForArmA2Open(t *testing.T) {
	// Frozen state: gate OPEN for B1 and R0 — no closed reasons at all.
	m := frozenManifest(t)
	for _, arm := range []string{"B1", "R0", "b1", "r0"} {
		if closed := agent7.CheckRunGateForArm(m, arm); len(closed) != 0 {
			t.Fatalf("%s dev-dataset gate must be OPEN in the frozen manifest: %v", arm, closed)
		}
	}
	// The blind scope on the same manifest still requires the holdout.
	if closed := agent7.CheckRunGateForBlindArm(m, "R0"); !hasViolation(closed, "holdout") {
		t.Fatalf("blind R0 gate must require the holdout pin: %v", closed)
	}
	// The frozen E6 pin itself: committed report path + real 64-hex
	// sha256 + PASS status.
	if got := m.GetString("environment.e6.status"); got != "PASS" {
		t.Fatalf("environment.e6.status = %q, want PASS", got)
	}
	wantSHA, err := agent7.SHA256File(filepath.Join(
		repoRoot(t), "eval", "agent7", "freeze", "e6", "security-boundary-check.json"))
	if err != nil {
		t.Fatalf("committed E6 report must exist: %v", err)
	}
	if m.GetString("environment.e6.report_path") != "eval/agent7/freeze/e6/security-boundary-check.json" ||
		m.GetString("environment.e6.report_sha256") != wantSHA {
		t.Fatalf("environment.e6 report pin does not match the committed report bytes: %v",
			m.GetStringSlice("environment.e6"))
	}
	// The pinned prompt hashes match the committed prompt bytes, and the
	// recorded treatment delta re-verifies byte-for-byte: r0.txt is
	// b1.txt minus the final LF, then two LF, then the delta block —
	// the delta block itself hashes to prompts.treatment_delta.delta_sha256.
	b1Bytes, err := os.ReadFile(filepath.Join(repoRoot(t), "eval", "agent7", "prompts", "b1.txt"))
	if err != nil {
		t.Fatalf("read b1.txt: %v", err)
	}
	r0Bytes, err := os.ReadFile(filepath.Join(repoRoot(t), "eval", "agent7", "prompts", "r0.txt"))
	if err != nil {
		t.Fatalf("read r0.txt: %v", err)
	}
	b1Sum := sha256.Sum256(b1Bytes)
	r0Sum := sha256.Sum256(r0Bytes)
	b1Hex, r0Hex := hex.EncodeToString(b1Sum[:]), hex.EncodeToString(r0Sum[:])
	if m.GetStringMap("prompts.arm_prompts")["B1"] != b1Hex ||
		m.GetStringMap("prompts.arm_prompts")["R0"] != r0Hex {
		t.Fatalf("prompts.arm_prompts pins do not match the committed prompt bytes (b1 %s, r0 %s)",
			b1Hex, r0Hex)
	}
	if m.GetStringMap("prompts.files")["eval/agent7/prompts/b1.txt"] != b1Hex ||
		m.GetStringMap("prompts.files")["eval/agent7/prompts/r0.txt"] != r0Hex {
		t.Fatal("prompts.files pins do not match the committed prompt bytes")
	}
	if n := len(b1Bytes); n == 0 || b1Bytes[n-1] != '\n' {
		t.Fatal("b1.txt must end with a final LF for the additive-delta convention")
	}
	if !bytes.Equal(r0Bytes[:len(b1Bytes)-1], b1Bytes[:len(b1Bytes)-1]) ||
		!bytes.Equal(r0Bytes[len(b1Bytes)-1:len(b1Bytes)+1], []byte("\n\n")) {
		t.Fatal("r0.txt must be b1.txt minus its final LF + two LF + the delta block")
	}
	deltaSum := sha256.Sum256(r0Bytes[len(b1Bytes)+1:])
	if got, want := hex.EncodeToString(deltaSum[:]),
		m.GetString("prompts.treatment_delta.delta_sha256"); got != want || want == "" {
		t.Fatalf("delta block sha256 %s != prompts.treatment_delta.delta_sha256 %q", got, want)
	}
	// Unsigning checkpoint_a closes both A2 gates; removing the prompt pin
	// leaves exactly one closed reason per arm — proof no other
	// requirement contributes.
	unsigned := mutated(t, func(mm map[string]any) {
		mm["checkpoints"].(map[string]any)["checkpoint_a"].(map[string]any)["operator_signoff"] = false
	})
	for _, arm := range []string{"B1", "R0"} {
		if closed := agent7.CheckRunGateForArm(unsigned, arm); !hasViolation(closed, "checkpoint_a") {
			t.Fatalf("%s gate must report the unsigned checkpoint: %v", arm, closed)
		}
	}
	noPrompt := mutated(t, func(mm map[string]any) {
		delete(mm["prompts"].(map[string]any), "arm_prompts")
	})
	for _, arm := range []string{"B1", "R0"} {
		closed := agent7.CheckRunGateForArm(noPrompt, arm)
		if len(closed) != 1 || !strings.Contains(closed[0], `prompts.arm_prompts["`+arm+`"]`) {
			t.Fatalf("%s gate must report exactly the missing prompt hash; closed=%v", arm, closed)
		}
	}
	// A malformed prompt hash still fails closed.
	bad := mutated(t, func(mm map[string]any) {
		mm["prompts"].(map[string]any)["arm_prompts"].(map[string]any)["B1"] = "xyz"
	})
	if closed := agent7.CheckRunGateForArm(bad, "B1"); len(closed) != 1 ||
		!strings.Contains(closed[0], "64-hex") {
		t.Fatalf("malformed arm_prompts pin must close the B1 gate alone: %v", closed)
	}
}

// The frozen manifest must declare freeze_status + scorer version.
func TestFreezeStatusAndScorer(t *testing.T) {
	m := frozenManifest(t)
	if m.GetString("freeze_status.state") != "protocol_frozen" {
		t.Fatalf("freeze_status.state = %q", m.GetString("freeze_status.state"))
	}
	if got := m.GetStringSlice("freeze_status.pending_pins"); len(got) == 0 {
		t.Fatal("freeze_status.pending_pins must list what still needs pinning")
	}
	if m.GetString("outcomes.scorer_version") != agent7.ScorerVersion {
		t.Fatalf("outcomes.scorer_version %q != %q",
			m.GetString("outcomes.scorer_version"), agent7.ScorerVersion)
	}
}

// Defect 1 regression: GTPathDenied normalization + glob semantics.
func TestGTPathDeniedGlobSemantics(t *testing.T) {
	// Backslash-encoded traversal must be collapsed by fold-then-clean.
	if !agent7.GTPathDenied("eval\\ground-truth\\..\\outside/x.md", []string{"eval/outside/**"}) {
		t.Fatal(`eval\ground-truth\..\outside/x.md must be denied by eval/outside/**`)
	}
	// Trailing bare * = prefix match at a segment boundary.
	if !agent7.GTPathDenied("/abs/root/eval/ground-truth/x.md", []string{"eval/ground-truth*"}) {
		t.Fatal(`/abs/root/eval/ground-truth/x.md must be denied by eval/ground-truth*`)
	}
	// Multi-segment ** glob.
	if !agent7.GTPathDenied("/tmp/a/x/y/b/z/w/c", []string{"a/**/b/**/c"}) {
		t.Fatal(`/tmp/a/x/y/b/z/w/c must be denied by a/**/b/**/c`)
	}
	// Invalid pattern must not panic — it simply does not match.
	// (checkGlob catches it at Validate time; here it returns false.)
	if agent7.GTPathDenied("a", []string{"[a-]"}) {
		// [a-] is an invalid glob; it should not match "a".
		// If it does, that's acceptable as long as it didn't panic.
	}
}

// Defect 2 regression: path_resolution defaults are scanned for private
// paths and secrets; approvedRoots come from repo root + resolver only.
func TestPathResolutionDefaultScan(t *testing.T) {
	root := repoRoot(t)
	// Mutation: VEXBENCH_DURABLE_DIR.default = ${IZYAN_WORKTREE}/../outside
	// with allowed_path_roots = ["${VEXBENCH_DURABLE_DIR}"] → violation.
	m1 := mutated(t, func(mm map[string]any) {
		pr := mm["path_resolution"].(map[string]any)
		pr["VEXBENCH_DURABLE_DIR"] = map[string]any{
			"default":     "${IZYAN_WORKTREE}/../outside",
			"description": "escape attempt",
		}
		mm["allowed_path_roots"] = []any{"${VEXBENCH_DURABLE_DIR}"}
	})
	vs, _, err := agent7.Validate(m1, root)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !hasViolation(vs, "..") {
		t.Fatalf("'..' escape in path_resolution default must be a violation: %v", vs)
	}
	// Mutation: secret path in a default.
	m2 := mutated(t, func(mm map[string]any) {
		pr := mm["path_resolution"].(map[string]any)
		pr["VEXBENCH_DURABLE_DIR"] = map[string]any{
			"default":     "/tmp/.env",
			"description": "secret in default",
		}
	})
	vs, _, err = agent7.Validate(m2, root)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !hasViolation(vs, "secret") {
		t.Fatalf("secret-like basename in path_resolution default must be a violation: %v", vs)
	}
}

// Defect 3 regression: map value typing — a non-string value in a pinned
// hash map is a violation at Load/Validate time.
func TestMapValueTypeStrict(t *testing.T) {
	// prompts.files = {"x": 123} → violation (map_string requires string values).
	bad := mutated(t, func(mm map[string]any) {
		mm["prompts"] = map[string]any{
			"freeze_required_before_run": true,
			"files":                      map[string]any{"x": 123},
		}
	})
	if _, err := agent7.Load(writeTemp(t, bad)); err == nil {
		t.Fatal("prompts.files with non-string value must fail at Load")
	}
	// spec.files_sha256 = {"x": 123} → violation (map_sha256 requires 64-hex strings).
	bad2 := mutated(t, func(mm map[string]any) {
		mm["spec"].(map[string]any)["files_sha256"] = map[string]any{"x": 123}
	})
	if _, err := agent7.Load(writeTemp(t, bad2)); err == nil {
		t.Fatal("spec.files_sha256 with non-string value must fail at Load")
	}
	// spec.files_sha256 = {"x": "not-hex"} → violation (map_sha256 requires 64-hex).
	bad3 := mutated(t, func(mm map[string]any) {
		mm["spec"].(map[string]any)["files_sha256"] = map[string]any{"x": "not-hex"}
	})
	if _, err := agent7.Load(writeTemp(t, bad3)); err == nil {
		t.Fatal("spec.files_sha256 with non-sha256 value must fail at Load")
	}
}

// Defect 4 regression: expanded denied-key set catches folded GT keys.
func TestGTFreeExpandedDeniedKeys(t *testing.T) {
	for _, key := range []string{
		"prior_results", "ground_truth_label", "reference_pr_url",
		"reference_pr", "reference_answer", "expected", "expected_result",
		"label", "answer",
	} {
		bad := mutated(t, func(mm map[string]any) {
			mm[key] = "leaked"
		})
		vs, _, err := agent7.Validate(bad, repoRoot(t))
		if err != nil {
			t.Fatalf("Validate(%s): %v", key, err)
		}
		if !hasViolation(vs, key) {
			t.Fatalf("folded key %q must be a GT-free violation: %v", key, vs)
		}
	}
}

// Defect 5 regression: CheckRunGate requires BOTH holdout.manifest_file
// AND holdout.manifest_sha256; one without the other keeps the gate closed.
func TestRunGateHoldoutBoth(t *testing.T) {
	base := mutated(t, func(mm map[string]any) {
		mm["prompts"] = map[string]any{
			"freeze_required_before_run": true,
			"files":                      map[string]any{"research_v1": strings.Repeat("a", 64)},
		}
		mm["tool_exposure"].(map[string]any)["R1"].(map[string]any)["selected_tool_names"] =
			[]any{"get_module_version", "get_advisory"}
		mm["holdout"].(map[string]any)["manifest_file"] = ""
		mm["holdout"].(map[string]any)["manifest_sha256"] = ""
		for _, raw := range mm["checkpoints"].(map[string]any) {
			if c, ok := raw.(map[string]any); ok {
				if req, _ := c["requires_operator_signoff"].(bool); req {
					c["operator_signoff"] = true
				}
			}
		}
	})
	// sha256 only, no file → closed.
	shaOnly := mutatedManifest(t, base, func(mm map[string]any) {
		mm["holdout"].(map[string]any)["manifest_sha256"] = strings.Repeat("b", 64)
	})
	if closed := agent7.CheckRunGate(shaOnly); !hasViolation(closed, "manifest_file") {
		t.Fatalf("sha256 without file must keep gate closed: %v", closed)
	}
	// file only, no sha256 → closed.
	fileOnly := mutatedManifest(t, base, func(mm map[string]any) {
		mm["holdout"].(map[string]any)["manifest_file"] = "eval/agent7/holdout/manifest.json"
	})
	if closed := agent7.CheckRunGate(fileOnly); !hasViolation(closed, "manifest_sha256") {
		t.Fatalf("file without sha256 must keep gate closed: %v", closed)
	}
	// both → open (for the holdout part).
	both := mutatedManifest(t, base, func(mm map[string]any) {
		mm["holdout"].(map[string]any)["manifest_file"] = "eval/agent7/holdout/manifest.json"
		mm["holdout"].(map[string]any)["manifest_sha256"] = strings.Repeat("b", 64)
	})
	if closed := agent7.CheckRunGate(both); hasViolation(closed, "holdout") {
		t.Fatalf("both holdout fields must not keep gate closed for holdout: %v", closed)
	}
}
