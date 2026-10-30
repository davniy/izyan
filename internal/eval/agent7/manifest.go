// Package agent7 is the PR-0 control plane for the A0–A10 agent-driven
// evidence-assessment lane (plan
// docs/dev/plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md,
// spec docs/dev/specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md).
//
// It loads and validates the frozen experiment manifest
// (eval/agent7/freeze/manifest.json, schema agent7-manifest/1), renders the
// agent-visible projection of a task record (ground truth never crosses the
// boundary) and classifies per-attempt outcomes. It is a pure library: no
// network, no exec, and no import of the analyzer verdict path
// (internal/{evaluator,states,workflow}). PR-0 changes no izyan analyze
// behaviour; run roots, baselines, arms, scoring and decisions dirs are
// created only by the PRs that fill them (plan §7: no empty scaffolding).
//
// Threat model: the attempt container sees only the product snapshot; the
// izyan repo and every GT carrier are never mounted. gt_paths_denied is the
// policy list the future tool broker must enforce inside the sandbox — the
// manifest itself is not the isolation boundary.
package agent7

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ManifestSchema is the frozen manifest schema id.
const ManifestSchema = "agent7-manifest/1"

// ScorerVersion identifies the frozen scorer contract (the code in this
// package). It is pinned in the manifest so arm outputs are comparable.
const ScorerVersion = "agent7-scorer/1"

// ExperimentID is the A-series experiment id; smoke runs carry
// ExperimentSmoke.
const (
	ExperimentID    = "agent7"
	ExperimentSmoke = "agent7-smoke"
)

// ExpectedDatasetSHA256 pins the development dataset (plan §A1): the same
// 30-task Go VEX-Bench JSONL used by Tasks 4–6.
const ExpectedDatasetSHA256 = "60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3"

// Outcome classes (plan §0.5, spec §9.2): distinct terminal classes, never
// merged into each other and never into a safe verdict.
const (
	OutcomeOK              = "OK"
	OutcomeFailed          = "FAILED"
	OutcomeInfraError      = "INFRA_ERROR"
	OutcomeInvalidFormat   = "INVALID_FORMAT"
	OutcomeAbstain         = "ABSTAIN"
	OutcomeProviderRefused = "PROVIDER_REFUSED"
)

// OutcomeClasses is the canonical, closed outcome class list frozen in the
// manifest.
var OutcomeClasses = []string{
	OutcomeOK, OutcomeFailed, OutcomeInfraError,
	OutcomeInvalidFormat, OutcomeAbstain, OutcomeProviderRefused,
}

// agentVisibleKeys is the complete allowlist of task-record keys that may
// cross the agent boundary. Every allowlisted value must be a scalar
// string — anything else is rejected.
var agentVisibleKeys = map[string]bool{
	"task_id":    true,
	"cve_id":     true,
	"repo_url":   true,
	"commit_sha": true,
}

// gtDeniedKeys is the normalized form of the denied GT-class keys. Keys are
// folded: lowercased with '_', '-' and ' ' removed, so "groundTruth",
// "GROUND_TRUTH", "Ground_Truth" and "referencePR" are all denied.
var gtDeniedKeys = map[string]bool{
	"groundtruth":         true,
	"groundtruthcategory": true,
	"reference":           true,
	"referencepr":         true,
	"prurl":               true,
	"expect":              true,
	"expected":            true,
	"expectedresult":      true,
	"hidden":              true,
}

// foldKey normalizes a key for GT-denial matching: case-folded and
// separator-folded so camelCase, UPPER_SNAKE and mixed spellings of a
// denied key cannot slip past the boundary.
func foldKey(k string) string {
	k = strings.ToLower(k)
	k = strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == ' ' {
			return -1
		}
		return r
	}, k)
	return k
}

// gtFreeManifestDeniedKeys are folded key spellings that must not appear
// anywhere in the committed manifest — the manifest is shared and must be
// GT-free (per-case labels, expectations and references stay controller-
// side data, never pins).
var gtFreeManifestDeniedKeys = map[string]bool{
	"gtsafecaseids":        true,
	"gtexploitablecaseids": true,
	"caseclasses":          true,
	"groundtruth":          true,
	"groundtruthcategory":  true,
	"groundtruthlabel":     true,
	"expect":               true,
	"expected":             true,
	"expectedresult":       true,
	"reference":            true,
	"referencepr":          true,
	"referenceprurl":       true,
	"referenceanswer":      true,
	"priorresults":         true,
	"label":                true,
	"answer":               true,
}

// gtFreeManifestAllowKeys are manifest keys whose names look GT-class but
// are allowed because they are policy text/paths, not case labels.
var gtFreeManifestAllowKeys = map[string]bool{
	"gt_policy":       true,
	"gt_paths_denied": true,
	"gt_class_counts": true,
	"gt_safe_count":   true,
}

// requiredGTProbes are repo-relative paths the manifest's gt_paths_denied
// list must provably deny (Validate fails closed otherwise). They cover
// every in-repo GT label carrier; the external tasks file is checked
// separately via its resolved path.
var requiredGTProbes = []string{
	"eval/ground-truth.md",
	"eval/ground-truth/real-yaml-http.md",
	"eval/ground-truth/real-ssh-callback.md",
	"eval/corpus.json",
	"eval/corpus-real.json",
	"eval/corpus-reviewed.json",
	"eval/live-corpus.json",
}

// secretNameMarkers flag basenames and fragments that must never appear
// inside a committed manifest (credentials/env material). Matching is
// case-insensitive on path basenames so "API_KEY", "Id_Rsa" and
// ".env.prod" are all caught.
var secretNameMarkers = []string{
	".env", "id_rsa", "id_ed25519", "credentials", "password",
	"token", "api_key", "secret", ".npmrc", ".aws", ".pem",
	".git-credentials",
}

// pathVarRe matches ${VAR} placeholders.
var pathVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// sha256Re is the strict 64-hex digest form required for pinned hashes.
var sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// PathVar describes one manifest path placeholder: its optional default
// and its resolved value. No operator-local absolute path may be
// committed as a default — resolution is env-first, and the only
// code-level fallback is IZYAN_WORKTREE → the repository root.
type PathVar struct {
	Name     string
	EnvValue string // ${VAR} from the environment, "" when unset
	Default  string // manifest path_resolution.<var>.default, "" = no default
}

// Resolved returns the effective path: env first, then default. An
// unresolved ${...} tail is treated as unset (it can never be a usable
// absolute path).
func (v PathVar) Resolved() string {
	r := v.EnvValue
	if r == "" {
		r = v.Default
	}
	if strings.Contains(r, "${") {
		return ""
	}
	return r
}

// Set reports whether the variable resolves to a concrete path.
func (v PathVar) Set() bool { return v.Resolved() != "" }

// ResolvePathVars reads path_resolution from the manifest and overlays
// the process environment. Semantics (frozen):
//
//   - IZYAN_WORKTREE falls back to repoRoot — always resolvable;
//   - VEXBENCH_* carry NO committed default: VEXBENCH_HARNESS_DIR and
//     VEXBENCH_REPOS_DIR resolve only from their own env or by
//     derivation from a set VEXBENCH_DURABLE_DIR;
//   - every other variable resolves from env or its recorded default;
//     when nothing resolves, dependent checks must skip explicitly.
func ResolvePathVars(m Manifest, repoRoot string) map[string]PathVar {
	out := map[string]PathVar{}
	pr, _ := m["path_resolution"].(map[string]any)
	for name, raw := range pr {
		def := ""
		if d, ok := raw.(map[string]any); ok {
			if s, ok := d["default"].(string); ok {
				def = s
			}
		} else if s, ok := raw.(string); ok {
			def = s
		}
		out[name] = PathVar{Name: name, Default: def, EnvValue: os.Getenv(name)}
	}
	// Declared-but-absent variables still resolve from the environment.
	for _, name := range []string{
		"IZYAN_WORKTREE", "IZYAN_MASTER_WORKTREE",
		"VEXBENCH_DURABLE_DIR", "VEXBENCH_HARNESS_DIR", "VEXBENCH_REPOS_DIR",
	} {
		if _, ok := out[name]; !ok {
			out[name] = PathVar{Name: name, EnvValue: os.Getenv(name)}
		}
	}
	// IZYAN_WORKTREE's only code-level fallback: the repository root the
	// caller passed — the worktree in use.
	if v := out["IZYAN_WORKTREE"]; v.EnvValue == "" && v.Default == "" {
		v.Default = filepath.Clean(repoRoot)
		out["IZYAN_WORKTREE"] = v
	}
	// Second pass: expand ${VAR} references inside defaults (e.g.
	// VEXBENCH_HARNESS_DIR may be derived as
	// ${VEXBENCH_DURABLE_DIR}/agent-ctl — but only when DURABLE is set).
	// Two passes are enough for the declared nesting depth.
	for range 2 {
		for name, v := range out {
			if v.EnvValue == "" && strings.Contains(v.Default, "${") {
				v.Default = expandVars(v.Default, out)
				out[name] = v
			}
		}
	}
	return out
}

// expandVars substitutes ${VAR} in a path template. Unset variables are
// left verbatim (they can never be an absolute path then, so the
// private-path scan treats them as policy text, not a location).
func expandVars(s string, vars map[string]PathVar) string {
	return pathVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := pathVarRe.FindStringSubmatch(m)[1]
		if v, ok := vars[name]; ok && v.Set() {
			return v.Resolved()
		}
		return m
	})
}

// ResolvedPath expands ${VAR} placeholders in a manifest path field.
// Unset variables stay verbatim — the caller decides whether the
// resolved path is usable (it is not, when "${" remains).
func ResolvedPath(m Manifest, repoRoot, dotted string) string {
	return expandVars(m.GetString(dotted), ResolvePathVars(m, repoRoot))
}

// Manifest is the frozen manifest kept as a generic map: PR-0 freezes the
// shape, not a Go struct, so later A-tasks may extend it without breaking
// the loader. Accessors below read through the dotted-path convention.
type Manifest map[string]any

// requiredField describes one required dotted path plus the JSON type it
// must carry. A missing field, an empty value or a wrong type are all
// fail-closed violations.
type requiredField struct {
	path string
	typ  string // "string" | "strings" | "stringmap" | "number" | "bool" | "object" | "map_or_empty" | "any"
}

// requiredFields is the complete contract: every field the experiment
// needs must exist AND carry the expected shape.
var requiredFields = []requiredField{
	{"schema", "string"}, {"experiment_id", "string"}, {"frozen_at_utc", "string"},
	{"goal", "any"}, {"implementation_language", "string"},
	{"freeze_status.state", "string"}, {"freeze_status.pending_pins", "strings"},
	{"run_gate", "object"},
	{"spec.files_sha256", "map_sha256"}, {"spec.plan_sha256", "map_sha256"},
	{"freeze.files_sha256", "map_sha256"}, {"controller.files_sha256", "map_sha256"},
	{"controller.package", "string"},
	{"izyan_base.worktree", "string"}, {"izyan_base.branch", "string"},
	{"izyan_base.commit", "string"},
	{"harness.dir", "string"}, {"harness.commit", "string"},
	{"harness.dirty_files", "strings"},
	{"harness.task6_patch_file", "string"}, {"harness.task6_patch_sha256", "string"},
	{"images", "object"},
	{"toolchain.go", "string"}, {"toolchain.opencode", "string"},
	{"model.id", "string"}, {"model.provider", "string"},
	{"model.provider_model_id", "string"},
	{"prompts.freeze_required_before_run", "bool"},
	{"prompts.files", "map_string"}, {"prompts.arm_prompts", "map_string"},
	{"environment.e6", "object"}, {"environment.e6.status", "string"},
	{"dataset.tasks_file", "string"}, {"dataset.tasks_sha256", "string"},
	{"dataset.task_ids", "strings"}, {"dataset.repos_dir", "string"},
	{"dataset.acquisition_sha256", "string"},
	{"dataset.snapshot_hashes", "map_string"},
	{"attempt_policy.timeout_seconds", "number"},
	{"attempt_policy.repeats", "number"},
	{"attempt_policy.parallel", "number"},
	{"attempt_policy.retries", "number"},
	{"attempt_policy.attempt_key", "string"},
	{"arms", "object"}, {"tool_exposure", "object"},
	{"outcomes.classes", "strings"}, {"outcomes.scorer_version", "string"},
	{"outcomes.official_categories", "strings"},
	{"smoke.selection_rule", "string"},
	{"gt_policy", "string"}, {"gt_paths_denied", "strings"},
	{"holdout.selection_protocol", "string"},
	{"checkpoints", "object"}, {"attribution", "object"},
	{"path_resolution", "object"},
	{"allowed_path_roots", "strings"},
	{"private_path_patterns", "strings"},
	{"limitations", "strings"},
}

// Load parses a manifest file and fails closed: unreadable file, invalid
// JSON, wrong schema and any missing/mistyped required field are errors,
// never silently tolerated.
func Load(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest %s: invalid JSON: %w", path, err)
	}
	if m.GetString("schema") != ManifestSchema {
		return nil, fmt.Errorf("manifest %s: schema %q != %q",
			path, m.GetString("schema"), ManifestSchema)
	}
	if missing := m.MissingFields(); len(missing) > 0 {
		return nil, fmt.Errorf("manifest %s: missing or mistyped required fields: %s",
			path, strings.Join(missing, ", "))
	}
	return m, nil
}

// MissingFields lists required dotted paths that are absent, empty or of
// the wrong JSON type.
func (m Manifest) MissingFields() []string {
	var out []string
	for _, f := range requiredFields {
		v, ok := m.get(f.path)
		if !ok {
			out = append(out, f.path+" (missing)")
			continue
		}
		if !checkType(v, f.typ) {
			out = append(out, f.path+" (wrong type, want "+f.typ+")")
		}
	}
	return out
}

func checkType(v any, typ string) bool {
	if v == nil {
		return false
	}
	switch typ {
	case "any":
		return !isEmptyValue(v)
	case "string":
		s, ok := v.(string)
		return ok && s != ""
	case "strings":
		l, ok := v.([]any)
		if !ok {
			return false
		}
		for _, e := range l {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return len(l) > 0
	case "stringmap":
		d, ok := v.(map[string]any)
		if !ok || len(d) == 0 {
			return false
		}
		for _, e := range d {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	case "map_sha256":
		d, ok := v.(map[string]any)
		if !ok || len(d) == 0 {
			return false
		}
		for _, e := range d {
			s, ok := e.(string)
			if !ok || !sha256Re.MatchString(s) {
				return false
			}
		}
		return true
	case "map_string":
		d, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for _, e := range d {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	case "number":
		_, ok := v.(float64)
		return ok
	case "bool":
		_, ok := v.(bool)
		return ok
	case "object":
		d, ok := v.(map[string]any)
		return ok && len(d) > 0
	case "map_or_empty":
		_, ok := v.(map[string]any)
		return ok
	}
	return false
}

func isEmptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func (m Manifest) get(dotted string) (any, bool) {
	var node any = map[string]any(m)
	for _, part := range strings.Split(dotted, ".") {
		d, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node, ok = d[part]
		if !ok {
			return nil, false
		}
	}
	return node, true
}

// GetString returns the string at a dotted path ("" when absent/non-string).
func (m Manifest) GetString(dotted string) string {
	if v, ok := m.get(dotted); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetFloat returns the numeric value at a dotted path (0 when absent).
func (m Manifest) GetFloat(dotted string) float64 {
	if v, ok := m.get(dotted); ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}

// GetStringSlice returns the string list at a dotted path (nil when absent).
func (m Manifest) GetStringSlice(dotted string) []string {
	v, ok := m.get(dotted)
	if !ok {
		return nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// GetStringMap returns the string→string map at a dotted path (nil when
// absent). Non-string values are skipped.
func (m Manifest) GetStringMap(dotted string) map[string]string {
	v, ok := m.get(dotted)
	if !ok {
		return nil
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(d))
	for k, e := range d {
		if s, ok := e.(string); ok {
			out[k] = s
		}
	}
	return out
}

// SHA256File returns the hex sha256 of a file's bytes.
func SHA256File(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// approvedRoots builds the code-level set of roots a committed manifest is
// allowed to reference: the repository root plus the resolved
// ${VEXBENCH_*} variables. The manifest's allowed_path_roots must be a
// subset of this set — it is policy, not an authority grant.
func approvedRoots(repoRoot string, vars map[string]PathVar) []string {
	set := map[string]bool{filepath.Clean(repoRoot): true}
	out := []string{filepath.Clean(repoRoot)}
	for _, name := range []string{"VEXBENCH_DURABLE_DIR", "VEXBENCH_HARNESS_DIR", "VEXBENCH_REPOS_DIR"} {
		if v, ok := vars[name]; ok && v.Set() {
			p := filepath.Clean(v.Resolved())
			if !set[p] {
				set[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// Validate runs every check that can be performed without running the
// experiment; it returns violations (empty = clean) and whether the
// external tasks file was resolved. When datasetPresent=false the
// dataset-pin check did not run — callers/tests must skip explicitly,
// never assume.
//
// Checks: every required field is present and correctly typed; pinned file
// hashes match real bytes (including prompts.files, which maps each
// committed prompt artifact to its sha256); dataset pin (hash + all 30
// task ids, when the file resolves); every required GT probe is denied by
// gt_paths_denied and every denied entry is a valid glob; the manifest is
// GT-free (no per-case labels/expectations/references anywhere); every
// path is inside the code-level approved roots or a declared ${VAR}; arms
// repeats consistent with attempt_policy unless the deviation is recorded
// in limitations.
func Validate(m Manifest, repoRoot string) (violations []string, datasetPresent bool, err error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, false, fmt.Errorf("repo root: %w", err)
	}
	root = filepath.Clean(root)
	vars := ResolvePathVars(m, root)
	violations = append(violations, m.MissingFields()...)

	// 1. Pinned file hashes must match real bytes (fail closed). A
	//    non-map group is a violation, not a skip.
	for _, group := range []string{
		"spec.files_sha256", "spec.plan_sha256",
		"freeze.files_sha256", "controller.files_sha256",
		"prompts.files",
	} {
		v, ok := m.get(group)
		if !ok {
			continue // already reported as missing
		}
		d, ok := v.(map[string]any)
		if !ok {
			violations = append(violations, group+": not a string map — cannot verify pins")
			continue
		}
		for rel, rawWant := range d {
			want, ok := rawWant.(string)
			if !ok || !sha256Re.MatchString(want) {
				violations = append(violations,
					fmt.Sprintf("%s[%q]: pin is not a 64-hex sha256", group, rel))
				continue
			}
			got, herr := SHA256File(filepath.Join(root, filepath.FromSlash(rel)))
			switch {
			case herr != nil:
				violations = append(violations,
					fmt.Sprintf("%s[%q]: unreadable pinned file: %v", group, rel, herr))
			case !strings.EqualFold(got, want):
				violations = append(violations,
					fmt.Sprintf("%s[%q]: sha256 mismatch (got %s)", group, rel, got))
			}
		}
	}

	// 2. Dataset pin — only when the external tasks file resolves.
	tasksTemplate := m.GetString("dataset.tasks_file")
	tasksFile := expandVars(tasksTemplate, vars)
	if filepath.IsAbs(tasksFile) {
		if _, statErr := os.Stat(tasksFile); statErr == nil {
			datasetPresent = true
			if sum, herr := SHA256File(tasksFile); herr != nil {
				violations = append(violations, fmt.Sprintf("dataset.tasks_file unreadable: %v", herr))
			} else if !strings.EqualFold(sum, m.GetString("dataset.tasks_sha256")) {
				violations = append(violations,
					fmt.Sprintf("dataset.tasks_sha256 mismatch: file hashes to %s", sum))
			}
			tasks, terr := LoadTaskRecords(tasksFile)
			if terr != nil {
				violations = append(violations, fmt.Sprintf("dataset.tasks_file unparsable: %v", terr))
			} else {
				want := m.GetStringSlice("dataset.task_ids")
				if len(tasks) != len(want) {
					violations = append(violations,
						fmt.Sprintf("dataset task count %d != manifest %d", len(tasks), len(want)))
				}
				pinned := make(map[string]bool, len(want))
				for _, id := range want {
					pinned[id] = true
				}
				for i, t := range tasks {
					if i < len(want) && t.TaskID != want[i] {
						violations = append(violations,
							fmt.Sprintf("dataset task_ids[%d] = %q, manifest pins %q", i, t.TaskID, want[i]))
					}
					if !pinned[t.TaskID] {
						violations = append(violations,
							fmt.Sprintf("dataset task %q not in manifest task_ids", t.TaskID))
					}
				}
			}
		}
	}

	// 3. GT path denial: every required probe must be denied by a valid
	//    glob in gt_paths_denied; an invalid glob is a violation, never
	//    silently ignored.
	denied := m.GetStringSlice("gt_paths_denied")
	for _, entry := range denied {
		if err := checkGlob(entry); err != nil {
			violations = append(violations,
				fmt.Sprintf("gt_paths_denied entry %q: invalid glob: %v", entry, err))
		}
	}
	for _, probe := range requiredGTProbes {
		if !GTPathDenied(probe, denied) {
			violations = append(violations,
				fmt.Sprintf("gt_paths_denied does not deny required GT path %q", probe))
		}
	}
	// The external tasks-file template must be denied under its resolved
	// form; the relative-glob form also covers it.
	if filepath.IsAbs(tasksFile) && !GTPathDenied(tasksFile, GTPathsDeniedResolved(m, root)) {
		violations = append(violations,
			fmt.Sprintf("gt_paths_denied does not deny the resolved external GT carrier %q", tasksFile))
	}

	// 4. GT-free manifest invariant: no per-case labels, expectations or
	//    references anywhere in the committed manifest.
	violations = append(violations, gtFreeViolations(m)...)

	// 5. Private-path / secret scan against the code-level approved set.
	approved := approvedRoots(root, vars)
	violations = append(violations, privatePathViolations(m, approved, vars)...)

	// 6. Arm repeats consistent with attempt_policy, else the deviation
	//    must be recorded in limitations (Task-6 precedent).
	policy := m.GetFloat("attempt_policy.repeats")
	arms, _ := m["arms"].(map[string]any)
	limText := strings.ToLower(strings.Join(m.GetStringSlice("limitations"), "\n"))
	for name, raw := range arms {
		a, ok := raw.(map[string]any)
		if !ok {
			violations = append(violations, fmt.Sprintf("arms.%s: not an object", name))
			continue
		}
		r, _ := a["repeats"].(float64)
		if r == policy {
			continue
		}
		lname := strings.ToLower(name)
		if !(strings.Contains(limText, lname) && strings.Contains(limText, "repeats")) {
			violations = append(violations,
				fmt.Sprintf("arms.%s.repeats %v != attempt_policy.repeats %v and no limitations entry records the deviation",
					name, r, policy))
		}
	}
	return violations, datasetPresent, nil
}

// gtFreeViolations walks the whole manifest for key names that carry
// per-case GT semantics (folded so spelling variants cannot hide them).
// Policy fields in gtFreeManifestAllowKeys are exempt — they are paths or
// prose rules, not labels.
func gtFreeViolations(m Manifest) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(v any, where string)
	walk = func(v any, where string) {
		switch t := v.(type) {
		case map[string]any:
			for k, e := range t {
				fk := foldKey(k)
				if gtFreeManifestDeniedKeys[fk] && !gtFreeManifestAllowKeys[k] {
					p := where + "." + k
					if !seen[p] {
						seen[p] = true
						out = append(out,
							fmt.Sprintf("%s: per-case GT/reference key must not be committed in the manifest", p))
					}
				}
				walk(e, where+"."+k)
			}
		case []any:
			for i, e := range t {
				walk(e, fmt.Sprintf("%s[%d]", where, i))
			}
		}
	}
	walk(map[string]any(m), "$")
	sort.Strings(out)
	return out
}

// privatePathViolations enforces the private-path and secret contract:
//
//   - allowed_path_roots must be a subset of the code-level approved roots
//     (repo root + resolved ${VEXBENCH_*} vars) — it may only ever narrow;
//   - every concrete absolute path in the manifest must lie under an
//     approved root (or equal ${VA_PRODUCT_REPO}-class placeholders);
//   - path basenames must not match secret markers, case-insensitively;
//   - '..' escapes in approved paths are rejected.
func privatePathViolations(m Manifest, approved []string, vars map[string]PathVar) []string {
	var out []string
	seen := map[string]bool{}
	report := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			out = append(out, msg)
		}
	}

	approvedSet := map[string]bool{}
	for _, r := range approved {
		approvedSet[filepath.Clean(r)] = true
	}
	underApproved := func(p string) bool {
		c := filepath.Clean(p)
		if approvedSet[c] {
			return true
		}
		for r := range approvedSet {
			if strings.HasPrefix(c, r+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}

	// allowed_path_roots must be a subset of the approved set after
	// variable expansion and cleaning; '..' escapes are rejected.
	for _, entry := range m.GetStringSlice("allowed_path_roots") {
		if entry == "${VA_PRODUCT_REPO}" {
			continue
		}
		resolved := expandVars(entry, vars)
		if strings.Contains(resolved, "${") {
			continue // unresolved placeholder: policy, not a path
		}
		c := filepath.Clean(resolved)
		if strings.Contains(entry, "..") || !underApproved(c) {
			report(fmt.Sprintf("allowed_path_roots entry %q is outside the approved root set", entry))
		}
	}

	var walk func(v any, where string)
	walk = func(v any, where string) {
		// Skip rulebook fields that are policy, not content.
		switch where {
		case "$.private_path_patterns":
			return
		}
		switch t := v.(type) {
		case map[string]any:
			// path_resolution defaults are scanned (descriptions are
			// policy text and skipped); every resolved default must be
			// empty or under an approved root, with no ".." escape.
			if where == "$.path_resolution" {
				for varName, vv := range t {
					vm, ok := vv.(map[string]any)
					if !ok {
						continue
					}
					def, _ := vm["default"].(string)
					if def == "" {
						continue
					}
					resolved := expandVars(def, vars)
					if strings.Contains(resolved, "..") {
						report(fmt.Sprintf("path_resolution.%s.default: '..' escape in %q", varName, def))
						continue
					}
					if strings.Contains(resolved, "${") {
						continue // unresolved placeholder: policy, not a path
					}
					if filepath.IsAbs(resolved) && !underApproved(resolved) {
						report(fmt.Sprintf("path_resolution.%s.default: absolute path outside the approved root set: %q", varName, resolved))
					}
					// Secret-basename scan on the resolved default.
					if !strings.Contains(resolved, " ") {
						base := strings.ToLower(resolved)
						for _, sep := range []string{"/", "\\"} {
							if i := strings.LastIndex(base, sep); i >= 0 {
								base = base[i+1:]
							}
						}
						for _, marker := range secretNameMarkers {
							if strings.Contains(base, marker) {
								report(fmt.Sprintf("path_resolution.%s.default: secret-like basename %q in %q", varName, marker, resolved))
							}
						}
					}
				}
				// Do not descend into path_resolution further —
				// defaults are handled above, descriptions are prose.
				return
			}
			for k, e := range t {
				walk(e, where+"."+k)
			}
		case []any:
			for i, e := range t {
				walk(e, fmt.Sprintf("%s[%d]", where, i))
			}
		case string:
			// Secret markers: basename scan, separator- and
			// case-insensitive. A bare token (no separators) is a
			// filename; a string containing a space is prose, never a
			// basename, and is skipped.
			if !strings.Contains(t, " ") {
				base := strings.ToLower(t)
				for _, sep := range []string{"/", "\\"} {
					if i := strings.LastIndex(base, sep); i >= 0 {
						base = base[i+1:]
					}
				}
				for _, marker := range secretNameMarkers {
					if strings.Contains(base, marker) {
						report(fmt.Sprintf("%s: secret-like basename %q in %q", where, marker, t))
					}
				}
			}
			for _, p := range m.GetStringSlice("private_path_patterns") {
				if p != "" && strings.Contains(t, p) {
					report(fmt.Sprintf("%s: matches private_path_patterns %q: %q", where, p, t))
				}
			}
			resolved := expandVars(t, vars)
			if !filepath.IsAbs(resolved) {
				return
			}
			if strings.Contains(resolved, ".."+string(filepath.Separator)) {
				report(fmt.Sprintf("%s: '..' escape in path %q", where, t))
				return
			}
			if !underApproved(resolved) {
				report(fmt.Sprintf("%s: absolute path outside the approved root set: %q", where, resolved))
			}
		}
	}
	walk(map[string]any(m), "$")
	sort.Strings(out)
	return out
}

// checkGlob validates a gt_paths_denied pattern. Supported syntax: '*',
// '**', '?' and '[...]' classes. An invalid pattern is an error so a
// malformed deny rule can never widen the boundary silently.
func checkGlob(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty pattern")
	}
	// Delegate the bracket/escape syntax check to path.Match on a probe;
	// '**' is an extension so it is pre-validated structurally.
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[':
			j := i + 1
			if j < len(pattern) && pattern[j] == '^' {
				j++
			}
			for ; j < len(pattern) && pattern[j] != ']'; j++ {
			}
			if j >= len(pattern) {
				return fmt.Errorf("unterminated character class")
			}
			i = j
		case '\\':
			i++ // skip escaped char
			if i >= len(pattern) {
				return fmt.Errorf("trailing escape")
			}
		}
	}
	return nil
}

// GTPathDenied reports whether candidate is denied by the gt_paths_denied
// list. Normalization folds separators FIRST (so a backslash-encoded
// traversal is collapsed), then cleans. Matching is segment-based:
//   - "**" matches zero or more whole segments;
//   - "*" within a segment is matched by path.Match;
//   - a trailing bare "*" (no "/") is a prefix match at a segment boundary;
//   - a relative pattern also denies an absolute candidate whose tail
//     segments match (suffix alignment).
//
// An invalid pattern (e.g. unterminated character class) is reported via
// checkGlob at Validate time; here it simply does not match. Symlink
// canonicalization is NOT this matcher's job — that is
// internal/readgate's responsibility (readgate.go:26,47); this is a
// normalized string policy check.
func GTPathDenied(candidate string, denied []string) bool {
	cand := normPath(candidate)
	candSegs := splitSegs(cand)
	candRel := strings.TrimPrefix(cand, "/")
	candRelSegs := splitSegs(candRel)
	for _, entry := range denied {
		e := normPath(entry)
		eFold, cFold := strings.ToLower(e), strings.ToLower(cand)
		eRel := strings.TrimPrefix(e, "/")
		// Exact match (absolute or relative form).
		if eFold == cFold || strings.ToLower(eRel) == strings.ToLower(candRel) {
			return true
		}
		eSegs := splitSegs(e)
		eRelSegs := splitSegs(eRel)
		// Try the absolute and relative forms of the pattern against
		// the absolute and relative forms of the candidate, plus every
		// progressively shorter tail of the candidate segments (so a
		// relative glob denies an absolute candidate by suffix).
		for _, pat := range [][]string{eSegs, eRelSegs} {
			if len(pat) == 0 {
				continue
			}
			if segMatch(pat, candSegs) || segMatch(pat, candRelSegs) {
				return true
			}
			for start := 1; start < len(candSegs); start++ {
				if segMatch(pat, candSegs[start:]) {
					return true
				}
			}
		}
	}
	return false
}

// normPath folds backslashes to slashes, cleans, and re-slashes so the
// result is a canonical slash path with no "." or ".." segments.
func normPath(p string) string {
	s := strings.ReplaceAll(p, "\\", "/")
	s = filepath.ToSlash(filepath.Clean(s))
	return s
}

// splitSegs splits a slash path into non-empty segments.
func splitSegs(p string) []string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// segMatch reports whether a segment-glob pattern matches a path's
// segments. "**" matches zero or more segments; "*" and other glob
// characters within a single segment are matched by path.Match.
// An invalid pattern segment returns false (never panics).
func segMatch(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		// "**" matches zero or more segments.
		for i := 0; i <= len(segs); i++ {
			if segMatch(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	// Trailing segment with a glob char (not "**") = prefix match:
	// it matches the first candidate segment by prefix and allows
	// any remaining segments (so "eval/ground-truth*" denies
	// "eval/ground-truth/x.md").
	if len(pat) == 1 && strings.ContainsAny(pat[0], "*?[") {
		ok, err := path.Match(pat[0], segs[0])
		if err != nil {
			return false
		}
		return ok
	}
	ok, err := path.Match(pat[0], segs[0])
	if err != nil {
		return false // invalid pattern segment — not a match, not a panic
	}
	if !ok {
		return false
	}
	return segMatch(pat[1:], segs[1:])
}

// GTPathsDeniedResolved returns gt_paths_denied with ${VAR} placeholders
// expanded through path_resolution (env first, then freeze-time defaults).
// Unset variables stay verbatim — they match nothing concrete, which is
// correct: an unresolvable root cannot hold files.
func GTPathsDeniedResolved(m Manifest, repoRoot string) []string {
	vars := ResolvePathVars(m, repoRoot)
	out := make([]string, 0, len(m.GetStringSlice("gt_paths_denied")))
	for _, e := range m.GetStringSlice("gt_paths_denied") {
		out = append(out, expandVars(e, vars))
	}
	return out
}

// TaskRecord is one control-plane dataset record. GroundTruth and
// GroundTruthCategory stay controller-side; they must never reach the
// agent — use RenderAgentInput.
type TaskRecord struct {
	TaskID              string `json:"task_id"`
	RepoURL             string `json:"repo_url"`
	CommitSHA           string `json:"commit_sha"`
	CVEID               string `json:"cve_id"`
	GroundTruth         string `json:"ground_truth"`          // exploitable|not_exploitable
	GroundTruthCategory string `json:"ground_truth_category"` // vulnerable|code_not_reachable|...
}

// LoadTaskRecords parses a VEX-Bench JSONL tasks file (one object per line).
func LoadTaskRecords(path string) ([]TaskRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open tasks: %w", err)
	}
	var out []TaskRecord
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec TaskRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("tasks %s:%d: %w", path, i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// RenderAgentInput returns the agent-visible projection of a source record:
// exactly the allowlisted identity keys with scalar-string values. It
// fails closed — a denied GT-class key at ANY depth (including inside
// nested maps, slices and map[string]string values, folded for case and
// separators) or a non-scalar value under an allowlisted key is an error,
// never a silent strip.
func RenderAgentInput(record map[string]any) (map[string]any, error) {
	if key, found := findDeniedKey(record, ""); found {
		return nil, fmt.Errorf("agent input contains denied GT-class key %q", key)
	}
	out := make(map[string]any, len(agentVisibleKeys))
	for k, v := range record {
		if !agentVisibleKeys[k] {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("agent input key %q must be a scalar string, got %T", k, v)
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("agent input has no allowlisted identity keys")
	}
	return out, nil
}

// findDeniedKey reports the first denied key reachable anywhere in a
// decoded JSON value (dotted path for diagnostics), folding case and
// separators so spelling variants cannot evade the boundary.
func findDeniedKey(v any, prefix string) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if gtDeniedKeys[foldKey(k)] {
				return p, true
			}
			if sub, found := findDeniedKey(t[k], p); found {
				return sub, true
			}
		}
	case []any:
		for i, e := range t {
			if sub, found := findDeniedKey(e, fmt.Sprintf("%s[%d]", prefix, i)); found {
				return sub, true
			}
		}
	case map[string]string:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if gtDeniedKeys[foldKey(k)] {
				return p, true
			}
		}
	}
	return "", false
}

// armGateReqs describes the arm-scoped run-gate requirements for one arm.
// Arms not listed here have no defined gate and CheckRunGateForArm fails
// closed on them — a new arm may never run on silently assumed rules.
type armGateReqs struct {
	prompt   bool     // LLM arm: prompts.arm_prompts[arm] must pin a 64-hex sha256 (A2/A4)
	toolsR1  bool     // MCP arm: tool_exposure.R1.selected_tool_names must pin 1..5 names (A4)
	signoffs []string // phase checkpoints needing operator_signoff beyond checkpoint_0
}

// armGates is the frozen arm → requirement mapping (E6 sandbox design §0
// option 1, protocol.md "Run gate"):
//
//   - every arm shares the reproducibility/environment pins: scorer version,
//     run_profile memory/parallelism/degraded pins, the E6 sandbox report and
//     checkpoint_0 operator sign-off;
//   - B1/R0 (A2): the arm's prompt-hash pin + checkpoint_a sign-off;
//   - R1/R2 (A4+): prompt pin + the <=5 selected Izyan tool list +
//     checkpoint_b sign-off;
//   - B0/PR1 (deterministic, no prompt): checkpoint_a / checkpoint_c
//     sign-off respectively;
//   - a blind (A9) run of any arm additionally requires the pinned holdout
//     manifest — use CheckRunGateForBlindArm.
var armGates = map[string]armGateReqs{
	"B0":  {signoffs: []string{"checkpoint_a"}},
	"B1":  {prompt: true, signoffs: []string{"checkpoint_a"}},
	"R0":  {prompt: true, signoffs: []string{"checkpoint_a"}},
	"R1":  {prompt: true, toolsR1: true, signoffs: []string{"checkpoint_b"}},
	"R2":  {prompt: true, toolsR1: true, signoffs: []string{"checkpoint_b"}},
	"PR1": {signoffs: []string{"checkpoint_c"}},
}

// manifestMap returns v as a string-keyed map, or nil when it is absent or
// of another shape.
func manifestMap(v any) map[string]any {
	d, _ := v.(map[string]any)
	return d
}

// appendGate appends msg to closed once — identical reasons reported by
// different scopes are emitted a single time.
func appendGate(closed []string, seen map[string]bool, msg string) []string {
	if !seen[msg] {
		seen[msg] = true
		closed = append(closed, msg)
	}
	return closed
}

// checkSharedGatePins verifies the environment and reproducibility pins
// every arm shares (E6 sandbox design §0 option 1): scorer version, the
// run_profile memory ceiling / parallelism bound / degraded-declaration
// pins, the E6 sandbox-probe report pin and checkpoint_0 sign-off.
func checkSharedGatePins(m Manifest, closed []string, seen map[string]bool) []string {
	if m.GetString("outcomes.scorer_version") == "" {
		closed = appendGate(closed, seen, "outcomes.scorer_version is unset")
	}
	for _, f := range []string{
		"run_profile.parallelism_upper_bound",
		"run_profile.mem_limit",
		"run_profile.degraded_declaration",
	} {
		if m.GetString(f) == "" {
			closed = appendGate(closed, seen,
				fmt.Sprintf("%s is unset — the run-profile/reproducibility pin must be declared", f))
		}
	}

	// E6 sandbox-probe report: all three pins must be present — a verified
	// PASS report at a pinned path with a pinned sha256. "ENV_FAIL" reports
	// (e.g. model provider unreachable during a VPN outage) and "FAIL"
	// reports (isolation assertion violated) both keep the gate closed:
	// only status "PASS" opens it.
	e6 := manifestMap(manifestMap(m["environment"])["e6"])
	if m.GetString("environment.e6.report_path") == "" {
		closed = appendGate(closed, seen,
			"environment.e6.report_path is unset — pin the E6 sandbox-probe report")
	}
	if !sha256Re.MatchString(m.GetString("environment.e6.report_sha256")) {
		closed = appendGate(closed, seen,
			"environment.e6.report_sha256 is not a 64-hex sha256 — pin the E6 report bytes hash")
	}
	if e6["status"] != "PASS" {
		closed = appendGate(closed, seen,
			fmt.Sprintf("environment.e6.status is %q — the gate opens only on a PASS report (ENV_FAIL/FAIL/not_verified all close it)",
				e6["status"]))
	}

	// Checkpoint 0 is the universal launch checkpoint — every arm needs it.
	return checkSignoff(m, "checkpoint_0", closed, seen)
}

// checkSignoff requires checkpoints.<name> to carry operator_signoff true;
// a checkpoint absent from the manifest is itself a violation.
func checkSignoff(m Manifest, name string, closed []string, seen map[string]bool) []string {
	cp := manifestMap(manifestMap(m["checkpoints"])[name])
	if cp == nil {
		return appendGate(closed, seen,
			fmt.Sprintf("checkpoints.%s is absent — required sign-off definition missing", name))
	}
	if req, _ := cp["requires_operator_signoff"].(bool); req {
		if done, _ := cp["operator_signoff"].(bool); !done {
			closed = appendGate(closed, seen,
				fmt.Sprintf("checkpoints.%s requires operator sign-off", name))
		}
	}
	return closed
}

// checkR1ToolGate enforces the <=5 selected Izyan tool list pinned by A4.
func checkR1ToolGate(m Manifest, closed []string, seen map[string]bool) []string {
	tools := m.GetStringSlice("tool_exposure.R1.selected_tool_names")
	if len(tools) == 0 {
		closed = appendGate(closed, seen,
			"tool_exposure.R1.selected_tool_names is empty — the <=5 tool subset must be pinned (A4)")
	}
	if len(tools) > 5 {
		closed = appendGate(closed, seen,
			fmt.Sprintf("tool_exposure.R1.selected_tool_names has %d tools; the cap is 5", len(tools)))
	}
	return closed
}

// checkHoldoutGate enforces the A9 holdout pin: BOTH the file path and its
// sha256 must be present; one without the other keeps the gate closed.
func checkHoldoutGate(m Manifest, closed []string, seen map[string]bool) []string {
	holdoutFile := m.GetString("holdout.manifest_file")
	holdoutSHA := m.GetString("holdout.manifest_sha256")
	switch {
	case holdoutFile == "" && holdoutSHA == "":
		closed = appendGate(closed, seen, "holdout manifest is not pinned (required before blind runs, A9)")
	case holdoutFile == "":
		closed = appendGate(closed, seen, "holdout.manifest_sha256 is pinned but holdout.manifest_file is empty")
	case holdoutSHA == "":
		closed = appendGate(closed, seen, "holdout.manifest_file is pinned but holdout.manifest_sha256 is empty")
	}
	return closed
}

// checkArmRunGate evaluates the gate for one scope: an arm plus whether the
// run is blind (A9 holdout). Arm ids are case-insensitive — they are
// normalized to the canonical uppercase id before the armGates /
// arm_prompts lookup; an unknown arm still fails closed.
func checkArmRunGate(m Manifest, arm string, blind bool, closed []string, seen map[string]bool) []string {
	arm = strings.ToUpper(arm)
	req, known := armGates[arm]
	if !known {
		return appendGate(closed, seen,
			fmt.Sprintf("arm %q is not defined in armGates — the run gate fails closed for unknown arms", arm))
	}
	if req.prompt {
		s, ok := m.GetStringMap("prompts.arm_prompts")[arm]
		switch {
		case !ok || s == "":
			closed = appendGate(closed, seen,
				fmt.Sprintf("prompts.arm_prompts[%q] is not pinned — the arm's prompt bytes+sha256 must be pinned before its run (A2/A4)", arm))
		case !sha256Re.MatchString(s):
			closed = appendGate(closed, seen,
				fmt.Sprintf("prompts.arm_prompts[%q] is not a 64-hex sha256", arm))
		}
	}
	if req.toolsR1 {
		closed = checkR1ToolGate(m, closed, seen)
	}
	for _, cp := range req.signoffs {
		closed = checkSignoff(m, cp, closed, seen)
	}
	if blind {
		closed = checkHoldoutGate(m, closed, seen)
	}
	return closed
}

// CheckRunGateForArm reports the pins still missing before a development-
// dataset run of the given arm may start. A non-empty list means the gate
// is CLOSED for that arm — the run is not permitted.
//
// The gate is arm-scoped (E6 sandbox design §0 option 1): every arm shares
// the environment/reproducibility pins — outcomes.scorer_version, the
// run_profile memory-ceiling/parallelism/degraded-declaration pins, the E6
// sandbox-probe report pin (environment.e6) and checkpoint_0 sign-off —
// while per-arm requirements differ:
//
//   - B1/R0 (the A2 comparison) need only their own prompt hash pinned in
//     prompts.arm_prompts plus checkpoint_a sign-off; the R1 tool list and
//     the A9 holdout do NOT close their gate;
//   - R1/R2 additionally need tool_exposure.R1.selected_tool_names (1..5)
//     and checkpoint_b sign-off;
//   - B0/PR1 are deterministic — no prompt — and need the shared pins plus
//     checkpoint_a / checkpoint_c sign-off respectively;
//   - an arm absent from armGates fails closed.
//
// A blind (A9 holdout) run of any arm additionally needs the pinned holdout
// manifest — use CheckRunGateForBlindArm. Arm ids are matched
// case-insensitively ("b1" ≡ "B1"); unknown ids fail closed.
func CheckRunGateForArm(m Manifest, arm string) []string {
	seen := map[string]bool{}
	closed := checkSharedGatePins(m, nil, seen)
	closed = checkArmRunGate(m, arm, false, closed, seen)
	sort.Strings(closed)
	return closed
}

// CheckRunGateForBlindArm is CheckRunGateForArm for a blind (A9 holdout)
// run: identical requirements plus the pinned holdout manifest
// (holdout.manifest_file AND holdout.manifest_sha256).
func CheckRunGateForBlindArm(m Manifest, arm string) []string {
	seen := map[string]bool{}
	closed := checkSharedGatePins(m, nil, seen)
	closed = checkArmRunGate(m, arm, true, closed, seen)
	sort.Strings(closed)
	return closed
}

// CheckRunGate reports the pins still missing before the full A-series run
// matrix may start. A non-empty list means the run gate is CLOSED — runs
// are not permitted. This is the STRICT superset of every arm-scoped gate
// kept for the later phases: it requires, simultaneously, the legacy
// prompts.files pin (every prompt artifact recorded), an arm_prompts entry
// for every prompt-bearing arm, the R1 tool subset, the holdout manifest
// and every checkpoint sign-off — alongside the shared scorer /
// run-profile / E6 pins. Do not use it to judge a single A2-phase arm;
// CheckRunGateForArm is the per-arm gate.
func CheckRunGate(m Manifest) []string {
	var closed []string
	seen := map[string]bool{}

	// Prompts: non-empty files map, every value a strict 64-hex sha256.
	promptFiles := manifestMap(manifestMap(m["prompts"])["files"])
	if len(promptFiles) == 0 {
		closed = appendGate(closed, seen,
			"prompts.files is empty — prompt bytes+sha256 must be pinned before any run (A2)")
	} else {
		for name, v := range promptFiles {
			s, ok := v.(string)
			if !ok || !sha256Re.MatchString(s) {
				closed = appendGate(closed, seen,
					fmt.Sprintf("prompts.files[%q] is not a 64-hex sha256", name))
			}
		}
	}
	if req, _ := manifestMap(m["prompts"])["freeze_required_before_run"].(bool); !req {
		closed = appendGate(closed, seen, "prompts.freeze_required_before_run must be true")
	}

	// Shared environment/reproducibility pins plus every arm requirement
	// at once (arms iterated in a fixed order for deterministic output).
	closed = checkSharedGatePins(m, closed, seen)
	for _, arm := range []string{"B0", "B1", "R0", "R1", "R2", "PR1"} {
		closed = checkArmRunGate(m, arm, false, closed, seen)
	}
	closed = checkHoldoutGate(m, closed, seen)

	// Checkpoint sign-offs: every checkpoint must be signed off.
	if cp, ok := m["checkpoints"].(map[string]any); ok {
		for name, raw := range cp {
			if name == "meta_rule" {
				continue
			}
			c, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if signed, _ := c["requires_operator_signoff"].(bool); signed {
				if done, _ := c["operator_signoff"].(bool); !done {
					closed = appendGate(closed, seen,
						fmt.Sprintf("checkpoints.%s requires operator sign-off", name))
				}
			}
		}
	}
	sort.Strings(closed)
	return closed
}
