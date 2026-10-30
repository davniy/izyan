package agent7_test

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/agent7"
)

// key builds a frozen attempt key (experiment_id, arm, model, task_id,
// run_NNN) per the manifest's attempt_policy.attempt_key.
func key(arm, taskID string, run int) string {
	const model = "qwen3.6-35b"
	return arm + "|" + model + "|" + taskID + "|run_" +
		map[int]string{1: "001", 2: "002", 3: "003", 4: "004"}[run]
}

func okAttempt(arm, taskID string, run int, category string) agent7.AttemptRecord {
	return agent7.AttemptRecord{
		AttemptKey:    key(arm, taskID, run),
		ExperimentID:  agent7.ExperimentID,
		Arm:           arm,
		TaskID:        taskID,
		RunIndex:      run,
		Execution:     "ok",
		OfficialParse: "accepted",
		Category:      category,
	}
}

func infraAttempt(arm, taskID string, run int) agent7.AttemptRecord {
	return agent7.AttemptRecord{
		AttemptKey:    key(arm, taskID, run),
		ExperimentID:  agent7.ExperimentID,
		Arm:           arm,
		TaskID:        taskID,
		RunIndex:      run,
		Execution:     "transport_failure",
		OfficialParse: "no_result",
		FailureReason: "docker_start_failed",
	}
}

// gtSafeIDs returns the GT-safe case set from the real dataset when it
// resolves, else a synthetic fixture — controller-side data, never the
// manifest (the manifest is GT-free by invariant).
func gtSafeIDs(t *testing.T, m agent7.Manifest) []string {
	t.Helper()
	recs := datasetOrFixture(t, m)
	out := []string{}
	for _, r := range recs {
		if r.GroundTruth == "not_exploitable" {
			out = append(out, r.TaskID)
		}
	}
	return out
}

// Brief test 6a / review A3: the smoke block is a selection RULE, not a
// committed case list — 2 safe + 2 exploitable + 1 forced infra failure,
// host-side by GT class; no per-case ids or classes are committed.
func TestSmokeSelectionRule(t *testing.T) {
	m := frozenManifest(t)
	if m.GetString("smoke.selection_rule") == "" {
		t.Fatal("smoke.selection_rule must be pinned")
	}
	rule := m.GetString("smoke.selection_rule")
	if !strings.Contains(strings.ToLower(rule), "infra") {
		t.Fatal("smoke.selection_rule must record the forced infra failure injection")
	}
	quota, _ := m["smoke"].(map[string]any)["class_quota"].(map[string]any)
	if quota["not_exploitable"] != 2.0 || quota["exploitable"] != 2.0 ||
		quota["forced_infra_failure"] != 1.0 {
		t.Fatalf("smoke.class_quota must be 2 safe + 2 exploitable + 1 infra: %v", quota)
	}
	smoke, _ := m["smoke"].(map[string]any)
	if labels, _ := smoke["labels_never_reach_agent"].(bool); !labels {
		t.Fatal("smoke.labels_never_reach_agent must be pinned true")
	}
	// GT hygiene: no committed per-case ids or classes (review A3).
	for _, k := range []string{"case_ids", "case_classes", "case_ids_sha256"} {
		if _, ok := smoke[k]; ok {
			t.Fatalf("smoke.%s must not be committed — selection is a rule, not a label list", k)
		}
	}
}

// When the dataset resolves, the smoke quota is satisfiable: ≥2 safe and
// ≥2 exploitable classes exist in the frozen 30-case dev set.
func TestSmokeQuotaSatisfiable(t *testing.T) {
	m := frozenManifest(t)
	tasksFile := tasksFileOrSkip(t, m)
	recs, err := agent7.LoadTaskRecords(tasksFile)
	if err != nil {
		t.Fatal(err)
	}
	safe, exploit := 0, 0
	for _, r := range recs {
		switch r.GroundTruth {
		case "not_exploitable":
			safe++
		case "exploitable":
			exploit++
		}
	}
	if safe < 2 || exploit < 2 {
		t.Fatalf("frozen dataset cannot satisfy the smoke quota: %d safe %d exploitable", safe, exploit)
	}
}

// Brief test 6b: the forced infra failure classifies as INFRA_ERROR —
// never a safe/negative verdict — is excluded from case-level
// denominators and is reported separately.
func TestInfraFailureClassification(t *testing.T) {
	m := frozenManifest(t)
	out, err := agent7.ClassifyAttempt(infraAttempt("b1", "task-infra", 1))
	if err != nil {
		t.Fatalf("classify infra attempt: %v", err)
	}
	if out != agent7.OutcomeInfraError {
		t.Fatalf("infra attempt must classify INFRA_ERROR, got %s", out)
	}

	s, err := agent7.Aggregate(m, []agent7.AttemptRecord{
		okAttempt("b1", "case-a", 1, "vulnerable"),
		okAttempt("b1", "case-a", 2, "vulnerable"),
		okAttempt("b1", "case-a", 3, "vulnerable"),
		infraAttempt("b1", "case-infra", 1),
		infraAttempt("b1", "case-infra", 2),
		infraAttempt("b1", "case-infra", 3),
	}, nil, nil)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.AttemptCounts[agent7.OutcomeInfraError] != 3 {
		t.Fatalf("attempt-level must report 3 INFRA_ERROR, got %v", s.AttemptCounts)
	}
	if s.CaseTotal != 1 || s.CaseCounts[agent7.OutcomeOK] != 1 {
		t.Fatalf("case-level denominator must exclude the infra-only case: %+v", s)
	}
	if len(s.InfraOnlyCases) != 1 || s.InfraOnlyCases[0] != "case-infra" {
		t.Fatalf("infra-only case must be reported separately: %+v", s.InfraOnlyCases)
	}
	if s.CertifiedSafe != 0 || s.IncrementalSafeClear.Numerator != 0 {
		t.Fatal("infra failure must never become a safe/clear")
	}
}

// Brief test 6c: a synthetic best-of/retry admission set is rejected.
func TestBestOfRetryRejected(t *testing.T) {
	rec := okAttempt("r0", "case-a", 1, "vulnerable")
	rec.BestOf = true
	if _, err := agent7.ClassifyAttempt(rec); err == nil {
		t.Fatal("a best-of attempt must be rejected at classify time")
	}
	rec = okAttempt("r0", "case-a", 1, "vulnerable")
	rec.Retry = true
	if _, err := agent7.ClassifyAttempt(rec); err == nil {
		t.Fatal("an unreported retry must be rejected at classify time")
	}
	m := frozenManifest(t)
	sets := [][]agent7.AttemptRecord{
		{
			okAttempt("r0", "case-a", 1, "vulnerable"),
			okAttempt("r0", "case-a", 2, "vulnerable"),
			okAttempt("r0", "case-a", 3, "vulnerable"),
			okAttempt("r0", "case-a", 4, "vulnerable"), // undeclared 4th repeat
		},
		{
			okAttempt("r0", "case-a", 1, "vulnerable"),
			okAttempt("r0", "case-a", 1, "vulnerable"), // duplicate attempt_key
		},
		func() []agent7.AttemptRecord {
			a := okAttempt("r0", "case-a", 1, "vulnerable")
			a.BestOf = true
			return []agent7.AttemptRecord{a}
		}(),
	}
	for i, set := range sets {
		if _, err := agent7.Aggregate(m, set, nil, nil); err == nil {
			t.Fatalf("set %d: best-of/retry admission must be rejected", i)
		}
	}
}

// Classification table: every outcome class maps from its record shape.
func TestClassifyAttemptTable(t *testing.T) {
	cases := []struct {
		name string
		mut  func(r *agent7.AttemptRecord)
		want string
	}{
		{"ok", func(r *agent7.AttemptRecord) {}, agent7.OutcomeOK},
		{"abstain-uncertain", func(r *agent7.AttemptRecord) {
			r.Category = "uncertain"
		}, agent7.OutcomeAbstain},
		{"infra-transport", func(r *agent7.AttemptRecord) {
			r.Execution, r.OfficialParse = "transport_failure", "no_result"
		}, agent7.OutcomeInfraError},
		{"infra-docker-reason", func(r *agent7.AttemptRecord) {
			r.Execution, r.FailureReason = "nonzero_exit", "docker_cp_failed"
		}, agent7.OutcomeInfraError},
		{"provider-refusal", func(r *agent7.AttemptRecord) {
			r.Execution = "provider_refusal"
		}, agent7.OutcomeProviderRefused},
		{"refusal-flag", func(r *agent7.AttemptRecord) {
			r.ProviderRefusal = true
		}, agent7.OutcomeProviderRefused},
		{"invalid-format", func(r *agent7.AttemptRecord) {
			r.OfficialParse = "parse_fail"
		}, agent7.OutcomeInvalidFormat},
		{"failed-timeout", func(r *agent7.AttemptRecord) {
			r.Execution, r.FailureReason = "timeout", "timeout"
		}, agent7.OutcomeFailed},
		{"failed-nonzero", func(r *agent7.AttemptRecord) {
			r.Execution = "nonzero_exit"
		}, agent7.OutcomeFailed},
	}
	for _, tc := range cases {
		r := okAttempt("r0", "case-a", 1, "vulnerable")
		tc.mut(&r)
		got, err := agent7.ClassifyAttempt(r)
		if err != nil {
			t.Fatalf("%s: classify error: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

// Review C7: unknown enum values for execution / parse / reason are hard
// errors — never silently folded into FAILED or OK.
func TestUnknownEnumsRejected(t *testing.T) {
	cases := []struct {
		name string
		mut  func(r *agent7.AttemptRecord)
	}{
		{"unknown execution", func(r *agent7.AttemptRecord) { r.Execution = "weird" }},
		{"unknown parse", func(r *agent7.AttemptRecord) { r.OfficialParse = "bogus" }},
		{"unknown reason", func(r *agent7.AttemptRecord) { r.FailureReason = "magic" }},
	}
	for _, tc := range cases {
		r := okAttempt("r0", "case-a", 1, "vulnerable")
		tc.mut(&r)
		if _, err := agent7.ClassifyAttempt(r); err == nil {
			t.Fatalf("%s must be a hard error, never silently classified", tc.name)
		}
	}
}

// Review C7: case collapse is order-independent — the highest-precedence
// non-OK class wins regardless of attempt order (PROVIDER_REFUSED >
// INVALID_FORMAT > FAILED > ABSTAIN > OK).
func TestCaseOutcomeOrderIndependent(t *testing.T) {
	m := frozenManifest(t)
	mkSet := func(order []string) []agent7.AttemptRecord {
		var out []agent7.AttemptRecord
		for i, cls := range order {
			r := okAttempt("r0", "case-a", i+1, "vulnerable")
			switch cls {
			case agent7.OutcomeFailed:
				r.Execution, r.FailureReason = "timeout", "timeout"
			case agent7.OutcomeAbstain:
				r.Category = "uncertain"
			case agent7.OutcomeInvalidFormat:
				r.OfficialParse = "parse_fail"
			case agent7.OutcomeProviderRefused:
				r.Execution = "provider_refusal"
			}
			out = append(out, r)
		}
		return out
	}
	orders := [][]string{
		{agent7.OutcomeFailed, agent7.OutcomeAbstain, agent7.OutcomeOK},
		{agent7.OutcomeAbstain, agent7.OutcomeFailed, agent7.OutcomeOK},
		{agent7.OutcomeOK, agent7.OutcomeFailed, agent7.OutcomeAbstain},
	}
	for _, o := range orders {
		s, err := agent7.Aggregate(m, mkSet(o), nil, nil)
		if err != nil {
			t.Fatalf("aggregate order %v: %v", o, err)
		}
		if s.CaseCounts[agent7.OutcomeFailed] != 1 {
			t.Fatalf("order %v: case outcome must be FAILED regardless of order: %+v", o, s.CaseCounts)
		}
	}
	// Higher precedence: INVALID_FORMAT beats FAILED; PROVIDER_REFUSED
	// beats INVALID_FORMAT.
	s, err := agent7.Aggregate(m, mkSet([]string{
		agent7.OutcomeFailed, agent7.OutcomeInvalidFormat, agent7.OutcomeAbstain,
	}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.CaseCounts[agent7.OutcomeInvalidFormat] != 1 {
		t.Fatalf("INVALID_FORMAT must outrank FAILED: %+v", s.CaseCounts)
	}
	s, err = agent7.Aggregate(m, mkSet([]string{
		agent7.OutcomeProviderRefused, agent7.OutcomeInvalidFormat, agent7.OutcomeFailed,
	}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.CaseCounts[agent7.OutcomeProviderRefused] != 1 {
		t.Fatalf("PROVIDER_REFUSED must outrank INVALID_FORMAT: %+v", s.CaseCounts)
	}
}

// Brief test 7: aggregation never counts FAILED / ABSTAIN /
// PROVIDER_REFUSED / INFRA_ERROR as safe, and attempt-level vs case-level
// metrics stay separate.
func TestNoSubstitutionIntoSafe(t *testing.T) {
	m := frozenManifest(t)
	var attempts []agent7.AttemptRecord
	add := func(arm, task, cat string, mut func(r *agent7.AttemptRecord)) {
		for run := 1; run <= 3; run++ {
			r := okAttempt(arm, task, run, cat)
			mut(&r)
			r.AttemptKey = key(arm, task, run)
			attempts = append(attempts, r)
		}
	}
	add("r0", "case-ok", "vulnerable", func(r *agent7.AttemptRecord) {})
	add("r0", "case-failed", "", func(r *agent7.AttemptRecord) {
		r.Execution, r.FailureReason = "timeout", "timeout"
	})
	add("r0", "case-abstain", "uncertain", func(r *agent7.AttemptRecord) {})
	add("r0", "case-refused", "", func(r *agent7.AttemptRecord) {
		r.Execution = "provider_refusal"
	})
	add("r0", "case-infra", "", func(r *agent7.AttemptRecord) {
		r.Execution, r.FailureReason = "transport_failure", "docker_start_failed"
	})
	add("r0", "case-invalid", "", func(r *agent7.AttemptRecord) {
		r.OfficialParse = "parse_fail"
	})

	s, err := agent7.Aggregate(m, attempts, nil, nil)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.AttemptTotal != 18 {
		t.Fatalf("attempt_total = %d, want 18", s.AttemptTotal)
	}
	for _, cls := range []string{
		agent7.OutcomeFailed, agent7.OutcomeAbstain,
		agent7.OutcomeProviderRefused, agent7.OutcomeInfraError,
		agent7.OutcomeInvalidFormat,
	} {
		if s.AttemptCounts[cls] != 3 {
			t.Fatalf("attempt_counts[%s] = %d, want 3", cls, s.AttemptCounts[cls])
		}
	}
	if s.CaseTotal != 5 {
		t.Fatalf("case_total = %d, want 5 (infra-only excluded)", s.CaseTotal)
	}
	if s.CaseCounts[agent7.OutcomeOK] != 1 ||
		s.CaseCounts[agent7.OutcomeFailed] != 1 ||
		s.CaseCounts[agent7.OutcomeAbstain] != 1 ||
		s.CaseCounts[agent7.OutcomeProviderRefused] != 1 ||
		s.CaseCounts[agent7.OutcomeInvalidFormat] != 1 {
		t.Fatalf("case_counts must keep classes distinct: %v", s.CaseCounts)
	}
	if s.CertifiedSafe != 0 || s.IncrementalSafeClear.Numerator != 0 {
		t.Fatalf("no FAILED/ABSTAIN/PROVIDER_REFUSED/INFRA_ERROR may count as safe: %+v", s)
	}

	// Even a forged certified_safe flag on a non-OK attempt is rejected.
	forged := okAttempt("pr1", "case-ok", 1, "vulnerable")
	forged.CertifiedSafe = true
	forged.CertificateSource = agent7.CertSourcePR1
	forged.Execution, forged.FailureReason = "timeout", "timeout"
	if _, err := agent7.Aggregate(m, []agent7.AttemptRecord{forged}, nil, nil); err == nil {
		t.Fatal("certified_safe on a non-OK attempt must be rejected")
	}
}

// Review C7: CertifiedSafe requires explicit certificate provenance —
// baseline_b0 only on B0, pr1 only on PR1; any certificate flag on
// B1/R0/R1/R2 or without a source is rejected.
func TestCertificateProvenance(t *testing.T) {
	m := frozenManifest(t)
	cases := []struct {
		name string
		mut  func(r *agent7.AttemptRecord)
	}{
		{"cert on B1", func(r *agent7.AttemptRecord) {
			r.Arm = "b1"
			r.CertifiedSafe = true
			r.CertificateSource = agent7.CertSourcePR1
			r.AttemptKey = key("b1", "case-a", 1)
		}},
		{"cert on R1", func(r *agent7.AttemptRecord) {
			r.Arm = "r1"
			r.CertifiedSafe = true
			r.CertificateSource = agent7.CertSourcePR1
			r.AttemptKey = key("r1", "case-a", 1)
		}},
		{"baseline cert on R0", func(r *agent7.AttemptRecord) {
			r.Arm = "r0"
			r.CertifiedSafe = true
			r.CertificateSource = agent7.CertSourceBaselineB0
			r.AttemptKey = key("r0", "case-a", 1)
		}},
		{"cert without source", func(r *agent7.AttemptRecord) {
			r.CertifiedSafe = true
			r.CertificateSource = ""
		}},
		{"cert with bogus source", func(r *agent7.AttemptRecord) {
			r.Arm = "pr1"
			r.CertifiedSafe = true
			r.CertificateSource = "magic"
			r.AttemptKey = key("pr1", "case-a", 1)
		}},
	}
	for _, tc := range cases {
		r := okAttempt("r0", "case-a", 1, "vulnerable")
		tc.mut(&r)
		if _, err := agent7.Aggregate(m, []agent7.AttemptRecord{r}, nil, nil); err == nil {
			t.Fatalf("%s: certificate provenance violation must be rejected", tc.name)
		}
	}
	// Legit provenance is accepted: pr1 cert on PR1, baseline on B0.
	s, err := agent7.Aggregate(m, []agent7.AttemptRecord{
		func() agent7.AttemptRecord {
			r := okAttempt("pr1", "case-a", 1, "code_not_reachable")
			r.CertifiedSafe, r.CertificateSource = true, agent7.CertSourcePR1
			return r
		}(),
		func() agent7.AttemptRecord {
			r := okAttempt("b0", "case-b", 1, "code_not_reachable")
			r.CertifiedSafe, r.CertificateSource = true, agent7.CertSourceBaselineB0
			return r
		}(),
	}, nil, nil)
	if err != nil {
		t.Fatalf("legitimate certificates must classify: %v", err)
	}
	if len(s.NewCertifiedIDs) != 1 || s.NewCertifiedIDs[0] != "case-a" {
		t.Fatalf("pr1 cert must land in new_certified_ids: %+v", s.NewCertifiedIDs)
	}
	if len(s.BaselineCertifiedIDs) != 1 || s.BaselineCertifiedIDs[0] != "case-b" {
		t.Fatalf("b0 cert must land in baseline_certified_ids: %+v", s.BaselineCertifiedIDs)
	}
}

// CertifiedSafe / IncrementalSafeClear accounting: only certificates with
// explicit provenance on OK attempts count, measured against the GT-safe
// denominator with baseline-certified cases subtracted; baseline and new
// certified sets stay separate (spec §7.4).
func TestCertifiedSafeAccounting(t *testing.T) {
	m := frozenManifest(t)
	safeIDs := []string{"gt-safe-a", "gt-safe-b", "gt-safe-c", "gt-safe-d"}
	attempts := []agent7.AttemptRecord{
		func() agent7.AttemptRecord {
			r := okAttempt("pr1", safeIDs[0], 1, "code_not_reachable")
			r.CertifiedSafe, r.CertificateSource = true, agent7.CertSourcePR1
			return r
		}(),
		func() agent7.AttemptRecord {
			r := okAttempt("pr1", safeIDs[1], 1, "code_not_reachable")
			r.CertifiedSafe, r.CertificateSource = true, agent7.CertSourcePR1
			return r
		}(),
		func() agent7.AttemptRecord {
			r := okAttempt("pr1", "exploitable-case", 1, "code_not_reachable")
			r.CertifiedSafe, r.CertificateSource = true, agent7.CertSourcePR1
			return r
		}(),
		okAttempt("pr1", safeIDs[2], 1, "code_not_reachable"),
	}
	// baseline list supplied controller-side (GT-free manifest): safeIDs[0]
	// is already baseline-certified → no increment for it.
	baseline := []string{safeIDs[0]}
	s, err := agent7.Aggregate(m, attempts, safeIDs, baseline)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.BaselineCertifiedSafe != 1 {
		t.Fatalf("baseline_certified_safe = %d, want 1", s.BaselineCertifiedSafe)
	}
	if s.CertifiedSafe != 2 {
		t.Fatalf("certified_safe = %d, want 2 (only GT-safe new certs)", s.CertifiedSafe)
	}
	if s.IncrementalSafeClear.Numerator != 1 ||
		len(s.IncrementalSafeClear.CaseIDs) != 1 ||
		s.IncrementalSafeClear.CaseIDs[0] != safeIDs[1] {
		t.Fatalf("incremental numerator = %+v, want exactly %s",
			s.IncrementalSafeClear, safeIDs[1])
	}
	if s.IncrementalSafeClear.Denominator != len(safeIDs) {
		t.Fatalf("incremental denominator = %d, want %d GT-safe cases",
			s.IncrementalSafeClear.Denominator, len(safeIDs))
	}
}

// Defect 6 regression: Category must be in the official 12-category set;
// "garbage" → error, never silently OK.
func TestCategoryEnumStrict(t *testing.T) {
	rec := okAttempt("R0", "case-a", 1, "garbage")
	if _, err := agent7.ClassifyAttempt(rec); err == nil {
		t.Fatal(`Category="garbage" must be an error, not silently OK`)
	}
	// Every official category must classify without error.
	for _, cat := range []string{
		"false_positive", "code_not_present", "code_not_reachable",
		"requires_configuration", "requires_dependency", "requires_environment",
		"compiler_protected", "runtime_protected", "perimeter_protected",
		"mitigating_control_protected", "uncertain", "vulnerable",
	} {
		rec := okAttempt("R0", "case-a", 1, cat)
		if _, err := agent7.ClassifyAttempt(rec); err != nil {
			t.Fatalf("official category %q must classify: %v", cat, err)
		}
	}
	// Empty category is allowed (no parseable answer).
	rec2 := okAttempt("R0", "case-a", 1, "")
	if _, err := agent7.ClassifyAttempt(rec2); err != nil {
		t.Fatalf("empty category must be allowed: %v", err)
	}
}
