package agent7

import (
	"fmt"
	"sort"
	"strings"
)

// AttemptRecord is the controller-side terminal record of one attempt —
// the fields Classify/Aggregate need. CertifiedSafe marks a certificate
// produced by the proof lane; it requires CertificateSource provenance and
// may only ride on an OK attempt — never on a failure class (spec §2,
// §9.2: no substitution of non-OK into safe).
type AttemptRecord struct {
	AttemptKey        string `json:"attempt_key"` // (experiment_id, arm, model, task_id, run_NNN)
	ExperimentID      string `json:"experiment_id"`
	Arm               string `json:"arm"`
	TaskID            string `json:"task_id"`
	RunIndex          int    `json:"run_index"` // 1-based attempt ordinal
	Execution         string `json:"execution"` // attempt-status/1 ExecutionOutcome enum
	OfficialParse     string `json:"official_parse"`
	Category          string `json:"category"`       // parsed answer category; "uncertain" = abstain
	FailureReason     string `json:"failure_reason"` // attempt-status/1 FAILURE_REASONS enum
	CertifiedSafe     bool   `json:"certified_safe"`
	CertificateSource string `json:"certificate_source"` // "baseline_b0" | "pr1" — required when CertifiedSafe
	ProviderRefusal   bool   `json:"provider_refusal"`   // terminal text flagged as refusal
	Retry             bool   `json:"retry"`              // attempt re-run after seeing its result
	BestOf            bool   `json:"best_of"`            // attempt admitted from a best-of pool
}

// Certificate sources (spec §7.4): a safe certificate must say which lane
// produced it. Baseline certificates come only from independently
// re-verified B0 output; new certificates only from the PR1 offline
// projection. Anything else is rejected.
const (
	CertSourceBaselineB0 = "baseline_b0"
	CertSourcePR1        = "pr1"
)

// OfficialCategorySet is the closed set of parsed-answer categories used by
// the VEX-Bench harness (source of truth: internal/eval/vexbench/score.go
// Category* constants). An empty/absent category is allowed (the attempt
// did not produce a parseable answer); any non-empty value outside this
// set is an error, never silently OK.
var OfficialCategorySet = map[string]bool{
	"false_positive":               true,
	"code_not_present":             true,
	"code_not_reachable":           true,
	"requires_configuration":       true,
	"requires_dependency":          true,
	"requires_environment":         true,
	"compiler_protected":           true,
	"runtime_protected":            true,
	"perimeter_protected":          true,
	"mitigating_control_protected": true,
	"uncertain":                    true,
	"vulnerable":                   true,
}

// executionOutcomes is the closed enum of attempt-status/1 executions.
var executionOutcomes = map[string]bool{
	"ok":                      true,
	"timeout":                 true,
	"nonzero_exit":            true,
	"transport_failure":       true,
	"provider_refusal":        true,
	"invalid_terminal_answer": true,
	"no_output":               true,
}

// parseStatuses is the closed enum of terminal-parse outcomes.
var parseStatuses = map[string]bool{
	"accepted":   true,
	"parse_fail": true,
	"no_result":  true,
	"no_dir":     true,
}

// failureReasons is the closed enum of machine-readable failure reasons
// (attempt-status/1 FAILURE_REASONS). An empty reason is legal for OK
// attempts; a non-empty reason outside this set is a hard error, never
// silently folded into FAILED.
var failureReasons = map[string]bool{
	"timeout":                 true,
	"container_nonzero_exit":  true,
	"docker_create_failed":    true,
	"docker_cp_failed":        true,
	"docker_start_failed":     true,
	"artifact_export_failed":  true,
	"provider_refusal":        true,
	"provider_safety_filter":  true,
	"no_result":               true,
	"invalid_terminal_answer": true,
	"mcp_transport_failure":   true,
}

// infraExecutions are executions that never reached a model verdict —
// harness/transport failures. They map to INFRA_ERROR, are excluded from
// case-level denominators and reported separately (plan §0.5).
var infraExecutions = map[string]bool{
	"transport_failure": true,
}

// infraReasons are failure reasons on a finished run that still mean the
// infrastructure — not the agent — failed.
var infraReasons = map[string]bool{
	"docker_create_failed":   true,
	"docker_cp_failed":       true,
	"docker_start_failed":    true,
	"artifact_export_failed": true,
	"mcp_transport_failure":  true,
}

// casePrecedence orders non-infra outcome classes for case collapse. The
// highest-precedence non-OK class wins so the case outcome is independent
// of attempt order (documented, deterministic):
// PROVIDER_REFUSED > INVALID_FORMAT > FAILED > ABSTAIN > OK.
var casePrecedence = map[string]int{
	OutcomeOK:              0,
	OutcomeAbstain:         1,
	OutcomeFailed:          2,
	OutcomeInvalidFormat:   3,
	OutcomeProviderRefused: 4,
}

// ClassifyAttempt maps an attempt record to exactly one outcome class.
// Unknown enum values for execution/parse/category/reason are hard errors
// — never silently folded into FAILED or OK. Precedence is conservative:
// infra → refusal → format → fail → abstain → OK. An infra failure can
// never classify as a safe/negative verdict, and an unreported retry or
// best-of attempt is rejected outright.
func ClassifyAttempt(rec AttemptRecord) (string, error) {
	if rec.TaskID == "" || rec.AttemptKey == "" || rec.Arm == "" {
		return "", fmt.Errorf("attempt record missing identity fields (attempt_key/arm/task_id)")
	}
	if rec.Retry || rec.BestOf {
		return "", fmt.Errorf("attempt %s: unreported retry/best-of admission is forbidden (attempt_policy)",
			rec.AttemptKey)
	}
	if rec.RunIndex < 1 {
		return "", fmt.Errorf("attempt %s: run_index %d < 1", rec.AttemptKey, rec.RunIndex)
	}
	if !executionOutcomes[rec.Execution] {
		return "", fmt.Errorf("attempt %s: unknown execution %q", rec.AttemptKey, rec.Execution)
	}
	if rec.OfficialParse != "" && !parseStatuses[rec.OfficialParse] {
		return "", fmt.Errorf("attempt %s: unknown official_parse %q", rec.AttemptKey, rec.OfficialParse)
	}
	if rec.FailureReason != "" && !failureReasons[rec.FailureReason] {
		return "", fmt.Errorf("attempt %s: unknown failure_reason %q", rec.AttemptKey, rec.FailureReason)
	}
	if rec.Category != "" {
		if strings.TrimSpace(rec.Category) == "" {
			return "", fmt.Errorf("attempt %s: whitespace-only category", rec.AttemptKey)
		}
		if !OfficialCategorySet[rec.Category] {
			return "", fmt.Errorf("attempt %s: unknown category %q (not in the official 12-category set)", rec.AttemptKey, rec.Category)
		}
	}
	if rec.CertifiedSafe {
		if rec.CertificateSource != CertSourceBaselineB0 && rec.CertificateSource != CertSourcePR1 {
			return "", fmt.Errorf(
				"attempt %s: certified_safe requires certificate_source ∈ {baseline_b0, pr1}, got %q",
				rec.AttemptKey, rec.CertificateSource)
		}
	}
	if infraExecutions[rec.Execution] || infraReasons[rec.FailureReason] {
		return OutcomeInfraError, nil
	}
	if rec.Execution == "provider_refusal" || rec.ProviderRefusal ||
		rec.FailureReason == "provider_refusal" || rec.FailureReason == "provider_safety_filter" {
		return OutcomeProviderRefused, nil
	}
	if rec.Execution == "ok" && rec.OfficialParse != "accepted" {
		return OutcomeInvalidFormat, nil
	}
	if rec.Execution != "ok" {
		return OutcomeFailed, nil
	}
	if rec.Category == "uncertain" {
		return OutcomeAbstain, nil
	}
	return OutcomeOK, nil
}

// caseOutcome collapses a case's non-infra attempts to one case-level
// outcome, deterministic and independent of attempt order: the
// highest-precedence non-OK class wins (see casePrecedence). INFRA_ERROR
// never poisons a case: infra attempts are dropped from the case
// denominator, and a case whose every attempt is INFRA_ERROR is excluded
// from case metrics entirely (returned ok=false).
func caseOutcome(outs []string) (string, bool) {
	best := OutcomeOK
	bestRank := casePrecedence[OutcomeOK]
	usable := false
	for _, o := range outs {
		if o == OutcomeInfraError {
			continue
		}
		usable = true
		if rank := casePrecedence[o]; rank > bestRank {
			best, bestRank = o, rank
		}
	}
	return best, usable
}

// Summary is the aggregated experiment report. Attempt-level and
// case-level denominators stay separate (spec §9.2: 3 repeats of one case
// are not 3 independent cases); INFRA_ERROR is excluded from case-level
// denominators and reported separately. Baseline-certified and
// new-certified sets are kept distinct; IncrementalSafeClear is the
// unique-set difference (spec §7.4).
type Summary struct {
	// Attempt-level accounting over every classified attempt.
	AttemptTotal  int            `json:"attempt_total"`
	AttemptCounts map[string]int `json:"attempt_counts"`

	// Case-level accounting over unique task ids. Cases whose every
	// attempt is INFRA_ERROR are in InfraOnlyCases and are excluded from
	// CaseTotal.
	CaseTotal       int            `json:"case_total"`
	CaseCounts      map[string]int `json:"case_counts"`
	InfraOnlyCases  []string       `json:"infra_only_cases"`
	InfraErrorTasks []string       `json:"infra_error_tasks"`

	// Certificate accounting — a case counts as certified-safe only via
	// an explicit certificate source on an OK attempt; nothing else is
	// ever safe. The GT-safe denominator comes from the controller-side
	// task list, never from the manifest.
	GTSafeCaseIDs         []string `json:"gt_safe_case_ids"`
	BaselineCertifiedIDs  []string `json:"baseline_certified_ids"` // independently re-verified B0
	NewCertifiedIDs       []string `json:"new_certified_ids"`      // PR1 certificates on OK attempts
	BaselineCertifiedSafe int      `json:"baseline_certified_safe"`
	CertifiedSafe         int      `json:"certified_safe"` // |NewCertifiedIDs ∩ GT-safe|
	IncrementalSafeClear  struct {
		Numerator   int      `json:"numerator"`   // new certified safe minus baseline certified safe
		Denominator int      `json:"denominator"` // GT-safe case count
		CaseIDs     []string `json:"case_ids"`
	} `json:"incremental_safe_clear"`
}

// Aggregate classifies every attempt and builds the summary. gtSafeCaseIDs
// and baselineCertifiedIDs are controller-side datasets (the manifest is
// GT-free): callers pass them explicitly so the scorer never has to read
// labels from a committed file. Repeats of the same case keep their
// attempt rows but collapse to one case row; a duplicate attempt_key or a
// run_index beyond the arm/policy repeats is a hard error — repeats are
// declared, never smuggled (plan §0.5, §9.3).
func Aggregate(m Manifest, attempts []AttemptRecord, gtSafeCaseIDs, baselineCertifiedIDs []string) (*Summary, error) {
	policyRepeats := int(m.GetFloat("attempt_policy.repeats"))
	armRepeats := map[string]int{}
	if arms, ok := m["arms"].(map[string]any); ok {
		for name, raw := range arms {
			if a, ok := raw.(map[string]any); ok {
				if r, ok := a["repeats"].(float64); ok && r > 0 {
					armRepeats[strings.ToUpper(name)] = int(r)
				}
			}
		}
	}

	s := &Summary{
		AttemptCounts: map[string]int{},
		CaseCounts:    map[string]int{},
	}
	perCase := map[string][]string{}
	seenKey := map[string]bool{}
	infraSeen := map[string]bool{}

	for i, rec := range attempts {
		out, err := ClassifyAttempt(rec)
		if err != nil {
			return nil, err
		}
		if rec.AttemptKey == "" {
			return nil, fmt.Errorf("attempts[%d]: empty attempt_key", i)
		}
		if seenKey[rec.AttemptKey] {
			return nil, fmt.Errorf("duplicate attempt_key %q", rec.AttemptKey)
		}
		seenKey[rec.AttemptKey] = true
		repeats := policyRepeats
		if r, ok := armRepeats[strings.ToUpper(rec.Arm)]; ok {
			repeats = r
		}
		if repeats > 0 && rec.RunIndex > repeats {
			return nil, fmt.Errorf(
				"attempt %s: run_index %d exceeds declared repeats %d — undeclared extra attempt",
				rec.AttemptKey, rec.RunIndex, repeats)
		}
		if rec.CertifiedSafe {
			arm := strings.ToUpper(rec.Arm)
			switch rec.CertificateSource {
			case CertSourcePR1:
				if arm != "PR1" {
					return nil, fmt.Errorf(
						"attempt %s: pr1 certificate_source on arm %s — only the PR1 offline projection may produce new certificates",
						rec.AttemptKey, rec.Arm)
				}
			case CertSourceBaselineB0:
				if arm != "B0" {
					return nil, fmt.Errorf(
						"attempt %s: baseline_b0 certificate_source on arm %s — baseline certificates come only from B0",
						rec.AttemptKey, rec.Arm)
				}
			}
			if out != OutcomeOK {
				return nil, fmt.Errorf(
					"attempt %s: certified_safe on %s attempt — non-OK outcomes can never ground a certificate",
					rec.AttemptKey, out)
			}
			if rec.CertificateSource == CertSourcePR1 {
				s.NewCertifiedIDs = append(s.NewCertifiedIDs, rec.TaskID)
			} else {
				s.BaselineCertifiedIDs = append(s.BaselineCertifiedIDs, rec.TaskID)
			}
		}
		s.AttemptTotal++
		s.AttemptCounts[out]++
		perCase[rec.TaskID] = append(perCase[rec.TaskID], out)
		if out == OutcomeInfraError {
			infraSeen[rec.TaskID] = true
		}
	}

	for id, outs := range perCase {
		co, usable := caseOutcome(outs)
		if !usable {
			s.InfraOnlyCases = append(s.InfraOnlyCases, id)
			continue
		}
		s.CaseTotal++
		s.CaseCounts[co]++
	}
	for id := range infraSeen {
		s.InfraErrorTasks = append(s.InfraErrorTasks, id)
	}
	sort.Strings(s.InfraOnlyCases)
	sort.Strings(s.InfraErrorTasks)

	s.NewCertifiedIDs = dedupSorted(s.NewCertifiedIDs)
	s.BaselineCertifiedIDs = dedupSorted(append(s.BaselineCertifiedIDs, baselineCertifiedIDs...))
	s.GTSafeCaseIDs = dedupSorted(gtSafeCaseIDs)

	gtSafe := make(map[string]bool, len(s.GTSafeCaseIDs))
	for _, id := range s.GTSafeCaseIDs {
		gtSafe[id] = true
	}
	baseline := make(map[string]bool, len(s.BaselineCertifiedIDs))
	for _, id := range s.BaselineCertifiedIDs {
		baseline[id] = true
	}
	for _, id := range s.BaselineCertifiedIDs {
		if gtSafe[id] {
			s.BaselineCertifiedSafe++
		}
	}
	for _, id := range s.NewCertifiedIDs {
		if gtSafe[id] {
			s.CertifiedSafe++
		}
		if gtSafe[id] && !baseline[id] {
			s.IncrementalSafeClear.Numerator++
			s.IncrementalSafeClear.CaseIDs = append(s.IncrementalSafeClear.CaseIDs, id)
		}
	}
	s.IncrementalSafeClear.Denominator = len(s.GTSafeCaseIDs)
	return s, nil
}

func dedupSorted(ids []string) []string {
	set := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !set[id] {
			set[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
