// Offline authority-cutover comparison.
//
// A paired corpus measurement answers one question the post-change
// distribution cannot: what did the change do to the answers? It is only
// meaningful over matched material, so this tool pairs results by their case,
// input and build identities and refuses the comparison when the two runs do
// not describe the same population. An unmatched pair is not a delta.
//
// The report keeps the direction of every change — lost and gained definitive
// positives, lost and gained negatives, new and cleared failures, and each
// condition's own result transition — because the authority cutover is
// expected to lose weak positives. Those losses are the measurement, not a
// reason to re-admit the retired grounds.
package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// AuthorityDeltaSchema is the frozen discriminator of the comparison record.
const AuthorityDeltaSchema = "authority-delta/1"

// DeltaClass is the terminal side of one case in one run. The classes are
// exclusive: a failure publishes no verdict and is never counted as an
// abstention.
type DeltaClass string

const (
	// DeltaPositive is a published EXPLOITABLE verdict.
	DeltaPositive DeltaClass = "POSITIVE"
	// DeltaNegative is a definitive safe verdict — NOT_AFFECTED or
	// NO_EXPLOIT_PATH_FOUND.
	DeltaNegative DeltaClass = "NEGATIVE"
	// DeltaFailure is a case that produced no answer: an execution error or a
	// failed assessment.
	DeltaFailure DeltaClass = "FAILURE"
	// DeltaInconclusive is a published abstention with a reason.
	DeltaInconclusive DeltaClass = "INCONCLUSIVE"
	// DeltaNoVerdict is a legacy/empty result that committed to nothing.
	DeltaNoVerdict DeltaClass = "NO_VERDICT"
)

// DeltaTransition labels one recorded change.
type DeltaTransition string

const (
	TransitionLostPositive    DeltaTransition = "POSITIVE_LOST"
	TransitionGainedPositive  DeltaTransition = "POSITIVE_GAINED"
	TransitionLostNegative    DeltaTransition = "NEGATIVE_LOST"
	TransitionGainedNegative  DeltaTransition = "NEGATIVE_GAINED"
	TransitionNewFailure      DeltaTransition = "FAILURE_NEW"
	TransitionClearedFailure  DeltaTransition = "FAILURE_CLEARED"
	TransitionClassChange     DeltaTransition = "CLASS_CHANGED"
	ConditionAdded            DeltaTransition = "CONDITION_ADDED"
	ConditionRemoved          DeltaTransition = "CONDITION_REMOVED"
	ConditionPositiveLost     DeltaTransition = "CONDITION_POSITIVE_LOST"
	ConditionPositiveGained   DeltaTransition = "CONDITION_POSITIVE_GAINED"
	ConditionNegativeLost     DeltaTransition = "CONDITION_NEGATIVE_LOST"
	ConditionNegativeGained   DeltaTransition = "CONDITION_NEGATIVE_GAINED"
	ConditionResultTransition DeltaTransition = "CONDITION_RESULT_CHANGED"
)

// DeltaCounts is one run's population, recounted from its own results so the
// two sides are measured the same way.
type DeltaCounts struct {
	Cases        int `json:"cases"`
	Positives    int `json:"positives"`
	Negatives    int `json:"negatives"`
	Inconclusive int `json:"inconclusive"`
	Failures     int `json:"failures"`
	FalseSafe    int `json:"false_safe"`
}

// SideState is one case's recorded state in one run.
type SideState struct {
	Class        DeltaClass `json:"class"`
	Verdict      string     `json:"verdict,omitempty"`
	Outcome      string     `json:"assessment_outcome,omitempty"`
	FailureCodes []string   `json:"failure_codes,omitempty"`
	FalseSafe    bool       `json:"false_safe,omitempty"`
}

// ConditionTransition is one condition's result in both runs. A condition that
// exists on one side only says so: the model's conjunction changed, which is
// part of what the cutover did.
type ConditionTransition struct {
	ConditionID string          `json:"condition_id"`
	Before      string          `json:"before,omitempty"`
	After       string          `json:"after,omitempty"`
	Transition  DeltaTransition `json:"transition"`
}

// CaseDelta is one matched case whose recorded state changed. Transition is
// empty when the case's class did not move but one or more condition results
// did; the conditions then carry the whole change.
type CaseDelta struct {
	Key        string                `json:"key"`
	Case       string                `json:"case"`
	Transition DeltaTransition       `json:"transition"`
	Before     SideState             `json:"before"`
	After      SideState             `json:"after"`
	Conditions []ConditionTransition `json:"condition_transitions,omitempty"`
}

// AuthorityDelta is the comparison record: the matched population, each side's
// counts, and every transition that moved authority in either direction.
type AuthorityDelta struct {
	Schema string `json:"schema"`
	// Before/After pin the two runs' own identities when the caller supplies
	// them; the results alone cannot name a file.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`

	Matched int `json:"matched"`
	// Unchanged counts matched cases whose class and every condition result
	// are identical. Their absence from Transitions is what makes the record
	// readable.
	Unchanged int `json:"unchanged"`

	BeforeCounts DeltaCounts `json:"before_counts"`
	AfterCounts  DeltaCounts `json:"after_counts"`

	Transitions []CaseDelta `json:"transitions,omitempty"`
	// Conditions is the flat per-condition accounting: every condition
	// transition in the run, ordered by case then condition. It is the direct
	// measure of "which fact stopped being established".
	Conditions []CaseDeltaCondition `json:"conditions,omitempty"`
	// FalseSafeGained names the matched cases that became false-safe. It is
	// the one direction the harness must never accept, so it is called out
	// separately from the counts.
	FalseSafeGained []string `json:"false_safe_gained,omitempty"`
	FalseSafeLost   []string `json:"false_safe_lost,omitempty"`
}

// CaseDeltaCondition is one condition transition with its case identity.
type CaseDeltaCondition struct {
	Key         string          `json:"key"`
	Case        string          `json:"case"`
	ConditionID string          `json:"condition_id"`
	Before      string          `json:"before,omitempty"`
	After       string          `json:"after,omitempty"`
	Transition  DeltaTransition `json:"transition"`
}

// CompareAuthorityResults pairs two runs by case/input/build identity and
// reports what the change did to each matched case's conclusions.
//
// The comparison is refused when the two runs do not describe the same
// population: a case present on one side only, a duplicated identity, or an
// identity whose build differs. Refusing is the point — an unmatched
// comparison measures nothing, and reporting a delta over it would present
// different material as a behavioural change.
func CompareAuthorityResults(before, after []Result) (AuthorityDelta, error) {
	beforeByKey, err := indexResults("before", before)
	if err != nil {
		return AuthorityDelta{}, err
	}
	afterByKey, err := indexResults("after", after)
	if err != nil {
		return AuthorityDelta{}, err
	}
	if unmatched := unmatchedKeys(beforeByKey, afterByKey); len(unmatched) > 0 {
		return AuthorityDelta{}, fmt.Errorf(
			"authority delta: %d case identity(ies) are not present in both runs (%s); a comparison over unmatched material measures no change",
			len(unmatched), strings.Join(unmatched, ", "))
	}

	delta := AuthorityDelta{
		Schema:       AuthorityDeltaSchema,
		Matched:      len(beforeByKey),
		BeforeCounts: countResults(beforeByKey),
		AfterCounts:  countResults(afterByKey),
	}
	keys := make([]string, 0, len(beforeByKey))
	for key := range beforeByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		b, a := beforeByKey[key], afterByKey[key]
		entry := CaseDelta{
			Key:        key,
			Case:       b.Case.Label(),
			Before:     sideState(b),
			After:      sideState(a),
			Conditions: conditionTransitions(b.Claims, a.Claims),
		}
		entry.Transition = classTransition(entry.Before, entry.After)
		if entry.Transition == "" && len(entry.Conditions) == 0 {
			delta.Unchanged++
			continue
		}
		delta.Transitions = append(delta.Transitions, entry)
		for _, cond := range entry.Conditions {
			delta.Conditions = append(delta.Conditions, CaseDeltaCondition{
				Key: key, Case: entry.Case, ConditionID: cond.ConditionID,
				Before: cond.Before, After: cond.After, Transition: cond.Transition,
			})
		}
		if !entry.Before.FalseSafe && entry.After.FalseSafe {
			delta.FalseSafeGained = append(delta.FalseSafeGained, entry.Case)
		}
		if entry.Before.FalseSafe && !entry.After.FalseSafe {
			delta.FalseSafeLost = append(delta.FalseSafeLost, entry.Case)
		}
	}
	return delta, nil
}

// ResultKey is the identity a comparison pairs on: the case's label, its
// recorded input fingerprint and the build the result was admitted under.
func ResultKey(r Result) string {
	return r.Case.Label() + "\x00" + r.Case.InputIdentity() + "\x00" + r.Build
}

// indexResults groups one run's results by comparison identity.
func indexResults(side string, results []Result) (map[string]Result, error) {
	out := make(map[string]Result, len(results))
	for _, r := range results {
		key := ResultKey(r)
		if existing, ok := out[key]; ok {
			return nil, fmt.Errorf(
				"authority delta: %s run records case %q twice under the same input/build identity (verdicts %q and %q); the comparison cannot pair it",
				side, r.Case.Label(), existing.Verdict, r.Verdict)
		}
		out[key] = r
	}
	return out, nil
}

// unmatchedKeys names every identity missing from either side, in display form.
func unmatchedKeys(before, after map[string]Result) []string {
	var out []string
	for key, r := range before {
		if _, ok := after[key]; !ok {
			out = append(out, describeKey(r))
		}
	}
	for key, r := range after {
		if _, ok := before[key]; !ok {
			out = append(out, describeKey(r))
		}
	}
	sort.Strings(out)
	return out
}

// describeKey renders an identity for an error without dumping the raw
// fingerprint.
func describeKey(r Result) string {
	build := r.Build
	if build == "" {
		build = "no build identity"
	}
	return fmt.Sprintf("%s (%s)", r.Case.Label(), build)
}

// classOf classifies one result. A failure outranks the verdict: a failed
// assessment publishes no answer even when a legacy field carries one.
func classOf(r Result) DeltaClass {
	if r.Err != "" || r.AssessmentOutcome == string(domain.OutcomeFailed) {
		return DeltaFailure
	}
	switch r.Verdict {
	case string(domain.VerdictExploitable):
		return DeltaPositive
	case string(domain.VerdictNotAffected), string(domain.VerdictNoExploitPathFound):
		return DeltaNegative
	case string(domain.VerdictInconclusive):
		return DeltaInconclusive
	}
	return DeltaNoVerdict
}

// sideState reduces one result to the compared state.
func sideState(r Result) SideState {
	return SideState{
		Class:        classOf(r),
		Verdict:      r.Verdict,
		Outcome:      r.AssessmentOutcome,
		FailureCodes: append([]string(nil), r.FailureCodes...),
		FalseSafe:    r.FalseSafe,
	}
}

// classTransition names the direction a case's class moved, or "" when it did
// not move.
func classTransition(before, after SideState) DeltaTransition {
	if before.Class == after.Class {
		return ""
	}
	switch {
	case before.Class == DeltaPositive && after.Class != DeltaPositive:
		return TransitionLostPositive
	case after.Class == DeltaPositive && before.Class != DeltaPositive:
		return TransitionGainedPositive
	case before.Class == DeltaNegative && after.Class != DeltaNegative:
		return TransitionLostNegative
	case after.Class == DeltaNegative && before.Class != DeltaNegative:
		return TransitionGainedNegative
	case after.Class == DeltaFailure:
		return TransitionNewFailure
	case before.Class == DeltaFailure:
		return TransitionClearedFailure
	}
	return TransitionClassChange
}

// conditionTransitions reports every condition whose result differs between
// the two runs, including conditions that exist on one side only.
func conditionTransitions(before, after map[string]string) []ConditionTransition {
	ids := make([]string, 0, len(before)+len(after))
	seen := map[string]bool{}
	for id := range before {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for id := range after {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	var out []ConditionTransition
	for _, id := range ids {
		b, hadBefore := before[id]
		a, hasAfter := after[id]
		transition := conditionTransition(hadBefore, b, hasAfter, a)
		if transition == "" {
			continue
		}
		out = append(out, ConditionTransition{
			ConditionID: id, Before: b, After: a, Transition: transition,
		})
	}
	return out
}

// conditionTransition names one condition's movement.
func conditionTransition(hadBefore bool, before string, hasAfter bool, after string) DeltaTransition {
	switch {
	case !hadBefore && !hasAfter:
		return ""
	case !hadBefore:
		return ConditionAdded
	case !hasAfter:
		return ConditionRemoved
	case before == after:
		return ""
	case before == string(domain.ClaimTrue):
		return ConditionPositiveLost
	case after == string(domain.ClaimTrue):
		return ConditionPositiveGained
	case before == string(domain.ClaimFalse):
		return ConditionNegativeLost
	case after == string(domain.ClaimFalse):
		return ConditionNegativeGained
	}
	return ConditionResultTransition
}

// countResults recounts one side's population from its own results.
func countResults(results map[string]Result) DeltaCounts {
	out := DeltaCounts{Cases: len(results)}
	for _, r := range results {
		switch classOf(r) {
		case DeltaPositive:
			out.Positives++
		case DeltaNegative:
			out.Negatives++
		case DeltaInconclusive:
			out.Inconclusive++
		case DeltaFailure:
			out.Failures++
		}
		if r.FalseSafe {
			out.FalseSafe++
		}
	}
	return out
}

// Summary renders the delta as one reviewable block. Every direction is stated
// separately: a lost positive is reported as a loss, never netted against a
// gain elsewhere.
func (d AuthorityDelta) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "authority delta (matched cases: %d, unchanged: %d)\n", d.Matched, d.Unchanged)
	fmt.Fprintf(&b, "  before: positives=%d negatives=%d inconclusive=%d failures=%d false-safe=%d\n",
		d.BeforeCounts.Positives, d.BeforeCounts.Negatives, d.BeforeCounts.Inconclusive,
		d.BeforeCounts.Failures, d.BeforeCounts.FalseSafe)
	fmt.Fprintf(&b, "  after:  positives=%d negatives=%d inconclusive=%d failures=%d false-safe=%d\n",
		d.AfterCounts.Positives, d.AfterCounts.Negatives, d.AfterCounts.Inconclusive,
		d.AfterCounts.Failures, d.AfterCounts.FalseSafe)
	directions := []DeltaTransition{
		TransitionLostPositive, TransitionGainedPositive,
		TransitionLostNegative, TransitionGainedNegative,
		TransitionNewFailure, TransitionClearedFailure, TransitionClassChange,
	}
	for _, direction := range directions {
		var cases []string
		for _, t := range d.Transitions {
			if t.Transition == direction {
				cases = append(cases, t.Case)
			}
		}
		if len(cases) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%d): %s\n", direction, len(cases), strings.Join(cases, ", "))
	}
	if len(d.FalseSafeGained) > 0 {
		fmt.Fprintf(&b, "  FALSE-SAFE GAINED (%d): %s\n", len(d.FalseSafeGained), strings.Join(d.FalseSafeGained, ", "))
	}
	if len(d.FalseSafeLost) > 0 {
		fmt.Fprintf(&b, "  false-safe lost (%d): %s\n", len(d.FalseSafeLost), strings.Join(d.FalseSafeLost, ", "))
	}
	if len(d.Conditions) > 0 {
		fmt.Fprintf(&b, "  condition transitions: %d\n", len(d.Conditions))
	}
	return b.String()
}
