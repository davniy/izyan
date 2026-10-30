package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EvaluationSchemaVersion identifies evaluation.json, the offline
// comparison report of one saved decision package against external
// controls. The live triage and replay paths never read it and never
// require the inputs it compares against.
const EvaluationSchemaVersion = "triage-evaluation.v1"

// ErrFalseSafe is returned by VerifyFalseSafe when a decision package
// reduces risk beyond what the authoritative control result permits. It is
// the hard spec §13.3 condition — a count in an evaluation report is never
// a tunable threshold, the error itself is the enforcement point.
var ErrFalseSafe = errors.New("agenttriage: false-safe recommendation")

// AuthoritativeBaseline is an external control result a saved package is
// compared against in offline evaluation: the disposition the authoritative
// system allows, optionally the externally labelled judgment, and where the
// control came from. It is an explicit evaluation input only — live triage
// never loads it, and no field here can alter a package or a live result.
// An empty Disposition means no control exists — a machine reduction can
// then never be verified safe.
type AuthoritativeBaseline struct {
	Disposition Recommendation `json:"disposition"`
	// ExpectedJudgment is the external ground truth for the investigation
	// judgment. It is optional: a control disposition may be known without
	// an externally labelled judgment, in which case the judgment
	// comparison stays explicitly unassessed.
	ExpectedJudgment *Verdict `json:"expected_judgment,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Priority         string   `json:"priority,omitempty"`
	Source           string   `json:"source,omitempty"`
}

// baselineDocument is the triage-baselines.v1 input file: a list of
// external control results keyed by finding id. It is consumed only by the
// offline evaluator — a finding absent from the list has no verified
// baseline, never a safe reduction.
type baselineDocument struct {
	SchemaVersion string `json:"schema_version"`
	Baselines     []struct {
		FindingID        string   `json:"finding_id"`
		Disposition      string   `json:"disposition"`
		ExpectedJudgment *Verdict `json:"expected_judgment,omitempty"`
		Severity         string   `json:"severity,omitempty"`
		Priority         string   `json:"priority,omitempty"`
		Source           string   `json:"source,omitempty"`
	} `json:"baselines"`
}

// BaselinesSchemaVersion identifies the offline baseline JSON document.
const BaselinesSchemaVersion = "triage-baselines.v1"

// LoadBaselines reads the external comparison file. A finding without an
// entry has no supplied control: offline evaluation reports the comparison
// as unassessed rather than inventing a correct result.
func LoadBaselines(path string) (map[string]AuthoritativeBaseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agenttriage: baseline %s: %w", path, err)
	}
	var doc baselineDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("agenttriage: baseline %s does not parse: %w", path, err)
	}
	if doc.SchemaVersion != "" && doc.SchemaVersion != BaselinesSchemaVersion {
		return nil, fmt.Errorf("agenttriage: baseline %s schema %q is not %s", path, doc.SchemaVersion, BaselinesSchemaVersion)
	}
	out := make(map[string]AuthoritativeBaseline, len(doc.Baselines))
	for i, b := range doc.Baselines {
		id := strings.TrimSpace(b.FindingID)
		if id == "" {
			return nil, fmt.Errorf("agenttriage: baseline %s: entry %d has no finding_id", path, i)
		}
		if !Recommendation(b.Disposition).Valid() {
			return nil, fmt.Errorf("agenttriage: baseline %s: entry %d (%s) has invalid disposition %q", path, i, id, b.Disposition)
		}
		out[id] = AuthoritativeBaseline{
			Disposition:      Recommendation(b.Disposition),
			ExpectedJudgment: b.ExpectedJudgment,
			Severity:         b.Severity,
			Priority:         b.Priority,
			Source:           b.Source,
		}
	}
	return out, nil
}

// VerifyFalseSafe enforces spec §13.3's hard condition on the machine axis
// alone: a package whose machine disposition recommends DISMISSED or
// LOWERED while the authoritative control result forbids that reduction is
// a false-safe — an error, not a metric to tune. UNCHANGED never reduces
// and is always safe; a package carrying an invalid recommendation is a
// contract violation on its own. A control that cannot name its
// disposition cannot permit a reduction either. The human proposal is
// never consulted here: a model judgment, a human proposal and a human
// Accept are not machine-safe conclusions.
func VerifyFalseSafe(pkg DecisionPackage, baseline AuthoritativeBaseline) error {
	rec := pkg.MachineDisposition.Recommendation
	if !rec.Valid() {
		return fmt.Errorf("agenttriage: decision package %s carries invalid machine recommendation %q", pkg.FindingID, rec)
	}
	if rec == RecommendationUnchanged {
		return nil
	}
	if !baseline.Disposition.Valid() {
		return fmt.Errorf("agenttriage: finding %s: no authoritative baseline disposition — %s cannot be verified safe", pkg.FindingID, rec)
	}
	if strengthOf(rec) > strengthOf(baseline.Disposition) {
		return fmt.Errorf("%w: finding %s recommends %s while authoritative baseline %q permits at most %s",
			ErrFalseSafe, pkg.FindingID, rec, baseline.Source, baseline.Disposition)
	}
	return nil
}

// ComparisonStatus states whether an offline comparison was actually
// performed. Absent controls or external labels leave the comparison
// UNASSESSED — never a measured zero-error result.
type ComparisonStatus string

const (
	// ComparisonAssessed means the external input needed for this
	// comparison was supplied and the counters below are measured against
	// it.
	ComparisonAssessed ComparisonStatus = "ASSESSED"
	// ComparisonUnassessed means the external input was absent; the
	// corresponding counters carry no verdict.
	ComparisonUnassessed ComparisonStatus = "UNASSESSED"
)

// EvaluationCoverage records which comparisons were actually possible for
// one saved package.
type EvaluationCoverage struct {
	ControlDisposition ComparisonStatus `json:"control_disposition"`
	ExpectedJudgment   ComparisonStatus `json:"expected_judgment"`
}

// HumanEvaluation counts errors of the human recommendation only. A human
// CLOSE or LOWER_PRIORITY proposal is a proposal for a person: it is never
// a machine reduction, and an incorrect proposal is scored here — never as
// ErrFalseSafe.
type HumanEvaluation struct {
	// ReductionProposals counts CLOSE/LOWER_PRIORITY proposals.
	ReductionProposals int64 `json:"reduction_proposals"`
	// ReductionControlMismatches counts reduction proposals the supplied
	// control disposition does not permit.
	ReductionControlMismatches int64 `json:"reduction_control_mismatches"`
	// NegativeJudgments counts NOT_EXPLOITABLE judgments.
	NegativeJudgments int64 `json:"negative_judgments"`
	// IncorrectNegativeJudgments counts negative judgments against an
	// external EXPLOITABLE expected_judgment.
	IncorrectNegativeJudgments int64 `json:"incorrect_negative_judgments"`
	// CloseOnExploitable counts CLOSE proposals against an external
	// EXPLOITABLE expected_judgment.
	CloseOnExploitable int64 `json:"close_on_exploitable"`
}

// MachineEvaluation counts machine safety outcomes against the supplied
// control. It is computed from the machine disposition alone.
type MachineEvaluation struct {
	// Reductions counts DISMISSED/LOWERED machine recommendations.
	Reductions int64 `json:"reductions"`
	// FalseSafe counts reductions stronger than the supplied control
	// disposition permits.
	FalseSafe int64 `json:"false_safe"`
	// UnverifiedReductions counts reductions with no valid control to
	// verify them; they are a coverage gap, never a safe result.
	UnverifiedReductions int64 `json:"unverified_reductions"`
}

// DecisionEvaluation is the offline comparison report of one verified
// decision package. Package identity pins the exact artifacts evaluated;
// coverage states which comparisons were possible; human and machine
// errors stay on separate counters; violations lists every measured
// comparison failure. Missing controls never appear as a clean comparison.
type DecisionEvaluation struct {
	SchemaVersion string `json:"schema_version"`
	EvaluatedAt   string `json:"evaluated_at,omitempty"`
	RunID         string `json:"run_id"`
	FindingID     string `json:"finding_id"`
	// DecisionPackageHash is the canonical hash of the evaluated package —
	// the same identity replay and Accept/Reject records bind to.
	DecisionPackageHash   string           `json:"decision_package_hash"`
	Judgment              Verdict          `json:"judgment"`
	ProposedAction        HumanActionKind  `json:"proposed_action"`
	Support               SupportLevel     `json:"support"`
	MachineRecommendation Recommendation   `json:"machine_recommendation"`
	Automation            AutomationStatus `json:"automation"`
	// Baseline records the supplied external comparison inputs. It is
	// copied here as audit evidence and is never attached to the package.
	Baseline *AuthoritativeBaseline `json:"baseline,omitempty"`
	Coverage EvaluationCoverage     `json:"coverage"`
	Human    HumanEvaluation        `json:"human"`
	Machine  MachineEvaluation      `json:"machine"`
	// Violations names each measured comparison failure (exit 1 for the
	// offline command). An empty list with UNASSESSED coverage is not a
	// measured success.
	Violations []string `json:"violations,omitempty"`
}

// EvaluateDecisionPackage compares one verified decision package with the
// supplied external control. It is a pure read-only projection: it never
// mutates the package, never changes a rendered action and never feeds a
// label back into the product. The machine disposition is checked with
// VerifyFalseSafe; a human CLOSE/LOWER_PRIORITY proposal is compared
// against the control disposition as a distinct human recommendation
// error; an optional expected_judgment compares negative judgments and
// CLOSE-on-exploitable proposals. A nil or disposition-less baseline is
// reported as UNASSESSED coverage, never as fabricated zero errors.
func EvaluateDecisionPackage(pkg DecisionPackage, baseline *AuthoritativeBaseline) DecisionEvaluation {
	eval := DecisionEvaluation{
		SchemaVersion:         EvaluationSchemaVersion,
		RunID:                 pkg.RunID,
		FindingID:             pkg.FindingID,
		DecisionPackageHash:   canonicalDecisionHash(pkg),
		Judgment:              pkg.Judgment.Verdict,
		ProposedAction:        pkg.ProposedAction.Kind,
		Support:               pkg.Support.Level,
		MachineRecommendation: pkg.MachineDisposition.Recommendation,
		Automation:            pkg.MachineDisposition.Automation,
		Baseline:              baseline,
	}

	controlPresent := baseline != nil && baseline.Disposition.Valid()
	if controlPresent {
		eval.Coverage.ControlDisposition = ComparisonAssessed
	} else {
		eval.Coverage.ControlDisposition = ComparisonUnassessed
	}
	if baseline != nil && baseline.ExpectedJudgment != nil {
		eval.Coverage.ExpectedJudgment = ComparisonAssessed
	} else {
		eval.Coverage.ExpectedJudgment = ComparisonUnassessed
	}

	// Human axis: a reduction proposal is not a machine reduction. Its
	// mismatch with the control is scored as a human recommendation error.
	proposal := RecommendationUnchanged
	switch pkg.ProposedAction.Kind {
	case HumanActionClose:
		proposal = RecommendationDismissed
	case HumanActionLowerPriority:
		proposal = RecommendationLowered
	}
	if proposal != RecommendationUnchanged {
		eval.Human.ReductionProposals = 1
		if controlPresent && strengthOf(proposal) > strengthOf(baseline.Disposition) {
			eval.Human.ReductionControlMismatches = 1
			eval.Violations = append(eval.Violations, fmt.Sprintf(
				"human reduction control mismatch: finding %s proposes %s while the control disposition %q permits at most %s",
				pkg.FindingID, pkg.ProposedAction.Kind, baseline.Source, baseline.Disposition))
		}
	}

	// Human axis: external judgment labels. A negative judgment and a
	// CLOSE proposal against an exploitable case are separate mistakes.
	if pkg.Judgment.Verdict == VerdictNotExploitable {
		eval.Human.NegativeJudgments = 1
	}
	if eval.Coverage.ExpectedJudgment == ComparisonAssessed && *baseline.ExpectedJudgment == VerdictExploitable {
		if pkg.Judgment.Verdict == VerdictNotExploitable {
			eval.Human.IncorrectNegativeJudgments = 1
			eval.Violations = append(eval.Violations, fmt.Sprintf(
				"incorrect negative judgment: finding %s judges %s while the external expected_judgment is %s",
				pkg.FindingID, pkg.Judgment.Verdict, VerdictExploitable))
		}
		if pkg.ProposedAction.Kind == HumanActionClose {
			eval.Human.CloseOnExploitable = 1
			eval.Violations = append(eval.Violations, fmt.Sprintf(
				"close on exploitable: finding %s proposes %s while the external expected_judgment is %s",
				pkg.FindingID, pkg.ProposedAction.Kind, VerdictExploitable))
		}
	}

	// Machine axis: only the machine disposition is compared. A reduction
	// beyond the control is the hard false-safe; a reduction without a
	// valid control is unverified, not a fabricated pass.
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		eval.Machine.Reductions = 1
		if !controlPresent {
			eval.Machine.UnverifiedReductions = 1
		} else if err := VerifyFalseSafe(pkg, *baseline); errors.Is(err, ErrFalseSafe) {
			eval.Machine.FalseSafe = 1
			eval.Violations = append(eval.Violations, fmt.Sprintf(
				"machine false-safe: finding %s recommends %s while the control disposition %q permits at most %s",
				pkg.FindingID, pkg.MachineDisposition.Recommendation, baseline.Source, baseline.Disposition))
		} else if err != nil {
			eval.Machine.UnverifiedReductions = 1
		}
	}
	return eval
}

// WriteDecisionEvaluation persists the offline comparison as
// <dir>/evaluation.json. It is written outside the source run directory
// (the caller enforces that) and never touches the evaluated package.
func WriteDecisionEvaluation(ctx context.Context, dir string, eval DecisionEvaluation) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", errors.New("agenttriage: evaluation: output directory is empty")
	}
	eval.SchemaVersion = EvaluationSchemaVersion
	eval.EvaluatedAt = time.Now().UTC().Format(time.RFC3339)
	path := filepath.Join(dir, "evaluation.json")
	if err := writeJSONAtomic(ctx, path, eval); err != nil {
		return "", fmt.Errorf("agenttriage: write evaluation: %w", err)
	}
	return path, nil
}
