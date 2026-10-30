package vexbench

import (
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// CaseOutcome is the safety-aware classification of one case against its
// ground truth. INCONCLUSIVE is always abstain, never safe.
type CaseOutcome string

const (
	OutcomeCorrectSafe    CaseOutcome = "correct_safe"
	OutcomeCorrectExploit CaseOutcome = "correct_exploitable"
	OutcomeAbstain        CaseOutcome = "abstain"
	OutcomeWrong          CaseOutcome = "wrong"
	OutcomeFailed         CaseOutcome = "failed"
)

// Official VEX-Bench compatibility categories — the only values
// CompatibilityCategory may return.
const (
	CategoryFalsePositive      = "false_positive"
	CategoryCodeNotPresent     = "code_not_present"
	CategoryCodeNotReachable   = "code_not_reachable"
	CategoryRequiresConfig     = "requires_configuration"
	CategoryRequiresDependency = "requires_dependency"
	CategoryRequiresEnv        = "requires_environment"
	CategoryCompilerProtected  = "compiler_protected"
	CategoryRuntimeProtected   = "runtime_protected"
	CategoryPerimeterProtected = "perimeter_protected"
	CategoryMitigatingControl  = "mitigating_control_protected"
	CategoryUncertain          = "uncertain"
	CategoryVulnerable         = "vulnerable"
)

// NOT_AFFECTED discriminators: which AffectedResult field closed the case.
// Callers pass one of these as the falsifier argument when the verdict is
// NOT_AFFECTED, since a bare safe verdict loses the reason.
const (
	AffectedModuleAbsent  = "module-absent"         // module outside the dep graph
	AffectedVersionFixed  = "version-outside-range" // resolved version already fixed
	AffectedPackageAbsent = "package-absent"        // package outside the import closure
	AffectedBuildExcluded = "build-not-relevant"    // different platform/build config
	// AffectedImplementationAbsent is the platform-gated implementation
	// facet: the package is present on the recorded target, but the
	// advisory's vulnerable implementation is excluded by the build
	// constraints. The exploit requires an environment/platform the
	// product does not ship.
	AffectedImplementationAbsent = "implementation-absent"
)

// Prediction is one case's analyzer result plus the runner's bookkeeping.
type Prediction struct {
	TaskID       string `json:"task_id"`
	RequestedCVE string `json:"requested_cve"`
	// AssessmentOutcome is the requested finding's terminal classification:
	// DECIDED, EXTERNAL_DEPENDENCY or FAILED. Empty for a legacy prediction,
	// which is classified from Verdict alone.
	AssessmentOutcome string `json:"assessment_outcome,omitempty"`
	// Verdict is the requested verdict: NOT_AFFECTED,
	// NO_EXPLOIT_PATH_FOUND, EXPLOITABLE or INCONCLUSIVE; "" means the run
	// published no verdict (a failed analysis).
	Verdict string `json:"verdict"`
	// Category is the compatibility projection of the verdict — normally
	// the value returned by CompatibilityCategory.
	Category string `json:"category"`
	Failed   bool   `json:"failed,omitempty"`
}

// Metrics is the safety-aware aggregate over one run.
type Metrics struct {
	Total             int     `json:"total"`
	FalseSafe         int     `json:"false_safe"`
	FalsePositive     int     `json:"false_positive"`
	SafeClearRate     float64 `json:"safe_clear_rate"`
	ExploitableRecall float64 `json:"exploitable_recall"`
	InconclusiveRate  float64 `json:"inconclusive_rate"`
	CompletionRate    float64 `json:"completion_rate"`
	StatusCorrect     int     `json:"status_correct"`
	ReasonCorrect     int     `json:"reason_correct"`
	// Decided/ExternalDependency/AnalysisFailed separate the terminal
	// classifications: only Decided is a definitive answer, an external
	// dependency is an abstention, and a failed analysis is neither a
	// completion nor an abstention.
	Decided            int `json:"decided"`
	ExternalDependency int `json:"external_dependency"`
	AnalysisFailed     int `json:"analysis_failed"`
}

// safeVerdict reports whether verdict is a safe negative.
func safeVerdict(verdict string) bool {
	return verdict == string(domain.VerdictNotAffected) ||
		verdict == string(domain.VerdictNoExploitPathFound)
}

func exploitableGT(groundTruth string) bool {
	return strings.EqualFold(groundTruth, "exploitable")
}

// Classify places one prediction relative to the task's ground truth:
// a safe verdict on an exploitable task is a false-safe (outcome wrong);
// INCONCLUSIVE abstains on any ground truth; a failed run or a missing /
// malformed verdict classifies as failed, never as safe.
//
// The requested assessment outcome is authoritative when present: a FAILED
// analysis is a failed run even if a primary record happened to carry a
// verdict, and an EXTERNAL_DEPENDENCY is an abstention, never a definitive
// answer.
func Classify(t Task, p Prediction) CaseOutcome {
	switch {
	case p.AssessmentOutcome == string(domain.OutcomeFailed):
		return OutcomeFailed
	case p.AssessmentOutcome == string(domain.OutcomeExternal):
		return OutcomeAbstain
	case p.Failed, p.Verdict == "":
		return OutcomeFailed
	case p.Verdict == string(domain.VerdictInconclusive):
		return OutcomeAbstain
	case p.Verdict == string(domain.VerdictExploitable):
		if exploitableGT(t.GroundTruth) {
			return OutcomeCorrectExploit
		}
		return OutcomeWrong
	case safeVerdict(p.Verdict):
		if exploitableGT(t.GroundTruth) {
			return OutcomeWrong // false-safe
		}
		return OutcomeCorrectSafe
	default:
		// Missing/malformed output is an error, not an implicit safe.
		return OutcomeFailed
	}
}

// Compute aggregates predictions over tasks. A task without a prediction
// counts as failed; a prediction without a matching task is ignored.
func Compute(preds []Prediction, tasks []Task) Metrics {
	byID := make(map[string]Prediction, len(preds))
	for _, p := range preds {
		if _, dup := byID[p.TaskID]; !dup {
			byID[p.TaskID] = p
		}
	}

	var m Metrics
	var gtSafe, gtExploitable, abstain, failed, correctSafe, correctExploit int
	for _, t := range tasks {
		m.Total++
		outcome := OutcomeFailed
		p, ok := byID[t.TaskID]
		if ok {
			outcome = Classify(t, p)
		}
		switch outcome {
		case OutcomeCorrectSafe:
			correctSafe++
			m.StatusCorrect++
			m.Decided++
			if p.Category == t.GroundTruthCategory {
				m.ReasonCorrect++
			}
		case OutcomeCorrectExploit:
			correctExploit++
			m.StatusCorrect++
			m.Decided++
			if p.Category == t.GroundTruthCategory {
				m.ReasonCorrect++
			}
		case OutcomeAbstain:
			abstain++
		case OutcomeWrong:
			// Only a published definitive verdict can reach this outcome, so
			// the wrong answer still counts as a definitive (wrong) answer.
			m.Decided++
			switch {
			case safeVerdict(p.Verdict) && exploitableGT(t.GroundTruth):
				m.FalseSafe++
			case p.Verdict == string(domain.VerdictExploitable):
				m.FalsePositive++
			}
		case OutcomeFailed:
			failed++
			m.AnalysisFailed++
		}
		if ok && p.AssessmentOutcome == string(domain.OutcomeExternal) {
			m.ExternalDependency++
		}
		if exploitableGT(t.GroundTruth) {
			gtExploitable++
		} else {
			gtSafe++
		}
	}
	if gtSafe > 0 {
		m.SafeClearRate = float64(correctSafe) / float64(gtSafe)
	}
	if gtExploitable > 0 {
		m.ExploitableRecall = float64(correctExploit) / float64(gtExploitable)
	}
	if m.Total > 0 {
		m.InconclusiveRate = float64(abstain) / float64(m.Total)
		m.CompletionRate = float64(m.Total-failed) / float64(m.Total)
	}
	return m
}

// CompatibilityCategory projects a verdict onto the 12 official VEX-Bench
// categories (plan §5.2). The second argument carries the discriminator:
// for NOT_AFFECTED it is one of the Affected* constants (which
// AffectedResult field closed the case); for NO_EXPLOIT_PATH_FOUND it is
// the grounding claim's Falsifier, with the trusted-infrastructure basis
// optionally appended as "<falsifier>:<basis>" (domain.Basis* values).
// Anything not representable — unknown falsifier, missing discriminator,
// abstention or a failed run — projects to "uncertain" so no result leaves
// the official category set.
func CompatibilityCategory(verdict, falsifier string) string {
	fals, _, hasBasis := strings.Cut(falsifier, ":")
	switch verdict {
	case string(domain.VerdictExploitable):
		return CategoryVulnerable
	case string(domain.VerdictInconclusive):
		return CategoryUncertain
	case string(domain.VerdictNotAffected):
		switch fals {
		case AffectedModuleAbsent, AffectedVersionFixed:
			return CategoryCodeNotPresent
		case AffectedPackageAbsent:
			return CategoryCodeNotReachable
		case AffectedBuildExcluded, AffectedImplementationAbsent:
			// Both close on a build/platform restriction: the vulnerable
			// code/implementation is not part of what the product ships
			// for its supported target.
			return CategoryRequiresEnv
		}
		return CategoryUncertain
	case string(domain.VerdictNoExploitPathFound):
		switch fals {
		case domain.FalsifierPackageAbsent, domain.FalsifierLocusPackageAbsent:
			return CategoryCodeNotPresent
		case domain.FalsifierLocusFunctionUnreached,
			domain.FalsifierGovulncheckSilence,
			domain.FalsifierUnreachedExportedSubject:
			return CategoryCodeNotReachable
		case domain.FalsifierConfigGatedOff,
			domain.FalsifierSafeConfigAssignment,
			domain.FalsifierSafeConfigKey,
			domain.FalsifierZeroValueConfig:
			return CategoryRequiresConfig
		case domain.FalsifierLoopbackOnly:
			return CategoryPerimeterProtected
		case domain.FalsifierProtocolRoleMismatch,
			domain.FalsifierSnapshotFactMismatch:
			return CategoryRequiresEnv
		case domain.FalsifierGuards,
			domain.FalsifierConstantOrGeneratedInput,
			domain.FalsifierMissingPairMember,
			domain.FalsifierMissingSourceSymbol,
			domain.FalsifierNoProductReader:
			return CategoryMitigatingControl
		case domain.FalsifierTrustedInfrastructure:
			// The basis decides: operator-declared or detected perimeter is
			// perimeter protection; a code-level config origin is a
			// mitigating control. No basis → ambiguous → uncertain.
			if !hasBasis {
				return CategoryUncertain
			}
			switch basis(falsifier) {
			case domain.BasisDeclaredTrust, domain.BasisAutoPerimeter:
				return CategoryPerimeterProtected
			case domain.BasisConfigOrigin:
				return CategoryMitigatingControl
			}
			return CategoryUncertain
		}
		return CategoryUncertain
	}
	return CategoryUncertain
}

// basis returns the trusted-infrastructure ground basis appended to
// falsifier as "<falsifier>:<basis>", or "" when none is present.
func basis(falsifier string) string {
	_, b, _ := strings.Cut(falsifier, ":")
	return b
}
