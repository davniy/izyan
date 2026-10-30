// Standalone govulncheck baseline: the differentiation evidence. Each
// real-dep case records what unmodified `govulncheck -mode source` says
// about the advisory on the generated product — reachable, package-level
// import only, silent despite knowing the advisory, not in its DB, or a
// tool error — so the report can compare it against the analyzer verdict.
//
// A label describes one run, never safety: "silent" is emitted only for a
// successfully completed run whose recorded coverage includes the advisory
// and the whole measured build. Unknown or narrowed coverage is reported as
// coverage-incomplete, and a package-level finding is not symbol
// reachability.
package eval

import (
	"context"
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// Baseline outcome labels, recorded on Result.Baseline.
const (
	BaselineReachable    = "reachable"     // finding with a function-level trace
	BaselinePackageLevel = "package-level" // imported package, no symbol trace
	BaselineModuleLevel  = "module-level"  // module referenced, no package/symbol trace
	BaselineSilent       = "silent"        // advisory covered, full scope, no finding emitted
	BaselineNotInDB      = "not-in-db"     // advisory absent from the DB snapshot
	// BaselineCoverageIncomplete is a completed run whose silence cannot
	// ground a negative: the advisory was not covered or the scope was
	// narrowed. It is deliberately distinct from both "silent" and "error".
	BaselineCoverageIncomplete = "coverage-incomplete"
	BaselineError              = "error" // govulncheck did not run cleanly
)

// BaselineFromEvidence classifies the durable govulncheck record already
// collected for a case. It never reinterprets a failed run's parseable
// prefix: the typed outcome is authoritative. A completed record's content
// must decode; there is no raw-text fallback.
func BaselineFromEvidence(ev domain.Evidence, v domain.Vulnerability) string {
	run := ev.Govulncheck
	if run == nil {
		return fmt.Sprintf("%s: govulncheck run outcome not recorded (legacy record)", BaselineError)
	}
	switch run.Outcome {
	case domain.GovulncheckFailed:
		msg := run.Error
		if msg == "" {
			msg = "process failed"
		}
		return fmt.Sprintf("%s: %s", BaselineError, msg)
	case domain.GovulncheckNotRun:
		msg := run.Error
		if msg == "" {
			msg = "govulncheck did not run"
		}
		return fmt.Sprintf("%s: %s", BaselineError, msg)
	case domain.GovulncheckCompletedEmpty, domain.GovulncheckCompletedWithResults:
	default:
		return fmt.Sprintf("%s: unrecognized govulncheck outcome %q", BaselineError, run.Outcome)
	}
	res, err := goanalysis.Parse([]byte(ev.Content))
	if err != nil {
		return fmt.Sprintf("%s: completed run output undecodable: %v", BaselineError, err)
	}
	fs := res.ForVulnerability(v)
	packageLevel := false
	for _, f := range fs {
		for _, fr := range f.Trace {
			if fr.Function != "" {
				return BaselineReachable
			}
			if fr.Package != "" {
				packageLevel = true
			}
		}
	}
	if packageLevel {
		return BaselinePackageLevel
	}
	if len(fs) > 0 {
		return BaselineModuleLevel
	}
	// No finding for the advisory. Silence is only a label when the run
	// recorded both advisory and scope coverage; otherwise the run did not
	// measure the question being asked.
	switch run.Coverage.Advisory {
	case domain.GovulncheckCoverageNotInDB:
		return BaselineNotInDB
	case domain.GovulncheckCoverageCovered:
		if run.Coverage.ScopeComplete {
			return BaselineSilent
		}
		return fmt.Sprintf("%s: advisory covered, but the run used a narrowed scope", BaselineCoverageIncomplete)
	default:
		return fmt.Sprintf("%s: advisory coverage unknown", BaselineCoverageIncomplete)
	}
}

// Baseline runs one standalone govulncheck on dir through the shared
// recorder and classifies its durable outcome. The runner must not be the
// corpus-wide caching one — generated products differ per case.
func Baseline(ctx context.Context, r goanalysis.Runner, dir string, v domain.Vulnerability, build domain.ProductSnapshot) string {
	if dir != "" {
		build.Repository = dir
	}
	// Calibration classifies one requested advisory. It has no loaded-record
	// bytes, so the measurement is identity-only: exact own-id coverage, no
	// byte pin, and no admission authority.
	ev, _ := goanalysis.CollectGovulncheck(ctx, r, build, vulnerability.LoadedRecord{Vuln: &v})
	return BaselineFromEvidence(ev, v)
}
