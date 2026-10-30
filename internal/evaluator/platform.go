package evaluator

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Platform evaluates PLATFORM_CONDITION and RUNTIME_CONDITION claims whose
// params declare snapshot facts — goos, goarch, go_version bounds — instead
// of code properties.
//
// GOOS/GOARCH comparisons consume the analyzed product build: only a valid,
// scoped product target can say which platform the product was built for. A
// host-default snapshot (or a partially declared target) supplies analysis
// context, not a product fact, so its platform mismatch can never produce
// FALSE — the check degrades to UNKNOWN.
//
// A go_version bound consumes the release toolchain (ReleaseGoVersion), which
// is an independently measured release fact: a contradiction stays usable
// even when the platform target is unknown.
type Platform struct{}

func (Platform) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionPlatform || cond.Kind == domain.ConditionRuntime
}

var goVersionBound = regexp.MustCompile(`^(<=|>=|<|>|=|==)?\s*v?(\d+\.\d+(?:\.\d+)?)$`)
var goVersionFrom = regexp.MustCompile(`go(\d+\.\d+(?:\.\d+)?)`)

// productGoVersion reports the toolchain that built the product release.
// Only ReleaseGoVersion counts: go.mod declares a language minimum and the
// snapshot's `go version` string describes the analysis environment — a
// `go_version` condition evaluated against either would silently claim a
// release fact we do not have, so an empty release version yields "".
func productGoVersion(p domain.ProductSnapshot) string {
	v := p.ReleaseGoVersion
	if m := goVersionFrom.FindStringSubmatch(v); m != nil {
		return "v" + m[1]
	}
	if semver.IsValid("v" + v) {
		return "v" + v
	}
	return ""
}

func (Platform) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.Platform",
	}
	type check struct {
		name  string
		want  string
		got   string
		ok    bool // the snapshot actually supplies an admissible product fact
		holds bool
	}
	// A platform fact describes the product build only under an admitted
	// target; a host default is analysis context.
	targetErr := domain.ValidateNegativeTarget(c.Product)
	var checks []check
	for _, name := range []string{"goos", "goarch"} {
		want := cond.Params[name]
		if want == "" {
			continue
		}
		got := c.Product.GOOS
		if name == "goarch" {
			got = c.Product.GOARCH
		}
		checks = append(checks, check{
			name: name, want: want, got: got,
			ok:    got != "" && targetErr == nil,
			holds: strings.EqualFold(got, want),
		})
	}
	if bound := cond.Params["go_version"]; bound != "" {
		if m := goVersionBound.FindStringSubmatch(strings.TrimSpace(bound)); m != nil {
			got := productGoVersion(c.Product)
			h := false
			if got != "" {
				op := m[1]
				cmp := semver.Compare(got, "v"+m[2])
				switch op {
				case "<":
					h = cmp < 0
				case "<=":
					h = cmp <= 0
				case ">":
					h = cmp > 0
				case ">=":
					h = cmp >= 0
				default: // =, ==
					h = cmp == 0
				}
			}
			checks = append(checks, check{
				name: "go_version", want: bound, got: got,
				ok: got != "", holds: h,
			})
		} else {
			claim.Limitations = append(claim.Limitations,
				"unparseable go_version bound: "+bound)
		}
	}
	if len(checks) == 0 {
		claim.Limitations = append(claim.Limitations,
			"condition declares no evaluable platform params (goos/goarch/go_version)")
		return claim
	}
	var missing, violated, platformUnusable []string
	for _, ch := range checks {
		if !ch.ok {
			missing = append(missing, ch.name)
			if ch.name == "goos" || ch.name == "goarch" {
				platformUnusable = append(platformUnusable, ch.name)
			}
			continue
		}
		if !ch.holds {
			violated = append(violated, fmt.Sprintf("%s: want %s, product is %s", ch.name, ch.want, ch.got))
		}
	}
	if len(platformUnusable) > 0 {
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"host/default platform facts (%s) cannot ground a product platform conclusion: %s",
			strings.Join(platformUnusable, ", "), targetErr))
	}
	switch {
	case len(violated) > 0:
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierSnapshotFactMismatch
		claim.Explanation = "snapshot fact mismatch: " + strings.Join(violated, "; ")
		claim.Limitations = append(claim.Limitations,
			"FALSE is a snapshot fact verdict, not a code-scope claim")
	case len(missing) > 0:
		claim.Limitations = append(claim.Limitations,
			"missing snapshot fact(s): "+strings.Join(missing, ", "))
		if slices.Contains(missing, "go_version") {
			claim.Limitations = append(claim.Limitations,
				"release toolchain unknown: pass --release-go-version or --binary; go.mod and the analysis toolchain are not the release toolchain")
		}
	default:
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf("%d platform fact(s) satisfied", len(checks))
	}
	return admitNegative(c, cond, claim)
}
