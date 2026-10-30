package evidencetools

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// ---- package-usage ----

// PackageUsageTool is the registered name of the bounded package/symbol
// usage check (Task 3): one advisory-declared package or symbol, checked
// against the product source closure under the recorded build context.
const PackageUsageTool = "package-usage"

// packageUsageArgs is the tool's stable argument shape: the advisory
// module for provenance, the declared package (required) and an optional
// declared symbol inside it.
type packageUsageArgs struct {
	Module  string `json:"module"`
	Package string `json:"package"`
	Symbol  string `json:"symbol,omitempty"`
}

// PackageUsageData is the typed payload of a package-usage observation:
// the three-state usage verdict plus the bounded scope and the gap list
// that produced it. NOT_USED is reported only alongside a VERIFIED
// negative verification; an UNKNOWN carries the scope gaps, never a
// silent empty result.
type PackageUsageData struct {
	Module               string            `json:"module"`
	Package              string            `json:"package"`
	Symbol               string            `json:"symbol,omitempty"`
	Present              bool              `json:"present"`
	Usage                string            `json:"usage"`
	ProductSites         []domain.CallSite `json:"product_sites,omitempty"`
	ImportSites          []domain.CallSite `json:"import_sites,omitempty"`
	NegativeVerification string            `json:"negative_verification,omitempty"`
	CheckScope           string            `json:"check_scope"`
	Limitations          []string          `json:"limitations"`
}

// packageUsageUsedLimit is the interpretation bound every USED
// observation carries: a recorded static site proves code-level use,
// nothing more.
const packageUsageUsedLimit = "positive static usage does not establish runtime execution or attacker reachability"

// packageUsageNegativeLimits are the interpretation bounds every VERIFIED
// NOT_USED observation carries: the negative is bounded to the recorded
// product-source/build scope and never claims runtime or deployment facts.
var packageUsageNegativeLimits = []string{
	"negative verification is bounded to statically resolved product-source imports/references/calls under the recorded build context",
	"does not prove runtime non-use, reflection/plugin/generated loading, or deployment absence",
}

// packageUsageUnknownLimit is the interpretation bound every UNKNOWN
// observation carries: an unclosed scope proves nothing in either
// direction. The observation's limitations keep this generic statement
// first and then name each case-specific scope gap verbatim
// (UsageScopeGaps over the payload), so a reader sees why the check
// stayed open rather than only that it did.
const packageUsageUnknownLimit = "scope is not closed; absence is not evidence of non-use"

// packageUsageNegativeCoverageRule names the closed scope a VERIFIED
// NOT_USED verdict examined — the coverage rule the COMPLETE status
// claims and an auditor can recheck.
const packageUsageNegativeCoverageRule = "closed negative verification: every loaded non-test product package scanned for imports/references/calls; build-gated files scanned syntactically; interface-dispatch, dynamic-marker, skipped-package and load-budget gaps checked — all gaps closed"

// packageUsageAbsentCoverageRule names the closed scope a VERIFIED
// NOT_USED verdict on an unlinked package examined: provable absence
// inside a complete product closure is positive evidence of non-use —
// a dispatch site cannot invoke a method of a package outside the link
// set, and no product source can import or reference it.
const packageUsageAbsentCoverageRule = "closed negative verification: complete product closure (no skipped or failed package, load budget unexhausted) with the target package provably absent from the linked import closure; build-gated files and dynamic-marker gaps checked — all gaps closed"

func (s *Session) packageUsage(ctx context.Context, a packageUsageArgs) (*Observation, error) {
	if a.Package == "" {
		return nil, fmt.Errorf("package is required")
	}
	subject := domain.SymbolRef{Package: a.Package, Symbol: a.Symbol}
	res, err := s.Source.ProductUsage(ctx, a.Module, subject)
	if err != nil {
		return nil, err
	}
	label := a.Package
	if a.Symbol != "" {
		label += "." + a.Symbol
	}
	if a.Module != "" {
		label = a.Module + " | " + label
	}
	sd, lims, serr := s.sourceScope(ctx, label)
	if serr != nil {
		return nil, serr
	}
	loaded, lerr := s.Source.ProductPackagePaths(ctx)
	if lerr != nil {
		return nil, lerr
	}
	sd.Packages = loaded
	if sd.Extra == nil {
		sd.Extra = map[string]string{}
	}
	sd.Extra["loaded_package_count"] = strconv.Itoa(len(loaded))
	sd.Extra["skipped_package_count"] = strconv.Itoa(len(sd.SkippedPackages))

	data := PackageUsageData{
		Module:               res.Module,
		Package:              res.Package,
		Symbol:               res.Symbol,
		Present:              res.Present,
		Usage:                string(res.Usage),
		ProductSites:         res.ProductSites,
		ImportSites:          res.ImportSites,
		NegativeVerification: string(res.NegativeVerification),
		CheckScope:           res.CheckScope,
		Limitations:          res.Limitations,
	}
	// specificGaps are the case-specific scope gaps that produced an
	// UNKNOWN verdict — everything in the payload except the fixed
	// baseline interpretation bounds. Fact text and observation
	// limitations must name exactly these: counting the full limitation
	// list conflates four always-present caveats with the actual gap,
	// and the count is unreadable as "why is this open" without the
	// named gaps.
	specificGaps := goanalysis.UsageScopeGaps(res.Limitations)

	target := res.Package
	if res.Symbol != "" {
		target += "." + res.Symbol
	}
	fact := fmt.Sprintf("package-usage for %s is undetermined (%d gap(s) open: %s)",
		target, len(specificGaps), strings.Join(specificGaps, "; "))
	if len(specificGaps) == 0 {
		fact = fmt.Sprintf("package-usage for %s is undetermined (0 gap(s) open)", target)
	}
	comp := CompletenessUnknown
	switch res.Usage {
	case goanalysis.PackageUsageUsed:
		if res.Symbol == "" {
			fact = fmt.Sprintf("package %s used by product source: %d import site(s), %d reference site(s)",
				res.Package, len(res.ImportSites), len(res.ProductSites))
		} else {
			fact = fmt.Sprintf("symbol %s used by product source: %d reference/call site(s)",
				target, len(res.ProductSites))
		}
		comp = CompletenessPartial
		lims = append(lims, packageUsageUsedLimit)
	case goanalysis.PackageUsageNotUsed:
		if res.Present {
			fact = fmt.Sprintf("%s is present in the linked product import closure but no product-source use was found (negative verification VERIFIED, scope bounded to %s)",
				target, res.CheckScope)
			sd.CoverageRule = packageUsageNegativeCoverageRule
		} else {
			fact = fmt.Sprintf("%s is absent from the linked product import closure and the recorded product closure is complete — no product source can use it (negative verification VERIFIED, scope bounded to %s)",
				target, res.CheckScope)
			sd.CoverageRule = packageUsageAbsentCoverageRule
		}
		comp = CompletenessComplete
		lims = append(lims, packageUsageNegativeLimits...)
	default:
		// UNKNOWN — INSUFFICIENT_SCOPE (or any unclosed shape the
		// primitive reports): the open gaps ride in the payload, the
		// observation claims no coverage either way. The generic
		// interpretation bound stays first, then every specific gap is
		// named verbatim so the observation's limitations surface why
		// the check stayed open — never just a count.
		lims = append(lims, packageUsageUnknownLimit)
		lims = append(lims, specificGaps...)
	}
	scope := res.CheckScope
	if scope == "" {
		scope = "product source closure of " + s.SnapshotRoot
	}
	scope += "; target " + target
	if res.Module != "" {
		scope += fmt.Sprintf(" of module %s", res.Module)
	}
	return s.ok(PackageUsageTool, fact, scope, comp, data, sd, lims), nil
}
