package evidencetools

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
)

// ---- usage-scope ----

// UsageScopeTool is the registered name of the dual build-closure usage
// check (B41): one advisory-declared package (or module-level aggregate)
// classified by membership in the recorded product and test build
// closures. It is a build-graph statement, never a source-usage verdict
// and never a safety claim.
const UsageScopeTool = "usage-scope"

// UsageScopeArgs is the tool's stable argument shape: the advisory module
// (required) and an optional declared package inside it. There is no
// symbol argument — the schema rejects it: the check classifies package
// build-closure membership, not symbol usage.
type UsageScopeArgs struct {
	Module  string `json:"module"`
	Package string `json:"package,omitempty"`
}

// UsageScopeData is the typed payload of a usage-scope observation: the
// build-closure classification plus the exact scope the classification
// ran under. test-only is reported only with
// product_absence_verification=VERIFIED (both paired closures complete);
// unknown is honest about being unclassified, except on a closed
// vendor-inventory derivation where it may carry
// product_absence_verification=VERIFIED_VENDOR_INVENTORY — exact
// subject absence from the product build closure under the recorded
// closed vendor inventory, still never a safety or runtime claim.
type UsageScopeData struct {
	Module  string `json:"module"`
	Package string `json:"package,omitempty"`

	ProductLinked bool   `json:"product_linked"`
	TestLinked    bool   `json:"test_linked"`
	UsageScope    string `json:"usage_scope"`

	ProductAbsenceVerification string `json:"product_absence_verification,omitempty"`

	// ClosureSource records which derivation produced the classification:
	// the paired `go list` streams or the offline vendor/source closure —
	// the auditor's evidence source.
	ClosureSource string `json:"closure_source,omitempty"`

	// ClosureSemantics names the fixed product-root rule both
	// derivations implement: product_all_packages — every applicable
	// first-party directory matched by ./... under the recorded build
	// context, never a selected shipped binary.
	ClosureSemantics string `json:"closure_semantics"`

	ProductPackageCount int `json:"product_package_count"`
	TestPackageCount    int `json:"test_package_count"`
	ProductRootCount    int `json:"product_root_count"`
	TestRootCount       int `json:"test_root_count"`

	CheckScope  string   `json:"check_scope"`
	Limitations []string `json:"limitations"`
}

// usageScopeCoverageRule names the closed scope a successful usage-scope
const usageScopeCoverageRule = "closure_semantics=product_all_packages — paired `go list` streams fully decoded and edge-closed: product closure = packages reachable from non-DepOnly ./... roots in `go list -deps -json ./...` (no -test); test closure = packages reachable from ForTest variants and synthetic .test driver mains in `go list -deps -test -json ./...`; the target is classified by membership in both closures"

// vendorClosureCoverageRule names the closed scope the offline
// vendor/source derivation examined — same product/test root semantics,
// derived without a toolchain subprocess and auditable from the recorded
// manifests alone. The VERIFIED_VENDOR_INVENTORY marker records the
// inventory-absence basis: absence from the product closure plus a
// complete consistency-checked vendor inventory, and for a module-level
// subject absence from every inventory leg.
const vendorClosureCoverageRule = "closure_semantics=product_all_packages — offline vendor/source closure, edge-closed: product closure = packages reachable by source-import edges from first-party dirs matched by ./... under the recorded build context; test closure = packages reachable from their internal/external test variants and synthetic .test driver mains; dependency resolution through vendor/modules.txt consistency-checked against go.mod; the target is classified by membership in both closures; product_absence_verification=VERIFIED_VENDOR_INVENTORY requires vendor_mode, the exact subject absent from both closures and the complete inventory — for a module-level subject absent from go.mod requires/replaces, modules.txt headers, the vendor tree and the first-party package set"

// usageScopeSharedLimits are the interpretation bounds EVERY usage-scope
// observation carries: a build-closure membership says nothing about
// runtime, dynamic loading, deployment exposure or safety.
var usageScopeSharedLimits = []string{
	"runtime execution, reflection, plugin loading, generated loading, deployment exposure and safety are out of scope for this classification",
}

// usageScopeKnownLimit is the interpretation bound a known classification
// carries: closure membership is not proof of source-level use.
const usageScopeKnownLimit = "the classification is build/linker-closure membership, not a source-level use check and not a runtime claim"

// usageScopeTestOnlyLimitFmt is the interpretation bound a test-only
// classification carries: the product absence is bounded to the recorded
// derivation under the recorded build context; %s is the derivation
// source (the go-list streams or the offline vendor/source closure).
const usageScopeTestOnlyLimitFmt = "product absence is verified only inside the recorded `%s` closure under the recorded build context — not a runtime, deployment or other-build-configuration claim"

// usageScopeUnknownLimit is the interpretation bound an unknown
// classification carries: absence from both recorded closures is not
// evidence in either direction.
const usageScopeUnknownLimit = "the target is absent from both recorded closures — the result is undetermined, not a proof of non-use or of safety"

// usageScopeVendorInventoryLimit is the interpretation bound a
// VERIFIED_VENDOR_INVENTORY-marked unknown carries: the absence is
// verified only inside the recorded closed vendor inventory under the
// recorded build context — never a runtime, deployment or
// other-build-configuration claim.
const usageScopeVendorInventoryLimit = "product absence is verified only inside the recorded closed vendor inventory under the recorded build context — not a runtime, deployment or other-build-configuration claim"

func (s *Session) usageScope(ctx context.Context, a UsageScopeArgs) (*Observation, error) {
	if a.Module == "" {
		return nil, fmt.Errorf("module is required")
	}
	vendored := vendorPresent(s.SnapshotRoot)
	var res affected.UsageScopeResult
	if vendored {
		// Offline derivation: vendor/modules.txt plus parsed source
		// imports under the recorded build context — the only closed
		// route on a vendored, network-isolated snapshot. The probe
		// fills the recorded build context (release toolchain, vendor
		// mode); its failure means the context is unverifiable and the
		// derivation fails closed as well.
		snap, err := s.probeSnapshot(ctx)
		if err != nil {
			return nil, fmt.Errorf("usage-scope product snapshot: %w", err)
		}
		res, err = affected.DeriveVendorUsageScope(ctx, s.SnapshotRoot, snap, a.Module, a.Package)
		if err != nil {
			// Any unreadable source, unresolvable import or
			// incomplete/inconsistent vendor metadata is an ERROR —
			// never a COMPLETE scope and never a verified negative.
			return nil, err
		}
	} else {
		if s.toolchainDenied() {
			return s.unsupported(UsageScopeTool,
				"toolchain execution (go list -deps -json ./...) requires the toolchain permission (--allow-toolchain) in the strict profile"), nil
		}
		if _, err := s.probeSnapshot(ctx); err != nil {
			return nil, err
		}
		var err error
		res, err = affected.ClassifyUsageScope(ctx, s.GoTool, s.SnapshotRoot, s.Build, a.Module, a.Package)
		if err != nil {
			return nil, err
		}
	}

	label := a.Module
	target := "module " + a.Module + " (module-level aggregate)"
	if a.Package != "" {
		label = a.Module + " | " + a.Package
		target = "package " + a.Package + " in module " + a.Module
	}
	coverage := usageScopeCoverageRule
	if res.Source == affected.VendorClosureSource {
		coverage = vendorClosureCoverageRule
	}
	sd := &ScopeDetails{
		SnapshotHash: s.SnapshotHash,
		SnapshotRoot: s.SnapshotRoot,
		ExternalSHA:  s.ExternalSHA,
		Subject:      label,
		BuildContext: s.buildContext(),
		CoverageRule: coverage,
		Extra: map[string]string{
			"closure_source":         res.Source,
			"closure_semantics":      affected.ClosureSemanticsProductAllPackages,
			"product_root_semantics": "non-DepOnly packages matched by ./... (ForTest variants and .test driver mains excluded)",
			"test_root_semantics":    "ForTest test variants and synthetic .test driver mains only",
			"product_package_count":  strconv.Itoa(res.ProductPackageCount),
			"test_package_count":     strconv.Itoa(res.TestPackageCount),
			"product_root_count":     strconv.Itoa(res.ProductRootCount),
			"test_root_count":        strconv.Itoa(res.TestRootCount),
		},
	}
	if res.Source == affected.VendorClosureSource {
		sd.Extra["product_closure_source"] = "first-party dirs matched by ./... under the recorded build context; edges from parsed source imports"
		sd.Extra["test_closure_source"] = "internal/external test variants and synthetic .test driver mains of the same dirs"
		sd.Extra["vendor_inventory_source"] = "vendor/modules.txt (consistency-checked against go.mod requires/replaces)"
	} else {
		sd.Extra["product_closure_cmd"] = "go list -deps -json ./... (no -test)"
		sd.Extra["test_closure_cmd"] = "go list -deps -test -json ./..."
	}

	var branchLimit string
	var fact string
	switch res.Usage {
	case affected.UsageScopeProduct:
		branchLimit = usageScopeKnownLimit
		fact = fmt.Sprintf("%s is reachable in the product build closure and not in the test closure (usage_scope=product)", target)
	case affected.UsageScopeTestOnly:
		branchLimit = fmt.Sprintf(usageScopeTestOnlyLimitFmt, res.Source)
		fact = fmt.Sprintf("%s is reachable in the test build closure and absent from the verified product closure (usage_scope=test-only, product_absence_verification=VERIFIED) — a bounded build-graph statement, never a safety claim", target)
	case affected.UsageScopeMixed:
		branchLimit = usageScopeKnownLimit
		fact = fmt.Sprintf("%s is reachable in both the product and the test build closures (usage_scope=mixed)", target)
	case affected.UsageScopeUnknown:
		if res.ProductAbsenceVerification == affected.ProductAbsenceVerificationVendorInventory {
			branchLimit = usageScopeVendorInventoryLimit
			fact = fmt.Sprintf("%s is absent from both recorded build closures under a complete consistency-checked vendor inventory (usage_scope=unknown, product_absence_verification=VERIFIED_VENDOR_INVENTORY) — a bounded build-graph statement, never a safety claim", target)
			break
		}
		fallthrough
	default:
		branchLimit = usageScopeUnknownLimit
		fact = fmt.Sprintf("%s is absent from both recorded build closures (usage_scope=unknown) — undetermined, never a non-use or safety claim", target)
	}
	dataLimits := append(append([]string(nil), res.Limitations...), branchLimit)
	dataLimits = append(dataLimits, usageScopeSharedLimits...)
	sort.Strings(dataLimits)
	data := UsageScopeData{
		Module:                     res.Module,
		Package:                    res.Package,
		ProductLinked:              res.ProductLinked,
		TestLinked:                 res.TestLinked,
		UsageScope:                 string(res.Usage),
		ProductAbsenceVerification: res.ProductAbsenceVerification,
		ClosureSource:              res.Source,
		ClosureSemantics:           affected.ClosureSemanticsProductAllPackages,
		ProductPackageCount:        res.ProductPackageCount,
		TestPackageCount:           res.TestPackageCount,
		ProductRootCount:           res.ProductRootCount,
		TestRootCount:              res.TestRootCount,
		CheckScope:                 res.CheckScope,
		Limitations:                dataLimits,
	}
	lims := append([]string(nil), dataLimits...)
	sort.Strings(lims)
	return s.ok(UsageScopeTool, fact, res.CheckScope+"; target "+strings.TrimSuffix(target, " (module-level aggregate)"),
		CompletenessComplete, data, sd, lims), nil
}
