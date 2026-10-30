package evidencetools

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// ---- symbol-unreachability ----

// SymbolUnreachabilityTool is the registered name of the bounded
// symbol-unreachability evidence check (Task 5): an advisory-declared module
// and its exact symbol set, proven unreachable from the recorded product
// scope only when every required subcheck closes.
const SymbolUnreachabilityTool = "symbol-unreachability"

// SymbolUnreachabilityArgs is the tool's stable argument shape: the advisory
// module for provenance and the exact declared symbol set — the only
// granularity this check answers.
type SymbolUnreachabilityArgs struct {
	Module   string             `json:"module"`
	Subjects []domain.SymbolRef `json:"subjects"`
}

// SymbolUnreachabilityData is the typed payload of a symbol-unreachability
// observation: the raw proof record. It carries no verdict field — the
// payload is evidence for CLOSE_NO_EXPLOIT_PATH style evaluation only and
// can never encode NOT_AFFECTED.
type SymbolUnreachabilityData struct {
	Result goanalysis.UnreachabilityResult `json:"result"`
}

// symbolUnreachabilityCoverageRule names the closed scope a complete
// unreachability proof examined — the coverage claim a COMPLETE observation
// makes and an auditor can recheck.
const symbolUnreachabilityCoverageRule = "bounded symbol unreachability: every declared subject's declaration resolved in the loaded dependency version; every loaded product package and function root enumerated and scanned for references, callers, may-call candidates, interface dispatch, dynamic markers and build-gated references; dep-internal callers, unbounded surfaces and module-internal reach from product-used API entries checked — all inventories closed. Sibling-method liveness is recorded by the source layer as an observation; it is not a deadness blocker — the admitted defect-semantics contract decides whether the dead symbol's invocation is necessary"

// symbolUnreachabilityCompleteLimits are the interpretation bounds a
// COMPLETE observation still carries: the proof is bounded to the recorded
// product-source/build scope and the subject's module internals, and it can
// never ground a not-affected claim.
var symbolUnreachabilityCompleteLimits = []string{
	"a complete result means the declared symbols are unreachable from the recorded product scope only — it is evidence for a no-exploit-path dismissal, never a not-affected or negative-applicability claim",
	"scope is the recorded build context (GOOS/GOARCH/build tags); alternate configurations are out of scope",
	"dynamic mechanisms outside the modeled markers (unmodeled reflection, plugin loading, generated loading, cgo, unsupported transports) are out of proof scope",
}

func (s *Session) symbolUnreachability(ctx context.Context, a SymbolUnreachabilityArgs) (*Observation, error) {
	if a.Module == "" {
		return nil, fmt.Errorf("module is required")
	}
	if len(a.Subjects) == 0 {
		return nil, fmt.Errorf("at least one subject is required")
	}
	if s.toolchainDenied() || s.GoTool == nil { return s.unsupported(SymbolUnreachabilityTool, "bounded unreachability requires a complete package inventory and toolchain capability"), nil }
	if _, err := s.probeSnapshot(ctx); err != nil { return nil, err }
	measurement := affected.MeasurePackageInventory(ctx, s.GoTool, s.SnapshotRoot, s.Build, false)
	res, err := s.Source.VerifyUnreachableWithInventory(ctx, a.Module, a.Subjects, measurement)
	if err != nil {
		return nil, err
	}
	if res.Complete {
		if err := res.ValidateComplete(domain.EffectiveBuildContext(s.Build)); err != nil {
			res.Complete = false
			res.Limitations = append(res.Limitations, "captured unreachability admission failed: " + err.Error())
		}
	}

	names := make([]string, 0, len(a.Subjects))
	for _, sub := range a.Subjects {
		names = append(names, sub.Package+"."+sub.Symbol)
	}
	sd, lims, serr := s.sourceScope(ctx, a.Module+" | "+strings.Join(names, ", "))
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

	sd.Extra["subject_count"] = strconv.Itoa(len(a.Subjects))
	// Which module graph grounds the version axis — the artifact/member/
	// build-info digests, never credentials — when the snapshot carries
	// release evidence for this advisory.
	for k, v := range ReleaseProvenanceExtra(s.snapshotReleaseView()) {
		sd.Extra[k] = v
	}

	data := SymbolUnreachabilityData{Result: res}

	comp := CompletenessUnknown
	var fact string
	switch {
	case res.ValidateComplete(domain.EffectiveBuildContext(s.Build)) == nil:
		sd.CoverageRule = symbolUnreachabilityCoverageRule
		comp = CompletenessComplete
		lims = append(lims, symbolUnreachabilityCompleteLimits...)
		fact = fmt.Sprintf("all %d declared symbol(s) of module %s resolved and unreachable inside the recorded product scope (%d product package(s), %d function root(s), %d entrypoint(s) examined; no open gap)",
			len(res.Subjects), a.Module, len(res.ProductPackages), len(res.ProductFunctionRoots), len(res.Entrypoints))
	case len(res.ProductReferences) > 0 || len(res.ModuleReachable) > 0:
		// Positive reach evidence: the check ran and observed a concrete
		// path — the scope was covered even though the proof cannot close.
		comp = CompletenessPartial
		fact = fmt.Sprintf("symbol-unreachability for module %s is disproven: %d product reference(s) and %d module-internal chain(s) reach the declared subject(s)",
			a.Module, len(res.ProductReferences), len(res.ModuleReachable))
	default:
		// Unclosed scope or unresolved declarations: UNKNOWN with the named
		// limitations in the payload — absence is never claimed.
		// res.Limitations is already the case-specific gap list (the
		// fixed proof boundaries ride in res.Boundaries); name the gaps
		// on the observation's limitations too, matching package-usage:
		// a count alone never surfaces why the proof stayed open.
		fact = fmt.Sprintf("symbol-unreachability for module %s is UNKNOWN: %d open limitation(s) (declaration_complete=%v references=%d may_call=%d dep_sites=%d dispatch=%d markers=%d gated=%d opaque=%v unbounded=%v)",
			a.Module, len(res.Limitations), res.DeclarationComplete, len(res.ProductReferences), len(res.MayCallSites),
			len(res.DependencyCallSites), len(res.InterfaceDispatchSites), len(res.DynamicMarkers),
			len(res.GatedReferences), res.Opaque, res.Unbounded)
		lims = append(lims, res.Limitations...)
	}
	return s.ok(SymbolUnreachabilityTool, fact,
		fmt.Sprintf("product packages of %s plus internals of module %s under the recorded build context", s.SnapshotRoot, a.Module),
		comp, data, sd, lims), nil
}
