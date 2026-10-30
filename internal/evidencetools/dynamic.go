package evidencetools

import (
	"context"
	"errors"
	"fmt"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// ---- scan_dynamic ----

type dynamicData struct {
	Markers []goanalysis.DynamicMarker `json:"dynamic_markers"`
	Count   int                        `json:"count"`
}

func (s *Session) scanDynamic(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	markers, err := s.Source.ScanDynamic(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"dynamic-marker scan covers product packages only: reflect/unsafe/plugin/linkname imports and stores, func-value references to the subject",
		"markers in dependency code, or dynamic mechanisms the scan does not model (e.g. go:generate, cgo), are not covered")
	return s.ok("scan_dynamic",
		fmt.Sprintf("%d dynamic-dispatch marker(s) near %s.%s in product packages", len(markers), ref.Package, ref.Symbol),
		fmt.Sprintf("product packages of %s", s.SnapshotRoot),
		CompletenessPartial,
		dynamicData{Markers: markers, Count: len(markers)}, sd, lims), nil
}

// ---- interface_dispatch_sites ----

type callSitesData struct {
	CallSites []domain.CallSite `json:"call_sites"`
	Count     int               `json:"count"`
}

func (s *Session) interfaceDispatchSites(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	sites, err := s.Source.InterfaceDispatchSites(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"interface dispatch sites invoke the subject's method name through an interface value; whether they dispatch to this implementation is not resolved here")
	return s.ok("interface_dispatch_sites",
		fmt.Sprintf("%d interface-dispatch site(s) that could invoke %s.%s", len(sites), ref.Package, ref.Symbol),
		fmt.Sprintf("interface method call sites in loaded scope of %s", s.SnapshotRoot),
		CompletenessPartial,
		callSitesData{CallSites: sites, Count: len(sites)}, sd, lims), nil
}

// ---- gated_refs ----

func (s *Session) gatedRefs(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	sites, err := s.Source.GatedRefs(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"gated references are references inside files excluded by the current build tags/configuration; they are NOT reachable under this build context but are reachable under other tag sets")
	return s.ok("gated_refs",
		fmt.Sprintf("%d build-tag-gated reference(s) to %s.%s outside the current build configuration", len(sites), ref.Package, ref.Symbol),
		fmt.Sprintf("files excluded by build context (GOOS=%s GOARCH=%s tags=%v) of %s",
			s.Build.GOOS, s.Build.GOARCH, s.Build.BuildTags, s.SnapshotRoot),
		CompletenessPartial,
		callSitesData{CallSites: sites, Count: len(sites)}, sd, lims), nil
}

// ---- dep_invocation_state ----

type depInvocationData struct {
	CallersInsideModule int  `json:"callers_inside_module"`
	SiblingLive         bool `json:"sibling_live"`
	Unbounded           bool `json:"unbounded"`
}

func (s *Session) depInvocationState(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	callers, siblingLive, unbounded, err := s.Source.DepInvocationState(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"dep-internal invocation state covers the subject's own module; callers reachable transitively inside it are deadness-checked, but callers in other modules are out of scope")
	if unbounded {
		lims = append(lims, "subject is exported and imported by other modules — the caller set is UNBOUNDED; zero in-module callers cannot ground a negative")
	}
	return s.ok("dep_invocation_state",
		fmt.Sprintf("%s.%s: %d in-module caller(s), sibling pipeline live=%v, unbounded=%v", ref.Package, ref.Symbol, callers, siblingLive, unbounded),
		fmt.Sprintf("module containing package %s", ref.Package),
		CompletenessPartial,
		depInvocationData{CallersInsideModule: callers, SiblingLive: siblingLive, Unbounded: unbounded},
		sd, lims), nil
}

// ---- module_usage ----

type moduleUsageArgs struct {
	Module string `json:"module"`
}

func (s *Session) moduleUsage(ctx context.Context, a moduleUsageArgs) (*Observation, error) {
	if a.Module == "" {
		return nil, fmt.Errorf("module path is required")
	}
	sites, err := s.Source.ModuleUsage(ctx, a.Module)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, a.Module)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"module usage enumerates product call sites whose callee package is owned by the module; nested modules and unresolved owners are surfaced via module_owner rather than silently attributed")
	return s.ok("module_usage",
		fmt.Sprintf("%d product call site(s) into module %s", len(sites), a.Module),
		fmt.Sprintf("product packages of %s calling packages of module %s", s.SnapshotRoot, a.Module),
		CompletenessPartial,
		callSitesData{CallSites: sites, Count: len(sites)}, sd, lims), nil
}

// ---- module_internal_reach ----

type moduleInternalReachArgs struct {
	Module   string             `json:"module"`
	Entries  []string           `json:"entries"`
	Subjects []domain.SymbolRef `json:"subjects"`
}

type moduleInternalReachData struct {
	Chains   map[string][]string `json:"chains"`
	Opaque   bool                `json:"opaque"`
	Complete bool                `json:"complete"`
	Reached  int                 `json:"reached"`
	Missing  []string            `json:"unreached_subjects"`
}

func (s *Session) moduleInternalReach(ctx context.Context, a moduleInternalReachArgs) (*Observation, error) {
	if a.Module == "" {
		return nil, fmt.Errorf("module path is required")
	}
	if len(a.Entries) == 0 || len(a.Subjects) == 0 {
		return nil, fmt.Errorf("entries and subjects are required")
	}
	res, err := s.Source.ModuleInternalReach(ctx, a.Module, a.Entries, a.Subjects)
	if err != nil {
		return nil, err
	}
	chains := res.Reachable
	opaque := res.Opaque
	sd, lims, serr := s.sourceScope(ctx, a.Module)
	if serr != nil {
		return nil, serr
	}
	var missing []string
	for _, sub := range a.Subjects {
		key := sub.Package + "." + sub.Symbol
		if _, ok := chains[key]; !ok {
			missing = append(missing, key)
		}
	}
	lims = append(lims,
		"intra-module reachability is computed without BuildFlags even when the session sets build tags: tagged-out files are treated as present, so reachability under tagged builds may be over-reported")
	if opaque {
		lims = append(lims, "opaque dispatch inside the module (unresolvable func-value/interface calls): unreached subjects are UNKNOWN, not absent")
	}
	if !res.Complete {
		lims = append(lims, "intra-module census is incomplete (load/type-check errors, dynamic materialization, or a truncated package-load budget): unreached subjects are UNKNOWN, not absent")
	}
	// Discovered positive chains stay usable even when the rest of the scan
	// is incomplete; only the negative direction depends on completeness.
	comp := CompletenessPartial
	if opaque || !res.Complete {
		comp = CompletenessUnknown
	}
	fact := fmt.Sprintf("%d/%d subject(s) reached inside module %s from given entries; opaque=%v complete=%v",
		len(chains), len(a.Subjects), a.Module, opaque, res.Complete)
	return s.ok("module_internal_reach", fact,
		fmt.Sprintf("call graph inside module %s (source-loaded packages)", a.Module),
		comp,
		moduleInternalReachData{Chains: chains, Opaque: opaque, Complete: res.Complete, Reached: len(chains), Missing: missing},
		sd, lims), nil
}

// ---- check_call_site_guard ----

type callSiteGuardArgs struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`
}

type callSiteGuardData struct {
	Gated    bool   `json:"gated"`
	DeadCode bool   `json:"dead_code"`
	Detail   string `json:"detail"`
}

func (s *Session) checkCallSiteGuard(ctx context.Context, a callSiteGuardArgs) (*Observation, error) {
	if a.File == "" || a.Line <= 0 {
		return nil, fmt.Errorf("file and line are required")
	}
	site := domain.CallSite{File: a.File, Line: a.Line, Column: a.Column}
	gated, dead, detail, err := s.Source.CheckCallSiteGuard(ctx, site)
	if err != nil {
		if errors.Is(err, goanalysis.ErrCallSiteNotFound) {
			return s.callSiteScopeObs("check_call_site_guard", err), nil
		}
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, fmt.Sprintf("%s:%d", a.File, a.Line))
	if serr != nil {
		return nil, serr
	}
	comp := CompletenessComplete
	if len(sd.SkippedPackages) > 0 {
		comp = CompletenessPartial
	}
	return s.ok("check_call_site_guard",
		fmt.Sprintf("call site %s:%d: gated=%v dead_code=%v (%s)", a.File, a.Line, gated, dead, detail),
		fmt.Sprintf("guard analysis of the enclosing function at %s:%d", a.File, a.Line),
		comp,
		callSiteGuardData{Gated: gated, DeadCode: dead, Detail: detail}, sd, lims), nil
}

// ---- field_assignments ----

type fieldAssignmentsData struct {
	Assignments []domain.ConfigAssignment `json:"assignments"`
	Count       int                       `json:"count"`
	Writers domain.ConfigWriterEvidence `json:"writers"`
}

func (s *Session) fieldAssignments(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	var inventory affected.PackageInventoryMeasurement
	if !s.toolchainDenied() && s.GoTool != nil {
		if _, err := s.probeSnapshot(ctx); err != nil { return nil, err }
		inventory = affected.MeasurePackageInventory(ctx, s.GoTool, s.SnapshotRoot, s.Build, false)
	}
	writers, err := s.Source.ConfigWritersWithInventory(ctx, ref, inventory)
	if err != nil {
		return nil, err
	}
	assignments := writers.Assignments
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims, writers.Blockers...)
	lims = append(lims, "configuration writer observations do not prove effective value or safety")
	return s.ok("field_assignments",
		fmt.Sprintf("%d assignment site(s) to %s.%s in product packages", len(assignments), ref.Package, ref.Symbol),
		fmt.Sprintf("product packages of %s", s.SnapshotRoot),
		CompletenessPartial,
		fieldAssignmentsData{Assignments: assignments, Count: len(assignments), Writers: writers}, sd, lims), nil
}

// ---- check_missing_call ----

type checkMissingCallArgs struct {
	Check    domain.SymbolRef `json:"check"`
	Pipeline domain.SymbolRef `json:"pipeline"`
}

type missingCallData struct {
	// Missing is the historical boolean projection; Status is the typed
	// observation and distinguishes "check invoked" (PRESENT) from "not
	// established" — an unreached pipeline or truncated search is never
	// evidence that the check is present.
	Missing       bool              `json:"missing"`
	Status        string            `json:"status"`
	Detail        string            `json:"detail"`
	LiveCallSites []domain.CallSite `json:"live_call_sites"`
}

func (s *Session) checkMissingCall(ctx context.Context, a checkMissingCallArgs) (*Observation, error) {
	if a.Check.Package == "" || a.Check.Symbol == "" || a.Pipeline.Package == "" || a.Pipeline.Symbol == "" {
		return nil, fmt.Errorf("check and pipeline symbol refs are required")
	}
	status, detail, sites, err := s.Source.CheckMissingCall(ctx, a.Check, a.Pipeline)
	if err != nil {
		return nil, err
	}
	missing := status == domain.MissingCallOmitted
	sd, lims, serr := s.sourceScope(ctx, a.Check.Package+"."+a.Check.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"missing-call analysis is bounded to the pipeline's live receiver sites in the loaded scope; a 'missing=false' result does not prove the check runs on all paths")
	return s.ok("check_missing_call",
		fmt.Sprintf("check %s.%s vs pipeline %s.%s: missing=%v (%s)", a.Check.Package, a.Check.Symbol, a.Pipeline.Package, a.Pipeline.Symbol, missing, detail),
		fmt.Sprintf("live receiver call sites of %s.%s in the loaded scope", a.Pipeline.Package, a.Pipeline.Symbol),
		CompletenessPartial,
		missingCallData{Missing: missing, Status: string(status), Detail: detail, LiveCallSites: sites}, sd, lims), nil
}

// ---- sensitive_fields ----

type sensitiveFieldsArgs struct {
	Package string `json:"package"`
}

type sensitiveFieldsData struct {
	Fields []domain.SymbolRef `json:"fields"`
	Count  int                `json:"count"`
}

func (s *Session) sensitiveFields(ctx context.Context, a sensitiveFieldsArgs) (*Observation, error) {
	if a.Package == "" {
		return nil, fmt.Errorf("package path is required")
	}
	fields, err := s.Source.SensitiveFields(ctx, a.Package)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, a.Package)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"sensitive-field detection is name-based (credential-named exported fields); non-obvious field names are not covered")
	return s.ok("sensitive_fields",
		fmt.Sprintf("%d credential-named exported field(s) in package %s", len(fields), a.Package),
		fmt.Sprintf("exported field declarations of package %s", a.Package),
		CompletenessPartial,
		sensitiveFieldsData{Fields: fields, Count: len(fields)}, sd, lims), nil
}
