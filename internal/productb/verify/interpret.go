package verify

import (
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// Interpret converts one recorded tool observation into one or more
// contract Observations, one per capability binding the tool serves for
// the claim shape under evaluation. Interpretation is a pure function of
// the recorded payload — live execution and replay produce identical
// contract observations from the same bytes, which is what makes replay
// able to rebuild the graph without an LLM.
//
// A tool that cannot serve the claim's shape yields no observations; the
// claim then records no_observations for that record.
type interpInput struct {
	// Observation is the recorded tool result under interpretation.
	Observation *triage.RecordedObservation
	// Shape is the claim shape being evaluated (the predicate the query
	// asked).
	Shape claimshape.Shape
	// ClaimSubject is the claim's canonical subject for coverage checks.
	ClaimSubject claimshape.Subject
}

// toolBinding maps one tool to one capability view of its observation.
// A single tool may serve several capabilities — verify_code_absence is
// both a declaration check and the scope-closure certificate — so the
// binding table is a list per tool, interpreted independently.
type toolBinding struct {
	capability string
	interp     func(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string)
	// closedScope computes whether this capability view proves a closed
	// universe for the decoded payload; nil means never closed.
	closedScope func(data, top map[string]any) bool
}

// toolBindings is the closed tool → capabilities table. Every entry names
// a generic check class — nothing keys on package, advisory or symbol.
var toolBindings = map[string][]toolBinding{
	"verify_code_absence": {
		{CapDeclarationResolver, interpVerifyCodeAbsence, closureCompleteOf},
		{CapScopeClosed, interpClosureCert, closureCompleteOf},
	},
	"symbol-unreachability": {
		{CapNegativeReachability, interpUnreachability, kernelCompleteOf},
		{CapScopeClosed, interpKernelClosureCert, kernelCompleteOf},
	},
	"find_symbol": {{CapDeclarationResolver, interpFindSymbol, func(data, top map[string]any) bool { return true }}},
	"get_module_version": {
		{CapModuleVersionResolver, interpModuleVersion, alwaysClosed},
		{CapScopeClosed, interpModuleUniverse, alwaysClosed},
	},
	"get_dependency_graph": {
		{CapModuleVersionResolver, interpDependencyGraph, alwaysClosed},
		{CapScopeClosed, interpModuleUniverse, alwaysClosed},
	},
	"find_callers":             {{CapReachability, interpReachProbe, nil}},
	"find_may_callers":         {{CapReachability, interpReachProbe, nil}},
	"find_references":          {{CapReachability, interpReachProbe, nil}},
	"find_dep_callers":         {{CapReachability, interpReachProbe, nil}},
	"module_usage":             {{CapReachability, interpReachProbe, nil}},
	"module_internal_reach":    {{CapReachability, interpModuleReach, nil}},
	"dep_invocation_state":     {{CapReachability, interpDepInvocation, nil}},
	"interface_dispatch_sites": {{CapReachability, interpGapOnly, nil}},
	"scan_dynamic":             {{CapReachability, interpGapOnly, nil}},
	"run_govulncheck":          {{CapReachability, interpGovulncheck, nil}},
	"trace_argument":           {{CapProvenanceTracer, interpTraceArgument, nil}},
	"check_call_site_guard":    {{CapGuardChecker, interpCallSiteGuard, nil}},
	"find_validations":         {{CapGuardChecker, interpValidations, nil}},
	"check_missing_call":       {{CapGuardChecker, interpMissingCall, nil}},
	"field_assignments":        {{CapConfigurationAnalyzer, interpFieldAssignments, nil}},
	"gated_refs":               {{CapBuildContext, interpGatedRefs, nil}},
	"get_product_snapshot":     {{CapBuildContext, interpProductSnapshot, nil}},
	"get_vulnerability":        {{CapAdvisoryRecord, interpAdvisoryRecord, nil}},
	"get_advisory":             {{CapAdvisoryRecord, interpAdvisoryRecord, nil}},
}

// closureCompleteOf reads the code-absence closure completeness flag.
func closureCompleteOf(data, top map[string]any) bool {
	_, _, complete, _ := scopeHashes(data, top)
	return complete
}

// kernelCompleteOf reads the unreachability kernel's completeness flag.
func kernelCompleteOf(data, top map[string]any) bool {
	res := mapOf(data, "result")
	if res == nil {
		res = data
	}
	c, _ := boolOf(res, "complete")
	return c
}

func alwaysClosed(data, top map[string]any) bool { return true }

// interpretRecorded runs every capability binding of one recorded
// observation against the claim shape and returns the contract
// observations. A tool that cannot serve the shape yields none.
func interpretRecorded(in interpInput) []Observation {
	o := in.Observation
	bindings, ok := toolBindings[o.Tool]
	if !ok {
		return nil
	}
	data, top := payloadEnvelope(o)
	var out []Observation
	for _, b := range bindings {
		res, gaps, covered, roles := b.interp(in, data, top)
		gaps = append(gaps, payloadGaps(data, top)...)
		scopeHash, _, _, _ := scopeHashes(data, top)
		obs := Observation{
			Capability:       b.capability,
			Result:           res,
			Completeness:     o.Completeness,
			ScopeHash:        scopeHash,
			SnapshotHash:     snapshotHashOf(o, data, top),
			BuildContextHash: buildContextHashOf(o, data, top),
			ToolVersion:      o.Tool + "@archive",
			RunID:            o.RunID,
			Attempt:          o.Attempt,
			SourceID:         o.ID,
			PayloadHash:      o.DataSHA256,
			CoveredSubjects:  covered,
			SubjectRoles:     roles,
			OpenGaps:         dedup(gaps),
			Limitations:      append([]string(nil), o.Limitations...),
			EvidenceRefs:     append([]string(nil), o.EvidenceRefs...),
		}
		if b.closedScope != nil && b.closedScope(data, top) {
			obs.ClosedScope = true
		}
		out = append(out, obs)
	}
	return out
}

// interpClosureCert reads the embedded import-closure report as the
// scope.closed certificate: a complete closure SUPPORTS both
// closure.complete and the closed-scope conjunction other shapes
// require; an incomplete one REFUTES closure.complete and never
// certifies a universal.
func interpClosureCert(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	sets := decodeSubjectSets(data)
	_, _, complete, gaps := scopeHashes(data, top)
	if complete {
		return ResultSupports, gaps, sets.Checked, sets.Roles
	}
	return ResultRefutes, gaps, sets.Checked, sets.Roles
}

// interpKernelClosureCert certifies the kernel's recorded scope: a
// complete unreachability proof closes the invocation universe it names.
func interpKernelClosureCert(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	res := mapOf(data, "result")
	if res == nil {
		res = data
	}
	var covered []claimshape.Subject
	for _, item := range listOf(res, "subjects") {
		if m, ok := item.(map[string]any); ok {
			if s := subjectFromData(m); s.Name != "" {
				covered = append(covered, s)
			}
		}
	}
	var gaps []string
	if op, ok := boolOf(res, "opaque"); ok && op {
		gaps = append(gaps, "opaque_dispatch")
	}
	if ub, ok := boolOf(res, "unbounded"); ok && ub {
		gaps = append(gaps, "unbounded_surface")
	}
	if c, ok := boolOf(res, "complete"); ok && c {
		return ResultSupports, gaps, covered, nil
	}
	return ResultRefutes, gaps, covered, nil
}

// interpModuleUniverse certifies the dependency-graph universe: an
// enumerated module list is a closed universe for module-membership
// questions.
func interpModuleUniverse(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	return ResultSupports, nil, nil, nil
}

// ---- interpreters: pure payload → Result mappings ----

// interpVerifyCodeAbsence interprets the code-absence payload. Result
// depends on the claim shape:
//   - subject.absent / control.absent: absence proven → SUPPORTS,
//     counterexample (present subject) → REFUTES, undecided → UNKNOWN;
//   - closure.complete: the embedded closure report decides;
//   - subject.declared: a declared subject SUPPORTS, a closed proof of
//     absence REFUTES.
func interpVerifyCodeAbsence(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	sets := decodeSubjectSets(data)
	covered := sets.Checked
	if len(covered) == 0 {
		covered = sets.Expected
	}
	var gaps []string
	gaps = appendGaps(gaps, data)
	switch in.Shape {
	case claimshape.ShapeClosureComplete:
		_, _, complete, _ := scopeHashes(data, top)
		if complete {
			return ResultSupports, gaps, covered, sets.Roles
		}
		return ResultRefutes, gaps, covered, sets.Roles
	case claimshape.ShapeSubjectDeclared:
		if len(sets.Present) > 0 {
			return ResultSupports, gaps, sets.Present, sets.Roles
		}
		if len(sets.Present) == 0 && len(sets.Checked) > 0 && sameSubjectSet(sets.Expected, sets.Checked) && len(sets.Absent) == len(sets.Checked) {
			return ResultRefutes, gaps, covered, sets.Roles
		}
		return ResultUnknown, gaps, covered, sets.Roles
	default: // subject.absent, control.absent
		if len(sets.Present) > 0 {
			return ResultRefutes, gaps, sets.Present, sets.Roles
		}
		if len(sets.Expected) == 0 || len(sets.Checked) == 0 {
			return ResultUnknown, append(gaps, "truncated_scope:no_subjects_checked"), covered, sets.Roles
		}
		if !sameSubjectSet(sets.Expected, sets.Checked) {
			return ResultUnknown, append(gaps, "truncated_scope:expected!=checked"), covered, sets.Roles
		}
		if !sameSubjectSet(sets.Checked, append(append([]claimshape.Subject(nil), sets.Absent...), sets.Present...)) {
			return ResultUnknown, append(gaps, "truncated_scope:undecided_subjects"), covered, sets.Roles
		}
		if len(sets.Absent) == len(sets.Checked) {
			return ResultSupports, gaps, covered, sets.Roles
		}
		return ResultUnknown, gaps, covered, sets.Roles
	}
}

// payloadGaps is the single gap surface for every capability view. Both
// the primary data object and auxiliary import-closure fields participate;
// a gap cannot disappear merely because a different capability reads it.
func payloadGaps(data, top map[string]any) []string {
	var gaps []string
	gaps = appendGaps(gaps, data)
	if closure := mapOf(data, "import_closure"); closure != nil {
		gaps = appendGaps(gaps, closure)
	}
	if closure := mapOf(top, "import_closure"); closure != nil {
		gaps = appendGaps(gaps, closure)
	}
	_, _, _, closureGaps := scopeHashes(data, top)
	return dedup(append(gaps, closureGaps...))
}

// appendGaps surfaces a payload's open gap sets under the registry's gap
// vocabulary.
func appendGaps(gaps []string, data map[string]any) []string {
	for _, k := range []string{"unresolved_dispatch", "dynamic_markers", "skipped_packages", "gated_references", "may_call_sites", "interface_dispatch_sites"} {
		for _, g := range listOf(data, k) {
			if s, ok := g.(string); ok {
				gaps = append(gaps, gapName(k)+":"+s)
			} else if m, ok := g.(map[string]any); ok {
				if f := strOf(m, "file"); f != "" {
					gaps = append(gaps, gapName(k)+":"+f)
				} else {
					gaps = append(gaps, gapName(k))
				}
			}
		}
	}
	return gaps
}

// interpUnreachability interprets the bounded kernel proof record.
func interpUnreachability(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	res := mapOf(data, "result")
	if res == nil {
		res = data // tolerate raw kernel payloads
	}
	var covered []claimshape.Subject
	for _, item := range listOf(res, "subjects") {
		if m, ok := item.(map[string]any); ok {
			if s := subjectFromData(m); s.Name != "" {
				covered = append(covered, s)
			}
		}
	}
	var gaps []string
	if refs, _, _, _ := callSitesOf(res, "product_references", "dependency_call_sites"); refs > 0 {
		// Positive reach evidence — the concrete counterexample.
		switch in.Shape {
		case claimshape.ShapePathUnreachable:
			return ResultRefutes, gaps, covered, nil
		default:
			return ResultSupports, gaps, covered, nil
		}
	}
	if reach := mapOf(res, "module_reachable"); len(reach) > 0 {
		switch in.Shape {
		case claimshape.ShapePathUnreachable:
			return ResultRefutes, gaps, covered, nil
		default:
			return ResultSupports, gaps, covered, nil
		}
	}
	// Gap inventory — anything open blocks the universal direction.
	for _, k := range []string{"may_call_sites", "interface_dispatch_sites", "dynamic_markers", "gated_references"} {
		for _, item := range listOf(res, k) {
			if m, ok := item.(map[string]any); ok {
				f := strOf(m, "file")
				if f != "" {
					gaps = append(gaps, "open_dynamic_marker:"+f)
				}
			}
		}
	}
	if dc, _, _, _ := callSitesOf(res, "dependency_call_sites"); dc > 0 {
		gaps = append(gaps, "unresolved_dispatch:dependency_call_sites")
	}
	if op, ok := boolOf(res, "opaque"); ok && op {
		gaps = append(gaps, "opaque_dispatch")
	}
	if ub, ok := boolOf(res, "unbounded"); ok && ub {
		gaps = append(gaps, "unbounded_surface")
	}
	if complete, ok := boolOf(res, "complete"); ok && complete {
		switch in.Shape {
		case claimshape.ShapePathUnreachable:
			return ResultSupports, gaps, covered, nil
		default:
			return ResultRefutes, gaps, covered, nil
		}
	}
	return ResultUnknown, gaps, covered, nil
}

// interpFindSymbol interprets a declaration lookup.
func interpFindSymbol(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	found, ok := boolOf(data, "found")
	if !ok {
		return ResultUnknown, nil, nil, nil
	}
	subj := claimshape.Subject{Kind: claimshape.SubjectSymbol}
	if sd := scopeDetailsMap(top); sd != nil {
		subj.Name = strOf(sd, "subject")
	}
	switch in.Shape {
	case claimshape.ShapeSubjectAbsent, claimshape.ShapeControlAbsent:
		if found {
			return ResultRefutes, nil, []claimshape.Subject{subj}, nil
		}
		return ResultSupports, nil, []claimshape.Subject{subj}, nil
	case claimshape.ShapeSubjectDeclared:
		if found {
			return ResultSupports, nil, []claimshape.Subject{subj}, nil
		}
		return ResultRefutes, nil, []claimshape.Subject{subj}, nil
	case claimshape.ShapePathReachable:
		if found {
			return ResultSupports, nil, []claimshape.Subject{subj}, nil
		}
		return ResultUnknown, nil, []claimshape.Subject{subj}, nil
	}
	if found {
		return ResultSupports, nil, []claimshape.Subject{subj}, nil
	}
	return ResultUnknown, nil, []claimshape.Subject{subj}, nil
}

// interpModuleVersion interprets a resolved module version.
func interpModuleVersion(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	// Module resolution can only answer a module-shaped claim. Never treat
	// a package/symbol/call-site name as a module path by string similarity.
	if in.ClaimSubject.Kind != claimshape.SubjectModule {
		return ResultUnknown, nil, nil, nil
	}
	present, ok := boolOf(data, "present")
	modPath := strOf(data, "module")
	if !ok || modPath == "" || in.ClaimSubject.Name != modPath {
		return ResultUnknown, nil, nil, nil
	}
	mod := claimshape.Subject{Kind: claimshape.SubjectModule, Name: modPath}
	switch in.Shape {
	case claimshape.ShapeApplicabilityVersionInRange:
		return ResultUnknown, nil, []claimshape.Subject{mod}, nil
	case claimshape.ShapeSubjectAbsent:
		if present {
			return ResultRefutes, nil, []claimshape.Subject{mod}, nil
		}
		return ResultSupports, nil, []claimshape.Subject{mod}, nil
	case claimshape.ShapeSubjectDeclared:
		if present {
			return ResultSupports, nil, []claimshape.Subject{mod}, nil
		}
		return ResultRefutes, nil, []claimshape.Subject{mod}, nil
	}
	return ResultUnknown, nil, []claimshape.Subject{mod}, nil
}

// interpDependencyGraph interprets the enumerated module list.
func interpDependencyGraph(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	// Dependency graphs enumerate module paths only. A symbol/package claim
	// is not a module lookup and must remain uncovered.
	if in.ClaimSubject.Kind != claimshape.SubjectModule || in.ClaimSubject.Name == "" {
		return ResultUnknown, nil, nil, nil
	}
	want := in.ClaimSubject.Name
	mods := listOf(data, "modules")
	present := false
	for _, item := range mods {
		if m, ok := item.(map[string]any); ok {
			p := strOf(m, "effective_path")
			if p == "" {
				p = strOf(m, "path")
			}
			if p == want {
				present = true
				break
			}
		}
	}
	subj := claimshape.Subject{Kind: claimshape.SubjectModule, Name: want}
	switch in.Shape {
	case claimshape.ShapeSubjectAbsent:
		if present {
			return ResultRefutes, nil, []claimshape.Subject{subj}, nil
		}
		return ResultSupports, nil, []claimshape.Subject{subj}, nil
	case claimshape.ShapeSubjectDeclared:
		if present {
			return ResultSupports, nil, []claimshape.Subject{subj}, nil
		}
		return ResultRefutes, nil, []claimshape.Subject{subj}, nil
	case claimshape.ShapeApplicabilityVersionInRange:
		return ResultUnknown, nil, []claimshape.Subject{subj}, nil
	}
	return ResultUnknown, nil, []claimshape.Subject{subj}, nil
}

// interpReachProbe interprets the caller/reference probes: a positive
// count is a concrete witness, zero is a refutation within the checked
// (partial) scope — the contract floor keeps it from ever reading as a
// closed negative.
func interpReachProbe(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	count, _, possible, partial := callSitesOf(data, "call_sites", "references")
	var gaps []string
	if partial {
		gaps = append(gaps, "truncated_scope:partial_enumeration")
	}
	if possible > 0 {
		gaps = append(gaps, "unresolved_dispatch:may_call_candidates")
	}
	switch in.Shape {
	case claimshape.ShapePathReachable:
		if count > 0 {
			return ResultSupports, gaps, nil, nil
		}
		return ResultRefutes, gaps, nil, nil
	case claimshape.ShapePathUnreachable:
		if count > 0 {
			return ResultRefutes, gaps, nil, nil
		}
		return ResultSupports, gaps, nil, nil
	case claimshape.ShapeSubjectDeclared:
		if count > 0 {
			return ResultSupports, gaps, nil, nil
		}
		// Zero occurrences in a partial scan never disproves a
		// declaration — only the declaration lookup can.
	}
	return ResultUnknown, gaps, nil, nil
}

// interpModuleReach interprets module-internal reachability chains.
func interpModuleReach(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	reached, ok := intOf(data, "reached")
	if !ok {
		if ch := mapOf(data, "chains"); ch != nil {
			reached = len(ch)
		}
	}
	var gaps []string
	if op, ok := boolOf(data, "opaque"); ok && op {
		gaps = append(gaps, "opaque_dispatch")
	}
	switch in.Shape {
	case claimshape.ShapePathUnreachable:
		if reached > 0 {
			return ResultRefutes, gaps, nil, nil
		}
		return ResultSupports, gaps, nil, nil
	default:
		if reached > 0 {
			return ResultSupports, gaps, nil, nil
		}
		return ResultRefutes, gaps, nil, nil
	}
}

// interpDepInvocation interprets dep-internal invocation state.
func interpDepInvocation(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	callers, _ := intOf(data, "callers_inside_module")
	var gaps []string
	if ub, ok := boolOf(data, "unbounded"); ok && ub {
		gaps = append(gaps, "unbounded_surface")
	}
	live := callers > 0
	if sl, ok := boolOf(data, "sibling_live"); ok && sl {
		live = true
	}
	switch in.Shape {
	case claimshape.ShapePathUnreachable:
		if live {
			return ResultRefutes, gaps, nil, nil
		}
		return ResultSupports, gaps, nil, nil
	default:
		if live {
			return ResultSupports, gaps, nil, nil
		}
		return ResultRefutes, gaps, nil, nil
	}
}

// interpGapOnly converts pure gap-inventory tools (dispatch sites, dynamic
// markers): their payload never adjudicates a predicate — it only names
// open gaps other capabilities must close.
func interpGapOnly(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	count, _, _, _ := callSitesOf(data, "call_sites", "markers")
	if count == 0 {
		if c, ok := intOf(data, "count"); ok {
			count = c
		}
	}
	var gaps []string
	if count > 0 {
		gaps = append(gaps, "open_dynamic_marker:"+in.Observation.Tool)
	}
	return ResultUnknown, gaps, nil, nil
}

// interpGovulncheck interprets the advisory reachability scan.
func interpGovulncheck(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	count, _ := intOf(data, "count")
	inDB, _ := boolOf(data, "in_database")
	var gaps []string
	if !inDB {
		gaps = append(gaps, "truncated_scope:advisory_not_in_db")
	}
	switch in.Shape {
	case claimshape.ShapePathReachable:
		if count > 0 {
			return ResultSupports, gaps, nil, nil
		}
		return ResultUnknown, gaps, nil, nil // empty findings never prove absence
	default:
		return ResultUnknown, gaps, nil, nil
	}
}

// interpTraceArgument interprets the bounded provenance trace: origins
// resolved per traced flow.
func interpTraceArgument(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	origins := listOf(data, "origins")
	unknownFlow, _ := boolOf(data, "unknown_flow")
	flows := listOf(data, "data_flows")
	var gaps []string
	if unknownFlow {
		gaps = append(gaps, "truncated_scope:unresolved_flow")
	}
	switch in.Shape {
	case claimshape.ShapeInputOrigin, claimshape.ShapeInputAttackerControlled:
		if len(flows) == 0 {
			return ResultUnknown, gaps, nil, nil
		}
		// The origin classes ride the observation payload as query
		// parameters — the claim's own parameter matching happens at
		// the claim level; here definite classes count as SUPPORTS of
		// "an origin is established", any UNKNOWN flow weakens it.
		definite := true
		var classes []string
		for _, o := range origins {
			if s, ok := o.(string); ok {
				classes = append(classes, s)
				if s == "" || s == "UNKNOWN" {
					definite = false
				}
			}
		}
		if !definite {
			gaps = append(gaps, "truncated_scope:unknown_origin")
			return ResultUnknown, gaps, nil, nil
		}
		return ResultSupports, gaps, nil, nil
	}
	return ResultUnknown, gaps, nil, nil
}

// interpCallSiteGuard interprets the call-site guard check.
func interpCallSiteGuard(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	gated, gOK := boolOf(data, "gated")
	dead, dOK := boolOf(data, "dead_code")
	if !gOK && !dOK {
		return ResultUnknown, nil, nil, nil
	}
	subj := siteSubject(top)
	switch in.Shape {
	case claimshape.ShapeControlPresent:
		if gated || dead {
			return ResultSupports, nil, []claimshape.Subject{subj}, nil
		}
		return ResultRefutes, nil, []claimshape.Subject{subj}, nil
	case claimshape.ShapeControlAbsent:
		if gated || dead {
			return ResultRefutes, nil, []claimshape.Subject{subj}, nil
		}
		return ResultSupports, nil, []claimshape.Subject{subj}, nil
	}
	return ResultUnknown, nil, []claimshape.Subject{subj}, nil
}

// interpValidations interprets the guard/validation enumeration.
func interpValidations(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	count := len(listOf(data, "validations"))
	if c, ok := intOf(data, "count"); ok && c > count {
		count = c
	}
	subj := siteSubject(top)
	switch in.Shape {
	case claimshape.ShapeControlPresent:
		if count > 0 {
			return ResultSupports, nil, []claimshape.Subject{subj}, nil
		}
		return ResultRefutes, nil, []claimshape.Subject{subj}, nil
	case claimshape.ShapeControlAbsent:
		if count > 0 {
			return ResultRefutes, nil, []claimshape.Subject{subj}, nil
		}
		return ResultSupports, nil, []claimshape.Subject{subj}, nil
	}
	return ResultUnknown, nil, []claimshape.Subject{subj}, nil
}

// interpMissingCall interprets the missing-call check.
func interpMissingCall(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	missing, ok := boolOf(data, "check_never_called")
	if !ok {
		if m, ok2 := boolOf(data, "missing"); ok2 {
			missing, ok = m, true
		}
	}
	if !ok {
		return ResultUnknown, nil, nil, nil
	}
	switch in.Shape {
	case claimshape.ShapeControlAbsent:
		if missing {
			return ResultSupports, nil, nil, nil
		}
		return ResultRefutes, nil, nil, nil
	case claimshape.ShapeControlPresent:
		if missing {
			return ResultRefutes, nil, nil, nil
		}
		return ResultSupports, nil, nil, nil
	}
	return ResultUnknown, nil, nil, nil
}

// interpFieldAssignments interprets configuration assignments.
func interpFieldAssignments(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	count := len(listOf(data, "assignments"))
	if c, ok := intOf(data, "count"); ok && c > count {
		count = c
	}
	var gaps []string
	for _, a := range listOf(data, "assignments") {
		if m, ok := a.(map[string]any); ok {
			if strOf(m, "value") == "" && strOf(m, "source") == "" {
				gaps = append(gaps, "truncated_scope:unresolvable_assignment")
			}
		}
	}
	if in.Shape != claimshape.ShapeConfigurationPredicate {
		return ResultUnknown, gaps, nil, nil
	}
	if count > 0 {
		return ResultSupports, gaps, nil, nil
	}
	return ResultUnknown, append(gaps, "no assignment observed; absence of a write is not a predicate answer"), nil, nil
}

// interpGatedRefs interprets build-gated references.
func interpGatedRefs(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	count, _, _, _ := callSitesOf(data, "call_sites")
	if c, ok := intOf(data, "count"); ok && c > count {
		count = c
	}
	var gaps []string
	if count > 0 {
		gaps = append(gaps, "build_gated_reference")
	}
	switch in.Shape {
	case claimshape.ShapeEnvironmentBuildGate:
		if count > 0 {
			return ResultSupports, gaps, nil, nil
		}
		return ResultRefutes, gaps, nil, nil
	case claimshape.ShapePathUnreachable, claimshape.ShapeSubjectAbsent:
		// Gated references only exist under another build context — they
		// are an open gap for this context's universals, not a witness.
		return ResultUnknown, gaps, nil, nil
	}
	return ResultUnknown, gaps, nil, nil
}

// interpProductSnapshot interprets snapshot build facts: context only —
// it can never adjudicate a gate predicate alone.
func interpProductSnapshot(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	return ResultUnknown, nil, nil, nil
}

// interpAdvisoryRecord interprets an authoritative record read: binding
// evidence for provenance.bound, context elsewhere.
func interpAdvisoryRecord(in interpInput, data, top map[string]any) (Result, []string, []claimshape.Subject, []string) {
	if in.Shape != claimshape.ShapeProvenanceBound {
		return ResultUnknown, nil, nil, nil
	}
	// A resolved record that names a subject binds it. Absence of the
	// expected subject makes the record non-binding.
	subj := claimshape.Subject{Kind: claimshape.SubjectAdvisory}
	if sd := scopeDetailsMap(top); sd != nil {
		subj.Name = strOf(sd, "subject")
	}
	if subj.Name == "" {
		subj.Name = strOf(data, "id")
	}
	return ResultSupports, nil, []claimshape.Subject{subj}, nil
}

// siteSubject recovers the checked call site as a canonical subject.
func siteSubject(top map[string]any) claimshape.Subject {
	if sd := scopeDetailsMap(top); sd != nil {
		if s := strOf(sd, "subject"); s != "" {
			return claimshape.Subject{Kind: claimshape.SubjectCallSite, Name: s}
		}
	}
	return claimshape.Subject{Kind: claimshape.SubjectCallSite}
}

func dedup(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// splitGap splits a "class:detail" gap name.
func splitGap(g string) (class, detail string) {
	if i := strings.IndexByte(g, ':'); i >= 0 {
		return g[:i], g[i+1:]
	}
	return g, ""
}
