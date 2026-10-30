package evidencetools

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
)

// ToolPermission names the session capability a tool contract requires. The
// registry publishes the requirement; the session — not a second list —
// resolves whether it is held.
type ToolPermission string

const (
	// PermissionNone — the tool needs no capability beyond a configured
	// snapshot/session.
	PermissionNone ToolPermission = "none"
	// PermissionExec — repository code executes (run_build/run_tests).
	PermissionExec ToolPermission = "exec"
	// PermissionToolchain — go/govulncheck subprocesses run.
	PermissionToolchain ToolPermission = "toolchain"
	// PermissionToolchainOrVendor — either the toolchain permission or a
	// vendored snapshot supports the closed offline derivation.
	PermissionToolchainOrVendor ToolPermission = "toolchain_or_vendor"
	// PermissionVulnSource — a configured advisory source is required.
	PermissionVulnSource ToolPermission = "vuln_source"
	// PermissionPatchSource — a configured patch provider is required.
	PermissionPatchSource ToolPermission = "patch_source"
)

// valid reports whether the permission is one of the registry's declared
// requirements.
func (p ToolPermission) valid() bool {
	switch p {
	case PermissionNone, PermissionExec, PermissionToolchain,
		PermissionToolchainOrVendor, PermissionVulnSource, PermissionPatchSource:
		return true
	}
	return false
}

// ToolContract is the one registry contract an advertised tool publishes:
// what the agent sees (name, description, argument schema), which session
// capability it requires, its repeat and per-run cost bounds, and the
// observation class governing how a successful payload is interpreted.
//
// evidencetools publishes one contract per registered check; triage publishes
// the same shape for the snapshot/material tools it serves in-process, and
// both project their agent-facing definitions, broker limits and audit
// classification from it. A new tool contract is therefore one registry row —
// never a parallel allowlist, description map, limit constant or confidence
// map.
type ToolContract struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	// Permission is the session capability the tool requires. It is
	// descriptive: the session resolves availability, the contract never
	// grants it.
	Permission ToolPermission `json:"permission"`
	// MaxCalls is the per-plan repeat bound (0 means the catalog default).
	MaxCalls int `json:"max_calls,omitempty"`
	// MaxRunCalls is the per-run cost bound: how many real invocations an
	// investigation may spend on this tool before the broker refuses further
	// distinct calls (0 means unbounded).
	MaxRunCalls int `json:"max_run_calls,omitempty"`
	// Evidence names the observation class a completed payload is
	// interpreted under. EvidenceNone means the payload never counts as
	// positive reachability/usage evidence.
	Evidence EvidenceClass `json:"evidence,omitempty"`
}

// CheckSpec describes one admissible evidence check: which session tool
// executes it, the agent-facing description, the closed-scope rule family
// the check's observations claim, the exact argument schema the MCP runtime
// enforces, and the per-plan call bound the flow broker applies. The catalog
// describes admissible requests and scope — it never interprets results and
// never carries verdict semantics.
//
// ID is the catalog-level name of the check; Tool is the session tool
// that executes it. They coincide for every MCP capability (the check
// catalog is the request catalog), while lane-internal checks may name
// a Tool the broker can schedule without a registered request shape.
//
// Permission, MaxCalls, MaxRunCalls and Evidence publish the same fields as
// ToolContract: Contract projects them onto the shared contract the broker
// and the audit trail read.
//
// Available and UnavailableReason are the session-resolved capability
// answer: a session view marks a check unavailable exactly when the
// session lacks the capability the check needs, and names that capability.
// The session-independent DefaultCheckCatalog grants nothing and therefore
// gates nothing — it answers "is this request shape admissible somewhere",
// never "may this session execute it".
type CheckSpec struct {
	ID                string          `json:"id"`
	Tool              string          `json:"tool"`
	Description       string          `json:"description"`
	CoverageRule      string          `json:"coverage_rule"`
	ArgumentSchema    json.RawMessage `json:"argument_schema"`
	Permission        ToolPermission  `json:"permission"`
	MaxCalls          int             `json:"max_calls"`
	MaxRunCalls       int             `json:"max_run_calls,omitempty"`
	Evidence          EvidenceClass   `json:"evidence,omitempty"`
	Available         bool            `json:"available"`
	UnavailableReason string          `json:"unavailable_reason,omitempty"`
}

// Contract projects the published spec onto the shared tool contract. The
// catalog id is the advertised tool name: the check catalog is the request
// catalog, so a check never advertises under a name the broker cannot
// resolve.
func (s CheckSpec) Contract() ToolContract {
	return ToolContract{
		Name:        s.ID,
		Description: s.Description,
		InputSchema: append(json.RawMessage(nil), s.ArgumentSchema...),
		Permission:  s.Permission,
		MaxCalls:    s.MaxCalls,
		MaxRunCalls: s.MaxRunCalls,
		Evidence:    s.Evidence,
	}
}

// CheckCatalog is the fail-closed admission surface for evidence-tool
// requests: Lookup reports registration, Validate answers whether a
// request for this session is admissible — registered check, declared
// capability present, and arguments satisfying the tool's schema. An
// unregistered check or a schema violation is always an error, never a
// permissive default.
type CheckCatalog interface {
	Lookup(id string) (CheckSpec, bool)
	Validate(id string, args json.RawMessage) error
	List() []CheckSpec
}

// checkNeed names the session capability a check requires before it can
// ever produce an OK observation. The broker rejects a request whose
// session lacks the capability; the runtime still returns UNSUPPORTED
// independently — the catalog gate is the earlier, descriptive layer.
type checkNeed int

const (
	needNone checkNeed = iota
	// needExec requires AllowExec: repository code executes.
	needExec
	// needToolchain requires the strict-profile toolchain permission
	// (AllowToolchain) — the tool unconditionally runs `go`/govulncheck
	// subprocesses.
	needToolchain
	// needToolchainOrVendor requires either the toolchain permission or a
	// vendored snapshot whose modules.txt/vendor tree support the closed
	// offline derivation (usage-scope's vendor path).
	needToolchainOrVendor
	// needVulnSource requires a configured advisory source
	// (VulnSource — static in tests, OSV under AllowNet).
	needVulnSource
	// needPatchSource requires a configured patch provider.
	needPatchSource
)

// permission names the requirement as published contract metadata. It never
// resolves availability: that stays the session's answer. A requirement the
// mapping does not know publishes an invalid permission rather than silently
// claiming "none", so catalog construction refuses it.
func (n checkNeed) permission() ToolPermission {
	switch n {
	case needNone:
		return PermissionNone
	case needExec:
		return PermissionExec
	case needToolchain:
		return PermissionToolchain
	case needToolchainOrVendor:
		return PermissionToolchainOrVendor
	case needVulnSource:
		return PermissionVulnSource
	case needPatchSource:
		return PermissionPatchSource
	}
	return ""
}

// checkEntry is the catalog's private row: the public CheckSpec plus the
// registration metadata — the agent-facing description, the concrete
// argument type the runtime schema is inferred from, the session capability
// the request needs, the per-run cost bound and the observation class.
type checkEntry struct {
	id           string
	tool         string
	description  string
	coverageRule string
	args         reflect.Type
	maxCalls     int
	runCalls     int
	need         checkNeed
	evidence     EvidenceClass
}

// checkEntryTable is the single source of truth for the advertised MCP
// surface: names, descriptions, argument shapes, scope rules, permission
// requirements, repeat/cost bounds and observation classes. The MCP server
// registers from here (mcp.go serverTools binds handlers, never names), the
// broker projects its catalog from here, and the audit classification reads
// the evidence class published here. maxCalls is the per-plan repeat bound
// the flow broker enforces; runCalls is the per-run cost bound the triage
// broker enforces for expensive subprocess checks; evidence declares how a
// successful payload may count as reachability/usage evidence — declaring a
// class never makes an empty response positive.
var checkEntryTable = []checkEntry{
	// research
	{id: "get_vulnerability", tool: "get_vulnerability", args: reflect.TypeOf(getVulnerabilityArgs{}), maxCalls: 1, need: needVulnSource,
		coverageRule: "single advisory document fetch (osv/v1/vulns/<id>)",
		description:  "Fetch the normalized advisory record for this session's CVE (OSV-compatible document: affected modules/packages/symbols, fixed versions, references)"},
	{id: "get_advisory", tool: "get_advisory", args: reflect.TypeOf(getAdvisoryArgs{}), need: needVulnSource,
		coverageRule: "single advisory document fetch (osv/v1/vulns/<id>)",
		description:  "Fetch any OSV-compatible advisory by id (GO-*, GHSA-*, CVE-*): record body, aliases, affected ranges"},
	{id: "get_fix_references", tool: "get_fix_references", args: reflect.TypeOf(getFixReferencesArgs{}), maxCalls: 1, need: needVulnSource,
		coverageRule: "all references of the fetched advisory record classified fix-bearing",
		description:  "List fix-bearing references (commit/patch URLs) of the session advisory record"},
	{id: "get_fix_diff", tool: "get_fix_diff", args: reflect.TypeOf(getFixDiffArgs{}), need: needPatchSource,
		coverageRule: "full patch body fetched within size cap; parsed file list covers all files in the diff",
		description:  "Fetch and parse the patch text of a fix reference URL (http/https only)"},
	// dependencies & build
	{id: "package-inventory", tool: "package-inventory", args: reflect.TypeOf(PackageInventoryArgs{}), need: needToolchain,
		coverageRule: "successful edge-closed package stream for ./... under the identified effective build",
		description: "Enumerate build packages and dependencies with optional tests; full digest-bound stdout, not source/load or whole-upstream completeness"},
	{id: "get_product_snapshot", tool: "get_product_snapshot", args: reflect.TypeOf(getProductSnapshotArgs{}), maxCalls: 1,
		coverageRule: "single product snapshot probe (go version + manifest scan, no git history)",
		description:  "Snapshot identity and build facts: content hash, external SHA, go directive, release toolchain evidence, GOOS/GOARCH/tags, replaces"},
	{id: "get_dependency_graph", tool: "get_dependency_graph", args: reflect.TypeOf(getDependencyGraphArgs{}), maxCalls: 1, need: needToolchain,
		coverageRule: "enumerated module list of the snapshot's main module graph",
		description:  "Enumerated module list of the snapshot (resolved + effective versions, replace info, vendor fallback)"},
	{id: "get_module_version", tool: "get_module_version", args: reflect.TypeOf(getModuleVersionArgs{}), need: needToolchain,
		coverageRule: "enumerated module list of the snapshot's main module graph",
		description:  "Resolved version of one module in the snapshot's dependency graph"},
	{id: "run_govulncheck", tool: "run_govulncheck", args: reflect.TypeOf(runGovulncheckArgs{}), maxCalls: 1, runCalls: 2, need: needToolchain,
		evidence:     EvidenceGovulncheck,
		coverageRule: "single govulncheck run over the snapshot for the session advisory",
		description:  "Run govulncheck over the snapshot for the session CVE (toolchain exec, no repo code run); reports DB coverage and findings, NOT absence proofs"},
	// code & calls
	{id: "find_symbol", tool: "find_symbol", args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "declaration lookup in one loaded and type-checked package",
		description:  "Locate a symbol (Func or Type.Method) in product or dependency packages; absence is COMPLETE inside a successfully loaded package"},
	{id: "find_references", tool: "find_references", evidence: EvidenceSiteSet, args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "product package references to the named symbol (loaded scope)",
		description:  "All references to a symbol in product packages (calls, value refs, field selections)"},
	{id: "find_callers", tool: "find_callers", evidence: EvidenceSiteSet, args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "statically named call sites in product packages only",
		description:  "Statically named call sites of a symbol in product packages only — interface/func-value/dep-internal callers are NOT included"},
	{id: "find_may_callers", tool: "find_may_callers", evidence: EvidenceSiteSet, args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "may-call sites incl. interface dispatch and function values in loaded scope",
		description:  "May-call sites incl. interface dispatch and function values, in loaded scope; flags unproven candidates"},
	{id: "find_dep_callers", tool: "find_dep_callers", args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "call sites inside the subject's own dependency package/module",
		description:  "Call sites of a symbol inside its own dependency package/module"},
	{id: "find_entrypoints", tool: "find_entrypoints", args: reflect.TypeOf(struct{}{}), maxCalls: 1,
		coverageRule: "recognized product entrypoints (main/init, exported, net/http handlers) in loaded scope",
		description:  "Recognized product entrypoints (main/init, exported, net/http handlers)"},
	{id: "read_function", tool: "read_function", args: reflect.TypeOf(readFunctionArgs{}),
		coverageRule: "verbatim source of one function declaration inside the snapshot",
		description:  "Verbatim source of a function in a file inside the snapshot"},
	{id: "read_source", tool: "read_source", args: reflect.TypeOf(readSourceArgs{}),
		coverageRule: "verbatim bytes of the requested line range of one file",
		description:  "Verbatim line range of a file inside the snapshot or module cache"},
	{id: "search_source", tool: "search_source", args: reflect.TypeOf(searchSourceArgs{}),
		coverageRule: "lexical regex search over loaded Go source files, capped at the match budget",
		description:  "Regex search over loaded Go source files (product + loaded deps); capped at 64 matches"},
	// dataflow & protection
	{id: "trace_argument", tool: "trace_argument", args: reflect.TypeOf(traceArgumentArgs{}),
		coverageRule: "bounded provenance trace of the selected call argument(s)",
		description:  "Data origin of one call argument (or all, arg_index=-1; receiver=-2) at a call site — bounded provenance trace"},
	{id: "find_validations", tool: "find_validations", args: reflect.TypeOf(findValidationsArgs{}),
		coverageRule: "guards preceding the call site, own frame plus bounded caller frames",
		description:  "Guards/validations constraining a call argument before a call site"},
	// dynamic reachability
	{id: "scan_dynamic", tool: "scan_dynamic", args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "dynamic-dispatch markers near the subject in loaded scope",
		description:  "Dynamic-dispatch markers near a symbol: reflect/unsafe/plugin/linkname imports and func-value references"},
	{id: "interface_dispatch_sites", tool: "interface_dispatch_sites", args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "interface-dispatch sites to the subject's method name in loaded scope",
		description:  "Call sites that dispatch to the subject's method name through an interface value"},
	{id: "gated_refs", tool: "gated_refs", args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "references inside files excluded by the recorded build tags/configuration",
		description:  "References to a symbol inside files excluded by the current build tags/configuration"},
	{id: "dep_invocation_state", tool: "dep_invocation_state", evidence: EvidenceDepInvocation, args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "in-module callers and pipeline liveness for the subject's own module",
		description:  "How the subject's own module invokes it: in-module callers, sibling pipeline liveness, unboundedness"},
	{id: "module_usage", tool: "module_usage", evidence: EvidenceSiteSet, args: reflect.TypeOf(moduleUsageArgs{}),
		coverageRule: "product call sites whose callee package belongs to the module prefix",
		description:  "Product call sites whose callee package belongs to a module path prefix"},
	{id: "module_internal_reach", tool: "module_internal_reach", args: reflect.TypeOf(moduleInternalReachArgs{}),
		coverageRule: "source-loaded module call graph from the given entry symbols",
		description:  "Reachability of subject symbols inside a module from given entry symbols (source-loaded module call graph)"},
	{id: "package-usage", tool: "package-usage", args: reflect.TypeOf(packageUsageArgs{}),
		coverageRule: packageUsageNegativeCoverageRule,
		description:  "Bounded product-source usage check of one advisory-declared package or symbol: USED on a concrete product import/reference/call, NOT_USED only on a closed negative verification, UNKNOWN when the scope is not closed; a negative is never a runtime or deployment claim"},
	{id: "usage-scope", tool: "usage-scope", args: reflect.TypeOf(UsageScopeArgs{}), need: needToolchainOrVendor,
		coverageRule: usageScopeCoverageRule,
		description:  "Dual build-closure classification of one advisory-declared package (or a module-level aggregate): product / test-only / mixed / unknown by membership in the recorded `go list -deps -json ./...` product closure and the `go list -deps -test -json ./...` test closure; test-only only on verified product absence — a build-graph statement, never a source-usage or safety claim"},
	{id: "symbol-unreachability", tool: "symbol-unreachability", args: reflect.TypeOf(SymbolUnreachabilityArgs{}), need: needToolchain,
		coverageRule: symbolUnreachabilityCoverageRule,
		description:  "Bounded unreachability proof for an advisory-declared module's exact symbol set: COMPLETE only when declarations resolve and every product/dependency scope gate (references, may-calls, dep callers, dispatch, dynamic markers, gated refs, opaque/unbounded) is closed — supports only no-exploit-path reasoning, never not-affected"},
	{id: "verify_code_absence", tool: "verify_code_absence", args: reflect.TypeOf(VerifyCodeAbsenceArgs{}), need: needToolchain,
		coverageRule: codeAbsenceCoverageRule,
		description:  "Check requested code subjects across the enumerated product import closure for the pinned build context; observation only, never a verdict — absence reports only when the closure is proven complete and no dynamic exception stays open"},
	// configuration & checks
	{id: "check_call_site_guard", tool: "check_call_site_guard", args: reflect.TypeOf(callSiteGuardArgs{}),
		coverageRule: "guard analysis of the enclosing function at the call site",
		description:  "Whether a call site sits under a config/statically-dead guard in its enclosing function"},
	{id: "field_assignments", tool: "field_assignments", args: reflect.TypeOf(symbolRefArgs{}),
		coverageRule: "product-side assignments to the named struct field/symbol in loaded scope",
		description:  "Product-side assignments to a struct field / symbol (config knob population)"},
	{id: "check_missing_call", tool: "check_missing_call", args: reflect.TypeOf(checkMissingCallArgs{}),
		coverageRule: "live receiver call sites of the pipeline subject in loaded scope",
		description:  "Whether a check method is never invoked while sibling pipeline methods stay live (missing-call shape)"},
	{id: "sensitive_fields", tool: "sensitive_fields", args: reflect.TypeOf(sensitiveFieldsArgs{}),
		coverageRule: "credential-named exported fields of the named package",
		description:  "Credential-named exported fields of a package (INFO_LEAK datum source)"},
	// exec (gated)
	{id: "run_build", tool: "run_build", args: reflect.TypeOf(runSubprocessArgs{}), maxCalls: 1, need: needExec,
		coverageRule: "full `go build ./...` over the snapshot",
		description:  "Run `go build ./...` in the snapshot (requires exec permission)"},
	{id: "run_tests", tool: "run_tests", args: reflect.TypeOf(runSubprocessArgs{}), maxCalls: 1, need: needExec,
		coverageRule: "full `go test ./...` over the snapshot",
		description:  "Run `go test ./...` in the snapshot (requires exec permission)"},
}

// checkCatalog is the CheckCatalog implementation: an immutable map of
// resolved specs. Availability is resolved once, when the catalog is built,
// and carried on every spec — so the advertised view (List/Definitions) and
// admission (Validate) can never disagree about which capabilities this
// session holds.
type checkCatalog struct {
	specs    map[string]CheckSpec
	resolved map[string]*jsonschema.Resolved
}

// DefaultCheckCatalog returns the session-independent catalog: every
// registered check, no capability gating (every entry reports Available
// with no reason). It answers "is this request admissible somewhere" — the
// verification-plan validator uses it because plan shape is checked before
// the session's capabilities are decided; the capability-gated view is
// Session.CheckCatalog.
func DefaultCheckCatalog() CheckCatalog {
	c, err := buildCheckCatalog(nil)
	if err != nil {
		// The catalog is compile-time data: a bad entry is a defect and
		// must fail fast, never degrade into an empty/permissive catalog.
		panic(fmt.Sprintf("evidencetools: default check catalog is malformed: %v", err))
	}
	return c
}

// CheckCatalog returns the session-scoped catalog: the same registered
// checks, but every entry carries the availability this session resolves —
// exec without AllowExec, toolchain under strict without AllowToolchain,
// advisory/patch research without a configured source. The advertised view
// and admission both read that one resolved answer, so a broker that
// advertises available entries and a Validate call can never disagree. This
// is the capability gate the flow broker consults before scheduling a
// check; the runtime still returns UNSUPPORTED on its own.
func (s *Session) CheckCatalog() CheckCatalog {
	c, err := buildCheckCatalog(func(n checkNeed) bool {
		switch n {
		case needExec:
			return s.AllowExec
		case needToolchain:
			return !s.toolchainDenied()
		case needToolchainOrVendor:
			return !s.toolchainDenied() || vendorPresent(s.SnapshotRoot)
		case needVulnSource:
			return s.VulnSource != nil
		case needPatchSource:
			return s.PatchSource != nil
		default:
			return true
		}
	})
	if err != nil {
		panic(fmt.Sprintf("evidencetools: check catalog is malformed: %v", err))
	}
	return c
}

// buildCheckCatalog freezes the entry table into a lookup view: each
// entry's argument schema is generated from the same argument type the
// MCP handler decodes, so plan-time admission and runtime decoding can
// never disagree about a field's existence or type. A nil avail grants
// every capability (the session-independent view).
func buildCheckCatalog(avail func(checkNeed) bool) (*checkCatalog, error) {
	c := &checkCatalog{
		specs:    map[string]CheckSpec{},
		resolved: map[string]*jsonschema.Resolved{},
	}
	for _, e := range checkEntryTable {
		if e.id == "" || e.tool == "" || e.description == "" || e.coverageRule == "" || e.args == nil {
			return nil, fmt.Errorf("check entry %q is under-specified", e.id)
		}
		if e.maxCalls < 0 {
			return nil, fmt.Errorf("check entry %q has negative max_calls", e.id)
		}
		if e.runCalls < 0 {
			return nil, fmt.Errorf("check entry %q has negative run_calls", e.id)
		}
		if !e.evidence.valid() {
			return nil, fmt.Errorf("check entry %q declares unknown observation class %q", e.id, e.evidence)
		}
		permission := e.need.permission()
		if !permission.valid() {
			return nil, fmt.Errorf("check entry %q declares an unknown session requirement", e.id)
		}
		if _, dup := c.specs[e.id]; dup {
			return nil, fmt.Errorf("check entry %q is registered twice", e.id)
		}
		schema, err := jsonschema.ForType(e.args, nil)
		if err != nil {
			return nil, fmt.Errorf("check %q argument schema: %w", e.id, err)
		}
		raw, err := schema.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("check %q argument schema marshal: %w", e.id, err)
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			return nil, fmt.Errorf("check %q argument schema resolve: %w", e.id, err)
		}
		if e.maxCalls == 0 {
			e.maxCalls = 8
		}
		available, reason := avail == nil || avail(e.need), ""
		if !available {
			reason = needReason(e.need)
		}
		c.specs[e.id] = CheckSpec{
			ID:                e.id,
			Tool:              e.tool,
			Description:       e.description,
			CoverageRule:      e.coverageRule,
			ArgumentSchema:    json.RawMessage(raw),
			Permission:        permission,
			MaxCalls:          e.maxCalls,
			MaxRunCalls:       e.runCalls,
			Evidence:          e.evidence,
			Available:         available,
			UnavailableReason: reason,
		}
		c.resolved[e.id] = resolved
	}
	return c, nil
}

// Lookup returns the registered spec for id.
func (c *checkCatalog) Lookup(id string) (CheckSpec, bool) {
	s, ok := c.specs[id]
	return s, ok
}

// List returns every registered spec in catalog order, each carrying this
// catalog's resolved availability. Silent re-gating is impossible: the view
// a caller advertises and the view Validate consults are the same specs.
func (c *checkCatalog) List() []CheckSpec {
	out := make([]CheckSpec, 0, len(checkEntryTable))
	for _, e := range checkEntryTable {
		if s, ok := c.specs[e.id]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Validate checks one request against the catalog: unknown ids fail
// closed, an entry this session marked unavailable is an admission error
// (the runtime would answer UNSUPPORTED — the catalog refuses earlier), and
// the arguments must satisfy the tool's generated input schema exactly as
// the MCP server applies it (empty input decodes as the tool's zero-argument
// object).
func (c *checkCatalog) Validate(id string, args json.RawMessage) error {
	spec, ok := c.specs[id]
	if !ok {
		return fmt.Errorf("check %q is not in the evidence catalog", id)
	}
	if !spec.Available {
		reason := spec.UnavailableReason
		if reason == "" {
			reason = "required session capability is unavailable"
		}
		return fmt.Errorf("check %q is unavailable: %s", id, reason)
	}
	v := make(map[string]any)
	if len(args) > 0 {
		if err := json.Unmarshal(args, &v); err != nil {
			return fmt.Errorf("check %q arguments: %w", id, err)
		}
		// An explicit JSON null is how a model spells "this optional member
		// is absent". A null is not a value for a typed property, so drop
		// null members before schema validation; a required member that was
		// sent as null therefore fails as missing, which is the honest
		// outcome.
		dropNullMembers(v)
	}
	if err := c.resolved[spec.ID].Validate(v); err != nil {
		return fmt.Errorf("check %q arguments: %w", spec.ID, err)
	}
	return nil
}

// dropNullMembers removes null-valued members from an argument object,
// recursively, leaving every other value untouched.
func dropNullMembers(obj map[string]any) {
	for k, v := range obj {
		switch t := v.(type) {
		case nil:
			delete(obj, k)
		case map[string]any:
			dropNullMembers(t)
		}
	}
}

// needReason names the missing capability in admission errors.
func needReason(n checkNeed) string {
	switch n {
	case needExec:
		return "the exec permission is denied (run_build/run_tests execute repository code)"
	case needToolchain:
		return "the toolchain permission is denied (the strict profile requires AllowToolchain for go/govulncheck subprocesses)"
	case needToolchainOrVendor:
		return "neither the toolchain permission nor a vendored snapshot (vendor/modules.txt) is available for the closure derivation"
	case needVulnSource:
		return "no advisory source is configured (captured advisory set absent; network research disabled)"
	case needPatchSource:
		return "no patch provider is configured (captured fix set absent; network research disabled)"
	default:
		return "required session capability is unavailable"
	}
}
