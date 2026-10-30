package evidencetools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPToolCatalog verifies every advertised tool registers with a
// typed schema and the Observation semantics are announced.
func TestMCPToolCatalog(t *testing.T) {
	s := newTestSession(t)
	srv := s.NewServer()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	catalog := s.CheckCatalog()
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.InputSchema == nil {
			t.Fatalf("tool %s has no input schema", tool.Name)
		}
		// The advertised surface is the check catalog's execution face:
		// every advertised tool must resolve to a registered check, and its
		// description must be the catalog's own — never a second label.
		spec, ok := catalog.Lookup(tool.Name)
		if !ok {
			t.Fatalf("advertised tool %s is not in the check catalog", tool.Name)
		}
		if tool.Description != spec.Description {
			t.Fatalf("tool %s description %q is not the catalog description %q", tool.Name, tool.Description, spec.Description)
		}
	}
	for _, want := range []string{
		// §6 minimal catalog
		"get_vulnerability", "get_advisory", "get_fix_references", "get_fix_diff",
		"get_product_snapshot", "get_dependency_graph", "get_module_version", "run_govulncheck",
		"find_symbol", "find_references", "find_callers", "find_entrypoints",
		"read_function", "read_source", "search_source",
		"trace_argument", "find_validations",
		"scan_dynamic", "interface_dispatch_sites", "gated_refs",
		"dep_invocation_state", "module_usage", "module_internal_reach",
		"package-usage", "usage-scope", "symbol-unreachability",
		"check_call_site_guard", "field_assignments", "check_missing_call", "sensitive_fields",
		"run_build", "run_tests",
	} {
		if !got[want] {
			t.Fatalf("tool %s not registered; have %v", want, got)
		}
	}
}

// TestMCPCallToolContract calls tools over a real MCP session and checks
// the Observation contract flows through structured content.
func TestMCPCallToolContract(t *testing.T) {
	s := newTestSession(t)
	var recs []AuditRecord
	s.Audit = AuditFunc(func(_ context.Context, r AuditRecord) { recs = append(recs, r) })
	srv := s.NewServer()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	call := func(name string, args map[string]any) *Observation {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("call %s: %v", name, err)
		}
		if res.IsError {
			t.Fatalf("call %s isError: %+v", name, res.Content)
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("call %s structured content: %v", name, err)
		}
		var o Observation
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("call %s unmarshal: %v\n%s", name, err, b)
		}
		return &o
	}

	// real backend call over the wire
	o := call("find_symbol", map[string]any{"package": "example.com/snapdep/vuln", "symbol": "Parse"})
	if o.ToolStatus != StatusOK || o.Completeness != CompletenessComplete {
		t.Fatalf("find_symbol: %s/%s err=%s", o.ToolStatus, o.Completeness, o.Error)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.SnapshotHash == "" {
		t.Fatalf("missing scope_details: %+v", o)
	}

	// traversal through MCP returns ERROR observation, not a crash.
	o = call("read_source", map[string]any{"file": "../go.mod"})
	if o.ToolStatus != StatusError || o.Completeness != CompletenessUnknown {
		t.Fatalf("traversal through MCP: %+v", o)
	}

	// exec without permission is UNSUPPORTED — distinct from ERROR.
	o = call("run_build", nil)
	if o.ToolStatus != StatusUnsupported {
		t.Fatalf("run_build without allow-exec: %s", o.ToolStatus)
	}

	// unknown module is a COMPLETE absence inside the closed module list.
	o = call("get_module_version", map[string]any{"module": "example.com/nonexistent"})
	if o.ToolStatus != StatusOK || o.Completeness != CompletenessComplete {
		t.Fatalf("get_module_version absent: %s/%s err=%s", o.ToolStatus, o.Completeness, o.Error)
	}

	if len(recs) == 0 {
		t.Fatal("audit sink saw no invocations")
	}
	for _, r := range recs {
		if r.Observation == nil || r.Observation.Tool == "" {
			t.Fatalf("audit record lacks observation: %+v", r)
		}
	}
}

// TestMCPPackageUsageContract calls package-usage over the wire: the
// declared symbol check returns the bounded observation shape, and the
// wire decode preserves the usage verdict fields the lane promotes on.
func TestMCPPackageUsageContract(t *testing.T) {
	s := newTestSession(t)
	srv := s.NewServer()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "package-usage",
		Arguments: map[string]any{
			"module":  "example.com/snapdep",
			"package": "example.com/snapdep/vuln",
			"symbol":  "Parse",
		}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		t.Fatalf("isError: %+v", res.Content)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var o Observation
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, b)
	}
	if o.Tool != "package-usage" || o.ToolStatus != StatusOK {
		t.Fatalf("tool=%s status=%s", o.Tool, o.ToolStatus)
	}
	data, ok := o.Data.(map[string]any)
	if !ok {
		t.Fatalf("wire payload is %T, want decoded map", o.Data)
	}
	if data["usage"] != "USED" {
		t.Fatalf("usage=%v, want USED", data["usage"])
	}
	if data["present"] != true {
		t.Fatalf("present=%v, want true", data["present"])
	}
	if data["check_scope"] == "" {
		t.Fatal("check_scope missing from wire payload")
	}
	// A missing package argument is rejected before the handler runs —
	// the tool cannot mint an observation over an invented subject.
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "package-usage",
		Arguments: map[string]any{"module": "example.com/snapdep"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res2.IsError {
		b2, _ := json.Marshal(res2.StructuredContent)
		var o2 Observation
		if uerr := json.Unmarshal(b2, &o2); uerr == nil {
			if o2.ToolStatus != StatusError {
				t.Fatalf("missing package accepted: %s", o2.ToolStatus)
			}
		}
	}
}

// TestMCPUsageScopeContract calls usage-scope over the wire with a stubbed
// GoTool: the advertised argument shape is exactly module (+optional
// package), a symbol argument is rejected by schema, and the returned
// observation carries the paired-closure scope fields the lane promotes on.
func TestMCPUsageScopeContract(t *testing.T) {
	s := newTestSession(t)
	s.GoTool = usageScopeStubTool{}
	srv := s.NewServer()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// The advertised schema is exactly module + optional package — no
	// symbol argument exists for this tool.
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	for _, tool := range lt.Tools {
		if tool.Name == "usage-scope" {
			b, _ := json.Marshal(tool.InputSchema)
			if err := json.Unmarshal(b, &schema); err != nil {
				t.Fatal(err)
			}
		}
	}
	if schema == nil {
		t.Fatal("usage-scope not advertised")
	}
	props, _ := schema["properties"].(map[string]any)
	if len(props) != 2 || props["module"] == nil || props["package"] == nil || props["symbol"] != nil {
		t.Fatalf("usage-scope schema properties: %v", props)
	}

	call := func(args map[string]any) *Observation {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "usage-scope", Arguments: args})
		if err != nil {
			t.Fatalf("call %v: %v", args, err)
		}
		if res.IsError {
			t.Fatalf("call %v isError: %+v", args, res.Content)
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var o Observation
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, b)
		}
		return &o
	}

	// test-only: VERIFIED product absence on two complete closures.
	o := call(map[string]any{"module": "test/only", "package": "test/only/pkg"})
	if o.ToolStatus != StatusOK || o.Completeness != CompletenessComplete {
		t.Fatalf("test-only: %s/%s", o.ToolStatus, o.Completeness)
	}
	data, ok := o.Data.(map[string]any)
	if !ok {
		t.Fatalf("wire payload is %T", o.Data)
	}
	if data["usage_scope"] != "test-only" || data["product_absence_verification"] != "VERIFIED" {
		t.Fatalf("test-only payload: %v", data)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.CoverageRule == "" ||
		o.ScopeDetails.Extra["product_closure_cmd"] == "" ||
		o.ScopeDetails.Extra["test_closure_cmd"] == "" ||
		o.ScopeDetails.Extra["product_root_semantics"] == "" ||
		o.ScopeDetails.Extra["test_root_semantics"] == "" {
		t.Fatalf("scope_details missing paired-stream fields: %+v", o.ScopeDetails)
	}

	// product / mixed / module-only aggregate / absent-from-both unknown.
	for target, want := range map[string]string{
		"both/mod":       "product",
		"ext/mod/dep":    "mixed",
		"absent/dep/pkg": "unknown",
	} {
		d := func() map[string]any {
			oo := call(map[string]any{"module": "x", "package": target})
			dd, _ := oo.Data.(map[string]any)
			return dd
		}()
		if d["usage_scope"] != want {
			t.Fatalf("%s: usage_scope=%v, want %s", target, d["usage_scope"], want)
		}
		if d["product_absence_verification"] != nil {
			t.Fatalf("%s: unexpected product_absence_verification %v", target, d["product_absence_verification"])
		}
	}
	o = call(map[string]any{"module": "test/only"})
	data, _ = o.Data.(map[string]any)
	if data["usage_scope"] != "test-only" {
		t.Fatalf("module-only aggregate: usage_scope=%v", data["usage_scope"])
	}
	if _, has := data["package"]; has {
		t.Fatalf("module-only aggregate carries a package path: %v", data["package"])
	}

	// A symbol argument is rejected by schema before the handler runs.
	res3, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "usage-scope",
		Arguments: map[string]any{"module": "test/only", "package": "test/only/pkg", "symbol": "F"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res3.IsError {
		b3, _ := json.Marshal(res3.StructuredContent)
		var o3 Observation
		if uerr := json.Unmarshal(b3, &o3); uerr == nil && o3.ToolStatus != StatusError {
			t.Fatalf("symbol argument accepted: %s", o3.ToolStatus)
		}
	}

	// A missing module is rejected.
	res4, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "usage-scope",
		Arguments: map[string]any{"package": "test/only/pkg"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res4.IsError {
		b4, _ := json.Marshal(res4.StructuredContent)
		var o4 Observation
		if uerr := json.Unmarshal(b4, &o4); uerr == nil && o4.ToolStatus != StatusError {
			t.Fatalf("missing module accepted: %s", o4.ToolStatus)
		}
	}
}

// TestMCPStrictProfileContract drives a strict session over the wire:
// the toolchain permission gate, the hardened scope stamps and the
// read-root confinement all surface through MCP as Observation shapes.
func TestMCPStrictProfileContract(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(SessionConfig{
		CVEID:        "GO-TEST-0001",
		SnapshotRoot: root,
		ExternalSHA:  "testsha0123456789",
		Strict:       true,
		// Explicit generous bound so machine load can't stall the real
		// go-list subprocess into the strict default timeout.
		ToolTimeout: 2 * time.Minute,
		VulnSource:  vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:       NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	srv := s.NewServer()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	call := func(name string, args map[string]any) *Observation {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("call %s: %v", name, err)
		}
		if res.IsError {
			t.Fatalf("call %s isError: %+v", name, res.Content)
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("call %s structured content: %v", name, err)
		}
		var o Observation
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("call %s unmarshal: %v\n%s", name, err, b)
		}
		return &o
	}

	// Exec-backed tools are UNSUPPORTED without the toolchain permission.
	o := call("get_dependency_graph", nil)
	if o.ToolStatus != StatusUnsupported || !strings.Contains(o.Error, "allow-toolchain") {
		t.Fatalf("strict get_dependency_graph: %+v", o)
	}
	// Source tools still run (loader exception named in scope).
	o = call("find_symbol", map[string]any{"package": "example.com/snapdep/vuln", "symbol": "Parse"})
	if o.ToolStatus != StatusOK {
		t.Fatalf("strict find_symbol: %s", o.Error)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.Profile != "strict" ||
		o.ScopeDetails.Extra["toolchain_exception"] == "" {
		t.Fatalf("strict scope must name the loader exception: %+v", o.ScopeDetails)
	}
	if v, _ := envValue(o.ScopeDetails.ToolchainEnv, "GOPROXY"); v != "off" {
		t.Fatalf("strict env must reach the wire: %+v", o.ScopeDetails.ToolchainEnv)
	}
	// Traversal stays a fail-closed ERROR.
	o = call("read_source", map[string]any{"file": "../go.mod"})
	if o.ToolStatus != StatusError {
		t.Fatalf("strict traversal: %+v", o)
	}
}

// TestRegistryDefinitionsDispatchParity pins the one-registry contract: the
// check registry publishes every advertised tool's contract, and the MCP
// server registers exactly those checks through their typed handlers. A
// handler without a registry row, a registry row without a handler, or an
// advertised tool whose published contract is missing permission/limit/
// observation metadata all fail here — so no second list can drift.
func TestRegistryDefinitionsDispatchParity(t *testing.T) {
	registered := map[string]bool{}
	for _, e := range checkEntryTable {
		if registered[e.id] {
			t.Fatalf("registry row %q is declared twice", e.id)
		}
		registered[e.id] = true
		if e.tool == e.id {
			continue
		}
		t.Fatalf("registry row %q advertises tool %q: the check catalog is the request catalog", e.id, e.tool)
	}
	for name := range serverTools {
		if !registered[name] {
			t.Fatalf("MCP handler %q has no registry row", name)
		}
	}
	for name := range registered {
		if _, ok := serverTools[name]; !ok {
			t.Fatalf("registry row %q has no MCP handler binding", name)
		}
	}

	cat := DefaultCheckCatalog()
	specs := cat.List()
	if len(specs) != len(registered) {
		t.Fatalf("catalog lists %d specs, registry declares %d", len(specs), len(registered))
	}
	for _, spec := range specs {
		if !spec.Permission.valid() {
			t.Fatalf("spec %s publishes no valid permission: %q", spec.ID, spec.Permission)
		}
		if spec.MaxCalls <= 0 {
			t.Fatalf("spec %s publishes no repeat bound", spec.ID)
		}
		if !spec.Evidence.valid() {
			t.Fatalf("spec %s publishes an unknown observation class %q", spec.ID, spec.Evidence)
		}
		contract := spec.Contract()
		if contract.Permission != spec.Permission || contract.MaxCalls != spec.MaxCalls ||
			contract.MaxRunCalls != spec.MaxRunCalls || contract.Evidence != spec.Evidence {
			t.Fatalf("spec %s contract does not publish the check's own metadata: %+v", spec.ID, contract)
		}
		if len(contract.InputSchema) == 0 || !json.Valid(contract.InputSchema) {
			t.Fatalf("spec %s contract has no valid argument schema", spec.ID)
		}
	}
	// Objective checks advertise their capability; the classification is
	// registry metadata, not a broker list.
	for name, want := range map[string]EvidenceClass{
		"find_callers":         EvidenceSiteSet,
		"find_references":      EvidenceSiteSet,
		"find_may_callers":     EvidenceSiteSet,
		"module_usage":         EvidenceSiteSet,
		"dep_invocation_state": EvidenceDepInvocation,
		"run_govulncheck":      EvidenceGovulncheck,
		"find_symbol":          EvidenceNone,
		"get_module_version":   EvidenceNone,
	} {
		spec, ok := cat.Lookup(name)
		if !ok {
			t.Fatalf("check %q is not registered", name)
		}
		if spec.Evidence != want {
			t.Fatalf("check %q observation class = %q, want %q", name, spec.Evidence, want)
		}
	}
	if spec, _ := cat.Lookup("run_govulncheck"); spec.MaxRunCalls <= 0 {
		t.Fatalf("run_govulncheck publishes no per-run cost bound: %+v", spec)
	}
}

// TestNoProductionVerdictPath statically guards the trust boundary: the
// adapter package must not reference the production verifier, evaluator
// or verdict machinery.
func TestNoProductionVerdictPath(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{
		"VerifyFalse", "domain.NegativeVerification", "VerdictEvaluator",
		"internal/evaluator", "internal/states", "internal/workflow",
		"domain.Verdict", "AnalysisCase",
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range banned {
			if strings.Contains(string(b), tok) {
				t.Fatalf("%s references production verdict path token %q", f, tok)
			}
		}
	}
}
