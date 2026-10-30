package evidencetools

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckSpecCatalogCoversAdvertisedTools pins the catalog surface to
// the MCP tool set: every registered check names a tool, carries the
// generated argument schema, a coverage rule and a non-negative call
// bound, and every advertised tool resolves through the catalog.
func TestCheckSpecCatalogCoversAdvertisedTools(t *testing.T) {
	cat := DefaultCheckCatalog()
	specs := cat.List()
	if len(specs) == 0 {
		t.Fatal("default catalog is empty")
	}
	if len(specs) != len(checkEntryTable) {
		t.Fatalf("catalog lists %d specs, table has %d", len(specs), len(checkEntryTable))
	}
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.ID == "" || spec.Tool == "" || spec.CoverageRule == "" {
			t.Fatalf("spec under-specified: %+v", spec)
		}
		if spec.Description == "" {
			t.Fatalf("spec %s has no agent-facing description", spec.ID)
		}
		if !spec.Available || spec.UnavailableReason != "" {
			t.Fatalf("session-independent spec %s must grant every capability: %+v", spec.ID, spec)
		}
		if len(spec.ArgumentSchema) == 0 || !json.Valid(spec.ArgumentSchema) {
			t.Fatalf("spec %s has no valid argument schema", spec.ID)
		}
		if spec.MaxCalls <= 0 {
			t.Fatalf("spec %s has no call bound", spec.ID)
		}
		if seen[spec.ID] {
			t.Fatalf("duplicate spec id %q", spec.ID)
		}
		seen[spec.ID] = true
		byTool, ok := cat.Lookup(spec.Tool)
		if !ok || byTool.ID != spec.ID {
			t.Fatalf("tool %q does not resolve to check %q", spec.Tool, spec.ID)
		}
	}
}

// TestCheckSpecValidateFailClosed pins the admission boundary: an
// unregistered check, malformed JSON, a schema-violating member, a
// wrong-typed field and a missing required field are all errors —
// never a permissive pass.
func TestCheckSpecValidateFailClosed(t *testing.T) {
	cat := DefaultCheckCatalog()
	if err := cat.Validate("no-such-check", json.RawMessage(`{}`)); err == nil {
		t.Fatal("unregistered check passed validation")
	}
	for _, tc := range []struct {
		name string
		id   string
		args string
	}{
		{"malformed-json", "usage-scope", `{"module":`},
		{"extra-field", "usage-scope", `{"module":"m","surprise":1}`},
		{"wrong-type", "usage-scope", `{"module":42}`},
		{"missing-required", "usage-scope", `{}`},
		{"symbol-not-admissible", "usage-scope", `{"module":"m","package":"m/p","symbol":"F"}`},
		{"missing-file", "read_source", `{"start":1}`},
		{"array-not-object", "read_source", `["main.go"]`},
		// A required member sent as an explicit null is dropped like any
		// other null, so it fails as missing rather than passing.
		{"required-member-null", "usage-scope", `{"module":null}`},
	} {
		if err := cat.Validate(tc.id, json.RawMessage(tc.args)); err == nil {
			t.Fatalf("%s: %s(%s) passed validation", tc.name, tc.id, tc.args)
		}
	}
	// Admissible requests pass.
	for _, tc := range []struct{ id, args string }{
		{"usage-scope", `{"module":"example.com/dep","package":"example.com/dep/pkg"}`},
		{"usage-scope", `{"module":"example.com/dep"}`},
		{"package-usage", `{"module":"example.com/dep","package":"example.com/dep/pkg","symbol":"Serve"}`},
		// An explicit JSON null is how a model spells "optional member
		// absent": it is normalized away, not rejected.
		{"package-usage", `{"module":"example.com/dep","package":"example.com/dep/pkg","symbol":null}`},
		{"usage-scope", `{"module":"example.com/dep","package":null}`},
		{"get_product_snapshot", `{}`},
		{"get_product_snapshot", ``},
		{"read_source", `{"file":"main.go","start":1,"end":9}`},
		{"module_internal_reach", `{"module":"m","entries":["main"],"subjects":[{"package":"m/p","symbol":"F"}]}`},
	} {
		if err := cat.Validate(tc.id, json.RawMessage(tc.args)); err != nil {
			t.Fatalf("%s(%s) rejected: %v", tc.id, tc.args, err)
		}
	}
}

// TestCheckSpecCapabilityGate proves the session-scoped catalog is
// capability-gated: exec and toolchain checks are denied in a strict
// session without the permissions, the advisory/patch research surface
// is denied without a configured source, and granting the permission
// re-opens exactly that check. Lookup still reports registration —
// gating lives in Validate so a denied capability is an admission
// error, never a silent UNSUPPORTED reached at dispatch.
func TestCheckSpecCapabilityGate(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	strict, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	cat := strict.CheckCatalog()

	for _, id := range []string{"run_build", "run_tests", "get_dependency_graph",
		"get_module_version", "run_govulncheck", "get_vulnerability", "get_advisory",
		"get_fix_references", "get_fix_diff"} {
		if err := cat.Validate(id, json.RawMessage(`{}`)); err == nil {
			t.Fatalf("check %q admissible without its session capability", id)
		}
		if _, ok := cat.Lookup(id); !ok {
			t.Fatalf("check %q must stay registered even when unavailable", id)
		}
	}
	// A capability-free check stays admissible.
	if err := cat.Validate("read_source", json.RawMessage(`{"file":"main.go"}`)); err != nil {
		t.Fatalf("read_source denied without cause: %v", err)
	}
	// Granting the permission admits exactly the gated check.
	strict.AllowExec = true
	if err := strict.CheckCatalog().Validate("run_build", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("run_build still denied after AllowExec: %v", err)
	}
	// The default (session-independent) catalog never gates on
	// capability: plan shape is validated before a session exists.
	if err := DefaultCheckCatalog().Validate("run_build", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("default catalog must not gate on capability: %v", err)
	}
}

// TestCheckSpecAvailabilityFollowsSessionPermissions pins the resolved
// availability contract: a session catalog marks exactly the checks whose
// capability the session denies, names that capability, and re-resolves when
// the permission is granted. The session-independent catalog grants every
// capability because it answers request shape, not session authority.
func TestCheckSpecAvailabilityFollowsSessionPermissions(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	strict, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)

	denied := map[string]string{
		"run_build":            "exec permission",
		"run_tests":            "exec permission",
		"get_dependency_graph": "toolchain permission",
		"get_module_version":   "toolchain permission",
		"run_govulncheck":      "toolchain permission",
		"usage-scope":          "toolchain permission",
		"package-inventory":    "toolchain permission",
		"verify_code_absence":  "toolchain permission",
		"symbol-unreachability": "toolchain permission",
		"get_vulnerability":    "advisory source",
		"get_advisory":         "advisory source",
		"get_fix_references":   "advisory source",
		"get_fix_diff":         "patch provider",
	}
	for _, spec := range strict.CheckCatalog().List() {
		want, gated := denied[spec.ID]
		if !gated {
			if !spec.Available || spec.UnavailableReason != "" {
				t.Fatalf("ungated check %s reports unavailable: %+v", spec.ID, spec)
			}
			continue
		}
		if spec.Available {
			t.Fatalf("gated check %s is available without its capability", spec.ID)
		}
		if !strings.Contains(spec.UnavailableReason, want) {
			t.Fatalf("check %s reason %q does not name %q", spec.ID, spec.UnavailableReason, want)
		}
	}

	// Granting the permission re-resolves exactly that check's availability.
	strict.AllowExec = true
	for _, spec := range strict.CheckCatalog().List() {
		if spec.ID == "run_build" || spec.ID == "run_tests" {
			if !spec.Available || spec.UnavailableReason != "" {
				t.Fatalf("%s stays unavailable after AllowExec: %+v", spec.ID, spec)
			}
		}
	}

	// Every listed guarantee is about a session: the default view gates
	// nothing and therefore reports everything available.
	for _, spec := range DefaultCheckCatalog().List() {
		if !spec.Available || spec.UnavailableReason != "" {
			t.Fatalf("default catalog gates %s: %+v", spec.ID, spec)
		}
	}
}

// TestCheckSpecToolDescriptionsStayRegistered proves the MCP surface reads
// descriptions from the catalog table: every advertised tool must
// keep a non-empty description (a missing one means the catalog lost
// the entry, not just a label).
func TestCheckSpecToolDescriptionsStayRegistered(t *testing.T) {
	cat := DefaultCheckCatalog()
	for _, name := range []string{
		"get_vulnerability", "get_advisory", "get_fix_references", "get_fix_diff",
		"get_product_snapshot", "get_dependency_graph", "get_module_version", "run_govulncheck",
		"find_symbol", "find_references", "find_callers", "find_may_callers", "find_dep_callers",
		"find_entrypoints", "read_function", "read_source", "search_source",
		"trace_argument", "find_validations",
		"scan_dynamic", "interface_dispatch_sites", "gated_refs",
		"dep_invocation_state", "module_usage", "module_internal_reach",
		"package-usage", "usage-scope",
		"check_call_site_guard", "field_assignments", "check_missing_call", "sensitive_fields",
		"run_build", "run_tests",
	} {
		spec, ok := cat.Lookup(name)
		if !ok {
			t.Fatalf("tool %q missing from the check catalog", name)
		}
		if spec.Description == "" || !strings.Contains(spec.Description, " ") {
			t.Fatalf("tool %q lost its catalog description", name)
		}
		if contract := spec.Contract(); contract.Name != name || contract.Description != spec.Description {
			t.Fatalf("tool %q contract does not project the published check: %+v", name, contract)
		}
	}
}
