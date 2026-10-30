package evidencetools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serverInstructions is the fixed contract text handed to the agent at
// MCP initialize. It declares only the Observation semantics and scope
// rules — no CVE-specific hints and no exploit-model guidance.
const serverInstructions = `Izyan evidence tools return an Observation per call:
  id, tool, fact, scope, completeness, tool_status, evidence_refs,
  limitations, scope_details, data.

Interpretation rules (binding):
- tool_status OK with an EMPTY result is NOT a safety finding.
  completeness=COMPLETE means "absent inside the closed scope named in
  scope/scope_details"; completeness=PARTIAL means "not found in the
  checked part only"; completeness=UNKNOWN means coverage could not be
  characterized.
- tool_status ERROR means the check failed (no coverage claim);
  UNSUPPORTED means the capability is not available in this session;
  TIMEOUT means the check exceeded its per-tool wall-clock bound.
- Never treat a PARTIAL/UNKNOWN negative, or an absent tool result, as
  evidence that a code path is safe or unreachable.
- scope_details is authoritative: it lists the build context, packages,
  skipped packages and limits that bounded the check. Product-scope
  results say nothing about dependency-internal, dynamically dispatched
  or other-build-configuration behavior unless the scope says so.`

// serverTool binds one registered check to its typed MCP handler. The
// registry owns every descriptive field — name, description, argument
// schema, permission, limits and observation class — so this table carries
// the handler and nothing else: adding a check is one registry row plus one
// binding, never a second name list.
type serverTool func(*mcp.Server, *Session, CheckSpec)

// serverTools is the handler half of the check registry, keyed by check id.
// NewServer walks the session catalog and dispatches through this table, so
// the advertised surface is exactly the registry and a registered check
// without a handler fails at server construction instead of silently
// vanishing from the MCP surface.
var serverTools = map[string]serverTool{
	"package-inventory": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.packageInventory)
	},
	"get_vulnerability": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ getVulnerabilityArgs) (*Observation, error) {
			return s.getVulnerability(ctx)
		})
	},
	"get_advisory": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.getAdvisory)
	},
	"get_fix_references": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ getFixReferencesArgs) (*Observation, error) {
			return s.getFixReferences(ctx)
		})
	},
	"get_fix_diff": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.getFixDiff)
	},

	"get_product_snapshot": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ getProductSnapshotArgs) (*Observation, error) {
			return s.getProductSnapshot(ctx)
		})
	},
	"get_dependency_graph": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ getDependencyGraphArgs) (*Observation, error) {
			return s.getDependencyGraph(ctx)
		})
	},
	"get_module_version": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.getModuleVersion)
	},
	"run_govulncheck": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ runGovulncheckArgs) (*Observation, error) {
			return s.runGovulncheck(ctx)
		})
	},

	"find_symbol": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.findSymbol)
	},
	"find_references": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.findReferences)
	},
	"find_callers": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.findCallers)
	},
	"find_may_callers": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.findMayCallers)
	},
	"find_dep_callers": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.findDepCallers)
	},
	"find_entrypoints": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ struct{}) (*Observation, error) {
			return s.findEntrypoints(ctx)
		})
	},
	"read_function": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.readFunction)
	},
	"read_source": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.readSource)
	},
	"search_source": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.searchSource)
	},

	"trace_argument": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.traceArgument)
	},
	"find_validations": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.findValidations)
	},

	"scan_dynamic": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.scanDynamic)
	},
	"interface_dispatch_sites": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.interfaceDispatchSites)
	},
	"gated_refs": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.gatedRefs)
	},
	"dep_invocation_state": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.depInvocationState)
	},
	"module_usage": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.moduleUsage)
	},
	"module_internal_reach": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.moduleInternalReach)
	},
	PackageUsageTool: func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.packageUsage)
	},
	UsageScopeTool: func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.usageScope)
	},
	SymbolUnreachabilityTool: func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.symbolUnreachability)
	},
	"verify_code_absence": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.verifyCodeAbsence)
	},

	"check_call_site_guard": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.checkCallSiteGuard)
	},
	"field_assignments": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.fieldAssignments)
	},
	"check_missing_call": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.checkMissingCall)
	},
	"sensitive_fields": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, s.sensitiveFields)
	},

	"run_build": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ runSubprocessArgs) (*Observation, error) {
			return s.runBuild(ctx)
		})
	},
	"run_tests": func(srv *mcp.Server, s *Session, spec CheckSpec) {
		reg(srv, spec, s, func(ctx context.Context, _ runSubprocessArgs) (*Observation, error) {
			return s.runTests(ctx)
		})
	},
}

// NewServer builds the MCP server exposing the session's tools. Registration
// is driven by the session-scoped catalog — the same view the flow broker and
// the triage DeterministicTools consult — so names, descriptions, argument
// schemas and permissions have exactly one source. Unavailable checks stay
// registered on purpose: their handlers answer UNSUPPORTED, the
// Observation-contract signal that the capability exists but this session
// does not hold it.
func (s *Session) NewServer() *mcp.Server {
	cat := s.CheckCatalog()
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "izyan-evidence-tools", Version: AdapterVersion},
		&mcp.ServerOptions{Instructions: serverInstructions})
	for _, spec := range cat.List() {
		bind, ok := serverTools[spec.ID]
		if !ok {
			// The catalog is compile-time data: a registered check without a
			// handler is a defect and must fail fast, never disappear from
			// the advertised surface.
			panic(fmt.Sprintf("evidencetools: check %q is registered without an MCP handler binding", spec.ID))
		}
		bind(srv, s, spec)
	}
	return srv
}

// Serve runs the session's MCP server on the given transport (stdio for
// the entrypoint, in-memory for tests).
func (s *Session) Serve(ctx context.Context, t mcp.Transport) error {
	return s.NewServer().Run(ctx, t)
}

// reg wires one handler: the advertised description and name come from the
// registered spec, and schema inference from In, Observation wrapping and the
// audit trail all live in s.invoke.
func reg[In any](srv *mcp.Server, spec CheckSpec, s *Session,
	fn func(context.Context, In) (*Observation, error)) {
	mcp.AddTool(srv, &mcp.Tool{Name: spec.ID, Description: spec.Description},
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *Observation, error) {
			return nil, s.invoke(ctx, spec.ID, rawArgs(req), func(c context.Context) (*Observation, error) {
				return fn(c, in)
			}), nil
		})
}

// rawArgs extracts the call's raw argument JSON for the audit record.
func rawArgs(req *mcp.CallToolRequest) json.RawMessage {
	if req == nil || req.Params == nil {
		return nil
	}
	b, err := json.Marshal(req.Params.Arguments)
	if err != nil || string(b) == "null" {
		return nil
	}
	return b
}
