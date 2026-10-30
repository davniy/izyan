package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// ToolCaller is the minimal deterministic-tool surface a live capability
// executor needs — the same contract triage.DetCaller already
// implements, so the existing evidence session is the only tool path.
type ToolCaller interface {
	CallTool(ctx context.Context, name string, args json.RawMessage) (*evidencetools.Observation, error)
}

// LiveBudget bounds live capability execution. The plan's "tool budget
// remains bounded by current limits" is enforced two ways: the executor
// never plans more than MaxCalls tool invocations, and every invocation
// still goes through the evidence session's own budgets (load, eval,
// hop, output) — this layer adds no unchecked work.
type LiveBudget struct {
	MaxCalls int
}

// DefaultLiveBudget is the conservative default for capability-driven
// re-derivation: few queries per claim, deterministic order.
const DefaultLiveBudget = 8

// PlannedQuery is one deterministic check a capability can run for a
// claim. Plans are built from claim structure only — the shape, its
// subject and structured parameters — never from prose.
type PlannedQuery struct {
	Capability string             `json:"capability"`
	Tool       string             `json:"tool"`
	Args       json.RawMessage    `json:"args"`
	Shape      claimshape.Shape   `json:"shape"`
	Subject    claimshape.Subject `json:"subject,omitempty"`
}

// PlanQueries deterministically derives the minimal query set a claim's
// shape implies under the registry. Claims without an implementable
// query path produce no plan entries — the capability gap is reported,
// not worked around.
func PlanQueries(c claimshape.CanonicalClaim) []PlannedQuery {
	var out []PlannedQuery
	subj := c.Subject
	symRef := func() json.RawMessage {
		b, _ := json.Marshal(map[string]string{
			"package": subj.Package,
			"symbol":  subj.Symbol,
		})
		return b
	}
	siteRef := func() json.RawMessage {
		f, l := siteParts(subj.Name)
		b, _ := json.Marshal(map[string]any{"file": f, "line": l})
		return b
	}
	subjectsArg := func() json.RawMessage {
		subs := paramSubjects(c, "subjects")
		if len(subs) == 0 {
			subs = []claimshape.Subject{subj}
		}
		type su struct {
			Package string `json:"package"`
			Symbol  string `json:"symbol"`
		}
		var list []su
		for _, s := range subs {
			if s.Package != "" {
				list = append(list, su{Package: s.Package, Symbol: s.Symbol})
			}
		}
		b, _ := json.Marshal(map[string]any{"subjects": list})
		return b
	}
	module := paramStr(c, "module")

	switch c.Shape {
	case claimshape.ShapeSubjectAbsent:
		if len(paramSubjects(c, "subjects")) > 0 || subj.Package != "" {
			out = append(out, PlannedQuery{Capability: CapDeclarationResolver, Tool: "verify_code_absence", Args: subjectsArg(), Shape: c.Shape, Subject: subj})
		} else if subj.Kind == claimshape.SubjectModule && subj.Name != "" {
			out = append(out, PlannedQuery{Capability: CapModuleVersionResolver, Tool: "get_module_version",
				Args: json.RawMessage(`{"module":` + quoteJSON(subj.Name) + `}`), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapeSubjectDeclared:
		if subj.Package != "" && subj.Symbol != "" {
			out = append(out, PlannedQuery{Capability: CapDeclarationResolver, Tool: "find_symbol", Args: symRef(), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapePathUnreachable:
		if module != "" {
			var subs []map[string]string
			for _, s := range append(paramSubjects(c, "subjects"), subj) {
				if s.Package != "" {
					subs = append(subs, map[string]string{"package": s.Package, "symbol": s.Symbol})
				}
			}
			if len(subs) > 0 {
				b, _ := json.Marshal(map[string]any{"module": module, "subjects": subs})
				out = append(out, PlannedQuery{Capability: CapNegativeReachability, Tool: "symbol-unreachability", Args: b, Shape: c.Shape, Subject: subj})
			}
		}
	case claimshape.ShapePathReachable:
		if subj.Package != "" && subj.Symbol != "" {
			out = append(out, PlannedQuery{Capability: CapReachability, Tool: "find_callers", Args: symRef(), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapeControlPresent, claimshape.ShapeControlAbsent:
		if subj.Kind == claimshape.SubjectCallSite && subj.Name != "" {
			out = append(out, PlannedQuery{Capability: CapGuardChecker, Tool: "check_call_site_guard", Args: siteRef(), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapeInputOrigin, claimshape.ShapeInputAttackerControlled:
		if subj.Kind == claimshape.SubjectCallSite && subj.Name != "" {
			out = append(out, PlannedQuery{Capability: CapProvenanceTracer, Tool: "trace_argument", Args: siteRef(), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapeEnvironmentBuildGate:
		if subj.Package != "" && subj.Symbol != "" {
			out = append(out, PlannedQuery{Capability: CapBuildContext, Tool: "gated_refs", Args: symRef(), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapeConfigurationPredicate:
		if subj.Package != "" && subj.Symbol != "" {
			out = append(out, PlannedQuery{Capability: CapConfigurationAnalyzer, Tool: "field_assignments", Args: symRef(), Shape: c.Shape, Subject: subj})
		}
	case claimshape.ShapeApplicabilityVersionInRange:
		if module != "" {
			out = append(out, PlannedQuery{Capability: CapModuleVersionResolver, Tool: "get_module_version",
				Args: json.RawMessage(`{"module":` + quoteJSON(module) + `}`), Shape: c.Shape, Subject: subj})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Capability != out[j].Capability {
			return out[i].Capability < out[j].Capability
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// siteParts splits a "file.go:LINE" subject name.
func siteParts(name string) (string, int) {
	f, l := name, 0
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == ':' {
			if n, err := parseInt(name[i+1:]); err == nil {
				f, l = name[:i], n
			}
			break
		}
	}
	return f, l
}

func parseInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ExecuteLive runs planned queries through the deterministic tool caller
// under a hard call budget and records each result as an archived-style
// observation the evaluator can consume. The executor never retries,
// never picks the best of several answers and never exceeds the budget:
// an exhausted budget leaves the claim UNKNOWN — the conservative
// direction.
func ExecuteLive(ctx context.Context, in Input, caller ToolCaller, budget LiveBudget) ([]triage.RecordedObservation, error) {
	if caller == nil || budget.MaxCalls <= 0 {
		return nil, nil
	}
	calls := 0
	seq := 0
	var out []triage.RecordedObservation
	// Challenges plan through the identical claim pipeline: the
	// reviewer channel only adds hypotheses to re-derive, bounded by
	// the same MaxCalls budget.
	claims, _ := mergeClaims(in.Claims, in.Challenges)
	for _, c := range claims {
		for _, q := range PlanQueries(c) {
			if calls >= budget.MaxCalls {
				return out, nil
			}
			calls++
			seq++
			raw, err := caller.CallTool(ctx, q.Tool, q.Args)
			if err != nil {
				continue
			}
			if raw == nil {
				continue
			}
			payload, merr := json.Marshal(raw)
			if merr != nil {
				continue
			}
			rec := triage.RecordedObservation{
				ID:           fmt.Sprintf("live-%04d", seq),
				Tool:         raw.Tool,
				Status:       string(raw.ToolStatus),
				Completeness: raw.Completeness,
				Scope:        raw.Scope,
				Payload:      payload,
				DataSHA256:   fullHash(payload),
				EvidenceRefs: append([]string(nil), raw.EvidenceRefs...),
				Limitations:  append([]string(nil), raw.Limitations...),
				RunID:        in.RunID,
				Attempt:      1,
			}
			if raw.ScopeDetails != nil {
				rec.SnapshotHash = raw.ScopeDetails.SnapshotHash
				if raw.ScopeDetails.BuildContext != nil {
					b, _ := json.Marshal(raw.ScopeDetails.BuildContext)
					rec.BuildContextHash = "sha256:" + fullHash(b)
				}
			}
			out = append(out, rec)
		}
	}
	return out, nil
}
