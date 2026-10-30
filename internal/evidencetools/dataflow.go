package evidencetools

import (
	"context"
	"errors"
	"fmt"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

// callSiteScopeObs translates ErrCallSiteNotFound — a position that is not
// an AST call — into an UNSUPPORTED observation with an explicit scoped
// limitation. It is deliberately not an errorObs: the check was not
// performed because the supplied position lies outside this tool's
// domain, and the observation must say so instead of reporting an
// execution failure or claiming the site was ungated/untraced.
func (s *Session) callSiteScopeObs(tool string, err error) *Observation {
	return &Observation{
		Fact:         "position is not a call site: " + err.Error(),
		Scope:        "call-site-only; supplied position is not an AST call",
		Completeness: CompletenessUnknown,
		ToolStatus:   StatusUnsupported,
		Error:        err.Error(),
		Limitations: []string{
			"trace/guard checks require the position of a call expression (file, line and column of the call); a declaration or non-call position cannot be evaluated",
			"an unanswerable call-site check is neither evidence of a guard's absence nor of a safe path",
		},
		ScopeDetails: &ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			ExternalSHA:  s.ExternalSHA,
		},
	}
}

// ---- trace_argument ----

type traceArgumentArgs struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`
	// ArgIndex selects the call argument to trace; -1 traces every
	// argument, -2 (domain.ArgReceiver) the receiver expression.
	ArgIndex int `json:"arg_index,omitempty"`
}

type traceData struct {
	DataFlows   []domain.DataFlow `json:"data_flows"`
	Origins     []string          `json:"origins"`
	UnknownFlow bool              `json:"unknown_flow"`
}

func (s *Session) traceArgument(ctx context.Context, a traceArgumentArgs) (*Observation, error) {
	if a.File == "" || a.Line <= 0 {
		return nil, fmt.Errorf("file and line are required")
	}
	site := domain.CallSite{File: a.File, Line: a.Line, Column: a.Column}
	var flows []domain.DataFlow
	var err error
	if a.ArgIndex < 0 && a.ArgIndex != domain.ArgReceiver {
		flows, _, err = s.Source.TraceAllArguments(ctx, site)
	} else {
		var f domain.DataFlow
		f, _, err = s.Source.TraceArgument(ctx, site, a.ArgIndex)
		flows = []domain.DataFlow{f}
	}
	if err != nil {
		if errors.Is(err, goanalysis.ErrCallSiteNotFound) {
			return s.callSiteScopeObs("trace_argument", err), nil
		}
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, fmt.Sprintf("%s:%d arg %d", a.File, a.Line, a.ArgIndex))
	if serr != nil {
		return nil, serr
	}
	data := traceData{DataFlows: flows}
	origins := map[string]bool{}
	for _, f := range flows {
		origins[string(f.Origin)] = true
		if f.Origin == domain.OriginUnknown || f.Origin == "" {
			data.UnknownFlow = true
		}
	}
	for o := range origins {
		data.Origins = append(data.Origins, o)
	}
	lims = append(lims,
		"provenance trace is bounded: hop/eval budgets, opaque dispatch and unresolved receivers degrade origins to UNKNOWN rather than prove them safe",
		"an origin value is an observation of the traced expression, not a safety verdict")
	comp := CompletenessPartial
	fact := fmt.Sprintf("%d dataflow(s) traced for call at %s:%d; origins: %v", len(flows), a.File, a.Line, data.Origins)
	o := s.ok("trace_argument", fact,
		fmt.Sprintf("call site %s:%d:%d and its bounded caller/provenance closure", a.File, a.Line, a.Column),
		comp, data, sd, lims)
	for _, f := range flows {
		if f.Source.File != "" {
			o.EvidenceRefs = append(o.EvidenceRefs, fmt.Sprintf("src:%s#L%d", f.Source.File, f.Source.Line))
		}
		if f.Sink.File != "" && f.Sink.File != f.Source.File {
			o.EvidenceRefs = append(o.EvidenceRefs, fmt.Sprintf("src:%s#L%d", f.Sink.File, f.Sink.Line))
		}
	}
	return o, nil
}

// ---- find_validations ----

type findValidationsArgs struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column,omitempty"`
	ArgIndex int    `json:"arg_index,omitempty"`
}

type validationsData struct {
	Validations []domain.Validation `json:"validations"`
	Count       int                 `json:"count"`
}

func (s *Session) findValidations(ctx context.Context, a findValidationsArgs) (*Observation, error) {
	if a.File == "" || a.Line <= 0 {
		return nil, fmt.Errorf("file and line are required")
	}
	site := domain.CallSite{File: a.File, Line: a.Line, Column: a.Column}
	var vals []domain.Validation
	var err error
	if a.ArgIndex < 0 && a.ArgIndex != domain.ArgReceiver {
		vals, _, err = s.Source.FindAllValidations(ctx, site)
	} else {
		vals, _, err = s.Source.FindValidations(ctx, site, a.ArgIndex)
	}
	if err != nil {
		if errors.Is(err, goanalysis.ErrCallSiteNotFound) {
			return s.callSiteScopeObs("find_validations", err), nil
		}
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, fmt.Sprintf("%s:%d arg %d", a.File, a.Line, a.ArgIndex))
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"guard enumeration is bounded by the same trace budgets as provenance; conditional guards apply only under their enclosing condition",
		"absence of a guard in this result is not proof that no validation exists elsewhere (e.g. in unchecked caller frames)")

	o := s.ok("find_validations",
		fmt.Sprintf("%d validation/guard record(s) before %s:%d", len(vals), a.File, a.Line),
		fmt.Sprintf("guards preceding the call at %s:%d (own frame plus bounded caller frames)", a.File, a.Line),
		CompletenessPartial,
		validationsData{Validations: vals, Count: len(vals)}, sd, lims)
	for _, v := range vals {
		if v.File != "" {
			o.EvidenceRefs = append(o.EvidenceRefs, fmt.Sprintf("src:%s#L%d", v.File, v.Line))
		}
	}
	return o, nil
}
