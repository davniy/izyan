package goanalysis

// This file answers one question before any specialized transport proof runs:
// does the affected module's own source implement a transport mechanism this
// build supports?
//
// The probe is deliberately narrow. It reads the product's dependency graph,
// the affected module's production source and the captured fix material. It
// never reads the exploit model: a nominated protocol role, a condition param,
// a prose regex match or an advisory keyword cannot establish that the
// mechanism applies, and a nomination therefore never starts the specialized
// checker. When the probe refuses, the capability is recorded as an
// observation — a refused specialized capability must not block Product B's
// independent human investigation.

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/tools/go/packages"

	"github.com/fedorovmv/izyan/internal/domain"
)

// TransportProofScope is the exact binding set a caller supplies for one
// rooted transport proof: the advisory record it must be pinned to, the
// affected subjects, the assessed product and the captured fix material. It
// carries no verdict, no mechanism and no "proven" flag — the probe discovers
// the mechanism from the module's source.
type TransportProofScope struct {
	Record    domain.RecordPin
	EntryRefs []int
	Subjects  []domain.SymbolRef
	Product   domain.ProductSnapshot
	FixURI    string
	FixDigest string
	FixDiff   string
}

// TransportApplicability is the probe's answer. Applicable is true only when
// every source-bound prerequisite holds; Refusals names each missing one so a
// caller records an observation instead of a proof claim. Request is the exact
// proof request to dispatch when applicable, and the zero value otherwise.
type TransportApplicability struct {
	Applicable bool
	Module     string
	Mechanism  string
	Request    domain.TransportProofRequest
	Refusals   []string
}

// Refused reports whether the probe found the capability inapplicable.
func (a TransportApplicability) Refused() bool { return !a.Applicable }

// Reason renders the refusals as one deterministic sentence.
func (a TransportApplicability) Reason() string {
	if len(a.Refusals) == 0 {
		return ""
	}
	out := ""
	for i, r := range a.Refusals {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

// TransportProofRequestFor returns the rooted transport proof request for this
// scope, and false when the specialized proof does not apply. Applicable is
// true only after the source-bound prerequisites are established: the affected
// subject resolves to a module in the product's dependency graph, the module's
// production source implements one supported transport mechanism lifecycle,
// and the request carries an exact record pin. An error means the probe could
// not measure those premises (the source failed to load); it is never a proof
// result.
func (ix *Index) TransportProofRequestFor(ctx context.Context, scope TransportProofScope) (domain.TransportProofRequest, bool, error) {
	app, err := ix.TransportApplicabilityFor(ctx, scope)
	if err != nil {
		return domain.TransportProofRequest{}, false, err
	}
	return app.Request, app.Applicable, nil
}

// TransportApplicabilityFor is TransportProofRequestFor with the measurement
// kept: the module, the discovered mechanism and every refusal are returned so
// a caller can record why the capability was not dispatched.
func (ix *Index) TransportApplicabilityFor(ctx context.Context, scope TransportProofScope) (TransportApplicability, error) {
	out := TransportApplicability{}
	if len(scope.Subjects) == 0 {
		out.Refusals = append(out.Refusals,
			"no affected subject is bound to this assessment, so no affected module can be resolved")
		return out, nil
	}
	if err := scope.Record.Validate(); err != nil {
		out.Refusals = append(out.Refusals, fmt.Sprintf(
			"the advisory record is not pinned to exact bytes (%v), so a rooted witness could never be re-admitted", err))
		return out, nil
	}

	ix.mu.Lock()
	if err := ix.load(ctx); err != nil {
		ix.mu.Unlock()
		return out, err
	}
	module := ix.transportModuleLocked(scope.Subjects)
	var modPkgs []*packages.Package
	var loadErr error
	if module != "" {
		modPkgs, loadErr = ix.loadExtra(ctx, module+"/...")
	}
	ix.mu.Unlock()
	out.Module = module
	if module == "" {
		out.Refusals = append(out.Refusals,
			"no affected subject package maps to a module in the product's dependency graph")
		return out, nil
	}
	if loadErr != nil {
		return out, fmt.Errorf("transport applicability: affected module %s source failed to load: %w", module, loadErr)
	}

	mechanism, refusal := transportMechanismInSource(buildTransportModule(modPkgs, module))
	if refusal != "" {
		out.Refusals = append(out.Refusals, refusal)
		return out, nil
	}
	out.Applicable = true
	out.Mechanism = mechanism
	out.Request = domain.TransportProofRequest{
		Record:    scope.Record,
		EntryRefs: append([]int(nil), scope.EntryRefs...),
		Subjects:  append([]domain.SymbolRef(nil), scope.Subjects...),
		Product:   scope.Product,
		Mechanism: mechanism,
		FixURI:    scope.FixURI,
		FixDigest: scope.FixDigest,
		FixDiff:   scope.FixDiff,
	}
	return out, nil
}

// transportMechanismInSource reports the supported mechanism the module's own
// source implements, or the refusal that names what is missing. The only
// supported mechanism is the HTTP/2 rapid-reset lifecycle, and its
// prerequisite is structural: one module function reads peer frames in a loop
// and dispatches on a stream-admission frame and a stream-reset frame. The
// remaining obligations are the trigger proof's, not the probe's business.
func transportMechanismInSource(m *transportModule) (string, string) {
	if m == nil || len(m.funcs) == 0 {
		return "", "the affected module carries no analyzable production source"
	}
	keys := make([]string, 0, len(m.funcs))
	for key := range m.funcs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, _, ok := frameLoopParts(m.funcs[key]); ok {
			return domain.MechanismHTTP2RapidReset, ""
		}
	}
	return "", fmt.Sprintf(
		"the affected module %s implements no supported transport mechanism lifecycle: no function reads peer frames in a loop and dispatches on both a stream-admission and a stream-reset frame",
		m.module)
}
