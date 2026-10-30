package evaluator

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Library payload admission constants. The class string mirrors
// exploit.ClassDeserialization; the evaluator deliberately does not import the
// exploit package — its gates are self-contained — and the advisory CWE is
// normalized with the repository convention (TrimSpace, upper-case, drop a
// "CWE-" prefix, tolerate a "-suffix").
const (
	libraryPayloadClass = "DESERIALIZATION"
	libraryPayloadCWE   = "502"
)

// admittedLibraryWitness returns the first recorded flow for cond that carries a
// persisted library-input witness passing every admission gate. Failure is "no
// new proof", never safety: callers keep their existing UNKNOWN/negative
// handling and must not turn a rejected witness into a FALSE claim. There is
// also no structural fallback — a rejected or removed witness leaves the
// enclosing evaluator on its own typed evidence, so module usage and transport
// frame names cannot promote the same condition.
func admittedLibraryWitness(cond domain.Condition, c *domain.AnalysisCase) (domain.DataFlow, *domain.LibraryInputWitness, bool) {
	if !libraryAdmissionApplies(cond, c) {
		return domain.DataFlow{}, nil, false
	}
	for _, f := range flowsFor(c, cond.ID) {
		w := f.LibraryInput
		if w == nil {
			continue
		}
		if libraryWitnessAdmitted(cond, c, f, w) {
			return f, w, true
		}
	}
	return domain.DataFlow{}, nil, false
}

// libraryAdmissionApplies evaluates the condition- and case-level gates that do
// not depend on a particular traced flow: a proven library shape with an
// evidence-backed complete census, a resolved root-cause sink matching the
// condition subject, the exact DESERIALIZATION class and advisory CWE-502, an
// ATTACKER_CONTROL condition scoped to an exact nonnegative ordinary argument,
// and no peer/config/directional/exposure/protocol-role/pair shape. The witness
// can never satisfy INPUT_CONSTRAINT or any other condition kind.
func libraryAdmissionApplies(cond domain.Condition, c *domain.AnalysisCase) bool {
	if c == nil || c.Exploit == nil || cond.Kind != domain.ConditionAttackerControl {
		return false
	}
	// Exact nonnegative sink argument: ArgAll, ArgReceiver and unscoped
	// positions are not an exact binding and never carry this proof.
	if cond.ArgIndex < 0 {
		return false
	}
	// Ordinary argument input: absent input_source is the current generic
	// deserialization model; only an explicit argument is equivalent.
	if src := cond.Params[domain.ParamInputSource]; src != "" && src != domain.InputArg {
		return false
	}
	// The witness proves payload binding at an ordinary argument. Directional
	// (read), exposure/config checks, protocol-role requirements and paired-API
	// shapes are different condition semantics it cannot satisfy.
	for _, key := range []string{
		domain.ParamDirection,
		domain.ParamCheck,
		domain.ParamProtocolRole,
		domain.ParamSequence,
		domain.ParamScope,
	} {
		if cond.Params[key] != "" {
			return false
		}
	}
	if c.Exploit.Class != libraryPayloadClass || !advisoryHasLibraryCWE(c.Vulnerability.CWE) {
		return false
	}
	shape := c.Product.Shape
	if shape == nil || shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete ||
		shape.Fingerprint == "" || c.Product.BinaryPath != "" {
		return false
	}
	// A proof record must be evidence-backed: the census is audited, not
	// asserted.
	if len(shape.EvidenceIDs) == 0 || !evidenceIDsResolve(c, shape.EvidenceIDs) {
		return false
	}
	// Resolved root-cause sink matching the condition subject: the exploit
	// model is built from a resolved root cause, and its condition speaks about
	// exactly those present sink symbols.
	rootSinks := resolvedRootCauseSinks(c)
	if len(rootSinks) == 0 {
		return false
	}
	modelSinks := modelSinkSet(c.Exploit)
	if len(modelSinks) == 0 {
		return false
	}
	subjects := conditionSubjects(cond)
	if len(subjects) == 0 {
		return false
	}
	for s := range subjects {
		if !rootSinks[s] || !modelSinks[s] {
			return false
		}
	}
	return true
}

// libraryWitnessAdmitted applies the flow- and witness-level gates to one
// recorded candidate: exact sink call and argument, current census fingerprint,
// product-owned importable public API, evidence-backed witness, and a
// payload-preserving transformation record. Nothing here reads source.
func libraryWitnessAdmitted(cond domain.Condition, c *domain.AnalysisCase, f domain.DataFlow, w *domain.LibraryInputWitness) bool {
	if w == nil || f.ConditionID != cond.ID || f.PayloadUnproven {
		return false
	}
	// The flow, the witness and the condition must agree on one exact
	// nonnegative argument.
	if cond.ArgIndex < 0 || f.Arg != cond.ArgIndex || w.Arg != cond.ArgIndex {
		return false
	}
	// The witness is pinned to the census that produced it: an inventory move
	// rebuilds the shape and moves the fingerprint.
	shape := c.Product.Shape
	if shape == nil || w.ShapeFingerprint == "" || w.ShapeFingerprint != shape.Fingerprint {
		return false
	}
	// Exact sink identity: the witness site always carries a column; a
	// line-only flow site is matched by file+line, a columned one exactly.
	if w.Site.File == "" || w.Site.Line == 0 || w.Site.Column == 0 {
		return false
	}
	if f.Sink.File != w.Site.File || f.Sink.Line != w.Site.Line {
		return false
	}
	if f.Sink.Column != 0 && f.Sink.Column != w.Site.Column {
		return false
	}
	// The witness must bind a resolved root-cause sink that the condition
	// names — a mismatched subject or a different sink is no proof.
	if !resolvedRootCauseSinks(c)[w.Sink] || !conditionSubjects(cond)[w.Sink] {
		return false
	}
	if !libraryAPICensusAdmitted(shape, w.API) {
		return false
	}
	// Formal identity and declaration are part of the persisted proof.
	if w.FormalIndex < 0 || w.FormalType == "" ||
		w.Declaration.File == "" || w.Declaration.Line == 0 || w.Declaration.Column == 0 {
		return false
	}
	// Evidence-backed witness: dangling proof references are not a proof.
	if len(w.EvidenceIDs) == 0 || !evidenceIDsResolve(c, w.EvidenceIDs) {
		return false
	}
	// Payload preservation: only the recorded preserving hop kinds are
	// eligible, and a security-relevant transform on the traced path breaks
	// the proof (it is provenance needing review, not a proven binding).
	for _, step := range w.Steps {
		switch step.Kind {
		case domain.LibraryPayloadIdentity,
			domain.LibraryPayloadByteConversion,
			domain.LibraryPayloadPreservingCall:
		default:
			return false
		}
	}
	for _, tx := range f.Transformations {
		if domain.IsSecurityTransform(tx.Callee) {
			return false
		}
	}
	return true
}

// libraryWitnessClaim records the admitted public-API binding as a TRUE
// attacker-control claim at the library boundary: the producer stays
// evaluator.ArgumentOrigin, the control basis is library-public-api, the shared
// limitation is mandatory, and no falsifier, negative-verification record or
// assumption id is invented. Deployment origin is not claimed.
func libraryWitnessClaim(cond domain.Condition, c *domain.AnalysisCase, w *domain.LibraryInputWitness) domain.Claim {
	claim := domain.Claim{
		ID:           domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID:  cond.ID,
		Result:       domain.ClaimTrue,
		Producer:     "evaluator.ArgumentOrigin",
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}
	claim.EvidenceIDs = appendEvidenceIDs(claim.EvidenceIDs, c.Product.Shape.EvidenceIDs)
	claim.EvidenceIDs = appendEvidenceIDs(claim.EvidenceIDs, w.EvidenceIDs)
	claim.Explanation = fmt.Sprintf(
		"public library API %s.%s formal #%d (%s) selects the payload reaching the resolved sink %s.%s argument #%d at %s:%d:%d; the payload is consumer-selectable, deployment attacker control is not established",
		w.API.Package, w.API.Symbol, w.FormalIndex, w.FormalType,
		w.Sink.Package, w.Sink.Symbol, w.Arg, w.Site.File, w.Site.Line, w.Site.Column)
	claim.Limitations = append(claim.Limitations, domain.LibraryAPIScopeLimitation)
	return claim
}

// advisoryHasLibraryCWE reports whether the advisory carries CWE-502 under the
// repository's CWE normalization convention.
func advisoryHasLibraryCWE(cwes []string) bool {
	for _, raw := range cwes {
		id := strings.TrimSpace(raw)
		id = strings.TrimPrefix(strings.ToUpper(id), "CWE-")
		if i := strings.IndexByte(id, '-'); i >= 0 {
			id = id[:i]
		}
		if id == libraryPayloadCWE {
			return true
		}
	}
	return false
}

// resolvedRootCauseSinks returns the present SINK symbols of a resolved
// root-cause model. A missing/undecided model, an ABSENT candidate and every
// non-sink role are not a resolved sink.
func resolvedRootCauseSinks(c *domain.AnalysisCase) map[domain.SymbolRef]bool {
	if c == nil || c.RootCause == nil || c.RootCause.Status != domain.RootCauseResolved {
		return nil
	}
	sinks := map[domain.SymbolRef]bool{}
	for _, rc := range c.RootCause.RootCauses {
		if rc.Absent || (rc.Role != "" && rc.Role != domain.RootCauseSink) {
			continue
		}
		if rc.Package == "" || rc.Symbol == "" {
			continue
		}
		sinks[domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol}] = true
	}
	return sinks
}

// modelSinkSet returns the sink symbols the exploit model was built from.
func modelSinkSet(model *domain.ExploitModel) map[domain.SymbolRef]bool {
	if model == nil {
		return nil
	}
	sinks := map[domain.SymbolRef]bool{}
	for _, s := range model.RootCauses {
		if s.Package != "" && s.Symbol != "" {
			sinks[s] = true
		}
	}
	return sinks
}

// conditionSubjects returns the condition's declared subject symbols.
func conditionSubjects(cond domain.Condition) map[domain.SymbolRef]bool {
	subjects := map[domain.SymbolRef]bool{}
	for _, s := range cond.Subjects {
		if s.Package != "" && s.Symbol != "" {
			subjects[s] = true
		}
	}
	if cond.Subject != nil && cond.Subject.Package != "" && cond.Subject.Symbol != "" {
		subjects[*cond.Subject] = true
	}
	return subjects
}

// libraryAPICensusAdmitted verifies the witness API against the persisted
// product census: the package must be a complete, importable product package
// owned by one of the product's modules, and the symbol must be exported. The
// witness builder proved the same property from source; this gate proves the
// persisted record still agrees with the census it cites.
func libraryAPICensusAdmitted(shape *domain.ProductShape, api domain.SymbolRef) bool {
	if shape == nil || api.Package == "" || api.Symbol == "" {
		return false
	}
	owned := make(map[string]bool, len(shape.OwnedModules))
	for _, m := range shape.OwnedModules {
		if m.Path != "" {
			owned[m.Path] = true
		}
	}
	if len(owned) == 0 {
		return false
	}
	name := api.Symbol
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	if r, _ := utf8.DecodeRuneInString(name); !unicode.IsUpper(r) {
		return false
	}
	for _, p := range shape.Packages {
		if p.Path != api.Package {
			continue
		}
		return p.ClauseComplete && p.Importable && p.Module != "" && owned[p.Module]
	}
	return false
}

// evidenceIDsResolve reports whether every id names a recorded evidence item.
func evidenceIDsResolve(c *domain.AnalysisCase, ids []domain.EvidenceID) bool {
	for _, id := range ids {
		if id == "" || c.EvidenceGraph.EvidenceByID(id) == nil {
			return false
		}
	}
	return true
}

// appendEvidenceIDs appends ids not already present, preserving order.
func appendEvidenceIDs(list []domain.EvidenceID, ids []domain.EvidenceID) []domain.EvidenceID {
	for _, id := range ids {
		if id != "" {
			list = appendUniqueID(list, id)
		}
	}
	return list
}
