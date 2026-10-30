package domain

import (
	"fmt"
	"strings"
)

// TransportProofSchema is the frozen schema discriminator of the rooted
// transport witnesses. A witness with another schema is not re-admitted: the
// bindings below are the proof, so their shape must be the agreed one.
const TransportProofSchema = "transport-proof/1"

// MechanismHTTP2RapidReset names the mechanism whose lifecycle obligations a
// TransportTriggerWitness discharges: a peer opens and immediately resets
// HTTP/2 streams while the server keeps executing their handlers, because
// stream removal does not join the handler and the fixed handler quota is
// absent.
const MechanismHTTP2RapidReset = "http2-rapid-reset"

// ParamMechanism binds a condition to a mechanism identifier. It selects the
// trigger obligation set the condition must discharge; it never carries the
// answer.
const ParamMechanism = "mechanism"

// TransportObligationID names one source/fix-bound obligation of a transport
// trigger. It is a closed enum so a consumer routes on the identifier instead
// of parsing prose.
type TransportObligationID string

const (
	// TransportObligationFrameConsumption: an active server transport
	// consumes peer-supplied HTTP/2 frames off the accepted connection.
	TransportObligationFrameConsumption TransportObligationID = "FRAME_CONSUMPTION"
	// TransportObligationResetReopen: the peer's frame stream can create a
	// stream, reset it, and create another — the dispatch admits all three.
	TransportObligationResetReopen TransportObligationID = "STREAM_RESET_REOPEN"
	// TransportObligationHandlerLifetime: handler execution is admitted and
	// its lifetime is asynchronous to the frame loop.
	TransportObligationHandlerLifetime TransportObligationID = "HANDLER_ASYNC_LIFETIME"
	// TransportObligationRemovalBeforeCompletion: reset removes the stream
	// from the active set without synchronously joining its handler.
	TransportObligationRemovalBeforeCompletion TransportObligationID = "STREAM_REMOVAL_BEFORE_COMPLETION"
	// TransportObligationNoFixedQuota: the analyzed source lacks the fixed
	// pre-dispatch handler-quota enforcement the fix introduces.
	TransportObligationNoFixedQuota TransportObligationID = "NO_FIXED_HANDLER_QUOTA"
	// TransportObligationControlPosition: every product-side control is
	// positioned after the vulnerable dispatch or is admission the reset
	// defeats, so none prevents the operation.
	TransportObligationControlPosition TransportObligationID = "CONTROL_POSITION"
)

// TransportTriggerObligationIDs is the ordered obligation set every
// http2-rapid-reset trigger witness must carry. The order is the proof order:
// frames → dispatch → lifetime → removal → missing fix → product controls.
var TransportTriggerObligationIDs = []TransportObligationID{
	TransportObligationFrameConsumption,
	TransportObligationResetReopen,
	TransportObligationHandlerLifetime,
	TransportObligationRemovalBeforeCompletion,
	TransportObligationNoFixedQuota,
	TransportObligationControlPosition,
}

// Valid reports whether id is a frozen transport obligation.
func (id TransportObligationID) Valid() bool {
	for _, known := range TransportTriggerObligationIDs {
		if id == known {
			return true
		}
	}
	return false
}

// TransportProofRequest is the source index's query for one rooted transport
// proof. Record and EntryRefs bind the proof to the assessed advisory record;
// Subjects are the affected symbols; FixURI/FixDigest/FixDiff are the fix
// evidence the trigger witness must be bound to. No member carries a verdict
// or a "proven" flag.
type TransportProofRequest struct {
	Record    RecordPin
	EntryRefs []int
	Subjects  []SymbolRef
	Product   ProductSnapshot
	Mechanism string
	FixURI    string
	FixDigest string
	FixDiff   string
}

// TransportProof is the proof collector's answer. Input is set only when the
// rooted listener/transport path is complete; Trigger is set only when the
// mechanism lifecycle obligations are all bound. Gaps carry the typed causes
// that kept a proof incomplete — an incomplete proof is analyzer work, never
// an external dependency.
type TransportProof struct {
	Input    *TransportInputWitness
	Trigger  *TransportTriggerWitness
	Evidence []Evidence
	Gaps     []AnalysisGap
}

// TransportSiteKind labels the role one source binding plays in a witness.
type TransportSiteKind string

const (
	TransportSiteRoot             TransportSiteKind = "PRODUCT_ROOT"
	TransportSiteConstruction     TransportSiteKind = "CONSTRUCTION"
	TransportSiteServe            TransportSiteKind = "SERVE_CALL"
	TransportSiteTransportEntry   TransportSiteKind = "TRANSPORT_ENTRY"
	TransportSiteFrameLoop        TransportSiteKind = "FRAME_LOOP"
	TransportSiteStreamAdmission  TransportSiteKind = "STREAM_ADMISSION"
	TransportSiteStreamReset      TransportSiteKind = "STREAM_RESET"
	TransportSiteHandlerStart     TransportSiteKind = "HANDLER_START"
	TransportSiteStreamRemoval    TransportSiteKind = "STREAM_REMOVAL"
	TransportSiteControl          TransportSiteKind = "PRODUCT_CONTROL"
	TransportSiteFixEnforcement   TransportSiteKind = "FIX_ENFORCEMENT"
	TransportSiteListenerCreation TransportSiteKind = "LISTENER_CREATION"
)

// TransportSite is one exact source binding: the symbol the bytes belong to,
// where those bytes are, their digest, and the verbatim slice the digest
// pins. A site with no digest or no source pins nothing and is rejected by the
// witness validators.
type TransportSite struct {
	Kind     TransportSiteKind `json:"kind"`
	Symbol   SymbolRef         `json:"symbol"`
	CallSite CallSite          `json:"call_site"`
	Digest   string            `json:"digest"`
	Source   string            `json:"source,omitempty"`
	Detail   string            `json:"detail,omitempty"`
}

// Validate enforces a pinned binding.
func (s TransportSite) Validate() error {
	if s.Symbol.Package == "" || s.Symbol.Symbol == "" {
		return fmt.Errorf("transport site %s: symbol is required", s.Kind)
	}
	if strings.TrimSpace(s.CallSite.File) == "" || s.CallSite.Line <= 0 {
		return fmt.Errorf("transport site %s (%s.%s): file and line are required",
			s.Kind, s.Symbol.Package, s.Symbol.Symbol)
	}
	if err := validatePinnedDigest("transport site "+string(s.Kind)+" digest", s.Digest); err != nil {
		return err
	}
	if strings.TrimSpace(s.Source) == "" {
		return fmt.Errorf("transport site %s (%s.%s): quoted source is required",
			s.Kind, s.Symbol.Package, s.Symbol.Symbol)
	}
	return nil
}

// TransportRoot pins the product-owned production root the path starts at: an
// owned package main function. Production is set only after the root file
// passed the production-file test, so a test/example/staging-only reference
// cannot be recorded as a root.
type TransportRoot struct {
	Package    string        `json:"package"`
	Production bool          `json:"production"`
	Site       TransportSite `json:"site"`
}

// Validate enforces the production-root binding.
func (r TransportRoot) Validate() error {
	if !r.Production {
		return fmt.Errorf("transport root %q: not a proven production root", r.Package)
	}
	if r.Package == "" {
		return fmt.Errorf("transport root: package is required")
	}
	if r.Site.Symbol.Package != r.Package {
		return fmt.Errorf("transport root %q: site symbol %q does not belong to the root package",
			r.Package, r.Site.Symbol.Package)
	}
	return r.Site.Validate()
}

// TransportServerBinding records that one server value was constructed by the
// affected module and that the same value's Serve was invoked.
type TransportServerBinding struct {
	Construction TransportSite `json:"construction"`
	Serve        TransportSite `json:"serve"`
	SameValue    bool          `json:"same_value"`
}

// Validate enforces construction → same-value → Serve.
func (b TransportServerBinding) Validate() error {
	if !b.SameValue {
		return fmt.Errorf("transport server binding: the constructed server is not the value passed to Serve")
	}
	if err := b.Construction.Validate(); err != nil {
		return err
	}
	if err := b.Serve.Validate(); err != nil {
		return err
	}
	if b.Construction.Symbol.Package != b.Serve.Symbol.Package {
		return fmt.Errorf("transport server binding: construction package %q and Serve package %q disagree",
			b.Construction.Symbol.Package, b.Serve.Symbol.Package)
	}
	return nil
}

// TransportListenerBinding records that the listener passed to Serve was
// constructed by product code and is the same value Serve received.
type TransportListenerBinding struct {
	Creation  TransportSite `json:"creation"`
	Serve     TransportSite `json:"serve"`
	SameValue bool          `json:"same_value"`
}

// Validate enforces creation → same-value → Serve.
func (b TransportListenerBinding) Validate() error {
	if !b.SameValue {
		return fmt.Errorf("transport listener binding: the constructed listener is not the value passed to Serve")
	}
	if err := b.Creation.Validate(); err != nil {
		return err
	}
	return b.Serve.Validate()
}

// TransportInputWitness pins the rooted server-transport input proof:
//
//	record/entry/build → product-owned production root → server construction →
//	listener construction → Serve on the same values → path into the affected
//	transport.
//
// It says a client of the product's affected transport supplies the bytes the
// transport consumes. It never says an adversary can reach that transport.
type TransportInputWitness struct {
	Schema      string                   `json:"schema"`
	Mechanism   string                   `json:"mechanism,omitempty"`
	Record      RecordPin                `json:"record"`
	EntryRefs   []int                    `json:"entry_refs,omitempty"`
	Module      string                   `json:"module"`
	Affected    []SymbolRef              `json:"affected"`
	Build       BuildContext             `json:"build"`
	Root        TransportRoot            `json:"root"`
	Chain       []TransportSite          `json:"chain"`
	Server      TransportServerBinding   `json:"server"`
	Listener    TransportListenerBinding `json:"listener"`
	Transport   []TransportSite          `json:"transport"`
	Artifacts   []TransportArtifact      `json:"artifacts"`
	EvidenceIDs []EvidenceID             `json:"evidence_ids"`
	Limitations []string                 `json:"limitations,omitempty"`
}

// TransportArtifact pins the exact source bytes one binding was read from.
type TransportArtifact struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// Validate enforces the artifact pin.
func (a TransportArtifact) Validate() error {
	if strings.TrimSpace(a.Path) == "" {
		return fmt.Errorf("transport artifact: path is required")
	}
	return validatePinnedDigest("transport artifact "+a.Path, a.Digest)
}

// Complete reports nil only when every rooted-input binding is present and
// pinned. A partial witness is analyzer work in progress, never a proof.
func (w *TransportInputWitness) Complete() error {
	if w == nil {
		return fmt.Errorf("transport input witness is missing")
	}
	if w.Schema != TransportProofSchema {
		return fmt.Errorf("transport input witness schema %q is not %q", w.Schema, TransportProofSchema)
	}
	if err := w.Record.Validate(); err != nil {
		return err
	}
	if err := validateEntryRefs("transport input entry refs", w.EntryRefs); err != nil {
		return err
	}
	if strings.TrimSpace(w.Module) == "" {
		return fmt.Errorf("transport input witness: module is required")
	}
	if w.Root.Validate() != nil {
		return fmt.Errorf("transport input witness: %w", w.Root.Validate())
	}
	if len(w.Chain) == 0 {
		return fmt.Errorf("transport input witness: root-to-serve chain is empty")
	}
	for i, step := range w.Chain {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("transport input witness chain[%d]: %w", i, err)
		}
	}
	if err := w.Server.Validate(); err != nil {
		return fmt.Errorf("transport input witness: %w", err)
	}
	if err := w.Listener.Validate(); err != nil {
		return fmt.Errorf("transport input witness: %w", err)
	}
	if len(w.Transport) == 0 {
		return fmt.Errorf("transport input witness: path into the affected transport is empty")
	}
	for i, step := range w.Transport {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("transport input witness transport[%d]: %w", i, err)
		}
	}
	if len(w.Affected) == 0 {
		return fmt.Errorf("transport input witness: affected symbols are required")
	}
	if len(w.Artifacts) == 0 {
		return fmt.Errorf("transport input witness: source artifacts are required")
	}
	for i, a := range w.Artifacts {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("transport input witness artifacts[%d]: %w", i, err)
		}
	}
	if len(w.EvidenceIDs) == 0 {
		return fmt.Errorf("transport input witness: evidence ids are required")
	}
	return nil
}

// TransportControlDisposition classifies one product-side control by its
// position relative to the vulnerable dispatch. Only a pre-dispatch quota
// prevents the mechanism; the others are recorded so their presence cannot be
// mistaken for prevention.
type TransportControlDisposition string

const (
	// TransportControlPreDispatchQuota bounds concurrent handler executions
	// before the transport dispatches them. It defeats the mechanism.
	TransportControlPreDispatchQuota TransportControlDisposition = "PRE_DISPATCH_QUOTA"
	// TransportControlHandlerLevel runs inside the handler chain, after the
	// stream was admitted and dispatched. A unary/stream interceptor is this.
	TransportControlHandlerLevel TransportControlDisposition = "HANDLER_LEVEL"
	// TransportControlTransportAdmission is transport admission keyed on the
	// active stream set the reset removes, so it does not bound handlers.
	TransportControlTransportAdmission TransportControlDisposition = "TRANSPORT_ADMISSION_RESET_DEFEATED"
	// TransportControlConnectionLevel bounds accepted connections, not the
	// handler executions one already-accepted connection dispatches.
	TransportControlConnectionLevel TransportControlDisposition = "CONNECTION_LEVEL"
	// TransportControlUnclassified is a concurrency-shaped control whose
	// position the analysis could not establish. It blocks the proof.
	TransportControlUnclassified TransportControlDisposition = "UNCLASSIFIED"
)

// Valid reports whether the disposition is frozen.
func (d TransportControlDisposition) Valid() bool {
	switch d {
	case TransportControlPreDispatchQuota, TransportControlHandlerLevel,
		TransportControlTransportAdmission, TransportControlConnectionLevel,
		TransportControlUnclassified:
		return true
	default:
		return false
	}
}

// Prevents reports whether the control defeats the transport mechanism.
func (d TransportControlDisposition) Prevents() bool {
	return d == TransportControlPreDispatchQuota
}

// BlocksProof reports whether the control's position is unknown, so the
// mechanism cannot be decided either way.
func (d TransportControlDisposition) BlocksProof() bool {
	return d == TransportControlUnclassified
}

// TransportControl is one product-side control with its position.
type TransportControl struct {
	Site        TransportSite               `json:"site"`
	Disposition TransportControlDisposition `json:"disposition"`
	Detail      string                      `json:"detail,omitempty"`
}

// Validate enforces a classified, pinned control.
func (c TransportControl) Validate() error {
	if !c.Disposition.Valid() {
		return fmt.Errorf("transport control disposition %q is unknown", c.Disposition)
	}
	if err := c.Site.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Detail) == "" {
		return fmt.Errorf("transport control %s.%s: position rationale is required",
			c.Site.Symbol.Package, c.Site.Symbol.Symbol)
	}
	return nil
}

// TransportFixBinding records the fix evidence the trigger proof is bound to
// and the enforcement identifiers that fix introduces. The analyzed source
// must not already contain them; that absence is the missing-quota proof.
type TransportFixBinding struct {
	URI              string          `json:"uri"`
	Digest           string          `json:"digest"`
	DiffDigest       string          `json:"diff_digest"`
	EnforcementNames []string        `json:"enforcement_names"`
	Sites            []TransportSite `json:"sites,omitempty"`
}

// Validate enforces the fix-evidence pin and the enforcement names.
func (b TransportFixBinding) Validate() error {
	if strings.TrimSpace(b.URI) == "" {
		return fmt.Errorf("transport fix binding: uri is required")
	}
	if err := validatePinnedDigest("transport fix binding digest", b.Digest); err != nil {
		return err
	}
	if err := validatePinnedDigest("transport fix binding diff digest", b.DiffDigest); err != nil {
		return err
	}
	if len(b.EnforcementNames) == 0 {
		return fmt.Errorf("transport fix binding: the fix introduces no identified handler-quota enforcement")
	}
	return nil
}

// TransportTriggerObligation is one discharged (or failed) trigger obligation
// with the exact source bindings that establish it. Absence records the source
// constructs the analysis proved absent — that is how a missing fix is bound.
type TransportTriggerObligation struct {
	ID        TransportObligationID `json:"id"`
	Satisfied bool                  `json:"satisfied"`
	Sites     []TransportSite       `json:"sites,omitempty"`
	Absence   []string              `json:"absence,omitempty"`
	Detail    string                `json:"detail,omitempty"`
}

// Validate enforces one obligation record.
func (o TransportTriggerObligation) Validate() error {
	if !o.ID.Valid() {
		return fmt.Errorf("transport obligation %q is unknown", o.ID)
	}
	if o.Satisfied && len(o.Sites) == 0 {
		return fmt.Errorf("transport obligation %s: a satisfied obligation needs source bindings", o.ID)
	}
	for i, s := range o.Sites {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("transport obligation %s sites[%d]: %w", o.ID, i, err)
		}
	}
	if !o.Satisfied && strings.TrimSpace(o.Detail) == "" {
		return fmt.Errorf("transport obligation %s: an unsatisfied obligation needs the reason", o.ID)
	}
	return nil
}

// TransportTriggerWitness pins the source/fix-bound mechanism proof. It
// carries the rooted input witness it extends, so a trigger can never be
// detached from the production root and listener that make it reachable.
type TransportTriggerWitness struct {
	Schema      string                       `json:"schema"`
	Mechanism   string                       `json:"mechanism"`
	Record      RecordPin                    `json:"record"`
	Module      string                       `json:"module"`
	Build       BuildContext                 `json:"build"`
	Input       TransportInputWitness        `json:"input"`
	Fix         TransportFixBinding          `json:"fix"`
	Obligations []TransportTriggerObligation `json:"obligations"`
	Controls    []TransportControl           `json:"controls,omitempty"`
	EvidenceIDs []EvidenceID                 `json:"evidence_ids"`
	Limitations []string                     `json:"limitations,omitempty"`
}

// Obligation returns the named obligation.
func (w *TransportTriggerWitness) Obligation(id TransportObligationID) (TransportTriggerObligation, bool) {
	if w == nil {
		return TransportTriggerObligation{}, false
	}
	for _, o := range w.Obligations {
		if o.ID == id {
			return o, true
		}
	}
	return TransportTriggerObligation{}, false
}

// PreventingControl returns the first product control that defeats the
// mechanism.
func (w *TransportTriggerWitness) PreventingControl() (TransportControl, bool) {
	if w == nil {
		return TransportControl{}, false
	}
	for _, c := range w.Controls {
		if c.Disposition.Prevents() {
			return c, true
		}
	}
	return TransportControl{}, false
}

// Complete reports nil only when the mechanism is identified, the rooted input
// witness is complete, the fix is bound, and every mechanism obligation is
// satisfied with no preventing control. It returns the first unmet
// requirement, so a caller can turn it into a typed gap instead of a verdict.
func (w *TransportTriggerWitness) Complete() error {
	if w == nil {
		return fmt.Errorf("transport trigger witness is missing")
	}
	if w.Schema != TransportProofSchema {
		return fmt.Errorf("transport trigger witness schema %q is not %q", w.Schema, TransportProofSchema)
	}
	if w.Mechanism != MechanismHTTP2RapidReset {
		return fmt.Errorf("transport trigger witness mechanism %q is not %q", w.Mechanism, MechanismHTTP2RapidReset)
	}
	if err := w.Record.Validate(); err != nil {
		return err
	}
	if err := w.Input.Complete(); err != nil {
		return fmt.Errorf("transport trigger witness: %w", err)
	}
	if w.Input.Mechanism != w.Mechanism {
		return fmt.Errorf("transport trigger witness mechanism %q disagrees with its input proof %q",
			w.Mechanism, w.Input.Mechanism)
	}
	if w.Input.Record.RecordID != w.Record.RecordID || w.Input.Module != w.Module {
		return fmt.Errorf("transport trigger witness record/module disagree with its input proof")
	}
	if err := w.Fix.Validate(); err != nil {
		return fmt.Errorf("transport trigger witness: %w", err)
	}
	if len(w.EvidenceIDs) == 0 {
		return fmt.Errorf("transport trigger witness: evidence ids are required")
	}
	for _, id := range TransportTriggerObligationIDs {
		o, ok := w.Obligation(id)
		if !ok {
			return fmt.Errorf("transport trigger witness: obligation %s is missing", id)
		}
		if err := o.Validate(); err != nil {
			return err
		}
		if !o.Satisfied {
			reason := o.Detail
			if reason == "" {
				reason = "no source binding established it"
			}
			return fmt.Errorf("transport trigger witness: obligation %s is unsatisfied: %s", id, reason)
		}
	}
	if c, ok := w.PreventingControl(); ok {
		return fmt.Errorf("transport trigger witness: product control %s.%s is a pre-dispatch quota and prevents the mechanism",
			c.Site.Symbol.Package, c.Site.Symbol.Symbol)
	}
	for i, c := range w.Controls {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("transport trigger witness controls[%d]: %w", i, err)
		}
		if c.Disposition.BlocksProof() {
			return fmt.Errorf("transport trigger witness: control %s.%s position is unclassified",
				c.Site.Symbol.Package, c.Site.Symbol.Symbol)
		}
	}
	return nil
}

// TransportWitnessFromEvidence returns the first transport input witness and
// the first transport trigger witness carried by the given evidence. It is the
// only read path: witnesses travel in evidence so a persisted proof is
// re-admitted rather than re-asserted.
func TransportWitnessFromEvidence(evidence []Evidence) (input *TransportInputWitness, trigger *TransportTriggerWitness) {
	for i := range evidence {
		if input == nil && evidence[i].TransportInput != nil {
			input = evidence[i].TransportInput
		}
		if trigger == nil && evidence[i].TransportTrigger != nil {
			trigger = evidence[i].TransportTrigger
		}
	}
	return input, trigger
}
