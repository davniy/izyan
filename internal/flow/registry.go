package flow

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// The registry is the loop's admission surface and nothing else: it
// knows which checks are registered, whether a request satisfies the
// check's declared argument schema, and which conditions exist. It
// never interprets an observation and never knows a verdict.

// CheckRegistry is the optional interface a Registry implements to
// advertise its registered check ids to the planner. When absent the
// planner sees an empty availability list — plans stay admissible only
// through Check, which still fails closed on anything unregistered.
type CheckRegistry interface {
	Checks() []evidencetools.CheckSpec
}

// DispatchableRegistry is the optional interface a Registry implements
// to mark which advertised check ids are actually dispatchable in this
// run. A catalog may list ids it registers but cannot execute — a
// lane-internal check the deterministic lane already ran discharges
// through caller-declared completions, never through the broker; the
// engine keeps such ids out of available_checks so the planner is never
// invited to schedule something admission must reject. When absent
// every advertised check is dispatchable.
type DispatchableRegistry interface {
	Dispatchable(id string) bool
}

// ConditionRegistry is the optional interface a Registry implements to
// advertise its known conditions to the planner.
type ConditionRegistry interface {
	Conditions() []Condition
}

// CatalogRegistry is the production Registry: check admission is the
// evidence session's capability-gated catalog (a session view refuses
// requests whose capability the session denies), and conditions come
// from a caller-built table — code or configuration owns both, never
// the planner.
type CatalogRegistry struct {
	catalog    evidencetools.CheckCatalog
	conditions map[string]Condition
	order      []string
}

// NewCatalogRegistry builds the registry over one check catalog plus
// the known conditions. A nil catalog or a malformed condition table
// (empty or duplicated id) fails construction — a broken admission
// surface is a defect, not a run outcome.
func NewCatalogRegistry(cat evidencetools.CheckCatalog, conds []Condition) (*CatalogRegistry, error) {
	if cat == nil {
		return nil, fmt.Errorf("flow: registry requires a check catalog")
	}
	r := &CatalogRegistry{catalog: cat, conditions: map[string]Condition{}}
	for i, c := range conds {
		if c.ID == "" {
			return nil, fmt.Errorf("flow: registry condition at index %d has no id", i)
		}
		if _, dup := r.conditions[c.ID]; dup {
			return nil, fmt.Errorf("flow: registry condition %q registered twice", c.ID)
		}
		r.conditions[c.ID] = c
		r.order = append(r.order, c.ID)
	}
	return r, nil
}

// Check admits one proposed action: the adapter id must be registered,
// the action's declared purpose must be present, and the arguments must
// satisfy the catalog check's schema for this session. Every failure is
// an error — the caller maps it to UNSUPPORTED_CHECK_OR_CONDITION and
// the action is never executed. When Lookup refuses an id the catalog's
// own Validate carries the precise reason — unregistered, or registered
// but undispatchable (a lane-carried check the lane's audit ledger
// discharges instead of the broker).
func (r *CatalogRegistry) Check(a PlanAction) error {
	if a.AdapterID == "" {
		return fmt.Errorf("action %q carries no adapter id", a.ID)
	}
	spec, ok := r.catalog.Lookup(a.AdapterID)
	if !ok {
		if verr := r.catalog.Validate(a.AdapterID, a.Arguments); verr != nil {
			return fmt.Errorf("adapter %q cannot be scheduled: %w", a.AdapterID, verr)
		}
		return fmt.Errorf("adapter %q is not registered in the check catalog", a.AdapterID)
	}
	if a.Purpose == "" {
		return fmt.Errorf("action %q carries no declared purpose", a.ID)
	}
	if err := r.catalog.Validate(a.AdapterID, a.Arguments); err != nil {
		return fmt.Errorf("adapter %q rejected the action arguments: %w", spec.Tool, err)
	}
	return nil
}

// Dispatchable reports whether the id resolves to a check the broker
// can execute — registered and backed by a session tool. A registered
// lane-internal id (catalog-listed, no dispatchable spec) reports
// false: it is dischargeable from the lane's audit ledger, never
// schedulable.
func (r *CatalogRegistry) Dispatchable(id string) bool {
	_, ok := r.catalog.Lookup(id)
	return ok
}

// Condition resolves a condition id; unknown ids report false.
func (r *CatalogRegistry) Condition(id string) (Condition, bool) {
	c, ok := r.conditions[id]
	return c, ok
}

// Checks advertises the catalog's registered checks — schema and
// per-plan call bounds included — to the planner.
func (r *CatalogRegistry) Checks() []evidencetools.CheckSpec {
	return r.catalog.List()
}

// Conditions advertises the registered conditions in declaration order.
func (r *CatalogRegistry) Conditions() []Condition {
	out := make([]Condition, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.conditions[id])
	}
	return out
}
