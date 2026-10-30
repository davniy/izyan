// Package box exercises generic/interface materialization rules in the
// reachability scope: instantiated generic receivers are live, generic
// functions behind unresolved dispatch are UNKNOWN, and uninstantiated
// concrete receivers keep the existing narrowing.
package box

// Box is a generic container instantiated by Run.
type Box[T any] struct {
	V T
}

// get is reached only through the resolved instantiation Box[int]
// inside Run — the generic receiver collapses to one node, so a live
// call on any instantiation marks it live.
func (b Box[T]) get() T {
	return b.V
}

// snap makes Box a snapper implementation: Run materializes Box[int]
// behind the interface, so dispatch may reach snap — may-edge UNKNOWN,
// never DEAD (generic receivers are never narrowed away).
func (b Box[T]) snap() string {
	return "b"
}

// never is never called and arity-incompatible with every unresolved
// site in the package — dead even on a generic receiver.
func (b Box[T]) never(a, b2, c int) int {
	return a
}

// Vec is a generic type that is never instantiated anywhere: its
// methods stay dead unless a dispatch candidate exists.
type Vec[T any] struct {
	N int
}

// mul is never called and incompatible with the unresolved sites —
// DEAD.
func (v Vec[T]) mul(k string) string {
	return k
}

// hammer is a concrete snapper implementation that is never
// materialized anywhere — the interface-dispatch narrowing can prove
// the receiver cannot be its dynamic type, so snap stays DEAD.
type hammer struct{}

func (hammer) snap() string { return "h" }

// snapper is the product-local interface Run dispatches through.
type snapper interface {
	snap() string
}

// Run instantiates Box[int], calls its method, issues one interface
// dispatch and one unresolved func-value call.
func Run() string {
	b := Box[int]{V: 7}
	var s snapper = Box[int]{}
	var sel func(int, int) int
	if sel == nil {
		sel = pickSel()
	}
	_ = sel(1, 2)
	_ = b.get()
	return s.snap()
}

// pickSel hides the func-value source: the sel() call site cannot be
// resolved to a declared callee, leaving an unresolved dispatch site.
func pickSel() func(int, int) int {
	return nil
}

// choose is a generic function never instantiated. The unresolved
// sel(int,int) call is arity-compatible with choose's declared
// signature — a resolved instantiation is a real edge, but an
// unresolved generic materialization stays UNKNOWN, never DEAD.
func choose[T any](a, b T) T {
	return a
}
