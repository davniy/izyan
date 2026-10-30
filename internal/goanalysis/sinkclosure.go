package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"time"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// SinkSetBasis returns the advisory-bound completeness contract for the
// condition's declared sink set. The set is complete only when every sink
// the exploit model declares is bound by the subjects and every
// unresolved subject is proven absent from the linked build. Advisory
// membership by itself is never a contract: a set that omits a declared
// sink, carries an extra subject outside the advisory modules, or leaves
// an unresolved non-absent subject returns ok=false so the sink closure
// stays KNOWN_ONLY.
func SinkSetBasis(c *domain.AnalysisCase, subjects []domain.SymbolRef, proof *domain.ContentAdmission) (string, bool) {
	if c == nil || c.Exploit == nil || len(subjects) == 0 {
		return "", false
	}
	if c.Vulnerability.ID == "" || c.Vulnerability.Module == "" {
		return "", false
	}
	// The contract binds the sink set to a resolved, affected version —
	// an undecided version cannot state which advisory subject set the
	// closure is complete for.
	if c.Affected == nil ||
		c.Affected.ModulePresent != domain.ClaimTrue ||
		c.Affected.VersionAffected != domain.ClaimTrue ||
		c.Affected.ResolvedVersion == "" {
		return "", false
	}
	mods := caseModules(c)
	subjectSet := map[string]bool{}
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		if s.Package == "" || s.Symbol == "" {
			return "", false
		}
		if !inCaseModules(s.Package, mods) {
			return "", false
		}
		if subjectSet[key] {
			return "", false
		}
		subjectSet[key] = true
	}
	absent := map[domain.SymbolRef]bool{}
	// A subject counts as proven absent only when the single shared admission
	// still establishes it. A saved AbsentSubjects entry is a conclusion, not
	// evidence: without this the completeness contract could call an
	// unadmitted subject absent and let a sink closure confirm a negative.
	absenceAdmission := domain.AdmitAbsence(c, affected.AdmittedBuildGraph(c.Product, c.EvidenceGraph.EvidenceList()), proof)
	for _, s := range c.Exploit.AbsentSubjects {
		if absenceAdmission.Admits(s).Admitted {
			absent[s] = true
		}
	}
	// Every declared sink must be bound by the subject set or proven
	// absent from the build: an omitted live sink is an enumeration gap.
	declared := map[string]domain.SymbolRef{}
	for _, s := range c.Exploit.RootCauses {
		declared[s.Package+"."+s.Symbol] = s
	}
	for _, s := range c.Vulnerability.AffectedSymbols {
		declared[s.Package+"."+s.Symbol] = s
	}
	if len(declared) == 0 {
		return "", false
	}
	for key, s := range declared {
		if subjectSet[key] || absent[s] {
			continue
		}
		return "", false
	}
	for key := range subjectSet {
		if _, ok := declared[key]; !ok {
			return "", false
		}
	}
	// An unresolved subject that is not proven absent could be a live
	// sink outside the subject set — the declared set is then incomplete.
	for _, s := range c.Exploit.UnresolvedSubjects {
		if !absent[s] {
			return "", false
		}
	}
	keys := make([]string, 0, len(subjectSet))
	for key := range subjectSet {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return fmt.Sprintf(
		"advisory %s: %d declared sink subject(s) in %s@%s, all bound to the closure; no unresolved non-absent subject",
		c.Vulnerability.ID, len(keys), c.Vulnerability.Module, c.Affected.ResolvedVersion), true
}

// ExploitLocusBindingBasis returns the deterministic completeness
// contract for a symbol-less advisory whose condition subjects were
// derived from a verified exploit-locus binding. Advisory membership or
// an LLM proposal alone never yields a basis: the record must be
// COMPLETE with no blocker, the advisory/module/version identities must
// equal the case, the affected entry must declare no structured symbols,
// the subject set must equal the binding's verified sink set exactly (no
// added subject, no omitted sink), every sink must carry its verified
// module identity, the trigger argument index must be the one the
// condition binds, and any unresolved subject must either be proven
// absent or be exactly a verified sink. Anything else returns ok=false
// so the closure stays KNOWN_ONLY — a cross-module sink is admissible
// only through this record, never by relaxing the ordinary basis.
func ExploitLocusBindingBasis(c *domain.AnalysisCase, subjects []domain.SymbolRef,
	binding *domain.ExploitLocusBinding, argIndex int, proof *domain.ContentAdmission) (string, bool) {
	if c == nil || c.Exploit == nil || binding == nil || !binding.Complete || len(binding.Blockers) > 0 {
		return "", false
	}
	if len(subjects) == 0 || len(binding.Sinks) == 0 {
		return "", false
	}
	if c.Vulnerability.ID == "" || c.Vulnerability.Module == "" ||
		c.Vulnerability.ID != binding.AdvisoryID || c.Vulnerability.Module != binding.Module {
		return "", false
	}
	if c.Affected == nil ||
		c.Affected.ModulePresent != domain.ClaimTrue ||
		c.Affected.VersionAffected != domain.ClaimTrue ||
		c.Affected.ResolvedVersion == "" ||
		c.Affected.ResolvedVersion != binding.Version {
		return "", false
	}
	if binding.VulnerablePackage == "" || binding.VulnerableSymbol == "" {
		return "", false
	}
	if argIndex < 0 || binding.TriggerArgIndex != argIndex {
		return "", false
	}
	// The route exists only for a genuinely symbol-less advisory entry:
	// an advisory that declares symbols belongs to the ordinary route.
	if len(c.Vulnerability.AffectedSymbols) > 0 {
		return "", false
	}
	for _, ap := range c.Vulnerability.AffectedPackages {
		if len(ap.Symbols) > 0 {
			return "", false
		}
	}
	bound := map[string]domain.ExploitLocusSink{}
	for _, s := range binding.Sinks {
		key := s.Package + "." + s.Symbol
		if s.Package == "" || s.Symbol == "" || s.Module == "" {
			return "", false
		}
		if _, dup := bound[key]; dup {
			return "", false
		}
		bound[key] = s
	}
	subjectSet := map[string]bool{}
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		if s.Package == "" || s.Symbol == "" || subjectSet[key] {
			return "", false
		}
		if _, ok := bound[key]; !ok {
			// No extra subject may be added: a subject outside the
			// verified sink set would claim coverage the binding never
			// enumerated.
			return "", false
		}
		subjectSet[key] = true
	}
	if len(subjectSet) != len(bound) {
		return "", false
	}
	absent := map[domain.SymbolRef]bool{}
	// A subject counts as proven absent only when the single shared admission
	// still establishes it. A saved AbsentSubjects entry is a conclusion, not
	// evidence: without this the completeness contract could call an
	// unadmitted subject absent and let a sink closure confirm a negative.
	absenceAdmission := domain.AdmitAbsence(c, affected.AdmittedBuildGraph(c.Product, c.EvidenceGraph.EvidenceList()), proof)
	for _, s := range c.Exploit.AbsentSubjects {
		if absenceAdmission.Admits(s).Admitted {
			absent[s] = true
		}
	}
	for _, s := range c.Exploit.UnresolvedSubjects {
		key := s.Package + "." + s.Symbol
		if absent[s] {
			continue
		}
		if _, ok := bound[key]; !ok {
			return "", false
		}
	}
	for _, s := range c.Exploit.RootCauses {
		key := s.Package + "." + s.Symbol
		if _, ok := bound[key]; !ok && !absent[s] {
			return "", false
		}
	}
	keys := make([]string, 0, len(subjectSet))
	for key := range subjectSet {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return fmt.Sprintf(
		"advisory %s: symbol-less exploit-locus binding %s; vulnerable %s.%s; complete product-facing trigger sink set at ArgIndex %d; %d verified sink(s) %v; all sink-to-locus paths resolved; no unresolved candidate",
		c.Vulnerability.ID, binding.ProposalID, binding.VulnerablePackage,
		binding.VulnerableSymbol, argIndex, len(keys), keys), true
}

// SinkClosure enumerates every call site of each subject in the
// completeness-declared sink set — product packages plus the reachable
// dependency cone — and classifies the payload input at each site that
// can execute in the effective build. argIndex selects the payload
// argument; a negative value covers every argument plus the receiver of
// the call (a method's receiver state is itself a payload position).
//
// A site is dead only with positive unreachable evidence — an unlinked
// package, a caller with no resolvable invocation path, or a method
// reachable solely through a reflect-dispatched API whose call sites
// cannot carry its receiver type (callerReachable). Dead sites are
// recorded for audit but contribute nothing. Everything else —
// unresolvable provenance, unseen callers, undischarged dispatch —
// keeps the closure incomplete rather than guessed safe.
//
// Complete requires: the recorded basis (a sink-set completeness
// contract), zero enumeration blockers, and every live site's payload
// input resolved to a non-external origin.
func (ix *Index) SinkClosure(ctx context.Context, condID domain.ConditionID, module, basis string,
	subjects []domain.SymbolRef, argIndex, hops int) (domain.SinkClosure, []domain.Evidence, error) {

	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)

	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
	}

	prevActiveCtx := ix.activeCtx
	ix.activeCtx = ctx
	defer func() {
		ix.activeCtx = prevActiveCtx
	}()

	prevBudget := ix.loadBudget
	prevExhausted := ix.loadBudgetExhausted
	if ix.loadBudget == 0 && !ix.loadBudgetExhausted {
		ix.loadBudget = 48
	}
	defer func() {
		// Only the query-scoped budget is restored: later queries may
		// load again, but a depletion recorded above stays in the
		// session-scoped truncation record, so this session can never
		// claim complete dependency coverage again.
		ix.loadBudget = prevBudget
		ix.loadBudgetExhausted = prevExhausted
	}()

	cl := domain.SinkClosure{ConditionID: condID, Module: module, Basis: basis}
	if err := ctx.Err(); err != nil {
		cl.Blockers = append(cl.Blockers, fmt.Sprintf("closure query deadline exceeded: %v", err))
		return cl, nil, nil
	}
	if ix.loadBudgetExhausted {
		cl.Blockers = append(cl.Blockers, "closure query package load budget exhausted")
		return cl, nil, nil
	}
	if err := ix.load(ctx); err != nil {
		return domain.SinkClosure{}, nil, err
	}
	if basis == "" {
		cl.Blockers = append(cl.Blockers,
			"sink set has no completeness contract (KNOWN_ONLY)")
	}
	if len(subjects) == 0 {
		cl.Blockers = append(cl.Blockers, "empty sink set")
	}
	prev := ix.hopLimit
	ix.hopLimit = hops
	ix.funcDeclCache = map[string]funcDeclResult{}
	defer func() {
		ix.hopLimit = prev
		ix.funcDeclCache = nil
	}()
	var livePos, configPos, dead, unsafePos, unresolved int
	pinned := map[string]bool{}
	cumulativeEvalBudget := maxEvalBudget * 8

	for _, subj := range subjects {
		if err := ctx.Err(); err != nil {
			cl.Blockers = append(cl.Blockers, fmt.Sprintf("closure query deadline exceeded: %v", err))
			unresolved++
			break
		}
		if ix.loadBudgetExhausted {
			cl.Blockers = append(cl.Blockers, "closure query package load budget exhausted")
			unresolved++
			break
		}
		key := subj.Package + "." + subj.Symbol
		// Every declared sink must exist in the analyzed version — a
		// missing symbol leaves the set's coverage unproven.
		cs, err := ix.findSymbol(ctx, subj)
		if err != nil || cs == nil {
			if ctx.Err() != nil {
				cl.Blockers = append(cl.Blockers, fmt.Sprintf("closure query deadline exceeded: %v", ctx.Err()))
				unresolved++
				break
			}
			if ix.loadBudgetExhausted {
				cl.Blockers = append(cl.Blockers, "closure query package load budget exhausted")
				unresolved++
				break
			}
			cl.Blockers = append(cl.Blockers,
				fmt.Sprintf("declared sink %s not found in analyzed version", key))
			continue
		}
		spkg := ix.pkgForPath(subj.Package)
		if spkg == nil {
			cl.Blockers = append(cl.Blockers,
				fmt.Sprintf("declared sink %s: owning package not loaded", key))
			continue
		}
		// Whole-module load so module-internal callers are enumerable —
		// callerScope for dep packages covers product+extras, and the
		// extras must include every package of the subject's module.
		if spkg.Module != nil {
			pattern := spkg.Module.Path + "/..."
			if _, err := ix.loadExtra(ctx, pattern); err != nil {
				if ctx.Err() != nil {
					cl.Blockers = append(cl.Blockers, fmt.Sprintf("closure query deadline exceeded: %v", ctx.Err()))
					unresolved++
					break
				}
				if ix.loadBudgetExhausted {
					cl.Blockers = append(cl.Blockers, "closure query package load budget exhausted")
					unresolved++
					break
				}
				cl.Blockers = append(cl.Blockers,
					fmt.Sprintf("declared sink %s: module load failed: %v", key, err))
			} else {
				// The subject module stays resident through the closure —
				// evicting it mid-verification drops its callers and turns
				// resolved payload positions UNKNOWN.
				if !pinned[pattern] {
					defer ix.pinExtraScoped(pattern)()
					pinned[pattern] = true
				}
			}
		}
		depBlockers := ix.unseenDepCallers(ctx, subj, spkg)
		cl.Blockers = append(cl.Blockers, depBlockers...)
		if ctx.Err() != nil || ix.loadBudgetExhausted {
			unresolved++
			break
		}
		seen := map[string]bool{}
		for _, r := range ix.callersOf(spkg, subj) {
			if ctx.Err() != nil {
				cl.Blockers = append(cl.Blockers, fmt.Sprintf("closure query deadline exceeded: %v", ctx.Err()))
				unresolved++
				break
			}
			if r.possible {
				cl.Blockers = append(cl.Blockers, fmt.Sprintf(
					"declared sink %s: caller set changed or has unresolved function-value dispatch", key))
				if r.call == nil || r.pkg == nil {
					continue
				}
			}
			skey := fmt.Sprintf("%s:%d:%d", r.Site.File, r.Site.Line, r.Site.Column)
			if seen[skey] {
				continue
			}
			seen[skey] = true
			if !ix.callerReachable(r.pkg, r.enclosing) {
				dead++
				cl.Sites = append(cl.Sites, domain.SinkSite{
					CallSite: r.Site, Sink: key, Arg: -1, Live: false,
					Detail: "dead in effective build",
				})
				continue
			}
			call := r.call
			// An exact payload position that the call does not supply is
			// an enumeration gap, not a site with a safe origin: the
			// declared argument index cannot be proven for this call.
			if argIndex >= 0 && argIndex >= len(call.Args) {
				cl.Blockers = append(cl.Blockers, fmt.Sprintf(
					"call site %s:%d invokes %s with %d argument(s); declared payload position %d is absent",
					r.Site.File, r.Site.Line, key, len(call.Args), argIndex))
				continue
			}
			var positions []struct {
				arg  int
				expr ast.Expr
			}
			add := func(arg int, e ast.Expr) {
				positions = append(positions, struct {
					arg  int
					expr ast.Expr
				}{arg, e})
			}
			if argIndex >= 0 {
				add(argIndex, call.Args[argIndex])
			} else {
				for i, a := range call.Args {
					add(i, a)
				}
			}
			// The receiver of a method call is object state the callee
			// reads — a payload position in its own right (a decoder's
			// buffer never travels through an argument). Exact-argument
			// mode enumerates only the declared payload position: the
			// post-reach contract binds one trigger argument, and a
			// receiver record would not match that exact ArgIndex.
			if argIndex < 0 {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if selection := r.pkg.TypesInfo.Selections[sel]; selection != nil && selection.Kind() == types.MethodVal {
						add(-1, sel.X)
					}
				}
			}
			for _, p := range positions {
				if err := ctx.Err(); err != nil {
					cl.Blockers = append(cl.Blockers, fmt.Sprintf("closure query deadline exceeded: %v", err))
					unresolved++
					break
				}
				if cumulativeEvalBudget <= 0 {
					addEvalBlocker(&cl)
					unresolved++
					livePos++
					cl.Sites = append(cl.Sites, domain.SinkSite{
						CallSite: r.Site, Sink: key, Arg: p.arg, Live: true,
						Origin: domain.OriginUnknown, Detail: "closure query evaluation budget exhausted",
					})
					continue
				}
				var tx []domain.CallSite
				ix.txBuf = &tx
				ix.traceSeen = map[types.Object]bool{}
				ix.paramSeen = map[string]bool{}
				ix.paramCache = map[string]classifyResult{}
				ix.classifyCache = map[classifyKey]classifyResult{}
				posBudget := cumulativeEvalBudget
				if posBudget > maxEvalBudget*4 {
					posBudget = maxEvalBudget * 4
				}
				ix.evalBudget = posBudget
				origin, why := ix.classify(r.pkg, r.enclosing, p.expr, 1)
				if ix.evalBudget < 0 {
					spent := posBudget
					cumulativeEvalBudget -= spent
				} else {
					spent := posBudget - ix.evalBudget
					cumulativeEvalBudget -= spent
				}
				ix.txBuf = nil
				ix.txSeen = nil
				ix.traceSeen = nil
				ix.paramSeen = nil
				ix.paramCache = nil
				ix.classifyCache = nil
				ix.evalBudget = 0
				livePos++
				switch {
				case domain.SafeOrigin(origin):
				case origin == domain.OriginConfiguration:
					// Configuration is a resolved, non-external origin:
					// it keeps the enumeration complete, but the
					// falsifier-specific gate (constant vs config basis)
					// decides whether it may ground a claim.
					configPos++
				case origin == domain.OriginUnknown || origin == "":
					unresolved++
				default:
					unsafePos++
				}
				detail := why
				if len(detail) > 300 {
					detail = detail[:300]
				}
				cl.Sites = append(cl.Sites, domain.SinkSite{
					CallSite: r.Site, Sink: key, Arg: p.arg, Live: true,
					Origin: origin, Detail: detail,
				})
			}
		}
	}
	// A budget exhausted anywhere in this verification session truncated
	// dependency coverage. The gap belongs to every later closure claim of
	// the session: a repeated, cleaner-looking enumeration must not discard
	// the earlier unresolved state, so the named truncation rides every
	// result as a blocker and keeps Complete false.
	cl.Blockers = append(cl.Blockers, ix.sessionTruncationBlockersLocked()...)
	cl.Complete = len(cl.Blockers) == 0 && unsafePos == 0 && unresolved == 0
	content := fmt.Sprintf(
		"cond=%s sinks=%d live-positions=%d config=%d unsafe=%d unresolved=%d dead-sites=%d blockers=%d complete=%v",
		condID, len(subjects), livePos, configPos, unsafePos, unresolved, dead,
		len(cl.Blockers), cl.Complete)
	if cl.Basis != "" {
		content += "; basis: " + cl.Basis
	}
	return cl, []domain.Evidence{{
		Kind:    domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "dependency sink-closure inventory " + module,
		Tool:    "goanalysis.Index.SinkClosure",
		Content: content,
	}}, nil
}

func addEvalBlocker(cl *domain.SinkClosure) {
	for _, b := range cl.Blockers {
		if b == "closure query evaluation budget exhausted" {
			return
		}
	}
	cl.Blockers = append(cl.Blockers, "closure query evaluation budget exhausted")
}

// pkgForPath locates a package among the loaded product roots and dep
// extras by its import path.
func (ix *Index) pkgForPath(path string) *packages.Package {
	for _, p := range ix.pkgs {
		if p.PkgPath == path {
			return p
		}
	}
	for _, p := range ix.allExtras() {
		if p.PkgPath == path {
			return p
		}
	}
	return nil
}

// unseenDepCallers reports dependency packages that import subj's
// package, can execute in this build, and are outside the loaded cone —
// the site enumeration cannot see their call sites, so each one blocks
// completeness. Product packages, same-module packages and loaded
// extras are covered; unlinked packages cannot execute.
func (ix *Index) unseenDepCallers(ctx context.Context, subj domain.SymbolRef, spkg *packages.Package) []string {
	if err := ctx.Err(); err != nil {
		return []string{fmt.Sprintf("closure query deadline exceeded: %v", err)}
	}
	if ix.loadBudgetExhausted {
		return []string{"closure query package load budget exhausted"}
	}
	mod := ""
	if spkg.Module != nil {
		mod = spkg.Module.Path
	}
	imps, err := ix.depImporters(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return []string{fmt.Sprintf("closure query deadline exceeded: %v", ctx.Err())}
		}
		if ix.loadBudgetExhausted {
			return []string{"closure query package load budget exhausted"}
		}
		return []string{fmt.Sprintf("dep-import index for %s unavailable: %v", subj.Package, err)}
	}
	linked := ix.linkedPaths()
	var out []string
	for _, imp := range imps[subj.Package] {
		if err := ctx.Err(); err != nil {
			out = append(out, fmt.Sprintf("closure query deadline exceeded: %v", err))
			break
		}
		if ix.loadBudgetExhausted {
			out = append(out, "closure query package load budget exhausted")
			break
		}
		if imp.path == subj.Package || (mod != "" && imp.module == mod) {
			continue // same package/module — covered by the module load
		}
		if ix.isProductPath(imp.path) {
			continue // product package — sites come from the root scan
		}
		if !linked[imp.path] {
			continue // unlinked — cannot execute in this build
		}
		if len(ix.extrasFor(imp.path)) > 0 {
			continue // loaded — sites enumerated
		}
		// The importer can execute but is not in the cone yet — pull it
		// in rather than give up on enumeration.
		if _, err := ix.loadExtra(ctx, imp.path); err == nil && len(ix.extrasFor(imp.path)) > 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			out = append(out, fmt.Sprintf("closure query deadline exceeded: %v", err))
			break
		}
		if ix.loadBudgetExhausted {
			out = append(out, "closure query package load budget exhausted")
			break
		}
		out = append(out, fmt.Sprintf(
			"dep package %s imports %s but is outside the enumerated cone — its call sites are unseen",
			imp.path, subj.Package))
	}
	return out
}
