package refindex

import (
	"context"
	"fmt"
	"sort"

	"github.com/fedorovmv/izyan/internal/goanalysis"
	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// UsageChecker is the slice of goanalysis.Index usage probing needs.
type UsageChecker interface {
	ProductUsage(ctx context.Context, module string, subject pbdomain.SymbolRef) (goanalysis.PackageUsageResult, error)
}

// atomVerdict is the per-atom classification result. Stratum and binding
// are orthogonal: stratum is the usage verdict, binding is how the
// advisory module's code reaches the build.
type atomVerdict struct {
	atom    Atom
	stratum UsageStratum
	binding Binding
	res     *goanalysis.PackageUsageResult // nil when no check ran
	present *bool                          // nil = presence unknown
}

// classifyUsage runs the per-atom usage checks and merges them into the
// document Usage block. Nil checker = the source index is unavailable:
// manifest facts still apply (self_implementation, manifest-not-present),
// everything else degrades to unknown.
func classifyUsage(ctx context.Context, ck UsageChecker, mb moduleBinding, atoms []Atom, modHint string) (Usage, []string) {
	u := Usage{Stratum: StratumUnknown, Binding: BindingDirect, State: StateUnknown}
	var notes []string

	if len(atoms) == 0 {
		// No declared locus material: only module-level binding facts can
		// still classify the document.
		if modHint != "" && modHint != mb.ModulePath {
			u.Binding = bindingOf(mb, modHint, "")
		}
		switch {
		case modHint == "":
			notes = append(notes, "advisory declares no affected module, package or symbol")
		case mb.ModulePath != "" && modHint == mb.ModulePath:
			u.Stratum = StratumSelfImplementation
		case !isStdlibModule(modHint):
			if !mb.moduleInGraph(modHint, "") {
				u.Stratum = StratumNotPresent
				u.State = StateNotUsed
				u.NegativeVerification = string(goanalysis.PackageUsageNegativeVerified)
				notes = append(notes, "advisory module "+modHint+" is absent from the product's module graph")
			}
		}
		u.Sites = []Site{}
		u.ImportSites = []Site{}
		u.Limitations = append(notes, "advisory declares no affected package or symbol; usage is classified at module level only")
		sort.Strings(u.Limitations)
		return u, u.Limitations
	}

	verdicts := make([]atomVerdict, 0, len(atoms))
	for _, a := range atoms {
		verdicts = append(verdicts, classifyAtom(ctx, ck, mb, a, &notes))
	}
	u = mergeVerdicts(verdicts)
	u.Limitations = mergeLimitations(verdicts, notes)
	return u, u.Limitations
}

// classifyAtom derives the usage stratum and module binding of one atom.
// The two dimensions are independent:
//
//  1. module identity — an atom of the product's own module is
//     self_implementation (binding "direct"): first-party code;
//  2. module-graph absence — not_present ONLY when the module is absent
//     from go.mod require/replace and vendor/modules.txt. ProductUsage.
//     Present is NOT used for this decision: the loaded types closure can
//     omit transitive dependency-internal packages, so Present=false alone
//     never proves absence;
//  3. binding — local replace = fork_copy, path-changing replace =
//     replacement_ambiguous, vendored = vendored_exact, else direct;
//  4. usage verdict — USED = reachable_{complete,partial} (product
//     references are direct evidence and win over a missing presence
//     entry); NOT_USED+VERIFIED with Present=true = unreachable_complete
//     REGARDLESS of binding (a vendored module can be unreachable);
//     anything else = unknown.
//
// Empty site lists never produce a negative stratum: only a verified
// in-closure negative or a module-graph absence verdict does.
func classifyAtom(ctx context.Context, ck UsageChecker, mb moduleBinding, a Atom, notes *[]string) atomVerdict {
	v := atomVerdict{atom: a, binding: BindingDirect}
	if a.Module == "" {
		v.stratum = StratumUnknown
		*notes = append(*notes, fmt.Sprintf("atom %s.%s declares no module; binding is unverifiable", a.Package, a.Symbol))
		return v
	}
	res, err := v.runCheck(ctx, ck, a)

	if mb.ModulePath != "" && a.Module == mb.ModulePath {
		v.stratum = StratumSelfImplementation
		return v
	}

	ver, _ := mb.requiredVersion(a.Module)
	if !mb.moduleInGraph(a.Module, ver) && !isStdlibModule(a.Module) {
		if !mb.shipsPackageUnderModule(a.Package) {
			v.stratum = StratumNotPresent
			return v
		}
		// The module is not a dependency, but the affected package ships
		// inside the product tree: a forked copy; the usage verdict still
		// decides the stratum.
		v.binding = BindingForkCopy
	} else {
		v.binding = bindingOf(mb, a.Module, ver)
	}

	if err != nil {
		v.stratum = StratumUnknown
		*notes = append(*notes, fmt.Sprintf("usage check failed for %s.%s: %v", a.Package, a.Symbol, err))
		return v
	}
	if res == nil {
		v.stratum = StratumUnknown
		if ck == nil {
			*notes = append(*notes, fmt.Sprintf("usage not checked for %s.%s: no source index", a.Package, a.Symbol))
		}
		return v
	}
	// A missing presence entry next to a present module graph is a scope
	// limitation, not absence: dependency-internal packages can be
	// reachable inside their dependency while the loaded types closure
	// omits them. Record it whenever it can influence the verdict.
	if !res.Present && res.Usage != goanalysis.PackageUsageUsed {
		*notes = append(*notes,
			fmt.Sprintf("package %s is not in the product source closure under the build context; its module is present in the module graph, and a dependency-internal package may be reachable inside the dependency", a.Package),
			linkedPathsLimitation)
	}
	switch res.Usage {
	case goanalysis.PackageUsageUsed:
		// Concrete product references are direct evidence; a missing
		// presence entry does not demote or negate them.
		if len(goanalysis.UsageScopeGaps(res.Limitations)) == 0 {
			v.stratum = StratumReachableComplete
		} else {
			v.stratum = StratumReachablePartial
		}
	case goanalysis.PackageUsageNotUsed:
		// Binding does not matter here: a closed negative is a closed
		// negative for vendored, replaced and direct modules alike.
		if res.Present && res.NegativeVerification == goanalysis.PackageUsageNegativeVerified {
			v.stratum = StratumUnreachableComplete
		} else {
			// NOT_USED without an in-closure VERIFIED negative is never a
			// closed negative: empty sites alone prove nothing.
			v.stratum = StratumUnknown
		}
	default:
		v.stratum = StratumUnknown
	}
	return v
}

// bindingOf derives the module binding from the manifest facts alone.
func bindingOf(mb moduleBinding, mod, ver string) Binding {
	if rep := mb.replacementFor(mod, ver); rep != nil {
		switch {
		case rep.local():
			return BindingForkCopy
		case rep.newPath != mod:
			return BindingReplacementAmbiguous
		}
	}
	if mb.VendorMode {
		if _, ok := mb.Vendored[mod]; ok {
			return BindingVendoredExact
		}
	}
	return BindingDirect
}

// linkedPathsLimitation records the known source-closure gap that makes a
// missing ProductUsage.Present entry non-dispositive for dependency
// packages. Usage references to such symbols need a govulncheck trace for
// corroboration; without one the stratum stays unknown (NA for scoring).
const linkedPathsLimitation = "goanalysis.linkedPaths can omit transitive dependency-internal packages; usage references to such symbols need a govulncheck trace for corroboration and stay NA here"

// runCheck executes ProductUsage for the atom unless it is a package atom
// (checked with Symbol "") or no checker exists. Returns the result and
// the probe error; records presence on the verdict.
func (v *atomVerdict) runCheck(ctx context.Context, ck UsageChecker, a Atom) (*goanalysis.PackageUsageResult, error) {
	if ck == nil {
		return nil, nil
	}
	res, err := ck.ProductUsage(ctx, a.Module, pbdomain.SymbolRef{Package: a.Package, Symbol: a.Symbol})
	if err != nil {
		return nil, err
	}
	v.res = &res
	p := res.Present
	v.present = &p
	return &res, nil
}

// mergeVerdicts folds per-atom verdicts into one Usage block. The state
// takes the most-proven verdict across atoms (USED > UNKNOWN > NOT_USED);
// the stratum follows the merged state:
//
//	self_implementation wins when any atom is first-party;
//	USED       -> reachable_complete, or reachable_partial when any atom
//	              stayed open;
//	UNKNOWN    -> unknown;
//	NOT_USED   -> not_present when every atom is module-graph absent,
//	              else unreachable_complete;
//
// Binding is merged independently by divergence rank
// (fork_copy > replacement_ambiguous > vendored_exact > direct) — a
// vendored module proven unreachable keeps both facts.
func mergeVerdicts(verdicts []atomVerdict) Usage {
	u := Usage{Sites: []Site{}, ImportSites: []Site{}}
	sawUsed, sawUnknown, sawNegative := false, false, false
	allNotPresent, anySelf, anyPartial := len(verdicts) > 0, false, false
	for _, v := range verdicts {
		if v.stratum != StratumNotPresent {
			allNotPresent = false
		}
		switch v.stratum {
		case StratumSelfImplementation:
			anySelf = true
		case StratumReachablePartial:
			anyPartial = true
		}
		switch v.atomState() {
		case StateUsed:
			sawUsed = true
		case StateNotUsed:
			sawNegative = true
		default:
			sawUnknown = true
		}
	}
	u.Binding = mergeBinding(verdicts)
	switch {
	case sawUsed:
		u.State = StateUsed
		if anyPartial || sawUnknown {
			u.Stratum = StratumReachablePartial
		} else {
			u.Stratum = StratumReachableComplete
		}
	case sawUnknown:
		u.State = StateUnknown
		u.Stratum = StratumUnknown
	case sawNegative:
		u.State = StateNotUsed
		if allNotPresent {
			u.Stratum = StratumNotPresent
		} else {
			u.Stratum = StratumUnreachableComplete
		}
	default:
		u.State = StateUnknown
		u.Stratum = StratumUnknown
	}
	if anySelf {
		u.Stratum = StratumSelfImplementation
	}
	u.NegativeVerification = mergedNegativeVerification(u.State, verdicts)
	u.Sites, u.ImportSites = mergeSites(verdicts)
	u.CheckScope = firstCheckScope(verdicts)
	return u
}

// atomState is the per-atom usage verdict for merging: module-graph
// absence counts as NOT_USED, a check result counts only when closed, and
// unchecked atoms stay UNKNOWN.
func (v atomVerdict) atomState() UsageState {
	switch v.stratum {
	case StratumNotPresent:
		return StateNotUsed
	}
	if v.res == nil {
		return StateUnknown
	}
	switch v.res.Usage {
	case goanalysis.PackageUsageUsed:
		return StateUsed
	case goanalysis.PackageUsageNotUsed:
		// An unverified negative is not a negative for the merged state.
		if v.res.Present && v.res.NegativeVerification == goanalysis.PackageUsageNegativeVerified {
			return StateNotUsed
		}
	}
	return StateUnknown
}

// mergeBinding reports the most divergent binding among the atoms.
func mergeBinding(verdicts []atomVerdict) Binding {
	best := BindingDirect
	for _, v := range verdicts {
		if rankBinding(v.binding) > rankBinding(best) {
			best = v.binding
		}
	}
	return best
}

// rankBinding orders bindings by divergence from the released module.
func rankBinding(b Binding) int {
	switch b {
	case BindingForkCopy:
		return 4
	case BindingReplacementAmbiguous:
		return 3
	case BindingVendoredExact:
		return 2
	case BindingDirect:
		return 1
	}
	return 0
}

// mergedNegativeVerification folds per-atom verifications: USED merges to
// "" (no negative was claimed); NOT_USED merges to VERIFIED only when
// every contributing atom closed its negative (verified or manifest/
// closure absence); UNKNOWN takes the strongest recorded verification.
func mergedNegativeVerification(state UsageState, verdicts []atomVerdict) string {
	switch state {
	case StateUsed:
		return ""
	case StateNotUsed:
		for _, v := range verdicts {
			if v.stratum == StratumNotPresent {
				continue // absence is closed by manifest or linked closure
			}
			if v.res == nil ||
				v.res.NegativeVerification != goanalysis.PackageUsageNegativeVerified {
				return string(goanalysis.PackageUsageNegativeInsufficientScope)
			}
		}
		return string(goanalysis.PackageUsageNegativeVerified)
	default:
		best := ""
		for _, v := range verdicts {
			if v.res == nil {
				continue
			}
			nv := string(v.res.NegativeVerification)
			if nv == string(goanalysis.PackageUsageNegativeContradicted) {
				return nv
			}
			if nv != "" {
				best = nv
			}
		}
		if best != "" {
			return best
		}
		return string(goanalysis.PackageUsageNegativeInsufficientScope)
	}
}

// mergeSites unions ProductSites/ImportSites across atoms, deduplicated
// and sorted for canonical output.
func mergeSites(verdicts []atomVerdict) (sites, imports []Site) {
	saw := map[Site]bool{}
	for _, v := range verdicts {
		if v.res == nil {
			continue
		}
		target := v.atom.Package + "." + v.atom.Symbol
		if v.atom.Symbol == "" {
			target = v.atom.Package
		}
		for _, cs := range v.res.ProductSites {
			s := siteOf(cs, target)
			if !saw[s] {
				saw[s] = true
				sites = append(sites, s)
			}
		}
	}
	sortSites(sites)
	saw = map[Site]bool{}
	for _, v := range verdicts {
		if v.res == nil {
			continue
		}
		// Import sites name the package edge, not the atom — per-atom
		// repetition of the same import spec dedups to one site.
		for _, cs := range v.res.ImportSites {
			s := siteOf(cs, v.atom.Package)
			if !saw[s] {
				saw[s] = true
				imports = append(imports, s)
			}
		}
	}
	sortSites(imports)
	return sites, imports
}

func siteOf(cs pbdomain.CallSite, target string) Site {
	return Site{File: cs.File, Line: cs.Line, Function: cs.Function,
		Package: cs.Package, Target: target}
}

func sortSites(sites []Site) {
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		if sites[i].Line != sites[j].Line {
			return sites[i].Line < sites[j].Line
		}
		if sites[i].Function != sites[j].Function {
			return sites[i].Function < sites[j].Function
		}
		return sites[i].Target < sites[j].Target
	})
}

// firstCheckScope reports the shared check scope; every ProductUsage
// verdict of one run uses the same scope text, so the first non-empty
// wins.
func firstCheckScope(verdicts []atomVerdict) string {
	for _, v := range verdicts {
		if v.res != nil && v.res.CheckScope != "" {
			return v.res.CheckScope
		}
	}
	return ""
}

// mergeLimitations deduplicates and sorts the union of builder notes and
// per-atom check limitations (baseline bounds included — they are part of
// the honesty record).
func mergeLimitations(verdicts []atomVerdict, notes []string) []string {
	set := map[string]bool{}
	var out []string
	add := func(l string) {
		if l == "" || set[l] {
			return
		}
		set[l] = true
		out = append(out, l)
	}
	for _, n := range notes {
		add(n)
	}
	for _, v := range verdicts {
		if v.res == nil {
			continue
		}
		for _, l := range v.res.Limitations {
			add(l)
		}
	}
	sort.Strings(out)
	return out
}
