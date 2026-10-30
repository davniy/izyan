package goanalysis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// DynamicCoverage is the scoped dynamic-dispatch record for one subject:
// every marker the product-side scan observed, narrowed to what could
// actually endanger the subject, then classified against the shipping
// scope. It is the single source of truth both verify_code_absence and
// future consumers use — the same relevance rule and receiver-instantiation
// narrowing VerifyUnreachable applies, never a parallel copy.
//
// Open means "may still reach or introduce the subject": a marker stays
// open only on subject-compatibility plus a LIVE or UNKNOWN enclosing
// site; dispatch stays open only while receiver narrowing cannot rule it
// out and its site is not proven dead. Close happens exclusively on a
// deterministic incompatibility proof (marker kind cannot invoke the
// subject, the resolved linkname target is outside the subject set, the
// receiver is never materialized under active narrowing) or on a proven
// DEAD enclosing site. Everything else — unknown marker kinds, scan or
// narrowing failures, unresolved compatible dispatch, UNKNOWN sites —
// stays open and marks the coverage incomplete.
type DynamicCoverage struct {
	// ObservedMarkers renders every product-side marker the scan saw,
	// before any classification — the audit baseline the relevance and
	// scope filters are applied to.
	ObservedMarkers []string
	// RelevantMarkers are the open markers: subject-compatible dynamic
	// escapes whose enclosing site is LIVE or UNKNOWN. Dead-site,
	// incompatible and ignored markers never appear here.
	RelevantMarkers []DynamicMarker
	// IgnoredMarkers renders the observed markers proven
	// subject-incompatible, one audit line per marker with the reason
	// the incompatibility holds.
	IgnoredMarkers []string
	// ClosedExceptions renders markers and dispatch sites closed by a
	// DEAD enclosing site or a completed narrowing, each with the reason.
	ClosedExceptions []string
	// UnresolvedDispatch renders the interface-dispatch sites that
	// remain open after receiver-instantiation narrowing — compatible
	// dispatches on LIVE or UNKNOWN sites only.
	UnresolvedDispatch []string
	// IncompleteReasons records why the coverage could not be proven
	// complete: scan or narrowing failures, missing scope, unknown
	// marker kinds and unresolved linkname operand inventories.
	IncompleteReasons []string
	// Complete is true only when the scan, the dispatch enumeration and
	// its narrowing all ran cleanly, the shipping scope itself is
	// complete, and every marker was classifiable.
	Complete bool
}

// dynMarkerEntry renders a marker as a byte-stable audit line.
func dynMarkerEntry(m DynamicMarker) string {
	return fmt.Sprintf("%s at %s:%d: %s", m.Kind, m.File, m.Line, m.Detail)
}

// dynSiteEntry renders a call site as a byte-stable audit line.
func dynSiteEntry(kind string, cs domain.CallSite) string {
	return fmt.Sprintf("%s at %s:%d in %s (%s)", kind, cs.File, cs.Line, cs.Function, cs.Package)
}

// knownDynMarkerKind enumerates every marker kind the current scanner can
// emit (plus "goroutine", reserved by the kind contract). A kind outside
// this set is unknown — it must stay open and never closes, because the
// classifier cannot know which mechanism it names.
func knownDynMarkerKind(kind string) bool {
	switch kind {
	case "reflect", "unsafe", "plugin", "linkname", "func_value",
		"reflect_method", "reflect_write", "unsafe_write", "unsafe_ptr",
		"goroutine":
		return true
	}
	return false
}

// ScanRelevantDynamic runs the product-side dynamic-marker scan for one
// subject and classifies every observation through the shared kernel
// rules — the per-marker relevance predicate relevantUsageMarkers is
// built on, the receiver-instantiation narrowing dispatchGaps applies,
// and the shipping-scope site verdicts. No rule is re-implemented: the
// result is exactly what VerifyUnreachable would keep for this subject,
// split into open/closed/ignored buckets with reasons.
//
// Classification order:
//
//  1. ScanDynamic produces the observed set (dynScanOverride test seam).
//  2. Subject relevance: bare reflect/unsafe imports and write-only
//     markers can never widen the call graph; func_value is bound to the
//     subject by construction; linkname is relevant only when its operand
//     cannot be resolved to a package outside the subject set or names
//     the subject directly; reflect_method requires an exported method
//     with a potentially materialized receiver; plugin requires a
//     bindable (exported or package-level) subject. Unknown kinds are
//     always relevant and keep the coverage incomplete.
//  3. Site state: a relevant marker whose enclosing site is proven DEAD
//     closes with "dead product site"; LIVE and UNKNOWN sites keep it
//     open.
//  4. InterfaceDispatchSites + dispatchGapsLocked narrowing: a site set
//     fully narrowed out closes with a receiver-instantiation reason;
//     each retained site is closed on a DEAD verdict and stays open
//     otherwise; enumeration or narrowing failure keeps the coverage
//     incomplete.
//
// A nil scope classifies every site UNKNOWN and marks the coverage
// incomplete — nothing is discarded on missing scope data.
func (ix *Index) ScanRelevantDynamic(ctx context.Context, scope *ShippingScope,
	ref domain.SymbolRef) (DynamicCoverage, error) {

	cov := DynamicCoverage{Complete: true}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		cov.Complete = false
		cov.IncompleteReasons = append(cov.IncompleteReasons,
			"dynamic-marker scan failed: "+err.Error())
		return cov, err
	}

	if scope == nil {
		cov.Complete = false
		cov.IncompleteReasons = append(cov.IncompleteReasons,
			"shipping scope unavailable: every site classifies UNKNOWN")
	} else if !scope.Complete {
		cov.Complete = false
		for _, r := range scope.UnknownReasons {
			cov.IncompleteReasons = append(cov.IncompleteReasons,
				"shipping scope incomplete: "+r)
		}
		if len(scope.UnknownReasons) == 0 {
			cov.IncompleteReasons = append(cov.IncompleteReasons,
				"shipping scope incomplete")
		}
	}
	siteState := func(cs domain.CallSite) ReachabilityState {
		return scope.SiteState(cs)
	}

	// The linkname target inventory rides the same importer index the
	// closure enumeration uses; when it is unavailable every linkname
	// operand is treated as unresolved — conservative compatibility,
	// never a fabricated miss.
	resolveLinkname := true
	if _, err := ix.depImporters(ctx); err != nil || ix.pkgModules == nil {
		resolveLinkname = false
		cov.Complete = false
		cov.IncompleteReasons = append(cov.IncompleteReasons,
			"linkname target inventory unavailable: every operand is unresolved")
	}

	var markers []DynamicMarker
	var scanErr error
	if ix.dynScanOverride != nil {
		markers, scanErr = ix.dynScanOverride(ref)
	} else {
		markers = ix.scanDynamic(ref)
	}
	if scanErr != nil {
		cov.Complete = false
		cov.IncompleteReasons = append(cov.IncompleteReasons,
			"dynamic-marker scan failed: "+scanErr.Error())
		sort.Strings(cov.IncompleteReasons)
		cov.IncompleteReasons = dedupStrings(cov.IncompleteReasons)
		return cov, scanErr
	}
	markers = dedupDynMarkers(markers)

	recvInst := ix.receiverTypeInstantiated(ctx, ref)
	_, prodNarrow := ix.productInstantiated()
	if !recvInst && prodNarrow && ix.receiverMayBeErased(ref) {
		recvInst = true
	}
	unknownKinds := map[string]bool{}
	var seenObs []string
	for _, m := range markers {
		seenObs = append(seenObs, dynMarkerEntry(m))
		relevant := usageMarkerRelevant(m, ref, recvInst, prodNarrow)
		ignoreReason := ""
		switch m.Kind {
		case "linkname":
			// The kernel text match can miss a resolved pull into an
			// unrelated package and can never clear an operand whose
			// package never materialized. Resolve against the module
			// inventory: resolved-to-another-package proves
			// incompatibility with this subject; unresolved is
			// conservatively relevant.
			if !relevant && resolveLinkname {
				if ops := linknameRe.FindStringSubmatch(m.Detail); ops != nil {
					if tp, _, ok := ix.resolveLinknameTarget(ops[2]); ok {
						if tp != ref.Package {
							relevant = false
							ignoreReason = fmt.Sprintf(
								"linkname resolves to %s, an inventoried package outside the subject set", tp)
						} else {
							relevant = true
						}
					} else {
						// Unresolvable operand: it may name the subject
						// package — relevance cannot be ruled out.
						relevant = true
					}
				}
			}
			if !resolveLinkname {
				relevant = true
			}
		case "goroutine":
			// go f() dispatches a bound value the static call graph
			// cannot resolve — conservatively relevant to any subject.
			relevant = true
		case "func_value", "reflect_method", "plugin":
			// Kind-level relevance already decided by the shared
			// predicate; nothing extra to resolve.
		default:
			if !knownDynMarkerKind(m.Kind) {
				unknownKinds[m.Kind] = true
				relevant = true
				break
			}
			// Bare imports and write-only shapes cannot widen the call
			// graph — deterministically incompatible with any subject.
			relevant = false
		}
		if !relevant {
			if ignoreReason == "" {
				ignoreReason = "cannot invoke this subject (kind/type/signature incompatible)"
			}
			cov.IgnoredMarkers = append(cov.IgnoredMarkers,
				dynMarkerEntry(m)+" [ignored: "+ignoreReason+"]")
			continue
		}
		if !knownDynMarkerKind(m.Kind) {
			// Unknown kinds are never closed, even on a DEAD site:
			// the classifier cannot prove what edge the marker forges.
			cov.RelevantMarkers = append(cov.RelevantMarkers, m)
			continue
		}
		switch siteState(m.CallSite) {
		case ReachabilityDead:
			cov.ClosedExceptions = append(cov.ClosedExceptions,
				dynMarkerEntry(m)+" [closed: dead product site]")
		default:
			cov.RelevantMarkers = append(cov.RelevantMarkers, m)
		}
	}
	cov.ObservedMarkers = append([]string(nil), seenObs...)

	if len(unknownKinds) > 0 {
		cov.Complete = false
		cov.IncompleteReasons = append(cov.IncompleteReasons, fmt.Sprintf(
			"unknown dynamic marker kind(s) observed: %s", strings.Join(sortedKeys(unknownKinds), ", ")))
	}

	// Interface dispatch: enumerate candidates, apply the identical
	// receiver-instantiation narrowing the verifier runs, then classify
	// surviving sites against the scope.
	disp, recvUnresolved, derr := ix.interfaceDispatchSites(ctx, ref)
	if derr != nil {
		cov.Complete = false
		cov.IncompleteReasons = append(cov.IncompleteReasons,
			"interface dispatch enumeration failed: "+derr.Error())
	} else {
		if len(disp) > 0 && (!prodNarrow || recvUnresolved) {
			cov.Complete = false
			cov.IncompleteReasons = append(cov.IncompleteReasons,
				"receiver-instantiation narrowing unavailable for interface dispatch")
		}
		narrowed := disp
		if !recvUnresolved {
			narrowed = ix.dispatchGapsLocked(ctx, ref, disp)
		}
		if len(disp) > 0 && len(narrowed) == 0 {
			cov.ClosedExceptions = append(cov.ClosedExceptions, fmt.Sprintf(
				"%d interface-dispatch candidate(s) [closed: subject receiver type is never materialized in product code; receiver-instantiation narrowing applies]",
				len(disp)))
		}
		for _, cs := range narrowed {
			switch siteState(cs) {
			case ReachabilityDead:
				cov.ClosedExceptions = append(cov.ClosedExceptions,
					dynSiteEntry("interface_dispatch", cs)+" [closed: dead product site]")
			default:
				cov.UnresolvedDispatch = append(cov.UnresolvedDispatch,
					dynSiteEntry("interface_dispatch", cs))
			}
		}
	}

	sort.Strings(cov.ObservedMarkers)
	sort.Strings(cov.IgnoredMarkers)
	sort.Strings(cov.ClosedExceptions)
	sort.Strings(cov.UnresolvedDispatch)
	sort.Strings(cov.IncompleteReasons)
	cov.ObservedMarkers = dedupStrings(cov.ObservedMarkers)
	cov.IgnoredMarkers = dedupStrings(cov.IgnoredMarkers)
	cov.ClosedExceptions = dedupStrings(cov.ClosedExceptions)
	cov.UnresolvedDispatch = dedupStrings(cov.UnresolvedDispatch)
	cov.IncompleteReasons = dedupStrings(cov.IncompleteReasons)
	return cov, nil
}
