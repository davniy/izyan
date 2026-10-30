package evidencetools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

type CodeSubject struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
	Role    string `json:"role,omitempty"`
}
type VerifyCodeAbsenceArgs struct {
	Subjects []CodeSubject `json:"subjects"`
}

// ImportClosureReport is the closure record embedded in a code_absence
// observation: the enumerated product import closure for the pinned build
// context plus the closed/open exception sets. Absence claims admit only
// when Complete is true and OpenExceptions is empty.
type ImportClosureReport struct {
	InventoryReference string `json:"inventory_reference,omitempty"`
	InventoryRaw string `json:"inventory_raw,omitempty"`
	InventoryError string `json:"inventory_error,omitempty"`
	InventoryBuild domain.BuildContext `json:"inventory_build"`
	InventoryRun domain.PackageListRun `json:"inventory_run"`
	InventoryScope *BuildContext `json:"inventory_scope,omitempty"`
	// Complete is the closure's own completeness flag — every member's
	// import edges were enumerated and no skipped package kept invisible
	// edges. It is never derived from search results.
	Complete bool `json:"complete"`
	// Hash pins the full inventory (roots, members, edges, importers,
	// modules, vendor residency, markers) for replay.
	Hash             string   `json:"hash"`
	ProductRoots     int      `json:"product_roots"`
	Packages         int      `json:"packages"`
	BrokenEdges      []string `json:"broken_edges,omitempty"`
	SkippedUnscanned []string `json:"skipped_unscanned,omitempty"`
	// ModuleBindings maps member packages to their resolved module
	// identity (path@version plus replacement and load directory); it is
	// part of the provenance the closure hash binds.
	ModuleBindings map[string]string `json:"module_bindings,omitempty"`
	// SourceHashes maps every member package to the sha256 of its
	// build-selected source set. Absence claims replay only against the
	// hashed inventory — a substituted module cache under the same path
	// and version yields a different closure hash.
	SourceHashes map[string]string `json:"source_hashes,omitempty"`
	// UnhashedSource lists members whose source set could not be fully
	// hashed; any entry keeps the closure incomplete.
	UnhashedSource []string `json:"unhashed_source,omitempty"`
	// SubjectImporters maps each expected subject's package path to the
	// closure members importing it — empty for every subject that was
	// proven absent because its package never entered the closure.
	SubjectImporters map[string][]string `json:"subject_importers,omitempty"`
	// ClosedExceptions and OpenExceptions hold one entry per dynamic
	// mechanism site classified during this check: a closed exception's
	// candidate set was fully enumerated and cannot reach any expected
	// subject; anything else is open and blocks COMPLETE.
	ClosedExceptions         []string          `json:"closed_exceptions,omitempty"`
	OpenExceptions           []string          `json:"open_exceptions,omitempty"`
	DynamicRelevance         []string          `json:"dynamic_relevance,omitempty"`
	IgnoredDynamicMarkers    []string          `json:"ignored_dynamic_markers,omitempty"`
	ScopeRule                string            `json:"scope_rule,omitempty"`
	ScopeComplete            bool              `json:"scope_complete"`
	ScopeHash                string            `json:"scope_hash,omitempty"`
	ShippingRoots            []string          `json:"shipping_roots,omitempty"`
	PackageStates            map[string]string `json:"package_states,omitempty"`
	ScopeUnknown             []string          `json:"scope_unknown,omitempty"`
	DiscardedUnreachable     []string          `json:"discarded_unreachable,omitempty"`
	DynamicRelevanceRule     string            `json:"dynamic_relevance_rule,omitempty"`
	DynamicRelevanceComplete bool              `json:"dynamic_relevance_complete"`
	ObservedDynamicMarkers   []string          `json:"observed_dynamic_markers,omitempty"`
}

// ValidateCodeAbsenceInventory replays the complete stdout behind a current
// absence record. Historical inventory-free reports remain readable, not
// admissible under the current coverage version.
func ValidateCodeAbsenceInventory(c *ImportClosureReport, snapshotHash, buildHash string) error {
	if c == nil || c.InventoryError != "" || c.InventoryScope == nil || c.InventoryScope.EffectiveBuild == nil {
		return errors.New("complete build-bound package inventory missing")
	}
	build := *c.InventoryScope.EffectiveBuild
	if build.GOOS == "" || build.GOARCH == "" || build.GoVersion == "" || c.InventoryScope.Toolchain == "" {
		return errors.New("inventory compiler or platform identity is unresolved")
	}
	if snapshotHash == "" || build.ContentHash != snapshotHash {
		return errors.New("inventory snapshot binding mismatch")
	}
	b, err := json.Marshal(c.InventoryScope)
	if err != nil || buildHash == "" || sha256Of(b) != buildHash {
		return errors.New("inventory effective scope hash mismatch")
	}
	if c.InventoryRun.WithTests {
		return errors.New("shipping absence requires a non-test inventory")
	}
	m := affected.PackageInventoryMeasurement{RawStream:c.InventoryRaw, RawSHA256:c.InventoryRun.RawSHA256, RawReference:c.InventoryReference, RawSize:len(c.InventoryRaw), Run:c.InventoryRun, Build:c.InventoryBuild}
	inventory, err := m.AdmitBuild(build)
	if err != nil { return err }
	for _, root := range c.ShippingRoots {
		if !inventory.Paths[root] { return fmt.Errorf("shipping root %q missing from admitted inventory", root) }
	}
	for pkg := range c.SourceHashes {
		if !inventory.Paths[pkg] { return fmt.Errorf("source-covered package %q missing from admitted inventory", pkg) }
	}
	return nil
}

type CodeAbsenceData struct {
	ExpectedSubjects []CodeSubject `json:"expected_subjects"`
	CheckedSubjects  []CodeSubject `json:"checked_subjects"`
	AbsentSubjects   []CodeSubject `json:"absent_subjects,omitempty"`
	// PresentSubjects lists expected subjects whose declaration was
	// resolved in the closure — counterexamples: a code_absent proof can
	// never rest on a payload with a non-empty present set.
	PresentSubjects     []CodeSubject `json:"present_subjects,omitempty"`
	AlternativeSubjects []CodeSubject `json:"alternative_subjects,omitempty"`
	SkippedPackages     []string      `json:"skipped_packages,omitempty"`
	// DynamicMarkers carries only OPEN dynamic markers — unresolved
	// dispatch and edge-forging sites still endangering a subject.
	// Fully enumerated, provably harmless sites live in
	// ImportClosure.ClosedExceptions instead.
	DynamicMarkers []string `json:"dynamic_markers,omitempty"`
	// UnresolvedDispatch carries interface-dispatch sites still open
	// against an expected subject after receiver-instantiation
	// narrowing — a subset of the open exceptions, surfaced separately
	// for the coverage contract.
	UnresolvedDispatch  []string             `json:"unresolved_dispatch,omitempty"`
	ImportClosure       *ImportClosureReport `json:"import_closure,omitempty"`
	SnapshotHash        string               `json:"snapshot_hash"`
	BuildContextHash    string               `json:"build_context_hash"`
	CoverageRule        string               `json:"coverage_rule"`
	CoverageRuleVersion string               `json:"coverage_rule_version"`
}

// The coverage rule names the closed scope the check claims; the wire
// version records which payload fields the verifier may rely on.
const codeAbsenceCoverageRule = "all requested subjects resolved inside the enumerated product import closure"

// CodeAbsenceCoverageRuleVersion is the admission contract version.
const CodeAbsenceCoverageRuleVersion = "5"
const CodeAbsenceScopeRule = "shipping-main-transitive-import-closure-v1"
const CodeAbsenceDynamicRule = "subject-relevant-dynamic-markers-v1"

func containsSubject(xs []CodeSubject, want CodeSubject) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// subjectState classifies one expected subject's resolution outcome.
type subjectState int

const (
	subjectUnresolved    subjectState = iota // package/source never resolved
	subjectPresent                           // declaration found — counterexample
	subjectAbsentDecl                        // package resolved, symbol absent
	subjectAbsentClosure                     // package provably outside the closure
)

func (s *Session) verifyCodeAbsence(ctx context.Context, a VerifyCodeAbsenceArgs) (*Observation, error) {
	if len(a.Subjects) == 0 {
		return nil, errors.New("subjects are required")
	}
	expected := append([]CodeSubject(nil), a.Subjects...)
	for _, subj := range expected {
		if subj.Package == "" || subj.Symbol == "" {
			return nil, fmt.Errorf("subject package and symbol are required")
		}
	}

	if s.toolchainDenied() || s.GoTool == nil { return s.unsupported("verify_code_absence", "a complete package inventory requires the toolchain capability"), nil }
	if _, err := s.probeSnapshot(ctx); err != nil { return nil, err }
	measurement := affected.MeasurePackageInventory(ctx, s.GoTool, s.SnapshotRoot, s.Build, false)
	closure, err := s.Source.EnumerateImportClosureWithInventory(ctx, measurement)
	if err != nil {
		return nil, fmt.Errorf("import closure enumeration failed: %w", err)
	}
	memberSet := make(map[string]bool, len(closure.Packages))
	for _, p := range closure.Packages {
		memberSet[p] = true
	}

	checked := make([]CodeSubject, 0, len(expected))
	absent := make([]CodeSubject, 0, len(expected))
	present := make([]CodeSubject, 0, len(expected))
	var limitations []string
	brokenSet := make(map[string]bool, len(closure.BrokenEdges)+len(closure.UnhashedSource))
	for _, p := range closure.BrokenEdges {
		brokenSet[p] = true
	}
	for _, p := range closure.UnhashedSource {
		brokenSet[p] = true
	}
	states := make(map[CodeSubject]subjectState, len(expected))

	// Subject resolution under the same pinned build context: a member
	// package resolves its declarations; a non-member package is absent
	// from the product build only when the closure itself is complete —
	// an incomplete closure cannot prove the package is unreachable by
	// import edges, so the subject stays unresolved.
	for _, subj := range expected {
		ref := domain.SymbolRef{Package: subj.Package, Symbol: subj.Symbol}
		if memberSet[subj.Package] && brokenSet[subj.Package] {
			limitations = append(limitations, fmt.Sprintf("subject %s.%s belongs to a package with unresolved source/edges", subj.Package, subj.Symbol))
			states[subj] = subjectUnresolved
			continue
		}
		if memberSet[subj.Package] {
			// Defensive consistency check: a member package must have at
			// least one member importer or be a product root; the graph
			// enumerating it as a member while reporting no edge is a
			// load inconsistency the check must not paper over.
			_, ferr := s.Source.FindSymbol(ctx, ref)
			switch {
			case ferr == nil:
				checked = append(checked, subj)
				present = append(present, subj)
				states[subj] = subjectPresent
			case errors.Is(ferr, goanalysis.ErrSymbolNotFoundInPackage):
				checked = append(checked, subj)
				absent = append(absent, subj)
				states[subj] = subjectAbsentDecl
			case errors.Is(ferr, goanalysis.ErrAmbiguousSymbol):
				checked = append(checked, subj)
				present = append(present, subj)
				states[subj] = subjectPresent
				limitations = append(limitations,
					fmt.Sprintf("subject %s.%s resolves ambiguously; absence not proven", subj.Package, subj.Symbol))
			default:
				limitations = append(limitations,
					fmt.Sprintf("subject %s.%s could not be checked: %v", subj.Package, subj.Symbol, ferr))
				states[subj] = subjectUnresolved
			}
			continue
		}
		if closure.Complete {
			// The package is outside the enumerated product import
			// closure: nothing in the build imports it. The reverse
			// importer set must agree — an in-closure importer would
			// make this member-free claim inconsistent.
			inside := closureImportersOf(closure, subj.Package, memberSet)
			if len(inside) > 0 {
				limitations = append(limitations,
					fmt.Sprintf("package %s is outside the closure yet lists in-closure importers %v", subj.Package, inside))
				states[subj] = subjectUnresolved
				continue
			}
			checked = append(checked, subj)
			absent = append(absent, subj)
			states[subj] = subjectAbsentClosure
			continue
		}
		if closure.InventoryError != "" {
			limitations = append(limitations, "subject package membership unresolved by the failed inventory: " + subj.Package)
			states[subj] = subjectUnresolved
			continue
		}
		// Incomplete closure: absence-by-membership is unprovable, but a
		// declaration lookup can still resolve the subject directly.
		_, ferr := s.Source.FindSymbol(ctx, ref)
		switch {
		case ferr == nil:
			checked = append(checked, subj)
			present = append(present, subj)
			states[subj] = subjectPresent
		case errors.Is(ferr, goanalysis.ErrSymbolNotFoundInPackage):
			checked = append(checked, subj)
			absent = append(absent, subj)
			states[subj] = subjectAbsentDecl
		case errors.Is(ferr, goanalysis.ErrAmbiguousSymbol):
			checked = append(checked, subj)
			present = append(present, subj)
			states[subj] = subjectPresent
			limitations = append(limitations,
				fmt.Sprintf("subject %s.%s resolves ambiguously; absence not proven", subj.Package, subj.Symbol))
		default:
			limitations = append(limitations,
				fmt.Sprintf("subject %s.%s could not be checked: %v", subj.Package, subj.Symbol, ferr))
			states[subj] = subjectUnresolved
		}
	}

	// Skipped and truncated scopes keep the observation open regardless
	// of what the subject loop resolved: invisible edges can hide an
	// import of the target package.
	if closure.InventoryError != "" { limitations = append(limitations, "package inventory: " + closure.InventoryError) }
	if len(closure.Skipped) > 0 {
		limitations = append(limitations,
			fmt.Sprintf("package loading skipped part of the product/source universe: %s", strings.Join(closure.Skipped, ", ")))
	}
	if len(closure.SkippedUnscanned) > 0 {
		limitations = append(limitations,
			fmt.Sprintf("skipped packages with unrecoverable import sets: %s", strings.Join(closure.SkippedUnscanned, ", ")))
	}
	if len(closure.BrokenEdges) > 0 {
		limitations = append(limitations,
			fmt.Sprintf("import closure has untrusted edge sets: %s", strings.Join(closure.BrokenEdges, ", ")))
	}
	if len(closure.UnhashedSource) > 0 {
		limitations = append(limitations,
			fmt.Sprintf("closure members without hashable source inventory: %s", strings.Join(closure.UnhashedSource, ", ")))
	}
	if s.Source.LoadBudgetExhausted() {
		limitations = append(limitations, "package-load budget exhausted; enumeration is truncated")
	}
	if s.ToolVer == "" {
		limitations = append(limitations, "toolchain identity unresolved; the build context cannot pin the compiler that produced the inventory")
	}

	// Dynamic-mechanism exceptions: classify every edge-forging marker in
	// the closure plus the product-side scan markers through the shared
	// scoped relevance API. A marker closes only when it cannot reach or
	// introduce any expected subject — proven incompatibility or a
	// proven-DEAD enclosing site; everything else stays open and blocks
	// COMPLETE.
	closed, open, ignored, undisp := s.classifyAbsenceExceptions(ctx, expected, states, memberSet, closure)
	allOpen := dedupSorted(append(append([]string(nil), open...), undisp...))
	if len(allOpen) > 0 {
		limitations = append(limitations, "dynamic-dispatch markers leave code coverage open")
	}
	closureAudit := append([]string(nil), closed...)
	closureAudit = append(closureAudit, ignored...)
	closureAudit = append(closureAudit, allOpen...)
	closure.BindDynamicRelevance(closureAudit)

	buildBytes, _ := json.Marshal(s.buildContext())
	buildHash := sha256Of(buildBytes)
	if !reflect.DeepEqual(s.Source.Build, s.Build) {
		limitations = append(limitations, "analysis build context differs from session build context")
	}

	rep := &ImportClosureReport{
		InventoryReference: closure.InventoryReference, InventoryRaw: closure.InventoryRaw, InventoryError: closure.InventoryError,
		InventoryBuild: closure.InventoryBuild, InventoryRun: closure.InventoryRun,
		InventoryScope: s.buildContext(),
		Complete: closure.Complete, Hash: closure.Hash, ProductRoots: len(closure.ProductRoots), Packages: len(closure.Packages),
		BrokenEdges: append([]string(nil), closure.BrokenEdges...), SkippedUnscanned: append([]string(nil), closure.SkippedUnscanned...),
		ModuleBindings: closure.ModuleBindings, SourceHashes: closure.SourceHashes, UnhashedSource: append([]string(nil), closure.UnhashedSource...),
		DynamicRelevance: append([]string(nil), closure.DynamicRelevance...), SubjectImporters: subjectImporters(expected, closure, memberSet),
		ClosedExceptions: closed, OpenExceptions: allOpen, IgnoredDynamicMarkers: ignored,
		ScopeRule: CodeAbsenceScopeRule, ScopeComplete: closure.ScopeComplete, ScopeHash: closure.ScopeHash,
		ShippingRoots: append([]string(nil), closure.ShippingRoots...), PackageStates: closure.PackageStates,
		ScopeUnknown: append([]string(nil), closure.ScopeUnknown...), DiscardedUnreachable: append([]string(nil), closure.DiscardedUnreachable...),
		DynamicRelevanceRule: CodeAbsenceDynamicRule, DynamicRelevanceComplete: closure.ScopeComplete && len(allOpen) == 0,
		ObservedDynamicMarkers: append([]string(nil), closure.DynamicRelevance...),
	}
	data := CodeAbsenceData{
		ExpectedSubjects:   expected,
		CheckedSubjects:    checked,
		AbsentSubjects:     absent,
		PresentSubjects:    present,
		SkippedPackages:    append([]string(nil), closure.Skipped...),
		DynamicMarkers:     open,
		UnresolvedDispatch: undisp,
		ImportClosure:      rep,
		SnapshotHash:       s.SnapshotHash,
		BuildContextHash:   buildHash,
		CoverageRule:       codeAbsenceCoverageRule,
		// The wire version advertises the closure-carrying payload shape.
		CoverageRuleVersion: CodeAbsenceCoverageRuleVersion,
	}
	c := CompletenessComplete
	if len(checked) != len(expected) || len(limitations) > 0 || len(allOpen) > 0 ||
		!closure.Complete || !reflect.DeepEqual(s.Source.Build, s.Build) {
		c = CompletenessPartial
		if len(checked) == 0 {
			c = CompletenessUnknown
		}
	}
	sd := &ScopeDetails{
		SnapshotHash:     s.SnapshotHash,
		ExternalSHA:      s.ExternalSHA,
		BuildContext:     s.buildContext(),
		SkippedPackages:  append([]string(nil), closure.Skipped...),
		CoverageRule:     codeAbsenceCoverageRule,
		CoverageRuleVers: CodeAbsenceCoverageRuleVersion,
		Extra:            map[string]string{"import_closure_hash": closure.Hash},
	}
	return s.ok("verify_code_absence",
		fmt.Sprintf("checked %d of %d requested code subjects; %d absent; closure=%v", len(checked), len(expected), len(absent), closure.Complete),
		"enumerated product import closure for the pinned build context", c, data, sd, limitations), nil
}

// closureImportersOf returns the in-closure importers of pkgPath.
func closureImportersOf(closure goanalysis.ImportClosure, pkgPath string, memberSet map[string]bool) []string {
	var out []string
	for _, imp := range closure.Importers[pkgPath] {
		if memberSet[imp] {
			out = append(out, imp)
		}
	}
	sort.Strings(out)
	return out
}

// subjectImporters records the in-closure importer set of every expected
// subject's package — the audit evidence behind an absent-by-closure
// claim and the surface a forged closure would have to hide.
func subjectImporters(expected []CodeSubject, closure goanalysis.ImportClosure, memberSet map[string]bool) map[string][]string {
	out := map[string][]string{}
	for _, subj := range expected {
		if _, done := out[subj.Package]; done {
			continue
		}
		if imps := closureImportersOf(closure, subj.Package, memberSet); len(imps) > 0 {
			out[subj.Package] = imps
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// classifyAbsenceExceptions splits every dynamic-mechanism marker into
// closed and open exceptions, auditing every discard with a reason.
// Product-side markers classify through the shared kernel relevance API
// (goanalysis.Index.ScanRelevantDynamic): the marker must be compatible
// with the subject AND live at a site the shipping scope cannot prove
// dead before it may block. A marker threatens only absence claims:
//
//   - present or unresolved subjects are already recorded as
//     counterexamples/gaps — kernel-relevant markers stay open so the
//     observation can never read as verified absence;
//   - absent-by-declaration subjects sit in a package whose source was
//     fully resolved under this build context, but declaration lookup
//     does not see promoted members — kernel-relevant markers stay
//     open rather than papering over a possible dispatch target;
//   - absent-by-closure subjects are endangered only by mechanisms that
//     can link code the import graph never listed: plugin, linkname, a
//     bound func value or goroutine (whose existence would contradict
//     the membership proof itself) and unknown kinds stay open.
//     reflect method dispatch reaches only linked receivers — an
//     unlinked package has no runtime type for them — so compatible
//     reflect_method markers and unresolved dispatch sites close;
//   - a relevant marker or dispatch site at a proven-DEAD enclosing
//     site closes regardless of subject state: it cannot execute.
//
// Edge-forging markers enumerated with the closure (dep + product
// members alike) keep their existing policy: they close only when the
// enumerated candidate set cannot reach an expected subject.
func (s *Session) classifyAbsenceExceptions(ctx context.Context, expected []CodeSubject,
	states map[CodeSubject]subjectState, memberSet map[string]bool, closure goanalysis.ImportClosure) (closed, open, ignored, undisp []string) {

	blocksAbsent := func(kind string, targetPkg, targetDecl string, resolved bool) bool {
		for _, subj := range expected {
			switch states[subj] {
			case subjectPresent:
				// A present declaration is a counterexample but does not
				// make unrelated closure markers open.
				continue
			case subjectUnresolved:
				return true
			case subjectAbsentClosure:
				switch kind {
				case "plugin", "cgo":
					return true
				case "linkname":
					if resolved {
						if targetPkg == subj.Package || !memberSet[targetPkg] {
							return true
						}
					} else if strings.HasPrefix(targetPkg, subj.Package+".") {
						// The operand names a declaration inside the
						// subject package yet the package never entered
						// the inventory — an invisible pull the import
						// graph cannot rule out.
						return true
					}
				}
			case subjectAbsentDecl:
				// plugin and cgo can link code the source inventory never
				// enumerated — a plugin can carry an extra copy of the
				// subject package — and no deterministic candidate
				// inventory exists for them, so they stay open. An
				// unresolved linkname operand naming the subject package
				// may pull exactly it; a resolved pull into it is an
				// invisible edge the declaration set did not see.
				switch kind {
				case "plugin", "cgo":
					return true
				case "linkname":
					if resolved {
						if targetPkg == subj.Package {
							return true
						}
					} else if strings.HasPrefix(targetPkg, subj.Package+".") {
						return true
					}
				}
			}
		}
		return false
	}

	// Edge-forging markers enumerated with the closure (dep + product
	// members alike).
	for _, m := range closure.EdgeMarkers {
		entry := fmt.Sprintf("%s at %s", m.Kind, m.Locator)
		if m.Target != "" {
			entry += " -> " + m.Target
		}
		if m.Kind == "linkname" && m.Resolved && m.TargetDecl != "" {
			entry += " (" + m.TargetDecl + ")"
		}
		if blocksAbsent(m.Kind, m.Target, m.TargetDecl, m.Resolved) {
			open = append(open, entry)
			continue
		}
		reason := "enumerated candidate set cannot reach an expected subject"
		if m.Kind == "linkname" && m.Resolved {
			reason = fmt.Sprintf("linkname resolves to %s.%s, an inventoried package outside the subject set", m.Target, m.TargetDecl)
		}
		closed = append(closed, entry+" ["+reason+"]")
	}

	// Product-side dispatch markers classify through the shared scoped
	// relevance API — the same relevance rule and receiver narrowing the
	// unreachability kernel applies, keyed to the shipping scope the
	// closure enumeration ran on.
	scope, serr := s.Source.BuildShippingScope(ctx)
	if serr != nil {
		open = append(open, "shipping scope unavailable: "+serr.Error())
	}
	// edgeBlocks mirrors blocksAbsent's per-kind verdict for
	// product-side markers against absent subjects: edge-forging kinds
	// (and anything invoking a value the membership proof says cannot
	// be bound) never close.
	edgeBlocks := func(kind string, st subjectState) bool {
		switch kind {
		case "plugin", "linkname", "func_value", "goroutine":
			return true
		case "reflect", "unsafe", "reflect_method",
			"reflect_write", "unsafe_write", "unsafe_ptr":
			return false
		}
		return true // unknown kinds never close
	}
	subjSuffix := func(subj CodeSubject) string {
		return fmt.Sprintf(" (subject %s.%s)", subj.Package, subj.Symbol)
	}
	for _, subj := range expected {
		ref := domain.SymbolRef{Package: subj.Package, Symbol: subj.Symbol}
		cov, err := s.Source.ScanRelevantDynamic(ctx, scope, ref)
		if err != nil {
			open = append(open, fmt.Sprintf("dynamic scan for %s.%s unavailable: %v",
				subj.Package, subj.Symbol, err))
			continue
		}
		suffix := subjSuffix(subj)
		for _, line := range cov.ClosedExceptions {
			closed = append(closed, line+suffix)
		}
		for _, line := range cov.IgnoredMarkers {
			ignored = append(ignored, line+suffix)
		}
		st := states[subj]
		if st == subjectPresent {
			// Present subjects keep the payload honest about residual
			// dispatch surface without blocking on it: the
			// counterexample, not the marker, denies absence.
			for _, r := range cov.IncompleteReasons {
				ignored = append(ignored, fmt.Sprintf("dynamic coverage incomplete for %s.%s: %s",
					subj.Package, subj.Symbol, r))
			}
		} else {
			for _, r := range cov.IncompleteReasons {
				open = append(open, fmt.Sprintf("dynamic coverage incomplete for %s.%s: %s",
					subj.Package, subj.Symbol, r))
			}
		}
		for _, m := range cov.RelevantMarkers {
			entry := fmt.Sprintf("%s at %s:%d: %s", m.Kind, m.File, m.Line, m.Detail)
			if st == subjectAbsentClosure && !edgeBlocks(m.Kind, st) {
				closed = append(closed, entry+suffix+
					" [closed: subject package outside the shipping closure; dispatch over linked code cannot reach it]")
				continue
			}
			open = append(open, entry+suffix)
		}
		for _, line := range cov.UnresolvedDispatch {
			if st == subjectAbsentClosure {
				closed = append(closed, line+suffix+
					" [closed: subject package outside the shipping closure; interface dispatch reaches only linked receivers]")
				continue
			}
			undisp = append(undisp, line+suffix)
		}
	}
	return dedupSorted(closed), dedupSorted(open), dedupSorted(ignored), dedupSorted(undisp)
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
