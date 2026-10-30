package research

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/flow"
	"golang.org/x/mod/module"
)

// The anchored-text subject gate. The planner may propose a check
// subject (module/package/symbol identity carried by the action
// arguments) that the advisory's structured declaration does not name —
// the vulnerable mechanism often lives only in the advisory's recorded
// prose. Such a proposal is admissible only when it carries a verbatim
// anchor: an exact quote from the recorded advisory text that names the
// subject. This layer validates the extraction the same way every
// other deterministic gate validates the planner's output — the
// proposal still becomes nothing by itself; an admitted check produces
// an ordinary observation the existing verdict gates evaluate.
//
// Every rejection carries a named reason, mirroring how verdict gates
// name theirs, checked in admission order:
//
//	SUBJECT_ANCHOR_MISSING           — a non-declared subject proposed
//	                                   without an anchor (the v1–v4
//	                                   rule, unchanged)
//	SUBJECT_ANCHOR_NOT_FOUND         — the quoted anchor is not a
//	                                   verbatim (whitespace-normalized)
//	                                   substring of the recorded
//	                                   advisory text
//	SUBJECT_MALFORMED                — invalid import-path / symbol
//	                                   shape or a package outside the
//	                                   module its arguments name
//	SUBJECT_OUTSIDE_AFFECTED_MODULE  — the subject's package does not
//	                                   lie inside an advisory-affected
//	                                   module
const (
	SubjectMalformedReason      = "SUBJECT_MALFORMED"
	SubjectAnchorMissingReason  = "SUBJECT_ANCHOR_MISSING"
	SubjectAnchorNotFoundReason = "SUBJECT_ANCHOR_NOT_FOUND"
	SubjectOutsideModuleReason  = "SUBJECT_OUTSIDE_AFFECTED_MODULE"
	anchorFieldSummary          = "summary"
	anchorFieldDescription      = "description"
	anchorFieldRawBody          = "raw_body"
)

// SubjectProvenance records the advisory-text anchor a check subject
// was derived from: the advisory field the deterministic gate matched
// the quote in and the quote itself. It is provenance only — never a
// verdict input — and is additive/omitempty so legacy shapes stay
// byte-identical.
type SubjectProvenance struct {
	Field string `json:"field"`
	Quote string `json:"quote"`
}

// proposedSubject is one subject identity extracted from an action's
// argument object: a package/symbol pair, a module, or a nested
// subjects[] member. where names the argument position for messages.
type proposedSubject struct {
	Module  string
	Package string
	Symbol  string
	where   string
}

// subjectGateRegistry wraps the catalog registry with the anchored-text
// subject gate. Check admission stays layered: the catalog decides the
// action is a registered, schema-conform request, then this gate binds
// the subject identity to the frozen advisory — declared subjects pass
// exactly as before; non-declared ones need a verbatim anchor plus
// affected-module membership. The embedded registry supplies
// Checks/Dispatchable/Conditions verbatim, so the planner surface and
// replay admission see one unchanged registry.
type subjectGateRegistry struct {
	*flow.CatalogRegistry
	lane *LaneResult
	subs []declaredSubject
	mods map[string]bool
}

// newSubjectGateRegistry builds the gate over this lane's advisory.
// Declared subjects and modules come from the same declaredSubjects
// projection the verdict gates use, so the meaning of "declared" can
// never drift between admission and evaluation.
func newSubjectGateRegistry(inner *flow.CatalogRegistry, lane *LaneResult) *subjectGateRegistry {
	g := &subjectGateRegistry{CatalogRegistry: inner, lane: lane, mods: map[string]bool{}}
	for _, s := range declaredSubjects(lane) {
		if s.Module != "" {
			g.mods[s.Module] = true
		}
	}
	g.subs = declaredSubjects(lane)
	return g
}

// Check admits one action after the catalog layer: identity-shape,
// declaration and anchor rules above. A rejection names its reason
// token so the recorded plan rejection says exactly which gate failed.
func (g *subjectGateRegistry) Check(a flow.PlanAction) error {
	if err := g.CatalogRegistry.Check(a); err != nil {
		return err
	}
	refs := extractProposedSubjects(a.Arguments)
	anchor := strings.TrimSpace(a.Anchor)
	var nonDeclared []proposedSubject
	for _, s := range refs {
		if !g.subjectDeclared(s) {
			nonDeclared = append(nonDeclared, s)
		}
	}
	switch {
	case len(nonDeclared) > 0 && anchor == "":
		return fmt.Errorf("%s: %s names a subject outside the advisory's structured declaration — a verbatim anchor quoting the advisory text is mandatory",
			SubjectAnchorMissingReason, nonDeclared[0].where)
	case anchor != "":
		if field := advisoryAnchorField(g.lane, anchor); field == "" {
			return fmt.Errorf("%s: the quoted anchor is not a verbatim substring of the recorded advisory text",
				SubjectAnchorNotFoundReason)
		}
	}
	for _, s := range nonDeclared {
		if err := s.wellFormed(); err != nil {
			return fmt.Errorf("%s: %s carries an invalid subject identity: %v",
				SubjectMalformedReason, s.where, err)
		}
		if !g.insideAffectedModule(s) {
			return fmt.Errorf("%s: %s names a subject whose package does not lie inside an advisory-affected module",
				SubjectOutsideModuleReason, s.where)
		}
	}
	return nil
}

// subjectDeclared reports whether the proposed identity is part of the
// advisory's structured declaration — the same binding relation
// advisoryBinds applies: an exact module/package match with the
// declared symbol matching or open, or a declared module named as a
// module-level subject. A package merely inside a declared module is
// deliberately NOT declared: that is the text-anchored case.
func (g *subjectGateRegistry) subjectDeclared(s proposedSubject) bool {
	for _, sub := range g.subs {
		switch {
		case s.Package == "" && s.Symbol == "":
			// A module-level subject is declared when the module is one
			// the advisory declares — the module aggregate is a
			// canonical subject for every affected entry.
			if s.Module == sub.Module {
				return true
			}
		case s.Package == "":
			// A symbol with no package is never a declared subject;
			// the malformed gate names it.
			continue
		case s.Module == "":
			// Package-qualified refs without a module member bind to the
			// declared package wherever it is declared.
			if sub.Package != s.Package {
				continue
			}
			if s.Symbol == "" || sub.Symbol == "" || sub.Symbol == s.Symbol {
				return true
			}
		default:
			if sub.Module != s.Module || sub.Package != s.Package {
				continue
			}
			if s.Symbol == "" || sub.Symbol == "" || sub.Symbol == s.Symbol {
				return true
			}
		}
	}
	return false
}

// insideAffectedModule reports whether the subject's package position
// lies inside an advisory-affected module (module root or a subpackage,
// the PackageInModule relation) — or, for a module-level subject, is a
// declared module itself.
func (g *subjectGateRegistry) insideAffectedModule(s proposedSubject) bool {
	pos := s.Package
	if pos == "" {
		pos = s.Module
	}
	if pos == "" {
		return false
	}
	for m := range g.mods {
		if domain.PackageInModule(pos, m) {
			return true
		}
	}
	return false
}

// wellFormed checks the identity shape of a non-declared subject: a
// legal Go import path for module/package members, the module/package
// containment relation when both are named, and the symbol grammar
// (Name or Type.Member). Declared advisory subjects are trusted and
// never reach this check.
func (s proposedSubject) wellFormed() error {
	if s.Module != "" {
		if err := module.CheckImportPath(s.Module); err != nil {
			return fmt.Errorf("module %q is not a valid import path", s.Module)
		}
	}
	if s.Package != "" {
		if err := module.CheckImportPath(s.Package); err != nil {
			return fmt.Errorf("package %q is not a valid import path", s.Package)
		}
		if s.Module != "" && !domain.PackageInModule(s.Package, s.Module) {
			return fmt.Errorf("package %q does not lie inside the named module %q", s.Package, s.Module)
		}
	}
	if s.Symbol != "" {
		if s.Package == "" {
			return fmt.Errorf("symbol %q names no package — a symbol is never a package identity", s.Symbol)
		}
		if !subjectSymbolShape(s.Symbol) {
			return fmt.Errorf("symbol %q is not a Name or Type.Member shape", s.Symbol)
		}
	}
	return nil
}

// subjectSymbolShape reports whether s is a plausible Go symbol name:
// one or two dot-separated identifier segments (Func / Type.Member /
// Type.Field). Advisory-declared symbols are never shape-checked; this
// bounds only text-proposed identities.
func subjectSymbolShape(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if !goIdent(p) {
			return false
		}
	}
	return true
}

// goIdent reports whether s is a non-empty Go identifier (letters,
// digits and '_', not starting with a digit).
func goIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || unicode.IsLetter(r):
		case unicode.IsDigit(r) && i > 0:
		default:
			return false
		}
	}
	return true
}

// extractProposedSubjects walks the action argument object and collects
// every member that names an advisory subject: top-level
// module/module_prefix/package/symbol members plus nested subjects[]
// and check/pipeline SymbolRef members (which inherit a top-level
// module for identity, never for a missing package). Members the
// schema already rejected never reach this walk; every remaining
// subject key is a proposed identity the gate must account for.
func extractProposedSubjects(args json.RawMessage) []proposedSubject {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(args, &obj); err != nil {
		return nil // malformed arguments are the catalog layer's rejection
	}
	var out []proposedSubject
	top := proposedSubject{where: "arguments"}
	if v := argString(obj, "module"); v != "" {
		top.Module = v
	}
	if v := argString(obj, "package"); v != "" {
		top.Package = v
	}
	if v := argString(obj, "symbol"); v != "" {
		top.Symbol = v
	}
	if top.Module != "" || top.Package != "" || top.Symbol != "" {
		out = append(out, top)
	}
	if v := argString(obj, "module_prefix"); v != "" {
		out = append(out, proposedSubject{Module: v, where: "arguments.module_prefix"})
	}
	out = append(out, extractNestedSubjects(obj, "subjects", top.Module)...)
	out = append(out, extractNestedSubjects(obj, "check", "")...)
	out = append(out, extractNestedSubjects(obj, "pipeline", "")...)
	return out
}

// extractNestedSubjects reads subject members nested under one key:
// either a single SymbolRef-shaped object ({package, symbol}) or an
// array of them. inheritModule supplies the module context the nested
// ref omits (symbol-unreachability subjects[] inherit the top-level
// module; check_missing_call pairs stay module-free).
func extractNestedSubjects(obj map[string]json.RawMessage, key, inheritModule string) []proposedSubject {
	raw, ok := obj[key]
	if !ok {
		return nil
	}
	var out []proposedSubject
	collect := func(v json.RawMessage, idx string) {
		var ref struct {
			Package string `json:"package"`
			Symbol  string `json:"symbol"`
		}
		if json.Unmarshal(v, &ref) != nil {
			return // a non-object member is the catalog schema's rejection
		}
		if ref.Package == "" && ref.Symbol == "" {
			return
		}
		out = append(out, proposedSubject{
			Module: inheritModule, Package: ref.Package, Symbol: ref.Symbol,
			where: "arguments." + key + idx,
		})
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil && arr != nil {
		for i, v := range arr {
			collect(v, fmt.Sprintf("[%d]", i))
		}
		return out
	}
	collect(raw, "")
	return out
}

func argString(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// normalizeAnchorText collapses runs of whitespace to single spaces:
func normalizeAnchorText(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// advisoryTextFields enumerates the recorded advisory text channels an
// anchor may cite, in match order: the normalized summary and
// description first, then the raw frozen body (the full recorded text
// the lane holds, which can carry prose the normalized fields dropped).
// The raw body is a JSON document, not prose — anchors matched there
// are whole-record excerpts, never fabricated text.
func advisoryTextFields(lane *LaneResult) [][2]string {
	var out [][2]string
	if lane == nil {
		return out
	}
	if v := lane.Advisory.Vuln; v != nil {
		if v.Summary != "" {
			out = append(out, [2]string{anchorFieldSummary, v.Summary})
		}
		if v.Description != "" {
			out = append(out, [2]string{anchorFieldDescription, v.Description})
		}
	}
	if len(lane.Advisory.RawBytes) > 0 {
		out = append(out, [2]string{anchorFieldRawBody, string(lane.Advisory.RawBytes)})
	}
	return out
}

// advisoryAnchorField returns the advisory field the anchor is a
// verbatim (whitespace-normalized) substring of, or "" when no recorded
// field contains it.
func advisoryAnchorField(lane *LaneResult, anchor string) string {
	needle := normalizeAnchorText(anchor)
	if needle == "" {
		return ""
	}
	for _, f := range advisoryTextFields(lane) {
		if strings.Contains(normalizeAnchorText(f[1]), needle) {
			return f[0]
		}
	}
	return ""
}

// actionProvenance records the deterministic half of the anchor
// provenance: the action's recorded quote plus the field the gate
// matched it in. Declared subjects and anchor-less actions carry no
// provenance — an empty result means the subject came from the
// structured declaration alone.
func actionProvenance(lane *LaneResult, a *flow.PlanAction) *SubjectProvenance {
	if a == nil {
		return nil
	}
	anchor := strings.TrimSpace(a.Anchor)
	if anchor == "" {
		return nil
	}
	field := advisoryAnchorField(lane, anchor)
	if field == "" {
		return nil
	}
	return &SubjectProvenance{Field: field, Quote: anchor}
}
