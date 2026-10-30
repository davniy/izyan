package domain

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// OperationResolution is the typed outcome of binding one vulnerable-operation
// declaration — a statement taken verbatim from the record's own prose — to a
// source declaration under the assessed build. Only OperationBound admits a
// binding; every other outcome is preserved on the model so a positive cannot
// hide a declared operation it failed to source-bind.
type OperationResolution string

const (
	// OperationBound means the declaration resolved to exactly one source
	// symbol inside the record's own affected scope.
	OperationBound OperationResolution = "BOUND"
	// OperationUnresolved means the declaration named an operation that no
	// bounded source lookup found (or the lookup could not run).
	OperationUnresolved OperationResolution = "UNRESOLVED"
	// OperationAmbiguous means more than one source declaration inside the
	// record's own scope carries the declared name.
	OperationAmbiguous OperationResolution = "AMBIGUOUS"
	// OperationConflicted means the record's own prose declares more than one
	// distinct vulnerable operation, so no single declaration is authoritative.
	OperationConflicted OperationResolution = "CONFLICTED"
)

// OperationDeclaration is one vulnerable-operation declaration the record's own
// prose makes, e.g. "An issue in the Unmarshal function …". A mention of a
// symbol is not a declaration: the sentence must locate a defect in the named
// operation. The quotation is kept verbatim so the model and its re-admission
// can be checked against the exact record bytes.
type OperationDeclaration struct {
	// Operation is the identifier exactly as the record writes it.
	Operation string `json:"operation"`
	// Quotation is the verbatim record sentence carrying the declaration.
	Quotation string `json:"quotation"`
	// Resolution is the typed outcome of binding the declaration to source.
	Resolution OperationResolution `json:"resolution"`
	// Detail records the evidence behind a non-BOUND outcome: the searched
	// scope, the competing declarations, or the loader failure.
	Detail string `json:"detail,omitempty"`
}

// OperationBinding is the narrow, typed binding between an exact advisory
// record, the vulnerable operation its own prose names, and the source
// declaration that operation resolves to under the assessed build.
//
// It is deliberately not an advisory-symbol enrichment: it never writes back
// into Vulnerability.AffectedSymbols, CWE, aliases, ranges or the record
// census, and it never draws on a sibling record. Its whole purpose is to let
// the root-cause resolver prefer the operation the record itself names over a
// fix-diff candidate, while staying checkable against the record bytes.
type OperationBinding struct {
	// RecordID is the exact record's own identity the declaration came from.
	RecordID string `json:"record_id"`
	// DocumentDigest pins the record bytes the quotation was read from.
	DocumentDigest string `json:"document_digest"`
	// AffectedEntry is the module path of the affected[] entry the resolved
	// package belongs to.
	AffectedEntry string `json:"affected_entry,omitempty"`
	// Operation is the identifier as the record writes it; Symbol is the
	// declaration it resolved to. They are equal by construction.
	Operation string `json:"operation"`
	// Quotation is the verbatim record sentence naming the operation.
	Quotation string `json:"quotation"`
	// Package and Symbol are the resolved source identity.
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
	// SourceFile/SourceLine locate the declaration under the assessed build.
	SourceFile string `json:"source_file,omitempty"`
	SourceLine int    `json:"source_line,omitempty"`
	// Vendored marks a binding taken from the snapshot's vendored source
	// because the Go loader could not load the package. It proves the
	// declaration exists in the build input, not that a typed load agreed.
	Vendored bool `json:"vendored,omitempty"`
}

// Subject returns the bound operation as a condition/locus subject.
func (b OperationBinding) Subject() SymbolRef {
	return SymbolRef{Package: b.Package, Symbol: b.Symbol}
}

// Location renders the source binding for reports and limitations.
func (b OperationBinding) Location() string {
	if b.SourceFile == "" {
		return ""
	}
	if b.SourceLine > 0 {
		return b.SourceFile + ":" + strconv.Itoa(b.SourceLine)
	}
	return b.SourceFile
}

// OperationScope is one affected[] entry the operation-binding resolver may
// search: the entry's module and the packages the record itself declares for
// it. An entry that declares no package is searched at its module path only —
// a generic operation name is never hunted through unrelated packages.
type OperationScope struct {
	Module   string   `json:"module"`
	Packages []string `json:"packages,omitempty"`
}

// SearchPackages returns the bounded package set this scope permits: the
// declared packages, or the module path when the entry declares none.
func (s OperationScope) SearchPackages() []string {
	if len(s.Packages) > 0 {
		return s.Packages
	}
	if s.Module == "" {
		return nil
	}
	return []string{s.Module}
}

// Contains reports whether pkg is inside this scope's bounded search set. The
// predicate is identical to SearchPackages so admission accepts exactly what
// the resolver was allowed to look at.
func (s OperationScope) Contains(pkg string) bool {
	return pkg != "" && slices.Contains(s.SearchPackages(), pkg)
}

// OwnProse returns the record's own prose — the only text a vulnerable-
// operation declaration may be taken from. Aliases, related records and fix
// metadata contribute nothing.
func (v Vulnerability) OwnProse() string {
	var parts []string
	if s := strings.TrimSpace(v.Summary); s != "" {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(v.Description); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, "\n")
}

// OwnProseSentences splits the record's own prose into trimmed sentence units,
// keeping each unit verbatim so a declaration quotation can be matched against
// the record text byte for byte.
func (v Vulnerability) OwnProseSentences() []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			out = append(out, s)
		}
		b.Reset()
	}
	for _, r := range v.OwnProse() {
		switch r {
		case '\n':
			flush()
		case '.', '!', '?':
			b.WriteRune(r)
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

// OperationScopes projects the record's own affected entries into the bounded
// search scopes an operation declaration may be resolved against. Per-module
// entries win when the record carries them; a flat intake contributes a single
// entry built from its module and package fields (the same projection the
// affected resolver uses). Unnamed entries carry no module owner and are
// skipped: an ownerless subject cannot bound a symbol lookup.
func (v Vulnerability) OperationScopes() []OperationScope {
	var out []OperationScope
	seen := map[string]bool{}
	add := func(module string, pkgs []string) {
		if module == "" && len(pkgs) == 0 {
			return
		}
		key := module + "\x00" + strings.Join(pkgs, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, OperationScope{Module: module, Packages: pkgs})
	}
	for _, am := range v.AffectedModules {
		if am.Unnamed && am.Module == "" {
			continue
		}
		var pkgs []string
		for _, p := range am.AffectedPackages {
			if p.Path != "" && !slices.Contains(pkgs, p.Path) {
				pkgs = append(pkgs, p.Path)
			}
		}
		add(am.Module, pkgs)
	}
	if len(out) > 0 {
		return out
	}
	var pkgs []string
	for _, p := range v.AffectedPackages {
		if p.Path != "" && !slices.Contains(pkgs, p.Path) {
			pkgs = append(pkgs, p.Path)
		}
	}
	if len(pkgs) == 0 && v.Package != "" {
		pkgs = []string{v.Package}
	}
	add(v.Module, pkgs)
	return out
}

// OperationScopeFor returns the record's own affected entry that owns pkg.
func (v Vulnerability) OperationScopeFor(pkg string) (OperationScope, bool) {
	for _, s := range v.OperationScopes() {
		if s.Contains(pkg) {
			return s, true
		}
	}
	return OperationScope{}, false
}

// AdmitOperationBinding re-admits a binding against the record and its pin. A
// persisted binding is never trusted on its own: the record identity and
// document digest must still match, the quotation must still appear verbatim
// in the record's own prose, and the resolved package must still sit inside
// the record's own affected scope. Any mismatch returns no binding.
func AdmitOperationBinding(b OperationBinding, v Vulnerability, pin *RecordPin) (OperationBinding, error) {
	switch {
	case strings.TrimSpace(b.RecordID) == "":
		return OperationBinding{}, fmt.Errorf("operation binding has no record identity")
	case strings.TrimSpace(b.Operation) == "" || strings.TrimSpace(b.Symbol) == "":
		return OperationBinding{}, fmt.Errorf("operation binding has no operation or symbol")
	case strings.TrimSpace(b.Quotation) == "":
		return OperationBinding{}, fmt.Errorf("operation binding has no verbatim quotation")
	case strings.TrimSpace(b.Package) == "":
		return OperationBinding{}, fmt.Errorf("operation binding has no resolved package")
	case strings.TrimSpace(b.DocumentDigest) == "":
		return OperationBinding{}, fmt.Errorf("operation binding has no document digest")
	case b.Operation != b.Symbol:
		return OperationBinding{}, fmt.Errorf(
			"operation binding declared %q but resolved %q; the quoted operation is the resolved symbol", b.Operation, b.Symbol)
	}
	if pin == nil {
		return OperationBinding{}, fmt.Errorf("record bytes are not pinned; the declaration cannot be checked against the advisory")
	}
	if pin.RecordID != b.RecordID || pin.DocumentDigest != b.DocumentDigest {
		return OperationBinding{}, fmt.Errorf(
			"operation binding was read from record %s (%s), not this record %s (%s)",
			b.RecordID, b.DocumentDigest, pin.RecordID, pin.DocumentDigest)
	}
	if b.RecordID != v.ID {
		return OperationBinding{}, fmt.Errorf("operation binding belongs to record %s, not %s", b.RecordID, v.ID)
	}
	if !strings.Contains(v.OwnProse(), b.Quotation) {
		return OperationBinding{}, fmt.Errorf(
			"quotation is not part of this record's own prose any more: %q", b.Quotation)
	}
	if !operationQuoted(b.Quotation, b.Operation) {
		return OperationBinding{}, fmt.Errorf("quotation does not name operation %q", b.Operation)
	}
	scope, ok := v.OperationScopeFor(b.Package)
	if !ok {
		return OperationBinding{}, fmt.Errorf(
			"package %s is outside the record's own affected scope", b.Package)
	}
	if scope.Module != b.AffectedEntry {
		return OperationBinding{}, fmt.Errorf(
			"operation binding names affected entry %q but package %s belongs to %q",
			b.AffectedEntry, b.Package, scope.Module)
	}
	return b, nil
}

// AdmitOperationBindings re-admits every binding and reports the rejected ones
// as named reasons. Rejection is "no binding", never a negative result.
func AdmitOperationBindings(bindings []OperationBinding, v Vulnerability, pin *RecordPin) ([]OperationBinding, []string) {
	var admitted []OperationBinding
	var rejected []string
	for _, b := range bindings {
		a, err := AdmitOperationBinding(b, v, pin)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("%s.%s: %v", b.Package, b.Symbol, err))
			continue
		}
		admitted = append(admitted, a)
	}
	return admitted, rejected
}

// operationQuoted reports whether the quotation names the operation as a whole
// identifier — "Unmarshal" must not be satisfied by "UnmarshalAll".
func operationQuoted(quotation, operation string) bool {
	return regexp.MustCompile(`(?:^|[^\w])` + regexp.QuoteMeta(operation) + `(?:[^\w]|$)`).MatchString(quotation)
}
