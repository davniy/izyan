package rootcause

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// This file resolves the vulnerable operation the record's *own prose* names.
// It is the second resolver priority: structured advisory symbols first, then
// an explicit own-record declaration that source-binds uniquely, then the fix
// diff. A declaration is a statement that locates a defect in a named
// operation ("An issue in the Unmarshal function …"); a mere mention of a
// symbol is not one, and a declaration that does not bind uniquely admits
// nothing.

// operationStopwords are prose tokens that look like identifiers but never
// name a Go operation in an advisory. The real gate is the declaration shape
// plus source binding; this list only keeps ordinary English and acronyms out
// of the candidate set.
var operationStopwords = map[string]bool{
	"The": true, "This": true, "These": true, "Those": true, "There": true, "Then": true,
	"That": true, "When": true, "While": true, "Where": true, "Which": true, "Who": true,
	"Whose": true, "However": true, "Moreover": true, "If": true, "In": true, "On": true,
	"At": true, "By": true, "For": true, "From": true, "With": true, "Without": true,
	"Within": true, "All": true, "Any": true, "Every": true, "Each": true, "Some": true,
	"Most": true, "Many": true, "No": true, "Not": true, "Only": true, "Also": true,
	"Note": true, "Its": true, "It": true, "They": true, "We": true, "You": true,
	"Our": true, "Your": true, "Their": true, "And": true, "Or": true, "But": true,
	"As": true, "To": true, "Of": true, "Is": true, "Are": true, "Was": true,
	"Were": true, "Be": true, "Been": true, "Has": true, "Have": true, "Had": true,
	"Do": true, "Does": true, "Did": true, "Can": true, "Could": true, "May": true,
	"Might": true, "Must": true, "Shall": true, "Should": true, "Will": true,
	"Would": true, "Go": true, "GoLang": true, "Golang": true, "Yaml": true,
	"YAML": true, "API": true, "APIs": true, "CVE": true, "GHSA": true, "OSV": true,
	"NVD": true, "CVSS": true, "DoS": true, "TLS": true, "SSL": true, "SSH": true,
	"HTTP": true, "HTTPS": true, "TCP": true, "UDP": true, "IP": true, "DNS": true,
	"JSON": true, "XML": true, "RCE": true, "SSRF": true, "XSS": true, "CSRF": true,
	"URL": true, "URI": true, "ID": true, "IDs": true, "CPU": true, "RAM": true,
	"GC": true, "PoC": true, "SDK": true, "CLI": true, "GUI": true, "SQL": true,
	"HTML": true, "CSS": true, "JWT": true, "UTF": true, "ASCII": true, "CWE": true,
	"OOM": true, "CORS": true, "AWS": true, "GCP": true, "HTTP2": true,
}

var (
	// backtickOperationRe captures an explicitly quoted operation name.
	backtickOperationRe = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)?)`")
	// bareOperationRe captures an unquoted capitalized identifier; advisories
	// name Go API operations by their exported spelling.
	bareOperationRe = regexp.MustCompile(`\b[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)?\b`)
	// negatedDeclarationRe rejects sentences that say no defect exists — a
	// denial of an issue is not a vulnerable-operation declaration.
	negatedDeclarationRe = regexp.MustCompile(`(?i)(?:\b(?:no|not|never|without|unaffected)\b[^.;!?\n]{0,40}\b(?:issue|problem|flaw|bug|defect|vulnerability|affected|vulnerable)\b|\bnot\s+affected\b|\bis\s+not\s+vulnerable\b)`)
)

// operationNounsUnquoted are the nouns that turn a bare capitalized token into
// a named operation. Only the code-identity nouns qualify: "a vulnerability in
// the GraphQL parser" / "… the Admin API" name a technology or a product, not a
// Go operation, and admitting them would let a project name become a root
// cause whenever the package happens to declare a same-named symbol.
const operationNounsUnquoted = `(?:function|method)`

// operationNounsQuoted additionally accepts the API-surface nouns: a backticked
// name is already marked as code, so a quoted name followed by "parser" or
// "handler" names an operation.
const operationNounsQuoted = `(?:function|method|parser|api|call|code|handler)`

// defectLocatedInRe matches "… issue/problem/flaw … in the <name> <noun> …" —
// the advisory locates the defect in the named operation. The noun is
// mandatory: without it "a vulnerability in Zitadel's login UI" would declare
// the project, not an operation.
func defectLocatedInRe(name string, quoted bool) *regexp.Regexp {
	q := regexp.QuoteMeta(name)
	noun := `\s+` + operationNounsUnquoted + `\b`
	if quoted {
		noun = `(?:\s+` + operationNounsQuoted + `\b)?`
	}
	return regexp.MustCompile(`(?i)\b(?:issue|problem|flaw|bug|defect|vulnerability|weakness)\b[^.;!?\n]{0,80}?\b(?:in|within|inside|affecting|affects)\s+(?:the\s+)?` + q + noun)
}

// operationDefectShapeRe matches "<name> <noun> … can/… … panic/crash/
// overflow/…" — the advisory predicates a defect of the named operation. The
// same noun restriction applies: only a code-identity noun (or a quoted name
// with an API-surface noun) names an operation.
func operationDefectShapeRe(name string, quoted bool) *regexp.Regexp {
	q := regexp.QuoteMeta(name)
	nouns := operationNounsUnquoted
	if quoted {
		nouns = operationNounsQuoted
	}
	return regexp.MustCompile(`(?i)\b` + q + `\s+` + nouns + `\b[^.;!?\n]{0,90}?\b(?:can|may|will|would|could|allows?|lets?|fails?|does\s+not|doesn't|is|are|was|were)\b[^.;!?\n]{0,70}?\b(?:panic|crash|overflow\w*|unbounded|out[- ]of[- ]bounds|vulnerab\w*|unsafe|incorrect\w*|wrong\w*|invalid|unvalidated|exhaust\w*|denial of service|attacker)\b`)
}

// operationDeclarations extracts the record's own vulnerable-operation
// declarations, deduplicated by operation name and kept verbatim.
func operationDeclarations(v domain.Vulnerability) []domain.OperationDeclaration {
	var decls []domain.OperationDeclaration
	seen := map[string]bool{}
	for _, sentence := range v.OwnProseSentences() {
		if len(sentence) < 12 || negatedDeclarationRe.MatchString(sentence) {
			continue
		}
		for _, name := range declaredNamesIn(sentence) {
			if seen[name] {
				continue
			}
			seen[name] = true
			decls = append(decls, domain.OperationDeclaration{Operation: name, Quotation: sentence})
		}
	}
	return decls
}

// declaredNamesIn returns the operation names this sentence declares as
// defective. Candidates come from quoted identifiers first, then unquoted
// exported spellings; both must match a declaration shape.
func declaredNamesIn(sentence string) []string {
	var names []string
	for _, m := range backtickOperationRe.FindAllStringSubmatch(sentence, -1) {
		name := m[1]
		if !operationIdentifier(name) || !declarationShape(sentence, name, true) {
			continue
		}
		if !containsName(names, name) {
			names = append(names, name)
		}
	}
	for _, name := range bareOperationRe.FindAllString(sentence, -1) {
		if !operationIdentifier(name) || operationStopwords[name] || !declarationShape(sentence, name, false) {
			continue
		}
		if !containsName(names, name) {
			names = append(names, name)
		}
	}
	return names
}

func declarationShape(sentence, name string, quoted bool) bool {
	return defectLocatedInRe(name, quoted).MatchString(sentence) ||
		operationDefectShapeRe(name, quoted).MatchString(sentence)
}

func operationIdentifier(name string) bool {
	if len(name) < 3 || operationStopwords[name] {
		return false
	}
	// Prose writes acronyms and mechanism names in all caps; Go operation
	// names carry a lowercase letter somewhere.
	return strings.ToUpper(name) != name
}

func containsName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// operationMatch is one source declaration inside the record's own scope.
type operationMatch struct {
	scope    domain.OperationScope
	pkg      string
	site     *domain.CallSite
	vendored bool
}

// resolveDeclarations resolves the record's prose declarations against source
// under the assessed build and records the outcome on the model. Exactly one
// uniquely bound declaration becomes an admitted OperationBinding; every other
// outcome stays a preserved declaration and returns no binding at all.
func (r Resolver) resolveDeclarations(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability, model *domain.RootCauseModel) ([]domain.Evidence, []string) {
	decls := operationDeclarations(v)
	if len(decls) == 0 {
		return nil, nil
	}
	model.OperationDeclarations = decls

	names := make([]string, 0, len(decls))
	for _, d := range decls {
		names = append(names, d.Operation)
	}
	if len(names) > 1 {
		detail := fmt.Sprintf(
			"the record's own prose declares %d distinct vulnerable operations (%s); no single declaration selects the defective operation",
			len(names), strings.Join(names, ", "))
		for i := range model.OperationDeclarations {
			model.OperationDeclarations[i].Resolution = domain.OperationConflicted
			model.OperationDeclarations[i].Detail = detail
		}
		return nil, []string{detail}
	}

	name := names[0]
	decl := &model.OperationDeclarations[0]
	fail := func(code domain.OperationResolution, detail string) ([]domain.Evidence, []string) {
		decl.Resolution = code
		decl.Detail = detail
		return nil, []string{detail}
	}

	if c == nil || c.RecordPin == nil {
		return fail(domain.OperationUnresolved, fmt.Sprintf(
			"declared operation %s is unbound: the record bytes are not pinned, so the declaration cannot be checked against the advisory", name))
	}
	if r.Source == nil {
		return fail(domain.OperationUnresolved, fmt.Sprintf(
			"declared operation %s is unbound: no source index is available to verify it under the assessed build", name))
	}
	scopes := v.OperationScopes()
	if len(scopes) == 0 {
		return fail(domain.OperationUnresolved, fmt.Sprintf(
			"declared operation %s is unbound: the record declares no affected module or package to search", name))
	}

	var (
		matches    []operationMatch
		searchErrs []string
		searched   []string
	)
	for _, scope := range scopes {
		for _, pkg := range scope.SearchPackages() {
			if containsName(searched, pkg) {
				continue
			}
			searched = append(searched, pkg)
			lk, err := r.Source.LookupSymbol(ctx, domain.SymbolRef{Package: pkg, Symbol: name})
			if err != nil {
				searchErrs = append(searchErrs, fmt.Sprintf("%s.%s: %v", pkg, name, err))
				continue
			}
			if lk.Site == nil {
				continue
			}
			matches = append(matches, operationMatch{scope: scope, pkg: pkg, site: lk.Site, vendored: lk.Vendored})
		}
	}

	switch {
	case len(matches) == 0:
		detail := fmt.Sprintf(
			"declared operation %s did not resolve inside the record's own scope (%s)",
			name, strings.Join(searched, ", "))
		if len(searchErrs) > 0 {
			detail += "; " + strings.Join(searchErrs, "; ")
		}
		return fail(domain.OperationUnresolved, detail)
	case len(matches) > 1:
		var where []string
		for _, m := range matches {
			where = append(where, m.pkg+"."+name)
		}
		return fail(domain.OperationAmbiguous, fmt.Sprintf(
			"declared operation %s is ambiguous inside the record's own scope: %s",
			name, strings.Join(where, ", ")))
	}

	m := matches[0]
	binding := domain.OperationBinding{
		RecordID:       v.ID,
		DocumentDigest: c.RecordPin.DocumentDigest,
		AffectedEntry:  m.scope.Module,
		Operation:      name,
		Quotation:      decl.Quotation,
		Package:        m.pkg,
		Symbol:         name,
		SourceFile:     m.site.File,
		SourceLine:     m.site.Line,
		Vendored:       m.vendored,
	}
	admitted, err := domain.AdmitOperationBinding(binding, v, c.RecordPin)
	if err != nil {
		return fail(domain.OperationUnresolved, fmt.Sprintf(
			"declared operation %s resolved to %s.%s but failed record-scope admission: %v", name, m.pkg, name, err))
	}
	decl.Resolution = domain.OperationBound
	decl.Detail = fmt.Sprintf("resolved to %s at %s", admitted.Package+"."+admitted.Symbol, admitted.Location())
	model.OperationBindings = append(model.OperationBindings, admitted)

	evs := []domain.Evidence{
		{
			Kind:    domain.EvidenceAdvisory,
			Quality: domain.QualityAuthoritative,
			Source:  "record prose: vulnerable-operation declaration",
			Tool:    "vulnerability.OSV",
			Content: admitted.Quotation + "\noperation: " + admitted.Operation,
		},
		{
			Kind:      domain.EvidenceSourceSnippet,
			Quality:   domain.QualityDeterministic,
			Source:    "source index: declared operation binding",
			Tool:      "goanalysis.Index.LookupSymbol",
			File:      admitted.SourceFile,
			StartLine: admitted.SourceLine,
			Content:   admitted.Package + "." + admitted.Symbol + " declared at " + admitted.Location(),
		},
	}
	var lims []string
	if admitted.Vendored {
		lims = append(lims, fmt.Sprintf(
			"declared operation %s.%s bound from vendored source (Go loader unavailable for the package)",
			admitted.Package, admitted.Symbol))
	}
	return evs, lims
}
