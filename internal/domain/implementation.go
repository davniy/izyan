package domain

import (
	"fmt"
	"go/build/constraint"
	"path"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// ImplementationLocusProposal is an LLM-inferred hypothesis about where a
// vulnerable implementation lives inside an advisory-declared module. It is
// never evidence and never a verdict input: Quality MUST stay
// QualityLLMInferred, the advisory reference and quoted span bind it to the
// frozen advisory bytes, and only the deterministic implementation verifier
// (affected.VerifyImplementationLocus) can turn a proposal into an
// implementation-presence fact.
//
// File is slash-separated and relative to the proposed package directory.
// Function names the function or method in that file whose body carries
// Marker; an empty Function is a binding locus — admissible only when the
// proposed file declares no functions, and Marker is then verified as a
// verbatim substring of the file itself.
// BuildExpression is the file's explicit //go:build (or // +build)
// expression; empty means the file carries no explicit expression.
// GOOS/GOARCH name the platforms the advisory attributes the vulnerable
// implementation to. They are hypothesis metadata only — the recorded
// go/build.Context decides selection.
type ImplementationLocusProposal struct {
	ID                  string          `json:"id"`
	Quality             EvidenceQuality `json:"quality"`
	Module              string          `json:"module"`
	Version             string          `json:"version"`
	Package             string          `json:"package"`
	File                string          `json:"file"`
	Function            string          `json:"function"`
	Marker              string          `json:"marker"`
	BuildExpression     string          `json:"build_expression"`
	GOOS                []string        `json:"goos,omitempty"`
	GOARCH              []string        `json:"goarch,omitempty"`
	AdvisoryEvidenceRef string          `json:"advisory_evidence_ref"`
	AdvisoryQuotedSpan  string          `json:"advisory_quoted_span"`
}

// Explicit bounds for a proposal. Every member is bounded so neither the
// agent answer nor a replay artifact can smuggle unbounded content into a
// report or a verifier scan.
const (
	MaxImplementationProposalIDBytes        = 128
	MaxImplementationProposalPathBytes      = 512
	MaxImplementationProposalFunctionBytes  = 256
	MaxImplementationProposalMarkerBytes    = 512
	MaxImplementationProposalBuildBytes     = 1024
	MaxImplementationProposalQuoteBytes     = 4096
	MaxImplementationProposalAdvisoryRef    = 256
	MaxImplementationProposalPlatformTokens = 16
	MaxImplementationProposalPlatformBytes  = 32
)

// Recorded advisory fields an implementation proposal may quote.
const (
	ImplementationAdvisoryFieldSummary = "summary"
	ImplementationAdvisoryFieldDetails = "details"
	ImplementationAdvisoryFieldRawBody = "raw_body"
)

var implementationProposalIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var implementationPlatformRe = regexp.MustCompile(`^[a-z0-9]+$`)

// Validate checks the proposal's typed shape. It deliberately performs no
// source lookup and resolves nothing: research admission and the
// deterministic verifier each bind the shape to the frozen advisory and the
// snapshot. A proposal that fails this check can never be admitted.
func (p ImplementationLocusProposal) Validate() error {
	switch {
	case !implementationProposalIDRe.MatchString(p.ID):
		return fmt.Errorf("id %q is empty or not a bounded [A-Za-z0-9._-] token", p.ID)
	case len(p.ID) > MaxImplementationProposalIDBytes:
		return fmt.Errorf("id exceeds %d bytes", MaxImplementationProposalIDBytes)
	case p.Quality != QualityLLMInferred:
		return fmt.Errorf("quality %q is not %s — only an LLM-inferred proposal is admissible", p.Quality, QualityLLMInferred)
	}
	if err := module.CheckImportPath(p.Module); err != nil {
		return fmt.Errorf("module %q is not a valid import path: %v", p.Module, err)
	}
	if len(p.Module) > MaxImplementationProposalPathBytes {
		return fmt.Errorf("module exceeds %d bytes", MaxImplementationProposalPathBytes)
	}
	if !semver.IsValid(p.Version) {
		return fmt.Errorf("version %q is not a valid semantic version", p.Version)
	}
	if err := module.CheckImportPath(p.Package); err != nil {
		return fmt.Errorf("package %q is not a valid import path: %v", p.Package, err)
	}
	if len(p.Package) > MaxImplementationProposalPathBytes {
		return fmt.Errorf("package exceeds %d bytes", MaxImplementationProposalPathBytes)
	}
	if !PackageInModule(p.Package, p.Module) {
		return fmt.Errorf("package %q does not lie inside module %q", p.Package, p.Module)
	}
	if err := validateProposalFile(p.File); err != nil {
		return err
	}
	if err := validateProposalFunction(p.Function); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(p.Marker) == "":
		return fmt.Errorf("marker is empty")
	case len(p.Marker) > MaxImplementationProposalMarkerBytes:
		return fmt.Errorf("marker exceeds %d bytes", MaxImplementationProposalMarkerBytes)
	case strings.ContainsRune(p.Marker, 0):
		return fmt.Errorf("marker contains a NUL byte")
	}
	if len(p.BuildExpression) > MaxImplementationProposalBuildBytes {
		return fmt.Errorf("build_expression exceeds %d bytes", MaxImplementationProposalBuildBytes)
	}
	if err := ValidateBuildExpression(p.BuildExpression); err != nil {
		return fmt.Errorf("build_expression: %v", err)
	}
	if err := validatePlatformTokens("goos", p.GOOS); err != nil {
		return err
	}
	if err := validatePlatformTokens("goarch", p.GOARCH); err != nil {
		return err
	}
	if len(p.AdvisoryEvidenceRef) == 0 || len(p.AdvisoryEvidenceRef) > MaxImplementationProposalAdvisoryRef {
		return fmt.Errorf("advisory_evidence_ref must be 1..%d bytes", MaxImplementationProposalAdvisoryRef)
	}
	if err := validateAdvisoryRefShape(p.AdvisoryEvidenceRef); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(p.AdvisoryQuotedSpan) == "":
		return fmt.Errorf("advisory_quoted_span is empty")
	case len(p.AdvisoryQuotedSpan) > MaxImplementationProposalQuoteBytes:
		return fmt.Errorf("advisory_quoted_span exceeds %d bytes", MaxImplementationProposalQuoteBytes)
	case strings.ContainsRune(p.AdvisoryQuotedSpan, 0):
		return fmt.Errorf("advisory_quoted_span contains a NUL byte")
	}
	return nil
}

// validateProposalFile confines the proposed file path: slash-separated,
// relative to the package directory, no traversal, no absolute/volume form,
// a non-test Go source file.
func validateProposalFile(file string) error {
	switch {
	case file == "":
		return fmt.Errorf("file is empty")
	case len(file) > MaxImplementationProposalPathBytes:
		return fmt.Errorf("file exceeds %d bytes", MaxImplementationProposalPathBytes)
	case strings.Contains(file, "\\"):
		return fmt.Errorf("file %q must use slash separators", file)
	case strings.HasPrefix(file, "/") || path.IsAbs(file):
		return fmt.Errorf("file %q must be relative to the package directory", file)
	}
	clean := path.Clean(file)
	if clean != file {
		return fmt.Errorf("file %q is not a clean relative path (want %q)", file, clean)
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("file %q escapes the package directory", file)
	}
	if !strings.HasSuffix(clean, ".go") {
		return fmt.Errorf("file %q is not a Go source file", file)
	}
	if strings.HasSuffix(clean, "_test.go") {
		return fmt.Errorf("file %q is a test file and is never part of the product build", file)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == "" || strings.HasPrefix(seg, ".") && seg != "." {
			return fmt.Errorf("file %q carries an empty, dot or hidden path segment", file)
		}
	}
	return nil
}

// validateProposalFunction accepts a top-level function name or a method
// reference in Name, Type.Name or (*Type).Name form. An empty reference is
// valid and denotes a binding locus: the deterministic verifier admits it
// only when the proposed file declares no functions.
func validateProposalFunction(function string) error {
	if function == "" {
		return nil
	}
	if len(function) > MaxImplementationProposalFunctionBytes {
		return fmt.Errorf("function exceeds %d bytes", MaxImplementationProposalFunctionBytes)
	}
	recv, name := splitFunctionRef(function)
	if name == "" || !validGoIdent(name) || !validGoIdent(recv) {
		return fmt.Errorf("function %q is not a Name, Type.Name or (*Type).Name reference", function)
	}
	return nil
}

// splitFunctionRef splits a proposal function reference into receiver and
// name. An empty receiver means a bare name or a top-level function.
func splitFunctionRef(function string) (recv, name string) {
	s := strings.TrimSpace(function)
	if strings.HasPrefix(s, "(") {
		if end := strings.Index(s, ")"); end > 1 && end+1 < len(s) && s[end+1] == '.' {
			return strings.TrimPrefix(s[1:end], "*"), s[end+2:]
		}
		return "", ""
	}
	if i := strings.LastIndex(s, "."); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// validGoIdent reports whether s is one Go identifier: empty is allowed
// (method receiver omitted); a non-empty identifier starts with a letter or
// '_' and continues with letters, digits or '_'.
func validGoIdent(s string) bool {
	if s == "" {
		return true
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

// ValidateBuildExpression checks that a proposed expression parses under
// the same syntax the toolchain uses. An empty expression is valid (the
// file carries no explicit constraint).
func ValidateBuildExpression(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	line := expr
	if !constraint.IsGoBuild(line) && !constraint.IsPlusBuild(line) {
		line = "//go:build " + line
	}
	if _, err := constraint.Parse(line); err != nil {
		return fmt.Errorf("%q does not parse as a build constraint: %v", expr, err)
	}
	return nil
}

func validatePlatformTokens(member string, tokens []string) error {
	if len(tokens) > MaxImplementationProposalPlatformTokens {
		return fmt.Errorf("%s carries %d tokens; maximum is %d", member, len(tokens), MaxImplementationProposalPlatformTokens)
	}
	seen := map[string]bool{}
	for _, t := range tokens {
		if len(t) == 0 || len(t) > MaxImplementationProposalPlatformBytes || !implementationPlatformRe.MatchString(t) {
			return fmt.Errorf("%s token %q is not a bounded lowercase platform token", member, t)
		}
		if seen[t] {
			return fmt.Errorf("%s token %q is duplicated", member, t)
		}
		seen[t] = true
	}
	return nil
}

func validateAdvisoryRefShape(ref string) error {
	switch {
	case strings.HasPrefix(ref, "adv:"):
		if strings.TrimSpace(strings.TrimPrefix(ref, "adv:")) == "" {
			return fmt.Errorf("advisory_evidence_ref %q names no advisory id", ref)
		}
		return nil
	case strings.HasPrefix(ref, "sha256:"):
		d := strings.TrimPrefix(ref, "sha256:")
		if len(d) != 64 || strings.ToLower(d) != d {
			return fmt.Errorf("advisory_evidence_ref %q must carry a 64-hex lowercase sha256", ref)
		}
		for _, r := range d {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return fmt.Errorf("advisory_evidence_ref %q must carry a 64-hex lowercase sha256", ref)
			}
		}
		return nil
	default:
		return fmt.Errorf("advisory_evidence_ref %q must be adv:<id> or sha256:<hex>", ref)
	}
}

// ValidateImplementationAdvisoryRef resolves a proposal's advisory
// reference against the frozen advisory identity: adv:<resolved-id> names
// the loaded document, sha256:<digest> pins its bytes (raw or canonical).
func ValidateImplementationAdvisoryRef(ref, advisoryID string, digests ...string) error {
	if err := validateAdvisoryRefShape(ref); err != nil {
		return err
	}
	if id, ok := strings.CutPrefix(ref, "adv:"); ok {
		if advisoryID == "" {
			return fmt.Errorf("advisory_evidence_ref %q cannot resolve: the frozen advisory identity is unknown", ref)
		}
		if id != advisoryID {
			return fmt.Errorf("advisory_evidence_ref %q does not resolve to the frozen advisory %q", ref, advisoryID)
		}
		return nil
	}
	want, _ := strings.CutPrefix(ref, "sha256:")
	for _, d := range digests {
		if d != "" && strings.EqualFold(d, want) {
			return nil
		}
	}
	return fmt.Errorf("advisory_evidence_ref %q does not resolve to any pinned frozen-advisory digest", ref)
}

// ImplementationAdvisoryQuoteField reports which recorded advisory field
// contains the proposal's quoted span. Matching is verbatim apart from
// whitespace-run normalization — the same anchor semantics the existing
// subject-anchor gate applies — and returns "" when the quote is a
// paraphrase or names no recorded advisory text.
func ImplementationAdvisoryQuoteField(quote, summary, details string, raw []byte) string {
	needle := normalizeAdvisoryQuote(quote)
	if needle == "" {
		return ""
	}
	for _, f := range []struct{ name, text string }{
		{ImplementationAdvisoryFieldSummary, summary},
		{ImplementationAdvisoryFieldDetails, details},
	} {
		if f.text != "" && strings.Contains(normalizeAdvisoryQuote(f.text), needle) {
			return f.name
		}
	}
	if len(raw) > 0 && strings.Contains(normalizeAdvisoryQuote(string(raw)), needle) {
		return ImplementationAdvisoryFieldRawBody
	}
	return ""
}

func normalizeAdvisoryQuote(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
