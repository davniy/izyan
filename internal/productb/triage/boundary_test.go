package triage

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoSecondAuthorityContract pins the adapter boundary at the import
// level: the package must never reach for Product A authority packages
// (canonical domain/evaluator) or re-import the V2 world it was ported
// from. §14.3.2 maps V2 types at adapter boundaries only — an import of
// internal/domain inside the triage adapter would be a second contract
// path, not a mapping.
func TestNoSecondAuthorityContract(t *testing.T) {
	forbidden := []string{
		"internal/domain",
		"internal/evaluator",
		"internal/affected",
		"agenttriage", // the V2 package this adapter replaces; no re-import
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, pkg := range pkgs {
		for file, f := range pkg.Files {
			if strings.HasSuffix(file, "_test.go") && file != "boundary_test.go" {
				continue
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if strings.Contains(path, bad) {
						t.Errorf("%s imports forbidden authority/V2 package %q", filepath.Base(file), path)
					}
				}
			}
		}
	}
}

// TestProposalCannotSetAuthorityFields is the S-06 acceptance pinned at
// the type level: the falsifier proposal carries no field that could ever
// encode a verification outcome, and every attempt to smuggle one through
// JSON fails at decode — never normalized into a trusted value.
func TestProposalCannotSetAuthorityFields(t *testing.T) {
	for _, field := range []string{
		"status", "verified", "mandatory", "coverage",
		"negative_verification", "recommendation", "verdict",
	} {
		payload := `{"id":"fp","claim_id":"c","condition_id":"c1","kind":"code_absent",` +
			`"subjects":[{"package":"p","symbol":"s"}],"evidence_refs":["e1"],` +
			`"` + field + `":true}`
		var p FalsifierProposal
		if err := json.Unmarshal([]byte(payload), &p); err == nil {
			t.Errorf("proposal field %q must be rejected at decode", field)
		} else if !strings.Contains(err.Error(), field) {
			t.Errorf("rejection of %q must name the field, got %v", field, err)
		}
	}
}

// TestAssessmentIsNotProductAVerdict: the Product B verdict enum rejects
// every Product A verdict spelling — an assessment can never be read as
// an authoritative verdict of the deterministic analyzer.
func TestAssessmentIsNotProductAVerdict(t *testing.T) {
	for _, legacy := range []string{
		"NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND", "FALSE", "TRUE", "UNKNOWN",
	} {
		var v Verdict
		if err := json.Unmarshal([]byte(`"`+legacy+`"`), &v); err == nil {
			t.Errorf("verdict %q must never decode into Product B Verdict", legacy)
		}
	}
}

// TestCanonicalLocatorRejectsNonCanonical: pseudo-locators that spell an
// observation result rather than an audited id never survive the canonical
// proposal-binding form; the fact gate keeps its own tolerant spellings
// for claim evidence but the verifier anchor stays strict.
func TestCanonicalLocatorRejectsNonCanonical(t *testing.T) {
	canonical := []string{"det:det-0001", "det:obs-0003"}
	for _, loc := range canonical {
		if !canonicalDetLocator(loc) {
			t.Errorf("canonical locator %q must be accepted", loc)
		}
	}
	for _, loc := range []string{
		"det:", "det: ", "DET:det-0001", "det:det-0001@aa",
		"search:needle=1", "list_files:pkg", "det-0001", // bare id is not the canonical form
		"obs:obs-0001", // obs: scheme is not the det: binding
	} {
		if canonicalDetLocator(loc) {
			t.Errorf("non-canonical locator %q must be rejected for proposal bindings", loc)
		}
	}
}
