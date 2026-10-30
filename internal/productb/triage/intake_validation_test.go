package triage

import (
	"context"
	"strings"
	"testing"
)

func fieldStatus(t *testing.T, v IntakeValidation, field string) FieldValidation {
	t.Helper()
	fv, ok := v.Field(field)
	if !ok {
		t.Fatalf("no FieldValidation for %q; fields: %+v", field, v.Fields)
	}
	return fv
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func testCatalog() Catalog {
	return Catalog{Entries: []CatalogEntry{
		{ID: "example-service", Kind: "git", Locator: "https://example.org/repos/example-service.git", Ecosystem: "go"},
		{ID: "example-parser", Kind: "git", Locator: "https://example.org/repos/parser.git", Ecosystem: "go", Aliases: []string{"parser-lib"}},
		{ID: "mirror-parser", Kind: "git", Locator: "https://mirror.example.org/repos/parser.git", Ecosystem: "go"},
	}}
}

// Every proposed ID must pass format plus provenance: an ID that appears
// neither in the raw document nor in a supplied advisory stays UNVERIFIED,
// and a malformed one is INVALID.
func TestIntakeValidationIDHallucination(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-12345"},
	}, nil, Catalog{})
	fv := fieldStatus(t, v, "vulnerability_ids")
	if fv.Status != IntakeUnverified {
		t.Fatalf("invented ID status = %q, want UNVERIFIED", fv.Status)
	}
	if !fv.BlocksRiskReduction {
		t.Fatal("UNVERIFIED vulnerability id must block risk reduction")
	}

	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-99-1"},
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "vulnerability_ids"); fv.Status != IntakeInvalid {
		t.Fatalf("malformed ID status = %q, want INVALID", fv.Status)
	}
	if len(v.Errors) == 0 {
		t.Fatal("INVALID field must be recorded in errors")
	}
}

func TestIntakeValidationIDInText(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
	}, nil, Catalog{})
	fv := fieldStatus(t, v, "vulnerability_ids")
	if fv.Status != IntakeValid {
		t.Fatalf("ID present in text status = %q, want VALID (reason %q)", fv.Status, fv.Reason)
	}
	if fv.BlocksRiskReduction {
		t.Fatal("VALID vulnerability id must not block risk reduction")
	}
}

// The document mentions no ID, but a supplied advisory ID confirms the
// candidate: VALID with advisory provenance.
func TestIntakeValidationIDFromAdvisory(t *testing.T) {
	raw := mustIntakeRecord(t, "Crash reported in example.org/library/parser version 1.4.2.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"cve-2099-0001"},
	}, []string{"CVE-2099-0001"}, Catalog{})
	fv := fieldStatus(t, v, "vulnerability_ids")
	if fv.Status != IntakeValid {
		t.Fatalf("advisory-confirmed ID status = %q, want VALID", fv.Status)
	}
	if !containsStr(fv.Provenance, "advisory") {
		t.Fatalf("advisory provenance expected, got %v", fv.Provenance)
	}
}

func TestIntakeValidationDuplicateIDs(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001", "cve-2099-0001"},
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "vulnerability_ids"); fv.Status != IntakeConflicting {
		t.Fatalf("duplicate canonical ID status = %q, want CONFLICTING", fv.Status)
	}
}

// Two distinct canonical IDs in one record make the primary ambiguous: the
// validator must not silently pick one.
func TestIntakeValidationAmbiguousIDs(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 and CVE-2099-0002 both affect parser.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001", "CVE-2099-0002"},
	}, nil, Catalog{})
	fv := fieldStatus(t, v, "vulnerability_ids")
	if fv.Status != IntakeConflicting {
		t.Fatalf("two distinct primary IDs status = %q, want CONFLICTING", fv.Status)
	}
	if !fv.BlocksRiskReduction {
		t.Fatal("ambiguous primary ID must block risk reduction")
	}
}

func TestIntakeValidationMissingIDs(t *testing.T) {
	raw := mustIntakeRecord(t, "Crash reported in example.org/library/parser version 1.4.2.")
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion}, nil, Catalog{})
	fv := fieldStatus(t, v, "vulnerability_ids")
	if fv.Status != IntakeUnavailable {
		t.Fatalf("missing IDs status = %q, want UNAVAILABLE", fv.Status)
	}
	if !fv.BlocksRiskReduction {
		t.Fatal("missing vulnerability id must block risk reduction")
	}
}

func TestIntakeValidationAliases(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Aliases:          []string{"GHSA-xxxx-yyyy-zzzz"},
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "aliases"); fv.Status != IntakeValid {
		t.Fatalf("alias in text status = %q, want VALID", fv.Status)
	}

	// Alias that is only the primary ID restated: alias/canonical mismatch.
	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Aliases:          []string{"cve-2099-0001"},
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "aliases"); fv.Status != IntakeConflicting {
		t.Fatalf("alias restating canonical ID status = %q, want CONFLICTING", fv.Status)
	}

	// Hallucinated alias: valid format, nowhere in text or advisory.
	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Aliases:          []string{"GHSA-aaaa-bbbb-cccc"},
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "aliases"); fv.Status != IntakeUnverified {
		t.Fatalf("hallucinated alias status = %q, want UNVERIFIED", fv.Status)
	}
}

func TestIntakeValidationPackageFromText(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Package:       "example.org/library/parser",
		Version:       "1.4.2",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "package"); fv.Status != IntakeValid {
		t.Fatalf("package in text status = %q, want VALID", fv.Status)
	}
	if fv := fieldStatus(t, v, "version"); fv.Status != IntakeValid {
		t.Fatalf("version in text status = %q, want VALID", fv.Status)
	}
}

func TestIntakeValidationPackageHallucinated(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 reported by scanner.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Package:       "example.org/library/not-in-text",
		Version:       "9.9.9",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "package"); fv.Status != IntakeUnverified {
		t.Fatalf("invented package status = %q, want UNVERIFIED", fv.Status)
	}
	if fv := fieldStatus(t, v, "version"); fv.Status != IntakeUnverified {
		t.Fatalf("invented version status = %q, want UNVERIFIED", fv.Status)
	}
}

func TestIntakeValidationPackageMissing(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion}, nil, Catalog{})
	fv := fieldStatus(t, v, "package")
	if fv.Status != IntakeUnavailable {
		t.Fatalf("absent optional package status = %q, want UNAVAILABLE", fv.Status)
	}
	if fv.BlocksRiskReduction {
		t.Fatal("absent optional package is a limitation, not a negative fact")
	}
}

// package@version appearing verbatim in the document conflicts with a
// different proposed version: CONFLICTING, never silent selection.
func TestIntakeValidationPackageVersionConflict(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 in module example.org/library/parser@1.4.2.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Package:          "example.org/library/parser",
		Version:          "2.0.0",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "version"); fv.Status != IntakeConflicting {
		t.Fatalf("version status = %q, want CONFLICTING (parser@1.4.2 in text)", fv.Status)
	}
}

// A PURL package carries its own ecosystem/name/version; a disagreeing
// version field makes the package CONFLICTING.
func TestIntakeValidationPURLConflict(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 in pkg:golang/example.org/library/parser@1.4.2.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Package:          "pkg:golang/example.org/library/parser@1.4.2",
		Version:          "2.0.0",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "package"); fv.Status != IntakeConflicting {
		t.Fatalf("PURL package vs version status = %q, want CONFLICTING", fv.Status)
	}

	// Consistent PURL: name found in text, version agrees → VALID pair.
	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Package:          "pkg:golang/example.org/library/parser@1.4.2",
		Version:          "1.4.2",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "package"); fv.Status != IntakeValid {
		t.Fatalf("consistent PURL package status = %q, want VALID (reason %q)", fv.Status, fv.Reason)
	}
}

func TestIntakeValidationPURLMalformed(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 somewhere.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Package:          "pkg:golang@1.2.3",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "package"); fv.Status != IntakeInvalid {
		t.Fatalf("malformed PURL status = %q, want INVALID", fv.Status)
	}
}

// PURL ecosystem must agree with the matched catalog entry's ecosystem.
func TestIntakeValidationPURLEcosystemConflict(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 in pkg:maven/example/parser@1.4.2, component parser.")
	catalog := Catalog{Entries: []CatalogEntry{
		{ID: "parser", Ecosystem: "go", Aliases: []string{"parser"}},
	}}
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Package:          "pkg:maven/example/parser@1.4.2",
		Component:        "parser",
	}, nil, catalog)
	if fv := fieldStatus(t, v, "component"); fv.Status != IntakeConflicting {
		t.Fatalf("PURL ecosystem vs catalog status = %q, want CONFLICTING", fv.Status)
	}
}

func TestIntakeValidationComponentMatch(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Component:     "parser-lib",
		Product:       "Example Service",
	}, nil, testCatalog())
	if fv := fieldStatus(t, v, "component"); fv.Status != IntakeValid {
		t.Fatalf("component matched by alias status = %q, want VALID (reason %q)", fv.Status, fv.Reason)
	}
	if fv := fieldStatus(t, v, "product"); fv.Status != IntakeValid {
		t.Fatalf("product matched by id status = %q, want VALID (reason %q)", fv.Status, fv.Reason)
	}
}

// Two entries expose the same normalized locator name "parser": an
// ambiguous catalog match is CONFLICTING, never a silent selection.
func TestIntakeValidationComponentAmbiguous(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Component:     "parser",
	}, nil, testCatalog())
	fv := fieldStatus(t, v, "component")
	if fv.Status != IntakeConflicting {
		t.Fatalf("ambiguous component status = %q, want CONFLICTING", fv.Status)
	}
	if !fv.BlocksRiskReduction {
		t.Fatal("CONFLICTING component must block risk reduction")
	}
}

func TestIntakeValidationComponentUnknown(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Component:     "nonexistent-thing",
	}, nil, testCatalog())
	if fv := fieldStatus(t, v, "component"); fv.Status != IntakeUnverified {
		t.Fatalf("unmatched component status = %q, want UNVERIFIED", fv.Status)
	}
	// An absent component is UNAVAILABLE, never a negative fact.
	v = ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion}, nil, testCatalog())
	if fv := fieldStatus(t, v, "component"); fv.Status != IntakeUnavailable {
		t.Fatalf("absent component status = %q, want UNAVAILABLE", fv.Status)
	}
}

func TestIntakeValidationSeverity(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText) // "Severity: high"
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Severity:      "high",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "severity"); fv.Status != IntakeValid {
		t.Fatalf("severity matching text status = %q, want VALID", fv.Status)
	}

	// LLM raising severity above the authoritative text claim is rejected.
	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Severity:      "critical",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "severity"); fv.Status != IntakeConflicting {
		t.Fatalf("severity above advisory status = %q, want CONFLICTING", fv.Status)
	}

	// Silent downgrades are rejected too: mismatch either way conflicts.
	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Severity:      "low",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "severity"); fv.Status != IntakeConflicting {
		t.Fatalf("severity below advisory status = %q, want CONFLICTING", fv.Status)
	}

	// No severity anywhere: LLM claim stays UNVERIFIED.
	raw = mustIntakeRecord(t, "CVE-2099-0001 in parser, no rating given.")
	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Severity:      "medium",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "severity"); fv.Status != IntakeUnverified {
		t.Fatalf("unlabeled severity status = %q, want UNVERIFIED", fv.Status)
	}
}

func TestIntakeValidationSeverityInvalid(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Severity:      "catastrophic",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "severity"); fv.Status != IntakeInvalid {
		t.Fatalf("unknown severity token status = %q, want INVALID", fv.Status)
	}
}

func TestIntakeValidationReleaseAndGoVersion(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText) // release 2026.10, go1.25.1
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Release:       "2026.10",
		GoVersion:     "go1.25.1",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "release"); fv.Status != IntakeValid {
		t.Fatalf("release status = %q, want VALID", fv.Status)
	}
	if fv := fieldStatus(t, v, "go_version"); fv.Status != IntakeValid {
		t.Fatalf("go_version status = %q, want VALID", fv.Status)
	}

	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Release:       "not a release!!",
		GoVersion:     "go2.0",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "release"); fv.Status != IntakeUnverified {
		t.Fatalf("bad release marker status = %q, want UNVERIFIED limitation", fv.Status)
	}
	if fv := fieldStatus(t, v, "go_version"); fv.Status != IntakeInvalid {
		t.Fatalf("bad go_version syntax status = %q, want INVALID", fv.Status)
	}

	v = ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Release:       "2030.01",
		GoVersion:     "go1.99.9",
	}, nil, Catalog{})
	if fv := fieldStatus(t, v, "release"); fv.Status != IntakeUnverified {
		t.Fatalf("release absent from text status = %q, want UNVERIFIED", fv.Status)
	}
	if fv := fieldStatus(t, v, "go_version"); fv.Status != IntakeUnverified {
		t.Fatalf("go_version absent from text status = %q, want UNVERIFIED", fv.Status)
	}
}

// Source hints that match a catalog entry id are confirmed by the catalog;
// anything else stays an LLM-only candidate.
func TestIntakeValidationSourceHints(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		SourceHints:   []string{"example-service", "invented-source"},
	}, nil, testCatalog())
	fields := v.FieldsNamed("source_hints")
	if len(fields) != 2 {
		t.Fatalf("source_hints fields = %d, want 2", len(fields))
	}
	if fields[0].Status != IntakeValid {
		t.Fatalf("catalog source hint status = %q, want VALID", fields[0].Status)
	}
	if fields[1].Status != IntakeUnverified {
		t.Fatalf("invented source hint status = %q, want UNVERIFIED", fields[1].Status)
	}
}

// Field-level provenance: every field has a deterministic status and a
// provenance trail naming where the value was confirmed (or only proposed).
func TestProvenanceAndStatusCoverage(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"},
		Aliases:          []string{"GHSA-xxxx-yyyy-zzzz"},
		Package:          "example.org/library/parser",
		Version:          "1.4.2",
		Component:        "parser-lib",
		Product:          "Example Service",
		Release:          "2026.10",
		GoVersion:        "go1.25.1",
		Severity:         "high",
		Summary:          "LLM-written summary",
		SourceHints:      []string{"example-service"},
		RefHint:          "v2026.10",
	}, []string{"CVE-2099-0001"}, testCatalog())
	if len(v.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", v.Errors)
	}
	for _, fv := range v.Fields {
		switch fv.Status {
		case IntakeValid, IntakeUnverified, IntakeConflicting, IntakeInvalid, IntakeUnavailable:
		default:
			t.Fatalf("field %q has unknown status %q", fv.Field, fv.Status)
		}
		if fv.Status == IntakeValid && len(fv.Provenance) == 0 {
			t.Fatalf("VALID field %q lacks provenance", fv.Field)
		}
	}
	if fv := fieldStatus(t, v, "vulnerability_ids"); !containsStr(fv.Provenance, "raw_text") {
		t.Fatalf("raw-text provenance expected, got %v", fv.Provenance)
	}
	// LLM prose is never self-confirming.
	if fv := fieldStatus(t, v, "summary"); fv.Status != IntakeUnverified {
		t.Fatalf("summary status = %q, want UNVERIFIED", fv.Status)
	}
	if fv := fieldStatus(t, v, "ref_hint"); fv.Status != IntakeUnverified {
		t.Fatalf("ref_hint status = %q, want UNVERIFIED", fv.Status)
	}
	// UNVERIFIED decision-relevant fields surface as limitations.
	if len(v.Limitations) == 0 {
		t.Fatal("expected limitations for UNVERIFIED fields")
	}
}

// The whole point of §4.2: nothing non-VALID can prop up DISMISSED/LOWERED.
func TestProvenanceBlocksRiskReduction(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-9999"}, // well-formed, hallucinated
		Severity:         "critical",                // contradicts text "high"
	}, nil, Catalog{})
	for _, fv := range v.Fields {
		if fv.Status != IntakeValid && fv.Status != IntakeUnavailable && !fv.BlocksRiskReduction {
			t.Fatalf("field %q status %q must block risk reduction", fv.Field, fv.Status)
		}
	}
}

func TestIntakeValidationAliasCanonicalIDWithoutAdvisory(t *testing.T) {
	raw := mustIntakeRecord(t, "GO-2026-5029 affects example service component.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion,
		Aliases:       []string{"GO-2026-5029", "CVE-2026-25681"},
		Component:     "example service",
	}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
	fv := fieldStatus(t, v, "vulnerability_ids")
	if fv.Status != IntakeValid || !containsStr(fv.Provenance, "raw_text") {
		t.Fatalf("alias-promoted id = %+v, want VALID/raw_text", fv)
	}
	if len(v.Errors) != 0 {
		t.Fatalf("text-confirmed id must not require advisory: %v", v.Errors)
	}
}

func TestIntakeValidationReleaseMarkerIsLimitation(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 affects example service, release type RELEASE.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"}, Component: "example service", Release: "RELEASE",
	}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
	if fv := fieldStatus(t, v, "release"); fv.Status != IntakeUnverified {
		t.Fatalf("release marker = %q, want UNVERIFIED", fv.Status)
	}
	if len(v.Errors) != 0 {
		t.Fatalf("release marker must not be fatal: %v", v.Errors)
	}
}

func TestIntakeValidationComponentVersionNormalization(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 affects TRACKER 6.5.0.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: []string{"CVE-2099-0001"}, Component: "TRACKER 6.5.0",
	}, nil, Catalog{Entries: []CatalogEntry{{ID: "TRACKER"}}})
	if fv := fieldStatus(t, v, "component"); fv.Status != IntakeValid {
		t.Fatalf("component = %+v, want catalog VALID", fv)
	}
	fv := fieldStatus(t, v, "component_version")
	if fv.Value != "6.5.0" || !containsStr(fv.Provenance, "llm_normalization") {
		t.Fatalf("component_version = %+v, want 6.5.0/llm_normalization", fv)
	}
}

func TestIntakeValidationUnknownIDIsLimitation(t *testing.T) {
	raw := mustIntakeRecord(t, "example service reports a vulnerability.")
	v := ValidateIntakeProposal(raw, IntakeProposal{
		SchemaVersion: IntakeProposalSchemaVersion, VulnerabilityIDs: []string{"CVE-2099-0001"}, Component: "example service",
	}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
	if fv := fieldStatus(t, v, "vulnerability_ids"); fv.Status != IntakeUnverified || len(v.Errors) != 0 {
		t.Fatalf("unknown id should be limitation: field=%+v errors=%v", fv, v.Errors)
	}
}

func TestIntakeValidationNoIDIsFatal(t *testing.T) {
	raw := mustIntakeRecord(t, "example service report with no vulnerability identifier.")
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion, Component: "example service"}, nil, Catalog{})
	if len(v.Errors) == 0 {
		t.Fatal("missing all vulnerability IDs must be fatal")
	}
}

func TestIntakeValidationConfirmedAliasPriority(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		want string
	}{
		{"cve-ghsa-go", []string{"CVE-2099-0001", "GHSA-aaaa-bbbb-cccc", "GO-2099-0001"}, "CVE-2099-0001"},
		{"ghsa-go", []string{"GHSA-aaaa-bbbb-cccc", "GO-2099-0001"}, "GHSA-aaaa-bbbb-cccc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustIntakeRecord(t, strings.Join(tc.ids, " is one advisory alias "))
			v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion, VulnerabilityIDs: tc.ids, Component: "example-service"}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
			fv := fieldStatus(t, v, "vulnerability_ids")
			if fv.Status != IntakeValid || fv.Value != tc.want || len(fv.Aliases) != len(tc.ids)-1 || len(v.Errors) != 0 {
				t.Fatalf("validation = %+v errors=%v, want primary %s and aliases", fv, v.Errors, tc.want)
			}
		})
	}
}

func TestIntakeValidationConfirmedSameClassConflicts(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 and CVE-2099-0002 affect example-service")
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion, VulnerabilityIDs: []string{"CVE-2099-0001", "CVE-2099-0002"}, Component: "example-service"}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
	if fv := fieldStatus(t, v, "vulnerability_ids"); fv.Status != IntakeConflicting || len(v.Errors) != 0 {
		t.Fatalf("same-class IDs = %+v errors=%v, want CONFLICTING limitation", fv, v.Errors)
	}
}

func TestIntakeValidationPackagePathNormalization(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 affects github.com/rabbitmq/amqp091-go 1.10.0 in example-service")
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion, VulnerabilityIDs: []string{"CVE-2099-0001"}, Package: "amqp091-go", Component: "example-service"}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
	fv := fieldStatus(t, v, "package")
	if fv.Status != IntakeValid || fv.Value != "github.com/rabbitmq/amqp091-go" || !containsStr(fv.Provenance, "raw_text") {
		t.Fatalf("normalized package = %+v, want VALID github.com/rabbitmq/amqp091-go/raw_text", fv)
	}
}

func TestIntakeValidationPackageAmbiguousPath(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 affects github.com/a/parser and gitlab.com/b/parser")
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion, VulnerabilityIDs: []string{"CVE-2099-0001"}, Package: "parser"}, nil, Catalog{})
	fv := fieldStatus(t, v, "package")
	if fv.Status != IntakeUnverified || !strings.HasPrefix(fv.Value, "ambiguous:") || !containsStr(v.Limitations, "package") {
		t.Fatalf("ambiguous package = %+v limitations=%v", fv, v.Limitations)
	}
}

func TestIntakeValidationPackageAlreadyFullPath(t *testing.T) {
	raw := mustIntakeRecord(t, "CVE-2099-0001 affects github.com/docker/docker v28.0.1")
	v := ValidateIntakeProposal(raw, IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion, VulnerabilityIDs: []string{"CVE-2099-0001"}, Package: "github.com/docker/docker"}, nil, Catalog{Entries: []CatalogEntry{{ID: "example-service"}}})
	fv := fieldStatus(t, v, "package")
	if fv.Status != IntakeValid || fv.Value != "github.com/docker/docker" {
		t.Fatalf("full path package = %+v", fv)
	}
}

// TestHintFieldsDoNotBlockReduction pins the structural optionality rule:
// an unverified hint (summary, source/ref hints, a version split out of a
// component name) is a limitation, never a gate, while an unverified
// decision field (package/version) still blocks.
func TestHintFieldsDoNotBlockReduction(t *testing.T) {
	var fields []FieldValidation
	for _, name := range []string{"summary", "source_hints", "ref_hint", "go_version", "component_version", "product_version", "release", "severity", "aliases"} {
		fields = append(fields, FieldValidation{Field: name, Status: IntakeUnverified})
	}
	fields = append(fields, FieldValidation{Field: "package", Status: IntakeUnverified})
	in := CheckInput{Stage0: Stage0Result{Validation: IntakeValidation{Fields: fields}}}
	res := checkFieldProvenance(context.Background(), in)
	if res.Status != CheckUnverified {
		t.Fatalf("status = %s (want UNVERIFIED from the required field only)", res.Status)
	}
	hintNotes := 0
	for _, r := range res.Reasons {
		if strings.Contains(r, "(hint, optional)") {
			hintNotes++
		}
	}
	if hintNotes != 9 {
		t.Fatalf("hint notes = %d reasons=%v", hintNotes, res.Reasons)
	}

	// Without the required field the same hints pass the gate.
	in.Stage0.Validation.Fields = fields[:9]
	if res := checkFieldProvenance(context.Background(), in); res.Status != CheckPass {
		t.Fatalf("hints gated the check: %s %v", res.Status, res.Reasons)
	}
}
