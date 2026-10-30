package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/google/jsonschema-go/jsonschema"
)

// This file is the export reason matrix. It drives every admitted proof that
// can close a vulnerability through both rendering paths — the legacy
// single-assessment exporters and the requested-finding projection — and
// asserts the OpenVEX and CycloneDX justification each proof supports. It also
// validates the resulting documents against the official schemas: vocabulary
// assertions alone cannot catch a structurally invalid statement.

type exportReason struct {
	vexStatus        string
	vexJustification string
	vexText          string
	cdxState         string
	cdxJustification string
	cdxText          string
}

func decodeExportReason(t *testing.T, vexRaw, cdxRaw []byte) exportReason {
	t.Helper()
	var vex struct {
		Statements []struct {
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(vexRaw, &vex); err != nil {
		t.Fatalf("invalid OpenVEX json: %v", err)
	}
	if len(vex.Statements) != 1 {
		t.Fatalf("OpenVEX statements = %d, want 1", len(vex.Statements))
	}
	var cdx struct {
		Vulnerabilities []struct {
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
				Detail        string `json:"detail"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(cdxRaw, &cdx); err != nil {
		t.Fatalf("invalid CycloneDX json: %v", err)
	}
	if len(cdx.Vulnerabilities) != 1 {
		t.Fatalf("CycloneDX vulnerabilities = %d, want 1", len(cdx.Vulnerabilities))
	}
	st := vex.Statements[0]
	an := cdx.Vulnerabilities[0].Analysis
	return exportReason{
		vexStatus:        st.Status,
		vexJustification: st.Justification,
		vexText:          st.ImpactStatement + " " + st.ActionStatement,
		cdxState:         an.State,
		cdxJustification: an.Justification,
		cdxText:          an.Detail,
	}
}

// renderLegacyReason drives OpenVEX and CycloneDX through the historical
// single-assessment path.
func renderLegacyReason(t *testing.T, c *domain.AnalysisCase) exportReason {
	t.Helper()
	vexRaw, err := OpenVEX(c)
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	cdxRaw, err := CycloneDX(c)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	return decodeExportReason(t, vexRaw, cdxRaw)
}

// renderProjectedReason drives the requested-finding projection directly. The
// matrix constructs the publication it wants to render; re-admission itself is
// covered by the requested-finding and measurement-admission suites.
func renderProjectedReason(t *testing.T, pub publication) exportReason {
	t.Helper()
	vexRaw, err := openVEXProjected(pub)
	if err != nil {
		t.Fatalf("projected OpenVEX: %v", err)
	}
	cdxRaw, err := cycloneDXProjected(pub)
	if err != nil {
		t.Fatalf("projected CycloneDX: %v", err)
	}
	return decodeExportReason(t, vexRaw, cdxRaw)
}

func matrixBaseCase(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	return &domain.AnalysisCase{
		ID: "matrix-case",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2024-0001",
			Module: "example.com/dep",
		},
		Product: admissionScopedProduct(),
		Affected: &domain.AffectedResult{
			Scope:           exactEntryScope("GO-2024-0001"),
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
	}
}

func matrixNotAffected(t *testing.T, reason string) *domain.AnalysisCase {
	t.Helper()
	c := matrixBaseCase(t)
	c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictNotAffected, Reason: reason}
	return c
}

// matrixNoExploitPath builds a re-admittable negative whose grounding claim
// carries the given falsifier. The trust-grounded routes are independent
// deployment facts; every other falsifier is a build-selected measurement, so
// the fixture gives it the scoped target and matching verification context the
// admission gate requires.
func matrixNoExploitPath(t *testing.T, falsifier, basis string, evidence ...domain.Evidence) *domain.AnalysisCase {
	t.Helper()
	c := matrixBaseCase(t)
	ctx := admissionContext(c.Product)
	claim := domain.Claim{
		ID:             "CL-C-REACH",
		ConditionID:    "C-REACH",
		Result:         domain.ClaimFalse,
		Falsifier:      falsifier,
		FalsifierBasis: basis,
		Explanation:    "verified proof: " + falsifier,
		NegativeVerification: &domain.NegativeVerification{
			Status:       domain.NegativeVerified,
			BuildContext: ctx,
			Notes:        "matrix fixture",
		},
	}
	c.Exploit = &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
	}}}
	c.Claims = []domain.Claim{claim}
	c.Verdict = &domain.VerdictResult{
		Verdict:      domain.VerdictNoExploitPathFound,
		Reason:       "mandatory exploit condition is proven false",
		ConditionIDs: []domain.ConditionID{"C-REACH"},
		GroundBasis:  basis,
	}
	if falsifier == domain.FalsifierTrustedInfrastructure &&
		(basis == "" || basis == domain.BasisDeclaredTrust || basis == domain.BasisAutoPerimeter) {
		// An operator/deployment assertion needs no build measurement.
		c.Claims[0].NegativeVerification.BuildContext = nil
	}
	c.EvidenceGraph.Evidence = evidence
	return c
}

func matrixSourceScan(product domain.ProductSnapshot) domain.Evidence {
	ctx := admissionContext(product)
	return domain.Evidence{
		ID:           "EV-SCAN-MATRIX",
		Kind:         domain.EvidenceSourceScan,
		BuildContext: ctx,
		SourceScan: &domain.SourceScanRun{
			Module:       "example.com/dep",
			Subjects:     []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
			EntrySymbols: []string{"example.com/prod.main"},
			Completed:    true,
			Complete:     true,
		},
	}
}

// matrixPublication wraps one record as the requested finding so the projected
// renderer is exercised with the same proof the legacy renderer sees.
func matrixPublication(t *testing.T, c *domain.AnalysisCase) publication {
	t.Helper()
	if c.Verdict == nil {
		t.Fatal("matrix fixture has no verdict")
	}
	req := domain.RequestedFinding{
		RequestedID: c.Vulnerability.ID,
		FindingProfile: domain.FindingProfile{
			Outcome: domain.OutcomeDecided,
			Verdict: c.Verdict.Verdict,
			Reason:  c.Verdict.Reason,
		},
	}
	return publication{
		requested: &req,
		primary:   c,
		records:   []*domain.AnalysisCase{c},
	}
}

func TestOpenVEXCycloneDXReasonMatrix(t *testing.T) {
	tests := []struct {
		name      string
		build     func(t *testing.T) *domain.AnalysisCase
		wantVex   string
		wantCDX   string
		wantProof string
	}{
		{
			name: "component absent",
			build: func(t *testing.T) *domain.AnalysisCase {
				c := matrixNotAffected(t, "vulnerable module is not part of the product dependency graph")
				c.Affected.ModulePresent = domain.ClaimFalse
				return c
			},
			wantVex:   "component_not_present",
			wantCDX:   "code_not_present",
			wantProof: "not part of the product dependency graph",
		},
		{
			name: "version out of range",
			build: func(t *testing.T) *domain.AnalysisCase {
				c := matrixNotAffected(t, "resolved version v1.0.0 is outside the affected range")
				c.Affected.VersionAffected = domain.ClaimFalse
				return c
			},
			wantVex:   "vulnerable_code_not_present",
			wantCDX:   "code_not_present",
			wantProof: "outside the affected range",
		},
		{
			name: "package exclusion",
			build: func(t *testing.T) *domain.AnalysisCase {
				c := matrixNotAffected(t, "affected package is not imported by the product build")
				c.Affected.PackagePresent = domain.ClaimFalse
				c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, admissionPackageList(c.Product))
				return c
			},
			wantVex:   "vulnerable_code_not_present",
			wantCDX:   "code_not_present",
			wantProof: "not imported by the product build",
		},
		{
			name: "build exclusion",
			build: func(t *testing.T) *domain.AnalysisCase {
				c := matrixNotAffected(t, "affected packages are constrained to other platforms/build configurations")
				c.Affected.BuildRelevant = domain.ClaimFalse
				return c
			},
			wantVex:   "vulnerable_code_not_present",
			wantCDX:   "code_not_present",
			wantProof: "other platforms/build configurations",
		},
		{
			name: "implementation absence",
			build: func(t *testing.T) *domain.AnalysisCase {
				c := matrixNotAffected(t, "the vulnerable implementation is deterministically absent from the product build")
				c.Affected.VulnerableImplementationPresent = domain.ClaimFalse
				return c
			},
			wantVex:   "vulnerable_code_not_present",
			wantCDX:   "code_not_present",
			wantProof: "deterministically absent from the product build",
		},
		{
			name: "unreachability",
			build: func(t *testing.T) *domain.AnalysisCase {
				c := matrixNoExploitPath(t, domain.FalsifierLocusFunctionUnreached, "")
				build := domain.EffectiveBuildContext(c.Product)
				res := goanalysis.UnreachabilityResult{
					Module:   "example.com/dep",
					Subjects: []goanalysis.UnreachabilitySubject{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
					Build:    build,
					Inventory: affected.RecordPackageInventory(
						[]byte(`{"ImportPath":"example.com/prod"}`),
						nil,
						c.Product,
						false,
					),
					ProductPackages:     []string{"example.com/prod"},
					Complete:            true,
					DeclarationComplete: true,
					EntrypointComplete:  true,
					ModuleEntryComplete: true,
					ModuleReachComplete: true,
				}
				raw, _ := json.Marshal(res)
				kernel := domain.Evidence{
					ID:           "EV-KERNEL-MATRIX",
					Kind:         domain.EvidenceSourceSnippet,
					BuildContext: &build,
					Content:      string(raw),
				}
				c.Claims[0].NegativeVerification.EvidenceIDs = []domain.EvidenceID{kernel.ID}
				c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, matrixSourceScan(c.Product), kernel)
				return c
			},
			wantVex:   "vulnerable_code_not_in_execute_path",
			wantCDX:   "code_not_reachable",
			wantProof: "verified proof: locus-function-unreached",
		},
		{
			name: "constant input",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierConstantOrGeneratedInput, "")
			},
			wantVex:   "vulnerable_code_cannot_be_controlled_by_adversary",
			wantCDX:   "",
			wantProof: "verified proof: constant-or-generated-input",
		},
		{
			name: "configuration",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierConfigGatedOff, "")
			},
			wantVex:   "",
			wantCDX:   "requires_configuration",
			wantProof: "verified proof: config-feature-disabled",
		},
		{
			name: "environment",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierProtocolRoleMismatch, "")
			},
			wantVex:   "",
			wantCDX:   "requires_environment",
			wantProof: "verified proof: protocol-role-mismatch",
		},
		{
			name: "guards",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierGuards, "")
			},
			wantVex:   "vulnerable_code_cannot_be_controlled_by_adversary",
			wantCDX:   "protected_by_mitigating_control",
			wantProof: "verified proof: guards",
		},
		{
			name: "loopback perimeter",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierLoopbackOnly, "")
			},
			wantVex:   "vulnerable_code_cannot_be_controlled_by_adversary",
			wantCDX:   "protected_at_perimeter",
			wantProof: "verified proof: loopback-only",
		},
		{
			name: "declared trust boundary",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierTrustedInfrastructure, domain.BasisDeclaredTrust)
			},
			wantVex:   "vulnerable_code_cannot_be_controlled_by_adversary",
			wantCDX:   "protected_at_perimeter",
			wantProof: "declared deployment trust boundary",
		},
		{
			name: "auto-detected perimeter",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierTrustedInfrastructure, domain.BasisAutoPerimeter)
			},
			wantVex:   "vulnerable_code_cannot_be_controlled_by_adversary",
			wantCDX:   "protected_at_perimeter",
			wantProof: "auto-detected cluster-internal perimeter",
		},
		{
			name: "config-origin trust basis",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, domain.FalsifierTrustedInfrastructure, domain.BasisConfigOrigin)
			},
			wantVex:   "vulnerable_code_cannot_be_controlled_by_adversary",
			wantCDX:   "protected_by_mitigating_control",
			wantProof: "administrator-managed configuration",
		},
		{
			name: "unrecognized proof",
			build: func(t *testing.T) *domain.AnalysisCase {
				return matrixNoExploitPath(t, "unrecognized-proof", "")
			},
			// No enum truthfully describes this proof: neither exporter may
			// turn it into an absence or unreachability assertion.
			wantVex:   "",
			wantCDX:   "",
			wantProof: "verified proof: unrecognized-proof",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.build(t)
			for _, path := range []struct {
				name   string
				render func() exportReason
			}{
				{"legacy", func() exportReason { return renderLegacyReason(t, c) }},
				{"projected", func() exportReason { return renderProjectedReason(t, matrixPublication(t, c)) }},
			} {
				got := path.render()
				if got.vexStatus != "not_affected" || got.cdxState != "not_affected" {
					t.Fatalf("%s: status = %q/%q, want not_affected (vex text: %q; cdx detail: %q)",
						path.name, got.vexStatus, got.cdxState, got.vexText, got.cdxText)
				}
				if got.vexJustification != tc.wantVex {
					t.Errorf("%s: OpenVEX justification = %q, want %q", path.name, got.vexJustification, tc.wantVex)
				}
				if got.cdxJustification != tc.wantCDX {
					t.Errorf("%s: CycloneDX justification = %q, want %q", path.name, got.cdxJustification, tc.wantCDX)
				}
				if !strings.Contains(got.vexText, tc.wantProof) {
					t.Errorf("%s: OpenVEX statement lacks the admitted proof %q: %q", path.name, tc.wantProof, got.vexText)
				}
				if !strings.Contains(got.cdxText, tc.wantProof) {
					t.Errorf("%s: CycloneDX detail lacks the admitted proof %q: %q", path.name, tc.wantProof, got.cdxText)
				}
			}
		})
	}
}

// corpusChild builds one corpus candidate with the affected fact that earned
// its NOT_AFFECTED result.
func corpusChild(t *testing.T, id string, affected domain.AffectedResult) *domain.AnalysisCase {
	t.Helper()
	c := matrixBaseCase(t)
	c.ID = domain.CaseID("corpus-" + id)
	c.Vulnerability.ID = id
	c.Affected = &affected
	c.Affected.Scope = exactEntryScope(id)
	c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictNotAffected, Reason: "candidate proved unaffected"}
	pin := reportPin(id)
	c.RecordPin = &pin
	return c
}

func corpusPublication(t *testing.T, basis *domain.CorpusNegativeBasis, records ...*domain.AnalysisCase) publication {
	t.Helper()
	primary := matrixBaseCase(t)
	primary.Vulnerability.ID = "CVE-2024-0001"
	primary.Verdict = &domain.VerdictResult{Verdict: domain.VerdictNotAffected, Reason: "corpus negative"}
	req := domain.RequestedFinding{
		RequestedID: "CVE-2024-0001",
		FindingProfile: domain.FindingProfile{
			Outcome:             domain.OutcomeDecided,
			Verdict:             domain.VerdictNotAffected,
			Reason:              "corpus negative",
			CorpusNegativeBasis: basis,
		},
	}
	pub := publication{requested: &req, primary: primary, records: []*domain.AnalysisCase{primary}}
	pub.records = append(pub.records, records...)
	return pub
}

func corpusBasis(records ...domain.CorpusAssessedRecord) *domain.CorpusNegativeBasis {
	return &domain.CorpusNegativeBasis{
		Reference:         "matrix-corpus",
		DeclaredDigest:    reportDigest("matrix-corpus"),
		ObservedDigest:    reportDigest("matrix-corpus"),
		CapturedAt:        "2026-10-20",
		Enumeration:       domain.DiscoveryFinished,
		ManifestDigest:    reportDigest("matrix-manifest"),
		AssessedRecords:   records,
		BoundaryStatement: domain.CorpusBoundaryStatement("matrix-corpus", reportDigest("matrix-corpus"), "2026-10-20"),
	}
}

func corpusRecord(c *domain.AnalysisCase) domain.CorpusAssessedRecord {
	return domain.CorpusAssessedRecord{
		Record:  *c.RecordPin,
		Outcome: domain.OutcomeDecided,
		Verdict: domain.VerdictNotAffected,
	}
}

func TestOpenVEXCycloneDXCorpusReasons(t *testing.T) {
	absent := corpusChild(t, "GO-ABSENT", domain.AffectedResult{ModulePresent: domain.ClaimFalse})
	version := corpusChild(t, "GO-VERSION", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		ResolvedVersion: "v0.15.0",
		VersionAffected: domain.ClaimFalse,
	})
	packageAbsent := corpusChild(t, "GO-PACKAGE", domain.AffectedResult{
		ModulePresent:  domain.ClaimTrue,
		PackagePresent: domain.ClaimFalse,
	})
	unrepresentable := corpusChild(t, "GO-UNPROVEN", domain.AffectedResult{ModulePresent: domain.ClaimTrue})

	tests := []struct {
		name    string
		basis   *domain.CorpusNegativeBasis
		records []*domain.AnalysisCase
		wantVex string
		wantCDX string
	}{
		{
			name:    "mixed version and component absence",
			basis:   corpusBasis(corpusRecord(absent), corpusRecord(version)),
			records: []*domain.AnalysisCase{absent, version},
			wantVex: "vulnerable_code_not_present",
			wantCDX: "code_not_present",
		},
		{
			name:    "package exclusion aggregates to vulnerable code absence",
			basis:   corpusBasis(corpusRecord(version), corpusRecord(packageAbsent)),
			records: []*domain.AnalysisCase{version, packageAbsent},
			wantVex: "vulnerable_code_not_present",
			wantCDX: "code_not_present",
		},
		{
			name:    "every candidate proved component absence",
			basis:   corpusBasis(corpusRecord(absent)),
			records: []*domain.AnalysisCase{absent},
			wantVex: "component_not_present",
			wantCDX: "code_not_present",
		},
		{
			name:    "empty corpus invents no absence",
			basis:   corpusBasis(),
			records: nil,
			wantVex: "",
			wantCDX: "",
		},
		{
			name:    "unrepresentable candidate proof invents no absence",
			basis:   corpusBasis(corpusRecord(absent), corpusRecord(unrepresentable)),
			records: []*domain.AnalysisCase{absent, unrepresentable},
			wantVex: "",
			wantCDX: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := renderProjectedReason(t, corpusPublication(t, tc.basis, tc.records...))
			if got.vexStatus != "not_affected" || got.cdxState != "not_affected" {
				t.Fatalf("status = %q/%q, want not_affected", got.vexStatus, got.cdxState)
			}
			if got.vexJustification != tc.wantVex || got.cdxJustification != tc.wantCDX {
				t.Fatalf("justification = %q/%q, want %q/%q",
					got.vexJustification, got.cdxJustification, tc.wantVex, tc.wantCDX)
			}
			if !strings.Contains(got.vexText, "implementations outside this corpus were not examined") {
				t.Fatalf("OpenVEX statement lacks the verbatim corpus boundary: %q", got.vexText)
			}
			if !strings.Contains(got.cdxText, "implementations outside this corpus were not examined") {
				t.Fatalf("CycloneDX detail lacks the verbatim corpus boundary: %q", got.cdxText)
			}
		})
	}
}

func loadOfficialSchema(t *testing.T, name string) *jsonschema.Resolved {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read schema %s: %v", name, err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema %s: %v", name, err)
	}
	// The CycloneDX schema references its SPDX and JSF sub-schemas by URL;
	// resolve those from the vendored copies so the test stays hermetic.
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{
		Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
			local := filepath.Join("testdata", filepath.Base(uri.Path))
			data, err := os.ReadFile(local)
			if err != nil {
				return nil, fmt.Errorf("load referenced schema %s from %s: %w", uri, local, err)
			}
			var referenced jsonschema.Schema
			if err := json.Unmarshal(data, &referenced); err != nil {
				return nil, fmt.Errorf("decode referenced schema %s: %w", uri, err)
			}
			return &referenced, nil
		},
	})
	if err != nil {
		t.Fatalf("resolve schema %s: %v", name, err)
	}
	return resolved
}

func validateOfficialSchema(t *testing.T, schema *jsonschema.Resolved, document []byte) {
	t.Helper()
	var instance any
	if err := json.Unmarshal(document, &instance); err != nil {
		t.Fatalf("decode exported document: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("document does not validate against the official schema: %v\n%s", err, document)
	}
}

func TestOpenVEXCycloneDXOfficialSchemas(t *testing.T) {
	openvexSchema := loadOfficialSchema(t, "openvex-0.2.0.schema.json")
	cyclonedxSchema := loadOfficialSchema(t, "cyclonedx-1.5.schema.json")
	cases := map[string]*domain.AnalysisCase{
		"legacy affected":             vexCase(t, domain.VerdictExploitable),
		"legacy negative":             matrixNotAffected(t, "module absent"),
		"projected composed positive": reportComposedPositive(t),
		"projected corpus negative":   reportCorpusNegative(t),
		"projected exact negative":    reportExactNegative(t),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			vexRaw, err := OpenVEX(c)
			if err != nil {
				t.Fatalf("OpenVEX: %v", err)
			}
			validateOfficialSchema(t, openvexSchema, vexRaw)
			cdxRaw, err := CycloneDX(c)
			if err != nil {
				t.Fatalf("CycloneDX: %v", err)
			}
			validateOfficialSchema(t, cyclonedxSchema, cdxRaw)
		})
	}
}

func TestOpenVEXProductSubcomponentShape(t *testing.T) {
	// A statement-level subcomponents member and a named subcomponent are
	// both invalid OpenVEX; the official schema nests subcomponents under the
	// product and allows only an @id/identifiers there.
	for _, tc := range []struct {
		name string
		pub  *domain.AnalysisCase
	}{
		{"legacy", vexCase(t, domain.VerdictExploitable)},
		{"projected", reportComposedPositive(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := OpenVEX(tc.pub)
			if err != nil {
				t.Fatalf("OpenVEX: %v", err)
			}
			var doc struct {
				Statements []map[string]any `json:"statements"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("invalid OpenVEX json: %v", err)
			}
			for _, statement := range doc.Statements {
				if _, ok := statement["subcomponents"]; ok {
					t.Fatalf("statement-level subcomponents is not valid OpenVEX: %v", statement)
				}
				products, _ := statement["products"].([]any)
				if len(products) == 0 {
					t.Fatalf("statement has no products: %v", statement)
				}
				for _, rawProduct := range products {
					product, _ := rawProduct.(map[string]any)
					subcomponents, ok := product["subcomponents"].([]any)
					if !ok {
						continue
					}
					if len(subcomponents) == 0 {
						t.Fatalf("empty subcomponents array must be omitted: %v", product)
					}
					for _, rawSub := range subcomponents {
						sub, _ := rawSub.(map[string]any)
						if _, ok := sub["name"]; ok {
							t.Fatalf("subcomponent carries the invalid name member: %v", sub)
						}
					}
				}
			}
		})
	}
}

func TestCycloneDXSerialNumberShape(t *testing.T) {
	pattern := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	seen := make(map[string]bool)
	for _, id := range []string{"case-one", "case-two"} {
		c := cdxCase(domain.VerdictInconclusive)
		c.ID = domain.CaseID(id)
		raw, err := CycloneDX(c)
		if err != nil {
			t.Fatalf("%s: CycloneDX: %v", id, err)
		}
		var doc struct {
			SerialNumber string `json:"serialNumber"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: invalid json: %v", id, err)
		}
		if !pattern.MatchString(doc.SerialNumber) {
			t.Fatalf("%s: serialNumber %q is not an RFC-4122 urn:uuid", id, doc.SerialNumber)
		}
		if seen[doc.SerialNumber] {
			t.Fatalf("%s: duplicate serialNumber %q", id, doc.SerialNumber)
		}
		seen[doc.SerialNumber] = true
	}
}
