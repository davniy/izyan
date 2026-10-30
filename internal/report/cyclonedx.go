package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// caseSerialNumber returns the deterministic RFC-4122 UUID the CycloneDX 1.5
// schema requires for serialNumber (pattern
// ^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$).
// It is derived from the case id so regenerating the same case yields the same
// serial number, while the version/variant nibbles make it a well-formed UUID
// rather than an arbitrary identifier in a urn:uuid wrapper.
func caseSerialNumber(id string) string {
	sum := sha256.Sum256([]byte("izyan:case:" + id))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4 (random-shaped, deterministic derivation)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CycloneDX VEX export (spec 1.5). Like the OpenVEX document this is a
// projection of the internal verdict — never a source (spec §25).
//
// Verdict → analysis mapping:
//
//	EXPLOITABLE            → exploitable
//	NOT_AFFECTED           → not_affected + justification selected from the
//	                         affected-chain fact that closed applicability
//	NO_EXPLOIT_PATH_FOUND  → not_affected + justification selected from the
//	                         grounding claim's falsifier (issued only after
//	                         negative verification ran). A proof with no
//	                         exact CycloneDX entry carries the reason in
//	                         analysis.detail instead.
//	INCONCLUSIVE / none    → in_triage + detail
//	refused negative       → in_triage (never not_affected)
//
// A negative is refused when its build target, measurement completion,
// coverage or recorded build context does not admit it; the refusal is
// reported in analysis.detail instead of exporting a clean claim.
type cdxDoc struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []cdxComponent     `json:"components,omitempty"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Component cdxComponent `json:"component,omitempty"`
}

type cdxComponent struct {
	BOMRef string `json:"bom-ref,omitempty"`
	Type   string `json:"type,omitempty"`
	Name   string `json:"name,omitempty"`
	PURL   string `json:"purl,omitempty"`
}

type cdxVulnerability struct {
	ID       string      `json:"id"`
	Source   cdxSource   `json:"source"`
	Affects  []cdxAffect `json:"affects,omitempty"`
	Analysis cdxAnalysis `json:"analysis"`
	// Recommendation carries the witness-bound remediation in the schema's
	// own recommendation field, so the fix is a first-class member rather
	// than prose buried in analysis.detail.
	Recommendation string `json:"recommendation,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

type cdxAnalysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// CycloneDX renders the case into a CycloneDX VEX document.
//
// A case carrying the requested-finding envelope exports one vulnerability
// entry per published identity — the requested identity, the primary record and
// each candidate record — with the witness records' components in
// `components`/`affects`. External dependencies and analysis failures both map
// to `in_triage`, but analysis.detail distinguishes them and neither ever
// becomes not_affected.
//
// Negative conclusions are re-admitted before projection: a refused
// build-dependent measurement or a refused advisory scope exports as
// in_triage, never as not_affected. A build-dependent negative carries the
// analyzed build's platform, tags, CGO, target provenance and bounded scope
// in analysis.detail.
func CycloneDX(c *domain.AnalysisCase) ([]byte, error) {
	pub := publish(c)
	if pub.refusal != nil {
		return nil, pub.refusal
	}
	if pub.requested != nil {
		return cycloneDXProjected(pub)
	}
	return cycloneDXLegacy(c)
}

// cycloneDXProjected renders the requested-finding projection.
func cycloneDXProjected(pub publication) ([]byte, error) {
	product := productRef(pub.primary.Product)
	entries := exportEntries(pub)
	vulnerabilities := make([]cdxVulnerability, 0, len(entries))
	components := make(map[string]cdxComponent, len(entries))
	for _, entry := range entries {
		state := pub.exportStateFor(entry)
		affects := []cdxAffect{{Ref: product}}
		for _, component := range pub.exportComponents(entry, state) {
			components[component.PURL] = cdxComponent{
				BOMRef: component.PURL,
				Type:   "library",
				Name:   component.Name,
				PURL:   component.PURL,
			}
			affects = append(affects, cdxAffect{Ref: component.PURL})
		}
		detail := state.Explanation
		if state.Status == "under_investigation" && state.Action != "" {
			// The state alone cannot distinguish an external dependency from
			// a failure; the detail must.
			detail = joinStatements(detail, state.Action)
		}
		analysis := cdxAnalysis{State: state.State, Detail: detail}
		if state.State == "not_affected" {
			// CycloneDX defines justification only for not_affected.
			analysis.Justification = state.CDXJustification
		}
		recommendation := ""
		if state.State == "exploitable" {
			recommendation = state.Action
		}
		vulnerabilities = append(vulnerabilities, cdxVulnerability{
			ID:             entry.Identity,
			Source:         cdxSource{Name: vulnSourceName(entry.Identity), URL: vulnRef(entry.Identity)},
			Affects:        dedupeAffects(affects),
			Analysis:       analysis,
			Recommendation: recommendation,
		})
	}
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: caseSerialNumber(string(pub.primary.ID)),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: vexTimestamp(pub.primary),
			Component: cdxComponent{
				BOMRef: product,
				Type:   "application",
				Name:   product,
				PURL:   product,
			},
		},
		Vulnerabilities: vulnerabilities,
	}
	if len(components) > 0 {
		refs := make([]string, 0, len(components))
		for ref := range components {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		doc.Components = make([]cdxComponent, 0, len(refs))
		for _, ref := range refs {
			doc.Components = append(doc.Components, components[ref])
		}
	}
	return json.MarshalIndent(doc, "", "  ")
}

// vulnSourceName names the advisory source of an exported identity.
func vulnSourceName(id string) string {
	if strings.HasPrefix(id, "GO-") {
		return "Go Vulnerability Database"
	}
	return "OSV"
}

// dedupeAffects keeps the first occurrence of each bom-ref in order.
func dedupeAffects(affects []cdxAffect) []cdxAffect {
	seen := make(map[string]bool, len(affects))
	out := make([]cdxAffect, 0, len(affects))
	for _, affect := range affects {
		if affect.Ref == "" || seen[affect.Ref] {
			continue
		}
		seen[affect.Ref] = true
		out = append(out, affect)
	}
	return out
}

// cycloneDXLegacy renders a legacy single-assessment case. It has no requested
// finding to project, so it keeps the historical vulnerability entry exactly.
func cycloneDXLegacy(c *domain.AnalysisCase) ([]byte, error) {
	buildScope := ""
	if negativeUsesBuildContext(c) {
		buildScope = buildScopeStatement(c)
	}
	c = admitNegativeConclusions(c).Case
	product := productRef(c.Product)
	var comp *cdxComponent
	var affects []cdxAffect
	if c.Vulnerability.Module != "" {
		purl := "pkg:golang/" + c.Vulnerability.Module
		if v := resolvedVersion(c); v != "" {
			purl += "@" + v
		}
		comp = &cdxComponent{
			BOMRef: purl,
			Type:   "library",
			Name:   c.Vulnerability.Module,
			PURL:   purl,
		}
		affects = []cdxAffect{{Ref: product}}
	}
	reason := ""
	var verdict domain.Verdict
	if c.Verdict != nil {
		verdict = c.Verdict.Verdict
		reason = c.Verdict.Reason
	}
	// See OpenVEX: admission above already demoted a refused negative to
	// INCONCLUSIVE, so this switch can only reach not_affected when the
	// scope and measurement authority survives.
	an := cdxAnalysis{Detail: reason}
	switch verdict {
	case domain.VerdictExploitable:
		an.State = "exploitable"
	case domain.VerdictNotAffected:
		an.State = "not_affected"
		an.Justification = affectedProofJustification(c).CDX
		an.Detail = joinStatements(an.Detail, buildScope)
	case domain.VerdictNoExploitPathFound:
		an.State = "not_affected"
		an.Justification = noExploitPathProof(c).CDX
		if basis := noExploitPathBasis(c); basis != "" {
			an.Detail = reason + " (" + basis + ")"
		}
		an.Detail = joinStatements(an.Detail, buildScope)
	default:
		an.State = "in_triage"
		if an.Detail == "" {
			an.Detail = "analysis inconclusive — manual review required"
		}
		an.Detail = joinStatements(an.Detail, buildScope)
	}
	if libraryAPIScope(c) && (an.State == "exploitable" || an.State == "in_triage") {
		// The existing analysis.detail is the only carrier: no new
		// response/properties schema is introduced for the library scope.
		parts := []string{
			fmt.Sprintf("exploitability_scope=%s", domain.ScopeLibraryAPI),
			fmt.Sprintf("control_basis=%s", domain.ControlBasisLibraryPublicAPI),
			"limitation: " + libraryAPILimitationText(false),
		}
		if scope := libraryScopeStatement(c); scope != "" {
			parts = append(parts, scope)
		}
		if an.Detail != "" {
			parts = append([]string{an.Detail}, parts...)
		}
		an.Detail = strings.Join(parts, "; ")
	}
	source := "OSV"
	if len(c.Vulnerability.ID) >= 3 && c.Vulnerability.ID[:3] == "GO-" {
		source = "Go Vulnerability Database"
	}
	vuln := cdxVulnerability{
		ID:       c.Vulnerability.ID,
		Source:   cdxSource{Name: source, URL: vulnRef(c.Vulnerability.ID)},
		Affects:  affects,
		Analysis: an,
	}
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: caseSerialNumber(string(c.ID)),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: vexTimestamp(c),
			Component: cdxComponent{
				BOMRef: product,
				Type:   "application",
				Name:   product,
				PURL:   product,
			},
		},
		Vulnerabilities: []cdxVulnerability{vuln},
	}
	if comp != nil {
		doc.Components = []cdxComponent{*comp}
	}
	return json.MarshalIndent(doc, "", "  ")
}
