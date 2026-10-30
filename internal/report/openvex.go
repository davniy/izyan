package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

// OpenVEX export (openvex.dev/ns/v0.2.0). The internal verdict model is
// independent of VEX per spec §25 — this is a projection, not a source.
//
// Verdict → status mapping:
//
//	EXPLOITABLE            → affected
//	NOT_AFFECTED           → not_affected + justification selected from the
//	                         affected-chain fact that closed applicability
//	NO_EXPLOIT_PATH_FOUND  → not_affected + justification selected from the
//	                         grounding claim's falsifier (issued only after
//	                         negative verification ran). When no OpenVEX
//	                         justification truthfully describes the proof, the
//	                         statement carries the proof in impact_statement.
//	INCONCLUSIVE / none    → under_investigation + action_statement
//	refused negative       → under_investigation (never not_affected)
//
// Subcomponents are nested under each product, as the official schema
// requires; a statement-level subcomponents member is not valid OpenVEX.
//
// A negative is refused when its build target, measurement completion,
// coverage or recorded build context does not admit it; the refusal is
// reported in the statement instead of exporting a clean claim.
//
// A case with the requested-finding envelope additionally keeps
// EXTERNAL_DEPENDENCY and FAILED distinct: both project to
// under_investigation, but the action statement says either
// "external_dependency: <named missing fact>" or
// "analysis_failed: <typed cause>" and a failure never becomes not_affected.
type vexDoc struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexComponent `json:"vulnerability"`
	Products        []vexProduct `json:"products"`
	Status          string       `json:"status"`
	Justification   string       `json:"justification,omitempty"`
	ImpactStatement string       `json:"impact_statement,omitempty"`
	ActionStatement string       `json:"action_statement,omitempty"`
}

type vexComponent struct {
	ID   string `json:"@id,omitempty"`
	Name string `json:"name,omitempty"`
}

// vexProduct is an OpenVEX component. The official schema nests subcomponents
// inside the product; the subcomponent itself carries only an IRI (or typed
// identifiers), never a free-form name.
type vexProduct struct {
	ID            string            `json:"@id,omitempty"`
	Subcomponents []vexSubcomponent `json:"subcomponents,omitempty"`
}

type vexSubcomponent struct {
	ID string `json:"@id,omitempty"`
}

// OpenVEX renders the case into an OpenVEX JSON document.
//
// A case carrying the requested-finding envelope exports one statement per
// published identity — the requested identity, the primary record and each
// candidate record — so the requested answer and the record-level assessments
// never collapse into one claim and related ids are never exported as aliases.
// A composed positive's subcomponents, impact and action come from the witness
// records that earned it.
//
// Before projection the case's negative conclusions are re-admitted: a
// refused build-dependent measurement or a refused advisory scope exports
// as under_investigation, never as not_affected. A build-dependent negative
// carries the analyzed build's platform, tags, CGO, target provenance and
// bounded scope in its impact or action statement.
func OpenVEX(c *domain.AnalysisCase) ([]byte, error) {
	pub := publish(c)
	if pub.refusal != nil {
		return nil, pub.refusal
	}
	if pub.requested != nil {
		return openVEXProjected(pub)
	}
	return openVEXLegacy(c)
}

// openVEXProjected renders the requested-finding projection: the requested
// identity first, then the primary and candidate records whose own ids are not
// already published.
func openVEXProjected(pub publication) ([]byte, error) {
	product := productRef(pub.primary.Product)
	entries := exportEntries(pub)
	statements := make([]vexStatement, 0, len(entries))
	for _, entry := range entries {
		state := pub.exportStateFor(entry)
		published := vexProduct{ID: product}
		for _, component := range pub.exportComponents(entry, state) {
			published.Subcomponents = append(published.Subcomponents, vexSubcomponent{ID: component.PURL})
		}
		st := vexStatement{
			Vulnerability: vexComponent{ID: vulnRef(entry.Identity), Name: entry.Identity},
			Products:      []vexProduct{published},
		}
		st.Status = state.Status
		st.Justification = state.Justification
		st.ImpactStatement = state.Impact
		st.ActionStatement = state.Action
		statements = append(statements, st)
	}
	doc := vexDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("urn:izyan:case:%s:openvex", pub.primary.ID),
		Author:     "izyan",
		Timestamp:  vexTimestamp(pub.primary),
		Version:    1,
		Statements: statements,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// exportComponents names the components an export entry publishes: the
// witness records' own modules for a composed positive, every assessed corpus
// record for a corpus-bounded negative, and the entry record's own module
// otherwise. A proven component absence publishes no subcomponent, because
// naming one would contradict the proof.
func (p publication) exportComponents(entry exportEntry, state exportState) []exportComponent {
	if state.Status == "not_affected" && state.Justification == "component_not_present" {
		return nil
	}
	var out []exportComponent
	seen := make(map[string]bool)
	add := func(components []exportComponent) {
		for _, component := range components {
			if seen[component.PURL] {
				continue
			}
			seen[component.PURL] = true
			out = append(out, component)
		}
	}
	if entry.requested() && len(entry.Witnesses) > 0 {
		add(witnessComponents(entry.Witnesses))
		return out
	}
	if entry.requested() && entry.Corpus != nil {
		for _, assessed := range entry.Corpus.AssessedRecords {
			record := p.recordForPin(assessed.Record)
			// A candidate whose own proof is component absence must not be
			// named as a subcomponent of the corpus statement: the proof
			// says exactly that it is not present.
			if affectedProofJustification(record).Vex == "component_not_present" {
				continue
			}
			add(componentsFor(record))
		}
		return out
	}
	add(componentsFor(entry.Record))
	return out
}

// openVEXLegacy renders a legacy single-assessment case. It has no requested
// finding to project, so it keeps the historical statement exactly.
func openVEXLegacy(c *domain.AnalysisCase) ([]byte, error) {
	buildScope := ""
	if negativeUsesBuildContext(c) {
		buildScope = buildScopeStatement(c)
	}
	c = admitNegativeConclusions(c).Case
	published := vexProduct{ID: productRef(c.Product)}
	if c.Vulnerability.Module != "" {
		sub := "pkg:golang/" + c.Vulnerability.Module
		if v := resolvedVersion(c); v != "" {
			sub += "@" + v
		}
		published.Subcomponents = []vexSubcomponent{{ID: sub}}
	}
	st := vexStatement{
		Vulnerability: vexComponent{ID: vulnRef(c.Vulnerability.ID), Name: c.Vulnerability.ID},
		Products:      []vexProduct{published},
	}
	reason := ""
	if c.Verdict != nil {
		reason = c.Verdict.Reason
		// Assumption ids travel in the impact statement as clearly
		// labelled policy inputs — never as VEX evidence, and never
		// silently: a consumer must see what the decision assumed.
		if len(c.Verdict.AssumptionIDs) > 0 {
			reason += " (declared assumptions, policy inputs not evidence: " +
				strings.Join(c.Verdict.AssumptionIDs, ", ") + ")"
		}
	}
	var verdict domain.Verdict
	if c.Verdict != nil {
		verdict = c.Verdict.Verdict
	}
	// A negative projection needs the same closure authority the verdict
	// evaluator demands: an exact advisory entry with complete coverage and
	// an admitted measurement of the analyzed build. Admission above has
	// already demoted a refused negative to INCONCLUSIVE, so the switch
	// below can only reach not_affected when that authority survives.
	switch verdict {
	case domain.VerdictExploitable:
		st.Status = "affected"
		st.ImpactStatement = reason
		// An affected statement must carry a concrete action even when no
		// fixed version is published.
		st.ActionStatement = affectedActionStatement(c)
		if libraryAPIScope(c) {
			// EXPLOITABLE stays affected: the public-API path is proven.
			// under_investigation would underclaim it, but the scope and the
			// mandatory limitation must travel with the statement.
			st.ImpactStatement = joinStatements(st.ImpactStatement, libraryScopeStatement(c), "Limitation: "+libraryAPILimitationText(false))
			st.ActionStatement += " (exploitability scope library-api; limitation: " + libraryAPILimitationText(false) + ")"
		}
	case domain.VerdictNotAffected:
		st.Status = "not_affected"
		st.Justification = affectedProofJustification(c).Vex
		st.ImpactStatement = joinStatements(reason, buildScope)
	case domain.VerdictNoExploitPathFound:
		// Only reached when a FALSE claim survived negative verification.
		// The grounding claim's falsifier selects the justification; a
		// proof with no exact OpenVEX entry keeps the impact statement.
		st.Status = "not_affected"
		st.Justification = noExploitPathProof(c).Vex
		st.ImpactStatement = reason
		if basis := noExploitPathBasis(c); basis != "" {
			st.ImpactStatement = reason + " (" + basis + ")"
		}
		st.ImpactStatement = joinStatements(st.ImpactStatement, buildScope)
	default:
		st.Status = "under_investigation"
		st.ActionStatement = "analysis inconclusive — manual review required"
		if reason != "" {
			st.ActionStatement += ": " + reason
		}
		st.ActionStatement = joinStatements(st.ActionStatement+".", buildScope)
		if libraryAPIScope(c) {
			// Status still comes solely from the verdict; the library
			// boundary is a projection of the evidence, not a status.
			st.ActionStatement = joinStatements(st.ActionStatement, libraryScopeStatement(c), "Limitation: "+libraryAPILimitationText(false))
		}
	}
	doc := vexDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("urn:izyan:case:%s:openvex", c.ID),
		Author:     "izyan",
		Timestamp:  vexTimestamp(c),
		Version:    1,
		Statements: []vexStatement{st},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// groundBasisText renders the trust basis of a NEPF verdict for VEX
// consumers: declared assertions, detected perimeters and config-origin
// provenance must not read as code-proven unreachability.
func groundBasisText(basis string) string {
	switch basis {
	case domain.BasisDeclaredTrust:
		return "rests on a declared deployment trust boundary (--trusted-peer or --perimeter), not on code-level verification"
	case domain.BasisAutoPerimeter:
		return "rests on an auto-detected cluster-internal perimeter from deployment manifests"
	case domain.BasisConfigOrigin:
		return "rests on the exact sink trigger arguments resolving to administrator-managed configuration under a declared config-trust policy assumption (not code-level unreachability); the assumption is a policy input, not evidence"
	default:
		return "rests on a deployment trust assumption"
	}
}

// vulnRef links GO-* ids to the Go vuln DB, everything else to OSV.
func vulnRef(id string) string {
	if strings.HasPrefix(id, "GO-") {
		return "https://pkg.go.dev/vuln/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

// productRef identifies the analyzed product: module path from go.mod
// (purl) at the analyzed commit, falling back to the repo path.
func productRef(p domain.ProductSnapshot) string {
	name := p.Repository
	if mod := modulePath(p.Repository); mod != "" {
		name = mod
	}
	id := "pkg:golang/" + name
	if p.Commit != "" {
		id += "@" + p.Commit
	}
	return id
}

func resolvedVersion(c *domain.AnalysisCase) string {
	if c.Affected == nil {
		return ""
	}
	return c.Affected.ResolvedVersion
}

func modulePath(repo string) string {
	b, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func vexTimestamp(c *domain.AnalysisCase) string {
	if !c.Workflow.UpdatedAt.IsZero() {
		return c.Workflow.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}
