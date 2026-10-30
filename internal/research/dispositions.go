package research

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"

	"github.com/fedorovmv/izyan/internal/domain"
)

// The R6 data-owned catalogs live in the repository at fixed paths and
// are written in the JSON subset of YAML 1.2 (every JSON document is a
// valid YAML document), so they parse through encoding/json with a
// closed member set — no permissive YAML reader, no new dependency.
const (
	DispositionsCatalogPath = "configs/research/dispositions.yaml"
	ConditionsCatalogPath   = "configs/research/conditions.yaml"
	ChecksCatalogPath       = "configs/research/checks.yaml"
	SafetyPolicyPath        = "rubrics/decision.yaml"
)

const (
	dispositionsCatalogSchema = "research-dispositions/1"
	conditionsCatalogSchema   = "research-conditions/1"
	checksCatalogSchema       = "research-checks/1"
	safetyPolicySchema        = "research-safety-policy/1"
)

// DispositionSpec is one catalog entry describing a proposed
// disposition: whether it is a code-grounded closure (verified
// deterministic premises only) and whether environment premises may
// support it. The catalog must cover the whole R6 enum and must agree
// with the code-side semantics — a config that weakens a disposition's
// premises is malformed, never silently relaxed.
type DispositionSpec struct {
	ID                        string `json:"id"`
	CodeGrounded              bool   `json:"code_grounded"`
	EnvironmentPremiseAllowed bool   `json:"environment_premise_allowed"`
	RequiresCompleteCoverage  bool   `json:"requires_complete_coverage"`
	Description               string `json:"description"`
}

// ConditionSpec is one generic condition/rule-catalog entry. It names a
// role and polarity class the flow layer may instantiate; it carries no
// case-specific subject.
type ConditionSpec struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	Polarity    string `json:"polarity"`
	Description string `json:"description"`
}

// CheckSpec is one generic deterministic check entry the flow layer may
// schedule; tool names a capability of the evidence lane.
type CheckSpec struct {
	ID          string `json:"id"`
	Tool        string `json:"tool"`
	Description string `json:"description"`
}

// VariableSpec is the catalog-declared answer set of one decision
// variable. Only catalog-owned variables (deployment_perimeter) may be
// declared here; derived variables take their values from the recorded
// build context and every other registry id is code-only — declaring
// either kind in the catalog is an error, never a silent override.
type VariableSpec struct {
	ID            string   `json:"id"`
	AllowedValues []string `json:"allowed_values"`
}

// Catalogs is the loaded condition/check/disposition catalog bundle.
// Variables carries the catalog-owned decision-variable answer sets.
type Catalogs struct {
	Dispositions []DispositionSpec
	Conditions   []ConditionSpec
	Checks       []CheckSpec
	Variables    []VariableSpec
}

// BaselineChecks are the deterministic checks a loadable configuration
// must always keep: they implement the required gates (applicability
// resolution and the two build-closure checks) that the monotonic policy
// forbids removing.
var BaselineChecks = []string{"affected-resolve", "package-usage", "usage-scope"}

// BaselineDispositions are the dispositions a loadable catalog must
// always cover — the full R6 enum.
var BaselineDispositions = []ProposedDisposition{
	DispositionCloseNotAffected, DispositionCloseNoExploitPath,
	DispositionAcceptEnvironmentalMitigation, DispositionKeepOpenForRemediation,
	DispositionHoldUnknown,
}

// BaselineConditionIDs are the generic condition entries the catalog
// must always carry (subject classes, never CVE-specific content).
var BaselineConditionIDs = []string{
	"module-present", "version-in-range", "package-linked",
	"deployment-perimeter", "peer-trust", "config-mode",
	"build-variant", "delivered-artifact", "protocol-role",
}

// readCatalogJSON decodes one catalog file with a closed member set.
func readCatalogJSON(fsys fs.FS, path string, dst any) error {
	raw, err := fs.ReadFile(fsys, path)
	if err != nil {
		return fmt.Errorf("research catalog %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("research catalog %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return fmt.Errorf("research catalog %s: trailing content", path)
	}
	return nil
}

type dispositionsFile struct {
	Schema       string            `json:"schema"`
	Dispositions []DispositionSpec `json:"dispositions"`
}

type conditionsFile struct {
	Schema     string          `json:"schema"`
	Conditions []ConditionSpec `json:"conditions"`
	// Variables is an optional member of the research-conditions/1
	// document: the catalog-declared allowed-value sets for
	// catalog-owned decision variables (deployment_perimeter).
	Variables []VariableSpec `json:"variables,omitempty"`
}

type checksFile struct {
	Schema string      `json:"schema"`
	Checks []CheckSpec `json:"checks"`
}

// LoadCatalogs loads the R6 condition/check/disposition catalog bundle
// from fsys (rooted at the repository root). Missing files, malformed
// documents, wrong schema ids and any weakening of the baseline coverage
// are all errors — a bad configuration never degrades into a permissive
// default.
func LoadCatalogs(fsys fs.FS) (Catalogs, error) {
	var c Catalogs
	var df dispositionsFile
	if err := readCatalogJSON(fsys, DispositionsCatalogPath, &df); err != nil {
		return Catalogs{}, err
	}
	if df.Schema != dispositionsCatalogSchema {
		return Catalogs{}, fmt.Errorf("research catalog %s: schema %q != %q", DispositionsCatalogPath, df.Schema, dispositionsCatalogSchema)
	}
	c.Dispositions = df.Dispositions
	var cf conditionsFile
	if err := readCatalogJSON(fsys, ConditionsCatalogPath, &cf); err != nil {
		return Catalogs{}, err
	}
	if cf.Schema != conditionsCatalogSchema {
		return Catalogs{}, fmt.Errorf("research catalog %s: schema %q != %q", ConditionsCatalogPath, cf.Schema, conditionsCatalogSchema)
	}
	c.Conditions = cf.Conditions
	c.Variables = cf.Variables
	var kf checksFile
	if err := readCatalogJSON(fsys, ChecksCatalogPath, &kf); err != nil {
		return Catalogs{}, err
	}
	if kf.Schema != checksCatalogSchema {
		return Catalogs{}, fmt.Errorf("research catalog %s: schema %q != %q", ChecksCatalogPath, kf.Schema, checksCatalogSchema)
	}
	c.Checks = kf.Checks
	if err := c.validate(); err != nil {
		return Catalogs{}, err
	}
	return c, nil
}

// validate enforces catalog integrity and the baseline floor: every
// disposition in the R6 enum is present with the code-agreed premises,
// every baseline check and condition id is present, ids are unique and
// no entry is under-specified.
func (c *Catalogs) validate() error {
	e := &ValidationError{}
	seenDisp := map[string]bool{}
	for i, d := range c.Dispositions {
		where := fmt.Sprintf("dispositions[%d]", i)
		if !isProposedDisposition(ProposedDisposition(d.ID)) {
			e.add("dispositions catalog: %s id %q is not an R6 disposition", where, d.ID)
			continue
		}
		if seenDisp[d.ID] {
			e.add("dispositions catalog: %s duplicates %q", where, d.ID)
		}
		seenDisp[d.ID] = true
		if d.Description == "" {
			e.add("dispositions catalog: %s description required", where)
		}
		// Premise semantics are fixed by the contract: CLOSE_* are
		// code-grounded, complete-coverage dispositions that never accept
		// environment premises; a catalog that loosens a CLOSE_* premise
		// is a relaxation and is rejected.
		close := isCloseDisposition(ProposedDisposition(d.ID))
		if close && (!d.CodeGrounded || d.EnvironmentPremiseAllowed || !d.RequiresCompleteCoverage) {
			e.add("dispositions catalog: %s %q must keep code_grounded=true, environment_premise_allowed=false, requires_complete_coverage=true", where, d.ID)
		}
		if !close && d.CodeGrounded {
			e.add("dispositions catalog: %s %q is not a code-grounded disposition", where, d.ID)
		}
	}
	for _, want := range BaselineDispositions {
		if !seenDisp[string(want)] {
			e.add("dispositions catalog: required disposition %q is missing", want)
		}
	}
	seenCond := map[string]bool{}
	for i, cd := range c.Conditions {
		where := fmt.Sprintf("conditions[%d]", i)
		if cd.ID == "" || cd.Description == "" {
			e.add("conditions catalog: %s id/description required", where)
		}
		if cd.ID != "" {
			if seenCond[cd.ID] {
				e.add("conditions catalog: %s duplicates %q", where, cd.ID)
			}
			seenCond[cd.ID] = true
		}
		switch cd.Role {
		case ConditionRoleApplicability, ConditionRolePath, ConditionRoleDeployment, ConditionRoleSupporting:
		default:
			e.add("conditions catalog: %s role %q invalid", where, cd.Role)
		}
		switch cd.Polarity {
		case PolarityPositive, PolarityNegative:
		default:
			e.add("conditions catalog: %s polarity %q invalid", where, cd.Polarity)
		}
	}
	for _, want := range BaselineConditionIDs {
		if !seenCond[want] {
			e.add("conditions catalog: required condition %q is missing", want)
		}
	}
	seenCheck := map[string]bool{}
	for i, ck := range c.Checks {
		where := fmt.Sprintf("checks[%d]", i)
		if ck.ID == "" || ck.Tool == "" || ck.Description == "" {
			e.add("checks catalog: %s id/tool/description required", where)
		}
		if ck.ID != "" {
			if seenCheck[ck.ID] {
				e.add("checks catalog: %s duplicates %q", where, ck.ID)
			}
			seenCheck[ck.ID] = true
		}
	}
	for _, want := range BaselineChecks {
		if !seenCheck[want] {
			e.add("checks catalog: required check %q is missing", want)
		}
	}
	// Catalog-declared decision variables: only catalog-owned ids may
	// declare allowed values here, and the catalog-owned variable must
	// always be present so the branch evaluator has a closed answer set.
	seenVar := map[string]bool{}
	for i, v := range c.Variables {
		where := fmt.Sprintf("variables[%d]", i)
		if v.ID == "" {
			e.add("conditions catalog: %s id required", where)
			continue
		}
		if v.ID != variableDeploymentPerimeter {
			e.add("conditions catalog: %s %q is not a catalog-owned decision variable — values are code-owned or unimplemented", where, v.ID)
			continue
		}
		if seenVar[v.ID] {
			e.add("conditions catalog: %s duplicates %q", where, v.ID)
		}
		seenVar[v.ID] = true
		if len(v.AllowedValues) == 0 {
			e.add("conditions catalog: %s %q requires a non-empty allowed_values set", where, v.ID)
		}
		seenVal := map[string]bool{}
		for _, val := range v.AllowedValues {
			if val == "" {
				e.add("conditions catalog: %s %q carries an empty allowed value", where, v.ID)
				continue
			}
			if seenVal[val] {
				e.add("conditions catalog: %s %q lists %q twice", where, v.ID, val)
			}
			seenVal[val] = true
		}
	}
	if !seenVar[variableDeploymentPerimeter] {
		e.add("conditions catalog: catalog-owned decision variable %q is missing its allowed_values declaration", variableDeploymentPerimeter)
	}
	if len(e.Problems) > 0 {
		return e
	}
	return nil
}

// DispositionForFalsifier is the single code-owned mapping from a
// falsifier/basis pair to the proposed disposition it may produce —
// the R6 trust boundary in one place. It knows only
// FalsifierTrustedInfrastructure, the one falsifier whose disposition
// depends on the premise kind:
//
//   - declared-trust, auto-perimeter or an unspecified basis is a
//     recorded environment premise: ACCEPT_ENVIRONMENTAL_MITIGATION is
//     the only admissible outcome — never a code-grounded CLOSE_*;
//   - BasisConfigOrigin stays code provenance: it may ground
//     CLOSE_NO_EXPLOIT_PATH only when the deterministic provenance
//     result covered every relevant sink input with complete scope and
//     no unresolved source (provenanceComplete); anything less is
//     HOLD_UNKNOWN, never a mitigation fallback.
//
// Every other falsifier kind is outside this function's contract: it
// returns an error so a caller can never smuggle a trusted-infra
// premise into a CLOSE_* through a renamed kind.
func DispositionForFalsifier(falsifier string, basis string, provenanceComplete bool) (ProposedDisposition, error) {
	if falsifier != domain.FalsifierTrustedInfrastructure {
		return "", fmt.Errorf("falsifier %q has no environment-dependent disposition mapping", falsifier)
	}
	switch basis {
	case domain.BasisConfigOrigin:
		if !provenanceComplete {
			return DispositionHoldUnknown, nil
		}
		return DispositionCloseNoExploitPath, nil
	case domain.BasisDeclaredTrust, domain.BasisAutoPerimeter, "":
		return DispositionAcceptEnvironmentalMitigation, nil
	default:
		// An unrecognized basis is not a proven code provenance and not
		// a declared premise shape: it fails closed to HOLD_UNKNOWN.
		return DispositionHoldUnknown, nil
	}
}
