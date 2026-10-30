package triage

import (
	"fmt"
	"strings"
	"slices"

	"github.com/davniy/izyan/internal/productb/domain"
)

const (
	MaxEnvironmentQuestions = 2
	MaxMandatoryPremises = 7
	EnvironmentUnknown = "unknown"
	VariableBuildVariant = "build_variant"
	VariableDeploymentPerimeter = "deployment_perimeter"
	VariableAdvisoryPrecondition = "advisory_precondition"
)

// DecisionVariable is code-owned. DerivedFrom contains captured source IDs,
// never model assertions about the truth of an environment condition.
type DecisionVariable struct {
	ID string `json:"id"`
	Question string `json:"question"`
	AllowedValues []string `json:"allowed_values"`
	Required bool `json:"required"`
	DerivedFrom []string `json:"derived_from,omitempty"`
}

// EnvironmentVariableProposal nominates a dimension, not its values or truth.
// Advisory nominations must quote one exact, digest-bound captured record.
type EnvironmentVariableProposal struct {
	ID string `json:"id"`
	RecordID string `json:"record_id,omitempty"`
	RecordSHA256 string `json:"record_sha256,omitempty"`
	Quote string `json:"quote,omitempty"`
}

func environmentVariables(in SupportInput) ([]DecisionVariable, error) {
	var out []DecisionVariable
	seen := map[string]bool{}
	for _, p := range in.Assessment.EnvironmentVariables {
		if seen[p.ID] { return nil, fmt.Errorf("duplicate environment variable %q", p.ID) }
		seen[p.ID] = true
		v := DecisionVariable{ID: p.ID, Required: true}
		switch p.ID {
		case VariableBuildVariant:
			if p.RecordID != "" || p.RecordSHA256 != "" || p.Quote != "" { return nil, fmt.Errorf("build variant cannot carry advisory provenance") }
			target := in.Stage0.BuildTarget
			if target == nil { target = in.Stage0.Investigation.BuildTarget }
			if target == nil || !target.Scoped() { return nil, fmt.Errorf("build_variant requires a recorded product target") }
			if err := target.Validate(); err != nil { return nil, fmt.Errorf("build_variant: %w", err) }
			v.Question = "Which recorded build closure variant produced the analyzed artifact?"
			v.Required = false
			// The recorded target is fixed, never an operator question. Evidence
			// about it does not transfer to a different delivered artifact.
			v.AllowedValues = []string{recordedBuildVariant(in.Stage0), "other"}
			v.DerivedFrom = []string{"recorded-build-target:" + projectionHash(target)}
		case VariableDeploymentPerimeter:
			if p.RecordID != "" || p.RecordSHA256 != "" || p.Quote != "" { return nil, fmt.Errorf("deployment perimeter cannot carry advisory provenance") }
			v.Question = "Which perimeter posture does the analyzed deployment run in?"
			v.AllowedValues = []string{domain.PerimeterClusterInternal, domain.PerimeterPublic, EnvironmentUnknown}
			v.DerivedFrom = []string{"deployment-perimeter:configured-product-scope"}
		case VariableAdvisoryPrecondition:
			if !advisoryEnvironmentQuote(p.Quote) { return nil, fmt.Errorf("advisory_precondition requires a verbatim deployment/configuration precondition") }
			bound := false
			for _, r := range in.Stage0.Investigation.Records {
				if r.RecordID == p.RecordID && r.SHA256 == p.RecordSHA256 && !r.Partial && validSHA256(r.SHA256) && hashBytes(r.Raw) == r.SHA256 && strings.Contains(string(r.Raw), p.Quote) {
					bound = true
				}
			}
			if !bound { return nil, fmt.Errorf("advisory_precondition quote is not bound to the exact captured record and digest") }
			v.Question = fmt.Sprintf("the advisory declares %q — does this exploitation precondition hold for the deployed environment, and is the named input/configuration attacker-influenced or operator-controlled?", p.Quote)
			v.AllowedValues = []string{"holds", "does_not_hold", EnvironmentUnknown}
			v.DerivedFrom = []string{p.RecordID + "@sha256:" + p.RecordSHA256, p.Quote}
		default:
			return nil, fmt.Errorf("environment variable %q is unsupported", p.ID)
		}
		out = append(out, v)
	}
	return out, nil
}

// These are the existing R6 generic deployment/precondition validators. They
// recognize question nominations only; a match establishes no necessity or fact.
func advisoryEnvironmentQuote(q string) bool {
	if strings.TrimSpace(q) != q || len(q) < 24 { return false }
	low := " " + strings.ToLower(q) + " "
	pre, env := false, false
	for _, s := range []string{"require", "only if", "only when", "only in", " must ", "must be", " if ", "when ", "where ", "unless", "controlled by", "enabled", "disabled"} {
		pre = pre || strings.Contains(low, s)
	}
	for _, s := range []string{"config", "option", "setting", "flag", "parameter", "argument", "environment", "deploy", "listener", "socket", "port", "endpoint", "exposed", "exposure", "perimeter", "network", "route", "operator", "administrator", "attacker-controlled", "user-controlled", "untrusted", "trusted", "upstream", "proxy", "host"} {
		env = env || strings.Contains(low, s)
	}
	return pre && env
}

func validSHA256(s string) bool {
	if len(s) != 64 { return false }
	for _, c := range s { if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return false } }
	return true
}

// recordedBuildVariant must describe effective configuration, not available
// files. Stage0 currently captures the platform target but no effective
// GOWORK/GOFLAGS/module-mode selection, so its build mode is unidentified.
// In particular, go.work can be disabled and vendor can be ignored.
func recordedBuildVariant(_ Stage0Result) string {
	return EnvironmentUnknown
}

func validateDecisionVariable(v DecisionVariable) error {
	var question string
	var values []string
	switch v.ID {
	case VariableBuildVariant:
		question = "Which recorded build closure variant produced the analyzed artifact?"
		if v.Required || len(v.AllowedValues) == 0 || len(v.DerivedFrom) != 1 || !strings.HasPrefix(v.DerivedFrom[0], "recorded-build-target:") || !validSHA256(strings.TrimPrefix(v.DerivedFrom[0], "recorded-build-target:")) { return fmt.Errorf("invalid recorded build dimension") }
		// Retain the declared recorded-mode schema, but live producers may
		// only emit it when effective configuration has actually been captured.
		if v.AllowedValues[0] == EnvironmentUnknown {
			values = []string{EnvironmentUnknown, "other"}
		} else {
			if !containsString([]string{"vendor", "workspace", "module"}, v.AllowedValues[0]) { return fmt.Errorf("invalid recorded build mode") }
			values = []string{v.AllowedValues[0], "other", EnvironmentUnknown}
		}
	case VariableDeploymentPerimeter:
		question = "Which perimeter posture does the analyzed deployment run in?"
		values = []string{domain.PerimeterClusterInternal, domain.PerimeterPublic, EnvironmentUnknown}
		if !v.Required || !slices.Equal(v.DerivedFrom, []string{"deployment-perimeter:configured-product-scope"}) { return fmt.Errorf("invalid deployment perimeter declaration") }
	case VariableAdvisoryPrecondition:
		if !v.Required || len(v.DerivedFrom) != 2 || !advisoryEnvironmentQuote(v.DerivedFrom[1]) { return fmt.Errorf("invalid advisory precondition provenance") }
		record, digest, ok := strings.Cut(v.DerivedFrom[0], "@sha256:")
		if !ok || record == "" || !validSHA256(digest) { return fmt.Errorf("invalid advisory precondition record binding") }
		question = fmt.Sprintf("the advisory declares %q — does this exploitation precondition hold for the deployed environment, and is the named input/configuration attacker-influenced or operator-controlled?", v.DerivedFrom[1])
		values = []string{"holds", "does_not_hold", EnvironmentUnknown}
	default:
		return fmt.Errorf("unsupported decision variable %q", v.ID)
	}
	if v.Question != question || !slices.Equal(v.AllowedValues, values) { return fmt.Errorf("decision variable %q changed its code-owned question or answers", v.ID) }
	return nil
}
