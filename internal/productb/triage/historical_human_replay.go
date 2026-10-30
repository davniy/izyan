package triage

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/llm"
)

// recordedAssessmentVersion selects a supported recorded schema without
// rewriting a byte. The full strict decoder still owns every ingress gate.
func recordedAssessmentVersion(content string) string {
	remaining := content
	for {
		candidate := llm.ExtractJSON(remaining)
		if candidate == "" { return "" }
		var head struct { SchemaVersion string `json:"schema_version"` }
		if json.Unmarshal([]byte(candidate), &head) == nil && (head.SchemaVersion == AssessmentSchemaVersion || head.SchemaVersion == "assessment.v2") { return head.SchemaVersion }
		pos := strings.Index(remaining, candidate)
		if pos < 0 { return "" }
		remaining = remaining[pos+len(candidate):]
	}
}

func validateRecordedDecisionJSON(data []byte, version string) error {
	if version != DecisionPackageSchemaVersion && version != "decision-package.v3" { return unsupportedLiveSchema("decision.json", version, DecisionPackageSchemaVersion) }
	var p DecisionPackage
	if err := json.Unmarshal(data, &p); err != nil { return err }
	if version == "decision-package.v3" && (p.HumanReviewPlan != nil || p.ProposedAction.Kind == HumanActionAcceptEnvironmentalMitigation) {
		return fmt.Errorf("decision-package.v3 cannot carry later environment branch semantics")
	}
	return p.validateSchema(version)
}
