package triage

import (
	"encoding/json"
	"fmt"

	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// UnreachabilityRuleID names an observation capability, not an automatic proof.
const UnreachabilityRuleID = "symbol-unreachability"

// Keep the entire kernel payload: projections must not erase open scope gates.
type unreachabilityPayload struct {
	ScopeDetails *evidencetools.ScopeDetails          `json:"scope_details"`
	PayloadRef   *evidencetools.ObservationPayloadRef `json:"payload_ref,omitempty"`
	Data         evidencetools.SymbolUnreachabilityData `json:"data"`
}

func parseUnreachabilityPayload(payload []byte) (unreachabilityPayload, bool) {
	var out unreachabilityPayload
	if err := json.Unmarshal(payload, &out); err != nil {
		return out, false
	}
	return out, true
}

// UnreachabilityObservationApproved replays full captured evidence against the
// independently acquired material build. Semantic necessity remains the mandatory
// condition source's responsibility; this never mints a Product B proof.
func UnreachabilityObservationApproved(obs RecordedObservation, s0 Stage0Result) (bool, string) {
	if obs.Tool != evidencetools.SymbolUnreachabilityTool {
		return false, "not a symbol-unreachability observation"
	}
	if obs.Status != ToolStatusOK || obs.Completeness != evidencetools.CompletenessComplete {
		return false, "observation is not OK/COMPLETE"
	}
	if s0.Snapshot.ContentHash == "" || obs.SnapshotHash != s0.Snapshot.ContentHash {
		return false, "observation is bound to another snapshot"
	}
	if obs.BuildContextHash == "" {
		return false, "observation carries no build context"
	}
	payload, ok := parseUnreachabilityPayload(obs.Payload)
	if !ok {
		return false, "observation payload does not parse"
	}
	if payload.PayloadRef != nil || payload.ScopeDetails == nil || payload.ScopeDetails.BuildContext == nil || payload.ScopeDetails.BuildContext.EffectiveBuild == nil {
		return false, "full bound scope payload unavailable"
	}
	if payload.ScopeDetails.SnapshotHash != obs.SnapshotHash || hashCanonical(payload.ScopeDetails.BuildContext) != obs.BuildContextHash {
		return false, "archived scope binding mismatch"
	}
	if s0.Materials.PackageBuild == nil {
		return false, "independent material build unavailable"
	}
	build := *s0.Materials.PackageBuild
	if build.ContentHash != obs.SnapshotHash {
		return false, "inventory snapshot mismatch"
	}
	if err := payload.ScopeDetails.BuildContext.EffectiveBuild.Matches(build); err != nil {
		return false, err.Error()
	}
	if err := payload.Data.Result.ValidateComplete(build); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// validateAdmittingUnreachabilityCoverage is shared by live verification,
// proof certificates and persisted decision admission. No source is loaded.
func validateAdmittingUnreachabilityCoverage(c FalsifierCoverage) error {
	if c.Completeness != string(evidencetools.CompletenessComplete) || c.UnreachabilityBuild == nil || len(c.UnreachabilityPayloads) == 0 {
		return fmt.Errorf("complete captured unreachability payload/build missing")
	}
	var checked []FalsifierSubject
	var dead []domain.SymbolRef
	for _, raw := range c.UnreachabilityPayloads {
		var observation evidencetools.Observation
		if err := json.Unmarshal(raw, &observation); err != nil {
			return err
		}
		rec := RecordedObservation{
			Tool: observation.Tool, Status: string(observation.ToolStatus), Completeness: observation.Completeness,
			SnapshotHash: c.SnapshotHash, BuildContextHash: c.BuildContextHash, Payload: raw,
		}
		s0 := Stage0Result{Snapshot: SnapshotManifest{ContentHash: c.SnapshotHash}, Materials: MaterialSet{PackageBuild: c.UnreachabilityBuild}}
		if ok, why := UnreachabilityObservationApproved(rec, s0); !ok {
			return fmt.Errorf("persisted unreachability: %s", why)
		}
		payload, _ := parseUnreachabilityPayload(raw)
		for _, subject := range payload.Data.Result.Subjects {
			checked = append(checked, FalsifierSubject{Package: subject.Package, Symbol: subject.Symbol})
			dead = append(dead, domain.SymbolRef{Package: subject.Package, Symbol: subject.Symbol})
		}
	}
	if !sameSubjects(c.ExpectedSubjects, checked) || !sameSubjects(c.ExpectedSubjects, c.CheckedSubjects) {
		return fmt.Errorf("captured subjects do not exactly cover the mandatory locus")
	}
	if _, err := domain.RequireDeadnessPremise(c.DeadnessContract, dead); err != nil {
		return err
	}
	return nil
}
