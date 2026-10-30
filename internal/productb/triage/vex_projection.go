package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VEXProjectionSchemaVersion is the schema of vex.json, the optional
// triage-scoped VEX projection artifact (spec §10.2). The projection is a
// separate document from internal/report.OpenVEX: it re-derives a
// statement from one decision-package.v1, never mutates the authoritative
// VEX state and never closes the finding it describes.
const VEXProjectionSchemaVersion = "triage-vex-projection.v1"

// AuditEventVEXProjection is the audit event type of the optional VEX
// projection: status "ok" records a written vex.json, status "denied"
// records the explicit reason the projection boundary refused a package.
const AuditEventVEXProjection = "vex_projection"

// VEX status vocabulary. The projection emits exactly one status —
// not_affected — and only for a DISMISSED package on a complete basis; a
// LOWERED or UNCHANGED recommendation is refused, never mapped onto
// under_investigation, because a triage record adds no statement the
// authoritative consumer could not derive itself.
const vexStatusNotAffected = "not_affected"

// vexJustification* are the OpenVEX justifications the triage lane may
// assert. component_not_present and vulnerable_code_not_present mirror the
// master notAffectedJustification mapping over the decision facts, and
// vulnerable_code_cannot_be_controlled_by_adversary is the only
// justification a trust/perimeter-grounded dismissal may carry — a
// deployment-boundary assumption is never
// vulnerable_code_not_in_execute_path, which the authoritative OpenVEX
// lane emits only after the negative-verification kernel ran.
const (
	vexJustificationComponentNotPresent = "component_not_present"
	vexJustificationCodeNotPresent      = "vulnerable_code_not_present"
	vexJustificationAdversaryControlled = "vulnerable_code_cannot_be_controlled_by_adversary"
	vexJustificationNotInExecutePath    = "vulnerable_code_not_in_execute_path"
)

// ErrVEXProjectionDenied marks a projection refusal: the package is valid
// but the §10.2 boundary does not admit it — an UNCHANGED or LOWERED
// recommendation, an incomplete or unstable basis, a demoted decision or a
// dismissal with no decisive deterministic ground. A refusal is a recorded
// limitation, never a technical failure and never an implicit statement.
var ErrVEXProjectionDenied = errors.New("agenttriage: VEX projection denied")

// VEXProjection is the optional triage-scoped VEX statement derived from
// one decision package (task brief contract). TriageOnly is always true:
// the document is explicitly non-authoritative and binds its basis through
// Provenance — the decision hash, the audit pins and the decisive facts.
type VEXProjection struct {
	SchemaVersion  string         `json:"schema_version"`
	FindingID      string         `json:"finding_id"`
	Recommendation Recommendation `json:"recommendation"`
	Status         string         `json:"status"`
	Justification  string         `json:"justification,omitempty"`
	Provenance     []string       `json:"provenance"`
	TriageOnly     bool           `json:"triage_only"`
}

// Validate checks the projection contract before it is written or
// consumed: only a triage-scoped not_affected statement over a valid
// recommendation is well-formed.
func (p VEXProjection) Validate() error {
	if p.SchemaVersion != VEXProjectionSchemaVersion {
		return fmt.Errorf("invalid schema_version %q", p.SchemaVersion)
	}
	if strings.TrimSpace(p.FindingID) == "" {
		return errors.New("finding_id is required")
	}
	if !p.Recommendation.Valid() {
		return fmt.Errorf("invalid recommendation %q", p.Recommendation)
	}
	if p.Recommendation != RecommendationDismissed {
		return fmt.Errorf("recommendation %s cannot accompany %s: only DISMISSED is projectable", p.Recommendation, p.Status)
	}
	if !p.TriageOnly {
		return errors.New("triage_only must be true: the projection is never authoritative")
	}
	if p.Status != vexStatusNotAffected {
		return fmt.Errorf("invalid status %q: the projection emits only not_affected", p.Status)
	}
	if p.Justification == "" || p.Justification == vexJustificationNotInExecutePath {
		return fmt.Errorf("invalid justification %q for a triage-scoped projection", p.Justification)
	}
	return nil
}

// confinedPerimeters are the deployment.exposure subjects that may ground
// a trust-boundary dismissal: the proven perimeter confines inbound
// reachability to the deployment boundary. "public" and "unknown" never
// qualify — mirroring the admitted lowering rule's vocabulary.
var confinedPerimeters = map[string]bool{
	"cluster-internal": true,
	"internal":         true,
	"loopback":         true,
}

// decisiveVEXBasis projects the decision facts onto the justification
// vocabulary: a REFUTES against package presence or affectedness on a
// closed scope is a code-level ground, a SUPPORTS deployment exposure on a
// confined perimeter is the trust-grounded basis spec §10.2 keeps apart
// from code-proven reachability. Facts are inspected in a deterministic
// order — presence, then affectedness, then exposure — so the strongest
// honest justification wins and a trust basis never shadows a code one.
func decisiveVEXBasis(facts []DecisionFact) (justification string, decisive []DecisionFact) {
	var presence, affected, exposure *DecisionFact
	for i := range facts {
		f := &facts[i]
		switch {
		case f.Kind == FactPackagePresence && f.Status == ObsRefutes && presence == nil:
			presence = f
		case f.Kind == FactPackageAffected && f.Status == ObsRefutes && affected == nil:
			affected = f
		case f.Kind == FactDeploymentExposure && f.Status == ObsSupports &&
			confinedPerimeters[f.Subject] && exposure == nil:
			exposure = f
		}
	}
	switch {
	case presence != nil:
		return vexJustificationComponentNotPresent, []DecisionFact{*presence}
	case affected != nil:
		return vexJustificationCodeNotPresent, []DecisionFact{*affected}
	case exposure != nil:
		return vexJustificationAdversaryControlled, []DecisionFact{*exposure}
	}
	return "", nil
}

// vexProvenance builds the explicit provenance list of the projection: the
// baseline the recommendation started from, the audit pins that bind the
// package to its run and the decisive facts with their own provenance.
// Empty pins are omitted — an absent hash is recorded absence, never an
// invented token; a package composed without severity metadata records the
// absence itself rather than a synthesized baseline.
func vexProvenance(p DecisionPackage, decisive []DecisionFact) []string {
	var out []string
	if b := p.MachineDisposition.Baseline; b != nil {
		out = append(out,
			"baseline.severity="+b.Severity,
			"baseline.priority="+b.Priority,
			"baseline.disposition="+string(b.Disposition),
			"baseline.source="+b.Source,
		)
	} else {
		out = append(out, "baseline:none")
	}
	out = append(out, "decision_package_sha256:"+canonicalDecisionHash(p))
	for _, pin := range []struct{ key, value string }{
		{"audit.ticket_hash", p.Audit.TicketHash},
		{"audit.config_hash", p.Audit.ConfigHash},
		{"audit.snapshot_hash", p.Audit.SnapshotHash},
		{"audit.advisory_hash", p.Audit.AdvisoryHash},
		{"audit.ruleset_hash", p.Audit.RulesetHash},
		{"audit.prompt_hash", p.Audit.PromptHash},
		{"audit.selected_ref", p.Audit.SelectedRef},
		{"audit.resolved_commit", p.Audit.ResolvedCommit},
	} {
		if pin.value != "" {
			out = append(out, pin.key+":"+pin.value)
		}
	}
	for _, f := range decisive {
		out = append(out, fmt.Sprintf("fact:%s:%s:%s", f.Kind, f.Status, f.Subject))
		for _, src := range f.Provenance {
			out = append(out, "source:"+src)
		}
	}
	return out
}

// ProjectVEX derives the optional triage-scoped VEX statement from one
// decision package (spec §10.2). It is a pure projection: it never mutates
// the package, never touches master VEX state and never invents a basis.
//
// Admission is deliberately narrow — a package is projectable only when
//
//   - it passes the decision-package.v3 contract (a malformed package is a
//     technical error, not a denial);
//   - the machine recommendation is DISMISSED — LOWERED is never
//     not_affected and UNCHANGED establishes nothing, whatever the proposed
//     human action or the derived support says;
//   - the fact basis is COMPLETE, no demotion was recorded and the run was
//     stable — PARTIAL/FAILED validation or an unstable/demoted decision
//     forbids the statement;
//   - no residual assumption still blocks reduction and no decision fact
//     is conflicting — an open premise is not a fully valid basis;
//   - the facts carry a decisive deterministic ground: a refuted package
//     presence/affectedness on the closed build graph, or a supported
//     confining deployment perimeter for a trust-grounded dismissal. An
//     undecisive observation — the "trust-only" case — or a public
//     perimeter cannot ground not_affected.
//
// Everything else returns an error wrapping ErrVEXProjectionDenied; the
// caller records it as a limitation, never a technical failure.
func ProjectVEX(p DecisionPackage) (VEXProjection, error) {
	deny := func(format string, args ...any) (VEXProjection, error) {
		return VEXProjection{}, fmt.Errorf("%w: %s", ErrVEXProjectionDenied, fmt.Sprintf(format, args...))
	}
	if err := p.Validate(); err != nil {
		return VEXProjection{}, fmt.Errorf("agenttriage: VEX projection: decision package invalid: %w", err)
	}
	machine := p.MachineDisposition
	switch machine.Recommendation {
	case RecommendationDismissed:
	case RecommendationLowered:
		return deny("recommendation LOWERED is never not_affected")
	case RecommendationUnchanged:
		return deny("recommendation UNCHANGED establishes no reduction to project")
	default:
		return VEXProjection{}, fmt.Errorf("agenttriage: VEX projection: unknown recommendation %q", machine.Recommendation)
	}
	// The projection is a machine statement: the human action, the human
	// support level and any human acceptance are never consulted, so none of
	// them can satisfy a prerequisite below.
	if v := p.TechnicalAssessment.FactValidation; v != string(ValidationComplete) {
		return deny("fact validation is %s, not COMPLETE", orDash(v))
	}
	if len(machine.Demotions) > 0 {
		return deny("%d demotion(s) recorded: the permitted reduction was not established", len(machine.Demotions))
	}
	switch p.TechnicalAssessment.StabilityResult {
	case "", "stable":
	default:
		return deny("stability_result %q is not a stable basis", p.TechnicalAssessment.StabilityResult)
	}
	for _, c := range machine.ResidualAssumptions {
		if c.Status != ConditionSatisfied && strings.HasPrefix(c.Effect, "blocks_") {
			return deny("residual assumption %s is %s and blocks the reduction", c.ID, c.Status)
		}
	}
	for _, f := range p.Facts {
		if f.Status == ObsConflicting {
			return deny("fact %s (%s) is conflicting", f.ID, f.Kind)
		}
	}
	justification, decisive := decisiveVEXBasis(p.Facts)
	if justification == "" {
		for _, proof := range p.FalsifierProofs {
			if proof.Kind == FalsifierCodeAbsent || proof.Kind == FalsifierLocusPackageAbsent || proof.Kind == FalsifierLocusFunctionAbsent {
				return deny("agent-origin falsifier proof %s (%s) is not an admissible VEX absence basis", proof.ID, proof.Kind)
			}
		}
		return deny("no decisive deterministic fact grounds the dismissal: an unvalidated proposal cannot produce not_affected")
	}
	proj := VEXProjection{
		SchemaVersion:  VEXProjectionSchemaVersion,
		FindingID:      p.FindingID,
		Recommendation: machine.Recommendation,
		Status:         vexStatusNotAffected,
		Justification:  justification,
		Provenance:     vexProvenance(p, decisive),
		TriageOnly:     true,
	}
	if err := proj.Validate(); err != nil {
		return VEXProjection{}, fmt.Errorf("agenttriage: VEX projection: %w", err)
	}
	return proj, nil
}

// vexRunDir resolves the run directory the optional artifact belongs to:
// outDir itself when a decision.json already sits inside it, otherwise the
// canonical <outDir>/<finding-id> subdirectory — the same convention
// WriteDecision uses.
func vexRunDir(outDir string, p VEXProjection) (string, error) {
	dir := strings.TrimSpace(outDir)
	if _, err := os.Stat(filepath.Join(dir, "decision.json")); errors.Is(err, os.ErrNotExist) {
		name, nameErr := RunDirName(p.FindingID)
		if nameErr != nil {
			return "", nameErr
		}
		dir = filepath.Join(outDir, name)
	}
	return dir, nil
}

// WriteVEXProjection persists the optional triage-scoped VEX statement as
// vex.json inside the finding run directory. The run's own decision.json
// must exist and match the projection's finding — a projection beside a
// foreign or missing package is a consistency error, never a stray file.
// The decision event is appended to the run's append-only audit log.
func (w ArtifactWriter) WriteVEXProjection(ctx context.Context, outDir string, p VEXProjection) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("agenttriage: VEX projection: %w", err)
	}
	dir, err := vexRunDir(outDir, p)
	if err != nil {
		return err
	}
	decisionBytes, err := os.ReadFile(filepath.Join(dir, "decision.json"))
	if err != nil {
		return fmt.Errorf("agenttriage: VEX projection: decision.json is required: %w", err)
	}
	var pkg DecisionPackage
	if err := json.Unmarshal(decisionBytes, &pkg); err != nil {
		return fmt.Errorf("agenttriage: VEX projection: decision.json does not parse: %w", err)
	}
	if pkg.FindingID != p.FindingID || pkg.MachineDisposition.Recommendation != p.Recommendation {
		return fmt.Errorf("agenttriage: VEX projection: decision.json does not match finding %q", p.FindingID)
	}
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o755); err != nil {
		return fmt.Errorf("agenttriage: VEX projection: create audit directory: %w", err)
	}
	if err := writeJSONAtomic(ctx, filepath.Join(dir, "vex.json"), p); err != nil {
		return err
	}
	stamp := w.now().UTC()
	raw, _ := json.Marshal(p)
	return appendAuditLog(ctx, filepath.Join(dir, "audit", "events.jsonl"), []AuditEvent{{
		Type:      AuditEventVEXProjection,
		Timestamp: stamp,
		RunID:     pkg.RunID,
		Status:    "ok",
		Hash:      hashBytes(raw),
		Scope:     p.FindingID,
	}}, pkg.RunID, stamp)
}

// RecordVEXProjectionDenial appends the explicit refusal reason of one
// denied projection to the run's append-only audit log. It writes no
// vex.json; a refusal is a limitation of the optional artifact, never a
// statement and never an error channel entry.
func (w ArtifactWriter) RecordVEXProjectionDenial(ctx context.Context, outDir string, pkg DecisionPackage, cause error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := vexRunDir(outDir, VEXProjection{FindingID: pkg.FindingID})
	if err != nil {
		return err
	}
	stamp := w.now().UTC()
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o755); err != nil {
		return fmt.Errorf("agenttriage: VEX projection: create audit directory: %w", err)
	}
	return appendAuditLog(ctx, filepath.Join(dir, "audit", "events.jsonl"), []AuditEvent{{
		Type:        AuditEventVEXProjection,
		Timestamp:   stamp,
		RunID:       pkg.RunID,
		Status:      "denied",
		Scope:       pkg.FindingID,
		Limitations: []string{shortErr(cause.Error())},
	}}, pkg.RunID, stamp)
}
