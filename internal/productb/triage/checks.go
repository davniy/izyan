package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// CheckStatus is the machine outcome of one deterministic check (spec §6.4).
// A check reports what it could verify; it never emits a recommendation.
type CheckStatus string

const (
	// CheckPass — everything the check covers verified cleanly.
	CheckPass CheckStatus = "PASS"
	// CheckLimitation — the check ran but part of its scope is constrained;
	// recorded as a limitation, never a negative fact.
	CheckLimitation CheckStatus = "LIMITATION"
	// CheckUnverified — the covered claim could not be confirmed: it stays a
	// hypothesis and can never support DISMISSED/LOWERED.
	CheckUnverified CheckStatus = "UNVERIFIED"
	// CheckConflicting — two authoritative facts disagree inside the check's
	// scope; the contradiction is recorded, not resolved.
	CheckConflicting CheckStatus = "CONFLICTING"
	// CheckInvalid — the checked object is malformed or outside its scope.
	CheckInvalid CheckStatus = "INVALID"
	// CheckUnavailable — an input the check needs was never supplied or
	// could not be reached; absence is not a negative fact.
	CheckUnavailable CheckStatus = "UNAVAILABLE"
	// CheckError — the check itself failed technically; a package cannot be
	// honestly composed on top of it.
	CheckError CheckStatus = "ERROR"
)

// CheckID enumerates the §6.4 check set in spec order.
const (
	CheckIDIntakeIdentity     = "C01"
	CheckIDFieldProvenance    = "C02"
	CheckIDSourceResolution   = "C03"
	CheckIDRefResolution      = "C04"
	CheckIDSnapshotIntegrity  = "C05"
	CheckIDAdvisory           = "C06"
	CheckIDPackageVersion     = "C07"
	CheckIDReleaseToolchain   = "C08"
	CheckIDArtifactIdentity   = "C09"
	CheckIDEvidenceReferences = "C10"
	CheckIDScopeAlternatives  = "C11"
	CheckIDRiskPolicy         = "C12"
	CheckIDPackageStability   = "C13"
	CheckIDFalsifierProof     = "C14"
)

// CheckResult is one check's machine verdict: the check id, its status,
// short deterministic reasons and the repair hints a feedback pass may
// carry — bindings only, never a semantic answer.
type CheckResult struct {
	ID              string      `json:"id"`
	Status          CheckStatus `json:"status"`
	Reasons         []string    `json:"reasons,omitempty"`
	ExpectedRepairs []string    `json:"expected_repairs,omitempty"`
}

// Check is one deterministic check of the decision surface (spec §11.2).
// Implementations are pure evaluations over already-collected materials —
// they never dial, never mutate and never emit a recommendation.
type Check interface {
	ID() string
	Evaluate(context.Context, CheckInput) CheckResult
}

// CheckInput aggregates everything the check set may inspect: the Stage 0
// resolution result, the agent assessment, the fact gate report, the
// collected provider facts and — at the final gate — the composed package
// the last two checks verify. Profiles and Rules let C12 re-derive the
// permitted recommendation deterministically.
type CheckInput struct {
	Stage0     Stage0Result
	Assessment Assessment
	Validation FactValidation
	Facts      []DecisionFact
	Package    *DecisionPackage
	Profiles   []DecisionProfile
	Rules      []DecisionRule
	Falsifiers *FalsifierReport
}

func checkResult(id string, status CheckStatus, reasons []string, repairs []string) CheckResult {
	return CheckResult{ID: id, Status: status, Reasons: reasons, ExpectedRepairs: repairs}
}

func passResult(id string) CheckResult { return checkResult(id, CheckPass, nil, nil) }

// checkFunc adapts a plain function to Check.
type checkFunc struct {
	id string
	fn func(context.Context, CheckInput) CheckResult
}

func (c checkFunc) ID() string { return c.id }
func (c checkFunc) Evaluate(ctx context.Context, in CheckInput) CheckResult {
	if err := ctx.Err(); err != nil {
		return checkResult(c.id, CheckUnavailable, []string{fmt.Sprintf("check aborted: %v", err)}, nil)
	}
	return c.fn(ctx, in)
}

// DefaultChecks returns the full C01–C13 set in spec order.
func DefaultChecks() []Check {
	return []Check{
		checkFunc{CheckIDIntakeIdentity, checkIntakeIdentity},
		checkFunc{CheckIDFieldProvenance, checkFieldProvenance},
		checkFunc{CheckIDSourceResolution, checkSourceResolution},
		checkFunc{CheckIDRefResolution, checkRefResolution},
		checkFunc{CheckIDSnapshotIntegrity, checkSnapshotIntegrity},
		checkFunc{CheckIDAdvisory, checkAdvisoryApplicability},
		checkFunc{CheckIDPackageVersion, checkPackageVersionFact},
		checkFunc{CheckIDReleaseToolchain, checkReleaseToolchain},
		checkFunc{CheckIDArtifactIdentity, checkArtifactIdentity},
		checkFunc{CheckIDEvidenceReferences, checkEvidenceReferences},
		checkFunc{CheckIDScopeAlternatives, checkScopeAlternatives},
		checkFunc{CheckIDRiskPolicy, checkRiskPolicy},
		checkFunc{CheckIDPackageStability, checkPackageStability},
		checkFunc{CheckIDFalsifierProof, checkFalsifierProof},
	}
}

// prePackageCheckIDs lists the checks that must run before packaging in
// spec order; C12/C13 verify the composed package and run at the final
// gate once it exists.
var prePackageCheckIDs = []string{
	CheckIDIntakeIdentity, CheckIDFieldProvenance, CheckIDSourceResolution,
	CheckIDRefResolution, CheckIDSnapshotIntegrity, CheckIDAdvisory,
	CheckIDPackageVersion, CheckIDReleaseToolchain, CheckIDArtifactIdentity,
	CheckIDEvidenceReferences, CheckIDScopeAlternatives,
}

// PrePackageChecks returns C01–C11 — the set that evaluates before a
// decision package exists.
func PrePackageChecks() []Check {
	all := DefaultChecks()
	out := make([]Check, 0, len(prePackageCheckIDs))
	byID := map[string]Check{}
	for _, c := range all {
		byID[c.ID()] = c
	}
	for _, id := range prePackageCheckIDs {
		out = append(out, byID[id])
	}
	return out
}

// C01 — intake identity: vulnerability ids, package, component and the
// input hash must agree between the raw record, the proposal, the
// normalized finding and the snapshot manifest.
func checkIntakeIdentity(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDIntakeIdentity
	s0 := in.Stage0
	var reasons, repairs []string
	status := CheckPass

	worst := func(s CheckStatus, reason, repair string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, reason)
		if repair != "" {
			repairs = append(repairs, repair)
		}
	}

	if len(s0.Raw.Raw) > 0 && s0.Raw.TicketHash != "" {
		sum := sha256.Sum256(s0.Raw.Raw)
		if got, want := hex.EncodeToString(sum[:]), strings.TrimPrefix(s0.Raw.TicketHash, "sha256:"); got != want {
			worst(CheckConflicting, "raw ticket_hash does not match the record bytes", "re-ingest the intake record; hashes must be computed over the verbatim bytes")
		}
	}

	if f := s0.Input.Finding; f.FindingID == "" {
		worst(CheckError, "normalized finding carries no finding_id", "")
	}
	if s0.Snapshot.InputHash != "" && s0.Input.SHA256 != "" && s0.Snapshot.InputHash != s0.Input.SHA256 {
		worst(CheckConflicting, "snapshot input_hash does not match the normalized finding hash", "rebuild the snapshot from the same normalized finding")
	}

	for _, fv := range s0.Validation.FieldsNamed("vulnerability_ids") {
		switch fv.Status {
		case IntakeValid, IntakeUnverified:
			// UNVERIFIED stays usable: Stage 0 may confirm the id against a
			// separate advisory lane later.
		case IntakeUnavailable:
			worst(CheckUnavailable, "no vulnerability id was extracted or confirmed", "")
		case IntakeConflicting:
			worst(CheckConflicting, "vulnerability id is conflicting: "+fv.Reason, "state a single advisory id the frozen advisory resolves")
		case IntakeInvalid:
			worst(CheckInvalid, "vulnerability id is invalid: "+fv.Reason, "supply a syntactically valid advisory id")
		default:
			worst(CheckUnverified, "vulnerability id status is unknown: "+string(fv.Status), "")
		}
	}
	if fv, ok := s0.Validation.Field("package"); ok {
		worst(fieldStatusCheck(fv), fieldReason("package", fv), "")
	}
	if fv, ok := s0.Validation.Field("component"); ok {
		worst(fieldStatusCheck(fv), fieldReason("component", fv), "")
	}
	return checkResult(id, status, reasons, repairs)
}

// fieldStatusCheck maps an intake field status onto a check status; an
// absent field blocks the check only when it is decision-relevant —
// optional fields degrade to LIMITATIONS, never a negative fact.
func fieldStatusCheck(fv FieldValidation) CheckStatus {
	switch fv.Status {
	case IntakeValid:
		return CheckPass
	case IntakeUnavailable:
		if fv.BlocksRiskReduction {
			return CheckUnavailable
		}
		return CheckLimitation
	case IntakeUnverified:
		return CheckUnverified
	case IntakeConflicting:
		return CheckConflicting
	case IntakeInvalid:
		return CheckInvalid
	default:
		return CheckUnverified
	}
}
func fieldReason(field string, fv FieldValidation) string {
	r := fmt.Sprintf("field %s is %s", field, strings.ToLower(string(fv.Status)))
	if fv.Reason != "" {
		r += ": " + fv.Reason
	}
	return r
}

// checkRank orders check statuses from best to worst; the unknown-status
// branch fails closed so an unrecognized outcome never reads as PASS.
func checkRank(s CheckStatus) int {
	switch s {
	case CheckPass:
		return 0
	case CheckLimitation:
		return 1
	case CheckUnavailable:
		return 2
	case CheckUnverified:
		return 3
	case CheckConflicting:
		return 4
	case CheckInvalid:
		return 5
	case CheckError:
		return 6
	default:
		return 5
	}
}

// C02 — field provenance: every decision-relevant intake field carries a
// deterministic status, and a VALID status names the source that confirmed
// it. LLM-only provenance keeps the field unverified.
func checkFieldProvenance(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDFieldProvenance
	var reasons, repairs []string
	status := CheckPass
	worst := func(s CheckStatus, reason string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, reason)
	}
	for _, fv := range in.Stage0.Validation.Fields {
		if fv.Field == "" || fv.Status == "" {
			worst(CheckInvalid, "field validation entry without field or status")
			continue
		}
		if fv.Status != IntakeValid && hintField(fv.Field) {
			// A severity that contradicts the raw record is a downgrade
			// attempt and must never be accepted silently; every other hint
			// status is a recorded limitation no rule derives from.
			if fv.Field == "severity" && fv.Status == IntakeConflicting {
				worst(CheckConflicting, fieldReason(fv.Field, fv))
				continue
			}
			reasons = append(reasons, fmt.Sprintf("field %s is %s (hint, optional)", fv.Field, strings.ToLower(string(fv.Status))))
			continue
		}
		switch fv.Status {
		case IntakeValid:
			if len(fv.Provenance) == 0 {
				worst(CheckUnverified, fmt.Sprintf("field %s is VALID without provenance — LLM-only confirmation", fv.Field))
				repairs = append(repairs, "confirm field "+fv.Field+" against raw text, advisory or catalog")
			}
		case IntakeUnavailable:
			if fv.BlocksRiskReduction {
				worst(CheckUnavailable, fmt.Sprintf("field %s is unavailable", fv.Field))
			} else {
				// An absent optional field does not touch any decision
				// fact; it stays a note on the check, never a gate.
				reasons = append(reasons, fmt.Sprintf("field %s is unavailable (optional)", fv.Field))
			}
		case IntakeUnverified:
			worst(CheckUnverified, fieldReason(fv.Field, fv))
		case IntakeConflicting:
			worst(CheckConflicting, fieldReason(fv.Field, fv))
		case IntakeInvalid:
			worst(CheckInvalid, fieldReason(fv.Field, fv))
		default:
			worst(CheckUnverified, fmt.Sprintf("field %s carries unknown status %q", fv.Field, fv.Status))
		}
	}
	return checkResult(id, status, reasons, repairs)
}

// C03 — source resolution: the selected catalog entry exists, is a
// repository kind and is the entry the materialization metadata names.
func checkSourceResolution(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDSourceResolution
	s0 := in.Stage0
	if strings.TrimSpace(s0.CatalogEntry.ID) == "" {
		return checkResult(id, CheckUnavailable, []string{"no catalog source was selected"}, nil)
	}
	if !siteRepoKinds[s0.CatalogEntry.Kind] {
		return checkResult(id, CheckInvalid,
			[]string{fmt.Sprintf("catalog entry %q kind %q cannot serve as a source repository", s0.CatalogEntry.ID, s0.CatalogEntry.Kind)}, nil)
	}
	md := s0.Source.Metadata
	if md.SourceID != "" && md.SourceID != s0.CatalogEntry.ID {
		return checkResult(id, CheckConflicting,
			[]string{fmt.Sprintf("materialized source %q does not match selected catalog entry %q", md.SourceID, s0.CatalogEntry.ID)}, nil)
	}
	return passResult(id)
}

// C04 — ref resolution: the selected ref is a member of the bounded
// candidate list (or the absence of the list is honestly recorded) and the
// resolved commit is pinned wherever the candidate list exists.
func checkRefResolution(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDRefResolution
	s0 := in.Stage0
	if len(s0.CandidateRefs) == 0 {
		// kind:local non-git sources legitimately enumerate no refs; the
		// checkout materializes in place and the snapshot pins the content.
		if s0.Snapshot.ContentHash != "" {
			return checkResult(id, CheckLimitation,
				[]string{"source has no enumerable refs; content is pinned by snapshot hash"}, nil)
		}
		return checkResult(id, CheckUnavailable, []string{"no ref candidates and no pinned snapshot"}, nil)
	}
	selectedID := firstNonEmpty(s0.SelectedRef.ID, s0.RefResolution.SelectedID)
	member := false
	for _, c := range s0.CandidateRefs {
		if c.ID != "" && c.ID == selectedID {
			member = true
			break
		}
	}
	if !member {
		return checkResult(id, CheckInvalid,
			[]string{fmt.Sprintf("selected ref %q is not a member of the bounded candidate list", selectedID)},
			[]string{"select a ref from the enumerated candidates"})
	}
	if s0.RefResolution.ResolvedCommit == "" && s0.RefResolution.SelectedID != "" {
		return checkResult(id, CheckUnverified,
			[]string{"selected ref has no resolved commit pinned"}, nil)
	}
	if s0.SelectedRef.Source != "" && s0.CatalogEntry.ID != "" && s0.SelectedRef.Source != s0.CatalogEntry.ID {
		return checkResult(id, CheckConflicting,
			[]string{fmt.Sprintf("selected ref source %q does not match catalog entry %q", s0.SelectedRef.Source, s0.CatalogEntry.ID)}, nil)
	}
	return passResult(id)
}

// C05 — snapshot integrity: schema, content hash, input binding and
// revision status all agree.
func checkSnapshotIntegrity(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDSnapshotIntegrity
	m := in.Stage0.Snapshot
	var reasons []string
	status := CheckPass
	worst := func(s CheckStatus, r string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
	}
	if m.SchemaVersion == "" && m.ContentHash == "" && m.InputHash == "" {
		return checkResult(id, CheckUnavailable, []string{"no snapshot manifest was produced"}, nil)
	}
	if m.SchemaVersion != SnapshotSchemaVersion {
		worst(CheckInvalid, fmt.Sprintf("snapshot schema_version %q is not %s", m.SchemaVersion, SnapshotSchemaVersion))
	}
	if m.ContentHash == "" {
		worst(CheckUnverified, "snapshot carries no content_hash")
	}
	if m.InputHash == "" {
		worst(CheckUnverified, "snapshot is not bound to an input hash")
	}
	switch m.RevisionStatus {
	case FactValid:
		if m.ResolvedRevision == "" && m.Revision != "" {
			worst(CheckUnverified, "revision is marked VALID but no resolved revision is recorded")
		}
	case FactUnavailable:
		if len(in.Stage0.CandidateRefs) > 0 {
			worst(CheckUnverified, "ref candidates exist but the snapshot revision is UNAVAILABLE")
		}
	case FactConflicting:
		worst(CheckConflicting, "snapshot revision conflicts with the selected ref")
	case FactInvalid:
		worst(CheckInvalid, "snapshot revision does not match the selected ref")
	}
	return checkResult(id, status, reasons, nil)
}

// C06 — advisory applicability: a frozen advisory exists, is hash-pinned
// and names the intake vulnerability id. A partial (ticket-derived or
// stub) record is a limitation, not evidence.
func checkAdvisoryApplicability(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDAdvisory
	res := in.Stage0.Resolution
	var reasons []string
	status := CheckPass
	worst := func(s CheckStatus, r string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
	}
	if res == nil {
		return checkResult(id, CheckUnavailable, []string{"no advisory resolution exists"}, nil)
	}
	rec := res.Record
	if rec.Source == "" {
		worst(CheckUnavailable, "every advisory lane missed; the record is a stub")
	}
	if rec.SHA256 == "" && rec.Source != "" {
		worst(CheckUnverified, "advisory record carries no content hash")
	}
	if res.Partial {
		worst(CheckLimitation, "advisory record is partial (ticket-projected or a stub); it cannot ground applicability claims")
	}
	if v := res.Vulnerability; v != nil && rec.Source != "" {
		want := canonicalVulnID(firstVulnID(in.Stage0))
		if want != "" && canonicalVulnID(v.ID) != want && !containsCanonicalID(v.Aliases, want) && canonicalVulnID(rec.ResolvedID) != want {
			worst(CheckConflicting, fmt.Sprintf("frozen advisory %s does not claim the intake vulnerability %s", v.ID, want))
		}
	}
	return checkResult(id, status, reasons, nil)
}

func firstVulnID(s0 Stage0Result) string {
	if len(s0.Proposal.VulnerabilityIDs) > 0 {
		return s0.Proposal.VulnerabilityIDs[0]
	}
	if len(s0.Input.Finding.Vulnerability.IDs) > 0 {
		return s0.Input.Finding.Vulnerability.IDs[0]
	}
	return ""
}

func containsCanonicalID(ids []string, want string) bool {
	for _, id := range ids {
		if canonicalVulnID(id) == want {
			return true
		}
	}
	return false
}

// C07 — component/package/version: the deterministic package check agrees
// with the claim. A graph-proven absence or mismatch is a fact, not a
// failure of the check itself.
func checkPackageVersionFact(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDPackageVersion
	res := in.Stage0.PackageCheck
	switch res.Class {
	case "":
		return checkResult(id, CheckUnavailable, []string{"package/version check never ran"}, nil)
	case CheckAffectedRange, CheckVersionConfirmed:
		return passResult(id)
	case CheckModuleAbsent:
		if in.Stage0.Materials.ModuleGraph != nil && in.Stage0.Materials.ModuleGraph.Complete && len(in.Stage0.Materials.ModuleGraph.Modules) > 0 {
			// Closed-graph absence is the decisive package-absent ground,
			// not a limitation or intake contradiction.
			return passResult(id)
		}
		return checkResult(id, CheckUnverified, append([]string{}, res.Reason),
			[]string{"provide a complete build graph before relying on absence"})
	case CheckVersionMismatch:
		return checkResult(id, CheckConflicting, append([]string{}, res.Reason),
			[]string{"reconcile the claimed version with the version resolved in the build graph"})
	case CheckUnresolved:
		return checkResult(id, CheckUnverified,
			append(append([]string{}, res.Reason), res.Limitations...), nil)
	default:
		return checkResult(id, CheckUnverified, []string{"unknown package check class " + string(res.Class)}, nil)
	}
}

// C08 — release/toolchain: the release toolchain was either proven from
// release evidence or honestly recorded as unknown; a claimed-vs-evidence
// conflict is conflicting.
func checkReleaseToolchain(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDReleaseToolchain
	fact := in.Stage0.ReleaseToolchain
	if fact.Conflict {
		return checkResult(id, CheckConflicting,
			[]string{"release toolchain evidence conflicts with the intake claim"},
			[]string{"supply the release binary or its build evidence"})
	}
	if fact.Version == "" {
		// The release toolchain only decides standard-library applicability
		// (B39): a third-party module claim is version-compared against the
		// module graph, so an unknown release Go version is a limitation,
		// never a gate on such a decision.
		if stdlibClaim(in.Stage0) {
			return checkResult(id, CheckUnavailable,
				append([]string{"release toolchain is unknown"}, fact.Limitations...), nil)
		}
		return checkResult(id, CheckLimitation,
			append([]string{"release toolchain is unknown (irrelevant to a module claim)"}, fact.Limitations...), nil)
	}
	if in.Stage0.Toolchain.Mismatch {
		return checkResult(id, CheckLimitation,
			[]string{fmt.Sprintf("release toolchain go%s could not be provisioned; analysis ran on the local toolchain", fact.Version)}, nil)
	}
	return passResult(id)
}

// C09 — artifact identity: declared SBOM/binary/deploy artifacts resolve
// to pinned digests; an absent optional artifact is a limitation.
func checkArtifactIdentity(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDArtifactIdentity
	m := in.Stage0.Snapshot
	t := in.Stage0.Input.Finding.Target
	var reasons []string
	status := CheckPass
	worst := func(s CheckStatus, r string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
	}
	declared := map[string]string{}
	for _, a := range m.Artifacts {
		if a.Role != "" {
			declared[a.Role] = a.Path
		}
		if a.SHA256 == "" {
			worst(CheckUnverified, fmt.Sprintf("artifact %s carries no digest", a.Path))
		}
	}
	for role, path := range map[string]string{"sbom": t.SBOM, "binary": t.Binary} {
		if path == "" {
			continue
		}
		if _, ok := declared[role]; !ok {
			worst(CheckUnavailable, fmt.Sprintf("declared %s artifact %s is not in the snapshot manifest", role, path))
		}
	}
	return checkResult(id, status, reasons, nil)
}

// C10 — evidence references: the fact gate's per-reference verdicts are
// projected verbatim — a non-VALID status is mapped, never rewritten.
func checkEvidenceReferences(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDEvidenceReferences
	fv := in.Validation
	var reasons, repairs []string
	status := CheckPass
	worst := func(s CheckStatus, r, repair string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
		if repair != "" {
			repairs = append(repairs, repair)
		}
	}
	switch fv.Status {
	case ValidationComplete:
	case ValidationPartial:
		worst(CheckUnverified, "fact validation is PARTIAL: some references are unresolved", "")
	case ValidationFailed:
		worst(CheckInvalid, "fact validation FAILED: some references are broken or conflicting", "")
	case "":
		worst(CheckUnavailable, "no fact gate report exists", "")
	default:
		worst(CheckUnverified, "unknown fact validation status "+string(fv.Status), "")
	}
	for _, rc := range fv.References {
		name := rc.EvidenceID
		if name == "" {
			name = rc.Subject
		}
		switch rc.Status {
		case FactValid:
		case FactUnreferenced:
			worst(CheckUnverified, "decision-relevant claim "+name+" is unreferenced", rc.ExpectedRepair)
		case FactUnavailable:
			worst(CheckUnavailable, "reference "+name+" is unavailable: "+rc.Reason, rc.ExpectedRepair)
		case FactConflicting:
			worst(CheckConflicting, "reference "+name+" is conflicting: "+rc.Reason, rc.ExpectedRepair)
		case FactInvalid:
			worst(CheckInvalid, "reference "+name+" is invalid: "+rc.Reason, rc.ExpectedRepair)
		default:
			worst(CheckUnverified, "reference "+name+" has unknown status "+string(rc.Status), "")
		}
	}
	return checkResult(id, status, reasons, repairs)
}

// C11 — scope and alternatives: a REFUTES fact (a proven absence) must sit
// on a closed, enumerable scope — a local observation, a PARTIAL tool
// result or a scoped package claim can never ground global negation.
func checkScopeAlternatives(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDScopeAlternatives
	var reasons, repairs []string
	status := CheckPass
	worst := func(s CheckStatus, r, repair string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
		if repair != "" {
			repairs = append(repairs, repair)
		}
	}
	for _, f := range in.Facts {
		if f.Status != ObsRefutes {
			continue
		}
		if !closedNegationScope(f) {
			worst(CheckUnverified,
				fmt.Sprintf("fact %s (%s) claims an absence from scope %q — a local observation cannot prove global negation", f.ID, f.Kind, f.Scope),
				"re-run the check over a closed scope (complete build graph, full snapshot) or downgrade the claim")
		}
		if len(f.Provenance) == 0 {
			worst(CheckUnverified, "absence fact "+f.ID+" carries no provenance", "")
		}
	}
	return checkResult(id, status, reasons, repairs)
}

// closedNegationScope reports whether a refuting fact rests on a closed
// enumeration — the complete build graph, the full snapshot manifest or
// the module version graph — rather than a partial tool observation.
func closedNegationScope(f DecisionFact) bool {
	for _, s := range []string{f.Scope} {
		switch strings.ToLower(s) {
		case "build-graph", "module_graph", "module-graph", "snapshot", "snapshot-manifest":
			return true
		case "falsifier":
			// The falsifier report is a closed enumeration: the verifier
			// walks every proposal the assessment declared, so "no proposal"
			// is a complete statement about that report — not a local
			// observation standing in for global negation.
			return true
		}
	}
	for _, p := range f.Provenance {
		switch strings.ToLower(p) {
		case "module_graph", "go list -m all", "vendor/modules.txt", "snapshot.json":
			return true
		}
	}
	return false
}

// C12 — risk/disposition policy: the recorded recommendation must equal
// the one the rules permit over the same facts, and must never be stronger
// than the recomputed ceiling or weaker than an established falsifier
// without a recorded demotion.
func checkRiskPolicy(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDRiskPolicy
	if in.Package == nil {
		return checkResult(id, CheckUnavailable, []string{"no decision package to verify"}, nil)
	}
	p := *in.Package
	rec := p.MachineDisposition.Recommendation
	if !rec.Valid() {
		return checkResult(id, CheckInvalid, []string{"invalid recommendation " + string(rec)}, nil)
	}
	if b := p.MachineDisposition.Baseline; b != nil && strengthOf(b.Disposition) > strengthOf(rec) {
		return checkResult(id, CheckConflicting,
			[]string{fmt.Sprintf("recommendation %s outruns the baseline disposition %s", rec, b.Disposition)}, nil)
	}
	if p.MachineDisposition.Baseline == nil && rec != RecommendationUnchanged {
		return checkResult(id, CheckConflicting,
			[]string{fmt.Sprintf("recommendation %s has no recorded baseline metadata to start from", rec)}, nil)
	}
	candidate, rule := evaluateDecisionRules(in.Rules, decisionFactSet(in.Facts))
	if rec == candidate {
		return passResult(id)
	}
	if strengthOf(rec) < strengthOf(candidate) {
		// The package is more conservative than the computed ceiling — the
		// composer recorded a demotion; verify one was actually registered.
		for _, d := range p.MachineDisposition.Demotions {
			if strings.Contains(d, rule.ID) || strings.Contains(d, string(candidate)) {
				return passResult(id)
			}
		}
		return checkResult(id, CheckUnverified,
			[]string{fmt.Sprintf("recommendation %s is below the rule-derived %s without a recorded demotion", rec, candidate)}, nil)
	}
	return checkResult(id, CheckConflicting,
		[]string{fmt.Sprintf("recommendation %s exceeds the rule-derived ceiling %s (rule %s)", rec, candidate, rule.ID)}, nil)
}

// C13 — package and stability: the composed package passes strict
// schema/contract validation, and a recorded stability result is a known
// value. Stability *drift* is handled upstream as a technical error; the
// check only validates the record's coherence.
func checkPackageStability(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDPackageStability
	if in.Package == nil {
		return checkResult(id, CheckUnavailable, []string{"no decision package to verify"}, nil)
	}
	p := *in.Package
	var reasons []string
	status := CheckPass
	worst := func(s CheckStatus, r string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
	}
	if err := p.Validate(); err != nil {
		worst(CheckInvalid, "package contract: "+err.Error())
	}
	switch s := p.TechnicalAssessment.StabilityResult; s {
	case "", "stable", "unstable", "unstable_demoted", "drift_blocked":
	case "drift":
		worst(CheckInvalid, "stability result drift must surface as a technical error, not a package")
	default:
		worst(CheckInvalid, "unknown stability_result "+s)
	}
	return checkResult(id, status, reasons, nil)
}

// RunChecks evaluates checks in order and returns one result per check —
// machine statuses only; a recommendation is never produced here.
func RunChecks(ctx context.Context, checks []Check, in CheckInput) []CheckResult {
	if ctx == nil {
		ctx = context.Background()
	}
	out := make([]CheckResult, 0, len(checks))
	for _, c := range checks {
		res := c.Evaluate(ctx, in)
		res.ID = c.ID()
		out = append(out, res)
	}
	return out
}

// CheckResultsByID indexes a result slice for the composer; the first
// result per id wins, so a caller cannot smuggle a second verdict under a
// duplicate id.
func CheckResultsByID(results []CheckResult) map[string]CheckResult {
	out := make(map[string]CheckResult, len(results))
	for _, r := range results {
		if _, dup := out[r.ID]; dup {
			continue
		}
		out[r.ID] = r
	}
	return out
}

// C14 — falsifier proof integrity: the persisted proof report, the admitted
// fact derived from it and the package that rests on it must agree. An
// unsupported proposal is a limitation (the finding simply stays UNCHANGED);
// a malformed, forged or foreign proof is a technical error, because a
// package resting on it must never be emitted as if nothing happened.
func checkFalsifierProof(_ context.Context, in CheckInput) CheckResult {
	id := CheckIDFalsifierProof
	var reasons, repairs []string
	status := CheckPass
	worst := func(s CheckStatus, r, repair string) {
		if checkRank(s) > checkRank(status) {
			status = s
		}
		reasons = append(reasons, r)
		if repair != "" {
			repairs = append(repairs, repair)
		}
	}
	admittedFacts := 0
	for _, f := range in.Facts {
		if f.Kind == FactFalsifierAdmitted && f.Status == ObsSupports {
			admittedFacts++
		}
	}
	if in.Falsifiers == nil {
		if admittedFacts > 0 {
			worst(CheckInvalid,
				"falsifier.admitted is SUPPORTS but no falsifier report was persisted",
				"persist the verifier report next to the decision package")
		}
		return checkResult(id, status, reasons, repairs)
	}
	r := *in.Falsifiers
	for _, v := range ValidateProofReport(r) {
		worst(CheckInvalid, v.Reason, v.Repair)
	}

	proposals := map[string]FalsifierProposal{}
	for _, p := range in.Assessment.FalsifierProposals {
		proposals[p.ID] = p
	}
	verified := 0
	snap := in.Stage0.Snapshot.ContentHash
	for i := range r.Proofs {
		p := r.Proofs[i]
		violations := ValidateProofCertificate(p, proposals, snap)
		aborted := len(violations) == 1 && violations[0].Class == ViolationNoProposal
		for _, v := range violations {
			worst(CheckInvalid, v.Reason, v.Repair)
		}
		if aborted {
			// A proof with no persisted proposal stops at the binding
			// step — the same early stop the contract performs.
			continue
		}
		switch p.Status {
		case FalsifierVerified:
			verified++
		default:
			// Unsupported or unknown proofs are limitations, never errors:
			// the finding simply keeps its conservative recommendation.
			worst(CheckUnverified,
				fmt.Sprintf("proof %s is %s (basis %s)", p.ID, p.Status, p.Basis),
				"admit only a checker-verified falsifier")
		}
	}
	if verified > 0 && admittedFacts == 0 {
		worst(CheckInvalid,
			"a proof is VERIFIED but falsifier.admitted is not SUPPORTS",
			"project the verified proof onto the admitted decision fact")
	}
	if in.Package != nil {
		if want := in.Package.Audit.RulesetHash; want != "" && r.RuleSetHash != "" && want != r.RuleSetHash {
			worst(CheckInvalid,
				fmt.Sprintf("falsifier report ruleset %q does not match the package ruleset %q", r.RuleSetHash, want),
				"re-run the verifier under the package ruleset")
		}
	}
	return checkResult(id, status, reasons, repairs)
}

// stdlibClaim reports whether the finding's package claim resolves to the
// standard library — the only claim class whose applicability needs the
// release Go version. An unknown package stays conservative (true).
func stdlibClaim(s0 Stage0Result) bool {
	path := firstNonEmpty(s0.PackageCheck.ResolvedPath, s0.PackageCheck.ClaimedPath,
		s0.Input.Finding.Component.Package)
	path = strings.TrimSpace(path)
	if path == "" {
		return true
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}
