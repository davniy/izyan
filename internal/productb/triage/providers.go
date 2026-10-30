package triage

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/exposure"
	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/toolchain"
)

// Decision-fact statuses returned by fact providers (spec §11.1). They are
// deliberately distinct from the fact gate's FactStatus vocabulary
// (VALID/INVALID/...): a provider observation states what the evidence
// establishes — SUPPORTS/REFUTES the named fact — never a recommendation.
const (
	ObsSupports    = "SUPPORTS"
	ObsRefutes     = "REFUTES"
	ObsUnavailable = "UNAVAILABLE"
	ObsConflicting = "CONFLICTING"
	ObsLimitation  = "LIMITATION"
)

// Canonical decision-fact kinds the composer understands. Providers outside
// this set still deliver facts — they simply never become decision-relevant
// unless a profile or rule names them.
const (
	FactVulnerabilityID          = "vulnerability_id"
	FactComponentIdentity        = "component_identity"
	FactSource                   = "source"
	FactRef                      = "ref"
	FactCommit                   = "commit"
	FactSnapshotIntegrity        = "snapshot_integrity"
	FactAdvisory                 = "advisory"
	FactBaseline                 = "baseline"
	FactPackageClaim             = "package_claim"
	FactPackagePresence          = "package_presence"
	FactPackageAffected          = "package_affected"
	FactComponentNotPresent      = "component_not_present"
	FactModuleGraph              = "module_graph_complete"
	FactTestOnlyDependency       = "test_only_dependency"
	FactReleaseToolchain         = "release_toolchain"
	FactAnalysisToolchain        = "analysis_toolchain"
	FactDeploymentExposure       = "deployment_exposure"
	FactToolObservation          = "tool_observation"
	FactFalsifierProposalPresent = "falsifier_proposal_present"
	FactFalsifierKernelPresent   = "falsifier_kernel_present"
	FactFalsifierAdmitted        = "falsifier_admitted"
	FactLLMVerdict               = "llm_verdict"
	FactProviderError            = "provider"
)

// ProviderInput is everything a fact provider may inspect: the resolved
// Stage 0 result, the agent's structured result with its gate validation,
// the recorded deterministic observations and the deterministic falsifier
// report. A provider never sees credentials, secrets or the semantic verdict
// as a mandate — it returns scoped facts and limitations only.
type ProviderInput struct {
	Stage0         Stage0Result
	Observations   []evidencetools.Observation
	Assessment     Assessment
	FactValidation FactValidation
	Recorded       []RecordedObservation
	Falsifiers     *FalsifierReport
}

// FactProvider collects decision facts for one bounded scope (spec §11.1).
// Providers return observations with provenance; they never return a
// recommendation and never let an absent input read as a negative fact.
type FactProvider interface {
	Name() string
	Collect(context.Context, ProviderInput) ([]DecisionFact, error)
}

// DefaultProviders returns the standard provider set in deterministic
// order: Stage 0 resolution facts, package/version, toolchain, materials
// (incl. deployment exposure) and recorded tool observations.
func DefaultProviders() []FactProvider {
	return []FactProvider{
		Stage0FactsProvider{},
		PackageFactsProvider{},
		ToolchainFactsProvider{},
		MaterialsFactsProvider{},
		ObservationsProvider{},
		FalsifierFactsProvider{},
	}
}

// FalsifierFactsProvider is the provider facade for the falsifier report.
type FalsifierFactsProvider struct{}

// FalsifierFactsProvider projects the deterministic falsifier report onto
// ordinary decision facts. It never inspects proposal prose and never turns
// an agent verdict into a fact: the only admitted signal is a VERIFIED proof
// issued by the deterministic verifier, and its absence is a structural fact
// (no proposal), not a safety claim.
func (FalsifierFactsProvider) Name() string { return "falsifier" }

func (FalsifierFactsProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	proofs := []FalsifierProof(nil)
	if in.Falsifiers != nil {
		proofs = in.Falsifiers.Proofs
	}
	reportHash := ""
	if in.Falsifiers != nil {
		reportHash = in.Falsifiers.Hash
	}
	base := []string{"falsifier-verification.v1"}
	if reportHash != "" {
		base = append(base, "report:"+reportHash)
	}
	if len(proofs) == 0 {
		present := newFact("falsifier", FactFalsifierProposalPresent, ObsRefutes, "proposals", "falsifier", append(append([]string(nil), base...), "source:proposal"))
		kernel := newFact("falsifier", FactFalsifierKernelPresent, ObsRefutes, "kernel", "falsifier", append(append([]string(nil), base...), "source:kernel"))
		admitted := newFact("falsifier", FactFalsifierAdmitted, ObsRefutes, "admitted", "falsifier", append([]string(nil), base...))
		return []DecisionFact{present, kernel, admitted}, nil
	}
	proposalProofs := make([]FalsifierProof, 0, len(proofs))
	kernels := make([]FalsifierProof, 0, len(proofs))
	for _, p := range proofs {
		if isKernelMintedProof(p) {
			kernels = append(kernels, p)
		} else {
			proposalProofs = append(proposalProofs, p)
		}
	}
	present := newFact("falsifier", FactFalsifierProposalPresent, ObsRefutes, "proposals", "falsifier", append(append([]string(nil), base...), "source:proposal"))
	if len(proposalProofs) > 0 {
		present.Status = ObsSupports
		present.EvidenceRefs = proposalRefs(proposalProofs)
	}
	kernel := newFact("falsifier", FactFalsifierKernelPresent, ObsRefutes, "kernel", "falsifier", append(append([]string(nil), base...), "source:kernel"))
	if len(kernels) > 0 {
		kernel.Status = ObsSupports
		kernel.EvidenceRefs = proofRefs(kernels)
	}
	admitted := newFact("falsifier", FactFalsifierAdmitted, ObsUnavailable, "admitted", "falsifier", append([]string(nil), base...))
	for i := range proofs {
		p := &proofs[i]
		if p.Status != FalsifierVerified || p.Basis != BasisCheckerVerified {
			continue
		}
		admitted.Status = ObsSupports
		admitted.EvidenceRefs = append([]string(nil), p.EvidenceRefs...)
		admitted.Provenance = append([]string(nil), base...)
		admitted.Provenance = append(admitted.Provenance, "proof:"+p.ID, "rule:"+p.RuleID+"@"+p.RuleVersion)
		if isKernelMintedProof(*p) {
			admitted.Provenance = append(admitted.Provenance, "source:kernel")
		} else {
			admitted.Provenance = append(admitted.Provenance, "source:proposal")
		}
		break
	}
	return []DecisionFact{present, kernel, admitted}, nil
}

func isKernelMintedProof(p FalsifierProof) bool {
	return CheckerMintedProof(p)
}

func proofRefs(proofs []FalsifierProof) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range proofs {
		for _, r := range p.EvidenceRefs {
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

func proposalRefs(proofs []FalsifierProof) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range proofs {
		for _, r := range p.EvidenceRefs {
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

func newFact(provider, kind, status, subject, scope string, provenance []string) DecisionFact {
	return DecisionFact{
		ID:         factID(provider, kind, subject),
		Kind:       kind,
		Status:     status,
		Subject:    subject,
		Scope:      scope,
		Provenance: provenance,
	}
}

// factID derives a stable, replayable fact id from provider, kind and
// subject — never random, so identical runs produce identical packages.
func factID(provider, kind, subject string) string {
	return fmt.Sprintf("fact-%s-%s-%s", provider, kind, shortHashToken(kind+"\x00"+subject))
}

func shortHashToken(s string) string {
	sum := hashBytes([]byte(s))
	if len(sum) > 10 {
		return sum[:10]
	}
	return sum
}

// intakeFieldStatus looks up the deterministic status an intake field
// received during validation.
func intakeFieldStatus(v IntakeValidation, field string) (IntakeFieldStatus, []string) {
	if fv, ok := v.Field(field); ok {
		return fv.Status, fv.Provenance
	}
	return "", nil
}

// intakeStatusToObs maps an intake validation status onto a provider
// observation status. UNVERIFIED and INVALID both land on UNAVAILABLE —
// the fact is not established; INVALID is never read as refutation.
func intakeStatusToObs(s IntakeFieldStatus) string {
	switch s {
	case IntakeValid:
		return ObsSupports
	case IntakeConflicting:
		return ObsConflicting
	case IntakeUnverified, IntakeUnavailable, IntakeInvalid:
		return ObsUnavailable
	default:
		return ObsUnavailable
	}
}

// Stage0FactsProvider projects the Stage 0 resolution outcome — intake
// identity, selected source/ref/commit, snapshot hash, advisory identity
// and the authoritative baseline — into decision facts.
type Stage0FactsProvider struct{}

// Name implements FactProvider.
func (Stage0FactsProvider) Name() string { return "stage0" }

// Collect implements FactProvider.
func (Stage0FactsProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	s0 := in.Stage0
	var out []DecisionFact

	if len(s0.Proposal.VulnerabilityIDs) > 0 || len(s0.Input.Finding.Vulnerability.IDs) > 0 {
		st, prov := intakeFieldStatus(s0.Validation, "vulnerability_ids")
		out = append(out, newFact("stage0", FactVulnerabilityID, intakeStatusToObs(st),
			firstVulnID(s0), "intake", prov))
	}
	if name := strings.TrimSpace(firstNonEmpty(s0.Proposal.Component, s0.Proposal.Product)); name != "" {
		st, prov := intakeFieldStatus(s0.Validation, "component")
		if st == "" {
			st, prov = intakeFieldStatus(s0.Validation, "product")
		}
		out = append(out, newFact("stage0", FactComponentIdentity, intakeStatusToObs(st),
			name, "snapshot", prov))
	}

	if id := strings.TrimSpace(s0.CatalogEntry.ID); id != "" {
		out = append(out, newFact("stage0", FactSource, ObsSupports, id, "stage0",
			[]string{"catalog", "stage0.json"}))
	}
	if name := strings.TrimSpace(s0.SelectedRef.Name); name != "" {
		out = append(out, newFact("stage0", FactRef, ObsSupports, name, "stage0",
			[]string{"ref_resolution"}))
	}
	if commit := strings.TrimSpace(firstNonEmpty(s0.RefResolution.ResolvedCommit, s0.SelectedRef.Commit)); commit != "" {
		out = append(out, newFact("stage0", FactCommit, ObsSupports, commit, "stage0",
			[]string{"ref_resolution"}))
	}
	if h := strings.TrimSpace(s0.Snapshot.ContentHash); h != "" {
		out = append(out, newFact("stage0", FactSnapshotIntegrity, ObsSupports, h, "snapshot",
			[]string{"snapshot.json"}))
	}
	switch rec := s0.Advisory; {
	case rec.Source == "":
		out = append(out, newFact("stage0", FactAdvisory, ObsUnavailable,
			firstVulnID(s0), "advisory", []string{"advisory_resolution"}))
	case s0.Resolution != nil && s0.Resolution.Partial:
		out = append(out, newFact("stage0", FactAdvisory, ObsLimitation,
			firstNonEmpty(rec.ResolvedID, rec.ID), "advisory", []string{string(rec.Source)}))
	default:
		out = append(out, newFact("stage0", FactAdvisory, ObsSupports,
			firstNonEmpty(rec.ResolvedID, rec.ID), "advisory", []string{string(rec.Source)}))
	}
	if baseline, _, err := composeBaseline(s0, ""); err == nil && baseline != nil {
		out = append(out, newFact("stage0", FactBaseline, ObsSupports,
			baseline.Severity, "baseline", []string{baseline.Source}))
	}
	return out, nil
}

// PackageFactsProvider projects the deterministic package/version check
// (CheckPackageVersion) into facts: the claim's resolvability, the
// package's presence in the build graph and whether the resolved version
// falls inside an advisory affected range. MODULE_ABSENT is a REFUTES
// against a closed build graph — the deterministic falsifier — while an
// UNRESOLVED check is UNAVAILABLE, never an absence.
type PackageFactsProvider struct{}

// Name implements FactProvider.
func (PackageFactsProvider) Name() string { return "package" }

// Collect implements FactProvider.
func (PackageFactsProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	res := in.Stage0.PackageCheck
	if res.Class == "" {
		return nil, nil
	}
	prov := res.Provenance
	if len(prov) == 0 && res.EvidenceSource != "" {
		prov = []string{res.EvidenceSource}
	}
	subject := firstNonEmpty(res.ResolvedPath, res.ClaimedPath)
	// Module absence is grounded only in module-graph completeness. A complete
	// package inventory is a different, build-scoped material and never repairs
	// missing module coverage or expands this claim to whole-upstream source.
	complete := in.Stage0.Materials.ModuleGraph != nil && in.Stage0.Materials.ModuleGraph.Complete && len(in.Stage0.Materials.ModuleGraph.Modules) > 0
	var out []DecisionFact

	claimStatus := ObsSupports
	switch res.Class {
	case CheckUnresolved:
		claimStatus = ObsUnavailable
	case CheckVersionMismatch:
		claimStatus = ObsConflicting
	case CheckModuleAbsent:
		if !complete {
			claimStatus = ObsUnavailable
		}
	}
	out = append(out, newFact("package", FactPackageClaim, claimStatus, subject, "build-graph", prov))

	switch res.Class {
	case CheckModuleAbsent:
		if complete {
			// This is the decisive package-absent falsifier. It is a
			// REFUTES observation for package.present, not a conflict
			// with the ticket's valid finding identity.
			out = append(out, newFact("package", FactComponentNotPresent, ObsSupports, subject, "build-graph", prov))
			out = append(out, newFact("package", FactPackagePresence, ObsRefutes, subject, "build-graph", prov))
			out = append(out, newFact("package", FactPackageAffected, ObsRefutes, subject, "build-graph", prov))
		} else {
			// A hand-built/inconsistent MODULE_ABSENT record cannot be
			// trusted when the graph is not closed.
			out = append(out, newFact("package", FactPackagePresence, ObsUnavailable, subject, "build-graph", prov))
			out = append(out, newFact("package", FactPackageAffected, ObsUnavailable, subject, "build-graph", prov))
		}
	case CheckUnresolved:
		out = append(out, newFact("package", FactPackagePresence, ObsUnavailable, subject, "build-graph", prov))
	case CheckVersionMismatch:
		out = append(out, newFact("package", FactPackagePresence, ObsSupports, subject, "build-graph", prov))
		out = append(out, newFact("package", FactPackageAffected, ObsUnavailable, subject, "build-graph", prov))
	case CheckAffectedRange:
		out = append(out, newFact("package", FactPackagePresence, ObsSupports, subject, "build-graph", prov))
		out = append(out, newFact("package", FactPackageAffected, ObsSupports, subject, "build-graph", prov))
	case CheckVersionConfirmed:
		out = append(out, newFact("package", FactPackagePresence, ObsSupports, subject, "build-graph", prov))
		if len(in.Stage0.Resolution.Projection.AffectedVersions) > 0 || len(resolutionRanges(in.Stage0)) > 0 {
			out = append(out, newFact("package", FactPackageAffected, ObsRefutes, subject, "build-graph", prov))
		} else {
			out = append(out, newFact("package", FactPackageAffected, ObsUnavailable, subject, "build-graph", prov))
		}
	}
	return out, nil
}

// resolutionRanges reports whether the resolved advisory declares any
// affected range for the check's resolved module — VERSION_CONFIRMED only
// refutes affectedness when ranges existed to compare against.
func resolutionRanges(s0 Stage0Result) []domain.VersionRange {
	if s0.Resolution == nil {
		return nil
	}
	if p := s0.Resolution.Projection; p.Module != "" {
		return p.AffectedVersions
	}
	return nil
}

// ToolchainFactsProvider projects the release-toolchain evidence and the
// provisioned analysis toolchain. An unknown release toolchain is
// UNAVAILABLE — never evidence of safety — and a provisioned-but-mismatched
// analysis toolchain REFUTES the "analysis ran under the release toolchain"
// claim. Resolve is optional: when nil the provider trusts the toolchain
// Stage 0 already provisioned and never re-dials.
type ToolchainFactsProvider struct {
	Resolve func(context.Context, string) (toolchain.Toolchain, []string)
}

// Name implements FactProvider.
func (ToolchainFactsProvider) Name() string { return "toolchain" }

// Collect implements FactProvider.
func (p ToolchainFactsProvider) Collect(ctx context.Context, in ProviderInput) ([]DecisionFact, error) {
	fact := in.Stage0.ReleaseToolchain
	var out []DecisionFact
	switch {
	case fact.Conflict:
		out = append(out, newFact("toolchain", FactReleaseToolchain, ObsConflicting,
			firstNonEmpty(fact.Claimed, fact.Version), "release", []string{string(fact.Source)}))
	case fact.Version == "":
		out = append(out, newFact("toolchain", FactReleaseToolchain, ObsUnavailable,
			"release", "release", []string{string(fact.Source)}))
	default:
		out = append(out, newFact("toolchain", FactReleaseToolchain, ObsSupports,
			fact.Version, "release", []string{string(fact.Source)}))
	}

	tc := in.Stage0.Toolchain
	if (tc.Mode == "" && tc.Version == "" && tc.GoBin == "") && p.Resolve != nil && fact.Version != "" {
		tc, _ = p.Resolve(ctx, fact.Version)
	}
	switch {
	case tc.Mismatch:
		out = append(out, newFact("toolchain", FactAnalysisToolchain, ObsRefutes,
			firstNonEmpty(tc.Version, "local"), "toolchain", []string{string(tc.Mode)}))
	case tc.Version != "" || tc.Mode == toolchain.ModeLocal:
		out = append(out, newFact("toolchain", FactAnalysisToolchain, ObsSupports,
			tc.Version, "toolchain", []string{string(tc.Mode)}))
	default:
		out = append(out, newFact("toolchain", FactAnalysisToolchain, ObsUnavailable,
			"local", "toolchain", nil))
	}
	return out, nil
}

// MaterialsFactsProvider projects the collected material set: one fact per
// material (availability is a fact, never content), the module-graph
// completeness flag and the deployment perimeter classified at Stage 0.
// An empty deploy scan is UNAVAILABLE — never evidence of isolation.
type MaterialsFactsProvider struct{}

// Name implements FactProvider.
func (MaterialsFactsProvider) Name() string { return "materials" }

// Collect implements FactProvider.
func (MaterialsFactsProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	set := in.Stage0.Materials
	var out []DecisionFact
	for _, m := range set.Materials {
		status := ObsUnavailable
		switch m.Availability {
		case MaterialAvailable:
			status = ObsSupports
		case MaterialInvalid:
			status = ObsConflicting
		}
		out = append(out, DecisionFact{
			ID:         factID("materials", m.Kind, m.ID),
			Kind:       m.Kind,
			Status:     status,
			Subject:    m.ID,
			Scope:      m.Scope,
			Provenance: m.Provenance,
		})
	}
	if g := set.ModuleGraph; g != nil {
		status := ObsRefutes
		if g.Complete {
			status = ObsSupports
		}
		out = append(out, newFact("materials", FactModuleGraph, status,
			g.Source, "build-graph", []string{g.Source}))
	} else {
		out = append(out, newFact("materials", FactModuleGraph, ObsUnavailable,
			"module-graph", "build-graph", nil))
	}
	if f := testOnlyFact(in.Stage0); f != nil {
		out = append(out, *f)
	}
	if d := set.Deploy; d != nil {
		switch d.Perimeter {
		case domain.PerimeterClusterInternal, domain.PerimeterPublic:
			out = append(out, newFact("materials", FactDeploymentExposure, ObsSupports,
				d.Perimeter, "deployment", []string{"deploy_scan"}))
		default:
			out = append(out, newFact("materials", FactDeploymentExposure, ObsUnavailable,
				firstNonEmpty(d.Perimeter, domain.PerimeterUnknown), "deployment", []string{"deploy_scan"}))
		}
	}
	return out, nil
}

// ObservationsProvider projects recorded evidencetools observations (and
// the audit-trail tool events when no typed list was supplied) into scoped
// facts. An observation never carries a verdict; ERROR and UNSUPPORTED
// calls are UNAVAILABLE, and a PARTIAL scope is always accompanied by a
// LIMITATION fact so the composer cannot misread local coverage as global
// negation.
type ObservationsProvider struct{}

// Name implements FactProvider.
func (ObservationsProvider) Name() string { return "observations" }

// Collect implements FactProvider.
func (ObservationsProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	var out []DecisionFact
	for _, obs := range in.Observations {
		status := ObsSupports
		switch obs.ToolStatus {
		case evidencetools.StatusError, evidencetools.StatusUnsupported:
			status = ObsUnavailable
		}
		scope := obs.Scope
		if scope == "" {
			scope = "observation"
		}
		f := newFact("observations", FactToolObservation, status,
			firstNonEmpty(obs.Fact, obs.Tool), scope, []string{"det:" + obs.ID})
		f.ID = factID("observations", obs.Tool, obs.ID)
		f.EvidenceRefs = append(f.EvidenceRefs, obs.EvidenceRefs...)
		out = append(out, f)
		if obs.Completeness == evidencetools.CompletenessPartial || obs.Completeness == evidencetools.CompletenessUnknown {
			out = append(out, newFact("observations", "observation_coverage", ObsLimitation,
				obs.ID, scope, []string{"det:" + obs.ID}))
		}
	}
	if len(in.Observations) > 0 {
		return out, nil
	}
	// Audit fallback: rebuild observation facts from recorded tool_call
	// events so replay composes an identical package without the session.
	for _, ev := range in.Stage0.Events {
		if ev.Type != AuditEventToolCall || ev.ObservationID == "" {
			continue
		}
		status := ObsSupports
		if ev.Status != "" && ev.Status != "ok" {
			status = ObsUnavailable
		}
		scope := ev.Scope
		if scope == "" {
			scope = "observation"
		}
		f := newFact("observations", FactToolObservation, status,
			ev.Tool, scope, []string{"det:" + ev.ObservationID})
		f.EvidenceRefs = append(f.EvidenceRefs, "det:"+ev.ObservationID)
		out = append(out, f)
		if ev.ReachEvidence {
			out = append(out, newFact("observations", "reachability_evidence", ObsSupports,
				ev.Tool, scope, []string{"det:" + ev.ObservationID}))
		}
	}
	return out, nil
}

// DeployScanProvider adapts internal/exposure into a fact provider
// (spec §12.2): it runs ScanDeployWithOptions over the configured roots
// and classifies the perimeter with ClassifyPerimeter. The scan's product
// attribution is exact; a missing manifest or an empty scan is UNAVAILABLE
// — never evidence of isolation — and the provider never emits a
// recommendation.
type DeployScanProvider struct {
	// RootPath scans deployment manifests under the materialized source
	// root. Empty falls back to the materialized root of the Stage 0
	// result, then produces no facts at all.
	RootPath    string
	ExtraPaths  []string
	ArchivePath string
	// ProductNames bound the perimeter attribution: only deploy facts
	// whose owner names the analyzed product may scope its inbound
	// reachability. Empty derives candidates from the intake proposal.
	ProductNames []string
	// Scan and Classify are injectable for deterministic tests; nil uses
	// the real exposure package entry points.
	Scan     func(exposure.DeployScanOptions) ([]domain.ExposureFact, error)
	Classify func([]domain.ExposureFact, []string) domain.PerimeterAssessment
}

// Name implements FactProvider.
func (DeployScanProvider) Name() string { return "deploy-scan" }

// Collect implements FactProvider.
func (p DeployScanProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	root := p.RootPath
	if root == "" {
		root = in.Stage0.Source.Root
	}
	if root == "" && len(p.ExtraPaths) == 0 && p.ArchivePath == "" {
		return nil, nil
	}
	scan := p.Scan
	if scan == nil {
		scan = exposure.ScanDeployWithOptions
	}
	classify := p.Classify
	if classify == nil {
		classify = exposure.ClassifyPerimeter
	}
	facts, err := scan(exposure.DeployScanOptions{
		RootPath:    root,
		ExtraPaths:  p.ExtraPaths,
		ArchivePath: p.ArchivePath,
	})
	if err != nil {
		return nil, fmt.Errorf("deploy scan: %w", err)
	}
	product := p.ProductNames
	if len(product) == 0 {
		product = deployProductNames(in.Stage0)
	}
	perimeter := classify(facts, product).Perimeter

	var out []DecisionFact
	for i, f := range facts {
		subject := firstNonEmpty(f.Target, f.Address)
		out = append(out, DecisionFact{
			ID:         factID("deploy-scan", "deploy_surface", fmt.Sprintf("%s#%d", subject, i)),
			Kind:       "deploy_surface",
			Status:     ObsSupports,
			Subject:    subject,
			Scope:      "deployment",
			Provenance: []string{"deploy_scan", filepath.ToSlash(f.File)},
		})
	}
	switch perimeter {
	case domain.PerimeterClusterInternal, domain.PerimeterPublic:
		out = append(out, newFact("deploy-scan", FactDeploymentExposure, ObsSupports,
			perimeter, "deployment", []string{"deploy_scan"}))
	default:
		out = append(out, newFact("deploy-scan", FactDeploymentExposure, ObsUnavailable,
			perimeter, "deployment", []string{"deploy_scan"}))
	}
	return out, nil
}

// deployProductNames derives the exact-match product names a perimeter
// classification may attribute deploy facts to: module basename, component
// and product names — never a fuzzy prefix.
func deployProductNames(s0 Stage0Result) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	add(s0.Proposal.Component)
	add(s0.Proposal.Product)
	if base := filepath.Base(strings.TrimSuffix(s0.Proposal.Package, "/")); base != "." && base != "" {
		add(base)
	}
	add(filepath.Base(strings.TrimSuffix(s0.CatalogEntry.ID, "/")))
	return out
}

// testOnlyFact states the deterministic test-only distinction for the
// finding's module: SUPPORTS only when the non-test closure excludes every
// package the module owns, REFUTES when it does not, UNAVAILABLE while the
// distinction was never established.
func testOnlyFact(s0 Stage0Result) *DecisionFact {
	module := firstNonEmpty(s0.PackageCheck.ResolvedPath, s0.PackageCheck.ClaimedPath,
		s0.Input.Finding.Component.Package, s0.Input.Finding.Component.Name)
	module = strings.TrimSpace(module)
	if module == "" {
		return nil
	}
	graph := s0.Materials.ModuleGraph
	if graph != nil {
		if m, ok := graph.ModulePath(module); ok {
			module = m.Path
		}
	}
	// A decided fact is required: an undecided premise on a dismissal rule
	// would demote every weaker reduction. REFUTES therefore means "the
	// test-only claim does not hold" — either the module is linked into the
	// build closure, or the non-test closure was never established (the
	// materials limitations carry which) — never that a dismissal is safe.
	status := ObsRefutes
	provenance := []string{"go_list_deps_nontest"}
	if graph != nil && s0.Materials.PackageBuild != nil && graph.PackageInventory != nil && graph.BuildPackageInventory != nil {
		build := *s0.Materials.PackageBuild
		tests, product := graph.PackageInventory, graph.BuildPackageInventory
		testInventory, testErr := tests.AdmitBuild(build)
		buildInventory, buildErr := product.AdmitBuild(build)
		matching := build.ContentHash != "" && build.ContentHash == s0.Snapshot.ContentHash && build.GOOS != "" && build.GOARCH != "" && build.GoVersion != "" && tests.Run.WithTests && !product.Run.WithTests
		if target := s0.BuildTarget; target != nil {
			targetBuild := build
			targetBuild.GOOS, targetBuild.GOARCH, targetBuild.CGOEnabled, targetBuild.BuildTags = target.GOOS, target.GOARCH, target.CGOEnabled, target.BuildTags
			matching = matching && targetBuild.Matches(build) == nil
		}
		if testErr == nil && buildErr == nil && matching {
			derived, err := testOnlyModulesForPaths(graph, testInventory.Paths, buildInventory.Paths)
			if err == nil && derived[module] { status = ObsSupports }
			provenance = append(provenance, tests.RawReference, product.RawReference)
		} else {
			provenance = []string{"package_inventory_not_admitted"}
		}
	} else {
		provenance = []string{"go_list_deps_nontest_absent"}
	}
	f := newFact("materials", FactTestOnlyDependency, status, module, "build-graph", provenance)
	return &f
}

// LLMVerdictFactsProvider surfaces the agent's own verdict as a decision
// fact: it is the first opinion of the two-track decision, visible to
// predicates and to the package consumer, and never a substitute for the
// deterministic basis.
type LLMVerdictFactsProvider struct{}

func (LLMVerdictFactsProvider) Name() string { return "llm" }

func (LLMVerdictFactsProvider) Collect(_ context.Context, in ProviderInput) ([]DecisionFact, error) {
	if !in.Assessment.Verdict.Valid() {
		return []DecisionFact{newFact("llm", FactLLMVerdict, ObsUnavailable, "unknown", "llm", nil)}, nil
	}
	return []DecisionFact{newFact("llm", FactLLMVerdict, ObsSupports, string(in.Assessment.Verdict), "llm",
		[]string{firstNonEmpty(in.Assessment.SchemaVersion, AssessmentSchemaVersion)})}, nil
}
