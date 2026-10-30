package triage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/exposure"
	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/productb/vulnerability"
	"github.com/davniy/izyan/internal/toolchain"
)

// factsByKind indexes the collected facts by kind; a provider emitting two
// facts of one kind yields the slice in order.
func factsByKind(t *testing.T, facts []DecisionFact) map[string][]DecisionFact {
	t.Helper()
	out := map[string][]DecisionFact{}
	for _, f := range facts {
		if f.ID == "" || f.Kind == "" || f.Status == "" || f.Scope == "" {
			t.Fatalf("fact missing identity fields: %+v", f)
		}
		out[f.Kind] = append(out[f.Kind], f)
	}
	return out
}

func TestProviderStage0Facts(t *testing.T) {
	s0 := goodStage0()
	facts, err := (Stage0FactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactVulnerabilityID]; len(got) != 1 || got[0].Status != ObsSupports || got[0].Subject != "CVE-2099-0001" {
		t.Fatalf("vulnerability_id fact wrong: %+v", got)
	}
	if got := by[FactComponentIdentity]; len(got) != 1 || got[0].Status != ObsSupports {
		t.Fatalf("component_identity fact wrong: %+v", got)
	}
	for _, kind := range []string{FactSource, FactRef, FactCommit, FactSnapshotIntegrity, FactAdvisory, FactBaseline} {
		got := by[kind]
		if len(got) != 1 || got[0].Status != ObsSupports {
			t.Fatalf("kind %s: want one SUPPORTS fact, got %+v", kind, got)
		}
	}
}

// TestProviderStage0FactsUnverifiedID: a field that stayed UNVERIFIED is
// an UNAVAILABLE fact — never a confirmation and never a refutation.
func TestProviderStage0FactsUnverifiedID(t *testing.T) {
	s0 := goodStage0()
	for i := range s0.Validation.Fields {
		if s0.Validation.Fields[i].Field == "vulnerability_ids" {
			s0.Validation.Fields[i].Status = IntakeUnverified
			s0.Validation.Fields[i].Provenance = nil
		}
	}
	facts, err := (Stage0FactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactVulnerabilityID]; len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("unverified id must yield UNAVAILABLE, got %+v", got)
	}
}

// TestProviderStage0FactsNoAdvisory: every lane missing yields UNAVAILABLE —
// an absent advisory is never a negative fact about applicability.
func TestProviderStage0FactsNoAdvisory(t *testing.T) {
	s0 := goodStage0()
	s0.Advisory = vulnerability.FrozenAdvisory{}
	s0.Resolution = nil
	facts, err := (Stage0FactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactAdvisory]; len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("missing advisory must yield UNAVAILABLE, got %+v", got)
	}
}

// TestPackageFactsProviderModuleAbsent: MODULE_ABSENT over a closed build
// graph is the deterministic falsifier — package_presence REFUTES and the
// fact carries provenance; it is still never a dismissal by itself.
func TestProviderPackageFactsModuleAbsent(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class:          CheckModuleAbsent,
		ClaimedPath:    "example.org/library",
		EvidenceSource: "module_graph",
		Reason:         "module example.org/library absent from the complete module graph",
		Provenance:     []string{"go list -m all"},
	}
	facts, err := (PackageFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	pres := by[FactPackagePresence]
	if len(pres) != 1 || pres[0].Status != ObsRefutes || pres[0].Scope != "build-graph" {
		t.Fatalf("package_presence must REFUTES over build-graph scope: %+v", pres)
	}
	if len(pres[0].Provenance) == 0 {
		t.Fatal("absence fact must carry provenance")
	}
	aff := by[FactPackageAffected]
	if len(aff) != 1 || aff[0].Status != ObsRefutes {
		t.Fatalf("absent module cannot be affected: %+v", aff)
	}
}

// TestProviderPackageFactsUnresolved: an undecidable claim is UNAVAILABLE —
// an empty or partial search is never evidence of absence.
func TestProviderPackageFactsUnresolved(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class:       CheckUnresolved,
		ClaimedPath: "example.org/library",
		Reason:      "module present but its version is undecidable",
	}
	facts, err := (PackageFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactPackagePresence]; len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("unresolved claim must yield UNAVAILABLE presence, got %+v", got)
	}
	if got := by[FactPackageClaim]; len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("unresolved claim fact wrong: %+v", got)
	}
}

// TestProviderPackageFactsMismatch: claimed-vs-resolved version conflict is
// CONFLICTING — a contradiction on a decision-relevant fact.
func TestProviderPackageFactsMismatch(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class:           CheckVersionMismatch,
		ClaimedPath:     "example.org/library",
		ClaimedVersion:  "v1.9.9",
		ResolvedPath:    "example.org/library",
		ResolvedVersion: "v1.2.3",
		Reason:          "claimed version v1.9.9 conflicts with resolved example.org/library@v1.2.3",
	}
	facts, err := (PackageFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactPackageClaim]; len(got) != 1 || got[0].Status != ObsConflicting {
		t.Fatalf("mismatched claim must be CONFLICTING: %+v", got)
	}
}

func TestProviderToolchainFacts(t *testing.T) {
	t.Run("resolved release toolchain supports", func(t *testing.T) {
		s0 := goodStage0()
		s0.ReleaseToolchain = ReleaseToolchainFact{Version: "1.25.8", Source: domain.GoVersionSourceBinary, Location: "bin/service-example"}
		s0.Toolchain = toolchain.Toolchain{Version: "1.25.8", Mode: toolchain.ModeSDK, GoBin: "go"}
		facts, err := (ToolchainFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		by := factsByKind(t, facts)
		if got := by[FactReleaseToolchain]; len(got) != 1 || got[0].Status != ObsSupports || got[0].Subject != "1.25.8" {
			t.Fatalf("release_toolchain fact wrong: %+v", got)
		}
		if got := by[FactAnalysisToolchain]; len(got) != 1 || got[0].Status != ObsSupports {
			t.Fatalf("analysis_toolchain fact wrong: %+v", got)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		s0 := goodStage0()
		s0.ReleaseToolchain = ReleaseToolchainFact{Version: "1.24.0", Claimed: "go1.25.8", Conflict: true, Source: domain.GoVersionSourceDockerfile}
		facts, err := (ToolchainFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		by := factsByKind(t, facts)
		if got := by[FactReleaseToolchain]; len(got) != 1 || got[0].Status != ObsConflicting {
			t.Fatalf("conflicting release toolchain must be CONFLICTING: %+v", got)
		}
	})
	t.Run("unknown is unavailable, never a fact of safety", func(t *testing.T) {
		s0 := goodStage0()
		s0.ReleaseToolchain = ReleaseToolchainFact{}
		s0.Toolchain = toolchain.Toolchain{Mismatch: true, Version: "1.26.0", Mode: toolchain.ModeLocal}
		facts, err := (ToolchainFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		by := factsByKind(t, facts)
		if got := by[FactReleaseToolchain]; len(got) != 1 || got[0].Status != ObsUnavailable {
			t.Fatalf("unknown release toolchain must be UNAVAILABLE: %+v", got)
		}
		if got := by[FactAnalysisToolchain]; len(got) != 1 || got[0].Status != ObsRefutes {
			t.Fatalf("provisioned mismatch must refute toolchain.match: %+v", got)
		}
	})
	t.Run("injected resolver", func(t *testing.T) {
		s0 := goodStage0()
		s0.ReleaseToolchain = ReleaseToolchainFact{Version: "1.25.8", Source: domain.GoVersionSourceBinary}
		s0.Toolchain = toolchain.Toolchain{}
		p := ToolchainFactsProvider{Resolve: func(context.Context, string) (toolchain.Toolchain, []string) {
			return toolchain.Toolchain{Version: "1.25.8", Mode: toolchain.ModeSDK, GoBin: "go"}, []string{"provided by installed SDK"}
		}}
		facts, err := p.Collect(context.Background(), ProviderInput{Stage0: s0})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		by := factsByKind(t, facts)
		if got := by[FactAnalysisToolchain]; len(got) != 1 || got[0].Status != ObsSupports || got[0].Subject != "1.25.8" {
			t.Fatalf("injected resolve result must surface: %+v", got)
		}
	})
}

func TestProviderMaterialsFacts(t *testing.T) {
	s0 := goodStage0()
	s0.Materials = MaterialSet{
		Materials: []Material{
			{ID: "go.mod", Kind: MaterialModuleManifest, Source: "snapshot", Scope: "build", SHA256: "aa", Availability: MaterialAvailable, Provenance: []string{"snapshot.json"}},
			{ID: "sbom.cdx.json", Kind: MaterialSBOM, Source: "artifact", Scope: "artifact", Availability: MaterialUnavailable},
		},
		ModuleGraph: &ModuleGraph{Source: "go list -m all", Complete: true, Modules: []ModuleVersion{{Path: "example.org/library", Version: "v1.2.3"}}},
		Deploy:      &DeployFacts{FactCount: 1, Perimeter: domain.PerimeterClusterInternal, ScannedPaths: []string{"deploy"}},
	}
	facts, err := (MaterialsFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[MaterialModuleManifest]; len(got) != 1 || got[0].Status != ObsSupports {
		t.Fatalf("available material must SUPPORT: %+v", got)
	}
	if got := by[MaterialSBOM]; len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("absent material must be UNAVAILABLE: %+v", got)
	}
	if got := by[FactModuleGraph]; len(got) != 1 || got[0].Status != ObsSupports {
		t.Fatalf("complete module graph must SUPPORT: %+v", got)
	}
	if got := by[FactDeploymentExposure]; len(got) != 1 || got[0].Status != ObsSupports || got[0].Subject != domain.PerimeterClusterInternal {
		t.Fatalf("perimeter fact wrong: %+v", got)
	}
}

// TestProviderMaterialsFactsEmptyDeploy: an empty deploy scan never reads
// as proven isolation — the perimeter fact is UNAVAILABLE.
func TestProviderMaterialsFactsEmptyDeploy(t *testing.T) {
	s0 := goodStage0()
	s0.Materials = MaterialSet{Deploy: &DeployFacts{Perimeter: domain.PerimeterUnknown}}
	facts, err := (MaterialsFactsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactDeploymentExposure]; len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("unknown perimeter must be UNAVAILABLE: %+v", got)
	}
}

func TestProviderObservations(t *testing.T) {
	obs := []evidencetools.Observation{
		{ID: "obs-1", Tool: "find_symbol", Fact: "found", Scope: "snapshot", Completeness: evidencetools.CompletenessComplete, ToolStatus: evidencetools.StatusOK, EvidenceRefs: []string{"ev:src:foo.go@abc"}},
		{ID: "obs-2", Tool: "find_callers", Scope: "snapshot", Completeness: evidencetools.CompletenessPartial, ToolStatus: evidencetools.StatusError, Error: "tool failed"},
	}
	facts, err := (ObservationsProvider{}).Collect(context.Background(), ProviderInput{Observations: obs})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	got := by[FactToolObservation]
	if len(got) != 2 {
		t.Fatalf("want 2 observation facts, got %+v", got)
	}
	var ok, failed DecisionFact
	for _, f := range got {
		if strings.Contains(f.ID, "find_symbol") {
			ok = f
		} else {
			failed = f
		}
	}
	if ok.Status != ObsSupports || len(ok.EvidenceRefs) != 1 {
		t.Fatalf("OK observation must SUPPORT with evidence refs: %+v", ok)
	}
	if failed.Status != ObsUnavailable {
		t.Fatalf("errored observation must be UNAVAILABLE: %+v", failed)
	}
	if cov := by["observation_coverage"]; len(cov) != 1 || cov[0].Status != ObsLimitation {
		t.Fatalf("partial completeness must emit a LIMITATION fact: %+v", cov)
	}
}

// TestObservationsProviderAuditFallback: without typed observations the
// provider rebuilds facts from recorded tool_call audit events — replay
// composes the identical package.
func TestProviderObservationsAuditFallback(t *testing.T) {
	s0 := goodStage0()
	s0.Events = []AuditEvent{
		{Type: AuditEventToolCall, ObservationID: "obs-9", Tool: "find_callers", Status: "ok", ReachEvidence: true, Scope: "snapshot"},
		{Type: AuditEventMaterials},
	}
	facts, err := (ObservationsProvider{}).Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	if got := by[FactToolObservation]; len(got) != 1 || got[0].Status != ObsSupports {
		t.Fatalf("audit-recorded observation must SUPPORT: %+v", got)
	}
	if got := by["reachability_evidence"]; len(got) != 1 || got[0].Status != ObsSupports {
		t.Fatalf("reach evidence fact must be emitted: %+v", got)
	}
}

// TestProviderDeployScan real-scan coverage: a ClusterIP service manifest
// owned by the analyzed product classifies cluster-internal — the provider
// adapts exposure.ScanDeployWithOptions + ClassifyPerimeter without a
// fabricated verdict.
func TestProviderDeployScan(t *testing.T) {
	dir := t.TempDir()
	deploy := filepath.Join(dir, "deploy")
	if err := os.MkdirAll(deploy, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "apiVersion: v1\nkind: Service\nmetadata:\n  name: service-example\nspec:\n  type: ClusterIP\n  ports:\n    - port: 8080\n"
	if err := os.WriteFile(filepath.Join(deploy, "service.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	p := DeployScanProvider{RootPath: dir, ProductNames: []string{"service-example"}}
	s0 := goodStage0()
	facts, err := p.Collect(context.Background(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	got := by[FactDeploymentExposure]
	if len(got) != 1 || got[0].Status != ObsSupports || got[0].Subject != domain.PerimeterClusterInternal {
		t.Fatalf("cluster-internal perimeter fact wrong: %+v", got)
	}
	if len(by["deploy_surface"]) == 0 {
		t.Fatal("deploy surface facts must be recorded")
	}
}

// TestProviderDeployScanNoManifest: nothing scanned → perimeter UNAVAILABLE;
// the absent manifest is never evidence of isolation.
func TestProviderDeployScanNoManifest(t *testing.T) {
	dir := t.TempDir()
	p := DeployScanProvider{RootPath: dir, ProductNames: []string{"service-example"}}
	facts, err := p.Collect(context.Background(), ProviderInput{Stage0: goodStage0()})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	got := by[FactDeploymentExposure]
	if len(got) != 1 || got[0].Status != ObsUnavailable {
		t.Fatalf("empty scan must yield UNAVAILABLE perimeter: %+v", got)
	}
}

// TestProviderDeployScanPublic: a published public surface classifies
// public — deployment exposure stays a fact, never a dismissal.
func TestProviderDeployScanPublic(t *testing.T) {
	p := DeployScanProvider{
		RootPath: "x",
		Scan: func(exposure.DeployScanOptions) ([]domain.ExposureFact, error) {
			return []domain.ExposureFact{{
				Direction: "inbound", Kind: "deployment", Target: "k8s:Service:LoadBalancer",
				Address: "LoadBalancer", Scope: domain.ScopeAllInterfaces, Owner: "service-example",
			}}, nil
		},
		Classify: exposure.ClassifyPerimeter,
	}
	facts, err := p.Collect(context.Background(), ProviderInput{Stage0: goodStage0()})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	by := factsByKind(t, facts)
	got := by[FactDeploymentExposure]
	if len(got) != 1 || got[0].Status != ObsSupports || got[0].Subject != domain.PerimeterPublic {
		t.Fatalf("public perimeter fact wrong: %+v", got)
	}
}

func TestProviderDeterministicIDs(t *testing.T) {
	s0 := goodStage0()
	f1, err := collectFacts(context.Background(), DefaultProviders(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("collectFacts: %v", err)
	}
	f2, err := collectFacts(context.Background(), DefaultProviders(), ProviderInput{Stage0: s0})
	if err != nil {
		t.Fatalf("collectFacts: %v", err)
	}
	if len(f1) != len(f2) {
		t.Fatalf("non-deterministic fact count: %d vs %d", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i].ID != f2[i].ID {
			t.Fatalf("fact %d id differs: %q vs %q", i, f1[i].ID, f2[i].ID)
		}
	}
}
