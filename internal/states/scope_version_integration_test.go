package states_test

// The mixed-record regression pins the recorded Kubernetes CVE-2023-44487
// advisory ("HTTP/2 Rapid Reset") end to end through the real pipeline slice:
//
//	FileSource{NoAliasEnrichment: true} intake (the actual 22-entry document)
//	  -> GoResolver over a minimal module graph
//	  -> CheckAffected -> EvaluateVerdict
//	  -> persistence round trip
//	  -> report.json / Markdown / OpenVEX / CycloneDX
//	  -> the same persisted scope through the research decision/artifact
//	     projection.
//
// The document declares golang.org/x/net (Go), twenty Tomcat/Jetty/Akka Maven
// entries and one SwiftURL entry: the Go entry is only a projection of a
// 22-entry record, so the x/net version fact (v0.17.0 is outside the declared
// range) stays established while no finding-level negative may close, and no
// gRPC entry or gRPC affectedness is invented from the module graph.
//
// This is an integration slice, not a complete Kubernetes analysis: the module
// graph is a minimal test input based on the measured snapshot (x/net v0.17.0
// and grpc v1.55.0, the versions the recorded snapshot pins), and the
// evidence-collection/gap-loop states are out of scope. The complete CLI run is
// TestScopeVersionCalibration in cmd/izyan.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/persistence/filesystem"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/research"
	"github.com/fedorovmv/izyan/internal/states"
	"github.com/fedorovmv/izyan/internal/toolaudit"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

const (
	scopeVersionAdvisoryPath   = "../../eval/agent7/advisories/k8s-44487.json"
	scopeVersionAdvisoryDigest = "sha256:077330160d3adbbb93b2294e3db541c70a746677a4128a1bd8843dab688dae39"
	scopeVersionModulesFixture = "testdata/k8s-44487-modules.jsonl"

	scopeVersionGHSA = "GHSA-qppj-fm5r-hxr3"
	scopeVersionCVE  = "CVE-2023-44487"

	scopeVersionXNet        = "golang.org/x/net"
	scopeVersionXNetVersion = "v0.17.0"
	scopeVersionGRPC        = "google.golang.org/grpc"
	scopeVersionGRPCVersion = "v1.55.0"

	scopeVersionOriginalEntries = 22
)

// scopeVersionGoTool supplies only the module graph. Every package-list method
// fails the test: the resolved x/net version is outside the affected range, so
// no package/build reachability probe may run on that path (the claims stay
// UNKNOWN rather than reading a fixed version as component absence).
type scopeVersionGoTool struct {
	t        *testing.T
	modules  []byte
	modCalls int
	pkgCalls int
}

func (g *scopeVersionGoTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	g.modCalls++
	return g.modules,
		"go list -m -json all (minimal test input from internal/states/testdata/k8s-44487-modules.jsonl — measured x/net and grpc versions, not a captured tool trace)",
		nil
}

func (g *scopeVersionGoTool) ListPackages(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, error) {
	g.pkgCalls++
	g.t.Errorf("ListPackages must not run on the all-fixed version path (the resolved version is outside every affected range)")
	return nil, fmt.Errorf("unexpected ListPackages call")
}

func (g *scopeVersionGoTool) ListPackagesScope(_ context.Context, _ string, _ domain.ProductSnapshot, withTests bool) ([]byte, error) {
	g.pkgCalls++
	g.t.Errorf("ListPackagesScope(withTests=%t) must not run on the all-fixed version path", withTests)
	return nil, fmt.Errorf("unexpected ListPackagesScope call")
}

// TestScopeVersionMixedRecordRegression drives the recorded 22-entry advisory
// through the real intake, resolver, workflow transition, verdict, persistence
// and report/export projection for both request identities, and replays the
// persisted scope through the research decision/artifact publication.
func TestScopeVersionMixedRecordRegression(t *testing.T) {
	advisoryRaw, err := os.ReadFile(scopeVersionAdvisoryPath)
	if err != nil {
		t.Fatalf("read the recorded 22-entry advisory: %v", err)
	}
	if got := digestOf(advisoryRaw); got != scopeVersionAdvisoryDigest {
		t.Fatalf("recorded advisory digest = %s, want %s (the pinned raw document)", got, scopeVersionAdvisoryDigest)
	}
	modules, err := os.ReadFile(scopeVersionModulesFixture)
	if err != nil {
		t.Fatalf("read the module-graph fixture: %v", err)
	}
	for _, want := range []string{scopeVersionXNet, scopeVersionXNetVersion, scopeVersionGRPC, scopeVersionGRPCVersion} {
		if !strings.Contains(string(modules), want) {
			t.Fatalf("module-graph fixture does not carry the measured %s", want)
		}
	}

	repo := initRepo(t)
	for _, requested := range []string{scopeVersionCVE, scopeVersionGHSA} {
		t.Run(requested, func(t *testing.T) {
			runScopeVersionMixedRecord(t, repo, advisoryRaw, requested)
		})
	}
}

func runScopeVersionMixedRecord(t *testing.T, repo string, advisoryRaw []byte, requested string) {
	t.Helper()
	ctx := context.Background()
	caseDir := filepath.Join(t.TempDir(), "cases")
	store := filesystem.New(caseDir)
	c := &domain.AnalysisCase{
		ID: domain.CaseID("scope-version-" + strings.ToLower(requested)),
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCreated,
			StartedAt: time.Now().UTC(),
			Limits:    domain.AnalysisLimits{MaxIterations: 64},
		},
	}
	c.EvidenceGraph.Version = "1"
	if err := store.Create(ctx, c); err != nil {
		t.Fatalf("create case: %v", err)
	}
	ctx = toolaudit.WithRecorder(ctx, &toolaudit.Recorder{Sink: c.EvidenceGraph.AddToolExecution})

	// ---- product snapshot (real probe of the fixture repository) ----
	tr, err := (states.SnapshotProduct{Repo: repository.Service{}, Path: repo}).Run(ctx, c)
	if err != nil {
		t.Fatalf("snapshot product: %v", err)
	}
	if tr.Next != domain.StateResolveVulnerability {
		t.Fatalf("snapshot product next state = %s, want RESOLVE_VULNERABILITY", tr.Next)
	}
	c.Workflow.State = tr.Next

	// ---- real intake: the actual document, alias enrichment disabled ----
	tr, err = (states.ResolveVulnerability{
		Source: vulnerability.FileSource{Path: scopeVersionAdvisoryPath, NoAliasEnrichment: true},
		ID:     requested,
	}).Run(ctx, c)
	if err != nil {
		t.Fatalf("resolve vulnerability: %v", err)
	}
	if tr.Next != domain.StateCheckAffected {
		t.Fatalf("resolve vulnerability next state = %s, want CHECK_AFFECTED", tr.Next)
	}
	c.Workflow.State = tr.Next

	scope := assertScopeVersionIntake(t, &c.Vulnerability, requested)

	// ---- deterministic affected chain over the minimal measured graph ----
	tool := &scopeVersionGoTool{t: t, modules: mustReadFixture(t)}
	tr, err = (states.CheckAffected{Resolver: affected.GoResolver{Tool: tool}}).Run(ctx, c)
	if err != nil {
		t.Fatalf("check affected: %v", err)
	}
	if tr.Next != domain.StateResolveRootCause {
		t.Fatalf("CheckAffected next state = %s, want RESOLVE_ROOT_CAUSE under the Go projection", tr.Next)
	}
	if tool.modCalls != 1 {
		t.Fatalf("module graph listed %d times, want exactly 1", tool.modCalls)
	}
	if tool.pkgCalls != 0 {
		t.Fatalf("package-list methods ran %d times on the all-fixed version path, want 0", tool.pkgCalls)
	}
	c.Workflow.State = tr.Next
	assertScopeVersionComponentFacts(t, c, scope)

	// ---- verdict: the component negative may not close the requested scope ----
	tr, err = (states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(ctx, c)
	if err != nil {
		t.Fatalf("evaluate verdict: %v", err)
	}
	if tr.Next != domain.StateBuildReport {
		t.Fatalf("EvaluateVerdict next state = %s, want BUILD_REPORT", tr.Next)
	}
	if c.Verdict != nil {
		t.Fatalf("verdict = %+v (%s), want none: the component negative cannot close the requested scope", c.Verdict, c.Verdict.Reason)
	}
	if !hasAnalysisGap(c, domain.GapUnsupportedNegativeScope) {
		t.Fatalf("scope refusal lacks its typed cause: %+v", c.AnalysisGaps)
	}
	for _, p := range c.Profiles {
		if p.Verdict != "" {
			t.Fatalf("profile %s retained verdict = %s", p.Profile, p.Verdict)
		}
	}
	c.Workflow.State = tr.Next

	// ---- persistence round trip keeps the census and the component facts ----
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("save case: %v", err)
	}
	loaded, err := store.Load(ctx, c.ID)
	if err != nil {
		t.Fatalf("load case: %v", err)
	}
	assertScopeVersionPersisted(t, loaded, scope, "first round trip")
	if err := store.Save(ctx, loaded); err != nil {
		t.Fatalf("re-save case: %v", err)
	}
	reloaded, err := store.Load(ctx, c.ID)
	if err != nil {
		t.Fatalf("re-load case: %v", err)
	}
	assertScopeVersionPersisted(t, reloaded, scope, "second round trip")

	// ---- reports and VEX exports from the persisted case ----
	reportDir := filepath.Join(caseDir, string(c.ID))
	tr, err = (states.BuildReport{Dir: reportDir}).Run(ctx, reloaded)
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	if tr.Next != domain.StateFailed {
		t.Fatalf("BuildReport next state = %s, want FAILED (scope failure still writes the report)", tr.Next)
	}
	assertScopeVersionReports(t, reportDir, requested)

	// ---- the same loaded scope through research decision/artifact ----
	assertScopeVersionResearchProjection(t, reloaded, advisoryRaw, requested)
}

// assertScopeVersionIntake pins the recorded document's census and the bound
// requested identity. The two requests differ only in Kind: the CVE request is
// a CVE-scoped KNOWN_ONLY binding, the exact GHSA request is an
// ADVISORY_ENTRIES/KNOWN_ONLY binding of the same projected record. Neither may
// close.
func assertScopeVersionIntake(t *testing.T, v *domain.Vulnerability, requested string) *domain.AdvisoryScope {
	t.Helper()
	if v.ID != scopeVersionGHSA {
		t.Fatalf("resolved document id = %q, want %q", v.ID, scopeVersionGHSA)
	}
	if len(v.AffectedModules) != 1 || v.AffectedModules[0].Module != scopeVersionXNet {
		t.Fatalf("affected modules = %+v, want exactly %s", v.AffectedModules, scopeVersionXNet)
	}
	for _, m := range v.AffectedModules {
		if strings.Contains(m.Module, "grpc") {
			t.Fatalf("intake invented a gRPC affected module: %+v", m)
		}
	}
	scope := v.Scope
	if scope == nil {
		t.Fatal("intake bound no advisory scope")
	}
	if scope.RequestedID != requested || scope.ResolvedID != scopeVersionGHSA {
		t.Fatalf("scope identity requested=%q resolved=%q, want requested=%q resolved=%q",
			scope.RequestedID, scope.ResolvedID, requested, scopeVersionGHSA)
	}
	wantKind := domain.ScopeAdvisoryEntries
	if requested != scopeVersionGHSA {
		wantKind = domain.ScopeCVE
	}
	if scope.Kind != wantKind {
		t.Fatalf("scope kind = %q, want %q", scope.Kind, wantKind)
	}
	if scope.Coverage != domain.CoverageKnownOnly {
		t.Fatalf("scope coverage = %q, want KNOWN_ONLY (a Go projection of a 22-entry record)", scope.Coverage)
	}
	if scope.RecordExtent != domain.RecordExtentGoProjection {
		t.Fatalf("record extent = %q, want GO_PROJECTION", scope.RecordExtent)
	}
	inventory := scope.RecordInventory
	if inventory == nil {
		t.Fatal("scope carries no record census")
	}
	if err := inventory.Validate(scope.ResolvedID); err != nil {
		t.Fatalf("record census is not structurally valid: %v", err)
	}
	if inventory.DocumentDigest != scopeVersionAdvisoryDigest {
		t.Fatalf("census document digest = %s, want the pinned raw digest %s",
			inventory.DocumentDigest, scopeVersionAdvisoryDigest)
	}
	if inventory.AffectedEntryCount != scopeVersionOriginalEntries || len(inventory.Entries) != scopeVersionOriginalEntries {
		t.Fatalf("census entries = %d/%d, want %d original affected[] entries",
			inventory.AffectedEntryCount, len(inventory.Entries), scopeVersionOriginalEntries)
	}
	if !reflect.DeepEqual(inventory.RepresentedRefs, []int{1}) {
		t.Fatalf("represented refs = %v, want [1] (the Go entry)", inventory.RepresentedRefs)
	}
	wantOmitted := make([]int, 0, scopeVersionOriginalEntries-1)
	for i := range scopeVersionOriginalEntries {
		if i != 1 {
			wantOmitted = append(wantOmitted, i)
		}
	}
	if !reflect.DeepEqual(inventory.OmittedRefs, wantOmitted) {
		t.Fatalf("omitted refs = %v, want %v", inventory.OmittedRefs, wantOmitted)
	}
	ecosystems := map[string]int{}
	for _, entry := range inventory.Entries {
		ecosystems[entry.Ecosystem]++
		if entry.Ecosystem != "Go" && strings.Contains(entry.Module, "grpc") {
			t.Fatalf("census carries a gRPC entry: %+v", entry)
		}
	}
	if !reflect.DeepEqual(ecosystems, map[string]int{"Go": 1, "Maven": 20, "SwiftURL": 1}) {
		t.Fatalf("census ecosystems = %v, want Go=1 Maven=20 SwiftURL=1", ecosystems)
	}
	if inventory.Entries[1].Module != scopeVersionXNet {
		t.Fatalf("census Go entry = %+v, want %s", inventory.Entries[1], scopeVersionXNet)
	}
	if scope.AllowsNegativeClosure() {
		t.Fatal("a projected 22-entry record authorized a negative finding-level closure")
	}
	return scope
}

// assertScopeVersionComponentFacts pins the preserved component facts and the
// declared absence of package/build reachability evaluation.
func assertScopeVersionComponentFacts(t *testing.T, c *domain.AnalysisCase, intake *domain.AdvisoryScope) {
	t.Helper()
	a := c.Affected
	if a == nil {
		t.Fatal("CheckAffected recorded no affected result")
	}
	if a.ModulePresent != domain.ClaimTrue {
		t.Fatalf("ModulePresent = %s, want TRUE", a.ModulePresent)
	}
	if a.ResolvedVersion != scopeVersionXNetVersion {
		t.Fatalf("ResolvedVersion = %q, want %q", a.ResolvedVersion, scopeVersionXNetVersion)
	}
	if a.VersionAffected != domain.ClaimFalse {
		t.Fatalf("VersionAffected = %s, want FALSE (outside the declared range)", a.VersionAffected)
	}
	if a.PackagePresent != domain.ClaimUnknown {
		t.Fatalf("PackagePresent = %s, want UNKNOWN (no package probe ran)", a.PackagePresent)
	}
	if a.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("BuildRelevant = %s, want UNKNOWN (no package probe ran)", a.BuildRelevant)
	}
	if a.VulnerableImplementationPresent != domain.ClaimUnknown {
		t.Fatalf("VulnerableImplementationPresent = %s, want UNKNOWN", a.VulnerableImplementationPresent)
	}
	if !slices.Equal(a.CheckedModules, []string{scopeVersionXNet}) {
		t.Fatalf("CheckedModules = %v, want exactly [%s]", a.CheckedModules, scopeVersionXNet)
	}
	if len(a.SelectedModules) != 0 || a.SelectedModule != "" || len(a.VersionAffectedModules) != 0 {
		t.Fatalf("selected/version-affected modules = %v/%q/%v, want none on the all-fixed path",
			a.SelectedModules, a.SelectedModule, a.VersionAffectedModules)
	}
	// No gRPC (or any other) module may be invented from the module graph.
	for _, list := range [][]string{a.CheckedModules, a.SelectedModules, a.VersionAffectedModules} {
		for _, module := range list {
			if strings.Contains(module, "grpc") {
				t.Fatalf("affected result invented gRPC module %q from the module graph", module)
			}
		}
	}
	for _, m := range c.Vulnerability.AffectedModules {
		if strings.Contains(m.Module, "grpc") {
			t.Fatalf("advisory projection invented a gRPC affected module: %+v", m)
		}
	}
	// The census survives the resolver byte-for-byte.
	if a.Scope == nil {
		t.Fatal("affected result lost the advisory scope")
	}
	if err := a.Scope.RecordInventory.Validate(a.Scope.ResolvedID); err != nil {
		t.Fatalf("resolver narrowed or broke the census: %v", err)
	}
	if !reflect.DeepEqual(a.Scope.RecordInventory, intake.RecordInventory) {
		t.Fatalf("resolver changed the record census:\n got %+v\nwant %+v", a.Scope.RecordInventory, intake.RecordInventory)
	}
	if a.Scope.RecordExtent != domain.RecordExtentGoProjection || a.Scope.AllowsNegativeClosure() {
		t.Fatalf("resolver scope extent=%q closes=%v, want GO_PROJECTION and no closure",
			a.Scope.RecordExtent, a.Scope.AllowsNegativeClosure())
	}
	// The engine-side module evidence is the only resolver artifact.
	if !slices.Contains(a.EvidenceIDs, domain.EvidenceID("EV-AFFECTED-MODULES")) {
		t.Fatalf("affected evidence ids = %v, want EV-AFFECTED-MODULES", a.EvidenceIDs)
	}
	if c.EvidenceGraph.EvidenceByID("EV-AFFECTED-MODULES") == nil {
		t.Fatal("module-graph evidence was not recorded on the evidence graph")
	}
	// Both limitations must be recorded: the unchecked reachability axis and
	// the scope refusal the CheckAffected transition added.
	joined := strings.Join(a.Limitations, "\n")
	if !strings.Contains(joined, "package/build reachability was not evaluated") {
		t.Fatalf("affected limitations do not name the unchecked reachability axis:\n%s", joined)
	}
	wantScopeLimitation := "partial advisory scope: checked modules golang.org/x/net do not establish complete coverage of " + a.Scope.RequestedID
	if !strings.Contains(joined, wantScopeLimitation) {
		t.Fatalf("affected limitations do not carry the transition's scope refusal %q:\n%s", wantScopeLimitation, joined)
	}
	if !strings.Contains(strings.Join(c.EvidenceGraph.Limitations, "\n"), wantScopeLimitation) {
		t.Fatalf("the scope refusal was not recorded on the evidence graph:\n%s",
			strings.Join(c.EvidenceGraph.Limitations, "\n"))
	}
}

// assertScopeVersionPersisted checks that a stored/loaded case keeps the census
// and the component facts verbatim.
func assertScopeVersionPersisted(t *testing.T, c *domain.AnalysisCase, intake *domain.AdvisoryScope, label string) {
	t.Helper()
	if c.Affected == nil || c.Affected.Scope == nil {
		t.Fatalf("%s: affected scope missing after persistence", label)
	}
	scope := c.Affected.Scope
	if scope.RecordExtent != domain.RecordExtentGoProjection || scope.Coverage != domain.CoverageKnownOnly {
		t.Fatalf("%s: extent/coverage = %s/%s, want GO_PROJECTION/KNOWN_ONLY", label, scope.RecordExtent, scope.Coverage)
	}
	if scope.AllowsNegativeClosure() {
		t.Fatalf("%s: persisted projection authorized a negative closure", label)
	}
	if err := scope.RecordInventory.Validate(scope.ResolvedID); err != nil {
		t.Fatalf("%s: persisted census is invalid: %v", label, err)
	}
	if !reflect.DeepEqual(scope.RecordInventory, intake.RecordInventory) {
		t.Fatalf("%s: persisted census changed:\n got %+v\nwant %+v", label, scope.RecordInventory, intake.RecordInventory)
	}
	a := c.Affected
	if a.ModulePresent != domain.ClaimTrue || a.VersionAffected != domain.ClaimFalse ||
		a.ResolvedVersion != scopeVersionXNetVersion || a.PackagePresent != domain.ClaimUnknown ||
		a.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("%s: component facts changed: module=%s version_affected=%s resolved=%q package=%s build=%s",
			label, a.ModulePresent, a.VersionAffected, a.ResolvedVersion, a.PackagePresent, a.BuildRelevant)
	}
	if c.Verdict != nil {
		t.Fatalf("%s: persisted verdict = %+v, want none (scope failure)", label, c.Verdict)
	}
	if !hasAnalysisGap(c, domain.GapUnsupportedNegativeScope) {
		t.Fatalf("%s: persisted scope failure lacks its typed cause: %+v", label, c.AnalysisGaps)
	}
}

// assertScopeVersionReports pins the human/export projection of the refused
// component negative: report.json keeps the facts and census, the Markdown
// renders extent and census, and neither VEX export claims a clean negative.
func assertScopeVersionReports(t *testing.T, dir, requested string) {
	t.Helper()
	persisted := readCaseFile(t, filepath.Join(dir, "report.json"))
	var reported domain.AnalysisCase
	if err := json.Unmarshal(persisted, &reported); err != nil {
		t.Fatalf("decode report.json: %v", err)
	}
	if reported.Affected == nil || reported.Affected.Scope == nil {
		t.Fatal("report.json lost the affected scope")
	}
	if reported.Affected.Scope.RecordExtent != domain.RecordExtentGoProjection {
		t.Fatalf("report extent = %q, want GO_PROJECTION", reported.Affected.Scope.RecordExtent)
	}
	if err := reported.Affected.Scope.RecordInventory.Validate(reported.Affected.Scope.ResolvedID); err != nil {
		t.Fatalf("report census is invalid: %v", err)
	}
	if got := reported.Affected.Scope.RecordInventory; got.AffectedEntryCount != scopeVersionOriginalEntries ||
		len(got.RepresentedRefs) != 1 || len(got.OmittedRefs) != scopeVersionOriginalEntries-1 {
		t.Fatalf("report census = %d entries / %d represented / %d omitted",
			got.AffectedEntryCount, len(got.RepresentedRefs), len(got.OmittedRefs))
	}
	if reported.Verdict != nil {
		t.Fatalf("report verdict = %+v, want none (scope failure)", reported.Verdict)
	}
	// The report projection is owned by Task 8; the in-memory case and the
	// persisted case store carry the typed scope cause.
	if reported.Affected.ModulePresent != domain.ClaimTrue || reported.Affected.VersionAffected != domain.ClaimFalse ||
		reported.Affected.ResolvedVersion != scopeVersionXNetVersion ||
		reported.Affected.PackagePresent != domain.ClaimUnknown || reported.Affected.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("report changed the component facts: %+v", reported.Affected)
	}
	for _, m := range reported.Affected.CheckedModules {
		if strings.Contains(m, "grpc") {
			t.Fatalf("report invented gRPC module %q", m)
		}
	}
	for _, m := range reported.Vulnerability.AffectedModules {
		if strings.Contains(m.Module, "grpc") {
			t.Fatalf("report invented a gRPC affected module: %+v", m)
		}
	}

	markdown := string(readCaseFile(t, filepath.Join(dir, "report.en.md")))
	if !strings.Contains(markdown, "`GO_PROJECTION`") {
		t.Fatalf("Markdown does not render the record extent:\n%s", markdown)
	}
	if !strings.Contains(markdown, "22 entries: 1 represented, 21 omitted") {
		t.Fatalf("Markdown does not render the census counts:\n%s", markdown)
	}

	var vex struct {
		Statements []struct {
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(readCaseFile(t, filepath.Join(dir, "openvex.json")), &vex); err != nil {
		t.Fatalf("decode openvex.json: %v", err)
	}
	if len(vex.Statements) == 0 {
		t.Fatal("openvex.json carries no statement")
	}
	for _, st := range vex.Statements {
		if st.Status != "under_investigation" {
			t.Fatalf("OpenVEX status = %q for request %s, want under_investigation", st.Status, requested)
		}
	}

	var cdx struct {
		Vulnerabilities []struct {
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(readCaseFile(t, filepath.Join(dir, "cyclonedx.json")), &cdx); err != nil {
		t.Fatalf("decode cyclonedx.json: %v", err)
	}
	if len(cdx.Vulnerabilities) == 0 {
		t.Fatal("cyclonedx.json carries no vulnerability")
	}
	for _, v := range cdx.Vulnerabilities {
		if v.Analysis.State != "in_triage" {
			t.Fatalf("CycloneDX state = %q for request %s, want in_triage", v.Analysis.State, requested)
		}
	}
}

// assertScopeVersionResearchProjection replays the persisted scope through the
// research publication surfaces: the deterministic applicability rule that
// records the local version fact stays established with its fact refs, the
// decision-artifact builder proposes no global close, and the publication
// guards refuse both a supplied negative decision and a supplied closing
// artifact.
func assertScopeVersionResearchProjection(t *testing.T, c *domain.AnalysisCase, advisoryRaw []byte, requested string) {
	t.Helper()
	scope := c.Affected.Scope
	contentHash := scopeVersionLaneContentHash(c.Product.Commit)
	canonicalAdvisoryDigest, err := vexbench.CanonicalSHA256(advisoryRaw)
	if err != nil {
		t.Fatalf("canonical digest of the recorded advisory: %v", err)
	}

	// The lane's advisory projection: original affected[] order, so census
	// indices and impl ids agree exactly as the research lane builds them.
	impls := make([]research.AffectedImplementation, 0, len(scope.RecordInventory.Entries))
	for i, entry := range scope.RecordInventory.Entries {
		impl := research.AffectedImplementation{
			ID:        fmt.Sprintf("adv-%02d", i+1),
			Ecosystem: entry.Ecosystem,
			Module:    entry.Module,
			SourceRef: "adv:" + scope.ResolvedID,
		}
		switch {
		case entry.Ecosystem != "Go":
			impl.Binding = research.BindNonGo
		case entry.Module == "":
			impl.Binding = research.BindIncomplete
		case requested != scope.ResolvedID:
			impl.Binding = research.BindAliasResolved
		default:
			impl.Binding = research.BindExact
		}
		impls = append(impls, impl)
	}

	observation := &evidencetools.Observation{
		ID:           "OBS-44487",
		Tool:         "affected-resolve",
		Fact:         "affected chain resolved over the recorded advisory census",
		Scope:        "minimal recorded module graph (x/net v0.17.0)",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		Data:         map[string]any{"affected_result": *c.Affected},
		ScopeDetails: &evidencetools.ScopeDetails{
			SnapshotHash: contentHash,
			Subject:      "module:" + scopeVersionXNet,
			CoverageRule: "deterministic resolver over the recorded module graph and the advisory's declared version ranges",
		},
	}
	observationDigest, err := canonicalJSONDigest(observation)
	if err != nil {
		t.Fatalf("pin the affected-resolve observation: %v", err)
	}
	lane := &research.LaneResult{
		ContentHash: contentHash,
		Snapshot:    c.Product,
		Advisory: research.AdvisoryRecord{
			Input: research.AdvisoryInput{
				RequestedID:     scope.RequestedID,
				ResolvedID:      scope.ResolvedID,
				SourceKind:      "frozen_file",
				SourcePath:      scopeVersionAdvisoryPath,
				RawSHA256:       strings.TrimPrefix(digestOf(advisoryRaw), "sha256:"),
				CanonicalSHA256: canonicalAdvisoryDigest,
			},
			Vuln:  &c.Vulnerability,
			Impls: impls,
		},
		Affected: *c.Affected,
		Observations: []*evidencetools.Observation{
			observation,
		},
		Records: []evidencetools.AuditRecord{{
			Tool:        "affected-resolve",
			Args:        json.RawMessage(`{}`),
			Observation: observation,
			RecordTime:  time.Now().UTC(),
		}},
		CanonicalByObs: map[string]string{observation.ID: observationDigest},
	}

	facts, err := research.BuildDecisionFacts(research.FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatalf("build research facts: %v", err)
	}
	rules, err := research.BuildRuleFacts(research.FactBuildInput{Lane: lane})
	if err != nil {
		t.Fatalf("build research rule facts: %v", err)
	}
	factID := "fact-" + strings.ToLower(observation.ID)
	versionRule := -1
	for i := range rules {
		if rules[i].Subject == "module:"+scopeVersionXNet &&
			rules[i].Predicate == evaluator.PredicateVersionInRange &&
			rules[i].Value == "false" {
			versionRule = i
		}
	}
	if versionRule < 0 {
		t.Fatalf("the local version fact was not projected: %+v", rules)
	}
	if rules[versionRule].ID != factID || rules[versionRule].Status != research.FactStatusVerified ||
		rules[versionRule].Coverage != research.FactCoverageComplete || rules[versionRule].Digest == "" {
		t.Fatalf("local version fact is not an established, digest-bound COMPLETE fact: %+v", rules[versionRule])
	}
	if !slices.ContainsFunc(facts, func(f research.Fact) bool {
		return f.ID == factID && f.Status == research.FactStatusVerified
	}) {
		t.Fatalf("the version fact is not part of the shared fact envelope: %+v", facts)
	}

	artifact, err := research.BuildDecisionArtifact(context.Background(), research.ArtifactInput{
		Lane:      lane,
		Facts:     facts,
		RuleFacts: rules,
		Policy:    research.BaselineSafetyPolicy(),
		Catalogs:  &research.Catalogs{},
		Pins: research.ReplayAndPolicyPins{
			PromptDigest: strings.Repeat("a", 64),
			PolicyDigest: strings.Repeat("b", 64),
			CatalogDigests: map[string]string{
				"conditions":   strings.Repeat("c", 64),
				"checks":       strings.Repeat("d", 64),
				"dispositions": strings.Repeat("e", 64),
			},
		},
	})
	if err != nil {
		t.Fatalf("build decision artifact: %v", err)
	}
	if artifact.ProposedDisposition != research.DispositionHoldUnknown {
		t.Fatalf("artifact proposed %q under the projected scope, want HOLD_UNKNOWN", artifact.ProposedDisposition)
	}
	assertNoResearchClose(t, "builder artifact", &artifact)
	unknown := scopeVersionUnknownBranch(t, &artifact)
	if !limitationNames(unknown.Limitations, "scoped applicability gap") ||
		!limitationNames(unknown.Limitations, "version-out-of-range") ||
		!limitationNames(unknown.Limitations, factID) {
		t.Fatalf("the unknown branch does not record the local establishment and the scope gap: %+v", unknown)
	}

	// Publication guard 1: a supplied negative decision is projected to an
	// open decision; its evidence stays visible.
	negative := &research.EvidenceDecision{
		Verdict:         domain.VerdictNotAffected,
		Reason:          "resolved version v0.17.0 is outside the affected range",
		EvidenceRefs:    []string{"obs:" + observation.ID},
		Scope:           "recorded advisory scope",
		Coverage:        "COMPLETE",
		Limitations:     []string{"scoped to the loaded advisory entries"},
		TicketRationale: "component fact established",
	}
	report := research.Assemble(research.AssembleInput{
		Lane:              lane,
		Decision:          negative,
		DeterministicOnly: true,
		RunID:             "scope-version-" + strings.ToLower(requested),
		StartedAt:         time.Now().UTC(),
		FinishedAt:        time.Now().UTC(),
	})
	if report.Decision == nil {
		t.Fatal("assembled report carries no decision")
	}
	if report.Decision.Verdict != domain.VerdictInconclusive || report.Decision.Coverage != "INSUFFICIENT_SCOPE" {
		t.Fatalf("published decision = %s/%s, want INCONCLUSIVE/INSUFFICIENT_SCOPE",
			report.Decision.Verdict, report.Decision.Coverage)
	}
	if !slices.Contains(report.Decision.EvidenceRefs, "obs:"+observation.ID) {
		t.Fatalf("published decision dropped the recorded evidence: %v", report.Decision.EvidenceRefs)
	}
	if negative.Verdict != domain.VerdictNotAffected || negative.Coverage != "COMPLETE" {
		t.Fatalf("the caller's decision was mutated: %+v", negative)
	}

	// Publication guard 2: a stale artifact that still proposes a global
	// close is demoted; the caller's artifact is untouched and the local
	// fact survives on the published copy.
	stale := &research.DecisionArtifact{}
	rawArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("encode artifact: %v", err)
	}
	if err := json.Unmarshal(rawArtifact, stale); err != nil {
		t.Fatalf("copy artifact: %v", err)
	}
	stale.ProposedDisposition = research.DispositionCloseNotAffected
	guarded := research.Assemble(research.AssembleInput{
		Lane:              lane,
		DecisionArtifact:  stale,
		DeterministicOnly: true,
		RunID:             "scope-version-stale-" + strings.ToLower(requested),
		StartedAt:         time.Now().UTC(),
		FinishedAt:        time.Now().UTC(),
	})
	if guarded.DecisionArtifact == nil {
		t.Fatal("assembled report carries no published artifact")
	}
	if stale.ProposedDisposition != research.DispositionCloseNotAffected {
		t.Fatalf("the caller's artifact was mutated: %+v", stale.ProposedDisposition)
	}
	if guarded.DecisionArtifact.ProposedDisposition != research.DispositionHoldUnknown {
		t.Fatalf("published artifact proposal = %q, want HOLD_UNKNOWN",
			guarded.DecisionArtifact.ProposedDisposition)
	}
	assertNoResearchClose(t, "published artifact", guarded.DecisionArtifact)
	if !slices.ContainsFunc(guarded.DecisionArtifact.SharedFacts, func(f research.Fact) bool {
		return f.ID == factID && f.Status == research.FactStatusVerified
	}) {
		t.Fatalf("published artifact lost the local version fact: %+v", guarded.DecisionArtifact.SharedFacts)
	}
	publishedUnknown := scopeVersionUnknownBranch(t, guarded.DecisionArtifact)
	if !limitationNames(publishedUnknown.Limitations, "scoped applicability gap") {
		t.Fatalf("published artifact does not name the scope refusal: %+v", publishedUnknown)
	}
	// Current deterministic publication retains the same scope refusal, through
	// the canonical requested-finding authority rather than an R6 artifact.
	lane.RequestedID = requested
	lane.ExactRecordIntake = true
	lane.RecordPin = &domain.RecordPin{
		RecordID: scopeVersionGHSA, DocumentDigest: digestOf(advisoryRaw),
		SourceLocator: scopeVersionAdvisoryPath,
	}
	primary, err := research.RecordCase(lane)
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.PublishRequest(primary); err != nil {
		t.Fatal(err)
	}
	current := research.Assemble(research.AssembleInput{
		Lane: lane, Decision: negative, DeterministicOnly: true,
		RunID: "canonical-scope", StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if current.Schema != research.ReportSchemaV5 || current.RequestComposition == nil {
		t.Fatalf("canonical research publication missing: %s", current.Schema)
	}
	if current.RequestComposition.Verdict == domain.VerdictNotAffected ||
		current.RequestComposition.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatal("projected mixed-record component negative closed the request")
	}
	if current.DecisionArtifact != nil {
		t.Fatal("current deterministic publication acquired an R6 artifact requirement")
	}
}

// scopeVersionUnknownBranch returns the artifact's explicit unknown branch.
func scopeVersionUnknownBranch(t *testing.T, a *research.DecisionArtifact) *research.DecisionBranch {
	t.Helper()
	for i := range a.Branches {
		if a.Branches[i].ID == "B-UNKNOWN" {
			return &a.Branches[i]
		}
	}
	t.Fatalf("artifact carries no explicit unknown branch: %+v", a.Branches)
	return nil
}

// assertNoResearchClose requires that neither the artifact-level proposal nor
// any branch proposes a CLOSE_* disposition.
func assertNoResearchClose(t *testing.T, label string, a *research.DecisionArtifact) {
	t.Helper()
	if isCloseDisposition(a.ProposedDisposition) {
		t.Fatalf("%s proposes a global close %q under a non-closing scope", label, a.ProposedDisposition)
	}
	for _, branch := range a.Branches {
		if isCloseDisposition(branch.ProposedDisposition) {
			t.Fatalf("%s carries a closing branch %s (%s)", label, branch.ID, branch.ProposedDisposition)
		}
	}
	for _, edge := range a.JustificationGraph {
		if isCloseDisposition(edge.Disposition) {
			t.Fatalf("%s carries a closing justification edge %s (%s)", label, edge.ID, edge.Disposition)
		}
	}
}

func isCloseDisposition(d research.ProposedDisposition) bool {
	switch d {
	case research.DispositionCloseNotAffected, research.DispositionCloseNoExploitPath:
		return true
	}
	return false
}

func limitationNames(limitations []string, want string) bool {
	for _, limitation := range limitations {
		if strings.Contains(limitation, want) {
			return true
		}
	}
	return false
}

// scopeVersionLaneContentHash derives the lane's snapshot binding for this
// test projection. It is a fixture-local binding (the hermetic snapshot is not
// an externally pinned tree, so the production content hash is unavailable);
// every observation, the lane and the artifact share it.
func scopeVersionLaneContentHash(commit string) string {
	sum := sha256.Sum256([]byte("scope-version-regression:" + commit))
	return hex.EncodeToString(sum[:])
}

// canonicalJSONDigest is the observation pin the research persistence layer
// records: sha256 over the canonical MarshalIndent form.
func canonicalJSONDigest(v any) (string, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustReadFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(scopeVersionModulesFixture)
	if err != nil {
		t.Fatalf("read the module-graph fixture: %v", err)
	}
	return raw
}

func readCaseFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}
