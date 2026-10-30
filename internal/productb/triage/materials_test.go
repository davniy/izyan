package triage

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/productb/affected"
	domain "github.com/davniy/izyan/internal/productb/domain"
)

// fakeGoTool injects deterministic go list output without subprocesses.
type fakeGoTool struct {
	modules    []affected.Module
	moduleErr  error
	packages   []affected.Package
	packageErr error
}

func (f fakeGoTool) ListModules(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, string, error) {
	if f.moduleErr != nil {
		return nil, "go list -m -json all", f.moduleErr
	}
	var buf bytes.Buffer
	for _, m := range f.modules {
		b, err := json.Marshal(m)
		if err != nil {
			return nil, "", err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), "go list -m -json all", nil
}

func (f fakeGoTool) ListPackages(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, error) {
	if f.packageErr != nil {
		return nil, f.packageErr
	}
	var buf bytes.Buffer
	for _, p := range f.packages {
		b, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func (f fakeGoTool) ListBuildPackages(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, error) {
	if f.packageErr != nil {
		return nil, f.packageErr
	}
	var buf bytes.Buffer
	for _, p := range f.packages {
		b, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// materialByID returns the collected material with the given id.
func materialByID(set MaterialSet, id string) (Material, bool) {
	for _, m := range set.Materials {
		if m.ID == id {
			return m, true
		}
	}
	return Material{}, false
}

func hasLim(lims []string, substr string) bool {
	for _, l := range lims {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// writeModuleTree creates a tiny Go module: go.mod with one require plus a
// main package.
func writeModuleTree(t *testing.T, dir, module, dep, depVer string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, "go.mod"),
		"module "+module+"\n\ngo 1.23\n\nrequire "+dep+" "+depVer+"\n")
	writeFile(t, filepath.Join(dir, "main.go"),
		"package main\n\nimport _ \""+dep+"\"\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(dir, "go.sum"),
		dep+" "+depVer+" h1:example=\n"+dep+" "+depVer+"/go.mod h1:example=\n")
	return dir
}

func materialManifest(t *testing.T, root string) SnapshotManifest {
	t.Helper()
	m, err := LocalSnapshotBuilder{}.Build(context.Background(),
		snapshotInput(t, Target{Repository: root}))
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}
	return m
}

func TestMaterialFactsGoModuleTree(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	for _, id := range []string{"go.mod", "go.sum"} {
		mat, ok := materialByID(set, id)
		if !ok {
			t.Fatalf("material %q missing from set", id)
		}
		if mat.Availability != MaterialAvailable {
			t.Fatalf("material %s availability = %q", id, mat.Availability)
		}
		if mat.SHA256 == "" || mat.Size == 0 {
			t.Fatalf("material %s lacks hash/size", id)
		}
		if len(mat.Provenance) == 0 {
			t.Fatalf("material %s lacks provenance", id)
		}
	}
	gm, ok := materialByID(set, "vendor/modules.txt")
	if !ok || gm.Availability != MaterialUnavailable {
		t.Fatalf("vendor/modules.txt availability = %+v (ok=%v), want UNAVAILABLE", gm, ok)
	}
	if set.ModuleGraph == nil {
		t.Fatal("module graph missing")
	}
	if set.ModuleGraph.Source != "go.mod" {
		t.Fatalf("module graph source = %q, want go.mod", set.ModuleGraph.Source)
	}
	var found bool
	for _, mv := range set.ModuleGraph.Modules {
		if mv.Path == "example.org/parser" && mv.Version == "v1.4.2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("example.org/parser v1.4.2 not in module graph: %+v", set.ModuleGraph.Modules)
	}
}

func TestMaterialFactsVendorModules(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	writeFile(t, filepath.Join(root, "vendor", "modules.txt"),
		"# example.org/parser v1.4.2\n## explicit; go 1.23\nexample.org/parser\n")
	m := materialManifest(t, root)

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.ModuleGraph == nil || set.ModuleGraph.Source != "vendor/modules.txt" {
		t.Fatalf("module graph = %+v, want vendor/modules.txt source", set.ModuleGraph)
	}
	if !set.ModuleGraph.Complete {
		t.Fatal("vendor module graph must be marked complete")
	}
}

func TestMaterialFactsGoListTool(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)

	tool := fakeGoTool{
		modules: []affected.Module{
			{Path: "example.org/service", Main: true, Version: "v0.0.0"},
			{Path: "example.org/parser", Version: "v1.4.1"},
		},
		packages: []affected.Package{
			{ImportPath: "example.org/service", Name: "main"},
			{ImportPath: "example.org/parser", Name: "parser"},
		},
	}
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, tool)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.ModuleGraph == nil || set.ModuleGraph.Source != "go list -m -json all" {
		t.Fatalf("module graph = %+v, want go list source", set.ModuleGraph)
	}
	if !set.ModuleGraph.Linked["example.org/parser"] {
		t.Fatal("linked import set missing example.org/parser")
	}
	// The go list module graph wins over the declared go.mod requirement.
	res := CheckPackageVersion(
		IntakeProposal{Package: "example.org/parser", Version: "1.4.2"},
		set, AdvisoryProjection{}, "")
	if res.Class != CheckVersionMismatch {
		t.Fatalf("class = %q, want version mismatch (resolved v1.4.1)", res.Class)
	}
	if res.ResolvedVersion != "v1.4.1" {
		t.Fatalf("resolved = %q", res.ResolvedVersion)
	}
}

func TestMaterialFactsMissingModuleManifests(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.py"), "print('x')\n")
	m := materialManifest(t, root)

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.ModuleGraph != nil {
		t.Fatalf("module graph should be absent for a non-Go tree: %+v", set.ModuleGraph)
	}
	for _, id := range []string{"go.mod", "go.sum"} {
		mat, ok := materialByID(set, id)
		if !ok || mat.Availability != MaterialUnavailable {
			t.Fatalf("%s availability = %+v (ok=%v), want UNAVAILABLE", id, mat, ok)
		}
	}
}

func TestMaterialFactsSBOMBinaryArtifacts(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	writeFile(t, filepath.Join(root, "sbom.json"), `{"bomFormat":"CycloneDX"}`)
	bin := filepath.Join(root, "service-example")
	writeFile(t, bin, "\x7fELFfake")

	in := snapshotInput(t, Target{Repository: root, SBOM: "sbom.json", Binary: bin})
	m, err := (LocalSnapshotBuilder{AllowExternalArtifacts: true}).Build(context.Background(), in)
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	sbom, ok := materialByID(set, "sbom")
	if !ok || sbom.Availability != MaterialAvailable || sbom.Kind != MaterialSBOM {
		t.Fatalf("sbom material = %+v (ok=%v)", sbom, ok)
	}
	b, ok := materialByID(set, "binary")
	if !ok || b.Availability != MaterialAvailable || b.Kind != MaterialBinary {
		t.Fatalf("binary material = %+v (ok=%v)", b, ok)
	}
	// Roles must be recorded on the snapshot manifest artifacts.
	var sawSBOM, sawBin bool
	for _, a := range m.Artifacts {
		if a.Role == "sbom" {
			sawSBOM = true
		}
		if a.Role == "binary" {
			sawBin = true
		}
	}
	if !sawSBOM || !sawBin {
		t.Fatalf("artifact roles missing: %+v", m.Artifacts)
	}
}

func TestPackageCheckModuleAbsent(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)
	tool := fakeGoTool{modules: []affected.Module{
		{Path: "example.org/service", Main: true},
		{Path: "example.org/parser", Version: "v1.4.2"},
	}}
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, tool)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	res := CheckPackageVersion(
		IntakeProposal{Package: "example.org/unrelated", Version: "9.9.9"},
		set, AdvisoryProjection{}, "")
	if res.Class != CheckModuleAbsent {
		t.Fatalf("class = %q, want module absent", res.Class)
	}
	// Absence is a fact about the build graph, never proof of safety.
	if !strings.Contains(res.Reason, "absent") || !hasLim(res.Limitations, "absence") {
		t.Fatalf("absent reason/limitation missing caveat: %q %+v", res.Reason, res.Limitations)
	}

	v := ValidatePackageVersion(context.Background(),
		IntakeProposal{Package: "example.org/unrelated", Component: "service-example"},
		set, AdvisoryProjection{})
	if len(v.Errors) != 0 {
		t.Fatalf("module absence must not be a technical error: %v", v.Errors)
	}
	pkgF, ok := v.Field("package")
	if !ok || pkgF.Status != IntakeValid {
		t.Fatalf("complete-graph absence must keep package claim valid: %+v", pkgF)
	}
	checkF, ok := v.Field("package_check")
	if !ok || checkF.Value != string(CheckModuleAbsent) {
		t.Fatalf("package_check = %+v (ok=%v)", checkF, ok)
	}
	if len(checkF.Provenance) == 0 {
		t.Fatal("package_check lacks provenance")
	}
}

func TestPackageCheckVersionMismatchNotAbsent(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	res := CheckPackageVersion(
		IntakeProposal{Package: "example.org/parser", Version: "1.9.9"},
		set, AdvisoryProjection{}, "")
	if res.Class != CheckVersionMismatch {
		t.Fatalf("class = %q, want version mismatch", res.Class)
	}
	if res.Class == CheckModuleAbsent {
		t.Fatal("version mismatch must never collapse into module absent")
	}
	if res.ResolvedVersion != "v1.4.2" {
		t.Fatalf("resolved = %q, want v1.4.2", res.ResolvedVersion)
	}
}

func TestPackageCheckAffectedRange(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	adv := AdvisoryProjection{AffectedModules: []domain.AffectedModule{{
		Module:           "example.org/parser",
		AffectedVersions: []domain.VersionRange{{Introduced: "1.0.0", Fixed: "1.5.0"}},
	}}}
	res := CheckPackageVersion(
		IntakeProposal{Package: "example.org/parser", Version: "1.4.2"},
		set, adv, "")
	if res.Class != CheckAffectedRange {
		t.Fatalf("class = %q, want version in affected range", res.Class)
	}
}

func TestPackageCheckConfirmedOutsideRange(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.6.0")
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n\nrequire example.org/parser v1.6.0\n")
	m := materialManifest(t, root)
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	adv := AdvisoryProjection{AffectedModules: []domain.AffectedModule{{
		Module:           "example.org/parser",
		AffectedVersions: []domain.VersionRange{{Fixed: "1.5.0"}},
	}}}
	res := CheckPackageVersion(
		IntakeProposal{Package: "example.org/parser", Version: "1.6.0"},
		set, adv, "")
	if res.Class != CheckVersionConfirmed {
		t.Fatalf("class = %q, want version confirmed", res.Class)
	}
}

func TestPackageCheckLimitedGraph(t *testing.T) {
	root := t.TempDir()
	// No go.mod, no vendor, no tool output — only a stray go.sum-free tree.
	writeFile(t, filepath.Join(root, "main.py"), "print(1)\n")
	m := materialManifest(t, root)
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	res := CheckPackageVersion(
		IntakeProposal{Package: "example.org/parser", Version: "1.4.2"},
		set, AdvisoryProjection{}, "")
	if res.Class != CheckUnresolved {
		t.Fatalf("class = %q, want unresolved", res.Class)
	}
	if len(res.Limitations) == 0 {
		t.Fatal("unresolved check must carry a limitation")
	}
}

func TestPackageCheckAdvisoryConfirmed(t *testing.T) {
	// No module graph at all: the advisory still confirms the claim.
	set := MaterialSet{}
	adv := AdvisoryProjection{AffectedModules: []domain.AffectedModule{{
		Module:           "example.org/parser",
		AffectedVersions: []domain.VersionRange{{Fixed: "1.5.0"}},
	}}}
	v := ValidatePackageVersion(context.Background(),
		IntakeProposal{Package: "example.org/parser", Version: "1.4.2", Component: "service-example"},
		set, adv)
	pkgF, _ := v.Field("package")
	if pkgF.Status != IntakeValid {
		t.Fatalf("package status = %q, want VALID (advisory)", pkgF.Status)
	}
	found := false
	for _, p := range pkgF.Provenance {
		if p == "advisory" {
			found = true
		}
	}
	if !found {
		t.Fatalf("package provenance = %v, want advisory", pkgF.Provenance)
	}
}

func TestPackageCheckMalformedPURL(t *testing.T) {
	set := MaterialSet{}
	v := ValidatePackageVersion(context.Background(),
		IntakeProposal{Package: "pkg:golang/@1.4.2"},
		set, AdvisoryProjection{})
	pkgF, _ := v.Field("package")
	if pkgF.Status != IntakeInvalid {
		t.Fatalf("package status = %q, want INVALID", pkgF.Status)
	}
	if len(v.Errors) == 0 {
		t.Fatal("malformed PURL must raise an error")
	}
}

func TestPackageCheckRequiredLocatorMissing(t *testing.T) {
	// No package, no component, no product: nothing binds the finding to a
	// source — materialization cannot proceed, so this is an error.
	v := ValidatePackageVersion(context.Background(),
		IntakeProposal{Version: "1.4.2"},
		MaterialSet{}, AdvisoryProjection{})
	if len(v.Errors) == 0 {
		t.Fatal("missing every source locator must be an error")
	}
	// Optional package context with a component to resolve against is a
	// limitation, not an error.
	v = ValidatePackageVersion(context.Background(),
		IntakeProposal{Component: "service-example"},
		MaterialSet{}, AdvisoryProjection{})
	if len(v.Errors) != 0 {
		t.Fatalf("missing optional package must not be an error: %v", v.Errors)
	}
	pkgF, _ := v.Field("package")
	if pkgF.Status != IntakeUnavailable {
		t.Fatalf("package status = %q, want UNAVAILABLE", pkgF.Status)
	}
}

func TestPackageCheckStdlibUnknownToolchain(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	// stdlib claims resolve against the release toolchain, not module data;
	// an unknown release toolchain keeps the check unresolved.
	res := CheckPackageVersion(
		IntakeProposal{Package: "stdlib", Version: "1.24.0"},
		set, AdvisoryProjection{AffectedModules: []domain.AffectedModule{{Module: "stdlib"}}}, "")
	if res.Class != CheckUnresolved {
		t.Fatalf("class = %q, want unresolved for unknown release toolchain", res.Class)
	}
	if !hasLim(res.Limitations, "toolchain") {
		t.Fatalf("stdlib limitation must name the toolchain: %v", res.Limitations)
	}
	// With a known toolchain the range check resolves deterministically.
	res = CheckPackageVersion(
		IntakeProposal{Package: "stdlib", Version: "1.24.0"},
		set, AdvisoryProjection{AffectedModules: []domain.AffectedModule{{
			Module:           "stdlib",
			AffectedVersions: []domain.VersionRange{{Fixed: "1.24.5"}},
		}}}, "1.24.0")
	if res.Class != CheckAffectedRange {
		t.Fatalf("class = %q, want affected range for toolchain 1.24.0 < 1.24.5", res.Class)
	}
}

func TestDeployFactsEmptyUnavailable(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service-example", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.Deploy == nil {
		t.Fatal("deploy facts missing")
	}
	if len(set.Deploy.Facts) != 0 {
		t.Fatalf("deploy facts = %d, want none", len(set.Deploy.Facts))
	}
	if set.Deploy.Perimeter != domain.PerimeterUnknown {
		t.Fatalf("perimeter = %q, want unknown (empty scan is never isolated)", set.Deploy.Perimeter)
	}
	mat, ok := materialByID(set, "deploy-scan")
	if !ok || mat.Availability != MaterialUnavailable {
		t.Fatalf("deploy-scan material = %+v (ok=%v), want UNAVAILABLE", mat, ok)
	}
	if !hasLim(mat.Limitations, "deployment") {
		t.Fatalf("deploy-scan lacks a limitation: %v", mat.Limitations)
	}
}

func TestDeployFactsClusterIP(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service-example", "example.org/parser", "v1.4.2")
	writeFile(t, filepath.Join(root, "deploy", "service.yaml"), `apiVersion: v1
kind: Service
metadata:
  name: service-example
spec:
  type: ClusterIP
  ports:
  - port: 8080
`)
	m := materialManifest(t, root)
	m.Materialization.SourceID = "service-example"

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.Deploy == nil || len(set.Deploy.Facts) == 0 {
		t.Fatal("deploy facts empty for a ClusterIP manifest")
	}
	if set.Deploy.Perimeter != domain.PerimeterClusterInternal {
		t.Fatalf("perimeter = %q, want cluster-internal: %s", set.Deploy.Perimeter, set.Deploy.Rationale)
	}
	mat, ok := materialByID(set, "deploy-scan")
	if !ok || mat.Availability != MaterialAvailable {
		t.Fatalf("deploy-scan = %+v (ok=%v)", mat, ok)
	}
	if mat.SHA256 == "" {
		t.Fatal("deploy-scan material lacks facts hash")
	}
}

func TestDeployFactsPublicIngress(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service-example", "example.org/parser", "v1.4.2")
	writeFile(t, filepath.Join(root, "deploy", "ingress.yaml"), `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: service-example
spec:
  rules:
  - host: service.example.org
`)
	m := materialManifest(t, root)
	m.Materialization.SourceID = "service-example"

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.Deploy.Perimeter != domain.PerimeterPublic {
		t.Fatalf("perimeter = %q, want public", set.Deploy.Perimeter)
	}
}

func writeTestZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTestTGZ(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDeployFactsArchiveTGZ(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service-example", "example.org/parser", "v1.4.2")
	writeTestTGZ(t, filepath.Join(root, "deploy-manifests.tar.gz"), map[string]string{
		"manifests/service.yaml": `apiVersion: v1
kind: Service
metadata:
  name: service-example
spec:
  type: ClusterIP
`,
	})
	m := materialManifest(t, root)
	m.Materialization.SourceID = "service-example"

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	arch, ok := materialByID(set, "deploy-archive:deploy-manifests.tar.gz")
	if !ok || arch.Availability != MaterialAvailable {
		t.Fatalf("deploy archive material = %+v (ok=%v)", arch, ok)
	}
	if arch.SHA256 == "" {
		t.Fatal("archive material lacks sha256")
	}
	if len(set.Deploy.Facts) == 0 {
		t.Fatal("archive manifest produced no facts")
	}
}

func TestDeployFactsArchiveZipSlip(t *testing.T) {
	outer := t.TempDir()
	root := filepath.Join(outer, "repo")
	writeModuleTree(t, root, "example.org/service-example", "example.org/parser", "v1.4.2")
	writeTestZip(t, filepath.Join(root, "deploy.zip"), map[string]string{
		"../../evil.yaml":              "evil: true\n",
		"manifests/../evil-inner.yaml": "evil: true\n",
	})
	m := materialManifest(t, root)

	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	arch, ok := materialByID(set, "deploy-archive:deploy.zip")
	if !ok || arch.Availability != MaterialInvalid {
		t.Fatalf("zip-slip archive must be INVALID, got %+v (ok=%v)", arch, ok)
	}
	if _, err := os.Stat(filepath.Join(outer, "evil.yaml")); !os.IsNotExist(err) {
		t.Fatalf("zip-slip wrote outside the extraction root: %v", err)
	}
}

func TestDeployFactsConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service-example", "example.org/parser", "v1.4.2")
	deploy := t.TempDir()
	writeFile(t, filepath.Join(deploy, "service.yaml"), `apiVersion: v1
kind: Service
metadata:
  name: service-example
spec:
  type: ClusterIP
`)
	m := materialManifest(t, root)
	m.Materialization.SourceID = "service-example"
	cfg := SiteConfig{Deployment: DeploymentConfig{Paths: []string{deploy}}}

	set, err := CollectMaterials(context.Background(), m, cfg, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if len(set.Deploy.Facts) == 0 {
		t.Fatal("configured deployment path produced no facts")
	}
}

func TestMaterialFactsProvenanceAndHash(t *testing.T) {
	root := t.TempDir()
	writeModuleTree(t, root, "example.org/service", "example.org/parser", "v1.4.2")
	m := materialManifest(t, root)
	set, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if h := MaterialSetHash(set); h == "" || len(h) != 64 {
		t.Fatalf("material set hash = %q", h)
	}
	set2, err := CollectMaterials(context.Background(), m, SiteConfig{}, nil)
	if err != nil {
		t.Fatalf("CollectMaterials 2: %v", err)
	}
	if MaterialSetHash(set) != MaterialSetHash(set2) {
		t.Fatal("material set hash is not deterministic")
	}
}

// TestMaterialsClassifyTestOnlyDependency proves the distinction on real
// source: the fixture's product binary never imports the vendored uuid
// package, only its test does, so the module must be classified test-only and
// the dismissal rule must fire on that fact.
func TestMaterialsClassifyTestOnlyDependency(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "falsifier-test-only"))
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "go.mod")); statErr != nil {
		t.Skipf("fixture missing: %v", statErr)
	}
	set, err := CollectMaterials(context.Background(), SnapshotManifest{
		SchemaVersion: SnapshotSchemaVersion,
		FindingID:     "finding-test-only",
		Repository:    root,
		ContentHash:   "test-only-fixture",
	}, SiteConfig{}, affected.ExecGoTool{})
	if err != nil {
		t.Fatalf("CollectMaterials: %v", err)
	}
	if set.ModuleGraph == nil {
		t.Fatalf("no module graph: %v", set.Limitations)
	}
	if set.ModuleGraph.TestOnly == nil {
		t.Fatalf("test-only distinction not established: %v", set.Limitations)
	}
	if !set.ModuleGraph.TestOnly["github.com/google/uuid"] {
		t.Fatalf("uuid not classified test-only: %+v", set.ModuleGraph.TestOnly)
	}

	s0 := versionRangeStage0(CheckAffectedRange)
	s0.Materials = set
	s0.PackageCheck.ResolvedPath = "github.com/google/uuid"
	f := testOnlyFact(s0)
	if f == nil || f.Status != ObsSupports {
		t.Fatalf("test-only fact = %+v", f)
	}
}

func TestPackageInventoryMaterialsRejectsPartialGraph(t *testing.T) {
	tool := fakeGoTool{modules: []affected.Module{{Path:"inventory.test/product", Main:true}}, packages: []affected.Package{{ImportPath:"inventory.test/product", Name:"main", Deps:[]string{"missing"}}}}
	g, mats, lims := collectModuleGraph(context.Background(), t.TempDir(), tool, domain.ProductSnapshot{})
	if g == nil || !g.Complete { t.Fatal("package failure must not erase independent module graph") }
	if len(g.Linked) != 0 || g.PackageInventory != nil || len(lims) == 0 { t.Fatalf("partial package graph admitted: %+v %v", g, lims) }
	for _, m := range mats { if m.Kind == MaterialBuildGraph { t.Fatal("partial graph published as available build material") } }
	tool.packages[0].Deps = nil
	g, _, _ = collectModuleGraph(context.Background(), t.TempDir(), tool, domain.ProductSnapshot{})
	if !g.Linked["inventory.test/product"] || g.PackageInventory == nil || g.PackageInventory.RawReference != "sha256:"+sha256hex([]byte(g.PackageInventory.RawStream)) { t.Fatalf("complete inventory binding missing: %+v", g) }
}

func TestPackageInventoryTestOnlyRequiresClosedGraphs(t *testing.T) {
	g := &ModuleGraph{Modules:[]ModuleVersion{{Path:"inventory.test/product"}}}
	valid := []byte(`{"ImportPath":"inventory.test/product"}`)
	for _, raw := range [][]byte{[]byte(`{"ImportPath":"inventory.test/product"} {`), []byte(`{"ImportPath":"inventory.test/product","Error":{"Err":"load failed"}}`), []byte(`{"ImportPath":"inventory.test/product"} {"ImportPath":"inventory.test/product"}`)} {
		if _, err := testOnlyModules(g, raw, valid); err == nil { t.Fatal("partial test graph admitted") }
		if _, err := testOnlyModules(g, valid, raw); err == nil { t.Fatal("partial product graph admitted") }
	}
}
