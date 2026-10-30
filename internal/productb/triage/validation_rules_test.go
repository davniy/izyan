package triage

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

// localGoVersion returns the bare version of `go` in PATH.
func localGoVersion(t *testing.T) string {
	t.Helper()
	v, err := toolchain.LocalVersion(context.Background())
	if err != nil {
		t.Skipf("no local go: %v", err)
	}
	return v
}

// offlineForToolchain forces deterministic toolchain resolution: SDK lookup
// misses for fictional versions, and GOTOOLCHAIN download cannot reach a proxy.
func offlineForToolchain(t *testing.T) {
	t.Helper()
	t.Setenv("GOPROXY", "off")
	t.Setenv("GONOSUMCHECK", "1")
}

func TestToolchainFactsGoModDirectiveNotRelease(t *testing.T) {
	// The go.mod `go` directive is a language minimum — spec §4.2 forbids it
	// as release-toolchain evidence.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	fact := DiscoverReleaseToolchain(context.Background(), IntakeProposal{}, m)
	if fact.Version != "" {
		t.Fatalf("go.mod go-directive must not produce a release toolchain: %+v", fact)
	}
	if fact.Source != domain.GoVersionSource("") {
		t.Fatalf("source = %q, want empty (unknown)", fact.Source)
	}
	if !hasLim(fact.Limitations, "go.mod") {
		t.Fatalf("missing minimum-version limitation: %v", fact.Limitations)
	}
}

func TestToolchainFactsToolchainDirective(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n\ntoolchain go1.24.6\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	fact := DiscoverReleaseToolchain(context.Background(), IntakeProposal{}, m)
	if fact.Version != "go1.24.6" {
		t.Fatalf("release toolchain = %q, want go1.24.6", fact.Version)
	}
	if fact.Source != domain.GoVersionSourceToolchain {
		t.Fatalf("source = %q, want toolchain", fact.Source)
	}
	if !strings.Contains(fact.Location, "go.mod") {
		t.Fatalf("location = %q", fact.Location)
	}
}

func TestToolchainFactsVersionFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n")
	writeFile(t, filepath.Join(root, ".go-version"), "1.24.6\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	fact := DiscoverReleaseToolchain(context.Background(), IntakeProposal{}, m)
	if fact.Version != "go1.24.6" {
		t.Fatalf("release toolchain = %q, want go1.24.6", fact.Version)
	}
	if fact.Source != domain.GoVersionSourceVersionFile {
		t.Fatalf("source = %q, want version-file", fact.Source)
	}
}

func TestToolchainFactsBinary(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go binary in PATH")
	}
	abs, err := filepath.Abs(gobin)
	if err != nil {
		t.Fatal(err)
	}
	m := SnapshotManifest{
		Repository: filepath.Dir(abs),
		Artifacts:  []SnapshotFile{{Path: abs, Role: "binary"}},
	}
	fact := DiscoverReleaseToolchain(context.Background(), IntakeProposal{}, m)
	if fact.Version == "" {
		t.Fatal("embedded toolchain fact missing for the go binary itself")
	}
	if fact.Source != domain.GoVersionSourceBinary {
		t.Fatalf("source = %q, want binary", fact.Source)
	}
}

func TestToolchainFactsClaimFallback(t *testing.T) {
	// With no deterministic evidence, an intake go_version claim is used as
	// the analysis target — recorded as a claim, never as release evidence.
	m := SnapshotManifest{}
	fact := DiscoverReleaseToolchain(context.Background(),
		IntakeProposal{GoVersion: "go1.25.1"}, m)
	if fact.Version != "go1.25.1" || fact.Source != "intake" {
		t.Fatalf("fact = %+v, want intake go1.25.1", fact)
	}
	if !hasLim(fact.Limitations, "unverified") {
		t.Fatalf("claim fallback must carry an unverified limitation: %v", fact.Limitations)
	}
}

func TestToolchainFactsClaimVsEvidenceConflict(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n\ntoolchain go1.24.6\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	fact := DiscoverReleaseToolchain(context.Background(),
		IntakeProposal{GoVersion: "go1.25.9"}, m)
	if fact.Version != "go1.24.6" {
		t.Fatalf("evidence must win over the LLM claim: %+v", fact)
	}
	if !fact.Conflict {
		t.Fatal("conflicting intake claim not recorded")
	}
}

func TestReleaseToolchainResolveExactTarget(t *testing.T) {
	cur := localGoVersion(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	tc, lims, err := ResolveReleaseToolchain(context.Background(),
		IntakeProposal{GoVersion: "go" + cur}, m, SiteConfig{})
	if err != nil {
		t.Fatalf("ResolveReleaseToolchain: %v", err)
	}
	if tc.Mismatch {
		t.Fatalf("local go%s should satisfy target go%s: %+v %v", cur, cur, tc, lims)
	}
	if tc.Mode != toolchain.ModeLocal {
		t.Fatalf("mode = %q, want local", tc.Mode)
	}
}

func TestReleaseToolchainResolveMismatch(t *testing.T) {
	offlineForToolchain(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	tc, lims, err := ResolveReleaseToolchain(context.Background(),
		IntakeProposal{GoVersion: "go0.0.0-nonexistent"}, m, SiteConfig{})
	if err != nil {
		t.Fatalf("ResolveReleaseToolchain: %v", err)
	}
	if !tc.Mismatch {
		t.Fatalf("fictional target must mismatch: %+v", tc)
	}
	if !hasLim(lims, "toolchain") {
		t.Fatalf("mismatch limitation missing: %v", lims)
	}
}

func TestReleaseToolchainUnknownIsLimitation(t *testing.T) {
	offlineForToolchain(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.org/service\n\ngo 1.23\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	m := materialManifest(t, root)

	cfg := SiteConfig{Toolchain: ToolchainConfig{Rules: []ToolchainRule{{
		Ecosystem:                        "go",
		RequireReleaseToolchainForStdlib: true,
		AllowLocalToolchainFallback:      false,
	}}}}
	tc, lims, err := ResolveReleaseToolchain(context.Background(), IntakeProposal{}, m, cfg)
	if err != nil {
		t.Fatalf("unknown release toolchain is a limitation, not an error: %v", err)
	}
	if tc.Mismatch {
		t.Fatalf("no target was requested; local env must not mismatch: %+v", tc)
	}
	if !hasLim(lims, "release toolchain") {
		t.Fatalf("unknown-toolchain limitation missing: %v", lims)
	}
	// The go.mod go directive must not be substituted for the release toolchain.
	if !hasLim(lims, "go.mod") {
		t.Fatalf("go.mod caveat missing: %v", lims)
	}
}

func TestValidationRuleIDs(t *testing.T) {
	rules := ValidationRules(SnapshotManifest{})
	if len(rules) == 0 {
		t.Fatal("no validation rules registered")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID() == "" {
			t.Fatal("rule with empty id")
		}
		if seen[r.ID()] {
			t.Fatalf("duplicate rule id %q", r.ID())
		}
		seen[r.ID()] = true
	}
}

func TestPackageCheckRuleShape(t *testing.T) {
	rule := PackageVersionRule{}
	fv := rule.Validate(context.Background(), ValidationInput{
		Proposal: IntakeProposal{Package: "example.org/parser", Version: "1.4.2"},
		Materials: MaterialSet{ModuleGraph: &ModuleGraph{
			Source:   "go.mod",
			Complete: false,
			Modules:  []ModuleVersion{{Path: "example.org/parser", Version: "v1.4.2"}},
		}},
		Advisory: AdvisoryProjection{AffectedModules: []domain.AffectedModule{{
			Module:           "example.org/parser",
			AffectedVersions: []domain.VersionRange{{Fixed: "1.5.0"}},
		}}},
	})
	if fv.Field != "package_check" {
		t.Fatalf("field = %q", fv.Field)
	}
	if fv.Status != IntakeValid {
		t.Fatalf("deterministic fact status = %q, want VALID", fv.Status)
	}
	if fv.Value != string(CheckAffectedRange) {
		t.Fatalf("value = %q, want affected-range", fv.Value)
	}
	if len(fv.Provenance) == 0 {
		t.Fatal("rule fact lacks provenance")
	}
}

func TestValidatePackageVersionFieldCoverage(t *testing.T) {
	// Every materialized field gets a verdict — no silent fields.
	v := ValidatePackageVersion(context.Background(),
		IntakeProposal{Package: "example.org/parser", Version: "1.4.2", Component: "svc"},
		MaterialSet{}, AdvisoryProjection{})
	names := map[string]bool{}
	for _, f := range v.Fields {
		names[f.Field] = true
	}
	for _, want := range []string{"package", "version", "package_check"} {
		if !names[want] {
			t.Fatalf("missing field %q in %+v", want, v.Fields)
		}
	}
}
