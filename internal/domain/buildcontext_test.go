package domain

import (
	"errors"
	"strings"
	"testing"
)

func artifactTarget() ProductTarget {
	return ProductTarget{
		GOOS:            "linux",
		GOARCH:          "amd64",
		BuildTags:       []string{"netgo", "osusergo"},
		CGOEnabled:      false,
		Source:          ProductTargetSourceArtifactBuildInfo,
		Scope:           ProductTargetScopeArtifact,
		ArtifactSHA256:  strings.Repeat("a", 64),
		BuildInfoSHA256: strings.Repeat("b", 64),
	}
}

func TestBuildContextMatches(t *testing.T) {
	snap := ProductSnapshot{
		Repository:        "example.com/prod",
		Commit:            "abc123",
		ExternalCommitSHA: "ext-1",
		ContentHash:       "sha256:tree",
		GOOS:              "linux",
		GOARCH:            "amd64",
		BuildTags:         []string{"netgo", "osusergo"},
		CGOEnabled:        true,
		GoVersion:         "go1.24.1",
		GoModDirective:    "1.23",
		VendorMode:        true,
		GoWorkFile:        "go.work",
		GoFlags:           "-mod=vendor",
		ReplaceDirectives: []ReplaceDirective{{Old: "a", New: "b"}},
		BinaryPath:        "/out/prod",
	}
	target := artifactTarget()
	target.CGOEnabled = true
	snap.Target = &target

	base := EffectiveBuildContext(snap)
	clone := EffectiveBuildContext(snap)
	clone.BuildTags = []string{"osusergo", "netgo"} // order-insensitive
	if err := base.Matches(clone); err != nil {
		t.Fatalf("same context with reordered tags must match: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*BuildContext)
		field  string
	}{
		{"repository", func(b *BuildContext) { b.Repository = "other" }, "repository"},
		{"commit", func(b *BuildContext) { b.Commit = "def456" }, "commit"},
		{"external sha", func(b *BuildContext) { b.ExternalCommitSHA = "ext-2" }, "external_commit_sha"},
		{"content hash", func(b *BuildContext) { b.ContentHash = "other" }, "content_hash"},
		{"goos", func(b *BuildContext) { b.GOOS = "darwin" }, "goos"},
		{"goarch", func(b *BuildContext) { b.GOARCH = "arm64" }, "goarch"},
		{"tags", func(b *BuildContext) { b.BuildTags = []string{"netgo"} }, "build_tags"},
		{"cgo", func(b *BuildContext) { b.CGOEnabled = false }, "cgo_enabled"},
		{"go version", func(b *BuildContext) { b.GoVersion = "go1.25" }, "go_version"},
		{"go mod", func(b *BuildContext) { b.GoModDirective = "1.22" }, "go_mod_directive"},
		{"vendor", func(b *BuildContext) { b.VendorMode = false }, "vendor_mode"},
		{"workspace", func(b *BuildContext) { b.GoWorkFile = "" }, "go_work_file"},
		{"go flags", func(b *BuildContext) { b.GoFlags = "" }, "go_flags"},
		{"replace", func(b *BuildContext) {
			b.ReplaceDirectives = []ReplaceDirective{{Old: "a", New: "c"}}
		}, "replace_directives"},
		{"binary path", func(b *BuildContext) { b.BinaryPath = "/out/other" }, "binary_path"},
		{"binary digest", func(b *BuildContext) { b.BinarySHA256 = strings.Repeat("c", 64) }, "binary_sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := EffectiveBuildContext(snap)
			tc.mutate(&changed)
			err := base.Matches(changed)
			if err == nil {
				t.Fatal("divergent context must not match")
			}
			if !errors.Is(err, ErrBuildContextMismatch) {
				t.Fatalf("error %v must wrap ErrBuildContextMismatch", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q must name divergent field %q", err, tc.field)
			}
		})
	}
}

func TestBuildContextCapturesSlices(t *testing.T) {
	snap := ProductSnapshot{
		GOOS:              "linux",
		GOARCH:            "amd64",
		BuildTags:         []string{"netgo"},
		ReplaceDirectives: []ReplaceDirective{{Old: "a", New: "b"}},
	}
	target := artifactTarget()
	snap.Target = &target

	ctx := EffectiveBuildContext(snap)
	snap.BuildTags[0] = "mutated"
	snap.ReplaceDirectives[0].New = "mutated"
	target.ArtifactSHA256 = strings.Repeat("c", 64)

	if ctx.BuildTags[0] != "netgo" {
		t.Fatalf("captured tags were mutated: %v", ctx.BuildTags)
	}
	if ctx.ReplaceDirectives[0].New != "b" {
		t.Fatalf("captured replace directives were mutated: %v", ctx.ReplaceDirectives)
	}
	if ctx.BinarySHA256 != strings.Repeat("a", 64) {
		t.Fatalf("captured binary digest was mutated: %q", ctx.BinarySHA256)
	}
}

func TestValidateNegativeTarget(t *testing.T) {
	valid := func() (ProductSnapshot, ProductTarget) {
		target := artifactTarget()
		return ProductSnapshot{
			GOOS:       target.GOOS,
			GOARCH:     target.GOARCH,
			BuildTags:  append([]string(nil), target.BuildTags...),
			CGOEnabled: target.CGOEnabled,
			Target:     &target,
		}, target
	}

	t.Run("missing target", func(t *testing.T) {
		if err := ValidateNegativeTarget(ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}); err == nil {
			t.Fatal("a snapshot without target provenance must be refused")
		}
	})

	t.Run("host default", func(t *testing.T) {
		snap, _ := valid()
		snap.Target = &ProductTarget{
			GOOS: "linux", GOARCH: "amd64", CGOEnabled: false,
			Source: ProductTargetSourceHostDefault,
		}
		if err := ValidateNegativeTarget(snap); err == nil {
			t.Fatal("host default must not ground a build-dependent negative")
		}
	})

	t.Run("invalid target record", func(t *testing.T) {
		snap, target := valid()
		target.GOOS = "Linux!"
		snap.Target = &target
		if err := ValidateNegativeTarget(snap); err == nil {
			t.Fatal("invalid target record must be refused")
		}
	})

	t.Run("artifact target without digests", func(t *testing.T) {
		snap, target := valid()
		target.ArtifactSHA256 = ""
		snap.Target = &target
		if err := ValidateNegativeTarget(snap); err == nil {
			t.Fatal("artifact target without a digest binding must be refused")
		}
	})

	t.Run("valid matching target", func(t *testing.T) {
		snap, _ := valid()
		if err := ValidateNegativeTarget(snap); err != nil {
			t.Fatalf("valid target refused: %v", err)
		}
	})

	t.Run("platform mismatch", func(t *testing.T) {
		snap, _ := valid()
		snap.GOARCH = "arm64"
		if err := ValidateNegativeTarget(snap); !errors.Is(err, ErrBuildContextMismatch) {
			t.Fatalf("error=%v, want ErrBuildContextMismatch", err)
		}
	})

	t.Run("tag mismatch", func(t *testing.T) {
		snap, _ := valid()
		snap.BuildTags = []string{"netgo"}
		if err := ValidateNegativeTarget(snap); !errors.Is(err, ErrBuildContextMismatch) {
			t.Fatalf("error=%v, want ErrBuildContextMismatch", err)
		}
	})

	t.Run("cgo mismatch", func(t *testing.T) {
		snap, _ := valid()
		snap.CGOEnabled = true
		if err := ValidateNegativeTarget(snap); !errors.Is(err, ErrBuildContextMismatch) {
			t.Fatalf("error=%v, want ErrBuildContextMismatch", err)
		}
	})

	t.Run("operator declared target", func(t *testing.T) {
		snap := ProductSnapshot{
			GOOS: "linux", GOARCH: "amd64", BuildTags: []string{"netgo"},
			Target: &ProductTarget{
				GOOS: "linux", GOARCH: "amd64", BuildTags: []string{"netgo"},
				Source: ProductTargetSourceOperatorDeclared,
				Scope:  ProductTargetScopeOperator,
			},
		}
		if err := ValidateNegativeTarget(snap); err != nil {
			t.Fatalf("scoped operator target refused: %v", err)
		}
	})
}
