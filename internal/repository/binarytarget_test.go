package repository

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// targetFromBuildInfo is the one extraction shared by the artifact channel
// and plain --binary: complete, unambiguous settings produce a validated
// digest-bound target; anything else fails closed to nil.
func TestTargetFromBuildInfo(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	settings := func(extra ...debug.BuildSetting) []debug.BuildSetting {
		base := []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "arm64"},
			{Key: "CGO_ENABLED", Value: "1"},
			{Key: "-tags", Value: "netgo,osusergo"},
		}
		return append(base, extra...)
	}

	got := targetFromBuildInfo(&debug.BuildInfo{Settings: settings()}, digest, digest, "bin/tool")
	if got == nil {
		t.Fatal("complete settings produced no target")
	}
	if got.GOOS != "linux" || got.GOARCH != "arm64" || !got.CGOEnabled {
		t.Fatalf("target facts = %+v", got)
	}
	if strings.Join(got.BuildTags, ",") != "netgo,osusergo" {
		t.Fatalf("target tags = %v", got.BuildTags)
	}
	if got.Source != domain.ProductTargetSourceArtifactBuildInfo ||
		got.Scope != domain.ProductTargetScopeArtifact ||
		got.ArtifactSHA256 != digest || got.BuildInfoSHA256 != digest ||
		got.BinaryMember != "bin/tool" {
		t.Fatalf("target provenance = %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("target does not validate: %v", err)
	}

	// A bare binary has no enclosing artifact and no member; both digests
	// are the binary's own SHA-256.
	bare := targetFromBuildInfo(&debug.BuildInfo{Settings: settings()}, digest, digest, "")
	if bare == nil || bare.BinaryMember != "" {
		t.Fatalf("bare target = %+v", bare)
	}

	tests := []struct {
		name     string
		bi       *debug.BuildInfo
		artifact string
		build    string
	}{
		{
			name: "duplicate setting",
			bi: &debug.BuildInfo{Settings: append(settings(),
				debug.BuildSetting{Key: "GOOS", Value: "windows"})},
			artifact: digest, build: digest,
		},
		{
			name: "missing cgo setting",
			bi: &debug.BuildInfo{Settings: []debug.BuildSetting{
				{Key: "GOOS", Value: "linux"},
				{Key: "GOARCH", Value: "arm64"},
			}},
			artifact: digest, build: digest,
		},
		{
			name: "invalid cgo value",
			bi: &debug.BuildInfo{Settings: []debug.BuildSetting{
				{Key: "GOOS", Value: "linux"},
				{Key: "GOARCH", Value: "arm64"},
				{Key: "CGO_ENABLED", Value: "yes"},
			}},
			artifact: digest, build: digest,
		},
		{
			name: "tags hidden in GOFLAGS",
			bi: &debug.BuildInfo{Settings: settings(
				debug.BuildSetting{Key: "GOFLAGS", Value: "-tags=netgo"})},
			artifact: digest, build: digest,
		},
		{
			name: "invalid platform",
			bi: &debug.BuildInfo{Settings: []debug.BuildSetting{
				{Key: "GOOS", Value: "Linux!"},
				{Key: "GOARCH", Value: "arm64"},
				{Key: "CGO_ENABLED", Value: "0"},
			}},
			artifact: digest, build: digest,
		},
		{
			name:     "missing artifact digest",
			bi:       &debug.BuildInfo{Settings: settings()},
			artifact: "", build: digest,
		},
		{
			name:     "missing build-info digest",
			bi:       &debug.BuildInfo{Settings: settings()},
			artifact: digest, build: "",
		},
		{
			name:     "nil build info",
			bi:       nil,
			artifact: digest, build: digest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetFromBuildInfo(tc.bi, tc.artifact, tc.build, ""); got != nil {
				t.Fatalf("expected fail-closed nil, got %+v", got)
			}
		})
	}
}

// A plain binary's build info is read from the file itself and bound to the
// file's SHA-256. An unreadable binary or incomplete settings is an error
// the caller records separately from release-toolchain availability.
func TestBuildInfoTargetFromPath(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real binary")
	}
	dir := t.TempDir()
	exe := buildTestBinaryFor(t, dir, "example.com/binary-target", "linux", "arm64", "netgo")
	wantSHA, _, err := hashFileSHA256(context.Background(), exe)
	if err != nil {
		t.Fatal(err)
	}
	got, err := buildInfoTargetFromPath(context.Background(), exe)
	if err != nil {
		t.Fatalf("buildInfoTargetFromPath: %v", err)
	}
	if got == nil {
		t.Fatal("no target extracted")
	}
	if got.GOOS != "linux" || got.GOARCH != "arm64" || got.CGOEnabled {
		t.Fatalf("target facts = %+v", got)
	}
	if strings.Join(got.BuildTags, ",") != "netgo" {
		t.Fatalf("target tags = %v", got.BuildTags)
	}
	if got.ArtifactSHA256 != wantSHA || got.BuildInfoSHA256 != wantSHA {
		t.Fatalf("target digests = %q/%q, want %q", got.ArtifactSHA256, got.BuildInfoSHA256, wantSHA)
	}
	if got.BinaryMember != "" {
		t.Fatalf("bare binary target member = %q", got.BinaryMember)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("target does not validate: %v", err)
	}

	if got, err := buildInfoTargetFromPath(context.Background(), ""); got != nil || err != nil {
		t.Fatalf("empty path = %+v, %v; want nil, nil", got, err)
	}
	notGo := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(notGo, []byte("not a go binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildInfoTargetFromPath(context.Background(), notGo); err == nil {
		t.Fatal("non-Go file produced a target")
	}
}
