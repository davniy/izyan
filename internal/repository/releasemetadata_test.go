package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// TestLoadReleaseMetadata covers the release-metadata/1 channel contract:
// a well-formed document yields a typed AUTHORITATIVE summary; every
// malformed, unreadable or credential-bearing input returns the same
// NOT_RUN/RELEASE_METADATA_INVALID outcome — never an error, never a
// silent skip.
func TestLoadReleaseMetadata(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("resolved document", func(t *testing.T) {
		p := write("meta.json", `{
		  "schema": "release-metadata/1",
		  "go_version": "go1.25.10",
		  "modules": [{"path":"example.com/dep","version":"v1.4.0"}],
		  "artifact_sha256": "`+strings.Repeat("ab", 32)+`"
		}`)
		sum := LoadReleaseMetadata(p)
		if sum == nil || sum.Status != domain.ReleaseStatusResolved {
			t.Fatalf("status %+v", sum)
		}
		if len(sum.Items) != 1 || sum.Items[0].Version != "go1.25.10" ||
			sum.Items[0].TrustClass != domain.ReleaseTrustAuthoritative ||
			sum.Items[0].Source != domain.GoVersionSourceExplicit {
			t.Fatalf("items %+v", sum.Items)
		}
		if len(sum.Modules) != 1 || sum.Modules[0].Path != "example.com/dep" {
			t.Fatalf("modules %+v", sum.Modules)
		}
		if sum.ArtifactSHA256 != strings.Repeat("ab", 32) {
			t.Fatalf("artifact sha %q", sum.ArtifactSHA256)
		}
	})

	t.Run("modules only", func(t *testing.T) {
		p := write("mods.json", `{"schema":"release-metadata/1",
		  "modules":[{"path":"example.com/net","version":"v0.9.1"}]}`)
		sum := LoadReleaseMetadata(p)
		if sum == nil || sum.Status != domain.ReleaseStatusUnknown ||
			len(sum.Modules) != 1 {
			t.Fatalf("summary %+v", sum)
		}
	})

	t.Run("build target facts", func(t *testing.T) {
		p := write("target.json", `{
		  "schema": "release-metadata/1",
		  "target": {"goos":"linux","goarch":"amd64","build_tags":["netgo"],"cgo_enabled":false}
		}`)
		sum := LoadReleaseMetadata(p)
		if sum == nil || sum.Status != domain.ReleaseStatusUnknown {
			t.Fatalf("target-only document status %+v", sum)
		}
		if sum.Target == nil || sum.Target.GOOS != "linux" || sum.Target.GOARCH != "amd64" ||
			sum.Target.CGOEnabled || strings.Join(sum.Target.BuildTags, ",") != "netgo" {
			t.Fatalf("target %+v", sum.Target)
		}
		if sum.Target.Source != domain.ProductTargetSourceReleaseMetadata ||
			sum.Target.Scope != domain.ProductTargetScopeRelease {
			t.Fatalf("target provenance %+v", sum.Target)
		}
	})

	for name, body := range map[string]string{
		"wrong schema":     `{"schema":"release-metadata/0","go_version":"go1.25.0"}`,
		"target no cgo":    `{"schema":"release-metadata/1","target":{"goos":"linux","goarch":"amd64"}}`,
		"target bad goos":  `{"schema":"release-metadata/1","target":{"goos":"Linux","goarch":"amd64","cgo_enabled":false}}`,
		"target no goarch": `{"schema":"release-metadata/1","target":{"goos":"linux","cgo_enabled":false}}`,
		"policy assertion": `{"schema":"release-metadata/1","supported_targets":["linux"]}`,
		"unknown key":      `{"schema":"release-metadata/1","go_version":"go1.25.0","extra":1}`,
		"malformed json":   `{"schema":`,
		"empty document":   `{"schema":"release-metadata/1"}`,
		"bad version":      `{"schema":"release-metadata/1","go_version":"not-a-version"}`,
		"bad module path":  `{"schema":"release-metadata/1","modules":[{"path":"https://x/y","version":"v1.0.0"}]}`,
		"bad module ver":   `{"schema":"release-metadata/1","modules":[{"path":"a/b","version":"latest"}]}`,
		"bad digest":       `{"schema":"release-metadata/1","artifact_sha256":"deadbeef"}`,
		"credential key":   `{"schema":"release-metadata/1","go_version":"go1.25.0","password":"hunter2"}`,
		"trailing content": `{"schema":"release-metadata/1","go_version":"go1.25.0"} {}`,
	} {
		t.Run("reject "+name, func(t *testing.T) {
			sum := LoadReleaseMetadata(write("bad-"+strings.ReplaceAll(name, " ", "_")+".json", body))
			if sum == nil || sum.Status != domain.ReleaseStatusNotRun ||
				sum.ReasonCode != domain.ReleaseReasonMetadataInvalid {
				t.Fatalf("%s: summary %+v", name, sum)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		sum := LoadReleaseMetadata(filepath.Join(dir, "nope.json"))
		if sum.Status != domain.ReleaseStatusNotRun ||
			sum.ReasonCode != domain.ReleaseReasonMetadataInvalid {
			t.Fatalf("summary %+v", sum)
		}
	})
	t.Run("directory", func(t *testing.T) {
		sum := LoadReleaseMetadata(dir)
		if sum.Status != domain.ReleaseStatusNotRun {
			t.Fatalf("summary %+v", sum)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		p := filepath.Join(dir, "big.json")
		if err := os.WriteFile(p, make([]byte, maxReleaseMetadataBytes+1), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := LoadReleaseMetadata(p)
		if sum.Status != domain.ReleaseStatusNotRun {
			t.Fatalf("summary %+v", sum)
		}
	})
}
