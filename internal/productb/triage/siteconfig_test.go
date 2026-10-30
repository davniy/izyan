package triage

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const siteConfigYAML = `schema_version: triage-site.v1
sources:
  repositories:
    - id: example-service
      kind: git
      locator: https://example.org/repos/example-service.git
      credential_ref: secret://scm/example-service
      release_policy: published-release
      ecosystem: go
      aliases:
        - svc-example
    - id: local-example-service
      kind: local
      root: ${TRIAGE_WORKSPACE}/example-service
      release_policy: declared-ref
  artifacts:
    - id: local-sbom
      kind: filesystem
      root: ${TRIAGE_WORKSPACE}/artifacts
      patterns:
        - "**/*.spdx.json"
        - "**/*.cdx.json"
    - id: package-cache
      kind: nexus
      locator: https://packages.example.org/repository/releases
      credential_ref: secret://packages/read
      patterns:
        - "com/example/**/*.jar"
    - id: public-artifacts
      kind: http
      locator: https://artifacts.example.org/releases
      patterns:
        - "example-service-*.tar.gz"
    - id: image-registry
      kind: oci
      locator: registry.example.org/repos
      credential_ref: secret://registry/read
      patterns:
        - "example-service@sha256:*"
  advisory:
    priority:
      - ticket
      - frozen_osv
      - osv_api
    freeze: true
    allowed_domains:
      - advisories.example.org
      - api.osv.dev
resolution:
  release_policies:
    published-release:
      allowed_ref_kinds:
        - tag
        - release
      require_resolved_commit: true
    declared-ref:
      allowed_ref_kinds:
        - commit
        - tag
      require_resolved_commit: true
  max_candidates: 16
  max_feedback_passes: 2
snapshot:
  root: ${TRIAGE_WORKSPACE}/triage-snapshots
  immutable: true
  hash_algorithm: sha256
  require_contained_paths: true
toolchain:
  rules:
    - ecosystem: go
      require_release_toolchain_for_stdlib: true
      allow_local_toolchain_fallback: false
deployment:
  paths:
    - ${TRIAGE_WORKSPACE}/deploy
    - ${TRIAGE_WORKSPACE}/manifests
  allow_external_sources: false
policy:
  profiles:
    - public-hostile
    - internal-service
  fail_on:
    - unchanged
  on_drift: error
  stability_retries: 2
budgets:
  max_llm_steps: 32
  max_tool_calls: 128
  max_source_bytes: 1048576
  max_advisory_bytes: 524288
  timeout_seconds: 900
  max_output_tokens: 24000
`

// The JSON twin of siteConfigYAML: same field values, different encoding.
// LoadSiteConfig must derive the same pre-expansion hash from both.
const siteConfigJSON = `{
  "schema_version": "triage-site.v1",
  "sources": {
    "repositories": [
      {"id": "example-service", "kind": "git", "locator": "https://example.org/repos/example-service.git", "credential_ref": "secret://scm/example-service", "release_policy": "published-release", "ecosystem": "go", "aliases": ["svc-example"]},
      {"id": "local-example-service", "kind": "local", "root": "${TRIAGE_WORKSPACE}/example-service", "release_policy": "declared-ref"}
    ],
    "artifacts": [
      {"id": "local-sbom", "kind": "filesystem", "root": "${TRIAGE_WORKSPACE}/artifacts", "patterns": ["**/*.spdx.json", "**/*.cdx.json"]},
      {"id": "package-cache", "kind": "nexus", "locator": "https://packages.example.org/repository/releases", "credential_ref": "secret://packages/read", "patterns": ["com/example/**/*.jar"]},
      {"id": "public-artifacts", "kind": "http", "locator": "https://artifacts.example.org/releases", "patterns": ["example-service-*.tar.gz"]},
      {"id": "image-registry", "kind": "oci", "locator": "registry.example.org/repos", "credential_ref": "secret://registry/read", "patterns": ["example-service@sha256:*"]}
    ],
    "advisory": {"priority": ["ticket", "frozen_osv", "osv_api"], "freeze": true, "allowed_domains": ["advisories.example.org", "api.osv.dev"]}
  },
  "resolution": {
    "release_policies": {
      "published-release": {"allowed_ref_kinds": ["tag", "release"], "require_resolved_commit": true},
      "declared-ref": {"allowed_ref_kinds": ["commit", "tag"], "require_resolved_commit": true}
    },
    "max_candidates": 16,
    "max_feedback_passes": 2
  },
  "snapshot": {"root": "${TRIAGE_WORKSPACE}/triage-snapshots", "immutable": true, "hash_algorithm": "sha256", "require_contained_paths": true},
  "toolchain": {"rules": [{"ecosystem": "go", "require_release_toolchain_for_stdlib": true, "allow_local_toolchain_fallback": false}]},
  "deployment": {"paths": ["${TRIAGE_WORKSPACE}/deploy", "${TRIAGE_WORKSPACE}/manifests"], "allow_external_sources": false},
  "policy": {"profiles": ["public-hostile", "internal-service"], "fail_on": ["unchanged"], "on_drift": "error", "stability_retries": 2},
  "budgets": {"max_llm_steps": 32, "max_tool_calls": 128, "max_source_bytes": 1048576, "max_advisory_bytes": 524288, "timeout_seconds": 900, "max_output_tokens": 24000}
}`

func writeSiteConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "triage-site.cfg")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSiteConfigLoadYAML(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("TRIAGE_WORKSPACE", ws)
	cfg, hash, err := LoadSiteConfig(writeSiteConfig(t, siteConfigYAML))
	if err != nil {
		t.Fatalf("LoadSiteConfig: %v", err)
	}
	if cfg.SchemaVersion != SiteConfigSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", cfg.SchemaVersion, SiteConfigSchemaVersion)
	}
	if hash == "" || len(hash) != 64 {
		t.Fatalf("config hash = %q, want lowercase sha256 hex", hash)
	}
	if cfg.SourceHash == "" || cfg.ResolvedHash == "" || cfg.ResolvedHash != hash {
		t.Fatalf("hashes not recorded: source=%q resolved=%q returned=%q", cfg.SourceHash, cfg.ResolvedHash, hash)
	}

	repos := cfg.Sources.Repositories
	if len(repos) != 2 {
		t.Fatalf("repositories = %d, want 2", len(repos))
	}
	if repos[0].ID != "example-service" || repos[0].Kind != "git" ||
		repos[0].Locator != "https://example.org/repos/example-service.git" ||
		repos[0].CredentialRef != "secret://scm/example-service" ||
		repos[0].ReleasePolicy != "published-release" || repos[0].Ecosystem != "go" {
		t.Fatalf("repository[0] decoded wrong: %+v", repos[0])
	}
	if repos[1].Root != filepath.Join(ws, "example-service") {
		t.Fatalf("repository[1].root = %q, ${TRIAGE_WORKSPACE} not expanded", repos[1].Root)
	}

	arts := cfg.Sources.Artifacts
	if len(arts) != 4 {
		t.Fatalf("artifacts = %d, want 4", len(arts))
	}
	for i, want := range []string{"filesystem", "nexus", "http", "oci"} {
		if arts[i].Kind != want {
			t.Fatalf("artifact[%d].kind = %q, want %q", i, arts[i].Kind, want)
		}
		if len(arts[i].Patterns) == 0 {
			t.Fatalf("artifact[%d] (%s) has no patterns", i, want)
		}
	}
	if arts[0].Root != filepath.Join(ws, "artifacts") {
		t.Fatalf("artifact root = %q, ${TRIAGE_WORKSPACE} not expanded", arts[0].Root)
	}

	adv := cfg.Sources.Advisory
	if !reflect.DeepEqual(adv.Priority, []string{"ticket", "frozen_osv", "osv_api"}) || !adv.Freeze {
		t.Fatalf("advisory decoded wrong: %+v", adv)
	}
	if cfg.Resolution.MaxCandidates != 16 || len(cfg.Resolution.ReleasePolicies) != 2 ||
		!cfg.Resolution.ReleasePolicies["published-release"].RequireResolvedCommit {
		t.Fatalf("resolution decoded wrong: %+v", cfg.Resolution)
	}
	if cfg.Snapshot.Root != filepath.Join(ws, "triage-snapshots") || cfg.Snapshot.HashAlgorithm != "sha256" {
		t.Fatalf("snapshot decoded wrong: %+v", cfg.Snapshot)
	}
	if cfg.Policy.OnDrift != "error" || cfg.Policy.StabilityRetries != 2 ||
		!reflect.DeepEqual(cfg.Policy.FailOn, []string{"unchanged"}) {
		t.Fatalf("policy decoded wrong: %+v", cfg.Policy)
	}
	if cfg.Budgets.MaxLLMSteps != 32 || cfg.Budgets.MaxToolCalls != 128 ||
		cfg.Budgets.MaxSourceBytes != 1048576 || cfg.Budgets.TimeoutSeconds != 900 ||
		cfg.Budgets.MaxOutputTokens != 24000 {
		t.Fatalf("budgets decoded wrong: %+v", cfg.Budgets)
	}

	cat := cfg.Catalog()
	if len(cat.Entries) != 6 {
		t.Fatalf("catalog entries = %d, want 6 (2 repositories + 4 artifacts)", len(cat.Entries))
	}
	if e, ok := cat.Lookup("image-registry"); !ok || e.Kind != "oci" || e.CredentialRef != "secret://registry/read" {
		t.Fatalf("catalog lookup of artifact id failed: %+v", e)
	}
}

func TestSiteConfigLoadJSONMatchesYAML(t *testing.T) {
	t.Setenv("TRIAGE_WORKSPACE", t.TempDir())
	yamlPath := writeSiteConfig(t, siteConfigYAML)
	jsonPath := writeSiteConfig(t, siteConfigJSON)

	yamlCfg, yamlHash, err := LoadSiteConfig(yamlPath)
	if err != nil {
		t.Fatalf("YAML load: %v", err)
	}
	jsonCfg, jsonHash, err := LoadSiteConfig(jsonPath)
	if err != nil {
		t.Fatalf("JSON load: %v", err)
	}
	if yamlHash != jsonHash {
		t.Fatalf("config hash differs between YAML (%s) and JSON (%s) twins", yamlHash, jsonHash)
	}
	if !reflect.DeepEqual(yamlCfg, jsonCfg) {
		t.Fatalf("YAML and JSON configs differ:\nYAML: %+v\nJSON: %+v", yamlCfg, jsonCfg)
	}
}

func TestSiteConfigRejectsUnknownField(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"yaml top-level", "schema_version: triage-site.v1\nbogus_key: 1\n"},
		{"yaml nested", "schema_version: triage-site.v1\nsnapshot:\n  root: /tmp/snap\n  bogus_key: true\n"},
		{"yaml entry", "schema_version: triage-site.v1\nsources:\n  repositories:\n    - id: x\n      kind: local\n      root: /tmp/x\n      password: hunter2\n"},
		{"json top-level", `{"schema_version":"triage-site.v1","bogus_key":1}`},
		{"json entry", `{"schema_version":"triage-site.v1","sources":{"repositories":[{"id":"x","kind":"local","root":"/tmp/x","token":"abc"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := LoadSiteConfig(writeSiteConfig(t, tc.body)); err == nil {
				t.Fatal("expected unknown-field rejection")
			}
		})
	}
}

func TestSiteConfigRejectsBadSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"missing", "sources: {}\n"},
		{"wrong", "schema_version: triage-site.v2\n"},
		{"foreign", `{"schema_version":"finding.v1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := LoadSiteConfig(writeSiteConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), SiteConfigSchemaVersion) {
				t.Fatalf("error = %v, want schema version error naming %q", err, SiteConfigSchemaVersion)
			}
		})
	}
}

func TestSiteConfigRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"yaml", "schema_version: triage-site.v1\nsources:\n\t- broken tab\n", "line"},
		{"yaml bad mapping", "schema_version: triage-site.v1\nsources\n  repositories: [unclosed\n", "line"},
		{"json", `{"schema_version": "triage-site.v1", }`, "offset"},
		{"json truncated", `{"schema_version": "triage-site.v1"`, "offset"},
		{"garbage", "\x00\x01 not a document at all {{{", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := LoadSiteConfig(writeSiteConfig(t, tc.body))
			if err == nil {
				t.Fatal("expected parse error")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks position marker %q", err, tc.want)
			}
		})
	}
}

func TestSiteConfigEnvExpansion(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("TRIAGE_WORKSPACE", ws)
	path := writeSiteConfig(t, "schema_version: triage-site.v1\nsnapshot:\n  root: ${TRIAGE_WORKSPACE}/snap\n")

	cfg, hash, err := LoadSiteConfig(path)
	if err != nil {
		t.Fatalf("LoadSiteConfig: %v", err)
	}
	if cfg.Snapshot.Root != filepath.Join(ws, "snap") {
		t.Fatalf("snapshot.root = %q", cfg.Snapshot.Root)
	}
	if hash == "" || cfg.SourceHash == hash {
		t.Fatalf("resolved hash must differ from pre-expansion source hash: %q vs %q", cfg.SourceHash, hash)
	}

	// Same file, different environment: the source hash is preserved while
	// the resolved hash follows the expansion — provenance drift sees the
	// effective configuration, not just the file.
	t.Setenv("TRIAGE_WORKSPACE", t.TempDir())
	cfg2, hash2, err := LoadSiteConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg2.SourceHash != cfg.SourceHash {
		t.Fatal("pre-expansion hash changed with the environment")
	}
	if hash2 == hash {
		t.Fatal("resolved config hash ignored the expansion")
	}
}

func TestSiteConfigUnsetEnv(t *testing.T) {
	path := writeSiteConfig(t, "schema_version: triage-site.v1\nsnapshot:\n  root: ${TRIAGE_UNSET_NEVER_DEFINED}/snap\n")
	_, _, err := LoadSiteConfig(path)
	if err == nil || !strings.Contains(err.Error(), "TRIAGE_UNSET_NEVER_DEFINED") {
		t.Fatalf("error = %v, want unset-variable error naming the variable", err)
	}
}

// TestSiteConfigCredentialRefNeverExpanded: credential_ref is a reference,
// never a value — the loader must not expand ${...} inside it, must not read
// the referenced secret, and must keep it verbatim in the structure.
func TestSiteConfigCredentialRefNeverExpanded(t *testing.T) {
	t.Setenv("TRIAGE_SECRET_VALUE", "s3cr3t-token")
	body := `schema_version: triage-site.v1
sources:
  repositories:
    - id: repo
      kind: git
      locator: https://example.org/repo.git
      credential_ref: secret://scm/${TRIAGE_SECRET_VALUE}
`
	cfg, _, err := LoadSiteConfig(writeSiteConfig(t, body))
	if err != nil {
		t.Fatalf("LoadSiteConfig: %v", err)
	}
	got := cfg.Sources.Repositories[0].CredentialRef
	if strings.Contains(got, "s3cr3t-token") {
		t.Fatalf("credential_ref expanded the secret-bearing variable: %q", got)
	}
	if got != "secret://scm/${TRIAGE_SECRET_VALUE}" {
		t.Fatalf("credential_ref rewritten to %q", got)
	}
	// An inline credential that is not a secret:// reference is rejected.
	bad := writeSiteConfig(t, `schema_version: triage-site.v1
sources:
  repositories:
    - id: repo
      kind: git
      locator: https://example.org/repo.git
      credential_ref: "s3cr3t-token"
`)
	if _, _, err := LoadSiteConfig(bad); err == nil {
		t.Fatal("inline credential value accepted as credential_ref")
	}
}

func TestSiteConfigRejectsInvalidEntries(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo string
	}{
		{"duplicate id", "    - id: dup\n      kind: git\n      locator: https://example.org/a.git\n    - id: dup\n      kind: git\n      locator: https://example.org/b.git\n"},
		{"normalized duplicate id", "    - id: Example Service\n      kind: git\n      locator: https://example.org/a.git\n    - id: example-service\n      kind: git\n      locator: https://example.org/b.git\n"},
		{"bad kind", "    - id: x\n      kind: svn\n      locator: https://example.org/x.git\n"},
		{"missing locator", "    - id: x\n      kind: git\n"},
		{"missing root", "    - id: x\n      kind: local\n"},
		{"relative root", "    - id: x\n      kind: local\n      root: relative/path\n"},
		{"locator with userinfo", "    - id: x\n      kind: git\n      locator: https://user:pw@example.org/x.git\n"},
		{"locator without scheme", "    - id: x\n      kind: git\n      locator: example.org/x.git\n"},
		{"empty id", "    - kind: git\n      locator: https://example.org/x.git\n"},
		{"ambiguous alias pair", "    - id: one\n      kind: git\n      locator: https://example.org/one.git\n      aliases: [shared]\n    - id: two\n      kind: git\n      locator: https://example.org/two.git\n      aliases: [SHARED]\n"},
		{"alias equals other id", "    - id: one\n      kind: git\n      locator: https://example.org/one.git\n      aliases: [two]\n    - id: two\n      kind: git\n      locator: https://example.org/two.git\n"},
		{"unknown release policy", "    - id: x\n      kind: git\n      locator: https://example.org/x.git\n      release_policy: no-such-policy\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSiteConfig(t, "schema_version: triage-site.v1\nsources:\n  repositories:\n"+tc.repo)
			if _, _, err := LoadSiteConfig(path); err == nil {
				t.Fatal("expected entry rejection")
			}
		})
	}

	// Repository/artifact id collision across the two lists.
	cross := `schema_version: triage-site.v1
sources:
  repositories:
    - id: shared
      kind: git
      locator: https://example.org/a.git
  artifacts:
    - id: shared
      kind: http
      locator: https://example.org/releases
      patterns: ["*.tar.gz"]
`
	if _, _, err := LoadSiteConfig(writeSiteConfig(t, cross)); err == nil {
		t.Fatal("cross-list duplicate id accepted")
	}

	for _, tc := range []struct {
		name string
		art  string
	}{
		{"artifact bad kind", "    - id: a\n      kind: git\n      locator: https://example.org/a.git\n      patterns: [\"x\"]\n"},
		{"artifact missing locator", "    - id: a\n      kind: http\n      patterns: [\"x\"]\n"},
		{"artifact missing patterns", "    - id: a\n      kind: http\n      locator: https://example.org/releases\n"},
		{"artifact filesystem root", "    - id: a\n      kind: filesystem\n      locator: https://example.org/releases\n      patterns: [\"x\"]\n"},
		{"artifact empty pattern", "    - id: a\n      kind: filesystem\n      root: /tmp/a\n      patterns: [\"\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSiteConfig(t, "schema_version: triage-site.v1\nsources:\n  artifacts:\n"+tc.art)
			if _, _, err := LoadSiteConfig(path); err == nil {
				t.Fatal("expected artifact rejection")
			}
		})
	}
}

func TestSiteConfigRejectsInvalidConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"bad on_drift", "schema_version: triage-site.v1\npolicy:\n  on_drift: warn\n"},
		{"bad fail_on", "schema_version: triage-site.v1\npolicy:\n  fail_on: [explode]\n"},
		{"bad advisory priority", "schema_version: triage-site.v1\nsources:\n  advisory:\n    priority: [magic]\n"},
		{"negative max_llm_steps", "schema_version: triage-site.v1\nbudgets:\n  max_llm_steps: -1\n"},
		{"negative tool calls", "schema_version: triage-site.v1\nbudgets:\n  max_tool_calls: -4\n"},
		{"negative source bytes", "schema_version: triage-site.v1\nbudgets:\n  max_source_bytes: -1\n"},
		{"negative timeout", "schema_version: triage-site.v1\nbudgets:\n  timeout_seconds: -30\n"},
		{"negative output tokens", "schema_version: triage-site.v1\nbudgets:\n  max_output_tokens: -1\n"},
		{"negative retries", "schema_version: triage-site.v1\npolicy:\n  stability_retries: -1\n"},
		{"negative candidates", "schema_version: triage-site.v1\nresolution:\n  max_candidates: -2\n"},
		{"bad hash algorithm", "schema_version: triage-site.v1\nsnapshot:\n  root: /tmp/s\n  hash_algorithm: md5\n"},
		{"bad ref kind", "schema_version: triage-site.v1\nresolution:\n  release_policies:\n    p:\n      allowed_ref_kinds: [wildcard]\n"},
		{"relative snapshot root", "schema_version: triage-site.v1\nsnapshot:\n  root: relative/snap\n"},
		{"empty toolchain ecosystem", "schema_version: triage-site.v1\ntoolchain:\n  rules:\n    - require_release_toolchain_for_stdlib: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := LoadSiteConfig(writeSiteConfig(t, tc.body)); err == nil {
				t.Fatal("expected config rejection")
			}
		})
	}
}

func TestSiteConfigMissingFile(t *testing.T) {
	if _, _, err := LoadSiteConfig(filepath.Join(t.TempDir(), "no-such.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestSiteConfigSecretsNeverLeak: a credential smuggled into a locator —
// even via env expansion — is rejected, and the error must not echo the
// expanded secret material back.
func TestSiteConfigSecretsNeverLeak(t *testing.T) {
	secret := "s3cr3t-token-value"
	t.Setenv("TRIAGE_SECRET_VALUE", secret)
	path := writeSiteConfig(t, `schema_version: triage-site.v1
sources:
  repositories:
    - id: repo
      kind: git
      locator: https://${TRIAGE_SECRET_VALUE}@example.org/repo.git
`)
	_, _, err := LoadSiteConfig(path)
	if err == nil {
		t.Fatal("locator with embedded credentials accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error echoed the secret: %v", err)
	}
}

// TestSiteConfigBaseline covers the optional `baseline` block: a valid
// default severity loads, the raw value round-trips for the composer, an
// unknown value fails schema validation before any LLM traffic, and the
// strict decoder still rejects unknown keys inside the new section.
func TestSiteConfigBaseline(t *testing.T) {
	t.Run("accepted severities load", func(t *testing.T) {
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "medium"} {
			body := "schema_version: triage-site.v1\nbaseline:\n  default_severity: " + sev + "\n"
			cfg, _, err := LoadSiteConfig(writeSiteConfig(t, body))
			if err != nil {
				t.Fatalf("default_severity %s must load: %v", sev, err)
			}
			if cfg.Baseline.DefaultSeverity != sev {
				t.Fatalf("default_severity = %q, want %q", cfg.Baseline.DefaultSeverity, sev)
			}
		}
	})
	t.Run("absent section stays unset", func(t *testing.T) {
		cfg, _, err := LoadSiteConfig(writeSiteConfig(t, "schema_version: triage-site.v1\n"))
		if err != nil {
			t.Fatalf("minimal config must load: %v", err)
		}
		if cfg.Baseline.DefaultSeverity != "" {
			t.Fatalf("no baseline section must leave default severity empty, got %q", cfg.Baseline.DefaultSeverity)
		}
	})
	t.Run("unknown severity rejected", func(t *testing.T) {
		for _, sev := range []string{"SEVERE", "blocker", "p0", "unknown2"} {
			body := "schema_version: triage-site.v1\nbaseline:\n  default_severity: " + sev + "\n"
			if _, _, err := LoadSiteConfig(writeSiteConfig(t, body)); err == nil {
				t.Fatalf("default_severity %s must fail schema validation", sev)
			}
		}
	})
	t.Run("unknown field inside baseline rejected", func(t *testing.T) {
		body := "schema_version: triage-site.v1\nbaseline:\n  bogus_key: true\n"
		if _, _, err := LoadSiteConfig(writeSiteConfig(t, body)); err == nil {
			t.Fatal("unknown baseline key must be rejected")
		}
	})
}

func TestSiteConfigFrozenDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRIAGE_FROZEN_DIR", dir)
	cfg, _, err := LoadSiteConfig(writeSiteConfig(t, "schema_version: triage-site.v1\nsources:\n  advisory:\n    freeze: true\n    frozen_dir: ${TRIAGE_FROZEN_DIR}\n"))
	if err != nil {
		t.Fatalf("LoadSiteConfig: %v", err)
	}
	if cfg.Sources.Advisory.FrozenDir != dir {
		t.Fatalf("frozen_dir = %q, want %q", cfg.Sources.Advisory.FrozenDir, dir)
	}

	missing := filepath.Join(t.TempDir(), "missing-frozen")
	if _, _, err := LoadSiteConfig(writeSiteConfig(t, "schema_version: triage-site.v1\nsources:\n  advisory:\n    frozen_dir: "+missing+"\n")); err == nil {
		t.Fatal("non-existent frozen_dir accepted")
	}
	file := filepath.Join(t.TempDir(), "frozen.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg, _, err := LoadSiteConfig(writeSiteConfig(t, "schema_version: triage-site.v1\nsources:\n  advisory:\n    frozen_dir: "+file+"\n")); err != nil || cfg.Sources.Advisory.FrozenDir != file {
		t.Fatalf("regular frozen store file should load: cfg=%+v err=%v", cfg.Sources.Advisory, err)
	}
}

func TestSiteConfigFrozenDirOptional(t *testing.T) {
	cfg, _, err := LoadSiteConfig(writeSiteConfig(t, "schema_version: triage-site.v1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources.Advisory.FrozenDir != "" {
		t.Fatalf("absent frozen_dir = %q, want empty", cfg.Sources.Advisory.FrozenDir)
	}
}
