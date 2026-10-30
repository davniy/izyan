package triage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SiteConfigSchemaVersion identifies the site configuration document this
// loader accepts. Any other schema_version — or its absence — is a config
// error, never silently assumed.
const SiteConfigSchemaVersion = "triage-site.v1"

// SiteConfig is the decoded triage-site.v1 document: the bounded set of
// admitted sources plus the policy, snapshot, toolchain, deployment and
// budget configuration that governs a triage run. It is the strict schema —
// the loader rejects unknown fields in every block.
type SiteConfig struct {
	SchemaVersion string           `json:"schema_version" yaml:"schema_version"`
	Sources       SiteSources      `json:"sources" yaml:"sources"`
	Resolution    ResolutionConfig `json:"resolution" yaml:"resolution"`
	Snapshot      SnapshotConfig   `json:"snapshot" yaml:"snapshot"`
	Toolchain     ToolchainConfig  `json:"toolchain" yaml:"toolchain"`
	Deployment    DeploymentConfig `json:"deployment" yaml:"deployment"`
	Policy        PolicyConfig     `json:"policy" yaml:"policy"`
	Baseline      BaselineConfig   `json:"baseline" yaml:"baseline"`
	Budgets       BudgetConfig     `json:"budgets" yaml:"budgets"`

	// SourceHash is sha256 of the canonical document before environment
	// expansion: the identity of the config file itself, identical for the
	// YAML and JSON twin of the same configuration.
	SourceHash string `json:"-" yaml:"-"`
	// ResolvedHash is sha256 of the canonical document after environment
	// expansion: the identity of the configuration that actually governed
	// the run. Provenance and drift checks bind to this value. It is
	// computed over references only — credential contents are never read
	// or hashed.
	ResolvedHash string `json:"-" yaml:"-"`
}

// SiteSources is the `sources` block: admitted repositories, admitted
// artifact sources and the advisory source policy.
type SiteSources struct {
	Repositories []CatalogEntry   `json:"repositories,omitempty" yaml:"repositories,omitempty"`
	Artifacts    []ArtifactSource `json:"artifacts,omitempty" yaml:"artifacts,omitempty"`
	Advisory     AdvisoryConfig   `json:"advisory" yaml:"advisory"`
}

// ArtifactSource is an admitted material source: a catalog entry plus the
// glob patterns that bound which artifacts may be fetched from it.
type ArtifactSource struct {
	CatalogEntry `yaml:",inline"`
	Patterns     []string `json:"patterns" yaml:"patterns"`
}

// AdvisoryConfig is the `sources.advisory` block: deterministic source
// priority, freeze requirement and the bounded set of remote domains an
// advisory fetch may touch.
type AdvisoryConfig struct {
	FrozenDir      string   `json:"frozen_dir,omitempty" yaml:"frozen_dir,omitempty"`
	Priority       []string `json:"priority,omitempty" yaml:"priority,omitempty"`
	Freeze         bool     `json:"freeze" yaml:"freeze"`
	AllowedDomains []string `json:"allowed_domains,omitempty" yaml:"allowed_domains,omitempty"`
}

// ResolutionConfig is the `resolution` block: named release policies plus
// enumeration bounds for ref candidates and LLM feedback passes.
type ResolutionConfig struct {
	ReleasePolicies   map[string]ReleasePolicy `json:"release_policies,omitempty" yaml:"release_policies,omitempty"`
	MaxCandidates     int                      `json:"max_candidates" yaml:"max_candidates"`
	MaxFeedbackPasses int                      `json:"max_feedback_passes" yaml:"max_feedback_passes"`
}

// ReleasePolicy bounds which ref kinds an entry may resolve to and whether
// the selected ref must resolve to a concrete commit.
type ReleasePolicy struct {
	AllowedRefKinds       []string `json:"allowed_ref_kinds" yaml:"allowed_ref_kinds"`
	RequireResolvedCommit bool     `json:"require_resolved_commit" yaml:"require_resolved_commit"`
}

// SnapshotConfig is the `snapshot` block.
type SnapshotConfig struct {
	Root                  string `json:"root" yaml:"root"`
	Immutable             bool   `json:"immutable" yaml:"immutable"`
	HashAlgorithm         string `json:"hash_algorithm" yaml:"hash_algorithm"`
	RequireContainedPaths bool   `json:"require_contained_paths" yaml:"require_contained_paths"`
}

// ToolchainConfig is the `toolchain` block.
type ToolchainConfig struct {
	Rules []ToolchainRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// ToolchainRule binds toolchain requirements to one ecosystem.
type ToolchainRule struct {
	Ecosystem                        string `json:"ecosystem" yaml:"ecosystem"`
	RequireReleaseToolchainForStdlib bool   `json:"require_release_toolchain_for_stdlib" yaml:"require_release_toolchain_for_stdlib"`
	AllowLocalToolchainFallback      bool   `json:"allow_local_toolchain_fallback" yaml:"allow_local_toolchain_fallback"`
}

// DeploymentConfig is the `deployment` block: the bounded local directories
// deployment artifacts may be read from.
type DeploymentConfig struct {
	Paths                []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	AllowExternalSources bool     `json:"allow_external_sources" yaml:"allow_external_sources"`
}

// PolicyConfig is the `policy` block: allowed recommendation profiles, the
// CI fail_on thresholds and the drift/stability contract.
type PolicyConfig struct {
	Profiles         []string `json:"profiles,omitempty" yaml:"profiles,omitempty"`
	FailOn           []string `json:"fail_on,omitempty" yaml:"fail_on,omitempty"`
	OnDrift          string   `json:"on_drift" yaml:"on_drift"`
	StabilityRetries int      `json:"stability_retries" yaml:"stability_retries"`
}

// BaselineConfig is the `baseline` block: the configured severity the
// composer may fall back to when neither the advisory nor the intake
// carries one. An absent block keeps the fail-closed default — no
// configured severity means an unresolvable baseline stays a technical
// error. UNKNOWN is an admitted value: it produces a nominal P2 package.
type BaselineConfig struct {
	DefaultSeverity string `json:"default_severity,omitempty" yaml:"default_severity,omitempty"`
}

// baselineSeverities lists the values baseline.default_severity may take.
var baselineSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "UNKNOWN": true,
}

// BudgetConfig is the `budgets` block. Zero means unset — the caller's own
// defaults apply.
type BudgetConfig struct {
	MaxLLMSteps      int   `json:"max_llm_steps" yaml:"max_llm_steps"`
	MaxToolCalls     int   `json:"max_tool_calls" yaml:"max_tool_calls"`
	MaxSourceBytes   int64 `json:"max_source_bytes" yaml:"max_source_bytes"`
	MaxAdvisoryBytes int64 `json:"max_advisory_bytes" yaml:"max_advisory_bytes"`
	TimeoutSeconds   int   `json:"timeout_seconds" yaml:"timeout_seconds"`
	// MaxOutputTokens bounds the LLM response size for the triage agent.
	// Zero falls back to the CLI default; an explicit LLM_MAX_TOKENS
	// environment override wins over the config value.
	MaxOutputTokens int `json:"max_output_tokens" yaml:"max_output_tokens"`
}

// Catalog builds the bounded source catalog admitted by this config:
// repositories first, then artifact sources, in configuration order. The
// catalog is the only surface intake validation and Stage 0 resolution may
// pick sources from — an id outside it does not exist.
func (c SiteConfig) Catalog() Catalog {
	out := Catalog{Entries: make([]CatalogEntry, 0, len(c.Sources.Repositories)+len(c.Sources.Artifacts))}
	out.Entries = append(out.Entries, c.Sources.Repositories...)
	for _, a := range c.Sources.Artifacts {
		out.Entries = append(out.Entries, a.CatalogEntry)
	}
	return out
}

// LoadSiteConfig reads, strictly decodes, environment-expands and validates a
// triage-site.v1 document. Files starting with '{' are parsed as strict JSON
// (unknown fields rejected, errors carry the byte offset); everything else is
// parsed as strict YAML (unknown fields rejected, errors carry line numbers).
// The returned hash is the resolved config hash — the sha256 of the canonical
// post-expansion document, computed over references only; credentials are
// never read, expanded, hashed or leaked into errors.
func LoadSiteConfig(path string) (SiteConfig, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SiteConfig{}, "", fmt.Errorf("site config %s: %w", path, err)
	}
	cfg, err := decodeSiteConfig(data)
	if err != nil {
		return SiteConfig{}, "", fmt.Errorf("site config %s: %w", path, err)
	}
	if cfg.SchemaVersion != SiteConfigSchemaVersion {
		return SiteConfig{}, "", fmt.Errorf("site config %s: schema_version = %q, want %q", path, cfg.SchemaVersion, SiteConfigSchemaVersion)
	}
	cfg.SourceHash = siteConfigHash(cfg)
	if err := expandSiteConfig(&cfg); err != nil {
		return SiteConfig{}, "", fmt.Errorf("site config %s: %w", path, err)
	}
	cfg.ResolvedHash = siteConfigHash(cfg)
	if err := ValidateSiteConfig(cfg); err != nil {
		return SiteConfig{}, "", fmt.Errorf("site config %s: %w", path, err)
	}
	return cfg, cfg.ResolvedHash, nil
}

// decodeSiteConfig strictly decodes the document. Format is chosen on the
// first non-space byte: '{' means JSON, anything else means YAML. A document
// may not carry a second JSON value or a second YAML document.
func decodeSiteConfig(data []byte) (SiteConfig, error) {
	var cfg SiteConfig
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return SiteConfig{}, fmt.Errorf("decode JSON: %w", siteJSONErr(err, len(data)))
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			if err == nil {
				return SiteConfig{}, fmt.Errorf("decode JSON: trailing data at offset %d", dec.InputOffset())
			}
			return SiteConfig{}, fmt.Errorf("decode JSON: %w", siteJSONErr(err, len(data)))
		}
		return cfg, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return SiteConfig{}, fmt.Errorf("decode YAML: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return SiteConfig{}, fmt.Errorf("decode YAML: unexpected second document")
		}
		return SiteConfig{}, fmt.Errorf("decode YAML: %w", err)
	}
	return cfg, nil
}

// siteJSONErr reports the byte offset of JSON syntax errors and truncations
// so a broken file is located without dumping its content.
func siteJSONErr(err error, size int) error {
	var syn *json.SyntaxError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("%s at offset %d", syn.Error(), syn.Offset)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("unexpected end of JSON input at offset %d", size)
	default:
		return err
	}
}

// siteConfigHash is the deterministic identity of a decoded config: sha256
// over its canonical JSON encoding (sorted map keys, fixed field order),
// independent of whether the source document was YAML or JSON.
func siteConfigHash(cfg SiteConfig) string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	return hashBytes(data)
}

// reSiteEnvRef matches the explicitly supported ${NAME} expansion syntax.
// Bare $NAME is not expanded: the site config admits only the braced form,
// keeping expansion deterministic and grep-able.
var reSiteEnvRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandSiteConfig expands ${NAME} references in exactly the fields that may
// hold operator-supplied roots and locators. Credential references, ids,
// aliases, patterns and every policy token are never expanded — expansion
// must not become a channel for secret material or identity rewriting.
// An unset or empty variable is a config error naming the variable, never
// its would-be value.
func expandSiteConfig(cfg *SiteConfig) error {
	expand := func(field, s string) (string, error) {
		var unset string
		out := reSiteEnvRef.ReplaceAllStringFunc(s, func(m string) string {
			name := m[2 : len(m)-1]
			v, ok := os.LookupEnv(name)
			if !ok || v == "" {
				unset = name
				return m
			}
			return v
		})
		if unset != "" {
			return "", fmt.Errorf("%s: environment variable %s is not set", field, unset)
		}
		return out, nil
	}
	entry := func(which string, e *CatalogEntry) error {
		var err error
		if e.Root, err = expand(which+".root", e.Root); err != nil {
			return err
		}
		if e.Locator, err = expand(which+".locator", e.Locator); err != nil {
			return err
		}
		return nil
	}
	for i := range cfg.Sources.Repositories {
		e := &cfg.Sources.Repositories[i]
		if err := entry(fmt.Sprintf("sources.repositories[%d]", i), e); err != nil {
			return err
		}
	}
	for i := range cfg.Sources.Artifacts {
		e := &cfg.Sources.Artifacts[i].CatalogEntry
		if err := entry(fmt.Sprintf("sources.artifacts[%d]", i), e); err != nil {
			return err
		}
	}
	var err error
	if cfg.Sources.Advisory.FrozenDir, err = expand("sources.advisory.frozen_dir", cfg.Sources.Advisory.FrozenDir); err != nil {
		return err
	}
	if cfg.Snapshot.Root, err = expand("snapshot.root", cfg.Snapshot.Root); err != nil {
		return err
	}
	for i := range cfg.Deployment.Paths {
		if cfg.Deployment.Paths[i], err = expand(fmt.Sprintf("deployment.paths[%d]", i), cfg.Deployment.Paths[i]); err != nil {
			return err
		}
	}
	return nil
}

var (
	siteRepoKinds     = map[string]bool{"local": true, "git": true}
	siteArtifactKinds = map[string]bool{"filesystem": true, "nexus": true, "http": true, "oci": true}
	siteRefKinds      = map[string]bool{"commit": true, "tag": true, "branch": true, "release": true}
	siteAdvisoryKinds = map[string]bool{"ticket": true, "frozen_osv": true, "osv_api": true}
	siteFailOnKinds   = map[string]bool{"unchanged": true, "low-support": true, "conditional": true, "unverified-disposition": true}
	siteEcosystems    = map[string]bool{"go": true, "npm": true, "maven": true, "pypi": true, "cargo": true, "gem": true, "nuget": true, "deb": true, "rpm": true, "generic": true}
)

// ValidateSiteConfig is the deterministic gate over a decoded site config:
// entry shape (kind, locator/root, credential reference), identity
// uniqueness (ids, normalized ids, aliases), policy reference integrity and
// non-negative bounds. It validates the expanded form — call it after
// environment expansion, exactly as LoadSiteConfig does.
func ValidateSiteConfig(cfg SiteConfig) error {
	if cfg.SchemaVersion != SiteConfigSchemaVersion {
		return fmt.Errorf("schema_version = %q, want %q", cfg.SchemaVersion, SiteConfigSchemaVersion)
	}
	ids := map[string]string{}
	aliases := map[string]string{}
	check := func(which string, e CatalogEntry, kinds map[string]bool, wantRoot bool) error {
		return validateSiteEntry(which, e, kinds, wantRoot, cfg.Resolution.ReleasePolicies, ids, aliases)
	}
	for i, e := range cfg.Sources.Repositories {
		wantRoot := e.Kind == "local"
		if err := check(fmt.Sprintf("sources.repositories[%d]", i), e, siteRepoKinds, wantRoot); err != nil {
			return err
		}
	}
	for i, a := range cfg.Sources.Artifacts {
		which := fmt.Sprintf("sources.artifacts[%d]", i)
		wantRoot := a.Kind == "filesystem"
		if err := check(which, a.CatalogEntry, siteArtifactKinds, wantRoot); err != nil {
			return err
		}
		if len(a.Patterns) == 0 {
			return fmt.Errorf("%s.patterns: artifact source requires at least one pattern", which)
		}
		for j, p := range a.Patterns {
			pf := fmt.Sprintf("%s.patterns[%d]", which, j)
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("%s: empty pattern", pf)
			}
			if filepath.IsAbs(p) {
				return fmt.Errorf("%s: pattern must be relative", pf)
			}
			for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
				if seg == ".." {
					return fmt.Errorf("%s: pattern must not escape the source root", pf)
				}
			}
		}
	}
	if err := validateSiteAdvisory(cfg.Sources.Advisory); err != nil {
		return err
	}
	if err := validateSiteResolution(cfg.Resolution); err != nil {
		return err
	}
	if cfg.Sources.Advisory.FrozenDir != "" {
		info, err := os.Stat(cfg.Sources.Advisory.FrozenDir)
		if err != nil {
			return fmt.Errorf("sources.advisory.frozen_dir: %w", err)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("sources.advisory.frozen_dir: must be a file or directory, got %q", cfg.Sources.Advisory.FrozenDir)
		}
	}
	if cfg.Snapshot.HashAlgorithm != "" && cfg.Snapshot.HashAlgorithm != "sha256" {
		return fmt.Errorf("snapshot.hash_algorithm = %q, want sha256", cfg.Snapshot.HashAlgorithm)
	}
	if cfg.Snapshot.Root != "" && !filepath.IsAbs(cfg.Snapshot.Root) {
		return fmt.Errorf("snapshot.root: must be an absolute path, got %q", cfg.Snapshot.Root)
	}
	for i, r := range cfg.Toolchain.Rules {
		if strings.TrimSpace(r.Ecosystem) == "" {
			return fmt.Errorf("toolchain.rules[%d].ecosystem is required", i)
		}
	}
	for i, p := range cfg.Deployment.Paths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("deployment.paths[%d]: empty path", i)
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("deployment.paths[%d]: must be an absolute path", i)
		}
	}
	if s := cfg.Baseline.DefaultSeverity; s != "" && !baselineSeverities[strings.ToUpper(strings.TrimSpace(s))] {
		return fmt.Errorf("baseline.default_severity = %q, want CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN", s)
	}
	for i, p := range cfg.Policy.Profiles {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("policy.profiles[%d]: empty profile", i)
		}
	}
	for i, f := range cfg.Policy.FailOn {
		if !siteFailOnKinds[f] {
			return fmt.Errorf("policy.fail_on[%d] = %q, want unchanged|low-support|conditional|unverified-disposition", i, f)
		}
	}
	switch cfg.Policy.OnDrift {
	case "", "error":
	default:
		return fmt.Errorf("policy.on_drift = %q, want error", cfg.Policy.OnDrift)
	}
	if cfg.Policy.StabilityRetries < 0 {
		return fmt.Errorf("policy.stability_retries must be >= 0, got %d", cfg.Policy.StabilityRetries)
	}
	b := cfg.Budgets
	for _, nb := range []struct {
		field string
		value int64
	}{
		{"budgets.max_llm_steps", int64(b.MaxLLMSteps)},
		{"budgets.max_tool_calls", int64(b.MaxToolCalls)},
		{"budgets.max_source_bytes", b.MaxSourceBytes},
		{"budgets.max_advisory_bytes", b.MaxAdvisoryBytes},
		{"budgets.timeout_seconds", int64(b.TimeoutSeconds)},
		{"budgets.max_output_tokens", int64(b.MaxOutputTokens)},
	} {
		if nb.value < 0 {
			return fmt.Errorf("%s must be >= 0, got %d", nb.field, nb.value)
		}
	}
	return nil
}

// validateSiteEntry checks one catalog entry: known kind for its list,
// exactly the locator/root shape the kind needs, a credential reference that
// is a secret:// link rather than an inline value, a release policy that
// exists in resolution.release_policies, and no id/alias collisions that
// would make catalog matching ambiguous. ids and aliases accumulate the
// normalized identities across both source lists.
func validateSiteEntry(
	which string,
	e CatalogEntry,
	kinds map[string]bool,
	wantRoot bool,
	policies map[string]ReleasePolicy,
	ids, aliases map[string]string,
) error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("%s.id is required", which)
	}
	if !kinds[e.Kind] {
		return fmt.Errorf("%s.kind = %q is not an admitted source kind", which, e.Kind)
	}
	if wantRoot {
		if strings.TrimSpace(e.Root) == "" {
			return fmt.Errorf("%s.root is required for kind %q", which, e.Kind)
		}
		if !filepath.IsAbs(e.Root) {
			return fmt.Errorf("%s.root must be an absolute path, got %q", which, e.Root)
		}
		if e.Locator != "" {
			return fmt.Errorf("%s.locator must not be set for kind %q (root is the source)", which, e.Kind)
		}
	} else {
		if strings.TrimSpace(e.Locator) == "" {
			return fmt.Errorf("%s.locator is required for kind %q", which, e.Kind)
		}
		if e.Root != "" {
			return fmt.Errorf("%s.root must not be set for kind %q (locator is the source)", which, e.Root)
		}
		if err := validateSiteLocator(which, e.Kind, e.Locator); err != nil {
			return err
		}
	}
	if e.CredentialRef != "" {
		if !strings.HasPrefix(e.CredentialRef, "secret://") || strings.TrimPrefix(e.CredentialRef, "secret://") == "" {
			return fmt.Errorf("%s.credential_ref must be a secret:// reference, never an inline credential", which)
		}
	}
	if e.ReleasePolicy != "" {
		if _, ok := policies[e.ReleasePolicy]; !ok {
			return fmt.Errorf("%s.release_policy = %q is not defined in resolution.release_policies", which, e.ReleasePolicy)
		}
	}
	if e.Ecosystem != "" && !siteEcosystems[strings.ToLower(e.Ecosystem)] {
		return fmt.Errorf("%s.ecosystem = %q is not a known ecosystem", which, e.Ecosystem)
	}
	id := normalizeMatchID(e.ID)
	if prev, dup := ids[id]; dup {
		return fmt.Errorf("%s.id %q duplicates %s (normalized id %q)", which, e.ID, prev, id)
	}
	for _, a := range e.Aliases {
		na := normalizeMatchID(a)
		if na == "" {
			return fmt.Errorf("%s.aliases: empty alias", which)
		}
		if prev, dup := aliases[na]; dup {
			return fmt.Errorf("%s.aliases: alias %q duplicates an alias of %s — catalog match would be ambiguous", which, a, prev)
		}
		if prev, dup := ids[na]; dup {
			return fmt.Errorf("%s.aliases: alias %q collides with entry id of %s — catalog match would be ambiguous", which, a, prev)
		}
		aliases[na] = fmt.Sprintf("%s (id %q)", which, e.ID)
	}
	if prev, dup := aliases[id]; dup {
		return fmt.Errorf("%s.id %q collides with alias of %s — catalog match would be ambiguous", which, e.ID, prev)
	}
	ids[id] = fmt.Sprintf("%s (id %q)", which, e.ID)
	return nil
}

// validateSiteLocator checks a remote locator: an absolute URL for URL-ish
// kinds, a bare host/name reference for OCI. Userinfo is rejected everywhere:
// credentials belong in credential_ref, never in a locator — expanded or
// not — so no secret can be smuggled into provenance or errors.
func validateSiteLocator(which, kind, locator string) error {
	if kind == "oci" {
		if strings.ContainsAny(locator, " \t") {
			return fmt.Errorf("%s.locator %q is not a valid OCI reference", which, locator)
		}
		return nil
	}
	u, err := url.Parse(locator)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s.locator %q is not an absolute URL", which, locator)
	}
	if kind == "http" || kind == "nexus" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s.locator %q: kind %q requires an http(s) URL", which, locator, kind)
		}
	}
	if u.User != nil {
		return fmt.Errorf("%s.locator carries userinfo; credentials must go through credential_ref", which)
	}
	return nil
}

func validateSiteAdvisory(a AdvisoryConfig) error {
	seen := map[string]bool{}
	for i, p := range a.Priority {
		if !siteAdvisoryKinds[p] {
			return fmt.Errorf("sources.advisory.priority[%d] = %q, want ticket|frozen_osv|osv_api", i, p)
		}
		if seen[p] {
			return fmt.Errorf("sources.advisory.priority[%d] = %q duplicates an earlier entry", i, p)
		}
		seen[p] = true
	}
	for i, d := range a.AllowedDomains {
		if strings.TrimSpace(d) == "" || strings.ContainsAny(d, " \t:/") {
			return fmt.Errorf("sources.advisory.allowed_domains[%d] = %q is not a bare domain", i, d)
		}
	}
	return nil
}

func validateSiteResolution(r ResolutionConfig) error {
	for name, p := range r.ReleasePolicies {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("resolution.release_policies: empty policy name")
		}
		for i, k := range p.AllowedRefKinds {
			if !siteRefKinds[k] {
				return fmt.Errorf("resolution.release_policies[%q].allowed_ref_kinds[%d] = %q, want commit|tag|branch|release", name, i, k)
			}
		}
	}
	if r.MaxCandidates < 0 {
		return fmt.Errorf("resolution.max_candidates must be >= 0, got %d", r.MaxCandidates)
	}
	if r.MaxFeedbackPasses < 0 {
		return fmt.Errorf("resolution.max_feedback_passes must be >= 0, got %d", r.MaxFeedbackPasses)
	}
	return nil
}
