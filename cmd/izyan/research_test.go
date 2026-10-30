package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/research"
)

// researchArgs is the shared offline CLI argument set over the committed
// usage-scope fixture and the frozen advisory.
func researchArgs(root, adv, out, replay string) []string {
	args := []string{
		"--snapshot", root, "--cve", "GO-TEST-DEC1",
		"--advisory-file", adv, "--output-dir", out,
		"--external-commit-sha", "fixture-sha-t6",
		// This fixture asserts an applicability negative, which requires
		// an identified product build: a host-default target cannot
		// ground a build-dependent conclusion.
		"--goos", "linux", "--goarch", "amd64",
	}
	if replay != "" {
		args = append(args, "--replay-agent-turn", replay)
	}
	return args
}

// decisionFixtureRoot returns the committed usage-scope snapshot: its dep
// covers product/mixed/test-only build-closure classes, so the wired
// verification phase exercises a real session check without any model or
// harness call.
func decisionFixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "usagescope"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// writeDecisionAdvisory pins a frozen advisory declaring the test-only dep
// package of the usagescope fixture as the single affected subject.
func writeDecisionAdvisory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	adv := `{
	  "id": "GO-TEST-DEC1",
	  "summary": "advisory bound to the test-only dep package",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/usagedep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/usagedep/testonly"}]}
	  }]
	}`
	p := filepath.Join(dir, "GO-TEST-DEC1.json")
	if err := os.WriteFile(p, []byte(adv), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeDecisionReplayRun persists a minimal replayable run: report.json
// with one OK agent attempt plus the retained answer.txt carrying the
// given verification plan (nil plan => a plan-free answer).

func writeDecisionReplayRun(t *testing.T, planJSON string) string {
	t.Helper()
	dir := t.TempDir()
	answer := `final answer:
{"category":"code_not_reachable","reasoning":"the affected package never links into product code","assessment":{"triage_recommendation":{"action":"needs review"}}` + planJSON + `}`
	sum := sha256.Sum256([]byte(answer))
	sha := hex.EncodeToString(sum[:])
	report := `{"schema":"research-report/2","mode":"research","run":{"run_id":"research-GO-TEST-DEC1-1",
	  "attempts":[{"id":"attempt-0001","kind":"deterministic","ordinal":1,"status":"OK"},
	              {"id":"attempt-0002","kind":"agent","ordinal":2,"status":"OK"}]},
	  "agent_output":{"status":"OK","category":"code_not_reachable","attempt_id":"attempt-0002",
	    "raw_artifact":{"path":"agent/attempt-0002/answer.txt","sha256":"` + sha + `"}},
	  "contract_extensions":[],"disposition":{}}`
	// The original run's manifest pins the frozen v1 prompt: replay must
	// preserve exactly that pin — never silently substitute a newer default.
	manifest := `{"schema":"research-run-manifest/1","run_id":"research-GO-TEST-DEC1-1",
	  "agent":{"status":"OK","manifest":{"prompt_path":"eval/agent7/prompts/r0-v1.txt",
	    "prompt_sha256":"55b01e9a505bd058cb7be568f08c0e58364b8048e5acea030a14534f7031a0ae"}}}`
	if err := os.WriteFile(filepath.Join(dir, "run-manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	ad := filepath.Join(dir, "agent", "attempt-0002")
	if err := os.MkdirAll(ad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ad, "answer.txt"), []byte(answer), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --replay-agent-turn rebuilds the agent part from a persisted run. The
// retired no-agent switches no longer exist: the command never calls a model,
// so there is nothing for them to suppress (the flag surface is asserted
// absent in TestResearch_OfflineLaneFlagsRegistered).
// A bad replay dir fails closed before anything is written.
func TestResearch_ReplayBadDirFailsBeforeOutput(t *testing.T) {
	dir := t.TempDir()
	err := runResearch([]string{
		"--snapshot", dir, "--cve", "CVE-2024-32473",
		"--advisory-file", dir + "/adv.json", "--output-dir", dir + "/out",
		"--replay-agent-turn", dir + "/missing-run",
	})
	if err == nil || !strings.Contains(err.Error(), "replay-agent-turn") {
		t.Fatalf("expected replay load error, got %v", err)
	}
}

// Malformed historical documents fail validation before any output is emitted.
func TestResearch_InvalidHistoricalSchemaRefusedAtReplay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report string
	}{
		{"research-report/3", `{"schema":"research-report/3","mode":"research","run":{},"agent_output":{"status":"FAILED"},"disposition":{}}`},
		{"slice2 marker", `{"schema":"research-report/2","mode":"research","run":{},"agent_output":{"status":"FAILED"},"contract_extensions":["slice2-fidelity/3"],"disposition":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			replayDir := filepath.Join(dir, "old-run")
			if err := os.MkdirAll(replayDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(replayDir, "report.json"), []byte(tc.report), 0o644); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "out")
			err := runResearch([]string{
				"--snapshot", filepath.Join(dir, "snap"), "--cve", "CVE-2024-32473",
				"--advisory-file", filepath.Join(dir, "adv.json"), "--output-dir", out,
				"--replay-agent-turn", replayDir,
			})
			if err == nil || !strings.Contains(err.Error(), "replay-agent-turn") {
				t.Fatalf("malformed historical document was not refused: %v", err)
			}
			// The refusal precedes every other stage: no output exists.
			if _, serr := os.Stat(out); !os.IsNotExist(serr) {
				t.Fatalf("replay abort emitted output: %v", serr)
			}
		})
	}
}

// The offline evidence lane surface: --govulndb/--modcache/--build-cache-dir
// stay registered flags (the offline runbook depends on them), and the retired
// live-model switches are gone — the command starts no model, so a flag that
// only selected "do not call the model" would be a no-op.
func TestResearch_OfflineLaneFlagsRegistered(t *testing.T) {
	fs := flag.NewFlagSet("research", flag.ContinueOnError)
	var o researchOpts
	researchFlags(fs, &o)
	for _, name := range []string{"govulndb", "modcache", "build-cache-dir", "snapshot", "cve", "advisory-file",
		"artifact", "artifact-url", "artifact-credentials-env", "artifact-cache-dir",
		"artifact-timeout", "artifact-max-download-bytes", "artifact-max-extracted-bytes",
		"artifact-max-entries", "release-metadata", "ticket", "ticket-id"} {
		if fs.Lookup(name) == nil {
			t.Fatalf("flag --%s missing", name)
		}
	}
	for _, retired := range []string{"no-agent", "model", "provider", "base-url", "api-key-env",
		"agent-timeout", "agent-prompt-file"} {
		if fs.Lookup(retired) != nil {
			t.Fatalf("retired live flag --%s is still registered", retired)
		}
	}
	if err := fs.Parse([]string{
		"--snapshot", "/s", "--cve", "CVE-1", "--advisory-file", "/a.json",
		"--output-dir", "/o", "--govulndb", "/db", "--modcache", "/mc",
		"--build-cache-dir", "/bc",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.govulndb != "/db" || o.modcache != "/mc" || o.buildCacheDir != "/bc" {
		t.Fatalf("opts: %+v", o)
	}
}

// The per-tool bound defaults to the controller-measured 15m (a
// source-mode govulncheck over a ~1700-package vendored closure fit
// under it while 60s recorded TIMEOUT) and stays overridable.
func TestResearch_DeterministicTimeoutDefaultAndOverride(t *testing.T) {
	var o researchOpts
	fs := flag.NewFlagSet("research", flag.ContinueOnError)
	researchFlags(fs, &o)
	if o.detTimeout != 15*time.Minute {
		t.Fatalf("deterministic-timeout default = %s, want 15m", o.detTimeout)
	}
	if err := fs.Parse([]string{"--deterministic-timeout", "90s"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.detTimeout != 90*time.Second {
		t.Fatalf("overridden deterministic-timeout = %s", o.detTimeout)
	}
}

// --build-cache-dir reaches the strict session through the declared env
// channel (lane options carry no field): the flag sets it for the whole
// process before any route runs.
func TestResearch_BuildCacheDirSetsSessionEnv(t *testing.T) {
	dir := t.TempDir()
	bc := filepath.Join(dir, "bc")
	t.Setenv(evidencetools.BuildCacheDirEnv, "")
	err := runResearch([]string{
		"--snapshot", filepath.Join(dir, "no-snapshot"), "--cve", "CVE-2024-32473",
		"--advisory-file", filepath.Join(dir, "adv.json"),
		"--output-dir", filepath.Join(dir, "out"),
		"--build-cache-dir", bc,
	})
	// The lane fails on the missing snapshot; the env declaration must
	// already be in place — that is what the strict session consumes.
	if err == nil {
		t.Fatal("missing snapshot must fail the lane")
	}
	if got := os.Getenv(evidencetools.BuildCacheDirEnv); got != bc {
		t.Fatalf("%s=%q want %q", evidencetools.BuildCacheDirEnv, got, bc)
	}
}

// The command starts no model: the retired endpoint contract (model,
// provider label, base URL, credential env) is not part of the flag surface,
// so there is no live turn to gate and no credential to pin. A replayed turn
// keeps the identity the original run recorded, byte-identically.
func TestResearch_AgentIdentityComesFromReplayOnly(t *testing.T) {
	fs := flag.NewFlagSet("research", flag.ContinueOnError)
	var o researchOpts
	researchFlags(fs, &o)
	for _, retired := range []string{"model", "provider", "base-url", "api-key-env"} {
		if fs.Lookup(retired) != nil {
			t.Fatalf("live endpoint flag --%s is still registered", retired)
		}
	}
	// No turn: NOT_REQUESTED, with no fabricated identity.
	bare := agentManifest(researchOpts{}, nil, nil)
	if bare["status"] != research.AgentNotRequested {
		t.Fatalf("turn-less manifest status = %v", bare["status"])
	}
	if bare["provider"] != "" || bare["model"] != "" {
		t.Fatalf("turn-less manifest invented an endpoint identity: %v", bare)
	}
	// A replayed turn's recorded identity wins verbatim.
	replayTurn := &research.AgentTurn{Provider: "legacy-label", Model: "recorded-model"}
	replayed := agentManifest(researchOpts{}, replayTurn, nil)
	if replayed["provider"] != "legacy-label" || replayed["model"] != "recorded-model" {
		t.Fatalf("replayed identity not preserved: %v", replayed)
	}
	// The options manifest records the lane as deterministic and carries no
	// endpoint provenance at all.
	opts := optionsManifest(researchOpts{})
	if opts["deterministic_only"] != true {
		t.Fatalf("options deterministic_only = %v", opts["deterministic_only"])
	}
	for _, k := range []string{"agent_provider", "agent_base_url", "agent_api_key_env", "prompt_file", "agent_timeout"} {
		if _, ok := opts[k]; ok {
			t.Fatalf("%s recorded for a lane that never calls a model", k)
		}
	}
}

// The per-tool bound defaults to the controller-measured 15m (a
// source-mode govulncheck over a ~1700-package vendored closure fit
// under it while 60s recorded TIMEOUT) and stays overridable.

// --artifact and --artifact-url are mutually exclusive flag-misuse:
// they fail before any output dir is created, like the advisory-source
// pair. Channel failures instead live inside the lane as NOT_RUN.
func TestResearch_ArtifactFlagMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	err := runResearch([]string{
		"--snapshot", dir, "--cve", "CVE-2024-32473",
		"--advisory-file", dir + "/adv.json", "--output-dir", dir + "/out",
		"--artifact", dir + "/a.zip", "--artifact-url", "https://example.invalid/a.zip",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
	if _, statErr := os.Stat(dir + "/out"); statErr == nil {
		t.Fatal("output dir created before flag rejection")
	}
	for _, bad := range [][]string{
		{"--artifact-max-download-bytes", "-1"},
		{"--artifact-timeout", "-1s"},
	} {
		err := runResearch(append([]string{
			"--snapshot", dir, "--cve", "CVE-1",
			"--advisory-file", dir + "/adv.json", "--output-dir", dir + "/out2",
			"--artifact", dir + "/a.zip",
		}, bad...))
		if err == nil || !strings.Contains(err.Error(), "non-negative") {
			t.Fatalf("%v: expected bounds error, got %v", bad, err)
		}
	}
}

// TestResearch_ReleaseNotRunEndToEnd drives the real lane through the
// CLI with an artifact path that does not exist: the requested channel
// fails closed ARTIFACT_PATH_MISSING, the report carries run.outcome
// NOT_RUN plus the /3 release_evidence block, agent output stays
// NOT_REQUESTED (no model path ran), the run manifest records the
// channel outcome, and every artifact is still persisted.
func TestResearch_ReleaseNotRunEndToEnd(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	args := append(researchArgs(root, adv, out, ""),
		"--artifact", filepath.Join(dir, "missing.tar.gz"))
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Run struct {
			Outcome       string `json:"outcome"`
			OutcomeReason string `json:"outcome_reason"`
		} `json:"run"`
		Input struct {
			Snapshot struct {
				ReleaseEvidence *struct {
					Status             string `json:"status"`
					ReasonCode         string `json:"reason_code"`
					VersionGraphSource string `json:"version_graph_source"`
				} `json:"release_evidence"`
			} `json:"snapshot"`
		} `json:"input"`
		AgentOutput struct {
			Status string `json:"status"`
		} `json:"agent_output"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Run.Outcome != "NOT_RUN" || doc.Run.OutcomeReason != "ARTIFACT_PATH_MISSING" {
		t.Fatalf("run outcome %+v", doc.Run)
	}
	re := doc.Input.Snapshot.ReleaseEvidence
	if re == nil || re.Status != "NOT_RUN" || re.ReasonCode != "ARTIFACT_PATH_MISSING" ||
		re.VersionGraphSource != "unavailable" {
		t.Fatalf("release_evidence %+v", re)
	}
	if doc.AgentOutput.Status != "NOT_REQUESTED" {
		t.Fatalf("agent status %q", doc.AgentOutput.Status)
	}
	// The manifest records the same named outcome under release_evidence
	// plus the channel options — and never the missing path's bytes.
	mb, err := os.ReadFile(filepath.Join(out, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mdoc struct {
		ReleaseEvidence *struct {
			Status     string `json:"status"`
			ReasonCode string `json:"reason_code"`
		} `json:"release_evidence"`
		Options map[string]any `json:"options"`
		Agent   map[string]any `json:"agent"`
	}
	if err := json.Unmarshal(mb, &mdoc); err != nil {
		t.Fatal(err)
	}
	if mdoc.ReleaseEvidence == nil || mdoc.ReleaseEvidence.Status != "NOT_RUN" ||
		mdoc.ReleaseEvidence.ReasonCode != "ARTIFACT_PATH_MISSING" {
		t.Fatalf("manifest release_evidence %+v", mdoc.ReleaseEvidence)
	}
	if mdoc.Options["artifact_path"] == "" {
		t.Fatal("manifest lost the artifact_path option")
	}
	if mdoc.Agent["skipped_reason"] == "" {
		t.Fatal("manifest agent row lacks skipped_reason")
	}
	// Lane artifacts exist; the lane observation ledger records the
	// channel outcome.
	if _, err := os.Stat(filepath.Join(out, "observations.jsonl")); err != nil {
		t.Fatal("observations ledger missing")
	}
	ob, _ := os.ReadFile(filepath.Join(out, "observations.jsonl"))
	if !strings.Contains(string(ob), "release-evidence") ||
		!strings.Contains(string(ob), "ARTIFACT_PATH_MISSING") {
		t.Fatal("release-evidence lane observation missing from ledger")
	}
}

// TestResearch_ReleaseMetadataNotRunEndToEnd feeds a malformed
// release-metadata/1 document through the CLI: the channel fails closed
// NOT_RUN/RELEASE_METADATA_INVALID and the report records it.
func TestResearch_ReleaseMetadataNotRunEndToEnd(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	dir := t.TempDir()
	meta := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(meta, []byte(`{"schema":"release-metadata/2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	args := append(researchArgs(root, adv, out, ""),
		"--release-metadata", meta)
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Run struct {
			Outcome       string `json:"outcome"`
			OutcomeReason string `json:"outcome_reason"`
		} `json:"run"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Run.Outcome != "NOT_RUN" || doc.Run.OutcomeReason != "RELEASE_METADATA_INVALID" {
		t.Fatalf("run outcome %+v", doc.Run)
	}
}

// writeDeclaredAssumptionsDoc pins a well-formed declared-assumptions/1
// document (policy/scope inputs only) for the CLI tests.
func writeDeclaredAssumptionsDoc(t *testing.T, dir string, members ...domain.DeclaredAssumption) string {
	t.Helper()
	doc := domain.DeclaredAssumptionsDocument{
		Schema:        domain.DeclaredAssumptionsSchema,
		Assumptions:   members,
		ContentDigest: domain.DeclaredAssumptionsContentDigest(domain.DeclaredAssumptionsSchema, members),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "assumptions.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func declaredAssumptionMember(t *testing.T, id string, kind domain.DeclaredAssumptionKind) domain.DeclaredAssumption {
	t.Helper()
	a := domain.DeclaredAssumption{
		ID: id, Kind: kind,
		Statement:  "statement for " + id,
		Scope:      domain.AssumptionScopeProduct,
		Authority:  "security-owner",
		Owner:      "platform-security",
		SourceRef:  "policy://" + id,
		ReviewDate: "2027-01-01",
	}
	if kind == domain.AssumptionSupportedTargets {
		a.Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}, GOARCH: []string{"amd64"}}
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return a
}

// --declared-assumptions is an explicit input channel: the report carries
// the typed members in their own block, the manifest records only
// sanitized provenance, and no assumption is promoted to evidence.
func TestDeclaredAssumptionsResearchEndToEnd(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	dir := t.TempDir()
	trust := declaredAssumptionMember(t, "ASM-CONFIG-TRUST", domain.AssumptionConfigTrust)
	targets := declaredAssumptionMember(t, "ASM-LINUX", domain.AssumptionSupportedTargets)
	path := writeDeclaredAssumptionsDoc(t, dir, trust, targets)
	out := filepath.Join(dir, "out")
	args := append(researchArgs(root, adv, out, ""),
		"--declared-assumptions", path)
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}

	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Input struct {
			DeclaredAssumptions *struct {
				Path        string `json:"path"`
				SHA256      string `json:"sha256"`
				Schema      string `json:"schema"`
				LoadError   string `json:"load_error"`
				Assumptions []struct {
					ID   string `json:"id"`
					Kind string `json:"kind"`
				} `json:"assumptions"`
			} `json:"declared_assumptions"`
		} `json:"input"`
		VerifiedFacts []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"verified_facts"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	da := doc.Input.DeclaredAssumptions
	if da == nil || da.LoadError != "" {
		t.Fatalf("declared_assumptions input = %+v", da)
	}
	if da.Path != "local:assumptions.json" || strings.Contains(da.Path, dir) {
		t.Fatalf("path is not sanitized provenance: %q", da.Path)
	}
	if da.Schema != domain.DeclaredAssumptionsSchema || len(da.SHA256) != 64 || len(da.Assumptions) != 2 {
		t.Fatalf("declared_assumptions block = %+v", da)
	}
	for _, f := range doc.VerifiedFacts {
		if f.ID == trust.ID || f.ID == targets.ID {
			t.Fatalf("assumption promoted to a verified fact: %+v", f)
		}
	}

	md, err := os.ReadFile(filepath.Join(out, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "## Declared assumptions — policy/scope inputs, not deterministic evidence") ||
		!strings.Contains(string(md), trust.ID) || !strings.Contains(string(md), targets.ID) {
		t.Fatalf("assumptions section missing from report.md")
	}

	mb, err := os.ReadFile(filepath.Join(out, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mdoc struct {
		Options map[string]any `json:"options"`
	}
	if err := json.Unmarshal(mb, &mdoc); err != nil {
		t.Fatal(err)
	}
	if got, _ := mdoc.Options["declared_assumptions"].(string); got != "local:assumptions.json" {
		t.Fatalf("manifest declared_assumptions = %q", got)
	}
	ob, err := os.ReadFile(filepath.Join(out, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ob), "declared-assumptions") || !strings.Contains(string(ob), trust.ID) {
		t.Fatal("declared-assumptions lane observation missing from the ledger")
	}
}

// A malformed document fails closed through the CLI: the report records
// the typed intake error and still validates.
func TestDeclaredAssumptionsResearchInvalidEndToEnd(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "assumptions.json")
	if err := os.WriteFile(path, []byte(`{"schema":"declared-assumptions/2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	args := append(researchArgs(root, adv, out, ""),
		"--declared-assumptions", path)
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Input struct {
			DeclaredAssumptions *struct {
				LoadError string `json:"load_error"`
			} `json:"declared_assumptions"`
		} `json:"input"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Input.DeclaredAssumptions == nil ||
		doc.Input.DeclaredAssumptions.LoadError != domain.AssumptionsLoadInvalid {
		t.Fatalf("declared_assumptions block = %+v", doc.Input.DeclaredAssumptions)
	}
}

// writeProposalArtifact pins an implementation-locus-proposals/1 document
// bound to the exact advisory file bytes (advisory_sha256) whose members
// quote the advisory verbatim — the operator-side replay artifact.
func writeProposalArtifact(t *testing.T, dir, advPath string, members []domain.ImplementationLocusProposal) string {
	t.Helper()
	raw, err := os.ReadFile(advPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	doc := struct {
		Schema         string                               `json:"schema"`
		AdvisorySHA256 string                               `json:"advisory_sha256"`
		Proposals      []domain.ImplementationLocusProposal `json:"proposals"`
	}{
		Schema:         "implementation-locus-proposals/1",
		AdvisorySHA256: hex.EncodeToString(sum[:]),
		Proposals:      members,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "proposals.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func decisionLocusProposal() domain.ImplementationLocusProposal {
	return domain.ImplementationLocusProposal{
		ID: "locus-a", Quality: domain.QualityLLMInferred,
		Module: "example.com/usagedep", Version: "v1.0.0",
		Package: "example.com/usagedep/testonly",
		File:    "testonly.go", Function: "TestOnly",
		Marker:              "test-only marker",
		AdvisoryEvidenceRef: "adv:GO-TEST-DEC1",
		AdvisoryQuotedSpan:  "advisory bound to the test-only dep package",
	}
}

// --implementation-locus-proposal is a typed input channel: the report
// carries the admitted members in their own block with sanitized
// provenance and digest pins, and the manifest records the flag path.
func TestImplementationProposalResearchEndToEnd(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	dir := t.TempDir()
	path := writeProposalArtifact(t, dir, adv, []domain.ImplementationLocusProposal{decisionLocusProposal()})
	out := filepath.Join(dir, "out")
	args := append(researchArgs(root, adv, out, ""),
		"--implementation-locus-proposal", path)
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Input struct {
			ImplementationLocusProposals *struct {
				Source         string `json:"source"`
				Path           string `json:"path"`
				SHA256         string `json:"sha256"`
				AdvisorySHA256 string `json:"advisory_sha256"`
				LoadError      string `json:"load_error"`
				Proposals      []struct {
					ID      string `json:"id"`
					Quality string `json:"quality"`
				} `json:"proposals"`
			} `json:"implementation_locus_proposals"`
		} `json:"input"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	pi := doc.Input.ImplementationLocusProposals
	if pi == nil || pi.LoadError != "" {
		t.Fatalf("implementation_locus_proposals input = %+v", pi)
	}
	if pi.Source != "artifact-file" {
		t.Fatalf("source = %q", pi.Source)
	}
	if pi.Path != "local:proposals.json" || strings.Contains(pi.Path, dir) {
		t.Fatalf("path is not sanitized provenance: %q", pi.Path)
	}
	if len(pi.SHA256) != 64 || len(pi.AdvisorySHA256) != 64 ||
		len(pi.Proposals) != 1 || pi.Proposals[0].ID != "locus-a" ||
		pi.Proposals[0].Quality != string(domain.QualityLLMInferred) {
		t.Fatalf("proposals block = %+v", pi)
	}
	mb, err := os.ReadFile(filepath.Join(out, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mdoc struct {
		Options map[string]any `json:"options"`
	}
	if err := json.Unmarshal(mb, &mdoc); err != nil {
		t.Fatal(err)
	}
	if got, _ := mdoc.Options["implementation_locus_proposal"].(string); got != "local:proposals.json" {
		t.Fatalf("manifest implementation_locus_proposal = %q", got)
	}
	ob, err := os.ReadFile(filepath.Join(out, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ob), "implementation-axis") {
		t.Fatal("implementation-axis lane observation missing from the ledger")
	}
}

// A missing or malformed artifact fails closed through the CLI: the
// report records the typed intake error and no member is admitted.
func TestImplementationProposalResearchInvalidEndToEnd(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	args := append(researchArgs(root, adv, out, ""),
		"--implementation-locus-proposal",
		filepath.Join(dir, "absent.json"))
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Input struct {
			ImplementationLocusProposals *struct {
				LoadError string `json:"load_error"`
				Proposals []any  `json:"proposals"`
			} `json:"implementation_locus_proposals"`
		} `json:"input"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	pi := doc.Input.ImplementationLocusProposals
	if pi == nil || pi.LoadError != research.ImplementationProposalsLoadUnreadable ||
		len(pi.Proposals) != 0 {
		t.Fatalf("implementation_locus_proposals block = %+v", pi)
	}
}
