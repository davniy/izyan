package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/productb/vulnerability"
)

// stage0GitRepo builds a small local repository usable as a catalog source:
// two versioned release tags on main plus a go.mod so material collection
// sees a real module manifest.
func stage0GitRepo(t *testing.T) (dir, headSHA string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		gitCmd(t, dir, args...)
	}
	run("init", "-q", "-b", "main")
	run("config", "user.name", "Test")
	run("config", "user.email", "test@example.com")
	writeFile(t, filepath.Join(dir, "version.txt"), "v1.4.0")
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.org/service\n\ngo 1.25\n")
	run("add", ".")
	run("commit", "-q", "-m", "release 1.4.0")
	run("tag", "v1.4.0")
	writeFile(t, filepath.Join(dir, "version.txt"), "v1.5.0")
	run("add", ".")
	run("commit", "-q", "-m", "release 1.5.0")
	run("tag", "v1.5.0")
	headSHA = strings.TrimSpace(gitOutput(t, dir, "rev-parse", "HEAD"))
	return dir, headSHA
}

// stage0Config is the minimal triage-site configuration for a local git
// source: published-release policy, advisory freeze and no remote lanes.
func stage0Config(dir string) SiteConfig {
	return SiteConfig{
		SchemaVersion: SiteConfigSchemaVersion,
		Sources: SiteSources{
			Repositories: []CatalogEntry{{
				ID:            "example-service",
				Kind:          "local",
				Root:          dir,
				ReleasePolicy: "published-release",
				Ecosystem:     "go",
				Aliases:       []string{"service-example"},
			}},
			Advisory: AdvisoryConfig{Priority: []string{"ticket", "frozen_osv"}, Freeze: true},
		},
		Resolution: ResolutionConfig{
			ReleasePolicies:   map[string]ReleasePolicy{"published-release": publishedReleasePolicy()},
			MaxCandidates:     16,
			MaxFeedbackPasses: 2,
		},
		Budgets: BudgetConfig{MaxAdvisoryBytes: 1 << 20},
	}
}

// stage0Input assembles the Stage0Input for a text ticket over the fixture
// repository. The fake chat scripts the intake proposal and ref selection.
func stage0Input(t *testing.T, ticket string, chat ChatClient) Stage0Input {
	t.Helper()
	dir, _ := stage0GitRepo(t)
	raw, err := ParseIntakeRecord([]byte(ticket), 1)
	if err != nil {
		t.Fatalf("ParseIntakeRecord: %v", err)
	}
	return Stage0Input{
		Raw:        raw,
		Config:     stage0Config(dir),
		ChatClient: chat,
		FreezeDir:  t.TempDir(),
		Now:        fixedNow,
	}
}

const stage0TicketText = `Scanner reported CVE-2099-0001 (alias GHSA-xxxx-yyyy-zzzz) in module example.org/library/parser.
Component service-example, product Example Service, release v1.4.0, built with go1.25.1.
Affected version 1.4.2. Severity: high.`

const stage0ProposalJSON = `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"aliases":["GHSA-xxxx-yyyy-zzzz"],"package":"example.org/library/parser","version":"1.4.2","component":"service-example","product":"Example Service","release":"v1.4.0","go_version":"go1.25.1","severity":"high","summary":"parser overflow"}`

// A trusted scanner ticket may supply the release Go version. The LLM must
// still extract that value from the ticket rather than inventing another one:
// an UNVERIFIED proposal is retained for audit but never reaches the finding,
// release toolchain or package applicability check.
func TestStage0GoVersionRequiresConfirmedTicketExtraction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ticket string
		status IntakeFieldStatus
		wantGo string
	}{
		{
			name:   "trusted ticket version",
			ticket: stage0TicketText,
			status: IntakeValid,
			wantGo: "go1.25.1",
		},
		{
			name:   "LLM version absent from ticket",
			ticket: strings.Replace(stage0TicketText, ", built with go1.25.1", "", 1),
			status: IntakeUnverified,
		},
		{
			name:   "LLM version contradicts ticket",
			ticket: strings.Replace(stage0TicketText, "go1.25.1", "go1.24.2", 1),
			status: IntakeUnverified,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := stage0Input(t, tc.ticket, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
			res, err := ResolveStage0(context.Background(), in)
			if err != nil {
				t.Fatalf("ResolveStage0: %v", err)
			}
			defer res.Source.Cleanup()

			fv, ok := res.Validation.Field("go_version")
			if !ok || fv.Status != tc.status {
				t.Fatalf("go_version validation = %+v (found=%v), want %s", fv, ok, tc.status)
			}
			if res.Proposal.GoVersion != "go1.25.1" {
				t.Fatalf("original LLM proposal was lost: %+v", res.Proposal)
			}
			if got := res.Input.Finding.Target.Toolchain; got != tc.wantGo {
				t.Fatalf("finding target toolchain = %q, want %q", got, tc.wantGo)
			}
			if res.ReleaseToolchain.Version != tc.wantGo {
				t.Fatalf("release toolchain = %+v, want version %q", res.ReleaseToolchain, tc.wantGo)
			}
			if res.Materials.Toolchain == nil || res.Materials.Toolchain.Version != tc.wantGo {
				t.Fatalf("material toolchain = %+v, want version %q", res.Materials.Toolchain, tc.wantGo)
			}
		})
	}
}

// stage0Chat returns a scripted client answering the intake extraction and
// then the ref selection naming selectedID (empty means use fallback).
func stage0Chat(proposal, selectedID string) *stubIntakeChat {
	replies := []string{proposal}
	if selectedID != "" {
		replies = append(replies, refSelectJSON(selectedID, "exact", "selected release"))
	}
	return &stubIntakeChat{replies: replies}
}

func TestStage0VerticalSliceText(t *testing.T) {
	in := stage0Input(t, stage0TicketText, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()

	if res.Input.Finding.FindingID == "" {
		t.Fatal("synthesized finding_id is empty")
	}
	if !strings.HasPrefix(res.Input.Finding.FindingID, "intake-") {
		t.Fatalf("finding_id %q must derive from the intake record", res.Input.Finding.FindingID)
	}
	if res.Input.Finding.SchemaVersion != FindingSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", res.Input.Finding.SchemaVersion, FindingSchemaVersion)
	}
	if len(res.Input.Finding.Vulnerability.IDs) != 1 || res.Input.Finding.Vulnerability.IDs[0] != "CVE-2099-0001" {
		t.Fatalf("vulnerability.ids = %v", res.Input.Finding.Vulnerability.IDs)
	}
	if len(res.Input.Raw) == 0 || res.Input.SHA256 == "" {
		t.Fatal("normalized finding input must carry raw bytes and sha256")
	}
	if res.Proposal.Package != "example.org/library/parser" {
		t.Fatalf("proposal package = %q", res.Proposal.Package)
	}
	if len(res.Validation.Errors) != 0 {
		t.Fatalf("validation errors: %v", res.Validation.Errors)
	}
	if res.CatalogEntry.ID != "example-service" {
		t.Fatalf("catalog entry = %q, want example-service", res.CatalogEntry.ID)
	}
	if len(res.CandidateRefs) == 0 {
		t.Fatal("no ref candidates enumerated")
	}
	if res.SelectedRef.Name != "v1.4.0" || res.SelectedRef.Kind != RefTag {
		t.Fatalf("selected ref = %+v, want tag v1.4.0", res.SelectedRef)
	}
	if res.Source.Metadata.Mode != MaterializationWorktree && res.Source.Metadata.Mode != MaterializationLocal {
		t.Fatalf("materialization mode = %q, want isolated worktree or local", res.Source.Metadata.Mode)
	}
	if res.Snapshot.ContentHash == "" || res.Snapshot.SchemaVersion != SnapshotSchemaVersion {
		t.Fatalf("snapshot manifest incomplete: %+v", res.Snapshot)
	}
	if res.Snapshot.Materialization.SourceID != "example-service" {
		t.Fatalf("materialization provenance missing: %+v", res.Snapshot.Materialization)
	}
	if res.Snapshot.Materialization.SelectedRef != "v1.4.0" {
		t.Fatalf("materialization selected_ref = %q", res.Snapshot.Materialization.SelectedRef)
	}
	if res.Advisory.SchemaVersion != vulnerability.FrozenAdvisorySchemaVersion || res.Advisory.SHA256 == "" {
		t.Fatalf("frozen advisory record incomplete: %+v", res.Advisory)
	}
	if res.Resolution == nil || len(res.Resolution.Attempts) == 0 {
		t.Fatal("advisory resolution must record source attempts")
	}
	if res.Materials.ModuleGraph == nil || len(res.Materials.ModuleGraph.Modules) == 0 {
		t.Fatal("module graph must resolve over the snapshot")
	}
	if res.PackageCheck.Class == "" {
		t.Fatal("package check classification empty")
	}
	if res.Toolchain.GoBin == "" {
		t.Fatal("toolchain unresolved")
	}
	if len(res.Events) == 0 {
		t.Fatal("stage 0 must emit audit events")
	}
	wantTypes := map[string]bool{
		AuditEventIntakeResolution: true,
		AuditEventSourceResolution: true,
		AuditEventRefResolution:    true,
		AuditEventMaterialization:  true,
		AuditEventAdvisoryFreeze:   true,
		AuditEventMaterials:        true,
		AuditEventPackageCheck:     true,
		AuditEventToolchain:        true,
	}
	for _, ev := range res.Events {
		delete(wantTypes, ev.Type)
	}
	if len(wantTypes) != 0 {
		t.Fatalf("missing audit event types: %v", wantTypes)
	}
	if len(res.Transcript) == 0 {
		t.Fatal("LLM transcript must carry the intake/ref selection messages")
	}
	// Ticket hash must be bound to the verbatim record bytes.
	if res.Raw.TicketHash != hashBytes(in.Raw.Raw) {
		t.Fatalf("ticket_hash drift: %q != sha256(record)", res.Raw.TicketHash)
	}
}

func TestStage0VerticalSliceJSON(t *testing.T) {
	ticket := `{"vulnerability":"CVE-2099-0001","summary":"parser overflow","severity":"high","module":"example.org/library/parser","component":"service-example","release":"v1.4.0","go_version":"go1.25.1"}`
	in := stage0Input(t, ticket, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if res.Raw.Format != IntakeJSON {
		t.Fatalf("format = %q, want json", res.Raw.Format)
	}
	if res.SelectedRef.Name != "v1.4.0" {
		t.Fatalf("selected ref = %q", res.SelectedRef.Name)
	}
}

func TestStage0MissingVulnIDIsError(t *testing.T) {
	proposal := `{"schema_version":"intake-proposal.v1","component":"service-example","summary":"no id anywhere"}`
	in := stage0Input(t, "component service-example flagged as problematic", stage0Chat(proposal, ""))
	_, err := ResolveStage0(context.Background(), in)
	if err == nil {
		t.Fatal("intake without any vulnerability id must be a technical error")
	}
}

func TestStage0UnresolvableSourceIsError(t *testing.T) {
	proposal := `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"component":"no-such-service","summary":"parser overflow"}`
	in := stage0Input(t, "CVE-2099-0001 in component no-such-service", stage0Chat(proposal, ""))
	_, err := ResolveStage0(context.Background(), in)
	mustError(t, err, "source")
}

func TestStage0NoAdmissibleRefIsError(t *testing.T) {
	// HEAD is untagged and no tag/release ref exists: the published-release
	// policy admits nothing and fallback must never pick HEAD silently.
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "user.email", "test@example.com")
	writeFile(t, filepath.Join(dir, "a.txt"), "work")
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-q", "-m", "work")
	raw := mustIntakeRecord(t, stage0TicketText)
	in := Stage0Input{
		Raw:        raw,
		Config:     stage0Config(dir),
		ChatClient: stage0Chat(stage0ProposalJSON, ""),
		FreezeDir:  t.TempDir(),
		Now:        fixedNow,
	}
	_, err := ResolveStage0(context.Background(), in)
	mustError(t, err, "ref")
}

func TestStage0AmbiguousCatalogMatchIsError(t *testing.T) {
	dir, _ := stage0GitRepo(t)
	// Two catalog entries answer to the same name: the match is
	// CONFLICTING, never a silent pick — and with no usable source the
	// run is a technical error carrying the conflict as a limitation.
	cfg := stage0Config(dir)
	cfg.Sources.Repositories = append(cfg.Sources.Repositories, CatalogEntry{
		ID: "example-service-mirror", Kind: "local", Root: dir,
		ReleasePolicy: "published-release", Aliases: []string{"service-example"},
	})
	raw := mustIntakeRecord(t, stage0TicketText)
	in := Stage0Input{
		Raw:        raw,
		Config:     cfg,
		ChatClient: stage0Chat(stage0ProposalJSON, ""),
		FreezeDir:  t.TempDir(),
	}
	res, err := ResolveStage0(context.Background(), in)
	if err == nil {
		t.Fatal("ambiguous catalog match must be a technical error")
	}
	var sawConflicting bool
	for _, f := range res.Validation.Fields {
		if f.Field == "component" && f.Status == IntakeConflicting {
			sawConflicting = true
		}
	}
	for _, f := range res.Validation.Fields {
		if f.Field == "component" && f.Status == IntakeValid {
			t.Fatal("component match must not silently resolve to VALID")
		}
	}
	if !sawConflicting {
		t.Fatalf("component field must be CONFLICTING, got %+v", res.Validation.Fields)
	}
}

func TestStage0FreezeNeverTouchesNetwork(t *testing.T) {
	// freeze:true must confine advisory resolution to ticket material and
	// the frozen store — even an allowed OSV domain may not be dialed.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
	}))
	defer srv.Close()
	host := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0]

	dir, _ := stage0GitRepo(t)
	cfg := stage0Config(dir)
	cfg.Sources.Advisory.AllowedDomains = []string{host}
	raw := mustIntakeRecord(t, `{"vulnerability":"CVE-2099-0001","component":"service-example","osv":{"id":"CVE-2099-0001","summary":"embedded advisory","affected":[]}}`)
	in := Stage0Input{
		Raw:        raw,
		Config:     cfg,
		ChatClient: stage0Chat(stage0ProposalJSON, "tag:v1.4.0"),
		FreezeDir:  t.TempDir(),
		OSVBaseURL: srv.URL,
	}
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if hits != 0 {
		t.Fatalf("freeze:true hit the network %d time(s)", hits)
	}
	if res.Advisory.SHA256 == "" {
		t.Fatal("frozen advisory identity missing")
	}
}

func TestStage0FrozenDocServedOffline(t *testing.T) {
	// A frozen store prepared by an earlier run serves with freeze:true and
	// a dead remote: replay-shaped resolution with zero network access.
	frozenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(frozenDir, "GO-2099-0001.json"), []byte(advisoryOSVDoc), 0o444); err != nil {
		t.Fatal(err)
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++ }))
	defer srv.Close()
	host := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0]

	dir, _ := stage0GitRepo(t)
	cfg := stage0Config(dir)
	cfg.Sources.Advisory.Priority = []string{"frozen_osv"}
	cfg.Sources.Advisory.AllowedDomains = []string{host}
	raw := mustIntakeRecord(t, `{"vulnerability":"CVE-2099-0001","component":"service-example"}`)
	in := Stage0Input{
		Raw:        raw,
		Config:     cfg,
		ChatClient: stage0Chat(stage0ProposalJSON, "tag:v1.4.0"),
		FreezeDir:  t.TempDir(),
		FrozenDir:  frozenDir,
		OSVBaseURL: srv.URL,
	}
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if hits != 0 {
		t.Fatalf("frozen resolution hit the network %d time(s)", hits)
	}
	if res.Advisory.Source != vulnerability.AdvisoryFrozenOSV || res.Advisory.ResolvedID != "GO-2099-0001" {
		t.Fatalf("advisory record = %+v", res.Advisory)
	}
}

func TestStage0UnverifiedIDWithoutAdvisoryIsError(t *testing.T) {
	// The LLM claims an id absent from the raw text and every advisory
	// lane: nothing confirms it, so there is no conservative continuation.
	proposal := `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"component":"service-example","summary":"overflow"}`
	in := stage0Input(t, "component service-example misconfigured", stage0Chat(proposal, ""))
	res, err := ResolveStage0(context.Background(), in)
	if err == nil {
		t.Fatal("unverified vulnerability ID must be a technical error")
	}
	if res.Raw.TicketHash == "" {
		t.Fatal("failed Stage 0 must retain the raw record identity")
	}
}

func TestStage0LocalCheckoutOffRequestedRefIsError(t *testing.T) {
	// A local git checkout is never mutated: selecting another release uses
	// a detached worktree and leaves the source checkout at its original HEAD.
	dir, _ := stage0GitRepo(t)
	gitCmd(t, dir, "checkout", "-q", "v1.4.0")
	initial := strings.TrimSpace(gitOutput(t, dir, "rev-parse", "HEAD"))
	raw := mustIntakeRecord(t, strings.Replace(stage0TicketText, "v1.4.0", "v1.5.0", 1))
	in := Stage0Input{
		Raw: raw, Config: stage0Config(dir),
		ChatClient: stage0Chat(strings.Replace(stage0ProposalJSON, `"release":"v1.4.0"`, `"release":"v1.5.0"`, 1), "tag:v1.5.0"),
		FreezeDir:  t.TempDir(),
	}
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if res.Source.Metadata.Mode != MaterializationWorktree {
		t.Fatalf("mode = %q, want worktree", res.Source.Metadata.Mode)
	}
	if got := strings.TrimSpace(gitOutput(t, dir, "rev-parse", "HEAD")); got != initial {
		t.Fatalf("source checkout mutated: head=%s initial=%s", got, initial)
	}
}

func TestStage0FallbackSelection(t *testing.T) {
	// A bad agent answer (ref outside the bounded list) must route through
	// bounded feedback and end on the deterministic fallback — never HEAD.
	chat := &stubIntakeChat{replies: []string{
		stage0ProposalJSON,
		refSelectJSON("tag:v9.9.9", "exact", "invented"),
		refSelectJSON("tag:v9.9.9", "exact", "invented again"),
		refSelectJSON("tag:v9.9.9", "exact", "still invented"),
	}}
	in := stage0Input(t, stage0TicketText, chat)
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if res.RefResolution.SelectionProvenance != RefProvenanceFallback {
		t.Fatalf("provenance = %q, want fallback", res.RefResolution.SelectionProvenance)
	}
	// requested v1.4.0; same-series/nearest fallback must land on v1.4.0.
	if res.SelectedRef.Name != "v1.4.0" {
		t.Fatalf("fallback ref = %q, want v1.4.0", res.SelectedRef.Name)
	}
}

func TestIntakeFindingIDDeterministic(t *testing.T) {
	raw := mustIntakeRecord(t, "text one")
	a, b := IntakeFindingID(raw), IntakeFindingID(raw)
	if a != b || a == "" {
		t.Fatalf("IntakeFindingID not deterministic: %q vs %q", a, b)
	}
	other := mustIntakeRecord(t, "text two")
	if IntakeFindingID(other) == a {
		t.Fatal("distinct records must not share a finding_id")
	}
	if !strings.Contains(a, "intake-") {
		t.Fatalf("finding_id %q must be readable as intake-derived", a)
	}
}

func TestStage0ResultRoundtripJSON(t *testing.T) {
	// Everything handed to artifact writers must serialize: spot-check the
	// provenance-facing fields survive a JSON round trip.
	in := stage0Input(t, stage0TicketText, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	for name, v := range map[string]any{
		"proposal":    res.Proposal,
		"validation":  res.Validation,
		"materials":   res.Materials,
		"snapshot":    res.Snapshot,
		"advisory":    res.Advisory,
		"resolution":  res.RefResolution,
		"toolchain_f": res.ReleaseToolchain,
	} {
		b, err := json.Marshal(v)
		if err != nil || len(b) == 0 {
			t.Fatalf("%s does not marshal: %v", name, err)
		}
	}
	if res.ConfigHash == "" {
		t.Fatal("config hash must be recorded")
	}
}

func TestStage0RequestedReleasePrecedence(t *testing.T) {
	cases := []struct {
		name         string
		p            IntakeProposal
		want, source string
	}{
		{"release", IntakeProposal{Release: "6.5.0", RefHint: "release/6.5.0", ComponentVersion: "6.2.0-1530", ProductVersion: "6.5.2"}, "6.5.0", "release"},
		{"ref hint", IntakeProposal{RefHint: "release/6.2.0"}, "release/6.2.0", "ref_hint"},
		{"component version", IntakeProposal{ComponentVersion: "6.2.0-1530", ProductVersion: "6.5.2"}, "6.2.0-1530", "component_version"},
		{"product version", IntakeProposal{ProductVersion: "6.5.2"}, "6.5.2", "product_version"},
		{"none", IntakeProposal{}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, source, _ := requestedRelease(tc.p)
			if got != tc.want || source != tc.source {
				t.Fatalf("requestedRelease = %q/%q, want %q/%q", got, source, tc.want, tc.source)
			}
		})
	}
}

func TestStage0ComponentBuildSuffixSameSeriesFallback(t *testing.T) {
	policy := ReleasePolicy{AllowedRefKinds: []string{"tag"}, RequireResolvedCommit: true}
	cands := []RefCandidate{
		{ID: "tag:v6.2.0-3056", Name: "v6.2.0-3056", Kind: RefTag, Release: "6.2.0-3056", Commit: strings.Repeat("b2", 20), Source: "service-example"},
	}
	got, rule, err := fallbackCandidate(cands, policy, "6.2.0-1530", false)
	if err != nil {
		t.Fatalf("fallbackCandidate: %v", err)
	}
	if got.Name != "v6.2.0-3056" || rule != RefRuleSameReleaseBuild {
		t.Fatalf("picked %q with rule %q, want v6.2.0-3056 same-release-build", got.Name, rule)
	}
}

func TestStage0AgentFindingViewFromResolution(t *testing.T) {
	// A ticket carrying an embedded OSV document resolves a full advisory;
	// the agent-facing view must carry its prose, aliases and severity so
	// lookup_advisory never reports empty fields.
	ticket := `{"vulnerability":"CVE-2099-0001","component":"service-example","release":"v1.4.0","osv":{"id":"GHSA-p77j-4mvh-x3m3","aliases":["CVE-2099-0001"],"summary":"resolved advisory summary","details":"resolved advisory description with the vulnerable code path","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"example.org/library/parser","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.4.3"}]}]}],"references":[{"type":"ADVISORY","url":"https://example.com/adv"}]}}`
	in := stage0Input(t, ticket, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if res.Resolution == nil || res.Resolution.Vulnerability == nil {
		t.Fatal("embedded advisory must resolve to a vulnerability record")
	}

	view := res.AgentFinding()
	v := view.Finding.Vulnerability
	if v.Summary != "resolved advisory summary" || v.Description != "resolved advisory description with the vulnerable code path" {
		t.Fatalf("agent view missing advisory prose: %+v", v)
	}
	if !containsCanonicalID(v.IDs, "GHSA-p77j-4mvh-x3m3") || !containsCanonicalID(v.IDs, "CVE-2099-0001") {
		t.Fatalf("agent view ids %v must carry resolved id plus intake ids", v.IDs)
	}
	if len(v.References) == 0 || v.References[0] != "https://example.com/adv" {
		t.Fatalf("agent view references: %v", v.References)
	}
	if v.BaseSeverity != "HIGH" {
		t.Fatalf("agent view severity = %q", v.BaseSeverity)
	}
	// The normalized intake finding and its raw bytes are untouched: the
	// view is a projection, never a rewrite of stored provenance.
	if view.SHA256 != res.Input.SHA256 || string(view.Raw) != string(res.Input.Raw) {
		t.Fatal("agent view must preserve the normalized input record and hash")
	}
	if res.Input.Finding.Vulnerability.Description != "" {
		t.Fatal("normalized input.json finding must not absorb advisory prose")
	}
	// Idempotent: re-applying to the view changes nothing (replay path).
	twice := Stage0AgentFinding(view, res.Resolution.Vulnerability)
	if !jsonEqual(twice.Finding.Vulnerability, view.Finding.Vulnerability) {
		t.Fatalf("view not idempotent: %+v vs %+v", twice.Finding.Vulnerability, view.Finding.Vulnerability)
	}
}

func TestStage0AgentFindingWithoutResolution(t *testing.T) {
	// No advisory resolution: the view is the normalized finding itself.
	raw := mustIntakeRecord(t, "scanner flagged CVE-2099-0001")
	in := FindingInput{Finding: Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     IntakeFindingID(raw),
		Vulnerability: Vulnerability{IDs: []string{"CVE-2099-0001"}, Summary: "intake summary"},
	}, Raw: raw.Raw, SHA256: raw.TicketHash}
	view := Stage0AgentFinding(in, nil)
	if !jsonEqual(view.Finding.Vulnerability, in.Finding.Vulnerability) {
		t.Fatalf("nil advisory must preserve the finding: %+v", view.Finding.Vulnerability)
	}
	var zero Stage0Result
	if got := zero.AdvisoryVulnerability(); got != nil {
		t.Fatalf("empty result advisory = %+v", got)
	}
	if got := zero.AdvisoryProjection(); got != nil {
		t.Fatalf("empty result projection = %+v", got)
	}
}

// stage0BuildInput is the operator-supplied build selection used by the
// target tests: Linux/amd64 with a tag and explicit CGO, deliberately not
// derived from the analyzer host.
const stage0BuildInput = `{"goos":"linux","goarch":"amd64","build_tags":["netgo"],"cgo_enabled":true,"source":"operator-declared","scope":"operator"}`

// TestStage0CarriesResolvedBuildTarget: Stage 0 resolves the supplied build
// once and persists it in both the Stage 0 projection and the material
// projection; the agent-facing finding carries the same record.
func TestStage0CarriesResolvedBuildTarget(t *testing.T) {
	ctx := context.Background()
	in := stage0Input(t, stage0TicketText, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	in.Investigation = InvestigationInputs{Build: json.RawMessage(stage0BuildInput)}
	res, err := ResolveStage0(ctx, in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if res.BuildTarget == nil {
		t.Fatal("Stage 0 did not resolve the supplied product build")
	}
	if res.BuildTarget.GOOS != "linux" || res.BuildTarget.GOARCH != "amd64" ||
		len(res.BuildTarget.BuildTags) != 1 || res.BuildTarget.BuildTags[0] != "netgo" ||
		!res.BuildTarget.CGOEnabled {
		t.Fatalf("resolved target = %+v, want linux/amd64 tags=[netgo] cgo=true", *res.BuildTarget)
	}
	if err := res.BuildTarget.Validate(); err != nil {
		t.Fatalf("resolved target does not validate: %v", err)
	}

	view, err := json.Marshal(res.AgentFinding().Finding)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(view), `"build":{"goos":"linux","goarch":"amd64"`) {
		t.Fatalf("agent-facing finding does not carry the resolved build: %s", view)
	}

	dir, err := (ArtifactWriter{Clock: fixedNow, Model: "stage0-target", ToolVersions: map[string]string{"izyan": "test"}}).
		WriteStage0Artifacts(ctx, t.TempDir(), res)
	if err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(string(mustRead(t, filepath.Join(dir, "stage0.json")))), &doc); err != nil {
		t.Fatal(err)
	}
	bt, ok := doc["build_target"].(map[string]any)
	if !ok {
		t.Fatalf("stage0.json has no build_target: %v", doc["build_target"])
	}
	if bt["goos"] != "linux" || bt["goarch"] != "amd64" {
		t.Fatalf("stage0 build_target = %v", bt)
	}
	proj := string(mustRead(t, filepath.Join(dir, "investigation-inputs.json")))
	if !strings.Contains(proj, `"build_target"`) || !strings.Contains(proj, `"goos": "linux"`) {
		t.Fatalf("material projection does not carry the resolved target: %s", proj)
	}
}

// TestStage0MissingBuildTargetStaysAbsent: without a supplied build no target
// is invented; the absence is recorded as a limitation in the Stage 0
// projection and the agent-facing finding carries no build record.
func TestStage0MissingBuildTargetStaysAbsent(t *testing.T) {
	ctx := context.Background()
	in := stage0Input(t, stage0TicketText, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(ctx, in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()
	if res.BuildTarget != nil {
		t.Fatalf("Stage 0 invented a target from analysis context: %+v", res.BuildTarget)
	}
	if !strings.Contains(strings.Join(res.Limitations, "\n"), "no product build target was identified") {
		t.Fatalf("Stage 0 limitations do not name the absent target: %v", res.Limitations)
	}
	view, err := json.Marshal(res.AgentFinding().Finding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(view), `"build"`) {
		t.Fatalf("agent-facing finding with no target carries a build record: %s", view)
	}

	dir, err := (ArtifactWriter{Clock: fixedNow, Model: "stage0-target", ToolVersions: map[string]string{"izyan": "test"}}).
		WriteStage0Artifacts(ctx, t.TempDir(), res)
	if err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(string(mustRead(t, filepath.Join(dir, "stage0.json")))), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["build_target"]; ok {
		t.Fatalf("stage0.json recorded a build_target for an unidentified build: %v", doc["build_target"])
	}
}
