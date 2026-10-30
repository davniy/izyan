package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
)

const advisoryOSVDoc = `{
  "id": "GO-2099-0001",
  "aliases": ["CVE-2099-0001"],
  "summary": "example advisory",
  "affected": [
    {
      "package": {"name": "example.org/library/parser", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.3"}]}],
      "ecosystem_specific": {"imports": [{"path": "example.org/library/parser", "symbols": ["Parse"]}]}
    }
  ]
}`

func advisoryTestConfig(freeze bool, domains ...string) SiteConfig {
	return SiteConfig{
		SchemaVersion: SiteConfigSchemaVersion,
		Sources: SiteSources{
			Advisory: AdvisoryConfig{
				Priority:       []string{"ticket", "frozen_osv", "osv_api"},
				Freeze:         freeze,
				AllowedDomains: domains,
			},
		},
		Budgets: BudgetConfig{MaxAdvisoryBytes: 1 << 20},
	}
}

func advisoryRawIntake(t *testing.T, body string) *RawIntake {
	t.Helper()
	raw, err := ParseIntakeRecord([]byte(body), 1)
	if err != nil {
		t.Fatal(err)
	}
	return &raw
}

func advisoryProposal(ids ...string) IntakeProposal {
	return IntakeProposal{
		SchemaVersion:    IntakeProposalSchemaVersion,
		VulnerabilityIDs: ids,
	}
}

func TestAdvisoryPriorityTicketFrozenAPI(t *testing.T) {
	freezeDir := t.TempDir()
	frozenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(frozenDir, "GO-2099-0001.json"), []byte(advisoryOSVDoc), 0o444); err != nil {
		t.Fatal(err)
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		fmt.Fprint(w, advisoryOSVDoc)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	host = strings.Split(host, ":")[0]

	raw := advisoryRawIntake(t, `{
		"vulnerability": "CVE-2099-0001",
		"osv": {"id": "CVE-2099-0001", "summary": "ticket-embedded advisory", "affected": []}
	}`)
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false, host), AdvisoryInput{
		Proposal:   advisoryProposal("CVE-2099-0001"),
		Raw:        raw,
		FrozenDir:  frozenDir,
		OSVBaseURL: srv.URL,
	}, freezeDir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.Source != vulnerability.AdvisoryTicket {
		t.Fatalf("ticket lane must win by configured priority, got %q", res.Record.Source)
	}
	if hits != 0 {
		t.Fatalf("ticket hit must not touch the OSV API, got %d requests", hits)
	}
	if res.Vulnerability.Summary != "ticket-embedded advisory" {
		t.Fatalf("v: %+v", res.Vulnerability)
	}
	if len(res.Attempts) == 0 || res.Attempts[0].Kind != vulnerability.AdvisoryTicket ||
		res.Attempts[0].Status != vulnerability.AttemptResolved {
		t.Fatalf("attempts: %+v", res.Attempts)
	}
}

func TestAdvisoryFreezeExcludesNetworkAndPinsHash(t *testing.T) {
	dir := t.TempDir()
	// First run: freeze:false + remote API → the document is frozen into the run dir.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, advisoryOSVDoc)
	}))
	host := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0]
	res1, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false, host), AdvisoryInput{
		Proposal:   advisoryProposal("CVE-2099-0001"),
		Raw:        advisoryRawIntake(t, "scanner flagged CVE-2099-0001 in example.org/library/parser"),
		OSVBaseURL: srv.URL,
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res1.Record.Path == "" || res1.Record.SHA256 == "" {
		t.Fatalf("frozen record must pin path+hash: %+v", res1.Record)
	}
	srv.Close()

	// Second run: freeze:true — the frozen copy serves; no network at all.
	res2, err := ResolveAdvisory(context.Background(), advisoryTestConfig(true), AdvisoryInput{
		Proposal:   advisoryProposal("CVE-2099-0001"),
		Raw:        advisoryRawIntake(t, "scanner flagged CVE-2099-0001 in example.org/library/parser"),
		OSVBaseURL: srv.URL, // dead server: any dial would fail
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Record.Source != vulnerability.AdvisoryFrozenOSV {
		t.Fatalf("replay must resolve from the frozen copy, got %q", res2.Record.Source)
	}
	if res2.Vulnerability.ID != "GO-2099-0001" || res2.Vulnerability.FixedVersions[0] != "1.4.3" {
		t.Fatalf("frozen doc content wrong: %+v", res2.Vulnerability)
	}
	raw, err := os.ReadFile(res2.Record.Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != res2.Record.SHA256 {
		t.Fatal("frozen hash does not match stored bytes")
	}

	// Tamper with the frozen document: the freeze record must reject it.
	if err := os.WriteFile(res2.Record.Path, []byte(`{"id":"GO-2099-0001","affected":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAdvisory(context.Background(), advisoryTestConfig(true), AdvisoryInput{
		Proposal: advisoryProposal("CVE-2099-0001"),
	}, dir); err == nil {
		t.Fatal("substituted frozen advisory must be rejected, not silently used")
	}
}

func TestAdvisoryAPIUnavailableFallsBackToFrozen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GO-2099-0001.json"), []byte(advisoryOSVDoc), 0o444); err != nil {
		t.Fatal(err)
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	host := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0]

	// Priority osv_api first: unavailable remote must fall back to frozen.
	cfg := advisoryTestConfig(false, host)
	cfg.Sources.Advisory.Priority = []string{"osv_api", "frozen_osv"}
	res, err := ResolveAdvisory(context.Background(), cfg, AdvisoryInput{
		Proposal:   advisoryProposal("CVE-2099-0001"),
		FrozenDir:  dir,
		OSVBaseURL: srv.URL,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.Source != vulnerability.AdvisoryFrozenOSV {
		t.Fatalf("frozen copy must cover an unavailable API, got %q", res.Record.Source)
	}
	if hits < 2 {
		t.Fatalf("technical failure must see a bounded retry, got %d requests", hits)
	}
	var sawUnavailable bool
	for _, a := range res.Attempts {
		if a.Kind == vulnerability.AdvisoryOSVAPI && a.Status == vulnerability.AttemptUnavailable {
			sawUnavailable = true
		}
	}
	if !sawUnavailable {
		t.Fatalf("unavailable attempt must be recorded: %+v", res.Attempts)
	}
}

func TestAdvisoryMissingYieldsPartialWithLimitation(t *testing.T) {
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  advisoryProposal("CVE-2099-0001"),
		Raw:       advisoryRawIntake(t, "scanner flagged CVE-2099-0001 in example.org/library/parser"),
		FrozenDir: t.TempDir(),
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial {
		t.Fatal("absent advisory must produce a partial projection")
	}
	if res.Vulnerability == nil || res.Vulnerability.ID != "CVE-2099-0001" {
		t.Fatalf("partial projection must keep the valid intake id: %+v", res.Vulnerability)
	}
	var lim bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "advisory") {
			lim = true
		}
	}
	if !lim {
		t.Fatalf("missing advisory must be a limitation, not a question: %+v", res.Limitations)
	}
}

func TestAdvisoryAliasResolution(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GO-2099-0001.json"), []byte(advisoryOSVDoc), 0o444); err != nil {
		t.Fatal(err)
	}
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  advisoryProposal("CVE-2099-0001"),
		FrozenDir: dir,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Vulnerability.ID != "GO-2099-0001" || res.Record.ResolvedID != "GO-2099-0001" {
		t.Fatalf("alias must resolve to the canonical document: %+v", res.Record)
	}
	if res.Partial {
		t.Fatal("frozen OSV document must not be marked partial")
	}
}

func TestAdvisoryVersionConflictIsDeterministicLimitation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GO-2099-0001.json"), []byte(advisoryOSVDoc), 0o444); err != nil {
		t.Fatal(err)
	}
	p := advisoryProposal("CVE-2099-0001")
	p.Version = "9.9.9" // outside advisory ranges [0, 1.4.3)
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  p,
		FrozenDir: dir,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var conflict bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "9.9.9") {
			conflict = true
		}
	}
	if !conflict {
		t.Fatalf("version conflict must surface as a deterministic limitation: %+v", res.Limitations)
	}
	// The advisory document wins: its ranges stay authoritative.
	if res.Projection.FixedVersions[0] != "1.4.3" {
		t.Fatalf("advisory ranges must not be rewritten by the ticket claim: %+v", res.Projection)
	}

	// Same advisory, in-range version: no conflict limitation.
	p.Version = "1.4.0"
	res, err = ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  p,
		FrozenDir: dir,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Limitations {
		if strings.Contains(l, "1.4.0") {
			t.Fatalf("in-range version must not produce a conflict: %+v", res.Limitations)
		}
	}
}

const advisoryCVEGITDoc = `{
  "id": "CVE-2099-0001",
  "aliases": ["GHSA-p77j-4mvh-x3m3"],
  "summary": "legacy CVE entry, GIT-only ranges",
  "affected": [
    {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}]}]}
  ]
}`

const advisoryGHSAMirrorDoc = `{
  "id": "GHSA-p77j-4mvh-x3m3",
  "aliases": ["CVE-2099-0001", "GO-2099-0001"],
  "summary": "GHSA mirror without affected entries"
}`

func TestAdvisoryAliasChainResolvesUsableDoc(t *testing.T) {
	store := t.TempDir()
	writeOSV := func(name, body string) {
		if err := os.WriteFile(filepath.Join(store, name), []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	writeOSV("CVE-2099-0001.json", advisoryCVEGITDoc)
	writeOSV("GHSA-p77j-4mvh-x3m3.json", advisoryGHSAMirrorDoc)
	writeOSV("GO-2099-0001.json", advisoryOSVDoc)
	writeOSV("CVE-2099-7777.json", `{"id":"CVE-2099-7777","affected":[{"package":{"name":"example.org/library/parser","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)

	freezeDir := t.TempDir()
	p := advisoryProposal("CVE-2099-0001")
	p.Package = "example.org/library/parser"
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  p,
		FrozenDir: store,
	}, freezeDir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.ResolvedID != "GO-2099-0001" || res.Record.Source != vulnerability.AdvisoryFrozenOSV {
		t.Fatalf("record: %+v", res.Record)
	}
	if len(res.Projection.AffectedVersions) == 0 || res.Projection.AffectedVersions[0].Fixed != "1.4.3" {
		t.Fatalf("projection must carry the GO doc's ranges: %+v", res.Projection)
	}
	var aliasLim bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "GO-2099-0001") {
			aliasLim = true
		}
	}
	if !aliasLim {
		t.Fatalf("alias resolution must surface a limitation: %+v", res.Limitations)
	}
	// Only the selected document is frozen — the superseded CVE doc must
	// not appear in the run's freeze output.
	entries, _ := os.ReadDir(freezeDir)
	var docs int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && !strings.HasSuffix(e.Name(), ".freeze.json") {
			docs++
			if e.Name() != "GO-2099-0001.json" {
				t.Fatalf("unexpected frozen doc %s", e.Name())
			}
		}
	}
	if docs != 1 {
		t.Fatalf("exactly one advisory must be frozen, got %d", docs)
	}
}

func TestAdvisoryAliasChainPrefersIntakePackage(t *testing.T) {
	store := t.TempDir()
	writeOSV := func(name, body string) {
		if err := os.WriteFile(filepath.Join(store, name), []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	writeOSV("CVE-2099-0001.json", advisoryCVEGITDoc)
	writeOSV("GHSA-p77j-4mvh-x3m3.json", `{"id":"GHSA-p77j-4mvh-x3m3","aliases":["GO-2099-0001","GO-2099-0002"]}`)
	writeOSV("GO-2099-0001.json", advisoryOSVDoc) // example.org/library/parser
	writeOSV("GO-2099-0002.json", `{"id":"GO-2099-0002","affected":[{"package":{"name":"example.org/library/other","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.1"}]}]}]}`)

	p := advisoryProposal("CVE-2099-0001")
	p.Package = "example.org/library/other"
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  p,
		FrozenDir: store,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.ResolvedID != "GO-2099-0002" {
		t.Fatalf("package-matching alias must win: %+v", res.Record)
	}
}

func TestAdvisoryAliasChainNoUsableDoc(t *testing.T) {
	store := t.TempDir()
	writeOSV := func(name, body string) {
		if err := os.WriteFile(filepath.Join(store, name), []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	writeOSV("CVE-2099-0001.json", advisoryCVEGITDoc)
	writeOSV("GHSA-p77j-4mvh-x3m3.json", advisoryGHSAMirrorDoc)

	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  advisoryProposal("CVE-2099-0001"),
		FrozenDir: store,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Vulnerability.ID != "CVE-2099-0001" {
		t.Fatalf("no usable alias doc keeps the original selection: %+v", res.Vulnerability)
	}
	if !res.Partial {
		t.Fatal("an advisory without usable package ranges must be marked partial")
	}
	var lim bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "ranges") || strings.Contains(l, "partial") {
			lim = true
		}
	}
	if !lim {
		t.Fatalf("unusable advisory must produce a limitation: %+v", res.Limitations)
	}
}

func TestAdvisoryTicketPartialProjection(t *testing.T) {
	raw := advisoryRawIntake(t, `{
		"vulnerability": "CVE-2099-0001",
		"aliases": ["GHSA-abcd-efgh-ijkl"],
		"summary": "parser overflow per vendor bulletin"
	}`)
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal: IntakeProposal{
			SchemaVersion:    IntakeProposalSchemaVersion,
			VulnerabilityIDs: []string{"CVE-2099-0001"},
			Aliases:          []string{"GHSA-abcd-efgh-ijkl"},
		},
		Raw:       raw,
		FrozenDir: t.TempDir(),
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.Source != vulnerability.AdvisoryTicket {
		t.Fatalf("ticket projection source = %q", res.Record.Source)
	}
	if !res.Partial {
		t.Fatal("ticket-derived projection without an embedded document is partial")
	}
	if res.Vulnerability.Aliases[0] != "GHSA-abcd-efgh-ijkl" {
		t.Fatalf("aliases must carry into the projection: %+v", res.Vulnerability)
	}
}

func TestAdvisoryWeakTicketProjectionResolves(t *testing.T) {
	// Ticket-only run: the intake projection carries no package-scoped
	// ranges and no lane/alias yields a usable document, yet the run must
	// keep an advisory — the weak ticket projection resolves as partial.
	raw := advisoryRawIntake(t, `{
		"vulnerability": "CVE-2099-0001",
		"aliases": ["GHSA-abcd-efgh-ijkl"],
		"summary": "parser overflow per vendor bulletin",
		"severity": "high"
	}`)
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(true), AdvisoryInput{
		Proposal: IntakeProposal{
			SchemaVersion:    IntakeProposalSchemaVersion,
			VulnerabilityIDs: []string{"CVE-2099-0001"},
			Aliases:          []string{"GHSA-abcd-efgh-ijkl"},
			Severity:         "high",
		},
		Raw:       raw,
		FrozenDir: t.TempDir(),
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Vulnerability == nil || res.Vulnerability.ID != "CVE-2099-0001" {
		t.Fatalf("weak projection must resolve the advisory identity: %+v", res.Vulnerability)
	}
	if !res.Partial || !res.Record.Partial || res.Record.Source != vulnerability.AdvisoryTicket {
		t.Fatalf("weak resolution must stay partial and ticket-sourced: %+v", res.Record)
	}
	if res.Record.SHA256 == "" {
		t.Fatal("weak resolution must still pin the frozen bytes hash")
	}
	if !strings.EqualFold(res.Vulnerability.BaseSeverity, "high") {
		t.Fatalf("baseline severity must survive on the projection: %+v", res.Vulnerability)
	}
	var lim bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "partial") {
			lim = true
		}
	}
	if !lim {
		t.Fatalf("weak advisory resolution must record a limitation: %+v", res.Limitations)
	}
}

func TestAdvisoryProjectionCarriesSymbols(t *testing.T) {
	// OSV Go records declare vulnerable symbols under
	// affected[].ecosystem_specific.imports[].symbols; the projection the
	// checks and the agent payload consume must carry them.
	store := t.TempDir()
	doc := `{
	  "id": "GO-2099-0001",
	  "aliases": ["CVE-2099-0001"],
	  "affected": [{
	    "package": {"name": "example.org/library/parser", "ecosystem": "Go"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.3"}]}],
	    "ecosystem_specific": {"imports": [
	      {"path": "example.org/library/parser", "symbols": ["Parse", "parseFrame", "New"]},
	      {"path": "example.org/library/parser/sub", "symbols": ["Handle"]}
	    ]}
	  }]
	}`
	if err := os.WriteFile(filepath.Join(store, "GO-2099-0001.json"), []byte(doc), 0o444); err != nil {
		t.Fatal(err)
	}
	res, err := ResolveAdvisory(context.Background(), advisoryTestConfig(false), AdvisoryInput{
		Proposal:  advisoryProposal("CVE-2099-0001"),
		FrozenDir: store,
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	syms := res.Projection.AffectedSymbols
	if len(syms) != 4 {
		t.Fatalf("projection symbols = %+v, want 4", syms)
	}
	if syms[0].Symbol != "Parse" || syms[1].Symbol != "parseFrame" || syms[2].Symbol != "New" ||
		syms[0].Package != "example.org/library/parser" {
		t.Fatalf("symbol order must be document order: %+v", syms)
	}
	if syms[3].Package != "example.org/library/parser/sub" || syms[3].Symbol != "Handle" {
		t.Fatalf("second import path must carry its symbols: %+v", syms)
	}
}

func TestAdvisoryLookupExposesSymbols(t *testing.T) {
	proj := &AdvisoryProjection{
		Module: "example.org/library/parser",
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.org/library/parser", Symbol: "Parse"},
			{Package: "example.org/library/parser/sub", Symbol: "Handle"},
		},
	}
	rt := ReadOnlyTools{Advisory: proj}
	obs := callTool(t, &rt, context.Background(), "lookup_advisory", map[string]any{})
	if obs.Status != ToolStatusOK {
		t.Fatalf("status = %q", obs.Status)
	}
	d := obsData(t, obs)
	if d["symbols_available"] != true {
		t.Fatalf("symbols_available = %v", d["symbols_available"])
	}
	syms, ok := d["affected_symbols"].([]any)
	if !ok || len(syms) != 2 {
		t.Fatalf("affected_symbols = %v", d["affected_symbols"])
	}
	first := syms[0].(map[string]any)
	if first["package"] != "example.org/library/parser" || first["symbol"] != "Parse" {
		t.Fatalf("symbol entry = %v", first)
	}
	paths, ok := d["affected_import_paths"].(map[string]any)
	if !ok || len(paths["example.org/library/parser"].([]any)) != 1 ||
		len(paths["example.org/library/parser/sub"].([]any)) != 1 {
		t.Fatalf("affected_import_paths = %v", d["affected_import_paths"])
	}
}

func TestAdvisoryLookupWithoutSymbolsReportsLimitation(t *testing.T) {
	rt := ReadOnlyTools{} // no advisory projection: symbols unavailable
	obs := callTool(t, &rt, context.Background(), "lookup_advisory", map[string]any{})
	if obs.Status != ToolStatusOK {
		t.Fatalf("status = %q", obs.Status)
	}
	d := obsData(t, obs)
	if d["symbols_available"] != false {
		t.Fatalf("symbols_available = %v", d["symbols_available"])
	}
	if _, present := d["affected_symbols"]; !present {
		t.Fatal("affected_symbols field must be present even when empty")
	}
	var lim bool
	for _, l := range obs.Limitations {
		if strings.Contains(l, "vulnerable symbols") {
			lim = true
		}
	}
	if !lim {
		t.Fatalf("absent symbols must produce a limitation: %v", obs.Limitations)
	}
}
