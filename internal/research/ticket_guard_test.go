package research

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

// writeTicket writes a tracker ticket document (JSON or plain text)
// for the lane tests.
func writeTicket(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureLaneOpts runs the real lane over evidencesnap with extra
// options (ticket/release metadata) — the same harness runFixtureLane
// uses, widened for the optional channels.
func fixtureLaneOpts(t *testing.T, advisory string, mutate func(*LaneOptions)) (*LaneResult, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	o := LaneOptions{
		CVE: "GO-TEST-0002", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-2",
		Timeout: 60 * time.Second,
	}
	if mutate != nil {
		mutate(&o)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, o)
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	return lane, out
}

// fixedRangeAdvisory resolves evidencesnap's snapdep v1.0.0 OUTSIDE its
// affected ranges — today's out-of-range closing.
const fixedRangeAdvisory = `{
  "id": "GO-TEST-0002",
  "summary": "fixed-version fixture advisory",
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.9.9"}]}],
    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
  }],
  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
}`

// The case-03/case-04 shape end to end: the ticket declares snapdep
// 0.5.0 (inside the advisory range) while the analyzed build resolves
// v1.0.0 (outside it). The out-of-range negative must be refused — the
// report blocks the version axis with the named reason, both versions,
// and no FIXED entry status.
func TestLaneTicketPackageMismatchBlocks(t *testing.T) {
	dir := t.TempDir()
	ticket := writeTicket(t, dir, "ticket.json", `{
	  "id": "CASE-227168",
	  "vulnerability": "GO-TEST-0002", "aliases": ["GO-2026-4526"],
	  "component": "DEMO",
	  "product": "Demo Mesh", "release": "Demo Mesh 1.10.3",
	  "package": "example.com/snapdep", "version": "0.5.0",
	  "distribution_url": "https://user:secret@portal.example.org/_DEMO/1.10.3-1919/_DEMO-1.10.3-1919-distrib.zip?token=secret"
	}`)
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.Ticket = ticket
	})
	ar := lane.Affected
	if !ar.VersionAxisBlocked {
		t.Fatalf("version axis not blocked: %+v", ar)
	}
	if ar.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("VersionAffected=%s, want UNKNOWN", ar.VersionAffected)
	}
	if ar.ModulePresent != domain.ClaimTrue {
		t.Fatalf("ModulePresent=%s, want TRUE", ar.ModulePresent)
	}
	if ar.PackagePresent == domain.ClaimFalse || ar.BuildRelevant == domain.ClaimFalse {
		t.Fatalf("blocked path must not assert package/build absence: %+v", ar)
	}
	if ar.TicketCheck == nil ||
		ar.TicketCheck.PackageVersionCheck != domain.TicketCheckMismatch ||
		ar.TicketCheck.DeclaredVersion != "0.5.0" || ar.TicketCheck.ResolvedVersion != "v1.0.0" {
		t.Fatalf("ticket check %+v, want MISMATCH 0.5.0 vs v1.0.0", ar.TicketCheck)
	}
	if lane.Ticket == nil || lane.Ticket.SHA256 == "" || lane.Ticket.Claims == nil {
		t.Fatalf("ticket channel record %+v", lane.Ticket)
	}
	// The deterministic decision can never promote a blocked axis: the
	// only route to a terminal verdict stays the FALSE axes.
	if d, ok := laneApplicabilityDecision(lane); ok {
		t.Fatalf("blocked lane yielded a terminal applicability decision: %+v", d)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "ticket-block",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	pa := r.ProductApplicability
	if !pa.VersionAxisBlocked || pa.VersionAxisBlockReason != domain.TicketReasonPackageVersionMismatch {
		t.Fatalf("report block fields: %+v", pa)
	}
	if pa.VersionAffected == "FALSE" || pa.AdvisoryEntryStatus == EntryFixed {
		t.Fatalf("blocked run produced a negative: %+v", pa)
	}
	if pa.AdvisoryEntryStatus != EntryUnknown {
		t.Fatalf("advisory_entry_status=%q, want UNKNOWN under the refusal", pa.AdvisoryEntryStatus)
	}
	if r.Input.Ticket == nil || r.Input.Ticket.Claims == nil ||
		r.Input.Ticket.Claims.PackageVersion != "0.5.0" {
		t.Fatalf("input.ticket %+v", r.Input.Ticket)
	}
	if r.Input.Ticket.DistributionURL != "https://portal.example.org/_DEMO/1.10.3-1919/_DEMO-1.10.3-1919-distrib.zip" {
		t.Fatalf("input.ticket distribution locator = %q", r.Input.Ticket.DistributionURL)
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	text := string(md)
	for _, want := range []string{
		"ticket distribution locator (recorded, not fetched)",
		"provide/acquire the exact ticket distribution",
		"--artifact",
		"--artifact-url",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("report missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "secret") {
		t.Fatal("report leaked distribution credentials")
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("blocked report invalid:\n%v", err)
	}
	// The decision route never sees a NOT_AFFECTED candidate.
	if d, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane}); err != nil || d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("blocked lane decision = %+v err %v, want INCONCLUSIVE", d, err)
	}
}

// The real tracker text shape (case-03, single line): the product
// version blob, the component label, the library line carrying its
// version inline, and the self-contained PURL. The intake must yield
// exactly the package axis the JSON form does — the version-label
// regex may not hijack "Версия продукта:".
func TestLaneTicketTextPackageMismatchBlocks(t *testing.T) {
	dir := t.TempDir()
	ticket := writeTicket(t, dir, "ticket.txt",
		`Новая потенциальная уязвимость в Demo Mesh 1.10.3
Версия продукта: Demo Mesh 1.10.3 Тип версии продукта: HOTFIX Ссылка на дистрибутив: https://example.invalid/_DEMO-1.10.3-1919-distrib.zip Компонент: DEMO 1.1.1-2397 Библиотека: example.com/snapdep 0.5.0 PURL: pkg:golang/example.com/snapdep@0.5.0 Алиасы на уязвимость: GO-2026-4526, CVE-2026-32287 Описание уязвимости: overflow in Parse
`)
	lane, _ := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.Ticket = ticket
	})
	if lane.Ticket == nil || lane.Ticket.Claims == nil {
		t.Fatalf("text ticket record %+v", lane.Ticket)
	}
	claims := lane.Ticket.Claims
	if claims.Package != "example.com/snapdep" || claims.PackageVersion != "0.5.0" {
		t.Fatalf("text intake claims %+v, want snapdep 0.5.0", claims)
	}
	if claims.Component != "DEMO 1.1.1-2397" ||
		claims.ProductVersion != "Demo Mesh 1.10.3" {
		t.Fatalf("text intake leaked labels into claims %+v", claims)
	}
	ar := lane.Affected
	if !ar.VersionAxisBlocked || ar.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("text ticket must block the version axis: %+v", ar)
	}
	if ar.TicketCheck == nil || ar.TicketCheck.PackageVersionCheck != domain.TicketCheckMismatch ||
		ar.TicketCheck.DeclaredVersion != "0.5.0" {
		t.Fatalf("text ticket check %+v", ar.TicketCheck)
	}
}

// The logrus control shape as text: "Библиотека: <module> v1.0.0"
// carries the matching resolved version and "Версия продукта:" must
// not steal it — the closing stands.
func TestLaneTicketTextMatchingVersionKeepsClosing(t *testing.T) {
	dir := t.TempDir()
	ticket := writeTicket(t, dir, "ticket.txt",
		`Новая потенциальная уязвимость GO-2026-7777 в Demo Platform DEMO 6.2.0
Версия продукта: Demo Platform DEMO 6.2.0
Компонент: DEMO-CORE
Библиотека: example.com/snapdep v1.0.0
`)
	lane, _ := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.Ticket = ticket
	})
	if lane.Ticket == nil || lane.Ticket.Claims == nil {
		t.Fatalf("text ticket record %+v", lane.Ticket)
	}
	claims := lane.Ticket.Claims
	if claims.Package != "example.com/snapdep" || claims.PackageVersion != "v1.0.0" {
		t.Fatalf("text intake claims %+v, want snapdep v1.0.0", claims)
	}
	if claims.ProductVersion != "Demo Platform DEMO 6.2.0" || claims.Component != "DEMO-CORE" {
		t.Fatalf("text intake leaked labels into claims %+v", claims)
	}
	ar := lane.Affected
	if ar.VersionAxisBlocked || ar.VersionAffected != domain.ClaimFalse {
		t.Fatalf("matching text ticket changed the closing: %+v", ar)
	}
	if ar.TicketCheck == nil || ar.TicketCheck.PackageVersionCheck != domain.TicketCheckMatch {
		t.Fatalf("text ticket check %+v, want MATCH", ar.TicketCheck)
	}
	if d, ok := laneApplicabilityDecision(lane); !ok || d.Verdict != domain.VerdictNotAffected {
		t.Fatalf("matching version must keep the deterministic NOT_AFFECTED: %+v", d)
	}
}

// Control: the same lane with the ticket declaring exactly the resolved
// version keeps today's out-of-range closing — including the FIXED
// entry status and the supporting outside-range statement.
func TestLaneTicketMatchingVersionKeepsClosing(t *testing.T) {
	dir := t.TempDir()
	ticket := writeTicket(t, dir, "ticket.json", `{
	  "vulnerability": "GO-TEST-0002", "aliases": ["GO-TEST-0002"],
	  "package": "example.com/snapdep", "version": "1.0.0"
	}`)
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.Ticket = ticket
	})
	ar := lane.Affected
	if ar.VersionAxisBlocked || ar.VersionAffected != domain.ClaimFalse {
		t.Fatalf("matching version changed the closing: %+v", ar)
	}
	if ar.TicketCheck == nil || ar.TicketCheck.PackageVersionCheck != domain.TicketCheckMatch {
		t.Fatalf("package axis %+v, want MATCH", ar.TicketCheck)
	}
	if ar.TicketCheck.DeclaredVersionInRanges == nil || *ar.TicketCheck.DeclaredVersionInRanges {
		t.Fatalf("declared 1.0.0 must be reported outside the advisory range: %+v", ar.TicketCheck)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "ticket-match",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.ProductApplicability.VersionAffected != "FALSE" ||
		r.ProductApplicability.AdvisoryEntryStatus != EntryFixed {
		t.Fatalf("matching-version report changed: %+v", r.ProductApplicability)
	}
	// The deterministic negative still stands: same closing as today.
	if d, ok := laneApplicabilityDecision(lane); !ok || d.Verdict != domain.VerdictNotAffected {
		t.Fatalf("matching version must keep the deterministic NOT_AFFECTED: %+v", d)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("matching-version report invalid:\n%v", err)
	}
}

// The case-14/case-18 shape: product drift alone (DEMO 6.5.2 vs the
// analyzed 6.5.0 supplied by release metadata) with an identical
// package version — ANALYZED_BUILD_MISMATCH is recorded, the closing
// stands, the version axis is not blocked.
func TestLaneTicketProductDriftKeepsClosing(t *testing.T) {
	dir := t.TempDir()
	ticket := writeTicket(t, dir, "ticket.json", `{
	  "vulnerability": "GO-TEST-0002",
	  "product": "DEMO", "release": "DEMO 6.5.2",
	  "package": "example.com/snapdep", "version": "1.0.0"
	}`)
	meta := filepath.Join(dir, "release.json")
	if err := os.WriteFile(meta, []byte(`{"schema":"release-metadata/1",
	  "modules":[
	    {"path":"example.com/evidencesnap","version":"v6.5.0"},
	    {"path":"example.com/snapdep","version":"v1.0.0"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.Ticket = ticket
		o.ReleaseMetadata = meta
	})
	ar := lane.Affected
	if ar.VersionAxisBlocked || ar.VersionAffected != domain.ClaimFalse {
		t.Fatalf("product drift must not block or change the closing: %+v", ar)
	}
	tc := ar.TicketCheck
	if tc == nil || tc.ProductVersionCheck != domain.TicketCheckMismatch {
		t.Fatalf("product axis %+v, want MISMATCH", tc)
	}
	if tc.PackageVersionCheck != domain.TicketCheckMatch {
		t.Fatalf("package axis %+v, want MATCH", tc)
	}
	foundReason := false
	for _, r := range tc.Reasons {
		if r == domain.TicketReasonAnalyzedBuildMismatch {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("reason %s missing: %+v", domain.TicketReasonAnalyzedBuildMismatch, tc.Reasons)
	}
	joined := strings.Join(ar.Limitations, "\n")
	if !strings.Contains(joined, domain.TicketReasonAnalyzedBuildMismatch) ||
		!strings.Contains(joined, "6.5.2") || !strings.Contains(joined, "v6.5.0") {
		t.Fatalf("informational limitation must name both versions: %v", ar.Limitations)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "ticket-drift",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.ProductApplicability.AdvisoryEntryStatus != EntryFixed {
		t.Fatalf("drift changed the closing: %+v", r.ProductApplicability)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("drift report invalid:\n%v", err)
	}
}

// An unparsable ticket file: the channel record carries the parse
// error, the check degrades to NOT_CHECKED with the named reason, and
// the unaffected closing stands — never a silent pass, never a failure.
func TestLaneTicketInvalid(t *testing.T) {
	dir := t.TempDir()
	bad := writeTicket(t, dir, "ticket.json", `{not json`)
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.Ticket = bad
	})
	if lane.Ticket == nil || lane.Ticket.ParseError != domain.TicketReasonInvalid ||
		lane.Ticket.Claims != nil {
		t.Fatalf("malformed ticket record %+v", lane.Ticket)
	}
	ar := lane.Affected
	if ar.VersionAxisBlocked || ar.VersionAffected != domain.ClaimFalse {
		t.Fatalf("malformed ticket changed the closing: %+v", ar)
	}
	if ar.TicketCheck == nil || ar.TicketCheck.ParseError != domain.TicketReasonInvalid ||
		ar.TicketCheck.PackageVersionCheck != domain.TicketCheckNotChecked {
		t.Fatalf("check %+v, want NOT_CHECKED + TICKET_INVALID", ar.TicketCheck)
	}
	found := false
	for _, o := range lane.Observations {
		if o.Tool == "ticket-load" {
			found = true
			if o.ToolStatus != "OK" || o.Completeness != "PARTIAL" {
				t.Fatalf("ticket-load observation %+v", o)
			}
		}
	}
	if !found {
		t.Fatal("no ticket-load observation recorded")
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "ticket-bad",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Input.Ticket == nil || r.Input.Ticket.ParseError == "" {
		t.Fatalf("input record %+v", r.Input.Ticket)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("malformed-ticket report invalid:\n%v", err)
	}
}

// No ticket: the lane and report are byte-identical to today —
// no input block, no check, no blocked flag anywhere on the wire.
func TestLaneNoTicketUnchanged(t *testing.T) {
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, nil)
	if lane.Ticket != nil || lane.Affected.TicketCheck != nil {
		t.Fatalf("no-ticket lane carries ticket state: %+v", lane.Affected)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "ticket-none",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Input.Ticket != nil || r.ProductApplicability.TicketCheck != nil ||
		r.ProductApplicability.VersionAxisBlocked || r.ProductApplicability.VersionAxisBlockReason != "" {
		t.Fatalf("no-ticket report carries ticket members: %+v", r.ProductApplicability)
	}
	jb, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"ticket"`, `"ticket_check"`, `"version_axis_blocked"`, `"version_axis_block_reason"`} {
		if strings.Contains(string(jb), key) {
			t.Fatalf("legacy wire shape carries %s", key)
		}
	}
	if r.ProductApplicability.AdvisoryEntryStatus != EntryFixed {
		t.Fatalf("no-ticket closing changed: %+v", r.ProductApplicability)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("no-ticket report invalid:\n%v", err)
	}
}

// entryStatus must never label a refused entry "fixed": the blocked
// module reads "unknown" while unaffected checked entries still read
// "fixed" — the per-entry split stays honest under a partial refusal.
func TestEntryStatusBlockedModule(t *testing.T) {
	pa := ProductApplicability{
		ModulePresent: "TRUE", VersionAffected: "UNKNOWN",
		CheckedModules: []string{"example.com/a", "example.com/b"},
		TicketCheck: &domain.TicketCheck{
			PackageVersionCheck: domain.TicketCheckMismatch,
			BlockedModules:      []string{"example.com/a"},
		},
	}
	if st := entryStatus(AffectedImplementation{Ecosystem: "Go", Module: "example.com/a"}, pa); st != "unknown" {
		t.Fatalf("blocked entry status=%q, want unknown", st)
	}
	if st := entryStatus(AffectedImplementation{Ecosystem: "Go", Module: "example.com/b"}, pa); st != "fixed" {
		t.Fatalf("checked entry status=%q, want fixed", st)
	}
}
