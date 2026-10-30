package research

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/advfeed"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// writeFeedDir builds a synthetic offline dump directory.
func writeFeedDir(t *testing.T, docs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range docs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func feedOptions(dir string) *advfeed.Options {
	return &advfeed.Options{LocalPath: dir, Ecosystem: advfeed.EcosystemGo}
}

// A module-only frozen advisory (no ecosystem_specific.imports) is
// completed from the alias record in the dump: the lane mints real
// package/symbol subjects, the impl record is filled, and the report
// input carries the feed provenance (alias id + dump sha256).
func TestAdvisoryFeedCompletesImportsFromAlias(t *testing.T) {
	feedDir := writeFeedDir(t, map[string]string{
		"GO-FEED-9001.json": `{
		  "id": "GO-FEED-9001",
		  "aliases": ["GHSA-feed-0001"],
		  "affected": [{
		    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
		    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
		    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
		  }]
		}`,
	})
	advisory := `{
	  "id": "GHSA-feed-0001",
	  "aliases": ["GO-FEED-9001"],
	  "summary": "module-only advisory completed via alias",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
	  }]
	}`
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GHSA-feed-0001", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: filepath.Join(dir, "out"), ExternalCommitSHA: "feed-sha-1",
		Timeout:      60 * time.Second,
		AdvisoryFeed: feedOptions(feedDir),
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	fr := lane.Advisory.Input.FeedResolution
	if fr == nil || fr.Status != advfeed.StatusResolved {
		t.Fatalf("feed_resolution = %+v", fr)
	}
	if len(fr.SourceIDs) != 1 || fr.SourceIDs[0] != "GO-FEED-9001" {
		t.Fatalf("source_ids = %v", fr.SourceIDs)
	}
	if fr.DumpSHA256 == "" || fr.FeedRef == "" {
		t.Fatalf("provenance incomplete: %+v", fr)
	}
	// The impl record carries the completed subjects.
	im := lane.Advisory.Impls[0]
	if im.Package == nil || *im.Package != "example.com/snapdep/vuln" {
		t.Fatalf("impl package = %v", im.Package)
	}
	if len(im.Symbols) != 1 || im.Symbols[0] != "Parse" {
		t.Fatalf("impl symbols = %v", im.Symbols)
	}
	// The domain vulnerability the lane probes gained the same subjects.
	am := lane.Advisory.Vuln.AffectedModules[0]
	if len(am.AffectedPackages) != 1 || am.AffectedPackages[0].Path != "example.com/snapdep/vuln" {
		t.Fatalf("vuln affected packages = %+v", am.AffectedPackages)
	}
	if len(am.AffectedSymbols) != 1 || am.AffectedSymbols[0].Symbol != "Parse" {
		t.Fatalf("vuln affected symbols = %+v", am.AffectedSymbols)
	}
	// The lane minted the bounded checks the frozen file alone could not.
	usageCalls := 0
	for _, rec := range lane.Records {
		if rec.Tool == evidencetools.PackageUsageTool {
			pkg, sym := usageArgsOf(rec)
			if pkg == "example.com/snapdep/vuln" && sym == "Parse" {
				usageCalls++
			}
		}
	}
	if usageCalls == 0 {
		t.Fatal("no package-usage check ran for the feed-completed symbol")
	}
	foundSymbol := false
	for _, o := range lane.Observations {
		if o.Tool == "find_symbol" && o.ToolStatus == evidencetools.StatusOK && strings.Contains(o.Fact, "Parse") {
			foundSymbol = true
		}
	}
	if !foundSymbol {
		t.Fatal("find_symbol never ran for the feed-completed symbol")
	}
	// The report assembles and validates with the feed provenance block.
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "feed-complete",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, filepath.Join(dir, "out")); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// An advisory that already declares imports is never touched by the
// feed: status is not_required and no subjects change.
func TestAdvisoryFeedKeepsDeclaredImports(t *testing.T) {
	feedDir := writeFeedDir(t, map[string]string{
		"GO-FEED-9002.json": `{
		  "id": "GO-FEED-9002", "aliases": ["GO-TEST-0002"],
		  "affected": [{
		    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
		    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/OTHER", "symbols": ["Fake"]}]}
		  }]
		}`,
	})
	advisory := `{
	  "id": "GO-TEST-0002",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }]
	}`
	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GO-TEST-0002", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: filepath.Join(dir, "out"), ExternalCommitSHA: "feed-sha-2",
		Timeout:      60 * time.Second,
		AdvisoryFeed: feedOptions(feedDir),
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	fr := lane.Advisory.Input.FeedResolution
	if fr == nil || fr.Status != advfeed.StatusNotRequired {
		t.Fatalf("feed_resolution = %+v, want not_required", fr)
	}
	im := lane.Advisory.Impls[0]
	if im.Package == nil || *im.Package != "example.com/snapdep/vuln" {
		t.Fatalf("declared package overridden: %v", im.Package)
	}
	for _, s := range im.Symbols {
		if s == "Fake" {
			t.Fatalf("feed symbol leaked into a declared advisory: %v", im.Symbols)
		}
	}
}

// A feed that cannot supply the subjects (alias record carries no
// imports) leaves the module-only binding untouched and records the
// named reason ADVISORY_IMPORTS_UNAVAILABLE — and the assembled report
// keeps the existing UNKNOWN, now carrying the named reason.
func TestAdvisoryFeedUnresolvedKeepsUnknown(t *testing.T) {
	feedDir := writeFeedDir(t, map[string]string{
		// Alias record exists but declares no imports for the module.
		"GO-FEED-9003.json": `{
		  "id": "GO-FEED-9003", "aliases": ["GHSA-feed-9003"],
		  "affected": [{"package": {"ecosystem": "Go", "name": "example.com/snapdep"},
		    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
		}`,
	})
	advisory := `{
	  "id": "GHSA-feed-9003",
	  "aliases": ["GO-FEED-9003"],
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
	  }]
	}`
	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GHSA-feed-9003", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: filepath.Join(dir, "out"), ExternalCommitSHA: "feed-sha-3",
		Timeout:      60 * time.Second,
		AdvisoryFeed: feedOptions(feedDir),
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	fr := lane.Advisory.Input.FeedResolution
	if fr == nil || fr.Reason != ReasonAdvisoryImportsUnavailable {
		t.Fatalf("feed_resolution = %+v", fr)
	}
	if fr.Status != advfeed.StatusNoImports {
		t.Fatalf("status = %q, want no_imports", fr.Status)
	}
	// No subjects were invented: no package-usage check ran.
	for _, rec := range lane.Records {
		if rec.Tool == evidencetools.PackageUsageTool {
			t.Fatalf("package-usage check ran on unresolved advisory: %s", rec.Args)
		}
	}
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "feed-unresolved",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	var unknown *UnknownEntry
	for i := range r.Unknowns {
		if strings.Contains(r.Unknowns[i].Statement, "no package or symbol identifies a package-level subject") {
			unknown = &r.Unknowns[i]
		}
	}
	if unknown == nil {
		t.Fatal("module-only unknown missing")
	}
	if !strings.Contains(unknown.Reason, ReasonAdvisoryImportsUnavailable) {
		t.Fatalf("unknown lacks the named reason: %q", unknown.Reason)
	}
	if err := Validate(r, filepath.Join(dir, "out")); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
}

// With no feed configured the advisory input carries no feed_resolution
// member at all — the legacy wire shape is untouched.
func TestAdvisoryFeedAbsentWithoutConfig(t *testing.T) {
	in := AdvisoryInput{RequestedID: "X", ResolvedID: "X"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "feed_resolution") {
		t.Fatalf("feed_resolution leaked into an unconfigured report: %s", b)
	}
}

func TestExactRecordIntakeRejectsFeedEnrichment(t *testing.T) {
	dir := writeFeedDir(t, map[string]string{"GO-EXACT.json": `{"id":"GO-EXACT","affected":[{"package":{"ecosystem":"Go","name":"example.com/m"}}]}`})
	for _, options := range []LaneOptions{
		{RequestContract: true}, {RecordOnly: true}, {Corpus: &advfeed.CorpusOptions{}},
	} {
		options.CVE = "GO-EXACT"
		options.AdvisoryFile = filepath.Join(dir, "GO-EXACT.json")
		options.AdvisoryFeed = feedOptions("missing-feed-must-not-be-consulted")
		record, err := loadFrozenAdvisory(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		if record.Input.FeedResolution != nil || len(record.Vuln.AffectedSymbols) != 0 {
			t.Fatal("exact-record assessment consulted feed enrichment")
		}
	}
}
