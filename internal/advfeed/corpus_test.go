package advfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

func corpusDocJSON(t *testing.T, id, summary string, aliases, related, modules []string) string {
	t.Helper()
	affected := make([]map[string]any, 0, len(modules))
	for _, module := range modules {
		affected = append(affected, map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": module},
			"ranges": []any{map[string]any{
				"type": "SEMVER",
				"events": []any{
					map[string]any{"introduced": "0"},
					map[string]any{"fixed": "1.0.1"},
				},
			}},
			"ecosystem_specific": map[string]any{
				"imports": []any{map[string]any{"path": module + "/pkg", "symbols": []string{"F"}}},
			},
		})
	}
	doc := map[string]any{"id": id, "aliases": aliases, "related": related, "affected": affected}
	if summary != "" {
		doc["summary"] = summary
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func writeCorpusFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readAdvisoryFixture(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(body)
}

func acquireCorpusDir(t *testing.T, dir string, declaration *domain.CorpusDeclaration, selections []domain.RecordPin) *Corpus {
	t.Helper()
	corpus, err := AcquireCorpus(context.Background(), CorpusOptions{
		Feed:        Options{LocalPath: dir, Now: func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }},
		Declaration: declaration,
		Selections:  selections,
	})
	if err != nil {
		t.Fatalf("AcquireCorpus: %v", err)
	}
	return corpus
}

func corpusPin(t *testing.T, recordID string, body string, locator string) domain.RecordPin {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	return domain.RecordPin{
		RecordID:       recordID,
		DocumentDigest: "sha256:" + hex.EncodeToString(sum[:]),
		SourceLocator:  locator,
	}
}

func discoveredIDs(discovery domain.RelatedDiscovery) []string {
	ids := make([]string, 0, len(discovery.Candidates))
	for _, candidate := range discovery.Candidates {
		ids = append(ids, candidate.Record.RecordID)
	}
	sort.Strings(ids)
	return ids
}

func candidateByID(discovery domain.RelatedDiscovery, id string) *domain.DiscoveryCandidate {
	for i := range discovery.Candidates {
		if discovery.Candidates[i].Record.RecordID == id {
			return &discovery.Candidates[i]
		}
	}
	return nil
}

func hasDiscoveryEdge(candidate domain.DiscoveryCandidate, kind domain.RelationKind, id, from string) bool {
	for _, edge := range candidate.Edges {
		if edge.Kind == kind && edge.ID == id && edge.FromID == from {
			return true
		}
	}
	return false
}

func containsPin(pins []domain.RecordPin, pin domain.RecordPin) bool {
	for _, current := range pins {
		if current.Same(pin) {
			return true
		}
	}
	return false
}

func TestCorpusDiscovery(t *testing.T) {
	t.Run("inverse related lookup discovers grpc", func(t *testing.T) {
		primaryBody := readAdvisoryFixture(t, "../../eval/agent7/advisories/k8s-44487.json")
		grpcBody := readAdvisoryFixture(t, "../../eval/advisories/reviewed/GO-2023-2153.json")
		dir := writeCorpusFiles(t, map[string]string{
			"GHSA-qppj-fm5r-hxr3.json": primaryBody,
			"GO-2023-2153.json":        grpcBody,
			// Direct related of GO-2023-2153, two hops from the primary.
			"decoy-transitive.json": corpusDocJSON(t, "GO-9999-0001", "",
				nil, []string{"GO-2023-2153"}, []string{"example.com/decoy"}),
			// Same implementation module, but no identity relationship.
			"decoy-unrelated.json": corpusDocJSON(t, "GO-9999-0002", "",
				nil, nil, []string{"google.golang.org/grpc"}),
		})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		manifest := corpus.Manifest()
		if err := manifest.Validate(); err != nil {
			t.Fatalf("manifest: %v", err)
		}
		if manifest.Enumeration != domain.DiscoveryFinished {
			t.Fatalf("enumeration = %q, want finished", manifest.Enumeration)
		}
		if !strings.HasPrefix(manifest.ObservedDigest, "sha256:") {
			t.Fatalf("observed digest = %q", manifest.ObservedDigest)
		}
		if len(manifest.Documents) != 4 {
			t.Fatalf("documents = %d, want 4", len(manifest.Documents))
		}

		aliasPins := corpus.Lookup(RelationshipAlias, "CVE-2023-44487")
		if len(aliasPins) != 1 || aliasPins[0].RecordID != "GHSA-qppj-fm5r-hxr3" {
			t.Fatalf("alias(CVE) = %+v, want only the primary GHSA", aliasPins)
		}
		relatedPins := corpus.Lookup(RelationshipRelated, "CVE-2023-44487")
		if !containsPin(relatedPins, corpusPin(t, "GO-2023-2153", grpcBody, "corpus/GO-2023-2153.json")) {
			t.Fatalf("related(CVE) did not contain the inverse GO record: %+v", relatedPins)
		}
		if !containsPin(relatedPins, corpusPin(t, "GHSA-qppj-fm5r-hxr3", primaryBody, "corpus/GHSA-qppj-fm5r-hxr3.json")) {
			t.Fatalf("related(CVE) did not contain the primary's own related entry: %+v", relatedPins)
		}
		if recordPins := corpus.Lookup(RelationshipRecord, "CVE-2023-44487"); len(recordPins) != 0 {
			t.Fatalf("record(CVE) = %+v, want no document whose own id is the CVE", recordPins)
		}

		primary, err := vulnerability.LoadExactBytes([]byte(primaryBody), "GHSA-qppj-fm5r-hxr3", "corpus/GHSA-qppj-fm5r-hxr3.json")
		if err != nil {
			t.Fatal(err)
		}
		discovery := corpus.Discover("GHSA-qppj-fm5r-hxr3", &primary)
		if err := discovery.Validate(); err != nil {
			t.Fatalf("discovery: %v", err)
		}
		if discovery.Enumeration != domain.DiscoveryFinished || discovery.Corpus == nil {
			t.Fatalf("discovery enumeration/corpus = %q %+v", discovery.Enumeration, discovery.Corpus)
		}
		ids := discoveredIDs(discovery)
		if len(ids) != 1 || ids[0] != "GO-2023-2153" {
			t.Fatalf("discovered %v, want only GO-2023-2153", ids)
		}
		candidate := candidateByID(discovery, "GO-2023-2153")
		if candidate == nil {
			t.Fatal("GO-2023-2153 not nominated")
		}
		if candidate.Disposition != domain.DispositionNotEvaluated {
			t.Fatalf("disposition = %q", candidate.Disposition)
		}
		if !hasDiscoveryEdge(*candidate, domain.RelationRelated, "CVE-2023-44487", "GO-2023-2153") {
			t.Fatalf("candidate has no inverse related edge from its own field: %+v", candidate.Edges)
		}
		if !limitationContains(discovery, "no transitive related closure") {
			t.Fatalf("limitations = %v", discovery.Limitations)
		}
	})

	t.Run("exact request keeps every explicit cve seed", func(t *testing.T) {
		primaryBody := corpusDocJSON(t, "GHSA-seed-test-1234-5678", "",
			[]string{"CVE-2099-0001", "CVE-2099-0002", "BIT-golang-2099-0001"},
			[]string{"CVE-2099-0003"}, []string{"example.com/primary"})
		aliasDoc := corpusDocJSON(t, "GO-2099-1001", "", []string{"CVE-2099-0001"}, nil, []string{"example.com/a"})
		recordDoc := corpusDocJSON(t, "CVE-2099-0002", "", nil, nil, []string{"example.com/b"})
		relatedDoc := corpusDocJSON(t, "GO-2099-1003", "", nil, []string{"CVE-2099-0003"}, []string{"example.com/c"})
		dir := writeCorpusFiles(t, map[string]string{
			"primary.json": primaryBody,
			"alias.json":   aliasDoc,
			"record.json":  recordDoc,
			"related.json": relatedDoc,
		})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		primary, err := vulnerability.LoadExactBytes([]byte(primaryBody), "GHSA-seed-test-1234-5678", "corpus/primary.json")
		if err != nil {
			t.Fatal(err)
		}
		discovery := corpus.Discover("GHSA-seed-test-1234-5678", &primary)
		if err := discovery.Validate(); err != nil {
			t.Fatalf("discovery: %v", err)
		}
		ids := discoveredIDs(discovery)
		for _, want := range []string{"GO-2099-1001", "CVE-2099-0002", "GO-2099-1003"} {
			if !contains(ids, want) {
				t.Fatalf("discovered %v, missing %s", ids, want)
			}
		}
		aliasCandidate := candidateByID(discovery, "GO-2099-1001")
		if aliasCandidate == nil || !hasDiscoveryEdge(*aliasCandidate, domain.RelationAlias, "CVE-2099-0001", "GO-2099-1001") {
			t.Fatalf("alias seed was not retained: %+v", aliasCandidate)
		}
		recordCandidate := candidateByID(discovery, "CVE-2099-0002")
		if recordCandidate == nil || !hasDiscoveryEdge(*recordCandidate, domain.RelationRecord, "CVE-2099-0002", "CVE-2099-0002") {
			t.Fatalf("record seed was not retained: %+v", recordCandidate)
		}
		relatedCandidate := candidateByID(discovery, "GO-2099-1003")
		if relatedCandidate == nil || !hasDiscoveryEdge(*relatedCandidate, domain.RelationRelated, "CVE-2099-0003", "GO-2099-1003") {
			t.Fatalf("related seed was not retained: %+v", relatedCandidate)
		}
		// The seed's originating field is retained on the candidate.
		if !hasDiscoveryEdge(*aliasCandidate, domain.RelationAlias, "CVE-2099-0001", "GHSA-seed-test-1234-5678") {
			t.Fatalf("primary alias origin missing: %+v", aliasCandidate.Edges)
		}
		if !hasDiscoveryEdge(*relatedCandidate, domain.RelationRelated, "CVE-2099-0003", "GHSA-seed-test-1234-5678") {
			t.Fatalf("primary related origin missing: %+v", relatedCandidate.Edges)
		}
	})

	t.Run("cve requests use only the requested cve as a shared-key seed", func(t *testing.T) {
		primaryBody := corpusDocJSON(t, "GHSA-multi-cve-0000-0000", "",
			[]string{"CVE-2099-0011"}, []string{"CVE-2099-0012"}, []string{"example.com/primary"})
		aliasDoc := corpusDocJSON(t, "GO-2099-1100", "", []string{"CVE-2099-0011"}, nil, []string{"example.com/alias"})
		inverseDoc := corpusDocJSON(t, "GO-2099-1101", "", nil, []string{"CVE-2099-0011"}, []string{"example.com/inverse"})
		siblingOwned := corpusDocJSON(t, "CVE-2099-0012", "", nil, nil, []string{"example.com/sibling"})
		siblingRelatedOnly := corpusDocJSON(t, "GO-2099-1102", "", nil, []string{"CVE-2099-0012"}, []string{"example.com/sibling-rel"})
		dir := writeCorpusFiles(t, map[string]string{
			"primary.json":         primaryBody,
			"alias.json":           aliasDoc,
			"inverse.json":         inverseDoc,
			"sibling-owned.json":   siblingOwned,
			"sibling-related.json": siblingRelatedOnly,
		})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		primary, err := vulnerability.LoadExactBytes([]byte(primaryBody), "GHSA-multi-cve-0000-0000", "corpus/primary.json")
		if err != nil {
			t.Fatal(err)
		}
		discovery := corpus.Discover("CVE-2099-0011", &primary)
		if err := discovery.Validate(); err != nil {
			t.Fatalf("discovery: %v", err)
		}
		ids := discoveredIDs(discovery)
		for _, want := range []string{"GO-2099-1100", "GO-2099-1101", "CVE-2099-0012"} {
			if !contains(ids, want) {
				t.Fatalf("discovered %v, missing %s", ids, want)
			}
		}
		if contains(ids, "GO-2099-1102") {
			t.Fatalf("a sibling CVE's related entry was expanded transitively: %v", ids)
		}
	})

	t.Run("identical documents deduplicate", func(t *testing.T) {
		body := corpusDocJSON(t, "GO-2099-2000", "", []string{"CVE-2099-2000"}, nil, []string{"example.com/dup"})
		dir := writeCorpusFiles(t, map[string]string{
			"a/GO-2099-2000.json": body,
			"b/GO-2099-2000.json": body,
		})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		manifest := corpus.Manifest()
		if manifest.Enumeration != domain.DiscoveryFinished {
			t.Fatalf("enumeration = %q", manifest.Enumeration)
		}
		if len(manifest.Documents) != 1 {
			t.Fatalf("documents = %+v, want one deduplicated pin", manifest.Documents)
		}
		discovery := corpus.Discover("CVE-2099-2000", nil)
		if len(discovery.Candidates) != 1 {
			t.Fatalf("candidates = %+v, want one", discovery.Candidates)
		}
		if discovery.Candidates[0].Record.RecordID != "GO-2099-2000" {
			t.Fatalf("candidate = %+v", discovery.Candidates[0])
		}
		if err := discovery.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("conflicting bytes stay ambiguous unless selected", func(t *testing.T) {
		aBody := corpusDocJSON(t, "CVE-2099-3000", "first version", nil, nil, []string{"example.com/conflict"})
		bBody := corpusDocJSON(t, "CVE-2099-3000", "second version", nil, nil, []string{"example.com/conflict"})
		dir := writeCorpusFiles(t, map[string]string{
			"a/CVE-2099-3000.json": aBody,
			"b/CVE-2099-3000.json": bBody,
		})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		discovery := corpus.Discover("CVE-2099-3000", nil)
		if len(discovery.Candidates) != 2 {
			t.Fatalf("candidates = %+v, want two conflicting versions", discovery.Candidates)
		}
		for _, candidate := range discovery.Candidates {
			if candidate.Disposition != domain.DispositionAmbiguous {
				t.Fatalf("candidate %+v is not ambiguous", candidate)
			}
		}
		if !limitationContains(discovery, "conflicting document version") {
			t.Fatalf("limitations = %v", discovery.Limitations)
		}

		selected := corpusPin(t, "CVE-2099-3000", aBody, "corpus/a/CVE-2099-3000.json")
		selectedCorpus := acquireCorpusDir(t, dir, nil, []domain.RecordPin{selected})
		selectedDiscovery := selectedCorpus.Discover("CVE-2099-3000", nil)
		if len(selectedDiscovery.Candidates) != 1 {
			t.Fatalf("selected candidates = %+v, want one", selectedDiscovery.Candidates)
		}
		if selectedDiscovery.Candidates[0].Disposition != domain.DispositionNotEvaluated {
			t.Fatalf("selected disposition = %q", selectedDiscovery.Candidates[0].Disposition)
		}
		if !selectedDiscovery.Candidates[0].Record.Same(selected) {
			t.Fatalf("selected pin = %+v", selectedDiscovery.Candidates[0].Record)
		}

		missing := corpusPin(t, "CVE-2099-3000", "missing", "corpus/missing.json")
		missCorpus := acquireCorpusDir(t, dir, nil, []domain.RecordPin{missing})
		missDiscovery := missCorpus.Discover("CVE-2099-3000", nil)
		if !limitationContains(missDiscovery, "does not match an enumerated document") {
			t.Fatalf("limitations = %v", missDiscovery.Limitations)
		}

		if _, err := AcquireCorpus(context.Background(), CorpusOptions{
			Feed: Options{LocalPath: dir},
			Selections: []domain.RecordPin{
				selected,
				corpusPin(t, "CVE-2099-3000", bBody, "corpus/b/CVE-2099-3000.json"),
			},
		}); err == nil {
			t.Fatal("two different selections for one record id were accepted")
		}
	})

	t.Run("related ids never feed alias enrichment", func(t *testing.T) {
		body := corpusDocJSON(t, "GO-2099-9000", "", nil, []string{"CVE-2099-9000"}, []string{"example.com/rel"})
		dir := writeCorpusFiles(t, map[string]string{"GO-2099-9000.json": body})
		feed, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		resolution := feed.ResolveImports("CVE-2099-9000", nil, "example.com/rel")
		if resolution.Status != StatusNotFound {
			t.Fatalf("related id reached the subject-completion index: %+v", resolution)
		}
		corpus := acquireCorpusDir(t, dir, nil, nil)
		if pins := corpus.Lookup(RelationshipAlias, "CVE-2099-9000"); len(pins) != 0 {
			t.Fatalf("related id entered the alias index: %+v", pins)
		}
		if pins := corpus.Lookup(RelationshipRelated, "CVE-2099-9000"); len(pins) != 1 {
			t.Fatalf("related lookup = %+v", pins)
		}
	})

	t.Run("missing sources are explicit outcomes", func(t *testing.T) {
		corpus, err := AcquireCorpus(context.Background(), CorpusOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if corpus.Manifest().Enumeration != domain.DiscoveryNotConfigured {
			t.Fatalf("enumeration = %q", corpus.Manifest().Enumeration)
		}
		discovery := corpus.Discover("CVE-2099-4000", nil)
		if err := discovery.Validate(); err != nil {
			t.Fatalf("not-configured discovery: %v", err)
		}
		if discovery.Enumeration != domain.DiscoveryNotConfigured || len(discovery.Candidates) != 0 {
			t.Fatalf("discovery = %+v", discovery)
		}
		if !limitationContains(discovery, "no advisory corpus is configured") {
			t.Fatalf("limitations = %v", discovery.Limitations)
		}

		missingDir, err := AcquireCorpus(context.Background(), CorpusOptions{
			Feed: Options{LocalPath: filepath.Join(t.TempDir(), "absent")},
		})
		if err != nil {
			t.Fatal(err)
		}
		if missingDir.Manifest().Enumeration != domain.DiscoveryUnavailable {
			t.Fatalf("absent local enumeration = %q", missingDir.Manifest().Enumeration)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()
		remote, err := AcquireCorpus(context.Background(), CorpusOptions{
			Feed: Options{BaseURL: server.URL, CacheDir: t.TempDir()},
		})
		if err != nil {
			t.Fatal(err)
		}
		if remote.Manifest().Enumeration != domain.DiscoveryUnavailable {
			t.Fatalf("remote enumeration = %q", remote.Manifest().Enumeration)
		}
		remoteDiscovery := remote.Discover("CVE-2099-4001", nil)
		if remoteDiscovery.Enumeration != domain.DiscoveryUnavailable || len(remoteDiscovery.Candidates) != 0 {
			t.Fatalf("remote discovery = %+v", remoteDiscovery)
		}
		if !limitationContains(remoteDiscovery, "could not be enumerated") {
			t.Fatalf("limitations = %v", remoteDiscovery.Limitations)
		}
	})

	t.Run("read and decode failures are visible", func(t *testing.T) {
		valid := corpusDocJSON(t, "GO-2099-5000", "", []string{"CVE-2099-5000"}, nil, []string{"example.com/valid"})
		bad := `{"id":"GO-9999-9000","aliases":["CVE-2099-5000"],"affected":"not-an-array"}`
		dir := writeCorpusFiles(t, map[string]string{
			"valid.json": valid,
			"bad.json":   bad,
			"no-id.json": `{"summary":"not an advisory"}`,
		})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		manifest := corpus.Manifest()
		if manifest.Enumeration != domain.DiscoveryPartial {
			t.Fatalf("enumeration = %q, want partial", manifest.Enumeration)
		}
		if len(manifest.Problems) != 2 {
			t.Fatalf("problems = %+v, want the decode failure and the missing id", manifest.Problems)
		}
		if err := manifest.Validate(); err != nil {
			t.Fatal(err)
		}
		discovery := corpus.Discover("CVE-2099-5000", nil)
		if err := discovery.Validate(); err != nil {
			t.Fatal(err)
		}
		if discovery.Enumeration != domain.DiscoveryPartial {
			t.Fatalf("discovery enumeration = %q", discovery.Enumeration)
		}
		failed := candidateByID(discovery, "GO-9999-9000")
		if failed == nil || failed.Disposition != domain.DispositionLoadFailed {
			t.Fatalf("load failure not visible: %+v", failed)
		}
		validCandidate := candidateByID(discovery, "GO-2099-5000")
		if validCandidate == nil || validCandidate.Disposition != domain.DispositionNotEvaluated {
			t.Fatalf("valid candidate = %+v", validCandidate)
		}
		if !limitationContains(discovery, "partial") {
			t.Fatalf("limitations = %v", discovery.Limitations)
		}
	})

	t.Run("manifest digest reuses the feed convention", func(t *testing.T) {
		files := map[string]string{
			"GO-2099-6001.json": corpusDocJSON(t, "GO-2099-6001", "", []string{"CVE-2099-6001"}, nil, []string{"example.com/one"}),
			"GO-2099-6002.json": corpusDocJSON(t, "GO-2099-6002", "", nil, nil, []string{"example.com/two"}),
		}
		dir := writeCorpusFiles(t, files)
		feed, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		corpus := acquireCorpusDir(t, dir, nil, nil)
		want := "sha256:" + feed.Prov.SHA256
		if corpus.Manifest().ObservedDigest != want {
			t.Fatalf("directory digest = %q, want %q", corpus.Manifest().ObservedDigest, want)
		}

		zipBody := zipBytes(t, files)
		zipPath := filepath.Join(t.TempDir(), "dump.zip")
		if err := os.WriteFile(zipPath, zipBody, 0o644); err != nil {
			t.Fatal(err)
		}
		zipFeed, err := Open(zipPath)
		if err != nil {
			t.Fatal(err)
		}
		zipCorpus, err := AcquireCorpus(context.Background(), CorpusOptions{Feed: Options{LocalPath: zipPath}})
		if err != nil {
			t.Fatal(err)
		}
		if zipCorpus.Manifest().Enumeration != domain.DiscoveryFinished {
			t.Fatalf("zip enumeration = %q", zipCorpus.Manifest().Enumeration)
		}
		if got, want := zipCorpus.Manifest().ObservedDigest, "sha256:"+zipFeed.Prov.SHA256; got != want {
			t.Fatalf("zip digest = %q, want %q", got, want)
		}
	})

	t.Run("remote corpus acquisition pins the archive bytes", func(t *testing.T) {
		docBody := corpusDocJSON(t, "GO-2099-8500", "", []string{"CVE-2099-8500"}, nil, []string{"example.com/remote"})
		zipBody := zipBytes(t, map[string]string{"GO-2099-8500.json": docBody})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ecosystems.txt":
				_, _ = w.Write([]byte("Go\n"))
			case "/Go/all.zip":
				_, _ = w.Write(zipBody)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		corpus, err := AcquireCorpus(context.Background(), CorpusOptions{
			Feed: Options{BaseURL: server.URL, CacheDir: t.TempDir()},
		})
		if err != nil {
			t.Fatal(err)
		}
		manifest := corpus.Manifest()
		if manifest.Enumeration != domain.DiscoveryFinished {
			t.Fatalf("remote enumeration = %q, problems = %+v", manifest.Enumeration, manifest.Problems)
		}
		if want := "sha256:" + sha256Hex(zipBody); manifest.ObservedDigest != want {
			t.Fatalf("remote observed digest = %q, want %q", manifest.ObservedDigest, want)
		}
		pins := corpus.Lookup(RelationshipRecord, "GO-2099-8500")
		if len(pins) != 1 {
			t.Fatalf("remote pins = %+v", pins)
		}
		loaded, err := corpus.Document(context.Background(), pins[0])
		if err != nil {
			t.Fatal(err)
		}
		if string(loaded.Raw) != docBody {
			t.Fatal("remote corpus did not retain the exact member bytes")
		}
	})

	t.Run("document loads only pinned bytes", func(t *testing.T) {
		body := corpusDocJSON(t, "GO-2099-7000", "", []string{"CVE-2099-7000"}, nil, []string{"example.com/doc"})
		dir := writeCorpusFiles(t, map[string]string{"GO-2099-7000.json": body})
		corpus := acquireCorpusDir(t, dir, nil, nil)
		pins := corpus.Lookup(RelationshipRecord, "GO-2099-7000")
		if len(pins) != 1 {
			t.Fatalf("pins = %+v", pins)
		}
		loaded, err := corpus.Document(context.Background(), pins[0])
		if err != nil {
			t.Fatal(err)
		}
		if string(loaded.Raw) != body {
			t.Fatal("Document did not return the pinned bytes")
		}
		if !loaded.Pin.Same(pins[0]) {
			t.Fatalf("loaded pin = %+v, want %+v", loaded.Pin, pins[0])
		}
		altered := pins[0]
		altered.DocumentDigest = "sha256:" + strings.Repeat("1", 64)
		if _, err := corpus.Document(context.Background(), altered); err == nil {
			t.Fatal("a pin for other bytes was resolved")
		}
		foreign := pins[0]
		foreign.RecordID = "GO-0000-0000"
		if _, err := corpus.Document(context.Background(), foreign); err == nil {
			t.Fatal("a pin for an unenumerated record was resolved")
		}
	})

	t.Run("declared corpus identity is separate from observed manifest", func(t *testing.T) {
		body := corpusDocJSON(t, "GO-2099-8000", "", []string{"CVE-2099-8000"}, nil, []string{"example.com/decl"})
		dir := writeCorpusFiles(t, map[string]string{"GO-2099-8000.json": body})
		base := acquireCorpusDir(t, dir, nil, nil)
		observed := base.Manifest().ObservedDigest
		declaration := &domain.CorpusDeclaration{
			Reference:      "operator-corpus-2026-10",
			ExpectedDigest: observed,
			CapturedAt:     "2026-10-25",
		}
		declared := acquireCorpusDir(t, dir, declaration, nil)
		discovery := declared.Discover("CVE-2099-8000", nil)
		if discovery.Corpus == nil {
			t.Fatal("declared discovery has no corpus reference")
		}
		if discovery.Corpus.Reference != declaration.Reference ||
			discovery.Corpus.Digest != declaration.ExpectedDigest ||
			discovery.Corpus.CapturedAt != declaration.CapturedAt {
			t.Fatalf("corpus reference = %+v, declaration = %+v", discovery.Corpus, declaration.Pinned())
		}
		if err := discovery.Corpus.Validate(); err != nil {
			t.Fatal(err)
		}

		wrong := &domain.CorpusDeclaration{
			Reference:      "operator-corpus-2026-10",
			ExpectedDigest: "sha256:" + strings.Repeat("2", 64),
			CapturedAt:     "2026-10-25",
		}
		mismatched := acquireCorpusDir(t, dir, wrong, nil)
		mismatchDiscovery := mismatched.Discover("CVE-2099-8000", nil)
		if !limitationContains(mismatchDiscovery, "declared corpus digest") {
			t.Fatalf("limitations = %v", mismatchDiscovery.Limitations)
		}
	})
}

func limitationContains(discovery domain.RelatedDiscovery, fragment string) bool {
	for _, limitation := range discovery.Limitations {
		if strings.Contains(limitation, fragment) {
			return true
		}
	}
	return false
}
