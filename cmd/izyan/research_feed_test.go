package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parseFeedFlags(t *testing.T, args ...string) (*researchOpts, *flag.FlagSet) {
	t.Helper()
	fs := flag.NewFlagSet("research", flag.ContinueOnError)
	var o researchOpts
	researchFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "osv-url" {
			o.osvURLSet = true
		}
	})
	return &o, fs
}

// All five feed flags register, and a local feed path alone configures
// the lane's feed options with no remote fields.
func TestResearch_FeedFlagsRegisteredAndLocal(t *testing.T) {
	for _, name := range []string{"osv-feed", "osv-url", "osv-cache-dir", "osv-dump-ttl", "osv-no-proxy"} {
		fs := flag.NewFlagSet("research", flag.ContinueOnError)
		var o researchOpts
		researchFlags(fs, &o)
		if fs.Lookup(name) == nil {
			t.Fatalf("flag --%s missing", name)
		}
	}
	o, _ := parseFeedFlags(t, "--osv-feed", "dumps/Go")
	got, err := feedOptionsFromFlags(o)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.LocalPath != "dumps/Go" || got.BaseURL != "" {
		t.Fatalf("opts = %+v", got)
	}
}

// URL resolution: explicit flag wins, IZYAN_OSV_URL falls back to the
// public default host, and the TTL flag bounds cache age.
func TestResearch_FeedOptionsRemoteResolution(t *testing.T) {
	// Explicit URL.
	o, _ := parseFeedFlags(t, "--osv-url", "https://example.test/osv",
		"--osv-cache-dir", "/tmp/c", "--osv-dump-ttl", "48h")
	got, err := feedOptionsFromFlags(o)
	if err != nil {
		t.Fatal(err)
	}
	if got.BaseURL != "https://example.test/osv" || got.CacheDir != "/tmp/c" || got.DumpTTL != 48*time.Hour {
		t.Fatalf("opts = %+v", got)
	}

	// Env URL with no flag.
	t.Setenv(osvURLEnv, "https://mirror.test/osv")
	o, _ = parseFeedFlags(t)
	got, err = feedOptionsFromFlags(o)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.BaseURL != "https://mirror.test/osv" {
		t.Fatalf("env opts = %+v", got)
	}
}

// Mutual exclusion, dependent flags without a source, and negative TTL
// are flag errors — the lane never silently guesses.
func TestResearch_FeedOptionsValidation(t *testing.T) {
	t.Run("local+url", func(t *testing.T) {
		o, _ := parseFeedFlags(t, "--osv-feed", "d", "--osv-url", "u")
		if _, err := feedOptionsFromFlags(o); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cache-dir without url", func(t *testing.T) {
		o, _ := parseFeedFlags(t, "--osv-cache-dir", "/c")
		if _, err := feedOptionsFromFlags(o); err == nil || !strings.Contains(err.Error(), "--osv-url") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no-proxy without source", func(t *testing.T) {
		o, _ := parseFeedFlags(t, "--osv-no-proxy")
		if _, err := feedOptionsFromFlags(o); err == nil || !strings.Contains(err.Error(), "--osv-url") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("negative ttl", func(t *testing.T) {
		o, _ := parseFeedFlags(t, "--osv-url", "u", "--osv-dump-ttl", "-1h")
		if _, err := feedOptionsFromFlags(o); err == nil || !strings.Contains(err.Error(), "non-negative") {
			t.Fatalf("err = %v", err)
		}
	})
}

// optionsManifest records provenance-safe members only: the local feed
// path goes through ProvenanceLocalRef (basename), the remote URL is
// sanitized, and the cache directory path never appears.
func TestResearch_FeedOptionsManifestProvenance(t *testing.T) {
	o, _ := parseFeedFlags(t, "--osv-feed", "/very/local/dir")
	m := optionsManifest(*o)
	if m["osv_feed"] == "/very/local/dir" {
		t.Fatalf("absolute local path recorded: %v", m["osv_feed"])
	}
	if _, ok := m["osv_url"]; ok {
		t.Fatalf("osv_url recorded for a local feed: %+v", m)
	}

	t.Setenv(osvURLEnv, "")
	o, _ = parseFeedFlags(t, "--osv-url", "https://user:pw@mirror.test/osv?x=1",
		"--osv-cache-dir", "/tmp/secret", "--osv-no-proxy")
	m = optionsManifest(*o)
	if u, _ := m["osv_url"].(string); strings.Contains(u, "pw") || strings.Contains(u, "x=1") {
		t.Fatalf("credentials/query leaked into manifest: %v", u)
	}
	if m["osv_dump_ttl"] == nil {
		t.Fatalf("ttl not recorded: %+v", m)
	}
	if !reflectBool(t, m, "osv_no_proxy") {
		t.Fatalf("osv_no_proxy missing: %+v", m)
	}
	// The OSV cache path must not surface as a value anywhere.
	for k, v := range m {
		if s, _ := v.(string); strings.Contains(s, "/tmp/secret") {
			t.Fatalf("cache dir recorded in manifest: %s=%v", k, v)
		}
	}
	t.Setenv(osvURLEnv, "")
	o, _ = parseFeedFlags(t)
	m = optionsManifest(*o)
	for k := range m {
		if strings.HasPrefix(k, "osv_") {
			t.Fatalf("osv key %q present without any feed configured", k)
		}
	}
}

func reflectBool(t *testing.T, m map[string]any, key string) bool {
	t.Helper()
	v, ok := m[key].(bool)
	return ok && v
}

// A local dump directory supplied through the flag opens without any
// network — Acquire resolves subjects offline.
func TestResearch_AcquireFromLocalDirFlags(t *testing.T) {
	dir := t.TempDir()
	doc := `{"id":"GO-X","aliases":["GHSA-y"],"affected":[{"package":{"ecosystem":"Go","name":"example.com/m"},
	  "ecosystem_specific":{"imports":[{"path":"example.com/m","symbols":["F"]}]}}]}`
	if err := os.WriteFile(filepath.Join(dir, "GO-X.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	o, _ := parseFeedFlags(t, "--osv-feed", dir)
	opts, err := feedOptionsFromFlags(o)
	if err != nil {
		t.Fatal(err)
	}
	if opts.LocalPath != dir || opts.BaseURL != "" {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestResearchPublicationCorpusInputContracts(t *testing.T) {
	t.Setenv(osvURLEnv, "")
	digest := strings.Repeat("ab", 32)
	o, _ := parseFeedFlags(t, "--osv-feed", "offline", "--corpus-digest", digest,
		"--corpus-captured-at", "2026-10-28T00:00:00Z", "--record-pin", "GO-X="+digest)
	feed, err := feedOptionsFromFlags(o)
	if err != nil {
		t.Fatal(err)
	}
	corpus, _, err := researchCorpusOptions(o, feed)
	if err != nil {
		t.Fatal(err)
	}
	if corpus.Declaration.ExpectedDigest != "sha256:"+digest || len(corpus.Selections) != 1 ||
		corpus.Selections[0].DocumentDigest != "sha256:"+digest {
		t.Fatalf("shared corpus pin contract lost: %+v", corpus)
	}
	for _, args := range [][]string{
		{"--corpus-digest", digest},
		{"--osv-feed", "offline", "--corpus-digest", digest},
		{"--osv-feed", "offline", "--record-pin", "GO-X=bad"},
		{"--osv-feed", "offline", "--record-pin", "GO-X="+digest, "--record-pin", "GO-X="+strings.Repeat("cd", 32)},
	} {
		o, _ := parseFeedFlags(t, args...)
		feed, err := feedOptionsFromFlags(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := researchCorpusOptions(o, feed); err == nil {
			t.Fatalf("invalid input accepted: %v", args)
		}
	}
}
