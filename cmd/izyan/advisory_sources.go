package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/advfeed"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/repository"
)

// attributionManifestSchema is the closed schema of the operator-supplied
// capture manifest. The manifest lists captured publisher/CNA documents with
// the digest each file must have; it is not a CVE mapping and admits nothing by
// itself — attribution admission still runs the normalized-capture checks.
const attributionManifestSchema = "attribution-captures/1"

// attributionManifest is the closed decode target of a capture manifest.
type attributionManifest struct {
	Schema   string               `json:"schema"`
	Captures []attributionCapture `json:"captures"`
}

// attributionCapture is one listed capture: the source URI recorded in an
// attribution, the local file holding its bytes and the expected digest.
type attributionCapture struct {
	SourceURI string `json:"source_uri"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}

// pinnedDigestPattern is the only accepted digest spelling of an operator pin:
// a lowercase sha256 over the exact bytes.
var pinnedDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// advisorySourceFlags registers the corpus/attribution surface shared by every
// authoritative command. The feed flag names follow the research lane's
// convention. An executable's --osv-url is the single-record OSV API base and is
// deliberately never treated as a dump source: a remote corpus is configured
// through IZYAN_OSV_URL, exactly like the research lane.
func advisorySourceFlags(fs *flag.FlagSet, o *analyzeOpts) {
	fs.StringVar(&o.osvFeed, "osv-feed", "", "offline OSV dump (a directory of OSV JSON documents or one zip archive) used as the pinned advisory corpus for record discovery")
	fs.StringVar(&o.osvCacheDir, "osv-cache-dir", "", "cached dump directory for a corpus fetched from "+osvURLEnv+" (default per-user cache)")
	fs.DurationVar(&o.osvDumpTTL, "osv-dump-ttl", 7*24*time.Hour, "max age of a cached corpus dump before a forced re-download (0 = freshness by length probe only)")
	fs.BoolVar(&o.osvNoProxy, "osv-no-proxy", false, "fetch the corpus dump without http_proxy/https_proxy (default honours the environment)")
	fs.StringVar(&o.corpusDigest, "corpus-digest", "", "declared sha256 of the enumerated corpus (requires --corpus-captured-at); without a declaration a CVE request cannot close negatively")
	fs.StringVar(&o.corpusCapturedAt, "corpus-captured-at", "", "declared RFC3339 capture date of the corpus (requires --corpus-digest)")
	fs.Var(&o.recordPins, "record-pin", "record id selection as <record-id>=<sha256> when one record id carries conflicting documents (repeatable)")
	fs.StringVar(&o.attributionFile, "attribution-file", "", "capture manifest ("+attributionManifestSchema+") of publisher/CNA documents for directional CVE attribution")
}

// advisorySourceOptions is the command-independent corpus/capture configuration.
// Every authoritative command resolves exactly these fields, so the research lane
// adopts the identical resolution instead of reimplementing flag semantics.
type advisorySourceOptions struct {
	Feed             string
	CacheDir         string
	DumpTTL          time.Duration
	NoProxy          bool
	CorpusDigest     string
	CorpusCapturedAt string
	RecordPins       []string
	AttributionFile  string
}

// resolvedAdvisorySources is the shared resolution outcome. Corpus is nil when no
// source is configured: discovery then records not_configured, and nothing can
// ground a CVE-wide negative.
type resolvedAdvisorySources struct {
	Corpus               *advfeed.Corpus
	Declaration          *domain.CorpusDeclaration
	AttributionMaterials map[string]string
}

// resolveCorpusSource validates the shared options and acquires the pinned
// corpus, the operator-declared boundary and the captured attribution materials.
//
// Invalid operator input is a usage error, raised before any analysis exists. A
// configured source that cannot be read is NOT an error here: it becomes the
// corpus manifest's explicit unavailable outcome, so no caller can mistake "not
// searched" for "nothing found". Supplying a feed without a declaration grants
// no negative authority; Addendum A closure stays unavailable.
func resolveCorpusSource(ctx context.Context, o advisorySourceOptions) (resolvedAdvisorySources, error) {
	var resolved resolvedAdvisorySources
	feed, configured, err := corpusFeedOptions(o)
	if err != nil {
		return resolved, err
	}
	materials, err := attributionMaterials(o.AttributionFile)
	if err != nil {
		return resolved, err
	}
	resolved.AttributionMaterials = materials
	if !configured {
		return resolved, nil
	}
	declaration, err := corpusDeclarationFromOptions(o, feed)
	if err != nil {
		return resolved, err
	}
	selections, err := recordSelections(o.RecordPins)
	if err != nil {
		return resolved, err
	}
	corpus, err := advfeed.AcquireCorpus(ctx, advfeed.CorpusOptions{
		Feed:        feed,
		Declaration: declaration,
		Selections:  selections,
	})
	if err != nil {
		return resolved, err
	}
	resolved.Corpus = corpus
	resolved.Declaration = declaration
	return resolved, nil
}

// resolveAdvisorySources applies the shared resolution to one analyzer command.
func resolveAdvisorySources(ctx context.Context, o *analyzeOpts) error {
	resolved, err := resolveCorpusSource(ctx, o.advisorySourceOptions())
	if err != nil {
		return err
	}
	o.attributionMaterials = resolved.AttributionMaterials
	o.corpusDeclaration = resolved.Declaration
	if resolved.Corpus != nil {
		o.corpus = resolved.Corpus
	}
	return nil
}

// advisorySourceOptions projects a command's flag fields onto the shared
// configuration.
func (o analyzeOpts) advisorySourceOptions() advisorySourceOptions {
	return advisorySourceOptions{
		Feed:             o.osvFeed,
		CacheDir:         o.osvCacheDir,
		DumpTTL:          o.osvDumpTTL,
		NoProxy:          o.osvNoProxy,
		CorpusDigest:     o.corpusDigest,
		CorpusCapturedAt: o.corpusCapturedAt,
		RecordPins:       o.recordPins,
		AttributionFile:  o.attributionFile,
	}
}

// corpusFeedOptions resolves the feed configuration. configured is false when no
// source is named at all — a run without a corpus records DISCOVERY
// not_configured and still answers exact-record requests.
func corpusFeedOptions(o advisorySourceOptions) (advfeed.Options, bool, error) {
	if o.DumpTTL < 0 {
		return advfeed.Options{}, false, fmt.Errorf(
			"--osv-dump-ttl must be non-negative (0 = freshness by length probe only)")
	}
	envURL := strings.TrimSpace(os.Getenv(osvURLEnv))
	switch {
	case o.Feed != "" && envURL != "":
		return advfeed.Options{}, false, fmt.Errorf("--osv-feed and %s are mutually exclusive", osvURLEnv)
	case o.Feed != "":
		return advfeed.Options{LocalPath: o.Feed, Ecosystem: advfeed.EcosystemGo}, true, nil
	case envURL != "":
		return advfeed.Options{
			BaseURL:   envURL,
			Ecosystem: advfeed.EcosystemGo,
			CacheDir:  o.CacheDir,
			DumpTTL:   o.DumpTTL,
			NoProxy:   o.NoProxy,
		}, true, nil
	}
	if o.CacheDir != "" || o.NoProxy || o.CorpusDigest != "" ||
		o.CorpusCapturedAt != "" || len(o.RecordPins) > 0 {
		return advfeed.Options{}, false, fmt.Errorf(
			"--osv-cache-dir/--osv-no-proxy/--corpus-digest/--corpus-captured-at/--record-pin require --osv-feed or %s (--osv-url is the single-record OSV API, never a corpus dump source)",
			osvURLEnv)
	}
	return advfeed.Options{}, false, nil
}

// corpusDeclarationFromOptions builds the operator-declared boundary. A digest
// and a capture date are the two halves of one declaration: supplying either
// alone is a usage error rather than a silently weaker claim.
func corpusDeclarationFromOptions(o advisorySourceOptions, feed advfeed.Options) (*domain.CorpusDeclaration, error) {
	if o.CorpusDigest == "" && o.CorpusCapturedAt == "" {
		return nil, nil
	}
	if o.CorpusDigest == "" || o.CorpusCapturedAt == "" {
		return nil, fmt.Errorf("a declared corpus boundary needs both --corpus-digest and --corpus-captured-at")
	}
	digest, err := normalizePinnedDigest(o.CorpusDigest)
	if err != nil {
		return nil, fmt.Errorf("--corpus-digest: %w", err)
	}
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(o.CorpusCapturedAt))
	if err != nil {
		return nil, fmt.Errorf("--corpus-captured-at must be an RFC3339 timestamp (e.g. 2026-10-20T00:00:00Z): %w", err)
	}
	declaration := &domain.CorpusDeclaration{
		Reference:      corpusReference(feed),
		ExpectedDigest: digest,
		CapturedAt:     at.UTC().Format(time.RFC3339),
	}
	if err := declaration.Validate(); err != nil {
		return nil, fmt.Errorf("corpus declaration: %w", err)
	}
	return declaration, nil
}

// corpusReference is the operator-visible corpus identity. It is a provenance
// label, never a path or a credential: the same sanitization the feed itself
// records.
func corpusReference(feed advfeed.Options) string {
	if feed.LocalPath != "" {
		return repository.ProvenanceLocalRef(feed.LocalPath)
	}
	if base := sanitizeDumpURL(feed.BaseURL); base != "" {
		return base
	}
	return "advisory corpus"
}

// sanitizeDumpURL strips userinfo, query and fragment so a recorded corpus
// reference can never carry credential material.
func sanitizeDumpURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

// recordSelections parses the repeatable <record-id>=<sha256> selections that
// choose exact bytes when one record id appears with conflicting documents.
func recordSelections(flags []string) ([]domain.RecordPin, error) {
	var out []domain.RecordPin
	seen := map[string]string{}
	for _, raw := range flags {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			id, digest, ok := strings.Cut(item, "=")
			id = strings.TrimSpace(id)
			if !ok || id == "" {
				return nil, fmt.Errorf("--record-pin %q: want <record-id>=<sha256>", item)
			}
			normalized, err := normalizePinnedDigest(digest)
			if err != nil {
				return nil, fmt.Errorf("--record-pin %s: %w", id, err)
			}
			if previous, dup := seen[id]; dup {
				if previous != normalized {
					return nil, fmt.Errorf("--record-pin: record %s is selected with two different document digests (%s and %s)",
						id, previous, normalized)
				}
				continue
			}
			seen[id] = normalized
			out = append(out, domain.RecordPin{
				RecordID:       id,
				DocumentDigest: normalized,
				SourceLocator:  "selection:" + id,
			})
		}
	}
	return out, nil
}

// normalizePinnedDigest accepts the sha256 spelling or a bare lowercase hex
// digest and returns the canonical "sha256:<hex>" form.
func normalizePinnedDigest(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", fmt.Errorf("a sha256 digest is required")
	}
	if !strings.HasPrefix(trimmed, "sha256:") {
		trimmed = "sha256:" + trimmed
	}
	if !pinnedDigestPattern.MatchString(trimmed) {
		return "", fmt.Errorf("%q is not a sha256 digest (want sha256:<64 lowercase hex characters>)", raw)
	}
	return trimmed, nil
}

// attributionMaterials reads the closed capture manifest and verifies every
// listed file against its declared digest before analysis. The returned map is
// the source-URI → captured-bytes mapping the attribution resolver reads; a
// digest mismatch is an input error, because silently accepting different bytes
// would let an attribution rest on material nobody pinned.
func attributionMaterials(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attribution captures: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest attributionManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("attribution captures %s: %w", path, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("attribution captures %s: trailing data after the manifest", path)
	}
	if manifest.Schema != attributionManifestSchema {
		return nil, fmt.Errorf("attribution captures %s: schema %q is not %q",
			path, manifest.Schema, attributionManifestSchema)
	}
	if len(manifest.Captures) == 0 {
		return nil, fmt.Errorf("attribution captures %s: no captures are listed", path)
	}
	base := filepath.Dir(path)
	materials := make(map[string]string, len(manifest.Captures))
	for n, capture := range manifest.Captures {
		uri := strings.TrimSpace(capture.SourceURI)
		if uri == "" {
			return nil, fmt.Errorf("attribution captures %s: captures[%d].source_uri is required", path, n)
		}
		if _, dup := materials[uri]; dup {
			return nil, fmt.Errorf("attribution captures %s: source_uri %q is listed twice", path, uri)
		}
		file := strings.TrimSpace(capture.Path)
		if file == "" {
			return nil, fmt.Errorf("attribution captures %s: captures[%d].path is required", path, n)
		}
		if !filepath.IsAbs(file) {
			file = filepath.Join(base, file)
		}
		want, err := normalizePinnedDigest(capture.SHA256)
		if err != nil {
			return nil, fmt.Errorf("attribution captures %s: captures[%d].sha256: %w", path, n, err)
		}
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("attribution capture %s: %w", uri, err)
		}
		sum := sha256.Sum256(body)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != want {
			return nil, fmt.Errorf("attribution capture %s: bytes in %s hash to %s, not the declared %s",
				uri, file, got, want)
		}
		materials[uri] = file
	}
	return materials, nil
}
