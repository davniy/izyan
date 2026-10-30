package advfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxDownloadBytes bounds one ecosystem dump. The whole Go zip is tens of
// megabytes; the cap only guards against a misbehaving or hostile source.
const maxDownloadBytes = 1 << 30

// dumpMeta is the sidecar (<name>.meta.json) written next to every cached
// dump. checked_at is the freshness probe timestamp — it is only refreshed
// by a real remote contact and never on cache fallback.
type dumpMeta struct {
	Ecosystem string `json:"ecosystem"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	CheckedAt string `json:"checked_at"`
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Options) ecosystem() string {
	if o.Ecosystem != "" {
		return o.Ecosystem
	}
	return EcosystemGo
}

func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if o.NoProxy {
		tr.Proxy = nil
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Minute}
}

func (o Options) cacheDir() (string, error) {
	if o.CacheDir != "" {
		return o.CacheDir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "izyan-osv-dump"), nil
}

// fetchRemote acquires one ecosystem dump from a remote OSV source.
// Order: ecosystems.txt decides presence (an absent ecosystem is
// osv_missing, not an error — and a stale cache is not served for an
// ecosystem the source no longer lists). Then the dump's cache freshness
// is decided by a length probe: a GET whose body is closed unread —
// Content-Length equal to the cached size reuses the cache, different
// length downloads. DumpTTL skips the probe and forces a download. Any
// remote failure falls back to a hash-verified cache, keeping its
// original CheckedAt; with no valid cache the outcome is feed_error.
func fetchRemote(ctx context.Context, o Options) (Outcome, error) {
	base, err := parseBaseURL(strings.TrimRight(o.BaseURL, "/"))
	if err != nil {
		return Outcome{}, err
	}
	eco := o.ecosystem()
	hc := o.client()
	dir, derr := o.cacheDir()
	if derr != nil {
		return Outcome{Status: StatusFeedError, Detail: derr.Error()}, nil
	}
	cacheZip := filepath.Join(dir, eco+".zip")
	cacheMetaPath := filepath.Join(dir, eco+".meta.json")
	dumpURL := base + "/" + eco + "/all.zip"
	provRef := sanitizeURL(base)

	cached := readCache(cacheZip, cacheMetaPath, dumpURL)

	// ---- ecosystems.txt: presence check ----
	ecoList, lerr := getText(ctx, hc, base+"/ecosystems.txt")
	if lerr != nil {
		if cached != nil {
			return fallbackOutcome(cached, provRef, lerr), nil
		}
		return Outcome{Status: StatusFeedError,
			Detail: fmt.Sprintf("ecosystems.txt fetch failed and no valid cache exists: %v", lerr)}, nil
	}
	if !hasEcosystem(ecoList, eco) {
		return Outcome{Status: StatusOSVMissing,
			Detail: fmt.Sprintf("ecosystem %q is not listed by the source (ecosystems.txt)", eco)}, nil
	}

	// ---- freshness: age cap or length probe ----
	fresh := false
	probeErr := error(nil)
	switch {
	case cached != nil && o.DumpTTL > 0 && o.now().Sub(cached.metaTime()) > o.DumpTTL:
		// Stale by the operator's age cap — download without probing.
	case cached == nil:
		// Nothing to reuse — download.
	default:
		// Length probe: a plain GET whose body is closed unread; the
		// source answers HEAD with 405 and ignores Range, so Content-
		// Length from a header-only GET is the freshness signal.
		l, perr := probeLength(ctx, hc, dumpURL)
		switch {
		case perr != nil:
			probeErr = perr
		case l == cached.meta.Size:
			fresh = true
			cached.meta.CheckedAt = o.now().Format(time.RFC3339)
			if werr := writeMeta(cacheMetaPath, cached.meta); werr != nil {
				// A meta write failure must not downgrade the data we
				// already validated — reuse it anyway.
				fresh = true
			}
		}
	}
	if fresh {
		f, err := openZipBytes(cached.body, provRef)
		if err != nil {
			return Outcome{Status: StatusFeedError,
				Detail: fmt.Sprintf("cached dump rejected on re-open: %v", err)}, nil
		}
		f.Prov.CheckedAt = cached.metaTime()
		return Outcome{Feed: f, Status: StatusResolved, Prov: f.Prov, Dump: cached.body}, nil
	}
	if probeErr != nil {
		// Mirror unreachable at probe time: serve the cache if it is
		// valid; otherwise the feed is simply unavailable.
		if cached != nil {
			return fallbackOutcome(cached, provRef, probeErr), nil
		}
		return Outcome{Status: StatusFeedError,
			Detail: fmt.Sprintf("dump length probe failed and no valid cache exists: %v", probeErr)}, nil
	}

	// ---- download ----
	body, derr := getBytes(ctx, hc, dumpURL, maxDownloadBytes)
	if derr != nil {
		if cached != nil {
			return fallbackOutcome(cached, provRef, derr), nil
		}
		return Outcome{Status: StatusFeedError,
			Detail: fmt.Sprintf("dump download failed and no valid cache exists: %v", derr)}, nil
	}
	f, oerr := openZipBytes(body, provRef)
	if oerr != nil {
		return Outcome{Status: StatusFeedError,
			Detail: fmt.Sprintf("downloaded dump is not a readable OSV zip: %v", oerr)}, nil
	}
	f.Prov.CheckedAt = o.now()
	if err := os.MkdirAll(dir, 0o755); err == nil {
		meta := dumpMeta{
			Ecosystem: eco, URL: dumpURL, SHA256: f.Prov.SHA256,
			Size:      int64(len(body)),
			CheckedAt: f.Prov.CheckedAt.Format(time.RFC3339),
		}
		// Cache writes are best-effort: a read-only cache dir degrades to
		// "always download", never to a failed run.
		if werr := os.WriteFile(cacheZip, body, 0o644); werr == nil {
			_ = writeMeta(cacheMetaPath, meta)
		}
	}
	return Outcome{Feed: f, Status: StatusResolved, Prov: f.Prov, Dump: body}, nil
}

// parseBaseURL validates the configured source base URL: http/https with
// a host and no embedded credentials; userinfo/query/fragment are
// dropped from the normalized value.
func parseBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("advisory feed base URL %q is invalid (want http(s)://host[/path])", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("advisory feed base URL %q must not embed credentials", raw)
	}
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

// hasEcosystem reports whether ecosystems.txt lists the name, one
// ecosystem per line, blanks and a possible trailing newline tolerated.
func hasEcosystem(list, eco string) bool {
	for _, line := range strings.Split(list, "\n") {
		if strings.TrimSpace(line) == eco {
			return true
		}
	}
	return false
}

// cachedDump is a cache pair that passed hash verification.
type cachedDump struct {
	body []byte
	meta dumpMeta
}

func (c *cachedDump) metaTime() time.Time {
	t, err := time.Parse(time.RFC3339, c.meta.CheckedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// readCache loads the cache pair only when the meta parses, matches the
// source URL and the stored digest verifies against the bytes. Anything
// else returns nil (a corrupt/absent cache is simply not a cache).
func readCache(zipPath, metaPath, url string) *cachedDump {
	mb, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}
	var m dumpMeta
	if err := json.Unmarshal(mb, &m); err != nil || m.URL != url {
		return nil
	}
	body, err := os.ReadFile(zipPath)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(body)
	if m.SHA256 != hex.EncodeToString(sum[:]) || m.Size != int64(len(body)) {
		return nil
	}
	return &cachedDump{body: body, meta: m}
}

func writeMeta(path string, m dumpMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// fallbackOutcome serves a validated cache after a remote failure. The
// meta timestamp is preserved verbatim — the source was not checked, so
// the check time must not move.
func fallbackOutcome(c *cachedDump, ref string, cause error) Outcome {
	f, err := openZipBytes(c.body, ref)
	if err != nil {
		return Outcome{Status: StatusFeedError,
			Detail: fmt.Sprintf("source failed (%v) and the cache is unusable: %v", cause, err)}
	}
	f.Prov.CheckedAt = c.metaTime()
	return Outcome{
		Feed:          f,
		Status:        StatusResolved,
		Prov:          f.Prov,
		Dump:          c.body,
		CacheFallback: true,
		Detail:        fmt.Sprintf("served from the verified cache after the source failed: %v", cause),
	}
}

// probeLength issues a GET and discards the body without reading it —
// Content-Length alone answers the freshness question.
func probeLength(ctx context.Context, hc *http.Client, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return -1, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return -1, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("probe %s: status %d", url, resp.StatusCode)
	}
	l := resp.ContentLength
	if l < 0 {
		l, _ = strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	}
	if l < 0 {
		return -1, fmt.Errorf("probe %s: no Content-Length to compare", url)
	}
	return l, nil
}

func getBytes(ctx context.Context, hc *http.Client, url string, cap int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > cap {
		return nil, fmt.Errorf("get %s: response exceeds %d bytes", url, cap)
	}
	return body, nil
}

func getText(ctx context.Context, hc *http.Client, url string) (string, error) {
	b, err := getBytes(ctx, hc, url, 1<<20)
	return string(b), err
}
