package advfeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// trackedBody reports whether anyone read the response body — the
// length probe must not.
type trackedBody struct {
	io.Reader
	read *atomic.Bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	b.read.Store(true)
	return b.Reader.Read(p)
}
func (b *trackedBody) Close() error { return nil }

type fakeResp struct {
	status  int
	body    string
	length  int64
	failErr error // RoundTrip error instead of a response
}

type fakeTransport struct {
	// handler decides each response; reqs records the request sequence.
	handler func(req *http.Request) fakeResp
	reqs    []string
	reads   []*atomic.Bool // per-request read flag, parallel to reqs
}

// probeReads reports which requests to urlSuffix actually read their
// response body — a length probe never does, a download always does.
func (ft *fakeTransport) probeReads(urlSuffix string) (probes, downloads int) {
	for i, r := range ft.reqs {
		if !strings.HasSuffix(r, urlSuffix) {
			continue
		}
		if ft.reads[i].Load() {
			downloads++
		} else {
			probes++
		}
	}
	return
}

func (ft *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.reqs = append(ft.reqs, req.Method+" "+req.URL.String())
	read := &atomic.Bool{}
	ft.reads = append(ft.reads, read)
	fr := ft.handler(req)
	if fr.failErr != nil {
		return nil, fr.failErr
	}
	if fr.status == 0 {
		fr.status = http.StatusOK
	}
	body := &trackedBody{Reader: strings.NewReader(fr.body), read: read}
	resp := &http.Response{
		StatusCode: fr.status,
		Body:       body,
		Header:     http.Header{},
		Request:    req,
	}
	// Zero length means "report the body length"; tests override it only
	// to simulate a changed dump without changing bytes.
	l := fr.length
	if l == 0 {
		l = int64(len(fr.body))
	}
	resp.ContentLength = l
	resp.Header.Set("Content-Length", fmt.Sprint(l))
	return resp, nil
}

func fakeClient(ft *fakeTransport) *http.Client { return &http.Client{Transport: ft} }

func fetchOpts(ft *fakeTransport, dir string) Options {
	return Options{
		BaseURL:   "https://mirror.test/osv",
		Ecosystem: EcosystemGo,
		CacheDir:  dir,
		Client:    fakeClient(ft),
	}
}

func dumpBody(t *testing.T) string {
	return string(zipBytes(t, map[string]string{
		"GO-1.json": docJSON("GO-1", []string{"GHSA-x"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/m",
				Imports: []Import{{Path: "example.com/m", Symbols: []string{"F"}}}}}),
	}))
}

const testEcosystems = "npm\nGo\nPyPI\n"

// The length probe (a GET whose body is closed unread) reuses a cache
// whose recorded size matches Content-Length: the dump is never
// downloaded again and the check timestamp is refreshed.
func TestFetchLengthProbeReusesCache(t *testing.T) {
	dir := t.TempDir()
	dump := dumpBody(t)
	ft := &fakeTransport{}
	// First acquire: cold cache → ecosystems.txt + full download.
	ft.handler = func(req *http.Request) fakeResp {
		switch req.URL.Path {
		case "/osv/ecosystems.txt":
			return fakeResp{body: testEcosystems}
		case "/osv/Go/all.zip":
			return fakeResp{body: dump}
		}
		return fakeResp{status: http.StatusNotFound}
	}
	out, err := Acquire(context.Background(), fetchOpts(ft, dir))
	if err != nil || out.Feed == nil {
		t.Fatalf("first fetch: %+v %v", out, err)
	}
	if len(ft.reqs) != 2 || ft.reads[1].Load() == false {
		t.Fatalf("cold fetch reqs=%v reads=%v", ft.reqs, ft.reads)
	}

	// Second acquire: probe sees the same length — body must NOT be read
	// and the cache serves the dump.
	out2, err := Acquire(context.Background(), fetchOpts(ft, dir))
	if err != nil || out2.Feed == nil {
		t.Fatalf("second fetch: %+v %v", out2, err)
	}
	if len(ft.reqs) != 4 {
		t.Fatalf("expected ecosystems.txt + probe, got %v", ft.reqs)
	}
	if !strings.HasSuffix(ft.reqs[3], "/Go/all.zip") {
		t.Fatalf("last request is not the length probe: %v", ft.reqs)
	}
	if ft.reads[3].Load() {
		t.Fatal("length probe read the dump body")
	}
	if out2.CacheFallback {
		t.Fatal("cache reuse mislabeled as fallback")
	}
	if res := out2.Feed.ResolveImports("GHSA-x", nil, "example.com/m"); !res.OK {
		t.Fatalf("cached feed did not resolve: %+v", res)
	}
}

// A changed Content-Length re-downloads the dump.
func TestFetchChangedLengthRedownloads(t *testing.T) {
	dir := t.TempDir()
	dump := dumpBody(t)
	dump2 := string(zipBytes(t, map[string]string{
		"GO-1.json": docJSON("GO-1", []string{"GHSA-x"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/m",
				Imports: []Import{{Path: "example.com/m", Symbols: []string{"F"}}}}}),
		"GO-2.json": docJSON("GO-2", nil,
			[]testAffected{{Ecosystem: "Go", Name: "example.com/n",
				Imports: []Import{{Path: "example.com/n", Symbols: []string{"G"}}}}}),
	}))
	ft := &fakeTransport{}
	serveDump := &dump
	ft.handler = func(req *http.Request) fakeResp {
		switch req.URL.Path {
		case "/osv/ecosystems.txt":
			return fakeResp{body: testEcosystems}
		case "/osv/Go/all.zip":
			return fakeResp{body: *serveDump}
		}
		return fakeResp{status: http.StatusNotFound}
	}
	if _, err := Acquire(context.Background(), fetchOpts(ft, dir)); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if p, d := ft.probeReads("/Go/all.zip"); p != 0 || d != 1 {
		t.Fatalf("cold fetch probes=%d downloads=%d", p, d)
	}
	*serveDump = dump2
	out, err := Acquire(context.Background(), fetchOpts(ft, dir))
	if err != nil || out.Feed == nil {
		t.Fatalf("re-fetch: %+v %v", out, err)
	}
	if p, d := ft.probeReads("/Go/all.zip"); p != 1 || d != 2 {
		t.Fatalf("changed length: probes=%d downloads=%d (want 1+2)", p, d)
	}
	// The refreshed dump is indexed, not the stale one.
	if res := out.Feed.ResolveImports("GO-2", nil, "example.com/n"); !res.OK {
		t.Fatalf("refreshed dump missing GO-2: %+v", res)
	}
}

// DumpTTL forces a refresh without probing.
func TestFetchTTLForcesRedownload(t *testing.T) {
	dir := t.TempDir()
	dump := dumpBody(t)
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	ft := &fakeTransport{}
	ft.handler = func(req *http.Request) fakeResp {
		switch req.URL.Path {
		case "/osv/ecosystems.txt":
			return fakeResp{body: testEcosystems}
		case "/osv/Go/all.zip":
			return fakeResp{body: dump}
		}
		return fakeResp{status: http.StatusNotFound}
	}
	o := fetchOpts(ft, dir)
	o.Now = func() time.Time { return now }
	if _, err := Acquire(context.Background(), o); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	// Same dump length, TTL unexpired → probe only.
	o.Now = func() time.Time { return now.Add(time.Hour) }
	if out, err := Acquire(context.Background(), o); err != nil {
		t.Fatalf("within-TTL fetch: %+v err=%v", out, err)
	}
	if p, d := ft.probeReads("/Go/all.zip"); p != 1 || d != 1 {
		t.Fatalf("within-TTL fetch probed/downloaded wrong: p=%d d=%d", p, d)
	}
	// TTL expired → straight to download, no length probe. The probe
	// above refreshed checked_at to now+1h, so expiry needs >2h past it.
	o.DumpTTL = 2 * time.Hour
	o.Now = func() time.Time { return now.Add(4 * time.Hour) }
	out, err := Acquire(context.Background(), o)
	if err != nil || out.Feed == nil {
		t.Fatalf("expired-TTL fetch: %+v %v", out, err)
	}
	if p, d := ft.probeReads("/Go/all.zip"); p != 1 || d != 2 {
		t.Fatalf("TTL did not force re-download (p=%d d=%d, reqs=%v)", p, d, ft.reqs)
	}
}

// An ecosystem absent from ecosystems.txt is osv_missing — a documented
// gap, not an error — and no dump request is made.
func TestFetchMissingEcosystem(t *testing.T) {
	dir := t.TempDir()
	ft := &fakeTransport{}
	ft.handler = func(req *http.Request) fakeResp {
		switch req.URL.Path {
		case "/osv/ecosystems.txt":
			return fakeResp{body: "npm\nPyPI\n"}
		}
		t.Fatalf("unexpected request %s", req.URL)
		return fakeResp{status: http.StatusNotFound}
	}
	out, err := Acquire(context.Background(), fetchOpts(ft, dir))
	if err != nil {
		t.Fatalf("osv_missing returned an error: %v", err)
	}
	if out.Status != StatusOSVMissing || out.Feed != nil {
		t.Fatalf("want osv_missing, got %+v", out)
	}
	if len(ft.reqs) != 1 {
		t.Fatalf("dump request made for a missing ecosystem: %v", ft.reqs)
	}
}

// A dead source serves the hash-verified cache and says so; the recorded
// check timestamp stays at the cached value.
func TestFetchFallsBackToCache(t *testing.T) {
	dir := t.TempDir()
	dump := dumpBody(t)
	checked := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ft := &fakeTransport{}
	ft.handler = func(req *http.Request) fakeResp {
		switch req.URL.Path {
		case "/osv/ecosystems.txt":
			return fakeResp{body: testEcosystems}
		case "/osv/Go/all.zip":
			return fakeResp{body: dump}
		}
		return fakeResp{status: http.StatusNotFound}
	}
	o := fetchOpts(ft, dir)
	o.Now = func() time.Time { return checked }
	if _, err := Acquire(context.Background(), o); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}
	// Now the mirror dies.
	ft.handler = func(req *http.Request) fakeResp {
		return fakeResp{failErr: fmt.Errorf("connection refused")}
	}
	later := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	o.Now = func() time.Time { return later }
	out, err := Acquire(context.Background(), o)
	if err != nil || out.Feed == nil {
		t.Fatalf("fallback fetch: %+v %v", out, err)
	}
	if !out.CacheFallback {
		t.Fatal("fallback not marked")
	}
	if !out.Prov.CheckedAt.Equal(checked) {
		t.Fatalf("fallback refreshed the check time: %v want %v", out.Prov.CheckedAt, checked)
	}
	if res := out.Feed.ResolveImports("GHSA-x", nil, "example.com/m"); !res.OK {
		t.Fatalf("fallback feed unusable: %+v", res)
	}
}

// A dead source with no cache fails closed.
func TestFetchNoCacheFails(t *testing.T) {
	ft := &fakeTransport{}
	ft.handler = func(req *http.Request) fakeResp {
		return fakeResp{failErr: fmt.Errorf("connection refused")}
	}
	out, err := Acquire(context.Background(), fetchOpts(ft, t.TempDir()))
	if err != nil {
		t.Fatalf("expected outcome, not error: %v", err)
	}
	if out.Status != StatusFeedError || out.Feed != nil {
		t.Fatalf("want feed_error, got %+v", out)
	}
}

// A corrupted cache (digest mismatch) is not served on fallback.
func TestFetchCorruptCacheNotServed(t *testing.T) {
	dir := t.TempDir()
	dump := dumpBody(t)
	ft := &fakeTransport{}
	ft.handler = func(req *http.Request) fakeResp {
		switch req.URL.Path {
		case "/osv/ecosystems.txt":
			return fakeResp{body: testEcosystems}
		case "/osv/Go/all.zip":
			return fakeResp{body: dump}
		}
		return fakeResp{status: http.StatusNotFound}
	}
	if _, err := Acquire(context.Background(), fetchOpts(ft, dir)); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}
	// Corrupt the cached zip.
	zipPath := dir + "/Go.zip"
	b, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, append(b, 1, 2, 3), 0o644); err != nil {
		t.Fatal(err)
	}
	ft.handler = func(req *http.Request) fakeResp {
		return fakeResp{failErr: fmt.Errorf("connection refused")}
	}
	out, err := Acquire(context.Background(), fetchOpts(ft, dir))
	if err != nil {
		t.Fatalf("expected outcome, not error: %v", err)
	}
	if out.Feed != nil || out.Status != StatusFeedError {
		t.Fatalf("corrupt cache served: %+v", out)
	}
}

// The proxy choice is an observable transport property: the default
// client honours the environment, NoProxy makes requests direct.
func TestHTTPClientProxyModes(t *testing.T) {
	d := Options{}.client()
	tr, ok := d.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("default client does not honour the proxy environment")
	}
	np := Options{NoProxy: true}.client()
	tr2, ok := np.Transport.(*http.Transport)
	if !ok || tr2.Proxy != nil {
		t.Fatal("NoProxy client still consults the proxy environment")
	}
}
