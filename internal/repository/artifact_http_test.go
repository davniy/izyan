package repository

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

const artifactTestCredentials = "testuser:testsecret"

// tlsArtifactServer serves a fixed payload behind HTTPS and records what
// arrived on the wire for credential assertions.
type tlsArtifactServer struct {
	*httptest.Server
	payload    []byte
	statusCode int
	lastAuth   string
	sawQuery   string
}

func newTLSArtifactServer(t *testing.T, payload []byte) *tlsArtifactServer {
	t.Helper()
	s := &tlsArtifactServer{payload: payload, statusCode: http.StatusOK}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lastAuth = r.Header.Get("Authorization")
		s.sawQuery = r.URL.RawQuery
		if s.statusCode != http.StatusOK {
			w.WriteHeader(s.statusCode)
			fmt.Fprintln(w, "denied")
			return
		}
		w.Write(s.payload)
	}))
	t.Cleanup(s.Server.Close)
	return s
}

func urlArtifactOpts(t *testing.T, dir, url string, client *http.Client) ArtifactOptions {
	t.Helper()
	t.Setenv(DefaultArtifactCredentialsEnv, artifactTestCredentials)
	return ArtifactOptions{
		URL:        url,
		CacheDir:   filepath.Join(dir, "cache"),
		httpClient: client,
	}
}

func TestArtifactURL_HTTPSBinary(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	srv := newTLSArtifactServer(t, readFileBytes(t, exe))
	opts := urlArtifactOpts(t, dir, srv.URL+"/dist/app", srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s/%q", res.Status, res.Reason)
	}
	if !strings.HasPrefix(res.Evidence.SelectedVersion, "go") {
		t.Fatalf("version = %q", res.Evidence.SelectedVersion)
	}
	wantSHA, _, _ := hashFileSHA256(context.Background(), exe)
	if res.Evidence.ArtifactSHA256 != wantSHA {
		t.Fatalf("sha = %s, want %s", res.Evidence.ArtifactSHA256, wantSHA)
	}
	if srv.lastAuth == "" {
		t.Fatal("authorization header not sent")
	}
	// The recorded source reference carries no query and no credentials.
	it := itemAt(t, res.Evidence.Items, domain.GoVersionSourceBinary)
	if strings.Contains(it.Location, "testsecret") || strings.ContainsAny(it.Location, "?#") {
		t.Fatalf("source ref leaks: %q", it.Location)
	}
}

func TestArtifactURL_MissingCredentials(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, []byte("x"))
	opts := urlArtifactOpts(t, dir, srv.URL+"/a", srv.Client())
	t.Setenv(DefaultArtifactCredentialsEnv, "")
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactCredentialsMissing)
	if srv.lastAuth != "" {
		t.Fatal("request reached server without credentials")
	}
}

func TestArtifactURL_MalformedCredentials(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, []byte("x"))
	opts := urlArtifactOpts(t, dir, srv.URL+"/a", srv.Client())
	t.Setenv(DefaultArtifactCredentialsEnv, "justauser")
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactCredentialsMissing)
}

func TestArtifactURL_Unauthorized(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, []byte("x"))
	srv.statusCode = http.StatusUnauthorized
	opts := urlArtifactOpts(t, dir, srv.URL+"/a", srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactHTTPUnauthorized)
}

func TestArtifactURL_DownloadFailed(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, []byte("x"))
	url := srv.URL + "/a"
	srv.Close()
	opts := urlArtifactOpts(t, dir, url, srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactDownloadFailed)
}

func TestArtifactURL_InvalidSchemes(t *testing.T) {
	dir := t.TempDir()
	for _, u := range []string{
		"http://example.invalid/a.zip",      // plain HTTP is never allowed
		"ftp://example.invalid/a.zip",       //
		"https://user:pw@example.invalid/a", // credentials in URL refused
		"notaurl",
	} {
		opts := urlArtifactOpts(t, dir, u, nil)
		res, err := ResolveReleaseArtifact(context.Background(), opts)
		wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactURLInvalid)
	}
}

func TestArtifactURL_RedirectDowngradeRefused(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(readFileBytes(t, exe))
	}))
	defer plain.Close()
	srv := &tlsArtifactServer{}
	srv.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/stolen", http.StatusFound)
	}))
	defer srv.Close()
	opts := urlArtifactOpts(t, dir, srv.Server.URL+"/a", srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	// Redirect to HTTP must never be followed.
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactDownloadFailed)
}

func TestArtifactURL_SameHostHTTPSRedirect(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	payload := readFileBytes(t, exe)
	srv := &tlsArtifactServer{}
	srv.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.lastAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/real" {
			w.Write(payload)
			return
		}
		http.Redirect(w, r, srv.Server.URL+"/real", http.StatusFound)
	}))
	defer srv.Close()
	opts := urlArtifactOpts(t, dir, srv.Server.URL+"/entry", srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("same-host https redirect = %s/%q err=%v", res.Status, res.Reason, err)
	}
	if srv.lastAuth == "" {
		t.Fatal("authorization not forwarded on same-host https redirect")
	}
}

func TestArtifactURL_DownloadSizeLimit(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, make([]byte, 2048))
	opts := urlArtifactOpts(t, dir, srv.URL+"/a", srv.Client())
	opts.MaxDownloadBytes = 512
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactSizeLimit)
}

func TestArtifactURL_Timeout(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, []byte("x"))
	opts := urlArtifactOpts(t, dir, srv.URL+"/a", srv.Client())
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	res, err := ResolveReleaseArtifact(ctx, opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactTimeout)
}

// The URL→content index lets a repeated request resolve entirely from the
// cache: after the server is gone the same URL still resolves, and no
// credential material is persisted in the cache.
func TestArtifactURL_CacheReuseBySHA(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	srv := newTLSArtifactServer(t, readFileBytes(t, exe))
	url := srv.URL + "/dist/app"
	opts := urlArtifactOpts(t, dir, url, srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("first resolve = %s/%q err=%v", res.Status, res.Reason, err)
	}
	sha := res.Evidence.ArtifactSHA256
	srv.Close()
	res, err = ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("cache reuse = %s/%q err=%v", res.Status, res.Reason, err)
	}
	if res.Evidence.ArtifactSHA256 != sha {
		t.Fatalf("reused sha = %s", res.Evidence.ArtifactSHA256)
	}
	// Cache metadata contains no credential material. The artifact blob
	// itself is the downloaded file — only index/meta may not leak.
	filepath.Walk(opts.CacheDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.Name() != "index.json" && info.Name() != "meta.json" {
			return nil
		}
		if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), "testsecret") {
			t.Fatalf("credential leaked into cache file %s", p)
		}
		return nil
	})
}

// Credentials must never surface: not in the resolution, not in the
// marshaled evidence, not in cache metadata; the URL's query is stripped
// from the recorded source reference.
func TestArtifactURL_CredentialRedaction(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, []byte("x"))
	srv.statusCode = http.StatusUnauthorized
	opts := urlArtifactOpts(t, dir, srv.URL+"/a?token=testsecret&x=1", srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	wantReason(t, res, err, domain.ReleaseStatusNotRun, domain.ReleaseReasonArtifactHTTPUnauthorized)
	if strings.Contains(marshaledResolution(t, res), "testsecret") {
		t.Fatal("credential in marshaled evidence")
	}
	// A failed run must not persist the secret anywhere under the cache.
	filepath.Walk(opts.CacheDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), "testsecret") {
			t.Fatalf("credential persisted in %s", p)
		}
		return nil
	})
}

// Credentials are scoped to an origin, not to a hostname: a redirect to
// another port on the same host targets a different service, and Go
// forwards the Authorization header when the hostname matches.
func TestArtifactURL_CrossOriginRedirectRefused(t *testing.T) {
	dir := t.TempDir()
	exe := testBinary(t)
	target := newTLSArtifactServer(t, readFileBytes(t, exe))
	redirector := &tlsArtifactServer{}
	redirector.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/real", http.StatusFound)
	}))
	defer redirector.Close()
	ru, rerr := url.Parse(redirector.URL)
	tu, terr := url.Parse(target.URL)
	if rerr != nil || terr != nil || ru.Hostname() != tu.Hostname() || ru.Port() == tu.Port() {
		t.Skipf("need same host, different port: %v vs %v", ru, tu)
	}
	// A client that trusts both test certificates, so the only thing that
	// can stop the redirect is the origin policy itself.
	pool := x509.NewCertPool()
	pool.AddCert(redirector.Certificate())
	pool.AddCert(target.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	opts := urlArtifactOpts(t, dir, redirector.URL+"/entry", client)
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err == nil && res.Status == domain.ReleaseStatusResolved {
		t.Fatalf("cross-origin redirect resolved: %+v", res)
	}
	if target.lastAuth != "" {
		t.Fatalf("authorization reached a different origin: %q", target.lastAuth)
	}
}

// A cache slot is trusted only while its bytes still hash to the
// recorded digest; a tampered blob must not supply authoritative
// build-info evidence.
func TestArtifactURL_CacheReuseRejectsTamperedBlob(t *testing.T) {
	dir := t.TempDir()
	srv := newTLSArtifactServer(t, readFileBytes(t, testBinary(t)))
	opts := urlArtifactOpts(t, dir, srv.URL+"/dist/app", srv.Client())
	res, err := ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved {
		t.Fatalf("first resolve = %s/%q err=%v", res.Status, res.Reason, err)
	}
	sha := res.Evidence.ArtifactSHA256
	slot := filepath.Join(opts.CacheDir, sha)
	if err := os.WriteFile(filepath.Join(slot, "artifact"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if meta := readArtifactMeta(slot, sha, true); meta != nil {
		t.Fatal("tampered cache slot must not be trusted")
	}
	res, err = ResolveReleaseArtifact(context.Background(), opts)
	if err != nil || res.Status != domain.ReleaseStatusResolved || res.Evidence.ArtifactSHA256 != sha {
		t.Fatalf("re-download after tamper = %s/%q err=%v", res.Status, res.Reason, err)
	}
	got, _, err := hashFileSHA256(context.Background(), filepath.Join(slot, "artifact"))
	if err != nil || got != sha {
		t.Fatalf("cached blob not restored: %s err=%v", got, err)
	}
}
