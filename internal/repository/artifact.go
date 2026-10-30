package repository

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/davniy/izyan/internal/domain"
)

// DefaultArtifactCredentialsEnv is the default environment variable an
// artifact URL credential is read from. The value is `username:password`
// for HTTP Basic authentication. The credential is sent in an
// Authorization header only: it never enters a URL, an error, a log line,
// a report, a manifest, or the cache.
const DefaultArtifactCredentialsEnv = "IZYAN_ARTIFACT_CREDENTIALS"

// Bounded acquisition defaults. A caller may only lower them.
const (
	defaultArtifactTimeout    = 10 * time.Minute
	maxArtifactDownloadBytes  = int64(2) << 30 // 2 GiB
	maxArtifactExtractedBytes = int64(8) << 30 // 8 GiB
	maxArtifactEntries        = 20000
	maxArtifactFileBytes      = int64(512) << 20 // 512 MiB per candidate
	maxArtifactNesting        = 4
)

// ArtifactOptions configures the bounded release-artifact channel. Exactly
// one of Path (local file: a Go binary or a ZIP distribution archive) or
// URL (HTTPS download, Basic auth via the credentials environment
// variable) selects the artifact.
type ArtifactOptions struct {
	Path           string
	URL            string
	CredentialsEnv string
	CacheDir       string
	Timeout        time.Duration
	// MaxDownloadBytes bounds the artifact file itself (downloaded or
	// local). MaxExtractedBytes bounds the cumulative unpacked payload.
	// MaxArchiveEntries bounds the total archive member count, including
	// nested archives. Zero means the package default; the defaults are
	// ceilings — only lower limits are honored.
	MaxDownloadBytes  int64
	MaxExtractedBytes int64
	MaxArchiveEntries int
	// ProductModule is the analyzed product's module path; when several
	// archive members carry build info, a candidate whose main module
	// matches is preferred.
	ProductModule string
	// ForbidDirs lists directories the artifact cache must not live under
	// (the analyzed snapshot root and the report output directory). A
	// CacheDir inside any of them is rejected before any artifact work.
	ForbidDirs []string

	httpClient *http.Client // test seam: supplies TLS trust for httptest servers
}

func (o ArtifactOptions) withDefaults() ArtifactOptions {
	if o.Timeout <= 0 {
		o.Timeout = defaultArtifactTimeout
	}
	if o.MaxDownloadBytes <= 0 {
		o.MaxDownloadBytes = maxArtifactDownloadBytes
	}
	if o.MaxExtractedBytes <= 0 {
		o.MaxExtractedBytes = maxArtifactExtractedBytes
	}
	if o.MaxArchiveEntries <= 0 {
		o.MaxArchiveEntries = maxArtifactEntries
	}
	if o.CredentialsEnv == "" {
		o.CredentialsEnv = DefaultArtifactCredentialsEnv
	}
	return o
}

// ArtifactResolution is the outcome of the release-artifact channel.
// Every expected input, download, archive-safety, and build-info failure
// is reported here as an explicit fail-closed status with a named reason
// code — never hidden in a nil result. Only unexpected programmer or I/O
// errors travel through the error return.
type ArtifactResolution struct {
	Evidence domain.ReleaseEvidenceSummary
	Status   domain.ReleaseEvidenceStatus
	Reason   string
	// Target is the selected binary's recorded build-target fact when
	// debug.BuildInfo.Settings carried a complete GOOS/GOARCH/
	// CGO_ENABLED shape. It is bound to the artifact SHA-256, the binary
	// member and the build-info digest; nil means the artifact recorded
	// no usable target and the service must fall through to the next
	// precedence source.
	Target *domain.ProductTarget
}

// artifactReject carries an expected fail-closed outcome: a named reason
// code, an optional sanitized detail error, and — when the artifact was
// already hashed or candidates were already inspected — the provenance
// that may still be recorded. Details never contain credentials.
type artifactReject struct {
	reason string
	err    error
	items  []domain.ReleaseEvidenceItem
	sha    string
}

func (e *artifactReject) Error() string {
	if e.err != nil {
		return e.reason + ": " + e.err.Error()
	}
	return e.reason
}

func (e *artifactReject) Unwrap() error { return e.err }

func rejectArtifact(reason string, err error) *artifactReject {
	return &artifactReject{reason: reason, err: err}
}

// ResolveReleaseArtifact resolves the release-artifact channel requested
// by opts: it acquires a local file or HTTPS download under the configured
// bounds, safely materializes ZIP content into the external
// content-addressed cache, locates Go binaries (including inside nested
// stored ZIPs), reads their embedded build info, and selects the release
// candidate. The result is an AUTHORITATIVE evidence summary, or an
// explicit NOT_RUN/NOT_REQUESTED outcome with a named reason code.
func ResolveReleaseArtifact(ctx context.Context, opts ArtifactOptions) (ArtifactResolution, error) {
	opts = opts.withDefaults()
	res, err := resolveReleaseArtifact(ctx, opts)
	var rej *artifactReject
	switch {
	case err == nil:
		return res, nil
	case errors.As(err, &rej):
		out := ArtifactResolution{Status: domain.ReleaseStatusNotRun, Reason: rej.reason}
		out.Evidence.Status = domain.ReleaseStatusNotRun
		out.Evidence.ReasonCode = rej.reason
		out.Evidence.Items = rej.items
		out.Evidence.ArtifactSHA256 = rej.sha
		return out, nil
	default:
		return ArtifactResolution{}, err
	}
}

func resolveReleaseArtifact(ctx context.Context, opts ArtifactOptions) (ArtifactResolution, error) {
	if opts.Path != "" && opts.URL != "" {
		return ArtifactResolution{}, &artifactReject{reason: domain.ReleaseReasonArtifactURLInvalid,
			err: errors.New("artifact path and URL are mutually exclusive")}
	}
	if opts.Path == "" && opts.URL == "" {
		res := ArtifactResolution{Status: domain.ReleaseStatusNotRequested, Reason: domain.ReleaseReasonArtifactNotRequested}
		res.Evidence.Status = domain.ReleaseStatusNotRequested
		res.Evidence.ReasonCode = domain.ReleaseReasonArtifactNotRequested
		return res, nil
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cacheDir, err := prepareArtifactCache(opts)
	if err != nil {
		return ArtifactResolution{}, err
	}
	var acq *acquiredArtifact
	if opts.Path != "" {
		acq, err = acquireLocalArtifact(ctx, opts, cacheDir)
	} else {
		acq, err = acquireURLArtifact(ctx, opts, cacheDir)
	}
	if err != nil {
		return ArtifactResolution{}, err
	}
	if err := materializeArtifact(ctx, opts, acq); err != nil {
		return ArtifactResolution{}, err
	}
	cands, err := inspectCandidates(ctx, acq)
	if err != nil {
		return ArtifactResolution{}, err
	}
	if len(cands) == 0 {
		reason := domain.ReleaseReasonArtifactNoGoBinary
		if !acq.archive {
			reason = domain.ReleaseReasonArtifactBuildInfoUnreadable
		}
		return ArtifactResolution{}, &artifactReject{reason: reason, sha: acq.sha256}
	}
	selected, recorded, ok := selectArtifactCandidate(cands, opts.ProductModule)
	items, err := candidateItems(ctx, acq, recorded)
	if err != nil {
		return ArtifactResolution{}, err
	}
	if !ok {
		return ArtifactResolution{}, &artifactReject{
			reason: domain.ReleaseReasonArtifactAmbiguousBinary,
			items:  items,
			sha:    acq.sha256,
		}
	}
	summary := ResolveReleaseEvidence(items)
	if summary.Status != domain.ReleaseStatusResolved {
		// Candidates carried build info but no usable toolchain version:
		// the channel produced no authoritative release fact.
		return ArtifactResolution{}, &artifactReject{
			reason: domain.ReleaseReasonArtifactBuildInfoUnreadable,
			items:  items,
			sha:    acq.sha256,
		}
	}
	summary.Modules = releaseModules(selected.bi)
	summary.Target = buildInfoTarget(acq, selected)
	res := ArtifactResolution{Evidence: summary, Status: summary.Status, Reason: summary.ReasonCode, Target: summary.Target}
	return res, nil
}

// acquiredArtifact is the artifact file after acquisition: either the
// caller-supplied local path or the content-addressed cache blob. When
// meta is non-nil the cache slot already holds complete materialized
// content and extraction is skipped.
type acquiredArtifact struct {
	sourceRef  string // sanitized provenance reference, never credentials
	sourceFile string // local artifact path or cached blob path
	sha256     string
	size       int64
	cacheDir   string
	slot       string // cacheDir/sha256
	meta       *artifactMeta
	archive    bool
}

// artifactMeta is the cache commit record. It contains only the source
// kind, the sanitized source reference, size, SHA-256, and member
// metadata — never credentials, URLs with query, or absolute paths.
type artifactMeta struct {
	Kind      string           `json:"kind"` // "local" | "url"
	SourceRef string           `json:"source_ref"`
	Size      int64            `json:"size"`
	SHA256    string           `json:"sha256"`
	Archive   bool             `json:"archive,omitempty"`
	Members   []artifactMember `json:"members,omitempty"`
}

// artifactMember records one extracted regular file: the logical archive
// member identity (nested members use "outer.zip/inner" form) and its
// location inside the slot's tree directory.
type artifactMember struct {
	Member string `json:"member"`
	Path   string `json:"path"` // slash-separated path relative to the slot's tree dir
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// artifactCtxErr maps context termination inside acquisition work to the
// named timeout outcome; caller cancellation propagates unchanged.
func artifactCtxErr(ctx context.Context) error {
	switch ctx.Err() {
	case nil:
		return nil
	case context.DeadlineExceeded:
		return rejectArtifact(domain.ReleaseReasonArtifactTimeout, ctx.Err())
	default:
		return ctx.Err()
	}
}

// artifactNetErr classifies download/transport failures. The url.Error
// wrapper is stripped so detail text never echoes a request URL — query
// parameters may carry operator-supplied tokens.
func artifactNetErr(ctx context.Context, err error) error {
	if cerr := artifactCtxErr(ctx); cerr != nil {
		return cerr
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return rejectArtifact(domain.ReleaseReasonArtifactTimeout, ue.Err)
		}
		return rejectArtifact(domain.ReleaseReasonArtifactDownloadFailed, ue.Err)
	}
	return rejectArtifact(domain.ReleaseReasonArtifactDownloadFailed, err)
}

// prepareArtifactCache resolves the external content-addressed cache
// directory, rejecting locations inside the snapshot or output directory.
func prepareArtifactCache(opts ArtifactOptions) (string, error) {
	dir := opts.CacheDir
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "izyan-artifacts")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("artifact cache dir: %w", err)
	}
	for _, forbid := range opts.ForbidDirs {
		fabs, err := filepath.Abs(forbid)
		if err != nil {
			return "", fmt.Errorf("artifact cache guard dir: %w", err)
		}
		rel, err := filepath.Rel(fabs, abs)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)) {
			return "", fmt.Errorf("artifact cache dir %q must not be inside %q", abs, fabs)
		}
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("artifact cache dir: %w", err)
	}
	// Resolve the created directory and each forbidden root physically. This
	// catches symlinks and case-folding aliases that lexical paths miss.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("artifact cache dir: %w", err)
	}
	for _, forbid := range opts.ForbidDirs {
		fabs, err := filepath.Abs(forbid)
		if err != nil {
			continue
		}
		if containedIn(fabs, real) {
			return "", fmt.Errorf("artifact cache dir %q must not be inside %q", real, fabs)
		}
	}
	st, err := os.Stat(real)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("artifact cache dir %q is not a directory", real)
	}
	return real, nil
}

// acquireLocalArtifact stats and hashes a local artifact path: the
// SHA-256 is recorded for reproducibility and doubles as the cache key.
func acquireLocalArtifact(ctx context.Context, opts ArtifactOptions, cacheDir string) (*acquiredArtifact, error) {
	path := opts.Path
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, rejectArtifact(domain.ReleaseReasonArtifactPathMissing, err)
	case err != nil:
		return nil, rejectArtifact(domain.ReleaseReasonArtifactPathUnreadable, err)
	case st.IsDir():
		return nil, rejectArtifact(domain.ReleaseReasonArtifactPathUnreadable,
			fmt.Errorf("%s is a directory", path))
	}
	if st.Size() > opts.MaxDownloadBytes {
		return nil, rejectArtifact(domain.ReleaseReasonArtifactSizeLimit,
			fmt.Errorf("artifact size %d exceeds limit", st.Size()))
	}
	sha, size, err := hashFileSHA256(ctx, path)
	if err != nil {
		if cerr := artifactCtxErr(ctx); cerr != nil {
			return nil, cerr
		}
		return nil, rejectArtifact(domain.ReleaseReasonArtifactPathUnreadable, err)
	}
	acq := &acquiredArtifact{
		sourceRef:  ProvenanceLocalRef(path),
		sourceFile: path,
		sha256:     sha,
		size:       size,
		cacheDir:   cacheDir,
		slot:       filepath.Join(cacheDir, sha),
	}
	acq.meta = readArtifactMeta(acq.slot, sha, false)
	return acq, nil
}

// acquireURLArtifact downloads an HTTPS artifact under the configured
// bounds into the content-addressed cache, reusing a previously cached
// copy when the same URL was already fetched. Credentials come only from
// the named environment variable and travel only in the Authorization
// header.
func acquireURLArtifact(ctx context.Context, opts ArtifactOptions, cacheDir string) (*acquiredArtifact, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		// Never echo the raw URL: it may carry userinfo or query tokens.
		return nil, rejectArtifact(domain.ReleaseReasonArtifactURLInvalid,
			errors.New("URL must be https://host/path without userinfo"))
	}
	u.Fragment = ""
	if opts.CredentialsEnv == "" {
		return nil, rejectArtifact(domain.ReleaseReasonArtifactCredentialsMissing,
			errors.New("empty credentials environment variable name"))
	}
	val, ok := os.LookupEnv(opts.CredentialsEnv)
	user, pass, found := strings.Cut(strings.TrimSpace(val), ":")
	if !ok || !found || user == "" {
		return nil, rejectArtifact(domain.ReleaseReasonArtifactCredentialsMissing,
			fmt.Errorf("environment variable %s is unset or not in username:password form", opts.CredentialsEnv))
	}
	sourceRef := sanitizeURLRef(u)
	urlHash := sha256.Sum256([]byte(u.String()))
	key := hex.EncodeToString(urlHash[:])
	if sha := artifactIndexLookup(cacheDir, key); sha != "" {
		slot := filepath.Join(cacheDir, sha)
		if meta := readArtifactMeta(slot, sha, true); meta != nil {
			return &acquiredArtifact{
				sourceRef:  sourceRef,
				sourceFile: filepath.Join(slot, "artifact"),
				sha256:     sha,
				size:       meta.Size,
				cacheDir:   cacheDir,
				slot:       slot,
				meta:       meta,
			}, nil
		}
		artifactIndexRemove(cacheDir, key)
	}
	tmp, err := os.CreateTemp(cacheDir, ".dl-*")
	if err != nil {
		return nil, fmt.Errorf("artifact download temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		tmp.Close()
		return nil, rejectArtifact(domain.ReleaseReasonArtifactURLInvalid, err)
	}
	req.SetBasicAuth(user, pass)
	resp, err := artifactHTTPClient(opts).Do(req)
	if err != nil {
		tmp.Close()
		return nil, artifactNetErr(ctx, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		tmp.Close()
		return nil, rejectArtifact(domain.ReleaseReasonArtifactHTTPUnauthorized,
			fmt.Errorf("HTTP status %d", resp.StatusCode))
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		tmp.Close()
		return nil, rejectArtifact(domain.ReleaseReasonArtifactDownloadFailed,
			fmt.Errorf("HTTP status %d", resp.StatusCode))
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, opts.MaxDownloadBytes+1))
	tmp.Close()
	if err != nil {
		return nil, artifactNetErr(ctx, err)
	}
	if n > opts.MaxDownloadBytes {
		return nil, rejectArtifact(domain.ReleaseReasonArtifactSizeLimit,
			fmt.Errorf("download exceeds %d bytes", opts.MaxDownloadBytes))
	}
	sha := hex.EncodeToString(h.Sum(nil))
	slot := filepath.Join(cacheDir, sha)
	if err := os.MkdirAll(slot, 0o700); err != nil {
		return nil, fmt.Errorf("artifact cache slot: %w", err)
	}
	blob := filepath.Join(slot, "artifact")
	os.Remove(blob)
	if err := os.Rename(tmpName, blob); err != nil {
		return nil, fmt.Errorf("artifact cache store: %w", err)
	}
	artifactIndexStore(cacheDir, key, sha)
	return &acquiredArtifact{
		sourceRef:  sourceRef,
		sourceFile: blob,
		sha256:     sha,
		size:       n,
		cacheDir:   cacheDir,
		slot:       slot,
	}, nil
}

// artifactHTTPClient builds the download client: normal certificate
// verification, and redirects restricted to HTTPS on the original host.
func artifactHTTPClient(opts ArtifactOptions) *http.Client {
	base := http.DefaultClient
	if opts.httpClient != nil {
		base = opts.httpClient
	}
	c := *base
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect to non-HTTPS URL refused")
		}
		// Credentials are scoped to the exact origin. A redirect to the
		// same hostname on another port targets a different service, and
		// Go forwards the Authorization header when the host matches, so
		// the port must be part of the comparison.
		if artifactOrigin(req.URL) != artifactOrigin(via[0].URL) {
			return errors.New("redirect to a different origin refused")
		}
		return nil
	}
	return &c
}

// ProvenanceLocalRef is the provenance label for an operator-supplied
// local path (artifact, release binary or release-metadata document).
// Only the basename is recorded: the absolute path is machine-specific
// and must not leak into reports, run manifests or cache metadata, while
// the content digest — which is what actually makes the run reproducible
// — is carried alongside it.
func ProvenanceLocalRef(path string) string {
	trimmed := strings.TrimSpace(path)
	base := filepath.Base(trimmed)
	if base == "" || base == "." || base == ".." || base == "/" ||
		strings.ContainsAny(base, `/\`) {
		// Never echo a bare root, a parent hop, or anything that still
		// carries path structure.
		return "local:input"
	}
	for _, r := range base {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return "local:input"
		}
	}
	return "local:" + base
}

// artifactOrigin is the scheme://host:port origin of a URL, with the
// scheme's default port substituted when the URL omits one.
func artifactOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// sanitizeURLRef is the only URL form that may be recorded: scheme, host,
// and path, with userinfo, query, and fragment stripped.
func sanitizeURLRef(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}).String()
}

// materializeArtifact determines the artifact kind and, for ZIP archives,
// extracts content into the cache slot's tree directory — unless a
// complete slot was already reused. It writes the commit metadata last:
// a slot without meta.json is treated as incomplete and rebuilt.
func materializeArtifact(ctx context.Context, opts ArtifactOptions, acq *acquiredArtifact) error {
	if acq.meta != nil {
		acq.archive = acq.meta.Archive
		return nil
	}
	isZip, err := sniffZipMagic(acq.sourceFile)
	if err != nil {
		return rejectArtifact(domain.ReleaseReasonArtifactPathUnreadable, err)
	}
	acq.archive = isZip
	kind := "local"
	if acq.slot != "" && acq.sourceFile == filepath.Join(acq.slot, "artifact") {
		kind = "url"
	}
	meta := &artifactMeta{Kind: kind, SourceRef: acq.sourceRef, Size: acq.size, SHA256: acq.sha256}
	if !isZip {
		if acq.size > maxArtifactFileBytes {
			return rejectArtifact(domain.ReleaseReasonArtifactSizeLimit,
				fmt.Errorf("candidate file size %d exceeds limit", acq.size))
		}
		if kind == "url" {
			meta.Archive = false
			if err := writeArtifactMeta(acq.slot, meta); err != nil {
				return err
			}
		}
		return nil
	}
	meta.Archive = true
	tree := filepath.Join(acq.slot, "tree")
	tmp, err := os.MkdirTemp(acq.cacheDir, ".ext-*")
	if err != nil {
		return fmt.Errorf("artifact extract temp: %w", err)
	}
	budget := &zipBudget{maxEntries: opts.MaxArchiveEntries, compressed: opts.MaxDownloadBytes, extracted: opts.MaxExtractedBytes}
	err = extractZipInto(ctx, acq.sourceFile, tmp, "", "", budget, meta, 0)
	if err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := os.MkdirAll(acq.slot, 0o700); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("artifact cache slot: %w", err)
	}
	os.RemoveAll(tree)
	if err := os.Rename(tmp, tree); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("artifact extract store: %w", err)
	}
	if err := writeArtifactMeta(acq.slot, meta); err != nil {
		return err
	}
	acq.meta = meta
	return nil
}

// zipBudget accumulates entry, compressed-size, and extracted-size bounds
// zipBudget accumulates entry, compressed-size, and extracted-size bounds
// across an archive and every nested archive it contains.
type zipBudget struct {
	entries    int
	maxEntries int
	compressed int64
	extracted  int64
}

// extractZipInto unpacks zipPath under destRoot: regular members go to
// destRoot/m/<name>, nested archives are recursively expanded under
// destRoot/x/<k>/ with member identities recorded as "outer/inner".
// relBase is destRoot's slash-separated path relative to the slot's tree
// root so recorded member paths stay resolvable on cache reuse. Every
// unsafe shape — traversal, symlink, non-regular entry, corrupt or lying
// archive, excessive nesting — is a fail-closed ARCHIVE_UNSAFE; every
// exceeded bound is SIZE_LIMIT.
func extractZipInto(ctx context.Context, zipPath, destRoot, relBase, prefix string, budget *zipBudget, meta *artifactMeta, depth int) error {
	if err := artifactCtxErr(ctx); err != nil {
		return err
	}
	if depth > maxArtifactNesting {
		return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe,
			fmt.Errorf("nested archive depth exceeds %d", maxArtifactNesting))
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
	}
	defer zr.Close()
	membersDir := filepath.Join(destRoot, "m")
	if err := os.MkdirAll(membersDir, 0o700); err != nil {
		return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
	}
	expandSeq := 0
	for _, f := range zr.File {
		if err := artifactCtxErr(ctx); err != nil {
			return err
		}
		budget.entries++
		if budget.entries > budget.maxEntries {
			return rejectArtifact(domain.ReleaseReasonArtifactSizeLimit,
				fmt.Errorf("archive exceeds %d entries", budget.maxEntries))
		}
		if !safeMemberName(f.Name) {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe,
				fmt.Errorf("unsafe archive member name %q", f.Name))
		}
		if f.CompressedSize64 > uint64(budget.compressed) {
			return rejectArtifact(domain.ReleaseReasonArtifactSizeLimit,
				fmt.Errorf("archive compressed size exceeds limit"))
		}
		budget.compressed -= int64(f.CompressedSize64)
		if f.Mode().IsDir() || strings.HasSuffix(f.Name, "/") {
			continue
		}
		if !f.Mode().IsRegular() {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe,
				fmt.Errorf("non-regular archive member %q", f.Name))
		}
		if f.UncompressedSize64 > uint64(budget.extracted) {
			return rejectArtifact(domain.ReleaseReasonArtifactSizeLimit,
				fmt.Errorf("archive extracted size exceeds limit"))
		}
		target := filepath.Join(membersDir, filepath.FromSlash(f.Name))
		if !containedIn(membersDir, target) {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe,
				fmt.Errorf("archive member escapes destination: %q", f.Name))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
		}
		rc, err := f.Open()
		if err != nil {
			out.Close()
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
		}
		declared := int64(f.UncompressedSize64)
		written, err := io.CopyN(out, rc, declared+1)
		rc.Close()
		out.Close()
		if err != nil && err != io.EOF {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
		}
		if written > declared {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe,
				fmt.Errorf("archive member %q larger than declared", f.Name))
		}
		if written < declared {
			// A member whose content is shorter than the central
			// directory declares is a malformed or truncated archive;
			// accepting it would let a partial payload be inspected as
			// if it were complete.
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe,
				fmt.Errorf("archive member %q is shorter than declared", f.Name))
		}
		budget.extracted -= written
		rel, rerr := filepath.Rel(destRoot, target)
		if rerr != nil {
			return fmt.Errorf("artifact member path: %w", rerr)
		}
		recPath := filepath.ToSlash(rel)
		if relBase != "" {
			recPath = relBase + "/" + recPath
		}
		memberSHA, _, hashErr := hashFileSHA256(ctx, target)
		if hashErr != nil {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, hashErr)
		}
		meta.Members = append(meta.Members, artifactMember{
			Member: prefix + f.Name,
			Path:   recPath,
			Size:   written,
			SHA256: memberSHA,
		})
		nested, err := sniffZipMagic(target)
		if err != nil {
			return rejectArtifact(domain.ReleaseReasonArtifactArchiveUnsafe, err)
		}
		if nested {
			expandDir := filepath.Join(destRoot, "x", itoa(expandSeq))
			expandSeq++
			if err := os.MkdirAll(expandDir, 0o700); err != nil {
				return fmt.Errorf("artifact nested extract dir: %w", err)
			}
			expandBase := joinRelPath(relBase, "x/"+itoa(expandSeq-1))
			if err := extractZipInto(ctx, target, expandDir, expandBase, prefix+f.Name+"/", budget, meta, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// safeMemberName rejects absolute paths, traversal segments, NUL bytes,
// and backslashes (a Windows separator that zip name canonicalization
// does not protect against).
func safeMemberName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.IndexByte(name, 0) >= 0 || strings.Contains(name, `\`) {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// joinRelPath joins tree-root-relative slash paths, tolerating an empty base.
func joinRelPath(base, child string) string {
	if base == "" {
		return child
	}
	return base + "/" + child
}

// containedIn verifies target is physically, strictly inside dir. Existing
// ancestors are compared by file identity, so case folding and symlink aliases
// cannot evade the guard. The target itself may not exist yet during extraction.
func containedIn(dir, target string) bool {
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	for p := absTarget; ; p = filepath.Dir(p) {
		if info, statErr := os.Stat(p); statErr == nil {
			if os.SameFile(dirInfo, info) {
				return p != absTarget
			}
		} else if !os.IsNotExist(statErr) {
			return false
		}
		next := filepath.Dir(p)
		if next == p {
			return false
		}
	}
}

// sniffZipMagic reports whether the file starts with a ZIP local header,
// an empty-archive EOCD, or a spanning marker. Only PK-prefixed files are
// treated as archives; a PK file that fails to open is corrupt, not a
// binary.
func sniffZipMagic(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var magic [4]byte
	n, err := io.ReadFull(f, magic[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	if n < 4 {
		return false, nil
	}
	return magic[0] == 'P' && magic[1] == 'K' &&
		(magic[2] == 0x03 && magic[3] == 0x04 ||
			magic[2] == 0x05 && magic[3] == 0x06 ||
			magic[2] == 0x07 && magic[3] == 0x08), nil
}

// artifactCandidate is a file carrying valid Go build info.
type artifactCandidate struct {
	member string // archive member identity, "" for a bare artifact file
	file   string
	bi     *debug.BuildInfo
	canon  string
	// buildInfoSHA256 is the candidate binary's digest, filled by
	// candidateItems when the accepted pool is hashed. It binds the
	// candidate's build-info facts (modules and target settings) to the
	// exact bytes they were read from.
	buildInfoSHA256 string
}

// inspectCandidates scans extracted members in stable lexical order and
// retains only files with valid Go build info; members above the
// per-candidate size bound are never inspected.
func inspectCandidates(ctx context.Context, acq *acquiredArtifact) ([]*artifactCandidate, error) {
	var files []artifactMember
	if !acq.archive {
		files = []artifactMember{{Member: "", Path: "", Size: acq.size}}
	} else {
		files = append(files, acq.meta.Members...)
		sort.Slice(files, func(i, j int) bool { return files[i].Member < files[j].Member })
	}
	var cands []*artifactCandidate
	for _, m := range files {
		if err := artifactCtxErr(ctx); err != nil {
			return nil, err
		}
		if m.Size > maxArtifactFileBytes {
			continue
		}
		path := acq.sourceFile
		if acq.archive {
			path = filepath.Join(acq.slot, "tree", filepath.FromSlash(m.Path))
		}
		bi, err := buildinfo.ReadFile(path)
		if err != nil || bi == nil {
			continue
		}
		cands = append(cands, &artifactCandidate{member: m.Member, file: path, bi: bi, canon: canonInventory(bi)})
	}
	return cands, nil
}

// selectArtifactCandidate applies the candidate-selection policy: a
// single candidate wins; among several, candidates whose main module
// matches the analyzed product are preferred; if the remaining pool has
// byte-equivalent toolchain and module inventories the lexical first is
// selected and every candidate is recorded; otherwise the artifact is
// ambiguous.
func selectArtifactCandidate(cands []*artifactCandidate, productModule string) (selected *artifactCandidate, recorded []*artifactCandidate, ok bool) {
	if len(cands) == 1 {
		return cands[0], cands, true
	}
	pool := cands
	if productModule != "" {
		var matching []*artifactCandidate
		for _, c := range cands {
			if c.bi.Main.Path == productModule {
				matching = append(matching, c)
			}
		}
		if len(matching) > 0 {
			pool = matching
		}
	}
	if len(pool) == 1 {
		return pool[0], pool, true
	}
	canon := pool[0].canon
	for _, c := range pool[1:] {
		if c.canon != canon {
			return nil, pool, false
		}
	}
	return pool[0], pool, true
}

// canonInventory renders the toolchain and module inventory of a build
// info record for byte-equivalence comparison: Go version, main module,
// and the order-insensitive dependency set including replacements.
func canonInventory(bi *debug.BuildInfo) string {
	var b strings.Builder
	b.WriteString(bi.GoVersion)
	b.WriteByte(0)
	canonModule(&bi.Main, &b)
	deps := make([]*debug.Module, len(bi.Deps))
	copy(deps, bi.Deps)
	var rendered []string
	for _, d := range deps {
		var db strings.Builder
		canonModule(d, &db)
		rendered = append(rendered, db.String())
	}
	sort.Strings(rendered)
	for _, r := range rendered {
		b.WriteString(r)
	}
	return b.String()
}

func canonModule(m *debug.Module, b *strings.Builder) {
	fmt.Fprintf(b, "%s\x00%s\x00%s", m.Path, m.Version, m.Sum)
	if m.Replace != nil {
		b.WriteString("\x00=>\x00")
		canonModule(m.Replace, b)
	}
	b.WriteByte(0)
}

// candidateItems builds the recorded AUTHORITATIVE evidence items for the
// candidate set, hashing each selected-pool binary so the build-info
// provenance is verifiable.
func candidateItems(ctx context.Context, acq *acquiredArtifact, cands []*artifactCandidate) ([]domain.ReleaseEvidenceItem, error) {
	items := make([]domain.ReleaseEvidenceItem, 0, len(cands))
	for _, c := range cands {
		sha, _, err := hashFileSHA256(ctx, c.file)
		if err != nil {
			if cerr := artifactCtxErr(ctx); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("artifact candidate hash: %w", err)
		}
		c.buildInfoSHA256 = sha
		items = append(items, domain.ReleaseEvidenceItem{
			Version:         c.bi.GoVersion,
			Source:          domain.GoVersionSourceBinary,
			TrustClass:      domain.ReleaseTrustAuthoritative,
			Location:        acq.sourceRef,
			ArtifactSHA256:  acq.sha256,
			BinaryMember:    c.member,
			BuildInfoSHA256: sha,
		})
	}
	return items, nil
}

// releaseModules converts embedded build info into the release module
// graph: the main module first, then dependencies, each carrying its
// applied replacement.
func releaseModules(bi *debug.BuildInfo) []domain.ReleaseModule {
	mods := make([]domain.ReleaseModule, 0, len(bi.Deps)+1)
	if bi.Main.Path != "" || bi.Main.Version != "" {
		mods = append(mods, releaseModule(&bi.Main, true))
	}
	for _, d := range bi.Deps {
		mods = append(mods, releaseModule(d, false))
	}
	return mods
}

// buildInfoTarget extracts the selected binary's build-target settings
// from debug.BuildInfo.Settings and binds them to the artifact SHA-256,
// binary member and candidate build-info digest. Every consumed setting
// must be present exactly once: duplicate keys are a recorded-ambiguity
// shape and a GOFLAGS-carried tag set cannot be reconstructed into the
// exact flag value, so both fail closed to nil (no target fact).
func buildInfoTarget(acq *acquiredArtifact, c *artifactCandidate) *domain.ProductTarget {
	if acq == nil || c == nil {
		return nil
	}
	return targetFromBuildInfo(c.bi, acq.sha256, c.buildInfoSHA256, c.member)
}

// targetFromBuildInfo is the single build-info → ProductTarget extraction
// shared by the artifact channel and a plain --binary: the recorded target
// is bound to the artifact digest, the binary member and the build-info
// digest so the observation remains verifiable. It fails closed to nil when
// the settings are duplicate, incomplete or cannot be reconstructed.
func targetFromBuildInfo(bi *debug.BuildInfo, artifactSHA256, buildInfoSHA256, member string) *domain.ProductTarget {
	if bi == nil || artifactSHA256 == "" || buildInfoSHA256 == "" {
		return nil
	}
	values := map[string]string{}
	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS", "GOARCH", "CGO_ENABLED", "-tags", "GOFLAGS":
			if _, dup := values[s.Key]; dup {
				return nil
			}
			values[s.Key] = s.Value
		}
	}
	if strings.Contains(values["GOFLAGS"], "-tags") {
		return nil
	}
	cgo, ok := values["CGO_ENABLED"]
	if !ok || (cgo != "0" && cgo != "1") {
		return nil
	}
	target := &domain.ProductTarget{
		GOOS:            values["GOOS"],
		GOARCH:          values["GOARCH"],
		BuildTags:       splitBuildTags(values["-tags"]),
		CGOEnabled:      cgo == "1",
		Source:          domain.ProductTargetSourceArtifactBuildInfo,
		Scope:           domain.ProductTargetScopeArtifact,
		ArtifactSHA256:  artifactSHA256,
		BuildInfoSHA256: buildInfoSHA256,
		BinaryMember:    member,
	}
	if err := target.Validate(); err != nil {
		return nil
	}
	return target
}

// buildInfoTargetFromPath reads a bare Go binary's embedded build info and
// returns its digest-bound build target. ArtifactSHA256 and
// BuildInfoSHA256 are both the binary's SHA-256 (a bare binary has no
// enclosing artifact and no archive member), matching the bare-artifact
// convention. An extraction gap — unreadable build info or incomplete
// build settings — is an error so the caller can record it separately from
// release-toolchain availability.
func buildInfoTargetFromPath(ctx context.Context, binaryPath string) (*domain.ProductTarget, error) {
	if binaryPath == "" {
		return nil, nil
	}
	bi, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("binary build info: %w", err)
	}
	sha, _, err := hashFileSHA256(ctx, binaryPath)
	if err != nil {
		return nil, fmt.Errorf("binary digest: %w", err)
	}
	target := targetFromBuildInfo(bi, sha, sha, "")
	if target == nil {
		return nil, errors.New("binary build info does not carry a complete, unambiguous build target")
	}
	return target, nil
}

// splitBuildTags splits a recorded -tags value into its tag set. The Go
// toolchain accepts comma- or space-separated lists in the flag value;
// empty entries are dropped and order is normalized to the recorded
// order for stable reporting. Validation happens on the target.
func splitBuildTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func releaseModule(m *debug.Module, main bool) domain.ReleaseModule {
	rm := domain.ReleaseModule{Path: m.Path, Version: m.Version, Main: main}
	if m.Replace != nil {
		r := releaseModule(m.Replace, false)
		rm.Replace = &r
	}
	return rm
}

// hashFileSHA256 streams a file's digest without loading it into memory.
func hashFileSHA256(ctx context.Context, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			total += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", 0, rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), total, nil
}

// --- content-addressed cache ------------------------------------------------

// artifactIndexPath maps a URL request identity (SHA-256 of the exact
// URL, credentials excluded) to the artifact content slot.
func artifactIndexPath(cacheDir string) string {
	return filepath.Join(cacheDir, "index.json")
}

func artifactIndexLookup(cacheDir, key string) string {
	b, err := os.ReadFile(artifactIndexPath(cacheDir))
	if err != nil {
		return ""
	}
	var idx map[string]string
	if json.Unmarshal(b, &idx) != nil {
		return ""
	}
	return idx[key]
}

func artifactIndexStore(cacheDir, key, sha string) {
	idx := map[string]string{}
	if b, err := os.ReadFile(artifactIndexPath(cacheDir)); err == nil {
		json.Unmarshal(b, &idx)
	}
	idx[key] = sha
	if b, err := json.Marshal(idx); err == nil {
		os.WriteFile(artifactIndexPath(cacheDir), b, 0o600)
	}
}

func artifactIndexRemove(cacheDir, key string) {
	b, err := os.ReadFile(artifactIndexPath(cacheDir))
	if err != nil {
		return
	}
	var idx map[string]string
	if json.Unmarshal(b, &idx) != nil {
		return
	}
	delete(idx, key)
	if b, err := json.Marshal(idx); err == nil {
		os.WriteFile(artifactIndexPath(cacheDir), b, 0o600)
	}
}

// readArtifactMeta returns the slot's commit record when the slot is
// complete: metadata consistent with the content key, the blob present
// for downloaded artifacts, and every recorded member on disk. Every member
// is re-hashed and must be an unlinked, non-symlink regular file.
func readArtifactMeta(slot, sha string, needBlob bool) *artifactMeta {
	b, err := os.ReadFile(filepath.Join(slot, "meta.json"))
	if err != nil {
		return nil
	}
	var meta artifactMeta
	if json.Unmarshal(b, &meta) != nil || meta.SHA256 != sha {
		return nil
	}
	if needBlob {
		blob := filepath.Join(slot, "artifact")
		if st, err := os.Stat(blob); err != nil || !st.Mode().IsRegular() {
			return nil
		}
		got, size, err := hashFileSHA256(context.Background(), blob)
		if err != nil || got != sha || (meta.Size > 0 && size != meta.Size) {
			return nil
		}
	}
	tree := filepath.Join(slot, "tree")
	var members []os.FileInfo
	for _, m := range meta.Members {
		target := filepath.Join(tree, filepath.FromSlash(m.Path))
		if !containedIn(tree, target) {
			return nil
		}
		st, err := os.Lstat(target)
		if err != nil || !st.Mode().IsRegular() || m.SHA256 == "" || st.Size() != m.Size {
			return nil
		}
		if linkCount(st) > 1 {
			return nil
		}
		for _, prior := range members {
			if os.SameFile(prior, st) {
				return nil
			}
		}
		got, size, err := hashFileSHA256(context.Background(), target)
		if err != nil || size != m.Size || got != m.SHA256 {
			return nil
		}
		members = append(members, st)
	}
	return &meta
}

func linkCount(info os.FileInfo) uint64 {
	sys := info.Sys()
	if sys == nil {
		return 0
	}
	v := reflect.ValueOf(sys)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0
	}
	f := v.FieldByName("Nlink")
	if !f.IsValid() || !f.CanUint() {
		return 0
	}
	return f.Uint()
}

func writeArtifactMeta(slot string, meta *artifactMeta) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("artifact cache meta: %w", err)
	}
	if err := os.WriteFile(filepath.Join(slot, "meta.json"), b, 0o600); err != nil {
		return fmt.Errorf("artifact cache meta: %w", err)
	}
	return nil
}
