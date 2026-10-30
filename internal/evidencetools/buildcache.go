package evidencetools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BuildCacheDirEnv is the declared environment channel for the per-run
// Go build cache root: `izyan research --build-cache-dir` reaches the
// strict evidence session through it (the lane options have no field),
// and a caller may set it directly. SessionConfig.BuildCacheRoot wins
// when both are present. Unlike ambient GOCACHE — which is never
// inherited — this variable is an explicit, recorded declaration.
const BuildCacheDirEnv = "IZYAN_BUILD_CACHE_DIR"

// BuildCacheCorruptReason is the fail-closed reason code recorded when a
// tool fails on a corrupted Go build cache: a pruned or damaged cache
// makes `go list`/`govulncheck` error mid-analysis, and silently
// retrying against the same cache cannot produce a sound result. The
// remedy is a fresh declared root (`--build-cache-dir`) or clearing the
// pinned cache (`go clean -cache` under the effective GOCACHE).
const BuildCacheCorruptReason = "BUILD_CACHE_CORRUPT"

// resolveBuildCacheRoot picks the effective GOCACHE pin: the declared
// config/env root when present, otherwise the platform default
// (os.UserCacheDir/go-build — the same directory the go tool uses when
// GOCACHE is unset). Reusing the default keeps one warm cache per
// machine instead of paying a cold build per run, while the explicit
// pin blocks any ambient GOCACHE a caller leaked into the process
// environment. The resolved root is canonicalized and must never sit
// inside the snapshot or a forbidden output directory — a writable
// cache there would contaminate analyzed or reported ground.
func resolveBuildCacheRoot(declared, snapshotRoot string, forbid []string) (string, error) {
	dir := declared
	if dir == "" {
		dir = os.Getenv(BuildCacheDirEnv)
	}
	if dir == "" {
		var err error
		dir, err = defaultBuildCacheRoot()
		if err != nil {
			return "", fmt.Errorf("build cache root: %w", err)
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("build cache root: %w", err)
	}
	// Canonicalize like the module cache, but go one step further: a
	// declared root that does not exist yet keeps its lexical path
	// after EvalSymlinks, which would leave a symlinked ancestor
	// (e.g. /var -> /private/var) uncanonicalized and let the
	// inside-snapshot guard compare different spellings of one
	// directory. Resolve the nearest existing ancestor and rejoin the
	// missing tail so the guard and the GOCACHE pin always compare
	// canonical identities — without creating the directory.
	abs = resolveExistingPrefix(abs)
	guards := append([]string{snapshotRoot}, forbid...)
	for _, g := range guards {
		if g == "" {
			continue
		}
		gabs, gerr := filepath.Abs(g)
		if gerr != nil {
			continue
		}
		gabs = resolveExistingPrefix(gabs)
		if insideOrEqual(abs, gabs) {
			return "", fmt.Errorf("build cache root %s must not be inside %s", abs, gabs)
		}
	}
	return abs, nil
}

// resolveExistingPrefix canonicalizes a possibly-missing path by
// resolving the nearest existing ancestor and rejoining the tail, so a
// not-yet-created root still gets a canonical identity.
func resolveExistingPrefix(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	parent, tail := filepath.Dir(p), filepath.Base(p)
	for {
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(resolved, tail)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return p // nothing resolves — keep the lexical path
		}
		parent, tail = next, filepath.Join(filepath.Base(parent), tail)
	}
}

// defaultBuildCacheRoot returns the go tool's default cache location
// (os.UserCacheDir/go-build). When the platform cannot name a cache
// directory there is no honest default: fail closed and name the
// declared-channel remedy rather than falling back to an ambient or
// throwaway path.
func defaultBuildCacheRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no platform cache directory (%v); declare %s or a build-cache flag", err, BuildCacheDirEnv)
	}
	return filepath.Join(base, "go-build"), nil
}

// insideOrEqual reports whether path p is dir itself or lives under it.
func insideOrEqual(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// buildCacheCorruptErr classifies a failed tool error as build-cache
// corruption when it carries one of the two measured signatures:
// "cache entry not found" (the go build cache's own missing-entry
// diagnostic) or an ENOENT on a path inside the effective cache root
// (a pruned/corrupted cache file). Both mean the cache lied about its
// contents; the check must fail closed with the named reason instead of
// degrading into a partial result.
func buildCacheCorruptErr(err error, cacheRoot string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	sig := ""
	if strings.Contains(msg, "cache entry not found") {
		sig = "cache entry not found"
	} else if cacheRoot != "" &&
		strings.Contains(msg, cacheRoot) &&
		strings.Contains(msg, "no such file or directory") {
		sig = "missing entry under " + cacheRoot
	}
	if sig == "" {
		return err
	}
	return fmt.Errorf("%s: go build cache %s is corrupted (%s); rerun with a fresh --build-cache-dir or `go clean -cache` under the pinned GOCACHE: %w",
		BuildCacheCorruptReason, cacheRoot, sig, err)
}
