package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/repository"
)

// SnapshotSchemaVersion is the only manifest schema the builder produces.
const SnapshotSchemaVersion = "snapshot.v1"

type SnapshotFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Role marks manifest artifacts that carry a fixed meaning — "sbom" or
	// "binary" — so material collection and toolchain discovery can resolve
	// them without re-reading the finding. Empty for plain tree files.
	Role string `json:"role,omitempty"`
}

type SnapshotManifest struct {
	SchemaVersion    string         `json:"schema_version"`
	FindingID        string         `json:"finding_id"`
	Repository       string         `json:"repository,omitempty"`
	Revision         string         `json:"revision,omitempty"`
	ResolvedRevision string         `json:"resolved_revision,omitempty"`
	RevisionStatus   FactStatus     `json:"revision_status"`
	ContentHash      string         `json:"content_hash,omitempty"`
	InputHash        string         `json:"input_hash"`
	Files            []SnapshotFile `json:"files,omitempty"`
	Artifacts        []SnapshotFile `json:"artifacts,omitempty"`
	CreatedAt        string         `json:"created_at"`
	// Materialization is the source-provenance block: how the snapshotted
	// root was produced, from which catalog source, at which selected ref
	// and resolved commit, and the content hash observed at materialization
	// time. Plain Build leaves it empty; BuildMaterialized fills it.
	Materialization MaterializationMetadata `json:"materialization"`
}

// BuildMaterialized builds the manifest over a materialized source root and
// records its provenance block. The materialization root hash pins the tree
// state observed at materialization: a root that drifted before this build
// produces a technical error rather than a manifest mixing two states.
func (b LocalSnapshotBuilder) BuildMaterialized(ctx context.Context, in FindingInput, src MaterializedSource) (SnapshotManifest, error) {
	if src.Root == "" {
		return SnapshotManifest{}, errors.New("snapshot: materialized source has no root")
	}
	in.Finding.Target.Repository = src.Root
	m, err := b.Build(ctx, in)
	m.Materialization = src.Metadata
	if err != nil {
		return m, err
	}
	if src.Metadata.RootHash != "" && m.ContentHash != src.Metadata.RootHash {
		return m, fmt.Errorf("snapshot: materialized root drifted: content hash %q != materialized %q", m.ContentHash, src.Metadata.RootHash)
	}
	return m, nil
}

type SnapshotBuilder interface {
	Build(context.Context, FindingInput) (SnapshotManifest, error)
}

// LocalSnapshotBuilder builds a snapshot.v1 manifest over the local tree named
// by Finding.Target.Repository. Confinement is verified before hashing:
// symlinks resolving outside the root and go.mod/go.work path replacements
// escaping it are rejected rather than absorbed into the identity. It does not
// use repository.Service.Snapshot, which requires Go-specific probes.
type LocalSnapshotBuilder struct {
	// AllowExternalArtifacts records Target.SBOM/Binary paths that resolve
	// outside the snapshot root; without it only contained files are listed.
	AllowExternalArtifacts bool
	// Now supplies CreatedAt for audit; nil means time.Now. Hash fields never
	// depend on it.
	Now func() time.Time
	// afterCollect, when set, runs between the tree entry collection and the
	// stability re-check; tests use it to inject mid-build mutations.
	afterCollect func()
}

func (b LocalSnapshotBuilder) Build(ctx context.Context, in FindingInput) (SnapshotManifest, error) {
	m := SnapshotManifest{
		SchemaVersion:  SnapshotSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Repository:     strings.TrimSpace(in.Finding.Target.Repository),
		Revision:       strings.TrimSpace(in.Finding.Target.Revision),
		RevisionStatus: FactUnavailable,
	}
	m.InputHash = in.SHA256
	if m.InputHash == "" && len(in.Raw) > 0 {
		sum := sha256.Sum256(in.Raw)
		m.InputHash = hex.EncodeToString(sum[:])
	}
	if m.InputHash == "" {
		return m, errors.New("snapshot: finding input has neither sha256 nor raw bytes")
	}

	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	m.CreatedAt = now().UTC().Format(time.RFC3339)

	root, err := canonicalDir(m.Repository)
	if err != nil {
		return m, err
	}
	if root != "" {
		if err := repository.VerifyContained(root); err != nil {
			return m, err
		}
		if err := repository.CheckPathReplacements(root); err != nil {
			return m, err
		}
		if m.Revision != "" {
			m.RevisionStatus = FactInvalid
			if _, sha, rerr := repository.ResolveRef(ctx, root, m.Revision); rerr == nil {
				m.RevisionStatus = FactValid
				m.ResolvedRevision = sha
			}
		}
		// One pass over the tree yields both the canonical hash and the
		// file-level manifest; a second collection then verifies the tree
		// did not mutate while it was read. A divergence is a technical
		// error, not a manifest mixing two states.
		entries, err := collectContentEntries(root)
		if err != nil {
			return m, err
		}
		if b.afterCollect != nil {
			b.afterCollect()
		}
		again, err := collectContentEntries(root)
		if err != nil {
			return m, err
		}
		if m.ContentHash = hashContentEntries(entries); m.ContentHash != hashContentEntries(again) {
			return m, errors.New("snapshot: tree mutated during build")
		}
		m.Files = filesFromEntries(entries)
	}
	m.Artifacts = snapshotArtifacts(root, b.AllowExternalArtifacts, in.Finding.Target)
	return m, nil
}

// canonicalDir resolves path to an existing canonical directory; an empty
// path means the finding carried no repository and yields "".
func canonicalDir(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("snapshot: resolve repository path: %w", err)
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("snapshot: resolve repository path: %w", err)
	}
	info, err := os.Stat(canon)
	if err != nil {
		return "", fmt.Errorf("snapshot: stat repository: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("snapshot: repository path %q is not a directory", path)
	}
	return canon, nil
}

// contentHashVersion mirrors the canonical tree encoding version inside
// internal/repository (unexported). For trees without .git pointer files
// hashContentEntries produces hashes identical to repository.ContentHash —
// tests pin that equivalence; a worktree's .git gitdir pointer is skipped
// entirely so the same commit materializes identical identities regardless
// of the temp path it landed at.
const contentHashVersion = "t1"

// contentEntry is one hashed tree element; a symlink contributes its target
// string rather than followed content, exactly like repository's encoding.
type contentEntry struct {
	rel     string
	kind    string
	mode    fs.FileMode
	length  int64
	payload string
}

// collectContentEntries gathers every hashable tree element in a single
// walk: dirs, symlinks (target string) and file bytes, skipping .git
// administrative metadata in every form — a repository .git directory and
// the .git pointer file a worktree carries. The pointer embeds an absolute
// temp path, so hashing it would make the same commit hash differently at
// every materialization location. The file-level manifest is derived from
// these same entries so both reflect one observation of the tree.
func collectContentEntries(root string) ([]contentEntry, error) {
	var out []contentEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		entry := contentEntry{rel: rel, mode: info.Mode()}
		switch {
		case d.IsDir():
			entry.kind = "dir"
		case info.Mode()&os.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			entry.kind = "symlink"
			entry.payload = target
			entry.length = int64(len(target))
		default:
			entry.kind = "file"
			sum, size, herr := hashFileSHA256(path)
			if herr != nil {
				return herr
			}
			entry.payload = sum
			entry.length = size
		}
		out = append(out, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// hashContentEntries renders entries into the canonical tree hash, identical
// to repository.ContentHash for the same tree state.
func hashContentEntries(entries []contentEntry) string {
	sorted := slices.Clone(entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].rel < sorted[j].rel })
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", contentHashVersion)
	for _, e := range sorted {
		fmt.Fprintf(h, "%s\t%s\t%o\t%d\t", e.rel, e.kind, e.mode&0o111, e.length)
		io.WriteString(h, e.payload)
		io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// filesFromEntries projects the manifest's file list from collected entries:
// regular files only, sorted by path.
func filesFromEntries(entries []contentEntry) []SnapshotFile {
	var files []SnapshotFile
	for _, e := range entries {
		if e.kind != "file" || !e.mode.IsRegular() {
			continue
		}
		files = append(files, SnapshotFile{Path: e.rel, SHA256: e.payload, Size: e.length})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

// snapshotArtifacts hashes the optional Target.SBOM and Target.Binary inputs.
// Missing, unreadable or disallowed artifacts are simply absent from the
// manifest — their absence is recorded, not treated as a negative fact.
func snapshotArtifacts(root string, allowExternal bool, t Target) []SnapshotFile {
	var out []SnapshotFile
	seen := make(map[string]bool)
	for _, named := range []struct{ name, role string }{
		{t.SBOM, "sbom"},
		{t.Binary, "binary"},
	} {
		f, ok := artifactFile(root, allowExternal, named.name)
		if !ok || seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		f.Role = named.role
		out = append(out, f)
	}
	return out
}

func artifactFile(root string, allowExternal bool, name string) (SnapshotFile, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return SnapshotFile{}, false
	}
	candidate := name
	if !filepath.IsAbs(candidate) {
		if root == "" {
			return SnapshotFile{}, false
		}
		candidate = filepath.Join(root, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return SnapshotFile{}, false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return SnapshotFile{}, false
	}
	path := resolved
	if root != "" {
		if rel, rerr := filepath.Rel(root, resolved); rerr == nil {
			rel = filepath.ToSlash(rel)
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, "../")) {
				path = rel
			} else if !allowExternal {
				return SnapshotFile{}, false
			}
		}
	} else if !allowExternal {
		return SnapshotFile{}, false
	}
	sum, size, err := hashFileSHA256(resolved)
	if err != nil {
		return SnapshotFile{}, false
	}
	return SnapshotFile{Path: path, SHA256: sum, Size: size}, true
}

func hashFileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
