package triage

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/repository"
)

// MaterializationMode records how a catalog source became a snapshot root.
type MaterializationMode string

const (
	// MaterializationLocal uses the configured source directory in place —
	// no copy. Its immutability is the operator's contract; the recorded
	// root hash and the snapshot stability re-check pin the observation.
	MaterializationLocal MaterializationMode = "local"
	// MaterializationWorktree checks the selected commit out into a
	// detached git worktree; the source checkout is never touched.
	MaterializationWorktree MaterializationMode = "worktree"
	// MaterializationClone fetches a remote repository into an isolated
	// clone under the materialization clone root.
	MaterializationClone MaterializationMode = "clone"
)

// MaterializationMetadata is the provenance block recorded into
// snapshot.json: how the snapshot root was produced, from which catalog
// source, at which selected ref and resolved commit, and the canonical
// content hash observed at materialization time. It carries the credential
// reference only — credential values never enter metadata.
type MaterializationMetadata struct {
	Mode           MaterializationMode `json:"mode"`
	SourceID       string              `json:"source_id"`
	Locator        string              `json:"locator,omitempty"`
	SelectedRef    string              `json:"selected_ref,omitempty"`
	ResolvedCommit string              `json:"resolved_commit,omitempty"`
	RootHash       string              `json:"root_hash,omitempty"`
	CreatedAt      string              `json:"created_at"`
	CredentialRef  string              `json:"credential_ref,omitempty"`
	Limitations    []string            `json:"limitations,omitempty"`
}

// MaterializedSource is a snapshot-ready root plus its provenance. Cleanup
// is always non-nil and idempotent; it removes only materialized state —
// never the configured source repository or local root. A worktree cleanup
// that cannot take the inter-process lock reports the failure instead of
// mutating shared git metadata unlocked.
type MaterializedSource struct {
	Root     string
	Metadata MaterializationMetadata
	Cleanup  func() error
}

// SourceMaterializer resolves a catalog entry and the selected ref
// candidate into an isolated, immutable-for-the-run source tree.
type SourceMaterializer interface {
	Materialize(
		context.Context,
		CatalogEntry,
		RefCandidate,
		MaterializationPolicy,
	) (MaterializedSource, error)
}

// MaterializationPolicy bounds one materialization run. AllowedModes empty
// admits every mode; CloneRoot is the isolated directory clones are created
// under (the process temp dir when empty); RequirePinnedCommit rejects
// sources that cannot name a resolved commit. Credential material is never
// part of the policy — it enters through Materializer.Credentials.
type MaterializationPolicy struct {
	AllowedModes        []MaterializationMode `json:"allowed_modes,omitempty" yaml:"allowed_modes,omitempty"`
	RequirePinnedCommit bool                  `json:"require_pinned_commit,omitempty" yaml:"require_pinned_commit,omitempty"`
	CloneRoot           string                `json:"clone_root,omitempty" yaml:"clone_root,omitempty"`
}

// Materializer is the deterministic Stage 0 source materializer. It selects
// the mode from the entry shape — local roots are used in place, local git
// locators produce a detached worktree, remote git locators an isolated
// clone — then pins ref, commit and content identity and verifies the
// materialized tree for containment before it is handed to the snapshot
// builder. Every failure is a technical error; no mode ever mutates the
// configured source checkout.
type Materializer struct {
	// Credentials resolves an entry's credential_ref to environment
	// bindings for the remote fetch. It is the only boundary secret
	// material crosses; bindings go to the clone process environment and
	// nowhere else. A nil provider with a non-empty credential_ref is a
	// technical error.
	Credentials func(credentialRef string) (env []string, err error)
	// Now supplies MaterializationMetadata.CreatedAt; nil means time.Now.
	Now func() time.Time
}

// Materialize implements SourceMaterializer.
func (m Materializer) Materialize(
	ctx context.Context,
	entry CatalogEntry,
	cand RefCandidate,
	policy MaterializationPolicy,
) (MaterializedSource, error) {
	src := MaterializedSource{
		Metadata: MaterializationMetadata{
			SourceID:      strings.TrimSpace(entry.ID),
			Locator:       entryLocator(entry),
			SelectedRef:   selectedRefName(cand),
			CredentialRef: strings.TrimSpace(entry.CredentialRef),
		},
		Cleanup: func() error { return nil },
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	src.Metadata.CreatedAt = now().UTC().Format(time.RFC3339)

	fail := func(err error) (MaterializedSource, error) {
		_ = src.Cleanup()
		return src, err
	}

	if src.Metadata.SourceID == "" {
		return src, fmt.Errorf("materialization: catalog entry has no id")
	}
	for _, mode := range policy.AllowedModes {
		switch mode {
		case MaterializationLocal, MaterializationWorktree, MaterializationClone:
		default:
			return src, fmt.Errorf("materialization: policy admits unknown mode %q", mode)
		}
	}
	mode, err := materializationMode(entry)
	if err != nil {
		return src, err
	}
	if !policy.allows(mode) {
		return src, fmt.Errorf("materialization: mode %q for source %q is not admitted by policy", mode, entry.ID)
	}

	src.Metadata.Mode = mode
	switch mode {
	case MaterializationLocal:
		err = materializeLocal(ctx, refRepoPath(entry), cand, &src)
	case MaterializationWorktree:
		err = materializeWorktree(ctx, refRepoPath(entry), cand, &src)
	default:
		err = m.materializeClone(ctx, entry, cand, policy.CloneRoot, &src)
	}
	if err != nil {
		return fail(err)
	}
	if policy.RequirePinnedCommit && src.Metadata.ResolvedCommit == "" {
		return fail(fmt.Errorf("materialization: source %q resolved no pinned commit required by policy", entry.ID))
	}
	if err := verifyMaterializedRoot(src.Root); err != nil {
		return fail(err)
	}
	entries, err := collectContentEntries(src.Root)
	if err != nil {
		return fail(fmt.Errorf("materialization: content hash: %w", err))
	}
	src.Metadata.RootHash = hashContentEntries(entries)
	return src, nil
}

// materializeLocal adopts the configured source directory as the snapshot
// root. When a ref was selected the checkout must stand at that ref —
// materializing a different revision out of the same directory would
// require mutating the source, so a mismatch is a technical error.
func materializeLocal(ctx context.Context, rootPath string, cand RefCandidate, src *MaterializedSource) error {
	if rootPath == "" {
		return fmt.Errorf("materialization: source %q has no local root", src.Metadata.SourceID)
	}
	root, err := canonicalDir(rootPath)
	if err != nil {
		return err
	}
	src.Root = root

	_, head, herr := repository.ResolveRef(ctx, root, "HEAD")
	switch expected := expectedRef(cand); {
	case herr != nil && expected != "":
		return fmt.Errorf("materialization: source %q selected ref %q but root is not a git repository", src.Metadata.SourceID, expected)
	case herr != nil:
		src.Metadata.Limitations = append(src.Metadata.Limitations, "root is not a git repository; no resolved commit to pin")
	case expected != "":
		_, sha, err := repository.ResolveRef(ctx, root, expected)
		if err != nil {
			return fmt.Errorf("materialization: selected ref %q does not resolve in source %q", expected, src.Metadata.SourceID)
		}
		if sha != head {
			return fmt.Errorf("materialization: source %q checkout is at %s, not at selected ref %q (%s)", src.Metadata.SourceID, head, expected, sha)
		}
		src.Metadata.ResolvedCommit = head
	default:
		src.Metadata.ResolvedCommit = head
	}
	return nil
}

// materializeWorktree checks the selected ref's commit out into a detached
// worktree under the process temp dir. The pin is authoritative: with an
// enumerated commit the worktree is created at that commit (a later ref
// move cannot alter the observation); without one the ref name is resolved
// at creation time.
func materializeWorktree(ctx context.Context, repoPath string, cand RefCandidate, src *MaterializedSource) error {
	if repoPath == "" {
		return fmt.Errorf("materialization: source %q has no local repository", src.Metadata.SourceID)
	}
	expected := expectedRef(cand)
	if expected == "" {
		return fmt.Errorf("materialization: git source %q requires a selected ref", src.Metadata.SourceID)
	}
	target := cand.Commit
	if target == "" {
		target = expected
	}
	root, cleanup, err := repository.NewWorktree(ctx, repoPath, target)
	if err != nil {
		return fmt.Errorf("materialization: %w", err)
	}
	src.Cleanup = cleanup
	src.Root = root

	_, head, err := repository.ResolveRef(ctx, root, "HEAD")
	if err != nil {
		return fmt.Errorf("materialization: resolve worktree HEAD: %w", err)
	}
	if cand.Commit != "" && head != cand.Commit {
		return fmt.Errorf("materialization: worktree resolved %s, want pinned commit %s", head, cand.Commit)
	}
	src.Metadata.ResolvedCommit = head
	return nil
}

// materializeClone fetches a remote git locator into an isolated clone
// under cloneRoot. Credential material resolves through m.Credentials and
// reaches the clone process only as environment bindings. The clone is
// checked out at the selected ref's commit; a remote that cannot supply it
// is a technical error.
func (m Materializer) materializeClone(ctx context.Context, entry CatalogEntry, cand RefCandidate, cloneRoot string, src *MaterializedSource) error {
	locator := strings.TrimSpace(entry.Locator)
	if strings.Contains(locator, "://") {
		if u, err := url.Parse(locator); err == nil && u.User != nil {
			return fmt.Errorf("materialization: source %q locator carries userinfo; credentials must go through credential_ref", src.Metadata.SourceID)
		}
	}
	var env []string
	if ref := strings.TrimSpace(entry.CredentialRef); ref != "" {
		if m.Credentials == nil {
			return fmt.Errorf("materialization: source %q requires credential %q but no credential provider is configured", src.Metadata.SourceID, ref)
		}
		credEnv, err := m.Credentials(ref)
		if err != nil {
			return fmt.Errorf("materialization: resolve credential %q: %w", ref, err)
		}
		env = credEnv
	}
	parent, err := cloneParentDir(cloneRoot)
	if err != nil {
		return fmt.Errorf("materialization: %w", err)
	}
	dst := filepath.Join(parent, "src")
	head, err := repository.Clone(ctx, locator, repository.CloneOptions{
		Destination:    dst,
		CredentialEnv:  env,
		ExpectedCommit: expectedRef(cand),
	})
	if err != nil {
		_ = os.RemoveAll(parent)
		return fmt.Errorf("materialization: %w", err)
	}
	var once sync.Once
	src.Cleanup = func() error {
		var rmErr error
		once.Do(func() { rmErr = os.RemoveAll(parent) })
		return rmErr
	}
	src.Root = dst
	src.Metadata.ResolvedCommit = head
	return nil
}

// materializationMode derives the mode from the entry shape: a local-kind
// root is used in place, a remote git locator is cloned, and every other
// local repository path produces a detached worktree.
func materializationMode(entry CatalogEntry) (MaterializationMode, error) {
	switch entry.Kind {
	case "local", "filesystem":
		return MaterializationLocal, nil
	case "git":
		if isRemoteLocator(entry.Locator) {
			return MaterializationClone, nil
		}
		if refRepoPath(entry) != "" {
			return MaterializationWorktree, nil
		}
		return "", fmt.Errorf("materialization: git source %q has neither local repository nor remote locator", entry.ID)
	default:
		return "", fmt.Errorf("materialization: source kind %q is not a repository source", entry.Kind)
	}
}

func (p MaterializationPolicy) allows(mode MaterializationMode) bool {
	if len(p.AllowedModes) == 0 {
		return true
	}
	for _, m := range p.AllowedModes {
		if m == mode {
			return true
		}
	}
	return false
}

// verifyMaterializedRoot is the confinement gate every materialized tree
// passes before the snapshot builder sees it: no symlink may resolve
// outside the root, no go.mod/go.work path replacement may point outside
// it, and the canonical content hash pins the tree state.
func verifyMaterializedRoot(root string) error {
	if err := repository.VerifyContained(root); err != nil {
		return err
	}
	if err := repository.CheckPathReplacements(root); err != nil {
		return err
	}
	return nil
}

// cloneParentDir canonicalizes the clone root and creates one fresh parent
// directory inside it; the clone destination lives one level deeper so the
// repository path never exists beforehand.
func cloneParentDir(cloneRoot string) (string, error) {
	if cloneRoot == "" {
		cloneRoot = os.TempDir()
	}
	if err := os.MkdirAll(cloneRoot, 0o755); err != nil {
		return "", fmt.Errorf("clone_root: %w", err)
	}
	abs, err := filepath.Abs(cloneRoot)
	if err != nil {
		return "", fmt.Errorf("clone_root: %w", err)
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("clone_root: %w", err)
	}
	parent, err := os.MkdirTemp(canon, "clone-*")
	if err != nil {
		return "", fmt.Errorf("clone_root: %w", err)
	}
	return parent, nil
}

// entryLocator is the recorded provenance locator: the configured locator,
// or the local root when the root is the source.
func entryLocator(entry CatalogEntry) string {
	if loc := strings.TrimSpace(entry.Locator); loc != "" {
		return loc
	}
	return strings.TrimSpace(entry.Root)
}

// selectedRefName is the recorded ref identity: the candidate's ref name,
// or its bounded-list id when the name is empty.
func selectedRefName(cand RefCandidate) string {
	if name := strings.TrimSpace(cand.Name); name != "" {
		return name
	}
	return strings.TrimSpace(cand.ID)
}

// expectedRef is what the materialized root must resolve to: the pinned
// commit when enumerated, else the ref name, else the candidate id.
func expectedRef(cand RefCandidate) string {
	if c := strings.TrimSpace(cand.Commit); c != "" {
		return c
	}
	return selectedRefName(cand)
}

func isRemoteLocator(loc string) bool {
	return strings.Contains(loc, "://") || strings.HasPrefix(loc, "git@")
}
