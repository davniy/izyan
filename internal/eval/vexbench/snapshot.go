package vexbench

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// LocateSnapshot resolves a task's repository snapshot inside reposDir using
// the VEX-Bench layout <reposDir>/<owner>/<repo>/<commit_sha> and returns the
// canonical path. Any escape from reposDir — by ".." segments or by symlink —
// and any ".git" path segment is rejected; the directory must exist.
// LocateSnapshotPath resolves a repository snapshot inside reposDir given
// the repoURL and commitSHA without requiring a benchmark Task object.
func LocateSnapshotPath(reposDir, repoURL, commitSHA string) (string, error) {
	owner, repo, err := parseRepoURL(repoURL)
	if err != nil {
		return "", err
	}
	for _, seg := range []string{owner, repo, commitSHA} {
		if err := checkSegment(seg); err != nil {
			return "", fmt.Errorf("locate snapshot: %w", err)
		}
	}

	rootAbs, err := filepath.Abs(reposDir)
	if err != nil {
		return "", fmt.Errorf("locate snapshot: resolve repos dir: %w", err)
	}
	root, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("locate snapshot: repos dir %s: %w", reposDir, err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("locate snapshot: repos dir %s is not a directory", reposDir)
	}

	raw := filepath.Join(root, owner, repo, commitSHA)
	if err := checkInside(root, raw); err != nil {
		return "", fmt.Errorf("locate snapshot: %s escapes repos dir", raw)
	}
	canon, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", fmt.Errorf("locate snapshot: resolve %s: %w", raw, err)
	}
	if err := checkInside(root, canon); err != nil {
		return "", fmt.Errorf("locate snapshot: %s resolves outside repos dir", raw)
	}
	info, err = os.Stat(canon)
	if err != nil {
		return "", fmt.Errorf("locate snapshot: snapshot %s: %w", canon, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("locate snapshot: %s is not a directory", canon)
	}
	return canon, nil
}

func LocateSnapshot(reposDir string, t Task) (string, error) {
	path, err := LocateSnapshotPath(reposDir, t.RepoURL, t.CommitSHA)
	if err != nil {
		return "", fmt.Errorf("locate snapshot %s: %w", t.TaskID, err)
	}
	return path, nil
}

// parseRepoURL extracts owner/repo from a repository URL or path-like
// string: https://github.com/owner/repo[.git], git@github.com:owner/repo,
// or bare owner/repo.
func parseRepoURL(raw string) (owner, repo string, err error) {
	s := strings.TrimSpace(strings.TrimRight(raw, "/"))
	var tail string
	switch {
	case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"):
		u, perr := url.Parse(s)
		if perr != nil {
			return "", "", fmt.Errorf("parse repo url %q: %w", raw, perr)
		}
		tail = strings.Trim(u.Path, "/")
	case strings.HasPrefix(s, "git@"):
		_, after, ok := strings.Cut(s, ":")
		if !ok {
			return "", "", fmt.Errorf("parse repo url %q: want git@host:owner/repo", raw)
		}
		tail = strings.Trim(after, "/")
	default:
		tail = s
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("parse repo url %q: want owner/repo", raw)
	}
	owner, repo = parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("parse repo url %q: empty owner or repo", raw)
	}
	return owner, repo, nil
}

// checkSegment rejects path segments that could relocate the lookup outside
// the repos dir or into VCS metadata.
func checkSegment(seg string) error {
	if seg == "" {
		return fmt.Errorf("empty path segment")
	}
	if seg == "." || seg == ".." || strings.ContainsAny(seg, "/\\") {
		return fmt.Errorf("invalid path segment %q", seg)
	}
	if strings.EqualFold(seg, ".git") {
		return fmt.Errorf(".git path segment not allowed")
	}
	return nil
}

// checkInside verifies target lies strictly under root using canonical path
// semantics — never a plain string-prefix comparison.
func checkInside(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("outside root")
	}
	return nil
}
