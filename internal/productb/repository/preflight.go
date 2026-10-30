package repository

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckPathReplacements scans the snapshot's go.mod and go.work and rejects
// any filesystem replace/use target that resolves outside the snapshot. It
// runs before the package loader reads the tree, so a local replace cannot
// pull source from outside the snapshot into the analysis.
//
// Module-version replaces (module => module vX.Y.Z) are allowed: they
// resolve from the module cache, not from disk outside the roots.
func CheckPathReplacements(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if canon, cerr := filepath.EvalSymlinks(abs); cerr == nil {
		abs = canon
	}
	for _, name := range []string{"go.mod", "go.work"} {
		path := filepath.Join(abs, name)
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		if err := checkReplacementsIn(string(b), name, abs); err != nil {
			return err
		}
	}
	return nil
}

// checkReplacementsIn validates the replace/use lines of one manifest.
func checkReplacementsIn(content, name, root string) error {
	inBlock := "" // "replace" or "use" while inside a parenthesised block
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		var target string
		switch {
		case strings.Contains(trimmed, "=>"):
			rhs := strings.TrimSpace(strings.SplitN(trimmed, "=>", 2)[1])
			rhs = strings.TrimSpace(strings.SplitN(rhs, "//", 2)[0])
			target = rhs
		case strings.HasPrefix(trimmed, "use "):
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "use "))
			if rest == "(" {
				inBlock = "use"
				continue
			}
			target = rest
		case strings.HasPrefix(trimmed, "replace"):
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "replace"))
			if rest == "(" {
				inBlock = "replace"
			}
			continue
		case inBlock == "use":
			if trimmed == ")" {
				inBlock = ""
				continue
			}
			target = trimmed
		case inBlock == "replace":
			if trimmed == ")" {
				inBlock = ""
			}
			continue
		default:
			continue
		}
		if target == "" {
			continue
		}
		if !isPathTarget(target) {
			continue // module@version replace: resolved from the module cache
		}
		ok, err := resolveWithin(root, target)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", name, i+1, err)
		}
		if !ok {
			return fmt.Errorf("%s:%d: path target %q escapes the snapshot root", name, i+1, target)
		}
	}
	return nil
}

// isPathTarget reports whether a replace/use target names a filesystem path
// rather than a module path with an optional version.
func isPathTarget(target string) bool {
	return strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "../") ||
		target == "." || target == ".." ||
		filepath.IsAbs(target)
}

// resolveWithin reports whether target resolves inside root. Symlinks are
// resolved on the longest existing prefix so a link that points outside is
// caught even when the final path component does not exist yet.
func resolveWithin(root, target string) (bool, error) {
	joined := filepath.Join(root, target)
	if filepath.IsAbs(target) {
		joined = filepath.Clean(target)
	}
	if resolved, ok := resolveExistingPrefix(joined); ok {
		return lexicallyWithin(root, resolved), nil
	}
	return lexicallyWithin(root, filepath.Clean(joined)), nil
}

// resolveExistingPrefix resolves symlinks along the longest existing prefix
// of path and re-appends the remaining components. It returns the resolved
// path and whether any prefix existed.
func resolveExistingPrefix(path string) (string, bool) {
	cur := filepath.Clean(path)
	var rest []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			resolved, rerr := filepath.EvalSymlinks(cur)
			if rerr != nil {
				return "", false
			}
			for i := len(rest) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, rest[i])
			}
			return resolved, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
}

// lexicallyWithin reports whether target lives at or under root.
func lexicallyWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, "../"))
}
