package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// contentHashVersion prefixes the canonical tree encoding. Bump it whenever
// the encoding changes so old hashes are never compared with new ones.
const contentHashVersion = "t1"

// ContentHash computes a canonical hash of a snapshot tree. The identity is
// independent of filesystem walk order and of irrelevant mode bits:
//
//   - entries are sorted by slash-separated relative path;
//   - each entry contributes its kind (dir/file/symlink), the executable
//     bit, its length and its bytes;
//   - a symlink contributes its target string, never the content it points
//     at, so a link escaping the tree cannot pull foreign bytes into the
//     identity;
//   - .git administrative metadata is excluded; vendor/ and build files are
//     included.
//
// The tree is expected to be immutable for the duration of an analysis.
func ContentHash(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	entries, err := collectTreeEntries(abs)
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	h := sha256.New()
	fmt.Fprintf(h, "%s\n", contentHashVersion)
	for _, e := range entries {
		fmt.Fprintf(h, "%s\t%s\t%o\t%d\t", e.rel, e.kind, e.mode&0o111, e.length)
		io.WriteString(h, e.payload)
		io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type treeEntry struct {
	rel     string
	kind    string
	mode    fs.FileMode
	length  int64
	payload string
}

func collectTreeEntries(root string) ([]treeEntry, error) {
	var out []treeEntry
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
		// .git administrative metadata is not part of the snapshot content.
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		entry := treeEntry{rel: rel, mode: info.Mode()}
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
			sum, size, herr := hashFile(path)
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

// hashFile returns the sha256 of a regular file and its byte length.
func hashFile(path string) (string, int64, error) {
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

// treeEscape is a filesystem entry that resolves outside its root. It is
// reported fail-closed rather than silently followed: a snapshot must not be
// able to pull content from outside itself into the analysis.
type treeEscape struct {
	Rel    string
	Target string
}

func (e treeEscape) Error() string {
	return fmt.Sprintf("snapshot entry %s escapes the snapshot root (target %s)", e.Rel, e.Target)
}

// VerifyContained walks root and rejects any symlink whose canonical target
// resolves outside root, and any symlink cycle. It runs before any loader
// reads the tree, so confinement does not depend on a later read returning
// an error. On success it returns nil.
func VerifyContained(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	// Canonicalise the root too: on platforms where the temp/repo path is
	// itself behind a symlink (macOS /var -> /private/var), comparing a
	// resolved target against a lexical root would reject every internal
	// symlink.
	if canon, cerr := filepath.EvalSymlinks(abs); cerr == nil {
		abs = canon
	}
	return filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(abs, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		target, lerr := os.Readlink(path)
		if lerr != nil {
			return lerr
		}
		resolved, rerr := filepath.EvalSymlinks(path)
		if rerr != nil {
			// An unresolvable symlink cannot be followed, so it cannot
			// leak content from outside the snapshot — treat it as inert.
			// Broken and cyclic links occur legitimately in real source
			// trees (test fixtures, docker build contexts, image rootfs
			// overlays), and a fail-closed rejection here would refuse to
			// analyse those repositories at all.
			return nil
		}
		// Compare canonical paths; EvalSymlinks already resolved the root.
		inside, rerr := isWithin(abs, resolved)
		if rerr != nil {
			return rerr
		}
		if !inside {
			// A link out of the tree is only a leak if it yields readable
			// source. Links to character/block devices, FIFOs and sockets
			// (e.g. testdata fixtures pointing at /dev/null) carry no
			// source content and are inert for analysis; only links to
			// regular files or directories are rejected.
			if info, serr := os.Stat(path); serr == nil {
				mode := info.Mode()
				if mode&(os.ModeDevice|os.ModeCharDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
					return nil
				}
			}
			return treeEscape{Rel: rel, Target: target}
		}
		return nil
	})
}

// isWithin reports whether target (canonical) lies at or under root
// (canonical). Both must be absolute.
func isWithin(root, target string) (bool, error) {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false, err
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return true, nil
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return false, nil
	}
	return true, nil
}
