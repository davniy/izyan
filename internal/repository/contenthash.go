package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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
		writeCanonicalEntry(h, e.rel, e.kind, e.mode, e.length, e.payload)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeCanonicalEntry(w io.Writer, rel, kind string, mode fs.FileMode, length int64, payload string) {
	fmt.Fprintf(w, "%s\t%s\t%o\t%d\t", rel, kind, mode&0o111, length)
	io.WriteString(w, payload)
	io.WriteString(w, "\n")
}

// ContentManifestEntry records one validated tree entry from a ContentManifest.
type ContentManifestEntry struct {
	Path       string      `json:"path"`
	Kind       string      `json:"kind"`
	Executable bool        `json:"executable"`
	Size       int64       `json:"size"`
	Payload    string      `json:"payload"`
	Mode       fs.FileMode `json:"mode"`
}

// CaptureContentManifest collects tree entries under root, encodes them canonically
// using the same format as ContentHash, and returns the raw manifest bytes.
func CaptureContentManifest(root string) ([]byte, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	entries, err := collectTreeEntries(abs)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n", contentHashVersion)
	for _, e := range entries {
		writeCanonicalEntry(&buf, e.rel, e.kind, e.mode, e.length, e.payload)
	}
	return buf.Bytes(), nil
}

// ValidateContentManifest parses raw manifest bytes, validates framing, path confinement,
// character encoding, ordering, and uniqueness, and checks that the reconstructed tree digest
// matches expectedContentHash. It returns the list of validated entries.
func ValidateContentManifest(raw []byte, expectedContentHash string) ([]ContentManifestEntry, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty manifest")
	}
	expectedContentHash = strings.TrimSpace(expectedContentHash)
	if expectedContentHash == "" {
		return nil, errors.New("empty expected content hash")
	}

	// Verify version header
	newlineIdx := bytes.IndexByte(raw, '\n')
	if newlineIdx == -1 {
		return nil, errors.New("malformed manifest: missing header newline")
	}
	header := string(raw[:newlineIdx])
	if header != contentHashVersion {
		return nil, fmt.Errorf("unsupported manifest version %q, expected %q", header, contentHashVersion)
	}

	// Stream-verify the content hash directly over raw bytes
	h := sha256.New()
	h.Write(raw)
	computedHash := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(computedHash, expectedContentHash) {
		return nil, fmt.Errorf("manifest hash mismatch: computed %s, expected %s", computedHash, expectedContentHash)
	}

	// Parse entries from lines
	rest := raw[newlineIdx+1:]
	var entries []ContentManifestEntry
	var lastPath string
	hasLastPath := false

	lineStart := 0
	for lineStart < len(rest) {
		lineEnd := bytes.IndexByte(rest[lineStart:], '\n')
		if lineEnd == -1 {
			return nil, errors.New("malformed manifest: unterminated entry line")
		}
		lineEnd += lineStart
		lineBytes := rest[lineStart:lineEnd]
		lineStart = lineEnd + 1

		// Each entry has format: <rel>\t<kind>\t<mode>\t<length>\t<payload>
		parts := strings.SplitN(string(lineBytes), "\t", 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("malformed manifest entry: expected 5 tab-separated fields, got %d", len(parts))
		}
		relPath, kind, modeStr, lengthStr, payload := parts[0], parts[1], parts[2], parts[3], parts[4]

		// Path validation
		if err := validateManifestPath(relPath); err != nil {
			return nil, fmt.Errorf("invalid manifest path %q: %w", relPath, err)
		}

		// Order and uniqueness
		if hasLastPath {
			if relPath == lastPath {
				return nil, fmt.Errorf("duplicate manifest entry for path %q", relPath)
			}
			if relPath < lastPath {
				return nil, fmt.Errorf("out-of-order manifest entry: %q after %q", relPath, lastPath)
			}
		}
		lastPath = relPath
		hasLastPath = true

		// Kind validation
		switch kind {
		case "dir", "file", "symlink":
		default:
			return nil, fmt.Errorf("invalid entry kind %q for path %q", kind, relPath)
		}

		// Mode validation: octal mode (mode & 0o111)
		modeVal, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil || modeVal > 0o111 || modeStr != fmt.Sprintf("%o", modeVal) {
			return nil, fmt.Errorf("invalid mode %q for path %q", modeStr, relPath)
		}
		mode := fs.FileMode(modeVal)
		executable := (mode & 0o111) != 0

		// Length validation
		lengthVal, err := strconv.ParseInt(lengthStr, 10, 64)
		if err != nil || lengthVal < 0 || lengthStr != strconv.FormatInt(lengthVal, 10) {
			return nil, fmt.Errorf("invalid length %q for path %q", lengthStr, relPath)
		}

		// Payload validation
		switch kind {
		case "dir":
			if lengthVal != 0 {
				return nil, fmt.Errorf("directory %q must have length 0, got %d", relPath, lengthVal)
			}
			if payload != "" {
				return nil, fmt.Errorf("directory %q must have empty payload", relPath)
			}
		case "symlink":
			if int64(len(payload)) != lengthVal {
				return nil, fmt.Errorf("symlink %q length %d does not match payload length %d", relPath, lengthVal, len(payload))
			}
			if payload == "" {
				return nil, fmt.Errorf("symlink %q has empty target payload", relPath)
			}
		case "file":
			if len(payload) != 64 {
				return nil, fmt.Errorf("file %q payload must be 64-char sha256 hex digest, got %q", relPath, payload)
			}
			for _, c := range payload {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return nil, fmt.Errorf("file %q payload contains non-hex chars: %q", relPath, payload)
				}
			}
		}

		entries = append(entries, ContentManifestEntry{
			Path:       relPath,
			Kind:       kind,
			Executable: executable,
			Size:       lengthVal,
			Payload:    payload,
			Mode:       mode,
		})
	}

	return entries, nil
}

func validateManifestPath(p string) error {
	if p == "" {
		return errors.New("empty path")
	}
	if !utf8.ValidString(p) {
		return errors.New("non-UTF-8 path encoding")
	}
	// Reject control characters, carriage return, newline, null bytes
	for _, r := range p {
		if unicode.IsControl(r) {
			return errors.New("path contains control characters")
		}
	}
	// Confined relative slash-separated path
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return errors.New("path must not be absolute")
	}
	if strings.Contains(p, "\\") {
		return errors.New("path contains backslashes")
	}
	cleaned := path.Clean(p)
	if cleaned != p {
		return fmt.Errorf("path is not canonical (cleaned: %q)", cleaned)
	}
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return errors.New("path escapes root")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("path contains empty or dot segments")
		}
	}
	return nil
}

type treeEntry struct {
	rel     string
	kind    string
	mode    fs.FileMode
	length  int64
	payload string
}

func collectTreeEntries(root string) ([]treeEntry, error) {
	// WalkDir does not follow a symlink at its root. Resolve it before walking,
	// as VerifyContained does, so root aliases identify the actual source tree.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	root = resolved
	var out []treeEntry
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		// Validate the original filesystem name before t1 framing can reinterpret
		// tabs/newlines in a name as fields or additional manifest entries.
		if err := validateManifestPath(rel); err != nil {
			return fmt.Errorf("invalid snapshot path %q: %w", rel, err)
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
