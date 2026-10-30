package fixbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
)

// TreeEntry is a captured product-snapshot t1 entry, including directories and
// executable bits. This is not a directory listing: every regular file's bytes
// are supplied and the complete entry set must reconstruct the independently
// recorded product content hash. Symlink-bearing captures remain unsupported.
type TreeEntry struct {
	Path       string `json:"path"`
	Directory  bool   `json:"directory,omitempty"`
	Executable uint32 `json:"executable,omitempty"`
	Bytes      []byte `json:"bytes,omitempty"`
}

type TreeEvidence struct {
	Entries        []TreeEntry `json:"entries"`
	SnapshotDigest string      `json:"snapshot_digest"`
	Module         string      `json:"module"`
	Root           string      `json:"root"`
	// ContentDigest is Task 2's content identity for the selected local root.
	ContentDigest string `json:"content_digest"`
}

func CheckTreeAnchor(e TreeEvidence) (*SourceAnchor, error) {
	if e.Module == "" || e.SnapshotDigest == "" || e.ContentDigest == "" || e.Root == "" {
		return nil, fmt.Errorf("tree evidence lacks independently recorded snapshot/local selection identity")
	}
	if path.Clean(e.Root) != e.Root || strings.HasPrefix(e.Root, "/") || e.Root == ".." || strings.HasPrefix(e.Root, "../") || strings.Contains(e.Root, "\\") {
		return nil, fmt.Errorf("unconfined captured local root")
	}
	entries := append([]TreeEntry(nil), e.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	h := sha256.New()
	fmt.Fprint(h, "t1\n")
	seen := map[string]bool{}
	for _, entry := range entries {
		p := entry.Path
		if p == "" || path.Clean(p) != p || strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../") || strings.ContainsAny(p, "\\\n\r\t") || seen[p] {
			return nil, fmt.Errorf("invalid/duplicate product entry %q", p)
		}
		for _, part := range strings.Split(p, "/") {
			if part == ".git" {
				return nil, fmt.Errorf("administrative entry is not product content")
			}
		}
		seen[p] = true
		if entry.Executable & ^uint32(0111) != 0 {
			return nil, fmt.Errorf("unsupported entry mode")
		}
		if entry.Directory {
			fmt.Fprintf(h, "%s\tdir\t%o\t0\t\n", p, entry.Executable)
		} else {
			sum := sha256.Sum256(entry.Bytes)
			fmt.Fprintf(h, "%s\tfile\t%o\t%d\t%x\n", p, entry.Executable, len(entry.Bytes), sum)
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.TrimPrefix(e.SnapshotDigest, "sha256:") {
		return nil, fmt.Errorf("captured product tree does not match independently recorded t1 snapshot identity")
	}
	a := &SourceAnchor{Kind: AnchorLocalTree, Module: e.Module, Tree: &e}
	local := sha256.New()
	// Task 2's moduleTreeDigest uses WalkDir order (component-wise lexical),
	// while the product t1 hash above uses whole-path lexical order.
	sort.Slice(entries, func(i, j int) bool {
		left, right := strings.Split(entries[i].Path, "/"), strings.Split(entries[j].Path, "/")
		for k := 0; k < len(left) && k < len(right); k++ {
			if left[k] != right[k] {
				return left[k] < right[k]
			}
		}
		return len(left) < len(right)
	})
	for _, entry := range entries {
		if entry.Directory || (e.Root != "." && !strings.HasPrefix(entry.Path, e.Root+"/")) {
			continue
		}
		rel := entry.Path
		if e.Root != "." {
			rel = strings.TrimPrefix(entry.Path, e.Root+"/")
		}
		local.Write([]byte(rel))
		local.Write([]byte{0})
		local.Write(entry.Bytes)
		local.Write([]byte{0})
		a.Files = append(a.Files, AnchorFile{Path: rel, Bytes: entry.Bytes, Digest: DigestBytes(entry.Bytes)})
		a.Variants = appendUnique(a.Variants, sourceVariants(rel, entry.Bytes)...)
	}
	sort.Slice(a.Files, func(i, j int) bool { return a.Files[i].Path < a.Files[j].Path })
	got := "sha256:" + hex.EncodeToString(local.Sum(nil))
	if got != e.ContentDigest || len(a.Files) == 0 {
		return nil, fmt.Errorf("captured local root does not match Task 2 selected content digest")
	}
	a.Checksum = ChecksumEvidence{Kind: ChecksumTreeDigest, Value: got, Source: "captured product t1:" + e.SnapshotDigest}
	a.Complete = true
	return a, nil
}
