package fixbinding

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// ArchiveEvidence contains the captured archive and the recorded checksum line
// that pins its exact effective coordinate. The checker hashes the full archive
// contents using Go's h1 rule; saved Complete and per-file digests confer no
// credibility. The record itself must be supplied from the immutable product
// input bundle (Task 6); this is not an admission API.
type ArchiveEvidence struct {
	Bytes   []byte `json:"bytes"`
	Module  string `json:"module"`
	Version string `json:"version"`
	GoSum   []byte `json:"go_sum"`
}

// CheckArchiveAnchor reconstructs the entire archive file set and binds it to
// the exact effective coordinate using captured go.sum evidence. This is pure:
// no directory listing, cache state or host toolchain participates.
func CheckArchiveAnchor(e ArchiveEvidence) (*SourceAnchor, error) {
 if len(e.Bytes)>32<<20 { return nil,fmt.Errorf("archive exceeds 32 MiB capture limit") }
	if e.Module == "" || e.Version == "" {
		return nil, fmt.Errorf("archive anchor requires an exact effective coordinate")
	}
	want := ""
	for _, line := range strings.Split(string(e.GoSum), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == e.Module && fields[1] == e.Version {
			if want != "" && want != fields[2] {
				return nil, fmt.Errorf("conflicting recorded module checksums")
			}
			want = fields[2]
		}
	}
	if !strings.HasPrefix(want, "h1:") {
		return nil, fmt.Errorf("no captured archive checksum for %s@%s", e.Module, e.Version)
	}
	zr, err := zip.NewReader(bytes.NewReader(e.Bytes), int64(len(e.Bytes)))
	if err != nil {
		return nil, fmt.Errorf("decode module archive: %w", err)
	}
	prefix := e.Module + "@" + e.Version + "/"
 if len(zr.File)>100000 { return nil,fmt.Errorf("archive member limit exceeded") }
 remaining:=int64(64<<20)
	files := make(map[string][]byte, len(zr.File))
 members:=map[string]bool{}
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) {
			return nil, fmt.Errorf("archive member %q has wrong coordinate", f.Name)
		}
		rel := strings.TrimPrefix(f.Name, prefix)
  clean:=strings.TrimSuffix(rel,"/")
  if clean=="" || clean=="." || clean==".." || path.Clean(clean)!=clean || strings.HasPrefix(clean,"../") || strings.HasPrefix(clean,"/") || strings.ContainsAny(clean,"\\\n\r\t") || members[clean] {return nil,fmt.Errorf("invalid/duplicate archive member %q",rel)}
  members[clean]=true
		if f.FileInfo().IsDir() {
			continue
		}
		if rel == "" || path.Clean(rel) != rel || strings.HasPrefix(rel, "../") || strings.ContainsAny(rel, "\\\n\r") || strings.HasPrefix(rel, "/") {
			return nil, fmt.Errorf("invalid archive member %q", rel)
		}
		if _, exists := files[rel]; exists {
			return nil, fmt.Errorf("duplicate archive member %q", rel)
		}
  if !f.Mode().IsRegular() || f.UncompressedSize64>32<<20 {return nil,fmt.Errorf("nonregular/oversized archive member %q",rel)}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(r,remaining+1))
		closeErr := r.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
 if int64(len(raw))>remaining { return nil,fmt.Errorf("archive expanded capture limit exceeded") }
 remaining-=int64(len(raw))
		files[rel] = raw
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("archive contains no files")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	anchor := &SourceAnchor{Kind: AnchorModuleArchive, Module: e.Module, Version: e.Version}
	for _, name := range names {
		raw := files[name]
		sum := sha256.Sum256(raw)
		fmt.Fprintf(h, "%x  %s\n", sum, prefix+name)
		anchor.Files = append(anchor.Files, AnchorFile{Path: name, Digest: DigestBytes(raw), Bytes: raw})
		anchor.Variants = appendUnique(anchor.Variants, sourceVariants(name, raw)...)
	}
	got := "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	if got != want {
		return nil, fmt.Errorf("archive checksum mismatch: got %s, recorded %s", got, want)
	}
	anchor.Checksum = ChecksumEvidence{Kind: ChecksumGoSumH1, Value: got, Source: "captured go.sum"}
	anchor.Complete = true
	anchor.Archive = &e
	return anchor, nil
}

// sourceVariants accounts for explicit constraints and filename-selected build
// variants independently of the product-linked package set.
func sourceVariants(name string, raw []byte) []string {
	if !strings.HasSuffix(name, ".go") {
		return nil
	}
	out := []string{}
	base := strings.TrimSuffix(path.Base(name), ".go")
	if strings.Contains(base, "_") {
		out = append(out, "filename:"+base)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build ") || strings.HasPrefix(line, "// +build ") {
			out = append(out, line)
		}
		if line != "" && !strings.HasPrefix(line, "//") {
			break
		}
	}
	return out
}
