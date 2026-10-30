package goanalysis

import (
	"fmt"
 "io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fixbinding"
)

// A local selection's own directory digest identifies its bytes but cannot
// independently certify the inventory boundary. Capture the entire product
// tree and reconstruct the recorded t1 snapshot identity before extracting it.
func (ix *Index) capturedLocalTree(sel domain.EffectiveSourceSelection) *fixbinding.SourceAnchor {
	if ix.Build.ContentHash == "" {
		return nil
	}
	root := sel.SourceRoot
	if sel.SourceKind == domain.ModuleSourceVendor && sel.LocalReplacement != nil {
		root = sel.LocalReplacement.Directory
	}
	evidence := fixbinding.TreeEvidence{SnapshotDigest: ix.Build.ContentHash, Module: sel.EffectiveModule, Root: root, ContentDigest: sel.ContentDigest}
	if sel.SourceKind == domain.ModuleSourceVendor {
		dir := filepath.Join(ix.Dir, filepath.FromSlash(root))
		digest, err := moduleTreeDigest(dir)
		if err != nil {
			return nil
		}
		evidence.ContentDigest = digest
	}
 capturedBytes:=int64(0)
	err := filepath.WalkDir(ix.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(ix.Dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("complete local capture does not support nonregular entry %s", rel)
		}
		entry := fixbinding.TreeEntry{Path: filepath.ToSlash(rel), Directory: d.IsDir(), Executable: uint32(info.Mode() & 0111)}
  if len(evidence.Entries)>=100000 || info.Size()>32<<20 {return fmt.Errorf("local source capture member/size limit exceeded")}
  if !d.IsDir(){capturedBytes+=info.Size();if capturedBytes>128<<20{return fmt.Errorf("local source capture exceeds 128 MiB")}}
		if !d.IsDir() {
   f,openErr:=os.Open(p);if openErr!=nil{return openErr}
   entry.Bytes,err=io.ReadAll(io.LimitReader(f,32<<20+1));closeErr:=f.Close();if closeErr!=nil && err==nil{err=closeErr}
   if len(entry.Bytes)>32<<20{return fmt.Errorf("local source file exceeds capture limit")}
			if err != nil {
				return err
			}
		}
		evidence.Entries = append(evidence.Entries, entry)
		return nil
	})
	if err != nil {
		return &fixbinding.SourceAnchor{Kind: fixbinding.AnchorLocalTree, Module: sel.EffectiveModule, Reason: err.Error()}
	}
	anchor, err := fixbinding.CheckTreeAnchor(evidence)
	if err != nil {
		return &fixbinding.SourceAnchor{Kind: fixbinding.AnchorLocalTree, Module: sel.EffectiveModule, Tree: &evidence, Reason: err.Error()}
	}
	return anchor
}
