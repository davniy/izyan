package goanalysis

import (
	"fmt"
 "io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fixbinding"
	"golang.org/x/mod/module"
)

// SourceCensus is diagnostic, not an admission object. Its four results answer
// separate questions; neither selection nor parsing certifies an inventory.
type SourceCensus struct {
	Selection    domain.EffectiveSourceSelection
	Inventory    fixbinding.SourceInventory
	Census       *fixbinding.Census
	Completeness fixbinding.Completeness
}

func (ix *Index) SelectedSourceCensus(modulePath, version string) (*SourceCensus, error) {
	src, err := ix.SelectedModuleSource(modulePath, version)
	if err != nil {
		return nil, err
	}
	return ix.sourceCensus(src)
}

// SelectedSourceCensusFor retains Task 2's declared/effective coordinate and
// original entry. No original-module fallback can answer for a replacement.
func (ix *Index) SelectedSourceCensusFor(selection domain.EffectiveSourceSelection) (*SourceCensus, error) {
	if err := ix.VerifyModuleSource(selection); err != nil {
		return nil, err
	}
	src, err := ix.ResolveModuleSource(selection.DeclaredModule, selection.DeclaredVersion, selection.EffectiveVersion)
	if err != nil {
		return nil, err
	}
	src.Selection.EntryRef = selection.EntryRef
	return ix.sourceCensus(src)
}

func (ix *Index) sourceCensus(src domain.ResolvedModuleSource) (*SourceCensus, error) {
	sel := src.Selection
	files, gaps := walkCensusTree(src.Dir)
	observed := fixbinding.ObservedSource{
		Kind: fixbinding.SourceKind(sel.SourceKind), Module: sel.EffectiveModule,
		Version: sel.EffectiveVersion, Root: sel.SourceRoot,
		Files: files, WalkComplete: len(gaps) == 0, WalkGaps: gaps,
	}
	if sel.SourceKind == domain.ModuleSourceVendor {
		observed.ManifestPackages = ix.censusVendorPackages(sel.DeclaredModule)
		observed.ManifestModules = []string{sel.DeclaredModule + "@" + sel.DeclaredVersion}
	}
	anchor := ix.capturedArchive(sel)
	inv := fixbinding.AssembleInventory(fixbinding.InventoryInput{
		Module: sel.EffectiveModule, Version: sel.EffectiveVersion,
		Observed: observed, Anchor: anchor,
	})
	out := &SourceCensus{Selection: sel, Inventory: inv}
	if captured := inv.CensusFiles(); len(captured) > 0 {
		c, err := fixbinding.CensusSource(fixbinding.CensusOptions{
			Module: fixbinding.ModuleIdentity{Kind: string(sel.SourceKind), Path: sel.EffectiveModule,
				Version: sel.EffectiveVersion, Digest: sel.ContentDigest}, ImportPath: sel.DeclaredModule, Files: captured,
		})
		if err != nil {
			return nil, err
		}
		out.Census = c
	}
	out.Completeness = fixbinding.Assess(inv, out.Census)
	return out, nil
}

// capturedArchive acquires the exact effective module zip and the product's
// recorded checksum bytes. Directory content and modules.txt never establish
// the archive's file boundary. Missing captures remain explicit input gaps.
func (ix *Index) capturedArchive(sel domain.EffectiveSourceSelection) *fixbinding.SourceAnchor {
	if sel.LocalReplacement != nil || sel.Workspace != nil {
		return ix.capturedLocalTree(sel)
	}
	if sel.EffectiveVersion == "" || sel.LocalReplacement != nil || sel.Workspace != nil {
		return nil // A complete captured product/VCS tree is required, not a listing.
	}
	p, err := module.EscapePath(sel.EffectiveModule)
	if err != nil {
		return nil
	}
	v, err := module.EscapeVersion(sel.EffectiveVersion)
	if err != nil {
		return nil
	}
	zipBytes, err := os.ReadFile(filepath.Join(ix.modCacheDir(), "cache", "download", p, "@v", v+".zip"))
	if err != nil {
		return nil
	}
	sums, err := os.ReadFile(filepath.Join(ix.Dir, "go.sum"))
	if err != nil {
		return nil
	}
	evidence := fixbinding.ArchiveEvidence{Bytes: zipBytes, Module: sel.EffectiveModule, Version: sel.EffectiveVersion, GoSum: sums}
	anchor, err := fixbinding.CheckArchiveAnchor(evidence)
	if err != nil {
		return &fixbinding.SourceAnchor{Kind: fixbinding.AnchorModuleArchive, Module: sel.EffectiveModule,
			Version: sel.EffectiveVersion, Archive: &evidence, Reason: err.Error()}
	}
	return anchor
}

// walkCensusTree captures every regular file, without build filtering. Symlinks
// and read failures are gaps; neither is followed outside the selected source.
func walkCensusTree(root string) ([]fixbinding.ObservedFile, []string) {
	var files []fixbinding.ObservedFile
	var gaps []string
 capturedBytes:=int64(0)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			gaps = append(gaps, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			gaps = append(gaps, err.Error())
			return nil
		}
		if !d.Type().IsRegular() {
			gaps = append(gaps, "unsupported nonregular file: "+rel)
			return nil
		}
  info,err:=d.Info();if err!=nil{return err}
  if len(files)>=100000 || info.Size()>32<<20 || capturedBytes+info.Size()>128<<20{return fmt.Errorf("selected source census capture limit exceeded")}
  capturedBytes+=info.Size()
  f,err:=os.Open(p);if err!=nil{return err}
  raw,err:=io.ReadAll(io.LimitReader(f,32<<20+1));closeErr:=f.Close();if closeErr!=nil && err==nil{err=closeErr}
  if len(raw)>32<<20{return fmt.Errorf("selected source file exceeds capture limit")}
		if err != nil {
			gaps = append(gaps, err.Error())
			return nil
		}
		files = append(files, fixbinding.ObservedFile{Path: filepath.ToSlash(rel), Bytes: raw, Digest: fixbinding.DigestBytes(raw)})
		return nil
	})
	if err != nil {
		gaps = append(gaps, err.Error())
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, gaps
}

// censusVendorPackages records subset membership only, using module-relative
// package paths. Replacements do not change vendored import paths.
func (ix *Index) censusVendorPackages(modulePath string) []string {
	raw, err := os.ReadFile(filepath.Join(ix.Dir, "vendor", "modules.txt"))
	if err != nil {
		return nil
	}
	current := ""
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			fields := strings.Fields(strings.TrimPrefix(line, "# "))
			current = ""
			if len(fields) >= 2 && fields[1] != "=>" {
				current = fields[0]
			}
			continue
		}
		if strings.HasPrefix(line, "#") || current != modulePath {
			continue
		}
		if line == modulePath {
			out = append(out, ".")
		} else if strings.HasPrefix(line, modulePath+"/") {
			out = append(out, strings.TrimPrefix(line, modulePath+"/"))
		}
	}
	return sortedUniqueStrings(out)
}
