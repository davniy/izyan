package fixbinding

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// This file establishes what a source inventory may claim. Four results are
// measured and reported separately because they answer four different
// questions, and an analysis that collapses them into one flag always ends up
// letting a measured-but-incomplete fact authorise a conclusion:
//
//	INPUT     — is the file set the analysis reads the whole implementation?
//	PARSE     — was every one of those files actually parsed and resolved?
//	ANALYSIS  — did the operation/resource scan account for every use?
//	COVER     — could any alternative implementation be missing from the
//	            enumerated subject set?
//
// A vendored tree answers the first question "no" on its own. vendor/modules.txt
// records which module and which packages the build selected; it is a
// selection and subset-membership observation, never a statement about the
// packages or files the upstream module contains. Whole-implementation
// coverage therefore needs an independent anchor: the exact module archive tied
// to the selected coordinate with captured checksum evidence, a complete
// captured VCS tree, or a complete captured local-replacement tree anchored in
// the product snapshot.

// CompletenessAspect names one of the four results. They are not
// interchangeable and there is deliberately no aggregate accessor: a consumer
// that needs a specific aspect must read that aspect and state why it accepts
// it.
type CompletenessAspect string

const (
	// AspectInput is input-inventory completeness: the analysis reads the
	// whole implementation, established from an independently anchored source.
	AspectInput CompletenessAspect = "INPUT_INVENTORY"
	// AspectParse is parsing/type-resolution completeness.
	AspectParse CompletenessAspect = "PARSE_TYPE_RESOLUTION"
	// AspectAnalysis is operation/resource analysis completeness.
	AspectAnalysis CompletenessAspect = "OPERATION_RESOURCE_ANALYSIS"
	// AspectCover is necessary-cover completeness: no alternative subject can
	// be missing from the enumerated set. It is a precondition of a necessary
	// disjunction, not the disjunction itself.
	AspectCover CompletenessAspect = "NECESSARY_COVER"
)

// AspectResult is one checker-derived result. Complete is true only when the
// aspect was measured against its own evidence; Reason states the measured
// fact, and Blocking lists the codes that blocked it.
type AspectResult struct {
	Aspect   CompletenessAspect `json:"aspect"`
	Complete bool               `json:"complete"`
	Reason   string             `json:"reason,omitempty"`
	Blocking []string           `json:"blocking,omitempty"`
}

func (r *AspectResult) fail(code, format string, args ...any) {
	r.Complete = false
	if r.Reason == "" {
		r.Reason = fmt.Sprintf(format, args...)
	}
	if code != "" {
		r.Blocking = appendUnique(r.Blocking, code)
	}
}

// Completeness carries the four results side by side. It has no method that
// reports "the inventory is complete": every caller must name the aspect it
// relies on, so a weaker measured fact cannot stand in for a stronger one.
type Completeness struct {
	Input    AspectResult `json:"input"`
	Parse    AspectResult `json:"parse"`
	Analysis AspectResult `json:"analysis"`
	Cover    AspectResult `json:"cover"`
}

// Result returns one aspect's result.
func (c Completeness) Result(aspect CompletenessAspect) AspectResult {
	switch aspect {
	case AspectInput:
		return c.Input
	case AspectParse:
		return c.Parse
	case AspectAnalysis:
		return c.Analysis
	case AspectCover:
		return c.Cover
	}
	return AspectResult{Aspect: aspect, Reason: fmt.Sprintf("the aspect %q is unknown", aspect)}
}

// Assess combines the two independently measured halves: the input inventory
// (established from the anchored source) and the census results (parse,
// analysis, cover). Each result keeps its own evidence and reason.
func Assess(inv SourceInventory, c *Census) Completeness {
	out := Completeness{}
	out.Input = inv.Input
	if c == nil {
		missing := "no census was measured for this source"
		out.Parse = AspectResult{Aspect: AspectParse, Reason: missing, Blocking: []string{CodeCensusMissing}}
		out.Analysis = AspectResult{Aspect: AspectAnalysis, Reason: missing, Blocking: []string{CodeCensusMissing}}
		out.Cover = AspectResult{Aspect: AspectCover, Reason: missing, Blocking: []string{CodeCensusMissing}}
		return out
	}
	out.Parse = c.Parse
	out.Analysis = c.Analysis
	out.Cover = c.Cover
	return out
}

// AnchorKind names one independently established inventory of a selected
// implementation.
type AnchorKind string

const (
	// AnchorModuleArchive is the exact module archive tied to the selected
	// coordinate, with captured checksum evidence binding it to that
	// coordinate.
	AnchorModuleArchive AnchorKind = "MODULE_ARCHIVE"
	// AnchorVCSTree is a complete captured VCS tree.
	AnchorVCSTree AnchorKind = "VCS_TREE"
	// AnchorLocalTree is a complete captured local-replacement or workspace
	// module tree, anchored in the product snapshot.
	AnchorLocalTree AnchorKind = "LOCAL_REPLACEMENT_TREE"
)

// ChecksumKind names the captured evidence that binds an anchor to its
// selected coordinate.
type ChecksumKind string

const (
	// ChecksumGoSumH1 is a go.sum h1 module hash (an exact archive hash).
	ChecksumGoSumH1 ChecksumKind = "go.sum/h1"
	// ChecksumVCSCommit is a captured VCS commit identity.
	ChecksumVCSCommit ChecksumKind = "vcs-commit"
	// ChecksumTreeDigest is the digest of a captured tree that the snapshot
	// itself owns (a confined local replacement or workspace member).
	ChecksumTreeDigest ChecksumKind = "tree-digest"
)

// ChecksumEvidence records the captured checksum that ties an anchor to the
// coordinate it claims. An anchor without checksum evidence is not anchored.
type ChecksumEvidence struct {
	Kind   ChecksumKind `json:"kind"`
	Value  string       `json:"value"`
	Source string       `json:"source,omitempty"`
}

// AnchorFile is one file the independent inventory establishes.
type AnchorFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	// Bytes is the captured content, analysis-local. The persisted identity is
	// the digest; a checker receives the bytes as part of its input bundle.
	Bytes []byte `json:"-"`
}

// SourceAnchor is one independently established complete inventory of a
// selected implementation: the exact file set and the evidence that binds it
// to the selected coordinate.
type SourceAnchor struct {
	Kind     AnchorKind       `json:"kind"`
	Module   string           `json:"module"`
	Version  string           `json:"version,omitempty"`
	Checksum ChecksumEvidence `json:"checksum"`
	Archive  *ArchiveEvidence `json:"archive,omitempty"`
	Tree     *TreeEvidence    `json:"tree,omitempty"`
	// Files is the complete file set, sorted by path.
	Files []AnchorFile `json:"files"`
	// Variants are the build constraints the anchor accounts for. A variant
	// the observed source uses and the anchor does not carry makes the anchor
	// incomplete for this build.
	Variants []string `json:"variants,omitempty"`
	Complete bool     `json:"complete"`
	Reason   string   `json:"reason,omitempty"`
	// WalkGaps records entries the acquisition could not read. A walk with a
	// gap is not a complete inventory.
	WalkGaps []string `json:"walk_gaps,omitempty"`
}

// FileList returns the anchor's paths in sorted order.
func (a *SourceAnchor) FileList() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.Files))
	for _, f := range a.Files {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

// SourceKind names how the observed bytes were acquired.
type SourceKind string

const (
	SourceVendor           SourceKind = "vendor"
	SourceModuleCache      SourceKind = "module-cache"
	SourceLocalReplacement SourceKind = "local-replacement"
	SourceVCSTree          SourceKind = "vcs-tree"
)

// ObservedFile is one file the acquisition enumerated.
type ObservedFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Bytes  []byte `json:"-"`
}

// ObservedSource is the source tree the analysis actually reads, together with
// the evidence the acquisition collected about it. The manifest fields are
// selection evidence only: ManifestModules says which module the build
// selected, ManifestPackages which packages it vendored.
type ObservedSource struct {
	Kind    SourceKind `json:"kind"`
	Module  string     `json:"module"`
	Version string     `json:"version,omitempty"`
	Root    string     `json:"root,omitempty"`
	// Files is the complete enumeration of the tree, sorted by path.
	Files []ObservedFile `json:"files"`
	// Digest is the digest of the file set (path and content).
	Digest string `json:"digest,omitempty"`
	// ManifestModules and ManifestPackages are what vendor/modules.txt
	// establishes: the selected module and the vendored package subset.
	ManifestModules  []string `json:"manifest_modules,omitempty"`
	ManifestPackages []string `json:"manifest_packages,omitempty"`
	// Variants are the build constraints the acquisition accounted for.
	Variants []string `json:"variants,omitempty"`
	// WalkComplete reports whether the enumeration covered the whole tree.
	WalkComplete bool     `json:"walk_complete"`
	WalkGaps     []string `json:"walk_gaps,omitempty"`
}

// VendorReconciliation reconciles the vendored bytes with the anchored source.
// The manifest establishes selection and subset membership; only this
// reconciliation establishes that the compiled bytes are a faithful subset of
// the anchored implementation.
type VendorReconciliation struct {
	// Retained files are present in the vendor tree with the anchored digest.
	Retained []string `json:"retained,omitempty"`
	// Pruned files belong to packages the build did not vendor. They stay in
	// the discovery inventory, so a pruned package cannot hide an alternative.
	Pruned []string `json:"pruned,omitempty"`
	// Trimmed files belong to a vendored package but are missing from the
	// vendor tree. Vendor pruning works at package granularity, so a partial
	// package is a trimmed overlay, not pruning.
	Trimmed []string `json:"trimmed,omitempty"`
	// Modified files disagree with the anchored digest.
	Modified []string `json:"modified,omitempty"`
	// Extras are vendored files the anchor does not contain.
	Extras []string `json:"extras,omitempty"`
	// UnlistedPackages are anchored packages vendor/modules.txt does not list.
	UnlistedPackages []string `json:"unlisted_packages,omitempty"`
	// Overlay reports bytes that do not come from the anchored source.
	Overlay  bool     `json:"overlay"`
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons,omitempty"`
}

// InventoryInput is the antecedent evidence for one selected implementation.
type InventoryInput struct {
	Module   string
	Version  string
	Observed ObservedSource
	// Anchor is the independent complete inventory, nil when none was captured.
	Anchor *SourceAnchor
}

// SourceInventory is the measured inventory of one selected implementation:
// what the build reads, what the independent anchor establishes, and the
// input-inventory result derived from their relationship.
type SourceInventory struct {
	Module         string                `json:"module"`
	Version        string                `json:"version,omitempty"`
	Observed       ObservedSource        `json:"observed"`
	Anchor         *SourceAnchor         `json:"anchor,omitempty"`
	Reconciliation *VendorReconciliation `json:"reconciliation,omitempty"`
	Input          AspectResult          `json:"input"`
}

// Anchored reports whether an independent complete inventory was established.
func (s SourceInventory) Anchored() bool {
	return s.Anchor != nil && s.Anchor.Complete && s.Anchor.Checksum.Value != "" && s.Input.Complete
}

// CensusFiles returns the file bytes the census must scan. When an anchor
// exists the census scans the anchored implementation, never the observed
// subset: a vendored build must enumerate alternatives the build did not link.
func (s SourceInventory) CensusFiles() map[string][]byte {
	out := map[string][]byte{}
	if s.Anchor != nil && len(s.Anchor.Files) > 0 {
		for _, f := range s.Anchor.Files {
			if f.Bytes != nil {
				out[f.Path] = f.Bytes
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, f := range s.Observed.Files {
		if f.Bytes != nil {
			out[f.Path] = f.Bytes
		}
	}
	return out
}

// AssembleInventory measures one selected implementation's input inventory.
// Every rule here answers the same question — "are these bytes the whole
// implementation?" — and none of them accepts a manifest, a directory listing
// or a successful parse as the answer.
func AssembleInventory(in InventoryInput) SourceInventory {
	out := SourceInventory{
		Module:   in.Module,
		Version:  in.Version,
		Observed: sortedObserved(in.Observed),
		Anchor:   sortAnchor(in.Anchor),
		Input:    AspectResult{Aspect: AspectInput},
	}
	out.Input.Complete = true
	// Reconstruct the boundary from independently pinned captured bytes, not
	// saved completeness, per-file digests or a directory listing.
	if out.Anchor != nil {
		var checked *SourceAnchor
		var err error
		switch {
		case out.Anchor.Archive != nil && out.Anchor.Tree == nil:
			checked, err = CheckArchiveAnchor(*out.Anchor.Archive)
		case out.Anchor.Tree != nil && out.Anchor.Archive == nil:
			checked, err = CheckTreeAnchor(*out.Anchor.Tree)
		default:
			err = fmt.Errorf("no unambiguous supported complete capture evidence accompanies this anchor")
		}
		if err != nil {
			out.Input.fail(CodeAnchorUnchecked, "%v", err)
		} else {
			out.Anchor = checked
		}
	}
	for i := range out.Observed.Files {
		f := &out.Observed.Files[i]
		if f.Bytes == nil {
			out.Input.fail(CodeWalkIncomplete, "observed file %s has no captured bytes", f.Path)
		} else {
			f.Digest = DigestBytes(f.Bytes)
		}
	}

	if !out.Observed.WalkComplete {
		out.Input.fail(CodeWalkIncomplete,
			"the %s source walk for %s did not complete: %s",
			out.Observed.Kind, in.Module, strings.Join(out.Observed.WalkGaps, "; "))
	}
	if out.Anchor == nil {
		out.Input.fail(CodeNoAnchor,
			"no independently anchored inventory exists for %s: a %s tree establishes selection and subset membership only, never the whole implementation",
			in.Module, out.Observed.Kind)
		out.Input.Complete = false
		return out
	}
	if !out.Anchor.Complete {
		reason := out.Anchor.Reason
		if reason == "" {
			reason = "the anchor did not complete its own enumeration"
		}
		out.Input.fail(CodeAnchorIncomplete, "the anchored inventory of %s is incomplete: %s", out.Anchor.Module, reason)
	}
	if out.Anchor.Checksum.Value == "" || out.Anchor.Checksum.Kind == "" {
		out.Input.fail(CodeAnchorUnchecked,
			"the anchored inventory of %s carries no captured checksum evidence, so it is not tied to the selected coordinate",
			out.Anchor.Module)
	}
	if strings.TrimSpace(out.Anchor.Module) != strings.TrimSpace(in.Module) {
		out.Input.fail(CodeAnchorCoordinate,
			"the anchored inventory names %s but the selection is %s", out.Anchor.Module, in.Module)
	}
	if out.Anchor.Version != "" && in.Version != "" && out.Anchor.Version != in.Version {
		out.Input.fail(CodeAnchorCoordinate,
			"the anchored inventory names %s@%s but the selection is %s@%s",
			out.Anchor.Module, out.Anchor.Version, in.Module, in.Version)
	}
	if len(out.Observed.WalkGaps) > 0 {
		out.Input.fail(CodeWalkIncomplete, "the observed tree carries unread entries: %s", strings.Join(out.Observed.WalkGaps, "; "))
	}

	// A build variant the observed source uses and the anchor does not carry
	// means the anchor was captured under a narrower build view: the
	// implementation behind that variant is simply not in the inventory.
	for _, file := range out.Observed.Files {
		for _, variant := range sourceVariants(file.Path, file.Bytes) {
			if !containsString(out.Anchor.Variants, variant) {
				out.Input.fail(CodeVariantUnaccounted, "observed variant %q is not in the anchored inventory", variant)
			}
		}
	}

	if out.Observed.Kind == SourceVendor {
		out.Reconciliation = reconcileVendor(out.Observed, out.Anchor)
		if !out.Reconciliation.Complete {
			for _, reason := range out.Reconciliation.Reasons {
				out.Input.fail(CodeVendorOverlay, "%s", reason)
			}
			out.Input.Complete = false
		}
		return out
	}

	// A non-vendored carrier must be exactly the anchored tree: the analysis
	// reads the same bytes the anchor describes, or it is reading some other
	// source.
	if diff := compareFileSets(out.Observed.Files, out.Anchor.Files); diff != "" {
		out.Input.fail(CodeNotAnchored, "the observed %s source is not the anchored tree: %s", out.Observed.Kind, diff)
	}
	return out
}

// reconcileVendor reconciles the vendored bytes with the anchored implementation.
// Every retained byte must agree. Omitted non-Go/test metadata is recorded as
// pruned, while missing Go files in retained/listed packages are refused.
func reconcileVendor(observed ObservedSource, anchor *SourceAnchor) *VendorReconciliation {
	rec := &VendorReconciliation{}
	anchorDigests := make(map[string]string, len(anchor.Files))
	for _, f := range anchor.Files {
		anchorDigests[f.Path] = f.Digest
	}
	observedDigests := make(map[string]string, len(observed.Files))
	for _, f := range observed.Files {
		observedDigests[f.Path] = f.Digest
	}
	vendoredDirs := map[string]bool{}
	for p := range observedDigests {
		vendoredDirs[path.Dir(p)] = true
	}
	for _, dir := range observed.ManifestPackages {
		if dir == "" {
			dir = "."
		}
		vendoredDirs[dir] = true
	}

	anchorPaths := make([]string, 0, len(anchorDigests))
	for p := range anchorDigests {
		anchorPaths = append(anchorPaths, p)
	}
	sort.Strings(anchorPaths)
	for _, p := range anchorPaths {
		got, present := observedDigests[p]
		want := anchorDigests[p]
		switch {
		case present && want != "" && got == want:
			rec.Retained = append(rec.Retained, p)
		case present:
			rec.Modified = append(rec.Modified, p)
		case vendoredDirs[path.Dir(p)] && isCensusGoFile(p):
			rec.Trimmed = append(rec.Trimmed, p)
		default:
			rec.Pruned = append(rec.Pruned, p)
		}
	}
	observedPaths := make([]string, 0, len(observedDigests))
	for p := range observedDigests {
		observedPaths = append(observedPaths, p)
	}
	sort.Strings(observedPaths)
	for _, p := range observedPaths {
		if _, ok := anchorDigests[p]; !ok {
			rec.Extras = append(rec.Extras, p)
		}
	}

	listed := make(map[string]bool, len(observed.ManifestPackages))
	for _, p := range observed.ManifestPackages {
		listed[p] = true
	}
	seen := map[string]bool{}
	for _, p := range anchorPaths {
		if !isCensusGoFile(p) {
			continue
		}
		pkg := path.Dir(p)
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		if !listed[pkg] {
			rec.UnlistedPackages = append(rec.UnlistedPackages, pkg)
		}
	}
	sort.Strings(rec.UnlistedPackages)

	rec.Complete = true
	for _, f := range observed.Files {
		if isCensusGoFile(f.Path) && !listed[path.Dir(f.Path)] {
			rec.Complete = false
			rec.Reasons = append(rec.Reasons, "vendored package is not a member of the manifest subset: "+path.Dir(f.Path))
		}
	}
	if len(rec.Modified) > 0 {
		rec.Overlay = true
		rec.Complete = false
		rec.Reasons = append(rec.Reasons, fmt.Sprintf(
			"%d vendored file(s) disagree with the anchored source: %s",
			len(rec.Modified), strings.Join(preview(rec.Modified), ", ")))
	}
	if len(rec.Extras) > 0 {
		rec.Overlay = true
		rec.Complete = false
		rec.Reasons = append(rec.Reasons, fmt.Sprintf(
			"%d vendored file(s) do not exist in the anchored source: %s",
			len(rec.Extras), strings.Join(preview(rec.Extras), ", ")))
	}
	if len(rec.Trimmed) > 0 {
		rec.Complete = false
		rec.Reasons = append(rec.Reasons, fmt.Sprintf(
			"%d anchored file(s) are missing from a package the vendor tree does carry (%s); vendor pruning works at package granularity, so this is a trimmed overlay, not pruning",
			len(rec.Trimmed), strings.Join(preview(rec.Trimmed), ", ")))
	}
	return rec
}

// compareFileSets returns a description of the first difference between two
// file sets, or "" when they are identical.
func compareFileSets(observed []ObservedFile, anchored []AnchorFile) string {
	if len(observed) != len(anchored) {
		return fmt.Sprintf("the observed tree carries %d file(s) and the anchor %d", len(observed), len(anchored))
	}
	for i := range observed {
		if observed[i].Path != anchored[i].Path {
			return fmt.Sprintf("the observed tree carries %q where the anchor carries %q", observed[i].Path, anchored[i].Path)
		}
		if observed[i].Digest != anchored[i].Digest {
			return fmt.Sprintf("the digest of %q changed", observed[i].Path)
		}
	}
	return ""
}

func sortedObserved(s ObservedSource) ObservedSource {
	s.Files = append([]ObservedFile(nil), s.Files...)
	sort.SliceStable(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	s.ManifestModules = appendUnique(nil, s.ManifestModules...)
	s.ManifestPackages = appendUnique(nil, s.ManifestPackages...)
	s.Variants = appendUnique(nil, s.Variants...)
	s.WalkGaps = appendUnique(nil, s.WalkGaps...)
	return s
}

func sortAnchor(a *SourceAnchor) *SourceAnchor {
	if a == nil {
		return nil
	}
	cp := *a
	cp.Files = append([]AnchorFile(nil), a.Files...)
	sort.SliceStable(cp.Files, func(i, j int) bool { return cp.Files[i].Path < cp.Files[j].Path })
	cp.Variants = appendUnique(nil, a.Variants...)
	cp.WalkGaps = appendUnique(nil, a.WalkGaps...)
	return &cp
}

func appendUnique(dst []string, values ...string) []string {
	for _, v := range values {
		if v == "" || containsString(dst, v) {
			continue
		}
		dst = append(dst, v)
	}
	return dst
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// preview caps an evidence list so a reason stays readable.
func preview(list []string) []string {
	const max = 5
	if len(list) <= max {
		return list
	}
	out := append([]string(nil), list[:max]...)
	return append(out, fmt.Sprintf("… and %d more", len(list)-max))
}

// Blocking codes. A consumer reads the code, not the prose.
const (
	CodeNoAnchor           = "NO_INDEPENDENT_ANCHOR"
	CodeAnchorIncomplete   = "ANCHOR_INCOMPLETE"
	CodeAnchorUnchecked    = "ANCHOR_UNCHECKED"
	CodeAnchorCoordinate   = "ANCHOR_COORDINATE_MISMATCH"
	CodeVariantUnaccounted = "BUILD_VARIANT_UNACCOUNTED"
	CodeVendorOverlay      = "VENDOR_OVERLAY"
	CodeWalkIncomplete     = "SOURCE_WALK_INCOMPLETE"
	CodeNotAnchored        = "OBSERVED_NOT_ANCHORED"
	CodeCensusMissing      = "CENSUS_MISSING"
)
