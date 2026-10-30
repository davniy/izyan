package fixbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// This file reconstructs the premises of one binding from the pinned input
// bundle. It reads no file, runs no process and consults no cache: every
// premise is either captured bytes, an independently measured record supplied
// in the bundle, or a fact re-derived from those two.
//
// The order is deliberate. Identity and entry are established first because
// every later premise is about *this* record's *this* entry. The effective
// coordinate and its anchored inventory follow, because the census must scan the
// implementation the recorded build actually ships. Only then are the artifacts
// re-hashed and inventoried, the patch effects mapped onto the census, the
// mechanism covers built and the non-counterpart certificates derived.

// Derive reconstructs the canonical binding for one pinned input bundle.
//
// A non-nil error is a refusal carrying the premise that could not be
// re-derived; the returned binding still states what was measured so a caller
// can render the obligation. A nil error means the cover was reconstructed;
// absence authority additionally requires Admit (the claim relationship).
func Derive(in Inputs) (Binding, error) {
	b := Binding{Contract: domain.FixProofContract, Rules: domain.FixProofRules, EntryRef: in.EntryRef, Status: BindingUnmeasured}

	// 1. Record identity: the pin must describe exactly these bytes, and the
	// bytes must decode to exactly that record.
	vuln, err := deriveRecord(&b, in)
	if err != nil {
		return b, err
	}

	// 2. The original affected[] entry the binding is about.
	entry, err := deriveEntry(vuln, in.EntryRef)
	if err != nil {
		return b, err
	}
	b.Entry = entry

	// 3. The effective source the recorded build selects for that entry, and
	// the independently anchored inventory of it.
	sel, err := deriveSelection(in, entry)
	if err != nil {
		return b, err
	}
	b.Module, b.Version = sel.EffectiveModule, sel.EffectiveVersion
	b.SourceKind, b.SourceRoot, b.ContentDigest = string(sel.SourceKind), sel.SourceRoot, sel.ContentDigest
 var reconstructionErr error
 in, reconstructionErr = ReconstructSources(in)
 if reconstructionErr != nil { return b, refuse(RefusalInput, "source captures: %v", reconstructionErr) }
 b.CaptureDigest = DigestBytes(canonicalJSON(in.Captures))

	// 4. The selected implementation census, measured over the anchored
	// implementation (never the product-linked subset).
	census, err := deriveCensus(&b, in, sel)
	if err != nil {
		return b, err
	}

	// 5. The record's locator set and every locator's re-verified acquisition.
	series, artifacts, bound, err := deriveArtifacts(&b, in, vuln)
	if err != nil {
		return b, err
	}
	b.Series, b.Artifacts, b.PrimaryLocator = series, artifacts, bound[0].record.Locator

	// 5b. Each locator's own complete patch-side source. Locators are not a
	// series, so their sources are separate premises: one locator's source is
	// never resolved against another's bytes.
	patchSources, err := derivePatchSources(&b, in)
	if err != nil {
		return b, err
	}
	b.PatchSources = patchSources

	// 6. The implementation boundary a non-counterpart proof is measured over.
	// Its blocking facts are folded in only by the checks that need a closed
	// boundary (the cover and each certificate); a mapped-only binding does not
	// depend on them.
	boundary := buildBoundary(in, sel, census)

	// 7. Patch inventories, effect dispositions and correspondence.
	if err := deriveEffects(&b, in, boundary, bound); err != nil {
		return b, err
	}
	// An incomplete changed-span accounting cannot establish a necessary cover:
	// a residual or defect is exactly a mechanism that could be missing from the
	// subject set, so the blocking facts are reported before any subject.
	if len(b.Obligations) > 0 {
		b.Status = BindingUnresolved
		b.Detail = fmt.Sprintf("%d unresolved proof obligation(s): %s", len(b.Obligations), obligationSummary(b.Obligations))
		b.Digest = b.CanonicalDigest()
		return b, refuse(RefusalObligations, "the binding keeps %d unresolved proof obligation(s): %s",
			len(b.Obligations), obligationSummary(b.Obligations))
	}

	// 8. The necessary cover over every enumerated carrier of each mechanism.
	mechanisms, cover, err := buildCover(&b, boundary)
	if err != nil {
		b.Status = BindingUnresolved
		b.Digest = b.CanonicalDigest()
		return b, err
	}
	b.Mechanisms, b.Cover = mechanisms, cover

	// 9. The claim relationship is checked by Admit; Derive only records that a
	// cover exists.
	b.Status = BindingCover
	b.Digest = b.CanonicalDigest()
	return b, nil
}

// deriveRecord hashes and decodes the captured advisory bytes and checks the
// pin. The decoded document is the only source of entry indices, declarations
// and fix locators.
func deriveRecord(b *Binding, in Inputs) (*domain.Vulnerability, error) {
	if err := in.Pin.Validate(); err != nil {
		return nil, refuse(RefusalIdentity, "record pin is not valid: %v", err)
	}
	if len(in.Raw) == 0 {
		return nil, refuse(RefusalIdentity, "no captured advisory bytes accompany the pin for %q", in.Pin.RecordID)
	}
	sum := sha256.Sum256(in.Raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != in.Pin.DocumentDigest {
		return nil, refuse(RefusalIdentity,
			"the captured advisory bytes hash to %s, not the pinned %s", digest, in.Pin.DocumentDigest)
	}
	vuln, decodedDigest, err := vulnerability.ParseOSV(in.Raw)
	if err != nil {
		return nil, refuse(RefusalIdentity, "the captured advisory bytes do not decode: %v", err)
	}
	if decodedDigest != in.Pin.DocumentDigest {
		return nil, refuse(RefusalIdentity,
			"the decoder reads document digest %s but the pin records %s", decodedDigest, in.Pin.DocumentDigest)
	}
	if vuln == nil || vuln.ID == "" {
		return nil, refuse(RefusalIdentity, "the captured advisory bytes carry no record identity")
	}
	if vuln.ID != in.Pin.RecordID {
		return nil, refuse(RefusalIdentity,
			"the captured bytes are record %s, not the pinned %s", vuln.ID, in.Pin.RecordID)
	}
	b.RecordID, b.DocumentDigest = vuln.ID, in.Pin.DocumentDigest
	return vuln, nil
}

// deriveEntry reconstructs one original affected[] entry: its original index,
// ecosystem and module, plus the scope and declarations the entry declares.
func deriveEntry(v *domain.Vulnerability, entryRef int) (EntryRecord, error) {
	if v.Scope == nil || v.Scope.RecordInventory == nil {
		return EntryRecord{}, refuse(RefusalEntry,
			"the record carries no original affected[] census, so no original entry index can be reconstructed")
	}
	inventory := v.Scope.RecordInventory
	if err := inventory.Validate(v.ID); err != nil {
		return EntryRecord{}, refuse(RefusalEntry, "the record's original affected[] census is not valid: %v", err)
	}
	if entryRef < 0 || entryRef >= inventory.AffectedEntryCount {
		return EntryRecord{}, refuse(RefusalEntry,
			"entry %d is outside the record's %d original affected[] entries", entryRef, inventory.AffectedEntryCount)
	}
	original := inventory.Entries[entryRef]
	if original.Ecosystem != "Go" {
		return EntryRecord{}, refuse(RefusalEntry,
			"original entry %d belongs to ecosystem %q, not Go", entryRef, original.Ecosystem)
	}
	if strings.TrimSpace(original.Module) == "" {
		return EntryRecord{}, refuse(RefusalEntry,
			"original entry %d declares no module, so no selected implementation can be reconstructed for it", entryRef)
	}
	var merged *domain.AffectedModule
	for i := range v.AffectedModules {
		if v.AffectedModules[i].Module == original.Module {
			merged = &v.AffectedModules[i]
			break
		}
	}
	if merged == nil {
		return EntryRecord{}, refuse(RefusalEntry,
			"original entry %d declares module %s but the record carries no decoded entry for it", entryRef, original.Module)
	}
	rec := EntryRecord{
		Index:     entryRef,
		Ecosystem: original.Ecosystem,
		Module:    original.Module,
		Ranges:    append([]domain.VersionRange(nil), merged.AffectedVersions...),
	}
	for _, pkg := range merged.AffectedPackages {
		rec.Packages = appendUniqueString(rec.Packages, pkg.Path)
	}
	rec.Symbols = normalizeSubjects(merged.AffectedSymbols)
	rec.FixedVersions = appendUniqueString(nil, merged.FixedVersions...)
	return rec, nil
}

// deriveSelection returns the one current effective-source descriptor for the
// entry and requires the supplied inventory to describe exactly that source.
func deriveSelection(in Inputs, entry EntryRecord) (domain.EffectiveSourceSelection, error) {
	var matches []domain.EffectiveSourceSelection
	for _, candidate := range in.Selection {
		if candidate.EntryRef == entry.Index {
			matches = append(matches, candidate)
		}
	}
	if len(matches) != 1 {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"entry %d carries %d effective-source descriptors; exactly one current selection is required",
			entry.Index, len(matches))
	}
	sel := matches[0]
	if err := sel.Validate(); err != nil {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate, "the recorded effective source is not valid: %v", err)
	}
	if sel.Failure != nil {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"the recorded build's selected source for %s is unavailable: %s: %s",
			sel.DeclaredModule, sel.Failure.Kind, sel.Failure.Detail)
	}
	if strings.TrimSpace(string(sel.SourceKind)) == "" {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"no source kind was resolved for %s, so no implementation bytes can be re-read", sel.DeclaredModule)
	}
	if sel.DeclaredModule != entry.Module {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"the effective-source descriptor is for %s but original entry %d declares %s",
			sel.DeclaredModule, entry.Index, entry.Module)
	}
	inv := in.Inventory
	if !inv.Anchored() {
		reason := inv.Input.Reason
		if reason == "" {
			reason = "no independently anchored complete implementation inventory was supplied"
		}
		return domain.EffectiveSourceSelection{}, refuse(RefusalInput,
			"the inventory of %s is not independently anchored: %s", sel.DeclaredModule, reason)
	}
	if inv.Module != sel.EffectiveModule {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"the inventory describes %s but the recorded build selects %s", inv.Module, sel.EffectiveModule)
	}
	if inv.Version != sel.EffectiveVersion {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"the inventory describes %s@%s but the recorded build selects %s@%s",
			inv.Module, inv.Version, sel.EffectiveModule, sel.EffectiveVersion)
	}
	if string(inv.Observed.Kind) != string(sel.SourceKind) {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"the inventory was read from a %s source but the recorded build selects %s",
			inv.Observed.Kind, sel.SourceKind)
	}
	if inv.Observed.Root != sel.SourceRoot {
		return domain.EffectiveSourceSelection{}, refuse(RefusalCoordinate,
			"the inventory root %q is not the recorded selection root %q", inv.Observed.Root, sel.SourceRoot)
	}
	return sel, nil
}

// deriveCensus measures the selected implementation from its anchored bytes.
func deriveCensus(b *Binding, in Inputs, sel domain.EffectiveSourceSelection) (*Census, error) {
	files := in.Inventory.CensusFiles()
	if len(files) == 0 {
		return nil, refuse(RefusalCensus,
			"the anchored inventory of %s carries no captured file bytes, so no implementation can be scanned", sel.EffectiveModule)
	}
	anchor := ""
	if in.Inventory.Anchor != nil {
		anchor = string(in.Inventory.Anchor.Checksum.Kind) + ":" + in.Inventory.Anchor.Checksum.Value
	}
	census, err := CensusSource(CensusOptions{
		Module: ModuleIdentity{Kind: string(sel.SourceKind), Path: sel.EffectiveModule,
			Version: sel.EffectiveVersion, Digest: sel.ContentDigest},
		ImportPath:    sel.DeclaredModule,
		Files:         files,
		WalkClosures:  true,
		Registrations: true,
	})
	if err != nil {
		return nil, refuse(RefusalCensus, "the selected implementation census could not be measured: %v", err)
	}
	b.Census = CensusRecord{
		Module: census.Module, Version: census.Version, Kind: census.Kind,
		SourceRef: census.SourceRef, Boundary: census.Boundary, Files: census.Files,
		Digest: census.Digest, Anchor: anchor, PackagePaths: append([]string(nil), census.PackagePaths...),
		Operations: len(census.Operations), Wrappers: len(census.Wrappers),
		Anchored: in.Inventory.Anchored(), Parse: census.Parse, Analysis: census.Analysis,
	}
	return census, nil
}

// derivePatchSources pins each declared locator's own patch-side source. A
// bundle may only be supplied for a locator the pinned record actually
// declares and whose artifact bytes were captured; an anonymous capture (no
// module identity) is refused, because the correspondence would otherwise
// resolve identifiers against bytes with no recorded provenance.
//
// Records are produced in advisory declaration order. A locator with no bundle
// has no record, and the inventory keeps its MISSING_PATCH_SOURCE obligation.
func derivePatchSources(b *Binding, in Inputs) ([]PatchSourceRecord, error) {
	if len(in.PatchSources) == 0 {
		return nil, nil
	}
	declared := make(map[string]bool, len(b.Series))
	for _, s := range b.Series {
		declared[s.Locator] = true
	}
	artifactDigest := make(map[string]string, len(b.Artifacts))
	for _, a := range b.Artifacts {
		artifactDigest[a.Locator] = a.Digest
	}
	for locator := range in.PatchSources {
		if !declared[locator] {
			return nil, refuse(RefusalInput,
				"a patch-side source is recorded for %q, which the record does not declare as a fix locator", locator)
		}
	}
	var out []PatchSourceRecord
	for _, s := range b.Series {
		bundle := in.PatchSources[s.Locator]
		if bundle == nil {
			continue
		}
		if strings.TrimSpace(bundle.Module.Path) == "" {
			return nil, refuse(RefusalInput,
				"the patch-side source for %q carries no module identity, so the correspondence has no recorded provenance",
				s.Locator)
		}
		out = append(out, PatchSourceRecord{
			Locator:        s.Locator,
			ArtifactDigest: artifactDigest[s.Locator],
			Module:         bundle.Module.Path,
			Version:        bundle.Module.Version,
			Files:          len(bundle.Files),
			Digest:         DigestBytes(canonicalJSON(bundle)),
		})
	}
	return out, nil
}

// boundArtifact is one captured, relevant artifact whose bytes are inventoried.
type boundArtifact struct {
	record ArtifactRecord
	bytes  []byte
}

// deriveArtifacts re-verifies every declared fix locator against the record,
// re-hashes the captured bytes, recomputes their changed coordinates and decides
// which artifacts are relevant to the selected implementation.
func deriveArtifacts(b *Binding, in Inputs,
	vuln *domain.Vulnerability) ([]SeriesLocator, []ArtifactRecord, []boundArtifact, error) {
	refs := fix.Resolver{}.Resolve(*vuln)
	series := make([]SeriesLocator, 0, len(refs))
	declared := map[string]string{}
	for _, ref := range refs {
		if strings.TrimSpace(ref.URL) == "" {
			return nil, nil, nil, refuse(RefusalSeries, "the record declares an empty fix locator")
		}
		if _, seen := declared[ref.URL]; seen {
			continue
		}
		declared[ref.URL] = ref.Kind
		series = append(series, SeriesLocator{Locator: ref.URL, Kind: ref.Kind})
	}
	if len(series) == 0 {
		return nil, nil, nil, refuse(RefusalSeries,
			"the record declares no fix locator, so no fix artifact premise can be reconstructed")
	}

	byLocator := map[string]ArtifactInput{}
	for _, artifact := range in.Artifacts {
		locator := artifact.Artifact.Locator
		if locator == "" {
			return nil, nil, nil, refuse(RefusalArtifacts, "an artifact input carries no locator")
		}
		if _, duplicate := byLocator[locator]; duplicate {
			return nil, nil, nil, refuse(RefusalArtifacts, "locator %q is accounted more than once", locator)
		}
		if _, ok := declared[locator]; !ok {
			return nil, nil, nil, refuse(RefusalArtifacts,
				"locator %q is not declared by the record, so it cannot be part of this binding", locator)
		}
		byLocator[locator] = artifact
	}

	bodies, err := artifactBodies(byLocator)
	if err != nil {
		return nil, nil, nil, err
	}
	selectedFiles := censusFiles(in.Inventory)
	records := make([]ArtifactRecord, 0, len(series))
	var bound []boundArtifact
	for _, loc := range series {
		artifact, ok := byLocator[loc.Locator]
		if !ok {
			return nil, nil, nil, refuse(RefusalArtifacts,
				"declared locator %q was not acquired, so its availability was never established", loc.Locator)
		}
		record, err := verifyArtifact(loc, artifact, bodies[loc.Locator], selectedFiles)
		if err != nil {
			return nil, nil, nil, err
		}
		if record.Captured && record.Relevant {
			bound = append(bound, boundArtifact{record: record, bytes: bodies[loc.Locator]})
		}
		records = append(records, record)
	}

	// A declared commit locator without captured bytes is a missing required
	// artifact: the fix material was requested and the provider holds none.
	for i := range records {
		if records[i].Captured || records[i].Kind != "commit" {
			continue
		}
		b.Obligations = append(b.Obligations, ProofObligation{
			Kind: "ARTIFACT", Code: "PROOF_ARTIFACT_MISSING", Locator: records[i].Locator,
			Detail: fmt.Sprintf("declared fix commit %s has no captured bytes (outcome %s)",
				records[i].Locator, records[i].Outcome),
		})
	}
	if len(bound) == 0 {
		return nil, records, nil, refuse(RefusalArtifacts,
			"no captured artifact's changed coordinates exist in the selected implementation, so no effect can be mapped")
	}
	for i := range records {
		records[i].Bound = records[i].Relevant && records[i].Captured
	}
	// Deterministic order: the declaration order of the series.
	sort.SliceStable(bound, func(i, j int) bool {
		return seriesIndex(series, bound[i].record.Locator) < seriesIndex(series, bound[j].record.Locator)
	})
	return series, records, bound, nil
}

// artifactBodies resolves each locator's captured bytes, following a duplicate
// reference to the locator that recorded them. Identical bodies are recorded
// once by the acquisition, so a duplicate locator carries no repeated payload;
// its provenance and digest still have to be re-verified against the bytes it
// points at.
func artifactBodies(byLocator map[string]ArtifactInput) (map[string][]byte, error) {
	out := make(map[string][]byte, len(byLocator))
	for locator, input := range byLocator {
		if len(input.Bytes) > 0 {
			out[locator] = input.Bytes
		}
	}
	for locator, input := range byLocator {
		if len(out[locator]) > 0 {
			continue
		}
		target := input.Artifact.DuplicateOf
		if target == "" {
			continue
		}
		seen := map[string]bool{locator: true}
		body := []byte(nil)
		for target != "" {
			if seen[target] {
				return nil, refuse(RefusalArtifacts, "locator %q's duplicate chain is circular", locator)
			}
			seen[target] = true
			if recorded, ok := out[target]; ok && len(recorded) > 0 {
				body = recorded
				break
			}
			next, ok := byLocator[target]
			if !ok {
				return nil, refuse(RefusalArtifacts,
					"locator %q duplicates %q, which is not part of the supplied artifacts", locator, target)
			}
			target = next.Artifact.DuplicateOf
		}
		if len(body) == 0 {
			return nil, refuse(RefusalArtifacts,
				"locator %q duplicates %q, but no captured bytes are available for it", locator, input.Artifact.DuplicateOf)
		}
		out[locator] = body
	}
	return out, nil
}

// verifyArtifact re-checks one acquisition record against the bytes supplied
// with it. A captured outcome must carry bytes that still hash to its recorded
// digest; an uncaptured outcome must carry none. Relevance and changed
// coordinates are recomputed from those bytes.
func verifyArtifact(loc SeriesLocator, in ArtifactInput, body []byte, selected map[string]bool) (ArtifactRecord, error) {
	artifact := in.Artifact
	if artifact.Locator != loc.Locator {
		return ArtifactRecord{}, refuse(RefusalArtifacts,
			"artifact input names locator %q, not the declared %q", artifact.Locator, loc.Locator)
	}
	if err := artifact.Validate(); err != nil {
		return ArtifactRecord{}, refuse(RefusalArtifacts, "locator %q: %v", loc.Locator, err)
	}
	if artifact.Kind != "" && loc.Kind != "" && artifact.Kind != loc.Kind {
		return ArtifactRecord{}, refuse(RefusalArtifacts,
			"locator %q was acquired as %q but the record declares %q", loc.Locator, artifact.Kind, loc.Kind)
	}
	record := ArtifactRecord{
		Locator: loc.Locator, Kind: loc.Kind, Outcome: artifact.Outcome,
		Provenance: artifact.Provenance, DuplicateOf: artifact.DuplicateOf,
		Captured: artifact.Outcome.Captured(),
	}
	if !record.Captured {
		if len(body) > 0 {
			return ArtifactRecord{}, refuse(RefusalArtifacts,
				"locator %q records outcome %s but carries captured bytes", loc.Locator, artifact.Outcome)
		}
		return record, nil
	}
	if len(body) == 0 {
		return ArtifactRecord{}, refuse(RefusalArtifacts,
			"locator %q records captured outcome %s but the bundle supplies no bytes", loc.Locator, artifact.Outcome)
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != artifact.Digest {
		return ArtifactRecord{}, refuse(RefusalArtifacts,
			"locator %q captured bytes hash to %s, not the recorded %s", loc.Locator, digest, artifact.Digest)
	}
	if artifact.Size != 0 && artifact.Size != len(body) {
		return ArtifactRecord{}, refuse(RefusalArtifacts,
			"locator %q records %d captured byte(s) but the bundle supplies %d", loc.Locator, artifact.Size, len(body))
	}
	record.Digest, record.Size = digest, len(body)
	record.Coordinates = artifactCoordinates(body)
	record.Relevant = coordinatesRelevant(record.Coordinates, selected)
	return record, nil
}

// artifactCoordinates re-derives the module-relative non-test Go paths a
// captured patch changes. It is recomputed from the bytes: a producer's
// coordinate list is never the premise.
func artifactCoordinates(patch []byte) []string {
	parsed := ParseUnifiedDiff(patch)
	var out []string
	seen := map[string]bool{}
	for _, file := range parsed.Files {
		p := file.Path
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// coordinatesRelevant reports whether any changed path — or its directory —
// exists in the selected implementation. A patch whose paths this version does
// not carry belongs to another release line, not to this version's fix.
func coordinatesRelevant(paths []string, selected map[string]bool) bool {
	if len(selected) == 0 {
		return false
	}
	dirs := map[string]bool{}
	for file := range selected {
		dirs[dirOf(file)] = true
	}
	for _, p := range paths {
		if selected[p] || dirs[dirOf(p)] {
			return true
		}
	}
	return false
}

// censusFiles is the anchored implementation's module-relative file set.
func censusFiles(inv SourceInventory) map[string]bool {
	out := map[string]bool{}
	for name := range inv.CensusFiles() {
		out[name] = true
	}
	return out
}

// seriesIndex returns the declaration position of a locator.
func seriesIndex(series []SeriesLocator, locator string) int {
	for i, loc := range series {
		if loc.Locator == locator {
			return i
		}
	}
	return len(series)
}

func appendUniqueString(dst []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

func obligationSummary(obligations []ProofObligation) string {
	kinds := make([]string, 0, len(obligations))
	for _, o := range obligations {
		k := o.Code
		if k == "" {
			k = o.Kind
		}
		if !containsString(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ", ")
}
