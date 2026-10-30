package fixbinding

import (
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// This file turns the captured patch bytes into the canonical effect inventory
// and maps every effect onto the closed implementation boundary. Nothing is
// accepted from a saved summary: the effects, their checked values, their
// locations, the omission sites and the dispositions are all re-extracted from
// the bytes and re-measured against the anchored source.

// deriveEffects inventories every bound patch and dispositions its effects.
func deriveEffects(b *Binding, in Inputs, boundary *implementationBoundary, bound []boundArtifact) error {
	for i, artifact := range bound {
		// Only this locator's own patch-side source may resolve its identifiers.
		// Falling back to another artifact's source would let one locator's
		// bytes qualify a different tree's identifiers.
		inventory, err := InventoryPatch(artifact.bytes, InventoryOptions{Source: in.PatchSources[artifact.record.Locator]})
		if err != nil {
			return refuse(RefusalPatch, "locator %q: %v", artifact.record.Locator, err)
		}
		prefix := fmt.Sprintf("P%d/", i+1)
		b.Patches = append(b.Patches, PatchRecord{
			Locator:           artifact.record.Locator,
			Digest:            artifact.record.Digest,
			Files:             len(inventory.Files),
			Effects:           len(inventory.Effects),
			InventoryDigest:   inventoryDigest(inventory),
			InventoryComplete: inventory.Complete(),
		})
		for _, obligation := range inventory.Obligations() {
			b.Obligations = append(b.Obligations, ProofObligation{
				Kind: obligation.Kind, Code: obligation.Code, Locator: artifact.record.Locator,
				File: obligation.Path, Line: obligation.Line, Detail: obligation.Detail,
			})
		}
		for _, effect := range inventory.Effects {
			record, obligations := effectRecord(effect, prefix, artifact.record.Locator, boundary)
			b.Effects = append(b.Effects, record)
			b.Obligations = append(b.Obligations, obligations...)
		}
	}
	if len(b.Effects) == 0 {
		b.Obligations = append(b.Obligations, ProofObligation{
			Kind: "PATCH", Code: "NO_EXECUTABLE_EFFECT",
			Detail: "the captured fix material changes no supported security operation, so it establishes no mechanism",
		})
	}
	return nil
}

// inventoryDigest pins the complete changed-span accounting of one patch.
func inventoryDigest(inventory *Inventory) string {
	return DigestBytes(canonicalJSON(inventory))
}

// effectRecord dispositions one patch effect from re-derived facts.
func effectRecord(effect Effect, prefix, locator string, boundary *implementationBoundary) (EffectRecord, []ProofObligation) {
	record := EffectRecord{
		ID: prefix + effect.ID, Locator: locator, Path: effect.Path, Class: string(effect.Class),
		Added: effect.Added, Removed: effect.Removed,
		Spans:    append([]string(nil), effect.Spans...),
		Branches: branchKeys(effect.Branches),
	}
	if effect.Before != nil {
		record.Before = operationRecord(effect.Before)
	}
	if effect.After != nil {
		record.After = operationRecord(effect.After)
	}
	if effect.Before == nil && effect.After == nil {
		record.Disposition = DispositionUnresolved
		record.Detail = "the captured effect names no operation"
		return record, []ProofObligation{obligationFor(record, "EFFECT", "EFFECT_NAMES_NO_OPERATION", record.Detail)}
	}

	reference := effect.Before
	if reference == nil {
		reference = effect.After
	}
	key, ok := OperationCorrespondenceKey(reference)
	if !ok {
		record.Disposition = DispositionUnresolved
		record.Detail = "the patch-side resource identity of the changed operation is not established"
		return record, []ProofObligation{obligationFor(record, "EFFECT", "UNRESOLVED_RESOURCE", record.Detail)}
	}
	if effect.Before != nil && effect.After != nil {
		afterKey, afterOK := OperationCorrespondenceKey(effect.After)
		if !afterOK || afterKey != key {
			record.Disposition = DispositionUnresolved
			record.Detail = "the patch changes the operation's resource operand, so no cross-version correspondence is established"
			return record, []ProofObligation{obligationFor(record, "EFFECT", "CHANGED_RESOURCE_OPERAND", record.Detail)}
		}
	}

	mechanism := mechanismKey{Class: record.Class, Key: key}
	candidates := boundary.candidates(mechanism)
	var matching []LocationRecord
	omission := &OmissionRecord{ResourceKey: key, Class: record.Class}
	addedMode := ""
	if effect.Added {
		if effect.After != nil {
			addedMode = effect.After.Mode
		}
		// An added operation does not exist in the vulnerable source, so every
		// enumerated operation of the same class on the same resource is a
		// carrier of the mechanism: an operation already carrying the added
		// value is the fix's own behaviour elsewhere, and one that does not is
		// the omission site. Neither may be dropped from the subject set.
		matching = candidates
		omission.Mode = addedMode
	} else {
		expectedMode := ""
		if effect.Before != nil {
			expectedMode = effect.Before.Mode
		}
		for _, candidate := range candidates {
			if candidate.Mode == expectedMode {
				matching = append(matching, candidate)
			}
		}
	}

	switch {
	case len(matching) > 0:
		record.Disposition = DispositionMapped
		record.Locations = matching
		record.Subjects = subjectsOf(matching)
		if effect.Added {
			var carriers []domain.SymbolRef
			for _, candidate := range matching {
				if candidate.Mode != addedMode {
					carriers = append(carriers, candidate.Subject())
				}
			}
			omission.Carriers = normalizeSubjects(carriers)
			omission.Verified = len(omission.Carriers) > 0
			if omission.Verified {
				omission.Detail = "the selected implementation performs the same operation on the same resource without the added protection"
			} else {
				omission.Detail = "no selected-source operation on this resource lacks the added value"
			}
			record.Omission = omission
			record.Detail = fmt.Sprintf("%d boundary operation(s) carry this mechanism on the resource", len(matching))
		} else {
			record.Detail = fmt.Sprintf("%d selected-source operation(s) correspond to the patch's changed value", len(matching))
		}
		return record, nil
	case len(candidates) > 0:
		record.Disposition = DispositionUnresolved
		record.Detail = fmt.Sprintf(
			"the mechanism exists at %d boundary location(s) but none carries the patch's checked value", len(candidates))
		return record, []ProofObligation{obligationFor(record, "EFFECT", "VALUE_CORRESPONDENCE", record.Detail)}
	}

	certificate, blocking := boundary.certificate(mechanism)
	if certificate != nil {
		record.Disposition = DispositionInapplicable
		record.Certificate = certificate
		record.Detail = "the closed implementation boundary contains no operation of this mechanism on this resource"
		return record, nil
	}
	record.Disposition = DispositionUnresolved
	record.Detail = "no counterpart could be excluded for the mechanism, so the effect stays unresolved"
	if len(blocking) == 0 {
		blocking = []ProofObligation{obligationFor(record, "CERTIFICATE", "CERTIFICATE_UNESTABLISHED", record.Detail)}
	}
	return record, blocking
}

// obligationFor builds one effect-scoped obligation.
func obligationFor(record EffectRecord, kind, code, detail string) ProofObligation {
	return ProofObligation{Kind: kind, Code: code, Locator: record.Locator, File: record.Path, Detail: detail}
}

// operationRecord reduces one resolved operation to its re-checkable identity.
func operationRecord(operation *Operation) *OperationRecord {
	if operation == nil {
		return nil
	}
	record := &OperationRecord{
		Identity:   operation.Identity.String(),
		Source:     operation.Identity.Source,
		ImportPath: operation.Identity.ImportPath,
		Receiver:   operation.Identity.Receiver,
		Name:       operation.Identity.Name,
		Signature:  operation.Identity.Signature,
		Class:      string(operation.Class),
		Mode:       operation.Mode,
	}
	if key, ok := OperationCorrespondenceKey(operation); ok {
		record.ResourceKey = key
	}
	return record
}

// locationRecord is one census operation as a verified location. The four
// relation components are the checked relation: the declaration identity, the
// resource key and the checked value all had to agree for the location to be
// enumerated, and the flow component is the enclosing declaration.
func locationRecord(component string, operation CensusOperation) LocationRecord {
	key, _ := CorrespondenceKey(operation.Operation.Resource.Expr.Identity)
	return LocationRecord{
		Component:   component,
		File:        operation.File,
		Line:        operation.Operation.Line,
		Col:         operation.Operation.Col,
		Package:     operation.Package,
		Symbol:      operation.Declaration.Name,
		Declaration: operation.Declaration.String(),
		Identity:    operation.Operation.Identity.String(),
		Class:       string(operation.Operation.Class),
		ResourceKey: key,
		Mode:        operation.Operation.Mode,
		Components:  []string{RelationOperation, RelationResource, RelationValue, RelationFlow},
		Entry:       operation.Entry,
	}
}

// subjectsOf returns the deduplicated absence subjects of a location set.
func subjectsOf(locations []LocationRecord) []domain.SymbolRef {
	refs := make([]domain.SymbolRef, 0, len(locations))
	for _, location := range locations {
		refs = append(refs, location.Subject())
	}
	return normalizeSubjects(refs)
}

// branchKeys renders the enclosing guard conditions in source order. They are
// patch-side facts: a later correspondence does not compare their text against a
// restructured implementation, so they stay provenance.
func branchKeys(guards []Guard) []string {
	var out []string
	for _, guard := range guards {
		condition := strings.Join(strings.Fields(guard.Condition), " ")
		if condition == "" {
			continue
		}
		out = append(out, guard.Kind+":"+condition)
	}
	return out
}

// sortSubjectRecords orders a subject list deterministically.
func sortSubjectRecords(records []SubjectRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		left, right := records[i], records[j]
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.Symbol != right.Symbol {
			return left.Symbol < right.Symbol
		}
		if left.File != right.File {
			return left.File < right.File
		}
		return left.Line < right.Line
	})
}
