package fixbinding

import (
	"sort"

	"github.com/fedorovmv/izyan/internal/domain"
)

// This file builds the necessary disjunction a claim may range over:
//
//	D(entry, mechanism) => Exec(s_1) or ... or Exec(s_n)
//
// The subject set is not "the operations the patch mapped". It is every
// enumerated carrier of the mechanism in the closed implementation boundary:
// each mapped alternative plus every same-class operation on the same
// correspondence resource, whatever its checked value and wherever in the
// boundary it lives. A narrowed set would let a linked bypass disappear; an
// empty set grounds nothing at all.

// buildCover builds one necessary cover per mechanism and the aggregate cover a
// claim must reference.
func buildCover(b *Binding, boundary *implementationBoundary) ([]MechanismCover, CoverRecord, error) {
	// The candidate enumeration is only exhaustive when the boundary is closed
	// and every component's analysis is complete. A partial census cannot
	// ground a cover, so it is refused before any subject is claimed.
	if len(boundary.blocking) > 0 {
		return nil, CoverRecord{}, refuse(RefusalCover,
			"the implementation boundary is not closed, so no subject set can be complete: %s",
			obligationSummary(boundary.blocking))
	}
	var censusBlocking []ProofObligation
	for _, component := range boundary.components {
		censusBlocking = append(censusBlocking, componentCensusObligations(component)...)
	}
	if len(censusBlocking) > 0 {
		return nil, CoverRecord{}, refuse(RefusalCover,
			"the implementation analysis kept unresolved uses that could hide a carrier: %s",
			obligationSummary(censusBlocking))
	}

	classes := map[string][]EffectRecord{}
	var ordered []string
	for _, effect := range b.Effects {
		if effect.Class == "" {
			continue
		}
		if _, seen := classes[effect.Class]; !seen {
			ordered = append(ordered, effect.Class)
		}
		classes[effect.Class] = append(classes[effect.Class], effect)
	}
	sort.Strings(ordered)

	mechanisms := make([]MechanismCover, 0, len(ordered))
	var all []domain.SymbolRef
	for _, class := range ordered {
		effects := classes[class]
		keys := map[string]bool{}
		for _, effect := range effects {
			for _, key := range effectResourceKeys(effect) {
				keys[key] = true
			}
		}
		keyList := sortedStrings(keys)

		var candidates []LocationRecord
		for _, key := range keyList {
			candidates = append(candidates, boundary.candidates(mechanismKey{Class: class, Key: key})...)
		}
		if len(candidates) == 0 {
			// A mechanism every effect discharged as INAPPLICABLE requires no
			// execution of any subject, so it contributes nothing — and grounds
			// nothing. An unresolved effect without a carrier is a refusal.
			vacuous := true
			for _, effect := range effects {
				if effect.Disposition != DispositionInapplicable {
					vacuous = false
					break
				}
			}
			if vacuous {
				continue
			}
			return nil, CoverRecord{}, refuse(RefusalCover,
				"mechanism %s keeps an unresolved effect but the boundary enumerates no carrier for it", class)
		}

		mappedRefs := map[domain.SymbolRef]bool{}
		for _, effect := range effects {
			for _, subject := range effect.Subjects {
				mappedRefs[subject] = true
			}
		}
		records := subjectRecords(candidates, mappedRefs)
		subjectDigest := SubjectSetDigest(refsOf(records))
		mechanisms = append(mechanisms, MechanismCover{
			Mechanism:     class,
			Keys:          keyList,
			Subjects:      records,
			Mapped:        filterSubjects(records, true),
			Alternatives:  filterSubjects(records, false),
			SubjectDigest: subjectDigest,
		})
		for _, record := range records {
			all = append(all, record.Ref())
		}
	}

	if len(mechanisms) == 0 || len(normalizeSubjects(all)) == 0 {
		return nil, CoverRecord{}, refuse(RefusalSubjects,
			"the binding enumerates no carrier for any mechanism; an inventory with no subject never grounds absence")
	}

	coverSubjects := normalizeSubjects(all)
	var mapped, alternatives []domain.SymbolRef
	for _, mechanism := range mechanisms {
		for _, record := range mechanism.Mapped {
			mapped = append(mapped, record.Ref())
		}
		for _, record := range mechanism.Alternatives {
			alternatives = append(alternatives, record.Ref())
		}
	}
	subjectDigest := SubjectSetDigest(coverSubjects)
	// The cover identity binds the artifact/source association, not only the
	// subjects: two bindings whose locators point at different patch-side
	// trees must not share a cover identity even when their subject sets match.
	premisesDigest := DigestBytes(canonicalJSON(struct {
		Series       []SeriesLocator     `json:"series,omitempty"`
		Artifacts    []ArtifactRecord    `json:"artifacts,omitempty"`
		PatchSources []PatchSourceRecord `json:"patch_sources,omitempty"`
 CaptureDigest string `json:"capture_digest"`
	}{b.Series, b.Artifacts, b.PatchSources, b.CaptureDigest}))
	coverID := CoverID(b.DocumentDigest, b.EntryRef, b.Census.Digest, subjectDigest, premisesDigest)
	for i := range mechanisms {
		mechanisms[i].ID = MechanismID(coverID, mechanisms[i].Mechanism, mechanisms[i].SubjectDigest)
	}
	cover := CoverRecord{
		Rule: domain.FixProofCoverRule, Mechanisms: len(mechanisms),
		Subjects: coverSubjects, Mapped: normalizeSubjects(mapped), Alternatives: normalizeSubjects(alternatives),
		SubjectDigest: subjectDigest, ID: coverID,
	}
	return mechanisms, cover, nil
}

// effectResourceKeys are the correspondence keys the effect's operation names.
// The two images must agree (a changed operand stays unresolved), so this is
// normally one key.
func effectResourceKeys(effect EffectRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, key := range []string{resourceKeyOf(effect.Before), resourceKeyOf(effect.After)} {
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func resourceKeyOf(operation *OperationRecord) string {
	if operation == nil {
		return ""
	}
	return operation.ResourceKey
}

// subjectRecords reduces locations to one record per absence subject. The first
// location in the deterministic order is the carrier; an extra location for the
// same declaration does not create a second subject.
func subjectRecords(candidates []LocationRecord, mapped map[domain.SymbolRef]bool) []SubjectRecord {
	sortLocations(candidates)
	seen := map[domain.SymbolRef]bool{}
	out := make([]SubjectRecord, 0, len(candidates))
	for _, candidate := range candidates {
		ref := candidate.Subject()
		if ref.Package == "" || ref.Symbol == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, SubjectRecord{
			Package: ref.Package, Symbol: ref.Symbol,
			File: candidate.File, Line: candidate.Line,
			Declaration: candidate.Declaration, Identity: candidate.Identity, Mode: candidate.Mode,
			Alternative: !mapped[ref], Map: mapped[ref],
		})
	}
	sortSubjectRecords(out)
	return out
}

// filterSubjects keeps the mapped or the alternative subset.
func filterSubjects(records []SubjectRecord, mapped bool) []SubjectRecord {
	var out []SubjectRecord
	for _, record := range records {
		if record.Map == mapped {
			out = append(out, record)
		}
	}
	return out
}

// refsOf projects subject records onto absence identities.
func refsOf(records []SubjectRecord) []domain.SymbolRef {
	out := make([]domain.SymbolRef, 0, len(records))
	for _, record := range records {
		out = append(out, record.Ref())
	}
	return out
}

// sortedStrings returns the sorted keys of a set.
func sortedStrings(set map[string]bool) []string {
	var out []string
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
