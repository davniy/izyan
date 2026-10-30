package fixbinding

import (
	"reflect"

	"github.com/davniy/izyan/internal/domain"
)

// This file is the admission boundary. Admit re-derives the whole binding from
// the immutable input bundle and then requires the claim to equal that
// reconstruction premise by premise. No argument, record or label decides
// anything: a claimed status, a saved Complete flag or a component list is
// diagnostic text until it matches what the bytes produce.
//
// The refusals are grouped by premise so a consumer routes on the identifier.
// Every group is compared in both directions, so removing an effect, a subject,
// a location or a certificate is as much a mismatch as adding one.

// Admit reconstructs the binding and admits the claim only when every premise
// agrees with the reconstruction and the supplied claim relationship covers
// exactly the reconstructed subject set.
//
// A nil error means the returned binding is the checker-created admission
// object. The caller must use *that* object: the claimed value is never returned
// and never gains authority.
func Admit(ctx AdmissionInput, claimed Binding, in Inputs) (Binding, error) {
 if err := validateAdmission(ctx,in); err != nil { return Binding{},err }
	canonical, err := Derive(in)
	if err != nil {
		return canonical, err
	}
	if in.Claim == nil {
		return canonical, refuse(RefusalClaim,
			"no claim relationship was supplied: a cover with no condition/verification relationship grounds nothing")
	}
	if err := CheckClaim(canonical, *in.Claim); err != nil {
		return canonical, err
	}
	if err := compareBinding(claimed, canonical); err != nil {
		return canonical, err
	}
	canonical.Claim = in.Claim
	canonical.Status = BindingAdmitted
	canonical.Digest = canonical.CanonicalDigest()
	return canonical, nil
}

// CheckClaim requires a condition/verification relationship to reference this
// admitted cover and to range over its complete, nonempty subject set. A
// narrowed condition, an empty condition and a verification that recorded
// another cover identity are all refused.
func CheckClaim(b Binding, claim CoverClaim) error {
	switch b.Status {
	case BindingCover, BindingAdmitted:
	default:
		return refuse(RefusalClaim, "the binding carries no established cover (status %s)", b.Status)
	}
	if len(b.Cover.Subjects) == 0 || b.Cover.SubjectDigest == "" || b.Cover.ID == "" {
		return refuse(RefusalClaim, "the binding's cover is empty, so no claim can range over it")
	}
	if len(claim.ConditionSubjects) == 0 {
		return refuse(RefusalClaim,
			"the condition's subject set is empty: an empty cover never grounds absence")
	}
	if !sameSubjects(claim.ConditionSubjects, b.Cover.Subjects) {
		return refuse(RefusalClaim,
			"the condition ranges over %d subject(s) but the necessary cover requires %d (%s)",
			len(normalizeSubjects(claim.ConditionSubjects)), len(b.Cover.Subjects),
			describeDifference(claim.ConditionSubjects, b.Cover.Subjects))
	}
	if claim.VerificationCoverID != b.Cover.ID {
		return refuse(RefusalClaim,
			"the negative verification recorded cover %q, not this admitted cover %q",
			claim.VerificationCoverID, b.Cover.ID)
	}
	if claim.VerificationSubjectDigest != b.Cover.SubjectDigest {
		return refuse(RefusalClaim,
			"the negative verification recorded subject-set digest %q, not %q",
			claim.VerificationSubjectDigest, b.Cover.SubjectDigest)
	}
	return nil
}

// describeDifference names the first subject only one side carries.
func describeDifference(claimed, canonical []domain.SymbolRef) string {
	left := map[domain.SymbolRef]bool{}
	for _, subject := range normalizeSubjects(claimed) {
		left[subject] = true
	}
	right := map[domain.SymbolRef]bool{}
	for _, subject := range normalizeSubjects(canonical) {
		right[subject] = true
	}
	for _, subject := range normalizeSubjects(claimed) {
		if !right[subject] {
			return "the claim adds " + subject.Package + "." + subject.Symbol
		}
	}
	for _, subject := range normalizeSubjects(canonical) {
		if !left[subject] {
			return "the claim omits " + subject.Package + "." + subject.Symbol
		}
	}
	return "the sets differ"
}

// compareBinding refuses any claimed value the reconstruction does not produce.
func compareBinding(claimed, canonical Binding) error {
 if claimed.CaptureDigest != canonical.CaptureDigest { return refuse(RefusalInput,"capture provenance digest differs") }
	if claimed.Contract != canonical.Contract || claimed.Rules != canonical.Rules {
		return refuse(RefusalContract,
			"the claimed binding names contract %q and rules %q, not %q and %q",
			claimed.Contract, claimed.Rules, canonical.Contract, canonical.Rules)
	}
	if claimed.RecordID != canonical.RecordID || claimed.DocumentDigest != canonical.DocumentDigest {
		return refuse(RefusalIdentity,
			"the claimed binding belongs to record %s (%s), not %s (%s)",
			claimed.RecordID, claimed.DocumentDigest, canonical.RecordID, canonical.DocumentDigest)
	}
	if claimed.EntryRef != canonical.EntryRef {
		return refuse(RefusalEntry,
			"the claimed binding binds entry %d, but the input bundle is entry %d",
			claimed.EntryRef, canonical.EntryRef)
	}
	if !reflect.DeepEqual(claimed.Entry, canonical.Entry) {
		return refuse(RefusalEntry,
			"the claimed binding's entry scope/declarations do not match the record's original entry %d",
			canonical.EntryRef)
	}
	if claimed.Module != canonical.Module || claimed.Version != canonical.Version ||
		claimed.SourceKind != canonical.SourceKind || claimed.SourceRoot != canonical.SourceRoot ||
		claimed.ContentDigest != canonical.ContentDigest {
		return refuse(RefusalCoordinate,
			"the claimed binding names %s@%s (%s at %s), not the current selection %s@%s (%s at %s)",
			claimed.Module, claimed.Version, claimed.SourceKind, claimed.SourceRoot,
			canonical.Module, canonical.Version, canonical.SourceKind, canonical.SourceRoot)
	}
	if !reflect.DeepEqual(claimed.Series, canonical.Series) {
		return refuse(RefusalSeries,
			"the claimed binding's fix locator set does not match the %d locator(s) the record declares",
			len(canonical.Series))
	}
	if !reflect.DeepEqual(claimed.Artifacts, canonical.Artifacts) {
		return refuse(RefusalArtifacts,
			"the claimed binding's artifact accounts do not match the re-verified captures")
	}
	if claimed.PrimaryLocator != canonical.PrimaryLocator {
		return refuse(RefusalArtifacts,
			"the claimed binding binds locator %q, not the re-derived primary %q",
			claimed.PrimaryLocator, canonical.PrimaryLocator)
	}
	if !reflect.DeepEqual(claimed.Census, canonical.Census) {
		return refuse(RefusalCensus,
			"the claimed binding's source census does not match the reconstruction from the anchored inventory")
	}
	if !reflect.DeepEqual(claimed.PatchSources, canonical.PatchSources) {
		return refuse(RefusalPatch,
			"the claimed binding's per-locator patch-side source records do not match the captures the correspondence resolved identifiers against")
	}
	if !reflect.DeepEqual(claimed.Patches, canonical.Patches) {
		return refuse(RefusalPatch,
			"the claimed binding's patch inventories do not match the re-extracted changed-span accounting")
	}
	if err := compareEffects(claimed.Effects, canonical.Effects); err != nil {
		return err
	}
	if err := compareMechanisms(claimed.Mechanisms, canonical.Mechanisms); err != nil {
		return err
	}
	if !reflect.DeepEqual(claimed.Cover, canonical.Cover) {
		return refuse(RefusalCover,
			"the claimed binding's cover identity or subject digest does not match the reconstructed cover")
	}
	if !reflect.DeepEqual(claimed.Obligations, canonical.Obligations) {
		return refuse(RefusalObligations,
			"the claimed binding's unresolved obligations do not match the reconstruction")
	}
	// A claimed Claim field is deliberately not compared: the claim relationship
	// is an input premise, re-checked against the reconstruction by CheckClaim,
	// never a value the claimed binding may assert about itself.
	return nil
}

// compareEffects refuses any effect-side premise that differs.
func compareEffects(claimed, canonical []EffectRecord) error {
	if len(claimed) != len(canonical) {
		return refuse(RefusalEffects,
			"the claimed binding carries %d effect(s) but the captured bytes produce %d",
			len(claimed), len(canonical))
	}
	for i := range canonical {
		want, got := canonical[i], claimed[i]
		if got.ID != want.ID || got.Locator != want.Locator || got.Path != want.Path ||
			got.Class != want.Class || got.Added != want.Added || got.Removed != want.Removed ||
			!reflect.DeepEqual(got.Before, want.Before) || !reflect.DeepEqual(got.After, want.After) ||
			!reflect.DeepEqual(got.Spans, want.Spans) || !reflect.DeepEqual(got.Branches, want.Branches) ||
			got.Disposition != want.Disposition || got.Detail != want.Detail {
			return refuse(RefusalEffects,
				"effect %s does not match the effect the captured patch bytes produce", want.ID)
		}
		if !reflect.DeepEqual(got.Locations, want.Locations) {
			return refuse(RefusalLocations,
				"effect %s carries source locations the correspondence did not verify", want.ID)
		}
		if !reflect.DeepEqual(got.Omission, want.Omission) {
			return refuse(RefusalLocations,
				"effect %s carries an omission site the correspondence did not verify", want.ID)
		}
		if !reflect.DeepEqual(got.Subjects, want.Subjects) {
			return refuse(RefusalSubjects,
				"effect %s carries subjects the correspondence did not establish", want.ID)
		}
		if !reflect.DeepEqual(got.Certificate, want.Certificate) {
			return refuse(RefusalNonCounterpart,
				"effect %s carries a non-counterpart certificate the closed boundary did not produce", want.ID)
		}
	}
	return nil
}

// compareMechanisms refuses any cover-side premise that differs, including an
// added or removed alternative subject.
func compareMechanisms(claimed, canonical []MechanismCover) error {
	if len(claimed) != len(canonical) {
		return refuse(RefusalCover,
			"the claimed binding carries %d mechanism cover(s) but the reconstruction produces %d",
			len(claimed), len(canonical))
	}
	for i := range canonical {
		want, got := canonical[i], claimed[i]
		if got.Mechanism != want.Mechanism || !reflect.DeepEqual(got.Keys, want.Keys) {
			return refuse(RefusalCover,
				"mechanism %s does not match the reconstructed mechanism identity", want.Mechanism)
		}
		if !reflect.DeepEqual(got.Subjects, want.Subjects) ||
			!reflect.DeepEqual(got.Mapped, want.Mapped) ||
			!reflect.DeepEqual(got.Alternatives, want.Alternatives) {
			return refuse(RefusalSubjects,
				"mechanism %s carries a subject set the enumeration did not produce", want.Mechanism)
		}
		if got.SubjectDigest != want.SubjectDigest || got.ID != want.ID {
			return refuse(RefusalCover,
				"mechanism %s carries a cover identity the enumeration did not produce", want.Mechanism)
		}
	}
	return nil
}
