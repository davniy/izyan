package fixbinding

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fedorovmv/izyan/internal/domain"
)

// This file is the activation boundary of the persisted content-proof
// contract. It is the only producer of domain.FixProof and the only place the
// shared absence admission is built for a case.
//
// There is deliberately no path that trusts a saved proof: Readmit decodes the
// claimed binding and the captured input bundle, re-derives every premise with
// Derive, compares the claim with the reconstruction, and returns the
// checker-created result. The domain boundary then uses that result — never the
// saved projection — for the cover and for refusal domination.

// Persist records a checker-created binding and the exact input bundle it was
// derived from as the model's persisted proof contract. It re-runs the
// derivation and refuses to persist a claimed binding that the inputs do not
// reconstruct, so a producer cannot attach an asserted summary.
func Persist(ctx AdmissionInput, claimed Binding, in Inputs) (*domain.FixProof, error) {
 if err := validateAdmission(ctx,in); err != nil { return nil,err }
	canonical, err := Derive(in)
	if err != nil {
		return nil, err
	}
	if err := compareBinding(claimed, canonical); err != nil {
		return nil, err
	}
	switch canonical.Status {
	case BindingCover, BindingAdmitted:
	default:
		return nil, refuse(RefusalStatus,
			"the derivation established no cover (status %s), so there is nothing to persist", canonical.Status)
	}
	bindingBytes, err := json.Marshal(canonical)
	if err != nil {
		return nil, refuse(RefusalStatus, "the canonical binding cannot be serialized: %v", err)
	}
	inputBytes, err := json.Marshal(in)
	if err != nil {
		return nil, refuse(RefusalInput, "the captured input bundle cannot be serialized: %v", err)
	}
	proof := project(canonical)
	proof.Binding = bindingBytes
	proof.Inputs = inputBytes
	return proof, nil
}

// Readmit re-derives one persisted proof from its captured input bundle and
// returns the checker-created binding. The saved projection and the saved
// status are never returned: the caller receives the reconstruction.
func Readmit(ctx AdmissionInput, p *domain.FixProof) (Binding, error) {
	if p == nil {
		return Binding{}, refuse(RefusalInput, "no persisted content proof is available")
	}
	if err := p.Validate(); err != nil {
		return Binding{}, refuse(RefusalContract, "%v", err)
	}
	var claimed Binding
	if err := json.Unmarshal(p.Binding, &claimed); err != nil {
		return claimed, refuse(RefusalContract, "the persisted canonical binding does not decode: %v", err)
	}
	in, err := decodeInputs(p.Inputs)
	if err != nil {
		return claimed, err
	}
 if err := validateAdmission(ctx,in); err != nil { return claimed,err }
	canonical, err := Derive(in)
	if err != nil {
		return canonical, err
	}
	if err := compareBinding(claimed, canonical); err != nil {
		return canonical, err
	}
	switch canonical.Status {
	case BindingCover, BindingAdmitted:
	default:
		return canonical, refuse(RefusalStatus,
			"the re-derived binding carries no cover (status %s)", canonical.Status)
	}
	if len(canonical.Cover.Subjects) == 0 || canonical.Cover.SubjectDigest == "" || canonical.Cover.ID == "" {
		return canonical, refuse(RefusalCover,
			"the re-derived binding's necessary cover is empty, so no claim can range over it")
	}
	canonical.Digest = canonical.CanonicalDigest()
	return canonical, nil
}

// AdmitModelProof re-derives the model's persisted proof at the shared
// boundary. A model without a proof yields nil (the record, operator and
// exact-preimage routes keep their own evidence); a model with a proof that
// does not re-derive yields a refused admission that names the premise and the
// subjects the saved proof claimed, so the refusal dominates dependent labels.
func AdmitModelProof(ctx AdmissionInput, m *domain.RootCauseModel) *domain.ContentAdmission {
	if m == nil || m.FixProof == nil {
		return nil
	}
	admission := &domain.ContentAdmission{}
	var claimed Binding
	if err := json.Unmarshal(m.FixProof.Binding, &claimed); err == nil {
		admission.Subjects = claimedSubjects(claimed)
	} else {
		admission.Opaque = true
	}
	canonical, err := Readmit(ctx, m.FixProof)
	if err != nil {
		code := RefusalCodeOf(err)
		if code == "" {
			code = RefusalInput
		}
		admission.Refusals = append(admission.Refusals, fmt.Sprintf("%s: %v", code, err))
		return admission
	}
	proof := project(canonical)
	bindingBytes, marshalErr := json.Marshal(canonical)
	if marshalErr != nil {
		admission.Refusals = append(admission.Refusals,
			fmt.Sprintf("%s: the reconstructed binding cannot be serialized: %v", RefusalStatus, marshalErr))
		return admission
	}
	proof.Binding = bindingBytes
	proof.Inputs = append(json.RawMessage(nil), m.FixProof.Inputs...)
	admission.Proof = proof
	return admission
}


// project renders the canonical binding as the persisted projection. Every
// field is copied from the reconstruction, not from the claimed value.
func project(b Binding) *domain.FixProof {
	cover := domain.FixProofCover{
		Rule:          b.Cover.Rule,
		ID:            b.Cover.ID,
		SubjectDigest: b.Cover.SubjectDigest,
		Subjects:      append([]domain.SymbolRef(nil), b.Cover.Subjects...),
		Mapped:        append([]domain.SymbolRef(nil), b.Cover.Mapped...),
		Alternatives:  append([]domain.SymbolRef(nil), b.Cover.Alternatives...),
		Packages:      coverPackages(b.Cover.Subjects),
	}
	return &domain.FixProof{
		Contract:       b.Contract,
		Rules:          b.Rules,
		RecordID:       b.RecordID,
		DocumentDigest: b.DocumentDigest,
		EntryRef:       b.EntryRef,
		Module:         b.Module,
		Version:        b.Version,
		SourceKind:     b.SourceKind,
		ContentDigest:  b.ContentDigest,
		Cover:          cover,
		Digest:         b.Digest,
	}
}

// coverPackages lists every package the necessary cover's subject set belongs
// to. The mechanism cover names subjects; the product fact is measured per
// package, so the projection carries the derived package set.
func coverPackages(subjects []domain.SymbolRef) []string {
	seen := make(map[string]bool, len(subjects))
	var out []string
	for _, subject := range normalizeSubjects(subjects) {
		if subject.Package == "" || seen[subject.Package] {
			continue
		}
		seen[subject.Package] = true
		out = append(out, subject.Package)
	}
	sort.Strings(out)
	return out
}

// claimedSubjects lists every subject a claimed binding asserts, so a refused
// proof still names the dependencies it would have carried.
func claimedSubjects(b Binding) []domain.SymbolRef {
	var out []domain.SymbolRef
	out = append(out, b.Cover.Subjects...)
	out = append(out, b.Cover.Mapped...)
	out = append(out, b.Cover.Alternatives...)
	for _, mechanism := range b.Mechanisms {
		for _, subject := range mechanism.Subjects {
			out = append(out, subject.Ref())
		}
	}
	for _, effect := range b.Effects {
		out = append(out, effect.Subjects...)
		if effect.Omission != nil {
			out = append(out, effect.Omission.Carriers...)
		}
	}
	return normalizeSubjects(out)
}

// decodeInputs decodes the persisted immutable input bundle and re-hydrates the
// analysis-local source bytes the inventory identity pins. The persisted anchor
// carries its captured evidence (the exact archive or product tree), so the pure
// checker can rebuild the file set and re-verify it against the recorded digest
// instead of trusting a saved listing.
func decodeInputs(raw json.RawMessage) (Inputs, error) {
	var in Inputs
	if len(raw) == 0 {
		return in, refuse(RefusalInput,
			"the persisted proof carries no captured input bundle, so its premises cannot be re-derived")
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return in, refuse(RefusalInput, "the persisted input bundle does not decode: %v", err)
	}
	if err := hydrateInventory("selected implementation", &in.Inventory); err != nil {
		return in, refuse(RefusalInput, "%v", err)
	}
	return in, nil
}

// hydrateInventory rebuilds the captured source bytes of one anchored
// inventory and refuses a listing that disagrees with the recorded identity in
// either direction. The bytes are supplied to the checker as part of its input
// bundle; the persisted digest alone is not an implementation.
func hydrateInventory(label string, inv *SourceInventory) error {
	if inv == nil || inv.Anchor == nil {
		return nil
	}
	var refreshed *SourceAnchor
	var err error
	switch inv.Anchor.Kind {
	case AnchorModuleArchive:
		if inv.Anchor.Archive == nil {
			return fmt.Errorf("the persisted %s anchor carries no captured archive evidence, so its file bytes cannot be re-read", label)
		}
		refreshed, err = CheckArchiveAnchor(*inv.Anchor.Archive)
	case AnchorLocalTree:
		if inv.Anchor.Tree == nil {
			return fmt.Errorf("the persisted %s anchor carries no captured product-tree evidence, so its file bytes cannot be re-read", label)
		}
		refreshed, err = CheckTreeAnchor(*inv.Anchor.Tree)
	default:
		return fmt.Errorf("the persisted %s anchor kind %q carries no re-readable captured bytes", label, inv.Anchor.Kind)
	}
	if err != nil {
		return fmt.Errorf("the persisted %s anchor does not re-derive: %v", label, err)
	}
	byPath := make(map[string]AnchorFile, len(refreshed.Files))
	for _, file := range refreshed.Files {
		byPath[file.Path] = file
	}
	if len(byPath) != len(inv.Anchor.Files) {
		return fmt.Errorf("the persisted %s anchor lists %d file(s) but its captured evidence carries %d",
			label, len(inv.Anchor.Files), len(byPath))
	}
	for i := range inv.Anchor.Files {
		file := &inv.Anchor.Files[i]
		captured, ok := byPath[file.Path]
		if !ok {
			return fmt.Errorf("the persisted %s anchor lists %q, which its captured evidence does not carry", label, file.Path)
		}
		if file.Digest != "" && file.Digest != captured.Digest {
			return fmt.Errorf("the persisted %s anchor records digest %s for %q, not the captured %s",
				label, file.Digest, file.Path, captured.Digest)
		}
		file.Digest = captured.Digest
		file.Bytes = captured.Bytes
	}
	return nil
}
