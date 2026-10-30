package domain

import "fmt"

// CandidateBindingStatus is the typed outcome of binding a candidate's patch
// coordinate to the selected version's own source. Only
// CandidateBindingAdmitted establishes that the candidate names a real subject
// of the selected version; the other two states never ground an absence claim.
type CandidateBindingStatus string

const (
	// CandidateBindingUnmeasured means the selected version's own source
	// could not be resolved, so identity was neither established nor
	// refuted. It is a missing prerequisite, never absence evidence.
	CandidateBindingUnmeasured CandidateBindingStatus = "UNMEASURED"
	// CandidateBindingAdmitted means the patch coordinate resolves at the
	// same module-relative path in the selected version's own source.
	CandidateBindingAdmitted CandidateBindingStatus = "ADMITTED"
	// CandidateBindingUnmapped means the selected version's own source was
	// read and does not carry the patch coordinate at that module-relative
	// path: the candidate names no subject of the selected version at all,
	// so absence from the product closure says nothing about it.
	CandidateBindingUnmapped CandidateBindingStatus = "UNMAPPED"
)

// CandidateBinding records what establishes that a fix-derived candidate's
// subject exists in the selected version's own source. The patch coordinate is
// module-relative, and the module/version pair is the recorded dependency
// coordinate the source was read at — no other version's bytes may answer.
//
// A binding is evidence about identity only. It is not a fixed-implementation
// proof, it never implies the defect is absent, and it never feeds
// NOT_AFFECTED. It is also not absence authority on its own: while the
// content-derived proof contract is withdrawn, a stored coordinate binding —
// including one whose status is ADMITTED — authorises no absence claim. The
// binding stays on the record because UNMEASURED and UNMAPPED are the typed
// diagnostics that say why a candidate names no subject of the selected
// version, and because re-landing the admitted proof contract needs the
// observation. Nothing in AbsenceIdentity admits on it.
type CandidateBinding struct {
	Status CandidateBindingStatus `json:"status"`
	Module string                 `json:"module,omitempty"`
	// Version is the selected dependency version the source was read at.
	Version string `json:"version,omitempty"`
	// PatchPath is the module-relative patch coordinate the candidate was
	// derived from.
	PatchPath string `json:"patch_path,omitempty"`
	// SourceKind names the selected-source carrier that was consulted:
	// vendor or module-cache. Empty when no source was resolved.
	SourceKind string `json:"source_kind,omitempty"`
	// Detail is the bounded measured observation behind Status.
	Detail string `json:"detail,omitempty"`
	// SameLine records the exact-preimage correspondence the candidate's
	// changed region was matched by, when the route was measured. A recorded
	// CORRESPONDED status is the only content-derived identity basis the
	// withdrawal left intact, and it is re-derived from the model's captured
	// artifact bytes before any consumer relies on it — see AbsenceAdmission.
	SameLine *SameLineCorrespondence `json:"same_line,omitempty"`
}

// IdentityBasis names what establishes a subject as a real subject of the
// selected version.
type IdentityBasis string

const (
	IdentityBasisNone IdentityBasis = ""
	// IdentityBasisRecordEntry means the advisory record itself names the
	// subject: its affected symbols, its affected packages, or an
	// independently re-admitted own-record operation binding.
	IdentityBasisRecordEntry IdentityBasis = "RECORD_ENTRY"
	// IdentityBasisOperatorInput means the operator supplied the subject
	// explicitly. That is an input, not a derived guess: it is recorded as
	// such and never inferred from an origin label, from similarity or from a
	// duplicate of a derived candidate.
	IdentityBasisOperatorInput IdentityBasis = "OPERATOR_INPUT"
	// IdentityBasisSameLinePreimage means the subject's own changed region was
	// matched exactly in the selected version's source at one unambiguous site,
	// the enclosing declaration read from that source is the subject, and the
	// record's declared package boundary covers it. It is content-derived, so
	// it is re-derived from captured bytes before admission (see
	// AbsenceAdmission) rather than read as a label.
	IdentityBasisSameLinePreimage IdentityBasis = "SAME_LINE_PREIMAGE"
	// IdentityBasisContentBinding means the subject is a member of the
	// necessary cover the persisted content proof's checker re-derived from the
	// captured input bundle. It is the only basis the full cross-line binding
	// route establishes, and it exists only while the checker re-admits the
	// proof at the boundary.
	IdentityBasisContentBinding IdentityBasis = "CONTENT_BINDING"
)

// AbsenceIdentityAdmission is the single shared answer to "may this subject
// ground an absence claim?". Every producer of absence evidence and every
// consumer that grounds a negative on it asks this question through this
// record, so the rule cannot drift between the resolver, the exploit model
// builder, the negative verifier and the publication boundary.
type AbsenceIdentityAdmission struct {
	Admitted bool
	Basis    IdentityBasis
	// Reason states why an unadmitted subject may not ground absence. Empty
	// when Admitted is true.
	Reason string
}

// Candidates returns every candidate record the model holds, regardless of its
// verification state (resolved, alternative or unverified). Absence admission
// must see all of them: a subject that was dropped into Alternatives or
// Unverified is still a candidate whose identity claim was made.
func (m *RootCauseModel) Candidates() []RootCause {
	if m == nil {
		return nil
	}
	out := make([]RootCause, 0, len(m.RootCauses)+len(m.Alternatives)+len(m.Unverified))
	out = append(out, m.RootCauses...)
	out = append(out, m.Alternatives...)
	out = append(out, m.Unverified...)
	return out
}

// RecordDeclaresSubject reports whether the record itself names the subject or
// its package among the affected entries. A record-declared subject is a real
// subject of the advisory even when the selected version does not contain it:
// "not declared by the selected source" is then a measured answer about a
// declared subject, not a guess.
func RecordDeclaresSubject(v Vulnerability, s SymbolRef) bool {
	for _, sym := range v.AffectedSymbols {
		if sym == s {
			return true
		}
	}
	if s.Package == "" {
		return false
	}
	for _, p := range v.AffectedPackages {
		if p.Path == s.Package {
			return true
		}
	}
	for _, entry := range v.AffectedModules {
		// A module-level affected entry declares the module itself, which is
		// the identity a module-level absence subject names.
		if entry.Module == s.Package {
			return true
		}
		for _, p := range entry.AffectedPackages {
			if p.Path == s.Package {
				return true
			}
		}
	}
	return v.Module != "" && v.Module == s.Package
}

// AbsenceIdentity resolves whether subject s may ground an absence claim,
// given the candidate records the caller's model holds and the exact record.
//
// It requires an affirmative admitted basis. A candidate origin label, a
// stored Absent flag, a patch-coordinate binding and the mere absence of a
// matching candidate all confer nothing: they record what a producer asserted,
// not what the record or the operator established. The accepted bases are:
//
//   - the record itself declares the subject (RECORD_ENTRY);
//   - the subject is a genuine operator assertion (OPERATOR_INPUT), which is a
//     recorded input rather than a derivation — a MANUAL candidate that
//     duplicates or relabels another candidate is not one;
//   - the caller re-admits an own-record operation binding for the subject
//     (RECORD_ENTRY), which AbsenceAdmission does against the pinned record.
//
// Neither a matching function name, a path suffix nor a similarity match is
// among them: none of those establishes that the subject exists in the
// selected version. A subject no candidate names is not automatically
// admitted either — an unmatched subject has no admitted basis unless the
// record declares it.
func AbsenceIdentity(candidates []RootCause, v Vulnerability, s SymbolRef) AbsenceIdentityAdmission {
	var matched []RootCause
	for _, rc := range candidates {
		if rc.Package == s.Package && rc.Symbol == s.Symbol {
			matched = append(matched, rc)
		}
	}
	if RecordDeclaresSubject(v, s) {
		return AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisRecordEntry}
	}
	if operatorAssertion(matched) {
		return AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisOperatorInput}
	}
	return AbsenceIdentityAdmission{Reason: absenceIdentityRefusal(matched, s)}
}

// operatorAssertion reports whether the candidates naming s are one explicit
// operator input. The MANUAL origin is an operator assertion only when every
// candidate for the subject carries it: a MANUAL copy added beside a
// fix-derived or LLM-proposed candidate is a relabel of that derivation, not a
// new operator input, and it cannot launder a refused derivation. Duplicate
// MANUAL entries for the same subject are one assertion, not several, and a
// MANUAL label on a candidate that carries a patch-coordinate binding is a
// relabel of fix material.
func operatorAssertion(matched []RootCause) bool {
	if len(matched) == 0 {
		return false
	}
	for _, rc := range matched {
		if rc.Origin != RootCauseOriginManual {
			return false
		}
		if rc.Binding != nil {
			return false
		}
	}
	return true
}

// CandidateSubjectIdentity reports whether a candidate may be modelled as a
// subject of the selected version at all. It answers a different and
// deliberately weaker question than AbsenceIdentity: naming a subject is not
// permission to conclude anything from that subject's absence.
//
// The accepted forms are the candidate's own provenance — a record-declared
// subject, an operator-supplied subject, an LLM hypothesis (governed by its own
// consumer-side admission), or a fix-derived candidate whose module-relative
// patch coordinate resolves in the selected version's own source. The last one
// is why this predicate exists separately: a resolved coordinate is a real
// observation about the selected source, so the candidate may be looked up and
// modelled, but it is still not absence authority (see AbsenceIdentity).
func CandidateSubjectIdentity(rc RootCause, v Vulnerability) AbsenceIdentityAdmission {
	if RecordDeclaresSubject(v, SymbolRef{Package: rc.Package, Symbol: rc.Symbol}) {
		return AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisRecordEntry}
	}
	if rc.Binding != nil || rc.Origin == RootCauseOriginFixDerived {
		if rc.Binding != nil && rc.Binding.Status == CandidateBindingAdmitted {
			return AbsenceIdentityAdmission{Admitted: true}
		}
		return AbsenceIdentityAdmission{Reason: candidateIdentityState(rc)}
	}
	switch rc.Origin {
	case RootCauseOriginAdvisory:
		return AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisRecordEntry}
	case RootCauseOriginManual:
		return AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisOperatorInput}
	case RootCauseOriginLLMProposed:
		// An LLM-proposed candidate is a model hypothesis with its own
		// consumer-side admission. It may be looked up and modelled; it never
		// establishes a record declaration, a source identity or a completeness
		// boundary, so absence still requires an affirmative basis.
		return AbsenceIdentityAdmission{Admitted: true}
	}
	return AbsenceIdentityAdmission{Reason: candidateIdentityState(rc)}
}

// admitOwnRecordOperationSubject re-admits the model's own-record operation
// bindings for subject s. Only an admitted binding is a record declaration; a
// rejected one is named so the refusal says which check failed.
func admitOwnRecordOperationSubject(m *RootCauseModel, v Vulnerability, pin *RecordPin, s SymbolRef) (bool, string) {
	if m == nil {
		return false, ""
	}
	var rejected string
	for _, b := range m.OperationBindings {
		if b.Package != s.Package || b.Symbol != s.Symbol {
			continue
		}
		if _, err := AdmitOperationBinding(b, v, pin); err != nil {
			rejected = fmt.Sprintf(
				"the model's own-record operation binding for %s.%s does not re-admit: %v",
				b.Package, b.Symbol, err)
			continue
		}
		return true, ""
	}
	return false, rejected
}

// sameLineRoute is one exact-preimage route re-derived from persisted data:
// the subject it establishes and the record's own declared package boundary.
type sameLineRoute struct {
	subject  SymbolRef
	packages []string
}

// reDeriveSameLineRoute re-derives one candidate's exact-preimage route. A
// recorded CORRESPONDED status is never the premise: the record must be
// structurally complete, its subject must be the candidate's own subject, the
// saved cover must equal the record's own declared boundary re-derived from the
// persisted record and affected chain, and the preimage digest must reproduce
// from the complete captured artifact bytes.
//
// The saved cover is compared, never trusted. An edited summary that narrows
// the declared boundary to the absent member therefore refuses instead of
// hiding a linked omitted alternative.
func reDeriveSameLineRoute(m *RootCauseModel, v Vulnerability, affected *AffectedResult,
	rc RootCause) (sameLineRoute, string) {

	subject := SymbolRef{Package: rc.Package, Symbol: rc.Symbol}
	sl := rc.Binding.SameLine
	if err := sl.validate(); err != nil {
		return sameLineRoute{}, fmt.Sprintf(
			"the same-line correspondence named by %s is not a complete record: %v",
			absenceSubjectLabel(subject), err)
	}
	if !sl.Covers() {
		return sameLineRoute{}, fmt.Sprintf(
			"the same-line correspondence for %s records %s: %s",
			absenceSubjectLabel(subject), sl.Status, sl.Detail)
	}
	if sl.OmissionSite != subject {
		return sameLineRoute{}, fmt.Sprintf(
			"the same-line correspondence for %s establishes %s instead, so it does not establish this subject",
			absenceSubjectLabel(subject), absenceSubjectLabel(sl.OmissionSite))
	}
	modulePath := rc.Binding.Module
	if modulePath == "" {
		modulePath = v.Module
	}
	boundary := DeclaredSubjectBoundary(v, affected, modulePath)
	if len(boundary) == 0 {
		return sameLineRoute{}, fmt.Sprintf(
			"no declared package boundary for %s is available, so the correspondence carries no necessary cover",
			absenceSubjectLabel(subject))
	}
	if !sameStringSet(sl.Cover, boundary) {
		return sameLineRoute{}, fmt.Sprintf(
			"the recorded cover %v is not the record's own declared boundary %v for %s, so the saved cover cannot be read as the canonical one",
			sl.Cover, boundary, absenceSubjectLabel(subject))
	}
	if !containsString(boundary, subject.Package) {
		return sameLineRoute{}, fmt.Sprintf(
			"the record's declared package boundary %v does not cover %s, so the correspondence names no subject of this advisory",
			boundary, absenceSubjectLabel(subject))
	}
	patch, ok := capturedArtifactBytes(m, sl.Locator)
	if !ok {
		return sameLineRoute{}, fmt.Sprintf(
			"no complete captured bytes for locator %s accompany the record, so its preimage claim cannot be re-derived",
			sl.Locator)
	}
	digest, ok := PreimageDigest(patch, sl.Path)
	if !ok {
		return sameLineRoute{}, fmt.Sprintf(
			"the captured bytes for %s carry no before-image of %s", sl.Locator, sl.Path)
	}
	if digest != sl.PreimageDigest {
		return sameLineRoute{}, fmt.Sprintf(
			"the captured bytes for %s hash the before-image of %s to %s, not the recorded %s",
			sl.Locator, sl.Path, digest, sl.PreimageDigest)
	}
	return sameLineRoute{subject: subject, packages: boundary}, ""
}

// admitSameLineSubject re-derives the exact-preimage identity behind subject s
// from the model's captured bytes and the record's own declared boundary.
//
// Every candidate naming s that carries a route must re-derive; one covering
// route establishes the subject, and only as an identity: this function answers
// nothing about whether any build omits the subject.
func admitSameLineSubject(m *RootCauseModel, v Vulnerability, affected *AffectedResult,
	s SymbolRef) (bool, string) {

	if m == nil {
		return false, ""
	}
	var rejected string
	for _, rc := range m.Candidates() {
		if rc.Package != s.Package || rc.Symbol != s.Symbol {
			continue
		}
		if rc.Binding == nil || rc.Binding.SameLine == nil {
			continue
		}
		if _, reason := reDeriveSameLineRoute(m, v, affected, rc); reason != "" {
			rejected = reason
			continue
		}
		return true, ""
	}
	return false, rejected
}

// capturedArtifactBytes resolves one locator's complete captured bytes from the
// model's artifact inventory, following a duplicate reference and re-checking
// the recorded digest so a stale row establishes nothing.
func capturedArtifactBytes(m *RootCauseModel, locator string) ([]byte, bool) {
	if m == nil || locator == "" {
		return nil, false
	}
	byLocator := make(map[string]FixArtifact, len(m.FixArtifacts))
	for _, a := range m.FixArtifacts {
		byLocator[a.Locator] = a
	}
	a, ok := byLocator[locator]
	for guard := 0; ok && a.Bytes == "" && a.DuplicateOf != ""; guard++ {
		if guard > len(m.FixArtifacts) {
			return nil, false
		}
		a, ok = byLocator[a.DuplicateOf]
	}
	if !ok || !a.Outcome.Captured() || a.Bytes == "" {
		return nil, false
	}
	if a.Digest != "" && a.Digest != EvidenceContentDigest(a.Bytes) {
		return nil, false
	}
	return []byte(a.Bytes), true
}

// absenceIdentityRefusal states why the candidates naming a subject do not
// ground absence, naming the typed binding state rather than a generic reason.
func absenceIdentityRefusal(matched []RootCause, s SymbolRef) string {
	subject := s.Package
	if s.Symbol != "" {
		subject += "." + s.Symbol
	}
	if len(matched) == 0 {
		return fmt.Sprintf(
			"subject %s is named by no candidate record and is not declared by the advisory record, so no admitted basis establishes its identity in the selected version; its absence from the product closure is vacuous and cannot ground a negative",
			subject)
	}
	detail := candidateIdentityState(matched[0])
	if len(matched) > 1 {
		detail += fmt.Sprintf(
			" (%d further candidate record(s) name the same subject; a duplicate adds no identity)",
			len(matched)-1)
	}
	return fmt.Sprintf(
		"subject %s has no admitted absence basis: %s; its absence from the product closure cannot ground a negative",
		subject, detail)
}

// candidateIdentityState renders what the candidate records about its own
// identity. It never infers a state the record does not carry.
func candidateIdentityState(rc RootCause) string {
	if b := rc.Binding; b != nil {
		switch b.Status {
		case CandidateBindingUnmapped:
			return fmt.Sprintf(
				"the candidate's fix coordinate %s does not exist in the selected source of %s@%s (%s), so the candidate is unmapped rather than absent",
				b.PatchPath, b.Module, b.Version, b.SourceKind)
		case CandidateBindingUnmeasured:
			detail := b.Detail
			if detail == "" {
				detail = "no measurable selected-version source"
			}
			return "the candidate's version binding is unmeasured: " + detail
		case CandidateBindingAdmitted:
			return fmt.Sprintf(
				"the candidate's patch coordinate %s resolves in the selected source of %s@%s (%s), but a coordinate binding is a selected-source observation, not absence authority: the content-derived identity contract is withdrawn, so the candidate's identity must be re-established by an admitted proof",
				b.PatchPath, b.Module, b.Version, b.SourceKind)
		}
		return "the candidate's version binding records no status"
	}
	if rc.Origin == RootCauseOriginFixDerived {
		return "the fix-derived candidate carries no patch-coordinate binding into the selected version's source"
	}
	switch rc.Origin {
	case RootCauseOriginAdvisory:
		return "the candidate is labelled advisory-declared, but the advisory record does not declare this subject and no re-admitted own-record operation binding establishes it"
	case RootCauseOriginLLMProposed:
		return "the candidate is an LLM proposal: an LLM may propose a location but cannot establish a record declaration, a source identity or a completeness boundary"
	case RootCauseOriginManual:
		return "the candidate is labelled operator-supplied, but a duplicated or relabelled candidate is not a new operator input, so the label establishes nothing"
	}
	return "the candidate records neither a record entry nor an admitted version binding (origin unrecorded)"
}
