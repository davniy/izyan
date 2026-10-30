package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// This file defines the single admitted result every consumer of derived
// absence consults. One question — "may this subject ground an absence claim,
// and against which necessary cover?" — has one answer here, and the resolver,
// the exploit-model builder, the condition evaluators, the negative verifier,
// the verdict boundary and publication all ask it through this record.
//
// The record is derived from persisted, re-checkable data only: the model's
// candidate records, the exact record, the affected chain, the captured fix
// artifact bytes and the admitted build-graph inventory. A saved Absent flag, a
// candidate origin label, a patch coordinate or a prose equation is never
// authority; those are observations a producer asserted, not premises the
// boundary re-derived. Replaying the same case therefore reaches the same
// answer as the fresh analysis that produced it.

// AbsenceCoverRuleDeclaredBoundary names the necessary-cover rule the
// exact-preimage route establishes: the record's own declared package boundary
// is the necessary disjunction D(entry) => linked(p1) or ... or linked(pn), and
// the verified omission site is the mapped subject.
const AbsenceCoverRuleDeclaredBoundary = "declared-package-boundary/1"

// AbsenceCoverRuleAggregate names the aggregate rule when more than one
// re-derivable content route contributes to one cover: the exact-preimage
// route's declared boundary and the persisted content proof's enumerated
// mechanism cover. The platform's own basis is recorded on the route, not on
// the aggregate; the aggregate identity binds the union it actually admits.
const AbsenceCoverRuleAggregate = "admitted-content-cover/1"

// AbsenceBuildGraph is the admitted product build inventory an absence claim is
// measured against. Only an Admitted graph whose set is nonempty may ground a
// package-absence claim: a missing, incomplete or context-mismatched inventory
// measured nothing and must never read as universal absence.
type AbsenceBuildGraph struct {
	// Paths is every import path in the admitted complete build closure.
	Paths map[string]bool
	// EvidenceID is the package-list measurement the graph decodes from.
	EvidenceID EvidenceID
	// Admitted reports whether a complete, context-matching package-list
	// inventory was admitted. Reason names the refusal when it was not.
	Admitted bool
	Reason   string
}

// Links reports whether pkg is part of the admitted build graph.
func (g AbsenceBuildGraph) Links(pkg string) bool {
	if pkg == "" || g.Paths == nil {
		return false
	}
	return g.Paths[pkg]
}

// AbsenceCover is one canonical necessary cover: the nonempty subject set a
// claim must range over, the identity that binds the subject set, and — for the
// declared-boundary rule — every package whose absence the cover requires.
//
// It is plain re-derivable data. The same persisted inputs always produce the
// same ID and subject-set digest, so a saved verification that recorded another
// cover cannot re-admit.
type AbsenceCover struct {
	// Rule names the enumeration rule the cover was built from.
	Rule string `json:"rule"`
	// ID binds the record identity, the rule, the declared boundary and the
	// subject-set digest. It is never a completeness proof by itself.
	ID string `json:"id"`
	// SubjectDigest is the digest of Subjects: sorted, deduplicated, rendered
	// by absence identity.
	SubjectDigest string `json:"subject_digest"`
	// Subjects is the canonical claim subject set. It contains every mapped
	// alternative and every applicable authoritative subject the rule
	// enumerated; a claim must equal it exactly.
	Subjects []SymbolRef `json:"subjects"`
	// Mapped is the subset the patch mapping verified.
	Mapped []SymbolRef `json:"mapped,omitempty"`
	// Alternatives is the subset only the exhaustive enumeration found. The
	// exact-preimage route enumerates none, but an alternative can never be
	// dropped from a cover this record carries.
	Alternatives []SymbolRef `json:"alternatives,omitempty"`
	// Packages is the necessary disjunction of implementations: every member
	// must be absent from the admitted build graph for the cover to hold.
	Packages []string `json:"packages,omitempty"`
}

// Covers reports whether the canonical subject set contains s.
func (c AbsenceCover) Covers(s SymbolRef) bool {
	for _, subject := range c.Subjects {
		if subject == s {
			return true
		}
	}
	return false
}

// CoversPackage reports whether the necessary disjunction names pkg.
func (c AbsenceCover) CoversPackage(pkg string) bool {
	for _, member := range c.Packages {
		if member == pkg {
			return true
		}
	}
	return false
}

// AbsenceSubjectSetDigest digests a subject set: sorted, deduplicated and
// rendered by absence identity. Two different subject sets never share it, so a
// claim cannot silently narrow the cover it recorded.
func AbsenceSubjectSetDigest(subjects []SymbolRef) string {
	refs := normalizeSubjectSet(subjects)
	var b strings.Builder
	fmt.Fprintf(&b, "subjects:%d\n", len(refs))
	for _, s := range refs {
		fmt.Fprintf(&b, "%s\x00%s\n", s.Package, s.Symbol)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AbsenceCoverIdentity binds one cover to its record, enumeration rule,
// declared boundary and subject set. A saved verification that names another
// identity cannot re-admit against this one.
func AbsenceCoverIdentity(rule, recordID, documentDigest, module string, boundary []string, subjectDigest string) string {
	members := append([]string(nil), boundary...)
	sort.Strings(members)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%s\n%s\n%s\n%d\n", rule, recordID, documentDigest, module, subjectDigest, len(members))
	for _, member := range members {
		fmt.Fprintf(&b, "%s\n", member)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AbsenceAdmission is the single admitted result for derived absence. Consumers
// query it per subject; none of them re-derives its own opinion from labels,
// coordinate bindings or RootCause.Absent flags.
//
// The zero value admits nothing: an absent result is the fail-closed answer, so
// a consumer that could not build the admission refuses rather than guesses.
type AbsenceAdmission struct {
	cover          *AbsenceCover
	subjects       map[SymbolRef]AbsenceIdentityAdmission
	refusals       []string
	build          AbsenceBuildGraph
	documentDigest string
	// content is the checker-created admission of the model's persisted
	// content proof. It is nil when the model carries none, and a refused
	// admission when one did not re-derive — in which case the subjects it
	// claimed are dependents of the refused derivation, not independent ones.
	content *ContentAdmission
	// vulnerability is retained so a subject no candidate names can still be
	// answered by the record's own declaration, exactly as the pre-migration
	// gate answered an unmatched subject.
	vulnerability Vulnerability
}

// AdmitAbsence derives the single admission for a case. It reads the case's
// root-cause model, exact record, affected chain and record pin; the caller
// supplies the admitted build graph the absence is measured against and the
// checker-created admission of the model's persisted content proof (nil when
// the model carries none). Subjects the exploit model carries in its absent
// set are included, so a saved absent flag is answered by the same admission
// that answers a candidate.
func AdmitAbsence(c *AnalysisCase, build AbsenceBuildGraph, content *ContentAdmission) AbsenceAdmission {
	if c == nil {
		return AbsenceAdmission{
			refusals: []string{"no analysis case record is available to establish any subject's identity"},
			build:    build,
			content:  content,
		}
	}
	var absent []SymbolRef
	if c.Exploit != nil {
		absent = c.Exploit.AbsentSubjects
	}
	return AdmitAbsenceFor(c.RootCause, c.Vulnerability, c.Affected, c.RecordPin, absent, build, content)
}

// AdmitAbsenceFor derives the single admission from the pieces a boundary
// holds. A nil model admits nothing; a model with a withdrawn content binding
// preserves the refusal rather than letting the payload decay into a weaker
// route.
//
// content is the checker-created result of the model's persisted proof
// contract. A model carrying a proof but no re-derived admission is refused
// rather than read through its saved projection: the whole point of the
// persisted contract is that the pure checker, not the file, decides.
func AdmitAbsenceFor(m *RootCauseModel, v Vulnerability, affected *AffectedResult,
	pin *RecordPin, absent []SymbolRef, build AbsenceBuildGraph,
	content *ContentAdmission) AbsenceAdmission {

	a := AbsenceAdmission{
		subjects:      make(map[SymbolRef]AbsenceIdentityAdmission),
		build:         build,
		content:       content,
		vulnerability: v,
	}
	if pin != nil {
		a.documentDigest = pin.DocumentDigest
	}
	if m == nil {
		a.refusals = append(a.refusals,
			"no root-cause model is available: no subject identity is established")
		return a
	}
	if m.FixBinding != nil {
		a.refusals = append(a.refusals, m.FixBinding.Notice())
	}
	if m.FixProof != nil && content == nil {
		a.refusals = append(a.refusals,
			"the model carries a persisted content proof that this boundary did not re-derive, so its saved cover and subjects establish nothing")
	}
	if content != nil && !content.Admitted() {
		a.refusals = append(a.refusals, content.Refusals...)
	}
	a.cover = a.deriveCover(m, v, affected, content)

	known := make(map[SymbolRef]bool)
	for _, rc := range m.Candidates() {
		known[SymbolRef{Package: rc.Package, Symbol: rc.Symbol}] = true
	}
	for _, subject := range absent {
		known[subject] = true
	}
	if content != nil {
		for _, subject := range content.Subjects {
			known[subject] = true
		}
	}
	if content != nil && content.Proof != nil {
		for _, subject := range content.Proof.Cover.Subjects {
			known[subject] = true
		}
	}
	for subject := range known {
		a.subjects[subject] = a.admitSubject(m, v, affected, pin, subject)
	}
	return a
}

// deriveCover rebuilds the aggregate necessary cover from every re-derivable
// content route the model carries: the exact-preimage route's declared boundary
// and the persisted content proof's enumerated mechanism cover when the checker
// re-admitted it. A route that is not complete, whose saved cover is not the
// record's own re-derived boundary, or whose captured bytes no longer reproduce
// the recorded premises contributes no subject and records a refusal.
func (a *AbsenceAdmission) deriveCover(m *RootCauseModel, v Vulnerability,
	affected *AffectedResult, content *ContentAdmission) *AbsenceCover {

	var subjects []SymbolRef
	var mapped []SymbolRef
	var alternatives []SymbolRef
	var packages []string
	seenPackage := make(map[string]bool)
	declared := 0
	addPackages := func(members []string) {
		for _, member := range members {
			if member == "" || seenPackage[member] {
				continue
			}
			seenPackage[member] = true
			packages = append(packages, member)
		}
	}
	for _, rc := range m.Candidates() {
		if rc.Binding == nil || rc.Binding.SameLine == nil {
			continue
		}
		route, reason := reDeriveSameLineRoute(m, v, affected, rc)
		if reason != "" {
			a.refusals = append(a.refusals, reason)
			continue
		}
		declared++
		subjects = append(subjects, route.subject)
		mapped = append(mapped, route.subject)
		addPackages(route.packages)
	}
	rule := AbsenceCoverRuleDeclaredBoundary
	if content.Admitted() {
		proof := content.Proof
		// The checker rebuilt the cover from the captured input bundle, so
		// these are reconstruction values, not saved projections.
		subjects = append(subjects, proof.Cover.Subjects...)
		mapped = append(mapped, proof.Cover.Mapped...)
		alternatives = append(alternatives, proof.Cover.Alternatives...)
		addPackages(proof.Cover.Packages)
		if declared > 0 {
			rule = AbsenceCoverRuleAggregate
		} else {
			rule = proof.Cover.Rule
		}
	}
	subjects = normalizeSubjectSet(subjects)
	if len(subjects) == 0 {
		return nil
	}
	mapped = normalizeSubjectSet(mapped)
	alternatives = normalizeSubjectSet(alternatives)
	sort.Strings(packages)
	digest := AbsenceSubjectSetDigest(subjects)
	return &AbsenceCover{
		Rule:          rule,
		ID:            AbsenceCoverIdentity(rule, v.ID, a.documentDigest, v.Module, packages, digest),
		SubjectDigest: digest,
		Subjects:      subjects,
		Mapped:        mapped,
		Alternatives:  alternatives,
		Packages:      packages,
	}
}

// admitSubject answers the per-subject identity question from the same
// re-derivable bases the pre-migration gate used: the record's own declaration,
// one genuine operator assertion, a re-admitted own-record operation binding,
// the exact-preimage route re-derived from captured bytes, and the persisted
// content proof when the checker re-admitted it.
func (a *AbsenceAdmission) admitSubject(m *RootCauseModel, v Vulnerability, affected *AffectedResult,
	pin *RecordPin, s SymbolRef) AbsenceIdentityAdmission {

	out := AbsenceIdentity(m.Candidates(), v, s)
	if !out.Admitted {
		admitted, reason := admitOwnRecordOperationSubject(m, v, pin, s)
		if admitted {
			out = AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisRecordEntry}
		} else if reason != "" {
			out.Reason += "; " + reason
		}
	}
	// The exact-preimage route is content-derived and re-derived from the
	// model's captured artifact bytes and the record's own declared boundary,
	// so a recorded status is never the premise.
	if !out.Admitted {
		admitted, reason := admitSameLineSubject(m, v, affected, s)
		if admitted {
			out = AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisSameLinePreimage}
		} else if reason != "" {
			out.Reason += "; " + reason
		}
	}
	// The persisted content proof is consulted only through the checker-created
	// admission: a subject the reconstructed necessary cover names is a
	// subject of the selected implementation, whatever the saved projection
	// said.
	if !out.Admitted && a.content.Admitted() && a.content.Proof.Cover.contains(s) {
		out = AbsenceIdentityAdmission{Admitted: true, Basis: IdentityBasisContentBinding}
	}
	// Withdrawal dominates dependent identities. A model that still carries a
	// content-derived fix binding was produced by the withdrawn implementation,
	// and every subject that binding admitted is a dependent of it: a candidate
	// carrying the operator label for such a subject is a duplicate of the
	// withdrawn derivation, never a new operator input. An independent record
	// declaration or re-admitted own-record operation binding still closes
	// through its own route — this is dependency-specific refusal, not a global
	// veto.
	if out.Admitted && out.Basis == IdentityBasisOperatorInput && m.FixBinding != nil {
		if m.FixBinding.Opaque {
			return AbsenceIdentityAdmission{Reason: m.FixBinding.OpaqueRefusal()}
		}
		if m.FixBinding.ClaimsSubject(s) {
			return AbsenceIdentityAdmission{Reason: m.FixBinding.Refusal(s)}
		}
	}
	// The same dependency rule applies to the re-landed contract: a persisted
	// proof that the checker refused establishes nothing, and an operator or
	// LLM label over one of its claimed subjects is a relabel of the refused
	// derivation. Independent record declarations and re-derived content routes
	// stand on their own evidence.
	if a.content != nil && !a.content.Admitted() && (a.content.Opaque || a.content.ClaimsSubject(s)) {
		if !out.Admitted || (out.Basis != IdentityBasisRecordEntry && out.Basis != IdentityBasisSameLinePreimage) {
			return AbsenceIdentityAdmission{Reason: a.content.Refusal(s)}
		}
	}
	return out
}

// Admits reports whether subject s may ground an absence claim. The zero
// admission refuses every subject.
func (a AbsenceAdmission) Admits(s SymbolRef) AbsenceIdentityAdmission {
	if admission, ok := a.subjects[s]; ok {
		return admission
	}
	// A subject no candidate names can still be declared by the record itself:
	// that declaration is an affirmative basis which needs no candidate. Any
	// other unmatched subject is refused with the reason naming that fact.
	return AbsenceIdentity(nil, a.vulnerability, s)
}

// Cover returns a defensive projection of the canonical necessary cover, or
// nil when no re-derivable content proof established one. Callers cannot mutate
// the admission's internal cover through the returned pointer.
func (a AbsenceAdmission) Cover() *AbsenceCover {
	if a.cover == nil {
		return nil
	}
	return &AbsenceCover{
		Rule:          a.cover.Rule,
		ID:            a.cover.ID,
		SubjectDigest: a.cover.SubjectDigest,
		Subjects:      append([]SymbolRef(nil), a.cover.Subjects...),
		Mapped:        append([]SymbolRef(nil), a.cover.Mapped...),
		Alternatives:  append([]SymbolRef(nil), a.cover.Alternatives...),
		Packages:      append([]string(nil), a.cover.Packages...),
	}
}

// Refusals lists the typed reasons the derivation refused a dependency. They
// are preserved for diagnostics; they are never an exemption.
func (a AbsenceAdmission) Refusals() []string {
	return append([]string(nil), a.refusals...)
}

// DeclaredSubjectBoundary returns the record's own affected-package boundary
// for modulePath: the advisory's declared packages plus the affected chain's
// measured checked packages. It is the scope claim a necessary cover ranges
// over — what the record says the defect can execute in — not whatever the
// patch happened to touch.
func DeclaredSubjectBoundary(v Vulnerability, affected *AffectedResult, modulePath string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(pkg string) {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" || seen[pkg] || !inModule(pkg, modulePath) {
			return
		}
		seen[pkg] = true
		out = append(out, pkg)
	}
	for _, p := range v.AffectedPackages {
		add(p.Path)
	}
	for _, entry := range v.AffectedModules {
		for _, p := range entry.AffectedPackages {
			add(p.Path)
		}
	}
	if affected != nil {
		for _, pkg := range affected.CheckedPackages {
			add(pkg)
		}
	}
	sort.Strings(out)
	return out
}

// inModule reports whether pkg belongs to modulePath.
func inModule(pkg, modulePath string) bool {
	if modulePath == "" {
		return true
	}
	return pkg == modulePath || strings.HasPrefix(pkg, modulePath+"/")
}

// absenceSubjectLabel renders one subject for refusal text.
func absenceSubjectLabel(s SymbolRef) string {
	if s.Symbol == "" {
		return s.Package
	}
	return s.Package + "." + s.Symbol
}

// AbsenceSubjectsLabel renders a subject set for refusal text.
func AbsenceSubjectsLabel(subjects []SymbolRef) string {
	refs := normalizeSubjectSet(subjects)
	labels := make([]string, 0, len(refs))
	for _, s := range refs {
		labels = append(labels, absenceSubjectLabel(s))
	}
	return "[" + strings.Join(labels, ", ") + "]"
}

// normalizeSubjectSet sorts and deduplicates subject identities without
// inventing one: an entry with no package names nothing.
func normalizeSubjectSet(subjects []SymbolRef) []SymbolRef {
	seen := make(map[SymbolRef]bool, len(subjects))
	out := make([]SymbolRef, 0, len(subjects))
	for _, s := range subjects {
		if s.Package == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Symbol < out[j].Symbol
	})
	return out
}

// sameSubjectSet compares two subject sets in both directions, so removing an
// item is as much a mismatch as adding one.
func sameSubjectSet(a, b []SymbolRef) bool {
	left, right := normalizeSubjectSet(a), normalizeSubjectSet(b)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// sameStringSet compares two string sets in both directions.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// containsString reports whether list names value.
func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
