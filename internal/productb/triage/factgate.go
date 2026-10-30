package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/davniy/izyan/internal/repository"
)

// FactValidation is the fact gate result: an aggregate status plus one
// ReferenceCheck per cited evidence ID (or per unreferenced decision-relevant
// claim) and human-readable limitations. It records how reproducible the
// assessment is; it never judges whether the agent's prose is true.
type FactValidation struct {
	Status      FactValidationStatus `json:"status"`
	References  []ReferenceCheck     `json:"references"`
	Limitations []string             `json:"limitations,omitempty"`
}

// ReferenceCheck is the per-reference verdict. Status is a presence/binding
// fact, not a semantic one: VALID means the cited fact resolves inside the
// snapshot, never that the claim it supports is correct.
type ReferenceCheck struct {
	EvidenceID string     `json:"evidence_id,omitempty"`
	Status     FactStatus `json:"status"`
	Locator    string     `json:"locator,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	// Subject is the fact the check bound to (cited path, advisory id,
	// component or claim id); Scope names the domain the check ran in
	// (source, observation, advisory, component, revision, artifact,
	// claim or evidence). ExpectedRepair is the deterministic repair hint
	// feedback passes carry back to the agent — reproducibility only,
	// never a semantic answer. SnapshotHash pins the report to the
	// manifest's content hash.
	Subject        string `json:"subject,omitempty"`
	Scope          string `json:"scope,omitempty"`
	ExpectedRepair string `json:"expected_repair,omitempty"`
	SnapshotHash   string `json:"snapshot_hash,omitempty"`
	// Effect records the deterministic consequence of a non-VALID check:
	// on a reference a decision-relevant claim relies on it is
	// EffectBlocksRiskReduction — the fact can never support DISMISSED or
	// LOWERED. It states a demotion rule, not a semantic judgement.
	Effect string `json:"effect,omitempty"`
	// Tool names the tool that produced a det:<id> observation (empty for
	// non-observation references); ReachEvidence marks a verified
	// reference whose observation positively establishes reachability or
	// usage of the vulnerable code. It is a structured fact read by the
	// decision-fact providers, never by summary text and never as proof.
	Tool          string `json:"tool,omitempty"`
	ReachEvidence bool   `json:"reach_evidence,omitempty"`
}

// FactGate verifies the factual resolvability of the evidence an assessment
// cites: path containment, file existence, line bounds, evidence IDs, source
// and artifact hashes pinned by the snapshot, advisory membership, component
// identity, revision identity and the run's recorded tool observations.
// It performs no semantic analysis of source or of claim statements.
type FactGate struct {
	// Observations is the run's recorded observation index:
	// observation id -> its ObservationPin (data sha256, inner payload
	// hashes, producing tool, reachability classification; see
	// ObservationIndex). It is what observation evidence locators
	// (`det:<id>`, `obs:<id>` or the bare `<id>`) verify against; lookup
	// is case-insensitive and folds '_' to '-' on both sides, resolving
	// only on an unambiguous match. An empty index leaves every such
	// reference UNAVAILABLE.
	Observations map[string]ObservationPin
	// Offline marks the replay path: checks that would read the live
	// repository (file bytes, search re-scans, ref resolution) verify
	// against recorded data only — the snapshot manifest's pinned hashes
	// and the recorded validation. Replay never touches the working tree.
	Offline bool
	// Recorded is the fact-gate validation the source run persisted
	// (fact-gate.json). In offline mode a recorded run replays its stored
	// validation verbatim — after an internal-consistency re-check — so
	// replay reproduces the recorded gate byte-identically even when the
	// live tree is gone or changed.
	Recorded *FactValidation
}

// Validate checks the assessment's evidence bindings against the immutable
// snapshot manifest and returns the aggregate validation status:
//
//	COMPLETE — every check resolved VALID;
//	PARTIAL  — some check is UNAVAILABLE or a decision-relevant claim is
//	           UNREFERENCED (missing context is not a negative fact);
//	FAILED   — some check is INVALID or CONFLICTING, or the assessment
//	           structure itself is malformed.
func (g FactGate) Validate(ctx context.Context, in FindingInput, m SnapshotManifest, a Assessment) FactValidation {
	if ctx == nil {
		ctx = context.Background()
	}
	out := FactValidation{Status: ValidationComplete, References: []ReferenceCheck{}}
	failed := false

	// Offline replay with a recorded validation replays the stored gate
	// verbatim: the recorded run pinned every fact to the same snapshot
	// this replay verifies, so the stored result IS the deterministic
	// re-derivation — provided it is internally consistent and covers the
	// assessment's evidence ids.
	if g.Offline && g.Recorded != nil {
		return g.replayRecordedValidation(*g.Recorded, a)
	}

	if a.SchemaVersion != "" && a.SchemaVersion != AssessmentSchemaVersion {
		out.Limitations = append(out.Limitations,
			fmt.Sprintf("assessment schema_version %q is not %s", a.SchemaVersion, AssessmentSchemaVersion))
		failed = true
	}

	evidence := make(map[string]EvidenceRef, len(a.Evidence))
	duplicate := make(map[string]bool)
	for _, ev := range a.Evidence {
		if ev.ID == "" {
			out.Limitations = append(out.Limitations, "assessment contains an evidence entry without id")
			failed = true
			continue
		}
		if _, dup := evidence[ev.ID]; dup {
			duplicate[ev.ID] = true
			continue
		}
		evidence[ev.ID] = ev
	}
	if len(duplicate) > 0 {
		ids := make([]string, 0, len(duplicate))
		for id := range duplicate {
			ids = append(ids, id)
			out.References = append(out.References, ReferenceCheck{
				EvidenceID: id,
				Status:     FactInvalid,
				Reason:     "duplicate evidence id; reference cannot be resolved unambiguously",
			})
		}
		out.Limitations = append(out.Limitations,
			fmt.Sprintf("assessment has duplicate evidence ids: %s", strings.Join(ids, ", ")))
		failed = true
	}

	// decisionBound[refID] records whether at least one decision-relevant
	// claim cites the evidence id — it is what marks a non-VALID check as
	// blocking risk reduction. UNREFERENCED checks are decision-bound by
	// construction (only decision-relevant claims produce them).
	decisionBound := make(map[string]bool)
	for _, claim := range a.Claims {
		for _, refID := range claim.EvidenceRefs {
			decisionBound[refID] = decisionBound[refID] || claim.DecisionRelevant
		}
	}

	checked := make(map[string]bool)
	for i, claim := range a.Claims {
		claimSubject := claim.ID
		if claimSubject == "" {
			claimSubject = fmt.Sprintf("claims[%d]", i)
		}
		if len(claim.EvidenceRefs) == 0 {
			if claim.DecisionRelevant {
				out.References = append(out.References, ReferenceCheck{
					Status:  FactUnreferenced,
					Reason:  fmt.Sprintf("decision-relevant claim %q cites no evidence", claim.ID),
					Subject: claimSubject,
					Scope:   factScopeClaim,
				})
			}
			continue
		}
		for _, refID := range claim.EvidenceRefs {
			if refID == "" {
				out.References = append(out.References, ReferenceCheck{
					Status:  FactInvalid,
					Reason:  fmt.Sprintf("claim %q cites an empty evidence id", claim.ID),
					Subject: claimSubject,
					Scope:   factScopeClaim,
				})
				continue
			}
			if duplicate[refID] || checked[refID] {
				continue
			}
			checked[refID] = true
			ev, ok := evidence[refID]
			if !ok {
				// decodeAssessment rejects dangling evidence_refs before an
				// assessment ever reaches the gate; a hand-built assessment
				// that still carries one reports the unresolvable fact as
				// UNAVAILABLE (context missing), never silently dropped.
				out.References = append(out.References, ReferenceCheck{
					EvidenceID: refID,
					Status:     FactUnavailable,
					Reason:     "evidence id is not declared in the assessment",
					Subject:    refID,
					Scope:      factScopeEvidence,
				})
				continue
			}
			rc, lim := g.checkEvidence(ctx, in, m, ev)
			if lim != "" {
				out.Limitations = append(out.Limitations, lim)
			}
			out.References = append(out.References, rc)
		}
	}

	for _, rc := range out.References {
		switch rc.Status {
		case FactInvalid, FactConflicting:
			failed = true
		case FactUnavailable, FactUnreferenced:
			if out.Status == ValidationComplete {
				out.Status = ValidationPartial
			}
		}
	}
	if failed {
		out.Status = ValidationFailed
	}

	// Report annotation (spec §7.1): every check is pinned to the snapshot
	// it verified against, a non-VALID check records the reproducibility
	// repair it would take to resolve, and checks a decision-relevant claim
	// relies on are marked as blocking risk reduction — a mechanical fact
	// for the feedback loop and the demotion rules, never a verdict.
	for i := range out.References {
		rc := &out.References[i]
		rc.SnapshotHash = m.ContentHash
		if rc.Scope == "" {
			rc.Scope = factScopeEvidence
		}
		if rc.Subject == "" {
			rc.Subject = rc.EvidenceID
		}
		if rc.Status == FactValid {
			continue
		}
		if rc.ExpectedRepair == "" {
			rc.ExpectedRepair = factExpectedRepair(rc.Status)
		}
		if rc.Status == FactUnreferenced || decisionBound[rc.EvidenceID] {
			rc.Effect = EffectBlocksRiskReduction
		}
	}
	return out
}

// replayRecordedValidation returns the stored fact-gate validation for an
// offline replay. It is not trusted blindly: the recorded statuses must be
// valid enum values, every evidence id the assessment declares must be
// covered by a recorded check, and det:<id> observation references are
// re-derived against the rebuilt index — a degraded or tampered index
// surfaces exactly like at run time. The aggregate status is recomputed
// from the checks: a recorded status that disagrees is inconsistent
// recorded data, so the replay returns FAILED and the caller surfaces a
// drift error — never a different verdict.
func (g FactGate) replayRecordedValidation(rec FactValidation, a Assessment) FactValidation {
	byID := map[string]EvidenceRef{}
	for _, ev := range a.Evidence {
		if ev.ID != "" {
			byID[ev.ID] = ev
		}
	}
	out := rec
	out.References = append([]ReferenceCheck(nil), rec.References...)
	out.Limitations = append([]string(nil), rec.Limitations...)
	covered := map[string]bool{}
	failed := false
	degraded := false
	for i := range out.References {
		rc := &out.References[i]
		if !rc.Status.Valid() {
			return FactValidation{
				Status:      ValidationFailed,
				Limitations: []string{fmt.Sprintf("recorded fact check for %q carries invalid status %q", rc.EvidenceID, rc.Status)},
			}
		}
		if rc.EvidenceID != "" {
			covered[rc.EvidenceID] = true
		}
		// Observation references re-derive against the rebuilt index —
		// the recorded audit log is the evidence, not the live tree.
		if ev, ok := byID[rc.EvidenceID]; ok {
			if id, sha, ok := parseDetLocator(ev.Locator); ok {
				fresh, _ := g.checkDetObservation(ev, id, sha)
				rc.Status, rc.Reason = fresh.Status, fresh.Reason
				rc.Tool, rc.ReachEvidence = fresh.Tool, fresh.ReachEvidence
			}
		}
		switch rc.Status {
		case FactInvalid, FactConflicting:
			failed = true
		case FactUnavailable, FactUnreferenced:
			degraded = true
		}
	}
	// The live gate validates exactly the evidence a claim relies on; an
	// entry the assessment declares but no claim cites never grounds a fact.
	// Replay reproduces that contract: referenced-and-uncovered is drift,
	// unreferenced evidence is a note.
	referenced := map[string]bool{}
	for _, claim := range a.Claims {
		for _, id := range claim.EvidenceRefs {
			referenced[id] = true
		}
	}
	for _, ev := range a.Evidence {
		if ev.ID == "" || covered[ev.ID] {
			continue
		}
		if referenced[ev.ID] {
			return FactValidation{
				Status:      ValidationFailed,
				Limitations: []string{fmt.Sprintf("recorded fact validation does not cover evidence %q", ev.ID)},
			}
		}
		// Unreferenced evidence is skipped without a note: replay must
		// reproduce the recorded validation verbatim, and a note the live
		// gate never emitted would surface as decision drift.
	}

	// The derived status reflects the checks as replayed: a degraded index
	// can only weaken the recorded status, never strengthen it — the worse
	// of the two wins, so a tampered status cannot promote itself and a
	// lost index honestly degrades to PARTIAL.
	derived := ValidationComplete
	if failed {
		derived = ValidationFailed
	} else if degraded {
		derived = ValidationPartial
	}
	out.Status = rec.Status
	switch {
	case rec.Status == ValidationFailed, derived == ValidationFailed:
		out.Status = ValidationFailed
	case rec.Status == ValidationPartial || derived == ValidationPartial:
		out.Status = ValidationPartial
	default:
		out.Status = ValidationComplete
	}
	return out
}

// Canonical evidence kinds. The gate's contract knows only these; every
// other recognized spelling is a synonym resolved by evidenceKindAliases.
const (
	kindSourceSpan  = "source_span"
	kindFile        = "file"
	kindAdvisory    = "advisory"
	kindComponent   = "component"
	kindRevision    = "revision"
	kindArtifact    = "artifact"
	kindObservation = "observation"
)

// evidenceKindAliases maps normalized kind spellings to canonical kinds.
// normalizeKind folds case and strips the separators '_', '-', '.' and ' ',
// so "Go_Mod", "go.mod" and "go-mod" all reach kindFile.
var evidenceKindAliases = map[string]string{
	"sourcespan": kindSourceSpan,
	"source":     kindSourceSpan,
	"code":       kindSourceSpan,
	"snippet":    kindSourceSpan,

	"file":               kindFile,
	"manifest":           kindFile,
	"gomod":              kindFile,
	"gosum":              kindFile,
	"lockfile":           kindFile,
	"modulefile":         kindFile,
	"dependencymanifest": kindFile,

	"advisory":      kindAdvisory,
	"vulnerability": kindAdvisory,
	"cve":           kindAdvisory,
	"ghsa":          kindAdvisory,
	"osv":           kindAdvisory,
	"bdu":           kindAdvisory,

	"component":  kindComponent,
	"package":    kindComponent,
	"dependency": kindComponent,
	"module":     kindComponent,

	"revision": kindRevision,
	"commit":   kindRevision,
	"ref":      kindRevision,
	"gitref":   kindRevision,

	"artifact": kindArtifact,
	"sbom":     kindArtifact,
	"binary":   kindArtifact,

	"observation":       kindObservation,
	"toolresult":        kindObservation,
	"toolobservation":   kindObservation,
	"search":            kindObservation,
	"searchresult":      kindObservation,
	"searchtext":        kindObservation,
	"searchobservation": kindObservation,
	"filelist":          kindObservation,
	"snapshotfilelist":  kindObservation,
	"repository":        kindObservation,

	"det":                      kindObservation,
	"detresult":                kindObservation,
	"detobservation":           kindObservation,
	"deterministic":            kindObservation,
	"deterministicobservation": kindObservation,
	"deterministictool":        kindObservation,
	"deterministictoolresult":  kindObservation,
	"listfiles":                kindObservation,
	"filelisting":              kindObservation,
}

// normalizeKind folds an evidence kind for lookup: lowercased, trimmed and
// stripped of the separators '_', '-', '.' and ' '.
func normalizeKind(kind string) string {
	kind = strings.TrimSpace(kind)
	var b strings.Builder
	b.Grow(len(kind))
	for _, r := range kind {
		switch r {
		case '_', '-', '.', ' ':
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// checkEvidence verifies a single evidence entry and returns its check plus
// an optional limitation describing why the fact could not be established.
// The kind is first normalized through the synonym table; when it remains
// unknown the check is inferred from the locator shape alone (declared
// advisory id, declared snapshot path, declared artifact, finding component
// identity, det:/obs: observation reference) — a fact of form, never a
// judgement of meaning. Locator forms that unambiguously name a recorded
// fact resolve regardless of the declared kind; a kind that names
// something else is recorded as a limitation so the provenance of the
// check stays visible. The legacy pseudo-locators "search:<needle>=<n>"
// and "list_files:<path>[=<n>]" name nothing reproducible — no scope,
// query or truncation context — so they are always UNAVAILABLE: only the
// recorded observation id (obs:<id>, det:<id>) cites the tool result.
func (g FactGate) checkEvidence(ctx context.Context, in FindingInput, m SnapshotManifest, ev EvidenceRef) (ReferenceCheck, string) {
	base := ReferenceCheck{
		EvidenceID: ev.ID,
		Locator:    strings.TrimSpace(ev.Locator),
		Subject:    strings.TrimSpace(ev.Locator),
		Scope:      factScopeEvidence,
	}
	if base.Subject == "" {
		base.Subject = ev.ID
	}
	norm := normalizeKind(ev.Kind)
	if norm == "" {
		// Kind-less evidence is never interpreted as file evidence: an
		// omitted kind is ambiguous input, not a source_span, so it can
		// only be unavailable — never VALID.
		base.Status = FactUnavailable
		base.Reason = "evidence has no kind"
		return base, fmt.Sprintf("evidence %s: no kind declared; unclassified evidence cannot verify against the snapshot", ev.ID)
	}
	loc := strings.TrimSpace(ev.Locator)
	for _, scheme := range []string{"search:", "list_files:"} {
		if len(loc) >= len(scheme) && strings.EqualFold(loc[:len(scheme)], scheme) {
			// A bare search:/list_files: spelling never becomes VALID: it is
			// not a canonical locator — no recorded run owns it — and a
			// count alone cannot carry the tool's scope, skipped files or
			// truncation. The recorded observation id is the only citation.
			base.Status = FactUnavailable
			base.Reason = "synthesized search/list_files locators are not canonical evidence; cite the recorded observation as obs:<id> or det:<id>"
			base.Scope = factScopeObservation
			base.ExpectedRepair = "cite the recorded observation as obs:<id> or det:<id>"
			return base, fmt.Sprintf("evidence %s: %s", ev.ID, base.Reason)
		}
	}
	canon, ok := evidenceKindAliases[norm]
	if !ok {
		canon, ok = inferEvidenceKind(in, m, ev)
	}
	if !ok {
		base.Status = FactUnavailable
		base.Reason = fmt.Sprintf("evidence kind %q has no fact check", ev.Kind)
		return base, fmt.Sprintf("evidence %s: kind %q was not recognized and the locator did not match a known fact shape; it cannot verify against the snapshot", ev.ID, ev.Kind)
	}
	base.Scope = factScopeForKind(canon)
	// An observation locator names a recorded tool observation of this
	// run and verifies against the observation index — whatever the
	// declared kind says. The canonical spelling for it is
	// kind=observation.
	if id, sha, ok := parseDetLocator(ev.Locator); ok {
		base.Subject = id
		rc, rcLim := g.checkDetObservation(ev, id, sha)
		base.Status, base.Reason = rc.Status, rc.Reason
		base.Tool, base.ReachEvidence = rc.Tool, rc.ReachEvidence
		base.ExpectedRepair = rc.ExpectedRepair
		var lim string
		if !detLocatorKinds[norm] {
			lim = fmt.Sprintf("evidence %s: kind %q does not name a tool observation; evidence kind was inferred from the locator shape", ev.ID, ev.Kind)
		}
		lim = joinLimitation(lim, rcLim)
		if rc.Status == FactUnavailable {
			lim = joinLimitation(lim, fmt.Sprintf("evidence %s: %s", ev.ID, rc.Reason))
		}
		return base, lim
	}

	if canon == kindObservation {
		// Observation-family kinds re-derive only through the locator
		// shape: a locator naming a declared snapshot file runs the
		// ordinary file fact check, a locator outside the snapshot is
		// unavailable, and every other observation stays a recorded
		// limitation, never a verified fact.
		//

		if locatorOutsideSnapshot(ev.Locator) {
			base.Status = FactUnavailable
			base.Reason = "locator is outside the snapshot; not re-derivable here"
			lim := fmt.Sprintf("evidence %s: %s", ev.ID, base.Reason)
			if norm != normalizeKind(kindObservation) {
				lim = joinLimitation(
					fmt.Sprintf("evidence %s: kind %q is not a canonical evidence kind; evidence kind was inferred from the locator shape", ev.ID, ev.Kind),
					lim)
			}
			return base, lim
		}
		if fileShapeDeclared(m, ev.Locator) {
			var rc ReferenceCheck
			if g.Offline {
				rc = checkFilePinned(m, ev)
			} else {
				rc = g.checkFile(ctx, m, ev)
			}
			base.Status, base.Reason = rc.Status, rc.Reason
			return base, fmt.Sprintf("evidence %s: observation kind %q carries a file locator; evidence kind was inferred from the locator shape", ev.ID, ev.Kind)
		}
		base.Status = FactUnavailable
		base.Reason = "tool observation is not re-derivable from the snapshot"
		return base, fmt.Sprintf("evidence %s: observation status and coverage recorded as a limitation, not as a verified fact", ev.ID)
	}
	// A file locator outside the snapshot — module cache, toolchain tree,
	// any absolute path — can never be re-derived here: it is UNAVAILABLE
	// context, not a malformed in-snapshot reference.
	if (canon == kindSourceSpan || canon == kindFile) && locatorOutsideSnapshot(ev.Locator) {
		base.Status = FactUnavailable
		base.Reason = "locator is outside the snapshot; not re-derivable here"
		lim := fmt.Sprintf("evidence %s: %s", ev.ID, base.Reason)
		if norm != normalizeKind(canon) {
			lim = joinLimitation(
				fmt.Sprintf("evidence %s: kind %q is not a canonical evidence kind; evidence kind was inferred from the locator shape", ev.ID, ev.Kind),
				lim)
		}
		return base, lim
	}
	var rc ReferenceCheck
	var lim string
	switch canon {
	case kindSourceSpan, kindFile:
		if g.Offline {
			rc = checkFilePinned(m, ev)
		} else {
			rc = g.checkFile(ctx, m, ev)
		}
	case kindArtifact:
		if g.Offline {
			rc, lim = g.checkArtifactPinned(in, m, ev)
		} else {
			rc, lim = g.checkArtifact(ctx, in, m, ev)
		}
	case kindAdvisory:
		rc = g.checkAdvisory(in, ev)
	case kindComponent:
		rc = g.checkComponent(in, ev)
	case kindRevision:
		if g.Offline {
			rc = checkRevisionRecorded(m, ev)
		} else {
			rc = g.checkRevision(ctx, m, ev)
		}
	}
	base.Status, base.Reason = rc.Status, rc.Reason
	if norm != normalizeKind(canon) {
		lim = joinLimitation(
			fmt.Sprintf("evidence %s: kind %q is not a canonical evidence kind; evidence kind was inferred from the locator shape", ev.ID, ev.Kind),
			lim)
	}
	return base, lim
}

// inferEvidenceKind resolves an unrecognized evidence kind by the shape of
// its locator alone: a recorded observation reference (det:<id>, obs:<id>),
// a declared advisory id, a declared snapshot path (with or without a line
// span), a declared artifact, the finding's component identity, or a path
// plainly outside the snapshot. It returns ok=false when no shape matches;
// such evidence is reported UNAVAILABLE rather than assigned a check by
// guesswork.
func inferEvidenceKind(in FindingInput, m SnapshotManifest, ev EvidenceRef) (string, bool) {
	loc := strings.TrimSpace(ev.Locator)
	if loc == "" {
		return "", false
	}
	// Observation-shape locators resolve to the observation check so an
	// unrecognized kind still reaches the deterministic re-derivation —
	// and an out-of-snapshot locator is surfaced as unavailable context
	// instead of an uncheckable unknown kind.
	if _, _, ok := parseDetLocator(loc); ok {
		return kindObservation, true
	}
	for _, id := range in.Finding.Vulnerability.IDs {
		if strings.EqualFold(strings.TrimSpace(id), loc) {
			return kindAdvisory, true
		}
	}
	if fl, err := parseFileLocator(loc); err == nil && declaredFile(m, fl.path) != nil {
		if fl.start > 0 {
			return kindSourceSpan, true
		}
		return kindFile, true
	}
	if al, err := parseArtifactLocator(loc); err == nil {
		for _, a := range m.Artifacts {
			if artifactMatch(al.path, al.abs, a.Path) {
				return kindArtifact, true
			}
		}
		for _, name := range []string{in.Finding.Target.SBOM, in.Finding.Target.Binary} {
			if declaredMatch(al, name) {
				return kindArtifact, true
			}
		}
	}
	if componentLocatorMatch(in.Finding.Component, loc) {
		return kindComponent, true
	}
	if locatorOutsideSnapshot(loc) {
		return kindObservation, true
	}
	return "", false
}

// componentLocatorMatch reports whether a locator is exactly the finding's
// component identity: the bare name/package, or name@version with the
// declared version (compared canonically — a leading "v" is decoration).
// A mismatching name or version is not a shape match — the component check
// itself produces CONFLICTING for those only when the agent explicitly
// declared a component kind.
func componentLocatorMatch(c Component, loc string) bool {
	name, version := loc, ""
	if i := strings.LastIndex(loc, "@"); i >= 0 {
		name, version = loc[:i], loc[i+1:]
	}
	name = strings.TrimSpace(name)
	if name == "" || (name != c.Name && name != c.Package) {
		return false
	}
	return version == "" || canonicalModuleVersion(strings.TrimSpace(version)) == canonicalModuleVersion(c.Version)
}

// canonicalModuleVersion folds the decorative "v"/"V" prefix of a module
// version so the component check compares spellings like "v1.10.0" and
// "1.10.0" as the same version. Only the prefix is touched: build suffixes
// such as "+incompatible" stay part of the identity, and a bare "v" or a
// prefix not followed by a digit is not a version marker at all.
func canonicalModuleVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// checkFile verifies a source_span/file evidence: locator parse, path
// containment, declaration in the manifest, optional declared hash and
// optional line bounds. Reading the file for bounds also proves the bytes
// still match the pinned snapshot hash.
func (g FactGate) checkFile(ctx context.Context, m SnapshotManifest, ev EvidenceRef) ReferenceCheck {
	fail := func(s FactStatus, format string, args ...any) ReferenceCheck {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}
	}
	if strings.TrimSpace(m.Repository) == "" {
		return fail(FactUnavailable, "finding provides no repository snapshot")
	}
	loc, err := parseFileLocator(ev.Locator)
	if err != nil {
		return fail(FactInvalid, "malformed locator: %v", err)
	}
	decl := declaredFile(m, loc.path)
	if decl == nil {
		return fail(FactInvalid, "file %q is not declared in the snapshot manifest", loc.path)
	}
	root, err := canonicalDir(m.Repository)
	if err != nil || root == "" {
		return fail(FactUnavailable, "snapshot repository root cannot be resolved")
	}
	abs, inside, rerr := resolveDeclaredPath(root, loc.path)
	if rerr != nil {
		return fail(FactUnavailable, "declared file %q can no longer be resolved: %v", loc.path, rerr)
	}
	if !inside {
		return fail(FactInvalid, "file %q resolves outside the snapshot root", loc.path)
	}
	return verifyFileEntry(ctx, ev, *decl, abs, loc)
}

// declaredFile returns the manifest entry for path, or nil when the
// snapshot never declared it.
func declaredFile(m SnapshotManifest, path string) *SnapshotFile {
	for i := range m.Files {
		if m.Files[i].Path == path {
			return &m.Files[i]
		}
	}
	return nil
}

// fileShapeDeclared reports whether the locator parses as a
// snapshot-relative path[:line] whose path is declared in the manifest.
// It is a shape fact only: nothing about the locator's meaning is judged.
func fileShapeDeclared(m SnapshotManifest, raw string) bool {
	fl, err := parseFileLocator(raw)
	if err != nil {
		return false
	}
	return declaredFile(m, fl.path) != nil
}

// joinLimitation concatenates two limitation sentences, skipping empty
// parts, so a search check and an inferred-kind note can both surface.
func joinLimitation(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

// locatorOutsideSnapshot reports whether a locator plainly names a path
// outside the snapshot root: an absolute POSIX path, a Windows drive or
// UNC path, or a "~"-home spelling. Module-cache paths produced by the
// deterministic tools fall in this class — such references carry context
// the run recorded, but nothing here can re-derive them, so they are
// UNAVAILABLE rather than INVALID. Detection is lexical; nothing touches
// the filesystem.
func locatorOutsideSnapshot(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	if filepath.IsAbs(s) || strings.HasPrefix(s, "/") || s == "~" || strings.HasPrefix(s, "~/") {
		return true
	}
	// Windows absolute forms written with slashes: "C:/..." or "//srv/x".
	if len(s) >= 3 && s[1] == ':' && (s[2] == '/' || s[2] == '\\') &&
		((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		return true
	}
	return false
}

// detLocatorKinds are the normalized evidence-kind spellings that already
// name a recorded tool observation; with them a det:<id> locator needs no
// inferred-kind limitation.
var detLocatorKinds = map[string]bool{
	"observation":              true,
	"toolresult":               true,
	"toolobservation":          true,
	"det":                      true,
	"detresult":                true,
	"detobservation":           true,
	"deterministic":            true,
	"deterministicobservation": true,
	"deterministictool":        true,
	"deterministictoolresult":  true,
}

// observationIDScheme enumerates the locator schemes that name a recorded
// tool observation: the canonical "det:" plus "obs:"/"set:" spellings
// agents produce by reusing the id's own prefix. Comparison is
// case-insensitive.
var observationIDSchemes = []string{"det:", "obs:", "set:"}

// bareObservationID matches the audited id space ("det-NNNN", "obs-NNNN",
// "set-NNNN") spelled without a scheme: case-insensitive, '-'/'_'
// separators only. A bare locator must match this shape exactly — the
// wider charset accepted after a scheme is what a file path or a
// component name can also look like, and those still belong to the
// remaining shape checks.
var bareObservationID = regexp.MustCompile(`(?i)^(det|obs|set)[-_][0-9]+$`)

// parseDetLocator parses a locator that references one tool observation
// recorded by this run: "det:<id>" or "det:<id>@<sha256>" (plus the "obs:"
// and "set:" scheme spellings, all schemes case-insensitive), or the bare
// audited id itself ("obs-0011", "OBS_0011"). Observation ids are the
// audited id space ("det-NNNN", "obs-NNNN", "set-NNNN"); with a scheme the
// id charset is checked loosely (letters, digits, '-', '_', '.') and the
// index lookup decides membership, while a bare locator is recognized only
// in the exact audited id shape so paths and names keep their own checks.
func parseDetLocator(raw string) (id, sha string, ok bool) {
	raw = strings.TrimSpace(raw)
	rest := raw
	bare := true
	for _, scheme := range observationIDSchemes {
		if len(raw) > len(scheme) && strings.EqualFold(raw[:len(scheme)], scheme) {
			rest = raw[len(scheme):]
			bare = false
			break
		}
	}
	if bare && !bareObservationID.MatchString(raw) {
		return "", "", false
	}
	id = strings.TrimSpace(rest)
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		id, sha = strings.TrimSpace(rest[:i]), rest[i+1:]
	}
	if id == "" {
		return "", "", false
	}
	for _, r := range id {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return "", "", false
		}
	}
	return id, sha, true
}

// normalizeObservationID folds an observation id for comparison:
// lowercased, trimmed and with '_' folded to '-', so "OBS_0011" and
// "obs-0011" are the same id. Both the cited and the recorded side pass
// through it — matching is deterministic, never guessed.
func normalizeObservationID(id string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(id)), "_", "-")
}

// resolveObservation finds the recorded observation pin a cited id names.
// The exact recorded spelling wins first; otherwise both sides are
// normalized and the id resolves only when it names exactly one recorded
// observation — zero matches and ambiguous ones are both unresolved (the
// check reports them UNAVAILABLE, as an id the run never produced).
func (g FactGate) resolveObservation(id string) (string, ObservationPin, bool) {
	if pin, ok := g.Observations[id]; ok {
		return id, pin, true
	}
	want := normalizeObservationID(id)
	found := ""
	var pin ObservationPin
	for k, p := range g.Observations {
		if normalizeObservationID(k) != want {
			continue
		}
		if found != "" {
			return "", ObservationPin{}, false
		}
		found, pin = k, p
	}
	if found == "" {
		return "", ObservationPin{}, false
	}
	return found, pin, true
}

// checkDetObservation verifies an observation reference against the run's
// recorded observation index (FactGate.Observations). The observation id
// is the anchor — but only a call that actually produced a fact anchors:
// an id whose recorded status is DENIED, ERROR, TIMEOUT or UNSUPPORTED, or
// whose completeness is PARTIAL/UNKNOWN, resolves as UNAVAILABLE context,
// never VALID, so a denied or failed call cannot launder an empty result
// into a verified fact. A resolvable OK observation verifies VALID;
// declared sha256 values never demote it to CONFLICTING, because agents
// routinely confuse payload hashes with envelope hashes while the
// reference still names the right recorded fact. Id lookup is normalized
// on both sides (lowercased, trimmed, '_' folded to '-') so "det:DET-0004"
// or "obs_0011" still name the recorded "det-0004"/"obs-0011"; an id that
// resolves to no recorded observation — or ambiguously to more than one —
// stays UNAVAILABLE context, never a semantic judgement. A declared hash
// equal to the recorded data_sha256 verifies silently; one matching a
// sha256-like token inside the recorded payload verifies with the
// inner-hash limitation; any other declared hash verifies with a
// "declared hash does not match" limitation.
func (g FactGate) checkDetObservation(ev EvidenceRef, id, sha string) (ReferenceCheck, string) {
	resolved, pin, ok := g.resolveObservation(id)
	if !ok {
		return ReferenceCheck{
			Status: FactUnavailable,
			Reason: fmt.Sprintf("observation %q is not among the run's recorded tool observations", id),
		}, ""
	}
	switch {
	case pin.Status != string(ToolStatusOK):
		// The recorded call produced no fact at all: denied, errored,
		// timed out or never executed. Citing it verifies nothing —
		// only an observation that actually completed is a fact.
		status := pin.Status
		if status == "" {
			status = "unknown"
		}
		return ReferenceCheck{
			Status:         FactUnavailable,
			Reason:         fmt.Sprintf("observation %q recorded status %q; the call produced no fact", resolved, status),
			Tool:           pin.Tool,
			ExpectedRepair: "cite an observation id whose call completed with status OK",
		}, ""
	case pin.Coverage == "PARTIAL" || pin.Coverage == "UNKNOWN":
		// An incomplete deterministic check is context, not a verified
		// fact: PARTIAL means only the checked part, UNKNOWN means the
		// coverage could not even be characterized.
		return ReferenceCheck{
			Status:         FactUnavailable,
			Reason:         fmt.Sprintf("observation %q recorded %s coverage; an incomplete check is not a verified fact", resolved, pin.Coverage),
			Tool:           pin.Tool,
			ExpectedRepair: "cite an observation id whose recorded coverage is COMPLETE, or rerun the check in a scope it can close",
		}, ""
	}
	rc := ReferenceCheck{Status: FactValid, Tool: pin.Tool, ReachEvidence: pin.ReachEvidence}
	var lim string
	seen := map[string]bool{}
	for _, want := range []string{strings.TrimSpace(ev.SHA256), sha} {
		if want == "" || seen[strings.ToLower(want)] {
			continue
		}
		seen[strings.ToLower(want)] = true
		switch {
		case strings.EqualFold(want, pin.DataSHA256):
		case containsFold(pin.InnerSHA256, want):
			lim = joinLimitation(lim, fmt.Sprintf(
				"evidence %s: hash matched an inner observation hash of %q (a sha256 embedded in the payload, not the data_sha256 envelope)", ev.ID, resolved))
		default:
			lim = joinLimitation(lim, fmt.Sprintf(
				"evidence %s: declared hash does not match the observation data hash; the id is the anchor", ev.ID))
		}
	}
	return rc, lim
}

// containsFold reports whether list holds an element equal to s under
// case-insensitive comparison.
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// checkArtifact verifies an sbom/binary artifact evidence. Artifacts are
// reachable only through the finding's declared SBOM/Binary inputs; a locator
// naming anything else is a foreign reference, while a declared input that
// the snapshot did not capture is unavailable rather than broken.
func (g FactGate) checkArtifact(ctx context.Context, in FindingInput, m SnapshotManifest, ev EvidenceRef) (ReferenceCheck, string) {
	fail := func(s FactStatus, format string, args ...any) (ReferenceCheck, string) {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}, ""
	}
	loc, err := parseArtifactLocator(ev.Locator)
	if err != nil {
		return fail(FactInvalid, "malformed locator: %v", err)
	}
	for _, a := range m.Artifacts {
		if !artifactMatch(loc.path, loc.abs, a.Path) {
			continue
		}
		if filepath.IsAbs(a.Path) {
			return verifyFileEntry(ctx, ev, a, a.Path, loc), ""
		}
		root, rerr := canonicalDir(m.Repository)
		if rerr != nil || root == "" {
			return fail(FactUnavailable, "snapshot repository root cannot be resolved")
		}
		abs, inside, rerr := resolveDeclaredPath(root, a.Path)
		if rerr != nil {
			return fail(FactUnavailable, "declared artifact %q can no longer be resolved: %v", a.Path, rerr)
		}
		if !inside {
			return fail(FactInvalid, "artifact %q resolves outside the snapshot root", a.Path)
		}
		return verifyFileEntry(ctx, ev, a, abs, loc), ""
	}
	for _, name := range []string{in.Finding.Target.SBOM, in.Finding.Target.Binary} {
		if declaredMatch(loc, name) {
			return fail(FactUnavailable, "declared artifact %q was not captured in the snapshot", strings.TrimSpace(name))
		}
	}
	if loc.abs {
		// An absolute artifact locator that matches nothing the finding
		// declared points at a file outside the snapshot — module cache,
		// toolchain tree, another drive path. It is unavailable context,
		// not a broken in-snapshot reference.
		return ReferenceCheck{
			Status: FactUnavailable,
			Reason: "locator is outside the snapshot; not re-derivable here",
		}, fmt.Sprintf("evidence %s: locator %q is outside the snapshot; not re-derivable here", ev.ID, loc.path)
	}
	return fail(FactInvalid, "artifact %q is not among the declared finding artifacts", loc.path)
}

// artifactMatch reports whether a parsed locator names the manifest artifact
// path. Absolute locators match absolute manifest paths after cleaning;
// relative locators match relative manifest paths exactly.
func artifactMatch(locPath string, locAbs bool, mpath string) bool {
	if filepath.IsAbs(mpath) || strings.HasPrefix(mpath, "/") {
		return locAbs && filepath.Clean(mpath) == filepath.Clean(locPath)
	}
	if locAbs {
		return false
	}
	if p, err := cleanRelPath(mpath); err == nil {
		return p == locPath
	}
	return mpath == locPath
}

// declaredMatch reports whether a relative artifact locator names the same
// in-tree file as the declared finding input path (SBOM or Binary).
func declaredMatch(loc fileLocator, declared string) bool {
	declared = strings.TrimSpace(declared)
	if declared == "" {
		return false
	}
	if filepath.IsAbs(declared) || strings.HasPrefix(declared, "/") {
		return loc.abs && filepath.Clean(declared) == filepath.Clean(loc.path)
	}
	d, err := cleanRelPath(filepath.ToSlash(declared))
	return err == nil && !loc.abs && d == loc.path
}

// checkAdvisory verifies the cited vulnerability ID is one of the finding's
// declared advisory IDs. Membership is presence-only; nothing about the
// advisory text is interpreted.
func (g FactGate) checkAdvisory(in FindingInput, ev EvidenceRef) ReferenceCheck {
	loc := strings.TrimSpace(ev.Locator)
	if loc == "" {
		return ReferenceCheck{Status: FactInvalid, Reason: "advisory evidence has no id locator"}
	}
	if len(in.Finding.Vulnerability.IDs) == 0 {
		return ReferenceCheck{Status: FactUnavailable, Reason: "finding declares no advisory ids"}
	}
	for _, id := range in.Finding.Vulnerability.IDs {
		if strings.EqualFold(strings.TrimSpace(id), loc) {
			return ReferenceCheck{Status: FactValid}
		}
	}
	return ReferenceCheck{
		Status: FactInvalid,
		Reason: fmt.Sprintf("advisory id %q is not among the finding's declared ids", loc),
	}
}

// checkComponent verifies name/package and, when the locator carries a
// version suffix ("name@version"), version identity against the finding.
// Versions compare canonically: a decorative leading "v"/"V" does not
// distinguish "v1.10.0" from "1.10.0", while suffixes like "+incompatible"
// remain part of the identity. A name the finding never declared is a
// direct contradiction, not a broken reference, so it is CONFLICTING.
func (g FactGate) checkComponent(in FindingInput, ev EvidenceRef) ReferenceCheck {
	loc := strings.TrimSpace(ev.Locator)
	if loc == "" {
		return ReferenceCheck{Status: FactInvalid, Reason: "component evidence has no locator"}
	}
	name, version := loc, ""
	if i := strings.LastIndex(loc, "@"); i >= 0 {
		name, version = loc[:i], loc[i+1:]
	}
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return ReferenceCheck{Status: FactInvalid, Reason: fmt.Sprintf("malformed component locator %q", loc)}
	}
	comp := in.Finding.Component
	if strings.TrimSpace(comp.Name) == "" && strings.TrimSpace(comp.Package) == "" {
		return ReferenceCheck{Status: FactUnavailable, Reason: "finding declares no component identity"}
	}
	if name != comp.Name && name != comp.Package {
		return ReferenceCheck{
			Status: FactConflicting,
			Reason: fmt.Sprintf("component %q does not match finding component %q package %q", name, comp.Name, comp.Package),
		}
	}
	if version == "" {
		return ReferenceCheck{Status: FactValid}
	}
	if comp.Version == "" {
		return ReferenceCheck{Status: FactUnavailable, Reason: "finding declares no component version"}
	}
	if canonicalModuleVersion(version) != canonicalModuleVersion(comp.Version) {
		return ReferenceCheck{
			Status: FactConflicting,
			Reason: fmt.Sprintf("version %q conflicts with finding component version %q", version, comp.Version),
		}
	}
	return ReferenceCheck{Status: FactValid}
}

// checkRevision verifies the cited ref matches the snapshot revision. When
// the spelling differs the refs are resolved via git so aliases of the same
// commit are not misread as conflicts.
func (g FactGate) checkRevision(ctx context.Context, m SnapshotManifest, ev EvidenceRef) ReferenceCheck {
	fail := func(s FactStatus, format string, args ...any) ReferenceCheck {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}
	}
	loc := strings.TrimSpace(ev.Locator)
	if loc == "" {
		return fail(FactInvalid, "revision evidence has no locator")
	}
	if strings.TrimSpace(m.Repository) == "" {
		return fail(FactUnavailable, "finding provides no repository snapshot")
	}
	if strings.TrimSpace(m.Revision) == "" {
		return fail(FactUnavailable, "finding declares no revision")
	}
	if loc == m.Revision {
		if m.RevisionStatus == FactValid {
			return ReferenceCheck{Status: FactValid}
		}
		return fail(FactInvalid, "revision %q does not resolve in the snapshot repository", loc)
	}
	root, err := canonicalDir(m.Repository)
	if err != nil || root == "" {
		return fail(FactUnavailable, "snapshot repository root cannot be resolved")
	}
	_, citedSHA, err := repository.ResolveRef(ctx, root, loc)
	if err != nil {
		return fail(FactInvalid, "revision %q does not resolve in the snapshot repository", loc)
	}
	_, snapSHA, err := repository.ResolveRef(ctx, root, m.Revision)
	if err != nil {
		return fail(FactConflicting, "snapshot revision %q no longer resolves", m.Revision)
	}
	if citedSHA != snapSHA {
		return fail(FactConflicting, "revision %q resolves to %s, not the snapshot revision %s", loc, citedSHA, snapSHA)
	}
	return ReferenceCheck{Status: FactValid}
}

// checkFilePinned is the offline counterpart of checkFile: it verifies the
// locator against the snapshot manifest only — path declared, declared
// sha256 agreement — and never opens the file or resolves the repository
// root. Byte equality and line bounds were verified when the run was
// recorded; offline replay trusts that recorded pin (the same one the
// run's own audit bound) instead of re-reading the working tree.
func checkFilePinned(m SnapshotManifest, ev EvidenceRef) ReferenceCheck {
	fail := func(s FactStatus, format string, args ...any) ReferenceCheck {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}
	}
	if strings.TrimSpace(m.Repository) == "" {
		return fail(FactUnavailable, "finding provides no repository snapshot")
	}
	loc, err := parseFileLocator(ev.Locator)
	if err != nil {
		return fail(FactInvalid, "malformed locator: %v", err)
	}
	decl := declaredFile(m, loc.path)
	if decl == nil {
		return fail(FactInvalid, "file %q is not declared in the snapshot manifest", loc.path)
	}
	if want := strings.TrimSpace(ev.SHA256); want != "" && !hashMatches(want, ev.Quote, decl.SHA256) {
		return fail(FactConflicting, "declared sha256 %q does not match the snapshot hash of %q", want, decl.Path)
	}
	return ReferenceCheck{Status: FactValid}
}

// checkArtifactPinned is the offline counterpart of checkArtifact: it
// matches the locator against the manifest's artifact set and the declared
// sha256 pin — artifact bytes are never read. An unpinned artifact cannot
// verify offline; the recorded pin is the only evidence binding.
func (g FactGate) checkArtifactPinned(in FindingInput, m SnapshotManifest, ev EvidenceRef) (ReferenceCheck, string) {
	fail := func(s FactStatus, format string, args ...any) (ReferenceCheck, string) {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}, ""
	}
	loc, err := parseArtifactLocator(ev.Locator)
	if err != nil {
		return fail(FactInvalid, "malformed locator: %v", err)
	}
	for _, a := range m.Artifacts {
		if !artifactMatch(loc.path, loc.abs, a.Path) {
			continue
		}
		if a.SHA256 == "" {
			return fail(FactUnavailable, "declared artifact %q carries no sha256 pin", a.Path)
		}
		if want := strings.TrimSpace(ev.SHA256); want != "" && !hashMatches(want, ev.Quote, a.SHA256) {
			return fail(FactConflicting, "declared sha256 %q does not match the snapshot hash of %q", want, a.Path)
		}
		return ReferenceCheck{Status: FactValid}, ""
	}
	for _, name := range []string{in.Finding.Target.SBOM, in.Finding.Target.Binary} {
		if declaredMatch(loc, name) {
			return fail(FactUnavailable, "declared artifact %q was not captured in the snapshot", strings.TrimSpace(name))
		}
	}
	if loc.abs {
		return ReferenceCheck{
			Status: FactUnavailable,
			Reason: "locator is outside the snapshot; not re-derivable here",
		}, fmt.Sprintf("evidence %s: locator %q is outside the snapshot; not re-derivable here", ev.ID, loc.path)
	}
	return fail(FactInvalid, "artifact %q is not among the declared finding artifacts", loc.path)
}

// checkRevisionRecorded is the offline counterpart of checkRevision: the
// recorded snapshot's revision status answers a locator naming the pinned
// ref; any other locator cannot be re-resolved without git access, so it
// stays UNAVAILABLE rather than being guessed.
func checkRevisionRecorded(m SnapshotManifest, ev EvidenceRef) ReferenceCheck {
	fail := func(s FactStatus, format string, args ...any) ReferenceCheck {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}
	}
	loc := strings.TrimSpace(ev.Locator)
	if loc == "" {
		return fail(FactInvalid, "revision evidence has no locator")
	}
	if strings.TrimSpace(m.Repository) == "" {
		return fail(FactUnavailable, "finding provides no repository snapshot")
	}
	if strings.TrimSpace(m.Revision) == "" {
		return fail(FactUnavailable, "finding declares no revision")
	}
	if loc == m.Revision {
		if m.RevisionStatus == FactValid {
			return ReferenceCheck{Status: FactValid}
		}
		return fail(FactInvalid, "revision %q does not resolve in the snapshot repository", loc)
	}
	return fail(FactUnavailable, "revision %q is not the pinned snapshot revision; offline replay cannot resolve refs", loc)
}

// verifyFileEntry runs the checks shared by source files and artifacts:
// declared hash agreement, pinned-hash drift detection and line bounds.
// decl is the manifest entry; abs is the on-disk path to read.
func verifyFileEntry(ctx context.Context, ev EvidenceRef, decl SnapshotFile, abs string, loc fileLocator) ReferenceCheck {
	fail := func(s FactStatus, format string, args ...any) ReferenceCheck {
		return ReferenceCheck{Status: s, Reason: fmt.Sprintf(format, args...)}
	}
	if want := strings.TrimSpace(ev.SHA256); want != "" && !hashMatches(want, ev.Quote, decl.SHA256) {
		return fail(FactConflicting, "declared sha256 %q does not match the snapshot hash of %q", want, decl.Path)
	}
	sum, lines, err := hashAndCountLines(ctx, abs)
	if err != nil {
		return fail(FactUnavailable, "file %q cannot be read: %v", decl.Path, err)
	}
	if sum != decl.SHA256 {
		return fail(FactConflicting, "content of %q changed since the snapshot was pinned", decl.Path)
	}
	if loc.start != 0 && loc.end > lines {
		return fail(FactInvalid, "lines %d-%d exceed %q which has %d lines", loc.start, loc.end, decl.Path, lines)
	}
	return ReferenceCheck{Status: FactValid}
}

// hashMatches accepts a declared sha256 when it matches either the pinned
// file hash or the hash of the quoted span; both are factual bindings the
// agent may have recorded.
func hashMatches(want, quote, got string) bool {
	if strings.EqualFold(want, got) {
		return true
	}
	if quote == "" {
		return false
	}
	sum := sha256.Sum256([]byte(quote))
	return strings.EqualFold(want, hex.EncodeToString(sum[:]))
}

// resolveDeclaredPath resolves a declared snapshot-relative path to its
// canonical absolute location. A vanished or unresolvable entry comes back
// as err (the source is unavailable); an entry that resolves outside the
// root comes back as inside=false (an escaping, hence invalid, reference).
func resolveDeclaredPath(root, rel string) (abs string, inside bool, err error) {
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", false, err
	}
	rel2, rerr := filepath.Rel(root, resolved)
	if !insideRoot(rel2, rerr) {
		return "", false, nil
	}
	return resolved, true, nil
}

// hashAndCountLines streams the file once, returning its sha256 and the
// number of lines (newline count plus one when the file is non-empty and
// lacks a trailing newline).
func hashAndCountLines(ctx context.Context, abs string) (string, int, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 32*1024)
	var lines int
	var seen, lastNL bool
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, rerr := f.Read(buf)
		chunk := buf[:n]
		h.Write(chunk)
		for _, b := range chunk {
			if b == '\n' {
				lines++
			}
		}
		if n > 0 {
			seen = true
			lastNL = chunk[n-1] == '\n'
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return "", 0, rerr
		}
	}
	if seen && !lastNL {
		lines++
	}
	return hex.EncodeToString(h.Sum(nil)), lines, nil
}

// resolveSnapshotPath converts a declared snapshot-relative path to its
// canonical absolute path, refusing anything that resolves outside root.
func resolveSnapshotPath(root, rel string) (string, bool) {
	abs, inside, err := resolveDeclaredPath(root, rel)
	if err != nil || !inside {
		return "", false
	}
	return abs, true
}
