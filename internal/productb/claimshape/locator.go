package claimshape

import (
	"regexp"
	"strings"

	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// The locator parsing mirrors the fact gate's own conventions: the same
// observation-id schemes, the same bare-id shape and the same
// normalization, so an id the run accepted resolves identically offline.
var observationIDSchemes = []string{"det:", "obs:", "set:"}

var bareObservationID = regexp.MustCompile(`(?i)^(det|obs|set)[-_][0-9]+$`)

// advisoryID matches the declared advisory-id shapes agents cite as
// advisory evidence locators.
var advisoryID = regexp.MustCompile(`(?i)^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|BDU:\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$`)

// searchProbe matches the legacy agent-synthesized locator
// "search:<needle>=<count>"; the trailing count is part of the locator
// spelling, so it is structured input, not prose.
var searchProbe = regexp.MustCompile(`^search:.*=(\d+)$`)

var listFilesProbe = regexp.MustCompile(`^list_files:([^=]+?)(?:=(\d+))?$`)

// parseObservationLocator extracts the recorded-observation id a locator
// names: a "det:"/"obs:"/"set:"-schemed reference (optionally with a
// "@<sha256>" pin) or the bare audited id itself.
func parseObservationLocator(raw string) (id, sha string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	rest := raw
	for _, scheme := range observationIDSchemes {
		if len(raw) > len(scheme) && strings.EqualFold(raw[:len(scheme)], scheme) {
			rest = raw[len(scheme):]
			id = strings.TrimSpace(rest)
			if i := strings.LastIndex(id, "@"); i >= 0 {
				id, sha = strings.TrimSpace(id[:i]), strings.TrimSpace(id[i+1:])
			}
			return id, sha, id != ""
		}
	}
	if bareObservationID.MatchString(raw) {
		return strings.TrimSpace(raw), "", true
	}
	return "", "", false
}

// normalizeObservationID folds an observation id for comparison exactly
// the way the fact gate does: lowercase, trimmed, '_' to '-'.
func normalizeObservationID(id string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(id)), "_", "-")
}

// observationIndex resolves cited observation ids to the run's recorded
// observations. Resolution is unique-or-fail: when several recorded
// observations normalize to the same id, only an exact-spelling match
// wins, otherwise the reference stays unresolved and is reported — a
// guess would fabricate provenance.
type observationIndex struct {
	byNormalized map[string][]*triage.RecordedObservation
	byExact      map[string]*triage.RecordedObservation
	ambiguous    map[string]bool
}

func newObservationIndex(obs []triage.RecordedObservation) *observationIndex {
	ix := &observationIndex{
		byNormalized: map[string][]*triage.RecordedObservation{},
		byExact:      map[string]*triage.RecordedObservation{},
		ambiguous:    map[string]bool{},
	}
	for i := range obs {
		o := &obs[i]
		norm := normalizeObservationID(o.ID)
		if ix.byExact[o.ID] != nil {
			ix.ambiguous[norm] = true
		}
		ix.byNormalized[norm] = append(ix.byNormalized[norm], o)
		if ix.byExact[o.ID] == nil {
			ix.byExact[o.ID] = o
		}
	}
	for norm, xs := range ix.byNormalized {
		if len(xs) > 1 {
			ix.ambiguous[norm] = true
		}
	}
	return ix
}

// resolve returns the recorded observation a cited id names, or nil and
// a flag telling whether the id was unresolvable (unknown or ambiguous).
func (ix *observationIndex) resolve(id string) (*triage.RecordedObservation, bool) {
	if o := ix.byExact[id]; o != nil && !ix.ambiguous[normalizeObservationID(o.ID)] {
		return o, false
	}
	norm := normalizeObservationID(id)
	xs := ix.byNormalized[norm]
	if len(xs) == 1 {
		return xs[0], false
	}
	if len(xs) > 1 {
		// Duplicate id spellings: every candidate names the same
		// observation family only when the payloads agree on tool.
		tool := xs[0].Tool
		for _, o := range xs[1:] {
			if o.Tool != tool {
				return nil, true
			}
		}
		return xs[0], false
	}
	return nil, true
}

// ambiguousIDs reports the normalized ids the index cannot resolve
// deterministically.
func (ix *observationIndex) ambiguousIDs() []string {
	out := make([]string, 0, len(ix.ambiguous))
	for id := range ix.ambiguous {
		out = append(out, id)
	}
	return out
}
