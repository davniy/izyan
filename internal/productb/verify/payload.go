package verify

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// payloadEnvelope unwraps a recorded observation payload: archived entries
// carry the full tool Observation envelope (fields under "data"), while
// raw-tool records carry their fields at top level. Both are consulted.
func payloadEnvelope(o *triage.RecordedObservation) (data, top map[string]any) {
	var env struct {
		Data         map[string]any `json:"data"`
		ScopeDetails map[string]any `json:"scope_details"`
	}
	if len(o.Payload) > 0 {
		_ = json.Unmarshal(o.Payload, &env)
	}
	if len(env.Data) > 0 {
		data = env.Data
	}
	if len(o.Payload) > 0 {
		var m map[string]any
		if json.Unmarshal(o.Payload, &m) == nil {
			top = m
		}
	}
	return data, top
}

// scopeDetailsMap returns the envelope scope_details object.
func scopeDetailsMap(top map[string]any) map[string]any {
	if sd, ok := top["scope_details"].(map[string]any); ok {
		return sd
	}
	return nil
}

func strOf(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func boolOf(m map[string]any, key string) (bool, bool) {
	if v, ok := m[key].(bool); ok {
		return v, true
	}
	return false, false
}

func listOf(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func mapOf(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func intOf(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int(v), true
		case int:
			return v, true
		}
	}
	return 0, false
}

// subjectFromData renders one {package, symbol, role?} payload member into
// a canonical subject.
func subjectFromData(m map[string]any) claimshape.Subject {
	pkg := strOf(m, "package")
	sym := strOf(m, "symbol")
	if pkg == "" && sym == "" {
		return claimshape.Subject{Kind: claimshape.SubjectUnknown}
	}
	name := pkg
	if sym != "" {
		name = pkg + "." + sym
	}
	return claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: name, Package: pkg, Symbol: sym}
}

// roleFromData returns a payload member's role vocabulary entry, if any.
func roleFromData(m map[string]any) string { return strOf(m, "role") }

// subjectSets decodes the subject arrays of the code-absence payload.
type subjectSets struct {
	Expected []claimshape.Subject
	Checked  []claimshape.Subject
	Absent   []claimshape.Subject
	Present  []claimshape.Subject
	Skipped  []string
	Roles    []string
}

func decodeSubjectSets(data map[string]any) subjectSets {
	var out subjectSets
	roles := map[string]bool{}
	decode := func(key string) []claimshape.Subject {
		var subs []claimshape.Subject
		for _, item := range listOf(data, key) {
			if m, ok := item.(map[string]any); ok {
				s := subjectFromData(m)
				if s.Name != "" {
					subs = append(subs, s)
				}
				if r := roleFromData(m); r != "" {
					roles[r] = true
				}
			}
		}
		return subs
	}
	out.Expected = decode("expected_subjects")
	out.Checked = decode("checked_subjects")
	out.Absent = decode("absent_subjects")
	out.Present = decode("present_subjects")
	for _, s := range listOf(data, "skipped_packages") {
		if v, ok := s.(string); ok {
			out.Skipped = append(out.Skipped, v)
		}
	}
	for r := range roles {
		out.Roles = append(out.Roles, r)
	}
	sort.Strings(out.Roles)
	return out
}

// sameSubjectSet reports whether two canonical subject sets are equal.
func sameSubjectSet(a, b []claimshape.Subject) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(s claimshape.Subject) string {
		return string(s.Kind) + "\x00" + s.Name
	}
	ka := make([]string, len(a))
	for i, s := range a {
		ka[i] = key(s)
	}
	kb := make([]string, len(b))
	for i, s := range b {
		kb[i] = key(s)
	}
	sort.Strings(ka)
	sort.Strings(kb)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

// coverageRuleVersionOf pulls the coverage-rule version out of a payload
// (code-absence pins the admission contract by version).
func coverageRuleVersionOf(data, top map[string]any) string {
	if v := strOf(data, "coverage_rule_version"); v != "" {
		return v
	}
	return strOf(top, "coverage_rule_version")
}

// scopeHashes resolves the observation's scope hash: an explicit
// scope_hash / closure hash wins, else a deterministic digest of the
// scope_details object pins the recorded scope. Replay stability comes
// from canonical serialization, never from map iteration order.
func scopeHashes(data, top map[string]any) (scopeHash, closureHash string, complete bool, openGaps []string) {
	closure := mapOf(data, "import_closure")
	if closure == nil {
		closure = mapOf(top, "import_closure")
	}
	if closure != nil {
		closureHash = strOf(closure, "hash")
		scopeHash = strOf(closure, "scope_hash")
		if c, ok := boolOf(closure, "complete"); ok {
			complete = c
		}
		for _, k := range []string{"open_exceptions", "observed_dynamic_markers", "skipped_unscanned", "unhashed_source", "scope_unknown"} {
			for _, g := range listOf(closure, k) {
				if s, ok := g.(string); ok {
					openGaps = append(openGaps, gapName(k)+":"+s)
				}
			}
		}
		if lb, ok := boolOf(closure, "load_budget_exhausted"); ok && lb {
			openGaps = append(openGaps, "truncated_scope:load_budget_exhausted")
		}
	}
	if scopeHash == "" {
		scopeHash = closureHash
	}
	if scopeHash == "" {
		if sd := scopeDetailsMap(top); sd != nil {
			scopeHash = "scope:" + shortHash(canonicalJSON(sd))
		}
	}
	return scopeHash, closureHash, complete, openGaps
}

// gapName maps a payload gap-list key to the registry's gap vocabulary.
func gapName(payloadKey string) string {
	switch payloadKey {
	case "open_exceptions":
		return "open_exception"
	case "observed_dynamic_markers", "dynamic_markers", "may_call_sites", "interface_dispatch_sites":
		return "open_dynamic_marker"
	case "skipped_unscanned", "skipped_packages":
		return "skipped_package"
	case "unhashed_source", "scope_unknown":
		return "truncated_scope"
	case "unresolved_dispatch":
		return "unresolved_dispatch"
	case "gated_references":
		return "build_gated_reference"
	}
	return payloadKey
}

// snapshotHashOf resolves the snapshot hash: the recorded column wins,
// else the payload's scope_details / data copies.
func snapshotHashOf(o *triage.RecordedObservation, data, top map[string]any) string {
	if o.SnapshotHash != "" {
		return o.SnapshotHash
	}
	if sd := scopeDetailsMap(top); sd != nil {
		if v := strOf(sd, "snapshot_hash"); v != "" {
			return v
		}
	}
	return strOf(data, "snapshot_hash")
}

// buildContextHashOf resolves the build-context hash: the recorded column
// wins, else a digest of the payload's build_context object.
func buildContextHashOf(o *triage.RecordedObservation, data, top map[string]any) string {
	if o.BuildContextHash != "" {
		return o.BuildContextHash
	}
	if sd := scopeDetailsMap(top); sd != nil {
		if bc := mapOf(sd, "build_context"); bc != nil {
			return "sha256:" + shortHash(canonicalJSON(bc))
		}
	}
	return strOf(data, "build_context_hash")
}

// callSitesOf decodes a callsite list payload into count + sample names.
func callSitesOf(data map[string]any, keys ...string) (count int, sites []string, possible int, partialEnum bool) {
	for _, k := range keys {
		for _, item := range listOf(data, k) {
			if m, ok := item.(map[string]any); ok {
				count++
				if len(sites) < 8 {
					f, ln := strOf(m, "file"), strOf(m, "func")
					if li, ok := intOf(m, "line"); ok {
						sites = append(sites, f+":"+itoa(li)+" "+ln)
					} else if f != "" {
						sites = append(sites, f+" "+ln)
					}
				}
			}
		}
		if count > 0 {
			break
		}
	}
	if c, ok := intOf(data, "count"); ok && c > count {
		count = c
	}
	if p, ok := intOf(data, "possible_count"); ok {
		possible = p
	}
	if pe, ok := boolOf(data, "partial_enumeration"); ok {
		partialEnum = pe
	}
	return count, sites, possible, partialEnum
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// subjectMatches reports whether a covered subject satisfies a claim. Exact
// names are only interchangeable when their identifier kinds agree; a
// module path must never satisfy a package/symbol claim by spelling alone.
func subjectMatches(claim, covered claimshape.Subject) bool {
	if covered.Name == "" || claim.Name == "" {
		return false
	}
	if claim.Kind == covered.Kind && claim.Name == covered.Name {
		return true
	}
	if claim.Package != "" && claim.Kind == claimshape.SubjectSymbol &&
		covered.Kind == claimshape.SubjectSymbol && claim.Package == covered.Package &&
		claim.Symbol == covered.Symbol && claim.Symbol != "" {
		return true
	}
	if covered.Kind == claimshape.SubjectPackage && claim.Kind == claimshape.SubjectSymbol && claim.Package == covered.Name {
		return true
	}
	return false
}

// normalizeSubjectName renders a canonical comparison key.
func subjectKey(s claimshape.Subject) string {
	return string(s.Kind) + "|" + strings.ToLower(s.Name)
}
