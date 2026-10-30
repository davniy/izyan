package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// canonicalJSON renders v with sorted map keys so two runs serialize the
// same structure identically — map iteration order can never leak into a
// hash or the report.
func canonicalJSON(v any) []byte {
	b, _ := json.Marshal(canonValue(v))
	return b
}

// canonValue rebuilds a JSON-decoded structure with sorted keys.
func canonValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m := make(map[string]any, len(t))
		for _, k := range keys {
			m[k] = canonValue(t[k])
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = canonValue(e)
		}
		return out
	default:
		return v
	}
}

// shortHash returns the first 16 hex chars of a sha256 — the same
// truncation evidencetools evidence refs use, so hashes cross-reference.
func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func fullHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
