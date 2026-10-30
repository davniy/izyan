// Package fix resolves fix-commit references and fetches their patches.
// The patch is the strongest AUTHORITATIVE evidence for root-cause
// automation: it names the functions the vendor actually changed.
package fix

import (
	"net/url"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// Reference points at a vendor fix — a commit or patch that resolves the
// vulnerability. It deliberately carries no version list: which release lines a
// reference belongs to is a claim that needs evidence, so an aggregate
// FixedVersions list copied onto every reference proves nothing about any one
// of them.
type Reference struct {
	URL  string `json:"url"`
	Kind string `json:"kind"` // commit | advisory
}

// Resolver extracts fix references from a normalized Vulnerability.
type Resolver struct{}

// Resolve returns fix-bearing references: advisory entries typed FIX (or
// WEB/ADVISORY URLs that look like VCS commits). Each reference stands on its
// own: the returned set is not a patch series, and no aggregate fixed-version
// list is attached to it.
func (Resolver) Resolve(v domain.Vulnerability) []Reference {
	var out []Reference
	for _, r := range v.References {
		if !isFixReference(r.Type, r.URL) {
			continue
		}
		out = append(out, Reference{
			URL:  r.URL,
			Kind: refKind(r.Type, r.URL),
		})
	}
	return out
}

func isFixReference(typ, raw string) bool {
	t := strings.ToUpper(typ)
	if t == "FIX" {
		return true
	}
	if t != "ADVISORY" && t != "WEB" && t != "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "/commit/") ||
		strings.Contains(p, "/commits/") ||
		(u.Host == "github.com" && strings.Contains(p, "/pull/")) ||
		(strings.Contains(u.Host, "googlesource.com") && strings.Contains(p, "/+/")) ||
		strings.HasSuffix(p, ".patch") || strings.HasSuffix(p, ".diff")
}

func refKind(typ, raw string) string {
	if strings.EqualFold(typ, "FIX") {
		return "commit"
	}
	u, err := url.Parse(raw)
	if err == nil && (strings.Contains(u.Path, "/commit/") || strings.Contains(u.Path, "/+/")) {
		return "commit"
	}
	return "advisory"
}
