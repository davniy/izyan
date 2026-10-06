package vuln

import "fmt"

// URI and ParseURI form the serialize/re-parse pair the URI_CONFUSION
// pattern completes — String loses data a re-parse interprets.
type URI struct {
	Raw  string
	User string
}

func (u URI) String() string {
	if u.User != "" {
		return u.User + "@" + u.Raw
	}
	return u.Raw
}

func ParseURI(s string) (URI, error) {
	if s == "" {
		return URI{}, fmt.Errorf("empty URI")
	}
	return URI{Raw: s}, nil
}

// SafeFormatter is another Stringer implementation in the dependency that is
// never instantiated anywhere in ifaceprod.
type SafeFormatter struct{}

func (s SafeFormatter) String() string { return "safe" }

// DepInternalFormatter implements fmt.Stringer and is instantiated inside the
// dependency itself, but NEVER in product packages.
type DepInternalFormatter struct{}

func (d DepInternalFormatter) String() string { return "dep-internal" }

var _ = &DepInternalFormatter{}
