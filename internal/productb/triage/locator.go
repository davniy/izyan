package triage

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// fileLocator is a parsed evidence locator. start == 0 means the locator
// names a whole file; otherwise start/end are the 1-based inclusive span.
type fileLocator struct {
	path  string
	start int
	end   int
	abs   bool
}

// parseFileLocator parses a snapshot-relative locator in one of the accepted
// forms: "dir/file.go", "dir/file.go:42", "dir/file.go:42-57",
// "dir/file.go#L42" or "dir/file.go#L42-L57". Only relative paths contained
// in the snapshot root are accepted; absolute paths and parent escapes are
// rejected lexically, before the filesystem is ever touched.
func parseFileLocator(raw string) (fileLocator, error) {
	return parseLocator(raw, false)
}

// parseArtifactLocator parses an artifact locator. Artifacts may legitimately
// live outside the snapshot root (SBOM/Binary inputs recorded by absolute
// path), so absolute locator paths are accepted here; containment is decided
// later by matching against the declared artifact identity.
func parseArtifactLocator(raw string) (fileLocator, error) {
	return parseLocator(raw, true)
}

func parseLocator(raw string, allowAbs bool) (fileLocator, error) {
	base, spec, hashForm, err := splitLocator(raw)
	if err != nil {
		return fileLocator{}, err
	}
	var loc fileLocator
	if spec != nil {
		if err := loc.setLines(*spec, hashForm); err != nil {
			return fileLocator{}, err
		}
	}
	if base == "" {
		return loc, errors.New("locator has no path")
	}
	if filepath.IsAbs(base) || strings.HasPrefix(base, "/") {
		if !allowAbs {
			return fileLocator{}, fmt.Errorf("locator path %q is absolute, outside the snapshot root", base)
		}
		loc.path = path.Clean(base)
		loc.abs = true
		return loc, nil
	}
	p, err := cleanRelPath(base)
	if err != nil {
		return fileLocator{}, err
	}
	loc.path = p
	return loc, nil
}

// splitLocator strips the optional line suffix ("#L…" or trailing ":…") and
// returns the path part. spec is nil when no line form was present; hashForm
// selects the "#L" grammar.
func splitLocator(raw string) (base string, spec *string, hashForm bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, false, errors.New("empty locator")
	}
	if i := strings.LastIndex(raw, "#"); i >= 0 {
		frag := raw[i+1:]
		return raw[:i], &frag, true, nil
	}
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		if s := raw[i+1:]; isLineSpec(s) {
			return raw[:i], &s, false, nil
		}
	}
	return raw, nil, false, nil
}

// isLineSpec reports whether s looks like a line suffix ("42", "42-57").
// Malformed candidates still return true so they surface as parse errors
// instead of being silently reabsorbed into the path.
func isLineSpec(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '-' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// setLines parses a line suffix into the locator. hashForm selects the
// "L42[-L57]" grammar; otherwise the "42[-57]" grammar is used.
func (l *fileLocator) setLines(spec string, hashForm bool) error {
	fail := func(err error) error { return fmt.Errorf("bad line spec %q: %v", spec, err) }
	parse := func(s string) (int, error) {
		if hashForm {
			if !strings.HasPrefix(s, "L") {
				return 0, fmt.Errorf("hash form requires L<number>, got %q", s)
			}
			s = s[1:]
		}
		return parseLineNumber(s)
	}
	parts := strings.Split(spec, "-")
	if len(parts) > 2 {
		return fail(errors.New("too many segments"))
	}
	start, err := parse(parts[0])
	if err != nil {
		return fail(err)
	}
	end := start
	if len(parts) == 2 {
		if end, err = parse(parts[1]); err != nil {
			return fail(err)
		}
	}
	if start < 1 {
		return fail(fmt.Errorf("line numbers are 1-based, got %d", start))
	}
	if end < start {
		return fail(fmt.Errorf("reversed line range %d-%d", start, end))
	}
	l.start, l.end = start, end
	return nil
}

func parseLineNumber(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty line number")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("bad line number %q", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("bad line number %q", s)
	}
	return n, nil
}

// cleanRelPath normalizes a slash-separated relative path and proves it
// names a file inside the snapshot root: no absolute form, no parent
// segments, no drive-letter colon. Rejection is lexical; nothing here
// touches the filesystem.
func cleanRelPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("locator has no path")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("locator path %q escapes the snapshot root", p)
		}
	}
	clean := path.Clean(p)
	if clean == "." {
		return "", fmt.Errorf("locator path %q names no file", p)
	}
	if strings.Contains(clean, ":") {
		return "", fmt.Errorf("locator path %q is not snapshot-relative", p)
	}
	return clean, nil
}
