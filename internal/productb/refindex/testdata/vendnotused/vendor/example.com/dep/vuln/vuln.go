// Package vuln is the test dependency carrying the "vulnerable" code.
package vuln

import "io"

// Parse decodes a wire frame. The advisory names it as the defect site.
func Parse(b []byte) (string, error) {
	if len(b) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	return string(b), nil
}

// Reader is a vulnerable type with method members.
type Reader struct {
	buf []byte
}

// Read copies the buffered frame out.
func (r *Reader) Read(p []byte) (int, error) {
	return copy(p, r.buf), nil
}

// Config is a vulnerable data carrier type.
type Config struct {
	Limit int
}

// DefaultLimit is a package-level variable named by some advisories.
var DefaultLimit = 64

func unused() {}
