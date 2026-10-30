// Package vuln is first-party code named by the advisory — the product
// module itself implements the vulnerable symbol.
package vuln

// Parse decodes a wire frame.
func Parse(b []byte) (string, error) {
	return string(b), nil
}
