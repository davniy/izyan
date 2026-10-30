// Package vuln is the pretend advisory dependency inside the snapshot.
package vuln

// Parse is the pretend vulnerable symbol the product calls.
func Parse(s string) string {
	return "parsed:" + s
}

// helper is dep-internal code reachable only through Parse.
func helper(s string) string {
	return Parse(s)
}
