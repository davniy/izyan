// Command libasserthttpprod ingests documents POSTed to /compare and passes
// the request body to the assertion library's public YAML comparator. The
// application selects the payload from the network; the library only parses
// it.
package main

import (
	"io"
	"log"
	"net/http"

	"example.com/libassertprod/assert"
)

// testingT satisfies the library's minimal testing interface without
// coupling the handler to the testing package.
type testingT struct{}

func (testingT) Errorf(string, ...interface{}) {}

func compare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if !assert.YAMLEq(testingT{}, string(body), "name: stable\n") {
		http.Error(w, "documents differ", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	http.HandleFunc("/compare", compare)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
