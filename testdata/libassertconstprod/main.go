// Command libassertconstprod checks the shipped document through the
// assertion library and through the parser the helper wraps. Every operand is
// a compile-time constant: no consumer can select the payload.
package main

import (
	"fmt"

	"example.com/dep/vuln"
	"example.com/libassertprod/assert"
)

// testingT satisfies the library's minimal testing interface.
type testingT struct{}

func (testingT) Errorf(string, ...interface{}) {}

const baseline = "name: stable\nactions: [read]\n"

func validateBuiltin() {
	if !assert.YAMLEq(testingT{}, baseline, baseline) {
		fmt.Println("built-in document is not self-equivalent")
	}
	if vuln.ParseBytes([]byte(baseline)) != baseline {
		fmt.Println("built-in document did not round-trip")
	}
}

func main() {
	validateBuiltin()
}
