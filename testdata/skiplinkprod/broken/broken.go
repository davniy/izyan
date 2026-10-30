// Package broken fails to type-check; it sits inside the shipping
// closure because the shipping main imports it — its invisible
// references stay a scope gap.
package broken

import _ "example.com/unreachdep/vulnlib"

// X is referenced by the shipping main.
var X = undefinedIdentifier
