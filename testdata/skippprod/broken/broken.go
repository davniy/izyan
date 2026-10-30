package broken

import _ "example.com/unreachdep/vulnlib"

// This package fails to type-check: references inside it are invisible to
// the index, so no negative check may call the scope closed.
func Broken() int { return undefinedIdentifier }
