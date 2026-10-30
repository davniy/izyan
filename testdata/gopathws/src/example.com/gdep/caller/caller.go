// Package caller is a sibling package inside the same (module-less)
// dependency: it invokes the vulnerable symbol at package init. Without
// module ownership metadata the cone cannot enumerate this call, so the
// proof must stay open on the unresolved-ownership limitation.
package caller

import "example.com/gdep/lib"

var _ = lib.Vulnerable()
