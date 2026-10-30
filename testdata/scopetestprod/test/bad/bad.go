// Package bad fails to type-check and is never imported. Its package
// clause still parses, so it is provably a non-root dead package whose
// broken state must not reopen the closure. Its recovered import of svc
// makes it a skipped-channel importer of a member package.
package bad

import "example.com/scopetestprod/svc"

func Broken() int { return svc.Serve() + undefinedIdentifier }
