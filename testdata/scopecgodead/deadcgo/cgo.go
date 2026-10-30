package deadcgo

import "C"

// CVal is the cgo entry surface of a dead package.
func CVal() int { return 1 }
