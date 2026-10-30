//go:build linux

package host

// Read is the Linux host-identity implementation. It is the only
// implementation selected under the recorded product build target and
// it does not carry the BSD-only vulnerable marker.
func Read() string { return "machine-id" }
