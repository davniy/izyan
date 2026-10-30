package main

import (
	"fmt"

	"example.com/impldep/host"
)

// main links the host-identity package whose platform-specific
// implementation differs between Linux and BSD: under the recorded
// Linux build target the kern.hostid-carrying BSD implementation is
// deterministically excluded — the shape case-04's advisory describes.
func main() {
	fmt.Println(host.Read())
}
