package main

import (
	"fmt"

	"example.com/dep/vuln"
)

func main() {
	// The vulnerable package is linked, but the affected symbol is never
	// referenced — the podman x/crypto ssh/agent shape.
	s, err := vuln.Parse([]byte("frame"))
	fmt.Println(s, err)
}
