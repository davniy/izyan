package main

import (
	"fmt"

	"example.com/dep/vuln"
)

func main() {
	s, err := vuln.Parse([]byte("frame"))
	fmt.Println(s, err)
}
