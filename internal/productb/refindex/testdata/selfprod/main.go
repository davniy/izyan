package main

import (
	"fmt"

	"example.com/selfprod/vuln"
)

func main() {
	s, _ := vuln.Parse([]byte("x"))
	fmt.Println(s)
}
