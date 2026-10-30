package main

import (
	"fmt"

	_ "example.com/initattr/reg"
	"example.com/mixdep/lib"
)

func main() {
	fmt.Println(lib.Used())
}
