package main

import "example.com/vend/vendlib"

// main links a vendored dependency; deadpkg is never imported.
func main() {
	println(vendlib.V())
}
