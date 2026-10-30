package main

import "example.com/scopecgoprod/hascgo"

// main links a cgo package: the reachable dynamic-link surface keeps
// the shipping scope open.
func main() {
	_ = hascgo.Run()
}
