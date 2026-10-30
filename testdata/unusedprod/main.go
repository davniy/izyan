// Product requires the vulnerable module but never imports it: the module
// usage scan measures zero call sites into it. This is the fixture for
// "no usage" — as opposed to a module that is used but whose declared sink
// is never invoked.
package main

import "fmt"

func main() {
	fmt.Println("no dependency usage")
}
