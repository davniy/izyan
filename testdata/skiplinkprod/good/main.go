// Command good is a second shipping main that type-checks cleanly, so the
// index still has valid product packages when cmd/app fails to load.
package main

import "fmt"

func main() {
	fmt.Println("ok")
}
