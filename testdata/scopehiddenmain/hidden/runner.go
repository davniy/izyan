// The hidden main clause: go list reports "found packages foo and
// main" and names the package foo — but this main still links, so the
// scope must treat the directory as a shipping root, never discard it.
package main

func main() {}
