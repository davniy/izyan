package main

import (
	"fmt"
	"net"
	"os"

	"example.com/snapdep/vuln"
)

// main exercises the vulnerable dep symbol with input the process
// receives — the entrypoint candidates the adapter should surface.
func main() {
	ln, _ := net.Listen("tcp", ":0")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	buf := make([]byte, 16)
	n, _ := c.Read(buf)
	fmt.Println(vuln.Parse(string(buf[:n])))
	fmt.Println(vuln.Parse(os.Args[1]))
}
