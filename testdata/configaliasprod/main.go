package main

import (
	"os"

	"example.com/postreachdep/transformer"
)

type Settings struct {
	Expression string `mapstructure:"expression"`
}

func load() Settings {
	var s Settings
	return s
}

func main() {
	s := load()
	// The writable alias carries a write the syntactic write-site scan
	// cannot attribute to the field.
	p := &s.Expression
	*p = os.Args[1]
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}
