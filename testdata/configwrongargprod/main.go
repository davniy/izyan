package main

import (
	"os"

	"example.com/postreachdep/transformer"
)

type Settings struct {
	Doc        string `mapstructure:"doc"`
	Expression string `mapstructure:"expression"`
}

func load() Settings {
	var s Settings
	return s
}

func main() {
	s := load()
	// The document argument is configuration-derived; the exact trigger
	// argument is external. Only the trigger position may be bound.
	s.Expression = os.Args[1]
	transformer.Query(s.Doc, s.Expression)
}
