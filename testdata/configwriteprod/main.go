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
	// A later assignment from external input must outrank the
	// configuration tag: configuration plus message data is external.
	s.Expression = os.Args[1]
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}
