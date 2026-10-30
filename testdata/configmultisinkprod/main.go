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
	// One declared sink receives configuration, the other external
	// input: the shared trigger condition cannot be falsified.
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
	_ = transformer.Find(&transformer.Node{}, os.Args[1])
}
