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
	// Configuration plus message-derived data: the external origin must
	// win over the configuration field.
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression+os.Args[1])
}
