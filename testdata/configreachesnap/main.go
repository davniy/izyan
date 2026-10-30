package main

import (
	"example.com/confsnapdep/transformer"
)

// Settings is populated by the administrator-managed configuration
// decoder; no product code assigns its fields syntactically.
type Settings struct {
	Expression string `mapstructure:"expression"`
}

func load() Settings {
	var s Settings
	return s
}

func run(s Settings) {
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}

func main() {
	run(load())
}
