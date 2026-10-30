package main

import (
	"fmt"

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
	// Module usage without positive sink reach is not a post-reach proof.
	fmt.Println(transformer.Helper())
	_ = load()
}
