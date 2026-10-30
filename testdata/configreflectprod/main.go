package main

import (
	"os"
	"reflect"

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
	// Reflection writes the field invisibly to the syntactic write-site
	// scan; the tag fallback must not claim the field stayed
	// administrator-managed.
	v := reflect.ValueOf(&s).Elem().FieldByName("Expression")
	v.SetString(os.Args[1])
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}
