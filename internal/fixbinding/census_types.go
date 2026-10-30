package fixbinding

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
)

// checkCensusTypes checks captured packages without an ambient importer. Source
// parsing and the supported API resolver are not full Go type resolution. A
// package whose imported declarations are not captured/typechecked stays
// incomplete; there is deliberately no host GOROOT/cache fallback in this leaf.
func checkCensusTypes(c *Census, files map[string][]byte, names []string) {
	packages := map[string][]string{}
	for _, name := range names {
		packages[dirOf(name)] = append(packages[dirOf(name)], name)
	}
	dirs := make([]string, 0, len(packages))
	for dir := range packages {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		fset := token.NewFileSet()
		var syntax []*ast.File
		for _, name := range packages[dir] {
			f, err := parser.ParseFile(fset, name, files[name], 0)
			if err != nil {
				c.Parse.fail(CodeParseFile, "%v", err)
				continue
			}
			syntax = append(syntax, f)
			if len(sourceVariants(name, files[name])) > 0 {
				c.Parse.fail("BUILD_VARIANT_TYPE_RESOLUTION", "build-variant package requires separate type resolution: %s", name)
			}
		}
		if len(syntax) == 0 {
			continue
		}
		config := types.Config{Error: func(err error) { c.Parse.fail("TYPE_RESOLUTION_FAILED", "%v", err) }}
		if _, err := config.Check(c.Module+"/"+dir, fset, syntax, nil); err != nil {
			c.Parse.fail("TYPE_RESOLUTION_FAILED", "%v", err)
		}
	}
	if c.Parse.Reason == "" {
		c.Parse.Complete = true
		c.Parse.Reason = fmt.Sprintf("parsed and type-resolved %d closed captured package(s)", len(packages))
	}
}
