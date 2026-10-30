package fixbinding

import (
	"path"
	"strings"
)

// unsupportedSourceMaterial names inputs for which no closed implementation
// rule exists. All build variants are inventoried, but merging their declarations
// is not a type-resolution proof. Nested module boundaries require their own
// selected-source evidence rather than being silently skipped.
func unsupportedSourceMaterial(name string, raw []byte) string {
	if path.Base(name) == "go.mod" && name != "go.mod" {
		return "nested module requires independent selected component evidence"
	}
	switch path.Ext(name) {
	case ".go":
		text := string(raw)
		if strings.Contains(text, `"C"`) {
			return "cgo implementation requires captured native inputs"
		}
		if strings.Contains(text, "//go:") || strings.Contains(text, "// +build") || strings.Contains(text, "// Code generated") {
			return "generated/directive/build-variant input requires a supported construction rule"
		}
		if len(sourceVariants(name, raw)) > 0 {
			return "filename-selected variant requires independent build/type resolution"
		}
	case ".mod", ".sum", ".md", ".txt", ".LICENSE":
		return ""
	default:
		if path.Base(name) == "LICENSE" || path.Base(name) == "NOTICE" {
			return ""
		}
		return "non-Go or generated/build-affecting material requires an implementation rule"
	}
	return ""
}
