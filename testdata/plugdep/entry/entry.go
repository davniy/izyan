// Package entry loads a plugin at runtime: whatever the plugin provides
// is invisible to the static call graph, so the module cone cannot be
// proven closed.
package entry

import "plugin"

// Used is the benign API the product calls.
func Used() string { return "ok" }

// Run opens a plugin and resolves a symbol at runtime.
func Run() string {
	p, err := plugin.Open("w.so")
	if err != nil {
		return "err"
	}
	s, err := p.Lookup("Vulnerable")
	if err != nil {
		return "err"
	}
	if f, ok := s.(func() string); ok {
		return f()
	}
	return "?"
}
