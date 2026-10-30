// Package readgate confines file reads to an explicit set of canonical
// roots. It exists for benchmark isolation: an analyzed snapshot must not
// be able to make the analyzer read files outside its own tree (or outside
// the module cache and prepared inputs).
//
// The gate checks the *canonical* target (symlinks resolved) before a file
// is opened, so an in-tree symlink pointing outside is rejected rather than
// followed. Violations are errors, never silent reads.
package readgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Gate is a set of canonical roots a read is allowed to stay within. A nil
// *Gate permits everything — the default for non-benchmark runs.
type Gate struct {
	roots []string
}

// New canonicalises each root and returns a gate. Roots that do not exist
// are ignored (a missing module cache is not an error).
func New(roots ...string) *Gate {
	g := &Gate{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		canon, err := filepath.EvalSymlinks(r)
		if err != nil {
			canon = r
		}
		abs, aerr := filepath.Abs(canon)
		if aerr != nil {
			continue
		}
		g.roots = append(g.roots, filepath.Clean(abs))
	}
	return g
}

// Check verifies that target resolves under one of the gate's roots. It is
// a no-op on a nil gate.
func (g *Gate) Check(target string) error {
	if g == nil || len(g.roots) == 0 {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		// A path that does not resolve (missing file, broken symlink, cycle)
		// cannot be shown to be inside the roots: fail closed.
		return fmt.Errorf("read gate: %s does not resolve: %w", target, err)
	}
	for _, root := range g.roots {
		if within(root, resolved) {
			return nil
		}
	}
	return fmt.Errorf("read gate: %s resolves outside the allowed roots", target)
}

// Allows reports whether gate permits target. A nil gate allows everything.
func (g *Gate) Allows(target string) bool {
	return g.Check(target) == nil
}

// Roots returns the canonical roots (for diagnostics).
func (g *Gate) Roots() []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.roots...)
}

// within reports whether target lies at or under root; both must be cleaned
// absolute paths. Only a structural prefix counts: /a/b is inside /a, but
// /a-b is not inside /a.
func within(root, target string) bool {
	if target == root {
		return true
	}
	return strings.HasPrefix(target, root+string(filepath.Separator))
}

// Open opens path after checking it against the gate.
func (g *Gate) Open(path string) (*os.File, error) {
	if err := g.Check(path); err != nil {
		return nil, err
	}
	return os.Open(path)
}

// ReadFile reads path after checking it against the gate.
func (g *Gate) ReadFile(path string) ([]byte, error) {
	if err := g.Check(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
