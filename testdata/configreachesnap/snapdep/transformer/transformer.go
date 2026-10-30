// Package transformer is a generic data-transformation dependency used by
// the post-reach configuration fixtures. QueryAll/Find take the trigger
// expression as their second argument.
package transformer

// Node is an opaque document node.
type Node struct{}

// QueryAll evaluates expression against top and returns every match.
func QueryAll(top *Node, expression string) ([]*Node, error) {
	_ = top
	_ = expression
	return nil, nil
}

// Find evaluates expression against top and returns the first match.
func Find(top *Node, expression string) *Node {
	_ = top
	_ = expression
	return nil
}

// Helper is a non-sink API used to record module usage without config or
// trigger data.
func Helper() string { return "helper" }
