// Package loose fails to type-check and imports nothing that any main
// reaches — its recovered edge set is empty, so the closure proves it
// dead: unreachable with recoverable edges.
package loose

func Loose() int {
	return undefinedIdentifier
}
