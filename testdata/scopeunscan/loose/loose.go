// Package loose fails to type-check but parses fine; it sits outside
// the shipping closure with fully recovered edges.
package loose

func Loose() int {
	return undefinedIdentifier
}
