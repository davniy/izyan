// Package libb is imported by liba — still no confirmed root: a library
// snapshot never yields DEAD.
package libb

// Helper is called by liba.Use.
func Helper() string {
	return "h"
}
