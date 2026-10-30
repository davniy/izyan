// Package cli is the fixture's command runner: it executes the command value
// the entry point constructed.
package cli

import "example.com/transportcommandprod/command"

// Run executes the command.
func Run(c *command.Command) int {
	if err := c.Execute(); err != nil {
		return 1
	}
	return 0
}
