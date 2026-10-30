// Package command models a CLI command value: the handler field carries the
// function the runner executes. It is fixture code for the command-root control,
// standing in for the cobra command type a shipped Go CLI uses.
package command

import "context"

// Handler serves one command invocation.
type Handler func(context.Context) error

// Command is one CLI command.
type Command struct {
	Use  string
	RunE Handler
}

// Execute runs the registered handler.
func (c *Command) Execute() error {
	if c.RunE == nil {
		return nil
	}
	return c.RunE(context.Background())
}
