// Package app mirrors a cobra-based Go CLI: the transport is served from the
// command handler, and the handler is registered as a function value.
package app

import (
	"context"
	"net"

	"example.com/transportcommandprod/command"
	dep "example.com/transportresetdep"
)

// NewAgentCommand constructs the agent command and registers run as its
// handler. Construction alone serves nothing: the command must be executed.
func NewAgentCommand() *command.Command {
	return &command.Command{Use: "agent", RunE: run}
}

func run(ctx context.Context) error {
	return serve(ctx)
}

func serve(_ context.Context) error {
	srv, err := dep.NewServer()
	if err != nil {
		return err
	}
	lis, err := createListener("/var/lib/transportagent.sock")
	if err != nil {
		return err
	}
	return srv.Serve(lis)
}

func createListener(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
