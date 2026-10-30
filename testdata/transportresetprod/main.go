package main

import (
	"context"
	"fmt"
	"net"

	dep "example.com/transportresetdep"
)

// main is the production root: the pod-resources socket is served by the
// kubelet command, not by a library API.
func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}

func run() error {
	return servePodResources()
}

// servePodResources constructs the server and its listener and serves the same
// values, mirroring the shipped kubelet shape.
func servePodResources() error {
	srv, err := dep.NewServer(dep.UnaryInterceptor(podResourcesLimiter()))
	if err != nil {
		return err
	}
	lis, err := createListener("/var/lib/kubelet/pod-resources.sock")
	if err != nil {
		return err
	}
	return srv.Serve(lis)
}

func createListener(socketPath string) (net.Listener, error) {
	return net.Listen("unix", socketPath)
}

// podResourcesLimiter is a handler-level unary interceptor. It runs inside the
// handler chain, after the transport admitted and dispatched the stream, so it
// cannot bound the handlers a reset cycle leaves running.
func podResourcesLimiter() dep.Handler {
	return func(_ context.Context, s *dep.Stream) error {
		if s.Replicas() > maxPodResourcesListItems {
			return fmt.Errorf("pod resources list item bound exceeded")
		}
		return nil
	}
}

const maxPodResourcesListItems = 1024
