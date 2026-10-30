// Package server mirrors the kubelet's podresources listener: the product
// constructs the affected server and its own Unix listener and serves it. It
// is fixture code for the synthetic worked case.
package server

import (
	"context"
	"net"

	"google.golang.org/grpc"
)

// PodResourcesProviders supplies the served resource data.
type PodResourcesProviders interface {
	List() []string
}

// podResourcesLimiter is a handler-level control: it runs inside the handler
// chain, after the transport admitted and dispatched the stream. It cannot
// bound concurrent handler executions.
func podResourcesLimiter(_ context.Context, _ *grpc.Stream) error { return nil }

// ListenAndServePodResources initializes a gRPC server to serve the
// PodResources service on endpoint.
func ListenAndServePodResources(endpoint string, providers PodResourcesProviders) {
	if providers == nil {
		return
	}
	server := grpc.NewServer(
		grpc.MaxConcurrentStreams(100),
		grpc.UnaryInterceptor(podResourcesLimiter),
	)
	server.RegisterHandler(func(ctx context.Context, _ *grpc.Stream) error {
		_ = providers.List()
		return ctx.Err()
	})
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return
	}
	_ = server.Serve(listener)
}
