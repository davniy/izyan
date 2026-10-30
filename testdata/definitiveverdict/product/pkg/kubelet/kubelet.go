// Package kubelet mirrors the kubelet's ownership of the podresources
// listener. It is fixture code for the synthetic worked case.
package kubelet

import "example.com/definitiveproduct/pkg/kubelet/server"

// Kubelet is the node agent.
type Kubelet struct {
	endpoint string
}

// NewKubelet constructs a kubelet bound to endpoint.
func NewKubelet(endpoint string) *Kubelet { return &Kubelet{endpoint: endpoint} }

// ListenAndServePodResources runs the kubelet podresources grpc service.
func (kl *Kubelet) ListenAndServePodResources() {
	server.ListenAndServePodResources(kl.endpoint, nil)
}
