// Package app mirrors the kubelet's startup path: the podresources listener is
// started asynchronously from the server run function. It is fixture code for
// the synthetic worked case.
package app

import (
	"context"
	"path/filepath"

	"example.com/definitiveproduct/pkg/kubelet"
)

// Run starts the node agent's listeners.
func Run(_ context.Context) {
	k := kubelet.NewKubelet(filepath.Join("/var/lib/kubelet", "pod-resources", "kubelet.sock"))
	go k.ListenAndServePodResources()
}
