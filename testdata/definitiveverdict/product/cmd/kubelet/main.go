// Command kubelet is the fixture's shipped entry point. It is fixture code for
// the synthetic worked case: the production root reaches the affected
// transport through plain calls, so the proof's root rule applies unchanged.
package main

import (
	"context"

	"example.com/definitiveproduct/cmd/kubelet/app"
)

func main() {
	app.Run(context.Background())
}
