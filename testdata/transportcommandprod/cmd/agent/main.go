// Command agent is the fixture's shipped entry point, reached exactly the way a
// cobra product is: the package main builds the command and runs it.
package main

import (
	"os"

	"example.com/transportcommandprod/cli"
	"example.com/transportcommandprod/cmd/agent/app"
)

func main() {
	command := app.NewAgentCommand()
	os.Exit(cli.Run(command))
}
