package goanalysis

// Command-handler entry controls. A production entry point registered as a
// command handler is a production root, but only with the whole registration
// chain proven: a constructor reached from package main, the handler field it
// installs, and the command actually executed there. Every near-miss stays a
// typed reachability gap, and an already-fixed module is still refused.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

const (
	commandFixtureDir = "../../testdata/transportcommandprod"
	commandDepDir     = "../../testdata/transportresetprod"
)

func copyCommandFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range map[string]string{
		"transportcommandprod": commandFixtureDir,
		"transportresetprod":   commandDepDir,
	} {
		if err := os.CopyFS(filepath.Join(root, name), os.DirFS(src)); err != nil {
			t.Fatalf("copy fixture %s: %v", name, err)
		}
	}
	return filepath.Join(root, "transportcommandprod")
}

func writeCommandFixtureFile(t *testing.T, product, rel, content string) {
	t.Helper()
	path := filepath.Join(product, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func commandProofRequest(t *testing.T) domain.TransportProofRequest {
	t.Helper()
	req := transportProofRequest(transportFixtureFixDiff)
	req.Subjects = []domain.SymbolRef{{Package: "example.com/transportresetdep", Symbol: "Server.Serve"}}
	return req
}

func chainMentions(w *domain.TransportInputWitness, want string) bool {
	if w == nil {
		return false
	}
	for _, site := range w.Chain {
		if strings.Contains(site.Detail, want) {
			return true
		}
	}
	return false
}

// commandFixtureMain is the shipped entry point of the command fixture.
const commandFixtureMain = `package main

import (
	"os"

	"example.com/transportcommandprod/cli"
	"example.com/transportcommandprod/cmd/agent/app"
)

func main() {
	command := app.NewAgentCommand()
	os.Exit(cli.Run(command))
}
`

// TestTransportProofCommandRoot proves the command-handler entry predicate and
// every near-miss around it.
func TestTransportProofCommandRoot(t *testing.T) {
	ctx := context.Background()

	prove := func(t *testing.T, product string) domain.TransportProof {
		t.Helper()
		proof, err := (&Index{Dir: product}).ProveServerTransport(ctx, commandProofRequest(t))
		if err != nil {
			t.Fatalf("prove: %v", err)
		}
		return proof
	}

	requireNoRoot := func(t *testing.T, proof domain.TransportProof) {
		t.Helper()
		if proof.Input != nil {
			t.Fatalf("control produced a rooted witness: root=%q chain=%+v", proof.Input.Root.Package, proof.Input.Chain)
		}
		if !containsGapCode(transportGapCodes(proof), domain.GapReachabilityProofIncomplete) {
			t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapReachabilityProofIncomplete)
		}
	}

	t.Run("a registered command handler reached from package main roots the proof", func(t *testing.T) {
		product := copyCommandFixture(t)
		proof := prove(t, product)
		if proof.Input == nil {
			t.Fatalf("no rooted input witness; gaps=%s", transportGapText(proof))
		}
		if err := proof.Input.Complete(); err != nil {
			t.Fatalf("input witness incomplete: %v", err)
		}
		if proof.Input.Root.Package != "example.com/transportcommandprod/cmd/agent/app" {
			t.Fatalf("root = %q; want the serve-owning product package", proof.Input.Root.Package)
		}
		if !chainMentions(proof.Input, "command handler field RunE registers") {
			t.Fatalf("chain records no handler registration: %+v", proof.Input.Chain)
		}
		if !chainMentions(proof.Input, "command constructor") {
			t.Fatalf("chain records no constructor call site: %+v", proof.Input.Chain)
		}
		if !chainMentions(proof.Input, "is executed") {
			t.Fatalf("chain records no command execution: %+v", proof.Input.Chain)
		}
		if !chainMentions(proof.Input, "production process entry point (package main)") {
			t.Fatalf("chain records no package main entry: %+v", proof.Input.Chain)
		}
		if proof.Trigger == nil {
			t.Fatalf("no trigger witness; gaps=%s", transportGapText(proof))
		}
		if err := proof.Trigger.Complete(); err != nil {
			t.Fatalf("trigger witness incomplete: %v (%s)", err, triggerObligationText(proof.Trigger))
		}
		if len(proof.Gaps) != 0 {
			t.Fatalf("gaps = %s; want none", transportGapText(proof))
		}
	})

	t.Run("a constructor that is never called from package main does not qualify", func(t *testing.T) {
		product := copyCommandFixture(t)
		writeCommandFixtureFile(t, product, "cmd/agent/main.go", `package main

func main() {}
`)
		writeCommandFixtureFile(t, product, "cmd/agent/main_test.go", `package main

import (
	"testing"

	"example.com/transportcommandprod/cli"
	"example.com/transportcommandprod/cmd/agent/app"
)

func TestAgentCommand(t *testing.T) {
	cli.Run(app.NewAgentCommand())
}
`)
		requireNoRoot(t, prove(t, product))
	})

	t.Run("a command that is never executed does not qualify", func(t *testing.T) {
		product := copyCommandFixture(t)
		writeCommandFixtureFile(t, product, "cmd/agent/main.go", `package main

import "example.com/transportcommandprod/cmd/agent/app"

func main() {
	_ = app.NewAgentCommand()
}
`)
		requireNoRoot(t, prove(t, product))
	})

	t.Run("a constructor that does not return the command does not qualify", func(t *testing.T) {
		product := copyCommandFixture(t)
		writeCommandFixtureFile(t, product, "cmd/agent/app/server.go", `package app

import (
	"context"
	"net"

	dep "example.com/transportresetdep"
	"example.com/transportcommandprod/command"
)

func NewAgentCommand() *command.Command {
	cmd := &command.Command{Use: "agent", RunE: run}
	_ = cmd
	return &command.Command{Use: "other"}
}

func run(ctx context.Context) error { return serve(ctx) }

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

func createListener(path string) (net.Listener, error) { return net.Listen("unix", path) }
`)
		requireNoRoot(t, prove(t, product))
	})

	t.Run("a tree carrying the fix quota is refused through the command handler", func(t *testing.T) {
		product := copyCommandFixture(t)
		transport := filepath.Join(filepath.Dir(product), "transportresetprod", "dep", "transport", "transport.go")
		raw, err := os.ReadFile(transport)
		if err != nil {
			t.Fatalf("read transport source: %v", err)
		}
		src := string(raw)
		src = strings.Replace(src, "\tmu            sync.Mutex\n",
			"\tmu            sync.Mutex\n\thandlerQuota  chan struct{}\n", 1)
		src = strings.Replace(src, "\t\tactiveStreams: make(map[uint32]*Stream),\n",
			"\t\tactiveStreams: make(map[uint32]*Stream),\n\t\thandlerQuota:  make(chan struct{}, 16),\n", 1)
		src = strings.Replace(src, "\tgo t.runHandler(s)\n",
			"\tselect {\n\tcase t.handlerQuota <- struct{}{}:\n\tcase <-t.ctx.Done():\n\t\treturn\n\t}\n\tdefer func() { <-t.handlerQuota }()\n\tgo t.runHandler(s)\n", 1)
		if err := os.WriteFile(transport, []byte(src), 0o644); err != nil {
			t.Fatalf("write transport source: %v", err)
		}

		proof := prove(t, product)
		if proof.Input == nil {
			t.Fatalf("the command-rooted input lost its proof; gaps=%s", transportGapText(proof))
		}
		if proof.Trigger == nil {
			t.Fatal("no trigger witness recorded for the fixed tree")
		}
		if err := proof.Trigger.Complete(); err == nil {
			t.Fatal("a tree that already carries the fix quota still produced a complete trigger witness")
		}
		requireTransportObligation(t, proof.Trigger, domain.TransportObligationNoFixedQuota, false)
		if !containsGapCode(transportGapCodes(proof), domain.GapTriggerProofIncomplete) {
			t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapTriggerProofIncomplete)
		}
	})
}
