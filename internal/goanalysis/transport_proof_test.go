package goanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

const transportFixtureDir = "../../testdata/transportresetprod"

// transportFixtureFixDiff is the publisher fix shape for the mechanism: it
// introduces a bounded handler-quota channel, acquires it before the handler
// runs and releases it on the way out.
const transportFixtureFixDiff = `commit f2180b4d5403d2210b30b93098eb7da31c05c721
--- a/transport/transport.go
+++ b/transport/transport.go
@@ type ServerTransport struct {
     mu            sync.Mutex
     activeStreams map[uint32]*Stream
+    // handlerQuota bounds how many stream handlers execute at once.
+    handlerQuota chan struct{}
 }
@@ func (t *ServerTransport) operateHeaders(f *http2.MetaHeadersFrame) {
     t.mu.Unlock()
+    select {
+    case t.handlerQuota <- struct{}{}:
+    case <-t.ctx.Done():
+        return
+    }
+    defer func() { <-t.handlerQuota }()
     go t.runHandler(s)
 }
`

func transportRecordPin() domain.RecordPin {
	sum := sha256.Sum256([]byte(`{"id":"GO-TEST-TRANSPORT","summary":"fixture record"}`))
	return domain.RecordPin{
		RecordID:       "GO-TEST-TRANSPORT",
		DocumentDigest: "sha256:" + hex.EncodeToString(sum[:]),
		SourceLocator:  "file:///fixtures/GO-TEST-TRANSPORT.json",
	}
}

func copyTransportFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(transportFixtureDir)); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return dst
}

func writeTransportFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func transportProofRequest(fixDiff string) domain.TransportProofRequest {
	req := domain.TransportProofRequest{
		Record:    transportRecordPin(),
		Subjects:  []domain.SymbolRef{{Package: "example.com/transportresetdep", Symbol: "Server.Serve"}},
		Mechanism: domain.MechanismHTTP2RapidReset,
		FixURI:    "https://example.com/fix/f2180b4d5403d2210b30b93098eb7da31c05c721",
		FixDiff:   fixDiff,
	}
	if fixDiff != "" {
		sum := sha256.Sum256([]byte(fixDiff))
		req.FixDigest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return req
}

func transportGapCodes(proof domain.TransportProof) []domain.GapCode {
	var codes []domain.GapCode
	for _, g := range proof.Gaps {
		codes = append(codes, g.Code)
	}
	return codes
}

// transportGapText renders the typed gaps with their producer messages so a
// failing table entry states why the proof stopped.
func transportGapText(proof domain.TransportProof) string {
	if len(proof.Gaps) == 0 {
		return "<no gaps>"
	}
	var parts []string
	for _, g := range proof.Gaps {
		parts = append(parts, string(g.Code)+": "+g.Message)
	}
	return strings.Join(parts, " | ")
}

// triggerObligationText renders each obligation's state and detail.
func triggerObligationText(w *domain.TransportTriggerWitness) string {
	if w == nil {
		return "<no trigger>"
	}
	var parts []string
	for _, o := range w.Obligations {
		state := "unsatisfied"
		if o.Satisfied {
			state = "satisfied"
		}
		parts = append(parts, string(o.ID)+"="+state+" ("+o.Detail+")")
	}
	return strings.Join(parts, "; ")
}

func containsGapCode(codes []domain.GapCode, want domain.GapCode) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func requireTransportObligation(t *testing.T, w *domain.TransportTriggerWitness, id domain.TransportObligationID, want bool) {
	t.Helper()
	if w == nil {
		t.Fatalf("trigger witness is nil, want obligation %s", id)
	}
	o, ok := w.Obligation(id)
	if !ok {
		t.Fatalf("trigger witness has no %s obligation (have %v)", id, w.Obligations)
	}
	if o.Satisfied != want {
		t.Fatalf("obligation %s satisfied=%v want %v (detail %q)", id, o.Satisfied, want, o.Detail)
	}
}

// TestTransportProof is the rooted-transport / trigger-witness table: the full
// witness, every control that must not qualify, and every missing obligation
// that must surface as a typed gap.
func TestTransportProof(t *testing.T) {
	ctx := context.Background()
	fixDiff := transportFixtureFixDiff

	fullWitness := func(t *testing.T, proof domain.TransportProof) {
		t.Helper()
		if proof.Input == nil {
			t.Fatalf("input witness is nil; gaps=%s", transportGapText(proof))
		}
		if err := proof.Input.Complete(); err != nil {
			t.Fatalf("input witness incomplete: %v", err)
		}
		if proof.Input.Root.Package != "example.com/transportresetprod" || !proof.Input.Root.Production {
			t.Fatalf("root = %+v; want the production package main root", proof.Input.Root)
		}
		if len(proof.Input.Chain) < 3 {
			t.Fatalf("root-to-serve chain = %d hops; want main → run → serve", len(proof.Input.Chain))
		}
		if !proof.Input.Server.SameValue || !proof.Input.Listener.SameValue {
			t.Fatalf("server/listener bindings lost the same-value proof: %+v %+v",
				proof.Input.Server, proof.Input.Listener)
		}
		if proof.Input.Server.Construction.Symbol.Package != "example.com/transportresetdep" {
			t.Fatalf("server construction = %+v; want the affected module constructor",
				proof.Input.Server.Construction.Symbol)
		}
		if len(proof.Input.Transport) < 2 {
			t.Fatalf("transport path = %d hops; want Serve → frame loop", len(proof.Input.Transport))
		}
		if proof.Trigger == nil {
			t.Fatalf("trigger witness is nil; gaps=%s", transportGapText(proof))
		}
		if err := proof.Trigger.Complete(); err != nil {
			t.Fatalf("trigger witness incomplete: %v (%s; gaps %s)", err,
				triggerObligationText(proof.Trigger), transportGapText(proof))
		}
		for _, id := range domain.TransportTriggerObligationIDs {
			requireTransportObligation(t, proof.Trigger, id, true)
		}
		if len(proof.Trigger.Fix.EnforcementNames) != 1 || proof.Trigger.Fix.EnforcementNames[0] != "handlerQuota" {
			t.Fatalf("fix enforcement names = %v; want [handlerQuota]", proof.Trigger.Fix.EnforcementNames)
		}
		noQuota, _ := proof.Trigger.Obligation(domain.TransportObligationNoFixedQuota)
		if len(noQuota.Absence) == 0 {
			t.Fatal("missing-quota obligation carries no absence record")
		}
		removal, _ := proof.Trigger.Obligation(domain.TransportObligationRemovalBeforeCompletion)
		if len(removal.Absence) == 0 {
			t.Fatal("removal obligation carries no no-join absence record")
		}
		if len(proof.Gaps) != 0 {
			t.Fatalf("gaps = %s; want none", transportGapText(proof))
		}
	}

	requireNoRootedInput := func(t *testing.T, proof domain.TransportProof) {
		t.Helper()
		if proof.Input != nil {
			t.Fatalf("control produced a rooted witness: %+v", proof.Input)
		}
		if !containsGapCode(transportGapCodes(proof), domain.GapReachabilityProofIncomplete) {
			t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapReachabilityProofIncomplete)
		}
	}

	type testCase struct {
		name    string
		mutate  func(t *testing.T, dir string)
		request func() domain.TransportProofRequest
		check   func(t *testing.T, proof domain.TransportProof)
	}

	cases := []testCase{
		{
			name:  "rooted production transport and rapid reset lifecycle prove the trigger",
			check: fullWitness,
		},
		{
			name: "import only reference does not qualify",
			mutate: func(t *testing.T, dir string) {
				writeTransportFile(t, dir, "main.go", `package main

import (
	"fmt"

	_ "example.com/transportresetdep"
)

func main() {
	fmt.Println("transport imported, never served")
}
`)
			},
			check: requireNoRootedInput,
		},
		{
			name: "dial only client does not qualify",
			mutate: func(t *testing.T, dir string) {
				writeTransportFile(t, dir, "main.go", `package main

import (
	"context"
	"fmt"
	"net"

	dep "example.com/transportresetdep"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9090")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	client := dep.NewClient(conn)
	if err := client.Call(context.Background(), "/svc/Method"); err != nil {
		fmt.Println(err)
	}
}
`)
			},
			check: requireNoRootedInput,
		},
		{
			name: "constructed server that is never served does not qualify",
			mutate: func(t *testing.T, dir string) {
				writeTransportFile(t, dir, "main.go", `package main

import (
	"fmt"

	dep "example.com/transportresetdep"
)

func main() {
	srv, err := dep.NewServer()
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = srv
}
`)
			},
			check: requireNoRootedInput,
		},
		{
			name: "test only serve path does not qualify",
			mutate: func(t *testing.T, dir string) {
				writeTransportFile(t, dir, "main.go", `package main

func main() {}
`)
				writeTransportFile(t, dir, "serve_test.go", `package main

import (
	"net"
	"testing"

	dep "example.com/transportresetdep"
)

func TestServe(t *testing.T) {
	srv, err := dep.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Serve(lis)
}
`)
			},
			check: requireNoRootedInput,
		},
		{
			name: "unrooted library API does not qualify",
			mutate: func(t *testing.T, dir string) {
				writeTransportFile(t, dir, "main.go", `package main

func main() {}
`)
				writeTransportFile(t, dir, "pkg/api/server.go", `package api

import (
	"net"

	dep "example.com/transportresetdep"
)

// Start serves the transport but nothing production-rooted calls it.
func Start(lis net.Listener) error {
	srv, err := dep.NewServer()
	if err != nil {
		return err
	}
	return srv.Serve(lis)
}
`)
			},
			check: requireNoRootedInput,
		},
		{
			name: "missing fix evidence emits TRIGGER_PROOF_INCOMPLETE",
			request: func() domain.TransportProofRequest {
				return transportProofRequest("")
			},
			check: func(t *testing.T, proof domain.TransportProof) {
				t.Helper()
				if proof.Input == nil {
					t.Fatalf("input witness lost by the trigger gap; gaps=%s", transportGapText(proof))
				}
				if proof.Trigger == nil {
					t.Fatal("mechanism detected but no trigger witness recorded")
				}
				if err := proof.Trigger.Complete(); err == nil {
					t.Fatal("trigger witness reported complete without fix evidence")
				}
				requireTransportObligation(t, proof.Trigger, domain.TransportObligationNoFixedQuota, false)
				if !containsGapCode(transportGapCodes(proof), domain.GapTriggerProofIncomplete) {
					t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapTriggerProofIncomplete)
				}
			},
		},
		{
			name: "fix digest mismatch is a proof gap",
			request: func() domain.TransportProofRequest {
				req := transportProofRequest(fixDiff)
				req.FixDigest = "sha256:" + strings.Repeat("0", 64)
				return req
			},
			check: func(t *testing.T, proof domain.TransportProof) {
				t.Helper()
				requireTransportObligation(t, proof.Trigger, domain.TransportObligationNoFixedQuota, false)
				if !containsGapCode(transportGapCodes(proof), domain.GapTriggerProofIncomplete) {
					t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapTriggerProofIncomplete)
				}
			},
		},
		{
			name: "already fixed source does not prove the mechanism",
			mutate: func(t *testing.T, dir string) {
				path := filepath.Join(dir, "dep", "transport", "transport.go")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read transport source: %v", err)
				}
				src := string(data)
				src = strings.Replace(src, "\tmu            sync.Mutex\n",
					"\tmu            sync.Mutex\n\thandlerQuota  chan struct{}\n", 1)
				src = strings.Replace(src, "\t\tactiveStreams: make(map[uint32]*Stream),\n",
					"\t\tactiveStreams: make(map[uint32]*Stream),\n\t\thandlerQuota:  make(chan struct{}, 16),\n", 1)
				src = strings.Replace(src, "\tgo t.runHandler(s)\n",
					"\tselect {\n\tcase t.handlerQuota <- struct{}{}:\n\tcase <-t.ctx.Done():\n\t\treturn\n\t}\n\tdefer func() { <-t.handlerQuota }()\n\tgo t.runHandler(s)\n", 1)
				if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
					t.Fatalf("write transport source: %v", err)
				}
			},
			check: func(t *testing.T, proof domain.TransportProof) {
				t.Helper()
				if proof.Trigger == nil {
					t.Fatal("no trigger witness recorded for the fixed source")
				}
				requireTransportObligation(t, proof.Trigger, domain.TransportObligationNoFixedQuota, false)
				if !containsGapCode(transportGapCodes(proof), domain.GapTriggerProofIncomplete) {
					t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapTriggerProofIncomplete)
				}
			},
		},
		{
			name: "pre dispatch handler quota prevents the positive",
			mutate: func(t *testing.T, dir string) {
				writeTransportFile(t, dir, "main.go", `package main

import (
	"fmt"
	"net"

	dep "example.com/transportresetdep"
)

var handlerSlots = make(chan struct{}, 8)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}

func run() error {
	return servePodResources()
}

func servePodResources() error {
	select {
	case handlerSlots <- struct{}{}:
	default:
		return fmt.Errorf("handler quota exhausted")
	}
	defer func() { <-handlerSlots }()

	srv, err := dep.NewServer()
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
`)
			},
			check: func(t *testing.T, proof domain.TransportProof) {
				t.Helper()
				if proof.Input == nil {
					t.Fatalf("input witness missing; gaps=%s", transportGapText(proof))
				}
				if proof.Trigger != nil {
					if err := proof.Trigger.Complete(); err == nil {
						t.Fatal("a pre-dispatch handler quota still produced a complete trigger witness")
					}
				}
				requireTransportObligation(t, proof.Trigger, domain.TransportObligationControlPosition, false)
				if !containsGapCode(transportGapCodes(proof), domain.GapTriggerProofIncomplete) {
					t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapTriggerProofIncomplete)
				}
			},
		},
		{
			name: "transport stream admission is recorded but does not prevent",
			mutate: func(t *testing.T, dir string) {
				path := filepath.Join(dir, "main.go")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read main: %v", err)
				}
				src := strings.Replace(string(data),
					"dep.NewServer(dep.UnaryInterceptor(podResourcesLimiter()))",
					"dep.NewServer(dep.UnaryInterceptor(podResourcesLimiter()), dep.MaxConcurrentStreams(100))", 1)
				if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
					t.Fatalf("write main: %v", err)
				}
			},
			check: func(t *testing.T, proof domain.TransportProof) {
				t.Helper()
				fullWitness(t, proof)
				var sawInterceptor, sawAdmission bool
				for _, c := range proof.Trigger.Controls {
					switch c.Disposition {
					case domain.TransportControlHandlerLevel:
						sawInterceptor = true
					case domain.TransportControlTransportAdmission:
						sawAdmission = true
					}
				}
				if !sawInterceptor {
					t.Fatalf("controls = %+v; want the unary interceptor recorded as handler-level", proof.Trigger.Controls)
				}
				if !sawAdmission {
					t.Fatalf("controls = %+v; want MaxConcurrentStreams recorded as reset-defeated admission", proof.Trigger.Controls)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyTransportFixture(t)
			if tc.mutate != nil {
				tc.mutate(t, dir)
			}
			ix := &Index{Dir: dir}
			req := transportProofRequest(fixDiff)
			if tc.request != nil {
				req = tc.request()
			}
			proof, err := ix.ProveServerTransport(ctx, req)
			if err != nil {
				t.Fatalf("prove: %v", err)
			}
			tc.check(t, proof)
		})
	}
}

// TestTransportMechanismHasNoDefault pins the discovery contract: the proof
// never supplies a mechanism the request did not name. A caller that omits it
// still receives the rooted input witness — the transport path is a proof of
// its own — but no trigger witness, and the typed gap says the mechanism was
// not established instead of assuming http2-rapid-reset.
func TestTransportMechanismHasNoDefault(t *testing.T) {
	ctx := context.Background()
	dir := copyTransportFixture(t)
	ix := &Index{Dir: dir}

	req := transportProofRequest(transportFixtureFixDiff)
	req.Mechanism = ""
	proof, err := ix.ProveServerTransport(ctx, req)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if proof.Input == nil {
		t.Fatalf("the rooted input proof was lost with the mechanism; gaps=%s", transportGapText(proof))
	}
	if err := proof.Input.Complete(); err != nil {
		t.Fatalf("input witness incomplete: %v", err)
	}
	if proof.Trigger != nil {
		t.Fatalf("an unnamed mechanism produced a trigger witness: %+v", proof.Trigger)
	}
	if !containsGapCode(transportGapCodes(proof), domain.GapTriggerProofIncomplete) {
		t.Fatalf("gaps = %s; want %s", transportGapText(proof), domain.GapTriggerProofIncomplete)
	}
	for _, gap := range proof.Gaps {
		if strings.Contains(gap.Message, domain.MechanismHTTP2RapidReset) {
			t.Fatalf("gap message assumed the rapid-reset mechanism: %q", gap.Message)
		}
	}
}
