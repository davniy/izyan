package goanalysis

// Regression for the two proof completions the real worked case required.
//
// The synthetic product under testdata/definitiveverdict mirrors the shape of
// the real Kubernetes/gRPC-Go code: the transport invokes the stream dispatch
// synchronously and the handler's goroutine belongs to the caller-supplied
// callback, and the upstream fix introduces a counting semaphore rather than an
// inline channel.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

const (
	workedFixtureDir = "../../testdata/definitiveverdict"
	workedFixtureMod = "google.golang.org/grpc"
	workedPatchPath  = "../states/testdata/definitive-verdict/grpc-handler-quota.patch"
)

func copyWorkedFixture(t *testing.T) (product, module string) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"product", "grpc"} {
		if err := os.CopyFS(filepath.Join(root, name), os.DirFS(filepath.Join(workedFixtureDir, name))); err != nil {
			t.Fatalf("copy fixture %s: %v", name, err)
		}
	}
	return filepath.Join(root, "product"), filepath.Join(root, "grpc")
}

func workedPatch(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(workedPatchPath)
	if err != nil {
		t.Fatalf("read the captured fix patch: %v", err)
	}
	return string(raw)
}

func workedRequest(t *testing.T) domain.TransportProofRequest {
	t.Helper()
	diff := workedPatch(t)
	return domain.TransportProofRequest{
		Record: domain.RecordPin{
			RecordID:       "GO-2023-2153",
			DocumentDigest: "sha256:e0e6817babaaffa610f5f1386e5cd3817ff53412cb3f7867dffc398c0e7f5a90",
			SourceLocator:  "osv-feed:GO-2023-2153",
		},
		EntryRefs: []int{0},
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc", Symbol: "NewServer"},
			{Package: "google.golang.org/grpc", Symbol: "Server.Serve"},
			{Package: "google.golang.org/grpc", Symbol: "Server.initServerWorkers"},
			{Package: "google.golang.org/grpc/internal/transport", Symbol: "NewServerTransport"},
		},
		Mechanism: domain.MechanismHTTP2RapidReset,
		FixURI:    "https://github.com/grpc/grpc-go/commit/f2180b4d5403d2210b30b93098eb7da31c05c721",
		FixDiff:   diff,
	}
}

// TestTransportProofRealShapes proves the mechanism over the real lifecycle
// shape and keeps every near-miss a failure.
func TestTransportProofRealShapes(t *testing.T) {
	t.Run("the real dispatch split and the captured fix prove the mechanism", func(t *testing.T) {
		product, _ := copyWorkedFixture(t)
		req := workedRequest(t)
		proof, err := (&Index{Dir: product}).ProveServerTransport(context.Background(), req)
		if err != nil {
			t.Fatalf("prove: %v", err)
		}
		if len(proof.Gaps) > 0 {
			t.Fatalf("unexpected gaps: %s", transportGapText(proof))
		}
		if proof.Trigger == nil {
			t.Fatal("no trigger witness")
		}
		for _, obligation := range proof.Trigger.Obligations {
			if !obligation.Satisfied {
				t.Fatalf("obligation %s unsatisfied: %s", obligation.ID, obligation.Detail)
			}
		}
		if !strings.Contains(proof.Trigger.Input.Root.Package, "pkg/kubelet/server") {
			t.Fatalf("root = %q", proof.Trigger.Input.Root.Package)
		}
		if !containsFixName(proof.Trigger.Fix.EnforcementNames, "newHandlerQuota") {
			t.Fatalf("enforcement names = %v", proof.Trigger.Fix.EnforcementNames)
		}
	})

	t.Run("a synchronous dispatch leaves the handler lifetime unproven", func(t *testing.T) {
		product, module := copyWorkedFixture(t)
		path := filepath.Join(module, "server.go")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		mutated := strings.Replace(string(raw), "\t\tgo func() {", "\t\tfunc() {", 1)
		if mutated == string(raw) {
			t.Fatal("control did not remove the asynchronous handler start")
		}
		if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
			t.Fatal(err)
		}
		proof, err := (&Index{Dir: product}).ProveServerTransport(context.Background(), workedRequest(t))
		if err != nil {
			t.Fatalf("prove: %v", err)
		}
		if proof.Trigger == nil {
			return
		}
		for _, obligation := range proof.Trigger.Obligations {
			if obligation.ID == domain.TransportObligationHandlerLifetime && obligation.Satisfied {
				t.Fatalf("handler lifetime was earned without a goroutine: %s", obligation.Detail)
			}
		}
	})

	t.Run("the captured fix names its semaphore enforcement", func(t *testing.T) {
		names, err := fixQuotaNames(workedPatch(t))
		if err != nil {
			t.Fatalf("fix quota: %v", err)
		}
		if !containsFixName(names, "atomicSemaphore") || !containsFixName(names, "newHandlerQuota") {
			t.Fatalf("names = %v", names)
		}
		if containsFixName(names, "wait") {
			t.Fatalf("a generic pre-fix identifier became an enforcement name: %v", names)
		}
	})

	t.Run("a channel without acquire and release is not a quota", func(t *testing.T) {
		diff := "--- a/x.go\n+++ b/x.go\n+type q struct {\n+\tch chan struct{}\n+}\n"
		if _, err := fixQuotaNames(diff); err == nil {
			t.Fatal("a bare channel field was accepted as a handler quota")
		}
	})

	t.Run("a semaphore without a deferred release is not a handler quota", func(t *testing.T) {
		diff := `--- a/x.go
+++ b/x.go
+type sem struct {
+	wait chan struct{}
+}
+func newSem() *sem { return &sem{wait: make(chan struct{}, 1)} }
+func (q *sem) acquire() { <-q.wait }
+func (q *sem) release() { q.wait <- struct{}{} }
+func serve() {
+	q := newSem()
+	q.acquire()
+	q.release()
+}
`
		if _, err := fixQuotaNames(diff); err == nil {
			t.Fatal("a semaphore without a deferred release was accepted as a handler quota")
		}
	})
}

func containsFixName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
