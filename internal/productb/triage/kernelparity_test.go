package triage_test

// Kernel parity and post-port safety fixtures (port review §item-7): the
// adapter lane exercises the real kernel tools end to end — session →
// DeterministicTools broker → RecordedObservation — and asserts the
// blocking contract the falsifier admission path depends on:
//
//   - a COMPLETE verify_code_absence / symbol-unreachability observation
//     records the fields the admission path consumes (status, completeness,
//     snapshot and build-context hashes, payload shape);
//   - LIVE (referenced), UNKNOWN (unresolved) and PARTIAL/skipped/
//     open-dispatch states stay blocking — never minted as proofs;
//   - the symbol-unreachability payload the consumer decodes is exactly the
//     payload the producer emits (wire parity, not a re-shaped copy).
//
// The post-port corpus/census gate itself is CI-level: when the pinned
// corpus is unavailable the job fails and names the missing input — the
// merge is never eligible on a skipped gate.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/productb/triage"
)

// paritySession builds an evidence session over a testdata product the
// same way the live CLI does — the snapshot root is the product module.
func paritySession(t *testing.T, fixture string) *evidencetools.Session {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	s, err := evidencetools.NewSession(evidencetools.SessionConfig{
		SnapshotRoot: root,
		ExternalSHA:  "parity-sha-0001",
		Audit:        evidencetools.NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession(%s): %v", fixture, err)
	}
	return s
}

// parityDetTools wires the session to the adapter's deterministic broker:
// the same DeterministicTools/ClientCaller/ObservationStore path the agent
// run uses, so a parity failure is a wire-contract failure, not a test seam.
func parityDetTools(t *testing.T, s *evidencetools.Session) (*triage.DeterministicTools, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	client, err := s.Connect(ctx)
	if err != nil {
		t.Fatalf("session connect: %v", err)
	}
	det := &triage.DeterministicTools{
		Caller:           triage.ClientCaller{Client: client},
		Catalog:          triage.CatalogFromCheckCatalog(s.CheckCatalog()),
		ObservationStore: triage.NewRunObservationStore(triage.AttemptRunID("parity-finding", 1), 1),
	}
	return det, func() { _ = client.Close() }
}

// TestKernelParityCodeAbsenceAdmissionChain: a complete verify_code_absence
// observation survives the broker as the recorded shape the falsifier
// admission path consumes — the same fields falsifier.go checks before a
// code_absent proposal may verify.
func TestKernelParityCodeAbsenceAdmissionChain(t *testing.T) {
	s := paritySession(t, "evidencesnap")
	det, closeFn := parityDetTools(t, s)
	defer closeFn()
	ctx := context.Background()

	args, _ := json.Marshal(evidencetools.VerifyCodeAbsenceArgs{Subjects: []evidencetools.CodeSubject{
		{Package: "example.com/snapdep/vuln", Symbol: "Nope"},
	}})
	obs := det.Call(ctx, "verify_code_absence", args)
	if obs.Status != string(triage.ToolStatusOK) {
		t.Fatalf("verify_code_absence status = %s (%v)", obs.Status, obs.Limitations)
	}
	recs := det.Observations()
	if len(recs) != 1 {
		t.Fatalf("recorded %d observations", len(recs))
	}
	rec := recs[0]
	// The admission contract: the recorded observation must carry the
	// completeness the verifier requires, the snapshot/build binding it
	// cross-checks, and a parseable payload — a missing field here is a
	// parity break between producer and consumer, not a stylistic drift.
	if rec.Completeness != evidencetools.CompletenessComplete {
		t.Fatalf("completeness = %s (limitations=%v)", rec.Completeness, rec.Limitations)
	}
	if rec.SnapshotHash == "" || rec.BuildContextHash == "" {
		t.Fatalf("recorded observation lost its snapshot/build binding: %+v", rec)
	}
	var payload struct {
		Data evidencetools.CodeAbsenceData `json:"data"`
	}
	if err := json.Unmarshal(rec.Payload, &payload); err != nil {
		t.Fatalf("recorded payload does not decode as the producer's shape: %v", err)
	}
	if len(payload.Data.AbsentSubjects) != 1 || payload.Data.ImportClosure == nil || !payload.Data.ImportClosure.Complete {
		t.Fatalf("absence payload lost the closure record admission consumes: %+v", payload.Data)
	}
}

// TestKernelParityBlockingStates: every non-COMPLETE kernel state stays
// blocking at the recorded-observation layer — a skipped package, a
// reachable-but-broken closure and an unresolved symbol never surface as
// the COMPLETE owning observation an absent-code proof requires.
func TestKernelParityBlockingStates(t *testing.T) {
	ctx := context.Background()

	// Reachable skipped package: the closure stays open, COMPLETE is
	// unreachable, the recorded observation must report PARTIAL with the
	// skipped member named.
	t.Run("skipped package blocks COMPLETE", func(t *testing.T) {
		s := paritySession(t, "scopeskipp")
		det, closeFn := parityDetTools(t, s)
		defer closeFn()
		args, _ := json.Marshal(evidencetools.VerifyCodeAbsenceArgs{Subjects: []evidencetools.CodeSubject{
			{Package: "example.com/scopeskipp/loose", Symbol: "Nope"},
		}})
		det.Call(ctx, "verify_code_absence", args)
		rec := det.Observations()[0]
		if rec.Completeness == evidencetools.CompletenessComplete {
			t.Fatalf("reachable skipped package recorded COMPLETE: %+v", rec)
		}
		var payload struct {
			Data evidencetools.CodeAbsenceData `json:"data"`
		}
		if err := json.Unmarshal(rec.Payload, &payload); err != nil || len(payload.Data.SkippedPackages) == 0 {
			t.Fatalf("skipped member must be reported in the payload: %+v", payload.Data)
		}
	})

	// Open dynamic dispatch: a product package containing a reflect
	// marker leaves coverage open — DynamicMarkers must survive the wire
	// as a blocking limitation, never silently dropped.
	t.Run("open dynamic dispatch blocks COMPLETE", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/dyn\n\ngo 1.23\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package dyn\nimport \"reflect\"\nfunc Parse(){_=reflect.TypeOf(1)}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := evidencetools.NewSession(evidencetools.SessionConfig{SnapshotRoot: root, Audit: evidencetools.NopAudit{}})
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		det, closeFn := parityDetTools(t, s)
		defer closeFn()
		args, _ := json.Marshal(evidencetools.VerifyCodeAbsenceArgs{Subjects: []evidencetools.CodeSubject{
			{Package: "example.com/dyn", Symbol: "Parse"},
		}})
		det.Call(ctx, "verify_code_absence", args)
		rec := det.Observations()[0]
		if rec.Completeness == evidencetools.CompletenessComplete {
			t.Fatalf("open dispatch recorded COMPLETE: %+v", rec)
		}
		var payload struct {
			Data evidencetools.CodeAbsenceData `json:"data"`
		}
		if err := json.Unmarshal(rec.Payload, &payload); err != nil || len(payload.Data.DynamicMarkers) == 0 {
			t.Fatalf("open dispatch markers must reach the recorded payload: %+v", payload.Data)
		}
	})
}

// TestKernelParityUnreachabilityPayload: the recorded symbol-unreachability
// observation is the exact payload the producer emitted — the consumer's
// projection decodes it, the snapshot binding matches, and the approved /
// minted-proof path accepts it. This is the wire-parity half of the
// kernel gate: a shape drift between goanalysis/evidencetools and the
// triage consumer fails here, not in production.
func TestKernelParityUnreachabilityPayload(t *testing.T) {
	s := paritySession(t, "evidencesnap")
	det, closeFn := parityDetTools(t, s)
	defer closeFn()
	ctx := context.Background()

	args, _ := json.Marshal(evidencetools.SymbolUnreachabilityArgs{
		Module: "example.com/snapdep",
		Subjects: []domain.SymbolRef{
			{Package: "example.com/snapdep/vuln", Symbol: "helper"},
		},
	})
	det.Call(ctx, evidencetools.SymbolUnreachabilityTool, args)
	recs := det.Observations()
	if len(recs) != 1 {
		t.Fatalf("recorded %d observations", len(recs))
	}
	rec := recs[0]

	build := domain.EffectiveBuildContext(s.Build)
	s0 := triage.Stage0Result{Snapshot: triage.SnapshotManifest{ContentHash: rec.SnapshotHash}, Materials: triage.MaterialSet{PackageBuild: &build}}
	approved, why := triage.UnreachabilityObservationApproved(rec, s0)
	if !approved {
		t.Fatalf("complete kernel proof rejected at the adapter boundary: %s (obs=%+v)", why, rec)
	}
	// The observation is a read-only deadness fact, not a proof: the
	// product keeps the closed wire shape for proposal verification, but
	// nothing mints a checker proof from it without an admitted proposal.
	var payload struct {
		Data struct {
			Result struct {
				Complete            bool     `json:"complete"`
				DeclarationComplete bool     `json:"declaration_complete"`
				Limitations         []string `json:"limitations"`
				Subjects            []struct {
					Package string `json:"package"`
					Symbol  string `json:"symbol"`
				} `json:"subjects"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !payload.Data.Result.Complete || !payload.Data.Result.DeclarationComplete || len(payload.Data.Result.Limitations) != 0 {
		t.Fatalf("kernel wire shape is not closed: %+v", payload.Data.Result)
	}
	if len(payload.Data.Result.Subjects) != 1 ||
		payload.Data.Result.Subjects[0].Package != "example.com/snapdep/vuln" ||
		payload.Data.Result.Subjects[0].Symbol != "helper" {
		t.Fatalf("kernel subjects = %+v", payload.Data.Result.Subjects)
	}
}

// TestKernelParityUnreachabilityBlocking: LIVE (referenced) and UNKNOWN
// (unresolved) subjects never approve — the kernel's incomplete result is
// preserved through the wire, not upgraded.
func TestKernelParityUnreachabilityBlocking(t *testing.T) {
	ctx := context.Background()
	call := func(t *testing.T, symbol string) triage.RecordedObservation {
		t.Helper()
		s := paritySession(t, "evidencesnap")
		det, closeFn := parityDetTools(t, s)
		defer closeFn()
		args, _ := json.Marshal(evidencetools.SymbolUnreachabilityArgs{
			Module:   "example.com/snapdep",
			Subjects: []domain.SymbolRef{{Package: "example.com/snapdep/vuln", Symbol: symbol}},
		})
		det.Call(ctx, evidencetools.SymbolUnreachabilityTool, args)
		return det.Observations()[0]
	}

	t.Run("LIVE referenced symbol", func(t *testing.T) {
		rec := call(t, "Parse")
		s0 := triage.Stage0Result{Snapshot: triage.SnapshotManifest{ContentHash: rec.SnapshotHash}}
		if approved, _ := triage.UnreachabilityObservationApproved(rec, s0); approved {
			t.Fatal("a referenced symbol must never mint an unreachability approval")
		}
	})
	t.Run("UNKNOWN unresolved symbol", func(t *testing.T) {
		rec := call(t, "NoSuchSymbol")
		s0 := triage.Stage0Result{Snapshot: triage.SnapshotManifest{ContentHash: rec.SnapshotHash}}
		if approved, _ := triage.UnreachabilityObservationApproved(rec, s0); approved {
			t.Fatal("an unresolved symbol must never mint an unreachability approval")
		}
	})
	t.Run("foreign snapshot binding", func(t *testing.T) {
		rec := call(t, "helper")
		s0 := triage.Stage0Result{Snapshot: triage.SnapshotManifest{ContentHash: "sha256:other-snapshot"}}
		if approved, _ := triage.UnreachabilityObservationApproved(rec, s0); approved {
			t.Fatal("an observation bound to another snapshot must never approve")
		}
	})
}
