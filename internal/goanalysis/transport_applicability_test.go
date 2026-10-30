package goanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// This file pins the applicability contract: the specialized transport proof
// is dispatched only after the affected module's own source establishes a
// supported mechanism lifecycle. Model condition params, nominated protocol
// roles and prose route regexes are never consulted here — they are not
// evidence that the capability applies.

// unsupportedTransportFixture copies the transport fixture and removes the
// module's frame loop while keeping everything else intact: the module still
// builds a server, still exposes a listener entry point and still dispatches a
// HandleStreams method, so prose and fix-diff role detection would nominate the
// server role for it. What it no longer does is consume peer frames.
func unsupportedTransportFixture(t *testing.T) string {
	t.Helper()
	dir := copyTransportFixture(t)
	path := filepath.Join(dir, "dep", "transport", "transport.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transport source: %v", err)
	}
	src := string(raw)
	head := strings.Index(src, "// HandleStreams consumes")
	tail := strings.Index(src, "// operateHeaders admits")
	if head < 0 || tail < 0 || tail <= head {
		t.Fatalf("the fixture's frame loop is not where this test expects it")
	}
	stub := `// HandleStreams serves the accepted connection. This module decodes no
// versioned frame protocol, so it carries no stream lifecycle to prove.
func (t *ServerTransport) HandleStreams(ctx context.Context, handle func(context.Context, *Stream)) {
	t.handle = handle
	_ = ctx
}

`
	src = src[:head] + stub + src[tail:]
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write unsupported transport source: %v", err)
	}
	return dir
}

func transportApplicabilityScope(fixDiff string) TransportProofScope {
	return TransportProofScope{
		Record:   transportRecordPin(),
		Subjects: []domain.SymbolRef{{Package: "example.com/transportresetdep", Symbol: "Server.Serve"}},
		FixURI:   "https://example.com/fix/f2180b4d5403d2210b30b93098eb7da31c05c721",
		FixDiff:  fixDiff,
		FixDigest: func() string {
			if fixDiff == "" {
				return ""
			}
			sum := sha256.Sum256([]byte(fixDiff))
			return "sha256:" + hex.EncodeToString(sum[:])
		}(),
	}
}

// TestTransportApplicabilityRejectsRoleNomination is the nomination control:
// the affected module builds a server, names a listener entry point Serve and
// dispatches a HandleStreams method, so prose and fix-diff role detection would
// nominate the server role for it. The probe still refuses, because the source
// implements no supported mechanism lifecycle — a nomination is not
// applicability.
func TestTransportApplicabilityRejectsRoleNomination(t *testing.T) {
	ctx := context.Background()
	ix := &Index{Dir: unsupportedTransportFixture(t)}

	app, err := ix.TransportApplicabilityFor(ctx, transportApplicabilityScope(transportFixtureFixDiff))
	if err != nil {
		t.Fatalf("applicability probe: %v", err)
	}
	if app.Applicable {
		t.Fatalf("a transport with no frame lifecycle was reported applicable: %+v", app)
	}
	if app.Mechanism != "" {
		t.Fatalf("refused probe still named mechanism %q", app.Mechanism)
	}
	if len(app.Request.Subjects) != 0 || app.Request.Mechanism != "" {
		t.Fatalf("refused probe still produced a proof request: %+v", app.Request)
	}
	if reason := app.Reason(); !strings.Contains(reason, "implements no supported transport mechanism lifecycle") {
		t.Fatalf("refusal %q does not name the missing lifecycle", reason)
	}

	req, ok, err := ix.TransportProofRequestFor(ctx, transportApplicabilityScope(transportFixtureFixDiff))
	if err != nil {
		t.Fatalf("request probe: %v", err)
	}
	if ok || req.Mechanism != "" {
		t.Fatalf("TransportProofRequestFor returned applicable=%v request=%+v, want no dispatch", ok, req)
	}
}

// TestTransportApplicabilityRequestsTheDiscoveredMechanism is the positive
// control: the same scope over a module that does implement the frame
// lifecycle yields the request, with the mechanism discovered from the source
// rather than supplied by the caller.
func TestTransportApplicabilityRequestsTheDiscoveredMechanism(t *testing.T) {
	ctx := context.Background()
	ix := &Index{Dir: copyTransportFixture(t)}

	req, ok, err := ix.TransportProofRequestFor(ctx, transportApplicabilityScope(transportFixtureFixDiff))
	if err != nil {
		t.Fatalf("request probe: %v", err)
	}
	if !ok {
		t.Fatalf("the fixture's frame lifecycle was not reported applicable: %+v", req)
	}
	if req.Mechanism != domain.MechanismHTTP2RapidReset {
		t.Fatalf("mechanism = %q, want the source-discovered %q", req.Mechanism, domain.MechanismHTTP2RapidReset)
	}
	if req.Record != transportRecordPin() {
		t.Fatalf("request record = %+v, want the supplied pin", req.Record)
	}
	if len(req.EntryRefs) != 0 {
		t.Fatalf("entry refs = %v, want the caller's (empty) set", req.EntryRefs)
	}
	if req.FixDiff != transportFixtureFixDiff || req.FixDigest == "" {
		t.Fatal("the request dropped the captured fix material the trigger proof binds")
	}

	// The dispatched proof still establishes the trigger witness: applicability
	// gates the checker, it never replaces it.
	proof, err := ix.ProveServerTransport(ctx, req)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if proof.Trigger == nil || proof.Trigger.Complete() != nil {
		t.Fatalf("applicable request produced no complete trigger: gaps=%s", transportGapText(proof))
	}
}

// TestTransportApplicabilityRequiresAPinnedRecord refuses a scope whose record
// is not pinned to exact bytes: a rooted witness that cannot be re-admitted is
// not worth producing.
func TestTransportApplicabilityRequiresAPinnedRecord(t *testing.T) {
	ix := &Index{Dir: copyTransportFixture(t)}
	scope := transportApplicabilityScope(transportFixtureFixDiff)
	scope.Record = domain.RecordPin{RecordID: "GO-TEST-TRANSPORT"}

	app, err := ix.TransportApplicabilityFor(context.Background(), scope)
	if err != nil {
		t.Fatalf("applicability probe: %v", err)
	}
	if app.Applicable {
		t.Fatalf("an unpinned record was reported applicable: %+v", app)
	}
	if reason := app.Reason(); !strings.Contains(reason, "not pinned to exact bytes") {
		t.Fatalf("refusal %q does not name the missing pin", reason)
	}
}
