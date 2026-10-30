package evidencetools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// TestEvidenceCallClient exercises the typed-call adapter over a real
// strict confined session wired in memory: raw argument bytes pass
// through verbatim, every executed call produces an Observation plus a
// session audit record, and the confinement gate rejects out-of-roots
// reads as ERROR observations — never silent skips.
func TestEvidenceCallClient(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	sentinel := filepath.Join(parent, "ground_truth.json")
	must(t, os.WriteFile(sentinel, []byte(`{"label":"exploitable"}`), 0o644))

	s, err := NewSession(SessionConfig{
		SnapshotRoot:   root,
		CVEID:          "GO-TEST-0001",
		Strict:         true,
		AllowToolchain: true,
		VulnSource:     vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:          NopAudit{},
	})
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := s.Connect(ctx)
	must(t, err)
	// A confined in-root read returns a real Observation with the strict
	// scope stamps; raw arguments are dispatched verbatim.
	o, err := c.Call(ctx, "read_source", json.RawMessage(`{"file":"main.go","start":1,"end":3}`))
	must(t, err)
	if o.ToolStatus != StatusOK || o.Tool != "read_source" || o.ID == "" {
		t.Fatalf("read_source: %+v", o)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.Profile != profileStrict || len(o.ScopeDetails.ReadRoots) == 0 {
		t.Fatalf("missing strict scope details: %+v", o.ScopeDetails)
	}

	// Path outside the session roots is a gate ERROR observation —
	// a failed check, never a read.
	o, err = c.Call(ctx, "read_source", json.RawMessage(`{"file":"`+sentinel+`"}`))
	must(t, err)
	if o.ToolStatus != StatusError || o.Completeness != CompletenessUnknown || o.Data != nil {
		t.Fatalf("out-of-roots read: %+v", o)
	}
	o, err = c.Call(ctx, "read_source", json.RawMessage(`{"file":"../ground_truth.json"}`))
	must(t, err)
	if o.ToolStatus != StatusError {
		t.Fatalf("traversal read: %+v", o)
	}

	// An unregistered tool and an argument shape the schema cannot
	// decode produce call errors, not observations.
	o, err = c.Call(ctx, "definitely_not_a_tool", json.RawMessage(`{}`))
	if err == nil || o != nil {
		t.Fatalf("unknown tool: obs=%+v err=%v", o, err)
	}
	o, err = c.Call(ctx, "read_source", json.RawMessage(`{"file":42}`))
	if err == nil || o != nil {
		t.Fatalf("invalid arguments: obs=%+v err=%v", o, err)
	}

	// run_build is never enabled in this session profile: UNSUPPORTED
	// observation, not an exec.
	o, err = c.Call(ctx, "run_build", nil)
	must(t, err)
	if o.ToolStatus != StatusUnsupported {
		t.Fatalf("run_build: %s (%s)", o.ToolStatus, o.Error)
	}

	must(t, c.Close())
}

// TestEvidenceCallClientAudit proves calls through the adapter reach
// the session's audit sink exactly as the stdio agent path would.
func TestEvidenceCallClientAudit(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	var recs []AuditRecord
	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, CVEID: "GO-TEST-0001", Strict: true,
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      AuditFunc(func(_ context.Context, r AuditRecord) { recs = append(recs, r) }),
	})
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := s.Connect(ctx)
	must(t, err)
	defer c.Close()

	args := json.RawMessage(`{"file":"main.go"}`)
	o, err := c.Call(ctx, "read_source", args)
	must(t, err)
	if len(recs) != 1 {
		t.Fatalf("audit records=%d", len(recs))
	}
	if string(recs[0].Args) != `{"file":"main.go"}` || recs[0].Observation == nil ||
		recs[0].Observation.ID != o.ID || recs[0].Tool != "read_source" {
		t.Fatalf("audit record does not pin the call: %+v", recs[0])
	}
	if !strings.HasPrefix(o.ID, "OBS-") {
		t.Fatalf("session-minted id: %q", o.ID)
	}
}
