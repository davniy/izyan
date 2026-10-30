package research

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

func evidencesnapRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func runLaneAt(t *testing.T, root, advisory string, timeout time.Duration) (*LaneResult, string) {
	t.Helper()
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GO-TEST-SYM", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-sym",
		Timeout: timeout,
		// The test's premise is an identified build being analysed; a
		// host-default lane cannot ground the symbol proof.
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		// The fixture lanes receive the admitted contract a production
		// caller supplies after resolving defect semantics. Without it the
		// deadness routes stay INCONCLUSIVE (asserted separately).
		DefectSemantics: fixtureDefectSemantics(t, advisory),
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	return lane, out
}

// fixtureDefectSemantics derives the test contract from the inline advisory:
// its first declared symbol is the operation whose invocation the advisory
// documents. This is test input, not lane inference — the lane itself never
// derives semantics.
func fixtureDefectSemantics(t *testing.T, advisory string) *domain.DefectSemanticsContract {
	t.Helper()
	var doc struct {
		ID       string `json:"id"`
		Affected []struct {
			EcosystemSpecific struct {
				Imports []struct {
					Path    string   `json:"path"`
					Symbols []string `json:"symbols"`
				} `json:"imports"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	}
	if err := json.Unmarshal([]byte(advisory), &doc); err != nil {
		t.Fatalf("fixture advisory: %v", err)
	}
	for _, entry := range doc.Affected {
		for _, imp := range entry.EcosystemSpecific.Imports {
			if imp.Path == "" || len(imp.Symbols) == 0 {
				continue
			}
			return &domain.DefectSemanticsContract{
				Mode:     domain.DefectSemanticsDefectiveCheck,
				RecordID: doc.ID,
				Check:    domain.SymbolRef{Package: imp.Path, Symbol: imp.Symbols[0]},
			}
		}
	}
	return nil
}

func symbolRecords(lane *LaneResult) []evidencetools.AuditRecord {
	var out []evidencetools.AuditRecord
	for _, rec := range lane.Records {
		if rec.Tool == evidencetools.SymbolUnreachabilityTool {
			out = append(out, rec)
		}
	}
	return out
}

func declaredSymbolArgs(t *testing.T, rec evidencetools.AuditRecord) evidencetools.SymbolUnreachabilityArgs {
	t.Helper()
	var args evidencetools.SymbolUnreachabilityArgs
	if err := json.Unmarshal(rec.Args, &args); err != nil {
		t.Fatalf("args: %v", err)
	}
	return args
}

// Unused advisory-declared symbol (vuln.helper is dep-internal, unexported
// and never invoked): the lane itself dispatches the bounded proof and the
// authority route closes NO_EXPLOIT_PATH_FOUND/COMPLETE with audit-bound
// refs — no agent proposal, no decision artifact.
func TestDeterministicSymbolProofUnusedSymbol(t *testing.T) {
	lane, _ := runLaneAt(t, evidencesnapRoot(t), `{
	  "id": "GO-TEST-SYM",
	  "summary": "advisory declaring the dead dep symbol",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["helper"]}]}
	  }]
	}`, 60*time.Second)

	recs := symbolRecords(lane)
	if len(recs) != 1 {
		t.Fatalf("symbol-unreachability records = %d, want 1", len(recs))
	}
	args := declaredSymbolArgs(t, recs[0])
	if args.Module != "example.com/snapdep" || len(args.Subjects) != 1 ||
		args.Subjects[0].Package != "example.com/snapdep/vuln" || args.Subjects[0].Symbol != "helper" {
		t.Fatalf("dispatched subjects = %+v, want exactly the declared symbol", args)
	}
	proof := lane.SymbolProof
	if proof == nil {
		t.Fatal("lane did not run its symbol-unreachability attempt")
	}
	dec := proof.Decision
	if dec.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("decision = %+v (trace limitations %v)", dec, proof.Trace.Limitations)
	}
	if dec.Coverage != "COMPLETE" || dec.ConditionID != "declared-symbol-unreachable" ||
		dec.Falsifier != domain.FalsifierDeclaredSymbolUnreached ||
		dec.NegativeVerification == nil || dec.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("decision shape = %+v", dec)
	}
	if len(dec.EvidenceRefs) == 0 {
		t.Fatal("complete proof carries no evidence refs")
	}
	for _, ref := range dec.EvidenceRefs {
		if !strings.HasPrefix(ref, "sha256:") {
			t.Fatalf("ref %q is not an audit-bound digest", ref)
		}
	}
	if len(proof.Audit) == 0 || proof.Audit[0].Observation == nil {
		t.Fatal("no audit record bound to the attempt")
	}
	if proof.Trace == nil || len(proof.Trace.Requests) != 1 || !proof.Trace.Complete {
		t.Fatalf("trace = %+v", proof.Trace)
	}
	// The proof is bound to the persisted lane audit: the observation id
	// resolves to a persisted artifact pin.
	obsID := proof.Audit[0].Observation.ID
	if _, ok := lane.ArtifactByObs[obsID]; !ok {
		t.Fatalf("symbol proof observation %s is not persisted", obsID)
	}
}

// Used advisory symbol: the primitive records the reach evidence and the
// lane decision is INCONCLUSIVE naming the observed use — never a closure.
func TestDeterministicSymbolProofUsedSymbol(t *testing.T) {
	lane, _ := runLaneAt(t, evidencesnapRoot(t), `{
	  "id": "GO-TEST-SYM",
	  "summary": "advisory declaring the used dep symbol",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }]
	}`, 60*time.Second)

	proof := lane.SymbolProof
	if proof == nil {
		t.Fatal("lane did not attempt the symbol proof")
	}
	dec := proof.Decision
	if dec.Verdict != domain.VerdictInconclusive {
		t.Fatalf("a used symbol must stay INCONCLUSIVE, got %+v", dec)
	}
	// The decision reason is the primitive's own conclusion, not a
	// generic trace phrase: the declared symbol is reached, with the
	// counts the audit-recorded payload reports.
	if strings.Contains(dec.Reason, "verification trace is incomplete") {
		t.Fatalf("generic trace phrase must not be the decision reason: %q", dec.Reason)
	}
	if !strings.Contains(dec.Reason, "is disproven") || !strings.Contains(dec.Reason, "reach the declared subject(s)") {
		t.Fatalf("reason does not name the disproven conclusion: %q", dec.Reason)
	}
	var refs int
	for _, rec := range proof.Audit {
		var d evidencetools.SymbolUnreachabilityData
		if rec.Observation != nil && decodeData(rec.Observation.Data, &d) {
			refs += len(d.Result.ProductReferences)
		}
	}
	if want := fmt.Sprintf("%d product reference(s)", refs); !strings.Contains(dec.Reason, want) {
		t.Fatalf("reason lacks the payload's recorded count %q: %q", want, dec.Reason)
	}
	joined := strings.Join(dec.Limitations, "\n") + "\n" + dec.Reason
	if !strings.Contains(joined, "Parse") {
		t.Fatalf("decision does not name the observed use: %+v", dec)
	}
	if !strings.Contains(strings.Join(dec.Limitations, "\n"), "is disproven") {
		t.Fatalf("named conclusion missing from decision limitations: %v", dec.Limitations)
	}
	for _, o := range proof.Trace.Observations {
		if o.Completeness == evidencetools.CompletenessComplete {
			t.Fatal("a reachable symbol must not produce a COMPLETE proof observation")
		}
	}
}

// Incomplete proofs stay INCONCLUSIVE carrying the primitive's named
// limitation: an unresolvable declaration names the declaration failure,
// and a build-tag-gated reference keeps the scope open.
func TestDeterministicSymbolProofIncomplete(t *testing.T) {
	lane, _ := runLaneAt(t, evidencesnapRoot(t), `{
	  "id": "GO-TEST-SYM",
	  "summary": "advisory declaring a symbol absent from the dep version",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["DoesNotExist"]}]}
	  }]
	}`, 60*time.Second)

	proof := lane.SymbolProof
	if proof == nil {
		t.Fatal("lane did not attempt the symbol proof")
	}
	dec := proof.Decision
	if dec.Verdict != domain.VerdictInconclusive {
		t.Fatalf("incomplete proof must be INCONCLUSIVE, got %+v", dec)
	}
	if !strings.Contains(dec.Reason, "is UNKNOWN") || strings.Contains(dec.Reason, "verification trace is incomplete") {
		t.Fatalf("reason must carry the primitive's UNKNOWN conclusion: %q", dec.Reason)
	}
	joined := strings.Join(dec.Limitations, "\n")
	if !strings.Contains(joined, "DoesNotExist") {
		t.Fatalf("named limitation missing the unresolved declaration: %+v", dec)
	}
	if !strings.Contains(dec.Reason, "DoesNotExist") {
		t.Fatalf("reason does not name the open declaration limitation: %q", dec.Reason)
	}
}

// A gated (build-tag-excluded) reference keeps the proof's gated-set gate
// open: the lane stays INCONCLUSIVE and names the gated reference.
func TestDeterministicSymbolProofGatedReference(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", `module example.com/symgated

go 1.23

require example.com/snapdep v1.0.0

replace example.com/snapdep => ./snapdep
`)
	write("main.go", `package main

import "example.com/snapdep/vuln"

func main() { println(vuln.Parse("x")) }
`)
	write("gated.go", `//go:build izyan_probe

package main

import "example.com/snapdep/vuln"

var _ = vuln.Helper
`)
	write("snapdep/go.mod", `module example.com/snapdep

go 1.23
`)
	write("snapdep/vuln/vuln.go", `package vuln

// Parse is the product-called symbol.
func Parse(s string) string { return "parsed:" + s }

// Helper is exported but referenced only by a build-tag-excluded file.
func Helper(s string) string { return Parse(s) }
`)

	lane, _ := runLaneAt(t, root, `{
	  "id": "GO-TEST-SYM",
	  "summary": "advisory declaring the gated dep symbol",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Helper"]}]}
	  }]
	}`, 60*time.Second)

	proof := lane.SymbolProof
	if proof == nil {
		t.Fatal("lane did not attempt the symbol proof")
	}
	dec := proof.Decision
	if dec.Verdict == domain.VerdictNoExploitPathFound || dec.Verdict == domain.VerdictNotAffected {
		t.Fatalf("a gated reference can never close: %+v", dec)
	}
	if dec.Verdict != domain.VerdictInconclusive {
		t.Fatalf("decision = %+v", dec)
	}
	if strings.Contains(dec.Reason, "verification trace is incomplete") ||
		(!strings.Contains(strings.ToLower(dec.Reason), "gated") && !strings.Contains(strings.ToLower(dec.Reason), "open limitation")) {
		t.Fatalf("reason does not name the open gated limitation: %q", dec.Reason)
	}
	joined := strings.Join(dec.Limitations, "\n") + "\n" + dec.Reason
	if !strings.Contains(strings.ToLower(joined), "gated") && !strings.Contains(strings.ToLower(joined), "build tag") {
		t.Fatalf("decision does not name the gated reference: %+v", dec)
	}
}

// A module-only advisory (no declared symbols) leaves the lane exactly as
// before: no symbol-unreachability records and no lane decision.
func TestDeterministicSymbolProofModuleOnlyUnchanged(t *testing.T) {
	lane, _ := runLaneAt(t, evidencesnapRoot(t), `{
	  "id": "GO-TEST-SYM",
	  "summary": "module-only advisory",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
	  }]
	}`, 60*time.Second)

	if lane.SymbolProof != nil {
		t.Fatalf("module-only advisory must not attempt a symbol proof: %+v", lane.SymbolProof.Decision)
	}
	if n := len(symbolRecords(lane)); n != 0 {
		t.Fatalf("symbol-unreachability records = %d, want 0", n)
	}
}

// A tool-level failure (the per-call wall-clock timeout) is a failed
// check, never unreachability — the decision is INCONCLUSIVE naming the
// recorded timeout.
func TestDeterministicSymbolProofToolTimeout(t *testing.T) {
	lane, _ := runLaneAt(t, evidencesnapRoot(t), `{
	  "id": "GO-TEST-SYM",
	  "summary": "advisory declaring the dead dep symbol",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["helper"]}]}
	  }]
	}`, time.Nanosecond)

	proof := lane.SymbolProof
	if proof == nil {
		t.Fatal("lane did not attempt the symbol proof")
	}
	dec := proof.Decision
	if dec.Verdict == domain.VerdictNoExploitPathFound || dec.Verdict == domain.VerdictNotAffected {
		t.Fatalf("a tool failure can never close: %+v", dec)
	}
	if dec.Verdict != domain.VerdictInconclusive {
		t.Fatalf("decision = %+v", dec)
	}
	if !strings.Contains(dec.Reason, "TIMEOUT") || strings.Contains(dec.Reason, "verification trace is incomplete") {
		t.Fatalf("reason does not name the recorded timeout: %q", dec.Reason)
	}
	joined := strings.Join(dec.Limitations, "\n") + "\n" + dec.Reason
	if !strings.Contains(strings.ToLower(joined), "timeout") && !strings.Contains(joined, "timed out") {
		t.Fatalf("decision does not name the tool failure: %+v", dec)
	}
}

// Case-10 class gate, end to end: the product reaches the declared symbol
// only through a func-valued call whose candidate set never resolves.
// The may-call enumeration stays open, so the proof can never complete —
// the lane decision is INCONCLUSIVE and the reason names the partial
// enumeration, whatever the returned site count happens to be.
func TestDeterministicSymbolProofOpenMayCall(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fvopensnap"))
	if err != nil {
		t.Fatal(err)
	}
	lane, _ := runLaneAt(t, root, `{
	  "id": "GO-TEST-SYM",
	  "summary": "advisory declaring a symbol reachable only through an unresolved func value",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/fvdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/fvdep/vuln", "symbols": ["Parse"]}]}
	  }]
	}`, 60*time.Second)

	proof := lane.SymbolProof
	if proof == nil {
		t.Fatal("lane did not attempt the symbol proof")
	}
	dec := proof.Decision
	if dec.Verdict != domain.VerdictInconclusive {
		t.Fatalf("an open may-call enumeration can never close: %+v", dec)
	}
	// The empty/under-counted caller set is evidence of nothing: the
	// decision names the open enumeration, never a zero count.
	if !strings.Contains(dec.Reason, "may-call enumeration") {
		t.Fatalf("the partial may-call enumeration must be named: %q", dec.Reason)
	}
	if strings.Contains(dec.Reason, "unreachable") && !strings.Contains(dec.Reason, "UNKNOWN") {
		t.Fatalf("an open proof must not read as unreachability: %q", dec.Reason)
	}
}
