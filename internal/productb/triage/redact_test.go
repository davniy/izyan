package triage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRedactSecretsPatterns pins the F-7 allowlist: every credential shape
// the artifact writer can echo is replaced, never passed through.
func TestRedactSecretsPatterns(t *testing.T) {
	for _, s := range []string{
		"authorization: Bearer abcdefghij1234567890",
		"api_key=sk-abcdefghijklmnopqrstuvwxyz1234",
		"sk-proj-abcdefghijklmnop_1234567890",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"github_pat_11ABCDEF_0123456789abcdefghij",
		"glpat-abcdefghijklmnopqrst",
		"xoxb-" + strings.Repeat("0", 12) + "-" + strings.Repeat("a", 16),
		"token=deadbeefcafe1234567890",
		"password: hunter2",
	} {
		got := redactSecrets(s)
		if strings.Contains(got, s) || !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("secret not redacted in %q -> %q", s, got)
		}
	}
}

// TestWriteErrorRedactsSecrets drives the artifact path end-to-end: a
// technical failure that echoes credentials must not persist them.
func TestWriteErrorRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	in := FindingInput{Finding: Finding{FindingID: "FIND-1", SchemaVersion: FindingSchemaVersion}}
	w := ArtifactWriter{}
	secretErr := errors.New("llm call failed: authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234 token=hunter2")
	path, err := w.WriteError(context.Background(), dir, in, secretErr)
	if err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc ErrorDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc.Error, "sk-") || strings.Contains(doc.Error, "hunter2") || strings.Contains(doc.Error, "Bearer") {
		t.Fatalf("error.json carried secrets: %q", doc.Error)
	}
	if !strings.Contains(doc.Error, "[REDACTED]") {
		t.Fatalf("error.json shows no redaction marker: %q", doc.Error)
	}
	if filepath.Base(path) != errorFileName {
		t.Fatalf("unexpected path %s", path)
	}
}

// TestAuditLogRedactsLimitations: an error-derived audit event must not
// persist credentials — the audit writer scrubs every limitation line
// before it reaches audit/events.jsonl.
func TestAuditLogRedactsLimitations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ev := AuditEvent{Type: AuditEventError, Status: "error", Scope: "stage0",
		Limitations: []string{"advisory fetch failed: authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}
	if err := appendAuditLog(context.Background(), path, []AuditEvent{ev}, "run-1", time.Now().UTC()); err != nil {
		t.Fatalf("appendAuditLog: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ghp_") || strings.Contains(string(raw), "Bearer") {
		t.Fatalf("audit log persisted a credential: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("audit log shows no redaction marker: %s", raw)
	}
}

// TestStage0FailureRedactsEverywhere drives the stage-0 failure artifact
// path: the secret inside the failing error must not appear in error.json,
// the partial raw-agent.json, stage0.json limitations, materials.json or
// the audit trail.
func TestStage0FailureRedactsEverywhere(t *testing.T) {
	dir := t.TempDir()
	res := Stage0Result{
		Input: FindingInput{Finding: Finding{FindingID: "FIND-9", SchemaVersion: FindingSchemaVersion}},
		// A sub-step limitation that already embeds the leaked token —
		// it survives stage0's own shortErr and must be scrubbed at the
		// artifact boundary instead.
		Limitations: []string{"module graph via govulndb failed: api_key=sk-abcdefghijklmnopqrstuvwxyz1234"},
		Materials:   MaterialSet{Materials: []Material{{ID: "go-mod", Kind: "manifest", Source: "test", Scope: "s"}}, Limitations: []string{"go list -deps failed: token=secret_token_xyz"}},
	}
	runErr := errors.New("resolve advisory: authorization: Bearer glpat-abcdefghijklmnop0123456789")
	if _, err := (ArtifactWriter{}).WriteStage0Failure(context.Background(), dir, res, runErr); err != nil {
		t.Fatalf("WriteStage0Failure: %v", err)
	}
	rn, nerr := RunDirName("FIND-9")
	if nerr != nil {
		t.Fatal(nerr)
	}
	runDir := filepath.Join(dir, rn)
	for _, f := range []string{"error.json", "raw-agent.json", "stage0.json", "materials.json", filepath.Join("audit", "events.jsonl")} {
		b, err := os.ReadFile(filepath.Join(runDir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, needle := range []string{"sk-abcdefghijklmnopqrstuvwxyz1234", "glpat-abcdefghijklmnop0123456789", "secret_token_xyz", "Bearer"} {
			if strings.Contains(string(b), needle) {
				t.Fatalf("%s persisted secret %q", f, needle)
			}
		}
	}
}

// TestAuditLogRedactsNestedProjections pins the recursive pass on the
// audit event: credential-shaped text inside a NESTED stage projection
// (RefResolutionAudit.FallbackReason, MaterializationAudit.Limitations,
// IntakeAudit field reasons) must be scrubbed — a top-level-only loop
// over ev.Limitations can never reach it.
func TestAuditLogRedactsNestedProjections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ev := AuditEvent{
		Type: AuditEventRefResolution, Status: "fallback", Scope: "stage0",
		Ref: &RefResolutionAudit{
			SelectedID: "r1", SelectedRef: "1.2.3", ResolutionRule: "fallback",
			FallbackReason: "agent ref selection failed: Authorization: Bearer ghp_" + strings.Repeat("n", 36),
		},
		Materialize: &MaterializationAudit{
			Mode:        "clone",
			SourceID:    "repo-a",
			Limitations: []string{"clone stderr: token=glpat-" + strings.Repeat("c", 20)},
		},
	}
	if err := appendAuditLog(context.Background(), path, []AuditEvent{ev}, "run-1", time.Now().UTC()); err != nil {
		t.Fatalf("appendAuditLog: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"ghp_" + strings.Repeat("n", 36), "glpat-" + strings.Repeat("c", 20)} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("audit log persisted nested credential %q in event: %s", needle, raw)
		}
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("audit log shows no redaction marker: %s", raw)
	}
	// The event must still decode — redaction is lossy, never structural.
	var back AuditEvent
	if err := json.Unmarshal(raw[:len(raw)-1], &back); err != nil {
		t.Fatalf("redacted event does not decode: %v", err)
	}
	if back.Ref == nil || back.Ref.SelectedRef != "1.2.3" {
		t.Fatalf("ref projection mangled by redaction: %+v", back.Ref)
	}
}

// TestIntakeAuditRedactsNestedFields: intake-audit.json serializes
// IntakeFieldAudit.Reason, document Errors and the materialization
// projection verbatim — a credential inside any of them must be scrubbed
// before the file lands.
func TestIntakeAuditRedactsNestedFields(t *testing.T) {
	dir := t.TempDir()
	res := Stage0Result{
		Input: FindingInput{Finding: Finding{FindingID: "FIND-9"}},
		Validation: IntakeValidation{
			Fields: []FieldValidation{
				{Field: "advisory_id", Status: IntakeConflicting, Reason: "llm probe failed: api_key=sk-ant-" + strings.Repeat("k", 20)},
			},
			Errors: []string{"proposal ingest: token=tok_live_" + strings.Repeat("t", 16)},
		},
	}
	res.Source.Metadata = MaterializationMetadata{
		Mode: "local", SourceID: "repo-a",
		Limitations: []string{"worktree add failed: Authorization: Bearer ghp_" + strings.Repeat("w", 36)},
	}
	if err := WriteIntakeAudit(context.Background(), dir, res); err != nil {
		t.Fatalf("WriteIntakeAudit: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "intake-audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"sk-ant-" + strings.Repeat("k", 20), "tok_live_" + strings.Repeat("t", 16), "ghp_" + strings.Repeat("w", 36)} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("intake-audit.json persisted nested credential %q", needle)
		}
	}
	var doc IntakeAuditDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("redacted intake audit does not decode: %v", err)
	}
	if doc.Fields[0].Reason == "" || doc.Materialization == nil {
		t.Fatalf("redaction dropped document structure: %+v", doc)
	}
}

// TestStage0ArtifactsRedactNestedLimitations: snapshot.json carries
// MaterializationMetadata.Limitations verbatim — a credential inside the
// nested list must never persist.
func TestStage0ArtifactsRedactNestedLimitations(t *testing.T) {
	dir := t.TempDir()
	res := Stage0Result{
		Input: FindingInput{Finding: Finding{FindingID: "FIND-9"}},
	}
	res.Snapshot = SnapshotManifest{
		SchemaVersion: SnapshotSchemaVersion,
		FindingID:     "FIND-9",
		Materialization: MaterializationMetadata{
			Mode: "clone", SourceID: "repo-a",
			Limitations: []string{"clone failed: password=" + strings.Repeat("h", 20) + "_Secret"},
		},
	}
	res.Source.Metadata = res.Snapshot.Materialization
	res.Limitations = []string{"stage0 done"}
	writeStage0Files(context.Background(), dir, res, "FIND-9")
	raw, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), strings.Repeat("h", 20)+"_Secret") || strings.Contains(string(raw), "password=") {
		t.Fatalf("snapshot.json persisted nested credential: %s", raw)
	}
	raw2, err := os.ReadFile(filepath.Join(dir, "stage0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw2), strings.Repeat("h", 20)+"_Secret") {
		t.Fatalf("stage0.json persisted nested credential: %s", raw2)
	}
}

// TestAuditLogRedactsDecisionAxes: the decision audit event carries text
// from the model judgment, the human action and the derived support. Every
// one of those axis objects must go through the same recursive credential
// pass, and the event must stay decodable with its axes separate.
func TestAuditLogRedactsDecisionAxes(t *testing.T) {
	pkg := actionCardFixture(t)
	pkg.Judgment.Summary = "operator pasted api_key=sk-abcdefghijklmnopqrstuvwxyz1234 into the judgment"
	pkg.ProposedAction.Instruction = "run with authorization: Bearer ghp_" + strings.Repeat("x", 36)
	pkg.Support.Reasons = []string{"support note token=deadbeefcafe1234567890"}

	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ev := DecisionAuditEvent(pkg, "run-1", time.Unix(1, 0).UTC())
	if err := appendAuditLog(context.Background(), path, []AuditEvent{ev}, "run-1", time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("appendAuditLog: %v", err)
	}
	raw := mustRead(t, path)
	for _, needle := range []string{
		"sk-abcdefghijklmnopqrstuvwxyz1234",
		"ghp_" + strings.Repeat("x", 36),
		"deadbeefcafe1234567890",
		"Bearer",
	} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("decision audit event persisted %q: %s", needle, raw)
		}
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("decision audit event shows no redaction marker: %s", raw)
	}
	var back AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &back); err != nil {
		t.Fatalf("redacted decision event does not decode: %v", err)
	}
	if back.Decision == nil {
		t.Fatalf("redacted decision event lost its projection: %s", raw)
	}
	if back.Decision.HumanAction.Kind != string(pkg.ProposedAction.Kind) ||
		back.Decision.Machine.Recommendation != string(pkg.MachineDisposition.Recommendation) {
		t.Fatalf("redaction crossed the decision axes: %+v", back.Decision)
	}
}

// TestAuditLogRedactsHumanDecision: the human decision audit event carries
// the person's actor and reason as a projection distinct from the package
// axes. Credentials pasted into either field never reach the log, while the
// record id, decision, package binding and artifact hash survive.
func TestAuditLogRedactsHumanDecision(t *testing.T) {
	pkg := actionCardFixture(t)
	rec := HumanDecisionRecord{
		SchemaVersion:       HumanDecisionSchemaVersion,
		RunID:               pkg.RunID,
		FindingID:           pkg.FindingID,
		DecisionPackageHash: canonicalDecisionHash(pkg),
		Decision:            HumanDecisionAccept,
		Actor:               "alice",
		Reason:              "operator pasted api_key=sk-abcdefghijklmnopqrstuvwxyz1234 into the reason",
		RecordedAt:          time.Unix(1, 0).UTC(),
	}
	rec.ID = humanDecisionRecordID(rec)
	event := HumanDecisionAuditEvent(rec, time.Unix(1, 0).UTC())
	if event.Hash == "" {
		t.Fatal("human decision audit event carries no artifact hash")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := appendAuditLog(context.Background(), path, []AuditEvent{event}, rec.RunID, time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("appendAuditLog: %v", err)
	}
	raw := string(mustRead(t, path))
	for _, needle := range []string{"sk-abcdefghijklmnopqrstuvwxyz1234", "api_key"} {
		if strings.Contains(raw, needle) {
			t.Fatalf("human decision audit event persisted %q: %s", needle, raw)
		}
	}
	if !strings.Contains(raw, "[REDACTED]") {
		t.Fatalf("human decision audit event shows no redaction marker: %s", raw)
	}
	var back AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &back); err != nil {
		t.Fatalf("redacted human decision event does not decode: %v", err)
	}
	if back.HumanDecision == nil {
		t.Fatalf("redacted human decision event lost its projection: %s", raw)
	}
	if back.Decision != nil {
		t.Fatalf("human decision was projected under the package decision keys: %s", raw)
	}
	if back.HumanDecision.RecordID != rec.ID || back.HumanDecision.Decision != string(HumanDecisionAccept) ||
		back.HumanDecision.DecisionPackageHash != rec.DecisionPackageHash ||
		back.HumanDecision.Actor != rec.Actor {
		t.Fatalf("redaction crossed the human decision projection: %+v", back.HumanDecision)
	}
	if back.Hash != hashBytes(encodeHumanDecisionOrFail(t, rec)) {
		t.Fatalf("human decision audit artifact hash = %q, want the record bytes hash", back.Hash)
	}
}
