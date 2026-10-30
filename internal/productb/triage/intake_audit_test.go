package triage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// intakeAuditDir resolves the run directory Stage 0 artifacts were written
// into: the ticket path returns the directory from WriteStage0Artifacts,
// failures come back through WriteStage0Failure's error.json path.
func intakeAuditRead(t *testing.T, dir string) IntakeAuditDocument {
	t.Helper()
	var doc IntakeAuditDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "intake-audit.json")), &doc); err != nil {
		t.Fatalf("intake-audit.json does not parse: %v", err)
	}
	return doc
}

// TestIntakeAuditFieldsAndProvenance: a fully resolved ticket run stores a
// field-by-field audit — every intake field's status, provenance and
// risk-reduction flag — plus the source, ref, advisory, materialization
// and toolchain provenance bound to the run's hashes.
func TestIntakeAuditFieldsAndProvenance(t *testing.T) {
	in := stage0Input(t, stage0TicketText, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()

	out := t.TempDir()
	w := ArtifactWriter{Clock: replayClockA}
	dir, err := w.WriteStage0Artifacts(context.Background(), out, res)
	if err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}
	if err := WriteIntakeAudit(context.Background(), dir, res); err != nil {
		t.Fatalf("WriteIntakeAudit: %v", err)
	}

	doc := intakeAuditRead(t, dir)
	if doc.SchemaVersion != IntakeAuditSchemaVersion {
		t.Fatalf("schema_version = %q, want %s", doc.SchemaVersion, IntakeAuditSchemaVersion)
	}
	if doc.TicketHash != res.Raw.TicketHash || doc.Format != string(res.Raw.Format) || doc.RecordIndex != res.Raw.RecordIndex {
		t.Fatalf("record identity = %+v, want hash=%s format=%s index=%d", doc, res.Raw.TicketHash, res.Raw.Format, res.Raw.RecordIndex)
	}
	if doc.FindingID != res.Input.Finding.FindingID || doc.FindingID == "" {
		t.Fatalf("finding_id = %q", doc.FindingID)
	}
	if doc.ConfigHash == "" || doc.ConfigHash != res.ConfigHash {
		t.Fatalf("config_hash = %q, want %q", doc.ConfigHash, res.ConfigHash)
	}
	if doc.ProposalHash == "" {
		t.Fatal("proposal_hash is empty")
	}
	if doc.AdvisoryHash == "" || doc.SnapshotHash == "" {
		t.Fatalf("advisory/snapshot hash empty: %+v", doc)
	}
	if len(doc.Fields) == 0 {
		t.Fatal("intake audit recorded no fields")
	}
	// Field-by-field auditability: the validation verdicts land verbatim —
	// status, deterministic provenance and the risk-reduction block flag.
	byField := map[string]IntakeFieldAudit{}
	for _, f := range doc.Fields {
		byField[f.Field] = f
	}
	ids, ok := byField["vulnerability_ids"]
	if !ok || ids.Status != IntakeValid {
		t.Fatalf("vulnerability_ids field = %+v", ids)
	}
	if len(ids.Provenance) == 0 {
		t.Fatal("vulnerability_ids carries no provenance")
	}
	if _, ok := byField["severity"]; !ok {
		t.Fatal("severity field missing")
	}
	// The field table itself stores value hashes only; identifiers that are
	// themselves provenance (selected ref, claimed package) still appear in
	// the matching projection, exactly like stage0.json records them.
	if ids.ValueSHA256 == "" {
		t.Fatal("vulnerability_ids carries no value hash")
	}
	// Source provenance: the catalog entry that resolved the ticket.
	if doc.Source == nil || doc.Source.SourceID != "example-service" {
		t.Fatalf("source = %+v", doc.Source)
	}
	// Ref provenance: the bounded selection, its rule and who chose.
	if doc.Ref == nil || doc.Ref.SelectedRef != "v1.4.0" || doc.Ref.SelectedID == "" {
		t.Fatalf("ref = %+v", doc.Ref)
	}
	if doc.Ref.SelectionProvenance == "" || doc.Ref.CandidatesHash == "" || doc.Ref.ResolvedCommit == "" {
		t.Fatalf("ref audit incomplete: %+v", doc.Ref)
	}
	// Advisory freeze: every source attempt plus the frozen identity.
	if doc.Advisory == nil || doc.Advisory.SHA256 == "" || doc.Advisory.Source == "" {
		t.Fatalf("advisory = %+v", doc.Advisory)
	}
	if len(doc.Advisory.Attempts) == 0 {
		t.Fatal("advisory attempts missing")
	}
	// Materialization: mode and source identity with the pinned root hash.
	if doc.Materialization == nil || doc.Materialization.Mode == "" || doc.Materialization.RootHash == "" {
		t.Fatalf("materialization = %+v", doc.Materialization)
	}
	// Toolchain: the release-toolchain fact and the provisioned toolchain.
	if doc.Toolchain == nil {
		t.Fatal("toolchain audit missing")
	}
	// Package check result.
	if doc.PackageCheck == nil || doc.PackageCheck.Class == "" {
		t.Fatalf("package_check = %+v", doc.PackageCheck)
	}
	// Materials summary hash pins the collected set.
	if doc.Materials == nil || doc.Materials.MaterialsHash == "" {
		t.Fatalf("materials = %+v", doc.Materials)
	}
}

// TestIntakeAuditNoSecrets: a ticket carrying credential-shaped strings
// produces an audit document with identities and hashes only — neither the
// secret token nor the verbatim ticket text reaches the file.
func TestIntakeAuditNoSecrets(t *testing.T) {
	const secret = "s3cr3t-t0k3n-0001"
	ticket := `{"vulnerability": "CVE-2099-0001", "component": "service-example", "release": "v1.4.0", "severity": "high", "package": "example.org/library/parser", "version": "1.4.2", "credential": "` + secret + `"}`
	proposal := `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"component":"service-example","release":"v1.4.0","package":"example.org/library/parser","version":"1.4.2","severity":"high"}`
	in := stage0Input(t, ticket, stage0Chat(proposal, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()

	dir, err := (ArtifactWriter{Clock: replayClockA}).WriteStage0Artifacts(context.Background(), t.TempDir(), res)
	if err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}
	if err := WriteIntakeAudit(context.Background(), dir, res); err != nil {
		t.Fatalf("WriteIntakeAudit: %v", err)
	}
	raw := string(mustRead(t, filepath.Join(dir, "intake-audit.json")))
	if strings.Contains(raw, secret) {
		t.Fatal("intake-audit.json contains the credential token")
	}
	if strings.Contains(raw, `"credential"`) {
		t.Fatal("intake-audit.json contains the credential field name")
	}
	if strings.Contains(raw, string(res.Raw.Raw)) {
		t.Fatal("intake-audit.json embeds the verbatim ticket record")
	}
	var doc IntakeAuditDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.TicketHash == "" {
		t.Fatal("audit lost the ticket hash binding")
	}
}

// TestIntakeAuditPartialOnFailure: a Stage 0 run that fails still records
// the partial audit honestly — intake validation ran (so fields exist),
// the later stages carry nothing and the error is not rewritten.
func TestIntakeAuditPartialOnFailure(t *testing.T) {
	// The proposal claims a malformed id — deterministic validation marks
	// it INVALID, records the error and the resolution stops before
	// source/ref/advisory ever run.
	in := stage0Input(t, "scanner output without usable identifiers and no component", stage0Chat(
		`{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-9999"],"component":"service-example"}`, ""))
	res, err := ResolveStage0(context.Background(), in)
	if err == nil {
		defer res.Source.Cleanup()
		t.Fatal("ResolveStage0 succeeded for an id-less ticket")
	}
	out := t.TempDir()
	errPath, werr := (ArtifactWriter{Clock: replayClockA}).WriteStage0Failure(context.Background(), out, res, err)
	if werr != nil {
		t.Fatalf("WriteStage0Failure: %v", werr)
	}
	dir := filepath.Dir(errPath)
	if werr := WriteIntakeAudit(context.Background(), dir, res); werr != nil {
		t.Fatalf("WriteIntakeAudit: %v", werr)
	}
	doc := intakeAuditRead(t, dir)
	if doc.TicketHash != res.Raw.TicketHash {
		t.Fatalf("ticket_hash = %q", doc.TicketHash)
	}
	if len(doc.Errors) == 0 {
		t.Fatal("partial audit recorded no validation errors")
	}
	if doc.Advisory != nil && doc.Advisory.SHA256 != "" {
		t.Fatalf("failed run gained an advisory: %+v", doc.Advisory)
	}
	if doc.Source != nil && doc.Source.SourceID != "" {
		t.Fatalf("failed run gained a source: %+v", doc.Source)
	}
}

// TestIntakeAuditFieldStatusesPersisted: the intake_resolution audit event
// keeps the field-level verdicts (hash-only values) so the append-only log
// is auditable field-by-field exactly like the artifact.
func TestIntakeAuditFieldStatusesPersisted(t *testing.T) {
	in := stage0Input(t, stage0TicketText, stage0Chat(stage0ProposalJSON, "tag:v1.4.0"))
	res, err := ResolveStage0(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveStage0: %v", err)
	}
	defer res.Source.Cleanup()

	var ev *AuditEvent
	for i := range res.Events {
		if res.Events[i].Type == AuditEventIntakeResolution {
			ev = &res.Events[i]
		}
	}
	if ev == nil || ev.Intake == nil {
		t.Fatalf("no intake_resolution event in %+v", res.Events)
	}
	if len(ev.Intake.Fields) == 0 {
		t.Fatal("intake event carries no per-field audit")
	}
	var found bool
	for _, f := range ev.Intake.Fields {
		if f.Field == "vulnerability_ids" {
			found = f.Status == IntakeValid
			if f.ValueSHA256 == "" {
				t.Fatalf("field %s carries no value hash", f.Field)
			}
		}
	}
	if !found {
		t.Fatalf("vulnerability_ids VALID field missing: %+v", ev.Intake.Fields)
	}
	if ev.Intake.TicketHash != res.Raw.TicketHash {
		t.Fatalf("ticket_hash = %q", ev.Intake.TicketHash)
	}
}
