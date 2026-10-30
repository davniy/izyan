package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/flock"
)

// HumanDecisionSchemaVersion is the schema of one human-decision record.
const HumanDecisionSchemaVersion = "human-decision.v2"

// humanDecisionsDirName is the append-only collection of Accept/Reject
// records inside a run directory. Every record is its own immutable file;
// the directory is never rewritten as a whole.
const humanDecisionsDirName = "human-decisions"

// humanDecisionsLockName serializes writers of the review collection. It
// lives beside the collection so the collection itself contains only
// <record-id>.json files.
const humanDecisionsLockName = "human-decisions.lock"

// ErrHumanDecisionExists marks the refusal to overwrite an existing
// immutable review record.
var ErrHumanDecisionExists = errors.New("human decision record already exists")

// ErrHumanDecisionLockMissing marks a review collection restored without its
// required lock file. Readers never create the lock: without it the
// collection's integrity cannot be established.
var ErrHumanDecisionLockMissing = errors.New("human decision: review collection is missing its lock file")

// ErrDirectorySyncUnsupported marks a platform on which the review record's
// directory entries cannot be fsynced. The writer reports it as a durability
// failure instead of claiming an unsupported success.
var ErrDirectorySyncUnsupported = errors.New("human decision: directory sync unsupported on this platform")

// syncReviewDir is the test-seam wrapper around the platform syncDir.
func (w ArtifactWriter) syncReviewDir(path string) error {
	if w.testSyncDir != nil {
		return w.testSyncDir(path)
	}
	return syncDir(path)
}

// HumanDecision is a person's Accept/Reject of one delivered proposal. It
// is a human decision only: it is not a machine verdict, an admitted proof,
// a VEX statement, a Product A conclusion or permission to auto-close.
type HumanDecision string

const (
	HumanDecisionAccept HumanDecision = "ACCEPT"
	HumanDecisionReject HumanDecision = "REJECT"
)

// Valid reports whether d is one of the recorded human decisions.
func (d HumanDecision) Valid() bool {
	return d == HumanDecisionAccept || d == HumanDecisionReject
}

// ParseHumanDecision accepts the CLI spelling ("accept"/"reject",
// case-insensitive) and returns the canonical enum value.
func ParseHumanDecision(s string) (HumanDecision, error) {
	d := HumanDecision(strings.ToUpper(strings.TrimSpace(s)))
	if !d.Valid() {
		return "", fmt.Errorf("agenttriage: human decision: %q is not %q or %q", s, HumanDecisionAccept, HumanDecisionReject)
	}
	return d, nil
}

// HumanDecisionInput is the operator input of one recording call.
type HumanDecisionInput struct {
	Decision HumanDecision
	Actor    string
	Reason   string
	// ProjectionHash optionally pins the selected review session against
	// concurrent answer updates between presentation and recording.
	ProjectionHash string
}

// HumanDecisionRecord is one entry of human-decisions/<record-id>.json. It
// binds the person's decision to the exact canonical decision package that
// was delivered, and carries nothing that could grant machine authority.
type HumanDecisionRecord struct {
	SchemaVersion       string        `json:"schema_version"`
	ID                  string        `json:"id"`
	RunID               string        `json:"run_id"`
	FindingID           string        `json:"finding_id"`
	DecisionPackageHash string        `json:"decision_package_hash"`
	Decision            HumanDecision `json:"decision"`
	Actor               string        `json:"actor"`
	Reason              string        `json:"reason"`
	RecordedAt          time.Time     `json:"recorded_at"`
	BranchID string `json:"branch_id,omitempty"`
	ProjectionHash string `json:"projection_hash,omitempty"`
	AssertionIDs []string `json:"assertion_ids,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// UnmarshalJSON strictly rejects unknown fields: a record carrying any
// authority-capable key is malformed, never silently extended.
func (r *HumanDecisionRecord) UnmarshalJSON(data []byte) error {
	type plain HumanDecisionRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var x plain
	if err := dec.Decode(&x); err != nil {
		return err
	}
	if x.SchemaVersion == "human-decision.v1" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil { return err }
		for _, key := range []string{"branch_id", "projection_hash", "assertion_ids", "reason_code"} {
			if _, exists := fields[key]; exists { return fmt.Errorf("historical human-decision.v1: unknown field %q", key) }
		}
	}
	*r = HumanDecisionRecord(x)
	return nil
}

// humanDecisionRecordID derives the content-addressed, path-safe record id
// from the canonical record content. The id field itself is excluded.
func humanDecisionRecordID(r HumanDecisionRecord) string {
	r.ID = ""
	data, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return "hd-" + hashBytes(data)
}

// encodeHumanDecisionRecord is the exact immutable file encoding. The audit
// event hashes these bytes, so the recorded artifact hash and the file hash
// are the same value.
func encodeHumanDecisionRecord(r HumanDecisionRecord) ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func validateHumanDecisionPackage(pkg DecisionPackage) error {
	if pkg.SchemaVersion != DecisionPackageSchemaVersion {
		return unsupportedLiveSchema("decision.json", pkg.SchemaVersion, DecisionPackageSchemaVersion)
	}
	if err := pkg.Validate(); err != nil {
		return fmt.Errorf("decision package is invalid: %w", err)
	}
	return nil
}

func (r HumanDecisionRecord) validate(pkg DecisionPackage) error {
	if r.SchemaVersion != HumanDecisionSchemaVersion && r.SchemaVersion != "human-decision.v1" {
		return fmt.Errorf("unsupported human decision schema %q", r.SchemaVersion)
	}
	switch pkg.SchemaVersion {
	case DecisionPackageSchemaVersion:
		if r.SchemaVersion != HumanDecisionSchemaVersion { return errors.New("current decision package requires human-decision.v2 projection binding") }
	case "decision-package.v3":
		if r.SchemaVersion != "human-decision.v1" { return errors.New("historical decision-package.v3 requires human-decision.v1") }
	default:
		return fmt.Errorf("unsupported review package schema %q", pkg.SchemaVersion)
	}
	if r.SchemaVersion == "human-decision.v1" && (r.BranchID != "" || r.ProjectionHash != "" || len(r.AssertionIDs) != 0 || r.ReasonCode != "") { return errors.New("historical v1 record carries later branch semantics") }
	if r.SchemaVersion == HumanDecisionSchemaVersion && (r.ProjectionHash == "" || r.ReasonCode != "HUMAN_"+string(r.Decision)) { return errors.New("invalid v2 projection binding or reason code") }
	if strings.TrimSpace(r.ID) == "" || r.ID != humanDecisionRecordID(r) {
		return fmt.Errorf("record id %q does not match the canonical record content", r.ID)
	}
	if r.RunID == "" || r.RunID != pkg.RunID {
		return fmt.Errorf("record run_id %q does not match the decision package run %q", r.RunID, pkg.RunID)
	}
	if r.FindingID == "" || r.FindingID != pkg.FindingID {
		return fmt.Errorf("record finding_id %q does not match the decision package finding %q", r.FindingID, pkg.FindingID)
	}
	if want := canonicalDecisionHash(pkg); r.DecisionPackageHash != want {
		return fmt.Errorf("record decision_package_hash %q does not match the decision package hash %q", r.DecisionPackageHash, want)
	}
	if !r.Decision.Valid() {
		return fmt.Errorf("record decision %q is not %q or %q", r.Decision, HumanDecisionAccept, HumanDecisionReject)
	}
	if strings.TrimSpace(r.Actor) == "" {
		return errors.New("record actor is required")
	}
	if r.SchemaVersion == "human-decision.v1" && strings.TrimSpace(r.Reason) == "" {
		return errors.New("record reason is required")
	}
	if r.RecordedAt.IsZero() {
		return errors.New("record recorded_at is required")
	}
	if _, offset := r.RecordedAt.Zone(); offset != 0 {
		return fmt.Errorf("record recorded_at %s is not UTC", r.RecordedAt.Format(time.RFC3339Nano))
	}
	return nil
}

// humanDecisionFile is one verified record plus the exact bytes read from
// disk. Replay copies Bytes verbatim; it never re-encodes or re-stamps a
// historical decision.
type humanDecisionFile struct {
	Record HumanDecisionRecord
	Bytes  []byte
}

// readHumanDecisionFiles loads every record in the run's append-only review
// collection and binds it to pkg. Missing history is valid; malformed,
// foreign or partially written history is a technical error.
func readHumanDecisionFiles(runDir string, pkg DecisionPackage) ([]humanDecisionFile, error) {
	return readHumanDecisionFilesSchema(runDir, pkg, DecisionPackageSchemaVersion)
}

// readHumanDecisionFilesSchema is replay-only for original historical bytes.
func readHumanDecisionFilesSchema(runDir string, pkg DecisionPackage, schemaVersion string) ([]humanDecisionFile, error) {
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return nil, errors.New("human decision: empty run directory")
	}
	if err := pkg.validateSchema(schemaVersion); err != nil {
		return nil, fmt.Errorf("human decision: %w", err)
	}
	recordsDir := filepath.Join(dir, humanDecisionsDirName)
	if _, statErr := os.Stat(recordsDir); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("human decision: inspect %s: %w", recordsDir, statErr)
	}
	// Readers take a non-creating shared lock: a writer publishes the record
	// name before writing its bytes, so an unlocked read could observe a
	// valid run as a partial record. The lock file must already exist; a
	// restored collection without it is an integrity error, never an
	// invitation to create one in the source run.
	lockPath := filepath.Join(dir, humanDecisionsLockName)
	unlock, err := flock.Shared(lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("human decision: %s exists but %s is missing: %w", recordsDir, humanDecisionsLockName, ErrHumanDecisionLockMissing)
		}
		return nil, fmt.Errorf("human decision: lock review collection %s: %w", lockPath, err)
	}
	defer unlock()
	assertionFiles, assertionErr := readEnvironmentAssertionFilesUnlocked(dir, pkg)
	if assertionErr != nil { return nil, assertionErr }
	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		return nil, fmt.Errorf("human decision: read %s: %w", recordsDir, err)
	}
	files := make([]humanDecisionFile, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("human decision: %q in the review collection is not a regular record file", name)
		}
		if !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("human decision: unexpected file %q in the review collection", name)
		}
		data, err := os.ReadFile(filepath.Join(recordsDir, name))
		if err != nil {
			return nil, fmt.Errorf("human decision: read %s: %w", name, err)
		}
		var rec HumanDecisionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("human decision: %s does not parse: %w", name, err)
		}
		if err := rec.validate(pkg); err != nil {
			return nil, fmt.Errorf("human decision: %s: %w", name, err)
		}
		if rec.SchemaVersion == HumanDecisionSchemaVersion {
			if err := validateReviewProjection(rec, pkg, assertionFiles); err != nil { return nil, fmt.Errorf("human decision: %s: %w", name, err) }
		}
		if want := rec.ID + ".json"; name != want {
			return nil, fmt.Errorf("human decision: file name %q does not match record id %q", name, rec.ID)
		}
		files = append(files, humanDecisionFile{Record: rec, Bytes: data})
	}
	sort.Slice(files, func(i, j int) bool {
		a, b := files[i].Record, files[j].Record
		if a.RecordedAt.Equal(b.RecordedAt) {
			return a.ID < b.ID
		}
		return a.RecordedAt.Before(b.RecordedAt)
	})
	return files, nil
}

// ReadHumanDecisions returns the verified append-only review history of one
// decision package, in recorded order. Multiple records are history, not
// input to a "latest decision wins" machine policy: nothing here changes
// the machine disposition or the package.
func ReadHumanDecisions(runDir string, pkg DecisionPackage) ([]HumanDecisionRecord, error) {
	files, err := readHumanDecisionFiles(runDir, pkg)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	out := make([]HumanDecisionRecord, len(files))
	for i, f := range files {
		out[i] = f.Record
	}
	return out, nil
}

// WriteHumanDecision records one person's Accept/Reject of the exact
// decision package currently delivered in runDir. The record is a new
// immutable file under human-decisions/<record-id>.json, created under the
// collection's portable flock and fsynced before success is returned. The
// decision package, card, assessment, proofs and policy material are only
// read; they are never rewritten.
//
// The immutable record is the primary persistence result. An audit-append
// failure is reported together with the persisted path and record; the
// record is not deleted and the failed audit is never retried as a new
// decision.
func (w ArtifactWriter) WriteHumanDecision(ctx context.Context, runDir string, in HumanDecisionInput) (HumanDecisionRecord, string, error) {
	var rec HumanDecisionRecord
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return rec, "", err
	}
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return rec, "", errors.New("agenttriage: human decision: empty run directory")
	}
	decision, err := ParseHumanDecision(string(in.Decision))
	if err != nil {
		return rec, "", err
	}
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		return rec, "", errors.New("agenttriage: human decision: actor is required")
	}
	reason := strings.TrimSpace(in.Reason)
	// The optional reason is a comment, not a request for technical research.
	pkg, err := loadCurrentDecisionPackage(dir)
	if err != nil {
		return rec, "", fmt.Errorf("agenttriage: human decision: %w", err)
	}
	stamp := w.now().UTC()
	rec = HumanDecisionRecord{
		SchemaVersion:       HumanDecisionSchemaVersion,
		RunID:               pkg.RunID,
		FindingID:           pkg.FindingID,
		DecisionPackageHash: canonicalDecisionHash(pkg),
		Decision:            decision,
		Actor:               actor,
		Reason:              reason,
		RecordedAt:          stamp,
	}
	unlockProjection, err := flock.Exclusive(filepath.Join(dir, humanDecisionsLockName), 0o600)
	if err != nil { return rec, "", err }
	defer unlockProjection()
	assertionFiles, err := readEnvironmentAssertionFilesUnlocked(dir, pkg)
	if err != nil { return rec, "", err }
	var assertions []EnvironmentAssertion
	for _, file := range assertionFiles { assertions = append(assertions, file.Assertion) }
	projection, err := ApplyEnvironmentAssertions(pkg, assertions)
	if err != nil { return rec, "", err }
	if in.ProjectionHash != "" && in.ProjectionHash != projection.ProjectionHash { return rec, "", errors.New("human review projection changed since branch selection") }
	if projection.Status == HumanBranchAwaitingInput { return rec, "", errors.New("environment answers are required before Accept/Reject") }
	rec.BranchID, rec.ProjectionHash, rec.AssertionIDs = projection.BranchID, projection.ProjectionHash, projection.AssertionIDs
	rec.ReasonCode = "HUMAN_" + string(decision)
	rec.ID = humanDecisionRecordID(rec)
	if err := validateReviewProjection(rec, pkg, assertionFiles); err != nil { return rec, "", err }
	if rec.ID == "" {
		return rec, "", errors.New("agenttriage: human decision: cannot derive a record id")
	}
	data, err := encodeHumanDecisionRecord(rec)
	if err != nil {
		return rec, "", fmt.Errorf("agenttriage: human decision: encode record: %w", err)
	}

	path, err := w.appendReviewRecord(ctx, dir, humanDecisionsDirName, rec.ID, data)
	if err != nil { return rec, path, err }

	// The immutable record is already persisted. An audit failure is
	// reported with the record path; it never deletes the decision and is
	// never retried as a new one.
	if err := appendAuditLog(ctx, filepath.Join(dir, "audit", "events.jsonl"),
		[]AuditEvent{HumanDecisionAuditEvent(rec, rec.RecordedAt)}, rec.RunID, rec.RecordedAt); err != nil {
		return rec, path, fmt.Errorf("agenttriage: human decision %s persisted at %s but the audit append failed: %w", rec.ID, path, err)
	}
	return rec, path, nil
}
