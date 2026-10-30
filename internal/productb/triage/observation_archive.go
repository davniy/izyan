package triage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/davniy/izyan/internal/evidencetools"
)

const (
	// ObservationArchiveSchemaVersion is the current archive schema: the
	// canonical payload of every observation is stored exactly once in the
	// archive's content-addressed payload table (keyed by its sha256), and
	// each observation entry is a projection that references those bytes by
	// data_sha256. Two observations that produced identical bytes therefore
	// share one archived payload.
	ObservationArchiveSchemaVersion = "observation-archive.v2"
	// observationArchiveSchemaV1 is the historical schema: every entry
	// carried its payload inline. Such an archive stays readable as recorded
	// history — its entries keep their original meaning and are never
	// rewritten into the current shape.
	observationArchiveSchemaV1 = "observation-archive.v1"
)

// RecordedObservation is one archived observation: the hash-pinned
// projection of a tool call the run recorded. Status, completeness, scope,
// evidence refs and the scope hashes are derived projections of the payload;
// the canonical payload itself is stored once in ObservationArchive.Payloads
// and referenced here by DataSHA256. In-memory callers still read the resolved
// bytes from Payload, which ReadObservationArchive fills from the table and
// WriteObservationArchive moves into it.
type RecordedObservation struct {
	ID               string                     `json:"id"`
	Tool             string                     `json:"tool"`
	Status           string                     `json:"status"`
	Completeness     evidencetools.Completeness `json:"completeness"`
	Scope            string                     `json:"scope"`
	Payload          json.RawMessage            `json:"-"`
	DataSHA256       string                     `json:"data_sha256,omitempty"`
	EvidenceRefs     []string                   `json:"evidence_refs,omitempty"`
	Limitations      []string                   `json:"limitations,omitempty"`
	SnapshotHash     string                     `json:"snapshot_hash,omitempty"`
	BuildContextHash string                     `json:"build_context_hash,omitempty"`
	RunID            string                     `json:"run_id,omitempty"`
	Attempt          int                        `json:"attempt"`
}
type observationRecorder interface{ record(ToolObservation) }

func recordObservation(store ObservationStore, obs ToolObservation) {
	if r, ok := store.(observationRecorder); ok {
		r.record(obs)
	}
}

type ObservationStore interface{ Observations() []RecordedObservation }
type observationAttempt interface{ attemptNumber() int }

func attemptNumber(store ObservationStore) int {
	if s, ok := store.(observationAttempt); ok {
		return s.attemptNumber()
	}
	return 0
}
func observationID(prefix string, seq int, store ObservationStore) string {
	// Only retries carry an attempt-qualified id: the primary attempt keeps
	// the historical unattributed form, while every stability retry gets an
	// isolated id space so no attempt can resolve another attempt's evidence.
	if n := attemptNumber(store); n > 1 {
		return fmt.Sprintf("%s-a%d-%04d", prefix, n, seq)
	}
	return fmt.Sprintf("%s-%04d", prefix, seq)
}

type observationStore struct {
	mu           sync.Mutex
	attempt      int
	runID        string
	observations []RecordedObservation
}

// NewObservationStore returns a per-attempt store that stamps the attempt
// number on every recorded observation.
func NewObservationStore(attempt int) ObservationStore { return &observationStore{attempt: attempt} }

// NewRunObservationStore returns a per-attempt store that additionally stamps
// the owning run identity on every recorded observation, so the falsifier
// verifier can reject evidence recorded by another run.
func NewRunObservationStore(runID string, attempt int) ObservationStore {
	return &observationStore{attempt: attempt, runID: runID}
}
func (s *observationStore) attemptNumber() int { return s.attempt }

// AttemptRunID derives the deterministic run identity of one stability
// attempt: the same finding at the same attempt always gets the same id, so
// live verification and offline replay agree without extra state.
func AttemptRunID(findingID string, attempt int) string {
	return fmt.Sprintf("%s@attempt-%d", findingID, attempt)
}
func (s *observationStore) Observations() []RecordedObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RecordedObservation(nil), s.observations...)
}
func (s *observationStore) record(obs ToolObservation) {
	if obs.ID == "" {
		return
	}
	s.mu.Lock()
	for _, existing := range s.observations {
		if existing.ID == obs.ID {
			// One observation id is one canonical archive entry: a
			// repeated (cached) call re-records the same id and must not
			// mint a second binding — the per-call audit event already
			// covers the request.
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()
	payload := obs.Data
	if len(obs.archiveData) > 0 {
		payload = obs.archiveData
	}
	r := RecordedObservation{ID: obs.ID, Tool: obs.Tool, Status: obs.Status, Scope: obs.Scope, Payload: append(json.RawMessage(nil), payload...), DataSHA256: obs.DataSHA256, Limitations: append([]string(nil), obs.Limitations...), RunID: obs.RunID, Attempt: obs.Attempt}
	if r.RunID == "" {
		r.RunID = s.runID
	}
	if r.Attempt == 0 {
		r.Attempt = s.attempt
	}
	if obs.Coverage != "" {
		r.Completeness = evidencetools.Completeness(obs.Coverage)
	}
	if len(payload) > 0 {
		var raw evidencetools.Observation
		if json.Unmarshal(payload, &raw) == nil {
			r.EvidenceRefs = append([]string(nil), raw.EvidenceRefs...)
			if raw.ScopeDetails != nil {
				r.SnapshotHash = raw.ScopeDetails.SnapshotHash
				if raw.ScopeDetails.BuildContext != nil {
					b, _ := json.Marshal(raw.ScopeDetails.BuildContext)
					h := sha256.Sum256(b)
					r.BuildContextHash = hex.EncodeToString(h[:])
				}
			}
		}
	}
	if r.DataSHA256 == "" && len(r.Payload) > 0 {
		h := sha256.Sum256(r.Payload)
		r.DataSHA256 = hex.EncodeToString(h[:])
	}
	s.mu.Lock()
	for _, existing := range s.observations {
		if existing.ID == obs.ID {
			s.mu.Unlock()
			return
		}
	}
	s.observations = append(s.observations, r)
	s.mu.Unlock()
}

// ObservationArchive is the persisted archive of one run's recorded
// observations. Payloads holds every distinct canonical observation payload
// exactly once, keyed by its sha256; Observations holds the hash-pinned
// projections that reference those payloads by DataSHA256. The payload is the
// canonical record — a display or audit projection never carries it a second
// time.
type ObservationArchive struct {
	SchemaVersion string                     `json:"schema_version"`
	Payloads      map[string]json.RawMessage `json:"payloads,omitempty"`
	Observations  []RecordedObservation      `json:"observations"`
}

// observationArchiveV1 is the historical wire form: each entry carried its
// payload inline. It is read as history only.
type observationArchiveV1 struct {
	SchemaVersion string                  `json:"schema_version"`
	Observations  []recordedObservationV1 `json:"observations"`
}

// recordedObservationV1 is the historical entry: the current projection plus
// the inline payload the schema carried before the payload table existed.
type recordedObservationV1 struct {
	RecordedObservation
	Payload json.RawMessage `json:"payload,omitempty"`
}

type observationSliceStore struct{ items []RecordedObservation }

func (s observationSliceStore) Observations() []RecordedObservation {
	return append([]RecordedObservation(nil), s.items...)
}

func WriteObservationArchive(ctx context.Context, path string, store ObservationStore) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	archive := ObservationArchive{
		SchemaVersion: ObservationArchiveSchemaVersion,
		Payloads:      map[string]json.RawMessage{},
	}
	if store != nil {
		// The archive stores each observation id once: the first recorded
		// entry is canonical — a repeat (e.g. a cached call) adds an audit
		// event, never a second binding. The payload table stores each
		// distinct payload once no matter how many entries reference it.
		seen := map[string]bool{}
		for _, o := range store.Observations() {
			if o.ID != "" && seen[o.ID] {
				continue
			}
			seen[o.ID] = true
			archive.projectPayload(&o)
			archive.Observations = append(archive.Observations, o)
		}
	}
	b, err := json.MarshalIndent(archive, "", "  ")
	if err != nil {
		return fmt.Errorf("triage: encode observation archive: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".observation-archive-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return nil
}

// projectPayload moves one entry's canonical payload into the archive's
// content-addressed table and reduces the entry to a digest reference. The
// payload is stored once, in compact form, under the digest the entry names —
// so a read-then-write round trip keeps the same reference. An entry whose
// recorded digest disagrees with its bytes keeps a reference nothing
// resolves: the writer never invents a digest that would make a tampered
// record load.
func (a *ObservationArchive) projectPayload(o *RecordedObservation) {
	if len(o.Payload) == 0 {
		return
	}
	compact := compactPayload(o.Payload)
	sum := hex.EncodeToString(sha256Sum(compact))
	if o.DataSHA256 == "" {
		o.DataSHA256 = sum
	}
	if payloadDigestMatches(o.Payload, o.DataSHA256) {
		if _, ok := a.Payloads[o.DataSHA256]; !ok {
			a.Payloads[o.DataSHA256] = compact
		}
	}
	o.Payload = nil
}

func ReadObservationArchive(path string) (ObservationArchive, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ObservationArchive{}, err
	}
	var head struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return ObservationArchive{}, fmt.Errorf("triage: observation archive: %w", err)
	}
	switch head.SchemaVersion {
	case ObservationArchiveSchemaVersion:
		var a ObservationArchive
		if err := json.Unmarshal(b, &a); err != nil {
			return a, fmt.Errorf("triage: observation archive: %w", err)
		}
		if err := a.resolvePayloads(); err != nil {
			return a, err
		}
		return a, nil
	case observationArchiveSchemaV1:
		var historical observationArchiveV1
		if err := json.Unmarshal(b, &historical); err != nil {
			return ObservationArchive{}, fmt.Errorf("triage: historical observation archive: %w", err)
		}
		return historical.current()
	default:
		return ObservationArchive{}, fmt.Errorf("triage: observation archive schema %q is not %s", head.SchemaVersion, ObservationArchiveSchemaVersion)
	}
}

// resolvePayloads binds every entry to the payload its digest names and
// verifies the bytes still hash to that digest: an unresolved reference or a
// swapped payload is a read error, so no locator can resolve against
// tampered evidence.
func (a ObservationArchive) resolvePayloads() error {
	for i := range a.Observations {
		o := &a.Observations[i]
		if o.DataSHA256 == "" {
			continue
		}
		payload, ok := a.Payloads[o.DataSHA256]
		if !ok {
			return fmt.Errorf("triage: observation %s: payload %s is not archived", o.ID, o.DataSHA256)
		}
		if !payloadDigestMatches(payload, o.DataSHA256) {
			return fmt.Errorf("triage: observation %s: data hash mismatch", o.ID)
		}
		o.Payload = append(json.RawMessage(nil), payload...)
	}
	return nil
}

// payloadDigestMatches reports whether payload hashes to digest verbatim or
// after compaction. The archive is persisted with indentation, so a reloaded
// payload carries formatting whitespace the original compact marshal did not
// have; the digest always names the canonical compact bytes.
func payloadDigestMatches(payload json.RawMessage, digest string) bool {
	if digest == "" {
		return true
	}
	if hex.EncodeToString(sha256Sum(payload)) == digest {
		return true
	}
	return hex.EncodeToString(sha256Sum(compactPayload(payload))) == digest
}

// compactPayload returns the canonical compact form of a JSON payload. Bytes
// that are not valid JSON are returned unchanged, so a malformed payload still
// keeps its own digest and fails closed on the recorded comparison.
func compactPayload(payload json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if err := json.Compact(&buf, payload); err != nil {
		return append(json.RawMessage(nil), payload...)
	}
	return append(json.RawMessage(nil), buf.Bytes()...)
}

// current converts a historical v1 archive into the in-memory archive shape,
// keeping every entry's recorded inline payload and verifying it against its
// data_sha256 exactly as the v1 reader did. History is read, never upgraded.
func (h observationArchiveV1) current() (ObservationArchive, error) {
	a := ObservationArchive{
		SchemaVersion: h.SchemaVersion,
		Payloads:      map[string]json.RawMessage{},
		Observations:  make([]RecordedObservation, 0, len(h.Observations)),
	}
	for _, legacy := range h.Observations {
		o := legacy.RecordedObservation
		o.Payload = legacy.Payload
		if len(o.Payload) > 0 && !payloadDigestMatches(o.Payload, o.DataSHA256) {
			return a, fmt.Errorf("triage: observation %s: data hash mismatch", o.ID)
		}
		a.Observations = append(a.Observations, o)
	}
	return a, nil
}
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
