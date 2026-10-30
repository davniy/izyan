package vexbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OSVFetch is one observed fetch of an OSV document during advisory
// preparation — the direct request, every alias attempt, and both
// successful and rejected/errored responses. It is benchmark provenance:
// control-plane data written outside the singleton advisory directory and
// outside the snapshot.
type OSVFetch struct {
	TaskID        string `json:"task_id"`
	RequestedID   string `json:"requested_id"`
	Role          string `json:"role"` // "direct" for the task CVE, "alias" otherwise
	URL           string `json:"url"`
	StartedAtUTC  string `json:"started_at_utc"`
	FinishedAtUTC string `json:"finished_at_utc"`
	DurationMs    int64  `json:"duration_ms"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	// DocumentID is the advisory's own id field (best effort — the body may
	// not parse, e.g. an error page).
	DocumentID string `json:"document_id,omitempty"`
	// BodySHA256/BodyBytes/BodyRef describe the exact bytes handed to the
	// resolver. BodyRef points at a persisted copy under provenance/osv/ so
	// the captured bytes can be audited without a second fetch.
	BodySHA256 string `json:"body_sha256,omitempty"`
	BodyBytes  int    `json:"body_bytes,omitempty"`
	BodyRef    string `json:"body_ref,omitempty"`
	// Chosen marks the fetch whose document was saved as the advisory.
	Chosen bool `json:"chosen"`
}

// FetchRecorder wraps a Fetcher (the benchmark's real OSV transport) and
// records every fetch — request id, UTC start/finish, error and the exact
// returned body with its digest — without changing fetch order, outcome or
// the bytes the advisory resolver sees. Bodies persist under
// <provenanceDir>/osv/<sha256>.json; Flush writes the record index to
// <provenanceDir>/osv-fetches.jsonl once per task.
//
// A capture I/O failure is returned to the resolver as a fetch error —
// provenance must not silently succeed — so the caller reports the case
// failed instead of claiming recorded fetches it does not have.
type FetchRecorder struct {
	taskID   string
	cve      string
	dir      string
	inner    Fetcher
	mu       sync.Mutex
	records  []OSVFetch
	chosen   string
	flushed  bool
	flushErr error
}

// NewFetchRecorder wraps inner (nil means FetchOSV) for one task's advisory
// preparation. provenanceDir receives osv-fetches.jsonl records and the
// osv/ body files; it must be control-plane storage, never the advisory
// dir or the snapshot.
func NewFetchRecorder(taskID, cve, provenanceDir string, inner Fetcher) *FetchRecorder {
	if inner == nil {
		inner = FetchOSV
	}
	return &FetchRecorder{taskID: taskID, cve: cve, dir: provenanceDir, inner: inner}
}

// Fetch implements Fetcher.
func (r *FetchRecorder) Fetch(ctx context.Context, id string) ([]byte, error) {
	rec := OSVFetch{
		TaskID:      r.taskID,
		RequestedID: id,
		URL:         defaultOSVBaseURL + "/v1/vulns/" + canonicalOSVID(id),
	}
	if id == r.cve {
		rec.Role = "direct"
	} else {
		rec.Role = "alias"
	}
	start := time.Now()
	body, err := r.inner(ctx, id)
	finish := time.Now()
	rec.StartedAtUTC = start.UTC().Format(time.RFC3339Nano)
	rec.FinishedAtUTC = finish.UTC().Format(time.RFC3339Nano)
	rec.DurationMs = finish.Sub(start).Milliseconds()
	if err != nil {
		// Transport error: recorded verbatim, no invented HTTP status.
		rec.Error = err.Error()
		r.mu.Lock()
		r.records = append(r.records, rec)
		r.mu.Unlock()
		return nil, err
	}
	rec.OK = true
	sum := sha256.Sum256(body)
	rec.BodySHA256 = hex.EncodeToString(sum[:])
	rec.BodyBytes = len(body)
	var ident struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &ident) == nil {
		rec.DocumentID = ident.ID
	}
	// Persist the exact bytes before the resolver ever sees them.
	if capErr := r.persistBody(rec.BodySHA256, body); capErr != nil {
		rec.Error = "provenance capture: " + capErr.Error()
		r.mu.Lock()
		r.records = append(r.records, rec)
		r.mu.Unlock()
		return nil, capErr
	}
	rec.BodyRef = filepath.Join("osv", rec.BodySHA256+".json")
	r.mu.Lock()
	r.records = append(r.records, rec)
	r.mu.Unlock()
	return body, nil
}

// MarkChosen records which fetched body was saved as the advisory (its
// SHA256 from AdvisoryResult). Empty is a no-op — nothing was chosen.
func (r *FetchRecorder) MarkChosen(sha string) {
	if sha == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.records {
		if r.records[i].BodySHA256 == sha {
			r.records[i].Chosen = true
			r.chosen = sha
			return
		}
	}
	r.chosen = sha // unmatched — Flush reports it instead of dropping it
}

// Count reports how many fetch records were captured so far.
func (r *FetchRecorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

// Flush appends the task's fetch records to osv-fetches.jsonl. It runs once
// per recorder; a second call is a no-op. Concurrent Flush calls from
// different recorders targeting the same directory are serialized.
func (r *FetchRecorder) Flush() error {
	r.mu.Lock()
	if r.flushed {
		err := r.flushErr
		r.mu.Unlock()
		return err
	}
	if r.chosen != "" {
		matched := false
		for i := range r.records {
			if r.records[i].Chosen {
				matched = true
			}
		}
		if !matched {
			for i := range r.records {
				if r.records[i].BodySHA256 == r.chosen {
					r.records[i].Chosen = true
					matched = true
					break
				}
			}
		}
		if !matched {
			r.mu.Unlock()
			return fmt.Errorf("provenance: chosen advisory sha256 %s was never fetched", r.chosen)
		}
	}
	recs := append([]OSVFetch{}, r.records...)
	dir := r.dir
	r.mu.Unlock()

	if len(recs) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.setFlushErr(fmt.Errorf("provenance: create dir: %w", err))
		return r.flushErr
	}
	osvLogMu.Lock()
	defer osvLogMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, "osv-fetches.jsonl"),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		r.setFlushErr(fmt.Errorf("provenance: open fetch log: %w", err))
		return r.flushErr
	}
	for _, rec := range recs {
		line, merr := json.Marshal(rec)
		if merr != nil {
			f.Close()
			r.setFlushErr(fmt.Errorf("provenance: encode fetch record: %w", merr))
			return r.flushErr
		}
		if _, werr := f.Write(append(line, '\n')); werr != nil {
			f.Close()
			r.setFlushErr(fmt.Errorf("provenance: write fetch record: %w", werr))
			return r.flushErr
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		r.setFlushErr(fmt.Errorf("provenance: fsync fetch log: %w", err))
		return r.flushErr
	}
	if err := f.Close(); err != nil {
		r.setFlushErr(fmt.Errorf("provenance: close fetch log: %w", err))
		return r.flushErr
	}
	r.setFlushErr(nil)
	return nil
}

func (r *FetchRecorder) setFlushErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushed = true
	r.flushErr = err
}

// persistBody writes the fetched bytes under their content digest. A body
// already on disk must hold identical bytes — a mismatch is a hard capture
// error, never an overwrite.
func (r *FetchRecorder) persistBody(sha string, body []byte) error {
	bodyDir := filepath.Join(r.dir, "osv")
	if err := os.MkdirAll(bodyDir, 0o755); err != nil {
		return fmt.Errorf("create body dir: %w", err)
	}
	path := filepath.Join(bodyDir, sha+".json")
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(body) {
			return nil
		}
		return fmt.Errorf("body file %s exists with different bytes", path)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write body %s: %w", sha, err)
	}
	return nil
}

var osvLogMu sync.Mutex
