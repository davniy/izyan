package vexbench_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/eval/vexbench"
)

// readOSVLog loads the persisted fetch records, verifying each line is an
// independently parseable JSON object (append concurrency safety).
func readOSVLog(t *testing.T, provDir string) []vexbench.OSVFetch {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(provDir, "osv-fetches.jsonl"))
	if err != nil {
		t.Fatalf("read fetch log: %v", err)
	}
	var recs []vexbench.OSVFetch
	for i, line := range splitLines(string(data)) {
		var rec vexbench.OSVFetch
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("fetch log line %d does not parse: %v", i+1, err)
		}
		recs = append(recs, rec)
	}
	return recs
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func mustFetchTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("bad timestamp %q: %v", s, err)
	}
	return ts
}

func TestFetchRecorderCapturesUsedBytes(t *testing.T) {
	advDir := t.TempDir()
	provDir := t.TempDir()
	rec := vexbench.NewFetchRecorder("task-1", "CVE-2099-0001", provDir, fixtureFetcher)

	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0001", advDir, rec.Fetch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable {
		t.Fatalf("outcome=%v want usable", res.Outcome)
	}
	rec.MarkChosen(res.SHA256)
	if err := rec.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rec.Count() != 1 {
		t.Fatalf("records=%d want 1 — recording must not add fetches", rec.Count())
	}

	recs := readOSVLog(t, provDir)
	if len(recs) != 1 {
		t.Fatalf("log lines=%d want 1", len(recs))
	}
	r := recs[0]
	if r.Role != "direct" || r.RequestedID != "CVE-2099-0001" || !r.OK || !r.Chosen {
		t.Fatalf("bad direct record: %+v", r)
	}
	if r.DocumentID != "CVE-2099-0001" {
		t.Fatalf("document_id=%q", r.DocumentID)
	}
	if r.URL != "https://api.osv.dev/v1/vulns/CVE-2099-0001" {
		t.Fatalf("url=%q", r.URL)
	}
	// The persisted body must be byte-identical to what the resolver saved.
	bodyFile, err := os.ReadFile(filepath.Join(provDir, "osv", r.BodySHA256+".json"))
	if err != nil {
		t.Fatalf("body file missing: %v", err)
	}
	used, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(bodyFile) != string(used) {
		t.Fatal("captured body differs from the bytes saved as the advisory")
	}
	if r.BodyBytes != len(used) || r.BodySHA256 != res.SHA256 {
		t.Fatalf("digest mismatch: record %+v vs saved sha %s", r, res.SHA256)
	}
	// Timestamps are real fetch wall-clock — never the advisory's own
	// "modified" field.
	if res.Modified == "" {
		t.Fatal("expected advisory modified to be captured")
	}
	start := mustFetchTime(t, r.StartedAtUTC)
	finish := mustFetchTime(t, r.FinishedAtUTC)
	if finish.Before(start) {
		t.Fatal("finish before start")
	}
	if got := start.Format("2006-01-02"); got == res.Modified[:10] {
		t.Fatalf("fetch start %q implausibly equals advisory modified %q", r.StartedAtUTC, res.Modified)
	}
	// The fetch log is control-plane data: it must not appear inside the
	// singleton advisory directory.
	if n := len(dirEntries(t, advDir)); n != 1 {
		t.Fatalf("advisory dir must hold exactly one file, got %d", n)
	}
}

func TestFetchRecorderRejectedAndAliasFetches(t *testing.T) {
	// CVE-2099-0003 is unusable; its GO-* alias is saved. Both fetches must
	// be recorded — rejected bodies are provenance too.
	advDir := t.TempDir()
	provDir := t.TempDir()
	var calls []string
	fetch := func(ctx context.Context, id string) ([]byte, error) {
		calls = append(calls, id)
		return fixtureFetcher(ctx, id)
	}
	rec := vexbench.NewFetchRecorder("task-3", "CVE-2099-0003", provDir, fetch)

	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0003", advDir, rec.Fetch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryUsable || res.Resolved != "GO-2099-0003" {
		t.Fatalf("outcome=%v resolved=%q — recording changed resolution", res.Outcome, res.Resolved)
	}
	rec.MarkChosen(res.SHA256)
	if err := rec.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// No additional fetch was issued by the recorder.
	if len(calls) != 2 {
		t.Fatalf("fetch calls=%v want exactly [direct, alias]", calls)
	}

	recs := readOSVLog(t, provDir)
	if len(recs) != 2 {
		t.Fatalf("log lines=%d want 2 (direct + alias)", len(recs))
	}
	direct, alias := recs[0], recs[1]
	if direct.Role != "direct" || direct.Chosen {
		t.Fatalf("direct record wrong: %+v", direct)
	}
	if direct.BodySHA256 == "" || direct.BodyRef == "" {
		t.Fatal("rejected direct fetch must keep its body for audit")
	}
	if alias.Role != "alias" || !alias.Chosen || alias.RequestedID != "GO-2099-0003" {
		t.Fatalf("alias record wrong: %+v", alias)
	}
	// Both bodies persisted under their own digests.
	for _, r := range recs {
		if _, err := os.Stat(filepath.Join(provDir, r.BodyRef)); err != nil {
			t.Fatalf("body file %s missing: %v", r.BodyRef, err)
		}
	}
}

func TestFetchRecorderTransportErrorRecorded(t *testing.T) {
	// CVE-2099-0008 has no fixture — the fetch fails; the record keeps the
	// real transport error and no invented status or body.
	advDir := t.TempDir()
	provDir := t.TempDir()
	rec := vexbench.NewFetchRecorder("task-e", "CVE-2099-0008", provDir, fixtureFetcher)

	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0008", advDir, rec.Fetch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryError {
		t.Fatalf("outcome=%v want error", res.Outcome)
	}
	if err := rec.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readOSVLog(t, provDir)
	if len(recs) != 1 || recs[0].OK || recs[0].Error == "" || recs[0].BodySHA256 != "" {
		t.Fatalf("transport-error record wrong: %+v", recs)
	}
	if recs[0].Chosen {
		t.Fatal("errored fetch must not be marked chosen")
	}
}

func TestFetchRecorderCaptureIOFailureIsExplicit(t *testing.T) {
	// The provenance directory cannot be created (a file sits in its
	// place): the fetch must surface a capture error to the resolver, and
	// the outcome must be error — never a silent unrecorded success.
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0001",
		t.TempDir(), vexbench.NewFetchRecorder("task-io", "CVE-2099-0001", filepath.Join(blocker, "prov"), fixtureFetcher).Fetch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != vexbench.AdvisoryError {
		t.Fatalf("capture failure must fail the preparation, got %v", res.Outcome)
	}
}

func TestFetchRecorderFlushFailureIsExplicit(t *testing.T) {
	// Bodies persist but the log file cannot be created: Flush reports it.
	parent := t.TempDir()
	provDir := filepath.Join(parent, "prov")
	if err := os.MkdirAll(filepath.Join(provDir, "osv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(provDir, "osv-fetches.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := vexbench.NewFetchRecorder("task-fl", "CVE-2099-0001", provDir, fixtureFetcher)
	res, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0001", t.TempDir(), rec.Fetch)
	if err != nil {
		t.Fatal(err)
	}
	rec.MarkChosen(res.SHA256)
	if err := rec.Flush(); err == nil {
		t.Fatal("flush must report the failed log write")
	}
}

func TestFetchRecorderConcurrentFlush(t *testing.T) {
	// Parallel workers share the provenance directory: concurrent flushes
	// must not interleave or lose lines.
	provDir := t.TempDir()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cve := fmt.Sprintf("CVE-2099-%04d", i+1)
			rec := vexbench.NewFetchRecorder(fmt.Sprintf("task-%d", i), cve, provDir, fixtureFetcher)
			res, err := vexbench.PrepareAdvisory(context.Background(), cve, t.TempDir(), rec.Fetch)
			if err != nil {
				t.Error(err)
				return
			}
			rec.MarkChosen(res.SHA256)
			if err := rec.Flush(); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	recs := readOSVLog(t, provDir)
	if len(recs) == 0 {
		t.Fatal("no records flushed")
	}
	byTask := map[string]int{}
	for _, r := range recs {
		byTask[r.TaskID]++
	}
	for i := range 4 {
		if byTask[fmt.Sprintf("task-%d", i)] == 0 {
			t.Fatalf("task-%d records lost: %v", i, recs)
		}
	}
}

func TestFetchRecorderUnmatchedChosenFails(t *testing.T) {
	rec := vexbench.NewFetchRecorder("task-u", "CVE-2099-0001", t.TempDir(), fixtureFetcher)
	if _, err := vexbench.PrepareAdvisory(context.Background(), "CVE-2099-0001", t.TempDir(), rec.Fetch); err != nil {
		t.Fatal(err)
	}
	rec.MarkChosen("0000000000000000000000000000000000000000000000000000000000000000")
	if err := rec.Flush(); err == nil {
		t.Fatal("flush must fail when the chosen digest was never fetched")
	}
}
