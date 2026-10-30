package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/flock"
)

// humanDecisionFixture records one complete decision-bearing run and returns
// its validated package: the binding target every review record must name.
func humanDecisionFixture(t *testing.T) (replayFixture, DecisionPackage) {
	t.Helper()
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	pkg, err := ValidateDecisionPackageJSON(mustRead(t, filepath.Join(f.runDir, "decision.json")))
	if err != nil {
		t.Fatalf("recorded decision.json: %v", err)
	}
	return f, pkg
}

func recordHumanDecision(t *testing.T, runDir string, clock func() time.Time, decision HumanDecision, actor, reason string) (HumanDecisionRecord, string) {
	t.Helper()
	rec, path, err := (ArtifactWriter{Clock: clock}).WriteHumanDecision(
		context.Background(), runDir,
		HumanDecisionInput{Decision: decision, Actor: actor, Reason: reason},
	)
	if err != nil {
		t.Fatalf("WriteHumanDecision(%s): %v", decision, err)
	}
	return rec, path
}

func humanDecisionRecordDir(runDir string) string {
	return filepath.Join(runDir, humanDecisionsDirName)
}

// TestHumanDecisionPackageBinding: an Accept/Reject record binds to the
// exact canonical decision package it was recorded against — its identity,
// finding and canonical hash — and a replaced or foreign package is never
// matched to the old record.
func TestHumanDecisionPackageBinding(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	rec, path := recordHumanDecision(t, f.runDir, replayClockA, HumanDecisionAccept, "alice", "reviewed the recorded build graph")

	if rec.SchemaVersion != HumanDecisionSchemaVersion {
		t.Fatalf("record schema = %q, want %q", rec.SchemaVersion, HumanDecisionSchemaVersion)
	}
	if rec.RunID != pkg.RunID || rec.FindingID != pkg.FindingID {
		t.Fatalf("record identity = (%q, %q), want (%q, %q)", rec.RunID, rec.FindingID, pkg.RunID, pkg.FindingID)
	}
	if want := canonicalDecisionHash(pkg); rec.DecisionPackageHash != want {
		t.Fatalf("decision_package_hash = %q, want canonical package hash %q", rec.DecisionPackageHash, want)
	}
	if rec.Decision != HumanDecisionAccept || rec.Actor != "alice" || rec.Reason != "reviewed the recorded build graph" {
		t.Fatalf("record content = %+v", rec)
	}
	if !rec.RecordedAt.Equal(replayClockA()) {
		t.Fatalf("recorded_at = %s, want the writer clock %s", rec.RecordedAt, replayClockA())
	}
	if !strings.HasPrefix(rec.ID, "hd-") || strings.ContainsAny(rec.ID, `/\`) {
		t.Fatalf("record id %q is not a safe content-derived id", rec.ID)
	}
	if got, want := path, filepath.Join(humanDecisionRecordDir(f.runDir), rec.ID+".json"); got != want {
		t.Fatalf("record path = %q, want %q", got, want)
	}
	if got := filepath.Base(path); got != rec.ID+".json" {
		t.Fatalf("record file name = %q, want content id %q", got, rec.ID)
	}

	history, err := ReadHumanDecisions(f.runDir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions: %v", err)
	}
	if len(history) != 1 || !jsonEqual(history[0], rec) {
		t.Fatalf("history = %+v, want the single recorded decision %+v", history, rec)
	}

	// A different package never validates against the recorded history —
	// the record names the exact package it was made against.
	other := pkg
	other.Judgment.Summary = "a different conclusion recorded after the review"
	if _, err := ReadHumanDecisions(f.runDir, other); err == nil {
		t.Fatal("a foreign package matched the recorded decision")
	} else if !strings.Contains(err.Error(), "decision_package_hash") {
		t.Fatalf("foreign package error does not name the package binding: %v", err)
	}

	// Replacing decision.json in the run directory does not re-bind the
	// existing record to the replacement.
	dir := copyRunDir(t, f.runDir)
	rewriteDecision(t, dir, func(p *DecisionPackage) {
		p.Judgment.Summary = "replaced after the human review"
	})
	replaced, err := ValidateDecisionPackageJSON(mustRead(t, filepath.Join(dir, "decision.json")))
	if err != nil {
		t.Fatalf("replaced decision.json: %v", err)
	}
	if _, err := ReadHumanDecisions(dir, replaced); err == nil {
		t.Fatal("a replaced decision package re-bound the old human decision")
	}
}

// TestHumanDecisionAppendOnly: every Accept/Reject is a new immutable file;
// later decisions neither rewrite an earlier record nor any delivered
// artifact, and a duplicate record id is refused instead of overwritten.
func TestHumanDecisionAppendOnly(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	protected := map[string][]byte{}
	for _, name := range []string{"decision.json", "decision.md", "assessment.json", "fact-gate.json"} {
		protected[filepath.Join(f.runDir, name)] = mustRead(t, filepath.Join(f.runDir, name))
	}

	accept, acceptPath := recordHumanDecision(t, f.runDir, replayClockA, HumanDecisionAccept, "alice", "the recorded build graph is complete")
	acceptBytes := append([]byte(nil), mustRead(t, acceptPath)...)
	reject, rejectPath := recordHumanDecision(t, f.runDir, replayClockB, HumanDecisionReject, "bob", "deployment evidence is still missing")
	thirdClock := func() time.Time { return replayClockB().Add(time.Hour) }
	third, thirdPath := recordHumanDecision(t, f.runDir, thirdClock, HumanDecisionAccept, "alice", "a second pass on the same proposal")

	if acceptPath == rejectPath || rejectPath == thirdPath || acceptPath == thirdPath {
		t.Fatalf("decisions overwrote one another: %s %s %s", acceptPath, rejectPath, thirdPath)
	}
	if !bytes.Equal(acceptBytes, mustRead(t, acceptPath)) {
		t.Fatal("a later decision rewrote the first record")
	}

	// Repeating an identical record (same clock and content) is refused:
	// the existing immutable file is never overwritten.
	_, dupPath, err := (ArtifactWriter{Clock: replayClockA}).WriteHumanDecision(
		context.Background(), f.runDir,
		HumanDecisionInput{Decision: HumanDecisionAccept, Actor: "alice", Reason: "the recorded build graph is complete"},
	)
	if err == nil {
		t.Fatal("an identical record was accepted twice")
	}
	if dupPath != "" {
		t.Fatalf("a refused duplicate returned a record path %q", dupPath)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate error does not report the existing record: %v", err)
	}
	if !bytes.Equal(acceptBytes, mustRead(t, acceptPath)) {
		t.Fatal("a duplicate attempt modified the existing record")
	}

	entries, err := os.ReadDir(humanDecisionRecordDir(f.runDir))
	if err != nil {
		t.Fatalf("read record directory: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("record count = %d, want 3", len(entries))
	}

	history, err := ReadHumanDecisions(f.runDir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history = %d records, want 3", len(history))
	}
	if history[0].ID != accept.ID || history[1].ID != reject.ID || history[2].ID != third.ID {
		t.Fatalf("history order = %s, %s, %s; want recorded order", history[0].ID, history[1].ID, history[2].ID)
	}
	if history[0].RecordedAt.After(history[1].RecordedAt) || history[1].RecordedAt.After(history[2].RecordedAt) {
		t.Fatalf("history is not chronological: %+v", history)
	}

	for path, before := range protected {
		if !bytes.Equal(before, mustRead(t, path)) {
			t.Fatalf("%s changed after recording human decisions", filepath.Base(path))
		}
	}
}

// TestHumanDecisionConcurrentAppend: concurrent Accept/Reject writers all
// land as distinct immutable records under the collection lock, and an
// identical concurrent record is created exactly once.
func TestHumanDecisionConcurrentAppend(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	writer := ArtifactWriter{Clock: replayClockA}
	const n = 8

	records := make([]HumanDecisionRecord, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			decision := HumanDecisionAccept
			if i%2 == 1 {
				decision = HumanDecisionReject
			}
			records[i], _, errs[i] = writer.WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{
				Decision: decision, Actor: "alice", Reason: fmt.Sprintf("concurrent review %d", i),
			})
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent writer %d: %v", i, err)
		}
	}
	seen := map[string]bool{}
	for _, rec := range records {
		if rec.ID == "" || seen[rec.ID] {
			t.Fatalf("concurrent records share or lack an id: %+v", records)
		}
		seen[rec.ID] = true
	}
	history, err := ReadHumanDecisions(f.runDir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions: %v", err)
	}
	if len(history) != n {
		t.Fatalf("history = %d records, want %d", len(history), n)
	}

	// Identical content under the same clock is one record: the lock and
	// O_EXCL creation keep the file immutable even under a race.
	const dupN = 6
	var mu sync.Mutex
	success, duplicates := 0, 0
	var unexpected []error
	var dupWG sync.WaitGroup
	startDup := make(chan struct{})
	for range dupN {
		dupWG.Add(1)
		go func() {
			defer dupWG.Done()
			<-startDup
			_, path, err := writer.WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{
				Decision: HumanDecisionReject, Actor: "bob", Reason: "identical concurrent decision",
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
				if path == "" {
					unexpected = append(unexpected, errors.New("successful record returned no path"))
				}
			case strings.Contains(err.Error(), "already exists"):
				duplicates++
			default:
				unexpected = append(unexpected, err)
			}
		}()
	}
	close(startDup)
	dupWG.Wait()
	if len(unexpected) > 0 {
		t.Fatalf("unexpected concurrent duplicate errors: %v", unexpected)
	}
	if success != 1 || duplicates != dupN-1 {
		t.Fatalf("identical concurrent writers: %d created, %d refused; want 1 and %d", success, duplicates, dupN-1)
	}
	history, err = ReadHumanDecisions(f.runDir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions after duplicate race: %v", err)
	}
	if len(history) != n+1 {
		t.Fatalf("history after duplicate race = %d records, want %d", len(history), n+1)
	}
}

// TestHumanDecisionReaderWaitsForWriter: the record name is published
// before its bytes are written, so a reader that did not take the collection
// lock could observe an empty file and reject a valid run. Readers share the
// writer's lock and therefore see the completed record.
func TestHumanDecisionReaderWaitsForWriter(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	created := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	writer := ArtifactWriter{
		Clock: replayClockA,
		testAfterHumanDecisionCreate: func() {
			once.Do(func() { close(created) })
			<-release
		},
	}
	type writeResult struct {
		rec  HumanDecisionRecord
		path string
		err  error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		rec, path, err := writer.WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{
			Decision: HumanDecisionAccept, Actor: "alice", Reason: "reviewed while a reader waited",
		})
		writeDone <- writeResult{rec: rec, path: path, err: err}
	}()
	<-created

	type readResult struct {
		recs []HumanDecisionRecord
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		recs, err := ReadHumanDecisions(f.runDir, pkg)
		readDone <- readResult{recs: recs, err: err}
	}()
	select {
	case got := <-readDone:
		t.Fatalf("reader completed while the writer held the collection lock (partial record): %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)

	wr := <-writeDone
	if wr.err != nil {
		t.Fatalf("writer: %v", wr.err)
	}
	rr := <-readDone
	if rr.err != nil {
		t.Fatalf("reader after the writer released the lock: %v", rr.err)
	}
	if len(rr.recs) != 1 || rr.recs[0].ID != wr.rec.ID {
		t.Fatalf("reader history = %+v, want the completed record %s", rr.recs, wr.rec.ID)
	}
}

// TestHumanDecisionMissingLockRejected: a review collection restored without
// its lock is an integrity error. The reader must not create the missing
// lock or otherwise mutate the source run.
func TestHumanDecisionMissingLockRejected(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	recordHumanDecision(t, f.runDir, replayClockA, HumanDecisionAccept, "alice", "recorded before the lock was lost")
	lockPath := filepath.Join(f.runDir, humanDecisionsLockName)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	before := hashTree(t, f.runDir)

	_, err := ReadHumanDecisions(f.runDir, pkg)
	if err == nil || !errors.Is(err, ErrHumanDecisionLockMissing) {
		t.Fatalf("missing lock error = %v, want ErrHumanDecisionLockMissing", err)
	}
	if !strings.Contains(err.Error(), humanDecisionsLockName) {
		t.Fatalf("missing lock error does not name the required lock file: %v", err)
	}
	if _, statErr := os.Stat(lockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the reader recreated the missing lock file: %v", statErr)
	}
	after := hashTree(t, f.runDir)
	for name, sum := range before {
		if after[name] != sum {
			t.Fatalf("reader modified source file %s despite the missing lock", name)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("reader changed the source file count: %d -> %d", len(before), len(after))
	}
}

// TestHumanDecisionReadOnlyLock: readers open the lock read-only, so a lock
// file without write permission (and a collection directory without write
// permission) is still readable. A platform without a shared lock reports
// its explicit limitation instead of silently reading unlocked.
func TestHumanDecisionReadOnlyLock(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	rec, _ := recordHumanDecision(t, f.runDir, replayClockA, HumanDecisionAccept, "alice", "read through a read-only lock")
	lockPath := filepath.Join(f.runDir, humanDecisionsLockName)
	recordsDir := humanDecisionRecordDir(f.runDir)
	if err := os.Chmod(lockPath, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(recordsDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(recordsDir, 0o755)
		_ = os.Chmod(lockPath, 0o600)
	})

	history, err := ReadHumanDecisions(f.runDir, pkg)
	if err != nil {
		if errors.Is(err, flock.ErrUnsupported) {
			t.Skipf("shared read lock is unsupported on this platform: %v", err)
		}
		t.Fatalf("read-only lock was not readable: %v", err)
	}
	if len(history) != 1 || history[0].ID != rec.ID {
		t.Fatalf("read-only lock history = %+v, want the recorded decision %s", history, rec.ID)
	}
}

// TestHumanDecisionDirectorySyncFailure: the record file and its collection
// directory entry are both made durable before success is reported. A
// directory-sync failure after the record bytes landed keeps the complete
// record, returns its path with an honest error and never retries it as a
// new decision.
func TestHumanDecisionDirectorySyncFailure(t *testing.T) {
	t.Run("collection sync preserves the record", func(t *testing.T) {
		f, pkg := humanDecisionFixture(t)
		recordsDir := humanDecisionRecordDir(f.runDir)
		writer := ArtifactWriter{
			Clock: replayClockA,
			testSyncDir: func(path string) error {
				if path == recordsDir {
					return errors.New("injected review directory sync failure")
				}
				return syncDir(path)
			},
		}
		rec, path, err := writer.WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{
			Decision: HumanDecisionAccept, Actor: "alice", Reason: "directory sync will fail",
		})
		if err == nil || !strings.Contains(err.Error(), "review directory sync") {
			t.Fatalf("directory sync failure = %v, want an honest review-directory sync error", err)
		}
		if rec.ID == "" || path == "" {
			t.Fatalf("sync failure did not report the persisted record: rec=%+v path=%q", rec, path)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("the complete record was treated as a partial file: %v", statErr)
		}
		history, rerr := ReadHumanDecisions(f.runDir, pkg)
		if rerr != nil {
			t.Fatalf("persisted record is unreadable: %v", rerr)
		}
		if len(history) != 1 || history[0].ID != rec.ID {
			t.Fatalf("history after sync failure = %+v", history)
		}
		audit := string(mustRead(t, filepath.Join(f.runDir, "audit", "events.jsonl")))
		if strings.Contains(audit, `"type":"human_decision"`) {
			t.Fatalf("a non-durable record was announced in the audit log: %s", audit)
		}
	})

	t.Run("parent sync failure aborts before the record", func(t *testing.T) {
		f, _ := humanDecisionFixture(t)
		writer := ArtifactWriter{
			Clock: replayClockA,
			testSyncDir: func(path string) error {
				if path == f.runDir {
					return errors.New("injected run-directory sync failure")
				}
				return syncDir(path)
			},
		}
		_, path, err := writer.WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{
			Decision: HumanDecisionReject, Actor: "bob", Reason: "parent sync will fail",
		})
		if err == nil || !strings.Contains(err.Error(), "sync run directory") {
			t.Fatalf("parent sync failure = %v, want a run-directory sync error", err)
		}
		if path != "" {
			t.Fatalf("parent sync failure returned a record path %q", path)
		}
		entries, rerr := os.ReadDir(humanDecisionRecordDir(f.runDir))
		if rerr == nil && len(entries) != 0 {
			t.Fatalf("parent sync failure left records behind: %v", entries)
		}
		audit := string(mustRead(t, filepath.Join(f.runDir, "audit", "events.jsonl")))
		if strings.Contains(audit, `"type":"human_decision"`) {
			t.Fatalf("parent sync failure announced a record: %s", audit)
		}
	})
}

// TestHumanDecisionNeverChangesMachineDisposition: recording a person's
// decision leaves the delivered package, judgment, support, proofs and
// machine reduction byte-identical. The record has no machine, proof or
// VEX fields, so an Accept cannot become a machine-safe result.
func TestHumanDecisionNeverChangesMachineDisposition(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	protected := map[string][]byte{}
	for _, name := range []string{"decision.json", "decision.md", "assessment.json"} {
		protected[filepath.Join(f.runDir, name)] = mustRead(t, filepath.Join(f.runDir, name))
	}
	machineBefore := mustRead(t, filepath.Join(f.runDir, "decision.json"))

	accept, acceptPath := recordHumanDecision(t, f.runDir, replayClockA, HumanDecisionAccept, "alice", "accept the proposal")
	_, rejectPath := recordHumanDecision(t, f.runDir, replayClockB, HumanDecisionReject, "bob", "reject the proposal")

	for path, before := range protected {
		if !bytes.Equal(before, mustRead(t, path)) {
			t.Fatalf("%s changed after a human decision", filepath.Base(path))
		}
	}
	var after DecisionPackage
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, "decision.json")), &after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(machineBefore, mustRead(t, filepath.Join(f.runDir, "decision.json"))) {
		t.Fatal("decision.json bytes changed after recording a human decision")
	}
	if !jsonEqual(after.MachineDisposition, pkg.MachineDisposition) {
		t.Fatalf("machine disposition changed: %+v -> %+v", pkg.MachineDisposition, after.MachineDisposition)
	}
	if !jsonEqual(after.Support, pkg.Support) || len(after.FalsifierProofs) != len(pkg.FalsifierProofs) {
		t.Fatal("support or admitted proofs changed after recording a human decision")
	}

	// The record format can only carry a person's decision: no machine
	// recommendation, proof, VEX or Product A authority key exists.
	allowed := map[string]bool{
		"schema_version": true, "id": true, "run_id": true, "finding_id": true,
		"decision_package_hash": true, "decision": true, "actor": true,
		"reason": true, "recorded_at": true,
		"branch_id": true, "projection_hash": true, "assertion_ids": true, "reason_code": true,
	}
	for _, path := range []string{acceptPath, rejectPath} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(mustRead(t, path), &fields); err != nil {
			t.Fatalf("record %s: %v", filepath.Base(path), err)
		}
		for key := range fields {
			if !allowed[key] {
				t.Fatalf("record carries an authority-capable field %q: %s", key, mustRead(t, path))
			}
		}
	}
	if accept.Decision != HumanDecisionAccept {
		t.Fatalf("accept record decision = %q", accept.Decision)
	}

	t.Run("VEX projection is not touched", func(t *testing.T) {
		vexPkg := dismissedPackage(t)
		dir := t.TempDir()
		if err := writeJSONAtomic(context.Background(), filepath.Join(dir, "decision.json"), vexPkg); err != nil {
			t.Fatal(err)
		}
		if err := writeFileAtomic(context.Background(), filepath.Join(dir, "decision.md"), RenderDecisionMarkdown(vexPkg)); err != nil {
			t.Fatal(err)
		}
		proj, err := ProjectVEX(vexPkg)
		if err != nil {
			t.Fatalf("ProjectVEX: %v", err)
		}
		if err := (ArtifactWriter{Clock: replayClockA}).WriteVEXProjection(context.Background(), dir, proj); err != nil {
			t.Fatalf("WriteVEXProjection: %v", err)
		}
		vexBefore := mustRead(t, filepath.Join(dir, "vex.json"))
		pkgBefore := mustRead(t, filepath.Join(dir, "decision.json"))
		recordHumanDecision(t, dir, replayClockB, HumanDecisionAccept, "alice", "the VEX projection must stay untouched")
		if !bytes.Equal(vexBefore, mustRead(t, filepath.Join(dir, "vex.json"))) {
			t.Fatal("recording a human decision rewrote vex.json")
		}
		if !bytes.Equal(pkgBefore, mustRead(t, filepath.Join(dir, "decision.json"))) {
			t.Fatal("recording a human decision rewrote the dismissed decision package")
		}
	})
}

// TestHumanDecisionRejectsInvalidRecord: malformed input, foreign packages
// and tampered record files are refused; the reader never repairs or
// partially accepts a review record.
func TestHumanDecisionRejectsInvalidRecord(t *testing.T) {
	f, pkg := humanDecisionFixture(t)

	for name, in := range map[string]HumanDecisionInput{
		"missing decision":    {Actor: "alice", Reason: "reviewed"},
		"unknown decision":    {Decision: "MAYBE", Actor: "alice", Reason: "reviewed"},
		"accept blank actor":  {Decision: HumanDecisionAccept, Actor: "   ", Reason: "reviewed"},
		"reject blank actor":  {Decision: HumanDecisionReject, Actor: "", Reason: "reviewed"},
	} {
		t.Run("write/"+name, func(t *testing.T) {
			_, path, err := (ArtifactWriter{Clock: replayClockA}).WriteHumanDecision(context.Background(), f.runDir, in)
			if err == nil {
				t.Fatalf("%s was accepted: %+v", name, in)
			}
			if path != "" {
				t.Fatalf("%s returned a record path %q", name, path)
			}
		})
	}
	t.Run("write/missing decision package", func(t *testing.T) {
		_, _, err := (ArtifactWriter{Clock: replayClockA}).WriteHumanDecision(
			context.Background(), t.TempDir(),
			HumanDecisionInput{Decision: HumanDecisionAccept, Actor: "alice", Reason: "reviewed"},
		)
		if err == nil || !strings.Contains(err.Error(), "decision.json") {
			t.Fatalf("missing decision.json error = %v", err)
		}
	})
	t.Run("write/historical decision package", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "decision.json"), `{"schema_version":"decision-package.v2"}`)
		_, _, err := (ArtifactWriter{Clock: replayClockA}).WriteHumanDecision(
			context.Background(), dir,
			HumanDecisionInput{Decision: HumanDecisionAccept, Actor: "alice", Reason: "reviewed"},
		)
		if !errors.Is(err, ErrUnsupportedLiveSchema) {
			t.Fatalf("historical package error = %v, want ErrUnsupportedLiveSchema", err)
		}
	})
	t.Run("write/absent history is valid", func(t *testing.T) {
		history, err := ReadHumanDecisions(f.runDir, pkg)
		if err != nil {
			t.Fatalf("ReadHumanDecisions on absent history: %v", err)
		}
		if len(history) != 0 {
			t.Fatalf("failed writes left records behind: %+v", history)
		}
	})

	base := HumanDecisionRecord{
		SchemaVersion:       HumanDecisionSchemaVersion,
		RunID:               pkg.RunID,
		FindingID:           pkg.FindingID,
		DecisionPackageHash: canonicalDecisionHash(pkg),
		Decision:            HumanDecisionAccept,
		Actor:               "alice",
		Reason:              "reviewed the recorded proposal",
		RecordedAt:          replayClockA(),
	}
	projection, err := ApplyEnvironmentAssertions(pkg, nil)
	if err != nil { t.Fatal(err) }
	base.BranchID, base.ProjectionHash, base.AssertionIDs = projection.BranchID, projection.ProjectionHash, projection.AssertionIDs
	base.ReasonCode = "HUMAN_ACCEPT"
	base.ID = humanDecisionRecordID(base)

	type mutateCase struct {
		name   string
		mutate func(*HumanDecisionRecord)
		keepID bool
	}
	cases := []mutateCase{
		{"wrong schema", func(r *HumanDecisionRecord) { r.SchemaVersion = "human-decision.v999" }, false},
		{"content and id disagree", func(r *HumanDecisionRecord) { r.Actor = "mallory" }, true},
		{"foreign run", func(r *HumanDecisionRecord) { r.RunID = "other-run" }, false},
		{"foreign finding", func(r *HumanDecisionRecord) { r.FindingID = "other-finding" }, false},
		{"foreign package hash", func(r *HumanDecisionRecord) { r.DecisionPackageHash = strings.Repeat("ab", 32) }, false},
		{"unknown decision", func(r *HumanDecisionRecord) { r.Decision = "MAYBE" }, false},
		{"blank actor", func(r *HumanDecisionRecord) { r.Actor = " " }, false},
		{"blank reason code", func(r *HumanDecisionRecord) { r.ReasonCode = "" }, false},
		{"zero recorded_at", func(r *HumanDecisionRecord) { r.RecordedAt = time.Time{} }, false},
		{"non-utc recorded_at", func(r *HumanDecisionRecord) {
			r.RecordedAt = time.Date(2026, 10, 15, 13, 0, 0, 0, time.FixedZone("CEST", 3600))
		}, false},
	}
	for _, tc := range cases {
		t.Run("read/"+tc.name, func(t *testing.T) {
			dir := copyRunDir(t, f.runDir)
			rec := base
			tc.mutate(&rec)
			if !tc.keepID {
				rec.ID = humanDecisionRecordID(rec)
			}
			writeHumanDecisionFile(t, dir, rec.ID+".json", rec)
			if _, err := ReadHumanDecisions(dir, pkg); err == nil {
				t.Fatalf("%s was accepted by the reader", tc.name)
			}
		})
	}

	t.Run("read/unknown field", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var fields map[string]any
		if err := json.Unmarshal(encodeHumanDecisionOrFail(t, base), &fields); err != nil {
			t.Fatal(err)
		}
		fields["machine_disposition"] = map[string]any{"recommendation": "DISMISSED"}
		raw, err := json.MarshalIndent(fields, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeHumanDecisionBytes(t, dir, base.ID+".json", append(raw, '\n'))
		if _, err := ReadHumanDecisions(dir, pkg); err == nil {
			t.Fatal("a record with an authority-capable unknown field was accepted")
		}
	})
	t.Run("read/file name and id disagree", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		writeHumanDecisionFile(t, dir, "hd-not-the-record-id.json", base)
		if _, err := ReadHumanDecisions(dir, pkg); err == nil {
			t.Fatal("a record whose file name differs from its id was accepted")
		}
	})
	t.Run("read/unexpected file", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		writeHumanDecisionBytes(t, dir, "notes.txt", []byte("not a record"))
		if _, err := ReadHumanDecisions(dir, pkg); err == nil {
			t.Fatal("a non-record file in the review collection was ignored")
		}
	})
	t.Run("read/audit failure preserves the record", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		if err := os.RemoveAll(filepath.Join(dir, "audit")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "audit"), []byte("blocked"), 0o644); err != nil {
			t.Fatal(err)
		}
		rec, path, err := (ArtifactWriter{Clock: replayClockA}).WriteHumanDecision(
			context.Background(), dir,
			HumanDecisionInput{Decision: HumanDecisionAccept, Actor: "alice", Reason: "audit append will fail"},
		)
		if err == nil || path == "" {
			t.Fatalf("audit failure was not reported after a persisted record: rec=%+v path=%q err=%v", rec, path, err)
		}
		if !strings.Contains(err.Error(), "audit") {
			t.Fatalf("audit failure error does not name the audit append: %v", err)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("the persisted record was deleted after the audit failure: %v", statErr)
		}
		history, rerr := ReadHumanDecisions(dir, pkg)
		if rerr != nil {
			t.Fatalf("persisted record is unreadable: %v", rerr)
		}
		if len(history) != 1 || history[0].ID != rec.ID {
			t.Fatalf("history after audit failure = %+v", history)
		}
	})
}

func encodeHumanDecisionOrFail(t *testing.T, rec HumanDecisionRecord) []byte {
	t.Helper()
	data, err := encodeHumanDecisionRecord(rec)
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}
	return data
}

func writeHumanDecisionFile(t *testing.T, runDir, name string, rec HumanDecisionRecord) {
	t.Helper()
	writeHumanDecisionBytes(t, runDir, name, encodeHumanDecisionOrFail(t, rec))
}

func writeHumanDecisionBytes(t *testing.T, runDir, name string, data []byte) {
	t.Helper()
	dir := humanDecisionRecordDir(runDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(runDir, humanDecisionsLockName)
	if _, err := os.Stat(lockPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
