package triage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S-09 acceptance: cross-boundary replay fails closed. A recorded run must
// never accept a decision package, observation archive, falsifier report or
// stability sidecar produced by a different run — including one recorded by
// the Product A kernel lane: its stamps are foreign evidence, not replayable
// pins. (V2's ported tests cover in-run drift; these pin the cross-run and
// cross-product cases.)

// TestReplayForeignDecisionRejected: decision.json recorded by run A copied
// into run B's directory. The recomposed hash cannot match → technical error.
func TestReplayForeignDecisionRejected(t *testing.T) {
	a := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	b := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	data, err := os.ReadFile(filepath.Join(a.runDir, "decision.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.runDir, "decision.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), b.runDir); err == nil {
		t.Fatal("foreign decision.json replayed clean")
	}
}

// TestReplayForeignObservationArchiveRejected: the observation archive of a
// different run — the "Product A sidecar" case: observations stamped with a
// foreign run id are foreign evidence the falsifier verifier must refuse,
// and a persisted VERIFIED is recomputed, never trusted.
func TestReplayForeignObservationArchiveRejected(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	// Give the run a falsifier report so replay must consult the archive,
	// then graft a proof whose evidence exists only in a foreign archive.
	r := replayEmptyProofReport(t, f.runDir)
	r.Proofs = []FalsifierProof{{ID: "fp", ProposalID: "fp", ClaimID: "missing", ConditionID: "cond", Kind: FalsifierCodeAbsent, Status: FalsifierVerified, Basis: BasisCheckerVerified}}
	r.Hash = reportHash(r)
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(f.runDir, "falsifier-verification.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := ReadObservationArchive(filepath.Join(f.runDir, "observation-archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Foreign stamps: a run identity this run never minted (e.g. a Product A
	// kernel run) and a payload hash that is internally consistent.
	a.Observations = append(a.Observations, RecordedObservation{
		ID: "foreign-1", RunID: "product-a-kernel-run", Attempt: 1,
		Tool: "verify_code_absence", Status: string(ToolStatusOK),
		Payload:    json.RawMessage(`{"x":1}`),
		DataSHA256: sha256Hex(t, []byte(`{"x":1}`)),
	})
	if err := WriteObservationArchive(context.Background(), filepath.Join(f.runDir, "observation-archive.json"), observationSliceStore{items: a.Observations}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("foreign observation archive accepted")
	}
}

// TestReplayForeignStabilitySidecarRejected: stability.json bound to a
// different run id is never replayable state for this run.
func TestReplayForeignStabilitySidecarRejected(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	doc := StabilityDocument{
		SchemaVersion: StabilitySchemaVersion,
		RunID:         "product-a-run-999", // foreign identity
		FindingID:     "scanner-123",
		StabilityReport: StabilityReport{
			Retries: 0, Stable: true,
			Attempts: []StabilityAttempt{{
				Attempt:        1,
				Recommendation: RecommendationUnchanged,
				PromptHash:     f.promptHash,
				InputHash:      f.stored.Audit.FindingHash,
				SnapshotHash:   f.stored.Audit.SnapshotHash,
			}},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.runDir, "stability.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("foreign stability.json accepted")
	}
}

// TestReplayTamperedObservationPayloadRejected: a payload byte changed under
// a kept data_sha256 — the tampered archive can never replay clean.
func TestReplayTamperedObservationPayloadRejected(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	replayEmptyProofReport(t, f.runDir)
	p := filepath.Join(f.runDir, "observation-archive.json")
	a, err := ReadObservationArchive(p)
	if err != nil {
		t.Fatal(err)
	}
	a.Observations = append(a.Observations, RecordedObservation{
		ID: "tampered", Tool: "read_file", Status: string(ToolStatusOK),
		Payload:    json.RawMessage(`{"bad":true}`),
		DataSHA256: strings.Repeat("0", 64),
	})
	if err := WriteObservationArchive(context.Background(), p, observationSliceStore{items: a.Observations}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("observation payload tamper accepted")
	}
}

// rewriteSchemaVersion mutates one recorded artifact's schema_version while
// leaving every other field in place, so the live-version rejection is the
// first check that fires.
func rewriteSchemaVersion(t *testing.T, path, version string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, path), &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	doc["schema_version"] = version
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(data))
}

// TestReplayHistoricalLiveSchemasRejected: the live cutover never re-admits
// an old live schema. assessment.v1, decision-package.v2 and
// stability-runs.v1 are history: replay refuses each with an actionable
// unsupported-version error naming the current schema and the offline
// extractors, instead of upgrading the record into a current human package.
func TestReplayHistoricalLiveSchemasRejected(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)

	cases := []struct {
		name  string
		old   string
		cur   string
		patch func(t *testing.T, dir string)
	}{
		{
			name: "assessment.v1", old: "assessment.v1", cur: AssessmentSchemaVersion,
			patch: func(t *testing.T, dir string) {
				rewriteSchemaVersion(t, filepath.Join(dir, "assessment.json"), "assessment.v1")
			},
		},
		{
			name: "decision-package.v2", old: "decision-package.v2", cur: DecisionPackageSchemaVersion,
			patch: func(t *testing.T, dir string) {
				rewriteSchemaVersion(t, filepath.Join(dir, "decision.json"), "decision-package.v2")
			},
		},
		{
			name: "stability-runs.v1", old: "stability-runs.v1", cur: StabilitySchemaVersion,
			patch: func(t *testing.T, dir string) {
				doc := StabilityDocument{
					SchemaVersion: "stability-runs.v1",
					RunID:         "historical-run", FindingID: "scanner-123",
					StabilityReport: StabilityReport{Retries: 0, Stable: true, Attempts: []StabilityAttempt{{
						Attempt: 1, Recommendation: RecommendationUnchanged,
					}}},
				}
				data, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(dir, "stability.json"), string(data))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyRunDir(t, f.runDir)
			tc.patch(t, dir)
			_, err := PrepareReplay(context.Background(), dir)
			if err == nil {
				t.Fatalf("%s replayed through the live pipeline", tc.old)
			}
			if !errors.Is(err, ErrUnsupportedLiveSchema) {
				t.Fatalf("%s rejection must wrap ErrUnsupportedLiveSchema, got: %v", tc.old, err)
			}
			for _, want := range []string{tc.old, tc.cur, "history only", "offline extractors"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("%s rejection is not actionable (missing %q): %v", tc.old, want, err)
				}
			}
		})
	}
}

// TestReplayForeignHumanDecisionHistoryRejected: an Accept/Reject record
// copied from another run is foreign review history. Replay re-verifies the
// record's package binding and refuses it, so a decision recorded against a
// different delivered proposal can never ride along with this one.
func TestReplayForeignHumanDecisionHistoryRejected(t *testing.T) {
	a := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	b := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	rec, path := recordHumanDecision(t, a.runDir, replayClockA, HumanDecisionAccept, "alice", "reviewed the delivered build graph")

	dir := humanDecisionRecordDir(b.runDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.runDir, humanDecisionsLockName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, rec.ID+".json"), mustRead(t, path), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := PrepareReplay(context.Background(), b.runDir)
	if err == nil {
		t.Fatal("foreign human-decision history replayed clean")
	}
	for _, want := range []string{"human decision", "decision_package_hash"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("foreign review rejection lacks %q: %v", want, err)
		}
	}
}
