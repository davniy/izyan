package heldoutgate

// absenceRecord builds a clean COMPLETE verify_code_absence archive
// record for tests — the shape a re-derived probe produces. RunID is
// left empty on purpose: absenceInput stamps the deterministic probe id,
// mirroring how DeriveAbsenceProbe binds records at mint time.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	agenttriage "github.com/fedorovmv/izyan/internal/productb/triage"
	"github.com/fedorovmv/izyan/internal/productb/verify"
)

func absenceRecord(t *testing.T, subjects []map[string]string) agenttriage.RecordedObservation {
	t.Helper()
	subs := make([]any, 0, len(subjects))
	for _, s := range subjects {
		subs = append(subs, map[string]any{"package": s["package"], "symbol": s["symbol"], "role": "func"})
	}
	env := map[string]any{
		"id": "OBS-1", "tool": "verify_code_absence",
		"fact": "checked subjects", "scope": "closed universe",
		"completeness": "COMPLETE", "tool_status": "OK",
		"scope_details": map[string]any{
			"snapshot_hash":         "snap-1",
			"build_context":         map[string]any{"goos": "linux", "goarch": "arm64"},
			"coverage_rule_version": "4",
		},
		"data": map[string]any{
			"expected_subjects":     subs,
			"checked_subjects":      subs,
			"absent_subjects":       subs,
			"snapshot_hash":         "snap-1",
			"build_context_hash":    "bctx-1",
			"coverage_rule_version": "4",
			"import_closure": map[string]any{
				"complete": true, "hash": "cl-1", "scope_hash": "sc-1",
			},
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return agenttriage.RecordedObservation{
		ID: "probe-0001", Tool: "verify_code_absence", Status: "OK",
		Completeness: evidencetools.CompletenessComplete,
		Payload:      b, DataSHA256: hex.EncodeToString(sum[:]),
		Attempt:      1,
		SnapshotHash: "snap-1", BuildContextHash: "bctx-1",
	}
}

func absenceGroup() SpecGroup {
	var g SpecGroup
	g.Repo, g.Ref, g.Advisory, g.Module = "repo", "1.0", "ADV-1", "dep/mod"
	g.Subjects = append(g.Subjects, struct {
		Package string `json:"package"`
		Symbol  string `json:"symbol"`
	}{Package: "dep/mod", Symbol: "Vuln"})
	return g
}

// TestEligibleAbsenceAdmits: a complete closed-scope absence record must
// admit SUPPORTS and compile DISMISSED — the §8.3 admission coverage gate.
func TestEligibleAbsenceAdmits(t *testing.T) {
	rec := absenceRecord(t, []map[string]string{{"package": "dep/mod", "symbol": "Vuln"}})
	in := absenceInput(absenceGroup(), rec, "", "")
	rep := verify.Evaluate(in)
	if rep.Decision().Disposition != "DISMISSED" {
		t.Fatalf("disposition=%s want DISMISSED (%v)", rep.Decision().Disposition, rep.Claims)
	}
	ce := rep.ClaimOutcomeOf("claim-probe-absence")
	if ce == nil || ce.Outcome != verify.OutcomeTrue {
		t.Fatalf("claim outcome=%v", ce)
	}
}

// TestMutationsRefuseAdmission: every §8.4 mutation applied to an
// eligible record must leave it non-admitting for the absence direction.
func TestMutationsRefuseAdmission(t *testing.T) {
	subjects := []map[string]string{{"package": "dep/mod", "symbol": "Vuln"}}
	rec := absenceRecord(t, subjects)
	g := absenceGroup()
	row := AbsenceGroupRow{
		GroupKey: specKey(g), Repo: g.Repo, Ref: g.Ref, Advisory: g.Advisory,
		Module: g.Module, Tickets: []string{"T-1"},
		ReDerived: ProbeSummary{
			Status: "OK", Completeness: "COMPLETE", Checked: 1, Absent: 1,
			ClosureComplete: true,
		},
		ParityOK: true,
	}
	row.EligibleForAdmission, row.ProofEligible = true, true
	rows := Mutations([]AbsenceGroupRow{row}, map[string]agenttriage.RecordedObservation{row.GroupKey: rec})
	if len(rows) != len(mutationList) {
		t.Fatalf("mutations=%d want %d", len(rows), len(mutationList))
	}
	var failed []string
	for _, m := range rows {
		if !m.Pass {
			failed = append(failed, m.Mutation+":"+m.GotEstablished)
		}
	}
	// D-5 regression: auxiliary scope.closed evidence must not establish
	// subject.absent. Mutations that remove checked coverage or add an
	// unresolved dispatch marker must remain non-admitting.
	if len(failed) != 0 {
		t.Fatalf("mutation failures = %v; auxiliary evidence admitted a predicate", failed)
	}
}

// TestRunBindingIdentity: the archive's own stamp is the replay identity —
// the document-level run id of decision.json can never bind records.
func TestRunBindingIdentity(t *testing.T) {
	obs := []agenttriage.RecordedObservation{{RunID: "f-1@attempt-1"}}
	id, notes := ReplayIdentity(obs, "f-1")
	if id != "f-1@attempt-1" || len(notes) != 0 {
		t.Fatalf("id=%q notes=%v", id, notes)
	}
	mixed := append(append([]agenttriage.RecordedObservation(nil), obs...), agenttriage.RecordedObservation{RunID: "other@attempt-1"})
	id, notes = ReplayIdentity(mixed, "f-1")
	if len(notes) == 0 {
		t.Fatal("mixed stamps must produce a contamination note")
	}
}

// TestForeignObservationNeverAdmits: a record stamped with another run's
// id can never satisfy the provenance binding — the §8.3 foreign gate.
func TestForeignObservationNeverAdmits(t *testing.T) {
	rec := absenceRecord(t, []map[string]string{{"package": "dep/mod", "symbol": "Vuln"}})
	rec.RunID = "foreign-run"
	in := absenceInput(absenceGroup(), rec, "", "")
	in.RunID = "own-run"
	in.AssumeArchiveRun = false
	rep := verify.Evaluate(in)
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("foreign observation produced %s", rep.Decision().Disposition)
	}
	for _, ce := range rep.Claims {
		for _, g := range ce.Groups {
			for _, adm := range g.Observations {
				if adm.Admitted {
					t.Fatalf("foreign record admitted: %v", adm)
				}
			}
		}
	}
}

// TestHoldoutFoldsGrouped: folds never split a group and never share one.
func TestHoldoutFoldsGrouped(t *testing.T) {
	var runs []CorpusRunRow
	for i, key := range []string{"r1|famA|adv1", "r1|famA|adv1", "r1|famB|adv2", "r2|famA|adv1"} {
		runs = append(runs, CorpusRunRow{Ticket: "t" + string(rune('0'+i)), GroupKey: key})
	}
	folds := HoldoutFolds(runs, 3)
	seen := map[string]int{}
	for _, f := range folds {
		if prev, dup := seen[f.GroupKey]; dup && prev != f.Fold {
			t.Fatalf("group %s split across folds %d and %d", f.GroupKey, prev, f.Fold)
		}
		seen[f.GroupKey] = f.Fold
	}
}

// TestPartialNeverAdmitsUniversal: a PARTIAL record never admits the
// absence direction — the §6.3 invariant at the gate.
func TestPartialNeverAdmitsUniversal(t *testing.T) {
	rec := absenceRecord(t, []map[string]string{{"package": "dep/mod", "symbol": "Vuln"}})
	rec.Completeness = evidencetools.CompletenessPartial
	in := absenceInput(absenceGroup(), rec, "", "")
	rep := verify.Evaluate(in)
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("PARTIAL produced %s", rep.Decision().Disposition)
	}
}

// TestArchiveObservationID: admission ids minted for archive records
// parse as foreign-eligible; derived/cert ids never do.
func TestArchiveObservationID(t *testing.T) {
	for id, want := range map[string]bool{
		"det-0001#0#declaration_resolver":        true,
		"claim-1#derived:advisory_range_matcher": false,
		"proof:fp-1#claim-2":                     false,
		"obs-1":                                  false,
	} {
		if got := isArchiveObservation(id); got != want {
			t.Errorf("isArchiveObservation(%q)=%v want %v", id, got, want)
		}
	}
}

// TestGroupKeyStable: group keys carry repository+family+advisory.
func TestGroupKeyStable(t *testing.T) {
	k := groupKey("repo-a", "mod", "ADV-1")
	if k != "repo-a|mod|ADV-1" {
		t.Fatalf("key=%s", k)
	}
	_ = claimshape.ShapeUnsupported
}
