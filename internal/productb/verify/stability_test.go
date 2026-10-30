package verify

import (
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/productb/claimshape"
	triage "github.com/davniy/izyan/internal/productb/triage"
)

// --- attempt fixtures ---

func dismissedInput(t *testing.T) Input {
	in := baseInput(absentClaim(), absenceObs(t, nil))
	in.Advisory = advisoryWithSymbols()
	return in
}

func stablePins() AttemptPins {
	return AttemptPins{
		InputHash: "in-1", SnapshotHash: "snap-1", AdvisoryHash: "adv-1",
		BuildContextHash: "bc-1", RulesetHash: "rules-1", PromptHash: "prompt-1",
		BudgetHash: "budget-1", SelectedRef: "main", ResolvedCommit: "deadbeef",
	}
}

func attempt(n int, rep Report) Attempt {
	return Attempt{Attempt: n, Pins: stablePins(), Report: rep}
}

// --- decisive vs semantic surface ---

func TestDecisiveHashExcludesLLMSurface(t *testing.T) {
	// Two attempts whose claims differ only in attempt-local identity
	// and prose must share the decisive surface — semantic drift, never
	// instability (§6.5).
	a := dismissedInput(t)
	b := dismissedInput(t)
	bc := absentClaim()
	bc.ID = "c-attempt2"
	bc.Source.Statement = "the vulnerable symbol cannot be found in the shipping closure"
	b.Claims = []claimshape.CanonicalClaim{bc}
	ra, rb := Evaluate(a), Evaluate(b)
	if ra.Decisive.Hash != rb.Decisive.Hash {
		t.Fatal("claim identity drift changed the decisive surface")
	}
	if ra.SemanticHash == rb.SemanticHash {
		t.Fatal("semantic surface must notice the different claim")
	}
	v := Assess([]Attempt{attempt(1, ra), attempt(2, rb)})
	if !v.Stable || v.Drift {
		t.Fatalf("semantic drift must not demote: %+v", v)
	}
	if !v.SemanticDrift {
		t.Fatal("semantic drift not recorded")
	}
	if v.Disposition != "DISMISSED" {
		t.Fatalf("disposition = %+v", v)
	}
}

func TestUnstableDecisiveEvidenceDemotes(t *testing.T) {
	// One attempt's counterexample flips the predicate: the decisive
	// surface disagrees, reduction is forbidden — UNCHANGED, and no
	// attempt is selected as the better answer.
	stable := Evaluate(dismissedInput(t))
	shiftedIn := dismissedInput(t)
	shiftedIn.Observations = append(shiftedIn.Observations, partialPresenceObs())
	shifted := Evaluate(shiftedIn)
	if stable.Decision().Disposition != "DISMISSED" {
		t.Fatalf("fixture: %v", stable.Decision())
	}
	if stable.Decisive.Hash == shifted.Decisive.Hash {
		t.Fatal("counterexample did not move the decisive surface")
	}
	v := Assess([]Attempt{attempt(1, stable), attempt(2, shifted)})
	if v.Stable || v.Drift {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Disposition != "UNCHANGED" || v.DemotedFrom != "DISMISSED" {
		t.Fatalf("demotion = %+v", v)
	}
	if len(v.Attempts) != 2 || v.Retries != 1 {
		t.Fatalf("attempt audit = %+v", v)
	}
	found := false
	for _, l := range v.Limitations {
		if l == "attempt 2: decisive surface changed ("+stable.Decisive.Hash+" -> "+shifted.Decisive.Hash+")" {
			found = true
		}
	}
	if !found {
		t.Fatalf("divergence not recorded: %+v", v.Limitations)
	}
}

func TestNoMajorityVoteAcrossAttempts(t *testing.T) {
	// Two DISMISSED attempts and one conflicted attempt: the majority
	// never wins — the dissenting attempt blocks reduction.
	d1 := Evaluate(dismissedInput(t))
	conflictedIn := dismissedInput(t)
	conflictedIn.Observations = append(conflictedIn.Observations, presenceObs())
	conf := Evaluate(conflictedIn)
	if conf.Decision().Disposition == "DISMISSED" {
		t.Fatal("fixture: conflict dismissed")
	}
	v := Assess([]Attempt{attempt(1, d1), attempt(2, d1), attempt(3, conf)})
	if v.Disposition != "UNCHANGED" || v.Stable {
		t.Fatalf("majority decided: %+v", v)
	}
}

func TestProvenanceDriftDemotes(t *testing.T) {
	// A changed snapshot pin is technical drift, not instability: the
	// disposition demotes unconditionally.
	a := Evaluate(dismissedInput(t))
	b := Evaluate(dismissedInput(t))
	pins2 := stablePins()
	pins2.SnapshotHash = "snap-other"
	v := Assess([]Attempt{attempt(1, a), {Attempt: 2, Pins: pins2, Report: b}})
	if !v.Drift || v.Disposition != "UNCHANGED" || v.DemotedFrom != "DISMISSED" {
		t.Fatalf("drift verdict = %+v", v)
	}
}

func TestStableAttemptsKeepReduction(t *testing.T) {
	a := Evaluate(dismissedInput(t))
	v := Assess([]Attempt{attempt(1, a), attempt(2, a), attempt(3, a)})
	if !v.Stable || v.Drift || v.SemanticDrift {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Disposition != "DISMISSED" || v.DemotedFrom != "" {
		t.Fatalf("stable reduction demoted: %+v", v)
	}
}

func TestSingleAttemptVacuouslyStable(t *testing.T) {
	a := Evaluate(dismissedInput(t))
	v := Assess([]Attempt{attempt(1, a)})
	if !v.Stable || v.Disposition != "DISMISSED" {
		t.Fatalf("single attempt = %+v", v)
	}
}

func TestUnstableUnchangedStaysUnchanged(t *testing.T) {
	// Instability between two non-reducing verdicts is recorded but
	// the disposition was already UNCHANGED — nothing to demote.
	a := Evaluate(Input{RunID: "run-1", FindingID: "f-1"})
	b := Evaluate(dismissedInput(t))
	v := Assess([]Attempt{attempt(1, a), attempt(2, b)})
	if v.Stable || v.Disposition != "UNCHANGED" {
		t.Fatalf("verdict = %+v", v)
	}
}

// --- 5×3-shaped scenario: flips never reduce ---

func TestFiveByThreeStyleSeries(t *testing.T) {
	// Mirrors the measured instability class: five findings × three
	// re-derivations. Two findings flip DISMISSED↔UNCHANGED, one
	// carries contradictory evidence, two stay stable. No flipped or
	// conflicted finding may keep a reduction — the controller must
	// demote every unstable series.
	flipped := func(n int) Report {
		if n == 3 {
			in := dismissedInput(t)
			in.Observations = append(in.Observations, partialPresenceObs())
			return Evaluate(in)
		}
		return Evaluate(dismissedInput(t))
	}
	conflicted := func(n int) Report {
		in := dismissedInput(t)
		if n == 2 {
			in.Observations = append(in.Observations, presenceObs())
		}
		return Evaluate(in)
	}
	type ticket struct {
		name     string
		mk       func(int) Report
		wantDisp string
		wantStab bool
	}
	tickets := []ticket{
		{"stable-1", func(int) Report { return Evaluate(dismissedInput(t)) }, "DISMISSED", true},
		{"stable-2", func(int) Report { return Evaluate(dismissedInput(t)) }, "DISMISSED", true},
		{"flip-A", flipped, "UNCHANGED", false},
		{"flip-B", flipped, "UNCHANGED", false},
		{"conflict", conflicted, "UNCHANGED", false},
	}
	for _, tk := range tickets {
		var attempts []Attempt
		for n := 1; n <= 3; n++ {
			attempts = append(attempts, attempt(n, tk.mk(n)))
		}
		v := Assess(attempts)
		if v.Disposition != tk.wantDisp || v.Stable != tk.wantStab {
			t.Fatalf("%s: verdict = %+v", tk.name, v)
		}
		if v.Disposition == "DISMISSED" || v.Disposition == "LOWERED" {
			if !v.Stable {
				t.Fatalf("%s reduced on unstable evidence", tk.name)
			}
		}
	}
}

func TestUnstableProofStatusDemotes(t *testing.T) {
	// The 9-alarm class: one attempt's proof certificate verifies,
	// another's stays UNKNOWN — proof status is decisive.
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	verified := Input{RunID: "run-1", FindingID: "f-1", SnapshotHash: "snap-1"}
	verified.Advisory = advisoryWithSymbols()
	verified.Falsifiers = proofReport(locusProof("det-k", triage.AdvisoryConditionID("ADV-1"), subjects))
	a := Evaluate(verified)
	if a.Decision().Disposition != "DISMISSED" {
		t.Fatalf("fixture: %v", a.Decision())
	}
	unknown := verified
	p := locusProof("det-k", triage.AdvisoryConditionID("ADV-1"), subjects)
	p.Status = triage.FalsifierUnknown
	p.History = []triage.FalsifierTransition{
		{From: triage.FalsifierUnknown, To: triage.FalsifierUnknown, Reason: "bounded"},
	}
	unknown.Falsifiers = proofReport(p)
	b := Evaluate(unknown)
	v := Assess([]Attempt{attempt(1, a), attempt(2, b)})
	if v.Disposition != "UNCHANGED" || v.Stable {
		t.Fatalf("proof-status flip kept reduction: %+v", v)
	}
}

func TestConflictStateIsDecisive(t *testing.T) {
	// A hidden conflict inside one attempt must move the decisive
	// hash even when the disposition agrees.
	a := Evaluate(dismissedInput(t))
	conflictedIn := dismissedInput(t)
	conflictedIn.Observations = append(conflictedIn.Observations, presenceObs())
	b := Evaluate(conflictedIn)
	if a.Decisive.Hash == b.Decisive.Hash {
		t.Fatal("conflict state did not move the decisive surface")
	}
	if len(b.Decisive.Conflicts) == 0 {
		t.Fatal("conflict not fingerprinted")
	}
	v := Assess([]Attempt{attempt(1, a), attempt(2, b)})
	if v.Stable {
		t.Fatalf("hidden conflict passed as stable: %+v", v)
	}
}

func TestAssessKeepsEveryAttemptVerbatim(t *testing.T) {
	// The verdict echoes every attempt projection — a preferred
	// attempt is never distilled out.
	a := Evaluate(dismissedInput(t))
	bIn := dismissedInput(t)
	bIn.Observations = append(bIn.Observations, partialPresenceObs())
	b := Evaluate(bIn)
	v := Assess([]Attempt{attempt(1, a), attempt(2, b), attempt(3, a)})
	if len(v.Attempts) != 3 {
		t.Fatalf("attempts = %+v", v.Attempts)
	}
	if v.Attempts[0].DecisiveHash != a.Decisive.Hash || v.Attempts[1].DecisiveHash != b.Decisive.Hash {
		t.Fatalf("projections not verbatim: %+v", v.Attempts)
	}
}

// regression guard: PARTIAL evidence can never stabilize into a
// reduction even across identical attempts.
func TestPartialNeverReducesUnderStability(t *testing.T) {
	partial := absenceObs(t, func(o *triage.RecordedObservation) {
		o.Completeness = evidencetools.CompletenessPartial
	})
	in := baseInput(absentClaim(), partial)
	in.Advisory = advisoryWithSymbols()
	rep := Evaluate(in)
	v := Assess([]Attempt{attempt(1, rep), attempt(2, rep)})
	if v.Disposition != "UNCHANGED" {
		t.Fatalf("partial stabilized into reduction: %+v", v)
	}
}
