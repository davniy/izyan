package verify

import (
	"encoding/json"
	"testing"

	"github.com/davniy/izyan/internal/productb/claimshape"
	triage "github.com/davniy/izyan/internal/productb/triage"
)

// --- challenge normalization and re-derivation ---

func challengeRowOf(rep Report, id string) *ChallengeEval {
	for i := range rep.Challenges {
		if rep.Challenges[i].ChallengeID == id {
			return &rep.Challenges[i]
		}
	}
	return nil
}

func TestChallengeNormalizesAndRederives(t *testing.T) {
	// An alternative-caller proposal mints a path.reachable claim over
	// the named subject and passes through the identical cycle: with
	// no reachability evidence recorded it stays UNKNOWN — the channel
	// cannot assert the caller exists.
	in := baseInput(absentClaim(), absenceObs(t, nil))
	in.Advisory = advisoryWithSymbols()
	in.Challenges = []Challenge{{
		ID:      "rev-1",
		Kind:    ChallengeAlternativeCaller,
		Target:  "c-1",
		Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Handler", Package: "dep/pkg", Symbol: "Handler"},
	}}
	rep := Evaluate(in)
	row := challengeRowOf(rep, "rev-1")
	if row == nil || row.Rejected != "" {
		t.Fatalf("challenge row = %+v", row)
	}
	ev := rep.ClaimOutcomeOf(row.ClaimID)
	if ev == nil || ev.Shape != claimshape.ShapePathReachable {
		t.Fatalf("challenge claim = %+v", ev)
	}
	if ev.Outcome != OutcomeUnknown {
		t.Fatalf("unevidenced challenge adjudicated: %+v", ev)
	}
}

func TestChallengeCitedEvidenceRederives(t *testing.T) {
	// A contradictory-observation challenge cites a recorded counter-
	// example: the deterministic cycle — not the reviewer — computes
	// DISPROVED for it, and the challenge polarity FALSE reads TRUE
	// (the reviewer's hypothesis stood on evidence).
	in := baseInput(absentClaim(), partialPresenceObs())
	in.Advisory = advisoryWithSymbols()
	in.Challenges = []Challenge{{
		ID:           "rev-2",
		Kind:         ChallengeContradictoryObservation,
		Target:       "c-1",
		Shape:        claimshape.ShapeSubjectAbsent,
		Subject:      claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"},
		EvidenceRefs: []string{"det-2"},
	}}
	rep := Evaluate(in)
	row := challengeRowOf(rep, "rev-2")
	if row == nil {
		t.Fatal("no challenge row")
	}
	if row.Predicate != PredicateDisproved || row.Outcome != OutcomeTrue {
		t.Fatalf("challenge outcome = %+v", row)
	}
	// A sustained counterexample removes the falsifier — the decision
	// degrades conservatively instead of trusting the absence.
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("decision = %+v", rep.Decision())
	}
}

func TestChallengeContradictionBlocksDismissal(t *testing.T) {
	// Same predicate, same context, contradictory admitted evidence:
	// the conflict contests the clean falsifier instead of losing a
	// vote (§6.4). c-1 asserts absence of a sibling subject while its
	// cited check's admitted coverage spans the advisory universe —
	// without the challenge's contradiction it would falsify.
	c := absentClaim()
	c.Subject = claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Other", Package: "dep/pkg", Symbol: "Other"}
	in := baseInput(c, absenceObs(t, nil), presenceObs())
	in.Advisory = advisoryWithSymbols()
	in.Challenges = []Challenge{{
		ID:           "rev-3",
		Kind:         ChallengeContradictoryObservation,
		Shape:        claimshape.ShapeSubjectAbsent,
		Subject:      claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"},
		EvidenceRefs: []string{"det-1", "det-2"},
	}}
	rep := Evaluate(in)
	row := challengeRowOf(rep, "rev-3")
	if row == nil || row.Predicate != PredicateConflicting {
		t.Fatalf("challenge outcome = %+v", row)
	}
	if rep.ClaimOutcomeOf("c-1").Predicate != PredicateHolds {
		t.Fatalf("clean falsifier = %+v", rep.ClaimOutcomeOf("c-1"))
	}
	cond := condOf(graphOf(t, rep), triage.AdvisoryConditionID("ADV-1"))
	if cond != nil && cond.Value == "FALSE" {
		t.Fatalf("conflict falsified the condition: %+v", cond)
	}
	if cond != nil && len(cond.Contested) == 0 {
		t.Fatalf("contested falsifier not recorded: %+v", cond)
	}
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("conflict decided: %+v", rep.Decision())
	}
}

func TestChallengeCannotContestAcrossContexts(t *testing.T) {
	// Contradictory evidence pinned to a different build context never
	// contests the certificate's own context (§6.4 separation).
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	foreign := partialPresenceObs()
	foreign.ID = "det-foreign"
	foreign.SnapshotHash = "snap-2"
	foreign.BuildContextHash = "bc-2"
	in := Input{RunID: "run-1", FindingID: "f-1", SnapshotHash: "snap-1", Observations: []triage.RecordedObservation{foreign}}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(locusProof("det-kernel-x", triage.AdvisoryConditionID("ADV-1"), subjects))
	in.Challenges = []Challenge{{
		ID:           "rev-4",
		Kind:         ChallengeContradictoryObservation,
		Shape:        claimshape.ShapeSubjectAbsent,
		Subject:      claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"},
		EvidenceRefs: []string{"det-foreign"},
	}}
	rep := Evaluate(in)
	row := challengeRowOf(rep, "rev-4")
	if row == nil || row.Predicate != PredicateDisproved {
		t.Fatalf("foreign-context challenge = %+v", row)
	}
	if rep.Decision().Disposition != "DISMISSED" {
		t.Fatalf("cross-context conflict contested the certificate: %+v", rep.Decision())
	}
}

func TestContradictedCertificateContestsVerified(t *testing.T) {
	// A clean CONTRADICTED certificate bound to the same condition in
	// the same context contests the VERIFIED one: no certificate wins
	// a vote.
	subjects := []triage.FalsifierSubject{{Package: "dep/pkg", Symbol: "Victim"}}
	verified := locusProof("det-kernel-v", triage.AdvisoryConditionID("ADV-1"), subjects)
	contra := locusProof("det-kernel-c", triage.AdvisoryConditionID("ADV-1"), subjects)
	contra.Status = triage.FalsifierContradicted
	contra.Coverage.PresentSubjects = subjects
	contra.Coverage.AbsentSubjects = nil
	contra.History = []triage.FalsifierTransition{
		{From: triage.FalsifierUnknown, To: triage.FalsifierContradicted, Reason: "counterexample recorded"},
	}
	in := Input{RunID: "run-1", FindingID: "f-1"}
	in.Advisory = advisoryWithSymbols()
	in.Falsifiers = proofReport(verified, contra)
	rep := Evaluate(in)
	cond := condOf(graphOf(t, rep), triage.AdvisoryConditionID("ADV-1"))
	if cond != nil && cond.Value == "FALSE" {
		t.Fatalf("contradicted certificate falsified: %+v", cond)
	}
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("certificate conflict decided: %+v", rep.Decision())
	}
}

// --- order invariance ---

func TestChallengeOrderInvariant(t *testing.T) {
	mk := func(order []int) Report {
		chs := []Challenge{
			{ID: "rev-a", Kind: ChallengeAlternativeCaller, Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Handler", Package: "dep/pkg", Symbol: "Handler"}},
			{ID: "rev-b", Kind: ChallengeMissingSubject, Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Extra", Package: "dep/pkg", Symbol: "Extra"}},
			{ID: "rev-c", Kind: ChallengeScopeGap},
			{ID: "rev-d", Kind: ChallengeContradictoryObservation, Shape: claimshape.ShapeSubjectAbsent, Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.Victim", Package: "dep/pkg", Symbol: "Victim"}, EvidenceRefs: []string{"det-1"}},
			{ID: "rev-e", Kind: ChallengeUnsupportedCausalStep, PremiseFamilies: []string{"subject", "path"}},
		}
		var picked []Challenge
		for _, i := range order {
			picked = append(picked, chs[i])
		}
		in := baseInput(absentClaim(), absenceObs(t, nil))
		in.Advisory = advisoryWithSymbols()
		in.Challenges = picked
		return Evaluate(in)
	}
	a := mk([]int{0, 1, 2, 3, 4})
	b := mk([]int{4, 3, 2, 1, 0})
	c := mk([]int{2, 0, 4, 1, 3})
	if a.Hash != b.Hash || a.Hash != c.Hash {
		t.Fatalf("challenge order changed graph hash: %s %s %s", a.Hash, b.Hash, c.Hash)
	}
	if a.Decision().Disposition != b.Decision().Disposition || a.Decision().Disposition != c.Decision().Disposition {
		t.Fatalf("challenge order changed decision: %+v %+v %+v", a.Decision(), b.Decision(), c.Decision())
	}
	if a.SemanticHash != b.SemanticHash || a.Decisive.Hash != b.Decisive.Hash {
		t.Fatal("challenge order changed stability surfaces")
	}
	if len(a.Challenges) != len(b.Challenges) {
		t.Fatalf("challenge audit rows differ: %d vs %d", len(a.Challenges), len(b.Challenges))
	}
	// The same five proposals in every permutation: minted claim ids
	// are a function of content, never of input order.
	idsA := map[string]bool{}
	for _, r := range a.Challenges {
		idsA[r.ClaimID] = true
	}
	for _, r := range b.Challenges {
		if !idsA[r.ClaimID] {
			t.Fatalf("permutation minted a different claim: %+v", r)
		}
	}
}

// --- proposal-only boundary: no authority ---

func TestChallengeCannotForgeAuthority(t *testing.T) {
	for _, field := range []string{
		"status", "verdict", "recommendation", "outcome", "result",
		"proof", "proof_status", "falsifier", "mandatory", "admitted",
		"verified", "negative_verification", "coverage", "completeness",
		"condition_id", "bound_proposals", "facets",
		"observations", "run_id", "snapshot_hash", "build_context_hash",
		"scope_hash", "tool", "tool_version", "scope", "open_gaps",
	} {
		raw := `{"kind":"missing_subject","` + field + `":true,` +
			`"subject":{"kind":"symbol","name":"dep/pkg.X"}}`
		var ch Challenge
		if err := json.Unmarshal([]byte(raw), &ch); err == nil {
			t.Fatalf("forbidden field %q accepted: %+v", field, ch)
		}
	}
	// Unknown fields are schema errors, not proposals.
	var ch Challenge
	if err := json.Unmarshal([]byte(`{"kind":"missing_subject","bogus":1,"subject":{"kind":"symbol","name":"dep/pkg.X"}}`), &ch); err == nil {
		t.Fatal("unknown challenge field accepted")
	}
}

func TestChallengeMintedClaimCarriesNoAuthority(t *testing.T) {
	// The minted claim must never carry the channels proposals or
	// facets travel on — even when the reviewer asks nicely.
	ch := Challenge{
		ID:         "rev-x",
		Kind:       ChallengeMissingSubject,
		Subject:    claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.X", Package: "dep/pkg", Symbol: "X"},
		Parameters: map[string]string{"bound_proposals": "yes", "facets": "yes"},
	}
	c, row := normalizeChallenge(ch)
	if row.Rejected != "" {
		t.Fatalf("challenge rejected: %s", row.Rejected)
	}
	if got := boundProposals(c); len(got) != 0 {
		t.Fatalf("challenge minted bound proposals: %+v", got)
	}
	if v, ok := c.Parameters["facets"].([]claimshape.Facet); ok && len(v) > 0 {
		t.Fatalf("challenge minted facets: %+v", v)
	}
	if len(c.Scope.ObservationIDs) != 0 || c.Scope.SnapshotHash != "" || c.Scope.BuildContextHash != "" {
		t.Fatalf("challenge pinned provenance: %+v", c.Scope)
	}
}

func TestChallengeRejectedVacuousOrInvalid(t *testing.T) {
	rep := Evaluate(Input{
		RunID: "run-1", FindingID: "f-1",
		Challenges: []Challenge{
			{ID: "bad-kind", Kind: "verdict_override", Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.X"}},
			{ID: "vacuous", Kind: ChallengeScopeGap},
			{ID: "no-shape", Kind: ChallengeContradictoryObservation, Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.X"}},
		},
	})
	if len(rep.Challenges) != 3 {
		t.Fatalf("rejected challenges not audited: %+v", rep.Challenges)
	}
	for _, row := range rep.Challenges {
		if row.Rejected == "" {
			t.Fatalf("invalid challenge minted a claim: %+v", row)
		}
		if row.ClaimID != "" {
			t.Fatalf("rejected challenge bound to a claim: %+v", row)
		}
	}
	if rep.Decision().Disposition != "UNCHANGED" {
		t.Fatalf("rejected challenges moved the decision: %+v", rep.Decision())
	}
}

func TestChallengeDedupesIdenticalProposals(t *testing.T) {
	claim1, _ := normalizeChallenge(Challenge{
		ID: "rev-1", Kind: ChallengeAlternativeCaller,
		Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.H", Package: "dep/pkg", Symbol: "H"},
	})
	claim2, _ := normalizeChallenge(Challenge{
		ID: "rev-2", Kind: ChallengeAlternativeCaller,
		Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.H", Package: "dep/pkg", Symbol: "H"},
	})
	if claim1.ID != claim2.ID {
		t.Fatalf("identical proposals minted different claims: %s vs %s", claim1.ID, claim2.ID)
	}
	in := baseInput(absentClaim(), absenceObs(t, nil))
	in.Challenges = []Challenge{
		{ID: "rev-1", Kind: ChallengeAlternativeCaller, Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.H", Package: "dep/pkg", Symbol: "H"}},
		{ID: "rev-2", Kind: ChallengeAlternativeCaller, Subject: claimshape.Subject{Kind: claimshape.SubjectSymbol, Name: "dep/pkg.H", Package: "dep/pkg", Symbol: "H"}},
	}
	rep := Evaluate(in)
	claims := 0
	for _, r := range rep.Challenges {
		if r.ClaimID == claim1.ID && !r.Merged {
			claims++
		}
	}
	if claims != 1 {
		t.Fatalf("duplicate proposals not merged: %+v", rep.Challenges)
	}
	count := 0
	for _, ev := range rep.Claims {
		if ev.ClaimID == claim1.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate claim nodes minted: %d", count)
	}
}

// --- persistence round-trip ---

func TestChallengesDocumentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	doc := ChallengesDocument{
		RunID: "run-1", FindingID: "f-1",
		Challenges: []Challenge{{
			ID: "rev-1", Kind: ChallengeScopeGap, Target: "cond-1",
			Parameters: map[string]string{"module": "dep"},
			Rationale:  "closure may not cover the plugin surface",
		}},
	}
	path := dir + "/challenges.json"
	if err := WriteChallenges(path, doc); err != nil {
		t.Fatalf("write: %v", err)
	}
	back, err := ReadChallenges(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(back.Challenges) != 1 || back.Challenges[0].Kind != ChallengeScopeGap {
		t.Fatalf("round trip = %+v", back)
	}
}
