package triage

import (
	"context"
	"errors"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// TestFalsifierVerifierVerifiedViaConfiguredSource pins the production path:
// a fully bound deterministic source (ruleset, module, version, snapshot and
// build context) can admit a proof, while the unbound diagnostic constructor
// never can.
func TestFalsifierVerifierVerifiedViaConfiguredSource(t *testing.T) {
	models := map[string]domain.ExploitModel{
		"ADV-1": {MandatoryConditions: []domain.Condition{{
			ID:        "cond-1",
			Kind:      domain.ConditionMissingCall,
			Mandatory: true,
			Subject:   &domain.SymbolRef{Package: "example.org/p", Symbol: "Control"},
		}}},
	}
	_, buildHash := currentInventoryFixture("snap-1")
	opts := MandatoryConditionSourceOptions{
		Models:           models,
		RuleID:           "rule-1",
		RuleVersion:      "v1",
		RuleSetHash:      "rules-1",
		Module:           "example.org/mod",
		ResolvedVersion:  "v1.0.0",
		SnapshotHash:     "snap-1",
		BuildContextHash: buildHash,
	}
	src, err := NewConfiguredMandatoryConditionSource(opts)
	if err != nil {
		t.Fatalf("configured source: %v", err)
	}
	in, _ := verifierFixture(FalsifierCodeAbsent, src)
	p := runProof(t, in, src)
	if p.Status != FalsifierVerified || p.Basis != BasisCheckerVerified || p.RuleID != "rule-1" {
		t.Fatalf("configured source did not admit: %+v", p)
	}

	for name, mutate := range map[string]func(o *MandatoryConditionSourceOptions){
		"ruleset":  func(o *MandatoryConditionSourceOptions) { o.RuleSetHash = "" },
		"snapshot": func(o *MandatoryConditionSourceOptions) { o.SnapshotHash = "" },
		"build":    func(o *MandatoryConditionSourceOptions) { o.BuildContextHash = "" },
		"module":   func(o *MandatoryConditionSourceOptions) { o.Module = "" },
		"version":  func(o *MandatoryConditionSourceOptions) { o.ResolvedVersion = "" },
		"rule":     func(o *MandatoryConditionSourceOptions) { o.RuleVersion = "" },
		"models":   func(o *MandatoryConditionSourceOptions) { o.Models = nil },
	} {
		o := opts
		mutate(&o)
		if _, err := NewConfiguredMandatoryConditionSource(o); err == nil {
			t.Fatalf("incomplete %s binding produced a source", name)
		}
	}

	unbound := NewModelMandatoryConditionSource(models, "rule-1", "v1")
	unboundIn, _ := verifierFixture(FalsifierCodeAbsent, unbound)
	if p := runProof(t, unboundIn, unbound); p.Status == FalsifierVerified {
		t.Fatalf("unbound diagnostic source admitted a proof: %+v", p)
	}
	if _, err := unbound.Resolve(context.Background(), MandatoryConditionLookup{AdvisoryID: "ADV-1", Module: "example.org/mod", ResolvedVersion: "v1.0.0", SnapshotHash: "snap-1", Proposal: FalsifierProposal{ConditionID: "cond-1", Kind: FalsifierCodeAbsent}}); !errors.Is(err, ErrMandatorySourceUnbound) {
		t.Fatalf("unbound source resolved instead of failing closed: %v", err)
	}
}

// TestObservationStoreStampsRunIdentity pins the end-to-end run stamping the
// verifier relies on: observations recorded through the real store carry the
// owning run id and attempt, so evidence from another run can be rejected.
func TestObservationStoreStampsRunIdentity(t *testing.T) {
	store := NewRunObservationStore(AttemptRunID("finding-1", 2), 2)
	rec, ok := store.(observationRecorder)
	if !ok {
		t.Fatal("store does not record observations")
	}
	rec.record(ToolObservation{ID: "det-1", Tool: "verify_code_absence", Status: ToolStatusOK, Coverage: "COMPLETE"})
	got := store.Observations()
	if len(got) != 1 {
		t.Fatalf("observations=%d", len(got))
	}
	if want := AttemptRunID("finding-1", 2); got[0].RunID != want {
		t.Fatalf("run id = %q, want %q", got[0].RunID, want)
	}
	if got[0].Attempt != 2 {
		t.Fatalf("attempt = %d, want 2", got[0].Attempt)
	}
	// An observation carrying its own run identity keeps it: the store never
	// rewrites provenance it was handed.
	rec.record(ToolObservation{ID: "det-2", RunID: "explicit-run", Attempt: 3})
	got = store.Observations()
	if got[1].RunID != "explicit-run" || got[1].Attempt != 3 {
		t.Fatalf("explicit provenance overwritten: %+v", got[1])
	}

	// The verifier rejects evidence stamped with another run and admits the
	// same evidence when the identity matches.
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.RunID = "another-run"
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal("foreign-run observation admitted")
	}
	o.RunID = in.RunID
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status != FalsifierVerified {
		t.Fatal("matching run identity rejected")
	}
}

// TestFalsifierVerifierUsesResolvedModuleVersion pins the intake-gap fallback:
// a finding that names no component version still binds to the module version
// the snapshot's module graph resolved — the identity the deterministic tools
// recorded — instead of an empty string that would disable admission.
func TestFalsifierVerifierUsesResolvedModuleVersion(t *testing.T) {
	_, buildHash := currentInventoryFixture("snap-1")
	src, err := NewAdvisoryConditionSource(AdvisoryConditionOptions{
		AdvisoryID:       "ADV-1",
		Module:           "example.org/mod",
		ResolvedVersion:  "v1.0.0",
		SnapshotHash:     "snap-1",
		BuildContextHash: buildHash,
		RuleID:           "advisory-code-absence",
		RuleVersion:      "1",
		RuleSetHash:      "rules-1",
		Symbols:          []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}},
	})
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	in, _ := verifierFixture(FalsifierCodeAbsent, src)
	in.Proposals[0].ConditionID = AdvisoryConditionID("ADV-1")
	in.Stage0.Input.Finding.Component.Version = ""
	in.Stage0.PackageCheck = PackageCheckResult{
		Class:           CheckVersionConfirmed,
		ClaimedPath:     "example.org/p",
		ResolvedPath:    "example.org/mod",
		ResolvedVersion: "v1.0.0",
	}
	if got := runProof(t, in, src); got.Status != FalsifierVerified {
		t.Fatalf("resolved-version fallback did not admit: %+v", got)
	}

	// Without a resolved version the proof stays impossible: the source is
	// bound to a concrete version and an empty lookup never matches it.
	in.Stage0.PackageCheck.ResolvedVersion = ""
	if got := runProof(t, in, src); got.Status == FalsifierVerified {
		t.Fatalf("empty resolved version admitted: %+v", got)
	}
}
