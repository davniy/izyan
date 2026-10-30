package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func advisoryOptions() AdvisoryConditionOptions {
	return AdvisoryConditionOptions{
		AdvisoryID:       "GO-2026-4762",
		Module:           "google.golang.org/grpc",
		ResolvedVersion:  "v1.58.3",
		SnapshotHash:     "snap-1",
		BuildContextHash: "build-1",
		RuleID:           "advisory-code-absence",
		RuleVersion:      "1",
		RuleSetHash:      "rules-1",
		Symbols: []FalsifierSubject{
			{Package: "google.golang.org/grpc", Symbol: "Server.Serve"},
			{Package: "google.golang.org/grpc/internal/transport", Symbol: "NewServerTransport"},
		},
	}
}

// TestAdvisoryConditionSourceResolvesDeclaredSymbols pins the deterministic
// contract: the condition comes from the advisory's declared symbols, is
// marked mandatory, and carries the exact bindings the caller configured.
func TestAdvisoryConditionSourceResolvesDeclaredSymbols(t *testing.T) {
	src, err := NewAdvisoryConditionSource(advisoryOptions())
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if got, want := src.RuleSetHash(), "rules-1"; got != want {
		t.Fatalf("ruleset = %q, want %q", got, want)
	}
	cond, err := src.Resolve(context.Background(), MandatoryConditionLookup{
		AdvisoryID:      "GO-2026-4762",
		Module:          "google.golang.org/grpc",
		ResolvedVersion: "v1.58.3",
		SnapshotHash:    "snap-1",
		Proposal:        FalsifierProposal{ConditionID: AdvisoryConditionID("GO-2026-4762"), Kind: FalsifierCodeAbsent},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !cond.Mandatory || cond.Kind != FalsifierCodeAbsent {
		t.Fatalf("condition = %+v", cond)
	}
	if cond.ID != "cond-GO-2026-4762" {
		t.Fatalf("condition id = %q", cond.ID)
	}
	if len(cond.ExpectedSubjects) != 2 {
		t.Fatalf("expected subjects = %+v", cond.ExpectedSubjects)
	}
	if cond.SnapshotHash != "snap-1" || cond.BuildContextHash != "build-1" {
		t.Fatalf("bindings lost: %+v", cond)
	}
}

// TestAdvisoryConditionSourceIsFailClosed pins every refusal: no advisory id,
// no declared symbols, an unbound source, a wrong condition id, and a
// mismatched module/version/snapshot all resolve to an error — never to a
// condition the verifier could admit.
func TestAdvisoryConditionSourceIsFailClosed(t *testing.T) {
	if _, err := NewAdvisoryConditionSource(func() AdvisoryConditionOptions {
		o := advisoryOptions()
		o.Symbols = nil
		return o
	}()); err == nil {
		t.Fatal("source without declared symbols was created")
	}
	if _, err := NewAdvisoryConditionSource(func() AdvisoryConditionOptions {
		o := advisoryOptions()
		o.AdvisoryID = " "
		return o
	}()); err == nil {
		t.Fatal("source without advisory id was created")
	}
	for name, mutate := range map[string]func(o *AdvisoryConditionOptions){
		"ruleset": func(o *AdvisoryConditionOptions) { o.RuleSetHash = "" },
		"module":  func(o *AdvisoryConditionOptions) { o.Module = "" },
		"version": func(o *AdvisoryConditionOptions) { o.ResolvedVersion = "" },
		"snapshot": func(o *AdvisoryConditionOptions) {
			o.SnapshotHash = ""
		},
		"build": func(o *AdvisoryConditionOptions) { o.BuildContextHash = "" },
	} {
		o := advisoryOptions()
		mutate(&o)
		if _, err := NewAdvisoryConditionSource(o); err == nil {
			t.Fatalf("%s binding missing but source was created", name)
		}
	}

	src, err := NewAdvisoryConditionSource(advisoryOptions())
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	lookup := MandatoryConditionLookup{
		AdvisoryID:      "GO-2026-4762",
		Module:          "google.golang.org/grpc",
		ResolvedVersion: "v1.58.3",
		SnapshotHash:    "snap-1",
		Proposal:        FalsifierProposal{ConditionID: "cond-somethingelse"},
	}
	if _, err := src.Resolve(context.Background(), lookup); err == nil || !strings.Contains(err.Error(), "is not") {
		t.Fatalf("wrong condition id resolved: %v", err)
	}
	lookup.Proposal.ConditionID = AdvisoryConditionID("GO-2026-4762")
	for name, mutate := range map[string]func(l *MandatoryConditionLookup){
		"advisory": func(l *MandatoryConditionLookup) { l.AdvisoryID = "OTHER-1" },
		"module":   func(l *MandatoryConditionLookup) { l.Module = "other.module" },
		"version":  func(l *MandatoryConditionLookup) { l.ResolvedVersion = "v9.9.9" },
		"snapshot": func(l *MandatoryConditionLookup) { l.SnapshotHash = "other-snap" },
	} {
		l := lookup
		mutate(&l)
		if _, err := src.Resolve(context.Background(), l); err == nil {
			t.Fatalf("%s mismatch resolved", name)
		}
	}
}

// TestAdvisoryConditionSourceUnboundIsFailClosed pins that a zero-valued
// source can never resolve, whatever the caller asks for.
func TestAdvisoryConditionSourceUnboundIsFailClosed(t *testing.T) {
	if _, err := (AdvisoryConditionSource{}).Resolve(context.Background(), MandatoryConditionLookup{}); err == nil {
		t.Fatal("unbound advisory source resolved a condition")
	}
}

// TestAdvisoryConditionSourceFeedsVerifier pins the end-to-end contract of
// the new source: with the verifier's other gates satisfied, a proposal that
// names the advisory's declared symbol is admitted. A proposal that invents
// a subject does not die on the mismatch — the check runs on the
// authoritative affected_symbols alone — but an observation covering only
// the invented subject is no proof either: the verifier never checks the
// agent's own list.
func TestAdvisoryConditionSourceFeedsVerifier(t *testing.T) {
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
	adapt := func(in *FalsifierVerificationInput) {
		in.Proposals[0].ConditionID = AdvisoryConditionID("ADV-1")
		in.Assessment.Claims = append([]Claim(nil), in.Assessment.Claims...)
	}
	in, _ := verifierFixture(FalsifierCodeAbsent, src)
	adapt(&in)
	p := runProof(t, in, src)
	if p.Status != FalsifierVerified {
		t.Fatalf("declared-symbol proposal rejected: %+v", p)
	}
	if p.ConditionID != "cond-ADV-1" || !p.Mandatory || p.RuleID != "advisory-code-absence" {
		t.Fatalf("proof identity = %+v", p)
	}

	// An invented extra subject is ignored: verification still runs against
	// the advisory's affected_symbols and the substitution is recorded.
	fabricated, _ := verifierFixture(FalsifierCodeAbsent, src)
	adapt(&fabricated)
	fabricated.Proposals[0].Subjects = append(fabricated.Proposals[0].Subjects,
		FalsifierSubject{Package: "evil.example", Symbol: "Unrelated"})
	got := runProof(t, fabricated, src)
	if got.Status != FalsifierVerified {
		t.Fatalf("authoritative check refused over invented subject: %+v", got)
	}
	for _, s := range got.Coverage.ExpectedSubjects {
		if s.Package == "evil.example" || s.Symbol == "Unrelated" {
			t.Fatalf("invented subject checked: %+v", got.Coverage)
		}
	}

	// An observation covering only the invented set never proves the
	// advisory's symbols absent.
	fabricated2, o2 := verifierFixture(FalsifierCodeAbsent, src)
	adapt(&fabricated2)
	fabricated2.Proposals[0].Subjects = []FalsifierSubject{{Package: "evil.example", Symbol: "Unrelated"}}
	o2.Payload = json.RawMessage(`{"checked_subjects":[{"package":"evil.example","symbol":"Unrelated"}]}`)
	fabricated2.Observations = []RecordedObservation{*o2}
	if p := runProof(t, fabricated2, src); p.Status == FalsifierVerified {
		t.Fatalf("invented subject admitted: %+v", p)
	}
}
