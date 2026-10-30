package triage

import (
	"context"
	"errors"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

func TestMandatoryConditionSourceDeterministicOnly(t *testing.T) {
	src, err := NewConfiguredMandatoryConditionSource(MandatoryConditionSourceOptions{
		Models:           map[string]domain.ExploitModel{"ADV-1": {MandatoryConditions: []domain.Condition{{ID: "cond-1", Kind: domain.ConditionMissingCall, Mandatory: true, Subject: &domain.SymbolRef{Package: "p", Symbol: "S"}}}}},
		RuleID:           "rule",
		RuleVersion:      "v1",
		RuleSetHash:      "rules-1",
		Module:           "example.org/mod",
		ResolvedVersion:  "v1.0.0",
		SnapshotHash:     "snap-1",
		BuildContextHash: "build-1",
	})
	if err != nil {
		t.Fatalf("configured source: %v", err)
	}
	p := FalsifierProposal{ConditionID: "cond-1", Kind: FalsifierCodeAbsent}
	c, err := src.Resolve(context.Background(), MandatoryConditionLookup{AdvisoryID: "ADV-1", Module: "example.org/mod", ResolvedVersion: "v1.0.0", SnapshotHash: "snap-1", Proposal: p})
	if err != nil || !c.Mandatory || c.RuleID != "rule" || c.RuleVersion != "v1" {
		t.Fatalf("condition=%+v err=%v", c, err)
	}
}

// TestMandatoryConditionSourceUnconfiguredIsFailClosed pins the honest failure
// mode of the diagnostic constructor: without ruleset, snapshot and
// build-context bindings it can never resolve a condition that a proof could
// rest on.
func TestMandatoryConditionSourceUnconfiguredIsFailClosed(t *testing.T) {
	src := NewModelMandatoryConditionSource(map[string]domain.ExploitModel{"A": {MandatoryConditions: []domain.Condition{{ID: "c", Kind: domain.ConditionMissingCall, Mandatory: true, Subject: &domain.SymbolRef{Package: "p", Symbol: "S"}}}}}, "rule", "v1")
	if _, err := src.Resolve(context.Background(), MandatoryConditionLookup{AdvisoryID: "A", Proposal: FalsifierProposal{ConditionID: "c"}}); !errors.Is(err, ErrMandatorySourceUnbound) {
		t.Fatalf("unbound source resolved: err=%v", err)
	}
}

// TestMandatoryConditionSourceConfigurationRequired pins constructor
// validation: a partially bound production source is refused outright.
func TestMandatoryConditionSourceConfigurationRequired(t *testing.T) {
	models := map[string]domain.ExploitModel{"A": {MandatoryConditions: []domain.Condition{{ID: "c", Kind: domain.ConditionMissingCall, Mandatory: true, Subject: &domain.SymbolRef{Package: "p", Symbol: "S"}}}}}
	full := MandatoryConditionSourceOptions{Models: models, RuleID: "r", RuleVersion: "v1", RuleSetHash: "rules-1", Module: "m", ResolvedVersion: "v1.0.0", SnapshotHash: "snap-1", BuildContextHash: "build-1"}
	if _, err := NewConfiguredMandatoryConditionSource(full); err != nil {
		t.Fatalf("complete options rejected: %v", err)
	}
	for name, mutate := range map[string]func(o *MandatoryConditionSourceOptions){
		"models":  func(o *MandatoryConditionSourceOptions) { o.Models = nil },
		"rule":    func(o *MandatoryConditionSourceOptions) { o.RuleVersion = "" },
		"ruleset": func(o *MandatoryConditionSourceOptions) { o.RuleSetHash = "" },
		"module":  func(o *MandatoryConditionSourceOptions) { o.Module = "" },
		"version": func(o *MandatoryConditionSourceOptions) { o.ResolvedVersion = "" },
		"snapshot": func(o *MandatoryConditionSourceOptions) {
			o.SnapshotHash = ""
		},
		"build": func(o *MandatoryConditionSourceOptions) { o.BuildContextHash = "" },
	} {
		o := full
		mutate(&o)
		if _, err := NewConfiguredMandatoryConditionSource(o); err == nil {
			t.Fatalf("%s binding missing but source created", name)
		}
	}
}
func TestMandatoryConditionSourceUnsupported(t *testing.T) {
	src := NewModelMandatoryConditionSource(nil, "rule", "v1")
	if _, err := src.Resolve(context.Background(), MandatoryConditionLookup{AdvisoryID: "missing", Proposal: FalsifierProposal{ConditionID: "c"}}); err == nil {
		t.Fatal("expected unsupported source")
	}
	configured, err := NewConfiguredMandatoryConditionSource(MandatoryConditionSourceOptions{
		Models:           map[string]domain.ExploitModel{"A": {MandatoryConditions: []domain.Condition{{ID: "c", Kind: domain.ConditionMissingCall, Mandatory: true, Subject: &domain.SymbolRef{Package: "p", Symbol: "S"}}}}},
		RuleID:           "rule",
		RuleVersion:      "v1",
		RuleSetHash:      "rules-1",
		Module:           "example.org/mod",
		ResolvedVersion:  "v1.0.0",
		SnapshotHash:     "snap-1",
		BuildContextHash: "build-1",
	})
	if err != nil {
		t.Fatalf("configured source: %v", err)
	}
	if _, err := configured.Resolve(context.Background(), MandatoryConditionLookup{AdvisoryID: "missing", Module: "example.org/mod", ResolvedVersion: "v1.0.0", SnapshotHash: "snap-1", Proposal: FalsifierProposal{ConditionID: "c"}}); err == nil {
		t.Fatal("expected unsupported advisory")
	}
}
func TestMandatoryConditionSourceRuleStability(t *testing.T) {
	src, err := NewConfiguredMandatoryConditionSource(MandatoryConditionSourceOptions{
		Models:           map[string]domain.ExploitModel{"A": {MandatoryConditions: []domain.Condition{{ID: "c", Kind: domain.ConditionMissingCall, Mandatory: true, Subject: &domain.SymbolRef{Package: "p", Symbol: "S"}}}}},
		RuleID:           "rule-1",
		RuleVersion:      "2026-01",
		RuleSetHash:      "rules-1",
		Module:           "example.org/mod",
		ResolvedVersion:  "v1.0.0",
		SnapshotHash:     "snap-1",
		BuildContextHash: "build-1",
	})
	if err != nil {
		t.Fatalf("configured source: %v", err)
	}
	c, _ := src.Resolve(context.Background(), MandatoryConditionLookup{AdvisoryID: "A", Module: "example.org/mod", ResolvedVersion: "v1.0.0", SnapshotHash: "snap-1", Proposal: FalsifierProposal{ConditionID: "c"}})
	if c.RuleID != "rule-1" || c.RuleVersion != "2026-01" {
		t.Fatalf("unstable rule identity: %+v", c)
	}
}
