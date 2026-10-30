package evaluator

import (
	"context"
	"strings"
	"testing"
)

func verifiedFact(id, subj, pred, value string) RuleFact {
	return RuleFact{
		ID: id, Subject: subj, Kind: RuleFactKindObservation,
		Predicate: pred, Value: value, Status: "VERIFIED",
		Coverage: "COMPLETE", Digest: strings.Repeat("ab", 32),
	}
}

func mustEvalCond(t *testing.T, r *AdapterRegistry, c ConditionInput, facts []RuleFact) RuleResult {
	t.Helper()
	res, err := r.EvaluateCondition(context.Background(), c, facts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestRuleAdapterEvaluation pins the fail-closed semantics: registered
// conditions decide ESTABLISHED only over verified, complete, digested
// establishing facts per subject; UNKNOWN and CONTRADICTED are the
// named fallbacks, never silent defaults.
func TestRuleAdapterEvaluation(t *testing.T) {
	reg := DefaultAdapterRegistry()
	subj := "package:example.com/dep|example.com/dep/vuln"
	cond := ConditionInput{ID: "package-linked", Role: "applicability", Polarity: "POSITIVE",
		Required: true, SubjectRefs: []string{subj}}

	t.Run("established", func(t *testing.T) {
		res := mustEvalCond(t, reg, cond, []RuleFact{
			verifiedFact("fact-1", subj, PredicateProductClosureMembership, "linked")})
		if res.Status != RuleEstablished || len(res.FactRefs) != 1 || res.FactRefs[0] != "fact-1" {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("unknown-no-fact", func(t *testing.T) {
		res := mustEvalCond(t, reg, cond, nil)
		if res.Status != RuleUnknown || len(res.Limitations) != 1 {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("unknown-no-subjects", func(t *testing.T) {
		res := mustEvalCond(t, reg, ConditionInput{ID: "package-linked"}, nil)
		if res.Status != RuleUnknown || len(res.Limitations) != 1 {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("contradicted", func(t *testing.T) {
		res := mustEvalCond(t, reg, cond, []RuleFact{
			verifiedFact("fact-2", subj, PredicateProductClosureMembership, "absent-verified")})
		if res.Status != RuleContradicted || len(res.Contradictions) != 1 {
			t.Fatalf("res=%+v", res)
		}
	})
	// Degraded/unbound facts never establish — they surface as
	// limitations, the same way an absent fact does.
	for _, tc := range []struct {
		name string
		fact RuleFact
	}{
		{"status-not-verified", func() RuleFact {
			f := verifiedFact("f", subj, PredicateProductClosureMembership, "linked")
			f.Status = "DEGRADED"
			return f
		}()},
		{"partial-coverage", func() RuleFact {
			f := verifiedFact("f", subj, PredicateProductClosureMembership, "linked")
			f.Coverage = "PARTIAL"
			return f
		}()},
		{"no-digest", func() RuleFact {
			f := verifiedFact("f", subj, PredicateProductClosureMembership, "linked")
			f.Digest = ""
			return f
		}()},
		{"unclassified-value", verifiedFact("f", subj, PredicateProductClosureMembership, "unclassified")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := mustEvalCond(t, reg, cond, []RuleFact{tc.fact})
			if res.Status != RuleUnknown || len(res.Limitations) == 0 {
				t.Fatalf("res=%+v", res)
			}
		})
	}
}

// TestRuleAdapterRegisteredRules: the deterministic negative rules
// (module absent from graph, subject absent from product closure) are
// establishable only on the typed verified values — and contradict on
// their opposites.
func TestRuleAdapterRegisteredRules(t *testing.T) {
	reg := DefaultAdapterRegistry()
	subj := "module:example.com/dep"
	rc := func(facts ...RuleFact) RuleContext {
		return RuleContext{
			Facts:      facts,
			Conditions: []ConditionInput{{ID: "c", SubjectRefs: []string{subj}}},
		}
	}
	t.Run("module-absent-established", func(t *testing.T) {
		res, err := reg.EvaluateRule(context.Background(), "rule.module-absent-from-graph",
			rc(verifiedFact("f-1", subj, PredicateModulePresent, "false")))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != RuleEstablished {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("module-absent-contradicted", func(t *testing.T) {
		res, err := reg.EvaluateRule(context.Background(), "rule.module-absent-from-graph",
			rc(verifiedFact("f-1", subj, PredicateModulePresent, "true")))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != RuleContradicted {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("module-absent-unknown", func(t *testing.T) {
		res, err := reg.EvaluateRule(context.Background(), "rule.module-absent-from-graph",
			rc(verifiedFact("f-1", subj, PredicateModulePresent, "unknown")))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != RuleUnknown {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("source-usage-positive-lowerbound-establishes", func(t *testing.T) {
		res, err := reg.EvaluateRule(context.Background(), "rule.subject-used-by-product-source",
			rc(verifiedFact("f-1", subj, PredicateProductSourceUsage, "positive-lowerbound")))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != RuleEstablished {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("not-used-verified-contradicts-used-rule", func(t *testing.T) {
		res, err := reg.EvaluateRule(context.Background(), "rule.subject-used-by-product-source",
			rc(verifiedFact("f-1", subj, PredicateProductSourceUsage, "not-used-verified")))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != RuleContradicted {
			t.Fatalf("res=%+v", res)
		}
	})
	t.Run("no-subjects-in-context", func(t *testing.T) {
		res, err := reg.EvaluateRule(context.Background(), "rule.module-absent-from-graph", RuleContext{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != RuleUnknown {
			t.Fatalf("res=%+v", res)
		}
	})
}

// TestRuleAdapterFailClosedRegistration pins the registration gates:
// unknown ids are evaluation errors, malformed/duplicate registrations
// panic, and a rule that cannot establish its proposition is UNKNOWN —
// never a permissive default.
func TestRuleAdapterFailClosedRegistration(t *testing.T) {
	reg := DefaultAdapterRegistry()
	if _, err := reg.EvaluateCondition(context.Background(),
		ConditionInput{ID: "never-registered"}, nil); err == nil {
		t.Fatal("unregistered condition evaluated without error")
	}
	if _, err := reg.EvaluateRule(context.Background(), "rule.nope", RuleContext{}); err == nil {
		t.Fatal("unregistered rule evaluated without error")
	}
	if !reg.HasCondition("module-present") || !reg.HasRule("rule.subject-not-used-by-product-source") {
		t.Fatal("baseline adapters missing")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("malformed registration did not panic")
		}
	}()
	NewAdapterRegistry().registerCondition("bad", conditionSpec{})
}

// TestSubjectGranularity pins subject identity as part of the adapter
// contract: a package-level fact never satisfies a module- or
// symbol-level subject, and subjects are matched verbatim — no
// prefix-or-parent inference exists anywhere in the adapter.
func TestSubjectGranularity(t *testing.T) {
	reg := DefaultAdapterRegistry()
	cond := ConditionInput{ID: "package-linked", SubjectRefs: []string{
		"module:example.com/dep",
		"package:example.com/dep|example.com/dep/vuln",
	}}
	// Only the package-level fact exists: the module-level subject
	// stays UNKNOWN, so the whole condition is UNKNOWN (not half-true).
	res := mustEvalCond(t, reg, cond, []RuleFact{
		verifiedFact("f-pkg", "package:example.com/dep|example.com/dep/vuln",
			PredicateProductClosureMembership, "linked")})
	if res.Status != RuleUnknown || len(res.FactRefs) != 1 || len(res.Limitations) != 1 {
		t.Fatalf("res=%+v", res)
	}
	// And a module-level fact over the same module does not satisfy
	// the package subject either.
	res = mustEvalCond(t, reg, ConditionInput{ID: "package-linked",
		SubjectRefs: []string{"package:example.com/dep|example.com/dep/vuln"}},
		[]RuleFact{verifiedFact("f-mod", "module:example.com/dep",
			PredicateModulePresent, "true")})
	if res.Status != RuleUnknown {
		t.Fatalf("res=%+v", res)
	}
}
