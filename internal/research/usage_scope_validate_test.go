package research

import (
	"strings"
	"testing"
	"time"
)

func TestUsageScopeFactValidation(t *testing.T) {
	base := scopeFact("OBS-0041", "example.com/m", "example.com/m/p", string(UsageScopeTestOnly), ProductAbsenceVerificationVerified)
	cases := []struct {
		name string
		mut  func(*VerifiedFact)
		bad  bool
	}{
		{"positive complete test-only", func(*VerifiedFact) {}, false},
		{"kind tool mismatch", func(f *VerifiedFact) { f.Tool = "package-usage" }, true},
		{"symbol subject", func(f *VerifiedFact) { f.UsageSubject.Symbol = "S" }, true},
		{"claim false", func(f *VerifiedFact) { f.Claim = "FALSE" }, true},
		{"negative verification", func(f *VerifiedFact) { f.NegativeVerification = NegativeVerificationVerified }, true},
		{"test-only without product absence", func(f *VerifiedFact) { f.ProductAbsenceVerification = "" }, true},
		{"invalid product absence marker", func(f *VerifiedFact) { f.ProductAbsenceVerification = "MAYBE" }, true},
		{"partial coverage", func(f *VerifiedFact) { f.Coverage = "PARTIAL" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			if base.UsageSubject != nil {
				s := *base.UsageSubject
				f.UsageSubject = &s
			}
			tc.mut(&f)
			var e ValidationError
			validateBuildUsageScopeFact(&e, f, "fact")
			if got := len(e.Problems) != 0; got != tc.bad {
				t.Fatalf("invalid=%v, want %v: %v", got, tc.bad, e.Problems)
			}
		})
	}
}

// The product-absence marker validity table is exact:
// VERIFIED ⇔ test-only, VERIFIED_VENDOR_INVENTORY ⇔ unknown, and every
// other (scope, marker) combination — including an unknown fact that
// carries no marker at all — validates or rejects exactly as tabled.
func TestUsageScopeVendorMarkerValidation(t *testing.T) {
	validUnknown := scopeFact("OBS-0051", "example.com/m", "example.com/m/p",
		string(UsageScopeUnknown), ProductAbsenceVerificationVendorInventory)
	cases := []struct {
		name  string
		scope string
		mark  string
		bad   bool
	}{
		{"test-only + VERIFIED", string(UsageScopeTestOnly), ProductAbsenceVerificationVerified, false},
		{"test-only + vendor marker", string(UsageScopeTestOnly), ProductAbsenceVerificationVendorInventory, true},
		{"test-only without marker", string(UsageScopeTestOnly), "", true},
		{"unknown + vendor marker", string(UsageScopeUnknown), ProductAbsenceVerificationVendorInventory, false},
		{"unknown without marker", string(UsageScopeUnknown), "", false},
		{"unknown + VERIFIED", string(UsageScopeUnknown), ProductAbsenceVerificationVerified, true},
		{"unknown + forged marker", string(UsageScopeUnknown), "VERIFIED_VENDOR_TREE", true},
		{"product + vendor marker", string(UsageScopeProduct), ProductAbsenceVerificationVendorInventory, true},
		{"product + VERIFIED", string(UsageScopeProduct), ProductAbsenceVerificationVerified, true},
		{"mixed + vendor marker", string(UsageScopeMixed), ProductAbsenceVerificationVendorInventory, true},
		{"invalid scope + vendor marker", "totally", ProductAbsenceVerificationVendorInventory, true},
		{"invalid scope + VERIFIED", "totally", ProductAbsenceVerificationVerified, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validUnknown
			s := *validUnknown.UsageSubject
			f.UsageSubject = &s
			f.UsageScope = tc.scope
			f.ProductAbsenceVerification = tc.mark
			var e ValidationError
			validateBuildUsageScopeFact(&e, f, "fact")
			if got := len(e.Problems) != 0; got != tc.bad {
				t.Fatalf("invalid=%v, want %v: %v", got, tc.bad, e.Problems)
			}
		})
	}
}

func TestUsageScopeAxisValidation(t *testing.T) {
	lane := fakeLane(t)
	lane.Facts = append(lane.Facts, scopeFact("OBS-0042", "example.com/m", "example.com/m/p", string(UsageScopeTestOnly), ProductAbsenceVerificationVerified))
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "axis-validation"})
	if r.ExploitationAxes.BuildUsageScope == nil {
		t.Fatal("expected build usage axis")
	}
	r.ExploitationAxes.BuildUsageScope.Statement = "forged"
	var e ValidationError
	validateBuildUsageScopeAxis(&e, r)
	if len(e.Problems) == 0 {
		t.Fatal("forged axis accepted")
	}
}

// A BUILD_USAGE_SCOPE fact is strictly non-carrier: it can never be
// cited by ANY exploitation condition (not only the B42 usage
// predicate), never enter evidence_level.evidence_refs, and never
// count as a confirmed path transition.
func TestUsageScopeNonCarrierCitation(t *testing.T) {
	b41 := scopeFact("OBS-0044", "example.com/m", "example.com/m/p", string(UsageScopeProduct), "")
	build := func() *Report {
		lane := fakeLane(t)
		lane.Facts = append(lane.Facts, b41)
		return Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "non-carrier",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
	}

	t.Run("control report validates", func(t *testing.T) {
		if err := Validate(build(), ""); err != nil {
			t.Fatalf("pristine report invalid:\n%v", err)
		}
	})

	t.Run("non-B42 deterministic condition citing a B41 fact is rejected", func(t *testing.T) {
		r := build()
		var target *ExploitationCondition
		for i := range r.ExploitationConditions {
			c := &r.ExploitationConditions[i]
			if c.Origin == OriginDeterm && c.Subject != subjProductPackageUsage {
				target = c
				break
			}
		}
		if target == nil {
			t.Fatal("fixture has no non-B42 deterministic condition")
		}
		target.EvidenceRefs = append(target.EvidenceRefs, b41.ID)
		err := Validate(r, "")
		if err == nil || !strings.Contains(err.Error(), "BUILD_USAGE_SCOPE") {
			t.Fatalf("B41 fact cited by %q accepted:\n%v", target.Subject, err)
		}
	})

	t.Run("B42 usage condition citing a B41 fact is rejected", func(t *testing.T) {
		r := build()
		r.ExploitationConditions = append(r.ExploitationConditions, ExploitationCondition{
			ID: "EC-B41", Subject: subjProductPackageUsage,
			Origin: OriginDeterm, State: StateUnknown, Necessity: "required",
			Role: ConditionRolePath, Axis: ECAxisCodeReachability,
			Scope:        "bounded product source scope",
			UsageSubject: &FactUsageSubject{Module: "example.com/m", Package: "example.com/m/p"},
			EvidenceRefs: []string{b41.ID},
			Limitations:  []string{"the unresolved usage check is never negative proof"},
		})
		err := Validate(r, "")
		if err == nil || !strings.Contains(err.Error(), "BUILD_USAGE_SCOPE") {
			t.Fatalf("B41 fact cited by the B42 usage condition accepted:\n%v", err)
		}
	})

	t.Run("evidence_level containing a B41 ref is rejected", func(t *testing.T) {
		r := build()
		if r.EvidenceLevel == nil {
			t.Fatal("fixture report has no evidence_level")
		}
		r.EvidenceLevel.EvidenceRefs = append(r.EvidenceLevel.EvidenceRefs, b41.ID)
		err := Validate(r, "")
		if err == nil ||
			!strings.Contains(err.Error(), "evidence_level.evidence_refs") ||
			!strings.Contains(err.Error(), "BUILD_USAGE_SCOPE") {
			t.Fatalf("evidence_level citing a B41 fact accepted:\n%v", err)
		}
	})
}
