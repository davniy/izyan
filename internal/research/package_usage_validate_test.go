package research

import (
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// refutedUsageReport assembles a valid /3 report whose single package
// usage condition is REFUTED on a VERIFIED negative under a COMPLETE
// recorded scope; the promoted fact is claim=FALSE +
// negative_verification=VERIFIED + coverage=COMPLETE.
func refutedUsageReport(t *testing.T) *Report {
	t.Helper()
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	lane := usageLane(t, module, pkg, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", module, pkg, "", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
		},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			usageFact("OBS-0020", module, pkg, "", "FALSE", NegativeVerificationVerified, "no product-source use of "+pkg),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "puv-refuted",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("refuted baseline report invalid:\n%v", err)
	}
	return r
}

// absentUsageReport assembles a valid /3 report whose package usage
// condition is REFUTED on the closure-absence basis: the usage payload
// records present=false under a COMPLETE scope (the target is provably
// absent from the complete product closure), the promoted fact is
// claim=FALSE + negative_verification=VERIFIED + coverage=COMPLETE +
// usage_basis=absent_from_closure, and the applicability probe's own
// package_not_in_import_closure basis legitimately carries
// vulnerable_code_reachability=FALSE with a SUPPORTED NON_APPLICABLE
// classification.
func absentUsageReport(t *testing.T) *Report {
	t.Helper()
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	o := usageObs("OBS-0020", module, pkg, "", "NOT_USED", "VERIFIED", evidencetools.CompletenessComplete)
	o.Data.(map[string]any)["present"] = false
	f := usageFact("OBS-0020", module, pkg, "", "FALSE", NegativeVerificationVerified,
		pkg+" is provably absent from the complete product closure")
	f.UsageBasis = UsageBasisAbsentFromClosure
	lane := usageLane(t, module, pkg, nil,
		[]*evidencetools.Observation{o},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected; "+pkg+" not imported"),
			f,
		})
	lane.Affected.PackagePresent = domain.ClaimFalse
	lane.Affected.BuildRelevant = domain.ClaimFalse
	lane.Affected.CheckedPackages = []string{pkg}
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane,
		Turn:  turnWith(t, "code_not_present", "the affected package never links into product code", nil),
		RunID: "puv-absent", StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("absent-basis baseline report invalid:\n%v", err)
	}
	return r
}

// usedUsageReport assembles a valid /3 report whose package usage
// condition is SUPPORTED on a USED verdict: the TRUE PACKAGE_USAGE fact
// is a static carrier and closes the path at L1.
func usedUsageReport(t *testing.T) *Report {
	t.Helper()
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	lane := usageLane(t, module, pkg, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", module, pkg, "", "USED", "", evidencetools.CompletenessPartial),
		},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			usageFact("OBS-0020", module, pkg, "", "TRUE", "", "package "+pkg+" used by product source"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "puv-used",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("used baseline report invalid:\n%v", err)
	}
	return r
}

// agentUsageReport assembles a valid /3 report with a canonical agent
// usage hypothesis (OPEN path condition citing only agent material)
// beside the deterministic UNKNOWN usage condition.
func agentUsageReport(t *testing.T) *Report {
	t.Helper()
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	turn := turnWith(t, "vulnerable", "the product calls the vulnerable symbol",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{
					map[string]any{
						"statement": "the product invokes the vulnerable entrypoint",
						"subject":   "Affected Package/Symbol Used By Product Code",
					},
				},
			},
		})
	lane := usageLane(t, module, pkg, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
		},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "puv-agent",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("agent baseline report invalid:\n%v", err)
	}
	return r
}

// lowerBoundUsageReport assembles a valid /3 report whose usage check
// stayed UNKNOWN but promoted a PACKAGE_USAGE_LOWER_BOUND fact: the
// UNKNOWN condition cites it as an auditable positive lower bound —
// subject-bound, never a verdict, never negative proof.
func lowerBoundUsageReport(t *testing.T) *Report {
	t.Helper()
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	lane := usageLane(t, module, pkg, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
		},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			usageLowerBoundFact("OBS-0020", module, pkg, "", "package "+pkg+" referenced (unresolved scope)"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "puv-bound",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("lower-bound baseline report invalid:\n%v", err)
	}
	return r
}

// usageCondition returns the deterministic condition on the canonical
// usage subject; the fixtures carry exactly one.
func usageCondition(t *testing.T, r *Report) *ExploitationCondition {
	t.Helper()
	var found *ExploitationCondition
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Subject == subjProductPackageUsage && c.Origin == OriginDeterm {
			if found != nil {
				t.Fatal("fixture has more than one deterministic usage condition")
			}
			found = c
		}
	}
	if found == nil {
		t.Fatal("no deterministic usage condition")
	}
	return found
}

// agentUsageCondition returns the canonical agent usage hypothesis
// (origin=agent on the usage subject).
func agentUsageCondition(t *testing.T, r *Report) *ExploitationCondition {
	t.Helper()
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Subject == subjProductPackageUsage && c.Origin == OriginAgent {
			return c
		}
	}
	t.Fatal("no agent usage condition")
	return nil
}

// factOf returns the verified fact bound to obsID (fact-<obsid lowercase>).
func factOf(t *testing.T, r *Report, obsID string) *VerifiedFact {
	t.Helper()
	id := "fact-" + strings.ToLower(obsID)
	for i := range r.VerifiedFacts {
		if r.VerifiedFacts[i].ID == id {
			return &r.VerifiedFacts[i]
		}
	}
	t.Fatalf("no fact %s", id)
	return nil
}

// assertInvalid fails unless Validate rejects r with a problem naming want.
func assertInvalid(t *testing.T, r *Report, want string) {
	t.Helper()
	err := Validate(r, "")
	if err == nil {
		t.Fatalf("forged report accepted; want rejection naming %q", want)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("rejection lacks %q:\n%v", want, err)
	}
}

// TestPackageUsageFactValidation pins the PACKAGE_USAGE fact contract:
// kind and tool mark each other, a FALSE claim exists only as a
// VERIFIED negative under COMPLETE coverage, and negative_verification
// is meaningless anywhere else.
func TestPackageUsageFactValidation(t *testing.T) {
	t.Run("FALSE fact without negative verification", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").NegativeVerification = ""
		assertInvalid(t, r, "claim=FALSE PACKAGE_USAGE fact requires negative_verification=VERIFIED")
	})

	t.Run("FALSE fact with non-VERIFIED negative verification", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").NegativeVerification = "INSUFFICIENT_SCOPE"
		assertInvalid(t, r, "negative_verification \"INSUFFICIENT_SCOPE\" invalid")
	})

	t.Run("FALSE fact under PARTIAL coverage is never negative proof", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").Coverage = "PARTIAL"
		assertInvalid(t, r, "requires coverage=COMPLETE")
	})

	t.Run("package-usage tool fact without kind", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").Kind = ""
		assertInvalid(t, r, "requires a package-usage fact kind")
	})

	t.Run("PACKAGE_USAGE kind on a non-package-usage tool", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").Tool = "module_usage"
		assertInvalid(t, r, "kind=PACKAGE_USAGE requires tool=package-usage")
	})

	t.Run("unknown fact kind", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").Kind = "OBSERVATION"
		assertInvalid(t, r, "kind \"OBSERVATION\" invalid")
	})

	t.Run("PACKAGE_USAGE fact with empty scope", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").Scope = ""
		assertInvalid(t, r, "scope")
	})

	t.Run("negative verification on a non-package fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0002").NegativeVerification = NegativeVerificationVerified
		assertInvalid(t, r, "only meaningful on a PACKAGE_USAGE fact")
	})

	t.Run("negative verification on a TRUE usage fact", func(t *testing.T) {
		r := usedUsageReport(t)
		factOf(t, r, "OBS-0020").NegativeVerification = NegativeVerificationVerified
		assertInvalid(t, r, "must not appear on a claim=TRUE package-usage fact")
	})

	t.Run("lower-bound fact cited on an UNKNOWN usage path validates", func(t *testing.T) {
		r := lowerBoundUsageReport(t)
		c := usageCondition(t, r)
		if c.State != StateUnknown {
			t.Fatalf("usage condition = %s, want UNKNOWN (a lower-bound fact never decides)", c.State)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("evidence_level = %+v, want L2 (a lower-bound fact never closes the path)", r.EvidenceLevel)
		}
	})

	t.Run("lower-bound fact with a FALSE claim", func(t *testing.T) {
		r := lowerBoundUsageReport(t)
		factOf(t, r, "OBS-0020").Claim = "FALSE"
		assertInvalid(t, r, "requires claim=TRUE")
	})

	t.Run("lower-bound fact with COMPLETE coverage", func(t *testing.T) {
		r := lowerBoundUsageReport(t)
		factOf(t, r, "OBS-0020").Coverage = "COMPLETE"
		assertInvalid(t, r, "requires coverage=PARTIAL")
	})

	t.Run("lower-bound fact with negative verification", func(t *testing.T) {
		r := lowerBoundUsageReport(t)
		factOf(t, r, "OBS-0020").NegativeVerification = NegativeVerificationVerified
		assertInvalid(t, r, "must not appear on a claim=TRUE package-usage fact")
	})

	t.Run("package-usage fact without a usage subject", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").UsageSubject = nil
		assertInvalid(t, r, "requires usage_subject with a non-empty package")
	})

	t.Run("package-usage fact with an empty package subject", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").UsageSubject = &FactUsageSubject{Module: "golang.org/x/net"}
		assertInvalid(t, r, "non-empty package")
	})

	t.Run("usage subject on a non-package fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0002").UsageSubject = &FactUsageSubject{Package: "golang.org/x/net/http2"}
		assertInvalid(t, r, "only meaningful on a package-usage fact")
	})

	t.Run("usage basis on a TRUE usage fact", func(t *testing.T) {
		r := usedUsageReport(t)
		factOf(t, r, "OBS-0020").UsageBasis = UsageBasisPresentUnused
		assertInvalid(t, r, "only meaningful on a claim=FALSE PACKAGE_USAGE fact")
	})

	t.Run("usage basis on a non-package fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0002").UsageBasis = UsageBasisAbsentFromClosure
		assertInvalid(t, r, "only meaningful on a claim=FALSE PACKAGE_USAGE fact")
	})

	t.Run("usage basis with an invalid value", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").UsageBasis = "module_absent"
		assertInvalid(t, r, "usage_basis \"module_absent\" invalid")
	})

	t.Run("closure-absence basis on a symbol-subject fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		f := factOf(t, r, "OBS-0020")
		f.UsageSubject = &FactUsageSubject{Module: "golang.org/x/net", Package: "golang.org/x/net/http2", Symbol: "ServeConn"}
		f.UsageBasis = UsageBasisAbsentFromClosure
		assertInvalid(t, r, "requires a package-level subject")
	})

	t.Run("closure-absence basis on a package-subject fact validates", func(t *testing.T) {
		r := absentUsageReport(t)
		if factOf(t, r, "OBS-0020").UsageBasis != UsageBasisAbsentFromClosure {
			t.Fatal("absent-basis fixture lost its basis")
		}
	})
}

// TestPackageUsageConditionValidation pins the /3 usage-condition
// contract: the deterministic required path predicate may be SUPPORTED
// only behind a TRUE usage fact and REFUTED only behind a verified
// negative usage fact under a complete scope; a REFUTED path never
// yields a safe/auto-close/non-applicable outcome; an UNKNOWN state
// never hides a resolved negative; and agent material can never carry
// the predicate.
func TestPackageUsageConditionValidation(t *testing.T) {
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	t.Run("USED closes the path and validates at L1", func(t *testing.T) {
		r := usedUsageReport(t)
		c := usageCondition(t, r)
		if c.State != StateSupported || c.Role != ConditionRolePath {
			t.Fatalf("usage condition = %+v, want SUPPORTED path", c)
		}
		if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
			t.Fatalf("evidence_level = %+v, want L1", r.EvidenceLevel)
		}
	})

	t.Run("REFUTED baseline validates as L2", func(t *testing.T) {
		r := refutedUsageReport(t)
		c := usageCondition(t, r)
		if c.State != StateRefuted || r.EvidenceLevel == nil ||
			r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("state=%s level=%+v, want REFUTED/L2", c.State, r.EvidenceLevel)
		}
		if !containsStr(r.EvidenceLevel.BlockingConditions, c.ID) {
			t.Fatalf("REFUTED condition not blocking: %v", r.EvidenceLevel.BlockingConditions)
		}
	})

	t.Run("REFUTED without a verified negative usage fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).EvidenceRefs = []string{"obs:OBS-0020"}
		assertInvalid(t, r, "requires an evidence_ref to a PACKAGE_USAGE fact with claim=FALSE")
	})

	t.Run("REFUTED with a degraded negative scope", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").Coverage = "PARTIAL"
		assertInvalid(t, r, "never negative proof")
	})

	t.Run("REFUTED with an unverified negative", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").NegativeVerification = "INSUFFICIENT_SCOPE"
		assertInvalid(t, r, "never negative proof")
	})

	t.Run("REFUTED citing a TRUE usage fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		positive := usageFact("OBS-0021", module, pkg, "", "TRUE", "", "package "+pkg+" used")
		r.VerifiedFacts = append(r.VerifiedFacts, positive)
		c := usageCondition(t, r)
		c.EvidenceRefs = append(c.EvidenceRefs, positive.ID)
		assertInvalid(t, r, "must not cite a claim=TRUE PACKAGE_USAGE fact")
	})

	t.Run("REFUTED missing the bounded negative verification limitation", func(t *testing.T) {
		r := refutedUsageReport(t)
		c := usageCondition(t, r)
		var lims []string
		for _, lim := range c.Limitations {
			if strings.HasPrefix(lim, "negative verification=VERIFIED") {
				continue
			}
			lims = append(lims, lim)
		}
		c.Limitations = lims
		assertInvalid(t, r, "bounded negative verification")
	})

	t.Run("REFUTED missing the not-a-safe-conclusion limitation", func(t *testing.T) {
		r := refutedUsageReport(t)
		c := usageCondition(t, r)
		var lims []string
		for _, lim := range c.Limitations {
			if strings.Contains(lim, "not a safe conclusion") {
				continue
			}
			lims = append(lims, lim)
		}
		c.Limitations = lims
		assertInvalid(t, r, "not a safe conclusion")
	})

	t.Run("REFUTED with an auto_close disposition", func(t *testing.T) {
		r := refutedUsageReport(t)
		r.Disposition.AutoClose = true
		assertInvalid(t, r, "auto_close")
	})

	t.Run("REFUTED with a non-applicability classification", func(t *testing.T) {
		r := refutedUsageReport(t)
		r.ClassificationReview.Class = ClassNonApplicable
		r.ClassificationReview.Status = StatusSupported
		assertInvalid(t, r, "NON_APPLICABLE")
	})

	t.Run("SUPPORTED citing a non-usage static-carrier fact", func(t *testing.T) {
		r := usedUsageReport(t)
		// affected-resolve is a static carrier, so the L1 carrier check
		// alone would close the condition; the usage rule still demands
		// the resolving fact to be a PACKAGE_USAGE claim=TRUE.
		usageCondition(t, r).EvidenceRefs = []string{"fact-obs-0002"}
		assertInvalid(t, r, "requires an evidence_ref to a PACKAGE_USAGE fact with claim=TRUE")
	})

	t.Run("REFUTED with vulnerable_code_reachability=FALSE", func(t *testing.T) {
		r := refutedUsageReport(t)
		r.ProductApplicability.VulnerableCodeReachability = VCRFalse
		assertInvalid(t, r, "vulnerable_code_reachability=FALSE")
	})

	t.Run("usage fact cited as evidence for reachability FALSE", func(t *testing.T) {
		r := refutedUsageReport(t)
		f := factOf(t, r, "OBS-0020")
		r.ProductApplicability.VulnerableCodeReachability = VCRFalse
		r.ProductApplicability.EvidenceRefs = append(r.ProductApplicability.EvidenceRefs, f.ID)
		assertInvalid(t, r, "can never underwrite vulnerable_code_reachability=FALSE")
	})

	t.Run("usage fact inside a negative basis for reachability FALSE", func(t *testing.T) {
		r := refutedUsageReport(t)
		f := factOf(t, r, "OBS-0020")
		r.ProductApplicability.VulnerableCodeReachability = VCRFalse
		r.ProductApplicability.Basis = append(r.ProductApplicability.Basis, ApplicabilityBasis{
			Kind: ABNotInImportClosure, Status: ABEstablished, Source: ABSourceDeterministic,
			Statement: "forged import-closure absence", CheckScope: "synthetic scope",
			VerifiedEvidenceRefs: []string{f.ID},
		})
		assertInvalid(t, r, "can never carry a reachability FALSE")
	})

	t.Run("SUPPORTED citing only an observation ref", func(t *testing.T) {
		r := usedUsageReport(t)
		usageCondition(t, r).EvidenceRefs = []string{"obs:OBS-0020"}
		assertInvalid(t, r, "requires an evidence_ref to a PACKAGE_USAGE fact with claim=TRUE")
	})

	t.Run("SUPPORTED citing the FALSE usage fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).State = StateSupported
		assertInvalid(t, r, "claim=TRUE")
	})

	t.Run("UNKNOWN citing a verified negative fact", func(t *testing.T) {
		r := refutedUsageReport(t)
		c := usageCondition(t, r)
		c.State = StateUnknown
		c.Limitations = append(c.Limitations, "an undecided usage check is never negative proof")
		assertInvalid(t, r, "cites the verified negative PACKAGE_USAGE fact")
	})

	t.Run("UNKNOWN missing the never-negative-proof limitation", func(t *testing.T) {
		r := refutedUsageReport(t)
		c := usageCondition(t, r)
		c.State = StateUnknown
		c.Limitations = []string{"follow-up: re-run the package-usage check"}
		assertInvalid(t, r, "never negative proof")
	})

	t.Run("deterministic usage condition with role=deployment", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).Role = ConditionRoleDeployment
		assertInvalid(t, r, "role=path")
	})

	t.Run("deterministic usage condition with necessity=supporting", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).Necessity = "supporting"
		assertInvalid(t, r, "necessity=required")
	})

	t.Run("usage condition off the code-reachability axis", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).Axis = ECAxisOther
		assertInvalid(t, r, "axis=code_reachability")
	})

	t.Run("deterministic usage condition in state=OPEN", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).State = StateOpen
		assertInvalid(t, r, "state=OPEN invalid")
	})

	t.Run("deterministic usage condition in state=CONFLICTED", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).State = StateConflicted
		assertInvalid(t, r, "state=CONFLICTED")
	})

	t.Run("forged L1 over a REFUTED usage path", func(t *testing.T) {
		r := refutedUsageReport(t)
		r.EvidenceLevel.Level = EvidenceLevelL1
		assertInvalid(t, r, "does not match recomputed")
	})

	t.Run("forged L1 over an UNKNOWN usage path", func(t *testing.T) {
		r := usedUsageReport(t)
		c := usageCondition(t, r)
		c.State = StateUnknown
		c.Limitations = append(c.Limitations, "an undecided usage check is never negative proof")
		assertInvalid(t, r, "does not match recomputed")
	})

	t.Run("forged L1 with only an agent usage claim", func(t *testing.T) {
		r := usedUsageReport(t)
		r.AgentAssertions = append(r.AgentAssertions, AgentAssertion{
			ID: "A-0099", Statement: "the product calls the vulnerable package",
			Subject: subjProductPackageUsage, State: StateOpen, Basis: BasisHypothesis,
			EvidenceRefs: []string{"A-0099"},
		})
		c := usageCondition(t, r)
		c.Origin = OriginAgent
		c.State = StateOpen
		c.Role = ConditionRolePath
		c.Necessity = "required"
		c.UsageSubject = nil
		c.EvidenceRefs = []string{"A-0099"}
		assertInvalid(t, r, "does not match recomputed")
	})

	t.Run("agent usage condition citing a verified fact", func(t *testing.T) {
		r := agentUsageReport(t)
		positive := usageFact("OBS-0099", module, pkg, "", "TRUE", "", "package "+pkg+" used")
		r.VerifiedFacts = append(r.VerifiedFacts, positive)
		ac := agentUsageCondition(t, r)
		ac.EvidenceRefs = append(ac.EvidenceRefs, positive.ID)
		assertInvalid(t, r, "cites verified fact")
	})

	t.Run("agent usage condition promoted to SUPPORTED", func(t *testing.T) {
		r := agentUsageReport(t)
		agentUsageCondition(t, r).State = StateSupported
		assertInvalid(t, r, "state=OPEN")
	})

	t.Run("deterministic usage condition citing agent material", func(t *testing.T) {
		r := agentUsageReport(t)
		if len(r.AgentAssertions) == 0 {
			t.Fatal("no agent assertions in fixture")
		}
		c := usageCondition(t, r)
		c.EvidenceRefs = append(c.EvidenceRefs, r.AgentAssertions[0].ID)
		assertInvalid(t, r, "deterministic condition references agent-origin")
	})
	t.Run("agent usage condition carrying a usage subject", func(t *testing.T) {
		r := agentUsageReport(t)
		agentUsageCondition(t, r).UsageSubject = &FactUsageSubject{
			Module: module, Package: pkg,
		}
		assertInvalid(t, r, "must not carry usage_subject")
	})

	t.Run("deterministic usage condition without a usage subject", func(t *testing.T) {
		r := refutedUsageReport(t)
		usageCondition(t, r).UsageSubject = nil
		assertInvalid(t, r, "requires usage_subject with a non-empty package")
	})

	t.Run("SUPPORTED citing a fact bound to a different package", func(t *testing.T) {
		r := usedUsageReport(t)
		other := usageFact("OBS-0040", module, "golang.org/x/net/http2/hpack", "", "TRUE", "",
			"package golang.org/x/net/http2/hpack used")
		r.VerifiedFacts = append(r.VerifiedFacts, other)
		usageCondition(t, r).EvidenceRefs = []string{other.ID}
		assertInvalid(t, r, "different usage_subject")
	})

	t.Run("SUPPORTED citing a fact bound to a different symbol", func(t *testing.T) {
		r := usedUsageReport(t)
		other := usageFact("OBS-0040", module, pkg, "ServeConn", "TRUE", "",
			"symbol "+pkg+".ServeConn used")
		r.VerifiedFacts = append(r.VerifiedFacts, other)
		usageCondition(t, r).EvidenceRefs = []string{other.ID}
		assertInvalid(t, r, "different usage_subject")
	})

	t.Run("SUPPORTED citing a fact bound to a different module", func(t *testing.T) {
		r := usedUsageReport(t)
		other := usageFact("OBS-0040", "golang.org/x/mod", pkg, "", "TRUE", "",
			"package "+pkg+" used")
		r.VerifiedFacts = append(r.VerifiedFacts, other)
		usageCondition(t, r).EvidenceRefs = []string{other.ID}
		assertInvalid(t, r, "different usage_subject")
	})

	t.Run("REFUTED citing a verified negative for another subject", func(t *testing.T) {
		r := refutedUsageReport(t)
		other := usageFact("OBS-0040", module, "golang.org/x/net/http2/hpack", "",
			"FALSE", NegativeVerificationVerified,
			"no product-source use of golang.org/x/net/http2/hpack")
		r.VerifiedFacts = append(r.VerifiedFacts, other)
		usageCondition(t, r).EvidenceRefs = []string{other.ID}
		assertInvalid(t, r, "different usage_subject")
	})

	t.Run("SUPPORTED citing an unbound usage fact", func(t *testing.T) {
		r := usedUsageReport(t)
		other := usageFact("OBS-0040", module, pkg, "", "TRUE", "", "package "+pkg+" used")
		other.UsageSubject = nil
		r.VerifiedFacts = append(r.VerifiedFacts, other)
		usageCondition(t, r).EvidenceRefs = []string{other.ID}
		assertInvalid(t, r, "carries no usage_subject")
	})

	t.Run("SUPPORTED citing a lower-bound fact cannot close the path", func(t *testing.T) {
		r := usedUsageReport(t)
		bound := usageLowerBoundFact("OBS-0040", module, pkg, "",
			"package "+pkg+" referenced (unresolved scope)")
		r.VerifiedFacts = append(r.VerifiedFacts, bound)
		usageCondition(t, r).EvidenceRefs = []string{bound.ID}
		assertInvalid(t, r, "a positive lower bound in an open scope is not a USED verdict")
	})

	t.Run("REFUTED citing a lower-bound fact is never negative proof", func(t *testing.T) {
		r := refutedUsageReport(t)
		bound := usageLowerBoundFact("OBS-0040", module, pkg, "",
			"package "+pkg+" referenced (unresolved scope)")
		r.VerifiedFacts = append(r.VerifiedFacts, bound)
		c := usageCondition(t, r)
		c.EvidenceRefs = append(c.EvidenceRefs, bound.ID)
		assertInvalid(t, r, "never negative proof")
	})

	t.Run("UNKNOWN citing a lower-bound fact for a different subject", func(t *testing.T) {
		r := lowerBoundUsageReport(t)
		c := usageCondition(t, r)
		c.UsageSubject = &FactUsageSubject{
			Module: module, Package: "golang.org/x/net/http2/hpack",
		}
		assertInvalid(t, r, "different usage_subject")
	})
	t.Run("lower-bound fact relabelled as a USED verdict on SUPPORTED", func(t *testing.T) {
		r := lowerBoundUsageReport(t)
		factOf(t, r, "OBS-0020").Kind = FactKindPackageUsage
		usageCondition(t, r).State = StateSupported
		assertInvalid(t, r, "a lower bound cannot close the path")
	})
}

// TestPackageUsageAbsentBasisValidation pins the closure-absence
// relaxation: a REFUTED usage condition may sit beside
// vulnerable_code_reachability=FALSE and a SUPPORTED NON_APPLICABLE
// classification only while its cited verified negative carries
// usage_basis=absent_from_closure and the condition names the
// runtime/dynamic boundary — the bounded basis (explicit or legacy
// empty) keeps both prohibitions.
func TestPackageUsageAbsentBasisValidation(t *testing.T) {
	// (a) closure-absence basis + the runtime/dynamic boundary
	// limitation: REFUTED beside VCR=FALSE and SUPPORTED NON_APPLICABLE
	// validates.
	t.Run("absent basis validates beside reachability FALSE and NON_APPLICABLE", func(t *testing.T) {
		r := absentUsageReport(t)
		c := usageCondition(t, r)
		if c.State != StateRefuted {
			t.Fatalf("usage condition = %s, want REFUTED", c.State)
		}
		if r.ProductApplicability.VulnerableCodeReachability != VCRFalse {
			t.Fatalf("vulnerable_code_reachability = %q, want FALSE (fixture must exercise the relaxed rule)",
				r.ProductApplicability.VulnerableCodeReachability)
		}
		if r.ClassificationReview.Class != ClassNonApplicable ||
			r.ClassificationReview.Status != StatusSupported {
			t.Fatalf("classification = %s/%s, want NON_APPLICABLE/SUPPORTED (fixture must exercise the relaxed rule)",
				r.ClassificationReview.Class, r.ClassificationReview.Status)
		}
		boundary := false
		for _, lim := range c.Limitations {
			if namesRuntimeBoundary(lim) {
				boundary = true
			}
		}
		if !boundary {
			t.Fatalf("REFUTED condition carries no runtime/dynamic boundary limitation: %v", c.Limitations)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("absent-basis REFUTED report rejected:\n%v", err)
		}
	})

	// (b) the same shape without the runtime/dynamic boundary
	// limitation: the negative stays unbounded in exactly the way the
	// relaxation forbids, so both prohibitions fire with the
	// boundary-required reason.
	t.Run("absent basis without the runtime boundary is rejected", func(t *testing.T) {
		r := absentUsageReport(t)
		c := usageCondition(t, r)
		var lims []string
		for _, lim := range c.Limitations {
			if namesRuntimeBoundary(lim) {
				continue
			}
			lims = append(lims, lim)
		}
		c.Limitations = lims
		assertInvalid(t, r, "runtime/dynamic boundary")
	})

	// (c)+(d) the bounded basis — an explicit present_unused or a
	// legacy fact with no member — keeps the original prohibition:
	// a bounded usage negative never proves reachability.
	for _, basis := range []string{UsageBasisPresentUnused, ""} {
		name := "explicit present_unused basis keeps the reachability prohibition"
		if basis == "" {
			name = "legacy fact without a basis member keeps the reachability prohibition"
		}
		t.Run(name, func(t *testing.T) {
			r := refutedUsageReport(t)
			factOf(t, r, "OBS-0020").UsageBasis = basis
			r.ProductApplicability.VulnerableCodeReachability = VCRFalse
			assertInvalid(t, r, "a bounded usage negative does not prove reachability")
		})
	}

	t.Run("bounded basis keeps the non-applicability prohibition", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").UsageBasis = UsageBasisPresentUnused
		r.ClassificationReview.Class = ClassNonApplicable
		r.ClassificationReview.Status = StatusSupported
		assertInvalid(t, r, "can never accompany a SUPPORTED NON_APPLICABLE classification")
	})

	// The relaxation never reaches the auto-close prohibition: a
	// REFUTED path still never yields an automatic close-out.
	t.Run("absent basis still never auto-closes", func(t *testing.T) {
		r := absentUsageReport(t)
		r.Disposition.AutoClose = true
		assertInvalid(t, r, "auto_close")
	})
}
