package finding_test

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/finding"
)

// outcomeScope is an exact fully-represented GO record: the only scope
// authority that can ground a negative closure in this codebase.
func outcomeScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"}},
			RepresentedRefs:    []int{0},
		},
	}
}

func verdictOutcome(t *testing.T, result domain.AssessmentResult) domain.Verdict {
	t.Helper()
	if result.Verdict == nil {
		return ""
	}
	return result.Verdict.Verdict
}

func hasGapCode(result domain.AssessmentResult, code domain.GapCode) bool {
	for _, g := range result.Gaps {
		if g.Code == code {
			return true
		}
	}
	return false
}

func gapCodes(result domain.AssessmentResult) []string {
	out := make([]string, 0, len(result.Gaps))
	for _, g := range result.Gaps {
		out = append(out, string(g.Code))
	}
	return out
}

// TestAssessmentOutcomePolicy pins the terminal-outcome policy:
//
//   - a sufficient admitted proof decides first, even while unrelated
//     supporting obligations remain unresolved;
//   - every decision-relevant code/proof/input/scope blocker fails the
//     assessment;
//   - only a fully evidence-bound external fact yields EXTERNAL_DEPENDENCY;
//   - mixed blockers fail, and an unclassified unresolved obligation fails
//     explicitly instead of abstaining;
//   - claim truth values are never rewritten by the classification.
func TestAssessmentOutcomePolicy(t *testing.T) {
	verifiedConfig := func() domain.Claim {
		return domain.Claim{
			ID:          "CL-CONFIG",
			ConditionID: "C-CONFIG",
			Result:      domain.ClaimFalse,
			Falsifier:   domain.FalsifierSnapshotFactMismatch,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
			},
		}
	}
	configModel := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-CONFIG", Kind: domain.ConditionRuntime, Mandatory: true,
		}},
		SupportingFactors: []domain.Condition{{
			ID: "C-SUPPORT", Kind: domain.ConditionPlatform, Mandatory: false,
		}},
	}
	supportGap := domain.AnalysisGap{
		Owner: domain.GapOwnerCode, Code: domain.GapAnalysisBudgetExhausted,
		Obligation: domain.ObligationMeasurement, Message: "supporting fact budget",
	}
	supportClaim := domain.Claim{
		ID: "CL-SUPPORT", ConditionID: "C-SUPPORT", Result: domain.ClaimUnknown,
		AnalysisGaps: []domain.AnalysisGap{supportGap},
	}

	cases := []struct {
		name           string
		in             finding.AssessmentInput
		wantOutcome    domain.AssessmentOutcome
		wantVerdict    domain.Verdict
		wantGaps       []domain.GapCode
		wantNoGaps     []domain.GapCode
		wantExternal   bool
		wantLimitation string
	}{
		{
			name: "sufficient proof wins over unrelated blockers",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Affected: domain.AffectedResult{Scope: outcomeScope("GO-2026-PROOF1")},
					Model:    configModel,
					Claims:   []domain.Claim{verifiedConfig(), supportClaim},
				},
				Gaps: []domain.AnalysisGap{{
					Owner: domain.GapOwnerCode, Code: domain.GapMeasurementNotCompleted,
					Obligation: domain.ObligationMeasurement, Message: "unrelated measurement gap",
				}},
				AssessmentID: "ASSESS-PROOF1",
			},
			wantOutcome:    domain.OutcomeDecided,
			wantVerdict:    domain.VerdictNoExploitPathFound,
			wantGaps:       []domain.GapCode{domain.GapMeasurementNotCompleted},
			wantLimitation: "supporting gap on C-SUPPORT",
		},
		{
			name: "code-owned unresolved obligation fails",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: configModel,
					Claims: []domain.Claim{{
						ID: "CL-CONFIG", ConditionID: "C-CONFIG", Result: domain.ClaimUnknown,
						AnalysisGaps: []domain.AnalysisGap{{
							Owner: domain.GapOwnerCode, Code: domain.GapReachabilityProofIncomplete,
							Obligation: domain.ObligationCondition, ConditionID: "C-CONFIG",
							Message: "reachability proof remains incomplete",
						}},
					}},
				},
				AssessmentID: "ASSESS-CODE",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapReachabilityProofIncomplete},
		},
		{
			name: "trigger proof gap is preserved, never relabelled external",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: domain.ExploitModel{
						MandatoryConditions: []domain.Condition{{
							ID: "C-TRIGGER", Kind: domain.ConditionCustom, Mandatory: true,
						}},
					},
					Claims: []domain.Claim{{
						ID: "CL-TRIGGER", ConditionID: "C-TRIGGER", Result: domain.ClaimUnknown,
						AnalysisGaps: []domain.AnalysisGap{{
							Owner: domain.GapOwnerProof, Code: domain.GapTriggerProofIncomplete,
							Obligation: domain.ObligationCondition, ConditionID: "C-TRIGGER",
							Message: "mechanism trigger witness was not established",
						}},
					}},
				},
				AssessmentID: "ASSESS-TRIGGER",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapTriggerProofIncomplete},
			wantNoGaps:  []domain.GapCode{domain.GapUnclassifiedAnalysisGap},
		},
		{
			name: "version the artifact cannot settle is an external dependency",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Affected: domain.AffectedResult{
						ModulePresent:   domain.ClaimTrue,
						VersionAffected: domain.ClaimUnknown,
						EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES"},
					},
				},
				AssessmentID: "ASSESS-EXTERNAL",
			},
			wantOutcome:  domain.OutcomeExternal,
			wantVerdict:  domain.VerdictInconclusive,
			wantGaps:     []domain.GapCode{domain.GapExternalDependencyUnresolved},
			wantExternal: true,
		},
		{
			name: "external version plus a measured code blocker stays failed",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Affected: domain.AffectedResult{
						ModulePresent:   domain.ClaimTrue,
						VersionAffected: domain.ClaimUnknown,
						EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES"},
					},
				},
				Gaps: []domain.AnalysisGap{{
					Owner: domain.GapOwnerInput, Code: domain.GapInputResolutionFailed,
					Obligation: domain.ObligationPackagePresence, Message: "package inventory failed",
				}},
				AssessmentID: "ASSESS-MIXED",
			},
			wantOutcome:  domain.OutcomeFailed,
			wantVerdict:  "",
			wantGaps:     []domain.GapCode{domain.GapInputResolutionFailed, domain.GapExternalDependencyUnresolved},
			wantExternal: false,
		},
		{
			name: "pending mandatory criticism fails",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: domain.ExploitModel{
						MandatoryConditions:     []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
						PendingConditionReviews: []domain.ConditionID{"C-REACH"},
					},
					Claims: []domain.Claim{{ConditionID: "C-REACH", Result: domain.ClaimTrue}},
				},
				AssessmentID: "ASSESS-REVIEW",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapReviewUnresolved},
		},
		{
			name: "failed negative verification fails",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: domain.ExploitModel{
						MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
					},
					Claims: []domain.Claim{{
						ConditionID: "C-REACH", Result: domain.ClaimFalse,
						Falsifier: "guards",
						NegativeVerification: &domain.NegativeVerification{
							Status: domain.NegativeInsufficientScope,
						},
					}},
				},
				AssessmentID: "ASSESS-NEGATIVE",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapNegativeVerificationIncomplete},
		},
		{
			name: "timeout is an analysis failure",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: configModel,
					Claims: []domain.Claim{{
						ID: "CL-CONFIG", ConditionID: "C-CONFIG", Result: domain.ClaimUnknown,
					}},
				},
				Gaps: []domain.AnalysisGap{{
					Owner: domain.GapOwnerCode, Code: domain.GapAnalysisTimeout,
					Obligation: domain.ObligationMeasurement, Message: "analysis context ended",
				}},
				AssessmentID: "ASSESS-TIMEOUT",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapAnalysisTimeout},
		},
		{
			name: "skipped measurement is an analysis failure",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: configModel,
					Claims: []domain.Claim{{
						ID: "CL-CONFIG", ConditionID: "C-CONFIG", Result: domain.ClaimUnknown,
					}},
				},
				Gaps: []domain.AnalysisGap{{
					Owner: domain.GapOwnerProof, Code: domain.GapMeasurementNotCompleted,
					Obligation: domain.ObligationMeasurement, Message: "govulncheck did not run",
				}},
				AssessmentID: "ASSESS-SKIPPED",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapMeasurementNotCompleted},
		},
		{
			name: "missing proof artifact is an analysis failure",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: configModel,
					Claims: []domain.Claim{{
						ID: "CL-CONFIG", ConditionID: "C-CONFIG", Result: domain.ClaimUnknown,
					}},
				},
				Gaps: []domain.AnalysisGap{{
					Owner: domain.GapOwnerProof, Code: domain.GapProofArtifactMissing,
					Obligation: domain.ObligationRootCause, Message: "dependency source sidecar is missing",
				}},
				AssessmentID: "ASSESS-SIDECAR",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapProofArtifactMissing},
		},
		{
			name: "unclassified unresolved obligation fails explicitly",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: domain.ExploitModel{
						MandatoryConditions: []domain.Condition{{
							ID: "C-CUSTOM", Kind: domain.ConditionCustom, Mandatory: true,
						}},
					},
					Claims: []domain.Claim{{ConditionID: "C-CUSTOM", Result: domain.ClaimUnknown}},
				},
				AssessmentID: "ASSESS-UNCLASSIFIED",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapUnclassifiedAnalysisGap},
		},
		{
			name: "an external label without a bound dependency is analyzer work",
			in: finding.AssessmentInput{
				VerdictInput: evaluator.VerdictInput{
					Model: configModel,
					Claims: []domain.Claim{{
						ID: "CL-CONFIG", ConditionID: "C-CONFIG", Result: domain.ClaimUnknown,
					}},
				},
				Gaps: []domain.AnalysisGap{{
					Owner: domain.GapOwnerExternal, Code: domain.GapExternalDependencyUnresolved,
					Obligation: domain.ObligationVersionRange, Message: "unbound externality claim",
				}},
				AssessmentID: "ASSESS-UNBOUND",
			},
			wantOutcome: domain.OutcomeFailed,
			wantVerdict: "",
			wantGaps:    []domain.GapCode{domain.GapUnclassifiedAnalysisGap},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]domain.Claim(nil), tc.in.Claims...)
			result := finding.Assess(tc.in)
			if err := result.Validate(); err != nil {
				t.Fatalf("Assess returned an invalid result: %v (%+v)", err, result)
			}
			if result.Outcome != tc.wantOutcome {
				t.Fatalf("outcome=%s want %s (%v)", result.Outcome, tc.wantOutcome, result.Gaps)
			}
			if got := verdictOutcome(t, result); got != tc.wantVerdict {
				t.Fatalf("verdict=%q want %q", got, tc.wantVerdict)
			}
			for _, code := range tc.wantGaps {
				if !hasGapCode(result, code) {
					t.Fatalf("missing gap %s; got %v", code, gapCodes(result))
				}
			}
			for _, code := range tc.wantNoGaps {
				if hasGapCode(result, code) {
					t.Fatalf("unexpected gap %s; got %v", code, gapCodes(result))
				}
			}
			if got := len(result.ExternalDependencies) > 0; got != tc.wantExternal {
				t.Fatalf("external dependencies=%v want %v (%+v)", got, tc.wantExternal, result.ExternalDependencies)
			}
			if tc.wantLimitation != "" {
				found := false
				for _, l := range result.Limitations {
					if strings.Contains(l, tc.wantLimitation) {
						found = true
					}
				}
				if !found {
					t.Fatalf("limitations %v do not contain %q", result.Limitations, tc.wantLimitation)
				}
			}
			// Classification never rewrites claim truth values.
			if len(before) != len(tc.in.Claims) {
				t.Fatalf("input claim set changed length")
			}
			for i := range before {
				if before[i].Result != tc.in.Claims[i].Result {
					t.Fatalf("claim %s result rewritten: %s -> %s",
						before[i].ConditionID, before[i].Result, tc.in.Claims[i].Result)
				}
			}
		})
	}
}

// TestAssessmentOutcomePolicyExternalFields pins the evidence-bound shape of
// an external answer: the missing fact, the affected obligation, the boundary
// evidence, why the artifact cannot supply it, the changing alternatives and
// the resolving evidence must all be present.
func TestAssessmentOutcomePolicyExternalFields(t *testing.T) {
	result := finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Affected: domain.AffectedResult{
				ModulePresent:   domain.ClaimTrue,
				VersionAffected: domain.ClaimUnknown,
				EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES"},
			},
		},
		AssessmentID: "ASSESS-EXTERNAL-FIELDS",
	})
	if result.Outcome != domain.OutcomeExternal {
		t.Fatalf("outcome=%s want EXTERNAL_DEPENDENCY (%v)", result.Outcome, result.Gaps)
	}
	if len(result.ExternalDependencies) != 1 {
		t.Fatalf("dependencies=%d want 1", len(result.ExternalDependencies))
	}
	dep := result.ExternalDependencies[0]
	if dep.MissingFact == "" || dep.AffectedObligation != domain.ObligationVersionRange ||
		len(dep.BoundaryEvidenceRefs) == 0 || dep.WhyArtifactCannotSupply == "" ||
		len(dep.AlternativesChanging) < 2 || dep.ResolvingEvidence == "" {
		t.Fatalf("dependency is not fully bound: %+v", dep)
	}
	for _, ref := range dep.BoundaryEvidenceRefs {
		if ref.AssessmentID != "ASSESS-EXTERNAL-FIELDS" || ref.Ref != "EV-AFFECTED-MODULES" {
			t.Fatalf("boundary ref is not qualified to this assessment: %+v", ref)
		}
	}
}
