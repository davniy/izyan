package research

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var testDigest = strings.Repeat("ab", 32)

func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unmarshalJSON(t *testing.T, b []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatal(err)
	}
}

// unmarshalStrictJSON decodes with the same closed-member rule
// ParseReport uses at every level.
func unmarshalStrictJSON(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// validArtifact is a self-consistent decision-artifact/1 document: two
// conditional branches over one declared variable plus the explicit
// HOLD_UNKNOWN fallback branch.
func validArtifact(t *testing.T) *DecisionArtifact {
	t.Helper()
	return &DecisionArtifact{
		Schema: DecisionArtifactSchemaV1,
		FindingIdentity: FindingIdentity{
			ID:         "finding-1",
			AdvisoryID: "GO-TEST-0001",
		},
		TargetScope: TargetScope{
			SnapshotContentHash: testDigest,
			CommitSHA:           "deadbeef",
			Scope:               "recorded product snapshot",
		},
		AdvisoryBinding: AdvisoryBinding{
			AdvisoryID:     "GO-TEST-0001",
			AdvisoryDigest: testDigest,
			SubjectRefs:    []string{"adv-01"},
		},
		SharedFacts: []Fact{{
			ID:              "F-1",
			Proposition:     "package golang.org/x/net/http2 is absent from the product build closure",
			Subject:         "golang.org/x/net/http2",
			Scope:           "paired go list closures of the recorded snapshot",
			SourceTool:      "usage-scope",
			ToolVersion:     "v1",
			ObservationRefs: []string{"obs:OBS-0002"},
			DataDigest:      testDigest,
			Coverage:        FactCoverageComplete,
			Freshness:       "this run",
			Status:          FactStatusVerified,
		}},
		DecisionVariables: []DecisionVariable{{
			ID:            "peer_trust",
			Question:      "is the deployment declared to run with trusted peers only?",
			AllowedValues: []string{"trusted", "untrusted"},
			Required:      true,
		}},
		Branches: []DecisionBranch{{
			ID:          "B-UNTRUSTED",
			Assignments: map[string]string{"peer_trust": "untrusted"},
			Conditions: []Condition{{
				ID: "C-1", Statement: "untrusted peer input can reach the affected sink",
				Role: ConditionRolePath, SubjectRefs: []string{"adv-01"}, Required: true,
				Polarity: PolarityPositive,
			}},
			FactRefs:            []string{"F-1"},
			Coverage:            FactCoverageComplete,
			Status:              BranchComplete,
			ProposedDisposition: DispositionCloseNoExploitPath,
		}, {
			ID:          "B-TRUSTED",
			Assignments: map[string]string{"peer_trust": "trusted"},
			Conditions: []Condition{{
				ID: "C-2", Statement: "deployment declared trusted-peers only",
				Role: ConditionRoleDeployment, SubjectRefs: []string{"adv-01"}, Required: true,
				Polarity: PolarityPositive,
			}},
			FactRefs: []string{"F-1"},
			EnvironmentAssertions: []EnvironmentAssertion{{
				Variable: "peer_trust", Value: "trusted", Principal: "operator",
				Timestamp: "2026-10-15T00:00:00Z", Source: "triage-answer",
				Freshness: "this triage session",
			}},
			Coverage:            FactCoverageComplete,
			Status:              BranchComplete,
			ProposedDisposition: DispositionAcceptEnvironmentalMitigation,
		}, {
			ID:                  "B-UNKNOWN",
			Coverage:            FactCoverageNotEvaluated,
			Status:              BranchNotDecisionReady,
			ProposedDisposition: DispositionHoldUnknown,
			Limitations:         []string{"environment posture not recorded"},
		}},
		ProposedDisposition: DispositionHoldUnknown,
		JustificationGraph: []Justification{{
			ID: "J-1", PremiseFactRefs: []string{"F-1"}, ConditionRefs: []string{"C-1"},
			RuleID: "package-absence-close", CoverageBasis: "paired build closures",
			Disposition: DispositionCloseNoExploitPath,
			Statement:   "verified build-closure absence grounds the close on the untrusted branch",
		}},
		Contradictions: []Contradiction{},
		HumanAction: HumanAction{
			Mode:                    HumanActionAnswerThenAcceptReject,
			EnvironmentQuestionRefs: []string{"peer_trust"},
			AllowedResponses:        []string{HumanResponseAccept, HumanResponseReject},
			MandatoryFactRefs:       []string{"F-1"},
		},
		ReplayAndPolicyPins: ReplayAndPolicyPins{
			PromptDigest: testDigest,
			PolicyDigest: testDigest,
			CatalogDigests: map[string]string{
				"conditions": testDigest, "checks": testDigest, "dispositions": testDigest,
			},
		},
	}
}

// mutArtifact returns the artifact with fn applied; the helper keeps
// every mutation an explicit contract-level change on the valid shape.
func mutArtifact(t *testing.T, fn func(*DecisionArtifact)) *DecisionArtifact {
	t.Helper()
	a := validArtifact(t)
	fn(a)
	return a
}

func artifactInvalid(t *testing.T, a *DecisionArtifact, wantSub string) {
	t.Helper()
	err := ValidateDecisionArtifact(a)
	if err == nil {
		t.Fatalf("artifact accepted; want violation mentioning %q", wantSub)
	}
	if wantSub != "" && !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("violation does not mention %q:\n%v", wantSub, err)
	}
}

func artifactValid(t *testing.T, a *DecisionArtifact) {
	t.Helper()
	if err := ValidateDecisionArtifact(a); err != nil {
		t.Fatalf("valid artifact rejected:\n%v", err)
	}
}

func TestDecisionArtifactSchemaV1(t *testing.T) {
	artifactValid(t, validArtifact(t))

	a := mutArtifact(t, func(a *DecisionArtifact) { a.Schema = "decision-artifact/2" })
	artifactInvalid(t, a, "decision_artifact.schema")

	a = mutArtifact(t, func(a *DecisionArtifact) { a.Schema = "" })
	artifactInvalid(t, a, "schema")
}

func TestDecisionArtifactValidationRules(t *testing.T) {
	t.Run("fact provenance and digest shape", func(t *testing.T) {
		// Accepted shape is covered by validArtifact; now reject.
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].ObservationRefs = nil
		})
		artifactInvalid(t, a, "observation_refs required")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].ObservationRefs = []string{"OBS-0002"}
		})
		artifactInvalid(t, a, "obs:OBS-")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].DataDigest = "not-a-digest"
		})
		artifactInvalid(t, a, "data_digest must be 64-hex")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].SourceTool = ""
		})
		artifactInvalid(t, a, "source_tool/tool_version required")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].ToolVersion = ""
		})
		artifactInvalid(t, a, "source_tool/tool_version required")
	})

	t.Run("branch status and disposition enums", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].Status = "HALF_DONE"
		})
		artifactInvalid(t, a, "status \"HALF_DONE\" invalid")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].ProposedDisposition = "AUTO_CLOSE"
		})
		artifactInvalid(t, a, "not an R6 disposition")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.ProposedDisposition = ProposedDisposition("SAFE")
		})
		artifactInvalid(t, a, "not an R6 disposition")
	})

	t.Run("variable enum membership", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].Assignments["peer_trust"] = "mostly"
		})
		artifactInvalid(t, a, "outside the variable's allowed_values")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].Assignments["mood"] = "good"
		})
		artifactInvalid(t, a, "not a declared decision variable")
	})

	t.Run("replay and policy pins", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.ReplayAndPolicyPins.PolicyDigest = ""
		})
		artifactInvalid(t, a, "policy_digest must be 64-hex")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			delete(a.ReplayAndPolicyPins.CatalogDigests, "checks")
		})
		artifactInvalid(t, a, "missing the \"checks\" catalog pin")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.ReplayAndPolicyPins.CatalogDigests["conditions"] = "zz"
		})
		artifactInvalid(t, a, "catalog_digests[\"conditions\"] must be 64-hex")
	})

	t.Run("explicit unknown branch", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches = a.Branches[:2] // drop the HOLD_UNKNOWN branch
		})
		artifactInvalid(t, a, "explicit unknown branch")
	})

	t.Run("close proposals need a backing justification", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.JustificationGraph = nil
		})
		artifactInvalid(t, a, "no justification edge backs it")
	})

	t.Run("contradicted branch may only hold or keep open", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].Status = BranchContradicted
		})
		artifactInvalid(t, a, "CONTRADICTED")
	})

	t.Run("awaiting input requires declared inputs", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].Status = BranchAwaitingInput
		})
		artifactInvalid(t, a, "AWAITING_INPUT requires declared required_environment_inputs")
	})

	t.Run("complete branch requires complete coverage", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].Coverage = FactCoveragePartial
		})
		artifactInvalid(t, a, "COMPLETE")
	})
}

func TestDecisionArtifactCloseGuards(t *testing.T) {
	t.Run("close branch cannot carry environment assertions", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			// Laundering attempt: declare the trusted-peer answer on the
			// closing branch itself.
			a.Branches[0].EnvironmentAssertions = []EnvironmentAssertion{{
				Variable: "peer_trust", Value: "untrusted", Principal: "operator",
				Timestamp: "2026-10-15T00:00:00Z", Source: "triage-answer", Freshness: "now",
			}}
		})
		artifactInvalid(t, a, "cannot rest on environment assertions")
	})

	t.Run("close justification cannot cite contradictions", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Contradictions = []Contradiction{{
				ID: "CT-1", Kind: ContradictionAgentVsDeterministic, Subject: "adv-01",
				Summary: "agent claimed reachability", Resolution: ResolutionUnresolved,
			}}
			a.JustificationGraph[0].ContradictionRefs = []string{"CT-1"}
		})
		artifactInvalid(t, a, "cannot cite contradictions")
	})

	t.Run("close justification needs a verified premise", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].Status = FactStatusDegraded
		})
		artifactInvalid(t, a, "VERIFIED premise")
	})
}

func TestDecisionArtifactBranchIsolation(t *testing.T) {
	t.Run("a branch cannot borrow another branch's environment premise", func(t *testing.T) {
		// B-UNTRUSTED assigns peer_trust=untrusted; an assertion answering
		// trusted for that variable is a borrowed premise and must be
		// rejected as contradicting the branch's own assignment.
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].EnvironmentAssertions = []EnvironmentAssertion{{
				Variable: "peer_trust", Value: "trusted", Principal: "operator",
				Timestamp: "2026-10-15T00:00:00Z", Source: "triage-answer", Freshness: "now",
			}}
			a.Branches[0].ProposedDisposition = DispositionAcceptEnvironmentalMitigation
			a.Branches[0].Status = BranchComplete
		})
		artifactInvalid(t, a, "contradicts this branch's own assignment")
	})

	t.Run("assertions only answer a branch's own declared variables", func(t *testing.T) {
		// B-UNKNOWN declares neither an assignment nor a required input for
		// peer_trust, so an assertion there borrows another branch's premise.
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[2].EnvironmentAssertions = []EnvironmentAssertion{{
				Variable: "peer_trust", Value: "trusted", Principal: "operator",
				Timestamp: "2026-10-15T00:00:00Z", Source: "triage-answer", Freshness: "now",
			}}
		})
		artifactInvalid(t, a, "not declared by this branch")
	})

	t.Run("a branch cannot reference facts outside shared_facts", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.Branches[0].FactRefs = []string{"F-OTHER-BRANCH"}
		})
		artifactInvalid(t, a, "does not resolve to a shared fact")
	})
}

func TestHumanContractBounds(t *testing.T) {
	t.Run("at most two environment questions", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			for _, id := range []string{"v2", "v3"} {
				a.DecisionVariables = append(a.DecisionVariables, DecisionVariable{
					ID: id, Question: "q" + id, AllowedValues: []string{"x", "y"}, Required: true,
				})
			}
			a.HumanAction.EnvironmentQuestionRefs = []string{"peer_trust", "v2", "v3"}
		})
		artifactInvalid(t, a, "exceed the R6 bound of 2")
	})

	t.Run("at most seven mandatory facts", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			for i := 2; i <= 8; i++ {
				id := fmt.Sprintf("F-%d", i)
				a.SharedFacts = append(a.SharedFacts, Fact{
					ID: id, Proposition: "p", Subject: "s", Scope: "scope",
					SourceTool: "usage-scope", ToolVersion: "v1",
					ObservationRefs: []string{"obs:OBS-0002"}, DataDigest: testDigest,
					Coverage: FactCoverageComplete, Freshness: "this run", Status: FactStatusVerified,
				})
				a.HumanAction.MandatoryFactRefs = append(a.HumanAction.MandatoryFactRefs, id)
			}
		})
		artifactInvalid(t, a, "exceed the R6 bound of 7")
	})

	t.Run("allowed responses are exactly accept and reject", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.HumanAction.AllowedResponses = []string{HumanResponseAccept, HumanResponseReject, "Defer"}
		})
		artifactInvalid(t, a, "exactly [Accept Reject]")

		a = mutArtifact(t, func(a *DecisionArtifact) {
			a.HumanAction.AllowedResponses = []string{HumanResponseAccept}
		})
		artifactInvalid(t, a, "exactly [Accept Reject]")
	})

	t.Run("question refs resolve to required variables", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.HumanAction.EnvironmentQuestionRefs = []string{"nope"}
		})
		artifactInvalid(t, a, "not a declared decision variable")
	})

	t.Run("mode is consistent with questions", func(t *testing.T) {
		a := mutArtifact(t, func(a *DecisionArtifact) {
			a.HumanAction.Mode = HumanActionAcceptReject // still has question refs
		})
		artifactInvalid(t, a, "ACCEPT_REJECT cannot carry environment questions")
	})
}

func TestEnvironmentAssertionContractLayer(t *testing.T) {
	// The type carries no claim/verdict surface at all — there is no
	// field a result could be written into.
	for _, name := range []string{"Claim", "Result", "Falsifier", "Verdict", "NegativeVerification"} {
		if _, ok := reflect.TypeOf(EnvironmentAssertion{}).FieldByName(name); ok {
			t.Fatalf("EnvironmentAssertion must not carry a %s field", name)
		}
	}
	// An assertion that smuggles claim-shaped members is not decodable
	// under the closed member set.
	a := validArtifact(t)
	raw := mustMarshalJSON(t, a)
	doc := map[string]any{}
	unmarshalJSON(t, raw, &doc)
	branches := doc["branches"].([]any)
	b0 := branches[0].(map[string]any)
	b0["environment_assertions"] = []any{map[string]any{
		"variable": "peer_trust", "value": "untrusted", "principal": "op",
		"timestamp": "2026-10-15T00:00:00Z", "source": "triage-answer", "freshness": "now",
		"claim": map[string]any{"result": "FALSE"},
	}}
	forged := mustMarshalJSON(t, doc)
	parsed := &DecisionArtifact{}
	if err := unmarshalStrictJSON(forged, parsed); err == nil {
		t.Fatal("an environment assertion carrying a claim member must not decode")
	}

	// And it can never stand in for a fact: a declared-trust statement in
	// shared_facts is rejected as non-independent provenance. Every
	// trust/operator/agent source class is rejected the same way — an
	// EnvironmentAssertion is the only typed home for such premises.
	for _, src := range []string{
		"declared-trust", "trusted-peer", "trusted-infrastructure",
		"auto-perimeter", "operator-assertion", "environment",
		"agent", "agent-output", "llm",
	} {
		bad := mutArtifact(t, func(a *DecisionArtifact) {
			a.SharedFacts[0].SourceTool = src
		})
		artifactInvalid(t, bad, "not independent tool provenance")
	}
}

func TestDecisionVariableDerivedFrom(t *testing.T) {
	// A declared variable may carry advisory-text provenance; the shape
	// is validated, never free-form.
	a := mutArtifact(t, func(a *DecisionArtifact) {
		a.DecisionVariables[0].DerivedFrom = &SubjectProvenance{
			Field: "description", Quote: "exploitation requires a negative value",
		}
	})
	artifactValid(t, a)

	bad := mutArtifact(t, func(a *DecisionArtifact) {
		a.DecisionVariables[0].DerivedFrom = &SubjectProvenance{Field: "intent", Quote: "q"}
	})
	artifactInvalid(t, bad, "derived_from.field")

	bad = mutArtifact(t, func(a *DecisionArtifact) {
		a.DecisionVariables[0].DerivedFrom = &SubjectProvenance{Field: "description"}
	})
	artifactInvalid(t, bad, "derived_from.quote")
}
