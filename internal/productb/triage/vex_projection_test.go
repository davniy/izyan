package triage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dismissedPackage composes a real DISMISSED package over the good Stage 0
// fixture: the vulnerable module proven absent from the closed build graph
// is the module-absent falsifier of the default ruleset.
func dismissedPackage(t *testing.T) DecisionPackage {
	t.Helper()
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class:          CheckModuleAbsent,
		ClaimedPath:    "example.org/library",
		EvidenceSource: "module_graph",
		Reason:         "module example.org/library absent from the complete module graph",
		Provenance:     []string{"go list -m all"},
	}
	pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("fixture recommendation = %s, want DISMISSED", pkg.MachineDisposition.Recommendation)
	}
	return pkg
}

// trustDismissedPackage composes a DISMISSED package whose only decisive
// ground is a confining deployment perimeter — a trust-grounded basis per
// spec §10.2, admissible through an admitted ruleset that permits it.
func trustDismissedPackage(t *testing.T) DecisionPackage {
	t.Helper()
	c := Composer{Rules: []DecisionRule{{
		ID:             "trust-perimeter-dismissal",
		Recommendation: RecommendationDismissed,
		Applicability: Predicate{
			Op:    "eq",
			Left:  map[string]any{"fact": "deployment.exposure"},
			Right: "cluster-internal",
		},
		Reason: "the deployment perimeter confines inbound reachability to the cluster",
	}}}
	pkg, err := c.Compose(context.Background(), goodStage0(), goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("fixture recommendation = %s, want DISMISSED", pkg.MachineDisposition.Recommendation)
	}
	return pkg
}

// versionSafePackage composes a DISMISSED package grounded on the resolved
// version falling outside every advisory affected range — the vulnerable
// code is present but the pinned version carries none of it.
func versionSafePackage(t *testing.T) DecisionPackage {
	t.Helper()
	s0 := goodStage0()
	s0.PackageCheck.Class = CheckVersionConfirmed
	s0.PackageCheck.ResolvedVersion = "v1.3.0"
	s0.PackageCheck.Reason = "example.org/library@v1.3.0 is outside every advisory affected range"
	c := Composer{Rules: []DecisionRule{{
		ID:             "version-outside-affected-dismissal",
		Recommendation: RecommendationDismissed,
		Applicability: Predicate{
			Op:    "eq",
			Left:  map[string]any{"fact": "package.affected"},
			Right: false,
		},
		Reason: "the resolved version carries no affected range",
	}}}
	pkg, err := c.Compose(context.Background(), s0, goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("fixture recommendation = %s, want DISMISSED", pkg.MachineDisposition.Recommendation)
	}
	return pkg
}

// loweredPackage composes the LOWERED package the default ruleset permits
// on a proven cluster-internal perimeter.
func loweredPackage(t *testing.T) DecisionPackage {
	t.Helper()
	pkg := composeOrFail(t, goodStage0(), goodAssessment(), completeValidation())
	if pkg.MachineDisposition.Recommendation != RecommendationLowered {
		t.Fatalf("fixture recommendation = %s, want LOWERED", pkg.MachineDisposition.Recommendation)
	}
	return pkg
}

// unchangedPackage composes an UNCHANGED package: the deployment exposure
// stays undecidable, so no reduction is established.
func unchangedPackage(t *testing.T) DecisionPackage {
	t.Helper()
	s0 := goodStage0()
	s0.Materials.Deploy = &DeployFacts{Perimeter: "unknown"}
	pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("fixture recommendation = %s, want UNCHANGED", pkg.MachineDisposition.Recommendation)
	}
	return pkg
}

func TestVexProjectionDismissedModuleAbsent(t *testing.T) {
	proj, err := ProjectVEX(dismissedPackage(t))
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	if proj.SchemaVersion != VEXProjectionSchemaVersion {
		t.Fatalf("schema_version = %q", proj.SchemaVersion)
	}
	if proj.Status != "not_affected" {
		t.Fatalf("status = %q, want not_affected", proj.Status)
	}
	if proj.Justification != "component_not_present" {
		t.Fatalf("justification = %q, want component_not_present", proj.Justification)
	}
	if proj.Recommendation != RecommendationDismissed || !proj.TriageOnly {
		t.Fatalf("projection must carry the DISMISSED recommendation and triage_only: %+v", proj)
	}
	joined := strings.Join(proj.Provenance, "\n")
	for _, want := range []string{"decision_package_sha256:", "baseline.disposition=", "baseline.severity=", "fact:package_presence:REFUTES:example.org/library"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("provenance missing %q:\n%s", want, joined)
		}
	}
}

func TestVexProjectionTrustBasis(t *testing.T) {
	proj, err := ProjectVEX(trustDismissedPackage(t))
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	if proj.Status != "not_affected" {
		t.Fatalf("status = %q, want not_affected", proj.Status)
	}
	// A trust/perimeter ground is an assumption about the deployment
	// boundary, never code-proven unreachability (spec §10.2): the
	// projection must name the trust justification and never the
	// execute-path justification, which only negative verification may
	// assert in the authoritative OpenVEX lane.
	if proj.Justification != "vulnerable_code_cannot_be_controlled_by_adversary" {
		t.Fatalf("justification = %q, want vulnerable_code_cannot_be_controlled_by_adversary", proj.Justification)
	}
	if strings.Contains(strings.Join(proj.Provenance, "\n"), "fact:deployment_exposure:SUPPORTS:cluster-internal") == false {
		t.Fatalf("provenance must name the decisive exposure fact: %v", proj.Provenance)
	}
}

func TestVexProjectionVersionOutsideAffected(t *testing.T) {
	proj, err := ProjectVEX(versionSafePackage(t))
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	if proj.Justification != "vulnerable_code_not_present" {
		t.Fatalf("justification = %q, want vulnerable_code_not_present", proj.Justification)
	}
	if strings.Contains(strings.Join(proj.Provenance, "\n"), "fact:package_affected:REFUTES:") == false {
		t.Fatalf("provenance must name the decisive affected fact: %v", proj.Provenance)
	}
}

// TestVexProjectionNeverExecutePath: no admissible projection may claim
// the execute-path justification — triage has no negative-verification
// kernel, so vulnerable_code_not_in_execute_path is outside its vocabulary.
func TestVexProjectionNeverExecutePath(t *testing.T) {
	for name, pkg := range map[string]DecisionPackage{
		"module absent":   dismissedPackage(t),
		"trust perimeter": trustDismissedPackage(t),
		"version safe":    versionSafePackage(t),
	} {
		proj, err := ProjectVEX(pkg)
		if err != nil {
			t.Fatalf("%s: ProjectVEX: %v", name, err)
		}
		if proj.Justification == "vulnerable_code_not_in_execute_path" {
			t.Fatalf("%s: execute-path justification is outside the triage vocabulary", name)
		}
	}
}

func TestVexProjectionDeniedRecommendations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pkg     func(t *testing.T) DecisionPackage
		wantSub string
	}{
		{"LOWERED never not_affected", loweredPackage, "LOWERED"},
		{"UNCHANGED establishes nothing", unchangedPackage, "UNCHANGED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proj, err := ProjectVEX(tc.pkg(t))
			if !errors.Is(err, ErrVEXProjectionDenied) {
				t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q must name %s", err, tc.wantSub)
			}
			if proj.Status == "not_affected" {
				t.Fatal("a denied projection still carried not_affected")
			}
		})
	}
}

// TestVexProjectionDeniedIncompleteBasis: an unvalidated or demoted
// DISMISSED record — PARTIAL/FAILED/unknown fact validation, recorded
// demotions, semantic instability or a still-open blocking assumption —
// can never produce an authoritative not_affected, however the
// recommendation field reads.
func TestVexProjectionDeniedIncompleteBasis(t *testing.T) {
	t.Run("PARTIAL fact validation", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.TechnicalAssessment.FactValidation = string(ValidationPartial)
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
	t.Run("FAILED fact validation", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.TechnicalAssessment.FactValidation = string(ValidationFailed)
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
	t.Run("recorded demotion", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.MachineDisposition.Demotions = []string{"check C07 is UNVERIFIED"}
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
	t.Run("unstable basis", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.TechnicalAssessment.StabilityResult = "unstable"
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
	t.Run("unstable demoted basis", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.TechnicalAssessment.StabilityResult = "unstable_demoted"
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
	t.Run("open blocking assumption", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.MachineDisposition.ResidualAssumptions = append(pkg.MachineDisposition.ResidualAssumptions, Condition{
			ID:        "assumption-rule-falsifier",
			Predicate: Predicate{Op: "exists", Path: "package.present"},
			Status:    ConditionUnknown,
			Scope:     "rule",
			Effect:    "blocks_lowered_and_dismissed",
		})
		if err := pkg.Validate(); err != nil {
			t.Fatalf("mutated fixture must stay schema-valid: %v", err)
		}
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
	t.Run("conflicting decision fact", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.Facts = append(pkg.Facts, DecisionFact{
			ID: "fact-conflict", Kind: FactReleaseToolchain, Status: ObsConflicting,
			Subject: "1.25.8", Scope: "release",
		})
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
}

// TestVexProjectionDeniedTrustOnly: a DISMISSED record with no decisive
// deterministic ground — only an UNAVAILABLE perimeter observation or a
// non-confining perimeter — is an unvalidated proposal, never a basis for
// not_affected.
func TestVexProjectionDeniedTrustOnly(t *testing.T) {
	t.Run("undecisive perimeter observation", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.Facts = []DecisionFact{{
			ID: "fact-exposure", Kind: FactDeploymentExposure, Status: ObsUnavailable,
			Subject: "unknown", Scope: "deployment", Provenance: []string{"deploy_scan"},
		}}
		_, err := ProjectVEX(pkg)
		if !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
		if !strings.Contains(err.Error(), "deterministic") {
			t.Fatalf("error %q must name the missing deterministic ground", err)
		}
	})
	t.Run("public perimeter is not a confining ground", func(t *testing.T) {
		pkg := dismissedPackage(t)
		pkg.Facts = []DecisionFact{{
			ID: "fact-exposure", Kind: FactDeploymentExposure, Status: ObsSupports,
			Subject: "public", Scope: "deployment", Provenance: []string{"deploy_scan"},
		}}
		if _, err := ProjectVEX(pkg); !errors.Is(err, ErrVEXProjectionDenied) {
			t.Fatalf("err = %v, want ErrVEXProjectionDenied", err)
		}
	})
}

func TestVexProjectionInvalidPackage(t *testing.T) {
	if _, err := ProjectVEX(DecisionPackage{}); err == nil {
		t.Fatal("an invalid decision package must fail validation")
	} else if errors.Is(err, ErrVEXProjectionDenied) {
		t.Fatalf("a contract violation is a technical error, not a denial: %v", err)
	}
	pkg := dismissedPackage(t)
	pkg.SchemaVersion = "decision-package.v0"
	if _, err := ProjectVEX(pkg); err == nil || errors.Is(err, ErrVEXProjectionDenied) {
		t.Fatalf("schema_version violation must be a technical error, got %v", err)
	}
}

// TestVexProjectionSerializes: the artifact is a small triage-scoped
// document — triage_only is always true, the recommendation is the
// package's own and the OpenVEX vocabulary is used only on the wire.
func TestVexProjectionSerializes(t *testing.T) {
	proj, err := ProjectVEX(dismissedPackage(t))
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	raw, err := json.Marshal(proj)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["triage_only"] != true {
		t.Fatalf("triage_only = %v", wire["triage_only"])
	}
	if wire["status"] != "not_affected" || wire["justification"] != "component_not_present" {
		t.Fatalf("wire status/justification wrong: %v", wire)
	}
	if wire["recommendation"] != "DISMISSED" {
		t.Fatalf("recommendation = %v", wire["recommendation"])
	}
	if _, ok := wire["provenance"].([]any); !ok {
		t.Fatalf("provenance must serialize as a list: %v", wire["provenance"])
	}
}

func TestVexProjectionValidate(t *testing.T) {
	proj, err := ProjectVEX(dismissedPackage(t))
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	if err := proj.Validate(); err != nil {
		t.Fatalf("valid projection failed Validate: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*VEXProjection)
	}{
		{"wrong schema", func(p *VEXProjection) { p.SchemaVersion = "v9" }},
		{"empty finding", func(p *VEXProjection) { p.FindingID = "" }},
		{"non triage-scoped", func(p *VEXProjection) { p.TriageOnly = false }},
		{"unknown status", func(p *VEXProjection) { p.Status = "affected" }},
		{"missing justification", func(p *VEXProjection) { p.Justification = "" }},
		{"invalid recommendation", func(p *VEXProjection) { p.Recommendation = "CLOSED" }},
		{"lowered with not_affected", func(p *VEXProjection) { p.Recommendation = RecommendationLowered }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mut := proj
			tc.mutate(&mut)
			if err := mut.Validate(); err == nil {
				t.Fatalf("%s: Validate must reject the projection", tc.name)
			}
		})
	}
}

func TestVexProjectionWriteArtifact(t *testing.T) {
	pkg := dismissedPackage(t)
	proj, err := ProjectVEX(pkg)
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	dir := t.TempDir()
	decisionBytes, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "decision.json"), decisionBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	w := ArtifactWriter{}
	if err := w.WriteVEXProjection(context.Background(), dir, proj); err != nil {
		t.Fatalf("WriteVEXProjection: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vex.json"))
	if err != nil {
		t.Fatalf("vex.json missing: %v", err)
	}
	var got VEXProjection
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("vex.json does not parse: %v", err)
	}
	if got.Status != "not_affected" || got.Justification != "component_not_present" || !got.TriageOnly {
		t.Fatalf("vex.json wrong: %+v", got)
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatalf("audit log missing: %v", err)
	}
	if !strings.Contains(string(audit), `"type":"vex_projection"`) || !strings.Contains(string(audit), `"status":"ok"`) {
		t.Fatalf("audit must record the projection: %s", audit)
	}
}

func TestVexProjectionWriteConsistency(t *testing.T) {
	pkg := dismissedPackage(t)
	proj, err := ProjectVEX(pkg)
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	w := ArtifactWriter{}

	t.Run("missing decision.json", func(t *testing.T) {
		if err := w.WriteVEXProjection(context.Background(), t.TempDir(), proj); err == nil {
			t.Fatal("projection without a decision.json must fail")
		}
	})
	t.Run("foreign decision.json", func(t *testing.T) {
		dir := t.TempDir()
		other := pkg
		other.FindingID = "finding-other-001"
		raw, _ := json.Marshal(other)
		if err := os.WriteFile(filepath.Join(dir, "decision.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteVEXProjection(context.Background(), dir, proj); err == nil {
			t.Fatal("projection beside a foreign decision.json must fail")
		}
		if _, statErr := os.Stat(filepath.Join(dir, "vex.json")); !os.IsNotExist(statErr) {
			t.Fatal("a failed consistency check must not leave vex.json")
		}
	})
	t.Run("invalid decision.json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "decision.json"), []byte("not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteVEXProjection(context.Background(), dir, proj); err == nil {
			t.Fatal("an unparsable decision.json must fail")
		}
	})
}

func TestVexProjectionDenialRecorded(t *testing.T) {
	pkg := loweredPackage(t)
	_, perr := ProjectVEX(pkg)
	if perr == nil {
		t.Fatal("LOWERED must be denied")
	}
	dir := t.TempDir()
	decisionBytes, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "decision.json"), decisionBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := ArtifactWriter{}
	if err := w.RecordVEXProjectionDenial(context.Background(), dir, pkg, perr); err != nil {
		t.Fatalf("RecordVEXProjectionDenial: %v", err)
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"type":"vex_projection"`) || !strings.Contains(string(audit), `"status":"denied"`) {
		t.Fatalf("audit must record the denial: %s", audit)
	}
	if !strings.Contains(string(audit), "LOWERED") {
		t.Fatalf("denial must carry the explicit reason: %s", audit)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "vex.json")); !os.IsNotExist(statErr) {
		t.Fatal("a denial must never leave a vex.json artifact")
	}
}

func TestVexDeniesCodeLevelFalsifier(t *testing.T) {
	p := dismissedPackage(t)
	p.Facts = nil
	report := falsifierReport(FalsifierVerified, []string{"e1"}, "fp-code")
	p.FalsifierProofs = report.Proofs
	p.Audit.FalsifierHash = report.Hash
	_, err := ProjectVEX(p)
	if !errors.Is(err, ErrVEXProjectionDenied) || !strings.Contains(err.Error(), "agent-origin falsifier") {
		t.Fatalf("err=%v", err)
	}
	if p.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("decision changed: %s", p.MachineDisposition.Recommendation)
	}
}

func TestVexPackageAbsenceRegression(t *testing.T) {
	p := dismissedPackage(t)
	got, err := ProjectVEX(p)
	if err != nil {
		t.Fatalf("ProjectVEX: %v", err)
	}
	if got.Justification != vexJustificationComponentNotPresent && got.Justification != vexJustificationCodeNotPresent {
		t.Fatalf("justification=%q", got.Justification)
	}
}
