package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

// checkStatus runs one named check against the input and fails the test
// when the check id is unknown.
func checkStatus(t *testing.T, id string, in CheckInput) CheckResult {
	t.Helper()
	for _, c := range DefaultChecks() {
		if c.ID() == id {
			return c.Evaluate(context.Background(), in)
		}
	}
	t.Fatalf("unknown check %q", id)
	return CheckResult{}
}

// TestCheckMatrix exercises the C01–C11 set on a clean fixture plus the
// decisive failure modes of each check — every status is a machine value
// the composer consumes, never a prose verdict.
func TestCheckMatrix(t *testing.T) {
	good := CheckInput{Stage0: goodStage0(), Assessment: goodAssessment(), Validation: completeValidation()}

	t.Run("all pre-package checks pass on a clean run", func(t *testing.T) {
		got := RunChecks(context.Background(), PrePackageChecks(), good)
		if len(got) != len(prePackageCheckIDs) {
			t.Fatalf("want %d results, got %d", len(prePackageCheckIDs), len(got))
		}
		for i, r := range got {
			if r.ID != prePackageCheckIDs[i] {
				t.Fatalf("result %d id = %q, want %q", i, r.ID, prePackageCheckIDs[i])
			}
			if r.Status != CheckPass {
				t.Fatalf("check %s = %s reasons=%v, want PASS", r.ID, r.Status, r.Reasons)
			}
		}
	})

	cases := []struct {
		name   string
		id     string
		mutate func(*CheckInput)
		want   CheckStatus
	}{
		{
			name: "C01 conflicting intake hash",
			id:   CheckIDIntakeIdentity,
			mutate: func(in *CheckInput) {
				in.Stage0.Raw.TicketHash = strings.Repeat("0", 64)
			},
			want: CheckConflicting,
		},
		{
			name: "C01 conflicting input hash between finding and snapshot",
			id:   CheckIDIntakeIdentity,
			mutate: func(in *CheckInput) {
				in.Stage0.Snapshot.InputHash = "deadbeef"
			},
			want: CheckConflicting,
		},
		{
			name: "C01 conflicting vulnerability ids",
			id:   CheckIDIntakeIdentity,
			mutate: func(in *CheckInput) {
				in.Stage0.Validation.Fields = append(in.Stage0.Validation.Fields, FieldValidation{
					Field: "vulnerability_ids", Status: IntakeConflicting, Reason: "two candidate ids disagree",
				})
			},
			want: CheckConflicting,
		},
		{
			name: "C02 VALID without provenance is unverified",
			id:   CheckIDFieldProvenance,
			mutate: func(in *CheckInput) {
				for i := range in.Stage0.Validation.Fields {
					if in.Stage0.Validation.Fields[i].Field == "vulnerability_ids" {
						in.Stage0.Validation.Fields[i].Provenance = nil
					}
				}
			},
			want: CheckUnverified,
		},
		{
			name: "C02 absent optional field is a note, not a gate",
			id:   CheckIDFieldProvenance,
			mutate: func(in *CheckInput) {
				in.Stage0.Validation.Fields = append(in.Stage0.Validation.Fields, FieldValidation{
					Field: "go_version", Status: IntakeUnavailable,
				})
			},
			want: CheckPass,
		},
		{
			name: "C02 absent decision-relevant field stays unavailable",
			id:   CheckIDFieldProvenance,
			mutate: func(in *CheckInput) {
				in.Stage0.Validation.Fields = append(in.Stage0.Validation.Fields, FieldValidation{
					Field: "vulnerability_ids", Status: IntakeUnavailable, BlocksRiskReduction: true,
				})
			},
			want: CheckUnavailable,
		},
		{
			name: "C03 missing source is unavailable",
			id:   CheckIDSourceResolution,
			mutate: func(in *CheckInput) {
				in.Stage0.CatalogEntry = CatalogEntry{}
				in.Stage0.Source.Metadata.SourceID = ""
			},
			want: CheckUnavailable,
		},
		{
			name: "C03 artifact kind cannot serve as source",
			id:   CheckIDSourceResolution,
			mutate: func(in *CheckInput) {
				in.Stage0.CatalogEntry.Kind = "oci"
				in.Stage0.Source.Metadata.SourceID = in.Stage0.CatalogEntry.ID
			},
			want: CheckInvalid,
		},
		{
			name: "C03 materialized source mismatch is conflicting",
			id:   CheckIDSourceResolution,
			mutate: func(in *CheckInput) {
				in.Stage0.Source.Metadata.SourceID = "other-source"
			},
			want: CheckConflicting,
		},
		{
			name: "C04 ref outside the bounded list is invalid",
			id:   CheckIDRefResolution,
			mutate: func(in *CheckInput) {
				in.Stage0.SelectedRef = RefCandidate{ID: "ghost", Name: "refs/heads/ghost", Kind: RefBranch, Source: "svc"}
				in.Stage0.RefResolution.SelectedID = "ghost"
			},
			want: CheckInvalid,
		},
		{
			name: "C04 missing resolved commit is unverified",
			id:   CheckIDRefResolution,
			mutate: func(in *CheckInput) {
				in.Stage0.RefResolution.ResolvedCommit = ""
			},
			want: CheckUnverified,
		},
		{
			name: "C04 local source without refs is a limitation",
			id:   CheckIDRefResolution,
			mutate: func(in *CheckInput) {
				in.Stage0.CandidateRefs = nil
				in.Stage0.SelectedRef = RefCandidate{}
			},
			want: CheckLimitation,
		},
		{
			name: "C05 wrong schema is invalid",
			id:   CheckIDSnapshotIntegrity,
			mutate: func(in *CheckInput) {
				in.Stage0.Snapshot.SchemaVersion = "snapshot.v0"
			},
			want: CheckInvalid,
		},
		{
			name: "C05 missing content hash is unverified",
			id:   CheckIDSnapshotIntegrity,
			mutate: func(in *CheckInput) {
				in.Stage0.Snapshot.ContentHash = ""
			},
			want: CheckUnverified,
		},
		{
			name: "C06 missing advisory resolution is unavailable",
			id:   CheckIDAdvisory,
			mutate: func(in *CheckInput) {
				in.Stage0.Resolution = nil
				in.Stage0.Advisory = vulnerability.FrozenAdvisory{}
			},
			want: CheckUnavailable,
		},
		{
			name: "C06 partial advisory is a limitation",
			id:   CheckIDAdvisory,
			mutate: func(in *CheckInput) {
				in.Stage0.Resolution.Partial = true
			},
			want: CheckLimitation,
		},
		{
			name: "C06 advisory naming another id is conflicting",
			id:   CheckIDAdvisory,
			mutate: func(in *CheckInput) {
				in.Stage0.Resolution.Vulnerability.ID = "CVE-2099-9999"
				in.Stage0.Resolution.Vulnerability.Aliases = nil
				in.Stage0.Resolution.Record.ResolvedID = "CVE-2099-9999"
			},
			want: CheckConflicting,
		},
		{
			name: "C07 version mismatch is conflicting",
			id:   CheckIDPackageVersion,
			mutate: func(in *CheckInput) {
				in.Stage0.PackageCheck.Class = CheckVersionMismatch
				in.Stage0.PackageCheck.Reason = "claimed v1.9.9 vs resolved v1.2.3"
			},
			want: CheckConflicting,
		},
		{
			name: "C07 complete-graph module absence is PASS fact",
			id:   CheckIDPackageVersion,
			mutate: func(in *CheckInput) {
				in.Stage0.PackageCheck.Class = CheckModuleAbsent
				in.Stage0.PackageCheck.Reason = "module absent from complete graph"
			},
			want: CheckPass,
		},
		{
			name: "C07 unresolved check is unverified",
			id:   CheckIDPackageVersion,
			mutate: func(in *CheckInput) {
				in.Stage0.PackageCheck.Class = CheckUnresolved
			},
			want: CheckUnverified,
		},
		{
			// The release Go version decides standard-library applicability
			// only (B39); a module claim is version-compared against the
			// module graph, so an unknown release toolchain must not gate it.
			name: "C08 unknown release toolchain is a limitation for a module claim",
			id:   CheckIDReleaseToolchain,
			mutate: func(in *CheckInput) {
				in.Stage0.ReleaseToolchain = ReleaseToolchainFact{}
			},
			want: CheckLimitation,
		},
		{
			name: "C08 unknown release toolchain blocks a stdlib claim",
			id:   CheckIDReleaseToolchain,
			mutate: func(in *CheckInput) {
				in.Stage0.ReleaseToolchain = ReleaseToolchainFact{}
				in.Stage0.PackageCheck.ResolvedPath = "internal/syscall/unix"
				in.Stage0.Input.Finding.Component.Package = "net/http"
			},
			want: CheckUnavailable,
		},
		{
			name: "C08 claim/evidence conflict is conflicting",
			id:   CheckIDReleaseToolchain,
			mutate: func(in *CheckInput) {
				in.Stage0.ReleaseToolchain.Conflict = true
			},
			want: CheckConflicting,
		},
		{
			name: "C08 provisioned mismatch is a limitation",
			id:   CheckIDReleaseToolchain,
			mutate: func(in *CheckInput) {
				in.Stage0.Toolchain = toolchain.Toolchain{Mismatch: true, Mode: toolchain.ModeLocal, Version: "1.26.0"}
			},
			want: CheckLimitation,
		},
		{
			name: "C09 artifact without digest is unverified",
			id:   CheckIDArtifactIdentity,
			mutate: func(in *CheckInput) {
				in.Stage0.Snapshot.Artifacts = append(in.Stage0.Snapshot.Artifacts, SnapshotFile{Path: "sbom.cdx.json", Role: "sbom"})
			},
			want: CheckUnverified,
		},
		{
			name: "C09 declared artifact missing is unavailable",
			id:   CheckIDArtifactIdentity,
			mutate: func(in *CheckInput) {
				in.Stage0.Input.Finding.Target.SBOM = "missing.cdx.json"
			},
			want: CheckUnavailable,
		},
		{
			name: "C10 partial fact validation is unverified",
			id:   CheckIDEvidenceReferences,
			mutate: func(in *CheckInput) {
				in.Validation = FactValidation{Status: ValidationPartial, References: []ReferenceCheck{{
					Subject: "c1", Status: FactUnreferenced, ExpectedRepair: "cite a declared evidence id",
				}}}
			},
			want: CheckUnverified,
		},
		{
			name: "C10 failed fact validation is invalid",
			id:   CheckIDEvidenceReferences,
			mutate: func(in *CheckInput) {
				in.Validation = FactValidation{Status: ValidationFailed, References: []ReferenceCheck{{
					EvidenceID: "ev-1", Status: FactInvalid, Reason: "path outside snapshot",
				}}}
			},
			want: CheckInvalid,
		},
		{
			name: "C11 local observation cannot prove global absence",
			id:   CheckIDScopeAlternatives,
			mutate: func(in *CheckInput) {
				in.Facts = []DecisionFact{{
					ID: "f-1", Kind: "reachability", Status: ObsRefutes,
					Subject: "vulnerableFunc", Scope: "observation",
				}}
			},
			want: CheckUnverified,
		},
		{
			name: "C11 closed-scope absence is accepted as a fact",
			id:   CheckIDScopeAlternatives,
			mutate: func(in *CheckInput) {
				in.Facts = []DecisionFact{{
					ID: "f-1", Kind: FactPackagePresence, Status: ObsRefutes,
					Subject: "example.org/library", Scope: "build-graph",
					Provenance: []string{"go list -m all"},
				}}
			},
			want: CheckPass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := CheckInput{Stage0: goodStage0(), Assessment: goodAssessment(), Validation: completeValidation()}
			tc.mutate(&in)
			got := checkStatus(t, tc.id, in)
			if got.Status != tc.want {
				t.Fatalf("check %s = %s, want %s (reasons=%v)", tc.id, got.Status, tc.want, got.Reasons)
			}
		})
	}
}

// TestCheckMatrixFinalGate covers C12/C13 — the checks that verify the
// composed package at the final gate.
func TestCheckMatrixFinalGate(t *testing.T) {
	s0 := goodStage0()
	a := goodAssessment()
	pkg, err := ComposeDecision(context.Background(), s0, a, completeValidation(), nil, nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}

	t.Run("C12 accepts the composed recommendation", func(t *testing.T) {
		in := CheckInput{Package: &pkg, Facts: pkg.Facts, Rules: DefaultRules()}
		got := checkStatus(t, CheckIDRiskPolicy, in)
		if got.Status != CheckPass {
			t.Fatalf("C12 = %s reasons=%v", got.Status, got.Reasons)
		}
	})
	t.Run("C12 catches a recommendation above the rule ceiling", func(t *testing.T) {
		forged := pkg
		forged.MachineDisposition.Recommendation = RecommendationDismissed
		in := CheckInput{Package: &forged, Facts: pkg.Facts, Rules: DefaultRules()}
		got := checkStatus(t, CheckIDRiskPolicy, in)
		if got.Status != CheckConflicting {
			t.Fatalf("C12 = %s, want CONFLICTING", got.Status)
		}
	})
	t.Run("C12 accepts a recorded demotion", func(t *testing.T) {
		demoted, err := ComposeDecision(context.Background(), s0, a, FactValidation{
			Status: ValidationPartial,
			References: []ReferenceCheck{{
				Subject: "c1", Status: FactUnreferenced, Effect: EffectBlocksRiskReduction,
			}},
		}, nil, nil)
		if err != nil {
			t.Fatalf("compose demoted: %v", err)
		}
		if demoted.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("demoted package recommendation = %s", demoted.MachineDisposition.Recommendation)
		}
		in := CheckInput{Package: &demoted, Facts: demoted.Facts, Rules: DefaultRules()}
		got := checkStatus(t, CheckIDRiskPolicy, in)
		if got.Status != CheckPass {
			t.Fatalf("C12 = %s reasons=%v, want PASS for recorded demotion", got.Status, got.Reasons)
		}
	})
	t.Run("C12 without package is unavailable", func(t *testing.T) {
		got := checkStatus(t, CheckIDRiskPolicy, CheckInput{Facts: pkg.Facts})
		if got.Status != CheckUnavailable {
			t.Fatalf("C12 = %s, want UNAVAILABLE", got.Status)
		}
	})

	t.Run("C13 accepts a valid package", func(t *testing.T) {
		got := checkStatus(t, CheckIDPackageStability, CheckInput{Package: &pkg})
		if got.Status != CheckPass {
			t.Fatalf("C13 = %s reasons=%v", got.Status, got.Reasons)
		}
	})
	t.Run("C13 rejects a contract violation", func(t *testing.T) {
		broken := pkg
		broken.MachineDisposition.Recommendation = Recommendation("TAMPERED")
		got := checkStatus(t, CheckIDPackageStability, CheckInput{Package: &broken})
		if got.Status != CheckInvalid {
			t.Fatalf("C13 = %s, want INVALID", got.Status)
		}
	})
	t.Run("C13 rejects drift rendered as a stability result", func(t *testing.T) {
		broken := pkg
		broken.TechnicalAssessment.StabilityResult = "drift"
		got := checkStatus(t, CheckIDPackageStability, CheckInput{Package: &broken})
		if got.Status != CheckInvalid {
			t.Fatalf("C13 = %s, want INVALID for drift-as-package", got.Status)
		}
	})
}
