package finding

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// axisAdmittedScope is an exact-record scope that admits negative closure.
func axisAdmittedScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID:  id,
		ResolvedID:   id,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageComplete,
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

// axisRefusedScope is a CVE scope: structurally valid but never closure
// authority.
func axisRefusedScope(id string) *domain.AdvisoryScope {
	scope := axisAdmittedScope(id)
	scope.Kind = domain.ScopeCVE
	scope.Coverage = domain.CoverageKnownOnly
	return scope
}

func axisPositiveAffected(scope *domain.AdvisoryScope) domain.AffectedResult {
	return domain.AffectedResult{
		Scope:           scope,
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}
}

func TestAssessmentAxesVulnerabilityRoutes(t *testing.T) {
	positive := axisPositiveAffected(axisAdmittedScope("GO-2026-0001"))
	implementationAbsent := positive
	implementationAbsent.VulnerableImplementationPresent = domain.ClaimFalse

	moduleAbsent := axisPositiveAffected(axisAdmittedScope("GO-2026-0001"))
	moduleAbsent.ModulePresent = domain.ClaimFalse
	versionUnaffected := axisPositiveAffected(axisAdmittedScope("GO-2026-0001"))
	versionUnaffected.VersionAffected = domain.ClaimFalse
	packageAbsent := axisPositiveAffected(axisAdmittedScope("GO-2026-0001"))
	packageAbsent.PackagePresent = domain.ClaimFalse
	buildIrrelevant := axisPositiveAffected(axisAdmittedScope("GO-2026-0001"))
	buildIrrelevant.BuildRelevant = domain.ClaimFalse

	refusedNegative := axisPositiveAffected(axisRefusedScope("CVE-2026-0001"))
	refusedNegative.ModulePresent = domain.ClaimFalse

	cases := []struct {
		name     string
		outcome  domain.AssessmentOutcome
		verdict  domain.Verdict
		affected domain.AffectedResult
		want     AxisFact
	}{
		{
			name:     "earned not-affected is false even beside affirmative facts",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNotAffected,
			affected: positive,
			want:     AxisFalse,
		},
		{
			name:     "module absence",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNotAffected,
			affected: moduleAbsent,
			want:     AxisFalse,
		},
		{
			name:     "version exclusion",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNotAffected,
			affected: versionUnaffected,
			want:     AxisFalse,
		},
		{
			name:     "package absence",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNotAffected,
			affected: packageAbsent,
			want:     AxisFalse,
		},
		{
			name:     "build irrelevance",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNotAffected,
			affected: buildIrrelevant,
			want:     AxisFalse,
		},
		{
			name:     "admitted implementation absence",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNotAffected,
			affected: implementationAbsent,
			want:     AxisFalse,
		},
		{
			name:     "optional implementation axis unknown keeps affirmative applicability",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNoExploitPathFound,
			affected: positive,
			want:     AxisTrue,
		},
		{
			name:     "NEPF alone supplies no affirmative fact",
			outcome:  domain.OutcomeDecided,
			verdict:  domain.VerdictNoExploitPathFound,
			affected: domain.AffectedResult{Scope: axisAdmittedScope("GO-2026-0002")},
			want:     AxisUnknown,
		},
		{
			name:     "failed analysis retains established applicability",
			outcome:  domain.OutcomeFailed,
			affected: positive,
			want:     AxisTrue,
		},
		{
			name:     "external dependency retains established applicability",
			outcome:  domain.OutcomeExternal,
			verdict:  domain.VerdictInconclusive,
			affected: positive,
			want:     AxisTrue,
		},
		{
			name:    "failed analysis with no facts is unknown",
			outcome: domain.OutcomeFailed,
			want:    AxisUnknown,
		},
		{
			name:     "refused component negative is never false",
			outcome:  domain.OutcomeFailed,
			affected: refusedNegative,
			want:     AxisUnknown,
		},
		{
			name:    "admitted exploitability positive entails vulnerability",
			outcome: domain.OutcomeDecided,
			verdict: domain.VerdictExploitable,
			want:    AxisTrue,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vulnerabilityFact(tc.outcome, tc.verdict, tc.affected); got != tc.want {
				t.Fatalf("vulnerabilityFact() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAssessmentAxesExploitability(t *testing.T) {
	cases := []struct {
		name    string
		outcome domain.AssessmentOutcome
		verdict domain.Verdict
		want    AxisFact
	}{
		{"decided exploitable", domain.OutcomeDecided, domain.VerdictExploitable, AxisTrue},
		{"decided no-exploit-path", domain.OutcomeDecided, domain.VerdictNoExploitPathFound, AxisFalse},
		{"decided not-affected", domain.OutcomeDecided, domain.VerdictNotAffected, AxisNotApplicable},
		{"failed", domain.OutcomeFailed, "", AxisUnknown},
		{"external", domain.OutcomeExternal, domain.VerdictInconclusive, AxisUnknown},
		{"decided inconclusive", domain.OutcomeDecided, domain.VerdictInconclusive, AxisUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exploitabilityFact(tc.outcome, tc.verdict); got != tc.want {
				t.Fatalf("exploitabilityFact() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAssessmentAxesInvariant(t *testing.T) {
	contradiction := AssessmentAxes{Records: []AxisRow{{
		SubjectID:             "GO-2026-0001",
		AssessmentID:          "assessment",
		Profile:               domain.ProfileZeroTrust,
		VulnerableCodeInBuild: AxisFalse,
		Exploitable:           AxisTrue,
	}}}
	if err := contradiction.validate(); err == nil {
		t.Fatal("FALSE + TRUE was accepted as a valid projection")
	}

	consistent := AssessmentAxes{
		Requested: []AxisRow{{SubjectID: "CVE-2026-1", VulnerableCodeInBuild: AxisUnknown, Exploitable: AxisUnknown}},
		Records: []AxisRow{
			{SubjectID: "GO-2026-1", VulnerableCodeInBuild: AxisTrue, Exploitable: AxisTrue},
			{SubjectID: "GO-2026-2", VulnerableCodeInBuild: AxisFalse, Exploitable: AxisNotApplicable},
			{SubjectID: "GO-2026-3", VulnerableCodeInBuild: AxisUnknown, Exploitable: AxisFalse},
		},
	}
	if err := consistent.validate(); err != nil {
		t.Fatalf("consistent projection refused: %v", err)
	}
}
