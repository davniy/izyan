package eval_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/eval"
)

type baselineRunner struct {
	raw     string
	pattern string
	err     error
}

func (r baselineRunner) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	pattern := r.pattern
	if pattern == "" {
		pattern = "./..."
	}
	if r.err != nil {
		return []byte(r.raw), pattern, r.err
	}
	return []byte(r.raw), pattern, nil
}

const baselineConfig = `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n"

func baselineEvidence(outcome domain.GovulncheckOutcome, content string) domain.Evidence {
	return domain.Evidence{
		ID:   "EV-GV-1",
		Kind: domain.EvidenceGovulncheck,
		Govulncheck: &domain.GovulncheckRun{
			Outcome: outcome,
			Coverage: domain.GovulncheckCoverage{
				AdvisoryID: "V-1",
				Advisory:   domain.GovulncheckCoverageCovered,
			},
		},
		Content: content,
	}
}

func baselineEvidenceWithCoverage(outcome domain.GovulncheckOutcome, content string, advisory domain.GovulncheckAdvisoryCoverage, scopeComplete bool) domain.Evidence {
	ev := baselineEvidence(outcome, content)
	ev.Govulncheck.Coverage.Advisory = advisory
	ev.Govulncheck.Coverage.ScopeComplete = scopeComplete
	return ev
}

func baselineVuln() domain.Vulnerability {
	return domain.Vulnerability{ID: "V-1", Module: "example.com/dep"}
}

func TestBaselineSeparatesModulePackageAndReachableFindings(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"module only", baselineConfig + `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep"}]}}`, eval.BaselineModuleLevel},
		{"package imported", baselineConfig + `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep","package":"example.com/dep/vuln"}]}}`, eval.BaselinePackageLevel},
		{"symbol reachable", baselineConfig + `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep","package":"example.com/dep/vuln","function":"Sink"}]}}`, eval.BaselineReachable},
		{"package after module", baselineConfig + `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep"}]}}
{"finding":{"osv":"V-1","trace":[{"package":"example.com/dep/vuln"}]}}`, eval.BaselinePackageLevel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fromEvidence := eval.BaselineFromEvidence(
				baselineEvidence(domain.GovulncheckCompletedWithResults, tc.raw), baselineVuln())
			if fromEvidence != tc.want {
				t.Fatalf("fromEvidence=%q want %q", fromEvidence, tc.want)
			}
			got := eval.Baseline(context.Background(), baselineRunner{raw: tc.raw}, "", baselineVuln(), domain.ProductSnapshot{})
			if got != tc.want {
				t.Fatalf("Baseline=%q want %q", got, tc.want)
			}
		})
	}
}

func TestBaselineCoverageGatesSilence(t *testing.T) {
	empty := baselineConfig
	for _, tc := range []struct {
		name          string
		outcome       domain.GovulncheckOutcome
		advisory      domain.GovulncheckAdvisoryCoverage
		scopeComplete bool
		want          string
	}{
		{"covered full scope is silent", domain.GovulncheckCompletedEmpty, domain.GovulncheckCoverageCovered, true, eval.BaselineSilent},
		{"covered narrowed scope is not silent", domain.GovulncheckCompletedEmpty, domain.GovulncheckCoverageCovered, false, eval.BaselineCoverageIncomplete},
		{"unknown advisory coverage is not silent", domain.GovulncheckCompletedEmpty, domain.GovulncheckCoverageUnknown, true, eval.BaselineCoverageIncomplete},
		{"unknown scope is not silent", domain.GovulncheckCompletedEmpty, domain.GovulncheckCoverageCovered, false, eval.BaselineCoverageIncomplete},
		{"advisory absent from db", domain.GovulncheckCompletedEmpty, domain.GovulncheckCoverageNotInDB, true, eval.BaselineNotInDB},
		{"findings for other advisories with full coverage", domain.GovulncheckCompletedWithResults, domain.GovulncheckCoverageCovered, true, eval.BaselineSilent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := eval.BaselineFromEvidence(
				baselineEvidenceWithCoverage(tc.outcome, empty, tc.advisory, tc.scopeComplete), baselineVuln())
			if got != tc.want && !strings.HasPrefix(got, tc.want+":") {
				t.Fatalf("baseline=%q want %q", got, tc.want)
			}
		})
	}
}

func TestBaselineFailedPrefixStaysError(t *testing.T) {
	// The prefix is a valid finding, but the process failed: the typed
	// outcome, not the parseable bytes, is authoritative.
	raw := baselineConfig + `{"finding":{"osv":"V-1","trace":[{"package":"example.com/dep/vuln","function":"Sink"}]}}`
	ev := baselineEvidence(domain.GovulncheckFailed, raw)
	ev.Govulncheck.Error = "exit status 1"
	got := eval.BaselineFromEvidence(ev, baselineVuln())
	if !strings.HasPrefix(got, eval.BaselineError) {
		t.Fatalf("failed run classified as %q, want error", got)
	}
	for _, bad := range []string{eval.BaselineReachable, eval.BaselinePackageLevel, eval.BaselineSilent} {
		if got == bad {
			t.Fatalf("failed run classified as %q", bad)
		}
	}

	got = eval.Baseline(context.Background(), baselineRunner{raw: raw, err: errors.New("exit status 1")}, "", baselineVuln(), domain.ProductSnapshot{})
	if !strings.HasPrefix(got, eval.BaselineError) {
		t.Fatalf("Baseline failed run classified as %q, want error", got)
	}
}

func TestBaselineNotRunAndLegacyRecordsAreErrors(t *testing.T) {
	notRun := baselineEvidence(domain.GovulncheckNotRun, "")
	notRun.Govulncheck.Error = "govulncheck runner not configured"
	if got := eval.BaselineFromEvidence(notRun, baselineVuln()); !strings.HasPrefix(got, eval.BaselineError) {
		t.Fatalf("not-run record classified as %q, want error", got)
	}
	legacy := domain.Evidence{
		ID:      "EV-LEGACY",
		Kind:    domain.EvidenceGovulncheck,
		Content: baselineConfig + `{"finding":{"osv":"V-1","trace":[{"package":"example.com/dep/vuln"}]}}`,
	}
	if got := eval.BaselineFromEvidence(legacy, baselineVuln()); !strings.HasPrefix(got, eval.BaselineError) {
		t.Fatalf("legacy record classified as %q, want error", got)
	}
}

func TestBaselineCompletedUndecodableIsError(t *testing.T) {
	ev := baselineEvidence(domain.GovulncheckCompletedEmpty, "not a govulncheck stream")
	if got := eval.BaselineFromEvidence(ev, baselineVuln()); !strings.HasPrefix(got, eval.BaselineError) {
		t.Fatalf("undecodable completed record classified as %q, want error", got)
	}
}
