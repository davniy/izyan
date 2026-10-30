package eval_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval"
)

func record(r *eval.Report, c eval.Case, verdict domain.Verdict) {
	r.Record(c, verdict, "", nil, "", "", nil, nil, eval.Projection{})
}

func TestReportFalseSafe(t *testing.T) {
	var r eval.Report
	// Exploitable expectation, analyzer says NO_EXPLOIT_PATH_FOUND.
	record(&r, eval.Case{ID: "c1", Vuln: "V-1", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictNoExploitPathFound)
	if r.Metrics.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want 1", r.Metrics.FalseSafe)
	}
	if !r.Results[0].FalseSafe {
		t.Fatal("result not flagged false-safe")
	}

	// Safe expectation met by a safe verdict — not false-safe.
	record(&r, eval.Case{ID: "c2", Vuln: "V-2", Expect: []string{"NO_EXPLOIT_PATH_FOUND"}},
		domain.VerdictNoExploitPathFound)
	if r.Metrics.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want still 1", r.Metrics.FalseSafe)
	}

	// INCONCLUSIVE where EXPLOITABLE expected: a fail but not false-safe.
	record(&r, eval.Case{ID: "c3", Vuln: "V-3", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictInconclusive)
	if r.Metrics.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want still 1", r.Metrics.FalseSafe)
	}
	if r.Metrics.ExpectPass != 1 || r.Metrics.ExpectFail != 2 || r.Metrics.Total != 3 {
		t.Fatalf("metrics=%+v", r.Metrics)
	}
}

func TestReportInconclusiveCounted(t *testing.T) {
	var r eval.Report
	record(&r, eval.Case{Vuln: "V-1", Expect: []string{"INCONCLUSIVE"}}, domain.VerdictInconclusive)
	record(&r, eval.Case{Vuln: "V-2"}, domain.VerdictInconclusive)
	if r.Metrics.Inconclusive != 2 {
		t.Fatalf("inconclusive=%d", r.Metrics.Inconclusive)
	}
	if r.Metrics.NoExpect != 1 {
		t.Fatalf("informational=%d", r.Metrics.NoExpect)
	}
}

func TestReportSignalClearedCountsOnlySafeVerdictsAgainstGovulncheckSignals(t *testing.T) {
	var r eval.Report
	for _, tc := range []struct {
		id       string
		verdict  domain.Verdict
		baseline string
		expect   []string
	}{
		{"negative", domain.VerdictNoExploitPathFound, eval.BaselinePackageLevel, []string{"NO_EXPLOIT_PATH_FOUND"}},
		{"positive", domain.VerdictExploitable, eval.BaselineReachable, []string{"EXPLOITABLE"}},
		{"silent", domain.VerdictNotAffected, eval.BaselineSilent, []string{"NOT_AFFECTED"}},
		{"module", domain.VerdictNotAffected, "module-level", []string{"NOT_AFFECTED"}},
		{"unsafe", domain.VerdictNoExploitPathFound, eval.BaselineReachable, []string{"EXPLOITABLE"}},
	} {
		r.Record(eval.Case{ID: tc.id, Expect: tc.expect}, tc.verdict, "", nil, "", "", nil, nil, eval.Projection{})
		r.RecordBaseline(tc.baseline)
	}
	if r.Metrics.GovulncheckSignals != 3 || r.Metrics.SignalCleared != 1 {
		t.Fatalf("signal metrics=%+v; want 1/3", r.Metrics)
	}
	if r.Metrics.ReachableSignals != 2 || r.Metrics.ReachableCleared != 0 ||
		r.Metrics.PackageLevelSignals != 1 || r.Metrics.PackageLevelCleared != 1 {
		t.Fatalf("signal breakdown=%+v; want reachable 0/2 and package-level 1/1", r.Metrics)
	}
}

func TestReportClaimsAssert(t *testing.T) {
	var r eval.Report
	r.Record(eval.Case{
		Vuln:   "V-1",
		Expect: []string{"EXPLOITABLE"},
		Claims: map[string]string{"C-REACH": "TRUE", "C-INPUT": "TRUE"},
	}, domain.VerdictExploitable, "", map[string]string{
		"C-REACH": "TRUE", "C-INPUT": "TRUE",
	}, "", "", nil, nil, eval.Projection{})
	if r.Metrics.ClaimsFail != 0 {
		t.Fatalf("claims_fail=%d want 0", r.Metrics.ClaimsFail)
	}
	r.Record(eval.Case{
		Vuln:   "V-2",
		Claims: map[string]string{"C-EXPOSED": "FALSE"},
	}, domain.VerdictNoExploitPathFound, "", map[string]string{
		"C-EXPOSED": "TRUE",
	}, "", "", nil, nil, eval.Projection{})
	if r.Metrics.ClaimsFail != 1 {
		t.Fatalf("claims_fail=%d want 1", r.Metrics.ClaimsFail)
	}
}

func TestCaseUnmarshalRootCauses(t *testing.T) {
	raw := `{"cases":[{
		"vuln":"GO-X","repo":"testdata/ifaceprod",
		"root_causes":[
			"example.com/dep/vuln.Parse",
			{"package":"example.com/dep/vuln","symbol":"URI.String","role":"SINK"}
		],
		"expect":["INCONCLUSIVE"],
		"expect_claims":{"C-ROUNDTRIP":"FALSE"}
	}]}`
	var c eval.Corpus
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	rc := c.Cases[0].RootCauses
	if len(rc) != 2 {
		t.Fatalf("root_causes=%+v", rc)
	}
	if rc[0].Package != "example.com/dep/vuln" || rc[0].Symbol != "Parse" {
		t.Fatalf("string form parsed wrong: %+v", rc[0].RootCause)
	}
	if rc[1].Symbol != "URI.String" || rc[1].Package != "example.com/dep/vuln" {
		t.Fatalf("object form parsed wrong: %+v", rc[1].RootCause)
	}
	if rc[0].Role != domain.RootCauseSink {
		t.Fatalf("role=%q want SINK", rc[0].Role)
	}
}

// TestOutcomeAccounting keeps the three terminal classifications separate: a
// failed analysis is not a completed analysis, an external dependency is not a
// definitive answer, and neither can be scored as a success.
func TestOutcomeAccounting(t *testing.T) {
	decided := func(verdict domain.Verdict) eval.Projection {
		return eval.Projection{
			Available: true, Outcome: domain.OutcomeDecided, Verdict: verdict,
			RequestedID: "GO-2023-2153", RequestedKind: "ADVISORY_ENTRIES",
			Profile: "zero_trust", Build: "linux/amd64", FailureCodes: nil,
		}
	}
	var r eval.Report
	// Decided safe answer satisfies a safe expectation and is a definitive
	// answer.
	r.Record(eval.Case{ID: "safe", Expect: []string{"NOT_AFFECTED"}},
		domain.VerdictNotAffected, "", nil, "", "", nil, nil, decided(domain.VerdictNotAffected))
	// Decided positive satisfies an EXPLOITABLE expectation.
	r.Record(eval.Case{ID: "positive", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictExploitable, "", nil, "", "", nil, nil, decided(domain.VerdictExploitable))
	// A false positive is counted separately from a false safe.
	r.Record(eval.Case{ID: "over-call", Expect: []string{"NOT_AFFECTED"}},
		domain.VerdictExploitable, "", nil, "", "", nil, nil, decided(domain.VerdictExploitable))
	// A false safe is still counted and is never a decided success.
	r.Record(eval.Case{ID: "under-call", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictNoExploitPathFound, "", nil, "", "", nil, nil, decided(domain.VerdictNoExploitPathFound))

	// An external dependency publishes INCONCLUSIVE and satisfies an
	// INCONCLUSIVE expectation, but never counts as a definitive answer.
	r.Record(eval.Case{ID: "external", Expect: []string{"INCONCLUSIVE"}},
		domain.VerdictInconclusive, "", nil, "", "", nil, nil, eval.Projection{
			Available: true, Outcome: domain.OutcomeExternal, Verdict: domain.VerdictInconclusive,
			ExternalDependencies: []string{"the shipped Go toolchain is not recorded"},
		})
	// An external answer is not the definitive answer the case wanted.
	r.Record(eval.Case{ID: "external-vs-positive", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictInconclusive, "", nil, "", "", nil, nil, eval.Projection{
			Available: true, Outcome: domain.OutcomeExternal, Verdict: domain.VerdictInconclusive,
			ExternalDependencies: []string{"whether the deployed socket admits hostile peers"},
		})

	// A failed analysis has no verdict: it is not a completion and not an
	// abstention.
	r.Record(eval.Case{ID: "failed", Expect: []string{"INCONCLUSIVE"}},
		"", "", nil, "", "", nil, nil, eval.Projection{
			Available: true, Outcome: domain.OutcomeFailed,
			FailureCodes: []string{"PROOF/TRIGGER_PROOF_INCOMPLETE"},
		})
	// A case that expects an explicit failure passes on the FAILED token.
	r.Record(eval.Case{ID: "failed-expected", Expect: []string{"FAILED"}},
		"", "", nil, "", "", nil, nil, eval.Projection{
			Available: true, Outcome: domain.OutcomeFailed,
			FailureCodes: []string{"SCOPE/UNSUPPORTED_NEGATIVE_SCOPE"},
		})
	// A legacy result without a projection keeps verdict-based accounting.
	record(&r, eval.Case{ID: "legacy", Expect: []string{"NO_EXPLOIT_PATH_FOUND"}},
		domain.VerdictNoExploitPathFound)

	m := r.Metrics
	if m.Decided != 4 || m.ExternalDependency != 2 || m.AnalysisFailed != 2 {
		t.Fatalf("outcome counts = decided %d, external %d, failed %d; want 4/2/2",
			m.Decided, m.ExternalDependency, m.AnalysisFailed)
	}
	if m.FalseSafe != 1 || m.FalsePositive != 1 {
		t.Fatalf("error counts = false-safe %d, false-positive %d; want 1/1", m.FalseSafe, m.FalsePositive)
	}
	if m.Inconclusive != 2 {
		t.Fatalf("inconclusive = %d, want the 2 external answers only", m.Inconclusive)
	}
	if m.ExpectPass != 5 || m.ExpectFail != 4 {
		t.Fatalf("expect pass/fail = %d/%d; want 5/4", m.ExpectPass, m.ExpectFail)
	}
	if got := m.Verdicts[string(domain.VerdictInconclusive)]; got != 2 {
		t.Fatalf("verdicts[INCONCLUSIVE] = %d, want 2", got)
	}
	if _, ok := m.Verdicts[""]; ok {
		t.Fatal("a failed analysis must not contribute an empty verdict bucket")
	}
	// The failure and the external dependency are distinguishable in the
	// persisted report.
	var failed, external *eval.Result
	for i := range r.Results {
		switch r.Results[i].Case.ID {
		case "failed":
			failed = &r.Results[i]
		case "external":
			external = &r.Results[i]
		}
	}
	if failed == nil || failed.Verdict != "" || failed.AssessmentOutcome != "FAILED" ||
		len(failed.FailureCodes) != 1 {
		t.Fatalf("failed result = %+v", failed)
	}
	if external == nil || external.Verdict != string(domain.VerdictInconclusive) ||
		external.AssessmentOutcome != "EXTERNAL_DEPENDENCY" || len(external.ExternalDependencies) != 1 {
		t.Fatalf("external result = %+v", external)
	}
	if !strings.Contains(r.Markdown(), "analysis failed: 2") {
		t.Fatalf("markdown lost the failure population:\n%s", r.Markdown())
	}
}

func TestMarkdownRenders(t *testing.T) {
	var r eval.Report
	record(&r, eval.Case{ID: "c1", Vuln: "V-1", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictNoExploitPathFound)
	md := r.Markdown()
	if !strings.Contains(md, "false-safe: 1") || !strings.Contains(md, "FALSE-SAFE") {
		t.Fatalf("markdown missing false-safe markers:\n%s", md)
	}
}

func TestReportClearedSplits(t *testing.T) {
	var r eval.Report
	// auto + deeper: locus falsifier, no expert input
	r.Record(eval.Case{ID: "deep", Expect: []string{"NO_EXPLOIT_PATH_FOUND"}},
		domain.VerdictNoExploitPathFound, "", nil,
		domain.FalsifierLocusFunctionUnreached, "", nil, nil, eval.Projection{})
	r.RecordBaseline(eval.BaselineReachable)
	// expert + deeper: non_locus makes it assisted
	r.Record(eval.Case{ID: "expert",
		Expect:   []string{"NO_EXPLOIT_PATH_FOUND"},
		NonLocus: []domain.LocusDecision{{Basis: "test"}},
	}, domain.VerdictNoExploitPathFound, "", nil,
		domain.FalsifierLocusPackageAbsent, "", nil, nil, eval.Projection{})
	r.RecordBaseline(eval.BaselinePackageLevel)
	// auto + echo: govulncheck-silence reproduces its own contract
	r.Record(eval.Case{ID: "echo", Expect: []string{"NO_EXPLOIT_PATH_FOUND"}},
		domain.VerdictNoExploitPathFound, "", nil,
		domain.FalsifierGovulncheckSilence, "", nil, nil, eval.Projection{})
	r.RecordBaseline(eval.BaselinePackageLevel)
	// auto + affectedness
	r.Record(eval.Case{ID: "aff", Expect: []string{"NOT_AFFECTED"}},
		domain.VerdictNotAffected, "", nil, "", "", nil, nil, eval.Projection{})
	r.RecordBaseline(eval.BaselineReachable)

	m := r.Metrics
	if m.SignalCleared != 4 || m.SignalClearedAuto != 3 || m.SignalClearedExpert != 1 {
		t.Fatalf("auto/expert split=%+v; want 4 total, 3 auto, 1 expert", m)
	}
	if m.ClearedDeeper != 2 || m.ClearedEcho != 1 || m.ClearedAffectedness != 1 {
		t.Fatalf("evidence-class split=%+v; want 2 deeper, 1 echo, 1 affectedness", m)
	}
	md := r.Markdown()
	for _, want := range []string{"cleared auto", "deeper: 2", "locus-function-unreached"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestWriteAuditPackets_OnlySignalCleared(t *testing.T) {
	dir := t.TempDir()
	var r eval.Report
	r.Record(eval.Case{ID: "cleared-case", Vuln: "GO-X", Expect: []string{"NO_EXPLOIT_PATH_FOUND"}},
		domain.VerdictNoExploitPathFound, "", nil,
		domain.FalsifierConstantOrGeneratedInput, "", []string{"EV-1"}, nil, eval.Projection{})
	r.RecordBaseline(eval.BaselineReachable)
	r.Record(eval.Case{ID: "loud-case", Vuln: "GO-Y", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictExploitable, "", nil, "", "", nil, nil, eval.Projection{})
	r.RecordBaseline(eval.BaselineReachable)

	if err := eval.WriteAuditPackets(dir, "eval/corpus-real.json", "eval/.gen", r,
		map[string]string{"cleared-case": "eval/.gen/cleared-case"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "cleared-case.md" {
		t.Fatalf("audit dir=%v; want exactly cleared-case.md", entries)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "cleared-case.md"))
	md := string(data)
	for _, want := range []string{"constant-or-generated-input", "EV-1", "govulncheck -mode source", "deeper"} {
		if !strings.Contains(md, want) {
			t.Fatalf("audit packet missing %q:\n%s", want, md)
		}
	}
}

// Deployment context fields on a case parse from JSON — the batch harness
// propagates them into analyzeOpts the same way CLI flags do.
func TestCaseDeployFields(t *testing.T) {
	var c eval.Corpus
	raw := `{"cases":[{"vuln":"GO-TEST","repo":"/r","trusted_peer":true,
		"perimeter":"cluster","deploy_manifests":"/m1,/m2"}]}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	got := c.Cases[0]
	if !got.TrustedPeer || got.Perimeter != "cluster" || got.DeployManifests != "/m1,/m2" {
		t.Fatalf("case=%+v", got)
	}
}
