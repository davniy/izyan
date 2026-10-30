package states_test

// Deterministic end-to-end acceptance for the two negative-admission gates:
//
//  1. a build-dependent negative must describe an identified product build
//     (non-nil, validated, scoped target matching the effective context);
//  2. its measurement must have completed and covered the negated subject.
//
// Every test here drives the real workflow (snapshot → affected → root cause
// → model → evidence → conditions → negative check → verdict → report) on a
// small fixture. The only synthetic inputs are the ones the harness already
// owns: a stub affected chain, a fake govulncheck runner and — where a test
// crosses the inventory axis — one typed package-list record, exactly the
// evidence `go list` would produce. Assertions target the *first* erroneous
// claim (result, falsifier, verification, cited measurement) as well as the
// terminal verdict and the persisted VEX exports.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/report"
	"github.com/davniy/izyan/internal/repository"
	"github.com/davniy/izyan/internal/states"
	"github.com/davniy/izyan/internal/vulnerability"
)

const provenanceAdvisoryID = "GO-TEST-PROV"

// provenanceVulnerability is the advisory identity every case in this file
// runs: an exact, fully represented advisory record (so a negative conclusion
// may close the requested identity) over the named module and symbols.
func provenanceVulnerability(module string, symbols ...domain.SymbolRef) *domain.Vulnerability {
	return &domain.Vulnerability{
		ID:              provenanceAdvisoryID,
		Module:          module,
		Scope:           exactScope(provenanceAdvisoryID),
		AffectedSymbols: symbols,
	}
}

// writeProvenanceModel persists one exploit model document.
func writeProvenanceModel(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// provenanceCase is one fully driven case plus its persisted artifact dir.
type provenanceCase struct {
	caseDir string
	dir     string
	c       *domain.AnalysisCase
}

// runProvenanceCase drives the workflow and requires it to complete: an
// uncompleted state would hide the claim-level assertions behind an
// infrastructure outcome.
func runProvenanceCase(t *testing.T, deps engineDeps) provenanceCase {
	t.Helper()
	run := runProvenanceCaseState(t, deps, domain.StateCompleted)
	if run.c.Verdict == nil {
		t.Fatal("completed case carries no verdict")
	}
	return run
}

// runProvenanceCaseState drives the workflow and asserts its terminal state.
// Refusal cases now terminate FAILED with a typed cause and no verdict; they
// still write their diagnostic report.
func runProvenanceCaseState(t *testing.T, deps engineDeps, want domain.WorkflowState) provenanceCase {
	t.Helper()
	c := runEngine(t, deps)
	if c.Workflow.State != want {
		t.Fatalf("state=%s reason=%s, want %s", c.Workflow.State, c.Workflow.Reason, want)
	}
	return provenanceCase{caseDir: deps.CaseDir, c: c}
}

// artifactDir is the directory report.Write populated for the case.
func (p provenanceCase) artifactDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(p.caseDir, string(p.c.ID))
}

// vexStatuses decodes the persisted OpenVEX statement status and the
// persisted CycloneDX analysis state for the case's vulnerability.
func (p provenanceCase) vexStatuses(t *testing.T) (openVEX, cyclonedx string) {
	t.Helper()
	var ov struct {
		Statements []struct {
			Status string `json:"status"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(p.artifactDir(t), "openvex.json")), &ov); err != nil {
		t.Fatalf("decode openvex.json: %v", err)
	}
	if len(ov.Statements) != 1 {
		t.Fatalf("openvex statements=%d, want 1", len(ov.Statements))
	}
	var cdx struct {
		Vulnerabilities []struct {
			Analysis struct {
				State string `json:"state"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(p.artifactDir(t), "cyclonedx.json")), &cdx); err != nil {
		t.Fatalf("decode cyclonedx.json: %v", err)
	}
	if len(cdx.Vulnerabilities) != 1 {
		t.Fatalf("cyclonedx vulnerabilities=%d, want 1", len(cdx.Vulnerabilities))
	}
	return ov.Statements[0].Status, cdx.Vulnerabilities[0].Analysis.State
}

// runOutcome returns the single typed govulncheck record the case recorded.
func runOutcome(t *testing.T, c *domain.AnalysisCase) *domain.Evidence {
	t.Helper()
	var found *domain.Evidence
	count := 0
	for i := range c.EvidenceGraph.Evidence {
		e := &c.EvidenceGraph.Evidence[i]
		if e.Kind != domain.EvidenceGovulncheck {
			continue
		}
		count++
		found = e
	}
	if count != 1 {
		t.Fatalf("case recorded %d govulncheck measurements, want exactly one run record", count)
	}
	if found.Govulncheck == nil {
		t.Fatal("case recorded no typed govulncheck run")
	}
	return found
}

// assertNoSilenceFalsifier: a failed or not-run measurement never produces a
// silence-derived falsifier, on any claim.
func assertNoSilenceFalsifier(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	for _, cl := range c.Claims {
		if cl.Falsifier == domain.FalsifierGovulncheckSilence {
			t.Fatalf("claim %s carries a silence-derived falsifier from a run that did not measure: %+v",
				cl.ConditionID, cl)
		}
	}
}

// claimLimitationContains asserts one claim recorded a limitation containing
// want; it returns the claim for further assertions.
func claimLimitationContains(t *testing.T, c *domain.AnalysisCase, id domain.ConditionID, want string) domain.Claim {
	t.Helper()
	cl := findClaimT(t, c.Claims, id)
	for _, l := range cl.Limitations {
		if strings.Contains(l, want) {
			return cl
		}
	}
	t.Fatalf("claim %s limitations=%v do not mention %q", id, cl.Limitations, want)
	return cl
}

// assertCompleteSourceScan requires one recorded source measurement that
// completed over a complete, non-opaque census, covers the subject and
// carries the product-used entry symbols — the measurement an independent
// reachability negative rests on.
func assertCompleteSourceScan(t *testing.T, c *domain.AnalysisCase, subject domain.SymbolRef) {
	t.Helper()
	build := domain.EffectiveBuildContext(c.Product)
	for i := range c.EvidenceGraph.Evidence {
		e := &c.EvidenceGraph.Evidence[i]
		scan := e.SourceScan
		if e.Kind != domain.EvidenceSourceScan || scan == nil {
			continue
		}
		if !scan.Completed || !scan.Complete || scan.Opaque || len(scan.EntrySymbols) == 0 {
			continue
		}
		if e.BuildContext == nil || e.BuildContext.Matches(build) != nil {
			continue
		}
		for _, s := range scan.Subjects {
			if s == subject {
				return
			}
		}
	}
	t.Fatalf("no completed, complete, non-opaque source measurement covers %s.%s under the case build",
		subject.Package, subject.Symbol)
}

// TestTargetProvenanceE2ETargetGate is the first gate end to end: the same
// constant-input falsification — a build-dependent source proof — closes the
// case under an operator-declared product build and stays UNKNOWN under the
// analyzer host default. The refused case must not reach a safe verdict and
// must not export a negative VEX statement.
func TestTargetProvenanceE2ETargetGate(t *testing.T) {
	const model = `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	// The vulnerable symbol IS reached (govulncheck call path), and the only
	// call site passes a compile-time constant: C-INPUT is where the
	// build-dependent negative lands.
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"` + provenanceAdvisoryID + `","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	cases := []struct {
		name    string
		options repository.SnapshotOptions
		// admitted is whether the analyzed build is an identified product
		// build; only then may the negative close.
		admitted bool
	}{
		{name: "host default (zero options)", options: repository.SnapshotOptions{}, admitted: false},
		{name: "operator-declared build", options: declaredSnapshotOptions(), admitted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modelPath := writeProvenanceModel(t, model)
			repo := initRepoFrom(t, "constprod")
			wantState := domain.StateFailed
			if tc.admitted {
				wantState = domain.StateCompleted
			}
			run := runProvenanceCaseState(t, engineDeps{
				RepoPath: repo,
				VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
					provenanceAdvisoryID: provenanceVulnerability("example.com/dep",
						domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}),
				}},
				VulnID:          provenanceAdvisoryID,
				Resolver:        stubResolver{},
				ManualRC:        []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
				Model:           modelPath,
				CaseDir:         filepath.Join(t.TempDir(), "cases"),
				Govulncheck:     fakeGovulncheck{out: []byte(gv)},
				SnapshotOptions: tc.options,
				UseSource:       true,
			}, wantState)
			c := run.c

			// The recorded target never fabricates provenance: the zero
			// options case is a host default with no scope.
			if c.Product.Target == nil {
				t.Fatal("product snapshot carries no target record")
			}
			if tc.admitted {
				if c.Product.Target.Source != domain.ProductTargetSourceOperatorDeclared ||
					c.Product.Target.Scope != domain.ProductTargetScopeOperator {
					t.Fatalf("target=%+v, want operator-declared/operator", c.Product.Target)
				}
			} else {
				if c.Product.Target.Source != domain.ProductTargetSourceHostDefault ||
					c.Product.Target.Scoped() {
					t.Fatalf("target=%+v, want an unscoped host default", c.Product.Target)
				}
				if err := domain.ValidateNegativeTarget(c.Product); err == nil {
					t.Fatal("host default passed negative-target validation")
				}
			}

			// The positive half is independent: reachability stays TRUE in
			// both runs.
			if reach := findClaimT(t, c.Claims, "C-REACH"); reach.Result != domain.ClaimTrue {
				t.Fatalf("C-REACH=%s, want TRUE (%s)", reach.Result, reach.Explanation)
			}

			input := findClaimT(t, c.Claims, "C-INPUT")
			if tc.admitted {
				if input.Result != domain.ClaimFalse || input.Falsifier != domain.FalsifierConstantOrGeneratedInput {
					t.Fatalf("C-INPUT=%s/%s, want FALSE/%s", input.Result, input.Falsifier, domain.FalsifierConstantOrGeneratedInput)
				}
				if input.NegativeVerification == nil || input.NegativeVerification.Status != domain.NegativeVerified {
					t.Fatalf("negative verification=%+v, want VERIFIED", input.NegativeVerification)
				}
				if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
					t.Fatalf("verdict=%s (%s), want NO_EXPLOIT_PATH_FOUND", c.Verdict.Verdict, c.Verdict.Reason)
				}
				if openVEX, cdx := run.vexStatuses(t); openVEX != "not_affected" || cdx != "not_affected" {
					t.Fatalf("exports openvex=%q cyclonedx=%q, want not_affected/not_affected", openVEX, cdx)
				}
				return
			}

			// Refused: the claim is UNKNOWN — not FALSE plus a caveat — and
			// the refusal is a typed proof blocker, so no verdict is earned.
			if input.Result != domain.ClaimUnknown {
				t.Fatalf("C-INPUT=%s, want UNKNOWN under a host default", input.Result)
			}
			claimLimitationContains(t, c, "C-INPUT", "FALSE refused:")
			if c.Verdict != nil {
				t.Fatalf("verdict=%+v, want none under a host default", c.Verdict)
			}
			if !hasAnalysisGap(c, domain.GapInputTraceIncomplete) {
				t.Fatalf("refusal lacks its typed cause: %+v", c.AnalysisGaps)
			}
			if openVEX, cdx := run.vexStatuses(t); openVEX != "under_investigation" || cdx != "in_triage" {
				t.Fatalf("exports openvex=%q cyclonedx=%q, want under_investigation/in_triage", openVEX, cdx)
			}
			// The persisted report must agree with the exports. (The report
			// projection is owned by Task 8; it carries the nil verdict and
			// the operator-declared target, not the in-memory gap list.)
			persisted := decodePersistedCase(t, filepath.Join(run.artifactDir(t), "report.json"))
			if persisted.Verdict != nil {
				t.Fatalf("report.json verdict=%+v, want none", persisted.Verdict)
			}
		})
	}
}

// TestTargetProvenanceE2EGovulncheckOutcomes crosses the four recorded run
// outcomes with the two usage shapes that reach a reachability claim:
//
//   - a direct call (extprod calls vuln.Parse) stays TRUE under every
//     outcome — no outcome may suppress an independent positive;
//   - a product that uses the module but never invokes the declared sink
//     (unreachprod) may only be falsified when the run actually completed.
func TestTargetProvenanceE2EGovulncheckOutcomes(t *testing.T) {
	const directCallModel = `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}}
	]}`
	const unusedSinkModel = `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/unreachdep/vulnlib","symbol":"OrphanA"}}
	]}`

	// A completed run that measured the advisory and stayed silent. The OSV
	// document identifies the advisory and declares the sink symbols; the
	// absence of findings is the measurement.
	silent := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"osv":{"id":"` + provenanceAdvisoryID + `","affected":[{"package":{"name":"%s","ecosystem":"Go"},
 "ecosystem_specific":{"imports":[{"path":"%s","symbols":["%s"]}]}}]}}`
	withSink := func(module, pkg, symbol string) string {
		return fmt.Sprintf(silent, module, pkg, symbol)
	}

	// A findings stream: one call path into the sink.
	finding := func(module, pkg, symbol string) string {
		return `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"` + provenanceAdvisoryID + `","fixed_version":"v1.2.0","trace":[
 {"module":"` + module + `","package":"` + module + `","function":"main","position":{"filename":"main.go","line":8}},
 {"module":"` + pkg + `","package":"` + pkg + `","function":"` + symbol + `","position":{"filename":"vuln.go","line":4}}
]}}`
	}

	type want struct {
		result    domain.ClaimResult
		falsifier string
		// verified requires a VERIFIED negative verification on the claim.
		verified bool
		verdict  domain.Verdict
	}
	cases := []struct {
		name    string
		fixture string
		extra   []string
		module  string
		subject domain.SymbolRef
		model   string
		run     func() (fakeGovulncheck, bool) // runner + runner-configured
		want    want
	}{
		{
			name:    "completed with results and a call path keeps the direct-call positive",
			fixture: "extprod",
			module:  "example.com/dep",
			subject: domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"},
			model:   directCallModel,
			run: func() (fakeGovulncheck, bool) {
				return fakeGovulncheck{out: []byte(finding("example.com/extprod", "example.com/dep/vuln", "Parse"))}, true
			},
			// extprod forwards os.Args into the sink, so with C-REACH TRUE
			// only C-REACH is mandatory here: the verdict is EXPLOITABLE.
			want: want{result: domain.ClaimTrue, verdict: domain.VerdictExploitable},
		},
		{
			name:    "completed with results that only name the module keeps the positive",
			fixture: "extprod",
			module:  "example.com/dep",
			subject: domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"},
			model:   directCallModel,
			run: func() (fakeGovulncheck, bool) {
				// A module-level finding is not symbol reachability; the
				// direct call still proves the positive.
				return fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"` + provenanceAdvisoryID + `","trace":[{"module":"example.com/dep","position":{"filename":"go.mod","line":1}}]}}`)}, true
			},
			want: want{result: domain.ClaimTrue, verdict: domain.VerdictExploitable},
		},
		{
			name:    "failed run is positive-only and never fabricates a silence negative",
			fixture: "unreachprod",
			extra:   []string{"unreachdep"},
			module:  "example.com/unreachdep",
			subject: domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
			model:   unusedSinkModel,
			run: func() (fakeGovulncheck, bool) {
				return fakeGovulncheck{err: errGovulncheckMissing}, true
			},
			want: want{result: domain.ClaimUnknown, verdict: domain.VerdictInconclusive},
		},
		{
			name:    "not-run measurement is positive-only",
			fixture: "unreachprod",
			extra:   []string{"unreachdep"},
			module:  "example.com/unreachdep",
			subject: domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
			model:   unusedSinkModel,
			run:     func() (fakeGovulncheck, bool) { return fakeGovulncheck{}, false },
			want:    want{result: domain.ClaimUnknown, verdict: domain.VerdictInconclusive},
		},
		{
			name:    "completed-empty with full coverage may ground a verified silence negative",
			fixture: "unreachprod",
			extra:   []string{"unreachdep"},
			module:  "example.com/unreachdep",
			subject: domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
			model:   unusedSinkModel,
			run: func() (fakeGovulncheck, bool) {
				return fakeGovulncheck{out: []byte(withSink("example.com/unreachdep", "example.com/unreachdep/vulnlib", "OrphanA"))}, true
			},
			want: want{
				result:    domain.ClaimFalse,
				falsifier: domain.FalsifierGovulncheckSilence,
				verified:  true,
				verdict:   domain.VerdictNoExploitPathFound,
			},
		},
		{
			name:    "completed-empty over a narrowed scope cannot ground silence",
			fixture: "unreachprod",
			extra:   []string{"unreachdep"},
			module:  "example.com/unreachdep",
			subject: domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
			model:   unusedSinkModel,
			run: func() (fakeGovulncheck, bool) {
				return fakeGovulncheck{
					out:     []byte(withSink("example.com/unreachdep", "example.com/unreachdep/vulnlib", "OrphanA")),
					pattern: "./cmd/...",
				}, true
			},
			// The negative survives through the *independent* complete source
			// measurement, and the claim says exactly that — never silence.
			want: want{
				result:    domain.ClaimFalse,
				falsifier: domain.FalsifierUnreachedExportedSubject,
				verified:  true,
				verdict:   domain.VerdictNoExploitPathFound,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modelPath := writeProvenanceModel(t, tc.model)
			runner, configured := tc.run()
			deps := engineDeps{
				RepoPath: initRepoFrom(t, tc.fixture, tc.extra...),
				VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
					provenanceAdvisoryID: provenanceVulnerability(tc.module, tc.subject),
				}},
				VulnID:          provenanceAdvisoryID,
				Resolver:        stubResolver{},
				ManualRC:        []domain.RootCause{{Package: tc.subject.Package, Symbol: tc.subject.Symbol}},
				Model:           modelPath,
				CaseDir:         filepath.Join(t.TempDir(), "cases"),
				SnapshotOptions: declaredSnapshotOptions(),
				UseSource:       true,
			}
			if configured {
				deps.Govulncheck = runner
			}
			wantState := domain.StateCompleted
			if tc.want.verdict == domain.VerdictInconclusive {
				// A failed/not-run measurement leaves the condition UNKNOWN:
				// that is an analysis failure, not an environmental answer.
				wantState = domain.StateFailed
			}
			run := runProvenanceCaseState(t, deps, wantState)
			c := run.c

			measurement := runOutcome(t, c)
			runRecord := measurement.Govulncheck
			switch {
			case !configured:
				if runRecord.Outcome != domain.GovulncheckNotRun {
					t.Fatalf("outcome=%s, want not_run", runRecord.Outcome)
				}
			case runner.err != nil:
				if runRecord.Outcome != domain.GovulncheckFailed || runRecord.Error == "" {
					t.Fatalf("outcome=%s error=%q, want a failed run with its error", runRecord.Outcome, runRecord.Error)
				}
			default:
				if runRecord.Outcome == domain.GovulncheckFailed || runRecord.Outcome == domain.GovulncheckNotRun {
					t.Fatalf("outcome=%s, want a completed run", runRecord.Outcome)
				}
			}

			claim := findClaimT(t, c.Claims, "C-REACH")
			if claim.Result != tc.want.result {
				t.Fatalf("C-REACH=%s (%s), want %s", claim.Result, claim.Explanation, tc.want.result)
			}
			if claim.Falsifier != tc.want.falsifier {
				t.Fatalf("C-REACH falsifier=%q, want %q (%s)", claim.Falsifier, tc.want.falsifier, claim.Explanation)
			}
			if tc.want.verified {
				if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
					t.Fatalf("negative verification=%+v, want VERIFIED", claim.NegativeVerification)
				}
				for _, id := range claim.EvidenceIDs {
					if c.EvidenceGraph.EvidenceByID(id) == nil {
						t.Fatalf("claim cites missing evidence %s", id)
					}
				}
				if tc.want.falsifier == domain.FalsifierGovulncheckSilence {
					// Silence must cite the run it measured.
					cited := false
					for _, id := range claim.EvidenceIDs {
						if id == measurement.ID {
							cited = true
						}
					}
					if !cited {
						t.Fatalf("silence claim cites %v, not its measurement %s", claim.EvidenceIDs, measurement.ID)
					}
				} else {
					// The independent source proof must rest on a recorded,
					// complete, context-matching measurement — not on the
					// absence of a govulncheck finding.
					assertCompleteSourceScan(t, c, tc.subject)
				}
			}
			if c.Verdict == nil {
				if wantState != domain.StateFailed {
					t.Fatalf("completed case carries no verdict")
				}
				if !hasAnalysisGap(c, domain.GapMeasurementNotCompleted) {
					t.Fatalf("failed run lacks its measurement cause: %+v", c.AnalysisGaps)
				}
			} else if c.Verdict.Verdict != tc.want.verdict {
				t.Fatalf("verdict=%s (%s), want %s", c.Verdict.Verdict, c.Verdict.Reason, tc.want.verdict)
			}
			if runRecord.Outcome == domain.GovulncheckFailed || runRecord.Outcome == domain.GovulncheckNotRun {
				assertNoSilenceFalsifier(t, c)
			}
		})
	}
}

// errGovulncheckMissing is a tool-failure sentinel, not evidence.
var errGovulncheckMissing = fmt.Errorf("govulncheck: binary missing")

// TestTargetProvenanceE2EModuleChainSurvivesFailure: a recorded
// module-internal chain from a product-used API is independent of
// govulncheck. The run failed, so the case may not become safe — but the
// chain still proves reachability and the claim must say so.
func TestTargetProvenanceE2EModuleChainSurvivesFailure(t *testing.T) {
	const model = `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/calleemutdep","symbol":"ReadOne"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/calleemutdep","symbol":"ReadOne"},"arg_index":0}
	]}`
	subject := domain.SymbolRef{Package: "example.com/calleemutdep", Symbol: "ReadOne"}
	run := runProvenanceCase(t, engineDeps{
		// The product drives Entry, which invokes ReadOne inside the module;
		// no product code names ReadOne.
		RepoPath: initRepoFrom(t, "calleemutprod", "calleemutdep"),
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			provenanceAdvisoryID: provenanceVulnerability("example.com/calleemutdep", subject),
		}},
		VulnID:          provenanceAdvisoryID,
		Resolver:        stubResolver{},
		ManualRC:        []domain.RootCause{{Package: subject.Package, Symbol: subject.Symbol}},
		Model:           writeProvenanceModel(t, model),
		CaseDir:         filepath.Join(t.TempDir(), "cases"),
		Govulncheck:     fakeGovulncheck{err: errGovulncheckMissing},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})
	c := run.c

	if rec := runOutcome(t, c).Govulncheck; rec.Outcome != domain.GovulncheckFailed {
		t.Fatalf("outcome=%s, want the failed run under test", rec.Outcome)
	}
	reach := findClaimT(t, c.Claims, "C-REACH")
	if reach.Result != domain.ClaimTrue {
		t.Fatalf("C-REACH=%s (%s), want TRUE from the module-internal chain", reach.Result, reach.Explanation)
	}
	if reach.Falsifier != "" {
		t.Fatalf("C-REACH TRUE carries falsifier %q", reach.Falsifier)
	}
	if len(reach.EvidenceIDs) == 0 {
		t.Fatal("module-chain TRUE cites no evidence")
	}
	if !strings.Contains(reach.Explanation, "ReadOne") {
		t.Fatalf("explanation does not name the proven subject: %s", reach.Explanation)
	}
	// The product feeds the module API a freshly dialled network stream, so
	// the independent input evidence also resolves: the failure of the run is
	// not a case-wide veto and the verdict is EXPLOITABLE.
	if input := findClaimT(t, c.Claims, "C-INPUT"); input.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s (%s), want TRUE from the network-derived input", input.Result, input.Explanation)
	}
	if c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%s (%s), want EXPLOITABLE", c.Verdict.Verdict, c.Verdict.Reason)
	}
	assertNoSilenceFalsifier(t, c)
	if openVEX, _ := run.vexStatuses(t); openVEX != "affected" {
		t.Fatalf("openvex status=%q, want affected", openVEX)
	}
}

// inventoryResolver keeps the deterministic affected chain TRUE (like
// stubResolver) and records one typed package-list measurement, so a case can
// cross the inventory axis without a second `go list` subprocess. The recorded
// content is exactly what the resolver would have decoded.
type inventoryResolver struct {
	content   string
	completed bool
	complete  bool
	// foreignContext records the measurement against a different build.
	foreignContext bool
}

func (r inventoryResolver) Resolve(ctx context.Context, vuln domain.Vulnerability, product domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	res, ev, err := stubResolver{}.Resolve(ctx, vuln, product)
	if err != nil {
		return res, ev, err
	}
	build := domain.EffectiveBuildContext(product)
	if r.foreignContext {
		build.Commit = "a-different-build"
	}
	return res, append(ev, domain.Evidence{
		ID:           "EV-AFFECTED-PACKAGES",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Source:       "go list -deps -test -json ./...",
		Tool:         "go",
		Command:      "go list -deps -test -json ./...",
		Content:      r.content,
		BuildContext: &build,
		PackageList: &domain.PackageListRun{
			Completed: r.completed,
			Complete:  r.complete,
			WithTests: true,
			Pattern:   "./...",
		},
	}), nil
}

// TestTargetProvenanceE2EIndependentSourceProof crosses the inventory and
// target axes on the locus negative: a linked locus package with a completed,
// complete, non-opaque source measurement may be falsified even when
// govulncheck failed, and every weaker measurement — partial inventory,
// undecodable inventory, foreign build context, host default — leaves the
// locus UNKNOWN.
func TestTargetProvenanceE2EIndependentSourceProof(t *testing.T) {
	const model = `{"impact":"t","mandatory_conditions":[
		{"id":"C-LOCUS","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "params":{"check":"locus"},
		 "subjects":[{"package":"example.com/unreachdep/vulnlib","symbol":"OrphanA"}]}
	]}`
	const completeInventory = `{"ImportPath":"example.com/unreachprod"}
{"ImportPath":"example.com/unreachdep/vulnlib","Imports":[]}
`
	buildProduct := func(t *testing.T, resolver inventoryResolver, options repository.SnapshotOptions, wantState domain.WorkflowState) provenanceCase {
		t.Helper()
		return runProvenanceCaseState(t, engineDeps{
			// The product drives Benign only: OrphanA is linked but has no
			// product or dep-internal caller, so the source proof closes.
			RepoPath: initRepoFrom(t, "unreachprod", "unreachdep"),
			VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
				provenanceAdvisoryID: provenanceVulnerability("example.com/unreachdep",
					domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}),
			}},
			VulnID:          provenanceAdvisoryID,
			Resolver:        resolver,
			ManualRC:        []domain.RootCause{{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}},
			Model:           writeProvenanceModel(t, model),
			CaseDir:         filepath.Join(t.TempDir(), "cases"),
			Govulncheck:     fakeGovulncheck{err: errGovulncheckMissing},
			SnapshotOptions: options,
			UseSource:       true,
		}, wantState)
	}

	cases := []struct {
		name     string
		resolver inventoryResolver
		options  repository.SnapshotOptions
		// falsified is whether the admitted measurement may prove the locus
		// function unreached.
		falsified bool
	}{
		{
			name:      "admitted: complete inventory, declared build, failed govulncheck",
			resolver:  inventoryResolver{content: completeInventory, completed: true, complete: true},
			options:   declaredSnapshotOptions(),
			falsified: true,
		},
		{
			name:     "host-default build refuses the locus negative",
			resolver: inventoryResolver{content: completeInventory, completed: true, complete: true},
			options:  repository.SnapshotOptions{},
		},
		{
			name:     "partial inventory refuses the linked-package premise",
			resolver: inventoryResolver{content: `{"ImportPath":"example.com/unreachprod"}`, completed: true, complete: false},
			options:  declaredSnapshotOptions(),
		},
		{
			name: "undecodable inventory content refuses even a complete record",
			resolver: inventoryResolver{
				content:   `{"ImportPath":"example.com/unreachdep/vulnlib"`,
				completed: true,
				complete:  true,
			},
			options: declaredSnapshotOptions(),
		},
		{
			name: "inventory measured on a different build is non-admitting",
			resolver: inventoryResolver{
				content:        completeInventory,
				completed:      true,
				complete:       true,
				foreignContext: true,
			},
			options: declaredSnapshotOptions(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantState := domain.StateFailed
			if tc.falsified {
				wantState = domain.StateCompleted
			}
			run := buildProduct(t, tc.resolver, tc.options, wantState)
			c := run.c
			if rec := runOutcome(t, c).Govulncheck; rec.Outcome != domain.GovulncheckFailed {
				t.Fatalf("outcome=%s, want the failed run under test", rec.Outcome)
			}
			claim := findClaimT(t, c.Claims, "C-LOCUS")

			if !tc.falsified {
				if claim.Result != domain.ClaimUnknown {
					t.Fatalf("C-LOCUS=%s falsifier=%q, want UNKNOWN (explanation %q, limitations %v)",
						claim.Result, claim.Falsifier, claim.Explanation, claim.Limitations)
				}
				// The refusal is a typed proof blocker: no safe verdict and no
				// environmental abstention.
				if c.Verdict != nil {
					t.Fatalf("verdict=%+v (%s), want none for a refused measurement",
						c.Verdict, c.Verdict.Reason)
				}
				if !hasAnalysisGap(c, domain.GapReachabilityProofIncomplete) {
					t.Fatalf("refusal lacks its typed cause: %+v", c.AnalysisGaps)
				}
				if openVEX, cdx := run.vexStatuses(t); openVEX != "under_investigation" || cdx != "in_triage" {
					t.Fatalf("exports openvex=%q cyclonedx=%q, want under_investigation/in_triage", openVEX, cdx)
				}
				return
			}

			// The independent source proof is not vetoed by the failed
			// govulncheck run.
			if claim.Result != domain.ClaimFalse || claim.Falsifier != domain.FalsifierLocusFunctionUnreached {
				t.Fatalf("C-LOCUS=%s/%s, want FALSE/%s (explanation %q, limitations %v)", claim.Result, claim.Falsifier,
					domain.FalsifierLocusFunctionUnreached, claim.Explanation, claim.Limitations)
			}
			if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
				t.Fatalf("negative verification=%+v, want VERIFIED", claim.NegativeVerification)
			}
			if claim.NegativeVerification.BuildContext == nil {
				t.Fatal("verified build-dependent negative records no build context")
			}
			if err := claim.NegativeVerification.BuildContext.Matches(domain.EffectiveBuildContext(c.Product)); err != nil {
				t.Fatalf("verified negative build context does not match the case build: %v", err)
			}
			if len(claim.EvidenceIDs) == 0 {
				t.Fatal("verified locus negative cites no measurement")
			}
			if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
				t.Fatalf("verdict=%s (%s), want NO_EXPLOIT_PATH_FOUND", c.Verdict.Verdict, c.Verdict.Reason)
			}
			// A build-dependent negative carries the analyzed build's scope
			// into both exports.
			if openVEX, cdx := run.vexStatuses(t); openVEX != "not_affected" || cdx != "not_affected" {
				t.Fatalf("exports openvex=%q cyclonedx=%q, want not_affected/not_affected", openVEX, cdx)
			}
			openvex := mustRead(t, filepath.Join(run.artifactDir(t), "openvex.json"))
			if !strings.Contains(string(openvex), "operator-declared") {
				t.Fatalf("build-dependent negative does not name its target provenance: %s", openvex)
			}
		})
	}
}

// TestTargetProvenanceE2EPersistedReplay replays the persisted claim/verdict
// of an admitted case: the same build keeps the negative, while a host-default
// product or a verification measured on another build is refused and the case
// falls back to INCONCLUSIVE — including in the exported VEX document.
func TestTargetProvenanceE2EPersistedReplay(t *testing.T) {
	const model = `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"` + provenanceAdvisoryID + `","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	run := runProvenanceCase(t, engineDeps{
		RepoPath: initRepoFrom(t, "constprod"),
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			provenanceAdvisoryID: provenanceVulnerability("example.com/dep",
				domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}),
		}},
		VulnID:          provenanceAdvisoryID,
		Resolver:        stubResolver{},
		ManualRC:        []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:           writeProvenanceModel(t, model),
		CaseDir:         filepath.Join(t.TempDir(), "cases"),
		Govulncheck:     fakeGovulncheck{out: []byte(gv)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})
	if run.c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("baseline verdict=%s, want NO_EXPLOIT_PATH_FOUND", run.c.Verdict.Verdict)
	}

	// Replay from the persisted artifact, so assertions run against what a
	// consumer of the case document actually reads.
	persistedPath := filepath.Join(run.artifactDir(t), "report.json")
	loadPersisted := func(t *testing.T) *domain.AnalysisCase {
		t.Helper()
		return decodePersistedCase(t, persistedPath)
	}

	replay := func(t *testing.T, mutate func(*domain.AnalysisCase)) *domain.AnalysisCase {
		t.Helper()
		c := loadPersisted(t)
		mutate(c)
		c.Verdict = nil
		if _, err := (states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict.Run: %v", err)
		}
		return c
	}

	t.Run("same build keeps the admitted negative", func(t *testing.T) {
		c := replay(t, func(*domain.AnalysisCase) {})
		if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("verdict=%s (%s), want NO_EXPLOIT_PATH_FOUND", c.Verdict.Verdict, c.Verdict.Reason)
		}
		raw, err := report.OpenVEX(c)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"status": "not_affected"`) {
			t.Fatalf("admitted replay does not export not_affected: %s", raw)
		}
	})

	t.Run("host default refuses the persisted negative", func(t *testing.T) {
		c := replay(t, func(c *domain.AnalysisCase) {
			c.Product.Target = &domain.ProductTarget{
				GOOS: c.Product.GOOS, GOARCH: c.Product.GOARCH,
				Source: domain.ProductTargetSourceHostDefault,
			}
		})
		requireAssessmentFailed(t, c, domain.GapNegativeVerificationIncomplete)
		refused := false
		for _, g := range c.AnalysisGaps {
			if strings.Contains(g.Message, "negative verification for C-INPUT refused") {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("analysis gaps do not record the refusal: %+v", c.AnalysisGaps)
		}
		raw, err := report.OpenVEX(c)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"status": "not_affected"`) {
			t.Fatalf("refused replay exported a negative VEX statement: %s", raw)
		}
	})

	t.Run("verification measured on another build is refused", func(t *testing.T) {
		c := replay(t, func(c *domain.AnalysisCase) {
			for i := range c.Claims {
				nv := c.Claims[i].NegativeVerification
				if nv == nil || nv.BuildContext == nil {
					continue
				}
				nv.BuildContext.GOARCH = "mips64"
			}
		})
		requireAssessmentFailed(t, c, domain.GapNegativeVerificationIncomplete)
		raw, err := report.CycloneDX(c)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"state": "not_affected"`) {
			t.Fatalf("mismatched-build replay exported not_affected: %s", raw)
		}
	})
}
