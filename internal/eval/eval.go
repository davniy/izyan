// Package eval runs the analyzer over a corpus of cases and reports the
// spec's quality metrics — most importantly the false-safe count: cases
// where the analyzer returned a safe verdict (NOT_AFFECTED /
// NO_EXPLOIT_PATH_FOUND) while the expectation says it should not.
// That is the stop criterion of the project: a regression that makes an
// exploitable input look safe is the one failure the harness must catch.
package eval

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// Case is one corpus entry: an advisory analyzed against a repository.
type Case struct {
	ID       string `json:"id,omitempty"`
	Vuln     string `json:"vuln"`
	VulnFile string `json:"vuln_file,omitempty"`
	Repo     string `json:"repo,omitempty"`
	// Ref pins a repo-type case to a git ref (tag/branch/commit): the
	// harness materializes the tree via `git archive` into .gen so the
	// source repo's checkout is never touched. Used when a product
	// version maps to a component release ref rather than a checkout.
	Ref string `json:"ref,omitempty"`
	// Product names a directory of committed product sources (e.g.
	// "products/yaml-http" under eval/); combined with Module+Deps the
	// harness materializes a buildable module under <corpus>/.gen/<id> —
	// vulnerable manifests live only inside .gen, never in the tree.
	// Product and Repo are mutually exclusive.
	Product string            `json:"product,omitempty"`
	Module  string            `json:"module,omitempty"`
	Deps    map[string]string `json:"deps,omitempty"`
	// RootCauses supplies manual root causes, bypassing resolution. Entries
	// are either "pkg/path.Symbol" strings or objects
	// {"package":"pkg/path","symbol":"Type.Method","role":"SINK"} — the
	// object form is needed for method subjects, where the string form
	// cannot split package path from symbol name.
	RootCauses   []RootCauseRef `json:"root_causes,omitempty"`
	ExploitModel string         `json:"exploit_model,omitempty"`
	// NonLocus supplies expert necessity decisions for the defect-locus
	// contract: declared symbols asserted not to be defect sites, with the
	// recorded justification. Entries are explicit expert input (stamped
	// with expert provenance at load). The falsifier's coverage shrinks only
	// by these recorded decisions — never by an unproven textual scan or a
	// machine proposal.
	NonLocus []domain.LocusDecision `json:"non_locus,omitempty"`
	// GoVersion requests the target toolchain ("1.21.13" or "go1.21.13") —
	// the version the release was built with. Resolved via SDK/GOTOOLCHAIN;
	// unavailability records a limitation, never a silent wrong-version run.
	GoVersion string `json:"go_version,omitempty"`
	// GOOS/GOARCH/BuildTags override the snapshot target platform for this
	// case — needed for platform-specific deps (e.g. linux-only unix calls).
	GOOS      string   `json:"goos,omitempty"`
	GOARCH    string   `json:"goarch,omitempty"`
	BuildTags []string `json:"build_tags,omitempty"`
	// TrustedPeer declares the case's deployment runs strictly with
	// trusted peers (--trusted-peer equivalent, per-case). It is an
	// operator assertion — recorded as declared-trust ground basis, never
	// code-level proof.
	TrustedPeer bool `json:"trusted_peer,omitempty"`
	// Perimeter sets the deployment perimeter context for this case
	// (auto|cluster|public — same values as --perimeter).
	Perimeter string `json:"perimeter,omitempty"`
	// DeployManifests points at deployment manifests for this case —
	// comma-separated directories or .tgz/.tar.gz/.zip archives, same
	// contract as --deploy-manifests. Manifests ground perimeter and
	// exposure facts for deployment-dependent falsifiers.
	DeployManifests string `json:"deploy_manifests,omitempty"`
	// Expect lists acceptable verdicts; empty means informational only
	// (the case still counts toward distribution metrics).
	Expect []string `json:"expect,omitempty"`
	// Claims asserts per-condition claim results, e.g.
	// {"C-EXPOSED":"FALSE"}. A mismatch fails the case.
	Claims map[string]string `json:"expect_claims,omitempty"`
}

// Corpus is the case list plus an optional shared repository path.
type Corpus struct {
	Repo  string `json:"repo,omitempty"`
	Cases []Case `json:"cases"`
}

// RootCauseRef is a manual root-cause entry: "pkg/path.Symbol" sugar or the
// explicit domain.RootCause object form.
type RootCauseRef struct {
	domain.RootCause
}

// UnmarshalJSON accepts either a "pkg/path.Symbol" string (last dot splits
// package path from symbol) or a full RootCause object.
func (r *RootCauseRef) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		i := strings.LastIndex(s, ".")
		if i <= 0 {
			return fmt.Errorf("root_causes entry %q: want pkg/path.Symbol", s)
		}
		r.RootCause = domain.RootCause{
			Package:   s[:i],
			Symbol:    s[i+1:],
			Role:      domain.RootCauseSink,
			Mechanism: "provided manually via eval corpus",
			Origin:    domain.RootCauseOriginManual,
		}
		return nil
	}
	return json.Unmarshal(b, &r.RootCause)
}

// Label returns the display name of a case.
func (c Case) Label() string {
	if c.ID != "" {
		return c.ID
	}
	return c.Vuln
}

// InputIdentity fingerprints the case's recorded inputs — the advisory, the
// tree it is analyzed against, the product material and the resolved module
// graph. Two runs of the same corpus produce the same identity; a case whose
// label survived while its input changed does not, so a comparison can refuse
// to pair them instead of pretending it measured one case twice.
func (c Case) InputIdentity() string {
	var b strings.Builder
	write := func(field, value string) {
		fmt.Fprintf(&b, "%s=%s\x00", field, value)
	}
	write("vuln", c.Vuln)
	write("vuln_file", c.VulnFile)
	write("repo", c.Repo)
	write("ref", c.Ref)
	write("product", c.Product)
	write("module", c.Module)
	write("exploit_model", c.ExploitModel)
	write("go_version", c.GoVersion)
	write("goos", c.GOOS)
	write("goarch", c.GOARCH)
	write("build_tags", strings.Join(c.BuildTags, ","))
	deps := make([]string, 0, len(c.Deps))
	for module, version := range c.Deps {
		deps = append(deps, module+"@"+version)
	}
	sort.Strings(deps)
	write("deps", strings.Join(deps, ","))
	return b.String()
}

// ProofOriginRef is the calibration-visible witness behind a positive: which
// independent assessment earned it, from which exact record bytes, for which
// entry/mechanism and under which attribution. It never carries ground truth.
type ProofOriginRef struct {
	AssessmentID   string `json:"assessment_id"`
	RecordID       string `json:"record_id"`
	DocumentDigest string `json:"record_digest,omitempty"`
	EntryRefs      []int  `json:"entry_refs,omitempty"`
	MechanismID    string `json:"mechanism_id,omitempty"`
	AttributionID  string `json:"attribution_id,omitempty"`
	Profile        string `json:"profile,omitempty"`
}

// Projection is the requested-finding projection of one case: the terminal
// classification every consumer shares. Available is false when the case
// produced no publication projection at all — an execution failure, never a
// verdict, a safe answer or an analysis failure.
type Projection struct {
	Available            bool
	RequestedID          string
	RequestedKind        string
	Coverage             string
	Outcome              domain.AssessmentOutcome
	Verdict              domain.Verdict
	Reason               string
	ExploitabilityScope  string
	Profile              string
	Build                string
	PrimaryRecord        string
	PrimaryDigest        string
	CandidateIDs         []string
	AttributionOutcomes  []string
	ProofOrigins         []ProofOriginRef
	CorpusDigest         string
	FailureCodes         []string
	ExternalDependencies []string
}

// failedToken is the published outcome token of a FAILED assessment. A failure
// has no verdict, so scoring uses this explicit token instead of an empty
// string that could be mistaken for a missing answer.
const failedToken = "FAILED"

// Result is the outcome of one corpus case.
type Result struct {
	Case    Case              `json:"case"`
	Verdict string            `json:"verdict,omitempty"`
	Reason  string            `json:"reason,omitempty"`
	Claims  map[string]string `json:"claims,omitempty"`
	Err     string            `json:"error,omitempty"`
	// AssessmentOutcome is the requested finding's terminal classification:
	// DECIDED, EXTERNAL_DEPENDENCY or FAILED. Empty for a legacy result.
	AssessmentOutcome string `json:"assessment_outcome,omitempty"`
	// FailureCodes are the typed causes behind a FAILED outcome, rendered as
	// OWNER/CODE.
	FailureCodes []string `json:"failure_codes,omitempty"`
	// Requested identity and coverage of the answer, not of the primary record.
	RequestedID   string `json:"requested_id,omitempty"`
	RequestedKind string `json:"requested_kind,omitempty"`
	Coverage      string `json:"coverage,omitempty"`
	// PrimaryRecord/PrimaryDigest pin the request's primary record bytes.
	PrimaryRecord string `json:"primary_record,omitempty"`
	PrimaryDigest string `json:"primary_record_digest,omitempty"`
	// CandidateIDs are the independently assessed discovery candidates.
	CandidateIDs []string `json:"candidate_ids,omitempty"`
	// AttributionOutcomes records every directional CVE attribution attempt
	// as "<attribution-id>=<admission>".
	AttributionOutcomes []string `json:"attribution_outcomes,omitempty"`
	// ProofOrigins name the admitted witnesses of a positive.
	ProofOrigins []ProofOriginRef `json:"proof_origins,omitempty"`
	// Profile/Build are the provenance of the admitted result.
	Profile string `json:"profile,omitempty"`
	Build   string `json:"build,omitempty"`
	// CorpusDigest pins the corpus a declared negative rests on.
	CorpusDigest string `json:"corpus_digest,omitempty"`
	// ExternalDependencies name the decision-changing facts behind an
	// EXTERNAL_DEPENDENCY outcome.
	ExternalDependencies []string `json:"external_dependencies,omitempty"`
	// ExpectOK is nil when the case carries no expectations.
	ExpectOK  *bool `json:"expect_ok,omitempty"`
	ClaimsOK  *bool `json:"claims_ok,omitempty"`
	FalseSafe bool  `json:"false_safe,omitempty"`
	// Baseline records what standalone govulncheck reported about this
	// advisory on the case's repository: reachable / package-level /
	// silent / not-in-db / error. Empty when no baseline ran.
	Baseline string `json:"govulncheck_baseline,omitempty"`
	// ExpertAssisted marks cases whose safe verdict depended on input
	// the machine cannot derive from the advisory: expert non_locus
	// decisions or manually supplied root causes. Auto vs expert
	// cleared counts are reported separately — govulncheck receives
	// no expert input, so only the auto count is a like-for-like
	// comparison.
	ExpertAssisted bool `json:"expert_assisted,omitempty"`
	// Falsifier / GroundBasis identify the grounding claim of a safe
	// verdict — the evidence class that cleared the signal
	// (see clearedKind).
	Falsifier   string `json:"falsifier,omitempty"`
	GroundBasis string `json:"ground_basis,omitempty"`
	// EvidenceIDs of the grounding claim — pointers an independent
	// reviewer can check in the persisted case.
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// Metrics is the aggregate evaluation report — the numbers the spec's
// stop criterion is expressed in.
type Metrics struct {
	Total      int            `json:"total"`
	Errors     int            `json:"errors"`
	ExpectPass int            `json:"expect_pass"`
	ExpectFail int            `json:"expect_fail"`
	NoExpect   int            `json:"informational"`
	Verdicts   map[string]int `json:"verdicts"`
	// FalseSafe — cases reported NOT_AFFECTED or NO_EXPLOIT_PATH_FOUND
	// while their expectation did not allow a safe verdict. The stop
	// criterion: this must stay zero.
	FalseSafe int `json:"false_safe"`
	// FalsePositive — cases that published EXPLOITABLE while their
	// expectation did not allow it. The symmetric stop criterion.
	FalsePositive int `json:"false_positive"`
	// Inconclusive counts published INCONCLUSIVE answers (external
	// dependencies). A FAILED assessment is not an abstention and is never
	// counted here.
	Inconclusive int `json:"inconclusive"`
	// Decided/ExternalDependency/AnalysisFailed are the terminal
	// classifications of the requested finding. A failed analysis is not a
	// completed analysis, and an external dependency is not a definitive
	// answer: readers must never add the last two to Decided.
	Decided             int `json:"decided"`
	ExternalDependency  int `json:"external_dependency"`
	AnalysisFailed      int `json:"analysis_failed"`
	GovulncheckSignals  int `json:"govulncheck_signals,omitempty"`
	SignalCleared       int `json:"signal_cleared,omitempty"`
	ReachableSignals    int `json:"reachable_signals,omitempty"`
	ReachableCleared    int `json:"reachable_cleared,omitempty"`
	PackageLevelSignals int `json:"package_level_signals,omitempty"`
	PackageLevelCleared int `json:"package_level_cleared,omitempty"`
	// SignalClearedAuto/Expert split cleared signals by whether the
	// verdict needed expert input (non_locus/root_causes). Only the
	// auto count compares like-for-like with govulncheck.
	SignalClearedAuto   int `json:"signal_cleared_auto,omitempty"`
	SignalClearedExpert int `json:"signal_cleared_expert,omitempty"`
	// ClearedDeeper/Echo/Affectedness split cleared signals by the
	// evidence class that grounded the safe verdict.
	ClearedDeeper       int `json:"cleared_deeper,omitempty"`
	ClearedEcho         int `json:"cleared_echo,omitempty"`
	ClearedAffectedness int `json:"cleared_affectedness,omitempty"`
	// ClaimsFail counts cases whose per-condition claim assertions did not
	// hold — a finer regression signal than verdicts alone.
	ClaimsFail int `json:"claims_fail"`
}

// Report pairs metrics with per-case results.
type Report struct {
	Metrics Metrics  `json:"metrics"`
	Results []Result `json:"results"`
}

var safeVerdicts = map[domain.Verdict]bool{
	domain.VerdictNotAffected:        true,
	domain.VerdictNoExploitPathFound: true,
}

// ClearedKind classifies the evidence class that cleared a govulncheck
// signal — the honest measure of added value.
const (
	// ClearedKindDeeper: proof outside govulncheck's contract —
	// locus absence/unreachability, constant/generated input,
	// config gating, snapshot facts, trust boundary, loopback scope.
	ClearedKindDeeper = "deeper"
	// ClearedKindEcho: a falsifier reproducing govulncheck's own
	// reachability contract under a different invocation — silence,
	// no module usage, or our own call-graph proof that no declared
	// exported subject is called. Valuable but not new evidence.
	ClearedKindEcho = "echo"
	// ClearedKindAffectedness: NOT_AFFECTED by the deterministic
	// affectedness chain on a signaled case (baseline disagrees with
	// the product's resolved dependency graph).
	ClearedKindAffectedness = "affectedness"
)

// echoFalsifiers reproduce govulncheck's own reachability analysis
// rather than adding a new class of proof.
var echoFalsifiers = map[string]bool{
	domain.FalsifierGovulncheckSilence:       true,
	domain.FalsifierNoModuleUsage:            true,
	domain.FalsifierUnreachedExportedSubject: true,
}

// clearedKind maps a cleared result to its evidence class.
func clearedKind(verdict string, falsifier string) string {
	if verdict == string(domain.VerdictNotAffected) {
		return ClearedKindAffectedness
	}
	if echoFalsifiers[falsifier] {
		return ClearedKindEcho
	}
	return ClearedKindDeeper
}

// Record folds one finished case into the report. The projection is the
// authoritative requested answer: when it is available its outcome, verdict
// and diagnostics override the explicitly passed verdict/reason, so a caller
// cannot accidentally score the primary record instead of the request. A
// legacy caller (no projection) keeps the historical verdict-based accounting.
// falsifier and groundBasis identify the grounding claim of the deciding
// assessment (empty for NOT_AFFECTED and non-safe verdicts); evidenceIDs point
// at the claim's evidence for independent review.
func (r *Report) Record(c Case, verdict domain.Verdict, reason string, claims map[string]string, falsifier, groundBasis string, evidenceIDs []string, runErr error, projection Projection) {
	res := Result{
		Case:           c,
		Claims:         claims,
		ExpertAssisted: len(c.NonLocus) > 0 || len(c.RootCauses) > 0,
		Falsifier:      falsifier,
		GroundBasis:    groundBasis,
		EvidenceIDs:    evidenceIDs,
	}
	if projection.Available {
		res.AssessmentOutcome = string(projection.Outcome)
		res.FailureCodes = projection.FailureCodes
		res.RequestedID = projection.RequestedID
		res.RequestedKind = projection.RequestedKind
		res.Coverage = projection.Coverage
		res.PrimaryRecord = projection.PrimaryRecord
		res.PrimaryDigest = projection.PrimaryDigest
		res.CandidateIDs = projection.CandidateIDs
		res.AttributionOutcomes = projection.AttributionOutcomes
		res.ProofOrigins = projection.ProofOrigins
		res.Profile = projection.Profile
		res.Build = projection.Build
		res.CorpusDigest = projection.CorpusDigest
		res.ExternalDependencies = projection.ExternalDependencies
		// The projection is the one authoritative answer: it decides the
		// published verdict and reason, not the caller's record-level view.
		verdict = projection.Verdict
		reason = projection.Reason
	}
	if runErr != nil {
		res.Err = runErr.Error()
		r.Metrics.Errors++
	} else {
		res.Verdict = string(verdict)
		res.Reason = reason
		switch {
		case projection.Available && projection.Outcome == domain.OutcomeFailed:
			// A failure publishes no verdict, so it is neither a safe answer
			// nor an abstention. It is not a completed analysis either.
			r.Metrics.AnalysisFailed++
		default:
			if r.Metrics.Verdicts == nil {
				r.Metrics.Verdicts = map[string]int{}
			}
			r.Metrics.Verdicts[res.Verdict]++
			if verdict == domain.VerdictInconclusive {
				r.Metrics.Inconclusive++
			}
		}
		if projection.Available {
			switch projection.Outcome {
			case domain.OutcomeDecided:
				r.Metrics.Decided++
			case domain.OutcomeExternal:
				r.Metrics.ExternalDependency++
			}
		}
	}
	if len(c.Expect) > 0 {
		published := res.Verdict
		if projection.Available && projection.Outcome == domain.OutcomeFailed {
			published = failedToken
		}
		ok := false
		for _, want := range c.Expect {
			if published == want {
				ok = true
			}
		}
		res.ExpectOK = &ok
		if ok {
			r.Metrics.ExpectPass++
		} else {
			r.Metrics.ExpectFail++
			res.FalseSafe = safeVerdicts[verdict]
			if res.FalseSafe {
				r.Metrics.FalseSafe++
			}
			if verdict == domain.VerdictExploitable {
				r.Metrics.FalsePositive++
			}
		}
	} else {
		r.Metrics.NoExpect++
	}
	if len(c.Claims) > 0 {
		ok := true
		for id, want := range c.Claims {
			if res.Claims[id] != want {
				ok = false
			}
		}
		res.ClaimsOK = &ok
		if !ok {
			r.Metrics.ClaimsFail++
		}
	}
	r.Metrics.Total++
	r.Results = append(r.Results, res)
}

// RecordBaseline attaches the standalone result to the most recently
// recorded case and counts a verified safe verdict against a finding.
func (r *Report) RecordBaseline(baseline string) {
	if len(r.Results) == 0 {
		return
	}
	res := &r.Results[len(r.Results)-1]
	res.Baseline = baseline
	if baseline != BaselineReachable && baseline != BaselinePackageLevel {
		return
	}
	r.Metrics.GovulncheckSignals++
	if baseline == BaselineReachable {
		r.Metrics.ReachableSignals++
	} else {
		r.Metrics.PackageLevelSignals++
	}
	if !res.FalseSafe && res.Err == "" &&
		(res.Verdict == string(domain.VerdictNotAffected) || res.Verdict == string(domain.VerdictNoExploitPathFound)) {
		r.Metrics.SignalCleared++
		if res.ExpertAssisted {
			r.Metrics.SignalClearedExpert++
		} else {
			r.Metrics.SignalClearedAuto++
		}
		switch clearedKind(res.Verdict, res.Falsifier) {
		case ClearedKindEcho:
			r.Metrics.ClearedEcho++
		case ClearedKindAffectedness:
			r.Metrics.ClearedAffectedness++
		default:
			r.Metrics.ClearedDeeper++
		}
		if baseline == BaselineReachable {
			r.Metrics.ReachableCleared++
		} else {
			r.Metrics.PackageLevelCleared++
		}
	}
}

// Markdown renders the report as a reviewable table.
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Evaluation report\n\n")
	fmt.Fprintf(&b, "cases: %d | errors: %d | expect pass: %d | expect fail: %d | **false-safe: %d** | inconclusive: %d\n\n",
		r.Metrics.Total, r.Metrics.Errors, r.Metrics.ExpectPass, r.Metrics.ExpectFail,
		r.Metrics.FalseSafe, r.Metrics.Inconclusive)
	// The terminal classification is reported as three separate populations:
	// moving tool limitations out of INCONCLUSIVE is not an increase in
	// successful completion.
	fmt.Fprintf(&b, "requested outcomes: decided: %d | external dependency: %d | analysis failed: %d | false-positive: %d\n\n",
		r.Metrics.Decided, r.Metrics.ExternalDependency, r.Metrics.AnalysisFailed, r.Metrics.FalsePositive)
	if r.Metrics.GovulncheckSignals > 0 {
		fmt.Fprintf(&b, "signal cleared: %d/%d\n\n", r.Metrics.SignalCleared, r.Metrics.GovulncheckSignals)
		fmt.Fprintf(&b, "reachable cleared: %d/%d | package-level cleared: %d/%d\n\n",
			r.Metrics.ReachableCleared, r.Metrics.ReachableSignals,
			r.Metrics.PackageLevelCleared, r.Metrics.PackageLevelSignals)
		if r.Metrics.SignalCleared > 0 {
			fmt.Fprintf(&b, "cleared auto (no expert input): %d | cleared expert-assisted: %d\n\n",
				r.Metrics.SignalClearedAuto, r.Metrics.SignalClearedExpert)
			fmt.Fprintf(&b, "cleared by evidence class — deeper: %d | echo (govulncheck-contract): %d | affectedness: %d\n\n",
				r.Metrics.ClearedDeeper, r.Metrics.ClearedEcho, r.Metrics.ClearedAffectedness)
		}
	}
	if r.Metrics.ClaimsFail > 0 {
		fmt.Fprintf(&b, "claim mismatches: %d\n\n", r.Metrics.ClaimsFail)
	}
	if len(r.Metrics.Verdicts) > 0 {
		var vs []string
		for v, n := range r.Metrics.Verdicts {
			vs = append(vs, fmt.Sprintf("%s=%d", v, n))
		}
		sort.Strings(vs)
		fmt.Fprintf(&b, "verdicts: %s\n\n", strings.Join(vs, " "))
	}
	b.WriteString("| case | outcome | verdict | expect | claims | govulncheck | falsifier | note |\n|---|---|---|---|---|---|---|---|\n")
	for _, res := range r.Results {
		v := res.Verdict
		if res.Err != "" {
			v = "ERROR"
		}
		outcome := res.AssessmentOutcome
		if outcome == "" {
			outcome = "-"
		}
		if res.Err != "" {
			outcome = "EXECUTION_ERROR"
		}
		exp := "-"
		if res.ExpectOK != nil {
			if *res.ExpectOK {
				exp = "ok"
			} else {
				exp = "FAIL"
			}
		}
		cl := "-"
		if res.ClaimsOK != nil {
			if *res.ClaimsOK {
				cl = "ok"
			} else {
				cl = "FAIL"
			}
		}
		gv := res.Baseline
		if gv == "" {
			gv = "-"
		}
		note := ""
		switch {
		case res.FalseSafe:
			note = "**FALSE-SAFE**"
		case res.Err != "":
			note = res.Err
		case len(res.FailureCodes) > 0:
			note = strings.Join(res.FailureCodes, " ")
		case len(res.ExternalDependencies) > 0:
			note = "external: " + strings.Join(res.ExternalDependencies, "; ")
		}
		fals := res.Falsifier
		if res.GroundBasis != "" {
			fals += "(" + res.GroundBasis + ")"
		}
		if res.ExpertAssisted {
			fals += "*"
		}
		if fals == "" {
			fals = "-"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			res.Case.Label(), outcome, v, exp, cl, gv, fals, note)
	}
	return b.String()
}
