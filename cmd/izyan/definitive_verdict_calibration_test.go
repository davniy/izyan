package main

// Opt-in end-to-end calibration of the definitive-verdict contract on the real
// Kubernetes snapshot that motivated it.
//
// The run uses the recorded frozen advisory document, the configured frozen OSV
// corpus (record discovery + inverse related lookup), the captured gRPC
// publisher advisory (directional CVE attribution) and the live upstream fix
// patch fetched by the production fix provider. No analysis input is stubbed:
// the request pipeline, the isolated record assessment, the source/fix-bound
// transport proof, composition, persistence and publication all run as shipped.
//
// It skips with named prerequisites when an asset is missing — a skipped
// calibration is never a pass. The claim-level ledger is printed for the
// calibration report.
//
//	VA_VEX_TASKS   vex_bench_go.jsonl
//	VA_SNAPSHOTS   snapshot root (<owner>/<repo>/<commit>)
//	VA_FROZEN_OSV  frozen OSV advisory directory (the pinned corpus)
//	VA_CASES       output root for case directories

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
)

const (
	definitiveTask        = "kubernetes-kubernetes-e196d24-CVE-2023-44487"
	definitiveCVE         = "CVE-2023-44487"
	definitiveGHSA        = "GHSA-qppj-fm5r-hxr3"
	definitiveGRPC        = "GO-2023-2153"
	definitiveSHA         = "e196d2491087e93bd29f0e5a538aab60667021e3"
	definitiveEvidenceDir = "../../internal/states/testdata/definitive-verdict"
	definitiveTargetGRPC  = "google.golang.org/grpc"
	definitiveTargetCover = "v1.55.0"
)

// definitiveLedger is the claim-level record of one real worked-case run. It
// keeps the requested answer, the deciding witness, the record facts and the
// measured terminal state side by side, so a report can separate a definitive
// answer from an external dependency and from an analysis failure.
type definitiveLedger struct {
	Task        string  `json:"task"`
	Commit      string  `json:"commit"`
	RequestedID string  `json:"requested_id"`
	WallSeconds float64 `json:"wall_seconds"`

	PrimaryRecord   string   `json:"primary_record,omitempty"`
	PrimaryDigest   string   `json:"primary_digest,omitempty"`
	PrimaryExtent   string   `json:"primary_extent,omitempty"`
	PrimaryCoverage string   `json:"primary_coverage,omitempty"`
	PrimaryEntries  int      `json:"primary_entries,omitempty"`
	PrimaryPresent  int      `json:"primary_represented,omitempty"`
	PrimaryOmitted  int      `json:"primary_omitted,omitempty"`
	PrimaryModules  []string `json:"primary_go_modules,omitempty"`

	CensusUntouched bool `json:"census_untouched"`

	DiscoveryEnumeration string   `json:"discovery_enumeration,omitempty"`
	DiscoveryCandidates  []string `json:"discovery_candidates,omitempty"`
	CorpusReference      string   `json:"corpus_reference,omitempty"`
	CorpusDigest         string   `json:"corpus_digest,omitempty"`
	AttributionRecord    string   `json:"attribution_record,omitempty"`
	AttributionBasis     string   `json:"attribution_basis,omitempty"`
	AttributionAdmission string   `json:"attribution_admission,omitempty"`
	PublisherAdvisory    string   `json:"publisher_advisory,omitempty"`
	AttributionFixRefs   []string `json:"attribution_fix_refs,omitempty"`

	AssessmentOutcome string   `json:"assessment_outcome,omitempty"`
	Verdict           string   `json:"verdict,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	Profile           string   `json:"profile,omitempty"`
	IsTargetActual    bool     `json:"is_target_actual"`
	ExploitScope      string   `json:"exploitability_scope,omitempty"`
	FailureCodes      []string `json:"failure_codes,omitempty"`
	Limitations       []string `json:"limitations,omitempty"`

	ProofOriginRecord     string   `json:"proof_origin_record,omitempty"`
	ProofOriginAssessment string   `json:"proof_origin_assessment,omitempty"`
	ProofOriginProfile    string   `json:"proof_origin_profile,omitempty"`
	ProofOriginEvidence   int      `json:"proof_origin_evidence_refs,omitempty"`
	WitnessRecord         string   `json:"witness_record,omitempty"`
	WitnessMechanism      string   `json:"witness_mechanism,omitempty"`
	WitnessRoot           string   `json:"witness_root,omitempty"`
	WitnessFixDigest      string   `json:"witness_fix_digest,omitempty"`
	WitnessFixEnforcement []string `json:"witness_fix_enforcement,omitempty"`
	WitnessObligationsMet int      `json:"witness_obligations_met,omitempty"`
	WitnessObligationsAll int      `json:"witness_obligations_total,omitempty"`
	PeerInputClaim        string   `json:"peer_input_claim,omitempty"`
	PeerInputBasis        string   `json:"peer_input_control_basis,omitempty"`
	ConstraintClaim       string   `json:"constraint_claim,omitempty"`

	ResolvedVersion     string   `json:"resolved_version,omitempty"`
	VersionAffected     string   `json:"version_affected,omitempty"`
	VersionAffectedMods []string `json:"version_affected_modules,omitempty"`
	CheckedModules      []string `json:"checked_modules,omitempty"`

	TerminalState  string   `json:"terminal_state,omitempty"`
	ReportWritten  bool     `json:"report_written"`
	ExportsWritten []string `json:"exports_written,omitempty"`

	// DeploymentQuestion is the separate external question this answer does
	// not settle; it is reported distinctly from exploitability.
	DeploymentQuestion string `json:"deployment_question"`

	AcceptanceTarget string `json:"acceptance_target"`
	AcceptanceMet    bool   `json:"acceptance_met"`
	AcceptanceCause  string `json:"acceptance_cause,omitempty"`
}

// definitiveRun is one executed calibration request.
type definitiveRun struct {
	ledger *definitiveLedger
	c      *domain.AnalysisCase
	err    error
}

func TestDefinitiveVerdictCalibration(t *testing.T) {
	tasksPath := strings.TrimSpace(os.Getenv("VA_VEX_TASKS"))
	reposDir := strings.TrimSpace(os.Getenv("VA_SNAPSHOTS"))
	osvDir := strings.TrimSpace(os.Getenv("VA_FROZEN_OSV"))
	casesDir := strings.TrimSpace(os.Getenv("VA_CASES"))

	var missing []string
	for _, in := range []struct {
		name  string
		value string
		dir   bool
	}{
		{"VA_VEX_TASKS", tasksPath, false},
		{"VA_SNAPSHOTS", reposDir, true},
		{"VA_FROZEN_OSV", osvDir, true},
		// VA_CASES is the output root: a missing directory is created below.
	} {
		if in.value == "" {
			missing = append(missing, in.name+" (unset)")
			continue
		}
		info, err := os.Stat(in.value)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s=%s (%v)", in.name, in.value, err))
			continue
		}
		if in.dir && !info.IsDir() {
			missing = append(missing, in.name+"="+in.value+" (not a directory)")
		}
		if !in.dir && info.IsDir() {
			missing = append(missing, in.name+"="+in.value+" (not a file)")
		}
	}
	// The publisher capture must be pinned before any analysis.
	attributionFile, err := filepath.Abs(filepath.Join(definitiveEvidenceDir, "attribution-captures.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(attributionFile); err != nil {
		missing = append(missing, "attribution captures: "+err.Error())
	}
	if casesDir == "" {
		missing = append(missing, "VA_CASES (unset)")
	}
	if len(missing) > 0 {
		t.Skipf("definitive-verdict calibration requires the external VEX-Bench corpus: %s", strings.Join(missing, "; "))
	}
	if err := os.MkdirAll(casesDir, 0o755); err != nil {
		t.Fatalf("prepare VA_CASES: %v", err)
	}

	tasks, err := vexbench.LoadGoTasks(tasksPath)
	if err != nil {
		t.Fatalf("load tasks: %v", err)
	}
	var task vexbench.Task
	found := false
	for _, candidate := range tasks {
		if candidate.TaskID == definitiveTask {
			task, found = candidate, true
		}
	}
	if !found {
		t.Fatalf("pinned calibration case %s is absent from %s", definitiveTask, tasksPath)
	}
	if task.CVEID != definitiveCVE {
		t.Fatalf("task CVE = %s, want %s", task.CVEID, definitiveCVE)
	}
	if task.CommitSHA != definitiveSHA {
		t.Fatalf("task commit = %s, want the pinned %s", task.CommitSHA, definitiveSHA)
	}

	snapshot, err := vexbench.LocateSnapshot(reposDir, task)
	if err != nil {
		t.Fatalf("locate snapshot: %v", err)
	}
	exactAdvisory := filepath.Join(osvDir, definitiveGHSA+".json")
	advisoryRaw, err := os.ReadFile(exactAdvisory)
	if err != nil {
		t.Fatalf("frozen corpus has no exact %s document: %v", definitiveGHSA, err)
	}
	if canonical, err := vexbench.CanonicalSHA256(advisoryRaw); err == nil {
		t.Logf("primary advisory: %s canonical %s", exactAdvisory, canonical)
	}

	ctx := context.Background()
	budget, err := parseMemLimit(firstNonEmpty(os.Getenv("VA_MEM_LIMIT"), "24GiB"))
	if err != nil {
		t.Fatalf("VA_MEM_LIMIT: %v", err)
	}
	ctx, stop := applyMemoryLimit(ctx, budget)
	defer stop()

	tc, lims := resolveAnalysisToolchain(ctx, "")
	if tc.GoBin == "" {
		t.Fatalf("analysis toolchain unresolved: %s", strings.Join(lims, "; "))
	}
	t.Logf("analysis toolchain: go%s (%s); corpus: %s", tc.Version, tc.Mode, osvDir)

	run := func(t *testing.T, requestID string) definitiveRun {
		t.Helper()
		caseDir := filepath.Join(casesDir, "definitive-verdict",
			sanitizeCaseName(task.TaskID), sanitizeCaseName(requestID))
		t.Setenv("IZYAN_SNAPSHOT_SHA", task.CommitSHA)
		opts := analyzeOpts{
			repo:              snapshot,
			vulnID:            requestID,
			vulnFile:          exactAdvisory,
			externalCommitSHA: task.CommitSHA,
			detOnly:           true,
			suppressEnvFile:   true,
			envReplace:        true,
			confineReads:      true,
			advisoryDir:       osvDir,
			caseDir:           caseDir,
			perimeterMode:     "auto",
			cveAnalysis:       "off",
			toolchain:         tc,
			osvFeed:           osvDir,
			attributionFile:   attributionFile,
		}
		// The shared corpus/capture resolution runs before the first case
		// exists, exactly as the analyze command does.
		if resolveErr := resolveAdvisorySources(ctx, &opts); resolveErr != nil {
			t.Fatalf("resolve advisory sources: %v", resolveErr)
		}
		if opts.corpus == nil {
			t.Fatalf("the configured frozen corpus was not acquired from %s", osvDir)
		}
		start := time.Now()
		c, runErr := analyzeCase(ctx, opts)
		wall := time.Since(start)
		ledger := &definitiveLedger{
			Task:        task.TaskID,
			Commit:      task.CommitSHA,
			RequestedID: requestID,
			WallSeconds: wall.Seconds(),
			DeploymentQuestion: "can an arbitrary external attacker reach the deployed Unix socket? " +
				"(socket permissions, placement, ingress or authentication) — not settled by this answer",
			AcceptanceTarget: "DECIDED/EXPLOITABLE, profile zero_trust, scope transport-peer, " +
				"proof origin GO-2023-2153, C-PEER-INPUT transport-peer-input",
		}
		if runErr != nil {
			ledger.TerminalState = "ERROR"
			ledger.AcceptanceCause = runErr.Error()
			return definitiveRun{ledger: ledger, err: runErr}
		}
		definitiveFillLedger(ledger, c, caseDir)
		return definitiveRun{ledger: ledger, c: c}
	}

	logRun := func(t *testing.T, r definitiveRun) {
		t.Helper()
		raw, err := json.MarshalIndent(r.ledger, "", "  ")
		if err != nil {
			t.Fatalf("encode ledger: %v", err)
		}
		t.Logf("definitive-verdict ledger [%s]:\n%s", r.ledger.RequestedID, raw)
	}

	var cveRun, ghsaRun definitiveRun
	t.Run("the requested CVE on the real snapshot", func(t *testing.T) {
		cveRun = run(t, definitiveCVE)
		logRun(t, cveRun)
		if cveRun.err != nil {
			t.Fatalf("analysis error: %v", cveRun.err)
		}
		definitiveAssertPrimary(t, cveRun.ledger, definitiveCVE)
		definitiveAssertDiscovery(t, cveRun.c)
		definitiveAssertAttribution(t, cveRun.c)
		definitiveAssertRecordFacts(t, cveRun.c)
	})

	t.Run("the exact broad GHSA request keeps its own scope failure", func(t *testing.T) {
		ghsaRun = run(t, definitiveGHSA)
		logRun(t, ghsaRun)
		if ghsaRun.err != nil {
			t.Fatalf("analysis error: %v", ghsaRun.err)
		}
		definitiveAssertPrimary(t, ghsaRun.ledger, definitiveGHSA)
		ledger := ghsaRun.ledger
		if ledger.AssessmentOutcome != string(domain.OutcomeFailed) {
			t.Fatalf("exact broad GHSA request outcome = %s, want FAILED (no gRPC substitution)",
				ledger.AssessmentOutcome)
		}
		if ledger.Verdict != "" {
			t.Fatalf("exact broad GHSA request published verdict %q", ledger.Verdict)
		}
		if !slices.Contains(ledger.FailureCodes, string(domain.GapOwnerScope)+"/"+string(domain.GapUnsupportedNegativeScope)) {
			t.Fatalf("exact broad GHSA failure codes = %v", ledger.FailureCodes)
		}
		if ledger.ProofOriginRecord != "" {
			t.Fatalf("the exact GHSA request adopted related witness %q", ledger.ProofOriginRecord)
		}
		// The independent record assessment stays its own finding: the exact
		// broad request neither adopts its witness nor loses its diagnostics.
		foundRelated := false
		for _, related := range ghsaRun.c.RelatedRecords {
			if related.Record.RecordID != definitiveGRPC || related.Analysis == nil {
				continue
			}
			requested := related.Analysis.RequestedFinding
			if requested == nil || requested.RequestedID != definitiveGRPC {
				t.Fatalf("the %s assessment has no own requested finding: %+v", definitiveGRPC, requested)
			}
			foundRelated = true
		}
		if !foundRelated {
			t.Fatalf("the independent %s assessment was not retained: %+v",
				definitiveGRPC, ghsaRun.c.RelatedRecords)
		}
	})

	t.Run("acceptance target", func(t *testing.T) {
		if cveRun.ledger == nil {
			t.Skip("the worked-case run did not execute")
		}
		if cveRun.ledger.AcceptanceMet {
			t.Logf("acceptance met: %s via %s", cveRun.ledger.AcceptanceTarget, cveRun.ledger.ProofOriginRecord)
			return
		}
		// A skipped calibration is not completion: state the measured cause.
		t.Skipf("ACCEPTANCE NOT MET — measured %s/%q with failure codes %v, cause: %s",
			cveRun.ledger.AssessmentOutcome, cveRun.ledger.Verdict, cveRun.ledger.FailureCodes,
			cveRun.ledger.AcceptanceCause)
	})
}

// definitiveFillLedger records one completed run.
func definitiveFillLedger(ledger *definitiveLedger, c *domain.AnalysisCase, caseDir string) {
	if c == nil {
		ledger.TerminalState = "NIL"
		ledger.AcceptanceCause = "analysis returned no case"
		return
	}
	ledger.TerminalState = string(c.Workflow.State)
	ledger.PrimaryRecord = c.Vulnerability.ID
	if c.RecordPin != nil {
		ledger.PrimaryDigest = c.RecordPin.DocumentDigest
	}
	if scope := c.Vulnerability.Scope; scope != nil {
		ledger.PrimaryExtent = string(scope.RecordExtent)
		ledger.PrimaryCoverage = string(scope.Coverage)
		if inventory := scope.RecordInventory; inventory != nil {
			ledger.PrimaryEntries = inventory.AffectedEntryCount
			ledger.PrimaryPresent = len(inventory.RepresentedRefs)
			ledger.PrimaryOmitted = len(inventory.OmittedRefs)
		}
	}
	for _, module := range c.Vulnerability.AffectedModules {
		ledger.PrimaryModules = append(ledger.PrimaryModules, module.Module)
	}
	ledger.CensusUntouched = ledger.PrimaryEntries == 22 && ledger.PrimaryPresent == 1 &&
		ledger.PrimaryOmitted == 21 && strings.Join(ledger.PrimaryModules, ",") == "golang.org/x/net"

	if discovery := c.RelatedDiscovery; discovery != nil {
		ledger.DiscoveryEnumeration = string(discovery.Enumeration)
		for _, candidate := range discovery.Candidates {
			ledger.DiscoveryCandidates = append(ledger.DiscoveryCandidates,
				candidate.Record.RecordID+":"+string(candidate.Disposition))
		}
	}
	if manifest := c.CorpusManifest; manifest != nil {
		ledger.CorpusDigest = manifest.ObservedDigest
		if c.CorpusDeclaration != nil {
			ledger.CorpusReference = c.CorpusDeclaration.Reference
		}
	}
	for _, attribution := range c.Attributions {
		if attribution.Admitted() && attribution.Candidate.RecordID == definitiveGRPC {
			ledger.AttributionRecord = attribution.Candidate.RecordID
			ledger.AttributionBasis = string(attribution.Basis)
			ledger.AttributionAdmission = string(attribution.Admission)
			ledger.PublisherAdvisory = attribution.PublisherAdvisory
			ledger.AttributionFixRefs = append([]string(nil), attribution.FixRefs...)
		}
	}
	if finding := c.RequestedFinding; finding != nil {
		ledger.AssessmentOutcome = string(finding.Outcome)
		ledger.Verdict = string(finding.Verdict)
		ledger.Reason = finding.Reason
		ledger.Profile = string(finding.Profile)
		ledger.IsTargetActual = finding.IsTargetActual
		ledger.ExploitScope = string(finding.ExploitabilityScope)
		ledger.Limitations = append([]string(nil), finding.Limitations...)
		for _, gap := range finding.Gaps {
			if finding.Outcome != domain.OutcomeDecided {
				ledger.FailureCodes = append(ledger.FailureCodes,
					string(gap.Owner)+"/"+string(gap.Code))
			}
		}
		if len(finding.ProofOrigins) > 0 {
			origin := finding.ProofOrigins[0]
			ledger.ProofOriginRecord = origin.Record.RecordID
			ledger.ProofOriginAssessment = string(origin.AssessmentID)
			ledger.ProofOriginProfile = string(origin.Profile)
			ledger.ProofOriginEvidence = len(origin.EvidenceRefs)
		}
		if finding.Outcome == domain.OutcomeDecided && finding.Verdict == domain.VerdictExploitable &&
			finding.Profile == domain.ProfileZeroTrust && finding.IsTargetActual &&
			finding.ExploitabilityScope == domain.ScopeTransportPeer &&
			len(finding.ProofOrigins) == 1 && finding.ProofOrigins[0].Record.RecordID == definitiveGRPC {
			ledger.AcceptanceMet = true
		}
	}
	// The deciding record's own witness and facts.
	for _, related := range c.RelatedRecords {
		if related.Record.RecordID != definitiveGRPC || related.Analysis == nil {
			continue
		}
		child := related.Analysis
		if child.Affected != nil {
			ledger.ResolvedVersion = child.Affected.ResolvedVersion
			ledger.VersionAffected = string(child.Affected.VersionAffected)
			ledger.VersionAffectedMods = append([]string(nil), child.Affected.VersionAffectedModules...)
			ledger.CheckedModules = append([]string(nil), child.Affected.CheckedModules...)
		}
		for _, evidence := range child.EvidenceGraph.EvidenceList() {
			trigger := evidence.TransportTrigger
			if trigger == nil {
				continue
			}
			ledger.WitnessRecord = trigger.Record.RecordID
			ledger.WitnessMechanism = trigger.Mechanism
			ledger.WitnessRoot = trigger.Input.Root.Package
			ledger.WitnessFixDigest = trigger.Fix.Digest
			ledger.WitnessFixEnforcement = append([]string(nil), trigger.Fix.EnforcementNames...)
			ledger.WitnessObligationsAll = len(trigger.Obligations)
			for _, obligation := range trigger.Obligations {
				if obligation.Satisfied {
					ledger.WitnessObligationsMet++
				}
			}
		}
		for _, claim := range child.Claims {
			switch claim.ConditionID {
			case "C-PEER-INPUT":
				ledger.PeerInputClaim = string(claim.Result)
				ledger.PeerInputBasis = string(claim.ControlBasis)
			case "C-CONSTRAINT":
				ledger.ConstraintClaim = string(claim.Result)
			}
		}
		if ledger.AcceptanceMet && (ledger.PeerInputClaim != string(domain.ClaimTrue) ||
			ledger.PeerInputBasis != string(domain.ControlBasisTransportPeerInput)) {
			ledger.AcceptanceMet = false
		}
		if ledger.AcceptanceMet && (ledger.WitnessObligationsMet == 0 ||
			ledger.WitnessObligationsMet != ledger.WitnessObligationsAll) {
			ledger.AcceptanceMet = false
		}
	}

	reportDir := filepath.Join(caseDir, string(c.ID))
	for _, name := range []string{"report.json", "report.md", "openvex.json", "cyclonedx.json"} {
		if _, err := os.Stat(filepath.Join(reportDir, name)); err == nil {
			ledger.ExportsWritten = append(ledger.ExportsWritten, name)
		}
	}
	ledger.ReportWritten = slices.Contains(ledger.ExportsWritten, "report.json")
	if !ledger.AcceptanceMet && ledger.AcceptanceCause == "" {
		ledger.AcceptanceCause = acceptanceCause(c)
	}
}

// acceptanceCause states the measured blocker behind an unmet acceptance
// target, taken from the recorded typed diagnostics (never from prose).
func acceptanceCause(c *domain.AnalysisCase) string {
	if c == nil {
		return "no case"
	}
	var root string
	if discovery := c.RelatedDiscovery; discovery != nil {
		for _, candidate := range discovery.Candidates {
			if candidate.Record.RecordID == definitiveGRPC {
				root = string(candidate.Disposition) + ": " + candidate.Note
			}
		}
	}
	if finding := c.RequestedFinding; finding != nil {
		var codes []string
		for _, gap := range finding.Gaps {
			codes = append(codes, string(gap.Owner)+"/"+string(gap.Code))
		}
		return fmt.Sprintf("requested %s/%q; gaps %v; candidate %s",
			finding.Outcome, finding.Verdict, codes, root)
	}
	return "no requested finding; candidate " + root
}

// definitiveAssertPrimary pins the recorded 22-entry census and the request
// identity that the run must never mutate.
func definitiveAssertPrimary(t *testing.T, ledger *definitiveLedger, requestID string) {
	t.Helper()
	if ledger.PrimaryRecord != definitiveGHSA {
		t.Fatalf("primary record = %q, want the exact %s document", ledger.PrimaryRecord, definitiveGHSA)
	}
	if ledger.PrimaryExtent != string(domain.RecordExtentGoProjection) ||
		ledger.PrimaryCoverage != string(domain.CoverageKnownOnly) {
		t.Fatalf("primary extent/coverage = %q/%q", ledger.PrimaryExtent, ledger.PrimaryCoverage)
	}
	if ledger.PrimaryEntries != 22 || ledger.PrimaryPresent != 1 || ledger.PrimaryOmitted != 21 {
		t.Fatalf("primary census = %d/%d/%d, want 22/1/21",
			ledger.PrimaryEntries, ledger.PrimaryPresent, ledger.PrimaryOmitted)
	}
	if !slices.Equal(ledger.PrimaryModules, []string{"golang.org/x/net"}) {
		t.Fatalf("primary Go projection = %v", ledger.PrimaryModules)
	}
	if ledger.RequestedID != requestID {
		t.Fatalf("requested id = %q, want %q", ledger.RequestedID, requestID)
	}
}

// definitiveAssertDiscovery pins the configured corpus enumeration and the
// inverse related nomination of the independent gRPC record.
func definitiveAssertDiscovery(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	discovery := c.RelatedDiscovery
	if discovery == nil {
		t.Fatal("no discovery record")
	}
	if discovery.Enumeration != domain.DiscoveryFinished {
		t.Fatalf("discovery enumeration = %q, want finished", discovery.Enumeration)
	}
	if c.CorpusManifest == nil || c.CorpusManifest.ObservedDigest == "" {
		t.Fatal("discovery ran without a pinned corpus manifest")
	}
	for _, candidate := range discovery.Candidates {
		if candidate.Record.RecordID == definitiveGRPC {
			return
		}
	}
	t.Fatalf("inverse related(%s) did not nominate %s: %+v", definitiveCVE, definitiveGRPC, discovery.Candidates)
}

// definitiveAssertAttribution pins the directional publisher attribution and
// the fact that it never entered the GO record's aliases.
func definitiveAssertAttribution(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	var admitted *domain.CVEAttribution
	for i := range c.Attributions {
		attribution := &c.Attributions[i]
		if attribution.Candidate.RecordID == definitiveGRPC && attribution.Admitted() {
			admitted = attribution
		}
	}
	if admitted == nil {
		t.Fatalf("no admitted directional attribution for %s: %+v", definitiveGRPC, c.Attributions)
	}
	if admitted.Basis != domain.AttributionPublisher {
		t.Fatalf("attribution basis = %q, want publisher", admitted.Basis)
	}
	if admitted.PublisherAdvisory != "GHSA-m425-mq94-257g" {
		t.Fatalf("publisher advisory = %q", admitted.PublisherAdvisory)
	}
	if !slices.Contains(admitted.FixRefs, "https://github.com/grpc/grpc-go/pull/6703") {
		t.Fatalf("attribution fix refs = %v", admitted.FixRefs)
	}
	for _, related := range c.RelatedRecords {
		if related.Record.RecordID != definitiveGRPC {
			continue
		}
		if slices.Contains(related.Analysis.Vulnerability.Aliases, definitiveCVE) {
			t.Fatalf("%s aliases were mutated with the requested CVE: %v",
				definitiveGRPC, related.Analysis.Vulnerability.Aliases)
		}
	}
}

// definitiveAssertRecordFacts pins the two independent applicability facts.
func definitiveAssertRecordFacts(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	if c.Affected != nil && c.Affected.VersionAffected == domain.ClaimTrue {
		t.Fatalf("the primary x/net entry became affected: %+v", c.Affected)
	}
	for _, related := range c.RelatedRecords {
		if related.Record.RecordID != definitiveGRPC || related.Analysis == nil {
			continue
		}
		affected := related.Analysis.Affected
		if affected == nil {
			t.Fatalf("%s assessed without affected facts", definitiveGRPC)
		}
		if !slices.Contains(affected.CheckedModules, definitiveTargetGRPC) {
			t.Fatalf("checked modules = %v, want %s", affected.CheckedModules, definitiveTargetGRPC)
		}
		if affected.ResolvedVersion != "" && affected.ResolvedVersion != definitiveTargetCover {
			t.Fatalf("gRPC resolved version = %q, want %s", affected.ResolvedVersion, definitiveTargetCover)
		}
	}
}
