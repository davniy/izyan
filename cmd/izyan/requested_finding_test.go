package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/justification"
	"github.com/fedorovmv/izyan/internal/report"
)

const (
	consumersCVE         = "CVE-2023-44487"
	consumersPrimary     = "GHSA-qppj-fm5r-hxr3"
	consumersChild       = "GO-2023-2153"
	consumersGRPCModule  = "google.golang.org/grpc"
	consumersGRPCFix     = "1.56.3"
	consumersPrimaryCase = domain.CaseID("consumers-primary")
	consumersChildCase   = domain.CaseID("consumers-child")
	// Two distinct mechanisms so witness selection is observable: the dossier
	// must explain the gRPC one, never the primary x/net one.
	consumersGRPCMechanism = "HTTP/2 Rapid Reset admitted handler work after a peer stream reset"
	consumersXNetMechanism = "x/net h2 stream-limit accounting"
)

func consumersDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func consumersPin(id string) domain.RecordPin {
	return domain.RecordPin{
		RecordID:       id,
		DocumentDigest: consumersDigest(id),
		SourceLocator:  "corpus/" + id + ".json",
	}
}

func consumersBuild() domain.BuildContext {
	return domain.BuildContext{
		Repository: "github.com/kubernetes/kubernetes",
		Commit:     "e196d24",
		GOOS:       "linux",
		GOARCH:     "amd64",
		GoVersion:  "go1.25.0",
	}
}

func consumersProduct(b domain.BuildContext) domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: b.Repository,
		Commit:     b.Commit,
		GOOS:       b.GOOS,
		GOARCH:     b.GOARCH,
		GoVersion:  b.GoVersion,
	}
}

// consumersScope is an exact-record request scope with a one-entry census.
func consumersScope(requestedID string, kind domain.AdvisoryScopeKind, coverage domain.AdvisoryCoverage) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: requestedID,
		ResolvedID:  requestedID,
		Kind:        kind,
		Coverage:    coverage,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         requestedID,
			DocumentDigest:     consumersDigest(requestedID),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go"}},
			RepresentedRefs:    []int{0},
		},
	}
}

// consumersNegativeScope is the full-record scope a record-level negative needs.
// Every represented original entry must name its Go module, so the census is
// admissible rather than merely shaped like one.
func consumersNegativeScope(id, module string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID:  id,
		ResolvedID:   id,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     consumersDigest(id),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: module}},
			RepresentedRefs:    []int{0},
		},
	}
}

func consumersAddEvidence(c *domain.AnalysisCase, ids ...domain.EvidenceID) {
	for _, id := range ids {
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:      id,
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "consumers-test",
			Content: string(id),
		})
	}
}

// consumersAssess classifies a record exactly as the workflow does, including
// the record-level producer gaps it carries.
func consumersAssess(c *domain.AnalysisCase, claims []domain.Claim) domain.AssessmentResult {
	affected := domain.AffectedResult{}
	if c.Affected != nil {
		affected = *c.Affected
	}
	model := domain.ExploitModel{}
	if c.Exploit != nil {
		model = *c.Exploit
	}
	return finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:  c.Product,
			Affected: affected,
			Model:    model,
			Claims:   claims,
			Evidence: c.EvidenceGraph.EvidenceList(),
		},
		RootCause:    c.RootCause,
		Gaps:         c.AnalysisGaps,
		AssessmentID: c.ID,
	})
}

func consumersAttribution(id string, pin domain.RecordPin) domain.CVEAttribution {
	return domain.CVEAttribution{
		ID:                id,
		CVEID:             consumersCVE,
		Candidate:         pin,
		EntryRefs:         []int{0},
		MechanismID:       "http2-rapid-reset",
		Basis:             domain.AttributionPublisher,
		SourceURI:         "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
		CapturedDigest:    consumersDigest("a"),
		SourceField:       "cve_ids[0]",
		SourceQuote:       consumersCVE,
		PublisherAdvisory: "GHSA-m425-mq94-257g",
		Module:            consumersGRPCModule,
		Repository:        "github.com/grpc/grpc-go",
		FixRefs:           []string{"https://github.com/grpc/grpc-go/pull/6703"},
		Admission:         domain.AttributionAdmitted,
	}
}

// consumersPositiveRecord builds one independently earned library-API positive
// with its own module, resolved version, published fixes and mechanism.
func consumersPositiveRecord(t *testing.T, id domain.CaseID, recordID, module, resolved string,
	fixed []string, mechanism string) *domain.AnalysisCase {
	t.Helper()
	build := consumersBuild()
	pin := consumersPin(recordID)
	claims := []domain.Claim{{
		ID:           "CL-C-API",
		ConditionID:  "C-API",
		Result:       domain.ClaimTrue,
		EvidenceIDs:  []domain.EvidenceID{"EV-API"},
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}}
	c := &domain.AnalysisCase{
		ID:          id,
		RequestedID: recordID,
		Vulnerability: domain.Vulnerability{
			ID:            recordID,
			Module:        module,
			FixedVersions: fixed,
			Scope:         consumersScope(recordID, domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   consumersProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: resolved,
		},
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-API", Kind: domain.ConditionInputConstraint, Mandatory: true,
		}}},
		Claims: claims,
		CVEAnalysis: &domain.CVEAnalysisProposal{Mechanisms: []domain.DefectMechanism{{
			ID:            "M-WITNESS",
			Summary:       mechanism,
			FaultingSites: []string{"grpc.(*Server).handleRawConn"},
		}}},
	}
	consumersAddEvidence(c, "EV-API")
	result := consumersAssess(c, claims)
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         result,
	}}
	c.Verdict = result.Verdict
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize %q: %v", id, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// consumersCVEPositive builds the worked case: a CVE request whose primary x/net
// record is affected-but-unproved and whose gRPC candidate earned the positive.
func consumersCVEPositive(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := consumersBuild()
	child := consumersPositiveRecord(t, consumersChildCase, consumersChild, consumersGRPCModule,
		"1.55.0", []string{"1.56.3", "1.57.1", "1.58.3"}, consumersGRPCMechanism)
	childPin := consumersPin(consumersChild)
	primaryPin := consumersPin(consumersPrimary)
	root := &domain.AnalysisCase{
		ID:          consumersPrimaryCase,
		RequestedID: consumersCVE,
		Vulnerability: domain.Vulnerability{
			ID:            consumersPrimary,
			Module:        "golang.org/x/net",
			FixedVersions: []string{"0.23.0"},
			Scope:         consumersScope(consumersCVE, domain.ScopeCVE, domain.CoverageKnownOnly),
		},
		RecordPin: &primaryPin,
		Product:   consumersProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "0.17.0",
		},
		CVEAnalysis: &domain.CVEAnalysisProposal{Mechanisms: []domain.DefectMechanism{{
			ID: "M-PRIMARY", Summary: consumersXNetMechanism,
		}}},
		RelatedDiscovery: &domain.RelatedDiscovery{
			RequestedID: consumersCVE,
			Enumeration: domain.DiscoveryPartial,
			Corpus: &domain.CorpusReference{
				Reference: "osv-dump", Digest: consumersDigest("corpus"), CapturedAt: "2026-10-20",
			},
			Candidates: []domain.DiscoveryCandidate{{
				Record:      childPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: consumersCVE}},
				Disposition: domain.DispositionEvaluated,
			}},
		},
		RelatedRecords: []domain.RelatedRecordAssessment{{ID: child.ID, Record: childPin, Analysis: child}},
		Attributions:   []domain.CVEAttribution{consumersAttribution("ATTR-CHILD", childPin)},
	}
	rootResult := consumersAssess(root, nil)
	root.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         rootResult,
	}}
	root.Verdict = rootResult.Verdict
	if err := finding.Finalize(root); err != nil {
		t.Fatalf("finalize cve root: %v", err)
	}
	root.Workflow.State = domain.StateCompleted
	return root
}

// consumersFailedCase is an exact request whose trigger proof did not complete.
func consumersFailedCase(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := consumersBuild()
	pin := consumersPin(consumersPrimary)
	c := &domain.AnalysisCase{
		ID:          consumersPrimaryCase,
		RequestedID: consumersPrimary,
		Vulnerability: domain.Vulnerability{
			ID:    consumersPrimary,
			Scope: consumersScope(consumersPrimary, domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   consumersProduct(build),
		AnalysisGaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerProof,
			Code:         domain.GapTriggerProofIncomplete,
			Obligation:   domain.ObligationCondition,
			AssessmentID: consumersPrimaryCase,
			Message:      "the Rapid Reset trigger obligation was not proved",
		}},
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         consumersAssess(c, nil),
	}}
	// EvaluateVerdict normally publishes the actual profile's verdict and
	// claims on the record; the record-level extractors read them.
	c.Verdict = c.ProfileAssessments[0].Result.Verdict
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize failed case: %v", err)
	}
	c.Workflow.State = domain.StateFailed
	return c
}

// consumersCVEFailed is the CVE-scoped form of the failure: the primary could
// not decide and no declared corpus can close the request.
func consumersCVEFailed(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	c := consumersFailedCase(t)
	c.RequestedID = consumersCVE
	c.Vulnerability.Scope = consumersScope(consumersCVE, domain.ScopeCVE, domain.CoverageKnownOnly)
	c.RelatedDiscovery = &domain.RelatedDiscovery{
		RequestedID: consumersCVE,
		Enumeration: domain.DiscoveryNotConfigured,
		Limitations: []string{"no advisory corpus is configured; no CVE discovery was performed"},
	}
	c.RequestedFinding = nil
	c.Schema = ""
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize cve failure: %v", err)
	}
	c.Workflow.State = domain.StateFailed
	return c
}

// consumersExternalCase is an exact request answered by a named external fact.
func consumersExternalCase(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := consumersBuild()
	pin := consumersPin(consumersPrimary)
	c := &domain.AnalysisCase{
		ID:          consumersPrimaryCase,
		RequestedID: consumersPrimary,
		Vulnerability: domain.Vulnerability{
			ID:    consumersPrimary,
			Scope: consumersScope(consumersPrimary, domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   consumersProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimUnknown,
			EvidenceIDs:     []domain.EvidenceID{"EV-VERSION"},
		},
	}
	consumersAddEvidence(c, "EV-VERSION")
	result := consumersAssess(c, nil)
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         result,
	}}
	c.Verdict = result.Verdict
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize external case: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// consumersCorpusNegative is a declared, digest-pinned corpus whose only
// candidate earned its own record-level negative.
func consumersCorpusNegative(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := consumersBuild()
	child := &domain.AnalysisCase{
		ID:          consumersChildCase,
		RequestedID: consumersChild,
		Vulnerability: domain.Vulnerability{
			ID:    consumersChild,
			Scope: consumersNegativeScope(consumersChild, consumersGRPCModule),
		},
		Product: consumersProduct(build),
		// The negative-closure gate reads the scope from the affected facts;
		// a full-record, complete census is what a record-level negative needs.
		Affected: &domain.AffectedResult{
			Scope:         consumersNegativeScope(consumersChild, consumersGRPCModule),
			ModulePresent: domain.ClaimFalse,
		},
	}
	childPin := consumersPin(consumersChild)
	child.RecordPin = &childPin
	childResult := consumersAssess(child, nil)
	if childResult.Outcome != domain.OutcomeDecided || childResult.Verdict == nil ||
		childResult.Verdict.Verdict != domain.VerdictNotAffected {
		t.Fatalf("fixture precondition: candidate assessment = %s/%q gaps=%+v limitations=%+v",
			childResult.Outcome, childResult.Verdict, childResult.Gaps, childResult.Limitations)
	}
	child.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         childResult,
	}}
	child.Verdict = childResult.Verdict
	if err := finding.Finalize(child); err != nil {
		t.Fatalf("finalize negative child: %v", err)
	}
	child.Workflow.State = domain.StateCompleted

	primaryPin := consumersPin(consumersPrimary)
	reference := "osv-dump-2026-10-20"
	digest := consumersDigest("declared-corpus")
	manifest := domain.CorpusManifest{
		Reference:      reference,
		CapturedAt:     "2026-10-20",
		ObservedDigest: digest,
		Enumeration:    domain.DiscoveryFinished,
		Documents:      []domain.RecordPin{childPin},
		Sources: []domain.CorpusSource{{
			Ref: "https://osv.dev/dump", SHA256: consumersDigest("source"), CheckedAt: "2026-10-20",
		}},
	}
	root := &domain.AnalysisCase{
		ID:          consumersPrimaryCase,
		RequestedID: consumersCVE,
		Vulnerability: domain.Vulnerability{
			ID:    consumersPrimary,
			Scope: consumersScope(consumersCVE, domain.ScopeCVE, domain.CoverageKnownOnly),
		},
		RecordPin:         &primaryPin,
		Product:           consumersProduct(build),
		CorpusDeclaration: &domain.CorpusDeclaration{Reference: reference, ExpectedDigest: digest, CapturedAt: "2026-10-20"},
		CorpusManifest:    &manifest,
		RelatedDiscovery: &domain.RelatedDiscovery{
			RequestedID: consumersCVE,
			Enumeration: domain.DiscoveryFinished,
			Corpus:      &domain.CorpusReference{Reference: reference, Digest: digest, CapturedAt: "2026-10-20"},
			Candidates: []domain.DiscoveryCandidate{{
				Record:      childPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: consumersCVE}},
				Disposition: domain.DispositionEvaluated,
			}},
		},
		RelatedRecords: []domain.RelatedRecordAssessment{{ID: child.ID, Record: childPin, Analysis: child}},
	}
	rootResult := consumersAssess(root, nil)
	root.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         rootResult,
	}}
	root.Verdict = rootResult.Verdict
	if err := finding.Finalize(root); err != nil {
		t.Fatalf("finalize corpus negative: %v", err)
	}
	root.Workflow.State = domain.StateCompleted
	return root
}

func consumersProject(t *testing.T, c *domain.AnalysisCase) requestedView {
	t.Helper()
	view, err := projectRequested(c)
	if err != nil {
		t.Fatalf("project requested finding: %v", err)
	}
	return view
}

// captureStdout runs fn with stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout: %v", err)
	}
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return buf.String()
}

// consumersCorpusDir writes the gRPC advisory fixture into a fresh dump
// directory and returns its path.
func consumersCorpusDir(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../eval/advisories/reviewed/GO-2023-2153.json")
	if err != nil {
		t.Fatalf("read gRPC advisory: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, consumersChild+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRequestedFindingConsumers(t *testing.T) {
	t.Run("a failed request publishes no verdict and exits nonzero", func(t *testing.T) {
		c := consumersFailedCase(t)
		var printErr error
		out := captureStdout(t, func() { printErr = printCase(c, t.TempDir(), "en") })
		if printErr == nil {
			t.Fatal("a FAILED requested assessment must exit nonzero")
		}
		for _, want := range []string{
			"assessment_outcome: FAILED",
			"failure_code: PROOF/TRIGGER_PROOF_INCOMPLETE",
			"report: ",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("output lacks %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "verdict:") {
			t.Fatalf("a FAILED result published a verdict line:\n%s", out)
		}
		if strings.Contains(out, "priority: DISMISSED") {
			t.Fatalf("a FAILED result inherited a dismissed risk disposition:\n%s", out)
		}
	})

	t.Run("an external dependency names the decision-changing fact", func(t *testing.T) {
		c := consumersExternalCase(t)
		var printErr error
		out := captureStdout(t, func() { printErr = printCase(c, t.TempDir(), "en") })
		if printErr != nil {
			t.Fatalf("an external dependency is an honest answer, not a failure: %v", printErr)
		}
		for _, want := range []string{
			"assessment_outcome: EXTERNAL_DEPENDENCY",
			"verdict: INCONCLUSIVE",
			"external_dependency: the affected entry's version as shipped in the delivered artifact",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("output lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("a composed CVE positive renders its witness, not the primary", func(t *testing.T) {
		c := consumersCVEPositive(t)
		var printErr error
		out := captureStdout(t, func() { printErr = printCase(c, t.TempDir(), "en") })
		if printErr != nil {
			t.Fatalf("a decided positive must exit zero: %v", printErr)
		}
		for _, want := range []string{
			"requested: " + consumersCVE + " (CVE, KNOWN_ONLY coverage)",
			"assessment_outcome: DECIDED",
			"verdict: EXPLOITABLE",
			"exploitability_scope: library-api",
			"proof_origin: " + consumersChild,
			"profile: zero_trust",
			domain.LibraryAPIScopeLimitation,
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("output lacks %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "proof_origin: "+consumersPrimary) {
			t.Fatalf("the primary record was presented as the witness:\n%s", out)
		}
	})

	t.Run("remediation targets the composed witness", func(t *testing.T) {
		c := consumersCVEPositive(t)
		targets := remediationTargets(consumersProject(t, c))
		if len(targets) != 1 {
			t.Fatalf("targets = %+v", targets)
		}
		target := targets[0]
		if target.Module != consumersGRPCModule || target.FixedVersion != "v"+consumersGRPCFix ||
			target.ResolvedVersion != "1.55.0" {
			t.Fatalf("target = %+v", target)
		}
		if target.Origin.Record.RecordID != consumersChild {
			t.Fatalf("target witness = %+v", target.Origin)
		}
		// Fixture precondition: the primary record *does* publish its own fix,
		// so a primary-reading implementation would have returned x/net.
		module, version, ok := report.FixTarget(c)
		if !ok || module != "golang.org/x/net" || version != "v0.23.0" {
			t.Fatalf("fixture primary fix target = %s %s %v; want x/net v0.23.0", module, version, ok)
		}
		for _, nonDecided := range []*domain.AnalysisCase{consumersFailedCase(t), consumersExternalCase(t)} {
			if got := remediationTargets(consumersProject(t, nonDecided)); len(got) != 0 {
				t.Fatalf("a non-positive result planned a fix: %+v", got)
			}
		}
	})

	t.Run("scan rows classify FAILED and external results distinctly", func(t *testing.T) {
		failed := scanRowFromCase("CVE-FAILED", consumersFailedCase(t), nil)
		if failed.Outcome != "FAILED" || failed.Verdict != "" || len(failed.FailureCodes) == 0 {
			t.Fatalf("failed row = %+v", failed)
		}
		external := scanRowFromCase("CVE-EXTERNAL", consumersExternalCase(t), nil)
		if external.Outcome != "EXTERNAL_DEPENDENCY" || external.Verdict != "INCONCLUSIVE" {
			t.Fatalf("external row = %+v", external)
		}
		if len(external.FailureCodes) != 0 {
			t.Fatalf("an external dependency acquired failure codes: %+v", external)
		}
		positive := scanRowFromCase(consumersCVE, consumersCVEPositive(t), nil)
		if positive.Outcome != "DECIDED" || positive.Verdict != "EXPLOITABLE" ||
			positive.ProofOrigin != consumersChild {
			t.Fatalf("positive row = %+v", positive)
		}
		execErr := scanRowFromCase("CVE-ERROR", nil, io.ErrUnexpectedEOF)
		if execErr.State != "ERROR" || execErr.Verdict != "" || execErr.Outcome != "" {
			t.Fatalf("execution error row = %+v", execErr)
		}
	})

	t.Run("the harness projection carries identity and witness provenance", func(t *testing.T) {
		projection := evalProjection(consumersProject(t, consumersCVEPositive(t)))
		if !projection.Available || projection.Outcome != domain.OutcomeDecided ||
			projection.Verdict != domain.VerdictExploitable {
			t.Fatalf("projection = %+v", projection)
		}
		if projection.RequestedID != consumersCVE ||
			projection.RequestedKind != string(domain.ScopeCVE) ||
			projection.Coverage != string(domain.CoverageKnownOnly) {
			t.Fatalf("request identity = %+v", projection)
		}
		if projection.PrimaryRecord != consumersPrimary ||
			projection.PrimaryDigest != consumersDigest(consumersPrimary) {
			t.Fatalf("primary record = %+v", projection)
		}
		if len(projection.CandidateIDs) != 1 || projection.CandidateIDs[0] != consumersChild {
			t.Fatalf("candidates = %+v", projection.CandidateIDs)
		}
		if len(projection.AttributionOutcomes) != 1 ||
			projection.AttributionOutcomes[0] != "ATTR-CHILD=admitted" {
			t.Fatalf("attributions = %+v", projection.AttributionOutcomes)
		}
		if len(projection.ProofOrigins) != 1 ||
			projection.ProofOrigins[0].RecordID != consumersChild ||
			projection.ProofOrigins[0].AttributionID != "ATTR-CHILD" {
			t.Fatalf("origins = %+v", projection.ProofOrigins)
		}
		if projection.Profile != string(domain.ProfileZeroTrust) || projection.Build == "" {
			t.Fatalf("provenance = %+v", projection)
		}
		if len(projection.FailureCodes) != 0 || len(projection.ExternalDependencies) != 0 {
			t.Fatalf("a decided positive carried diagnostics: %+v", projection)
		}

		corpusProjection := evalProjection(consumersProject(t, consumersCorpusNegative(t)))
		if corpusProjection.Verdict != domain.VerdictNotAffected ||
			corpusProjection.CorpusDigest == "" {
			t.Fatalf("corpus negative projection = %+v", corpusProjection)
		}
	})

	t.Run("the benchmark envelope consumes the same projection", func(t *testing.T) {
		task := vexbench.Task{TaskID: "vex-1", CVEID: consumersCVE, GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"}
		var env vexEnvelope
		prediction := vexOutcomeFromView(consumersProject(t, consumersCVEPositive(t)), &env, task)
		if prediction.AssessmentOutcome != "DECIDED" || prediction.Verdict != "EXPLOITABLE" || prediction.Failed {
			t.Fatalf("prediction = %+v", prediction)
		}
		if env.AssessmentOutcome != "DECIDED" || env.ExploitabilityScope != "library-api" ||
			env.PrimaryRecord != consumersPrimary {
			t.Fatalf("envelope = %+v", env)
		}
		if len(env.ProofOrigins) != 1 || env.ProofOrigins[0].RecordID != consumersChild {
			t.Fatalf("envelope origins = %+v", env.ProofOrigins)
		}
		if len(env.CandidateIDs) != 1 || env.CandidateIDs[0] != consumersChild {
			t.Fatalf("envelope candidates = %+v", env.CandidateIDs)
		}
		if got := vexbench.Classify(task, prediction); got != vexbench.OutcomeCorrectExploit {
			t.Fatalf("scoring outcome = %q", got)
		}
		if label := vexPredictionLabel(prediction); label != "DECIDED EXPLOITABLE" {
			t.Fatalf("label = %q", label)
		}

		// A FAILED CVE request publishes no verdict and is scored as a failure.
		var failedEnv vexEnvelope
		failedPrediction := vexOutcomeFromView(consumersProject(t, consumersCVEFailed(t)), &failedEnv, task)
		if failedPrediction.Verdict != "" || !failedPrediction.Failed ||
			failedEnv.AssessmentOutcome != "FAILED" || len(failedEnv.FailureCodes) == 0 {
			t.Fatalf("failed envelope = %+v / %+v", failedPrediction, failedEnv)
		}
		if got := vexbench.Classify(task, failedPrediction); got != vexbench.OutcomeFailed {
			t.Fatalf("a failed analysis classified %q", got)
		}

		// An external dependency abstains and is not a definitive answer.
		var externalEnv vexEnvelope
		exactTask := vexbench.Task{TaskID: "vex-2", CVEID: consumersPrimary, GroundTruth: "exploitable"}
		externalPrediction := vexOutcomeFromView(consumersProject(t, consumersExternalCase(t)), &externalEnv, exactTask)
		if externalPrediction.Verdict != "INCONCLUSIVE" || externalPrediction.Failed {
			t.Fatalf("external prediction = %+v", externalPrediction)
		}
		if got := vexbench.Classify(exactTask, externalPrediction); got != vexbench.OutcomeAbstain {
			t.Fatalf("an external dependency classified %q", got)
		}
	})

	t.Run("justification identifies the selected witness", func(t *testing.T) {
		c := consumersCVEPositive(t)
		dossier := justification.Build(c)
		if dossier.VulnerabilityID != consumersCVE || dossier.Verdict != domain.VerdictExploitable {
			t.Fatalf("dossier = %+v", dossier)
		}
		if !strings.Contains(dossier.TechnicalMechanism, consumersGRPCMechanism) {
			t.Fatalf("dossier explains %q, not the gRPC witness", dossier.TechnicalMechanism)
		}
		if strings.Contains(dossier.TechnicalMechanism, consumersXNetMechanism) {
			t.Fatalf("dossier read the primary record's mechanism: %q", dossier.TechnicalMechanism)
		}
		facts := strings.Join(dossier.VerifiedFacts, "\n")
		for _, want := range []string{consumersChild, "ATTR-CHILD", consumersGRPCModule} {
			if !strings.Contains(facts, want) {
				t.Fatalf("dossier facts lack %q:\n%s", want, facts)
			}
		}

		failed := justification.Build(consumersFailedCase(t))
		if failed.Verdict != "" {
			t.Fatalf("a FAILED analysis published verdict %q", failed.Verdict)
		}
		external := justification.Build(consumersExternalCase(t))
		if external.Verdict != domain.VerdictInconclusive {
			t.Fatalf("external dossier verdict = %q", external.Verdict)
		}
		var questions []string
		for _, item := range external.HumanRemainder {
			questions = append(questions, item.Question)
		}
		if !strings.Contains(strings.Join(questions, "\n"), "release toolchain") {
			t.Fatalf("external dossier does not name the missing fact: %+v", external)
		}
	})

	t.Run("an undeclared corpus cannot close the CVE request", func(t *testing.T) {
		// Same records, same corpus manifest, no operator declaration: Addendum
		// A closure must be unavailable, and the request must fail explicitly
		// instead of becoming a bounded negative.
		c := consumersCorpusNegative(t)
		c.CorpusDeclaration = nil
		c.RequestedFinding = nil
		c.Schema = ""
		if err := finding.Finalize(c); err != nil {
			t.Fatalf("finalize undeclared corpus: %v", err)
		}
		c.Workflow.State = domain.StateFailed
		view := consumersProject(t, c)
		if view.Finding.Outcome != domain.OutcomeFailed || view.Finding.Verdict != "" {
			t.Fatalf("undeclared corpus closed the request: %+v", view.Finding.FindingProfile)
		}
		found := false
		for _, gap := range view.Finding.Gaps {
			if gap.Code == domain.GapUnsupportedNegativeScope {
				found = true
			}
		}
		if !found {
			t.Fatalf("undeclared corpus failure lacks UNSUPPORTED_NEGATIVE_SCOPE: %+v", view.Finding.Gaps)
		}
	})

	t.Run("a configured corpus without a declaration cannot close a CVE negative", func(t *testing.T) {
		t.Setenv(osvURLEnv, "")
		feed := consumersCorpusDir(t)
		undeclared := analyzeOpts{osvFeed: feed}
		if err := resolveAdvisorySources(context.Background(), &undeclared); err != nil {
			t.Fatalf("resolve undeclared corpus: %v", err)
		}
		if undeclared.corpus == nil {
			t.Fatal("a configured feed produced no corpus")
		}
		if undeclared.corpusDeclaration != nil {
			t.Fatal("a corpus declaration was invented without operator input")
		}
		manifest := undeclared.corpus.Manifest()
		discovery := undeclared.corpus.Discover(consumersCVE, nil)
		c := &domain.AnalysisCase{
			RequestedID: consumersCVE,
			Vulnerability: domain.Vulnerability{
				Scope: consumersScope(consumersCVE, domain.ScopeCVE, domain.CoverageKnownOnly),
			},
			CorpusManifest:   &manifest,
			RelatedDiscovery: &discovery,
		}
		if _, err := domain.DeclaredCorpusBoundary(c); err == nil {
			t.Fatal("declared-corpus closure is available without a declaration")
		}

		// The same boundary is admitted once the operator declares its digest
		// and capture date.
		declared := analyzeOpts{
			osvFeed:          feed,
			corpusDigest:     manifest.ObservedDigest,
			corpusCapturedAt: "2026-10-26T00:00:00Z",
		}
		if err := resolveAdvisorySources(context.Background(), &declared); err != nil {
			t.Fatalf("resolve declared corpus: %v", err)
		}
		if declared.corpusDeclaration == nil {
			t.Fatal("an explicit digest and capture date produced no declaration")
		}
		declaredManifest := declared.corpus.Manifest()
		declaredDiscovery := declared.corpus.Discover(consumersCVE, nil)
		c.CorpusDeclaration = declared.corpusDeclaration
		c.CorpusManifest = &declaredManifest
		c.RelatedDiscovery = &declaredDiscovery
		if _, err := domain.DeclaredCorpusBoundary(c); err != nil {
			t.Fatalf("declared corpus boundary refused: %v", err)
		}
	})

	t.Run("a declared corpus needs a source and both halves", func(t *testing.T) {
		t.Setenv(osvURLEnv, "")
		unconfigured := analyzeOpts{corpusDigest: consumersDigest("corpus"), corpusCapturedAt: "2026-10-26T00:00:00Z"}
		if err := resolveAdvisorySources(context.Background(), &unconfigured); err == nil {
			t.Fatal("a declaration without a corpus source must fail before analysis")
		}
		partial := analyzeOpts{osvFeed: consumersCorpusDir(t), corpusDigest: consumersDigest("corpus")}
		if err := resolveAdvisorySources(context.Background(), &partial); err == nil {
			t.Fatal("a digest without a capture date must fail before analysis")
		}
		badDate := analyzeOpts{osvFeed: consumersCorpusDir(t), corpusDigest: consumersDigest("corpus"), corpusCapturedAt: "2026-10-26"}
		if err := resolveAdvisorySources(context.Background(), &badDate); err == nil {
			t.Fatal("a non-RFC3339 capture date must fail before analysis")
		}
	})

	t.Run("the capture manifest is verified before analysis", func(t *testing.T) {
		t.Setenv(osvURLEnv, "")
		dir := t.TempDir()
		body := []byte(`{"basis":"publisher","advisory_id":"GHSA-m425-mq94-257g",` +
			`"cve_ids":["CVE-2023-44487"],"module":"google.golang.org/grpc",` +
			`"fix_refs":["https://github.com/grpc/grpc-go/pull/6703"]}`)
		if err := os.WriteFile(filepath.Join(dir, "capture.json"), body, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		manifest := map[string]any{
			"schema": attributionManifestSchema,
			"captures": []map[string]string{{
				"source_uri": "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
				"path":       "capture.json",
				"sha256":     "sha256:" + hex.EncodeToString(sum[:]),
			}},
		}
		manifestPath := filepath.Join(dir, "captures.json")
		writeManifest := func(doc map[string]any) {
			t.Helper()
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		writeManifest(manifest)
		resolved := analyzeOpts{attributionFile: manifestPath}
		if err := resolveAdvisorySources(context.Background(), &resolved); err != nil {
			t.Fatalf("resolve capture manifest: %v", err)
		}
		if len(resolved.attributionMaterials) != 1 {
			t.Fatalf("materials = %+v", resolved.attributionMaterials)
		}
		if _, ok := resolved.attributionMaterials["https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g"]; !ok {
			t.Fatalf("capture URI missing from %+v", resolved.attributionMaterials)
		}

		// A digest mismatch fails closed: different bytes never reach admission.
		manifest["captures"] = []map[string]string{{
			"source_uri": "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
			"path":       "capture.json",
			"sha256":     consumersDigest("other-bytes"),
		}}
		writeManifest(manifest)
		mismatched := analyzeOpts{attributionFile: manifestPath}
		if err := resolveAdvisorySources(context.Background(), &mismatched); err == nil {
			t.Fatal("a capture whose bytes do not match its digest must fail before analysis")
		}

		// The schema is closed: an unknown field is refused, never ignored.
		manifest["captures"] = []map[string]string{{
			"source_uri": "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
			"path":       "capture.json",
			"sha256":     "sha256:" + hex.EncodeToString(sum[:]),
		}}
		manifest["trusted_cve_mapping"] = "CVE-2023-44487"
		writeManifest(manifest)
		unknownField := analyzeOpts{attributionFile: manifestPath}
		if err := resolveAdvisorySources(context.Background(), &unknownField); err == nil {
			t.Fatal("an unknown manifest field must be refused")
		}
	})
}
