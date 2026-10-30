package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/finding"
)

// This file exercises the report/export cutover to the shared requested-finding
// projection. Every fixture is a genuine analysis-case/2 record: its profile
// result is produced by finding.Assess and its envelope by finding.Finalize, so
// finding.Project re-admits it rather than trusting a hand-written conclusion.

const (
	reportCVE           = "CVE-2023-44487"
	reportPrimaryRecord = "GHSA-qppj-fm5r-hxr3"
	reportChildRecord   = "GO-2023-2153"
	reportSecondRecord  = "GO-2023-2154"

	reportPrimaryCase = domain.CaseID("report-primary")
	reportChildCase   = domain.CaseID("report-child")
	reportSecondCase  = domain.CaseID("report-second")

	// reportPrimaryFixed is x/net's published fix. Nothing in a composed gRPC
	// answer may recommend it.
	reportPrimaryFixed = "v0.17.0"
	// reportChildFixed is gRPC's published fix: the witness-bound remediation.
	reportChildFixed = "v1.58.3"
)

func reportDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func reportPin(id string) domain.RecordPin {
	return domain.RecordPin{
		RecordID:       id,
		DocumentDigest: reportDigest(id),
		SourceLocator:  "corpus/" + id + ".json",
	}
}

func reportBuild() domain.BuildContext {
	return domain.BuildContext{
		Repository: "github.com/kubernetes/kubernetes",
		Commit:     "e196d24",
		GOOS:       "linux",
		GOARCH:     "amd64",
		GoVersion:  "go1.25.0",
	}
}

func reportProduct(build domain.BuildContext) domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: build.Repository,
		Commit:     build.Commit,
		GOOS:       build.GOOS,
		GOARCH:     build.GOARCH,
		GoVersion:  build.GoVersion,
	}
}

func reportScope(requestedID, module string, kind domain.AdvisoryScopeKind, coverage domain.AdvisoryCoverage) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID:  requestedID,
		ResolvedID:   requestedID,
		Kind:         kind,
		Coverage:     coverage,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         requestedID,
			DocumentDigest:     reportDigest(requestedID),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: module}},
			RepresentedRefs:    []int{0},
		},
	}
}

func reportAssess(c *domain.AnalysisCase, claims []domain.Claim) domain.AssessmentResult {
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
			RecordPin: c.RecordPin,
			AdvisoryRecord: c.AdvisoryRecord,
		},
		RootCause:    c.RootCause,
		AssessmentID: c.ID,
	})
}

func reportAddEvidence(c *domain.AnalysisCase, ids ...domain.EvidenceID) {
	for _, id := range ids {
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:      id,
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "report-test",
			Content: string(id),
		})
	}
}

func reportAttribution(id string, pin domain.RecordPin) domain.CVEAttribution {
	return domain.CVEAttribution{
		ID:                id,
		CVEID:             reportCVE,
		Candidate:         pin,
		EntryRefs:         []int{0},
		MechanismID:       "http2-rapid-reset",
		Basis:             domain.AttributionPublisher,
		SourceURI:         "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
		CapturedDigest:    reportDigest("captured-attribution"),
		SourceField:       "cve_ids[0]",
		SourceQuote:       reportCVE,
		PublisherAdvisory: "GHSA-m425-mq94-257g",
		Module:            "google.golang.org/grpc",
		Repository:        "github.com/grpc/grpc-go",
		FixRefs:           []string{"https://github.com/grpc/grpc-go/pull/6703"},
		Admission:         domain.AttributionAdmitted,
	}
}

// reportPositiveRecord builds one independently earned library-API positive for
// the gRPC record, with gRPC's own module, resolved version and published fix.
func reportPositiveRecord(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := reportBuild()
	pin := reportPin(reportChildRecord)
	claims := []domain.Claim{{
		ID:           "CL-C-API",
		ConditionID:  "C-API",
		Result:       domain.ClaimTrue,
		EvidenceIDs:  []domain.EvidenceID{"EV-API"},
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}}
	c := &domain.AnalysisCase{
		ID:          reportChildCase,
		RequestedID: reportChildRecord,
		Vulnerability: domain.Vulnerability{
			ID:            reportChildRecord,
			Module:        "google.golang.org/grpc",
			FixedVersions: []string{reportChildFixed},
			BaseSeverity:  "HIGH",
			BaseScore:     7.5,
			Scope:         reportScope(reportChildRecord, "google.golang.org/grpc", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   reportProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			ResolvedVersion: "v1.58.0",
		},
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-API", Kind: domain.ConditionInputConstraint, Mandatory: true,
		}}},
		Claims: claims,
	}
	reportAddEvidence(c, "EV-API")
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         reportAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize positive record: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// reportFailedPrimary builds the primary x/net record: it carries its own
// published fix, but its analysis never earned a verdict.
func reportFailedPrimary(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := reportBuild()
	pin := reportPin(reportPrimaryRecord)
	c := &domain.AnalysisCase{
		ID:          reportPrimaryCase,
		RequestedID: reportCVE,
		Vulnerability: domain.Vulnerability{
			ID:            reportPrimaryRecord,
			Module:        "golang.org/x/net",
			FixedVersions: []string{reportPrimaryFixed},
			BaseSeverity:  "CRITICAL",
			BaseScore:     9.8,
			Scope:         reportScope(reportCVE, "golang.org/x/net", domain.ScopeCVE, domain.CoverageKnownOnly),
		},
		RecordPin: &pin,
		Product:   reportProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v0.16.0",
		},
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         reportAssess(&domain.AnalysisCase{ID: reportPrimaryCase}, nil),
	}}
	return c
}

// reportComposedPositive builds the worked shape: the CVE request's primary
// record failed, and one independently attributed related gRPC record earned
// the positive.
func reportComposedPositive(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	root := reportFailedPrimary(t)
	child := reportPositiveRecord(t)
	childPin := reportPin(reportChildRecord)
	root.RelatedDiscovery = &domain.RelatedDiscovery{
		RequestedID: reportCVE,
		Enumeration: domain.DiscoveryPartial,
		Corpus: &domain.CorpusReference{
			Reference:  "osv-related-index",
			Digest:     reportDigest("related-index"),
			CapturedAt: "2026-10-20",
		},
		Candidates: []domain.DiscoveryCandidate{{
			Record:      childPin,
			Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: reportCVE}},
			Disposition: domain.DispositionEvaluated,
		}},
		Limitations: []string{"only the configured related index was enumerated"},
	}
	root.RelatedRecords = []domain.RelatedRecordAssessment{{ID: child.ID, Record: childPin, Analysis: child}}
	root.Attributions = []domain.CVEAttribution{reportAttribution("ATTR-GRPC", childPin)}
	if err := finding.Finalize(root); err != nil {
		t.Fatalf("finalize composed positive: %v", err)
	}
	root.Workflow.State = domain.StateCompleted
	return root
}

// reportNegativeChild builds one nominated candidate's own NOT_AFFECTED
// result. The absent variant proves component absence; the version variant
// proves the analyzed version is outside the affected range.
func reportNegativeChild(t *testing.T, id domain.CaseID, recordID string, absent bool) *domain.AnalysisCase {
	t.Helper()
	build := reportBuild()
	pin := reportPin(recordID)
	affected := &domain.AffectedResult{
		Scope:         reportScope(recordID, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		ModulePresent: domain.ClaimFalse,
	}
	if !absent {
		affected = &domain.AffectedResult{
			Scope:           reportScope(recordID, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimFalse,
			ResolvedVersion: "v0.15.0",
		}
	}
	c := &domain.AnalysisCase{
		ID:          id,
		RequestedID: recordID,
		Vulnerability: domain.Vulnerability{
			ID:     recordID,
			Module: "golang.org/x/net",
			Scope:  reportScope(recordID, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   reportProduct(build),
		Affected:  affected,
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         reportAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize negative record %q: %v", id, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// reportCorpusNegative builds a declared, digest-pinned, completely enumerated
// corpus whose every nominated candidate earned its own NOT_AFFECTED result.
func reportCorpusNegative(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	root := reportFailedPrimary(t)
	absent := reportNegativeChild(t, reportChildCase, reportChildRecord, true)
	present := reportNegativeChild(t, reportSecondCase, reportSecondRecord, false)
	absentPin := reportPin(reportChildRecord)
	presentPin := reportPin(reportSecondRecord)
	reference := "osv-dump-2026-10-20"
	digest := reportDigest("declared-corpus")
	root.CorpusDeclaration = &domain.CorpusDeclaration{
		Reference:      reference,
		ExpectedDigest: digest,
		CapturedAt:     "2026-10-20",
	}
	root.CorpusManifest = &domain.CorpusManifest{
		Reference:      reference,
		CapturedAt:     "2026-10-20",
		ObservedDigest: digest,
		Enumeration:    domain.DiscoveryFinished,
		Documents:      []domain.RecordPin{absentPin, presentPin},
		Sources: []domain.CorpusSource{{
			Ref: "https://osv.dev/dump", SHA256: reportDigest("corpus-source"), CheckedAt: "2026-10-20",
		}},
	}
	root.RelatedDiscovery = &domain.RelatedDiscovery{
		RequestedID: reportCVE,
		Enumeration: domain.DiscoveryFinished,
		Corpus:      &domain.CorpusReference{Reference: reference, Digest: digest, CapturedAt: "2026-10-20"},
		Candidates: []domain.DiscoveryCandidate{
			{
				Record:      absentPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: reportCVE}},
				Disposition: domain.DispositionEvaluated,
			},
			{
				Record:      presentPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationAlias, ID: reportCVE}},
				Disposition: domain.DispositionEvaluated,
			},
		},
	}
	root.RelatedRecords = []domain.RelatedRecordAssessment{
		{ID: absent.ID, Record: absentPin, Analysis: absent},
		{ID: present.ID, Record: presentPin, Analysis: present},
	}
	if err := finding.Finalize(root); err != nil {
		t.Fatalf("finalize corpus negative: %v", err)
	}
	root.Workflow.State = domain.StateCompleted
	return root
}

// reportExternalRequest builds an exact request whose decisive fact lies
// outside the artifact.
func reportExternalRequest(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := reportBuild()
	pin := reportPin(reportPrimaryRecord)
	c := &domain.AnalysisCase{
		ID:          reportPrimaryCase,
		RequestedID: reportPrimaryRecord,
		Vulnerability: domain.Vulnerability{
			ID:     reportPrimaryRecord,
			Module: "golang.org/x/net",
			Scope:  reportScope(reportPrimaryRecord, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   reportProduct(build),
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimUnknown,
			EvidenceIDs:     []domain.EvidenceID{"EV-VERSION"},
		},
	}
	reportAddEvidence(c, "EV-VERSION")
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         reportAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize external request: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// reportFailedRequest builds an exact request whose own analysis never earned a
// verdict.
func reportFailedRequest(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := reportBuild()
	pin := reportPin(reportPrimaryRecord)
	c := &domain.AnalysisCase{
		ID:          reportPrimaryCase,
		RequestedID: reportPrimaryRecord,
		Vulnerability: domain.Vulnerability{
			ID:     reportPrimaryRecord,
			Module: "golang.org/x/net",
			Scope:  reportScope(reportPrimaryRecord, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   reportProduct(build),
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         reportAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize failed request: %v", err)
	}
	c.Workflow.State = domain.StateFailed
	return c
}

// reportExactNegative builds an exact advisory request answered NOT_AFFECTED by
// the component's absence.
func reportExactNegative(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := reportBuild()
	pin := reportPin(reportPrimaryRecord)
	c := &domain.AnalysisCase{
		ID:          reportPrimaryCase,
		RequestedID: reportPrimaryRecord,
		Vulnerability: domain.Vulnerability{
			ID:     reportPrimaryRecord,
			Module: "golang.org/x/net",
			Scope:  reportScope(reportPrimaryRecord, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
		},
		RecordPin: &pin,
		Product:   reportProduct(build),
		Affected: &domain.AffectedResult{
			Scope:         reportScope(reportPrimaryRecord, "golang.org/x/net", domain.ScopeAdvisoryEntries, domain.CoverageComplete),
			ModulePresent: domain.ClaimFalse,
		},
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         reportAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize exact negative: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// reportExports decodes both export documents.
type reportExports struct {
	vex struct {
		Statements []struct {
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
			Vulnerability   struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Products []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID   string `json:"@id"`
					Name string `json:"name"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	cdx struct {
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
				Detail        string `json:"detail"`
			} `json:"analysis"`
			Recommendation string `json:"recommendation"`
		} `json:"vulnerabilities"`
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
	}
}

func reportDecodeExports(t *testing.T, c *domain.AnalysisCase) reportExports {
	t.Helper()
	var out reportExports
	vex, err := OpenVEX(c)
	if err != nil {
		t.Fatalf("openvex: %v", err)
	}
	if err := json.Unmarshal(vex, &out.vex); err != nil {
		t.Fatalf("invalid OpenVEX json: %v", err)
	}
	cdx, err := CycloneDX(c)
	if err != nil {
		t.Fatalf("cyclonedx: %v", err)
	}
	if err := json.Unmarshal(cdx, &out.cdx); err != nil {
		t.Fatalf("invalid CycloneDX json: %v", err)
	}
	return out
}

func (e reportExports) vexStatement(name string) (string, string, string, string) {
	for _, statement := range e.vex.Statements {
		if statement.Vulnerability.Name != name {
			continue
		}
		return statement.Status, statement.Justification, statement.ImpactStatement, statement.ActionStatement
	}
	return "", "", "", ""
}

// vexSubcomponentIDs returns the subcomponent identities nested under the
// named statement's products.
func (e reportExports) vexSubcomponentIDs(name string) []string {
	for _, statement := range e.vex.Statements {
		if statement.Vulnerability.Name != name {
			continue
		}
		var out []string
		for _, product := range statement.Products {
			for _, subcomponent := range product.Subcomponents {
				out = append(out, subcomponent.ID)
			}
		}
		return out
	}
	return nil
}

func (e reportExports) cdxVulnerability(id string) (string, string, string, bool) {
	state, justification, detail, _, ok := e.cdxEntry(id)
	return state, justification, detail, ok
}

func (e reportExports) cdxEntry(id string) (string, string, string, string, bool) {
	for _, vulnerability := range e.cdx.Vulnerabilities {
		if vulnerability.ID != id {
			continue
		}
		return vulnerability.Analysis.State, vulnerability.Analysis.Justification,
			vulnerability.Analysis.Detail, vulnerability.Recommendation, true
	}
	return "", "", "", "", false
}

func TestRequestedFindingReports(t *testing.T) {
	t.Run("a composed positive renders the requested identity and the witness", func(t *testing.T) {
		c := reportComposedPositive(t)
		en := Markdown(c, "en")
		ru := Markdown(c, "ru")
		exports := reportDecodeExports(t, c)

		for _, want := range []string{
			"# Vulnerability analysis: " + reportCVE,
			"## Requested finding: `DECIDED`",
			"`EXPLOITABLE`",
			"proven via related record `report-child`",
			"## Primary record: unchanged assessment",
			"### Candidate assessments",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN report is missing %q:\n%s", want, en)
			}
		}
		for _, want := range []string{
			"# Анализ уязвимости: " + reportCVE,
			"## Запрошенный результат: `DECIDED`",
			"доказано через связанную запись `report-child`",
		} {
			if !strings.Contains(ru, want) {
				t.Fatalf("RU report is missing %q:\n%s", want, ru)
			}
		}
		// Witness-bound remediation: gRPC's fix, never x/net's.
		if !strings.Contains(en, "google.golang.org/grpc") || !strings.Contains(en, reportChildFixed) {
			t.Fatalf("EN report does not recommend the gRPC fix:\n%s", en)
		}
		if strings.Contains(en, reportPrimaryFixed) || strings.Contains(ru, reportPrimaryFixed) {
			t.Fatalf("report recommends the primary record's fixed version %q:\n%s", reportPrimaryFixed, en)
		}
		// RU and EN carry the same claims.
		for _, want := range []string{reportCVE, reportChildRecord, reportChildFixed, "`EXPLOITABLE`"} {
			if !strings.Contains(ru, want) {
				t.Fatalf("RU report is missing the EN claim %q:\n%s", want, ru)
			}
		}
		if tracker := TrackerRationale(c); !strings.Contains(tracker, "`EXPLOITABLE`") && !strings.Contains(tracker, "эксплуатируем") {
			t.Fatalf("tracker rationale disagrees with the requested verdict:\n%s", tracker)
		}

		// Every written artifact agrees on the requested result.
		dir := t.TempDir()
		if err := Write(dir, c); err != nil {
			t.Fatalf("write report: %v", err)
		}
		for _, name := range []string{"report.json", "report.md", "report.en.md", "openvex.json", "cyclonedx.json"} {
			if _, err := os.ReadFile(filepath.Join(dir, name)); err != nil {
				t.Fatalf("missing artifact %s: %v", name, err)
			}
		}
		rawReport, err := os.ReadFile(filepath.Join(dir, "report.json"))
		if err != nil {
			t.Fatalf("read report.json: %v", err)
		}
		var persisted struct {
			Schema           string `json:"schema"`
			RequestedFinding struct {
				RequestedID string `json:"requested_id"`
				Outcome     string `json:"assessment_outcome"`
				Verdict     string `json:"verdict"`
			} `json:"requested_finding"`
		}
		if err := json.Unmarshal(rawReport, &persisted); err != nil {
			t.Fatalf("invalid report.json: %v", err)
		}
		if persisted.Schema != string(domain.CaseSchemaV2) ||
			persisted.RequestedFinding.RequestedID != reportCVE ||
			persisted.RequestedFinding.Outcome != string(domain.OutcomeDecided) ||
			persisted.RequestedFinding.Verdict != string(domain.VerdictExploitable) {
			t.Fatalf("report.json companion disagrees: %+v", persisted)
		}

		if len(exports.vex.Statements) != 3 {
			t.Fatalf("openvex statements = %d, want the requested CVE, the primary record and the candidate record",
				len(exports.vex.Statements))
		}
		status, _, impact, action := exports.vexStatement(reportCVE)
		if status != "affected" {
			t.Fatalf("requested statement status = %q, want affected", status)
		}
		if !strings.Contains(action, reportChildFixed) || strings.Contains(action, reportPrimaryFixed) {
			t.Fatalf("requested action is not witness-bound: %q", action)
		}
		for _, want := range []string{"library-api", "proven via related record `report-child`", "publisher advisory GHSA-m425-mq94-257g"} {
			if !strings.Contains(impact, want) {
				t.Fatalf("requested impact statement is missing %q: %q", want, impact)
			}
		}
		if status, _, _, _ := exports.vexStatement(reportChildRecord); status != "affected" {
			t.Fatalf("candidate statement status = %q, want affected", status)
		}
		if status, _, _, _ := exports.vexStatement(reportPrimaryRecord); status != "under_investigation" {
			t.Fatalf("primary statement status = %q, want its own failed assessment", status)
		}
		state, _, detail, recommendation, ok := exports.cdxEntry(reportCVE)
		if !ok || state != "exploitable" {
			t.Fatalf("requested cycloneDX entry = %q/%v", state, ok)
		}
		if !strings.Contains(recommendation, reportChildFixed) || strings.Contains(recommendation, reportPrimaryFixed) {
			t.Fatalf("requested cycloneDX recommendation is not witness-bound: %q", recommendation)
		}
		if !strings.Contains(detail, "publisher advisory GHSA-m425-mq94-257g") {
			t.Fatalf("requested cycloneDX detail carries no source attribution: %q", detail)
		}
	})

	t.Run("a corpus negative states its boundary and does not claim absence", func(t *testing.T) {
		c := reportCorpusNegative(t)
		en := Markdown(c, "en")
		exports := reportDecodeExports(t, c)

		for _, want := range []string{
			"## Requested finding: `DECIDED`",
			"`NOT_AFFECTED`",
			"### Corpus negative basis (Addendum A)",
			"osv-dump-2026-10-20",
			reportDigest("declared-corpus"),
			"2026-10-20",
			"implementations outside this corpus were not examined",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN report is missing %q:\n%s", want, en)
			}
		}
		status, justification, impact, _ := exports.vexStatement(reportCVE)
		if status != "not_affected" {
			t.Fatalf("requested statement status = %q, want not_affected", status)
		}
		// One candidate proved component absence, the other proved a version
		// exclusion: both are absence proofs, so the aggregate is vulnerable
		// code absence — never component absence and never an invented
		// reachability claim.
		if justification != "vulnerable_code_not_present" {
			t.Fatalf("justification = %q, want vulnerable_code_not_present", justification)
		}
		if !strings.Contains(impact, "implementations outside this corpus were not examined") {
			t.Fatalf("impact statement does not carry the corpus boundary: %q", impact)
		}
		// The candidate that proved component absence must not be named as a
		// subcomponent; the version-exclusion candidate still names its
		// component with the resolved version.
		subcomponents := exports.vexSubcomponentIDs(reportCVE)
		sawVersioned := false
		for _, subcomponent := range subcomponents {
			if subcomponent == "pkg:golang/golang.org/x/net" {
				t.Fatalf("corpus statement names the absent component: %v", subcomponents)
			}
			if subcomponent == "pkg:golang/golang.org/x/net@v0.15.0" {
				sawVersioned = true
			}
		}
		if !sawVersioned {
			t.Fatalf("corpus statement lost the present component: %v", subcomponents)
		}
		state, cdxJust, detail, ok := exports.cdxVulnerability(reportCVE)
		if !ok || state != "not_affected" || cdxJust != "code_not_present" {
			t.Fatalf("requested cycloneDX entry = %q/%q/%v", state, cdxJust, ok)
		}
		if !strings.Contains(detail, "implementations outside this corpus were not examined") {
			t.Fatalf("cycloneDX detail does not carry the corpus boundary: %q", detail)
		}
	})

	t.Run("an external dependency is not a failure", func(t *testing.T) {
		c := reportExternalRequest(t)
		en := Markdown(c, "en")
		exports := reportDecodeExports(t, c)

		for _, want := range []string{
			"## Requested finding: `EXTERNAL_DEPENDENCY`",
			"`INCONCLUSIVE`",
			"### External dependencies (EXTERNAL_DEPENDENCY)",
			"Missing fact",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN report is missing %q:\n%s", want, en)
			}
		}
		if strings.Contains(en, "## Verdict: `NOT_AFFECTED`") {
			t.Fatalf("external dependency rendered a safe verdict:\n%s", en)
		}
		status, _, _, action := exports.vexStatement(reportPrimaryRecord)
		if status != "under_investigation" {
			t.Fatalf("statement status = %q, want under_investigation", status)
		}
		if !strings.Contains(action, "external_dependency:") {
			t.Fatalf("action does not distinguish the external dependency: %q", action)
		}
		state, _, detail, ok := exports.cdxVulnerability(reportPrimaryRecord)
		if !ok || state != "in_triage" {
			t.Fatalf("cycloneDX entry = %q/%v", state, ok)
		}
		if !strings.Contains(detail, "external_dependency:") || strings.Contains(detail, "analysis_failed:") {
			t.Fatalf("cycloneDX detail does not distinguish the external dependency: %q", detail)
		}
	})

	t.Run("a failure publishes diagnostics and no verdict", func(t *testing.T) {
		c := reportFailedRequest(t)
		en := Markdown(c, "en")
		ru := Markdown(c, "ru")
		exports := reportDecodeExports(t, c)

		for _, want := range []string{
			"## Requested finding: `FAILED`",
			"no verdict was earned",
			"### Analysis failure diagnostics (FAILED)",
		} {
			if !strings.Contains(en, want) {
				t.Fatalf("EN report is missing %q:\n%s", want, en)
			}
		}
		if !strings.Contains(ru, "## Запрошенный результат: `FAILED`") {
			t.Fatalf("RU report does not state the failure:\n%s", ru)
		}
		if strings.Contains(en, "## Verdict:") || strings.Contains(en, "P0") || strings.Contains(en, "DISMISSED") {
			t.Fatalf("a failed result rendered a verdict or a triage disposition:\n%s", en)
		}
		status, _, _, action := exports.vexStatement(reportPrimaryRecord)
		if status != "under_investigation" {
			t.Fatalf("statement status = %q, want under_investigation", status)
		}
		if !strings.Contains(action, "analysis_failed:") {
			t.Fatalf("action does not distinguish the failure: %q", action)
		}
		state, _, detail, ok := exports.cdxVulnerability(reportPrimaryRecord)
		if !ok || state != "in_triage" {
			t.Fatalf("cycloneDX entry = %q/%v", state, ok)
		}
		if !strings.Contains(detail, "analysis_failed:") || strings.Contains(detail, "external_dependency:") {
			t.Fatalf("cycloneDX detail does not distinguish the failure: %q", detail)
		}
		if tracker := TrackerRationale(c); strings.Contains(tracker, "DISMISSED") {
			t.Fatalf("tracker rationale carries a dismissed disposition: %q", tracker)
		}
		dir := t.TempDir()
		if err := Write(dir, c); err != nil {
			t.Fatalf("a failed analysis wrote no diagnostic report: %v", err)
		}
		rawReport, err := os.ReadFile(filepath.Join(dir, "report.json"))
		if err != nil {
			t.Fatalf("read diagnostic report.json: %v", err)
		}
		var persisted struct {
			RequestedFinding struct {
				Outcome string `json:"assessment_outcome"`
				Verdict string `json:"verdict"`
			} `json:"requested_finding"`
		}
		if err := json.Unmarshal(rawReport, &persisted); err != nil {
			t.Fatalf("invalid diagnostic report.json: %v", err)
		}
		if persisted.RequestedFinding.Outcome != string(domain.OutcomeFailed) ||
			persisted.RequestedFinding.Verdict != "" {
			t.Fatalf("diagnostic report.json = %+v, want a verdict-less FAILED outcome", persisted.RequestedFinding)
		}
	})

	t.Run("a tampered proof is refused, not re-projected", func(t *testing.T) {
		c := reportComposedPositive(t)
		child := c.RelatedRecords[0].Analysis
		child.ProfileAssessments[0].Claims[0].Result = domain.ClaimUnknown

		en := Markdown(c, "en")
		if !strings.Contains(en, "# Publication refused:") || !strings.Contains(en, "## Refusal reason") {
			t.Fatalf("refused case rendered a conclusion:\n%s", en)
		}
		if strings.Contains(en, "## Requested finding:") || strings.Contains(en, `"EXPLOITABLE"`) {
			t.Fatalf("refused case published a requested finding:\n%s", en)
		}
		vexErr, cdxErr := error(nil), error(nil)
		_, vexErr = OpenVEX(c)
		_, cdxErr = CycloneDX(c)
		for name, err := range map[string]error{"openvex": vexErr, "cyclonedx": cdxErr} {
			if err == nil {
				t.Fatalf("%s exported a tampered proof", name)
			}
			if errors.Is(err, finding.ErrLegacyCase) {
				t.Fatalf("%s refused the case as legacy instead of as a tampered proof: %v", name, err)
			}
			if errors.Is(err, finding.ErrPolicyDrift) {
				continue
			}
			var drift *finding.PolicyDriftError
			if errors.As(err, &drift) {
				continue
			}
			if !strings.Contains(err.Error(), "not supported by the current record assessment") {
				t.Fatalf("%s err = %v, want a re-admission refusal", name, err)
			}
		}
		if err := Write(t.TempDir(), c); err == nil {
			t.Fatal("Write published a drifted conclusion")
		}
		if _, err := FixTargets(c); err == nil {
			t.Fatal("FixTargets published a target for a drifted conclusion")
		}
	})

	t.Run("an exact request keeps its single record result", func(t *testing.T) {
		c := reportExactNegative(t)
		en := Markdown(c, "en")
		exports := reportDecodeExports(t, c)

		if !strings.Contains(en, "## Requested finding: `DECIDED`") || !strings.Contains(en, "`NOT_AFFECTED`") {
			t.Fatalf("EN report is missing the requested negative:\n%s", en)
		}
		if strings.Contains(en, "implementations outside this corpus were not examined") {
			t.Fatalf("an exact request carried a corpus boundary it never declared:\n%s", en)
		}
		if strings.Contains(en, "### Candidate assessments") {
			t.Fatalf("an exact request rendered a candidate table:\n%s", en)
		}
		if len(exports.vex.Statements) != 1 {
			t.Fatalf("statements = %d, want one deduplicated identity", len(exports.vex.Statements))
		}
		status, justification, _, _ := exports.vexStatement(reportPrimaryRecord)
		if status != "not_affected" || justification != "component_not_present" {
			t.Fatalf("statement = %q/%q", status, justification)
		}
		state, cdxJust, _, ok := exports.cdxVulnerability(reportPrimaryRecord)
		if !ok || state != "not_affected" || cdxJust != "code_not_present" {
			t.Fatalf("cycloneDX entry = %q/%q/%v", state, cdxJust, ok)
		}
	})
}

func TestWitnessRemediation(t *testing.T) {
	c := reportComposedPositive(t)
	targets, err := FixTargets(c)
	if err != nil {
		t.Fatalf("fix targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %+v, want exactly the gRPC witness", targets)
	}
	target := targets[0]
	if target.Module != "google.golang.org/grpc" ||
		target.ResolvedVersion != "v1.58.0" || target.FixedVersion != reportChildFixed {
		t.Fatalf("target = %+v", target)
	}
	if target.Origin.AssessmentID != reportChildCase {
		t.Fatalf("target origin = %q, want the witness record", target.Origin.AssessmentID)
	}
	if target.FixedVersion == reportPrimaryFixed || target.Module == "golang.org/x/net" {
		t.Fatalf("target adopted the primary record's fix: %+v", target)
	}

	// The witness-bound section names the record that earned the answer and
	// the primary record's fix never appears anywhere in the report.
	for _, lang := range []string{"en", "ru"} {
		report := Markdown(c, lang)
		if !strings.Contains(report, "## ") || !strings.Contains(report, reportChildFixed) {
			t.Fatalf("%s report does not carry the witness fix:\n%s", lang, report)
		}
		if strings.Contains(report, reportPrimaryFixed) {
			t.Fatalf("%s report carries the primary record's fix %q", lang, reportPrimaryFixed)
		}
	}
	en := Markdown(c, "en")
	if !strings.Contains(en, "### Witness-bound remediation and severity") {
		t.Fatalf("report does not separate witness remediation:\n%s", en)
	}
	if !strings.Contains(en, "Severity of witness assessment `report-child`") {
		t.Fatalf("report does not attribute severity to the witness record:\n%s", en)
	}
	if !strings.Contains(en, "Request priority:") || !strings.Contains(en, "`report-child`") {
		t.Fatalf("request-level priority does not name the assessment it summarizes:\n%s", en)
	}

	// The tracker rationale carries the same witness-bound target.
	if tracker := TrackerRationale(c); !strings.Contains(tracker, reportChildFixed) ||
		strings.Contains(tracker, reportPrimaryFixed) {
		t.Fatalf("tracker rationale is not witness-bound:\n%s", tracker)
	}

	// An exact single-record request keeps FixTarget available for the one
	// assessment it explicitly names.
	exact := reportPositiveRecord(t)
	module, fixed, ok := FixTarget(exact)
	if !ok || module != "google.golang.org/grpc" || fixed != reportChildFixed {
		t.Fatalf("single-assessment target = %q/%q/%v", module, fixed, ok)
	}
}
