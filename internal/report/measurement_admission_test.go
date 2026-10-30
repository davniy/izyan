package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// ---------- admission fixtures ----------

const admissionInventoryStream = `{"ImportPath":"example.com/prod","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Name":"vuln","DepOnly":true,"Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`

const admissionGovConfig = `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n"

func admissionTarget() *domain.ProductTarget {
	return &domain.ProductTarget{
		GOOS:            "linux",
		GOARCH:          "amd64",
		BuildTags:       []string{"netgo"},
		CGOEnabled:      false,
		Source:          domain.ProductTargetSourceArtifactBuildInfo,
		Scope:           domain.ProductTargetScopeArtifact,
		ArtifactSHA256:  strings.Repeat("a", 64),
		BuildInfoSHA256: strings.Repeat("b", 64),
	}
}

func admissionScopedProduct() domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: "example.com/prod",
		Commit:     "abc123",
		GoVersion:  "go1.24.0",
		GOOS:       "linux",
		GOARCH:     "amd64",
		BuildTags:  []string{"netgo"},
		Target:     admissionTarget(),
	}
}

func admissionHostDefaultProduct() domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: "example.com/prod",
		Commit:     "abc123",
		GoVersion:  "go1.24.0",
		GOOS:       "linux",
		GOARCH:     "amd64",
		BuildTags:  []string{"netgo"},
	}
}

func admissionContext(p domain.ProductSnapshot) *domain.BuildContext {
	ctx := domain.EffectiveBuildContext(p)
	return &ctx
}

func admissionTargetNoTags() *domain.ProductTarget {
	t := admissionTarget()
	t.BuildTags = nil
	return t
}

func admissionInventoryEvidence(p domain.ProductSnapshot, id, content string) domain.Evidence {
	ctx := domain.EffectiveBuildContext(p)
	return domain.Evidence{
		ID:           domain.EvidenceID(id),
		Kind:         domain.EvidencePackageList,
		Content:      content,
		Command:      "go list -deps -test -json ./...",
		BuildContext: &ctx,
		PackageList: &domain.PackageListRun{
			Completed: true,
			Complete:  true,
			WithTests: true,
			Pattern:   "./...",
		},
	}
}

// withReportBuildAdmission gives a fixture an admitted product target and a
// complete package inventory matching it, and stamps the claim
// verifications with the same build context. It exists only to keep
// report fixtures inside the post-admission regime.
func withReportBuildAdmission(c *domain.AnalysisCase, inventory string) {
	c.Product.Target = admissionTargetNoTags()
	ctx := domain.EffectiveBuildContext(c.Product)
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		admissionInventoryEvidence(c.Product, "EV-PKG-LIST", inventory))
	for i := range c.Claims {
		if c.Claims[i].NegativeVerification != nil {
			c.Claims[i].NegativeVerification.BuildContext = &ctx
		}
	}
}

func admissionPackageList(p domain.ProductSnapshot) domain.Evidence {
	ctx := domain.EffectiveBuildContext(p)
	return domain.Evidence{
		ID:           "EV-PKG-LIST",
		Kind:         domain.EvidencePackageList,
		Content:      admissionInventoryStream,
		Command:      "go list -deps -test -json ./...",
		BuildContext: &ctx,
		PackageList: &domain.PackageListRun{
			Completed: true,
			Complete:  true,
			WithTests: true,
			Pattern:   "./...",
		},
	}
}

func admissionGovEvidence(id string, outcome domain.GovulncheckOutcome, ctx *domain.BuildContext, coverage domain.GovulncheckCoverage) domain.Evidence {
	return domain.Evidence{
		ID:           domain.EvidenceID(id),
		Kind:         domain.EvidenceGovulncheck,
		Tool:         "govulncheck",
		Content:      admissionGovConfig,
		BuildContext: ctx,
		Govulncheck: &domain.GovulncheckRun{
			Outcome:  outcome,
			Coverage: coverage,
		},
	}
}

func admissionSourceScan(ctx *domain.BuildContext) domain.Evidence {
	return domain.Evidence{
		ID:           "EV-SCAN-1",
		Kind:         domain.EvidenceSourceScan,
		BuildContext: ctx,
		SourceScan: &domain.SourceScanRun{
			Module:    "example.com/dep",
			Subjects:  []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
			Completed: true,
			Complete:  true,
		},
	}
}

// admissionGovulncheckRun returns a completed govulncheck measurement bound
// to ctx. A persisted no-module-usage negative additionally requires an
// applicable completed run: the live evaluator only emits that falsifier
// from a completed run, so replay must not admit one without it.
func admissionGovulncheckRun(ctx *domain.BuildContext) domain.Evidence {
	return domain.Evidence{
		ID:           "EV-GOVULN-1",
		Kind:         domain.EvidenceGovulncheck,
		BuildContext: ctx,
		Govulncheck: &domain.GovulncheckRun{
			Outcome:  domain.GovulncheckCompletedEmpty,
			Pattern:  "./...",
			Mode:     "source",
			Coverage: domain.GovulncheckCoverage{AdvisoryID: "GO-TEST-1", Advisory: domain.GovulncheckCoverageCovered, ScopeComplete: true},
		},
	}
}

func admissionClaim(falsifier string, verification *domain.NegativeVerification, evidenceIDs ...string) domain.Claim {
	cl := domain.Claim{
		ID:          "CL-C-REACH",
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   falsifier,
	}
	for _, id := range evidenceIDs {
		cl.EvidenceIDs = append(cl.EvidenceIDs, domain.EvidenceID(id))
	}
	cl.NegativeVerification = verification
	return cl
}

func verifiedAdmission(falsifier string, ctx *domain.BuildContext, evidenceIDs ...string) domain.Claim {
	return admissionClaim(falsifier, &domain.NegativeVerification{
		Status:       domain.NegativeVerified,
		BuildContext: ctx,
		Notes:        "measurement admitted in fixture",
	}, evidenceIDs...)
}

func admissionCase(product domain.ProductSnapshot, verdict domain.Verdict, cl domain.Claim, evidence ...domain.Evidence) *domain.AnalysisCase {
	c := &domain.AnalysisCase{
		ID: "case-admission",
		Vulnerability: domain.Vulnerability{
			ID:               "GO-2024-0001",
			Module:           "example.com/dep",
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
		},
		Product: product,
		Affected: &domain.AffectedResult{
			Scope:           exactEntryScope("GO-2024-0001"),
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID:       "C-REACH",
				Kind:     domain.ConditionSymbolReachable,
				Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
			}},
		},
		Claims:  []domain.Claim{cl},
		Verdict: &domain.VerdictResult{Verdict: verdict, Reason: "verified negative", ConditionIDs: []domain.ConditionID{"C-REACH"}},
	}
	c.EvidenceGraph.Evidence = evidence
	return c
}

func admissionNotAffected(product domain.ProductSnapshot) *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: "case-admission-na",
		Vulnerability: domain.Vulnerability{
			ID:               "GO-2024-0001",
			Module:           "example.com/dep",
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
		},
		Product: product,
		Affected: &domain.AffectedResult{
			Scope:           exactEntryScope("GO-2024-0001"),
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v0.9.0",
			VersionAffected: domain.ClaimFalse,
		},
		Verdict: &domain.VerdictResult{Verdict: domain.VerdictNotAffected, Reason: "resolved version outside affected range"},
	}
}

func admissionVex(t *testing.T, c *domain.AnalysisCase) (status, justification, text string) {
	t.Helper()
	doc := decodeVex(t, c)
	st := doc.Statements[0]
	return st.Status, st.Justification, st.ImpactStatement + " " + st.ActionStatement
}

func admissionCDX(t *testing.T, c *domain.AnalysisCase) (state, justification, detail string) {
	t.Helper()
	b, err := CycloneDX(c)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
				Detail        string `json:"detail"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid CycloneDX json: %v", err)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities=%d want 1", len(doc.Vulnerabilities))
	}
	a := doc.Vulnerabilities[0].Analysis
	return a.State, a.Justification, a.Detail
}

func admissionNoCleanClaim(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	for _, md := range []string{Markdown(c, "ru"), Markdown(c, "en")} {
		for _, forbidden := range []string{
			"Clean (No call path found)",
			"Трасса вызовов не обнаружена (Clean)",
			"Трасса вызовов от кода продукта не обнаружена (чисто)",
			"No call path from product code found (clean)",
			"Not reachable",
			"🟢 Не достижим",
		} {
			if strings.Contains(md, forbidden) {
				t.Fatalf("report renders refused measurement as clean (%q):\n%s", forbidden, md)
			}
		}
	}
}

// ---------- direct-export replay matrix ----------

func TestMeasurementAdmissionRefusesHostDefaultTarget(t *testing.T) {
	product := admissionHostDefaultProduct()
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierNoModuleUsage, admissionContext(product)),
		admissionSourceScan(admissionContext(product)))

	if status, _, _ := admissionVex(t, c); status != "under_investigation" {
		t.Fatalf("OpenVEX status=%q, want under_investigation for host-default target", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "in_triage" {
		t.Fatalf("CycloneDX state=%q, want in_triage for host-default target", state)
	}
	admissionNoCleanClaim(t, c)
	if !strings.Contains(Markdown(c, "en"), "negative conclusion refused") {
		t.Fatalf("Markdown does not state the refusal:\n%s", Markdown(c, "en"))
	}
}

func TestMeasurementAdmissionRefusesFailedRun(t *testing.T) {
	product := admissionScopedProduct()
	cov := domain.GovulncheckCoverage{
		AdvisoryID:    "GO-2024-0001",
		Advisory:      domain.GovulncheckCoverageCovered,
		Subjects:      []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
		ScopeComplete: true,
	}
	ev := admissionGovEvidence("EV-GV", domain.GovulncheckFailed, admissionContext(product), cov)
	ev.Govulncheck.Error = "exit status 1"
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierGovulncheckSilence, admissionContext(product), "EV-GV"), ev)

	if status, _, _ := admissionVex(t, c); status != "under_investigation" {
		t.Fatalf("OpenVEX status=%q, want under_investigation for failed run", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "in_triage" {
		t.Fatalf("CycloneDX state=%q, want in_triage for failed run", state)
	}
	admissionNoCleanClaim(t, c)
	md := Markdown(c, "en")
	if !strings.Contains(md, "Reachability not measured") {
		t.Fatalf("failed run does not render as unmeasured:\n%s", md)
	}
}

func TestMeasurementAdmissionRefusesMissingSubjectCoverage(t *testing.T) {
	product := admissionScopedProduct()
	cov := domain.GovulncheckCoverage{
		AdvisoryID:    "GO-2024-0001",
		Advisory:      domain.GovulncheckCoverageCovered,
		Subjects:      []domain.SymbolRef{{Package: "example.com/other", Symbol: "Elsewhere"}},
		ScopeComplete: true,
	}
	ev := admissionGovEvidence("EV-GV", domain.GovulncheckCompletedEmpty, admissionContext(product), cov)
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierGovulncheckSilence, admissionContext(product), "EV-GV"), ev)

	if status, _, _ := admissionVex(t, c); status != "under_investigation" {
		t.Fatalf("OpenVEX status=%q, want under_investigation for missing subject coverage", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "in_triage" {
		t.Fatalf("CycloneDX state=%q, want in_triage for missing subject coverage", state)
	}
}

func TestMeasurementAdmissionRefusesContextMismatch(t *testing.T) {
	product := admissionScopedProduct()
	other := product
	other.BuildTags = []string{"other-tag"}
	mismatched := admissionContext(other)
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierNoModuleUsage, admissionContext(product)),
		admissionSourceScan(mismatched))

	if status, _, _ := admissionVex(t, c); status != "under_investigation" {
		t.Fatalf("OpenVEX status=%q, want under_investigation for context mismatch", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "in_triage" {
		t.Fatalf("CycloneDX state=%q, want in_triage for context mismatch", state)
	}
}

func TestMeasurementAdmissionRefusesLegacyVerifiedWithoutContext(t *testing.T) {
	product := admissionScopedProduct()
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierNoModuleUsage, nil),
		admissionSourceScan(admissionContext(product)))

	if status, _, _ := admissionVex(t, c); status != "under_investigation" {
		t.Fatalf("OpenVEX status=%q, want under_investigation for verification without context", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "in_triage" {
		t.Fatalf("CycloneDX state=%q, want in_triage for verification without context", state)
	}
}

func TestMeasurementAdmissionAdmitsIndependentVersionNegative(t *testing.T) {
	c := admissionNotAffected(admissionHostDefaultProduct())
	if status, _, _ := admissionVex(t, c); status != "not_affected" {
		t.Fatalf("OpenVEX status=%q, want independent version negative to stay not_affected", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "not_affected" {
		t.Fatalf("CycloneDX state=%q, want independent version negative to stay not_affected", state)
	}
}

func TestMeasurementAdmissionAdmitsIndependentDeploymentNegative(t *testing.T) {
	product := admissionHostDefaultProduct()
	cl := admissionClaim(domain.FalsifierTrustedInfrastructure, &domain.NegativeVerification{Status: domain.NegativeVerified})
	cl.FalsifierBasis = domain.BasisDeclaredTrust
	cl.ConditionID = "C-PEER-INPUT"
	c := admissionCase(product, domain.VerdictNoExploitPathFound, cl)
	c.Exploit.MandatoryConditions = []domain.Condition{{
		ID: "C-PEER-INPUT", Kind: "input", Description: "peer input controlled",
	}}
	c.Verdict.ConditionIDs = []domain.ConditionID{"C-PEER-INPUT"}

	if status, _, _ := admissionVex(t, c); status != "not_affected" {
		t.Fatalf("OpenVEX status=%q, want deployment-trust negative to stay not_affected", status)
	}
	if state, _, _ := admissionCDX(t, c); state != "not_affected" {
		t.Fatalf("CycloneDX state=%q, want deployment-trust negative to stay not_affected", state)
	}
}

func TestMeasurementAdmissionAdmitsScopedBuildNegative(t *testing.T) {
	product := admissionScopedProduct()
	ctx := admissionContext(product)
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierNoModuleUsage, ctx),
		admissionSourceScan(ctx), admissionPackageList(product), admissionGovulncheckRun(ctx))

	status, _, vexText := admissionVex(t, c)
	if status != "not_affected" {
		t.Fatalf("OpenVEX status=%q, want not_affected for an admitted scoped build negative", status)
	}
	state, _, cdxText := admissionCDX(t, c)
	if state != "not_affected" {
		t.Fatalf("CycloneDX state=%q, want not_affected for an admitted scoped build negative", state)
	}
	for _, want := range []string{
		"platform linux/amd64",
		"build tags: netgo",
		"CGO_ENABLED=0",
		"target provenance: artifact-build-info",
		"does not assert that every supported",
	} {
		if !strings.Contains(vexText, want) {
			t.Errorf("OpenVEX explanation lacks %q: %q", want, vexText)
		}
		if !strings.Contains(cdxText, want) {
			t.Errorf("CycloneDX explanation lacks %q: %q", want, cdxText)
		}
	}
	if !strings.Contains(Markdown(c, "en"), "only the analyzed build") {
		t.Fatalf("human report lacks the build scope statement:\n%s", Markdown(c, "en"))
	}
}

func TestMeasurementAdmissionEvidenceDetailNeverInventsCallPath(t *testing.T) {
	product := admissionScopedProduct()
	pkgFinding := admissionGovConfig + `{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/dep","package":"example.com/dep/vuln"}]}}`
	ev := admissionGovEvidence("EV-GV-PKG", domain.GovulncheckCompletedWithResults, admissionContext(product),
		domain.GovulncheckCoverage{AdvisoryID: "GO-2024-0001", Advisory: domain.GovulncheckCoverageCovered, ScopeComplete: true})
	ev.Content = pkgFinding
	c := admissionCase(product, domain.VerdictNotAffected, domain.Claim{}, ev)

	detail := formatEvidenceDetail(ev, c, false)
	if strings.Contains(detail, "Call path") || strings.Contains(detail, "Трасса вызова") {
		t.Fatalf("package-level govulncheck detail invented a call path: %q", detail)
	}
	if !strings.Contains(detail, "package-level finding only") {
		t.Fatalf("package-level detail = %q, want package-level wording", detail)
	}

	failed := admissionGovEvidence("EV-GV-FAILED", domain.GovulncheckFailed, admissionContext(product),
		domain.GovulncheckCoverage{AdvisoryID: "GO-2024-0001", Advisory: domain.GovulncheckCoverageUnknown})
	failed.Content = pkgFinding
	failed.Govulncheck.Error = "exit status 1"
	detail = formatEvidenceDetail(failed, c, false)
	if strings.Contains(detail, "Call path") {
		t.Fatalf("failed govulncheck record rendered as a call path: %q", detail)
	}
	if !strings.Contains(detail, "no reachability measurement") {
		t.Fatalf("failed detail = %q, want no-reachability-measurement wording", detail)
	}
}

func TestMeasurementAdmissionWritePersistsProjectedConclusions(t *testing.T) {
	product := admissionHostDefaultProduct()
	c := admissionCase(product, domain.VerdictNoExploitPathFound,
		verifiedAdmission(domain.FalsifierNoModuleUsage, admissionContext(product)),
		admissionSourceScan(admissionContext(product)))

	dir := t.TempDir()
	if err := Write(dir, c); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var written domain.AnalysisCase
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatalf("report.json decode: %v", err)
	}
	if written.Verdict == nil || written.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("persisted verdict = %+v, want INCONCLUSIVE", written.Verdict)
	}
	if len(written.Claims) != 1 || written.Claims[0].Result != domain.ClaimUnknown {
		t.Fatalf("persisted claim = %+v, want UNKNOWN", written.Claims)
	}
	if written.Claims[0].NegativeVerification == nil ||
		written.Claims[0].NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("historical verification record was not preserved: %+v", written.Claims[0].NegativeVerification)
	}
	if !strings.Contains(strings.Join(written.EvidenceGraph.Limitations, "\n"), "negative verification for C-REACH refused") {
		t.Fatalf("persisted case lacks the refusal limitation: %v", written.EvidenceGraph.Limitations)
	}

	// The original case stays historical: direct exports project, they do
	// not rewrite the record.
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("Write mutated the historical case verdict: %+v", c.Verdict)
	}
	if c.Claims[0].Result != domain.ClaimFalse {
		t.Fatalf("Write mutated the historical claim result: %+v", c.Claims[0])
	}
}

// TestProjectedMeasurementAdmission pins the single-admission property on the
// publication surfaces: a saved negative whose measurement or advisory
// completeness no longer admits it is refused by finding.Project, so no report,
// VEX document or artifact publishes a demoted conclusion as a clean negative.
func TestProjectedMeasurementAdmission(t *testing.T) {
	c := reportExactNegative(t)
	// The advisory record is now only partially represented, so its
	// component-absence fact cannot close the requested advisory.
	c.Affected.Scope = reportScope(reportPrimaryRecord, "golang.org/x/net",
		domain.ScopeAdvisoryEntries, domain.CoverageKnownOnly)
	// The persisted result still claims the clean negative: exactly the
	// historical conclusion current admission no longer supports.
	c.ProfileAssessments[0].Result = domain.AssessmentResult{
		Outcome: domain.OutcomeDecided,
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNotAffected,
			Reason:  "module is not in the dependency graph",
		},
	}

	en := Markdown(c, "en")
	if !strings.Contains(en, "# Publication refused:") {
		t.Fatalf("a refused negative was published:\n%s", en)
	}
	if strings.Contains(en, "`NOT_AFFECTED`") || strings.Contains(en, "## Requested finding:") {
		t.Fatalf("a refused negative published a requested verdict:\n%s", en)
	}
	if _, err := OpenVEX(c); err == nil {
		t.Fatal("openvex published a refused negative")
	}
	if _, err := CycloneDX(c); err == nil {
		t.Fatal("cyclonedx published a refused negative")
	}
	dir := t.TempDir()
	if err := Write(dir, c); err == nil {
		t.Fatal("Write published a refused negative")
	}
}

func TestUnreachabilityReplayPublicationRequiresKernel(t *testing.T) {
	for _, name := range []string{"valid", "summary-only", "missing-inventory", "foreign-inventory", "malformed-inventory", "open-gate", "uncited"} {
		t.Run(name, func(t *testing.T) {
			product := admissionScopedProduct()
			build := domain.EffectiveBuildContext(product)
			result := goanalysis.UnreachabilityResult{Module:"example.com/dep", Subjects:[]goanalysis.UnreachabilitySubject{{Package:"example.com/dep/vuln",Symbol:"Sink"}}, Build:build,
				Inventory:affected.RecordPackageInventory([]byte(admissionInventoryStream),nil,product,false), ProductPackages:[]string{"example.com/prod"}, Complete:true,DeclarationComplete:true,EntrypointComplete:true,ModuleEntryComplete:true,ModuleReachComplete:true}
			switch name {
			case "missing-inventory": result.Inventory = affected.PackageInventoryMeasurement{}
			case "foreign-inventory": result.Inventory.Build.Commit = "foreign"
			case "malformed-inventory": result.Inventory = affected.RecordPackageInventory([]byte(`{"ImportPath":"example.com/prod","Imports":["missing"]}`),nil,product,false); result.Inventory.Run.Complete,result.Inventory.Run.Error = true,""
			case "open-gate": result.InterfaceDispatchSites = []domain.CallSite{{Function:"unknown"}}
			}
			raw, _ := json.Marshal(result)
			kernel := domain.Evidence{ID:"kernel",Kind:domain.EvidenceSourceSnippet,BuildContext:&build,Content:string(raw)}
			claim := verifiedAdmission(domain.FalsifierLocusFunctionUnreached,&build)
			claim.NegativeVerification.EvidenceIDs = []domain.EvidenceID{kernel.ID}
			if name=="uncited" { claim.NegativeVerification.EvidenceIDs = nil }
			scan := admissionSourceScan(&build); scan.SourceScan.EntrySymbols = []string{"example.com/dep.Live"}
			c := admissionCase(product,domain.VerdictNoExploitPathFound,claim,admissionPackageList(product),scan)
			if name!="summary-only" { c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,kernel) }
			historical, _ := json.Marshal(c)
			var replay domain.AnalysisCase
			if err := json.Unmarshal(historical,&replay); err != nil { t.Fatal(err) }
			projection := admitNegativeConclusions(&replay)
			if name=="valid" {
				if projection.Case.Claims[0].Result!=domain.ClaimFalse || projection.Case.Verdict.Verdict!=domain.VerdictNoExploitPathFound { t.Fatalf("valid full payload refused: %+v",projection) }
			} else {
				if projection.Case.Claims[0].Result!=domain.ClaimUnknown || projection.Case.Verdict.Verdict==domain.VerdictNoExploitPathFound { t.Fatalf("invalid archive remains publishable: %+v",projection) }
				admissionNoCleanClaim(t,&replay)
				status,_,_ := admissionVex(t,&replay); if status=="not_affected" { t.Fatal("invalid archived negative exported as not affected") }
			}
			after, _ := json.Marshal(&replay)
			if string(after)!=string(historical) { t.Fatal("publication mutated historical evidence or verification record") }
		})
	}
}
