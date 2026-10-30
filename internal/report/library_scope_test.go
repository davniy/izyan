package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// libraryScopeWitness is the synthetic public-formal → sink binding used by
// the library-scope projection tests. It mirrors the shape Task 2 persists:
// a product-owned public library function whose string formal reaches a
// deserialization sink argument through a byte-preserving conversion.
func libraryScopeWitness() domain.LibraryInputWitness {
	return domain.LibraryInputWitness{
		API:         domain.SymbolRef{Package: "github.com/stretchr/testify/assert", Symbol: "YAMLEq"},
		Declaration: domain.CallSite{File: "assert/assertions.go", Line: 1500, Column: 1, Function: "YAMLEq"},
		FormalIndex: 1,
		FormalName:  "expected",
		FormalType:  "string",
		Sink:        domain.SymbolRef{Package: "gopkg.in/yaml.v3", Symbol: "Unmarshal"},
		Site:        domain.CallSite{File: "assert/assertions.go", Line: 1573, Column: 24, Function: "YAMLEq"},
		Arg:         0,
		Steps: []domain.LibraryPayloadStep{{
			Kind: domain.LibraryPayloadByteConversion,
			Site: domain.CallSite{File: "assert/assertions.go", Line: 1571, Function: "YAMLEq"},
		}},
		ShapeFingerprint: "sha256:shape",
		EvidenceIDs:      []domain.EvidenceID{"EV-LIB-BINDING"},
	}
}

// libraryScopeCase is a synthetic library-basis EXPLOITABLE case: TRUE
// attacker-control claim grounded in the public API, exact witness, UNKNOWN
// deployment origin and explicit verdict/profile scopes.
func libraryScopeCase() *domain.AnalysisCase {
	w := libraryScopeWitness()
	return &domain.AnalysisCase{
		ID: "case-library-scope",
		Vulnerability: domain.Vulnerability{
			ID:               "GHSA-lib-test",
			Module:           "gopkg.in/yaml.v3",
			AffectedPackages: []domain.AffectedPackage{{Path: "gopkg.in/yaml.v3"}},
			FixedVersions:    []string{"v3.0.1"},
		},
		Product: domain.ProductSnapshot{
			Repository: "github.com/stretchr/testify",
			Commit:     "abcdef1234567890",
			GoVersion:  "go1.23.0",
			GOOS:       "linux",
			GOARCH:     "amd64",
			Shape: &domain.ProductShape{
				Kind:           domain.ProductShapeLibrary,
				CensusComplete: true,
				RootModule:     "github.com/stretchr/testify",
				Fingerprint:    "sha256:shape",
			},
		},
		Affected: &domain.AffectedResult{
			ModulePresent:                   domain.ClaimTrue,
			VersionAffected:                 domain.ClaimTrue,
			PackagePresent:                  domain.ClaimTrue,
			BuildRelevant:                   domain.ClaimTrue,
			VulnerableImplementationPresent: domain.ClaimTrue,
			ResolvedVersion:                 "v3.0.0",
			Limitations:                     []string{"affected-record limitation"},
		},
		Claims: []domain.Claim{
			{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue},
			{ID: "CL-C-LOCUS", ConditionID: "C-LOCUS", Result: domain.ClaimTrue},
			{
				ID: "CL-C-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimTrue,
				ControlBasis: domain.ControlBasisLibraryPublicAPI,
				Limitations:  []string{"claim-local limitation"},
			},
		},
		Verdict: &domain.VerdictResult{
			Verdict:             domain.VerdictExploitable,
			Reason:              "library public-API payload path proven",
			ExploitabilityScope: domain.ScopeLibraryAPI,
			Limitations:         []string{"verdict limitation"},
		},
		Profiles: []domain.ProfileVerdict{
			{
				Profile: domain.ProfileZeroTrust, Title: "Public Internet",
				Verdict: domain.VerdictExploitable, Reason: "library public-API path proven",
				Priority: domain.PriorityP1, IsTargetActual: true,
				ExploitabilityScope: domain.ScopeLibraryAPI,
			},
			{
				Profile: domain.ProfileClusterPerimeter, Title: "Internal Cluster",
				Verdict: domain.VerdictInconclusive, Reason: "deployment exposure unestablished",
				Priority: domain.PriorityP2, IsTargetActual: false,
			},
		},
		Exploit: &domain.ExploitModel{
			Class:         "DESERIALIZATION",
			LocusSubjects: []domain.SymbolRef{w.Sink},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{{
				ID:      "EV-LIB-BINDING",
				Kind:    domain.EvidenceDataFlow,
				Quality: domain.QualityDeterministic,
				Content: "public formal → sink argument",
			}},
			DataFlows: []domain.DataFlow{{
				ConditionID:  "C-INPUT",
				Arg:          w.Arg,
				Origin:       domain.OriginUnknown,
				Sink:         w.Site,
				Summary:      "public library formal reaches the deserialization sink",
				LibraryInput: &w,
			}},
		},
	}
}

// deploymentScopeCase is the positive control: a deployment-origin TRUE
// C-INPUT claim with no library basis must keep today's remote-client
// narrative.
func deploymentScopeCase() *domain.AnalysisCase {
	c := libraryScopeCase()
	c.ID = "case-deployment-scope"
	c.Verdict = &domain.VerdictResult{
		Verdict: domain.VerdictExploitable,
		Reason:  "all mandatory conditions met",
	}
	c.Profiles = nil
	c.Claims = []domain.Claim{
		{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ID: "CL-C-LOCUS", ConditionID: "C-LOCUS", Result: domain.ClaimTrue},
		{ID: "CL-C-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimTrue},
	}
	c.EvidenceGraph.DataFlows = nil
	c.EvidenceGraph.Exposures = []domain.ExposureFact{{
		CallSite:  domain.CallSite{File: "cmd/server/main.go", Line: 20},
		Direction: "inbound",
		Kind:      "listener",
		Target:    "net/http.ListenAndServe",
		Address:   "0.0.0.0:8080",
	}}
	return c
}

func countOccurrences(haystack, needle string) int {
	if needle == "" {
		return 0
	}
	return strings.Count(haystack, needle)
}

func TestMarkdownLibraryScopeLimitationRUEN(t *testing.T) {
	c := libraryScopeCase()
	ru := Markdown(c, "ru")
	en := Markdown(c, "en")

	if !strings.Contains(ru, libraryAPILimitationText(true)) {
		t.Fatalf("RU report lacks the localized library-API limitation:\n%s", ru)
	}
	if strings.Contains(ru, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("RU report must not carry the EN limitation verbatim:\n%s", ru)
	}
	if !strings.Contains(en, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("EN report lacks the exact shared limitation constant:\n%s", en)
	}
	if !strings.Contains(ru, "> **Область эксплуатации:** `library-api`") {
		t.Fatalf("RU report lacks the verdict scope line:\n%s", ru)
	}
	if !strings.Contains(en, "> **Exploitability scope:** `library-api`") {
		t.Fatalf("EN report lacks the verdict scope line:\n%s", en)
	}
	// Claim limitations are aggregated, not dropped.
	for _, md := range []string{ru, en} {
		if !strings.Contains(md, "claim-local limitation") {
			t.Fatalf("claim limitation missing from report:\n%s", md)
		}
	}
	// The Limitations section lists the boundary once; the summary and the
	// key-facts note legitimately restate it.
	limsSection := ru
	if i := strings.Index(limsSection, "### Ограничения анализа"); i >= 0 {
		limsSection = limsSection[i:]
	}
	if got := countOccurrences(limsSection, libraryAPILimitationText(true)); got != 1 {
		t.Fatalf("limitations section must list the library limitation exactly once, got %d", got)
	}
}

func TestMarkdownLibraryScopeNoFabricatedRemoteInput(t *testing.T) {
	c := libraryScopeCase()
	ru := Markdown(c, "ru")
	en := Markdown(c, "en")

	forbiddenRU := []string{
		"Входные данные от удалённого клиента",
		"Сценарий атаки на сервис",
		"входящее сетевое подключение",
		"сервис принимает",
		"0.0.0.0",
		"скомпилирован в бинарный файл",
		"процесса сервера",
	}
	forbiddenEN := []string{
		"Remote client input",
		"Product Attack Scenario",
		"Inbound Request Ingestion",
		"service accepts",
		"0.0.0.0",
		"compiled into the build binary",
		"server process",
	}
	for _, f := range forbiddenRU {
		if strings.Contains(ru, f) {
			t.Errorf("RU library report contains fabricated deployment fact %q:\n%s", f, ru)
		}
	}
	for _, f := range forbiddenEN {
		if strings.Contains(en, f) {
			t.Errorf("EN library report contains fabricated deployment fact %q:\n%s", f, en)
		}
	}
	if !strings.Contains(ru, "выбирается потребителем библиотеки") ||
		!strings.Contains(en, "selectable by a library consumer") {
		t.Fatalf("library reports must state consumer selectability:\nRU:\n%s\nEN:\n%s", ru, en)
	}
}

func TestMarkdownLibraryScopeWitnessBinding(t *testing.T) {
	c := libraryScopeCase()
	ru := Markdown(c, "ru")
	en := Markdown(c, "en")

	ruWant := []string{
		"### Привязка публичного API библиотеки к уязвимому вызову",
		"github.com/stretchr/testify/assert.YAMLEq",
		"assert/assertions.go:1500",
		"формальный параметр №1 `expected` (`string`)",
		"gopkg.in/yaml.v3.Unmarshal",
		"аргумент №0 в `assert/assertions.go:1573`",
		"преобразование с сохранением байтов",
		"EV-LIB-BINDING",
	}
	enWant := []string{
		"### Library Public API → Vulnerable Sink Binding",
		"github.com/stretchr/testify/assert.YAMLEq",
		"assert/assertions.go:1500",
		"formal #1 `expected` (`string`)",
		"gopkg.in/yaml.v3.Unmarshal",
		"argument #0 at `assert/assertions.go:1573`",
		"byte-preserving conversion",
		"EV-LIB-BINDING",
	}
	for _, w := range ruWant {
		if !strings.Contains(ru, w) {
			t.Errorf("RU witness block missing %q", w)
		}
	}
	for _, w := range enWant {
		if !strings.Contains(en, w) {
			t.Errorf("EN witness block missing %q", w)
		}
	}
}

func TestMarkdownLibraryScopeDeploymentControl(t *testing.T) {
	c := deploymentScopeCase()
	ru := Markdown(c, "ru")
	en := Markdown(c, "en")

	if !strings.Contains(ru, "🔴 Недоверенный ввод") ||
		!strings.Contains(ru, "Входные данные от удалённого клиента передаются аргументом в уязвимый код") {
		t.Fatalf("deployment-origin claim lost its remote-client wording:\n%s", ru)
	}
	if !strings.Contains(en, "🔴 Untrusted input") ||
		!strings.Contains(en, "Remote client input is passed as an argument into the vulnerable code") {
		t.Fatalf("deployment-origin claim lost its remote-client wording:\n%s", en)
	}
	if !strings.Contains(ru, "и скомпилирован в бинарный файл") {
		t.Fatalf("deployment report lost the compiled-into-binary fact:\n%s", ru)
	}
	for _, md := range []string{ru, en} {
		if strings.Contains(md, "library-api") {
			t.Fatalf("deployment report must not carry library scope:\n%s", md)
		}
		if strings.Contains(md, domain.LibraryAPIScopeLimitation) {
			t.Fatalf("deployment report must not carry the library limitation:\n%s", md)
		}
	}
}

func TestMarkdownLibraryScopeInconclusiveInputFact(t *testing.T) {
	c := libraryScopeCase()
	c.Verdict = &domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "one or more mandatory exploit conditions remain unresolved: C-EXPOSURE",
	}
	c.Profiles = nil
	c.Claims = append(c.Claims, domain.Claim{
		ID: "CL-C-EXPOSURE", ConditionID: domain.ConditionID("C-EXPOSURE"),
		Result:      domain.ClaimUnknown,
		Limitations: []string{"deployment exposure model not established"},
	})

	if !libraryAPIControlProven(c) {
		t.Fatal("TRUE library-basis C-INPUT must remain library input control")
	}
	if attackerControlProven(c) {
		t.Fatal("library-basis C-INPUT must not be reported as deployment attacker control")
	}

	ru := Markdown(c, "ru")
	en := Markdown(c, "en")
	for _, md := range []string{ru, en} {
		if strings.Contains(md, "Входные данные от удалённого клиента") ||
			strings.Contains(md, "Remote client input") {
			t.Fatalf("INCONCLUSIVE library case rendered remote-client input:\n%s", md)
		}
	}
	if !strings.Contains(ru, "🔴 Выбираемо потребителем") {
		t.Fatalf("TRUE library input fact missing from key facts:\n%s", ru)
	}
	if !strings.Contains(en, "🔴 Consumer-selectable") {
		t.Fatalf("TRUE library input fact missing from EN key facts:\n%s", en)
	}
	if !strings.Contains(ru, "Не доказано (`C-EXPOSURE`)") {
		t.Fatalf("unresolved condition not named in established facts:\n%s", ru)
	}
	if !strings.Contains(ru, libraryAPILimitationText(true)) ||
		!strings.Contains(en, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("INCONCLUSIVE library case lacks the mandatory limitation")
	}
}

func TestAllLimitationsAggregatesClaimLimitations(t *testing.T) {
	c := libraryScopeCase()
	c.Claims = append(c.Claims, domain.Claim{
		ID: "CL-C-EXPOSURE", ConditionID: domain.ConditionID("C-EXPOSURE"),
		Result:      domain.ClaimUnknown,
		Limitations: []string{"claim-only limitation", "claim-only limitation"},
	})

	en := allLimitations(c, false)
	ru := allLimitations(c, true)

	if got := countOccurrences(strings.Join(en, "\n"), "claim-only limitation"); got != 1 {
		t.Fatalf("claim limitation must be aggregated exactly once, got %d", got)
	}
	if !strings.Contains(strings.Join(en, "\n"), domain.LibraryAPIScopeLimitation) {
		t.Fatalf("EN limitations lack the exact library constant: %v", en)
	}
	ruJoined := strings.Join(ru, "\n")
	if !strings.Contains(ruJoined, libraryAPILimitationText(true)) {
		t.Fatalf("RU limitations lack the localized library limitation: %v", ru)
	}
	if strings.Contains(ruJoined, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("RU limitations leaked the EN library limitation: %v", ru)
	}
	for _, want := range []string{"affected-record limitation", "verdict limitation", "claim-local limitation"} {
		if !strings.Contains(ruJoined, want) {
			t.Fatalf("aggregated limitations missing %q: %v", want, ru)
		}
	}
}

func TestReportLibraryScopeJSONRoundTrip(t *testing.T) {
	c := libraryScopeCase()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal case: %v", err)
	}
	var got domain.AnalysisCase
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal case: %v", err)
	}
	if got.Verdict == nil || got.Verdict.ExploitabilityScope != domain.ScopeLibraryAPI {
		t.Fatalf("verdict scope lost: %+v", got.Verdict)
	}
	var basis domain.ControlBasis
	for _, cl := range got.Claims {
		if cl.ConditionID == "C-INPUT" {
			basis = cl.ControlBasis
		}
	}
	if basis != domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("claim control basis lost: %q", basis)
	}
	if len(got.Profiles) == 0 || got.Profiles[0].ExploitabilityScope != domain.ScopeLibraryAPI {
		t.Fatalf("profile scope lost: %+v", got.Profiles)
	}
	if len(got.EvidenceGraph.DataFlows) == 0 || got.EvidenceGraph.DataFlows[0].LibraryInput == nil {
		t.Fatalf("library input witness lost: %+v", got.EvidenceGraph.DataFlows)
	}
	w := got.EvidenceGraph.DataFlows[0].LibraryInput
	if w.FormalIndex != 1 || w.FormalName != "expected" || w.Arg != 0 ||
		w.Site.Line != 1573 || len(w.Steps) != 1 || len(w.EvidenceIDs) != 1 {
		t.Fatalf("witness fields lost: %+v", w)
	}

	dir := t.TempDir()
	if err := Write(dir, c); err != nil {
		t.Fatalf("write report: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatalf("unmarshal report.json: %v", err)
	}
	verdict, _ := doc["verdict"].(map[string]any)
	if verdict["exploitability_scope"] != string(domain.ScopeLibraryAPI) {
		t.Fatalf("report.json lost verdict scope: %v", verdict)
	}
	claims, _ := doc["claims"].([]any)
	foundBasis := false
	for _, rawClaim := range claims {
		claim, _ := rawClaim.(map[string]any)
		if claim["control_basis"] == string(domain.ControlBasisLibraryPublicAPI) {
			foundBasis = true
		}
	}
	if !foundBasis {
		t.Fatalf("report.json lost claim control basis: %v", claims)
	}
	graph, _ := doc["evidence_graph"].(map[string]any)
	flows, _ := graph["data_flows"].([]any)
	if len(flows) == 0 {
		t.Fatal("report.json lost data flows")
	}
	flow, _ := flows[0].(map[string]any)
	witness, _ := flow["library_input"].(map[string]any)
	if witness == nil || witness["formal_index"] != float64(1) {
		t.Fatalf("report.json lost library_input witness: %v", flow)
	}
	product, _ := doc["product"].(map[string]any)
	shape, _ := product["shape"].(map[string]any)
	if shape == nil || shape["kind"] != string(domain.ProductShapeLibrary) {
		t.Fatalf("report.json lost product shape: %v", product)
	}
}

func TestTrackerRationaleLibraryScope(t *testing.T) {
	c := libraryScopeCase()
	got := TrackerRationale(c)

	want := []string{
		"Exploitable — область публичного API библиотеки (`library-api`)",
		"выбираемая потребителем библиотеки",
		"Привязка:",
		"формальный параметр №1 `expected` (`string`)",
		"Ограничение:",
		libraryAPILimitationText(true),
		"Требуется исправление",
		"v3.0.1",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("tracker rationale missing %q:\n%s", w, got)
		}
	}
	for _, forbidden := range []string{
		"удалённого клиента",
		"скомпилирован в бинарный файл",
		"процесса сервера",
		"0.0.0.0",
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("tracker rationale contains fabricated deployment fact %q:\n%s", forbidden, got)
		}
	}
}

func TestPerimeterMatrixLibraryScopeRUEN(t *testing.T) {
	c := libraryScopeCase()
	ru := Markdown(c, "ru")
	en := Markdown(c, "en")

	for _, want := range []string{
		"(область: `library-api`)",
		"**Область вывода:** `library-api`",
		"Consumer Deployment Mitigations",
	} {
		if !strings.Contains(ru, want) {
			t.Errorf("RU perimeter matrix missing %q", want)
		}
	}
	for _, want := range []string{
		"(scope: `library-api`)",
		"**Exploitability scope:** `library-api`",
		"Mitigation Options for a Consuming Application",
	} {
		if !strings.Contains(en, want) {
			t.Errorf("EN perimeter matrix missing %q", want)
		}
	}
	// The deployment perimeter must be attributed to a consuming
	// application, never to the library.
	if !strings.Contains(ru, "относится к нижестоящему приложению, а не к библиотеке") ||
		!strings.Contains(en, "describes a consuming application, not the library") {
		t.Fatalf("perimeter matrix does not attribute the deployment perimeter to a consumer")
	}
	if strings.Contains(ru, "0.0.0.0") || strings.Contains(en, "0.0.0.0") {
		t.Fatalf("library perimeter matrix asserted a 0.0.0.0 bind")
	}
}

func vexStatementFor(t *testing.T, c *domain.AnalysisCase) vexStatement {
	t.Helper()
	raw, err := OpenVEX(c)
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	var doc vexDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal OpenVEX: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected one statement, got %d", len(doc.Statements))
	}
	return doc.Statements[0]
}

func TestOpenVEXLibraryScope(t *testing.T) {
	st := vexStatementFor(t, libraryScopeCase())
	if st.Status != "affected" {
		t.Fatalf("library-basis EXPLOITABLE must project as affected, got %q", st.Status)
	}
	if st.ActionStatement == "" {
		t.Fatal("affected statement must carry an action statement")
	}
	if !strings.Contains(st.ImpactStatement, "library-api") ||
		!strings.Contains(st.ImpactStatement, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("impact statement lacks scope/limitation: %q", st.ImpactStatement)
	}
	if !strings.Contains(st.ActionStatement, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("action statement lacks the limitation: %q", st.ActionStatement)
	}

	inconclusive := libraryScopeCase()
	inconclusive.Verdict = &domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "one or more mandatory exploit conditions remain unresolved",
	}
	st = vexStatementFor(t, inconclusive)
	if st.Status != "under_investigation" {
		t.Fatalf("INCONCLUSIVE must stay under_investigation, got %q", st.Status)
	}
	if !strings.Contains(st.ActionStatement, "library-api") ||
		!strings.Contains(st.ActionStatement, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("INCONCLUSIVE library action statement lacks scope/limitation: %q", st.ActionStatement)
	}
}

func TestOpenVEXAffectedActionStatement(t *testing.T) {
	withFix := deploymentScopeCase()
	if st := vexStatementFor(t, withFix); st.ActionStatement == "" ||
		!strings.Contains(st.ActionStatement, "upgrade") ||
		!strings.Contains(st.ActionStatement, "v3.0.1") {
		t.Fatalf("affected action statement missing remediation: %q", st.ActionStatement)
	}

	noFix := deploymentScopeCase()
	noFix.Vulnerability.FixedVersions = nil
	if st := vexStatementFor(t, noFix); st.ActionStatement == "" ||
		!strings.Contains(st.ActionStatement, "no fixed version") {
		t.Fatalf("affected action statement must recommend a generic mitigation: %q", st.ActionStatement)
	}

	lib := libraryScopeCase()
	if st := vexStatementFor(t, lib); !strings.Contains(st.ActionStatement, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("library action statement lacks the mandatory limitation: %q", st.ActionStatement)
	}
}

func TestLibraryScopeUnadmittedWitnessStructuralOnly(t *testing.T) {
	c := libraryScopeCase()
	c.Verdict = &domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "library public-API admission not established: C-INPUT unresolved",
	}
	c.Profiles = nil
	c.Claims = []domain.Claim{
		{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ID: "CL-C-LOCUS", ConditionID: "C-LOCUS", Result: domain.ClaimTrue},
		{ID: "CL-C-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimUnknown},
	}
	// The witness stays in the graph; admission never converted it.
	if libraryAPIScope(c) {
		t.Fatal("raw witness must not promote itself into an active library scope")
	}
	if libraryAPIControlProven(c) {
		t.Fatal("raw witness must not promote itself into an admitted control basis")
	}

	ru := Markdown(c, "ru")
	en := Markdown(c, "en")
	for _, md := range []string{ru, en} {
		if strings.Contains(md, "library-api") {
			t.Fatalf("unadmitted witness leaked an active library scope:\n%s", md)
		}
		if strings.Contains(md, domain.LibraryAPIScopeLimitation) {
			t.Fatalf("unadmitted witness emitted the mandatory library limitation:\n%s", md)
		}
		if strings.Contains(md, "Library Public API → Vulnerable Sink Binding") ||
			strings.Contains(md, "Привязка публичного API библиотеки к уязвимому вызову") {
			t.Fatalf("unadmitted witness rendered under the admitted-conclusion heading:\n%s", md)
		}
	}
	if !strings.Contains(ru, "### Структурная привязка входа библиотеки (не является принятым выводом)") {
		t.Fatalf("RU structural witness heading missing:\n%s", ru)
	}
	if !strings.Contains(en, "### Structural Library Input Witness (not an admitted conclusion)") {
		t.Fatalf("EN structural witness heading missing:\n%s", en)
	}
	// The structural binding itself is still useful evidence.
	for _, md := range []string{ru, en} {
		if !strings.Contains(md, "gopkg.in/yaml.v3.Unmarshal") {
			t.Fatalf("structural witness binding was dropped:\n%s", md)
		}
	}

	st := vexStatementFor(t, c)
	if st.Status != "under_investigation" {
		t.Fatalf("unadmitted witness changed the VEX status: %q", st.Status)
	}
	for _, text := range []string{st.ImpactStatement, st.ActionStatement} {
		if strings.Contains(text, "library-api") ||
			strings.Contains(text, "library-public-api") ||
			strings.Contains(text, domain.LibraryAPIScopeLimitation) {
			t.Fatalf("unadmitted witness leaked into OpenVEX: %q", text)
		}
	}

	raw, err := CycloneDX(c)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	var doc cdxDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	an := doc.Vulnerabilities[0].Analysis
	if an.State != "in_triage" {
		t.Fatalf("unadmitted witness changed the CycloneDX state: %q", an.State)
	}
	for _, leak := range []string{"library-api", "library-public-api", domain.LibraryAPIScopeLimitation} {
		if strings.Contains(an.Detail, leak) {
			t.Fatalf("unadmitted witness leaked into CycloneDX detail: %q", an.Detail)
		}
	}
}

func TestLibraryScopeExternalOriginPrecedence(t *testing.T) {
	c := deploymentScopeCase()
	w := libraryScopeWitness()
	// A witness retained by the graph must not outrank an external origin
	// that actually won the C-INPUT claim.
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID:  "C-INPUT",
		Arg:          w.Arg,
		Origin:       domain.OriginUnknown,
		Sink:         w.Site,
		Summary:      "retained structural witness",
		LibraryInput: &w,
	}}

	if !attackerControlProven(c) {
		t.Fatal("external-origin TRUE C-INPUT must remain deployment attacker control")
	}
	if libraryAPIScope(c) || libraryAPIControlProven(c) {
		t.Fatal("retained witness overrode the external origin")
	}

	ru := Markdown(c, "ru")
	en := Markdown(c, "en")
	if !strings.Contains(ru, "🔴 Недоверенный ввод") ||
		!strings.Contains(ru, "Входные данные от удалённого клиента передаются аргументом в уязвимый код") {
		t.Fatalf("deployment narrative did not win in RU:\n%s", ru)
	}
	if !strings.Contains(en, "🔴 Untrusted input") ||
		!strings.Contains(en, "Remote client input is passed as an argument into the vulnerable code") {
		t.Fatalf("deployment narrative did not win in EN:\n%s", en)
	}
	for _, md := range []string{ru, en} {
		if strings.Contains(md, "library-api") {
			t.Fatalf("external-origin report gained a library scope:\n%s", md)
		}
		if strings.Contains(md, domain.LibraryAPIScopeLimitation) {
			t.Fatalf("external-origin report gained the library limitation:\n%s", md)
		}
	}
	// The retained witness is still structural evidence, not a conclusion.
	if !strings.Contains(en, "### Structural Library Input Witness (not an admitted conclusion)") {
		t.Fatalf("retained witness was not labelled structural:\n%s", en)
	}

	st := vexStatementFor(t, c)
	if st.Status != "affected" {
		t.Fatalf("external-origin VEX status changed: %q", st.Status)
	}
	if st.ActionStatement == "" || !strings.Contains(st.ActionStatement, "upgrade") {
		t.Fatalf("external-origin affected statement lost remediation: %q", st.ActionStatement)
	}
	for _, text := range []string{st.ImpactStatement, st.ActionStatement} {
		if strings.Contains(text, "library-api") ||
			strings.Contains(text, "library-public-api") ||
			strings.Contains(text, domain.LibraryAPIScopeLimitation) {
			t.Fatalf("external-origin VEX gained library scope/basis: %q", text)
		}
	}

	raw, err := CycloneDX(c)
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	var doc cdxDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	an := doc.Vulnerabilities[0].Analysis
	if an.State != "exploitable" {
		t.Fatalf("external-origin CycloneDX state changed: %q", an.State)
	}
	for _, leak := range []string{"library-api", "library-public-api", domain.LibraryAPIScopeLimitation} {
		if strings.Contains(an.Detail, leak) {
			t.Fatalf("external-origin CycloneDX detail gained library scope/basis: %q", an.Detail)
		}
	}
}

func TestCycloneDXLibraryScope(t *testing.T) {
	raw, err := CycloneDX(libraryScopeCase())
	if err != nil {
		t.Fatalf("CycloneDX: %v", err)
	}
	var doc cdxDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("expected one vulnerability, got %d", len(doc.Vulnerabilities))
	}
	an := doc.Vulnerabilities[0].Analysis
	if an.State != "exploitable" {
		t.Fatalf("library EXPLOITABLE must stay exploitable, got %q", an.State)
	}
	for _, want := range []string{
		"exploitability_scope=library-api",
		"control_basis=library-public-api",
		domain.LibraryAPIScopeLimitation,
	} {
		if !strings.Contains(an.Detail, want) {
			t.Errorf("analysis.detail missing %q: %q", want, an.Detail)
		}
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal generic CycloneDX: %v", err)
	}
	for _, forbidden := range []string{"responses", "properties", "impact_statement"} {
		if _, ok := generic[forbidden]; ok {
			t.Fatalf("CycloneDX introduced a new top-level %q field", forbidden)
		}
	}
	vulns, _ := generic["vulnerabilities"].([]any)
	vuln, _ := vulns[0].(map[string]any)
	analysis, _ := vuln["analysis"].(map[string]any)
	for key := range analysis {
		switch key {
		case "state", "justification", "detail":
		default:
			t.Fatalf("CycloneDX analysis gained a new field %q", key)
		}
	}

	inconclusive := libraryScopeCase()
	inconclusive.Verdict = &domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "one or more mandatory exploit conditions remain unresolved",
	}
	raw, err = CycloneDX(inconclusive)
	if err != nil {
		t.Fatalf("CycloneDX inconclusive: %v", err)
	}
	var doc2 cdxDoc
	if err := json.Unmarshal(raw, &doc2); err != nil {
		t.Fatalf("unmarshal CycloneDX inconclusive: %v", err)
	}
	an = doc2.Vulnerabilities[0].Analysis
	if an.State != "in_triage" {
		t.Fatalf("INCONCLUSIVE state changed: %q", an.State)
	}
	if !strings.Contains(an.Detail, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("in_triage detail lacks the library limitation: %q", an.Detail)
	}
}

// TestScopeProjectionKeepsLibraryAndTransportDistinct pins the two
// exploitability scopes as separate propositions: each carries its own boundary
// text and its own mandatory limitation, the transport limitation stays
// verbatim in machine-readable output, and a transport-peer conclusion is not
// admitted through the library-API scope rule (so it stays subject to the
// deployment/perimeter rules).
func TestScopeProjectionKeepsLibraryAndTransportDistinct(t *testing.T) {
	library := scopeStatement(domain.ScopeLibraryAPI)
	transport := scopeStatement(domain.ScopeTransportPeer)
	if library == "" || transport == "" {
		t.Fatalf("scope statements = %q / %q", library, transport)
	}
	if library == transport {
		t.Fatalf("both scopes rendered the same statement: %q", library)
	}
	if !strings.Contains(transport, "affected transport") ||
		!strings.Contains(transport, "whether an adversary can reach that transport") {
		t.Fatalf("transport statement does not state its own boundary: %q", transport)
	}
	if strings.Contains(transport, "library consumer") {
		t.Fatalf("transport statement borrowed the library-API boundary: %q", transport)
	}
	if got := localizeScopeLimitation(domain.ScopeTransportPeer, true); got != domain.TransportPeerScopeLimitation {
		t.Fatalf("RU transport limitation is not the verbatim English statement: %q", got)
	}
	if got := localizeScopeLimitation(domain.ScopeLibraryAPI, true); got == domain.LibraryAPIScopeLimitation {
		t.Fatalf("library limitation was not localized: %q", got)
	}

	// A transport-peer verdict is not a library-API conclusion: the library
	// scope helper must not adopt it and exempt it from perimeter rules.
	c := &domain.AnalysisCase{
		Verdict: &domain.VerdictResult{
			Verdict:             domain.VerdictExploitable,
			ExploitabilityScope: domain.ScopeTransportPeer,
		},
	}
	if libraryAPIScope(c) {
		t.Fatal("a transport-peer conclusion was admitted through the library-API scope rule")
	}
	if statement := libraryScopeStatement(c); statement != "" {
		t.Fatalf("a transport-peer case exported a library statement: %q", statement)
	}

	// The transport limitation travels verbatim into the structured/text
	// export metadata as well, in every language.
	pub := publication{}
	meta := pub.exportMetadata(exportEntry{
		Identity:    reportCVE,
		Role:        "requested",
		Limitations: []string{domain.TransportPeerScopeLimitation},
	})
	if !strings.Contains(meta, domain.TransportPeerScopeLimitation) {
		t.Fatalf("export metadata does not carry the verbatim transport limitation: %q", meta)
	}
}
