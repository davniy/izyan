package states_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/states"
	"github.com/davniy/izyan/internal/vulnerability"
)

// The end-to-end library proof runs on a synthetic but complete advisory: a
// CWE-502 deserialization range over the fixture module's bytes sink. Nothing
// in these tests hand-sets C-INPUT — the advisory supplies the CWE, the
// affected package/symbol and the range, and the existing affected resolver,
// root-cause resolver, model builder and source verifier derive the rest.
const (
	libraryE2EAdvisoryID  = "GHSA-lib5-e2e0-p4gw"
	libraryE2EAdvisoryCVE = "CVE-2099-5021"
	libraryE2ESink        = "example.com/dep/vuln"
	libraryE2ESinkSymbol  = "ParseBytes"
	libraryE2ELibraryAPI  = "example.com/libassertprod/assert.YAMLEq"
)

// libraryE2EVulnerability is the synthetic advisory the end-to-end library
// tests run: a CWE-502 deserialization range over the fixture module's bytes
// sink. Nothing in these tests hand-sets C-INPUT — the advisory supplies the
// CWE, the affected package/symbol and the range, and the existing affected
// resolver, root-cause resolver, model builder and source verifier derive the
// rest.
func libraryE2EVulnerability() *domain.Vulnerability {
	return &domain.Vulnerability{
		ID:      libraryE2EAdvisoryID,
		Aliases: []string{libraryE2EAdvisoryCVE},
		Module:  "example.com/dep",
		// The canonical GHSA request is bound to a fully represented Go
		// record, so the component/condition negatives may close it; the
		// CVE alias request stays KNOWN_ONLY at intake.
		Scope:        exactScopeFor(libraryE2EAdvisoryID, "example.com/dep"),
		Summary:      "Deserializer panic reachable through the assertion library's public comparator",
		Description:  "Both operands of the public comparison helper are parsed with the affected deserializer; a consumer forwarding untrusted documents reaches the panic.",
		CWE:          []string{"CWE-502"},
		BaseSeverity: "HIGH",
		BaseScore:    8.1,
		AffectedVersions: []domain.VersionRange{{
			Introduced: "1.0.0",
			Fixed:      "1.0.1",
		}},
		FixedVersions: []string{"1.0.1"},
		AffectedPackages: []domain.AffectedPackage{{
			Path:    libraryE2ESink,
			Symbols: []string{libraryE2ESinkSymbol},
		}},
		AffectedSymbols: []domain.SymbolRef{{
			Package: libraryE2ESink,
			Symbol:  libraryE2ESinkSymbol,
		}},
		References: []domain.Reference{{
			Type: "ADVISORY",
			URL:  "https://example.com/advisories/" + libraryE2EAdvisoryID,
		}},
	}
}

// libraryE2EOptions configures one pipeline run against a fixture product.
type libraryE2EOptions struct {
	fixture     string
	requestID   string
	additional  []string
	govulncheck string
	prepare     func(t *testing.T, repo string)
	// admissionControl mutates the advisory before the run. The library
	// payload admission gate is keyed on the exact exploit class and CWE, so
	// the negative controls change only those facts.
	admissionControl func(*domain.Vulnerability)
	// expectUnproven marks a negative control: the mutation refuses the
	// library basis, so the terminal assessment is FAILED (no verdict) while
	// the artifact remains unproven.
	expectUnproven bool
}

// runLibraryE2E drives the real workflow end to end: snapshot, advisory
// resolution, affected resolution, derived root cause and exploit model,
// source evidence collection, negative checking, verdict and report writing.
func runLibraryE2E(t *testing.T, opts libraryE2EOptions) (c *domain.AnalysisCase, repo, caseDir string) {
	t.Helper()
	repo = initRepoFrom(t, opts.fixture, opts.additional...)
	if opts.prepare != nil {
		opts.prepare(t, repo)
	}
	dir := t.TempDir()
	caseDir = filepath.Join(dir, "cases")
	vuln := libraryE2EVulnerability()
	if opts.admissionControl != nil {
		opts.admissionControl(vuln)
	}
	deps := engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			libraryE2EAdvisoryID: vuln,
		}},
		VulnID:    opts.requestID,
		Resolver:  affected.GoResolver{},
		CaseDir:   caseDir,
		UseSource: true,
		// The library-consumer fixtures assert build-dependent negatives
		// (constant NEPF, test-only NOT_AFFECTED): they must declare the
		// analyzed build, not inherit the analyzer host.
		SnapshotOptions: declaredSnapshotOptions(),
	}
	if opts.govulncheck != "" {
		deps.Govulncheck = fakeGovulncheck{out: []byte(opts.govulncheck)}
	}
	c = runEngine(t, deps)
	wantState := domain.StateCompleted
	if opts.expectUnproven {
		wantState = domain.StateFailed
	}
	if c.Workflow.State != wantState {
		t.Fatalf("state=%s reason=%s, want %s", c.Workflow.State, c.Workflow.Reason, wantState)
	}
	return c, repo, caseDir
}

// libraryInputWitnesses returns the persisted public-formal bindings of the
// C-INPUT trace, in sink order.
func libraryInputWitnesses(t *testing.T, c *domain.AnalysisCase) []domain.LibraryInputWitness {
	t.Helper()
	var out []domain.LibraryInputWitness
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID != "C-INPUT" || f.LibraryInput == nil {
			continue
		}
		out = append(out, *f.LibraryInput)
	}
	return out
}

// witnessForFormal selects the persisted binding recorded for one public
// formal parameter.
func witnessForFormal(t *testing.T, witnesses []domain.LibraryInputWitness, formal int) domain.LibraryInputWitness {
	t.Helper()
	for _, w := range witnesses {
		if w.FormalIndex == formal {
			return w
		}
	}
	t.Fatalf("no persisted binding for public formal #%d: %+v", formal, witnesses)
	return domain.LibraryInputWitness{}
}

// assertWitnessEvidenceResolves: every id a persisted witness cites must
// resolve in the case's evidence graph.
func assertWitnessEvidenceResolves(t *testing.T, c *domain.AnalysisCase, w domain.LibraryInputWitness) {
	t.Helper()
	if len(w.EvidenceIDs) == 0 {
		t.Fatalf("persisted witness cites no evidence: %+v", w)
	}
	for _, id := range w.EvidenceIDs {
		if c.EvidenceGraph.EvidenceByID(id) == nil {
			t.Fatalf("persisted witness cites missing evidence %s", id)
		}
	}
}

// readCaseArtifact reads one persisted report artifact.
func readCaseArtifact(t *testing.T, caseDir string, c *domain.AnalysisCase, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(caseDir, string(c.ID), name))
	if err != nil {
		t.Fatalf("read persisted %s: %v", name, err)
	}
	return b
}

// decodePersistedCase loads a persisted case document (the store snapshot or
// report.json) as the domain type, so assertions run against what a consumer
// of the artifact actually reads.
func decodePersistedCase(t *testing.T, path string) *domain.AnalysisCase {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var c domain.AnalysisCase
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &c
}

// fixtureLinesWith returns the 1-based line numbers of a fixture file whose
// text contains marker. Witness sites are compared against the fixture itself
// instead of hard-coded numbers.
func fixtureLinesWith(t *testing.T, path, marker string) []int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var out []int
	for i, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, marker) {
			out = append(out, i+1)
		}
	}
	if len(out) == 0 {
		t.Fatalf("fixture %s has no %q line", path, marker)
	}
	return out
}

// TestE2ELibraryPublicAPIExploitable proves the complete deterministic path on
// a library product: affected applicability, independent reach and locus
// facts, both persisted public-formal payload bindings, and the scoped
// EXPLOITABLE verdict — through the persisted artifacts, not the in-memory
// case only. The advisory is requested twice: by its canonical GHSA identity
// (COMPLETE coverage) and by its CVE alias (KNOWN_ONLY). KNOWN_ONLY blocks
// unsupported negative closure; it must not block the proven positive and must
// not be relabelled.
func TestE2ELibraryPublicAPIExploitable(t *testing.T) {
	cases := []struct {
		name      string
		requestID string
		scopeKind domain.AdvisoryScopeKind
		coverage  domain.AdvisoryCoverage
		scopeCell string
		closureOK bool
	}{
		{
			name:      "canonical GHSA request",
			requestID: libraryE2EAdvisoryID,
			scopeKind: domain.ScopeAdvisoryEntries,
			coverage:  domain.CoverageComplete,
			scopeCell: "`" + libraryE2EAdvisoryID + "` (`ADVISORY_ENTRIES`, `COMPLETE`)",
			closureOK: true,
		},
		{
			name:      "CVE alias request against the same advisory",
			requestID: libraryE2EAdvisoryCVE,
			scopeKind: domain.ScopeCVE,
			coverage:  domain.CoverageKnownOnly,
			scopeCell: "`" + libraryE2EAdvisoryCVE + "` → `" + libraryE2EAdvisoryID + "` (`CVE`, `KNOWN_ONLY`)",
			closureOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, repo, caseDir := runLibraryE2E(t, libraryE2EOptions{
				fixture:   "libassertprod",
				requestID: tc.requestID,
			})

			// Product shape: a proven library with a complete census.
			shape := c.Product.Shape
			if shape == nil || shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete {
				t.Fatalf("shape=%+v, want a proven LIBRARY with a complete census", shape)
			}
			if shape.Fingerprint == "" || len(shape.EvidenceIDs) == 0 {
				t.Fatalf("shape proof lost its fingerprint/evidence: %+v", shape)
			}
			// The whole path must be deterministic: no LLM-backed state ran.
			if got := c.Workflow.Usage.LLMCalls; got != 0 {
				t.Fatalf("library e2e used %d LLM call(s); the proof must be fully deterministic", got)
			}

			// Affected applicability is decided by the real resolver.
			if c.Affected == nil {
				t.Fatal("affected result missing")
			}
			for _, axis := range []struct {
				name string
				got  domain.ClaimResult
			}{
				{"ModulePresent", c.Affected.ModulePresent},
				{"VersionAffected", c.Affected.VersionAffected},
				{"PackagePresent", c.Affected.PackagePresent},
				{"BuildRelevant", c.Affected.BuildRelevant},
			} {
				if axis.got != domain.ClaimTrue {
					t.Fatalf("affected %s=%s, want TRUE (affected=%+v)", axis.name, axis.got, *c.Affected)
				}
			}
			scope := c.Affected.Scope
			if scope == nil {
				t.Fatal("advisory scope missing")
			}
			if scope.RequestedID != tc.requestID || scope.ResolvedID != libraryE2EAdvisoryID ||
				scope.Kind != tc.scopeKind || scope.Coverage != tc.coverage {
				t.Fatalf("scope=%+v, want requested=%s resolved=%s kind=%s coverage=%s",
					*scope, tc.requestID, libraryE2EAdvisoryID, tc.scopeKind, tc.coverage)
			}
			if scope.AllowsNegativeClosure() != tc.closureOK {
				t.Fatalf("negative closure=%t under %+v, want %t", scope.AllowsNegativeClosure(), *scope, tc.closureOK)
			}

			// Reach and locus are independent mandatory facts: separate
			// claims, each grounded in evidence, neither derived from the
			// library witness.
			for _, id := range []domain.ConditionID{"C-REACH", "C-LOCUS"} {
				cl := findClaimT(t, c.Claims, id)
				if cl.Result != domain.ClaimTrue {
					t.Fatalf("%s=%s, want TRUE (claim=%+v)", id, cl.Result, cl)
				}
				if len(cl.EvidenceIDs) == 0 {
					t.Fatalf("%s TRUE claim cites no evidence", id)
				}
				if cl.ConditionID == id && cl.Producer == "" {
					t.Fatalf("%s claim has no producer", id)
				}
			}

			// The input claim is the library public-API boundary fact.
			input := findClaimT(t, c.Claims, "C-INPUT")
			if input.Result != domain.ClaimTrue {
				t.Fatalf("C-INPUT=%s, want TRUE (claim=%+v)", input.Result, input)
			}
			if input.ControlBasis != domain.ControlBasisLibraryPublicAPI {
				t.Fatalf("C-INPUT basis=%q, want %q", input.ControlBasis, domain.ControlBasisLibraryPublicAPI)
			}
			if input.Producer != "evaluator.ArgumentOrigin" {
				t.Fatalf("C-INPUT producer=%q, want evaluator.ArgumentOrigin", input.Producer)
			}
			if !slices.Contains(input.Limitations, domain.LibraryAPIScopeLimitation) {
				t.Fatalf("C-INPUT lost the mandatory limitation: %v", input.Limitations)
			}
			if len(input.EvidenceIDs) == 0 {
				t.Fatal("library TRUE claim cites no evidence")
			}
			if len(input.AssumptionIDs) != 0 {
				t.Fatalf("consumer selectability is a code fact, not an assumption: %v", input.AssumptionIDs)
			}

			// Both public formals are persisted with exact payload bindings.
			witnesses := libraryInputWitnesses(t, c)
			if len(witnesses) != 2 {
				t.Fatalf("persisted bindings=%d, want the fixture's two public formals: %+v", len(witnesses), witnesses)
			}
			assertFile := filepath.Join(repo, "assert", "assert.go")
			sinkLines := fixtureLinesWith(t, assertFile, "vuln.ParseBytes(")
			declLines := fixtureLinesWith(t, assertFile, "func YAMLEq(")
			for _, tc2 := range []struct {
				formal int
				name   string
			}{{1, "expected"}, {2, "actual"}} {
				w := witnessForFormal(t, witnesses, tc2.formal)
				if w.API.Package+"."+w.API.Symbol != libraryE2ELibraryAPI {
					t.Fatalf("formal #%d API=%s.%s, want %s", tc2.formal, w.API.Package, w.API.Symbol, libraryE2ELibraryAPI)
				}
				if w.FormalName != tc2.name || w.FormalType != "string" {
					t.Fatalf("formal #%d is %q (%s), want %q (string)", tc2.formal, w.FormalName, w.FormalType, tc2.name)
				}
				if w.Sink.Package != libraryE2ESink || w.Sink.Symbol != libraryE2ESinkSymbol {
					t.Fatalf("formal #%d sink=%+v, want %s.%s", tc2.formal, w.Sink, libraryE2ESink, libraryE2ESinkSymbol)
				}
				if w.Arg != 0 {
					t.Fatalf("formal #%d binds sink argument #%d, want #0", tc2.formal, w.Arg)
				}
				if w.Site.File != assertFile || !slices.Contains(sinkLines, w.Site.Line) {
					t.Fatalf("formal #%d site=%s:%d, want a fixture ParseBytes call line %v",
						tc2.formal, w.Site.File, w.Site.Line, sinkLines)
				}
				if w.Declaration.File != assertFile || !slices.Contains(declLines, w.Declaration.Line) {
					t.Fatalf("formal #%d declaration=%s:%d, want the YAMLEq declaration %v",
						tc2.formal, w.Declaration.File, w.Declaration.Line, declLines)
				}
				if w.ShapeFingerprint != shape.Fingerprint {
					t.Fatalf("formal #%d witness fingerprint=%s, want the persisted shape fingerprint %s",
						tc2.formal, w.ShapeFingerprint, shape.Fingerprint)
				}
				assertWitnessEvidenceResolves(t, c, w)
			}

			// Deployment origins stay UNKNOWN: the boundary fact never
			// invents external untrusted provenance.
			for _, f := range c.EvidenceGraph.DataFlows {
				if f.ConditionID != "C-INPUT" {
					continue
				}
				if f.Origin != domain.OriginUnknown {
					t.Fatalf("library flow origin=%s, want UNKNOWN", f.Origin)
				}
			}

			// The verdict is the scoped positive, in both perimeter profiles.
			if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
				t.Fatalf("verdict=%+v, want EXPLOITABLE", c.Verdict)
			}
			if c.Verdict.ExploitabilityScope != domain.ScopeLibraryAPI {
				t.Fatalf("verdict scope=%q, want %q", c.Verdict.ExploitabilityScope, domain.ScopeLibraryAPI)
			}
			if c.Verdict.Reason != "all mandatory exploit conditions are satisfied" {
				t.Fatalf("reason=%q, want the unchanged mandatory-conjunction reason", c.Verdict.Reason)
			}
			if !slices.Contains(c.Verdict.Limitations, domain.LibraryAPIScopeLimitation) {
				t.Fatalf("verdict lost the mandatory limitation: %v", c.Verdict.Limitations)
			}
			if len(c.Profiles) != 2 {
				t.Fatalf("profiles=%+v, want zero_trust and cluster_perimeter", c.Profiles)
			}
			for _, p := range c.Profiles {
				if p.Verdict != domain.VerdictExploitable || p.ExploitabilityScope != domain.ScopeLibraryAPI {
					t.Fatalf("profile %s verdict=%s scope=%q, want EXPLOITABLE/%s",
						p.Profile, p.Verdict, p.ExploitabilityScope, domain.ScopeLibraryAPI)
				}
			}

			// --- Persisted artifacts -------------------------------------
			caseJSON := decodePersistedCase(t, filepath.Join(caseDir, string(c.ID)+".json"))
			reportJSON := decodePersistedCase(t, filepath.Join(caseDir, string(c.ID), "report.json"))

			for name, persisted := range map[string]*domain.AnalysisCase{
				"case store snapshot": caseJSON,
				"report.json":         reportJSON,
			} {
				if persisted.Product.Shape == nil || persisted.Product.Shape.Kind != domain.ProductShapeLibrary {
					t.Fatalf("%s: product shape=%+v, want LIBRARY", name, persisted.Product.Shape)
				}
				if persisted.Verdict == nil || persisted.Verdict.Verdict != domain.VerdictExploitable ||
					persisted.Verdict.ExploitabilityScope != domain.ScopeLibraryAPI {
					t.Fatalf("%s: verdict=%+v, want EXPLOITABLE/%s", name, persisted.Verdict, domain.ScopeLibraryAPI)
				}
				pInput := findClaimT(t, persisted.Claims, "C-INPUT")
				if pInput.Result != domain.ClaimTrue || pInput.ControlBasis != domain.ControlBasisLibraryPublicAPI {
					t.Fatalf("%s: persisted C-INPUT=%s basis=%q", name, pInput.Result, pInput.ControlBasis)
				}
				pWitnesses := libraryInputWitnesses(t, persisted)
				if len(pWitnesses) != 2 {
					t.Fatalf("%s: persisted bindings=%d, want 2", name, len(pWitnesses))
				}
				for _, w := range pWitnesses {
					if w.Sink.Package != libraryE2ESink || w.Sink.Symbol != libraryE2ESinkSymbol || w.Arg != 0 {
						t.Fatalf("%s: persisted binding=%+v", name, w)
					}
					assertWitnessEvidenceResolves(t, persisted, w)
				}
				if persisted.Affected.Scope == nil || persisted.Affected.Scope.Coverage != tc.coverage {
					t.Fatalf("%s: persisted coverage=%+v, want %s", name, persisted.Affected.Scope, tc.coverage)
				}
				if len(persisted.Profiles) != 2 {
					t.Fatalf("%s: persisted profiles=%+v", name, persisted.Profiles)
				}
				for _, p := range persisted.Profiles {
					if p.ExploitabilityScope != domain.ScopeLibraryAPI || p.Verdict != domain.VerdictExploitable {
						t.Fatalf("%s: persisted profile %s verdict=%s scope=%q", name, p.Profile, p.Verdict, p.ExploitabilityScope)
					}
				}
			}

			// Raw document: the new fields are on disk with their exact
			// labels, and the requested coverage was not relabelled.
			for _, raw := range []struct {
				name string
				b    []byte
			}{
				{"case store snapshot", mustRead(t, filepath.Join(caseDir, string(c.ID)+".json"))},
				{"report.json", mustRead(t, filepath.Join(caseDir, string(c.ID), "report.json"))},
			} {
				for _, want := range []string{
					`"kind": "LIBRARY"`,
					`"library_input"`,
					`"control_basis": "library-public-api"`,
					`"exploitability_scope": "library-api"`,
					`"requested_id": "` + tc.requestID + `"`,
					`"resolved_id": "` + libraryE2EAdvisoryID + `"`,
					`"coverage": "` + string(tc.coverage) + `"`,
				} {
					if !strings.Contains(string(raw.b), want) {
						t.Fatalf("%s is missing %s", raw.name, want)
					}
				}
			}

			// RU/EN Markdown: exact scope lines, both bindings, the mandatory
			// limitation, the unchanged advisory identity, and no fabricated
			// deployment input.
			en := string(readCaseArtifact(t, caseDir, c, "report.en.md"))
			ru := string(readCaseArtifact(t, caseDir, c, "report.md"))
			for _, want := range []string{
				"> **Exploitability scope:** `library-api`",
				"control basis: `library-public-api`",
				domain.LibraryAPIScopeLimitation,
				tc.scopeCell,
			} {
				if !strings.Contains(en, want) {
					t.Fatalf("report.en.md is missing %q", want)
				}
			}
			for _, want := range []string{
				"> **Область эксплуатации:** `library-api`",
				"Основание контроля: `library-public-api`",
				"Область library-API:",
				tc.scopeCell,
			} {
				if !strings.Contains(ru, want) {
					t.Fatalf("report.md is missing %q", want)
				}
			}
			for _, w := range witnesses {
				if want := englishBinding(w); !strings.Contains(en, want) {
					t.Fatalf("report.en.md is missing the binding %q", want)
				}
				if want := russianBinding(w); !strings.Contains(ru, want) {
					t.Fatalf("report.md is missing the binding %q", want)
				}
			}
			for _, forbidden := range []string{"remote client", "inbound request", "0.0.0.0"} {
				if strings.Contains(strings.ToLower(en), forbidden) {
					t.Fatalf("report.en.md fabricates deployment exposure (%q) for a library-scope positive", forbidden)
				}
			}
			if strings.Contains(ru, "Входные данные от удалённого клиента") {
				t.Fatal("report.md fabricates remote client input for a library-scope positive")
			}

			// OpenVEX: the scoped positive projects to `affected` with the
			// scope and limitation in the impact statement.
			var vex struct {
				Statements []struct {
					Vulnerability struct {
						Name string `json:"name"`
					} `json:"vulnerability"`
					Status          string `json:"status"`
					ImpactStatement string `json:"impact_statement"`
					ActionStatement string `json:"action_statement"`
				} `json:"statements"`
			}
			if err := json.Unmarshal(readCaseArtifact(t, caseDir, c, "openvex.json"), &vex); err != nil {
				t.Fatalf("decode openvex.json: %v", err)
			}
			if len(vex.Statements) != 1 {
				t.Fatalf("openvex statements=%d, want 1", len(vex.Statements))
			}
			st := vex.Statements[0]
			if st.Vulnerability.Name != libraryE2EAdvisoryID {
				t.Fatalf("openvex vulnerability=%q, want %s", st.Vulnerability.Name, libraryE2EAdvisoryID)
			}
			if st.Status != "affected" {
				t.Fatalf("openvex status=%q, want affected", st.Status)
			}
			if !strings.Contains(st.ImpactStatement, "Exploitability scope: library-api") ||
				!strings.Contains(st.ImpactStatement, domain.LibraryAPIScopeLimitation) {
				t.Fatalf("openvex impact statement lost the scope/limitation: %q", st.ImpactStatement)
			}
			if !strings.Contains(st.ActionStatement, "exploitability scope library-api") {
				t.Fatalf("openvex action statement lost the scope: %q", st.ActionStatement)
			}

			// CycloneDX: state mapping unchanged, scope/basis/limitation in
			// the existing analysis detail.
			var cdx struct {
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Analysis struct {
						State  string `json:"state"`
						Detail string `json:"detail"`
					} `json:"analysis"`
				} `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(readCaseArtifact(t, caseDir, c, "cyclonedx.json"), &cdx); err != nil {
				t.Fatalf("decode cyclonedx.json: %v", err)
			}
			if len(cdx.Vulnerabilities) != 1 || cdx.Vulnerabilities[0].ID != libraryE2EAdvisoryID {
				t.Fatalf("cyclonedx vulnerabilities=%+v, want the requested advisory", cdx.Vulnerabilities)
			}
			analysis := cdx.Vulnerabilities[0].Analysis
			if analysis.State != "exploitable" {
				t.Fatalf("cyclonedx state=%q, want exploitable", analysis.State)
			}
			for _, want := range []string{
				"exploitability_scope=library-api",
				"control_basis=library-public-api",
				domain.LibraryAPIScopeLimitation,
			} {
				if !strings.Contains(analysis.Detail, want) {
					t.Fatalf("cyclonedx detail is missing %q: %q", want, analysis.Detail)
				}
			}
		})
	}
}

// englishBinding renders the exact EN binding sentence from the persisted
// witness — the report must state the formal → sink argument identity.
func englishBinding(w domain.LibraryInputWitness) string {
	return fmt.Sprintf("`%s` (declared at `%s:%d`) formal #%d `%s` (`%s`) → `%s.%s` argument #%d at `%s:%d`",
		w.API.Package+"."+w.API.Symbol, w.Declaration.File, w.Declaration.Line,
		w.FormalIndex, w.FormalName, w.FormalType,
		w.Sink.Package, w.Sink.Symbol, w.Arg, w.Site.File, w.Site.Line)
}

// russianBinding renders the exact RU binding sentence from the persisted
// witness.
func russianBinding(w domain.LibraryInputWitness) string {
	return fmt.Sprintf("`%s` (объявлен в `%s:%d`), формальный параметр №%d `%s` (`%s`) → `%s.%s`, аргумент №%d в `%s:%d`",
		w.API.Package+"."+w.API.Symbol, w.Declaration.File, w.Declaration.Line,
		w.FormalIndex, w.FormalName, w.FormalType,
		w.Sink.Package, w.Sink.Symbol, w.Arg, w.Site.File, w.Site.Line)
}

// mustRead reads a file an assertion needs.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// sameOrigins compares origin multisets: the trace records a set of live
// payload positions, and their order is not part of the claim.
func sameOrigins(got, want []domain.DataOrigin) bool {
	a := append([]domain.DataOrigin(nil), got...)
	b := append([]domain.DataOrigin(nil), want...)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// commitFixtureChange records a fixture edit so the analyzed snapshot matches
// a real repository state.
func commitFixtureChange(t *testing.T, repo, message string) {
	t.Helper()
	for _, args := range [][]string{
		{"git", "add", "."},
		{"git", "-c", "user.email=test@test", "-c", "user.name=test", "commit", "-qm", message},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

// TestE2ELibraryPublicCallersDoNotCloseBoundary: in-repository callers of the
// public API — constant-only and test-only — never close the library boundary.
// The public formal stays consumer-selectable (UNKNOWN deployment origin, an
// admitted witness, the scoped positive), because a caller in this repository
// says nothing about a different consumer of the same artifact.
func TestE2ELibraryPublicCallersDoNotCloseBoundary(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
	}{
		{
			name: "constant-only in-repository caller",
			file: "assert/builtin.go",
			body: `package assert

const builtinDoc = "name: stable\n"

// CompareBuiltin compares the shipped document through the public helper. The
// operand is a constant, but that says nothing about other consumers.
func CompareBuiltin() bool { return YAMLEq(nopT{}, builtinDoc, builtinDoc) }

type nopT struct{}

func (nopT) Errorf(string, ...interface{}) {}
`,
		},
		{
			name: "test-only in-repository caller",
			file: "assert/assert_test.go",
			body: `package assert_test

import (
	"testing"

	"example.com/libassertprod/assert"
)

func TestBuiltin(t *testing.T) {
	if !assert.YAMLEq(t, "name: stable\n", "name: stable\n") {
		t.Fatal("documents differ")
	}
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, repo, _ := runLibraryE2E(t, libraryE2EOptions{
				fixture:   "libassertprod",
				requestID: libraryE2EAdvisoryID,
				prepare: func(t *testing.T, repo string) {
					path := filepath.Join(repo, filepath.FromSlash(tc.file))
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
						t.Fatal(err)
					}
					commitFixtureChange(t, repo, "add "+tc.file)
				},
			})

			if c.Product.Shape == nil || c.Product.Shape.Kind != domain.ProductShapeLibrary {
				t.Fatalf("shape=%+v, want LIBRARY", c.Product.Shape)
			}
			input := findClaimT(t, c.Claims, "C-INPUT")
			if input.Result != domain.ClaimTrue || input.ControlBasis != domain.ControlBasisLibraryPublicAPI {
				t.Fatalf("C-INPUT=%s basis=%q; an in-repository caller must not close the boundary",
					input.Result, input.ControlBasis)
			}
			witnesses := libraryInputWitnesses(t, c)
			if len(witnesses) != 2 {
				t.Fatalf("persisted bindings=%d, want both public formals: %+v", len(witnesses), witnesses)
			}
			for _, f := range c.EvidenceGraph.DataFlows {
				if f.ConditionID != "C-INPUT" {
					continue
				}
				if f.Origin != domain.OriginUnknown {
					t.Fatalf("flow origin=%s: an in-repository %s caller was treated as the deployment origin",
						f.Origin, tc.name)
				}
				if f.LibraryInput == nil {
					t.Fatalf("flow lost its public-formal witness: %s", f.Summary)
				}
			}
			if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable ||
				c.Verdict.ExploitabilityScope != domain.ScopeLibraryAPI {
				t.Fatalf("verdict=%+v, want EXPLOITABLE/%s", c.Verdict, domain.ScopeLibraryAPI)
			}
			if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(tc.file))); err != nil {
				t.Fatalf("prepared caller is missing: %v", err)
			}
		})
	}
}

// TestE2ELibraryConsumerCalibration: the same vulnerable artifact yields three
// different application conclusions depending on how a real consumer uses the
// library. None of them acquires the library basis or scope: the boundary
// field describes the analyzed product, which here is an application.
func TestE2ELibraryConsumerCalibration(t *testing.T) {
	const gvTrace = `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GHSA-lib5-e2e0-p4gw","fixed_version":"v1.0.1","trace":[
 {"module":"%s","package":"%s","function":"%s","position":{"filename":"main.go","line":1}},
 {"module":"example.com/libassertprod","package":"example.com/libassertprod/assert","function":"YAMLEq","position":{"filename":"assert/assert.go","line":21}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"ParseBytes","position":{"filename":"vuln/vuln.go","line":17}}
]}}`

	cases := []struct {
		name           string
		fixture        string
		govulncheck    string
		verdict        domain.Verdict
		inputResult    domain.ClaimResult
		falsifier      string
		negativeStatus domain.NegativeVerificationStatus
		wantOrigins    []domain.DataOrigin
		testOnlyScope  []string
	}{
		{
			name:        "HTTP body forwarded into the library",
			fixture:     "libasserthttpprod",
			govulncheck: fmt.Sprintf(gvTrace, "example.com/libasserthttpprod", "example.com/libasserthttpprod", "main.compare"),
			verdict:     domain.VerdictExploitable,
			inputResult: domain.ClaimTrue,
			// External provenance is ordinary deployment evidence: the
			// application forwards the request body itself.
			wantOrigins: []domain.DataOrigin{domain.OriginExternalUntrusted, domain.OriginConstant},
		},
		{
			name:        "fixed literals passed into the library",
			fixture:     "libassertconstprod",
			govulncheck: fmt.Sprintf(gvTrace, "example.com/libassertconstprod", "example.com/libassertconstprod", "main.validateBuiltin"),
			verdict:     domain.VerdictNoExploitPathFound,
			inputResult: domain.ClaimFalse,
			falsifier:   domain.FalsifierConstantOrGeneratedInput,
			// NEPF is only valid with a verified negative.
			negativeStatus: domain.NegativeVerified,
			wantOrigins:    []domain.DataOrigin{domain.OriginConstant, domain.OriginConstant, domain.OriginConstant},
		},
		{
			name:          "library imported only from _test.go",
			fixture:       "libasserttestprod",
			verdict:       domain.VerdictNotAffected,
			inputResult:   domain.ClaimUnknown,
			testOnlyScope: []string{"example.com/dep/vuln"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, caseDir := runLibraryE2E(t, libraryE2EOptions{
				fixture:     tc.fixture,
				requestID:   libraryE2EAdvisoryID,
				additional:  []string{"libassertprod"},
				govulncheck: tc.govulncheck,
			})

			// The consumer is an application, never a library product. A
			// NOT_AFFECTED case terminates at the affected-chain gate, so
			// it never collects evidence — and therefore never admits.
			if tc.verdict != domain.VerdictNotAffected {
				if c.Product.Shape == nil || c.Product.Shape.Kind != domain.ProductShapeApplication {
					t.Fatalf("shape=%+v, want APPLICATION", c.Product.Shape)
				}
			} else if c.Product.Shape != nil {
				t.Fatalf("NOT_AFFECTED consumer collected a product shape: %+v", c.Product.Shape)
			}
			if c.Verdict == nil || c.Verdict.Verdict != tc.verdict {
				t.Fatalf("verdict=%+v, want %s", c.Verdict, tc.verdict)
			}
			// No library basis and no library scope — the boundary field
			// must not leak to an application consumer.
			for _, cl := range c.Claims {
				if cl.ControlBasis == domain.ControlBasisLibraryPublicAPI {
					t.Fatalf("consumer claim %s acquired the library basis: %+v", cl.ConditionID, cl)
				}
			}
			if c.Verdict.ExploitabilityScope != "" {
				t.Fatalf("consumer verdict scope=%q, want empty", c.Verdict.ExploitabilityScope)
			}
			for _, p := range c.Profiles {
				if p.ExploitabilityScope != "" {
					t.Fatalf("consumer profile %s scope=%q, want empty", p.Profile, p.ExploitabilityScope)
				}
			}
			for _, f := range c.EvidenceGraph.DataFlows {
				if f.LibraryInput != nil {
					t.Fatalf("consumer flow acquired a library witness: %+v", f.LibraryInput)
				}
			}

			switch tc.verdict {
			case domain.VerdictExploitable:
				input := findClaimT(t, c.Claims, "C-INPUT")
				if input.Result != domain.ClaimTrue {
					t.Fatalf("C-INPUT=%s, want TRUE", input.Result)
				}
				var origins []domain.DataOrigin
				for _, f := range c.EvidenceGraph.DataFlows {
					if f.ConditionID == "C-INPUT" {
						origins = append(origins, f.Origin)
					}
				}
				if !sameOrigins(origins, tc.wantOrigins) {
					t.Fatalf("C-INPUT flow origins=%v, want %v", origins, tc.wantOrigins)
				}
			case domain.VerdictNoExploitPathFound:
				input := findClaimT(t, c.Claims, "C-INPUT")
				if input.Result != tc.inputResult || input.Falsifier != tc.falsifier {
					t.Fatalf("C-INPUT=%s falsifier=%s, want %s/%s", input.Result, input.Falsifier, tc.inputResult, tc.falsifier)
				}
				if input.NegativeVerification == nil || input.NegativeVerification.Status != tc.negativeStatus {
					t.Fatalf("C-INPUT negative verification=%+v, want %s", input.NegativeVerification, tc.negativeStatus)
				}
				if len(input.NegativeVerification.EvidenceIDs) == 0 {
					t.Fatal("VERIFIED negative cites no evidence")
				}
				var origins []domain.DataOrigin
				for _, f := range c.EvidenceGraph.DataFlows {
					if f.ConditionID == "C-INPUT" {
						origins = append(origins, f.Origin)
					}
				}
				if !sameOrigins(origins, tc.wantOrigins) {
					t.Fatalf("C-INPUT flow origins=%v, want all-constant %v", origins, tc.wantOrigins)
				}
			case domain.VerdictNotAffected:
				if !slices.Equal(c.Affected.TestOnlyScope, tc.testOnlyScope) {
					t.Fatalf("TestOnlyScope=%v, want %v", c.Affected.TestOnlyScope, tc.testOnlyScope)
				}
				if c.Affected.PackagePresent != domain.ClaimFalse || c.Affected.BuildRelevant != domain.ClaimFalse {
					t.Fatalf("affected package=%s build=%s, want FALSE/FALSE",
						c.Affected.PackagePresent, c.Affected.BuildRelevant)
				}
				if !strings.Contains(c.Verdict.Reason, "test scope") {
					t.Fatalf("reason=%q must name the test scope", c.Verdict.Reason)
				}
				// No admission: the case never reaches condition analysis.
				if len(c.Claims) != 0 {
					t.Fatalf("NOT_AFFECTED consumer evaluated conditions: %+v", c.Claims)
				}
				if len(c.EvidenceGraph.DataFlows) != 0 {
					t.Fatalf("NOT_AFFECTED consumer traced data flows: %+v", c.EvidenceGraph.DataFlows)
				}
				// The shipped library source is not mislabelled as test-only:
				// the exclusion names the affected dependency package only.
				if strings.Contains(c.Verdict.Reason, "libassertprod") {
					t.Fatalf("reason=%q mislabels the shipped library source as test-only", c.Verdict.Reason)
				}
			}

			// Persisted artifacts carry the same absence of library scope.
			for name, path := range map[string]string{
				"case store snapshot": filepath.Join(caseDir, string(c.ID)+".json"),
				"report.json":         filepath.Join(caseDir, string(c.ID), "report.json"),
			} {
				persisted := decodePersistedCase(t, path)
				if persisted.Verdict == nil || persisted.Verdict.Verdict != tc.verdict {
					t.Fatalf("%s: verdict=%+v, want %s", name, persisted.Verdict, tc.verdict)
				}
				if persisted.Verdict.ExploitabilityScope != "" {
					t.Fatalf("%s: verdict scope=%q, want empty", name, persisted.Verdict.ExploitabilityScope)
				}
				for _, p := range persisted.Profiles {
					if p.ExploitabilityScope != "" {
						t.Fatalf("%s: profile %s scope=%q, want empty", name, p.Profile, p.ExploitabilityScope)
					}
				}
				raw := string(mustRead(t, path))
				for _, forbidden := range []string{"library_input", "library-public-api", "library-api"} {
					if strings.Contains(raw, forbidden) {
						t.Fatalf("%s leaks the library boundary field %q", name, forbidden)
					}
				}
			}
			en := string(readCaseArtifact(t, caseDir, c, "report.en.md"))
			ru := string(readCaseArtifact(t, caseDir, c, "report.md"))
			for _, forbidden := range []string{"exploitability scope library-api", "Library-API scope"} {
				if strings.Contains(strings.ToLower(en), strings.ToLower(forbidden)) {
					t.Fatalf("consumer report.en.md claims the library scope (%q)", forbidden)
				}
			}
			if strings.Contains(ru, "Область эксплуатации:** `library-api`") || strings.Contains(ru, "Область library-API") {
				t.Fatal("consumer report.md claims the library scope")
			}
		})
	}
}

// TestE2ELibraryPositiveNeedsReachAndLocus: a library-input-positive case is
// not a verdict by itself. With the independently mandatory reach or locus
// fact missing, the same admitted library claim stays INCONCLUSIVE and carries
// no scoped positive — failed admission is one thing, but proven selectability
// without a reachable defect is still an open question, never a negative.
func TestE2ELibraryPositiveNeedsReachAndLocus(t *testing.T) {
	base, _, _ := runLibraryE2E(t, libraryE2EOptions{
		fixture:   "libassertprod",
		requestID: libraryE2EAdvisoryID,
	})
	if base.Verdict == nil || base.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("baseline verdict=%+v, want the scoped positive", base.Verdict)
	}

	for _, tc := range []struct {
		name string
		drop domain.ConditionID
	}{
		{"reach missing", "C-REACH"},
		{"locus missing", "C-LOCUS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Work on a persisted copy of the completed case so the mutation
			// exercises the verdict integration, not a hand-built claim set.
			b, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var c domain.AnalysisCase
			if err := json.Unmarshal(b, &c); err != nil {
				t.Fatal(err)
			}
			found := false
			for i := range c.Claims {
				if c.Claims[i].ConditionID != tc.drop {
					continue
				}
				found = true
				c.Claims[i].Result = domain.ClaimUnknown
				c.Claims[i].Falsifier = ""
				c.Claims[i].NegativeVerification = nil
				c.Claims[i].EvidenceIDs = nil
				c.Claims[i].Explanation = "evidence collection did not establish this fact"
			}
			if !found {
				t.Fatalf("claim %s is missing from the completed case", tc.drop)
			}
			c.Verdict = nil
			c.Profiles = nil

			if _, err := (states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), &c); err != nil {
				t.Fatalf("EvaluateVerdict.Run: %v", err)
			}
			if c.Verdict != nil {
				t.Fatalf("verdict=%+v, want none: the unresolved %s must FAIL the assessment", c.Verdict, tc.drop)
			}
			if len(c.AnalysisGaps) == 0 {
				t.Fatalf("failed assessment carries no typed cause")
			}
			for _, p := range c.Profiles {
				if p.ExploitabilityScope != "" {
					t.Fatalf("failed profile %s carries scope=%q", p.Profile, p.ExploitabilityScope)
				}
				if p.Verdict != "" {
					t.Fatalf("failed profile %s retained verdict=%s", p.Profile, p.Verdict)
				}
			}
			// The library claim itself stays proven: the missing fact is a
			// different condition, and selectability alone is not a verdict.
			input := findClaimT(t, c.Claims, "C-INPUT")
			if input.Result != domain.ClaimTrue || input.ControlBasis != domain.ControlBasisLibraryPublicAPI {
				t.Fatalf("library input claim was disturbed: %+v", input)
			}
		})
	}
}

// TestE2ELibraryAdmissionControls pins the admissions the library proof must
// NOT acquire. The public-API payload proof is a narrow exception: it is
// available only for the DESERIALIZATION class over an advisory carrying
// CWE-502. Changing either fact must leave the same artifact unproven — never
// EXPLOITABLE and never scoped as a library API. This is the control that
// prevents recovering calibration counts by widening admission.
func TestE2ELibraryAdmissionControls(t *testing.T) {
	cases := []struct {
		name    string
		control func(*domain.Vulnerability)
		// wantClass is the exploit class the model builder derives after the
		// mutation; it documents why the gate is or is not reached. Only the
		// record's own CWE ids select a class, so a mutation that removes or
		// misnumbers the CWE leaves the class unestablished.
		wantClass string
		// wantNominatedClass is the class the textual vocabulary suggested.
		// It is recorded as a nomination and never selects a pattern: the
		// control asserts the vocabulary WAS present, so the refusal below is
		// caused by the missing structured signal and not by absent prose.
		wantNominatedClass string
	}{
		{
			name:      "non-DESERIALIZATION class (CWE-400)",
			wantClass: "RESOURCE_EXHAUSTION",
			control: func(v *domain.Vulnerability) {
				v.CWE = []string{"CWE-400"}
				v.Summary = "unbounded allocation while parsing a document"
				v.Description = "memory growth is unbounded for large documents"
			},
		},
		{
			name:               "DESERIALIZATION class without advisory CWE-502",
			wantClass:          "",
			wantNominatedClass: "DESERIALIZATION",
			control: func(v *domain.Vulnerability) {
				// The keyword classifier still derives DESERIALIZATION from a
				// dense deserialization vocabulary, but the admitted class also
				// requires the advisory CWE. The vocabulary alone is recorded as
				// a nomination and selects no pattern.
				v.CWE = nil
				v.Summary = "deserialization of untrusted documents: unmarshal of attacker-controlled payloads"
				v.Description = "the deserialization path unmarshals untrusted input; both operands are parsed with the affected deserializer"
			},
		},
		{
			name:               "adjacent CWE number is not CWE-502",
			wantClass:          "",
			wantNominatedClass: "DESERIALIZATION",
			control: func(v *domain.Vulnerability) {
				// Same vocabulary as the previous control; only the normalized
				// CWE identity differs, so only the CWE gate can refuse the
				// proof and the class stays unestablished.
				v.CWE = []string{"CWE-5020"}
				v.Summary = "deserialization of untrusted documents: unmarshal of attacker-controlled payloads"
				v.Description = "the deserialization path unmarshals untrusted input; both operands are parsed with the affected deserializer"
			},
		},
	}

	// The positive control: the unmodified advisory DOES admit the library
	// proof, so a refusal below is caused by the mutation only.
	base, _, _ := runLibraryE2E(t, libraryE2EOptions{
		fixture:   "libassertprod",
		requestID: libraryE2EAdvisoryID,
	})
	if base.Exploit == nil || base.Exploit.Class != "DESERIALIZATION" {
		t.Fatalf("baseline class=%v, want DESERIALIZATION", base.Exploit)
	}
	if input := findClaimT(t, base.Claims, "C-INPUT"); input.ControlBasis != domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("baseline C-INPUT basis=%q, want the library public-API proof", input.ControlBasis)
	}
	if len(libraryInputWitnesses(t, base)) != 2 {
		t.Fatalf("baseline witnessed bindings=%d, want both public formals", len(libraryInputWitnesses(t, base)))
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, caseDir := runLibraryE2E(t, libraryE2EOptions{
				fixture:          "libassertprod",
				requestID:        libraryE2EAdvisoryID,
				admissionControl: tc.control,
				expectUnproven:   true,
			})
			if c.Exploit == nil {
				t.Fatal("no exploit model was built")
			}
			if c.Exploit.Class != tc.wantClass {
				t.Fatalf("class=%s, want %q (the control must exercise the intended gate)",
					c.Exploit.Class, tc.wantClass)
			}
			if tc.wantNominatedClass != "" {
				nominated := false
				for _, n := range c.Exploit.MechanismNominations {
					if n.Kind == domain.MechanismNominationClass && n.Value == tc.wantNominatedClass {
						nominated = true
					}
				}
				if !nominated {
					t.Fatalf("the control's vocabulary did not even nominate %s: %+v",
						tc.wantNominatedClass, c.Exploit.MechanismNominations)
				}
				if !c.Exploit.UnresolvedMechanism {
					t.Fatal("a keyword-nominated class left the mechanism resolved")
				}
			}
			// No claim acquires the library basis. Candidate witnesses may
			// still be *recorded* (the trace is not admission), so the
			// observable is the claim basis, not the presence of a binding.
			for _, cl := range c.Claims {
				if cl.ControlBasis == domain.ControlBasisLibraryPublicAPI {
					t.Fatalf("claim %s acquired the library basis without admission: %+v", cl.ConditionID, cl)
				}
			}
			// The artifact is still vulnerable; only its exploitability
			// through the public API is unproven. That unfinished proof
			// must FAIL, never publish a safe or inconclusive verdict.
			if c.Verdict != nil {
				t.Fatalf("verdict=%+v (%s), want none without library admission",
					c.Verdict, c.Verdict.Reason)
			}
			if len(c.AnalysisGaps) == 0 {
				t.Fatalf("failed assessment carries no typed cause")
			}
			for _, p := range c.Profiles {
				if p.ExploitabilityScope != "" {
					t.Fatalf("profile %s scope=%q, want empty", p.Profile, p.ExploitabilityScope)
				}
				if p.Verdict != "" {
					t.Fatalf("failed profile %s retained verdict=%s", p.Profile, p.Verdict)
				}
			}
			// Persisted artifacts and VEX exports agree.
			for _, name := range []string{"report.json", "openvex.json", "cyclonedx.json"} {
				raw := string(mustRead(t, filepath.Join(caseDir, string(c.ID), name)))
				for _, forbidden := range []string{"library-public-api", "library-api"} {
					if strings.Contains(raw, forbidden) {
						t.Fatalf("%s claims the refused library boundary %q", name, forbidden)
					}
				}
			}
			en := string(readCaseArtifact(t, caseDir, c, "report.en.md"))
			if strings.Contains(strings.ToLower(en), "exploitability scope library-api") {
				t.Fatal("report.en.md claims the library scope without admission")
			}
		})
	}
}
