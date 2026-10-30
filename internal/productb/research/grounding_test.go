package research

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// groundFixture builds a report whose answer cites real snapshot files and
// runs analyzeAnswer + groundAnswer over it.
func groundFixture(t *testing.T, reasoning string) (*Report, string, advisoryResult) {
	t.Helper()
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"category":"vulnerable","reasoning":` + jsonString(reasoning) + `}`
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Report{
		RunID:     "ground-run",
		Artifacts: map[string]string{},
		Analysis: Analysis{
			Assumptions: ExtractionList{Items: []string{}},
			Unknowns:    ExtractionList{Items: []string{}},
		},
	}
	analyzeAnswer(Options{SnapshotDir: snap}, r, out)
	ares := advisoryResult{
		affected: []goAffectedRef{{
			am: pbdomain.AffectedModule{
				Module: "example.com/dep",
				AffectedPackages: []pbdomain.AffectedPackage{
					{Path: "example.com/prod/pkg", Symbols: []string{"X"}},
				},
			},
		}},
		cwes: []string{"CWE-22"},
	}
	groundAnswer(snap, out, r, ares, nil)
	return r, out, ares
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestGroundAnswerProjectsClaims(t *testing.T) {
	r, out, _ := groundFixture(t,
		"Root cause at pkg/x.go:3 inside pkg.X. CWE-22 applies.")
	if !r.Answer.Parsed || r.Answer.Category != "vulnerable" {
		t.Fatalf("answer contract changed: %+v", r.Answer)
	}
	if len(r.Analysis.RootCauseLocations) == 0 {
		t.Fatal("no root_cause_locations projected")
	}
	l := r.Analysis.RootCauseLocations[0]
	if l.Status != "verified_exact" || l.Path != "pkg/x.go" || l.Line != 3 {
		t.Fatalf("location: %+v", l)
	}
	var cweOK bool
	for _, a := range r.Analysis.MechanismAtoms {
		if a.Key == "CWE-22" && a.Status == "verified" {
			cweOK = true
		}
	}
	if !cweOK {
		t.Fatalf("mechanism atoms: %+v", r.Analysis.MechanismAtoms)
	}
	if r.Artifacts["reportcheck"] != "reportcheck.json" {
		t.Fatalf("artifact: %+v", r.Artifacts)
	}
	b, err := os.ReadFile(filepath.Join(out, "reportcheck.json"))
	if err != nil {
		t.Fatalf("reportcheck.json missing: %v", err)
	}
	var doc struct {
		Schema string `json:"schema"`
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("reportcheck.json: %v", err)
	}
	if doc.Schema != "izyan-reportcheck/1" || doc.CaseID != "ground-run" {
		t.Fatalf("reportcheck doc: %+v", doc)
	}
}

func TestGroundAnswerLeavesContractUntouched(t *testing.T) {
	r, _, _ := groundFixture(t, "Root cause at pkg/x.go:3.")
	before, _ := json.Marshal(r.Answer)
	// report.json round-trip: the answer block must serialize identically
	// whether or not grounding ran — the additive fields live elsewhere.
	var decoded struct {
		Answer   AnswerInfo `json:"answer"`
		Analysis struct {
			RootCauseLocations []json.RawMessage `json:"root_cause_locations"`
			UsageSites         []json.RawMessage `json:"usage_sites"`
			MechanismAtoms     []json.RawMessage `json:"mechanism_atoms"`
		} `json:"analysis"`
	}
	full, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(full, &decoded); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(decoded.Answer)
	if string(before) != string(after) {
		t.Fatal("answer block mutated by grounding")
	}
	if len(decoded.Analysis.RootCauseLocations) == 0 {
		t.Fatal("root_cause_locations absent from report.json")
	}
}

func TestGroundAnswerRendersSection(t *testing.T) {
	r, _, _ := groundFixture(t,
		"The defect is pkg/x.go:3. The product calls pkg/x.go:3 from main.")
	md := renderMarkdown(r)
	if !strings.Contains(md, "Citation grounding") {
		t.Fatal("report.md lacks the grounding section")
	}
	if !strings.Contains(md, "verified_exact") {
		t.Fatal("grounding section lacks statuses")
	}
}

func TestGroundAnswerNoAnswer(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Report{RunID: "empty-run", Artifacts: map[string]string{}, Analysis: Analysis{
		Assumptions: ExtractionList{Items: []string{}},
		Unknowns:    ExtractionList{Items: []string{}},
	}}
	groundAnswer(snap, out, r, advisoryResult{}, nil)
	if len(r.Analysis.RootCauseLocations) != 0 || len(r.Analysis.MechanismAtoms) != 0 {
		t.Fatal("grounding invented claims for a missing answer")
	}
	if renderMarkdown(r) == "" {
		t.Fatal("render failed without grounded claims")
	}
	if strings.Contains(renderMarkdown(r), "Citation grounding") {
		t.Fatal("empty grounding must not render a section")
	}
	if strings.Contains(renderMarkdown(r), "Path claims") {
		t.Fatal("empty grounding must not render a path-claims section")
	}
}

// legacyReportMD is the section layout report.md itself renders: a
// root-cause section with a resolvable citation and a usage section.
const legacyReportMD = `# CVE research — CVE-X

## Root cause

The defect is pkg/x.go:3 inside pkg.X.

## Usage paths

The product calls pkg/x.go:3 from main.
`

// A dossier that lost its raw answer still grounds from report.md: the
// legacy section is the claim source and parse.source says so.
func TestGroundAnswerLegacyMarkdownWithoutRaw(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "report.md"), []byte(legacyReportMD), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Report{RunID: "legacy-run", Artifacts: map[string]string{}, Analysis: Analysis{
		Assumptions: ExtractionList{Items: []string{}},
		Unknowns:    ExtractionList{Items: []string{}},
	}}
	groundAnswer(snap, out, r, advisoryResult{}, nil)

	if len(r.Analysis.RootCauseLocations) == 0 {
		t.Fatal("no root_cause_locations grounded from report.md")
	}
	l := r.Analysis.RootCauseLocations[0]
	if l.Path != "pkg/x.go" || l.Line != 3 || l.Status != "verified_exact" {
		t.Fatalf("grounded location = %+v", l)
	}
	if len(r.Analysis.UsageSites) == 0 {
		t.Fatal("usage section not projected")
	}
	doc := readReportcheck(t, out)
	if doc.Parse.Source != "legacy_md" {
		t.Fatalf("parse.source = %q, want legacy_md", doc.Parse.Source)
	}
}

// The contract source ladder is structured → legacy_md → raw_answer; a
// raw answer never outranks report.md, and structured claims outrank both.
func TestGroundAnswerSourcePriority(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"category":"vulnerable","reasoning":"The defect is in main.go:3."}`
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "report.md"), []byte(legacyReportMD), 0o644); err != nil {
		t.Fatal(err)
	}

	// No structured claims: report.md wins over the raw answer.
	r := &Report{RunID: "prio-md", Artifacts: map[string]string{}, Analysis: Analysis{
		Assumptions: ExtractionList{Items: []string{}},
		Unknowns:    ExtractionList{Items: []string{}},
	}}
	groundAnswer(snap, out, r, advisoryResult{}, nil)
	doc := readReportcheck(t, out)
	if doc.Parse.Source != "legacy_md" {
		t.Fatalf("with raw+md and no structured claims: source = %q, want legacy_md", doc.Parse.Source)
	}
	for _, l := range r.Analysis.RootCauseLocations {
		if l.Path == "main.go" {
			t.Fatalf("raw-answer claim outranked report.md: %+v", l)
		}
	}

	// Structured claims win over both.
	r2 := &Report{RunID: "prio-structured", Artifacts: map[string]string{}, Analysis: Analysis{
		RootCause:   "The defect is pkg/x.go:3.",
		Assumptions: ExtractionList{Items: []string{}},
		Unknowns:    ExtractionList{Items: []string{}},
	}}
	groundAnswer(snap, out, r2, advisoryResult{}, nil)
	doc = readReportcheck(t, out)
	if doc.Parse.Source != "structured" {
		t.Fatalf("with structured claims: source = %q, want structured", doc.Parse.Source)
	}
}

// Replay of a dossier whose raw answer is gone but whose report.md
// survived still produces grounded claims from the legacy section.
func TestReplayRunWithoutRawAnswerGroundsFromReportMD(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	answer := `{"category":"vulnerable","reasoning":"The defect is in pkg/x.go:3 inside pkg.X."}`
	export := `{"messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":` +
		mustJSONRaw(t, answer) + `}]}]}`
	stub := stubDocker(t, strings.Replace(dockerStubOK, "AGENT_STDOUT_PAYLOAD", export, 1))

	orig, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		AllowAgent: true, DockerBin: stub,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	origDir := filepath.Join(out, "runs", orig.RunID)
	if len(orig.Analysis.RootCauseLocations) == 0 {
		t.Fatalf("live run did not ground: %+v", orig.Analysis)
	}
	// Simulate an old dossier: only report.md survives, no raw answer.
	if err := os.Remove(filepath.Join(origDir, "raw_agent_output.txt")); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Options{ReplayRun: origDir})
	if err != nil {
		t.Fatalf("ReplayRun without raw answer: %v", err)
	}
	if len(rep.Analysis.RootCauseLocations) == 0 {
		t.Fatal("replay produced no grounded claims from report.md")
	}
	if rep.Answer.Category != orig.Answer.Category || rep.Answer.Reasoning != orig.Answer.Reasoning {
		t.Fatalf("stored answer not carried verbatim: %+v", rep.Answer)
	}
	newDir := filepath.Join(out, "runs", rep.RunID)
	doc := readReportcheck(t, newDir)
	if doc.Parse.Source != "legacy_md" {
		t.Fatalf("replay parse.source = %q, want legacy_md", doc.Parse.Source)
	}
	if _, err := os.Stat(filepath.Join(newDir, "raw_agent_output.txt")); err == nil {
		t.Fatal("replay invented a raw answer")
	}
}

// readReportcheck decodes the dossier's grounding artifact.
func readReportcheck(t *testing.T, dir string) struct {
	CaseID string `json:"case_id"`
	Report struct {
		Category        string `json:"category"`
		ReasoningSHA256 string `json:"reasoning_sha256"`
	} `json:"report"`
	Parse struct {
		Source string `json:"source"`
	} `json:"parse"`
	Claims struct {
		Locations []struct {
			Raw string `json:"raw"`
		} `json:"locations"`
		Negative []struct {
			Raw      string `json:"raw"`
			Polarity string `json:"polarity"`
			Scope    string `json:"scope"`
		} `json:"negative"`
	} `json:"claims"`
} {
	t.Helper()
	var doc struct {
		CaseID string `json:"case_id"`
		Report struct {
			Category        string `json:"category"`
			ReasoningSHA256 string `json:"reasoning_sha256"`
		} `json:"report"`
		Parse struct {
			Source string `json:"source"`
		} `json:"parse"`
		Claims struct {
			Locations []struct {
				Raw string `json:"raw"`
			} `json:"locations"`
			Negative []struct {
				Raw      string `json:"raw"`
				Polarity string `json:"polarity"`
				Scope    string `json:"scope"`
			} `json:"negative"`
		} `json:"claims"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "reportcheck.json"))
	if err != nil {
		t.Fatalf("reportcheck.json: %v", err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("reportcheck.json: %v", err)
	}
	return doc
}

// caddyShapedSnapshot reproduces the observed misclassification shape: a
// version citation in go.mod, a checksum citation in go.sum, and import
// block lines in listeners.go/server.go/httptransport.go — plus one real
// call site inside a function body.
func caddyShapedSnapshot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "0123456789abcdef0123456789abcdef01234567")
	write := func(rel, body string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gomod := []string{"module github.com/caddyserver/caddy/v2", "", "go 1.22", ""}
	for len(gomod) < 30 {
		gomod = append(gomod, "// dependency note")
	}
	write("go.mod", strings.Join(gomod, "\n")+"\n")
	write("go.sum", "example.com/dep v1.0.0 h1:x=\n")

	listeners := []string{"package caddyhttp", ""}
	for len(listeners) < 30 {
		listeners = append(listeners, "// pad")
	}
	listeners = append(listeners, "import (", "\t\"net\"", "\t\"net/http\"", "\t\"sync\"", ")", "",
		"// Listen starts the listener.", "func Listen() {", "\t_, _ = net.Listen(\"tcp\", \"\")", "\t_ = http.DefaultClient", "}")
	write("modules/caddyhttp/listeners.go", strings.Join(listeners, "\n")+"\n")

	server := []string{"package caddyhttp", ""}
	for len(server) < 31 {
		server = append(server, "// pad")
	}
	server = append(server, "import (", "\t\"context\"", "\t\"net/http\"", "\t\"time\"", ")", "")
	for len(server) < 54 {
		server = append(server, "// pad")
	}
	server = append(server, "func Serve(ctx context.Context) error {")
	for len(server) < 59 {
		server = append(server, "\t_ = ctx")
	}
	server = append(server, "\tsrv := &http.Server{}", "\t_ = srv", "\treturn nil", "}")
	write("modules/caddyhttp/server.go", strings.Join(server, "\n")+"\n")

	transport := []string{"package reverseproxy", ""}
	for len(transport) < 31 {
		transport = append(transport, "// pad")
	}
	transport = append(transport, "import (", "\t\"net/http\"", "\t\"sync\"", "\t\"time\"", ")")
	write("modules/caddyhttp/reverseproxy/httptransport.go", strings.Join(transport, "\n")+"\n")
	return root
}

// Manifest/checksum citations and import lines never become root-cause
// locations or usage sites; a real call site inside a function still does.
func TestProjectionExcludesMetadataAndImports(t *testing.T) {
	snap := caddyShapedSnapshot(t)
	out := t.TempDir()
	md := `# CVE research — CVE-X

## Root cause

Caddy v2 is affected (go.mod:22); checksum go.sum:400.

## Usage paths

The product calls net.Listen at modules/caddyhttp/listeners.go:32-34.
The product calls caddyhttp.Serve at modules/caddyhttp/server.go:34-36.
The product calls http.Transport at modules/caddyhttp/reverseproxy/httptransport.go:35.
The product calls caddyhttp.Serve at modules/caddyhttp/server.go:60.
`
	r := &Report{RunID: "caddy-run", Artifacts: map[string]string{}, Analysis: Analysis{
		Assumptions: ExtractionList{Items: []string{}},
		Unknowns:    ExtractionList{Items: []string{}},
	}}
	groundAnswer(snap, out, r, advisoryResult{}, []byte(md))

	// Root-cause locations: no manifests or checksums.
	for _, l := range r.Analysis.RootCauseLocations {
		if l.Path == "go.mod" || l.Path == "go.sum" {
			t.Fatalf("metadata leaked into root_cause_locations: %+v", l)
		}
	}
	// Usage sites: only the concrete call site inside Serve.
	if len(r.Analysis.UsageSites) != 1 {
		t.Fatalf("usage sites = %+v, want exactly server.go:60", r.Analysis.UsageSites)
	}
	u := r.Analysis.UsageSites[0]
	if u.Path != "modules/caddyhttp/server.go" || u.Line != 60 || u.Kind != "usage" {
		t.Fatalf("usage site = %+v", u)
	}
	// Every presence-only citation lands in citation_metadata.
	want := map[string]bool{
		"go.mod:22":                            false,
		"go.sum:400":                           false,
		"modules/caddyhttp/listeners.go:32-34": false,
		"modules/caddyhttp/server.go:34-36":    false,
		"modules/caddyhttp/reverseproxy/httptransport.go:35": false,
	}
	for _, l := range r.Analysis.CitationMetadata {
		want[l.Raw] = true
		if l.Kind != "metadata" && l.Kind != "import" {
			t.Fatalf("metadata citation kind = %q: %+v", l.Kind, l)
		}
	}
	for raw, seen := range want {
		if !seen {
			t.Fatalf("citation %q missing from citation_metadata: %+v", raw, r.Analysis.CitationMetadata)
		}
	}
	// The rendered report shows the presence-only section, and the
	// grounding artifact records legacy_md for the replay case.
	rendered := renderMarkdown(r)
	if !strings.Contains(rendered, "Metadata / import citations") {
		t.Fatal("report.md lacks the metadata section")
	}
	doc := readReportcheck(t, out)
	if doc.Parse.Source != "legacy_md" {
		t.Fatalf("parse.source = %q, want legacy_md", doc.Parse.Source)
	}
}

// Replay of a caddy-shaped dossier (raw answer gone, report.md surviving)
// keeps manifests and import lines out of both projections.
func TestReplayRunCaddyShapedClaimsExcluded(t *testing.T) {
	snap := caddyShapedSnapshot(t)
	out := filepath.Join(t.TempDir(), "out")
	adv := filepath.Join(t.TempDir(), "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	answer := `{"category":"vulnerable","reasoning":"The defect is the pinned version at go.mod:22. ` +
		`The product calls net.Listen at modules/caddyhttp/listeners.go:32-34 and caddyhttp.Serve at modules/caddyhttp/server.go:60."}`
	export := `{"messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":` +
		mustJSONRaw(t, answer) + `}]}]}`
	stub := stubDocker(t, strings.Replace(dockerStubOK, "AGENT_STDOUT_PAYLOAD", export, 1))

	const caseID = "caddyserver-caddy-8dc7667-CVE-2025-29785"
	orig, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		CaseID:     caseID,
		AllowAgent: true, DockerBin: stub,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if orig.Request.CaseID != caseID {
		t.Fatalf("request.case_id = %q, want %q", orig.Request.CaseID, caseID)
	}
	origDir := filepath.Join(out, "runs", orig.RunID)
	if got := readReportcheck(t, origDir).CaseID; got != caseID {
		t.Fatalf("reportcheck case_id = %q, want the controller case id", got)
	}
	if err := os.Remove(filepath.Join(origDir, "raw_agent_output.txt")); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{ReplayRun: origDir})
	if err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	for _, l := range rep.Analysis.RootCauseLocations {
		if l.Path == "go.mod" || l.Path == "go.sum" {
			t.Fatalf("metadata in root_cause_locations after replay: %+v", l)
		}
	}
	for _, l := range rep.Analysis.UsageSites {
		if l.Kind != "usage" {
			t.Fatalf("non-usage kind in usage_sites: %+v", l)
		}
		if strings.HasPrefix(l.Path, "modules/caddyhttp/listeners.go") {
			t.Fatalf("import line in usage_sites: %+v", l)
		}
	}
	md := renderMarkdown(rep)
	if !strings.Contains(md, "Metadata / import citations") {
		t.Fatal("re-rendered report.md lacks the metadata section")
	}
	if rep.Request.CaseID != caseID {
		t.Fatalf("replay dropped the stored case id: %q", rep.Request.CaseID)
	}
	if got := readReportcheck(t, filepath.Join(out, "runs", rep.RunID)).CaseID; got != caseID {
		t.Fatalf("replay reportcheck case_id = %q, want %q", got, caseID)
	}

	// --case-id on replay overrides the stored key without touching the
	// run identity.
	rep2, err := Run(context.Background(), Options{ReplayRun: origDir, CaseID: "override-case"})
	if err != nil {
		t.Fatalf("ReplayRun with --case-id: %v", err)
	}
	if rep2.Request.CaseID != "override-case" || rep2.RerenderOf != orig.RunID {
		t.Fatalf("override request: %+v", rep2.Request)
	}
	if got := readReportcheck(t, filepath.Join(out, "runs", rep2.RunID)).CaseID; got != "override-case" {
		t.Fatalf("override reportcheck case_id = %q", got)
	}
}

// Without --case-id the run id is the join key (legacy behaviour).
func TestGroundingCaseIDFallsBackToRunID(t *testing.T) {
	snap := caddyShapedSnapshot(t)
	out := t.TempDir()
	r := &Report{RunID: "20261019T224228Z", Artifacts: map[string]string{}, Analysis: Analysis{
		RootCause:   "The defect is at modules/caddyhttp/server.go:60.",
		Assumptions: ExtractionList{Items: []string{}},
		Unknowns:    ExtractionList{Items: []string{}},
	}}
	groundAnswer(snap, out, r, advisoryResult{}, []byte(legacyReportMD))
	if got := readReportcheck(t, out).CaseID; got != "20261019T224228Z" {
		t.Fatalf("case_id = %q, want the run id fallback", got)
	}
}

// A dossier replay with an absence statement keeps the official category
// and surfaces the absence claim: the podman case, end to end.
func TestReplayRunKeepsCategoryAndAbsenceClaim(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	reasoning := "The package example.com/ssh/agent is imported but never used from first-party code."
	answer := `{"category":"code_not_reachable","reasoning":` + jsonString(reasoning) + `}`
	export := `{"messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":` +
		mustJSONRaw(t, answer) + `}]}]}`
	stub := stubDocker(t, strings.Replace(dockerStubOK, "AGENT_STDOUT_PAYLOAD", export, 1))

	orig, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		CaseID:     "podman-case",
		AllowAgent: true, DockerBin: stub,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	origDoc := readReportcheck(t, filepath.Join(out, "runs", orig.RunID))
	if origDoc.Report.Category != "code_not_reachable" {
		t.Fatalf("live report.category = %q", origDoc.Report.Category)
	}
	if origDoc.Report.ReasoningSHA256 == "" {
		t.Fatal("live report.reasoning_sha256 missing")
	}
	if !hasAbsenceClaim(origDoc.Claims.Negative) {
		t.Fatalf("live negative claims: %+v", origDoc.Claims.Negative)
	}

	// Legacy dossier: raw answer gone, report.md survives.
	origDir := filepath.Join(out, "runs", orig.RunID)
	if err := os.Remove(filepath.Join(origDir, "raw_agent_output.txt")); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{ReplayRun: origDir})
	if err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	if rep.Answer.Category != "code_not_reachable" || rep.Answer.Reasoning != reasoning {
		t.Fatalf("answer contract changed: %+v", rep.Answer)
	}
	doc := readReportcheck(t, filepath.Join(out, "runs", rep.RunID))
	if doc.Parse.Source != "legacy_md" {
		t.Fatalf("replay source = %q", doc.Parse.Source)
	}
	if doc.Report.Category != "code_not_reachable" {
		t.Fatalf("replay report.category = %q", doc.Report.Category)
	}
	if !hasAbsenceClaim(doc.Claims.Negative) {
		t.Fatalf("replay negative claims: %+v", doc.Claims.Negative)
	}
	if len(rep.Analysis.NegativeClaims) == 0 {
		t.Fatal("analysis.negative_claims not projected")
	}
	for _, c := range rep.Analysis.NegativeClaims {
		if c.Polarity != "absence" || c.Scope != "first_party" {
			t.Fatalf("path claim = %+v, want absence/first_party", c)
		}
	}
	if !strings.Contains(renderMarkdown(rep), "Path claims (negative / presence)") {
		t.Fatal("report.md lacks the path-claims section")
	}
}

func hasAbsenceClaim(claims []struct {
	Raw      string `json:"raw"`
	Polarity string `json:"polarity"`
	Scope    string `json:"scope"`
}) bool {
	for _, c := range claims {
		if c.Polarity == "absence" && strings.Contains(c.Raw, "never used from first-party code") {
			return true
		}
	}
	return false
}
