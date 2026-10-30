package rootcause

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fix"
	"github.com/davniy/izyan/internal/goanalysis"
)

func depVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GO-TEST-1",
		Module: "example.com/dep",
		AffectedPackages: []domain.AffectedPackage{
			{Path: "example.com/dep/vuln", Symbols: []string{"Parse"}},
		},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
		},
		References: []domain.Reference{
			{Type: "FIX", URL: "https://example.com/dep/commit/abc"},
		},
		FixedVersions: []string{"v1.0.1"},
	}
}

func TestResolveFromAdvisorySymbols(t *testing.T) {
	m, evs, err := Resolver{}.Resolve(context.Background(), &domain.AnalysisCase{}, depVuln())
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 {
		t.Fatalf("model=%+v", m)
	}
	if m.RootCauses[0].Symbol != "Parse" || m.RootCauses[0].Role != domain.RootCauseSink {
		t.Fatalf("rc=%+v", m.RootCauses[0])
	}
	if len(evs) == 0 {
		t.Fatal("expected advisory evidence")
	}
}

// fakePatch serves one captured body for every locator it is asked for. The
// single-artifact shape covers the fixtures that only need "the fix diff"; the
// full artifact-set accounting is exercised with fix.CapturedProvider.
type fakePatch struct {
	out      string
	err      error
	requests []string
}

func (f *fakePatch) Acquire(_ context.Context, ref fix.Reference) domain.FixArtifact {
	f.requests = append(f.requests, ref.URL)
	record := domain.FixArtifact{Locator: ref.URL, Kind: ref.Kind, Provenance: "test fake"}
	if f.err != nil {
		record.Outcome = domain.FixArtifactAcquisitionFailed
		record.Detail = f.err.Error()
		return record
	}
	record.Outcome = domain.FixArtifactComplete
	record.Digest = domain.EvidenceContentDigest(f.out)
	record.Size = len(f.out)
	record.Bytes = f.out
	record.Detail = "served by the test fake"
	return record
}

func TestResolveFromPatch(t *testing.T) {
	v := depVuln()
	v.AffectedSymbols = nil // force patch path
	p := &fakePatch{out: `diff --git a/vuln/vuln.go b/vuln/vuln.go
index 1..2 100644
--- a/vuln/vuln.go
+++ b/vuln/vuln.go
@@ -5,3 +5,4 @@ func Parse(s string) (string, error) {
-	return s, nil
+	if s == "" { return "", errors.New("empty") }
+	return s, nil
`}
	r := Resolver{Patch: p}
	m, evs, err := r.Resolve(context.Background(), &domain.AnalysisCase{}, v)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 {
		t.Fatalf("model=%+v", m)
	}
	rc := m.RootCauses[0]
	if rc.Symbol != "Parse" || rc.Package != "example.com/dep/vuln" {
		t.Fatalf("rc=%+v", rc)
	}
	var hasFix bool
	for _, e := range evs {
		if e.Kind == domain.EvidenceFixDiff {
			hasFix = true
		}
	}
	if !hasFix {
		t.Fatal("expected FIX_DIFF evidence")
	}
}

func TestResolveNotFound(t *testing.T) {
	m, _, err := Resolver{}.Resolve(context.Background(), &domain.AnalysisCase{}, domain.Vulnerability{ID: "X"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseNotFound {
		t.Fatalf("status=%s", m.Status)
	}
}

func TestVerifierDropsUnknown(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	if err != nil {
		t.Fatal(err)
	}
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink},
			{Package: "example.com/dep/vuln", Symbol: "Nope", Role: domain.RootCauseSink},
		},
	}
	lim := vf.Verify(context.Background(), nil, m, depVuln())
	if len(m.RootCauses) != 1 || m.RootCauses[0].Symbol != "Parse" {
		t.Fatalf("root causes=%+v lim=%v", m.RootCauses, lim)
	}
	if len(m.Alternatives) != 1 || m.Alternatives[0].Symbol != "Nope" {
		t.Fatalf("alternatives=%+v", m.Alternatives)
	}
	if len(m.Unverified) != 1 || m.Unverified[0].Symbol != "Nope" {
		t.Fatalf("unverified=%+v — in-scope candidate that failed resolution must be flagged", m.Unverified)
	}
}

// A candidate outside the advisory's affected packages is an alternative,
// not an unverified in-scope sink — it must not block the exploit model.
func TestVerifierOutOfScopeNotUnverified(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink},
			{Package: "example.com/dep/other", Symbol: "Fn", Role: domain.RootCauseSink},
		},
	}
	vf.Verify(context.Background(), nil, m, depVuln())
	if len(m.Unverified) != 0 {
		t.Fatalf("unverified=%+v — out-of-scope drop is not a verification failure", m.Unverified)
	}
}

func TestVerifierRejectsForeignPackage(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	v := depVuln()
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/other", Symbol: "Fn", Role: domain.RootCauseSink},
		},
	}
	vf.Verify(context.Background(), nil, m, v)
	if m.Status != domain.RootCauseAmbiguous {
		t.Fatalf("status=%s want AMBIGUOUS (all candidates rejected)", m.Status)
	}
}

// rootCauseProduct returns a snapshot with an admitted artifact-build-info
// target: the product-build gate every package-absence conclusion needs.
func rootCauseProduct() domain.ProductSnapshot {
	p := domain.ProductSnapshot{Repository: "/repo", Commit: "deadbeef", GOOS: "linux", GOARCH: "amd64"}
	p.Target = &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source:          domain.ProductTargetSourceArtifactBuildInfo,
		Scope:           domain.ProductTargetScopeArtifact,
		ArtifactSHA256:  strings.Repeat("a", 64),
		BuildInfoSHA256: strings.Repeat("b", 64),
	}
	return p
}

// completePackageListEvidence records a completed, complete package-list
// inventory for the snapshot's effective build context.
func completePackageListEvidence(id string, snapshot domain.ProductSnapshot, content string) domain.Evidence {
	ctx := domain.EffectiveBuildContext(snapshot)
	return domain.Evidence{
		ID:           domain.EvidenceID(id),
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Tool:         "go",
		Source:       "go list -deps -test -json ./...",
		Command:      "go list -deps -test -json ./...",
		Content:      content,
		BuildContext: &ctx,
		PackageList: &domain.PackageListRun{
			Completed: true,
			Complete:  true,
			WithTests: true,
			Pattern:   "./...",
		},
	}
}

// A candidate whose package never entered the product's build graph is
// resolved by absence — but only from a completed, complete inventory whose
// context matches the snapshot. It must stay in RootCauses flagged Absent so
// locus and reachability evaluation can ground falsifiers on it.
func TestRootCauseAbsent(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	// The record declares both packages: their identity as subjects of the
	// advisory is the entry itself, so absence from the build graph is
	// evidence about real subjects.
	v := domain.Vulnerability{
		ID: "GO-TEST-ABS",
		AffectedPackages: []domain.AffectedPackage{
			{Path: "example.com/dep/vuln"},
			{Path: "example.com/dep/xds"},
		},
	}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink},
			{Package: "example.com/dep/vuln", Symbol: "Nope", Role: domain.RootCauseSink},
			{Package: "example.com/dep/xds", Symbol: "RouteAndProcess", Role: domain.RootCauseSink},
		},
	}
	product := rootCauseProduct()
	c := &domain.AnalysisCase{Product: product}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		completePackageListEvidence("EV-PKGS", product,
			`{"ImportPath":"example.com/constprod"}{"ImportPath":"example.com/dep/vuln"}`))
	vf.Verify(context.Background(), c, m, v)
	if m.Status != domain.RootCauseResolved {
		t.Fatalf("status=%s", m.Status)
	}
	var found bool
	for _, rc := range m.RootCauses {
		if rc.Symbol == "RouteAndProcess" {
			found = true
			if !rc.Absent {
				t.Fatalf("xds candidate must be flagged Absent: %+v", rc)
			}
		}
	}
	if !found {
		t.Fatalf("absent-package candidate dropped from RootCauses: %+v", m.RootCauses)
	}
	if len(m.Unverified) != 1 || m.Unverified[0].Symbol != "Nope" {
		t.Fatalf("unverified=%+v — present-package miss stays a verification gap", m.Unverified)
	}
}

// Without package-list evidence absence is unknown: the same candidate
// stays a verification failure, never a silent negative.
func TestVerifierAbsentNeedsPackageList(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	v := domain.Vulnerability{ID: "GO-TEST-ABS"}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/xds", Symbol: "RouteAndProcess", Role: domain.RootCauseSink},
		},
	}
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	vf.Verify(context.Background(), c, m, v)
	if len(m.Unverified) != 1 {
		t.Fatalf("unverified=%+v — no build graph, no absence", m.Unverified)
	}
	if m.Status != domain.RootCauseAmbiguous {
		t.Fatalf("status=%s want AMBIGUOUS", m.Status)
	}
}

// A corrupt package list proves nothing even when it claims to be a
// completed, complete inventory: the strict decoder must fail, so the
// candidate stays unverified.
func TestVerifierAbsentCorruptPackageList(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	v := domain.Vulnerability{ID: "GO-TEST-ABS"}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/xds", Symbol: "RouteAndProcess", Role: domain.RootCauseSink},
		},
	}
	product := rootCauseProduct()
	c := &domain.AnalysisCase{Product: product}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		completePackageListEvidence("EV-PKGS", product, `{garbage`))
	vf.Verify(context.Background(), c, m, v)
	if len(m.Unverified) != 1 {
		t.Fatalf("unverified=%+v — corrupt list is not absence evidence", m.Unverified)
	}
}

// vendorRefusingProduct writes a vendored snapshot the Go loader refuses: the
// go 1.15 module replaces example.com/dep by module version, which a modern
// toolchain will not resolve under -mod=vendor. The vendored package is still
// on disk — the k8s-3121 shape.
func vendorRefusingProduct(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":             "module example.com/prod\n\ngo 1.15\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => example.com/dep v1.0.0\n",
		"prod.go":            "package prod\n\nfunc Main() {}\n",
		"vendor/modules.txt": "# example.com/dep v1.0.0 => example.com/dep v1.0.0\n## explicit\nexample.com/dep/pkg\n",
		"vendor/example.com/dep/pkg/file.go": "" +
			"package pkg\n\n" +
			"type unmarshal struct{}\n\n" +
			"func (p *unmarshal) Generate() {}\n\n" +
			"func (p *unmarshal) field() {}\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hasLimitation(lims []string, sub string) bool {
	for _, l := range lims {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// A loader refusal on a vendored snapshot must not demote advisory symbols to
// Alternatives: the vendored tree is the build input, and its declaration is
// the verification. A symbol the vendored source does not declare stays
// unverified — the loader gap is never absence.
func TestVerifierResolvesVendoredSymbolWhenLoaderFails(t *testing.T) {
	vf := Verifier{Source: &goanalysis.Index{
		Dir:        vendorRefusingProduct(t),
		Build:      domain.ProductSnapshot{VendorMode: true},
		ReplaceEnv: true,
		Env:        []string{"GOPROXY=off", "GOWORK=off"},
	}}
	v := domain.Vulnerability{
		ID:               "GO-TEST-VENDOR",
		Module:           "example.com/dep",
		AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/pkg"}},
		AffectedSymbols:  []domain.SymbolRef{{Package: "example.com/dep/pkg", Symbol: "unmarshal.Generate"}},
	}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/pkg", Symbol: "unmarshal.Generate", Role: domain.RootCauseSink},
		},
	}
	lim := vf.Verify(context.Background(), nil, m, v)
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 ||
		len(m.Alternatives) != 0 || len(m.Unverified) != 0 {
		t.Fatalf("vendored symbol not verified: model=%+v lim=%v", m, lim)
	}
	if !hasLimitation(lim, "verified against vendored source") {
		t.Fatalf("limitations=%v — the vendored-source basis must be recorded", lim)
	}

	missing := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/pkg", Symbol: "unmarshal.Missing", Role: domain.RootCauseSink},
		},
	}
	lim = vf.Verify(context.Background(), nil, missing, v)
	if missing.Status != domain.RootCauseAmbiguous || len(missing.RootCauses) != 0 ||
		len(missing.Alternatives) != 1 || len(missing.Unverified) != 1 {
		t.Fatalf("undeclared symbol must stay unverified: model=%+v lim=%v", missing, lim)
	}
	if !hasLimitation(lim, "Go loader failed") {
		t.Fatalf("limitations=%v — the loader failure must be named", lim)
	}
	if hasLimitation(lim, "not found in source") {
		t.Fatalf("limitations=%v — a loader failure must not read as a negative result", lim)
	}
}

func containsEvidenceID(ids []domain.EvidenceID, want domain.EvidenceID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// A candidate that resolves from the module cache is still product-absent when
// its package never entered the admitted complete closure: absence is decided
// before product-independent source lookup, and the inventory is cited.
// Under the old ordering the successful lookup retained the subject without
// Absent=true, conflating "exists in dependency source" with "linked into the
// product".
func TestCandidateAbsenceDecidedBeforeSourceLookup(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	product := rootCauseProduct()
	c := &domain.AnalysisCase{Product: product}
	// Only the product package is linked; example.com/dep/vuln is present in
	// the dependency source but outside the product closure.
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		completePackageListEvidence("EV-PKGS", product,
			`{"ImportPath":"example.com/constprod"}`))
	v := domain.Vulnerability{
		ID:               "GO-TEST-ABS",
		AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
	}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginAdvisory},
		},
	}
	lim := vf.Verify(context.Background(), c, m, v)
	if len(m.RootCauses) != 1 || !m.RootCauses[0].Absent {
		t.Fatalf("source-present but product-unlinked candidate must be Absent: model=%+v lim=%v", m, lim)
	}
	if len(m.Unverified) != 0 {
		t.Fatalf("unverified=%+v — verified absence is not a source-verification failure", m.Unverified)
	}
	if !containsEvidenceID(m.RootCauses[0].EvidenceIDs, "EV-PKGS") {
		t.Fatalf("evidence=%v — absence must cite the admitted inventory", m.RootCauses[0].EvidenceIDs)
	}
	if !hasLimitation(lim, "resolved by absence") || !hasLimitation(lim, "EV-PKGS") {
		t.Fatalf("limitations=%v — the absence basis must be named", lim)
	}
	if !hasLimitation(lim, "admitted product build graph") {
		t.Fatalf("limitations=%v — absence must name the admitted closure", lim)
	}
}

// Absence needs an admitted complete inventory even when the symbol loads from
// dependency source: a missing or non-admitting list measures nothing, so the
// candidate stays verified-present, never absent-by-default.
func TestCandidateAbsenceRequiresAdmittedInventory(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	product := rootCauseProduct()
	v := domain.Vulnerability{
		ID:               "GO-TEST-ABS",
		AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
	}
	cases := []struct {
		name string
		add  func(*domain.AnalysisCase)
	}{
		{name: "no package-list evidence", add: func(*domain.AnalysisCase) {}},
		{name: "unadmitted list", add: func(c *domain.AnalysisCase) {
			c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
				partialPackageListEvidence(product, nil, `{"ImportPath":"example.com/constprod"}`))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &domain.AnalysisCase{Product: product}
			tc.add(c)
			m := &domain.RootCauseModel{
				Status: domain.RootCauseResolved,
				RootCauses: []domain.RootCause{
					{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink},
				},
			}
			vf.Verify(context.Background(), c, m, v)
			if len(m.RootCauses) != 1 || m.RootCauses[0].Absent {
				t.Fatalf("candidate marked absent without an admitted inventory: %+v", m.RootCauses)
			}
			if len(m.Unverified) != 0 {
				t.Fatalf("unverified=%+v — a source-verified symbol is not a lookup failure", m.Unverified)
			}
		})
	}
}

// One absent subject beside one linked subject must keep their states apart:
// only the unlinked package is absence evidence, and the linked subject stays
// a verified-present sink rather than joining the absent set.
func TestCandidateAbsenceMixedPresence(t *testing.T) {
	// The dependency source is present at the selected version, so the
	// fix-derived candidate's coordinate binds and its missing package is a
	// real product fact; the advisory-declared subject stays linked.
	root := selectedSourceFixture(t, "example.com/dep", "v1.0.0", map[string]string{
		"vuln/vuln.go": "package vuln\n\nfunc Parse() {}\n",
		"xds/xds.go":   "package xds\n\nfunc RouteAndProcess() {}\n",
	})
	vf := Verifier{Source: &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}}}
	product := rootCauseProduct()
	c := &domain.AnalysisCase{
		Product: product,
		Affected: &domain.AffectedResult{
			SelectedModule:  "example.com/dep",
			SelectedModules: []string{"example.com/dep"},
			ResolvedVersion: "v1.0.0",
		},
	}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		completePackageListEvidence("EV-PKGS", product,
			`{"ImportPath":"example.com/constprod"}{"ImportPath":"example.com/dep/vuln"}`))
	// The record declares both packages: absence from the build graph is
	// evidence about declared subjects, and that declaration is the
	// affirmative basis. The fix-derived candidate still carries its resolving
	// coordinate binding, but a coordinate binding is not absence authority —
	// the record's own declaration is what admits the absent subject, while
	// the linked subject stays a verified-present sink.
	v := domain.Vulnerability{
		ID: "GO-TEST-ABS",
		AffectedPackages: []domain.AffectedPackage{
			{Path: "example.com/dep/vuln"},
			{Path: "example.com/dep/xds"},
		},
	}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginAdvisory},
			{Package: "example.com/dep/xds", Symbol: "RouteAndProcess", Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginFixDerived,
				Binding: &domain.CandidateBinding{
					Status: domain.CandidateBindingUnmeasured, Module: "example.com/dep", PatchPath: "xds/xds.go",
				}},
		},
	}
	vf.Verify(context.Background(), c, m, v)
	if len(m.RootCauses) != 2 {
		t.Fatalf("root causes=%+v — a mixed model keeps both subjects", m.RootCauses)
	}
	var absent, present int
	for _, rc := range m.RootCauses {
		switch {
		case rc.Symbol == "RouteAndProcess":
			if !rc.Absent {
				t.Fatalf("unlinked subject must be absent: %+v", rc)
			}
			absent++
		case rc.Symbol == "Parse":
			if rc.Absent {
				t.Fatalf("linked subject must not be marked absent: %+v", rc)
			}
			present++
		}
	}
	if absent != 1 || present != 1 {
		t.Fatalf("absent=%d present=%d — mixed presence collapsed", absent, present)
	}
	if len(m.Unverified) != 0 {
		t.Fatalf("unverified=%+v — both subjects are resolved", m.Unverified)
	}
}

// selectedSourceFixture writes a snapshot root whose vendor tree carries one
// dependency module at one version. The vendor tree is the selected version's
// own source, so a fix-derived candidate's patch coordinate can be admitted or
// refuted without touching the host module cache or the network.
func selectedSourceFixture(t *testing.T, module, version string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/prod\n\ngo 1.15\n\nrequire "+module+" "+version+"\n")
	write("prod.go", "package prod\n\nfunc Main() {}\n")
	manifest := "# " + module + " " + version + "\n## explicit\n"
	seen := map[string]bool{}
	for rel := range files {
		dir := path.Dir(rel)
		pkg := module
		if dir != "." {
			pkg += "/" + dir
		}
		if !seen[pkg] {
			seen[pkg] = true
			manifest += pkg + "\n"
		}
		write("vendor/"+module+"/"+rel, files[rel])
	}
	write("vendor/modules.txt", manifest)
	return root
}

// candidateModel records one fix-derived candidate at the patch coordinate the
// candidate was read from.
func candidateModel(pkg, symbol, module, patchPath string) *domain.RootCauseModel {
	return &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: pkg, Symbol: symbol, Role: domain.RootCauseSink,
			Origin: domain.RootCauseOriginFixDerived,
			Binding: &domain.CandidateBinding{
				Status: domain.CandidateBindingUnmeasured, Module: module, PatchPath: patchPath,
			},
		}},
	}
}

// absenceCase records the selected dependency coordinate and the product
// package inventory the absence check reads.
func absenceCase(t *testing.T, product domain.ProductSnapshot, module, version, inventory string) *domain.AnalysisCase {
	t.Helper()
	c := &domain.AnalysisCase{
		Product: product,
		Affected: &domain.AffectedResult{
			SelectedModule:  module,
			SelectedModules: []string{module},
			ResolvedVersion: version,
		},
	}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
		completePackageListEvidence("EV-PKGS", product, inventory))
	return c
}

func hasGap(gaps []domain.AnalysisGap, owner domain.GapOwner, code domain.GapCode, obligation domain.Obligation) bool {
	for _, g := range gaps {
		if g.Owner == owner && g.Code == code && g.Obligation == obligation {
			return true
		}
	}
	return false
}

// The measured defect: a fix patch from another release line produced candidates
// that do not exist in the selected version at all. Such a candidate must never
// be recorded Absent — its absence from the product closure is vacuous — and the
// typed cause is a CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE gap that keeps the
// root cause unresolved.
func TestCandidateAbsenceRequiresSelectedVersionIdentity(t *testing.T) {
	// Selected v1 source: the daemon package lives at services/server, and the
	// patched cmd/containerd/server path does not exist at all — exactly the
	// Helm/CVE-2024-25621 shape.
	root := selectedSourceFixture(t, "github.com/containerd/containerd", "v1.7.27", map[string]string{
		"services/server/server.go": "package server\n\nfunc CreateTopLevelDirectories() error { return nil }\n",
		"main.go":                   "package main\n\nfunc main() {}\n",
	})
	p := &fakePatch{out: `diff --git a/cmd/containerd/server/server.go b/cmd/containerd/server/server.go
index 1..2 100644
--- a/cmd/containerd/server/server.go
+++ b/cmd/containerd/server/server.go
@@ -40,3 +40,4 @@ func CreateTopLevelDirectories(config Config) error {
-	if err := os.Chmod(config.Root, 0o711); err != nil {
+	if err := os.Chmod(config.Root, 0o700); err != nil {
`}
	v := domain.Vulnerability{
		ID:         "GHSA-test",
		Module:     "github.com/containerd/containerd",
		References: []domain.Reference{{Type: "FIX", URL: "https://github.com/containerd/containerd/commit/7c59e8e9"}},
	}
	product := rootCauseProduct()
	c := absenceCase(t, product, v.Module, "v1.7.27", `{"ImportPath":"example.com/constprod"}`)
	src := &goanalysis.Index{Dir: root, Env: []string{"GOPROXY=off", "GOWORK=off"}}

	m, _, err := Resolver{Patch: p, Source: src}.Resolve(context.Background(), c, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.RootCauses) == 0 {
		t.Fatalf("model=%+v — the fix-derived candidate must still be modelled", m)
	}
	for _, rc := range m.RootCauses {
		if rc.Binding == nil || rc.Binding.PatchPath != "cmd/containerd/server/server.go" {
			t.Fatalf("rc=%+v — the fix coordinate must be recorded on the candidate", rc)
		}
	}

	lim := Verifier{Source: src}.Verify(context.Background(), c, m, v)

	for _, rc := range m.Candidates() {
		if rc.Absent {
			t.Fatalf("candidate %s.%s marked Absent although its package does not exist in the selected version: %+v",
				rc.Package, rc.Symbol, rc)
		}
	}
	if m.Status == domain.RootCauseResolved {
		t.Fatalf("status=%s — an unmapped candidate cannot leave the root cause resolved", m.Status)
	}
	if len(m.Unverified) == 0 {
		t.Fatalf("unverified=%+v — the unmapped candidate must stay a blocking obligation", m.Unverified)
	}
	if !hasGap(m.AnalysisGaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", m.AnalysisGaps)
	}
	for _, l := range lim {
		if strings.Contains(l, "resolved by absence") {
			t.Fatalf("limitations=%v — an unmapped candidate was resolved by absence", l)
		}
	}
}

// A same-line fix still binds — the patch path resolves in the selected
// version's own source — but a resolved coordinate is an identity observation,
// not absence authority. While the content-derived proof contract is withdrawn,
// automatic patch-only same-line absence loses its coordinate-only exemption:
// the candidate leaves the resolved set, is not marked Absent, and stays a
// blocking obligation with a typed CODE / ROOT_CAUSE_UNRESOLVED cause. A
// record-declared subject or an independent operator input keeps its own route.
func TestCandidateAbsenceSameLineFixCoordinateIsNotAbsenceAuthority(t *testing.T) {
	root := selectedSourceFixture(t, "github.com/docker/docker", "v26.0.1", map[string]string{
		"libnetwork/osl/namespace_linux.go": "package osl\n\nfunc setIPv6() error { return nil }\n",
	})
	v := domain.Vulnerability{ID: "CVE-test", Module: "github.com/docker/docker"}
	product := rootCauseProduct()
	c := absenceCase(t, product, v.Module, "v26.0.1", `{"ImportPath":"example.com/constprod"}`)
	m := candidateModel("github.com/docker/docker/libnetwork/osl", "setIPv6",
		v.Module, "libnetwork/osl/namespace_linux.go")

	Verifier{Source: &goanalysis.Index{Dir: root}}.Verify(context.Background(), c, m, v)

	for _, rc := range m.Candidates() {
		if rc.Absent {
			t.Fatalf("candidate %s.%s grounded absence on a coordinate binding alone: %+v",
				rc.Package, rc.Symbol, rc)
		}
	}
	if m.Status == domain.RootCauseResolved {
		t.Fatalf("status=%s — a coordinate-only subject cannot leave the root cause resolved", m.Status)
	}
	if len(m.Unverified) != 1 {
		t.Fatalf("unverified=%+v — the subject must stay a blocking obligation", m.Unverified)
	}
	rc := m.Unverified[0]
	if rc.Binding == nil || rc.Binding.Status != domain.CandidateBindingAdmitted {
		t.Fatalf("binding=%+v — the same-line coordinate is still recorded as admitted", rc.Binding)
	}
	if !hasGap(m.AnalysisGaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want the typed withdrawal failure CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", m.AnalysisGaps)
	}
}

// A record-declared subject keeps its own absence route: the declaration is the
// affirmative basis, so a missing package stays evidence about a subject the
// advisory names. This is the retained independent route, not the withdrawn
// coordinate exemption.
func TestCandidateAbsenceRecordDeclaredSubjectStaysAdmissible(t *testing.T) {
	root := selectedSourceFixture(t, "github.com/docker/docker", "v26.0.1", map[string]string{
		"libnetwork/osl/namespace_linux.go": "package osl\n\nfunc setIPv6() error { return nil }\n",
	})
	v := domain.Vulnerability{
		ID:     "CVE-test",
		Module: "github.com/docker/docker",
		AffectedPackages: []domain.AffectedPackage{
			{Path: "github.com/docker/docker/libnetwork/osl"},
		},
	}
	product := rootCauseProduct()
	c := absenceCase(t, product, v.Module, "v26.0.1", `{"ImportPath":"example.com/constprod"}`)
	m := candidateModel("github.com/docker/docker/libnetwork/osl", "setIPv6",
		v.Module, "libnetwork/osl/namespace_linux.go")

	Verifier{Source: &goanalysis.Index{Dir: root}}.Verify(context.Background(), c, m, v)

	if len(m.RootCauses) != 1 {
		t.Fatalf("root causes=%+v unverified=%+v", m.RootCauses, m.Unverified)
	}
	if !m.RootCauses[0].Absent {
		t.Fatalf("rc=%+v — a record-declared subject's missing package stays a measured absence", m.RootCauses[0])
	}
	if hasGap(m.AnalysisGaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — a record-declared subject carries an admitted basis", m.AnalysisGaps)
	}
}

// No similarity authority: the same file basename and the same function name at
// a different path are not identity. A coordinate that does not resolve stays
// unmapped even when a same-named declaration exists elsewhere in the source.
func TestCandidateAbsenceRejectsSimilarityMatch(t *testing.T) {
	root := selectedSourceFixture(t, "github.com/docker/docker", "v26.0.1", map[string]string{
		"libnetwork/osl/namespace_linux.go": "package osl\n\nfunc setIPv6() error { return nil }\n",
	})
	v := domain.Vulnerability{ID: "CVE-test", Module: "github.com/docker/docker"}
	product := rootCauseProduct()
	c := absenceCase(t, product, v.Module, "v26.0.1", `{"ImportPath":"example.com/constprod"}`)
	m := candidateModel("github.com/docker/docker/internal/osl", "setIPv6",
		v.Module, "internal/osl/namespace_linux.go")

	Verifier{Source: &goanalysis.Index{Dir: root}}.Verify(context.Background(), c, m, v)

	for _, rc := range m.Candidates() {
		if rc.Absent {
			t.Fatalf("candidate %s.%s accepted a similarity match as identity: %+v", rc.Package, rc.Symbol, rc)
		}
	}
	if len(m.Unverified) != 1 {
		t.Fatalf("unverified=%+v — the unmapped candidate must stay blocking", m.Unverified)
	}
	b := m.Unverified[0].Binding
	if b == nil || b.Status != domain.CandidateBindingUnmapped || b.SourceKind != goanalysis.ModuleSourceVendor {
		t.Fatalf("binding=%+v — want UNMAPPED against the selected vendor source", b)
	}
	if !hasGap(m.AnalysisGaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED/ROOT_CAUSE", m.AnalysisGaps)
	}
}

// A selected-source input that cannot be resolved is a missing prerequisite, not
// absence: no vendored copy and no module-cache entry for the recorded
// coordinate.
func TestCandidateAbsenceSelectedSourceUnresolved(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-test", Module: "example.com/dep"}
	product := rootCauseProduct()
	c := absenceCase(t, product, v.Module, "v1.0.0", `{"ImportPath":"example.com/constprod"}`)
	m := candidateModel("example.com/dep/xds", "RouteAndProcess", v.Module, "xds/xds.go")

	vf := Verifier{Source: &goanalysis.Index{
		Dir: t.TempDir(),
		Env: []string{"GOMODCACHE=" + t.TempDir(), "GOPROXY=off", "GOWORK=off"},
	}}
	vf.Verify(context.Background(), c, m, v)

	for _, rc := range m.Candidates() {
		if rc.Absent {
			t.Fatalf("candidate %s.%s marked Absent without a measurable selected source: %+v", rc.Package, rc.Symbol, rc)
		}
	}
	if len(m.Unverified) != 1 {
		t.Fatalf("unverified=%+v — an unmeasured binding must stay blocking", m.Unverified)
	}
	if b := m.Unverified[0].Binding; b == nil || b.Status != domain.CandidateBindingUnmeasured {
		t.Fatalf("binding=%+v — want UNMEASURED", b)
	}
	if !hasGap(m.AnalysisGaps, domain.GapOwnerInput, domain.GapInputResolutionFailed, domain.ObligationRootCause) {
		t.Fatalf("gaps=%+v — want INPUT/INPUT_RESOLUTION_FAILED/ROOT_CAUSE", m.AnalysisGaps)
	}
}
