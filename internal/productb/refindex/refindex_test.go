package refindex

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/goanalysis"
	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// ---- symbol normalization -------------------------------------------------

func TestNormalizeSymbol(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Parse", "Parse"},
		{"T.M", "T.M"},
		{"(*T).M", "T.M"},
		{"(T).M", "T.M"},
		{"*T.M", "T.M"},
		{"  Read  ", "Read"},
		{"*", ""},
		{"", ""},
		{"Token.Valid", "Token.Valid"},
		{"(*Claims).Valid", "Claims.Valid"},
	}
	for _, c := range cases {
		if got := normalizeSymbol(c.in); got != c.want {
			t.Errorf("normalizeSymbol(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---- atom construction ----------------------------------------------------

func advisoryDoc(t *testing.T, name string) *loadedAdvisory {
	t.Helper()
	la, err := loadAdvisory(context.Background(), AdvisoryOptions{
		File: filepath.Join("testdata", "advisories", name), NoNet: true,
	})
	if err != nil {
		t.Fatalf("loadAdvisory(%s): %v", name, err)
	}
	return la
}

func TestBuildAtomsNormalizationDedup(t *testing.T) {
	la := advisoryDoc(t, "dep-parse.json")
	atoms, hadWildcard, _ := buildAtoms(la)
	if hadWildcard {
		t.Fatal("dep-parse has no wildcards")
	}
	var syms []string
	for _, a := range atoms {
		syms = append(syms, a.Symbol)
	}
	// "Parse" appears twice and "(*Reader).Read" folds to "Reader.Read";
	// atoms sort by symbol.
	want := []string{"Config", "DefaultLimit", "Parse", "Reader.Read"}
	if strings.Join(syms, ",") != strings.Join(want, ",") {
		t.Fatalf("atoms = %v, want %v", syms, want)
	}
	for _, a := range atoms {
		if a.Module != "example.com/dep" || a.Package != "example.com/dep/vuln" {
			t.Fatalf("atom binding wrong: %+v", a)
		}
		if a.AdvisoryID != "GO-EVAL-RI-PARSE" {
			t.Fatalf("atom advisory_id = %q", a.AdvisoryID)
		}
	}
	// Kinds from spelling: methods are "method", bare names "func".
	kinds := map[string]string{}
	for _, a := range atoms {
		kinds[a.Symbol] = a.SymbolKind
	}
	if kinds["Reader.Read"] != KindMethod || kinds["Parse"] != KindFunc {
		t.Fatalf("kinds = %v", kinds)
	}
	if got := atoms[2].Role; got != RoleParse { // Parse -> parse role
		t.Fatalf("Parse role = %q, want %q", got, RoleParse)
	}
}

func TestBuildAtomsWildcard(t *testing.T) {
	la := advisoryDoc(t, "dep-wild.json")
	atoms, hadWildcard, _ := buildAtoms(la)
	if !hadWildcard {
		t.Fatal("wildcard flag lost")
	}
	if len(atoms) != 1 || atoms[0].Symbol != "" || atoms[0].SymbolKind != KindPackage {
		t.Fatalf("wildcard atoms = %+v", atoms)
	}
}

func TestBuildAtomsPackageOnly(t *testing.T) {
	la := advisoryDoc(t, "dep-pkg.json")
	atoms, hadWildcard, _ := buildAtoms(la)
	if hadWildcard {
		t.Fatal("symbol-less import is not a wildcard")
	}
	if len(atoms) != 1 || atoms[0].SymbolKind != KindPackage {
		t.Fatalf("package atoms = %+v", atoms)
	}
}

// ---- family adoption ------------------------------------------------------

func TestFamilyAdoption(t *testing.T) {
	dir := t.TempDir()
	// GHSA document declares the package but no symbols; the GO sibling
	// names them. Family closure must adopt the GO document's symbols
	// without changing the selected document's identity.
	writeFile(t, filepath.Join(dir, "GHSA-fam-0001.json"), `{
	  "id": "GHSA-fam-0001",
	  "aliases": ["GO-2024-9999"],
	  "affected": [{
	    "package": {"name": "example.com/dep", "ecosystem": "Go"},
	    "ecosystem_specific": {"imports": [{"path": "example.com/dep/vuln"}]}
	  }]
	}`)
	writeFile(t, filepath.Join(dir, "GO-2024-9999.json"), `{
	  "id": "GO-2024-9999",
	  "aliases": ["GHSA-fam-0001"],
	  "affected": [{
	    "package": {"name": "example.com/dep", "ecosystem": "Go"},
	    "ecosystem_specific": {"imports": [{"path": "example.com/dep/vuln", "symbols": ["Parse"]}]}
	  }]
	}`)
	la, err := loadAdvisory(context.Background(), AdvisoryOptions{
		Dir: dir, ID: "GHSA-fam-0001", NoNet: true,
	})
	if err != nil {
		t.Fatalf("loadAdvisoryDir: %v", err)
	}
	if la.vuln.ID != "GHSA-fam-0001" {
		t.Fatalf("selected = %s", la.vuln.ID)
	}
	atoms, _, _ := buildAtoms(la)
	if len(atoms) != 2 {
		t.Fatalf("atoms = %+v", atoms)
	}
	// The adopted symbol atom carries the family document's id.
	var named *Atom
	for i := range atoms {
		if atoms[i].Symbol != "" {
			named = &atoms[i]
		}
	}
	if named == nil || named.Symbol != "Parse" || named.AdvisoryID != "GO-2024-9999" {
		t.Fatalf("adopted atom = %+v", named)
	}
	if len(la.docs) != 2 {
		t.Fatalf("family docs = %v", la.docs)
	}
}

// ---- strata classification -------------------------------------------------

// fakeChecker returns queued ProductUsage results keyed pkg+"."+symbol.
type fakeChecker struct {
	res map[string]goanalysis.PackageUsageResult
	err error
}

func (f fakeChecker) ProductUsage(_ context.Context, module string, subject pbdomain.SymbolRef) (goanalysis.PackageUsageResult, error) {
	if f.err != nil {
		return goanalysis.PackageUsageResult{}, f.err
	}
	r, ok := f.res[subject.Package+"."+subject.Symbol]
	if !ok {
		r = goanalysis.PackageUsageResult{Module: module, Package: subject.Package,
			Symbol: subject.Symbol, Usage: goanalysis.PackageUsageUnknown}
	}
	return r, nil
}

func usageRes(state goanalysis.PackageUsageState, nv goanalysis.PackageUsageNegativeVerification, present bool, lims ...string) goanalysis.PackageUsageResult {
	return goanalysis.PackageUsageResult{
		Present: present, Usage: state, NegativeVerification: nv,
		Limitations: lims,
	}
}

// res adapts a fabricated PackageUsageResult to the *PackageUsageResult
// the table's res field expects.
func res(r goanalysis.PackageUsageResult) *goanalysis.PackageUsageResult { return &r }

func atomOf(mod, pkg, sym string) Atom {
	return Atom{Module: mod, Package: pkg, Symbol: normalizeSymbol(sym),
		SymbolKind: KindFunc, Role: RoleSink, AdvisoryID: "A-1"}
}

func TestStrataTable(t *testing.T) {
	key := "example.com/dep/vuln.Parse"
	depAtom := atomOf("example.com/dep", "example.com/dep/vuln", "Parse")
	depMb := moduleBinding{ModulePath: "example.com/prod",
		Requires: map[string]string{"example.com/dep": "v1.0.0"}}

	cases := []struct {
		name     string
		mb       moduleBinding
		atom     Atom
		res      *goanalysis.PackageUsageResult
		want     UsageStratum
		wantBind Binding
		wantSt   UsageState
		wantNV   string
	}{
		{"reachable_complete", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true)),
			StratumReachableComplete, BindingDirect, StateUsed, ""},
		{"reachable_partial_gap", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true, "case gap")),
			StratumReachablePartial, BindingDirect, StateUsed, ""},
		{"unreachable_verified", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageNotUsed, goanalysis.PackageUsageNegativeVerified, true)),
			StratumUnreachableComplete, BindingDirect, StateNotUsed, "VERIFIED"},
		{"not_used_unverified_is_unknown", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageNotUsed, goanalysis.PackageUsageNegativeInsufficientScope, true)),
			StratumUnknown, BindingDirect, StateUnknown, "INSUFFICIENT_SCOPE"},
		{"unknown_check", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageUnknown, goanalysis.PackageUsageNegativeInsufficientScope, true)),
			StratumUnknown, BindingDirect, StateUnknown, "INSUFFICIENT_SCOPE"},
		// Module present in the module graph (required), but the package is
		// absent from the loaded source closure: scope limitation, never a
		// negative. Mirrors caddy/quic-go internal/ackhandler.
		{"absent_from_closure_module_present", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageUnknown, goanalysis.PackageUsageNegativeInsufficientScope, false)),
			StratumUnknown, BindingDirect, StateUnknown, "INSUFFICIENT_SCOPE"},
		{"absent_but_used", depMb, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", false)),
			StratumReachableComplete, BindingDirect, StateUsed, ""},
		{"self_implementation", moduleBinding{ModulePath: "example.com/dep"}, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true)),
			StratumSelfImplementation, BindingDirect, StateUsed, ""},
		// Binding is orthogonal to the usage verdict: a forked or
		// ambiguous binding keeps the reachable stratum when USED.
		{"local_replace_fork_used", moduleBinding{ModulePath: "example.com/prod",
			Requires: map[string]string{"example.com/dep": "v1.0.0"},
			Replaces: []replaceRule{{oldPath: "example.com/dep", newPath: "../dep"}}}, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true)),
			StratumReachableComplete, BindingForkCopy, StateUsed, ""},
		{"replacement_ambiguous_used", moduleBinding{ModulePath: "example.com/prod",
			Requires: map[string]string{"example.com/dep": "v1.0.0"},
			Replaces: []replaceRule{{oldPath: "example.com/dep", newPath: "example.com/fork/dep", newVer: "v9.9.9"}}}, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true)),
			StratumReachableComplete, BindingReplacementAmbiguous, StateUsed, ""},
		{"version_pin_replace_exact", moduleBinding{ModulePath: "example.com/prod",
			Requires: map[string]string{"example.com/dep": "v1.0.0"},
			Replaces: []replaceRule{{oldPath: "example.com/dep", newPath: "example.com/dep", newVer: "v1.0.1"}}}, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true)),
			StratumReachableComplete, BindingDirect, StateUsed, ""},
		{"vendored_reachable", moduleBinding{ModulePath: "example.com/prod",
			Requires:   map[string]string{"example.com/dep": "v1.2.3"},
			VendorMode: true,
			Vendored:   map[string]string{"example.com/dep": "# example.com/dep v1.2.3"}}, depAtom,
			res(usageRes(goanalysis.PackageUsageUsed, "", true)),
			StratumReachableComplete, BindingVendoredExact, StateUsed, ""},
		// Podman shape (x/crypto vendored, product source never calls the
		// affected symbols): a closed negative wins over the binding.
		{"vendored_unreachable", moduleBinding{ModulePath: "example.com/prod",
			Requires:   map[string]string{"example.com/dep": "v1.2.3"},
			VendorMode: true,
			Vendored:   map[string]string{"example.com/dep": "# example.com/dep v1.2.3"}}, depAtom,
			res(usageRes(goanalysis.PackageUsageNotUsed, goanalysis.PackageUsageNegativeVerified, true)),
			StratumUnreachableComplete, BindingVendoredExact, StateNotUsed, "VERIFIED"},
		{"vendored_scope_limited", moduleBinding{ModulePath: "example.com/prod",
			Requires:   map[string]string{"example.com/dep": "v1.2.3"},
			VendorMode: true,
			Vendored:   map[string]string{"example.com/dep": "# example.com/dep v1.2.3"}}, depAtom,
			res(usageRes(goanalysis.PackageUsageUnknown, goanalysis.PackageUsageNegativeInsufficientScope, false)),
			StratumUnknown, BindingVendoredExact, StateUnknown, "INSUFFICIENT_SCOPE"},
		{"not_required_absent", moduleBinding{ModulePath: "example.com/prod"}, depAtom,
			res(usageRes(goanalysis.PackageUsageUnknown, goanalysis.PackageUsageNegativeInsufficientScope, false)),
			StratumNotPresent, BindingDirect, StateNotUsed, "VERIFIED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resMap := map[string]goanalysis.PackageUsageResult{key: *c.res}
			u, _ := classifyUsage(context.Background(), fakeChecker{res: resMap}, c.mb, []Atom{c.atom}, c.atom.Module)
			if u.Stratum != c.want {
				t.Fatalf("stratum = %s, want %s", u.Stratum, c.want)
			}
			if u.Binding != c.wantBind {
				t.Fatalf("binding = %s, want %s", u.Binding, c.wantBind)
			}
			if u.State != c.wantSt {
				t.Fatalf("state = %s, want %s", u.State, c.wantSt)
			}
			if u.NegativeVerification != c.wantNV {
				t.Fatalf("negative_verification = %q, want %q", u.NegativeVerification, c.wantNV)
			}
		})
	}
}

func TestStrataNoChecker(t *testing.T) {
	// No index: only manifest facts classify — a module that is not a
	// declared dependency is not_present; a required module is unknown.
	depAtom := atomOf("example.com/dep", "example.com/dep/vuln", "Parse")
	u, _ := classifyUsage(context.Background(), nil,
		moduleBinding{ModulePath: "example.com/prod"}, []Atom{depAtom}, "example.com/dep")
	if u.Stratum != StratumNotPresent || u.State != StateNotUsed {
		t.Fatalf("absent module: %+v", u)
	}
	u, _ = classifyUsage(context.Background(), nil,
		moduleBinding{ModulePath: "example.com/prod",
			Requires: map[string]string{"example.com/dep": "v1.0.0"}}, []Atom{depAtom}, "example.com/dep")
	if u.Stratum != StratumUnknown || u.State != StateUnknown {
		t.Fatalf("required unverified: %+v", u)
	}
	// self_implementation without index still classifies.
	u, _ = classifyUsage(context.Background(), nil,
		moduleBinding{ModulePath: "example.com/dep"}, []Atom{depAtom}, "example.com/dep")
	if u.Stratum != StratumSelfImplementation {
		t.Fatalf("self without index: %+v", u)
	}
}

func TestMergeMultiAtom(t *testing.T) {
	// One USED atom + one NOT_USED/VERIFIED atom: merged state USED,
	// usage verdict (USED) is independent of the fork binding.
	atoms := []Atom{
		atomOf("example.com/dep", "example.com/dep/vuln", "Parse"),
		atomOf("example.com/dep", "example.com/dep/vuln", "Reader.Read"),
	}
	ck := fakeChecker{res: map[string]goanalysis.PackageUsageResult{
		"example.com/dep/vuln.Parse":       usageRes(goanalysis.PackageUsageUsed, "", true),
		"example.com/dep/vuln.Reader.Read": usageRes(goanalysis.PackageUsageNotUsed, goanalysis.PackageUsageNegativeVerified, true),
	}}
	mb := moduleBinding{ModulePath: "example.com/prod",
		Requires: map[string]string{"example.com/dep": "v1.0.0"},
		Replaces: []replaceRule{{oldPath: "example.com/dep", newPath: "../dep"}}}
	u, _ := classifyUsage(context.Background(), ck, mb, atoms, "example.com/dep")
	if u.State != StateUsed || u.Stratum != StratumReachableComplete {
		t.Fatalf("merged = %s/%s", u.State, u.Stratum)
	}
	if u.Binding != BindingForkCopy {
		t.Fatalf("binding = %s, want fork_copy", u.Binding)
	}
}

// ---- locus status ----------------------------------------------------------

func TestLocusStatus(t *testing.T) {
	resolved := Atom{Package: "p", Symbol: "F", SymbolKind: KindFunc, Decl: &Decl{Path: "f.go", Line: 1, EndLine: 3}}
	unresolved := Atom{Package: "p", Symbol: "F", SymbolKind: KindFunc}
	pkgAtom := Atom{Package: "p", SymbolKind: KindPackage}
	cases := []struct {
		name      string
		atoms     []Atom
		wild, pkg bool
		want      LocusStatus
	}{
		{"empty", nil, false, false, LocusNA},
		{"resolved", []Atom{resolved}, false, false, LocusResolved},
		{"unresolved", []Atom{unresolved}, false, false, LocusUnresolved},
		{"mixed", []Atom{resolved, unresolved}, false, false, LocusUnresolved},
		{"package_only", []Atom{pkgAtom}, false, true, LocusPackageOnly},
		{"wildcard", []Atom{pkgAtom}, true, false, LocusWildcard},
	}
	for _, c := range cases {
		if got := locusStatus(c.atoms, c.wild, c.pkg); got != c.want {
			t.Errorf("%s: locusStatus = %s, want %s", c.name, got, c.want)
		}
	}
}

// ---- canonical determinism --------------------------------------------------

func TestCanonicalDeterministic(t *testing.T) {
	doc := &Doc{
		Schema: Schema, CaseID: "X-1",
		Advisory: Advisory{ID: "X-1", Digest: "sha256:a",
			Documents: []AdvisoryDoc{{ID: "X-1", SHA256: "sha256:b"}}},
		Snapshot: Snapshot{Path: "/tmp/x", Commit: "abc", ContentHash: "sha256:c"},
		BuildContext: BuildCtx{GOOS: "linux", GOARCH: "amd64",
			Tags: []string{}, ModuleMode: "mod"},
		Locus: Locus{Atoms: []Atom{{Module: "m", Package: "m/p", Symbol: "F",
			SymbolKind: KindFunc, Role: RoleSink, AdvisoryID: "X-1"}}, Status: LocusUnresolved},
		Usage: Usage{Stratum: StratumUnknown, Binding: BindingDirect, State: StateUnknown,
			Sites: []Site{}, ImportSites: []Site{}, Limitations: []string{"a"}},
		Auxiliary: Auxiliary{FixDiff: FixDiff{Status: FixDiffNotAttempted, Files: []FixDiffFile{}}},
	}
	if err := Seal(doc); err != nil {
		t.Fatal(err)
	}
	b1, err := Canonical(doc)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Canonical(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("canonical output not byte-identical")
	}
	if !strings.HasPrefix(doc.Hashes.CanonicalSHA256, "sha256:") {
		t.Fatalf("hash = %q", doc.Hashes.CanonicalSHA256)
	}
	// The hash covers the document without the hashes field: re-sealing a
	// stripped copy reproduces it.
	dup := *doc
	dup.Hashes = nil
	if err := Seal(&dup); err != nil {
		t.Fatal(err)
	}
	if dup.Hashes.CanonicalSHA256 != doc.Hashes.CanonicalSHA256 {
		t.Fatal("hash not stable across re-seal")
	}
}

// ---- module binding ---------------------------------------------------------

func TestReadModuleBinding(t *testing.T) {
	mb := readModuleBinding(filepath.Join("testdata", "forkprod"))
	if mb.ModulePath != "example.com/forkprod" {
		t.Fatalf("module = %q", mb.ModulePath)
	}
	ver, ok := mb.requiredVersion("example.com/dep")
	if !ok || ver != "v0.0.0" {
		t.Fatalf("require = %q %v", ver, ok)
	}
	rep := mb.replacementFor("example.com/dep", ver)
	if rep == nil || !rep.local() || rep.newPath != "../dep" {
		t.Fatalf("replace = %+v", rep)
	}
}

func TestReadModuleBindingVendor(t *testing.T) {
	mb := readModuleBinding(filepath.Join("testdata", "vendprod"))
	if !mb.VendorMode {
		t.Fatal("vendor mode not detected")
	}
	if _, ok := mb.Vendored["example.com/dep"]; !ok {
		t.Fatal("vendored module missing")
	}
}

func TestFixDiffCounts(t *testing.T) {
	patch := `diff --git a/f.go b/f.go
index 111..222 100644
--- a/f.go
+++ b/f.go
@@ -1,3 +1,4 @@
 package f
+added
-removed
 kept
diff --git a/g.go b/g.go
new file mode 100644
--- /dev/null
+++ b/g.go
@@ -0,0 +1,2 @@
+package g
+func G() {}
`
	files := countDiffFiles(patch)
	if len(files) != 2 {
		t.Fatalf("files = %+v", files)
	}
	if files[0].Path != "f.go" || files[0].Additions != 1 || files[0].Deletions != 1 {
		t.Fatalf("f.go = %+v", files[0])
	}
	if files[1].Path != "g.go" || files[1].Additions != 2 {
		t.Fatalf("g.go = %+v", files[1])
	}
}

// ---- integration over fixtures ----------------------------------------------

// requireGo skips fixture-loading tests when no go toolchain is present.
func requireGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
}

// buildCase runs the full builder over a fixture product and advisory.
func buildCase(t *testing.T, prod, advisory string) *Doc {
	t.Helper()
	requireGo(t)
	root, err := filepath.Abs(filepath.Join("testdata", prod))
	if err != nil {
		t.Fatal(err)
	}
	ix := &goanalysis.Index{Dir: root}
	doc, err := Builder{Opts: Options{
		SnapshotRoot: root,
		Advisory: AdvisoryOptions{
			File:  filepath.Join("testdata", "advisories", advisory),
			NoNet: true,
		},
		Symbols: ix,
		Usage:   ix,
	}}.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return doc
}

// buildCaseDir runs the builder with an advisory directory + selected id —
// the family-closure lane (CVE wrapper selecting a GO sibling).
func buildCaseDir(t *testing.T, prod, advisoryDir, id string) *Doc {
	t.Helper()
	requireGo(t)
	root, err := filepath.Abs(filepath.Join("testdata", prod))
	if err != nil {
		t.Fatal(err)
	}
	ix := &goanalysis.Index{Dir: root}
	doc, err := Builder{Opts: Options{
		SnapshotRoot: root,
		Advisory: AdvisoryOptions{
			Dir:   filepath.Join("testdata", "advisories", advisoryDir),
			ID:    id,
			NoNet: true,
		},
		Symbols: ix,
		Usage:   ix,
	}}.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return doc
}

// TestBuildFamilyPromotion guards the CVE-wrapper shape: the selected
// document declares no affected entry at all, so the family's GO sibling
// supplies the locus. Promotion must be attributed to the source document
// and stay deterministic.
func TestBuildFamilyPromotion(t *testing.T) {
	// CVE-2099-0001: wrapper with no affected[] at all.
	// CVE-2099-0002: wrapper whose affected[] carries ranges but no
	// imports[] — both shapes declare zero (module, package) entries.
	for _, id := range []string{"CVE-2099-0001", "CVE-2099-0002"} {
		t.Run(id, func(t *testing.T) {
			doc := buildCaseDir(t, "forkprod", "family", id)
			if len(doc.Locus.Atoms) == 0 {
				t.Fatal("no atoms promoted from the family document")
			}
			if doc.Locus.Status != LocusResolved {
				t.Fatalf("locus = %s; atoms %+v", doc.Locus.Status, doc.Locus.Atoms)
			}
			var syms []string
			for _, a := range doc.Locus.Atoms {
				if a.AdvisoryID != "GO-EVAL-RI-FAM" {
					t.Fatalf("atom %s.%s advisory_id = %q, want GO-EVAL-RI-FAM",
						a.Package, a.Symbol, a.AdvisoryID)
				}
				if a.Module != "example.com/dep" || a.Package != "example.com/dep/vuln" {
					t.Fatalf("atom binding = %s %s", a.Module, a.Package)
				}
				if a.Decl == nil {
					t.Fatalf("atom %s unresolved", a.Symbol)
				}
				syms = append(syms, a.Symbol)
			}
			want := []string{"Parse", "Reader.Read"} // sorted, "(*Reader).Read" folded
			if strings.Join(syms, ",") != strings.Join(want, ",") {
				t.Fatalf("atoms = %v, want %v", syms, want)
			}
			if doc.Advisory.ID != id {
				t.Fatalf("selected advisory = %s", doc.Advisory.ID)
			}
			if doc.Usage.Stratum != StratumReachableComplete || doc.Usage.State != StateUsed {
				t.Fatalf("usage = %s/%s", doc.Usage.Stratum, doc.Usage.State)
			}
			if doc.Usage.Binding != BindingForkCopy {
				t.Fatalf("binding = %s, want fork_copy", doc.Usage.Binding)
			}
			// Determinism: promoted atoms must not depend on map iteration.
			d2 := buildCaseDir(t, "forkprod", "family", id)
			b1, err := Canonical(doc)
			if err != nil {
				t.Fatal(err)
			}
			b2, err := Canonical(d2)
			if err != nil {
				t.Fatal(err)
			}
			if string(b1) != string(b2) || doc.Hashes.CanonicalSHA256 != d2.Hashes.CanonicalSHA256 {
				t.Fatal("family promotion is not byte-identical across runs")
			}
		})
	}
}

func TestTransitiveDependencyInternalUnknown(t *testing.T) {
	// Caddy shape (CVE-2025-29785 / GO-2025-3735): the advisory module is
	// required in go.mod, but the advisory package is dependency-internal
	// and absent from the loaded source closure (goanalysis.linkedPaths
	// gap). That is a scope limitation, never a not_present/VERIFIED
	// negative.
	atom := atomOf("github.com/quic-go/quic-go",
		"github.com/quic-go/quic-go/internal/ackhandler",
		"sentPacketHandler.ReceivedAck")
	ck := fakeChecker{res: map[string]goanalysis.PackageUsageResult{
		"github.com/quic-go/quic-go/internal/ackhandler.sentPacketHandler.ReceivedAck": usageRes(
			goanalysis.PackageUsageUnknown, goanalysis.PackageUsageNegativeInsufficientScope, false),
	}}
	mb := moduleBinding{
		ModulePath: "github.com/caddyserver/caddy/v2",
		Requires:   map[string]string{"github.com/quic-go/quic-go": "v0.50.0"},
	}
	u, lims := classifyUsage(context.Background(), ck, mb, []Atom{atom}, "github.com/quic-go/quic-go")
	if u.Stratum != StratumUnknown {
		t.Fatalf("stratum = %s, want unknown", u.Stratum)
	}
	if u.State != StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", u.State)
	}
	if u.NegativeVerification != string(goanalysis.PackageUsageNegativeInsufficientScope) {
		t.Fatalf("negative_verification = %q, want INSUFFICIENT_SCOPE", u.NegativeVerification)
	}
	found := false
	for _, l := range lims {
		if l == linkedPathsLimitation {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("linkedPaths limitation missing from %v", lims)
	}
}

func TestBuildForkCopy(t *testing.T) {
	doc := buildCase(t, "forkprod", "dep-parse.json")
	if doc.Usage.Stratum != StratumReachableComplete {
		t.Fatalf("stratum = %s, want reachable_complete", doc.Usage.Stratum)
	}
	if doc.Usage.Binding != BindingForkCopy {
		t.Fatalf("binding = %s, want fork_copy", doc.Usage.Binding)
	}
	if doc.Usage.State != StateUsed {
		t.Fatalf("state = %s, want USED", doc.Usage.State)
	}
	if doc.Locus.Status != LocusResolved {
		t.Fatalf("locus = %s; atoms %+v", doc.Locus.Status, doc.Locus.Atoms)
	}
	// Parse must carry a resolved declaration with an end line.
	var parse *Atom
	for i := range doc.Locus.Atoms {
		if doc.Locus.Atoms[i].Symbol == "Parse" {
			parse = &doc.Locus.Atoms[i]
		}
		if doc.Locus.Atoms[i].Symbol == "Reader.Read" &&
			doc.Locus.Atoms[i].SymbolKind != KindMethod {
			t.Fatalf("Reader.Read kind = %s", doc.Locus.Atoms[i].SymbolKind)
		}
	}
	if parse == nil || parse.Decl == nil || parse.Decl.Line == 0 || parse.Decl.EndLine <= parse.Decl.Line {
		t.Fatalf("Parse decl = %+v", parse)
	}
	if len(doc.Usage.Sites) == 0 {
		t.Fatal("expected usage sites")
	}
}

func TestBuildVendoredExact(t *testing.T) {
	doc := buildCase(t, "vendprod", "dep-parse.json")
	if doc.Usage.Stratum != StratumReachableComplete {
		t.Fatalf("stratum = %s, want reachable_complete", doc.Usage.Stratum)
	}
	if doc.Usage.Binding != BindingVendoredExact {
		t.Fatalf("binding = %s, want vendored_exact", doc.Usage.Binding)
	}
	if doc.Usage.State != StateUsed {
		t.Fatalf("state = %s, want USED from the vendored package", doc.Usage.State)
	}
	if doc.Locus.Status != LocusResolved {
		t.Fatalf("locus = %s; atoms %+v", doc.Locus.Status, doc.Locus.Atoms)
	}
	if doc.BuildContext.ModuleMode != "vendor" {
		t.Fatalf("module_mode = %s", doc.BuildContext.ModuleMode)
	}
}

// TestBuildVendoredUnreachable is the podman shape: the module ships from
// the vendor tree and the product source never calls the affected symbol.
// The closed negative must win over the binding: stratum
// unreachable_complete, binding vendored_exact.
func TestBuildVendoredUnreachable(t *testing.T) {
	doc := buildCase(t, "vendnotused", "dep-reader.json")
	if doc.Usage.Stratum != StratumUnreachableComplete {
		t.Fatalf("stratum = %s, want unreachable_complete", doc.Usage.Stratum)
	}
	if doc.Usage.Binding != BindingVendoredExact {
		t.Fatalf("binding = %s, want vendored_exact", doc.Usage.Binding)
	}
	if doc.Usage.State != StateNotUsed {
		t.Fatalf("state = %s, want NOT_USED", doc.Usage.State)
	}
	if doc.Usage.NegativeVerification != "VERIFIED" {
		t.Fatalf("negative_verification = %q, want VERIFIED", doc.Usage.NegativeVerification)
	}
	if doc.Locus.Status != LocusResolved {
		t.Fatalf("locus = %s; atoms %+v", doc.Locus.Status, doc.Locus.Atoms)
	}
}

func TestBuildSelfImplementation(t *testing.T) {
	doc := buildCase(t, "selfprod", "self-parse.json")
	if doc.Usage.Stratum != StratumSelfImplementation {
		t.Fatalf("stratum = %s, want self_implementation", doc.Usage.Stratum)
	}
	if doc.Locus.Status != LocusResolved {
		t.Fatalf("locus = %s", doc.Locus.Status)
	}
}

func TestBuildNotPresent(t *testing.T) {
	doc := buildCase(t, "notdepprod", "dep-parse.json")
	if doc.Usage.Stratum != StratumNotPresent {
		t.Fatalf("stratum = %s, want not_present", doc.Usage.Stratum)
	}
	if doc.Usage.State != StateNotUsed || doc.Usage.NegativeVerification != "VERIFIED" {
		t.Fatalf("usage = %+v", doc.Usage)
	}
}

func TestBuildStdlibNotLinked(t *testing.T) {
	// stdlib is a pseudo-module, not a go.mod dependency: a stdlib package
	// missing from the source closure is a scope limitation, never a
	// module-graph absence. net/url is not imported by the product.
	doc := buildCase(t, "notdepprod", "stdlib.json")
	if doc.Usage.Stratum != StratumUnknown {
		t.Fatalf("stratum = %s, want unknown", doc.Usage.Stratum)
	}
	if doc.Usage.State != StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", doc.Usage.State)
	}
	if doc.Usage.NegativeVerification != "INSUFFICIENT_SCOPE" {
		t.Fatalf("negative_verification = %q", doc.Usage.NegativeVerification)
	}
}

func TestBuildWildcard(t *testing.T) {
	doc := buildCase(t, "wildprod", "dep-wild.json")
	if doc.Locus.Status != LocusWildcard {
		t.Fatalf("locus = %s", doc.Locus.Status)
	}
	if len(doc.Locus.Atoms) != 1 || doc.Locus.Atoms[0].SymbolKind != KindPackage {
		t.Fatalf("atoms = %+v", doc.Locus.Atoms)
	}
}

func TestBuildPackageOnly(t *testing.T) {
	doc := buildCase(t, "forkprod", "dep-pkg.json")
	if doc.Locus.Status != LocusPackageOnly {
		t.Fatalf("locus = %s", doc.Locus.Status)
	}
}

func TestBuildDeterministic(t *testing.T) {
	d1 := buildCase(t, "forkprod", "dep-parse.json")
	d2 := buildCase(t, "forkprod", "dep-parse.json")
	b1, err := Canonical(d1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Canonical(d2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("repeated build is not byte-identical")
	}
	if d1.Hashes.CanonicalSHA256 != d2.Hashes.CanonicalSHA256 {
		t.Fatal("canonical hash differs between runs")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---- network family closure ------------------------------------------------

// TestNetFamilyClosure guards the CVE-wrapper network lane: the selected
// CVE document declares no affected[] at all, so the locus must come from
// the aliased GO document fetched through the OSV source. A missing alias
// document surfaces as a limitation, never a failure.
func TestNetFamilyClosure(t *testing.T) {
	requireGo(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		switch id {
		case "CVE-2025-47914":
			fmt.Fprint(w, `{
				"id": "CVE-2025-47914",
				"summary": "Out of bounds read in SSH agent parsing",
				"aliases": ["GHSA-f6x5-jh6r-wrfv", "GO-2025-4135"]
			}`)
		case "GO-2025-4135":
			fmt.Fprint(w, `{
				"id": "GO-2025-4135",
				"aliases": ["CVE-2025-47914", "GHSA-f6x5-jh6r-wrfv"],
				"affected": [{
					"package": {"name": "example.com/dep", "ecosystem": "Go"},
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
					"ecosystem_specific": {
						"imports": [{"path": "example.com/dep/vuln", "symbols": ["Parse", "(*Reader).Read"]}]
					}
				}]
			}`)
		default: // GHSA-f6x5-jh6r-wrfv and anything else
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"not found"}`)
		}
	}))
	defer srv.Close()

	build := func(t *testing.T) *Doc {
		t.Helper()
		root, err := filepath.Abs(filepath.Join("testdata", "forkprod"))
		if err != nil {
			t.Fatal(err)
		}
		ix := &goanalysis.Index{Dir: root}
		doc, err := Builder{Opts: Options{
			SnapshotRoot: root,
			Advisory: AdvisoryOptions{
				ID:         "CVE-2025-47914",
				OSVBaseURL: srv.URL,
			},
			Symbols: ix,
			Usage:   ix,
		}}.Build(context.Background())
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		return doc
	}

	doc := build(t)
	if doc.Advisory.ID != "CVE-2025-47914" {
		t.Fatalf("advisory = %s", doc.Advisory.ID)
	}
	if len(doc.Locus.Atoms) == 0 {
		t.Fatal("family closure produced no atoms")
	}
	for _, a := range doc.Locus.Atoms {
		if a.AdvisoryID != "GO-2025-4135" {
			t.Fatalf("atom %s advisory_id = %s, want GO-2025-4135", a.Symbol, a.AdvisoryID)
		}
	}
	// The unfetchable GHSA alias is a limitation, not a failure.
	found := false
	for _, l := range doc.Usage.Limitations {
		if strings.Contains(l, "GHSA-f6x5-jh6r-wrfv") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing-alias limitation absent from %v", doc.Usage.Limitations)
	}
	// The GO document must appear verbatim in the digest corpus.
	var ids []string
	for _, d := range doc.Advisory.Documents {
		ids = append(ids, d.ID)
	}
	if strings.Join(ids, ",") != "CVE-2025-47914,GO-2025-4135" {
		t.Fatalf("digest documents = %v", ids)
	}

	// Determinism: same server, same bytes.
	b1, err := Canonical(doc)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Canonical(build(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("repeated network build is not byte-identical")
	}
}
