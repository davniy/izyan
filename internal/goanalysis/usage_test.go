package goanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// usageModule writes a temp product module requiring example.com/dep with a
// local replace to testdata/dep, then writes the given source files.
func usageModule(t *testing.T, files map[string]string) string {
	t.Helper()
	depAbs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "dep"))
	if err != nil {
		t.Fatal(err)
	}
	gomod := "module example.com/usageprod\n\ngo 1.23\n\n" +
		"require example.com/dep v1.0.0\n\nreplace example.com/dep => " + depAbs + "\n"
	return usageModuleGomod(t, gomod, files)
}

// usageModuleGomod writes a temp module tree with the given go.mod
// content and the given files — unlike usageModule it supports nested
// local modules (each carrying its own go.mod) for multi-module
// fixtures.
func usageModuleGomod(t *testing.T, gomod string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", gomod)
	for name, body := range files {
		write(name, body)
	}
	return dir
}

func productUsage(t *testing.T, ix *Index, module, pkg, sym string) PackageUsageResult {
	t.Helper()
	res, err := ix.ProductUsage(context.Background(), module,
		domain.SymbolRef{Package: pkg, Symbol: sym})
	if err != nil {
		t.Fatalf("ProductUsage(%s, %s.%s): %v", module, pkg, sym, err)
	}
	return res
}

type wantVerdict struct {
	present bool
	usage   PackageUsageState
	neg     PackageUsageNegativeVerification
}

func checkVerdict(t *testing.T, res PackageUsageResult, w wantVerdict) {
	t.Helper()
	if res.Present != w.present || res.Usage != w.usage || res.NegativeVerification != w.neg {
		t.Fatalf("present=%v usage=%s negative=%s; want present=%v usage=%s negative=%s (limitations=%d)",
			res.Present, res.Usage, res.NegativeVerification,
			w.present, w.usage, w.neg, len(res.Limitations))
	}
	if res.Usage == PackageUsageNotUsed {
		if res.NegativeVerification != PackageUsageNegativeVerified {
			t.Fatalf("NOT_USED without VERIFIED negative verification")
		}
		if res.CheckScope == "" {
			t.Fatal("NOT_USED must record the bounded check scope")
		}
		if len(res.Limitations) == 0 {
			t.Fatal("usage verdict must carry explicit limitations")
		}
	}
}

func TestProductUsage(t *testing.T) {
	ctx := context.Background()

	t.Run("DirectCallIsUsed", func(t *testing.T) {
		ix := fixture(t, "constprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse")
		checkVerdict(t, res, wantVerdict{present: true, usage: PackageUsageUsed})
		if len(res.ProductSites) == 0 {
			t.Fatal("USED must name at least one concrete product site")
		}
		found := false
		for _, s := range res.ProductSites {
			if s.Function == "main" && s.File != "" && s.Line > 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a product site inside main, got %d site(s)", len(res.ProductSites))
		}
	})

	t.Run("DirectImportIsUsed", func(t *testing.T) {
		ix := fixture(t, "constprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
		checkVerdict(t, res, wantVerdict{present: true, usage: PackageUsageUsed})
		if len(res.ImportSites) == 0 {
			t.Fatal("package-level USED must record the direct import site")
		}
	})

	t.Run("BlankImportIsUsed", func(t *testing.T) {
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	_ "example.com/dep/vuln"
)

func main() {}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
		checkVerdict(t, res, wantVerdict{present: true, usage: PackageUsageUsed})
		if len(res.ImportSites) != 1 {
			t.Fatalf("blank import must be one import site, got %d", len(res.ImportSites))
		}
	})

	t.Run("TransitivePresentPackageNotUsed", func(t *testing.T) {
		// dep5/deep is linked transitively through dep5/driver, but the
		// product never imports or references it — the only admissible
		// NOT_USED shape: closed scope, VERIFIED.
		ix := fixture(t, "xmodprod")
		res := productUsage(t, ix, "example.com/dep5", "example.com/dep5/deep", "")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
		if len(res.ProductSites) != 0 || len(res.ImportSites) != 0 {
			t.Fatal("NOT_USED must carry no product sites")
		}
	})

	t.Run("TransitivePresentSymbolNotUsed", func(t *testing.T) {
		ix := fixture(t, "xmodprod")
		res := productUsage(t, ix, "example.com/dep5", "example.com/dep5/deep", "Sink")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
	})

	t.Run("UnusedDeclaredSymbolNotUsed", func(t *testing.T) {
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

func main() {
	c, err := vuln.Connect(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}
	_, _ = c.Next()
}
`,
			"gated.go": `//go:build special

package main

import "example.com/dep/vuln"

func gated() string { return vuln.Parse2("x") }
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Qos")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
	})

	t.Run("GatedReferenceIsUnknown", func(t *testing.T) {
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

func main() {
	c, err := vuln.Connect(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}
	_, _ = c.Next()
}
`,
			"gated.go": `//go:build special

package main

import "example.com/dep/vuln"

func gated() string { return vuln.Parse2("x") }
`,
		})
		ix := &Index{Dir: dir}
		// Parse2 is declared and the package is linked, but a build-gated
		// file references it — the negative scope is not closed.
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("GatedPackageImportIsUnknown", func(t *testing.T) {
		// gatedprod imports dep/vuln only under -tags special; the package
		// is both absent from the active closure and referenced by a gated
		// file — either alone forbids NOT_USED.
		ix := fixture(t, "gatedprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("InterfaceDispatchIsUnknown", func(t *testing.T) {
		// ifaceprod instantiates vuln.URI and calls s.String() on an
		// interface value: the concrete impl behind the interface may be
		// URI — an unresolved dispatch candidate that must block the
		// negative even though no typed site names URI.String.
		ix := fixture(t, "ifaceprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "URI.String")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("UninstantiatedDispatchNarrowed", func(t *testing.T) {
		// SafeFormatter is also a Stringer but is never instantiated in
		// product code: instantiation narrowing closes this dispatch gap
		// and the negative verifies.
		ix := fixture(t, "ifaceprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "SafeFormatter.String")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
	})

	t.Run("DynamicMarkerIsUnknown", func(t *testing.T) {
		// reflectprod calls reflect.Value.MethodByName; Conn.Next is an
		// exported method on a product-instantiated receiver type
		// (materialized via the vuln.Connect return), so dynamic dispatch
		// leaves the negative unclosed.
		ix := fixture(t, "reflectprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Conn.Next")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("MissingSymbolIsUnknown", func(t *testing.T) {
		ix := fixture(t, "constprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "DoesNotExist")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("AbsentPackageCompleteClosureVerifiesNotUsed", func(t *testing.T) {
		// dep5/deep is absent from constprod's linked closure, and the
		// closure is complete (every product package type-checked, no
		// truncation): provable absence is positive evidence — a verified
		// negative, not a gap. The dep is not even in go.mod: absence
		// never requires the target to be loadable.
		ix := fixture(t, "constprod")
		res := productUsage(t, ix, "example.com/dep5", "example.com/dep5/deep", "")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
		if got := UsageScopeGaps(res.Limitations); len(got) != 0 {
			t.Fatalf("a verified absence carries no scope gap, got %v", got)
		}
		if len(res.Limitations) != len(usageBaselineLimitations(ix)) {
			t.Fatalf("absence-verified limitations=%v, want only the baseline bounds", res.Limitations)
		}
	})

	t.Run("AbsentPackageSymbolStaysUnknown", func(t *testing.T) {
		// Symbol-level path unchanged: absence never verifies a symbol
		// negative — the symbol check keeps the linked-package premise
		// (its negative belongs to symbol-unreachability).
		ix := fixture(t, "constprod")
		res := productUsage(t, ix, "example.com/dep5", "example.com/dep5/deep", "Sink")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("AbsentPackageIncompleteClosureIsUnknown", func(t *testing.T) {
		// The product fails to type-check one package: the closure is
		// incomplete, so absence stays a fail-closed gap — the target
		// could be linked only through the failed package.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

func main() {}
`,
			"sub/sub.go": `package sub

import "fmt"

func Broken() string {
	return fmt.Sprintf("%d", fmt.Nonexistent())
}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		gaps := UsageScopeGaps(res.Limitations)
		if len(gaps) != 1 || gaps[0] != usageAbsenceGap {
			t.Fatalf("incomplete-closure gaps=%v, want exactly the preserved absence gap", gaps)
		}
	})
	t.Run("AbsentRequiredPackageVerifiesNotUsed", func(t *testing.T) {
		// dep/vuln is required in go.mod but never imported: it is absent
		// from the linked closure of a complete product, so the
		// package-level negative verifies on the absence basis.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

func main() {}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
	})

	t.Run("AbsentRequiredPackageSymbolStaysUnknown", func(t *testing.T) {
		// Same package, symbol subject: the declaration resolves (the
		// package loads from the module cache), but a symbol never
		// verifies on package absence — the symbol-level contract keeps
		// the linked-package premise and reports the absence gap.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

func main() {}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		found := false
		for _, g := range UsageScopeGaps(res.Limitations) {
			if g == usageAbsenceGap {
				found = true
			}
		}
		if !found {
			t.Fatalf("symbol absence gap must be named: %v", res.Limitations)
		}
	})

	t.Run("LinkedPackageDispatchGapUnchanged", func(t *testing.T) {
		// The target is linked transitively (product imports drv, drv
		// imports vuln) and the product dispatches String() through an
		// interface with instantiation narrowing disabled by an unsafe
		// import: a linked package with unresolved dispatch candidates
		// keeps its gap verbatim. (A directly imported package is USED
		// and never reaches the dispatch check.)
		dir := usageModuleGomod(t,
			"module example.com/dispprod\n\ngo 1.23\n\nrequire example.com/dispdep v1.0.0\n\nreplace example.com/dispdep => ./dep\n",
			map[string]string{
				"main.go": `package main

import (
	"fmt"
	_ "unsafe"

	"example.com/dispdep/drv"
)

type stringer interface{ String() string }

func main() {
	var s stringer
	drv.Go()
	fmt.Println(s.String())
}
`,
				"dep/go.mod":     "module example.com/dispdep\n\ngo 1.23\n",
				"dep/drv/drv.go": "package drv\n\nimport \"example.com/dispdep/vuln\"\n\nfunc Go() { _ = vuln.URI{} }\n",
				"dep/vuln/vuln.go": `package vuln

type URI struct{}

func (u URI) String() string { return "uri" }
`,
			})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dispdep", "example.com/dispdep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		want := "interface-dispatched call site(s) may invoke a method of package example.com/dispdep/vuln — the dynamic receiver is unresolved"
		for _, g := range UsageScopeGaps(res.Limitations) {
			if strings.Contains(g, want) {
				return
			}
		}
		t.Fatalf("dispatch gap missing from %v", res.Limitations)
	})

	t.Run("AbsentPackageDispatchSitesProduceNoGap", func(t *testing.T) {
		// The product dispatches String() on an interface — a method
		// name the unlinked dep declares — and disables instantiation
		// narrowing via an unsafe import: the old code reported every
		// such site as a dispatch gap. For an unlinked package the scan
		// is skipped entirely; absence in the complete closure verifies.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"
	_ "unsafe"
)

type stringer interface{ String() string }

func shout(s stringer) string { return s.String() }

func main() {
	var s stringer
	fmt.Println(shout(s))
}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
		if got := UsageScopeGaps(res.Limitations); len(got) != 0 {
			t.Fatalf("no dispatch gap may be reported for an unlinked package, got %v", got)
		}
		// White-box check that suppression is semantic, not an empty
		// candidate set: the dep loads and the product sites would have
		// matched the dispatch-gap rule had the package been linked.
		extra, err := ix.loadExtra(context.Background(), "example.com/dep/vuln")
		if err != nil {
			t.Fatalf("dep load for the white-box dispatch check: %v", err)
		}
		var depPkg *packages.Package
		for _, p := range extra {
			if p.PkgPath == "example.com/dep/vuln" {
				depPkg = p
				break
			}
		}
		if depPkg == nil {
			t.Fatal("dep package did not load for the white-box check")
		}
		if sites := ix.pkgDispatchGaps(depPkg, false); len(sites) == 0 {
			t.Fatal("fixture drift: no dispatch candidates — the no-gap assertion is vacuous")
		}
	})

	t.Run("AbsentPackageSymbolDispatchSuppressed", func(t *testing.T) {
		// Symbol-level counterpart of the dispatch rule: the product
		// dispatches String() on an interface — a method name declared
		// in the unlinked dep — but a dispatch site cannot invoke a
		// method of an unlinked package, so no dispatch gap is reported.
		// The symbol negative itself stays UNKNOWN on the preserved
		// linked-package premise (absence gap only).
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"
	_ "unsafe"
)

type stringer interface{ String() string }

func main() {
	var s stringer
	fmt.Println(s.String())
}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "URI.String")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		gaps := UsageScopeGaps(res.Limitations)
		if len(gaps) != 1 || gaps[0] != usageAbsenceGap {
			t.Fatalf("unlinked symbol gaps=%v, want exactly the absence premise gap", gaps)
		}
	})

	t.Run("UnresolvedReceiverKeepsDispatchOpen", func(t *testing.T) {
		// Missing.String names no declared type: the dispatch scan can
		// only keep the name-matched superset open — a named gap, never
		// an empty candidate list.
		ix := fixture(t, "ifaceprod")
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Missing.String")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		found := false
		for _, g := range UsageScopeGaps(res.Limitations) {
			if strings.Contains(g, "receiver type could not be resolved") {
				found = true
			}
		}
		if !found {
			t.Fatalf("unresolved-receiver dispatch gap missing from %v", res.Limitations)
		}
	})

	t.Run("SkippedPackageBlocksDispatchNarrowing", func(t *testing.T) {
		// SafeFormatter is uninstantiated in every product file the
		// loader can see — but one product package failed to type-check,
		// so the instantiation inventory is incomplete and narrowing is
		// forbidden: the dispatch site stays an open gap.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"

	_ "example.com/dep/vuln"
)

func shout(s fmt.Stringer) string { return s.String() }

func main() { fmt.Println(shout(nil)) }
`,
			"broken/broken.go": `package broken

func Broken() int { return undefinedIdentifier }
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "SafeFormatter.String")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		found := false
		for _, g := range UsageScopeGaps(res.Limitations) {
			if strings.Contains(g, "interface-dispatched call site(s) may invoke") {
				found = true
			}
		}
		if !found {
			t.Fatalf("incomplete inventory must keep the dispatch gap open: %v", res.Limitations)
		}
	})

	t.Run("SkippedPackageBlocksPackageNarrowing", func(t *testing.T) {
		// Package-level twin: the linked dep's method-bearing types look
		// uninstantiated product-side, yet a failed product package makes
		// the inventory incomplete — the dispatch gap must not verify.
		dir := usageModuleGomod(t,
			"module example.com/dispprod\n\ngo 1.23\n\nrequire example.com/dispdep v1.0.0\n\nreplace example.com/dispdep => ./dep\n",
			map[string]string{
				"main.go": `package main

import (
	"fmt"

	"example.com/dispdep/drv"
)

type stringer interface{ String() string }

func main() {
	var s stringer
	drv.Go()
	fmt.Println(s.String())
}
`,
				"broken/broken.go": `package broken

func Broken() int { return undefinedIdentifier }
`,
				"dep/go.mod":     "module example.com/dispdep\n\ngo 1.23\n",
				"dep/drv/drv.go": "package drv\n\nimport \"example.com/dispdep/vuln\"\n\nfunc Go() { _ = vuln.URI{} }\n",
				"dep/vuln/vuln.go": `package vuln

type URI struct{}

func (u URI) String() string { return "uri" }
`,
			})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dispdep", "example.com/dispdep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		found := false
		for _, g := range UsageScopeGaps(res.Limitations) {
			if strings.Contains(g, "interface-dispatched call site(s) may invoke a method of package") {
				found = true
			}
		}
		if !found {
			t.Fatalf("incomplete inventory must keep the package dispatch gap open: %v", res.Limitations)
		}
	})

	t.Run("SkippedPackagePackageNarrowingControl", func(t *testing.T) {
		// Control for SkippedPackageBlocksPackageNarrowing: with every
		// product package type-checked the same module verifies —
		// narrowing was the only thing the broken package blocked.
		dir := usageModuleGomod(t,
			"module example.com/dispprod\n\ngo 1.23\n\nrequire example.com/dispdep v1.0.0\n\nreplace example.com/dispdep => ./dep\n",
			map[string]string{
				"main.go": `package main

import (
	"fmt"

	"example.com/dispdep/drv"
)

type stringer interface{ String() string }

func main() {
	var s stringer
	drv.Go()
	fmt.Println(s.String())
}
`,
				"dep/go.mod":     "module example.com/dispdep\n\ngo 1.23\n",
				"dep/drv/drv.go": "package drv\n\nimport \"example.com/dispdep/vuln\"\n\nfunc Go() { _ = vuln.URI{} }\n",
				"dep/vuln/vuln.go": `package vuln

type URI struct{}

func (u URI) String() string { return "uri" }
`,
			})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dispdep", "example.com/dispdep/vuln", "")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
	})

	t.Run("UnresolvedReceiverReflectMarkerStaysRelevant", func(t *testing.T) {
		// reflect.MethodByName can invoke only instantiated receivers —
		// but an unresolvable receiver type is not proof of
		// non-instantiation, so the marker stays an open gap.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"
	"reflect"
)

type svc struct{}

func main() {
	fmt.Println(reflect.ValueOf(&svc{}).MethodByName("Serve").IsValid())
}
`,
		})
		ix := &Index{Dir: dir}
		// The package is unlinked (the marker product never imports it);
		// the verdict is UNKNOWN either way — the assertion targets the
		// reflect_method gap surviving an unresolved receiver.
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Missing.Next")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		found := false
		for _, g := range UsageScopeGaps(res.Limitations) {
			if strings.Contains(g, "reflect_method") {
				found = true
			}
		}
		if !found {
			t.Fatalf("reflect_method marker must stay relevant for an unresolved receiver: %v", res.Limitations)
		}
	})

	t.Run("EmptySubjectIsUnknown", func(t *testing.T) {
		// A module-only advisory has no package subject: UNKNOWN, never
		// an invented package path verdict.
		ix := fixture(t, "constprod")
		res := productUsage(t, ix, "example.com/dep", "", "")
		checkVerdict(t, res, wantVerdict{
			present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("DeterministicByteStable", func(t *testing.T) {
		ix := fixture(t, "xmodprod")
		subj := domain.SymbolRef{Package: "example.com/dep5/deep", Symbol: "Sink"}
		r1, err := ix.ProductUsage(ctx, "example.com/dep5", subj)
		if err != nil {
			t.Fatal(err)
		}
		b1, err := json.Marshal(r1)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			r2, err := ix.ProductUsage(ctx, "example.com/dep5", subj)
			if err != nil {
				t.Fatal(err)
			}
			b2, err := json.Marshal(r2)
			if err != nil {
				t.Fatal(err)
			}
			if string(b1) != string(b2) {
				t.Fatalf("run %d diverged", i+2)
			}
		}
		// A fresh index over the same snapshot must agree byte-for-byte.
		ix2 := fixture(t, "xmodprod")
		r3, err := ix2.ProductUsage(ctx, "example.com/dep5", subj)
		if err != nil {
			t.Fatal(err)
		}
		b3, err := json.Marshal(r3)
		if err != nil {
			t.Fatal(err)
		}
		if string(b1) != string(b3) {
			t.Fatal("fresh index produced a different result")
		}
	})
}

// UsageScopeGaps splits a ProductUsage limitation list into the fixed
// baseline interpretation bounds (usageBaselineLimitations) and the
// case-specific scope gaps that produced the verdict — the absence-gap
// and every other case finding survive verbatim.
func TestUsageScopeGapsSplitsBaseline(t *testing.T) {
	baseline := usageBaselineLimitations(nil)
	if len(baseline) == 0 {
		t.Fatal("baseline bound list is empty")
	}
	gaps := []string{
		"target package is absent from the linked import closure of the current build context",
		"1 reference(s)/import(s) of example.com/dep/vuln in files excluded by the current build tags",
	}
	lims := append(append([]string(nil), baseline...), gaps...)
	got := UsageScopeGaps(lims)
	if len(got) != 2 || got[0] != gaps[0] || got[1] != gaps[1] {
		t.Fatalf("UsageScopeGaps=%v, want the two specific gaps verbatim", got)
	}
	// Order is payload order, and the input is never mutated.
	if len(UsageScopeGaps(baseline)) != 0 {
		t.Fatal("baseline-only list yields no specific gap")
	}
	// A real verdict mixes baseline + case gaps end-to-end: gatedprod
	// carries exactly one specific gap (the build-gated import) out of
	// five recorded limitations — the package's absence from the
	// complete linked closure is positive evidence, never a gap, and on
	// its own would verify the negative.
	ix := fixture(t, "gatedprod")
	res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "")
	checkVerdict(t, res, wantVerdict{
		present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	if got := UsageScopeGaps(res.Limitations); len(got) != 1 ||
		len(res.Limitations)-len(got) != len(baseline) {
		t.Fatalf("real verdict gaps=%v of %v limitations, want 1 specific + %d baseline",
			got, res.Limitations, len(baseline))
	}
}

func TestProductUsageNegativeVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("SkippedPackageNeverNotUsed", func(t *testing.T) {
		// sub imports the target but fails type-checking: its references
		// are invisible to the index, so absence of sites can never be
		// read as NOT_USED. Parse2 has no references in main either.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import "example.com/dep/vuln"

func main() {
	_ = vuln.Parse
}
`,
			"sub/sub.go": `package sub

import "example.com/dep/vuln"

func Broken() string {
	return vuln.Parse2(undefinedSymbol)
}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("SkippedNonImporterBlocksLinkedNegative", func(t *testing.T) {
		// main links the target, while broken receives an opaque value and
		// imports only fmt. Its syntax cannot close a typed dispatch scan.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"example.com/dep/vuln"
	"example.com/usageprod/broken"
)

func main() {
	_ = vuln.Parse
	broken.Run(any(vuln.Parse))
}
`,
			"broken/broken.go": `package broken

import "fmt"

func Run(value any) {
	fmt.Println(value)
	_ = undefinedIdentifier
}
`,
		})
		ix := &Index{Dir: dir}
		diags, err := ix.SkippedPackageDiagnostics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, d := range diags {
			if d.Path == "example.com/usageprod/broken" {
				found = true
				if !d.SourceVisible || !d.ImportsComplete || slices.Contains(d.Imports, "example.com/dep/vuln") {
					t.Fatalf("counterexample does not exercise recovered non-importer: %+v", d)
				}
			}
		}
		if !found {
			t.Fatalf("broken package missing from skipped census: %+v", diags)
		}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		if gaps := UsageScopeGaps(res.Limitations); len(gaps) == 0 || !strings.Contains(strings.Join(gaps, "; "), "example.com/usageprod/broken") {
			t.Fatalf("missing named skipped-package limitation: %v", gaps)
		}
	})

	t.Run("UnscannedPackageCensusHonest", func(t *testing.T) {
		// A package whose only file is unreadable fails to load with no
		// recoverable source at all: it must appear in the public skipped
		// inventory (feeding ScopeDetails.SkippedPackages and
		// skipped_package_count) and it must block NOT_USED.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import "example.com/dep/vuln"

func main() {
	_ = vuln.Parse
}
`,
			"sub/broken.go": `package sub

import "example.com/dep/vuln"

func Broken() string { return vuln.Parse2("x") }
`,
		})
		if err := os.Chmod(filepath.Join(dir, "sub", "broken.go"), 0o000); err != nil {
			t.Skipf("cannot drop read permission: %v", err)
		}
		defer os.Chmod(filepath.Join(dir, "sub", "broken.go"), 0o644)
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
		skipped, err := ix.SkippedPackages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range skipped {
			if p == "example.com/usageprod/sub" {
				found = true
			}
		}
		if !found || len(skipped) == 0 {
			t.Fatalf("unrecoverable skipped package missing from census: %v", skipped)
		}
	})

	t.Run("ExhaustedBudgetNeverNotUsed", func(t *testing.T) {
		ix := fixture(t, "xmodprod")
		ix.loadBudget = 1 // the dep-package load consumes it
		res := productUsage(t, ix, "example.com/dep5", "example.com/dep5/deep", "Sink")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("CancelledContextNeverNotUsed", func(t *testing.T) {
		ix := fixture(t, "xmodprod")
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		res, err := ix.ProductUsage(cctx, "example.com/dep5",
			domain.SymbolRef{Package: "example.com/dep5/deep", Symbol: "Sink"})
		if err == nil && res.Usage == PackageUsageNotUsed {
			t.Fatal("a cancelled check must never report NOT_USED")
		}
	})

	t.Run("LoadFailureReturnsError", func(t *testing.T) {
		ix := &Index{Dir: filepath.Join(t.TempDir(), "does-not-exist")}
		_, err := ix.ProductUsage(ctx, "example.com/dep",
			domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"})
		if err == nil {
			t.Fatal("a failed product load is an error, not a verdict")
		}
	})

	t.Run("PluginMarkerBlocksNegative", func(t *testing.T) {
		// plugin.Lookup can bind any exported symbol; Parse2 has zero
		// typed references but the escape stays unclosed.
		dir := usageModule(t, map[string]string{
			"main.go": `package main

import (
	"fmt"
	_ "plugin"
	"os"

	"example.com/dep/vuln"
)

func main() {
	_, _ = vuln.Connect(os.Args[1])
	fmt.Println("ok")
}
`,
		})
		ix := &Index{Dir: dir}
		res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
		checkVerdict(t, res, wantVerdict{
			present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	})

	t.Run("EmptyResultIsNotNegativeProof", func(t *testing.T) {
		// Sweep a set of subjects: a NOT_USED verdict must always carry
		// VERIFIED + a bounded scope — an empty site list alone is never
		// negative proof, and UNKNOWN must always explain its scope gap.
		ix := fixture(t, "xmodprod")
		subjects := []domain.SymbolRef{
			{Package: "example.com/dep5/deep", Symbol: "Sink"},
			{Package: "example.com/dep5/driver", Symbol: "Drive"},
			{Package: "example.com/dep5/deep"},
			{Package: "example.com/dep5/driver"},
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
		}
		for _, s := range subjects {
			res := productUsage(t, ix, "example.com/dep5", s.Package, s.Symbol)
			switch res.Usage {
			case PackageUsageNotUsed:
				if res.NegativeVerification != PackageUsageNegativeVerified || res.CheckScope == "" {
					t.Fatalf("NOT_USED for %s.%s lacks verified bounded scope", s.Package, s.Symbol)
				}
			case PackageUsageUsed:
				if len(res.ProductSites) == 0 && len(res.ImportSites) == 0 {
					t.Fatalf("USED for %s.%s must name a concrete site", s.Package, s.Symbol)
				}
			case PackageUsageUnknown:
				if res.NegativeVerification != PackageUsageNegativeInsufficientScope {
					t.Fatalf("UNKNOWN for %s.%s must be INSUFFICIENT_SCOPE", s.Package, s.Symbol)
				}
				if len(res.Limitations) == 0 {
					t.Fatalf("UNKNOWN for %s.%s must record scope-gap limitations", s.Package, s.Symbol)
				}
			default:
				t.Fatalf("unexpected usage state %q for %s.%s", res.Usage, s.Package, s.Symbol)
			}
		}
	})
}

// A failed product package with zero recovered imports still belongs to
// the scope denominator: nothing outside it may close a negative — the
// failed files are unseen product code, and "no imports recovered" is a
// syntactic fact, not proof the package was empty.
func TestSkippedPackageZeroImportStaysInDenominator(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

func main() {}
`,
		"brokenpkg/broken.go": `package brokenpkg

func Broken() int { return undefinedIdentifier }
`,
	})
	ix := &Index{Dir: dir}
	paths, err := ix.SkippedPackages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(paths, "example.com/usageprod/brokenpkg") {
		t.Fatalf("zero-import failed package missing from census: %v", paths)
	}
	res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
	checkVerdict(t, res, wantVerdict{
		present: false, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
}

// TestProductUsageFuncValueGap: a symbol the product never references can
// still be invoked through a func-typed variable — an unresolved
// signature-compatible call site must keep the negative UNKNOWN, and an
// open enumeration is a gap even when no compatible site exists.
func TestProductUsageFuncValueGap(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse")
	checkVerdict(t, res, wantVerdict{
		present: true, usage: PackageUsageUnknown, neg: PackageUsageNegativeInsufficientScope})
	found := false
	for _, l := range res.Limitations {
		if strings.Contains(l, "function-value call site") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unresolved func-value site must be a named gap: %v", res.Limitations)
	}
}

// TestProductUsageFuncValueResolvedNotClosed: a func-value call whose
// candidate set resolves to a sibling symbol still leaves the declared
// subject's negative unverifiable only when it may reach the subject —
// a resolved, incompatible dispatch is not a gap. Parse2's signature
// differs from every product func-value call, so the negative closes.
func TestProductUsageFuncValueResolvedNotClosed(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	res := productUsage(t, ix, "example.com/dep", "example.com/dep/vuln", "Parse2")
	checkVerdict(t, res, wantVerdict{
		present: true, usage: PackageUsageNotUsed, neg: PackageUsageNegativeVerified})
}
