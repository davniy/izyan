package fixbinding

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

const identitySource = `package app

import (
	"os"
	stdos "os"
	"example.com/other"
)

type Config struct {
	Root string
}

type OtherConfig struct {
	Root string
}

type Thing struct{}

func (t *Thing) MkdirAll(path string, m os.FileMode) error { return nil }

func Aliases() {
	os.MkdirAll("/data", 0o700)
	stdos.MkdirAll("/data", 0o700)
	other.MkdirAll("/data", 0o700)
}

func Shadowed(os *Config) {
	os.MkdirAll("x", 0o700)
}

func Method(t *Thing) {
	t.MkdirAll("/data", 0o700)
}

func Resources(config *Config, otherCfg *OtherConfig, config2 *Config) {
	os.MkdirAll(config.Root, 0o700)
	os.MkdirAll(otherCfg.Root, 0o700)
	os.MkdirAll(config2.Root, 0o700)
}

func Aliased(config *Config) {
	p := config.Root
	q := p
	os.MkdirAll(q, 0o700)
	os.MkdirAll(config.Root, 0o700)
}
`

func analyzeIdentitySource(t *testing.T, img Image) *FileAnalysis {
	t.Helper()
	fa, err := AnalyzeFile("app.go", []byte(identitySource), AnalyzeOptions{
		Module: ModuleIdentity{Path: "example.com/app", Version: "v1.0.0"},
		Image:  img,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return fa
}

// callsIn returns the calls of one declared function, in source order.
func callsIn(t *testing.T, fa *FileAnalysis, name string) []CallSite {
	t.Helper()
	decls := append([]DeclaredFunction(nil), fa.Declarations...)
	sort.Slice(decls, func(i, j int) bool { return decls[i].Line < decls[j].Line })
	start, end := -1, 1<<30
	for i, d := range decls {
		if d.Declaration.Name == name {
			start = d.Line
			if i+1 < len(decls) {
				end = decls[i+1].Line
			}
			break
		}
	}
	if start < 0 {
		t.Fatalf("no declaration %s in %+v", name, fa.Declarations)
	}
	var out []CallSite
	for _, c := range fa.Calls {
		if c.Line >= start && c.Line < end {
			out = append(out, c)
		}
	}
	return out
}

func TestQualifiedAPIAndResourceEqualityRequired(t *testing.T) {
	t.Run("aliased imports normalize", func(t *testing.T) {
		fa := analyzeIdentitySource(t, ImageAfter)
		calls := callsIn(t, fa, "Aliases")
		if len(calls) != 3 {
			t.Fatalf("calls = %d: %+v", len(calls), calls)
		}
		for _, c := range calls[:2] {
			if !c.Resolved {
				t.Fatalf("call %s must resolve: %s", c.Func, c.Reason)
			}
			if c.Identity.ImportPath != "os" || c.Identity.Name != "MkdirAll" {
				t.Fatalf("call %s resolved to %+v", c.Func, c.Identity)
			}
		}
		if !calls[0].Identity.Equal(calls[1].Identity) {
			t.Fatalf("an aliased import must normalize to the same API: %+v vs %+v", calls[0].Identity, calls[1].Identity)
		}
		if calls[2].Identity.ImportPath != "example.com/other" {
			t.Fatalf("the unrelated package resolved to %+v", calls[2].Identity)
		}
		if calls[0].Identity.Equal(calls[2].Identity) {
			t.Fatal("an unrelated package's MkdirAll must not equal os.MkdirAll")
		}
		if calls[2].Operation != nil {
			t.Fatalf("an unrelated package's MkdirAll must not be a supported operation: %+v", calls[2].Operation)
		}
	})

	t.Run("shadowed package name", func(t *testing.T) {
		fa := analyzeIdentitySource(t, ImageAfter)
		calls := callsIn(t, fa, "Shadowed")
		if len(calls) != 1 {
			t.Fatalf("calls = %d", len(calls))
		}
		if calls[0].Resolved {
			t.Fatalf("a shadowed os must not resolve to the package: %+v", calls[0].Identity)
		}
		if calls[0].Operation != nil {
			t.Fatalf("a shadowed os must not yield an operation: %+v", calls[0].Operation)
		}
		if calls[0].Reason == "" {
			t.Fatal("an unresolved callee must state why")
		}
	})

	t.Run("same-named method", func(t *testing.T) {
		fa := analyzeIdentitySource(t, ImageAfter)
		calls := callsIn(t, fa, "Method")
		if len(calls) != 1 {
			t.Fatalf("calls = %d", len(calls))
		}
		if !calls[0].Resolved || !calls[0].Local {
			t.Fatalf("the local method must resolve as a local declaration: %+v", calls[0])
		}
		if calls[0].Identity.Receiver != "example.com/app.Thing" {
			t.Fatalf("receiver identity = %q", calls[0].Identity.Receiver)
		}
		std := APIIdentity{Source: "stdlib", ImportPath: "os", Name: "MkdirAll"}
		if calls[0].Identity.Equal(std) {
			t.Fatal("a same-named method must not equal os.MkdirAll")
		}
		if calls[0].Operation != nil {
			t.Fatalf("a same-named method must not be a supported operation: %+v", calls[0].Operation)
		}
	})

	t.Run("unrelated configured roots", func(t *testing.T) {
		fa := analyzeIdentitySource(t, ImageAfter)
		calls := callsIn(t, fa, "Resources")
		if len(calls) != 3 {
			t.Fatalf("calls = %d", len(calls))
		}
		ops := make([]Operation, 3)
		for i, c := range calls {
			if c.Operation == nil {
				t.Fatalf("call %d is not a supported operation: %s", i, c.OperationReason)
			}
			ops[i] = *c.Operation
			if !ops[i].Resource.Resolved() {
				t.Fatalf("call %d resource is unresolved: %s", i, ops[i].Resource.Missing())
			}
		}
		if ops[0].Resource.Equal(ops[1].Resource) {
			t.Fatalf("two unrelated Config.Root fields must not compare equal: %+v", ops[0].Resource)
		}
		if ops[0].Resource.Equal(ops[2].Resource) {
			t.Fatalf("two unrelated Config instances sharing a type must not compare equal: %+v", ops[0].Resource)
		}
		// The same declaration in the pre-image has the same identity.
		before := analyzeIdentitySource(t, ImageBefore)
		beforeCalls := callsIn(t, before, "Resources")
		if beforeCalls[0].Operation == nil {
			t.Fatalf("before image call unresolved: %s", beforeCalls[0].OperationReason)
		}
		if !ops[0].Resource.Equal(beforeCalls[0].Operation.Resource) {
			t.Fatal("the same declared parameter field must be equal across the patch images")
		}
	})

	t.Run("alias chain requires a witnessed equation", func(t *testing.T) {
		fa := analyzeIdentitySource(t, ImageAfter)
		calls := callsIn(t, fa, "Aliased")
		if len(calls) != 2 {
			t.Fatalf("calls = %d", len(calls))
		}
		var resources []ResourceIdentity
		for _, c := range calls {
			if c.Operation == nil {
				t.Fatalf("aliased call is not a supported operation: %s", c.OperationReason)
			}
			resources = append(resources, c.Operation.Resource)
		}
		if !resources[0].Equal(resources[1]) {
			t.Fatalf("p := config.Root; q := p; MkdirAll(q) must equal MkdirAll(config.Root): %+v vs %+v",
				resources[0], resources[1])
		}
		if got := CheckResourceEquation(RuleIdenticalResolvedExpression, resources[0], resources[1], nil); got.Equal {
			t.Fatalf("an equation without source witnesses must not hold: %+v", got)
		} else if !strings.Contains(got.Reason, "witness") {
			t.Fatalf("the refusal must name the missing witness: %q", got.Reason)
		}
		witnesses := append(append([]Witness{}, resources[0].Expr.Witnesses...), resources[1].Expr.Witnesses...)
		got := CheckResourceEquation(RuleIdenticalResolvedExpression, resources[0], resources[1], witnesses)
		if !got.Equal {
			t.Fatalf("a structurally equal expression with witnesses must hold: %+v", got)
		}
	})

	t.Run("rendered text is not an equation", func(t *testing.T) {
		src := `package app

import "os"

type Config struct{ Root string }
type OtherConfig struct{ Root string }

func F(config *Config)      { os.MkdirAll(config.Root, 0o700) }
func G(config *OtherConfig) { os.MkdirAll(config.Root, 0o700) }
`
		fa, err := AnalyzeFile("same.go", []byte(src), AnalyzeOptions{
			Module: ModuleIdentity{Path: "example.com/app"}, Image: ImageAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		var resources []ResourceIdentity
		for _, c := range fa.Calls {
			if c.Operation == nil {
				t.Fatalf("call unresolved: %s", c.OperationReason)
			}
			resources = append(resources, c.Operation.Resource)
		}
		if len(resources) != 2 {
			t.Fatalf("resources = %d", len(resources))
		}
		if resources[0].Expr.Text != resources[1].Expr.Text {
			t.Fatalf("the test needs identical rendered text, got %q and %q", resources[0].Expr.Text, resources[1].Expr.Text)
		}
		if resources[0].Equal(resources[1]) {
			t.Fatal("identical rendered text must not make two unrelated resources equal")
		}
		eq := CheckResourceEquation(RuleIdenticalResolvedExpression, resources[0], resources[1],
			append(resources[0].Expr.Witnesses, resources[1].Expr.Witnesses...))
		if eq.Equal {
			t.Fatalf("a rendered string must not establish an equation: %+v", eq)
		}
	})

	t.Run("same declaration value", func(t *testing.T) {
		src := `package app

import "os"

func F(p string) { os.MkdirAll(p, 0o700) }
`
		after, err := AnalyzeFile("value.go", []byte(src), AnalyzeOptions{
			Module: ModuleIdentity{Path: "example.com/app"}, Image: ImageAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		before, err := AnalyzeFile("value.go", []byte(src), AnalyzeOptions{
			Module: ModuleIdentity{Path: "example.com/app"}, Image: ImageBefore,
		})
		if err != nil {
			t.Fatal(err)
		}
		if after.Calls[0].Operation == nil || before.Calls[0].Operation == nil {
			t.Fatal("the parameter operand must resolve on both images")
		}
		left := after.Calls[0].Operation.Resource
		right := before.Calls[0].Operation.Resource
		if !left.Equal(right) {
			t.Fatalf("the same declared parameter must be equal across images: %+v vs %+v", left, right)
		}
		eq := CheckResourceEquation(RuleSameDeclarationValue, left, right,
			append(left.Expr.Witnesses, right.Expr.Witnesses...))
		if !eq.Equal {
			t.Fatalf("the same-declaration-value equation must hold: %+v", eq)
		}
	})

	t.Run("constructor application is structured", func(t *testing.T) {
		src := `package app

import (
	"os"
	"path/filepath"
)

type Config struct{ Root string }

func F(config *Config) {
	root := filepath.Join(config.Root, "bound")
	os.MkdirAll(root, 0o700)
	os.MkdirAll(filepath.Join(config.Root, "bound"), 0o700)
}
`
		fa, err := AnalyzeFile("ctor.go", []byte(src), AnalyzeOptions{
			Module: ModuleIdentity{Path: "example.com/app"}, Image: ImageAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		var resources []ResourceIdentity
		for _, c := range fa.Calls {
			if c.Operation == nil {
				continue
			}
			resources = append(resources, c.Operation.Resource)
		}
		if len(resources) != 2 {
			t.Fatalf("supported operation resources = %d", len(resources))
		}
		if !resources[0].Equal(resources[1]) {
			t.Fatalf("a constructor application must compare structurally: %+v vs %+v", resources[0], resources[1])
		}
		eq := CheckResourceEquation(RuleSameConstructorApplication, resources[0], resources[1],
			append(resources[0].Expr.Witnesses, resources[1].Expr.Witnesses...))
		if !eq.Equal {
			t.Fatalf("the constructor equation must hold: %+v", eq)
		}
	})

	t.Run("missing patch-side qualification stays unresolved", func(t *testing.T) {
		patch := `diff --git a/pkg/new.go b/pkg/new.go
new file mode 100644
--- /dev/null
+++ b/pkg/new.go
@@ -0,0 +1,5 @@
+package pkg
+
+import "os"
+
+func New() { os.MkdirAll("/data", 0o700) }
`
		inv, err := InventoryPatch([]byte(patch), InventoryOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(inv.Effects) != 0 {
			t.Fatalf("no operation can be recognised without patch-side qualification: %+v", inv.Effects)
		}
		found := false
		for _, r := range inv.Residuals {
			if r.Kind == ResidualMissingSource {
				found = true
			}
		}
		if !found {
			t.Fatalf("a missing patch-side source must stay an obligation: %+v", inv.Residuals)
		}
		if inv.Complete() {
			t.Fatal("a patch with unqualified operations cannot be complete")
		}
	})

	t.Run("repository-local wrapper requires a checked body summary", func(t *testing.T) {
		src := `package pkg

import (
	"io/fs"
	"os"
)

type Config struct{ Root string }

func mkdirAll(root string, perm fs.FileMode) error {
	return os.MkdirAll(root, perm)
}

func Use(config *Config) {
	_ = mkdirAll(config.Root, 0o700)
}
`
		fa, err := AnalyzeFile("pkg/a.go", []byte(src), AnalyzeOptions{
			Module: ModuleIdentity{Path: "example.com/app"}, Image: ImageAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		var wrapper DeclaredFunction
		for _, d := range fa.Declarations {
			if d.Declaration.Name == "mkdirAll" {
				wrapper = d
			}
		}
		if wrapper.Identity.Name == "" {
			t.Fatalf("wrapper declaration not found: %+v", fa.Declarations)
		}
		target := APIIdentity{
			Source: "stdlib", ImportPath: "os", Name: "MkdirAll",
			Signature: "func(path string, perm os.FileMode) error",
		}
		summary := WrapperSummary{
			Function:   wrapper.Identity,
			BodyDigest: wrapper.BodyDigest,
			Forwards: []WrapperForward{{
				Target: target, Class: ClassDirCreate, ResourceParam: 0, ModeParam: 1,
			}},
		}
		patch := addedFilePatch("pkg/a.go", src)
		source := &SourceBundle{
			Module:   ModuleIdentity{Path: "example.com/app"},
			Files:    map[string]FileSource{"pkg/a.go": {After: []byte(src)}},
			Wrappers: []WrapperSummary{summary},
		}
		inv, err := InventoryPatch([]byte(patch), InventoryOptions{Source: source})
		if err != nil {
			t.Fatal(err)
		}
		var wrapped *Effect
		for i := range inv.Effects {
			if inv.Effects[i].Class == ClassDirCreate && inv.Effects[i].After != nil &&
				inv.Effects[i].After.Identity.Equal(target) {
				wrapped = &inv.Effects[i]
			}
		}
		if wrapped == nil {
			t.Fatalf("the wrapper call was not resolved through its summary: %+v", inv.Effects)
		}
		if wrapped.After.Mode != "0700" {
			t.Fatalf("wrapper mode = %q", wrapped.After.Mode)
		}
		if !wrapped.After.Resource.Resolved() {
			t.Fatalf("wrapper resource is unresolved: %s", wrapped.After.Resource.Missing())
		}

		tampered := source
		tampered.Wrappers = []WrapperSummary{{
			Function: summary.Function, BodyDigest: "sha256:0000",
			Forwards: summary.Forwards,
		}}
		inv, err = InventoryPatch([]byte(patch), InventoryOptions{Source: tampered})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range inv.Effects {
			if e.After != nil && e.After.Identity.Equal(target) {
				t.Fatalf("a summary not bound to the body must not establish the operation: %+v", e)
			}
		}
	})
}

// addedFilePatch renders a new-file unified diff for src.
func addedFilePatch(path, src string) string {
	lines := strings.Split(strings.TrimSuffix(src, "\n"), "\n")
	var b strings.Builder
	fmt.Fprintf(&b, "diff --git a/%s b/%s\nnew file mode 100644\n--- /dev/null\n+++ b/%s\n", path, path, path)
	fmt.Fprintf(&b, "@@ -0,0 +1,%d @@\n", len(lines))
	for _, line := range lines {
		b.WriteString("+")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
