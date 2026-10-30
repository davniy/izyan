package affected

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// vendSnapRoot builds a minimal vendored snapshot:
//
//	module example.com/host (main module)
//	  main.go            — imports dep/shared (product code with tests)
//	  main_test.go       — imports dep/testonly (test-only linkage)
//	  lib/lib.go         — imports dep/prod (untested second product root)
//	vendor/example.com/dep v1.0.0 with packages prod, shared, testonly,
//	internal/helper — dep/prod imports dep/internal/helper to prove
//	vendored-internal visibility inside the module boundary.
//	vendor/example.com/unused v1.0.0 with package pkg — a complete,
//	consistent vendored module nothing imports: listed but unreachable,
//	so a module-level subject can never claim inventory absence.
//
// Every class the tool reports is exercised from this one tree.
func vendSnapRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/host\n\ngo 1.23\n\nrequire (\n\texample.com/dep v1.0.0\n\texample.com/unused v1.0.0\n)\n")
	write("main.go", "package main\n\nimport (\n\t\"fmt\"\n\t\"example.com/dep/shared\"\n)\n\nfunc main() { fmt.Println(shared.Name()) }\n")
	write("main_test.go", "package main\n\nimport (\n\t\"testing\"\n\t\"example.com/dep/testonly\"\n)\n\nfunc TestProbe(t *testing.T) {\n\tif testonly.Name() == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n")
	// lib carries no tests: its prod import stays product-only — a test
	// variant would inherit the prod imports and reclassify it mixed.
	write("lib/lib.go", "package lib\n\nimport \"example.com/dep/prod\"\n\nfunc V() string { return prod.Name() }\n")
	write("vendor/modules.txt",
		"# example.com/dep v1.0.0\n"+
			"## explicit; go 1.23\n"+
			"example.com/dep/internal/helper\n"+
			"example.com/dep/prod\n"+
			"example.com/dep/shared\n"+
			"example.com/dep/testonly\n"+
			"# example.com/unused v1.0.0\n"+
			"## explicit; go 1.23\n"+
			"example.com/unused/pkg\n")
	write("vendor/example.com/dep/internal/helper/helper.go", "package helper\n\nfunc Help() string { return \"h\" }\n")
	write("vendor/example.com/dep/prod/prod.go", "package prod\n\nimport \"example.com/dep/internal/helper\"\n\nfunc Name() string { return helper.Help() }\n")
	write("vendor/example.com/dep/shared/shared.go", "package shared\n\nfunc Name() string { return \"s\" }\n")
	write("vendor/example.com/dep/testonly/testonly.go", "package testonly\n\nfunc Name() string { return \"t\" }\n")
	write("vendor/example.com/unused/pkg/pkg.go", "package pkg\n\nfunc Name() string { return \"u\" }\n")
	return root
}

// derive runs the offline deriver and fails the test on error.
func derive(t *testing.T, root string, build domain.ProductSnapshot, module, pkg string) UsageScopeResult {
	t.Helper()
	res, err := DeriveVendorUsageScope(context.Background(), root, build, module, pkg)
	if err != nil {
		t.Fatalf("DeriveVendorUsageScope(%s, %s): %v", module, pkg, err)
	}
	return res
}

// deriveErr asserts the derivation failed closed and names the reason
// family in the error — an error is the only honest outcome of an
// incomplete or unsupported shape.
func deriveErr(t *testing.T, root string, build domain.ProductSnapshot, module, pkg, want string) {
	t.Helper()
	res, err := DeriveVendorUsageScope(context.Background(), root, build, module, pkg)
	if err == nil {
		t.Fatalf("DeriveVendorUsageScope(%s, %s) succeeded: %+v — a %s shape must fail closed", module, pkg, res, want)
	}
	if res.Usage != UsageScopeUnknown || res.ProductAbsenceVerification != "" {
		t.Fatalf("errored result must not read as a classification: %+v", res)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not name %q", err, want)
	}
}

// TestVendorClosureClasses classifies every advisory-target shape over one
// vendored fixture: product-only, test-only with verified product absence,
// mixed, absent-from-both and the module-level aggregate.
func TestVendorClosureClasses(t *testing.T) {
	root := vendSnapRoot(t)
	build := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64", VendorMode: true}

	t.Run("product", func(t *testing.T) {
		res := derive(t, root, build, "example.com/dep", "example.com/dep/prod")
		if res.Usage != UsageScopeProduct || !res.ProductLinked || res.TestLinked {
			t.Fatalf("product classification: %+v", res)
		}
		if res.ProductAbsenceVerification != "" {
			t.Fatalf("product result carries absence verification %q", res.ProductAbsenceVerification)
		}
		if res.Source != VendorClosureSource {
			t.Fatalf("source=%q", res.Source)
		}
	})

	t.Run("test-only verified", func(t *testing.T) {
		res := derive(t, root, build, "example.com/dep", "example.com/dep/testonly")
		if res.Usage != UsageScopeTestOnly || res.ProductLinked || !res.TestLinked {
			t.Fatalf("test-only classification: %+v", res)
		}
		if res.ProductAbsenceVerification != ProductAbsenceVerificationVerified {
			t.Fatalf("product_absence_verification=%q, want VERIFIED", res.ProductAbsenceVerification)
		}
		if res.ProductRootCount == 0 || res.TestRootCount == 0 {
			t.Fatalf("root counts: %+v", res)
		}
	})

	t.Run("mixed", func(t *testing.T) {
		res := derive(t, root, build, "example.com/dep", "example.com/dep/shared")
		if res.Usage != UsageScopeMixed || !res.ProductLinked || !res.TestLinked {
			t.Fatalf("mixed classification: %+v", res)
		}
	})

	t.Run("absent from both under closed vendor inventory", func(t *testing.T) {
		res := derive(t, root, build, "example.com/dep", "example.com/dep/absent")
		if res.Usage != UsageScopeUnknown || res.ProductLinked || res.TestLinked {
			t.Fatalf("unknown classification: %+v", res)
		}
		if res.ProductAbsenceVerification != ProductAbsenceVerificationVendorInventory {
			t.Fatalf("vendor-inventory absence must carry VERIFIED_VENDOR_INVENTORY: %+v", res)
		}
	})

	t.Run("module aggregate", func(t *testing.T) {
		res := derive(t, root, build, "example.com/dep", "")
		if res.Usage != UsageScopeMixed || !res.ProductLinked || !res.TestLinked {
			t.Fatalf("module aggregate: %+v", res)
		}
		if len(res.Limitations) == 0 {
			t.Fatal("module aggregate must name its aggregate interpretation bound")
		}
	})

	t.Run("absent module aggregate verified by inventory", func(t *testing.T) {
		// A module absent from go.mod, modules.txt, the vendor tree and
		// the first-party set gets the vendor-inventory absence marker at
		// module granularity — usage stays unknown, never test-only.
		res := derive(t, root, build, "example.com/gone", "")
		if res.Usage != UsageScopeUnknown {
			t.Fatalf("absent module aggregate: %+v", res)
		}
		if res.ProductAbsenceVerification != ProductAbsenceVerificationVendorInventory {
			t.Fatalf("module-level inventory absence must carry VERIFIED_VENDOR_INVENTORY: %+v", res)
		}
	})

	t.Run("listed-but-unreachable module keeps no marker", func(t *testing.T) {
		// example.com/unused sits in the closed vendor inventory, so the
		// module is not inventory-absent — the aggregate stays a plain
		// unknown without the absence marker.
		res := derive(t, root, build, "example.com/unused", "")
		if res.Usage != UsageScopeUnknown {
			t.Fatalf("listed-but-unreachable module aggregate: %+v", res)
		}
		if res.ProductAbsenceVerification != "" {
			t.Fatalf("module present in the inventory must not carry an absence marker: %q", res.ProductAbsenceVerification)
		}
	})
}

// TestVendorClosureStdlibOpacity: a stdlib-shaped target absent from the
// product set can never verify product absence — stdlib-internal edges
// are opaque to this derivation.
func TestVendorClosureStdlibOpacity(t *testing.T) {
	root := vendSnapRoot(t)
	build := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64", VendorMode: true}
	res := derive(t, root, build, "internal/cpu", "internal/cpu")
	if res.Usage == UsageScopeTestOnly || res.ProductAbsenceVerification != "" {
		t.Fatalf("stdlib-shaped target must not verify absence: %+v", res)
	}
	if res.Usage != UsageScopeUnknown {
		t.Fatalf("stdlib-shaped target: %+v", res)
	}
	found := false
	for _, l := range res.Limitations {
		if strings.Contains(l, "stdlib") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stdlib opacity not recorded: %v", res.Limitations)
	}
}

// TestVendorClosureInventoryMarker: the VERIFIED_VENDOR_INVENTORY
// marker is emitted only when every emission condition holds —
// vendor_mode recorded, the inventory complete and consistency-checked,
// the subject absent at its declared granularity. Any broken or
// incomplete shape fails closed, and an unrecorded vendor mode strips
// the marker from an otherwise identical absent-from-both result.
func TestVendorClosureInventoryMarker(t *testing.T) {
	build := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64", VendorMode: true}

	t.Run("package absent at exact identity", func(t *testing.T) {
		root := vendSnapRoot(t)
		res := derive(t, root, build, "example.com/dep", "example.com/dep/absent")
		if res.Usage != UsageScopeUnknown ||
			res.ProductAbsenceVerification != ProductAbsenceVerificationVendorInventory {
			t.Fatalf("package-level vendor-inventory absence: %+v", res)
		}
	})

	t.Run("module absent at empty package identity", func(t *testing.T) {
		root := vendSnapRoot(t)
		res := derive(t, root, build, "example.com/gone", "")
		if res.Usage != UsageScopeUnknown || res.Package != "" ||
			res.ProductAbsenceVerification != ProductAbsenceVerificationVendorInventory {
			t.Fatalf("module-level vendor-inventory absence: %+v", res)
		}
	})

	t.Run("module vendored but unreachable", func(t *testing.T) {
		root := vendSnapRoot(t)
		res := derive(t, root, build, "example.com/unused", "")
		if res.Usage != UsageScopeUnknown || res.ProductAbsenceVerification != "" {
			t.Fatalf("a module present in the closed inventory is not inventory-absent: %+v", res)
		}
	})

	t.Run("unrecorded vendor mode suppresses the marker", func(t *testing.T) {
		root := vendSnapRoot(t)
		res := derive(t, root, domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"},
			"example.com/gone", "")
		if res.Usage != UsageScopeUnknown || res.ProductAbsenceVerification != "" {
			t.Fatalf("marker requires the recorded vendor_mode=true context: %+v", res)
		}
	})

	t.Run("missing modules.txt fails closed", func(t *testing.T) {
		root := vendSnapRoot(t)
		if err := os.Remove(filepath.Join(root, "vendor", "modules.txt")); err != nil {
			t.Fatal(err)
		}
		deriveErr(t, root, build, "example.com/gone", "", "modules.txt")
	})

	t.Run("malformed modules.txt fails closed", func(t *testing.T) {
		root := vendSnapRoot(t)
		if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"),
			[]byte("# example.com/dep v1.0.0\nbogus package line\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		deriveErr(t, root, build, "example.com/gone", "", "malformed")
	})

	t.Run("stray vendored package fails closed", func(t *testing.T) {
		root := vendSnapRoot(t)
		d := filepath.Join(root, "vendor", "example.com", "dep", "extra")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "e.go"), []byte("package extra\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		deriveErr(t, root, build, "example.com/gone", "", "incomplete vendor metadata")
	})

	t.Run("module present in go.mod require never marked", func(t *testing.T) {
		root := vendSnapRoot(t)
		res := derive(t, root, build, "example.com/dep", "")
		if res.Usage == UsageScopeUnknown && res.ProductAbsenceVerification != "" {
			t.Fatalf("impossible state: %+v", res)
		}
		if res.ProductAbsenceVerification == ProductAbsenceVerificationVendorInventory {
			t.Fatalf("vendored-and-linked module carries the absence marker: %+v", res)
		}
	})
}

// TestVendorClosureBuildContext: the recorded GOOS and build tags select
// which files — and therefore which imports — the closure sees.
func TestVendorClosureBuildContext(t *testing.T) {
	root := vendSnapRoot(t)
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A windows-only file links dep/testonly into the product closure.
	write("lib/x_windows.go", "package lib\n\nimport _ \"example.com/dep/testonly\"\n")
	// A tag-gated file does the same under the recorded tag.
	write("lib/tagged.go", "//go:build specialtag\n\npackage lib\n\nimport _ \"example.com/dep/testonly\"\n")

	base := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	res := derive(t, root, base, "example.com/dep", "example.com/dep/testonly")
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("linux/untagged: %+v", res)
	}
	res = derive(t, root, domain.ProductSnapshot{GOOS: "windows", GOARCH: "amd64"}, "example.com/dep", "example.com/dep/testonly")
	if res.Usage != UsageScopeMixed || !res.ProductLinked {
		t.Fatalf("windows: %+v — windows-only import must join the product closure", res)
	}
	res = derive(t, root, domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64", BuildTags: []string{"specialtag"}}, "example.com/dep", "example.com/dep/testonly")
	if res.Usage != UsageScopeMixed || !res.ProductLinked {
		t.Fatalf("specialtag: %+v — tag-gated import must join the product closure", res)
	}
}

// TestVendorClosureCgoContext: with CGO_ENABLED=0 a file importing "C" is
// excluded exactly as the toolchain excludes it; under CGO_ENABLED=1 the
// same file is an unsupported build feature — an error, never a negative.
func TestVendorClosureCgoContext(t *testing.T) {
	write := func(root, rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root := vendSnapRoot(t)
	write(root, "lib/cgo.go", "package lib\n\n/*\nint one() { return 1; }\n*/\nimport \"C\"\n\nimport _ \"example.com/dep/testonly\"\n\nvar _ = C.one()\n")
	res := derive(t, root, domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}, "example.com/dep", "example.com/dep/testonly")
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("CGO_ENABLED=0: cgo file must be excluded: %+v", res)
	}
	deriveErr(t, root, domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64", CGOEnabled: true},
		"example.com/dep", "example.com/dep/testonly", "imports \"C\"")
}

// TestVendorClosureFailClosed covers every incomplete or unsupported
// shape: each must return an error naming the reason — never a
// classification, never a silent absence.
func TestVendorClosureFailClosed(t *testing.T) {
	build := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}

	cases := []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   string
	}{
		{"malformed source", func(t *testing.T, root string) {
			must := os.WriteFile(filepath.Join(root, "lib", "lib.go"), []byte("package lib\n\nimport (\n"), 0o644)
			if must != nil {
				t.Fatal(must)
			}
		}, "parse"},
		{"unresolved import", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "lib", "lib.go"),
				[]byte("package lib\n\nimport _ \"example.com/dep/missing\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "unresolved import"},
		{"unlisted vendored package", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "lib", "lib.go"),
				[]byte("package lib\n\nimport _ \"example.com/dep/unlisted\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			d := filepath.Join(root, "vendor", "example.com", "dep", "unlisted")
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "u.go"), []byte("package unlisted\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "unlisted in modules.txt"},
		{"unlisted stray vendor dir", func(t *testing.T, root string) {
			d := filepath.Join(root, "vendor", "example.com", "dep", "extra")
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "e.go"), []byte("package extra\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "incomplete vendor metadata"},
		{"listed package dir missing", func(t *testing.T, root string) {
			mt := filepath.Join(root, "vendor", "modules.txt")
			b, err := os.ReadFile(mt)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(mt, append(b, "# example.com/hanging v0.9.9\n## explicit\nexample.com/hanging/pkg\n"...), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "go.mod"),
				[]byte("module example.com/host\n\ngo 1.23\n\nrequire (\n\texample.com/dep v1.0.0\n\texample.com/unused v1.0.0\n\texample.com/hanging v0.9.9\n)\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "missing at"},
		{"vendored module not required", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "go.mod"),
				[]byte("module example.com/host\n\ngo 1.23\n\nrequire example.com/other v1.0.0\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "not required in go.mod"},
		{"header version mismatch", func(t *testing.T, root string) {
			mt := filepath.Join(root, "vendor", "modules.txt")
			b, err := os.ReadFile(mt)
			if err != nil {
				t.Fatal(err)
			}
			b = []byte(strings.Replace(string(b), "v1.0.0", "v9.9.9", 1))
			if err := os.WriteFile(mt, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "version"},
		{"direct require not explicit", func(t *testing.T, root string) {
			mt := filepath.Join(root, "vendor", "modules.txt")
			b, err := os.ReadFile(mt)
			if err != nil {
				t.Fatal(err)
			}
			b = []byte(strings.Replace(string(b), "## explicit; go 1.23", "## go 1.23", 1))
			if err := os.WriteFile(mt, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "explicit"},
		{"replace not mirrored", func(t *testing.T, root string) {
			mt := filepath.Join(root, "vendor", "modules.txt")
			b, err := os.ReadFile(mt)
			if err != nil {
				t.Fatal(err)
			}
			b = []byte(strings.Replace(string(b), "# example.com/dep v1.0.0",
				"# example.com/dep v1.0.0 => example.com/fork v1.2.3", 1))
			if err := os.WriteFile(mt, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "replace"},
		{"go.work composition", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "go.work"),
				[]byte("go 1.23\n\nuse .\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "go.work"},
		{"undecidable go1 tag", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "lib", "future.go"),
				[]byte("//go:build go1.99\n\npackage lib\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "decidable release floor"},
		{"malformed build constraint", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "lib", "bad.go"),
				[]byte("//go:build (\n\npackage lib\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "build constraint"},
		{"import cycle", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "lib", "lib.go"),
				[]byte("package lib\n\nimport _ \"example.com/host/cyc\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			d := filepath.Join(root, "cyc")
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "c.go"),
				[]byte("package cyc\n\nimport _ \"example.com/host/lib\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "import cycle"},
		{"syso object", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "lib", "blob.syso"), []byte{0}, 0o644); err != nil {
				t.Fatal(err)
			}
		}, ".syso"},
		{"cross-module internal import", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "main.go"),
				[]byte("package main\n\nimport \"example.com/dep/internal/helper\"\n\nfunc main() { println(helper.Help()) }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "internal"},
		{"nested module composition", func(t *testing.T, root string) {
			d := filepath.Join(root, "nested")
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example.com/host/nested\n\ngo 1.23\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "n.go"), []byte("package nested\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "lib", "lib.go"),
				[]byte("package lib\n\nimport _ \"example.com/host/nested\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "nested module"},
		{"empty product enumeration", func(t *testing.T, root string) {
			for _, f := range []string{"main.go", "main_test.go", filepath.Join("lib", "lib.go")} {
				if err := os.Remove(filepath.Join(root, f)); err != nil {
					t.Fatal(err)
				}
			}
		}, "no first-party packages"},
		{"malformed go.mod", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module\n\nrequire ("), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "go.mod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := vendSnapRoot(t)
			tc.mutate(t, root)
			deriveErr(t, root, build, "example.com/dep", "example.com/dep/testonly", tc.want)
		})
	}
}

// TestVendorClosureDeterministic: the same inputs derive byte-identical
// results — the observation payload must be replay-stable.
func TestVendorClosureDeterministic(t *testing.T) {
	root := vendSnapRoot(t)
	build := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	r1 := derive(t, root, build, "example.com/dep", "example.com/dep/testonly")
	r2 := derive(t, root, build, "example.com/dep", "example.com/dep/testonly")
	b1, err := json.Marshal(r1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(r2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("non-deterministic result:\n%s\n%s", b1, b2)
	}
}
