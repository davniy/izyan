package fixbinding

import (
	"strings"
	"testing"
)

// containerdCRIPatch is the exact captured patch from the reviewed case
// (github.com/containerd/cri#1628). Its two hunks change executable code this
// inventory cannot classify as a supported operation, and the patch belongs to
// another repository than the module it was reviewed against. It must never be
// discharged by a name-absence proof.
func containerdCRIPatch() []byte {
	return []byte(`diff --git a/pkg/server/container_create_unix.go b/pkg/server/container_create_unix.go
index 6ebebf9ad..bbe55e2cf 100644
--- a/pkg/server/container_create_unix.go
+++ b/pkg/server/container_create_unix.go
@@ -147,7 +147,7 @@ func (c *criService) containerSpec(id string, sandboxID string, sandboxPid uint3
 
 	// Apply envs from image config first, so that envs from container config
 	// can override them.
-	env := imageConfig.Env
+	env := append([]string{}, imageConfig.Env...)
 	for _, e := range config.GetEnvs() {
 		env = append(env, e.GetKey()+"="+e.GetValue())
 	}
diff --git a/pkg/server/container_create_windows.go b/pkg/server/container_create_windows.go
index 86a08d89e..b689f3246 100644
--- a/pkg/server/container_create_windows.go
+++ b/pkg/server/container_create_windows.go
@@ -52,7 +52,7 @@ func (c *criService) containerSpec(id string, sandboxID string, sandboxPid uint3
 
 	// Apply envs from image config first, so that envs from container config
 	// can override them.
-	env := imageConfig.Env
+	env := append([]string{}, imageConfig.Env...)
 	for _, e := range config.GetEnvs() {
 		env = append(env, e.GetKey()+"="+e.GetValue())
 	}
`)
}

// deriveVariant derives the fixture with extra or replaced selected-source files
// and an optional captured external implementation component.
func deriveVariant(t *testing.T, extra map[string][]byte, external []ExternalComponent) (Binding, error) {
	t.Helper()
	in := fixtureInputs(t)
	files := fixtureSelectedFiles()
	for name, body := range extra {
		files[name] = body
	}
	in.Captures, _ = captureFixture(t, fixtureRecordBytes(), files, external...)
	in.Inventory = inventoryForCaptures(t, files, in.Captures)
	return Derive(in)
}

// effectOfClass returns the fixture's effect for one operation class.
func effectOfClass(t *testing.T, binding Binding, class string) EffectRecord {
	t.Helper()
	for _, effect := range binding.Effects {
		if effect.Class == class {
			return effect
		}
	}
	t.Fatalf("no effect of class %s in %+v", class, binding.Effects)
	return EffectRecord{}
}

// hasLocation reports whether any location was verified in the named file.
func hasLocation(effect EffectRecord, file string) bool {
	for _, location := range effect.Locations {
		if location.File == file {
			return true
		}
	}
	return false
}

// hasLocationComponent reports whether a location came from the named boundary
// component.
func hasLocationComponent(effect EffectRecord, component string) bool {
	for _, location := range effect.Locations {
		if location.Component == component {
			return true
		}
	}
	return false
}

// coverHasSubject reports whether the cover's necessary subject set carries the
// subject.
func coverHasSubject(binding Binding, pkg, symbol string) bool {
	for _, subject := range binding.Cover.Subjects {
		if subject.Package == pkg && subject.Symbol == symbol {
			return true
		}
	}
	return false
}

// TestNonCounterpartRequiresClosedImplementationProof pins F8. A counterpart that
// carries none of the patched names, a split or wrapped implementation, an
// imported implementation component, a registration initializer in another
// file or package, an inline initializer closure and an exported constructor are
// all represented or blocking. Opaque foreign changes never earn INAPPLICABLE,
// and a removed or shortened certificate is refused.
func TestNonCounterpartRequiresClosedImplementationProof(t *testing.T) {
	base := fixtureInputs(t)
	baseBinding := deriveFixture(t, base)
	baseline := effectOfClass(t, baseBinding, string(ClassModeChange))
	if baseline.Disposition != DispositionInapplicable || baseline.Certificate == nil {
		t.Fatalf("baseline effect is %s; the fixture must earn a closed-boundary certificate: %s",
			baseline.Disposition, effectText(baseline))
	}
	if baseline.Certificate.Rule != CertificateStructuralRule {
		t.Fatalf("certificate rule=%q", baseline.Certificate.Rule)
	}
	if len(baseline.Certificate.Registrations) == 0 {
		t.Fatal("the certificate accounted for no registration construction")
	}
	if len(baseline.Subjects) != 0 {
		t.Fatalf("a discharged effect carries subjects: %v", baseline.Subjects)
	}

	t.Run("renamed counterpart is represented", func(t *testing.T) {
		binding, err := deriveVariant(t, map[string][]byte{
			"ops/ops.go": []byte(`package ops

import (
	"os"

	"example.com/dep/config"
)

// Fixup carries none of the patched declaration's names; the mechanism is what
// identifies it.
func Fixup(cfg *config.Config) {
	_ = os.Chmod(cfg.Root, 0o700)
}
`),
		}, nil)
		if err != nil {
			t.Fatalf("renamed counterpart was not represented: %v\n%s", err, binding.Detail)
		}
		effect := effectOfClass(t, binding, string(ClassModeChange))
		if effect.Disposition != DispositionMapped {
			t.Fatalf("renamed counterpart disposition=%s: %s", effect.Disposition, effectText(effect))
		}
		if !hasLocation(effect, "ops/ops.go") {
			t.Fatalf("renamed counterpart is not among the verified locations: %s", effectText(effect))
		}
		if !coverHasSubject(binding, "example.com/dep/ops", "Fixup") {
			t.Fatalf("renamed counterpart is not in the necessary cover: %+v", binding.Cover)
		}
	})

	t.Run("split and wrapped counterparts are represented", func(t *testing.T) {
		shapes := map[string]string{
			"split": `package ops

import (
	"os"

	"example.com/dep/config"
)

func Fixup(cfg *config.Config) { repairRoot(cfg.Root) }

func repairRoot(root string) { os.Chmod(root, 0o700) }
`,
			"wrapped": `package ops

import (
	"os"

	"example.com/dep/config"
)

func Tidy(cfg *config.Config) { chmodRoot(cfg.Root) }

func chmodRoot(root string) { os.Chmod(root, 0o700) }
`,
		}
		for name, body := range shapes {
			t.Run(name, func(t *testing.T) {
				binding, err := deriveVariant(t, map[string][]byte{"ops/ops.go": []byte(body)}, nil)
				if err != nil {
					t.Fatalf("%s counterpart was not represented: %v\n%s", name, err, binding.Detail)
				}
				effect := effectOfClass(t, binding, string(ClassModeChange))
				if effect.Disposition != DispositionMapped || !hasLocation(effect, "ops/ops.go") {
					t.Fatalf("%s counterpart disposition=%s: %s", name, effect.Disposition, effectText(effect))
				}
			})
		}
	})

	t.Run("external implementation component", func(t *testing.T) {
		blankImport := map[string][]byte{
			"builtins/builtins.go": []byte("package builtins\n\nimport _ \"github.com/containerd/cri\"\n"),
		}
		criModule, criVersion := "github.com/containerd/cri", "v1.4.13"

		t.Run("unresolved external edge blocks", func(t *testing.T) {
			binding, err := deriveVariant(t, blankImport, nil)
			if err == nil {
				t.Fatalf("a blank-imported implementation component outside the boundary admitted: %+v", binding.Cover)
			}
			if !hasObligationCode(binding.Obligations, "UNRESOLVED_EXTERNAL_EDGE") {
				t.Fatalf("obligations=%+v — the unresolved external edge is not named", binding.Obligations)
			}
			for _, effect := range binding.Effects {
				if effect.Disposition == DispositionInapplicable {
					t.Fatalf("effect %s was discharged although the imported implementation is unresolved", effect.ID)
				}
			}
		})

		t.Run("counterpart inside the imported component is represented", func(t *testing.T) {
			inventory := anchoredInventory(t, criModule, criVersion, map[string][]byte{
				"service.go": []byte(`package cri

import (
	"os"

	"example.com/dep/config"
)

// EnsureStateDir lives in another module entirely.
func EnsureStateDir(cfg *config.Config) {
	_ = os.Chmod(cfg.Root, 0o700)
}
`),
			})
			binding, err := deriveVariant(t, blankImport, []ExternalComponent{{ImportPath: criModule, Inventory: inventory}})
			if err != nil {
				t.Fatalf("the imported component's counterpart was not represented: %v\n%s", err, binding.Detail)
			}
			effect := effectOfClass(t, binding, string(ClassModeChange))
			if effect.Disposition != DispositionMapped || !hasLocationComponent(effect, criModule) {
				t.Fatalf("imported counterpart disposition=%s: %s", effect.Disposition, effectText(effect))
			}
			if !coverHasSubject(binding, criModule, "EnsureStateDir") {
				t.Fatalf("the imported implementation is not in the necessary cover: %+v", binding.Cover)
			}
		})

		t.Run("closed imported component still earns the certificate", func(t *testing.T) {
			inventory := anchoredInventory(t, criModule, criVersion, map[string][]byte{
				"service.go": []byte("package cri\n\ntype Service struct{}\n"),
			})
			binding, err := deriveVariant(t, blankImport, []ExternalComponent{{ImportPath: criModule, Inventory: inventory}})
			if err != nil {
				t.Fatalf("a resolved and closed external component did not earn the certificate: %v\n%s", err, binding.Detail)
			}
			effect := effectOfClass(t, binding, string(ClassModeChange))
			if effect.Disposition != DispositionInapplicable {
				t.Fatalf("disposition=%s, want INAPPLICABLE", effect.Disposition)
			}
			if len(effect.Certificate.Components) < 2 {
				t.Fatalf("certificate components=%+v — the imported component must be part of the boundary", effect.Certificate.Components)
			}
		})
	})

	t.Run("named registration initializer in another file", func(t *testing.T) {
		binding, err := deriveVariant(t, map[string][]byte{
			"plugin/register.go": []byte(`package plugin

func init() {
	Register(Registration{ID: "example.com/dep/register", InitFn: initImpl})
}
`),
			"plugin/impl.go": []byte(`package plugin

import (
	"os"

	"example.com/dep/config"
)

func initImpl(cfg *config.Config) error {
	return os.Chmod(cfg.Root, 0o700)
}
`),
		}, nil)
		if err != nil {
			t.Fatalf("the initializer body in another file was not represented: %v\n%s", err, binding.Detail)
		}
		effect := effectOfClass(t, binding, string(ClassModeChange))
		if effect.Disposition != DispositionMapped || !hasLocation(effect, "plugin/impl.go") {
			t.Fatalf("initializer body disposition=%s: %s", effect.Disposition, effectText(effect))
		}
	})

	t.Run("named registration initializer in another package", func(t *testing.T) {
		binding, err := deriveVariant(t, map[string][]byte{
			"plugin/register.go": []byte(`package plugin

import "example.com/dep/impl"

func init() {
	Register(Registration{ID: "example.com/dep/impl", InitFn: impl.Init})
}
`),
			"impl/impl.go": []byte(`package impl

import (
	"os"

	"example.com/dep/config"
)

func Init(cfg *config.Config) error {
	return os.Chmod(cfg.Root, 0o700)
}
`),
		}, nil)
		if err != nil {
			t.Fatalf("the initializer body in another package was not represented: %v\n%s", err, binding.Detail)
		}
		effect := effectOfClass(t, binding, string(ClassModeChange))
		if effect.Disposition != DispositionMapped || !hasLocation(effect, "impl/impl.go") {
			t.Fatalf("initializer body disposition=%s: %s", effect.Disposition, effectText(effect))
		}
	})

	t.Run("unresolved registration initializer blocks", func(t *testing.T) {
		binding, err := deriveVariant(t, map[string][]byte{
			"plugin/register.go": []byte(`package plugin

import "github.com/unknown/component"

func init() {
	Register(Registration{ID: "example.com/dep/unknown", InitFn: component.Init})
}
`),
		}, nil)
		if err == nil {
			t.Fatalf("a registration initializer outside the boundary admitted: %+v", binding.Cover)
		}
		if !hasObligationCode(binding.Obligations, "UNRESOLVED_EXTERNAL_EDGE") {
			t.Fatalf("obligations=%+v — the unresolved initializer edge is not named", binding.Obligations)
		}
		for _, effect := range binding.Effects {
			if effect.Disposition == DispositionInapplicable {
				t.Fatalf("effect %s was discharged with an unresolved initializer edge", effect.ID)
			}
		}
	})

	t.Run("inline initializer closure is analysed", func(t *testing.T) {
		binding, err := deriveVariant(t, map[string][]byte{
			"plugin/plugin.go": []byte(`package plugin

import (
	"os"

	"example.com/dep/config"
)

type Registration struct {
	ID     string
	InitFn func(*config.Config) error
}

// Register records one plugin registration.
func Register(r Registration) {
	_ = r
}

func init() {
	Register(Registration{ID: "example.com/dep/plugin", InitFn: func(cfg *config.Config) error {
		return os.Chmod(cfg.Root, 0o700)
	}})
}
`),
		}, nil)
		if err != nil {
			t.Fatalf("the inline initializer closure was not analysed: %v\n%s", err, binding.Detail)
		}
		effect := effectOfClass(t, binding, string(ClassModeChange))
		if effect.Disposition != DispositionMapped {
			t.Fatalf("inline closure disposition=%s: %s", effect.Disposition, effectText(effect))
		}
		found := false
		for _, location := range effect.Locations {
			if location.File == "plugin/plugin.go" && strings.Contains(location.Declaration, "@lit") {
				found = true
			}
		}
		if !found {
			t.Fatalf("the inline closure's operation is not a location: %s", effectText(effect))
		}
	})

	t.Run("exported direct constructor is represented", func(t *testing.T) {
		binding, err := deriveVariant(t, map[string][]byte{
			"server/direct.go": []byte(`package server

import (
	"os"

	"example.com/dep/config"
)

// NewServer constructs the component directly, bypassing any registration.
func NewServer(cfg *config.Config) error {
	return os.Chmod(cfg.Root, 0o700)
}
`),
		}, nil)
		if err != nil {
			t.Fatalf("the exported direct constructor was not represented: %v\n%s", err, binding.Detail)
		}
		effect := effectOfClass(t, binding, string(ClassModeChange))
		if effect.Disposition != DispositionMapped {
			t.Fatalf("direct constructor disposition=%s: %s", effect.Disposition, effectText(effect))
		}
		found := false
		for _, location := range effect.Locations {
			if location.File == "server/direct.go" && location.Entry {
				found = true
			}
		}
		if !found {
			t.Fatalf("the direct constructor keeps no direct-entry provenance: %s", effectText(effect))
		}
	})

	t.Run("removed or shortened certificate is refused", func(t *testing.T) {
		in := base
		in.Claim = claimFor(baseBinding)

		t.Run("removed", func(t *testing.T) {
			mutated := cloneBinding(t, baseBinding)
			dischargedEffect(t, &mutated).Certificate = nil
			_, err := Admit(fixtureContext(t), mutated, in)
			refusedCode(t, err, RefusalNonCounterpart)
		})

		t.Run("shortened boundary", func(t *testing.T) {
			mutated := cloneBinding(t, baseBinding)
			dischargedEffect(t, &mutated).Certificate.Components = nil
			_, err := Admit(fixtureContext(t), mutated, in)
			refusedCode(t, err, RefusalNonCounterpart)
		})

		t.Run("shortened registration accounting", func(t *testing.T) {
			mutated := cloneBinding(t, baseBinding)
			dischargedEffect(t, &mutated).Certificate.Registrations = nil
			_, err := Admit(fixtureContext(t), mutated, in)
			refusedCode(t, err, RefusalNonCounterpart)
		})

		t.Run("stale certificate digest", func(t *testing.T) {
			mutated := cloneBinding(t, baseBinding)
			dischargedEffect(t, &mutated).Certificate.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			_, err := Admit(fixtureContext(t), mutated, in)
			refusedCode(t, err, RefusalNonCounterpart)
		})
	})

	t.Run("opaque foreign change never earns INAPPLICABLE", func(t *testing.T) {
		// The real captured CRI patch changes an environment slice, not a
		// supported operation. It must stay an unresolved changed span.
		in := fixtureInputs(t)
		patch := containerdCRIPatch()
		in.Artifacts = []ArtifactInput{capturedArtifact(fixtureLocator, "commit", patch)}
		files := fixtureSelectedFiles()
		files["pkg/server/container_create_unix.go"] = []byte(`package server

type criService struct{}

func (c *criService) containerSpec() {}
`)
		in.Captures, _ = captureFixture(t, fixtureRecordBytes(), files)
		in.Inventory = inventoryForCaptures(t, files, in.Captures)
		// No patch-side source exists for these opaque foreign changed spans.
		in.PatchSources = nil
		binding, err := Derive(in)
		if err == nil {
			t.Fatalf("an opaque foreign change established a binding: %+v", binding)
		}
		if code := RefusalCodeOf(err); code != RefusalObligations && code != RefusalCover {
			t.Fatalf("refusal=%s (%v), want a blocking refusal", code, err)
		}
		if len(binding.Effects) != 0 {
			t.Fatalf("effects=%+v — an opaquely changed span is not a classified effect", binding.Effects)
		}
		if len(binding.Obligations) == 0 {
			t.Fatal("the opaque change left no obligation")
		}
	})
}

// dischargedEffect returns the binding's INAPPLICABLE effect.
func dischargedEffect(t *testing.T, binding *Binding) *EffectRecord {
	t.Helper()
	for i := range binding.Effects {
		if binding.Effects[i].Disposition == DispositionInapplicable {
			return &binding.Effects[i]
		}
	}
	t.Fatalf("no discharged effect in %+v", binding.Effects)
	return nil
}
