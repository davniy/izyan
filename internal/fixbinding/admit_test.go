package fixbinding

import (
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// TestAdmissionReconstructsAllPremises pins F2. The binding is derived from real
// captured inputs — an exact advisory document, the exact patch bytes, the exact
// payload-side source and the exact selected implementation — and admitted. Then
// every premise is mutated on a copy while the original input roots stay fixed.
//
// A mutation that the reconstruction does not produce must be refused. Nothing
// is refused because a status or a label says so: the claimed value simply has no
// counterpart in what the bytes establish.
func TestAdmissionReconstructsAllPremises(t *testing.T) {
	in := fixtureInputs(t)
	binding := deriveFixture(t, in)
	admitted := admitFixture(t, fixtureContext(t), in, binding)

	// The fixture must actually exercise every premise group the mutations
	// target. Without this the negative cases would prove nothing.
	if len(admitted.Effects) < 2 {
		t.Fatalf("fixture derived %d effect(s), want a mapped and a discharged one: %+v", len(admitted.Effects), admitted.Effects)
	}
	if len(admitted.Cover.Subjects) < 2 {
		t.Fatalf("fixture cover has %d subject(s), want a mapped subject and an alternative: %+v",
			len(admitted.Cover.Subjects), admitted.Cover)
	}
	if len(admitted.Series) == 0 || len(admitted.Artifacts) == 0 {
		t.Fatal("fixture carries no artifact premise")
	}
	mapped := effectByDisposition(t, admitted, DispositionMapped)
	if len(mapped.Locations) == 0 {
		t.Fatalf("fixture mapped effect carries no location: %s", effectText(mapped))
	}
	if len(admitted.Mechanisms) == 0 || len(admitted.Mechanisms[0].Alternatives) == 0 {
		t.Fatalf("fixture carries no alternative subject to mutate: %+v", admitted.Mechanisms)
	}
	certified := effectByDisposition(t, admitted, DispositionInapplicable)
	if certified.Certificate == nil || len(certified.Certificate.Components) == 0 {
		t.Fatalf("fixture carries no non-counterpart certificate to mutate: %s", effectText(certified))
	}

	// Every premise group, mutated one at a time. The mutation is applied to a
	// deep copy: the canonical binding and the input bundle stay untouched, which
	// is exactly the "original input roots stay fixed" condition.
	cases := []struct {
		name   string
		want   RefusalCode
		mutate func(t *testing.T, b *Binding)
	}{
		{"effects: changed value", RefusalEffects, func(t *testing.T, b *Binding) {
			b.Effects[0].Before.Mode = "0755"
		}},
		{"effects: changed class", RefusalEffects, func(t *testing.T, b *Binding) {
			b.Effects[0].Class = string(ClassFileCreate)
		}},
		{"effects: changed resource", RefusalEffects, func(t *testing.T, b *Binding) {
			b.Effects[0].Before.ResourceKey = "type:example.com/other.Config"
		}},
		{"effects: removed effect", RefusalEffects, func(t *testing.T, b *Binding) {
			b.Effects = b.Effects[:len(b.Effects)-1]
		}},
		{"effects: disposition flipped", RefusalEffects, func(t *testing.T, b *Binding) {
			discharged := certifiedEffect(t, b)
			discharged.Disposition = DispositionMapped
		}},
		{"alternative subjects: dropped", RefusalSubjects, func(t *testing.T, b *Binding) {
			b.Mechanisms[0].Alternatives = nil
			b.Mechanisms[0].Subjects = b.Mechanisms[0].Mapped
		}},
		{"alternative subjects: invented", RefusalSubjects, func(t *testing.T, b *Binding) {
			b.Mechanisms[0].Alternatives = append(b.Mechanisms[0].Alternatives,
				SubjectRecord{Package: "example.com/dep/extra", Symbol: "Bypass", File: "extra/bypass.go", Line: 1})
		}},
		{"locators: artifact digest", RefusalArtifacts, func(t *testing.T, b *Binding) {
			b.Artifacts[0].Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"locators: artifact relevance", RefusalArtifacts, func(t *testing.T, b *Binding) {
			b.Artifacts[0].Relevant = false
		}},
		{"locators: primary", RefusalArtifacts, func(t *testing.T, b *Binding) {
			b.PrimaryLocator = "https://github.com/example/dep/commit/def456"
		}},
		{"entry indices: shifted", RefusalEntry, func(t *testing.T, b *Binding) {
			b.EntryRef = 1
		}},
		{"entry indices: scope", RefusalEntry, func(t *testing.T, b *Binding) {
			b.Entry.Packages = nil
		}},
		{"series membership: dropped", RefusalSeries, func(t *testing.T, b *Binding) {
			b.Series = nil
		}},
		{"series membership: added", RefusalSeries, func(t *testing.T, b *Binding) {
			b.Series = append(b.Series, SeriesLocator{Locator: "https://github.com/example/dep/commit/def456", Kind: "commit"})
		}},
		{"effective coordinate: module", RefusalCoordinate, func(t *testing.T, b *Binding) {
			b.Module = "example.com/other"
		}},
		{"effective coordinate: version", RefusalCoordinate, func(t *testing.T, b *Binding) {
			b.Version = "v0.7.0"
		}},
		{"effective coordinate: source root", RefusalCoordinate, func(t *testing.T, b *Binding) {
			b.SourceRoot = fixtureModule + "@v0.7.0"
		}},
		{"locations: line", RefusalLocations, func(t *testing.T, b *Binding) {
			location := &b.Effects[0].Locations[0]
			location.Line++
		}},
		{"locations: file", RefusalLocations, func(t *testing.T, b *Binding) {
			b.Effects[0].Locations[0].File = "server/elsewhere.go"
		}},
		{"locations: relation components", RefusalLocations, func(t *testing.T, b *Binding) {
			b.Effects[0].Locations[0].Components = []string{RelationOperation}
		}},
		{"census fields: file count", RefusalCensus, func(t *testing.T, b *Binding) {
			b.Census.Files++
		}},
		{"census fields: digest", RefusalCensus, func(t *testing.T, b *Binding) {
			b.Census.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"census fields: operation count", RefusalCensus, func(t *testing.T, b *Binding) {
			b.Census.Operations++
		}},
		{"census fields: anchor evidence", RefusalCensus, func(t *testing.T, b *Binding) {
			b.Census.Anchor = "go.sum/h1:sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"patch-side capture: digest", RefusalPatch, func(t *testing.T, b *Binding) {
			b.PatchSources[0].Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"patch-side capture: module", RefusalPatch, func(t *testing.T, b *Binding) {
			b.PatchSources[0].Module = "example.com/other"
		}},
		{"patch-side capture: association", RefusalPatch, func(t *testing.T, b *Binding) {
			b.PatchSources[0].Locator = "https://example.com/other/commit"
		}},
		{"patch inventory: accounting digest", RefusalPatch, func(t *testing.T, b *Binding) {
			b.Patches[0].InventoryDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"non-counterpart records: digest", RefusalNonCounterpart, func(t *testing.T, b *Binding) {
			certifiedEffect(t, b).Certificate.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"non-counterpart records: component removed", RefusalNonCounterpart, func(t *testing.T, b *Binding) {
			certificate := certifiedEffect(t, b).Certificate
			certificate.Components = nil
		}},
		{"non-counterpart records: registration removed", RefusalNonCounterpart, func(t *testing.T, b *Binding) {
			certificate := certifiedEffect(t, b).Certificate
			certificate.Registrations = nil
		}},
		{"non-counterpart records: rule", RefusalNonCounterpart, func(t *testing.T, b *Binding) {
			certifiedEffect(t, b).Certificate.Rule = "declaration-name-absence"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneBinding(t, binding)
			tc.mutate(t, &mutated)
			claimed := mutated
			inWithClaim := in
			inWithClaim.Claim = claimFor(binding)
			_, err := Admit(fixtureContext(t), claimed, inWithClaim)
			refusedCode(t, err, tc.want)
		})
	}

	t.Run("joint mutation is refused", func(t *testing.T) {
		mutated := cloneBinding(t, binding)
		mutated.Effects[0].Before.Mode = "0755"
		mutated.Cover.SubjectDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		mutated.Census.Files++
		mutated.EntryRef = 1
		inWithClaim := in
		inWithClaim.Claim = claimFor(binding)
		_, err := Admit(fixtureContext(t), mutated, inWithClaim)
		if err == nil {
			t.Fatal("a jointly mutated binding was admitted")
		}
		if RefusalCodeOf(err) == "" {
			t.Fatalf("joint refusal carries no typed code: %v", err)
		}
	})

	// The claim relationship is its own premise group: a narrowed condition, an
	// empty one and a verification that recorded another cover are all refused.
	t.Run("claim relationship", func(t *testing.T) {
		narrowed := claimFor(binding)
		narrowed.ConditionSubjects = narrowed.ConditionSubjects[:1]
		inNarrow := in
		inNarrow.Claim = narrowed
		_, err := Admit(fixtureContext(t), binding, inNarrow)
		refusedCode(t, err, RefusalClaim)

		empty := claimFor(binding)
		empty.ConditionSubjects = nil
		inEmpty := in
		inEmpty.Claim = empty
		_, err = Admit(fixtureContext(t), binding, inEmpty)
		refusedCode(t, err, RefusalClaim)

		otherCover := claimFor(binding)
		otherCover.VerificationCoverID = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		inOther := in
		inOther.Claim = otherCover
		_, err = Admit(fixtureContext(t), binding, inOther)
		refusedCode(t, err, RefusalClaim)

		inMissing := in
		inMissing.Claim = nil
		_, err = Admit(fixtureContext(t), binding, inMissing)
		refusedCode(t, err, RefusalClaim)
	})
}

// TestAllInapplicableInventoryEstablishesNoCover pins the rule that an inventory
// with no subject never grounds absence: every effect discharged as INAPPLICABLE
// leaves the cover empty, and an empty cover is refused.
func TestAllInapplicableInventoryEstablishesNoCover(t *testing.T) {
	in := fixtureInputs(t)
	in.Artifacts = []ArtifactInput{capturedArtifact(fixtureLocator, "commit", fixtureAddedOnlyPatchBytes())}
	in.PatchSources = map[string]*SourceBundle{
		fixtureLocator: {
			Module: ModuleIdentity{Path: fixtureModule, Version: fixtureSelectedVer},
			Files: map[string]FileSource{
				fixturePatchPath: {Before: fixtureBefore(), After: fixtureAddedOnlyAfter()},
			},
		},
	}
	binding, err := Derive(in)
	if err == nil {
		t.Fatalf("an all-INAPPLICABLE inventory admitted a cover: %+v", binding.Cover)
	}
	if code := RefusalCodeOf(err); code != RefusalSubjects && code != RefusalCover {
		t.Fatalf("refusal=%s (%v), want an empty-subject refusal", code, err)
	}
	if len(binding.Cover.Subjects) != 0 {
		t.Fatalf("cover=%+v — a discharged inventory must carry no subject", binding.Cover)
	}
	for _, effect := range binding.Effects {
		if effect.Disposition != DispositionInapplicable {
			t.Fatalf("effect %s disposition=%s, want INAPPLICABLE", effect.ID, effect.Disposition)
		}
		if len(effect.Subjects) != 0 {
			t.Fatalf("effect %s carries subjects although it was discharged: %v", effect.ID, effect.Subjects)
		}
	}
}

// TestBindingRequiresAnchoredInventory pins that an unanchored (vendor-only)
// inventory cannot ground any premise: the source boundary is refused before a
// subject is considered.
func TestBindingRequiresAnchoredInventory(t *testing.T) {
	in := fixtureInputs(t)
	files := fixtureSelectedFiles()
	observed := ObservedSource{Kind: SourceVendor, Module: fixtureModule, Version: fixtureSelectedVer,
		Root: "vendor/" + fixtureModule, WalkComplete: true}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	names = sortedStrings(mapOfNames(names))
	for _, name := range names {
		observed.Files = append(observed.Files, ObservedFile{Path: name, Bytes: files[name], Digest: DigestBytes(files[name])})
	}
	observed.ManifestModules = []string{fixtureModule + "@" + fixtureSelectedVer}
	observed.ManifestPackages = []string{fixtureModule + "/server", fixtureModule + "/config"}
	in.Inventory = AssembleInventory(InventoryInput{Module: fixtureModule, Version: fixtureSelectedVer, Observed: observed})
	_, err := Derive(in)
	if err == nil {
		t.Fatal("a vendor-only inventory grounded a binding")
	}
	if code := RefusalCodeOf(err); code != RefusalInput {
		t.Fatalf("refusal=%s (%v), want %s", code, err, RefusalInput)
	}
}

// TestBindingRefusesSubstitutedRecordAndArtifact pins that the premise roots are
// not interchangeable: another record, mutated patch bytes, a missing declared
// locator and a byte count that disagrees with the bytes are all refused.
func TestBindingRefusesSubstitutedRecordAndArtifact(t *testing.T) {
	base := fixtureInputs(t)

	t.Run("mutated patch bytes", func(t *testing.T) {
		in := base
		original := capturedArtifact(fixtureLocator, "commit", fixturePatchBytes())
		body := append([]byte(nil), fixturePatchBytes()...)
		body[len(body)-2] = 'x'
		original.Bytes = body
		in.Artifacts = []ArtifactInput{original}
		_, err := Derive(in)
		refusedCode(t, err, RefusalArtifacts)
	})

	t.Run("declared locator not acquired", func(t *testing.T) {
		in := base
		in.Artifacts = nil
		_, err := Derive(in)
		refusedCode(t, err, RefusalArtifacts)
	})

	t.Run("undeclared locator supplied", func(t *testing.T) {
		in := base
		in.Artifacts = append(in.Artifacts, capturedArtifact("https://github.com/example/dep/commit/zzz", "commit", fixturePatchBytes()))
		_, err := Derive(in)
		refusedCode(t, err, RefusalArtifacts)
	})

	t.Run("mutated record bytes", func(t *testing.T) {
		in := base
		mutated := append([]byte(nil), in.Raw...)
		mutated = append(mutated[:len(mutated)-2], []byte(" }\n")...)
		in.Raw = mutated
		_, err := Derive(in)
		refusedCode(t, err, RefusalIdentity)
	})

	t.Run("another entry index", func(t *testing.T) {
		in := base
		in.EntryRef = 3
		_, err := Derive(in)
		refusedCode(t, err, RefusalEntry)
	})

	t.Run("missing effective selection", func(t *testing.T) {
		in := base
		in.Selection = nil
		_, err := Derive(in)
		refusedCode(t, err, RefusalCoordinate)
	})

	t.Run("failed effective selection", func(t *testing.T) {
		in := base
		selection := fixtureSelection()
		selection[0].SourceKind, selection[0].SourceRoot = "", ""
		selection[0].Failure = &domain.ModuleSourceFailure{
			Kind: domain.ModuleSourceUnavailable, Detail: "the fork is not cached",
		}
		in.Selection = selection
		_, err := Derive(in)
		refusedCode(t, err, RefusalCoordinate)
	})

	t.Run("mutated anchored source", func(t *testing.T) {
		original := deriveFixture(t, base)
		in := base
		files := fixtureSelectedFiles()
		files["config/config.go"] = append(files["config/config.go"], []byte("\n// edited\n")...)
		captures, current := captureFixture(t, fixtureRecordBytes(), files)
		in.Captures = captures
		in.Inventory = inventoryForCaptures(t, files, captures)
		in.Claim = claimFor(original)
		// The binding derived from the original bytes is admitted against source
		// bytes that changed: its census, cover identity and subject digest all
		// describe another implementation.
		_, err := Admit(current, original, in)
		refusedCode(t, err, RefusalClaim)
	})
}

// cloneBinding deep-copies a binding through its JSON form. Every field of the
// proof contract is exported and JSON-tagged, so the copy is exact.
func cloneBinding(t *testing.T, binding Binding) Binding {
	t.Helper()
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("marshal binding: %v", err)
	}
	var out Binding
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal binding: %v", err)
	}
	return out
}

// certifiedEffect returns the binding's INAPPLICABLE effect for mutation.
func certifiedEffect(t *testing.T, binding *Binding) *EffectRecord {
	t.Helper()
	for i := range binding.Effects {
		if binding.Effects[i].Disposition == DispositionInapplicable {
			return &binding.Effects[i]
		}
	}
	t.Fatalf("no discharged effect in %+v", binding.Effects)
	return nil
}

// mapOfNames turns a name slice into a set for sortedStrings.
func mapOfNames(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}
