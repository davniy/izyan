package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// A persisted descriptor names the source carrier in a stable, machine
// independent form. A host path, a failure that also claims a source, and a
// versionless source carrying an invented version are all refused.
func TestEffectiveSourceSelectionRejectsHostSourceIdentity(t *testing.T) {
	valid := func() EffectiveSourceSelection {
		return EffectiveSourceSelection{
			EntryRef:         0,
			DeclaredModule:   "example.com/orig",
			DeclaredVersion:  "v1.0.0",
			EffectiveModule:  "example.com/fork",
			EffectiveVersion: "v1.2.0",
			SourceKind:       ModuleSourceModuleCache,
			SourceRoot:       "example.com/fork@v1.2.0",
			Replacements:     []ReplaceDirective{{Old: "example.com/orig@v1.0.0", New: "example.com/fork@v1.2.0"}},
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid descriptor refused: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*EffectiveSourceSelection)
	}{
		{"absolute source root", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceLocalReplacement
			s.SourceRoot = "/home/operator/fork"
			s.LocalReplacement = &LocalReplacementSelection{Module: s.DeclaredModule, Directory: "/home/operator/fork"}
		}},
		{"parent traversal root", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceLocalReplacement
			s.SourceRoot = "../fork"
			s.LocalReplacement = &LocalReplacementSelection{Module: s.DeclaredModule, Directory: "../fork"}
		}},
		{"host path replacement identity", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceVendor
			s.SourceRoot = "vendor/example.com/orig"
			s.LocalReplacement = &LocalReplacementSelection{Module: s.DeclaredModule, Directory: "/abs/fork"}
		}},
		{"host path workspace identity", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceWorkspace
			s.SourceRoot = "libs/orig"
			s.Workspace = &WorkspaceSelection{Module: s.DeclaredModule, Directory: "/abs/libs/orig"}
		}},
		{"module-cache root disagrees with coordinate", func(s *EffectiveSourceSelection) {
			s.SourceRoot = "example.com/orig@v1.2.0"
		}},
		{"local replacement invents a version", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceLocalReplacement
			s.SourceRoot = "third_party/orig"
			s.LocalReplacement = &LocalReplacementSelection{Module: s.DeclaredModule, Directory: "third_party/orig"}
		}},
		{"local replacement without identity", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceLocalReplacement
			s.SourceRoot = "third_party/orig"
		}},
		{"workspace without membership", func(s *EffectiveSourceSelection) {
			s.SourceKind = ModuleSourceWorkspace
			s.SourceRoot = "libs/orig"
		}},
		{"failure carrying a source", func(s *EffectiveSourceSelection) {
			s.Failure = &ModuleSourceFailure{Kind: ModuleSourceUnavailable, Detail: "missing"}
			s.SourceKind = ModuleSourceModuleCache
		}},
		{"unknown source kind", func(s *EffectiveSourceSelection) { s.SourceKind = "guessed" }},
		{"unknown failure kind", func(s *EffectiveSourceSelection) {
			s.SourceKind = ""
			s.SourceRoot = ""
			s.Failure = &ModuleSourceFailure{Kind: "SOMETHING", Detail: "x"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			selection := valid()
			tc.mutate(&selection)
			if err := selection.Validate(); err == nil {
				t.Fatalf("descriptor %+v was admitted", selection)
			}
		})
	}

	// The descriptor survives a JSON round trip unchanged: it is the persisted
	// input, not an analysis-local view.
	encoded, err := json.Marshal(valid())
	if err != nil {
		t.Fatal(err)
	}
	var decoded EffectiveSourceSelection
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("round-tripped descriptor refused: %v", err)
	}
	if decoded.EffectiveModule != "example.com/fork" || decoded.SourceRoot != "example.com/fork@v1.2.0" ||
		len(decoded.Replacements) != 1 {
		t.Fatalf("round trip lost descriptor fields: %+v", decoded)
	}
}

// The advisory capture is only admissible when its bytes still hash to the
// pin: a persisted capture may not silently describe another document.
func TestAdvisoryRecordCaptureValidatesPinnedBytes(t *testing.T) {
	raw := []byte(`{"id":"GO-2099-0001","affected":[]}`)
	sum := sha256.Sum256(raw)
	pin := RecordPin{
		RecordID:       "GO-2099-0001",
		DocumentDigest: recordDigestPrefix + hex.EncodeToString(sum[:]),
		SourceLocator:  "corpus/GO-2099-0001.json",
	}
	capture := AdvisoryRecordCapture{Pin: pin, Bytes: raw}
	if err := capture.Validate(); err != nil {
		t.Fatalf("valid capture refused: %v", err)
	}

	encoded, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AdvisoryRecordCapture
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("round-tripped capture refused: %v", err)
	}
	if string(decoded.Bytes) != string(raw) {
		t.Fatalf("round trip changed the bytes: %q", decoded.Bytes)
	}

	decoded.Bytes = []byte(`{"id":"GO-2099-0001","affected":[]} `)
	if err := decoded.Validate(); err == nil {
		t.Fatal("mutated capture bytes were admitted")
	}
	if err := (AdvisoryRecordCapture{Pin: pin}).Validate(); err == nil {
		t.Fatal("a capture with no bytes was admitted")
	}
}
