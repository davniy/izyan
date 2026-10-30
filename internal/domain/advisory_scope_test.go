package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const testRecordDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testGoEntry(index int, module string) RecordEntry {
	return RecordEntry{Index: index, Ecosystem: "Go", Module: module}
}

func testInventoryWithEntries(id string, entries ...RecordEntry) *RecordInventory {
	refs := make([]int, len(entries))
	for n := range refs {
		refs[n] = n
	}
	return &RecordInventory{
		AdvisoryID:         id,
		DocumentDigest:     testRecordDigest,
		AffectedEntryCount: len(entries),
		Entries:            entries,
		RepresentedRefs:    refs,
	}
}

func fullInventory(id string) *RecordInventory {
	return testInventoryWithEntries(id, testGoEntry(0, "golang.org/x/net"))
}

func twoEntryInventory(id string) *RecordInventory {
	return testInventoryWithEntries(id,
		testGoEntry(0, "example.com/a"),
		testGoEntry(1, "example.com/b"))
}

func scopeWithInventory(id string, inventory *RecordInventory) *AdvisoryScope {
	return &AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: ScopeAdvisoryEntries, Coverage: CoverageComplete,
		RecordExtent: RecordExtentFullRecord, RecordInventory: inventory,
	}
}

func fullRecordScope(id string) *AdvisoryScope {
	return scopeWithInventory(id, fullInventory(id))
}

func TestAdvisoryScopeAllowsNegativeClosure(t *testing.T) {
	const (
		goID   = "GO-2026-1234"
		ghsaID = "GHSA-abcd-efgh-ijkl"
	)
	tests := []struct {
		name  string
		scope *AdvisoryScope
		want  bool
	}{
		{"nil", nil, false},
		{"empty", &AdvisoryScope{}, false},
		{"exact GO full record", fullRecordScope(goID), true},
		{"exact GHSA full record", fullRecordScope(ghsaID), true},
		{"exact GO two entries", scopeWithInventory(goID, twoEntryInventory(goID)), true},
		{
			"CVE alias of a full record",
			&AdvisoryScope{
				RequestedID: "CVE-2026-1234", ResolvedID: ghsaID,
				Kind: ScopeCVE, Coverage: CoverageKnownOnly,
				RecordExtent: RecordExtentFullRecord, RecordInventory: fullInventory(ghsaID),
			},
			false,
		},
		{
			"direct CVE with full record",
			&AdvisoryScope{
				RequestedID: "CVE-2026-1234", ResolvedID: "CVE-2026-1234",
				Kind: ScopeCVE, Coverage: CoverageComplete,
				RecordExtent: RecordExtentFullRecord, RecordInventory: fullInventory("CVE-2026-1234"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.AllowsNegativeClosure(); got != tt.want {
				t.Fatalf("AllowsNegativeClosure()=%v, want %v", got, tt.want)
			}
		})
	}

	t.Run("legacy or inconsistent scope fields", func(t *testing.T) {
		mutations := []struct {
			name   string
			mutate func(*AdvisoryScope)
		}{
			{"requested empty", func(s *AdvisoryScope) { s.RequestedID = "" }},
			{"resolved empty", func(s *AdvisoryScope) { s.ResolvedID = "" }},
			{"known only coverage", func(s *AdvisoryScope) { s.Coverage = CoverageKnownOnly }},
			{"unknown coverage", func(s *AdvisoryScope) { s.Coverage = "FUTURE" }},
			{"unknown kind", func(s *AdvisoryScope) { s.Kind = "FUTURE" }},
			{"CVE kind", func(s *AdvisoryScope) { s.Kind = ScopeCVE }},
			{"mismatched identity", func(s *AdvisoryScope) { s.ResolvedID = "GO-2026-5678" }},
			{"unknown ID", func(s *AdvisoryScope) { s.RequestedID, s.ResolvedID = "OTHER-1", "OTHER-1" }},
			{"lowercase GHSA prefix", func(s *AdvisoryScope) {
				s.RequestedID, s.ResolvedID = "ghsa-abcd-efgh-ijkl", "ghsa-abcd-efgh-ijkl"
			}},
			{"missing extent", func(s *AdvisoryScope) { s.RecordExtent = "" }},
			{"unknown extent", func(s *AdvisoryScope) { s.RecordExtent = RecordExtentUnknown }},
			{"projection extent", func(s *AdvisoryScope) { s.RecordExtent = RecordExtentGoProjection }},
			{"future extent", func(s *AdvisoryScope) { s.RecordExtent = "FUTURE" }},
			{"missing inventory", func(s *AdvisoryScope) { s.RecordInventory = nil }},
		}
		for _, tt := range mutations {
			t.Run(tt.name, func(t *testing.T) {
				scope := *fullRecordScope(goID)
				tt.mutate(&scope)
				if scope.AllowsNegativeClosure() {
					t.Fatalf("mutated scope still authorized closure: %+v", scope)
				}
			})
		}
	})

	t.Run("valid extent but structurally unsound inventory", func(t *testing.T) {
		mutations := []struct {
			name   string
			mutate func(*RecordInventory)
		}{
			{"bound to another record", func(i *RecordInventory) { i.AdvisoryID = "GO-2026-5678" }},
			{"missing digest", func(i *RecordInventory) { i.DocumentDigest = "" }},
			{"malformed digest", func(i *RecordInventory) { i.DocumentDigest = "sha256:" + strings.Repeat("A", 64) }},
			{"count mismatch", func(i *RecordInventory) { i.AffectedEntryCount = 2 }},
			{"entry index out of order", func(i *RecordInventory) { i.Entries[0].Index = 1 }},
			{"represented non-Go entry", func(i *RecordInventory) { i.Entries[0].Ecosystem = "Maven" }},
			{"represented unresolved ecosystem", func(i *RecordInventory) { i.Entries[0].Ecosystem = "" }},
			{"represented unresolved module", func(i *RecordInventory) { i.Entries[0].Module = "" }},
			{"empty census", func(i *RecordInventory) {
				*i = RecordInventory{AdvisoryID: goID, DocumentDigest: testRecordDigest}
			}},
			{"omitted entry", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.RepresentedRefs = []int{0}
				i.OmittedRefs = []int{1}
			}},
			{"duplicate ref", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.RepresentedRefs = []int{0, 0}
				i.OmittedRefs = []int{1}
			}},
			{"unordered refs", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.RepresentedRefs = []int{1, 0}
			}},
			{"out of bounds ref", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.RepresentedRefs = []int{0, 2}
			}},
			{"negative ref", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.RepresentedRefs = []int{-1, 0, 1}
			}},
			{"missing ref", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.RepresentedRefs = []int{0}
			}},
			{"overlapping refs", func(i *RecordInventory) {
				*i = *twoEntryInventory(goID)
				i.OmittedRefs = []int{1}
			}},
		}
		for _, tt := range mutations {
			t.Run(tt.name, func(t *testing.T) {
				scope := *fullRecordScope(goID)
				tt.mutate(scope.RecordInventory)
				if scope.AllowsNegativeClosure() {
					t.Fatalf("scope with unsound inventory authorized closure: %+v", scope.RecordInventory)
				}
			})
		}
	})
}

func TestRecordInventoryValidate(t *testing.T) {
	const (
		goID   = "GO-2026-1234"
		ghsaID = "GHSA-abcd-efgh-ijkl"
	)
	tests := []struct {
		name      string
		recordID  string
		inventory func() *RecordInventory
		wantErr   bool
	}{
		{"full Go record", goID, func() *RecordInventory { return fullInventory(goID) }, false},
		{"full GHSA record", ghsaID, func() *RecordInventory { return fullInventory(ghsaID) }, false},
		{"partial inventory is structurally valid", goID, func() *RecordInventory {
			inventory := testInventoryWithEntries(goID,
				testGoEntry(0, "example.com/a"),
				testGoEntry(1, "example.com/b"),
				RecordEntry{Index: 2, Ecosystem: "Maven", Module: "org.example:lib"})
			inventory.RepresentedRefs = []int{0}
			inventory.OmittedRefs = []int{1, 2}
			return inventory
		}, false},
		{"non-Go full record is structurally valid", goID, func() *RecordInventory {
			return testInventoryWithEntries(goID,
				RecordEntry{Index: 0, Ecosystem: "Maven", Module: "org.example:lib"})
		}, false},
		{"unresolved identity is structurally valid", goID, func() *RecordInventory {
			return testInventoryWithEntries(goID, RecordEntry{Index: 0, Ecosystem: "Go"})
		}, false},
		{"empty census is structurally valid", goID, func() *RecordInventory {
			return &RecordInventory{AdvisoryID: goID, DocumentDigest: testRecordDigest}
		}, false},
		{"nil inventory", goID, func() *RecordInventory { return nil }, true},
		{"empty recorded identity", "", func() *RecordInventory { return fullInventory(goID) }, true},
		{"empty advisory identity", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.AdvisoryID = ""
			return inventory
		}, true},
		{"mismatched advisory identity", goID, func() *RecordInventory { return fullInventory(ghsaID) }, true},
		{"digest without prefix", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.DocumentDigest = strings.Repeat("a", 64)
			return inventory
		}, true},
		{"digest wrong algorithm", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.DocumentDigest = "sha1:" + strings.Repeat("a", 64)
			return inventory
		}, true},
		{"digest uppercase hex", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.DocumentDigest = "sha256:" + strings.ToUpper(strings.Repeat("a", 64))
			return inventory
		}, true},
		{"digest short", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.DocumentDigest = "sha256:" + strings.Repeat("a", 63)
			return inventory
		}, true},
		{"digest long", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.DocumentDigest = "sha256:" + strings.Repeat("a", 65)
			return inventory
		}, true},
		{"digest non-hex", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.DocumentDigest = "sha256:" + strings.Repeat("g", 64)
			return inventory
		}, true},
		{"count too high", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.AffectedEntryCount = 2
			return inventory
		}, true},
		{"count too low", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.AffectedEntryCount = 1
			return inventory
		}, true},
		{"entry index not position", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.Entries[0].Index = 1
			return inventory
		}, true},
		{"entry negative index", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.Entries[0].Index = -1
			return inventory
		}, true},
		{"duplicate entry index", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.Entries[1].Index = 0
			return inventory
		}, true},
		{"ref unordered", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.RepresentedRefs = []int{1, 0}
			return inventory
		}, true},
		{"ref duplicate", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.RepresentedRefs = []int{0, 0}
			inventory.OmittedRefs = []int{1}
			return inventory
		}, true},
		{"ref out of bounds", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.RepresentedRefs = []int{0, 2}
			return inventory
		}, true},
		{"ref negative", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.RepresentedRefs = []int{-1, 0, 1}
			return inventory
		}, true},
		{"ref missing", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.RepresentedRefs = []int{0}
			return inventory
		}, true},
		{"ref overlapping", goID, func() *RecordInventory {
			inventory := twoEntryInventory(goID)
			inventory.OmittedRefs = []int{1}
			return inventory
		}, true},
		{"zero count with entry", goID, func() *RecordInventory {
			inventory := fullInventory(goID)
			inventory.AffectedEntryCount = 0
			return inventory
		}, true},
		{"zero count with ref", goID, func() *RecordInventory {
			return &RecordInventory{
				AdvisoryID: goID, DocumentDigest: testRecordDigest,
				RepresentedRefs: []int{0},
			}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inventory().Validate(tt.recordID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRecordInventorySameModuleEntriesBothRequired: intake merges entries by
// module name, but the census still has to require representation of every
// original entry — a shared module name cannot collapse two source refs into
// one closeable fact.
func TestRecordInventorySameModuleEntriesBothRequired(t *testing.T) {
	const id = "GO-2026-1234"
	shared := func() *RecordInventory {
		return testInventoryWithEntries(id,
			testGoEntry(0, "golang.org/x/net"),
			testGoEntry(1, "golang.org/x/net"))
	}
	if err := shared().Validate(id); err != nil {
		t.Fatalf("full same-module inventory must be structurally valid: %v", err)
	}
	if !scopeWithInventory(id, shared()).AllowsNegativeClosure() {
		t.Fatal("representing both original refs must authorize closure")
	}
	for _, omitted := range []int{0, 1} {
		inventory := shared()
		inventory.RepresentedRefs = []int{1 - omitted}
		inventory.OmittedRefs = []int{omitted}
		if err := inventory.Validate(id); err != nil {
			t.Fatalf("partial same-module inventory must stay structurally valid (omitted %d): %v", omitted, err)
		}
		if scopeWithInventory(id, inventory).AllowsNegativeClosure() {
			t.Fatalf("merged module authorized closure with original entry %d omitted", omitted)
		}
	}
}

func TestAdvisoryScopeBasisDoesNotAffectClosure(t *testing.T) {
	const id = "GO-2026-1234"
	bases := []string{
		"",
		"complete declared Go entries of the exact loaded advisory record; not CVE-wide coverage",
		"not CVE-wide coverage",
		"FULL_RECORD",
		"GO_PROJECTION: 21 entries omitted",
	}
	for _, basis := range bases {
		closable := fullRecordScope(id)
		closable.Basis = basis
		if !closable.AllowsNegativeClosure() {
			t.Fatalf("basis %q changed a full-record decision", basis)
		}
		refused := fullRecordScope(id)
		refused.RecordExtent = RecordExtentGoProjection
		refused.Basis = basis
		if refused.AllowsNegativeClosure() {
			t.Fatalf("basis %q changed a projection refusal", basis)
		}
	}
}

func TestAdvisoryScopeClone(t *testing.T) {
	const id = "GO-2026-1234"

	t.Run("nil", func(t *testing.T) {
		if clone := (*AdvisoryScope)(nil).Clone(); clone != nil {
			t.Fatalf("nil clone = %+v, want nil", clone)
		}
	})

	t.Run("without inventory", func(t *testing.T) {
		original := &AdvisoryScope{
			RequestedID: "CVE-2026-1234", ResolvedID: "GHSA-abcd-efgh-ijkl",
			Kind: ScopeCVE, Coverage: CoverageKnownOnly, Basis: "original",
		}
		clone := original.Clone()
		if clone == original {
			t.Fatal("clone aliases the original scope")
		}
		if !reflect.DeepEqual(original, clone) {
			t.Fatalf("clone = %+v, want %+v", clone, original)
		}
		clone.Basis = "changed"
		if original.Basis != "original" {
			t.Fatalf("clone mutation reached the original: %q", original.Basis)
		}
	})

	t.Run("inventory mutation isolation", func(t *testing.T) {
		original := &AdvisoryScope{
			RequestedID: id, ResolvedID: id,
			Kind: ScopeAdvisoryEntries, Coverage: CoverageComplete,
			Basis: "original", RecordExtent: RecordExtentFullRecord,
			RecordInventory: &RecordInventory{
				AdvisoryID: id, DocumentDigest: testRecordDigest,
				AffectedEntryCount: 3,
				Entries: []RecordEntry{
					testGoEntry(0, "example.com/a"),
					testGoEntry(1, "example.com/b"),
					testGoEntry(2, "example.com/c"),
				},
				RepresentedRefs: []int{0, 1},
				OmittedRefs:     []int{2},
			},
		}
		clone := original.Clone()
		if clone == original || clone.RecordInventory == original.RecordInventory {
			t.Fatal("clone shares the original scope or inventory object")
		}
		if !reflect.DeepEqual(original, clone) {
			t.Fatalf("clone = %+v, want %+v", clone, original)
		}

		clone.RequestedID = "GO-2026-5678"
		clone.ResolvedID = "GO-2026-5678"
		clone.Kind = ScopeCVE
		clone.Coverage = CoverageKnownOnly
		clone.Basis = "changed"
		clone.RecordExtent = RecordExtentUnknown
		clone.RecordInventory.AdvisoryID = "GO-2026-5678"
		clone.RecordInventory.DocumentDigest = "sha256:" + strings.Repeat("b", 64)
		clone.RecordInventory.AffectedEntryCount = 1
		clone.RecordInventory.Entries[0] = RecordEntry{Index: 9, Ecosystem: "Maven", Module: "evil.example/lib"}
		clone.RecordInventory.RepresentedRefs[0] = 2
		clone.RecordInventory.OmittedRefs[0] = 0
		clone.RecordInventory.Entries = append(clone.RecordInventory.Entries, testGoEntry(3, "example.com/d"))
		clone.RecordInventory.RepresentedRefs = append(clone.RecordInventory.RepresentedRefs, 2)
		clone.RecordInventory.OmittedRefs = append(clone.RecordInventory.OmittedRefs, 1)

		if err := original.RecordInventory.Validate(id); err != nil {
			t.Fatalf("original inventory mutated through clone: %v", err)
		}
		if original.RequestedID != id || original.ResolvedID != id ||
			original.Kind != ScopeAdvisoryEntries || original.Coverage != CoverageComplete ||
			original.Basis != "original" || original.RecordExtent != RecordExtentFullRecord {
			t.Fatalf("original scope mutated through clone: %+v", original)
		}
		if got := original.RecordInventory.Entries[0].Module; got != "example.com/a" {
			t.Fatalf("original entry mutated through clone: module %q", got)
		}
		if original.RecordInventory.RepresentedRefs[0] != 0 || original.RecordInventory.OmittedRefs[0] != 2 {
			t.Fatalf("original refs mutated through clone: represented %v omitted %v",
				original.RecordInventory.RepresentedRefs, original.RecordInventory.OmittedRefs)
		}
		if len(original.RecordInventory.Entries) != 3 ||
			len(original.RecordInventory.RepresentedRefs) != 2 ||
			len(original.RecordInventory.OmittedRefs) != 1 {
			t.Fatalf("original slice lengths mutated through clone: %+v", original.RecordInventory)
		}
	})

	t.Run("closable decision survives clone mutation", func(t *testing.T) {
		original := fullRecordScope(id)
		clone := original.Clone()
		clone.RecordExtent = RecordExtentUnknown
		clone.RecordInventory.Entries[0].Ecosystem = "Maven"
		clone.RecordInventory.RepresentedRefs[0] = 9
		if !original.AllowsNegativeClosure() {
			t.Fatal("clone mutation disabled the original's closure")
		}
		if original.RecordInventory.Entries[0].Ecosystem != "Go" ||
			original.RecordInventory.RepresentedRefs[0] != 0 {
			t.Fatalf("original inventory mutated through clone: %+v", original.RecordInventory)
		}
	})

	t.Run("nil slices stay nil", func(t *testing.T) {
		original := &AdvisoryScope{
			RequestedID: id, ResolvedID: id,
			RecordInventory: &RecordInventory{AdvisoryID: id, DocumentDigest: testRecordDigest},
		}
		clone := original.Clone()
		if clone.RecordInventory.Entries != nil ||
			clone.RecordInventory.RepresentedRefs != nil ||
			clone.RecordInventory.OmittedRefs != nil {
			t.Fatalf("nil inventory slices became non-nil: %+v", clone.RecordInventory)
		}
	})
}

// TestAdvisoryScopeRecordMetadataJSON: the new fields are optional on the
// wire, and a legacy COMPLETE scope that predates them must decode but never
// authorize closure.
func TestAdvisoryScopeRecordMetadataJSON(t *testing.T) {
	const legacyJSON = `{"requested_id":"GO-2026-1234","resolved_id":"GO-2026-1234",` +
		`"kind":"ADVISORY_ENTRIES","coverage":"COMPLETE"}`
	var legacy AdvisoryScope
	if err := json.Unmarshal([]byte(legacyJSON), &legacy); err != nil {
		t.Fatalf("legacy scope decode: %v", err)
	}
	if legacy.RecordExtent != "" || legacy.RecordInventory != nil {
		t.Fatalf("legacy scope acquired structural evidence: %+v", legacy)
	}
	if legacy.AllowsNegativeClosure() {
		t.Fatal("legacy COMPLETE without structural evidence authorized closure")
	}
	encodedLegacy, err := json.Marshal(&legacy)
	if err != nil {
		t.Fatalf("legacy scope encode: %v", err)
	}
	if strings.Contains(string(encodedLegacy), "record_extent") ||
		strings.Contains(string(encodedLegacy), "record_inventory") {
		t.Fatalf("optional record metadata was emitted for a legacy scope: %s", encodedLegacy)
	}

	full := fullRecordScope("GO-2026-1234")
	encoded, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("full scope encode: %v", err)
	}
	for _, want := range []string{
		`"record_extent":"FULL_RECORD"`,
		`"record_inventory":{`,
		`"document_digest":"` + testRecordDigest + `"`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("encoded scope %s lacks %s", encoded, want)
		}
	}
	var decoded AdvisoryScope
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("full scope decode: %v", err)
	}
	if !decoded.AllowsNegativeClosure() {
		t.Fatalf("decoded full record lost closure: %+v", decoded.RecordInventory)
	}
	if !reflect.DeepEqual(full.RecordInventory, decoded.RecordInventory) {
		t.Fatalf("round-trip inventory = %+v, want %+v", decoded.RecordInventory, full.RecordInventory)
	}
}

func TestAdvisoryScopeAffectedHasNegative(t *testing.T) {
	for _, axis := range []string{"module", "version", "package", "build", "implementation"} {
		t.Run(axis, func(t *testing.T) {
			r := AffectedResult{}
			if r.HasNegative() {
				t.Fatal("zero result closes")
			}
			switch axis {
			case "module":
				r.ModulePresent = ClaimFalse
			case "version":
				r.VersionAffected = ClaimFalse
			case "package":
				r.PackagePresent = ClaimFalse
			case "build":
				r.BuildRelevant = ClaimFalse
			case "implementation":
				r.VulnerableImplementationPresent = ClaimFalse
				if r.HasNegative() {
					t.Fatal("implementation closes without package/build facts")
				}
				r.PackagePresent = ClaimTrue
				if r.HasNegative() {
					t.Fatal("implementation closes without build fact")
				}
				r.BuildRelevant = ClaimTrue
			}
			if !r.HasNegative() {
				t.Fatal("negative not recognized")
			}
		})
	}
}
