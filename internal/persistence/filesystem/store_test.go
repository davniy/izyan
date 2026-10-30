package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
)

const storeTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func storeTestInventory(id string, module string) *domain.RecordInventory {
	return &domain.RecordInventory{
		AdvisoryID:         id,
		DocumentDigest:     storeTestDigest,
		AffectedEntryCount: 1,
		Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: module}},
		RepresentedRefs:    []int{0},
	}
}

func storeTestScope(id string, module string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		Basis:           "exact record with a complete pre-filter census",
		RecordExtent:    domain.RecordExtentFullRecord,
		RecordInventory: storeTestInventory(id, module),
	}
}

// Both scope copies of a persisted case travel through the store without
// being collapsed, re-derived or re-bound: the vulnerability copy and the
// affected copy keep their own inventory and closure authority.
func TestScopeInventoryStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	vulnScope := storeTestScope("GHSA-aaaa-bbbb-cccc", "example.com/vuln")
	affectedScope := storeTestScope("GO-2026-0001", "example.com/other")
	c := &domain.AnalysisCase{
		ID: "case-scope-roundtrip",
		Vulnerability: domain.Vulnerability{
			ID: "GHSA-aaaa-bbbb-cccc", Module: "example.com/vuln",
			Scope: vulnScope,
		},
		Affected: &domain.AffectedResult{
			Scope:           affectedScope,
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimFalse,
		},
	}

	root := t.TempDir()
	store := New(root)
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load(ctx, c.ID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(loaded.Vulnerability.Scope, vulnScope) {
		t.Fatalf("vulnerability scope round-trip mismatch:\n got %#v\nwant %#v",
			loaded.Vulnerability.Scope, vulnScope)
	}
	if !reflect.DeepEqual(loaded.Affected.Scope, affectedScope) {
		t.Fatalf("affected scope round-trip mismatch:\n got %#v\nwant %#v",
			loaded.Affected.Scope, affectedScope)
	}
	if !loaded.Vulnerability.Scope.AllowsNegativeClosure() ||
		!loaded.Affected.Scope.AllowsNegativeClosure() {
		t.Fatal("round-tripped full-record scopes lost their closure authority")
	}

	// Save the decoded case again: no field may be inferred, dropped or
	// re-bound on a second encode/decode cycle.
	secondRoot := t.TempDir()
	second := New(secondRoot)
	if err := second.Save(ctx, loaded); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	reloaded, err := second.Load(ctx, c.ID)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if !reflect.DeepEqual(reloaded.Vulnerability.Scope, vulnScope) ||
		!reflect.DeepEqual(reloaded.Affected.Scope, affectedScope) {
		t.Fatalf("second round-trip changed the scopes:\n%#v\n%#v",
			reloaded.Vulnerability.Scope, reloaded.Affected.Scope)
	}
}

func TestLegacyScopeStoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	const legacyID = "case-legacy-scope"
	legacyJSON := `{
  "id": "` + legacyID + `",
  "vulnerability": {
    "id": "GO-2026-0001",
    "scope": {
      "requested_id": "GO-2026-0001",
      "resolved_id": "GO-2026-0001",
      "kind": "ADVISORY_ENTRIES",
      "coverage": "COMPLETE"
    }
  },
  "affected": {
    "scope": {
      "requested_id": "GO-2026-0001",
      "resolved_id": "GO-2026-0001",
      "kind": "ADVISORY_ENTRIES",
      "coverage": "COMPLETE"
    },
    "module_present": "TRUE",
    "resolved_version": "v1.0.0",
    "version_affected": "FALSE"
  }
}`

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, legacyID+".json"), []byte(legacyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	store := New(root)
	loaded, err := store.Load(ctx, domain.CaseID(legacyID))
	if err != nil {
		t.Fatalf("legacy case must stay decodable: %v", err)
	}

	for name, scope := range map[string]*domain.AdvisoryScope{
		"vulnerability": loaded.Vulnerability.Scope,
		"affected":      loaded.Affected.Scope,
	} {
		if scope == nil {
			t.Fatalf("%s scope disappeared on decode", name)
		}
		if scope.Coverage != domain.CoverageComplete {
			t.Fatalf("%s legacy coverage = %q, want COMPLETE preserved verbatim", name, scope.Coverage)
		}
		if scope.RecordExtent != "" || scope.RecordInventory != nil {
			t.Fatalf("%s scope acquired structural fields on decode: extent=%q inventory=%#v",
				name, scope.RecordExtent, scope.RecordInventory)
		}
		if scope.AllowsNegativeClosure() {
			t.Fatalf("%s legacy COMPLETE scope authorized a negative", name)
		}
	}

	// Re-encode: optional fields stay absent, and no completeness is
	// inferred from the legacy coverage assertion or the affected facts.
	secondRoot := t.TempDir()
	second := New(secondRoot)
	if err := second.Save(ctx, loaded); err != nil {
		t.Fatalf("re-encode legacy case: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(secondRoot, legacyID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "record_extent") ||
		strings.Contains(string(raw), "record_inventory") {
		t.Fatalf("legacy re-encode invented structural scope fields:\n%s", raw)
	}
	var reencoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &reencoded); err != nil {
		t.Fatalf("re-encoded case is not valid JSON: %v", err)
	}
	reloaded, err := second.Load(ctx, domain.CaseID(legacyID))
	if err != nil {
		t.Fatalf("reload re-encoded legacy case: %v", err)
	}
	if reloaded.Vulnerability.Scope.AllowsNegativeClosure() ||
		reloaded.Affected.Scope.AllowsNegativeClosure() {
		t.Fatal("legacy case acquired closure authority across a re-encode")
	}
}

func storeBuild() domain.BuildContext {
	return domain.BuildContext{
		Repository: "github.com/example/product",
		Commit:     "abc123",
		GOOS:       "linux",
		GOARCH:     "amd64",
		GoVersion:  "go1.25.0",
	}
}

func storeProduct(build domain.BuildContext) domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: build.Repository,
		Commit:     build.Commit,
		GOOS:       build.GOOS,
		GOARCH:     build.GOARCH,
		GoVersion:  build.GoVersion,
	}
}

// storeFinalizedPositive is one analysis-case/2 request result with every
// independent proof artifact a publication projection consumes: exact record
// pin, profile claim set and result, and a composed requested finding whose
// proof origin carries qualified references.
func storeFinalizedPositive(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	const recordID = "GO-2026-9001"
	build := storeBuild()
	pin := domain.RecordPin{
		RecordID:       recordID,
		DocumentDigest: storeTestDigest,
		SourceLocator:  "corpus/" + recordID + ".json",
	}
	claims := []domain.Claim{{
		ID:           "CL-C-API",
		ConditionID:  "C-API",
		Result:       domain.ClaimTrue,
		EvidenceIDs:  []domain.EvidenceID{"EV-API"},
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}}
	c := &domain.AnalysisCase{
		ID:            "case-v2-positive",
		RequestedID:   recordID,
		Schema:        domain.CaseSchemaV2,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: storeTestScope(recordID, "example.com/product")},
		RecordPin:     &pin,
		Product:       storeProduct(build),
		Affected:      &domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue},
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-API", Kind: domain.ConditionInputConstraint, Mandatory: true,
		}}},
		Claims: claims,
		ProfileAssessments: []domain.ProfileAssessment{{
			Profile:        domain.ProfileZeroTrust,
			IsTargetActual: true,
			Build:          build,
			Claims:         claims,
			Result: domain.AssessmentResult{
				Outcome: domain.OutcomeDecided,
				Verdict: &domain.VerdictResult{
					Verdict:             domain.VerdictExploitable,
					Reason:              "the product calls the library public API with attacker input",
					ConditionIDs:        []domain.ConditionID{"C-API"},
					EvidenceIDs:         []domain.EvidenceID{"EV-API"},
					ExploitabilityScope: domain.ScopeLibraryAPI,
				},
			},
		}},
		Workflow: domain.WorkflowStatus{State: domain.StateCompleted},
	}
	c.EvidenceGraph.Version = "1"
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID: "EV-API", Kind: domain.EvidenceSourceSnippet, Quality: domain.QualityDeterministic,
		Source: "store-test", Content: "public API call",
	})
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize positive case: %v", err)
	}
	return c
}

func TestCaseResultPersistence(t *testing.T) {
	ctx := context.Background()

	t.Run("a finalized analysis-case/2 result round-trips every proof artifact", func(t *testing.T) {
		c := storeFinalizedPositive(t)
		root := t.TempDir()
		store := New(root)
		if err := store.Save(ctx, c); err != nil {
			t.Fatalf("save finalized case: %v", err)
		}
		loaded, err := store.Load(ctx, c.ID)
		if err != nil {
			t.Fatalf("load finalized case: %v", err)
		}
		if loaded.Schema != domain.CaseSchemaV2 {
			t.Fatalf("schema = %q, want %q", loaded.Schema, domain.CaseSchemaV2)
		}
		if err := domain.ValidateFinalizedCase(loaded); err != nil {
			t.Fatalf("loaded case is not publishable: %v", err)
		}
		if !reflect.DeepEqual(loaded.RecordPin, c.RecordPin) {
			t.Fatalf("record pin changed:\n got %+v\nwant %+v", loaded.RecordPin, c.RecordPin)
		}
		if !reflect.DeepEqual(loaded.ProfileAssessments, c.ProfileAssessments) {
			t.Fatalf("profile assessments changed:\n got %+v\nwant %+v",
				loaded.ProfileAssessments, c.ProfileAssessments)
		}
		if !reflect.DeepEqual(loaded.RequestedFinding, c.RequestedFinding) {
			t.Fatalf("requested finding changed:\n got %+v\nwant %+v",
				loaded.RequestedFinding, c.RequestedFinding)
		}
		if loaded.RequestedFinding.ProofOrigins[0].Record != *loaded.RecordPin {
			t.Fatal("the persisted origin does not carry the persisted record pin")
		}
	})

	t.Run("a composed result is savable before the workflow terminal state", func(t *testing.T) {
		c := storeFinalizedPositive(t)
		// Composition runs before BUILD_REPORT; the workflow is not terminal
		// yet, but the FINAL envelope is already authoritative.
		c.Workflow.State = domain.StateBuildReport
		store := New(t.TempDir())
		if err := store.Save(ctx, c); err != nil {
			t.Fatalf("save composed case at BUILD_REPORT: %v", err)
		}
		loaded, err := store.Load(ctx, c.ID)
		if err != nil {
			t.Fatalf("load composed case at BUILD_REPORT: %v", err)
		}
		if err := domain.ValidateFinalizedCase(loaded); err != nil {
			t.Fatalf("composed case at BUILD_REPORT is not publishable: %v", err)
		}
	})

	t.Run("a legacy case loads unchanged and acquires no new-contract data", func(t *testing.T) {
		const legacyID = "case-legacy-result"
		legacyJSON := `{
  "id": "` + legacyID + `",
  "vulnerability": {
    "id": "GO-2020-0001",
    "scope": {
      "requested_id": "GO-2020-0001",
      "resolved_id": "GO-2020-0001",
      "kind": "ADVISORY_ENTRIES",
      "coverage": "COMPLETE"
    }
  },
  "affected": {"module_present": "FALSE", "resolved_version": "v1.0.0", "version_affected": "FALSE"},
  "workflow": {"state": "COMPLETED"}
}`
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, legacyID+".json"), []byte(legacyJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		store := New(root)
		loaded, err := store.Load(ctx, domain.CaseID(legacyID))
		if err != nil {
			t.Fatalf("legacy case must stay decodable: %v", err)
		}
		if loaded.Schema != "" || loaded.RequestedFinding != nil || loaded.RelatedDiscovery != nil ||
			loaded.CorpusManifest != nil || loaded.CorpusDeclaration != nil ||
			loaded.Attributions != nil || loaded.ProfileAssessments != nil ||
			loaded.RecordPin != nil || len(loaded.RelatedRecords) != 0 {
			t.Fatalf("legacy case acquired analysis-case/2 fields: %+v", loaded)
		}
		second := New(t.TempDir())
		if err := second.Save(ctx, loaded); err != nil {
			t.Fatalf("re-save legacy case: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(second.Root, legacyID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"requested_finding", "related_discovery", "attributions",
			"profile_assessments", "corpus_manifest", "\"schema\""} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("legacy re-encode invented %q:\n%s", forbidden, raw)
			}
		}
	})

	t.Run("an unknown schema is rejected on load and on save", func(t *testing.T) {
		const unknownID = "case-unknown-schema"
		root := t.TempDir()
		raw := `{"id":"` + unknownID + `","schema":"analysis-case/3"}`
		if err := os.WriteFile(filepath.Join(root, unknownID+".json"), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		store := New(root)
		if _, err := store.Load(ctx, domain.CaseID(unknownID)); err == nil ||
			!strings.Contains(err.Error(), "unknown schema") {
			t.Fatalf("unknown schema load err = %v", err)
		}
		err := store.Save(ctx, &domain.AnalysisCase{ID: unknownID, Schema: domain.CaseResultSchema("analysis-case/3")})
		if err == nil || !strings.Contains(err.Error(), "unknown schema") {
			t.Fatalf("unknown schema save err = %v", err)
		}
	})

	t.Run("analysis-case/2 requires an envelope and a terminal result requires FINAL", func(t *testing.T) {
		store := New(t.TempDir())
		if err := store.Save(ctx, &domain.AnalysisCase{
			ID:       "case-v2-no-envelope",
			Schema:   domain.CaseSchemaV2,
			Workflow: domain.WorkflowStatus{State: domain.StateAssessRelatedRecords},
		}); err == nil || !strings.Contains(err.Error(), "requires a requested_finding envelope") {
			t.Fatalf("missing envelope err = %v", err)
		}

		pendingFinding := &domain.RequestedFinding{
			Status:              domain.FindingPending,
			RequestedID:         "GO-2026-9001",
			RequestedKind:       domain.ScopeAdvisoryEntries,
			Coverage:            domain.CoverageComplete,
			PrimaryAssessmentID: "case-v2-pending-envelope",
		}
		pending := &domain.AnalysisCase{
			ID:               "case-v2-pending-envelope",
			Schema:           domain.CaseSchemaV2,
			RequestedFinding: pendingFinding,
			Workflow:         domain.WorkflowStatus{State: domain.StateAssessRelatedRecords},
		}
		if err := store.Save(ctx, pending); err != nil {
			t.Fatalf("a pending composed envelope must be resumable: %v", err)
		}
		loaded, err := store.Load(ctx, pending.ID)
		if err != nil {
			t.Fatalf("load pending envelope: %v", err)
		}
		if loaded.RequestedFinding.Status != domain.FindingPending {
			t.Fatalf("pending status = %q", loaded.RequestedFinding.Status)
		}

		pending.Workflow.State = domain.StateCompleted
		if err := store.Save(ctx, pending); err == nil || !strings.Contains(err.Error(), "FINAL") {
			t.Fatalf("terminal pending err = %v", err)
		}
	})

	t.Run("a pending root is loadable but not publishable", func(t *testing.T) {
		pin := domain.RecordPin{
			RecordID:       "GO-2026-9001",
			DocumentDigest: storeTestDigest,
			SourceLocator:  "corpus/GO-2026-9001.json",
		}
		c := &domain.AnalysisCase{
			ID:            "case-pending-root",
			RequestedID:   "CVE-2023-44487",
			Vulnerability: domain.Vulnerability{ID: "GHSA-qppj-fm5r-hxr3"},
			RecordPin:     &pin,
			Workflow:      domain.WorkflowStatus{State: domain.StateAssessRelatedRecords},
			RelatedDiscovery: &domain.RelatedDiscovery{
				RequestedID: "CVE-2023-44487",
				Enumeration: domain.DiscoveryPartial,
			},
		}
		store := New(t.TempDir())
		if err := store.Save(ctx, c); err != nil {
			t.Fatalf("pending root must be resumable: %v", err)
		}
		loaded, err := store.Load(ctx, c.ID)
		if err != nil {
			t.Fatalf("load pending root: %v", err)
		}
		if loaded.RequestedID != c.RequestedID || loaded.RelatedDiscovery == nil ||
			loaded.RelatedDiscovery.Enumeration != domain.DiscoveryPartial {
			t.Fatalf("pending root lost request state: %+v", loaded)
		}
		if err := domain.ValidateFinalizedCase(loaded); err == nil {
			t.Fatal("a pending root must not pass the publication gate")
		}
	})

	t.Run("a terminal legacy case carrying request fields is rejected", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID:            "case-legacy-masquerade",
			Vulnerability: domain.Vulnerability{ID: "GO-2020-0002"},
			Workflow:      domain.WorkflowStatus{State: domain.StateCompleted},
			RelatedDiscovery: &domain.RelatedDiscovery{
				RequestedID: "CVE-2023-44487",
				Enumeration: domain.DiscoveryPartial,
			},
		}
		store := New(t.TempDir())
		err := store.Save(ctx, c)
		if err == nil || !strings.Contains(err.Error(), "without the analysis-case/2 discriminator") {
			t.Fatalf("masquerade save err = %v", err)
		}
		raw, marshalErr := json.Marshal(c)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		root := t.TempDir()
		if writeErr := os.WriteFile(filepath.Join(root, string(c.ID)+".json"), raw, 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		if _, loadErr := New(root).Load(ctx, c.ID); loadErr == nil ||
			!strings.Contains(loadErr.Error(), "without the analysis-case/2 discriminator") {
			t.Fatalf("masquerade load err = %v", loadErr)
		}
	})

	t.Run("child disposition and exact-record rules gate final persistence", func(t *testing.T) {
		root := storeFinalizedPositive(t)
		childPin := domain.RecordPin{
			RecordID:       "GO-2023-2153",
			DocumentDigest: "sha256:" + strings.Repeat("cd", 32),
			SourceLocator:  "corpus/GO-2023-2153.json",
		}
		partialChild := &domain.AnalysisCase{
			ID:            "case-child-partial",
			RequestedID:   childPin.RecordID,
			Vulnerability: domain.Vulnerability{ID: childPin.RecordID},
			RecordPin:     &childPin,
			Product:       root.Product,
		}
		root.RelatedDiscovery = &domain.RelatedDiscovery{
			RequestedID: root.RequestedFinding.RequestedID,
			Enumeration: domain.DiscoveryPartial,
			Candidates: []domain.DiscoveryCandidate{{
				Record:      childPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: root.RequestedID}},
				Disposition: domain.DispositionEvaluated,
			}},
		}
		root.RelatedRecords = []domain.RelatedRecordAssessment{{
			ID: partialChild.ID, Record: childPin, Analysis: partialChild,
		}}
		store := New(t.TempDir())
		err := store.Save(ctx, root)
		if err == nil || !strings.Contains(err.Error(), "was not finalized") {
			t.Fatalf("evaluated partial child save err = %v", err)
		}

		root.RelatedDiscovery.Candidates[0].Disposition = domain.DispositionUnsupported
		if err := store.Save(ctx, root); err != nil {
			t.Fatalf("explicitly unassessed partial child must persist: %v", err)
		}
		loaded, err := store.Load(ctx, root.ID)
		if err != nil {
			t.Fatalf("load unassessed child: %v", err)
		}
		if len(loaded.RelatedRecords) != 1 || loaded.RelatedRecords[0].Analysis == nil {
			t.Fatalf("partial child lost: %+v", loaded.RelatedRecords)
		}

		loaded.RelatedRecords[0].Analysis.RelatedDiscovery = &domain.RelatedDiscovery{
			RequestedID: childPin.RecordID,
			Enumeration: domain.DiscoveryPartial,
		}
		if err := store.Save(ctx, loaded); err == nil ||
			!strings.Contains(err.Error(), "may not recurse") {
			t.Fatalf("nested child discovery save err = %v", err)
		}
		loaded.RelatedRecords[0].Analysis.RelatedDiscovery = nil

		loaded.RelatedRecords[0].Analysis.RecordPin.DocumentDigest = "sha256:" + strings.Repeat("ef", 32)
		if err := store.Save(ctx, loaded); err == nil ||
			!strings.Contains(err.Error(), "does not identify the nominated record bytes") {
			t.Fatalf("child pin mismatch save err = %v", err)
		}
		loaded.RelatedRecords[0].Analysis.RecordPin = &childPin

		loaded.CorpusManifest = &domain.CorpusManifest{
			Reference:      "osv-dump",
			CapturedAt:     "2026-10-20",
			ObservedDigest: storeTestDigest,
			Enumeration:    domain.DiscoveryFinished,
			Documents:      []domain.RecordPin{childPin},
		}
		if err := store.Save(ctx, loaded); err != nil {
			t.Fatalf("final root with a pinned manifest must persist: %v", err)
		}
		loaded.CorpusManifest.ObservedDigest = "not-a-digest"
		if err := store.Save(ctx, loaded); err == nil ||
			!strings.Contains(err.Error(), "sha256 digest") {
			t.Fatalf("malformed manifest save err = %v", err)
		}
	})
}

// storeCompactJSON renders a JSON document without insignificant whitespace so
// a round-tripped payload can be compared by value.
func storeCompactJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact json: %v", err)
	}
	return buf.String()
}

// A stored content-derived fix binding is withdrawn, non-admitting historical
// evidence. The loader keeps its exact payload — a load/save cycle never
// rewrites history — records the withdrawal on the evaluation copy, and the
// shared gate refuses the subjects it named instead of letting the payload
// decay into a weaker coordinate route.
func TestLoadRecognisesWithdrawnFixBinding(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	id := domain.CaseID("case-withdrawn-binding")
	subj := domain.SymbolRef{Package: "example.com/vuln/xds", Symbol: "RouteAndProcess"}
	payload := `{"record_id":"GHSA-aaaa-bbbb-cccc","document_digest":"` + storeTestDigest +
		`","module":"example.com/vuln","version":"v1.0.0","subjects":[{"package":"example.com/vuln/xds","symbol":"RouteAndProcess"}],"status":"ADMITTED"}`
	stored := `{
  "id": "case-withdrawn-binding",
  "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "module": "example.com/vuln"},
  "product": {"repository": "example.com/product"},
  "evidence_graph": {},
  "root_cause": {
    "status": "RESOLVED",
    "root_causes": [{"package": "example.com/vuln/xds", "symbol": "RouteAndProcess", "role": "SINK", "origin": "FIX_DERIVED", "absent": true}],
    "fix_binding": ` + payload + `
  },
  "workflow": {"state": "COMPLETED"}
}`
	if err := os.WriteFile(filepath.Join(root, string(id)+".json"), []byte(stored), 0o644); err != nil {
		t.Fatal(err)
	}

	store := New(root)
	c, err := store.Load(ctx, id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.RootCause == nil || c.RootCause.FixBinding == nil {
		t.Fatal("the loader discarded the withdrawn fix binding")
	}
	if got := storeCompactJSON(t, c.RootCause.FixBinding.Raw); got != storeCompactJSON(t, []byte(payload)) {
		t.Fatalf("withdrawn payload not preserved:\n got %s\nwant %s", got, payload)
	}
	if !c.RootCause.FixBinding.ClaimsSubject(subj) {
		t.Fatalf("withdrawn binding=%+v — lost the subjects it admitted", c.RootCause.FixBinding)
	}
	if len(c.WithdrawnEvidence) != 1 ||
		c.WithdrawnEvidence[0].Kind != domain.WithdrawnContentDerivedFixBinding ||
		c.WithdrawnEvidence[0].Detail == "" {
		t.Fatalf("withdrawn evidence=%+v — the loader did not record the withdrawal", c.WithdrawnEvidence)
	}
	if admission := domain.AdmitAbsence(c, domain.AbsenceBuildGraph{}, nil).Admits(subj); admission.Admitted {
		t.Fatalf("the loaded case admitted absence through the withdrawn binding (basis %q)", admission.Basis)
	}

	// Re-saving preserves the historical payload: the withdrawal removes
	// authority, not what an earlier run recorded.
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, string(id)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		RootCause struct {
			FixBinding json.RawMessage `json:"fix_binding"`
		} `json:"root_cause"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if got := storeCompactJSON(t, probe.RootCause.FixBinding); got != storeCompactJSON(t, []byte(payload)) {
		t.Fatalf("re-save rewrote the historical payload:\n got %s\nwant %s", got, payload)
	}
	if strings.Contains(string(raw), "withdrawn_evidence") {
		t.Fatal("the evaluation-copy withdrawal marker was persisted into stored history")
	}
}

// A withdrawn payload this build cannot interpret is still history: the loader
// keeps the bytes verbatim, does not fail the case, and refuses every operator
// assertion for the model because the dependency's subject set is unknown.
func TestLoadKeepsUnreadableWithdrawnPayload(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	id := domain.CaseID("case-opaque-withdrawn-binding")
	stored := `{
  "id": "case-opaque-withdrawn-binding",
  "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "module": "example.com/vuln"},
  "product": {"repository": "example.com/product"},
  "evidence_graph": {},
  "root_cause": {
    "status": "RESOLVED",
    "root_causes": [{"package": "example.com/vuln/xds", "symbol": "RouteAndProcess", "role": "SINK", "origin": "MANUAL"}],
    "fix_binding": "not-an-object"
  },
  "workflow": {"state": "COMPLETED"}
}`
	if err := os.WriteFile(filepath.Join(root, string(id)+".json"), []byte(stored), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := New(root).Load(ctx, id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.RootCause == nil || c.RootCause.FixBinding == nil {
		t.Fatal("the loader discarded the unreadable withdrawn payload")
	}
	if !c.RootCause.FixBinding.Opaque {
		t.Fatal("the unreadable payload was not marked opaque")
	}
	if got := storeCompactJSON(t, c.RootCause.FixBinding.Raw); got != `"not-an-object"` {
		t.Fatalf("unreadable payload bytes were not preserved: %s", got)
	}
	subj := domain.SymbolRef{Package: "example.com/vuln/xds", Symbol: "RouteAndProcess"}
	if admission := domain.AdmitAbsence(c, domain.AbsenceBuildGraph{}, nil).Admits(subj); admission.Admitted {
		t.Fatalf("an operator label over an unreadable withdrawn dependency admitted absence (basis %q)", admission.Basis)
	}
}
