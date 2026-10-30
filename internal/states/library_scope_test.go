package states

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/goanalysis"
)

// TestCollectEvidenceProductShapeRecorded: evidence collection proves and
// persists the product shape before source analysis, records its evidence,
// links the evidence ids back into the shape, and does so for a library whose
// shipping scope is deliberately incomplete.
func TestCollectEvidenceProductShapeRecorded(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "scopelib"))
	if err != nil {
		t.Fatal(err)
	}
	ix := &goanalysis.Index{Dir: product}
	c := &domain.AnalysisCase{ID: "CASE-SHAPE"}
	h := CollectEvidence{Source: ix}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("CollectEvidence.Run: %v", err)
	}

	shape := c.Product.Shape
	if shape == nil {
		t.Fatal("evidence collection must persist a product shape")
	}
	if shape.Kind != domain.ProductShapeLibrary {
		t.Fatalf("kind=%s, want LIBRARY (limitations=%v)", shape.Kind, shape.Limitations)
	}
	if !shape.CensusComplete {
		t.Fatalf("library census must be complete: %v", shape.Limitations)
	}
	if shape.Fingerprint == "" {
		t.Fatal("persisted proof must carry its input fingerprint")
	}
	if len(shape.Packages) == 0 {
		t.Fatal("persisted proof must carry the package census")
	}
	if len(shape.EvidenceIDs) == 0 {
		t.Fatal("persisted proof must reference its evidence")
	}
	for _, id := range shape.EvidenceIDs {
		ev := c.EvidenceGraph.EvidenceByID(id)
		if ev == nil {
			t.Fatalf("shape references missing evidence %s", id)
		}
		if ev.Quality != domain.QualityDeterministic {
			t.Fatalf("evidence %s quality=%s", id, ev.Quality)
		}
		if ev.Kind != domain.EvidenceBuild && ev.Kind != domain.EvidencePackageList {
			t.Fatalf("evidence %s kind=%s", id, ev.Kind)
		}
	}

	// A library has no shipping root by design: the shape proof must not
	// depend on the shipping scope closing.
	scope, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatalf("BuildShippingScope: %v", err)
	}
	if scope.Complete {
		t.Fatalf("library fixture must leave the shipping scope open, got %v", scope.UnknownReasons)
	}
}

// TestCollectEvidenceProductShapeBinaryUnknown: binary-mode cases are
// ineligible for library scope even when a source index is present; the
// persisted shape stays UNKNOWN and names binary analysis as the reason.
func TestCollectEvidenceProductShapeBinaryUnknown(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "scopelib"))
	if err != nil {
		t.Fatal(err)
	}
	c := &domain.AnalysisCase{
		ID: "CASE-SHAPE-BINARY",
		Product: domain.ProductSnapshot{
			Repository: product,
			BinaryPath: "/tmp/release-binary",
		},
	}
	h := CollectEvidence{Source: &goanalysis.Index{Dir: product}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("CollectEvidence.Run: %v", err)
	}

	shape := c.Product.Shape
	if shape == nil {
		t.Fatal("binary-mode collection must still persist an ineligible shape")
	}
	if shape.Kind != domain.ProductShapeUnknown {
		t.Fatalf("binary-mode kind=%s, want UNKNOWN", shape.Kind)
	}
	if shape.CensusComplete || shape.Fingerprint != "" {
		t.Fatalf("binary-mode shape must not carry a source proof: %+v", shape)
	}
	if len(shape.Limitations) == 0 || !strings.Contains(shape.Limitations[0], "binary") {
		t.Fatalf("binary-mode reason missing: %v", shape.Limitations)
	}
	if len(shape.Packages) != 0 || len(shape.OwnedModules) != 0 {
		t.Fatalf("binary-mode shape must not invent a census: %+v", shape)
	}
}

// libraryWitnessFixture proves the testdata/libassertprod shape and returns the
// index plus the first exact vulnerable-sink site.
func libraryWitnessFixture(t *testing.T) (*goanalysis.Index, domain.CallSite) {
	t.Helper()
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "libassertprod"))
	if err != nil {
		t.Fatal(err)
	}
	ix := &goanalysis.Index{Dir: product}
	ctx := context.Background()
	shape, _, err := ix.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	if shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete {
		t.Fatalf("fixture is not a proven library: kind=%s complete=%t", shape.Kind, shape.CensusComplete)
	}
	sites, err := ix.FindCallers(ctx, domain.SymbolRef{
		Package: "example.com/dep/vuln", Symbol: "ParseBytes",
	})
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(sites) == 0 {
		t.Fatal("fixture has no sink call site")
	}
	return ix, sites[0]
}

// TestGapLibraryInputWitnessSkipped: a flow already carrying a proven payload
// witness is never deepened — its UNKNOWN origin is by design, not an open
// question — so planning records no hypothesis and spends no tool call.
func TestGapLibraryInputWitnessSkipped(t *testing.T) {
	ix, site := libraryWitnessFixture(t)
	ctx := context.Background()
	flow, evs, err := ix.TraceArgument(ctx, site, 0)
	if err != nil {
		t.Fatalf("TraceArgument: %v", err)
	}
	if flow.LibraryInput == nil {
		t.Fatalf("fixture must produce a witness: %s", flow.Summary)
	}
	c := &domain.AnalysisCase{ID: "CASE-GAP-WITNESS-SKIP"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: 0,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "ParseBytes"}},
	}
	flow.ConditionID = cond.ID
	c.EvidenceGraph.AddArgumentTrace([]domain.DataFlow{flow}, evs)
	before := c.UsageSnapshot().ToolCalls

	if progress := (GapAnalysis{Source: ix}).plan(ctx, c, cond, map[string]bool{}); progress {
		t.Fatal("a witnessed flow must not be deepened")
	}
	if len(c.Hypotheses) != 0 {
		t.Fatalf("witnessed flow produced hypotheses: %+v", c.Hypotheses)
	}
	if got := c.UsageSnapshot().ToolCalls; got != before {
		t.Fatalf("gap planning spent %d tool call(s) on a witnessed flow", got-before)
	}
	flows := flowsForCond(c, cond.ID)
	if len(flows) != 1 || flows[0].LibraryInput == nil || flows[0].Origin != domain.OriginUnknown {
		t.Fatalf("witnessed flow was disturbed: %+v", flows)
	}
}

// TestGapLibraryInputDeeperWitnessRecorded: a deeper trace that newly obtains a
// payload witness counts as progress and replaces the whole shallow flow. The
// deployment origin stays UNKNOWN, the persisted witness references resolvable
// evidence, and nothing stale survives the replacement.
func TestGapLibraryInputDeeperWitnessRecorded(t *testing.T) {
	ix, site := libraryWitnessFixture(t)
	ctx := context.Background()
	c := &domain.AnalysisCase{ID: "CASE-GAP-WITNESS-DEEPER"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: 0,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "ParseBytes"}},
	}
	shallow := domain.DataFlow{
		ConditionID: cond.ID,
		Source:      site,
		Sink:        site,
		Arg:         0,
		Origin:      domain.OriginUnknown,
		Summary:     "shallow trace could not resolve the origin",
	}
	c.EvidenceGraph.AddDataFlows(shallow)

	h := GapAnalysis{Source: ix}
	if !h.actDeepTrace(ctx, c, cond, shallow) {
		t.Fatal("a deeper trace that obtains a payload witness must count as progress")
	}
	flows := flowsForCond(c, cond.ID)
	if len(flows) != 1 {
		t.Fatalf("deeper trace left %d flows, want one replacement", len(flows))
	}
	got := flows[0]
	if got.Origin != domain.OriginUnknown {
		t.Fatalf("witnessed flow origin=%s, want UNKNOWN", got.Origin)
	}
	if got.LibraryInput == nil {
		t.Fatalf("deeper trace did not record the witness: %s", got.Summary)
	}
	if got.LibraryInput.Site != site || got.LibraryInput.Arg != 0 {
		t.Fatalf("witness site=%+v arg=%d, want %+v arg 0", got.LibraryInput.Site, got.LibraryInput.Arg, site)
	}
	if len(got.LibraryInput.EvidenceIDs) == 0 {
		t.Fatal("persisted witness must reference its evidence")
	}
	for _, id := range got.LibraryInput.EvidenceIDs {
		if c.EvidenceGraph.EvidenceByID(id) == nil {
			t.Fatalf("witness references missing evidence %s", id)
		}
	}
	if len(c.Hypotheses) != 1 {
		t.Fatalf("hypotheses=%+v", c.Hypotheses)
	}
	hyp := c.Hypotheses[0]
	if hyp.Status != domain.HypothesisConfirmed || !strings.Contains(hyp.Notes, "library payload witness") {
		t.Fatalf("hypothesis=%+v", hyp)
	}
}

// TestCollectProvenanceLibraryInputWitness: the evidence collector's
// argument-trace writer persists the library payload witness through the
// evidence-first seam, so both fixture bindings survive collection with
// resolvable evidence and UNKNOWN deployment origins.
func TestCollectProvenanceLibraryInputWitness(t *testing.T) {
	ix, _ := libraryWitnessFixture(t)
	c := &domain.AnalysisCase{ID: "CASE-COLLECT-WITNESS"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: 0,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "ParseBytes"}},
	}
	(CollectEvidence{Source: ix}).collectProvenance(context.Background(), c, cond,
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "ParseBytes"})

	flows := flowsForCond(c, cond.ID)
	if len(flows) != 2 {
		t.Fatalf("collected flows=%d, want the fixture's two sink bindings", len(flows))
	}
	formals := map[int]bool{}
	for _, flow := range flows {
		if flow.Origin != domain.OriginUnknown {
			t.Fatalf("collected flow origin=%s, want UNKNOWN", flow.Origin)
		}
		w := flow.LibraryInput
		if w == nil {
			t.Fatalf("collected flow lost its witness: %s", flow.Summary)
		}
		if w.API.Symbol != "YAMLEq" || w.Site != flow.Sink || w.Arg != 0 {
			t.Fatalf("collected witness=%+v for sink %+v", w, flow.Sink)
		}
		if len(w.EvidenceIDs) == 0 {
			t.Fatal("collected witness references no evidence")
		}
		for _, id := range w.EvidenceIDs {
			if c.EvidenceGraph.EvidenceByID(id) == nil {
				t.Fatalf("witness references missing evidence %s", id)
			}
		}
		formals[w.FormalIndex] = true
	}
	if !formals[1] || !formals[2] {
		t.Fatalf("collected formals=%v, want the distinct 1 (expected) and 2 (actual) bindings", formals)
	}
}

// libraryPerimeterCase is a COMPLETE library case whose mandatory conjunction
// carries a proven library public-API control claim next to a reachability
// fact. The advisory summary matches the peer-input heuristic, so the
// cluster-perimeter profile would rewrite the input claim without the library
// exemption.
func libraryPerimeterCase() *domain.AnalysisCase {
	sink := domain.SymbolRef{Package: "example.com/dep/yaml", Symbol: "Unmarshal"}
	return &domain.AnalysisCase{
		ID: "CASE-LIBRARY-PERIMETER",
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2099-0001",
			Module:       "example.com/dep",
			Summary:      "malformed yaml documents are deserialized without bounds",
			CWE:          []string{"CWE-502"},
			BaseSeverity: "HIGH",
			BaseScore:    8.1,
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/lib",
			Shape: &domain.ProductShape{
				Kind: domain.ProductShapeLibrary, CensusComplete: true, Fingerprint: "SHAPE-FP-1",
			},
		},
		PerimeterAssessment: &domain.PerimeterAssessment{
			Perimeter: domain.PerimeterClusterInternal,
			Basis:     domain.PerimeterBasisOperatorDeclared,
		},
		Affected: &domain.AffectedResult{
			Scope:           exactScope("GO-2099-0001"),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			Class:      "DESERIALIZATION",
			RootCauses: []domain.SymbolRef{sink},
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true, Subjects: []domain.SymbolRef{sink}},
				{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, ArgIndex: 0, Subjects: []domain.SymbolRef{sink}, Description: "attacker controls arg 0 of the affected sink"},
			},
		},
		Claims: []domain.Claim{
			{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue, Producer: "evaluator.SymbolReachable"},
			{
				ID: "CL-C-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimTrue,
				Producer:     "evaluator.ArgumentOrigin",
				ControlBasis: domain.ControlBasisLibraryPublicAPI,
				Limitations:  []string{domain.LibraryAPIScopeLimitation},
			},
		},
	}
}

// TestEvaluateVerdictLibraryClaimSurvivesPerimeterProfile: the admitted
// library-basis TRUE claim is exempt from the cluster-perimeter peer-input
// rewrite, both profiles carry the scope, and the selected verdict keeps it.
// Without the basis the same peer-shaped claim is still rewritten, proving the
// exemption is what protects the library positive.
func TestEvaluateVerdictLibraryClaimSurvivesPerimeterProfile(t *testing.T) {
	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}

	t.Run("library claim preserved in both profiles", func(t *testing.T) {
		c := libraryPerimeterCase()
		if _, err := h.Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict.Run: %v", err)
		}
		if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict=%+v, want EXPLOITABLE", c.Verdict)
		}
		if c.Verdict.ExploitabilityScope != domain.ScopeLibraryAPI {
			t.Fatalf("actual verdict scope=%q, want %q", c.Verdict.ExploitabilityScope, domain.ScopeLibraryAPI)
		}
		if c.Verdict.Reason != "all mandatory exploit conditions are satisfied" {
			t.Fatalf("reason=%q, want the unchanged mandatory-conjunction reason", c.Verdict.Reason)
		}
		if !slices.Contains(c.Verdict.Limitations, domain.LibraryAPIScopeLimitation) {
			t.Fatalf("actual verdict lost the library limitation: %v", c.Verdict.Limitations)
		}
		if len(c.Profiles) != 2 {
			t.Fatalf("profiles=%d, want two perimeter profiles", len(c.Profiles))
		}
		for i, prof := range c.Profiles {
			if prof.Verdict != domain.VerdictExploitable {
				t.Fatalf("profile[%d] verdict=%s, want EXPLOITABLE (library claim must not be rewritten)", i, prof.Verdict)
			}
			if prof.ExploitabilityScope != domain.ScopeLibraryAPI {
				t.Fatalf("profile[%d] scope=%q, want %q", i, prof.ExploitabilityScope, domain.ScopeLibraryAPI)
			}
		}
		var input *domain.Claim
		for i := range c.Claims {
			if c.Claims[i].ConditionID == "C-INPUT" {
				input = &c.Claims[i]
			}
		}
		if input == nil || input.Result != domain.ClaimTrue ||
			input.ControlBasis != domain.ControlBasisLibraryPublicAPI {
			t.Fatalf("library claim was mutated: %+v", input)
		}
	})

	t.Run("peer-input claim without library basis is still rewritten", func(t *testing.T) {
		c := libraryPerimeterCase()
		for i := range c.Claims {
			if c.Claims[i].ConditionID == "C-INPUT" {
				c.Claims[i].ControlBasis = ""
				c.Claims[i].Limitations = nil
			}
		}
		if _, err := h.Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict.Run: %v", err)
		}
		if len(c.Profiles) != 2 {
			t.Fatalf("profiles=%d, want two perimeter profiles", len(c.Profiles))
		}
		if c.Profiles[0].Verdict != domain.VerdictExploitable {
			t.Fatalf("zero-trust profile=%s, want EXPLOITABLE", c.Profiles[0].Verdict)
		}
		if c.Profiles[1].Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("cluster-perimeter profile=%s, want NO_EXPLOIT_PATH_FOUND", c.Profiles[1].Verdict)
		}
		if c.Profiles[1].ExploitabilityScope != "" || c.Verdict.ExploitabilityScope != "" {
			t.Fatalf("unscoped positive leaked a library scope: profiles=%+v verdict=%+v",
				c.Profiles, c.Verdict)
		}
	})
}
