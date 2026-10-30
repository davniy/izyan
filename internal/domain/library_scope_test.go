package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func libraryScopeShapeFixture() ProductShape {
	return ProductShape{
		Kind:           ProductShapeLibrary,
		CensusComplete: true,
		RootModule:     "github.com/stretchr/testify",
		OwnedModules: []ProductModuleShape{
			{Path: "github.com/stretchr/testify", Directory: "."},
		},
		ExcludedModules: []ProductModuleShape{
			{Path: "github.com/stretchr/testify/_codegen", Directory: "_codegen"},
		},
		WorkspaceFile: "go.work",
		Packages: []ProductPackageShape{
			{
				Path:           "github.com/stretchr/testify/assert",
				Module:         "github.com/stretchr/testify",
				Directory:      "assert",
				PackageNames:   []string{"assert"},
				Files:          []string{"assert/assert.go", "assert/assertions.go"},
				ClauseComplete: true,
				Importable:     true,
				LoadErrors:     []string{"assert/assertions.go:12:3: unresolved"},
			},
			{
				Path:         "github.com/stretchr/testify/_codegen",
				Module:       "github.com/stretchr/testify/_codegen",
				Directory:    "_codegen",
				PackageNames: []string{"main"},
			},
		},
		Fingerprint: "9f8e7d",
		EvidenceIDs: []EvidenceID{"EV-001", "EV-002"},
		Limitations: []string{"nested module excluded"},
	}
}

func libraryScopeWitnessFixture() LibraryInputWitness {
	return LibraryInputWitness{
		API: SymbolRef{Package: "github.com/stretchr/testify/assert", Symbol: "YAMLEq"},
		Declaration: CallSite{
			File: "assert/assertions.go", Line: 1560, Column: 1, Function: "YAMLEq",
		},
		FormalIndex: 1,
		FormalName:  "expected",
		FormalType:  "string",
		Sink:        SymbolRef{Package: "gopkg.in/yaml.v3", Symbol: "Unmarshal"},
		Site: CallSite{
			File: "assert/assertions.go", Line: 1573, Column: 12, Function: "YAMLEq",
		},
		Arg:              0,
		ShapeFingerprint: "9f8e7d",
		Steps: []LibraryPayloadStep{
			{
				Kind: LibraryPayloadByteConversion,
				Site: CallSite{File: "assert/assertions.go", Line: 1573, Column: 28},
			},
			{
				Kind: LibraryPayloadIdentity,
				Site: CallSite{File: "assert/assertions.go", Line: 1573, Column: 12},
			},
		},
		EvidenceIDs: []EvidenceID{"EV-003", "EV-004"},
	}
}

// TestLibraryScopeJSONRoundTrip: every frozen library-scope field survives a
// whole-case serialization round trip, including the optional pointers and
// the flattened profile scope.
func TestLibraryScopeJSONRoundTrip(t *testing.T) {
	shape := libraryScopeShapeFixture()
	witness := libraryScopeWitnessFixture()
	claim := Claim{
		ID:           "C-INPUT",
		ConditionID:  "C-INPUT",
		Result:       ClaimTrue,
		ControlBasis: ControlBasisLibraryPublicAPI,
	}
	verdict := VerdictResult{
		Verdict:             VerdictExploitable,
		Reason:              "library public API reaches the sink",
		ExploitabilityScope: ScopeLibraryAPI,
		Limitations:         []string{LibraryAPIScopeLimitation},
	}
	profile := ProfileVerdict{
		Profile:             ProfileZeroTrust,
		Title:               "zero trust",
		Verdict:             VerdictExploitable,
		Reason:              "library public API reaches the sink",
		Priority:            PriorityP1,
		SLA:                 "7d",
		ExploitabilityScope: ScopeLibraryAPI,
	}
	in := AnalysisCase{
		ID:      "CASE-1",
		Product: ProductSnapshot{Repository: "github.com/stretchr/testify", Shape: &shape},
		Claims:  []Claim{claim},
		Verdict: &verdict,
		Profiles: []ProfileVerdict{
			profile,
		},
		EvidenceGraph: EvidenceGraph{
			DataFlows: []DataFlow{{
				ConditionID:  "C-INPUT",
				Source:       CallSite{File: "assert/assertions.go", Line: 1573, Column: 28, Function: "YAMLEq"},
				Arg:          0,
				Origin:       OriginUnknown,
				Sink:         witness.Site,
				LibraryInput: &witness,
			}},
		},
	}

	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out AnalysisCase
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// AnalysisCase embeds a mutex, so the round trip is checked on the
	// serialized form rather than by copying the struct.
	again, err := json.Marshal(&out)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(raw) != string(again) {
		t.Fatalf("round trip lost library-scope data:\n in=%s\nout=%s", raw, again)
	}
	if out.Product.Shape == nil || out.Product.Shape.Kind != ProductShapeLibrary {
		t.Fatalf("shape did not round trip: %+v", out.Product.Shape)
	}
	if out.Verdict.ExploitabilityScope != ScopeLibraryAPI ||
		out.Profiles[0].ExploitabilityScope != ScopeLibraryAPI ||
		out.Claims[0].ControlBasis != ControlBasisLibraryPublicAPI {
		t.Fatalf("scope/basis did not round trip: verdict=%q profile=%q claim=%q",
			out.Verdict.ExploitabilityScope, out.Profiles[0].ExploitabilityScope, out.Claims[0].ControlBasis)
	}
	if got := out.EvidenceGraph.DataFlows[0].LibraryInput; got == nil || !reflect.DeepEqual(*got, witness) {
		t.Fatalf("witness did not round trip: %+v", got)
	}
}

// TestLibraryScopeOptionalFieldsOmitted: an existing deployment-scoped case
// serializes without any new key, preserving the persisted schema.
func TestLibraryScopeOptionalFieldsOmitted(t *testing.T) {
	verdict := VerdictResult{Verdict: VerdictInconclusive, Reason: "unresolved"}
	raw, err := json.Marshal(AnalysisCase{
		ID:      "CASE-2",
		Product: ProductSnapshot{Repository: "example.com/app"},
		Claims:  []Claim{{ID: "C-INPUT", Result: ClaimUnknown}},
		Verdict: &verdict,
		Profiles: []ProfileVerdict{{
			Profile: ProfileZeroTrust, Title: "zero trust", Verdict: VerdictInconclusive,
		}},
		EvidenceGraph: EvidenceGraph{
			DataFlows: []DataFlow{{ConditionID: "C-INPUT", Arg: 0, Origin: OriginUnknown}},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"shape"`, `"library_input"`, `"control_basis"`, `"exploitability_scope"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("optional key %s must stay omitted, got %s", key, raw)
		}
	}
}

// TestLibraryScopeArgumentTraceEvidence: the graph writer records evidence
// first, links its assigned ids to the new witness, and appends the flow.
func TestLibraryScopeArgumentTraceEvidence(t *testing.T) {
	g := &EvidenceGraph{}
	witness := LibraryInputWitness{API: SymbolRef{Package: "example.com/lib", Symbol: "Parse"}}
	flow := DataFlow{
		ConditionID:  "C-INPUT",
		Arg:          0,
		Origin:       OriginUnknown,
		Sink:         CallSite{File: "lib/parse.go", Line: 12, Column: 7},
		LibraryInput: &witness,
	}

	evs := []Evidence{
		{Kind: EvidenceDataFlow, Quality: QualityDeterministic, Content: "traced parse formal"},
		{Kind: EvidenceSourceSnippet, Quality: QualityDeterministic, Content: "sink site"},
	}
	ids := g.AddArgumentTrace([]DataFlow{flow}, evs)
	if len(ids) != 2 || ids[0] != "EV-001" || ids[1] != "EV-002" {
		t.Fatalf("evidence ids=%v, want EV-001..EV-002", ids)
	}
	if len(g.Evidence) != 2 || len(g.DataFlows) != 1 {
		t.Fatalf("graph evidence=%d flows=%d", len(g.Evidence), len(g.DataFlows))
	}
	if got := g.DataFlows[0].LibraryInput; got == nil || !reflect.DeepEqual(got.EvidenceIDs, ids) {
		t.Fatalf("witness evidence ids=%v, want %v", got, ids)
	}

	// A second trace appends (never replaces) and a witness-free flow gets
	// no witness ids but still records its evidence.
	second := flow
	second.Sink = CallSite{File: "lib/parse.go", Line: 20, Column: 3}
	second.LibraryInput = nil
	secondIDs := g.AddArgumentTrace([]DataFlow{second}, []Evidence{{
		Kind: EvidenceDataFlow, Quality: QualityDeterministic, Content: "unwitnessed trace",
	}})
	if len(secondIDs) != 1 || secondIDs[0] != "EV-003" {
		t.Fatalf("second trace ids=%v", secondIDs)
	}
	if len(g.DataFlows) != 2 || len(g.Evidence) != 3 {
		t.Fatalf("second trace must append: evidence=%d flows=%d", len(g.Evidence), len(g.DataFlows))
	}
	if g.DataFlows[1].LibraryInput != nil {
		t.Fatal("an unwitnessed flow must not gain a witness")
	}
	if got := g.DataFlows[0].LibraryInput.EvidenceIDs; !reflect.DeepEqual(got, ids) {
		t.Fatalf("first witness ids changed: %v", got)
	}

	// The caller's own flow value is not retroactively mutated.
	if flow.LibraryInput.EvidenceIDs != nil {
		// The witness pointer is shared by construction in this fixture; the
		// graph writer must not write through to a caller-owned witness it
		// received on an appended flow.
		t.Fatalf("graph writer mutated the caller's witness: %v", flow.LibraryInput.EvidenceIDs)
	}
}

// TestLibraryScopeReplacementUsesColumn: distinct calls on one line are
// distinct trace slots; a replacement must not cross them, and replacing a
// witnessed flow with an unwitnessed one must not retain the old witness.
func TestLibraryScopeReplacementUsesColumn(t *testing.T) {
	g := &EvidenceGraph{}
	left := DataFlow{
		ConditionID: "C-INPUT",
		Arg:         0,
		Origin:      OriginUnknown,
		Summary:     "left call",
		Sink:        CallSite{File: "lib/parse.go", Line: 42, Column: 5},
	}
	right := left
	right.Sink.Column = 17
	right.Summary = "right call"

	g.ReplaceDataFlow(left)
	g.ReplaceDataFlow(right)
	if len(g.DataFlows) != 2 {
		t.Fatalf("same-line distinct columns collapsed into %d flow(s)", len(g.DataFlows))
	}

	deeper := right
	deeper.Origin = OriginExternalUntrusted
	deeper.Summary = "right call, deeper trace"
	g.ReplaceDataFlow(deeper)
	if len(g.DataFlows) != 2 {
		t.Fatalf("same-slot replacement appended: %d flows", len(g.DataFlows))
	}
	if g.DataFlows[0].Summary != "left call" {
		t.Fatalf("replacement crossed slots: left=%q", g.DataFlows[0].Summary)
	}
	if g.DataFlows[1].Summary != "right call, deeper trace" {
		t.Fatalf("right slot not replaced: %q", g.DataFlows[1].Summary)
	}

	// A witnessed flow occupying the left slot is replaced by an unwitnessed
	// deeper trace: the old witness must not survive the replacement.
	g.ReplaceDataFlow(DataFlow{
		ConditionID:  left.ConditionID,
		Arg:          left.Arg,
		Origin:       OriginUnknown,
		Sink:         left.Sink,
		LibraryInput: &LibraryInputWitness{API: SymbolRef{Package: "example.com/lib", Symbol: "Parse"}},
	})
	if g.DataFlows[0].LibraryInput == nil {
		t.Fatal("witnessed flow was not recorded")
	}
	ids := g.ReplaceArgumentTrace(DataFlow{
		ConditionID: left.ConditionID,
		Arg:         left.Arg,
		Origin:      OriginUnknown,
		Summary:     "unwitnessed deeper trace",
		Sink:        left.Sink,
	}, []Evidence{{Kind: EvidenceDataFlow, Quality: QualityDeterministic, Content: "deeper trace"}})
	if len(ids) != 1 || ids[0] != "EV-001" {
		t.Fatalf("replacement evidence ids=%v", ids)
	}
	if len(g.DataFlows) != 2 {
		t.Fatalf("replacement appended: %d flows", len(g.DataFlows))
	}
	if g.DataFlows[0].Summary != "unwitnessed deeper trace" {
		t.Fatalf("left slot not replaced: %q", g.DataFlows[0].Summary)
	}
	if g.DataFlows[0].LibraryInput != nil {
		t.Fatalf("old witness retained after replacement: %+v", g.DataFlows[0].LibraryInput)
	}
	if g.DataFlows[1].Summary != "right call, deeper trace" {
		t.Fatalf("replacement crossed slots: %q", g.DataFlows[1].Summary)
	}
}
