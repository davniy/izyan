package evaluator

import (
	"slices"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

const (
	libraryAdmissionAPIPkg  = "example.com/lib/assert"
	libraryAdmissionSinkPkg = "example.com/dep/yaml"
)

// libraryAdmissionCase is the admitted baseline: a proven library product, an
// evidence-backed complete census, a resolved deserialization sink, and one
// persisted public-formal → sink-argument witness for C-INPUT.
func libraryAdmissionCase(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	shape := &domain.ProductShape{
		Kind:           domain.ProductShapeLibrary,
		CensusComplete: true,
		RootModule:     "example.com/lib",
		OwnedModules:   []domain.ProductModuleShape{{Path: "example.com/lib", Directory: "."}},
		Packages: []domain.ProductPackageShape{{
			Path:           libraryAdmissionAPIPkg,
			Module:         "example.com/lib",
			Directory:      "assert",
			PackageNames:   []string{"assert"},
			ClauseComplete: true,
			Importable:     true,
		}},
		Fingerprint: "SHAPE-FP-1",
	}
	c := &domain.AnalysisCase{Product: admittedProduct(),
		ID: "CASE-LIBRARY-ADMISSION",
		Vulnerability: domain.Vulnerability{
			ID:      "GO-2099-0001",
			Module:  "example.com/dep",
			Summary: "yaml documents are deserialized without bounds",
			CWE:     []string{"CWE-502"},
		},
	}
	shape.EvidenceIDs = []domain.EvidenceID{
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-SHAPE-BUILD", Kind: domain.EvidenceBuild,
			Quality: domain.QualityDeterministic, Content: "product shape: example.com/lib",
		}),
		addCompletePackageListID(c, "EV-SHAPE-PKGS", `{"ImportPath":"example.com/lib/assert"}{"ImportPath":"example.com/dep/yaml"}`),
	}
	c.Product.Shape = shape

	site := domain.CallSite{
		File: "assert/assertions.go", Line: 1573, Column: 12,
		Function: "YAMLEq", Package: libraryAdmissionAPIPkg,
	}
	witness := &domain.LibraryInputWitness{
		API:         domain.SymbolRef{Package: libraryAdmissionAPIPkg, Symbol: "YAMLEq"},
		Declaration: domain.CallSite{File: "assert/assertions.go", Line: 1500, Column: 1, Function: "YAMLEq", Package: libraryAdmissionAPIPkg},
		FormalIndex: 1,
		FormalName:  "expected",
		FormalType:  "string",
		Sink:        domain.SymbolRef{Package: libraryAdmissionSinkPkg, Symbol: "Unmarshal"},
		Site:        site,
		Arg:         0,
		Steps: []domain.LibraryPayloadStep{{
			Kind: domain.LibraryPayloadByteConversion,
			Site: domain.CallSite{File: "assert/assertions.go", Line: 1572, Column: 20, Function: "YAMLEq"},
		}},
		ShapeFingerprint: shape.Fingerprint,
	}
	c.EvidenceGraph.AddArgumentTrace([]domain.DataFlow{{
		ConditionID:  "C-INPUT",
		Source:       site,
		Sink:         site,
		Arg:          0,
		Origin:       domain.OriginUnknown,
		Summary:      "public library formal is consumer-selectable",
		LibraryInput: witness,
	}}, []domain.Evidence{{
		ID: "EV-WITNESS-1", Kind: domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "source index: library public-formal payload binding",
		Tool:    "goanalysis.Index.TraceArgument",
		File:    "assert/assertions.go",
		Content: "api=example.com/lib/assert.YAMLEq decl=assert/assertions.go:1500:1 formal=1:string sink=example.com/dep/yaml.Unmarshal site=assert/assertions.go:1573:12 arg=0 steps=byte-preserving-conversion@assert/assertions.go:1572:20",
	}})

	c.RootCause = &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: libraryAdmissionSinkPkg, Symbol: "Unmarshal",
			Role: domain.RootCauseSink, Mechanism: "yaml document unmarshaling",
		}},
	}
	c.Exploit = &domain.ExploitModel{
		Class:      libraryPayloadClass,
		RootCauses: []domain.SymbolRef{{Package: libraryAdmissionSinkPkg, Symbol: "Unmarshal"}},
		MandatoryConditions: []domain.Condition{{
			ID:          "C-INPUT",
			Kind:        domain.ConditionAttackerControl,
			Mandatory:   true,
			ArgIndex:    0,
			Subjects:    []domain.SymbolRef{{Package: libraryAdmissionSinkPkg, Symbol: "Unmarshal"}},
			Description: "attacker controls arg 0 of the affected sink",
		}},
	}
	return c
}

// TestLibraryInputWitnessAdmitsAttackerControl: the admitted witness is a TRUE
// attacker-control claim at the library boundary — producer unchanged, library
// control basis, the exact shape/witness evidence, the shared limitation, an
// untouched UNKNOWN deployment origin, and no invented falsifier, negative
// verification or assumption ids.
func TestLibraryInputWitnessAdmitsAttackerControl(t *testing.T) {
	c := libraryAdmissionCase(t)
	cond := c.Exploit.MandatoryConditions[0]

	flow, witness, ok := admittedLibraryWitness(cond, c)
	if !ok {
		t.Fatal("baseline witness must be admitted")
	}
	if flow.LibraryInput != witness {
		t.Fatal("admitted flow and witness must be the same graph record")
	}
	if flow.Origin != domain.OriginUnknown {
		t.Fatalf("origin=%s, want UNKNOWN", flow.Origin)
	}
	if witness.Arg != cond.ArgIndex || witness.Sink != cond.Subjects[0] {
		t.Fatalf("witness arg=%d sink=%+v, want arg %d sink %+v", witness.Arg, witness.Sink, cond.ArgIndex, cond.Subjects[0])
	}
	if witness.ShapeFingerprint != c.Product.Shape.Fingerprint {
		t.Fatalf("witness fingerprint=%q, want %q", witness.ShapeFingerprint, c.Product.Shape.Fingerprint)
	}

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("result=%s, want TRUE (%s)", claim.Result, claim.Explanation)
	}
	if claim.Producer != "evaluator.ArgumentOrigin" {
		t.Fatalf("producer=%q, want evaluator.ArgumentOrigin", claim.Producer)
	}
	if claim.ControlBasis != domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("control basis=%q, want %q", claim.ControlBasis, domain.ControlBasisLibraryPublicAPI)
	}
	if claim.Falsifier != "" || claim.NegativeVerification != nil || len(claim.AssumptionIDs) != 0 {
		t.Fatalf("library claim invented negative machinery: falsifier=%q nv=%+v assumptions=%v",
			claim.Falsifier, claim.NegativeVerification, claim.AssumptionIDs)
	}
	if !slices.Contains(claim.Limitations, domain.LibraryAPIScopeLimitation) {
		t.Fatalf("missing shared limitation: %v", claim.Limitations)
	}
	if !strings.Contains(claim.Explanation, "example.com/lib/assert.YAMLEq") ||
		!strings.Contains(claim.Explanation, "example.com/dep/yaml.Unmarshal") {
		t.Fatalf("explanation does not name the API and sink: %q", claim.Explanation)
	}
	wantEvidence := []domain.EvidenceID{"EV-SHAPE-BUILD", "EV-SHAPE-PKGS", "EV-WITNESS-1"}
	gotEvidence := append([]domain.EvidenceID{}, claim.EvidenceIDs...)
	slices.Sort(gotEvidence)
	slices.Sort(wantEvidence)
	if !slices.Equal(gotEvidence, wantEvidence) {
		t.Fatalf("evidence ids=%v, want %v", gotEvidence, wantEvidence)
	}
	for _, id := range claim.EvidenceIDs {
		if c.EvidenceGraph.EvidenceByID(id) == nil {
			t.Fatalf("claim references missing evidence %s", id)
		}
	}
	// The claim only asserts consumer selectability.
	if strings.Contains(strings.ToLower(claim.Explanation), "remote client") ||
		strings.Contains(strings.ToLower(claim.Explanation), "deployment attacker control is established") {
		t.Fatalf("library claim asserts deployment control: %q", claim.Explanation)
	}

	// Genuine external origin keeps precedence: the witness never relabels a
	// deployment-proven path as library-scoped.
	externalCase := libraryAdmissionCase(t)
	externalCase.EvidenceGraph.AddArgumentTrace([]domain.DataFlow{{
		ConditionID: "C-INPUT",
		Source:      domain.CallSite{File: "app/handler.go", Line: 10, Column: 2, Function: "handle", Package: "example.com/app"},
		Sink:        externalCase.EvidenceGraph.DataFlows[0].Sink,
		Arg:         0,
		Origin:      domain.OriginExternalUntrusted,
		Summary:     "request body reaches the sink",
	}}, nil)
	externalClaim := (ArgumentOrigin{}).Evaluate(cond, externalCase)
	if externalClaim.Result != domain.ClaimTrue {
		t.Fatalf("external precedence: result=%s, want TRUE", externalClaim.Result)
	}
	if externalClaim.ControlBasis != "" {
		t.Fatalf("external precedence lost: control basis=%q", externalClaim.ControlBasis)
	}
	if strings.Contains(externalClaim.Explanation, "public library API") {
		t.Fatalf("external precedence lost: %q", externalClaim.Explanation)
	}
}

// TestLibraryInputWitnessGateMatrix mutates one gate at a time on an admitted
// baseline; every variant must be rejected with no new proof. Podman/Kubernetes
// resource-exhaustion and the Echo auth-bypass near miss are named controls,
// and application-shape rejection is tested independently of class rejection.
func TestLibraryInputWitnessGateMatrix(t *testing.T) {
	flowMut := func(fn func(*domain.DataFlow)) func(*testing.T, *domain.AnalysisCase) {
		return func(t *testing.T, c *domain.AnalysisCase) {
			t.Helper()
			if len(c.EvidenceGraph.DataFlows) == 0 {
				t.Fatal("fixture has no flow")
			}
			for i := range c.EvidenceGraph.DataFlows {
				fn(&c.EvidenceGraph.DataFlows[i])
			}
		}
	}
	condMut := func(fn func(*domain.Condition)) func(*testing.T, *domain.AnalysisCase) {
		return func(t *testing.T, c *domain.AnalysisCase) {
			t.Helper()
			fn(&c.Exploit.MandatoryConditions[0])
		}
	}
	shapeMut := func(fn func(*domain.ProductShape)) func(*testing.T, *domain.AnalysisCase) {
		return func(t *testing.T, c *domain.AnalysisCase) {
			t.Helper()
			fn(c.Product.Shape)
		}
	}
	witnessMut := func(fn func(*domain.LibraryInputWitness)) func(*testing.T, *domain.AnalysisCase) {
		return flowMut(func(f *domain.DataFlow) {
			if f.LibraryInput != nil {
				fn(f.LibraryInput)
			}
		})
	}

	cases := []struct {
		name  string
		apply func(*testing.T, *domain.AnalysisCase)
	}{
		{"class-missing", func(_ *testing.T, c *domain.AnalysisCase) { c.Exploit.Class = "" }},
		{"class-wrong", func(_ *testing.T, c *domain.AnalysisCase) { c.Exploit.Class = "WIRE_PARSER" }},
		{"keyword-only-classification-without-advisory-cwe", func(_ *testing.T, c *domain.AnalysisCase) {
			c.Vulnerability.CWE = nil
			c.Vulnerability.Summary = "malformed yaml is unmarshaled and decoded"
		}},
		{"cwe-missing", func(_ *testing.T, c *domain.AnalysisCase) { c.Vulnerability.CWE = nil }},
		{"cwe-wrong", func(_ *testing.T, c *domain.AnalysisCase) { c.Vulnerability.CWE = []string{"CWE-400"} }},
		{"cwe-adjacent-number", func(_ *testing.T, c *domain.AnalysisCase) { c.Vulnerability.CWE = []string{"CWE-5020"} }},
		{"root-cause-missing", func(_ *testing.T, c *domain.AnalysisCase) { c.RootCause = nil }},
		{"root-cause-unresolved", func(_ *testing.T, c *domain.AnalysisCase) { c.RootCause.Status = domain.RootCauseAmbiguous }},
		{"root-cause-absent-sink", func(_ *testing.T, c *domain.AnalysisCase) { c.RootCause.RootCauses[0].Absent = true }},
		{"root-cause-non-sink-role", func(_ *testing.T, c *domain.AnalysisCase) {
			c.RootCause.RootCauses[0].Role = domain.RootCausePropagation
		}},
		{"root-cause-wrong-sink", func(_ *testing.T, c *domain.AnalysisCase) { c.RootCause.RootCauses[0].Symbol = "Decode" }},
		{"model-root-cause-mismatch", func(_ *testing.T, c *domain.AnalysisCase) { c.Exploit.RootCauses[0].Symbol = "Decode" }},
		{"condition-subject-mismatch", condMut(func(cond *domain.Condition) {
			cond.Subjects = []domain.SymbolRef{{Package: libraryAdmissionSinkPkg, Symbol: "Decode"}}
		})},
		{"condition-input-constraint", condMut(func(cond *domain.Condition) { cond.Kind = domain.ConditionInputConstraint })},
		{"condition-other-kind", condMut(func(cond *domain.Condition) { cond.Kind = domain.ConditionConfiguration })},
		{"arg-all", condMut(func(cond *domain.Condition) { cond.ArgIndex = domain.ArgAll })},
		{"arg-receiver", condMut(func(cond *domain.Condition) { cond.ArgIndex = domain.ArgReceiver })},
		{"arg-index-mismatch", condMut(func(cond *domain.Condition) { cond.ArgIndex = 1 })},
		{"flow-arg-mismatch", flowMut(func(f *domain.DataFlow) { f.Arg = 1 })},
		{"witness-arg-mismatch", witnessMut(func(w *domain.LibraryInputWitness) { w.Arg = 1 })},
		{"input-source-peer", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamInputSource: domain.InputPeer}
		})},
		{"input-source-config", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamInputSource: domain.InputConfig}
		})},
		{"direction-read", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamDirection: domain.DirectionRead}
		})},
		{"check-exposure", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamCheck: domain.CheckExposure}
		})},
		{"check-config-flag", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamCheck: domain.CheckConfigFlag}
		})},
		{"protocol-role-requirement", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamProtocolRole: string(domain.ProtocolRoleServer)}
		})},
		{"paired-api-sequence", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamSequence: "a->b"}
		})},
		{"exposure-scope", condMut(func(cond *domain.Condition) {
			cond.Params = map[string]string{domain.ParamScope: "public"}
		})},
		{"shape-missing", func(_ *testing.T, c *domain.AnalysisCase) { c.Product.Shape = nil }},
		{"shape-unknown", shapeMut(func(shape *domain.ProductShape) { shape.Kind = domain.ProductShapeUnknown })},
		{"shape-owned-main-application", func(t *testing.T, c *domain.AnalysisCase) {
			shapeMut(func(shape *domain.ProductShape) {
				shape.Kind = domain.ProductShapeApplication
				shape.Packages = append(shape.Packages, domain.ProductPackageShape{
					Path: "example.com/lib/cmd/tool", Module: "example.com/lib",
					Directory: "cmd/tool", ClauseComplete: true, Importable: false,
				})
			})(t, c)
		}},
		{"shape-census-incomplete", shapeMut(func(shape *domain.ProductShape) { shape.CensusComplete = false })},
		{"binary-mode", func(_ *testing.T, c *domain.AnalysisCase) { c.Product.BinaryPath = "/tmp/lib.so" }},
		{"shape-fingerprint-missing", shapeMut(func(shape *domain.ProductShape) { shape.Fingerprint = "" })},
		{"shape-evidence-missing", shapeMut(func(shape *domain.ProductShape) { shape.EvidenceIDs = nil })},
		{"shape-evidence-dangling", shapeMut(func(shape *domain.ProductShape) {
			shape.EvidenceIDs = []domain.EvidenceID{"EV-SHAPE-MISSING"}
		})},
		{"api-package-not-importable", shapeMut(func(shape *domain.ProductShape) { shape.Packages[0].Importable = false })},
		{"api-package-not-owned", shapeMut(func(shape *domain.ProductShape) {
			shape.OwnedModules = []domain.ProductModuleShape{{Path: "example.com/other", Directory: "."}}
		})},
		{"api-symbol-not-exported", witnessMut(func(w *domain.LibraryInputWitness) { w.API.Symbol = "yamleq" })},
		{"witness-missing", flowMut(func(f *domain.DataFlow) { f.LibraryInput = nil })},
		{"witness-fingerprint-mismatch", witnessMut(func(w *domain.LibraryInputWitness) { w.ShapeFingerprint = "SHAPE-FP-OTHER" })},
		{"witness-site-line-mismatch", witnessMut(func(w *domain.LibraryInputWitness) { w.Site.Line++ })},
		{"witness-site-column-mismatch", witnessMut(func(w *domain.LibraryInputWitness) { w.Site.Column++ })},
		{"witness-site-missing-column", witnessMut(func(w *domain.LibraryInputWitness) { w.Site.Column = 0 })},
		{"witness-evidence-missing", witnessMut(func(w *domain.LibraryInputWitness) { w.EvidenceIDs = nil })},
		{"witness-evidence-dangling", witnessMut(func(w *domain.LibraryInputWitness) {
			w.EvidenceIDs = []domain.EvidenceID{"EV-WITNESS-MISSING"}
		})},
		{"witness-sink-mismatch", witnessMut(func(w *domain.LibraryInputWitness) {
			w.Sink = domain.SymbolRef{Package: libraryAdmissionSinkPkg, Symbol: "Decode"}
		})},
		{"witness-declaration-missing", witnessMut(func(w *domain.LibraryInputWitness) { w.Declaration = domain.CallSite{} })},
		{"witness-formal-type-missing", witnessMut(func(w *domain.LibraryInputWitness) { w.FormalType = "" })},
		{"witness-formal-index-negative", witnessMut(func(w *domain.LibraryInputWitness) { w.FormalIndex = -1 })},
		{"payload-unproven", flowMut(func(f *domain.DataFlow) { f.PayloadUnproven = true })},
		{"payload-step-unsupported", witnessMut(func(w *domain.LibraryInputWitness) {
			w.Steps = append(w.Steps, domain.LibraryPayloadStep{Kind: "opaque-transform"})
		})},
		{"payload-security-transform", flowMut(func(f *domain.DataFlow) {
			f.Transformations = []domain.CallSite{{Callee: "html.EscapeString"}}
		})},
		// Named corpus controls: both resource-exhaustion advisories also fail
		// the shape gate (real command), and the Echo auth bypass fails the
		// class gate on a library-shaped product.
		{"podman-resource-exhaustion-cve-2024-37298", func(_ *testing.T, c *domain.AnalysisCase) {
			c.Product.Shape.Kind = domain.ProductShapeApplication
			c.Exploit.Class = "RESOURCE_EXHAUSTION"
			c.Vulnerability.CWE = []string{"CWE-400"}
		}},
		{"kubernetes-resource-exhaustion-cve-2022-41717", func(_ *testing.T, c *domain.AnalysisCase) {
			c.Product.Shape.Kind = domain.ProductShapeApplication
			c.Exploit.Class = "RESOURCE_EXHAUSTION"
			c.Vulnerability.CWE = []string{"CWE-400"}
		}},
		{"echo-auth-bypass-cve-2020-26160", func(_ *testing.T, c *domain.AnalysisCase) {
			c.Exploit.Class = "AUTH_BYPASS"
			c.Vulnerability.CWE = []string{"CWE-285"}
			c.Vulnerability.Summary = "auth bypass via missing audience check"
		}},
		// Independent controls: neither gate may hide a defect in the other.
		{"application-shape-rejects-deserialization", func(_ *testing.T, c *domain.AnalysisCase) {
			c.Product.Shape.Kind = domain.ProductShapeApplication
		}},
		{"wrong-class-rejects-library-proof", func(_ *testing.T, c *domain.AnalysisCase) {
			c.Exploit.Class = "AUTH_BYPASS"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := libraryAdmissionCase(t)
			tc.apply(t, c)
			cond := c.Exploit.MandatoryConditions[0]
			if flow, witness, ok := admittedLibraryWitness(cond, c); ok {
				t.Fatalf("gate accepted an inadmissible witness: flow=%+v witness=%+v", flow, witness)
			}
			// A rejected witness must not produce a library-scoped claim.
			claim := (ArgumentOrigin{}).Evaluate(cond, c)
			if claim.ControlBasis == domain.ControlBasisLibraryPublicAPI {
				t.Fatalf("rejected witness still produced library control basis: %+v", claim)
			}
			if claim.Result == domain.ClaimTrue && claim.Producer == "evaluator.ArgumentOrigin" &&
				slices.Contains(claim.Limitations, domain.LibraryAPIScopeLimitation) {
				t.Fatalf("rejected witness still produced the library positive: %+v", claim)
			}
		})
	}
}

// TestLibraryInputConditionDefersTransportHeuristic: an admitted witness is
// delegated to argument provenance before the peer/transport heuristic and the
// --trusted-peer rewrite can intercept it; without the witness both heuristics
// still fire.
func TestLibraryInputConditionDefersTransportHeuristic(t *testing.T) {
	c := libraryAdmissionCase(t)
	c.Vulnerability.Summary = "malformed yaml documents are deserialized"
	c.Product.TrustedPeer = true
	c.EvidenceGraph.CallPaths = []domain.CallPath{{Frames: []domain.CallSite{{
		Package: "example.com/dep", Receiver: "Server", Function: "Serve",
	}}}}
	cond := c.Exploit.MandatoryConditions[0]

	claim := (ServerTransportInput{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("result=%s, want TRUE (explanation=%q)", claim.Result, claim.Explanation)
	}
	if claim.Producer != "evaluator.ArgumentOrigin" {
		t.Fatalf("producer=%q, want evaluator.ArgumentOrigin", claim.Producer)
	}
	if claim.ControlBasis != domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("control basis=%q, want library-public-api", claim.ControlBasis)
	}
	if strings.Contains(claim.Explanation, "server transport") || strings.Contains(claim.Explanation, "trusted") {
		t.Fatalf("transport heuristic intercepted the witness: %q", claim.Explanation)
	}

	// Control: without the witness the trusted-peer heuristic still governs the
	// same condition, so the delegation above is doing real work.
	noWitness := libraryAdmissionCase(t)
	noWitness.Vulnerability.Summary = c.Vulnerability.Summary
	noWitness.Product.TrustedPeer = true
	noWitness.EvidenceGraph.CallPaths = c.EvidenceGraph.CallPaths
	noWitness.EvidenceGraph.DataFlows[0].LibraryInput = nil
	peerClaim := (ServerTransportInput{}).Evaluate(cond, noWitness)
	if peerClaim.Result != domain.ClaimFalse || peerClaim.Falsifier != domain.FalsifierTrustedInfrastructure {
		t.Fatalf("trusted-peer control = %s/%s, want FALSE/%s",
			peerClaim.Result, peerClaim.Falsifier, domain.FalsifierTrustedInfrastructure)
	}
}

// TestLibraryInputWitnessDefersToPackageAbsence: package absence is a
// code-level negative and keeps precedence over the library positive in both
// argument and transport evaluation.
func TestLibraryInputWitnessDefersToPackageAbsence(t *testing.T) {
	c := libraryAdmissionCase(t)
	for i := range c.EvidenceGraph.Evidence {
		if c.EvidenceGraph.Evidence[i].ID == "EV-SHAPE-PKGS" {
			c.EvidenceGraph.Evidence[i].Content = `{"ImportPath":"example.com/lib/assert"}`
		}
	}
	cond := c.Exploit.MandatoryConditions[0]
	// The witness itself is still admissible: the FALSE below must come from
	// package absence, not from a silently rejected proof.
	if _, _, ok := admittedLibraryWitness(cond, c); !ok {
		t.Fatal("fixture must still carry an admissible witness")
	}

	for name, evaluator := range map[string]ConditionEvaluator{
		"argument-origin":  ArgumentOrigin{},
		"server-transport": ServerTransportInput{},
	} {
		t.Run(name, func(t *testing.T) {
			claim := evaluator.Evaluate(cond, c)
			if claim.Result != domain.ClaimFalse {
				t.Fatalf("result=%s, want FALSE (%s)", claim.Result, claim.Explanation)
			}
			if claim.Falsifier != domain.FalsifierPackageAbsent {
				t.Fatalf("falsifier=%q, want %q", claim.Falsifier, domain.FalsifierPackageAbsent)
			}
			if claim.ControlBasis != "" {
				t.Fatalf("package absence must not carry a library control basis: %q", claim.ControlBasis)
			}
			if slices.Contains(claim.Limitations, domain.LibraryAPIScopeLimitation) {
				t.Fatalf("package absence must not carry the library limitation: %v", claim.Limitations)
			}
		})
	}
}

// TestLibraryInputWitnessDoesNotSatisfyOtherConditions: the witness is typed
// attacker-control evidence only. INPUT_CONSTRAINT, reachability, locus,
// configuration and every other condition kind are untouched.
func TestLibraryInputWitnessDoesNotSatisfyOtherConditions(t *testing.T) {
	c := libraryAdmissionCase(t)
	cond := c.Exploit.MandatoryConditions[0]
	if !libraryAdmissionApplies(cond, c) {
		t.Fatal("baseline attacker-control condition must be admissible")
	}

	impossible := cond
	impossible.Kind = domain.ConditionInputConstraint
	if libraryAdmissionApplies(impossible, c) {
		t.Fatal("library admission must not apply to INPUT_CONSTRAINT")
	}
	claim := (ArgumentOrigin{}).Evaluate(impossible, c)
	if claim.Result == domain.ClaimTrue && claim.ControlBasis == domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("witness satisfied INPUT_CONSTRAINT: %+v", claim)
	}
	if claim.ControlBasis != "" {
		t.Fatalf("INPUT_CONSTRAINT claim carries library basis: %q", claim.ControlBasis)
	}

	for _, kind := range []domain.ConditionKind{
		domain.ConditionSymbolReachable,
		domain.ConditionValidation,
		domain.ConditionConfiguration,
		domain.ConditionAuthn,
		domain.ConditionRuntime,
		domain.ConditionCustom,
	} {
		other := cond
		other.Kind = kind
		if libraryAdmissionApplies(other, c) {
			t.Fatalf("library admission applied to %s", kind)
		}
		if (ArgumentOrigin{}).CanEvaluate(other) {
			t.Fatalf("ArgumentOrigin claims to evaluate %s", kind)
		}
	}

	// Locus is a reachability check shape: a paid witness never satisfies it.
	locus := cond
	locus.Kind = domain.ConditionSymbolReachable
	locus.Params = map[string]string{domain.ParamCheck: domain.CheckLocus}
	if libraryAdmissionApplies(locus, c) {
		t.Fatal("library admission applied to a locus condition")
	}
}

// TestLibraryInputRejectedWitnessHasNoStructuralFallback: the typed library
// witness is the only library positive route. Removing it must not let the
// same condition fall through to a weaker TRUE — a server-side frame and the
// condition's prose stay observations, so the transport evaluator keeps the
// claim UNKNOWN.
func TestLibraryInputRejectedWitnessHasNoStructuralFallback(t *testing.T) {
	c := libraryAdmissionCase(t)
	c.Vulnerability.Summary = "malformed yaml documents are deserialized"
	c.EvidenceGraph.CallPaths = []domain.CallPath{{Frames: []domain.CallSite{{
		Package: "example.com/dep", Receiver: "Server", Function: "Serve",
	}}}}
	cond := c.Exploit.MandatoryConditions[0]

	withWitness := (ServerTransportInput{}).Evaluate(cond, c)
	if withWitness.Result != domain.ClaimTrue {
		t.Fatalf("with witness = %s, want TRUE (%s)", withWitness.Result, withWitness.Explanation)
	}
	if withWitness.ControlBasis != domain.ControlBasisLibraryPublicAPI {
		t.Fatalf("with witness control basis = %q, want %q",
			withWitness.ControlBasis, domain.ControlBasisLibraryPublicAPI)
	}

	// Drop the typed witness: no structural route may promote the condition.
	c.EvidenceGraph.DataFlows[0].LibraryInput = nil
	without := (ServerTransportInput{}).Evaluate(cond, c)
	if without.Result != domain.ClaimUnknown {
		t.Fatalf("without witness = %s, want UNKNOWN: a removed witness must not fall through to a weaker TRUE (%s)",
			without.Result, without.Explanation)
	}
	if without.Falsifier != "" || without.NegativeVerification != nil {
		t.Fatalf("a missing witness produced a negative: %+v", without)
	}
}
