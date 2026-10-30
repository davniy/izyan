package goanalysis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
)

func persistedLocusFixture(t *testing.T) (domain.ProductSnapshot, *domain.ExploitModel, domain.Claim, domain.Condition, []domain.Evidence, UnreachabilityResult) {
	t.Helper()
	product := testProduct()
	product.Target = &domain.ProductTarget{GOOS: product.GOOS, GOARCH: product.GOARCH, Source: domain.ProductTargetSourceOperatorDeclared, Scope: domain.ProductTargetScopeOperator}
	build := domain.EffectiveBuildContext(product)
	subject := domain.SymbolRef{Package: "example.com/dep", Symbol: "Dead"}
	cond := domain.Condition{ID: "dead", Kind: domain.ConditionSymbolReachable, Mandatory: true, Subjects: []domain.SymbolRef{subject}}
	model := &domain.ExploitModel{RootCauses: []domain.SymbolRef{subject}, MandatoryConditions: []domain.Condition{cond}}
	claim := domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse, Falsifier: domain.FalsifierLocusFunctionUnreached,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified, BuildContext: &build, EvidenceIDs: []domain.EvidenceID{"kernel"}}}
	result := UnreachabilityResult{Module: "example.com/dep", Subjects: []UnreachabilitySubject{{Package: subject.Package, Symbol: subject.Symbol}}, Build: build,
		Inventory: affected.RecordPackageInventory([]byte(`{"ImportPath":"example.com/product","Name":"main"}`), nil, product, false),
		ProductPackages: []string{"example.com/product"}, Complete: true, DeclarationComplete: true, EntrypointComplete: true, ModuleEntryComplete: true, ModuleReachComplete: true}
	raw, err := json.Marshal(result)
	if err != nil { t.Fatal(err) }
	evidence := []domain.Evidence{
		{ID: "scan", Kind: domain.EvidenceSourceScan, BuildContext: &build, SourceScan: &domain.SourceScanRun{Module: result.Module, Completed: true, Complete: true, Subjects: []domain.SymbolRef{subject}, EntrySymbols: []string{"example.com/dep.Live"}}},
		{ID: "kernel", Kind: domain.EvidenceSourceSnippet, BuildContext: &build, Content: string(raw)},
	}
	return product, model, claim, cond, evidence, result
}

func TestValidateVerifiedNegativePersistedVerification(t *testing.T) {
	p, _, claim, cond, _, _ := persistedLocusFixture(t)
	claim.Falsifier = domain.FalsifierGuards
	claim.NegativeVerification.BuildContext = nil
	if err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p}, claim, cond); err == nil || !strings.Contains(err.Error(), "build context") { t.Fatalf("missing build: %v", err) }
	build := domain.EffectiveBuildContext(p)
	claim.NegativeVerification.BuildContext = &build
	if err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p}, claim, cond); err != nil { t.Fatal(err) }
	claim.NegativeVerification.Status = domain.NegativeInsufficientScope
	if err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p}, claim, cond); err == nil { t.Fatal("unverified record admitted") }
	claim.NegativeVerification.Status = domain.NegativeVerified
	foreign := build; foreign.Commit = "foreign"
	claim.NegativeVerification.BuildContext = &foreign
	if err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p}, claim, cond); err == nil { t.Fatal("foreign NV build admitted") }
	claim.NegativeVerification = nil
	if err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p}, claim, cond); err == nil { t.Fatal("missing NV admitted") }
	claim.Falsifier, claim.FalsifierBasis = domain.FalsifierTrustedInfrastructure, domain.BasisDeclaredTrust
	claim.NegativeVerification = &domain.NegativeVerification{Status: domain.NegativeVerified}
	p.Target = nil
	if err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p}, claim, cond); err != nil { t.Fatalf("independent basis: %v", err) }
}

func TestUnreachabilityReplayMainVerifiedAdmission(t *testing.T) {
	for _, name := range []string{"valid", "summary-only", "missing-inventory", "foreign-inventory", "foreign-result", "foreign-evidence", "foreign-nv", "truncated", "repinned-malformed", "projection-forgery", "uncited", "missing-model", "omitted-check", "stale-semantics", "two-subjects", "surplus", "duplicate", "empty-condition", "package-only", "malformed-condition", "declaration", "entrypoint", "module-entry", "module-reach", "reference", "may-call", "dependency", "dispatch", "dynamic", "gated", "reach", "limitation", "opaque", "unbounded"} {
		t.Run(name, func(t *testing.T) {
			p, model, claim, cond, evidence, result := persistedLocusFixture(t)
			switch name {
			case "summary-only": evidence = evidence[:1]
			case "missing-inventory": result.Inventory = affected.PackageInventoryMeasurement{}
			case "foreign-inventory": result.Inventory.Build.GOOS = "foreign"
			case "foreign-result": result.Build.Commit = "foreign"
			case "foreign-evidence": b := *evidence[1].BuildContext; b.Commit = "foreign"; evidence[1].BuildContext = &b
			case "foreign-nv": b := *claim.NegativeVerification.BuildContext; b.Commit = "foreign"; claim.NegativeVerification.BuildContext = &b
			case "truncated": result.Inventory.RawStream = result.Inventory.RawStream[:len(result.Inventory.RawStream)/2]
			case "repinned-malformed", "projection-forgery":
				result.Inventory = affected.RecordPackageInventory([]byte(`{"ImportPath":"example.com/product","Imports":["missing"]}`), nil, p, false)
				result.Inventory.Run.Complete, result.Inventory.Run.Completed, result.Inventory.Run.Error = true, true, ""
				if name == "projection-forgery" { result.Inventory.Packages = []affected.Package{{ImportPath:"example.com/product", Name:"main"}} }
			case "uncited": claim.NegativeVerification.EvidenceIDs = []domain.EvidenceID{"scan"}
			case "missing-model": model = nil
			case "omitted-check": model.DefectSemantics = &domain.DefectSemanticsContract{Mode:domain.DefectSemanticsOmittedCheck, RecordID:"GO-OMISSION", Check:cond.Subjects[0], Pipeline:&domain.SymbolRef{Package:"example.com/dep", Symbol:"Live"}}
			case "stale-semantics": model.DefectSemantics = &domain.DefectSemanticsContract{Mode:domain.DefectSemanticsDefectiveCheck, RecordID:"GO-STALE", Check:cond.Subjects[0], RecordDigest:"sha256:"+strings.Repeat("ab",32)}
			case "two-subjects": second := domain.SymbolRef{Package:"example.com/dep", Symbol:"Other"}; cond.Subjects = append(cond.Subjects, second); evidence[0].SourceScan.Subjects = append(evidence[0].SourceScan.Subjects, second)
			case "surplus": result.Subjects = append(result.Subjects, UnreachabilitySubject{Package:"example.com/dep",Symbol:"Other"})
			case "duplicate": result.Subjects = append(result.Subjects, result.Subjects[0])
			case "empty-condition": cond.Subjects = nil
			case "package-only": cond.Subjects[0].Symbol = ""; evidence[0].SourceScan.Subjects[0].Symbol = ""
			case "malformed-condition": cond.Subjects = append(cond.Subjects, domain.SymbolRef{Symbol:"MissingPackage"})
			case "declaration": result.DeclarationComplete = false
			case "entrypoint": result.EntrypointComplete = false
			case "module-entry": result.ModuleEntryComplete = false
			case "module-reach": result.ModuleReachComplete = false
			case "reference": result.ProductReferences = []domain.CallSite{{Function:"Live"}}
			case "may-call": result.MayCallSites = []MayCallSite{{Possible:true}}
			case "dependency": result.DependencyCallSites = []domain.CallSite{{Function:"Live"}}
			case "dispatch": result.InterfaceDispatchSites = []domain.CallSite{{Function:"Unknown"}}
			case "dynamic": result.DynamicMarkers = []DynamicMarker{{Kind:"reflect"}}
			case "gated": result.GatedReferences = []domain.CallSite{{Function:"Alternate"}}
			case "reach": result.ModuleReachable = map[string][]string{"example.com/dep.Dead":{"Live","Dead"}}
			case "limitation": result.Limitations = []string{"open"}
			case "opaque": result.Opaque = true
			case "unbounded": result.Unbounded = true
			}
			if len(evidence)>1 { raw, err := json.Marshal(result); if err != nil { t.Fatal(err) }; evidence[1].Content = string(raw) }
			err := ValidateVerifiedNegative(NegativeAdmissionInput{Product:p,Model:model,Evidence:evidence}, claim, cond)
			if name == "valid" { if err != nil { t.Fatal(err) } } else if err == nil { t.Fatal("invalid persisted negative admitted") }
		})
	}
}
