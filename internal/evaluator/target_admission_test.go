package evaluator

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Fixtures shared by the evaluator tests. A scoped operator-declared target
// is a legitimate product build identity (not a host default): producers of
// build-dependent negatives must admit it, and must refuse the same evidence
// when only a host default exists.

func admittedProduct() domain.ProductSnapshot {
	p := domain.ProductSnapshot{
		Repository: "/test/product",
		Commit:     "testcommit",
		GOOS:       "linux",
		GOARCH:     "amd64",
	}
	p.Target = &domain.ProductTarget{
		GOOS:   "linux",
		GOARCH: "amd64",
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	return p
}

func hostDefaultProduct() domain.ProductSnapshot {
	p := admittedProduct()
	p.Target = &domain.ProductTarget{
		GOOS:   p.GOOS,
		GOARCH: p.GOARCH,
		Source: domain.ProductTargetSourceHostDefault,
	}
	return p
}

// boundContext is the measurement identity of admittedProduct.
func boundContext() *domain.BuildContext {
	b := domain.EffectiveBuildContext(admittedProduct())
	return &b
}

// admittedSnapshot stamps an operator-declared target matching the
// snapshot's build axes, turning it into an identified product build. Empty
// axes default to the fixture platform. The snapshot's other fields
// (TrustedPeer, ReleaseGoVersion, …) are preserved.
func admittedSnapshot(p domain.ProductSnapshot) domain.ProductSnapshot {
	if p.GOOS == "" {
		p.GOOS = "linux"
	}
	if p.GOARCH == "" {
		p.GOARCH = "amd64"
	}
	p.Target = &domain.ProductTarget{
		GOOS:       p.GOOS,
		GOARCH:     p.GOARCH,
		BuildTags:  append([]string(nil), p.BuildTags...),
		CGOEnabled: p.CGOEnabled,
		Source:     domain.ProductTargetSourceOperatorDeclared,
		Scope:      domain.ProductTargetScopeOperator,
	}
	return p
}

// addCompletePackageList records a completed, complete inventory matching the
// case's effective build context.
func addCompletePackageList(c *domain.AnalysisCase, content string) domain.EvidenceID {
	return addCompletePackageListID(c, "EV-PKGS", content)
}

func addCompletePackageListID(c *domain.AnalysisCase, id domain.EvidenceID, content string) domain.EvidenceID {
	build := domain.EffectiveBuildContext(c.Product)
	return c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID:           id,
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		BuildContext: &build,
		PackageList:  &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./..."},
		Content:      content,
	})
}

// addSourceScan records one completed source measurement covering the given
// subjects (by owning package) with product-used entry symbols.
func addSourceScan(c *domain.AnalysisCase, subjects []domain.SymbolRef, complete, opaque bool) {
	for i, s := range subjects {
		build := domain.EffectiveBuildContext(c.Product)
		entries := []string{s.Package + ".Entry"}
		if opaque {
			entries = nil
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:           domain.EvidenceID("EV-SCAN-" + string(rune('A'+i))),
			Kind:         domain.EvidenceSourceScan,
			Quality:      domain.QualityDeterministic,
			Source:       "source index: module-internal reachability measurement",
			Tool:         "goanalysis.Index.ModuleInternalReach",
			BuildContext: &build,
			SourceScan: &domain.SourceScanRun{
				Module:       s.Package,
				Subjects:     []domain.SymbolRef{s},
				EntrySymbols: entries,
				Completed:    true,
				Complete:     complete,
				Opaque:       opaque,
			},
		})
	}
}

// addTypedGovulncheckSilence records a completed-empty, covered,
// scope-complete measurement declaring the given symbols.
func addTypedGovulncheckSilence(c *domain.AnalysisCase, subjects []domain.SymbolRef) domain.EvidenceID {
	build := domain.EffectiveBuildContext(c.Product)
	return c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID:           "EV-SILENCE",
		Kind:         domain.EvidenceGovulncheck,
		Quality:      domain.QualityDeterministic,
		BuildContext: &build,
		Govulncheck: &domain.GovulncheckRun{
			Outcome: domain.GovulncheckCompletedEmpty,
			Coverage: domain.GovulncheckCoverage{
				AdvisoryID:    c.Vulnerability.ID,
				Advisory:      domain.GovulncheckCoverageCovered,
				Subjects:      subjects,
				ScopeComplete: true,
			},
		},
	})
}

// addUsageScan records a completed module-usage measurement covering the
// subjects (no entry symbols — usage only).
func addUsageScan(c *domain.AnalysisCase, subjects []domain.SymbolRef) {
	for i, s := range subjects {
		build := domain.EffectiveBuildContext(c.Product)
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:           domain.EvidenceID("EV-USE-SCAN-" + string(rune('A'+i))),
			Kind:         domain.EvidenceSourceScan,
			Quality:      domain.QualityDeterministic,
			Source:       "source index: module usage measurement",
			Tool:         "goanalysis.Index.ModuleUsage",
			BuildContext: &build,
			SourceScan: &domain.SourceScanRun{
				Module:    s.Package,
				Subjects:  []domain.SymbolRef{s},
				Completed: true,
				Complete:  true,
			},
		})
	}
}

// completePackageList is a completed, complete inventory matching
// admittedProduct — the metadata a package-absence negative requires.
func completePackageList() domain.Evidence {
	build := domain.EffectiveBuildContext(admittedProduct())
	return domain.Evidence{
		ID:           "EV-FIXTURE-PACKAGE-LIST",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		BuildContext: &build,
		PackageList:  &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./..."},
		Content:      `{"ImportPath":"example.com/prod"}`,
	}
}

// Every build-dependent producer applies the target gate before returning a
// FALSE; independent deployment/release facts remain usable.
func TestTargetAdmissionBeforeEvaluatorFalse(t *testing.T) {
	reachCond := domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
	}
	reach := func(p domain.ProductSnapshot) domain.Claim {
		c := &domain.AnalysisCase{Product: p,
			// Package absence is evidence about a record-declared subject.
			Vulnerability: domain.Vulnerability{ID: "GO-TEST", AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/dep/vuln"},
			}}}
		addCompletePackageList(c, `{"ImportPath":"example.com/prod"}`)
		return SymbolReachable{}.Evaluate(reachCond, c)
	}
	if got := reach(hostDefaultProduct()); got.Result != domain.ClaimUnknown {
		t.Fatalf("host-default package absence produced %s", got.Result)
	}
	if got := reach(admittedProduct()); got.Result != domain.ClaimFalse ||
		got.Falsifier != domain.FalsifierPackageAbsent {
		t.Fatalf("admitted package absence = %+v", got)
	}

	validationCond := domain.Condition{ID: "C-V", Kind: domain.ConditionValidation}
	validation := func(p domain.ProductSnapshot) domain.Claim {
		c := &domain.AnalysisCase{Product: p}
		c.EvidenceGraph.DataFlows = []domain.DataFlow{{ConditionID: "C-V", Sink: domain.CallSite{File: "a.go", Line: 40}}}
		c.EvidenceGraph.Validations = []domain.Validation{{
			CallSite: domain.CallSite{File: "a.go", Line: 10},
			Guard:    true,
		}}
		return Validation{}.Evaluate(validationCond, c)
	}
	if got := validation(hostDefaultProduct()); got.Result != domain.ClaimUnknown {
		t.Fatalf("host-default guard proof produced %s", got.Result)
	}
	if got := validation(admittedProduct()); got.Result != domain.ClaimFalse {
		t.Fatalf("admitted guard proof = %+v", got)
	}

	presenceCond := domain.Condition{
		ID: "C-P", Kind: domain.ConditionConfiguration,
		Subjects: []domain.SymbolRef{{Package: "mod/amqp", Symbol: "PlainAuth"}},
		Params:   map[string]string{domain.ParamCheck: domain.CheckSymbolPresent},
	}
	presence := func(p domain.ProductSnapshot) domain.Claim {
		c := &domain.AnalysisCase{Product: p}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-PRES", Kind: domain.EvidenceSearchResult,
			Tool: "goanalysis.Index.FindSymbol", Source: "presence check mod/amqp.PlainAuth",
		})
		c.EvidenceGraph.AddSymbolDecl("mod/amqp.PlainAuth", nil)
		return Presence{}.Evaluate(presenceCond, c)
	}
	if got := presence(hostDefaultProduct()); got.Result != domain.ClaimUnknown {
		t.Fatalf("host-default source absence produced %s", got.Result)
	}
	if got := presence(admittedProduct()); got.Result != domain.ClaimFalse {
		t.Fatalf("admitted source absence = %+v", got)
	}

	config := func(p domain.ProductSnapshot) domain.Claim {
		c := &domain.AnalysisCase{Product: p}
		key := "crypto/tls.Config.InsecureSkipVerify"
		c.EvidenceGraph.AddConfigFlag(key, domain.ConfigAssignment{
			Subject: key, Value: "false", Source: "literal",
			CallSite: domain.CallSite{File: "x.go", Line: 3},
		})
		return ConfigFlag{}.Evaluate(tlsCond(), c)
	}
	if got := config(hostDefaultProduct()); got.Result != domain.ClaimUnknown {
		t.Fatalf("host-default config proof produced %s", got.Result)
	}
	if got := config(admittedProduct()); got.Result != domain.ClaimUnknown {
		t.Fatalf("admitted config proof = %+v", got)
	}

	publicCond := exposureCond()
	publicCond.Params[domain.ParamScope] = "public"
	codeExposure := func(p domain.ProductSnapshot) domain.Claim {
		c := exposureCase(domain.ExposureFact{
			Direction: "inbound", Kind: "listener", Target: "net.Listen",
			Address: "127.0.0.1:80", AddressSource: "literal", Scope: domain.ScopeLoopback,
		})
		c.Product = p
		return Exposure{}.Evaluate(publicCond, c)
	}
	if got := codeExposure(hostDefaultProduct()); got.Result != domain.ClaimUnknown {
		t.Fatalf("host-default code loopback produced %s", got.Result)
	}
	if got := codeExposure(admittedProduct()); got.Result != domain.ClaimFalse {
		t.Fatalf("admitted code loopback = %+v", got)
	}
	if got := codeExposure(hostDefaultProduct()); got.FalsifierBasis != "" {
		t.Fatalf("code loopback must not claim a deployment basis: %q", got.FalsifierBasis)
	}

	deployExposure := func(p domain.ProductSnapshot) domain.Claim {
		c := exposureCase(domain.ExposureFact{
			Direction: "inbound", Kind: "deployment", Target: "k8s:Service:ClusterIP",
			Address: "ClusterIP", AddressSource: "manifest svc.yaml", Scope: domain.ScopeLoopback,
		})
		c.Product = p
		return Exposure{}.Evaluate(publicCond, c)
	}
	got := deployExposure(hostDefaultProduct())
	if got.Result != domain.ClaimFalse || got.FalsifierBasis != domain.BasisDeployment {
		t.Fatalf("manifest loopback must stay independent: %+v", got)
	}
	if deploy := deployExposure(admittedProduct()); deploy.Result != domain.ClaimFalse {
		t.Fatalf("manifest loopback under an admitted target = %+v", deploy)
	}

	platformCond := domain.Condition{ID: "C-PLAT", Kind: domain.ConditionPlatform,
		Params: map[string]string{"goos": "windows"}}
	if got := (Platform{}).Evaluate(platformCond, &domain.AnalysisCase{Product: hostDefaultProduct()}); got.Result != domain.ClaimUnknown {
		t.Fatalf("host-default goos mismatch produced %s", got.Result)
	}
	if got := (Platform{}).Evaluate(platformCond, &domain.AnalysisCase{Product: admittedProduct()}); got.Result != domain.ClaimFalse {
		t.Fatalf("admitted goos mismatch = %+v", got)
	}
	releaseCond := domain.Condition{ID: "C-REL", Kind: domain.ConditionRuntime,
		Params: map[string]string{"go_version": ">=1.24"}}
	releaseProduct := hostDefaultProduct()
	releaseProduct.ReleaseGoVersion = "go1.21.5"
	if got := (Platform{}).Evaluate(releaseCond, &domain.AnalysisCase{Product: releaseProduct}); got.Result != domain.ClaimFalse {
		t.Fatalf("release-toolchain contradiction must stay usable: %+v", got)
	}
}
