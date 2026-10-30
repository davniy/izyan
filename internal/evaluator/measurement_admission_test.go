package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// packageAbsenceClaim evaluates a subject-bearing reachability condition
// whose only subject package is absent from the given inventory.
func packageAbsenceClaim(t *testing.T, p domain.ProductSnapshot, evidence func(*domain.AnalysisCase)) domain.Claim {
	t.Helper()
	c := &domain.AnalysisCase{Product: p,
		// The package-absence negative is about a subject the record declares.
		Vulnerability: domain.Vulnerability{ID: "GO-TEST", AffectedPackages: []domain.AffectedPackage{
			{Path: "example.com/dep/vuln"},
		}}}
	cond := domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
	}
	evidence(c)
	return SymbolReachable{}.Evaluate(cond, c)
}

// A package-absence negative is a measurement: a missing, partial or
// foreign-context inventory leaves the claim UNKNOWN.
func TestMeasurementAdmissionPackageAbsence(t *testing.T) {
	t.Run("missing inventory", func(t *testing.T) {
		got := packageAbsenceClaim(t, admittedProduct(), func(*domain.AnalysisCase) {})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("missing inventory produced FALSE: %+v", got)
		}
	})
	t.Run("partial inventory", func(t *testing.T) {
		got := packageAbsenceClaim(t, admittedProduct(), func(c *domain.AnalysisCase) {
			build := domain.EffectiveBuildContext(c.Product)
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID: "EV-PARTIAL", Kind: domain.EvidencePackageList,
				BuildContext: &build,
				PackageList:  &domain.PackageListRun{Completed: true, Complete: false, Pattern: "./cmd/..."},
				Content:      `{"ImportPath":"example.com/prod"}`,
			})
		})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("partial inventory produced FALSE: %+v", got)
		}
	})
	t.Run("foreign inventory", func(t *testing.T) {
		got := packageAbsenceClaim(t, admittedProduct(), func(c *domain.AnalysisCase) {
			foreign := domain.EffectiveBuildContext(c.Product)
			foreign.Commit = "another-build"
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID: "EV-FOREIGN", Kind: domain.EvidencePackageList,
				BuildContext: &foreign,
				PackageList:  &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./..."},
				Content:      `{"ImportPath":"example.com/prod"}`,
			})
		})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("foreign inventory produced FALSE: %+v", got)
		}
	})
	t.Run("complete matching inventory", func(t *testing.T) {
		got := packageAbsenceClaim(t, admittedProduct(), func(c *domain.AnalysisCase) {
			addCompletePackageList(c, `{"ImportPath":"example.com/prod"}`)
		})
		if got.Result != domain.ClaimFalse || got.Falsifier != domain.FalsifierPackageAbsent {
			t.Fatalf("complete inventory = %+v", got)
		}
	})
}

// moduleUsageProduct is the multi-module product every module-usage
// measurement below describes.
func moduleUsageCase(t *testing.T, p domain.ProductSnapshot) (*domain.AnalysisCase, domain.Condition) {
	t.Helper()
	c := &domain.AnalysisCase{Product: p}
	c.Vulnerability = domain.Vulnerability{
		ID: "GO-TEST-1", Module: "mod/amqp",
		AffectedSymbols: []domain.SymbolRef{{Package: "mod/amqp", Symbol: "Parse"}},
	}
	// A legacy text marker is not a measurement.
	c.EvidenceGraph.AddEvidence(domain.Evidence{Tool: "goanalysis.Index.ModuleUsage"})
	addTypedGovulncheck(c, domain.GovulncheckCompletedEmpty,
		domain.GovulncheckCoverageNotInDB, true, nil)
	return c, domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{{Package: "mod/amqp", Symbol: "Parse"}},
	}
}

// Zero module usage is a negative only from a completed, complete source
// measurement; a text marker, an incomplete census or a foreign context
// leave it UNKNOWN.
func TestMeasurementAdmissionModuleUsage(t *testing.T) {
	subject := domain.SymbolRef{Package: "mod/amqp", Symbol: "Parse"}
	t.Run("legacy text marker is not a measurement", func(t *testing.T) {
		c, cond := moduleUsageCase(t, admittedProduct())
		if got := (SymbolReachable{}).Evaluate(cond, c); got.Result == domain.ClaimFalse {
			t.Fatalf("text marker produced FALSE: %+v", got)
		}
	})
	t.Run("incomplete census", func(t *testing.T) {
		c, cond := moduleUsageCase(t, admittedProduct())
		build := domain.EffectiveBuildContext(c.Product)
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-SCAN-INCOMPLETE", Kind: domain.EvidenceSourceScan,
			BuildContext: &build,
			SourceScan: &domain.SourceScanRun{
				Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
				Completed: true, Complete: false,
			},
		})
		if got := (SymbolReachable{}).Evaluate(cond, c); got.Result == domain.ClaimFalse {
			t.Fatalf("incomplete census produced FALSE: %+v", got)
		}
	})
	t.Run("incomplete scan", func(t *testing.T) {
		c, cond := moduleUsageCase(t, admittedProduct())
		build := domain.EffectiveBuildContext(c.Product)
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-SCAN-PARTIAL", Kind: domain.EvidenceSourceScan,
			BuildContext: &build,
			SourceScan: &domain.SourceScanRun{
				Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
				Completed: false, Complete: true,
			},
		})
		if got := (SymbolReachable{}).Evaluate(cond, c); got.Result == domain.ClaimFalse {
			t.Fatalf("incomplete scan produced FALSE: %+v", got)
		}
	})
	t.Run("foreign context", func(t *testing.T) {
		c, cond := moduleUsageCase(t, admittedProduct())
		foreign := domain.EffectiveBuildContext(c.Product)
		foreign.Commit = "another-build"
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-SCAN-FOREIGN", Kind: domain.EvidenceSourceScan,
			BuildContext: &foreign,
			SourceScan: &domain.SourceScanRun{
				Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
				Completed: true, Complete: true,
			},
		})
		if got := (SymbolReachable{}).Evaluate(cond, c); got.Result == domain.ClaimFalse {
			t.Fatalf("foreign measurement produced FALSE: %+v", got)
		}
	})
	t.Run("wrong subject coverage", func(t *testing.T) {
		c, cond := moduleUsageCase(t, admittedProduct())
		addUsageScan(c, []domain.SymbolRef{{Package: "mod/amqp", Symbol: "Other"}})
		if got := (SymbolReachable{}).Evaluate(cond, c); got.Result == domain.ClaimFalse {
			t.Fatalf("wrong-subject measurement produced FALSE: %+v", got)
		}
	})
	t.Run("complete measurement", func(t *testing.T) {
		c, cond := moduleUsageCase(t, admittedProduct())
		addUsageScan(c, []domain.SymbolRef{subject})
		got := (SymbolReachable{}).Evaluate(cond, c)
		if got.Result != domain.ClaimFalse || got.Falsifier != domain.FalsifierNoModuleUsage {
			t.Fatalf("complete measurement = %+v", got)
		}
	})
}

// locusUnreached evaluates a two-subject locus set described by the given
// fixture; the build must actually link both packages.
func locusUnreached(t *testing.T, evidence func(*domain.AnalysisCase, domain.Condition)) domain.Claim {
	t.Helper()
	cond := domain.Condition{
		ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
		Params: map[string]string{domain.ParamCheck: domain.CheckLocus},
		Subjects: []domain.SymbolRef{
			{Package: "example.com/lib/internal/xds/server", Symbol: "RouteAndProcess"},
			{Package: "example.com/lib/internal/transport", Symbol: "legacyRoute"},
		},
	}
	c := caseWithPackages(
		"example.com/lib/internal/xds/server",
		"example.com/lib/internal/transport",
		"example.com/prod")
	evidence(c, cond)
	return evalLocus(cond, c)
}

// Linked packages with no call traces are UNKNOWN until a completed,
// complete, non-opaque source measurement covers the whole locus set.
func TestMeasurementAdmissionLocusUnreached(t *testing.T) {
	t.Run("empty collections are not a measurement", func(t *testing.T) {
		got := locusUnreached(t, func(*domain.AnalysisCase, domain.Condition) {})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("empty trace collections produced FALSE: %+v", got)
		}
	})
	t.Run("partial subject coverage", func(t *testing.T) {
		got := locusUnreached(t, func(c *domain.AnalysisCase, cond domain.Condition) {
			addSourceScan(c, cond.Subjects[:1], true, false)
		})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("partial coverage produced FALSE: %+v", got)
		}
	})
	t.Run("opaque measurement", func(t *testing.T) {
		got := locusUnreached(t, func(c *domain.AnalysisCase, cond domain.Condition) {
			addSourceScan(c, cond.Subjects, true, true)
		})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("opaque measurement produced FALSE: %+v", got)
		}
	})
	t.Run("incomplete measurement", func(t *testing.T) {
		got := locusUnreached(t, func(c *domain.AnalysisCase, cond domain.Condition) {
			addSourceScan(c, cond.Subjects, false, false)
		})
		if got.Result == domain.ClaimFalse {
			t.Fatalf("incomplete measurement produced FALSE: %+v", got)
		}
	})
	t.Run("complete non-opaque measurement", func(t *testing.T) {
		got := locusUnreached(t, func(c *domain.AnalysisCase, cond domain.Condition) {
			addSourceScan(c, cond.Subjects, true, false)
		})
		if got.Result != domain.ClaimFalse || got.Falsifier != domain.FalsifierLocusFunctionUnreached {
			t.Fatalf("complete measurement = %+v", got)
		}
	})
}

// Govulncheck silence is a negative only from a cited, completed-empty,
// covered, whole-build measurement that declares the evaluated symbols.
func TestMeasurementAdmissionGovulncheckSilence(t *testing.T) {
	subject := domain.SymbolRef{Package: "lib/internal/transport", Symbol: "recvBuffer.put"}
	cond := domain.Condition{ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{subject}}
	eval := func(mutate func(*domain.AnalysisCase, *domain.Condition)) domain.Claim {
		c := reachabilityCase()
		c.Product = admittedProduct()
		c.Vulnerability.AffectedSymbols = []domain.SymbolRef{subject}
		cond := cond
		mutate(c, &cond)
		return (SymbolReachable{}).Evaluate(cond, c)
	}
	if got := eval(func(c *domain.AnalysisCase, cond *domain.Condition) {
		addTypedGovulncheck(c, domain.GovulncheckCompletedEmpty,
			domain.GovulncheckCoverageCovered, true, []domain.SymbolRef{subject})
	}); got.Result != domain.ClaimFalse || got.Falsifier != domain.FalsifierGovulncheckSilence {
		t.Fatalf("full-coverage silence = %+v", got)
	}
	if got := eval(func(c *domain.AnalysisCase, cond *domain.Condition) {
		addTypedGovulncheck(c, domain.GovulncheckFailed,
			domain.GovulncheckCoverageUnknown, false, nil)
	}); got.Result == domain.ClaimFalse {
		t.Fatalf("failed measurement produced FALSE: %+v", got)
	}
	if got := eval(func(c *domain.AnalysisCase, cond *domain.Condition) {
		addTypedGovulncheck(c, domain.GovulncheckCompletedWithResults,
			domain.GovulncheckCoverageCovered, true, []domain.SymbolRef{subject})
	}); got.Result == domain.ClaimFalse {
		t.Fatalf("completed-with-results produced silence FALSE: %+v", got)
	}
	if got := eval(func(c *domain.AnalysisCase, cond *domain.Condition) {
		addTypedGovulncheck(c, domain.GovulncheckCompletedEmpty,
			domain.GovulncheckCoverageCovered, false, []domain.SymbolRef{subject})
	}); got.Result == domain.ClaimFalse {
		t.Fatalf("narrowed scan produced silence FALSE: %+v", got)
	}
	if got := eval(func(c *domain.AnalysisCase, cond *domain.Condition) {
		addTypedGovulncheck(c, domain.GovulncheckCompletedEmpty,
			domain.GovulncheckCoverageCovered, true, nil)
	}); got.Result == domain.ClaimFalse {
		t.Fatalf("undeclared subject coverage produced silence FALSE: %+v", got)
	}
}

// persistedReachabilityCase builds a case whose only reachability evidence is
// the module-usage observation for an unexported subject — exactly what the
// retired unexported-sink true used to consume.
func persistedReachabilityCase() (*domain.AnalysisCase, domain.ExploitModel, domain.Claim) {
	subject := domain.SymbolRef{Package: "mod/amqp", Symbol: "readLongstr"}
	c := &domain.AnalysisCase{Product: admittedProduct()}
	c.Vulnerability = domain.Vulnerability{
		ID: "GO-TEST-1", Module: "mod/amqp",
		AffectedSymbols: []domain.SymbolRef{subject},
	}
	build := domain.EffectiveBuildContext(c.Product)
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID: "EV-USE-SCAN", Kind: domain.EvidenceSourceScan, Quality: domain.QualityDeterministic,
		Source: "source index: module usage measurement", Tool: "goanalysis.Index.ModuleUsage",
		BuildContext: &build,
		SourceScan: &domain.SourceScanRun{
			Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
			Completed: true, Complete: true,
		},
	})
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
	})
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
		Subjects: []domain.SymbolRef{subject},
	}}}
	claim := domain.Claim{
		ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue,
		EvidenceIDs: []domain.EvidenceID{"EV-USE-SCAN"},
		Producer:    "evaluator.SymbolReachable",
	}
	c.Exploit = &model
	c.Claims = []domain.Claim{claim}
	return c, model, claim
}

// persistedReachabilityVerdict runs the verdict boundary with the case that
// owns the saved claims, so persisted positives are re-established against
// the recorded evidence instead of being trusted.
func persistedReachabilityVerdict(c *domain.AnalysisCase, model domain.ExploitModel,
	claims []domain.Claim) VerdictEvaluation {
	affected := affectedAllTrue()
	affected.Scope = fullRecordScope("GO-TEST-1", "mod/amqp")
	return (VerdictEvaluator{}).EvaluateDetailed(VerdictInput{
		Product:       c.Product,
		Affected:      affected,
		Model:         model,
		Claims:        claims,
		Evidence:      c.EvidenceGraph.EvidenceList(),
		Vulnerability: c.Vulnerability,
		RootCause:     c.RootCause,
		RecordPin: c.RecordPin,
		AdvisoryRecord: c.AdvisoryRecord,
		Case:          c,
	})
}

func persistedPositiveGap(gaps []domain.AnalysisGap, id domain.ConditionID) bool {
	for _, gap := range gaps {
		if gap.Owner == domain.GapOwnerProof && gap.Code == domain.GapMeasurementNotCompleted &&
			gap.ConditionID == id {
			return true
		}
	}
	return false
}

// A saved TRUE is not evidence. The retired weak positives (unexported-sink +
// module usage, frame-name/server-role transport) reproduce no TRUE from the
// recorded evidence, so replay demotes them at the verdict boundary; an exact
// direct call and a recorded intra-module chain are re-established and keep
// their authority.
func TestMeasurementAdmissionPersistedWeakPositive(t *testing.T) {
	t.Run("saved unexported-sink module-usage TRUE is demoted", func(t *testing.T) {
		c, model, claim := persistedReachabilityCase()
		got := persistedReachabilityVerdict(c, model, []domain.Claim{claim})
		if got.Verdict.Verdict == domain.VerdictExploitable {
			t.Fatalf("a saved weak positive grounded EXPLOITABLE: %+v", got.Verdict)
		}
		if got.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("verdict=%s, want INCONCLUSIVE", got.Verdict.Verdict)
		}
		if !persistedPositiveGap(got.Gaps, claim.ConditionID) {
			t.Fatalf("gaps=%+v; want a PROOF/MEASUREMENT_NOT_COMPLETED gap for %s", got.Gaps, claim.ConditionID)
		}
	})

	t.Run("saved frame-name transport TRUE is demoted", func(t *testing.T) {
		c := &domain.AnalysisCase{Product: admittedProduct()}
		c.Vulnerability = domain.Vulnerability{ID: "GO-TEST-1", Module: "mod/amqp"}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-CALLPATH", Kind: domain.EvidenceCallPath,
			Quality: domain.QualityDeterministic, Content: "server transport frame",
		})
		c.EvidenceGraph.AddCallPath(domain.CallPath{
			EvidenceID: "EV-CALLPATH",
			Frames: []domain.CallSite{{
				Package: "mod/amqp", Receiver: "*http2Server", Function: "HandleStreams",
			}},
		})
		model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-ATTACK", Kind: domain.ConditionAttackerControl, Mandatory: true,
		}}}
		claim := domain.Claim{
			ID: "CL-C-ATTACK", ConditionID: "C-ATTACK", Result: domain.ClaimTrue,
			EvidenceIDs: []domain.EvidenceID{"EV-CALLPATH"},
			Producer:    "evaluator.ServerTransportInput",
		}
		c.Exploit = &model
		c.Claims = []domain.Claim{claim}
		got := persistedReachabilityVerdict(c, model, []domain.Claim{claim})
		if got.Verdict.Verdict == domain.VerdictExploitable {
			t.Fatalf("a saved frame-name positive grounded EXPLOITABLE: %+v", got.Verdict)
		}
		if got.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("verdict=%s, want INCONCLUSIVE", got.Verdict.Verdict)
		}
		if !persistedPositiveGap(got.Gaps, claim.ConditionID) {
			t.Fatalf("gaps=%+v; want a PROOF/MEASUREMENT_NOT_COMPLETED gap for %s", got.Gaps, claim.ConditionID)
		}
	})

	t.Run("saved direct-call TRUE is re-established", func(t *testing.T) {
		subject := domain.SymbolRef{Package: "mod/amqp", Symbol: "Parse"}
		c := &domain.AnalysisCase{Product: admittedProduct()}
		c.Vulnerability = domain.Vulnerability{
			ID: "GO-TEST-1", Module: "mod/amqp",
			AffectedSymbols: []domain.SymbolRef{subject},
		}
		build := domain.EffectiveBuildContext(c.Product)
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-USE-SCAN", Kind: domain.EvidenceSourceScan, Quality: domain.QualityDeterministic,
			Source: "source index: module usage measurement", Tool: "goanalysis.Index.ModuleUsage",
			BuildContext: &build,
			SourceScan: &domain.SourceScanRun{
				Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
				Completed: true, Complete: true,
			},
		})
		c.EvidenceGraph.AddModuleUsages(domain.CallSite{
			Package: "prod/amqp", Function: "main", Callee: "mod/amqp.Parse", ModuleOwner: "mod/amqp",
		})
		model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			Subjects: []domain.SymbolRef{subject},
		}}}
		claim := domain.Claim{
			ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue,
			EvidenceIDs: []domain.EvidenceID{"EV-USE-SCAN"},
			Producer:    "evaluator.SymbolReachable",
		}
		c.Exploit = &model
		c.Claims = []domain.Claim{claim}
		got := persistedReachabilityVerdict(c, model, []domain.Claim{claim})
		if got.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict=%s, want EXPLOITABLE: an exact direct call re-establishes the saved positive (%+v)",
				got.Verdict.Verdict, got.Verdict)
		}
	})

	t.Run("saved intra-module chain TRUE is re-established", func(t *testing.T) {
		c, model, claim := persistedReachabilityCase()
		c.EvidenceGraph.AddModuleReachable("mod/amqp.readLongstr",
			[]string{"mod/amqp.DialTLS", "mod/amqp.readLongstr"})
		got := persistedReachabilityVerdict(c, model, []domain.Claim{claim})
		if got.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict=%s, want EXPLOITABLE: a recorded intra-module chain re-establishes the saved positive (%+v)",
				got.Verdict.Verdict, got.Verdict)
		}
	})
}

func fixtureLocusKernel(cond domain.Condition, product domain.ProductSnapshot) (domain.Evidence, goanalysis.UnreachabilityResult) {
	build := domain.EffectiveBuildContext(product)
	refs := condSubjects(cond)
	module := "example.com/dep"
	if len(refs) > 0 { module = refs[0].Package }
	result := goanalysis.UnreachabilityResult{Module:module, Build:build, Inventory:affected.RecordPackageInventory([]byte(`{"ImportPath":"example.com/product","Name":"main"}`), nil, product, false), ProductPackages:[]string{"example.com/product"}, Complete:true, DeclarationComplete:true, EntrypointComplete:true, ModuleEntryComplete:true, ModuleReachComplete:true}
	for _, ref := range refs { result.Subjects = append(result.Subjects, goanalysis.UnreachabilitySubject{Package:ref.Package, Symbol:ref.Symbol}) }
	raw, _ := json.Marshal(result)
	return domain.Evidence{ID:domain.EvidenceID("EV-KERNEL-"+string(cond.ID)), Kind:domain.EvidenceSourceSnippet, BuildContext:&build, Content:string(raw)}, result
}

func TestUnreachabilityReplayVerdictRequiresCapturedKernel(t *testing.T) {
	for _, name := range []string{"valid", "summary-only", "missing-inventory", "foreign-inventory", "malformed-inventory", "uncited", "open-dispatch", "missing-second-subject"} {
		t.Run(name, func(t *testing.T) {
			product := admittedProduct()
			ref := domain.SymbolRef{Package:"example.com/dep/vuln", Symbol:"Dead"}
			cond := domain.Condition{ID:"C-LOCUS", Kind:domain.ConditionSymbolReachable, Mandatory:true, Subjects:[]domain.SymbolRef{ref}}
			model := domain.ExploitModel{RootCauses:[]domain.SymbolRef{ref}, LocusSubjects:[]domain.SymbolRef{ref}, MandatoryConditions:[]domain.Condition{cond}}
			kernel, result := fixtureLocusKernel(cond, product)
			claim := domain.Claim{ConditionID:cond.ID, Result:domain.ClaimFalse, Falsifier:domain.FalsifierLocusFunctionUnreached, NegativeVerification:&domain.NegativeVerification{Status:domain.NegativeVerified, BuildContext:boundContext(), EvidenceIDs:[]domain.EvidenceID{kernel.ID}}}
			switch name {
			case "missing-inventory": result.Inventory = affected.PackageInventoryMeasurement{}
			case "foreign-inventory": result.Inventory.Build.Commit = "foreign"
			case "malformed-inventory": result.Inventory = affected.RecordPackageInventory([]byte(`{"ImportPath":"example.com/product","Imports":["missing"]}`), nil, product, false); result.Inventory.Run.Complete, result.Inventory.Run.Error = true, ""
			case "uncited": claim.NegativeVerification.EvidenceIDs = nil
			case "open-dispatch": result.InterfaceDispatchSites = []domain.CallSite{{Function:"unknown"}}
			case "missing-second-subject": cond.Subjects = append(cond.Subjects, domain.SymbolRef{Package:ref.Package,Symbol:"Other"}); model.MandatoryConditions[0] = cond; model.RootCauses = append(model.RootCauses, cond.Subjects[1]); model.LocusSubjects = append(model.LocusSubjects, cond.Subjects[1])
			}
			raw, _ := json.Marshal(result); kernel.Content = string(raw)
			evidence := append([]domain.Evidence{completePackageList()}, fixtureSourceScans(cond, product)...)
			if name != "summary-only" { evidence = append(evidence, kernel) }
			af := affectedAllTrue(); af.Scope = exactVerdictScope()
			in := VerdictInput{Product:product, Affected:af, Model:model, Claims:[]domain.Claim{claim}, Evidence:evidence}
			// JSON round-trip is the only replay input: no Index, source or tool.
			encoded, err := json.Marshal(in); if err != nil { t.Fatal(err) }
			var replay VerdictInput; if err := json.Unmarshal(encoded, &replay); err != nil { t.Fatal(err) }
			got := (VerdictEvaluator{}).EvaluateDetailed(replay)
			if name == "valid" {
				if got.Verdict.Verdict != domain.VerdictNoExploitPathFound { t.Fatalf("valid replay: %+v", got) }
			} else {
				admitted, refusals := admitVerdictInput(replay)
				if got.Verdict.Verdict == domain.VerdictNoExploitPathFound || admitted.Claims[0].Result != domain.ClaimUnknown || len(refusals)==0 { t.Fatalf("invalid replay retained authority: %+v", got) }
				if !strings.Contains(refusals[0].message, "negative") { t.Fatalf("missing admission explanation: %+v", refusals) }
			}
		})
	}
}

func TestUnreachabilityReplayAdmittedOmissionPremise(t *testing.T) {
	product := admittedProduct()
	for _, name := range []string{"omission-site", "absent-check", "stale-ground"} {
		t.Run(name, func(t *testing.T) {
			model := omissionModel()
			subject := omissionPipeline()
			if name=="absent-check" { subject = omissionCheck() }
			cond := domain.Condition{ID:"replay",Kind:domain.ConditionSymbolReachable,Subjects:[]domain.SymbolRef{subject}}
			kernel,_ := fixtureLocusKernel(cond,product)
			evidence := append(fixtureSourceScans(cond,product),kernel,omissionAdvisoryEvidence())
			if err:=domain.ValidateDefectSemanticsModel(*model,evidence); err!=nil { t.Fatalf("test requires admitted omission semantics: %v",err) }
			if name=="stale-ground" { evidence[len(evidence)-1].Content += " changed" }
			claim := domain.Claim{Result:domain.ClaimFalse,Falsifier:domain.FalsifierLocusFunctionUnreached,NegativeVerification:&domain.NegativeVerification{Status:domain.NegativeVerified,BuildContext:boundContext(),EvidenceIDs:[]domain.EvidenceID{kernel.ID}}}
			err:=goanalysis.ValidateVerifiedNegative(goanalysis.NegativeAdmissionInput{Product:product,Model:model,Evidence:evidence},claim,cond)
			if name=="omission-site" { if err!=nil { t.Fatal(err) } } else if err==nil { t.Fatal("omitted-check/stale semantics admitted") }
		})
	}
}

func TestForgedCompleteConfigVerdictRefuses(t *testing.T) {
	for _,falsifier:=range []string{domain.FalsifierSafeConfigAssignment,domain.FalsifierZeroValueConfig,domain.FalsifierSafeConfigKey} {
		product:=admittedProduct()
		build:=domain.EffectiveBuildContext(product)
		cond:=domain.Condition{ID:"C-CONFIG",Kind:domain.ConditionConfiguration,Mandatory:true,Params:map[string]string{domain.ParamCheck:domain.CheckConfigFlag,domain.ParamConfigPackage:"example.com/dep",domain.ParamConfigSymbol:"Config.Enabled"}}
		claim:=domain.Claim{ID:"CL-CONFIG",ConditionID:cond.ID,Result:domain.ClaimFalse,Falsifier:falsifier,NegativeVerification:&domain.NegativeVerification{Status:domain.NegativeVerified,BuildContext:&build}}
		in:=VerdictInput{Product:product,Affected:domain.AffectedResult{Scope:exactVerdictScope(),ModulePresent:domain.ClaimTrue,VersionAffected:domain.ClaimTrue},Model:domain.ExploitModel{MandatoryConditions:[]domain.Condition{cond}},Claims:[]domain.Claim{claim}}
		admitted,refusals:=admitVerdictInput(in)
		if len(refusals)==0 || admitted.Claims[0].Result!=domain.ClaimUnknown {t.Fatalf("%s forged configuration verification admitted",falsifier)}
		if in.Claims[0].Result!=domain.ClaimFalse || in.Claims[0].NegativeVerification.Status!=domain.NegativeVerified {t.Fatal("admission destroyed historical verification")}
	}
}
