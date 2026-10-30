package states_test

import (
	"runtime"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/repository"
)

// declaredSnapshotOptions declares the analyzed build explicitly: both axes
// are operator-declared, which is a legitimate product build identity. The
// zero SnapshotOptions value stays a host-default analysis context and is
// never admitting.
func declaredSnapshotOptions() repository.SnapshotOptions {
	return repository.SnapshotOptions{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// declaredProduct is the product snapshot a declared-target fixture resolves
// without running the repository probe.
func declaredProduct() domain.ProductSnapshot {
	p := domain.ProductSnapshot{
		Repository: "/test/product",
		Commit:     "declared-build",
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
	}
	p.Target = &domain.ProductTarget{
		GOOS: p.GOOS, GOARCH: p.GOARCH,
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	return p
}

// evalCaseVerdict runs the production verdict entry point with the case's
// product, model, claims and evidence list.
func evalCaseVerdict(c *domain.AnalysisCase, claims []domain.Claim) domain.VerdictResult {
	var affected domain.AffectedResult
	if c.Affected != nil {
		affected = *c.Affected
	}
	var model domain.ExploitModel
	if c.Exploit != nil {
		model = *c.Exploit
	}
	return evaluator.VerdictEvaluator{}.Evaluate(evaluator.VerdictInput{
		Product:  c.Product,
		Affected: affected,
		Model:    model,
		Claims:   claims,
		Evidence: c.EvidenceGraph.EvidenceList(),
		Vulnerability: c.Vulnerability,
		RootCause: c.RootCause,
		RecordPin: c.RecordPin,
		AdvisoryRecord: c.AdvisoryRecord,
	})
}

// evalBareVerdict runs the evaluator with only the given input — no product
// or evidence is supplied, so any build-dependent negative stays refused.
func evalBareVerdict(res domain.AffectedResult, model domain.ExploitModel, claims []domain.Claim) domain.VerdictResult {
	return evaluator.VerdictEvaluator{}.Evaluate(evaluator.VerdictInput{
		Affected: res,
		Model:    model,
		Claims:   claims,
	})
}
