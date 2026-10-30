package goanalysis

import (
	"runtime"

	"github.com/davniy/izyan/internal/domain"
)

// testProduct is the scoped product build every verifier fixture uses. The
// axes follow the host so package loading keeps its normal fixture
// behaviour; the target records them as an operator declaration, which is a
// legitimate product build identity (not a host default), and the source
// index carries the same snapshot.
func testProduct() domain.ProductSnapshot {
	p := domain.ProductSnapshot{
		Repository: "/test/product",
		Commit:     "testcommit",
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
	}
	p.Target = &domain.ProductTarget{
		GOOS:   p.GOOS,
		GOARCH: p.GOARCH,
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	return p
}

// hostProduct is the same analysis platform with no product scope.
func hostProduct() domain.ProductSnapshot {
	p := testProduct()
	p.Target = &domain.ProductTarget{
		GOOS: p.GOOS, GOARCH: p.GOARCH,
		Source: domain.ProductTargetSourceHostDefault,
	}
	return p
}

// boundTestIndex stamps the fixture build on an index that has none, so a
// verifier fixture's measurement identity matches its case.
func boundTestIndex(ix *Index) *Index {
	if ix != nil && ix.Build.GOOS == "" {
		ix.Build = testProduct()
	}
	return ix
}

// testCase is an empty analysis case bound to the fixture product build.
func testCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{Product: testProduct()}
}
