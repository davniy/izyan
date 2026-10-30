package states

import (
	"runtime"

	"github.com/davniy/izyan/internal/domain"
)

// declaredProduct is the product snapshot a declared-target fixture resolves
// without running the repository probe. Both axes are operator-declared,
// which is a legitimate product build identity (the zero value would be a
// host-default analysis context and is never admitting).
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
