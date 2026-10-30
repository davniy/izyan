package repository

import (
	"github.com/fedorovmv/izyan/internal/productb/domain"
	canonical "github.com/fedorovmv/izyan/internal/repository"
)

// LoadDeclaredAssumptions delegates to the canonical declared-assumptions/1
// intake: fail-closed, typed LoadError on unreadable/oversized/invalid
// documents, members retained for audit even under rejection. The Product B
// adapter consumes the same channel — an assumption is a policy input, never
// an EvidenceGraph fact, and its admission (domain.AdmitAssumption) is the
// same gate Product A uses.
func LoadDeclaredAssumptions(path string) *domain.DeclaredAssumptionsInput {
	return canonical.LoadDeclaredAssumptions(path)
}
