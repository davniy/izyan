package finding_test

import (
	"context"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/rootcause"
)

// The re-landed proof contract refuses dependencies, not unrelated evidence. A
// persisted proof that no longer re-derives invalidates every subject that
// depended on it — but an independently re-derived exact-preimage route for the
// same subject still stands, because that route's evidence is its own captured
// bytes.
func TestRefusedPersistedProofDoesNotVetoIndependentSameLineRoute(t *testing.T) {
	c, index, _ := rdCase(t)
	subject := domain.SymbolRef{Package: rdPkg, Symbol: "Parse"}
	model := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: rdPkg, Symbol: "Parse", Role: domain.RootCauseSink,
			Origin:  domain.RootCauseOriginFixDerived,
			Binding: &domain.CandidateBinding{Module: rdModule, PatchPath: rdPath},
		}},
		FixArtifacts: []domain.FixArtifact{{
			Locator:     rdLocator,
			Kind:        "commit",
			Outcome:     domain.FixArtifactComplete,
			Provenance:  "captured fixture",
			Digest:      domain.EvidenceContentDigest(rdPatch),
			Size:        len(rdPatch),
			Bytes:       rdPatch,
			Coordinates: []string{rdPath},
		}},
	}
	rootcause.Verifier{Source: index}.Verify(context.Background(), c, model, c.Vulnerability)
	c.RootCause = model

	fresh := rdAdmission(c, model)
	if !fresh.Admits(subject).Admitted {
		t.Fatalf("refusals=%v — the fresh exact-preimage route did not admit its subject", fresh.Refusals())
	}
	if fresh.Cover() == nil || !fresh.Cover().Covers(subject) {
		t.Fatalf("cover=%+v — the exact-preimage route established no cover", fresh.Cover())
	}

	// A persisted proof that claims the same subject but cannot be re-derived
	// is a refused dependency. It dominates labels over the subjects it
	// claimed; it does not veto the independent route.
	model.FixProof = rdAssertedProof(rdRecord, subject)
	replayed := rdAdmission(c, model)
	if !replayed.Admits(subject).Admitted {
		t.Fatalf("refusals=%v — a refused unrelated proof vetoed the independent exact-preimage route",
			replayed.Refusals())
	}
	if cover := replayed.Cover(); cover == nil || !cover.Covers(subject) {
		t.Fatalf("cover=%+v — the exact-preimage cover disappeared behind a refused proof", cover)
	}
}
