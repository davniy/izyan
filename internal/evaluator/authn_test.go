package evaluator

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func authnCond() domain.Condition {
	return domain.Condition{
		ID:   "C-AUTH",
		Kind: domain.ConditionAuthn,
	}
}

// TestAuthMiddlewareNameDoesNotProveCoverage pins the removal of the
// middleware-name TRUE path. An auth-middleware fact is matched by argument
// name and position; it records that auth-like wiring exists, not that every
// route to the vulnerable surface passes it. The claim stays UNKNOWN with a
// typed measurement gap, and a persisted TRUE from the removed path is demoted
// at the shared verdict boundary instead of grounding a positive.
func TestAuthMiddlewareNameDoesNotProveCoverage(t *testing.T) {
	cond := authnCond()
	c := exposureCase(
		domain.ExposureFact{Direction: "inbound", Kind: "listener", Target: "net.Listen",
			Address: ":9090", AddressSource: "literal", Scope: domain.ScopeAllInterfaces},
		domain.ExposureFact{Direction: "inbound", Kind: "auth-middleware", Target: "authMw",
			CallSite: domain.CallSite{File: "srv.go", Line: 12}},
	)
	c.ID = "CASE-AUTHN"
	cl := Authentication{}.Evaluate(cond, c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s (%s): a middleware name must not establish auth coverage", cl.Result, cl.Explanation)
	}
	if cl.Falsifier != "" || cl.NegativeVerification != nil {
		t.Fatalf("absence of proof must not become a negative: %+v", cl)
	}
	gap := measurementGapFor(t, cl.AnalysisGaps, cond.ID)
	if gap.Owner != domain.GapOwnerProof || gap.Code != domain.GapMeasurementNotCompleted ||
		gap.Obligation != domain.ObligationCondition {
		t.Fatalf("gap = %+v; want PROOF/MEASUREMENT_NOT_COMPLETED/CONDITION", gap)
	}
	if err := gap.Validate(); err != nil {
		t.Fatalf("typed gap is invalid: %v", err)
	}
	found := false
	for _, l := range cl.Limitations {
		if strings.Contains(l, "per-route") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected per-route coverage caveat, got %v", cl.Limitations)
	}

	// Replay: a saved TRUE on an authentication condition rested on exactly
	// that name match. No producer measures per-route coverage, so the saved
	// conclusion is demoted and cannot publish an EXPLOITABLE verdict.
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{cond},
	}
	saved := []domain.Claim{{ID: "CL-C-AUTH", ConditionID: cond.ID, Result: domain.ClaimTrue}}
	got := evalVerdictInput(affectedAllTrue(), model, saved, nil, domain.Vulnerability{})
	if got.Verdict.Verdict == domain.VerdictExploitable {
		t.Fatalf("a saved auth-name TRUE grounded a positive: %+v", got.Verdict)
	}
	if got.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%s, want INCONCLUSIVE", got.Verdict.Verdict)
	}
}

// measurementGapFor returns the single MEASUREMENT_NOT_COMPLETED gap a claim
// records for one condition.
func measurementGapFor(t *testing.T, gaps []domain.AnalysisGap, id domain.ConditionID) domain.AnalysisGap {
	t.Helper()
	var found []domain.AnalysisGap
	for _, gap := range gaps {
		if gap.Code == domain.GapMeasurementNotCompleted && gap.ConditionID == id {
			found = append(found, gap)
		}
	}
	if len(found) != 1 {
		t.Fatalf("claim gaps = %+v; want exactly one measurement gap for %s", gaps, id)
	}
	return found[0]
}

func TestAuthenticationNoWiring(t *testing.T) {
	// Listener present but no auth middleware: absence is not proof —
	// the claim must stay UNKNOWN, never FALSE.
	c := exposureCase(domain.ExposureFact{Direction: "inbound", Kind: "listener",
		Target: "net.Listen", Address: ":9090", AddressSource: "literal",
		Scope: domain.ScopeAllInterfaces})
	cl := Authentication{}.Evaluate(authnCond(), c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s, want UNKNOWN", cl.Result)
	}
}

func TestAuthenticationMiddlewareNoListener(t *testing.T) {
	// Auth wiring without a resolved listener may be dead code — UNKNOWN.
	c := exposureCase(domain.ExposureFact{Direction: "inbound", Kind: "auth-middleware",
		Target: "authMw", CallSite: domain.CallSite{File: "srv.go", Line: 12}})
	cl := Authentication{}.Evaluate(authnCond(), c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s, want UNKNOWN", cl.Result)
	}
	if !strings.Contains(cl.Limitations[0], "no inbound listener") {
		t.Fatalf("lims=%v", cl.Limitations)
	}
}
