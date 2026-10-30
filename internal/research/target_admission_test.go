package research

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// The applicability chain's build-dependent axes need an admitted target;
// module-graph and version facts stay independent.
func TestApplicabilityTarget(t *testing.T) {
	hostLane := decisionLane(domain.ClaimTrue)
	hostLane.Snapshot = domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	hostLane.Affected.PackagePresent = domain.ClaimFalse
	hostLane.AffectedEvidence = nil
	got := decide(t, DecisionInput{Lane: hostLane})
	if got.Verdict != domain.VerdictInconclusive || got.Coverage != "INSUFFICIENT_SCOPE" {
		t.Fatalf("host-default package absence closed: %+v", got)
	}

	moduleLane := decisionLane(domain.ClaimTrue)
	moduleLane.Snapshot = domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	moduleLane.Affected.ModulePresent = domain.ClaimFalse
	moduleLane.AffectedEvidence = nil
	if got := decide(t, DecisionInput{Lane: moduleLane}); got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("independent module absence refused: %+v", got)
	}

	admittedLane := decisionLane(domain.ClaimTrue)
	admittedLane.Affected.PackagePresent = domain.ClaimFalse
	if got := decide(t, DecisionInput{Lane: admittedLane}); got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("admitted package absence refused: %+v", got)
	}
}

// Research-created package-absence verification is re-admitted by the common
// evaluator: host-default lanes stay INCONCLUSIVE, admitted lanes close.
func TestPackageAbsenceTarget(t *testing.T) {
	trace := decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))

	hostLane := decisionLane(domain.ClaimTrue)
	hostLane.Snapshot = domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	hostLane.AffectedEvidence = nil
	got := decide(t, decisionInput(hostLane, decisionProposal(domain.FalsifierPackageAbsent), trace))
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("host-default package-absence proof promoted: %+v", got)
	}

	admittedLane := decisionLane(domain.ClaimTrue)
	got = decide(t, decisionInput(admittedLane, decisionProposal(domain.FalsifierPackageAbsent), trace))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("admitted package-absence proof = %+v", got)
	}
}

// F1 regression: the evidence session's lazy snapshot probe must not turn
// host-filled effective axes into a fresh operator-declared target. A lane
// with no target inputs stays host-default and cannot close the build-
// dependent post-reach config route.
func TestLaneHostDefaultDoesNotFabricateTarget(t *testing.T) {
	lane, _ := configLaneOpts(t, "", true, false)
	if lane.Snapshot.Target == nil ||
		lane.Snapshot.Target.Source != domain.ProductTargetSourceHostDefault {
		t.Fatalf("lane target = %+v, want host-default", lane.Snapshot.Target)
	}
	if lane.ConfigProof != nil {
		t.Fatalf("host-default lane closed a build-dependent config negative: %+v", lane.ConfigProof.Decision)
	}
}

// F2 regression: a complete, audited declared-symbol unreachability proof
// taken under host-default cannot close the research decision.
func TestDeclaredSymbolUnreachedHostDefaultRefused(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Snapshot = domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	lane.AffectedEvidence = nil
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), true))
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("host-default symbol proof promoted: %+v", got)
	}
	if got.NegativeVerification != nil && got.NegativeVerification.Status == domain.NegativeVerified {
		t.Fatalf("host-default symbol proof carries a VERIFIED negative: %+v", got.NegativeVerification)
	}
}
