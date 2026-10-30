package states_test

// P0 safety regressions. Each test reproduces the FIRST erroneous
// decision of a proven false-safe case, not just the terminal label:
//
//   - k8s-44487: a fixed x/net component closed the whole CVE before root
//     cause research ran. The regression proves the partial scope keeps the
//     pipeline going, preserves both the component fact and the uncovered
//     advisory entry, and ends INCONCLUSIVE.
//   - podman-48795: a legacy TLS floor was attached to an SSH downgrade and
//     a go.mod/release version fact then closed the case. The regression
//     proves neither builder admits the floor and an optional (supporting)
//     verified FALSE can never ground NO_EXPLOIT_PATH_FOUND.
//   - the same case's reviewer finding: an explicit demote removes the
//     irrelevant necessary condition without rewriting the verified claim
//     history, and the remaining UNKNOWN keeps the verdict INCONCLUSIVE.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/exploit"
	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/states"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// exactScope is the only scope authority that allows a negative closure: an
// exact GO-/GHSA- identity whose single original affected[] entry is a Go
// module the loaded record fully represented. COMPLETE coverage alone is not
// closure authority (see TestCheckAffectedPartialScopeContinues).
func exactScope(id string) *domain.AdvisoryScope {
	return exactScopeFor(id, "golang.org/x/net")
}

// exactScopeFor binds id to a full-content census of one named Go module.
func exactScopeFor(id, module string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: module}},
			RepresentedRefs:    []int{0},
		},
	}
}

// recordingRootCauseResolver records that root-cause resolution ran. The
// k8s-44487 regression is about the early exit BEFORE this state, so the
// assertion is on being invoked, not on the returned model.
type recordingRootCauseResolver struct {
	called bool
	model  *domain.RootCauseModel
}

func (r *recordingRootCauseResolver) Resolve(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	r.called = true
	return r.model, nil, nil
}

// partialComponentResolver reports one fixed advisory component while the
// requested identity is a CVE with KNOWN_ONLY coverage.
type partialComponentResolver struct{}

func (partialComponentResolver) Resolve(_ context.Context, v domain.Vulnerability, _ domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	return domain.AffectedResult{
		Scope:           v.Scope,
		ModulePresent:   domain.ClaimTrue,
		ResolvedVersion: "v0.17.0",
		VersionAffected: domain.ClaimFalse,
		CheckedModules:  []string{"golang.org/x/net"},
		EvidenceIDs:     []domain.EvidenceID{"EV-XNET-VERSION"},
	}, nil, nil
}

// TestP0PartialAdvisoryReachesRootCause reproduces k8s-44487: the harness
// loaded a single Go record for CVE-2023-44487 (x/net, fixed in the
// product) and the workflow closed the CVE before researching the other
// implementation. The K8s snapshot also contains gRPC v1.55.0, which the
// loaded record does not refute.
func TestP0PartialAdvisoryReachesRootCause(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()

	// A CVE-wide request is bound to the loaded record only: the resolver
	// derives Kind=CVE / Coverage=KNOWN_ONLY from the request id, so no
	// component-level FALSE may close it.
	requestedID := "CVE-2023-44487"
	vuln := &domain.Vulnerability{
		ID:            requestedID,
		Module:        "golang.org/x/net",
		FixedVersions: []string{"v0.33.0"},
		AffectedModules: []domain.AffectedModule{
			{
				Module:        "golang.org/x/net",
				FixedVersions: []string{"v0.33.0"},
				AffectedPackages: []domain.AffectedPackage{
					{Path: "golang.org/x/net/http2"},
				},
			},
			{
				Module: "google.golang.org/grpc",
				AffectedVersions: []domain.VersionRange{
					{Introduced: "0", LastAffected: "v1.56.2"},
				},
			},
		},
	}
	model := `{"impact":"HTTP/2 rapid reset","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"golang.org/x/net/http2","symbol":"Server"}}
	]}`
	modelPath := filepath.Join(dir, "model.json")
	if err := os.WriteFile(modelPath, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := &recordingRootCauseResolver{model: &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: "golang.org/x/net/http2", Symbol: "Server",
			Role: domain.RootCauseSink, Mechanism: "HTTP/2 stream reset",
		}},
	}}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			requestedID: vuln,
		}},
		VulnID:     requestedID,
		Resolver:   partialComponentResolver{},
		RCResolver: rc,
		Model:      modelPath,
		CaseDir:    filepath.Join(dir, "cases"),
	})

	if !rc.called {
		t.Fatal("root cause resolution never ran: the partial component fact closed the requested CVE before research (the k8s-44487 early exit)")
	}
	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
	}
	requireAssessmentFailed(t, c, domain.GapUnsupportedNegativeScope)

	// The component fact must survive unchanged.
	if c.Affected == nil {
		t.Fatal("affected result missing")
	}
	if c.Affected.VersionAffected != domain.ClaimFalse || c.Affected.ResolvedVersion != "v0.17.0" {
		t.Fatalf("fixed x/net component fact was lost or rewritten: %+v", c.Affected)
	}
	if len(c.Affected.EvidenceIDs) != 1 || c.Affected.EvidenceIDs[0] != "EV-XNET-VERSION" {
		t.Fatalf("component evidence was lost: %+v", c.Affected.EvidenceIDs)
	}
	if c.Affected.Scope == nil || c.Affected.Scope.RequestedID != requestedID ||
		c.Affected.Scope.Coverage != domain.CoverageKnownOnly {
		t.Fatalf("requested scope was not preserved: %+v", c.Affected.Scope)
	}

	// The other advisory implementation must stay in the model: narrowing
	// to the resolved component is exactly the false-safe mechanism.
	if len(c.Vulnerability.AffectedModules) != 2 {
		t.Fatalf("advisory entries were narrowed to the fixed component: %+v", c.Vulnerability.AffectedModules)
	}

	limitations := strings.Join(c.Affected.Limitations, "\n")
	for _, want := range []string{"partial advisory scope", requestedID, "golang.org/x/net"} {
		if !strings.Contains(limitations, want) {
			t.Fatalf("scope limitation %q does not name %q", limitations, want)
		}
	}

	if c.Verdict != nil {
		t.Fatalf("partial advisory scope produced a verdict: %+v", c.Verdict)
	}
	foundScope := false
	for _, g := range c.AnalysisGaps {
		if g.Code == domain.GapUnsupportedNegativeScope && strings.Contains(g.Message, requestedID) {
			foundScope = true
		}
	}
	if !foundScope {
		t.Fatalf("scope failure does not name the open request %s: %+v", requestedID, c.AnalysisGaps)
	}
}

// sshTerrapin is the podman-48795 advisory shape: an SSH key-exchange
// downgrade whose loaded bundle mentions a TLS floor from the foreign
// libssh2 patch, so the old builder attached it unconditionally.
func sshTerrapin() domain.Vulnerability {
	return domain.Vulnerability{
		ID:      "CVE-2023-48795",
		Module:  "golang.org/x/crypto",
		Summary: "SSH transport prefix truncation (Terrapin) enables a protocol downgrade",
		Description: "Terrapin attacks the SSH key exchange. The foreign libssh2 patch " +
			"also carries a TLS minimum version floor: Go < 1.18.",
		CWE: []string{"CWE-327"},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "golang.org/x/crypto/ssh", Symbol: "handshakeTransport"},
		},
	}
}

func sshRootCause() *domain.RootCauseModel {
	return &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: "golang.org/x/crypto/ssh", Symbol: "handshakeTransport",
			Role: domain.RootCauseSink, Mechanism: "SSH key-exchange prefix truncation",
		}},
	}
}

// tlsMechanismRootCause is the control: the same advisory text DOES declare
// a TLS floor, and a TLS mechanism must still receive it. Without this
// control the SSH assertion could pass by deleting the condition class.
func tlsMechanismRootCause() *domain.RootCauseModel {
	return &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: "crypto/tls", Symbol: "Config",
			Role: domain.RootCauseSink, Mechanism: "TLS protocol downgrade",
		}},
	}
}

func tlsFloorCondition(conds []domain.Condition) *domain.Condition {
	for i := range conds {
		if conds[i].Params["go_version"] != "" {
			return &conds[i]
		}
	}
	return nil
}

func assertNoTLSFloor(t *testing.T, label string, m *domain.ExploitModel) {
	t.Helper()
	if m == nil {
		t.Fatalf("%s: no model", label)
	}
	if cond := tlsFloorCondition(m.MandatoryConditions); cond != nil {
		t.Fatalf("%s: automatically created TLS floor in the conjunction: %+v", label, *cond)
	}
	if cond := tlsFloorCondition(m.SupportingFactors); cond != nil {
		t.Fatalf("%s: automatically created TLS floor among supporting factors: %+v", label, *cond)
	}
}

// llmAugmentedBuilder wires the real LLM-augmented builder against a local
// mock completion endpoint — no live model, no network egress.
func llmAugmentedBuilder(t *testing.T, reply string) *llm.ExploitModelBuilder {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       map[string]string{"role": "assistant", "content": reply},
				"finish_reason": "stop",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	client := llm.NewClient(llm.Config{
		BaseURL: srv.URL, AnalyzeModel: "mock", BuildModel: "mock", Enabled: true,
	})
	return &llm.ExploitModelBuilder{Client: client, Fallback: exploit.Builder{}}
}

func unknownClaims(m *domain.ExploitModel) []domain.Claim {
	var claims []domain.Claim
	for _, cond := range append(append([]domain.Condition{}, m.MandatoryConditions...), m.SupportingFactors...) {
		claims = append(claims, domain.Claim{
			ID: domain.ClaimID("CL-" + string(cond.ID)), ConditionID: cond.ID,
			Result: domain.ClaimUnknown,
		})
	}
	return claims
}

func allTrueAffected(scope *domain.AdvisoryScope) domain.AffectedResult {
	return domain.AffectedResult{
		Scope:           scope,
		ModulePresent:   domain.ClaimTrue,
		ResolvedVersion: "v0.19.0",
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}
}

// TestP0SSHDowngradeCannotCloseOnTLSFloor reproduces podman-48795: the
// legacy CRYPTO_DOWNGRADE pattern attached a mandatory TLS `<1.18` floor to
// an SSH downgrade, and a go.mod minimum / release toolchain of 1.20 then
// produced a verified FALSE that closed the case as NO_EXPLOIT_PATH_FOUND.
func TestP0SSHDowngradeCannotCloseOnTLSFloor(t *testing.T) {
	v := sshTerrapin()
	rc := sshRootCause()

	// The advisory text alone WOULD supply the floor — the SSH mechanism
	// guard, not a missing declaration, is what removes it.
	if bound := exploit.TLSFloorBound(v, rc); bound != "" {
		t.Fatalf("expected the SSH mechanism to suppress the declared floor, got %q", bound)
	}
	control, _ := (exploit.Builder{}).Build(context.Background(), &domain.AnalysisCase{}, v, tlsMechanismRootCause())
	if cond := tlsFloorCondition(control.MandatoryConditions); cond == nil || cond.Params["go_version"] != "<1.18" {
		t.Fatalf("control: a TLS mechanism must still receive the declared floor: %+v", control.MandatoryConditions)
	}

	models := map[string]*domain.ExploitModel{}
	det, _ := (exploit.Builder{}).Build(context.Background(), &domain.AnalysisCase{}, v, rc)
	models["deterministic"] = det

	const reply = `{"impact":"ssh downgrade","mandatory_conditions":[
		{"id":"C-PLATFORM","kind":"PLATFORM_CONDITION","mandatory":true,
		 "description":"legacy TLS floor","params":{"go_version":"<1.18"}}
	]}`
	augmented, lims := llmAugmentedBuilder(t, reply).Build(context.Background(), &domain.AnalysisCase{}, v, rc)
	models["llm-augmented"] = augmented
	if !strings.Contains(strings.Join(lims, "\n"), "rejected") {
		t.Fatalf("the TLS-floor proposal should have been rejected, limitations: %v", lims)
	}

	// Two snapshot variants: go.mod minimum only (release toolchain
	// unknown) and an explicit release toolchain of 1.20.
	products := map[string]domain.ProductSnapshot{
		"minimum-go-1.20": {GoVersion: "go1.22.0", MinimumGoVersion: "1.20"},
		"release-go-1.20": {GoVersion: "go1.22.0", MinimumGoVersion: "1.20", ReleaseGoVersion: "1.20"},
	}
	for name, m := range models {
		assertNoTLSFloor(t, name, m)
		for productName, product := range products {
			c := &domain.AnalysisCase{
				Vulnerability: v,
				Product:       product,
				Affected: func() *domain.AffectedResult {
					res := allTrueAffected(exactScope("GO-2023-48795"))
					return &res
				}(),
				RootCause: rc,
				Exploit:   m,
			}
			// Evaluate the modeled conditions against the snapshot fact,
			// exactly as the pipeline does. With no toolchain condition in
			// the model, neither go.mod minimum nor release toolchain can
			// mint a FALSE claim.
			if _, err := (states.EvaluateConditions{Evaluators: []evaluator.ConditionEvaluator{
				evaluator.Platform{}, evaluator.Presence{},
			}}).Run(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			for _, cl := range c.Claims {
				if cl.ConditionID == "C-PLATFORM" {
					t.Fatalf("%s/%s: TLS floor claim exists: %+v", name, productName, cl)
				}
			}
			got := evalCaseVerdict(c, c.Claims)
			if got.Verdict != domain.VerdictInconclusive {
				t.Fatalf("%s/%s: verdict=%s (%s), want INCONCLUSIVE — no automatically created floor may close the case",
					name, productName, got.Verdict, got.Reason)
			}
		}
	}

	// Harmful path control: with the legacy mandatory floor and its verified
	// FALSE present, the same exact-entry scope WOULD close. This proves the
	// regression is about condition admission, not about disabling NEPF.
	legacy := *det
	legacy.MandatoryConditions = append(append([]domain.Condition{}, det.MandatoryConditions...), domain.Condition{
		ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
		Description: "runtime toolchain permits the advisory-declared legacy TLS floor",
		Params:      map[string]string{"go_version": "<1.18"},
	})
	legacyClaims := append(unknownClaims(det), domain.Claim{
		ID: "CL-C-PLATFORM", ConditionID: "C-PLATFORM", Result: domain.ClaimFalse,
		Falsifier:            domain.FalsifierSnapshotFactMismatch,
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
	})
	if got := evalBareVerdict(allTrueAffected(exactScope("GO-2023-48795")), legacy, legacyClaims); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("legacy TLS-floor control did not close: %s (%s) — the regression would be vacuous", got.Verdict, got.Reason)
	}

	// An explicit optional (supporting) verified FALSE is never a basis for
	// NEPF: it cannot gate the conjunction.
	optional := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			Subjects: []domain.SymbolRef{{Package: "golang.org/x/crypto/ssh", Symbol: "handshakeTransport"}},
		}},
		SupportingFactors: []domain.Condition{{
			ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: false,
			Description: "legacy TLS floor", Params: map[string]string{"go_version": "<1.18"},
		}},
	}
	optionalClaims := []domain.Claim{
		{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimUnknown},
		{
			ID: "CL-C-PLATFORM", ConditionID: "C-PLATFORM", Result: domain.ClaimFalse,
			Falsifier:            domain.FalsifierSnapshotFactMismatch,
			NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		},
	}
	if got := evalBareVerdict(allTrueAffected(exactScope("GO-2023-48795")), optional, optionalClaims); got.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("optional verified FALSE grounded NEPF: %+v", got)
	}
	optionalClaims[0].Result = domain.ClaimTrue
	if got := evalBareVerdict(allTrueAffected(exactScope("GO-2023-48795")), optional, optionalClaims); got.Verdict != domain.VerdictExploitable {
		t.Fatalf("optional FACT must not gate the conjunction: %s (%s)", got.Verdict, got.Reason)
	}
}

// TestP0ReviewerRemovesLegacyTLSBlocker restores the erroneous legacy model
// (mandatory C-PLATFORM next to the SSH reachability condition), runs the
// real REVIEW -> REPAIR -> REVIEW loop with an explicit demote finding, and
// then evaluates the verdict on the repaired model.
func TestP0ReviewerRemovesLegacyTLSBlocker(t *testing.T) {
	platformClaim := domain.Claim{
		ID:          "CL-C-PLATFORM",
		ConditionID: "C-PLATFORM",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierSnapshotFactMismatch,
		EvidenceIDs: []domain.EvidenceID{"EV-PLATFORM-RELEASE"},
		NegativeVerification: &domain.NegativeVerification{
			Status:      domain.NegativeVerified,
			EvidenceIDs: []domain.EvidenceID{"EV-PLATFORM-RELEASE-NV"},
			Notes:       "release toolchain 1.20 is above the legacy floor",
		},
	}
	claimBefore := platformClaim
	c := &domain.AnalysisCase{
		Vulnerability: sshTerrapin(),
		Product: domain.ProductSnapshot{
			Repository: "example.com/podman", Commit: "6a65597",
			GoVersion: "go1.22.0", MinimumGoVersion: "1.20", ReleaseGoVersion: "1.20",
		},
		Affected: func() *domain.AffectedResult {
			res := allTrueAffected(exactScope("GO-2023-48795"))
			return &res
		}(),
		RootCause: sshRootCause(),
		Exploit: &domain.ExploitModel{
			Class:  string(exploit.ClassCryptoDowngrade),
			Impact: "SSH prefix truncation",
			MandatoryConditions: []domain.Condition{
				{
					ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
					Subjects: []domain.SymbolRef{{Package: "golang.org/x/crypto/ssh", Symbol: "handshakeTransport"}},
				},
				{
					ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
					Description: "runtime toolchain permits the advisory-declared legacy TLS floor",
					Params:      map[string]string{"go_version": "<1.18"},
				},
			},
		},
		Claims: []domain.Claim{
			{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimUnknown},
			platformClaim,
		},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{MaxReviewIterations: 2},
		},
	}

	// First erroneous decision: the legacy model closes before review.
	pre := evalCaseVerdict(c, c.Claims)
	if pre.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("legacy model did not reproduce the false-safe closure: %s (%s)", pre.Verdict, pre.Reason)
	}
	if len(pre.ConditionIDs) != 1 || pre.ConditionIDs[0] != "C-PLATFORM" {
		t.Fatalf("legacy closure must rest on C-PLATFORM: %v", pre.ConditionIDs)
	}

	review := states.Review{
		Reviewer: demoteOnceReviewer{
			target:  "C-PLATFORM",
			problem: "legacy TLS floor does not gate an SSH key-exchange downgrade",
		},
		Evaluator: evaluator.VerdictEvaluator{},
	}
	tr, err := review.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateRepairAnalysis {
		t.Fatalf("next=%s want REPAIR_ANALYSIS", tr.Next)
	}
	tr, err = (states.RepairAnalysis{}).Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next=%s want re-REVIEW", tr.Next)
	}
	tr, err = review.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT after the repaired model is accepted", tr.Next)
	}
	if len(c.Reviews) != 2 || c.Reviews[1].Result != domain.ReviewAccept {
		t.Fatalf("second review should accept the repaired model: %+v", c.Reviews)
	}

	// The repair is a necessity change, not a fact rewrite.
	if hasConditionID(c.Exploit.MandatoryConditions, "C-PLATFORM") {
		t.Fatalf("demoted condition returned to the conjunction: %+v", c.Exploit.MandatoryConditions)
	}
	if countCondition(c.Exploit.SupportingFactors, "C-PLATFORM") != 1 {
		t.Fatalf("C-PLATFORM must appear exactly once among supporting factors: %+v", c.Exploit.SupportingFactors)
	}
	claimAfter := findClaimT(t, c.Claims, "C-PLATFORM")
	if !reflect.DeepEqual(claimBefore, claimAfter) {
		t.Fatalf("demotion rewrote the verified platform claim:\nbefore=%+v\nafter=%+v", claimBefore, claimAfter)
	}
	lims := strings.Join(c.EvidenceGraph.Limitations, "\n")
	for _, want := range []string{"C-PLATFORM", "REV-1", "demoted to supporting"} {
		if !strings.Contains(lims, want) {
			t.Fatalf("repair limitation %q does not name %q", lims, want)
		}
	}
	if c.Verdict != nil {
		t.Fatalf("repair must not set the verdict: %+v", c.Verdict)
	}

	// Final evaluation on the repaired model: the remaining UNKNOWN keeps
	// the case INCONCLUSIVE and no verdict names the removed blocker.
	if tr, err = (states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateBuildReport {
		t.Fatalf("next=%s want BUILD_REPORT", tr.Next)
	}
	if c.Verdict != nil {
		t.Fatalf("repaired verdict=%+v want none: an unresolved mandatory condition must FAIL", c.Verdict)
	}
	for _, gap := range c.AnalysisGaps {
		if gap.ConditionID == "C-PLATFORM" {
			t.Fatalf("analysis gap still names the demoted blocker: %+v", gap)
		}
	}
	if !hasAnalysisGap(c, domain.GapReachabilityProofIncomplete) {
		t.Fatalf("repaired failure lacks a reachability cause: %+v", c.AnalysisGaps)
	}

	// Control: confirming the remaining mandatory condition does not restore
	// the earlier NEPF — the TLS floor no longer gates the conjunction.
	confirmed := false
	for i := range c.Claims {
		if c.Claims[i].ConditionID == "C-REACH" {
			c.Claims[i].Result = domain.ClaimTrue
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatal("C-REACH claim missing before the control evaluation")
	}
	if tr, err = (states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if c.Verdict.Verdict == domain.VerdictNoExploitPathFound || c.Verdict.Verdict == domain.VerdictNotAffected {
		t.Fatalf("prior NEPF survived the repair: %+v", c.Verdict)
	}
	if c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("confirmed remaining condition verdict=%s want EXPLOITABLE", c.Verdict.Verdict)
	}
}
