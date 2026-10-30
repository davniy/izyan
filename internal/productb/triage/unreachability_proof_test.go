package triage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
	canonicaldomain "github.com/davniy/izyan/internal/domain"
	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/productb/vulnerability"
)

// kernelSession runs the real unreachability tool against the mini fixture:
// the observation and its archive record come from the production code
// paths, not from a hand-built payload.
func kernelSession(t *testing.T) (*evidencetools.Session, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "unreachability-session"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := evidencetools.NewSession(evidencetools.SessionConfig{
		SnapshotRoot: root, Audit: evidencetools.NopAudit{}, GOOS: "darwin", GOARCH: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, root
}

// kernelObservation records the tool's observation the way the attempt
// archive does and returns the record.
func kernelObservation(t *testing.T, s *evidencetools.Session, args json.RawMessage) RecordedObservation {
	t.Helper()
	ctx := context.Background()
	client, err := s.Connect(ctx)
	if err != nil {
		t.Fatalf("session connect: %v", err)
	}
	defer client.Close()
	d := &DeterministicTools{
		Caller:  ClientCaller{Client: client},
		Catalog: CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog()),
	}
	store := NewRunObservationStore("run-1", 1)
	d.ObservationStore = store
	obs := d.Call(ctx, evidencetools.SymbolUnreachabilityTool, args)
	if obs.Status != ToolStatusOK {
		t.Fatalf("tool call = %+v", obs)
	}
	recorded := store.Observations()
	if len(recorded) != 1 || recorded[0].Tool != evidencetools.SymbolUnreachabilityTool {
		t.Fatalf("archive = %+v", recorded)
	}
	return recorded[0]
}

// unreachSubjects is the fixture advisory's declared vulnerable symbol set.
func unreachSubjects() []FalsifierSubject {
	return []FalsifierSubject{
		{Package: "example.com/sessiondep/vulnlib", Symbol: "OrphanA"},
		{Package: "example.com/sessiondep/vulnlib", Symbol: "OrphanB"},
	}
}

// unreachArgs renders the read-only symbol-unreachability request the
// fixture session answers.
func unreachArgs(t *testing.T) json.RawMessage {
	t.Helper()
	type ref struct {
		Package string `json:"package"`
		Symbol  string `json:"symbol"`
	}
	subjects := make([]ref, 0, len(unreachSubjects()))
	for _, s := range unreachSubjects() {
		subjects = append(subjects, ref{Package: s.Package, Symbol: s.Symbol})
	}
	raw, err := json.Marshal(struct {
		Module   string `json:"module"`
		Subjects []ref  `json:"subjects"`
	}{Module: "example.com/sessiondep", Subjects: subjects})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// stage0ForKernel grounds a Stage 0 result on the snapshot the session
// recorded: the module is present at an affected version and the advisory
// declares the two orphan symbols.
func stage0ForKernel(obs RecordedObservation, s *evidencetools.Session) Stage0Result {
	s0 := goodStage0()
	// The deadness question is evaluated without a deployment perimeter: a
	// lowering rule firing on unrelated exposure would obscure whether the
	// observation itself minted a reduction.
	s0.Materials.Deploy = nil
	s0.Snapshot.ContentHash = obs.SnapshotHash
	build := canonicaldomain.EffectiveBuildContext(s.Build)
	s0.Materials.PackageBuild = &build
	s0.PackageCheck.Class = CheckAffectedRange
	s0.PackageCheck.ResolvedPath = "example.com/sessiondep"
	s0.PackageCheck.ClaimedVersion = "v0.5.0"
	s0.PackageCheck.ResolvedVersion = "v0.5.0"
	vuln := domain.Vulnerability{
		ID:      "CVE-2099-0001",
		Module:  "example.com/sessiondep",
		Package: "example.com/sessiondep/vulnlib",
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/sessiondep/vulnlib", Symbol: "OrphanA"},
			{Package: "example.com/sessiondep/vulnlib", Symbol: "OrphanB"},
		},
	}
	projection := AdvisoryProjectionFromVulnerability(vuln)
	s0.Resolution = &AdvisoryResolution{
		Vulnerability: &vuln,
		Projection:    projection,
		Record: vulnerability.FrozenAdvisory{
			Source: "osv", SHA256: strings.Repeat("ab", 32), ResolvedID: "CVE-2099-0001",
		},
	}
	return s0
}

// TestUnreachabilityObservationApprovalRequiresClosedKernel: every way the
// kernel can stay open — limitations, partial completeness, an error
// status, a foreign snapshot, a missing build context, an unclosed
// checklist or a foreign tool — is rejected by the observation contract the
// proposal verifier still applies. No proof exists without a complete,
// run-bound observation.
func TestUnreachabilityObservationApprovalRequiresClosedKernel(t *testing.T) {
	s, _ := kernelSession(t)
	base := kernelObservation(t, s, unreachArgs(t))
	s0 := stage0ForKernel(base, s)
	if approved, why := UnreachabilityObservationApproved(base, s0); !approved {
		t.Fatalf("complete fixture observation rejected: %s", why)
	}

	cases := []struct {
		name   string
		mutate func(o *RecordedObservation)
	}{
		{name: "open gap in the kernel", mutate: func(o *RecordedObservation) {
			o.Payload = json.RawMessage(`{"data":{"result":{"complete":true,"declaration_complete":true,"limitations":["dep call site unverified"]}}}`)
		}},
		{name: "partial", mutate: func(o *RecordedObservation) { o.Completeness = evidencetools.CompletenessPartial }},
		{name: "error status", mutate: func(o *RecordedObservation) { o.Status = ToolStatusError }},
		{name: "other snapshot", mutate: func(o *RecordedObservation) { o.SnapshotHash = "sha256:another" }},
		{name: "no build context", mutate: func(o *RecordedObservation) { o.BuildContextHash = "" }},
		{name: "kernel did not close", mutate: func(o *RecordedObservation) {
			o.Payload = json.RawMessage(`{"data":{"result":{"complete":false,"declaration_complete":true}}}`)
		}},
		{name: "declarations unresolved", mutate: func(o *RecordedObservation) {
			o.Payload = json.RawMessage(`{"data":{"result":{"complete":true,"declaration_complete":false}}}`)
		}},
		{name: "unparseable payload", mutate: func(o *RecordedObservation) { o.Payload = json.RawMessage(`not-json`) }},
		{name: "foreign tool", mutate: func(o *RecordedObservation) { o.Tool = "verify_code_absence" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := base
			obs.EvidenceRefs = append([]string(nil), base.EvidenceRefs...)
			tc.mutate(&obs)
			approved, why := UnreachabilityObservationApproved(obs, s0)
			if approved {
				t.Fatalf("open observation approved: %+v", obs)
			}
			if why == "" {
				t.Fatalf("open observation carries no rejection reason: %+v", obs)
			}
		})
	}
}

// TestFalsifierVerifierAdmitsKernelBackedLocusFunction: an agent proposal of
// the unreachability kind is admissible exactly when the kernel's own
// complete observation backs it — the proposal shapes the claim, the checker
// decides it.
func TestFalsifierVerifierAdmitsKernelBackedLocusFunction(t *testing.T) {
	s, _ := kernelSession(t)
	obs := kernelObservation(t, s, unreachArgs(t))
	s0 := stage0ForKernel(obs, s)
	subjects := unreachSubjects()

	src := sourceFixture()
	src.condition.Kind = FalsifierLocusFunctionAbsent
	src.condition.ExpectedSubjects = append([]FalsifierSubject(nil), subjects...)
	src.condition.SnapshotHash = obs.SnapshotHash
	src.condition.BuildContextHash = obs.BuildContextHash
	src.condition.DefectSemantics = &canonicaldomain.DefectSemanticsContract{Mode: canonicaldomain.DefectSemanticsDefectiveCheck, RecordID: "CVE-2099-0001", Check: canonicaldomain.SymbolRef{Package: subjects[0].Package, Symbol: subjects[0].Symbol}}

	in, _ := verifierFixture(FalsifierLocusFunctionAbsent, src)
	in.Stage0 = s0
	in.Observations = []RecordedObservation{obs}
	in.Proposals[0].EvidenceRefs = []string{obs.ID}
	in.Proposals[0].Subjects = append([]FalsifierSubject(nil), subjects...)
	in.Assessment.Claims[0].EvidenceRefs = []string{obs.ID}
	in.FactValidation.References = []ReferenceCheck{{EvidenceID: obs.ID, Status: FactValid, SnapshotHash: obs.SnapshotHash}}
	proof := runProof(t, in, src)
	if proof.Status != FalsifierVerified || proof.Basis != BasisCheckerVerified {
		t.Fatalf("kernel-backed proposal not admitted: %+v", proof)
	}
	encoded, err := json.Marshal(proof.Coverage)
	if err != nil { t.Fatal(err) }
	var replay FalsifierCoverage
	if err := json.Unmarshal(encoded, &replay); err != nil { t.Fatal(err) }
	if err := validateAdmittingUnreachabilityCoverage(replay); err != nil { t.Fatalf("full persisted replay: %v", err) }
	for _, name := range []string{"missing-payload", "foreign-build", "missing-contract", "omitted-check"} {
		t.Run(name, func(t *testing.T) {
			var bad FalsifierCoverage
			_ = json.Unmarshal(encoded, &bad)
			switch name {
			case "missing-payload": bad.UnreachabilityPayloads = nil
			case "foreign-build": bad.UnreachabilityBuild.GOOS = "foreign"
			case "missing-contract": bad.DeadnessContract = nil
			case "omitted-check": bad.DeadnessContract.Mode = canonicaldomain.DefectSemanticsOmittedCheck; bad.DeadnessContract.Pipeline = &canonicaldomain.SymbolRef{Package: subjects[0].Package, Symbol: "LiveOmissionSite"}
			}
			if err := validateAdmittingUnreachabilityCoverage(bad); err == nil { t.Fatal("invalid persisted proof admitted") }
		})
	}

	// Without the kernel observation the same proposal stays unanswered.
	in.Observations = nil
	proof = runProof(t, in, src)
	if proof.Status == FalsifierVerified {
		t.Fatalf("proposal admitted without the kernel observation: %+v", proof)
	}
}

// TestDeadnessObservationDoesNotMintProof: a complete symbol-unreachability
// observation is a valid read-only deadness observation, so the human action
// stands. Nothing in the product converts it into a falsifier proof on its
// own: without an admitted proposal carrying it, the machine disposition
// stays UNCHANGED and the package publishes no reduction.
func TestDeadnessObservationDoesNotMintProof(t *testing.T) {
	s, _ := kernelSession(t)
	obs := kernelObservation(t, s, unreachArgs(t))
	s0 := stage0ForKernel(obs, s)

	approved, why := UnreachabilityObservationApproved(obs, s0)
	if !approved {
		t.Fatalf("complete deadness observation was rejected: %s", why)
	}

	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), s0, goodAssessment(), completeValidation(),
		EvidenceInput{Observations: []RecordedObservation{obs}})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.ProposedAction.Kind != HumanActionClose {
		t.Fatalf("human action = %s, want CLOSE", pkg.ProposedAction.Kind)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged || pkg.MachineDisposition.Automation == AutomationAllow {
		t.Fatalf("complete deadness observation minted a machine reduction: %+v", pkg.MachineDisposition)
	}
	if len(pkg.FalsifierProofs) != 0 {
		t.Fatalf("deadness observation produced falsifier proofs: %+v", pkg.FalsifierProofs)
	}
}
