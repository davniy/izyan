package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// implAxisAdvisory declares the implscope fixture's dep module affected
// and attributes the vulnerable implementation to the BSD/Solaris
// platforms — the generic case-04 shape. The proposal's quoted span is a
// verbatim substring of this summary.
const implAxisAdvisory = `{
  "id": "GO-TEST-IMPL1",
  "summary": "the host identity read in impldep/host resolves kern.hostid on BSD and Solaris systems",
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"ecosystem": "Go", "name": "example.com/impldep"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.1"}]}],
    "ecosystem_specific": {"imports": [{"path": "example.com/impldep/host"}]}
  }]
}`

// implscopeRoot gives each test an isolated copy of the generic
// implementation-scope fixture. The lane hashes its snapshot both before
// investigation and again at proof admission, so other tests must not be
// able to change its source tree between those checks.
func implscopeRoot(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "implscope"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	return root
}

// implAxisProposal returns the admitted hypothesis: the vulnerable
// implementation is the BSD-gated Read in impldep/host.
func implAxisProposal() domain.ImplementationLocusProposal {
	return domain.ImplementationLocusProposal{
		ID: "locus-host-bsd", Quality: domain.QualityLLMInferred,
		Module: "example.com/impldep", Version: "v1.2.0",
		Package:             "example.com/impldep/host",
		File:                "host_bsd.go",
		Function:            "Read",
		Marker:              "kern.hostid",
		BuildExpression:     "freebsd || openbsd",
		GOOS:                []string{"freebsd", "openbsd", "solaris"},
		AdvisoryEvidenceRef: "adv:GO-TEST-IMPL1",
		AdvisoryQuotedSpan:  "kern.hostid on BSD and Solaris systems",
	}
}

// writeProposalArtifactFile pins an implementation-locus-proposals/1
// document bound to the exact advisory bytes.
func writeProposalArtifactFile(t *testing.T, dir, advPath string, members ...domain.ImplementationLocusProposal) string {
	t.Helper()
	raw, err := os.ReadFile(advPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	doc := map[string]any{
		"schema":          ImplementationProposalsSchema,
		"advisory_sha256": hex.EncodeToString(sum[:]),
		"proposals":       members,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "proposals.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// implAxisLaneRuns the real deterministic lane over the implscope
// fixture with the operator target, assumptions document and proposal
// artifact the caller supplies. The lane returns its result; out names
// the report output dir for validation.
func implAxisLane(t *testing.T, root string, mutate func(*LaneOptions)) (*LaneResult, string) {
	t.Helper()
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(implAxisAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	o := LaneOptions{
		CVE: "GO-TEST-IMPL1", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-impl",
		GOOS: "linux", GOARCH: "amd64",
		Timeout: 90 * time.Second,
	}
	if mutate != nil {
		mutate(&o)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, o)
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	return lane, out
}

// implAxisAdvisoryPath rewrites the advisory document once for the
// proposal artifact pin — both the lane and the artifact must agree on
// the identical frozen bytes.
func implAxisAdvisoryPath(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(p, []byte(implAxisAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The case-04 shape end to end: an admitted locus proposal names the
// BSD-gated vulnerable implementation, the product-scope
// supported-targets assumption covers the recorded operator target, and
// the lane's own implementation-axis observation proves the marker
// absent from every selected alternate. The axis resolves FALSE and the
// standard applicability route yields NOT_AFFECTED — never through
// BuildRelevant.
func TestLaneImplementationAxisAbsentClosesNotAffected(t *testing.T) {
	dir := t.TempDir()
	targets := assumptionsUnit("ASM-IMPL-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	assumpPath := writeAssumptionsDoc(t, dir, "assumptions.json", assumptionsUnitDoc(targets))
	advPath := implAxisAdvisoryPath(t, dir)
	proposalPath := writeProposalArtifactFile(t, dir, advPath, implAxisProposal())

	lane, out := implAxisLane(t, implscopeRoot(t), func(o *LaneOptions) {
		o.DeclaredAssumptions = assumpPath
		o.ImplementationLocusProposals = proposalPath
		// The artifact proposal binds the identical advisory bytes:
		o.AdvisoryFile = advPath
	})

	if lane.ImplementationAxis == nil {
		t.Fatal("lane implementation axis record missing")
	}
	if lane.ImplementationAxis.ObservationID == "" {
		t.Fatal("lane implementation axis observation id missing")
	}
	af := lane.Affected
	if af.VulnerableImplementationPresent != domain.ClaimFalse {
		for _, o := range lane.Observations {
			if o.Tool == implementationAxisTool {
				raw, _ := json.Marshal(o.Data)
				t.Logf("implementation-axis data: %s", raw)
			}
		}
		t.Fatalf("vulnerable_implementation_present = %s (affected = %+v)",
			af.VulnerableImplementationPresent, af)
	}
	if af.PackagePresent != domain.ClaimTrue || af.BuildRelevant != domain.ClaimTrue {
		t.Fatalf("package/build = %s/%s — the package stays linked; the axis is not BuildRelevant",
			af.PackagePresent, af.BuildRelevant)
	}
	if af.ImplementationTargetScope != domain.AssumptionScopeProduct {
		t.Fatalf("implementation target scope = %q", af.ImplementationTargetScope)
	}
	if af.ImplementationLocus == "" {
		t.Fatal("implementation locus is empty on a FALSE axis")
	}
	foundAssumption := false
	for _, id := range af.AssumptionIDs {
		if id == targets.ID {
			foundAssumption = true
		}
	}
	if !foundAssumption {
		t.Fatalf("assumption ids %v lack %s", af.AssumptionIDs, targets.ID)
	}

	// The dedicated lane observation carries the axis intake and the
	// FALSE result — the earlier affected-resolve record stays pristine.
	var obsFound bool
	for _, o := range lane.Observations {
		if o.Tool == implementationAxisTool {
			obsFound = true
			if o.Completeness != evidencetools.CompletenessComplete {
				t.Fatalf("implementation-axis completeness = %s", o.Completeness)
			}
			raw, _ := json.Marshal(o.Data)
			for _, want := range []string{`"admitted":1`, "VERIFIED_ABSENT", "kern.hostid"} {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("implementation-axis data lacks %q: %s", want, raw)
				}
			}
		}
	}
	if !obsFound {
		t.Fatal("implementation-axis lane observation missing")
	}

	// The standard applicability route decides NOT_AFFECTED.
	dec, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane})
	if err != nil {
		t.Fatalf("VerifyDecision: %v", err)
	}
	if dec.Verdict != domain.VerdictNotAffected {
		t.Fatalf("decision verdict = %s reason = %q", dec.Verdict, dec.Reason)
	}

	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, Decision: &dec,
		RunID: "impl-axis", StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	pa := r.ProductApplicability
	if pa.VulnerableImplementationPresent != "FALSE" ||
		pa.ImplementationTargetScope != "product" ||
		pa.ImplementationLocus == "" {
		t.Fatalf("product_applicability axis = %+v", pa)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("report with FALSE implementation axis invalid:\n%v", err)
	}
}

// Control: when the marker also appears in a selected alternate
// implementation file, the same proposal verifies PRESENT — the
// implementation axis can never close and the decision stays
// INCONCLUSIVE, never NOT_AFFECTED.
func TestLaneImplementationAxisMarkerInSelectedStaysInconclusive(t *testing.T) {
	dir := t.TempDir()
	// Copy the fixture and embed the marker in the selected Linux
	// implementation: a comment inside Read's body is enough — the
	// verifier scans selected alternate files for the marker text.
	root := filepath.Join(dir, "snap")
	if err := os.CopyFS(root, os.DirFS(implscopeRoot(t))); err != nil {
		t.Fatal(err)
	}
	linuxImpl := filepath.Join(root, "impldep", "host", "host_linux.go")
	src, err := os.ReadFile(linuxImpl)
	if err != nil {
		t.Fatal(err)
	}
	marked := strings.Replace(string(src),
		"func Read() string { return \"machine-id\" }",
		"func Read() string { /* kern.hostid */ return \"machine-id\" }", 1)
	if marked == string(src) {
		t.Fatal("fixture substitution did not apply")
	}
	if err := os.WriteFile(linuxImpl, []byte(marked), 0o644); err != nil {
		t.Fatal(err)
	}

	targets := assumptionsUnit("ASM-IMPL-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	assumpPath := writeAssumptionsDoc(t, dir, "assumptions.json", assumptionsUnitDoc(targets))
	advPath := implAxisAdvisoryPath(t, dir)
	proposalPath := writeProposalArtifactFile(t, dir, advPath, implAxisProposal())

	lane, out := implAxisLane(t, root, func(o *LaneOptions) {
		o.DeclaredAssumptions = assumpPath
		o.ImplementationLocusProposals = proposalPath
		o.AdvisoryFile = advPath
	})

	if lane.Affected.VulnerableImplementationPresent != domain.ClaimTrue {
		t.Fatalf("vulnerable_implementation_present = %s want TRUE (marker hit on a selected alternate)",
			lane.Affected.VulnerableImplementationPresent)
	}
	dec, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane})
	if err != nil {
		t.Fatalf("VerifyDecision: %v", err)
	}
	if dec.Verdict == domain.VerdictNotAffected {
		t.Fatalf("marker-bearing selected alternate must not close: %s", dec.Verdict)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, Decision: &dec,
		RunID: "impl-axis-ctl", StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if err := Validate(r, out); err != nil {
		t.Fatalf("control report invalid:\n%v", err)
	}
}
