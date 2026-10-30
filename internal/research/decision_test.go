package research

import (
	"context"
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

//go:embed testdata/r6-recorded-symbol-unreachable.json
var recordedSymbolAuthorityFixture embed.FS

const testModule = "example.com/dep"
const testPackage = "example.com/dep/vuln"
const testRef = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// fullRecordScope is the exact-entry scope with a valid full-record census over
// the given original affected[] entries: every entry is recorded, represented
// and bound to the advisory identity, so the structural gate admits it.
func fullRecordScope(id string, entries ...domain.RecordEntry) *domain.AdvisoryScope {
	inventory := &domain.RecordInventory{
		AdvisoryID:         id,
		DocumentDigest:     "sha256:" + strings.Repeat("a", 64),
		AffectedEntryCount: len(entries),
	}
	for i, entry := range entries {
		entry.Index = i
		inventory.Entries = append(inventory.Entries, entry)
		inventory.RepresentedRefs = append(inventory.RepresentedRefs, i)
	}
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind:            domain.ScopeAdvisoryEntries,
		Coverage:        domain.CoverageComplete,
		Basis:           "complete declared Go entries of the exact loaded advisory record; not CVE-wide coverage",
		RecordExtent:    domain.RecordExtentFullRecord,
		RecordInventory: inventory,
	}
}

// exactAdvisoryScope is the scope the intake binds for an exact
// GO-/GHSA- advisory identifier: the loaded record's declared Go
// entries are complete for that requested identity, so its negatives
// may close it. The structural evidence (extent + census) is required —
// COMPLETE alone no longer authorizes a closure.
func exactAdvisoryScope(id string) *domain.AdvisoryScope {
	return fullRecordScope(id, domain.RecordEntry{Ecosystem: "Go", Module: testModule})
}

// projectionScope is an exact GO- identity whose loaded record is a Go
// projection of a broader document: the represented Go entry is complete for
// itself, but the record was reduced before the lane saw it, so no negative
// over the requested advisory identity may close.
func projectionScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageKnownOnly,
		Basis:        "loaded record reduced to its Go projection",
		RecordExtent: domain.RecordExtentGoProjection,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("b", 64),
			AffectedEntryCount: 2,
			Entries: []domain.RecordEntry{
				{Index: 0, Ecosystem: "Go", Module: testModule},
				{Index: 1, Ecosystem: "Maven", Module: "com.example:dep"},
			},
			RepresentedRefs: []int{0},
			OmittedRefs:     []int{1},
		},
	}
}

// inventorylessScope claims a full record with COMPLETE coverage but carries
// no census at all: the assertion is unbacked, so it fails closed.
func inventorylessScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageComplete,
		Basis:        "complete entry set asserted without structural evidence",
		RecordExtent: domain.RecordExtentFullRecord,
	}
}

// inconsistentScope claims a full record but its census contradicts itself —
// two declared entries and one recorded entry — so the evidence is malformed
// and can never authorize a closure.
func inconsistentScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageComplete,
		Basis:        "census contradicts its own extent",
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("c", 64),
			AffectedEntryCount: 2,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: testModule}},
			RepresentedRefs:    []int{0},
		},
	}
}

// extentRefusalScopes are the structural scope refusals every negative route
// must inherit: a reduced (Go-projection) record, a full-record claim with no
// census, and a self-contradicting census. None of them is derived from
// Coverage — the structural evidence alone decides.
func extentRefusalScopes(id string) map[string]*domain.AdvisoryScope {
	return map[string]*domain.AdvisoryScope{
		"go-projection":          projectionScope(id),
		"absent-inventory":       inventorylessScope(id),
		"inconsistent-inventory": inconsistentScope(id),
	}
}

// partialCVEScope is a CVE-identified request resolved to one loaded
// advisory record: the record's known Go entries are all that was
// checked, so the CVE's remaining implementations are outside the
// resolved scope and no negative may close it.
func partialCVEScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-0001",
		Kind:     domain.ScopeCVE,
		Coverage: domain.CoverageKnownOnly,
		Basis:    "loaded record supplies known Go advisory entries only",
	}
}

// decisionLane builds a fully-applicable lane: the advisory declares a
// single Go entry with one package and one symbol, the applicability
// chain is complete, and the intake bound the exact entry's complete
// scope (the ordinary closing baseline).
func decisionLane(version domain.ClaimResult) *LaneResult {
	pkg := testPackage
	snap := domain.ProductSnapshot{
		Repository: "/test/lane", Commit: "lane-commit",
		GOOS: "linux", GOARCH: "amd64",
	}
	snap.Target = &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	build := domain.EffectiveBuildContext(snap)
	pkgList := domain.Evidence{
		ID: "EV-LANE-PKGS", Kind: domain.EvidencePackageList, Quality: domain.QualityDeterministic,
		BuildContext: &build,
		PackageList:  &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./..."},
		Content:      `{"ImportPath":"example.com/dep/vuln"}`,
	}
	return &LaneResult{
		ContentHash:      "snapshot-hash",
		Snapshot:         snap,
		AffectedEvidence: []domain.Evidence{pkgList},
		Advisory: AdvisoryRecord{
			Vuln: &domain.Vulnerability{
				ID:               "GO-TEST-0001",
				Module:           testModule,
				Package:          testPackage,
				AffectedPackages: []domain.AffectedPackage{{Path: testPackage}},
				AffectedSymbols:  []domain.SymbolRef{{Package: testPackage, Symbol: "Sink"}},
			},
			Impls: []AffectedImplementation{{ID: "adv-01", Module: testModule, Package: &pkg, Symbols: []string{"Sink"}, Binding: BindExact}},
		},
		Affected: domain.AffectedResult{
			Scope:           exactAdvisoryScope("GO-TEST-0001"),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: version,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
	}
}

// decisionProposal proposes the build-closure falsifier at declared
// granularity: the build-closure route is package/module-identity exact,
// so it never carries a symbol.
func decisionProposal(kind domain.FalsifierKind) *FalsifierProposal {
	return &FalsifierProposal{Kind: kind, ConditionID: "condition-1", Module: testModule, Package: testPackage, Statement: "the condition is falsified", Scope: "complete product closure"}
}

func decisionObservation(tool string, data any) *evidencetools.Observation {
	return &evidencetools.Observation{
		ID: "OBS-1", Tool: tool, Fact: "closed check", Scope: "paired product and test build closures",
		Completeness: evidencetools.CompletenessComplete, ToolStatus: evidencetools.StatusOK,
		EvidenceRefs: []string{testRef}, Data: data,
		ScopeDetails: &evidencetools.ScopeDetails{
			SnapshotHash: "snapshot-hash", CoverageRule: "paired go list closures fully decoded",
			BuildContext: &evidencetools.BuildContext{GOOS: "linux", GOARCH: "amd64"},
		},
	}
}

// vendorScopeObservation mints a usage-scope observation recorded by the
// offline vendor/source derivation: the same closed-scope contract plus
// the vendor_mode=true build context it was derived under.
func vendorScopeObservation(data any) *evidencetools.Observation {
	o := decisionObservation(evidencetools.UsageScopeTool, data)
	o.ScopeDetails.BuildContext.VendorMode = true
	o.ScopeDetails.CoverageRule = "vendor/modules.txt+source-imports closure"
	return o
}

// vendorAbsentDataFor is the accepted vendor-inventory proof shape: a
// complete offline classification reporting the target unknown with the
// VERIFIED_VENDOR_INVENTORY marker and full derivation provenance.
func vendorAbsentDataFor(module, pkg string) evidencetools.UsageScopeData {
	return evidencetools.UsageScopeData{
		Module: module, Package: pkg,
		UsageScope:                 string(UsageScopeUnknown),
		ProductAbsenceVerification: ProductAbsenceVerificationVendorInventory,
		ClosureSource:              affected.VendorClosureSource,
		ClosureSemantics:           affected.ClosureSemanticsProductAllPackages,
		CheckScope:                 "closed vendor/source build closure",
	}
}

// decisionModuleLane builds a lane whose advisory declares a single
// module-only entry — the granularity a VERIFIED_VENDOR_INVENTORY
// module-level subject binds to.
func decisionModuleLane(version domain.ClaimResult) *LaneResult {
	lane := decisionLane(version)
	lane.Snapshot.VendorMode = true
	lane.Advisory.Vuln = &domain.Vulnerability{
		AffectedModules: []domain.AffectedModule{{Module: testModule}},
	}
	lane.Advisory.Impls = []AffectedImplementation{{ID: "adv-01", Module: testModule, Binding: BindExact}}
	return rebindLaneEvidence(lane)
}

// rebindLaneEvidence re-stamps the lane's inventory records with the current
// lane snapshot after a fixture mutates it (e.g. VendorMode): the fixture
// records describe the same build, so their measurement identity must follow
// the snapshot the decision will compare against.
func rebindLaneEvidence(l *LaneResult) *LaneResult {
	build := domain.EffectiveBuildContext(l.Snapshot)
	for i := range l.AffectedEvidence {
		if l.AffectedEvidence[i].Kind == domain.EvidencePackageList {
			l.AffectedEvidence[i].BuildContext = &build
		}
	}
	return l
}

// testArgs are the declared request arguments for the proposed
// subject — the audit record the session writes must carry the same
// canonical bytes.
func testArgs() json.RawMessage {
	return json.RawMessage(`{"module":"` + testModule + `","package":"` + testPackage + `"}`)
}

func decisionTrace(obs ...*evidencetools.Observation) *VerificationTrace {
	tr := &VerificationTrace{Complete: true}
	for i, o := range obs {
		if i > 0 && o.ID == obs[0].ID {
			cp := *o
			cp.ID = "OBS-" + string(rune('1'+i))
			o = &cp
		}
		tr.Requests = append(tr.Requests, VerificationRequest{ID: "check-" + string(rune('1'+i)), Tool: o.Tool, Arguments: testArgs(), ConditionID: "condition-1", Purpose: "probe"})
		tr.Observations = append(tr.Observations, o)
	}
	return tr
}

// decisionAudit builds the session audit records the persistence layer
// would hold for tr — one record per request/observation pair carrying
// the declared arguments and the returned observation verbatim. It is
// the test-side mirror of what EvidenceSession buffers during the
// audited call path.
func decisionAudit(tr *VerificationTrace) []evidencetools.AuditRecord {
	recs := make([]evidencetools.AuditRecord, 0, len(tr.Observations))
	for i, o := range tr.Observations {
		if o == nil {
			continue
		}
		// The session records its own observation copy — deep-copy so
		// later mutations of the trace's copy (as the P2-C regression
		// exercises) cannot leak into the independent pins.
		b, err := json.Marshal(o)
		if err != nil {
			panic(err)
		}
		var copy evidencetools.Observation
		if err := json.Unmarshal(b, &copy); err != nil {
			panic(err)
		}
		rec := evidencetools.AuditRecord{Tool: o.Tool, Observation: &copy}
		if i < len(tr.Requests) {
			rec.Args = tr.Requests[i].Arguments
		}
		recs = append(recs, rec)
	}
	return recs
}

// decisionInput wires a lane/proposal/trace with the persistence index
// VerifyDecision needs to resolve proof-observation evidence refs. The
// index comes only from the independently built audit records — never
// from the trace's own EvidenceRefs — exactly like the CLI builds it
// from the drained session audit.
func decisionInput(lane *LaneResult, p *FalsifierProposal, tr *VerificationTrace) DecisionInput {
	return DecisionInput{Lane: lane, Proposal: p, Trace: tr,
		ObservationIndex: VerificationObservationIndex(tr, decisionAudit(tr))}
}

// absentData is the only accepted proof shape: a complete paired
// build-closure classification reporting the target test-only with a
// verified product-absence half.
func absentData() evidencetools.UsageScopeData {
	return absentDataFor(testModule, testPackage)
}

func absentDataFor(module, pkg string) evidencetools.UsageScopeData {
	return evidencetools.UsageScopeData{
		Module: module, Package: pkg,
		UsageScope:                 string(UsageScopeTestOnly),
		ProductAbsenceVerification: ProductAbsenceVerificationVerified,
		CheckScope:                 "paired go list closures",
	}
}

func decide(t *testing.T, in DecisionInput) EvidenceDecision {
	t.Helper()
	got, err := VerifyDecision(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func requireInconclusive(t *testing.T, got EvidenceDecision) {
	t.Helper()
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("expected INCONCLUSIVE, got %+v", got)
	}
}

// Step 7 case 1: complete, exact-bound package/build-closure absence.
func TestVerifyDecisionPackageAbsence(t *testing.T) {
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	if got.Verdict != domain.VerdictNoExploitPathFound || got.Falsifier != domain.FalsifierPackageAbsent ||
		got.NegativeVerification == nil || got.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("decision=%+v", got)
	}
}

func TestPackageAbsenceRejectsTypedPayloadLimitation(t *testing.T) {
	d := absentData()
	d.Limitations = []string{"product package inventory incomplete"}
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, d))))
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "product package inventory incomplete") {
		t.Fatalf("incomplete payload inventory must block absence: %+v", got)
	}
}

// Step 7 case 2: every degraded variant of the same evidence fails
// closed. The *-trace subtests break the trace contract; the *-obs
// subtests keep trace.Complete=true so only the per-observation
// status/completeness gates can catch them.
func TestVerifyDecisionDegradedPackageAbsence(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*VerificationTrace)
	}{
		{"partial-trace", func(tr *VerificationTrace) {
			tr.Observations[0].Completeness = evidencetools.CompletenessPartial
			tr.Complete = false
		}},
		{"error-trace", func(tr *VerificationTrace) {
			tr.Observations[0].ToolStatus = evidencetools.StatusError
			tr.Complete = false
		}},
		{"timeout-trace", func(tr *VerificationTrace) {
			tr.Observations[0].ToolStatus = evidencetools.StatusTimeout
			tr.Complete = false
		}},
		{"skipped-check", func(tr *VerificationTrace) { tr.Observations = nil; tr.Complete = false }},
		{"partial-obs", func(tr *VerificationTrace) { tr.Observations[0].Completeness = evidencetools.CompletenessPartial }},
		{"error-obs", func(tr *VerificationTrace) { tr.Observations[0].ToolStatus = evidencetools.StatusError }},
		{"timeout-obs", func(tr *VerificationTrace) { tr.Observations[0].ToolStatus = evidencetools.StatusTimeout }},
		{"skipped-package", func(tr *VerificationTrace) {
			tr.Observations[0].ScopeDetails.SkippedPackages = []string{"example.com/prod/skip"}
		}},
		{"trace-limitation", func(tr *VerificationTrace) { tr.Limitations = []string{"check budget exhausted"} }},
		{"missing-coverage-rule", func(tr *VerificationTrace) { tr.Observations[0].ScopeDetails.CoverageRule = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))
			tc.mutate(tr)
			requireInconclusive(t, decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent), tr)))
		})
	}
}

// Step 7 case 2 (forged trace): a trace whose observation does not match
// its request, carries no snapshot/build identity, or disagrees with the
// lane identity must never ground a negative.
func TestVerifyDecisionForgedTrace(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*VerificationTrace)
	}{
		{"tool-mismatch", func(tr *VerificationTrace) { tr.Observations[0].Tool = "find_callers" }},
		{"condition-mismatch", func(tr *VerificationTrace) { tr.Requests[0].ConditionID = "other" }},
		{"empty-snapshot-hash", func(tr *VerificationTrace) { tr.Observations[0].ScopeDetails.SnapshotHash = "" }},
		{"empty-build-context", func(tr *VerificationTrace) { tr.Observations[0].ScopeDetails.BuildContext = nil }},
		{"snapshot-mismatch", func(tr *VerificationTrace) { tr.Observations[0].ScopeDetails.SnapshotHash = "other-hash" }},
		{"build-mismatch", func(tr *VerificationTrace) { tr.Observations[0].ScopeDetails.BuildContext.GOOS = "windows" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))
			tc.mutate(tr)
			requireInconclusive(t, decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent), tr)))
		})
	}
}

// F3: a lane without recorded identity cannot ground a terminal negative.
func TestVerifyDecisionLaneIdentityMissing(t *testing.T) {
	for _, mut := range []func(*LaneResult){
		func(l *LaneResult) { l.ContentHash = "" },
		func(l *LaneResult) { l.Snapshot.GOOS = "" },
		func(l *LaneResult) { l.Snapshot.GOARCH = "" },
	} {
		lane := decisionLane(domain.ClaimTrue)
		mut(lane)
		requireInconclusive(t, decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData())))))
	}
}

// Step 7 case 6: missing or malformed evidence references fail closed —
// an ID-shaped string is never proof.
func TestVerifyDecisionMalformedEvidenceRefs(t *testing.T) {
	for _, refs := range [][]string{nil, {""}, {"sha256:proof"}, {"OBS-0001"}} {
		o := decisionObservation(evidencetools.UsageScopeTool, absentData())
		o.EvidenceRefs = refs
		requireInconclusive(t, decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(o))))
	}
}

// F4: a well-formed digest ref that resolves to no recorded artifact is
// not evidence. The same ref promotes only when a persistence pin or a
// lane artifact records it.
func TestVerifyDecisionUnresolvableEvidenceRef(t *testing.T) {
	orphan := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	o := decisionObservation(evidencetools.UsageScopeTool, absentData())
	o.EvidenceRefs = []string{orphan}
	tr := decisionTrace(o)
	// Index present but records nothing for this observation.
	got := decide(t, DecisionInput{Lane: decisionLane(domain.ClaimTrue),
		Proposal: decisionProposal(domain.FalsifierPackageAbsent), Trace: tr,
		ObservationIndex: map[string][]string{"OBS-1": {}}})
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "resolves to no recorded artifact") {
		t.Fatalf("expected unresolvable-ref reason, got %q", got.Reason)
	}
	// The digest is resolvable when the persistence index pins it.
	got = decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent), tr))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("resolvable ref must promote, got %+v", got)
	}
	// And when a lane artifact records the same digest.
	lane := decisionLane(domain.ClaimTrue)
	lane.ArtifactByObs = map[string]ArtifactRef{"OBS-9": {Path: "artifacts/o", SHA256: strings.TrimPrefix(orphan, "sha256:")}}
	got = decide(t, DecisionInput{Lane: lane, Proposal: decisionProposal(domain.FalsifierPackageAbsent), Trace: tr,
		ObservationIndex: map[string][]string{}})
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("lane-recorded digest must promote, got %+v", got)
	}
}

// F4: a src: locator on a non-proof observation is a tool-defined ref
// shape — it must not fail closed on shape alone.
func TestVerifyDecisionSrcRefNonProof(t *testing.T) {
	o := decisionObservation("read_source", map[string]any{"text": "x"})
	o.EvidenceRefs = []string{"src:lib/a.go#L10"}
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierGovulncheckSilence), decisionTrace(o)))
	requireInconclusive(t, got)
	if strings.Contains(got.Reason, "malformed evidence") {
		t.Fatalf("src: ref rejected by shape: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "no accepted independent proof rule") {
		t.Fatalf("expected proof-rule reason, got %q", got.Reason)
	}
}

// P0-1: a package-usage non-use verdict on a linked package is not
// build-closure absence — it must fail closed even when the same trace
// also carries a real closure proof.
func TestPackageAbsenceRejectsSourceNonUse(t *testing.T) {
	present := evidencetools.PackageUsageData{
		Module: testModule, Package: testPackage, Present: true,
		Usage:                string(goanalysis.PackageUsageNotUsed),
		NegativeVerification: string(domain.NegativeVerified), CheckScope: "closed source scope",
	}
	cases := []struct {
		name string
		obs  []*evidencetools.Observation
	}{
		{"nonuse-only", []*evidencetools.Observation{
			decisionObservation(evidencetools.PackageUsageTool, present)}},
		{"nonuse-plus-closure", []*evidencetools.Observation{
			decisionObservation(evidencetools.PackageUsageTool, present),
			decisionObservation(evidencetools.UsageScopeTool, absentData())}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent), decisionTrace(tc.obs...)))
			requireInconclusive(t, got)
			if !strings.Contains(got.Reason, "present") && !strings.Contains(got.Reason, "no closed") {
				t.Fatalf("expected named blocker, got %q", got.Reason)
			}
		})
	}
}

// P0-1 shape check: a usage-scope payload missing the absence markers
// (wrong class or unverified product absence) never grounds a negative.
func TestPackageAbsenceRequiresClosureMarkers(t *testing.T) {
	for _, mut := range []func(*evidencetools.UsageScopeData){
		func(d *evidencetools.UsageScopeData) {
			d.UsageScope = string(UsageScopeUnknown)
			d.ProductAbsenceVerification = ""
		},
		func(d *evidencetools.UsageScopeData) {
			d.UsageScope = string(UsageScopeMixed)
			d.ProductAbsenceVerification = ""
			d.ProductLinked = true
		},
		func(d *evidencetools.UsageScopeData) { d.ProductAbsenceVerification = "" },
	} {
		d := absentData()
		mut(&d)
		requireInconclusive(t, decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(decisionObservation(evidencetools.UsageScopeTool, d)))))
	}
}

// P0-2: every advisory-declared subject must be covered or resolved.
func TestPackageAbsenceUncoveredSubject(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	second := "example.com/dep/other"
	lane.Advisory.Vuln.AffectedPackages = append(lane.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, second) {
		t.Fatalf("uncovered subject not named: %q", got.Reason)
	}
}

// P0-2 positive half: the uncovered second subject observed product-linked
// also fails closed (positive linkage and uncovered coverage agree).
func TestPackageAbsenceUncoveredLinkedSubject(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	second := "example.com/dep/other"
	lane.Advisory.Vuln.AffectedPackages = append(lane.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
	linked := evidencetools.UsageScopeData{
		Module: testModule, Package: second,
		UsageScope: string(UsageScopeProduct), ProductLinked: true, CheckScope: "paired go list closures",
	}
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent), decisionTrace(
		decisionObservation(evidencetools.UsageScopeTool, absentData()),
		decisionObservation(evidencetools.UsageScopeTool, linked))))
	requireInconclusive(t, got)
}

// F5 + hasPositiveUse isolation: positive evidence for a subject that is
// ALSO covered by an absence proof still blocks the negative — deleting
// hasPositiveUse would wrongly promote this trace.
func TestPositiveControlCoveredLinkedSubject(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	second := "example.com/dep/other"
	lane.Advisory.Vuln.AffectedPackages = append(lane.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
	linked := evidencetools.UsageScopeData{
		Module: testModule, Package: second,
		UsageScope: string(UsageScopeProduct), ProductLinked: true, CheckScope: "paired go list closures",
	}
	tr := decisionTrace(
		decisionObservation(evidencetools.UsageScopeTool, absentData()),
		decisionObservation(evidencetools.UsageScopeTool, absentDataFor(testModule, second)),
		decisionObservation(evidencetools.UsageScopeTool, linked))
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent), tr))
	requireInconclusive(t, got)
}

// F5: a lane lower-bound positive fact (package-usage UNKNOWN with a
// concrete product site recorded) blocks promotion even though it is not
// a full USED verdict.
func TestPositiveControlLowerBoundFact(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "OBS-L2", Kind: FactKindPackageUsageLowerBound, Claim: "TRUE", Coverage: "PARTIAL",
		UsageSubject: &FactUsageSubject{Module: testModule, Package: testPackage},
	})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
}

// P0-2 resolved half, positive outcome: a declared second subject is
// discharged by a recorded deterministic lane fact carrying verified
// product absence for exactly that package — then the negative stands.
func TestPackageAbsenceResolvedSubjectCovers(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	second := "example.com/dep/other"
	lane.Advisory.Vuln.AffectedPackages = append(lane.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "OBS-L1", Kind: FactKindBuildUsageScope, Claim: "TRUE", Coverage: "COMPLETE",
		UsageSubject:               &FactUsageSubject{Module: testModule, Package: second},
		UsageScope:                 string(UsageScopeTestOnly),
		ProductAbsenceVerification: ProductAbsenceVerificationVerified,
	})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("resolved-subject decision=%+v", got)
	}
}

// F1: a package-level lane fact can never resolve a module-level
// subject. Advisory: one package entry plus one module-only entry for the
// same module; the package's verified absence fact exists; the module
// aggregate subject stays unresolved → INCONCLUSIVE naming it.
func TestPackageAbsenceModuleSubjectNeedsModuleFact(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	pkg := testPackage
	lane.Advisory.Vuln = &domain.Vulnerability{
		AffectedModules: []domain.AffectedModule{
			{Module: testModule, AffectedPackages: []domain.AffectedPackage{{Path: testPackage}}},
			{Module: testModule},
		},
	}
	lane.Advisory.Impls = []AffectedImplementation{
		{ID: "adv-01", Module: testModule, Package: &pkg, Binding: BindExact},
		{ID: "adv-02", Module: testModule, Binding: BindExact},
	}
	// The advisory declares two original Go entries for the same module (one
	// package entry, one module-only entry), so its full-record census
	// records both: the advisory scope is not the blocker here, and each
	// entry keeps its own id.
	lane.Affected.Scope = fullRecordScope("GO-TEST-0001",
		domain.RecordEntry{Ecosystem: "Go", Module: testModule},
		domain.RecordEntry{Ecosystem: "Go", Module: testModule})
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "OBS-L1", Kind: FactKindBuildUsageScope, Claim: "TRUE", Coverage: "COMPLETE",
		UsageSubject:               &FactUsageSubject{Module: testModule, Package: testPackage},
		UsageScope:                 string(UsageScopeTestOnly),
		ProductAbsenceVerification: ProductAbsenceVerificationVerified,
	})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "adv-02") {
		t.Fatalf("unresolved module-level subject not named: %q", got.Reason)
	}
}

// P0-2 unresolved probe: a subject whose applicability probe never ran
// (or ran without a negative outcome) is not resolved.
func TestPackageAbsenceResolvedSubject(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	second := "example.com/dep/other"
	lane.Advisory.Vuln.AffectedPackages = append(lane.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
	lane.Affected.CheckedPackages = []string{testPackage, second}
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
}

// Step 7 case 2 (binding): a proposal naming a component outside the
// advisory's declared subjects is an advisory_scope_gap.
func TestAdvisoryBindingWrongEntry(t *testing.T) {
	p := decisionProposal(domain.FalsifierPackageAbsent)
	p.Package = "example.com/other"
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), p,
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "advisory_scope_gap") {
		t.Fatalf("decision=%+v", got)
	}
}

// Step 7 case 2 (unresolved subject): a symbol the advisory never
// declared cannot bind.
func TestVerifyDecisionUnresolvedSubject(t *testing.T) {
	p := decisionProposal(domain.FalsifierPackageAbsent)
	p.Symbol = "Undeclared"
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), p,
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "advisory_scope_gap") {
		t.Fatalf("decision=%+v", got)
	}
}

// R3: the VERIFIED_VENDOR_INVENTORY marker promotes an absent-from-both
// advisory subject only under the full vendor-inventory condition set —
// exact identity at declared granularity, the recorded vendored build
// context, the offline derivation source and semantics, and no
// marker-invalidating limitation. Every forged or degraded shape stays
// INCONCLUSIVE.
func TestVerifyDecisionVendorInventoryMarker(t *testing.T) {
	lane := func() *LaneResult {
		l := decisionLane(domain.ClaimTrue)
		l.Snapshot.VendorMode = true
		return rebindLaneEvidence(l)
	}

	t.Run("package-level marker promotes", func(t *testing.T) {
		got := decide(t, decisionInput(lane(), decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)))))
		if got.Verdict != domain.VerdictNoExploitPathFound || got.Falsifier != domain.FalsifierPackageAbsent ||
			got.NegativeVerification == nil || got.NegativeVerification.Status != domain.NegativeVerified {
			t.Fatalf("vendor-inventory decision=%+v", got)
		}
	})

	t.Run("module-level marker and module-only proposal promote", func(t *testing.T) {
		p := decisionProposal(domain.FalsifierPackageAbsent)
		p.Package = ""
		got := decide(t, decisionInput(decisionModuleLane(domain.ClaimTrue), p,
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, "")))))
		if got.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("module-level vendor-inventory decision=%+v", got)
		}
	})

	t.Run("module-level entry is never satisfied by an agent-chosen package", func(t *testing.T) {
		// Advisory declares only the module; the proposal names a package
		// inside it — no declared subject matches that granularity.
		p := decisionProposal(domain.FalsifierPackageAbsent)
		got := decide(t, decisionInput(decisionModuleLane(domain.ClaimTrue), p,
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)))))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "advisory_scope_gap") {
			t.Fatalf("decision=%+v", got)
		}
	})

	t.Run("symbol-bearing proposal is not the build-closure route", func(t *testing.T) {
		p := decisionProposal(domain.FalsifierPackageAbsent)
		p.Symbol = "Sink"
		got := decide(t, decisionInput(lane(), p,
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)))))
		requireInconclusive(t, got)
	})

	for _, tc := range []struct {
		name string
		mut  func(*evidencetools.UsageScopeData, *evidencetools.Observation)
	}{
		{"unknown with VERIFIED marker", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ProductAbsenceVerification = ProductAbsenceVerificationVerified
		}},
		{"test-only with vendor marker", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.UsageScope = string(UsageScopeTestOnly)
			d.TestLinked = true
		}},
		{"product-linked marker", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ProductLinked = true
		}},
		{"test-linked marker", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.TestLinked = true
		}},
		{"missing closure source", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ClosureSource = ""
		}},
		{"wrong closure source", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ClosureSource = "go list -deps -json ./..."
		}},
		{"missing closure semantics", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ClosureSemantics = ""
		}},
		{"wrong closure semantics", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ClosureSemantics = "product_binary"
		}},
		{"vendor mode absent", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			o.ScopeDetails.BuildContext.VendorMode = false
		}},
		{"marker-invalidating limitation", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.Limitations = []string{"vendor/modules.txt inventory is incomplete: unlisted package"}
		}},
		{"marker-invalidating observation limitation", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			o.Limitations = []string{"closure derivation left an import unresolved"}
		}},
		{"unknown without marker", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ProductAbsenceVerification = ""
		}},
		{"unrecognized marker", func(d *evidencetools.UsageScopeData, o *evidencetools.Observation) {
			d.ProductAbsenceVerification = "VERIFIED_VENDOR_TREE"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := vendorAbsentDataFor(testModule, testPackage)
			o := vendorScopeObservation(d)
			l := lane()
			tc.mut(&d, o)
			o.Data = d
			requireInconclusive(t, decide(t, decisionInput(l, decisionProposal(domain.FalsifierPackageAbsent), decisionTrace(o))))
		})
	}

	t.Run("lane vendor-mode mismatch blocks", func(t *testing.T) {
		// The observation carries vendor_mode=true but the lane's
		// recorded snapshot is non-vendored — contexts must match.
		got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)))))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "build-context mismatch") {
			t.Fatalf("decision=%+v", got)
		}
	})

	t.Run("multi-subject advisory requires marker coverage", func(t *testing.T) {
		l := lane()
		second := "example.com/dep/other"
		l.Advisory.Vuln.AffectedPackages = append(l.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
		got := decide(t, decisionInput(l, decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)))))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, second) {
			t.Fatalf("uncovered subject not named: %q", got.Reason)
		}
		got = decide(t, decisionInput(l, decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(
				vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)),
				vendorScopeObservation(vendorAbsentDataFor(testModule, second)))))
		if got.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("two covered subjects must promote, got %+v", got)
		}
	})

	t.Run("positive product linkage contradicts the marker", func(t *testing.T) {
		linked := vendorAbsentDataFor(testModule, testPackage)
		linked.UsageScope = string(UsageScopeProduct)
		linked.ProductLinked = true
		linked.ProductAbsenceVerification = ""
		got := decide(t, decisionInput(lane(), decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(
				vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)),
				vendorScopeObservation(linked))))
		requireInconclusive(t, got)
	})

	t.Run("lane marker fact resolves a declared subject", func(t *testing.T) {
		l := lane()
		second := "example.com/dep/other"
		l.Advisory.Vuln.AffectedPackages = append(l.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
		l.Facts = append(l.Facts, VerifiedFact{
			ID: "fact-vendor-1", Kind: FactKindBuildUsageScope, Claim: "TRUE", Coverage: "COMPLETE",
			UsageSubject:               &FactUsageSubject{Module: testModule, Package: second},
			UsageScope:                 string(UsageScopeUnknown),
			ProductAbsenceVerification: ProductAbsenceVerificationVendorInventory,
		})
		got := decide(t, decisionInput(l, decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(vendorScopeObservation(vendorAbsentDataFor(testModule, testPackage)))))
		if got.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("lane marker fact must resolve the second subject, got %+v", got)
		}
	})
}

// Step 7 case 3: deterministic positive-use evidence plus an agent
// non-reachability assertion never produces a safe verdict.
func TestPositiveControl(t *testing.T) {
	used := evidencetools.PackageUsageData{
		Module: testModule, Package: testPackage, Present: true,
		Usage: string(goanalysis.PackageUsageUsed), CheckScope: "closed source scope",
		ProductSites: []domain.CallSite{{File: "use.go", Line: 10, Function: "main"}},
	}
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.PackageUsageTool, used))))
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("expected INCONCLUSIVE, got %+v", got)
	}
}

// Step 7 case 4: an unresolved release toolchain/applicability fact stays
// INCONCLUSIVE and names the missing fact.
func TestUnknownControl(t *testing.T) {
	got := decide(t, decisionInput(decisionLane(domain.ClaimUnknown), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "release") || !strings.Contains(got.Reason, "release-go-version") {
		t.Fatalf("missing release fact not named: %q", got.Reason)
	}
}

// Ruling: the guard route has no proof capability — every guard
// proposal, structured or not, ends INCONCLUSIVE with the capability
// reason.
func TestGuardBound(t *testing.T) {
	obs := decisionObservation("find_validations", GuardVerification{
		AllLiveSinksEnumerated: true, MutableFlowsResolved: true, ViolatingTermsExcluded: true,
		DynamicMarkersChecked: true, CoverageClosed: true, BoundLow: ptrInt64(0), BoundHigh: ptrInt64(1024)})
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierGuards), decisionTrace(obs)))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "guard_verification_capability_missing") {
		t.Fatalf("decision=%+v", got)
	}
}

// P2-5: a nil context must not panic.
func TestVerifyDecisionNilContext(t *testing.T) {
	if _, err := VerifyDecision(nil, DecisionInput{}); err == nil {
		t.Fatal("nil context must return an error")
	}
}

// P1-B: the audited runner binds every dispatched request to the
// session audit record the call appended. An observation returned for
// subject A can never be credited to a request declaring subject B —
// the mismatch is recorded as a limitation and the decision stays
// INCONCLUSIVE.
func TestVerificationPlanAuditedBinding(t *testing.T) {
	plan := VerificationPlan{
		Falsifier: *decisionProposal(domain.FalsifierPackageAbsent),
		Checks: []VerificationRequest{{
			ID: "check-1", Tool: evidencetools.UsageScopeTool,
			Arguments: testArgs(), ConditionID: "condition-1", Purpose: "probe"}},
	}
	auditFor := func(args json.RawMessage, tool string) *evidencetools.AuditRecord {
		o := decisionObservation(evidencetools.UsageScopeTool, absentData())
		return &evidencetools.AuditRecord{Tool: tool, Args: args, Observation: o}
	}
	mkCall := func(rec *evidencetools.AuditRecord) (AuditedCallFunc, *[]evidencetools.AuditRecord) {
		var seen []evidencetools.AuditRecord
		return func(_ context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
			o := decisionObservation(tool, absentData())
			if rec != nil {
				r := *rec
				r.Observation = o
				seen = append(seen, r)
				return o, &r, nil
			}
			return o, nil, nil
		}, &seen
	}
	decideWith := func(tr *VerificationTrace, audit []evidencetools.AuditRecord) EvidenceDecision {
		return decide(t, DecisionInput{Lane: decisionLane(domain.ClaimTrue),
			Proposal:         decisionProposal(domain.FalsifierPackageAbsent),
			Trace:            tr,
			ObservationIndex: VerificationObservationIndex(tr, audit)})
	}

	// Matching audit record: the declared arguments are what the
	// session recorded — the trace closes and promotes.
	call, seen := mkCall(auditFor(testArgs(), evidencetools.UsageScopeTool))
	tr, err := RunVerificationPlanAudited(context.Background(), call, plan, len(plan.Checks))
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Complete || len(tr.Limitations) != 0 {
		t.Fatalf("bound trace marked incomplete: %+v", tr.Limitations)
	}
	if got := decideWith(tr, *seen); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("bound trace must promote, got %+v", got)
	}

	// Audit-recorded arguments for a different subject: the observation
	// must not ground the declared request.
	call, seen = mkCall(auditFor(json.RawMessage(
		`{"module":"`+testModule+`","package":"example.com/dep/other"}`), evidencetools.UsageScopeTool))
	tr, err = RunVerificationPlanAudited(context.Background(), call, plan, len(plan.Checks))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Complete {
		t.Fatal("mismatched audit record produced a complete trace")
	}
	if len(tr.Limitations) == 0 || !strings.Contains(tr.Limitations[0], "audit-recorded arguments differ") {
		t.Fatalf("mismatch not recorded as a limitation: %v", tr.Limitations)
	}
	if got := decideWith(tr, *seen); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("mismatched audit record must stay INCONCLUSIVE, got %+v", got)
	}

	// A call the session never recorded cannot be bound either.
	call, _ = mkCall(nil)
	tr, err = RunVerificationPlanAudited(context.Background(), call, plan, len(plan.Checks))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Complete || len(tr.Limitations) == 0 || !strings.Contains(tr.Limitations[0], "no session audit record") {
		t.Fatalf("unrecorded call must be a named limitation, got %+v", tr.Limitations)
	}

	// An audit record naming a different tool is a different call.
	call, seen = mkCall(auditFor(testArgs(), "read_source"))
	tr, err = RunVerificationPlanAudited(context.Background(), call, plan, len(plan.Checks))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Complete || len(tr.Limitations) == 0 || !strings.Contains(tr.Limitations[0], "audit record names tool") {
		t.Fatalf("tool-mismatched audit record must be a named limitation, got %+v", tr.Limitations)
	}
	if got := decideWith(tr, *seen); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("tool-mismatched audit record must stay INCONCLUSIVE, got %+v", got)
	}
}

// P2-C: the persistence index is independent of the trace's own
// EvidenceRefs — it is built from session audit records. Mutating the
// trace's refs to another pinned digest stays valid; mutating the
// independent pins themselves fails closed.
func TestVerifyDecisionIndexIndependence(t *testing.T) {
	tr := decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))
	in := decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent), tr)
	pins := in.ObservationIndex["OBS-1"]
	if len(pins) == 0 {
		t.Fatal("audit-recorded observation gained no persistence pins")
	}
	// A digest pin that is not the recorded EvidenceRefs value.
	var other string
	for _, p := range pins {
		if p != testRef {
			other = p
		}
	}
	if other == "" {
		t.Fatalf("expected a data-digest pin independent of %q, got %v", testRef, pins)
	}
	tr.Observations[0].EvidenceRefs = []string{other}
	if got := decide(t, in); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("independent pin must still promote, got %+v", got)
	}
	// Changing only the pins — trace untouched — removes the proof's
	// resolvable reference and fails closed.
	in.ObservationIndex["OBS-1"] = []string{"sha256:" + strings.Repeat("ee", 32)}
	got := decide(t, in)
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "resolves to no recorded artifact") {
		t.Fatalf("expected unresolvable-ref reason, got %q", got.Reason)
	}
}

// resolveObservation records the lane-side affected-resolve record the
// deterministic lane emits; its persisted payload carries the resolver
// evidence ids LaneResult.AffectedEvidence holds verbatim.
func resolveObservation(obsID string) *evidencetools.Observation {
	return &evidencetools.Observation{
		ID: obsID, Tool: "affected-resolve", Fact: "applicability chain",
		Scope:        "go module graph and import closure",
		Completeness: evidencetools.CompletenessComplete, ToolStatus: evidencetools.StatusOK,
	}
}

// C09 ruling: a deterministic applicability FALSE resolves NOT_AFFECTED
// on its own — no proposal, plan or trace is required, and nothing
// downstream may suppress it.
func TestApplicabilityFalseWithoutProposal(t *testing.T) {
	moduleAbsent := decisionLane(domain.ClaimTrue)
	moduleAbsent.Affected.ModulePresent = domain.ClaimFalse
	moduleAbsent.Affected.CheckedModules = []string{testModule}
	moduleAbsent.Affected.EvidenceIDs = []domain.EvidenceID{"EV-AFFECTED-MODULES"}
	moduleAbsent.AffectedEvidence = []domain.Evidence{{ID: "EV-AFFECTED-MODULES", Kind: "MODULE_GRAPH", Quality: "DETERMINISTIC", Source: "vendor/modules.txt"}}
	moduleAbsent.Observations = []*evidencetools.Observation{resolveObservation("OBS-0002")}
	versionUnaffected := decisionLane(domain.ClaimFalse)
	packageAbsent := decisionLane(domain.ClaimTrue)
	packageAbsent.Affected.PackagePresent = domain.ClaimFalse
	buildIrrelevant := decisionLane(domain.ClaimTrue)
	buildIrrelevant.Affected.BuildRelevant = domain.ClaimFalse
	implementationAbsent := decisionLane(domain.ClaimTrue)
	implementationAbsent.Affected.VulnerableImplementationPresent = domain.ClaimFalse
	implementationAbsent.Affected.ImplementationLocus = "example.com/dep/resource/host_bsd.go read"
	implementationAbsent.Affected.ImplementationTarget = "linux/amd64"
	implementationAbsent.Affected.ImplementationTargetScope = "product"
	implementationAbsent.Affected.AssumptionIDs = []string{"AT-linux-only"}
	for _, tc := range []struct {
		name string
		lane *LaneResult
	}{
		{"module absent", moduleAbsent},
		{"version outside range", versionUnaffected},
		{"package absent", packageAbsent},
		{"build irrelevant", buildIrrelevant},
		{"implementation absent", implementationAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decide(t, DecisionInput{Lane: tc.lane})
			if got.Verdict != domain.VerdictNotAffected {
				t.Fatalf("decision=%+v", got)
			}
			if got.Coverage != "COMPLETE" || got.Scope != "deterministic applicability chain" {
				t.Fatalf("applicability decision must carry chain scope and COMPLETE coverage: %+v", got)
			}
		})
	}
	got := decide(t, DecisionInput{Lane: moduleAbsent})
	if len(got.EvidenceRefs) != 1 || got.EvidenceRefs[0] != "obs:OBS-0002" {
		t.Fatalf("applicability refs must cite the carrier observation, got %+v", got.EvidenceRefs)
	}
	got = decide(t, DecisionInput{Lane: implementationAbsent})
	if len(got.AssumptionIDs) != 1 || got.AssumptionIDs[0] != "AT-linux-only" {
		t.Fatalf("implementation decision must carry the target-scope assumption ids, got %+v", got.AssumptionIDs)
	}
	if !strings.Contains(got.Reason, "host_bsd.go") || !strings.Contains(got.Reason, "linux/amd64") {
		t.Fatalf("implementation decision reason = %q", got.Reason)
	}
}

// A raw applicability FALSE is a fact about the components the loaded
// advisory declares. Under a partial scope — a CVE request resolved to
// one known advisory record — it stays evidence but never closes the
// requested advisory: the decision is INCONCLUSIVE, its coverage is not
// COMPLETE, the reason names the scoped gap, and the applicability
// evidence refs still resolve to the lane's affected-resolve record.
func TestApplicabilityPartialScopeDoesNotClose(t *testing.T) {
	build := func(scope *domain.AdvisoryScope) *LaneResult {
		lane := decisionLane(domain.ClaimFalse)
		lane.Affected.Scope = scope
		lane.Affected.EvidenceIDs = []domain.EvidenceID{"EV-AFFECTED-MODULES"}
		lane.AffectedEvidence = []domain.Evidence{
			{ID: "EV-AFFECTED-MODULES", Kind: "MODULE_GRAPH", Quality: "DETERMINISTIC", Source: "vendor/modules.txt"},
		}
		lane.Observations = []*evidencetools.Observation{resolveObservation("OBS-0008")}
		return lane
	}

	partial := decide(t, DecisionInput{Lane: build(partialCVEScope())})
	if partial.Verdict != domain.VerdictInconclusive {
		t.Fatalf("partial scope must not close: %+v", partial)
	}
	if partial.Coverage == "COMPLETE" {
		t.Fatalf("partial scope must not claim COMPLETE coverage: %+v", partial)
	}
	if !strings.Contains(partial.Reason, "scoped applicability gap") {
		t.Fatalf("reason must name the scoped applicability gap: %q", partial.Reason)
	}
	if len(partial.EvidenceRefs) != 1 || partial.EvidenceRefs[0] != "obs:OBS-0008" {
		t.Fatalf("the local facts must stay cited, got %+v", partial.EvidenceRefs)
	}

	// Exact-entry counterpart: the same FALSE under the ordinary
	// complete entry scope keeps closing the advisory.
	exact := decide(t, DecisionInput{Lane: build(exactAdvisoryScope("GO-TEST-0001"))})
	if exact.Verdict != domain.VerdictNotAffected || exact.Coverage != "COMPLETE" {
		t.Fatalf("exact-entry scope must keep the closing: %+v", exact)
	}
	if len(exact.EvidenceRefs) != 1 || exact.EvidenceRefs[0] != "obs:OBS-0008" {
		t.Fatalf("exact-entry refs = %+v", exact.EvidenceRefs)
	}
}

// Every negative route inherits the structural scope gate: an exact GO-
// identity whose loaded record is only a Go projection, a full-record claim
// carrying no census, and a self-contradicting census all refuse the closure
// on the applicability chain, the agent proposal, the symbol authority and the
// lane's own post-reach config proof. An exact identity alone — like COMPLETE
// coverage alone — is not completeness, so the complete-record control is the
// only shape that keeps each route.
func TestExtentGateBlocksEveryNegativeRoute(t *testing.T) {
	symbolSubjects := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}

	// Controls: the complete-record scope still closes every route.
	if got := decide(t, DecisionInput{Lane: decisionLane(domain.ClaimFalse)}); got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("applicability control = %+v", got)
	}
	if got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData())))); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("proposal control = %+v", got)
	}
	if got := decide(t, symbolAuthorityInput(decisionLane(domain.ClaimTrue), symbolSubjects,
		completeSymbolResult(symbolSubjects), true)); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("symbol authority control = %+v", got)
	}
	configBase, _ := configLaneOpts(t, "", true)
	if configBase.ConfigProof == nil {
		t.Fatal("config fixture produced no lane proof")
	}
	if got := decide(t, DecisionInput{Lane: configBase}); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("config authority control = %+v", got)
	}

	for name, scope := range extentRefusalScopes("GO-TEST-0001") {
		t.Run(name, func(t *testing.T) {
			applicability := decisionLane(domain.ClaimFalse)
			applicability.Affected.Scope = scope
			if got := decide(t, DecisionInput{Lane: applicability}); got.Verdict != domain.VerdictInconclusive ||
				!strings.Contains(got.Reason, "scoped applicability gap") {
				t.Fatalf("applicability route closed: %+v", got)
			}

			proposalLane := decisionLane(domain.ClaimTrue)
			proposalLane.Affected.Scope = scope
			if got := decide(t, decisionInput(proposalLane, decisionProposal(domain.FalsifierPackageAbsent),
				decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData())))); got.Verdict != domain.VerdictInconclusive ||
				!strings.Contains(got.Reason, "scoped applicability gap") {
				t.Fatalf("proposal route closed: %+v", got)
			}

			symbolLane := decisionLane(domain.ClaimTrue)
			symbolLane.Affected.Scope = scope
			if got := decide(t, symbolAuthorityInput(symbolLane, symbolSubjects,
				completeSymbolResult(symbolSubjects), true)); got.Verdict != domain.VerdictInconclusive ||
				!strings.Contains(got.Reason, "scoped applicability gap") {
				t.Fatalf("symbol authority route closed: %+v", got)
			}

			// The lane's config proof is a cached COMPLETE negative: it never
			// overrides the current lane scope.
			configLane := *configBase
			configLane.Affected.Scope = scope
			if got := decide(t, DecisionInput{Lane: &configLane}); got.Verdict != domain.VerdictInconclusive ||
				!strings.Contains(got.Reason, "scoped applicability gap") {
				t.Fatalf("config authority route closed: %+v", got)
			}
		})
	}
}

// The applicability route emits refs the report validator can resolve:
// every resolver evidence id is cited as the lane observation whose
// payload carries it — never a bare EV-* string.
func TestApplicabilityEvidenceRefsResolve(t *testing.T) {
	moduleAbsent := decisionLane(domain.ClaimTrue)
	moduleAbsent.Affected.ModulePresent = domain.ClaimFalse
	for _, tc := range []struct {
		name string
		lane *LaneResult
	}{
		{"module absent", moduleAbsent},
		{"version outside range", decisionLane(domain.ClaimFalse)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.lane.Affected.EvidenceIDs = []domain.EvidenceID{"EV-AFFECTED-MODULES", "EV-AFFECTED-PACKAGES"}
			tc.lane.AffectedEvidence = []domain.Evidence{
				{ID: "EV-AFFECTED-MODULES", Kind: "MODULE_GRAPH", Quality: "DETERMINISTIC", Source: "vendor/modules.txt"},
				{ID: "EV-AFFECTED-PACKAGES", Kind: "MODULE_GRAPH", Quality: "DETERMINISTIC", Source: "vendor/modules.txt"},
			}
			tc.lane.Observations = []*evidencetools.Observation{resolveObservation("OBS-0008")}
			got := decide(t, DecisionInput{Lane: tc.lane})
			if got.Verdict != domain.VerdictNotAffected {
				t.Fatalf("decision=%+v", got)
			}
			if len(got.EvidenceRefs) != 1 || got.EvidenceRefs[0] != "obs:OBS-0008" {
				t.Fatalf("refs must collapse to the carrier observation, got %+v", got.EvidenceRefs)
			}
			r := decisionReport(t, got.EvidenceRefs...)
			r.Decision.Verdict = domain.VerdictNotAffected
			r.VerifiedFacts = append(r.VerifiedFacts, factFor("OBS-0008", "affected-resolve", "applicability chain"))
			if err := Validate(r, ""); err != nil {
				t.Fatalf("report with resolved applicability refs rejected:\n%v", err)
			}
		})
	}
}

// An evidence id no lane observation carries stays raw in the decision —
// the citation must fail validation loudly, never be dropped or hidden.
func TestApplicabilityEvidenceRefsUnresolvableStayRaw(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Affected.ModulePresent = domain.ClaimFalse
	lane.Affected.EvidenceIDs = []domain.EvidenceID{"EV-ORPHAN"}
	got := decide(t, DecisionInput{Lane: lane})
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("decision=%+v", got)
	}
	if len(got.EvidenceRefs) != 1 || got.EvidenceRefs[0] != "EV-ORPHAN" {
		t.Fatalf("uncarried id must stay verbatim, got %+v", got.EvidenceRefs)
	}
	r := decisionReport(t, got.EvidenceRefs...)
	r.Decision.Verdict = domain.VerdictNotAffected
	err := Validate(r, "")
	if err == nil {
		t.Fatal("unresolvable applicability ref validated")
	}
	if !strings.Contains(err.Error(), "decision.evidence_refs") {
		t.Fatalf("expected a decision.evidence_refs failure, got: %v", err)
	}
}

// C09 ruling: an unrelated product-linked module — one the advisory never
// declares — can never contradict an applicability NOT_AFFECTED.
func TestApplicabilityFalseIgnoresUnrelatedPositive(t *testing.T) {
	lane := decisionModuleLane(domain.ClaimTrue)
	lane.Affected.ModulePresent = domain.ClaimFalse
	linked := evidencetools.UsageScopeData{
		Module:     "github.com/docker/docker",
		UsageScope: string(UsageScopeMixed), ProductLinked: true,
		CheckScope: "paired go list closures",
	}
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, linked))))
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("decision=%+v", got)
	}
}

// C09 ruling: the chain stays authoritative even when a positive
// observation binds to a declared subject — non-applicability is already
// proven, so the contradiction gate never runs.
func TestApplicabilityFalseWithDeclaredPositive(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Affected.ModulePresent = domain.ClaimFalse
	linked := evidencetools.UsageScopeData{
		Module: testModule, Package: testPackage,
		UsageScope: string(UsageScopeProduct), ProductLinked: true,
		CheckScope: "paired go list closures",
	}
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, linked))))
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("decision=%+v", got)
	}
}

// C09 ruling: with applicability unproven, a positive observation bound
// to a declared subject still blocks the negative promotion.
func TestApplicabilityUnknownDeclaredPositiveBlocks(t *testing.T) {
	lane := decisionLane(domain.ClaimUnknown)
	linked := evidencetools.UsageScopeData{
		Module: testModule, Package: testPackage,
		UsageScope: string(UsageScopeProduct), ProductLinked: true,
		CheckScope: "paired go list closures",
	}
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, linked))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "contradicts a negative promotion") {
		t.Fatalf("contradiction reason missing: %q", got.Reason)
	}
}

// C09 ruling: a module the advisory never declares being product-linked
// is not a contradiction — the closed absence proof for the declared
// package still promotes.
func TestPackageAbsenceUnrelatedPositiveDoesNotBlock(t *testing.T) {
	linked := evidencetools.UsageScopeData{
		Module:     "github.com/docker/docker",
		UsageScope: string(UsageScopeMixed), ProductLinked: true,
		CheckScope: "paired go list closures",
	}
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(
			decisionObservation(evidencetools.UsageScopeTool, absentData()),
			decisionObservation(evidencetools.UsageScopeTool, linked))))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("unrelated positive must not block, got %+v", got)
	}
}

// C09 ruling: the same scoping applies to lane facts — a product/mixed
// build-usage fact for a non-advisory module is not a contradiction.
func TestPackageAbsenceUnrelatedFactDoesNotBlock(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "OBS-L3", Kind: FactKindBuildUsageScope, Claim: "TRUE", Coverage: "COMPLETE",
		UsageSubject: &FactUsageSubject{Module: "github.com/docker/docker"},
		UsageScope:   string(UsageScopeMixed),
	})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("unrelated positive fact must not block, got %+v", got)
	}
}

// T6 control 3a: the closure proof for one declared subject can never be
// promoted while a bound package-usage observation records a different
// declared subject as linked — presence contradicts absence for the
// whole advisory claim, whatever the usage verdict on that record.
func TestPackageAbsenceContradictsOtherSubjectPresence(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	second := "example.com/dep/other"
	lane.Advisory.Vuln.AffectedPackages = append(lane.Advisory.Vuln.AffectedPackages, domain.AffectedPackage{Path: second})
	for _, usage := range []string{
		string(goanalysis.PackageUsageNotUsed),
		string(goanalysis.PackageUsageUnknown),
	} {
		present := evidencetools.PackageUsageData{
			Module: testModule, Package: second, Present: true,
			Usage:      usage,
			CheckScope: "closed source scope",
		}
		tr := decisionTrace(
			decisionObservation(evidencetools.UsageScopeTool, absentData()),
			decisionObservation(evidencetools.UsageScopeTool, absentDataFor(testModule, second)),
			decisionObservation(evidencetools.PackageUsageTool, present))
		got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent), tr))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "contradictory package/build facts") || !strings.Contains(got.Reason, second) {
			t.Fatalf("usage=%s: presence contradiction not named: %q", usage, got.Reason)
		}
	}
}

// T6 control 3b: a promoted present-unused PACKAGE_USAGE fact on the
// proposed subject contradicts the closure proof in the same trace —
// the decision never selects the favourable record.
func TestPackageAbsenceContradictsLanePresentUnusedFact(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "fact-obs-pu", Kind: FactKindPackageUsage, Claim: "FALSE", Coverage: "COMPLETE",
		UsageSubject: &FactUsageSubject{Module: testModule, Package: testPackage},
		UsageBasis:   UsageBasisPresentUnused,
	})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "contradictory package/build facts") ||
		!strings.Contains(got.Reason, "fact-obs-pu") {
		t.Fatalf("lane fact contradiction not named: %q", got.Reason)
	}
}

// T6 control 3c: a package-usage negative proven on the absence basis
// agrees with the closure proof — no conflict is manufactured, and the
// advisory still closes through package absence.
func TestPackageAbsenceAbsentBasisFactConsistent(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "fact-obs-pu", Kind: FactKindPackageUsage, Claim: "FALSE", Coverage: "COMPLETE",
		UsageSubject: &FactUsageSubject{Module: testModule, Package: testPackage},
		UsageBasis:   UsageBasisAbsentFromClosure,
	})
	got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
	if got.Verdict != domain.VerdictNoExploitPathFound || got.Falsifier != domain.FalsifierPackageAbsent {
		t.Fatalf("consistent absent-basis fact must not block: %+v", got)
	}
}

// T6 control 3d (the case-10 shape): a package-level absence record from
// the product's linked closure against a mixed build-usage class is a
// contradiction — the mixed classification names product-closure linkage,
// so no negative may promote and the decision names the disagreeing fact.
func TestPackageAbsenceMixedBuildUsageContradicts(t *testing.T) {
	t.Run("trace observation", func(t *testing.T) {
		mixed := evidencetools.UsageScopeData{
			Module: testModule, Package: testPackage,
			UsageScope: string(UsageScopeMixed), ProductLinked: true, TestLinked: true,
			CheckScope: "paired go list closures",
		}
		tr := decisionTrace(
			decisionObservation(evidencetools.UsageScopeTool, absentData()),
			decisionObservation(evidencetools.UsageScopeTool, mixed))
		got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent), tr))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "usage_scope=mixed") {
			t.Fatalf("mixed class not named: %q", got.Reason)
		}
	})
	t.Run("lane fact", func(t *testing.T) {
		lane := decisionLane(domain.ClaimTrue)
		lane.Facts = append(lane.Facts, VerifiedFact{
			ID: "fact-obs-b41", Kind: FactKindBuildUsageScope, Claim: "TRUE", Coverage: "COMPLETE",
			UsageSubject: &FactUsageSubject{Module: testModule, Package: testPackage},
			UsageScope:   string(UsageScopeMixed),
		})
		got := decide(t, decisionInput(lane, decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData()))))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "usage_scope=mixed") || !strings.Contains(got.Reason, "fact-obs-b41") {
			t.Fatalf("mixed lane fact not named: %q", got.Reason)
		}
	})
}

// T6 control 4: a package-usage verdict that records its subject absent
// from the linked source closure is never the package-absence proof —
// the build-closure route consumes only usage-scope evidence, so a
// source-only absence observation leaves the falsifier INCONCLUSIVE.
// A symbol-level subject is no absent either way: the same source-usage
// absence record never demotes a declared symbol to package-level proof.
func TestPackageAbsenceSourceAbsenceIsNotClosureProof(t *testing.T) {
	absentUsage := evidencetools.PackageUsageData{
		Module: testModule, Package: testPackage, Present: false,
		Usage:                string(goanalysis.PackageUsageNotUsed),
		NegativeVerification: string(domain.NegativeVerified),
		CheckScope:           "complete product source closure",
	}
	got := decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.PackageUsageTool, absentUsage))))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "no closed product build-closure absence proof") {
		t.Fatalf("source-usage absence promoted: %q", got.Reason)
	}
	// Symbol-flavoured record bound to the same package: still not a
	// build-closure proof, still INCONCLUSIVE.
	absentUsage.Symbol = "Sink"
	got = decide(t, decisionInput(decisionLane(domain.ClaimTrue), decisionProposal(domain.FalsifierPackageAbsent),
		decisionTrace(decisionObservation(evidencetools.PackageUsageTool, absentUsage))))
	requireInconclusive(t, got)
}

// T6 control 5: may_call=0 recorded while the enumeration is partial is
// never a closed empty caller set — alongside the 31-marker class of
// dynamic escapes the proof stays open and the decision names the
// primitive's own conclusion instead of promoting.
func TestDeclaredSymbolAuthorityOpenMayCallZeroSites(t *testing.T) {
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	r := completeSymbolResult(subs)
	r.Complete = false
	r.Limitations = []string{
		"may-call enumeration for " + testPackage + ".Sink is partial (unresolved function-value candidates); the caller set is not closed",
	}
	r.MayCallSites = nil
	r.DynamicMarkers = []goanalysis.DynamicMarker{
		{CallSite: domain.CallSite{File: "product/serve.go", Line: 42}, Kind: "reflect_method", Detail: "reflect.Value.MethodByName(\"Sink\")"},
	}
	got := decide(t, symbolAuthorityInput(decisionLane(domain.ClaimTrue), subs, r, true))
	requireInconclusive(t, got)

	if !strings.Contains(got.Reason, "may_call=0") || !strings.Contains(got.Reason, "markers=1") {
		t.Fatalf("the open enumeration must be named, got %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "partial") {
		t.Fatalf("the partial-enumeration limitation must be named, got %q", got.Reason)
	}
}

// T6 control 3e: a module-level absence proposal is contradicted by a
// package inside the module recorded present — the conflict binds
// through the declared module, not only exact package identity.
func TestPackageAbsenceModuleLevelPresenceConflict(t *testing.T) {
	lane := decisionModuleLane(domain.ClaimTrue)
	present := evidencetools.PackageUsageData{
		Module: testModule, Package: testPackage, Present: true,
		Usage:      string(goanalysis.PackageUsageUnknown),
		CheckScope: "open source scope",
	}
	p := &FalsifierProposal{Kind: domain.FalsifierPackageAbsent, ConditionID: "condition-1",
		Module: testModule, Statement: "the module is absent", Scope: "complete product closure"}
	// The module lane records vendor mode; the observation's build
	// context must match before the trace gate even runs.
	o := vendorScopeObservation(present)
	o.Tool = evidencetools.PackageUsageTool
	tr := decisionTrace(o)
	got := decide(t, decisionInput(lane, p, tr))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "contradictory package/build facts") {
		t.Fatalf("module-level presence conflict not named: %q", got.Reason)
	}
}

// T6 control 2: a package-present/symbol-unused advisory closes only
// through the symbol-unreachability authority — the package's recorded
// presence is evidence about the package, never a contradiction of the
// declared symbol, and never the package-absence route.
func TestDeclaredSymbolAuthorityCoexistsWithPackagePresence(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Facts = append(lane.Facts, VerifiedFact{
		ID: "fact-obs-pu", Kind: FactKindPackageUsage, Claim: "FALSE", Coverage: "COMPLETE",
		UsageSubject: &FactUsageSubject{Module: testModule, Package: testPackage},
		UsageBasis:   UsageBasisPresentUnused,
	})
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), true))
	if got.Verdict != domain.VerdictNoExploitPathFound || got.Falsifier != domain.FalsifierDeclaredSymbolUnreached {
		t.Fatalf("package presence must not veto symbol unreachability: %+v", got)
	}
	if got.NegativeVerification == nil || got.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("symbol route must carry a verified negative: %+v", got.NegativeVerification)
	}
}

func ptrInt64(v int64) *int64 { return &v }

// attachDefectivePremise binds the lane's admitted invocation-necessity
// premise for the declared-symbol authority tests: the first advisory-declared
// symbol is treated as the contracted check. Tests that tamper with the
// contract replace or clear it explicitly.
func attachDefectivePremise(lane *LaneResult) {
	if lane == nil || lane.DefectSemantics != nil {
		return
	}
	if refs := declaredSymbolRefs(lane); len(refs) > 0 {
		lane.DefectSemantics = &domain.DefectSemanticsContract{
			Mode:     domain.DefectSemanticsDefectiveCheck,
			RecordID: "GO-TEST-SYMBOL-PROOF",
			Check:    refs[0],
		}
	}
}

func symbolAuthorityInput(lane *LaneResult, subjects []FactUsageSubject, result goanalysis.UnreachabilityResult, withAudit bool) DecisionInput {
	// The declared-symbol authority route is a deadness negative: bind the
	// admitted invocation-necessity premise by default, exactly as a lane
	// carrying the resolved contract does. Tampering tests remove or replace
	// it; the route must then refuse the close.
	attachDefectivePremise(lane)
	o := decisionObservation(evidencetools.SymbolUnreachabilityTool, evidencetools.SymbolUnreachabilityData{Result: result})
	tr := decisionTrace(o)
	in := DecisionInput{Lane: lane, Trace: tr, Authority: &VerifiedFalsifierInput{Kind: domain.FalsifierDeclaredSymbolUnreached, ConditionID: "condition-1", RuleID: "rule.declared-symbols-unreached", Subjects: subjects}}
	args := evidencetools.SymbolUnreachabilityArgs{Module: result.Module}
	for _, s := range subjects {
		args.Subjects = append(args.Subjects, domain.SymbolRef{Package: s.Package, Symbol: s.Symbol})
	}
	tr.Requests[0].Arguments, _ = json.Marshal(args)
	if withAudit {
		in.Audit = decisionAudit(tr)
		in.ObservationIndex = VerificationObservationIndex(tr, in.Audit)
	}
	return in
}

func completeSymbolResult(subjects []FactUsageSubject) goanalysis.UnreachabilityResult {
	r := goanalysis.UnreachabilityResult{Module: testModule, DeclarationComplete: true, EntrypointComplete: true, Complete: true}
	r.ModuleEntryComplete, r.ModuleReachComplete = true, true
	snapshot := decisionLane(domain.ClaimTrue).Snapshot
	r.Build = domain.EffectiveBuildContext(snapshot)
	r.ProductPackages = []string{"example.com/product"}
	r.Inventory = affected.RecordPackageInventory([]byte(`{"ImportPath":"example.com/product","Name":"main"}`), nil, snapshot, false)
	for _, s := range subjects {
		r.Subjects = append(r.Subjects, goanalysis.UnreachabilitySubject{Package: s.Package, Symbol: s.Symbol})
	}
	return r
}

func TestDeclaredSymbolAuthorityTerminalShape(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), true))
	if got.Verdict != domain.VerdictNoExploitPathFound || got.Falsifier != domain.FalsifierDeclaredSymbolUnreached || got.NegativeVerification == nil || got.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("got=%+v", got)
	}
	if got.Verdict == domain.VerdictNotAffected {
		t.Fatal("symbol proof produced NOT_AFFECTED")
	}
}

func TestDeclaredSymbolProposalCannotActAsAuthority(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	p := decisionProposal(domain.FalsifierDeclaredSymbolUnreached)
	p.Subjects = []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	got := decide(t, DecisionInput{Lane: lane, Proposal: p})
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "no independent verification trace") {
		t.Fatalf("got=%+v", got)
	}
}

func TestDeclaredSymbolAuthorityIdentityAndCoverage(t *testing.T) {
	tests := []struct {
		name     string
		subjects []FactUsageSubject
		want     string
	}{
		{"package", []FactUsageSubject{{Module: testModule, Package: testPackage}}, "granularity is invalid"},
		{"module", []FactUsageSubject{{Module: testModule}}, "granularity is invalid"},
		{"wrong module", []FactUsageSubject{{Module: "example.com/other", Package: testPackage, Symbol: "Sink"}}, "exact advisory symbol"},
		{"missing", nil, "every declared symbol"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lane := decisionLane(domain.ClaimTrue)
			in := symbolAuthorityInput(lane, tc.subjects, completeSymbolResult(tc.subjects), true)
			got := decide(t, in)
			if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("got=%+v", got)
			}
		})
	}
}

func TestDeclaredSymbolAuthorityIncompleteGates(t *testing.T) {
	base := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	for _, tc := range []struct {
		name   string
		mutate func(*goanalysis.UnreachabilityResult)
	}{
		{"limitation", func(r *goanalysis.UnreachabilityResult) { r.Limitations = []string{"timeout"} }},
		{"entrypoint", func(r *goanalysis.UnreachabilityResult) { r.EntrypointComplete = false }},
		{"declaration", func(r *goanalysis.UnreachabilityResult) { r.DeclarationComplete = false }},
		{"opaque", func(r *goanalysis.UnreachabilityResult) { r.Opaque = true }},
		{"dependency", func(r *goanalysis.UnreachabilityResult) { r.DependencyCallSites = []domain.CallSite{{}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := completeSymbolResult(base)
			r.Complete = false
			tc.mutate(&r)
			got := decide(t, symbolAuthorityInput(decisionLane(domain.ClaimTrue), base, r, true))
			if got.Verdict != domain.VerdictInconclusive {
				t.Fatalf("got=%+v", got)
			}
		})
	}
}

func TestDeclaredSymbolAuthorityAuditAndUnknownRelease(t *testing.T) {
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	lane := decisionLane(domain.ClaimUnknown)
	lane.Affected.UnresolvedModules = []string{testModule}
	if got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), false)); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("missing audit got=%+v", got)
	}
	if got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), true)); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("unknown release got=%+v", got)
	}
	lane.Affected.UnresolvedModules = []string{"example.com/unresolved"}
	if got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), true)); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("omitted unresolved got=%+v", got)
	}
	if got := decide(t, decisionInput(decisionLane(domain.ClaimUnknown), decisionProposal(domain.FalsifierPackageAbsent), decisionTrace())); got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("non-symbol unknown got=%+v", got)
	}
}

func TestDeclaredSymbolAuthorityPositiveVeto(t *testing.T) {
	lane := decisionLane(domain.ClaimTrue)
	lane.Facts = []VerifiedFact{{Kind: FactKindPackageUsage, Claim: "TRUE", UsageSubject: &FactUsageSubject{Module: testModule, Package: testPackage, Symbol: "Sink"}}}
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	got := decide(t, symbolAuthorityInput(lane, subs, completeSymbolResult(subs), true))
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "contradicts") {
		t.Fatalf("got=%+v", got)
	}
}

func symbolFixtureLane(version domain.ClaimResult) *LaneResult {
	lane := decisionLane(version)
	lane.Advisory.Vuln.AffectedSymbols = append(lane.Advisory.Vuln.AffectedSymbols, domain.SymbolRef{Package: testPackage, Symbol: "Encode"})
	lane.Advisory.Impls[0].Symbols = append(lane.Advisory.Impls[0].Symbols, "Encode")
	return lane
}

func TestDeclaredSymbolAuthorityRecordedFixture(t *testing.T) {
	raw, err := recordedSymbolAuthorityFixture.ReadFile("testdata/r6-recorded-symbol-unreachable.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Subjects []struct{ Module, Package, Symbol string } `json:"subjects"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var subjects []FactUsageSubject
	for _, s := range f.Subjects {
		subjects = append(subjects, FactUsageSubject{Module: s.Module, Package: s.Package, Symbol: s.Symbol})
	}
	if len(subjects) != 2 {
		t.Fatalf("fixture subjects=%v", subjects)
	}
	lane := symbolFixtureLane(domain.ClaimUnknown)
	lane.Advisory.Vuln.Module = subjects[0].Module
	lane.Advisory.Vuln.Package = subjects[0].Package
	lane.Advisory.Vuln.AffectedPackages = []domain.AffectedPackage{{Path: subjects[0].Package}}
	lane.Advisory.Vuln.AffectedSymbols = []domain.SymbolRef{{Package: subjects[0].Package, Symbol: subjects[0].Symbol}, {Package: subjects[1].Package, Symbol: subjects[1].Symbol}}
	pkg := subjects[0].Package
	lane.Advisory.Impls[0].Module = subjects[0].Module
	lane.Advisory.Impls[0].Package = &pkg
	lane.Advisory.Impls[0].Symbols = []string{subjects[0].Symbol, subjects[1].Symbol}
	partial := completeSymbolResult(subjects[:1])
	partial.Module = subjects[0].Module
	partial.Complete = false
	got := decide(t, symbolAuthorityInput(lane, subjects, partial, true))
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("partial fixture promoted: %+v", got)
	}
	full := completeSymbolResult(subjects)
	full.Module = subjects[0].Module
	lane.Affected.UnresolvedModules = []string{subjects[0].Module}
	got = decide(t, symbolAuthorityInput(lane, subjects, full, true))
	if got.Verdict != domain.VerdictNoExploitPathFound || got.Coverage != "COMPLETE" || got.NegativeVerification == nil || got.NegativeVerification.Status != domain.NegativeVerified || got.Verdict == domain.VerdictNotAffected {
		t.Fatalf("complete fixture projection=%+v", got)
	}
}

// symbolAuthorityCaseInput is the complete, valid authority case: the
// lane's single advisory-declared symbol is proven unreachable by a
// complete payload, and its module is left unresolved so the narrow
// unknown-release exception applies. The baseline must close, so every
// tampering test below changes exactly one binding.
func symbolAuthorityCaseInput(t *testing.T) DecisionInput {
	t.Helper()
	subjects := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	lane := decisionLane(domain.ClaimUnknown)
	lane.Affected.UnresolvedModules = []string{testModule}
	r := completeSymbolResult(subjects)
	r.Module = testModule
	in := symbolAuthorityInput(lane, subjects, r, true)
	if got := decide(t, in); got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("baseline authority case must close: %+v", got)
	}
	return in
}

// A src: locator is a tool-defined pointer, not authority evidence: it is
// never accepted without a matching audit pin.
func TestDeclaredSymbolAuthorityRejectsUnpinnedSrcRef(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	in.Trace.Observations[0].EvidenceRefs = []string{"src:internal/advisory/case.go:12"}
	got := decide(t, in)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "not audit-bound") {
		t.Fatalf("unpinned src: locator must not ground a closure: %+v", got)
	}
}

// A mutated trace payload with a still-valid audit index must not close:
// the authority decodes only the audit-recorded payload.
func TestDeclaredSymbolAuthorityRejectsMutatedPayload(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	mutated := completeSymbolResult([]FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}})
	mutated.Module = testModule
	mutated.Subjects = append(mutated.Subjects, goanalysis.UnreachabilitySubject{Package: "synthetic.test/other", Symbol: "Extra"})
	in.Trace.Observations[0] = decisionObservation(evidencetools.SymbolUnreachabilityTool,
		evidencetools.SymbolUnreachabilityData{Result: mutated})
	got := decide(t, in)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "does not match the persisted audit record") {
		t.Fatalf("mutated payload must not ground a closure: %+v", got)
	}
}

// A record whose declared arguments differ from the request is not an
// authority record for that observation.
func TestDeclaredSymbolAuthorityRejectsMismatchedRequest(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	in.Audit[0].Args = json.RawMessage(`{"module":"synthetic.test/other","subjects":["Extra"]}`)
	got := decide(t, in)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "bound to its recorded request") {
		t.Fatalf("mismatched request arguments must not ground a closure: %+v", got)
	}
}

// Without a drained session audit the authority route has nothing to
// decode from, so a caller-constructed trace copy cannot close.
func TestDeclaredSymbolAuthorityRequiresAuditRecord(t *testing.T) {
	for _, tc := range []struct {
		name  string
		audit []evidencetools.AuditRecord
	}{
		{"no audit at all", nil},
		{"record for a different observation", []evidencetools.AuditRecord{{Tool: evidencetools.SymbolUnreachabilityTool, Observation: &evidencetools.Observation{ID: "OBS-OTHER"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := symbolAuthorityCaseInput(t)
			in.Audit = tc.audit
			got := decide(t, in)
			if got.Verdict != domain.VerdictInconclusive {
				t.Fatalf("missing audit record must not ground a closure: %+v", got)
			}
		})
	}
}

func TestDeclaredSymbolAuthorityRejectsUnboundAuditRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record evidencetools.AuditRecord
	}{
		{"different observation id", evidencetools.AuditRecord{Tool: evidencetools.SymbolUnreachabilityTool, Args: testArgs(), Observation: &evidencetools.Observation{ID: "OBS-EXTRA"}}},
		{"unmatched tool and arguments", evidencetools.AuditRecord{Tool: "read_source", Args: json.RawMessage(`{"other":true}`), Observation: &evidencetools.Observation{ID: "OBS-EXTRA"}}},
		{"missing observation", evidencetools.AuditRecord{Tool: "read_source", Args: json.RawMessage(`{}`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := symbolAuthorityCaseInput(t)
			in.Audit = append(in.Audit, tc.record)
			got := decide(t, in)
			if got.Verdict != domain.VerdictInconclusive || got.Coverage == "COMPLETE" || got.NegativeVerification != nil || !strings.Contains(strings.Join(got.Limitations, " "), "cannot become a fact") {
				t.Fatalf("unbound audit row must block authority: %+v", got)
			}
		})
	}
}

func TestDeclaredSymbolAuthorityRejectsWrongRequestModule(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	args := evidencetools.SymbolUnreachabilityArgs{Module: "other.example/module", Subjects: []domain.SymbolRef{{Package: testPackage, Symbol: "Sink"}}}
	in.Trace.Requests[0].Arguments, _ = json.Marshal(args)
	in.Audit[0].Args = in.Trace.Requests[0].Arguments
	got := decide(t, in)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "declared authority module") {
		t.Fatalf("request/audit agreement on a foreign module must not bind authority: %+v", got)
	}
}

// Canonical payload binding must be order-insensitive but never
// fail-open: a value that cannot be canonicalized binds to nothing.
func TestBindDigestsFailsClosed(t *testing.T) {
	if bindDigests(make(chan int), make(chan int)) {
		t.Fatal("un-canonicalizable payloads must not bind")
	}
	if !bindDigests(map[string]any{"a": 1, "b": "x"}, struct {
		B string `json:"b"`
		A int    `json:"a"`
	}{B: "x", A: 1}) {
		t.Fatal("equivalent payloads must bind regardless of key order")
	}
	if bindDigests(map[string]any{"a": 1}, map[string]any{"a": 2}) {
		t.Fatal("different payloads must not bind")
	}
}

// symbolAuthorityObs is symbolAuthorityInput for a caller-shaped
// observation: the lane path mints PARTIAL/UNKNOWN observations for
// unclosed proofs, and the decision must still surface the primitive's
// own conclusion rather than a generic trace phrase.
func symbolAuthorityObs(lane *LaneResult, subjects []FactUsageSubject, o *evidencetools.Observation, withAudit bool) DecisionInput {
	attachDefectivePremise(lane)
	tr := decisionTrace(o)
	in := DecisionInput{Lane: lane, Trace: tr, Authority: &VerifiedFalsifierInput{Kind: domain.FalsifierDeclaredSymbolUnreached, ConditionID: "condition-1", RuleID: "rule.declared-symbols-unreached", Subjects: subjects}}
	if withAudit {
		in.Audit = decisionAudit(tr)
		in.ObservationIndex = VerificationObservationIndex(tr, in.Audit)
	}
	return in
}

// A disproven lane proof (PARTIAL observation, positive reach evidence
// in the payload) must surface the primitive's own conclusion: the
// declared symbols are reached, with the counts the payload recorded.
// The wording comes from the payload — mutating the recorded reference
// count changes the reason.
func TestDeclaredSymbolReasonDisproven(t *testing.T) {
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	res := completeSymbolResult(subs)
	res.Module = testModule
	res.Complete = false
	res.ProductReferences = []domain.CallSite{{File: "cmd/app/main.go", Line: 12, Function: "main"}, {File: "cmd/app/main.go", Line: 30, Function: "main"}}
	o := decisionObservation(evidencetools.SymbolUnreachabilityTool, evidencetools.SymbolUnreachabilityData{Result: res})
	o.Completeness = evidencetools.CompletenessPartial
	got := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o, true))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "is disproven") || !strings.Contains(got.Reason, "2 product reference(s)") || !strings.Contains(got.Reason, "reach the declared subject(s)") {
		t.Fatalf("reason does not name the disproven conclusion: %q", got.Reason)
	}
	if strings.Contains(got.Reason, "verification trace is incomplete") {
		t.Fatalf("generic trace phrase must not be the reason: %q", got.Reason)
	}
	if !strings.Contains(strings.Join(got.Limitations, "\n"), "is disproven") {
		t.Fatalf("named conclusion missing from limitations: %v", got.Limitations)
	}
	res2 := res
	res2.ProductReferences = append(res2.ProductReferences, domain.CallSite{File: "internal/x.go", Line: 5, Function: "f"})
	o2 := decisionObservation(evidencetools.SymbolUnreachabilityTool, evidencetools.SymbolUnreachabilityData{Result: res2})
	o2.Completeness = evidencetools.CompletenessPartial
	got2 := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o2, true))
	requireInconclusive(t, got2)
	if !strings.Contains(got2.Reason, "3 product reference(s)") || got2.Reason == got.Reason {
		t.Fatalf("payload mutation must change the reason:\n%q\n%q", got.Reason, got2.Reason)
	}
}

// An open-scope proof (UNKNOWN observation, non-closed payload) must
// name the primitive's own limitation list — the unresolved
// declaration, the open may-call inventory, the gated reference —
// never a generic scope phrase. Mutating the recorded limitations
// changes the reason.
func TestDeclaredSymbolReasonUnknownLimitations(t *testing.T) {
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	res := completeSymbolResult(subs)
	res.Module = testModule
	res.Complete = false
	res.DeclarationComplete = false
	res.Limitations = []string{
		"declaration of " + testPackage + ".Sink did not resolve inside the loaded module",
		"may-call candidate inventory is open: 2 site(s) with unproven targets",
		"build-gated reference to " + testPackage + ".Sink excluded by the recorded build context",
	}
	o := decisionObservation(evidencetools.SymbolUnreachabilityTool, evidencetools.SymbolUnreachabilityData{Result: res})
	o.Completeness = evidencetools.CompletenessUnknown
	got := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o, true))
	requireInconclusive(t, got)
	if !strings.Contains(got.Reason, "is UNKNOWN") || !strings.Contains(got.Reason, "open limitation(s)") {
		t.Fatalf("reason does not name the unknown conclusion: %q", got.Reason)
	}
	for _, want := range []string{"declaration", "may-call candidate inventory", "build-gated"} {
		if !strings.Contains(got.Reason, want) {
			t.Fatalf("reason missing named limitation %q: %q", want, got.Reason)
		}
	}
	if strings.Contains(got.Reason, "verification trace is incomplete") {
		t.Fatalf("generic trace phrase must not be the reason: %q", got.Reason)
	}
	res2 := res
	res2.Limitations = []string{"dependency caller inventory for " + testPackage + ".Sink is open"}
	o2 := decisionObservation(evidencetools.SymbolUnreachabilityTool, evidencetools.SymbolUnreachabilityData{Result: res2})
	o2.Completeness = evidencetools.CompletenessUnknown
	got2 := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o2, true))
	requireInconclusive(t, got2)
	if !strings.Contains(got2.Reason, "dependency caller inventory") || got2.Reason == got.Reason {
		t.Fatalf("payload mutation must change the reason:\n%q\n%q", got.Reason, got2.Reason)
	}
}

// A failed check (TIMEOUT/ERROR) and a skipped request are named
// failures: the decision reason identifies the recorded status and
// error text or the missing observation — never "the trace is
// incomplete". Mutating the recorded error changes the reason.
func TestDeclaredSymbolReasonToolFailure(t *testing.T) {
	subs := []FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}}
	t.Run("timeout", func(t *testing.T) {
		o := decisionObservation(evidencetools.SymbolUnreachabilityTool, nil)
		o.ToolStatus = evidencetools.StatusTimeout
		o.Completeness = evidencetools.CompletenessUnknown
		o.Error = "context deadline exceeded"
		got := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o, true))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "TIMEOUT") || !strings.Contains(got.Reason, "context deadline exceeded") {
			t.Fatalf("reason does not name the tool failure: %q", got.Reason)
		}
		if strings.Contains(got.Reason, "verification trace is incomplete") {
			t.Fatalf("generic trace phrase must not be the reason: %q", got.Reason)
		}
	})
	t.Run("error-mutation", func(t *testing.T) {
		o := decisionObservation(evidencetools.SymbolUnreachabilityTool, nil)
		o.ToolStatus = evidencetools.StatusError
		o.Completeness = evidencetools.CompletenessUnknown
		o.Error = "load driver failed: cannot load module list"
		got := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o, true))
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "ERROR") || !strings.Contains(got.Reason, "cannot load module list") {
			t.Fatalf("reason does not name the recorded error: %q", got.Reason)
		}
		o2 := decisionObservation(evidencetools.SymbolUnreachabilityTool, nil)
		o2.ToolStatus = evidencetools.StatusError
		o2.Completeness = evidencetools.CompletenessUnknown
		o2.Error = "load driver failed: module cache is corrupt"
		got2 := decide(t, symbolAuthorityObs(decisionLane(domain.ClaimTrue), subs, o2, true))
		requireInconclusive(t, got2)
		if !strings.Contains(got2.Reason, "module cache is corrupt") || got2.Reason == got.Reason {
			t.Fatalf("error mutation must change the reason:\n%q\n%q", got.Reason, got2.Reason)
		}
	})
	t.Run("skipped-request", func(t *testing.T) {
		tr := decisionTrace()
		tr.Complete = false
		tr.Requests = append(tr.Requests, VerificationRequest{ID: "check-1", Tool: evidencetools.SymbolUnreachabilityTool, Arguments: testArgs(), ConditionID: "condition-1"})
		lane := decisionLane(domain.ClaimTrue)
		attachDefectivePremise(lane)
		in := DecisionInput{Lane: lane, Trace: tr,
			Authority: &VerifiedFalsifierInput{Kind: domain.FalsifierDeclaredSymbolUnreached, ConditionID: "condition-1", RuleID: "rule.declared-symbols-unreached", Subjects: subs}}
		got := decide(t, in)
		requireInconclusive(t, got)
		if !strings.Contains(got.Reason, "produced no observation") || !strings.Contains(got.Reason, testModule) {
			t.Fatalf("reason does not name the skipped request: %q", got.Reason)
		}
	})
}

// configReachAdvisory declares the fixture dependency's QueryAll sink and
// keeps the analyzed version inside the affected range.
const configReachAdvisory = `{
  "id": "GO-TEST-0003",
  "summary": "config-origin post-reach fixture advisory",
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"ecosystem": "Go", "name": "example.com/confsnapdep"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
    "ecosystem_specific": {"imports": [{"path": "example.com/confsnapdep/transformer", "symbols": ["QueryAll"]}]}
  }],
  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
}`

// configLaneFixture materializes the post-reach fixture in a temp snapshot.
// mainSrc, when non-empty, replaces the fixture's main.go so a negative
// control can plant an external write, an alias write or a reflection
// write against the configuration field.
func configLaneFixture(t *testing.T, mainSrc string) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "configreachesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "snap")
	for _, name := range []string{
		"go.mod", "main.go",
		filepath.Join("snapdep", "go.mod"),
		filepath.Join("snapdep", "transformer", "transformer.go"),
	} {
		b, rerr := os.ReadFile(filepath.Join(src, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		full := filepath.Join(dst, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if mainSrc != "" {
		if err := os.WriteFile(filepath.Join(dst, "main.go"), []byte(mainSrc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// configLaneOpts runs the real lane over the fixture. withAssumption
// supplies an admitted product-scope config-trust document. declared=false
// omits the operator GOOS/GOARCH axes, producing a host-default lane.
func configLaneOpts(t *testing.T, mainSrc string, withAssumption bool, declared ...bool) (*LaneResult, string) {
	t.Helper()
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(configReachAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	o := LaneOptions{
		CVE: "GO-TEST-0003", SnapshotPath: configLaneFixture(t, mainSrc),
		AdvisoryFile: advPath, OutputDir: filepath.Join(dir, "out"),
		ExternalCommitSHA: "fixture-config-sha", Timeout: 2 * time.Minute,
	}
	if len(declared) == 0 || declared[0] {
		o.GOOS, o.GOARCH = runtime.GOOS, runtime.GOARCH
	}
	if withAssumption {
		trust := assumptionsUnit("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
		o.DeclaredAssumptions = writeAssumptionsDoc(t, dir, "assumptions.json", assumptionsUnitDoc(trust))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, o)
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	return lane, o.OutputDir
}

// The G1 positive: an exact mapstructure-tagged trigger argument reaches
// the advisory-declared sink at the exact argument position inside a
// complete advisory-bound sink closure, and an admitted product-scope
// config-trust assumption exists. The lane's own post-reach proof yields
// NO_EXPLOIT_PATH_FOUND grounded on config-origin, never NOT_AFFECTED,
// and the report keeps evidence and policy ids in separate fields.
func TestLanePostReachConfigCloses(t *testing.T) {
	lane, out := configLaneOpts(t, "", true)
	if lane.ConfigProof == nil {
		t.Fatalf("lane did not close the post-reach route; affected=%+v", lane.Affected)
	}
	d := lane.ConfigProof.Decision
	if d.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict = %s, want NO_EXPLOIT_PATH_FOUND", d.Verdict)
	}
	if d.Verdict == domain.VerdictNotAffected {
		t.Fatal("the post-reach route must never produce NOT_AFFECTED")
	}
	if d.Falsifier != domain.FalsifierTrustedInfrastructure || d.GroundBasis != domain.BasisConfigOrigin {
		t.Fatalf("falsifier/basis = %s/%s", d.Falsifier, d.GroundBasis)
	}
	if len(d.AssumptionIDs) != 1 || d.AssumptionIDs[0] != "ASM-CONFIG-TRUST" {
		t.Fatalf("assumption ids = %v", d.AssumptionIDs)
	}
	if d.NegativeVerification == nil || d.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("negative verification = %+v", d.NegativeVerification)
	}
	if d.Coverage != "COMPLETE" || len(d.EvidenceRefs) == 0 {
		t.Fatalf("coverage/refs = %q/%v", d.Coverage, d.EvidenceRefs)
	}

	vr, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	if vr.Verdict != domain.VerdictNoExploitPathFound || vr.GroundBasis != domain.BasisConfigOrigin {
		t.Fatalf("VerifyDecision = %s/%s", vr.Verdict, vr.GroundBasis)
	}

	r := Assemble(AssembleInput{
		Lane: lane, Decision: &vr, DeterministicOnly: true, RunID: "config-reach",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if err := Validate(r, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
	if r.Decision.GroundBasis != domain.BasisConfigOrigin || len(r.Decision.AssumptionIDs) != 1 {
		t.Fatalf("report decision basis/assumptions = %q/%v", r.Decision.GroundBasis, r.Decision.AssumptionIDs)
	}
	refs := strings.Join(r.Decision.EvidenceRefs, ",")
	if strings.Contains(refs, "ASM-CONFIG-TRUST") {
		t.Fatalf("assumption id cited as evidence: %s", refs)
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Verdict basis", "config-origin", "ASM-CONFIG-TRUST",
		"administrator-managed configuration is outside the attacker model",
	} {
		if !strings.Contains(string(md), want) {
			t.Fatalf("report markdown lacks %q:\n%s", want, md)
		}
	}
}

// Without the declared config-trust assumption the route does not apply:
// provenance alone is not a trust policy, so the lane stays INCONCLUSIVE.
func TestLanePostReachConfigNeedsAssumption(t *testing.T) {
	lane, _ := configLaneOpts(t, "", false)
	if lane.ConfigProof != nil {
		t.Fatalf("route closed without an admitted assumption: %+v", lane.ConfigProof.Decision)
	}
	vr, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	if vr.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict without assumption = %s, want INCONCLUSIVE", vr.Verdict)
	}
}

const configExternalWriteMain = `package main

import (
	"os"

	"example.com/confsnapdep/transformer"
)

type Settings struct {
	Expression string ` + "`mapstructure:\"expression\"`" + `
}

func load() Settings {
	var s Settings
	return s
}

func main() {
	s := load()
	s.Expression = os.Args[1]
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}
`

const configAliasWriteMain = `package main

import (
	"os"

	"example.com/confsnapdep/transformer"
)

type Settings struct {
	Expression string ` + "`mapstructure:\"expression\"`" + `
}

func load() Settings {
	var s Settings
	return s
}

func main() {
	s := load()
	p := &s.Expression
	*p = os.Args[1]
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}
`

const configReflectWriteMain = `package main

import (
	"os"
	"reflect"

	"example.com/confsnapdep/transformer"
)

type Settings struct {
	Expression string ` + "`mapstructure:\"expression\"`" + `
}

func load() Settings {
	var s Settings
	return s
}

func main() {
	s := load()
	v := reflect.ValueOf(&s).Elem().FieldByName("Expression")
	v.SetString(os.Args[1])
	_, _ = transformer.QueryAll(&transformer.Node{}, s.Expression)
}
`

// An external write, a pointer alias and a reflection write each outrank
// the mapstructure tag: with the assumption admitted the lane still must
// not fabricate a configuration proof, and VerifyDecision stays
// INCONCLUSIVE.
func TestLanePostReachConfigWritePathsBlock(t *testing.T) {
	for name, src := range map[string]string{
		"external-write": configExternalWriteMain,
		"alias-write":    configAliasWriteMain,
		"reflect-write":  configReflectWriteMain,
	} {
		t.Run(name, func(t *testing.T) {
			lane, _ := configLaneOpts(t, src, true)
			if lane.ConfigProof != nil {
				t.Fatalf("%s fabricated a config proof: %+v", name, lane.ConfigProof.Decision)
			}
			vr, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane})
			if err != nil {
				t.Fatal(err)
			}
			if vr.Verdict != domain.VerdictInconclusive {
				t.Fatalf("%s verdict = %s, want INCONCLUSIVE", name, vr.Verdict)
			}
		})
	}
}

// The authority gate re-checks every element: a mutated proof (coverage,
// basis, assumption, recorded check) never becomes a verdict.
func TestVerifyPostReachConfigRejectsMalformed(t *testing.T) {
	lane, _ := configLaneOpts(t, "", true)
	if lane.ConfigProof == nil {
		t.Fatal("fixture did not produce a config proof")
	}
	base := *lane.ConfigProof
	for name, mutate := range map[string]func(*LaneConfigProof){
		"coverage":      func(p *LaneConfigProof) { p.Decision.Coverage = "INSUFFICIENT_SCOPE" },
		"no-basis":      func(p *LaneConfigProof) { p.Decision.GroundBasis = "" },
		"no-assumption": func(p *LaneConfigProof) { p.Decision.AssumptionIDs = nil },
		"no-check":      func(p *LaneConfigProof) { p.ObservationID = "" },
		"no-refs":       func(p *LaneConfigProof) { p.Decision.EvidenceRefs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			p.Decision = base.Decision
			mutate(&p)
			l := *lane
			l.ConfigProof = &p
			vr, err := VerifyDecision(context.Background(), DecisionInput{Lane: &l})
			if err != nil {
				t.Fatal(err)
			}
			if vr.Verdict != domain.VerdictInconclusive {
				t.Fatalf("malformed proof %s produced %s", name, vr.Verdict)
			}
		})
	}
}

// A negative proof claims something about the whole requested advisory.
// Under a partial scope — the loaded record covers only its known
// entries — no negative authority may close: the proposal route, the
// declared-symbol authority and the lane's post-reach configuration
// proof each stay INCONCLUSIVE with the scoped gap named, while their
// exact-entry counterparts keep their existing closing.
func TestVerifyDecisionPartialScopeBlocksNegativeAuthorities(t *testing.T) {
	t.Run("proposal route", func(t *testing.T) {
		in := decisionInput(decisionLane(domain.ClaimTrue),
			decisionProposal(domain.FalsifierPackageAbsent),
			decisionTrace(decisionObservation(evidencetools.UsageScopeTool, absentData())))
		if got := decide(t, in); got.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("exact-entry proposal route must close: %+v", got)
		}
		in.Lane.Affected.Scope = partialCVEScope()
		got := decide(t, in)
		if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "scoped applicability gap") {
			t.Fatalf("partial scope must refuse the proposal close: %+v", got)
		}
	})

	t.Run("declared-symbol authority", func(t *testing.T) {
		// symbolAuthorityCaseInput asserts its own exact-entry closing.
		in := symbolAuthorityCaseInput(t)
		in.Lane.Affected.Scope = partialCVEScope()
		got := decide(t, in)
		if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "scoped applicability gap") {
			t.Fatalf("partial scope must refuse the symbol authority: %+v", got)
		}
	})

	t.Run("post-reach config proof", func(t *testing.T) {
		lane, _ := configLaneOpts(t, "", true)
		if lane.ConfigProof == nil {
			t.Fatalf("fixture did not produce a config proof: %+v", lane.Affected)
		}
		exact, err := VerifyDecision(context.Background(), DecisionInput{Lane: lane})
		if err != nil || exact.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("exact-entry config proof must close: %+v err %v", exact, err)
		}
		partial := *lane
		partial.Affected.Scope = partialCVEScope()
		got := decide(t, DecisionInput{Lane: &partial})
		if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "scoped applicability gap") {
			t.Fatalf("partial scope must refuse the config-proof close: %+v", got)
		}
	})
}

// The declared-symbol authority is a deadness negative: without the admitted
// invocation-necessity premise the same complete kernel proof stays
// INCONCLUSIVE. This is the live and replay gate — a saved TRUE/VERIFIED
// claim cannot substitute for the contract.
func TestDeclaredSymbolAuthorityRequiresInvocationNecessity(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	in.Lane.DefectSemantics = nil
	got := decide(t, in)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "invocation-necessity premise") {
		t.Fatalf("missing premise must refuse the close: %+v", got)
	}
}

// An OMITTED_CHECK contract binds the omission site, not the absent check.
// The same check-only proof cannot dismiss a genuine omission.
func TestDeclaredSymbolAuthorityOmissionContractRefusesCheckDeadness(t *testing.T) {
	in := symbolAuthorityCaseInput(t)
	check := declaredSymbolRefs(in.Lane)[0]
	pipeline := domain.SymbolRef{Package: check.Package, Symbol: "OmissionSite"}
	in.Lane.DefectSemantics = &domain.DefectSemanticsContract{
		Mode:     domain.DefectSemanticsOmittedCheck,
		RecordID: "GO-TEST-OMISSION",
		Check:    check,
		Pipeline: &pipeline,
	}
	got := decide(t, in)
	if got.Verdict != domain.VerdictInconclusive || !strings.Contains(got.Reason, "invocation-necessity premise") {
		t.Fatalf("omission contract must refuse check-only deadness: %+v", got)
	}
}
