package evidencetools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"

	"github.com/davniy/izyan/internal/vulnerability"
)

var testVuln = &domain.Vulnerability{
	ID:      "GO-TEST-0001",
	Module:  "example.com/snapdep",
	Package: "example.com/snapdep/vuln",
	AffectedSymbols: []domain.SymbolRef{
		{Package: "example.com/snapdep/vuln", Symbol: "Parse"},
	},
	AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.0.1"}},
	FixedVersions:    []string{"1.0.1"},
}

// newTestSession builds a session over the committed fixture with
// everything offline: a static advisory source and no network/exec.
func newTestSession(t *testing.T) *Session {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(SessionConfig{
		CVEID:        "GO-TEST-0001",
		SnapshotRoot: root,
		ExternalSHA:  "testsha0123456789",
		VulnSource:   vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:        NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// TestToolCompletenessMatrix drives real handlers and asserts the status
// and completeness of each Observation class.
func TestToolCompletenessMatrix(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Closed-scope reads are COMPLETE.
	o := s.invoke(ctx, "read_source", nil, func(c context.Context) (*Observation, error) {
		return s.readSource(c, readSourceArgs{File: "main.go"})
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	if d, ok := o.Data.(sourceData); !ok || !strings.Contains(d.Source, "vuln.Parse") {
		t.Fatalf("read_source data: %+v", o.Data)
	}

	// Module graph: enumerated closed set -> COMPLETE (local replace).
	o = s.invoke(ctx, "get_dependency_graph", nil, func(c context.Context) (*Observation, error) {
		return s.getDependencyGraph(c)
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	if d, ok := o.Data.(dependencyGraphData); !ok || d.Count == 0 {
		t.Fatalf("dependency graph empty: %+v", o)
	}

	// find_symbol: present -> COMPLETE.
	o = s.invoke(ctx, "find_symbol", nil, func(c context.Context) (*Observation, error) {
		return s.findSymbol(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "Parse"})
	})
	assertObs(t, o, StatusOK, CompletenessComplete)

	// find_symbol: absent inside a loaded package -> OK empty COMPLETE.
	o = s.invoke(ctx, "find_symbol", nil, func(c context.Context) (*Observation, error) {
		return s.findSymbol(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "Nope"})
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	if d, ok := o.Data.(findSymbolData); !ok || d.Found {
		t.Fatalf("find_symbol should report absent: %+v", o.Data)
	}

	// find_callers: product-scope positive result, still PARTIAL.
	o = s.invoke(ctx, "find_callers", nil, func(c context.Context) (*Observation, error) {
		return s.findCallers(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "Parse"})
	})
	assertObs(t, o, StatusOK, CompletenessPartial)
	if d, ok := o.Data.(callersData); !ok || d.Count != 2 {
		t.Fatalf("find_callers expected 2 sites: %+v", o.Data)
	}

	// find_callers on a symbol with no product callers: OK empty PARTIAL —
	// must NOT be a complete negative.
	o = s.invoke(ctx, "find_callers", nil, func(c context.Context) (*Observation, error) {
		return s.findCallers(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "helper"})
	})
	assertObs(t, o, StatusOK, CompletenessPartial)
	if d, ok := o.Data.(callersData); !ok || d.Count != 0 {
		t.Fatalf("expected 0 callers: %+v", o.Data)
	}

	// trace_argument on a position inside the loaded scope that is not a
	// call -> UNSUPPORTED (scoped limitation), not an execution ERROR.
	o = s.invoke(ctx, "trace_argument", nil, func(c context.Context) (*Observation, error) {
		return s.traceArgument(c, traceArgumentArgs{File: "main.go", Line: 9000, ArgIndex: 0})
	})
	assertObs(t, o, StatusUnsupported, CompletenessUnknown)

	// run_build without --allow-exec -> UNSUPPORTED.
	o = s.invoke(ctx, "run_build", nil, func(c context.Context) (*Observation, error) {
		return s.runBuild(c)
	})
	assertObs(t, o, StatusUnsupported, CompletenessUnknown)
}

// TestCallSiteScopeBinding is the task-3 regression: call-site-only tools
// must succeed on a real call position (the in-fixture analogue of the
// connection.go:48 call site recorded in the ADR) and report an explicit
// UNSUPPORTED scope limitation on a declaration position — never a
// misleading ERROR, never a vacuous OK.
func TestCallSiteScopeBinding(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Real call site: vuln.Parse(...) inside handle (main.go:27).
	o := s.invoke(ctx, "find_callers", nil, func(c context.Context) (*Observation, error) {
		return s.findCallers(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "Parse"})
	})
	assertObs(t, o, StatusOK, CompletenessPartial)
	d, ok := o.Data.(callersData)
	if !ok || len(d.CallSites) == 0 {
		t.Fatalf("find_callers data: %+v", o.Data)
	}
	call := d.CallSites[0]
	if call.File == "" || call.Line == 0 || call.Column == 0 {
		t.Fatalf("call site missing position fields: %+v", call)
	}
	for _, tc := range []struct {
		tool string
		fn   func(context.Context) (*Observation, error)
	}{
		{"trace_argument", func(c context.Context) (*Observation, error) {
			return s.traceArgument(c, traceArgumentArgs{File: call.File, Line: call.Line, Column: call.Column, ArgIndex: -1})
		}},
		{"find_validations", func(c context.Context) (*Observation, error) {
			return s.findValidations(c, findValidationsArgs{File: call.File, Line: call.Line, Column: call.Column, ArgIndex: -1})
		}},
		{"check_call_site_guard", func(c context.Context) (*Observation, error) {
			return s.checkCallSiteGuard(c, callSiteGuardArgs{File: call.File, Line: call.Line, Column: call.Column})
		}},
	} {
		obs := s.invoke(ctx, tc.tool, nil, tc.fn)
		if obs.ToolStatus != StatusOK {
			t.Fatalf("%s on real call site %+v: status=%s err=%q", tc.tool, call, obs.ToolStatus, obs.Error)
		}
	}

	// Declaration position: the find_symbol site of Parse itself. The
	// dep package was loaded by find_symbol, so this exercises the
	// "file in scope, position not a call" branch exactly.
	o = s.invoke(ctx, "find_symbol", nil, func(c context.Context) (*Observation, error) {
		return s.findSymbol(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "Parse"})
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	sd, ok := o.Data.(findSymbolData)
	if !ok || !sd.Found || sd.Site == nil {
		t.Fatalf("find_symbol data: %+v", o.Data)
	}
	decl := *sd.Site
	for _, tc := range []struct {
		tool string
		fn   func(context.Context) (*Observation, error)
	}{
		{"trace_argument", func(c context.Context) (*Observation, error) {
			return s.traceArgument(c, traceArgumentArgs{File: decl.File, Line: decl.Line, Column: decl.Column, ArgIndex: -1})
		}},
		{"find_validations", func(c context.Context) (*Observation, error) {
			return s.findValidations(c, findValidationsArgs{File: decl.File, Line: decl.Line, Column: decl.Column, ArgIndex: -1})
		}},
		{"check_call_site_guard", func(c context.Context) (*Observation, error) {
			return s.checkCallSiteGuard(c, callSiteGuardArgs{File: decl.File, Line: decl.Line, Column: decl.Column})
		}},
	} {
		obs := s.invoke(ctx, tc.tool, nil, tc.fn)
		assertObs(t, obs, StatusUnsupported, CompletenessUnknown)
		if !strings.Contains(obs.Scope, "not an AST call") || !strings.Contains(obs.Error, "call site not found") {
			t.Fatalf("%s on declaration: scope=%q err=%q", tc.tool, obs.Scope, obs.Error)
		}
		if len(obs.Limitations) == 0 {
			t.Fatalf("%s on declaration: no scoped limitation recorded", tc.tool)
		}
	}
}

// TestScopeDetailsContent checks the scope block carries the facts an
// agent needs to reason about coverage.
func TestScopeDetailsContent(t *testing.T) {
	s := newTestSession(t)
	o := s.invoke(context.Background(), "find_callers", nil, func(c context.Context) (*Observation, error) {
		return s.findCallers(c, symbolRefArgs{Package: "example.com/snapdep/vuln", Symbol: "Parse"})
	})
	if o.ScopeDetails == nil {
		t.Fatal("scope_details missing")
	}
	if o.ScopeDetails.SnapshotHash == "" || o.ScopeDetails.BuildContext == nil {
		t.Fatalf("scope details incomplete: %+v", o.ScopeDetails)
	}
	if len(o.Limitations) == 0 {
		t.Fatal("find_callers must carry scope limitations")
	}
}

// TestObservationIDsAreUniqueAndAudited verifies the audit sink receives
// each real invocation.
func TestObservationIDsAreUniqueAndAudited(t *testing.T) {
	s := newTestSession(t)
	var recs []AuditRecord
	s.Audit = AuditFunc(func(_ context.Context, r AuditRecord) { recs = append(recs, r) })
	for range 3 {
		s.invoke(context.Background(), "read_source", nil, func(c context.Context) (*Observation, error) {
			return s.readSource(c, readSourceArgs{File: "main.go", Start: 1, End: 3})
		})
	}
	if len(recs) != 3 {
		t.Fatalf("audit records=%d", len(recs))
	}
	seen := map[string]bool{}
	for i, r := range recs {
		if r.Observation == nil || r.Observation.Tool != "read_source" {
			t.Fatalf("bad record %+v", r)
		}
		want := fmt.Sprintf("OBS-%04d", i+1)
		if r.Observation.ID != want {
			t.Fatalf("id=%q want %q", r.Observation.ID, want)
		}
		if seen[r.Observation.ID] {
			t.Fatalf("duplicate observation id %s", r.Observation.ID)
		}
		seen[r.Observation.ID] = true
	}
}

// releaseStubTool answers ListModules with a fixed source-graph listing;
// package listing is irrelevant for the module-version handlers.
type releaseStubTool struct{ modules []byte }

func (t releaseStubTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return t.modules, "go list -m -json all", nil
}
func (t releaseStubTool) ListPackages(context.Context, string, domain.ProductSnapshot) ([]byte, error) {
	return nil, nil
}
func (t releaseStubTool) ListPackagesScope(context.Context, string, domain.ProductSnapshot, bool) ([]byte, error) {
	return nil, nil
}

// With an authoritative release module graph, get_module_version keeps
// reporting the source-graph answer but additionally names the
// release-graph version that grounds release applicability.
func TestReleaseModuleVersionAxisReported(t *testing.T) {
	s := newTestSession(t)
	_, err := s.probeSnapshot(context.Background())
	must(t, err)
	s.GoTool = releaseStubTool{modules: []byte(
		`{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v0.9.0"}`)}
	s.Build.ReleaseModules = []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.4.0"}}
	s.Build.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status:          domain.ReleaseStatusResolved,
		SelectedVersion: "go1.42.0",
		SelectedSource:  domain.GoVersionSourceBinary,
		SelectedTrust:   domain.ReleaseTrustAuthoritative,
		ArtifactSHA256:  "aa11", BinaryMember: "bundle/bin/tool", BuildInfoSHA256: "bb22",
	}
	s.Build.ReleaseEvidenceRequired = true
	s.snap = &s.Build
	o := s.invoke(context.Background(), "get_module_version", nil,
		func(c context.Context) (*Observation, error) {
			return s.getModuleVersion(c, getModuleVersionArgs{Module: "example.com/dep"})
		})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d, ok := o.Data.(moduleVersionData)
	if !ok {
		t.Fatalf("data type %T", o.Data)
	}
	if d.EffectiveVersion != "v0.9.0" || d.Source != "go list -m -json all" {
		t.Fatalf("source answer changed: %+v", d)
	}
	if d.ReleaseVersion != "v1.4.0" || d.ReleasePresent == nil || !*d.ReleasePresent {
		t.Fatalf("release graph answer missing: %+v", d)
	}
	if o.ScopeDetails.Extra["release_artifact_sha256"] != "aa11" ||
		o.ScopeDetails.Extra["version_axis_graph"] != "release_module_graph" {
		t.Fatalf("provenance extra = %v", o.ScopeDetails.Extra)
	}
}

// A requested channel that failed leaves the release version undecidable:
// the source version is reported for provenance but named as such.
func TestReleaseModuleVersionBlocked(t *testing.T) {
	s := newTestSession(t)
	_, err := s.probeSnapshot(context.Background())
	must(t, err)
	s.GoTool = releaseStubTool{modules: []byte(
		`{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v0.9.0"}`)}
	s.Build.ReleaseEvidenceRequired = true
	s.Build.ReleaseEvidence = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusNotRun, ReasonCode: domain.ReleaseReasonArtifactDownloadFailed}
	s.snap = &s.Build
	o := s.invoke(context.Background(), "get_module_version", nil,
		func(c context.Context) (*Observation, error) {
			return s.getModuleVersion(c, getModuleVersionArgs{Module: "example.com/dep"})
		})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d, ok := o.Data.(moduleVersionData)
	if !ok {
		t.Fatalf("data type %T", o.Data)
	}
	if d.ReleaseVersion != "" || d.ReleaseStatus != "NOT_RUN" ||
		d.ReleaseReason != domain.ReleaseReasonArtifactDownloadFailed {
		t.Fatalf("blocked release axis must not serve the source version: %+v", d)
	}
	if o.ScopeDetails.Extra["version_axis_graph"] != "unavailable" {
		t.Fatalf("blocked graph extra = %v", o.ScopeDetails.Extra)
	}
	if !strings.Contains(o.Fact, "undecidable") {
		t.Fatalf("fact must name the undecidable release axis: %q", o.Fact)
	}
}

// Duplicate release-graph entries with disagreeing effective versions are
// a conflict: no release version is served.
func TestReleaseModuleGraphConflictUndecidable(t *testing.T) {
	s := newTestSession(t)
	_, err := s.probeSnapshot(context.Background())
	must(t, err)
	s.GoTool = releaseStubTool{modules: []byte(
		`{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v0.9.0"}`)}
	s.Build.ReleaseModules = []domain.ReleaseModule{
		{Path: "example.com/dep", Version: "v1.0.0"},
		{Path: "example.com/dep", Version: "v1.4.0"},
	}
	s.Build.ReleaseEvidence = &domain.ReleaseEvidenceSummary{Status: domain.ReleaseStatusResolved}
	s.snap = &s.Build
	o := s.invoke(context.Background(), "get_module_version", nil,
		func(c context.Context) (*Observation, error) {
			return s.getModuleVersion(c, getModuleVersionArgs{Module: "example.com/dep"})
		})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d, ok := o.Data.(moduleVersionData)
	if !ok {
		t.Fatalf("data type %T", o.Data)
	}
	if d.ReleaseVersion != "" || d.ReleaseStatus != string(domain.ReleaseStatusConflicted) ||
		d.ReleaseReason != domain.ReleaseReasonConflict {
		t.Fatalf("conflicting graph must resolve nothing: %+v", d)
	}
}

// With no release evidence at all, nothing is stamped: the observation
// keeps its exact legacy shape.
func TestReleaseProvenanceExtraAbsent(t *testing.T) {
	s := newTestSession(t)
	if extra := ReleaseProvenanceExtra(s.snapshotReleaseView()); extra != nil {
		t.Fatalf("no release evidence must yield nil extra: %v", extra)
	}
	_, err := s.probeSnapshot(context.Background())
	must(t, err)
	s.Build.ReleaseEvidence, s.Build.ReleaseModules = nil, nil
	s.Build.ReleaseEvidenceRequired = false
	s.snap = &s.Build
	s.GoTool = releaseStubTool{modules: []byte(
		`{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v0.9.0"}`)}
	o := s.invoke(context.Background(), "get_module_version", nil,
		func(c context.Context) (*Observation, error) {
			return s.getModuleVersion(c, getModuleVersionArgs{Module: "example.com/dep"})
		})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d, ok := o.Data.(moduleVersionData)
	if !ok {
		t.Fatalf("data type %T", o.Data)
	}
	if d.ReleaseStatus != "" || d.ReleasePresent != nil || d.ReleaseVersion != "" {
		t.Fatalf("legacy payload must not carry release fields: %+v", d)
	}
}

// The session's snapshot probe must honor the release-evidence channels
// the lane resolved: ReleaseMetadata passed via SessionConfig surfaces in
// the probed snapshot's evidence, modules, and required flag — the same
// view snapshotReleaseView and release provenance extras read.
func TestReleaseMetadataSessionProbe(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(SessionConfig{
		CVEID:        "GO-TEST-0001",
		SnapshotRoot: root,
		ExternalSHA:  "testsha0123456789",
		VulnSource:   vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:        NopAudit{},
		ReleaseMetadata: &domain.ReleaseEvidenceSummary{
			Status: domain.ReleaseStatusResolved,
			Items: []domain.ReleaseEvidenceItem{{
				Version:    "go1.42.0",
				Source:     domain.GoVersionSourceExplicit,
				TrustClass: domain.ReleaseTrustAuthoritative,
			}},
			Modules: []domain.ReleaseModule{{Path: "example.com/snapdep", Version: "v1.4.0"}},
		},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	snap, err := s.probeSnapshot(context.Background())
	if err != nil {
		t.Fatalf("probeSnapshot: %v", err)
	}
	if snap.ReleaseGoVersion != "go1.42.0" ||
		snap.ReleaseEvidence.Status != domain.ReleaseStatusResolved {
		t.Fatalf("session probe must resolve supplied metadata: %q %s",
			snap.ReleaseGoVersion, snap.ReleaseEvidence.Status)
	}
	if len(snap.ReleaseModules) != 1 || !snap.ReleaseEvidenceRequired {
		t.Fatalf("release modules/required flag must flow to the session snapshot: %+v required=%v",
			snap.ReleaseModules, snap.ReleaseEvidenceRequired)
	}
	// The session build context adopts the release view, so provenance
	// extras and get_module_version see the authoritative axis.
	view := s.snapshotReleaseView()
	if extra := ReleaseProvenanceExtra(view); extra == nil ||
		extra["version_axis_graph"] != "release_module_graph" {
		t.Fatalf("session provenance extras = %v", extra)
	}
}

func assertObs(t *testing.T, o *Observation, status ToolStatus, c Completeness) {
	t.Helper()
	if o == nil {
		t.Fatal("nil observation")
	}
	if o.ToolStatus != status || o.Completeness != c {
		t.Fatalf("obs tool_status=%s completeness=%s (want %s/%s); fact=%q err=%q lims=%v",
			o.ToolStatus, o.Completeness, status, c, o.Fact, o.Error, o.Limitations)
	}
	if o.ID == "" {
		t.Fatal("observation has no id")
	}
}
