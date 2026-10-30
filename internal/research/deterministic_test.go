package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/repository"
)

// TestDeterministicLane_Fixture runs the real lane end-to-end over the
// committed evidencesnap fixture plus a frozen advisory that names its
// snapdep/vuln.Parse symbol. This exercises every §5.1 step offline
// (external identity supplied, so no git probe runs).
func TestDeterministicLane_Fixture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0001",
	  "aliases": ["CVE-TEST-1"],
	  "summary": "test advisory for snapdep Parse",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  },{
	    "package": {"ecosystem": "npm", "name": "left-pad"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	advPath := filepath.Join(dir, "GO-TEST-0001.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GO-TEST-0001", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-1",
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	if lane.ContentHash == "" {
		t.Fatal("no content hash")
	}
	// persisted artifacts exist and are referenced
	for _, f := range lane.Facts {
		full := filepath.Join(out, f.Artifact.Path)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("artifact for %s missing: %v", f.ID, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "observations.jsonl")); err != nil {
		t.Fatal("observations.jsonl missing")
	}
	if _, err := os.Stat(filepath.Join(out, "deterministic-facts.json")); err != nil {
		t.Fatal("deterministic-facts.json missing")
	}
	// tool order sanity: preflight before session tools before govulncheck
	var tools []string
	for _, o := range lane.Observations {
		tools = append(tools, o.Tool)
	}
	wantPrefix := []string{"repository-preflight", "repository-snapshot", "advisory-load",
		"get_product_snapshot", "get_vulnerability", "get_dependency_graph"}
	for i, w := range wantPrefix {
		if i >= len(tools) || tools[i] != w {
			t.Fatalf("tool order mismatch at %d: got %v", i, tools)
		}
	}
	if tools[len(tools)-1] != "run_govulncheck" {
		t.Fatalf("last tool = %s, want run_govulncheck (UNSUPPORTED without db)", tools[len(tools)-1])
	}
	// the npm entry stays as non-go, never a product fact
	var npm *AffectedImplementation
	for i := range lane.Advisory.Impls {
		if lane.Advisory.Impls[i].Module == "left-pad" {
			npm = &lane.Advisory.Impls[i]
		}
	}
	if npm == nil || npm.Binding != BindNonGo {
		t.Fatalf("non-Go entry lost or misbound: %+v", npm)
	}
	// applicability resolved through the replace (effective path)
	if string(lane.Affected.ModulePresent) != "TRUE" {
		t.Fatalf("module_present=%s, want TRUE (replaced module present)", lane.Affected.ModulePresent)
	}
	// assembly+validation of the deterministic-only report
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "fixture",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.AgentOutput.Status != AgentNotRequested {
		t.Fatal("agent ran in deterministic-only")
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("fixture report invalid:\n%v", err)
	}
	// the symbol Parse must have produced a find_symbol OK observation
	foundParse := false
	for _, o := range lane.Observations {
		if o.Tool == "find_symbol" && o.ToolStatus == "OK" && strings.Contains(o.Fact, "Parse") {
			foundParse = true
		}
	}
	if !foundParse {
		t.Log("no find_symbol OK for Parse — checking errors instead")
		for _, o := range lane.Observations {
			if o.Tool == "find_symbol" {
				t.Logf("find_symbol %s %s %s", o.ToolStatus, o.Fact, o.Error)
			}
		}
		t.Fatal("Parse symbol never observed")
	}
	// Task 3 regression: the find_symbol declaration site of Parse must
	// never reach the call-site-only tools. boundSites is fed only by
	// find_callers (column-qualified positions), so trace_argument,
	// find_validations and check_call_site_guard see real call sites —
	// at least one OK each and no ERROR "check not performed" records.
	callSiteTools := map[string]struct{ ok, errs int }{}
	for _, o := range lane.Observations {
		switch o.Tool {
		case "trace_argument", "find_validations", "check_call_site_guard":
			st := callSiteTools[o.Tool]
			switch o.ToolStatus {
			case evidencetools.StatusOK:
				st.ok++
			case evidencetools.StatusError:
				st.errs++
			}
			callSiteTools[o.Tool] = st
		}
	}
	for tool, st := range callSiteTools {
		if st.errs > 0 {
			t.Errorf("%s produced %d ERROR observation(s) — a non-call position reached the tool", tool, st.errs)
		}
	}
	if len(callSiteTools) == 0 {
		t.Fatal("no call-site tool observations — find_callers bound no sites")
	}
	for tool, st := range callSiteTools {
		if st.ok == 0 {
			t.Errorf("%s never produced an OK observation over real call sites", tool)
		}
	}

	// B41 (Task 3): the advisory-declared package gets exactly one
	// usage-scope check — a package-level subject, never a symbol one —
	// immediately after the package-usage block. snapdep/vuln is
	// imported only by product code (the fixture has no test files), so
	// the promoted fact records usage_scope=product with no
	// product-absence marker and the optional /3 axis is ESTABLISHED.
	var scopeArgs []string
	lastUsagePos, firstScopePos := -1, -1
	for i, rec := range lane.Records {
		switch rec.Tool {
		case evidencetools.PackageUsageTool:
			lastUsagePos = i
		case evidencetools.UsageScopeTool:
			if firstScopePos < 0 {
				firstScopePos = i
			}
			var a struct {
				Module  string `json:"module"`
				Package string `json:"package"`
			}
			_ = json.Unmarshal(rec.Args, &a)
			scopeArgs = append(scopeArgs, a.Module+"|"+a.Package)
		}
	}
	if len(scopeArgs) != 1 || scopeArgs[0] != "example.com/snapdep|example.com/snapdep/vuln" {
		t.Fatalf("usage-scope subjects = %v, want the single advisory-declared package", scopeArgs)
	}
	if lastUsagePos < 0 || firstScopePos <= lastUsagePos {
		t.Fatalf("usage-scope must run immediately after the package-usage block (usage=%d scope=%d)", lastUsagePos, firstScopePos)
	}
	var scopeFact *VerifiedFact
	for i := range lane.Facts {
		if lane.Facts[i].Kind == FactKindBuildUsageScope {
			scopeFact = &lane.Facts[i]
		}
	}
	if scopeFact == nil {
		t.Fatal("no BUILD_USAGE_SCOPE fact promoted")
	}
	if scopeFact.UsageScope != "product" || scopeFact.ProductAbsenceVerification != "" ||
		scopeFact.NegativeVerification != "" || scopeFact.Claim != "TRUE" || scopeFact.Coverage != "COMPLETE" {
		t.Fatalf("B41 fact shape: %+v", scopeFact)
	}
	if scopeFact.UsageSubject == nil || scopeFact.UsageSubject.Package != "example.com/snapdep/vuln" ||
		scopeFact.UsageSubject.Symbol != "" {
		t.Fatalf("B41 fact subject %+v", scopeFact.UsageSubject)
	}
	ax := r.ExploitationAxes.BuildUsageScope
	if ax == nil || ax.Status != AxisEstablished || ax.Level != LevelPackageBuild ||
		ax.Basis != AxisBasisDeterministic || len(ax.EvidenceRefs) != 1 ||
		ax.EvidenceRefs[0] != scopeFact.ID {
		t.Fatalf("build_usage_scope axis = %+v", ax)
	}
	for _, ref := range r.EvidenceLevel.EvidenceRefs {
		if ref == scopeFact.ID {
			t.Fatal("B41 fact entered evidence_level.evidence_refs")
		}
	}

	// marshal once to be sure the report serializes
	jb, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(jb, &probe); err != nil {
		t.Fatal(err)
	}
	if probe["schema"] != ReportSchema {
		t.Fatalf("schema = %v", probe["schema"])
	}
}

// runFixtureLane runs the real lane over the committed evidencesnap
// fixture with the supplied advisory body — shared by the package-usage
// lane tests.
func runFixtureLane(t *testing.T, advisory string) (*LaneResult, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GO-TEST-0002", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-2",
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	return lane, out
}

func usageArgsOf(rec evidencetools.AuditRecord) (pkg, sym string) {
	var a struct {
		Package string `json:"package"`
		Symbol  string `json:"symbol"`
	}
	_ = json.Unmarshal(rec.Args, &a)
	return a.Package, a.Symbol
}

// package-usage runs once per advisory-declared subject — the declared
// package plus each declared symbol — after affected-resolve, in sorted
// order, and every OK verdict promotes to a typed fact whose artifact
// and digests follow the usual lane rules.
func TestDeterministicPackageUsageObserved(t *testing.T) {
	lane, out := runFixtureLane(t, `{
	  "id": "GO-TEST-0002",
	  "summary": "advisory with two declared symbols",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse", "helper"]}]}
	  }]
	}`)

	type usageRec struct {
		pkg, sym string
		obs      *evidencetools.Observation
	}
	var usages []usageRec
	for _, rec := range lane.Records {
		if rec.Tool != evidencetools.PackageUsageTool {
			continue
		}
		pkg, sym := usageArgsOf(rec)
		usages = append(usages, usageRec{pkg, sym, rec.Observation})
	}
	if len(usages) != 3 {
		var names []string
		for _, rec := range lane.Records {
			names = append(names, rec.Tool)
		}
		t.Fatalf("package-usage called %d times, want 3 (pkg + 2 symbols); tools=%v", len(usages), names)
	}
	// Sorted by package, then symbol: package-level first.
	want := []usageRec{
		{pkg: "example.com/snapdep/vuln"},
		{pkg: "example.com/snapdep/vuln", sym: "Parse"},
		{pkg: "example.com/snapdep/vuln", sym: "helper"},
	}
	for i, w := range want {
		if usages[i].pkg != w.pkg || usages[i].sym != w.sym {
			t.Fatalf("usage[%d]=(%s,%s), want (%s,%s)", i, usages[i].pkg, usages[i].sym, w.pkg, w.sym)
		}
	}
	// Every usage observation lands after the affected-resolve record.
	resolvePos := -1
	for i, rec := range lane.Records {
		if rec.Tool == "affected-resolve" {
			resolvePos = i
		}
	}
	for i, rec := range lane.Records {
		if rec.Tool == evidencetools.PackageUsageTool && i < resolvePos {
			t.Fatal("package-usage ran before affected-resolve")
		}
	}
	// Verdicts and promotion: package and Parse are USED (Kind +
	// Claim=TRUE); helper is the closed negative (Claim=FALSE +
	// negative_verification=VERIFIED).
	factByObs := map[string]VerifiedFact{}
	for _, f := range lane.Facts {
		factByObs[f.Provenance.ObservationID] = f
	}
	seenKind, seenFalse := 0, 0
	for _, u := range usages {
		o := u.obs
		if o == nil || o.ToolStatus != evidencetools.StatusOK {
			t.Fatalf("usage (%s,%s): status=%v", u.pkg, u.sym, o.ToolStatus)
		}
		var data map[string]any
		switch d := o.Data.(type) {
		case map[string]any:
			data = d
		default:
			b, _ := json.Marshal(d)
			_ = json.Unmarshal(b, &data)
		}
		f, promoted := factByObs[o.ID]
		if !promoted {
			t.Fatalf("usage (%s,%s) verdict %v did not become a fact", u.pkg, u.sym, data["usage"])
		}
		if f.Kind != FactKindPackageUsage {
			t.Fatalf("fact %s kind=%q, want PACKAGE_USAGE", f.ID, f.Kind)
		}
		if f.UsageSubject == nil || f.UsageSubject.Package != u.pkg ||
			f.UsageSubject.Symbol != u.sym || f.UsageSubject.Module != "example.com/snapdep" {
			t.Fatalf("fact %s usage_subject=%+v, want (%s,%s)", f.ID, f.UsageSubject, u.pkg, u.sym)
		}
		switch data["usage"] {
		case "USED":
			seenKind++
			if f.Claim != "TRUE" || f.NegativeVerification != "" {
				t.Fatalf("USED fact %s claim=%s negver=%q", f.ID, f.Claim, f.NegativeVerification)
			}
		case "NOT_USED":
			seenFalse++
			if f.Claim != "FALSE" || f.NegativeVerification != NegativeVerificationVerified {
				t.Fatalf("NOT_USED fact %s claim=%s negver=%q", f.ID, f.Claim, f.NegativeVerification)
			}
			if f.Coverage != "COMPLETE" {
				t.Fatalf("negative fact %s coverage=%s, want COMPLETE", f.ID, f.Coverage)
			}
		default:
			t.Fatalf("unexpected usage verdict %v", data["usage"])
		}
		// Artifact + digest semantics are the lane's usual ones.
		b, err := os.ReadFile(filepath.Join(out, f.Artifact.Path))
		if err != nil {
			t.Fatalf("%s: %v", f.ID, err)
		}
		if sha256Hex(b) != f.Artifact.SHA256 {
			t.Fatalf("%s artifact sha mismatch", f.ID)
		}
		if f.DataDigest == "" || f.InputDigest == "" || f.DataDigest == f.Artifact.SHA256 {
			t.Fatalf("%s digests invalid: data=%q input=%q", f.ID, f.DataDigest, f.InputDigest)
		}
	}
	if seenKind != 2 || seenFalse != 1 {
		t.Fatalf("USED=%d NOT_USED=%d, want 2 and 1", seenKind, seenFalse)
	}
	// The check is recorded in observations.jsonl too — one audit
	// record per package/symbol candidate.
	raw, err := os.ReadFile(filepath.Join(out, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jsonlUsage := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec struct {
			Tool string `json:"tool"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Tool == "package-usage" {
			jsonlUsage++
		}
	}
	if jsonlUsage != 3 {
		t.Fatalf("observations.jsonl carries %d package-usage records, want 3", jsonlUsage)
	}

	// The lane's facts assemble and validate end-to-end — the new kind,
	// claim and negative_verification fields stay inside the report
	// contract.
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "pkg-usage",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if err := Validate(r, out); err != nil {
		t.Fatalf("report with package-usage facts invalid:\n%v", err)
	}
}

// A module-only advisory declares no package-level subject: no
// package-usage observation is minted — the module path is never
// substituted for a package.
func TestDeterministicPackageUsageModuleOnly(t *testing.T) {
	lane, _ := runFixtureLane(t, `{
	  "id": "GO-TEST-0002",
	  "summary": "module-only advisory",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
	  }]
	}`)
	for _, rec := range lane.Records {
		if rec.Tool == evidencetools.PackageUsageTool {
			t.Fatalf("synthetic package-usage observation for module-only advisory: %s", rec.Args)
		}
	}
}

// Promotion rules over synthetic observations: only OK verdicts become
// facts; the VERIFIED negative needs a COMPLETE recorded scope; UNKNOWN
// promotes only as a positive lower bound.
func TestDeterministicPackageUsagePromotion(t *testing.T) {
	mkObs := func(id string, status evidencetools.ToolStatus, comp evidencetools.Completeness,
		data map[string]any) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: id, Tool: evidencetools.PackageUsageTool,
			Fact: "package-usage " + id, Scope: "bounded product source scope",
			Completeness: comp, ToolStatus: status,
			ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: strings.Repeat("ab", 32)},
			Data:         data,
		}
	}
	args := map[string]any{"module": "example.com/dep", "package": "example.com/dep/vuln"}

	t.Run("NOT_USED VERIFIED COMPLETE becomes a FALSE fact", func(t *testing.T) {
		obs := mkObs("OBS-0030", evidencetools.StatusOK, evidencetools.CompletenessComplete,
			map[string]any{
				"module": "example.com/dep", "package": "example.com/dep/vuln",
				"present": true, "usage": "NOT_USED",
				"negative_verification": "VERIFIED", "check_scope": "scope",
				"limitations": []any{"l"},
			})
		lane, _ := persistedLane(t, obs, evidencetools.PackageUsageData{
			Module: "example.com/dep", Package: "example.com/dep/vuln", Present: true,
			Usage: "NOT_USED", NegativeVerification: "VERIFIED", CheckScope: "scope",
		}, args)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0030" {
				f = &lane.Facts[i]
			}
		}
		if f == nil {
			t.Fatal("verified negative did not promote")
		}
		if f.Kind != FactKindPackageUsage || f.Claim != "FALSE" || f.NegativeVerification != NegativeVerificationVerified {
			t.Fatalf("fact=%+v", f)
		}
		if f.UsageBasis != UsageBasisPresentUnused {
			t.Fatalf("present negative fact usage_basis=%q, want %s", f.UsageBasis, UsageBasisPresentUnused)
		}
		if f.UsageSubject == nil || f.UsageSubject.Package != "example.com/dep/vuln" || f.UsageSubject.Module != "example.com/dep" {
			t.Fatalf("FALSE fact unbound to its subject: %+v", f.UsageSubject)
		}
	})

	t.Run("NOT_USED VERIFIED on an absent package records the closure basis", func(t *testing.T) {
		obs := mkObs("OBS-0036", evidencetools.StatusOK, evidencetools.CompletenessComplete,
			map[string]any{
				"module": "example.com/dep", "package": "example.com/dep/vuln",
				"present": false, "usage": "NOT_USED",
				"negative_verification": "VERIFIED", "check_scope": "scope",
				"limitations": []any{"l"},
			})
		lane, _ := persistedLane(t, obs, evidencetools.PackageUsageData{
			Module: "example.com/dep", Package: "example.com/dep/vuln", Present: false,
			Usage: "NOT_USED", NegativeVerification: "VERIFIED", CheckScope: "scope",
		}, args)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0036" {
				f = &lane.Facts[i]
			}
		}
		if f == nil {
			t.Fatal("verified absent-package negative did not promote")
		}
		if f.Kind != FactKindPackageUsage || f.Claim != "FALSE" || f.NegativeVerification != NegativeVerificationVerified {
			t.Fatalf("fact=%+v", f)
		}
		if f.UsageBasis != UsageBasisAbsentFromClosure {
			t.Fatalf("absent negative fact usage_basis=%q, want %s", f.UsageBasis, UsageBasisAbsentFromClosure)
		}
	})

	t.Run("NOT_USED VERIFIED with PARTIAL scope never becomes a fact", func(t *testing.T) {
		obs := mkObs("OBS-0031", evidencetools.StatusOK, evidencetools.CompletenessPartial,
			map[string]any{
				"module": "example.com/dep", "package": "example.com/dep/vuln",
				"present": true, "usage": "NOT_USED",
				"negative_verification": "VERIFIED", "check_scope": "scope",
				"limitations": []any{"l"},
			})
		lane, _ := persistedLane(t, obs, nil, args)
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0031" {
				t.Fatalf("PARTIAL negative promoted to fact %s", f.ID)
			}
		}
	})

	t.Run("UNKNOWN with positive linkage is a PACKAGE_USAGE_LOWER_BOUND fact", func(t *testing.T) {
		obs := mkObs("OBS-0032", evidencetools.StatusOK, evidencetools.CompletenessUnknown,
			map[string]any{
				"module": "example.com/dep", "package": "example.com/dep/vuln",
				"present": true, "usage": "UNKNOWN",
				"negative_verification": "INSUFFICIENT_SCOPE", "check_scope": "scope",
				"limitations": []any{"gap"},
			})
		lane, _ := persistedLane(t, obs, nil, args)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0032" {
				f = &lane.Facts[i]
			}
		}
		if f == nil {
			t.Fatal("positive lower bound did not promote")
		}
		if f.Kind != FactKindPackageUsageLowerBound || f.Claim != "TRUE" ||
			f.Coverage != "PARTIAL" || f.NegativeVerification != "" {
			t.Fatalf("lower-bound fact=%+v", f)
		}
		if f.UsageSubject == nil || f.UsageSubject.Package != "example.com/dep/vuln" || f.UsageSubject.Module != "example.com/dep" {
			t.Fatalf("lower-bound fact unbound to its subject: %+v", f.UsageSubject)
		}
	})

	t.Run("UNKNOWN without positive payload never becomes a fact", func(t *testing.T) {
		obs := mkObs("OBS-0033", evidencetools.StatusOK, evidencetools.CompletenessUnknown,
			map[string]any{
				"module": "example.com/dep", "package": "example.com/dep/absent",
				"present": false, "usage": "UNKNOWN",
				"negative_verification": "INSUFFICIENT_SCOPE", "check_scope": "scope",
				"limitations": []any{"target package is absent"},
			})
		lane, _ := persistedLane(t, obs, nil, args)
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0033" {
				t.Fatalf("UNKNOWN observation promoted to fact %s", f.ID)
			}
		}
	})

	t.Run("tool failure never becomes a fact", func(t *testing.T) {
		obs := mkObs("OBS-0034", evidencetools.StatusError, evidencetools.CompletenessUnknown, nil)
		lane, _ := persistedLane(t, obs, nil, args)
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0034" {
				t.Fatalf("ERROR observation promoted to fact %s", f.ID)
			}
		}
	})

	t.Run("subject-less record never becomes a fact", func(t *testing.T) {
		obs := mkObs("OBS-0035", evidencetools.StatusOK, evidencetools.CompletenessPartial,
			map[string]any{
				"module": "example.com/dep", "package": "example.com/dep/vuln",
				"present": true, "usage": "USED", "check_scope": "scope",
			})
		// No package in the invocation args: the fact has no subject to
		// bind to and must not promote, even for a USED verdict.
		lane, _ := persistedLane(t, obs, nil, map[string]any{"module": "example.com/dep"})
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0035" {
				t.Fatalf("subject-less observation promoted to fact %s", f.ID)
			}
		}
	})
}

// packageUsageCandidates covers the lane's enumeration contract:
// declared packages and symbols merge without duplication, a package
// identity comes only from the advisory, module-only advisories yield
// nothing and non-Go entries are filtered out.
func TestDeterministicPackageUsageCandidates(t *testing.T) {
	v := domain.Vulnerability{
		ID: "GO-TEST-0003",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln", Symbols: []string{"Parse"}}},
				AffectedSymbols:  []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Decode"}, {Package: "", Symbol: "NoPkg"}},
			},
			{Module: "example.com/module-only"},
			{
				Module:          "left-pad",
				AffectedSymbols: []domain.SymbolRef{{Package: "left-pad", Symbol: "pad"}},
			},
		},
	}
	goModules := map[string]bool{"example.com/dep": true, "example.com/module-only": true}
	got := packageUsageCandidates(v, goModules)
	type key struct{ pkg, sym string }
	var keys []key
	for _, s := range got {
		keys = append(keys, key{s.Package, s.Symbol})
	}
	want := []key{
		{"example.com/dep/vuln", ""},
		{"example.com/dep/vuln", "Decode"},
		{"example.com/dep/vuln", "Parse"},
	}
	if len(keys) != len(want) {
		t.Fatalf("candidates=%+v, want %+v", got, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("candidate[%d]=%+v, want %+v (got %v)", i, keys[i], want[i], keys)
		}
	}
	for _, s := range got {
		if s.Module == "left-pad" {
			t.Fatal("non-Go entry produced a candidate")
		}
	}
}

// Task 3 regression: callSitesOf must drop records that lack a column —
// an incomplete position cannot be verified as the call expression's own
// location and must not bind to call-site-only tools.
func TestCallSitesOfRequiresColumn(t *testing.T) {
	obs := &evidencetools.Observation{
		ToolStatus: evidencetools.StatusOK,
		Data: map[string]any{
			"call_sites": []any{
				map[string]any{"file": "a.go", "line": float64(10), "column": float64(5)},
				map[string]any{"file": "a.go", "line": float64(12)},
			},
			// A declaration-position record (find_symbol shape): dropped.
			"site": map[string]any{"file": "decl.go", "line": float64(3)},
		},
	}
	got := callSitesOf(obs, 8)
	if len(got) != 1 || got[0].Line != 10 || got[0].Column != 5 {
		t.Fatalf("callSitesOf=%+v, want the column-qualified site only", got)
	}
}

// §4/§9: artifact.sha256 verifies the file as written; data_digest stays
// the canonical payload digest — for a non-trivial payload they differ
// because the written file carries a trailing newline.
func TestArtifactSHA_MatchesFileBytes(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(`{"id":"GO-X","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"example.com/snapdep"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	lane, err := RunDeterministic(context.Background(), LaneOptions{
		CVE: "GO-X", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "sha",
		Timeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lane.Facts) == 0 {
		t.Fatal("no verified facts")
	}
	for _, f := range lane.Facts {
		b, err := os.ReadFile(filepath.Join(out, f.Artifact.Path))
		if err != nil {
			t.Fatalf("%s: %v", f.ID, err)
		}
		sum := sha256Hex(b)
		if sum != f.Artifact.SHA256 {
			t.Fatalf("%s artifact.sha256 %s != file bytes %s", f.ID, f.Artifact.SHA256, sum)
		}
		if f.Artifact.SHA256 == f.DataDigest {
			t.Fatalf("%s artifact digest equals data_digest %s — file digest must be over written bytes", f.ID, sum)
		}
	}
}

// §9 check 2: exploitation_conditions is never empty — the deterministic
// lane always derives the applicability chain plus the runtime predicate.
func TestDeterministicConditions_AlwaysPopulated(t *testing.T) {
	lane := fakeLane(t)
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "x",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if len(r.ExploitationConditions) == 0 {
		t.Fatal("no deterministic exploitation conditions")
	}
	var states []string
	for _, c := range r.ExploitationConditions {
		states = append(states, c.State)
		if c.Origin != OriginDeterm {
			t.Fatalf("condition %s origin %s", c.ID, c.Origin)
		}
		if c.State == StateOpen {
			t.Fatalf("deterministic condition %s is OPEN — the three-valued semantics reserve OPEN for agent hypotheses", c.ID)
		}
		if len(c.EvidenceRefs) == 0 {
			t.Fatalf("condition %s has no evidence refs", c.ID)
		}
		if c.State == StateUnknown && len(c.Limitations) == 0 {
			t.Fatalf("UNKNOWN condition %s carries no follow-up", c.ID)
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report with deterministic conditions invalid:\n%v", err)
	}
	t.Logf("states: %v", states)
}

// persistedLane rebuilds the fake lane's verified facts through the real
// persist projection, adding one caller-supplied observation + audit
// record, so coverage/artifact/digest semantics are exercised end to end.
// recordData mirrors production: the lane observation list carries the
// decoded (map) payload while the audit record keeps the tool's typed
// struct; pass a struct-shaped value to exercise the record path.
func persistedLane(t *testing.T, o *evidencetools.Observation, recordData any, args map[string]any) (*LaneResult, string) {
	t.Helper()
	lane := fakeLane(t)
	// The record-driven projection reads the tool name from the audit
	// record; keep the pre-existing observations' Tool fields in sync
	// with their lane tool names.
	lane.Observations[0].Tool = "advisory-load"
	lane.Observations[1].Tool = "affected-resolve"
	lane.Observations = append(lane.Observations, o)
	raw, _ := json.Marshal(args)
	recObs := o
	if recordData != nil {
		cp := *o
		cp.Data = recordData
		recObs = &cp
	}
	lane.Records = []evidencetools.AuditRecord{
		{Tool: "advisory-load", Args: raw, Observation: lane.Observations[0]},
		{Tool: "affected-resolve", Args: raw, Observation: lane.Observations[1]},
		{Tool: o.Tool, Args: raw, Observation: recObs},
	}
	lane.Facts = nil
	lane.ArtifactByObs = map[string]ArtifactRef{}
	lane.CanonicalByObs = map[string]string{}
	dir := t.TempDir()
	if err := lane.persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}
	return lane, dir
}

// mayCallersPayload mirrors the typed payload the session's audit record
// carries for find_may_callers (evidencetools.mayCallersData).
type mayCallersPayload struct {
	CallSites          []any `json:"call_sites"`
	Count              int   `json:"count"`
	PossibleCount      int   `json:"possible_count"`
	PartialEnumeration bool  `json:"partial_enumeration"`
}

// observation whose Completeness is UNKNOWN (an open enumeration such
// as find_may_callers) must never yield a verified_fact with
// coverage=UNKNOWN. With positive content it is a lower-bound fact at
// PARTIAL coverage; with none it is routed to the unknowns so its empty
// result cannot be read as absence. The fixture is the exact real shape
// from a recorded corporate run (component name withheld) / net.LookupCNAME.
func TestOpenEnumerationFactProjection(t *testing.T) {
	mayCallersObs := func(data map[string]any) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID:   "OBS-0014",
			Tool: "find_may_callers",
			Fact: fmt.Sprintf("%d may-call site(s) of net.LookupCNAME (1 with unproven targets)",
				int(data["count"].(float64))),
			Scope:        "loaded scope of /snap (product roots + retained dependency packages)",
			Completeness: evidencetools.CompletenessUnknown,
			ToolStatus:   evidencetools.StatusOK,
			Limitations: []string{
				"may-call scan covers direct, interface-dispatch and function-value sites in the loaded scope (product roots + retained dependency extras); unbounded cross-module callers of exported symbols are not enumerable",
				"call enumeration inside the loaded scope is incomplete (candidate sets open or extras generation changed mid-scan)",
			},
			ScopeDetails: &evidencetools.ScopeDetails{
				Subject: "net.LookupCNAME",
			},
			Data: data,
		}
	}
	args := map[string]any{"package": "net", "symbol": "LookupCNAME"}

	t.Run("open-ended positive becomes a PARTIAL lower-bound fact", func(t *testing.T) {
		obs := mayCallersObs(map[string]any{
			"call_sites":          []any{map[string]any{"file": "x.go", "line": float64(7), "possible": true}},
			"count":               float64(1),
			"possible_count":      float64(1),
			"partial_enumeration": true,
		})
		lane, dir := persistedLane(t, obs, mayCallersPayload{
			CallSites:          []any{map[string]any{"file": "x.go", "line": 7, "possible": true}},
			Count:              1,
			PossibleCount:      1,
			PartialEnumeration: true,
		}, args)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0014" {
				f = &lane.Facts[i]
			}
			if lane.Facts[i].Coverage != "COMPLETE" && lane.Facts[i].Coverage != "PARTIAL" {
				t.Fatalf("fact %s coverage %q outside the report contract", lane.Facts[i].ID, lane.Facts[i].Coverage)
			}
		}
		if f == nil {
			t.Fatal("OBS-0014 did not become a verified fact")
		}
		if f.Coverage != "PARTIAL" {
			t.Fatalf("coverage = %s, want PARTIAL (open enumeration lower bound)", f.Coverage)
		}
		openLim := false
		for _, l := range f.Limitations {
			if l == openEnumerationLimitation {
				openLim = true
			}
		}
		if !openLim {
			t.Fatalf("open-enumeration limitation missing: %v", f.Limitations)
		}
		// digest semantics unchanged: artifact sha is over written bytes,
		// data_digest is the canonical payload without the trailing LF.
		b, err := os.ReadFile(filepath.Join(dir, f.Artifact.Path))
		if err != nil {
			t.Fatal(err)
		}
		if sha256Hex(b) != f.Artifact.SHA256 {
			t.Fatalf("artifact sha256 does not match written bytes")
		}
		if f.DataDigest == "" || f.DataDigest == f.Artifact.SHA256 {
			t.Fatalf("data_digest must be the canonical payload digest, got %q", f.DataDigest)
		}
		// Assemble + self-validate: the report contract holds.
		r := Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "open-enum",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
		if err := Validate(r, dir); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})

	t.Run("open-ended empty becomes an unknown, never a fact", func(t *testing.T) {
		obs := mayCallersObs(map[string]any{
			"call_sites":          []any{},
			"count":               float64(0),
			"possible_count":      float64(0),
			"partial_enumeration": true,
		})
		lane, dir := persistedLane(t, obs, mayCallersPayload{
			CallSites:          []any{},
			Count:              0,
			PossibleCount:      0,
			PartialEnumeration: true,
		}, args)
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0014" {
				t.Fatalf("empty open enumeration became fact %s", f.ID)
			}
			if f.Coverage != "COMPLETE" && f.Coverage != "PARTIAL" {
				t.Fatalf("fact %s coverage %q outside the report contract", f.ID, f.Coverage)
			}
		}
		if lane.FactRef("OBS-0014") != "" {
			t.Fatal("FactRef resolved for a non-fact observation")
		}
		r := Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "open-enum",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
		var u *UnknownEntry
		for i := range r.Unknowns {
			for _, ref := range r.Unknowns[i].EvidenceRefs {
				if ref == "obs:OBS-0014" {
					u = &r.Unknowns[i]
				}
			}
		}
		if u == nil {
			t.Fatal("empty open enumeration is not recorded as an unknown")
		}
		if !strings.Contains(u.FollowUp, "find_may_callers") {
			t.Fatalf("follow-up does not name the check: %q", u.FollowUp)
		}
		// Nothing reads the empty result as absence: no deterministic
		// claim may be built on it.
		for _, c := range r.ProductExposure.Claims {
			for _, ref := range c.EvidenceRefs {
				if ref == "obs:OBS-0014" {
					t.Fatalf("absence-readable claim cites the open enumeration: %s", c.ID)
				}
			}
		}
		if err := Validate(r, dir); err != nil {
			t.Fatalf("report invalid:\n%v", err)
		}
	})
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// releaseEvidenceData must carry the snapshot's release-evidence outcome
// into the affected-resolve payload: status/reason, the selected
// authoritative toolchain, digests, and the module graph that grounded
// module versions — and stay absent entirely on a bare snapshot.
func TestReleaseGraphEvidenceData(t *testing.T) {
	bare := domain.ProductSnapshot{Repository: "/repo"}
	if got := releaseEvidenceData(bare); got != nil {
		t.Fatalf("no release evidence must yield nil payload: %v", got)
	}

	snap := domain.ProductSnapshot{
		Repository:              "/repo",
		ReleaseGoVersion:        "go1.42.0",
		GoVersionSource:         domain.GoVersionSourceBinary,
		ReleaseModules:          []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.4.0"}},
		ReleaseEvidenceRequired: true,
		ReleaseEvidence: &domain.ReleaseEvidenceSummary{
			Status:          domain.ReleaseStatusResolved,
			SelectedVersion: "go1.42.0",
			SelectedSource:  domain.GoVersionSourceBinary,
			SelectedTrust:   domain.ReleaseTrustAuthoritative,
			ArtifactSHA256:  "aa11", BinaryMember: "bundle/bin/tool", BuildInfoSHA256: "bb22",
			Items: []domain.ReleaseEvidenceItem{{
				Version: "go1.42.0", Source: domain.GoVersionSourceBinary,
				TrustClass: domain.ReleaseTrustAuthoritative, ArtifactSHA256: "aa11",
			}},
		},
	}
	m := releaseEvidenceData(snap)
	if m == nil {
		t.Fatal("resolved release evidence must produce a payload")
	}
	if m["status"] != "RESOLVED" || m["version_graph"] != "release_module_graph" ||
		m["version_graph_trust"] != string(domain.ReleaseTrustAuthoritative) ||
		m["version_graph_modules"] != 1 {
		t.Fatalf("authoritative projection: %v", m)
	}
	if m["artifact_sha256"] != "aa11" || m["binary_member"] != "bundle/bin/tool" ||
		m["build_info_sha256"] != "bb22" || m["selected_version"] != "go1.42.0" {
		t.Fatalf("provenance digests/selection missing: %v", m)
	}

	// A failed requested channel names its fail-closed reason and leaves
	// the version graph marked unavailable.
	blocked := domain.ProductSnapshot{
		Repository:              "/repo",
		ReleaseEvidenceRequired: true,
		ReleaseEvidence: &domain.ReleaseEvidenceSummary{
			Status:     domain.ReleaseStatusNotRun,
			ReasonCode: domain.ReleaseReasonArtifactPathMissing,
		},
	}
	m = releaseEvidenceData(blocked)
	if m == nil || m["status"] != "NOT_RUN" ||
		m["reason_code"] != domain.ReleaseReasonArtifactPathMissing ||
		m["version_graph"] != "unavailable" {
		t.Fatalf("blocked projection: %v", m)
	}
}

// TestLaneReleaseEvidenceProjection covers the /3 report block: a
// resolved lane carries status/selection/items/digests/graph provenance;
// a fail-closed lane carries NOT_RUN with its reason; a bare lane emits
// no member at all so legacy reports stay byte-identical.
func TestLaneReleaseEvidenceProjection(t *testing.T) {
	bare := &LaneResult{Snapshot: domain.ProductSnapshot{Repository: "/repo"}}
	if got := LaneReleaseEvidence(bare); got != nil {
		t.Fatalf("no release evidence must yield nil block: %+v", got)
	}
	if notRun, _ := LaneReleaseNotRun(bare); notRun {
		t.Fatal("bare lane must not be NOT_RUN")
	}

	resolved := &LaneResult{Snapshot: domain.ProductSnapshot{
		Repository:              "/repo",
		ReleaseEvidenceRequired: true,
		ReleaseModules:          []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.4.0"}},
		ReleaseEvidence: &domain.ReleaseEvidenceSummary{
			Status:          domain.ReleaseStatusResolved,
			SelectedVersion: "go1.42.0",
			SelectedSource:  domain.GoVersionSourceBinary,
			SelectedTrust:   domain.ReleaseTrustAuthoritative,
			ArtifactSHA256:  "aa11", BinaryMember: "bundle/bin/tool", BuildInfoSHA256: "bb22",
			Modules: []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.4.0"}},
			Items: []domain.ReleaseEvidenceItem{{
				Version: "go1.42.0", Source: domain.GoVersionSourceBinary,
				TrustClass: domain.ReleaseTrustAuthoritative, ArtifactSHA256: "aa11",
			}, {
				Version: "go1.25.0", Source: domain.GoVersionSourceGoMod,
				TrustClass: domain.ReleaseTrustSupporting, Location: "go.mod",
			}},
		},
	}}
	rep := LaneReleaseEvidence(resolved)
	if rep == nil || rep.Status != "RESOLVED" || rep.SelectedVersion != "go1.42.0" ||
		rep.SelectedTrust != "AUTHORITATIVE" || rep.ArtifactSHA256 != "aa11" ||
		rep.BinaryMember != "bundle/bin/tool" || rep.BuildInfoSHA256 != "bb22" ||
		rep.VersionGraphSource != "release-artifact" || rep.VersionGraphTrust != "AUTHORITATIVE" ||
		rep.ModuleCount != 1 || len(rep.Items) != 2 || len(rep.Modules) != 1 {
		t.Fatalf("resolved block %+v", rep)
	}
	if rep.Items[1].TrustClass != "SUPPORTING" {
		t.Fatalf("supporting item lost: %+v", rep.Items[1])
	}

	blocked := &LaneResult{Snapshot: domain.ProductSnapshot{
		Repository:              "/repo",
		ReleaseEvidenceRequired: true,
		ReleaseEvidence: &domain.ReleaseEvidenceSummary{
			Status:     domain.ReleaseStatusNotRun,
			ReasonCode: domain.ReleaseReasonArtifactCredentialsMissing,
		},
	}}
	rep = LaneReleaseEvidence(blocked)
	if rep == nil || rep.Status != "NOT_RUN" ||
		rep.ReasonCode != domain.ReleaseReasonArtifactCredentialsMissing ||
		rep.VersionGraphSource != "unavailable" || rep.SelectedVersion != "" {
		t.Fatalf("blocked block %+v", rep)
	}
	if notRun, reason := LaneReleaseNotRun(blocked); !notRun ||
		reason != domain.ReleaseReasonArtifactCredentialsMissing {
		t.Fatalf("notRun=%v reason=%q", notRun, reason)
	}
}

// A channel failure masked by a competing authority is still NOT_RUN:
// the resolved toolchain grounds stdlib but the failed required channel
// blocks the module-graph axis and the planner/model path.
func TestLaneReleaseNotRunMaskedChannel(t *testing.T) {
	masked := &LaneResult{Snapshot: domain.ProductSnapshot{
		Repository:              "/repo",
		ReleaseGoVersion:        "go1.42.7",
		GoVersionSource:         domain.GoVersionSourceExplicit,
		ReleaseEvidenceRequired: true,
		ReleaseEvidence: &domain.ReleaseEvidenceSummary{
			Status:                  domain.ReleaseStatusResolved,
			SelectedVersion:         "go1.42.7",
			SelectedSource:          domain.GoVersionSourceExplicit,
			SelectedTrust:           domain.ReleaseTrustAuthoritative,
			RequiredChannelFailures: []string{domain.ReleaseReasonArtifactPathMissing},
		},
	}}
	if notRun, reason := LaneReleaseNotRun(masked); !notRun ||
		reason != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("masked failure: notRun=%v reason=%q", notRun, reason)
	}
	rep := LaneReleaseEvidence(masked)
	if rep == nil || rep.VersionGraphSource != "unavailable" ||
		len(rep.RequiredChannelFailures) != 1 ||
		rep.RequiredChannelFailures[0] != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("masked block %+v", rep)
	}
	if rep.SelectedVersion != "go1.42.7" {
		t.Fatalf("explicit toolchain must stay selected for stdlib: %+v", rep)
	}
}

// TestDeterministicLaneArtifactPathMissing runs the real lane with an
// artifact path that does not exist: the requested channel fails closed
// NOT_RUN/ARTIFACT_PATH_MISSING, the release-evidence lane observation is
// persisted, the affected-resolve payload carries the blocked axis, and
// the assembled /2-shaped report validates with run.outcome NOT_RUN.
func TestDeterministicLaneArtifactPathMissing(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0001",
	  "aliases": ["CVE-TEST-1"],
	  "summary": "test advisory for snapdep Parse",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	advPath := filepath.Join(dir, "GO-TEST-0001.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GO-TEST-0001", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-1",
		Timeout: 60 * time.Second,
		ArtifactOptions: repository.ArtifactOptions{
			Path: filepath.Join(dir, "no-such-artifact"),
		},
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	if lane.Snapshot.ReleaseEvidence == nil ||
		lane.Snapshot.ReleaseEvidence.Status != domain.ReleaseStatusNotRun ||
		lane.Snapshot.ReleaseEvidence.ReasonCode != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("release evidence %+v", lane.Snapshot.ReleaseEvidence)
	}
	// The channel failure is its own recorded lane observation.
	var relObs *evidencetools.Observation
	for _, o := range lane.Observations {
		if o.Tool == "release-evidence" {
			relObs = o
		}
	}
	if relObs == nil || relObs.Completeness != evidencetools.CompletenessPartial {
		t.Fatalf("release-evidence observation %+v", relObs)
	}
	// The affected-resolve payload marks the version axis blocked.
	var resolve *evidencetools.Observation
	for _, o := range lane.Observations {
		if o.Tool == "affected-resolve" {
			resolve = o
		}
	}
	if resolve == nil {
		t.Fatal("affected-resolve observation missing")
	}
	raw, _ := json.Marshal(resolve.Data)
	if !strings.Contains(string(raw), `"status":"NOT_RUN"`) ||
		!strings.Contains(string(raw), domain.ReleaseReasonArtifactPathMissing) {
		t.Fatalf("affected-resolve payload lacks NOT_RUN axis: %s", raw)
	}
	if lane.Affected.ReleaseEvidenceStatus != "NOT_RUN" ||
		lane.Affected.ReleaseEvidenceReason != domain.ReleaseReasonArtifactPathMissing ||
		lane.Affected.VersionGraphSource != "unavailable" {
		t.Fatalf("affected axis %+v", lane.Affected)
	}
	// The assembled report carries the /3 provenance block and the
	// run-level NOT_RUN outcome, and it validates.
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "notrun",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Run.Outcome != "NOT_RUN" ||
		r.Run.OutcomeReason != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("run outcome %+v", r.Run)
	}
	if r.Input.Snapshot.ReleaseEvidence == nil ||
		r.Input.Snapshot.ReleaseEvidence.Status != "NOT_RUN" ||
		r.Input.Snapshot.ReleaseEvidence.ReasonCode != domain.ReleaseReasonArtifactPathMissing ||
		r.Input.Snapshot.ReleaseEvidence.VersionGraphSource != "unavailable" {
		t.Fatalf("release evidence block %+v", r.Input.Snapshot.ReleaseEvidence)
	}
	if r.AgentOutput.Status != AgentNotRequested {
		t.Fatalf("agent status %s", r.AgentOutput.Status)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("NOT_RUN report invalid:\n%v", err)
	}
}

// TestDeterministicLaneReleaseMetadataInvalid feeds the lane a malformed
// release-metadata document: the requested metadata channel fails closed
// NOT_RUN/RELEASE_METADATA_INVALID and the report records it.
func TestDeterministicLaneReleaseMetadataInvalid(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0001",
	  "summary": "test",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	advPath := filepath.Join(dir, "GO-TEST-0001.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(metaPath, []byte(`{"schema":"release-metadata/2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, err := RunDeterministic(ctx, LaneOptions{
		CVE: "GO-TEST-0001", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-1",
		Timeout: 60 * time.Second, ReleaseMetadata: metaPath,
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	if lane.Snapshot.ReleaseEvidence == nil ||
		lane.Snapshot.ReleaseEvidence.Status != domain.ReleaseStatusNotRun ||
		lane.Snapshot.ReleaseEvidence.ReasonCode != domain.ReleaseReasonMetadataInvalid {
		t.Fatalf("release evidence %+v", lane.Snapshot.ReleaseEvidence)
	}
	if notRun, reason := LaneReleaseNotRun(lane); !notRun ||
		reason != domain.ReleaseReasonMetadataInvalid {
		t.Fatalf("notRun=%v reason=%q", notRun, reason)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "notrun-meta",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Run.Outcome != "NOT_RUN" ||
		r.Run.OutcomeReason != domain.ReleaseReasonMetadataInvalid {
		t.Fatalf("run outcome %+v", r.Run)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("metadata NOT_RUN report invalid:\n%v", err)
	}
}

// loadFrozenAdvisory consumes the parser-produced census as-is. The record's
// own Impls, raw bytes and research digests are reporting inputs: they never
// repair or promote the scope, and a reduced record stays non-closing while
// its original entry identities stay visible.
func TestLoadFrozenAdvisoryScopeCensus(t *testing.T) {
	writeDoc := func(t *testing.T, id, affected string) string {
		t.Helper()
		doc := `{"id":"` + id + `","modified":"2026-01-01T00:00:00Z","affected":[` + affected + `]}`
		path := filepath.Join(t.TempDir(), id+".json")
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	goEntry := func(module string) string {
		return `{"package":{"ecosystem":"Go","name":"` + module + `"},
		  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}`
	}
	mavenEntry := func(module string) string {
		return `{"package":{"ecosystem":"Maven","name":"` + module + `"},
		  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}`
	}
	load := func(t *testing.T, id, affected string) *AdvisoryRecord {
		t.Helper()
		path := writeDoc(t, id, affected)
		rec, err := loadFrozenAdvisory(context.Background(), LaneOptions{CVE: id, AdvisoryFile: path})
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	t.Run("mixed record stays a Go projection", func(t *testing.T) {
		const id = "GO-TEST-CENSUS-1"
		rec := load(t, id, goEntry(testModule)+","+mavenEntry("com.example:dep"))
		scope := rec.Vuln.Scope
		if scope == nil {
			t.Fatal("frozen advisory carries no parser scope")
		}
		if scope.RequestedID != id || scope.ResolvedID != id ||
			scope.Kind != domain.ScopeAdvisoryEntries || scope.Coverage != domain.CoverageKnownOnly {
			t.Fatalf("bound scope = %+v", scope)
		}
		if scope.RecordExtent != domain.RecordExtentGoProjection {
			t.Fatalf("extent = %q, want GO_PROJECTION", scope.RecordExtent)
		}
		inventory := scope.RecordInventory
		if inventory == nil || inventory.AffectedEntryCount != 2 || len(inventory.Entries) != 2 {
			t.Fatalf("census = %+v", inventory)
		}
		if len(inventory.RepresentedRefs) != 1 || inventory.RepresentedRefs[0] != 0 ||
			len(inventory.OmittedRefs) != 1 || inventory.OmittedRefs[0] != 1 {
			t.Fatalf("census partition = %+v", inventory)
		}
		if inventory.DocumentDigest != "sha256:"+rec.Input.RawSHA256 {
			t.Fatalf("census digest %q does not bind the loaded bytes %q",
				inventory.DocumentDigest, rec.Input.RawSHA256)
		}
		if scope.AllowsNegativeClosure() {
			t.Fatalf("a Go projection authorized a closure: %+v", scope)
		}
		// Impls and the research digests are reporting inputs. They stay
		// complete and stable, and the scope stays exactly what the parser
		// produced.
		if len(rec.Impls) != 2 || rec.Impls[1].Binding != BindNonGo {
			t.Fatalf("impl projection = %+v", rec.Impls)
		}
		if rec.Input.CanonicalSHA256 == "" {
			t.Fatal("canonical digest was not recorded")
		}
		if scope.RecordExtent != domain.RecordExtentGoProjection || scope.AllowsNegativeClosure() {
			t.Fatalf("reporting inputs promoted the scope: %+v", scope)
		}
	})

	t.Run("go-only record stays closable", func(t *testing.T) {
		const id = "GO-TEST-CENSUS-2"
		rec := load(t, id, goEntry(testModule))
		scope := rec.Vuln.Scope
		if scope == nil || scope.RecordExtent != domain.RecordExtentFullRecord ||
			scope.Coverage != domain.CoverageComplete ||
			scope.RecordInventory == nil || scope.RecordInventory.DocumentDigest != "sha256:"+rec.Input.RawSHA256 {
			t.Fatalf("bound scope = %+v", scope)
		}
		if !scope.AllowsNegativeClosure() {
			t.Fatalf("a fully represented Go-only record must stay closable: %+v", scope)
		}
		lane := &LaneResult{Advisory: *rec, Affected: domain.AffectedResult{Scope: scope}}
		subs := declaredSubjects(lane)
		if len(subs) == 0 {
			t.Fatal("no declared subject")
		}
		for _, sub := range subs {
			if sub.EntryID != "adv-01" {
				t.Fatalf("entry id = %q, want adv-01", sub.EntryID)
			}
		}
	})

	// A merged AffectedModule is not positionally aligned with the original
	// entries: the Go entry is the second original affected[] element, so the
	// merged index would name the non-Go entry's id. The entry id must come
	// from the census index with module/ecosystem identity verified.
	t.Run("entry ids follow the census not the merged position", func(t *testing.T) {
		const id = "GO-TEST-CENSUS-3"
		rec := load(t, id, mavenEntry(testModule)+","+goEntry(testModule))
		if len(rec.Impls) != 2 || rec.Impls[0].ID != "adv-01" || rec.Impls[0].Binding != BindNonGo ||
			rec.Impls[1].ID != "adv-02" || rec.Impls[1].Binding != BindExact {
			t.Fatalf("impl projection = %+v", rec.Impls)
		}
		lane := &LaneResult{Advisory: *rec, Affected: domain.AffectedResult{Scope: rec.Vuln.Scope}}
		subs := declaredSubjects(lane)
		if len(subs) == 0 {
			t.Fatal("no declared subject")
		}
		for _, sub := range subs {
			if sub.EntryID != "adv-02" {
				t.Fatalf("merged module adopted the foreign entry id %q: %+v", sub.EntryID, sub)
			}
		}
	})
}
