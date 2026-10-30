package research

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// ---- helpers ----

// scopeObs mints a usage-scope observation row for the given subject
// under a closed (COMPLETE) paired stream.
func scopeObs(id, module, pkg, scope string, comp evidencetools.Completeness) *evidencetools.Observation {
	return &evidencetools.Observation{
		ID:           id,
		Tool:         evidencetools.UsageScopeTool,
		ToolStatus:   evidencetools.StatusOK,
		Fact:         "usage-scope over " + module + " | " + pkg,
		Scope:        "paired go list closures for " + pkg,
		Completeness: comp,
		ScopeDetails: &evidencetools.ScopeDetails{
			Subject:      module + " | " + pkg,
			CoverageRule: "paired `go list` streams fully decoded and edge-closed",
		},
		Data: map[string]any{
			"module": module, "package": pkg,
			"product_linked": scope == string(UsageScopeProduct) || scope == string(UsageScopeMixed),
			"test_linked":    scope == string(UsageScopeTestOnly) || scope == string(UsageScopeMixed),
			"usage_scope":    scope,
			"check_scope":    "paired go list -deps streams (GOOS=linux GOARCH=amd64)",
			"limitations":    []any{},
		},
	}
}

// scopeFact mints the promoted verified fact for a usage-scope
// observation id, bound to the same subject the record carried.
// prodAbs carries product_absence_verification (VERIFIED on test-only).
func scopeFact(obsID, module, pkg, scope, prodAbs string) VerifiedFact {
	f := factFor(obsID, evidencetools.UsageScopeTool, "usage-scope over "+module+" | "+pkg)
	f.Kind = FactKindBuildUsageScope
	f.UsageSubject = &FactUsageSubject{Module: module, Package: pkg}
	f.UsageScope = scope
	f.ProductAbsenceVerification = prodAbs
	f.Coverage = "COMPLETE"
	f.Scope = "paired go list closures for " + pkg
	return f
}

// scopeArgsOf decodes a usage-scope audit record's args.
func scopeArgsOf(rec evidencetools.AuditRecord) (module, pkg string) {
	var a struct {
		Module  string `json:"module"`
		Package string `json:"package"`
	}
	_ = json.Unmarshal(rec.Args, &a)
	return a.Module, a.Package
}

// scopeFacts returns every BUILD_USAGE_SCOPE fact on the lane, in
// ledger order.
func scopeFacts(lane *LaneResult) []VerifiedFact {
	var out []VerifiedFact
	for _, f := range lane.Facts {
		if f.Kind == FactKindBuildUsageScope {
			out = append(out, f)
		}
	}
	return out
}

// runUsageScopeLane runs the real lane over the usagescope fixture —
// the snapshot whose dep packages cover all four B41 classes.
func runUsageScopeLane(t *testing.T, advisory string) (*LaneResult, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "usagescope"))
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
		CVE: "GO-TEST-0041", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: out, ExternalCommitSHA: "fixture-sha-b41",
		Timeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	return lane, out
}

// ---- deterministic lane: candidates, calls, promotion ----

// One B41 observation per sorted advisory-declared package, no
// symbol-level check, immediately after the B42 package-usage block.
func TestDeterministicUsageScopeObserved(t *testing.T) {
	lane, out := runUsageScopeLane(t, `{
	  "id": "GO-TEST-0041",
	  "summary": "advisory covering all four build-closure classes",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/usagedep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [
	      {"path": "example.com/usagedep/prod", "symbols": ["Name"]},
	      {"path": "example.com/usagedep/shared"},
	      {"path": "example.com/usagedep/testonly"},
	      {"path": "example.com/usagedep/unused"}
	    ]}
	  }]
	}`)

	// Exactly one usage-scope call per declared package — sorted,
	// every one right of the last package-usage call.
	var scopes []string
	lastUsage, firstScope := -1, -1
	for i, rec := range lane.Records {
		switch rec.Tool {
		case evidencetools.PackageUsageTool:
			lastUsage = i
		case evidencetools.UsageScopeTool:
			if firstScope < 0 {
				firstScope = i
			}
			_, pkg := scopeArgsOf(rec)
			scopes = append(scopes, pkg)
		}
	}
	want := []string{
		"example.com/usagedep/prod",
		"example.com/usagedep/shared",
		"example.com/usagedep/testonly",
		"example.com/usagedep/unused",
	}
	if len(scopes) != len(want) {
		t.Fatalf("usage-scope called %d times, want %d; records=%v",
			len(scopes), len(want), scopes)
	}
	for i, w := range want {
		if scopes[i] != w {
			t.Fatalf("scope[%d]=%s, want %s (sorted package order)", i, scopes[i], w)
		}
	}
	if lastUsage >= 0 && firstScope < lastUsage {
		t.Fatalf("first usage-scope record precedes a package-usage record")
	}

	// Promotion: every class lands as a claim=TRUE BUILD_USAGE_SCOPE
	// fact bound to the exact package subject; test-only carries the
	// product-absence marker; no fact reuses NegativeVerification.
	byScope := map[string]VerifiedFact{}
	for _, f := range scopeFacts(lane) {
		if f.UsageSubject == nil {
			t.Fatalf("B41 fact %s has no usage_subject", f.ID)
		}
		byScope[f.UsageSubject.Package] = f
		if f.Claim != "TRUE" || f.Status != "OK" || f.Coverage != "COMPLETE" {
			t.Fatalf("B41 fact %s shape: claim=%s status=%s coverage=%s", f.ID, f.Claim, f.Status, f.Coverage)
		}
		if f.NegativeVerification != "" {
			t.Fatalf("B41 fact %s carries B42 negative_verification=%q", f.ID, f.NegativeVerification)
		}
	}
	if len(byScope) != 4 {
		t.Fatalf("promoted %d B41 facts, want 4: %v", len(byScope), byScope)
	}
	for pkg, w := range map[string]string{
		"example.com/usagedep/prod":     "product",
		"example.com/usagedep/shared":   "mixed",
		"example.com/usagedep/testonly": "test-only",
		"example.com/usagedep/unused":   "unknown",
	} {
		f, ok := byScope[pkg]
		if !ok {
			t.Fatalf("no B41 fact for %s", pkg)
		}
		if f.UsageScope != w {
			t.Fatalf("%s usage_scope=%s, want %s", pkg, f.UsageScope, w)
		}
		if w == "test-only" && f.ProductAbsenceVerification != ProductAbsenceVerificationVerified {
			t.Fatalf("test-only fact lacks product_absence_verification=VERIFIED: %+v", f)
		}
		if w != "test-only" && f.ProductAbsenceVerification != "" {
			t.Fatalf("%s fact carries product_absence_verification=%q", pkg, f.ProductAbsenceVerification)
		}
	}

	// The absent-from-both class is also an explicit unknown entry.
	foundUnknown := false
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "b41",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "example.com/usagedep | example.com/usagedep/unused") ||
			strings.Contains(u.Statement, "absent from both recorded build closures") {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatal("absent-from-both class not recorded as an explicit B41 unknown")
	}

	// Axis: one unknown-class fact ⇒ UNKNOWN, PACKAGE_BUILD,
	// deterministic, sorted B41 refs only — and validation passes.
	ax := r.ExploitationAxes.BuildUsageScope
	if ax == nil {
		t.Fatal("build_usage_scope axis missing with B41 facts present")
	}
	if ax.Status != AxisUnknown || ax.Level != LevelPackageBuild || ax.Basis != AxisBasisDeterministic {
		t.Fatalf("axis = %s/%s/%s, want UNKNOWN/PACKAGE_BUILD/deterministic", ax.Status, ax.Level, ax.Basis)
	}
	for _, ref := range ax.EvidenceRefs {
		f := func() *VerifiedFact {
			for i := range r.VerifiedFacts {
				if r.VerifiedFacts[i].ID == ref {
					return &r.VerifiedFacts[i]
				}
			}
			return nil
		}()
		if f == nil || f.Kind != FactKindBuildUsageScope {
			t.Fatalf("axis evidence_ref %q is not a BUILD_USAGE_SCOPE fact", ref)
		}
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("report invalid:\n%v", err)
	}
	// B41 facts alone can never raise the ladder: the report stays L2
	// with no B41 ref inside evidence_level.
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
		t.Fatalf("evidence_level=%v, want L2", r.EvidenceLevel)
	}
	for _, ref := range r.EvidenceLevel.EvidenceRefs {
		for _, f := range scopeFacts(lane) {
			if f.ID == ref {
				t.Fatalf("B41 fact %s leaked into evidence_level.evidence_refs", ref)
			}
		}
	}
	// And B41 adds no exploitation condition: no condition cites a
	// BUILD_USAGE_SCOPE fact.
	b41 := map[string]bool{}
	for _, f := range scopeFacts(lane) {
		b41[f.ID] = true
	}
	for _, c := range r.ExploitationConditions {
		for _, ref := range c.EvidenceRefs {
			if b41[ref] {
				t.Fatalf("condition %s cites B41 fact %s", c.ID, ref)
			}
		}
	}
	// Determinism: marshalling twice is byte-stable.
	b1, _ := json.Marshal(r.ExploitationAxes)
	b2, _ := json.Marshal(r.ExploitationAxes)
	if string(b1) != string(b2) {
		t.Fatal("axis serialization unstable")
	}
	f1, _ := json.Marshal(r.VerifiedFacts)
	f2, _ := json.Marshal(r.VerifiedFacts)
	if string(f1) != string(f2) {
		t.Fatal("facts serialization unstable")
	}
}

// A module-only advisory produces exactly one module-level aggregate
// check — never a package substitution.
func TestDeterministicUsageScopeModuleAggregate(t *testing.T) {
	lane, out := runUsageScopeLane(t, `{
	  "id": "GO-TEST-0041",
	  "summary": "module-only advisory",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/usagedep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
	  }]
	}`)
	var recs []evidencetools.AuditRecord
	for _, rec := range lane.Records {
		if rec.Tool == evidencetools.UsageScopeTool {
			recs = append(recs, rec)
		}
	}
	if len(recs) != 1 {
		t.Fatalf("usage-scope calls=%d, want 1 module aggregate", len(recs))
	}
	mod, pkg := scopeArgsOf(recs[0])
	if mod != "example.com/usagedep" || pkg != "" {
		t.Fatalf("aggregate args module=%q package=%q, want module only", mod, pkg)
	}
	// The wire args must omit the package key entirely.
	var raw map[string]any
	if err := json.Unmarshal(recs[0].Args, &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["package"]; has {
		t.Fatalf("aggregate args carry a package key: %s", recs[0].Args)
	}
	facts := scopeFacts(lane)
	if len(facts) != 1 {
		t.Fatalf("B41 facts=%d, want 1", len(facts))
	}
	f := facts[0]
	if f.UsageSubject == nil || f.UsageSubject.Package != "" || f.UsageSubject.Module != "example.com/usagedep" {
		t.Fatalf("aggregate fact subject %+v", f.UsageSubject)
	}
	if f.UsageScope != "mixed" {
		t.Fatalf("aggregate usage_scope=%s, want mixed (prod+shared in product closure, testonly in test)", f.UsageScope)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "b41-mod",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.ExploitationAxes.BuildUsageScope == nil {
		t.Fatal("axis missing for a promoted module aggregate")
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("module-aggregate report invalid:\n%v", err)
	}
}

// Candidate enumeration: packages explicit or symbol-projected, module
// aggregates only for entries with no package, non-Go skipped.
func TestDeterministicUsageScopeCandidates(t *testing.T) {
	v := domain.Vulnerability{
		ID: "GO-X",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/usagedep",
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/usagedep/prod", Symbols: []string{"Name"}}},
				AffectedSymbols:  []domain.SymbolRef{{Package: "example.com/usagedep/testonly", Symbol: "Helper"}},
			},
			{Module: "example.com/modonly"},
			{Module: "left-pad"}, // not in the Go set
		},
	}
	got := usageScopeCandidates(v, map[string]bool{
		"example.com/usagedep": true, "example.com/modonly": true,
	})
	want := []FactUsageSubject{
		{Module: "example.com/usagedep", Package: "example.com/usagedep/prod"},
		{Module: "example.com/usagedep", Package: "example.com/usagedep/testonly"},
		{Module: "example.com/modonly"},
	}
	if len(got) != len(want) {
		t.Fatalf("candidates=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d]=%+v, want %+v", i, got[i], want[i])
		}
	}
	for _, s := range got {
		if s.Module == "left-pad" {
			t.Fatal("non-Go entry produced a candidate")
		}
	}
	t.Run("duplicate package declarations never create a module aggregate", func(t *testing.T) {
		dup := domain.Vulnerability{
			ID: "GO-DUP",
			AffectedModules: []domain.AffectedModule{
				{
					Module:           "example.com/usagedep",
					AffectedPackages: []domain.AffectedPackage{{Path: "example.com/usagedep/prod"}},
				},
				{
					Module:           "example.com/usagedep",
					AffectedPackages: []domain.AffectedPackage{{Path: "example.com/usagedep/prod"}},
				},
			},
		}
		got := usageScopeCandidates(dup, map[string]bool{"example.com/usagedep": true})
		want := []FactUsageSubject{
			{Module: "example.com/usagedep", Package: "example.com/usagedep/prod"},
		}
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("duplicate declarations produced candidates %v, want %v", got, want)
		}
	})
}

func TestUsageScopeNonCarrierInLadderAndPartial(t *testing.T) {
	// A B41 fact id cited on a deterministic SUPPORTED path condition
	// must never enter evidence_level.evidence_refs and never count as
	// a confirmed transition toward attack_scenario=PARTIAL.
	b41Fact := VerifiedFact{
		ID:     "fact-obs-0099",
		Kind:   FactKindBuildUsageScope,
		Status: "OK",
		Tool:   evidencetools.UsageScopeTool,
		UsageSubject: &FactUsageSubject{
			Module:  "golang.org/x/net",
			Package: "golang.org/x/net/http2",
		},
		UsageScope:                 "test-only",
		ProductAbsenceVerification: "VERIFIED",
	}
	cond := ExploitationCondition{
		ID:        "C-01",
		Subject:   subjProductPackageUsage,
		State:     StateSupported,
		Origin:    OriginDeterm,
		Necessity: "required",
		Role:      ConditionRolePath,
		EvidenceRefs: []string{
			"fact-obs-0099",
		},
		UsageSubject: &FactUsageSubject{Module: "golang.org/x/net", Package: "golang.org/x/net/http2"},
	}
	open := ExploitationCondition{
		ID:        "C-02",
		Subject:   subjPackageReach,
		State:     StateUnknown,
		Origin:    OriginDeterm,
		Necessity: "required",
		Role:      ConditionRolePath,
	}
	r := &Report{
		VerifiedFacts:          []VerifiedFact{b41Fact},
		ExploitationConditions: []ExploitationCondition{cond, open},
	}
	el := deriveEvidenceLevel(r)
	for _, ref := range el.EvidenceRefs {
		if ref == "fact-obs-0099" {
			t.Fatalf("B41 fact leaked into evidence_level.evidence_refs: %v", el.EvidenceRefs)
		}
	}

	a := &assembler{factByID: map[string]bool{"fact-obs-0099": true}}
	a.slice2AttackStatus(r)
	if r.AttackScenario.Status == StatusPartial {
		t.Fatal("B41 fact counted as a confirmed transition (PARTIAL)")
	}
}

// Promotion through the real persist projection: only OK+COMPLETE
// decodable records with a bound subject become facts.
func TestDeterministicUsageScopePromotion(t *testing.T) {
	mk := func(id, comp, scope, prodAbs string) *evidencetools.Observation {
		o := scopeObs(id, "example.com/usagedep", "example.com/usagedep/prod", scope,
			evidencetools.Completeness(comp))
		if prodAbs != "" {
			m := o.Data.(map[string]any)
			m["product_absence_verification"] = prodAbs
		}
		return o
	}
	args := map[string]any{"module": "example.com/usagedep", "package": "example.com/usagedep/prod"}

	t.Run("test-only promotes with VERIFIED product absence", func(t *testing.T) {
		lane, _ := persistedLane(t,
			mk("OBS-0031", "COMPLETE", "test-only", "VERIFIED"),
			evidencetools.UsageScopeData{
				Module: "example.com/usagedep", Package: "example.com/usagedep/prod",
				UsageScope: "test-only", TestLinked: true,
				ProductAbsenceVerification: "VERIFIED", CheckScope: "scope",
			}, args)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0031" {
				f = &lane.Facts[i]
			}
		}
		if f == nil {
			t.Fatal("test-only observation did not promote")
		}
		if f.Kind != FactKindBuildUsageScope || f.UsageScope != "test-only" ||
			f.ProductAbsenceVerification != "VERIFIED" || f.NegativeVerification != "" ||
			f.Claim != "TRUE" || f.Coverage != "COMPLETE" {
			t.Fatalf("promoted fact shape: %+v", f)
		}
		if f.UsageSubject == nil || f.UsageSubject.Package != "example.com/usagedep/prod" ||
			f.UsageSubject.Symbol != "" {
			t.Fatalf("fact subject %+v", f.UsageSubject)
		}
	})

	t.Run("absent-from-both promotes an auditable unknown fact", func(t *testing.T) {
		unusedArgs := map[string]any{"module": "example.com/usagedep", "package": "example.com/usagedep/unused"}
		o := scopeObs("OBS-0031", "example.com/usagedep", "example.com/usagedep/unused", "unknown",
			evidencetools.CompletenessComplete)
		lane, _ := persistedLane(t, o,
			evidencetools.UsageScopeData{
				Module: "example.com/usagedep", Package: "example.com/usagedep/unused",
				UsageScope: "unknown", CheckScope: "scope",
			}, unusedArgs)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0031" {
				f = &lane.Facts[i]
			}
		}
		if f == nil {
			t.Fatal("absent-from-both observation did not promote")
		}
		if f.UsageScope != "unknown" || f.ProductAbsenceVerification != "" || f.Claim != "TRUE" {
			t.Fatalf("unknown-class fact shape: %+v", f)
		}
	})

	t.Run("vendor-inventory marker promotes on unknown", func(t *testing.T) {
		vendorArgs := map[string]any{"module": "example.com/usagedep", "package": "example.com/usagedep/absent"}
		o := scopeObs("OBS-0032", "example.com/usagedep", "example.com/usagedep/absent", "unknown",
			evidencetools.CompletenessComplete)
		o.Data.(map[string]any)["product_absence_verification"] = "VERIFIED_VENDOR_INVENTORY"
		o.Data.(map[string]any)["closure_source"] = "vendor/modules.txt+source-imports"
		o.Data.(map[string]any)["closure_semantics"] = "product_all_packages"
		lane, _ := persistedLane(t, o,
			evidencetools.UsageScopeData{
				Module: "example.com/usagedep", Package: "example.com/usagedep/absent",
				UsageScope:                 "unknown",
				ProductAbsenceVerification: "VERIFIED_VENDOR_INVENTORY",
				ClosureSource:              "vendor/modules.txt+source-imports",
				ClosureSemantics:           "product_all_packages",
				CheckScope:                 "scope",
			}, vendorArgs)
		var f *VerifiedFact
		for i := range lane.Facts {
			if lane.Facts[i].Provenance.ObservationID == "OBS-0032" {
				f = &lane.Facts[i]
			}
		}
		if f == nil {
			t.Fatal("vendor-inventory absence observation did not promote")
		}
		if f.UsageScope != "unknown" ||
			f.ProductAbsenceVerification != ProductAbsenceVerificationVendorInventory ||
			f.NegativeVerification != "" || f.Claim != "TRUE" || f.Coverage != "COMPLETE" {
			t.Fatalf("vendor-inventory fact shape: %+v", f)
		}
	})

	t.Run("degraded stream never promotes", func(t *testing.T) {
		lane, _ := persistedLane(t,
			mk("OBS-0031", "PARTIAL", "test-only", "VERIFIED"),
			evidencetools.UsageScopeData{
				Module: "example.com/usagedep", Package: "example.com/usagedep/prod",
				UsageScope: "test-only", ProductAbsenceVerification: "VERIFIED", CheckScope: "scope",
			}, args)
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0031" {
				t.Fatalf("PARTIAL usage-scope observation promoted: %+v", f)
			}
		}
	})

	t.Run("error observation never promotes", func(t *testing.T) {
		o := mk("OBS-0031", "UNKNOWN", "test-only", "")
		o.ToolStatus = evidencetools.StatusError
		o.Error = "go list failed"
		o.Data = nil
		lane, _ := persistedLane(t, o, nil, args)
		for _, f := range lane.Facts {
			if f.Provenance.ObservationID == "OBS-0031" {
				t.Fatalf("ERROR usage-scope observation promoted: %+v", f)
			}
		}
	})
}

// ---- the optional /3 axis ----

func TestUsageScopeAxis(t *testing.T) {
	t.Run("no B41 facts means no axis member", func(t *testing.T) {
		r := Assemble(AssembleInput{
			Lane:              fakeLane(t),
			DeterministicOnly: true, RunID: "no-b41",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
		if r.ExploitationAxes.BuildUsageScope != nil {
			t.Fatalf("axis present without B41 facts: %+v", r.ExploitationAxes.BuildUsageScope)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("no-B41 report invalid:\n%v", err)
		}
		// The serialized /3 document omits the member entirely.
		b, err := RenderJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		var probe map[string]any
		if err := json.Unmarshal(b, &probe); err != nil {
			t.Fatal(err)
		}
		axes := probe["exploitation_axes"].(map[string]any)
		if _, has := axes["build_usage_scope"]; has {
			t.Fatal("serialized axes carry build_usage_scope without B41 facts")
		}
	})

	t.Run("all-known classes derive ESTABLISHED with sorted refs", func(t *testing.T) {
		lane := fakeLane(t)
		lane.Advisory.Vuln.AffectedModules = []domain.AffectedModule{{
			Module: "example.com/usagedep",
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/usagedep/prod"},
				{Path: "example.com/usagedep/testonly"},
			},
		}}
		lane.Facts = append(lane.Facts,
			scopeFact("OBS-0032", "example.com/usagedep", "example.com/usagedep/testonly", "test-only", "VERIFIED"),
			scopeFact("OBS-0031", "example.com/usagedep", "example.com/usagedep/prod", "product", ""),
		)
		r := Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "b41-est",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
		ax := r.ExploitationAxes.BuildUsageScope
		if ax == nil {
			t.Fatal("axis missing with known B41 facts")
		}
		if ax.Status != AxisEstablished || ax.Level != LevelPackageBuild || ax.Basis != AxisBasisDeterministic {
			t.Fatalf("axis=%s/%s/%s", ax.Status, ax.Level, ax.Basis)
		}
		want := []string{"fact-obs-0031", "fact-obs-0032"}
		if len(ax.EvidenceRefs) != 2 || ax.EvidenceRefs[0] != want[0] || ax.EvidenceRefs[1] != want[1] {
			t.Fatalf("axis refs=%v, want sorted %v", ax.EvidenceRefs, want)
		}
		if !strings.Contains(ax.Statement, "build-closure") ||
			strings.Contains(strings.ToLower(ax.Statement), "safe") ||
			strings.Contains(strings.ToLower(ax.Statement), "exploit") {
			t.Fatalf("axis statement must describe build closure only: %q", ax.Statement)
		}
		var hasClosure, hasNoRuntime, hasBounded bool
		for _, l := range ax.Limitations {
			if strings.Contains(l, "build-closure membership") {
				hasClosure = true
			}
			if strings.Contains(l, "no source-level use") && strings.Contains(l, "safety") {
				hasNoRuntime = true
			}
			if strings.Contains(l, "test-only product absence") && strings.Contains(l, "closure") {
				hasBounded = true
			}
		}
		if !hasClosure || !hasNoRuntime || !hasBounded {
			t.Fatalf("axis limitations missing required bounds: %v", ax.Limitations)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("all-known report invalid:\n%v", err)
		}
	})

	t.Run("any unknown-class fact derives UNKNOWN", func(t *testing.T) {
		lane := fakeLane(t)
		lane.Facts = append(lane.Facts,
			scopeFact("OBS-0031", "example.com/usagedep", "example.com/usagedep/prod", "product", ""),
			scopeFact("OBS-0032", "example.com/usagedep", "example.com/usagedep/unused", "unknown", ""),
		)
		r := Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "b41-unk",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
		ax := r.ExploitationAxes.BuildUsageScope
		if ax == nil || ax.Status != AxisUnknown {
			t.Fatalf("axis=%+v, want UNKNOWN", ax)
		}
		if err := Validate(r, ""); err != nil {
			t.Fatalf("unknown-class report invalid:\n%v", err)
		}
	})
}

// The axis is strictly non-carrier: B41 facts alone cannot close a
// condition or raise the ladder — an L2 report stays L2 — and B41
// facts never enter evidence_level.evidence_refs.
func TestUsageScopeAxisNonCarrier(t *testing.T) {
	// Baseline: a lane whose advisory declares a package candidate but
	// whose package-usage check produced no carrier — the usage path
	// condition stays UNKNOWN and the ladder is L2.
	openLane := func(withB41 bool) *LaneResult {
		lane := fakeLane(t)
		lane.Advisory.Vuln.AffectedModules = []domain.AffectedModule{{
			Module:           "golang.org/x/net",
			AffectedPackages: []domain.AffectedPackage{{Path: "golang.org/x/net/http2"}},
		}}
		if withB41 {
			lane.Facts = append(lane.Facts,
				scopeFact("OBS-0031", "golang.org/x/net", "golang.org/x/net/http2", "product", ""),
				scopeFact("OBS-0032", "golang.org/x/net", "golang.org/x/net/testonly", "test-only", "VERIFIED"))
		}
		return lane
	}
	without := Assemble(AssembleInput{
		Lane: openLane(false), DeterministicOnly: true, RunID: "nc0",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	with := Assemble(AssembleInput{
		Lane: openLane(true), DeterministicOnly: true, RunID: "nc1",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if without.EvidenceLevel.Level != EvidenceLevelL2 {
		t.Fatalf("baseline level=%s, want L2 for this fixture", without.EvidenceLevel.Level)
	}
	if with.EvidenceLevel.Level != EvidenceLevelL2 {
		t.Fatalf("B41 facts raised the ladder: %s -> %s", without.EvidenceLevel.Level, with.EvidenceLevel.Level)
	}
	b41 := map[string]bool{"fact-obs-0031": true, "fact-obs-0032": true}
	for _, ref := range with.EvidenceLevel.EvidenceRefs {
		if b41[ref] {
			t.Fatalf("B41 fact %s entered evidence_level.evidence_refs", ref)
		}
	}
	for _, c := range with.ExploitationConditions {
		for _, ref := range c.EvidenceRefs {
			if b41[ref] {
				t.Fatalf("condition %s cites B41 fact %s", c.ID, ref)
			}
		}
	}
	if len(with.ExploitationConditions) != len(without.ExploitationConditions) {
		t.Fatalf("B41 added conditions: %d -> %d", len(without.ExploitationConditions), len(with.ExploitationConditions))
	}
}

// Agent claims never fill the B41 axis.
func TestUsageScopeAgentCannotFillAxis(t *testing.T) {
	lane := fakeLane(t)
	turn := turnFor(t, map[string]any{
		"category":  "vulnerable",
		"reasoning": "the vulnerable package is only used by tests (test-only usage scope)",
		"assessment": map[string]any{
			"attack_scenario": "test-only usage of the affected package",
		},
	})
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "b41-agent",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.ExploitationAxes.BuildUsageScope != nil {
		t.Fatalf("agent-only usage text populated the B41 axis: %+v", r.ExploitationAxes.BuildUsageScope)
	}
	for _, f := range r.VerifiedFacts {
		if f.Kind == FactKindBuildUsageScope {
			t.Fatalf("agent claim became a B41 fact: %+v", f)
		}
	}
}

// ---- consistency guard ----

func TestUsageScopeConsistency(t *testing.T) {
	mkReport := func(facts ...VerifiedFact) *Report {
		lane := fakeLane(t)
		lane.Facts = append(lane.Facts, facts...)
		return Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "cons",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
	}
	b41 := scopeFact("OBS-0031", "example.com/usagedep", "example.com/usagedep/testonly", "test-only", "VERIFIED")
	carrier := usageFact("OBS-0032", "example.com/usagedep", "example.com/usagedep/testonly", "", "TRUE", "", "used")
	lowerBound := usageLowerBoundFact("OBS-0033", "example.com/usagedep", "example.com/usagedep/testonly", "", "lb")

	t.Run("test-only plus carrier PACKAGE_USAGE is rejected", func(t *testing.T) {
		r := mkReport(b41, carrier)
		err := Validate(r, "")
		if err == nil {
			t.Fatal("test-only B41 fact coexisting with a carrier PACKAGE_USAGE fact accepted")
		}
		if !strings.Contains(err.Error(), "cannot coexist") {
			t.Fatalf("rejection does not name the B41/B42 conflict:\n%v", err)
		}
	})

	t.Run("symbol-level carrier for the same package still conflicts", func(t *testing.T) {
		symCarrier := usageFact("OBS-0034", "example.com/usagedep", "example.com/usagedep/testonly", "Name", "TRUE", "", "used")
		r := mkReport(b41, symCarrier)
		if err := Validate(r, ""); err == nil {
			t.Fatal("symbol-level PACKAGE_USAGE carrier escaped the guard")
		}
	})

	t.Run("lower bound is not a carrier and does not conflict", func(t *testing.T) {
		r := mkReport(b41, lowerBound)
		if errs := buildUsageScopeConflicts(r); len(errs) != 0 {
			t.Fatalf("lower-bound fact flagged as carrier: %v", errs)
		}
	})

	t.Run("module aggregate never participates", func(t *testing.T) {
		agg := scopeFact("OBS-0035", "example.com/usagedep", "", "test-only", "VERIFIED")
		// A module aggregate with test-only scope is unusual but must
		// never be compared package-wise.
		r := mkReport(agg, carrier)
		if errs := buildUsageScopeConflicts(r); len(errs) != 0 {
			t.Fatalf("module aggregate entered the comparison: %v", errs)
		}
	})

	t.Run("product/mixed/unknown never conflict", func(t *testing.T) {
		for _, scope := range []string{"product", "mixed", "unknown"} {
			f := scopeFact("OBS-0031", "example.com/usagedep", "example.com/usagedep/testonly", scope, "")
			r := mkReport(f, carrier)
			if errs := buildUsageScopeConflicts(r); len(errs) != 0 {
				t.Fatalf("usage_scope=%s flagged: %v", scope, errs)
			}
		}
	})

	t.Run("a different package subject never conflicts", func(t *testing.T) {
		other := scopeFact("OBS-0031", "example.com/usagedep", "example.com/usagedep/other", "test-only", "VERIFIED")
		r := mkReport(other, carrier)
		if errs := buildUsageScopeConflicts(r); len(errs) != 0 {
			t.Fatalf("different package flagged: %v", errs)
		}
	})
}

// ---- unknown/follow-up entries ----

func TestUsageScopeUnknowns(t *testing.T) {
	build := func(o *evidencetools.Observation, fact *VerifiedFact) *Report {
		lane := fakeLane(t)
		lane.Observations = append(lane.Observations, o)
		lane.Advisory.Vuln.AffectedModules = []domain.AffectedModule{{
			Module:           "example.com/usagedep",
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/usagedep/prod"}},
		}}
		if fact != nil {
			lane.Facts = append(lane.Facts, *fact)
		}
		return Assemble(AssembleInput{
			Lane: lane, DeterministicOnly: true, RunID: "b41u",
			StartedAt: time.Now(), FinishedAt: time.Now(),
		})
	}
	findUnknown := func(r *Report, obsID string) *UnknownEntry {
		for i := range r.Unknowns {
			for _, ref := range r.Unknowns[i].EvidenceRefs {
				if ref == "obs:"+obsID || ref == "fact-"+strings.ToLower(obsID) {
					return &r.Unknowns[i]
				}
			}
		}
		return nil
	}

	t.Run("error row keeps the generic unknown only", func(t *testing.T) {
		o := scopeObs("OBS-0041", "example.com/usagedep", "example.com/usagedep/prod", "product",
			evidencetools.CompletenessUnknown)
		o.ToolStatus = evidencetools.StatusError
		o.Error = "go list stream failed"
		o.Data = nil
		r := build(o, nil)
		u := findUnknown(r, "OBS-0041")
		if u == nil {
			t.Fatal("ERROR usage-scope row produced no unknown")
		}
		if u.Group != "build_usage_scope" {
			t.Fatalf("usage-scope unknown grouped %q", u.Group)
		}
		if r.ExploitationAxes.BuildUsageScope != nil {
			t.Fatal("axis present for a failed check")
		}
	})

	t.Run("degraded stream gets the explicit incomplete-stream entry", func(t *testing.T) {
		o := scopeObs("OBS-0041", "example.com/usagedep", "example.com/usagedep/prod", "product",
			evidencetools.CompletenessPartial)
		r := build(o, nil)
		u := findUnknown(r, "OBS-0041")
		if u == nil {
			t.Fatal("PARTIAL usage-scope row produced no unknown")
		}
		if !strings.Contains(u.Statement, "did not close the paired build-closure stream") {
			t.Fatalf("degraded-stream unknown wording: %q", u.Statement)
		}
	})

	t.Run("absent-from-both is an auditable undetermined entry", func(t *testing.T) {
		o := scopeObs("OBS-0041", "example.com/usagedep", "example.com/usagedep/unused", "unknown",
			evidencetools.CompletenessComplete)
		f := scopeFact("OBS-0041", "example.com/usagedep", "example.com/usagedep/unused", "unknown", "")
		r := build(o, &f)
		u := findUnknown(r, "OBS-0041")
		if u == nil {
			t.Fatal("absent-from-both class produced no unknown entry")
		}
		if !strings.Contains(u.Statement, "absent from both recorded build closures") {
			t.Fatalf("absent-from-both wording: %q", u.Statement)
		}
		// The entry cites the promoted fact (auditable class), and the
		// paired open/residual questions exist.
		foundPair := false
		for _, q := range r.OpenQuestions {
			if q.Subject == u.ID {
				foundPair = true
			}
		}
		if !foundPair {
			t.Fatalf("unknown %s has no paired open question", u.ID)
		}
		if r.ExploitationAxes.BuildUsageScope == nil || r.ExploitationAxes.BuildUsageScope.Status != AxisUnknown {
			t.Fatal("axis must exist and be UNKNOWN for the absent-from-both class")
		}
	})
}
