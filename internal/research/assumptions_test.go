package research

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

const assumptionsSectionHeading = "## Declared assumptions — policy/scope inputs, not deterministic evidence"

func assumptionsUnit(id string, kind domain.DeclaredAssumptionKind, scope string) domain.DeclaredAssumption {
	a := domain.DeclaredAssumption{
		ID:         id,
		Kind:       kind,
		Statement:  "statement for " + id,
		Scope:      scope,
		Authority:  "security-owner",
		Owner:      "platform-security",
		SourceRef:  "policy://" + id,
		ReviewDate: "2027-01-01",
	}
	if kind == domain.AssumptionSupportedTargets {
		a.Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}, GOARCH: []string{"amd64"}}
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return a
}

func assumptionsUnitDoc(members ...domain.DeclaredAssumption) domain.DeclaredAssumptionsDocument {
	return domain.DeclaredAssumptionsDocument{
		Schema:        domain.DeclaredAssumptionsSchema,
		Assumptions:   members,
		ContentDigest: domain.DeclaredAssumptionsContentDigest(domain.DeclaredAssumptionsSchema, members),
	}
}

func writeAssumptionsDoc(t *testing.T, dir, name string, doc domain.DeclaredAssumptionsDocument) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func assumptionsInputForTest(doc domain.DeclaredAssumptionsDocument) *domain.DeclaredAssumptionsInput {
	return &domain.DeclaredAssumptionsInput{
		Path: "local:assumptions.json", SHA256: strings.Repeat("ab", 32),
		Schema: doc.Schema, ContentDigest: doc.ContentDigest, Assumptions: doc.Assumptions,
	}
}

// The channel end to end: the lane loads the document, records it as a
// provenance observation, projects it into the report input, renders it
// in its own section, and keeps it out of evidence/facts.
func TestDeclaredAssumptionsLaneAndReport(t *testing.T) {
	dir := t.TempDir()
	trust := assumptionsUnit("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := assumptionsUnit("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	path := writeAssumptionsDoc(t, dir, "assumptions.json", assumptionsUnitDoc(trust, targets))

	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.DeclaredAssumptions = path
	})
	if lane.Assumptions == nil || lane.Assumptions.LoadError != "" {
		t.Fatalf("lane assumption record = %+v", lane.Assumptions)
	}
	if lane.Assumptions.Path != "local:assumptions.json" || lane.Assumptions.SHA256 == "" {
		t.Fatalf("lane assumption provenance = %+v", lane.Assumptions)
	}
	if ids := lane.Assumptions.AssumptionIDs(); len(ids) != 2 || ids[0] != trust.ID {
		t.Fatalf("assumption ids = %v", ids)
	}

	// The lane observation records provenance/member identity only —
	// no statement text, no secret material.
	var obs *evidencetools.Observation
	for _, o := range lane.Observations {
		if o.Tool == "declared-assumptions" {
			obs = o
		}
	}
	if obs == nil {
		t.Fatal("declared-assumptions lane observation missing")
	}
	if obs.Completeness != evidencetools.CompletenessComplete {
		t.Fatalf("observation completeness = %s", obs.Completeness)
	}
	raw, _ := json.Marshal(obs.Data)
	for _, want := range []string{`"ids"`, trust.ID, targets.ID, "declared-assumptions/1", lane.Assumptions.SHA256} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("observation data lacks %q: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), trust.Statement) {
		t.Fatalf("observation copied assumption statement text: %s", raw)
	}

	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "assumptions",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Input.DeclaredAssumptions == nil || r.Input.DeclaredAssumptions.LoadError != "" {
		t.Fatalf("report input assumptions = %+v", r.Input.DeclaredAssumptions)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("report with assumptions invalid:\n%v", err)
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), assumptionsSectionHeading) ||
		!strings.Contains(string(md), trust.Statement) ||
		!strings.Contains(string(md), "policy/scope inputs") {
		t.Fatalf("assumptions section missing from markdown:\n%s", md)
	}

	// Assumptions never enter the evidence space: no fact/evidence id
	// equals an assumption id, and no fact claims it.
	assumptionIDs := map[string]bool{trust.ID: true, targets.ID: true}
	for _, f := range r.VerifiedFacts {
		if assumptionIDs[f.ID] {
			t.Fatalf("assumption id used as verified fact id: %s", f.ID)
		}
	}
	jb, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		VerifiedFacts []struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Tool   string `json:"tool"`
			Claim  string `json:"claim"`
			Status string `json:"status"`
		} `json:"verified_facts"`
	}
	if err := json.Unmarshal(jb, &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.VerifiedFacts {
		if assumptionIDs[f.ID] || f.Tool == "declared-assumptions" && f.Kind == string(domain.EvidenceConfiguration) {
			t.Fatalf("assumption promoted into evidence: %+v", f)
		}
	}
	// The report input carries the typed members for audit while the
	// policy ids stay out of evidence_refs.
	if refs := strings.Join(r.Decision.EvidenceRefs, ","); strings.Contains(refs, trust.ID) || strings.Contains(refs, targets.ID) {
		t.Fatalf("assumption id cited as evidence: %s", refs)
	}
}

// A malformed document fails closed: the record keeps provenance, the
// observation is PARTIAL, the report stays valid, and admission refuses
// the document.
func TestDeclaredAssumptionsMalformedLane(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"schema":"declared-assumptions/1","assumptions":[{"id":"A"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.DeclaredAssumptions = path
	})
	if lane.Assumptions == nil || lane.Assumptions.LoadError != domain.AssumptionsLoadInvalid {
		t.Fatalf("malformed document record = %+v", lane.Assumptions)
	}
	var obs *evidencetools.Observation
	for _, o := range lane.Observations {
		if o.Tool == "declared-assumptions" {
			obs = o
		}
	}
	if obs == nil || obs.Completeness != evidencetools.CompletenessPartial {
		t.Fatalf("failed-intake observation = %+v", obs)
	}
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "assumptions-bad",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Input.DeclaredAssumptions == nil || r.Input.DeclaredAssumptions.LoadError != domain.AssumptionsLoadInvalid {
		t.Fatalf("report input = %+v", r.Input.DeclaredAssumptions)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("report with failed assumptions invalid:\n%v", err)
	}
	md, _ := RenderMarkdown(r)
	if !strings.Contains(string(md), "intake failed closed") {
		t.Fatalf("failed intake not rendered:\n%s", md)
	}
	if _, err := domain.AdmitAssumption(r.Input.DeclaredAssumptions, domain.AssumptionConfigTrust,
		domain.AssumptionScopeProduct, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectDocumentInvalid {
		t.Fatalf("failed channel admitted: %v", err)
	}
}

// Legacy reports keep their exact shape: no channel, no member.
func TestDeclaredAssumptionsAbsentKeepsLegacyShape(t *testing.T) {
	r := validReport(t)
	if r.Input.DeclaredAssumptions != nil {
		t.Fatal("lane without the channel carries an assumptions record")
	}
	jb, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(jb), "declared_assumptions") {
		t.Fatal("legacy report gained a declared_assumptions member")
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(md), assumptionsSectionHeading) {
		t.Fatal("legacy report gained an assumptions section")
	}
	// No document means no admissible config-trust assertion — the
	// channel is the only door.
	if _, err := domain.AdmitAssumption(nil, domain.AssumptionConfigTrust, domain.AssumptionScopeProduct,
		time.Now()); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectDocumentAbsent {
		t.Fatalf("missing document admitted: %v", err)
	}
}

// Report validation re-checks the persisted document: hand-edited
// statements, broken digests and dangling decision ids are rejected.
func TestDeclaredAssumptionsReportValidation(t *testing.T) {
	trust := assumptionsUnit("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	valid := assumptionsInputForTest(assumptionsUnitDoc(trust))

	t.Run("valid input block", func(t *testing.T) {
		r := validReport(t)
		r.Input.DeclaredAssumptions = valid
		if err := Validate(r, ""); err != nil {
			t.Fatalf("valid assumptions block rejected:\n%v", err)
		}
	})

	problems := func(t *testing.T, da *domain.DeclaredAssumptionsInput) string {
		t.Helper()
		e := &ValidationError{}
		validateDeclaredAssumptionsInput(e, da)
		return strings.Join(e.Problems, "\n")
	}
	t.Run("tampered member", func(t *testing.T) {
		da := assumptionsInputForTest(assumptionsUnitDoc(trust))
		da.Assumptions[0].Statement = "hand-edited report text"
		if got := problems(t, da); !strings.Contains(got, "digest") {
			t.Fatalf("tampered member accepted: %q", got)
		}
	})
	t.Run("missing schema", func(t *testing.T) {
		da := assumptionsInputForTest(assumptionsUnitDoc(trust))
		da.Schema = ""
		if got := problems(t, da); !strings.Contains(got, "schema") {
			t.Fatalf("missing schema accepted: %q", got)
		}
	})
	t.Run("missing intake digest", func(t *testing.T) {
		da := assumptionsInputForTest(assumptionsUnitDoc(trust))
		da.SHA256 = ""
		if got := problems(t, da); !strings.Contains(got, "sha256") {
			t.Fatalf("missing digest accepted: %q", got)
		}
	})
	t.Run("absolute path", func(t *testing.T) {
		da := assumptionsInputForTest(assumptionsUnitDoc(trust))
		da.Path = "/home/operator/assumptions.json"
		if got := problems(t, da); !strings.Contains(got, "provenance ref") {
			t.Fatalf("absolute path accepted: %q", got)
		}
	})
	t.Run("unknown load error", func(t *testing.T) {
		da := &domain.DeclaredAssumptionsInput{Path: "local:x", LoadError: "SOMETHING_ELSE"}
		if got := problems(t, da); !strings.Contains(got, "load_error") {
			t.Fatalf("unknown load error accepted: %q", got)
		}
	})
	t.Run("audit members under load error", func(t *testing.T) {
		da := &domain.DeclaredAssumptionsInput{Path: "local:x", SHA256: strings.Repeat("ab", 32),
			LoadError: domain.AssumptionsLoadInvalid, Assumptions: []domain.DeclaredAssumption{trust}}
		if got := problems(t, da); got != "" {
			t.Fatalf("audit members under a failed channel rejected: %q", got)
		}
	})
	t.Run("failed channel admits no decision refs", func(t *testing.T) {
		r := validReport(t)
		r.Schema = ReportSchemaV2
		r.Input.DeclaredAssumptions = &domain.DeclaredAssumptionsInput{
			Path: "local:bad.json", LoadError: domain.AssumptionsLoadInvalid,
			Assumptions: []domain.DeclaredAssumption{trust},
		}
		r.Decision = &EvidenceDecision{
			Verdict: domain.VerdictInconclusive, Reason: "policy input missing",
			Scope: "verification scope", Coverage: "NOT_EVALUATED",
			TicketRationale: "follow-up: reload a valid assumptions document",
			HumanQuestions:  []string{"which policy input resolves the gate?"},
			AssumptionIDs:   []string{trust.ID},
		}
		err := Validate(r, "")
		if err == nil || !strings.Contains(err.Error(), "does not resolve to input.declared_assumptions") {
			t.Fatalf("failed channel admitted a decision assumption ref: %v", err)
		}
	})
}

// Decision assumption refs resolve only against the declared document
// and never through the evidence space.
func TestAssumptionRefsResolveSeparatelyFromEvidence(t *testing.T) {
	baseDecision := func(ids ...string) *Report {
		return &Report{Decision: &EvidenceDecision{
			Verdict: domain.VerdictInconclusive, Reason: "unresolved",
			Scope: "verification scope", Coverage: "NOT_EVALUATED",
			TicketRationale: "follow-up: provide a deterministic check",
			HumanQuestions:  []string{"which check?"},
			AssumptionIDs:   ids,
		}}
	}
	refs := func() *refSpace {
		return &refSpace{
			facts:       map[string]bool{"fact-obs-0001": true},
			obs:         map[string]bool{"obs:OBS-0001": true},
			assumptions: map[string]bool{"ASM-CONFIG-TRUST": true},
		}
	}

	t.Run("admitted assumption resolves", func(t *testing.T) {
		e := &ValidationError{}
		validateDecision(e, baseDecision("ASM-CONFIG-TRUST"), refs())
		if len(e.Problems) != 0 {
			t.Fatalf("declared assumption ref rejected: %v", e.Problems)
		}
	})
	t.Run("undeclared assumption does not resolve", func(t *testing.T) {
		e := &ValidationError{}
		validateDecision(e, baseDecision("ASM-NOT-DECLARED"), refs())
		if !strings.Contains(strings.Join(e.Problems, "\n"), "does not resolve to input.declared_assumptions") {
			t.Fatalf("undeclared assumption accepted: %v", e.Problems)
		}
	})
	t.Run("assumption id doubling as evidence is rejected", func(t *testing.T) {
		r := refs()
		r.assumptions["fact-obs-0001"] = true
		e := &ValidationError{}
		validateDecision(e, baseDecision("fact-obs-0001"), r)
		if !strings.Contains(strings.Join(e.Problems, "\n"), "never evidence") {
			t.Fatalf("assumption/evidence collision accepted: %v", e.Problems)
		}
	})
	t.Run("duplicate citation is rejected", func(t *testing.T) {
		e := &ValidationError{}
		validateDecision(e, baseDecision("ASM-CONFIG-TRUST", "ASM-CONFIG-TRUST"), refs())
		if !strings.Contains(strings.Join(e.Problems, "\n"), "listed twice") {
			t.Fatalf("duplicate citation accepted: %v", e.Problems)
		}
	})
}

// Negative control: a declared assumption is an input, never a claim.
// It cannot close an unproven case — the same report that carries a
// valid config-trust and product-targets document still lands
// INCONCLUSIVE because no deterministic proof was provided.
func TestAssumptionAloneNeverProducesVerdict(t *testing.T) {
	dir := t.TempDir()
	trust := assumptionsUnit("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := assumptionsUnit("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	path := writeAssumptionsDoc(t, dir, "assumptions.json", assumptionsUnitDoc(trust, targets))
	lane, out := fixtureLaneOpts(t, fixedRangeAdvisory, func(o *LaneOptions) {
		o.DeclaredAssumptions = path
	})
	r := Assemble(AssembleInput{
		Lane: lane, DeterministicOnly: true, RunID: "assumption-alone",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.Decision == nil || r.Decision.Verdict != domain.VerdictInconclusive {
		t.Fatalf("assumption alone produced a verdict: %+v", r.Decision)
	}
	if len(r.Decision.AssumptionIDs) != 0 {
		t.Fatalf("decision cited an assumption without a proof: %v", r.Decision.AssumptionIDs)
	}
	if err := Validate(r, out); err != nil {
		t.Fatalf("assumption-only report invalid:\n%v", err)
	}
	// The G1 policy gate: with a document that declares only the target
	// matrix, config-trust stays inadmissible — no origin fact can
	// substitute for it.
	targetsOnly := assumptionsInputForTest(assumptionsUnitDoc(targets))
	if _, err := domain.AdmitAssumption(targetsOnly, domain.AssumptionConfigTrust,
		domain.AssumptionScopeProduct, time.Now()); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectAbsent {
		t.Fatalf("config-trust admitted from a targets-only document: %v", err)
	}
	// The G2 policy gate: an artifact-only declaration can never satisfy
	// a product-wide target requirement.
	artifact := assumptionsUnit("ASM-ARTIFACT", domain.AssumptionSupportedTargets, domain.AssumptionScopeArtifact)
	artifact.Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}}
	artifact.Digest = domain.CanonicalAssumptionDigest(artifact)
	artifactOnly := assumptionsInputForTest(assumptionsUnitDoc(artifact))
	if _, err := domain.AdmitAssumption(artifactOnly, domain.AssumptionSupportedTargets,
		domain.AssumptionScopeProduct, time.Now()); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectScopeMismatch {
		t.Fatalf("artifact scope satisfied a product-wide target claim: %v", err)
	}
}

// Replay never rewrites a persisted policy input: a tampered assumptions
// block aborts the replay, a valid one rides through unchanged.
func TestAssumptionReplayIntegrity(t *testing.T) {
	trust := assumptionsUnit("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	mutatePersisted := func(t *testing.T, da *domain.DeclaredAssumptionsInput) string {
		t.Helper()
		dir, _ := replayFixture(t)
		rb, err := os.ReadFile(filepath.Join(dir, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var rep Report
		if err := json.Unmarshal(rb, &rep); err != nil {
			t.Fatal(err)
		}
		rep.Input.DeclaredAssumptions = da
		b, err := json.Marshal(&rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("valid block replays", func(t *testing.T) {
		dir := mutatePersisted(t, assumptionsInputForTest(assumptionsUnitDoc(trust)))
		if _, err := LoadPersistedAgentTurn(dir); err != nil {
			t.Fatalf("valid assumptions block aborted replay: %v", err)
		}
	})
	t.Run("tampered block aborts", func(t *testing.T) {
		da := assumptionsInputForTest(assumptionsUnitDoc(trust))
		da.Assumptions[0].Statement = "hand-edited replay input"
		dir := mutatePersisted(t, da)
		if _, err := LoadPersistedAgentTurn(dir); err == nil ||
			!strings.Contains(err.Error(), "declared_assumptions") {
			t.Fatalf("tampered assumptions block replayed: %v", err)
		}
	})
	t.Run("failed channel block replays as recorded", func(t *testing.T) {
		dir := mutatePersisted(t, &domain.DeclaredAssumptionsInput{
			Path: "local:bad.json", LoadError: domain.AssumptionsLoadInvalid,
		})
		if _, err := LoadPersistedAgentTurn(dir); err != nil {
			t.Fatalf("recorded failed intake aborted replay: %v", err)
		}
	})
}
