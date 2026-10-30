package research

import (
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// renderLevelReport assembles a /3 report carrying all three rendered
// condition groups at once: deterministic confirmed conditions, a
// canonical agent path hypothesis (normalized to role=path, still
// OPEN, blocking L1) and unknown deployment conditions.
func renderLevelReport(t *testing.T) *Report {
	t.Helper()
	turn := turnWith(t, "vulnerable", "the malformed frame path may be exploitable",
		map[string]any{
			"attack_scenario": map[string]any{
				"claims": []any{
					map[string]any{
						"statement": "the affected package is imported and reachable",
						"subject":   "Affected Package Reachable ", // canonical modulo case/space
					},
					map[string]any{
						"statement": "an attacker could craft a frame through the listener",
						"subject":   "malformed frame delivery", // non-canonical → supporting
					},
				},
			},
		})
	lane := laneFor(t, "golang.org/x/net", domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		ResolvedVersion: "v0.10.0",
		SelectedModule:  "golang.org/x/net",
		SelectedModules: []string{"golang.org/x/net"},
		CheckedModules:  []string{"golang.org/x/net"},
	},
		[]*evidencetools.Observation{{
			ID: "OBS-0040", Tool: "listen-sites", ToolStatus: evidencetools.StatusOK,
			Fact: "one listener site", Scope: "inbound surface",
			Completeness: evidencetools.CompletenessPartial,
			Data:         map[string]any{"count": float64(1)},
		}},
		[]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", "golang.org/x/net@v0.10.0 affected"),
			factFor("OBS-0040", "listen-sites", "one listener site recorded"),
		})
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "render-lvl",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.EvidenceLevel == nil {
		t.Fatal("assembled /3 report without evidence_level")
	}
	return r
}

// evidenceLevelBlock extracts the rendered "## Evidence level
// (derived)" section so assertions apply to the block itself, not to
// unrelated report sections.
func evidenceLevelBlock(t *testing.T, md string) string {
	t.Helper()
	start := strings.Index(md, "## Evidence level")
	if start < 0 {
		t.Fatal("evidence level block missing")
	}
	rest := md[start:]
	end := strings.Index(rest, "\n## ")
	if end < 0 {
		t.Fatal("evidence level block not followed by another section")
	}
	return rest[:end]
}

// TestRender_EvidenceLevel pins the /3 render contract: the derived
// ladder is its own block with the fixed labels and the permanent
// disclaimer, deterministic facts / agent hypotheses / unknown
// conditions keep their separate groups, no level reads as a verdict,
// and legacy /1, /2 and slice-1 documents render unchanged.
func TestRender_EvidenceLevel(t *testing.T) {
	t.Run("level block renders before exploitation axes", func(t *testing.T) {
		r := renderLevelReport(t)
		// The canonical agent path hypothesis stays OPEN and blocks
		// L1, so the derived level is L2 with one blocker.
		if r.EvidenceLevel.Level != EvidenceLevelL2 {
			t.Fatalf("level = %s, want %s", r.EvidenceLevel.Level, EvidenceLevelL2)
		}
		if len(r.EvidenceLevel.BlockingConditions) == 0 {
			t.Fatal("expected blocking_conditions for the open agent path hypothesis")
		}
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)

		lvlIdx := strings.Index(out, "## Evidence level")
		axIdx := strings.Index(out, "## Exploitation conditions")
		if lvlIdx < 0 || axIdx < 0 || lvlIdx > axIdx {
			t.Fatal("evidence level block must render before exploitation axes")
		}
		blk := evidenceLevelBlock(t, out)
		for _, want := range []string{
			"L2 — потенциальный путь",
			"- **basis:** `" + EvidenceBasisDeterministic + "`",
			"- **statement:**",
			"- **scope:**",
			"- **condition refs:** `EC-",
			"- **evidence refs:** `fact-",
			"(`L2_POTENTIAL_PATH`)",
			"- **limitations:**",
			renderEvidenceLevelDisclaimer,
		} {
			if !strings.Contains(blk, want) {
				t.Fatalf("evidence level block missing %q:\n%s", want, blk)
			}
		}
		// The open agent path condition id is a listed blocker.
		var agentPathID string
		for i := range r.ExploitationConditions {
			c := &r.ExploitationConditions[i]
			if c.Origin == OriginAgent && c.Role == ConditionRolePath {
				agentPathID = c.ID
			}
		}
		if agentPathID == "" || !strings.Contains(blk, "`"+agentPathID+"`") {
			t.Fatalf("blocker %q not listed in the block", agentPathID)
		}
	})

	t.Run("three fixed level labels", func(t *testing.T) {
		for lvl, label := range map[string]string{
			EvidenceLevelL1: "L1 — статически подтверждённый путь",
			EvidenceLevelL2: "L2 — потенциальный путь",
			EvidenceLevelL3: "L3 — динамически подтверждённая эксплуатация",
		} {
			r := renderLevelReport(t)
			r.EvidenceLevel = &EvidenceLevel{
				Level:     lvl,
				Basis:     EvidenceBasisDynamic,
				Statement: "synthetic fixture statement",
				Scope:     "whole report scope",
			}
			md, err := RenderMarkdown(r)
			if err != nil {
				t.Fatal(err)
			}
			blk := evidenceLevelBlock(t, string(md))
			if !strings.Contains(blk, "- **level:** "+label) {
				t.Fatalf("level %s: label %q missing:\n%s", lvl, label, blk)
			}
			if !strings.Contains(blk, renderEvidenceLevelDisclaimer) {
				t.Fatalf("level %s: permanent disclaimer missing", lvl)
			}
			if !strings.Contains(blk, "- **limitations:** none recorded") {
				t.Fatalf("level %s: empty limitations line missing:\n%s", lvl, blk)
			}
		}
	})

	t.Run("disclaimer is permanent and never a stored-limitation copy", func(t *testing.T) {
		// Even a hand-made /3 payload without the disclaimer inside
		// limitations must render the permanent caption.
		r := renderLevelReport(t)
		r.EvidenceLevel.Limitations = nil
		r.EvidenceLevel.Statement = "custom statement without any stored disclaimer"
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		blk := evidenceLevelBlock(t, string(md))
		if !strings.Contains(blk, "> "+renderEvidenceLevelDisclaimer) {
			t.Fatalf("permanent disclaimer caption missing:\n%s", blk)
		}
	})

	t.Run("L1 never renders as a safety conclusion", func(t *testing.T) {
		r := renderLevelReport(t)
		r.EvidenceLevel = &EvidenceLevel{
			Level:              EvidenceLevelL1,
			Basis:              EvidenceBasisDeterministic,
			Statement:          "closed static path",
			Scope:              "whole report scope",
			ConditionRefs:      []string{"EC-0001"},
			EvidenceRefs:       []string{"fact-obs-0002"},
			BlockingConditions: []string{},
			Limitations:        []string{"still requires human review"},
		}
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		blk := evidenceLevelBlock(t, string(md))
		if !strings.Contains(blk, "L1 — статически подтверждённый путь") {
			t.Fatalf("L1 label missing:\n%s", blk)
		}
		// After removing the disclaimer line itself, the block may
		// never claim the product or path is safe / not exploitable.
		stripped := strings.ReplaceAll(blk, renderEvidenceLevelDisclaimer, "")
		for _, banned := range []string{"безопасен", "неэксплуатируем", "не эксплуатируем", "not exploitable"} {
			if strings.Contains(stripped, banned) {
				t.Fatalf("L1 block carries verdict phrasing %q:\n%s", banned, blk)
			}
		}
	})

	t.Run("L2 never renders as a negative conclusion", func(t *testing.T) {
		r := renderLevelReport(t) // derives L2
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		blk := evidenceLevelBlock(t, string(md))
		stripped := strings.ReplaceAll(blk, renderEvidenceLevelDisclaimer, "")
		for _, banned := range []string{"безопасен", "неэксплуатируем", "не эксплуатируем", "not exploitable", "not affected"} {
			if strings.Contains(stripped, banned) {
				t.Fatalf("L2 block carries verdict phrasing %q:\n%s", banned, blk)
			}
		}
	})

	t.Run("facts hypotheses and unknowns stay separate groups", func(t *testing.T) {
		r := renderLevelReport(t)
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		for _, group := range []string{
			"- **Подтверждённые факты:**",
			"- **Гипотезы агента (PROVISIONAL — не подтверждают exploit path):**",
			"- **Неизвестные условия:**",
		} {
			if !strings.Contains(out, group) {
				t.Fatalf("condition group %q missing", group)
			}
		}
		// Role is appended to the appendix condition row without
		// dropping origin/necessity/state/axis.
		appIdx := strings.Index(out, "### Full exploitation conditions")
		if appIdx < 0 {
			t.Fatal("appendix condition section missing")
		}
		app := out[appIdx:]
		for _, want := range []string{"role=path", "role=deployment", "role=applicability", "role=supporting"} {
			if !strings.Contains(app, want) {
				t.Fatalf("appendix conditions missing %q", want)
			}
		}
		// Rows keep the bracketed origin/necessity/state fields.
		if !strings.Contains(app, "[agent/required/OPEN") {
			t.Fatal("agent path hypothesis lost origin/necessity/state in appendix row")
		}
	})

	t.Run("legacy /1 and /2 renders emit no /3 block or role", func(t *testing.T) {
		for _, marker := range []string{Slice2ExtensionV1, Slice2Extension} {
			r := renderLevelReport(t)
			// Simulate a persisted pre-/3 document: strip the /3
			// members and re-mark.
			r.EvidenceLevel = nil
			for i := range r.ExploitationConditions {
				r.ExploitationConditions[i].Role = ""
			}
			r.ContractExtensions = []string{marker}
			md, err := RenderMarkdown(r)
			if err != nil {
				t.Fatal(err)
			}
			out := string(md)
			for _, banned := range []string{"## Evidence level", "role=", renderEvidenceLevelDisclaimer} {
				if strings.Contains(out, banned) {
					t.Fatalf("%s render contains %q", marker, banned)
				}
			}
			// Round-trip through JSON: still renders, still no block.
			j1, err := RenderJSON(r)
			if err != nil {
				t.Fatal(err)
			}
			r2, err := ParseReport(j1)
			if err != nil {
				t.Fatalf("%s round-trip rejected: %v", marker, err)
			}
			md2, err := RenderMarkdown(r2)

			if err != nil {
				t.Fatal(err)
			}
			if string(md) != string(md2) {
				t.Fatalf("%s markdown changed across JSON round-trip", marker)
			}
		}
	})
	t.Run("inert /2 members do not leak /3 UX", func(t *testing.T) {
		baseline := renderLevelReport(t)
		baseline.EvidenceLevel = nil
		for i := range baseline.ExploitationConditions {
			baseline.ExploitationConditions[i].Role = ""
		}
		baseline.ContractExtensions = []string{Slice2Extension}
		without, err := RenderMarkdown(baseline)
		if err != nil {
			t.Fatal(err)
		}

		inert := *baseline
		inert.ExploitationConditions = append([]ExploitationCondition(nil), baseline.ExploitationConditions...)
		inert.EvidenceLevel = &EvidenceLevel{
			Level: EvidenceLevelL3, Basis: EvidenceBasisDynamic,
			Statement: "inert member", Scope: "inert scope",
		}
		if len(inert.ExploitationConditions) == 0 {
			t.Fatal("fixture has no exploitation conditions")
		}
		inert.ExploitationConditions[0].Role = ConditionRolePath
		withInert, err := RenderMarkdown(&inert)
		if err != nil {
			t.Fatal(err)
		}
		if string(without) != string(withInert) {
			t.Fatal("inert /2 evidence_level/role members changed markdown")
		}
		for _, leaked := range []string{"## Evidence level", "role=", renderEvidenceLevelDisclaimer} {
			if strings.Contains(string(withInert), leaked) {
				t.Fatalf("inert /2 render leaked %q", leaked)
			}
		}
	})

	t.Run("slice-1 legacy report renders without evidence level", func(t *testing.T) {
		r := validReport(t)
		stripToLegacyShape(r)
		r.ContractExtensions = nil
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		for _, banned := range []string{"## Evidence level", "role=", renderEvidenceLevelDisclaimer} {
			if strings.Contains(out, banned) {
				t.Fatalf("legacy render contains %q", banned)
			}
		}
	})
}
