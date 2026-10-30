package research

import (
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// renderReport assembles a /3 report for render assertions (no agent
// turn; deterministic only).
func renderUsageReport(t *testing.T, module, pkg string,
	obs []*evidencetools.Observation, facts []VerifiedFact) *Report {
	t.Helper()
	lane := usageLane(t, module, pkg, nil, obs, facts)
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, RunID: "pur",
		StartedAt: time.Now(), FinishedAt: time.Now()})
	if err := Validate(r, ""); err != nil {
		t.Fatalf("render fixture invalid:\n%v", err)
	}
	return r
}

// sectionBlock extracts the markdown span from startMarker to the next
// `## `/`### ` heading at the same or higher level, so group-specific
// assertions stay inside their own block.
func sectionBlock(t *testing.T, md, startMarker string) string {
	t.Helper()
	start := strings.Index(md, startMarker)
	if start < 0 {
		t.Fatalf("marker %q missing:\n%s", startMarker, md)
	}
	rest := md[start:]
	end := len(rest)
	for _, cut := range []string{"\n- **", "\n## ", "\n### "} {
		if i := strings.Index(rest[1:], cut); i >= 0 && i+1 < end {
			end = i + 1
		}
	}
	return rest[:end]
}

// TestPackageUsageRender pins the /3 render contract for the package
// usage condition: a REFUTED path is displayed as a bounded refutation
// — never as «product is safe» — and the appendix registers carry the
// fact kind/claim/negative-verification/check-scope fields.
func TestPackageUsageRender(t *testing.T) {
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"

	t.Run("REFUTED renders as bounded refutation never as safety", func(t *testing.T) {
		r := refutedUsageReport(t)
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		c := usageCondition(t, r)

		grp := sectionBlock(t, out, "- **REFUTED")
		for _, want := range []string{
			"bounded path refutation",
			"не вывод о безопасности продукта",
			"`" + c.ID + "` [REFUTED]",
			"present in the recorded dependency/build scope",
			"no product-source use",
			"negative verification=VERIFIED",
			"not a safe conclusion",
		} {
			if !strings.Contains(grp, want) {
				t.Fatalf("REFUTED group missing %q:\n%s", want, grp)
			}
		}
		// The refuted group must never phrase the outcome as safety or
		// non-exploitability.
		for _, banned := range []string{"безопасен", "неэксплуатируем", "not exploitable", "not affected", "auto-close"} {
			if strings.Contains(grp, banned) {
				t.Fatalf("REFUTED group carries verdict phrasing %q:\n%s", banned, grp)
			}
		}
		// The refuted row left the confirmed-facts group.
		conf := sectionBlock(t, out, "- **Подтверждённые факты:**")
		if strings.Contains(conf, c.ID) {
			t.Fatalf("REFUTED condition still inside confirmed facts:\n%s", conf)
		}
	})

	t.Run("L2 block names the bounded refutation", func(t *testing.T) {
		r := refutedUsageReport(t)
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		blk := evidenceLevelBlock(t, string(md))
		if !strings.Contains(blk, "REFUTED path condition") || !strings.Contains(blk, "bounded scope") {
			t.Fatalf("L2 block lacks the bounded-refutation limitation:\n%s", blk)
		}
		c := usageCondition(t, r)
		if !strings.Contains(blk, "`"+c.ID+"`") {
			t.Fatalf("L2 block does not name the REFUTED blocker:\n%s", blk)
		}
	})

	t.Run("appendix facts carry kind claim negative verification and check scope", func(t *testing.T) {
		r := refutedUsageReport(t)
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		facts := sectionBlock(t, out, "### Full deterministic facts")
		for _, want := range []string{
			"kind: `PACKAGE_USAGE`",
			"claim `FALSE`",
			"negative verification: `VERIFIED`",
			"check scope",
		} {
			if !strings.Contains(facts, want) {
				t.Fatalf("facts appendix missing %q:\n%s", want, facts)
			}
		}
		// Legacy facts render the explicit empty-kind marker too.
		if !strings.Contains(facts, "kind: `-`") {
			t.Fatalf("legacy fact rows lack the empty-kind marker:\n%s", facts)
		}
		conds := sectionBlock(t, out, "### Full exploitation conditions")
		c := usageCondition(t, r)
		if !strings.Contains(conds, "`"+c.ID+"`") ||
			!strings.Contains(conds, "check scope:") {
			t.Fatalf("condition appendix lacks the usage row/check scope:\n%s", conds)
		}
	})

	t.Run("appendix fact renders the usage basis when present", func(t *testing.T) {
		r := refutedUsageReport(t)
		factOf(t, r, "OBS-0020").UsageBasis = UsageBasisAbsentFromClosure
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		facts := sectionBlock(t, string(md), "### Full deterministic facts")
		if !strings.Contains(facts, "usage basis: `absent_from_closure`") {
			t.Fatalf("facts appendix missing the usage basis row:\n%s", facts)
		}
		// A fact with no basis (the legacy shape) renders no basis row.
		r2 := refutedUsageReport(t)
		md2, err := RenderMarkdown(r2)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(md2), "usage basis:") {
			t.Fatalf("basis-less fact rendered a usage basis row:\n%s", md2)
		}
	})

	t.Run("USED renders as product-source usage with a TRUE claim", func(t *testing.T) {
		r := usedUsageReport(t)
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		conf := sectionBlock(t, out, "- **Подтверждённые факты:**")
		if !strings.Contains(conf, "used by product source") {
			t.Fatalf("confirmed group lacks the usage statement:\n%s", conf)
		}
		facts := sectionBlock(t, out, "### Full deterministic facts")
		if !strings.Contains(facts, "kind: `PACKAGE_USAGE`") ||
			!strings.Contains(facts, "claim `TRUE`") {
			t.Fatalf("TRUE usage fact row missing:\n%s", facts)
		}
		if strings.Contains(out, "- **REFUTED") {
			t.Fatal("USED report rendered the REFUTED group")
		}
	})

	t.Run("UNKNOWN usage renders unresolved never as a negative", func(t *testing.T) {
		r := renderUsageReport(t, module, pkg,
			[]*evidencetools.Observation{
				usageObs("OBS-0020", module, pkg, "", "UNKNOWN", "INSUFFICIENT_SCOPE", evidencetools.CompletenessUnknown),
			},
			[]VerifiedFact{
				factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
			})
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		unk := sectionBlock(t, out, "- **Неизвестные условия:**")
		if !strings.Contains(unk, "undecided") || !strings.Contains(unk, "never negative proof") {
			t.Fatalf("unknown group lacks the unresolved usage row:\n%s", unk)
		}
		if strings.Contains(out, "- **REFUTED") {
			t.Fatal("UNKNOWN report rendered the REFUTED group")
		}
		if strings.Contains(out, "no product-source use") {
			t.Fatal("UNKNOWN report renders a negative usage claim")
		}
	})

	t.Run("repeated render is byte-stable", func(t *testing.T) {
		r := refutedUsageReport(t)
		a, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		b, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatal("markdown render not byte-stable")
		}
		// Round-trip through the wire: re-render is identical too.
		j1, err := RenderJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := ParseReport(j1)
		if err != nil {
			t.Fatal(err)
		}
		a2, err := RenderMarkdown(r2)
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(a2) {
			t.Fatal("markdown changed across JSON round-trip")
		}
	})

	t.Run("/2 render keeps the pre-/3 condition shape", func(t *testing.T) {
		r := refutedUsageReport(t)
		r.ContractExtensions = []string{Slice2Extension}
		md, err := RenderMarkdown(r)
		if err != nil {
			t.Fatal(err)
		}
		out := string(md)
		for _, banned := range []string{
			"- **REFUTED — опровергнуто",
			"kind: `PACKAGE_USAGE`",
			"negative verification: `",
			"## Evidence level",
			"role=",
		} {
			if strings.Contains(out, banned) {
				t.Fatalf("/2 render leaked /3 wording %q", banned)
			}
		}
		// The refuted condition stays inside the confirmed-facts group
		// exactly as before /3 existed.
		conf := sectionBlock(t, out, "- **Подтверждённые факты:**")
		c := usageCondition(t, r)
		if !strings.Contains(conf, "`"+c.ID+"` [REFUTED]") {
			t.Fatalf("/2 render lost the REFUTED confirmed row:\n%s", conf)
		}
	})
}
