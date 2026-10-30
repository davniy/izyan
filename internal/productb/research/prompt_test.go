package research

import (
	"strings"
	"testing"
)

func TestRenderPrompt_ExactlyOneSubstitution(t *testing.T) {
	rendered, info, err := renderPrompt("CVE-2024-32473")
	if err != nil {
		t.Fatalf("renderPrompt: %v", err)
	}
	if info.Substitutions != 1 {
		t.Fatalf("substitutions = %d, want 1", info.Substitutions)
	}
	if info.TemplateSHA256 != frozenOfficialSHA256 {
		t.Fatalf("template sha256 %s != frozen pin", info.TemplateSHA256)
	}
	if strings.Contains(rendered, "{cve_id}") {
		t.Fatal("rendered prompt still contains the placeholder")
	}
	if !strings.Contains(rendered, "CVE-2024-32473") {
		t.Fatal("rendered prompt does not contain the CVE id")
	}
	// The frozen template remains an unchanged prefix: after restoring the
	// placeholder and stripping the additive rule block the bytes are
	// byte-identical to the pin.
	substituted := strings.TrimSuffix(rendered, "\n\n"+useBasedVerdictRule+"\n")
	if substituted == rendered {
		t.Fatal("rendered prompt does not end with the <USE_BASED_VERDICT> rule block")
	}
	if got := strings.Replace(substituted, "CVE-2024-32473", "{cve_id}", 1); got != b1Template {
		t.Fatal("rendered prompt diverges from the frozen template beyond the {cve_id} substitution and the appended rule block")
	}
	if !strings.HasPrefix(rendered, b1Template[:len("<ROLE>")]) {
		t.Fatal("frozen template is not the prompt prefix")
	}
	if !strings.HasSuffix(rendered, "</USE_BASED_VERDICT>\n") {
		t.Fatal("prompt does not end with the rule block closing tag")
	}
}

func TestRenderPrompt_UseBasedRuleContent(t *testing.T) {
	rendered, info, err := renderPrompt("CVE-2024-32473")
	if err != nil {
		t.Fatalf("renderPrompt: %v", err)
	}
	if info.RuleBlock == "" || info.RuleBlockSHA256 == "" {
		t.Fatal("PromptInfo does not record the rule block identity")
	}
	if info.RuleBlockSHA256 != sha256Hex([]byte(useBasedVerdictRule)) {
		t.Fatal("rule_block_sha256 does not match the embedded block")
	}
	if info.Name != "b1-plain+use-based-verdict" {
		t.Fatalf("prompt name %q does not record the appended block", info.Name)
	}
	for _, want := range []string{
		// Rule 1: executed vulnerable code inside the affected range is a
		// vulnerable verdict.
		`inside the advisory's affected range`,
		`the category is "vulnerable"`,
		`imported, referenced or called`,
		// Rule 2: restricted reachability is still reachability.
		`Restricted reachability is still reachability, never a safe category`,
		`unix-domain socket`,
		`localhost-only listener`,
		`same-user IPC channel`,
		`privileges the actor is assumed to already hold`,
		// Rule 3: safe categories only for absent/never-executed/real
		// control; uncertain stays an evidence fallback.
		`the vulnerable code never executes`,
		`control removes the attack surface entirely`,
		`fallback for genuinely missing evidence`,
		// The official output contract must be reaffirmed, not overridden.
		`{category, reasoning} output contract above are unchanged`,
	} {
		if !strings.Contains(useBasedVerdictRule, want) {
			t.Errorf("rule block missing %q", want)
		}
	}
	if !strings.Contains(rendered, useBasedVerdictRule) {
		t.Fatal("rendered prompt does not carry the rule block")
	}
	if strings.Contains(useBasedVerdictRule, "{cve_id}") {
		t.Fatal("rule block must not carry the {cve_id} placeholder")
	}
}

func TestRenderPrompt_NoCaseSpecificIdentifiers(t *testing.T) {
	// The appended delta — and only the delta — must stay free of case
	// hints. ScanProhibited runs on the template-level composition (the
	// {cve_id} placeholder is masked the same way WritePrompts scans arm
	// prompt files): structural patterns flag any advisory id in the delta,
	// and the dataset literals cover the pilot identifiers that motivated
	// the rule.
	composed := b1Template + "\n\n" + useBasedVerdictRule + "\n"
	ds := scanDataset{
		CVEIDs:          []string{"CVE-2023-44487", "CVE-2025-47914"},
		RepoSlugs:       []string{"grpc/grpc", "golang/x/crypto"},
		SmokeShortNames: []string{"k8s-44487"},
	}
	if findings := scanProhibited(composed, ds, b1Template); len(findings) != 0 {
		t.Fatalf("prompt composition carries prohibited identifiers: %v", findings)
	}
	// The block alone is clean even against a bare scan (no prefix).
	if findings := scanProhibited(useBasedVerdictRule, ds, ""); len(findings) != 0 {
		t.Fatalf("rule block carries prohibited identifiers: %v", findings)
	}
}

func TestRenderPrompt_RejectsBadCVE(t *testing.T) {
	for _, bad := range []string{"", "DROP TABLE", "{evil}", "CVE 2024"} {
		if _, _, err := renderPrompt(bad); err == nil {
			t.Fatalf("renderPrompt(%q) should fail", bad)
		}
	}
}
