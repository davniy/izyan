package research

import (
	"strings"
	"testing"
)

func TestUsageScopeRender(t *testing.T) {
	module, pkg := "example.com/m", "example.com/m/testonly"
	r := renderUsageReport(t, module, pkg, nil, []VerifiedFact{
		scopeFact("OBS-0043", module, pkg, string(UsageScopeTestOnly), ProductAbsenceVerificationVerified),
	})
	first, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("repeated render is not byte-stable")
	}
	out := string(first)
	for _, want := range []string{
		"build-closure usage scope",
		"usage scope: `test-only`",
		"usage subject: module=`example.com/m` package=`example.com/m/testonly`",
		"product absence verification: `VERIFIED`",
		"not a safety, runtime-use, exploitability, or not-affected conclusion",
		"paired product/test closure classification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q:\n%s", want, out)
		}
	}
	lower := strings.ToLower(out)
	for _, banned := range []string{"test-only is safe", "test-only: safe", "test-only — safe", "test-only is not affected", "test-only is not exploitable"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("render contains safety wording %q", banned)
		}
	}
}
