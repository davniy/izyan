package research

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAnswer_OfficialContract(t *testing.T) {
	for _, tc := range []struct {
		name, raw, wantCat, wantReasoning string
	}{
		{"bare", `{"category":"code_not_reachable","reasoning":"not imported"}`, "code_not_reachable", "not imported"},
		{"fenced", "```json\n{\"category\": \"vulnerable\", \"reasoning\": \"reachable\"}\n```", "vulnerable", "reachable"},
		{"prose", "Let me summarize.\n{\"category\":\"uncertain\",\"reasoning\":\"can't tell\"}\nDone.", "uncertain", "can't tell"},
		{"case_insensitive", `{"category":"VULNERABLE","reasoning":"x"}`, "vulnerable", "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat, rea, err := parseAnswer(tc.raw)
			if err != nil {
				t.Fatalf("parseAnswer: %v", err)
			}
			if cat != tc.wantCat || rea != tc.wantReasoning {
				t.Fatalf("got (%q,%q), want (%q,%q)", cat, rea, tc.wantCat, tc.wantReasoning)
			}
		})
	}
}

func TestParseAnswer_UnparseableNeverGuessed(t *testing.T) {
	for _, raw := range []string{
		"the code is clearly safe, trust me",
		`{"category":"probably_safe","reasoning":"x"}`, // invented category
		`{"reasoning":"no category at all"}`,
		"",
	} {
		if cat, _, err := parseAnswer(raw); err == nil || cat != "" {
			t.Fatalf("parseAnswer(%q) = (%q, nil), want error + empty category", raw, cat)
		}
	}
}

func TestAnalyzeAnswer_FacetsAndRefs(t *testing.T) {
	snap := t.TempDir()
	if err := os.MkdirAll(filepath.Join(snap, "pkg", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "package x\n// line2\n// line3\n// line4\n"
	if err := os.WriteFile(filepath.Join(snap, "pkg", "x", "x.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	raw := `{"category":"code_not_reachable","reasoning":"The vulnerability is a panic in pkg/x. pkg/x/x.go:2 defines it. It is called from pkg/x/x.go:4 but never reachable. I assume the binary is stripped, probably. Cannot determine the final impact."}`
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Report{
		Analysis: Analysis{ConfirmedFacts: []Fact{}, Assumptions: ExtractionList{State: "not_assessed"}, Unknowns: ExtractionList{State: "not_assessed"}},
	}
	o := Options{SnapshotDir: snap, OutDir: out}
	analyzeAnswer(o, r, out)

	if !r.Answer.Parsed || r.Answer.Category != "code_not_reachable" || r.Answer.CategoryLabel != "research_judgement" {
		t.Fatalf("answer = %+v", r.Answer)
	}
	if len(r.Analysis.AffectedImplementations) == 0 && len(r.Analysis.UsagePaths) == 0 {
		t.Fatalf("no claims bucketed: %+v", r.Analysis)
	}
	foundVerified := false
	for _, cl := range append(r.Analysis.UsagePaths, r.Analysis.AffectedImplementations...) {
		for _, p := range cl.PathsFound {
			if strings.HasPrefix(p, "pkg/x/x.go") {
				foundVerified = true
			}
		}
	}
	if !foundVerified {
		t.Fatalf("no found paths: %+v", r.Analysis.UsagePaths)
	}
	if r.Analysis.PresenceSummary.PathsFound == 0 {
		t.Fatal("presence summary not counting found paths")
	}
	if len(r.Analysis.Assumptions.Items) == 0 || r.Analysis.Assumptions.State != "extracted" {
		t.Fatalf("assumption sentence not captured: %+v", r.Analysis.Assumptions)
	}
	if len(r.Analysis.Unknowns.Items) == 0 || r.Analysis.Unknowns.State != "extracted" {
		t.Fatalf("unknown sentence not captured: %+v", r.Analysis.Unknowns)
	}
}

func TestAnalyzeAnswer_RawUnparseable(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Report{
		Analysis: Analysis{ConfirmedFacts: []Fact{}, Assumptions: ExtractionList{State: "not_assessed"}, Unknowns: ExtractionList{State: "not_assessed"}},
	}
	analyzeAnswer(Options{OutDir: out}, r, out)
	if r.Answer.Parsed || r.Answer.CategoryLabel != "unavailable" || r.Answer.Category != "" {
		t.Fatalf("unparseable answer must stay unavailable: %+v", r.Answer)
	}
	if r.Answer.ParseError == "" {
		t.Fatal("parse error not recorded")
	}
}

func TestRefVerify(t *testing.T) {
	snap := t.TempDir()
	if err := os.WriteFile(filepath.Join(snap, "a.go"), []byte("package a\n//l2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snap, "staging", "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap, "staging", "src", "secure_serving.go"), []byte("package x\n//l2\n//l3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ref, wantNorm, wantStatus string
	}{
		{"a.go", "a.go", "exists"},
		{"a.go:2", "a.go:2", "exists"},
		{"a.go:1-2", "a.go:1-2", "exists"},
		{"a.go#L2", "a.go#L2", "exists"},
		{"a.go#L1-L2", "a.go#L1-L2", "exists"},
		{"a.go:99", "a.go:99", "bad location"},
		{"nope.go:3", "nope.go:3", "missing"},
		// The defect case: container-absolute /work/ paths must resolve.
		{"/work/staging/src/secure_serving.go", "staging/src/secure_serving.go", "exists"},
		{"/work/staging/src/secure_serving.go:2", "staging/src/secure_serving.go:2", "exists"},
		{"staging/src/secure_serving.go#L1-L3", "staging/src/secure_serving.go#L1-L3", "exists"},
		// work/-prefixed (no leading slash) falls back to work/-stripped.
		{"work/staging/src/secure_serving.go", "staging/src/secure_serving.go", "exists"},
		// Other absolute paths resolve snapshot-relative after /-strip.
		{"/etc/passwd.go", "etc/passwd.go", "missing"},
		{"../../etc/evil.go", "../../etc/evil.go", "outside snapshot"},
	} {
		norm, st := refVerify(snap, tc.ref)
		if st != tc.wantStatus {
			t.Fatalf("refVerify(%q) status = %q, want %q", tc.ref, st, tc.wantStatus)
		}
		if st == "exists" && norm != tc.wantNorm {
			t.Fatalf("refVerify(%q) norm = %q, want %q", tc.ref, norm, tc.wantNorm)
		}
	}
}
