package research

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// policyFS renders a filesystem containing just the safety policy file.
func policyFS(t *testing.T, doc map[string]any) fstest.MapFS {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{SafetyPolicyPath: &fstest.MapFile{Data: b}}
}

func baselinePolicyDoc(t *testing.T) map[string]any {
	t.Helper()
	b := BaselineSafetyPolicy()
	return map[string]any{
		"schema":               safetyPolicySchema,
		"required_rules":       b.RequiredRules,
		"required_checks":      b.RequiredChecks,
		"forbidden_promotions": b.ForbiddenPromotions,
	}
}

func TestMonotonicPolicyBaselineLoads(t *testing.T) {
	p, err := LoadSafetyPolicy(policyFS(t, baselinePolicyDoc(t)))
	if err != nil {
		t.Fatalf("baseline-shaped policy rejected: %v", err)
	}
	base := BaselineSafetyPolicy()
	for _, want := range base.RequiredRules {
		if !stringSliceContains(p.RequiredRules, want) {
			t.Fatalf("loaded policy lost required rule %q", want)
		}
	}
	for _, want := range base.RequiredChecks {
		if !stringSliceContains(p.RequiredChecks, want) {
			t.Fatalf("loaded policy lost required check %q", want)
		}
	}
	for _, want := range base.ForbiddenPromotions {
		if !stringSliceContains(p.ForbiddenPromotions, want) {
			t.Fatalf("loaded policy lost forbidden promotion %q", want)
		}
	}
}

func TestMonotonicPolicyRejectsRelaxation(t *testing.T) {
	base := BaselineSafetyPolicy()

	// Removing a required gate is the forged-policy case.
	for i, victim := range base.RequiredRules {
		cand := BaselineSafetyPolicy()
		cand.RequiredRules = append(cand.RequiredRules[:i], cand.RequiredRules[i+1:]...)
		if err := ValidateMonotonicPolicy(base, cand); err == nil {
			t.Fatalf("policy missing rule %q accepted", victim)
		} else if !strings.Contains(err.Error(), victim) {
			t.Fatalf("violation does not name %q: %v", victim, err)
		}
	}
	cand := BaselineSafetyPolicy()
	cand.RequiredChecks = cand.RequiredChecks[:len(cand.RequiredChecks)-1]
	if err := ValidateMonotonicPolicy(base, cand); err == nil {
		t.Fatal("policy dropping a required check accepted")
	}
	cand = BaselineSafetyPolicy()
	cand.ForbiddenPromotions = nil
	if err := ValidateMonotonicPolicy(base, cand); err == nil {
		t.Fatal("policy un-forbidding promotions accepted")
	}

	// Loading a relaxed file fails closed — no permissive default.
	doc := baselinePolicyDoc(t)
	doc["required_rules"] = base.RequiredRules[1:]
	if _, err := LoadSafetyPolicy(policyFS(t, doc)); err == nil {
		t.Fatal("relaxed policy file loaded")
	}
	doc = baselinePolicyDoc(t)
	doc["required_checks"] = []string{}
	if _, err := LoadSafetyPolicy(policyFS(t, doc)); err == nil {
		t.Fatal("policy file emptying required_checks loaded")
	}
}

func TestMonotonicPolicyAcceptsTightening(t *testing.T) {
	base := BaselineSafetyPolicy()
	cand := BaselineSafetyPolicy()
	cand.RequiredRules = append(cand.RequiredRules, "new-verification-rule")
	cand.RequiredChecks = append(cand.RequiredChecks, "new-check")
	cand.ForbiddenPromotions = append(cand.ForbiddenPromotions, "new-promotion-veto")
	if err := ValidateMonotonicPolicy(base, cand); err != nil {
		t.Fatalf("strictly stronger policy rejected: %v", err)
	}
	doc := baselinePolicyDoc(t)
	doc["required_rules"] = cand.RequiredRules
	doc["required_checks"] = cand.RequiredChecks
	doc["forbidden_promotions"] = cand.ForbiddenPromotions
	if _, err := LoadSafetyPolicy(policyFS(t, doc)); err != nil {
		t.Fatalf("tightened policy file rejected: %v", err)
	}
}

func TestMonotonicPolicyLoadErrors(t *testing.T) {
	// Missing file: error, never a default.
	if _, err := LoadSafetyPolicy(fstest.MapFS{}); err == nil {
		t.Fatal("missing policy file loaded")
	}
	// Malformed document: error.
	bad := fstest.MapFS{SafetyPolicyPath: &fstest.MapFile{Data: []byte("{not json")}}
	if _, err := LoadSafetyPolicy(bad); err == nil {
		t.Fatal("malformed policy file loaded")
	}
	// Wrong schema id: error.
	doc := baselinePolicyDoc(t)
	doc["schema"] = "research-safety-policy/2"
	if _, err := LoadSafetyPolicy(policyFS(t, doc)); err == nil {
		t.Fatal("policy file with wrong schema loaded")
	}
	// Empty or duplicated members are malformed, not defaults.
	doc = baselinePolicyDoc(t)
	doc["required_rules"] = append(doc["required_rules"].([]string), "applicability-first-ordering")
	if _, err := LoadSafetyPolicy(policyFS(t, doc)); err == nil {
		t.Fatal("policy file with duplicated rule loaded")
	}
}

func TestMonotonicPolicyCatalogs(t *testing.T) {
	// The committed catalog bundle loads cleanly from the repo root.
	repoRoot := os.DirFS("../..")
	cats, err := LoadCatalogs(repoRoot)
	if err != nil {
		t.Fatalf("committed catalogs rejected: %v", err)
	}
	if len(cats.Dispositions) != len(BaselineDispositions) {
		t.Fatalf("catalog dispositions=%d, want %d", len(cats.Dispositions), len(BaselineDispositions))
	}
	p, err := LoadSafetyPolicy(repoRoot)
	if err != nil {
		t.Fatalf("committed policy rejected: %v", err)
	}
	// Every check the policy requires exists in the check catalog.
	checkIDs := map[string]bool{}
	for _, ck := range cats.Checks {
		checkIDs[ck.ID] = true
	}
	for _, req := range p.RequiredChecks {
		if !checkIDs[req] {
			t.Fatalf("policy requires check %q absent from checks catalog", req)
		}
	}

	// Missing catalog file: error, never a permissive default.
	empty := fstest.MapFS{}
	if _, err := LoadCatalogs(empty); err == nil {
		t.Fatal("missing catalogs loaded")
	}
	// A catalog that drops a baseline check is malformed, not defaulted.
	partial := fstest.MapFS{}
	for _, path := range []string{DispositionsCatalogPath, ConditionsCatalogPath, ChecksCatalogPath} {
		data, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		partial[path] = &fstest.MapFile{Data: data}
	}
	var checksDoc map[string]any
	if err := json.Unmarshal(partial[ChecksCatalogPath].Data, &checksDoc); err != nil {
		t.Fatal(err)
	}
	entries := checksDoc["checks"].([]any)
	kept := entries[:0]
	for _, en := range entries {
		if en.(map[string]any)["id"] != "package-usage" {
			kept = append(kept, en)
		}
	}
	checksDoc["checks"] = kept
	b, _ := json.Marshal(checksDoc)
	partial[ChecksCatalogPath] = &fstest.MapFile{Data: b}
	if _, err := LoadCatalogs(partial); err == nil {
		t.Fatal("catalog dropping a baseline check loaded")
	}
	// A catalog that loosens a CLOSE_* premise is a relaxation.
	var dispDoc map[string]any
	if err := json.Unmarshal(partial[DispositionsCatalogPath].Data, &dispDoc); err != nil {
		t.Fatal(err)
	}
	for _, en := range dispDoc["dispositions"].([]any) {
		m := en.(map[string]any)
		if m["id"] == "CLOSE_NO_EXPLOIT_PATH" {
			m["environment_premise_allowed"] = true
		}
	}
	relaxed := fstest.MapFS{}
	for path, f := range partial {
		relaxed[path] = f
	}
	b, _ = json.Marshal(dispDoc)
	relaxed[DispositionsCatalogPath] = &fstest.MapFile{Data: b}
	if _, err := LoadCatalogs(relaxed); err == nil {
		t.Fatal("catalog loosening a CLOSE_* premise loaded")
	}
}

func stringSliceContains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
