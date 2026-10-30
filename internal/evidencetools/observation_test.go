package evidencetools

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var errTest = errors.New("boom")

// TestObservationContract pins the spec §6.1 matrix: the four
// status/completeness combinations an agent must be able to tell apart.
func TestObservationContract(t *testing.T) {
	mk := func(status ToolStatus, c Completeness, sd *ScopeDetails) *Observation {
		o := &Observation{
			Fact:         "n matches",
			Scope:        "test scope",
			Completeness: c,
			ToolStatus:   status,
			ScopeDetails: sd,
		}
		finishObservation(o)
		return o
	}

	t.Run("OK empty COMPLETE stays complete for a closed scope", func(t *testing.T) {
		o := mk(StatusOK, CompletenessComplete, &ScopeDetails{CoverageRule: "closed file set"})
		if o.ToolStatus != StatusOK || o.Completeness != CompletenessComplete {
			t.Fatalf("obs=%+v", o)
		}
	})

	t.Run("OK empty PARTIAL stays partial", func(t *testing.T) {
		o := mk(StatusOK, CompletenessPartial, nil)
		if o.Completeness != CompletenessPartial {
			t.Fatalf("obs=%+v", o)
		}
	})

	t.Run("COMPLETE without coverage rule downgrades to PARTIAL", func(t *testing.T) {
		o := mk(StatusOK, CompletenessComplete, nil)
		if o.Completeness != CompletenessPartial {
			t.Fatalf("missing coverage rule must downgrade: %+v", o)
		}
		if len(o.Limitations) == 0 {
			t.Fatal("downgrade must be explained in limitations")
		}
	})

	t.Run("COMPLETE with skipped packages downgrades", func(t *testing.T) {
		o := mk(StatusOK, CompletenessComplete, &ScopeDetails{
			CoverageRule:    "closed set",
			SkippedPackages: []string{"example.com/broken"},
		})
		if o.Completeness != CompletenessPartial {
			t.Fatalf("skipped packages must downgrade: %+v", o)
		}
	})

	t.Run("COMPLETE with truncated results downgrades", func(t *testing.T) {
		o := mk(StatusOK, CompletenessComplete, &ScopeDetails{
			CoverageRule: "closed set",
			Limits:       &ScopeLimits{Truncated: true},
		})
		if o.Completeness != CompletenessPartial {
			t.Fatalf("truncation must downgrade: %+v", o)
		}
	})

	t.Run("ERROR is never COMPLETE", func(t *testing.T) {
		o := mk(StatusError, CompletenessComplete, &ScopeDetails{CoverageRule: "closed set"})
		if o.Completeness == CompletenessComplete {
			t.Fatalf("ERROR cannot claim coverage: %+v", o)
		}
		if o.Completeness != CompletenessUnknown {
			t.Fatalf("ERROR completeness must be UNKNOWN, got %s", o.Completeness)
		}
	})

	t.Run("UNSUPPORTED is never COMPLETE", func(t *testing.T) {
		o := mk(StatusUnsupported, CompletenessComplete, &ScopeDetails{CoverageRule: "closed set"})
		if o.Completeness != CompletenessUnknown {
			t.Fatalf("UNSUPPORTED completeness must be UNKNOWN, got %s", o.Completeness)
		}
	})

	t.Run("ERROR observation gets error text", func(t *testing.T) {
		s := &Session{}
		o := s.errorObs("x", errTest)
		if o.ToolStatus != StatusError || o.Error == "" || o.Completeness != CompletenessUnknown {
			t.Fatalf("obs=%+v", o)
		}
		finishObservation(o)
		if o.Completeness != CompletenessUnknown {
			t.Fatalf("obs=%+v", o)
		}
	})

	t.Run("empty ERROR fact cannot stand in for Error field", func(t *testing.T) {
		o := &Observation{ToolStatus: StatusError, Fact: "", Completeness: CompletenessPartial}
		finishObservation(o)
		if o.Error == "" {
			t.Fatal("ERROR without message must still record the fact text")
		}
	})
}

// TestObservationJSON pins the wire shape of the contract.
func TestObservationJSON(t *testing.T) {
	o := Observation{
		ID:           "OBS-0001",
		Tool:         "find_callers",
		Fact:         "0 statically-named call site(s) of p.F in product packages",
		Scope:        "product packages of /snap",
		Completeness: CompletenessPartial,
		ToolStatus:   StatusOK,
		EvidenceRefs: []string{"sha256:abc"},
		Limitations:  []string{"dep-internal callers not covered"},
		ScopeDetails: &ScopeDetails{SnapshotHash: "h", Subject: "p.F"},
		Data:         map[string]any{"count": 0},
	}
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var back Observation
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != o.ID || back.Completeness != o.Completeness || back.ToolStatus != o.ToolStatus {
		t.Fatalf("round trip: %+v", back)
	}
	// The wire keys must match the spec names.
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "fact", "scope", "completeness", "tool_status", "evidence_refs", "limitations"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing wire key %q in %s", k, b)
		}
	}
}

// TestNoVerdictVocabulary guards the spec §6.2 rule: adapter output must
// not smuggle production conclusions (safe/verdict language) into facts.
func TestNoVerdictVocabulary(t *testing.T) {
	banned := []string{"VERIFIED FALSE", "verdict", "not_affected", "safe=true"}
	for _, phrase := range banned {
		if strings.Contains(serverInstructions, phrase) {
			t.Fatalf("server instructions must not contain %q", phrase)
		}
	}
}
