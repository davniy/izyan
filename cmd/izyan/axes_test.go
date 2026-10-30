package main

import (
	"strings"
	"testing"
)

// TestAssessmentAxesCLI proves the CLI appends the derived projection while
// keeping every existing output key, and that a scoped positive carries its
// boundary on the same line.
func TestAssessmentAxesCLI(t *testing.T) {
	t.Run("a composed CVE positive appends requested and record axes", func(t *testing.T) {
		c := consumersCVEPositive(t)
		view := consumersProject(t, c)
		var printErr error
		out := captureStdout(t, func() { printErr = printRequestedFinding(view) })
		if printErr != nil {
			t.Fatalf("print requested finding: %v", printErr)
		}
		for _, want := range []string{
			"requested: " + consumersCVE,
			"assessment_outcome: DECIDED",
			"verdict: EXPLOITABLE",
			"reason: ",
			"profile: ",
			"assessment_axis: subject_kind=requested subject=" + consumersCVE,
			"assessment_axis: subject_kind=record subject=" + consumersChild,
			"vulnerable_code_in_build=TRUE",
			"exploitable=TRUE",
			"exploitability_scope=library-api",
			"record=" + consumersChild,
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("CLI output lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("a failed request keeps unknown axes", func(t *testing.T) {
		c := consumersFailedCase(t)
		view := consumersProject(t, c)
		var printErr error
		out := captureStdout(t, func() { printErr = printRequestedFinding(view) })
		if printErr == nil {
			t.Fatal("a FAILED requested assessment must exit nonzero")
		}
		for _, want := range []string{
			"assessment_outcome: FAILED",
			"assessment_axis: subject_kind=requested",
			"vulnerable_code_in_build=UNKNOWN",
			"exploitable=UNKNOWN",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("CLI output lacks %q:\n%s", want, out)
			}
		}
	})
}
