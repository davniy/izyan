package rootcause

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

// partialPackageListEvidence builds a package-list record the caller
// controls independently of its run record and content — the shape of a
// failed, truncated, legacy or context-mismatched measurement.
func partialPackageListEvidence(snapshot domain.ProductSnapshot, run *domain.PackageListRun, content string) domain.Evidence {
	e := domain.Evidence{
		ID:      "EV-PKGS",
		Kind:    domain.EvidencePackageList,
		Quality: domain.QualityDeterministic,
		Tool:    "go",
		Command: "go list -deps -test -json ./...",
		Source:  "go list -deps -test -json ./...",
		Content: content,
	}
	if run != nil {
		buildContext := domain.EffectiveBuildContext(snapshot)
		e.BuildContext = &buildContext
		e.PackageList = run
	}
	return e
}

// A failed, truncated, untyped or context-mismatched package list must not
// prove RootCause.Absent: the candidate stays unverified and the model
// ambiguous. Only an admitted complete matching inventory can close it.
func TestRootCausePartialPackageList(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	product := rootCauseProduct()
	v := domain.Vulnerability{ID: "GO-TEST-ABS"} // no affected-package constraint
	// A valid, complete-looking stream: only admission may read the
	// missing xds package as a product-graph absence.
	content := `{"ImportPath":"example.com/constprod"}{"ImportPath":"example.com/dep/vuln"}`
	dangling := `{"ImportPath":"example.com/constprod","Deps":["example.com/dep/vuln","example.com/gone"]}
{"ImportPath":"example.com/dep/vuln","Deps":[]}`
	otherBuild := product
	otherBuild.GOOS = "windows"

	failedRun := &domain.PackageListRun{
		Completed: false, Complete: false, WithTests: true, Pattern: "./...", Error: "exit status 1",
	}
	incompleteRun := &domain.PackageListRun{
		Completed: true, Complete: false, WithTests: true, Pattern: "./...",
	}
	completeRun := &domain.PackageListRun{
		Completed: true, Complete: true, WithTests: true, Pattern: "./...",
	}
	cases := []struct {
		name          string
		evidenceBuild domain.ProductSnapshot
		run           *domain.PackageListRun
		content       string
	}{
		{
			name:          "execution error with a parseable prefix",
			evidenceBuild: product,
			run:           failedRun,
			content:       content,
		},
		{
			name:          "truncated stream with admitted metadata",
			evidenceBuild: product,
			run:           completeRun,
			content:       strings.TrimSuffix(content, "}"),
		},
		{
			name:          "dangling edge with admitted metadata",
			evidenceBuild: product,
			run:           completeRun,
			content:       dangling,
		},
		{
			name:          "completed but not complete",
			evidenceBuild: product,
			run:           incompleteRun,
			content:       content,
		},
		{
			name:          "legacy record without typed metadata",
			evidenceBuild: product,
			run:           nil,
			content:       content,
		},
		{
			name:          "recorded context does not match the product",
			evidenceBuild: otherBuild,
			run:           completeRun,
			content:       content,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &domain.RootCauseModel{
				Status: domain.RootCauseResolved,
				RootCauses: []domain.RootCause{
					{Package: "example.com/dep/xds", Symbol: "RouteAndProcess", Role: domain.RootCauseSink},
				},
			}
			c := &domain.AnalysisCase{Product: product}
			c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence,
				partialPackageListEvidence(tc.evidenceBuild, tc.run, tc.content))
			lim := vf.Verify(context.Background(), c, m, v)
			if m.Status != domain.RootCauseAmbiguous {
				t.Fatalf("status=%s, want AMBIGUOUS: model=%+v", m.Status, m)
			}
			if len(m.Unverified) != 1 || m.Unverified[0].Symbol != "RouteAndProcess" {
				t.Fatalf("unverified=%+v — partial inventory resolved the candidate", m.Unverified)
			}
			for _, rc := range m.RootCauses {
				if rc.Absent {
					t.Fatalf("partial inventory set RootCause.Absent: %+v", rc)
				}
			}
			if !hasLimitation(lim, "package-absence check unavailable") {
				t.Fatalf("limitations=%v — the unverified absence gate must be named", lim)
			}
		})
	}
}
