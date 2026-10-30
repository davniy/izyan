package evaluator

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func platformCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{Product: admittedSnapshot(domain.ProductSnapshot{
		GOOS: "linux", GOARCH: "amd64",
		ReleaseGoVersion: "go1.21.5",
	})}
}

func TestPlatformEvaluate(t *testing.T) {
	ev := Platform{}
	c := platformCase()

	mk := func(params map[string]string) domain.Condition {
		return domain.Condition{ID: "C-PLAT", Kind: domain.ConditionPlatform, Params: params}
	}

	// Match on all declared facts -> TRUE.
	cl := ev.Evaluate(mk(map[string]string{"goos": "linux", "go_version": "<1.22"}), c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("match => TRUE, got %s (%s)", cl.Result, cl.Explanation)
	}
	// GOOS mismatch -> FALSE.
	cl = ev.Evaluate(mk(map[string]string{"goos": "windows"}), c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("mismatch => FALSE, got %s", cl.Result)
	}
	// go_version bound violated -> FALSE.
	cl = ev.Evaluate(mk(map[string]string{"go_version": ">=1.24"}), c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("violated bound => FALSE, got %s (%s)", cl.Result, cl.Explanation)
	}
	// Missing snapshot fact -> UNKNOWN.
	c2 := platformCase()
	c2.Product.GOOS = ""
	cl = ev.Evaluate(mk(map[string]string{"goos": "linux"}), c2)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("missing fact => UNKNOWN, got %s", cl.Result)
	}
	// No evaluable params -> UNKNOWN with limitation.
	cl = ev.Evaluate(mk(nil), c)
	if cl.Result != domain.ClaimUnknown || len(cl.Limitations) == 0 {
		t.Fatalf("no params => UNKNOWN+limitation, got %+v", cl)
	}
}

func TestPlatformEvaluate_ReleaseGoVersion(t *testing.T) {
	ev := Platform{}
	mk := func(params map[string]string) domain.Condition {
		return domain.Condition{ID: "C-PLAT", Kind: domain.ConditionPlatform, Params: params}
	}

	// go.mod declares a language minimum and `go version` is the analysis
	// toolchain — neither is the release toolchain. With no recorded
	// ReleaseGoVersion a go_version condition stays UNKNOWN.
	noRelease := &domain.AnalysisCase{
		Product: domain.ProductSnapshot{
			GOOS:             "linux",
			GOARCH:           "amd64",
			GoVersion:        "go version go1.26.1 darwin/arm64",
			GoModDirective:   "1.23",
			MinimumGoVersion: "1.23",
		},
	}
	cl := ev.Evaluate(mk(map[string]string{"go_version": "<1.24"}), noRelease)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("go.mod/analysis toolchain are not the release toolchain: got %s (%s)", cl.Result, cl.Explanation)
	}
	found := false
	for _, l := range cl.Limitations {
		if strings.Contains(l, "release toolchain") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected release-toolchain limitation, got %v", cl.Limitations)
	}

	// A recorded release toolchain resolves the bound — go-prefixed or bare.
	released := platformCase() // ReleaseGoVersion "go1.21.5"
	cl = ev.Evaluate(mk(map[string]string{"go_version": "<1.22"}), released)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("release go1.21.5 satisfies <1.22, got %s", cl.Result)
	}
	cl = ev.Evaluate(mk(map[string]string{"go_version": ">=1.24"}), released)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("release go1.21.5 violates >=1.24, got %s", cl.Result)
	}
	released.Product.ReleaseGoVersion = "1.21.5" // bare spelling
	cl = ev.Evaluate(mk(map[string]string{"go_version": "<1.22"}), released)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("bare release 1.21.5 satisfies <1.22, got %s", cl.Result)
	}

	// An empty GoVersionSource does not mask a recorded release version —
	// the value itself is the evidence; the source field only attributes it.
	released.Product.GoVersionSource = ""
	cl = ev.Evaluate(mk(map[string]string{"go_version": "<1.22"}), released)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("release version stands regardless of source attribution, got %s", cl.Result)
	}
}
