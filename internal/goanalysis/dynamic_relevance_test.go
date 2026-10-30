package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func relevantCoverage(t *testing.T, fixtureName string, ref domain.SymbolRef) DynamicCoverage {
	t.Helper()
	ix := fixture(t, fixtureName)
	scope, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cov, err := ix.ScanRelevantDynamic(context.Background(), scope, ref)
	if err != nil {
		t.Fatal(err)
	}
	return cov
}

func hasDynamicLine(xs []string, needle string) bool {
	for _, x := range xs {
		if strings.Contains(x, needle) {
			return true
		}
	}
	return false
}

func TestRelevantDynamicMarkersIgnoresBareReflectForIncompatibleSubject(t *testing.T) {
	cov := relevantCoverage(t, "reflectprod", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"})
	if len(cov.RelevantMarkers) != 0 {
		t.Fatalf("bare reflect and write markers must not be relevant to Parse: %+v", cov.RelevantMarkers)
	}
	if !hasDynamicLine(cov.IgnoredMarkers, "reflect import") {
		t.Fatalf("bare reflect import must be audited as ignored: %+v", cov.IgnoredMarkers)
	}
}

func TestRelevantDynamicMarkersKeepsCompatibleFuncValue(t *testing.T) {
	cov := relevantCoverage(t, "funcvalprod", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"})
	if !hasDynamicLine(cov.ObservedMarkers, "func_value") || !hasDynamicLine(covMarkerKinds(cov), "func_value") {
		t.Fatalf("compatible func_value must remain relevant: %+v", cov)
	}
}

func TestRelevantDynamicMarkersKeepsCompatibleReflectMethod(t *testing.T) {
	cov := relevantCoverage(t, "reflectprod", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Conn.Next"})
	if !hasDynamicLine(covMarkerKinds(cov), "reflect_method") {
		t.Fatalf("compatible reflect method must remain relevant: %+v", cov)
	}
}

func TestRelevantDynamicMarkersNarrowedInterfaceDispatch(t *testing.T) {
	cov := relevantCoverage(t, "ifaceprod", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"})
	if len(cov.UnresolvedDispatch) != 0 || len(cov.RelevantMarkers) != 0 {
		t.Fatalf("unmaterialized receiver must be narrowed out: %+v", cov)
	}
	if len(cov.ClosedExceptions) == 0 {
		t.Fatalf("narrowing must leave an audit reason: %+v", cov)
	}
}

func TestRelevantDynamicMarkersKeepsCompatibleInterfaceDispatch(t *testing.T) {
	cov := relevantCoverage(t, "ifaceprod", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"})
	if len(cov.UnresolvedDispatch) == 0 {
		t.Fatalf("materialized receiver interface dispatch must remain open: %+v", cov)
	}
}

func TestRelevantDynamicMarkersDeadSiteDiscarded(t *testing.T) {
	cov := relevantCoverage(t, "reldeadprod", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Conn.Next"})
	if len(cov.RelevantMarkers) != 0 || len(cov.ClosedExceptions) == 0 {
		t.Fatalf("dead enclosing dynamic site must close with audit reason: %+v", cov)
	}
	if !hasDynamicLine(cov.ClosedExceptions, "dead product site") {
		t.Fatalf("dead-site reason missing: %+v", cov.ClosedExceptions)
	}
}

func covMarkerKinds(cov DynamicCoverage) []string {
	out := make([]string, 0, len(cov.RelevantMarkers))
	for _, m := range cov.RelevantMarkers {
		out = append(out, m.Kind)
	}
	return out
}
