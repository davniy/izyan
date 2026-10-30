package goanalysis

import (
	"context"
	"errors"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func TestRelevantDynamicMarkersUnknownKindStaysOpenOnDeadSite(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	ix.dynScanOverride = func(domain.SymbolRef) ([]DynamicMarker, error) {
		return []DynamicMarker{{CallSite: domain.CallSite{Package: "example.com/scopetestprod/test/helper", File: "dead.go", Line: 1}, Kind: "future_edge", Detail: "unknown"}}, nil
	}
	scope, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cov, err := ix.ScanRelevantDynamic(context.Background(), scope, domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.RelevantMarkers) != 1 || len(cov.ClosedExceptions) != 0 || cov.Complete {
		t.Fatalf("unknown marker must remain open/incomplete: %+v", cov)
	}
}

func TestRelevantDynamicMarkersScanFailureBlocks(t *testing.T) {
	ix := fixture(t, "constprod")
	ix.dynScanOverride = func(domain.SymbolRef) ([]DynamicMarker, error) { return nil, errors.New("scanner failed") }
	scope, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cov, err := ix.ScanRelevantDynamic(context.Background(), scope, domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"})
	if err == nil || cov.Complete || len(cov.IncompleteReasons) == 0 {
		t.Fatalf("scan failure must remain open/incomplete: %+v err=%v", cov, err)
	}
}
