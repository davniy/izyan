package goanalysis

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

var tlsKnob = domain.SymbolRef{Package: "crypto/tls", Symbol: "Config.InsecureSkipVerify"}

func TestFieldAssignmentsFindsInsecure(t *testing.T) {
	ix := fixture(t, "tlsprod")
	got, err := ix.FieldAssignments(context.Background(), tlsKnob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("assignments=%+v", got)
	}
	var lit, konst bool
	for _, a := range got {
		switch a.Source + ":" + a.Value {
		case "literal:true":
			lit = true
		case "const:true":
			konst = true
		}
	}
	if !lit || !konst {
		t.Fatalf("want literal:true and const:true assignments, got %+v", got)
	}
}

func TestFieldAssignmentsNone(t *testing.T) {
	ix := fixture(t, "tlssafe")
	got, err := ix.FieldAssignments(context.Background(), tlsKnob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected assignments: %+v", got)
	}
}

func TestSymbolFieldType(t *testing.T) {
	ix := fixture(t, "tlssafe")
	kind, err := ix.SymbolFieldType(context.Background(), tlsKnob)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "bool" {
		t.Fatalf("kind=%q want bool", kind)
	}
	// non-field symbol resolves to nothing
	kind, err = ix.SymbolFieldType(context.Background(), domain.SymbolRef{
		Package: "crypto/tls", Symbol: "Dial"})
	if err != nil || kind != "" {
		t.Fatalf("kind=%q err=%v", kind, err)
	}
}

func TestCheckCallSiteGuard_DeadCodeAndDynamic(t *testing.T) {
	ix := fixture(t, "cfggateprod")
	sites, err := ix.ModuleUsage(context.Background(), "example.com/dep")
	if err != nil {
		t.Fatal(err)
	}

	var foundGatedDead, foundZeroValueDead, foundDynamic bool
	for _, s := range sites {
		if s.Function == "callVulnerableGated" {
			foundGatedDead = true
			if !s.DeadCode {
				t.Errorf("callVulnerableGated: expected DeadCode=true, got false (gated_by=%s)", s.GatedBy)
			}
		}
		if s.Function == "callVulnerableZeroValue" {
			foundZeroValueDead = true
			if !s.DeadCode {
				t.Errorf("callVulnerableZeroValue: expected DeadCode=true, got false (gated_by=%s)", s.GatedBy)
			}
		}
		if s.Function == "callVulnerableDynamic" {
			foundDynamic = true
			if s.DeadCode {
				t.Errorf("callVulnerableDynamic: expected DeadCode=false, got true")
			}
			if s.GatedBy == "" {
				t.Errorf("callVulnerableDynamic: expected GatedBy non-empty")
			}
		}
	}

	if !foundGatedDead {
		t.Errorf("callVulnerableGated not found in sites: %+v", sites)
	}
	if !foundZeroValueDead {
		t.Errorf("callVulnerableZeroValue not found in sites: %+v", sites)
	}
	if !foundDynamic {
		t.Errorf("callVulnerableDynamic not found in sites: %+v", sites)
	}
}

func TestTraceArgument_YamlTagAndConfigPackage(t *testing.T) {
	ix := fixture(t, "yamlconfigprod")

	// 1. AppConfig.XPath has yaml:"xpath" tag: must trace to OriginConfiguration
	parseSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	parseSites, err := ix.FindCallers(context.Background(), parseSym)
	if err != nil || len(parseSites) != 1 {
		t.Fatalf("FindCallers(Parse): sites=%v err=%v", parseSites, err)
	}
	flowYaml, _, err := ix.TraceArgumentBound(context.Background(), parseSites[0], 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flowYaml.Origin != domain.OriginConfiguration {
		t.Errorf("yaml tag field: got origin %s, want CONFIGURATION (summary: %s)", flowYaml.Origin, flowYaml.Summary)
	}

	// 2. Settings.Query is declared in package config: must trace to OriginConfiguration
	parseURISym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "ParseURI"}
	uriSites, err := ix.FindCallers(context.Background(), parseURISym)
	if err != nil || len(uriSites) != 1 {
		t.Fatalf("FindCallers(ParseURI): sites=%v err=%v", uriSites, err)
	}
	flowConfig, _, err := ix.TraceArgumentBound(context.Background(), uriSites[0], 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flowConfig.Origin != domain.OriginConfiguration {
		t.Errorf("config package field: got origin %s, want CONFIGURATION (summary: %s)", flowConfig.Origin, flowConfig.Summary)
	}
}
