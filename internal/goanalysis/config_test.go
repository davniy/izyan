package goanalysis

import (
	"context"
	"errors"
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

// TestCheckCallSiteGuard_NonCallPosition is the task-3 regression: a
// declaration position is not a call expression, so the guard check must
// report ErrCallSiteNotFound (later translated to UNSUPPORTED) instead of
// a vacuous gated=false OK. Real call sites keep working — including a
// call with no enclosing guard, which legitimately reports gated=false.
func TestCheckCallSiteGuard_NonCallPosition(t *testing.T) {
	ix := fixture(t, "cfggateprod")
	ctx := context.Background()

	decl, err := ix.FindSymbol(ctx, domain.SymbolRef{
		Package: "example.com/cfggateprod", Symbol: "callVulnerableGated"})
	if err != nil || decl == nil {
		t.Fatalf("FindSymbol: site=%v err=%v", decl, err)
	}
	if _, _, _, err := ix.CheckCallSiteGuard(ctx, *decl); !errors.Is(err, ErrCallSiteNotFound) {
		t.Fatalf("CheckCallSiteGuard at declaration %v: err=%v, want ErrCallSiteNotFound", decl, err)
	}
	// The same scope error surfaces from the provenance/validation paths —
	// they share callAt.
	if _, _, err := ix.TraceArgument(ctx, *decl, 0); !errors.Is(err, ErrCallSiteNotFound) {
		t.Fatalf("TraceArgument at declaration: err=%v, want ErrCallSiteNotFound", err)
	}
	if _, _, err := ix.FindValidations(ctx, *decl, 0); !errors.Is(err, ErrCallSiteNotFound) {
		t.Fatalf("FindValidations at declaration: err=%v, want ErrCallSiteNotFound", err)
	}

	// Real call sites still resolve: the gated call reports its guard, the
	// ungated call in main legitimately reports gated=false with no error.
	sites, err := ix.ModuleUsage(ctx, "example.com/dep")
	if err != nil {
		t.Fatal(err)
	}
	seenGated, seenUngated := false, false
	for _, s := range sites {
		gated, dead, detail, err := ix.CheckCallSiteGuard(ctx, s)
		if err != nil {
			t.Fatalf("CheckCallSiteGuard at call site %+v: %v", s, err)
		}
		switch s.Function {
		case "callVulnerableGated", "callVulnerableDynamic":
			if !gated {
				t.Errorf("%s call site: gated=false, want true (dead=%v %q)", s.Function, dead, detail)
			}
			seenGated = true
		case "main":
			if gated || dead {
				t.Errorf("ungated call in main: gated=%v dead=%v, want false/false", gated, dead)
			}
			seenUngated = true
		}
	}
	if !seenGated || !seenUngated {
		t.Fatalf("fixture sites incomplete: gated=%v ungated=%v (sites=%+v)", seenGated, seenUngated, sites)
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

// The exact trigger argument of a mapstructure-tagged configuration field
// traces to CONFIGURATION with its real ArgIndex — and only when no
// alias/reflect write can have populated the field unseen.
func TestTraceArgument_ConfigTagExactTriggerArgument(t *testing.T) {
	ix := fixture(t, "configoriginprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/postreachdep/transformer", Symbol: "QueryAll"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("FindCallers(QueryAll): sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Arg != 1 {
		t.Fatalf("flow arg=%d want 1", flow.Arg)
	}
	if flow.Origin != domain.OriginConfiguration {
		t.Fatalf("trigger origin=%s want CONFIGURATION (summary: %s)", flow.Origin, flow.Summary)
	}
}

func TestTraceArgument_ConfigFieldExternalWriteOutranksTag(t *testing.T) {
	ix := fixture(t, "configwriteprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/postreachdep/transformer", Symbol: "QueryAll"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("FindCallers(QueryAll): sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("external write origin=%s want EXTERNAL_UNTRUSTED (summary: %s)", flow.Origin, flow.Summary)
	}
}

func TestTraceArgument_ConfigFieldAliasBlocksTagFallback(t *testing.T) {
	ix := fixture(t, "configaliasprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/postreachdep/transformer", Symbol: "QueryAll"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("FindCallers(QueryAll): sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginUnknown {
		t.Fatalf("pointer-alias field origin=%s want UNKNOWN (summary: %s)", flow.Origin, flow.Summary)
	}
}

func TestTraceArgument_ConfigFieldReflectWriteBlocksTagFallback(t *testing.T) {
	ix := fixture(t, "configreflectprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/postreachdep/transformer", Symbol: "QueryAll"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("FindCallers(QueryAll): sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginUnknown {
		t.Fatalf("reflect-written field origin=%s want UNKNOWN (summary: %s)", flow.Origin, flow.Summary)
	}
}

func TestTraceArgument_ConfigPlusMessageDataStaysExternal(t *testing.T) {
	ix := fixture(t, "configmixedprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/postreachdep/transformer", Symbol: "QueryAll"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("FindCallers(QueryAll): sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("configuration+message origin=%s want EXTERNAL_UNTRUSTED (summary: %s)", flow.Origin, flow.Summary)
	}
}
