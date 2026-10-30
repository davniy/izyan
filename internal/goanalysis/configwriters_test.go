package goanalysis

import (
	"context"
	"testing"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
)

func configWriters(t *testing.T, fixtureName, pkg, symbol string) domain.ConfigWriterEvidence {
	t.Helper()
	e, err := fixture(t, fixtureName).ConfigWriters(context.Background(), domain.SymbolRef{Package: pkg, Symbol: symbol})
	if err != nil { t.Fatal(err) }
	if e.InventoryReference == "" || len(e.SourceHashes) == 0 || e.InventoryRaw == "" { t.Fatalf("missing pins: %+v", e) }
	return e
}

func TestConfigWritersDistinguishObjects(t *testing.T) {
	e := configWriters(t, "configscalarprod", "example.com/configscalar", "Config.Enabled")
	seen := map[string]domain.ConfigObject{}
	for _, o := range e.Objects { seen[o.Name] = o }
	for _, name := range []string{"cfg", "unused", "zero"} { if seen[name].ID == "" { t.Fatalf("missing %s: %+v", name, e) } }
	if seen["cfg"].ID == seen["unused"].ID { t.Fatal("merged storage") }
	for _, ev := range seen["unused"].Events { if ev.Kind == "consume" { t.Fatal("unused object acquired cfg consumer") } }
	var consumed, constant, zero bool
	for _, ev := range seen["cfg"].Events { consumed = consumed || ev.Kind == "consume"; constant = constant || ev.Value == "false" && ev.ValueSource == "const" }
	for _, ev := range seen["zero"].Events { zero = zero || ev.Kind == "default" && ev.Value == "false" }
	if !consumed || !constant || !zero { t.Fatalf("missing scalar evidence: %+v", e) }
}

func TestConfigWritersRecordDefaultsAndOverrides(t *testing.T) {
	e := configWriters(t, "configoverrideprod", "example.com/configoverride", "Options.Enabled")
	kinds, channels := map[string]bool{}, map[string]bool{}
	for _, o := range e.Objects { for _, ev := range o.Events { kinds[ev.Kind] = true; channels[ev.Channel] = true } }
	for _, ev := range e.RuntimeChannels { channels[ev.Channel] = true }
	for _, k := range []string{"copy", "alias", "address", "consume", "default"} { if !kinds[k] { t.Errorf("missing %s: %+v", k, e) } }
	for _, c := range []string{"environment", "flag", "config-file", "deserialization"} { if !channels[c] { t.Errorf("missing channel %s: %+v", c, e) } }
}

func TestConfigWritersOpenOnEscape(t *testing.T) {
	e := configWriters(t, "configoverrideprod", "example.com/configoverride", "Options.Enabled")
	var open bool
	for _, o := range e.Objects { open = open || len(o.Blockers) > 0 }
	if !open { t.Fatal("external/callback/address writes silently closed") }
}

func TestConfigWritersMissingInventoryStaysOpen(t *testing.T) {
	ix := fixture(t,"configscalarprod")
	e, err := ix.ConfigWritersWithInventory(context.Background(), domain.SymbolRef{Package:"example.com/configscalar",Symbol:"Config.Enabled"}, affected.PackageInventoryMeasurement{})
	if err != nil { t.Fatal(err) }
	if e.InventoryReference != "" || len(e.Blockers) == 0 || len(e.Objects) == 0 { t.Fatalf("missing inventory repaired or positive evidence lost: %+v",e) }
}

func TestConfigWritersOverrideIdentityStaysOpen(t *testing.T) {
	e := configWriters(t,"configoverrideprod","example.com/configoverride","Options.Enabled")
	objects := map[string]domain.ConfigObject{}
	for _, o := range e.Objects { objects[o.Name] = o }
	for _, name := range []string{"cfg","alias","v"} { if len(objects[name].Blockers) == 0 { t.Errorf("%s silently closed",name) } }
	var copied, aliased, consumed bool
	blockers := strings.Join(objects["cfg"].Blockers,"; ")
	for _, why := range []string{"address taken", "deserialization", "reflection", "unresolved callback", "object passed to callee"} {
		if !strings.Contains(blockers,why) { t.Errorf("missing concrete blocker %q: %s",why,blockers) }
	}
	for _, ev := range objects["cfg"].Events {
		copied = copied || ev.Kind == "copy" && ev.RelatedObject == objects["defaults"].ID
		consumed = consumed || ev.Kind == "consume" && ev.Callee.Symbol == "consume" && ev.Argument == 0
	}
	for _, ev := range objects["alias"].Events { aliased = aliased || ev.Kind == "alias" && ev.RelatedObject == objects["cfg"].ID }
	for _, ev := range objects["defaults"].Events { if ev.Kind == "consume" && ev.Callee.Symbol == "consume" { t.Fatal("copied-from default acquired destination consumer") } }
	if !copied || !aliased || !consumed { t.Fatalf("missing object-bound edges: %+v",e.Objects) }
	keys := map[string]string{}
	for _, ev := range e.RuntimeChannels { if ev.Key != "" { keys[ev.Channel] = ev.Key } }
	if keys["environment"] != `"ENABLE"` || keys["flag"] != `"enable"` || keys["config-file"] != `"settings.json"` { t.Fatalf("runtime names missing: %+v",keys) }
}

func configWriterBoundaryObjects(t *testing.T) (*Index, map[string]domain.ConfigObject) {
	t.Helper()
	ix := fixture(t,"configwriterboundsprod")
	e, err := ix.ConfigWriters(context.Background(),domain.SymbolRef{Package:"example.com/configwriterbounds",Symbol:"Config.Enabled"})
	if err != nil { t.Fatal(err) }
	objects := map[string]domain.ConfigObject{}
	for _, o := range e.Objects { objects[o.Name] = o }
	return ix, objects
}

func TestConfigWritersConsumerSitesResolve(t *testing.T) {
	ix, objects := configWriterBoundaryObjects(t)
	var direct, multiline bool
	for _, ev := range objects["multiline"].Events {
		if ev.Kind != "consume" { continue }
		ix.mu.Lock()
		call, _, pkg, err := ix.callAt(ev.Site)
		ix.mu.Unlock()
		if err != nil { t.Fatalf("recorded consumer cannot resolve: %+v: %v",ev,err) }
		if got := configCallee(pkg.TypesInfo,call); got != ev.Callee { t.Fatalf("wrong consumer: %+v != %+v",got,ev.Callee) }
		if _, _, err := ix.TraceArgument(context.Background(),ev.Site,ev.Argument); err != nil { t.Fatalf("consumer cannot trace: %+v: %v",ev,err) }
		direct = direct || ev.Callee.Symbol == "consume"
		multiline = multiline || ev.Callee.Symbol == "Consumer.Use"
	}
	if !direct || !multiline { t.Fatal("missing direct or multiline consumer") }
}

func TestConfigWritersOmittedFieldDefaults(t *testing.T) {
	_, objects := configWriterBoundaryObjects(t)
	for _, name := range []string{"empty","omitted"} {
		var zero bool
		for _, ev := range objects[name].Events { zero = zero || ev.Kind == "default" && ev.Value == "false" && ev.ValueSource == "zero" }
		if !zero { t.Errorf("%s lacks actual zero default: %+v",name,objects[name]) }
	}
	if _, ok := objects["foreign"]; ok { t.Fatal("foreign named struct merged into queried type") }
}

func TestConfigWritersTupleInitializerUnknown(t *testing.T) {
	_, objects := configWriterBoundaryObjects(t)
	o := objects["tuple"]
	for _, ev := range o.Events { if ev.Kind == "default" && ev.ValueSource == "zero" { t.Fatal("tuple constructor invented a false zero default") } }
	if !strings.Contains(strings.Join(o.Blockers,"; "),"multi-result initializer") { t.Fatalf("tuple constructor not blocked: %+v",o) }
}

func TestConfigWritersRangeAssignmentsOpen(t *testing.T) {
	_, objects := configWriterBoundaryObjects(t)
	for _, name := range []string{"rangedField","rangedObject"} {
		o := objects[name]
		if !strings.Contains(strings.Join(o.Blockers,"; "),"range assignment") { t.Errorf("range write not blocked for %s: %+v",name,o) }
		var measured bool
		for _, ev := range o.Events { measured = measured || ev.Kind == "range-write" }
		if !measured { t.Errorf("range write not recorded for %s",name) }
	}
}

func TestConfigWritersMethodValueCaptureOpen(t *testing.T) {
	_, objects := configWriterBoundaryObjects(t)
	o := objects["captured"]
	if !strings.Contains(strings.Join(o.Blockers,"; "),"pointer-receiver method value") { t.Fatalf("implicit address capture not blocked: %+v",o) }
	var capture bool
	for _, ev := range o.Events { capture = capture || ev.Kind == "receiver-capture" && ev.Callee.Symbol == "Config.Enable" }
	if !capture { t.Fatal("method capture not recorded on actual receiver object") }
	for _, ev := range objects["directReceiver"].Events { if ev.Kind == "receiver-capture" { t.Fatal("direct method invocation mislabeled as captured method value") } }
}

func TestConfigWritersParenthesizedReceiverInvocationOpen(t *testing.T) {
	ix, objects := configWriterBoundaryObjects(t)
	for _, name := range []string{"directReceiver","parenthesizedReceiver"} {
		o := objects[name]
		if !strings.Contains(strings.Join(o.Blockers,"; "),"object passed to callee") { t.Errorf("%s receiver mutation not blocked: %+v",name,o) }
		var consumed bool
		for _, ev := range o.Events {
			if ev.Kind == "receiver-capture" { t.Errorf("%s direct invocation mislabeled as capture",name) }
			if ev.Kind != "consume" { continue }
			if ev.Callee.Package != "example.com/configwriterbounds" || ev.Callee.Symbol != "Config.Enable" || ev.Argument != -1 { t.Errorf("%s wrong receiver/callee: %+v",name,ev) }
			ix.mu.Lock()
			call, _, pkg, err := ix.callAt(ev.Site)
			ix.mu.Unlock()
			if err != nil { t.Fatalf("%s receiver site cannot resolve: %v",name,err) }
			if configCallee(pkg.TypesInfo,call) != ev.Callee { t.Errorf("%s wrong resolved method",name) }
			consumed = true
		}
		if !consumed { t.Errorf("%s missing receiver-bound consumption",name) }
	}
}
