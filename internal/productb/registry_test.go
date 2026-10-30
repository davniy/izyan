package productb

import (
	"strings"
	"testing"
)

// requiredSchemas is the S-17 minimum surface the roadmap and the merge
// work package pin: every Product B schema the ported runtime emits or
// consumes, plus the deferred-slice schemas the registry must own before
// their producers land.
var requiredSchemas = []string{
	"finding.v1",
	"assessment.v3",
	"fact-gate.v1",
	"observation-archive.v1",
	"decision-package.v4",
	"human-decision.v1",
	"falsifier-verification.v1",
	"triage-metrics.v3",
	"triage-evaluation.v1",
	"ref-selection.v1",
	"intake-proposal.v1",
	"triage-vex-projection.v1",
	"triage-error.v1",
	"raw-agent.v1",
	// §14.3.3 ownership rows — pending producers must still be declared.
	"intake-record.v1",
	"intake-audit.v1",
	"stage0.v1",
	"triage-site.v1",
	"snapshot.v1",
	"triage-baselines.v1",
	"replay.v2",
	"stability-runs.v2",
	"condition-catalog.v1",
	"catalog-binding.v1",
}

// TestSchemaRegistryComplete is the Phase-0 gate shape required by §14.4:
// every Product B schema has a version, owner, producer, consumer, artifact
// path, compatibility and replay rule — no bare type names.
func TestSchemaRegistryComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Schemas() {
		// Two version spellings are legal: triage/runtime schemas carry
		// `.v<n>`; the S-12 research lane ships V2's established
		// `izyan-*/1` artifact spellings verbatim (renaming them would
		// break byte-identical replay and downstream joins).
		if !strings.HasSuffix(d.Version, ".v1") && !strings.HasSuffix(d.Version, ".v2") &&
			!strings.HasSuffix(d.Version, ".v3") && !strings.HasSuffix(d.Version, ".v4") &&
			!hasSlashVersionSuffix(d.Version) {
			t.Errorf("schema %q lacks a versioned suffix", d.Version)
		}
		if seen[d.Version] {
			t.Errorf("schema %q is registered twice", d.Version)
		}
		seen[d.Version] = true
		if d.Owner == "" {
			t.Errorf("schema %q has no owner", d.Version)
		}
		if d.Producer == "" {
			t.Errorf("schema %q has no producer", d.Version)
		}
		if len(d.Consumers) == 0 {
			t.Errorf("schema %q has no consumer", d.Version)
		}
		if d.Artifact == "" {
			t.Errorf("schema %q has no artifact path", d.Version)
		}
		if d.Compatibility == "" {
			t.Errorf("schema %q has no compatibility rule", d.Version)
		}
		if d.ReplayRule == "" {
			t.Errorf("schema %q has no replay rule", d.Version)
		}
		if d.Phase == "" {
			t.Errorf("schema %q has no phase", d.Version)
		}
	}
	for _, want := range requiredSchemas {
		if !seen[want] {
			t.Errorf("required schema %q is not registered", want)
		}
	}
}

// hasSlashVersionSuffix reports whether a schema version ends in "/<n>"
// — the S-12 research lane's V2 spelling (izyan-refindex/1 and friends).
func hasSlashVersionSuffix(v string) bool {
	i := strings.LastIndex(v, "/")
	if i < 0 || i == len(v)-1 {
		return false
	}
	for _, r := range v[i+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// TestSchemaLookup pins the mechanical surface: registered versions resolve,
// unknown versions fail, and a lookup of an undeclared version panics —
// adapters must never emit schemas the registry does not own.
func TestSchemaLookup(t *testing.T) {
	if _, ok := Lookup("finding.v1"); !ok {
		t.Fatal("finding.v1 must be registered")
	}
	if _, ok := Lookup("finding.v9"); ok {
		t.Fatal("finding.v9 must not resolve")
	}
	// Superseded live schemas are history: the registry declares only the
	// clean-cutover versions the live pipeline emits or consumes.
	for _, retired := range []string{"assessment.v1", "replay.v1", "stability-runs.v1", "decision-package.v2", "triage-metrics.v2"} {
		if _, ok := Lookup(retired); ok {
			t.Fatalf("superseded live schema %q must not be registered", retired)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustLookup on an undeclared schema must panic")
		}
	}()
	MustLookup("no-such-schema.v1")
}

// TestRegistryMatchesPortedSurface: every schema whose runtime exists in
// this repository is marked ported, and the deferred-slice schemas are
// marked pending — a ported runtime that forgets to declare itself or a
// pending schema claimed as ported both fail the gate.
func TestRegistryMatchesPortedSurface(t *testing.T) {
	for _, want := range []struct {
		version string
		ported  bool
	}{
		{"finding.v1", true},
		{"assessment.v3", true},
		{"snapshot.v1", true},
		{"observation-archive.v1", true},
		{"fact-gate.v1", true},
		{"decision-package.v4", true},
		{"human-decision.v1", true},
		{"falsifier-verification.v1", true},
		{"intake-proposal.v1", true},
		{"ref-selection.v1", true},
		{"triage-metrics.v3", true},
		{"triage-evaluation.v1", true},
		{"triage-vex-projection.v1", true},
		{"triage-error.v1", true},
		{"raw-agent.v1", true},
		{"condition-catalog.v1", false},
		{"catalog-binding.v1", true},
	} {
		d, ok := Lookup(want.version)
		if !ok {
			t.Fatalf("%s not registered", want.version)
		}
		if d.Ported != want.ported {
			t.Errorf("%s ported = %v, want %v", want.version, d.Ported, want.ported)
		}
	}
}
