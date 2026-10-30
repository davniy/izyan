package domain

import (
	"strings"
	"testing"
)

// A fix artifact record may state only what was measured: complete bytes with
// their digest, or a typed outcome that carries no captured content.
func TestFixArtifactRecordStatesOnlyWhatWasMeasured(t *testing.T) {
	digest := EvidenceContentDigest("patch bytes")
	accepted := []FixArtifact{
		{Locator: "https://example.com/a", Kind: "commit", Outcome: FixArtifactComplete,
			Provenance: "captured inputs", Digest: digest, Size: 11, Bytes: "patch bytes",
			Coordinates: []string{"internal/a/a.go"}},
		{Locator: "https://example.com/b", Kind: "commit", Outcome: FixArtifactComplete,
			Provenance: "captured inputs", Digest: digest, Size: 11, DuplicateOf: "https://example.com/a"},
		{Locator: "https://example.com/c", Outcome: FixArtifactUnmapped, Provenance: "captured inputs",
			Digest: digest, Size: 11, Bytes: "patch bytes", Coordinates: []string{"cmd/legacy/x.go"}},
		{Locator: "https://example.com/d", Outcome: FixArtifactApplicabilityUnknown,
			Provenance: "captured inputs", Digest: digest, Size: 11, Bytes: "patch bytes"},
		{Locator: "https://example.com/e", Outcome: FixArtifactUnavailable,
			Provenance: "captured inputs", Detail: "hold no artifact for this locator"},
		{Locator: "https://example.com/f", Outcome: FixArtifactUnsupportedAcquisition,
			Provenance: "http fetch", Detail: "no acquisition form for this locator"},
		{Locator: "https://example.com/g", Outcome: FixArtifactAcquisitionFailed,
			Provenance: "http fetch", Detail: "connection refused"},
	}
	for _, artifact := range accepted {
		if err := artifact.Validate(); err != nil {
			t.Fatalf("artifact=%+v must validate: %v", artifact, err)
		}
	}

	base := FixArtifact{Locator: "https://example.com/a", Outcome: FixArtifactComplete,
		Provenance: "captured inputs", Digest: digest, Size: 11, Bytes: "patch bytes"}
	refused := []struct {
		name   string
		mutate func(*FixArtifact)
	}{
		{"no locator", func(a *FixArtifact) { a.Locator = "  " }},
		{"unknown outcome", func(a *FixArtifact) { a.Outcome = "PROBABLY_FINE" }},
		{"no provenance", func(a *FixArtifact) { a.Provenance = "" }},
		{"duplicate of itself", func(a *FixArtifact) { a.DuplicateOf = a.Locator }},
		{"captured without digest", func(a *FixArtifact) { a.Digest = "" }},
		{"malformed digest", func(a *FixArtifact) { a.Digest = "sha256:NOTHEX" }},
		{"bytes claimed but absent", func(a *FixArtifact) { a.Bytes = "" }},
		{"unavailable carrying a digest", func(a *FixArtifact) {
			a.Outcome = FixArtifactUnavailable
			a.Bytes = ""
		}},
		{"unavailable carrying bytes", func(a *FixArtifact) { a.Outcome = FixArtifactUnavailable }},
		{"unavailable carrying coordinates", func(a *FixArtifact) {
			a.Outcome = FixArtifactUnavailable
			a.Digest, a.Size, a.Bytes = "", 0, ""
			a.Coordinates = []string{"internal/a/a.go"}
		}},
		{"failed acquisition carrying content", func(a *FixArtifact) {
			a.Outcome = FixArtifactAcquisitionFailed
		}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			artifact := base
			tc.mutate(&artifact)
			err := artifact.Validate()
			if err == nil {
				t.Fatalf("artifact=%+v must be refused", artifact)
			}
			if !strings.Contains(err.Error(), "fix artifact") {
				t.Fatalf("err=%v, want a fix-artifact diagnostic", err)
			}
		})
	}
}

// Accounting is per distinct locator: two rows for one locator would
// double-count one declared reference.
func TestValidateFixArtifactsRefusesRepeatedLocator(t *testing.T) {
	digest := EvidenceContentDigest("patch bytes")
	artifacts := []FixArtifact{
		{Locator: "https://example.com/a", Outcome: FixArtifactComplete,
			Provenance: "captured inputs", Digest: digest, Size: 11, Bytes: "patch bytes"},
		{Locator: "https://example.com/a", Outcome: FixArtifactUnavailable,
			Provenance: "captured inputs"},
	}
	err := ValidateFixArtifacts(artifacts)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("err=%v, want a repeated-locator refusal", err)
	}
	if err := ValidateFixArtifacts(nil); err != nil {
		t.Fatalf("err=%v, want nil artifacts to validate", err)
	}
}

// Captured is the property the gap mapping and the evidence choice both read: a
// captured outcome rests on complete bytes and carries a digest.
func TestFixArtifactOutcomeCaptured(t *testing.T) {
	captured := []FixArtifactOutcome{FixArtifactComplete, FixArtifactUnmapped, FixArtifactApplicabilityUnknown}
	for _, outcome := range captured {
		if !outcome.Captured() {
			t.Fatalf("outcome=%s must count as captured", outcome)
		}
	}
	notCaptured := []FixArtifactOutcome{FixArtifactUnavailable, FixArtifactUnsupportedAcquisition, FixArtifactAcquisitionFailed}
	for _, outcome := range notCaptured {
		if outcome.Captured() {
			t.Fatalf("outcome=%s must not count as captured", outcome)
		}
	}
}
