package domain

import (
	"fmt"
	"strings"
)

// FixArtifactOutcome is what the analysis established about one fix locator.
// The vocabulary states evidence, never an intention: a locator is only
// UNAVAILABLE when the configured provider was actually asked and held no
// bytes for it.
type FixArtifactOutcome string

const (
	// FixArtifactComplete: the provider returned the locator's complete bytes,
	// and every relevant changed coordinate resolves in the analysed version's
	// own selected source (or the artifact changes no non-test Go source at
	// all, so there is nothing to map and nothing is outstanding).
	FixArtifactComplete FixArtifactOutcome = "COMPLETE"
	// FixArtifactUnmapped: the bytes are complete, and the changed coordinates
	// were established absent from the selected source. The material is
	// available; it is simply not this version's fix — another release line,
	// an alternative representation, or an unrelated reference. It is never a
	// claim that bytes are missing.
	FixArtifactUnmapped FixArtifactOutcome = "UNMAPPED"
	// FixArtifactApplicabilityUnknown: the bytes are complete, but nothing
	// established whether they describe the analysed version at all (no
	// selected-source input, no recorded selected version, or bytes that carry
	// no interpretable diff). Like UNMAPPED this is analyzer work, not a
	// missing artifact.
	FixArtifactApplicabilityUnknown FixArtifactOutcome = "APPLICABILITY_UNKNOWN"
	// FixArtifactUnavailable: the provider was asked and holds no bytes for
	// this locator. Only this outcome may ground a missing-artifact claim.
	FixArtifactUnavailable FixArtifactOutcome = "UNAVAILABLE"
	// FixArtifactUnsupportedAcquisition: the configured provider does not
	// implement this locator's acquisition form, so nothing was measured in
	// either direction. This is an input capability gap, not a missing
	// artifact and not an absence of bytes.
	FixArtifactUnsupportedAcquisition FixArtifactOutcome = "UNSUPPORTED_ACQUISITION"
	// FixArtifactAcquisitionFailed: the provider could not answer (transport
	// failure, timeout, cancellation). Nothing is established about the
	// artifact's availability, so it grounds neither a missing-artifact claim
	// nor a mapping result.
	FixArtifactAcquisitionFailed FixArtifactOutcome = "ACQUISITION_FAILED"
)

// Validate rejects an unknown outcome, so a producer cannot invent a category
// the gap mapping does not know how to classify.
func (o FixArtifactOutcome) Validate() error {
	switch o {
	case FixArtifactComplete, FixArtifactUnmapped, FixArtifactApplicabilityUnknown,
		FixArtifactUnavailable, FixArtifactUnsupportedAcquisition, FixArtifactAcquisitionFailed:
		return nil
	default:
		return fmt.Errorf("unknown fix artifact outcome %q", o)
	}
}

// Captured reports whether the outcome rests on complete captured bytes. A
// captured outcome carries a digest; the other outcomes carry none.
func (o FixArtifactOutcome) Captured() bool {
	switch o {
	case FixArtifactComplete, FixArtifactUnmapped, FixArtifactApplicabilityUnknown:
		return true
	default:
		return false
	}
}

// FixArtifact is one fix locator's acquisition and applicability account. Every
// locator the record declares gets exactly one, so a reader can tell an
// artifact the provider does not hold from one that is present but does not
// describe the analysed version. Provenance is retained per locator even when
// two locators resolve to byte-identical material: the second record keeps its
// own Locator, Provenance and Digest, points at the first via DuplicateOf, and
// does not repeat the bytes.
type FixArtifact struct {
	// Locator is the reference URL the record declared, exactly as declared.
	Locator string `json:"locator"`
	// Kind is the reference's declared shape (commit | advisory).
	Kind string `json:"kind,omitempty"`
	// Outcome is the typed result of the acquisition and applicability check.
	Outcome FixArtifactOutcome `json:"outcome"`
	// Provenance names how the configured provider answered, so a reader can
	// distinguish configured captured inputs from a transport fetch.
	Provenance string `json:"provenance,omitempty"`
	// Digest pins the complete bytes (sha256:<lowercase hex>) for a captured
	// outcome.
	Digest string `json:"digest,omitempty"`
	// Size is the captured byte count.
	Size int `json:"size,omitempty"`
	// Bytes carries the complete captured artifact. It is recorded once per
	// distinct body; a locator whose bytes duplicate an earlier one leaves it
	// empty and names that locator in DuplicateOf.
	Bytes string `json:"bytes,omitempty"`
	// DuplicateOf names the locator that already recorded these exact bytes.
	DuplicateOf string `json:"duplicate_of,omitempty"`
	// Coordinates inventories the module-relative non-test Go paths the
	// artifact changes. It is recorded for captured artifacts only, and it is
	// what the applicability outcome is decided from.
	Coordinates []string `json:"coordinates,omitempty"`
	// Detail is the human-readable cause behind the outcome. It never carries
	// authority; the typed Outcome does.
	Detail string `json:"detail,omitempty"`
}

// Validate refuses a record that would misstate what was measured: a captured
// outcome without its digest, a failed acquisition carrying content, or a
// provenance-free answer.
func (a FixArtifact) Validate() error {
	if strings.TrimSpace(a.Locator) == "" {
		return fmt.Errorf("fix artifact: locator is required")
	}
	if err := a.Outcome.Validate(); err != nil {
		return fmt.Errorf("fix artifact %q: %w", a.Locator, err)
	}
	if strings.TrimSpace(a.Provenance) == "" {
		return fmt.Errorf("fix artifact %q: provenance of the answer is required", a.Locator)
	}
	if a.DuplicateOf == a.Locator {
		return fmt.Errorf("fix artifact %q: duplicate_of names the locator itself", a.Locator)
	}
	if a.Outcome.Captured() {
		if a.Digest == "" {
			return fmt.Errorf("fix artifact %q: outcome %s requires the captured bytes' digest", a.Locator, a.Outcome)
		}
		if err := validatePinnedDigest("fix artifact digest", a.Digest); err != nil {
			return fmt.Errorf("fix artifact %q: %w", a.Locator, err)
		}
		if a.Size > 0 && a.Bytes == "" && a.DuplicateOf == "" {
			return fmt.Errorf("fix artifact %q: outcome %s records %d captured byte(s) but carries neither the bytes nor a duplicate reference",
				a.Locator, a.Outcome, a.Size)
		}
		return nil
	}
	if a.Digest != "" || a.Bytes != "" || len(a.Coordinates) > 0 || a.DuplicateOf != "" {
		return fmt.Errorf("fix artifact %q: outcome %s carries no captured content, but the record holds some", a.Locator, a.Outcome)
	}
	if a.Size != 0 {
		return fmt.Errorf("fix artifact %q: outcome %s records a byte count although nothing was captured", a.Locator, a.Outcome)
	}
	return nil
}

// ValidateFixArtifacts validates one model's artifact inventory and refuses a
// locator recorded twice: accounting is per distinct locator, so a duplicate
// row would double-count one declared reference.
func ValidateFixArtifacts(artifacts []FixArtifact) error {
	seen := make(map[string]bool, len(artifacts))
	for n := range artifacts {
		a := artifacts[n]
		if err := a.Validate(); err != nil {
			return fmt.Errorf("fix artifacts[%d]: %w", n, err)
		}
		if seen[a.Locator] {
			return fmt.Errorf("fix artifacts[%d]: locator %q is recorded more than once", n, a.Locator)
		}
		seen[a.Locator] = true
	}
	return nil
}
