package fix

import (
	"context"
	"errors"

	"github.com/davniy/izyan/internal/domain"
)

// Provenance labels distinguish how a locator was answered. They are recorded
// on every artifact, so a reader can tell a configured captured input from a
// transport fetch without reading the provider's configuration.
const (
	ProvenanceCaptured = "configured captured inputs"
	ProvenanceHTTP     = "http fetch"
)

// ArtifactProvider is the configured fix-artifact source for one analysis. It
// answers each locator with exactly one typed record and never decides what the
// answer means for a verdict:
//
//   - complete bytes are recorded as FixArtifactComplete with their digest;
//   - a locator the provider does not hold is FixArtifactUnavailable;
//   - a locator whose acquisition form the provider does not implement is
//     FixArtifactUnsupportedAcquisition — nothing was measured in either
//     direction;
//   - a provider that could not answer at all (transport failure, timeout,
//     cancellation) records FixArtifactAcquisitionFailed.
//
// Acquire is total: it never aborts the caller, so one unreachable locator
// can never hide the artifacts that are available.
type ArtifactProvider interface {
	Acquire(ctx context.Context, ref Reference) domain.FixArtifact
}

// CapturedProvider serves artifacts that were captured before the analysis ran.
// It is the configured-input path: it reads nothing but the map it was built
// with, so the absence of an entry is a fact about the configured inputs, not a
// claim about the upstream repository.
type CapturedProvider struct {
	// Artifacts maps a fix locator, exactly as the record declared it, to its
	// complete captured bytes.
	Artifacts map[string]string
	// Label names the captured input set in the recorded provenance. Empty
	// falls back to ProvenanceCaptured.
	Label string
}

// Acquire implements ArtifactProvider.
func (p CapturedProvider) Acquire(_ context.Context, ref Reference) domain.FixArtifact {
	artifact := domain.FixArtifact{
		Locator:    ref.URL,
		Kind:       ref.Kind,
		Provenance: p.provenanceLabel(),
	}
	body, ok := p.Artifacts[ref.URL]
	if !ok {
		artifact.Outcome = domain.FixArtifactUnavailable
		artifact.Detail = "the configured captured inputs hold no artifact for this locator"
		return artifact
	}
	artifact.Outcome = domain.FixArtifactComplete
	artifact.Digest = domain.EvidenceContentDigest(body)
	artifact.Size = len(body)
	artifact.Bytes = body
	artifact.Detail = "captured in full from the configured inputs"
	return artifact
}

func (p CapturedProvider) provenanceLabel() string {
	if p.Label == "" {
		return ProvenanceCaptured
	}
	return p.Label
}

// Acquire implements ArtifactProvider on the same transport Fetch uses. The
// classification is deliberately conservative: only a definitive 404/410 makes
// the locator's bytes unavailable, and only an acquisition form this provider
// does not implement is unsupported. Every other failure — connection refused,
// timeout, cancellation, oversized or undecodable body — established nothing
// about the artifact and is recorded as a failed acquisition.
func (p HTTPProvider) Acquire(ctx context.Context, ref Reference) domain.FixArtifact {
	artifact := domain.FixArtifact{
		Locator:    ref.URL,
		Kind:       ref.Kind,
		Provenance: ProvenanceHTTP,
	}
	body, err := p.Fetch(ctx, ref)
	switch {
	case err == nil:
		artifact.Outcome = domain.FixArtifactComplete
		artifact.Digest = domain.EvidenceContentDigest(body)
		artifact.Size = len(body)
		artifact.Bytes = body
		artifact.Detail = "fetched in full"
	case errors.Is(err, ErrUnsupportedLocator):
		artifact.Outcome = domain.FixArtifactUnsupportedAcquisition
		artifact.Detail = err.Error()
	case errors.Is(err, ErrArtifactUnavailable):
		artifact.Outcome = domain.FixArtifactUnavailable
		artifact.Detail = err.Error()
	default:
		artifact.Outcome = domain.FixArtifactAcquisitionFailed
		artifact.Detail = err.Error()
	}
	return artifact
}

// AcquiredArtifact pairs one locator's accounting record with the complete bytes
// the acquisition returned. Body is empty for every outcome that did not capture
// bytes and for a locator whose bytes duplicate an earlier one.
type AcquiredArtifact struct {
	Record domain.FixArtifact
	Body   string
}

// AcquireAll requests every distinct locator the references declare, exactly
// once each and in declaration order. Duplicate references to one locator are
// one request: the same URL cannot be a second artifact.
//
// Identical bodies are recorded once. The first locator that captured a body
// keeps the bytes; a later locator with the same digest keeps its own Locator,
// Kind and Provenance and names the first in DuplicateOf, so provenance
// survives deduplication without repeating the payload.
//
// AcquireAll never stops early: an artifact that could not be acquired is
// recorded for that locator alone and the remaining locators are still
// requested.
func AcquireAll(ctx context.Context, provider ArtifactProvider, refs []Reference) []AcquiredArtifact {
	if provider == nil {
		return nil
	}
	requested := make(map[string]bool, len(refs))
	primary := make(map[string]string, len(refs))
	out := make([]AcquiredArtifact, 0, len(refs))
	for _, ref := range refs {
		if ref.URL == "" || requested[ref.URL] {
			continue
		}
		requested[ref.URL] = true
		record := provider.Acquire(ctx, ref)
		if record.Locator == "" {
			record.Locator = ref.URL
		}
		if record.Kind == "" {
			record.Kind = ref.Kind
		}
		body := ""
		switch {
		case !record.Outcome.Captured():
			record.Bytes = ""
		case record.Digest == "":
			// A provider that captured bytes without identifying them cannot
			// have its answer deduplicated; keep the bytes under this locator.
			body = record.Bytes
		case primary[record.Digest] != "":
			record.DuplicateOf = primary[record.Digest]
			record.Bytes = ""
		default:
			primary[record.Digest] = record.Locator
			body = record.Bytes
		}
		out = append(out, AcquiredArtifact{Record: record, Body: body})
	}
	return out
}
