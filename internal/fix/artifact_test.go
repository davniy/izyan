package fix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// countingProvider records the order and multiplicity of the locators it is
// asked for.
type countingProvider struct {
	inner    ArtifactProvider
	requests []string
}

func (p *countingProvider) Acquire(ctx context.Context, ref Reference) domain.FixArtifact {
	p.requests = append(p.requests, ref.URL)
	return p.inner.Acquire(ctx, ref)
}

// unsupportedFor answers one locator the way a provider without that
// acquisition form would.
type unsupportedFor struct {
	inner   ArtifactProvider
	locator string
}

func (p unsupportedFor) Acquire(ctx context.Context, ref Reference) domain.FixArtifact {
	if ref.URL != p.locator {
		return p.inner.Acquire(ctx, ref)
	}
	return domain.FixArtifact{
		Locator:    ref.URL,
		Kind:       ref.Kind,
		Provenance: "test provider",
		Outcome:    domain.FixArtifactUnsupportedAcquisition,
		Detail:     "unsupported acquisition form",
	}
}

const (
	testLocOne = "https://github.com/example/lib/commit/aaa"
	testLocTwo = "https://github.com/example/lib/commit/bbb"
)

const testPatchOne = `diff --git a/lib.go b/lib.go
--- a/lib.go
+++ b/lib.go
@@ -1,1 +1,2 @@ func F() {
+	// guarded
`

const testPatchTwo = `diff --git a/other.go b/other.go
--- a/other.go
+++ b/other.go
@@ -1,1 +1,2 @@ func G() {
+	// guarded
`

func refsFor(urls ...string) []Reference {
	out := make([]Reference, 0, len(urls))
	for _, u := range urls {
		out = append(out, Reference{URL: u, Kind: "commit"})
	}
	return out
}

// Every distinct locator is requested exactly once, in declaration order, and
// one locator's answer never stands in for another's.
func TestAcquireAllRequestsEveryDistinctLocator(t *testing.T) {
	provider := &countingProvider{inner: CapturedProvider{Artifacts: map[string]string{
		testLocOne: testPatchOne,
		testLocTwo: testPatchTwo,
	}}}
	acquired := AcquireAll(context.Background(), provider, refsFor(testLocOne, testLocTwo, testLocOne))

	want := []string{testLocOne, testLocTwo}
	if strings.Join(provider.requests, ",") != strings.Join(want, ",") {
		t.Fatalf("requests=%v, want each distinct locator once in order: %v", provider.requests, want)
	}
	if len(acquired) != 2 {
		t.Fatalf("acquired=%+v, want one record per distinct locator", acquired)
	}
	for n, locator := range want {
		record := acquired[n].Record
		if record.Locator != locator {
			t.Fatalf("record[%d]=%+v, want locator %s", n, record, locator)
		}
		if record.Outcome != domain.FixArtifactComplete || record.Digest == "" || acquired[n].Body == "" {
			t.Fatalf("record[%d]=%+v body=%q, want complete captured bytes", n, record, acquired[n].Body)
		}
	}
	if acquired[0].Record.Digest == acquired[1].Record.Digest {
		t.Fatal("two different bodies must not share one digest")
	}
}

// Byte-identical bodies are recorded once, but every locator keeps its own
// provenance: deduplication must never erase where an answer came from.
func TestAcquireAllDeduplicatesIdenticalBodies(t *testing.T) {
	provider := &countingProvider{inner: CapturedProvider{
		Artifacts: map[string]string{testLocOne: testPatchOne, testLocTwo: testPatchOne},
		Label:     "case fixture",
	}}
	acquired := AcquireAll(context.Background(), provider, refsFor(testLocOne, testLocTwo))

	if len(acquired) != 2 {
		t.Fatalf("acquired=%+v, want one record per locator", acquired)
	}
	primary, duplicate := acquired[0], acquired[1]
	if primary.Record.DuplicateOf != "" || primary.Body != testPatchOne {
		t.Fatalf("primary=%+v body=%q, want the bytes recorded once", primary.Record, primary.Body)
	}
	if duplicate.Record.DuplicateOf != testLocOne {
		t.Fatalf("duplicate=%+v, want duplicate_of=%s", duplicate.Record, testLocOne)
	}
	if duplicate.Record.Bytes != "" || duplicate.Body != "" {
		t.Fatalf("duplicate=%+v body=%q, want no second copy of the bytes", duplicate.Record, duplicate.Body)
	}
	if duplicate.Record.Digest != primary.Record.Digest {
		t.Fatalf("duplicate digest %s != primary digest %s", duplicate.Record.Digest, primary.Record.Digest)
	}
	if duplicate.Record.Provenance != "case fixture" || duplicate.Record.Locator != testLocTwo {
		t.Fatalf("duplicate=%+v, want its own locator and provenance", duplicate.Record)
	}
}

// An artifact the configured inputs do not hold is UNAVAILABLE, and a locator
// whose form the provider does not implement is UNSUPPORTED_ACQUISITION — two
// different facts that a single error return would conflate.
func TestAcquireAllKeepsUnavailableAndUnsupportedApart(t *testing.T) {
	provider := unsupportedFor{
		inner:   CapturedProvider{Artifacts: map[string]string{testLocOne: testPatchOne}},
		locator: testLocTwo,
	}
	acquired := AcquireAll(context.Background(), provider,
		refsFor(testLocOne, testLocTwo, "https://github.com/example/lib/commit/ccc"))

	if len(acquired) != 3 {
		t.Fatalf("acquired=%+v, want one record per locator", acquired)
	}
	if got := acquired[0].Record.Outcome; got != domain.FixArtifactComplete {
		t.Fatalf("outcome=%s, want an available artifact to be complete", got)
	}
	if got := acquired[1].Record.Outcome; got != domain.FixArtifactUnsupportedAcquisition {
		t.Fatalf("outcome=%s, want UNSUPPORTED_ACQUISITION", got)
	}
	if got := acquired[2].Record.Outcome; got != domain.FixArtifactUnavailable {
		t.Fatalf("outcome=%s, want UNAVAILABLE for a locator the inputs do not hold", got)
	}
	for _, a := range acquired[1:] {
		if a.Record.Digest != "" || a.Record.Bytes != "" || len(a.Record.Coordinates) > 0 {
			t.Fatalf("record=%+v, want no captured content for a locator that was not acquired", a.Record)
		}
		if err := a.Record.Validate(); err != nil {
			t.Fatalf("record=%+v does not validate: %v", a.Record, err)
		}
	}
}

// The HTTP transport types its results. A locator form it does not implement
// establishes nothing about the artifact; a definitive 404 does establish that
// the locator is not served; a server error establishes nothing either way.
func TestHTTPProviderAcquireTypesTransportResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.patch":
			_, _ = w.Write([]byte(testPatchOne))
		case "/gone.patch":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cases := []struct {
		url  string
		want domain.FixArtifactOutcome
	}{
		{url: server.URL + "/ok.patch", want: domain.FixArtifactComplete},
		{url: server.URL + "/gone.patch", want: domain.FixArtifactUnavailable},
		{url: server.URL + "/broken.patch", want: domain.FixArtifactAcquisitionFailed},
		{url: "https://osv.dev/vulnerability/GO-2026-0001", want: domain.FixArtifactUnsupportedAcquisition},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			record := HTTPProvider{}.Acquire(context.Background(), Reference{URL: tc.url, Kind: "commit"})
			if record.Outcome != tc.want {
				t.Fatalf("outcome=%s detail=%q, want %s", record.Outcome, record.Detail, tc.want)
			}
			if err := record.Validate(); err != nil {
				t.Fatalf("record=%+v does not validate: %v", record, err)
			}
			if tc.want == domain.FixArtifactComplete {
				if record.Size != len(testPatchOne) || record.Bytes != testPatchOne ||
					record.Digest != domain.EvidenceContentDigest(testPatchOne) {
					t.Fatalf("record=%+v, want the complete body with its digest", record)
				}
				return
			}
			if record.Digest != "" || record.Bytes != "" {
				t.Fatalf("record=%+v, want no captured content", record)
			}
		})
	}
}

// The typed sentinels are what the provider classification routes on, so a
// change in either direction must fail here rather than silently reclassify an
// artifact as missing.
func TestUnsupportedLocatorAndUnavailabilityAreTyped(t *testing.T) {
	if _, err := patchURL("https://osv.dev/vulnerability/GO-2026-0001"); !errors.Is(err, ErrUnsupportedLocator) {
		t.Fatalf("err=%v, want the unsupported-locator sentinel", err)
	}
	record := HTTPProvider{}.Acquire(context.Background(),
		Reference{URL: "https://osv.dev/vulnerability/GO-2026-0001"})
	if record.Outcome != domain.FixArtifactUnsupportedAcquisition {
		t.Fatalf("outcome=%s, want UNSUPPORTED_ACQUISITION", record.Outcome)
	}
}
