package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

// assumptionsMember builds a well-formed member with a matching digest.
func assumptionsMember(id string, kind domain.DeclaredAssumptionKind, scope string) domain.DeclaredAssumption {
	a := domain.DeclaredAssumption{
		ID:         id,
		Kind:       kind,
		Statement:  "statement for " + id,
		Scope:      scope,
		Authority:  "security-owner",
		Owner:      "platform-security",
		SourceRef:  "policy://" + id,
		ReviewDate: "2027-01-01",
	}
	if kind == domain.AssumptionSupportedTargets {
		a.Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}, GOARCH: []string{"amd64"}}
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return a
}

func assumptionsDoc(members ...domain.DeclaredAssumption) domain.DeclaredAssumptionsDocument {
	return domain.DeclaredAssumptionsDocument{
		Schema:        domain.DeclaredAssumptionsSchema,
		Assumptions:   members,
		ContentDigest: domain.DeclaredAssumptionsContentDigest(domain.DeclaredAssumptionsSchema, members),
	}
}

func writeAssumptions(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func marshalDoc(t *testing.T, doc domain.DeclaredAssumptionsDocument) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A well-formed document loads with its typed members, provenance and
// both digest pins; the record never carries the absolute path.
func TestDeclaredAssumptionsLoadValid(t *testing.T) {
	dir := t.TempDir()
	trust := assumptionsMember("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := assumptionsMember("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	doc := assumptionsDoc(trust, targets)
	p := writeAssumptions(t, dir, "assumptions.json", marshalDoc(t, doc))

	rec := LoadDeclaredAssumptions(p)
	if rec == nil || rec.LoadError != "" {
		t.Fatalf("valid document rejected: %+v", rec)
	}
	if rec.Path != ProvenanceLocalRef(p) || strings.Contains(rec.Path, filepath.Dir(p)) {
		t.Fatalf("path is not sanitized provenance: %q", rec.Path)
	}
	if len(rec.SHA256) != 64 {
		t.Fatalf("intake digest = %q", rec.SHA256)
	}
	if rec.Schema != domain.DeclaredAssumptionsSchema || rec.ContentDigest != doc.ContentDigest {
		t.Fatalf("document identity = %q / %q", rec.Schema, rec.ContentDigest)
	}
	if len(rec.Assumptions) != 2 || rec.Assumptions[1].ID != targets.ID {
		t.Fatalf("members = %+v", rec.Assumptions)
	}
	if got := rec.Document(); got == nil || len(got.Assumptions) != 2 {
		t.Fatalf("document projection = %+v", got)
	}
	// The loaded record admits both member kinds.
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if _, err := domain.AdmitAssumption(rec, domain.AssumptionConfigTrust, domain.AssumptionScopeProduct, now); err != nil {
		t.Fatalf("config-trust admission: %v", err)
	}
	if _, err := domain.AdmitAssumption(rec, domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct, now); err != nil {
		t.Fatalf("targets admission: %v", err)
	}
}

func TestDeclaredAssumptionsLoadAbsentPath(t *testing.T) {
	if rec := LoadDeclaredAssumptions(""); rec != nil {
		t.Fatalf("empty path must not create a channel record: %+v", rec)
	}
	if rec := LoadDeclaredAssumptions("   "); rec != nil {
		t.Fatalf("blank path must not create a channel record: %+v", rec)
	}
}

// Every malformed input fails closed with the intake's own reason; none
// of them panics or silently skips the channel.
func TestDeclaredAssumptionsLoadRejects(t *testing.T) {
	dir := t.TempDir()
	trust := assumptionsMember("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := assumptionsMember("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	valid := assumptionsDoc(trust, targets)
	validJSON := marshalDoc(t, valid)

	mutate := func(f func(*domain.DeclaredAssumptionsDocument)) []byte {
		d := valid
		d.Assumptions = append([]domain.DeclaredAssumption(nil), valid.Assumptions...)
		f(&d)
		return marshalDoc(t, d)
	}
	refreshDigests := func(d *domain.DeclaredAssumptionsDocument) {
		for i := range d.Assumptions {
			d.Assumptions[i].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[i])
		}
		d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
	}

	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"unknown field", []byte(`{"schema":"declared-assumptions/1","content_digest":"sha256:` +
			strings.Repeat("0", 64) + `","assumptions":[],"extra":true}`), domain.AssumptionsLoadInvalid},
		{"unknown member field", []byte(`{"schema":"declared-assumptions/1","content_digest":"sha256:` +
			strings.Repeat("0", 64) + `","assumptions":[{"id":"A","kind":"config-trust","statement":"s","scope":"product","authority":"a","owner":"o","source_ref":"r","digest":"sha256:` +
			strings.Repeat("0", 64) + `","review_date":"2027-01-01","trust_me":true}]}`), domain.AssumptionsLoadInvalid},
		{"wrong schema", mutate(func(d *domain.DeclaredAssumptionsDocument) { d.Schema = "declared-assumptions/2" }), domain.AssumptionsLoadInvalid},
		{"trailing content", append(append([]byte{}, validJSON...), []byte(` {}`)...), domain.AssumptionsLoadInvalid},
		{"empty document", []byte(`{}`), domain.AssumptionsLoadInvalid},
		{"duplicate ids", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions = append(d.Assumptions, d.Assumptions[0])
			refreshDigests(d)
		}), domain.AssumptionsLoadInvalid},
		{"invalid member digest", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Digest = "sha256:not-a-digest"
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		}), domain.AssumptionsLoadInvalid},
		{"digest mismatch", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Statement = "edited after pinning"
		}), domain.AssumptionsLoadInvalid},
		{"content digest mismatch", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[1].Statement = "edited after pinning"
			d.Assumptions[1].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[1])
		}), domain.AssumptionsLoadInvalid},
		{"missing owner", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Owner = ""
			refreshDigests(d)
		}), domain.AssumptionsLoadInvalid},
		{"empty source reference", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].SourceRef = ""
			refreshDigests(d)
		}), domain.AssumptionsLoadInvalid},
		{"invalid review date", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].ReviewDate = "01/01/2027"
			refreshDigests(d)
		}), domain.AssumptionsLoadInvalid},
		{"artifact scope for config-trust", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Scope = domain.AssumptionScopeArtifact
			refreshDigests(d)
		}), domain.AssumptionsLoadInvalid},
		{"product scope without targets", mutate(func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[1].Targets = nil
			refreshDigests(d)
		}), domain.AssumptionsLoadInvalid},
		{"credential key", []byte(`{"schema":"declared-assumptions/1","api_key":"secret"}`), domain.AssumptionsLoadInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeAssumptions(t, dir, strings.ReplaceAll(tc.name, " ", "_")+".json", tc.body)
			rec := LoadDeclaredAssumptions(p)
			if rec == nil {
				t.Fatalf("%s: channel record missing", tc.name)
			}
			if rec.LoadError != tc.want {
				t.Fatalf("%s: load_error = %q, want %q", tc.name, rec.LoadError, tc.want)
			}
			if rec.SHA256 == "" {
				t.Fatalf("%s: the exact bytes were not pinned", tc.name)
			}
			if _, err := domain.AdmitAssumption(rec, domain.AssumptionConfigTrust, domain.AssumptionScopeProduct, time.Now()); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectDocumentInvalid {
				t.Fatalf("%s: failed channel admitted: %v", tc.name, err)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		rec := LoadDeclaredAssumptions(filepath.Join(dir, "absent.json"))
		if rec == nil || rec.LoadError != domain.AssumptionsLoadUnreadable {
			t.Fatalf("missing file record = %+v", rec)
		}
	})
	t.Run("directory", func(t *testing.T) {
		rec := LoadDeclaredAssumptions(dir)
		if rec == nil || rec.LoadError != domain.AssumptionsLoadUnreadable {
			t.Fatalf("directory record = %+v", rec)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		p := writeAssumptions(t, dir, "big.json", make([]byte, maxDeclaredAssumptionsBytes+1))
		rec := LoadDeclaredAssumptions(p)
		if rec == nil || rec.LoadError != domain.AssumptionsLoadOversized {
			t.Fatalf("oversized record = %+v", rec)
		}
	})
}

// Expiry is an admission-time fact, not an intake failure: the document
// stays auditable but no decision may consume it.
func TestDeclaredAssumptionsLoadExpiredIsInadmissible(t *testing.T) {
	dir := t.TempDir()
	expired := assumptionsMember("ASM-EXPIRED", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	expired.ReviewDate = "2026-01-01"
	expired.Digest = domain.CanonicalAssumptionDigest(expired)
	doc := assumptionsDoc(expired)
	rec := LoadDeclaredAssumptions(writeAssumptions(t, dir, "expired.json", marshalDoc(t, doc)))
	if rec == nil || rec.LoadError != "" || len(rec.Assumptions) != 1 {
		t.Fatalf("expired document intake = %+v", rec)
	}
	_, err := domain.AdmitAssumption(rec, domain.AssumptionConfigTrust, domain.AssumptionScopeProduct,
		time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	if domain.AssumptionRejectionReason(err) != domain.AssumptionRejectExpired {
		t.Fatalf("expired assumption admission = %v", err)
	}
}

// Artifact-only target scope loads (it is a valid, narrower assertion)
// but can never satisfy a product-wide requirement.
func TestDeclaredAssumptionsLoadArtifactScopeCannotSatisfyProduct(t *testing.T) {
	dir := t.TempDir()
	artifact := assumptionsMember("ASM-ARTIFACT", domain.AssumptionSupportedTargets, domain.AssumptionScopeArtifact)
	rec := LoadDeclaredAssumptions(writeAssumptions(t, dir, "artifact.json", marshalDoc(t, assumptionsDoc(artifact))))
	if rec == nil || rec.LoadError != "" {
		t.Fatalf("artifact-scoped document rejected at intake: %+v", rec)
	}
	if _, err := domain.AdmitAssumption(rec, domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct,
		time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectScopeMismatch {
		t.Fatalf("artifact scope satisfied product-wide admission: %v", err)
	}
}
