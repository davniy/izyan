package domain_test

import (
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

// declaredAssumption builds one well-formed member with a matching
// digest pin.
func declaredAssumption(id string, kind domain.DeclaredAssumptionKind, scope string) domain.DeclaredAssumption {
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
		a.Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}}
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return a
}

// declaredDocument assembles a document with a matching content digest.
func declaredDocument(assumptions ...domain.DeclaredAssumption) *domain.DeclaredAssumptionsDocument {
	return &domain.DeclaredAssumptionsDocument{
		Schema:        domain.DeclaredAssumptionsSchema,
		Assumptions:   assumptions,
		ContentDigest: domain.DeclaredAssumptionsContentDigest(domain.DeclaredAssumptionsSchema, assumptions),
	}
}

// declaredInput wraps a loaded document as the persisted channel record.
func declaredInput(doc *domain.DeclaredAssumptionsDocument) *domain.DeclaredAssumptionsInput {
	return &domain.DeclaredAssumptionsInput{
		Path: "local:assumptions.json", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Schema: doc.Schema, ContentDigest: doc.ContentDigest, Assumptions: doc.Assumptions,
	}
}

func rejectionReason(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	return domain.AssumptionRejectionReason(err)
}

// A valid config-trust + supported-targets document validates and
// carries stable digest pins.
func TestDeclaredAssumptionsValidDocument(t *testing.T) {
	trust := declaredAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := declaredAssumption("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	doc := declaredDocument(trust, targets)
	if err := domain.ValidateDeclaredAssumptions(doc); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if doc.ContentDigest == "" || trust.Digest == "" {
		t.Fatalf("digests missing: %+v", doc)
	}
	// The canonical forms are stable and distinct from the raw content.
	if again := domain.CanonicalAssumptionDigest(trust); again != trust.Digest {
		t.Fatalf("digest not stable: %s vs %s", again, trust.Digest)
	}
	if again := domain.DeclaredAssumptionsContentDigest(doc.Schema, doc.Assumptions); again != doc.ContentDigest {
		t.Fatalf("content digest not stable: %s vs %s", again, doc.ContentDigest)
	}
	// An artifact-scoped supported-targets declaration is a valid
	// member — it just cannot satisfy a product-wide requirement.
	artifact := declaredAssumption("ASM-ARTIFACT", domain.AssumptionSupportedTargets, domain.AssumptionScopeArtifact)
	if err := domain.ValidateDeclaredAssumption(artifact); err != nil {
		t.Fatalf("artifact-scoped targets rejected: %v", err)
	}
}

// Every malformed member/document shape fails closed with the named
// rejection reason.
func TestDeclaredAssumptionsRejectsMalformed(t *testing.T) {
	trust := declaredAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := declaredAssumption("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	valid := func() *domain.DeclaredAssumptionsDocument { return declaredDocument(trust, targets) }

	cases := map[string]func(*domain.DeclaredAssumptionsDocument){
		"duplicate ids": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions = append(d.Assumptions, d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"wrong schema": func(d *domain.DeclaredAssumptionsDocument) { d.Schema = "declared-assumptions/2" },
		"empty members": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions = nil
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, nil)
		},
		"unsupported kind": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Kind = "anything-goes"
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"missing owner": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Owner = ""
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"empty source reference": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].SourceRef = ""
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"missing authority": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Authority = ""
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"empty statement": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Statement = ""
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"timestamp review date": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].ReviewDate = "2027-01-01T00:00:00Z"
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"valid_from after review": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].ValidFrom = "2027-02-01"
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"member digest mismatch": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Statement = "edited without re-pinning"
		},
		"content digest mismatch": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[1].Statement = "edited without re-pinning the document"
			d.Assumptions[1].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[1])
		},
		"missing member digest": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Digest = ""
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"config-trust with targets": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}}
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"config-trust artifact scope": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Scope = domain.AssumptionScopeArtifact
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"supported-targets without targets": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[1].Targets = nil
			d.Assumptions[1].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[1])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"empty target enumeration": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[1].Targets = &domain.ProductTargetScope{GOOS: nil}
			d.Assumptions[1].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[1])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"artifact target with several GOOS": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[1].Scope = domain.AssumptionScopeArtifact
			d.Assumptions[1].Targets = &domain.ProductTargetScope{GOOS: []string{"linux", "darwin"}}
			d.Assumptions[1].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[1])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"invalid scope": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Scope = "everywhere"
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
		"control characters": func(d *domain.DeclaredAssumptionsDocument) {
			d.Assumptions[0].Statement = "trusted\ninjected table row"
			d.Assumptions[0].Digest = domain.CanonicalAssumptionDigest(d.Assumptions[0])
			d.ContentDigest = domain.DeclaredAssumptionsContentDigest(d.Schema, d.Assumptions)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := valid()
			mutate(doc)
			err := domain.ValidateDeclaredAssumptions(doc)
			if err == nil {
				t.Fatalf("%s: malformed document accepted", name)
			}
			if reason := rejectionReason(t, err); reason == "" {
				t.Fatalf("%s: rejection is not typed: %v", name, err)
			}
		})
	}

	t.Run("nil document", func(t *testing.T) {
		if err := domain.ValidateDeclaredAssumptions(nil); rejectionReason(t, err) != domain.AssumptionRejectDocumentAbsent {
			t.Fatalf("nil document: %v", err)
		}
	})
	t.Run("member count bound", func(t *testing.T) {
		members := make([]domain.DeclaredAssumption, 0, domain.MaxDeclaredAssumptions+1)
		for i := 0; i <= domain.MaxDeclaredAssumptions; i++ {
			members = append(members, declaredAssumption(
				"ASM-"+string(rune('A'+i%26))+string(rune('a'+i/26)),
				domain.AssumptionConfigTrust, domain.AssumptionScopeProduct))
		}
		doc := declaredDocument(members...)
		if err := domain.ValidateDeclaredAssumptions(doc); err == nil {
			t.Fatal("oversized member list accepted")
		}
	})
}

// Scope coverage is a one-way lattice: product covers narrower scopes,
// nothing narrower covers product.
func TestAssumptionScopeCovers(t *testing.T) {
	cases := []struct {
		scope, required string
		want            bool
	}{
		{domain.AssumptionScopeProduct, domain.AssumptionScopeProduct, true},
		{domain.AssumptionScopeProduct, domain.AssumptionScopeArtifact, true},
		{domain.AssumptionScopeProduct, domain.AssumptionScopeDeployment, true},
		{domain.AssumptionScopeProduct, "config:app", true},
		{domain.AssumptionScopeArtifact, domain.AssumptionScopeProduct, false},
		{domain.AssumptionScopeArtifact, domain.AssumptionScopeArtifact, true},
		{domain.AssumptionScopeDeployment, domain.AssumptionScopeProduct, false},
		{domain.AssumptionScopeDeployment, "config:app", false},
		{"config:app", "config:app", true},
		{"config:app", "config:other", false},
		{"config:app", domain.AssumptionScopeProduct, false},
	}
	for _, tc := range cases {
		if got := domain.ScopeCovers(tc.scope, tc.required); got != tc.want {
			t.Errorf("ScopeCovers(%q, %q) = %v, want %v", tc.scope, tc.required, got, tc.want)
		}
	}
}

// Admission is the only door an assumption may enter a decision through:
// every inadmissible shape fails with its named reason.
func TestAssumptionAdmission(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	trust := declaredAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := declaredAssumption("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	valid := declaredInput(declaredDocument(trust, targets))

	t.Run("valid config-trust", func(t *testing.T) {
		got, err := domain.AdmitAssumption(valid, domain.AssumptionConfigTrust, domain.AssumptionScopeProduct, now)
		if err != nil || got.ID != trust.ID {
			t.Fatalf("admission = %+v, %v", got, err)
		}
		// A product-wide statement covers a narrower config surface.
		got, err = domain.AdmitAssumption(valid, domain.AssumptionConfigTrust, "config:app", now)
		if err != nil || got.ID != trust.ID {
			t.Fatalf("narrow-scope admission = %+v, %v", got, err)
		}
	})
	t.Run("valid product targets", func(t *testing.T) {
		got, err := domain.AdmitAssumption(valid, domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct, now)
		if err != nil || got.ID != targets.ID || got.Targets == nil || got.Targets.GOOS[0] != "linux" {
			t.Fatalf("target admission = %+v, %v", got, err)
		}
	})

	trustCases := []struct {
		name string
		in   *domain.DeclaredAssumptionsInput
		kind domain.DeclaredAssumptionKind
		want string
	}{
		{"missing document", nil, domain.AssumptionConfigTrust, domain.AssumptionRejectDocumentAbsent},
		{"failed intake", &domain.DeclaredAssumptionsInput{
			Path: "local:x", LoadError: domain.AssumptionsLoadInvalid,
		}, domain.AssumptionConfigTrust, domain.AssumptionRejectDocumentInvalid},
		{"missing config-trust", declaredInput(declaredDocument(targets)),
			domain.AssumptionConfigTrust, domain.AssumptionRejectAbsent},
		{"missing supported-targets", declaredInput(declaredDocument(trust)),
			domain.AssumptionSupportedTargets, domain.AssumptionRejectAbsent},
		{"artifact scope cannot satisfy product-wide", declaredInput(declaredDocument(
			declaredAssumption("ASM-ARTIFACT", domain.AssumptionSupportedTargets, domain.AssumptionScopeArtifact))),
			domain.AssumptionSupportedTargets, domain.AssumptionRejectScopeMismatch},
		{"tampered digest", func() *domain.DeclaredAssumptionsInput {
			doc := declaredDocument(trust)
			doc.Assumptions[0].Statement = "edited after pinning"
			return declaredInput(doc)
		}(), domain.AssumptionConfigTrust, domain.AssumptionRejectDigestMismatch},
		{"expired review date", func() *domain.DeclaredAssumptionsInput {
			a := trust
			a.ReviewDate = "2026-01-01"
			a.Digest = domain.CanonicalAssumptionDigest(a)
			return declaredInput(declaredDocument(a))
		}(), domain.AssumptionConfigTrust, domain.AssumptionRejectExpired},
		{"not yet valid", func() *domain.DeclaredAssumptionsInput {
			a := trust
			a.ValidFrom = "2027-01-01"
			a.Digest = domain.CanonicalAssumptionDigest(a)
			return declaredInput(declaredDocument(a))
		}(), domain.AssumptionConfigTrust, domain.AssumptionRejectNotYetValid},
		{"malformed member", func() *domain.DeclaredAssumptionsInput {
			a := trust
			a.Owner = ""
			a.Digest = domain.CanonicalAssumptionDigest(a)
			return declaredInput(declaredDocument(a))
		}(), domain.AssumptionConfigTrust, domain.AssumptionRejectMalformed},
	}
	for _, tc := range trustCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domain.AdmitAssumption(tc.in, tc.kind, domain.AssumptionScopeProduct, now)
			if err == nil {
				t.Fatalf("inadmissible assumption admitted: %+v", got)
			}
			if reason := domain.AssumptionRejectionReason(err); reason != tc.want {
				t.Fatalf("reason = %q, want %q (%v)", reason, tc.want, err)
			}
			if got.ID != "" {
				t.Fatalf("rejected admission returned a member: %+v", got)
			}
		})
	}

	t.Run("invalid required scope", func(t *testing.T) {
		_, err := domain.AdmitAssumption(valid, domain.AssumptionConfigTrust, "anywhere", now)
		if domain.AssumptionRejectionReason(err) != domain.AssumptionRejectMalformed {
			t.Fatalf("invalid required scope: %v", err)
		}
	})
	// A review date of "today" is still valid — expiry starts the day
	// after the declared review date.
	t.Run("review date today is admissible", func(t *testing.T) {
		a := trust
		a.ReviewDate = "2026-10-20"
		a.Digest = domain.CanonicalAssumptionDigest(a)
		_, err := domain.AdmitAssumption(declaredInput(declaredDocument(a)),
			domain.AssumptionConfigTrust, domain.AssumptionScopeProduct, now)
		if err != nil {
			t.Fatalf("today's review date rejected: %v", err)
		}
	})
}

// The document record and its accessors keep the policy inputs distinct:
// ids are carried, a failed channel exposes no document, and an empty
// record is not a document.
func TestDeclaredAssumptionsInputAccessors(t *testing.T) {
	trust := declaredAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	in := declaredInput(declaredDocument(trust))
	if doc := in.Document(); doc == nil || len(doc.Assumptions) != 1 {
		t.Fatalf("loaded document projection = %+v", doc)
	}
	if ids := in.AssumptionIDs(); len(ids) != 1 || ids[0] != trust.ID {
		t.Fatalf("assumption ids = %v", ids)
	}
	failed := &domain.DeclaredAssumptionsInput{Path: "local:x", LoadError: domain.AssumptionsLoadInvalid,
		Assumptions: []domain.DeclaredAssumption{trust}}
	if failed.Document() != nil {
		t.Fatal("failed channel exposed a usable document")
	}
	var nilInput *domain.DeclaredAssumptionsInput
	if nilInput.Document() != nil {
		t.Fatal("nil record exposed a document")
	}
}
