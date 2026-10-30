package triage

import (
	"encoding/json"
	"errors"
	"testing"
)

// testRun is the run identity every envelope fixture binds to.
var testRun = RunIdentity{
	CaseIdentityRef:      "case-01",
	AdvisoryDigest:       "sha256:advisory-aaaa",
	SnapshotDigest:       "sha256:snap-bbbb",
	ConditionCatalogHash: "cccc0000",
}

// validEnvelope returns a signed, run-bound envelope. Mutate and re-marshal
// to exercise the rejection paths.
func validEnvelope(t *testing.T) json.RawMessage {
	t.Helper()
	p := ProposalIngest{
		SchemaVersion:        ProposalIngestSchemaVersion,
		ProposalID:           "prop-0001",
		ProposalKind:         string(ProposalKindFalsifier),
		CaseIdentityRef:      testRun.CaseIdentityRef,
		AdvisoryDigest:       testRun.AdvisoryDigest,
		SnapshotDigest:       testRun.SnapshotDigest,
		ConditionCatalogHash: testRun.ConditionCatalogHash,
		Payload:              json.RawMessage(`{"condition_id":"cond-signal","check":"code_absent"}`),
		Source:               "productb/triage@run-1",
	}
	p.SignPayloadDigest()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// mutateEnvelope rewrites one field of the envelope, optionally re-signing
// the payload digest so integrity checks don't mask the identity check.
func mutateEnvelope(t *testing.T, resign bool, mutate func(*ProposalIngest)) json.RawMessage {
	t.Helper()
	var p ProposalIngest
	if err := json.Unmarshal(validEnvelope(t), &p); err != nil {
		t.Fatal(err)
	}
	mutate(&p)
	if resign {
		p.SignPayloadDigest()
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIngestProposalMatching(t *testing.T) {
	prov, err := IngestProposal(validEnvelope(t), testRun)
	if err != nil {
		t.Fatalf("matching proposal rejected: %v", err)
	}
	if prov.ProposalID != "prop-0001" || prov.ProposalKind != string(ProposalKindFalsifier) {
		t.Fatalf("provenance degraded: %+v", prov)
	}
	if string(prov.Payload) == "" || prov.PayloadDigest == "" {
		t.Fatal("provenance lost the payload or digest")
	}
}

func TestIngestProposalForeignSnapshot(t *testing.T) {
	raw := mutateEnvelope(t, true, func(p *ProposalIngest) {
		p.SnapshotDigest = "sha256:snap-foreign"
	})
	_, err := IngestProposal(raw, testRun)
	if !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("foreign-snapshot proposal admitted: %v", err)
	}
	var ie *IngestError
	if !errors.As(err, &ie) || ie.Field != "snapshot_digest" {
		t.Fatalf("rejection must name snapshot_digest, got %v", err)
	}
}

func TestIngestProposalAlteredAdvisory(t *testing.T) {
	raw := mutateEnvelope(t, true, func(p *ProposalIngest) {
		p.AdvisoryDigest = "sha256:advisory-altered"
	})
	_, err := IngestProposal(raw, testRun)
	if !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("altered-advisory proposal admitted: %v", err)
	}
	var ie *IngestError
	if !errors.As(err, &ie) || ie.Field != "advisory_digest" {
		t.Fatalf("rejection must name advisory_digest, got %v", err)
	}
}

func TestIngestProposalForeignCase(t *testing.T) {
	raw := mutateEnvelope(t, true, func(p *ProposalIngest) {
		p.CaseIdentityRef = "case-99"
	})
	_, err := IngestProposal(raw, testRun)
	if !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("foreign-case proposal admitted: %v", err)
	}
}

func TestIngestProposalStaleCatalogHash(t *testing.T) {
	raw := mutateEnvelope(t, true, func(p *ProposalIngest) {
		p.ConditionCatalogHash = "dddd1111" // catalog drifted since the proposal was minted
	})
	_, err := IngestProposal(raw, testRun)
	if !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("stale-catalog proposal admitted: %v", err)
	}
	var ie *IngestError
	if !errors.As(err, &ie) || ie.Field != "condition_catalog_hash" {
		t.Fatalf("rejection must name condition_catalog_hash, got %v", err)
	}
}

func TestIngestProposalTamperedPayload(t *testing.T) {
	// Change payload but keep the recorded digest: integrity fails before identity.
	raw := mutateEnvelope(t, false, func(p *ProposalIngest) {
		p.Payload = json.RawMessage(`{"condition_id":"cond-signal","check":"locus_package_absent"}`)
	})
	_, err := IngestProposal(raw, testRun)
	if !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("tampered payload admitted: %v", err)
	}
	var ie *IngestError
	if !errors.As(err, &ie) || ie.Field != "payload_digest" {
		t.Fatalf("rejection must name payload_digest, got %v", err)
	}
}

func TestIngestProposalMissingFields(t *testing.T) {
	for _, field := range []string{"proposal_id", "proposal_kind", "case_identity_ref", "advisory_digest", "snapshot_digest", "condition_catalog_hash", "source", "payload_digest"} {
		t.Run(field, func(t *testing.T) {
			resign := field != "payload_digest" // resigning would refill the digest
			raw := mutateEnvelope(t, resign, func(p *ProposalIngest) {
				switch field {
				case "proposal_id":
					p.ProposalID = ""
				case "proposal_kind":
					p.ProposalKind = ""
				case "case_identity_ref":
					p.CaseIdentityRef = ""
				case "advisory_digest":
					p.AdvisoryDigest = ""
				case "snapshot_digest":
					p.SnapshotDigest = ""
				case "condition_catalog_hash":
					p.ConditionCatalogHash = ""
				case "source":
					p.Source = ""
				case "payload_digest":
					p.PayloadDigest = ""
				}
			})
			if _, err := IngestProposal(raw, testRun); err == nil {
				t.Fatalf("envelope missing %s admitted", field)
			}
		})
	}
}

func TestIngestProposalRejectsUnknownFields(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(validEnvelope(t), &m); err != nil {
		t.Fatal(err)
	}
	m["verdict"] = "NOT_AFFECTED" // authority smuggling
	raw, _ := json.Marshal(m)
	if _, err := IngestProposal(raw, testRun); err == nil {
		t.Fatal("envelope with foreign authority field admitted")
	}
}

func TestIngestProposalWrongSchema(t *testing.T) {
	raw := mutateEnvelope(t, true, func(p *ProposalIngest) {
		p.SchemaVersion = "proposal-ingest.v2"
	})
	if _, err := IngestProposal(raw, testRun); err == nil {
		t.Fatal("wrong schema admitted")
	}
}

func TestDecodeProposalIngestValid(t *testing.T) {
	p, err := DecodeProposalIngest(validEnvelope(t))
	if err != nil {
		t.Fatalf("decode valid envelope: %v", err)
	}
	if !p.VerifyPayloadDigest() {
		t.Fatal("signed payload does not verify")
	}
}

// TestIngestProposalRejectsPartialRunIdentity pins the run-side rule: a
// zero or partial RunIdentity disables the foreign-binding checks, so
// ingest rejects before the envelope is even compared — never a skipped
// check passing as a match.
func TestIngestProposalRejectsPartialRunIdentity(t *testing.T) {
	cases := map[string]RunIdentity{
		"zero":               {},
		"no case":            {AdvisoryDigest: testRun.AdvisoryDigest, SnapshotDigest: testRun.SnapshotDigest, ConditionCatalogHash: testRun.ConditionCatalogHash},
		"no advisory digest": {CaseIdentityRef: testRun.CaseIdentityRef, SnapshotDigest: testRun.SnapshotDigest, ConditionCatalogHash: testRun.ConditionCatalogHash},
		"no snapshot digest": {CaseIdentityRef: testRun.CaseIdentityRef, AdvisoryDigest: testRun.AdvisoryDigest, ConditionCatalogHash: testRun.ConditionCatalogHash},
		"no catalog hash":    {CaseIdentityRef: testRun.CaseIdentityRef, AdvisoryDigest: testRun.AdvisoryDigest, SnapshotDigest: testRun.SnapshotDigest},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := IngestProposal(validEnvelope(t), run); !errors.Is(err, ErrNonAdmitting) {
				t.Fatalf("partial run identity admitted: %v", err)
			}
		})
	}
}

// TestProposalDecodersRejectTrailingJSON pins the P2-8 decoder rule on the
// ingest surface: an envelope followed by a second JSON value or garbage
// is malformed at both decode levels — never a silently accepted prefix.
func TestProposalDecodersRejectTrailingJSON(t *testing.T) {
	raw := validEnvelope(t)
	for name, tail := range map[string]string{
		"second object": ` {"proposal_id":"other"}`,
		"scalar":        ` 42`,
		"garbage":       ` !!!not-json`,
	} {
		t.Run(name, func(t *testing.T) {
			spliced := append(raw, []byte(tail)...)
			if _, err := DecodeProposalIngest(spliced); err == nil {
				t.Fatalf("DecodeProposalIngest accepted trailing %q", tail)
			}
			if _, err := IngestProposal(spliced, testRun); err == nil {
				t.Fatalf("IngestProposal accepted trailing %q", tail)
			}
		})
	}
}
