package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// The persisted proof contract is load/save schema: a proof that names another
// contract, carries no reconstructed cover, or carries no captured input bundle
// cannot be persisted at all. Admission still requires the checker to re-derive
// the premises; this is only the shape check.

func validFixProof() FixProof {
	subject := SymbolRef{Package: "example.com/dep/server", Symbol: "Create"}
	return FixProof{
		Contract:       FixProofContract,
		Rules:          FixProofRules,
		RecordID:       "GHSA-schema",
		DocumentDigest: "sha256:" + strings.Repeat("a", 64),
		EntryRef:       0,
		Module:         "example.com/dep",
		Version:        "v0.8.0",
		Cover: FixProofCover{
			Rule:          FixProofCoverRule,
			ID:            "sha256:" + strings.Repeat("b", 64),
			SubjectDigest: AbsenceSubjectSetDigest([]SymbolRef{subject}),
			Subjects:      []SymbolRef{subject},
			Packages:      []string{subject.Package},
		},
		Digest:  "sha256:" + strings.Repeat("c", 64),
		Binding: json.RawMessage(`{"contract":"` + FixProofContract + `"}`),
		Inputs:  json.RawMessage(`{"entry_ref":0}`),
	}
}

func TestFixProofValidateRefusesUnsupportedOrEmptyProof(t *testing.T) {
	valid := validFixProof()
	if err := valid.Validate(); err != nil {
		t.Fatalf("the canonical shape was refused: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*FixProof)
	}{
		{"other contract version", func(p *FixProof) { p.Contract = "fixbinding/re-derivation/0" }},
		{"other checker rules", func(p *FixProof) { p.Rules = "similarity" }},
		{"no record identity", func(p *FixProof) { p.RecordID = "" }},
		{"no document digest", func(p *FixProof) { p.DocumentDigest = "" }},
		{"negative entry", func(p *FixProof) { p.EntryRef = -1 }},
		{"empty subject set", func(p *FixProof) { p.Cover.Subjects = nil }},
		{"empty subject identity", func(p *FixProof) {
			p.Cover.Subjects = []SymbolRef{{Package: "example.com/dep"}}
		}},
		{"no cover identity", func(p *FixProof) { p.Cover.ID = "" }},
		{"no subject digest", func(p *FixProof) { p.Cover.SubjectDigest = "" }},
		{"no cover rule", func(p *FixProof) { p.Cover.Rule = "" }},
		{"no canonical binding", func(p *FixProof) { p.Binding = nil }},
		{"invalid canonical binding", func(p *FixProof) { p.Binding = json.RawMessage(`{`) }},
		{"no captured input bundle", func(p *FixProof) { p.Inputs = nil }},
		{"invalid input bundle", func(p *FixProof) { p.Inputs = json.RawMessage(`[`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := validFixProof()
			tc.mutate(&proof)
			if err := proof.Validate(); err == nil {
				t.Fatalf("a proof with %s was accepted", tc.name)
			}
		})
	}
}

// TestFixProofRoundTripsVerbatim keeps the historical/persisted bytes intact:
// the canonical binding and the captured input bundle are neither rewritten nor
// dropped by a load/save cycle.
func TestFixProofRoundTripsVerbatim(t *testing.T) {
	proof := validFixProof()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded FixProof
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(decoded.Binding) != string(proof.Binding) {
		t.Fatalf("canonical binding was rewritten: %s", decoded.Binding)
	}
	if string(decoded.Inputs) != string(proof.Inputs) {
		t.Fatalf("captured input bundle was rewritten: %s", decoded.Inputs)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("the round-tripped proof is invalid: %v", err)
	}
}
