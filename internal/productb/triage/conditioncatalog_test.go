package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// validCatalog returns a well-formed signed catalog for advisory
// CVE-TEST-1 bound to case "case-01": cond-signal (mandatory, allows
// code_absent + locus_function_unreached), cond-guard (mandatory, allows
// locus_package_absent only) and cond-soft (non-mandatory — never
// admittable).
func validCatalog(t *testing.T) *ConditionCatalog {
	t.Helper()
	c := &ConditionCatalog{
		SchemaVersion:   ConditionCatalogSchemaVersion,
		CatalogID:       "cat-0001",
		AdvisoryID:      "CVE-TEST-1",
		AdvisoryDigest:  "sha256:advisory-aaaa",
		CaseIdentityRef: "case-01",
		Conditions: []CatalogCondition{
			{
				ConditionID: "cond-signal",
				Kind:        "signal_presence",
				Mandatory:   true,
				Subjects: []CatalogSubject{
					{Package: "net/http", Symbol: "Serve", Role: "mandatory-control"},
				},
				ArgumentOrRoleBinding: "mandatory-control",
				CheckerID:             "import-closure",
				CheckerVersion:        "1.0.0",
				AllowedFalsifierKinds: []FalsifierKind{FalsifierCodeAbsent, FalsifierLocusFunctionAbsent},
				CoverageRule:          "every mandatory subject must resolve inside the snapshot",
			},
			{
				ConditionID:           "cond-guard",
				Kind:                  "guard_shape",
				Mandatory:             true,
				CheckerID:             "guard-checker",
				CheckerVersion:        "0.3",
				AllowedFalsifierKinds: []FalsifierKind{FalsifierLocusPackageAbsent},
				CoverageRule:          "guards must cover every declared caller",
			},
			{
				ConditionID:           "cond-soft",
				Kind:                  "soft_signal",
				Mandatory:             false,
				CheckerID:             "soft-checker",
				CheckerVersion:        "0.1",
				AllowedFalsifierKinds: []FalsifierKind{FalsifierCodeAbsent},
				CoverageRule:          "informational only",
			},
		},
	}
	c.Sign()
	return c
}

// fullBinding returns the complete run binding for validCatalog — the
// boundary never hands a partial binding to admission.
func fullBinding(c *ConditionCatalog) CatalogBinding {
	return CatalogBinding{
		AdvisoryID:          c.AdvisoryID,
		AdvisoryDigest:      c.AdvisoryDigest,
		CaseIdentityRef:     c.CaseIdentityRef,
		ExpectedCatalogHash: c.CatalogHash,
	}
}

func marshalCatalog(t *testing.T, c *ConditionCatalog) []byte {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func validProposal() FalsifierProposal {
	return FalsifierProposal{
		ID:          "prop-1",
		ClaimID:     "claim-1",
		ConditionID: "cond-signal",
		Kind:        FalsifierCodeAbsent,
		Subjects:    []FalsifierSubject{{Package: "net/http", Symbol: "Serve"}},
	}
}

func TestConditionCatalogRoundTrip(t *testing.T) {
	c := validCatalog(t)
	got, err := DecodeConditionCatalog(marshalCatalog(t, c))
	if err != nil {
		t.Fatalf("decode valid catalog: %v", err)
	}
	if got.CatalogHash != c.CatalogHash {
		t.Fatalf("hash drift on round trip: %q != %q", got.CatalogHash, c.CatalogHash)
	}
	if !got.VerifyHash() {
		t.Fatal("signed catalog does not verify")
	}
	cond, ok := got.Lookup("cond-signal")
	if !ok {
		t.Fatal("cond-signal missing after round trip")
	}
	if !cond.Mandatory || cond.CheckerID != "import-closure" {
		t.Fatalf("cond-signal degraded: %+v", cond)
	}
}

func TestConditionCatalogRejectsMalformed(t *testing.T) {
	for name, mutate := range map[string]func(*ConditionCatalog){
		"wrong schema version":    func(c *ConditionCatalog) { c.SchemaVersion = "condition-catalog.v2" },
		"missing catalog id":      func(c *ConditionCatalog) { c.CatalogID = "" },
		"missing advisory":        func(c *ConditionCatalog) { c.AdvisoryID = "" },
		"missing advisory digest": func(c *ConditionCatalog) { c.AdvisoryDigest = "" },
		"missing case ref":        func(c *ConditionCatalog) { c.CaseIdentityRef = "" },
		"empty condition id":      func(c *ConditionCatalog) { c.Conditions[0].ConditionID = "" },
		"duplicate condition": func(c *ConditionCatalog) {
			c.Conditions = append(c.Conditions, c.Conditions[1])
			c.Conditions[2].ConditionID = c.Conditions[0].ConditionID
		},
		"no checker":       func(c *ConditionCatalog) { c.Conditions[0].CheckerID = "" },
		"no coverage rule": func(c *ConditionCatalog) { c.Conditions[1].CoverageRule = "" },
		"no allowed kinds": func(c *ConditionCatalog) { c.Conditions[0].AllowedFalsifierKinds = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := validCatalog(t)
			mutate(c)
			c.Sign() // structural checks must fire before hash pinning matters
			if _, err := DecodeConditionCatalog(marshalCatalog(t, c)); err == nil {
				t.Fatal("malformed catalog decoded")
			}
		})
	}
}

func TestConditionCatalogRejectsUnknownFields(t *testing.T) {
	c := validCatalog(t)
	var m map[string]any
	if err := json.Unmarshal(marshalCatalog(t, c), &m); err != nil {
		t.Fatal(err)
	}
	m["verdict"] = "NOT_EXPLOITABLE"
	raw, _ := json.Marshal(m)
	if _, err := DecodeConditionCatalog(raw); err == nil {
		t.Fatal("catalog with foreign field decoded")
	}
}

func TestConditionCatalogStaleHash(t *testing.T) {
	c := validCatalog(t)
	// Sign, then mutate the content without re-signing: the recorded hash
	// no longer matches the canonical content.
	c.Conditions[0].Mandatory = false
	if _, err := DecodeConditionCatalog(marshalCatalog(t, c)); err == nil {
		t.Fatal("tampered catalog verified its hash")
	}
	// Binding must also refuse it.
	bind := CatalogBinding{AdvisoryID: "CVE-TEST-1", AdvisoryDigest: c.AdvisoryDigest, CaseIdentityRef: "case-01", ExpectedCatalogHash: strings.Repeat("0", 64)}
	if err := bind.CheckCatalog(c); !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("stale catalog admitted: %v", err)
	}
}

func TestConditionCatalogRunPinMismatch(t *testing.T) {
	c := validCatalog(t)
	bind := CatalogBinding{
		AdvisoryID:          "CVE-TEST-1",
		AdvisoryDigest:      c.AdvisoryDigest,
		CaseIdentityRef:     c.CaseIdentityRef,
		ExpectedCatalogHash: strings.Repeat("0", 64), // run pins another catalog
	}
	if err := bind.CheckCatalog(c); !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("catalog not matching the run pin admitted: %v", err)
	}
}

func TestConditionCatalogForeignCase(t *testing.T) {
	c := validCatalog(t)
	bind := CatalogBinding{AdvisoryID: c.AdvisoryID, AdvisoryDigest: c.AdvisoryDigest, CaseIdentityRef: "case-99", ExpectedCatalogHash: c.CatalogHash}
	if err := bind.CheckCatalog(c); !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("catalog for a foreign case admitted: %v", err)
	}
}

func TestConditionCatalogAdvisoryMismatch(t *testing.T) {
	c := validCatalog(t)
	for name, bind := range map[string]CatalogBinding{
		"advisory id":     {AdvisoryID: "CVE-OTHER-9", AdvisoryDigest: c.AdvisoryDigest, CaseIdentityRef: c.CaseIdentityRef, ExpectedCatalogHash: c.CatalogHash},
		"advisory digest": {AdvisoryID: c.AdvisoryID, AdvisoryDigest: "sha256:advisory-bbbb", CaseIdentityRef: c.CaseIdentityRef, ExpectedCatalogHash: c.CatalogHash},
	} {
		t.Run(name, func(t *testing.T) {
			if err := bind.CheckCatalog(c); !errors.Is(err, ErrNonAdmitting) {
				t.Fatalf("advisory mismatch admitted: %v", err)
			}
		})
	}
}

func TestAdmitFalsifierProposalNoCatalog(t *testing.T) {
	c0 := validCatalog(t)
	if _, err := AdmitFalsifierProposal(nil, fullBinding(c0), validProposal()); !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("nil catalog admitted: %v", err)
	}
}

func TestAdmitFalsifierProposalValid(t *testing.T) {
	c := validCatalog(t)
	cond, err := AdmitFalsifierProposal(c, fullBinding(c), validProposal())
	if err != nil {
		t.Fatalf("valid proposal not admitted: %v", err)
	}
	if cond.ConditionID != "cond-signal" || cond.CheckerID != "import-closure" {
		t.Fatalf("wrong binding returned: %+v", cond)
	}
}

func TestAdmitFalsifierProposalUnknownCondition(t *testing.T) {
	c := validCatalog(t)
	p := validProposal()
	p.ConditionID = "cond-invented"
	if _, err := AdmitFalsifierProposal(c, fullBinding(c), p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown condition admitted: %v", err)
	}
}

func TestAdmitFalsifierProposalDisallowedKind(t *testing.T) {
	c := validCatalog(t)
	p := validProposal()
	p.ConditionID = "cond-guard" // only locus_package_absent allowed
	p.Kind = FalsifierCodeAbsent // not allowed for cond-guard
	if _, err := AdmitFalsifierProposal(c, fullBinding(c), p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("disallowed kind admitted: %v", err)
	}
}

func TestAdmitFalsifierProposalStaleCatalogRejects(t *testing.T) {
	c := validCatalog(t)
	c.Conditions[0].AllowedFalsifierKinds = append(c.Conditions[0].AllowedFalsifierKinds, FalsifierLocusPackageAbsent)
	// catalog now tampered (hash stale): even an allowed proposal fails
	if _, err := AdmitFalsifierProposal(c, CatalogBinding{}, validProposal()); !errors.Is(err, ErrNonAdmitting) {
		t.Fatalf("proposal against stale catalog admitted: %v", err)
	}
}

func TestAdmitFalsifierProposalFullBinding(t *testing.T) {
	c := validCatalog(t)
	bind := CatalogBinding{
		AdvisoryID:          "CVE-TEST-1",
		AdvisoryDigest:      "sha256:advisory-aaaa",
		CaseIdentityRef:     "case-01",
		ExpectedCatalogHash: c.CatalogHash,
	}
	if _, err := AdmitFalsifierProposal(c, bind, validProposal()); err != nil {
		t.Fatalf("fully bound run rejected a valid proposal: %v", err)
	}
}

// TestCheckCatalogRejectsPartialBinding pins the run-identity rule: a
// binding with any empty field cannot detect a foreign/stale catalog, so
// admission fails closed before any catalog check runs.
func TestCheckCatalogRejectsPartialBinding(t *testing.T) {
	c := validCatalog(t)
	cases := map[string]CatalogBinding{
		"zero":                {},
		"no advisory id":      {AdvisoryDigest: c.AdvisoryDigest, CaseIdentityRef: c.CaseIdentityRef, ExpectedCatalogHash: c.CatalogHash},
		"no advisory digest":  {AdvisoryID: c.AdvisoryID, CaseIdentityRef: c.CaseIdentityRef, ExpectedCatalogHash: c.CatalogHash},
		"no case ref":         {AdvisoryID: c.AdvisoryID, AdvisoryDigest: c.AdvisoryDigest, ExpectedCatalogHash: c.CatalogHash},
		"no catalog hash pin": {AdvisoryID: c.AdvisoryID, AdvisoryDigest: c.AdvisoryDigest, CaseIdentityRef: c.CaseIdentityRef},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if err := b.CheckCatalog(c); !errors.Is(err, ErrNonAdmitting) {
				t.Fatalf("partial binding admitted: %v", err)
			}
		})
	}
}

// TestAdmitFalsifierProposalNonMandatoryCondition pins the F-4 rule: a
// falsifier for a non-mandatory condition can never discharge a mandatory
// claim, so admission is ErrUnsupported — never a KIND/lookup success.
func TestAdmitFalsifierProposalNonMandatoryCondition(t *testing.T) {
	c := validCatalog(t)
	p := validProposal()
	p.ConditionID = "cond-soft" // exists, allows FalsifierCodeAbsent, but Mandatory=false
	p.Kind = FalsifierCodeAbsent
	if _, err := AdmitFalsifierProposal(c, fullBinding(c), p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("non-mandatory condition admitted: %v", err)
	}
}

// TestDecodeConditionCatalogTrailingJSON pins the P2-8 decoder rule: a
// document followed by a second value or garbage is malformed — the strict
// decoder never silently accepts the prefix.
func TestDecodeConditionCatalogTrailingJSON(t *testing.T) {
	c := validCatalog(t)
	raw := marshalCatalog(t, c)
	for name, tail := range map[string]string{
		"second object": ` {"catalog_id":"other"}`,
		"scalar":        ` 42`,
		"garbage":       ` !!!not-json`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConditionCatalog(append(raw, []byte(tail)...)); err == nil {
				t.Fatalf("trailing %q accepted", tail)
			}
		})
	}
}

// TestConditionCatalogLookupAdvisoryCapabilities: the tool hint follows the
// same rule as the prompt — it never derives an admissible condition from
// the advisory id or its symbols. Bound capabilities carry the actual
// catalog ids/kinds/subjects; an unavailable capability carries the reason
// and no condition at all.
func TestConditionCatalogLookupAdvisoryCapabilities(t *testing.T) {
	c := validCatalog(t)
	caps := BuildProposalCapabilities(c, fullBinding(c))
	ro := &ReadOnlyTools{
		Finding:              FindingInput{Finding: Finding{Vulnerability: Vulnerability{IDs: []string{c.AdvisoryID}}}},
		ProposalCapabilities: caps,
	}
	obs := ro.handleLookupAdvisory(context.Background(), nil)
	var bound map[string]any
	if err := json.Unmarshal(obs.Data, &bound); err != nil {
		t.Fatal(err)
	}
	if _, ok := bound["condition_id"]; ok {
		t.Fatalf("lookup_advisory still advertises an advisory-derived condition id: %+v", bound)
	}
	reported, ok := bound["proposal_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("bound capabilities missing from lookup_advisory: %+v", bound)
	}
	if reported["catalog_hash"] != c.CatalogHash || reported["unavailable_reason"] != nil {
		t.Fatalf("bound capability report = %+v", reported)
	}
	conditions, _ := reported["conditions"].([]any)
	if len(conditions) != 2 {
		t.Fatalf("bound conditions = %+v, want the two mandatory entries", conditions)
	}
	first, _ := conditions[0].(map[string]any)
	if first["condition_id"] != "cond-signal" || first["kind"] != "signal_presence" {
		t.Fatalf("condition projection = %+v", first)
	}
	subjects, _ := first["subjects"].([]any)
	if len(subjects) != 1 {
		t.Fatalf("condition subjects = %+v", subjects)
	}

	unavailable := &ReadOnlyTools{
		Finding: FindingInput{Finding: Finding{Vulnerability: Vulnerability{IDs: []string{c.AdvisoryID}}}},
		ProposalCapabilities: ProposalCapabilities{
			UnavailableReason: "no condition catalog is bound to this run",
		},
	}
	obs = unavailable.handleLookupAdvisory(context.Background(), nil)
	var unbound map[string]any
	if err := json.Unmarshal(obs.Data, &unbound); err != nil {
		t.Fatal(err)
	}
	if _, ok := unbound["condition_id"]; ok {
		t.Fatalf("unavailable capability still advertises a condition: %+v", unbound)
	}
	reported, ok = unbound["proposal_capabilities"].(map[string]any)
	if !ok || reported["unavailable_reason"] != "no condition catalog is bound to this run" {
		t.Fatalf("unavailable capability report = %+v", unbound)
	}
	if _, ok := reported["conditions"]; ok {
		t.Fatalf("unavailable capability advertises conditions: %+v", reported)
	}

	// Without a capability report the tool simply omits the section; it
	// never falls back to the advisory-derived id.
	bare := &ReadOnlyTools{Finding: FindingInput{Finding: Finding{Vulnerability: Vulnerability{IDs: []string{c.AdvisoryID}}}}}
	obs = bare.handleLookupAdvisory(context.Background(), nil)
	var plain map[string]any
	if err := json.Unmarshal(obs.Data, &plain); err != nil {
		t.Fatal(err)
	}
	if _, ok := plain["condition_id"]; ok {
		t.Fatalf("capability-less lookup_advisory advertises a condition: %+v", plain)
	}
	if _, ok := plain["proposal_capabilities"]; ok {
		t.Fatalf("capability-less lookup_advisory invents a capability: %+v", plain)
	}
}
