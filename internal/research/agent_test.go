package research

import (
	"testing"
)

// agent_test covers the retained proposal surface of the one-case agent
// contract: the strict answer extraction and the fail-closed admission of
// locus proposals. The live model harness these tests used to cover is
// retired — `izyan triage` is the sole live human investigator.

func TestParseAgentAnswer(t *testing.T) {
	// fenced + whitespace tolerated
	a, err := parseAgentAnswer("```json\n{\"category\":\"vulnerable\",\"reasoning\":\"r\"}\n```")
	if err != nil || a.Category != "vulnerable" {
		t.Fatalf("fenced answer: %v %v", a, err)
	}
	// trailing prose and additional objects tolerated (E2E: model emits
	// fenced blocks then summary prose; a second fenced answer may carry
	// the real object).
	a, err = parseAgentAnswer(`{"category":"vulnerable","reasoning":"r"} tail`)
	if err != nil || a.Category != "vulnerable" {
		t.Fatalf("trailing prose: %v %v", a, err)
	}
	a, err = parseAgentAnswer(`{"category":"vulnerable","reasoning":"r"}{"x":1}`)
	if err != nil || a.Category != "vulnerable" {
		t.Fatalf("second object: %v %v", a, err)
	}
	// first object lacks category, second carries it (two fenced blocks)
	a, err = parseAgentAnswer("notes: ```\n{\"sections\":{\"mechanism\":{\"summary\":\"x\"}}}\n```\n```json\n{\"category\":\"vulnerable\",\"reasoning\":\"r\"}\n``` more prose")
	if err != nil || a.Category != "vulnerable" {
		t.Fatalf("two fenced blocks: %v %v", a, err)
	}
	// category nested under assessment
	a, err = parseAgentAnswer(`{"assessment":{"category":"uncertain","reasoning":"nested","vulnerability_mechanism":{"summary":"m"}}}`)
	if err != nil || a.Category != "uncertain" || a.Reasoning != "nested" {
		t.Fatalf("nested assessment: %v %v", a, err)
	}
	// truncated/unbalanced input -> INVALID_FORMAT material
	if _, err := parseAgentAnswer(`{"category":"vulnerable","reasoning":"r`); err == nil {
		t.Fatal("truncated object accepted")
	}
	if _, err := parseAgentAnswer("no json at all"); err == nil {
		t.Fatal("text without object accepted")
	}
	if _, err := parseAgentAnswer(`{"category":"nope","reasoning":"r"}`); err == nil {
		t.Fatal("bad category accepted")
	}
	if _, err := parseAgentAnswer(`{"category":"vulnerable"}`); err == nil {
		t.Fatal("missing reasoning accepted")
	}
}

func TestParseAgentAnswer_ImplementationLocusProposalStrict(t *testing.T) {
	// A proposal carrying an authoritative claim member is rejected while
	// the answer itself stays valid: the proposal can never act as a
	// verdict, and the extraction keeps the answer for limitation auditing.
	raw := `{"category":"uncertain","reasoning":"r","implementation_locus_proposals":[` +
		`{"id":"l1","quality":"LLM_INFERRED","module":"example.com/dep","version":"v1.0.0",` +
		`"package":"example.com/dep/pkg","file":"host_bsd.go","function":"read",` +
		`"marker":"kenv","build_expression":"freebsd","advisory_evidence_ref":"adv:A",` +
		`"advisory_quoted_span":"quote","claim":"NOT_AFFECTED"}]}`
	a, err := parseAgentAnswer(raw)
	if err != nil {
		t.Fatalf("answer rejected: %v", err)
	}
	if len(a.ImplementationLocusProposals) != 0 {
		t.Fatalf("claim-bearing proposal admitted: %+v", a.ImplementationLocusProposals)
	}
	if !limContains(a.proposalLimitations, "authoritative") {
		t.Fatalf("limitations = %v", a.proposalLimitations)
	}
	// An unknown member is equally rejected, never silently ignored.
	raw = `{"category":"uncertain","reasoning":"r","implementation_locus_proposals":[` +
		`{"id":"l1","quality":"LLM_INFERRED","module":"example.com/dep","version":"v1.0.0",` +
		`"package":"example.com/dep/pkg","file":"host_bsd.go","function":"read",` +
		`"marker":"kenv","build_expression":"freebsd","advisory_evidence_ref":"adv:A",` +
		`"advisory_quoted_span":"quote","authoritative":true}]}`
	a, err = parseAgentAnswer(raw)
	if err != nil {
		t.Fatalf("answer rejected: %v", err)
	}
	if len(a.ImplementationLocusProposals) != 0 {
		t.Fatalf("unknown-member proposal admitted: %+v", a.ImplementationLocusProposals)
	}
}
