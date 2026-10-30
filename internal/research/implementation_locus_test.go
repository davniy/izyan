package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

func implementationProposalMap() map[string]any {
	return map[string]any{
		"id":                    "locus-1",
		"quality":               string(domain.QualityLLMInferred),
		"module":                "golang.org/x/net",
		"version":               "v0.36.0",
		"package":               "golang.org/x/net/http2",
		"file":                  "frame.go",
		"function":              "ServeConn",
		"marker":                "RST_STREAM",
		"build_expression":      "linux",
		"goos":                  []any{"linux", "freebsd"},
		"goarch":                []any{"amd64"},
		"advisory_evidence_ref": "adv:GO-TEST-0001",
		"advisory_quoted_span":  "golang.org/x/net/http2 mishandles rapid RST_STREAM frames",
	}
}

func answerWithProposals(t *testing.T, proposals any) *agentAnswer {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"category":                       "uncertain",
		"reasoning":                      "test answer",
		"implementation_locus_proposals": proposals,
	})
	if err != nil {
		t.Fatal(err)
	}
	ans, err := parseAgentAnswer(string(b))
	if err != nil {
		t.Fatalf("answer rejected: %v", err)
	}
	return ans
}

func TestParseImplementationLocusProposals(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ans := answerWithProposals(t, []any{implementationProposalMap()})
		if len(ans.ImplementationLocusProposals) != 1 {
			t.Fatalf("proposals = %+v; limitations = %v", ans.ImplementationLocusProposals, ans.proposalLimitations)
		}
		if len(ans.proposalLimitations) != 0 {
			t.Fatalf("limitations = %v", ans.proposalLimitations)
		}
	})
	t.Run("null member", func(t *testing.T) {
		ans := answerWithProposals(t, nil)
		if len(ans.ImplementationLocusProposals) != 0 || len(ans.proposalLimitations) != 0 {
			t.Fatalf("proposals = %+v; limitations = %v", ans.ImplementationLocusProposals, ans.proposalLimitations)
		}
	})
	t.Run("forbidden verdict field", func(t *testing.T) {
		p := implementationProposalMap()
		p["verdict"] = "NOT_AFFECTED"
		ans := answerWithProposals(t, []any{p})
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("proposal with a verdict field admitted: %+v", ans.ImplementationLocusProposals)
		}
		if !limContains(ans.proposalLimitations, "verdict") {
			t.Fatalf("limitations = %v", ans.proposalLimitations)
		}
	})
	t.Run("forbidden negative verification field", func(t *testing.T) {
		p := implementationProposalMap()
		p["negative_verification"] = map[string]any{"status": "VERIFIED"}
		ans := answerWithProposals(t, []any{p})
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("proposal with negative_verification admitted: %+v", ans.ImplementationLocusProposals)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		p := implementationProposalMap()
		p["authoritative"] = true
		ans := answerWithProposals(t, []any{p})
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("proposal with an unknown member admitted: %+v", ans.ImplementationLocusProposals)
		}
		if !limContains(ans.proposalLimitations, "not a valid typed proposal") {
			t.Fatalf("limitations = %v", ans.proposalLimitations)
		}
	})
	t.Run("deterministic quality", func(t *testing.T) {
		p := implementationProposalMap()
		p["quality"] = string(domain.QualityDeterministic)
		ans := answerWithProposals(t, []any{p})
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("deterministic-quality proposal admitted: %+v", ans.ImplementationLocusProposals)
		}
	})
	t.Run("missing quality", func(t *testing.T) {
		p := implementationProposalMap()
		delete(p, "quality")
		ans := answerWithProposals(t, []any{p})
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("quality-less proposal admitted: %+v", ans.ImplementationLocusProposals)
		}
	})
	t.Run("duplicate ids", func(t *testing.T) {
		ans := answerWithProposals(t, []any{implementationProposalMap(), implementationProposalMap()})
		if len(ans.ImplementationLocusProposals) != 1 {
			t.Fatalf("proposals = %+v", ans.ImplementationLocusProposals)
		}
		if !limContains(ans.proposalLimitations, "duplicates proposal id") {
			t.Fatalf("limitations = %v", ans.proposalLimitations)
		}
	})
	t.Run("bound exceeded rejects the list", func(t *testing.T) {
		var list []any
		for i := 0; i <= maxImplementationLocusProposals; i++ {
			p := implementationProposalMap()
			p["id"] = "locus-" + string(rune('a'+i))
			list = append(list, p)
		}
		ans := answerWithProposals(t, list)
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("over-bound list partly admitted: %+v", ans.ImplementationLocusProposals)
		}
		if !limContains(ans.proposalLimitations, "bound") {
			t.Fatalf("limitations = %v", ans.proposalLimitations)
		}
	})
	t.Run("non-array member", func(t *testing.T) {
		ans := answerWithProposals(t, "not an array")
		if len(ans.ImplementationLocusProposals) != 0 {
			t.Fatalf("proposals = %+v", ans.ImplementationLocusProposals)
		}
		if !limContains(ans.proposalLimitations, "not a JSON array") {
			t.Fatalf("limitations = %v", ans.proposalLimitations)
		}
	})
}

func limContains(lims []string, want string) bool {
	for _, lim := range lims {
		if strings.Contains(lim, want) {
			return true
		}
	}
	return false
}

// locusLane mirrors fakeLane but carries real frozen advisory bytes whose
// recorded description the proposal quotes.
func locusLane(t *testing.T) *LaneResult {
	t.Helper()
	lane := fakeLane(t)
	lane.Advisory.Vuln.Summary = "test advisory"
	lane.Advisory.Vuln.Description = "golang.org/x/net/http2 mishandles rapid RST_STREAM frames"
	lane.Advisory.RawBytes = []byte(`{"id":"GO-TEST-0001","summary":"test advisory","details":"golang.org/x/net/http2 mishandles rapid RST_STREAM frames"}`)
	sum := sha256.Sum256(lane.Advisory.RawBytes)
	lane.Advisory.Input.RawSHA256 = hex.EncodeToString(sum[:])
	lane.Advisory.Input.CanonicalSHA256 = hex.EncodeToString(sum[:])
	return lane
}

func locusTurn(t *testing.T, p map[string]any) *AgentTurn {
	t.Helper()
	return turnFor(t, map[string]any{
		"category":                       "uncertain",
		"reasoning":                      "test reasoning",
		"implementation_locus_proposals": []any{p},
	})
}

func TestAssemble_ImplementationLocusProposal(t *testing.T) {
	lane := locusLane(t)
	turn := locusTurn(t, implementationProposalMap())
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-locus",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if len(r.ImplementationLocusProposals) != 1 {
		t.Fatalf("proposals = %+v; limitations = %v", r.ImplementationLocusProposals, r.EvidenceQuality.Limitations)
	}
	p := r.ImplementationLocusProposals[0]
	if p.Quality != domain.QualityLLMInferred {
		t.Fatalf("quality = %q", p.Quality)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("report with an admitted proposal invalid:\n%v", err)
	}
}

func TestAssemble_ImplementationLocusProposalRejected(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p map[string]any)
	}{
		{"paraphrased quote", func(p map[string]any) {
			p["advisory_quoted_span"] = "the advisory describes a frame-handling defect"
		}},
		{"wrong advisory reference", func(p map[string]any) {
			p["advisory_evidence_ref"] = "adv:GO-OTHER-0001"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := implementationProposalMap()
			tc.mutate(p)
			r := Assemble(AssembleInput{
				Lane: locusLane(t), Turn: locusTurn(t, p), RunID: "research-locus-rejected",
				StartedAt: time.Now(), FinishedAt: time.Now(),
			})
			if len(r.ImplementationLocusProposals) != 0 {
				t.Fatalf("rejected proposal projected: %+v", r.ImplementationLocusProposals)
			}
			if !limContains(r.EvidenceQuality.Limitations, "implementation locus proposal") {
				t.Fatalf("rejection not recorded: %v", r.EvidenceQuality.Limitations)
			}
			if err := Validate(r, ""); err != nil {
				t.Fatalf("report invalid after rejection:\n%v", err)
			}
		})
	}
}

func TestRender_ImplementationLocusProposal(t *testing.T) {
	lane := locusLane(t)
	turn := locusTurn(t, implementationProposalMap())
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-locus-render",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	text := string(md)
	if !strings.Contains(text, "Implementation-locus proposals (LLM-inferred, non-authoritative)") {
		t.Fatalf("proposal section missing:\n%s", text)
	}
	if !strings.Contains(text, "locus-1") || !strings.Contains(text, "RST_STREAM") {
		t.Fatalf("proposal detail missing:\n%s", text)
	}
	empty, err := RenderMarkdown(validReport(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "Implementation-locus proposals") {
		t.Fatal("proposal section rendered without a proposal")
	}
}

func TestValidate_ImplementationLocusProposal(t *testing.T) {
	base := func(t *testing.T) *Report {
		r := validReport(t)
		r.Vulnerability.Summary = "test advisory"
		r.Vulnerability.Description = "golang.org/x/net/http2 mishandles rapid RST_STREAM frames"
		r.ImplementationLocusProposals = []domain.ImplementationLocusProposal{{
			ID:                  "locus-1",
			Quality:             domain.QualityLLMInferred,
			Module:              "golang.org/x/net",
			Version:             "v0.36.0",
			Package:             "golang.org/x/net/http2",
			File:                "frame.go",
			Function:            "ServeConn",
			Marker:              "RST_STREAM",
			BuildExpression:     "linux",
			AdvisoryEvidenceRef: "adv:GO-TEST-0001",
			AdvisoryQuotedSpan:  "mishandles rapid RST_STREAM frames",
		}}
		return r
	}
	if err := Validate(base(t), ""); err != nil {
		t.Fatalf("valid proposal report rejected:\n%v", err)
	}

	r := base(t)
	r.ImplementationLocusProposals[0].AdvisoryQuotedSpan = "a paraphrase"
	if err := Validate(r, ""); err == nil {
		t.Fatal("paraphrased quote accepted")
	}

	r = base(t)
	r.ImplementationLocusProposals[0].AdvisoryEvidenceRef = "adv:GO-OTHER"
	if err := Validate(r, ""); err == nil {
		t.Fatal("wrong advisory reference accepted")
	}

	r = base(t)
	r.ImplementationLocusProposals = append(r.ImplementationLocusProposals, r.ImplementationLocusProposals[0])
	if err := Validate(r, ""); err == nil {
		t.Fatal("duplicate proposal id accepted")
	}

	r = base(t)
	r.ImplementationLocusProposals[0].Quality = domain.QualityDeterministic
	if err := Validate(r, ""); err == nil {
		t.Fatal("deterministic-quality proposal accepted")
	}
}

func TestAgentTurn_ImplementationLocusProposalsAccessor(t *testing.T) {
	var nilTurn *AgentTurn
	if got := nilTurn.ImplementationLocusProposals(); got != nil {
		t.Fatalf("nil turn proposals = %+v", got)
	}
	turn := locusTurn(t, implementationProposalMap())
	got := turn.ImplementationLocusProposals()
	if len(got) != 1 {
		t.Fatalf("proposals = %+v", got)
	}
	got[0].ID = "mutated"
	if turn.ImplementationLocusProposals()[0].ID != "locus-1" {
		t.Fatal("accessor returned the internal slice")
	}
}
