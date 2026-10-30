package verify

import (
	"encoding/json"
	"sort"

	"github.com/davniy/izyan/internal/productb/claimshape"
)

// Report is the deterministic evaluation output for one run: the contract
// observations bound to each claim, the claim outcomes, the entailment
// graph built over the admitted evidence (with the compiled disposition)
// and a canonical content hash for replay comparison. The decision is a
// deterministic compile of the graph — advisory for audit/replay, never
// applied to production by this layer.
type Report struct {
	SchemaVersion string      `json:"schema_version"`
	RunID         string      `json:"run_id,omitempty"`
	FindingID     string      `json:"finding_id,omitempty"`
	Claims        []ClaimEval `json:"claims"`
	Edges         []Edge      `json:"edges,omitempty"`
	Graph         *Graph      `json:"graph,omitempty"`
	// Challenges is the audit ledger of the reviewer channel: every
	// proposal, the claim it minted and the outcome the deterministic
	// cycle computed — the channel itself wrote none of these.
	Challenges []ChallengeEval `json:"challenges,omitempty"`
	// SemanticHash pins the claim-level surface (LLM-authored claims
	// and their outcomes). It may drift across retries while the proof
	// surface agrees — the semantic-instability case of plan §6.5.
	SemanticHash string `json:"semantic_hash,omitempty"`
	// Decisive is the proof/decision surface stability compares: the
	// conditions, the falsifiers that falsified them, the rule and
	// decision outcomes, the certificate statuses and the conflict
	// state. Reduction is permitted only when this surface is stable
	// across re-derivations.
	Decisive DecisiveSurface `json:"decisive,omitempty"`
	Hash     string          `json:"hash"`
}

// Decision returns the compiled disposition, or a zero UNCHANGED when no
// graph was built.
func (r *Report) Decision() Decision {
	if r.Graph != nil {
		return r.Graph.Decision
	}
	return Decision{Disposition: "UNCHANGED"}
}

// computeHash renders the canonical report hash — the replay stability
// token (plan §6.5: graph hash stays canonical across attempts).
func (r *Report) computeHash() string {
	tmp := *r
	tmp.Hash = ""
	return fullHash(canonicalJSON(reportCanon(tmp)))
}

// reportCanon projects the report into the canonical hashed structure.
func reportCanon(r Report) map[string]any {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// Marshal renders the report deterministically.
func (r Report) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ClaimOutcomeOf returns one claim's evaluation, or nil.
func (r *Report) ClaimOutcomeOf(id string) *ClaimEval {
	for i := range r.Claims {
		if r.Claims[i].ClaimID == id {
			return &r.Claims[i]
		}
	}
	return nil
}

// OutcomeHistogram counts claims per outcome — the report summary.
func (r *Report) OutcomeHistogram() map[string]int {
	out := map[string]int{}
	for _, c := range r.Claims {
		out[string(c.Outcome)]++
	}
	return out
}

// ShapeMatrix counts claims per shape × outcome — the Task-2 report data.
func (r *Report) ShapeMatrix() map[string]map[string]int {
	out := map[string]map[string]int{}
	for _, c := range r.Claims {
		row := out[string(c.Shape)]
		if row == nil {
			row = map[string]int{}
			out[string(c.Shape)] = row
		}
		row[string(c.Outcome)]++
	}
	return out
}

// SortedShapes lists the shape keys for stable report rendering.
func SortedShapes(m map[string]map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ShapeCoverage maps every canonical shape to the capabilities that can
// serve it and whether a deterministic binding exists — the report's
// capability-coverage table (shapes without implemented capability are
// the honest UNSUPPORTED remainder).
type ShapeCoverage struct {
	Shape        claimshape.Shape `json:"shape"`
	Capabilities []string         `json:"capabilities,omitempty"`
	Implemented  []string         `json:"implemented,omitempty"`
	Missing      []string         `json:"missing,omitempty"`
}

// CoverageTable computes shape → capability coverage for the registry.
func CoverageTable() []ShapeCoverage {
	var out []ShapeCoverage
	for _, s := range claimshape.CanonicalShapes() {
		row := ShapeCoverage{Shape: s}
		for _, id := range claimshape.RequiredCapabilities(s) {
			row.Capabilities = append(row.Capabilities, id)
			if c := CapabilityByID(id); c != nil && c.Implemented {
				row.Implemented = append(row.Implemented, id)
			} else {
				row.Missing = append(row.Missing, id)
			}
		}
		sort.Strings(row.Capabilities)
		sort.Strings(row.Implemented)
		sort.Strings(row.Missing)
		out = append(out, row)
	}
	return out
}
