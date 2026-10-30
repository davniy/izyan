// Package reportcheck grounds the root-cause locations, usage sites and
// mechanism atoms a research report claims, against the actual snapshot
// tree. It produces the izyan-reportcheck/1 document the root-cause scorer
// consumes.
//
// The grounder never rewrites a claim, the category or the answer: every
// extracted claim is reported verbatim (raw) with a deterministic
// verification status and a reason. "verified_*" means the cited artifact
// resolves in the snapshot — it never confirms what the claim says about
// it, and "unverified" never refutes it.
//
// Extraction rules (deterministic, in source-precedence order):
//   - structured: report.json analysis fields — root_cause/mechanism/
//     affected_implementations = locus context, usage_paths = usage
//     context, exploitation_conditions = unknown, reasoning = per-sentence
//     keyword classification;
//   - legacy_md: report.md sections — a "Root cause"/"Mechanism"/"Affected
//     implementations" heading = locus, a heading containing usage/call/
//     reachab/import = usage, "Agent reasoning (verbatim)" = per-sentence
//     rule, everything else = unknown;
//   - raw_answer: the raw answer text, per-sentence keyword rule.
//
// Citations are file references with an optional :line, :start-end, #Ln or
// #Ln-Lm suffix; symbol claims are Go-like dotted names — pkg.Func,
// pkg.T.M, (*T).M (normalized to T.M). A claimed symbol is attached to a
// citation when it is the only symbol in the sentence or sits within 60
// characters of the citation. Kind precedence on identical claims is
// locus > usage > unknown.
//
// Verification ladder: malformed range or a path escaping the snapshot
// root is unverified; a missing file is unverified unless its claimed
// symbol still resolves elsewhere (verified_symbol); a resolved file with
// in-bounds lines inside the claimed symbol's declaration — or inside an
// enclosing declaration when no symbol was claimed — is verified_exact; a
// resolved symbol whose cited file/lines do not match is verified_symbol;
// everything else with an existing file is verified_file.
package reportcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	pbdomain "github.com/davniy/izyan/internal/productb/domain"
)

// SchemaID is the document schema the grounder emits.
const SchemaID = "izyan-reportcheck/1"

// Location is one grounded location claim. Path is the normalized POSIX
// path relative to the snapshot root; Line/EndLine carry the cited range
// (EndLine equals Line for single-line citations, both zero for file-only
// citations). Symbol is the normalized claimed symbol — receiver forms
// (*T).M canonicalize to T.M and package qualifiers are kept
// (dep.Parse, dep.Server.Serve). EnclosingSymbol is the AST declaration
// enclosing the cited range in <import_path>.<symbol> form.
type Location struct {
	Raw             string `json:"raw"`
	Path            string `json:"path,omitempty"`
	Line            int    `json:"line,omitempty"`
	EndLine         int    `json:"end_line,omitempty"`
	Symbol          string `json:"symbol,omitempty"`
	Kind            string `json:"kind"`   // locus | usage | unknown | metadata | import
	Status          string `json:"status"` // verified_exact | verified_symbol | verified_file | unverified
	Reason          string `json:"reason"`
	Decl            *Decl  `json:"decl,omitempty"`
	EnclosingSymbol string `json:"enclosing_symbol,omitempty"`
}

// Decl is a resolved declaration span inside the snapshot.
type Decl struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
}

// MechanismAtom is one mechanism claim: an explicit Go symbol or an
// advisory key (CWE id) extracted from the report's reasoning.
type MechanismAtom struct {
	Raw    string `json:"raw"`
	Symbol string `json:"symbol,omitempty"`
	Key    string `json:"key,omitempty"`
	Status string `json:"status"` // verified | unverified
}

// NegativeClaim is one path statement extracted from the report's
// reasoning. Polarity is absence | presence; scope is first_party
// (default), module (module/package/dependency wording) or symbol (a
// qualified Go symbol is named). Raw is the verbatim sentence; path is the
// first cited path and Symbol the normalized first qualified symbol, when
// present. The claim is context for negative metrics — it is never
// promoted to a verdict.
type NegativeClaim struct {
	Raw      string `json:"raw"`
	Polarity string `json:"polarity"` // absence | presence
	Scope    string `json:"scope"`    // first_party | module | symbol
	Path     string `json:"path,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
}

// ClaimSet carries every grounded claim.
type ClaimSet struct {
	Locations      []Location      `json:"locations"`
	MechanismAtoms []MechanismAtom `json:"mechanism_atoms"`
	Negative       []NegativeClaim `json:"negative"`
}

// ParseInfo records which artifact fed extraction and what went wrong.
type ParseInfo struct {
	Source string   `json:"source"` // structured | legacy_md | raw_answer | none
	Errors []string `json:"errors"`
}

// ReportRef identifies the artifact the claims were grounded from, plus
// the official answer context carried from the structured report:
// Category is report.json answer.category verbatim (empty when absent) and
// ReasoningSHA256 hashes the answer reasoning text.
type ReportRef struct {
	Path            string `json:"path,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	Category        string `json:"category,omitempty"`
	ReasoningSHA256 string `json:"reasoning_sha256,omitempty"`
}

// Report is the izyan-reportcheck/1 document.
type Report struct {
	Schema string    `json:"schema"`
	CaseID string    `json:"case_id"`
	Report ReportRef `json:"report"`
	Parse  ParseInfo `json:"parse"`
	Claims ClaimSet  `json:"claims"`
}

// Options describes one grounding run. Content is taken from the byte
// fields when present, else read from the matching path — both empty means
// the artifact is absent. SnapshotDir is the root every cited path
// resolves against; an empty SnapshotDir still extracts claims but leaves
// every status unverified.
type Options struct {
	// CaseID is the controller-side case key recorded in the document
	// (usually the VEX-Bench task id); empty is allowed, callers then keep
	// their own fallback.
	CaseID         string
	ReportJSON     []byte
	ReportJSONPath string
	ReportMD       []byte
	ReportMDPath   string
	RawAnswer      []byte
	RawAnswerPath  string
	SnapshotDir    string
	// AdvisorySymbols are the frozen advisory-side symbol references a
	// mechanism atom can be verified against (affected symbols plus
	// per-package symbol lists). An empty or "*" Symbol acts as a
	// package-level wildcard.
	AdvisorySymbols []pbdomain.SymbolRef
	// AdvisoryKeys are frozen advisory keys (CWE ids).
	AdvisoryKeys []string
}

// Ground extracts the report's location and mechanism claims and verifies
// them against the snapshot. Errors are only hard I/O failures on the
// snapshot root itself; missing or unparsable report artifacts are
// recorded in parse.errors and degrade the parse source, never abort.
func Ground(o Options) (*Report, error) {
	rep := &Report{
		Schema: SchemaID,
		CaseID: o.CaseID,
		Parse:  ParseInfo{Source: "none", Errors: []string{}},
		Claims: ClaimSet{Locations: []Location{}, MechanismAtoms: []MechanismAtom{}},
	}

	content, err := loadArtifacts(o, rep)
	if err != nil {
		return nil, err
	}

	var units []extractUnit
	var mechText string
	switch {
	case len(content.structured.rootCause) != 0 || content.structured.hasClaims:
		rep.Parse.Source = "structured"
		units = content.structured.units()
		mechText = content.structured.reasoning
		rep.Report = ReportRef{Path: content.jsonPath, SHA256: sha256Hex(content.jsonBytes)}
	case len(content.md) > 0:
		rep.Parse.Source = "legacy_md"
		units = parseMarkdown(content.md)
		mechText = mdSection(content.md, "agent reasoning")
		rep.Report = ReportRef{Path: content.mdPath, SHA256: sha256Hex(content.md)}
	case len(content.raw) > 0:
		rep.Parse.Source = "raw_answer"
		units = parseRawText(content.raw)
		mechText = rawReasoning(content.raw)
		rep.Report = ReportRef{Path: content.rawPath, SHA256: sha256Hex(content.raw)}
	default:
		rep.Parse.Errors = append(rep.Parse.Errors,
			"no report content: report.json, report.md and raw answer are all absent or empty")
		return rep, nil
	}

	// Report context for negative metrics: the official answer category
	// verbatim and a digest of its reasoning. Carried from the structured
	// report whenever it was supplied, regardless of which source fed
	// extraction.
	if content.jsonParsed {
		rep.Report.Category = content.structured.answerCategory
		if content.structured.answerReasoning != "" {
			rep.Report.ReasoningSHA256 = sha256Hex([]byte(content.structured.answerReasoning))
		}
	}

	claims := extractLocations(units)
	atoms := extractMechanism(mechText, o.AdvisorySymbols, o.AdvisoryKeys)
	negative := extractNegative(mechText)
	if atoms == nil {
		atoms = []MechanismAtom{}
	}

	var idx *snapshotIndex
	if o.SnapshotDir != "" {
		var serr error
		idx, serr = buildIndex(o.SnapshotDir)
		if serr != nil {
			rep.Parse.Errors = append(rep.Parse.Errors, "snapshot index: "+serr.Error())
		}
	} else {
		rep.Parse.Errors = append(rep.Parse.Errors,
			"snapshot unavailable: claims extracted but not verified")
	}

	for _, c := range claims {
		rep.Claims.Locations = append(rep.Claims.Locations, verify(idx, c))
	}
	rep.Claims.MechanismAtoms = atoms
	rep.Claims.Negative = negative
	sortLocations(rep.Claims.Locations)
	return rep, nil
}

// Marshal renders the report as deterministic JSON (struct-order keys,
// pre-sorted claim slices, trailing newline).
func Marshal(r *Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// artifactContent carries whichever report artifacts were supplied.
type artifactContent struct {
	jsonBytes  []byte
	jsonPath   string
	md         []byte
	mdPath     string
	raw        []byte
	rawPath    string
	structured structuredContent
	jsonParsed bool
}

// loadArtifacts resolves bytes-vs-path for every artifact and parses the
// structured mirror when present.
func loadArtifacts(o Options, rep *Report) (artifactContent, error) {
	var c artifactContent
	load := func(have []byte, path string) ([]byte, bool) {
		if len(have) > 0 {
			return have, true
		}
		if path == "" {
			return nil, false
		}
		b, err := os.ReadFile(path)
		if err != nil {
			rep.Parse.Errors = append(rep.Parse.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil, false
		}
		return b, len(b) > 0
	}
	if b, ok := load(o.ReportJSON, o.ReportJSONPath); ok {
		c.jsonBytes, c.jsonPath = b, orPath(o.ReportJSONPath, "report.json")
		if s, err := parseStructured(b); err != nil {
			rep.Parse.Errors = append(rep.Parse.Errors, "report.json: "+err.Error())
		} else {
			c.structured = s
			c.jsonParsed = true
		}
	}
	if b, ok := load(o.ReportMD, o.ReportMDPath); ok {
		c.md, c.mdPath = b, orPath(o.ReportMDPath, "report.md")
	}
	if b, ok := load(o.RawAnswer, o.RawAnswerPath); ok {
		c.raw, c.rawPath = b, orPath(o.RawAnswerPath, "raw_agent_output.txt")
	}
	return c, nil
}

// rawReasoning unwraps a raw answer that is the official
// {category, reasoning} JSON object, so path statements are read from the
// reasoning text rather than from JSON scaffolding. Plain prose passes
// through verbatim.
func rawReasoning(raw []byte) string {
	var doc struct {
		Reasoning string `json:"reasoning"`
	}
	if json.Unmarshal(raw, &doc) == nil && doc.Reasoning != "" {
		return doc.Reasoning
	}
	return string(raw)
}

func orPath(p, def string) string {
	if p == "" {
		return def
	}
	return p
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sortLocations orders claims deterministically: path, range, symbol.
func sortLocations(locs []Location) {
	sort.Slice(locs, func(i, j int) bool {
		a, b := locs[i], locs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.EndLine != b.EndLine {
			return a.EndLine < b.EndLine
		}
		return a.Symbol < b.Symbol
	})
}
