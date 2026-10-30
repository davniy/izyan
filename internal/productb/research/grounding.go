package research

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/reportcheck"
)

// groundAnswer runs the deterministic report grounder over the agent's
// extracted claims: every cited location is checked against the snapshot
// tree (file exists, line range in bounds, enclosing Go declaration) and
// every mechanism atom is compared with the frozen advisory symbols.
// The result is projected into analysis.root_cause_locations,
// analysis.usage_sites and analysis.mechanism_atoms — additive fields
// that never touch the {category, reasoning} contract — and the full
// izyan-reportcheck/1 document is stored as reportcheck.json inside the
// run dossier. Grounding failures are recorded as unknowns, never fatal.
//
// The source ladder is the grounder's: structured analysis first, then
// report.md, then the raw answer. legacyMD supplies a report.md from
// outside runDir (a replayed dossier whose stored copy is the only
// surviving source); when nil, <runDir>/report.md is used if it exists.
func groundAnswer(snapshotDir, runDir string, r *Report, ares advisoryResult, legacyMD []byte) {
	mirror, err := json.Marshal(struct {
		Answer   AnswerInfo `json:"answer"`
		Analysis Analysis   `json:"analysis"`
	}{Answer: r.Answer, Analysis: r.Analysis})
	if err != nil {
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"report grounding skipped: analysis mirror did not marshal: "+err.Error())
		return
	}

	md, mdPath := legacyMD, ""
	if len(md) == 0 {
		if b, rerr := os.ReadFile(filepath.Join(runDir, "report.md")); rerr == nil && len(b) > 0 {
			md = b
		}
	}
	if len(md) > 0 {
		mdPath = "report.md"
	}

	// The scorer joins reference and grounding on the case key: the
	// controller-supplied --case-id when present, else the run id.
	caseID := r.Request.CaseID
	if caseID == "" {
		caseID = r.RunID
	}

	rep, err := reportcheck.Ground(reportcheck.Options{
		CaseID:          caseID,
		ReportJSON:      mirror,
		ReportJSONPath:  "report.json(analysis)",
		ReportMD:        md,
		ReportMDPath:    mdPath,
		RawAnswerPath:   filepath.Join(runDir, "raw_agent_output.txt"),
		SnapshotDir:     snapshotDir,
		AdvisorySymbols: advisorySymbolRefs(ares),
		AdvisoryKeys:    ares.cwes,
	})
	if err != nil {
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"report grounding failed: "+err.Error())
		return
	}

	for _, l := range rep.Claims.Locations {
		switch l.Kind {
		case reportcheck.KindUsage:
			r.Analysis.UsageSites = append(r.Analysis.UsageSites, l)
		case reportcheck.KindMetadata, reportcheck.KindImport:
			// Presence-only citations: never a locus, never a usage site.
			r.Analysis.CitationMetadata = append(r.Analysis.CitationMetadata, l)
		default:
			r.Analysis.RootCauseLocations = append(r.Analysis.RootCauseLocations, l)
		}
	}
	r.Analysis.MechanismAtoms = rep.Claims.MechanismAtoms
	r.Analysis.NegativeClaims = rep.Claims.Negative

	b, err := reportcheck.Marshal(rep)
	if err != nil {
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"reportcheck.json marshal failed: "+err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(runDir, "reportcheck.json"), b, 0o644); err != nil {
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"reportcheck.json write failed: "+err.Error())
		return
	}
	r.Artifacts["reportcheck"] = "reportcheck.json"
}

// advisorySymbolRefs collects the frozen advisory symbol references the
// grounder verifies mechanism atoms against: every comparable affected
// module's declared symbols plus per-package symbol lists, deduplicated
// and sorted so the ground input is deterministic.
func advisorySymbolRefs(ares advisoryResult) []pbdomain.SymbolRef {
	seen := map[string]bool{}
	var out []pbdomain.SymbolRef
	add := func(pkg, sym string) {
		k := pkg + "\x00" + sym
		if pkg == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, pbdomain.SymbolRef{Package: pkg, Symbol: sym})
	}
	for _, ref := range ares.affected {
		for _, s := range ref.am.AffectedSymbols {
			add(s.Package, s.Symbol)
		}
		for _, p := range ref.am.AffectedPackages {
			for _, s := range p.Symbols {
				add(p.Path, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Symbol < out[j].Symbol
	})
	return out
}
