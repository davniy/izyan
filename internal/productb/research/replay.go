package research

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/productb/vulnerability"
)

// ReplayRun re-renders a stored run dossier without any model call,
// container or network access. It reads <runDir>/report.json and reuses
// the recorded identity blocks (snapshot, advisory, prompt, run, request,
// mode) verbatim. The agent answer is
// replayed from the stored raw answer; an older dossier that lost the raw
// answer but kept report.md is still replayable — its answer block is
// carried verbatim from report.json (never re-derived, never invented) and
// grounding reads the stored report.md. Everything else is recomputed
// through the current extraction and host-fact consistency code, and a
// NEW dossier is written under the same case directory (…/runs/<new_id>/)
// marked rerender_of=<original run_id>. The original run directory is
// never modified.
//
// Inputs that must exist: report.json, the snapshot directory it names,
// the stored advisory documents it pins, and either raw_agent_output.txt
// or report.md. Missing input is a hard error — a re-render must not
// silently degrade into a different report.
func ReplayRun(_ context.Context, runDir, caseID string) (*Report, error) {
	origBytes, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return nil, fmt.Errorf("--replay-run %s: cannot read report.json: %w", runDir, err)
	}
	var orig Report
	if err := json.Unmarshal(origBytes, &orig); err != nil {
		return nil, fmt.Errorf("--replay-run %s: report.json does not parse: %w", runDir, err)
	}
	if orig.Schema != "izyan-research/2" {
		return nil, fmt.Errorf("--replay-run %s: report.json schema %q is not izyan-research/2", runDir, orig.Schema)
	}
	// The run dir convention is <out>/runs/<run_id>/; the case directory
	// root is two levels up and is where the new dossier is allocated.
	outDir := filepath.Dir(filepath.Dir(filepath.Clean(runDir)))
	if filepath.Base(filepath.Dir(filepath.Clean(runDir))) != "runs" {
		return nil, fmt.Errorf("--replay-run %s: expected a run directory <out>/runs/<run_id>", runDir)
	}
	snapDir := orig.Snapshot.Path
	if st, serr := os.Stat(snapDir); serr != nil || !st.IsDir() {
		return nil, fmt.Errorf("--replay-run %s: recorded snapshot path %s is missing or not a directory (%v) — host facts cannot be recomputed", runDir, snapDir, serr)
	}

	newID, newDir, err := allocateRunDir(outDir)
	if err != nil {
		return nil, fmt.Errorf("--replay-run %s: %w", runDir, err)
	}

	// Rebuild the advisory resolution from the dossier's stored document
	// copies so the consistency layer re-evaluates the exact bytes the
	// original run assessed. Copies land in the new dossier so it stays
	// self-contained; the recorded document paths still point at the
	// original dossier (identity blocks are verbatim).
	ares, docCopies, derr := replayAdvisory(orig, newDir)
	if derr != nil {
		return nil, fmt.Errorf("--replay-run %s: %w", runDir, derr)
	}

	r := &Report{
		Schema:      "izyan-research/2",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tool:        orig.Tool,
		Command:     orig.Command,
		Mode:        orig.Mode,
		RunID:       newID,
		RerenderOf:  orig.RunID,
		Disclaimer:  disclaimer,
		Request:     replayRequest(orig.Request, caseID),
		Snapshot:    orig.Snapshot,
		Advisory:    orig.Advisory,
		Prompt:      orig.Prompt,
		Run:         orig.Run,
		Artifacts:   map[string]string{},
		Limitations: append([]string{}, orig.Limitations...),
		Analysis: Analysis{
			// Mechanism/RootCause/claim lists/extraction states are NOT
			// copied: analyzeAnswer recomputes them from the stored raw
			// answer — deterministic, so identical text yields identical
			// extraction (drift would mean the rules changed).
			ConfirmedFacts:    append([]Fact{}, orig.Analysis.ConfirmedFacts...),
			Assumptions:       ExtractionList{State: "not_assessed", Items: []string{}},
			Unknowns:          ExtractionList{State: "not_assessed", Items: []string{}},
			AdvisoryMechanism: advisoryMechanismOf(orig.Advisory, ares),
		},
	}
	// Stored inputs the new dossier must carry. A dossier whose raw answer
	// is gone but whose report.md survived is still replayable: report.md
	// is then the claim source for grounding, while the answer block is
	// carried verbatim from report.json — never re-derived, never invented.
	rawSrc := filepath.Join(runDir, "raw_agent_output.txt")
	raw, rawErr := os.ReadFile(rawSrc)
	var legacyMD []byte
	switch {
	case rawErr == nil:
		if err := os.WriteFile(filepath.Join(newDir, "raw_agent_output.txt"), raw, 0o644); err != nil {
			return nil, fmt.Errorf("--replay-run %s: write raw_agent_output.txt: %w", runDir, err)
		}
		r.Artifacts["raw_answer"] = "raw_agent_output.txt"
	case os.IsNotExist(rawErr):
		md, mdErr := os.ReadFile(filepath.Join(runDir, "report.md"))
		if mdErr != nil {
			return nil, fmt.Errorf("--replay-run %s: no raw_agent_output.txt and no report.md — nothing to replay from: %v", runDir, mdErr)
		}
		legacyMD = md
	default:
		return nil, fmt.Errorf("--replay-run %s: cannot read raw_agent_output.txt: %w", runDir, rawErr)
	}

	// Replay provenance. The wording states which stored source the answer
	// and the claims actually came from.
	answerSource := "the agent answer is the stored raw answer text, byte-identical"
	if legacyMD != nil {
		answerSource = "the raw answer is absent, so the answer block is carried verbatim from report.json " +
			"and claims are grounded from the stored report.md"
	}
	r.Limitations = append(r.Limitations,
		fmt.Sprintf("re-render of run %s: no model call, no container, no network — "+
			"%s; "+
			"the snapshot identity is copied verbatim (the tree is not re-hashed) "+
			"while presence/version facts are recomputed from the snapshot as it exists now",
			orig.RunID, answerSource))
	nCopiedFacts := len(r.Analysis.ConfirmedFacts)
	r.Analysis.ConfirmedFacts = append(r.Analysis.ConfirmedFacts, Fact{
		Statement: fmt.Sprintf("re-rendered from run %s without a model call; %s", orig.RunID, answerSource),
		Reference: relReplay(runDir),
		Source:    "run",
	})
	r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items, ares.unknowns...)
	if legacyMD != nil {
		r.Analysis.Unknowns.Items = append(r.Analysis.Unknowns.Items,
			"raw agent answer is absent from the source dossier: analysis facets were not re-derived; "+
				"the answer block is the stored one and grounding reads the stored report.md")
	}
	for _, name := range []string{"prompt.txt", "opencode-config.json"} {
		if b, rerr := os.ReadFile(filepath.Join(runDir, name)); rerr == nil {
			if werr := os.WriteFile(filepath.Join(newDir, name), b, 0o644); werr != nil {
				return nil, fmt.Errorf("--replay-run %s: write %s: %w", runDir, name, werr)
			}
		}
	}
	if r.Prompt.Path != "" {
		if _, serr := os.Stat(filepath.Join(newDir, r.Prompt.Path)); serr == nil {
			r.Artifacts["prompt"] = r.Prompt.Path
		}
	}
	if r.Run.ConfigPath != "" {
		if _, serr := os.Stat(filepath.Join(newDir, r.Run.ConfigPath)); serr == nil {
			r.Artifacts["opencode_config"] = r.Run.ConfigPath
		}
	}
	for i, copy := range docCopies {
		rel, rerr := filepath.Rel(newDir, copy.newPath)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		if copy.doc.Role == "primary" || i == 0 {
			r.Artifacts["advisory_document"] = rel
		} else {
			r.Artifacts["advisory_document_"+sanitizeID(copy.doc.ID)] = rel
		}
	}

	// Recompute the analysis layer from the stored raw answer against the
	// recorded snapshot path, then re-run the host-fact consistency layer.
	// Without a raw answer the stored answer block is carried verbatim
	// (report.json is the only authority left) and grounding falls back to
	// the stored report.md.
	switch {
	case strings.TrimSpace(string(raw)) != "":
		analyzeAnswer(Options{SnapshotDir: snapDir}, r, newDir)
	case legacyMD != nil:
		r.Answer = orig.Answer
	default:
		r.Answer = AnswerInfo{CategoryLabel: "unavailable"}
	}
	r.ResearchState = researchStateOf(r)
	r.Consistency = assessConsistency(Options{SnapshotDir: snapDir}, r, ares)
	groundAnswer(snapDir, newDir, r, ares, legacyMD)
	bindEvidence(r)
	// Facts and the answer text were produced by the original attempt —
	// restore its stamp on the copied entries (the re-render only
	// re-derived them); consistency entries and findings keep the new id
	// since the re-render recomputed them.
	for i := range nCopiedFacts {
		r.Analysis.ConfirmedFacts[i].Attempt = orig.RunID
		r.Analysis.ConfirmedFacts[i].SnapshotHash = orig.Snapshot.ContentHash
	}
	// Answer provenance fields (source artifact, salvage flag) describe how
	// the ORIGINAL run obtained the text — replay cannot re-derive them, so
	// they are restored verbatim alongside the attempt stamp.
	r.Answer.Source = orig.Answer.Source
	r.Answer.Salvaged = orig.Answer.Salvaged
	r.Answer.AttemptID = orig.RunID

	if err := writeOutputs(r, newDir, nil); err != nil {
		return nil, fmt.Errorf("--replay-run %s: %w", runDir, err)
	}
	if err := appendRunIndex(outDir, r); err != nil {
		return nil, fmt.Errorf("--replay-run %s: update run index: %w", runDir, err)
	}
	return r, nil
}

// relReplay shortens a path for report references inside replay facts.
func relReplay(p string) string { return filepath.Base(p) }

// advisoryCopy records one advisory document copied into the new dossier.
type advisoryCopy struct {
	doc     AdvisoryDocument // the original block — verbatim, old path kept
	newPath string           // the copy inside the new run directory
}

// replayAdvisory re-reads every advisory document recorded in the
// original report, stores a byte copy in the new dossier and rebuilds the
// comparable Go affected set with the same rules resolveAdvisory applied
// (primary document first, first document wins per module, Go-ecosystem
// entries only). It never consults the network and never rewrites the
// recorded advisory identity block — the caller copies that verbatim.
func replayAdvisory(orig Report, newDir string) (advisoryResult, []advisoryCopy, error) {
	res := advisoryResult{info: orig.Advisory}
	var copies []advisoryCopy
	if len(orig.Advisory.Documents) == 0 {
		// Older dossiers may carry only the primary path.
		if orig.Advisory.Path == "" {
			return res, nil, nil
		}
		orig.Advisory.Documents = []AdvisoryDocument{{
			Role: "primary", ID: orig.Advisory.ID, SHA256: orig.Advisory.SHA256,
			Path: orig.Advisory.Path, Source: orig.Advisory.Source,
		}}
	}
	have := map[string]bool{}
	for i, doc := range orig.Advisory.Documents {
		raw, err := os.ReadFile(doc.Path)
		if err != nil {
			return res, copies, fmt.Errorf("recorded advisory document %s (%s) is missing: %w",
				doc.Path, doc.ID, err)
		}
		dest, err := storeAdvisoryDoc(newDir, filepath.Base(doc.Path), raw)
		if err != nil {
			return res, copies, fmt.Errorf("store advisory copy %s: %w", filepath.Base(doc.Path), err)
		}
		copies = append(copies, advisoryCopy{doc: doc, newPath: dest})

		v, perr := vulnerability.FileSource{Path: dest, NoAliasEnrichment: true}.Get(context.Background(), "")
		if perr != nil {
			return res, copies, fmt.Errorf("recorded advisory document %s does not parse: %w", doc.Path, perr)
		}
		if i == 0 {
			res.primaryDoc = doc
			if _, uncomparable := affectedPackageProbe(raw); uncomparable > 0 {
				res.uncomparable = uncomparable
			}
		}
		// Document order is the stored order: primary first, ecosystem
		// after — first document wins per module, exactly as
		// mergeGoAffected did for the original run.
		goNames, _ := affectedPackageProbe(raw)
		for _, am := range v.AffectedModules {
			if am.Module == "" || have[am.Module] {
				continue
			}
			if goNames != nil && !goNames[am.Module] {
				continue
			}
			have[am.Module] = true
			res.affected = append(res.affected, goAffectedRef{am: am, doc: doc})
		}
		// The mechanism reference text is the first description on file —
		// the primary document's when it carries one, else the first
		// ecosystem document that does.
		if res.details == "" && v.Description != "" {
			res.details = v.Description
			res.detailsSrc = v.ID
		}
		for _, c := range v.CWE {
			if !slices.Contains(res.cwes, c) {
				res.cwes = append(res.cwes, c)
			}
		}
	}
	return res, copies, nil
}

// replayRequest copies the original request block and applies the
// --case-id override: the stored case key survives a replay, and an
// explicit override re-stamps the case (never the run identity).
func replayRequest(orig RequestInfo, caseID string) RequestInfo {
	req := orig
	if caseID != "" {
		req.CaseID = caseID
	}
	return req
}
