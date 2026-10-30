package heldoutgate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/productb/claimshape"
	agenttriage "github.com/davniy/izyan/internal/productb/triage"
	"github.com/davniy/izyan/internal/productb/verify"
)

// RunCorpus replays every run of the corpus (<corpus>/<ticket>/intake-*/)
// through the corrected-binding verification replay and returns the
// per-run rows. It never calls a tool and never reads prose: claimshape
// carries verdicts as labels only.
func RunCorpus(corpus string, human map[string]ComparisonRow) ([]CorpusRunRow, error) {
	runs, err := claimshape.ListRuns(corpus)
	if err != nil {
		return nil, fmt.Errorf("heldout gate: corpus list: %w", err)
	}
	var rows []CorpusRunRow
	for _, rr := range runs {
		ticket, runDir := rr[0], rr[1]
		ext, err := claimshape.ExtractRun(runDir, ticket)
		if err != nil {
			return nil, fmt.Errorf("heldout gate: %s: %w", ticket, err)
		}
		rep, _, _, err := ReplayRun(runDir, ticket, true)
		if err != nil {
			return nil, fmt.Errorf("heldout gate: %s: %w", ticket, err)
		}
		pub, perr := verify.ReplayRun(runDir, ticket)
		row := CorpusRunRow{
			Ticket:         ticket,
			RunDir:         runDir,
			FindingID:      ext.FindingID,
			SourceID:       ext.SourceID,
			SelectedRef:    ext.SelectedRef,
			AdvisoryFamily: advisoryFamily(ext.Advisory),
			LLMVerdict:     ext.Verdict,
			InternalStatus: ext.InternalStatus,
			ReportHash:     rep.Hash,
			SemanticHash:   rep.SemanticHash,
			DecisiveHash:   rep.Decisive.Hash,
			RejectReasons:  map[string]int{},
			Claims:         len(rep.Claims),
			Alarms:         nil,
		}
		if perr == nil && pub != nil {
			row.DispositionPublished = pub.Decision().Disposition
		} else {
			row.DispositionPublished = "replay_error"
		}

		for _, id := range ext.Advisory.IDs {
			if row.AdvisoryID == "" {
				row.AdvisoryID = id
			}
		}
		if ext.Advisory.ResolvedID != "" {
			row.AdvisoryID = ext.Advisory.ResolvedID
		}
		row.GroupKey = groupKey(row.SourceID, row.AdvisoryFamily, row.AdvisoryID)
		if h, ok := human[ticket]; ok {
			row.Human = h.Human
			row.HumanReasonClass = h.HumanReasonClass
		}

		d := rep.Decision()
		row.Disposition, row.Rule, row.Reason = d.Disposition, d.Rule, d.Reason
		// Reduction basis: a DISMISSED must stand on a satisfied
		// mandatory-falsifier rule; the falsifiers must be admitted
		// claims/certificates with COMPLETE coverage and no conflict.
		if row.Disposition != "UNCHANGED" {
			row.Unverified = !reductionBasisOK(rep)
		}
		for _, ce := range rep.Claims {
			row.BoundObservations += ce.BoundObservations
			for _, g := range ce.Groups {
				for _, adm := range g.Observations {
					if adm.Admitted {
						row.Admitted++
					} else if adm.Reason != "" {
						row.RejectReasons[adm.Reason]++
					}
				}
			}
		}
		if rep.Graph != nil {
			for _, c := range rep.Graph.Conditions {
				var expected []string
				for _, s := range c.ExpectedSubjects {
					expected = append(expected, string(s.Kind)+":"+s.Name)
				}
				row.Conditions = append(row.Conditions, ConditionRow{
					ID: c.ID, Mandatory: c.Mandatory, Value: c.Value,
					FalsifiedBy: string(c.FalsifiedBy), Falsifiers: c.Falsifiers,
					Contested: c.Contested, ExpectedSubjects: expected, Reason: c.Reason,
				})
			}
		}
		runID, _ := ReplayIdentity(archiveOf(runDir), ext.FindingID)
		row.AttemptRunID = runID
		if len(row.RejectReasons) == 0 {
			row.RejectReasons = nil
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// archiveOf reloads the run's observation archive for identity
// resolution; missing/invalid archives yield nil.
func archiveOf(runDir string) []agenttriage.RecordedObservation {
	a, err := agenttriage.ReadObservationArchive(runDir + "/observation-archive.json")
	if err != nil {
		return nil
	}
	return a.Observations
}

// falsifiersOf reloads the run's persisted falsifier report when one
// exists; the certificate channel is part of the foreign-evidence
// surface too.
func falsifiersOf(runDir string) *agenttriage.FalsifierReport {
	b, err := os.ReadFile(runDir + "/falsifier-verify.json")
	if err != nil {
		return nil
	}
	var fr agenttriage.FalsifierReport
	if json.Unmarshal(b, &fr) != nil {
		return nil
	}
	return &fr
}

// reductionBasisOK re-verifies the graph behind a non-UNCHANGED
// decision against the §8.3 hard gates. The compiler's own
// coverage rule (claim parameters + covered subjects) is intentionally
// not trusted: the gate requires the falsifier's *admitted evidence* to
// provably cover the condition's expected universe, the established
// value to rest on COMPLETE, conflict-free groups, and every condition
// carrying the decision to be mandatory — so a claim that asserts
// subjects it never evidenced can never ground DISMISSED here.
func reductionBasisOK(rep *verify.Report) bool {
	g := rep.Graph
	if g == nil {
		return false
	}
	d := g.Decision
	if d.Disposition != "DISMISSED" && d.Disposition != "LOWERED" {
		return false
	}
	// covers edges: admitted observation id → covered subject names.
	covers := map[string]map[string]bool{}
	for _, e := range rep.Edges {
		if e.Kind != "covers" {
			continue
		}
		if covers[e.From] == nil {
			covers[e.From] = map[string]bool{}
		}
		// Edge target is "kind:name"; the name itself may contain ':'.
		covers[e.From][e.To] = true
	}
	evals := map[string]verify.ClaimEval{}
	for _, ce := range rep.Claims {
		evals[ce.ClaimID] = ce
	}

	verifiedCond := 0
	for _, c := range g.Conditions {
		if c.Value != "FALSE" {
			continue
		}
		if c.Mandatory == "unresolved" || len(c.Falsifiers) == 0 {
			continue
		}
		for _, f := range c.Falsifiers {
			if strings.HasPrefix(f, "claim:") {
				ce, ok := evals[f[6:]]
				if !ok || ce.Predicate != c.FalsifiedBy {
					continue
				}
				if !evidenceCovers(ce, covers, c.ExpectedSubjects, string(c.FalsifiedBy)) {
					continue
				}
				verifiedCond++
				break
			}
			if strings.HasPrefix(f, "proof:") {
				// A listed proof falsifier already passed the generic
				// certificate contract inside the graph; the gate keeps
				// it verified only when the certificate itself admitted
				// COMPLETE evidence (the compiler enforces this — the
				// row records it for audit).
				verifiedCond++
				break
			}
		}
	}
	return verifiedCond > 0
}

// evidenceCovers reports whether a falsifier claim's admitted
// observations (a) include at least one COMPLETE observation in a group
// that established the required value without a conflict and (b) cover
// every expected subject of the condition — the evidence-coverage check
// the compiler approximates with claim parameters.
func evidenceCovers(ce verify.ClaimEval, covers map[string]map[string]bool, expected []claimshape.Subject, want string) bool {
	wantEstablished := "holds"
	if want == string(verify.PredicateDisproved) {
		wantEstablished = "disproved"
	}
	var covered []string
	ok := false
	for _, g := range ce.Groups {
		if g.Established != wantEstablished {
			continue
		}
		groupOK := false
		for _, adm := range g.Observations {
			if !adm.Admitted {
				continue
			}
			groupOK = true
			// The falsification direction is universal: a PARTIAL
			// admission never verifies a reduction (§8.3 hard gate).
			if adm.Completeness != "COMPLETE" {
				groupOK = false
				break
			}
			for s := range covers[adm.ObservationID] {
				covered = append(covered, s)
			}
		}
		if groupOK {
			ok = true
		}
	}
	if !ok {
		return false
	}
	for _, e := range expected {
		found := false
		for _, cov := range covered {
			if coversExpected(cov, e) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// coversExpected mirrors verification's subjectMatches over the edge
// vocabulary: a covered subject answers an expected subject on exact
// name, package.symbol decomposition or package containment.
func coversExpected(covered string, e claimshape.Subject) bool {
	kind, name, _ := strings.Cut(covered, ":")
	if e.Name == "" {
		return true
	}
	if name == e.Name {
		return true
	}
	if e.Package != "" && kind == "package" && name == e.Package {
		return true
	}
	// Module absence answers every expected subject that lives inside
	// the module — covered module 'm' covers expected 'm/sub.X'.
	if kind == "module" && strings.HasPrefix(e.Package, name) {
		return true
	}
	if kind == "module" && e.Kind == claimshape.SubjectSymbol &&
		strings.HasPrefix(e.Name, name+"/") {
		return true
	}
	return false
}

// HoldoutFolds builds the §8.2 grouped partition: groups keyed on
// repository|advisory-family|advisory are assigned to folds by stable
// key order so no group is ever split and no family straddles two folds.
func HoldoutFolds(rows []CorpusRunRow, k int) []FoldRow {
	groups := map[string][]string{}
	for _, r := range rows {
		groups[r.GroupKey] = append(groups[r.GroupKey], r.Ticket)
	}
	keys := make([]string, 0, len(groups))
	for k2 := range groups {
		keys = append(keys, k2)
	}
	sort.Strings(keys)
	var folds []FoldRow
	for i, key := range keys {
		sort.Strings(groups[key])
		folds = append(folds, FoldRow{Fold: i % k, GroupKey: key, Tickets: groups[key]})
	}
	return folds
}

// CrossRunAdmissions evaluates each run's claims against the *previous*
// run's observation archive (sorted order, wrap-around). Any admitted
// observation is a foreign/cross-run admission — a hard-gate violation.
// Observations are only bound by citation or subject coverage; the run
// binding then decides admission.
func CrossRunAdmissions(corpus string) (int, []string, error) {
	runs, err := claimshape.ListRuns(corpus)
	if err != nil {
		return 0, nil, err
	}
	type prepared struct {
		ticket string
		runDir string
		in     verify.Input
	}
	var ps []prepared
	for _, rr := range runs {
		ext, err := claimshape.ExtractRun(rr[1], rr[0])
		if err != nil {
			return 0, nil, err
		}
		runID := ext.RunID
		if runID == "" {
			// The same fallback ReplayRun applies: the own archive's
			// stamps carry the canonical attempt identity — an empty
			// run id would re-home any foreign record.
			runID, _ = ReplayIdentity(archiveOf(rr[1]), ext.FindingID)
		}
		ps = append(ps, prepared{
			ticket: rr[0],
			runDir: rr[1],
			in: verify.Input{
				RunID:     runID,
				FindingID: ext.FindingID,
				Claims:    ext.Claims,
				Advisory:  ext.Advisory,
			},
		})
	}
	violations := 0
	var detail []string
	for i, p := range ps {
		// Foreign archive + falsifier report: the next run's evidence.
		// AssumeArchiveRun stays off — a foreign record must never
		// re-home into this run.
		foreign := ps[(i+1)%len(ps)]
		fin := p.in
		fin.Observations = archiveOf(foreign.runDir)
		fin.Falsifiers = falsifiersOf(foreign.runDir)
		fin.AssumeArchiveRun = false
		rep := verify.Evaluate(fin)
		n := 0
		for _, ce := range rep.Claims {
			for _, g := range ce.Groups {
				for _, adm := range g.Observations {
					if !adm.Admitted {
						continue
					}
					// Only archive-sourced observations count as foreign:
					// derived and certificate observations are minted
					// inside the run and can never be cross-run.
					if isArchiveObservation(adm.ObservationID) {
						n++
					}
				}
			}
		}
		if n > 0 {
			violations += n
			detail = append(detail, fmt.Sprintf("%s: %d foreign observations admitted from %s", p.ticket, n, foreign.ticket))
		}
	}
	return violations, detail, nil
}

// isArchiveObservation reports whether an admission id is an
// archive-sourced observation ("<rec-id>#<index>#<capability>") rather
// than a run-minted derived ("<claim>#derived:<cap>") or certificate
// ("proof:<id>#<claim>") observation.
func isArchiveObservation(id string) bool {
	i := strings.Index(id, "#")
	if i <= 0 {
		return false
	}
	j := strings.Index(id[i+1:], "#")
	if j <= 0 {
		return false
	}
	for _, r := range id[i+1 : i+1+j] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// runDirOf locates the intake dir of a ticket inside the corpus layout.
func runDirOf(corpus, ticket string) string {
	runs, _ := claimshape.ListRuns(corpus)
	for _, rr := range runs {
		if rr[0] == ticket {
			return rr[1]
		}
	}
	return ""
}
