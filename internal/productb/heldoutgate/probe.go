package heldoutgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/productb/claimshape"
	agenttriage "github.com/davniy/izyan/internal/productb/triage"
	"github.com/davniy/izyan/internal/productb/verify"
)

// KernelSpec mirrors the deterministic probe specification the earlier
// measurement produced: groups keyed by repository + ref + advisory with
// the authoritative affected subjects.
type KernelSpec struct {
	Groups []SpecGroup `json:"groups"`
}

// SpecGroup is one deterministic absence probe target.
type SpecGroup struct {
	Repo     string   `json:"repo"`
	Ref      string   `json:"ref"`
	Advisory string   `json:"advisory"`
	Tickets  []string `json:"tickets"`
	Module   string   `json:"module"`
	Subjects []struct {
		Package string `json:"package"`
		Symbol  string `json:"symbol"`
	} `json:"subjects"`
	Verdicts map[string]string `json:"verdicts"`
}

// specKey is the stable identity of one probe group: repo, ref, advisory
// and module name the deterministic family — tickets never enter.
func specKey(g SpecGroup) string {
	return g.Repo + "|" + g.Ref + "|" + g.Advisory + "|" + g.Module
}

// WorktreeMap mirrors worktrees.json: "repo|ref" → root.
type WorktreeMap map[string]struct {
	Root string `json:"root"`
	OK   bool   `json:"ok"`
}

// DeriveAbsenceProbe re-runs the deterministic verify_code_absence check
// for every spec group on its pinned worktree — a pure tool replay with
// no LLM anywhere — then evaluates the recorded observation through the
// generic admission contract. The recorded matrix line is compared for
// parity; a divergence means the re-derivation is not the same check.
func DeriveAbsenceProbe(spec KernelSpec, wts WorktreeMap, matrix []AbsenceGroupRow, limit int) ([]AbsenceGroupRow, map[string]agenttriage.RecordedObservation, []string) {
	recs := map[string]agenttriage.RecordedObservation{}
	// Index the recorded matrix for parity comparison.
	matrixByKey := map[string]ProbeSummary{}
	for _, m := range matrix {
		matrixByKey[m.GroupKey] = m.MatrixRecorded
	}

	type sessionRes struct {
		cli *evidencetools.Client
		err error
	}
	sessions := map[string]*sessionRes{}
	var mu sync.Mutex
	// Shadow's evidencetools surface has no Session.CallTool: every tool
	// call crosses the in-memory MCP boundary via Connect + Client.Call,
	// preserving the audited Observation contract an external agent sees.
	getClient := func(repo, ref string) (*evidencetools.Client, error) {
		key := repo + "|" + ref
		mu.Lock()
		defer mu.Unlock()
		if r, ok := sessions[key]; ok {
			return r.cli, r.err
		}
		wt, ok := wts[key]
		if !ok || !wt.OK || wt.Root == "" {
			r := &sessionRes{err: fmt.Errorf("no pinned worktree for %s", key)}
			sessions[key] = r
			return nil, r.err
		}
		sess, err := evidencetools.NewSession(evidencetools.SessionConfig{
			SnapshotRoot: wt.Root,
			Audit:        evidencetools.NopAudit{},
			GOOS:         "linux",
			GOARCH:       "arm64",
		})
		if err != nil {
			r := &sessionRes{err: err}
			sessions[key] = r
			return nil, err
		}
		cli, err := sess.Connect(context.Background())
		r := &sessionRes{cli: cli, err: err}
		sessions[key] = r
		return r.cli, r.err
	}

	var rows []AbsenceGroupRow
	var defects []string
	groups := spec.Groups
	if limit > 0 && limit < len(groups) {
		groups = groups[:limit]
	}
	for _, g := range groups {
		row := AbsenceGroupRow{
			GroupKey: specKey(g), Repo: g.Repo, Ref: g.Ref,
			Advisory: g.Advisory, Module: g.Module,
			Tickets:  append([]string(nil), g.Tickets...),
			Subjects: len(g.Subjects),
		}
		if rec, ok := matrixByKey[row.GroupKey]; ok {
			row.MatrixRecorded = rec
		}
		cli, err := getClient(g.Repo, g.Ref)
		if err != nil {
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}
		obs, rec, err := callAbsence(context.Background(), cli, g)
		if err != nil {
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}
		recs[row.GroupKey] = rec
		row.ReDerived = summarizeObservation(obs)
		row.SnapshotHash, row.BuildContextHash = pinsOf(rec)
		row.ParityOK, row.ParityDiffs = parity(row.MatrixRecorded, row.ReDerived)
		if !row.ParityOK {
			defects = append(defects, row.GroupKey+": probe re-derivation diverged: "+joinDiffs(row.ParityDiffs))
		}
		evaluateAbsenceGroup(&row, g, rec)
		rows = append(rows, row)
	}
	return rows, recs, defects
}

// callAbsence invokes the deterministic check and wraps the returned
// Observation envelope as a recorded archive observation.
func callAbsence(ctx context.Context, cli *evidencetools.Client, g SpecGroup) (*evidencetools.Observation, agenttriage.RecordedObservation, error) {
	subs := make([]map[string]string, 0, len(g.Subjects))
	for _, s := range g.Subjects {
		subs = append(subs, map[string]string{"package": s.Package, "symbol": s.Symbol})
	}
	args, _ := json.Marshal(map[string]any{"subjects": subs})
	obs, err := cli.Call(ctx, "verify_code_absence", args)
	if err != nil {
		return nil, agenttriage.RecordedObservation{}, fmt.Errorf("verify_code_absence: %w", err)
	}
	if obs == nil {
		return nil, agenttriage.RecordedObservation{}, fmt.Errorf("verify_code_absence: nil observation")
	}
	data, err := json.Marshal(obs)
	if err != nil {
		return nil, agenttriage.RecordedObservation{}, err
	}
	sum := sha256.Sum256(data)
	rec := agenttriage.RecordedObservation{
		ID:           "probe-0001",
		Tool:         "verify_code_absence",
		Status:       statusString(obs.ToolStatus),
		Completeness: obs.Completeness,
		Scope:        obs.Scope,
		Payload:      data,
		DataSHA256:   hex.EncodeToString(sum[:]),
		EvidenceRefs: append([]string(nil), obs.EvidenceRefs...),
		Limitations:  append([]string(nil), obs.Limitations...),
		RunID:        "probe-" + shortHashOf(specKey(g)),
		Attempt:      1,
	}
	if obs.ScopeDetails != nil {
		rec.SnapshotHash = obs.ScopeDetails.SnapshotHash
		if obs.ScopeDetails.BuildContext != nil {
			b, _ := json.Marshal(obs.ScopeDetails.BuildContext)
			h := sha256.Sum256(b)
			rec.BuildContextHash = hex.EncodeToString(h[:])
		}
	}
	return obs, rec, nil
}

func statusString(s evidencetools.ToolStatus) string {
	switch s {
	case evidencetools.StatusOK:
		return "OK"
	case evidencetools.StatusUnsupported:
		return "UNSUPPORTED"
	default:
		return "ERROR"
	}
}

func summarizeObservation(obs *evidencetools.Observation) ProbeSummary {
	out := ProbeSummary{
		Status:       statusString(obs.ToolStatus),
		Completeness: string(obs.Completeness),
		Limitations:  append([]string(nil), obs.Limitations...),
	}
	b, _ := json.Marshal(obs.Data)
	var d evidencetools.CodeAbsenceData
	_ = json.Unmarshal(b, &d)
	out.Checked = len(d.CheckedSubjects)
	out.Absent = len(d.AbsentSubjects)
	out.Present = len(d.PresentSubjects)
	if d.ImportClosure != nil {
		out.ClosureComplete = d.ImportClosure.ScopeComplete
		out.OpenExceptions = len(d.ImportClosure.OpenExceptions)
	}
	return out
}

func pinsOf(rec agenttriage.RecordedObservation) (snap, bctx string) {
	return rec.SnapshotHash, rec.BuildContextHash
}

// parity compares the recorded matrix line with the re-derived summary.
func parity(recorded, derived ProbeSummary) (bool, []string) {
	var diffs []string
	cmp := func(name string, a, b any) {
		if fmt.Sprint(a) != fmt.Sprint(b) {
			diffs = append(diffs, fmt.Sprintf("%s: recorded=%v derived=%v", name, a, b))
		}
	}
	if recorded.Status == "" && recorded.Completeness == "" {
		return true, nil // no recorded line — nothing to compare
	}
	cmp("status", recorded.Status, derived.Status)
	cmp("completeness", recorded.Completeness, derived.Completeness)
	cmp("checked", recorded.Checked, derived.Checked)
	cmp("absent", recorded.Absent, derived.Absent)
	cmp("present", recorded.Present, derived.Present)
	cmp("closure_complete", recorded.ClosureComplete, derived.ClosureComplete)
	cmp("open_exceptions", recorded.OpenExceptions, derived.OpenExceptions)
	return len(diffs) == 0, diffs
}

func joinDiffs(d []string) string {
	out := ""
	for i, s := range d {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// absenceInput builds the verification Input of one probe group: the
// advisory-derived mandatory locus subjects plus the recorded
// observation, under a content-addressed probe run id.
func absenceInput(g SpecGroup, rec agenttriage.RecordedObservation, pinSnap, pinBctx string) verify.Input {
	subs := make([]claimshape.Subject, 0, len(g.Subjects))
	for _, s := range g.Subjects {
		subs = append(subs, claimshape.Subject{
			Kind: claimshape.SubjectSymbol, Package: s.Package, Symbol: s.Symbol,
			Name: s.Package + "." + s.Symbol,
		})
	}
	var names []string
	for _, s := range subs {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	// The input's run identity is the content-addressed probe id —
	// independent of the record's own stamp, so a mutated foreign stamp
	// is exercised by the provenance binding, never re-homed.
	runID := "probe-" + shortHashOf(specKey(g))
	if rec.RunID == "" {
		rec.RunID = runID
	}
	claim := claimshape.CanonicalClaim{
		ID:                   "claim-probe-absence",
		Shape:                claimshape.ShapeSubjectAbsent,
		Subject:              claimshape.Subject{Kind: claimshape.SubjectClaimSet, Name: joinNames(names)},
		Parameters:           map[string]any{"subjects": subs},
		Polarity:             claimshape.PolarityTrue,
		EvidenceRefs:         []string{rec.ID},
		RequiredCapabilities: claimshape.RequiredCapabilities(claimshape.ShapeSubjectAbsent),
	}
	if pinSnap != "" {
		claim.Scope.SnapshotHash = pinSnap
	}
	if pinBctx != "" {
		claim.Scope.BuildContextHash = pinBctx
	}
	return verify.Input{
		RunID:        runID,
		FindingID:    "probe-" + g.Advisory + "-" + g.Ref,
		Claims:       []claimshape.CanonicalClaim{claim},
		Observations: []agenttriage.RecordedObservation{rec},
		Advisory: claimshape.AdvisoryFacts{
			IDs: []string{g.Advisory}, ResolvedID: g.Advisory,
			Module: g.Module, AffectedSymbols: subs,
		},
	}
}

func joinNames(ns []string) string {
	out := ""
	for i, n := range ns {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

func shortHashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

// ShortKey renders the stable short identity of one probe group key —
// used for deterministic artifact names in reports and dumps.
func ShortKey(groupKey string) string { return shortHashOf(groupKey) }

// evaluateAbsenceGroup runs the contract over the re-derived record and
// records the §8.3 outcome: eligibility, admission and soundness.
func evaluateAbsenceGroup(row *AbsenceGroupRow, g SpecGroup, rec agenttriage.RecordedObservation) {
	in := absenceInput(g, rec, "", "")
	rep := verify.Evaluate(in)
	d := rep.Decision()
	row.Disposition = d.Disposition
	row.Rule = d.Rule
	row.RejectReasons = map[string]int{}
	for _, ce := range rep.Claims {
		row.ClaimOutcome = string(ce.Outcome)
		row.Predicate = string(ce.Predicate)
		for _, gr := range ce.Groups {
			if gr.Established != "" {
				row.Established = gr.Established
			}
			for _, adm := range gr.Observations {
				if adm.Admitted {
					row.Admitted++
					if universalDir(adm, ce.Shape) {
						row.UniversalAdmitted++
					}
				} else if adm.Reason != "" {
					row.RejectReasons[adm.Reason]++
				}
			}
		}
	}
	// §8.3 eligibility for the universal (proof) direction: COMPLETE
	// observation over a complete closure with zero open exceptions AND
	// zero observed dynamic markers — the same gap list the contract
	// blocks on, so eligibility never disagrees with admission.
	closure := closureOf(rec)
	row.DynamicMarkers = len(closure.dynamicMarkers)
	row.EligibleForAdmission = row.ReDerived.Completeness == "COMPLETE" &&
		row.ReDerived.ClosureComplete && row.ReDerived.OpenExceptions == 0 &&
		row.DynamicMarkers == 0 && closure.unresolvedDispatch == 0 &&
		closure.scopeUnknown == 0
	row.ProofEligible = row.EligibleForAdmission &&
		row.ReDerived.Present == 0 &&
		row.ReDerived.Checked == row.ReDerived.Absent && row.ReDerived.Checked > 0
	switch {
	case !row.ParityOK:
		row.SoundnessOK = false
		row.SoundnessNote = "re-derivation diverged from recorded probe"
	case !row.EligibleForAdmission:
		// A non-eligible record may still yield an existential
		// counterexample (REFUTES has no closed-scope floor); what it
		// may never do is admit the universal direction or produce a
		// reduction. Counterexample admissions are counted separately.
		row.SoundnessOK = row.UniversalAdmitted == 0 && row.Disposition == "UNCHANGED"
		row.CounterexampleAdmissions = row.Admitted
		if !row.SoundnessOK {
			row.SoundnessNote = "non-eligible record admitted universal evidence or produced a verdict"
		}
	case row.ProofEligible:
		row.SoundnessOK = row.Admitted > 0 && row.Predicate == "HOLDS" && row.Disposition == "DISMISSED"
		if !row.SoundnessOK {
			row.SoundnessNote = "eligible absence proof was not admitted"
		}
	default: // eligible record, present>0: counterexample admission is expected
		row.SoundnessOK = row.Admitted > 0 && row.Predicate == "DISPROVED" &&
			row.ClaimOutcome == "FALSE" && row.Disposition == "UNCHANGED"
		if !row.SoundnessOK {
			row.SoundnessNote = "eligible refuted record mishandled"
		}
	}
}

// closureFacts projects the gap lists of an absence record's embedded
// closure report — the same fields scopeHashes maps into OpenGaps.
type closureFacts struct {
	dynamicMarkers     []string
	unresolvedDispatch int
	scopeUnknown       int
}

func closureOf(rec agenttriage.RecordedObservation) closureFacts {
	var f closureFacts
	var p struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(rec.Payload, &p) == nil {
		var d struct {
			Closure struct {
				Markers  []string `json:"observed_dynamic_markers"`
				Dispatch []string `json:"unresolved_dispatch"`
				Unknown  []string `json:"scope_unknown"`
			} `json:"import_closure"`
		}
		if json.Unmarshal(p.Data, &d) == nil {
			f.dynamicMarkers = d.Closure.Markers
			f.unresolvedDispatch = len(d.Closure.Dispatch)
			f.scopeUnknown = len(d.Closure.Unknown)
		}
	}
	return f
}

// universalDir reports whether an admitted observation exercised the
// closed-scope (universal) direction of its capability contract — the
// direction the §8.3 eligibility list gates.
func universalDir(adm verify.ObsAdmission, shape claimshape.Shape) bool {
	c := verify.Contract(adm.Capability, shape)
	if c == nil {
		return false
	}
	if adm.Result == verify.ResultSupports {
		return c.Supports.ClosedScope
	}
	return c.Refutes.ClosedScope
}

// subjectSetsOf pulls the checked subjects of a recorded absence
// payload back out for claim reconstruction.
func subjectSetsOf(rec agenttriage.RecordedObservation) []claimshape.Subject {
	var env struct {
		Data struct {
			Expected []struct {
				Package string `json:"package"`
				Symbol  string `json:"symbol"`
			} `json:"expected_subjects"`
		} `json:"data"`
	}
	if json.Unmarshal(rec.Payload, &env) != nil {
		return nil
	}
	var out []claimshape.Subject
	for _, s := range env.Data.Expected {
		out = append(out, claimshape.Subject{Kind: claimshape.SubjectSymbol, Package: s.Package, Symbol: s.Symbol, Name: s.Package + "." + s.Symbol})
	}
	return out
}

// Mutations applies the §8.4 generic mutations to every proof-eligible
// re-derived observation and reports whether the contract refuses
// admission. Mutations transform recorded bytes — they never name a
// package, advisory or ticket.
func Mutations(rows []AbsenceGroupRow, recs map[string]agenttriage.RecordedObservation) []MutationRow {
	var out []MutationRow
	for _, row := range rows {
		// Mutations exercise the universal direction: start from every
		// record that lists no present subject, then strip the gap
		// lists to a baseline the contract would admit. If the cleaned
		// baseline itself does not admit, every mutation row for the
		// group is marked indeterminate rather than vacuously passing.
		if row.ReDerived.Present != 0 || row.ReDerived.Checked == 0 {
			continue
		}
		rec, ok := recs[row.GroupKey]
		if !ok {
			continue
		}
		g := SpecGroup{Repo: row.Repo, Ref: row.Ref, Advisory: row.Advisory, Module: row.Module, Tickets: row.Tickets}
		for _, s := range subjectSetsOf(rec) {
			g.Subjects = append(g.Subjects, struct {
				Package string `json:"package"`
				Symbol  string `json:"symbol"`
			}{Package: s.Package, Symbol: s.Symbol})
		}
		orig := cleanBaseline(rec)
		baselineOK := func() bool {
			rep := verify.Evaluate(absenceInput(g, orig, "", ""))
			for _, ce := range rep.Claims {
				for _, gr := range ce.Groups {
					for _, adm := range gr.Observations {
						if adm.Admitted && universalDir(adm, ce.Shape) {
							return true
						}
					}
				}
			}
			return rep.Decision().Disposition == "DISMISSED"
		}()
		for _, m := range mutationList {
			mr := MutationRow{GroupKey: row.GroupKey, Mutation: m.name, Want: m.want}
			mut, pinSnap, pinBctx := m.apply(orig, orig)
			in := absenceInput(g, mut, pinSnap, pinBctx)
			rep := verify.Evaluate(in)
			mr.GotDisposition = rep.Decision().Disposition
			admitted, universal := 0, 0
			for _, ce := range rep.Claims {
				for _, gr := range ce.Groups {
					if gr.Established != "" {
						mr.GotEstablished = gr.Established
					}
					for _, adm := range gr.Observations {
						if adm.Admitted {
							admitted++
							if universalDir(adm, ce.Shape) {
								universal++
							}
						} else if adm.Reason != "" {
							mr.AdmissionReason = adm.Reason
						}
					}
				}
			}
			if !baselineOK {
				mr.Pass = false
				mr.AdmissionReason = "baseline_unclean:cleaned record admitted nothing universal"
				out = append(out, mr)
				continue
			}
			mr.Pass = mutationOK(mr, admitted, universal)
			out = append(out, mr)
		}
	}
	return out
}

// cleanBaseline strips the gap-list fields of an absence record so the
// mutation suite starts from a record the contract can actually admit:
// dynamic markers, open exceptions, dispatch and scope gaps are the
// environment noise the mutations then re-introduce one at a time.
func cleanBaseline(rec agenttriage.RecordedObservation) agenttriage.RecordedObservation {
	return editPayload(rec, func(data, _ map[string]any) {
		cl, _ := data["import_closure"].(map[string]any)
		if cl == nil {
			return
		}
		for _, k := range []string{"observed_dynamic_markers", "ignored_dynamic_markers", "closed_exceptions",
			"open_exceptions", "unresolved_dispatch", "scope_unknown", "skipped_unscanned",
			"unhashed_source", "skipped_packages"} {
			delete(cl, k)
		}
		delete(data, "dynamic_markers")
		delete(data, "unresolved_dispatch")
		delete(data, "skipped_packages")
	})
}

// mutationOK applies the §8.4 expectation: a mutated record must never
// still establish the absence predicate — the group must not reach
// "holds" and the run must stay UNCHANGED. A counterexample swap
// legitimately admits the REFUTES direction and must read "disproved"
// exactly: auxiliary conjunction evidence can no longer tip a group
// into "conflicting" (predicate-evidence split, post D-5).
func mutationOK(mr MutationRow, admitted, universal int) bool {
	if mr.GotDisposition != "UNCHANGED" {
		return false
	}
	if mr.GotEstablished == "holds" {
		return false
	}
	if mr.Mutation == "absent_to_present" {
		return mr.GotEstablished == "disproved"
	}
	return true
}

type mutation struct {
	name string
	want string
	// apply mutates the record; the returned pin hashes (when set) ask
	// for a claim-pinned scope so context mutations are observed as
	// context exclusions rather than silently re-pinned.
	apply func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string)
}

var mutationList = []mutation{
	{"absent_to_present", "non-admitting (counterexample disproves)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		return editPayload(r, func(data, _ map[string]any) {
			data["present_subjects"] = data["absent_subjects"]
			data["absent_subjects"] = nil
		}), "", ""
	}},
	{"drop_checked_subject", "non-admitting (undecided subject)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		return editPayload(r, func(data, _ map[string]any) {
			if xs, ok := data["checked_subjects"].([]any); ok && len(xs) > 0 {
				data["checked_subjects"] = xs[1:]
			}
			if xs, ok := data["absent_subjects"].([]any); ok && len(xs) > 0 {
				data["absent_subjects"] = xs[1:]
			}
		}), "", ""
	}},
	{"completeness_partial", "non-admitting (universal floor)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		r.Completeness = evidencetools.CompletenessPartial
		return editPayload(r, func(data, _ map[string]any) {
			data["completeness"] = "PARTIAL"
		}), "", ""
	}},
	{"unresolved_dispatch_marker", "non-admitting (dynamic gap)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		return editPayload(r, func(data, _ map[string]any) {
			data["unresolved_dispatch"] = []any{"iface-dispatch at pkg/f.go:1"}
			if c, ok := data["import_closure"].(map[string]any); ok {
				c["unresolved_dispatch"] = []any{"iface-dispatch at pkg/f.go:1"}
			}
		}), "", ""
	}},
	{"open_dynamic_marker", "non-admitting (dynamic gap)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		return editPayload(r, func(data, _ map[string]any) {
			data["dynamic_markers"] = []any{"reflect at pkg/f.go:1"}
			if c, ok := data["import_closure"].(map[string]any); ok {
				c["observed_dynamic_markers"] = []any{"reflect at pkg/f.go:1"}
			}
		}), "", ""
	}},
	{"closure_open_exception", "non-admitting (scope gap)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		return editPayload(r, func(data, _ map[string]any) {
			if c, ok := data["import_closure"].(map[string]any); ok {
				c["open_exceptions"] = []any{"pkg/x: unanalyzed"}
				c["scope_complete"] = false
				c["complete"] = false
			}
		}), "", ""
	}},
	{"snapshot_hash_changed", "non-admitting (context excluded)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		m := editPayload(r, func(data, env map[string]any) {
			if sd, ok := env["scope_details"].(map[string]any); ok {
				sd["snapshot_hash"] = "deadbeef"
			}
			data["snapshot_hash"] = "deadbeef"
		})
		m.SnapshotHash = "deadbeef"
		return m, orig.SnapshotHash, ""
	}},
	{"build_context_changed", "non-admitting (context excluded)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		m := editPayload(r, func(data, env map[string]any) {
			if sd, ok := env["scope_details"].(map[string]any); ok {
				if bc, ok := sd["build_context"].(map[string]any); ok {
					bc["goos"] = "plan9"
				}
			}
			data["build_context_hash"] = "deadbeef"
		})
		m.BuildContextHash = "deadbeef"
		return m, "", orig.BuildContextHash
	}},
	{"foreign_run_mix", "non-admitting (foreign run_id)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		r.RunID = r.RunID + "-foreign"
		return r, "", ""
	}},
	{"skipped_package", "non-admitting (scope gap)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		return editPayload(r, func(data, _ map[string]any) {
			data["skipped_packages"] = []any{"pkg/unscanned"}
			if c, ok := data["import_closure"].(map[string]any); ok {
				c["skipped_unscanned"] = []any{"pkg/unscanned"}
			}
		}), "", ""
	}},
	{"tool_status_error", "non-admitting (failed check)", func(orig, r agenttriage.RecordedObservation) (agenttriage.RecordedObservation, string, string) {
		r.Status = "ERROR"
		return r, "", ""
	}},
}

// editPayload rewrites the `data` member of the recorded observation
// envelope (and refreshes the payload hash so the mutation is a clean
// record, not a corrupted one — the contract must refuse it on
// semantics, never on syntax).
func editPayload(r agenttriage.RecordedObservation, f func(data, env map[string]any)) agenttriage.RecordedObservation {
	var env map[string]any
	if json.Unmarshal(r.Payload, &env) != nil || env == nil {
		return r
	}
	data, _ := env["data"].(map[string]any)
	if data == nil {
		data = env
	}
	f(data, env)
	b, err := json.Marshal(env)
	if err != nil {
		return r
	}
	r.Payload = b
	sum := sha256.Sum256(b)
	r.DataSHA256 = hex.EncodeToString(sum[:])
	return r
}
