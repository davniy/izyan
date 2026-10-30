package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/flow"
)

// replay.go rebuilds the agent turn of a persisted `izyan research` run
// (--replay-agent-turn): report assembly gets the exact agent_output and
// the exact run.attempts row the original run recorded — status,
// extraction record and artifacts verbatim — without any model call.
//
// Fail-closed contract:
//   - report.json must decode under the closed research-report/1 schema;
//   - a persisted report advertising slice2-fidelity/3 must additionally
//     pass the complete contract validation in place — including the
//     fail-closed recomputation of its derived evidence_level — before
//     its agent turn is accepted: a forged or stale level, an invalid
//     role, a dangling ref or a missing pinned fact artifact aborts the
//     replay and no report is written. Reports advertising only /1 or
//     /2 keep the existing compatibility path: no role or
//     evidence_level is required of them;
//   - agent_output must carry a known status, resolve unambiguously to a
//     persisted kind=agent attempt row, and agree with that row's status;
//   - every recorded artifact pin (answer_artifact, raw_artifact,
//     result_artifact, extraction.answer_artifact) must be consistent
//     across every record that cites it and match the bytes on disk — a
//     missing file, a sha256 mismatch or conflicting duplicate pins
//     aborts the replay and no report is written;
//   - a recorded OK status requires the retained answer.txt to parse under
//     strictExtract and to agree with the recorded category/reasoning.
//
// The replayed run never trusts the persisted evidence_level either:
// Assemble recomputes it through deriveEvidenceLevel — the same pure
// derivation a live run uses — so identical persisted input yields a
// byte-identical ladder, and no model or harness call happens on this
// path.

// LoadPersistedAgentTurn is the cmd-facing wrapper of
// loadPersistedAgentTurn (the loader is an internal API; see the unexported
// function for the verification contract).
func LoadPersistedAgentTurn(dir string) (*AgentTurn, error) {
	return loadPersistedAgentTurn(dir)
}

// loadPersistedAgentTurn reads a persisted run directory and rebuilds the
// agent turn exactly as it was recorded. dir must contain report.json
// (schema research-report/1–/4); when the report advertises
// slice2-fidelity/3 or is a research-report/3 or /4 the whole document — its
// derived evidence_level or decision_artifact included — is revalidated
// in place before the turn is accepted. A /4 document additionally has to
// carry a re-admitted request composition: Validate re-checks the composed
// answer's own invariants, its request identity against the analysed request
// and the corpus-basis/record-bound containment, so a replayed historical
// closure that current admission no longer supports is refused here rather
// than republished.
// run-manifest.json, when present, restores the operator-facing error
// and the original agent manifest.
func loadPersistedAgentTurn(dir string) (*AgentTurn, error) {
	if dir == "" {
		return nil, fmt.Errorf("replay dir is empty")
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("replay dir %s: %w", dir, err)
	}
	rb, err := os.ReadFile(filepath.Join(base, "report.json"))
	if err != nil {
		if _, historyErr := os.Stat(filepath.Join(base, "historical-replay.json")); historyErr == nil {
			return nil, ErrHistoricalAuthority
		}
		return nil, fmt.Errorf("replay dir %s: report.json unreadable: %w", base, err)
	}
	persisted, err := ParseReport(rb)
	if err != nil {
		return nil, fmt.Errorf("replay dir %s: %w", base, err)
	}
	// Retained input fields never become unchecked on the legacy compat path.
	retained := &ValidationError{}
	validateRetainedTicket(persisted, retained)
	validateRetainedConditions(persisted, retained)
	validateRetainedImplementation(persisted, retained)
	if len(retained.Problems) > 0 {
		return nil, fmt.Errorf("replay dir %s: %w", base, retained)
	}

	// Full-contract input gates: a persisted slice2-fidelity/3 report must
	// satisfy the whole marker contract — including the recomputed
	// evidence_level matching the stored object member-for-member — and a
	// persisted research-report/3 must carry a valid decision-artifact/1
	// member before its agent turn is accepted. This is the same single
	// validator live-emitted reports pass; run dir-scoped so the pinned
	// verified-fact artifacts are checked against their recorded digests
	// too. A forged level, a wrong role, a dangling ref, a malformed
	// artifact or a missing pinned artifact aborts the replay before any
	// replayed output exists. Reports advertising only /1 or /2 keep the
	// legacy compat path: no role, evidence_level or artifact is required
	// of them.
	if slices.Contains(persisted.ContractExtensions, Slice2ExtensionV3) ||
		persisted.Schema == ReportSchemaV3 || persisted.Schema == ReportSchemaV4 ||
		persisted.Schema == ReportSchemaV5 || len(persisted.VerifiedFacts) > 0 ||
		persisted.Decision != nil || persisted.DecisionArtifact != nil ||
		persisted.RequestComposition != nil || persisted.ExploitLocusBinding != nil {
		if verr := Validate(persisted, base); verr != nil {
			return nil, fmt.Errorf("replay dir %s: %w", base, verr)
		}
	}
	// The declared-assumptions block is an input-policy record: when a
	// persisted report carries one it must be self-consistent even on the
	// legacy /1-/2 compat path (the block is absent from pre-channel
	// reports, so this gate never rejects them). A hand-edited statement,
	// broken digest pin or unknown intake outcome aborts the replay —
	// replay can re-use a recorded turn, never rewrite its policy inputs.
	if persisted.Input.DeclaredAssumptions != nil {
		e := &ValidationError{}
		validateDeclaredAssumptionsInput(e, persisted.Input.DeclaredAssumptions)
		if len(e.Problems) > 0 {
			return nil, fmt.Errorf("replay dir %s: %w", base, e)
		}
	}
	// The implementation-locus proposal channel is an input record too:
	// the same replay gate — a hand-edited proposal, a broken pin or an
	// unknown intake outcome aborts the replay before anything emits.
	if persisted.Input.ImplementationLocusProposals != nil {
		e := &ValidationError{}
		validateImplementationProposalsInput(e, persisted.Input.ImplementationLocusProposals, &persisted.Input.Advisory)
		if len(e.Problems) > 0 {
			return nil, fmt.Errorf("replay dir %s: %w", base, e)
		}
	}
	out := persisted.AgentOutput
	switch out.Status {
	case AgentOK, AgentInvalidFormat, AgentFailed, AgentTimeout, AgentProviderRefused:
	default:
		return nil, fmt.Errorf("replay dir %s: persisted agent_output.status %q is not a replayable recorded turn", base, out.Status)
	}

	// The ledger row the saved agent_output resolved to. Without an
	// explicit attempt_id the row set must be unambiguous: exactly one
	// persisted kind=agent attempt is required, otherwise any choice
	// would silently pick a provenance record.
	var agentRows []*Attempt
	for i := range persisted.Run.Attempts {
		if persisted.Run.Attempts[i].Kind == "agent" {
			agentRows = append(agentRows, &persisted.Run.Attempts[i])
		}
	}
	var savedAttempt *Attempt
	if out.AttemptID != nil {
		for _, at := range agentRows {
			if at.ID == *out.AttemptID {
				savedAttempt = at
				break
			}
		}
		if savedAttempt == nil {
			return nil, fmt.Errorf("replay dir %s: agent_output.attempt_id %q does not resolve to a persisted kind=agent attempt row", base, *out.AttemptID)
		}
	} else {
		switch len(agentRows) {
		case 0:
			return nil, fmt.Errorf("replay dir %s: no persisted kind=agent attempt row and agent_output.attempt_id is absent", base)
		case 1:
			savedAttempt = agentRows[0]
		default:
			return nil, fmt.Errorf("replay dir %s: %d persisted kind=agent attempt rows and agent_output.attempt_id is absent — the replayed attempt is ambiguous", base, len(agentRows))
		}
	}
	// agent_output and its ledger row are two records of the same
	// attempt: a status disagreement means a corrupted persisted report.
	if savedAttempt.Status != out.Status {
		return nil, fmt.Errorf("replay dir %s: agent_output.status %s disagrees with the persisted attempt %s status %s",
			base, out.Status, savedAttempt.ID, savedAttempt.Status)
	}

	// The original run's manifest restores the operator-facing error text
	// and the harness pins; absent manifest is tolerated, corrupt is not.
	var agentErr, agentProvider, agentModel string
	var manifest AgentManifest
	if mb, merr := os.ReadFile(filepath.Join(base, "run-manifest.json")); merr == nil {
		var m struct {
			Agent struct {
				Status   string        `json:"status"`
				Error    string        `json:"error"`
				Provider string        `json:"provider"`
				Model    string        `json:"model"`
				Manifest AgentManifest `json:"manifest"`
			} `json:"agent"`
		}
		if jerr := json.Unmarshal(mb, &m); jerr != nil {
			return nil, fmt.Errorf("replay dir %s: run-manifest.json decode: %w", base, jerr)
		}
		agentErr = m.Agent.Error
		agentProvider = m.Agent.Provider
		agentModel = m.Agent.Model
		manifest = m.Agent.Manifest
	}

	// Every artifact the persisted report pins must verify against the
	// bytes on disk — and every record citing the same path must agree on
	// its digest (and on recorded size/selector metadata): silently
	// overwriting one pin with another would let a corrupted report pass.
	type pinMeta struct {
		sha      string
		size     int64
		hasSize  bool
		selector string
		hasSel   bool
	}
	pins := map[string]pinMeta{}
	var order []string
	var pinErr error
	pin := func(path, sha string, size int64, selector string, hasMeta bool) {
		if pinErr != nil || path == "" || sha == "" {
			return
		}
		if ex, dup := pins[path]; dup {
			switch {
			case ex.sha != sha:
				pinErr = fmt.Errorf("replay dir %s: conflicting sha256 pins for artifact %s: %s vs %s", base, path, ex.sha, sha)
			case hasMeta && ex.hasSize && ex.size != size:
				pinErr = fmt.Errorf("replay dir %s: conflicting size_bytes pins for artifact %s: %d vs %d", base, path, ex.size, size)
			case hasMeta && ex.hasSel && ex.selector != selector:
				pinErr = fmt.Errorf("replay dir %s: conflicting selector pins for artifact %s: %q vs %q", base, path, ex.selector, selector)
			}
			if hasMeta {
				if !ex.hasSize {
					ex.size, ex.hasSize = size, true
				}
				if !ex.hasSel {
					ex.selector, ex.hasSel = selector, true
				}
				pins[path] = ex
			}
			return
		}
		order = append(order, path)
		pins[path] = pinMeta{sha: sha, size: size, selector: selector, hasSize: hasMeta, hasSel: hasMeta}
	}
	addArt := func(a *AttemptArtifact) {
		if a != nil {
			pin(a.Path, a.SHA256, a.SizeBytes, a.Selector, true)
		}
	}
	addArt(out.AnswerArtifact)
	addArt(out.ResultArtifact)
	if out.Extraction != nil {
		addArt(out.Extraction.AnswerArtifact)
	}
	if out.RawArtifact.Path != nil && out.RawArtifact.SHA256 != nil {
		pin(*out.RawArtifact.Path, *out.RawArtifact.SHA256, 0, "", false)
	}
	addArt(savedAttempt.ResultArtifact)
	if savedAttempt.Extraction != nil {
		addArt(savedAttempt.Extraction.AnswerArtifact)
	}
	if pinErr != nil {
		return nil, pinErr
	}

	byPath := map[string][]byte{}
	for _, rel := range order {
		abs, rerr := replayArtifactPath(base, rel)
		if rerr != nil {
			return nil, rerr
		}
		b, rerr := os.ReadFile(abs)
		if rerr != nil {
			return nil, fmt.Errorf("replay dir %s: artifact %s recorded in report.json is unreadable: %w", base, rel, rerr)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != pins[rel].sha {
			return nil, fmt.Errorf("replay dir %s: artifact %s sha256 mismatch: recorded %s, on disk %s", base, rel, pins[rel].sha, got)
		}
		byPath[rel] = b
	}

	// Locate the retained answer/result bytes: the recorded artifact path
	// wins, else the conventional agent/<attempt>/… path under the dir.
	answerRel, resultRel := "", ""
	for _, c := range []struct {
		dst *string
		rel string
	}{
		{&answerRel, artifactPathOf(out.AnswerArtifact)},
		{&answerRel, extractionAnswerPath(out.Extraction)},
		{&answerRel, deref(out.RawArtifact.Path)},
		{&answerRel, "agent/" + savedAttempt.ID + "/answer.txt"},
		{&resultRel, artifactPathOf(out.ResultArtifact)},
		{&resultRel, artifactPathOf(savedAttempt.ResultArtifact)},
		{&resultRel, "agent/" + savedAttempt.ID + "/result.json"},
	} {
		if c.rel != "" && *c.dst == "" {
			*c.dst = c.rel
		}
	}
	answer := byPath[answerRel]
	if answer == nil && answerRel != "" {
		if abs, rerr := replayArtifactPath(base, answerRel); rerr == nil {
			if b, oerr := os.ReadFile(abs); oerr == nil {
				answer = b
				byPath[answerRel] = b
			} else if !os.IsNotExist(oerr) {
				return nil, fmt.Errorf("replay dir %s: answer artifact %s unreadable: %w", base, answerRel, oerr)
			}
		}
	}
	result := byPath[resultRel]
	if result == nil && resultRel != "" {
		if abs, rerr := replayArtifactPath(base, resultRel); rerr == nil {
			if b, oerr := os.ReadFile(abs); oerr == nil {
				result = b
				byPath[resultRel] = b
			}
		}
	}
	shaOf := func(b []byte) string {
		if len(b) == 0 {
			return ""
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}

	// Re-parse the retained answer text: the assembler consumes the parsed
	// answer in memory; the recorded extraction record is never re-derived
	// or rewritten — it stays exactly what the original run persisted.
	// Only an OK turn carries a parsed answer (RunAgent parity): when the
	// persisted status is non-OK the answer bytes stay an artifact only,
	// even if the current extractor would accept them.
	var ans *agentAnswer
	if answer != nil && out.Status == AgentOK {
		a, _ := strictExtract(string(answer))
		ans = a
	}
	if out.Status == AgentOK {
		if ans == nil {
			return nil, fmt.Errorf("replay dir %s: persisted status OK but the retained answer does not yield a valid answer object under the current extractor", base)
		}
		if out.Category == nil {
			return nil, fmt.Errorf("replay dir %s: persisted status OK but agent_output.category is absent", base)
		}
		if !strings.EqualFold(*out.Category, ans.Category) {
			return nil, fmt.Errorf("replay dir %s: persisted category %q disagrees with the pinned answer bytes (%q)", base, *out.Category, ans.Category)
		}
		if out.Reasoning != nil && *out.Reasoning != ans.Reasoning {
			return nil, fmt.Errorf("replay dir %s: persisted reasoning disagrees with the pinned answer bytes", base)
		}
	}
	var answerJSON []byte
	if ans != nil {
		answerJSON = answer
	}

	out.ReplayedFrom = &AgentReplayProvenance{
		Dir:               base,
		AnswerSHA256:      shaOf(answer),
		ResultSHA256:      shaOf(result),
		OriginalRunID:     persisted.Run.RunID,
		OriginalAttemptID: savedAttempt.ID,
	}
	return &AgentTurn{
		Output:     out,
		Answer:     ans,
		AnswerJSON: answerJSON,
		RawResult:  result,
		Manifest:   manifest,
		Err:        agentErr,
		// The recorded provider/model are the run's identity, not live
		// configuration: they persist verbatim through the rebuild so the
		// emitted manifest keeps the original label byte-identically.
		Provider:        agentProvider,
		Model:           agentModel,
		ResultArtifact:  out.ResultArtifact,
		AnswerArtifact:  out.AnswerArtifact,
		Extraction:      out.Extraction,
		ReplayedAttempt: savedAttempt,
	}, nil
}

// replayArtifactPath resolves a report-recorded artifact path against the
// replay dir: relative paths join dir and must not escape it; an absolute
// path (older manifests pinned host-absolute paths) is used as is.
func replayArtifactPath(dir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("replay dir %s: recorded artifact has no path", dir)
	}
	if filepath.IsAbs(rel) {
		return rel, nil
	}
	abs := filepath.Join(dir, rel)
	base := filepath.Clean(dir)
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("replay dir %s: artifact path %q escapes the replay directory", dir, rel)
	}
	return abs, nil
}

func artifactPathOf(a *AttemptArtifact) string {
	if a == nil {
		return ""
	}
	return a.Path
}

func extractionAnswerPath(ex *Extraction) string {
	if ex == nil {
		return ""
	}
	return artifactPathOf(ex.AnswerArtifact)
}

// ---- decision-ready run replay (--replay-decision-run) ----

// PersistedDecisionRun is the loaded record of a persisted
// decision-ready run directory: the recorded flow result (the replay
// contract's input) plus the session audit ledger the run persisted —
// the fact envelope rebuilds from the audit records, never from the
// result's own observation copies.
type PersistedDecisionRun struct {
	Result       flow.Result
	Audit        []evidencetools.AuditRecord
	ArtifactPath string // absolute path of the persisted decision-artifact.json
}

// LoadPersistedDecisionRun reads a persisted decision-ready run dir
// fail-closed: flow-result.json must decode under the recorded
// contract (unknown members are rejected), the event stream must be
// present and the verification-observations.jsonl ledger must decode
// row by row — a truncated or malformed record aborts the replay
// before any report is written. The model is never invoked on this
// path.
func LoadPersistedDecisionRun(dir string) (*PersistedDecisionRun, error) {
	resultPath := filepath.Join(dir, flowResultFile)
	raw, err := os.ReadFile(resultPath)
	if err != nil {
		return nil, fmt.Errorf("flow result %s: %w", resultPath, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var res flow.Result
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("flow result %s: %w", resultPath, err)
	}
	if len(res.Events) == 0 {
		return nil, fmt.Errorf("flow result %s carries no event stream — not a decision-ready run record", resultPath)
	}
	var audit []evidencetools.AuditRecord
	ledgerPath := filepath.Join(dir, flowObservationLedger)
	if f, err := os.Open(ledgerPath); err == nil {
		defer f.Close()
		ldec := json.NewDecoder(f)
		for row := 0; ; row++ {
			var rec evidencetools.AuditRecord
			if err := ldec.Decode(&rec); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("verification-observations.jsonl row %d: %w", row, err)
			}
			// An observation carrying payload_ref keeps only the bounded
			// envelope on the wire; the replay restores the complete
			// hash-bound payload from its sidecar so downstream
			// consumers decode the same typed result the tool produced.
			// A missing, altered, undecodable or digest-mismatched
			// sidecar aborts the replay — fail-closed, never a guess.
			if rec.Observation != nil && rec.Observation.PayloadRef != nil {
				data, perr := loadExternalizedPayload(dir, rec.Observation)
				if perr != nil {
					return nil, fmt.Errorf("verification-observations.jsonl row %d: %w", row, perr)
				}
				rec.Observation.Data = data
				rec.Observation.PayloadRef = nil
			}
			audit = append(audit, rec)
		}
	}
	return &PersistedDecisionRun{
		Result:       res,
		Audit:        audit,
		ArtifactPath: filepath.Join(dir, decisionArtifactFile),
	}, nil
}
