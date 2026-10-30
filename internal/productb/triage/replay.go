package triage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/flock"
	"github.com/davniy/izyan/internal/llm"
	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/productb/repository"
	"github.com/davniy/izyan/internal/productb/vulnerability"
)

// ReplaySchemaVersion is the schema of replay.json inside a replay report.
// v2 records support and machine-admissibility drift as separate outcomes of
// the replay comparison; replay.v1 is history.
const ReplaySchemaVersion = "replay.v2"

// AuditEventReplay is the audit event recorded once per replay report.
const AuditEventReplay = "replay_rendered"

// ErrUnsupportedLiveSchema names the refusal to consume or emit a live
// artifact recorded under a superseded schema. The live pipeline makes a
// clean cutover: an old assessment, decision package or stability record is
// never upgraded, re-admitted or reinterpreted as a current human decision.
// Historical extraction stays available through the explicitly historical
// offline readers.
var ErrUnsupportedLiveSchema = errors.New("agenttriage: unsupported live artifact schema version")

// phase1DetToolSurface is the deterministic-tool surface Phase 1 runs
// advertised, frozen by name. A history-only replay (a run that predates
// prompt-input.v1) must reproduce the recorded prompt byte-for-byte, so it
// reconstructs exactly this surface instead of today's session catalog — a
// newer capability set would silently re-admit tools the historical judgment
// never saw. This is a replay reconstruction of recorded history, never a
// live allowlist: live runs advertise the session-resolved catalog.
var phase1DetToolSurface = []string{
	"get_product_snapshot",
	"get_dependency_graph",
	"get_module_version",
	"run_govulncheck",
	"find_symbol",
	"find_references",
	"find_callers",
	"find_may_callers",
	"module_usage",
	"dep_invocation_state",
	"check_call_site_guard",
	"gated_refs",
	"find_validations",
	"check_missing_call",
	"verify_code_absence",
	"symbol-unreachability",
}

// phase1DetCatalog projects the frozen Phase 1 surface onto the broker
// catalog: registered checks only, in the frozen order. A name that no longer
// resolves is simply absent — the reconstruction can never invent a tool.
func phase1DetCatalog() []DetToolInfo {
	byName := map[string]DetToolInfo{}
	for _, info := range CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog()) {
		byName[info.Name] = info
	}
	out := make([]DetToolInfo, 0, len(phase1DetToolSurface))
	for _, name := range phase1DetToolSurface {
		if info, ok := byName[name]; ok {
			out = append(out, info)
		}
	}
	return out
}

// unsupportedLiveSchema renders the actionable unsupported-version error:
// which artifact, which version was found, which version the live pipeline
// consumes, and where the historical record can still be read.
func unsupportedLiveSchema(artifact, got, want string) error {
	return fmt.Errorf("%w: %s schema_version %q is history only; the live pipeline consumes %s. Re-record the run with the live schema; the historical record remains readable only through the offline extractors and is never regenerated into a current artifact", ErrUnsupportedLiveSchema, artifact, got, want)
}

type ReplayDocument struct {
	SchemaVersion        string `json:"schema_version"`
	RunID                string `json:"run_id"`
	FindingID            string `json:"finding_id"`
	RerenderOf           string `json:"rerender_of"`
	SourceRunID          string `json:"source_run_id,omitempty"`
	SourceAssessmentHash string `json:"source_assessment_hash,omitempty"`
	InputHash            string `json:"input_hash,omitempty"`
	SnapshotHash         string `json:"snapshot_hash,omitempty"`
	// BuildTarget is the product build the recorded run identified, after
	// replay re-derived it from the recorded inputs. Absent means the run
	// had no identified product target.
	BuildTarget         *domain.ProductTarget `json:"build_target,omitempty"`
	PromptHash          string                `json:"prompt_hash,omitempty"`
	ResponseHash        string                `json:"response_hash,omitempty"`
	AssessmentHash      string                `json:"assessment_hash,omitempty"`
	AssessmentHashMatch bool                  `json:"assessment_hash_match"`
	DecisionHash        string                `json:"decision_hash,omitempty"`
	SourceDecisionHash  string                `json:"source_decision_hash,omitempty"`
	DecisionHashMatch   bool                  `json:"decision_hash_match,omitempty"`
	// The per-axis comparison: replay preserves the recorded judgment and
	// proposed action and re-derives the premise closure, support and
	// machine disposition. Each axis records its own hash and match flag so
	// a support or machine-admissibility divergence is visible instead of
	// being collapsed into the aggregate decision hash.
	JudgmentHash                 string `json:"judgment_hash,omitempty"`
	SourceJudgmentHash           string `json:"source_judgment_hash,omitempty"`
	JudgmentMatch                bool   `json:"judgment_match,omitempty"`
	ActionHash                   string `json:"action_hash,omitempty"`
	SourceActionHash             string `json:"source_action_hash,omitempty"`
	ActionMatch                  bool   `json:"action_match,omitempty"`
	PremisesHash                 string `json:"premises_hash,omitempty"`
	SourcePremisesHash           string `json:"source_premises_hash,omitempty"`
	PremisesMatch                bool   `json:"premises_match,omitempty"`
	SupportHash                  string `json:"support_hash,omitempty"`
	SourceSupportHash            string `json:"source_support_hash,omitempty"`
	SupportMatch                 bool   `json:"support_match,omitempty"`
	MachineDispositionHash       string `json:"machine_disposition_hash,omitempty"`
	SourceMachineDispositionHash string `json:"source_machine_disposition_hash,omitempty"`
	MachineDispositionMatch      bool   `json:"machine_disposition_match,omitempty"`
	// HumanDecisions is the verified append-only Accept/Reject history of
	// the source run, copied verbatim into the replay output.
	// HumanDecisionHashes are the sha256 values of those original record
	// bytes, in the same order.
	HumanDecisions      []HumanDecisionRecord `json:"human_decisions,omitempty"`
	HumanDecisionHashes []string              `json:"human_decision_hashes,omitempty"`
	HumanReviewProjection *HumanReviewProjection `json:"human_review_projection,omitempty"`
	EnvironmentAssertionHashes []string `json:"environment_assertion_hashes,omitempty"`
	// Limitations records replay-time provenance notes propagated from
	// ReplayReport — e.g. an opted-in derived catalog binding.
	Limitations []string `json:"limitations,omitempty"`
	GeneratedAt string   `json:"generated_at,omitempty"`
}

// ReplayReport is the in-memory result of PrepareReplay: the verified inputs
// of a recorded run plus the re-composed assessment. Nothing is written;
// ArtifactWriter.WriteReplay persists it.
type ReplayReport struct {
	// Limitations records replay-time provenance notes — an opted-in
	// derived binding, attempt inference — propagated into replay.json.
	Limitations []string
	SourceDir   string
	SourceRunID string
	FindingID   string
	Input       FindingInput
	Manifest    SnapshotManifest
	Raw         RawAgentDocument
	Assessment  Assessment
	PromptHash  string
	// PromptInput is the verified prompt-input.v1 surface when the run
	// persisted one; nil for history-only runs.
	PromptInput *PromptInput
	// Investigation is the verified captured-set metadata projection when
	// the run persisted one; nil for runs without captured inputs.
	Investigation *InvestigationProjection
	// BuildTarget is the product build the run identified, re-derived from
	// the recorded inputs and verified against the persisted record. Nil
	// means the recorded run had no identified product target.
	BuildTarget      *domain.ProductTarget
	SourceAssessment Assessment
	Decision         *DecisionPackage
	SourceDecision   *DecisionPackage
	// Stability is the recorded stability.json retry report when the run
	// executed stabilization passes; nil for runs without them.
	Stability    *StabilityDocument
	InputJSON    []byte
	ManifestJSON []byte
	RawJSON      []byte
	FactGate     *FactValidation
	// RecomputedFalsifier is the falsifier report replay re-derived from
	// the selected attempt's own observations — never the persisted
	// document. Nil when the run recorded no falsifier surface.
	RecomputedFalsifier *FalsifierReport
	DecisionMarkdown    []byte
	SourceDecisionMD    []byte
	// HumanDecisions is the verified review history of SourceDecision, in
	// recorded order. HumanDecisionHashes are the sha256 values of the
	// original source record bytes. humanDecisionFiles retains those bytes
	// so WriteReplay copies them without re-encoding or re-stamping.
	HumanDecisions      []HumanDecisionRecord
	HumanDecisionHashes []string
	humanDecisionFiles  []humanDecisionFile
	environmentAssertionFiles []environmentAssertionFile
	HumanReviewProjection *HumanReviewProjection
}

// ReplayRun re-executes the deterministic part of a recorded triage run —
// input/snapshot/raw-response verification, recorded data consistency and
// fact-gate replay plus assessment composition — without any LLM call,
// network access or live repository read. It returns the re-composed
// assessment; the source run directory is never modified. Missing files,
// inconsistent recorded data or a response that no longer decodes are
// technical errors, never a new verdict. Drift detection against the live
// repository is a separate opt-in check (VerifySnapshotDrift).
func ReplayRun(ctx context.Context, runDir string) (Assessment, error) {
	rep, err := PrepareReplay(ctx, runDir)
	if err != nil {
		return Assessment{}, err
	}
	return rep.Assessment, nil
}

// ErrLegacyCatalogUnbound names the replay refusal for a proof-bearing
// run that persisted condition-catalog.json without catalog-binding.json.
// The live path pinned the catalog hash through the binding; deriving the
// pin from the catalog itself accepts any catalog whose self-hash is
// consistent, so hash drift since the run is undetectable. Replaying
// falsifier evidence without the persisted pin can silently accept
// evidence the run never bound — the replay refuses unless the caller
// opts in explicitly (ReplayOptions.AllowLegacyUnboundBinding), in which
// case the acceptance is recorded in the replay report.
var ErrLegacyCatalogUnbound = errors.New("agenttriage: legacy catalog has no persisted binding")

// ReplayOptions tunes PrepareReplay; the zero value is the strict
// contract every caller gets by default.
type ReplayOptions struct {
	// AllowLegacyUnboundBinding permits a proof-bearing legacy run that
	// recorded condition-catalog.json but not catalog-binding.json to
	// replay under the derived binding (advisory identity + the catalog's
	// own hash as pin). The limitation is recorded in the returned
	// ReplayReport — hash drift since the run stays undetectable.
	AllowLegacyUnboundBinding bool
}

// PrepareReplay loads and verifies one recorded run directory. Every check
// is fail-closed: a mismatch between recorded hashes and recomputed ones is
// a technical error, not a different assessment. Replay consumes only saved
// artifacts — it never resolves refs, re-hashes the working tree or reads
// the repository the manifest names.
func PrepareReplay(ctx context.Context, runDir string) (ReplayReport, error) {
	return PrepareReplayWithOptions(ctx, runDir, ReplayOptions{})
}

// PrepareReplayWithOptions is PrepareReplay with the explicit option set;
// the only supported relaxation is AllowLegacyUnboundBinding.
func PrepareReplayWithOptions(ctx context.Context, runDir string, opts ReplayOptions) (ReplayReport, error) {
	var rep ReplayReport
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return rep, errors.New("agenttriage: replay: run directory is empty")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, err)
	}
	if !info.IsDir() {
		return rep, fmt.Errorf("agenttriage: replay %s: not a directory", dir)
	}
	if abs, aerr := filepath.Abs(dir); aerr == nil {
		dir = abs
	}
	if canon, cerr := filepath.EvalSymlinks(dir); cerr == nil {
		dir = canon
	}
	rep.SourceDir = dir

	read := func(name string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("agenttriage: replay %s: cannot read %s: %w", dir, name, err)
		}
		return data, nil
	}

	inputBytes, err := read("input.json")
	if err != nil {
		return rep, err
	}
	// The recorded input_hash pins the verbatim file bytes: ArtifactWriter
	// stores in.Raw unchanged, so whitespace appended later still counts
	// as drift rather than a different-but-equivalent record.
	inputFileHash := hashBytes(inputBytes)
	findings, err := ParseFindings(bytes.NewReader(inputBytes))
	if err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: input.json: %w", dir, err)
	}
	if len(findings) != 1 {
		return rep, fmt.Errorf("agenttriage: replay %s: input.json holds %d findings, a run directory records exactly one", dir, len(findings))
	}
	rep.Input = findings[0]
	rep.FindingID = rep.Input.Finding.FindingID

	manifestBytes, err := read("snapshot.json")
	if err != nil {
		return rep, err
	}
	rep.ManifestJSON = manifestBytes
	var manifest SnapshotManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: snapshot.json does not parse: %w", dir, err)
	}
	rep.Manifest = manifest
	if manifest.SchemaVersion != SnapshotSchemaVersion {
		return rep, fmt.Errorf("agenttriage: replay %s: snapshot.json schema %q is not %s", dir, manifest.SchemaVersion, SnapshotSchemaVersion)
	}
	if manifest.FindingID != rep.FindingID {
		return rep, fmt.Errorf("agenttriage: replay %s: snapshot finding_id %q does not match input finding_id %q", dir, manifest.FindingID, rep.FindingID)
	}
	if manifest.InputHash != inputFileHash {
		return rep, fmt.Errorf("agenttriage: replay %s: input drift: input.json sha256 %s does not match recorded input_hash %s", dir, inputFileHash, manifest.InputHash)
	}
	if rep.Input.SHA256 != inputFileHash {
		return rep, fmt.Errorf("agenttriage: replay %s: input drift: parsed record sha256 %s does not match input.json bytes %s", dir, rep.Input.SHA256, inputFileHash)
	}
	// Stage 0 provenance: a snapshot recorded with materialization metadata
	// must be internally consistent — the pinned content hash, the selected
	// ref and the resolved commit it observed. Drift or disagreement is a
	// technical error, not a different snapshot.
	if md := manifest.Materialization; md.Mode != "" || md.SourceID != "" {
		if md.RootHash != "" && manifest.ContentHash != "" && md.RootHash != manifest.ContentHash {
			return rep, fmt.Errorf("agenttriage: replay %s: materialization root_hash %s does not match snapshot content_hash %s", dir, md.RootHash, manifest.ContentHash)
		}
		if md.ResolvedCommit != "" && manifest.ResolvedRevision != "" && md.ResolvedCommit != manifest.ResolvedRevision {
			return rep, fmt.Errorf("agenttriage: replay %s: materialization commit %s does not match resolved_revision %s", dir, md.ResolvedCommit, manifest.ResolvedRevision)
		}
	}
	// Stage 0 auxiliary artifacts are part of the run's provenance: when
	// present they must parse, and the recorded intake identity must match
	// the ticket hash the run claimed.
	if b, rerr := os.ReadFile(filepath.Join(dir, "intake.json")); rerr == nil {
		var rec intakeRecordDoc
		if err := json.Unmarshal(b, &rec); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: intake.json does not parse: %w", dir, err)
		}
		if rec.SchemaVersion != IntakeRecordSchemaVersion {
			return rep, fmt.Errorf("agenttriage: replay %s: intake.json schema %q is not %s", dir, rec.SchemaVersion, IntakeRecordSchemaVersion)
		}
		if got := hashBytes([]byte(rec.Raw)); got != rec.TicketHash {
			return rep, fmt.Errorf("agenttriage: replay %s: intake drift: ticket_hash %s does not match record bytes %s", dir, rec.TicketHash, got)
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read intake.json: %w", dir, rerr)
	}
	var stageDoc stage0Document
	stageDocLoaded := false
	if b, rerr := os.ReadFile(filepath.Join(dir, "stage0.json")); rerr == nil {
		if err := json.Unmarshal(b, &stageDoc); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: stage0.json does not parse: %w", dir, err)
		}
		if stageDoc.SchemaVersion != Stage0DocumentSchemaVersion {
			return rep, fmt.Errorf("agenttriage: replay %s: stage0.json schema %q is not %s", dir, stageDoc.SchemaVersion, Stage0DocumentSchemaVersion)
		}
		stageDocLoaded = true
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read stage0.json: %w", dir, rerr)
	}
	// Captured investigation material: the metadata projection must be
	// internally consistent, agree with the Stage 0 projection when both
	// were persisted, and every digest-addressed archived blob must still
	// reproduce its recorded digest and size. A tampered or missing archive
	// is drift, never a partial read.
	investigationProjection, perr := ReadInvestigationProjection(dir)
	if perr != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, perr)
	}
	if investigationProjection != nil {
		rep.Investigation = investigationProjection
		if stageDocLoaded && stageDoc.Investigation != nil && !jsonEqual(*investigationProjection, *stageDoc.Investigation) {
			return rep, fmt.Errorf("agenttriage: replay %s: %s disagrees with the Stage 0 investigation projection", dir, InvestigationInputsArtifactName)
		}
	} else if stageDocLoaded && stageDoc.Investigation != nil && !stageDoc.Investigation.Empty() {
		return rep, fmt.Errorf("agenttriage: replay %s: stage0.json records captured investigation inputs but %s is missing", dir, InvestigationInputsArtifactName)
	}

	// agentIn reconstructs the finding view the agent and fact gate saw:
	// the stored intake-normalized input.json enriched with the frozen
	// advisory recorded in stage0.json — deterministic, offline, identical
	// to the live run. Legacy run dirs without stage0.json keep rep.Input.
	agentIn := rep.Input
	var agentAdvisory *AdvisoryProjection
	if stageDocLoaded {
		agentIn = Stage0AgentFinding(rep.Input, stageDoc.ResolutionVuln)
		agentAdvisory = &stageDoc.ResolutionProjection
	}

	rawBytes, err := read("raw-agent.json")
	if err != nil {
		return rep, err
	}
	rep.RawJSON = rawBytes
	var doc RawAgentDocument
	if err := json.Unmarshal(rawBytes, &doc); err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: raw-agent.json does not parse: %w", dir, err)
	}
	rep.Raw = doc
	rep.SourceRunID = doc.RunID
	if doc.SchemaVersion != RawAgentSchemaVersion {
		return rep, fmt.Errorf("agenttriage: replay %s: raw-agent.json schema %q is not %s", dir, doc.SchemaVersion, RawAgentSchemaVersion)
	}
	if doc.FindingID != rep.FindingID {
		return rep, fmt.Errorf("agenttriage: replay %s: raw-agent finding_id %q does not match input finding_id %q", dir, doc.FindingID, rep.FindingID)
	}
	if len(doc.Messages) == 0 || doc.Messages[len(doc.Messages)-1].Role != "assistant" {
		return rep, fmt.Errorf("agenttriage: replay %s: raw-agent.json ends without an assistant response", dir)
	}
	lastMsg := doc.Messages[len(doc.Messages)-1]
	assessmentVersion := recordedAssessmentVersion(lastMsg.Content)
	if assessmentVersion != AssessmentSchemaVersion && assessmentVersion != "assessment.v2" {
		return rep, unsupportedLiveSchema("raw-agent.json assessment", assessmentVersion, AssessmentSchemaVersion)
	}
	agentAssessment, err := decodeAssessmentSchema(lastMsg.Content, rep.FindingID, assessmentVersion)
	if err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: recorded agent response no longer decodes as %s: %w", dir, AssessmentSchemaVersion, err)
	}
	if got := hashBytes([]byte(lastMsg.Content)); doc.ResponseHash != "" && doc.ResponseHash != got {
		return rep, fmt.Errorf("agenttriage: replay %s: response drift: recorded response hash %s, recomputed %s", dir, doc.ResponseHash, got)
	}

	// Stability record: when the run executed retries, stability.json must
	// parse, belong to this run and finding, and agree with the retry
	// transcripts pinned in raw-agent.json — every recorded run must keep
	// the same prompt hash and reproduce its recorded response hash.
	// Tampering is drift: a technical error, never a different verdict.
	if b, rerr := os.ReadFile(filepath.Join(dir, "stability.json")); rerr == nil {
		var sd StabilityDocument
		if err := json.Unmarshal(b, &sd); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: stability.json does not parse: %w", dir, err)
		}
		if sd.SchemaVersion != StabilitySchemaVersion {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, unsupportedLiveSchema("stability.json", sd.SchemaVersion, StabilitySchemaVersion))
		}
		if sd.FindingID != rep.FindingID || sd.RunID != doc.RunID {
			return rep, fmt.Errorf("agenttriage: replay %s: stability.json is bound to another run or finding", dir)
		}
		if sd.Retries != len(doc.StabilityRuns) {
			return rep, fmt.Errorf("agenttriage: replay %s: stability.json records %d retries, raw-agent.json pins %d", dir, sd.Retries, len(doc.StabilityRuns))
		}
		if len(sd.Attempts) != len(doc.StabilityRuns)+1 {
			return rep, fmt.Errorf("agenttriage: replay %s: stability.json records %d attempts for %d retries", dir, len(sd.Attempts), len(doc.StabilityRuns))
		}
		for i, at := range sd.Attempts {
			if at.PromptHash != doc.PromptHash {
				return rep, fmt.Errorf("agenttriage: replay %s: stability drift: attempt %d prompt_hash %s differs from the run prompt_hash %s", dir, at.Attempt, at.PromptHash, doc.PromptHash)
			}
			if rep.Input.SHA256 != "" && at.InputHash != rep.Input.SHA256 {
				return rep, fmt.Errorf("agenttriage: replay %s: stability drift: attempt %d input_hash %s differs from the recorded input hash %s", dir, at.Attempt, at.InputHash, rep.Input.SHA256)
			}
			if manifest.ContentHash != "" && at.SnapshotHash != manifest.ContentHash {
				return rep, fmt.Errorf("agenttriage: replay %s: stability drift: attempt %d snapshot_hash %s differs from snapshot content_hash %s", dir, at.Attempt, at.SnapshotHash, manifest.ContentHash)
			}
			if i == 0 {
				continue
			}
			r := doc.StabilityRuns[i-1]
			if r.PromptHash != "" && r.PromptHash != doc.PromptHash {
				return rep, fmt.Errorf("agenttriage: replay %s: stability drift: retry %d ran a different prompt %s", dir, at.Attempt, r.PromptHash)
			}
			if len(r.Messages) == 0 || r.Messages[len(r.Messages)-1].Role != "assistant" {
				return rep, fmt.Errorf("agenttriage: replay %s: stability_runs attempt %d ends without an assistant response", dir, at.Attempt)
			}
			if got := hashBytes([]byte(r.Messages[len(r.Messages)-1].Content)); r.ResponseHash != "" && r.ResponseHash != got {
				return rep, fmt.Errorf("agenttriage: replay %s: stability drift: retry %d response hash %s recomputes to %s", dir, at.Attempt, r.ResponseHash, got)
			}
		}
		rep.Stability = &sd
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read stability.json: %w", dir, rerr)
	}

	// Canonical-attempt selection: the run may have persisted a package
	// composed from a stability retry, not the primary transcript. The
	// recorded assessment.json's audit.response_hash pins which attempt's
	// response the verdict depends on — replay must reconstruct THAT
	// attempt, never assume attempt 1. Candidates: the primary transcript
	// tail (attempt 1) followed by every stability_runs tail (attempt
	// N+1).
	// stability.json's selected_attempt is the authoritative pin; the
	// recorded assessment.json's audit.response_hash cross-checks it —
	// replay must reconstruct THAT attempt, never assume attempt 1.
	// Candidates: the primary transcript tail (attempt 1) followed by
	// every stability_runs tail (attempt N+1). Legacy runs predate
	// selected_attempt: fall back to the response-hash scan.
	selectedAttempt := 1
	selectedMsg := lastMsg
	var storedAudit struct {
		Audit *struct {
			ResponseHash string `json:"response_hash"`
		} `json:"audit"`
	}
	if ab, aerr := os.ReadFile(filepath.Join(dir, "assessment.json")); aerr == nil {
		_ = json.Unmarshal(ab, &storedAudit)
	}
	wantHash := ""
	if storedAudit.Audit != nil {
		wantHash = storedAudit.Audit.ResponseHash
	}
	// The recorded pin decides; the response-hash check below verifies it
	// rather than guessing. An out-of-range pin is drift.
	if rep.Stability != nil && rep.Stability.SelectedAttempt > 0 {
		n := rep.Stability.SelectedAttempt
		if n < 1 || n > len(doc.StabilityRuns)+1 {
			return rep, fmt.Errorf("agenttriage: replay %s: stability.json selected_attempt %d out of range (%d attempts)", dir, n, len(doc.StabilityRuns)+1)
		}
		if n > 1 {
			r := doc.StabilityRuns[n-2]
			if len(r.Messages) == 0 || r.Messages[len(r.Messages)-1].Role != "assistant" {
				return rep, fmt.Errorf("agenttriage: replay %s: selected attempt %d ends without an assistant response", dir, n)
			}
			selectedMsg = r.Messages[len(r.Messages)-1]
		}
		selectedAttempt = n
	}
	if wantHash != "" && selectedAttempt == 1 && len(doc.StabilityRuns) > 0 && hashBytes([]byte(lastMsg.Content)) != wantHash {
		// No recorded pin: scan the recorded attempts for the hash —
		// the legacy inference path this field replaced.
		found := false
		for i, r := range doc.StabilityRuns {
			if len(r.Messages) == 0 {
				continue
			}
			m := r.Messages[len(r.Messages)-1]
			if m.Role == "assistant" && hashBytes([]byte(m.Content)) == wantHash {
				selectedMsg = m
				selectedAttempt = i + 2 // attempt 1 is the primary transcript
				found = true
				break
			}
		}
		if !found {
			return rep, fmt.Errorf("agenttriage: replay %s: assessment.json audit.response_hash %s matches no recorded attempt — canonical attempt is unresolvable", dir, wantHash)
		}
	}
	selectedResponseHash := hashBytes([]byte(selectedMsg.Content))
	if selectedAttempt != 1 {
		var derr error
		agentAssessment, derr = decodeAssessmentSchema(selectedMsg.Content, rep.FindingID, assessmentVersion)
		if derr != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: selected attempt %d response no longer decodes as %s: %w", dir, selectedAttempt, AssessmentSchemaVersion, derr)
		}
	}

	decisionBytes, decisionErr := os.ReadFile(filepath.Join(dir, "decision.json"))
	decisionPresent := decisionErr == nil
	if decisionErr != nil && !errors.Is(decisionErr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read decision.json: %w", dir, decisionErr)
	}
	if decisionPresent && !stageDocLoaded {
		return rep, fmt.Errorf("agenttriage: replay %s: decision.json requires stage0.json provenance", dir)
	}
	// fact-gate.json is the recorded gate the offline replay replays. It is
	// loaded whenever present — a recorded decision requires it, a run
	// without a decision still replays the stored validation.
	if b, ferr := os.ReadFile(filepath.Join(dir, "fact-gate.json")); ferr == nil {
		var fg factGateDocument
		if err := json.Unmarshal(b, &fg); err != nil || fg.SchemaVersion != FactGateSchemaVersion {
			return rep, fmt.Errorf("agenttriage: replay %s: fact-gate.json is invalid", dir)
		}
		rep.FactGate = &fg.Validation
	} else if decisionPresent {
		return rep, fmt.Errorf("agenttriage: replay %s: fact-gate.json is required: %w", dir, ferr)
	} else if !errors.Is(ferr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read fact-gate.json: %w", dir, ferr)
	}
	if decisionPresent {
		// The live schema is a clean cutover: a decision-package.v2 (or
		// any other historical version) is never upgraded or reinterpreted
		// as a current human package. Its judgment and action are history —
		// the offline extractors read them, replay does not.
		var decisionHead struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(decisionBytes, &decisionHead); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: decision.json does not parse: %w", dir, err)
		}
		decisionVersion := DecisionPackageSchemaVersion
		if assessmentVersion == "assessment.v2" { decisionVersion = "decision-package.v3" }
		if decisionHead.SchemaVersion != decisionVersion {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, unsupportedLiveSchema("decision.json", decisionHead.SchemaVersion, decisionVersion))
		}
		var decision DecisionPackage
		if err := validateRecordedDecisionJSON(decisionBytes, decisionVersion); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: decision.json is invalid: %w", dir, err)
		}
		if err := json.Unmarshal(decisionBytes, &decision); err != nil {
			return rep, err
		}
		rep.SourceDecision = &decision
		if md, err := os.ReadFile(filepath.Join(dir, "decision.md")); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: decision.md is required: %w", dir, err)
		} else {
			rep.SourceDecisionMD = md
			if !bytes.Equal(md, RenderDecisionMarkdown(decision)) {
				return rep, fmt.Errorf("agenttriage: replay %s: decision.md drift: rendered bytes differ", dir)
			}
		}
		files, herr := readHumanDecisionFilesSchema(dir, decision, decisionVersion)
		if herr != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, herr)
		}
		// Capture assertions after the decision snapshot: concurrent writers can
		// only append, so every assertion referenced by these records is present.
		assertions, aerr := ReadEnvironmentAssertions(dir, decision)
		if aerr != nil { return rep, aerr }
		if len(assertions) > 0 {
			unlock, err := flock.Shared(filepath.Join(dir, humanDecisionsLockName))
			if err != nil { return rep, err }
			rep.environmentAssertionFiles, aerr = readEnvironmentAssertionFilesUnlocked(dir, decision)
			unlock()
			if aerr != nil { return rep, aerr }
		}
		if decision.SchemaVersion == DecisionPackageSchemaVersion {
			var captured []EnvironmentAssertion
			for _, file := range rep.environmentAssertionFiles { captured = append(captured, file.Assertion) }
			projection, err := ApplyEnvironmentAssertions(decision, captured)
			if err != nil { return rep, err }
			rep.HumanReviewProjection = &projection
		}
		rep.humanDecisionFiles = files
		for _, f := range files {
			rep.HumanDecisions = append(rep.HumanDecisions, f.Record)
			rep.HumanDecisionHashes = append(rep.HumanDecisionHashes, hashBytes(f.Bytes))
		}
	} else {
		// Review history is only meaningful beside the package it binds
		// to; stray records are a contradiction, not an empty history.
		entries, derr := os.ReadDir(filepath.Join(dir, humanDecisionsDirName))
		if derr == nil && len(entries) > 0 {
			return rep, fmt.Errorf("agenttriage: replay %s: human decisions exist without a decision.json", dir)
		}
		if derr != nil && !errors.Is(derr, os.ErrNotExist) {
			return rep, fmt.Errorf("agenttriage: replay %s: read human decisions: %w", dir, derr)
		}
		assertionEntries, assertionErr := os.ReadDir(filepath.Join(dir, environmentAssertionsDirName))
		if assertionErr == nil && len(assertionEntries) > 0 { return rep, fmt.Errorf("environment assertions exist without a decision.json") }
		if assertionErr != nil && !errors.Is(assertionErr, os.ErrNotExist) { return rep, assertionErr }
	}
	if rep.Stability != nil && rep.Stability.Drift && decisionPresent {
		return rep, fmt.Errorf("agenttriage: replay %s: drift: a drifted stability run must not carry a decision package", dir)
	}
	if decisionPresent && rep.SourceDecision != nil && rep.SourceDecision.TechnicalAssessment.StabilityResult != "" && rep.Stability == nil {
		return rep, fmt.Errorf("agenttriage: replay %s: decision.json records stability_result %q but stability.json is missing", dir, rep.SourceDecision.TechnicalAssessment.StabilityResult)
	}
	if rep.Stability != nil && rep.SourceDecision != nil {
		want := "unstable"
		if rep.Stability.Stable {
			want = "stable"
		}
		if got := rep.SourceDecision.TechnicalAssessment.StabilityResult; got != "" &&
			((want == "stable") != (got == "stable")) {
			return rep, fmt.Errorf("agenttriage: replay %s: decision stability_result %q disagrees with stability.json stable=%v", dir, got, rep.Stability.Stable)
		}
	}

	assessmentBytes, err := read("assessment.json")
	if err != nil {
		return rep, err
	}
	var stored Assessment
	if err := json.Unmarshal(assessmentBytes, &stored); err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: assessment.json does not parse: %w", dir, err)
	}
	rep.SourceAssessment = stored
	if stored.SchemaVersion != assessmentVersion {
		return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, unsupportedLiveSchema("assessment.json", stored.SchemaVersion, assessmentVersion))
	}
	if stored.FindingID != rep.FindingID {
		return rep, fmt.Errorf("agenttriage: replay %s: assessment finding_id %q does not match input finding_id %q", dir, stored.FindingID, rep.FindingID)
	}
	if stored.VerdictSource != "agent" {
		return rep, fmt.Errorf("agenttriage: replay %s: assessment verdict_source %q is not %q", dir, stored.VerdictSource, "agent")
	}
	// The agent-owned fields of the stored assessment must reproduce from
	// the recorded raw response; composed fields (schema, finding id,
	// verdict_source, validation, audit) are cleared on both sides before
	// comparing. The machine policy outcome lives in the decision package's
	// machine disposition and is re-derived with it.
	storedAgent := stored
	storedAgent.SchemaVersion, storedAgent.FindingID, storedAgent.VerdictSource = "", "", ""
	storedAgent.FactValidation, storedAgent.FactValidationDetail = "", nil
	storedAgent.Audit = nil
	agentCmp := agentAssessment
	agentCmp.SchemaVersion, agentCmp.FindingID, agentCmp.VerdictSource = "", "", ""
	agentCmp.FactValidation, agentCmp.FactValidationDetail = "", nil
	agentCmp.Audit = nil
	wantBytes, _ := json.Marshal(storedAgent)
	gotBytes, _ := json.Marshal(agentCmp)
	if !bytes.Equal(wantBytes, gotBytes) {
		return rep, fmt.Errorf("agenttriage: replay %s: assessment.json agent fields do not reproduce from raw-agent.json", dir)
	}
	audit := stored.Audit
	if audit == nil {
		return rep, fmt.Errorf("agenttriage: replay %s: assessment.json has no audit block", dir)
	}
	if audit.FindingHash != inputFileHash {
		return rep, fmt.Errorf("agenttriage: replay %s: recorded audit finding_hash %s does not match input.json sha256 %s", dir, audit.FindingHash, inputFileHash)
	}
	if audit.SnapshotHash != manifest.ContentHash {
		return rep, fmt.Errorf("agenttriage: replay %s: recorded audit snapshot_hash %s does not match snapshot content_hash %s", dir, audit.SnapshotHash, manifest.ContentHash)
	}

	// Product build identity: re-derive the one selection the recorded
	// inputs describe, require the run's persisted build target to
	// reproduce it, and carry it into the replay surface. A new run that
	// identified a target must have persisted it; a history-only run is
	// never retroactively given a target it did not use.
	hasPromptInput := false
	if _, serr := os.Stat(filepath.Join(dir, PromptInputArtifactName)); serr == nil {
		hasPromptInput = true
	} else if !errors.Is(serr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read %s: %w", dir, PromptInputArtifactName, serr)
	}
	var recordedInputs InvestigationInputs
	if rep.Investigation != nil {
		inputs, ierr := rep.Investigation.Inputs()
		if ierr != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, ierr)
		}
		recordedInputs = inputs
	}
	resolvedBuild, berr := ResolveBuildTarget(rep.Input, recordedInputs, manifest)
	if berr != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: product build target: %w", dir, berr)
	}
	recordedBuild := cloneBuildTarget(recordedInputs.BuildTarget)
	if stageDocLoaded && stageDoc.BuildTarget != nil {
		staged := cloneBuildTarget(stageDoc.BuildTarget)
		if recordedBuild != nil {
			if cmp := compareBuildTargets(*recordedBuild, *staged); cmp != nil {
				return rep, fmt.Errorf("agenttriage: replay %s: stage0.json build_target disagrees with %s: %w", dir, InvestigationInputsArtifactName, cmp)
			}
		}
		recordedBuild = staged
	}
	if recordedBuild != nil {
		admitted, aerr := admitBuildTarget("recorded product build target", recordedBuild, manifest)
		if aerr != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, aerr)
		}
		recordedBuild = admitted
		if resolvedBuild == nil {
			return rep, fmt.Errorf("agenttriage: replay %s: recorded product build target does not reproduce from the recorded finding/build inputs", dir)
		}
		if cmp := compareBuildTargets(*resolvedBuild, *recordedBuild); cmp != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: product build target drift: recorded target does not reproduce from the recorded inputs: %w", dir, cmp)
		}
	} else if resolvedBuild != nil && hasPromptInput {
		return rep, fmt.Errorf("agenttriage: replay %s: recorded inputs identify a product build target but the run persisted no build target", dir)
	}
	rep.BuildTarget = cloneBuildTarget(recordedBuild)
	agentIn.Finding.Target.Build = cloneBuildTarget(recordedBuild)

	// Prompt identity: prompt-input.v1 records the exact surface the run
	// sent (system text, initial data messages, advertised tool
	// definitions). When present it is authoritative for prompt
	// verification — replay must not rebuild it from today's tool
	// definitions, which would silently re-admit a newer capability
	// surface into a historical judgment.
	var promptInput *PromptInput
	if b, rerr := os.ReadFile(filepath.Join(dir, PromptInputArtifactName)); rerr == nil {
		var stored PromptInput
		if err := decodeStrictJSON(b, &stored); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: %s does not parse: %w", dir, PromptInputArtifactName, err)
		}
		if err := stored.Validate(); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, err)
		}
		if stored.Messages[0].Role != "user" {
			return rep, fmt.Errorf("agenttriage: replay %s: %s first message role %q is not user", dir, PromptInputArtifactName, stored.Messages[0].Role)
		}
		if doc.PromptHash != "" && doc.PromptHash != stored.PromptHash {
			return rep, fmt.Errorf("agenttriage: replay %s: raw-agent prompt_hash %s does not match persisted %s %s", dir, doc.PromptHash, PromptInputArtifactName, stored.PromptHash)
		}
		if audit.PromptHash != stored.PromptHash {
			return rep, fmt.Errorf("agenttriage: replay %s: recorded audit prompt_hash %s does not match persisted %s %s", dir, audit.PromptHash, PromptInputArtifactName, stored.PromptHash)
		}
		promptInput = &stored
		rep.PromptInput = promptInput
		rep.PromptHash = stored.PromptHash
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read %s: %w", dir, PromptInputArtifactName, rerr)
	} else {
		// History-only reader: Phase 1 runs predate prompt-input.json. The
		// surface is reconstructed exactly as before, recorded as a
		// limitation, and grants no new proof authority.
		defs := (&ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: agentAdvisory}).Definitions()
		if audit.DetTools {
			set := &ToolSet{Parts: []ToolExecutor{
				&ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: agentAdvisory},
				&DeterministicTools{Catalog: phase1DetCatalog()},
			}}
			defs = set.Definitions()
		}
		system := BuildPrompt(defs, audit.DetTools)
		if assessmentVersion == "assessment.v2" { system = buildPhase1Prompt(defs, audit.DetTools) }
		var replaySet MaterialSet
		materialsPersisted := false
		if b, rerr := os.ReadFile(filepath.Join(dir, "materials.json")); rerr == nil {
			materialsPersisted = true
			if err := json.Unmarshal(b, &replaySet); err != nil {
				return rep, fmt.Errorf("agenttriage: replay %s: materials.json does not parse: %w", dir, err)
			}
			if err := validateMaterialSet(replaySet); err != nil {
				return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, err)
			}
		}
		initial := []llm.ChatMessage{{Role: "user", Content: BuildDataMessage(agentIn, manifest, BuildAgentMaterials(replaySet))}, {Role: "user", Content: "Assess the finding using the available read-only snapshot tools."}}
		rep.PromptHash = PromptHash(system, initial)
		if doc.PromptHash != "" && doc.PromptHash != rep.PromptHash && !materialsPersisted && len(doc.Messages) > 0 && doc.Messages[0].Role == "user" {
			initial[0] = doc.Messages[0]
			rep.PromptHash = PromptHash(system, initial)
		}
		if audit.PromptHash != rep.PromptHash {
			return rep, fmt.Errorf("agenttriage: replay %s: recorded audit prompt_hash %s does not match recomputed %s", dir, audit.PromptHash, rep.PromptHash)
		}
		rep.Limitations = append(rep.Limitations,
			PromptInputArtifactName+" is absent (history-only run): the prompt surface was verified by historical reconstruction from the recorded tool flag, not from persisted bytes; this grants no new proof authority")
	}
	if audit.ResponseHash != "" && audit.ResponseHash != selectedResponseHash {
		return rep, fmt.Errorf("agenttriage: replay %s: audit response_hash %s does not match the selected attempt %d response %s", dir, audit.ResponseHash, selectedAttempt, selectedResponseHash)
	}
	if audit.AssessmentHash != "" && audit.AssessmentHash != canonicalAssessmentHash(stored) {
		return rep, fmt.Errorf("agenttriage: replay %s: recorded audit assessment_hash %s does not match assessment.json content", dir, audit.AssessmentHash)
	}

	// Snapshot consistency: the recorded manifest is verified against
	// itself and the recorded run only — replay never re-reads the live
	// repository (no git resolve, no content hash, no artifact bytes).
	// A caller that wants live drift detection opts into
	// VerifySnapshotDrift explicitly; it is outside the replay contract.
	if strings.TrimSpace(manifest.Repository) == "" {
		if manifest.ContentHash != "" {
			return rep, fmt.Errorf("agenttriage: replay %s: snapshot.json pins content_hash without a repository", dir)
		}
		if manifest.Revision != "" {
			return rep, fmt.Errorf("agenttriage: replay %s: snapshot.json pins revision %q without a repository", dir, manifest.Revision)
		}
	}
	// A recorded revision pins the resolved commit SHA: a manifest that
	// names a ref but was recorded before resolved_revision existed fails
	// closed — the run can never be proven to have pinned what it claimed.
	if manifest.Revision != "" && manifest.ResolvedRevision == "" {
		return rep, fmt.Errorf("agenttriage: replay %s: snapshot.json has no resolved_revision for pinned revision %q", dir, manifest.Revision)
	}
	for _, a := range manifest.Artifacts {
		if a.Path == "" || a.SHA256 == "" {
			return rep, fmt.Errorf("agenttriage: replay %s: snapshot.json artifact entry missing path/sha256", dir)
		}
	}

	// Re-run the deterministic composition from the recorded agent
	// response: same verdict, freshly computed fact gate.
	// The observation index det:<id> references verify against is rebuilt
	// from the recorded audit/events.jsonl of the source run. The gate
	// runs offline: it replays the recorded validation when one exists
	// and otherwise verifies only against recorded pins — live repository
	// bytes are never read here.
	composed := agentAssessment
	composed.SchemaVersion = assessmentVersion
	composed.FindingID = rep.FindingID
	composed.VerdictSource = "agent"
	fv := FactGate{
		// Audit tool-call events carry the agent run id; recorded archive
		// observations carry the attempt-qualified identity. They are two
		// different stamps and each index must use its own.
		Observations: observationIndexFromAudit(dir, rep.SourceRunID, selectedAttempt),
		Offline:      true,
		Recorded:     rep.FactGate,
	}.Validate(ctx, agentIn, manifest, agentAssessment)
	if err := ctx.Err(); err != nil {
		return rep, fmt.Errorf("agenttriage: replay %s: fact gate: %w", dir, err)
	}
	composed.FactValidation = fv.Status
	composed.FactValidationDetail = &fv
	composed.Audit = &AssessmentAudit{
		FindingHash:  rep.Input.SHA256,
		SnapshotHash: manifest.ContentHash,
		PromptHash:   rep.PromptHash,
		ResponseHash: selectedResponseHash,
		Model:        audit.Model,
		ToolVersions: audit.ToolVersions,
		DetTools:     audit.DetTools,
	}
	composed.Audit.AssessmentHash = canonicalAssessmentHash(composed)
	rep.Assessment = composed
	var s0 Stage0Result
	if stageDocLoaded {
		var serr error
		s0, serr = loadStage0Artifacts(dir, rep.Input, manifest, stageDoc)
		if serr != nil {
			return rep, serr
		}
	} else {
		s0 = Stage0Result{Input: rep.Input, Snapshot: manifest}
	}
	archive, aerr := ReadObservationArchive(filepath.Join(dir, "observation-archive.json"))
	if aerr != nil {
		if !errors.Is(aerr, os.ErrNotExist) || len(agentAssessment.FalsifierProposals) > 0 || rep.SourceDecision != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: observation archive: %w", dir, aerr)
		}
	}
	// Evidence is attempt-scoped: only the selected attempt's observations
	// may reach the recomputed verifier. The merged archive carries every
	// attempt's records; a sibling attempt's ids/RunID must never rebind
	// this attempt's proofs — the run-stamped RunID mismatch alone would
	// fail every proof, so a VERIFIED retry could never replay.
	var attemptObs []RecordedObservation
	for _, o := range archive.Observations {
		if o.Attempt == selectedAttempt {
			attemptObs = append(attemptObs, o)
		}
	}
	archive.Observations = attemptObs
	var persistedFalsifier *FalsifierReport
	if b, ferr := os.ReadFile(filepath.Join(dir, "falsifier-verification.json")); ferr == nil {
		var fr FalsifierReport
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fr); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: falsifier report does not parse: %w", dir, err)
		}
		if fr.SchemaVersion != FalsifierVerificationSchemaVersion || fr.Hash == "" || fr.Hash != reportHash(fr) {
			return rep, fmt.Errorf("agenttriage: replay %s: falsifier report hash/schema mismatch", dir)
		}
		persistedFalsifier = &fr
	} else if !errors.Is(ferr, os.ErrNotExist) {
		return rep, fmt.Errorf("agenttriage: replay %s: cannot read falsifier-verification.json: %w", dir, ferr)
	}
	if len(agentAssessment.FalsifierProposals) > 0 && persistedFalsifier == nil {
		return rep, fmt.Errorf("agenttriage: replay %s: falsifier-verification.json is required for proposals", dir)
	}
	var recomputedFalsifier *FalsifierReport
	if recomputedFalsifier == nil && ((persistedFalsifier != nil && len(persistedFalsifier.Proofs) > 0) || len(agentAssessment.FalsifierProposals) > 0) {
		ruleset := ""
		if rep.SourceDecision != nil {
			ruleset = rep.SourceDecision.Audit.RulesetHash
		}
		if ruleset == "" && persistedFalsifier != nil {
			ruleset = persistedFalsifier.RuleSetHash
		}
		var symbols []FalsifierSubject
		for _, s := range stageDoc.ResolutionProjection.AffectedSymbols {
			symbols = append(symbols, FalsifierSubject{Package: s.Package, Symbol: s.Symbol})
		}
		build := ""
		for _, o := range archive.Observations {
			if o.BuildContextHash != "" {
				build = o.BuildContextHash
				break
			}
		}
		advID := ""
		if len(rep.Input.Finding.Vulnerability.IDs) > 0 {
			advID = rep.Input.Finding.Vulnerability.IDs[0]
		}
		module, version := rep.Input.Finding.Component.Package, rep.Input.Finding.Component.Version
		if module == "" {
			module = rep.Input.Finding.Component.Name
		}
		ruleID, ruleVersion := "advisory-code-absence", "1"
		if persistedFalsifier != nil && len(persistedFalsifier.Proofs) > 0 {
			ruleID, ruleVersion = persistedFalsifier.Proofs[0].RuleID, persistedFalsifier.Proofs[0].RuleVersion
			if ruleID == "" {
				ruleID = "advisory-code-absence"
			}
			if ruleVersion == "" {
				ruleVersion = "1"
			}
		}
		source, serr := NewAdvisoryConditionSource(AdvisoryConditionOptions{
			AdvisoryID: advID, Module: module, ResolvedVersion: version,
			SnapshotHash: manifest.ContentHash, BuildContextHash: build,
			RuleID: ruleID, RuleVersion: ruleVersion, RuleSetHash: ruleset, Symbols: symbols,
		})
		if serr != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: falsifier source: %w", dir, serr)
		}
		// Catalog admission is re-enforced on replay exactly the way the
		// live run enforced it: the persisted catalog is checked against
		// the persisted run binding, and only admitted proposals reach the
		// verifier. A missing, stale, tampered or foreign catalog fails
		// closed — every proposal replays as a non-admitted proof, which
		// deterministically mismatches any persisted verified set.
		var replayCatalog *ConditionCatalog
		if cb, cerr := os.ReadFile(filepath.Join(dir, "condition-catalog.json")); cerr == nil {
			cat, cerr := DecodeConditionCatalog(cb)
			if cerr != nil {
				return rep, fmt.Errorf("agenttriage: replay %s: condition catalog does not parse: %w", dir, cerr)
			}
			replayCatalog = &cat
		} else if !errors.Is(cerr, os.ErrNotExist) {
			return rep, fmt.Errorf("agenttriage: replay %s: cannot read condition-catalog.json: %w", dir, cerr)
		}
		var binding CatalogBinding
		bindingLoaded := false
		if bb, berr := os.ReadFile(filepath.Join(dir, "catalog-binding.json")); berr == nil {
			var doc CatalogBindingDocument
			dec := json.NewDecoder(bytes.NewReader(bb))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&doc); err != nil {
				return rep, fmt.Errorf("agenttriage: replay %s: catalog binding does not parse: %w", dir, err)
			}
			if doc.SchemaVersion != CatalogBindingSchemaVersion {
				return rep, fmt.Errorf("agenttriage: replay %s: catalog binding schema %q is not %s", dir, doc.SchemaVersion, CatalogBindingSchemaVersion)
			}
			binding = doc.Binding()
			bindingLoaded = true
		} else if !errors.Is(berr, os.ErrNotExist) {
			return rep, fmt.Errorf("agenttriage: replay %s: cannot read catalog-binding.json: %w", dir, berr)
		}
		if !bindingLoaded && replayCatalog != nil {
			// Proof-bearing replay without the persisted binding pin:
			// the live path enforced the catalog's hash against the
			// recorded binding, so accepting a self-consistent catalog
			// here silently forgives any post-run drift. Refuse unless
			// the caller explicitly opted in — the recorded limitation
			// marks the replay's provenance weakened.
			if !opts.AllowLegacyUnboundBinding {
				return rep, fmt.Errorf("agenttriage: replay %s: %w (run persisted condition-catalog.json but not catalog-binding.json; pass AllowLegacyUnboundBinding to accept the derived-pin limitation)", dir, ErrLegacyCatalogUnbound)
			}
			rep.Limitations = append(rep.Limitations, "legacy run persisted no catalog-binding.json: catalog admission replayed under a derived pin (catalog self-hash); hash drift since the run is undetectable")
			// Derive the binding the live path enforced: the frozen
			// advisory's identity/digest, the finding's case identity,
			// and the catalog's own hash as the run pin. A foreign
			// advisory/case still fails.
			binding.CaseIdentityRef = rep.Input.Finding.FindingID
			binding.ExpectedCatalogHash = replayCatalog.CatalogHash
			if stageDocLoaded && (stageDoc.Advisory.SHA256 != "" || stageDoc.Advisory.ID != "") {
				binding.AdvisoryDigest = stageDoc.Advisory.SHA256
				binding.AdvisoryID = stageDoc.Advisory.ID
				if stageDoc.Advisory.ResolvedID != "" {
					binding.AdvisoryID = stageDoc.Advisory.ResolvedID
				}
			}
		}
		admission := GateFalsifierProposals(replayCatalog, binding, agentAssessment.FalsifierProposals)
		got := NewFalsifierVerifier(source).Verify(ctx, FalsifierVerificationInput{
			Stage0: s0, Assessment: agentAssessment, FactValidation: fv,
			Proposals: admission.Admitted, Observations: archive.Observations,
			RulesetHash: ruleset, ExpectedRulesetHash: ruleset, RunID: AttemptRunID(rep.FindingID, selectedAttempt), Attempt: selectedAttempt,
		})
		if len(admission.Rejected) > 0 {
			got.Proofs = append(got.Proofs, admission.Rejected...)
			got = NewFalsifierReport(got.RuleSetHash, got.Proofs...)
		}
		recomputedFalsifier = &got
		rep.RecomputedFalsifier = recomputedFalsifier
		// A valid persisted report may be stale: coverage changes are replayed as
		// a deterministic status transition, not accepted as persisted VERIFIED.
	}
	if recomputedFalsifier != nil && persistedFalsifier == nil {
		persistedFalsifier = recomputedFalsifier
	}
	if rep.SourceDecision != nil {
		c := Composer{
			RunID:           rep.SourceDecision.RunID,
			historicalReplay: assessmentVersion == "assessment.v2",
			ExecutionMode:   rep.SourceDecision.ExecutionMode,
			RulesetHash:     rep.SourceDecision.Audit.RulesetHash,
			Limits:          rep.SourceDecision.Audit.Limits,
			BudgetResult:    rep.SourceDecision.TechnicalAssessment.BudgetResult,
			StabilityResult: rep.SourceDecision.TechnicalAssessment.StabilityResult,
			// Recomposition uses the recorded baseline default when the
			// original package was built on a configured fallback; the
			// replay environment may not carry the site config.
			DefaultBaselineSeverity: recordedBaselineSeverity(*rep.SourceDecision),
		}
		if rep.Stability != nil {
			// Recompose with the recorded retry report so the package is
			// byte-identical; a drifted report never reaches this point.
			c.Stability = &rep.Stability.StabilityReport
		}
		decision, derr := c.ComposeWithEvidence(ctx, s0, composed, fv, EvidenceInput{
			Observations:    archive.Observations,
			Falsifiers:      recomputedFalsifier,
			SelectedAttempt: selectedAttempt,
		})
		if derr != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: decision composition: %w", dir, derr)
		}
		// The recorded judgment and proposed action are the history this
		// replay preserves; the premise closure, the support and the
		// machine disposition are re-derived. Comparing each axis first
		// makes the drift explicit instead of hiding a support or
		// admissibility change inside a generic package-hash mismatch.
		if err := compareDecisionAxes(*rep.SourceDecision, decision); err != nil {
			return rep, fmt.Errorf("agenttriage: replay %s: %w", dir, err)
		}
		if got, want := canonicalDecisionHash(decision), canonicalDecisionHash(*rep.SourceDecision); got != want {
			return rep, fmt.Errorf("agenttriage: replay %s: decision drift: recomposed hash %s differs from stored %s", dir, got, want)
		}
		rep.Decision = &decision
		if rep.FactGate == nil || !jsonEqual(*rep.FactGate, fv) {
			return rep, fmt.Errorf("agenttriage: replay %s: fact-gate drift: stored validation differs from recomputed validation", dir)
		}
	}
	rep.Assessment = composed
	return rep, nil
}

// recordedBaselineSeverity is the baseline severity the recorded package
// was composed under. Replay reproduces it without reading the current site
// config, and a package composed without severity metadata yields the empty
// value — no fallback is invented on replay.
func recordedBaselineSeverity(p DecisionPackage) string {
	if p.MachineDisposition.Baseline == nil {
		return ""
	}
	return p.MachineDisposition.Baseline.Severity
}

// compareDecisionAxes reports the first result axis whose recomputation
// disagrees with the recorded package, naming the axis explicitly. Replay
// preserves the recorded judgment and proposed action and never rewrites
// them; the decisive premises, the derived support and the machine
// disposition are the values replay re-derives, so drift there is reported
// as support drift or machine-admissibility drift instead of a generic hash
// mismatch. The recorded support value is never accepted in place of the
// recomputation.
func compareDecisionAxes(recorded, recomputed DecisionPackage) error {
	if !jsonEqual(recorded.Judgment, recomputed.Judgment) {
		return fmt.Errorf("judgment drift: the recorded judgment is preserved verbatim and is not re-derived, but the recomposed package carries %q instead of %q",
			recomputed.Judgment.Verdict, recorded.Judgment.Verdict)
	}
	if !jsonEqual(recorded.ProposedAction, recomputed.ProposedAction) {
		return fmt.Errorf("proposed action drift: the recorded human action %q is preserved verbatim, but the recomposed package carries %q",
			recorded.ProposedAction.Kind, recomputed.ProposedAction.Kind)
	}
	if !jsonEqual(recorded.Premises, recomputed.Premises) {
		return fmt.Errorf("decisive premise drift: the recomputed premise closure differs from the recorded one; the recorded premises are not reused")
	}
	if !jsonEqual(recorded.Support, recomputed.Support) {
		return fmt.Errorf("support drift: recomputed support %s differs from the recorded support %s; replay reports the recomputation and never accepts the recorded value in its place",
			recomputed.Support.Level, recorded.Support.Level)
	}
	if !jsonEqual(recorded.HumanReviewPlan, recomputed.HumanReviewPlan) {
		return fmt.Errorf("human review plan drift: branch assignments, actions, premises, status or support differ from code recomputation")
	}
	if !jsonEqual(recorded.MachineDisposition, recomputed.MachineDisposition) {
		return fmt.Errorf("machine admissibility drift: the recomputed machine disposition %s/%s differs from the recorded %s/%s; the recorded reduction is not re-admitted",
			recomputed.MachineDisposition.Recommendation, recomputed.MachineDisposition.Automation,
			recorded.MachineDisposition.Recommendation, recorded.MachineDisposition.Automation)
	}
	return nil
}

// decisionAxisHashes is the per-axis comparison replay.json records: the
// recomputed hash, the recorded hash and whether the two matched. Support
// and machine-admissibility drift are separate outcomes; the recorded
// judgment and action are preserved, so their match flags document that
// replay reproduced the same history.
type decisionAxisHashes struct {
	JudgmentHash                 string
	SourceJudgmentHash           string
	JudgmentMatch                bool
	ActionHash                   string
	SourceActionHash             string
	ActionMatch                  bool
	PremisesHash                 string
	SourcePremisesHash           string
	PremisesMatch                bool
	SupportHash                  string
	SourceSupportHash            string
	SupportMatch                 bool
	MachineDispositionHash       string
	SourceMachineDispositionHash string
	MachineDispositionMatch      bool
}

// decisionAxisComparison hashes the recomposed and recorded axes
// independently. A replay that reaches persistence already proved the
// hashes agree (compareDecisionAxes fails closed); the recorded flags make
// the comparison auditable after the fact.
func decisionAxisComparison(recorded, recomputed DecisionPackage) decisionAxisHashes {
	return decisionAxisHashes{
		JudgmentHash:                 projectionHash(recomputed.Judgment),
		SourceJudgmentHash:           projectionHash(recorded.Judgment),
		JudgmentMatch:                jsonEqual(recorded.Judgment, recomputed.Judgment),
		ActionHash:                   projectionHash(recomputed.ProposedAction),
		SourceActionHash:             projectionHash(recorded.ProposedAction),
		ActionMatch:                  jsonEqual(recorded.ProposedAction, recomputed.ProposedAction),
		PremisesHash:                 projectionHash(recomputed.Premises),
		SourcePremisesHash:           projectionHash(recorded.Premises),
		PremisesMatch:                jsonEqual(recorded.Premises, recomputed.Premises),
		SupportHash:                  projectionHash(recomputed.Support),
		SourceSupportHash:            projectionHash(recorded.Support),
		SupportMatch:                 jsonEqual(recorded.Support, recomputed.Support),
		MachineDispositionHash:       projectionHash(recomputed.MachineDisposition),
		SourceMachineDispositionHash: projectionHash(recorded.MachineDisposition),
		MachineDispositionMatch:      jsonEqual(recorded.MachineDisposition, recomputed.MachineDisposition),
	}
}

// VerifySnapshotDrift checks the recorded snapshot manifest against the
// CURRENT repository state: the tree must hash to the pinned content hash,
// a recorded ref must still resolve to the pinned commit and every pinned
// artifact must still exist byte-identical. This is an explicit live check
// — deliberately OUTSIDE the replay contract: PrepareReplay/ReplayRun never
// call it, replay never touches git or the working tree. A caller that
// wants drift detection against a live source opts in here. Returns nil
// when the live tree matches the snapshot; drift or an unreadable
// repository is a technical error.
func VerifySnapshotDrift(ctx context.Context, manifest SnapshotManifest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(manifest.Repository) == "" {
		if manifest.ContentHash != "" || manifest.Revision != "" {
			return errors.New("agenttriage: snapshot drift check: manifest pins a repository that is not recorded")
		}
		return nil
	}
	root, cerr := canonicalDir(manifest.Repository)
	if cerr != nil {
		return fmt.Errorf("agenttriage: snapshot drift check: repository cannot be resolved: %w", cerr)
	}
	gotHash, herr := repository.ContentHash(root)
	if herr != nil {
		return fmt.Errorf("agenttriage: snapshot drift check: repository cannot be re-hashed: %w", herr)
	}
	if gotHash != manifest.ContentHash {
		return fmt.Errorf("agenttriage: snapshot drift: recorded content_hash %s, repository now hashes %s", manifest.ContentHash, gotHash)
	}
	// A recorded revision pins the resolved commit SHA: re-resolve the
	// ref now so a moved tag/branch is drift even when the working tree
	// and content hash still match. Manifests recorded before
	// resolved_revision existed carry an empty field and fail closed.
	if manifest.Revision != "" {
		if manifest.ResolvedRevision == "" {
			return fmt.Errorf("agenttriage: snapshot drift check: manifest has no resolved_revision for pinned revision %q", manifest.Revision)
		}
		_, sha, rerr := repository.ResolveRef(ctx, root, manifest.Revision)
		if rerr != nil {
			return fmt.Errorf("agenttriage: snapshot drift: pinned revision %q no longer resolves: %v", manifest.Revision, rerr)
		}
		if sha != manifest.ResolvedRevision {
			return fmt.Errorf("agenttriage: snapshot drift: pinned revision %q resolved to %s at run time, now resolves to %s", manifest.Revision, manifest.ResolvedRevision, sha)
		}
	}
	for _, a := range manifest.Artifacts {
		abs, derr := replayArtifactPath(manifest.Repository, a.Path)
		if derr != nil {
			return fmt.Errorf("agenttriage: snapshot drift check: artifact %q: %w", a.Path, derr)
		}
		sum, size, herr := hashFileSHA256(abs)
		if herr != nil {
			return fmt.Errorf("agenttriage: snapshot drift: artifact %q cannot be read: %v", a.Path, herr)
		}
		if sum != a.SHA256 || size != a.Size {
			return fmt.Errorf("agenttriage: snapshot drift: artifact %q changed since the snapshot was pinned", a.Path)
		}
	}
	return nil
}
func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// ReplayStage0 reproduces the Stage 0 resolution of a recorded run from its
// saved artifacts alone: stage0.json, intake.json, intake-proposal.json,
// materials.json and the frozen advisory document named by the freeze
// record. It never enumerates refs, materializes a source, re-runs intake
// extraction or contacts an advisory lane — git, OSV, tracker and registry
// are all out of scope; everything the Stage 0 run pinned is verified
// fail-closed. A missing or corrupt pinned artifact is a technical error,
// the same class a caller maps to exit 2.
func ReplayStage0(ctx context.Context, runDir string) (Stage0Result, error) {
	var s0 Stage0Result
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return s0, err
	}
	dir := strings.TrimSpace(runDir)
	if dir == "" {
		return s0, errors.New("agenttriage: replay: run directory is empty")
	}
	read := func(name string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("agenttriage: replay %s: cannot read %s: %w", dir, name, err)
		}
		return data, nil
	}
	docBytes, err := read("stage0.json")
	if err != nil {
		return s0, err
	}
	var doc stage0Document
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return s0, fmt.Errorf("agenttriage: replay %s: stage0.json does not parse: %w", dir, err)
	}
	var in FindingInput
	if b, rerr := os.ReadFile(filepath.Join(dir, "input.json")); rerr == nil {
		findings, ferr := ParseFindings(bytes.NewReader(b))
		if ferr != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: input.json: %w", dir, ferr)
		}
		if len(findings) != 1 {
			return s0, fmt.Errorf("agenttriage: replay %s: input.json holds %d findings, a run directory records exactly one", dir, len(findings))
		}
		in = findings[0]
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return s0, fmt.Errorf("agenttriage: replay %s: cannot read input.json: %w", dir, rerr)
	}
	var manifest SnapshotManifest
	if b, rerr := os.ReadFile(filepath.Join(dir, "snapshot.json")); rerr == nil {
		if err := json.Unmarshal(b, &manifest); err != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: snapshot.json does not parse: %w", dir, err)
		}
		if manifest.SchemaVersion != SnapshotSchemaVersion {
			return s0, fmt.Errorf("agenttriage: replay %s: snapshot.json schema %q is not %s", dir, manifest.SchemaVersion, SnapshotSchemaVersion)
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return s0, fmt.Errorf("agenttriage: replay %s: cannot read snapshot.json: %w", dir, rerr)
	} else if doc.Materialization.Mode != "" {
		return s0, fmt.Errorf("agenttriage: replay %s: snapshot.json is required: stage0.json records materialization mode %q", dir, doc.Materialization.Mode)
	}
	return loadStage0Artifacts(dir, in, manifest, doc)
}

// loadStage0Artifacts rebuilds the Stage0Result pinned in one run directory
// and verifies every artifact the recorded resolution produced. in and
// manifest are the already-verified run inputs (zero values are tolerated:
// a directory that never reached input/snapshot writing replays its Stage
// 0 projection without them). The checks are fail-closed and read-only:
// the verbatim intake record, the proposal and the material set must parse
// and stay schema-bound when their producing stage ran, and a frozen
// advisory the record pins must still exist byte-identical — a missing or
// changed frozen input is a technical error, never a re-resolution.
func loadStage0Artifacts(dir string, in FindingInput, manifest SnapshotManifest, doc stage0Document) (Stage0Result, error) {
	s0 := Stage0Result{
		Input: in, Snapshot: manifest, ConfigHash: doc.ConfigHash,
		CatalogEntry: doc.CatalogEntry, CandidateRefs: doc.CandidateRefs,
		SelectedRef: doc.SelectedRef, RefResolution: doc.RefResolution,
		Source:   MaterializedSource{Root: manifest.Repository, Metadata: doc.Materialization, Cleanup: func() error { return nil }},
		Advisory: doc.Advisory, ReleaseToolchain: doc.ReleaseToolchain,
		Toolchain: doc.Toolchain, PackageCheck: doc.PackageCheck,
		Validation: doc.Validation, Limitations: doc.Limitations,
	}
	if doc.SchemaVersion != Stage0DocumentSchemaVersion {
		return s0, fmt.Errorf("agenttriage: replay %s: stage0.json schema %q is not %s", dir, doc.SchemaVersion, Stage0DocumentSchemaVersion)
	}
	if doc.FindingID != "" && in.Finding.FindingID != "" && doc.FindingID != in.Finding.FindingID {
		return s0, fmt.Errorf("agenttriage: replay %s: stage0 finding_id %q does not match input finding_id %q", dir, doc.FindingID, in.Finding.FindingID)
	}

	// The verbatim intake record is mandatory: it is the ticket-hash
	// binding every Stage 0 artifact derives from.
	b, err := os.ReadFile(filepath.Join(dir, "intake.json"))
	if err != nil {
		return s0, fmt.Errorf("agenttriage: replay %s: cannot read intake.json: %w", dir, err)
	}
	var rec intakeRecordDoc
	if err := json.Unmarshal(b, &rec); err != nil {
		return s0, fmt.Errorf("agenttriage: replay %s: intake.json does not parse: %w", dir, err)
	}
	if rec.SchemaVersion != IntakeRecordSchemaVersion {
		return s0, fmt.Errorf("agenttriage: replay %s: intake.json schema %q is not %s", dir, rec.SchemaVersion, IntakeRecordSchemaVersion)
	}
	if got := hashBytes([]byte(rec.Raw)); got != rec.TicketHash {
		return s0, fmt.Errorf("agenttriage: replay %s: intake drift: ticket_hash %s does not match record bytes %s", dir, rec.TicketHash, got)
	}
	s0.Raw = RawIntake{Raw: []byte(rec.Raw), TicketHash: rec.TicketHash, Format: rec.Format, RecordIndex: rec.RecordIndex}

	// intake-proposal.json is required once validation ran — a Stage 0
	// that validated a proposal always persisted it.
	b, err = os.ReadFile(filepath.Join(dir, "intake-proposal.json"))
	if err != nil && !(errors.Is(err, os.ErrNotExist) && len(doc.Validation.Fields) == 0) {
		return s0, fmt.Errorf("agenttriage: replay %s: cannot read intake-proposal.json: %w", dir, err)
	}
	if err == nil {
		if err := json.Unmarshal(b, &s0.Proposal); err != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: intake-proposal.json does not parse: %w", dir, err)
		}
		if s0.Proposal.SchemaVersion != "" && s0.Proposal.SchemaVersion != IntakeProposalSchemaVersion {
			return s0, fmt.Errorf("agenttriage: replay %s: intake-proposal.json schema %q is not %s", dir, s0.Proposal.SchemaVersion, IntakeProposalSchemaVersion)
		}
	}

	// materials.json is required once materialization ran — collecting the
	// material set over the materialized root always persisted it.
	b, err = os.ReadFile(filepath.Join(dir, "materials.json"))
	if err != nil && !(errors.Is(err, os.ErrNotExist) && doc.Materialization.Mode == "") {
		return s0, fmt.Errorf("agenttriage: replay %s: cannot read materials.json: %w", dir, err)
	}
	if err == nil {
		if err := json.Unmarshal(b, &s0.Materials); err != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: materials.json does not parse: %w", dir, err)
		}
		if err := validateMaterialSet(s0.Materials); err != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: %w", dir, err)
		}
	}

	// The snapshot pins the materialized root: a recorded materialization
	// must agree with the manifest the run built over it.
	if md := doc.Materialization; manifest.SchemaVersion != "" && (md.Mode != "" || md.SourceID != "") {
		if md.RootHash != "" && manifest.ContentHash != "" && md.RootHash != manifest.ContentHash {
			return s0, fmt.Errorf("agenttriage: replay %s: materialization root_hash %s does not match snapshot content_hash %s", dir, md.RootHash, manifest.ContentHash)
		}
		if md.ResolvedCommit != "" && manifest.ResolvedRevision != "" && md.ResolvedCommit != manifest.ResolvedRevision {
			return s0, fmt.Errorf("agenttriage: replay %s: materialization commit %s does not match resolved_revision %s", dir, md.ResolvedCommit, manifest.ResolvedRevision)
		}
	}

	// Frozen advisory verification (spec §9.6 "advisory freeze"): a record
	// naming a frozen document requires the file to still exist with the
	// pinned size and hash — replay must never reach for a live lane.
	if adv := doc.Advisory; adv.Source != "" || adv.SHA256 != "" || adv.Path != "" {
		if adv.SchemaVersion != "" && adv.SchemaVersion != vulnerability.FrozenAdvisorySchemaVersion {
			return s0, fmt.Errorf("agenttriage: replay %s: advisory freeze record schema %q is not %s", dir, adv.SchemaVersion, vulnerability.FrozenAdvisorySchemaVersion)
		}
		if adv.Path == "" || adv.SHA256 == "" {
			return s0, fmt.Errorf("agenttriage: replay %s: advisory freeze record pins source %q without path/hash", dir, adv.Source)
		}
		// A relative record path is run-relative: the compatibility
		// transport binds its captured finding bytes as input.json inside
		// the run, so a copied run replays against its own bytes rather
		// than the original location. An absolute path keeps its historical
		// meaning.
		advPath := adv.Path
		if !filepath.IsAbs(advPath) {
			candidate := filepath.Join(dir, filepath.FromSlash(advPath))
			rel, rerr := filepath.Rel(dir, candidate)
			if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return s0, fmt.Errorf("agenttriage: replay %s: recorded advisory path %q escapes the run directory", dir, adv.Path)
			}
			advPath = candidate
		}
		data, rerr := os.ReadFile(advPath)
		if rerr != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: advisory record %s is missing or unreadable: %w", dir, advPath, rerr)
		}
		if adv.Size > 0 && int64(len(data)) != adv.Size {
			return s0, fmt.Errorf("agenttriage: replay %s: advisory record %s drifted: recorded size %d, now %d", dir, advPath, adv.Size, len(data))
		}
		if got := hashBytes(data); got != adv.SHA256 {
			return s0, fmt.Errorf("agenttriage: replay %s: advisory record %s drifted: recorded sha256 %s, recomputed %s", dir, advPath, adv.SHA256, got)
		}
	}
	if doc.ResolutionVuln != nil {
		s0.Resolution = &AdvisoryResolution{Vulnerability: doc.ResolutionVuln, Projection: doc.ResolutionProjection, Record: doc.Advisory}
	}
	if doc.Investigation != nil {
		inputs, ierr := doc.Investigation.Inputs()
		if ierr != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: Stage 0 investigation projection: %w", dir, ierr)
		}
		s0.Investigation = inputs
	}
	if doc.BuildTarget != nil {
		admitted, aerr := admitBuildTarget("recorded product build target", doc.BuildTarget, manifest)
		if aerr != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: %w", dir, aerr)
		}
		s0.BuildTarget = admitted
	}
	if (doc.BuildTarget == nil) != (s0.Investigation.BuildTarget == nil) {
		return s0, fmt.Errorf("agenttriage: replay %s: stage0.json build_target and the investigation projection disagree", dir)
	}
	if doc.BuildTarget != nil {
		if cmp := compareBuildTargets(*s0.BuildTarget, *s0.Investigation.BuildTarget); cmp != nil {
			return s0, fmt.Errorf("agenttriage: replay %s: stage0.json build_target disagrees with the investigation projection: %w", dir, cmp)
		}
	}
	return s0, nil
}

// WriteReplay persists a prepared replay as a NEW report directory next to
// other findings under outDir. It never writes into the source run directory
// or into the repository the snapshot pins; input.json, snapshot.json and
// raw-agent.json are copied verbatim, assessment.json/assessment.md are
// re-rendered from the replayed assessment and replay.json carries the
// rerender_of link.
func (w ArtifactWriter) WriteReplay(ctx context.Context, outDir string, rep ReplayReport) (RunArtifacts, error) {
	var art RunArtifacts
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return art, err
	}
	if strings.TrimSpace(rep.FindingID) == "" || strings.TrimSpace(rep.SourceDir) == "" {
		return art, errors.New("agenttriage: replay write: empty replay report")
	}
	if rep.Assessment.Audit == nil {
		return art, errors.New("agenttriage: replay write: replay report has no recomposed audit")
	}
	if rep.Assessment.FindingID != rep.FindingID {
		return art, fmt.Errorf("agenttriage: replay write: assessment finding_id %q does not match replay finding %q", rep.Assessment.FindingID, rep.FindingID)
	}
	sourceDir, err := filepath.Abs(rep.SourceDir)
	if err != nil {
		return art, fmt.Errorf("agenttriage: replay write: %w", err)
	}
	if canon, cerr := filepath.EvalSymlinks(sourceDir); cerr == nil {
		sourceDir = canon
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return art, fmt.Errorf("agenttriage: replay write: create output directory: %w", err)
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return art, fmt.Errorf("agenttriage: replay write: %w", err)
	}
	if canon, cerr := filepath.EvalSymlinks(absOut); cerr == nil {
		absOut = canon
	}
	if pathContains(sourceDir, absOut) {
		return art, fmt.Errorf("agenttriage: replay write: output directory %s lies inside the source run %s; the original run is never modified", outDir, rep.SourceDir)
	}
	if repo := strings.TrimSpace(rep.Manifest.Repository); repo != "" {
		if root, rerr := canonicalDir(repo); rerr == nil && root != "" && pathContains(root, absOut) {
			return art, fmt.Errorf("agenttriage: replay write: output directory %s lies inside repository %q; output is never written into a source repository", outDir, repo)
		}
	}

	name, err := RunDirName(rep.FindingID)
	if err != nil {
		return art, err
	}
	stamp := w.now().UTC()
	var randBuf [4]byte
	if _, err := rand.Read(randBuf[:]); err != nil {
		return art, fmt.Errorf("agenttriage: replay write: %w", err)
	}
	dirName := fmt.Sprintf("%s-replay-%s-%s", name, stamp.Format("20060102T150405Z"), hex.EncodeToString(randBuf[:]))
	art.RootDir = filepath.Join(absOut, dirName)
	if _, err := os.Lstat(art.RootDir); err == nil {
		return art, fmt.Errorf("agenttriage: replay write: target directory %s already exists", art.RootDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return art, fmt.Errorf("agenttriage: replay write: stat target directory: %w", err)
	}
	art.InputPath = filepath.Join(art.RootDir, "input.json")
	art.SnapshotPath = filepath.Join(art.RootDir, "snapshot.json")
	art.RawAgentPath = filepath.Join(art.RootDir, "raw-agent.json")
	art.AssessmentPath = filepath.Join(art.RootDir, "assessment.json")
	art.MarkdownPath = filepath.Join(art.RootDir, "assessment.md")
	art.DecisionPath = filepath.Join(art.RootDir, "decision.json")
	art.DecisionMarkdownPath = filepath.Join(art.RootDir, "decision.md")
	art.MaterialsPath = filepath.Join(art.RootDir, "materials.json")
	art.IntakeProposalPath = filepath.Join(art.RootDir, "intake-proposal.json")
	art.PromptInputPath = filepath.Join(art.RootDir, PromptInputArtifactName)
	art.FactGatePath = filepath.Join(art.RootDir, "fact-gate.json")
	art.AuditPath = filepath.Join(art.RootDir, "audit", "events.jsonl")
	art.RunID = newRunID(rep.FindingID, stamp)
	if err := os.MkdirAll(filepath.Dir(art.AuditPath), 0o755); err != nil {
		return art, fmt.Errorf("agenttriage: replay write: create replay directory: %w", err)
	}

	inputBytes := rep.InputJSON
	if len(inputBytes) == 0 {
		if inputBytes, err = json.MarshalIndent(rep.Input.Finding, "", "  "); err != nil {
			return art, fmt.Errorf("agenttriage: replay write: encode input: %w", err)
		}
	}
	if err := writeFileAtomic(ctx, art.InputPath, inputBytes); err != nil {
		return art, err
	}
	manifestBytes := rep.ManifestJSON
	if len(manifestBytes) == 0 {
		if manifestBytes, err = json.MarshalIndent(rep.Manifest, "", "  "); err != nil {
			return art, fmt.Errorf("agenttriage: replay write: encode snapshot: %w", err)
		}
		manifestBytes = append(manifestBytes, '\n')
	}
	if err := writeFileAtomic(ctx, art.SnapshotPath, manifestBytes); err != nil {
		return art, err
	}
	rawBytes := rep.RawJSON
	if len(rawBytes) == 0 {
		if rawBytes, err = json.MarshalIndent(rep.Raw, "", "  "); err != nil {
			return art, fmt.Errorf("agenttriage: replay write: encode raw agent document: %w", err)
		}
		rawBytes = append(rawBytes, '\n')
	}
	if err := writeFileAtomic(ctx, art.RawAgentPath, rawBytes); err != nil {
		return art, err
	}
	// Stage 0 auxiliaries travel verbatim with the replay report so the
	// re-rendered run keeps its intake/ref/materialization provenance.
	for _, aux := range []string{"intake.json", "intake-proposal.json", "materials.json", "stage0.json", "fact-gate.json", PromptInputArtifactName, InvestigationInputsArtifactName} {
		data, rerr := os.ReadFile(filepath.Join(sourceDir, aux))
		if errors.Is(rerr, os.ErrNotExist) {
			continue
		}
		if rerr != nil {
			return art, fmt.Errorf("agenttriage: replay write: cannot read %s: %w", aux, rerr)
		}
		if err := writeFileAtomic(ctx, filepath.Join(art.RootDir, aux), data); err != nil {
			return art, err
		}
	}
	// The digest-addressed material archive travels verbatim: a replay
	// output is itself a readable run whose captured bytes are still
	// available to read_material.
	if err := CopyInvestigationArchive(sourceDir, art.RootDir); err != nil {
		return art, fmt.Errorf("agenttriage: replay write: %w", err)
	}

	if err := writeJSONAtomic(ctx, art.AssessmentPath, rep.Assessment); err != nil {
		return art, err
	}
	if err := writeFileAtomic(ctx, art.MarkdownPath, renderMarkdown(rep.Assessment, stamp)); err != nil {
		return art, err
	}

	if rep.Decision != nil {
		if err := writeJSONAtomic(ctx, art.DecisionPath, *rep.Decision); err != nil {
			return art, err
		}
		if err := writeFileAtomic(ctx, art.DecisionMarkdownPath, RenderDecisionMarkdown(*rep.Decision)); err != nil {
			return art, err
		}
	}
	// Review history travels verbatim: the original record bytes are copied
	// as files, never re-encoded, re-stamped or regenerated. Replay creates
	// no new Accept and no new record id.
	humanDecisionHashes := make([]string, 0, len(rep.humanDecisionFiles))
	for _, file := range rep.humanDecisionFiles {
		recordPath := filepath.Join(art.RootDir, humanDecisionsDirName, file.Record.ID+".json")
		if err := writeFileAtomic(ctx, recordPath, file.Bytes); err != nil {
			return art, err
		}
		humanDecisionHashes = append(humanDecisionHashes, hashBytes(file.Bytes))
	}
	for _, file := range rep.environmentAssertionFiles {
		if err := writeFileAtomic(ctx, filepath.Join(art.RootDir, environmentAssertionsDirName, file.Assertion.ID+".json"), file.Bytes); err != nil { return art, err }
	}
	if len(rep.humanDecisionFiles) > 0 || len(rep.environmentAssertionFiles) > 0 {
		// The replay output is itself a readable run. Seed the collection
		// lock so a later reader never creates a file inside it.
		if err := writeFileAtomic(ctx, filepath.Join(art.RootDir, humanDecisionsLockName), nil); err != nil {
			return art, err
		}
	}
	sourceHash := ""
	if rep.SourceAssessment.Audit != nil {
		sourceHash = rep.SourceAssessment.Audit.AssessmentHash
	}
	sourceDecisionHash, decisionHash := "", ""
	decisionMatch := false
	axes := decisionAxisHashes{}
	if rep.SourceDecision != nil {
		sourceDecisionHash = canonicalDecisionHash(*rep.SourceDecision)
		decisionHash = canonicalDecisionHash(*rep.Decision)
		decisionMatch = sourceDecisionHash == decisionHash
		axes = decisionAxisComparison(*rep.SourceDecision, *rep.Decision)
	}
	doc := ReplayDocument{
		SchemaVersion: ReplaySchemaVersion, RunID: art.RunID, FindingID: rep.FindingID,
		RerenderOf: rep.SourceDir, SourceRunID: rep.SourceRunID, SourceAssessmentHash: sourceHash,
		InputHash: rep.Assessment.Audit.FindingHash, SnapshotHash: rep.Assessment.Audit.SnapshotHash,
		BuildTarget: cloneBuildTarget(rep.BuildTarget),
		PromptHash:  rep.Assessment.Audit.PromptHash, ResponseHash: rep.Assessment.Audit.ResponseHash,
		AssessmentHash: rep.Assessment.Audit.AssessmentHash, AssessmentHashMatch: rep.Assessment.Audit.AssessmentHash == sourceHash,
		DecisionHash: decisionHash, SourceDecisionHash: sourceDecisionHash, DecisionHashMatch: decisionMatch,
		JudgmentHash: axes.JudgmentHash, SourceJudgmentHash: axes.SourceJudgmentHash, JudgmentMatch: axes.JudgmentMatch,
		ActionHash: axes.ActionHash, SourceActionHash: axes.SourceActionHash, ActionMatch: axes.ActionMatch,
		PremisesHash: axes.PremisesHash, SourcePremisesHash: axes.SourcePremisesHash, PremisesMatch: axes.PremisesMatch,
		SupportHash: axes.SupportHash, SourceSupportHash: axes.SourceSupportHash, SupportMatch: axes.SupportMatch,
		MachineDispositionHash: axes.MachineDispositionHash, SourceMachineDispositionHash: axes.SourceMachineDispositionHash,
		MachineDispositionMatch: axes.MachineDispositionMatch,
		HumanDecisions:          append([]HumanDecisionRecord(nil), rep.HumanDecisions...),
		HumanDecisionHashes:     humanDecisionHashes,
		HumanReviewProjection: rep.HumanReviewProjection,
		Limitations:             rep.Limitations,
		GeneratedAt:             stamp.Format(time.RFC3339),
	}
	for _, file := range rep.environmentAssertionFiles { doc.EnvironmentAssertionHashes = append(doc.EnvironmentAssertionHashes, hashBytes(file.Bytes)) }
	if err := writeJSONAtomic(ctx, filepath.Join(art.RootDir, "replay.json"), doc); err != nil {
		return art, err
	}

	limitations := append([]string{
		"re-rendered replay: no model call, no network; the agent answer is the stored raw response",
	}, rep.Limitations...)
	if !doc.AssessmentHashMatch {
		limitations = append(limitations,
			fmt.Sprintf("assessment_hash %s differs from source %s: deterministic composition changed, agent verdict unchanged",
				doc.AssessmentHash, sourceHash))
	}
	event := AuditEvent{
		Type:        AuditEventReplay,
		Timestamp:   stamp,
		RunID:       art.RunID,
		Status:      "ok",
		Hash:        rep.Assessment.Audit.AssessmentHash,
		Scope:       rep.SourceDir,
		Limitations: limitations,
	}
	if err := appendAuditLog(ctx, art.AuditPath, []AuditEvent{event}, art.RunID, stamp); err != nil {
		return art, err
	}
	if w.Stdout != nil {
		// The replay's primary result is the human action card. A run
		// recorded before decision packages existed has no action to
		// announce; say so instead of presenting the investigation
		// assessment as the result. The line prints only after the report
		// and audit record landed, so a failed replay announces nothing.
		if rep.Decision != nil {
			fmt.Fprintf(w.Stdout, "triage replay %s action=%s support=%s machine=%s decision=%s\n",
				rep.FindingID, orDash(string(rep.Decision.ProposedAction.Kind)),
				orDash(string(rep.Decision.Support.Level)),
				orDash(string(rep.Decision.MachineDisposition.Recommendation)), art.DecisionMarkdownPath)
		} else {
			fmt.Fprintf(w.Stdout, "triage replay %s decision=none rerender_of=%s replay=%s\n",
				rep.FindingID, rep.SourceDir, art.RootDir)
		}
	}
	return art, nil
}

// observationIndexFromAudit rebuilds the observation id → ObservationPin
// index of one recorded run from its audit/events.jsonl. Only tool_call
// events stamped with the source run id are indexed: the log is append-only
// and a rerun of the same finding adds a new block, so unscoped ids would
// collide across runs. The pin carries the recorded inner payload hashes
// and reachability classification, so a replay resolves det:<id> citations
// and the automation annotation exactly as the live run did. A missing or
// partially unreadable log yields the subset that parses — det:<id>
// references degrade to UNAVAILABLE rather than turning a replay into a
// technical error.
func observationIndexFromAudit(dir, runID string, attempt int) map[string]ObservationPin {
	index := map[string]ObservationPin{}
	if strings.TrimSpace(runID) == "" {
		return index
	}
	data, err := os.ReadFile(filepath.Join(dir, "audit", "events.jsonl"))
	if err != nil {
		return index
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Type != AuditEventToolCall || ev.RunID != runID || ev.ObservationID == "" {
			continue
		}
		// det:<id> bindings are attempt-scoped: the primary run's events
		// carry Attempt=0 (recorded before attempts were numbered); a
		// retry's events stamp its number. Only the selected attempt's
		// calls may resolve this replay's evidence — a foreign attempt's
		// ids must never bind a citation they cannot prove.
		if ev.Attempt != attempt && !(attempt == 1 && ev.Attempt == 0) {
			continue
		}
		index[ev.ObservationID] = ObservationPin{
			Status:        ev.Status,
			Coverage:      ev.Coverage,
			DataSHA256:    ev.DataSHA256,
			InnerSHA256:   ev.InnerSHA256,
			Tool:          ev.Tool,
			ReachEvidence: ev.ReachEvidence,
		}
	}
	return index
}

// replayArtifactPath maps a manifest artifact path to its on-disk location:
// absolute paths stay as recorded; relative paths resolve inside the
// snapshot root and must not escape it.
func replayArtifactPath(repository, p string) (string, error) {
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	root, err := canonicalDir(repository)
	if err != nil {
		return "", err
	}
	if root == "" {
		return "", fmt.Errorf("relative artifact path %q without a snapshot root", p)
	}
	abs, ok := resolveSnapshotPath(root, p)
	if !ok {
		return "", fmt.Errorf("relative artifact path %q resolves outside the snapshot root", p)
	}
	return abs, nil
}

// pathContains reports whether dir is root itself or a descendant of it.
// Both arguments are canonical absolute paths.
func pathContains(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
