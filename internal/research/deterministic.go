package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fedorovmv/izyan/internal/advfeed"
	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/fixbinding"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/repository"
 "github.com/fedorovmv/izyan/internal/rootcause"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// LaneOptions carries the CLI-resolved inputs of the deterministic lane.
type LaneOptions struct {
	CVE               string
	SnapshotPath      string
	AdvisoryFile      string
	AdvisoryDir       string
	OutputDir         string
	ExternalCommitSHA string
	AnalysisGo        string
	GOOS              string
	GOARCH            string
	BuildTags         []string
	ModCache          string
	GovulnDB          string
	Timeout           time.Duration
 FixSourceCaptures *rootcause.SourceCaptureSet
	// ArtifactOptions requests the bounded release-artifact channel: a
	// local Go binary/ZIP or an HTTPS download whose embedded build info
	// is AUTHORITATIVE release evidence. Zero value = channel off.
	ArtifactOptions repository.ArtifactOptions
	// ReleaseMetadata is the optional path of a release-metadata/1
	// document (ticket/SBOM). The file is parsed once, before the
	// snapshot probe, and the typed summary feeds both the lane snapshot
	// and the evidence session so every consumer sees identical release
	ReleaseMetadata string
	// Ticket is the optional path of a tracker ticket (JSON ticket,
	// JSON array or plain text; "-" means stdin) carrying the product/
	// package version claims. A declared package version that differs
	// from the version the analysis resolved blocks the version axis
	// (TICKET_PACKAGE_VERSION_MISMATCH) — the ticket's question is
	// about a different build. Absent means the identity check never
	// ran. TicketID selects by key when the input holds several
	// tickets.
	Ticket   string
	TicketID string
	// DeclaredAssumptions is the optional path of a declared-assumptions/1
	// document (--declared-assumptions) carrying the run's typed
	// policy/scope inputs: administrator config trust and the supported
	// target matrix. Parsed once, before the lane record is assembled;
	// every failure is a typed fail-closed LoadError on the record —
	// assumptions are inputs, and an inadmissible member can only leave
	// its dependent gate unclosed, never pass silently.
	DeclaredAssumptions string
	// ImplementationLocusProposals is the optional path of an
	// implementation-locus-proposals/1 artifact
	// (--implementation-locus-proposal): a typed, sha-pinned carrier of
	// LLM-inferred implementation-locus hypotheses the lane binds to the
	// frozen advisory and feeds to the deterministic implementation
	// axis. Parsed once; every intake failure is a typed fail-closed
	// LoadError on the channel record — a failed channel admits
	// nothing and never substitutes for a deterministic fact.
	ImplementationLocusProposals string
	// DefectSemantics is the admitted defect-semantics contract a caller
	// already resolved for this advisory. The lane never derives it from
	// method names, prose, evidence-id prefixes or sibling observations;
	// nil means every deadness-based negative route in this lane stays
	// INCONCLUSIVE.
	DefectSemantics *domain.DefectSemanticsContract
	// ExploitLocusProposals is the optional path of an
	// exploit-locus-proposals/1 artifact
	// (--exploit-locus-proposal): a typed, sha-pinned carrier of
	// LLM-inferred hypotheses for a symbol-less advisory — the
	// vulnerable implementation, the product-facing trigger sink and
	// the trigger argument. Parsed once; every intake failure is a
	// typed fail-closed LoadError on the channel record — a failed
	// channel admits nothing.
	ExploitLocusProposals string
	// RetainedProposals are the implementation-locus proposals retained
	// inside a replayed agent turn (--replay-agent-turn): the same
	// hypotheses the original turn emitted, re-admitted at the
	// implementation-axis dispatch point with the original answer's
	// sha256 as the intake pin. The channel is only a carrier — the
	// axis still verifies every proposal deterministically.
	RetainedProposals []domain.ImplementationLocusProposal
	// RetainedExploitProposals are the exploit-locus proposals retained
	// inside a replayed agent turn: re-admitted at the binding dispatch
	// point with the retained answer's sha256 as the intake pin.
	RetainedExploitProposals []domain.ExploitLocusProposal
	// RetainedAnswerSHA256 is the replayed turn's retained-answer pin
	// that RetainedProposals were extracted from. Empty when the
	// replayed turn carries no answer pin; the intake record then
	// carries only the typed member set.
	RetainedAnswerSHA256 string
	// AdvisoryFeed, when non-nil, configures an OSV advisory dump source
	// (offline dir/zip or remote dump host) used to complete advisory
	// entries that declare no package/symbol subjects. The frozen file
	// stays authoritative: present data is never overridden.
	AdvisoryFeed *advfeed.Options
	// Corpus configures the request-level advisory corpus: the operator's
	// declared identity (reference, expected digest, capture date), the
	// configured feed and any explicit byte selections. Configuring a feed
	// is not closure authority — the corpus only nominates candidates and
	// supplies the observed manifest a declared completeness basis must
	// match.
	Corpus *advfeed.CorpusOptions
	// RequestContract selects the requested-finding contract's exact-bytes
	// intake: the frozen record's own subjects are the only ones an
	// assessment may use, so the alias/feed subject-merging path is never
	// consulted. This is the intake every /4 request composition requires.
	RequestContract bool
	// RecordOnly stops the lane at the record-finalization boundary: it
	// produces the record's own assessment and never discovers candidates,
	// composes a request or publishes a request composition. A record-only
	// lane is one child assessment of a request owned elsewhere.
	RecordOnly bool
}

// AdvisoryRecord is the loaded frozen advisory plus its normalized
// per-entry projection (including non-Go entries).
type AdvisoryRecord struct {
	Input       AdvisoryInput
	Vuln        *domain.Vulnerability
	Impls       []AffectedImplementation
	Outcome     string // vexbench outcome for --advisory-dir
	RawBytes    []byte
	PartialNote string
}

// LaneResult is everything the deterministic lane produced.
type LaneResult struct {
	SnapshotRoot     string
	ContentHash      string
	Snapshot         domain.ProductSnapshot
	Advisory         AdvisoryRecord
	Affected         domain.AffectedResult
	AffectedEvidence []domain.Evidence
	ResolveErr       error
	// Observations is every lane/session observation in call order.
	Observations []*evidencetools.Observation
	// Records mirrors Observations with tool/args for observations.jsonl.
	Records []evidencetools.AuditRecord
	// Facts is the verified_facts list (OK observations only).
	Facts []VerifiedFact
	// FactsArtifact pins deterministic-facts.json (path+sha+size) —
	// the deterministic attempt's result artifact (Slice-2 §2.7).
	FactsArtifact *AttemptArtifact
	// ArtifactByObs maps observation ID -> persisted artifact (path+sha
	// of the written file bytes). For an observation whose payload was
	// externalized (Observation.PayloadRef), the artifact pins the
	// bounded envelope form — the complete payload is pinned by
	// PayloadRef, never by this entry.
	ArtifactByObs map[string]ArtifactRef
	// CanonicalByObs maps observation ID -> canonical payload sha256
	// (the persisted observation JSON — envelope form for an
	// externalized payload — without the file's trailing newline); it
	// is the fact's data_digest. The complete externalized payload's
	// digest lives on Observation.PayloadRef.
	CanonicalByObs map[string]string
	// GraphModules is the resolved module list captured from the
	// get_dependency_graph observation at call time — kept separately
	// because the observation payload itself may be truncated on persist.
	GraphModules []string
	Toolchain    toolchain.Toolchain
	ToolEnv      []string
	// Ingress/Exposure are kept for claim assembly.
	ExposureFacts []domain.ExposureFact
	Entrypoints   int
	Ingress       map[string]domain.IngressClosure
	// FactsByTool indexes facts for claim references.
	obsIndex map[string]*evidencetools.Observation

	// Ticket is the tracker-ticket channel record when the operator
	// supplied one: provenance ref, pinned digest, parsed claims (or
	// the parse error that degraded the check to NOT_CHECKED). nil
	// when the channel was never requested — legacy lanes stay exactly
	// as before.
	Ticket *TicketRecord

	// Assumptions is the declared-assumptions/1 channel record when the
	// operator supplied one: provenance, pinned digest, typed members or
	// the fail-closed LoadError. nil when the channel was never
	// requested — legacy lanes stay exactly as before. Assumptions are
	// policy inputs; they never join Observations/Facts as evidence.
	Assumptions *domain.DeclaredAssumptionsInput
	// ImplementationProposals is the implementation-locus proposal
	// channel record when one supplied or replayed proposals:
	// provenance, pinned digests, the admitted members or the
	// fail-closed load error. nil when no channel was requested — the
	// axis then never attempts. Proposals are hypothesis inputs, never
	// evidence.
	ImplementationProposals *ImplementationProposalsInput
	// ExploitProposals is the exploit-locus proposal channel record when
	// one supplied or replayed proposals: provenance, pinned digests,
	// the admitted members or the fail-closed load error. nil when no
	// channel was requested — the binding route then never attempts.
	ExploitProposals *ExploitProposalsInput

	// ExploitBinding is the lane's own deterministic exploit-locus
	// binding attempt for a symbol-less advisory. nil when no channel
	// was supplied; populated (Complete or not) when the binding was
	// attempted, with the per-proposal verifications retained for
	// audit. Only a Complete binding may extend the post-reach
	// sink-set basis.
	ExploitBinding *LaneExploitBinding

	// ImplementationAxis records the deterministic lane's own
	// implementation-presence evaluation over the admitted proposals:
	// the dedicated observation/evidence-ref carrier the decision and
	// the report bind to (the axis mutates Affected but the
	// affected-resolve observation minted earlier stays the record of
	// the resolver chain alone). nil when no proposals were supplied —
	// an implementation axis without a proposal channel was never
	// attempted, which is different from an attempted-but-undecidable
	// axis (the latter still records its observation).
	ImplementationAxis *LaneImplementationAxis

	// SymbolProof is the lane's own bounded symbol-unreachability
	// attempt, evaluated through the VerifyDecision authority route
	// (FalsifierDeclaredSymbolUnreached). nil when the attempt did not
	// apply — a module/package-only advisory or an applicability axis
	// already FALSE — so legacy lanes keep their exact shape.
	SymbolProof *LaneSymbolProof

	// ConfigProof is the lane's own bounded post-reach configuration
	// attempt: the exact trigger argument is traced at every live site of
	// a complete advisory-bound sink closure and the resulting FALSE is
	// re-derived by the verifier. It is set only for a terminal
	// NO_EXPLOIT_PATH_FOUND; nil when the route does not apply (no
	// admissible config-trust assumption, package/module-only subjects,
	// unresolved non-absent advisory sink, disagreement on the trigger
	// argument) or did not close — the case then keeps the generic
	// INCONCLUSIVE path.
	ConfigProof *LaneConfigProof

	// RequestedID is the caller's request identity — the id discovery,
	// composition and every consumer report. It survives a primary
	// resolution failure, unlike the resolved advisory record id.
	RequestedID string
	// RecordOnly records that the lane stopped at the record-finalization
	// boundary and therefore owns no request composition.
	RecordOnly bool
	// ExactRecordIntake records that the lane used the requested-finding
	// contract's exact-bytes intake: no alias/feed subject merging ran.
	ExactRecordIntake bool
	// RecordPin pins the exact advisory bytes this record assessment was
	// derived from. It is the proof that no other record's ranges,
	// symbols, claims or completeness leaked in.
	RecordPin *domain.RecordPin
	// CorpusDeclaration is the operator-declared corpus boundary this
	// request ran under. A supplied feed alone is not a declaration.
	CorpusDeclaration *domain.CorpusDeclaration
	// CorpusManifest is the observed enumeration of that corpus: evidence
	// about the corpus, never about any vulnerability.
	CorpusManifest *domain.CorpusManifest
	// Discovery records which candidates the configured corpus nominated
	// and their assessment dispositions. It never transfers identity,
	// applicability or exploitability.
	Discovery *domain.RelatedDiscovery
	// Attributions records the directional CVE-to-record attribution
	// attempts. Only admitted entries may bind a record's independently
	// earned positive to the requested CVE.
	Attributions []domain.CVEAttribution
	// RelatedAssessments holds each nominated candidate's own independent
	// assessment. The nested cases are pointers because an analysis case
	// owns a mutex and an evidence graph.
	RelatedAssessments []domain.RelatedRecordAssessment
	// RequestComposition is the lane's re-admitted request answer, written
	// only by PublishRequest. Nil means the lane never composed a request,
	// and the report must not claim one.
	RequestComposition *domain.RequestedFinding
	// compositionAdmitted marks RequestComposition as the output of
	// PublishRequest's re-admission. It is unexported on purpose: no caller
	// can hand-build a composition and declare it publishable.
	compositionAdmitted bool
	// RequestedCase retains the canonical record/proof pins for fresh publication admission.
	RequestedCase *domain.AnalysisCase
	// DefectSemantics is the admitted defect-semantics contract this lane's
	// negative routes require before a deadness observation may become an
	// exploit falsifier. It is never derived from method names, evidence-id
	// prefixes, sibling liveness or prose: it is the typed contract resolved
	// by the shared semantic selection. Nil means this lane cannot convert
	// deadness into a negative — the routes stay INCONCLUSIVE.
	DefectSemantics *domain.DefectSemanticsContract
	// RecordModel is the exploit model the lane's own bounded proof route
	// built, kept verbatim so the record case re-admits through the one
	// verdict authority instead of re-deriving the proof. Nil when the
	// lane's record answer is the applicability chain alone.
	RecordModel *domain.ExploitModel
 RecordRootCause *domain.RootCauseModel
	// RecordClaims are the claims that proof route evaluated, in call
	// order. They belong to this record's own assessment.
	RecordClaims []domain.Claim
	// RecordEvidence is the evidence the proof route grounded those claims
	// in — this record's own closure and argument traces.
	RecordEvidence []domain.Evidence

	// outputDir is the persistence root persist() recorded: the base
	// externalized payload references resolve under. Empty before
	// persist or on synthetic lanes — a payload_ref then resolves to
	// nothing and the authoritative decode fails closed.
	outputDir string
}

// LaneSymbolProof records the deterministic lane's own bounded
// symbol-unreachability attempt (design §5.1 extension): when
// applicability resolved module-present=TRUE and version-affected=TRUE
// and the advisory declared exact symbol subjects, the lane dispatched
// evidencetools.SymbolUnreachabilityTool for exactly those subjects
// through the strict session and projected the audited records through
// VerifyDecision's deterministic authority route — no agent, no
// decision artifact. Trace/Observations are the lane-renumbered
// observation copies, Requests the declared per-module check list, and
// Audit the session audit records drained for exactly this attempt —
// the persistence pins VerificationObservationIndex and the authority
// route bind against. Decision is the authoritative outcome:
// NO_EXPLOIT_PATH_FOUND only on a complete audit-bound proof, otherwise
// INCONCLUSIVE carrying the primitive's named limitations; this route
// can never yield NOT_AFFECTED. The whole struct is nil whenever the
// attempt did not run (module/package-only advisory or an applicability
// axis already resolved FALSE).
type LaneSymbolProof struct {
	Trace    *VerificationTrace
	Audit    []evidencetools.AuditRecord
	Decision EvidenceDecision
}

// postReachConfigTool names the lane-recorded post-reach configuration
// check: one observation carrying the exact sink-closure attempt, its
// verified claim, the resulting verdict and the policy assumption the
// verdict cited.
const postReachConfigTool = "post-reach-config"

// LaneConfigProof records the deterministic lane's own bounded post-reach
// configuration attempt (G1). The attempt runs only when the applicability
// chain resolved every axis TRUE with a version, the advisory declares
// exact symbol subjects, an admitted product-scope config-trust assumption
// exists, and the exact trigger argument can be identified. It builds the
// advisory-bound sink set and its closure through the same source-index
// primitives the classic collector uses, traces the trigger argument at
// every live site, evaluates the post-reach contract and re-derives the
// FALSE through goanalysis.Verifier. ObservationID names the recorded
// lane observation (the check's persisted record), Trace gives the report
// its executed-check row, and Decision is the authoritative projection:
// NO_EXPLOIT_PATH_FOUND with FalsifierTrustedInfrastructure /
// BasisConfigOrigin and the declared assumption ids, or nothing (the
// struct stays nil and the case keeps INCONCLUSIVE). This route can never
// yield NOT_AFFECTED.
type LaneConfigProof struct {
	ObservationID string
	Trace         *VerificationTrace
	Decision      EvidenceDecision
}

// implementationAxisTool names the lane-recorded implementation-presence
// check: one observation carrying the proposal intake, the per-proposal
// deterministic verifications, the finalized affected chain and the
// target/assumption boundary the conclusion reached under.
const implementationAxisTool = "implementation-axis"

// LaneImplementationAxis records the deterministic lane's own
// implementation-presence evaluation (G2): the dedicated observation /
// evidence-ref carrier the decision, the report and the branch rules
// bind to. ObservationID names the recorded lane observation;
// EvidenceIDs are the verifier evidence ids that observation carries
// (the refs a NOT_AFFECTED decision cites via obs:<ObservationID>);
// AssumptionIDs are the admitted supported-targets policy ids the
// product-scope conclusion cited — policy inputs, never evidence.
// This route can only yield NOT_AFFECTED through the standard
// applicability chain; it never produces NO_EXPLOIT_PATH_FOUND.
type LaneImplementationAxis struct {
	ObservationID string
	EvidenceIDs   []string
	AssumptionIDs []string
}

// FactRef returns the verified-fact id for an observation, or "" when the
// observation did not become a fact.
func (r *LaneResult) FactRef(obsID string) string {
	for _, f := range r.Facts {
		if f.Provenance.ObservationID == obsID {
			return f.ID
		}
	}
	return ""
}

// RunDeterministic executes design §5.1 in the fixed order. It writes
// observations.jsonl, one canonical artifact per observation, and
// deterministic-facts.json under OutputDir (the only writable location).
// The strict evidence session it opens is closed before returning.
func RunDeterministic(ctx context.Context, o LaneOptions) (*LaneResult, error) {
	res, es, err := runDeterministic(ctx, o)
	if es != nil {
		_ = es.Close()
	}
	return res, err
}

// RunDeterministicSession is RunDeterministic with the strict confined
// evidence session left open for the case's remaining phases: the same
// session — its confinement roots, audit trail and in-memory MCP client
// — stays available through the agent turn and the bounded verification
// phase, then the caller closes it exactly once (EvidenceSession.Close).
// On error the handle is already closed and returns nil.
func RunDeterministicSession(ctx context.Context, o LaneOptions) (*LaneResult, *EvidenceSession, error) {
	res, es, err := runDeterministic(ctx, o)
	if err != nil && es != nil {
		_ = es.Close()
		es = nil
	}
	return res, es, err
}

// VerificationObservationIndex builds DecisionInput.ObservationIndex for
// the bounded verification phase: for every trace observation it lists
// the digest/pointer refs the persistence layer pins for that observation
// — the sha256 of the session-recorded payload bytes plus every
// session-recorded evidence ref — taken from the drained session audit
// records, never from the trace observation's own copy. An observation
// with no session audit record (a synthesized failure) gets no index
// entry, so nothing it cites can resolve. Audit records are paired to
// trace observations by the session-minted (already caller-renumbered)
// observation id; a record whose observation carries an id the trace
// never produced contributes nothing.
func VerificationObservationIndex(trace *VerificationTrace, audit []evidencetools.AuditRecord) map[string][]string {
	byID := map[string]*evidencetools.Observation{}
	if trace != nil {
		for _, o := range trace.Observations {
			if o != nil && o.ID != "" {
				byID[o.ID] = o
			}
		}
	}
	idx := map[string][]string{}
	for _, rec := range audit {
		o := rec.Observation
		if o == nil || o.ID == "" {
			continue
		}
		if _, ok := byID[o.ID]; !ok {
			continue
		}
		var pins []string
		if o.Data != nil {
			if b, err := json.Marshal(o.Data); err == nil {
				sum := sha256.Sum256(b)
				pins = append(pins, "sha256:"+hex.EncodeToString(sum[:]))
			}
		}
		for _, ref := range o.EvidenceRefs {
			if ref != "" {
				pins = append(pins, ref)
			}
		}
		if len(pins) > 0 {
			idx[o.ID] = append(idx[o.ID], pins...)
		}
	}
	return idx
}

// runDeterministic is the lane body. The returned EvidenceSession is
// always live on success and always closed-on-error semantics rest with
// the two public entry points above.
func runDeterministic(ctx context.Context, o LaneOptions) (*LaneResult, *EvidenceSession, error) {
	res := &LaneResult{
		ArtifactByObs:     map[string]ArtifactRef{},
		CanonicalByObs:    map[string]string{},
		Ingress:           map[string]domain.IngressClosure{},
		obsIndex:          map[string]*evidencetools.Observation{},
		RequestedID:       strings.TrimSpace(o.CVE),
		RecordOnly:        o.RecordOnly,
		ExactRecordIntake: exactRecordIntake(o),
		DefectSemantics:   o.DefectSemantics,
	}
	used := map[string]bool{}
	var seq int
	nextID := func() string {
		for {
			seq++
			id := fmt.Sprintf("OBS-%04d", seq)
			if !used[id] {
				used[id] = true
				return id
			}
		}
	}
	record := func(o2 *evidencetools.Observation, tool string, args any) {
		if o2.ID == "" {
			o2.ID = nextID()
		}
		used[o2.ID] = true
		res.Observations = append(res.Observations, o2)
		res.obsIndex[o2.ID] = o2
		raw, _ := json.Marshal(args)
		res.Records = append(res.Records, evidencetools.AuditRecord{
			Tool: tool, Args: raw, Observation: o2, RecordTime: time.Now().UTC(),
		})
	}
	mintObs := func(tool, fact, scope string, comp evidencetools.Completeness,
		data any, sd *evidencetools.ScopeDetails, lims []string) *evidencetools.Observation {
		o2 := &evidencetools.Observation{
			Tool: tool, Fact: fact, Scope: scope, Completeness: comp,
			ToolStatus: evidencetools.StatusOK, ScopeDetails: sd, Limitations: lims,
		}
		if data != nil {
			o2.Data = data
		}
		finishLaneObservation(o2)
		return o2
	}

	if err := os.MkdirAll(o.OutputDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("output dir: %w", err)
	}

	// ---- Step 1: normalize + preflight the snapshot before loading ----
	root, err := filepath.Abs(o.SnapshotPath)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot path: %w", err)
	}
	if canon, cerr := filepath.EvalSymlinks(root); cerr == nil {
		root = canon
	}
	if st, serr := os.Stat(root); serr != nil || !st.IsDir() {
		return nil, nil, fmt.Errorf("snapshot %s is not a directory: %v", root, serr)
	}
	res.SnapshotRoot = root
	if err := repository.VerifyContained(root); err != nil {
		return nil, nil, fmt.Errorf("snapshot containment failed (no evidence may be bound to an unsafe tree): %w", err)
	}
	if err := repository.CheckPathReplacements(root); err != nil {
		return nil, nil, fmt.Errorf("snapshot path-replacement preflight failed: %w", err)
	}
	contentHash, err := repository.ContentHash(root)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot content hash: %w", err)
	}
	res.ContentHash = contentHash
	record(mintObs("repository-preflight",
		fmt.Sprintf("snapshot %s contained, replaces confined, content hash %s", root, contentHash),
		"VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree",
		evidencetools.CompletenessComplete,
		map[string]string{"snapshot_root": root, "content_hash": contentHash},
		&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root,
			CoverageRule: "closed walk of the snapshot tree (canonical hash)"},
		nil), "repository-preflight", map[string]any{"snapshot": root})

	// ---- Step 2: snapshot identity/build facts ----
	tc, tcNotes := toolchain.Resolve(ctx, o.AnalysisGo)
	res.Toolchain = tc
	// The release-metadata channel is parsed once, here, so the lane
	// snapshot and the evidence session consume the identical typed
	// summary; a malformed/unreadable document is already a typed
	// NOT_RUN/RELEASE_METADATA_INVALID outcome, never a lane error.
	var releaseMeta *domain.ReleaseEvidenceSummary
	if strings.TrimSpace(o.ReleaseMetadata) != "" {
		releaseMeta = repository.LoadReleaseMetadata(o.ReleaseMetadata)
	}
	// The ticket channel is parsed once, here, so the lane record and
	// the resolver consume identical claims; a malformed or unreadable
	// ticket is already a typed ParseError outcome — the check degrades
	// to NOT_CHECKED, never a lane error.
	var ticketRec *TicketRecord
	if strings.TrimSpace(o.Ticket) != "" {
		ticketRec = loadTicket(o.Ticket, o.TicketID)
		res.Ticket = ticketRec
	}
	// The declared-assumptions channel is parsed once, here: the lane
	// record, the report input and every consumer see the identical
	// typed members (or the identical fail-closed LoadError). It never
	// feeds the evidence session — assumptions are policy inputs.
	if strings.TrimSpace(o.DeclaredAssumptions) != "" {
		res.Assumptions = repository.LoadDeclaredAssumptions(o.DeclaredAssumptions)
	}
	// The output directory is forbidden ground for artifact acquisition:
	// the channel may never read back bytes it or the lane just wrote.
	aopts := o.ArtifactOptions
	if outAbs, aerr := filepath.Abs(o.OutputDir); aerr == nil {
		aopts.ForbidDirs = append(append([]string{}, aopts.ForbidDirs...), outAbs)
	}
	snapOpts := repository.SnapshotOptions{
		GOOS: o.GOOS, GOARCH: o.GOARCH, BuildTags: o.BuildTags,
		ExternalCommitSHA: o.ExternalCommitSHA,
		GoBin:             tc.GoBin, Env: tc.Env,
		Artifact:        aopts,
		ReleaseMetadata: releaseMeta,
	}
	snap, err := (repository.Service{}).Snapshot(ctx, root, snapOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot identity: %w", err)
	}
	if snap.ContentHash == "" {
		snap.ContentHash = contentHash
	}
	res.Snapshot = snap
	{
		lims := append([]string{}, tcNotes...)
		if snap.ReleaseGoVersion == "" {
			lims = append(lims, "release toolchain is UNKNOWN: no binary build info or snapshot-local version pin; go.mod go directive is a minimum, not the release version")
		}
		snapView := laneSnapshotViewOf(snap)
		if note := laneListBoundNote("release module graph",
			len(snapView.ReleaseModules), len(snap.ReleaseModules)); note != "" {
			lims = append(lims, note)
		}
		record(mintObs("repository-snapshot",
			fmt.Sprintf("snapshot identity %s: go directive %s, release toolchain %q, %s/%s",
				snap.Commit, snap.GoModDirective, snap.ReleaseGoVersion, snap.GOOS, snap.GOARCH),
			"repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)",
			evidencetools.CompletenessComplete, snapView,
			&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root,
				ExternalSHA:  snap.ExternalCommitSHA,
				CoverageRule: "single product snapshot probe (go version + manifest scan, no git history when external identity supplied)"},
			lims), "repository-snapshot", snapOpts)
	}
	if snap.ReleaseEvidenceRequired {
		// Every explicitly requested release-evidence channel records its
		// own lane observation: the resolved/merged status and reason are
		// persisted so a fail-closed NOT_RUN is an auditable outcome, not
		// a gap in the record. Args carry presence booleans only — never
		// a URL, a credential, or a credential env value.
		re := snap.ReleaseEvidence
		status := string(domain.ReleaseStatusNotRequested)
		reason := ""
		if re != nil {
			status = string(re.Status)
			reason = re.ReasonCode
		}
		comp := evidencetools.CompletenessComplete
		var rlims []string
		if re == nil || re.Status == domain.ReleaseStatusNotRun {
			comp = evidencetools.CompletenessPartial
			rlims = append(rlims, fmt.Sprintf(
				"release evidence channel failed closed: %s — a missing declared channel is fail-closed, never evidence of absence",
				reason))
		}
		record(mintObs("release-evidence",
			fmt.Sprintf("release evidence channels: status %s reason %q", status, reason),
			"release-artifact + release-metadata channel merge via repository.Service.Snapshot precedence",
			comp, releaseEvidenceData(snap),
			&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root,
				CoverageRule: "requested release-evidence channels only; discovered snapshot declarations stay SUPPORTING"},
			rlims), "release-evidence", map[string]any{
			"artifact_path":    aopts.Path != "",
			"artifact_url":     aopts.URL != "",
			"release_metadata": releaseMeta != nil,
		})
	}

	// ---- Step 3: load exactly one frozen advisory ----
	adv, err := loadFrozenAdvisory(ctx, o)
	if err != nil {
		return nil, nil, err
	}
	res.Advisory = *adv
	// The exact record pin is the proof that this assessment used these
	// bytes and no other record's ranges, symbols or census.
	res.RecordPin = advisoryRecordPin(*adv)
	loadArgs := map[string]any{"cve": o.CVE, "source": adv.Input.SourceKind, "path": adv.Input.SourcePath}
	if adv.Input.FeedResolution != nil {
		// The feed attempt is part of the load record: its outcome is
		// auditable alongside the frozen source pin.
		loadArgs["feed_resolution"] = adv.Input.FeedResolution.Status
	}
	record(mintObs("advisory-load",
		fmt.Sprintf("frozen advisory %s resolved to %s (%d affected entries, source %s)",
			o.CVE, adv.Input.ResolvedID, len(adv.Impls), adv.Input.SourceKind),
		fmt.Sprintf("FileSource(%s) with alias enrichment disabled; no network", adv.Input.SourcePath),
		evidencetools.CompletenessComplete,
		map[string]any{"requested_id": o.CVE, "resolved_id": adv.Input.ResolvedID,
			"entries": len(adv.Impls), "outcome": adv.Outcome,
			"exact_record_intake": res.ExactRecordIntake},
		&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root,
			Subject: o.CVE, CoverageRule: "single frozen advisory document load"},
		advisoryLimitations(adv)), "advisory-load", loadArgs)

	// ---- Step 3b: request-level corpus discovery ----
	// A configured corpus nominates candidates against its own pinned
	// bytes and supplies the observed manifest. It is never closure
	// authority: a feed, a finished scan or an empty nomination set says
	// nothing about implementations outside the corpus.
	if o.Corpus != nil {
		if o.Corpus.Declaration != nil {
			decl := *o.Corpus.Declaration
			res.CorpusDeclaration = &decl
		}
		corpus, cerr := advfeed.AcquireCorpus(ctx, *o.Corpus)
		if cerr != nil {
			return nil, nil, fmt.Errorf("advisory corpus: %w", cerr)
		}
		manifest := corpus.Manifest()
		res.CorpusManifest = &manifest
		discovery := corpus.Discover(res.RequestedID, res.discoverySeed(adv))
		res.Discovery = &discovery
		record(mintObs("advisory-corpus",
			fmt.Sprintf("advisory corpus %s: enumeration %s, %d pinned document(s), %d nominated candidate(s)",
				manifest.Reference, manifest.Enumeration, len(manifest.Documents), len(discovery.Candidates)),
			"advfeed.AcquireCorpus + Corpus.Discover (operator-declared corpus, no ambient lookup)",
			corpusCompleteness(manifest.Enumeration),
			corpusObservationData(manifest, discovery),
			&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root, Subject: res.RequestedID,
				CoverageRule: "declared corpus boundary only; implementations outside it were not examined"},
			discovery.Limitations), "advisory-corpus", map[string]any{
			"enumeration": string(manifest.Enumeration),
			"declared":    res.CorpusDeclaration != nil,
			"selected":    len(o.Corpus.Selections),
		})
	}

	// The implementation-locus proposal channel is parsed once, here:
	// the lane record and every consumer see the identical typed
	// members (or the identical fail-closed LoadError). A
	// replay-agent-turn carries its retained proposals through the
	// same record shape; two proposal sources for one lane never mix.
	switch {
	case strings.TrimSpace(o.ImplementationLocusProposals) != "" &&
		len(o.RetainedProposals) > 0:
		res.ImplementationProposals = &ImplementationProposalsInput{
			Source:    ImplementationProposalsSourceArtifact,
			Path:      repository.ProvenanceLocalRef(o.ImplementationLocusProposals),
			LoadError: ImplementationProposalsLoadInvalid,
		}
	case strings.TrimSpace(o.ImplementationLocusProposals) != "":
		res.ImplementationProposals = loadImplementationProposalArtifact(
			o.ImplementationLocusProposals, adv)
	default:
		res.ImplementationProposals = replayedImplementationProposals(
			o.RetainedProposals, o.RetainedAnswerSHA256)
	}

	// The exploit-locus proposal channel is parsed once, beside the
	// implementation channel: the lane record and every consumer see the
	// identical typed members (or the identical fail-closed LoadError).
	// Two proposal sources for one lane never mix.
	switch {
	case strings.TrimSpace(o.ExploitLocusProposals) != "" &&
		len(o.RetainedExploitProposals) > 0:
		res.ExploitProposals = &ExploitProposalsInput{
			Source:    ExploitProposalsSourceArtifact,
			Path:      repository.ProvenanceLocalRef(o.ExploitLocusProposals),
			LoadError: ExploitProposalsLoadInvalid,
		}
	case strings.TrimSpace(o.ExploitLocusProposals) != "":
		res.ExploitProposals = loadExploitProposalArtifact(
			o.ExploitLocusProposals, adv)
	default:
		res.ExploitProposals = replayedExploitProposals(
			o.RetainedExploitProposals, o.RetainedAnswerSHA256)
	}

	if ticketRec != nil {
		// The supplied ticket records its own lane observation: the
		// pinned digest plus the parsed claims (or the typed parse
		// error), so the identity check's inputs are auditable exactly
		// like the other input channels.
		tdata := map[string]any{"path": ticketRec.Path}
		if ticketRec.SHA256 != "" {
			tdata["sha256"] = ticketRec.SHA256
		}
		var tlims []string
		comp := evidencetools.CompletenessComplete
		fact := fmt.Sprintf("ticket %s parsed: %d claim field(s)", ticketRec.Path, claimFieldCount(ticketRec.Claims))
		if ticketRec.Claims != nil {
			tdata["claims"] = ticketRec.Claims
		}
		if ticketRec.DistributionURL != "" {
			// The ticket's distribution locator is part of the channel's
			// auditable record — sanitized provenance, never fetched.
			tdata["distribution_url"] = ticketRec.DistributionURL
		}
		if ticketRec.ParseError != "" {
			comp = evidencetools.CompletenessPartial
			tdata["parse_error"] = ticketRec.ParseError
			fact = fmt.Sprintf("ticket %s could not be parsed (%s)", ticketRec.Path, ticketRec.ParseError)
			tlims = append(tlims,
				"ticket unparsable — the ticket-build identity check degrades to NOT_CHECKED, never a silent pass")
		}
		record(mintObs("ticket-load", fact,
			"tracker intake parse of the supplied ticket (JSON ticket/array or plain text, no LLM)",
			comp, tdata,
			&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root,
				CoverageRule: "single operator-supplied tracker ticket"},
			tlims), "ticket-load", map[string]any{"supplied": true})
	}

	if da := res.Assumptions; da != nil {
		// The declared-assumptions channel records only provenance and
		// the typed member identity — sanitized path, pinned digest,
		// schema, ids/kinds/scopes and the intake outcome. The statement
		// text stays on the report input, never in the observation; and
		// nothing here is evidence of any code fact.
		adata := map[string]any{"path": da.Path}
		if da.SHA256 != "" {
			adata["sha256"] = da.SHA256
		}
		if da.Schema != "" {
			adata["schema"] = da.Schema
		}
		if da.ContentDigest != "" {
			adata["content_digest"] = da.ContentDigest
		}
		if len(da.Assumptions) > 0 {
			members := make([]map[string]string, 0, len(da.Assumptions))
			for _, a := range da.Assumptions {
				members = append(members, map[string]string{"id": a.ID, "kind": string(a.Kind)})
			}
			adata["assumptions"] = members
			adata["ids"] = da.AssumptionIDs()
		}
		comp := evidencetools.CompletenessComplete
		var dlims []string
		fact := fmt.Sprintf("declared assumptions %s loaded: %d policy/scope input(s), digests verified",
			da.Path, len(da.Assumptions))
		if da.LoadError != "" {
			comp = evidencetools.CompletenessPartial
			adata["load_error"] = da.LoadError
			fact = fmt.Sprintf("declared assumptions %s failed intake (%s)", da.Path, da.LoadError)
			dlims = append(dlims,
				"declared assumptions failed closed — every assumption-dependent gate stays unclosed; a policy input is never inferred from evidence")
		} else {
			dlims = append(dlims,
				"declared assumptions are operator policy/scope inputs, not evidence: no assumption statement is a claim or a code fact; this record only pins the document (path, digest, ids)")
		}
		record(mintObs("declared-assumptions",
			fact,
			"repository.LoadDeclaredAssumptions intake of the operator-supplied declared-assumptions/1 document (closed member set, size bound, sha256 + content digest pins)",
			comp, adata,
			&evidencetools.ScopeDetails{SnapshotHash: contentHash, SnapshotRoot: root,
				CoverageRule: "single operator-supplied declared-assumptions document"},
			dlims), "declared-assumptions", map[string]any{"supplied": true, "load_error": da.LoadError})
	}

	// ---- Step 5: strict session boundary ----
	es, err := openEvidenceSession(ctx, o, root, snap, tc, adv, releaseMeta)
	if err != nil {
		return nil, nil, err
	}
	sess := es.sess
	res.ToolEnv = sess.ToolEnv

	call := func(tool string, args map[string]any) *evidencetools.Observation {
		raw, _ := json.Marshal(args)
		o2, cerr := es.Call(ctx, tool, raw)
		if o2 == nil {
			// The tool adapter itself failed to answer — still a lane
			// observation, never a silent skip.
			reason := "no observation returned"
			if cerr != nil {
				reason = cerr.Error()
			}
			o2 = &evidencetools.Observation{
				Tool: tool, Fact: "tool call failed at transport: " + reason,
				Scope: "check not performed", Completeness: evidencetools.CompletenessUnknown,
				ToolStatus: evidencetools.StatusError, Error: reason,
				ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: contentHash},
			}
		}
		// The lane owns the OBS id space: session-minted ids collide
		// with lane-minted ones (both start at OBS-0001), so renumber
		// unconditionally, including inside the captured audit records.
		o2.ID = nextID()
		res.Observations = append(res.Observations, o2)
		res.obsIndex[o2.ID] = o2
		// Keep the session's own audit record when it exists (it carries
		// args + executions), else synthesize one.
		if recs := es.DrainAudit(); len(recs) > 0 {
			for i := range recs {
				if recs[i].Observation != nil {
					recs[i].Observation.ID = o2.ID
				}
			}
			res.Records = append(res.Records, recs...)
		} else {
			res.Records = append(res.Records, evidencetools.AuditRecord{
				Tool: tool, Args: raw, Observation: o2, RecordTime: time.Now().UTC()})
		}
		return o2
	}

	// Session-scoped snapshot + advisory records (the session view of the
	// same inputs; keeps the session's own cache consistent for later
	// handlers that read s.snap / s.vuln).
	call("get_product_snapshot", map[string]any{})
	// Machine admission uses the effective execution build, including the
	// strict session's resolved GOFLAGS, not the earlier discovery probe.
	origExternalSHA := res.Snapshot.ExternalCommitSHA
	res.Snapshot = sess.Build
	res.Snapshot.ExternalCommitSHA = origExternalSHA
	call("get_vulnerability", map[string]any{})
	if dg := call("get_dependency_graph", map[string]any{}); dg != nil {
		res.GraphModules = graphModulePaths(dg.Data)
	}

	goImpls := goImplementations(adv.Impls)
	for _, im := range goImpls {
		call("get_module_version", map[string]any{"module": im.Module})
	}

	// ---- Step 6: product applicability via the existing resolver ----
	product := sess.Build
	product.Repository = sess.SnapshotRoot
	product.ExternalCommitSHA = sess.ExternalSHA
	product.ContentHash = sess.SnapshotHash
	resolver := affected.GoResolver{
		Tool: affected.ExecGoTool{
			Bin: sess.ToolBin, Env: sess.ToolEnv, Version: sess.ToolVer,
		},
		// Effective-source identity is recorded from the same bound build the
		// sender's own resolution used: the session snapshot's replace
		// directives, workspace mode and pinned module cache.
		Sources: &goanalysis.Index{Dir: sess.SnapshotRoot, Env: sess.ToolEnv, Build: product},
	}
	if ticketRec != nil {
		// The ticket's claims ride the resolver: a declared package
		// version that differs from the resolved one blocks the version
		// axis inside Resolve; a parse error degrades the check to
		// NOT_CHECKED with the named reason recorded.
		resolver.Ticket = ticketRec.Claims
		resolver.TicketErr = ticketRec.ParseError
	}
	// The resolver receives a copy whose scope is deep-copied: its
	// result becomes the lane's affected chain, and neither side may
	// reach the other's census through a shared pointer.
	advisoryCopy := *adv.Vuln
	advisoryCopy.Scope = adv.Vuln.Scope.Clone()
	ares, aev, rerr := resolver.Resolve(ctx, advisoryCopy, product)
	res.Affected = ares
	res.AffectedEvidence = aev
	{
		comp := evidencetools.CompletenessComplete
		lims := append([]string{}, ares.Limitations...)
		fact := fmt.Sprintf("applicability chain for %s: module_present=%s version_affected=%s package_present=%s build_relevant=%s (selected %v)",
			adv.Vuln.ID, ares.ModulePresent, ares.VersionAffected, ares.PackagePresent, ares.BuildRelevant, ares.SelectedModules)
		var o2 *evidencetools.Observation
		if rerr != nil {
			o2 = &evidencetools.Observation{
				Fact:  "affected resolution failed: " + rerr.Error(),
				Scope: "check not performed", Completeness: evidencetools.CompletenessUnknown,
				ToolStatus: evidencetools.StatusError, Error: rerr.Error(),
			}
		} else {
			sd := &evidencetools.ScopeDetails{
				SnapshotHash: sess.SnapshotHash, SnapshotRoot: sess.SnapshotRoot,
				ExternalSHA: sess.ExternalSHA, Subject: adv.Vuln.ID,
				CoverageRule: "closed applicability chain: module graph → version ranges → import closure → build relevance",
			}
			evidenceView := laneEvidenceView(aev)
			if note := laneEvidenceBoundNote(evidenceView); note != "" {
				lims = append(lims, note)
			}
			data := map[string]any{"affected_result": ares, "evidence": evidenceView}
			if re := releaseEvidenceData(product); re != nil {
				data["release_evidence"] = re
			}
			for k, v := range evidencetools.ReleaseProvenanceExtra(product) {
				if sd.Extra == nil {
					sd.Extra = map[string]string{}
				}
				sd.Extra[k] = v
			}
			o2 = mintObs("affected-resolve", fact,
				"affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)",
				comp, data, sd, lims)
		}
		record(o2, "affected-resolve", map[string]any{"vuln": adv.Vuln.ID})
	}

	// ---- Step 6a2: lane-owned implementation-presence axis ----
	// When the proposal channel supplied implementation-locus
	// hypotheses, the lane runs the deterministic axis immediately
	// after the resolver: admitted proposals are re-bound to this
	// frozen advisory and the exact snapshot, the recorded build
	// target and the declared supported-targets scope gate the
	// conclusion, and the finalized affected chain is updated in
	// place. A FALSE axis belongs to the standard applicability chain
	// (NOT_AFFECTED) — the bounded proof attempts below see it and
	// skip, exactly like any earlier axis FALSE. The attempt records
	// its own dedicated observation so the resolver record stays the
	// pristine statement of the resolver chain alone.
	laneImplementationAxis(ctx, res, sess, product, mintObs, record)
 if o.FixSourceCaptures!=nil { if err:=laneFixSourceCaptures(ctx,res,sess,o.FixSourceCaptures);err!=nil{return nil,nil,fmt.Errorf("fix-source captures: %w",err)} }

	// ---- Step 6b: bounded package/symbol usage checks ----
	// One package-usage observation per advisory-declared subject: a
	// package-level check per declared (or symbol-derived) package plus
	// a symbol-level check per declared symbol. A module-only advisory
	// yields no candidates — the module path is never substituted for a
	// package. Candidates are sorted for a stable call order.
	goModules := make(map[string]bool, len(goImpls))
	for _, im := range goImpls {
		goModules[im.Module] = true
	}
	for _, subj := range packageUsageCandidates(*adv.Vuln, goModules) {
		args := map[string]any{"module": subj.Module, "package": subj.Package}
		if subj.Symbol != "" {
			args["symbol"] = subj.Symbol
		}
		call(evidencetools.PackageUsageTool, args)
	}

	// ---- Step 6c: paired build-closure usage-scope checks (B41) ----
	// Immediately after the B42 block so all existing tools keep their
	// call order: one package-level check per sorted advisory-declared
	// package (explicit or symbol-projected, never a symbol-level
	// check), plus one module-level aggregate per entry that names no
	// package. The module path is never substituted for a package —
	// the aggregate carries an empty package argument by design.
	for _, subj := range usageScopeCandidates(*adv.Vuln, goModules) {
		args := map[string]any{"module": subj.Module}
		if subj.Package != "" {
			args["package"] = subj.Package
		}
		call(evidencetools.UsageScopeTool, args)
	}

	// ---- Step 7: source facts for advisory-bound subjects ----
	const maxSymbols = 16
	symbolBudget := maxSymbols
	var boundSites []domain.CallSite
	for _, im := range goImpls {
		// Module-scoped views once per module.
		mu := call("module_usage", map[string]any{"module": im.Module})
		entries := usageEntrySymbols(mu)
		if len(entries) > 0 && len(im.Symbols) > 0 {
			call("module_internal_reach", map[string]any{
				"module": im.Module, "entries": entries, "subjects": im.Symbols,
			})
		}
		if inv, iev, ierr := sess.Source.IngressInventory(ctx, im.Module, im.Symbols, 2); ierr != nil {
			record(&evidencetools.Observation{
				Fact: "ingress inventory failed: " + ierr.Error(), Scope: "check not performed",
				Completeness: evidencetools.CompletenessUnknown, ToolStatus: evidencetools.StatusError,
				Error:        ierr.Error(),
				ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: sess.SnapshotHash, ExternalSHA: sess.ExternalSHA, Subject: im.Module},
			}, "ingress-inventory", map[string]any{"module": im.Module})
		} else {
			res.Ingress[im.Module] = inv
			closureView := laneClosureViewOf(inv)
			evidenceView := laneEvidenceView(iev)
			lims := []string{"ingress inventory is bounded to the loaded module cone; a complete inventory is a scope fact, not a reachability verdict"}
			if note := laneEvidenceBoundNote(evidenceView); note != "" {
				lims = append(lims, note)
			}
			if note := laneListBoundNote("closure items", len(closureView.Items), len(inv.Items)); note != "" {
				lims = append(lims, note)
			}
			record(mintObs("ingress-inventory",
				fmt.Sprintf("ingress inventory for module %s: %d inventoried item(s), %d completeness blocker(s) (complete=%v)",
					im.Module, len(inv.Items), len(inv.Blockers), inv.Complete),
				fmt.Sprintf("goanalysis.IngressInventory over module %s (product boundary + reachable dep cone, 2 hops)", im.Module),
				evidencetools.CompletenessPartial,
				map[string]any{"closure": closureView, "evidence": evidenceView},
				&evidencetools.ScopeDetails{SnapshotHash: sess.SnapshotHash, SnapshotRoot: sess.SnapshotRoot,
					ExternalSHA: sess.ExternalSHA, Subject: im.Module},
				lims),
				"ingress-inventory", map[string]any{"module": im.Module, "subjects": im.Symbols})
		}
		for _, sr := range im.Symbols {
			if symbolBudget <= 0 {
				break
			}
			symbolBudget--
			call("find_symbol", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			// Only find_callers feeds boundSites: its sites are AST call
			// expressions, which is what the call-site-only tools below
			// require. A find_symbol declaration site is not a call and
			// must never be bound for them.
			fc := call("find_callers", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			boundSites = append(boundSites, callSitesOf(fc, 4)...)
			call("find_may_callers", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			call("find_dep_callers", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			call("scan_dynamic", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			call("interface_dispatch_sites", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			call("gated_refs", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
			call("dep_invocation_state", map[string]any{"package": sr.Package, "symbol": sr.Symbol})
		}
	}
	// Product exposure facts.
	epObs := call("find_entrypoints", map[string]any{})
	if c, ok := entrypointCount(epObs); ok {
		res.Entrypoints = c
	}
	for _, exposure := range []struct {
		name  string
		scope string
		run   func(context.Context) ([]domain.ExposureFact, error)
	}{
		{"listen-sites", "inbound listener binds in product packages",
			func(c context.Context) ([]domain.ExposureFact, error) { return sess.Source.ListenSites(c) }},
		{"inbound-auth-facts", "authentication/authorization facts around inbound handlers",
			func(c context.Context) ([]domain.ExposureFact, error) { return sess.Source.InboundAuthFacts(c) }},
	} {
		facts, ferr := exposure.run(ctx)
		if ferr != nil {
			record(&evidencetools.Observation{
				Fact: exposure.name + " failed: " + ferr.Error(), Scope: "check not performed",
				Completeness: evidencetools.CompletenessUnknown, ToolStatus: evidencetools.StatusError,
				Error:        ferr.Error(),
				ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: sess.SnapshotHash, ExternalSHA: sess.ExternalSHA},
			}, exposure.name, nil)
			continue
		}
		res.ExposureFacts = append(res.ExposureFacts, facts...)
		factsData, factsDropped := laneExposureFactsData(facts)
		factsLims := []string{"static exposure scan: a listener/dial site is a code fact, not runtime reachability"}
		if note := laneListBoundNote("facts", len(facts)-factsDropped, len(facts)); note != "" {
			factsLims = append(factsLims, note)
		}
		record(mintObs(exposure.name,
			fmt.Sprintf("%d %s observed", len(facts), exposure.scope),
			exposure.scope+" (static source scan; runtime reachability is out of scope)",
			evidencetools.CompletenessPartial, factsData,
			&evidencetools.ScopeDetails{SnapshotHash: sess.SnapshotHash, SnapshotRoot: sess.SnapshotRoot,
				ExternalSHA: sess.ExternalSHA},
			factsLims),
			exposure.name, nil)
	}
	for _, im := range goImpls {
		facts, ferr := sess.Source.DialSites(ctx, im.Module)
		if ferr != nil {
			record(&evidencetools.Observation{
				Fact: "dial-sites failed: " + ferr.Error(), Scope: "check not performed",
				Completeness: evidencetools.CompletenessUnknown, ToolStatus: evidencetools.StatusError,
				Error:        ferr.Error(),
				ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: sess.SnapshotHash, ExternalSHA: sess.ExternalSHA, Subject: im.Module},
			}, "dial-sites", map[string]any{"module": im.Module})
			continue
		}
		res.ExposureFacts = append(res.ExposureFacts, facts...)
		dialData, dialDropped := laneExposureFactsData(facts)
		dialLims := []string{"a dial site is a code fact; whether the endpoint is attacker-reachable is out of scope"}
		if note := laneListBoundNote("facts", len(facts)-dialDropped, len(facts)); note != "" {
			dialLims = append(dialLims, note)
		}
		record(mintObs("dial-sites",
			fmt.Sprintf("%d outbound dial/endpoint site(s) into module %s", len(facts), im.Module),
			fmt.Sprintf("outbound endpoints into module %s (static source scan)", im.Module),
			evidencetools.CompletenessPartial, dialData,
			&evidencetools.ScopeDetails{SnapshotHash: sess.SnapshotHash, SnapshotRoot: sess.SnapshotRoot,
				ExternalSHA: sess.ExternalSHA, Subject: im.Module},
			dialLims),
			"dial-sites", map[string]any{"module": im.Module})
	}
	// Bounded concrete call sites: provenance + guards on up to 8 sites.
	for i, site := range boundSites {
		if i >= 8 {
			break
		}
		call("trace_argument", map[string]any{"file": site.File, "line": site.Line, "column": site.Column, "arg_index": -1})
		call("find_validations", map[string]any{"file": site.File, "line": site.Line, "column": site.Column, "arg_index": -1})
		call("check_call_site_guard", map[string]any{"file": site.File, "line": site.Line, "column": site.Column})
	}
	// check_missing_call runs only for an explicit check/pipeline pair
	// (design §5.1.7); none is derivable from the advisory alone, so the
	// lane records its non-invocation as a scope note on the report.

	// ---- Step 7b: lane-owned bounded symbol-unreachability attempt ----
	// When applicability established module-present=TRUE and
	// version-affected=TRUE, no applicability axis resolved FALSE and
	// the advisory declares exact symbol subjects, the lane itself
	// dispatches the bounded proof — recorded through the same audited
	// call path as every other lane check. PackagePresent/BuildRelevant
	// UNKNOWN stays in scope: the proof is the bounded instrument that
	// can close that axis; an axis already FALSE belongs to the
	// deterministic applicability chain (NOT_AFFECTED) and never reaches
	// this route. Module/package-only advisories produce no subjects and
	// skip the step entirely.
	symbolProof := laneSymbolProofCalls(res, call)

	// ---- Step 7c: lane-owned bounded post-reach configuration attempt ----
	// The exact-argument configuration route runs only when the affected
	// chain resolved every axis TRUE with a version, the advisory declares
	// exact symbol subjects, and an admitted product-scope config-trust
	// assumption exists. Without those inputs the route does not apply and
	// the lane keeps its generic INCONCLUSIVE path; --trusted-peer, tags
	// and host defaults are never substitutes. A terminal proof records
	// its own observation here (before persistence) so the report carries
	// the executed check, its closure and its assumption boundary.
	// ---- Step 7b3: lane-owned exploit-locus binding attempt ----
	// For a symbol-less advisory the post-reach route has no
	// advisory-declared sink set. The binding route re-checks the
	// admitted LLM hypotheses against the snapshot and, only when every
	// deterministic check closes, supplies the verified product-facing
	// sink set the configuration proof below may consume.
	laneExploitLocus(ctx, res, sess, product, mintObs, record)

	configProof := lanePostReachConfig(ctx, res, sess, record)

	// ---- Step 8: govulncheck coverage (UNSUPPORTED without --govulndb) ----
	call("run_govulncheck", map[string]any{})

	// ---- Step 9: persist artifacts, observations, facts ----
	if err := res.persist(o.OutputDir); err != nil {
		return res, es, err
	}

	// ---- Step 10: lane-owned symbol-proof authority projection ----
	// Runs after persist so the promoted verified facts — the
	// positive-use veto VerifyDecision applies — and the persisted
	// digests exist before the decision binds to them. The lane mints
	// the authority input itself: no agent proposal and no decision
	// artifact are involved, and the route can never yield NOT_AFFECTED.
	if symbolProof != nil {
		res.SymbolProof = decideLaneSymbolProof(ctx, res, symbolProof)
	}
	// The config attempt already projected its decision from the verified
	// claim and recorded its observation before persistence; nothing here
	// depends on the promoted facts (absence is decided from the source
	// index at collection time).
	if configProof != nil {
		res.ConfigProof = configProof
	}
	return res, es, nil
}

// laneSymbolProofCalls dispatches the lane-owned bounded
// symbol-unreachability check through the strict session — one call per
// advisory-declared module carrying that module's exact declared
// symbol subjects. The attempt runs only when the applicability chain
// established module-present=TRUE and version-affected=TRUE with no
// axis resolved FALSE: an axis at FALSE means the affected code is
// absent and the case already belongs to the deterministic
// applicability chain, so a bounded proof would be unproductive work —
// and an UNKNOWN package/build axis is exactly what the closed proof
// can resolve. Every call is recorded in the lane audit like the other
// lane checks; the returned structure keeps the requests, observations
// and drained audit records the authority route binds to. nil when no
// exact symbol subjects exist or the attempt does not apply.
func laneSymbolProofCalls(res *LaneResult, call func(string, map[string]any) *evidencetools.Observation) *LaneSymbolProof {
	af := res.Affected
	if af.ModulePresent != domain.ClaimTrue || af.VersionAffected != domain.ClaimTrue ||
		af.PackagePresent == domain.ClaimFalse || af.BuildRelevant == domain.ClaimFalse ||
		af.VulnerableImplementationPresent == domain.ClaimFalse {
		return nil
	}
	type modSubjects struct {
		module   string
		subjects []domain.SymbolRef
	}
	byModule := map[string]*modSubjects{}
	var order []string
	seen := map[string]bool{}
	subs := declaredSubjects(res)
	for _, sub := range subs {
		if sub.Symbol == "" || sub.Package == "" {
			// A package/module-level declared subject can never be covered
			// by a symbol proof — the authority gate requires exact symbol
			// coverage, so a hybrid advisory skips the attempt and stays
			// INCONCLUSIVE on the generic path.
			return nil
		}
	}
	for _, sub := range subs {
		key := sub.Module + "|" + sub.Package + "." + sub.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		ms, ok := byModule[sub.Module]
		if !ok {
			ms = &modSubjects{module: sub.Module}
			byModule[sub.Module] = ms
			order = append(order, sub.Module)
		}
		ms.subjects = append(ms.subjects, domain.SymbolRef{Package: sub.Package, Symbol: sub.Symbol})
	}
	if len(order) == 0 {
		return nil
	}
	sort.Strings(order)
	trace := &VerificationTrace{Complete: true}
	var audit []evidencetools.AuditRecord
	for i, module := range order {
		args := map[string]any{"module": module, "subjects": byModule[module].subjects}
		raw, _ := json.Marshal(args)
		recStart := len(res.Records)
		obs := call(evidencetools.SymbolUnreachabilityTool, args)
		trace.Requests = append(trace.Requests, VerificationRequest{
			ID:          fmt.Sprintf("lane-symbol-%02d", i+1),
			Tool:        evidencetools.SymbolUnreachabilityTool,
			Arguments:   raw,
			Purpose:     "bounded deterministic unreachability proof for the advisory-declared symbols of " + module,
			ConditionID: "declared-symbol-unreachable",
		})
		trace.Observations = append(trace.Observations, obs)
		audit = append(audit, res.Records[recStart:]...)
		switch {
		case obs == nil:
			trace.Complete = false
			trace.Limitations = append(trace.Limitations,
				fmt.Sprintf("symbol-unreachability check for module %s produced no observation", module))
		case obs.ToolStatus != evidencetools.StatusOK:
			reason := obs.Error
			if reason == "" {
				reason = obs.Fact
			}
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"symbol-unreachability check for module %s returned %s: %s", module, obs.ToolStatus, reason))
		case obs.Completeness != evidencetools.CompletenessComplete:
			trace.Complete = false
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"symbol-unreachability check for module %s is %s: coverage is not closed and cannot ground a negative",
				module, obs.Completeness))
		}
	}
	return &LaneSymbolProof{Trace: trace, Audit: audit}
}

// postReachHops matches the verifier's own provenance depth
// (goanalysis verifyHops) so the closure and flows the lane records are
// reproducible at verification depth: a shallower collection would leave
// origins unresolved that the verifier later resolves differently. The
// bound is explicit in the observation's scope.
const postReachHops = 16

// lanePostReachConfig runs the lane's bounded post-reach configuration
// attempt (G1) over the same source-index primitives the classic
// collector uses. It builds the advisory-bound sink set, enumerates the
// sink closure, persists the exact trigger-argument flow at every live
// site, evaluates the post-reach contract
// (internal/evaluator/postreach.go) and re-derives the FALSE through
// goanalysis.Verifier — no agent proposal, no decision artifact.
//
// The attempt applies only when every applicability axis is TRUE with a
// resolved version, the advisory declares exact symbol subjects, an
// admitted product-scope config-trust assumption exists, and the subjects
// agree on one nonnegative trigger argument. Package/module-only
// subjects, unresolved non-absent advisory sinks, argument disagreement,
// missing/inadmissible assumptions and a non-closing closure all leave
// the proof nil (the case keeps its generic INCONCLUSIVE path). The
// route never yields NOT_AFFECTED.
func lanePostReachConfig(ctx context.Context, res *LaneResult, sess *evidencetools.Session,
	record func(*evidencetools.Observation, string, any)) *LaneConfigProof {

	if res == nil || res.Advisory.Vuln == nil || sess == nil || sess.Source == nil {
		return nil
	}
	af := res.Affected
	if af.ModulePresent != domain.ClaimTrue || af.VersionAffected != domain.ClaimTrue ||
		af.PackagePresent != domain.ClaimTrue || af.BuildRelevant != domain.ClaimTrue ||
		af.VulnerableImplementationPresent == domain.ClaimFalse || af.ResolvedVersion == "" {
		return nil
	}
	// The administrator-trust assertion is a declared policy input. No
	// tag, evidence kind, host default or --trusted-peer flag substitutes
	// for it: without an admissible member the route does not apply.
	if _, err := domain.AdmitAssumption(res.Assumptions, domain.AssumptionConfigTrust,
		domain.AssumptionScopeProduct, time.Now()); err != nil {
		return nil
	}
	// The post-reach contract is a Go sink-closure statement: non-Go
	// advisory entries are outside it and must not be relabeled absent.
	goModules := map[string]bool{}
	for _, im := range res.Advisory.Impls {
		if im.Binding != BindNonGo && im.Module != "" {
			goModules[im.Module] = true
		}
	}
	var subs []declaredSubject
	for _, s := range declaredSubjects(res) {
		// A package/module-level declared subject has no exact sink
		// argument to trace; the symbol route owns that shape.
		if s.Symbol == "" || s.Package == "" {
			return nil
		}
		if !goModules[s.Module] {
			continue
		}
		subs = append(subs, s)
	}

	// A symbol-less advisory has no advisory-declared sink to trace. The
	// binding route substitutes only a COMPLETE exploit-locus binding:
	// its verified product-facing sink set and exact trigger index then
	// define the G1 condition. Anything less leaves the case
	// INCONCLUSIVE — the route never guesses a sink and never returns
	// NOT_AFFECTED.
	var binding *domain.ExploitLocusBinding
	bindingRoute := false
	if len(subs) == 0 {
		if !canBindExploitLocus(res.ExploitBinding) {
			return nil
		}
		binding = res.ExploitBinding.Binding
		bindingRoute = true
	}
	if len(subs) == 0 && !bindingRoute {
		return nil
	}

	var resolved, absent []domain.SymbolRef
	seen := map[string]bool{}
	argIndex := -1
	if bindingRoute {
		for _, s := range binding.Sinks {
			resolved = append(resolved, domain.SymbolRef{Package: s.Package, Symbol: s.Symbol})
		}
		argIndex = binding.TriggerArgIndex
	}
	for _, sub := range subs {
		key := sub.Package + "." + sub.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		ref := domain.SymbolRef{Package: sub.Package, Symbol: sub.Symbol}
		if _, err := sess.Source.FindSymbol(ctx, ref); err != nil {
			if errors.Is(err, goanalysis.ErrSymbolNotFoundInPackage) {
				// The advisory names a symbol the linked version does not
				// declare: provably absent, so the sink set stays complete.
				absent = append(absent, ref)
				continue
			}
			// An unresolved symbol that is not proven absent could be a
			// live sink outside the closure — no completeness contract.
			return nil
		}
		idx, _, err := sess.Source.InputParamIndex(ref)
		if err != nil || idx < 0 {
			return nil
		}
		if argIndex < 0 {
			argIndex = idx
		} else if argIndex != idx {
			// One condition binds one exact argument; a subject set that
			// disagrees has no single trigger position to prove.
			return nil
		}
		resolved = append(resolved, ref)
	}
	if len(resolved) == 0 {
		return nil
	}

	// The verification case and the evaluator below are mutable proof
	// processing: both receive copies whose scope is deep-copied so no
	// mutation can reach the lane's census.
	vuln := *res.Advisory.Vuln
	vuln.Scope = res.Advisory.Vuln.Scope.Clone()
	afCopy := scopeClone(res.Affected)
	c := &domain.AnalysisCase{
		Product:             sess.Build,
		Vulnerability:       vuln,
		Affected:            &afCopy,
		DeclaredAssumptions: res.Assumptions,
	}
	cond := domain.Condition{
		ID:          "C-INPUT",
		Kind:        domain.ConditionAttackerControl,
		Mandatory:   true,
		ArgIndex:    argIndex,
		Subjects:    resolved,
		Description: "the trigger argument of the advisory-declared sink is attacker-influenced",
	}
	if bindingRoute {
		// The condition subjects are exactly the verified product-facing
		// sinks; the vulnerable implementation symbol stays in the
		// binding record and is never fabricated into the advisory's
		// symbol set.
		cond = bindingCondition(binding)
		cond.ID = "C-INPUT"
		if res.ExploitBinding != nil {
			c := cond
			res.ExploitBinding.Condition = &c
		}
	}
	c.Exploit = &domain.ExploitModel{
		Impact:              vuln.Summary,
		RootCauses:          resolved,
		UnresolvedSubjects:  absent,
		AbsentSubjects:      absent,
		MandatoryConditions: []domain.Condition{cond},
	}
	var basis string
	var ok bool
	var proof *domain.ContentAdmission
	if c != nil {
		proof = fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), c.RootCause)
	}
	if bindingRoute {
		// The binding-aware basis re-checks the symbol-less entry, the
		// exact subject set, the negative handling and the trigger
		// index; advisory membership or a proposal alone never yields a
		// completeness contract.
		basis, ok = goanalysis.ExploitLocusBindingBasis(c, resolved, binding, argIndex, proof)
	} else {
		basis, ok = goanalysis.SinkSetBasis(c, resolved, proof)
	}
	if !ok {
		// Advisory membership alone is never a completeness contract: a
		// missing sink, an out-of-module subject or an unresolved
		// non-absent candidate keeps the closure KNOWN_ONLY.
		return nil
	}
	cl, evs, err := sess.Source.SinkClosure(ctx, cond.ID, vuln.Module, basis, resolved, argIndex, postReachHops)
	if err != nil {
		return nil
	}
	// The binding route additionally re-checks that the closure's live
	// sites are exactly the verified binding sinks at the exact trigger
	// index: a diverging site means the condition would cover something
	// the binding never proved.
	routeBlocker := ""
	if bindingRoute {
		if merr := exploitBindingMatchesSites(binding, cl.Sites); merr != nil {
			routeBlocker = merr.Error()
		}
	}
	c.EvidenceGraph.AddSinkClosure(cl)
	for _, e := range evs {
		c.EvidenceGraph.AddEvidence(e)
	}
	for _, site := range cl.Sites {
		if !site.Live || site.Arg != argIndex {
			continue
		}
		flow, fevs, ferr := sess.Source.TraceArgumentBound(ctx, site.CallSite, argIndex, postReachHops)
		if ferr != nil {
			// The missing flow blocks the claim in the evaluator; the
			// attempt continues so the recorded blocker names it.
			continue
		}
		flow.ConditionID = cond.ID
		c.EvidenceGraph.AddArgumentTrace([]domain.DataFlow{flow}, fevs)
	}

	claim := (evaluator.ArgumentOrigin{}).Evaluate(cond, c)
	verified := claim
	if claim.Result == domain.ClaimFalse {
		verified = (goanalysis.Verifier{Source: sess.Source}).VerifyFalse(ctx, c, claim, cond)
	}
	vr := (evaluator.VerdictEvaluator{}).Evaluate(evaluator.VerdictInput{
		Product:  sess.Build,
		Affected: afCopy,
		Model:    *c.Exploit,
		Claims:   []domain.Claim{verified},
		Evidence: c.EvidenceGraph.EvidenceList(),
	})

	terminal := routeBlocker == "" && vr.Verdict == domain.VerdictNoExploitPathFound &&
		verified.Result == domain.ClaimFalse &&
		verified.Falsifier == domain.FalsifierTrustedInfrastructure &&
		verified.FalsifierBasis == domain.BasisConfigOrigin &&
		verified.NegativeVerification != nil &&
		verified.NegativeVerification.Status == domain.NegativeVerified &&
		len(verified.AssumptionIDs) > 0
	live := 0
	for _, site := range cl.Sites {
		if site.Live && site.Arg == argIndex {
			live++
		}
	}

	blocker := ""
	if !terminal {
		if routeBlocker != "" {
			blocker = routeBlocker
		} else if nv := verified.NegativeVerification; nv != nil && nv.Status != domain.NegativeVerified && nv.Notes != "" {
			blocker = nv.Notes
		} else if len(verified.Limitations) > 0 {
			blocker = verified.Limitations[len(verified.Limitations)-1]
		} else if vr.Reason != "" {
			blocker = vr.Reason
		} else {
			blocker = "the exact post-reach contract did not close"
		}
	}
	route := "the advisory-declared sink set"
	if bindingRoute {
		route = fmt.Sprintf("the verified exploit-locus sink set (binding %s, vulnerable %s.%s)",
			binding.ProposalID, binding.VulnerablePackage, binding.VulnerableSymbol)
	}
	var fact, scope string
	comp := evidencetools.CompletenessPartial
	var lims []string
	if terminal {
		comp = evidencetools.CompletenessComplete
		// The proof inputs are retained verbatim so the record case
		// re-admits through the one verdict authority instead of
		// re-deriving the closure from prose. They remain this record's
		// own model, claims and evidence.
		res.RecordModel = c.Exploit
		res.RecordClaims = []domain.Claim{verified}
		res.RecordEvidence = append(res.RecordEvidence, c.EvidenceGraph.EvidenceList()...)
		fact = fmt.Sprintf(
			"exact post-reach configuration closure verified: %d live sink site(s) of %s at trigger arg %d trace to administrator-managed configuration; NO_EXPLOIT_PATH_FOUND under declared config-trust assumption %s",
			live, route, argIndex, strings.Join(verified.AssumptionIDs, ", "))
		scope = fmt.Sprintf("goanalysis sink closure over module %s (product + reachable dependency cone, %d hops) with exact argument %d provenance, re-derived by goanalysis.Verifier",
			vuln.Module, postReachHops, argIndex)
	} else {
		fact = "post-reach configuration route did not close: " + singleLine(blocker) + "; the case remains INCONCLUSIVE"
		scope = fmt.Sprintf("bounded post-reach attempt over %s at trigger arg %d (attempted, not closed)", route, argIndex)
		lims = []string{singleLine(blocker)}
	}
	args := map[string]any{
		"condition_id": string(cond.ID),
		"module":       vuln.Module,
		"subjects":     resolved,
		"arg_index":    argIndex,
	}
	data := map[string]any{
		"condition_id":    string(cond.ID),
		"arg_index":       argIndex,
		"claim_result":    string(verified.Result),
		"falsifier":       verified.Falsifier,
		"falsifier_basis": verified.FalsifierBasis,
		"assumption_ids":  verified.AssumptionIDs,
		"verdict":         string(vr.Verdict),
		"coverage":        "INSUFFICIENT_SCOPE",
		"live_sites":      live,
		"sink_basis":      cl.Basis,
	}
	coverage := "INSUFFICIENT_SCOPE"
	if terminal {
		data["coverage"] = "COMPLETE"
		coverage = "COMPLETE"
	}
	o := &evidencetools.Observation{
		Tool:         postReachConfigTool,
		Fact:         fact,
		Scope:        scope,
		Completeness: comp,
		ToolStatus:   evidencetools.StatusOK,
		ScopeDetails: &evidencetools.ScopeDetails{
			SnapshotHash: sess.SnapshotHash,
			SnapshotRoot: sess.SnapshotRoot,
			ExternalSHA:  sess.ExternalSHA,
			Subject:      string(cond.ID),
			CoverageRule: "closed post-reach contract: applicability TRUE → advisory-bound sink set complete → every live site at the exact trigger argument → bounded provenance → verifier re-derivation",
		},
		Limitations: lims,
		Data:        data,
	}
	finishLaneObservation(o)
	record(o, postReachConfigTool, args)
	if !terminal {
		return nil
	}

	raw, _ := json.Marshal(args)
	successNote := ""
	for _, lim := range verified.Limitations {
		if strings.HasPrefix(lim, "exact sink closure verified") {
			successNote = lim
			break
		}
	}
	// The verifier's EvidenceIDs are case-local evidence-graph ids from
	// the ephemeral analysis case; the persisted lane observation is the
	// decision's evidence ref, so the report never cites an id that
	// resolves only inside this process.
	nv := &domain.NegativeVerification{Status: verified.NegativeVerification.Status}
	if verified.NegativeVerification.BuildContext != nil {
		// Bind the measurement identity the verifier actually observed —
		// never a freshly derived current context.
		bound := *verified.NegativeVerification.BuildContext
		nv.BuildContext = &bound
	}
	if note := verified.NegativeVerification.Notes; note != "" {
		nv.Notes = note
	}
	if lims := verified.NegativeVerification.Limitations; len(lims) > 0 {
		nv.Limitations = append([]string(nil), lims...)
	}
	decision := EvidenceDecision{
		Verdict: vr.Verdict,
		Reason: fmt.Sprintf("the exact trigger argument %d of every live sink site of %s resolves to administrator-managed configuration under declared assumption %s; sink closure complete (%s)",
			argIndex, route, strings.Join(verified.AssumptionIDs, ", "), cl.Basis),
		ConditionID:          string(cond.ID),
		Falsifier:            domain.FalsifierTrustedInfrastructure,
		NegativeVerification: nv,
		EvidenceRefs:         []string{"obs:" + o.ID},
		Scope:                "bounded post-reach configuration closure over " + route,
		Coverage:             coverage,
		Sufficiency:          successNote,
		AssumptionIDs:        append([]string(nil), verified.AssumptionIDs...),
		GroundBasis:          domain.BasisConfigOrigin,
		TicketRationale: fmt.Sprintf(
			"the vulnerable sink is positively reached and every live site's trigger argument resolves to administrator-managed configuration; the verdict rests on the declared config-trust policy assumption %s, not on code-level unreachability",
			strings.Join(verified.AssumptionIDs, ", ")),
	}
	if bindingRoute && res.ExploitBinding != nil {
		res.ExploitBinding.AssumptionIDs = append([]string(nil), verified.AssumptionIDs...)
		res.ExploitBinding.PostReachObservationID = o.ID
	}
	return &LaneConfigProof{
		ObservationID: o.ID,
		Trace: &VerificationTrace{
			Complete: true,
			Requests: []VerificationRequest{{
				ID:          "lane-post-reach-config",
				Tool:        postReachConfigTool,
				Arguments:   raw,
				Purpose:     "bounded exact-argument post-reach configuration closure for the advisory-declared sink set",
				ConditionID: string(cond.ID),
			}},
			Observations: []*evidencetools.Observation{o},
		},
		Decision: decision,
	}
}

// laneImplementationAxis runs the lane's own implementation-presence
// check (G2): the typed proposal channel supplies LLM-inferred locus
// hypotheses, each is re-admitted against this lane's frozen advisory,
// and the deterministic verifier decides vulnerable_implementation_
// present under the recorded build target and the declared
// supported-targets scope. The finalized affected chain is folded
// back into res.Affected (a FALSE there is an ordinary applicability
// axis FALSE — the standard NOT_AFFECTED route, never a code-level
// falsifier). The attempt always leaves exactly one recorded
// observation carrying the intake result, every per-proposal
// verification, the finalized chain and the pinned evidence, so the
// earlier affected-resolve record stays the resolver chain's pristine
// statement. A proposal channel that failed closed admits nothing:
// the observation records the typed outcome and the axis stays
// undecidable. Never yields NO_EXPLOIT_PATH_FOUND and never consumes
// an unadmitted proposal.
func laneImplementationAxis(ctx context.Context, res *LaneResult, sess *evidencetools.Session,
	product domain.ProductSnapshot,
	mintObs func(tool, fact, scope string, comp evidencetools.Completeness,
		data any, sd *evidencetools.ScopeDetails, lims []string) *evidencetools.Observation,
	record func(*evidencetools.Observation, string, any)) {
	in := res.ImplementationProposals
	if in == nil || res.Advisory.Vuln == nil || sess == nil {
		return // no proposal channel: the axis was never attempted
	}
	data := map[string]any{
		"source":          in.Source,
		"path":            in.Path,
		"advisory_sha256": in.AdvisorySHA256,
	}
	if in.RetainedAnswerSHA256 != "" {
		data["retained_answer_sha256"] = in.RetainedAnswerSHA256
	}
	var lims []string
	comp := evidencetools.CompletenessComplete

	var proposals []domain.ImplementationLocusProposal
	var rejected []string
	if in.LoadError != "" {
		// A failed channel admits nothing: the typed intake outcome is
		// the record; the axis is undecidable, never implicitly absent.
		data["load_error"] = in.LoadError
		lims = append(lims, "implementation-locus proposal channel failed closed ("+in.LoadError+"): the implementation axis is undecidable")
		comp = evidencetools.CompletenessPartial
	} else {
		// Dispatch-point admission: the same gate the agent path
		// applies — typed shape, LLM-inferred quality, the advisory
		// reference resolvable to this frozen document and a verbatim
		// recorded quote. A rejected member is named in the record,
		// never silently dropped.
		seen := map[string]bool{}
		for _, p := range in.Proposals {
			switch {
			case seen[p.ID]:
				rejected = append(rejected, fmt.Sprintf("%s: duplicate proposal id", p.ID))
			default:
				seen[p.ID] = true
				if err := AdmitImplementationLocusProposal(p, &res.Advisory); err != nil {
					rejected = append(rejected, fmt.Sprintf("%s: %v", p.ID, err))
					continue
				}
				proposals = append(proposals, p)
			}
		}
		data["proposed"] = len(in.Proposals)
		data["admitted"] = len(proposals)
		if len(rejected) > 0 {
			data["rejected"] = rejected
			for _, rj := range rejected {
				lims = append(lims, "implementation-locus proposal rejected at admission: "+rj)
			}
		}

		axis := affected.EvaluateImplementationAxis(ctx, affected.ImplementationAxisInput{
			Proposals:               proposals,
			Entries:                 affected.AffectedModuleEntries(*res.Advisory.Vuln),
			Affected:                scopeClone(res.Affected),
			Build:                   product,
			SnapshotRoot:            sess.SnapshotRoot,
			SnapshotContentHash:     sess.SnapshotHash,
			AdvisoryID:              res.Advisory.Input.ResolvedID,
			AdvisorySHA256:          res.Advisory.Input.RawSHA256,
			AdvisoryCanonicalSHA256: res.Advisory.Input.CanonicalSHA256,
			AdvisoryBytes:           res.Advisory.RawBytes,
			Assumptions:             res.Assumptions,
			Tool: affected.ExecGoTool{
				Bin: sess.ToolBin, Env: sess.ToolEnv, Version: sess.ToolVer,
			},
		})
		// The axis mutates the chain in place: the finalized result —
		// vulnerable_implementation_present, the established
		// package/build facts, target provenance, assumption ids and
		// limitations — replaces the resolver's earlier value, and the
		// verifier's evidence joins the lane's evidence set with its
		// ids folded into the chain's evidence ids.
		res.Affected = axis.Affected
		for _, ev := range axis.Evidence {
			res.AffectedEvidence = append(res.AffectedEvidence, ev)
			res.Affected.EvidenceIDs = append(res.Affected.EvidenceIDs, ev.ID)
		}
		data["affected_result"] = axis.Affected
		data["axis"] = map[string]any{
			"present":        axis.Present,
			"reason":         axis.Reason,
			"target_scope":   axis.TargetScope,
			"assumption_ids": axis.AssumptionIDs,
			"modules":        axis.Modules,
			"locus":          axis.Locus,
			"limitations":    axis.Limitations,
			"verifications":  axis.Verifications,
		}
		if axis.Target != nil {
			data["target"] = axis.Target
		}
		evidenceView := laneEvidenceView(axis.Evidence)
		data["evidence"] = evidenceView
		if note := laneEvidenceBoundNote(evidenceView); note != "" {
			lims = append(lims, note)
		}
		lims = append(lims, axis.Limitations...)
		res.ImplementationAxis = &LaneImplementationAxis{
			AssumptionIDs: append([]string(nil), axis.AssumptionIDs...),
		}
		for _, ev := range axis.Evidence {
			res.ImplementationAxis.EvidenceIDs = append(
				res.ImplementationAxis.EvidenceIDs, string(ev.ID))
		}
		if axis.Present != domain.ClaimFalse {
			comp = evidencetools.CompletenessPartial
		}
	}

	fact := fmt.Sprintf("implementation-presence axis for %s: vulnerable_implementation_present=%s (%d admitted proposal(s))",
		res.Advisory.Input.ResolvedID, res.Affected.VulnerableImplementationPresent, len(proposals))
	sd := &evidencetools.ScopeDetails{
		SnapshotHash: sess.SnapshotHash, SnapshotRoot: sess.SnapshotRoot,
		ExternalSHA: sess.ExternalSHA, Subject: res.Advisory.Input.ResolvedID,
		CoverageRule: "closed per-proposal verification: advisory-bound proposal set re-checked deterministically against the snapshot module source inventory under the recorded build target",
	}
	for k, v := range evidencetools.ReleaseProvenanceExtra(product) {
		if sd.Extra == nil {
			sd.Extra = map[string]string{}
		}
		sd.Extra[k] = v
	}
	o := mintObs(implementationAxisTool, fact,
		"affected.EvaluateImplementationAxis + VerifyImplementationLocus over the admitted implementation-locus proposals (module source inventory, AST function/marker, build-context selection, bounded alternate scan, go list -deps package probe under strict toolchain env)",
		comp, data, sd, lims)
	// Digest-bearing refs make the observation promotable: the frozen
	// advisory pin plus every verified file hash the axis produced.
	if res.Advisory.Input.RawSHA256 != "" {
		o.EvidenceRefs = append(o.EvidenceRefs, "sha256:"+res.Advisory.Input.RawSHA256)
	}
	if axData, ok := data["axis"].(map[string]any); ok {
		if vs, ok2 := axData["verifications"].([]affected.ImplementationVerification); ok2 {
			for _, v := range vs {
				if v.FileSHA256 != "" {
					o.EvidenceRefs = append(o.EvidenceRefs, "sha256:"+v.FileSHA256)
				}
			}
		}
	}
	record(o, implementationAxisTool, map[string]any{
		"vuln": res.Advisory.Input.ResolvedID, "proposals": len(in.Proposals),
	})
	if res.ImplementationAxis == nil {
		res.ImplementationAxis = &LaneImplementationAxis{}
	}
	res.ImplementationAxis.ObservationID = o.ID
}

// decideLaneSymbolProof projects the lane's own symbol-unreachability
// attempt through the VerifyDecision authority route — the same
// authority the decision-ready projection consults — so the lane itself
// yields a code-owned decision without an agent proposal or a decision
// artifact. A complete audit-bound proof over every advisory-declared
// symbol yields NO_EXPLOIT_PATH_FOUND; anything less stays INCONCLUSIVE
// and gains the primitive's named limitations so the report identifies
// the concrete blocker (a reachable site, an open gap, a tool failure)
// instead of a generic unknown. The applicability early-exit cannot
// fire here — the attempt only runs with every axis non-FALSE — so the
// route never produces NOT_AFFECTED.
func decideLaneSymbolProof(ctx context.Context, res *LaneResult, proof *LaneSymbolProof) *LaneSymbolProof {
	var subjects []FactUsageSubject
	seen := map[string]bool{}
	for _, sub := range declaredSubjects(res) {
		if sub.Symbol == "" || sub.Package == "" {
			continue
		}
		key := sub.Module + "|" + sub.Package + "." + sub.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		subjects = append(subjects, FactUsageSubject{Module: sub.Module, Package: sub.Package, Symbol: sub.Symbol})
	}
	// Rehydrate the authoritative payloads persistence externalized:
	// the authority route consumes the complete hash-bound typed
	// result, never the bounded wire envelope. Audit-record copies
	// rehydrate in place (they own the authoritative decode); trace
	// observations rehydrate into clones so the digest-pinned wire
	// copy the persistence layer recorded stays byte-identical for
	// discharge and fact binding. A missing, altered, undecodable or
	// digest-mismatched sidecar is a named trace limitation — the
	// closed-trace gate then holds the decision at INCONCLUSIVE.
	auditByID := map[string]*evidencetools.AuditRecord{}
	for i := range proof.Audit {
		rec := &proof.Audit[i]
		if rec.Observation != nil && rec.Observation.ID != "" {
			auditByID[rec.Observation.ID] = rec
		}
	}
	fail := func(format string, args ...any) {
		proof.Trace.Complete = false
		proof.Trace.Limitations = append(proof.Trace.Limitations,
			fmt.Sprintf(format, args...))
	}
	for id, rec := range auditByID {
		if err := res.rehydrateObservationPayload(rec.Observation); err != nil {
			fail("authoritative payload for %s cannot be rehydrated: %v", id, err)
		}
	}
	for i, o := range proof.Trace.Observations {
		if o == nil {
			continue
		}
		var src *evidencetools.Observation
		if rec := auditByID[o.ID]; rec != nil {
			src = rec.Observation
		} else {
			src = o
		}
		if src == o && o.PayloadRef == nil {
			continue
		}
		if err := res.rehydrateObservationPayload(src); err != nil {
			fail("authoritative payload for %s cannot be rehydrated: %v", o.ID, err)
			continue
		}
		if o.PayloadRef != nil {
			cp := *o
			cp.Data = src.Data
			cp.PayloadRef = nil
			proof.Trace.Observations[i] = &cp
		}
	}

	proof.Decision, _ = VerifyDecision(ctx, DecisionInput{
		Lane:  res,
		Trace: proof.Trace,
		Authority: &VerifiedFalsifierInput{
			Kind:        domain.FalsifierDeclaredSymbolUnreached,
			ConditionID: "declared-symbol-unreachable",
			RuleID:      "rule.declared-symbols-unreached",
			Subjects:    subjects,
		},
		Audit:            proof.Audit,
		ObservationIndex: VerificationObservationIndex(proof.Trace, proof.Audit),
	})
	if proof.Decision.Verdict == domain.VerdictInconclusive {
		proof.Decision.Limitations = laneSymbolLimitations(proof, proof.Decision.Limitations)
	}
	return proof
}

// laneSymbolLimitations lifts the primitive's recorded blockers into the
// decision's limitations: the decision's own named reason first (the
// conclusion the authority route re-derived from the observation
// payload), then the named reason a tool call failed (error or timeout
// is evidence of nothing) and every payload limitation the bounded
// proof recorded — including the positive-reach and open-gap lines
// naming the observed use. Payloads come from the session audit copies,
// the same bytes the authority binds. Output is deduplicated and capped
// so the projection stays bounded.
func laneSymbolLimitations(proof *LaneSymbolProof, lims []string) []string {
	have := map[string]bool{}
	for _, l := range lims {
		have[l] = true
	}
	add := func(l string) {
		if l != "" && !have[l] && len(proof.Decision.Limitations) < 32 {
			have[l] = true
			proof.Decision.Limitations = append(proof.Decision.Limitations, l)
		}
	}
	// The decision's named conclusion is itself a limitation entry: the
	// report's decision block lists residual limitations, and a reader
	// who opens only that block still sees the primitive's own statement.
	add(proof.Decision.Reason)
	if proof.Trace != nil {
		for _, l := range proof.Trace.Limitations {
			add(l)
		}
	}
	for _, rec := range proof.Audit {
		o := rec.Observation
		if o == nil || rec.Tool != evidencetools.SymbolUnreachabilityTool {
			continue
		}
		if o.ToolStatus != evidencetools.StatusOK {
			add(o.Error)
			add(o.Fact)
			for _, l := range o.Limitations {
				add(l)
			}
			continue
		}
		var d evidencetools.SymbolUnreachabilityData
		if !decodeData(o.Data, &d) {
			for _, l := range o.Limitations {
				add(l)
			}
			continue
		}
		if !d.Result.Complete {
			add(o.Fact)
		}
		if d.Result.Complete {
			if err := d.Result.ValidateComplete(d.Result.Build); err != nil { add(err.Error()) }
		}
		for _, l := range d.Result.Limitations {
			add(l)
		}
	}
	return proof.Decision.Limitations
}

// releaseEvidenceData renders the release-evidence record embedded in
// the affected-resolve observation payload: status/reason, the selected
// authoritative toolchain, the classified evidence items, artifact
// provenance digests, and which module graph grounded module-version
// applicability. nil when the snapshot carries no release evidence and
// none was required — legacy payloads stay byte-identical. Credentials
// and artifact URLs are never part of the summary, so nothing here can
// carry them.
func releaseEvidenceData(product domain.ProductSnapshot) map[string]any {
	re := product.ReleaseEvidence
	if re == nil && !product.ReleaseEvidenceRequired && len(product.ReleaseModules) == 0 {
		return nil
	}
	relMods, relAuth, relStatus := affected.ReleaseModulesFor(product)
	status, reason := relStatus, ""
	if i := strings.IndexByte(relStatus, '/'); i >= 0 {
		status, reason = relStatus[:i], relStatus[i+1:]
	}
	m := map[string]any{"status": status}
	if reason != "" {
		m["reason_code"] = reason
	}
	if re != nil {
		if re.SelectedVersion != "" {
			m["selected_version"] = re.SelectedVersion
			m["selected_source"] = string(re.SelectedSource)
		}
		if re.Items != nil {
			m["items"] = re.Items
		}
		if re.ArtifactSHA256 != "" {
			m["artifact_sha256"] = re.ArtifactSHA256
		}
		if re.BinaryMember != "" {
			m["binary_member"] = re.BinaryMember
		}
		if re.BuildInfoSHA256 != "" {
			m["build_info_sha256"] = re.BuildInfoSHA256
		}
	}
	switch {
	case relAuth:
		m["version_graph"] = "release_module_graph"
		m["version_graph_trust"] = string(domain.ReleaseTrustAuthoritative)
		m["version_graph_modules"] = len(relMods)
	case affected.ReleaseVersionAxisBlocked(product):
		m["version_graph"] = "unavailable"
	default:
		m["version_graph"] = "source_module_graph"
	}
	return m
}

// LaneReleaseEvidence projects the lane snapshot's release evidence into
// the /3 report block. It returns nil — keeping the member absent — when
// no release-evidence channel ran and none produced facts, so legacy
// reports stay byte-identical. Version-graph provenance names the graph
// the resolver actually used, mirrored from the affected-resolve axis:
// the release module graph (artifact build info or operator metadata),
// "unavailable" when a requested channel blocked the axis, or the
// source-snapshot fallback.
func LaneReleaseEvidence(lane *LaneResult) *ReleaseEvidenceReport {
	if lane == nil {
		return nil
	}
	snap := lane.Snapshot
	re := snap.ReleaseEvidence
	if re == nil && !snap.ReleaseEvidenceRequired && len(snap.ReleaseModules) == 0 {
		return nil
	}
	relMods, relAuth, relStatus := affected.ReleaseModulesFor(snap)
	rep := &ReleaseEvidenceReport{
		Status:  string(domain.ReleaseStatusNotRequested),
		Modules: snap.ReleaseModules,
	}
	status, reason := relStatus, ""
	if i := strings.IndexByte(relStatus, '/'); i >= 0 {
		status, reason = relStatus[:i], relStatus[i+1:]
	}
	if re != nil {
		rep.Status = string(re.Status)
		rep.ReasonCode = re.ReasonCode
		rep.RequiredChannelFailures = append([]string{}, re.RequiredChannelFailures...)
		rep.SelectedVersion = re.SelectedVersion
		rep.SelectedSource = string(re.SelectedSource)
		rep.SelectedTrust = string(re.SelectedTrust)
		for _, it := range re.Items {
			rep.Items = append(rep.Items, ReleaseEvidenceItemReport{
				Version:         it.Version,
				Source:          string(it.Source),
				TrustClass:      string(it.TrustClass),
				Location:        it.Location,
				ArtifactSHA256:  it.ArtifactSHA256,
				BinaryMember:    it.BinaryMember,
				BuildInfoSHA256: it.BuildInfoSHA256,
			})
		}
		rep.ArtifactSHA256 = re.ArtifactSHA256
		rep.BinaryMember = re.BinaryMember
		rep.BuildInfoSHA256 = re.BuildInfoSHA256
	} else {
		rep.Status = status
		rep.ReasonCode = reason
	}
	switch {
	case relAuth:
		rep.VersionGraphSource = "release-artifact"
		rep.VersionGraphTrust = string(domain.ReleaseTrustAuthoritative)
	case affected.ReleaseVersionAxisBlocked(snap):
		rep.VersionGraphSource = "unavailable"
	default:
		rep.VersionGraphSource = "source-snapshot"
	}
	if relAuth {
		rep.ModuleCount = len(relMods)
	}
	return rep
}

// LaneReleaseNotRun reports whether an explicitly requested release-
// evidence channel failed closed. True only when the snapshot required
// release evidence and the resolved status is NOT_RUN — absent evidence
// on a legacy snapshot is UNKNOWN, never a run failure.
func LaneReleaseNotRun(lane *LaneResult) (bool, string) {
	if lane == nil || !lane.Snapshot.ReleaseEvidenceRequired {
		return false, ""
	}
	re := lane.Snapshot.ReleaseEvidence
	if re == nil {
		return true, domain.ReleaseReasonAbsent
	}
	if len(re.RequiredChannelFailures) > 0 {
		return true, re.RequiredChannelFailures[0]
	}
	if re.Status == domain.ReleaseStatusNotRun {
		return true, re.ReasonCode
	}
	return false, ""
}

// finishLaneObservation mirrors evidencetools.finishObservation for the
// lane-minted records (same invariants: non-OK never COMPLETE; COMPLETE
// needs a coverage rule and an un-gapped scope).
func finishLaneObservation(o *evidencetools.Observation) {
	if o.ToolStatus != evidencetools.StatusOK && o.Completeness == evidencetools.CompletenessComplete {
		o.Completeness = evidencetools.CompletenessUnknown
	}
	if o.Completeness == evidencetools.CompletenessComplete {
		rule := ""
		truncated := false
		if o.ScopeDetails != nil {
			rule = o.ScopeDetails.CoverageRule
			truncated = len(o.ScopeDetails.SkippedPackages) > 0 ||
				(o.ScopeDetails.Limits != nil && (o.ScopeDetails.Limits.Truncated || o.ScopeDetails.Limits.OutputTruncated))
		}
		if rule == "" || truncated {
			o.Completeness = evidencetools.CompletenessPartial
			if rule == "" {
				o.Limitations = append(o.Limitations, "completeness downgraded: no closed-scope coverage rule recorded")
			} else {
				o.Limitations = append(o.Limitations, "completeness downgraded: skipped/truncated entries inside the claimed scope")
			}
		}
	}
	if o.ToolStatus == evidencetools.StatusError && o.Error == "" {
		o.Error = o.Fact
		if o.Error == "" {
			o.Error = "tool execution failed"
		}
	}
}

// Bounded-by-construction payload members. Every lane-minted
// observation payload must stay under maxObservationPayloadBytes for
// any real snapshot, so the last-resort capObservationPayload — which
// degrades COMPLETE to PARTIAL and would leave policy-required
// lane-carried checks undischarged — never triggers for them.
// Unbounded members are projected instead of truncated: evidence
// content becomes a digest-pinned preview, over-long member lists
// become a kept prefix plus the recorded total, and the semantic
// fields (affected_result, closure, release_evidence) that the
// discharge gate and downstream readers consume stay verbatim.
//
// laneEvidenceItemVerbatimBytes caps verbatim content embedded per
// evidence item; larger items keep a preview instead.
const laneEvidenceItemVerbatimBytes = 16 * 1024

// laneEvidenceItemPreviewBytes caps the preview stored for one
// bounded evidence item.
const laneEvidenceItemPreviewBytes = 4 * 1024

// laneEvidencePayloadTextBytes caps total content bytes (verbatim or
// preview) one payload's evidence list may embed, and
// laneEvidenceTextItems caps how many items may embed any text at
// all — so payload size does not grow with the number of evidence
// items.
const laneEvidencePayloadTextBytes = 48 * 1024
const laneEvidenceTextItems = 8

// lanePayloadMaxListItems caps the items embedded in one payload
// member list (ingress items, exposure facts, release modules); the
// projection records the full count so nothing reads a prefix as a
// closed enumeration.
const lanePayloadMaxListItems = 512

// laneEvidenceItem is the bounded payload projection of one
// domain.Evidence record. Every field marshals exactly like the
// embedded evidence except content handling: content up to
// laneEvidenceItemVerbatimBytes stays verbatim, anything larger keeps
// a rune-boundary preview instead, and items pushed past the shared
// text budget carry digests only. Every item records content_sha256
// and content_bytes so the stored bytes are pinned even when the
// verbatim text never enters the payload. content_bounded marks a
// record whose content member is not the complete text.
//
// The in-memory LaneResult.AffectedEvidence and res.Ingress keep full
// content — this projection exists only so no snapshot can push the
// stored observation payload past maxObservationPayloadBytes.
type laneEvidenceItem struct {
	domain.Evidence
	ContentPreview string `json:"content_preview,omitempty"`
	ContentSHA256  string `json:"content_sha256"`
	ContentBytes   int64  `json:"content_bytes"`
	ContentBounded bool   `json:"content_bounded,omitempty"`
}

// laneEvidenceView projects one evidence list for payload embedding
// under the budgets above. Item order and every non-content field are
// preserved; the returned slice is fresh — the caller's evidence is
// never mutated.
func laneEvidenceView(ev []domain.Evidence) []laneEvidenceItem {
	if ev == nil {
		return nil
	}
	out := make([]laneEvidenceItem, len(ev))
	textBytes, textItems := 0, 0
	for i, e := range ev {
		item := laneEvidenceItem{Evidence: e}
		sum := sha256.Sum256([]byte(e.Content))
		item.ContentSHA256 = hex.EncodeToString(sum[:])
		item.ContentBytes = int64(len(e.Content))
		switch {
		case len(e.Content) <= laneEvidenceItemVerbatimBytes &&
			textItems < laneEvidenceTextItems &&
			textBytes+len(e.Content) <= laneEvidencePayloadTextBytes &&
			utf8.ValidString(e.Content):
			// Small content inside the shared budget stays verbatim.
			textBytes += len(e.Content)
			textItems++
		case textItems < laneEvidenceTextItems:
			// A rune-boundary preview stands in for the full content;
			// when the shared budget is already exhausted the preview
			// is empty and the item carries its digests only.
			item.ContentBounded = true
			item.ContentPreview = utf8Prefix(e.Content,
				min(laneEvidenceItemPreviewBytes, laneEvidencePayloadTextBytes-textBytes))
			textBytes += len(item.ContentPreview)
			item.Content = ""
			textItems++
		default:
			// Past the per-payload item budget: metadata + digests.
			item.ContentBounded = true
			item.Content = ""
		}
		out[i] = item
	}
	return out
}

// utf8Prefix returns the longest prefix of s that is valid UTF-8 and
// at most max bytes — the stored preview is always valid JSON text.
func utf8Prefix(s string, max int) string {
	if max <= 0 {
		return ""
	}
	cut := min(len(s), max)
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut]
}

// laneListPrefix bounds a payload member list to its kept prefix and
// reports how many items were dropped, so a consumer can never read a
// prefix as the closed set.
func laneListPrefix[T any](items []T, max int) ([]T, int) {
	if len(items) <= max {
		return items, 0
	}
	return items[:max], len(items) - max
}

// laneSnapshotView is the repository-snapshot payload: the product
// snapshot verbatim except its release module graph, which is
// prefix-bounded — the count of the full graph travels in
// release_modules_total.
type laneSnapshotView struct {
	domain.ProductSnapshot
	ReleaseModulesTotal int `json:"release_modules_total,omitempty"`
}

func laneSnapshotViewOf(snap domain.ProductSnapshot) laneSnapshotView {
	v := laneSnapshotView{ProductSnapshot: snap}
	if snap.ReleaseModules != nil {
		v.ReleaseModulesTotal = len(snap.ReleaseModules)
		v.ReleaseModules, _ = laneListPrefix(snap.ReleaseModules, lanePayloadMaxListItems)
	}
	return v
}

// laneClosureView is the ingress-inventory payload's closure member:
// the closure verbatim except its item list, which is prefix-bounded
// — items_total records the full inventory size so the kept prefix is
// never read as complete coverage.
type laneClosureView struct {
	domain.IngressClosure
	ItemsTotal int `json:"items_total"`
}

func laneClosureViewOf(cl domain.IngressClosure) laneClosureView {
	v := laneClosureView{IngressClosure: cl, ItemsTotal: len(cl.Items)}
	v.Items, _ = laneListPrefix(cl.Items, lanePayloadMaxListItems)
	return v
}

// laneExposureFactsData bounds the facts member of the exposure-scan
// payloads (listen-sites, dial-sites, inbound-auth-facts): count stays
// the full fact count while facts keeps only the prefix and
// facts_dropped names the unembedded remainder — also returned so the
// observation's limitations can name the bound.
func laneExposureFactsData(facts []domain.ExposureFact) (map[string]any, int) {
	shown, dropped := laneListPrefix(facts, lanePayloadMaxListItems)
	data := map[string]any{"facts": shown, "count": len(facts)}
	if dropped > 0 {
		data["facts_dropped"] = dropped
	}
	return data, dropped
}

// laneEvidenceBoundNote names the bound on the observation's
// limitations: every preview or digest-only item is already marked in
// the payload (content_bounded + digest pins), and this note makes the
// bound visible on the record itself — bounding is never silent. ""
// when every embedded content is verbatim.
func laneEvidenceBoundNote(view []laneEvidenceItem) string {
	previewed, digestOnly := 0, 0
	for _, it := range view {
		if !it.ContentBounded {
			continue
		}
		if it.ContentPreview != "" {
			previewed++
		} else {
			digestOnly++
		}
	}
	if previewed == 0 && digestOnly == 0 {
		return ""
	}
	return fmt.Sprintf(
		"observation payload evidence bounded by construction: %d item(s) carry a digest-pinned preview, %d item(s) are digest-only; content_sha256/content_bytes pin the full bytes",
		previewed, digestOnly)
}

// laneListBoundNote names a prefix-bounded payload member list on the
// observation's limitations. "" when the whole list is embedded.
func laneListBoundNote(name string, kept, total int) string {
	if kept >= total {
		return ""
	}
	return fmt.Sprintf(
		"%s bounded in the stored payload: %d of %d item(s) embedded; the recorded total names the full result",
		name, kept, total)
}

// maxObservationPayloadBytes bounds every stored observation payload
// (the `data` member): oversized tool results are persisted truncated so
// material evidence stays bounded and preservable (analyzer convention:
// capped output plus an explicit limitation). The stored bytes — never a
// claim about the full result — are what artifacts, data_digest and the
// audit log pin.
const maxObservationPayloadBytes = 256 * 1024

const payloadSidecarSelector = "observation payload"

// observationPayloadSidecarPath renders the content-addressed artifact
// path an externalized payload sidecar must carry: the digest names the
// file, so a recorded reference pointing anywhere else fails closed.
func observationPayloadSidecarPath(sha string) string {
	return filepath.Join("artifacts", "payload-"+sha+".json")
}

// authoritativePayloadObservation reports payloads whose complete bytes must
// survive persistence. Package inventories and closure absence records bind
// full Go stdout; truncating those bytes would destroy replayable membership.
func authoritativePayloadObservation(o *evidencetools.Observation) bool {
	return o != nil && (o.Tool == evidencetools.SymbolUnreachabilityTool || o.Tool == "package-inventory" || o.Tool == "verify_code_absence" || o.Tool == "field_assignments")
}

// capObservationPayload enforces maxObservationPayloadBytes on o.Data in
// place before artifacts/observations.jsonl are written. Truncation is
// fully visible: the original digest + size go to ScopeLimits, the
// limitation names the cap, and COMPLETE downgrades to PARTIAL (a
// truncated payload can never underwrite a completeness claim).
//
// Authoritative symbol-unreachability payloads never truncate: the
// complete canonical payload bytes go to a content-addressed sidecar
// under artDir, Data becomes a bounded externalization envelope (never
// a prefix presented as the result), PayloadRef pins the sidecar
// sha256+size, and completeness stands — the full result stays
// recoverable and hash-bound. The envelope itself is never decodable
// as the proof, so every consumer of the typed result must rehydrate
// through resolveObservationPayload and fail closed when it cannot.
func capObservationPayload(o *evidencetools.Observation, artDir string) error {
	if o == nil || o.Data == nil {
		return nil
	}
	full, err := json.Marshal(o.Data)
	if err != nil {
		return nil
	}
	if len(full) <= maxObservationPayloadBytes {
		return nil
	}
	sum := sha256.Sum256(full)
	sumHex := hex.EncodeToString(sum[:])
	if authoritativePayloadObservation(o) {
		rel := observationPayloadSidecarPath(sumHex)
		if err := os.WriteFile(filepath.Join(artDir, filepath.Base(rel)), full, 0o644); err != nil {
			return fmt.Errorf("authoritative payload sidecar %s: %w", rel, err)
		}
		o.Data = map[string]any{
			"externalized_payload":    true,
			"cap_bytes":               maxObservationPayloadBytes,
			"full_payload_sha256":     sumHex,
			"full_payload_size_bytes": len(full),
		}
		o.PayloadRef = &evidencetools.ObservationPayloadRef{
			Path: rel, SHA256: sumHex, SizeBytes: int64(len(full)),
			Selector: payloadSidecarSelector,
		}
		if o.ScopeDetails == nil {
			o.ScopeDetails = &evidencetools.ScopeDetails{}
		}
		if o.ScopeDetails.Limits == nil {
			o.ScopeDetails.Limits = &evidencetools.ScopeLimits{}
		}
		o.ScopeDetails.Limits.FullPayloadSHA256 = sumHex
		o.ScopeDetails.Limits.FullPayloadSizeBytes = int64(len(full))
		o.Limitations = append(o.Limitations, fmt.Sprintf(
			"authoritative observation payload externalized at %d bytes (cap %d) to %s; the complete payload is the sha256-pinned sidecar, not the stored envelope",
			len(full), maxObservationPayloadBytes, rel))
		return nil
	}
	// Cut at a rune boundary so the stored prefix stays valid JSON text.
	cut := maxObservationPayloadBytes
	for cut > 0 && !utf8.Valid(full[:cut]) {
		cut--
	}
	o.Data = map[string]any{
		"truncated_payload":       true,
		"cap_bytes":               maxObservationPayloadBytes,
		"full_payload_sha256":     sumHex,
		"full_payload_size_bytes": len(full),
		"stored_payload_json":     string(full[:cut]),
	}
	if o.ScopeDetails == nil {
		o.ScopeDetails = &evidencetools.ScopeDetails{}
	}
	if o.ScopeDetails.Limits == nil {
		o.ScopeDetails.Limits = &evidencetools.ScopeLimits{}
	}
	o.ScopeDetails.Limits.OutputTruncated = true
	o.ScopeDetails.Limits.FullPayloadSHA256 = sumHex
	o.ScopeDetails.Limits.FullPayloadSizeBytes = int64(len(full))
	o.Limitations = append(o.Limitations, fmt.Sprintf(
		"observation payload truncated at %d bytes (full payload %d bytes, sha256 %s); stored bytes are a prefix of the tool result, not the full result",
		maxObservationPayloadBytes, len(full), sumHex))
	if o.Completeness == evidencetools.CompletenessComplete {
		o.Completeness = evidencetools.CompletenessPartial
	}
	return nil
}

// verifyObservationPayloadRef checks a recorded payload reference
// against dir: the path must be the content-addressed name of the
// recorded digest, resolve inside dir, and the bytes must match the
// recorded size and sha256. Returns the verified payload bytes. Any
// missing, escaping, size- or digest-mismatched sidecar is an error —
// callers fail closed, never decode an unverified payload.
func verifyObservationPayloadRef(dir string, ref *evidencetools.ObservationPayloadRef) ([]byte, error) {
	if ref == nil {
		return nil, fmt.Errorf("observation has no payload reference")
	}
	if ref.SHA256 == "" || ref.SizeBytes <= 0 || ref.Path == "" {
		return nil, fmt.Errorf("payload reference is incomplete (path %q, sha256 %q, size %d)", ref.Path, ref.SHA256, ref.SizeBytes)
	}
	if want := observationPayloadSidecarPath(ref.SHA256); filepath.Clean(ref.Path) != want {
		return nil, fmt.Errorf("payload reference path %q is not the content-addressed sidecar %q", ref.Path, want)
	}
	abs := filepath.Join(dir, filepath.Clean(ref.Path))
	base := filepath.Clean(dir)
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return nil, fmt.Errorf("payload reference path %q escapes the run directory", ref.Path)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("payload sidecar %s unreadable: %w", ref.Path, err)
	}
	if int64(len(b)) != ref.SizeBytes {
		return nil, fmt.Errorf("payload sidecar %s size mismatch: recorded %d, on disk %d", ref.Path, ref.SizeBytes, len(b))
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != ref.SHA256 {
		return nil, fmt.Errorf("payload sidecar %s sha256 mismatch: recorded %s, on disk %s", ref.Path, ref.SHA256, got)
	}
	return b, nil
}

// loadExternalizedPayload verifies the complete persisted envelope and its
// sidecar before either validation or live authority decodes the payload.
func loadExternalizedPayload(dir string, o *evidencetools.Observation) (any, error) {
	if o == nil || o.PayloadRef == nil {
		return nil, fmt.Errorf("observation has no payload reference")
	}
	ref := o.PayloadRef
	if ref.Selector != payloadSidecarSelector {
		return nil, fmt.Errorf("payload_ref selector %q != %q", ref.Selector, payloadSidecarSelector)
	}
	env, ok := o.Data.(map[string]any)
	if !ok || env["externalized_payload"] != true {
		return nil, fmt.Errorf("payload_ref is present but data is not the bounded externalization envelope")
	}
	if env["full_payload_sha256"] != ref.SHA256 {
		return nil, fmt.Errorf("data envelope sha256 %v disagrees with payload_ref sha256 %q", env["full_payload_sha256"], ref.SHA256)
	}
	size, ok := payloadEnvelopeSize(env["full_payload_size_bytes"])
	if !ok || size != ref.SizeBytes {
		return nil, fmt.Errorf("data envelope size %v disagrees with payload_ref size_bytes %d", env["full_payload_size_bytes"], ref.SizeBytes)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.Limits == nil ||
		o.ScopeDetails.Limits.FullPayloadSHA256 != ref.SHA256 ||
		o.ScopeDetails.Limits.FullPayloadSizeBytes != ref.SizeBytes {
		return nil, fmt.Errorf("scope limits full payload pins disagree with payload_ref sha256 %q size_bytes %d", ref.SHA256, ref.SizeBytes)
	}
	b, err := verifyObservationPayloadRef(dir, ref)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("payload sidecar %s undecodable: %w", ref.Path, err)
	}
	return v, nil
}

func payloadEnvelopeSize(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n < 0 || n >= 1<<63 || float64(int64(n)) != n {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}

// rehydrateObservationPayload restores the complete hash-bound payload
// of an authoritative observation in place: Data becomes the decoded
// sidecar content and PayloadRef clears — the in-memory copy then
// carries the same typed result the tool produced, the only form the
// decision authority may consume. The persisted envelope and its
// digest pins are untouched; rehydration is an in-memory operation on
// caller-owned copies. A lane without a recorded output directory,
// a missing/altered/undecodable sidecar or a mismatched digest is a
// named error — the caller degrades to INCONCLUSIVE, never a guess.
func (r *LaneResult) rehydrateObservationPayload(o *evidencetools.Observation) error {
	if o == nil || o.PayloadRef == nil {
		return nil
	}
	if r.outputDir == "" {
		return fmt.Errorf("observation %s carries an externalized payload but the lane recorded no output directory", o.ID)
	}
	data, err := loadExternalizedPayload(r.outputDir, o)
	if err != nil {
		return fmt.Errorf("observation %s: %w", o.ID, err)
	}
	o.Data = data
	o.PayloadRef = nil
	return nil
}

// persist writes observations.jsonl, per-observation canonical artifacts
// and deterministic-facts.json, then derives VerifiedFacts for OK
// observations.
func (r *LaneResult) persist(outDir string) error {
	artDir := filepath.Join(outDir, "artifacts")
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		return err
	}
	r.outputDir = outDir
	// Bound every stored payload before anything is written: the audit
	// record's Observation is the same pointer, so capping here covers
	// artifacts and observations.jsonl alike. Session-drained audit
	// records carry their own observation clones, so the records pass
	// covers any copy the lane list did not already process —
	// externalization is content-addressed and idempotent. Positive
	// findings are detected before capping so a truncated or
	// externalized envelope can never hide what the tool observed.
	posByObs := map[*evidencetools.Observation]bool{}
	for i := range r.Records {
		o := r.Records[i].Observation
		if o != nil && o.Completeness == evidencetools.CompletenessUnknown {
			posByObs[o] = observationHasPositive(o)
		}
	}
	seen := map[*evidencetools.Observation]bool{}
	for _, o := range r.Observations {
		if err := capObservationPayload(o, artDir); err != nil {
			return err
		}
		seen[o] = true
	}
	for i := range r.Records {
		o := r.Records[i].Observation
		if o == nil || seen[o] {
			continue
		}
		seen[o] = true
		// Only the authoritative payload family externalizes on the
		// audit copy; other oversized record payloads keep their
		// verbatim session form in the ledger exactly as before.
		if authoritativePayloadObservation(o) {
			if err := capObservationPayload(o, artDir); err != nil {
				return err
			}
		}
	}
	// One canonical artifact per observation: the observation record
	// itself, canonical-encoded, is the pinned payload.
	for _, o := range r.Observations {
		payload, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			return fmt.Errorf("artifact encode %s: %w", o.ID, err)
		}
		name := strings.ToLower(o.ID) + ".json"
		full := filepath.Join(artDir, name)
		written := append(payload, '\n')
		if err := os.WriteFile(full, written, 0o644); err != nil {
			return fmt.Errorf("artifact write %s: %w", o.ID, err)
		}
		// artifact.sha256 is the digest of the exact bytes on disk so a
		// third party can verify the file; data_digest (the fact field)
		// stays the canonical payload digest without the trailing LF.
		sum := sha256.Sum256(written)
		csum := sha256.Sum256(payload)
		r.CanonicalByObs[o.ID] = hex.EncodeToString(csum[:])
		r.ArtifactByObs[o.ID] = ArtifactRef{
			Path: filepath.Join("artifacts", name), SHA256: hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(written)),
			Selector:  "observation",
		}
	}
	// observations.jsonl — one audit record per line, call order.
	f, err := os.Create(filepath.Join(outDir, "observations.jsonl"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, rec := range r.Records {
		if err := enc.Encode(rec); err != nil {
			f.Close()
			return fmt.Errorf("observations.jsonl: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	// verified facts: OK observations only. An OK observation carrying
	// CompletenessUnknown is open-scope evidence: it becomes a verified
	// fact only when its payload records at least one concrete finding —
	// that positive is a lower bound, so it is reported as PARTIAL with
	// an explicit open-enumeration limitation. An OK+UNKNOWN observation
	// with no positive content never becomes a fact: silence in an
	// unbounded scope must not be readable as absence, so the assembler
	// routes it to the unknowns side instead.
	//
	// package-usage promotion is stricter on the negative side: USED
	// promotes as a PACKAGE_USAGE TRUE fact; a VERIFIED NOT_USED
	// promotes as a PACKAGE_USAGE FALSE fact only while the recorded
	// observation scope stays COMPLETE (a PARTIAL negative scope never
	// underwrites a FALSE claim); an UNKNOWN usage check promotes only
	// as a positive lower bound — never as a negative fact.
	//
	// usage-scope (B41) promotion is OK+COMPLETE-only: the recorded
	// build-closure class — product, test-only, mixed, or the
	// auditable absent-from-both unknown — becomes a claim=TRUE
	// BUILD_USAGE_SCOPE fact bound to the exact subject the record's
	// args name (never decoded from agent text, never a FALSE claim,
	// never NegativeVerification). A degraded or undecodable stream
	// promotes nothing and routes to the B41 unknown entries instead.
	generated := time.Now().UTC().Format(time.RFC3339)
	for i, rec := range r.Records {
		o := rec.Observation
		if o == nil || o.ToolStatus != evidencetools.StatusOK {
			continue
		}
		coverage := string(o.Completeness)
		lims := append([]string{}, o.Limitations...)
		claim := "TRUE"
		var factKind, factNegVer, factUsageScope, factProdAbs, factUsageBasis string
		var usageSubj *FactUsageSubject
		if rec.Tool == evidencetools.UsageScopeTool {
			// B41: only an OK observation over a closed paired stream
			// (recorded completeness COMPLETE) with a decodable
			// classification and an args-bound subject promotes. The
			// claim records the build-closure class — including the
			// absent-from-both unknown class — verbatim; it is never a
			// FALSE claim and never a NegativeVerification. Anything
			// else stays an auditable observation routed to the B41
			// unknown entries.
			d, ok := usageScopeDataOf(o)
			subj := usageScopeSubjectOf(rec.Args)
			if !ok || subj == nil || d.UsageScope == "" ||
				d.Module != subj.Module || d.Package != subj.Package ||
				o.Completeness != evidencetools.CompletenessComplete {
				continue
			}
			factKind = FactKindBuildUsageScope
			factUsageScope = d.UsageScope
			// The marker travels verbatim; validateBuildUsageScopeFact
			// owns the (usage_scope, marker) validity table, so a forged
			// combination fails validation instead of being silently
			// sanitized away here.
			factProdAbs = d.ProductAbsenceVerification
			usageSubj = subj
		} else if rec.Tool == evidencetools.PackageUsageTool {
			d, ok := packageUsageDataOf(o)
			verdict, negVer := goanalysis.PackageUsageState(d.Usage),
				goanalysis.PackageUsageNegativeVerification(d.NegativeVerification)
			subj := packageUsageSubjectOf(rec.Args)
			switch {
			case !ok || subj == nil:
				// An undecodable verdict or an observation with no
				// structured subject can never promote — a fact must be
				// bound to exactly the subject it checked.
				continue
			case verdict == goanalysis.PackageUsageUsed:
				factKind = FactKindPackageUsage
			case verdict == goanalysis.PackageUsageNotUsed &&
				negVer == goanalysis.PackageUsageNegativeVerified:
				// The negative claim exists only while the recorded
				// scope is closed; a degraded completeness cannot carry
				// a FALSE fact.
				if o.Completeness != evidencetools.CompletenessComplete {
					continue
				}
				factKind = FactKindPackageUsage
				claim = "FALSE"
				factNegVer = NegativeVerificationVerified
				// The negative's basis travels on the fact: a package
				// present-but-unused result is the bounded basis,
				// while a package provably absent from the complete
				// product closure is the stronger basis the validator
				// may read differently.
				if d.Present {
					factUsageBasis = UsageBasisPresentUnused
				} else {
					factUsageBasis = UsageBasisAbsentFromClosure
				}
			case packageUsagePositive(o):
				// An undetermined usage check that still records a
				// concrete product-source site or linkage is a positive
				// lower bound only — a distinct kind, never mistaken for
				// a USED verdict and never underwriting a negative.
				factKind = FactKindPackageUsageLowerBound
				coverage = string(evidencetools.CompletenessPartial)
				lims = append(lims, openEnumerationLimitation)
			default:
				continue
			}
			usageSubj = subj
		} else if o.Completeness == evidencetools.CompletenessUnknown {
			// Positivity was judged on the payload the tool produced —
			// the pre-cap snapshot — so a truncation/externalization
			// envelope can never hide a recorded finding nor fabricate
			// an absent one.
			if !posByObs[o] {
				continue
			}
			coverage = string(evidencetools.CompletenessPartial)
			lims = append(lims, openEnumerationLimitation)
		}
		inputDigest := sha256.Sum256(rec.Args)
		art, ok := r.ArtifactByObs[o.ID]
		if !ok {
			continue
		}
		ext := (*string)(nil)
		if o.ScopeDetails != nil && o.ScopeDetails.ExternalSHA != "" {
			s := o.ScopeDetails.ExternalSHA
			ext = &s
		}
		snapHash := r.ContentHash
		if o.ScopeDetails != nil && o.ScopeDetails.SnapshotHash != "" {
			snapHash = o.ScopeDetails.SnapshotHash
		}
		r.Facts = append(r.Facts, VerifiedFact{
			ID:                         fmt.Sprintf("fact-%s", strings.ToLower(o.ID)),
			Kind:                       factKind,
			UsageSubject:               usageSubj,
			UsageScope:                 factUsageScope,
			ProductAbsenceVerification: factProdAbs,
			Statement:                  o.Fact,
			Claim:                      claim,
			Tool:                       rec.Tool,
			ToolVersion:                toolVersionFor(rec.Tool, r),
			Command:                    commandString(rec.Tool, rec.Args),
			Scope:                      o.Scope,
			Status:                     "OK",
			Coverage:                   coverage,
			SnapshotContentHash:        snapHash,
			ExternalCommitSHA:          ext,
			InputDigest:                hex.EncodeToString(inputDigest[:]),
			DataDigest:                 r.CanonicalByObs[o.ID],
			Artifact:                   art,
			Provenance:                 FactProvenance{ObservationID: o.ID, Source: "deterministic-lane", GeneratedAt: generated},
			Limitations:                lims,
			NegativeVerification:       factNegVer,
			UsageBasis:                 factUsageBasis,
		})
		_ = i
	}
	factsDoc, err := json.MarshalIndent(map[string]any{
		"schema":            "deterministic-facts/1",
		"snapshot_root":     r.SnapshotRoot,
		"content_hash":      r.ContentHash,
		"observations":      len(r.Observations),
		"verified_fact_ids": factIDs(r.Facts),
		"facts":             r.Facts,
	}, "", "  ")
	if err != nil {
		return err
	}
	written := append(factsDoc, '\n')
	sum := sha256.Sum256(written)
	r.FactsArtifact = &AttemptArtifact{
		Path: "deterministic-facts.json", SHA256: hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(written)), Selector: "deterministic lane result",
	}
	return os.WriteFile(filepath.Join(outDir, "deterministic-facts.json"), written, 0o644)
}

func factIDs(f []VerifiedFact) []string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.ID)
	}
	return out
}

// openEnumerationLimitation is appended to a verified fact projected
// from an OK observation whose Completeness is UNKNOWN but whose payload
// records positive content: the positive finding is a lower bound, the
// open-ended scope affects negatives only.
const openEnumerationLimitation = "the recorded finding is a lower bound within an open-ended scope: " +
	"enumeration is not closed, so this check cannot establish absence — the open enumeration affects " +
	"negatives, not the found positive"

// negativePayloadKeys names observation-payload members that record
// misses rather than findings; a non-empty value under one is never
// positive content on its own.
var negativePayloadKeys = map[string]bool{
	"missing": true, "errors": true, "skipped": true,
}

// positiveBoolKeys names boolean payload members whose true value is a
// recorded positive (existence/presence) rather than metadata about the
// enumeration itself.
var positiveBoolKeys = map[string]bool{
	"found": true, "present": true, "in_database": true,
	"gated": true, "dead_code": true,
}

// positiveStringKeys names string payload members whose non-empty value
// is the observed content itself.
var positiveStringKeys = map[string]bool{
	"source": true, "content": true, "output": true, "diff": true, "patch": true,
}

// observationHasPositive reports whether an OK observation's Data
// payload records at least one concrete finding — a non-empty
// collection of findings or a positive count/reach field. Metadata
// about the enumeration (counts of unproven candidates, booleans
// describing the scan) is not positive content. Audit-record
// observations carry the tool's typed payload struct rather than a
// decoded map, so non-map payloads are normalized through the same
// JSON encoding the persisted artifact uses.
func observationHasPositive(o *evidencetools.Observation) bool {
	m, ok := o.Data.(map[string]any)
	if !ok {
		b, err := json.Marshal(o.Data)
		if err != nil || json.Unmarshal(b, &m) != nil {
			return false
		}
	}
	return positivePayloadValue(m, "")
}

// positivePayloadValue walks a decoded observation payload: findings
// under keys that record misses are skipped, and every member of a
// positive collection counts at the level that carries it.
func positivePayloadValue(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, m := range t {
			if negativePayloadKeys[k] {
				continue
			}
			if positivePayloadValue(m, k) {
				return true
			}
		}
		return false
	case []any:
		return len(t) > 0 && !negativePayloadKeys[key]
	case float64:
		return t > 0 && !negativePayloadKeys[key]
	case int:
		return t > 0 && !negativePayloadKeys[key]
	case int64:
		return t > 0 && !negativePayloadKeys[key]
	case bool:
		return t && positiveBoolKeys[key]
	case string:
		return t != "" && positiveStringKeys[key]
	default:
		return false
	}
}

func toolVersionFor(tool string, r *LaneResult) string {
	switch tool {
	case "affected-resolve", "repository-snapshot", "repository-preflight", "advisory-load",
		"ingress-inventory", "listen-sites", "dial-sites", "inbound-auth-facts":
		if r.Toolchain.Version != "" {
			return "izyan/research-lane go" + r.Toolchain.Version
		}
		return "izyan/research-lane"
	default:
		return evidencetools.AdapterVersion
	}
}

func commandString(tool string, args json.RawMessage) string {
	if len(args) == 0 {
		return tool
	}
	return fmt.Sprintf("%s %s", tool, string(args))
}

// loadFrozenAdvisory loads exactly one frozen OSV record and normalizes
// every affected entry (Go and non-Go) for the report.
func loadFrozenAdvisory(ctx context.Context, o LaneOptions) (*AdvisoryRecord, error) {
	rec := &AdvisoryRecord{Outcome: "frozen_file"}
	var path string
	switch {
	case o.AdvisoryFile != "":
		path = o.AdvisoryFile
		rec.Input.SourceKind = "frozen_file"
		rec.Input.SourcePath = o.AdvisoryFile
	case o.AdvisoryDir != "":
		prep := filepath.Join(o.OutputDir, "advisory")
		ar, err := vexbench.PrepareFrozenAdvisory(ctx, o.CVE, prep, o.AdvisoryDir)
		if err != nil {
			return nil, fmt.Errorf("prepare frozen advisory: %w", err)
		}
		if ar.Path == "" {
			return nil, fmt.Errorf("frozen advisory dir %s cannot serve %s: %s (%s)", o.AdvisoryDir, o.CVE, ar.Reason, ar.Outcome)
		}
		path = ar.Path
		rec.Outcome = ar.Outcome.String()
		if ar.Outcome == vexbench.AdvisoryPartial {
			rec.PartialNote = "advisory carries a Go entry without usable SEMVER ranges; applicability for that entry stays UNKNOWN"
		}
		rec.Input.SourceKind = "frozen_dir"
		rec.Input.SourcePath = path
	default:
		return nil, errors.New("exactly one of --advisory-dir/--advisory-file is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read advisory: %w", err)
	}
	rec.RawBytes = body
	sum := sha256.Sum256(body)
	rec.Input.RawSHA256 = hex.EncodeToString(sum[:])
	canon, err := vexbench.CanonicalSHA256(body)
	if err != nil {
		return nil, fmt.Errorf("canonical advisory digest: %w", err)
	}
	rec.Input.CanonicalSHA256 = canon
	v, err := (vulnerability.FileSource{Path: path, NoAliasEnrichment: true}).Get(ctx, o.CVE)
	if err != nil {
		return nil, fmt.Errorf("advisory %s does not cover %s: %w", path, o.CVE, err)
	}
	// The parser-produced scope is consumed verbatim: Impls, RawBytes and
	// the raw/canonical research digests below are reporting inputs and
	// never repair or promote completeness. A record the parser could only
	// reduce stays non-closing here.
	rec.Vuln = v
	rec.Input.RequestedID = o.CVE
	rec.Input.ResolvedID = v.ID
	rec.Input.Modified = nilStr(v.Modified)
	impls, err := normalizeImplementations(body, o.CVE, v.ID)
	if err != nil {
		return nil, fmt.Errorf("normalize advisory entries: %w", err)
	}
	rec.Impls = impls
	// Exact record intake never consults the alias/feed subject-merging
	// path: a common CVE key must not confer another record's package or
	// symbol coverage on this assessment. The feed channel stays available
	// to the legacy lane, where its outcome is reported verbatim.
	if !exactRecordIntake(o) {
		completeAdvisoryImports(ctx, o, rec)
	}
	return rec, nil
}

// osvDoc is the minimal OSV shape needed to preserve every affected
// entry, including non-Go ones the internal model folds away.
type osvDoc struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
				GOOS    []string `json:"goos"`
				GOARCH  []string `json:"goarch"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// normalizeImplementations projects every OSV affected[] entry into the
// report's affected_implementations. Non-Go entries stay visible with
// binding=non-go; Go entries without usable ranges are incomplete.
func normalizeImplementations(body []byte, requested, resolved string) ([]AffectedImplementation, error) {
	var doc osvDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	impls := make([]AffectedImplementation, 0, len(doc.Affected))
	for i, a := range doc.Affected {
		im := AffectedImplementation{
			ID:        fmt.Sprintf("adv-%02d", i+1),
			Ecosystem: a.Package.Ecosystem,
			Module:    a.Package.Name,
			SourceRef: fmt.Sprintf("adv:%s", doc.ID),
		}
		var symbols, goos, goarch []string
		for _, imp := range a.EcosystemSpecific.Imports {
			if im.Package == nil && imp.Path != "" {
				p := imp.Path
				im.Package = &p
			}
			im.imports = append(im.imports, implImport{Path: imp.Path, Symbols: imp.Symbols})
			symbols = append(symbols, imp.Symbols...)
			goos = append(goos, imp.GOOS...)
			goarch = append(goarch, imp.GOARCH...)
		}
		im.Symbols = dedupe(symbols)
		im.GOOS = dedupe(goos)
		im.GOARCH = dedupe(goarch)
		hasRangeEvent := false
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				b := VersionBounds{
					Introduced:   nilStr(ev.Introduced),
					Fixed:        nilStr(ev.Fixed),
					LastAffected: nilStr(ev.LastAffected),
				}
				if ev.Introduced != "" || ev.Fixed != "" || ev.LastAffected != "" {
					hasRangeEvent = true
				}
				im.AffectedVersions = append(im.AffectedVersions, b)
			}
			if r.Type == "SEMVER" {
				for _, ev := range r.Events {
					if ev.Fixed != "" {
						im.FixedVersions = append(im.FixedVersions, ev.Fixed)
					}
				}
			}
		}
		switch {
		case a.Package.Ecosystem != "Go" && a.Package.Ecosystem != "":
			im.Binding = BindNonGo
		case a.Package.Name == "" || !hasRangeEvent:
			im.Binding = BindIncomplete
		case requested != resolved:
			im.Binding = BindAliasResolved
		default:
			im.Binding = BindExact
		}
		impls = append(impls, im)
	}
	return impls, nil
}

func advisoryLimitations(a *AdvisoryRecord) []string {
	var lims []string
	if a.PartialNote != "" {
		lims = append(lims, a.PartialNote)
	}
	nonGo, incomplete := 0, 0
	for _, im := range a.Impls {
		switch im.Binding {
		case BindNonGo:
			nonGo++
		case BindIncomplete:
			incomplete++
		}
	}
	if nonGo > 0 {
		lims = append(lims, fmt.Sprintf("%d non-Go affected entries retained as advisory scope, never as product facts", nonGo))
	}
	if incomplete > 0 {
		lims = append(lims, fmt.Sprintf("%d advisory entries lack a usable Go package/range (binding=incomplete)", incomplete))
	}
	if fr := a.Input.FeedResolution; fr != nil && fr.Status != "" && fr.Status != advfeed.StatusNotRequired {
		lims = append(lims, fmt.Sprintf("advisory feed subject resolution: %s%s", fr.Status, feedResolutionSuffix(fr)))
	}
	return lims
}

func feedResolutionSuffix(fr *AdvisoryFeedResolution) string {
	switch fr.Status {
	case advfeed.StatusResolved:
		return fmt.Sprintf(" — subjects supplied by dump record(s) %s (dump sha256 %s)",
			strings.Join(fr.SourceIDs, ", "), shortHash(fr.DumpSHA256))
	default:
		if fr.Reason != "" {
			return " (" + fr.Reason + ": " + fr.Detail + ")"
		}
		return ""
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ReasonAdvisoryImportsUnavailable names the fail-closed outcome recorded
// when a configured advisory feed cannot supply the missing subjects.
const ReasonAdvisoryImportsUnavailable = "ADVISORY_IMPORTS_UNAVAILABLE"

// completeAdvisoryImports fills the package/symbol subjects of advisory
// entries whose frozen document declared no ecosystem_specific.imports,
// resolving them from the configured OSV advisory feed by advisory id and
// aliases. The frozen file stays authoritative: entries that already
// declare imports are never touched, and unresolved entries keep their
// module-only binding — the report records the named reason
// ADVISORY_IMPORTS_UNAVAILABLE next to the existing UNKNOWN.
func completeAdvisoryImports(ctx context.Context, o LaneOptions, rec *AdvisoryRecord) {
	if o.AdvisoryFeed == nil {
		return
	}
	fr := &AdvisoryFeedResolution{}
	rec.Input.FeedResolution = fr
	src := "local"
	if o.AdvisoryFeed.LocalPath == "" {
		src = "remote"
	}
	fr.FeedSource = src

	// Entries are aligned with doc.Affected by construction
	// (normalizeImplementations walks it in order).
	var doc osvDoc
	if err := json.Unmarshal(rec.RawBytes, &doc); err != nil || len(doc.Affected) != len(rec.Impls) {
		fr.Status = advfeed.StatusFeedError
		fr.Reason = ReasonAdvisoryImportsUnavailable
		fr.Detail = "advisory body could not be re-parsed for feed completion"
		return
	}
	need := map[int]bool{}
	for i, a := range doc.Affected {
		if a.Package.Ecosystem != "Go" && a.Package.Ecosystem != "" {
			continue
		}
		if a.Package.Name == "" || len(a.EcosystemSpecific.Imports) > 0 {
			continue
		}
		need[i] = true
	}
	if len(need) == 0 {
		// The advisory already declares every subject it can — the feed
		// is never consulted, so no source provenance is recorded.
		fr.Status = advfeed.StatusNotRequired
		return
	}
	needIdx := make([]int, 0, len(need))
	for i := range need {
		needIdx = append(needIdx, i)
	}
	sort.Ints(needIdx)

	outcome, aerr := advfeed.Acquire(ctx, *o.AdvisoryFeed)
	fr.FeedRef = outcome.Prov.Ref
	fr.DumpSHA256 = outcome.Prov.SHA256
	if !outcome.Prov.CheckedAt.IsZero() {
		fr.CheckedAt = outcome.Prov.CheckedAt.Format(time.RFC3339)
	}
	fr.CacheFallback = outcome.CacheFallback
	if outcome.Feed == nil {
		fr.Status = outcome.Status
		if fr.Status == "" {
			fr.Status = advfeed.StatusFeedError
		}
		fr.Reason = ReasonAdvisoryImportsUnavailable
		fr.Detail = outcome.Detail
		if fr.Detail == "" && aerr != nil {
			fr.Detail = aerr.Error()
		}
		for _, i := range needIdx {
			fr.Entries = append(fr.Entries, AdvisoryFeedResolutionEntry{
				ImplID: rec.Impls[i].ID, Module: rec.Impls[i].Module, Status: fr.Status,
			})
		}
		return
	}

	resolved, failed := 0, 0
	var details []string
	for _, i := range needIdx {
		im := &rec.Impls[i]
		res := outcome.Feed.ResolveImports(rec.Input.ResolvedID, rec.Vuln.Aliases, im.Module)
		fr.Entries = append(fr.Entries, AdvisoryFeedResolutionEntry{
			ImplID: im.ID, Module: im.Module, Status: res.Status, SourceID: res.SourceID,
		})
		if !res.OK {
			failed++
			details = append(details, fmt.Sprintf("%s (module %s): %s", im.ID, im.Module, res.Detail))
			continue
		}
		resolved++
		applyFeedImports(im, res.Imports)
		completeVulnImports(rec.Vuln, im.Module, res.Imports)
		if res.MatchedID != "" && res.MatchedID != rec.Input.ResolvedID {
			// The lookup hit an alias record, not the frozen id itself.
			fr.ResolvedIDs = appendUniqueStr(fr.ResolvedIDs, res.MatchedID)
		}
		fr.SourceIDs = appendUniqueStr(fr.SourceIDs, res.SourceID)
		rec.Vuln.Provenance["affected_symbols_source"] = "osv-dump:" + res.SourceID
	}
	switch {
	case failed == 0:
		fr.Status = advfeed.StatusResolved
	case resolved == 0:
		fr.Status = firstUnresolvedStatus(fr.Entries)
	default:
		// Mixed outcome: resolved entries keep their completed subjects;
		// the record still fails closed for the rest.
		fr.Status = "partial"
	}
	if failed > 0 {
		fr.Reason = ReasonAdvisoryImportsUnavailable
		fr.Detail = strings.Join(details, "; ")
	}
}

// applyFeedImports projects resolved feed imports into the report entry's
// flat and structured fields — the same shape normalizeImplementations
// produces for declared imports.
func applyFeedImports(im *AffectedImplementation, imports []advfeed.Import) {
	var symbols, goos, goarch []string
	for _, imp := range imports {
		if im.Package == nil && imp.Path != "" {
			p := imp.Path
			im.Package = &p
		}
		im.imports = append(im.imports, implImport{Path: imp.Path, Symbols: imp.Symbols})
		symbols = append(symbols, imp.Symbols...)
		goos = append(goos, imp.GOOS...)
		goarch = append(goarch, imp.GOARCH...)
	}
	im.Symbols = dedupe(symbols)
	im.GOOS = dedupe(goos)
	im.GOARCH = dedupe(goarch)
}

// completeVulnImports mirrors a feed-completed entry into the domain
// vulnerability the lane probes: the per-module AffectedModule record and
// the primary module's flat package/symbol lists. Only empty subject
// fields are filled — anything the frozen file declared is authoritative.
func completeVulnImports(v *domain.Vulnerability, module string, imports []advfeed.Import) {
	var pkgs []domain.AffectedPackage
	var syms []domain.SymbolRef
	seen := map[string]bool{}
	for _, imp := range imports {
		if imp.Path == "" {
			continue
		}
		pkgs = append(pkgs, domain.AffectedPackage{
			Path: imp.Path, Symbols: append([]string(nil), imp.Symbols...),
			GOOS: imp.GOOS, GOARCH: imp.GOARCH,
		})
		for _, s := range imp.Symbols {
			if seen[imp.Path+"."+s] {
				continue
			}
			seen[imp.Path+"."+s] = true
			syms = append(syms, domain.SymbolRef{Package: imp.Path, Symbol: s})
		}
	}
	for i := range v.AffectedModules {
		am := &v.AffectedModules[i]
		if am.Module != module || len(am.AffectedPackages) > 0 || len(am.AffectedSymbols) > 0 {
			continue
		}
		am.AffectedPackages = pkgs
		am.AffectedSymbols = syms
	}
	if module == v.Module && len(v.AffectedPackages) == 0 && len(v.AffectedSymbols) == 0 {
		v.AffectedPackages = pkgs
		v.AffectedSymbols = syms
		if v.Package == v.Module && len(pkgs) > 0 {
			v.Package = pkgs[0].Path
		}
	}
}

func firstUnresolvedStatus(entries []AdvisoryFeedResolutionEntry) string {
	for _, e := range entries {
		if e.Status != advfeed.StatusResolved {
			return e.Status
		}
	}
	return advfeed.StatusFeedError
}

func appendUniqueStr(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, s := range list {
		if s == v {
			return list
		}
	}
	return append(list, v)
}

// goImplementations returns the Go-ecosystem entries with their symbol
// refs projected for the deterministic lane.
func goImplementations(impls []AffectedImplementation) []struct {
	Module  string
	Symbols []domain.SymbolRef
} {
	var out []struct {
		Module  string
		Symbols []domain.SymbolRef
	}
	for _, im := range impls {
		if im.Binding != BindExact && im.Binding != BindAliasResolved && im.Binding != BindIncomplete {
			continue
		}
		if im.Ecosystem != "Go" && im.Ecosystem != "" {
			continue
		}
		e := struct {
			Module  string
			Symbols []domain.SymbolRef
		}{Module: im.Module}
		pkg := im.Module
		if im.Package != nil && *im.Package != "" {
			pkg = *im.Package
		}
		if len(im.imports) > 0 {
			// Structured imports bind every symbol to its own package
			// path; the flat Symbols list cannot express multi-package
			// declarations (including feed-completed ones).
			for _, imp := range im.imports {
				for _, s := range imp.Symbols {
					e.Symbols = append(e.Symbols, domain.SymbolRef{Package: imp.Path, Symbol: s})
				}
			}
		} else {
			for _, s := range im.Symbols {
				e.Symbols = append(e.Symbols, domain.SymbolRef{Package: pkg, Symbol: s})
			}
		}
		out = append(out, e)
	}
	return out
}

// packageUsageSubject is the internal name for the structured
// advisory-declared subject a package-usage check binds to; the wire
// type is FactUsageSubject (types.go).
type packageUsageSubject = FactUsageSubject

// packageUsageSubjectOf decodes the structured advisory-declared
// subject a package-usage observation was invoked with. The audit
// record's args are the authoritative binding for the promoted fact:
// when they carry no package, the observation has no subject and must
// never promote (a fact bound to nothing could be cited for anything).
func packageUsageSubjectOf(args json.RawMessage) *FactUsageSubject {
	if len(args) == 0 {
		return nil
	}
	var s FactUsageSubject
	if err := json.Unmarshal(args, &s); err != nil {
		return nil
	}
	if s.Package == "" {
		return nil
	}
	return &s
}

// packageUsageCandidates enumerates the package-usage subjects the lane
// probes: a package-level subject per advisory-declared package and a
// symbol-level subject per declared symbol, using the same entry/probe
// projection the resolver uses (AffectedModuleEntries +
// AffectedPackagesForEntry). A symbol without a package identity adds
// nothing and the module path is never substituted for a package, so a
// module-only advisory yields an empty list. Entries outside the Go
// implementation set are skipped. The result is deduplicated and sorted
// by package, then symbol, then module for a stable call order.
func packageUsageCandidates(vuln domain.Vulnerability, goModules map[string]bool) []FactUsageSubject {
	seen := map[FactUsageSubject]bool{}
	var out []FactUsageSubject
	add := func(module, pkg, symbol string) {
		if pkg == "" {
			return
		}
		s := FactUsageSubject{Module: module, Package: pkg, Symbol: symbol}
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, entry := range affected.AffectedModuleEntries(vuln) {
		if len(goModules) > 0 && !goModules[entry.Module] {
			continue
		}
		for _, p := range affected.AffectedPackagesForEntry(entry) {
			add(entry.Module, p.Path, "")
			for _, sym := range p.Symbols {
				add(entry.Module, p.Path, sym)
			}
		}
		for _, sr := range entry.AffectedSymbols {
			add(entry.Module, sr.Package, sr.Symbol)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Symbol != b.Symbol {
			return a.Symbol < b.Symbol
		}
		return a.Module < b.Module
	})
	return out
}

// packageUsageVerdict decodes a package-usage observation payload into
// its usage verdict and negative-verification state. The audit record
// carries the typed payload while lane observations carry the decoded
// map, so non-struct payloads are normalized through the same JSON the
// persisted artifact uses.
func packageUsageVerdict(o *evidencetools.Observation) (goanalysis.PackageUsageState, goanalysis.PackageUsageNegativeVerification, bool) {
	if o == nil || o.Data == nil {
		return "", "", false
	}
	if d, ok := o.Data.(evidencetools.PackageUsageData); ok {
		return goanalysis.PackageUsageState(d.Usage),
			goanalysis.PackageUsageNegativeVerification(d.NegativeVerification), true
	}
	b, err := json.Marshal(o.Data)
	if err != nil {
		return "", "", false
	}
	var d evidencetools.PackageUsageData
	if err := json.Unmarshal(b, &d); err != nil {
		return "", "", false
	}
	return goanalysis.PackageUsageState(d.Usage),
		goanalysis.PackageUsageNegativeVerification(d.NegativeVerification), true
}

// packageUsagePositive reports whether a package-usage payload records
// concrete positive content — a product-source site or the package's
// linkage into the import closure. An undetermined check with no
// positive payload must never promote to a fact.
func packageUsagePositive(o *evidencetools.Observation) bool {
	var (
		sites   []domain.CallSite
		present bool
	)
	switch d := o.Data.(type) {
	case evidencetools.PackageUsageData:
		sites = append(sites, d.ProductSites...)
		sites = append(sites, d.ImportSites...)
		present = d.Present
	case map[string]any:
		present, _ = d["present"].(bool)
		for _, k := range []string{"product_sites", "import_sites"} {
			if arr, ok := d[k].([]any); ok && len(arr) > 0 {
				return true
			}
		}
		return present
	default:
		return false
	}
	return len(sites) > 0 || present
}

// ---- B41 usage-scope subjects ----

// usageScopeCandidates enumerates the subjects the lane's paired
// build-closure check probes (B41): one package-level subject per
// advisory-declared package — explicit affected packages and packages
// projected from affected symbols through the same
// AffectedPackagesForEntry projection B42 uses — plus one module-level
// aggregate ({Module, Package:""}) per Go entry that names no package.
// The module path is never substituted for a package: the aggregate
// keeps an empty package and is a module-level statement only. There
// is no symbol-level B41 check. Entries outside the Go implementation
// set are skipped; the result is deduplicated, package checks sorted
// by package then module, aggregates sorted by module, package checks
// first — a stable call order.
func usageScopeCandidates(vuln domain.Vulnerability, goModules map[string]bool) []FactUsageSubject {
	seen := map[FactUsageSubject]bool{}
	var pkgs, mods []FactUsageSubject
	for _, entry := range affected.AffectedModuleEntries(vuln) {
		if len(goModules) > 0 && !goModules[entry.Module] {
			continue
		}
		// The module aggregate is gated by what the entry DECLARES,
		// never by what global deduplication emitted: when a later
		// entry repeats packages already seen for the same module,
		// every package takes the continue branch — but the entry is
		// still a package-declaring entry and must never collapse into
		// a module-level subject.
		entryDeclaresPkg := false
		for _, p := range affected.AffectedPackagesForEntry(entry) {
			if p.Path == "" {
				continue
			}
			entryDeclaresPkg = true
			s := FactUsageSubject{Module: entry.Module, Package: p.Path}
			if seen[s] {
				continue
			}
			seen[s] = true
			pkgs = append(pkgs, s)
		}
		if !entryDeclaresPkg && entry.Module != "" {
			s := FactUsageSubject{Module: entry.Module}
			if !seen[s] {
				seen[s] = true
				mods = append(mods, s)
			}
		}
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Package != pkgs[j].Package {
			return pkgs[i].Package < pkgs[j].Package
		}
		return pkgs[i].Module < pkgs[j].Module
	})
	sort.Slice(mods, func(i, j int) bool { return mods[i].Module < mods[j].Module })
	return append(pkgs, mods...)
}

// usageScopeSubjectOf decodes the structured advisory-declared subject
// a usage-scope record was invoked with. The audit record's args are
// the authoritative binding for the promoted fact, exactly as for
// package-usage — except an empty package is legal here: it names the
// module-level aggregate, and only the B41 rules (never the B42
// package-usage rules) decide whether that shape is a fact at all.
// When the args carry no module the record has no subject and can
// never promote.
func usageScopeSubjectOf(args json.RawMessage) *FactUsageSubject {
	if len(args) == 0 {
		return nil
	}
	var s FactUsageSubject
	if err := json.Unmarshal(args, &s); err != nil {
		return nil
	}
	if s.Module == "" || s.Symbol != "" {
		return nil
	}
	return &s
}

// usageScopeDataOf decodes a usage-scope observation payload into its
// typed data, mirroring packageUsageDataOf: the audit record carries
// the tool's typed struct while lane observations carry the decoded
// map, so non-struct payloads are normalized through the same JSON the
// persisted artifact uses. ok=false means the payload is absent or
// undecodable — never a classification either way.
func usageScopeDataOf(o *evidencetools.Observation) (evidencetools.UsageScopeData, bool) {
	if o == nil || o.Data == nil {
		return evidencetools.UsageScopeData{}, false
	}
	if d, ok := o.Data.(evidencetools.UsageScopeData); ok {
		return d, true
	}
	b, err := json.Marshal(o.Data)
	if err != nil {
		return evidencetools.UsageScopeData{}, false
	}
	var d evidencetools.UsageScopeData
	if err := json.Unmarshal(b, &d); err != nil {
		return evidencetools.UsageScopeData{}, false
	}
	return d, true
}

// usageEntrySymbols extracts callee names from a module_usage
// observation to seed module_internal_reach entries.
func usageEntrySymbols(o *evidencetools.Observation) []string {
	if o == nil || o.ToolStatus != evidencetools.StatusOK {
		return nil
	}
	data, ok := o.Data.(map[string]any)
	if !ok {
		return nil
	}
	sites, ok := data["call_sites"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, s := range sites {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := m["callee"].(string); ok && c != "" {
			if i := strings.LastIndex(c, "."); i > 0 {
				out = append(out, c[i+1:])
			}
		}
		if len(out) >= 8 {
			break
		}
	}
	return dedupe(out)
}

func callSitesOf(o *evidencetools.Observation, max int) []domain.CallSite {
	if o == nil || o.ToolStatus != evidencetools.StatusOK {
		return nil
	}
	data, ok := o.Data.(map[string]any)
	if !ok {
		return nil
	}
	var list []any
	for _, key := range []string{"call_sites", "site", "declaration", "references", "dispatch_sites"} {
		if v, ok := data[key]; ok {
			if arr, ok := v.([]any); ok {
				list = append(list, arr...)
			} else if v != nil {
				list = append(list, v)
			}
		}
	}
	var out []domain.CallSite
	for _, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		var cs domain.CallSite
		if f, ok := m["file"].(string); ok {
			cs.File = f
		}
		if l, ok := m["line"].(float64); ok {
			cs.Line = int(l)
		}
		if c, ok := m["column"].(float64); ok {
			cs.Column = int(c)
		}
		// Only fully-qualified positions bind to call-site tools: a record
		// without a column cannot be verified as the call expression's own
		// position and must not reach trace/find_validations/guard checks.
		if cs.File == "" || cs.Line == 0 || cs.Column <= 0 {
			continue
		}
		out = append(out, cs)
		if len(out) >= max {
			break
		}
	}
	return out
}

func entrypointCount(o *evidencetools.Observation) (int, bool) {
	if o == nil || o.ToolStatus != evidencetools.StatusOK {
		return 0, false
	}
	if data, ok := o.Data.(map[string]any); ok {
		if c, ok := data["count"].(float64); ok {
			return int(c), true
		}
	}
	return 0, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// goModuleCandidates scans free text for Go-module-path-like tokens:
// domain.prefixed slash paths capped at two segments (where module paths
// end), with a fallback when the cap lands on a `.go` file (e.g.
// golang.org/x/net/http2/server.go -> golang.org/x/net). Tokens that are
// file paths inside the snapshot are excluded.
func goModuleCandidates(text, snapshotRoot string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range moduleTokenRe.FindAllString(text, -1) {
		if raw == "" {
			continue
		}
		// cap at 3 segments (host + 2 path elements)
		parts := strings.Split(raw, "/")
		capped := raw
		if len(parts) > 3 {
			capped = strings.Join(parts[:3], "/")
		}
		if strings.HasSuffix(parts[len(parts)-1], ".go") && len(parts) > 3 {
			// trailing .go file -> the module is the 3-segment prefix
			capped = strings.Join(parts[:3], "/")
		}
		if isModuleFileToken(capped) {
			continue
		}
		if seen[capped] {
			continue
		}
		seen[capped] = true
		// file path inside the snapshot -> not a module token
		if snapshotRoot != "" {
			if st, err := os.Stat(filepath.Join(snapshotRoot, capped)); err == nil && !st.IsDir() {
				continue
			}
			if st, err := os.Stat(filepath.Join(snapshotRoot, raw)); err == nil && !st.IsDir() {
				continue
			}
		}
		out = append(out, capped)
	}
	return out
}

// moduleTokenRe matches domain-ish module paths: host.tld/path/...
var moduleTokenRe = regexp.MustCompile(`\b[a-z0-9.-]+\.[a-z]{2,}/[A-Za-z0-9._/~-]+`)

// isModuleFileToken reports whether a token is a plain file name or a
// file-pair reference rather than a module path: the well-known Go
// bookkeeping files (go.mod, go.sum, go.work — including the
// "go.mod/go.sum" pair form) and tokens whose last segment carries a
// document/source file extension. A token like this can never name a
// dependency module.
var moduleFileNameRe = regexp.MustCompile(`(?i)^(?:go\.(?:mod|sum|work)|readme[^/]*|changelog[^/]*|license[^/]*|notice[^/]*|authors[^/]*)$`)
var moduleFileExtRe = regexp.MustCompile(`(?i)\.(?:mod|sum|work|md|markdown|rst|txt|json|yaml|yml|toml|cfg|conf|ini|xml|csv|proto|lock|log|sh|py|js|ts|html|css|png|jpg|jpeg|gif|svg|pdf|zip|tar|gz|bz2|xz|patch|diff|golden|bin|dat|so|dll|dylib|a|exe|test)$`)

func isModuleFileToken(capped string) bool {
	for _, seg := range strings.Split(capped, "/") {
		if moduleFileNameRe.MatchString(seg) {
			return true
		}
	}
	parts := strings.Split(capped, "/")
	return moduleFileExtRe.MatchString(parts[len(parts)-1])
}

// graphModulePaths extracts the module paths from a get_dependency_graph
// payload ({modules:[{path:...}]}).
func graphModulePaths(data any) []string {
	m, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	mods, ok := m["modules"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, mv := range mods {
		if mm, ok := mv.(map[string]any); ok {
			if p, ok := mm["path"].(string); ok && p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}
