package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/davniy/izyan/internal/llm"
	"github.com/davniy/izyan/internal/productb/affected"
	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/productb/repository"
	"github.com/davniy/izyan/internal/productb/vulnerability"
	"github.com/davniy/izyan/internal/toolchain"
)

// IntakeRecordSchemaVersion identifies intake.json, the preserved transport
// record artifact of a --ticket run.
const IntakeRecordSchemaVersion = "intake-record.v1"

// Stage0DocumentSchemaVersion identifies stage0.json, the Stage 0 resolution
// summary artifact (source/ref/materialization/advisory/toolchain identity).
const Stage0DocumentSchemaVersion = "stage0.v1"

// IntakeFindingID derives the deterministic finding_id of a generic intake
// record. A ticket carries no tracker key, so identity comes from the record
// itself: the record index disambiguates identical documents inside one
// batch, and the ticket hash binds the id to the verbatim bytes. The first
// vulnerability id — advisory-provided or text-extracted — prefixes it for
// readability; it is cosmetic only, the hash carries identity.
func IntakeFindingID(raw RawIntake) string {
	slug := "record"
	if ids := extractIntakeVulnIDs(string(raw.Raw)); len(ids) > 0 {
		if s := normalizeMatchID(ids[0]); s != "" {
			slug = s
		}
	}
	return fmt.Sprintf("intake-%d-%s-%.12s", raw.RecordIndex, slug, raw.TicketHash)
}

// Stage0Input carries one generic intake record plus everything Stage 0 may
// consult: the validated site config, the admitted catalog, the LLM client
// (proposals only — never decisions) and the injectable materializer,
// Go tool and clock. FreezeDir is where selected advisory documents are
// immutably stored and (by default) where the frozen lane reads from;
// FrozenDir may name a pre-existing store prepared by an earlier run.
// OSVBaseURL overrides the OSV API endpoint; it is dialed only when freeze
// is off and allowed_domains admits it. CloneRoot bounds where remote
// sources are cloned (process temp dir and snapshot.root otherwise).
type Stage0Input struct {
	Raw          RawIntake
	Config       SiteConfig
	Catalog      Catalog
	ChatClient   ChatClient
	Materializer Materializer
	GoTool       affected.GoTool
	FreezeDir    string
	FrozenDir    string
	OSVBaseURL   string
	CloneRoot    string
	Now          func() time.Time
	// Investigation is the operator-supplied captured material set. Stage 0
	// adds the selected frozen advisory document to it, so the agent can
	// read exactly what this run selected rather than a remembered
	// vulnerability.
	Investigation InvestigationInputs
}

// Stage0Result is the complete Stage 0 outcome for one intake record: the
// normalized finding the downstream pipeline consumes, the validated intake
// proposal, the resolved source/ref/snapshot, the collected materials, the
// frozen advisory identity and the provisioned toolchain. On a technical
// error ResolveStage0 returns the partially filled result so the caller can
// still persist the raw record, the transcript and the audit events into
// the finding's error channel — nothing here ever turns a failure into a
// semantic verdict.
type Stage0Result struct {
	Raw              RawIntake
	Input            FindingInput
	Proposal         IntakeProposal
	Validation       IntakeValidation
	CatalogEntry     CatalogEntry
	CandidateRefs    []RefCandidate
	SelectedRef      RefCandidate
	RefResolution    RefResolution
	Source           MaterializedSource
	Snapshot         SnapshotManifest
	Materials        MaterialSet
	Advisory         vulnerability.FrozenAdvisory
	Resolution       *AdvisoryResolution
	PackageCheck     PackageCheckResult
	ReleaseToolchain ReleaseToolchainFact
	Toolchain        toolchain.Toolchain
	// Investigation is the complete captured material set this resolution
	// exposes: the supplied records/fixes plus the selected frozen advisory
	// document. Raw bytes stay in memory and are archived by the writer.
	Investigation InvestigationInputs
	// BuildTarget is the single product build selection this resolution
	// identified from the supplied input. Nil means no product build was
	// identified; the analyzer host is then only the analysis platform.
	BuildTarget *domain.ProductTarget
	Limitations []string
	// ConfigHash is the resolved triage-site hash that governed this
	// resolution — provenance for stage0.json and the audit trail.
	ConfigHash string
	// Events are the Stage 0 audit events in emission order; the artifact
	// writer stamps run id and timestamps when they reach events.jsonl.
	Events []AuditEvent
	// Transcript preserves the verbatim Stage 0 LLM exchanges (intake
	// extraction, ref selection incl. feedback) so raw-agent.json records
	// every model interaction of the run.
	Transcript []llm.ChatMessage
}

// ResolveStage0 runs the deterministic spine of Stage 0 (spec §4): LLM
// intake extraction → deterministic field validation → bounded catalog
// source resolution → ref enumeration → bounded LLM ref selection with
// deterministic fallback → non-mutating materialization → snapshot →
// advisory freeze → package/version fact check → release toolchain
// provisioning. The LLM may only propose; every selection is re-checked
// against the catalog, the bounded ref list and the release policy, and a
// current checkout or HEAD is never silently substituted for a requested
// ref. A technical failure returns the partial result plus the error — the
// caller turns it into the finding's error channel (exit 2), never a
// recommendation.
func ResolveStage0(ctx context.Context, in Stage0Input) (Stage0Result, error) {
	res := Stage0Result{
		Raw:           in.Raw,
		ConfigHash:    in.Config.ResolvedHash,
		Investigation: in.Investigation,
		Source:        MaterializedSource{Cleanup: func() error { return nil }},
	}
	if res.ConfigHash == "" {
		res.ConfigHash = siteConfigHash(in.Config)
	}
	emit := func(ev AuditEvent) { res.Events = append(res.Events, ev) }
	fail := func(format string, args ...any) (Stage0Result, error) {
		err := fmt.Errorf(format, args...)
		emit(AuditEvent{Type: AuditEventError, Status: "error", Scope: "stage0",
			Limitations: []string{shortErr(err.Error())}})
		return res, err
	}
	if len(in.Raw.Raw) == 0 {
		return fail("empty intake record")
	}

	// 1. LLM intake extraction: proposal only, never decisions.
	proposal, transcript, err := ExtractIntakeProposal(ctx, in.ChatClient, in.Raw)
	res.Transcript = append(res.Transcript, transcript...)
	if err != nil {
		emit(IntakeAuditEvent(in.Raw, IntakeProposal{}, IntakeValidation{}, "error"))
		return fail("intake extraction: %w", err)
	}
	res.Proposal = proposal

	// 2. Deterministic anti-hallucination validation (§4.2). Advisory ids
	// the raw record itself supplies (embedded document, advisory fields)
	// confirm ids the way a frozen advisory would; everything else needs
	// the text or a later advisory resolution.
	advisoryIDs := advisoryIDsFromIntake(in.Raw)
	catalog := in.Catalog
	if len(catalog.Entries) == 0 {
		catalog = in.Config.Catalog()
	}
	res.Validation = ValidateIntakeProposal(in.Raw, proposal, advisoryIDs, catalog)
	res.Limitations = append(res.Limitations, res.Validation.Limitations...)
	if len(res.Validation.Errors) > 0 {
		emit(IntakeAuditEvent(in.Raw, proposal, res.Validation, "error"))
		return fail("intake validation: %s", strings.Join(res.Validation.Errors, "; "))
	}
	emit(IntakeAuditEvent(in.Raw, proposal, res.Validation, "ok"))
	// The ticket is an admitted source of release Go version, but the LLM's
	// extraction is not: only a value confirmed in the raw ticket may become
	// a product/toolchain fact. Keep the original proposal for the audit trail.
	admittedProposal := proposal
	if fv, ok := res.Validation.Field("go_version"); !ok || fv.Status != IntakeValid {
		admittedProposal.GoVersion = ""
	}

	// 3. Vulnerability ids: proposal claims first; when the LLM proposed
	// none, the deterministic text/embedded scan supplies the admission the
	// spec reserves for "advisory id given as a separate valid input".
	vulnIDs := proposal.VulnerabilityIDs
	if !idConfirmed(res.Validation) && len(advisoryIDs) == 0 {
		return fail("vulnerability id is unverified and no separate advisory identifier is available")
	}
	if len(vulnIDs) == 0 {
		vulnIDs = extractIntakeVulnIDs(string(in.Raw.Raw))
	}
	if len(vulnIDs) == 0 {
		return fail("no vulnerability id in the intake document")
	}

	// 4. Source resolution: the intake picks a repository catalog entry —
	// never a fabricated path. Component and product names, then explicit
	// source hints, are matched with the catalog's deterministic
	// precedence; artifact sources cannot serve as source repositories.
	entry, mstatus, err := repoCatalog(in).MatchComponent(proposal)
	if err != nil {
		emit(SourceAuditEvent(CatalogEntry{}, "error"))
		return fail("source resolution: %w", err)
	}
	if mstatus != IntakeValid {
		reason := "no catalog repository matched the intake"
		if mstatus == IntakeConflicting {
			reason = "catalog match is ambiguous (CONFLICTING): several entries claim the intake"
		} else if proposal.Component+proposal.Product == "" && len(proposal.SourceHints) == 0 {
			reason = "intake names no component, product or source and the catalog cannot be assumed"
		}
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("source selection %s: %s", strings.ToLower(string(mstatus)), reason))
		emit(SourceAuditEvent(CatalogEntry{}, strings.ToLower(string(mstatus))))
		return fail("source resolution: %s", reason)
	}
	res.CatalogEntry = entry
	emit(SourceAuditEvent(entry, "ok"))

	// 5. Ref enumeration and bounded selection. kind:local sources are used
	// in place and may not even be git repositories; git sources enumerate
	// from the local repository — a remote locator is probe-cloned first so
	// the bounded list is real before the LLM sees it.
	policy := ReleasePolicy{}
	if entry.ReleasePolicy != "" {
		policy = in.Config.Resolution.ReleasePolicies[entry.ReleasePolicy]
	}
	requested, requestedSource, requestedLims := requestedRelease(proposal)
	res.Limitations = append(res.Limitations, requestedLims...)
	cands, repoPath, probeCleanup, lims, err := enumerateStage0Refs(ctx, in, entry, policy, requested)
	if probeCleanup != nil {
		defer probeCleanup()
	}
	res.Limitations = append(res.Limitations, lims...)
	if err != nil {
		emit(AuditEvent{Type: AuditEventRefResolution, Status: "error",
			Limitations: []string{shortErr(err.Error())}})
		return fail("ref enumeration: %w", err)
	}
	res.CandidateRefs = cands
	if len(cands) == 0 && strings.TrimSpace(requested) != "" {
		return fail("ref selection: no admissible candidate for requested ref %q", requested)
	}
	var selRes RefResolution
	if len(cands) == 0 {
		selRes = RefResolution{RequestedRelease: requested, RequestedSource: requestedSource}
		emit(AuditEvent{Type: AuditEventRefResolution, Status: "skipped",
			Limitations: lims})
	} else {
		var refTranscript []llm.ChatMessage
		selRes, refTranscript, err = SelectRef(ctx, in.ChatClient, RefSelectionRequest{
			Entry:             entry,
			Policy:            policy,
			RequestedRelease:  requested,
			RequestedSource:   requestedSource,
			Candidates:        cands,
			RepoPath:          repoPath,
			MaxFeedbackPasses: in.Config.Resolution.MaxFeedbackPasses,
		})
		res.Transcript = append(res.Transcript, refTranscript...)
		if err != nil {
			emit(RefAuditEvent(selRes, "", time.Time{}))
			return fail("ref selection: %w", err)
		}
		res.RefResolution = selRes
		if selRes.SelectionProvenance == RefProvenanceFallback && selRes.FallbackReason != "" {
			res.Limitations = append(res.Limitations,
				"ref selected by deterministic fallback: "+shortErr(selRes.FallbackReason))
		}
		if len(lims) > 0 {
			selRes.CandidateTruncation = strings.Join(lims, "; ")
			res.RefResolution = selRes
		}
		emit(RefAuditEvent(selRes, "", time.Time{}))
	}

	cand, ok := candLookup(res.CandidateRefs, selRes.SelectedID)
	if !ok && selRes.SelectedID != "" {
		cand = RefCandidate{
			ID: selRes.SelectedID, Name: selRes.SelectedRef, Kind: RefCommit,
			Commit: selRes.ResolvedCommit, Source: entry.ID,
			PolicyScore: refPolicyScore(RefCommit),
		}
	}
	res.SelectedRef = cand
	materializeEntry := entry
	if entry.Kind == "local" && strings.TrimSpace(cand.Name) != "" {
		// The generic Stage 0 contract never mutates a configured checkout:
		// present a local git source as an isolated worktree to the existing
		// materializer while retaining the catalog identity.
		materializeEntry.Kind = "git"
		materializeEntry.Locator = entry.Root
		materializeEntry.Root = ""
	}
	matPolicy := MaterializationPolicy{
		RequirePinnedCommit: policy.RequireResolvedCommit,
		CloneRoot:           firstNonEmpty(in.CloneRoot, in.Config.Snapshot.Root),
	}
	src, err := in.Materializer.Materialize(ctx, materializeEntry, cand, matPolicy)
	res.Source = src
	if err != nil {
		emit(MaterializationAuditEvent(src.Metadata, "error"))
		return fail("materialization: %w", err)
	}
	res.Limitations = append(res.Limitations, src.Metadata.Limitations...)
	emit(MaterializationAuditEvent(src.Metadata, "ok"))

	// The normalized finding is synthesized only after the source root
	// exists: Target.Repository pins the materialized root, Revision the
	// selected ref, Toolchain the intake's claimed release toolchain.
	res.Input = synthesizeFinding(in.Raw, admittedProposal, vulnIDs, entry, cand, src.Root)
	manifest, err := (LocalSnapshotBuilder{}).BuildMaterialized(ctx, res.Input, src)
	if err != nil {
		return fail("snapshot: %w", err)
	}
	res.Snapshot = manifest

	// The product build is resolved once, before any evidence session is
	// constructed: the finding's declared target/build and the supplied
	// investigation build input must agree, and an identified target is
	// carried by every attempt. No target stays absent; the analysis host
	// never becomes its substitute.
	buildTarget, buildErr := ResolveBuildTarget(res.Input, in.Investigation, manifest)
	if buildErr != nil {
		return fail("build target: %w", buildErr)
	}
	res.BuildTarget = buildTarget
	res.Investigation.BuildTarget = cloneBuildTarget(buildTarget)
	if buildTarget != nil {
		res.Input.Finding.Target.Build = cloneBuildTarget(buildTarget)
	} else {
		res.Limitations = append(res.Limitations, BuildTargetAbsentLimitation)
	}

	// 7. Advisory freeze (§5.2): configured lane priority, hash-pinned
	// copy. With freeze:true no remote dial ever happens.
	freezeDir := in.FreezeDir
	if freezeDir == "" && in.Config.Snapshot.Root != "" {
		freezeDir = filepath.Join(in.Config.Snapshot.Root, "advisory")
	}
	advProposal := proposal
	advProposal.VulnerabilityIDs = vulnIDs
	advisory, err := ResolveAdvisory(ctx, in.Config, AdvisoryInput{
		Proposal:   advProposal,
		Raw:        &res.Raw,
		FrozenDir:  in.FrozenDir,
		OSVBaseURL: in.OSVBaseURL,
	}, freezeDir)
	if err != nil {
		emit(AdvisoryAuditEvent(nil, "error"))
		return fail("advisory resolution: %w", err)
	}
	res.Resolution = advisory
	res.Advisory = advisory.Record
	res.Limitations = append(res.Limitations, advisory.Limitations...)
	// The selected frozen document is part of the captured material set:
	// the scripted investigator reads the exact bytes this run resolved,
	// not a paraphrase. A tampered frozen copy fails closed; an unfrozen
	// source that no longer exists is a recorded limitation.
	if rec, included, lim, cerr := capturedFrozenRecord(res.Advisory); cerr != nil {
		return fail("captured advisory: %v", cerr)
	} else if included {
		res.Investigation, cerr = res.Investigation.WithRecord(rec)
		if cerr != nil {
			return fail("captured advisory: %v", cerr)
		}
	} else if lim != "" {
		res.Limitations = append(res.Limitations, lim)
	}
	emit(AdvisoryAuditEvent(advisory, "ok"))
	// A stub record means every lane missed: the run may continue only when
	// deterministic validation confirmed the id in the raw text — an
	// unconfirmed id without an advisory is an error, never an invented
	// finding.
	if advisory.Record.Source == "" && !idConfirmed(res.Validation) {
		return fail("no advisory resolved for %s and the vulnerability id is unconfirmed in the intake", vulnIDs[0])
	}

	// 8. Materials over the snapshot plus the package/version fact check.
	materials, err := collectMaterialsForTarget(ctx, manifest, in.Config, in.GoTool, buildTarget)
	if err != nil {
		emit(AuditEvent{Type: AuditEventMaterials, Status: "error",
			Limitations: []string{shortErr(err.Error())}})
		return fail("materials: %w", err)
	}
	res.Limitations = append(res.Limitations, materials.Limitations...)

	fact := DiscoverReleaseToolchain(ctx, admittedProposal, manifest)
	res.ReleaseToolchain = fact
	res.Limitations = append(res.Limitations, fact.Limitations...)
	materials.Toolchain = &fact
	res.Materials = materials
	emit(MaterialsAuditEvent(materials, "", time.Time{}))

	pv := ValidatePackageVersion(ctx, proposal, materials, advisory.Projection)
	res.PackageCheck = CheckPackageVersion(proposal, materials, advisory.Projection, fact.Version)
	res.Limitations = append(res.Limitations, pv.Limitations...)
	for _, e := range pv.Errors {
		res.Limitations = append(res.Limitations, "package/version check: "+e)
	}
	res.Validation.Fields = append(res.Validation.Fields, pv.Fields...)
	emit(PackageCheckAuditEvent(res.PackageCheck, "", time.Time{}))

	// 9. Provision the analysis toolchain the release evidence names; an
	// unavailable toolchain is a limitation (Mismatch), never an error.
	tc, tcLims := toolchain.Resolve(ctx, fact.Version)
	res.Toolchain = tc
	res.Limitations = append(res.Limitations, tcLims...)
	emit(ToolchainAuditEvent(fact, tc, "", time.Time{}))

	return res, nil
}

// capturedFrozenRecord reads the selected frozen advisory document into a
// captured record. A record without a readable frozen path is excluded with
// a limitation; a path whose bytes disagree with the pinned digest is
// integrity drift and fails the resolution.
func capturedFrozenRecord(rec vulnerability.FrozenAdvisory) (CapturedRecord, bool, string, error) {
	if strings.TrimSpace(rec.SHA256) == "" || (strings.TrimSpace(rec.ID) == "" && strings.TrimSpace(rec.ResolvedID) == "") {
		return CapturedRecord{}, false, "", nil
	}
	if strings.TrimSpace(rec.Path) == "" {
		return CapturedRecord{}, false, "the selected frozen advisory has no readable document path; its captured bytes are unavailable to the investigator", nil
	}
	data, err := os.ReadFile(rec.Path)
	if err != nil {
		return CapturedRecord{}, false, "the selected frozen advisory document is unreadable: " + shortErr(err.Error()), nil
	}
	captured, err := CapturedRecordFromFrozen(rec, data)
	if err != nil {
		return CapturedRecord{}, false, "", err
	}
	return captured, true, "", nil
}

// idConfirmed reports whether deterministic validation marked at least one
// vulnerability id VALID — the only way an advisory-less run may continue.
func idConfirmed(v IntakeValidation) bool {
	for _, f := range v.Fields {
		if f.Field == "vulnerability_ids" && f.Status == IntakeValid {
			return true
		}
	}
	return false
}

// requestedRelease applies deterministic precedence for ref resolution.
// Component/product versions are used when the generic release field names
// a product release rather than the repository component version.
var requestedVersionRE = regexp.MustCompile(`^[vV]?\d+(\.\d+)*([-+._][A-Za-z0-9._-]+)?$`)

// requestedRelease applies deterministic precedence while rejecting tracker
// release labels and URL-shaped ref hints. Component/product versions are
// preferred over a ref hint unless the hint is an actual local ref name.
func requestedRelease(p IntakeProposal) (string, string, []string) {
	var limitations []string
	if value := strings.TrimSpace(p.Release); value != "" {
		if requestedVersionRE.MatchString(value) {
			return value, "release", limitations
		}
		limitations = append(limitations, "requested source ignored: release is not a version")
	}
	if value := strings.TrimSpace(p.ComponentVersion); value != "" {
		if requestedVersionRE.MatchString(value) {
			return value, "component_version", limitations
		}
		limitations = append(limitations, "requested source ignored: component_version is not a version")
	}
	if value := strings.TrimSpace(p.ProductVersion); value != "" {
		if requestedVersionRE.MatchString(value) {
			return value, "product_version", limitations
		}
		limitations = append(limitations, "requested source ignored: product_version is not a version")
	}
	if value := strings.TrimSpace(p.RefHint); value != "" {
		if refLikeRequested(value) {
			return value, "ref_hint", limitations
		}
		kind := "ref"
		if strings.Contains(value, "://") {
			kind = "url"
		}
		limitations = append(limitations, "requested source ignored: ref_hint is not a "+kind)
	}
	return "", "", limitations
}

func refLikeRequested(value string) bool {
	if value == "" || len(value) > 200 || strings.ContainsAny(value, " \t\r\n") || strings.Contains(value, "://") {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.Contains(value, "\\") {
		return false
	}
	// Release refs are an explicitly supported ref namespace; arbitrary
	// slash-bearing paths are not accepted as requested refs.
	return strings.HasPrefix(value, "release/") || strings.HasPrefix(value, "refs/") || !strings.Contains(value, "/")
}

// repoCatalog restricts the admitted catalog to repository sources: an
// artifact source (nexus/http/oci/filesystem) can never materialize a
// source tree, so intake fields must not bind to it.
func repoCatalog(in Stage0Input) Catalog {
	cat := in.Catalog
	if len(cat.Entries) == 0 {
		cat = in.Config.Catalog()
	}
	var repos []CatalogEntry
	for _, e := range cat.Entries {
		if siteRepoKinds[e.Kind] {
			repos = append(repos, e)
		}
	}
	return Catalog{Entries: repos}
}

// enumerateStage0Refs builds the bounded candidate list for the matched
// entry and returns the repository path the candidates resolve against.
// kind:local non-git directories legitimately have no refs: with no
// requested release they yield an empty list and the checkout materializes
// in place — a requested release without enumerable refs is an error, since
// falling back to HEAD is forbidden. The returned cleanup removes any
// temporary enumeration state (a remote probe clone); the caller defers it
// so it outlives ref selection, which re-resolves candidates inside it.
func enumerateStage0Refs(
	ctx context.Context,
	in Stage0Input,
	entry CatalogEntry,
	policy ReleasePolicy,
	requested string,
) ([]RefCandidate, string, func(), []string, error) {
	stats := &RefEnumerationStats{}
	enum := RefEnumerator{MaxCandidates: in.Config.Resolution.MaxCandidates, RequestedRelease: requested, Stats: stats}
	repoPath := refRepoPath(entry)

	if entry.Kind == "git" && isRemoteLocator(entry.Locator) {
		// Remote git sources need a local repository before refs can be
		// enumerated: an isolated probe clone sees every fetched ref, so the
		// bounded list is real before the LLM sees it. The materialization
		// clone happens later, checked out at the pinned commit — the probe
		// is removed once selection is done and never becomes the snapshot
		// root.
		probeDir, cleanup, err := probeRemoteRepo(ctx, in, entry)
		if err != nil {
			return nil, "", nil, nil, err
		}
		probeEntry := entry
		probeEntry.Root = probeDir
		probeEntry.Locator = ""
		cands, err := enum.Enumerate(ctx, probeEntry, policy)
		if err != nil {
			cleanup()
			return nil, "", nil, nil, fmt.Errorf("source %q: %w", entry.ID, err)
		}
		if stats.Truncated > 0 {
			return cands, probeDir, cleanup, []string{fmt.Sprintf("ref candidates truncated: %d admitted refs omitted", stats.Truncated)}, nil
		}
		return cands, probeDir, cleanup, nil, nil
	}

	if repoPath == "" {
		return nil, "", nil, nil, fmt.Errorf("source %q has no repository location", entry.ID)
	}
	if _, _, herr := repository.ResolveRef(ctx, repoPath, "HEAD"); herr != nil {
		if entry.Kind == "local" && requested == "" {
			return nil, repoPath, nil, []string{
				fmt.Sprintf("source %q is not a git repository; materializing the checkout in place", entry.ID),
			}, nil
		}
		if entry.Kind == "local" {
			return nil, "", nil, nil,
				fmt.Errorf("source %q is not a git repository and the intake requests release %q", entry.ID, requested)
		}
		return nil, "", nil, nil, fmt.Errorf("ref enumeration for %q: %w", entry.ID, herr)
	}
	cands, err := enum.Enumerate(ctx, entry, policy)
	if err != nil {
		return nil, "", nil, nil, err
	}
	if stats.Truncated > 0 {
		return cands, repoPath, nil, []string{fmt.Sprintf("ref candidates truncated: %d admitted refs omitted", stats.Truncated)}, nil
	}
	return cands, repoPath, nil, nil, nil
}

// probeRemoteRepo clones a remote git source into an isolated throwaway
// directory so its refs can be enumerated. The returned cleanup removes the
// clone; the caller keeps it alive until ref selection has finished, since
// candidate commits re-resolve inside the clone.
func probeRemoteRepo(ctx context.Context, in Stage0Input, entry CatalogEntry) (string, func(), error) {
	var env []string
	if ref := strings.TrimSpace(entry.CredentialRef); ref != "" {
		if in.Materializer.Credentials == nil {
			return "", nil, fmt.Errorf("source %q requires credential %q but no credential provider is configured", entry.ID, ref)
		}
		credEnv, err := in.Materializer.Credentials(ref)
		if err != nil {
			return "", nil, fmt.Errorf("source %q: resolve credential %q: %w", entry.ID, ref, err)
		}
		env = credEnv
	}
	parent, err := cloneParentDir(firstNonEmpty(in.CloneRoot, in.Config.Snapshot.Root))
	if err != nil {
		return "", nil, fmt.Errorf("probe clone: %w", err)
	}
	dst := filepath.Join(parent, "probe")
	if _, err := repository.Clone(ctx, entry.Locator, repository.CloneOptions{
		Destination:   dst,
		CredentialEnv: env,
	}); err != nil {
		_ = os.RemoveAll(parent)
		return "", nil, fmt.Errorf("probe clone of %q: %w", entry.ID, err)
	}
	var once sync.Once
	return dst, func() { once.Do(func() { _ = os.RemoveAll(parent) }) }, nil
}

// synthesizeFinding normalizes the validated intake into the internal
// finding.v1 the downstream pipeline consumes. Only confirmed or claimed
// fields are copied: the finding id derives from the record identity, the
// vulnerability ids from proposed/validated identifiers, the component from
// the proposal, the target from the materialized root and the selected
// ref — never from a hint. The verbatim intake record lives in intake.json,
// never inside the normalized finding.
func synthesizeFinding(raw RawIntake, p IntakeProposal, vulnIDs []string, entry CatalogEntry, cand RefCandidate, root string) FindingInput {
	ids := make([]string, 0, len(vulnIDs))
	for _, id := range vulnIDs {
		if c := canonicalVulnID(id); c != "" {
			ids = append(ids, c)
		}
	}
	f := Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     IntakeFindingID(raw),
		Vulnerability: Vulnerability{IDs: ids, Summary: strings.TrimSpace(p.Summary)},
		Component: Component{
			Name:      firstNonEmpty(strings.TrimSpace(p.Component), strings.TrimSpace(p.Product), entry.ID),
			Version:   strings.TrimSpace(p.Version),
			Ecosystem: strings.TrimSpace(entry.Ecosystem),
			Package:   strings.TrimSpace(p.Package),
		},
		Target: Target{
			Repository: root,
			Revision:   strings.TrimSpace(cand.Name),
			Toolchain:  strings.TrimSpace(p.GoVersion),
		},
		Scanner: Scanner{Severity: strings.TrimSpace(p.Severity)},
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	return FindingInput{Finding: f, Raw: b, SHA256: hashBytes(b)}
}

// Stage0AgentFinding projects the agent-facing finding view: the normalized
// intake finding enriched with the resolved advisory's identity and prose.
// The advisory is the authoritative record, so its id, aliases, summary,
// description, references and severity override or extend the intake's
// claims; intake ids stay first so identity order never shifts. When the
// resolution is absent or a partial stub, the view keeps whatever the
// projection carried — it never fabricates fields. Raw and SHA256 are
// preserved untouched: input.json stays the intake-normalized record and
// the view exists only for the agent surface (prompt + lookup_advisory).
// The merge is idempotent, so replay can re-apply it to a stored input.
func Stage0AgentFinding(in FindingInput, advisory *domain.Vulnerability) FindingInput {
	out := in
	v := out.Finding.Vulnerability
	if advisory != nil {
		// The resolved advisory's own id leads the list: it is the
		// authoritative identity of this finding's vulnerability, it names
		// the deterministic mandatory condition the agent must cite, and the
		// intake-declared ids and aliases follow as equally valid aliases.
		ids := make([]string, 0, len(v.IDs)+len(advisory.Aliases)+1)
		seen := map[string]bool{}
		if c := canonicalVulnID(advisory.ID); c != "" {
			seen[c] = true
			ids = append(ids, c)
		}
		for _, id := range append(append([]string(nil), advisory.Aliases...), v.IDs...) {
			if c := canonicalVulnID(id); c != "" && !seen[c] {
				seen[c] = true
				ids = append(ids, c)
			}
		}
		v.IDs = ids
		if s := strings.TrimSpace(advisory.Summary); s != "" {
			v.Summary = s
		}
		if s := strings.TrimSpace(advisory.Description); s != "" {
			v.Description = s
		}
		refSeen := map[string]bool{}
		for _, u := range v.References {
			refSeen[u] = true
		}
		for _, ref := range advisory.References {
			if u := strings.TrimSpace(ref.URL); u != "" && !refSeen[u] {
				refSeen[u] = true
				v.References = append(v.References, u)
			}
		}
		if s := strings.TrimSpace(advisory.BaseSeverity); s != "" {
			v.BaseSeverity = s
		}
		if advisory.BaseScore > 0 {
			v.BaseScore = advisory.BaseScore
		}
	}
	out.Finding.Vulnerability = v
	return out
}

// AgentFinding returns the finding view the bounded agent sees — the
// normalized intake finding plus the resolved advisory record.
func (res Stage0Result) AgentFinding() FindingInput {
	return Stage0AgentFinding(res.Input, res.AdvisoryVulnerability())
}

// AdvisoryVulnerability returns the resolved advisory document, nil when the
// advisory resolution never ran or produced no record.
func (res Stage0Result) AdvisoryVulnerability() *domain.Vulnerability {
	if res.Resolution == nil {
		return nil
	}
	return res.Resolution.Vulnerability
}

// AdvisoryProjection returns the resolved advisory's check projection —
// module plus affected/fixed version ranges — for the lookup_advisory tool.
func (res Stage0Result) AdvisoryProjection() *AdvisoryProjection {
	if res.Resolution == nil {
		return nil
	}
	return &res.Resolution.Projection
}

func advisoryIDsFromIntake(raw RawIntake) []string {
	var ids []string
	if doc := embeddedAdvisoryDoc(raw.Raw); len(doc) > 0 {
		var probe struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
		}
		if json.Unmarshal(doc, &probe) == nil {
			if isVulnIDFormat(probe.ID) {
				ids = append(ids, probe.ID)
			}
			for _, a := range probe.Aliases {
				if isVulnIDFormat(a) {
					ids = append(ids, a)
				}
			}
		}
	}
	if raw.Object != nil {
		for _, k := range []string{"vulnerability", "cve", "vuln", "advisory_id"} {
			if s := intakeString(raw.Object, k); isVulnIDFormat(s) {
				ids = append(ids, s)
			}
		}
	}
	return ids
}
