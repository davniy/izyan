// Package states implements the workflow StateHandlers for the deterministic
// slices of the analyzer. States whose automation belongs to later milestones
// terminate honestly at INCONCLUSIVE instead of pretending analysis happened.
package states

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/cveanalysis"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/exploit"
	"github.com/davniy/izyan/internal/exposure"
	"github.com/davniy/izyan/internal/finding"
	"github.com/davniy/izyan/internal/fixbinding"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/justification"
	"github.com/davniy/izyan/internal/llm"
	"github.com/davniy/izyan/internal/report"
	"github.com/davniy/izyan/internal/repository"
	"github.com/davniy/izyan/internal/review"
	"github.com/davniy/izyan/internal/risk"
	"github.com/davniy/izyan/internal/rootcause"
	"github.com/davniy/izyan/internal/toolaudit"
	"github.com/davniy/izyan/internal/tracker"
	"github.com/davniy/izyan/internal/vulnerability"
	"github.com/davniy/izyan/internal/workflow"
)

type Created struct{}

func (Created) State() domain.WorkflowState { return domain.StateCreated }

func (Created) Run(context.Context, *domain.AnalysisCase) (workflow.Transition, error) {
	return workflow.Transition{Next: domain.StateSnapshotProduct, Reason: "case created"}, nil
}

type SnapshotProduct struct {
	Repo    repository.Snapshotter
	Path    string
	Options repository.SnapshotOptions
	// Source is the case's source index. The resolved build context is
	// bound to it here — before root-cause resolution, affected probes or
	// evidence collection can load packages — so every later query observes
	// one build. A different context after a load fails closed.
	Source *goanalysis.Index
	// Snapshot is a snapshot already resolved by the caller (scan mode
	// resolves once for all cases). It is used instead of re-running the
	// probe; its repository identity must match Path.
	Snapshot *domain.ProductSnapshot
}

func (SnapshotProduct) State() domain.WorkflowState { return domain.StateSnapshotProduct }

func (h SnapshotProduct) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	snap, err := h.resolve(ctx)
	if err != nil {
		return workflow.Transition{
			Next:   domain.StateFailed,
			Reason: fmt.Sprintf("product snapshot failed (commit is mandatory for a verdict): %v", err),
		}, nil
	}
	c.Product = snap
	// Bind the resolved build before any package load. Root-cause
	// resolution is the first state that consumes the source index, so
	// binding in CollectEvidence (later) would leave a loaded index
	// already describing a different build context.
	if h.Source != nil {
		if err := h.Source.BindBuild(snap); err != nil {
			return workflow.Transition{
				Next:   domain.StateFailed,
				Reason: fmt.Sprintf("product build context binding failed: %v", err),
			}, nil
		}
	}
	c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
		Quality: domain.QualityAuthoritative,
		Source:  "product snapshot",
		Content: fmt.Sprintf("go_version=%q goos=%s goarch=%s release_toolchain=%q go_mod=%q build_tags=%v",
			snap.GoVersion, snap.GOOS, snap.GOARCH, snap.ReleaseGoVersion, snap.GoModDirective, snap.BuildTags),
	})
	// Per-case build provenance (including a scan snapshot reused across
	// cases): the exact selection every probe must share.
	build := domain.EffectiveBuildContext(snap)
	targetSource := domain.ProductTargetSourceHostDefault
	if snap.Target != nil {
		targetSource = snap.Target.Source
	}
	c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
		Quality: domain.QualityAuthoritative,
		Source:  "product build context",
		Content: fmt.Sprintf("goos=%s goarch=%s build_tags=%v cgo=%v vendor=%v workspace=%q goflags=%q target=%s replace_directives=%d",
			build.GOOS, build.GOARCH, build.BuildTags, build.CGOEnabled, build.VendorMode,
			build.GoWorkFile, build.GoFlags, targetSource, len(build.ReplaceDirectives)),
	})
	if snap.BinaryPath != "" {
		if info, err := repository.BinaryBuildInfo(ctx, snap.BinaryPath); err == nil {
			c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
				Quality: domain.QualityAuthoritative,
				Source:  "binary build info",
				File:    snap.BinaryPath,
				Tool:    "go",
				Command: "go version -m " + snap.BinaryPath,
				Content: info,
			})
		} else {
			c.EvidenceGraph.AddLimitation("binary build info unavailable: " + err.Error())
		}
		// The target-only gap is independent of the measured release
		// toolchain: it never invalidates a toolchain version already read
		// from the binary, and it never grounds a product target.
		if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceArtifactBuildInfo {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"plain --binary build-target extraction gap: the binary's embedded settings did not form a complete digest-bound target; target provenance remains %s (the release-toolchain channel is recorded separately)",
				targetSource))
		}
	}
	return workflow.Transition{Next: domain.StateResolveVulnerability, Reason: "product snapshot captured"}, nil
}

// resolve returns the case's snapshot: a caller-resolved scan snapshot when
// present (identity-checked), else a fresh probe.
func (h SnapshotProduct) resolve(ctx context.Context) (domain.ProductSnapshot, error) {
	if h.Snapshot == nil {
		if h.Repo == nil {
			return domain.ProductSnapshot{}, fmt.Errorf("no snapshotter configured")
		}
		return h.Repo.Snapshot(ctx, h.Path, h.Options)
	}
	snap := *h.Snapshot
	if h.Path != "" && snap.Repository != "" && !sameRepository(snap.Repository, h.Path) {
		return domain.ProductSnapshot{}, fmt.Errorf(
			"pre-resolved snapshot repository %q does not identify the case repository %q", snap.Repository, h.Path)
	}
	return snap, nil
}

// sameRepository compares two repository paths canonically: absolute,
// cleaned, and symlink-resolved when possible.
func sameRepository(a, b string) bool {
	canon := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			p = resolved
		}
		return filepath.Clean(p)
	}
	return canon(a) == canon(b)
}

type ResolveVulnerability struct {
	Source vulnerability.Source
	ID     string
	// Exact requires loading the record's exact bytes and pinning them, so the
	// primary assessment runs from its own document. Sources without
	// LoadExact fall back to the legacy identity-only load with a limitation.
	Exact bool
	// Next is the state after resolution. Empty keeps the legacy
	// CHECK_AFFECTED transition; request orchestration sets DISCOVER_RECORDS.
	Next domain.WorkflowState
	// Intake receives the exact primary record for request discovery and
	// attribution. It is optional and runtime-only.
	Intake *RecordIntake
}

func (ResolveVulnerability) State() domain.WorkflowState { return domain.StateResolveVulnerability }

// exactLoader is the optional exact-bytes capability of a vulnerability
// source. FileSource implements it; an identity-only source does not.
type exactLoader interface {
	LoadExact(ctx context.Context, recordID string) (vulnerability.LoadedRecord, error)
}

func (h ResolveVulnerability) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	c.RequestedID = h.ID
	next := h.Next
	if next == "" {
		next = domain.StateCheckAffected
	}
	if h.Exact {
		if loader, ok := h.Source.(exactLoader); ok {
			record, err := loader.LoadExact(ctx, h.ID)
			if err != nil {
				return h.unresolved(c, next, err), nil
			}
			c.Vulnerability = *record.Vuln
			pin := record.Pin
			c.RecordPin = &pin
			c.AdvisoryRecord = advisoryRecordCapture(record)
			if h.Intake != nil {
				h.Intake.Set(record)
			}
			return workflow.Transition{Next: next, Reason: "exact vulnerability record pinned"}, nil
		}
		c.EvidenceGraph.AddLimitation(
			"exact record bytes are unavailable from the configured source; the primary assessment is identity-only")
	}
	v, err := h.Source.Get(ctx, h.ID)
	if err != nil {
		return h.unresolved(c, next, err), nil
	}
	c.Vulnerability = *v
	return workflow.Transition{Next: next, Reason: "vulnerability normalized"}, nil
}

// advisoryRecordCapture persists the complete advisory bytes one record-level
// assessment was derived from. An identity-only load carries no bytes and
// records no capture: the case must not claim exact document inputs it never
// read.
func advisoryRecordCapture(record vulnerability.LoadedRecord) *domain.AdvisoryRecordCapture {
	if len(record.Raw) == 0 || record.Vuln == nil {
		return nil
	}
	return &domain.AdvisoryRecordCapture{
		Pin:   record.Pin,
		Bytes: append([]byte(nil), record.Raw...),
	}
}

// unresolved records a typed input-resolution cause. A request-orchestrated
// run continues to discovery so available CVE candidates are still assessed;
// a legacy single-record run keeps its historical FAILED terminal.
func (h ResolveVulnerability) unresolved(c *domain.AnalysisCase, next domain.WorkflowState, err error) workflow.Transition {
	gap := analysisGap(domain.GapOwnerInput, domain.GapInputResolutionFailed,
		domain.ObligationDiscovery, assessmentIDFor(c), "vulnerability resolution failed: "+err.Error())
	c.AnalysisGaps = appendGap(c.AnalysisGaps, gap)
	c.EvidenceGraph.AddLimitation(gap.Message)
	if h.Next == "" {
		return workflow.Transition{
			Next:   domain.StateFailed,
			Reason: fmt.Sprintf("vulnerability resolution failed: %v", err),
		}
	}
	return workflow.Transition{
		Next:   next,
		Reason: "primary resolution failed; request discovery continues",
	}
}

// ImplementationAxisFunc evaluates the affected chain's
// implementation-presence dimension after the deterministic chain has
// resolved. The classic workflow has no admitted proposal channel, so the
// hook stays nil there; a caller that does (the research lane) supplies
// affected.EvaluateImplementationAxis with its admitted proposals. The
// returned Affected result is the finalized chain (package/build facts
// established for the proposal's package, axis, target provenance,
// assumption ids, limitations); Evidence must be recorded by this state.
type ImplementationAxisFunc func(ctx context.Context, c *domain.AnalysisCase, res domain.AffectedResult) affected.ImplementationAxisResult

type CheckAffected struct {
	Resolver affected.Resolver
	// ImplementationAxis is optional. It is the ONLY route by which a
	// non-authoritative implementation-locus proposal can influence the
	// implementation axis; the returned ClaimResult is already the
	// deterministic verifier's outcome.
	ImplementationAxis ImplementationAxisFunc
}

func (CheckAffected) State() domain.WorkflowState { return domain.StateCheckAffected }

func (h CheckAffected) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	res, ev, err := h.Resolver.Resolve(ctx, c.Vulnerability, c.Product)
	if err != nil {
		return workflow.Transition{}, err
	}
	// The implementation-presence axis runs after the deterministic
	// chain and after proposal admission (the callback owns admission).
	// It can only narrow the chain to FALSE with a deterministic
	// verifier outcome; a nil callback leaves the axis UNKNOWN.
	if h.ImplementationAxis != nil {
		// The callback may mutate anything it is handed. Scope is the
		// finding-level closure authority resolved from the advisory
		// record, so it crosses the callback boundary as a deep copy and
		// the authoritative value is restored afterwards — a callback
		// cannot narrow the inventory, rewrite the record identity or
		// change the closure decision.
		scope := res.Scope
		res.Scope = scope.Clone()
		axis := h.ImplementationAxis(ctx, c, res)
		res = axis.Affected
		res.Scope = scope
		res.VulnerableImplementationPresent = axis.Present
		for _, e := range axis.Evidence {
			id := c.EvidenceGraph.AddEvidence(e)
			res.EvidenceIDs = append(res.EvidenceIDs, id)
		}
		if len(axis.AssumptionIDs) > 0 {
			res.AssumptionIDs = mergeUniqueStrings(res.AssumptionIDs, axis.AssumptionIDs)
		}
		// axis.Affected already carries the axis limitations; appending
		// axis.Limitations again would duplicate them.
	}
	c.Affected = &res
	for _, e := range ev {
		id := c.EvidenceGraph.AddEvidence(e)
		_ = id
	}
	// Multi-module advisories: narrow the vulnerability to the entries the
	// product actually links. Symbols and packages union across EVERY
	// selected module — a vulnerable path in a second imported entry must
	// reach downstream analysis; version fields follow the first selected
	// entry (the report's remediation view is per-module limited anyway).
	if len(res.SelectedModules) > 0 {
		byModule := map[string]*domain.AffectedModule{}
		for i := range c.Vulnerability.AffectedModules {
			am := &c.Vulnerability.AffectedModules[i]
			byModule[am.Module] = am
		}
		var pkgs []domain.AffectedPackage
		var syms []domain.SymbolRef
		seenPkg := map[string]bool{}
		seenSym := map[string]bool{}
		var first *domain.AffectedModule
		for _, m := range res.SelectedModules {
			am := byModule[m]
			if am == nil {
				continue
			}
			if first == nil {
				first = am
			}
			for _, p := range am.AffectedPackages {
				if !seenPkg[p.Path] {
					seenPkg[p.Path] = true
					pkgs = append(pkgs, p)
				}
			}
			for _, s := range am.AffectedSymbols {
				k := s.Package + "." + s.Symbol
				if !seenSym[k] {
					seenSym[k] = true
					syms = append(syms, s)
				}
			}
		}
		if first != nil && (len(res.SelectedModules) > 1 || first.Module != c.Vulnerability.Module) {
			c.Vulnerability.Module = first.Module
			c.Vulnerability.AffectedVersions = first.AffectedVersions
			c.Vulnerability.FixedVersions = first.FixedVersions
			c.Vulnerability.AffectedPackages = pkgs
			c.Vulnerability.AffectedSymbols = syms
			if len(pkgs) > 0 {
				c.Vulnerability.Package = pkgs[0].Path
			}
			if len(res.SelectedModules) > 1 {
				c.Affected.Limitations = append(c.Affected.Limitations,
					fmt.Sprintf("multi-module advisory: %d affected modules linked (%s) — "+
						"symbols unioned for analysis; version/remediation fields follow %s",
						len(res.SelectedModules), strings.Join(res.SelectedModules, ", "), first.Module))
			}
		}
	}
	c.EvidenceGraph.ComputeHash()
	// Without a selectable build every downstream measurement is meaningless:
	// root-cause resolution and reachability would only report consequences
	// of the same missing fact. Stop here so the request reports the
	// external dependency instead of a cascade of analysis failures.
	if c.Affected != nil && buildUnselected(*c.Affected) {
		return workflow.Transition{
			Next:   domain.StateEvaluateVerdict,
			Reason: "the analyzed build selects no product files: the product's target and build tags were not identified",
		}, nil
	}
	if c.Affected.HasNegative() {
		if c.Affected.Scope.AllowsNegativeClosure() {
			return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "deterministic negative: component not applicable within advisory scope"}, nil
		}
		requested := c.Vulnerability.ID
		if c.Affected.Scope != nil {
			requested = c.Affected.Scope.RequestedID
		}
		limitation := fmt.Sprintf("partial advisory scope: checked modules %s do not establish complete coverage of %s; component-negative facts cannot close the requested scope", strings.Join(c.Affected.CheckedModules, ", "), requested)
		c.Affected.Limitations = append(c.Affected.Limitations, limitation)
		c.EvidenceGraph.AddLimitation(limitation)
		return workflow.Transition{Next: domain.StateResolveRootCause, Reason: limitation}, nil
	}
	return workflow.Transition{Next: domain.StateResolveRootCause, Reason: "affected chain not refuted"}, nil
}

// buildUnselected reports whether package loading failed because the selected
// build excludes every product file — a target/configuration mismatch rather
// than a product or analyzer defect.
func buildUnselected(res domain.AffectedResult) bool {
	for _, g := range res.AnalysisGaps {
		if g.Owner == domain.GapOwnerExternal && g.Code == domain.GapExternalDependencyUnresolved {
			return true
		}
	}
	return false
}

// mergeUniqueStrings appends values not already present, preserving order.
func mergeUniqueStrings(dst, values []string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

// RootCauseResolver produces a root cause model — deterministic or
// LLM-assisted. LLM proposals still pass through Verifier.
// RootCauseProposer is an optional resolver extension: when every
// resolved candidate fails verification, the state asks it once for
// alternative candidates and verifies those the same way.
type RootCauseProposer interface {
	Propose(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) ([]domain.RootCause, []string, error)
}

type RootCauseResolver interface {
	Resolve(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error)
}

type ResolveRootCause struct {
	Manual    []domain.RootCause
	Resolver  RootCauseResolver
	Verifier  *rootcause.Verifier
	LLMClient llm.Completer
}

func (ResolveRootCause) State() domain.WorkflowState { return domain.StateResolveRootCause }

func (h ResolveRootCause) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if len(h.Manual) > 0 {
		manual := make([]domain.RootCause, 0, len(h.Manual))
		for _, rc := range h.Manual {
			if rc.Origin == "" {
				rc.Origin = domain.RootCauseOriginManual
			}
			manual = append(manual, rc)
		}
		c.RootCause = &domain.RootCauseModel{
			Status:     domain.RootCauseResolved,
			RootCauses: manual,
			Limitations: []string{
				"root cause provided manually; symbol existence verified only if verifier configured",
			},
		}
		if h.Verifier != nil {
			c.RootCause.Limitations = append(c.RootCause.Limitations,
				h.Verifier.Verify(ctx, c, c.RootCause, c.Vulnerability)...)
			if c.RootCause.Status != domain.RootCauseResolved {
				reason := "manual root cause failed verification: " + strings.Join(c.RootCause.Limitations, "; ")
				c.RootCause.AnalysisGaps = appendGap(c.RootCause.AnalysisGaps,
					rootCauseGap(c.ID, reason))
				c.EvidenceGraph.AddLimitation(reason)
				return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: reason}, nil
			}
		}
		return workflow.Transition{Next: domain.StateBuildExploitModel, Reason: "manual root cause accepted"}, nil
	}
	if h.Resolver == nil {
		reason := "root cause unresolved: no resolver configured and --root-cause not provided"
		c.AnalysisGaps = appendGap(c.AnalysisGaps, rootCauseGap(c.ID, reason))
		c.EvidenceGraph.AddLimitation(reason)
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: reason}, nil
	}
	if r, ok := h.Resolver.(*rootcause.Resolver); ok && r.Source == nil && h.Verifier != nil {
		r.Source = h.Verifier.Source
	}
	model, evs, err := h.Resolver.Resolve(ctx, c, c.Vulnerability)
	if err != nil {
		return workflow.Transition{}, fmt.Errorf("root cause resolve: %w", err)
	}
	for _, e := range evs {
		c.EvidenceGraph.AddEvidence(e)
	}
	if h.Verifier != nil && len(model.RootCauses) > 0 {
		model.Limitations = append(model.Limitations,
			h.Verifier.Verify(ctx, c, model, c.Vulnerability)...)
	}
	c.RootCause = model
	c.EvidenceGraph.ComputeHash()
	// Candidates may fail source verification (e.g. a symbol added only by
	// the fix commit). If the resolver can propose fresh candidates, ask
	// once and verify those through the same verifier.
	if model.Status != domain.RootCauseResolved && h.Verifier != nil {
		if p, ok := h.Resolver.(RootCauseProposer); ok {
			props, lims, err := p.Propose(ctx, c, c.Vulnerability)
			model.Limitations = append(model.Limitations, lims...)
			if err == nil && len(props) > 0 {
				model.RootCauses = props
				model.Limitations = append(model.Limitations,
					h.Verifier.Verify(ctx, c, model, c.Vulnerability)...)
				if len(model.RootCauses) > 0 {
					model.Status = domain.RootCauseResolved
				}
			}
		}
	}
	if model.Status != domain.RootCauseResolved {
		// An unresolvable root cause is a reason the mandatory conditions
		// cannot be established — it is not a reason to abandon the case
		// before a verdict exists. Record the typed cause and route through
		// the verdict evaluator so the failure still reaches reports.
		reason := fmt.Sprintf("root cause %s: %s", model.Status, strings.Join(model.Limitations, "; "))
		model.AnalysisGaps = appendGap(model.AnalysisGaps, rootCauseGap(c.ID, reason))
		c.EvidenceGraph.AddLimitation(reason)
		if c.StrictLLM {
			return workflow.Transition{Next: domain.StateBuildReport, Reason: "strict-llm: " + reason}, nil
		}
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: reason}, nil
	}
	if c.CVEAnalysisProfile == domain.ProfileAssist || c.CVEAnalysisProfile == domain.ProfileVerified {
		if err := ActResearchCVE(ctx, c, cveanalysis.NewDefaultSourceResolver(""), h.LLMClient); err != nil {
			reason := fmt.Sprintf("cve analysis failed: %v", err)
			gap := analysisGap(domain.GapOwnerCode, domain.GapCVEAttributionUnresolved,
				domain.ObligationAttribution, c.ID, reason)
			if c.StrictLLM {
				c.AnalysisGaps = appendGap(c.AnalysisGaps, gap)
				return workflow.Transition{Next: domain.StateBuildReport, Reason: "strict-llm: " + reason}, nil
			}
			c.EvidenceGraph.AddLimitation(reason)
		}
	}
	return workflow.Transition{Next: domain.StateBuildExploitModel, Reason: "root cause resolved from advisory/fix evidence"}, nil
}

// ExploitBuilder builds an exploit model from a resolved root cause.
type ExploitBuilder interface {
	Build(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability, rc *domain.RootCauseModel) (*domain.ExploitModel, []string)
}

type BuildExploitModel struct {
	ModelPath string
	Builder   ExploitBuilder
}

func (BuildExploitModel) State() domain.WorkflowState { return domain.StateBuildExploitModel }

func (h BuildExploitModel) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.ModelPath != "" {
		b, err := os.ReadFile(h.ModelPath)
		if err != nil {
			return failureTransition(c, inputGap(c.ID, domain.ObligationMeasurement,
				"read exploit model: "+err.Error()), c.StrictLLM), nil
		}
		var m domain.ExploitModel
		if err := json.Unmarshal(b, &m); err != nil {
			return failureTransition(c, inputGap(c.ID, domain.ObligationMeasurement,
				fmt.Sprintf("exploit model file is invalid: %v", err)), c.StrictLLM), nil
		}
		if len(m.MandatoryConditions) == 0 {
			return failureTransition(c, measurementGap(c.ID, domain.ObligationMeasurement,
				"exploit model has no mandatory conditions"), c.StrictLLM), nil
		}
		c.Exploit = &m
		return workflow.Transition{Next: domain.StateCollectEvidence, Reason: "exploit model loaded"}, nil
	}
	if h.Builder == nil || c.RootCause == nil {
		reason := "no exploit model: provide --exploit-model or configure a builder"
		gap := rootCauseGap(c.ID, reason)
		if h.Builder == nil && c.RootCause != nil {
			gap = inputGap(c.ID, domain.ObligationMeasurement, reason)
		}
		return failureTransition(c, gap, c.StrictLLM), nil
	}
	m, limitations := h.Builder.Build(ctx, c, c.Vulnerability, c.RootCause)
	if m == nil {
		return failureTransition(c, measurementGap(c.ID, domain.ObligationMeasurement,
			"exploit model could not be built: "+strings.Join(limitations, "; ")), c.StrictLLM), nil
	}
	for _, l := range limitations {
		c.EvidenceGraph.AddLimitation(l)
	}
	c.Exploit = m
	return workflow.Transition{Next: domain.StateCollectEvidence, Reason: "exploit model built from root causes"}, nil
}

type CollectEvidence struct {
	Govulncheck goanalysis.Runner
	Source      *goanalysis.Index
}

func (CollectEvidence) State() domain.WorkflowState { return domain.StateCollectEvidence }

func (h CollectEvidence) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	// The recorder always produces one typed run record — a nil runner is
	// recorded as not_run rather than silently absent.
	h.runGovulncheck(ctx, c)
	if h.Source != nil {
		// Case boundary: one index serves many advisories in scan/eval
		// mode, so the session-scoped budget record must not carry a
		// previous advisory's truncation into this one. The call is
		// idempotent for the same case — every later query (including a
		// re-run of this state) keeps the record sticky.
		h.Source.BeginVerificationSession(c.ID)
		// Pin the knowledge base the scans consulted — sources +
		// content digest let a report be checked against the exact
		// semantic revision that produced it.
		kb := h.Source.Knowledge()
		c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
			Quality: domain.QualityDeterministic,
			Source:  "knowledge base",
			Content: fmt.Sprintf("sources=%v digest=%s", kb.Sources, kb.Digest()),
		})
		h.collectProductShape(ctx, c)
		h.runSourceAnalysis(ctx, c)
		h.collectTransportProof(ctx, c)
		h.actCollectEvidence(ctx, c)
		h.runListenerScan(ctx, c)
		h.runModuleUsage(ctx, c)
		h.runExposure(ctx, c)
		// A budget exhausted during the source work truncated dependency
		// coverage for the whole verification session. Name it on the case:
		// an incomplete coverage set must never read as silent coverage, and
		// the record persists across repeated verification of the same
		// subject set.
		for _, l := range h.Source.BudgetLimitations() {
			c.EvidenceGraph.AddToolLimitation("source index budget truncation: " + l)
			c.AnalysisGaps = appendGap(c.AnalysisGaps, analysisGap(domain.GapOwnerCode,
				domain.GapAnalysisBudgetExhausted, domain.ObligationMeasurement, c.ID,
				"source index budget truncation: "+l))
		}
	}
	if h.Govulncheck == nil && h.Source == nil {
		c.EvidenceGraph.AddLimitation("no evidence collectors beyond affected resolution are wired yet")
	}
	if isStdlibModule(c.Vulnerability.Module) {
		if c.Product.ReleaseGoVersion != "" {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"stdlib advisory assessed against release toolchain %s (analysis toolchain %s, go.mod minimum %s)",
				c.Product.ReleaseGoVersion, c.Product.GoVersion, c.Product.GoModDirective))
		} else {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"stdlib advisory: applicability depends on the toolchain that built the release binary; pass --release-go-version or --binary (analysis toolchain %s, go.mod minimum %s)",
				c.Product.GoVersion, c.Product.GoModDirective))
		}
	}
	c.EvidenceGraph.ComputeHash()
	return workflow.Transition{Next: domain.StateEvaluateConditions, Reason: "deterministic evidence collection complete"}, nil
}

func (h CollectEvidence) runGovulncheck(ctx context.Context, c *domain.AnalysisCase) {
	record := goanalysis.RecordForCase(c)
	ev, res := goanalysis.CollectGovulncheck(ctx, h.Govulncheck, c.Product, record)
	run := ev.Govulncheck
	if run != nil {
		switch run.Outcome {
		case domain.GovulncheckFailed:
			c.EvidenceGraph.AddToolLimitation("govulncheck failed: " + run.Error)
			c.AnalysisGaps = appendGap(c.AnalysisGaps, measurementGap(c.ID, domain.ObligationMeasurement,
				"govulncheck failed: "+run.Error))
		case domain.GovulncheckNotRun:
			c.EvidenceGraph.AddToolLimitation("govulncheck did not run: " + run.Error)
			c.AnalysisGaps = appendGap(c.AnalysisGaps, measurementGap(c.ID, domain.ObligationMeasurement,
				"govulncheck did not run: "+run.Error))
		}
		if !run.Coverage.ScopeComplete && run.Pattern != "" &&
			(run.Outcome == domain.GovulncheckCompletedEmpty ||
				run.Outcome == domain.GovulncheckCompletedWithResults) {
			// Narrowed fallback scope is a limitation, never full coverage:
			// the directory/main-file heuristic cannot prove it complete.
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf(
				"govulncheck ran on narrowed scope %s; packages outside the pattern were not analyzed", run.Pattern))
			c.AnalysisGaps = appendGap(c.AnalysisGaps, measurementGap(c.ID, domain.ObligationMeasurement,
				fmt.Sprintf("govulncheck ran on narrowed scope %s; packages outside the pattern were not analyzed", run.Pattern)))
		}
	}
	evID := c.EvidenceGraph.AddEvidence(ev)
	if run == nil ||
		(run.Outcome != domain.GovulncheckCompletedEmpty && run.Outcome != domain.GovulncheckCompletedWithResults) {
		// A failed or not-run invocation has no consumable findings: the
		// raw prefix stays in evidence for audit only.
		return
	}
	// Project the shared stream against this case's own record. Findings are
	// never selected by a shared CVE key or alias, so another record's trace
	// cannot become this case's call path.
	projection, err := res.ProjectRecord(record)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation("govulncheck record projection failed: " + err.Error())
		return
	}
	for _, f := range projection.Findings {
		if !f.HasCallPath() {
			continue
		}
		cp := f.CallPath()
		if len(cp.Frames) == 0 {
			continue
		}
		cp.EvidenceID = evID
		c.EvidenceGraph.AddCallPath(cp)
	}
}

// isStdlibModule reports whether the advisory's module is one of the
// explicitly supported Go standard-library/toolchain pseudo-modules
// ("std", "stdlib", "toolchain", "cmd"). Classification is exact identity:
// an empty module name or a dot-less third-party path is never stdlib —
// the first-segment shape of an import path is not module identity.
func isStdlibModule(module string) bool {
	switch module {
	case "std", "stdlib", "toolchain", "cmd":
		return true
	}
	return false
}

// runListenerScan records product functions that open network listeners or
// start servers. For server-side transport vulnerabilities this evidence lets
// conditions resolve input provenance as remote-peer-controlled.
func (h CollectEvidence) runListenerScan(ctx context.Context, c *domain.AnalysisCase) {
	lst, err := h.Source.FindListeners(ctx)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("listener scan failed: %v", err))
		return
	}
	if len(lst) == 0 {
		return
	}
	c.EvidenceGraph.AddEntrypoints(lst...)
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceEntrypoint,
		Quality: domain.QualityDeterministic,
		Source:  "source index: network listener scan",
		Tool:    "goanalysis.Index.FindListeners",
		Content: fmt.Sprintf("product opens %d network listener/server entrypoint(s)", len(lst)),
	})
}

// runExposure resolves network-exposure facts: inbound listener binds
// (ListenSites, with address arguments resolved through literals, consts,
// env vars and struct fields) and outbound endpoints into the vulnerable
// module (DialSites). env:/config:-sourced addresses are looked up in the
// repository's config files so a fact carries the concrete value when
// statically available. Facts are recorded unconditionally — evaluators
// distinguish "no exposure found" from "scan never ran" via the evidence
// record.
func (h CollectEvidence) runExposure(ctx context.Context, c *domain.AnalysisCase) {
	var facts []domain.ExposureFact
	if h.Source != nil {
		in, err := h.Source.ListenSites(ctx)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("listener address scan failed: %v", err))
		} else {
			for i := range in {
				in[i].Scope = exposure.Scope(in[i].Address)
			}
			facts = append(facts, in...)
		}
		if module := c.Vulnerability.Module; module != "" && !isStdlibModule(module) {
			out, err := h.Source.DialSites(ctx, module)
			if err != nil {
				c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("dial-site scan failed: %v", err))
			} else {
				facts = append(facts, out...)
			}
		}
		if auth, err := h.Source.InboundAuthFacts(ctx); err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("inbound auth-middleware scan failed: %v", err))
		} else {
			facts = append(facts, auth...)
		}
	}

	if c.Product.Repository != "" || len(c.Product.DeployManifests) > 0 || c.Product.DeployArchive != "" {
		deployFacts, err := exposure.ScanDeployWithOptions(exposure.DeployScanOptions{
			RootPath:    c.Product.Repository,
			ExtraPaths:  c.Product.DeployManifests,
			ArchivePath: c.Product.DeployArchive,
		})
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("deployment manifest scan failed: %v", err))
		} else {
			facts = append(facts, deployFacts...)
		}
	}

	// Resolve env:/var:/field:-sourced addresses through the repo's config
	// files when a matching key exists.
	var items []exposure.Item
	if dir := c.Product.Repository; dir != "" {
		if scanned, err := exposure.ScanRepo(dir); err == nil {
			items = scanned
		} else {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config scan failed: %v", err))
		}
	}
	for i := range facts {
		f := &facts[i]
		if f.Direction == "outbound" {
			f.Scope = exposure.OutboundScope(f.AddressSource)
		}
		if f.Address != "" || !strings.HasPrefix(f.AddressSource, "env:") {
			continue
		}
		if it := exposure.Lookup(items, strings.TrimPrefix(f.AddressSource, "env:")); it != nil {
			f.Address = it.Value
			f.AddressSource = fmt.Sprintf("env:%s (config %s:%d)", it.Key, filepathBase(it.File), it.Line)
			f.Scope = exposure.OutboundScope("config:" + it.Key)
		}
	}
	for _, f := range facts {
		c.EvidenceGraph.AddExposure(f)
	}

	assessment := exposure.ClassifyPerimeter(c.EvidenceGraph.ExposuresList(), productNames(c))
	// An explicit operator trust selection is the only other admitted basis:
	// it is a declared perimeter, not an inference from exposure shape.
	operatorPerimeter := c.Product.TrustedPeer ||
		(c.Product.PerimeterOverride != "" && c.Product.PerimeterOverride != "auto")
	if operatorPerimeter {
		perimeter := assessment.Perimeter
		switch {
		case c.Product.PerimeterOverride == "cluster" || c.Product.PerimeterOverride == domain.PerimeterClusterInternal:
			perimeter = domain.PerimeterClusterInternal
		case c.Product.PerimeterOverride != "" && c.Product.PerimeterOverride != "auto":
			perimeter = c.Product.PerimeterOverride
		case c.Product.TrustedPeer:
			perimeter = domain.PerimeterClusterInternal
		}
		rationale := "perimeter explicitly selected by the operator"
		if c.Product.PerimeterOverride != "" && c.Product.PerimeterOverride != "auto" {
			rationale = "perimeter overridden by configuration: " + c.Product.PerimeterOverride
		}
		assessment = domain.NewPerimeterAssessment(perimeter, domain.PerimeterBasisOperatorDeclared, rationale)
	}
	c.PerimeterAssessment = &assessment
	c.DetectedPerimeter = assessment.Perimeter
	c.PerimeterRationale = assessment.Rationale

	var summary strings.Builder
	fmt.Fprintf(&summary, "%d exposure fact(s):", len(facts))
	for _, f := range facts {
		fmt.Fprintf(&summary, " %s %s", f.Direction, f.Target)
		if f.Address != "" {
			fmt.Fprintf(&summary, "=%s", f.Address)
		}
		if f.Scope != "" && f.Scope != domain.ScopeUnknown {
			fmt.Fprintf(&summary, "(%s)", f.Scope)
		}
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceConfiguration,
		Quality: domain.QualityDeterministic,
		Source:  "source index + repo config scan: exposure",
		Tool:    "goanalysis.Index.ListenSites+DialSites+InboundAuthFacts, exposure.ScanRepo",
		Content: summary.String(),
	})
	if c.DetectedPerimeter == domain.PerimeterClusterInternal {
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:      "EV-PERIMETER-CLUSTER",
			Kind:    domain.EvidenceConfiguration,
			Quality: domain.QualityStructural,
			Source:  "perimeter classifier: cluster-internal",
			Tool:    "exposure.ClassifyPerimeter",
			Content: fmt.Sprintf("cluster-internal topology inferred from attributed manifests/listeners: %s", c.PerimeterRationale),
		})
	}
}

// productNames collects identity candidates for deploy-fact attribution:
// the go.mod module basename, the analyzed binary name and the repository
// directory name. A manifest resource whose owner matches one of these
// names is attributed to the product; other owners describe foreign
// services (B35).
func productNames(c *domain.AnalysisCase) []string {
	var names []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			names = append(names, s)
		}
	}
	if mod := goModuleName(c.Product.Repository); mod != "" {
		add(mod[strings.LastIndex(mod, "/")+1:])
	}
	if c.Product.BinaryPath != "" {
		add(strings.TrimSuffix(filepathBase(c.Product.BinaryPath), filepath.Ext(c.Product.BinaryPath)))
	}
	if c.Product.Repository != "" {
		add(filepathBase(c.Product.Repository))
	}
	return names
}

func goModuleName(repo string) string {
	b, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// runModuleUsage records product call sites into each linked vulnerable
// module's API. For library-internal sinks (unexported, peer-driven)
// module usage — not a direct symbol reference — is what makes the
// vulnerable code run. Multi-module advisories can link several
// affected entries — each gets its own usage/reach scan.
func (h CollectEvidence) runModuleUsage(ctx context.Context, c *domain.AnalysisCase) {
	seen := map[string]bool{}
	var modules []string
	if c.Affected != nil {
		for _, m := range c.Affected.SelectedModules {
			if !seen[m] {
				seen[m] = true
				modules = append(modules, m)
			}
		}
	}
	if m := c.Vulnerability.Module; m != "" && !seen[m] {
		seen[m] = true
		modules = append(modules, m)
	}
	for _, module := range modules {
		if !isStdlibModule(module) {
			h.moduleUsage(ctx, c, module, modules)
		}
	}
}

func (h CollectEvidence) moduleUsage(ctx context.Context, c *domain.AnalysisCase, module string, linked []string) {
	sites, err := h.Source.ModuleUsage(ctx, module)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("module usage scan failed: %v", err))
		return
	}
	owned := 0
	for _, s := range sites {
		if s.ModuleOwner == module {
			owned++
		}
	}
	// The check record is written even with zero sites: it distinguishes
	// "verified no usage" from "never attempted" for evaluators.
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module usage check",
		Tool:    "goanalysis.Index.ModuleUsage",
		Content: fmt.Sprintf("%d product call site(s) with prefix %s; %d owner-confirmed", len(sites), module, owned),
	})
	// The exact subject set this scan is evidence about, computed whether or
	// not any call site exists. The typed record is what a negative claim
	// cites: completion and census completeness are measured facts, not
	// inferred from the nil error above.
	var subjects []domain.SymbolRef
	for _, sym := range c.Vulnerability.AffectedSymbols {
		if domain.OwnerModule(sym.Package, linked) == module {
			subjects = append(subjects, sym)
		}
	}
	if c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			if domain.OwnerModule(rc.Package, linked) == module {
				subjects = append(subjects, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
			}
		}
	}
	usageComplete := h.Source.SourceScanComplete()
	recordSourceScan(c, module, subjects, nil, true, usageComplete, false,
		fmt.Sprintf("%d product call site(s) with prefix %s (%d owner-confirmed); census complete=%v",
			len(sites), module, owned, usageComplete))
	if len(sites) == 0 {
		return
	}
	c.EvidenceGraph.AddModuleUsages(sites...)
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module usage",
		Tool:    "goanalysis.Index.ModuleUsage",
		Content: fmt.Sprintf("product has %d call site(s) with prefix %s (%d owner-confirmed), e.g. %s.%s (%s:%d)",
			len(sites), module, owned, sites[0].Package, sites[0].Function, sites[0].File, sites[0].Line),
	})

	// For affected symbols not invoked directly, trace call edges inside the
	// vendored module: product-used API → ... → sink.
	entries := map[string]bool{}
	for _, s := range sites {
		if s.Callee != "" && s.ModuleOwner == module {
			entries[s.Callee] = true
		}
	}
	var entryList []string
	for e := range entries {
		entryList = append(entryList, e)
	}
	if len(subjects) == 0 || len(entryList) == 0 {
		return
	}
	reach, err := h.Source.ModuleInternalReach(ctx, module, entryList, subjects)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("module internal reach scan failed: %v", err))
		return
	}
	// Record the check itself: its presence distinguishes "verified no chain"
	// from "never attempted" for evaluators.
	checked := make([]string, 0, len(subjects))
	for _, s := range subjects {
		checked = append(checked, s.Package+"."+s.Symbol)
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module-internal reachability check",
		Tool:    "goanalysis.Index.ModuleInternalReach",
		Content: fmt.Sprintf("checked %d subject(s) against %d product-used API entr(ies): %s",
			len(subjects), len(entryList), strings.Join(checked, ", ")),
	})
	recordSourceScan(c, module, subjects, entryList, true, reach.Complete, reach.Opaque,
		fmt.Sprintf("checked %d subject(s) against %d product-used API entr(ies): %s; complete=%v opaque=%v",
			len(subjects), len(entryList), strings.Join(checked, ", "), reach.Complete, reach.Opaque))
	// Opaque dispatch (func values, non-interface map calls) makes the call
	// graph incomplete: an unreached subject is UNKNOWN, not disproven.
	if reach.Opaque {
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "source index: module-internal opaque dispatch",
			Tool:    "goanalysis.Index.ModuleInternalReach",
			Content: "module contains calls whose callee cannot be resolved (func values/dynamic dispatch); unreached subjects are not disproven",
		})
	}
	for key, chain := range reach.Reachable {
		c.EvidenceGraph.AddModuleReachable(key, chain)
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "source index: module-internal call chain",
			Tool:    "goanalysis.Index.ModuleInternalReach",
			Content: fmt.Sprintf("%s reached from product-used API via: %s", key, strings.Join(chain, " -> ")),
		})
	}
}

// recordSourceScan persists one typed source-level measurement. The build
// context is captured now, so a later admission compares the measurement's
// actual identity rather than the case's current snapshot.
func recordSourceScan(c *domain.AnalysisCase, module string, subjects []domain.SymbolRef,
	entries []string, completed, complete, opaque bool, content string) {
	if c == nil {
		return
	}
	build := domain.EffectiveBuildContext(c.Product)
	tool := "goanalysis.Index.ModuleUsage"
	source := "source index: module usage measurement"
	if len(entries) > 0 {
		tool = "goanalysis.Index.ModuleInternalReach"
		source = "source index: module-internal reachability measurement"
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:         domain.EvidenceSourceScan,
		Quality:      domain.QualityDeterministic,
		Source:       source,
		Tool:         tool,
		Content:      content,
		BuildContext: &build,
		SourceScan: &domain.SourceScanRun{
			Module:       module,
			Subjects:     append([]domain.SymbolRef(nil), subjects...),
			EntrySymbols: append([]string(nil), entries...),
			Completed:    completed,
			Complete:     complete,
			Opaque:       opaque,
		},
	})
}

// collectProductShape proves the product shape before any source analysis:
// it is the prerequisite for library-scope admission. Module ownership and
// the source census are persisted with their evidence, and the evidence ids
// are linked back into the shape. Binary-mode cases stay ineligible even when
// a source index exists; a failed or stale proof publishes an UNKNOWN shape
// with its reason and never a library proof.
func (h CollectEvidence) collectProductShape(ctx context.Context, c *domain.AnalysisCase) {
	if c.Product.BinaryPath != "" {
		c.Product.Shape = &domain.ProductShape{
			Kind: domain.ProductShapeUnknown,
			Limitations: []string{
				"binary-mode analysis: no product source census exists, so the product shape is UNKNOWN",
			},
		}
		return
	}
	shape, evs, err := h.Source.BuildProductShape(ctx)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("product shape proof failed: %v", err))
		c.Product.Shape = &domain.ProductShape{
			Kind:        domain.ProductShapeUnknown,
			Limitations: []string{"product shape proof failed: " + err.Error()},
		}
		return
	}
	ids := make([]domain.EvidenceID, 0, len(evs))
	for _, e := range evs {
		ids = append(ids, c.EvidenceGraph.AddEvidence(e))
	}
	if shape != nil {
		shape.EvidenceIDs = append(shape.EvidenceIDs, ids...)
	}
	c.Product.Shape = shape
}

// runSourceAnalysis gathers call sites, argument provenance and validations
// for conditions that carry a subject symbol.
func (h CollectEvidence) runSourceAnalysis(ctx context.Context, c *domain.AnalysisCase) {
	if c.Exploit == nil {
		return
	}
	if err := h.Source.Loaded(ctx); err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("source index load failed: %v", err))
		return
	}
	conds := append([]domain.Condition{}, c.Exploit.MandatoryConditions...)
	conds = append(conds, c.Exploit.SupportingFactors...)
	seen := map[domain.ConditionID]bool{}
	for _, cond := range conds {
		if seen[cond.ID] {
			continue
		}
		seen[cond.ID] = true
		subjects := cond.Subjects
		if cond.Subject != nil {
			subjects = append(append([]domain.SymbolRef{}, subjects...), *cond.Subject)
		}
		switch {
		case cond.Kind == domain.ConditionCheckTrigger && cond.Mandatory:
			cert, err := h.Source.CaptureConfigWriterCertificate(ctx,c,cond)
			if err != nil {
				c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("configuration certificate %s: %v",cond.ID,err))
			} else if evidence, err := goanalysis.ConfigCertificateEvidence(cert); err == nil {
				c.EvidenceGraph.AddEvidence(evidence)
			}
		case cond.Params[domain.ParamCheck] == domain.CheckSymbolPresent:
			h.collectPresence(ctx, c, dedupSubjects(subjects))
		case cond.Params[domain.ParamCheck] == domain.CheckConfigFlag:
			h.collectConfigFlag(ctx, c, cond)
		case cond.Params[domain.ParamCheck] == domain.CheckConfigKey:
			h.collectConfigKey(ctx, c, cond)
		case cond.Params[domain.ParamDirection] == domain.DirectionRead:
			h.collectReaders(ctx, c, dedupSubjects(subjects))
		case needsProvenance(cond.Kind):
			for _, subj := range dedupSubjects(subjects) {
				h.collectProvenance(ctx, c, cond, subj)
			}
			subs := dedupSubjects(subjects)
			h.collectIngress(ctx, c, cond, subs)
			h.collectSinkClosure(ctx, c, cond, subs)
		}
	}
}

// collectIngress records the dependency ingress closure for a
// provenance-kind condition: every input at the product→module boundary
// plus every autonomous source inside the product-reachable dependency
// cone. The record carries completeness blockers and per-item origins —
// the evaluator consults it before accepting a constant-input falsifier.
// A failed inventory records a limitation, not silence: the condition's
// negative claim then cannot be verified.
func (h CollectEvidence) collectIngress(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition, subjects []domain.SymbolRef) {
	if c.Vulnerability.Module == "" || len(subjects) == 0 {
		return
	}
	// stdlib advisories span many packages without a single module tree —
	// the inventory is module-scoped.
	if isStdlibModule(c.Vulnerability.Module) {
		return
	}
	closure, evs, err := h.Source.IngressInventory(ctx, c.Vulnerability.Module, subjects, sinkClosureHops)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf(
			"ingress inventory %s (cond %s): %v", c.Vulnerability.Module, cond.ID, err))
		return
	}
	for _, e := range evs {
		c.EvidenceGraph.AddEvidence(e)
	}
	closure.ConditionID = cond.ID
	var safe, unsafe, unresolved int
	for _, it := range closure.Items {
		switch {
		case domain.SafeOrigin(it.Origin):
			safe++
		case it.Origin == domain.OriginUnknown || it.Origin == "":
			unresolved++
		default:
			unsafe++
		}
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "dependency ingress-closure inventory " + c.Vulnerability.Module,
		Tool:    "goanalysis.Index.IngressInventory",
		Content: fmt.Sprintf("cond=%s module=%s items=%d (safe=%d unsafe=%d unresolved=%d) blockers=%d complete=%v",
			cond.ID, c.Vulnerability.Module, len(closure.Items), safe, unsafe, unresolved,
			len(closure.Blockers), closure.Complete),
	})
	c.EvidenceGraph.AddIngressClosure(closure)
}

// collectSinkClosure records the sink-closure coverage for a
// provenance-kind condition: every live call site of each known sink
// (the condition's subjects) with the resolved origin of its payload
// input. Subjects remain KNOWN_ONLY until a separately verified
// completeness contract is available.
func (h CollectEvidence) collectSinkClosure(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition, subjects []domain.SymbolRef) {
	if c.Vulnerability.Module == "" || len(subjects) == 0 {
		return
	}
	if isStdlibModule(c.Vulnerability.Module) {
		return
	}
	// The sink set carries a completeness contract only for the
	// exact-argument attacker-control shape the post-reach route
	// consumes, and only when the declared subject set is complete.
	// Every other condition stays KNOWN_ONLY exactly as before, so the
	// constant/generated-input route is unchanged.
	basis := ""
	if cond.Kind == domain.ConditionAttackerControl && cond.ArgIndex >= 0 &&
		cond.Params[domain.ParamInputSource] != domain.InputPeer {
		var proof *domain.ContentAdmission
		if c != nil {
			proof = fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), c.RootCause)
		}
		if b, ok := goanalysis.SinkSetBasis(c, subjects, proof); ok {
			basis = b
		}
	}
	closure, evs, err := h.Source.SinkClosure(ctx, cond.ID, c.Vulnerability.Module, basis,
		subjects, cond.ArgIndex, sinkClosureHops)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf(
			"sink-closure inventory %s (cond %s): %v", c.Vulnerability.Module, cond.ID, err))
		return
	}
	for _, e := range evs {
		c.EvidenceGraph.AddEvidence(e)
	}
	c.EvidenceGraph.AddSinkClosure(closure)
	// Persist the exact site/argument trace for every live payload
	// position: the post-reach contract matches each live SinkSite to a
	// recorded DataFlow with the same sink, ArgIndex, origin,
	// transformations and summary. TraceArgumentBound is the same
	// bounded primitive the collector used for product call sites; a
	// site already traced by collectProvenance keeps its recorded flow —
	// gap analysis owns deepening unresolved ones.
	traced := map[string]bool{}
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID != cond.ID {
			continue
		}
		traced[fmt.Sprintf("%s:%d:%d:%s:%d", f.Sink.File, f.Sink.Line, f.Sink.Column, f.Sink.Function, f.Arg)] = true
	}
	for _, site := range closure.Sites {
		if !site.Live {
			continue
		}
		if cond.ArgIndex >= 0 && site.Arg != cond.ArgIndex {
			continue
		}
		key := fmt.Sprintf("%s:%d:%d:%s:%d", site.File, site.Line, site.Column, site.Function, site.Arg)
		if traced[key] {
			continue
		}
		flow, fevs, ferr := h.Source.TraceArgumentBound(ctx, site.CallSite, site.Arg, sinkClosureHops)
		if ferr != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf(
				"sink-site trace %s:%d arg %d (cond %s): %v",
				site.File, site.Line, site.Arg, cond.ID, ferr))
			continue
		}
		flow.ConditionID = cond.ID
		c.EvidenceGraph.AddArgumentTrace([]domain.DataFlow{flow}, fevs)
	}
}

// sinkClosureHops matches the negative-verification trace budget so the
// collected closure is reproducible at verification depth — a shallower
// collection would leave origins unresolved that the verifier later
// resolves differently.
const sinkClosureHops = 16

func dedupSubjects(in []domain.SymbolRef) []domain.SymbolRef {
	seen := map[string]bool{}
	var out []domain.SymbolRef
	for _, s := range in {
		k := s.Package + "." + s.Symbol
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// traceArgs traces a single argument (ArgIndex >= 0) or every argument
// (ArgIndex < 0, when the input parameter is unknown) at a call site.
func (h CollectEvidence) traceArgs(ctx context.Context, site domain.CallSite, cond domain.Condition) ([]domain.DataFlow, []domain.Evidence, error) {
	if cond.ArgIndex < 0 && cond.ArgIndex != domain.ArgReceiver {
		return h.Source.TraceAllArguments(ctx, site)
	}
	flow, evs, err := h.Source.TraceArgument(ctx, site, cond.ArgIndex)
	if err != nil {
		return nil, nil, err
	}
	return []domain.DataFlow{flow}, evs, nil
}

func needsProvenance(k domain.ConditionKind) bool {
	switch k {
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint, domain.ConditionValidation:
		return true
	}
	return false
}

func (h CollectEvidence) collectProvenance(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition, subj domain.SymbolRef) {
	sites, err := h.Source.FindCallers(ctx, subj)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("find_callers %s.%s: %v", subj.Package, subj.Symbol, err))
		return
	}
	if len(sites) == 0 {
		// Unexported dep subjects have no product callers — for peer-input
		// conditions their arguments are fed inside the dependency itself:
		// trace the dep-internal call sites of the subject.
		if evaluator.SymbolExported(subj) || !evaluator.WantsPeerInput(cond, c.Vulnerability) {
			c.EvidenceGraph.AddLimitation(
				fmt.Sprintf("no call sites of %s.%s found in product packages", subj.Package, subj.Symbol))
			return
		}
		depSites, derr := h.Source.FindDepCallers(ctx, subj)
		if derr != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("dep find_callers %s.%s: %v", subj.Package, subj.Symbol, derr))
			return
		}
		if len(depSites) == 0 {
			c.EvidenceGraph.AddLimitation(
				fmt.Sprintf("no call sites of %s.%s found in product or dependency packages", subj.Package, subj.Symbol))
			return
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "dep-internal caller scan " + subj.Package + "." + subj.Symbol,
			Tool:    "goanalysis.Index.FindDepCallers",
			Content: fmt.Sprintf("%d dep-internal call site(s) of %s.%s", len(depSites), subj.Package, subj.Symbol),
		})
		sites = depSites
	}
	for _, site := range sites {
		flows, evs, err := h.traceArgs(ctx, site, cond)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("trace_argument %s:%d: %v", site.File, site.Line, err))
			continue
		}
		for i := range flows {
			flows[i].ConditionID = cond.ID
		}
		c.EvidenceGraph.AddArgumentTrace(flows, evs)
		// Unpinned input position scans every argument; a pinned one
		// scans just that arg — records carry the Arg index either way.
		var vals []domain.Validation
		var vev []domain.Evidence
		var verr error
		if cond.ArgIndex < 0 && cond.ArgIndex != domain.ArgReceiver {
			vals, vev, verr = h.Source.FindAllValidations(ctx, site)
		} else {
			vals, vev, verr = h.Source.FindValidations(ctx, site, cond.ArgIndex)
		}
		err = verr
		if err == nil {
			for _, v := range vals {
				v.Property = fmt.Sprintf("cond=%s %s", cond.ID, v.Property)
				c.EvidenceGraph.AddValidations(v)
			}
			for _, e := range vev {
				c.EvidenceGraph.AddEvidence(e)
			}
		}
	}
}

// collectPresence resolves each subject in the dependency source for
// check=symbol_present conditions (INFO_LEAK pattern). Outcomes land in
// EvidenceGraph.SymbolDecls; the per-subject evidence record is written
// even on failure so evaluators can tell "checked" from "never ran".
func (h CollectEvidence) collectPresence(ctx context.Context, c *domain.AnalysisCase, subjects []domain.SymbolRef) {
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		site, err := h.Source.FindSymbol(ctx, subj)
		var content string
		switch {
		case err == nil:
			c.EvidenceGraph.AddSymbolDecl(key, site)
			content = fmt.Sprintf("%s declared at %s:%d", key, site.File, site.Line)
		case strings.Contains(err.Error(), "not found"):
			c.EvidenceGraph.AddSymbolDecl(key, nil)
			content = key + " not found in loaded packages"
		default:
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("presence check %s: %v", key, err))
			content = fmt.Sprintf("presence lookup for %s failed: %v", key, err)
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "presence check " + key,
			Tool:    "goanalysis.Index.FindSymbol",
			Content: content,
		})
	}
}

// collectReaders gathers product-code references to each subject for
// direction=read conditions (INFO_LEAK pattern): any reference is a
// candidate reader of the exposed datum. Sites land in
// EvidenceGraph.SymbolRefs; the per-subject check record is written even
// with zero hits to distinguish "verified none" from "never scanned".
func (h CollectEvidence) collectReaders(ctx context.Context, c *domain.AnalysisCase, subjects []domain.SymbolRef) {
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		sites, err := h.Source.SearchSymbol(ctx, subj)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("read-scope check %s: %v", key, err))
			continue
		}
		if len(sites) > 0 {
			c.EvidenceGraph.AddSymbolRefs(key, sites...)
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "read-scope check " + key,
			Tool:    "goanalysis.Index.SearchSymbol",
			Content: fmt.Sprintf("%d product reference site(s) to %s", len(sites), key),
		})
	}
}

// collectConfigFlag resolves a code-level configuration knob
// (config_package + config_symbol params): verifies the field exists in
// its package source, records the field kind (for Go zero-value
// reasoning) and collects every product assignment into
// EvidenceGraph.ConfigFlags.
func (h CollectEvidence) collectConfigFlag(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition) {
	pkg, sym := cond.Params[domain.ParamConfigPackage], cond.Params[domain.ParamConfigSymbol]
	if pkg == "" || sym == "" {
		return
	}
	key := pkg + "." + sym
	ref := domain.SymbolRef{Package: pkg, Symbol: sym}
	site, err := h.Source.FindSymbol(ctx, ref)
	var content string
	switch {
	case err == nil:
		c.EvidenceGraph.AddSymbolDecl(key, site)
		content = fmt.Sprintf("knob %s declared at %s:%d", key, site.File, site.Line)
	case strings.Contains(err.Error(), "not found"):
		c.EvidenceGraph.AddSymbolDecl(key, nil)
		content = "knob " + key + " not found in source"
	default:
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config flag %s decl: %v", key, err))
		content = fmt.Sprintf("config flag lookup for %s failed: %v", key, err)
	}
	if kind, kerr := h.Source.SymbolFieldType(ctx, ref); kerr == nil && kind != "" {
		c.EvidenceGraph.AddConfigFieldKind(key, kind)
	}
	writers, err := h.Source.ConfigWriters(ctx, ref)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config flag %s assignments: %v", key, err))
		return
	}
	assigns := writers.Assignments
	c.EvidenceGraph.AddConfigWriters(key, writers)
	for _, blocker := range writers.Blockers { c.EvidenceGraph.AddToolLimitation("config writers " + key + ": " + blocker) }
	c.EvidenceGraph.AddConfigFlag(key, assigns...)
	content += fmt.Sprintf("; %d assignment(s) in product code", len(assigns))
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSearchResult,
		Quality: domain.QualityDeterministic,
		Source:  "config flag check " + key,
		Tool:    "goanalysis.Index.FindSymbol+ConfigWriters",
		Content: content,
	})
}

// collectConfigKey resolves a file-level configuration knob
// (config_key param): scans repository config files for the key and
// records matches into EvidenceGraph.Configuration.
func (h CollectEvidence) collectConfigKey(_ context.Context, c *domain.AnalysisCase, cond domain.Condition) {
	key := cond.Params[domain.ParamConfigKey]
	if key == "" {
		return
	}
	dir := c.Product.Repository
	var content string
	if dir == "" {
		content = "repository path unavailable — config scan skipped"
	} else if items, err := exposure.FindKey(dir, key); err != nil {
		content = fmt.Sprintf("config key scan failed: %v", err)
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config key %s: %v", key, err))
	} else {
		for _, it := range items {
			evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
				Kind:    domain.EvidenceConfiguration,
				Quality: domain.QualityDeterministic,
				Source:  "config file " + it.File,
				Tool:    "exposure.FindKey",
				Content: fmt.Sprintf("%s=%s", it.Key, it.Value),
			})
			c.EvidenceGraph.AddConfigItem(domain.ConfigItem{
				Key: it.Key, Value: it.Value, File: it.File, Line: it.Line, Evidence: evID,
			})
		}
		content = fmt.Sprintf("%d occurrence(s) of key %q in repo config files", len(items), key)
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSearchResult,
		Quality: domain.QualityDeterministic,
		Source:  "config key check " + key,
		Tool:    "exposure.FindKey",
		Content: content,
	})
}

type EvaluateConditions struct {
	Evaluators []evaluator.ConditionEvaluator
	// Fallback was moved to GapAnalysis: the LLM claim evaluator must run
	// only after the deterministic hypothesis loop is exhausted, otherwise
	// an evidence-cited LLM TRUE can preempt a provable deterministic
	// FALSE the deep trace would have reached.
}

func (EvaluateConditions) State() domain.WorkflowState { return domain.StateEvaluateConditions }

func (h EvaluateConditions) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if c.Exploit == nil {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "no exploit model"}, nil
	}
	existing := map[domain.ConditionID]bool{}
	for _, cl := range c.Claims {
		existing[cl.ConditionID] = true
	}
	hasFalse := false
	for _, cond := range c.Exploit.MandatoryConditions {
		if existing[cond.ID] {
			if claim := findClaim(c.Claims, cond.ID); claim != nil && claim.Result == domain.ClaimFalse {
				hasFalse = true
			}
			continue
		}
		claim := domain.Claim{
			ID:          domain.ClaimID("CL-" + string(cond.ID)),
			ConditionID: cond.ID,
			Result:      domain.ClaimUnknown,
			Limitations: []string{"no evaluator handled this condition"},
		}
		for _, ev := range h.Evaluators {
			if ev.CanEvaluate(cond) {
				claim = ev.Evaluate(cond, c)
				break
			}
		}
		if claim.Result == domain.ClaimFalse {
			hasFalse = true
		}
		c.Claims = append(c.Claims, claim)
	}
	// The LLM fallback runs in GapAnalysis, after the deterministic
	// hypothesis loop — a fallback TRUE must not preempt a provable
	// deterministic FALSE that deep tracing or guard analysis reaches.
	// Supporting factors never gate the verdict, but they still get
	// claims — exposure/priority facts belong in the report, not only in
	// the raw evidence graph.
	for _, cond := range c.Exploit.SupportingFactors {
		if existing[cond.ID] {
			continue
		}
		claim := domain.Claim{
			ID:          domain.ClaimID("CL-" + string(cond.ID)),
			ConditionID: cond.ID,
			Result:      domain.ClaimUnknown,
			Limitations: []string{"no evaluator handled this condition"},
		}
		for _, ev := range h.Evaluators {
			if ev.CanEvaluate(cond) {
				claim = ev.Evaluate(cond, c)
				break
			}
		}
		c.Claims = append(c.Claims, claim)
	}
	if hasFalse {
		return workflow.Transition{Next: domain.StateNegativeCheck, Reason: "candidate FALSE requires negative verification"}, nil
	}
	if allMandatoryTrue(c) {
		return workflow.Transition{Next: domain.StateReview, Reason: "all mandatory conditions satisfied"}, nil
	}
	return workflow.Transition{Next: domain.StateGapAnalysis, Reason: "unresolved mandatory conditions"}, nil
}

func findClaim(claims []domain.Claim, id domain.ConditionID) *domain.Claim {
	for i := range claims {
		if claims[i].ConditionID == id {
			return &claims[i]
		}
	}
	return nil
}

func allMandatoryTrue(c *domain.AnalysisCase) bool {
	if c.Exploit == nil || len(c.Exploit.MandatoryConditions) == 0 {
		return false
	}
	for _, cond := range c.Exploit.MandatoryConditions {
		claim := findClaim(c.Claims, cond.ID)
		if claim == nil || claim.Result != domain.ClaimTrue {
			return false
		}
	}
	return true
}

type NegativeCheck struct {
	Verifier *goanalysis.Verifier
}

func (NegativeCheck) State() domain.WorkflowState { return domain.StateNegativeCheck }

func (h NegativeCheck) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	for i := range c.Claims {
		cl := &c.Claims[i]
		if cl.Result != domain.ClaimFalse || cl.NegativeVerification != nil {
			continue
		}
		if h.Verifier == nil {
			cl.NegativeVerification = &domain.NegativeVerification{
				Status:      domain.NegativeInsufficientScope,
				Limitations: []string{"negative verifier not configured"},
				AnalysisGaps: []domain.AnalysisGap{
					negativeVerificationGap(c.ID, cl.ConditionID, "negative verifier not configured"),
				},
			}
			continue
		}
		cond := findCondition(c.Exploit, cl.ConditionID)
		if cond == nil {
			cl.NegativeVerification = &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "cannot resolve condition for falsification",
				AnalysisGaps: []domain.AnalysisGap{
					negativeVerificationGap(c.ID, cl.ConditionID, "cannot resolve condition for falsification"),
				},
			}
			continue
		}
		updated := h.Verifier.VerifyFalse(ctx, c, *cl, *cond)
		if updated.NegativeVerification != nil &&
			updated.NegativeVerification.Status == domain.NegativeContradicted {
			// the falsification attempt found a counterexample: the FALSE
			// claim cannot stand; demote it to UNKNOWN with the reason.
			updated.Limitations = append(updated.Limitations,
				"false claim contradicted by negative verification")
		}
		*cl = updated
	}
	c.EvidenceGraph.ComputeHash()
	return workflow.Transition{Next: domain.StateReview, Reason: "negative verification applied"}, nil
}

func findCondition(m *domain.ExploitModel, id domain.ConditionID) *domain.Condition {
	if m == nil {
		return nil
	}
	for i := range m.MandatoryConditions {
		if m.MandatoryConditions[i].ID == id {
			return &m.MandatoryConditions[i]
		}
	}
	for i := range m.SupportingFactors {
		if m.SupportingFactors[i].ID == id {
			return &m.SupportingFactors[i]
		}
	}
	return nil
}

type Review struct {
	Reviewer  review.Reviewer
	Evaluator evaluator.VerdictEvaluator
}

func (Review) State() domain.WorkflowState { return domain.StateReview }

func (h Review) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Reviewer == nil {
		c.EvidenceGraph.AddLimitation("reviewer not configured; proposed verdict not reviewed")
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review skipped: no reviewer"}, nil
	}
	maxIt := c.Workflow.Limits.MaxReviewIterations
	if maxIt <= 0 {
		maxIt = 2
	}
	if len(c.Reviews) >= maxIt {
		reason := "review iteration budget exhausted; unresolved criticism blocks a final verdict"
		c.AnalysisGaps = appendGap(c.AnalysisGaps, analysisGap(domain.GapOwnerProof,
			domain.GapReviewUnresolved, domain.ObligationCondition, c.ID, reason))
		c.EvidenceGraph.AddLimitation(reason)
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: reason}, nil
	}

	// The proposed verdict is computed deterministically before review;
	// the reviewer may only repair claims, never set the verdict.
	proposed := h.Evaluator.Evaluate(evaluator.VerdictInput{
		Product:       c.Product,
		Affected:      affectedOf(c),
		Model:         exploitOf(c),
		Claims:        c.Claims,
		Evidence:      c.EvidenceGraph.EvidenceList(),
		Vulnerability: c.Vulnerability,
		RootCause:     c.RootCause,
		RecordPin:     c.RecordPin,
		AdvisoryRecord: c.AdvisoryRecord,
	})
	rev := h.Reviewer.Review(c, proposed)
	rev.ID = domain.ReviewID(fmt.Sprintf("REV-%d", len(c.Reviews)+1))
	c.Reviews = append(c.Reviews, rev)
	c.IncReviewIterations()
	c.EvidenceGraph.ComputeHash()

	if rev.Result != domain.ReviewRevise {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review ACCEPT"}, nil
	}
	if c.StrictLLM {
		for _, f := range rev.Findings {
			if strings.HasPrefix(f.Problem, "strict-llm:") {
				gap := analysisGap(domain.GapOwnerProof, domain.GapReviewUnresolved,
					domain.ObligationCondition, c.ID, f.Problem)
				c.AnalysisGaps = appendGap(c.AnalysisGaps, gap)
				c.Verdict = nil
				return workflow.Transition{Next: domain.StateBuildReport, Reason: f.Problem}, nil
			}
		}
	}
	// REVISE routes through the repair state; after bounded repair the case
	// re-enters REVIEW so the reviewer audits the repaired claim set.
	return workflow.Transition{Next: domain.StateRepairAnalysis, Reason: "review REVISE"}, nil
}

// RepairAnalysis applies the bounded repair for the latest review's
// findings. High-severity claim findings demote the claim to UNKNOWN.
// Condition actions are nominations, not mutations: a demote is applied
// only when the deterministic applicability contract names a concrete
// mechanism mismatch for that condition, and a promote is never applied
// because no contract establishes necessity (a no-mismatch applicability
// result is not proof). An unresolved high-severity condition criticism
// stays in PendingConditionReviews so the verdict cannot close around it.
// Repairs never edit a claim's result, falsifier, evidence or
// negative-verification record, and never set the verdict. A repaired
// case goes back to REVIEW so the reviewer sees the repaired package; an
// unrepairable finding (model/verdict targets) falls through to the
// verdict.
type RepairAnalysis struct{}

func (RepairAnalysis) State() domain.WorkflowState { return domain.StateRepairAnalysis }

func (RepairAnalysis) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if len(c.Reviews) == 0 {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "repair without a review"}, nil
	}
	rev := c.Reviews[len(c.Reviews)-1]
	reviewID := rev.ID
	if reviewID == "" {
		reviewID = domain.ReviewID(fmt.Sprintf("REV-%d", len(c.Reviews)))
	}
	repaired := false

	if c.Exploit != nil {
		// Condition actions are nominations. A demote is applied only when
		// the deterministic applicability contract names a concrete
		// mechanism mismatch for that condition; an empty result means no
		// mismatch was detected, not that necessity is proved. A promote
		// has no deterministic proof channel at all, so it never applies.
		actions := conditionActions(rev.Findings)
		for _, id := range sortedConditionIDs(actions) {
			cond := findCondition(c.Exploit, id)
			if cond == nil {
				continue
			}
			switch actions[id] {
			case domain.ReviewActionDemote:
				if !hasMandatoryCondition(c.Exploit, id) {
					continue
				}
				mismatch := exploit.ValidateConditionApplicability(c.Vulnerability, c.RootCause, *cond)
				if mismatch == "" {
					// An unproven demotion may not narrow the conjunction,
					// and closure may not proceed around the open critique.
					if !slices.Contains(c.Exploit.PendingConditionReviews, id) {
						c.Exploit.PendingConditionReviews = append(c.Exploit.PendingConditionReviews, id)
					}
					c.EvidenceGraph.AddLimitation(fmt.Sprintf(
						"condition %s demote nomination in review %s was not applied: no deterministic applicability mismatch; the critique remains pending and blocks closure",
						id, reviewID))
					continue
				}
				if demoteCondition(c.Exploit, id) {
					repaired = true
					c.EvidenceGraph.AddLimitation(fmt.Sprintf(
						"condition %s demoted to supporting by deterministic applicability mismatch on review %s: %s (%s)",
						id, reviewID,
						conditionActionProblem(rev.Findings, id, domain.ReviewActionDemote), mismatch))
				}
				removePendingConditionReview(c.Exploit, id)
			case domain.ReviewActionPromote:
				c.EvidenceGraph.AddLimitation(fmt.Sprintf(
					"condition %s promote nomination in review %s was not applied: no deterministic necessity proof exists (a no-mismatch applicability result does not prove necessity); the condition keeps its current necessity",
					id, reviewID))
			}
		}
		// An action-less high finding on a mandatory condition is an
		// unresolved critique of the conjunction, not a caveat to attach
		// next to a closure verdict.
		for _, f := range rev.Findings {
			if f.Severity != "high" || f.TargetType != "condition" || f.TargetID == "" {
				continue
			}
			if f.Action == domain.ReviewActionPromote || f.Action == domain.ReviewActionDemote {
				continue
			}
			id := domain.ConditionID(f.TargetID)
			// An explicit action in the same review already resolves this
			// condition's critique: a duplicate action-less finding must
			// not re-open it as pending.
			if _, acted := actions[id]; acted {
				continue
			}
			if !hasMandatoryCondition(c.Exploit, id) {
				continue
			}
			if !slices.Contains(c.Exploit.PendingConditionReviews, id) {
				c.Exploit.PendingConditionReviews = append(c.Exploit.PendingConditionReviews, id)
			}
		}
	}

	for _, f := range rev.Findings {
		if f.Severity != "high" {
			continue
		}
		if f.TargetType != "claim" {
			continue
		}
		for i := range c.Claims {
			if string(c.Claims[i].ID) != f.TargetID || c.Claims[i].Result == domain.ClaimUnknown {
				continue
			}
			// A TRUE claim backed by deterministic evidence is verified fact —
			// a reviewer's reinterpretation cannot undo it; the concern is
			// recorded as a caveat instead. FALSE claims stay demotable:
			// negative verification is weaker by nature.
			if c.Claims[i].Result == domain.ClaimTrue &&
				strings.HasPrefix(c.Claims[i].Producer, "evaluator.") &&
				claimHasDeterministicEvidence(c, &c.Claims[i]) {
				c.Claims[i].Limitations = append(c.Claims[i].Limitations,
					"reviewer concern (claim kept: deterministic evidence): "+f.Problem)
				continue
			}
			// A VERIFIED FALSE was already re-checked against dynamic
			// markers and coverage: it falls to a structural defect —
			// evidence the claim cites but the graph lacks — or to a
			// finding that cites a concrete counterexample artifact found
			// in the claim's own record. Semantic reinterpretation or a
			// merely proposed check is advisory — the deterministic
			// negative stands.
			nv := c.Claims[i].NegativeVerification
			if c.Claims[i].Result == domain.ClaimFalse &&
				nv != nil && nv.Status == domain.NegativeVerified &&
				!claimCitesMissingEvidence(c, &c.Claims[i]) &&
				!citesConcreteArtifact(c, &c.Claims[i], f) {
				c.Claims[i].Limitations = append(c.Claims[i].Limitations,
					"reviewer concern (VERIFIED FALSE kept: no concrete artifact cited): "+f.Problem)
				continue
			}
			c.Claims[i].Result = domain.ClaimUnknown
			c.Claims[i].Limitations = append(c.Claims[i].Limitations,
				"demoted by reviewer: "+f.Problem)
			repaired = true
		}
	}
	if !repaired {
		return workflow.Transition{Next: domain.StateEvaluateVerdict,
			Reason: "review REVISE: no repairable conditions or claims"}, nil
	}
	return workflow.Transition{Next: domain.StateReview,
		Reason: "repaired conditions and claims; re-review"}, nil
}

// conditionActions resolves the explicit high-severity condition actions
// in one review by target ID. An unknown or missing action carries no
// nomination semantics; for a promote/demote conflict on the same ID the
// demote wins regardless of order.
func conditionActions(findings []domain.ReviewFinding) map[domain.ConditionID]domain.ReviewAction {
	actions := map[domain.ConditionID]domain.ReviewAction{}
	for _, f := range findings {
		if f.Severity != "high" || f.TargetType != "condition" || f.TargetID == "" {
			continue
		}
		id := domain.ConditionID(f.TargetID)
		switch f.Action {
		case domain.ReviewActionDemote:
			actions[id] = domain.ReviewActionDemote
		case domain.ReviewActionPromote:
			if actions[id] != domain.ReviewActionDemote {
				actions[id] = domain.ReviewActionPromote
			}
		}
	}
	return actions
}

func sortedConditionIDs(actions map[domain.ConditionID]domain.ReviewAction) []domain.ConditionID {
	ids := make([]domain.ConditionID, 0, len(actions))
	for id := range actions {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func conditionActionProblem(findings []domain.ReviewFinding, id domain.ConditionID, action domain.ReviewAction) string {
	for _, f := range findings {
		if f.Severity == "high" && f.TargetType == "condition" &&
			f.TargetID == string(id) && f.Action == action {
			return f.Problem
		}
	}
	return ""
}

// demoteCondition physically moves the condition out of the mandatory
// conjunction into supporting factors. The condition record (claim,
// evidence, verification) is untouched; only its necessity changes. The
// only caller applies it after the deterministic applicability contract
// named a concrete mismatch — a reviewer request alone never demotes. The
// operation is idempotent: an already-demoted condition is not duplicated.
func demoteCondition(m *domain.ExploitModel, id domain.ConditionID) bool {
	idx := -1
	for i := range m.MandatoryConditions {
		if m.MandatoryConditions[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	cond := m.MandatoryConditions[idx]
	cond.Mandatory = false
	m.MandatoryConditions = append(m.MandatoryConditions[:idx], m.MandatoryConditions[idx+1:]...)
	for i := range m.SupportingFactors {
		if m.SupportingFactors[i].ID == id {
			m.SupportingFactors[i].Mandatory = false
			return true
		}
	}
	m.SupportingFactors = append(m.SupportingFactors, cond)
	return true
}

func hasMandatoryCondition(m *domain.ExploitModel, id domain.ConditionID) bool {
	for i := range m.MandatoryConditions {
		if m.MandatoryConditions[i].ID == id {
			return true
		}
	}
	return false
}

func removePendingConditionReview(m *domain.ExploitModel, id domain.ConditionID) {
	if len(m.PendingConditionReviews) == 0 {
		return
	}
	kept := m.PendingConditionReviews[:0]
	for _, pending := range m.PendingConditionReviews {
		if pending != id {
			kept = append(kept, pending)
		}
	}
	if len(kept) == 0 {
		m.PendingConditionReviews = nil
		return
	}
	m.PendingConditionReviews = kept
}

// claimCitesMissingEvidence reports whether the claim references evidence
// ids the graph does not hold — a structural defect that cannot be waved
// away by semantic review and demotes the claim unconditionally.
func claimCitesMissingEvidence(c *domain.AnalysisCase, cl *domain.Claim) bool {
	present := map[domain.EvidenceID]bool{}
	for _, e := range c.EvidenceGraph.Evidence {
		present[e.ID] = true
	}
	ids := append([]domain.EvidenceID{}, cl.EvidenceIDs...)
	if cl.NegativeVerification != nil {
		ids = append(ids, cl.NegativeVerification.EvidenceIDs...)
	}
	for _, id := range ids {
		if !present[id] {
			return true
		}
	}
	return false
}

// citesConcreteArtifact reports whether a review finding points at a
// concrete counterexample against this verified negative claim — one that
// is both named in the finding's problem and found in the claim's own
// record: a dynamic marker, a traced external origin, an uncovered site
// (file:line), or one of the claim's evidence ids. required_check is not
// scanned: it names a desired check outcome, not a found artifact.
func citesConcreteArtifact(c *domain.AnalysisCase, cl *domain.Claim, f domain.ReviewFinding) bool {
	var cited, citedSites []string
	for _, p := range artifactPatterns {
		cited = append(cited, p.FindAllString(f.Problem, -1)...)
	}
	citedIDs := evidenceIDPattern.FindAllString(f.Problem, -1)
	citedSites = sitePattern.FindAllString(f.Problem, -1)
	if len(cited)+len(citedIDs)+len(citedSites) == 0 {
		return false
	}
	linked, sites, corpus := claimArtifactCorpus(c, cl)
	for _, id := range citedIDs {
		if linked[id] {
			return true
		}
	}
	for _, tok := range cited {
		if strings.Contains(corpus, tok) {
			return true
		}
	}
	for _, s := range citedSites {
		if sites[s] {
			return true
		}
	}
	return false
}

// claimArtifactCorpus collects the weakening artifacts recorded for a
// claim's verified negative: its cited evidence ids, the verification
// limitations (the record where weakening markers land), and the origins
// of flows traced for its condition. Everything else is deliberately
// excluded because it documents what the verification accounted for, not
// what weakens it: nv.Notes carry the positive outcome and dismissed
// markers ("unrelated go:linkname pragma(s) ignored"), marker evidence
// records dismissed markers verbatim, validations and benign flow sites
// document coverage, the evaluator explanation and claim limitations are
// rationale/process text — the last also lets a rejected finding cite
// itself. A marker that weakened verification is substantiable through
// its limitation line (kind phrase, and file:line for write-markers);
// a marker the verifier dismissed has no limitation and must not
// substantiate.
func claimArtifactCorpus(c *domain.AnalysisCase, cl *domain.Claim) (linked, sites map[string]bool, corpus string) {
	var ids []domain.EvidenceID
	ids = append(ids, cl.EvidenceIDs...)
	if cl.NegativeVerification != nil {
		ids = append(ids, cl.NegativeVerification.EvidenceIDs...)
	}
	linked = map[string]bool{}
	for _, id := range ids {
		linked[string(id)] = true
	}
	var b strings.Builder
	if cl.NegativeVerification != nil {
		for _, l := range cl.NegativeVerification.Limitations {
			b.WriteString(l + "\n")
		}
	}
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID != cl.ConditionID && f.ConditionID != "" {
			continue
		}
		b.WriteString(string(f.Origin) + "\n")
	}
	corpus = b.String()
	sites = map[string]bool{}
	for _, tok := range sitePattern.FindAllString(corpus, -1) {
		file, line, ok := strings.Cut(tok, ":")
		if !ok {
			continue
		}
		// Every path suffix is a valid citation: a finding may write the
		// site as a/b.go:41, pkg/a/b.go:41 or the full recorded path.
		for i := 0; i < len(file); {
			sites[file[i:]+":"+line] = true
			j := strings.IndexByte(file[i:], '/')
			if j < 0 {
				break
			}
			i += j + 1
		}
	}
	return linked, sites, corpus
}

// artifactPatterns recognize the artifact citations that legitimately refute
// a VERIFIED negative: dynamic marker kinds (goanalysis ScanDynamic kinds and
// the negative-scope extensions), the marker phrases negative verification
// itself records, and traced external origins.
var artifactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\breflect_write\b|\bunsafe_write\b|\bunsafe_ptr\b|\bfunc_value\b|\blinkname\b|\bgo:linkname\b`),
	regexp.MustCompile(`\breflect\s+(import|usage)\b|\breflect\.Value\b|\bunsafe\s+(import|usage)\b|\bunsafe\.(Pointer|Add)\b|\bplugins?\s+(import|usage)\b|\bgoroutines?\b`),
	regexp.MustCompile(`interface[- ]dispatch|build[- ]tags?`),
	regexp.MustCompile(`\bEXTERNAL_UNTRUSTED\b|\bEXTERNAL_AUTHENTICATED\b|\bCONFIGURATION\b|\bDATABASE\b|\bINTERNAL_SERVICE\b`),
}

// sitePattern extracts file.go:line citations; the charset allows only
// path characters, so markdown/quote delimiters wrapping a citation
// (`server.go:41`, "server.go:41", **server.go:41**) are not part of the
// token. A cited site substantiates only against an exact recorded site,
// never a line-prefix match.
var sitePattern = regexp.MustCompile(`[\w./~-]+\.go:\d+`)

// evidenceIDPattern extracts evidence-id citations; a cited id must be one
// of the claim's own to substantiate.
var evidenceIDPattern = regexp.MustCompile(`\bEV-\d+\b`)

// claimHasDeterministicEvidence reports whether any evidence attached to the
// claim carries deterministic quality (tool output, not LLM inference).
func claimHasDeterministicEvidence(c *domain.AnalysisCase, cl *domain.Claim) bool {
	if len(cl.EvidenceIDs) == 0 {
		return false
	}
	byID := map[domain.EvidenceID]domain.EvidenceQuality{}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		byID[e.ID] = e.Quality
	}
	for _, id := range cl.EvidenceIDs {
		if q := byID[id]; q == domain.QualityDeterministic || q == domain.QualityAuthoritative {
			return true
		}
	}
	return false
}

func affectedOf(c *domain.AnalysisCase) domain.AffectedResult {
	if c.Affected != nil {
		return *c.Affected
	}
	return domain.AffectedResult{}
}

func exploitOf(c *domain.AnalysisCase) domain.ExploitModel {
	if c.Exploit != nil {
		return *c.Exploit
	}
	return domain.ExploitModel{}
}

func cloneCaseForRisk(c *domain.AnalysisCase, claims []domain.Claim, trustedPeer bool) *domain.AnalysisCase {
	cloned := &domain.AnalysisCase{
		ID:            c.ID,
		Vulnerability: c.Vulnerability,
		Product:       c.Product,
		Claims:        claims,
	}
	cloned.Product.TrustedPeer = trustedPeer
	for _, exp := range c.EvidenceGraph.ExposuresList() {
		cloned.EvidenceGraph.AddExposure(exp)
	}
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		cloned.EvidenceGraph.AddEvidence(ev)
	}
	return cloned
}

type EvaluateVerdict struct {
	Evaluator evaluator.VerdictEvaluator
	// Next is the state after the record's profile assessments. Empty keeps
	// the historical BUILD_REPORT transition; root orchestration sets
	// ASSESS_RELATED_RECORDS and record-only runs stop at BUILD_REPORT.
	Next domain.WorkflowState
}

func (EvaluateVerdict) State() domain.WorkflowState { return domain.StateEvaluateVerdict }

func (h EvaluateVerdict) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	affected := affectedOf(c)
	model := exploitOf(c)
	build := domain.EffectiveBuildContext(c.Product)
	stampCaseGapIDs(c)

	// Both profile claim sets are captured before the actual-profile
	// assignment overwrites c.Claims. The cluster-perimeter set stays a
	// hypothesis: it is only rewritten into trusted-infrastructure facts when
	// the typed perimeter basis independently admits trust.
	claimsZT := append([]domain.Claim(nil), c.Claims...)
	claimsCP := append([]domain.Claim(nil), c.Claims...)

	conds := make(map[domain.ConditionID]domain.Condition, len(model.MandatoryConditions)+len(model.SupportingFactors))
	for _, cond := range model.MandatoryConditions {
		conds[cond.ID] = cond
	}
	for _, cond := range model.SupportingFactors {
		conds[cond.ID] = cond
	}

	operatorAsserted := c.Product.TrustedPeer ||
		(c.Product.PerimeterOverride != "" && c.Product.PerimeterOverride != "auto")
	trustAdmitted := operatorAsserted ||
		(c.PerimeterAssessment != nil && c.PerimeterAssessment.AllowsTrustedPeerSelection())
	profileBasis := domain.BasisDeclaredTrust
	rewritten := make([]bool, len(claimsCP))
	if trustAdmitted {
		for i := range claimsCP {
			cl := &claimsCP[i]
			// A proven library public-API payload path is a code-level positive:
			// the cluster-perimeter trust heuristic speaks about deployment peer
			// input, so it must not replace this claim with trusted-infrastructure
			// FALSE. The library boundary is reported through the scope axis.
			if cl.Result == domain.ClaimTrue && cl.ControlBasis == domain.ControlBasisLibraryPublicAPI {
				continue
			}
			cond := conds[cl.ConditionID]
			isPeerInput := (cond.Kind == domain.ConditionAttackerControl || cond.Kind == domain.ConditionInputConstraint) &&
				cond.Params[domain.ParamInputSource] != domain.InputArg &&
				cond.Params[domain.ParamInputSource] != domain.InputConfig &&
				evaluator.WantsPeerInput(cond, c.Vulnerability)
			if isPeerInput || cl.Falsifier == domain.FalsifierTrustedInfrastructure {
				if cl.Result != domain.ClaimFalse {
					rewritten[i] = true
					cl.Falsifier = domain.FalsifierTrustedInfrastructure
				}
				cl.Result = domain.ClaimFalse
				if cl.Falsifier == "" {
					cl.Falsifier = domain.FalsifierTrustedInfrastructure
				}
				if cl.Falsifier == domain.FalsifierTrustedInfrastructure {
					if evaluator.HasConfigOriginOutbound(c, c.Vulnerability.Module) {
						cl.FalsifierBasis = domain.BasisConfigOrigin
						// The config-origin basis is a code trace measured under
						// this build: without an admitted target it cannot be
						// verified, so no VERIFIED record is fabricated.
						if domain.ValidateNegativeTarget(c.Product) == nil {
							build := domain.EffectiveBuildContext(c.Product)
							cl.NegativeVerification = &domain.NegativeVerification{
								Status:       domain.NegativeVerified,
								Notes:        "outbound destination endpoints are statically configured or loaded from trusted configuration (config-origin)",
								BuildContext: &build,
							}
						}
					} else if cl.FalsifierBasis == "" {
						cl.FalsifierBasis = profileBasis
					}
				}
				if cl.Explanation == "" {
					if cl.FalsifierBasis == domain.BasisConfigOrigin {
						cl.Explanation = "outbound destination endpoints are statically configured or loaded from trusted configuration (config-origin)"
					} else {
						cl.Explanation = "FALSE is decided by trusted cluster infrastructure / perimeter"
					}
				}
				if cl.NegativeVerification == nil {
					cl.NegativeVerification = &domain.NegativeVerification{
						Status: domain.NegativeVerified,
						Notes:  "FALSE is decided by product snapshot deployment trust facts (cluster-internal perimeter)",
					}
				}
			}
		}
	}

	ztResult := finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:   c.Product,
			Affected:  affected,
			Model:     model,
			Claims:    claimsZT,
			Evidence:  c.EvidenceGraph.EvidenceList(),
			RecordPin: c.RecordPin,
			AdvisoryRecord: c.AdvisoryRecord,
		},
		RootCause:     c.RootCause,
		Vulnerability: c.Vulnerability,
		Gaps:          c.AnalysisGaps,
		AssessmentID:  c.ID,
	})
	cpResult := finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:   c.Product,
			Affected:  affected,
			Model:     model,
			Claims:    claimsCP,
			Evidence:  c.EvidenceGraph.EvidenceList(),
			RecordPin: c.RecordPin,
			AdvisoryRecord: c.AdvisoryRecord,
		},
		RootCause:     c.RootCause,
		Vulnerability: c.Vulnerability,
		Gaps:          c.AnalysisGaps,
		AssessmentID:  c.ID,
	})
	ztResult.Limitations = append(ztResult.Limitations, c.EvidenceGraph.Limitations...)
	cpResult.Limitations = append(cpResult.Limitations, c.EvidenceGraph.Limitations...)
	if !trustAdmitted {
		cpResult.Limitations = append(cpResult.Limitations,
			"hypothetical cluster-perimeter profile: the recorded deployment basis does not establish trusted peers, so no trusted-peer rewrite was applied and this result must not be read as a deployment fact")
	}
	// An operator assertion cannot discharge sinks the exploit model never
	// resolved: a perimeter-rewritten FALSE covers only the modeled
	// conditions, so the unmodeled exploit shape stays unproven and the
	// assessment fails with a reachability gap.
	demoteOperatorNEPF(&cpResult, operatorAsserted, rewritten, claimsCP, model, c.ID)

	setGroundBasis(claimsZT, ztResult.Verdict)
	setGroundBasis(claimsCP, cpResult.Verdict)

	cRiskZT := riskForAssessment(c.Vulnerability, cloneCaseForRisk(c, claimsZT, false), ztResult)
	cRiskCP := riskForAssessment(c.Vulnerability, cloneCaseForRisk(c, claimsCP, true), cpResult)

	// A trusted-peer actual profile exists only when the typed perimeter
	// basis admitted trust (an operator declaration or an admitted deployment
	// policy). Listener locality and ClusterIP topology select nothing.
	isClusterTarget := trustAdmitted

	ztProfile := domain.ProfileVerdict{
		Profile:             domain.ProfileZeroTrust,
		Title:               "Внешний периметр (Zero Trust / Недоверенный пир)",
		Verdict:             verdictOf(ztResult),
		Reason:              assessmentReason(ztResult),
		Priority:            cRiskZT.Priority,
		SLA:                 cRiskZT.SLA,
		IsTargetActual:      !isClusterTarget,
		ExploitabilityScope: scopeOf(ztResult),
	}
	cpProfile := domain.ProfileVerdict{
		Profile:             domain.ProfileClusterPerimeter,
		Title:               "Внутренний кластер (K8s ClusterIP / Service Mesh)",
		Verdict:             verdictOf(cpResult),
		Reason:              assessmentReason(cpResult),
		Falsifier:           falsifierOf(cpResult, claimsCP),
		Priority:            cRiskCP.Priority,
		SLA:                 cRiskCP.SLA,
		IsTargetActual:      isClusterTarget,
		ExploitabilityScope: scopeOf(cpResult),
	}
	c.Profiles = []domain.ProfileVerdict{ztProfile, cpProfile}
	c.ProfileAssessments = []domain.ProfileAssessment{
		profileAssessment(domain.ProfileZeroTrust, !isClusterTarget, build, claimsZT, ztResult, &cRiskZT),
		profileAssessment(domain.ProfileClusterPerimeter, isClusterTarget, build, claimsCP, cpResult, &cRiskCP),
	}

	actual := ztResult
	actualClaims := claimsZT
	actualRisk := cRiskZT
	if isClusterTarget {
		actual = cpResult
		actualClaims = claimsCP
		actualRisk = cRiskCP
	}
	c.Claims = actualClaims
	c.Verdict = actual.Verdict
	c.ContextualRisk = &actualRisk
	c.AnalysisGaps = append([]domain.AnalysisGap(nil), actual.Gaps...)

	reason := "assessment FAILED"
	if actual.Verdict != nil {
		reason = "verdict evaluated: " + string(actual.Verdict.Verdict)
	}
	next := h.Next
	if next == "" {
		next = domain.StateBuildReport
	}
	return workflow.Transition{Next: next, Reason: reason}, nil
}

// stampCaseGapIDs binds every producer-emitted gap to this assessment once.
// Producers that do not know the case id leave the field empty; an unbound gap
// cannot be validated or re-admitted on replay.
func stampCaseGapIDs(c *domain.AnalysisCase) {
	id := assessmentIDFor(c)
	stamp := func(gaps []domain.AnalysisGap) {
		for i := range gaps {
			if gaps[i].AssessmentID == "" {
				gaps[i].AssessmentID = id
			}
		}
	}
	stamp(c.AnalysisGaps)
	if c.Affected != nil {
		stamp(c.Affected.AnalysisGaps)
	}
	if c.RootCause != nil {
		stamp(c.RootCause.AnalysisGaps)
	}
	for i := range c.Claims {
		stamp(c.Claims[i].AnalysisGaps)
		if nv := c.Claims[i].NegativeVerification; nv != nil {
			stamp(nv.AnalysisGaps)
		}
	}
}

func assessmentIDFor(c *domain.AnalysisCase) domain.CaseID {
	if c != nil && c.ID != "" {
		return c.ID
	}
	return domain.CaseID("assessment")
}

func normalizeAssessmentID(id domain.CaseID) domain.CaseID {
	if id != "" {
		return id
	}
	return domain.CaseID("assessment")
}

// appendGap appends a typed diagnostic once. A re-entered analysis state or a
// resumed case must not multiply the same cause.
func appendGap(gaps []domain.AnalysisGap, gap domain.AnalysisGap) []domain.AnalysisGap {
	for _, existing := range gaps {
		if existing.Owner == gap.Owner && existing.Code == gap.Code &&
			existing.Obligation == gap.Obligation && existing.ConditionID == gap.ConditionID &&
			existing.Message == gap.Message {
			return gaps
		}
	}
	return append(gaps, gap)
}

func analysisGap(owner domain.GapOwner, code domain.GapCode, obligation domain.Obligation,
	id domain.CaseID, message string) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:        owner,
		Code:         code,
		Obligation:   obligation,
		AssessmentID: normalizeAssessmentID(id),
		Message:      message,
	}
}

func rootCauseGap(id domain.CaseID, message string) domain.AnalysisGap {
	return analysisGap(domain.GapOwnerCode, domain.GapRootCauseUnresolved,
		domain.ObligationRootCause, id, message)
}

func inputGap(id domain.CaseID, obligation domain.Obligation, message string) domain.AnalysisGap {
	return analysisGap(domain.GapOwnerInput, domain.GapInputResolutionFailed, obligation, id, message)
}

func measurementGap(id domain.CaseID, obligation domain.Obligation, message string) domain.AnalysisGap {
	return analysisGap(domain.GapOwnerProof, domain.GapMeasurementNotCompleted, obligation, id, message)
}

func negativeVerificationGap(id domain.CaseID, condition domain.ConditionID, message string) domain.AnalysisGap {
	gap := analysisGap(domain.GapOwnerProof, domain.GapNegativeVerificationIncomplete,
		domain.ObligationCondition, id, message)
	gap.ConditionID = condition
	return gap
}

func budgetConditionGap(c *domain.AnalysisCase, condition domain.ConditionID, message string) domain.AnalysisGap {
	gap := analysisGap(domain.GapOwnerCode, domain.GapAnalysisBudgetExhausted,
		domain.ObligationCondition, assessmentIDFor(c), message)
	gap.ConditionID = condition
	return gap
}

// appendClaimGap attaches a cause to the claim that owns the condition, or to
// the case when the claim set no longer carries it.
func appendClaimGap(c *domain.AnalysisCase, condition domain.ConditionID, gap domain.AnalysisGap) {
	if cl := findClaim(c.Claims, condition); cl != nil {
		cl.AnalysisGaps = appendGap(cl.AnalysisGaps, gap)
		return
	}
	c.AnalysisGaps = appendGap(c.AnalysisGaps, gap)
}

// unresolvedConditionGap records the producer-side cause for a mandatory
// condition the bounded gap loop could not resolve. It routes on the typed
// condition kind, never on limitation text.
func unresolvedConditionGap(c *domain.AnalysisCase, cond domain.Condition) domain.AnalysisGap {
	code := domain.GapUnclassifiedAnalysisGap
	switch cond.Kind {
	case domain.ConditionSymbolReachable:
		code = domain.GapReachabilityProofIncomplete
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
		code = domain.GapInputTraceIncomplete
	case domain.ConditionCheckTrigger, domain.ConditionCheckInput:
		code = domain.GapTriggerProofIncomplete
	}
	gap := analysisGap(domain.GapOwnerCode, code, domain.ObligationCondition,
		assessmentIDFor(c),
		fmt.Sprintf("gap analysis exhausted without resolving %s condition %s", cond.Kind, cond.ID))
	gap.ConditionID = cond.ID
	return gap
}

// failureTransition records an analysis failure and routes it to the verdict
// evaluator (which produces failed profile assessments) or, for strict-LLM
// aborts, straight to report writing with no verdict. Analysis failures never
// terminate before the diagnostic deliverable exists.
func failureTransition(c *domain.AnalysisCase, gap domain.AnalysisGap, strict bool) workflow.Transition {
	c.AnalysisGaps = appendGap(c.AnalysisGaps, gap)
	c.EvidenceGraph.AddLimitation(gap.Message)
	if strict {
		c.Verdict = nil
		return workflow.Transition{Next: domain.StateBuildReport, Reason: gap.Message}
	}
	return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: gap.Message}
}

// demoteOperatorNEPF turns a declared-trust NEPF into an explicit analysis
// failure when the exploit model leaves an advisory-declared sink unresolved.
// An operator's trust assertion cannot discharge an exploit shape the model
// never covered; the claim set is preserved, only the verdict is withheld.
func demoteOperatorNEPF(result *domain.AssessmentResult, operatorAsserted bool, rewritten []bool,
	claims []domain.Claim, model domain.ExploitModel, id domain.CaseID) {
	if !operatorAsserted || result == nil || result.Verdict == nil ||
		result.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		return
	}
	absent := make(map[domain.SymbolRef]bool, len(model.AbsentSubjects))
	for _, s := range model.AbsentSubjects {
		absent[s] = true
	}
	unmodeled := 0
	for _, s := range model.UnresolvedSubjects {
		if !absent[s] {
			unmodeled++
		}
	}
	if unmodeled == 0 {
		return
	}
	demote := false
	for _, cid := range result.Verdict.ConditionIDs {
		for i := range claims {
			if claims[i].ConditionID == cid && rewritten[i] {
				demote = true
			}
		}
	}
	if !demote {
		return
	}
	reason := fmt.Sprintf(
		"cluster-perimeter verdict rests on a declared trust boundary, but %d advisory-declared subject(s) are unresolved: an operator assertion cannot discharge an unmodeled exploit shape",
		unmodeled)
	result.Outcome = domain.OutcomeFailed
	result.Verdict = nil
	result.Gaps = append(result.Gaps, domain.AnalysisGap{
		Owner:        domain.GapOwnerCode,
		Code:         domain.GapReachabilityProofIncomplete,
		Obligation:   domain.ObligationCondition,
		AssessmentID: id,
		Message:      reason,
	})
	result.Limitations = append(result.Limitations, reason)
}

// riskForAssessment derives the profile risk from the earned verdict. A failed
// assessment carries an explicitly unassessed risk: a stale DISMISSED priority
// beside a failure would read as a safe conclusion.
func riskForAssessment(v domain.Vulnerability, c *domain.AnalysisCase, result domain.AssessmentResult) domain.ContextualRisk {
	if result.Verdict != nil {
		return risk.Assess(v, c, *result.Verdict)
	}
	r := risk.Assess(v, c, domain.VerdictResult{Verdict: domain.VerdictInconclusive})
	r.Status = domain.RiskStatusUnassessed
	r.AdjustmentReason = "Assessment FAILED: no verdict was earned, so the analysis is incomplete and must not be read as safe."
	return r
}

func verdictOf(result domain.AssessmentResult) domain.Verdict {
	if result.Verdict == nil {
		return ""
	}
	return result.Verdict.Verdict
}

func scopeOf(result domain.AssessmentResult) domain.ExploitabilityScope {
	if result.Verdict == nil {
		return ""
	}
	return result.Verdict.ExploitabilityScope
}

func assessmentReason(result domain.AssessmentResult) string {
	if result.Verdict != nil {
		return result.Verdict.Reason
	}
	parts := make([]string, 0, len(result.Gaps))
	for _, g := range result.Gaps {
		parts = append(parts, string(g.Code)+": "+g.Message)
	}
	if len(parts) == 0 {
		return "analysis FAILED without a typed cause"
	}
	return "analysis FAILED: " + strings.Join(parts, "; ")
}

func falsifierOf(result domain.AssessmentResult, claims []domain.Claim) domain.FalsifierKind {
	if result.Verdict == nil {
		return ""
	}
	var out domain.FalsifierKind
	for _, id := range result.Verdict.ConditionIDs {
		for _, cl := range claims {
			if cl.ConditionID == id && cl.Falsifier != "" {
				out = domain.FalsifierKind(cl.Falsifier)
			}
		}
	}
	return out
}

func profileAssessment(profile domain.ThreatProfile, actual bool, build domain.BuildContext,
	claims []domain.Claim, result domain.AssessmentResult, risk *domain.ContextualRisk) domain.ProfileAssessment {
	return domain.ProfileAssessment{
		Profile:        profile,
		IsTargetActual: actual,
		Build:          build,
		Claims:         append([]domain.Claim(nil), claims...),
		Result:         result,
		ContextualRisk: risk,
	}
}

// setGroundBasis records what a NO_EXPLOIT_PATH_FOUND verdict rests on
// when the grounding claim is trusted-infrastructure: the claim's
// FalsifierBasis distinguishes operator assertion from detected perimeter
// and code-level config origin. Non-trust-grounded verdicts keep
// GroundBasis empty — their falsifier is already code-level.
func setGroundBasis(claims []domain.Claim, v *domain.VerdictResult) {
	if v == nil || v.Verdict != domain.VerdictNoExploitPathFound {
		return
	}
	for _, id := range v.ConditionIDs {
		for _, cl := range claims {
			if cl.ConditionID != id {
				continue
			}
			if cl.Falsifier == domain.FalsifierTrustedInfrastructure {
				v.GroundBasis = cl.FalsifierBasis
				if v.GroundBasis == "" {
					v.GroundBasis = domain.BasisDeclaredTrust
				}
				return
			}
		}
	}
}

type BuildReport struct {
	Dir     string
	Tracker tracker.Sink
	// Prior is the previous stored run of the same vuln/repo pair; when
	// set, its tool_executions hashes are diffed against this run's.
	Prior *domain.AnalysisCase
}

// diffToolExecutions records the reproducibility-diff between a prior
// run's audit trail and this one as RUNTIME evidence — drift means the
// deterministic layer produced different outputs across runs.
func diffToolExecutions(c, prior *domain.AnalysisCase) {
	drift := toolaudit.DiffExecutions(prior.EvidenceGraph.ToolExecutions, c.EvidenceGraph.ToolExecutions)
	content := fmt.Sprintf("baseline=%s invocations: prior=%d current=%d drift=%d",
		prior.ID, len(prior.EvidenceGraph.ToolExecutions), len(c.EvidenceGraph.ToolExecutions), len(drift))
	if len(drift) > 0 {
		content += "\n" + strings.Join(drift, "\n")
	}
	c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
		Quality: domain.QualityDeterministic,
		Source:  "reproducibility-diff",
		Content: content,
	})
	if len(drift) > 0 {
		c.EvidenceGraph.AddLimitation(fmt.Sprintf(
			"reproducibility: %d tool invocation(s) drifted vs prior run %s", len(drift), prior.ID))
	}
}

func (BuildReport) State() domain.WorkflowState { return domain.StateBuildReport }

func (h BuildReport) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Prior != nil {
		diffToolExecutions(c, h.Prior)
	}
	// A request-orchestrated run must publish the requested-finding envelope
	// even when an earlier state short-circuited straight to reporting (a
	// strict-LLM abort). Composition is additive: it never rewrites the
	// primary's verdict, claims or census.
	if c.RelatedDiscovery != nil && c.RequestedFinding == nil {
		if err := finding.Finalize(c); err != nil {
			return workflow.Transition{}, fmt.Errorf("build report: compose requested finding: %w", err)
		}
	}
	if c.CVEAnalysisProfile == domain.ProfileAssist || c.CVEAnalysisProfile == domain.ProfileVerified || c.Justification != nil {
		dossier := justification.Build(c)
		c.Justification = &dossier
	}
	if c.ContextualRisk == nil && c.Verdict != nil {
		cRisk := risk.Assess(c.Vulnerability, c, *c.Verdict)
		c.ContextualRisk = &cRisk
	}
	if err := report.Write(h.Dir, c); err != nil {
		return workflow.Transition{}, fmt.Errorf("build report: %w", err)
	}
	if h.Tracker != nil {
		if err := h.Tracker.Publish(ctx, string(c.ID), report.Markdown(c)); err != nil {
			c.EvidenceGraph.AddToolLimitation("tracker publish failed: " + err.Error())
		}
	}
	// The diagnostic deliverable is written before the terminal state is
	// chosen: an analysis failure must still leave a report behind, and only
	// an earned requested outcome (definitive, external-dependency
	// INCONCLUSIVE or corpus-bounded negative) completes the run.
	if c.RequestedFinding != nil {
		if c.RequestedFinding.Outcome == domain.OutcomeFailed {
			return workflow.Transition{Next: domain.StateFailed, Reason: "requested assessment FAILED; diagnostic report written to " + h.Dir}, nil
		}
		return workflow.Transition{Next: domain.StateCompleted, Reason: "requested finding written to " + h.Dir}, nil
	}
	if c.Verdict == nil {
		return workflow.Transition{Next: domain.StateFailed, Reason: "analysis failed; diagnostic report written to " + h.Dir}, nil
	}
	return workflow.Transition{Next: domain.StateCompleted, Reason: "report written to " + h.Dir}, nil
}

// transportProofEntryRefs binds the rooted transport proof to the record's own
// affected entries. An admitted attribution that names the same record bytes is
// authoritative; otherwise the record's represented inventory refs are used.
func transportProofEntryRefs(c *domain.AnalysisCase) []int {
	if c == nil {
		return nil
	}
	if c.RecordPin != nil {
		for _, attribution := range c.Attributions {
			if attribution.Admitted() && len(attribution.EntryRefs) > 0 &&
				attribution.Candidate.Same(*c.RecordPin) {
				return append([]int(nil), attribution.EntryRefs...)
			}
		}
	}
	if c.Vulnerability.Scope != nil && c.Vulnerability.Scope.RecordInventory != nil {
		return append([]int(nil), c.Vulnerability.Scope.RecordInventory.RepresentedRefs...)
	}
	return nil
}

// collectTransportProof runs the rooted server-transport proof for cases whose
// exploit model needs peer input at a server transport. It records only
// evidence and typed gaps: an incomplete proof never becomes a claim, and the
// claim evaluators re-admit the persisted witness themselves.
//
// The model's need for the capability is not evidence that it applies, so the
// specialized checker runs only after the source index establishes
// applicability from the affected module's own source. A refusal is an
// observation, never a blocking gap: an unsupported transport leaves the
// ordinary evaluation in place for the human investigation to continue.
func (h CollectEvidence) collectTransportProof(ctx context.Context, c *domain.AnalysisCase) {
	if h.Source == nil || c.Exploit == nil {
		return
	}
	if !needsRootedTransportProof(c) {
		return
	}
	module := c.Vulnerability.Module
	if module == "" || isStdlibModule(module) {
		return
	}
	if c.RecordPin == nil {
		// The witness must pin the exact advisory bytes it was bound
		// to; without the pin the proof cannot be re-admitted, so it is
		// not attempted and the missing input is named.
		c.AnalysisGaps = append(c.AnalysisGaps, domain.AnalysisGap{
			Owner:        domain.GapOwnerInput,
			Code:         domain.GapInputResolutionFailed,
			Obligation:   domain.ObligationCondition,
			AssessmentID: c.ID,
			Message:      "rooted transport proof requires the exact advisory-record document pin; this case carries none",
		})
		return
	}
	fixURI, fixDigest, fixDiff := transportFixEvidence(c)
	applicability, err := h.Source.TransportApplicabilityFor(ctx, goanalysis.TransportProofScope{
		Record:    *c.RecordPin,
		EntryRefs: transportProofEntryRefs(c),
		Subjects:  transportProofSubjects(c),
		Product:   c.Product,
		FixURI:    fixURI,
		FixDigest: fixDigest,
		FixDiff:   fixDiff,
	})
	if err != nil {
		c.EvidenceGraph.AddToolLimitation("rooted transport applicability probe failed: " + err.Error())
		return
	}
	if applicability.Refused() {
		c.EvidenceGraph.AddLimitation(
			"rooted transport proof is not applicable: " + applicability.Reason())
		return
	}
	proof, err := h.Source.ProveServerTransport(ctx, applicability.Request)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation("rooted transport proof failed: " + err.Error())
		return
	}
	for _, ev := range proof.Evidence {
		c.EvidenceGraph.AddEvidence(ev)
	}
	if proof.Trigger != nil && proof.Trigger.Mechanism != "" {
		// The mechanism is a discovered fact, so the condition that must
		// discharge it records which one the witness proved. A replayed
		// claim is then checked against the mechanism it speaks about.
		recordTransportMechanism(c, proof.Trigger.Mechanism)
	}
	for _, gap := range proof.Gaps {
		if gap.AssessmentID == "" {
			gap.AssessmentID = c.ID
		}
		c.AnalysisGaps = append(c.AnalysisGaps, gap)
	}
}

// needsRootedTransportProof reports whether the model requires peer-controlled
// bytes at a server-side transport: a peer-input attacker-control or input
// constraint condition and a server protocol role. Client-side and
// role-undetermined models keep their existing evaluation.
func needsRootedTransportProof(c *domain.AnalysisCase) bool {
	if c == nil || c.Exploit == nil {
		return false
	}
	if c.Exploit.ProtocolRole != domain.ProtocolRoleServer {
		return false
	}
	conditions := append([]domain.Condition{}, c.Exploit.MandatoryConditions...)
	conditions = append(conditions, c.Exploit.SupportingFactors...)
	for _, cond := range conditions {
		switch cond.Kind {
		case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
			if evaluator.WantsPeerInput(cond, c.Vulnerability) {
				return true
			}
		}
	}
	return false
}

// transportProofSubjects collects the advisory's own affected packages and
// symbols; the module itself is the fallback subject so module-level records
// still bind a module identity.
func transportProofSubjects(c *domain.AnalysisCase) []domain.SymbolRef {
	var out []domain.SymbolRef
	seen := map[domain.SymbolRef]bool{}
	add := func(s domain.SymbolRef) {
		if s.Package == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range c.Vulnerability.AffectedSymbols {
		add(s)
	}
	for _, p := range c.Vulnerability.AffectedPackages {
		add(domain.SymbolRef{Package: p.Path})
	}
	for _, m := range c.Vulnerability.AffectedModules {
		for _, s := range m.AffectedSymbols {
			add(s)
		}
		for _, p := range m.AffectedPackages {
			add(domain.SymbolRef{Package: p.Path})
		}
	}
	if len(out) == 0 && c.Vulnerability.Module != "" {
		add(domain.SymbolRef{Package: c.Vulnerability.Module})
	}
	return out
}

// transportFixEvidence returns the first collected fix diff with its own digest
// over the recorded bytes. The digest pins what was actually read, so a
// truncated patch can never be presented as the full fix.
func transportFixEvidence(c *domain.AnalysisCase) (uri, digest, diff string) {
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		if ev.Kind != domain.EvidenceFixDiff || ev.Content == "" {
			continue
		}
		sum := sha256.Sum256([]byte(ev.Content))
		return ev.Source, "sha256:" + hex.EncodeToString(sum[:]), ev.Content
	}
	return "", "", ""
}

// recordTransportMechanism stamps the detected mechanism on the peer-input
// constraint conditions it obliges. It records a discovered source fact; it
// never asserts the mechanism on a condition the proof did not prove.
func recordTransportMechanism(c *domain.AnalysisCase, mechanism string) {
	if c == nil || c.Exploit == nil || mechanism == "" {
		return
	}
	for i := range c.Exploit.MandatoryConditions {
		cond := &c.Exploit.MandatoryConditions[i]
		if cond.Kind != domain.ConditionInputConstraint {
			continue
		}
		if !evaluator.WantsPeerInput(*cond, c.Vulnerability) {
			continue
		}
		if cond.Params == nil {
			cond.Params = map[string]string{}
		}
		cond.Params[domain.ParamMechanism] = mechanism
	}
}
