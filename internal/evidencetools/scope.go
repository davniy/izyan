package evidencetools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

// sha256Of returns the hex sha256 of b.
func sha256Of(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// envKeyNames extracts the variable names from a KEY=value env list,
// sorted — ambient keys are recorded for audit truthfulness without
// copying host values.
func envKeyNames(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// finishObservation applies the completeness invariants to a built
// Observation before it leaves the adapter:
//
//   - ERROR/UNSUPPORTED never carry COMPLETE — a check that did not run
//     cannot claim a covered scope.
//   - COMPLETE requires a named coverage rule in ScopeDetails; without
//     one the observation is downgraded to PARTIAL.
//   - COMPLETE is rejected when the scope itself admits gaps (skipped
//     packages, truncation).
func finishObservation(o *Observation) {
	if o.ToolStatus != StatusOK && o.Completeness == CompletenessComplete {
		o.Completeness = CompletenessUnknown
	}
	if o.Completeness == CompletenessComplete {
		rule := ""
		truncated := false
		if o.ScopeDetails != nil {
			rule = o.ScopeDetails.CoverageRule
			if len(o.ScopeDetails.SkippedPackages) > 0 {
				truncated = true
			}
			if o.ScopeDetails.Limits != nil && (o.ScopeDetails.Limits.Truncated || o.ScopeDetails.Limits.OutputTruncated) {
				truncated = true
			}
		}
		if rule == "" || truncated {
			o.Completeness = CompletenessPartial
			if rule == "" {
				o.Limitations = append(o.Limitations,
					"completeness downgraded: no closed-scope coverage rule recorded")
			} else {
				o.Limitations = append(o.Limitations,
					"completeness downgraded: skipped/truncated entries inside the claimed scope")
			}
		}
	}
	if o.ToolStatus == StatusError {
		if o.Error == "" {
			o.Error = o.Fact
		}
		if o.Error == "" {
			o.Error = "tool execution failed"
		}
	}
}

// skipLimitation renders the skipped-packages coverage gap, or "".
func skipLimitation(skipped []string) string {
	if len(skipped) == 0 {
		return ""
	}
	n := len(skipped)
	shown := skipped
	if n > 5 {
		shown = skipped[:5]
	}
	return fmt.Sprintf("%d product package(s) failed type-check and were excluded from scope: %s%s",
		n, strings.Join(shown, ", "), map[bool]string{true: ", …", false: ""}[n > 5])
}

// skippedPaths projects the structured record to sorted package paths.
func skippedPaths(diags []goanalysis.SkippedPackage) []string {
	out := make([]string, 0, len(diags))
	for _, d := range diags {
		out = append(out, d.Path)
	}
	sort.Strings(out)
	return out
}

// skippedDiagnosticLimitations renders one actionable limitation per
// skipped package: the package path plus its primary compiler
// diagnostic — the concrete prerequisite/build failure a re-run needs
// resolved (e.g. a missing system header) — and the remediation bound.
// Bounded to 16 packages; the aggregate line already carries the count.
func skippedDiagnosticLimitations(diags []goanalysis.SkippedPackage) []string {
	const maxShown = 16
	var out []string
	for i, d := range diags {
		if i >= maxShown {
			break
		}
		reason := "no diagnostics recorded"
		if len(d.Errors) > 0 {
			reason = d.Errors[0]
		}
		out = append(out, fmt.Sprintf(
			"product package %s failed to build/type-check under the recorded load context (%s); its references are invisible — restore the missing build prerequisite or fix the package and re-run",
			d.Path, reason))
	}
	return out
}

// skippedDiagnosticsJSON serializes the bounded skip record for
// scope_details.extra — errors capped at 4/package and 240 chars,
// imports at 32, packages at 32 so the blob stays evidence-sized.
func skippedDiagnosticsJSON(diags []goanalysis.SkippedPackage) string {
	const maxPkgs, maxErrs, maxErrLen, maxImports = 32, 4, 240, 32
	type diag struct {
		Path            string   `json:"path"`
		Imports         []string `json:"imports,omitempty"`
		ImportsComplete bool     `json:"imports_complete"`
		Errors          []string `json:"errors,omitempty"`
		SourceVisible   bool     `json:"source_visible"`
	}
	out := make([]diag, 0, len(diags))
	for i, d := range diags {
		if i >= maxPkgs {
			break
		}
		e := diag{Path: d.Path, ImportsComplete: d.ImportsComplete, SourceVisible: d.SourceVisible}
		e.Imports = d.Imports
		if len(e.Imports) > maxImports {
			e.Imports = e.Imports[:maxImports]
		}
		e.Errors = d.Errors
		if len(e.Errors) > maxErrs {
			e.Errors = e.Errors[:maxErrs]
		}
		for j, s := range e.Errors {
			if len(s) > maxErrLen {
				e.Errors[j] = s[:maxErrLen] + "…"
			}
		}
		out = append(out, e)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// sourceScope builds the ScopeDetails shared by all goanalysis-backed
// tools: build context, product package inventory and skipped packages.
// loadErr propagates index load failure — the caller turns it into ERROR.
func (s *Session) sourceScope(ctx context.Context, subject string) (*ScopeDetails, []string, error) {
	if _, perr := s.probeSnapshot(ctx); perr != nil {
		return nil, nil, perr
	}
	sd := &ScopeDetails{
		SnapshotHash: s.SnapshotHash,
		SnapshotRoot: s.SnapshotRoot,
		ExternalSHA:  s.ExternalSHA,
		Subject:      subject,
		BuildContext: s.buildContext(),
	}
	var lims []string
	diags, err := s.Source.SkippedPackageDiagnostics(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(diags) > 0 {
		// The structured record lands in ScopeDetails (paths plus a
		// bounded JSON diagnostics blob); each package's primary compiler
		// diagnostic also rides the limitations so the observation names
		// the concrete prerequisite/build failure — never a silent skip.
		sd.SkippedPackages = skippedPaths(diags)
		if l := skipLimitation(sd.SkippedPackages); l != "" {
			lims = append(lims, l)
		}
		lims = append(lims, skippedDiagnosticLimitations(diags)...)
		if sd.Extra == nil {
			sd.Extra = map[string]string{}
		}
		sd.Extra["skipped_package_diagnostics"] = skippedDiagnosticsJSON(diags)
	}
	if s.Source.LoadBudgetExhausted() {
		lims = append(lims, "dependency package-load budget exhausted during this session; dep-internal coverage is truncated")
		if sd.Limits == nil {
			sd.Limits = &ScopeLimits{}
		}
		// Truncated marks the truncated dep-internal coverage so the
		// completeness invariant (COMPLETE rejected on truncated scopes)
		// sees the gap even when a handler forgets the limitation.
		sd.Limits.Truncated = true
	}
	s.toolchainException(sd,
		"package loader runs 'go list' subprocesses required for source indexing (no repo code executed)")
	return sd, lims, nil
}

// toolchainException records an exec-backed subprocess the strict
// toolchain permission does not gate because the session's analysis
// contract requires it — named in the audit scope, never silent.
func (s *Session) toolchainException(sd *ScopeDetails, reason string) {
	if !s.toolchainDenied() {
		return
	}
	if sd.Extra == nil {
		sd.Extra = map[string]string{}
	}
	sd.Extra["toolchain_exception"] = reason
}

// buildContext renders the snapshot's build configuration for scope
// records.
func (s *Session) buildContext() *BuildContext {
	b := s.Build
	toolchain := s.ToolVer
	if toolchain == "" {
		toolchain = s.ToolBin
	}
	effective := domain.EffectiveBuildContext(b)
	return &BuildContext{
		EffectiveBuild: &effective,
		GOOS:       b.GOOS,
		GOARCH:     b.GOARCH,
		CGOEnabled: b.CGOEnabled,
		BuildTags:  append([]string(nil), b.BuildTags...),
		GoVersion:  b.ReleaseGoVersion,
		VendorMode: b.VendorMode,
		Toolchain:  toolchain,
	}
}

// snapshotReleaseView returns the snapshot the release-evidence fields
// live on: the lazily probed snapshot when it exists, else the session's
// recorded build context (callers may have pre-seeded it). Fields are
// read-only here — handlers must never fabricate evidence.
func (s *Session) snapshotReleaseView() domain.ProductSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap != nil {
		return *s.snap
	}
	return s.Build
}

// ReleaseProvenanceExtra renders the release-evidence provenance keys for
// scope_details.extra: which module graph grounds the version axis, the
// release-evidence status/reason, and the artifact/member/build-info
// digests. It returns nil when the snapshot carries no release evidence
// and none was required, so legacy observations stay untouched. No
// credential or artifact URL ever lands here.
func ReleaseProvenanceExtra(snap domain.ProductSnapshot) map[string]string {
	re := snap.ReleaseEvidence
	if re == nil && !snap.ReleaseEvidenceRequired && len(snap.ReleaseModules) == 0 {
		return nil
	}
	mods, relAuth, status := affected.ReleaseModulesFor(snap)
	blocked := affected.ReleaseVersionAxisBlocked(snap)
	graph := "source_module_graph"
	switch {
	case relAuth:
		graph = "release_module_graph"
	case blocked:
		graph = "unavailable"
	}
	extra := map[string]string{
		"version_axis_graph": graph,
	}
	if relAuth {
		extra["version_axis_trust"] = string(domain.ReleaseTrustAuthoritative)
		extra["version_axis_modules"] = fmt.Sprintf("%d", len(mods))
	}
	if re != nil || snap.ReleaseEvidenceRequired {
		statusPart, reasonPart := status, ""
		if i := strings.IndexByte(status, '/'); i >= 0 {
			statusPart, reasonPart = status[:i], status[i+1:]
		}
		extra["release_evidence_status"] = statusPart
		if reasonPart != "" {
			extra["release_evidence_reason"] = reasonPart
		}
	}
	if re != nil {
		if re.ArtifactSHA256 != "" {
			extra["release_artifact_sha256"] = re.ArtifactSHA256
		}
		if re.BinaryMember != "" {
			extra["release_binary_member"] = re.BinaryMember
		}
		if re.BuildInfoSHA256 != "" {
			extra["release_build_info_sha256"] = re.BuildInfoSHA256
		}
	}
	return extra
}
