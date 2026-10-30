package evidencetools

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/repository"
)

// ---- get_product_snapshot ----

type getProductSnapshotArgs struct{}

func (s *Session) getProductSnapshot(ctx context.Context) (*Observation, error) {
	snap, err := s.probeSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return s.snapshotObs(snap), nil
}

// probeSnapshot runs (once, lazily) the product snapshot probe that fills
// s.snap and merges the discovered release/vendor facts into s.Build —
// every handler that needs the recorded build context may rely on it,
// independent of whether get_product_snapshot was invoked first.
func (s *Session) probeSnapshot(ctx context.Context) (domain.ProductSnapshot, error) {
	s.mu.Lock()
	if s.snap != nil {
		snap := *s.snap
		s.mu.Unlock()
		return snap, nil
	}
	s.mu.Unlock()

	snap, err := (repository.Service{}).Snapshot(ctx, s.SnapshotRoot, repository.SnapshotOptions{
		// Only caller-declared axes are target facts: the host-filled
		// analysis defaults in s.Build must not become operator-declared.
		GOOS:              s.declaredGOOS,
		GOARCH:            s.declaredGOARCH,
		BuildTags:         s.Build.BuildTags,
		ExternalCommitSHA: s.ExternalSHA,
		GoBin:             s.ToolBin,
		Env:               s.ToolEnv,
		Artifact:          s.Artifact,
		ReleaseMetadata:   s.ReleaseMetadata,
	})
	if err != nil {
		return domain.ProductSnapshot{}, err
	}
	// The service resolves the build-selection fields (vendor mode, workspace
	// mode, effective GOFLAGS, replace directives) itself; the session must
	// not overwrite them with a second, differently-scoped resolution.
	s.mu.Lock()
	s.snap = &snap
	s.Build = mergeBuildContext(s.Build, snap)
	merged := s.Build
	source := s.Source
	s.mu.Unlock()
	// The source index must describe the same identified build as the
	// session. BindBuild adopts the merged snapshot before the first load
	// and fails closed if the index already loaded under a different one;
	// a stale index would make every verification context comparison
	// disagree with the case's product snapshot.
	if source != nil {
		if err := source.BindBuild(merged); err != nil {
			return domain.ProductSnapshot{}, err
		}
	}
	return snap, nil
}

// mergeBuildContext keeps caller-forced GOOS/GOARCH/tags and adopts the
// discovered release/vendor/build-selection facts from the real snapshot.
func mergeBuildContext(b domain.ProductSnapshot, snap domain.ProductSnapshot) domain.ProductSnapshot {
	b.Commit = snap.Commit
	b.ExternalCommitSHA = snap.ExternalCommitSHA
	b.ContentHash = snap.ContentHash
	// Unpinned platform fields adopt the probe's effective pair — the
	// same default the toolchain itself applies.
	if b.GOOS == "" {
		b.GOOS = snap.GOOS
	}
	if b.GOARCH == "" {
		b.GOARCH = snap.GOARCH
	}
	b.GoVersion = snap.GoVersion
	b.GoModDirective = snap.GoModDirective
	b.MinimumGoVersion = snap.MinimumGoVersion
	b.ReleaseGoVersion = snap.ReleaseGoVersion
	b.GoVersionSource = snap.GoVersionSource
	b.ReleaseEvidence = snap.ReleaseEvidence
	b.ReleaseModules = snap.ReleaseModules
	b.ReleaseEvidenceRequired = snap.ReleaseEvidenceRequired
	b.BinaryPath = snap.BinaryPath
	b.Target = mergeTargetAuthority(b.Target, snap.Target)
	b.VendorMode = snap.VendorMode
	b.GoWorkFile = snap.GoWorkFile
	b.GoFlags = snap.GoFlags
	b.ReplaceDirectives = snap.ReplaceDirectives
	return b
}

// mergeTargetAuthority keeps the provenance authority that resolved the
// build. The lazy probe may refine measurement identity with facts it
// actually measured (artifact build info or release metadata), but a probe
// that merely re-reads the session's effective platform axes must never
// upgrade the original target to a fresh operator declaration.
func mergeTargetAuthority(original, probed *domain.ProductTarget) *domain.ProductTarget {
	if probed != nil && probed.Authoritative() {
		t := *probed
		return &t
	}
	if original != nil {
		t := *original
		return &t
	}
	if probed != nil {
		t := *probed
		return &t
	}
	return nil
}

func (s *Session) snapshotObs(snap domain.ProductSnapshot) *Observation {
	sd := &ScopeDetails{
		SnapshotHash: s.SnapshotHash,
		SnapshotRoot: s.SnapshotRoot,
		ExternalSHA:  snap.ExternalCommitSHA,
		BuildContext: &BuildContext{
			GOOS:       snap.GOOS,
			GOARCH:     snap.GOARCH,
			CGOEnabled: snap.CGOEnabled,
			BuildTags:  snap.BuildTags,
			GoVersion:  snap.ReleaseGoVersion,
			VendorMode: snap.VendorMode,
		},
		CoverageRule: "single product snapshot probe (go version + manifest scan, no git history)",
	}
	s.toolchainException(sd,
		"fixed 'go version' probe required for snapshot identity reporting (no repo code executed)")
	var lims []string
	if snap.ReleaseGoVersion == "" {
		lims = append(lims,
			"release toolchain is UNKNOWN: no binary build info or snapshot-local version pin; go.mod go directive is a minimum, not the release version")
	}
	if s.GoWorkPresent {
		lims = append(lims, "snapshot contains a go.work file; workspace-mode resolution is reported but module queries run with GOWORK=off")
	}
	return s.ok("get_product_snapshot",
		fmt.Sprintf("snapshot %s: content hash %s, go directive %s, %d replace directives", snap.ExternalCommitSHA, s.SnapshotHash, snap.GoModDirective, len(snap.ReplaceDirectives)),
		"this snapshot's build context and module manifest facts",
		CompletenessComplete, snap, sd, lims)
}

// ---- get_dependency_graph ----

type getDependencyGraphArgs struct{}

type dependencyGraphData struct {
	Modules []moduleEntry `json:"modules"`
	Count   int           `json:"count"`
	Source  string        `json:"source"` // "go list -m -json all" | "vendor/modules.txt"
}

// moduleEntry is one resolved module with its effective (post-replace)
// coordinates kept explicit — version matching must use the effective
// values, never the pre-replace ones.
type moduleEntry struct {
	Path             string `json:"path"`
	Version          string `json:"version"`
	EffectivePath    string `json:"effective_path"`
	EffectiveVersion string `json:"effective_version"`
	Main             bool   `json:"main,omitempty"`
	Indirect         bool   `json:"indirect,omitempty"`
	Replaced         bool   `json:"replaced,omitempty"`
	ReplacePath      string `json:"replace_path,omitempty"`
	ReplaceVersion   string `json:"replace_version,omitempty"`
	ReplaceIsLocal   bool   `json:"replace_is_local,omitempty"`
}

func (s *Session) listModules(ctx context.Context) ([]affected.Module, string, error) {
	if _, err := s.probeSnapshot(ctx); err != nil {
		return nil, "", err
	}
	raw, src, err := s.GoTool.ListModules(ctx, s.SnapshotRoot, s.Build)
	if err != nil {
		return nil, "", err
	}
	mods, err := affected.DecodeModules(raw)
	if err != nil {
		return nil, "", err
	}
	return mods, src, nil
}

func (s *Session) getDependencyGraph(ctx context.Context) (*Observation, error) {
	if s.toolchainDenied() {
		return s.unsupported("get_dependency_graph",
			"toolchain execution (go list -m -json all) requires the toolchain permission (--allow-toolchain) in the strict profile"), nil
	}
	mods, src, err := s.listModules(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]moduleEntry, 0, len(mods))
	for _, m := range mods {
		e := moduleEntry{
			Path:             m.Path,
			Version:          m.Version,
			EffectivePath:    m.EffectivePath(),
			EffectiveVersion: m.EffectiveVersion(),
			Main:             m.Main,
			Indirect:         m.Indirect,
		}
		if m.Replace != nil {
			e.Replaced = true
			e.ReplacePath = m.Replace.Path
			e.ReplaceVersion = m.Replace.Version
			e.ReplaceIsLocal = m.Replace.Version == "" && (filepath.IsAbs(m.Replace.Path) ||
				len(m.Replace.Path) > 0 && (m.Replace.Path[0] == '.' || m.Replace.Path[0] == '/'))
		}
		entries = append(entries, e)
	}
	sd := &ScopeDetails{
		SnapshotHash: s.SnapshotHash,
		ExternalSHA:  s.ExternalSHA,
		BuildContext: s.buildContext(),
		CoverageRule: "enumerated module list of the snapshot's main module graph",
		Extra:        map[string]string{"module_source": src},
	}
	// Release-graph provenance: when the snapshot carries release
	// evidence, name which graph grounds the version axis and record the
	// artifact/member/build-info digests — never credentials.
	view := s.snapshotReleaseView()
	for k, v := range ReleaseProvenanceExtra(view) {
		sd.Extra[k] = v
	}
	var lims []string
	if src == "vendor/modules.txt" {
		lims = append(lims, "module list comes from vendor/modules.txt (vendored build); replaces on disk are vendor content, not fetched versions")
	}
	if s.GoWorkPresent {
		lims = append(lims, "snapshot contains go.work but module queries run with GOWORK=off; module-mode resolution shown")
	}
	if affected.ReleaseVersionAxisBlocked(view) {
		_, _, status := affected.ReleaseModulesFor(view)
		lims = append(lims, fmt.Sprintf(
			"an explicitly requested release channel did not resolve (%s): source-graph module versions are build/package provenance, not release applicability evidence",
			status))
	}
	fact := fmt.Sprintf("dependency graph: %d module(s) resolved via %s", len(entries), src)
	return s.ok("get_dependency_graph", fact,
		fmt.Sprintf("module list of %s (%s)", s.SnapshotRoot, src),
		CompletenessComplete,
		dependencyGraphData{Modules: entries, Count: len(entries), Source: src},
		sd, lims), nil
}

// ---- get_module_version ----

type getModuleVersionArgs struct {
	Module string `json:"module"`
}

type moduleVersionData struct {
	Module           string `json:"module"`
	Present          bool   `json:"present"`
	Version          string `json:"version,omitempty"`
	EffectiveVersion string `json:"effective_version,omitempty"`
	Replaced         bool   `json:"replaced,omitempty"`
	Source           string `json:"source,omitempty"`
	// Release-axis fields: populated only when the snapshot's release
	// evidence governs or blocks the version axis. Source remains the
	// source-graph listing this tool always reported; the release fields
	// name what the authoritative release module graph says — or why it
	// cannot answer (CONFLICTED inside the graph, or a required channel
	// that failed, in which case the source version must not be
	// mistaken for a release fact).
	ReleaseStatus  string `json:"release_status,omitempty"`
	ReleaseReason  string `json:"release_reason,omitempty"`
	ReleasePresent *bool  `json:"release_present,omitempty"`
	ReleaseVersion string `json:"release_version,omitempty"`
}

// releaseVersionAxis inspects the release module graph for one module
// path and folds the result into data: the release-graph presence and
// unique effective version when the graph is authoritative, or the
// composed status when the version axis is blocked or conflicted. It
// returns the composed axis status for fact strings, or "" when no
// release evidence bears on this snapshot (legacy observations keep
// their exact previous shape).
func releaseVersionAxis(view domain.ProductSnapshot, module string, data *moduleVersionData) string {
	if !view.ReleaseEvidenceRequired && view.ReleaseEvidence == nil && len(view.ReleaseModules) == 0 {
		return ""
	}
	relMods, relAuth, relStatus := affected.ReleaseModulesFor(view)
	status, reason := relStatus, ""
	if i := strings.IndexByte(relStatus, '/'); i >= 0 {
		status, reason = relStatus[:i], relStatus[i+1:]
	}
	data.ReleaseStatus = status
	data.ReleaseReason = reason
	switch {
	case relAuth:
		vers := map[string]bool{}
		var unique []string
		present := false
		for _, m := range relMods {
			if m.Path != module && m.EffectivePath() != module {
				continue
			}
			present = true
			v := m.EffectiveVersion()
			if !vers[v] {
				vers[v] = true
				unique = append(unique, v)
			}
		}
		data.ReleasePresent = &present
		if len(unique) == 1 {
			data.ReleaseVersion = unique[0]
		} else if present && len(unique) > 1 {
			// The authoritative graph disagrees with itself: the
			// release version resolves to nothing.
			data.ReleaseStatus = string(domain.ReleaseStatusConflicted)
			data.ReleaseReason = domain.ReleaseReasonConflict
		}
		return "release graph: " + moduleReleaseVerdict(present, data.ReleaseVersion, data.ReleaseStatus)
	case affected.ReleaseVersionAxisBlocked(view):
		return "release version undecidable: " + relStatus
	default:
		return "release axis: " + relStatus
	}
}

// moduleReleaseVerdict renders the module's release-graph answer for the
// observation fact text.
func moduleReleaseVerdict(present bool, version, status string) string {
	switch {
	case !present:
		return "absent"
	case status == string(domain.ReleaseStatusConflicted):
		return "conflicting versions, undecidable"
	default:
		return version
	}
}

func (s *Session) getModuleVersion(ctx context.Context, a getModuleVersionArgs) (*Observation, error) {
	if a.Module == "" {
		return nil, fmt.Errorf("module path is required")
	}
	if s.toolchainDenied() {
		return s.unsupported("get_module_version",
			"toolchain execution (go list -m -json all) requires the toolchain permission (--allow-toolchain) in the strict profile"), nil
	}
	mods, src, err := s.listModules(ctx)
	if err != nil {
		return nil, err
	}
	view := s.snapshotReleaseView()
	for _, m := range mods {
		if m.Path == a.Module || m.EffectivePath() == a.Module {
			fact := fmt.Sprintf("module %s resolved to version %s", a.Module, m.EffectiveVersion())
			data := moduleVersionData{
				Module:           a.Module,
				Present:          true,
				Version:          m.Version,
				EffectiveVersion: m.EffectiveVersion(),
				Replaced:         m.Replace != nil,
				Source:           src,
			}
			if axis := releaseVersionAxis(view, a.Module, &data); axis != "" {
				fact += " (" + axis + ")"
			}
			sd := &ScopeDetails{
				SnapshotHash: s.SnapshotHash,
				Subject:      a.Module,
				CoverageRule: "enumerated module list of the snapshot's main module graph",
			}
			for k, v := range ReleaseProvenanceExtra(view) {
				if sd.Extra == nil {
					sd.Extra = map[string]string{}
				}
				sd.Extra[k] = v
			}
			return s.ok("get_module_version", fact,
				fmt.Sprintf("resolved module list of %s (%s)", s.SnapshotRoot, src),
				CompletenessComplete, data, sd, nil), nil
		}
	}
	// Module absent: the enumerated list is closed, so absence inside it
	// is a COMPLETE observation of the module graph — not a statement
	// about the code.
	data := moduleVersionData{Module: a.Module, Present: false, Source: src}
	fact := fmt.Sprintf("module %s is not in the resolved dependency graph (%d modules enumerated)", a.Module, len(mods))
	if axis := releaseVersionAxis(view, a.Module, &data); axis != "" {
		fact += " (" + axis + ")"
	}
	sd := &ScopeDetails{
		SnapshotHash: s.SnapshotHash,
		Subject:      a.Module,
		CoverageRule: "enumerated module list of the snapshot's main module graph",
	}
	for k, v := range ReleaseProvenanceExtra(view) {
		if sd.Extra == nil {
			sd.Extra = map[string]string{}
		}
		sd.Extra[k] = v
	}
	return s.ok("get_module_version", fact,
		fmt.Sprintf("resolved module list of %s (%s)", s.SnapshotRoot, src),
		CompletenessComplete, data, sd, nil), nil
}

// ---- run_govulncheck ----

type runGovulncheckArgs struct{}

type govulncheckData struct {
	InDatabase bool                 `json:"in_database"`
	Findings   []goanalysis.Finding `json:"findings"`
	Count      int                  `json:"count"`
	Pattern    string               `json:"pattern"`
	DBInfo     string               `json:"db_info,omitempty"`
}

func (s *Session) runGovulncheck(ctx context.Context) (*Observation, error) {
	// govulncheck runs the go toolchain but never executes repository
	// code — mirroring production, it is not gated by AllowExec. Under
	// the strict profile toolchain subprocesses are an explicit policy
	// decision instead: the AllowToolchain permission.
	if s.toolchainDenied() {
		return s.unsupported("run_govulncheck",
			"toolchain execution (govulncheck subprocess) requires the toolchain permission (--allow-toolchain) in the strict profile"), nil
	}
	if s.Strict && s.GovulnDBRoot == "" {
		return s.unsupported("run_govulncheck",
			"strict profile requires --govulndb to pin the vulnerability database"), nil
	}
	if s.Strict && s.ModCacheRoot == "" {
		// govulncheck shells out to the go toolchain, which would keep
		// using the ambient module cache outside the declared strict
		// read roots — fail closed until the caller pins one.
		return s.unsupported("run_govulncheck",
			"strict profile requires --modcache to declare the module cache the govulncheck subprocess may read"), nil
	}
	if s.GovulnDBRoot != "" {
		// A configured-but-missing, unreadable, or contentless DB root is
		// an absent capability, not a scan failure: UNSUPPORTED, while
		// errors against an existing readable database stay ERROR.
		// Probe the shapes govulncheck's local client accepts: a v1
		// database index or a flat directory of <GO-ID>.json entries.
		if !readableGovulnDB(s.GovulnDBRoot) {
			return s.unsupported("run_govulncheck",
				"configured govulndb root is missing, unreadable, or has no vulnerability entries: "+s.GovulnDBRoot), nil
		}
	}
	if s.GVRunner == nil {
		return s.unsupported("run_govulncheck", "govulncheck runner not configured"), nil
	}
	if s.VulnSource == nil {
		return s.unsupported("run_govulncheck", "advisory source not configured (network research disabled)"), nil
	}
	raw, pattern, gvErr := s.GVRunner.RunGovulncheck(ctx, s.SnapshotRoot, s.Build)
	if gvErr != nil {
		if errors.Is(gvErr, fs.ErrNotExist) {
			return s.unsupported("run_govulncheck", "govulncheck binary not available in this environment"), nil
		}
		return nil, fmt.Errorf("govulncheck: %w", gvErr)
	}
	res, err := goanalysis.Parse(raw)
	if err != nil {
		return nil, err
	}
	v, verr := s.sessionVulnerability(ctx)
	if verr != nil {
		return nil, verr
	}
	var data govulncheckData
	// The contract emits a JSON array for findings; a nil slice must not
	// serialize as null.
	data.Findings = []goanalysis.Finding{}
	data.Pattern = pattern
	data.InDatabase = res.Covers(*v)
	for _, f := range res.Findings {
		if f.OSV == v.ID || containsStr(v.Aliases, f.OSV) {
			data.Findings = append(data.Findings, f)
		}
	}
	data.Count = len(data.Findings)
	if informer, ok := s.GVRunner.(goanalysis.DBInformer); ok {
		if info, ierr := informer.DBInfo(ctx); ierr == nil {
			data.DBInfo = info
		}
	}
	sd := &ScopeDetails{
		SnapshotHash: s.SnapshotHash,
		ExternalSHA:  s.ExternalSHA,
		Subject:      v.ID,
		BuildContext: s.buildContext(),
		Extra: map[string]string{
			"scan_pattern":  pattern,
			"govulndb_root": s.GovulnDBRoot,
		},
	}
	lims := []string{
		"govulncheck findings are DB-coverage-limited: absence of findings is not proof of non-reachability; see in_database for whether this advisory is even in the scanned DB",
		"findings filtered to this advisory id and its aliases; the run scanned pattern " + pattern,
	}
	fact := fmt.Sprintf("govulncheck ran pattern %s: %d finding(s) for %s (advisory in DB: %v)", pattern, data.Count, v.ID, data.InDatabase)
	return s.ok("run_govulncheck", fact,
		fmt.Sprintf("govulncheck %s over %s", pattern, s.SnapshotRoot),
		CompletenessPartial, data, sd, lims), nil
}

// readableGovulnDB probes the pinned database root the way govulncheck's
// local client will consume it: either a v1 schema directory (index/
// modules.json + ID/<ID>.json entries) or the flat "<GO-ID>.json files
// only" layout (hybrid source, golang.org/x/vuln internal/client). The
// directory must exist, be listable, and hold at least one entry — an
// empty or unreadable root is a capability gap, not a scannable empty DB.
func readableGovulnDB(root string) bool {
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return false
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	var flat bool
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !flat && strings.HasSuffix(e.Name(), ".json") &&
			strings.HasPrefix(e.Name(), "GO-") {
			flat = true
		}
	}
	v1 := fileExists(filepath.Join(root, "index", "modules.json"))
	return flat || v1
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// vendorPresent reports whether the snapshot carries a vendor directory
// with modules.txt — the authoritative vendored-module record.
func vendorPresent(root string) bool {
	st, err := os.Stat(filepath.Join(root, "vendor", "modules.txt"))
	return err == nil && !st.IsDir()
}
