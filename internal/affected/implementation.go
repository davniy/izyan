package affected

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/repository"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// MaxImplementationScanFiles bounds one implementation-locus package scan:
// every non-test .go file in the proposed package directory is evaluated,
// and a directory above the bound fails closed instead of being scanned
// partially.
const MaxImplementationScanFiles = 256

// ImplementationVerificationStatus is the deterministic outcome of one
// implementation-locus verification. Only ImplementationVerifiedAbsent may
// enter a downstream affected-chain FALSE; Present and Unknown never do.
type ImplementationVerificationStatus string

const (
	ImplementationVerifiedAbsent      ImplementationVerificationStatus = "VERIFIED_ABSENT"
	ImplementationVerifiedPresent     ImplementationVerificationStatus = "VERIFIED_PRESENT"
	ImplementationVerificationUnknown ImplementationVerificationStatus = "UNKNOWN"
)

// Implementation check statuses. PASS records an established fact;
// PRESENT records the positive determination that the vulnerable
// implementation was found selected; UNKNOWN records a check that did not
// establish its fact and therefore fails the verification closed.
const (
	ImplementationCheckPass    = "PASS"
	ImplementationCheckPresent = "PRESENT"
	ImplementationCheckUnknown = "UNKNOWN"
)

// ImplementationTarget records the exact build context the verifier
// evaluated. It is copied from the recorded snapshot; the verifier never
// substitutes the analyzer host.
type ImplementationTarget struct {
	GOOS             string   `json:"goos"`
	GOARCH           string   `json:"goarch"`
	CGOEnabled       bool     `json:"cgo_enabled"`
	BuildTags        []string `json:"build_tags,omitempty"`
	GoVersion        string   `json:"go_version,omitempty"`
	ReleaseGoVersion string   `json:"release_go_version,omitempty"`
	ReleaseTags      []string `json:"release_tags,omitempty"`
}

// ImplementationCheck is one executed verifier step. Detail is a bounded
// human-readable observation; it never carries a verdict of its own.
type ImplementationCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// ImplementationVerificationInput is the deterministic input set for one
// LLM implementation-locus proposal. Only Proposal is LLM-inferred; every
// other member is a recorded lane fact. AdvisoryBytes are the exact frozen
// advisory bytes the digest members pin.
type ImplementationVerificationInput struct {
	Proposal                domain.ImplementationLocusProposal
	AffectedEntry           domain.AffectedModule
	Affected                domain.AffectedResult
	Build                   domain.ProductSnapshot
	SnapshotRoot            string
	SnapshotContentHash     string
	AdvisoryID              string
	AdvisorySHA256          string
	AdvisoryCanonicalSHA256 string
	AdvisoryBytes           []byte
	// EvidenceIDPrefix optionally overrides the deterministic evidence ids
	// (default EV-IMPL-<PROPOSAL-ID>).
	EvidenceIDPrefix string
}

// ImplementationVerification is the deterministic result of one
// implementation-locus verification. Status is the only member a downstream
// affected-chain decision may consume: VERIFIED_ABSENT states that the
// proposed vulnerable implementation is explicitly excluded under the
// recorded build context and no selected alternate in the package carries
// the marker; VERIFIED_PRESENT states the opposite; UNKNOWN means at least
// one deterministic check failed and nothing may be concluded.
//
// Evidence contains deterministic source/build records with snapshot and
// file hashes. The proposal itself stays LLM-inferred and is not promoted
// into evidence.
type ImplementationVerification struct {
	Status          ImplementationVerificationStatus `json:"status"`
	Reason          string                           `json:"reason"`
	ProposalID      string                           `json:"proposal_id"`
	ProposalQuality domain.EvidenceQuality           `json:"proposal_quality"`

	Module          string   `json:"module"`
	Version         string   `json:"version"`
	Package         string   `json:"package"`
	File            string   `json:"file"`
	Function        string   `json:"function"`
	Marker          string   `json:"marker"`
	BuildExpression string   `json:"build_expression"`
	GOOS            []string `json:"goos,omitempty"`
	GOARCH          []string `json:"goarch,omitempty"`

	Target   ImplementationTarget  `json:"target"`
	Checks   []ImplementationCheck `json:"checks"`
	Evidence []domain.Evidence     `json:"evidence,omitempty"`

	SnapshotContentHash   string   `json:"snapshot_content_hash"`
	AdvisorySHA256        string   `json:"advisory_sha256"`
	AdvisoryQuoteField    string   `json:"advisory_quote_field,omitempty"`
	ModuleSource          string   `json:"module_source,omitempty"` // main|vendor|replace
	ModuleVersion         string   `json:"module_version,omitempty"`
	FileSHA256            string   `json:"file_sha256,omitempty"`
	ActualBuildExpression string   `json:"actual_build_expression,omitempty"`
	BuildExpressionKind   string   `json:"build_expression_kind,omitempty"`
	FunctionLine          int      `json:"function_line,omitempty"`
	SelectedFiles         []string `json:"selected_files,omitempty"`
	ExcludedFiles         []string `json:"excluded_files,omitempty"`
	AlternateMarkerHits   []string `json:"alternate_marker_hits,omitempty"`
	ScanBound             int      `json:"scan_bound,omitempty"`
	Limitations           []string `json:"limitations,omitempty"`
}

// ClaimResult maps the deterministic verification onto the affected-chain
// `vulnerable_implementation_present` axis: a verified absent locus is the
// only FALSE; a verified present locus is TRUE; every unknown outcome stays
// UNKNOWN so it can never close the axis.
func (v ImplementationVerification) ClaimResult() domain.ClaimResult {
	switch v.Status {
	case ImplementationVerifiedAbsent:
		return domain.ClaimFalse
	case ImplementationVerifiedPresent:
		return domain.ClaimTrue
	default:
		return domain.ClaimUnknown
	}
}

// VerifyImplementationLocus executes every deterministic check the
// implementation-locus route requires: proposal shape and quality, advisory
// reference/digest/quote binding, snapshot content-hash identity, affected
// applicability and resolved version, module source inventory, package/file
// confinement, AST function and marker presence (or a binding locus — an
// empty function reference admitted only when the proposed file declares
// no functions, with the marker verified as a verbatim file substring),
// explicit build-expression equality, selection under the shared recorded
// go/build.Context, and a bounded marker scan of every selected alternate
// implementation file.
//
// Any failed check yields Unknown, never absence. A selected proposed file
// or a selected alternate carrying the marker yields Present. Only the
// complete absence outcome may later feed an affected-chain FALSE.
func VerifyImplementationLocus(ctx context.Context, in ImplementationVerificationInput) ImplementationVerification {
	v := &implementationVerifier{
		in: in,
		res: ImplementationVerification{
			Status:          ImplementationVerificationUnknown,
			Reason:          "implementation locus was not verified",
			ProposalID:      in.Proposal.ID,
			ProposalQuality: in.Proposal.Quality,
			Module:          in.Proposal.Module,
			Version:         in.Proposal.Version,
			Package:         in.Proposal.Package,
			File:            in.Proposal.File,
			Function:        in.Proposal.Function,
			Marker:          in.Proposal.Marker,
			BuildExpression: in.Proposal.BuildExpression,
			GOOS:            append([]string(nil), in.Proposal.GOOS...),
			GOARCH:          append([]string(nil), in.Proposal.GOARCH...),
			Target: ImplementationTarget{
				GOOS:             in.Build.GOOS,
				GOARCH:           in.Build.GOARCH,
				CGOEnabled:       in.Build.CGOEnabled,
				BuildTags:        append([]string(nil), in.Build.BuildTags...),
				GoVersion:        in.Build.GoVersion,
				ReleaseGoVersion: in.Build.ReleaseGoVersion,
			},
			ScanBound: MaxImplementationScanFiles,
			Limitations: []string{
				"the proposal is an LLM-inferred hypothesis; only the deterministic checks below bind it to source",
			},
		},
	}
	v.run(ctx)
	v.res.Evidence = v.evidence()
	return v.res
}

type implementationVerifier struct {
	in     ImplementationVerificationInput
	res    ImplementationVerification
	stop   bool
	root   string
	bctx   recordedBuild
	mod    implementationModuleSource
	pkgDir string
	file   string
}

func (v *implementationVerifier) pass(id, detail string) {
	v.res.Checks = append(v.res.Checks, ImplementationCheck{ID: id, Status: ImplementationCheckPass, Detail: detail})
}

func (v *implementationVerifier) unknown(id, detail string) {
	v.res.Checks = append(v.res.Checks, ImplementationCheck{ID: id, Status: ImplementationCheckUnknown, Detail: detail})
	if v.res.Status != ImplementationVerifiedPresent {
		v.res.Status = ImplementationVerificationUnknown
		v.res.Reason = detail
	}
	v.stop = true
}

func (v *implementationVerifier) present(id, detail string) {
	v.res.Checks = append(v.res.Checks, ImplementationCheck{ID: id, Status: ImplementationCheckPresent, Detail: detail})
	v.res.Status = ImplementationVerifiedPresent
	v.res.Reason = detail
	v.stop = true
}

func (v *implementationVerifier) run(ctx context.Context) {
	p := v.in.Proposal
	if err := p.Validate(); err != nil {
		v.unknown("proposal-shape", fmt.Sprintf("proposal %q is not admissible: %v", p.ID, err))
		return
	}
	v.pass("proposal-shape", fmt.Sprintf("typed proposal shape valid; quality=%s", p.Quality))
	if v.stop {
		return
	}

	v.verifyAdvisory()
	if v.stop {
		return
	}

	root, err := filepath.Abs(v.in.SnapshotRoot)
	if err != nil {
		v.unknown("snapshot-identity", fmt.Sprintf("snapshot root %q: %v", v.in.SnapshotRoot, err))
		return
	}
	if canon, cerr := filepath.EvalSymlinks(root); cerr == nil {
		root = canon
	}
	v.root = root
	v.verifySnapshotIdentity()
	if v.stop {
		return
	}

	v.verifyApplicability()
	if v.stop {
		return
	}

	v.verifyTarget()
	if v.stop {
		return
	}

	v.verifyModuleSource()
	if v.stop {
		return
	}

	v.verifyPackageFile(ctx)
	if v.stop {
		return
	}

	v.verifyBuildSelection()
	if v.stop {
		return
	}

	v.verifyClaimConsistency()
	if v.stop {
		return
	}

	v.verifyAlternates(ctx)
	if v.stop {
		return
	}

	v.res.Status = ImplementationVerifiedAbsent
	v.res.Reason = fmt.Sprintf(
		"the proposed vulnerable implementation %s is excluded under GOOS=%s GOARCH=%s and no selected alternate implementation in %s carries the marker",
		p.File, v.in.Build.GOOS, v.in.Build.GOARCH, p.Package)
	v.pass("implementation-absence", v.res.Reason)
}

func (v *implementationVerifier) verifyAdvisory() {
	p := v.in.Proposal
	if len(v.in.AdvisoryBytes) == 0 {
		v.unknown("advisory-digest", "the frozen advisory bytes were not supplied — the proposal cannot be bound to an advisory digest")
		return
	}
	sum := sha256.Sum256(v.in.AdvisoryBytes)
	raw := hex.EncodeToString(sum[:])
	v.res.AdvisorySHA256 = raw
	if v.in.AdvisorySHA256 != "" && !strings.EqualFold(v.in.AdvisorySHA256, raw) {
		v.unknown("advisory-digest", fmt.Sprintf("frozen advisory sha256 %s does not match the supplied bytes (%s)", v.in.AdvisorySHA256, raw))
		return
	}
	digests := []string{raw}
	if v.in.AdvisoryCanonicalSHA256 != "" {
		if len(v.in.AdvisoryCanonicalSHA256) != 64 {
			v.unknown("advisory-digest", "the canonical advisory digest is not 64-hex")
			return
		}
		digests = append(digests, v.in.AdvisoryCanonicalSHA256)
	}
	if err := domain.ValidateImplementationAdvisoryRef(p.AdvisoryEvidenceRef, v.in.AdvisoryID, digests...); err != nil {
		v.unknown("advisory-reference", err.Error())
		return
	}
	v.pass("advisory-reference", fmt.Sprintf("reference %q resolves to the frozen advisory %q / pinned digest", p.AdvisoryEvidenceRef, v.in.AdvisoryID))

	var doc struct {
		Summary string `json:"summary"`
		Details string `json:"details"`
	}
	if err := json.Unmarshal(v.in.AdvisoryBytes, &doc); err != nil {
		v.unknown("advisory-quote", fmt.Sprintf("frozen advisory bytes are not valid JSON: %v", err))
		return
	}
	field := domain.ImplementationAdvisoryQuoteField(p.AdvisoryQuotedSpan, doc.Summary, doc.Details, v.in.AdvisoryBytes)
	if field == "" {
		v.unknown("advisory-quote", "the quoted span is not an exact recorded substring of the frozen advisory summary/details/raw body")
		return
	}
	v.res.AdvisoryQuoteField = field
	v.pass("advisory-quote", fmt.Sprintf("quoted span is a verbatim substring of the advisory %s field", field))
}

func (v *implementationVerifier) verifySnapshotIdentity() {
	if len(v.in.SnapshotContentHash) != 64 {
		v.unknown("snapshot-identity", "the expected snapshot content hash is missing or not 64-hex — source identity cannot be verified")
		return
	}
	actual, err := repository.ContentHash(v.root)
	if err != nil {
		v.unknown("snapshot-identity", fmt.Sprintf("snapshot content hash: %v", err))
		return
	}
	v.res.SnapshotContentHash = actual
	if !strings.EqualFold(actual, v.in.SnapshotContentHash) {
		v.unknown("snapshot-identity", fmt.Sprintf("snapshot content hash %s does not match the recorded identity %s", actual, v.in.SnapshotContentHash))
		return
	}
	v.pass("snapshot-identity", fmt.Sprintf("snapshot tree content hash %s matches the recorded identity", actual))
}

func (v *implementationVerifier) verifyApplicability() {
	p, res, entry := v.in.Proposal, v.in.Affected, v.in.AffectedEntry
	if entry.Module == "" || p.Module != entry.Module {
		v.unknown("affected-entry", fmt.Sprintf("proposal module %q does not match the selected affected entry module %q", p.Module, entry.Module))
		return
	}
	if res.ModulePresent != domain.ClaimTrue || res.VersionAffected != domain.ClaimTrue || res.PackagePresent != domain.ClaimTrue {
		v.unknown("affected-applicability", fmt.Sprintf(
			"affected applicability is not established (module_present=%s version_affected=%s package_present=%s)",
			res.ModulePresent, res.VersionAffected, res.PackagePresent))
		return
	}
	if res.BuildRelevant != domain.ClaimTrue {
		v.unknown("affected-build", fmt.Sprintf("build relevance is %s — the package/platform applicability axis did not close TRUE", res.BuildRelevant))
		return
	}
	if res.ResolvedVersion == "" {
		v.unknown("affected-version", "the resolved module version is empty — the proposal version cannot be matched")
		return
	}
	if !sameImplementationVersion(res.ResolvedVersion, p.Version) {
		v.unknown("affected-version", fmt.Sprintf("proposal version %q does not match the resolved version %q", p.Version, res.ResolvedVersion))
		return
	}
	if res.SelectedModule != "" && res.SelectedModule != p.Module {
		v.unknown("affected-selection", fmt.Sprintf("the affected chain selected module %q, not the proposal module %q", res.SelectedModule, p.Module))
		return
	}
	if len(res.SelectedModules) > 0 && !slices.Contains(res.SelectedModules, p.Module) {
		v.unknown("affected-selection", fmt.Sprintf("the proposal module %q is not among the selected affected modules %v", p.Module, res.SelectedModules))
		return
	}
	if res.SelectedModule == "" && len(res.SelectedModules) == 0 {
		v.unknown("affected-selection", "the affected chain recorded no selected module — the proposal cannot be bound to a selected entry")
		return
	}
	// A declared advisory package is the affected component identity: the
	// proposal must name exactly that package. A module-level entry (no
	// declared packages) admits any package inside the module.
	if len(entry.AffectedPackages) > 0 {
		ok := false
		for _, ap := range entry.AffectedPackages {
			if ap.Path == p.Package {
				ok = true
				break
			}
		}
		if !ok {
			v.unknown("affected-package", fmt.Sprintf("proposal package %q is not a declared affected package of entry %q", p.Package, entry.Module))
			return
		}
	}
	v.pass("affected-applicability", fmt.Sprintf(
		"entry %s, resolved version %s, package %s, applicability TRUE", entry.Module, res.ResolvedVersion, p.Package))
}

func (v *implementationVerifier) verifyTarget() {
	if v.in.Build.GOOS == "" || v.in.Build.GOARCH == "" {
		v.unknown("target-scope", "the recorded build target has no explicit GOOS/GOARCH — an implementation conclusion requires a recorded target, never a host default")
		return
	}
	v.pass("target-scope", fmt.Sprintf("recorded target GOOS=%s GOARCH=%s CGO_ENABLED=%t tags=%v", v.in.Build.GOOS, v.in.Build.GOARCH, v.in.Build.CGOEnabled, v.in.Build.BuildTags))
}

// verifyClaimConsistency rejects an absence conclusion when the proposal's
// own advisory-derived platform set names the recorded target as affected:
// an implementation cannot be both excluded from and claimed affected on
// the same target. A selected proposed file returns Present before this
// check, so the contradiction only ever blocks absence.
func (v *implementationVerifier) verifyClaimConsistency() {
	if len(v.in.Proposal.GOOS) > 0 && slices.Contains(v.in.Proposal.GOOS, v.in.Build.GOOS) {
		v.unknown("target-consistency", fmt.Sprintf("the proposal claims GOOS %s as affected, contradicting the excluded implementation under the recorded target", v.in.Build.GOOS))
		return
	}
	if len(v.in.Proposal.GOARCH) > 0 && slices.Contains(v.in.Proposal.GOARCH, v.in.Build.GOARCH) {
		v.unknown("target-consistency", fmt.Sprintf("the proposal claims GOARCH %s as affected, contradicting the excluded implementation under the recorded target", v.in.Build.GOARCH))
		return
	}
	v.pass("target-consistency", "the proposal's advisory platform set does not claim the recorded target as affected")
}

func (v *implementationVerifier) verifyModuleSource() {
	mod, err := resolveImplementationModule(v.root, v.in.Proposal.Module, v.in.Proposal.Version, v.in.Proposal.Package)
	if err != nil {
		v.unknown("module-source", err.Error())
		return
	}
	v.mod = mod
	v.res.ModuleSource = mod.Kind
	v.res.ModuleVersion = mod.Version
	v.pass("module-source", fmt.Sprintf("%s module source %s at version %s", mod.Kind, mod.Dir, mod.Version))

	modBytes, err := os.ReadFile(filepath.Join(v.root, "go.mod"))
	if err != nil {
		v.unknown("module-source", fmt.Sprintf("read snapshot go.mod: %v", err))
		return
	}
	gomod, err := modfile.Parse("go.mod", modBytes, nil)
	if err != nil {
		v.unknown("module-source", fmt.Sprintf("parse snapshot go.mod: %v", err))
		return
	}
	bctx, err := newRecordedBuild(v.in.Build, gomod)
	if err != nil {
		v.unknown("module-source", fmt.Sprintf("recorded build context: %v", err))
		return
	}
	v.bctx = bctx
	v.res.Target.ReleaseTags = append([]string(nil), bctx.ctx.ReleaseTags...)
}

func (v *implementationVerifier) verifyPackageFile(ctx context.Context) {
	p := v.in.Proposal
	relPkg := strings.TrimPrefix(p.Package, p.Module)
	relPkg = strings.TrimPrefix(relPkg, "/")
	pkgDir := filepath.Join(v.mod.Dir, filepath.FromSlash(relPkg))
	realMod, err := filepath.EvalSymlinks(v.mod.Dir)
	if err != nil {
		v.unknown("package-path", fmt.Sprintf("resolve module dir %s: %v", v.mod.Dir, err))
		return
	}
	realPkg, err := filepath.EvalSymlinks(pkgDir)
	if err != nil {
		v.unknown("package-path", fmt.Sprintf("package directory %s does not exist in the module source: %v", pkgDir, err))
		return
	}
	if !pathWithin(realMod, realPkg) {
		v.unknown("package-path", fmt.Sprintf("package directory %s resolves outside module source %s", pkgDir, v.mod.Dir))
		return
	}
	st, err := os.Stat(realPkg)
	if err != nil || !st.IsDir() {
		v.unknown("package-path", fmt.Sprintf("package directory %s is not a readable directory", pkgDir))
		return
	}
	v.pkgDir = realPkg
	v.pass("package-path", fmt.Sprintf("package directory %s is confined under module source %s", relOr(relPkg, "."), v.mod.Dir))

	full := filepath.Join(realPkg, filepath.FromSlash(p.File))
	if !pathWithin(realPkg, full) {
		v.unknown("file-path", fmt.Sprintf("proposed file %q resolves outside package directory %s", p.File, pkgDir))
		return
	}
	if err := ctx.Err(); err != nil {
		v.unknown("file-read", err.Error())
		return
	}
	st, err = os.Stat(full)
	if err != nil {
		v.unknown("file-path", fmt.Sprintf("proposed file %s does not exist: %v", full, err))
		return
	}
	if !st.Mode().IsRegular() {
		v.unknown("file-path", fmt.Sprintf("proposed file %s is not a regular file", full))
		return
	}
	realFile, err := filepath.EvalSymlinks(full)
	if err != nil || !pathWithin(realMod, realFile) {
		v.unknown("file-path", fmt.Sprintf("proposed file %s does not resolve inside module source %s", full, v.mod.Dir))
		return
	}
	if filepath.Dir(realFile) != realPkg {
		v.unknown("file-path", fmt.Sprintf("proposed file %s resolves outside the package directory %s", full, pkgDir))
		return
	}
	v.file = realFile

	if err := checkGo1Constraints(realFile, v.bctx.relSet, v.bctx.relExact); err != nil {
		v.unknown("file-constraint-decidable", err.Error())
		return
	}
	src, err := os.ReadFile(realFile)
	if err != nil {
		v.unknown("file-read", fmt.Sprintf("read %s: %v", realFile, err))
		return
	}
	sum := sha256.Sum256(src)
	v.res.FileSHA256 = hex.EncodeToString(sum[:])
	v.pass("file-identity", fmt.Sprintf("file %s sha256 %s", relTo(v.root, realFile), v.res.FileSHA256))

	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, realFile, src, parser.ParseComments|parser.AllErrors)
	if err != nil {
		v.unknown("file-parse", fmt.Sprintf("parse %s: %v", realFile, err))
		return
	}
	if p.Function == "" {
		// Binding locus: the proposed file must declare no functions at
		// all, and the marker is a verbatim source substring of the file.
		if fd := firstFuncDecl(af); fd != nil {
			v.unknown("function-locate", fmt.Sprintf("binding locus file %s declares %s — an empty function is admissible only for a file with no function declarations", relTo(v.root, realFile), fd.Name.Name))
			return
		}
		v.pass("function-locate", fmt.Sprintf("binding locus %s declares no functions", relTo(v.root, realFile)))
		if off := bytes.Index(src, []byte(p.Marker)); off < 0 {
			v.unknown("marker-presence", fmt.Sprintf("marker %q does not occur verbatim in %s", p.Marker, relTo(v.root, realFile)))
			return
		} else {
			v.res.FunctionLine = lineOf(fset, af.FileStart, off)
			v.pass("marker-presence", fmt.Sprintf("marker %q occurs verbatim in %s at line %d", p.Marker, relTo(v.root, realFile), v.res.FunctionLine))
		}
		return
	}
	fd, err := locateProposedFunction(af, p.Function)
	if err != nil {
		v.unknown("function-locate", err.Error())
		return
	}
	if fd.Body == nil {
		v.unknown("function-locate", fmt.Sprintf("function %q has no body in %s", p.Function, relTo(v.root, realFile)))
		return
	}
	bodyStart := fset.Position(fd.Body.Pos()).Offset
	bodyEnd := fset.Position(fd.Body.End()).Offset
	if bodyStart < 0 || bodyEnd < bodyStart || bodyEnd > len(src) {
		v.unknown("function-locate", fmt.Sprintf("function %q body span is not addressable in %s", p.Function, relTo(v.root, realFile)))
		return
	}
	v.res.FunctionLine = fset.Position(fd.Pos()).Line
	if !bytes.Contains(src[bodyStart:bodyEnd], []byte(p.Marker)) {
		v.unknown("marker-presence", fmt.Sprintf("marker %q does not occur in the body of %s (%s:%d)", p.Marker, p.Function, relTo(v.root, realFile), v.res.FunctionLine))
		return
	}
	v.pass("marker-presence", fmt.Sprintf("marker %q occurs in the body of %s at line %d", p.Marker, p.Function, v.res.FunctionLine))
}

// firstFuncDecl returns the first function or method declaration in the
// file, or nil when the file is a pure binding locus.
func firstFuncDecl(af *ast.File) *ast.FuncDecl {
	for _, d := range af.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			return fd
		}
	}
	return nil
}

// lineOf converts a byte offset inside a parsed file into a 1-based line.
// base must be the file's FileStart position, so Pos arithmetic maps the
// offset back through the FileSet correctly.
func lineOf(fset *token.FileSet, base token.Pos, off int) int {
	return fset.Position(base + token.Pos(off)).Line
}

func (v *implementationVerifier) verifyBuildSelection() {
	p := v.in.Proposal
	actual, kind, err := explicitBuildExpression(v.file)
	if err != nil {
		v.unknown("build-expression", err.Error())
		return
	}
	v.res.ActualBuildExpression = actual
	v.res.BuildExpressionKind = kind
	want, err := canonicalBuildExpression(p.BuildExpression)
	if err != nil {
		v.unknown("build-expression", err.Error())
		return
	}
	if want != actual {
		v.unknown("build-expression", fmt.Sprintf("proposed build expression %q (%s) does not match the file's actual expression %q (%s)",
			strings.TrimSpace(p.BuildExpression), want, actual, kind))
		return
	}
	v.pass("build-expression", fmt.Sprintf("proposed expression matches the file's %s expression %q", kind, actual))

	match, err := v.bctx.ctx.MatchFile(v.pkgDir, filepath.Base(v.file))
	if err != nil {
		v.unknown("build-selection", fmt.Sprintf("evaluate %s under the recorded build context: %v", relTo(v.root, v.file), err))
		return
	}
	if match {
		v.present("build-selection", fmt.Sprintf("the proposed vulnerable file %s is selected for GOOS=%s GOARCH=%s — the implementation is present, not absent",
			relTo(v.root, v.file), v.in.Build.GOOS, v.in.Build.GOARCH))
		return
	}
	v.pass("build-selection", fmt.Sprintf("%s is excluded under GOOS=%s GOARCH=%s CGO_ENABLED=%t tags=%v",
		relTo(v.root, v.file), v.in.Build.GOOS, v.in.Build.GOARCH, v.in.Build.CGOEnabled, v.in.Build.BuildTags))
}

func (v *implementationVerifier) verifyAlternates(ctx context.Context) {
	entries, err := os.ReadDir(v.pkgDir)
	if err != nil {
		v.unknown("alternate-scan", fmt.Sprintf("read package directory %s: %v", v.pkgDir, err))
		return
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".swig"), strings.HasSuffix(name, ".swigcxx"):
			v.unknown("alternate-scan", fmt.Sprintf("%s carries a SWIG input — generated cgo builds are outside the supported model", filepath.Join(v.pkgDir, name)))
			return
		case strings.HasSuffix(name, ".syso"):
			v.unknown("alternate-scan", fmt.Sprintf("%s carries a .syso object — externally linked objects are outside the supported model", filepath.Join(v.pkgDir, name)))
			return
		case e.IsDir() || !strings.HasSuffix(name, ".go"):
			continue
		case strings.HasSuffix(name, "_test.go"):
			// Test files are never part of the product build; dependency
			// test files are excluded exactly as the vendor closure does.
			continue
		}
		names = append(names, name)
	}
	if len(names) > MaxImplementationScanFiles {
		v.unknown("alternate-scan", fmt.Sprintf("package directory %s carries %d Go files; the scan bound is %d — the scan is not truncated",
			v.pkgDir, len(names), MaxImplementationScanFiles))
		return
	}
	sort.Strings(names)
	proposedBase := filepath.Base(v.file)
	selected := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			v.unknown("alternate-scan", err.Error())
			return
		}
		full := filepath.Join(v.pkgDir, name)
		rel := relTo(v.root, full)
		if name == proposedBase {
			v.res.ExcludedFiles = append(v.res.ExcludedFiles, rel)
			continue
		}
		if err := checkGo1Constraints(full, v.bctx.relSet, v.bctx.relExact); err != nil {
			v.unknown("alternate-scan", err.Error())
			return
		}
		src, err := os.ReadFile(full)
		if err != nil {
			v.unknown("alternate-scan", fmt.Sprintf("read %s: %v", full, err))
			return
		}
		match, err := v.bctx.ctx.MatchFile(v.pkgDir, name)
		if err != nil {
			v.unknown("alternate-scan", fmt.Sprintf("evaluate %s under the recorded build context: %v", full, err))
			return
		}
		if !match {
			v.res.ExcludedFiles = append(v.res.ExcludedFiles, rel)
			continue
		}
		cgo, err := fileImportsC(full, src)
		if err != nil {
			v.unknown("alternate-scan", fmt.Sprintf("parse imports of %s: %v", full, err))
			return
		}
		if cgo && !v.bctx.ctx.CgoEnabled {
			// CGO_ENABLED=0 excludes cgo files exactly as the toolchain
			// does — an excluded file contributes nothing.
			v.res.ExcludedFiles = append(v.res.ExcludedFiles, rel)
			continue
		}
		selected++
		v.res.SelectedFiles = append(v.res.SelectedFiles, rel)
		if bytes.Contains(src, []byte(v.in.Proposal.Marker)) {
			v.res.AlternateMarkerHits = append(v.res.AlternateMarkerHits, rel)
			v.present("alternate-marker", fmt.Sprintf(
				"selected alternate implementation %s carries the vulnerable marker %q — the implementation is present, not absent",
				rel, v.in.Proposal.Marker))
			return
		}
	}
	if selected == 0 {
		v.unknown("alternate-scan", fmt.Sprintf("package directory %s selects no alternate implementation files under the recorded build context — an empty selection is not a closed absence", v.pkgDir))
		return
	}
	v.pass("alternate-scan", fmt.Sprintf("%d selected alternate file(s) scanned, %d excluded; no selected file carries marker %q",
		selected, len(v.res.ExcludedFiles), v.in.Proposal.Marker))
}

// implementationModuleSource is the resolved on-disk source of one
// advisory-declared module.
type implementationModuleSource struct {
	Dir     string
	Version string
	Kind    string // main|vendor|replace
}

// resolveImplementationModule binds the proposal's module/version to the
// snapshot's own inventory: the main module, a vendored module whose
// modules.txt header and go.mod require agree on the version, or a local
// replace confined to the snapshot tree. Anything else (module cache, a
// remote replace, a version disagreeing with the inventory) fails closed.
func resolveImplementationModule(root, modulePath, version, packagePath string) (implementationModuleSource, error) {
	modBytes, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return implementationModuleSource{}, fmt.Errorf("read snapshot go.mod: %v", err)
	}
	gomod, err := modfile.Parse("go.mod", modBytes, nil)
	if err != nil {
		return implementationModuleSource{}, fmt.Errorf("parse snapshot go.mod: %v", err)
	}
	// Module identity is exact: a nested module (example.com/dep/v2) owns
	// its packages even though its path is a prefix match for the parent.
	var mods []string
	if gomod.Module != nil && gomod.Module.Mod.Path != "" {
		mods = append(mods, gomod.Module.Mod.Path)
	}
	for _, r := range gomod.Require {
		mods = append(mods, r.Mod.Path)
	}
	for _, r := range gomod.Replace {
		mods = append(mods, r.Old.Path)
		if module.CheckImportPath(r.New.Path) == nil {
			mods = append(mods, r.New.Path)
		}
	}
	if owner := domain.OwnerModule(packagePath, mods); owner != "" && owner != modulePath {
		return implementationModuleSource{}, fmt.Errorf("package %s is owned by module %s, not the proposed module %s", packagePath, owner, modulePath)
	}
	if gomod.Module != nil && gomod.Module.Mod.Path == modulePath {
		return implementationModuleSource{Dir: root, Version: version, Kind: "main"}, nil
	}
	var req *modfile.Require
	for _, r := range gomod.Require {
		if r.Mod.Path == modulePath {
			req = r
			break
		}
	}
	if req == nil {
		return implementationModuleSource{}, fmt.Errorf("module %s is not required by the snapshot go.mod", modulePath)
	}
	if !sameImplementationVersion(req.Mod.Version, version) {
		return implementationModuleSource{}, fmt.Errorf("snapshot go.mod requires %s %s, not the proposed %s", modulePath, req.Mod.Version, version)
	}
	var local string
	for _, r := range gomod.Replace {
		if r.Old.Path != modulePath {
			continue
		}
		if r.New.Version != "" && !sameImplementationVersion(r.New.Version, version) {
			return implementationModuleSource{}, fmt.Errorf("snapshot replaces %s with version %s, not the proposed %s", modulePath, r.New.Version, version)
		}
		if isLocalModulePath(r.New.Path) {
			local = r.New.Path
		}
	}
	vendorDir := filepath.Join(root, "vendor")
	if st, err := os.Stat(vendorDir); err == nil && st.IsDir() {
		mt, err := os.ReadFile(filepath.Join(vendorDir, "modules.txt"))
		if err != nil {
			return implementationModuleSource{}, fmt.Errorf("read vendor/modules.txt: %v", err)
		}
		mv, err := vendorModuleVersion(mt, modulePath)
		if err != nil {
			return implementationModuleSource{}, err
		}
		if !sameImplementationVersion(mv, version) {
			return implementationModuleSource{}, fmt.Errorf("vendor/modules.txt lists %s %s, not the proposed %s", modulePath, mv, version)
		}
		dir := filepath.Join(vendorDir, filepath.FromSlash(modulePath))
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			return implementationModuleSource{}, fmt.Errorf("vendored module directory %s is missing", dir)
		}
		return implementationModuleSource{Dir: dir, Version: mv, Kind: "vendor"}, nil
	}
	if local != "" {
		dir := local
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, filepath.FromSlash(dir))
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return implementationModuleSource{}, fmt.Errorf("resolve snapshot root: %v", err)
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return implementationModuleSource{}, fmt.Errorf("resolve replaced module dir: %v", err)
		}
		if !pathWithin(absRoot, absDir) {
			return implementationModuleSource{}, fmt.Errorf("local replacement %s escapes the snapshot tree", local)
		}
		st, err := os.Stat(absDir)
		if err != nil || !st.IsDir() {
			return implementationModuleSource{}, fmt.Errorf("replaced module directory %s is missing", absDir)
		}
		return implementationModuleSource{Dir: absDir, Version: version, Kind: "replace"}, nil
	}
	return implementationModuleSource{}, fmt.Errorf("module %s has no vendored or confined local-replace source in the snapshot — a module-cache lookup is outside the verified scope", modulePath)
}

// vendorModuleVersion returns the single modules.txt header version for an
// exact module path; a missing or duplicated header fails closed.
func vendorModuleVersion(modulesTxt []byte, modulePath string) (string, error) {
	var found []string
	for _, line := range strings.Split(string(modulesTxt), "\n") {
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) < 2 || fields[0] != modulePath {
			continue
		}
		found = append(found, fields[1])
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("vendor/modules.txt carries no header for module %s", modulePath)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("vendor/modules.txt carries %d headers for module %s — module identity is ambiguous", len(found), modulePath)
	}
}

func isLocalModulePath(p string) bool {
	return filepath.IsAbs(p) || p == "." || p == ".." ||
		strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../")
}

func sameImplementationVersion(a, b string) bool {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	return a != "" && a == b
}

// locateProposedFunction finds the single FuncDecl the proposal names. A
// bare name matches a top-level function or a method; a Type.Name form
// additionally binds the receiver. Zero or multiple matches fail closed.
func locateProposedFunction(af *ast.File, function string) (*ast.FuncDecl, error) {
	recv, name := splitProposalFunctionRef(function)
	var matches []*ast.FuncDecl
	for _, d := range af.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != name {
			continue
		}
		if recv != "" {
			if fd.Recv == nil || len(fd.Recv.List) == 0 || receiverTypeName(fd.Recv.List[0].Type) != recv {
				continue
			}
		}
		matches = append(matches, fd)
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("function %q does not occur in the proposed file", function)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("function %q is ambiguous in the proposed file (%d declarations)", function, len(matches))
	}
}

func splitProposalFunctionRef(function string) (recv, name string) {
	s := strings.TrimSpace(function)
	if strings.HasPrefix(s, "(") {
		if end := strings.Index(s, ")"); end > 1 && end+1 < len(s) && s[end+1] == '.' {
			return strings.TrimPrefix(s[1:end], "*"), s[end+2:]
		}
		return "", ""
	}
	if i := strings.LastIndex(s, "."); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

func receiverTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	case *ast.IndexListExpr:
		return receiverTypeName(t.X)
	case *ast.ParenExpr:
		return receiverTypeName(t.X)
	}
	return ""
}

func fileImportsC(file string, src []byte) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, imp := range f.Imports {
		if imp.Path != nil && imp.Path.Value == `"C"` {
			return true, nil
		}
	}
	return false, nil
}

// canonicalBuildExpression renders a proposed expression under the
// toolchain's own build-constraint grammar so whitespace and parentheses
// never decide an equality check.
func canonicalBuildExpression(expr string) (string, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", nil
	}
	line := expr
	if !constraint.IsGoBuild(line) && !constraint.IsPlusBuild(line) {
		line = "//go:build " + line
	}
	e, err := constraint.Parse(line)
	if err != nil {
		return "", fmt.Errorf("proposed build expression %q: %v", expr, err)
	}
	return e.String(), nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func relTo(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}

func relOr(rel, fallback string) string {
	if rel == "" {
		return fallback
	}
	return filepath.ToSlash(rel)
}

// evidence renders the deterministic half of the verification: snapshot
// identity, the exact source locus, and the build-selection scan. The
// proposal's own LLM-inferred quality is carried on the result, never
// promoted into these records.
func (v *implementationVerifier) evidence() []domain.Evidence {
	if v.res.ProposalID == "" {
		return nil
	}
	prefix := v.in.EvidenceIDPrefix
	if prefix == "" {
		id := strings.ToUpper(v.res.ProposalID)
		var b strings.Builder
		for _, r := range id {
			switch {
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
				b.WriteRune(r)
			default:
				b.WriteByte('-')
			}
		}
		prefix = "EV-IMPL-" + b.String()
	}
	var out []domain.Evidence
	out = append(out, domain.Evidence{
		ID:           domain.EvidenceID(prefix + "-IDENTITY"),
		Kind:         domain.EvidenceBuild,
		Quality:      domain.QualityDeterministic,
		Source:       "snapshot content hash + vendor module inventory",
		File:         relTo(v.root, v.mod.Dir),
		Tool:         "affected.VerifyImplementationLocus",
		ToolVersion:  "implementation-locus/1",
		Command:      "verify-implementation-locus",
		Content:      fmt.Sprintf("snapshot_sha256=%s module=%s version=%s source_kind=%s package=%s", v.res.SnapshotContentHash, v.res.Module, v.res.Version, v.res.ModuleSource, v.res.Package),
		ArtifactHash: v.res.SnapshotContentHash,
		Limitations:  []string{"source identity is the snapshot content hash; module identity comes from go.mod/vendor/modules.txt"},
	})
	if v.file != "" {
		out = append(out, domain.Evidence{
			ID:           domain.EvidenceID(prefix + "-LOCUS"),
			Kind:         domain.EvidenceSourceSnippet,
			Quality:      domain.QualityDeterministic,
			Source:       "proposed locus resolved in the snapshot AST",
			File:         relTo(v.root, v.file),
			StartLine:    v.res.FunctionLine,
			EndLine:      v.res.FunctionLine,
			Tool:         "affected.VerifyImplementationLocus",
			ToolVersion:  "implementation-locus/1",
			Command:      "verify-implementation-locus",
			Content:      fmt.Sprintf("function=%s marker=%s file_sha256=%s build_expression=%s", v.res.Function, v.res.Marker, v.res.FileSHA256, v.res.ActualBuildExpression),
			ArtifactHash: v.res.FileSHA256,
			Limitations:  []string{"the proposal is LLM-inferred; this record is the deterministic source lookup it was checked against"},
		})
	}
	out = append(out, domain.Evidence{
		ID:          domain.EvidenceID(prefix + "-BUILD"),
		Kind:        domain.EvidenceBuild,
		Quality:     domain.QualityDeterministic,
		Source:      "go/build.Context recorded build selection",
		Tool:        "affected.VerifyImplementationLocus",
		ToolVersion: "implementation-locus/1",
		Command:     "verify-implementation-locus",
		Content: fmt.Sprintf("GOOS=%s GOARCH=%s CGO_ENABLED=%t tags=%v release_tags=%v selected=%v excluded=%v alternate_marker_hits=%v",
			v.res.Target.GOOS, v.res.Target.GOARCH, v.res.Target.CGOEnabled, v.res.Target.BuildTags, v.res.Target.ReleaseTags,
			v.res.SelectedFiles, v.res.ExcludedFiles, v.res.AlternateMarkerHits),
		Limitations: []string{
			fmt.Sprintf("scan scope: every non-test .go file in %s; bound %d files; runtime/deployment loading is out of scope", relTo(v.root, v.pkgDir), MaxImplementationScanFiles),
		},
	})
	return out
}
