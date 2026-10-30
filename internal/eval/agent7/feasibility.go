// A1.5 proof-feasibility preflight: deterministic per-case fact collector
// (plan §A1.5, spec §3, §7.1–7.4). It reads the frozen dataset record, the
// OSV advisory the run consumed, the pinned source snapshot (go.mod /
// go.sum / vendor/modules.txt / go.work / build-constrained and generated
// files) and the B0 run envelope (prediction.json), and emits
// machine-checkable facts for the independent expert classification
// (Task B). It collects facts only: ARTIFACT_FIXED / COMPONENT_ABSENT /
// BUILD_EXCLUDED checkers are NOT implemented here — proof_* fields report
// whether the underlying fact pattern is deterministically present,
// refuted or undecidable with the available inputs, never a certificate.
//
// The package stays a pure library: no exec, no network. The advisory is
// parsed with the same conversion the analyzer uses (vulnerability
// FileSource with alias enrichment off, so no OSV HTTP ever happens); the
// module graph is reconstructed from files (every go.mod require/replace
// plus vendor/modules.txt), matching the semantics of
// internal/affected.ExecGoTool.ListModules without running `go list`.
package agent7

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/vulnerability"
)

// FeasibilitySchema identifies the raw collector output version.
const FeasibilitySchema = "agent7-feasibility-facts/1"

// Tri-state fact values used by every yes/no fact column.
const (
	FactYes     = "yes"
	FactNo      = "no"
	FactUnknown = "unknown"
)

// Blocker kinds (frozen enum from the task brief):
//   - none:              no blocking reason recorded — either every proof
//     candidate's fact pattern is affirmatively refuted, or (after a
//     candidate) the advisory manifest is verified complete;
//   - missing_data:      a required input is absent or undecidable
//     (missing advisory/envelope/module records, no release toolchain,
//     vulnerable source not present in the snapshot, advisory
//     completeness unknown);
//   - missing_algorithm: the data exists but no deterministic offline
//     algorithm in this repo can evaluate it (in-tree/unversioned
//     components cannot enter a version comparison; go.work graph
//     resolution; package-import closure of non-vendored modules);
//   - scope:             the candidate is blocked on scope/applicability
//     grounds, not data (advisory manifest is known to be incomplete —
//     the vulnerable component is outside its affected list).
const (
	BlockerNone             = "none"
	BlockerMissingData      = "missing_data"
	BlockerMissingAlgorithm = "missing_algorithm"
	BlockerScope            = "scope"
	// BlockerIntegrity marks an integrity failure: the envelope's
	// recorded advisory hash differs from the advisory file consumed, or
	// the snapshot content hash differs from the frozen manifest pin.
	// Derived facts fail closed to unknown — a mismatch can never carry
	// a yes/no.
	BlockerIntegrity = "integrity"
)

// FactRecord is the machine-checkable fact set for one case (the frozen
// A1.5 column list). Every fact is a concrete value or the explicit
// string "unknown" — never a silent blank and never an invented value.
// Multi-entry advisories align their per-entry values with "|"
// (vulnerable_module / vulnerable_package / resolved_version /
// affected_range / fix_version); "none" marks a determinable absence.
// CollectionNotes is diagnostic text (fail-closed explanations and
// integrity mismatches); it is kept out of the fact columns and the CSV.
type FactRecord struct {
	TaskID                   string   `json:"task_id"`
	CVEID                    string   `json:"cve_id"`
	GTClass                  string   `json:"gt_class"`
	GTCategory               string   `json:"gt_category"`
	RepoURL                  string   `json:"repo_url"`
	CommitSHA                string   `json:"commit_sha"`
	SnapshotDir              string   `json:"snapshot_dir"`
	TargetKind               string   `json:"target_kind"`
	VulnerableModule         string   `json:"vulnerable_module"`
	VulnerablePackage        string   `json:"vulnerable_package"`
	ResolvedVersion          string   `json:"resolved_version"`
	AffectedRange            string   `json:"affected_range"`
	FixVersion               string   `json:"fix_version"`
	ComponentIsFirstParty    string   `json:"component_is_first_party"`
	ComponentInModuleGraph   string   `json:"component_in_module_graph"`
	ComponentVendored        string   `json:"component_vendored"`
	MultiModule              string   `json:"multi_module"`
	GoWork                   string   `json:"go_work"`
	GeneratedCodePresent     string   `json:"generated_code_present"`
	BuildTagGated            string   `json:"build_tag_gated"`
	ReleaseGoVersion         string   `json:"release_go_version"`
	GoVersionSource          string   `json:"go_version_source"`
	MinimumGoVersion         string   `json:"minimum_go_version"`
	VendorMode               string   `json:"vendor_mode"`
	GOOS                     string   `json:"goos"`
	GOARCH                   string   `json:"goarch"`
	BuildTags                []string `json:"build_tags"`
	ContentHash              string   `json:"content_hash"`
	AdvisorySource           string   `json:"advisory_source"`
	AdvisorySHA256           string   `json:"advisory_sha256"`
	AdvisoryModified         string   `json:"advisory_modified"`
	DeliveredArtifact        string   `json:"delivered_artifact_available"`
	BuildAttestation         string   `json:"build_attestation_available"`
	BinaryInventoryComplete  string   `json:"binary_inventory_complete"`
	AdvisoryManifestComplete string   `json:"advisory_manifest_complete"`
	IzyanVerdict             string   `json:"izyan_verdict"`
	IzyanFalsifier           string   `json:"izyan_falsifier"`
	IzyanGroundingConditions []string `json:"izyan_grounding_conditions"`
	IzyanLimitations         []string `json:"izyan_limitations"`
	IzyanError               string   `json:"izyan_error"`
	// RunEnvelopePresent records whether a prediction.json was read; a
	// missing envelope is a completeness failure, never a result.
	RunEnvelopePresent bool `json:"run_envelope_present"`
	// InfraError marks envelopes that carry an infrastructure failure
	// (run-profile error, context cancellation, advisory fetch error).
	// Such a case never enters verdict/outcome aggregates — the frozen
	// taxonomy reserves INFRA_ERROR for exactly this class.
	InfraError  bool   `json:"infra_error"`
	InfraReason string `json:"infra_reason,omitempty"`
	// RunSegment names the run directory the envelope was taken from when
	// the generator merges multiple run segments ("" for a single run).
	RunSegment           string   `json:"run_segment,omitempty"`
	ProofArtifactFixed   string   `json:"proof_artifact_fixed"`
	ProofComponentAbsent string   `json:"proof_component_absent"`
	ProofBuildExcluded   string   `json:"proof_build_excluded"`
	BlockerKind          string   `json:"blocker_kind"`
	CollectionNotes      []string `json:"collection_notes,omitempty"`
}

// FeasibilityInputs carries the controller-resolved inputs for one case.
// Any field may be absent; the collector degrades the dependent facts to
// "unknown" rather than inventing values.
type FeasibilityInputs struct {
	Task TaskRecord

	// SnapshotDir is the local path of the pinned source snapshot
	// (repos_dir/<owner>/<repo>/<sha>). Empty or missing → all
	// snapshot-derived facts become unknown.
	SnapshotDir string

	// PredictionPath is the B0 per-case envelope
	// (<run>/<case>/prediction.json). Empty or unreadable → izyan_* and
	// run-provenance facts unknown.
	PredictionPath string

	// AdvisoryPath is the prepared OSV document the run consumed
	// (<run>/<case>/advisory/<id>.json). Empty or unreadable →
	// advisory-derived facts unknown.
	AdvisoryPath string

	// ExpectedContentHash is the frozen manifest's snapshot hash for this
	// case ("" = not pinned). It never overwrites the observed hash; a
	// mismatch is reported in CollectionNotes.
	ExpectedContentHash string

	// AdvisoryManifestComplete lets the controller record externally
	// verified advisory completeness ("yes"/"no"; "" → unknown). Facts
	// alone cannot prove a manifest lists every affected component, so
	// the default is unknown and only an external audit may set "no".
	AdvisoryManifestComplete string
}

// predictionEnvelope mirrors the emitted fields of the B0 per-case
// envelope (cmd/izyan/vexbench.go vexEnvelope); only what the collector
// reads is declared. Ground truth never appears here — the envelope
// contract keeps it in scoring/cases.jsonl only.
type predictionEnvelope struct {
	TaskID           string   `json:"task_id"`
	TerminalState    string   `json:"terminal_state"`
	Verdict          string   `json:"verdict"`
	Reason           string   `json:"reason"`
	GroundingCond    []string `json:"grounding_condition_ids"`
	Falsifier        string   `json:"falsifier"`
	GroundBasis      string   `json:"ground_basis"`
	Limitations      []string `json:"limitations"`
	Error            string   `json:"error"`
	ScoringOutcome   string   `json:"scoring_outcome"`
	CompatibilityCat string   `json:"compatibility_category"`
	CaseDir          string   `json:"case_dir"`
	ReportPath       string   `json:"report_path"`
	ContentHash      string   `json:"content_hash"`
	AdvisorySource   string   `json:"advisory_source"`
	AdvisorySHA256   string   `json:"advisory_sha256"`
	AdvisoryResolved string   `json:"advisory_resolved"`
	AdvisoryModified string   `json:"advisory_modified"`
	ReleaseGoVersion string   `json:"release_go_version"`
	GoVersionSource  string   `json:"go_version_source"`
	MinimumGoVersion string   `json:"minimum_go_version"`
	VendorMode       bool     `json:"vendor_mode"`
	CGOEnabled       bool     `json:"cgo_enabled"`
	GOOS             string   `json:"goos"`
	GOARCH           string   `json:"goarch"`
	BuildTags        []string `json:"build_tags"`
}

// CollectCase reads the deterministic inputs of one case and returns its
// fact record. It never fails the whole collection: unreadable inputs
// mark the dependent facts "unknown" and are explained in
// CollectionNotes — the fail-closed rule for proof candidacy.
func CollectCase(ctx context.Context, in FeasibilityInputs) FactRecord {
	rec := FactRecord{TargetKind: "source_tree"}
	rec.TaskID = orUnknown(in.Task.TaskID)
	rec.CVEID = orUnknown(in.Task.CVEID)
	rec.GTClass = orUnknown(in.Task.GroundTruth)
	rec.GTCategory = orUnknown(in.Task.GroundTruthCategory)
	rec.RepoURL = orUnknown(in.Task.RepoURL)
	rec.CommitSHA = orUnknown(in.Task.CommitSHA)
	rec.SnapshotDir = snapshotKey(in.Task)

	var notes []string
	note := func(format string, args ...any) {
		notes = append(notes, fmt.Sprintf(format, args...))
	}

	env, envPresent := readEnvelope(in.PredictionPath, note)
	snap := scanSnapshot(in.SnapshotDir, envPresent && env.VendorMode, note)
	vuln, advSHA, advPresent := readAdvisory(ctx, in.AdvisoryPath, note)

	// --- run provenance facts --------------------------------------------------
	if envPresent {
		rec.ContentHash = orUnknown(env.ContentHash)
		rec.AdvisorySource = orUnknown(env.AdvisorySource)
		rec.AdvisorySHA256 = orUnknown(env.AdvisorySHA256)
		if rec.AdvisorySHA256 == FactUnknown {
			rec.AdvisorySHA256 = orUnknown(advSHA)
		}
		rec.AdvisoryModified = orUnknown(env.AdvisoryModified)
		if rec.AdvisoryModified == FactUnknown {
			rec.AdvisoryModified = orUnknown(vulnModified(vuln))
		}
		rec.ReleaseGoVersion = orUnknown(env.ReleaseGoVersion)
		rec.GoVersionSource = orUnknown(env.GoVersionSource)
		rec.MinimumGoVersion = orUnknown(env.MinimumGoVersion)
		rec.VendorMode = boolFact(env.VendorMode)
		rec.GOOS = orUnknown(env.GOOS)
		rec.GOARCH = orUnknown(env.GOARCH)
		rec.BuildTags = env.BuildTags
		rec.IzyanVerdict = orUnknown(env.Verdict)
		rec.IzyanFalsifier = orNone(env.Falsifier)
		rec.IzyanGroundingConditions = env.GroundingCond
		rec.IzyanLimitations = env.Limitations
		rec.IzyanError = orNone(env.Error)
		if ok, why := IsInfraEnvelope(env.TerminalState, env.Verdict, env.Reason, env.Error); ok {
			// An infra failure masquerading as an abstain verdict must
			// never be counted as an analyzer result (memguard/OSV
			// cancellations report INCONCLUSIVE+abstain at ~0s wall).
			rec.InfraError = true
			rec.InfraReason = why
			rec.IzyanVerdict = "infra_error"
		}
		rec.RunEnvelopePresent = true
	} else {
		rec.ContentHash = FactUnknown
		rec.AdvisorySHA256 = orUnknown(advSHA)
		rec.AdvisoryModified = orUnknown(vulnModified(vuln))
		if advPresent {
			rec.AdvisorySource = "file:" + filepath.Base(in.AdvisoryPath)
		} else {
			rec.AdvisorySource = FactUnknown
		}
		rec.ReleaseGoVersion = FactUnknown
		rec.GoVersionSource = FactUnknown
		rec.MinimumGoVersion = orUnknown(snap.minGo)
		rec.VendorMode = orUnknown(snap.vendorFact)
		rec.GOOS, rec.GOARCH = FactUnknown, FactUnknown
		rec.BuildTags = nil
		rec.IzyanVerdict = FactUnknown
		rec.IzyanFalsifier = FactUnknown
		rec.IzyanError = "prediction.json unavailable"
		// A missing envelope is a completeness failure, not a result.
		rec.InfraError = true
		rec.InfraReason = "prediction.json unavailable"
	}
	// Integrity gate: a mismatch between the envelope's recorded advisory
	// hash and the prepared advisory's bytes, or between the observed
	// snapshot content hash and the frozen manifest pin, invalidates every
	// advisory/snapshot-derived fact and all proof_* candidates — never
	// merely a note.
	integrityOK := true
	if in.ExpectedContentHash != "" && rec.ContentHash != FactUnknown &&
		!strings.EqualFold(rec.ContentHash, in.ExpectedContentHash) {
		note("integrity: content_hash %s does not match manifest snapshot hash %s",
			rec.ContentHash, in.ExpectedContentHash)
		integrityOK = false
	}
	if envPresent && advSHA != "" && env.AdvisorySHA256 != "" &&
		!strings.EqualFold(env.AdvisorySHA256, advSHA) {
		note("integrity: envelope advisory_sha256 %s differs from advisory file sha256 %s",
			env.AdvisorySHA256, advSHA)
		integrityOK = false
	}

	// --- snapshot facts --------------------------------------------------------
	rec.MultiModule = orUnknown(snap.multiModule)
	rec.GoWork = orUnknown(snap.goWork)
	rec.GeneratedCodePresent = orUnknown(snap.generated)
	if rec.MinimumGoVersion == FactUnknown {
		rec.MinimumGoVersion = orUnknown(snap.minGo)
	}

	// --- advisory component facts -----------------------------------------------
	entries := advisoryEntries(vuln)
	mods := make([]string, len(entries))
	pkgs := make([]string, len(entries))
	ranges := make([]string, len(entries))
	fixes := make([]string, len(entries))
	for i, e := range entries {
		mods[i] = orUnknown(e.Module)
		pkgs[i] = packageList(e)
		ranges[i] = orNone(rangeList(e.AffectedVersions))
		fixes[i] = orNone(strings.Join(e.FixedVersions, ","))
	}
	rec.VulnerableModule = orUnknown(strings.Join(mods, "|"))
	rec.VulnerablePackage = orUnknown(strings.Join(pkgs, "|"))
	rec.AffectedRange = orUnknown(strings.Join(ranges, "|"))
	rec.FixVersion = orUnknown(strings.Join(fixes, "|"))
	if !advPresent {
		rec.VulnerableModule = FactUnknown
		rec.VulnerablePackage = FactUnknown
		rec.AffectedRange = FactUnknown
		rec.FixVersion = FactUnknown
	}
	switch strings.ToLower(in.AdvisoryManifestComplete) {
	case FactYes, FactNo:
		rec.AdvisoryManifestComplete = strings.ToLower(in.AdvisoryManifestComplete)
	default:
		rec.AdvisoryManifestComplete = FactUnknown
	}

	// --- per-entry module resolution ---------------------------------------------
	vers := make([]string, len(entries))
	pres := make([]string, len(entries))
	vend := make([]string, len(entries))
	fpar := make([]string, len(entries))
	entBlock := make([]string, len(entries))
	for i, e := range entries {
		m := snap.resolveModule(e.Module)
		vers[i] = orUnknown(m.version)
		pres[i] = FactUnknown
		vend[i] = FactUnknown
		fpar[i] = FactUnknown
		entBlock[i] = m.blocker
		switch {
		case isStdlib(e.Module):
			pres[i] = FactYes // the toolchain always delivers stdlib
			vend[i] = FactNo
			fpar[i] = FactNo
			if envPresent && env.ReleaseGoVersion != "" {
				vers[i] = env.ReleaseGoVersion
			}
		case m.found:
			pres[i] = FactYes
			vend[i] = boolFact(m.vendored)
			fpar[i] = boolFact(m.firstParty)
		case m.undecidable:
			vend[i], fpar[i] = FactUnknown, FactUnknown
		default:
			pres[i] = FactNo
			vend[i] = FactNo
			fpar[i] = FactNo
		}
	}
	rec.ResolvedVersion = orUnknown(strings.Join(vers, "|"))
	if len(entries) == 0 {
		rec.ComponentInModuleGraph = FactUnknown
		rec.ComponentVendored = FactUnknown
		rec.ComponentIsFirstParty = FactUnknown
	} else {
		rec.ComponentInModuleGraph = aggregateAny(pres)
		rec.ComponentVendored = aggregateAny(vend)
		rec.ComponentIsFirstParty = aggregateAny(fpar)
	}

	// --- delivered-artifact facts: uniform for source snapshots ------------------
	// The benchmark mounts immutable source trees; no delivered artifact,
	// build attestation or binary inventory exists in the inputs. A
	// source-tree certificate can never claim a delivered binary.
	rec.DeliveredArtifact = FactNo
	rec.BuildAttestation = FactNo
	rec.BinaryInventoryComplete = FactUnknown

	// --- proof-candidate feasibility ----------------------------------------------
	// ARTIFACT_FIXED: every module entry must resolve to a version
	// deterministically outside its affected ranges. Semantics mirror
	// internal/affected inRange: [introduced, fixed) /
	// [introduced, last_affected]; an unresolvable version cannot be
	// compared (never read as fixed).
	fixedAll, fixedBlock := true, ""
	anyVerified := false // positive evidence: a present entry verified fixed
	for i, e := range entries {
		if pres[i] == FactNo {
			// Absent component: a fix comparison does not apply —
			// inapplicability (scope), neutral for this candidate,
			// never missing data.
			continue
		}
		if pres[i] != FactYes {
			fixedAll = false
			if fixedBlock == "" {
				fixedBlock = orDefault(entBlock[i], BlockerMissingData)
			}
			continue
		}
		v := feasNormalizeVersion(vers[i])
		if v == "" {
			fixedAll = false
			if fixedBlock == "" {
				fixedBlock = orDefault(entBlock[i], BlockerMissingAlgorithm)
			}
			continue
		}
		if len(e.AffectedVersions) == 0 {
			fixedAll = false
			if fixedBlock == "" {
				fixedBlock = BlockerMissingData // advisory carries no usable range
			}
			continue
		}
		if feasAffected(v, e.AffectedVersions) {
			fixedAll = false
			fixedBlock = ""
			break // affirmatively refuted: a resolved version inside the range
		}
		anyVerified = true
	}
	switch {
	case len(entries) == 0:
		rec.ProofArtifactFixed, fixedBlock = FactUnknown, BlockerMissingData
	case fixedBlock == "" && !fixedAll:
		rec.ProofArtifactFixed = FactNo
	case fixedAll && anyVerified:
		// Positive evidence: at least one present entry verifiably
		// outside every affected range; absent entries are neutral.
		rec.ProofArtifactFixed = FactYes
	default:
		rec.ProofArtifactFixed = FactUnknown
		if fixedBlock == "" {
			fixedBlock = BlockerMissingData
		}
	}

	// COMPONENT_ABSENT: every advisory module entry must be
	// deterministically outside the snapshot's module graph. Any present
	// entry refutes the candidate outright.
	absent := FactYes
	for _, p := range pres {
		switch p {
		case FactYes:
			absent = FactNo
		case FactUnknown:
			if absent != FactNo {
				absent = FactUnknown
			}
		}
	}
	absentBlock := ""
	switch {
	case len(entries) == 0:
		rec.ProofComponentAbsent, absentBlock = FactUnknown, BlockerMissingData
	case absent == FactYes:
		rec.ProofComponentAbsent = FactYes
	case absent == FactNo:
		rec.ProofComponentAbsent = FactNo
	default:
		rec.ProofComponentAbsent = FactUnknown
		for i, p := range pres {
			if p == FactUnknown {
				absentBlock = orDefault(entBlock[i], BlockerMissingData)
				break
			}
		}
	}

	// BUILD_EXCLUDED: `yes` requires POSITIVE evidence — every affected
	// package excluded under the run's build context AND none left
	// undecidable. A package whose source never enters the snapshot
	// (external module, stdlib), a module absent from the graph (the
	// component-absent fact, not exclusion), or a build context too weak
	// to decide are all undecidable, not excluded — incomplete variant
	// coverage can never certify exclusion.
	pkgExcluded, pkgIncluded, pkgUndecidable, pkgGated, pkgBlock := evaluatePackages(entries, snap, env, envPresent, note)
	rec.BuildTagGated = orUnknown(pkgGated)
	switch {
	case len(entries) == 0:
		rec.ProofBuildExcluded, pkgBlock = FactUnknown, BlockerMissingData
	case pkgIncluded > 0:
		// A package affirmatively included under the run context refutes
		// the candidate outright — undecidable siblings cannot rescue it.
		rec.ProofBuildExcluded = FactNo
	case pkgUndecidable > 0:
		rec.ProofBuildExcluded = FactUnknown
		pkgBlock = orDefault(pkgBlock, BlockerMissingData)
	case pkgExcluded > 0:
		rec.ProofBuildExcluded = FactYes
	default:
		// Nothing evaluated at all (empty package lists).
		rec.ProofBuildExcluded = FactUnknown
		pkgBlock = orDefault(pkgBlock, BlockerMissingData)
	}

	if !integrityOK {
		// Fail closed on integrity: every advisory/snapshot-derived fact
		// and every proof candidate becomes unknown; the reason stays in
		// collection_notes. Never emit yes/no from tainted inputs.
		for _, f := range []*string{
			&rec.VulnerableModule, &rec.VulnerablePackage, &rec.AffectedRange,
			&rec.FixVersion, &rec.ResolvedVersion,
			&rec.ComponentInModuleGraph, &rec.ComponentVendored,
			&rec.ComponentIsFirstParty, &rec.MultiModule, &rec.GoWork,
			&rec.GeneratedCodePresent, &rec.BuildTagGated,
			&rec.ProofArtifactFixed, &rec.ProofComponentAbsent,
			&rec.ProofBuildExcluded,
		} {
			*f = FactUnknown
		}
		rec.BlockerKind = BlockerIntegrity
		rec.CollectionNotes = notes
		return rec
	}
	// --- blocker roll-up ----------------------------------------------------------
	// With a live ("yes") candidate the blocker is what still blocks its
	// certificate: advisory completeness unknown = missing_data, a manifest
	// proven incomplete = scope (applicability, not data). Undecidable
	// siblings do not contaminate a live candidate's blocker. Without a
	// live candidate, the recorded input blocker of the undecidable
	// candidates wins; missing_data dominates because it is the cheaper
	// gap to close. All-refuted rows carry none.
	certBlock := BlockerMissingData
	if rec.AdvisoryManifestComplete == FactNo {
		certBlock = BlockerScope
	} else if rec.AdvisoryManifestComplete == FactYes {
		certBlock = BlockerNone
	}
	anyYes := false
	unknownKinds := map[string]bool{}
	for _, pair := range [][2]string{
		{rec.ProofArtifactFixed, fixedBlock},
		{rec.ProofComponentAbsent, absentBlock},
		{rec.ProofBuildExcluded, pkgBlock},
	} {
		switch pair[0] {
		case FactYes:
			anyYes = true
		case FactUnknown:
			unknownKinds[orDefault(pair[1], BlockerMissingData)] = true
		}
	}
	switch {
	case anyYes:
		rec.BlockerKind = certBlock
	case rec.AdvisoryManifestComplete == FactNo &&
		(rec.ProofArtifactFixed != FactNo || rec.ProofComponentAbsent != FactNo ||
			rec.ProofBuildExcluded != FactNo):
		// A manifest proven incomplete is the honest headline wherever a
		// candidate is still live or undecidable: no fact collection can
		// close an applicability gap. Fully refuted rows keep `none`.
		rec.BlockerKind = BlockerScope
	case unknownKinds[BlockerMissingData]:
		rec.BlockerKind = BlockerMissingData
	case unknownKinds[BlockerMissingAlgorithm]:
		rec.BlockerKind = BlockerMissingAlgorithm
	case unknownKinds[BlockerScope]:
		rec.BlockerKind = BlockerScope
	default:
		rec.BlockerKind = BlockerNone
	}
	rec.CollectionNotes = notes
	return rec
}

// IsInfraEnvelope reports whether a run envelope carries an
// infrastructure failure rather than an analyzer result, mirroring the
// frozen taxonomy's INFRA_ERROR class. Detection is deliberately
// conservative: only explicit signals qualify — a non-empty error field,
// terminal_state FAILED, or a reason that names an infrastructure cause
// (context cancellation, advisory fetch/OSV get failure). A plain
// "advisory unsupported"/"inconclusive" reason is a real outcome, never
// re-classified. The second return value is the raw reason for audit.
func IsInfraEnvelope(terminalState, verdict, reason, errField string) (bool, string) {
	if errField != "" {
		return true, errField
	}
	// Only COMPLETED/INCONCLUSIVE carry real analyzer results; any other
	// terminal_state — including FAILED and unknown values — is an
	// infrastructure outcome, never evidence.
	ts := strings.ToUpper(strings.TrimSpace(terminalState))
	if ts != "COMPLETED" && ts != "INCONCLUSIVE" {
		return true, orDefault(reason, "terminal_state="+terminalState)
	}
	r := strings.ToLower(reason)
	for _, sig := range []string{"advisory error", "context canceled", "context deadline exceeded", "osv get"} {
		if strings.Contains(r, sig) {
			return true, reason
		}
	}
	return false, ""
}

// readEnvelope loads prediction.json; a missing/invalid file is a
// collection note, not a fatal error — every run-derived fact degrades.
func readEnvelope(path string, note func(string, ...any)) (predictionEnvelope, bool) {
	var env predictionEnvelope
	if path == "" {
		return env, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		note("prediction.json unreadable: %v", err)
		return env, false
	}
	if err := json.Unmarshal(b, &env); err != nil {
		note("prediction.json malformed: %v", err)
		return env, false
	}
	// An envelope must carry the minimum identity of a completed attempt:
	// {} or a verdict-less stub is not evidence of a run.
	if env.TaskID == "" || env.TerminalState == "" {
		note("prediction.json incomplete: task_id/terminal_state missing")
		return env, false
	}
	return env, true
}

// readAdvisory parses the prepared OSV document with the analyzer's own
// conversion (FileSource, alias enrichment disabled → no network). It
// returns the vulnerability model, the file's sha256 and whether a
// usable document was parsed.
func readAdvisory(ctx context.Context, path string, note func(string, ...any)) (*domain.Vulnerability, string, bool) {
	if path == "" {
		return nil, "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		note("advisory unreadable: %v", err)
		return nil, "", false
	}
	sum := sha256.Sum256(b)
	src := vulnerability.FileSource{Path: path, NoAliasEnrichment: true}
	v, err := src.Get(ctx, "")
	if err != nil {
		note("advisory unparsable: %v", err)
		return nil, hex.EncodeToString(sum[:]), false
	}
	return v, hex.EncodeToString(sum[:]), true
}

// snapshotFacts is the deterministic file-level view of one snapshot.
type snapshotFacts struct {
	root        string
	scanned     bool
	rootModule  string
	minGo       string
	multiModule string
	goWork      string
	vendorFact  string
	generated   string
	gomods      []*gomodInfo
	vendorMods  map[string]affected.Module // by declared module path
	// parseFailures counts go.mod files that failed to parse. Any failure
	// fails closed on module ABSENCE: an unreadable require list may have
	// declared the module.
	parseFailures int
}

// gomodInfo is one parsed go.mod inside the snapshot.
type gomodInfo struct {
	dir     string
	module  string
	goVer   string
	require map[string]string         // declared path -> required version
	replace map[string]module.Version // declared path -> replacement
}

// resolvedModule is one advisory module resolved against the snapshot.
type resolvedModule struct {
	found       bool
	undecidable bool // files cannot decide presence (go.work composition)
	vendored    bool
	firstParty  bool
	unversioned bool // first-party code or a local replace: no released version
	version     string
	blocker     string // why present/undecidable when not affirmatively found
}

// scanSnapshot walks the snapshot once and extracts every snapshot-level
// fact. It never executes repository code: go.mod files are parsed,
// vendor/modules.txt is the authoritative vendored-module record, and the
// generated-code check is a bounded byte-prefix scan (vendored trees are
// skipped — they are dependency content, not product generation).
func scanSnapshot(dir string, envVendor bool, note func(string, ...any)) *snapshotFacts {
	sf := &snapshotFacts{vendorMods: map[string]affected.Module{}}
	if dir == "" {
		return sf
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		note("snapshot dir unresolvable: %v", err)
		return sf
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		note("snapshot dir missing: %s", dir)
		return sf
	}
	sf.scanned = true
	sf.root = root

	generatedSeen := false
	vendorSeen := false
	goWorkSeen := false
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			note("snapshot walk skipped %s: %v", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = p
		}
		if d.IsDir() {
			// .git must not exist in pinned snapshots (LocateSnapshot
			// rejects it). The vendor tree is walked only one level deep
			// so vendor/modules.txt is still read; vendored source is
			// reached through targeted package lookups instead.
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			if strings.HasPrefix(filepath.ToSlash(rel), "vendor/") {
				return fs.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "go.mod":
			if g := parseGoMod(p, note); g != nil {
				sf.gomods = append(sf.gomods, g)
			} else {
				sf.parseFailures++
			}
		case "go.work":
			if filepath.ToSlash(rel) == "go.work" {
				goWorkSeen = true
			}
		case "modules.txt":
			if filepath.ToSlash(rel) == "vendor/modules.txt" {
				b, err := os.ReadFile(p)
				if err != nil {
					note("vendor/modules.txt unreadable: %v", err)
					return nil
				}
				for _, m := range affected.ParseVendorModules(b) {
					sf.vendorMods[m.Path] = m
				}
				vendorSeen = true
			}
		default:
			if generatedSeen || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			// Go convention: a "Code generated ... DO NOT EDIT" comment
			// precedes the package clause; a 4 KiB head read covers it.
			head, err := readHead(p, 4096)
			if err == nil && bytes.Contains(head, []byte("Code generated")) &&
				bytes.Contains(head, []byte("DO NOT EDIT")) {
				generatedSeen = true
			}
		}
		return nil
	})
	if walkErr != nil {
		note("snapshot walk failed: %v", walkErr)
	}
	for _, g := range sf.gomods {
		if g.dir == root {
			sf.rootModule = g.module
			sf.minGo = g.goVer
		}
	}
	sf.multiModule = boolFact(len(sf.gomods) > 1)
	sf.goWork = boolFact(goWorkSeen)
	sf.generated = boolFact(generatedSeen)
	sf.vendorFact = boolFact(envVendor || vendorSeen)
	return sf
}

// parseGoMod reads one go.mod; malformed files are noted and skipped.
func parseGoMod(path string, note func(string, ...any)) *gomodInfo {
	b, err := os.ReadFile(path)
	if err != nil {
		note("go.mod unreadable %s: %v", path, err)
		return nil
	}
	f, err := modfile.Parse(path, b, nil)
	if err != nil {
		note("go.mod unparsable %s: %v", path, err)
		return nil
	}
	g := &gomodInfo{dir: filepath.Dir(path),
		require: map[string]string{}, replace: map[string]module.Version{}}
	if f.Module != nil {
		g.module = f.Module.Mod.Path
	}
	if f.Go != nil {
		g.goVer = f.Go.Version
	}
	for _, r := range f.Require {
		g.require[r.Mod.Path] = r.Mod.Version
	}
	for _, r := range f.Replace {
		g.replace[r.Old.Path] = r.New
	}
	return g
}

// resolveModule resolves one advisory module against the snapshot's
// file-level module records: vendor/modules.txt first (authoritative for
// a vendored build), then the union of every go.mod's require+replace.
// Local (in-tree) replaces mark the component first-party and unversioned
// — its content is in the snapshot, but no released version exists to
// compare with an advisory range.
func (sf *snapshotFacts) resolveModule(modulePath string) resolvedModule {
	var m resolvedModule
	if modulePath == "" {
		m.blocker = BlockerMissingData
		return m
	}
	if sf == nil || !sf.scanned {
		m.undecidable, m.blocker = true, BlockerMissingData
		return m
	}
	if sf.rootModule != "" &&
		(modulePath == sf.rootModule || strings.HasPrefix(modulePath, sf.rootModule+"/")) {
		m.found, m.firstParty, m.unversioned, m.version = true, true, true, "in-tree"
		return m
	}
	if vm, ok := sf.vendorMods[modulePath]; ok {
		m.found, m.vendored = true, true
		m.version = vm.EffectiveVersion()
		if vm.Replace != nil && isLocalPath(vm.Replace.Path) {
			m.firstParty, m.unversioned = true, true
			m.version = "in-tree"
		} else if m.version == "" {
			m.unversioned, m.version = true, "in-tree"
		}
		return m
	}
	for _, g := range sf.gomods {
		v, ok := g.require[modulePath]
		if !ok {
			continue
		}
		m.found = true
		m.version = v
		if nw, has := g.replace[modulePath]; has {
			switch {
			case isLocalPath(nw.Path):
				m.firstParty, m.unversioned = true, true
				m.version = "in-tree"
			case nw.Version != "":
				m.version = nw.Version
			}
		}
		return m
	}
	if sf.goWork == FactYes {
		// A workspace composes modules outside this module's require list;
		// absence cannot be asserted from files alone.
		m.undecidable, m.blocker = true, BlockerMissingAlgorithm
	} else if sf.parseFailures > 0 {
		// A go.mod that failed to parse may have declared this module:
		// absence cannot be asserted — fail closed.
		m.undecidable, m.blocker = true, BlockerMissingData
	}
	return m
}

// evaluatePackages classifies every affected package for the
// BUILD_EXCLUDED fact pattern under the run's build context. It returns
// (excluded, included, undecidable counts, buildTagGated tri-state,
// dominant blocker). "Excluded" requires POSITIVE evidence only — a
// package the advisory's own GOOS/GOARCH restriction removes, or an
// in-tree package whose files all fail the build constraints. Module
// absence is NOT exclusion evidence: an absent advisory sibling (a
// different version track) says nothing about the affected component,
// and even the absent module could still enter a build the file scan
// cannot see — both are undecidable.
//
// Per package, the decisive ladder is:
//  1. the advisory's own GOOS/GOARCH import restriction excludes it
//     under the run context          -> excluded (deterministic);
//  2. in-tree source (first-party, local replace or vendor/) exists
//     -> evaluate its files under the build context;
//  3. otherwise -> undecidable: stdlib (release toolchain needed) =
//     missing_data; absent module or a package dir whose constraints
//     the context cannot resolve = missing_data (incomplete variant
//     coverage); module presence the graph cannot decide (go.work,
//     unreadable go.mod) keeps its own blocker; external non-vendored
//     module source = missing_algorithm (needs the import closure).
func evaluatePackages(entries []domain.AffectedModule, sf *snapshotFacts,
	env predictionEnvelope, envPresent bool, note func(string, ...any)) (excluded, included, undecidable int, gated string, blocker string) {
	gated = FactNo
	gatedSeen := false
	ctxOK := envPresent && env.GOOS != "" && env.GOARCH != ""
	undec := func(b string, format string, args ...any) {
		undecidable++
		note(format, args...)
		if blocker == "" {
			blocker = b
		}
	}
	for _, e := range entries {
		if len(e.AffectedPackages) == 0 {
			// The advisory declares no packages for this entry: there is
			// no package-level fact to evaluate at all (scope gap, not
			// missing data).
			note("advisory entry %s declares no affected packages", orUnknown(e.Module))
			continue
		}
		for _, p := range e.AffectedPackages {
			if p.Path == "" {
				continue
			}
			if ctxOK && advisoryExcluded(p, env.GOOS, env.GOARCH) {
				excluded++
				continue
			}
			if isStdlib(e.Module) {
				// Standard-library sources ship with the release toolchain,
				// never inside the product snapshot.
				undec(BlockerMissingData,
					"vulnerable package %s is stdlib: source lives in the release toolchain, not the snapshot", p.Path)
				continue
			}
			mod := sf.resolveModule(e.Module)
			switch {
			case mod.found && (mod.vendored || mod.firstParty):
				dir := sf.locatePackageDir(e.Module, p.Path)
				if dir == "" {
					// Declared in the graph but no source ships inside
					// the snapshot for this package (e.g. a module
					// vendored without that package).
					undec(BlockerMissingData,
						"vulnerable package %s has no source inside the snapshot (module %s present)", p.Path, e.Module)
					continue
				}
				st, g := evalPackageDir(dir, env, ctxOK, note)
				if g {
					gatedSeen = true
				}
				switch st {
				case FactYes:
					excluded++
				case FactNo:
					included++
				default:
					undecidable++
					if blocker == "" {
						blocker = BlockerMissingData
					}
				}
			case !mod.found && !mod.undecidable:
				// Module deterministically outside the graph. Absence is
				// the component-absent fact, NOT build exclusion: the
				// package could still enter a build the file scan cannot
				// see, and a different version track says nothing about
				// the affected one.
				undec(BlockerMissingData,
					"vulnerable package %s module %s absent from module graph — exclusion not assertable", p.Path, e.Module)
			default:
				// Undecidable module presence, or an external module whose
				// sources never enter the snapshot.
				if mod.undecidable {
					undec(orDefault(mod.blocker, BlockerMissingData),
						"vulnerable package %s presence undecidable: %s", p.Path, mod.blocker)
				} else {
					undec(BlockerMissingAlgorithm,
						"vulnerable package %s source not inside snapshot (module %s not vendored)", p.Path, e.Module)
				}
			}
		}
	}
	if gatedSeen {
		gated = FactYes
	}
	if !ctxOK && excluded == 0 && included == 0 && blocker == "" {
		blocker = BlockerMissingData
	}
	return excluded, included, undecidable, gated, blocker
}

// locatePackageDir maps an advisory import path to a directory inside the
// snapshot: first-party packages resolve under their module root (or the
// local replace dir), vendored packages under vendor/. External,
// non-vendored packages are never inside a source snapshot — only their
// import closure (not available offline) would prove presence.
func (sf *snapshotFacts) locatePackageDir(modulePath, pkgPath string) string {
	if sf == nil || !sf.scanned || pkgPath == "" {
		return ""
	}
	// Vendored code ships verbatim under vendor/<pkg>.
	if _, ok := sf.vendorMods[modulePath]; ok {
		cand := filepath.Join(sf.root, "vendor", filepath.FromSlash(pkgPath))
		if isDir(cand) {
			return cand
		}
		return ""
	}
	// First-party package under the root module.
	if sf.rootModule != "" && strings.HasPrefix(pkgPath, sf.rootModule+"/") {
		rel := strings.TrimPrefix(pkgPath, sf.rootModule+"/")
		cand := filepath.Join(sf.root, filepath.FromSlash(rel))
		if isDir(cand) {
			return cand
		}
	}
	// Module replaced by an in-tree directory: <replaceDir>/<rest>.
	for _, g := range sf.gomods {
		if nw, ok := g.replace[modulePath]; ok && isLocalPath(nw.Path) && modulePath != "" &&
			strings.HasPrefix(pkgPath, modulePath+"/") {
			rel := strings.TrimPrefix(pkgPath, modulePath+"/")
			cand := filepath.Join(g.dir, filepath.FromSlash(nw.Path), filepath.FromSlash(rel))
			if isDir(cand) {
				return cand
			}
		}
		// Nested module with its own go.mod inside the root tree.
		if g.module != "" && g.dir != sf.root && strings.HasPrefix(pkgPath, g.module+"/") {
			rel := strings.TrimPrefix(pkgPath, g.module+"/")
			cand := filepath.Join(g.dir, filepath.FromSlash(rel))
			if isDir(cand) {
				return cand
			}
		}
	}
	return ""
}

// evalPackageDir evaluates every non-test .go file in dir under the run's
// build context: a package is build-excluded only when ALL files are
// excluded. Filename suffixes, //go:build / +build constraints and
// cgo-disabled "import \"C\"" files are evaluated via go/build; a release
// go version supplies go1.* release tags when known.
func evalPackageDir(dir string, env predictionEnvelope, ctxOK bool, note func(string, ...any)) (string, bool) {
	if !ctxOK {
		return FactUnknown, false
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		note("package dir unreadable %s: %v", dir, err)
		return FactUnknown, false
	}
	bctx := build.Context{
		GOOS:        env.GOOS,
		GOARCH:      env.GOARCH,
		Compiler:    "gc",
		CgoEnabled:  env.CGOEnabled,
		BuildTags:   env.BuildTags,
		ReleaseTags: releaseTags(env.ReleaseGoVersion),
	}
	hasFiles, allExcluded, anyUndecidable, anyTag := false, true, false, false
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		hasFiles = true
		verdict, tagged, err := fileIncluded(bctx, dir, name)
		if err != nil {
			note("build-constraint eval failed for %s/%s: %v", dir, name, err)
			return FactUnknown, anyTag
		}
		if tagged {
			anyTag = true
		}
		switch verdict {
		case FactYes:
			allExcluded = false
		case FactUnknown:
			anyUndecidable = true
		}
		// No early exit: every file is scanned so build_tag_gated reports
		// presence of constraints anywhere in the package, not just up to
		// the first included file.
	}
	if !hasFiles {
		// A directory with no buildable Go source contributes no shipped
		// vulnerable code — treat as excluded (vacuous truth), never yes.
		return FactYes, anyTag
	}
	if allExcluded {
		if anyUndecidable {
			return FactUnknown, anyTag
		}
		return FactYes, anyTag
	}
	return FactNo, anyTag
}

// fileIncluded reports whether one .go file is selected (FactYes),
// excluded (FactNo) or undecidable (FactUnknown) under the build context,
// and whether it carries any build constraint at all (build_tag_gated).
// "import \"C\"" files count as excluded when CGO is disabled, matching
// go/build's cgo filter. A //go:build expression that mentions a go1.*
// release tag is undecidable when the release toolchain is unknown — an
// optimistic guess would invent an exclusion.
func fileIncluded(bctx build.Context, dir, name string) (verdict string, tagged bool, err error) {
	match, err := bctx.MatchFile(dir, name)
	if err != nil {
		return FactUnknown, false, err
	}
	// Tag presence and go1.* usage come from the file head so
	// build_tag_gated is a fact, not an outcome.
	head, rerr := readHead(filepath.Join(dir, name), 2048)
	if rerr != nil {
		return FactUnknown, false, fmt.Errorf("read %s: %w", name, rerr)
	}
	tagged = bytes.Contains(head, []byte("//go:build")) || bytes.Contains(head, []byte("+build"))
	if tagged && bytes.Contains(head, []byte("go1.")) && len(bctx.ReleaseTags) == 0 {
		return FactUnknown, tagged, nil
	}
	if !match {
		return FactNo, tagged, nil
	}
	if !bctx.CgoEnabled {
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if perr != nil {
			return FactUnknown, tagged, fmt.Errorf("parse %s: %w", name, perr)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"C"` {
				return FactNo, tagged, nil
			}
		}
	}
	return FactYes, tagged, nil
}

// advisoryExcluded reports whether the advisory's own GOOS/GOARCH import
// restriction already excludes this package under the run context.
func advisoryExcluded(p domain.AffectedPackage, goos, goarch string) bool {
	if len(p.GOOS) > 0 && !containsStr(p.GOOS, goos) {
		return true
	}
	if len(p.GOARCH) > 0 && !containsStr(p.GOARCH, goarch) {
		return true
	}
	return false
}

// releaseTags builds the go1.* release tags go/build expects for a
// toolchain version like "go1.19.5". Unknown versions yield no release
// tags (constraints mentioning go1.N then evaluate conservatively).
func releaseTags(release string) []string {
	v := strings.TrimPrefix(strings.TrimSpace(release), "go")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return nil
	}
	minor := parts[1]
	// Go release tags run go1.1 .. go1.<minor>; derive the bound from the
	// version so 1.19.5 yields go1.1..go1.19 without a hardcoded table.
	var tags []string
	for i := 1; i <= 99; i++ {
		tag := fmt.Sprintf("go1.%d", i)
		if fmt.Sprintf("%d", i) == minor {
			tags = append(tags, tag)
			break
		}
		tags = append(tags, tag)
	}
	return tags
}

// feasNormalizeVersion mirrors internal/affected.normalizeVersion: OSV/Go
// spellings → canonical semver; "", "0" and "in-tree" are unversioned.
func feasNormalizeVersion(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "", "0", "in-tree":
		return ""
	}
	s = strings.TrimPrefix(s, "go")
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return ""
	}
	return semver.Canonical(s)
}

// feasAffected mirrors internal/affected.inRange over the whole range set:
// [introduced, fixed) or [introduced, last_affected]; an empty introduced
// matches all versions; an absent upper bound means affected without end.
func feasAffected(v string, ranges []domain.VersionRange) bool {
	for _, r := range ranges {
		if r.Introduced != "" {
			lo := feasNormalizeVersion(r.Introduced)
			if lo != "" && semver.Compare(v, lo) < 0 {
				continue
			}
		}
		if r.Fixed != "" {
			hi := feasNormalizeVersion(r.Fixed)
			if hi == "" || semver.Compare(v, hi) >= 0 {
				continue
			}
			return true
		}
		if r.LastAffected != "" {
			hi := feasNormalizeVersion(r.LastAffected)
			if hi == "" {
				continue
			}
			if semver.Compare(v, hi) <= 0 {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// advisoryEntries returns the advisory's per-module affected entries in
// document order (the same narrowing the resolver applies).
func advisoryEntries(v *domain.Vulnerability) []domain.AffectedModule {
	if v == nil {
		return nil
	}
	if len(v.AffectedModules) > 0 {
		return v.AffectedModules
	}
	if v.Module == "" {
		return nil
	}
	pkgs := v.AffectedPackages
	if len(pkgs) == 0 && v.Package != "" {
		pkgs = []domain.AffectedPackage{{Path: v.Package}}
	}
	return []domain.AffectedModule{{
		Module:           v.Module,
		AffectedVersions: v.AffectedVersions,
		FixedVersions:    v.FixedVersions,
		AffectedPackages: pkgs,
	}}
}

func vulnModified(v *domain.Vulnerability) string {
	if v == nil {
		return ""
	}
	return v.Modified
}

func isStdlib(modulePath string) bool {
	return modulePath == "stdlib" || modulePath == "toolchain"
}

func isLocalPath(p string) bool {
	return p == "." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") ||
		strings.HasPrefix(p, "/") || strings.HasPrefix(p, `.\`) || strings.HasPrefix(p, `..\`)
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(f, buf)
	if err != nil && m == 0 {
		return nil, err
	}
	return buf[:m], nil
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// aggregateAny reduces per-entry tri-states: yes if any entry is yes,
// else unknown if any is unknown, else no.
func aggregateAny(states []string) string {
	anyUnknown := false
	for _, s := range states {
		switch s {
		case FactYes:
			return FactYes
		case FactUnknown:
			anyUnknown = true
		}
	}
	if anyUnknown {
		return FactUnknown
	}
	return FactNo
}

// snapshotKey renders the task's snapshot identity repos_dir-relative
// (<owner>/<repo>/<commit>) — a stable, portable identity, never an
// operator-local absolute path.
func snapshotKey(t TaskRecord) string {
	owner, repo := ownerRepo(t.RepoURL)
	if owner == "" || t.CommitSHA == "" {
		return FactUnknown
	}
	return owner + "/" + repo + "/" + t.CommitSHA
}

// ownerRepo extracts owner/repo from a repository URL or path-like
// string: https://github.com/owner/repo[.git], git@github.com:owner/repo,
// or bare owner/repo (mirrors internal/eval/vexbench.parseRepoURL).
func ownerRepo(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if i := strings.Index(s, "@"); i >= 0 {
		if j := strings.Index(s[i:], ":"); j >= 0 {
			s = s[i+j+1:]
		}
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

func packageList(e domain.AffectedModule) string {
	var ps []string
	for _, p := range e.AffectedPackages {
		if p.Path != "" {
			ps = append(ps, p.Path)
		}
	}
	if len(ps) == 0 {
		return "none"
	}
	return strings.Join(ps, "+")
}

// rangeList renders one entry's affected ranges in OSV-interval form.
func rangeList(rs []domain.VersionRange) string {
	var parts []string
	for _, r := range rs {
		switch {
		case r.Fixed != "":
			parts = append(parts, "["+or0(r.Introduced)+","+r.Fixed+")")
		case r.LastAffected != "":
			parts = append(parts, "["+or0(r.Introduced)+","+r.LastAffected+"]")
		default:
			parts = append(parts, "["+or0(r.Introduced)+",)")
		}
	}
	return strings.Join(parts, " || ")
}

func or0(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return FactUnknown
	}
	return s
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func boolFact(b bool) string {
	if b {
		return FactYes
	}
	return FactNo
}
