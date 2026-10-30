package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CaseID string
type EvidenceID string
type ConditionID string
type ClaimID string
type ReviewID string

type ClaimResult string

const (
	ClaimTrue    ClaimResult = "TRUE"
	ClaimFalse   ClaimResult = "FALSE"
	ClaimUnknown ClaimResult = "UNKNOWN"
)

type Verdict string

const (
	VerdictNotAffected        Verdict = "NOT_AFFECTED"
	VerdictExploitable        Verdict = "EXPLOITABLE"
	VerdictNoExploitPathFound Verdict = "NO_EXPLOIT_PATH_FOUND"
	VerdictInconclusive       Verdict = "INCONCLUSIVE"
)

type WorkflowState string

const (
	StateCreated              WorkflowState = "CREATED"
	StateSnapshotProduct      WorkflowState = "SNAPSHOT_PRODUCT"
	StateResolveVulnerability WorkflowState = "RESOLVE_VULNERABILITY"
	// Request-level discovery and composition states. They bracket record
	// assessment and never replace the record evaluator: discovery nominates
	// candidates, assessment runs each record's own pipeline, and composition
	// projects the independently earned results into one requested answer.
	StateDiscoverRecords         WorkflowState = "DISCOVER_RECORDS"
	StateAssessRelatedRecords    WorkflowState = "ASSESS_RELATED_RECORDS"
	StateComposeRequestedFinding WorkflowState = "COMPOSE_REQUESTED_FINDING"
	StateCheckAffected           WorkflowState = "CHECK_AFFECTED"
	StateResolveRootCause        WorkflowState = "RESOLVE_ROOT_CAUSE"
	StateBuildExploitModel       WorkflowState = "BUILD_EXPLOIT_MODEL"
	StateCollectEvidence         WorkflowState = "COLLECT_EVIDENCE"
	StateEvaluateConditions      WorkflowState = "EVALUATE_CONDITIONS"
	StateGapAnalysis             WorkflowState = "GAP_ANALYSIS"
	StateNegativeCheck           WorkflowState = "NEGATIVE_CHECK"
	StateReview                  WorkflowState = "REVIEW"
	StateRepairAnalysis          WorkflowState = "REPAIR_ANALYSIS"
	StateEvaluateVerdict         WorkflowState = "EVALUATE_VERDICT"
	StateBuildReport             WorkflowState = "BUILD_REPORT"
	StateCompleted               WorkflowState = "COMPLETED"
	StateInconclusive            WorkflowState = "INCONCLUSIVE"
	StateFailed                  WorkflowState = "FAILED"
)

type Vulnerability struct {
	ID      string         `json:"id"`
	Scope   *AdvisoryScope `json:"scope,omitempty"`
	Aliases []string       `json:"aliases,omitempty"`
	// Related carries the record's direct related ids verbatim. It is a
	// discovery relationship only: the OSV schema permits a related entry to
	// name a similar but completely different vulnerability, so relatedness
	// establishes neither identity nor fact inheritance. Attribution needs its
	// own admitted basis, and exploitability needs the related record's own
	// independently earned proof.
	Related          []string          `json:"related,omitempty"`
	Module           string            `json:"module,omitempty"`
	Package          string            `json:"package,omitempty"`
	AffectedVersions []VersionRange    `json:"affected_versions,omitempty"`
	FixedVersions    []string          `json:"fixed_versions,omitempty"`
	AffectedPackages []AffectedPackage `json:"affected_packages,omitempty"`
	AffectedSymbols  []SymbolRef       `json:"affected_symbols,omitempty"`
	// AffectedModules carries per-affected-entry data for advisories that
	// span several modules (e.g. stdlib + golang.org/x/sys mirrors of the
	// same fix). Each entry holds the module path with its own version
	// ranges, packages and symbols; the resolver picks the entry matching
	// the product's dependency graph and narrows the vulnerability to it.
	AffectedModules []AffectedModule `json:"affected_modules,omitempty"`
	Summary         string           `json:"summary,omitempty"`
	Description     string           `json:"description,omitempty"`
	BaseSeverity    string           `json:"base_severity,omitempty"`
	BaseScore       float64          `json:"base_score,omitempty"`
	// SeveritySource / ScoreSource record where BaseSeverity and BaseScore
	// came from ("OSV", "GHSA", "NVD", "Scanner input", ...). Empty means
	// the origin is unknown and presentation must not claim one.
	SeveritySource string            `json:"severity_source,omitempty"`
	ScoreSource    string            `json:"score_source,omitempty"`
	CWE            []string          `json:"cwe,omitempty"`
	Modified       string            `json:"modified,omitempty"`
	References     []Reference       `json:"references,omitempty"`
	Provenance     map[string]string `json:"provenance,omitempty"`
}

type VersionRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type AffectedPackage struct {
	Path    string   `json:"path"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type SymbolRef struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
}

type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

// GoVersionSource identifies where ProductSnapshot.ReleaseGoVersion came
// from. An empty value means no evidence was found: the release toolchain
// is UNKNOWN and release-scoped applicability must stay unresolved.
type GoVersionSource string

const (
	GoVersionSourceGoMod       GoVersionSource = "go.mod"       // toolchain directive in go.mod
	GoVersionSourceToolchain   GoVersionSource = "toolchain"    // explicit toolchain directive
	GoVersionSourceDockerfile  GoVersionSource = "dockerfile"   // FROM golang:X build stage
	GoVersionSourceCI          GoVersionSource = "ci"           // CI setup-go version
	GoVersionSourceVersionFile GoVersionSource = "version-file" // .go-version/mise/asdf/build script pin
	GoVersionSourceBinary      GoVersionSource = "binary"       // go version -m on a release binary
	GoVersionSourceExplicit    GoVersionSource = "explicit"     // operator flag/ticket metadata
)

type ProductSnapshot struct {
	Repository       string   `json:"repository"`
	Commit           string   `json:"commit"`
	GoVersion        string   `json:"go_version"`
	GoModDirective   string   `json:"go_mod_directive,omitempty"`
	ReleaseGoVersion string   `json:"release_go_version,omitempty"`
	BinaryPath       string   `json:"binary_path,omitempty"`
	GOOS             string   `json:"goos"`
	GOARCH           string   `json:"goarch"`
	BuildTags        []string `json:"build_tags,omitempty"`
	CGOEnabled       bool     `json:"cgo_enabled"`
	// Target is the typed provenance of the GOOS/GOARCH/BuildTags/
	// CGOEnabled facts above: artifact build-info bound to the artifact
	// and build-info digests, release-metadata target facts, an explicit
	// operator declaration, or the analyzer host default. Only a
	// non-host target can ground a platform-scoped affected-chain
	// conclusion, and a product-wide conclusion additionally requires an
	// admitted supported-targets assumption.
	Target     *ProductTarget `json:"target,omitempty"`
	VendorMode bool           `json:"vendor_mode"`
	GoWorkFile string         `json:"go_work_file,omitempty"`
	// GoFlags records the effective GOFLAGS the snapshot resolved for
	// package loading, so every build-dependent probe shares one value.
	GoFlags           string             `json:"go_flags,omitempty"`
	ReplaceDirectives []ReplaceDirective `json:"replace_directives,omitempty"`
	TrustedPeer       bool               `json:"trusted_peer,omitempty"`
	DeployManifests   []string           `json:"deploy_manifests,omitempty"`
	DeployArchive     string             `json:"deploy_archive,omitempty"`
	PerimeterOverride string             `json:"perimeter_override,omitempty"`
	// MinimumGoVersion mirrors the go.mod `go` directive: the minimum
	// toolchain the module declares. It is NOT the release toolchain.
	MinimumGoVersion string `json:"minimum_go_version,omitempty"`
	// GoVersionSource identifies where ReleaseGoVersion came from; empty
	// means the release toolchain is UNKNOWN.
	GoVersionSource GoVersionSource `json:"go_version_source,omitempty"`
	// ExternalCommitSHA is the snapshot identity supplied by an external
	// controller (benchmark); when set, no local git history is consulted.
	ExternalCommitSHA string `json:"external_commit_sha,omitempty"`
	// ContentHash is the canonical snapshot-tree hash acquired for native and
	// external source snapshots before index binding or analysis.
	ContentHash string `json:"content_hash,omitempty"`
	// Shape is the proven product-shape record with its module ownership,
	// source census and input fingerprint. Nil means no shape was proven
	// (the proof never ran or the case is binary-only).
	Shape *ProductShape `json:"shape,omitempty"`
	// ReleaseEvidence is the classified, resolved record of every observed
	// release-toolchain declaration. ReleaseGoVersion above is only ever
	// populated from an AUTHORITATIVE selection inside this summary.
	ReleaseEvidence *ReleaseEvidenceSummary `json:"release_evidence,omitempty"`
	// ReleaseModules is the release binary's dependency module graph when
	// an authoritative artifact was analyzed; it is distinct from the
	// source snapshot's module resolution.
	ReleaseModules []ReleaseModule `json:"release_modules,omitempty"`
	// ReleaseEvidenceRequired records that an authoritative release-evidence
	// channel was explicitly requested for this snapshot; its failure must
	// surface as NOT_RUN, never as a silent fall back to supporting sources.
	ReleaseEvidenceRequired bool `json:"release_evidence_required,omitempty"`
}

type ReplaceDirective struct {
	Old string `json:"old"`
	New string `json:"new"`
}

type AffectedResult struct {
	Scope           *AdvisoryScope `json:"scope,omitempty"`
	ModulePresent   ClaimResult    `json:"module_present"`
	ResolvedVersion string         `json:"resolved_version,omitempty"`
	VersionAffected ClaimResult    `json:"version_affected"`
	PackagePresent  ClaimResult    `json:"package_present"`
	BuildRelevant   ClaimResult    `json:"build_relevant"`
	// VulnerableImplementationPresent is the affected chain's
	// implementation-presence dimension: whether the advisory's
	// vulnerable implementation (file/function/marker under an explicit
	// build expression) is part of the recorded product build.
	// FALSE means an admitted implementation-locus proposal was
	// deterministically verified absent under an authoritative or
	// declared product target scope; TRUE means a selected proposed or
	// alternate implementation carries the marker. It is independent of
	// BuildRelevant, which keeps its advisory/package platform
	// restriction meaning. Default UNKNOWN.
	VulnerableImplementationPresent ClaimResult `json:"vulnerable_implementation_present"`
	// ImplementationLocus names the verified implementation locus
	// (package, function, file, marker) the axis closed on. It is
	// report text derived from deterministic verification records.
	ImplementationLocus string `json:"implementation_locus,omitempty"`
	// ImplementationTarget is the build target the verification ran
	// under, e.g. "linux/amd64".
	ImplementationTarget string `json:"implementation_target,omitempty"`
	// ImplementationTargetScope is the scope the target facts cover:
	// "product" only when an admitted product-scope supported-targets
	// assumption covered the recorded target; "artifact", "release" or
	// "operator" for a narrower target that may not close a
	// product-wide conclusion.
	ImplementationTargetScope string `json:"implementation_target_scope,omitempty"`
	// ImplementationTargetSource is the ProductTarget source the target
	// facts came from (artifact-build-info|release-metadata|
	// operator-declared|host-default).
	ImplementationTargetSource string `json:"implementation_target_source,omitempty"`
	// ImplementationModules names the advisory module(s) the
	// implementation axis covered, so downstream branch facts bind the
	// predicate to the right module subject.
	ImplementationModules []string `json:"implementation_modules,omitempty"`
	// TestOnlyScope records the affected subjects that were found in the
	// recorded build streams but only through test roots (ForTest variants
	// and synthetic .test drivers) — the dependency is linked into the
	// product's tests, not into any product binary. It is the typed basis
	// for a PackagePresent=FALSE that must be reported as a test-scope
	// exclusion rather than as an absence from the recorded closure.
	// Empty means no subject was observed in test scope.
	TestOnlyScope    []string     `json:"test_only_scope,omitempty"`
	EvidenceIDs      []EvidenceID `json:"evidence_ids,omitempty"`
	Limitations      []string     `json:"limitations,omitempty"`
	UpgradeDropIn    bool         `json:"upgrade_drop_in,omitempty"`
	UpgradeMajorBump bool         `json:"upgrade_major_bump,omitempty"`
	// SelectedModule is the affected-entry module the product was
	// resolved against (multi-module advisories carry alternatives —
	// e.g. stdlib + golang.org/x/sys — and only the entry matching the
	// product's dependency graph is authoritative).
	SelectedModule string `json:"selected_module,omitempty"`
	// SelectedModules names every affected-entry module whose package set
	// resolved as imported (or every version-affected module when no
	// package probe ran). Two entries can both be linked into the
	// product — downstream narrowing must cover all of them, not just
	// SelectedModule.
	SelectedModules []string `json:"selected_modules,omitempty"`
	// CheckedModules names every advisory module entry probed against the
	// product's module graph — ModulePresent=FALSE means none of these
	// resolved to a product dependency.
	CheckedModules []string `json:"checked_modules,omitempty"`
	// CheckedPackages names the affected package paths probed against the
	// product's transitive import closure (go list -deps -test ./...,
	// including build-constraint-excluded files). PackagePresent=FALSE
	// means every listed path is absent — the code is not linked into
	// the product — not "some package was missing".
	CheckedPackages []string `json:"checked_packages,omitempty"`
	// PendingModules names linked modules whose version could not be
	// resolved (module present in go list -m, version undecidable). Their
	// code is in scope for analysis, but VersionAffected/ResolvedVersion
	// never describe them — a version fact must not be consumed as if it
	// proved a pending module's range.
	PendingModules []string `json:"pending_modules,omitempty"`
	// UnresolvedModules names every advisory-entry module whose version
	// could not be resolved, regardless of package linkage — the
	// population PendingModules draws from once a linked package is
	// found. A pending module whose package never linked still carries
	// an undecidable version verdict; downstream consumers must not read
	// it as fixed merely because it is absent from SelectedModules.
	UnresolvedModules []string `json:"unresolved_modules,omitempty"`
	// VersionAffectedModules names every advisory-entry module whose
	// version fell inside that entry's affected ranges. Membership is a
	// version fact, independent of the package probe: an entry stays
	// here even when its package is absent from the build closure
	// (package absence is a reachability result, not a version result).
	// SelectedModules narrows to the linked subset after the probe; this
	// list keeps the version-side membership intact.
	VersionAffectedModules []string `json:"version_affected_modules,omitempty"`
	// VersionGraphSource names which module graph grounded module-version
	// applicability: "release-artifact" when the authoritative release
	// module graph was used, "source-snapshot" for the checkout's own
	// go list/vendor resolution, "unavailable" when a required
	// release-evidence channel failed and the source graph could not
	// substitute. Empty on snapshots that never carried release evidence.
	VersionGraphSource string `json:"version_graph_source,omitempty"`
	// VersionGraphTrust is the release-evidence trust class of
	// VersionGraphSource ("AUTHORITATIVE"); empty for source-snapshot
	// resolution, which is not release evidence.
	VersionGraphTrust string `json:"version_graph_trust,omitempty"`
	// TicketCheck records the ticket-build identity comparison when a
	// ticket input was supplied (see TicketClaims). A
	// package-version mismatch sets VersionAxisBlocked: the version axis
	// then refused to close — VersionAffected stays UNKNOWN and no
	// "outside the affected range" negative may be produced for that
	// subject. The module/package-absence routes are unaffected.
	TicketCheck        *TicketCheck `json:"ticket_check,omitempty"`
	VersionAxisBlocked bool         `json:"version_axis_blocked,omitempty"`
	// ReleaseEvidenceStatus mirrors the snapshot's release-evidence
	// outcome (RESOLVED/CONFLICTED/NOT_RUN/…) when it governed or blocked
	// the version axis; ReleaseEvidenceReason is its named reason code.
	ReleaseEvidenceStatus string `json:"release_evidence_status,omitempty"`
	ReleaseEvidenceReason string `json:"release_evidence_reason,omitempty"`
	// AssumptionIDs names the admitted declared-assumptions/1 member ids
	// the applicability chain relied on (e.g. a product-wide supported
	// target scope). They are policy references, never evidence ids —
	// the assumptions live on the case's DeclaredAssumptions input.
	AssumptionIDs []string `json:"assumption_ids,omitempty"`
	// AnalysisGaps carries the typed causes the applicability resolver could not
	// discharge (unresolved graph, parser/resolver failure, incomplete
	// inventory, unsupported negative scope). They let the terminal outcome
	// fail on a structured cause instead of abstaining on prose.
	AnalysisGaps []AnalysisGap `json:"analysis_gaps,omitempty"`
	// EffectiveSources records, per advisory affected[] entry, the identity of
	// the source the recorded build actually selects: declared coordinate,
	// effective coordinate or local-replacement/workspace identity, the
	// applied replace/workspace provenance, and the stable source root. A
	// failure entry is the typed reason no source was established; it never
	// authorises reading the declared module's published bytes instead.
	EffectiveSources []EffectiveSourceSelection `json:"effective_sources,omitempty"`
}

// AffectedModule is one OSV affected[] entry: a module path with its own
// version ranges, packages and symbols. Advisories may list alternatives
// (stdlib + vendored module) — each is evaluated independently.
type AffectedModule struct {
	Module           string            `json:"module"`
	AffectedVersions []VersionRange    `json:"affected_versions,omitempty"`
	FixedVersions    []string          `json:"fixed_versions,omitempty"`
	AffectedPackages []AffectedPackage `json:"affected_packages,omitempty"`
	AffectedSymbols  []SymbolRef       `json:"affected_symbols,omitempty"`
	// Unnamed marks an advisory entry whose package name is empty: the
	// document declares affected subjects without a module owner. Module
	// stays empty and consumers must never classify such an entry as
	// stdlib or as a named dependency; it may only keep applicability
	// unresolved when one of its subjects is linked into the product.
	// Never projected into selected/pending/unresolved module name lists.
	Unnamed bool `json:"unnamed,omitempty"`
}

type RootCauseStatus string

const (
	RootCauseResolved  RootCauseStatus = "RESOLVED"
	RootCauseAmbiguous RootCauseStatus = "AMBIGUOUS"
	RootCauseNotFound  RootCauseStatus = "NOT_FOUND"
)

type RootCauseRole string

const (
	RootCauseEntrypoint  RootCauseRole = "ENTRYPOINT"
	RootCausePropagation RootCauseRole = "PROPAGATION"
	RootCauseSink        RootCauseRole = "SINK"
)

// RootCauseOrigin records where a candidate subject came from. Diagnostics
// must distinguish an advisory-declared subject from a fix-derived candidate:
// they carry different proof obligations, and calling both "declared" (or
// both "unresolved in source") misstates what was verified.
type RootCauseOrigin string

const (
	// RootCauseOriginAdvisory marks a subject the record itself declares —
	// an affected symbol or an admitted prose vulnerable-operation binding.
	RootCauseOriginAdvisory RootCauseOrigin = "ADVISORY_DECLARED"
	// RootCauseOriginFixDerived marks a candidate derived from the fix diff.
	RootCauseOriginFixDerived RootCauseOrigin = "FIX_DERIVED"
	// RootCauseOriginLLMProposed marks an LLM-proposed candidate.
	RootCauseOriginLLMProposed RootCauseOrigin = "LLM_PROPOSED"
	// RootCauseOriginManual marks a root cause the operator supplied
	// explicitly (--root-cause, a manual model, an eval corpus entry). It is
	// an operator input that names its own subject; it carries no version
	// derivation, so the selected-source binding rule does not re-decide it.
	RootCauseOriginManual RootCauseOrigin = "MANUAL"
)

type RootCause struct {
	Package     string        `json:"package"`
	Symbol      string        `json:"symbol"`
	Role        RootCauseRole `json:"role"`
	Mechanism   string        `json:"mechanism"`
	EvidenceIDs []EvidenceID  `json:"evidence_ids,omitempty"`
	// Origin is the typed candidate provenance. An empty value means the
	// producer did not record one (legacy/manual models); consumers must
	// say so rather than assume an origin.
	Origin RootCauseOrigin `json:"origin,omitempty"`
	// Absent marks a candidate whose package is proven absent from the
	// product's build graph (`go list -deps`): the symbol is unresolved in
	// source because the defect code is not linked in — resolved by
	// absence, not a verification failure. It is kept in RootCauses so
	// reachability evaluation can falsify mandatory conditions on it.
	//
	// It may only be recorded for a candidate whose identity as a subject of
	// the selected version is established (see AbsenceIdentity): absence is
	// evidence about real subjects only, and a candidate that does not exist
	// in the selected version's own source is unmapped, not absent.
	Absent bool `json:"absent,omitempty"`
	// Binding records how a candidate derived from fix material resolves
	// into the selected version's own source. It is nil for record-declared
	// subjects, whose identity comes from the advisory entry itself.
	Binding *CandidateBinding `json:"binding,omitempty"`
}

type RootCauseModel struct {
	Status       RootCauseStatus `json:"status"`
	RootCauses   []RootCause     `json:"root_causes"`
	Alternatives []RootCause     `json:"alternatives,omitempty"`
	// Unverified lists in-scope candidates (advisory-declared affected
	// packages) that failed source verification — the dependency source
	// does not contain the symbol. Unlike out-of-scope Alternatives these
	// narrow the modeled exploit space silently if dropped, so they are
	// surfaced to block positive verdicts on an incomplete model.
	Unverified  []RootCause `json:"unverified,omitempty"`
	Limitations []string    `json:"limitations,omitempty"`
	FixDiff     string      `json:"fix_diff,omitempty"`
	// OperationDeclarations records every vulnerable-operation declaration the
	// record's own prose makes, with its resolution outcome. Declarations that
	// did not source-bind stay here: a positive model must not hide an
	// operation the record declared but this build could not resolve.
	OperationDeclarations []OperationDeclaration `json:"operation_declarations,omitempty"`
	// OperationBindings carries the admitted own-record operation bindings this
	// model was resolved from. Every consumer re-admits them against the record
	// bytes and affected scope before relying on them.
	OperationBindings []OperationBinding `json:"operation_bindings,omitempty"`
	// AnalysisGaps carries the typed causes that kept the root-cause model
	// unresolved (ambiguity, unsupported binding, missing proof artifact).
	AnalysisGaps []AnalysisGap `json:"analysis_gaps,omitempty"`
	// FixArtifacts is the per-locator account of every fix reference the record
	// declared: complete captured bytes with their digest, or a typed outcome
	// saying why no bytes (or no applicability) were established. Every declared
	// locator appears exactly once, so a reader can tell an artifact the
	// provider does not hold from one that is present but describes another
	// release line.
	FixArtifacts []FixArtifact `json:"fix_artifacts,omitempty"`
	// FixProof is the persisted content-proof contract this model was resolved
	// from: the canonical checker output together with the exact captured input
	// bundle it was derived from. It grounds absence only after the pure checker
	// re-derives it at the shared boundary; a saved status, cover or subject set
	// is diagnostic and never authority. A model without one keeps the
	// record/operator/exact-preimage routes.
	FixProof *FixProof `json:"fix_proof,omitempty"`
	// FixBinding is the preserved, withdrawn content-derived fix binding this
	// model was resolved from. It is historical evidence only: the layer that
	// could re-derive it is gone, so it establishes no identity, absence or
	// completeness, and the shared absence admission refuses the subjects it
	// named instead of letting the payload decay into a weaker route. The stored
	// bytes are kept so a re-save never rewrites history.
	FixBinding *WithdrawnFixBinding `json:"fix_binding,omitempty"`
}

type ConditionKind string

const (
	ConditionSymbolReachable ConditionKind = "SYMBOL_REACHABLE"
	ConditionAttackerControl ConditionKind = "ATTACKER_CONTROL"
	ConditionInputConstraint ConditionKind = "INPUT_CONSTRAINT"
	ConditionValidation      ConditionKind = "VALIDATION"
	ConditionConfiguration   ConditionKind = "CONFIGURATION"
	ConditionBuild           ConditionKind = "BUILD_CONDITION"
	ConditionPlatform        ConditionKind = "PLATFORM_CONDITION"
	ConditionAuthn           ConditionKind = "AUTHENTICATION_CONDITION"
	ConditionRuntime         ConditionKind = "RUNTIME_CONDITION"
	ConditionCustom          ConditionKind = "CUSTOM"
	ConditionMissingCall     ConditionKind = "MISSING_CALL"
	// ConditionCheckTrigger is the dedicated mandatory obligation of a
	// DEFECTIVE_CHECK contract: one typed witness must establish the
	// advisory's argument/type predicates and the receiver-field input on
	// the same invocation and receiver.
	ConditionCheckTrigger ConditionKind = "CHECK_TRIGGER"
	// ConditionCheckInput is the receiver-field-bound input obligation of a
	// DEFECTIVE_CHECK contract. It is separate from ordinary provenance:
	// external origin alone never satisfies it.
	ConditionCheckInput ConditionKind = "CHECK_INPUT"
)

type DataOrigin string

const (
	OriginExternalUntrusted     DataOrigin = "EXTERNAL_UNTRUSTED"
	OriginExternalAuthenticated DataOrigin = "EXTERNAL_AUTHENTICATED"
	OriginConfiguration         DataOrigin = "CONFIGURATION"
	OriginDatabase              DataOrigin = "DATABASE"
	OriginInternalService       DataOrigin = "INTERNAL_SERVICE"
	OriginConstant              DataOrigin = "CONSTANT"
	OriginGenerated             DataOrigin = "GENERATED"
	OriginUnknown               DataOrigin = "UNKNOWN"
)

type ProtocolRole string

const (
	ProtocolRoleUnknown   ProtocolRole = ""
	ProtocolRoleServer    ProtocolRole = "server"
	ProtocolRoleClient    ProtocolRole = "client"
	ProtocolRoleSymmetric ProtocolRole = "symmetric"
)

// SafeOrigin reports whether a provenance origin is proven non-external —
// the value is a compile-time constant or a generated value whose inputs
// are all safe. Everything else is either attacker-capable,
// deployment-dependent, or unknown and cannot ground a negative claim.
func SafeOrigin(o DataOrigin) bool {
	return o == OriginConstant || o == OriginGenerated
}

// Condition param keys — declarative hints emitted by exploit patterns and
// consumed by evaluators. Unknown params are ignored, so patterns stay
// declarative: a param never asserts a verdict, it only narrows what to
// check.
const (
	// ParamInputSource declares where the condition's input is expected to
	// come from: "peer" (remote peer of a listener/dialed service), "arg"
	// (a product-code call argument) or "config" (deployment config). Only a
	// pattern template — selected by an authoritative class — or an
	// established input route may declare it; a prose route nomination never
	// fills it.
	ParamInputSource = "input_source"
	// ParamProtocolRole declares the required protocol role: "server",
	// "client" or "symmetric". It is a typed requirement: a producer must
	// establish the role from evidence, and the prose/fix-name role
	// nomination never fills it.
	ParamProtocolRole = "protocol_role"
	// ParamDirection selects the reachability direction: "read" looks for
	// readers of the subject (data exposure), not paths to a sink.
	ParamDirection = "direction"
	// ParamSequence names an API pair ("a->b") the product must invoke for
	// the vulnerable round-trip to exist.
	ParamSequence = "sequence"
	// ParamBound carries a constraint expression (e.g. "length > INT32_MAX")
	// for INPUT_CONSTRAINT conditions; a text annotation until guard
	// semantics land.
	ParamBound = "bound"
	// ParamCheck selects a structural check: "symbol_present" verifies the
	// subject exists in the dependency source; "exposure" resolves the
	// network exposure of the vulnerable surface; "config_flag" /
	// "config_key" resolve a configuration knob's effective value.
	ParamCheck = "check"
	// ParamConfigPackage/ParamConfigSymbol name a code-level configuration
	// knob (e.g. crypto/tls + Config.InsecureSkipVerify) for
	// check=config_flag.
	ParamConfigPackage = "config_package"
	ParamConfigSymbol  = "config_symbol"
	// ParamConfigKey names a repository config-file key for
	// check=config_key.
	ParamConfigKey = "config_key"
	// ParamInsecure is the knob value that enables the vulnerable
	// configuration (default "true").
	ParamInsecure = "insecure_value"
	// ParamScope specifies the required network exposure scope ("public", etc.).
	ParamScope = "scope"
)

const (
	InputPeer   = "peer"
	InputArg    = "arg"
	InputConfig = "config"

	DirectionRead = "read"

	CheckSymbolPresent = "symbol_present"
	CheckExposure      = "exposure"
	CheckConfigFlag    = "config_flag"
	CheckConfigKey     = "config_key"
	// CheckReachable routes a CUSTOM condition to the symbol-reachability
	// machinery (subjects, direction=read, sequence=a->b all apply).
	CheckReachable = "reachable"
	// CheckLocus marks a SYMBOL_REACHABLE condition whose subjects are the
	// advisory's defect locus — the functions where the vulnerable
	// operation lives — rather than the union of affected symbols. Its
	// falsifier is build-graph absence of the locus package(s), verified
	// against the product's `go list -deps` evidence, not call-path or
	// subject-escape arguments: code absent from the build cannot execute
	// through any dispatch.
	CheckLocus = "locus"
	// CheckMissingCall verifies that an advisory-declared security check is
	// omitted on an active execution pipeline.
	CheckMissingCall = "missing_call"
)

// Exposure scope values — deterministic classification of a resolved
// address. Inbound: how broadly a listener binds; outbound: where the
// endpoint's value originates.
const (
	ScopeAllInterfaces   = "all-interfaces"   // :port, 0.0.0.0, [::]
	ScopeLoopback        = "loopback"         // 127.0.0.1, ::1, localhost
	ScopeUnix            = "unix"             // unix socket path / "unix" network
	ScopeHostSpecific    = "host-specific"    // bound to a concrete IP/DNS name
	ScopeStatic          = "static-endpoint"  // outbound literal/const address
	ScopeConfigured      = "configured"       // outbound address from env/config/var
	ScopeClusterInternal = "cluster-internal" // cluster-internal service (ClusterIP, loopback, mesh)
	ScopeUnknown         = "unknown"
)

// ExposureFact is a resolved network-exposure fact: an inbound listener
// bind or an outbound endpoint into the vulnerable module. It is
// evidence, not a verdict — scope describes the fact, the caller decides
// what it means for exploitation.
type ExposureFact struct {
	CallSite
	// Direction: "inbound" (we listen) or "outbound" (we dial/connect).
	Direction string `json:"direction"`
	// Kind: "listener", "dial" or "endpoint-config".
	Kind string `json:"kind"`
	// Target is the callee that creates the exposure ("net.Listen",
	// "amqp091-go.DialTLS").
	Target string `json:"target,omitempty"`
	// Address is the resolved value when statically determinable.
	Address string `json:"address,omitempty"`
	// AddressSource records where Address came from: "literal", "const",
	// "var", "env:NAME", "config:key", "field:…" or "" when unresolved.
	AddressSource string `json:"address_source,omitempty"`
	Scope         string `json:"scope,omitempty"`
	// Owner names the deployment resource that declares the surface
	// (k8s metadata.name, compose service key). Empty = unattributed —
	// perimeter classification counts only owner-matched deploy facts.
	Owner string `json:"owner,omitempty"`
}

// Special argument indices for Condition.ArgIndex and DataFlow.Arg:
const (
	// ArgAll indicates whole-arg provenance covering all call arguments.
	ArgAll = -1
	// ArgReceiver indicates the method receiver expression (sel.X).
	ArgReceiver = -2
)

type Condition struct {
	ID                ConditionID       `json:"id"`
	Kind              ConditionKind     `json:"kind"`
	Description       string            `json:"description"`
	Mandatory         bool              `json:"mandatory"`
	Subject           *SymbolRef        `json:"subject,omitempty"`
	Subjects          []SymbolRef       `json:"subjects,omitempty"` // alternative symbols: condition holds if ANY is satisfied
	ArgIndex          int               `json:"arg_index,omitempty"`
	Params            map[string]string `json:"params,omitempty"`
	VerificationHints []string          `json:"verification_hints,omitempty"`
}

// MechanismNominationKind names the mechanism-shaping signal a nomination is
// about. Each kind mirrors one heuristic the builder records beside the
// authoritative model instead of applying it.
type MechanismNominationKind string

const (
	// MechanismNominationClass is the pattern-library class a textual or
	// fix-diff signal suggested.
	MechanismNominationClass MechanismNominationKind = "class"
	// MechanismNominationProtocolRole is the protocol role the record's prose
	// or the fix-diff file/symbol names suggested.
	MechanismNominationProtocolRole MechanismNominationKind = "protocol_role"
	// MechanismNominationInputRoute is the input route the record's prose
	// suggested.
	MechanismNominationInputRoute MechanismNominationKind = "input_route"
)

// MechanismNominationSource names the channel that produced a nomination.
// Every channel is a search signal, never a measurement.
type MechanismNominationSource string

const (
	// MechanismNominationKeywords is the advisory summary/description
	// vocabulary table.
	MechanismNominationKeywords MechanismNominationSource = "keywords"
	// MechanismNominationFixDiff is the touched-file/symbol text of the fix.
	MechanismNominationFixDiff MechanismNominationSource = "fix_diff"
	// MechanismNominationProse is a prose regex over the record's own bytes.
	MechanismNominationProse MechanismNominationSource = "prose"
	// MechanismNominationConflict records that the record's own signals named
	// two or more equally specific, incomparable mechanisms, so no single
	// value could be nominated.
	MechanismNominationConflict MechanismNominationSource = "conflict"
)

// MechanismNomination records one heuristic mechanism signal — a class, a
// protocol role or an input route — with the channel that produced it.
// Nominations are research and diagnostics material: they never select a
// class pattern, replace a generic condition, fill an authoritative param,
// narrow completeness, or establish a TRUE or FALSE. Value is empty for a
// conflict nomination, where the signals named no single mechanism.
type MechanismNomination struct {
	Kind   MechanismNominationKind   `json:"kind"`
	Value  string                    `json:"value,omitempty"`
	Source MechanismNominationSource `json:"source"`
}

type ExploitModel struct {
	// Class is the vulnerability class selected from the record's own
	// structured CWE ids — the only class authority. A class nominated from
	// keyword or fix-diff text never sets it; that nomination is recorded in
	// MechanismNominations and the generic model stands.
	Class string `json:"class,omitempty"`
	// Impact is the record's stated impact, kept for presentation.
	Impact string `json:"impact"`
	// ProtocolRole is the protocol role nominated by the record's prose and
	// fix-diff symbol names. It is a nomination: it is never written into a
	// condition param and never decides a falsifier.
	ProtocolRole        ProtocolRole `json:"protocol_role,omitempty"`
	RootCauses          []SymbolRef  `json:"root_causes"`
	MandatoryConditions []Condition  `json:"mandatory_conditions"`
	SupportingFactors   []Condition  `json:"supporting_factors,omitempty"`
	// MechanismNominations records the heuristic class, protocol-role and
	// input-route guesses this model was built beside. They are recorded for
	// research, diagnostics and review; none of them establishes necessity,
	// completeness, a TRUE or a FALSE.
	MechanismNominations []MechanismNomination `json:"mechanism_nominations,omitempty"`
	// UnresolvedMechanism records that the defect mechanism was only
	// nominated — keyword vocabulary, fix-diff text or conflicting prose —
	// so no class pattern was applied and the modeled conjunction omits the
	// conditions that nomination demanded. A non-empty conjunction over that
	// reduced set cannot ground a positive: EXPLOITABLE is withheld while an
	// independently verified mandatory falsifier may still ground a negative.
	UnresolvedMechanism bool `json:"unresolved_mechanism,omitempty"`
	// ProposedConditions carries model-generated condition nominations. The
	// entries keep the model's descriptions, subjects and params for expert
	// review, but are always non-authoritative: the model builder never
	// merges them into MandatoryConditions, evaluators never evaluate them,
	// and no review action can promote one. Mandatory is false on every
	// entry. Parameter values (e.g. a bound) live only here — they never
	// fill or rewrite an authoritative condition param.
	ProposedConditions []Condition `json:"proposed_conditions,omitempty"`
	// PendingConditionReviews names mandatory conditions a high-severity
	// review finding criticised without an independently established
	// repair — an action-less critique, or a demote nomination the narrow
	// applicability contract did not reject. Such a critique is recorded
	// but unresolved: a non-empty list keeps the verdict INCONCLUSIVE so
	// review-budget exhaustion cannot leave NEPF/EXPLOITABLE next to open
	// criticism of the model.
	PendingConditionReviews []ConditionID `json:"pending_condition_reviews,omitempty"`
	// UnresolvedSubjects are advisory-declared sinks that failed source
	// verification or were resolved by package absence — the modeled
	// conditions cover only the verified-present sinks, so EXPLOITABLE
	// would overclaim completeness. A non-empty list turns the verdict
	// INCONCLUSIVE with the missing subjects named; a verified FALSE on
	// the grouped reachability condition still grounds
	// NO_EXPLOIT_PATH_FOUND because it covers every declared symbol.
	UnresolvedSubjects []SymbolRef `json:"unresolved_subjects,omitempty"`
	// AbsentSubjects is the subset of UnresolvedSubjects whose package
	// absence from the build graph is verified by package-list evidence
	// (RootCause.Absent). Unlike genuinely unmodeled sinks these have no
	// unexplored exploit shape — the defect code is provably not linked —
	// so checks that demote on "unmodeled" subjects (e.g. the declared-trust
	// perimeter demotion) must not count them.
	AbsentSubjects []SymbolRef `json:"absent_subjects,omitempty"`
	// LocusSubjects names the defect-locus set L: advisory-declared symbols
	// whose package membership the locus-package-absent falsifier must
	// cover (spec §8). The machine never proves a declared symbol is not a
	// defect site — cross-function operand correspondence is not
	// textually decidable — so L defaults to the whole declared set and
	// shrinks only via recorded expert decisions (NonLocusBasis). Fix-diff
	// anchors (guarded site vs enabler candidate) annotate the set for the
	// expert but do not remove members.
	LocusSubjects []SymbolRef `json:"locus_subjects,omitempty"`
	// NonLocusBasis records exclusions from L: each entry asserts the named
	// declared symbol is not a defect locus, with the justification kept
	// verbatim. Only entries carrying explicit expert-input provenance
	// (LocusSourceExpertInput) are honored — a machine-origin decision that
	// was persisted here remains a proposal regardless of its authority
	// label. These decisions are expert input, not machine evidence —
	// verification may check the falsifier's package coverage, never the
	// truth of the basis itself.
	NonLocusBasis []LocusDecision `json:"non_locus_basis,omitempty"`
	// ProposedNonLocus carries machine-generated non-locus proposals for
	// declared symbols lacking defect-site anchors. Each entry keeps the
	// observed evidence (fix-diff class, body-scan result) as the basis.
	// Proposals never shrink L — they are the draft an expert may approve
	// by recording them as NonLocusBasis input.
	ProposedNonLocus []LocusDecision `json:"proposed_non_locus,omitempty"`
	// LocusAnnotations records the machine's per-symbol classification for
	// every member of L (guarded-site / enabler-candidate / fix-changed /
	// not-fix-changed) with the observed evidence, Authority
	// "machine-annotation". Annotations are advisory labels for the expert
	// and the assessment block — they never shrink L either.
	LocusAnnotations []LocusDecision `json:"locus_annotations,omitempty"`
	EvidenceIDs      []EvidenceID    `json:"evidence_ids,omitempty"`
	// InputRoute is the authoritative input-route decision this model was
	// built under. Only an explicit structured advisory field may bind the
	// vulnerable operation's input to a network peer, and the record
	// contract carries none: the prose vocabulary that suggests a route is a
	// nomination (MechanismNominations), never authority. The field is
	// persisted so replay and review re-derive the same mandatory set; a
	// route-gated pattern variant is eligible only under this value, and a
	// nomination never fills an input_source or protocol_role param.
	InputRoute string `json:"input_route,omitempty"`
	// OperationBindings persists the own-record operation bindings this model
	// used, re-admitted from the resolved root-cause model. They name the exact
	// operation the record declared, so a saved model can be re-admitted
	// against the record's own bytes instead of trusting a subject list.
	OperationBindings []OperationBinding `json:"operation_bindings,omitempty"`
	// DefectSemantics is the advisory-grounded selection between a defective
	// check invocation, an omitted check, and unresolved semantics for a
	// check-like advisory. It is the contract the mandatory conditions are
	// built from; the verdict gate refuses a model that was constructed from
	// a different mechanism (or from the removed heuristic).
	DefectSemantics *DefectSemanticsContract `json:"defect_semantics,omitempty"`
}

// LocusDecisionSource records how a locus decision entered the case. Only
// the explicit expert-input channel can establish an exclusion; a decision
// that merely carries an expert-looking Authority string does not.
type LocusDecisionSource string

const (
	// LocusSourceExpertInput marks decisions supplied through the explicit
	// expert channel: the --non-locus-basis file or a corpus non_locus entry.
	LocusSourceExpertInput LocusDecisionSource = "expert-input"
	// LocusSourceMachineProposal marks machine-generated nominations. They
	// are recorded for expert review and never shrink the authoritative L.
	LocusSourceMachineProposal LocusDecisionSource = "machine-proposal"
)

// LocusDecision is one non-locus decision: declared symbol S is asserted not
// to be a defect locus for this advisory. Basis is the recorded
// justification; Authority names who is claimed to have established it
// (e.g. "expert", a ticket id, a review ref) and is descriptive only. Source
// records how the decision entered the case and is the only authority test:
// an entry that did not come through explicit expert input is a proposal,
// whatever its Authority says.
type LocusDecision struct {
	Symbol    SymbolRef           `json:"symbol"`
	Basis     string              `json:"basis"`
	Authority string              `json:"authority,omitempty"`
	Source    LocusDecisionSource `json:"source,omitempty"`
}

// ExpertLocusDecisions stamps decisions supplied through an explicit expert
// channel with their provenance. It is called by the input readers (the
// --non-locus-basis file and corpus non_locus entries) and by nothing else:
// a decision loaded from persisted machine state is never promoted by this
// helper because it is never passed through it.
func ExpertLocusDecisions(in []LocusDecision) []LocusDecision {
	if len(in) == 0 {
		return nil
	}
	out := make([]LocusDecision, len(in))
	copy(out, in)
	for i := range out {
		out[i].Source = LocusSourceExpertInput
	}
	return out
}

type NegativeVerificationStatus string

const (
	NegativeVerified          NegativeVerificationStatus = "VERIFIED"
	NegativeInsufficientScope NegativeVerificationStatus = "INSUFFICIENT_SCOPE"
	NegativeContradicted      NegativeVerificationStatus = "CONTRADICTED"
)

// NegativeVerification records the independent re-derivation of a FALSE
// claim. EvidenceIDs are code evidence only: policy references
// (declared-assumptions/1 ids) travel on Claim.AssumptionIDs and
// VerdictResult.AssumptionIDs, never here — a verification record must
// not let an owner policy read as a measured check.
type NegativeVerification struct {
	Status      NegativeVerificationStatus `json:"status"`
	EvidenceIDs []EvidenceID               `json:"evidence_ids,omitempty"`
	Notes       string                     `json:"notes,omitempty"`
	Limitations []string                   `json:"limitations,omitempty"`
	// BuildContext is the measurement identity the verification ran under.
	// Nil makes a build-dependent verification non-admitting.
	BuildContext *BuildContext `json:"build_context,omitempty"`
	// CoverID and SubjectDigest are the necessary cover the negative relied
	// on: the admitted cover identity and the digest of its complete,
	// nonempty subject set. A content-derived absence records both, so an
	// edited summary that narrows the claim to the absent member cannot
	// re-admit. They are empty for a negative that rests on no content cover
	// (a record declaration or an operator assertion).
	CoverID       string `json:"cover_id,omitempty"`
	SubjectDigest string `json:"subject_digest,omitempty"`
	// AnalysisGaps carries the typed causes that kept the verification
	// incomplete. A missing negative-verification capability fails the
	// assessment; it never weakens the verdict to a softer one.
	AnalysisGaps []AnalysisGap `json:"analysis_gaps,omitempty"`
}

type HypothesisID string

type HypothesisStatus string

const (
	HypothesisOpen       HypothesisStatus = "OPEN"
	HypothesisConfirmed  HypothesisStatus = "CONFIRMED"
	HypothesisRejected   HypothesisStatus = "REJECTED"
	HypothesisUnresolved HypothesisStatus = "UNRESOLVED"
)

type Hypothesis struct {
	ID               HypothesisID     `json:"id"`
	ConditionID      ConditionID      `json:"condition_id"`
	Statement        string           `json:"statement"`
	ExpectedEvidence []EvidenceKind   `json:"expected_evidence,omitempty"`
	Status           HypothesisStatus `json:"status"`
	// EvidenceIDs point at what the planner's action produced.
	EvidenceIDs []EvidenceID `json:"evidence_ids,omitempty"`
	// Notes record the action taken / why it stayed unresolved.
	Notes string `json:"notes,omitempty"`
}

type Claim struct {
	ID          ClaimID     `json:"id"`
	ConditionID ConditionID `json:"condition_id"`
	Result      ClaimResult `json:"result"`
	// Proposal records a model nomination for this condition's result without
	// establishing it. It is audit material: a proposal never gates the
	// verdict and never justifies a locus reduction. TRUE is established only
	// by deterministic re-evaluation (or the condition's own evaluator) and
	// FALSE only by independent negative verification.
	Proposal             ClaimResult           `json:"proposal,omitempty"`
	EvidenceIDs          []EvidenceID          `json:"evidence_ids,omitempty"`
	Explanation          string                `json:"explanation,omitempty"`
	Limitations          []string              `json:"limitations,omitempty"`
	NegativeVerification *NegativeVerification `json:"negative_verification,omitempty"`
	// Producer names the evaluator/agent that emitted the claim. Claims from
	// deterministic evaluators backed by deterministic evidence are immune
	// to reviewer demotion — reinterpretation cannot undo a verified fact.
	Producer string `json:"producer,omitempty"`
	// Falsifier marks how a FALSE claim was derived so negative verification
	// picks the matching strategy: "guards" = bound-guard coverage.
	Falsifier string `json:"falsifier,omitempty"`
	// FalsifierBasis records what grounds a trusted-infrastructure FALSE:
	// "declared-trust" = operator assertion (--trusted-peer/--perimeter),
	// "auto-perimeter" = classifier-detected cluster isolation, "" = the
	// falsifier rests on code-level provenance (e.g. config-file origin).
	FalsifierBasis string `json:"falsifier_basis,omitempty"`
	// AssumptionIDs names the admitted declared-assumptions/1 member ids
	// this claim's falsifier additionally relied on — policy references,
	// disjoint from EvidenceIDs; assumptions are inputs, not evidence.
	AssumptionIDs []string `json:"assumption_ids,omitempty"`
	// ControlBasis names what grounds a TRUE attacker-control conclusion.
	// Empty for every deployment-origin claim; library-public-api marks the
	// proven product-owned public library API → sink binding, which does
	// not assert deployment exposure. transport-peer-input marks the
	// admitted transport-input binding, which scopes the verdict to
	// transport-peer without asserting deployed adversary access.
	ControlBasis ControlBasis `json:"control_basis,omitempty"`
	// AnalysisGaps carries the typed causes this claim's producer could not
	// discharge. It is structured on purpose: outcome classification routes
	// on gap codes, never on explanation or limitation text.
	AnalysisGaps []AnalysisGap `json:"analysis_gaps,omitempty"`
}

type FalsifierKind string

const (
	FalsifierGovulncheckSilence       = "govulncheck-silence"
	FalsifierNoModuleUsage            = "no-module-usage"
	FalsifierUnreachedExportedSubject = "unreached-exported-subject"
	FalsifierNoProductReader          = "no-product-reader"
	FalsifierMissingPairMember        = "missing-pair-member"
	FalsifierSnapshotFactMismatch     = "snapshot-fact-mismatch"
	FalsifierMissingSourceSymbol      = "missing-source-symbol"
	FalsifierSafeConfigAssignment     = "safe-config-assignment"
	FalsifierZeroValueConfig          = "zero-value-config"
	FalsifierSafeConfigKey            = "safe-config-key"
	FalsifierGuards                   = "guards"
	FalsifierConstantOrGeneratedInput = "constant-or-generated-input"
	// FalsifierTrustedInfrastructure grounds FALSE for transport / peer-input
	// conditions when the product deployment is explicitly declared to operate
	// strictly with trusted infrastructure and authenticated peers (--trusted-peer).
	FalsifierTrustedInfrastructure = "trusted-infrastructure"
	// FalsifierLocusPackageAbsent grounds FALSE for a locus-reachability
	// condition: every locus subject's package is absent from the
	// product's build graph (`go list -deps`), so the defect code is not
	// linked in and cannot execute through any path, including wrappers,
	// callbacks and dynamic dispatch.
	FalsifierLocusPackageAbsent = "locus-package-absent"
	// FalsifierPackageAbsent grounds FALSE for any subject-bearing
	// condition (reachability, input): every evaluated subject's package
	// is absent from the product's build graph (`go list -deps`), so no
	// call path or data flow into the defect code exists. Same premise as
	// locus-package-absent, applied to non-locus conditions.
	FalsifierPackageAbsent = "package-absent"
	// FalsifierDeclaredSymbolUnreached grounds a no-exploit-path decision only
	// from a complete deterministic symbol-unreachability proof.
	FalsifierDeclaredSymbolUnreached = "declared-symbol-unreached"
	// condition: locus packages are present in the product's build graph, but
	// the vulnerable functions have no observed call traces or module chains,
	// requiring negative verification of callers and dynamic markers.
	FalsifierLocusFunctionUnreached = "locus-function-unreached"
	// FalsifierConfigGatedOff grounds FALSE for reachability conditions when
	// all call paths to the vulnerable function are guarded by a configuration
	// flag that is statically proven disabled (false) or unassigned zero-value bool.
	FalsifierConfigGatedOff = "config-feature-disabled"
	// FalsifierLoopbackOnly grounds FALSE for exposure conditions requiring public scope
	// when all resolved network binds are strictly loopback/unix/cluster-internal.
	FalsifierLoopbackOnly = "loopback-only"
	// FalsifierProtocolRoleMismatch grounds FALSE when a vulnerability requires
	// a specific protocol role (server or client) that is contradicted by the product's
	// exclusive deployment mode (e.g. pure-client usage on a server-side vulnerability).
	FalsifierProtocolRoleMismatch = "protocol-role-mismatch"
)

// FalsifierBasis values for Claim.FalsifierBasis and VerdictResult.GroundBasis.
const (
	// BasisDeclaredTrust marks trusted-infrastructure falsification that
	// rests on an operator assertion (--trusted-peer or --perimeter), not
	// on code-level evidence.
	BasisDeclaredTrust = "declared-trust"
	// BasisAutoPerimeter marks trusted-infrastructure falsification that
	// rests on the classifier-detected cluster-internal perimeter.
	BasisAutoPerimeter = "auto-perimeter"
	// BasisConfigOrigin marks trusted-infrastructure falsification that
	// rests on traced config-file origins — a code-level provenance fact.
	BasisConfigOrigin = "config-origin"
)

type EvidenceQuality string

const (
	QualityAuthoritative EvidenceQuality = "AUTHORITATIVE"
	QualityDeterministic EvidenceQuality = "DETERMINISTIC"
	QualityStructural    EvidenceQuality = "STRUCTURAL"
	QualityHeuristic     EvidenceQuality = "HEURISTIC"
	QualityLLMInferred   EvidenceQuality = "LLM_INFERRED"
)

type EvidenceKind string

const (
	EvidenceAdvisory       EvidenceKind = "ADVISORY"
	EvidenceFixDiff        EvidenceKind = "FIX_DIFF"
	EvidenceModuleGraph    EvidenceKind = "MODULE_GRAPH"
	EvidencePackageList    EvidenceKind = "PACKAGE_LIST"
	EvidenceGovulncheck    EvidenceKind = "GOVULNCHECK"
	EvidenceSourceSnippet  EvidenceKind = "SOURCE_SNIPPET"
	EvidenceCallPath       EvidenceKind = "CALL_PATH"
	EvidenceDataFlow       EvidenceKind = "DATA_FLOW"
	EvidenceEntrypoint     EvidenceKind = "ENTRYPOINT"
	EvidenceValidation     EvidenceKind = "VALIDATION"
	EvidenceConfiguration  EvidenceKind = "CONFIGURATION"
	EvidenceRuntime        EvidenceKind = "RUNTIME"
	EvidenceBuild          EvidenceKind = "BUILD"
	EvidenceTest           EvidenceKind = "TEST"
	EvidenceSearchResult   EvidenceKind = "SEARCH_RESULT"
	EvidenceToolLimitation EvidenceKind = "TOOL_LIMITATION"
)

type Evidence struct {
	ID           EvidenceID      `json:"id"`
	Kind         EvidenceKind    `json:"kind"`
	Quality      EvidenceQuality `json:"quality"`
	Source       string          `json:"source"`
	Repository   string          `json:"repository,omitempty"`
	Commit       string          `json:"commit,omitempty"`
	File         string          `json:"file,omitempty"`
	StartLine    int             `json:"start_line,omitempty"`
	EndLine      int             `json:"end_line,omitempty"`
	Tool         string          `json:"tool,omitempty"`
	ToolVersion  string          `json:"tool_version,omitempty"`
	Command      string          `json:"command,omitempty"`
	Content      string          `json:"content"`
	ArtifactHash string          `json:"artifact_hash,omitempty"`
	Limitations  []string        `json:"limitations,omitempty"`
	// BuildContext is the measurement identity this evidence describes.
	// Nil means the producer did not record one — such evidence is
	// non-admitting for build-dependent conclusions.
	BuildContext *BuildContext `json:"build_context,omitempty"`
	// Govulncheck is the typed run record for EvidenceGovulncheck.
	Govulncheck *GovulncheckRun `json:"govulncheck,omitempty"`
	// PackageList is the typed inventory record for EvidencePackageList.
	PackageList *PackageListRun `json:"package_list,omitempty"`
	// SourceScan is the typed coverage record for source-level scans.
	SourceScan *SourceScanRun `json:"source_scan,omitempty"`
	// TransportInput is the rooted server-transport input witness this
	// evidence pins. It is a structured binding, not a "proven" flag: the
	// evaluator re-admits it against the case build and record before any
	// claim may rest on it.
	TransportInput *TransportInputWitness `json:"transport_input,omitempty"`
	// TransportTrigger is the source/fix-bound mechanism witness this
	// evidence pins. A partial witness is recorded on purpose: its failed
	// obligations are what a typed TRIGGER_PROOF_INCOMPLETE gap reports.
	TransportTrigger *TransportTriggerWitness `json:"transport_trigger,omitempty"`
	// CheckTrigger is the typed incorrect-check invocation witness this
	// evidence pins: operation, invocation/receiver identity, argument
	// literal, receiver payload representation and control origin on one
	// record. It is re-admitted by the evaluator and the verdict gate; a
	// saved claim or a raw flow never substitutes for it.
	CheckTrigger *CheckTriggerWitness `json:"check_trigger,omitempty"`
	// MissingCall is the typed check/pipeline omission observation: exact
	// check and pipeline identities, the measurement status and the advisory
	// record it was taken for. The omission evaluators bind it to the admitted
	// OMITTED_CHECK contract and the effective build; the record's build
	// context supplies the measurement identity.
	MissingCall *MissingCallWitness `json:"missing_call,omitempty"`
}

type CallSite struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Function string `json:"function"`
	Receiver string `json:"receiver,omitempty"`
	Package  string `json:"package,omitempty"`
	// Callee names the invoked symbol (e.g. "amqp.DialTLS") when the site is
	// recorded for module-usage evidence rather than as an enclosing function.
	Callee string `json:"callee,omitempty"`
	// ModuleOwner is the module path reported for Callee's package by the
	// product's import graph. Empty means ownership was not resolved.
	ModuleOwner string `json:"module_owner,omitempty"`
	// DeadCode is true when the call site is enclosed in a statically false condition
	// (e.g. an unassigned bool field or literal false feature flag).
	DeadCode bool `json:"dead_code,omitempty"`
	// GatedBy describes the condition guarding this call site (e.g. "cfg.EnableFeature").
	GatedBy string `json:"gated_by,omitempty"`
}

type CallPath struct {
	ConditionID ConditionID `json:"condition_id,omitempty"`
	EvidenceID  EvidenceID  `json:"evidence_id,omitempty"`
	Frames      []CallSite  `json:"frames"`
}

type DataFlow struct {
	ConditionID ConditionID `json:"condition_id,omitempty"`
	Source      CallSite    `json:"source"`
	// Arg is the sink call's argument index this flow was traced for;
	// -1 means the flow is not argument-scoped.
	Arg             int        `json:"arg"`
	Origin          DataOrigin `json:"origin"`
	Transformations []CallSite `json:"transformations,omitempty"`
	Sink            CallSite   `json:"sink"`
	Summary         string     `json:"summary,omitempty"`
	// Value is the argument's resolved integer literal/constant when the
	// trace could determine it — used to check constant arguments against
	// declared input bounds.
	Value           *int64 `json:"value,omitempty"`
	PayloadUnproven bool   `json:"payload_unproven,omitempty"`
	// LibraryInput is the proven public-library-formal → sink-argument
	// binding for this flow. Origin stays UNKNOWN: the witness proves the
	// payload is selectable by a library consumer, never that a deployment
	// exposes it to an attacker.
	LibraryInput *LibraryInputWitness `json:"library_input,omitempty"`
}

type Entrypoint struct {
	CallSite
	Kind    string `json:"kind,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Exposed bool   `json:"exposed"`
}

type Validation struct {
	CallSite
	Property string `json:"property"`
	// Guard marks a terminating if-check on the argument. Origin-assignment
	// records (Guard=false) document where the value came from — they are
	// not guards and cannot cover a sink.
	Guard bool `json:"guard,omitempty"`
	// Conditional marks a guard nested inside control flow: it applies only
	// when the enclosing condition holds, so it cannot unconditionally
	// cover the sink.
	Conditional bool `json:"conditional,omitempty"`
	// Covers marks a guard found in a caller frame (a different file/line)
	// that constrains the argument reaching this sink. Nil for guards that
	// precede the sink call in its own frame.
	Covers *CallSite `json:"covers,omitempty"`
	// Arg is the sink-call argument index this record constrains;
	// -1 means it applies regardless of position.
	Arg int `json:"arg"`
	// BoundLow/BoundHigh record the inclusive range a sanitize guard
	// enforces on the value — resolved to integers when the guard's
	// comparison side is a literal or a named constant.
	BoundLow  *int64 `json:"bound_low,omitempty"`
	BoundHigh *int64 `json:"bound_high,omitempty"`
}

type ConfigItem struct {
	Key      string     `json:"key"`
	Value    string     `json:"value"`
	File     string     `json:"file,omitempty"`
	Line     int        `json:"line,omitempty"`
	Evidence EvidenceID `json:"evidence_id,omitempty"`
}

// Ingress-item kinds: which slot of the product→dependency boundary (or
// which spot inside the reachable dependency cone) an inventoried input
// occupies.
const (
	IngressBoundaryArg      = "boundary_arg"      // call argument at a boundary entry
	IngressBoundaryReceiver = "boundary_receiver" // receiver object of a method entry
	IngressObjectState      = "object_state"      // writable state of an object passed at the boundary
	IngressConeSource       = "cone_source"       // autonomous source inside the reachable dep cone
	IngressIntermediateDep  = "intermediate_dep"  // product call into another dep module that can reach this one
)

// IngressItem is one element of an ingress-closure inventory: an input
// crossing the product→dependency boundary or an autonomous source
// inside the product-reachable dependency cone.
type IngressItem struct {
	CallSite
	Kind string `json:"kind"`
	// Callee names the invoked boundary symbol or the source-producing
	// call inside the cone.
	Callee string     `json:"callee,omitempty"`
	Arg    int        `json:"arg"` // argument index; -1 = receiver/object state
	Origin DataOrigin `json:"origin,omitempty"`
	// Reaches lists condition subject keys ("pkg.Symbol") provably
	// reachable from this item's boundary entry inside the module cone.
	// An empty list does not prove that the item cannot become payload.
	Reaches []string `json:"reaches,omitempty"`
	Detail  string   `json:"detail,omitempty"`
}

// IngressClosure is the coverage record of the ingress-closure
// completeness strategy: every input at the product→module boundary plus
// every autonomous source inside the product-reachable dependency cone.
// Complete means the inventory itself is closed — no unseen entries,
// sources or dispatch opacity; element origins then decide the claim.
type IngressClosure struct {
	ConditionID ConditionID   `json:"condition_id"`
	Module      string        `json:"module"`
	Complete    bool          `json:"complete"`
	Items       []IngressItem `json:"items,omitempty"`
	// Blockers explain why the inventory cannot be proven complete
	// (opaque dispatch, function-value escapes, unresolved scope).
	Blockers []string `json:"blockers,omitempty"`
}

// SinkSite is one payload-input position of one sink in the
// completeness-declared sink set: the call site, the position carrying
// payload (argument index, or -1 for receiver/object state), whether
// the enclosing caller is live in the effective build, and the resolved
// terminal origin of the input.
type SinkSite struct {
	CallSite
	// Sink names the subject key "pkg.Symbol" the site invokes.
	Sink string `json:"sink"`
	// Arg is the payload position: an argument index, or -1 for
	// receiver/object state.
	Arg int `json:"arg"`
	// Live is false only with positive unreachable evidence — an
	// unlinked package or a caller the build cannot invoke.
	Live   bool       `json:"live"`
	Origin DataOrigin `json:"origin,omitempty"`
	Detail string     `json:"detail,omitempty"`
}

// SinkClosure is the coverage record of the sink-closure completeness
// strategy: the condition's declared-complete sink set (Basis holds the
// completeness contract with provenance) plus every call site found in
// the product and the reachable dependency cone with the resolved
// origin of its payload input. Complete means every live site's payload
// input resolved to a non-external origin and no enumeration gap was
// found; dead sites are excluded by call-graph evidence and recorded
// for audit.
type SinkClosure struct {
	ConditionID ConditionID `json:"condition_id"`
	Module      string      `json:"module"`
	// Basis is the completeness contract for the sink set — which
	// authoritative declaration makes it exhaustive, bound to the
	// vulnerability, module and analyzed version. Without a basis the
	// set is KNOWN_ONLY and the closure cannot be complete.
	Basis    string     `json:"basis,omitempty"`
	Complete bool       `json:"complete"`
	Sites    []SinkSite `json:"sites,omitempty"`
	// Blockers explain enumeration gaps — callers in dependency modules
	// outside the loaded cone, unresolvable dispatch, or a declared sink
	// absent from the analyzed version.
	Blockers []string `json:"blockers,omitempty"`
}

// ConfigAssignment is a product-code assignment to a configuration knob
// (a Type.Field subject): composite-literal keys and x.Field = value
// assignments, with the assigned value resolved to a literal/const when
// statically determinable.
type ConfigAssignment struct {
	CallSite
	// Subject is the knob key "pkg.Type.Field".
	Subject string `json:"subject"`
	Value   string `json:"value,omitempty"`
	// Source: "literal", "const", or "" when the value is not resolvable.
	Source string `json:"source,omitempty"`
}

type EvidenceGraph struct {
	mu           sync.Mutex   `json:"-"`
	Version      string       `json:"version"`
	Evidence     []Evidence   `json:"evidence"`
	CallPaths    []CallPath   `json:"call_paths,omitempty"`
	DataFlows    []DataFlow   `json:"data_flows,omitempty"`
	Entrypoints  []Entrypoint `json:"entrypoints,omitempty"`
	ModuleUsages []CallSite   `json:"module_usages,omitempty"`
	// ModuleReachable maps an affected symbol ("pkg.Symbol") to the
	// intra-module call chain (product-used API → ... → subject) proven by
	// vendored-source analysis.
	ModuleReachable map[string][]string `json:"module_reachable,omitempty"`
	// SymbolRefs maps a subject ("pkg.Symbol") to product-code reference
	// sites collected for read-direction conditions — the candidate
	// readers/writers of an exposed datum.
	SymbolRefs map[string][]CallSite `json:"symbol_refs,omitempty"`
	// SymbolDecls records deterministic presence checks of subjects in the
	// dependency source: key "pkg.Symbol" -> declaration site. A present
	// key with a nil site means "checked, not found"; an absent key means
	// the lookup never ran or failed.
	SymbolDecls map[string]*CallSite `json:"symbol_decls,omitempty"`
	// Exposures records resolved network-exposure facts: inbound listener
	// binds and outbound endpoints into the vulnerable module.
	Exposures []ExposureFact `json:"exposures,omitempty"`
	// ConfigFlags maps a knob key "pkg.Type.Field" to the assignments
	// product code makes to it — empty list under a present key means
	// "checked, no assignments".
	ConfigFlags map[string][]ConfigAssignment `json:"config_flags,omitempty"`
	ConfigWriters map[string]ConfigWriterEvidence `json:"config_writers,omitempty"`
	// ConfigFieldKinds maps a knob key to the field's underlying kind
	// ("bool", "string", …) — enables Go zero-value reasoning when the
	// knob is never assigned.
	ConfigFieldKinds map[string]string `json:"config_field_kinds,omitempty"`
	// IngressClosures records the coverage set of the ingress-closure
	// completeness strategy per input condition: boundary items plus
	// autonomous sources inside the reachable dependency cone.
	IngressClosures []IngressClosure `json:"ingress_closures,omitempty"`
	// SinkClosures records the coverage set of the sink-closure
	// completeness strategy per input condition: the declared sink set
	// and per-site payload-input origins.
	SinkClosures  []SinkClosure `json:"sink_closures,omitempty"`
	Validations   []Validation  `json:"validations,omitempty"`
	Configuration []ConfigItem  `json:"configuration,omitempty"`
	Runtime       []EvidenceID  `json:"runtime,omitempty"`
	// ToolExecutions is the audit trail of external tool invocations
	// (spec §22): which tool ran, with what arguments, exit code and
	// output hashes — so every claim can be traced to a concrete run.
	ToolExecutions  []ToolExecution `json:"tool_executions,omitempty"`
	ToolLimitations []string        `json:"tool_limitations,omitempty"`
	Limitations     []string        `json:"limitations,omitempty"`
	Hash            string          `json:"hash,omitempty"`
}

// ToolExecution is one external tool invocation (spec §22). Stdout/stderr
// are hashed rather than stored — large outputs (govulncheck -json) are
// already persisted as evidence content; the hash pins the record to it.
type ToolExecution struct {
	ID           string   `json:"id"`
	Tool         string   `json:"tool"`
	Version      string   `json:"version,omitempty"`
	Dir          string   `json:"dir,omitempty"`
	Args         []string `json:"args,omitempty"`
	ExitCode     int      `json:"exit_code"`
	StdoutSHA256 string   `json:"stdout_sha256,omitempty"`
	StderrSHA256 string   `json:"stderr_sha256,omitempty"`
	DurationMs   int64    `json:"duration_ms"`
	Error        string   `json:"error,omitempty"`
}

// AddEvidence appends e to the graph, assigning an ID when empty, and
// returns the assigned EvidenceID. Safe for concurrent use — parallel
// condition evaluators add evidence into the same case graph.
func (g *EvidenceGraph) AddEvidence(e Evidence) EvidenceID {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.addEvidenceLocked(e)
}

// addEvidenceLocked is AddEvidence without the lock, so a multi-step writer
// can record evidence and link it into other graph records atomically.
// Callers MUST hold g.mu.
func (g *EvidenceGraph) addEvidenceLocked(e Evidence) EvidenceID {
	if e.ID == "" {
		e.ID = EvidenceID(fmt.Sprintf("EV-%03d", len(g.Evidence)+1))
	}
	g.Evidence = append(g.Evidence, e)
	return e.ID
}

// EvidenceByID returns the evidence with the given id, or nil.
func (g *EvidenceGraph) EvidenceByID(id EvidenceID) *Evidence {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.Evidence {
		if g.Evidence[i].ID == id {
			return &g.Evidence[i]
		}
	}
	return nil
}

// AddRuntimeEvidence records e as RUNTIME evidence and links its id into
// Runtime — the graph slice enumerating facts about the analyzed artifact's
// build/runtime environment (binary build info, target platform).
func (g *EvidenceGraph) AddRuntimeEvidence(e Evidence) EvidenceID {
	e.Kind = EvidenceRuntime
	id := g.AddEvidence(e)
	g.mu.Lock()
	g.Runtime = append(g.Runtime, id)
	g.mu.Unlock()
	return id
}

// AddToolExecution appends an audit record, assigning a TX-id.
func (g *EvidenceGraph) AddToolExecution(t ToolExecution) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t.ID == "" {
		t.ID = fmt.Sprintf("TX-%03d", len(g.ToolExecutions)+1)
	}
	g.ToolExecutions = append(g.ToolExecutions, t)
}

// AddLimitation appends a limitation, skipping exact duplicates — the
// same note (e.g. "no call sites") is meaningless when repeated per
// condition or per dynamic marker.
func (g *EvidenceGraph) AddLimitation(s string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.Limitations {
		if l == s {
			return
		}
	}
	g.Limitations = append(g.Limitations, s)
}

func (g *EvidenceGraph) AddToolLimitation(s string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.ToolLimitations {
		if l == s {
			return
		}
	}
	g.ToolLimitations = append(g.ToolLimitations, s)
}

func (g *EvidenceGraph) AddDataFlows(flows ...DataFlow) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.DataFlows = append(g.DataFlows, flows...)
}

// AddArgumentTrace records the evidence that grounds a traced argument flow,
// attaches its assigned ids to every witness on the new flows, and appends
// the flows. Evidence is recorded first so a persisted witness can never
// reference an id that does not exist.
func (g *EvidenceGraph) AddArgumentTrace(flows []DataFlow, evs []Evidence) []EvidenceID {
	g.mu.Lock()
	defer g.mu.Unlock()
	ids := make([]EvidenceID, 0, len(evs))
	for _, e := range evs {
		ids = append(ids, g.addEvidenceLocked(e))
	}
	list := make([]DataFlow, len(flows))
	copy(list, flows)
	for i := range list {
		attachWitnessEvidence(&list[i], ids)
	}
	g.DataFlows = append(g.DataFlows, list...)
	return ids
}

// ReplaceArgumentTrace records the evidence, attaches its ids to the new
// witness, then replaces the flow occupying the same trace slot. The old
// flow — including its witness — is discarded whole: a replacement traced
// without a witness must not retain the previous one. Appends when no slot
// matches.
func (g *EvidenceGraph) ReplaceArgumentTrace(flow DataFlow, evs []Evidence) []EvidenceID {
	g.mu.Lock()
	defer g.mu.Unlock()
	ids := make([]EvidenceID, 0, len(evs))
	for _, e := range evs {
		ids = append(ids, g.addEvidenceLocked(e))
	}
	attachWitnessEvidence(&flow, ids)
	g.replaceDataFlowLocked(flow)
	return ids
}

// attachWitnessEvidence links the evidence that produced a traced flow to the
// flow's library-input witness. The graph takes its own copy of the witness,
// so a caller reusing or mutating the same witness object cannot rewrite a
// persisted proof. A flow without a witness has nothing to reference, so the
// ids stay in the graph's evidence list only.
func attachWitnessEvidence(f *DataFlow, ids []EvidenceID) {
	if f == nil || f.LibraryInput == nil {
		return
	}
	w := *f.LibraryInput
	w.Steps = append([]LibraryPayloadStep(nil), f.LibraryInput.Steps...)
	w.EvidenceIDs = append(append([]EvidenceID(nil), f.LibraryInput.EvidenceIDs...), ids...)
	f.LibraryInput = &w
}

// ReplaceDataFlow swaps the flow recorded for the same condition, sink
// position and argument index (the gap-analysis loop's deeper trace
// supersedes the shallower UNKNOWN one). Appends when nothing matches.
func (g *EvidenceGraph) ReplaceDataFlow(f DataFlow) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.replaceDataFlowLocked(f)
}

// replaceDataFlowLocked is ReplaceDataFlow without the lock. The slot
// identity includes the sink column: distinct calls on one line must not
// overwrite each other's flows. Callers MUST hold g.mu.
func (g *EvidenceGraph) replaceDataFlowLocked(f DataFlow) {
	for i, ex := range g.DataFlows {
		if ex.ConditionID == f.ConditionID &&
			ex.Arg == f.Arg &&
			ex.Sink.File == f.Sink.File && ex.Sink.Line == f.Sink.Line &&
			ex.Sink.Column == f.Sink.Column {
			g.DataFlows[i] = f
			return
		}
	}
	g.DataFlows = append(g.DataFlows, f)
}

func (g *EvidenceGraph) AddValidations(vals ...Validation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Validations = append(g.Validations, vals...)
}

func (g *EvidenceGraph) AddCallPath(cp CallPath) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.CallPaths = append(g.CallPaths, cp)
}

func (g *EvidenceGraph) AddModuleUsages(sites ...CallSite) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ModuleUsages = append(g.ModuleUsages, sites...)
}

func (g *EvidenceGraph) AddModuleReachable(key string, chain []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ModuleReachable == nil {
		g.ModuleReachable = map[string][]string{}
	}
	g.ModuleReachable[key] = chain
}

func (g *EvidenceGraph) AddSymbolRefs(key string, sites ...CallSite) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.SymbolRefs == nil {
		g.SymbolRefs = map[string][]CallSite{}
	}
	g.SymbolRefs[key] = append(g.SymbolRefs[key], sites...)
}

// AddSymbolDecl records the outcome of a presence check: site nil means
// "checked, not found in the dependency source".
func (g *EvidenceGraph) AddSymbolDecl(key string, site *CallSite) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.SymbolDecls == nil {
		g.SymbolDecls = map[string]*CallSite{}
	}
	g.SymbolDecls[key] = site
}

// SymbolRefsFor returns the reference sites recorded for key (nil when the
// read-scope scan found none or never ran — disambiguated by the check
// evidence record).
func (g *EvidenceGraph) SymbolRefsFor(key string) []CallSite {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]CallSite, len(g.SymbolRefs[key]))
	copy(out, g.SymbolRefs[key])
	return out
}

// SymbolDeclFor reports the presence-check outcome for key: found=true,
// site non-nil when declared.
func (g *EvidenceGraph) SymbolDeclFor(key string) (site *CallSite, checked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	site, checked = g.SymbolDecls[key]
	return site, checked
}

// AddConfigFlag records an assignment to a configuration knob; a nil
// assignment still records that the knob was checked.
func (g *EvidenceGraph) AddConfigFlag(subject string, a ...ConfigAssignment) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ConfigFlags == nil {
		g.ConfigFlags = map[string][]ConfigAssignment{}
	}
	g.ConfigFlags[subject] = append(g.ConfigFlags[subject], a...)
}

func (g *EvidenceGraph) AddConfigWriters(subject string, evidence ConfigWriterEvidence) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ConfigWriters == nil { g.ConfigWriters = map[string]ConfigWriterEvidence{} }
	g.ConfigWriters[subject] = evidence
}

// ConfigFlagsFor returns assignments recorded for the knob; checked
// reports whether the lookup ran at all.
func (g *EvidenceGraph) ConfigFlagsFor(subject string) (list []ConfigAssignment, checked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	list, checked = g.ConfigFlags[subject]
	return list, checked
}

// AddConfigFieldKind records the underlying kind of a config knob field.
func (g *EvidenceGraph) AddConfigFieldKind(subject, kind string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ConfigFieldKinds == nil {
		g.ConfigFieldKinds = map[string]string{}
	}
	g.ConfigFieldKinds[subject] = kind
}

// SymbolFieldKind returns the recorded field kind for the knob.
func (g *EvidenceGraph) SymbolFieldKind(subject string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k, ok := g.ConfigFieldKinds[subject]
	return k, ok
}

// AddConfigItem records a configuration key/value found in the repo.
func (g *EvidenceGraph) AddConfigItem(it ConfigItem) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Configuration = append(g.Configuration, it)
}

// ConfigItems returns recorded configuration items.
func (g *EvidenceGraph) ConfigItems() []ConfigItem {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ConfigItem, len(g.Configuration))
	copy(out, g.Configuration)
	return out
}

// AddIngressClosure appends or replaces the closure record for the same
// (condition, module) — a recomputed inventory supersedes the earlier one.
func (g *EvidenceGraph) AddIngressClosure(cl IngressClosure) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, ex := range g.IngressClosures {
		if ex.ConditionID == cl.ConditionID && ex.Module == cl.Module {
			g.IngressClosures[i] = cl
			return
		}
	}
	g.IngressClosures = append(g.IngressClosures, cl)
}

// IngressClosureFor returns the recorded closure for a condition, or nil
// when the inventory was not run for it.
func (g *EvidenceGraph) IngressClosureFor(id ConditionID) *IngressClosure {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.IngressClosures {
		if g.IngressClosures[i].ConditionID == id {
			return &g.IngressClosures[i]
		}
	}
	return nil
}

// AddSinkClosure appends or replaces the closure record for the same
// (condition, module) — a recomputed inventory supersedes the earlier one.
func (g *EvidenceGraph) AddSinkClosure(cl SinkClosure) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, ex := range g.SinkClosures {
		if ex.ConditionID == cl.ConditionID && ex.Module == cl.Module {
			g.SinkClosures[i] = cl
			return
		}
	}
	g.SinkClosures = append(g.SinkClosures, cl)
}

// SinkClosureFor returns the recorded closure for a condition, or nil
// when the inventory was not run for it.
func (g *EvidenceGraph) SinkClosureFor(id ConditionID) *SinkClosure {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.SinkClosures {
		if g.SinkClosures[i].ConditionID == id {
			return &g.SinkClosures[i]
		}
	}
	return nil
}

// AddExposure records a resolved exposure fact.
func (g *EvidenceGraph) AddExposure(f ExposureFact) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Exposures = append(g.Exposures, f)
}

// ExposuresList returns a copy of the recorded exposure facts.
func (g *EvidenceGraph) ExposuresList() []ExposureFact {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ExposureFact, len(g.Exposures))
	copy(out, g.Exposures)
	return out
}

func (g *EvidenceGraph) AddEntrypoints(eps ...Entrypoint) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Entrypoints = append(g.Entrypoints, eps...)
}

// EvidenceList returns a copy of the evidence slice for safe iteration
// while other goroutines may be appending.
func (g *EvidenceGraph) EvidenceList() []Evidence {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Evidence, len(g.Evidence))
	copy(out, g.Evidence)
	return out
}

// ComputeHash sets Hash to the sha256 of the canonical graph encoding
// (Hash field excluded) and returns it.
func (g *EvidenceGraph) ComputeHash() string {
	g.Hash = ""
	b, err := json.Marshal(g)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	g.Hash = hex.EncodeToString(sum[:])
	return g.Hash
}

type ReviewResult string

const (
	ReviewAccept ReviewResult = "ACCEPT"
	ReviewRevise ReviewResult = "REVISE"
)

// ReviewAction names a reviewer's condition nomination. It is advisory:
// RepairAnalysis never moves a condition because a reviewer asked. Only the
// deterministic applicability contract may demote a condition (it names a
// concrete mechanism mismatch), and no contract establishes necessity, so a
// promote is recorded but never applied.
type ReviewAction string

const (
	ReviewActionPromote ReviewAction = "promote"
	ReviewActionDemote  ReviewAction = "demote"
)

type ReviewFinding struct {
	TargetType    string       `json:"target_type"`
	TargetID      string       `json:"target_id"`
	Action        ReviewAction `json:"action,omitempty"`
	Problem       string       `json:"problem"`
	RequiredCheck string       `json:"required_check,omitempty"`
	Severity      string       `json:"severity,omitempty"`
}

type Review struct {
	ID       ReviewID        `json:"id"`
	Result   ReviewResult    `json:"result"`
	Findings []ReviewFinding `json:"findings,omitempty"`
}

type VerdictResult struct {
	Verdict      Verdict       `json:"verdict"`
	Reason       string        `json:"reason"`
	ConditionIDs []ConditionID `json:"condition_ids,omitempty"`
	EvidenceIDs  []EvidenceID  `json:"evidence_ids,omitempty"`
	Limitations  []string      `json:"limitations,omitempty"`
	// ExploitabilityScope names the product boundary this verdict covers.
	// Empty for every deployment-scoped verdict; library-api when a
	// mandatory control claim rests on the proven library public API.
	ExploitabilityScope ExploitabilityScope `json:"exploitability_scope,omitempty"`
	// GroundBasis distinguishes what a NO_EXPLOIT_PATH_FOUND verdict rests
	// on: "declared-trust" (operator-asserted perimeter), "auto-perimeter"
	// (classifier-detected cluster isolation), "config-origin" (traced
	// inputs resolve to host configuration). Empty = grounded by
	// code-level verification (reachability/locus/provenance falsifiers).
	GroundBasis string `json:"ground_basis,omitempty"`
	// AssumptionIDs names the admitted declared-assumptions/1 member ids
	// the verdict's grounding relied on. Policy references travel beside
	// — never inside — EvidenceIDs so a consumer cannot mistake an
	// operator-declared scope/trust assertion for measured evidence.
	AssumptionIDs []string `json:"assumption_ids,omitempty"`
}

type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelNone     RiskLevel = "NONE"
	RiskLevelUnknown  RiskLevel = "UNKNOWN"
)

type TriagePriority string

const (
	PriorityP0        TriagePriority = "P0"        // Blocker (SLA: 24h immediate)
	PriorityP1        TriagePriority = "P1"        // Critical (SLA: 7d)
	PriorityP2        TriagePriority = "P2"        // Medium / High (SLA: Sprint / 30d)
	PriorityP3        TriagePriority = "P3"        // Low / Minor (SLA: Backlog)
	PriorityDismissed TriagePriority = "DISMISSED" // No action / False alarm (SLA: None)
)

// TriageDisposition is what contextual analysis actually did to the
// advisory's baseline rating: preserved it, lowered the remediation
// priority, dismissed the finding, or could not decide.
type TriageDisposition string

const (
	TriageUnchanged    TriageDisposition = "UNCHANGED"
	TriageLowered      TriageDisposition = "LOWERED"
	TriageDismissed    TriageDisposition = "DISMISSED"
	TriageInconclusive TriageDisposition = "INCONCLUSIVE"
)

type ContextualRiskStatus string

const (
	RiskStatusAssessed      ContextualRiskStatus = "ASSESSED"
	RiskStatusProvisional   ContextualRiskStatus = "PROVISIONAL"
	RiskStatusNotApplicable ContextualRiskStatus = "NOT_APPLICABLE"
	RiskStatusUnassessed    ContextualRiskStatus = "UNASSESSED"
)

type ContextualRisk struct {
	Status           ContextualRiskStatus `json:"status"`
	BaseSeverity     string               `json:"base_severity,omitempty"`
	BaseScore        float64              `json:"base_score,omitempty"`
	ContextualLevel  RiskLevel            `json:"contextual_level"`
	ContextualScore  float64              `json:"contextual_score,omitempty"`
	Priority         TriagePriority       `json:"priority"`
	SLA              string               `json:"sla,omitempty"`
	AdjustmentReason string               `json:"adjustment_reason"`
	Factors          RiskFactors          `json:"factors"`
	// TriageDisposition records what contextual analysis did to the
	// advisory baseline; BasePriority is that baseline priority (Priority
	// is the effective one); SeveritySource/ScoreSource mirror the
	// advisory's provenance for presentation.
	TriageDisposition TriageDisposition `json:"triage_disposition,omitempty"`
	BasePriority      TriagePriority    `json:"base_priority,omitempty"`
	SeveritySource    string            `json:"severity_source,omitempty"`
	ScoreSource       string            `json:"score_source,omitempty"`
}

type RiskFactors struct {
	Verdict        string `json:"verdict"`
	Exposure       string `json:"exposure"`        // PUBLIC (0.0.0.0), INTERNAL (127.0.0.1), NONE (no listeners)
	Authentication string `json:"authentication"`  // REQUIRED, NONE, UNKNOWN
	PayloadControl string `json:"payload_control"` // UNTRUSTED_EXTERNAL, CONSTANT, TRUSTED_INFRASTRUCTURE
	BlastRadius    string `json:"blast_radius"`    // PROCESS_CRASH_DOS, DATA_LEAK, RCE, DOWNGRADE, UNKNOWN
}

type ThreatProfile string

const (
	ProfileZeroTrust        ThreatProfile = "zero_trust"
	ProfileClusterPerimeter ThreatProfile = "cluster_perimeter"
)

const (
	PerimeterClusterInternal = "cluster-internal"
	PerimeterPublic          = "public"
	PerimeterUnknown         = "unknown"
)

type ProfileVerdict struct {
	Profile        ThreatProfile  `json:"profile"`
	Title          string         `json:"title"`
	Verdict        Verdict        `json:"verdict"`
	Reason         string         `json:"reason"`
	Falsifier      FalsifierKind  `json:"falsifier,omitempty"`
	Priority       TriagePriority `json:"priority"`
	SLA            string         `json:"sla"`
	IsTargetActual bool           `json:"is_target_actual"`
	// ExploitabilityScope is this profile's flattened copy of the actual
	// verdict's scope — a ProfileVerdict stores a flattened verdict, not a
	// VerdictResult.
	ExploitabilityScope ExploitabilityScope `json:"exploitability_scope,omitempty"`
}

type AnalysisLimits struct {
	MaxIterations       int `json:"max_iterations"`
	MaxToolCalls        int `json:"max_tool_calls"`
	MaxLLMCalls         int `json:"max_llm_calls"`
	MaxSourceReads      int `json:"max_source_reads"`
	MaxReviewIterations int `json:"max_review_iterations"`
}

type AnalysisUsage struct {
	Iterations       int `json:"iterations"`
	ToolCalls        int `json:"tool_calls"`
	LLMCalls         int `json:"llm_calls"`
	SourceReads      int `json:"source_reads"`
	ReviewIterations int `json:"review_iterations"`
}

type WorkflowStatus struct {
	State         WorkflowState `json:"state"`
	PreviousState WorkflowState `json:"previous_state,omitempty"`
	Reason        string        `json:"reason,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	FinishedAt    *time.Time    `json:"finished_at,omitempty"`
	Iteration     int           `json:"iteration"`
	// Timings records wall-clock seconds spent in each workflow state —
	// persisted so slow stages are visible in the case file, not guessed.
	Timings map[string]float64 `json:"timings,omitempty"`
	Limits  AnalysisLimits     `json:"limits"`
	Usage   AnalysisUsage      `json:"usage"`
}

type AnalysisCase struct {
	// mu guards Usage counters when condition evaluators or scan workers
	// touch the case concurrently. JSON ignores unexported fields.
	mu sync.Mutex `json:"-"`
	ID CaseID     `json:"id"`
	// External issue tracker integration metadata:
	TicketID        string          `json:"ticket_id,omitempty"`
	TicketComponent string          `json:"ticket_component,omitempty"`
	TicketRelease   string          `json:"ticket_release,omitempty"`
	Vulnerability   Vulnerability   `json:"vulnerability"`
	Product         ProductSnapshot `json:"product"`
	Affected        *AffectedResult `json:"affected,omitempty"`
	RootCause       *RootCauseModel `json:"root_cause,omitempty"`
	Exploit         *ExploitModel   `json:"exploit_model,omitempty"`
	EvidenceGraph   EvidenceGraph   `json:"evidence_graph"`
	Claims          []Claim         `json:"claims,omitempty"`
	Hypotheses      []Hypothesis    `json:"hypotheses,omitempty"`
	Reviews         []Review        `json:"reviews,omitempty"`
	Verdict         *VerdictResult  `json:"verdict,omitempty"`
	// NonLocusBasis carries the case's non-locus decisions: declared
	// symbols asserted not to be defect loci, with justifications. Only
	// entries with explicit expert-input provenance participate in the
	// locus falsifier's coverage obligation; any saved machine-origin entry
	// remains a proposal and is never treated as machine-verified evidence.
	NonLocusBasis []LocusDecision `json:"non_locus_basis,omitempty"`
	// DeclaredAssumptions is the operator-supplied declared-assumptions/1
	// channel record (--declared-assumptions): the typed policy/scope
	// inputs the run was given — administrator config trust and the
	// supported target matrix — with provenance and the intake outcome.
	// They are inputs, never evidence: nothing here enters the evidence
	// graph, and no member substitutes for a deterministic proof.
	DeclaredAssumptions *DeclaredAssumptionsInput `json:"declared_assumptions,omitempty"`
	// StrictLLM causes the analyzer to fail fast on LLM errors/refusals without falling back to deterministic code.
	StrictLLM bool `json:"strict_llm,omitempty"`
	// PriorCase references the previous stored run of the same
	// vulnerability/repository pair — the reproducibility-diff baseline.
	PriorCase CaseID         `json:"prior_case,omitempty"`
	Workflow  WorkflowStatus `json:"workflow"`

	// CVE Analysis Slice A artifacts:
	CVEAnalysisProfile AnalysisProfile        `json:"cve_analysis_profile,omitempty"`
	CVEAnalysisBundle  *CVESourceBundle       `json:"cve_analysis_bundle,omitempty"`
	CVEAnalysis        *CVEAnalysisProposal   `json:"cve_analysis,omitempty"`
	StrategyPlan       *StrategyPlan          `json:"strategy_plan,omitempty"`
	SemanticReview     *SemanticReview        `json:"semantic_review,omitempty"`
	Justification      *AnalysisJustification `json:"justification,omitempty"`
	ContextualRisk     *ContextualRisk        `json:"contextual_risk,omitempty"`
	DetectedPerimeter  string                 `json:"detected_perimeter,omitempty"`
	PerimeterRationale string                 `json:"perimeter_rationale,omitempty"`
	Profiles           []ProfileVerdict       `json:"profiles,omitempty"`

	// Schema discriminates the result contract. Empty marks a legacy case:
	// it stays readable and must not acquire inferred outcome, discovery,
	// attribution or corpus data. CaseSchemaV2 always carries
	// RequestedFinding.
	Schema CaseResultSchema `json:"schema,omitempty"`
	// RequestedID is the caller's original request identity. Unlike the
	// resolved advisory scope it survives a primary resolution failure, so
	// discovery and composition can still answer a CVE request whose primary
	// record could not be loaded.
	RequestedID string `json:"requested_id,omitempty"`
	// RecordPin identifies the exact record bytes this record-level
	// assessment was derived from. It is the proof that no other record's
	// ranges, symbols, claims, severity or completeness leaked in.
	RecordPin *RecordPin `json:"record_pin,omitempty"`
	// AdvisoryRecord persists the complete advisory bytes this record-level
	// assessment was derived from, together with their pin. The pin names the
	// document; the bytes let a future checker re-derive its inputs from the
	// case itself. Nil on an identity-only resolution, which never claimed
	// exact bytes.
	AdvisoryRecord *AdvisoryRecordCapture `json:"advisory_record,omitempty"`
	// WithdrawnEvidence records, on this evaluation copy only, the historical
	// proofs the loader recognised as withdrawn (a stored content-derived fix
	// binding). It is never persisted — the stored payload stays where it was
	// written — and it authorises nothing: every entry is a diagnostic that
	// says what was withdrawn rather than silently continuing with a weaker
	// route.
	WithdrawnEvidence []WithdrawnProof `json:"-"`
	// CorpusDeclaration is the operator-declared corpus boundary this request
	// was configured with. Addendum A closure requires it to match the
	// observed manifest exactly; a mere feed configuration is not a
	// declaration.
	CorpusDeclaration *CorpusDeclaration `json:"corpus_declaration,omitempty"`
	// CorpusManifest is the observed enumeration of the configured corpus.
	// It is evidence about the corpus, never about any vulnerability.
	CorpusManifest *CorpusManifest `json:"corpus_manifest,omitempty"`
	// Attributions records directional CVE-to-record attribution attempts.
	// Only AttributionAdmitted entries may bind a record's independently
	// earned positive to the requested CVE.
	Attributions []CVEAttribution `json:"attributions,omitempty"`
	// RequestedFinding is the single authoritative answer to the caller's
	// request, present on every v2 case including an exact request whose
	// requested and resolved ids match.
	RequestedFinding *RequestedFinding `json:"requested_finding,omitempty"`
	// RelatedDiscovery records what the configured corpus nominated for this
	// request: discovery only, never identity or fact inheritance.
	RelatedDiscovery *RelatedDiscovery `json:"related_discovery,omitempty"`
	// RelatedRecords holds each candidate's own assessment. The nested cases
	// are pointers because an analysis case owns a mutex and an evidence
	// graph; copying either by value would share or corrupt state.
	RelatedRecords []RelatedRecordAssessment `json:"related_records,omitempty"`
	// ProfileAssessments holds each threat profile's independent claim set and
	// terminal result, including hypothetical profiles, kept distinct from the
	// actual deployment assessment.
	ProfileAssessments []ProfileAssessment `json:"profile_assessments,omitempty"`
	// AnalysisGaps carries record-level typed causes that could not be
	// discharged. Outcome classification routes on these codes.
	AnalysisGaps []AnalysisGap `json:"analysis_gaps,omitempty"`
	// PerimeterAssessment records the exposure classification together with
	// what grounds it, so listener locality or topology can never select a
	// trusted-peer actual profile.
	PerimeterAssessment *PerimeterAssessment `json:"perimeter_assessment,omitempty"`
}

// AddHypothesis appends a hypothesis with an assigned H-id.
func (c *AnalysisCase) AddHypothesis(h Hypothesis) HypothesisID {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h.ID == "" {
		h.ID = HypothesisID(fmt.Sprintf("H-%03d", len(c.Hypotheses)+1))
	}
	c.Hypotheses = append(c.Hypotheses, h)
	return h.ID
}

// Usage counter helpers — the only safe writers under parallelism.
func (c *AnalysisCase) IncLLMCalls()    { c.mu.Lock(); c.Workflow.Usage.LLMCalls++; c.mu.Unlock() }
func (c *AnalysisCase) IncToolCalls()   { c.mu.Lock(); c.Workflow.Usage.ToolCalls++; c.mu.Unlock() }
func (c *AnalysisCase) IncSourceReads() { c.mu.Lock(); c.Workflow.Usage.SourceReads++; c.mu.Unlock() }
func (c *AnalysisCase) IncReviewIterations() {
	c.mu.Lock()
	c.Workflow.Usage.ReviewIterations++
	c.mu.Unlock()
}
func (c *AnalysisCase) UsageSnapshot() AnalysisUsage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Workflow.Usage
}

// securityTransformRe matches callee names that can alter whether exploit
// input still violates the sink's constraint — quoting, sanitization,
// bounds, crypto. A recorded transform is provenance, never proof: the
// analyzer does not model transform semantics, so a security-relevant
// transform is flagged for review, not trusted as a guard.
var securityTransformRe = regexp.MustCompile(`(?i)escape|quote|sanitiz|clean|valid|check|encrypt|decrypt|sign|verify|hash|md5|sha|limit|truncat|bound|cap|mask|redact|filter`)

// IsSecurityTransform reports whether a transformation callee name is
// security-relevant — it may change the properties an exploit condition
// depends on, so its presence is flagged in claim limitations.
func IsSecurityTransform(callee string) bool {
	base := callee
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	return securityTransformRe.MatchString(base)
}

// PackageInModule reports whether pkgPath belongs to module mod — the
// module root package itself or a subpackage. A bare prefix match is
// wrong: "example.com/dep" would swallow "example.com/dep5/...".
func PackageInModule(pkgPath, mod string) bool {
	return pkgPath == mod || strings.HasPrefix(pkgPath, mod+"/")
}

// OwnerModule returns the longest module path in mods containing pkgPath.
// Nested modules ("example.com/dep" vs "example.com/dep/v2") otherwise
// match several prefixes and the parent's evidence bleeds into the child.
func OwnerModule(pkgPath string, mods []string) string {
	best := ""
	for _, m := range mods {
		if PackageInModule(pkgPath, m) && len(m) > len(best) {
			best = m
		}
	}
	return best
}
