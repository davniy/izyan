package domain

// Release-evidence trust taxonomy. Every release-toolchain observation is
// classified before it may influence a version-based determination:
//
//	AUTHORITATIVE — measured or explicitly supplied release facts: the
//	release binary's embedded build info and ticket/SBOM release metadata
//	supplied by the operator. Only these may ground release (stdlib)
//	applicability.
//	SUPPORTING — declarable build inputs found in the source snapshot
//	(go.mod toolchain directive, Dockerfile FROM golang:X, CI setup-go,
//	.go-version/mise/asdf pins, release scripts). A supporting item is
//	provenance, never proof: it corroborates an authoritative version but
//	can never establish or override one.
//
// The status taxonomy covers the aggregate outcome:
//
//	RESOLVED — all authoritative items agree on one normalized version.
//	CONFLICTED — authoritative items disagree; no version is selected and
//	release applicability stays UNKNOWN (never the first or newest value).
//	UNKNOWN — no authoritative evidence: either none was found
//	(RELEASE_EVIDENCE_ABSENT) or only SUPPORTING declarations exist
//	(RELEASE_EVIDENCE_SUPPORTING_ONLY).
//	NOT_REQUESTED — no evidence channel ran (the summary itself may simply
//	be absent for legacy snapshots).
//	NOT_RUN — an explicitly requested channel failed; release evidence is
//	unavailable by an explicit fail-closed outcome, not by absence.
type ReleaseTrustClass string

const (
	ReleaseTrustAuthoritative ReleaseTrustClass = "AUTHORITATIVE"
	ReleaseTrustSupporting    ReleaseTrustClass = "SUPPORTING"
)

// Trust class constants are intentionally exhaustive for item classes:
// UNKNOWN/CONFLICTED/NOT_RUN describe summary status, never an item —
// an item either measured a release fact or merely declared one.
type ReleaseEvidenceStatus string

const (
	ReleaseStatusNotRequested ReleaseEvidenceStatus = "NOT_REQUESTED"
	ReleaseStatusResolved     ReleaseEvidenceStatus = "RESOLVED"
	ReleaseStatusUnknown      ReleaseEvidenceStatus = "UNKNOWN"
	ReleaseStatusConflicted   ReleaseEvidenceStatus = "CONFLICTED"
	ReleaseStatusNotRun       ReleaseEvidenceStatus = "NOT_RUN"
)

// Named reason codes for non-RESOLVED release-evidence outcomes. The
// ARTIFACT_* family covers the bounded acquisition channel (local path or
// HTTPS download): every expected input, download, archive-safety and
// build-info failure is an explicit fail-closed outcome, never a silent
// skip. RELEASE_* codes cover supplied metadata and the precedence
// resolver.
const (
	ReleaseReasonAbsent                = "RELEASE_EVIDENCE_ABSENT"
	ReleaseReasonSupportingOnly        = "RELEASE_EVIDENCE_SUPPORTING_ONLY"
	ReleaseReasonConflict              = "RELEASE_EVIDENCE_CONFLICT"
	ReleaseReasonMetadataInvalid       = "RELEASE_METADATA_INVALID"
	ReleaseReasonReleaseVersionInvalid = "RELEASE_VERSION_INVALID"

	ReleaseReasonArtifactNotRequested        = "ARTIFACT_NOT_REQUESTED"
	ReleaseReasonArtifactPathMissing         = "ARTIFACT_PATH_MISSING"
	ReleaseReasonArtifactPathUnreadable      = "ARTIFACT_PATH_UNREADABLE"
	ReleaseReasonArtifactCredentialsMissing  = "ARTIFACT_CREDENTIALS_MISSING"
	ReleaseReasonArtifactURLInvalid          = "ARTIFACT_URL_INVALID"
	ReleaseReasonArtifactDownloadFailed      = "ARTIFACT_DOWNLOAD_FAILED"
	ReleaseReasonArtifactHTTPUnauthorized    = "ARTIFACT_HTTP_UNAUTHORIZED"
	ReleaseReasonArtifactSizeLimit           = "ARTIFACT_SIZE_LIMIT"
	ReleaseReasonArtifactTimeout             = "ARTIFACT_TIMEOUT"
	ReleaseReasonArtifactArchiveUnsafe       = "ARTIFACT_ARCHIVE_UNSAFE"
	ReleaseReasonArtifactNoGoBinary          = "ARTIFACT_NO_GO_BINARY"
	ReleaseReasonArtifactAmbiguousBinary     = "ARTIFACT_AMBIGUOUS_BINARY"
	ReleaseReasonArtifactBuildInfoUnreadable = "ARTIFACT_BUILD_INFO_UNREADABLE"
)

// ReleaseModule is one module entry of the release binary's build info:
// the dependency graph of the shipped artifact, which may differ from the
// source snapshot's go.sum resolution. Replace points at the replacement
// module when the release build applied one.
type ReleaseModule struct {
	Path    string         `json:"path"`
	Version string         `json:"version"`
	Main    bool           `json:"main,omitempty"`
	Replace *ReleaseModule `json:"replace,omitempty"`
}

// ReleaseEvidenceItem is one observed release-toolchain declaration: what
// version the source claims, where it was found, its trust class, and —
// for artifact-derived items — the artifact/member/build-info provenance
// that makes the observation verifiable.
type ReleaseEvidenceItem struct {
	Version         string            `json:"version,omitempty"`
	Source          GoVersionSource   `json:"source"`
	TrustClass      ReleaseTrustClass `json:"trust_class"`
	Location        string            `json:"location,omitempty"`
	ArtifactSHA256  string            `json:"artifact_sha256,omitempty"`
	BinaryMember    string            `json:"binary_member,omitempty"`
	BuildInfoSHA256 string            `json:"build_info_sha256,omitempty"`
}

// ReleaseEvidenceSummary is the resolved record of release-toolchain
// evidence for a snapshot. Only an AUTHORITATIVE selection may populate
// SelectedVersion — a summary whose status is UNKNOWN or CONFLICTED must
// never carry a selected release version.
type ReleaseEvidenceSummary struct {
	Status                  ReleaseEvidenceStatus `json:"status"`
	ReasonCode              string                `json:"reason_code,omitempty"`
	RequiredChannelFailures []string              `json:"required_channel_failures,omitempty"`
	SelectedVersion         string                `json:"selected_version,omitempty"`
	SelectedSource          GoVersionSource       `json:"selected_source,omitempty"`
	SelectedTrust           ReleaseTrustClass     `json:"selected_trust,omitempty"`
	Items                   []ReleaseEvidenceItem `json:"items,omitempty"`
	Modules                 []ReleaseModule       `json:"modules,omitempty"`
	ArtifactSHA256          string                `json:"artifact_sha256,omitempty"`
	BinaryMember            string                `json:"binary_member,omitempty"`
	BuildInfoSHA256         string                `json:"build_info_sha256,omitempty"`
	// Target carries the release channel's build-target facts when the
	// channel recorded them: artifact build-info settings bound to the
	// artifact digest, or release-metadata build-target declarations.
	// It never carries a product support-matrix assertion — that is the
	// declared-assumptions channel's job.
	Target *ProductTarget `json:"target,omitempty"`
}
