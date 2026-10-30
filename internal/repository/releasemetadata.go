package repository

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// release-metadata/1 is the ticket/SBOM release-metadata document the
// operator supplies via --release-metadata: the shipped toolchain version
// and/or the shipped module graph, asserted by the release pipeline. Every
// member is operator-supplied AUTHORITATIVE evidence; a malformed or
// unreadable document is an explicit fail-closed channel outcome
// (NOT_RUN/RELEASE_METADATA_INVALID), never a silent skip.
const releaseMetadataSchema = "release-metadata/1"

// maxReleaseMetadataBytes bounds the operator-supplied metadata document.
// It is a static ticket/SBOM sidecar — anything larger is malformed input.
const maxReleaseMetadataBytes = int64(1) << 20

// metadataCredentialKeyRe rejects key names that would carry a credential
// into the evidence record: the metadata channel never needs secrets, and
// a leaked credential must never enter a report, observation, or cache.
var metadataCredentialKeyRe = regexp.MustCompile(`(?i)"[^"]*(credential|password|passwd|secret|api_?key|authorization|bearer|access_?token)[^"]*"\s*:`)

// releaseMetadataDoc is the strict release-metadata/1 shape: the member set
// is closed — unknown keys are rejected, never silently dropped.
type releaseMetadataDoc struct {
	Schema    string `json:"schema"`
	GoVersion string `json:"go_version,omitempty"`
	Modules   []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"modules,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	// Target declares the release build's own target facts. It is a
	// build fact (one release build has one GOOS/GOARCH/tag/cgo shape),
	// never a product support-matrix assertion: a release-metadata/1
	// document cannot claim which platforms the product supports.
	Target *releaseMetadataTarget `json:"target,omitempty"`
}

// releaseMetadataTarget is the strict target member: every build fact is
// explicit, including CGO_ENABLED (a missing value cannot be read as
// false). Build tags are optional and describe the release build's flag
// value; absent means no -tags flag.
type releaseMetadataTarget struct {
	GOOS       string   `json:"goos"`
	GOARCH     string   `json:"goarch"`
	BuildTags  []string `json:"build_tags,omitempty"`
	CGOEnabled *bool    `json:"cgo_enabled"`
}

// metadataFailClosed builds the NOT_RUN summary every malformed-input path
// returns. ReasonCode defaults to RELEASE_METADATA_INVALID; the service
// merge applies it only when no other channel resolved.
func metadataFailClosed() *domain.ReleaseEvidenceSummary {
	return &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusNotRun,
		ReasonCode: domain.ReleaseReasonMetadataInvalid,
	}
}

// LoadReleaseMetadata reads and validates a release-metadata/1 document and
// returns it as a typed ReleaseEvidenceSummary for SnapshotOptions.
// ReleaseMetadata: a declared go_version becomes an AUTHORITATIVE
// explicit-source item, declared modules become the release module graph,
// and a declared artifact digest travels as provenance. The summary is
// never nil: every failure — unreadable file, oversized document, wrong
// schema, malformed member, credential-bearing key — returns the same
// NOT_RUN/RELEASE_METADATA_INVALID channel outcome. The digest of a
// well-formed document is pinned in Items[...].Location's parent channel
// by the caller; the summary itself carries only release facts.
func LoadReleaseMetadata(path string) *domain.ReleaseEvidenceSummary {
	if strings.TrimSpace(path) == "" {
		return metadataFailClosed()
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxReleaseMetadataBytes {
		return metadataFailClosed()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return metadataFailClosed()
	}
	if metadataCredentialKeyRe.Match(raw) {
		return metadataFailClosed()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc releaseMetadataDoc
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return metadataFailClosed()
	}
	if doc.Schema != releaseMetadataSchema {
		return metadataFailClosed()
	}
	sum := &domain.ReleaseEvidenceSummary{Status: domain.ReleaseStatusUnknown}
	if v := strings.TrimSpace(doc.GoVersion); v != "" {
		if normalizeReleaseVersion(v) == "" || strings.ContainsAny(v, " \t\n\"'") {
			return metadataFailClosed()
		}
		sum.Items = append(sum.Items, domain.ReleaseEvidenceItem{
			Version:    v,
			Source:     domain.GoVersionSourceExplicit,
			TrustClass: domain.ReleaseTrustAuthoritative,
			Location:   ProvenanceLocalRef(path),
		})
	}
	for _, m := range doc.Modules {
		if !metadataModulePathOK(m.Path) || !metadataModuleVersionOK(m.Version) {
			return metadataFailClosed()
		}
		sum.Modules = append(sum.Modules, domain.ReleaseModule{Path: m.Path, Version: m.Version})
	}
	if doc.ArtifactSHA256 != "" {
		sha, derr := hex.DecodeString(doc.ArtifactSHA256)
		if derr != nil || len(sha) != 32 {
			return metadataFailClosed()
		}
		sum.ArtifactSHA256 = strings.ToLower(doc.ArtifactSHA256)
	}
	if doc.Target != nil {
		if doc.Target.CGOEnabled == nil {
			return metadataFailClosed()
		}
		target := &domain.ProductTarget{
			GOOS:       doc.Target.GOOS,
			GOARCH:     doc.Target.GOARCH,
			BuildTags:  doc.Target.BuildTags,
			CGOEnabled: *doc.Target.CGOEnabled,
			Source:     domain.ProductTargetSourceReleaseMetadata,
			Scope:      domain.ProductTargetScopeRelease,
		}
		if err := target.Validate(); err != nil {
			return metadataFailClosed()
		}
		sum.Target = target
	}
	if len(sum.Items) == 0 && len(sum.Modules) == 0 && sum.ArtifactSHA256 == "" && sum.Target == nil {
		// An empty document supplies no release fact: it is a malformed
		// channel, not evidence of absence.
		return metadataFailClosed()
	}
	if len(sum.Items) > 0 {
		sum.Status = domain.ReleaseStatusResolved
	}
	return sum
}

// metadataModulePathOK requires a plausible module path: no whitespace, no
// scheme, no userinfo marker — the path is provenance text, never a URL.
func metadataModulePathOK(p string) bool {
	if p == "" || len(p) > 256 {
		return false
	}
	return !strings.ContainsAny(p, " \t\n\"'@") && !strings.Contains(p, "://")
}

// metadataModuleVersionOK requires a semver-shaped module version.
var metadataModuleVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)?$`)

func metadataModuleVersionOK(v string) bool {
	return metadataModuleVersionRe.MatchString(v)
}
