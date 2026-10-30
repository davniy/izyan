package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// ProductTarget is the recorded build target of the analyzed product,
// with the provenance that makes the fact checkable. It is the only
// representation a platform-scoped conclusion may consume: GOOS/GOARCH
// copied onto ProductSnapshot without this record are ordinary analysis
// context and can never ground a product-wide implementation conclusion.
//
// Source names where the target facts came from:
//
//	artifact-build-info — the selected release artifact's (or a plain
//	                      --binary's) embedded debug.BuildInfo.Settings,
//	                      bound to the artifact SHA-256, binary member
//	                      (empty for a bare binary) and build-info digest;
//	release-metadata    — the operator-supplied release-metadata/1
//	                      document's build-target facts;
//	operator-declared   — explicit --goos/--goarch/--build-tags flags;
//	host-default        — the analyzer host, used only for ordinary
//	                      analysis, never for a product-wide conclusion.
//
// Scope names what the facts describe: one artifact, one release, or the
// operator-declared build. Product-wide conclusions additionally require
// an admitted supported-targets assumption; a target record alone never
// asserts the product support matrix.
type ProductTarget struct {
	GOOS            string   `json:"goos"`
	GOARCH          string   `json:"goarch"`
	BuildTags       []string `json:"build_tags,omitempty"`
	CGOEnabled      bool     `json:"cgo_enabled"`
	Source          string   `json:"source"`
	Scope           string   `json:"scope"`
	ArtifactSHA256  string   `json:"artifact_sha256,omitempty"`
	BuildInfoSHA256 string   `json:"build_info_sha256,omitempty"`
	BinaryMember    string   `json:"binary_member,omitempty"`
}

// ProductTarget source values.
const (
	ProductTargetSourceArtifactBuildInfo = "artifact-build-info"
	ProductTargetSourceReleaseMetadata   = "release-metadata"
	ProductTargetSourceOperatorDeclared  = "operator-declared"
	ProductTargetSourceHostDefault       = "host-default"
)

// ProductTarget scope values. Host defaults carry no scope: they describe
// the analyzer, not the product.
const (
	ProductTargetScopeArtifact = "artifact"
	ProductTargetScopeRelease  = "release"
	ProductTargetScopeOperator = "operator"
)

var (
	targetGOOSRe    = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	targetGOARCHRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_]*$`)
	targetTagRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._=-]{0,63}$`)
	hexDigestSha256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// MaxProductBuildTags bounds one recorded build-tag set.
const MaxProductBuildTags = 32

// Validate enforces the closed target record: a concrete GOOS/GOARCH,
// bounded build tags, a known source/scope pair, and — for artifact
// facts — the digest binding that makes the build-info observation
// verifiable. A host default carries no scope and no digest.
func (t ProductTarget) Validate() error {
	if !targetGOOSRe.MatchString(t.GOOS) {
		return fmt.Errorf("target goos %q is not a valid platform name", t.GOOS)
	}
	if !targetGOARCHRe.MatchString(t.GOARCH) {
		return fmt.Errorf("target goarch %q is not a valid platform name", t.GOARCH)
	}
	if len(t.BuildTags) > MaxProductBuildTags {
		return fmt.Errorf("target carries %d build tags; the bound is %d", len(t.BuildTags), MaxProductBuildTags)
	}
	for _, tag := range t.BuildTags {
		if !targetTagRe.MatchString(tag) {
			return fmt.Errorf("target build tag %q is invalid", tag)
		}
	}
	switch t.Source {
	case ProductTargetSourceArtifactBuildInfo:
		if t.Scope != ProductTargetScopeArtifact {
			return fmt.Errorf("artifact-build-info target scope %q != %q", t.Scope, ProductTargetScopeArtifact)
		}
		if !hexDigestSha256.MatchString(t.ArtifactSHA256) {
			return fmt.Errorf("artifact-build-info target lacks a 64-hex artifact digest")
		}
		if !hexDigestSha256.MatchString(t.BuildInfoSHA256) {
			return fmt.Errorf("artifact-build-info target lacks a 64-hex build-info digest")
		}
	case ProductTargetSourceReleaseMetadata:
		if t.Scope != ProductTargetScopeRelease {
			return fmt.Errorf("release-metadata target scope %q != %q", t.Scope, ProductTargetScopeRelease)
		}
		if t.ArtifactSHA256 != "" || t.BuildInfoSHA256 != "" || t.BinaryMember != "" {
			return fmt.Errorf("release-metadata target must not carry artifact/build-info digests")
		}
	case ProductTargetSourceOperatorDeclared:
		if t.Scope != ProductTargetScopeOperator {
			return fmt.Errorf("operator-declared target scope %q != %q", t.Scope, ProductTargetScopeOperator)
		}
		if t.ArtifactSHA256 != "" || t.BuildInfoSHA256 != "" || t.BinaryMember != "" {
			return fmt.Errorf("operator-declared target must not carry artifact/build-info digests")
		}
	case ProductTargetSourceHostDefault:
		if t.Scope != "" {
			return fmt.Errorf("host-default target carries scope %q; a host observation has no product scope", t.Scope)
		}
		if t.ArtifactSHA256 != "" || t.BuildInfoSHA256 != "" || t.BinaryMember != "" {
			return fmt.Errorf("host-default target must not carry artifact/build-info digests")
		}
	default:
		return fmt.Errorf("target source %q is not a known provenance", t.Source)
	}
	return nil
}

// Authoritative reports whether the target facts are measured release
// facts rather than an operator/host statement.
func (t ProductTarget) Authoritative() bool {
	return t.Source == ProductTargetSourceArtifactBuildInfo || t.Source == ProductTargetSourceReleaseMetadata
}

// Scoped reports whether the target describes a product build at all:
// a host default is analysis context, never a product target.
func (t ProductTarget) Scoped() bool {
	return t.Source != "" && t.Source != ProductTargetSourceHostDefault
}

// Platform renders the target's GOOS/GOARCH pair, e.g. "linux/amd64".
func (t ProductTarget) Platform() string {
	if t.GOOS == "" || t.GOARCH == "" {
		return ""
	}
	return t.GOOS + "/" + t.GOARCH
}

// TargetScopeMatch checks a recorded target against a declared target
// matrix: the recorded GOOS must be supported, GOARCH must be supported
// when the matrix names architectures, and the declared build tags must
// equal the recorded set (build tags select source files exactly as
// GOOS/GOARCH do, so an undeclared difference is not covered).
func TargetScopeMatch(target ProductTarget, ts ProductTargetScope) error {
	if len(ts.GOOS) == 0 {
		return fmt.Errorf("declared target matrix names no GOOS")
	}
	foundOS := false
	for _, g := range ts.GOOS {
		if g == target.GOOS {
			foundOS = true
			break
		}
	}
	if !foundOS {
		return fmt.Errorf("recorded target GOOS %q is not in the declared supported matrix %v", target.GOOS, ts.GOOS)
	}
	if len(ts.GOARCH) > 0 {
		foundArch := false
		for _, a := range ts.GOARCH {
			if a == target.GOARCH {
				foundArch = true
				break
			}
		}
		if !foundArch {
			return fmt.Errorf("recorded target GOARCH %q is not in the declared supported architectures %v", target.GOARCH, ts.GOARCH)
		}
	}
	if !sameTargetTags(target.BuildTags, ts.BuildTags) {
		return fmt.Errorf("recorded build tags %v do not match the declared supported build tags %v", target.BuildTags, ts.BuildTags)
	}
	return nil
}

// sameTargetTags compares tag sets order-insensitively.
func sameTargetTags(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, t := range a {
		seen[t]++
	}
	for _, t := range b {
		seen[t]--
		if seen[t] < 0 {
			return false
		}
	}
	return true
}

// BuildTargetSnapshot returns a copy of snap carrying target's build
// facts. The target provenance record itself is copied too, so every
// downstream verifier sees both the effective context and its source.
func BuildTargetSnapshot(snap ProductSnapshot, target ProductTarget) ProductSnapshot {
	snap.GOOS = target.GOOS
	snap.GOARCH = target.GOARCH
	snap.BuildTags = append([]string(nil), target.BuildTags...)
	snap.CGOEnabled = target.CGOEnabled
	t := target
	snap.Target = &t
	return snap
}

// TargetTagLine renders build tags for reason/limitation text.
func TargetTagLine(tags []string) string {
	if len(tags) == 0 {
		return "none"
	}
	return strings.Join(tags, ",")
}
