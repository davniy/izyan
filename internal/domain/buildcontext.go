package domain

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// GoWorkOff is the recorded GoWorkFile value of an inactive workspace
// mode: the snapshot applied GOWORK=off instead of letting each probe
// auto-discover (or inherit) a workspace of its own.
const GoWorkOff = "off"

// ErrBuildContextMismatch marks a comparison between two measurement
// identities that disagree. Callers tests it with errors.Is; the wrapped
// message names the divergent field.
var ErrBuildContextMismatch = errors.New("build context mismatch")

// BuildContext is the derived measurement identity of one product build: the
// repository state and the build-selection facts every build-dependent probe
// must share. It is NOT a provenance source — it carries no target Source or
// Scope. ProductTarget remains the provenance authority for the build facts
// copied here; this record only says which build a measurement describes.
type BuildContext struct {
	Repository        string `json:"repository"`
	Commit            string `json:"commit"`
	ExternalCommitSHA string `json:"external_commit_sha,omitempty"`
	ContentHash       string `json:"content_hash,omitempty"`

	GOOS       string   `json:"goos"`
	GOARCH     string   `json:"goarch"`
	BuildTags  []string `json:"build_tags,omitempty"`
	CGOEnabled bool     `json:"cgo_enabled"`

	GoVersion      string `json:"go_version"`
	GoModDirective string `json:"go_mod_directive,omitempty"`
	VendorMode     bool   `json:"vendor_mode"`
	// GoWorkFile records the workspace file the snapshot actually applied,
	// or the literal GoWorkOff value when workspace mode is inactive. An
	// empty value means the snapshot never resolved workspace mode (raw
	// in-process construction), and no GOWORK override is applied.
	GoWorkFile        string             `json:"go_work_file,omitempty"`
	GoFlags           string             `json:"go_flags,omitempty"`
	ReplaceDirectives []ReplaceDirective `json:"replace_directives,omitempty"`

	BinaryPath   string `json:"binary_path,omitempty"`
	BinarySHA256 string `json:"binary_sha256,omitempty"`
}

// EffectiveBuildContext derives the measurement identity of a product
// snapshot. Mutable slices are copied so a captured context cannot be
// rewritten by a later snapshot mutation.
func EffectiveBuildContext(s ProductSnapshot) BuildContext {
	b := BuildContext{
		Repository:        s.Repository,
		Commit:            s.Commit,
		ExternalCommitSHA: s.ExternalCommitSHA,
		ContentHash:       s.ContentHash,
		GOOS:              s.GOOS,
		GOARCH:            s.GOARCH,
		BuildTags:         slices.Clone(s.BuildTags),
		CGOEnabled:        s.CGOEnabled,
		GoVersion:         s.GoVersion,
		GoModDirective:    s.GoModDirective,
		VendorMode:        s.VendorMode,
		GoWorkFile:        s.GoWorkFile,
		GoFlags:           s.GoFlags,
		ReplaceDirectives: slices.Clone(s.ReplaceDirectives),
		BinaryPath:        s.BinaryPath,
	}
	// The binary digest is recorded on the target provenance record: it is
	// the artifact digest that binds the observed build info.
	if s.Target != nil {
		b.BinarySHA256 = s.Target.ArtifactSHA256
	}
	return b
}

// Matches compares every recorded field. Build tags compare
// order-insensitively (the same tag set selects the same files); all other
// fields — including replace-directive order — must be identical. The error
// names the first divergent field and wraps ErrBuildContextMismatch.
func (b BuildContext) Matches(other BuildContext) error {
	mismatch := func(field, recorded, effective string) error {
		return fmt.Errorf("%w: %s (recorded %q, effective %q)", ErrBuildContextMismatch, field, recorded, effective)
	}
	if b.Repository != other.Repository {
		return mismatch("repository", b.Repository, other.Repository)
	}
	if b.Commit != other.Commit {
		return mismatch("commit", b.Commit, other.Commit)
	}
	if b.ExternalCommitSHA != other.ExternalCommitSHA {
		return mismatch("external_commit_sha", b.ExternalCommitSHA, other.ExternalCommitSHA)
	}
	if b.ContentHash != other.ContentHash {
		return mismatch("content_hash", b.ContentHash, other.ContentHash)
	}
	if b.GOOS != other.GOOS {
		return mismatch("goos", b.GOOS, other.GOOS)
	}
	if b.GOARCH != other.GOARCH {
		return mismatch("goarch", b.GOARCH, other.GOARCH)
	}
	if !sameTargetTags(b.BuildTags, other.BuildTags) {
		return mismatch("build_tags", fmt.Sprint(b.BuildTags), fmt.Sprint(other.BuildTags))
	}
	if b.CGOEnabled != other.CGOEnabled {
		return mismatch("cgo_enabled", fmt.Sprint(b.CGOEnabled), fmt.Sprint(other.CGOEnabled))
	}
	if b.GoVersion != other.GoVersion {
		return mismatch("go_version", b.GoVersion, other.GoVersion)
	}
	if b.GoModDirective != other.GoModDirective {
		return mismatch("go_mod_directive", b.GoModDirective, other.GoModDirective)
	}
	if b.VendorMode != other.VendorMode {
		return mismatch("vendor_mode", fmt.Sprint(b.VendorMode), fmt.Sprint(other.VendorMode))
	}
	if b.GoWorkFile != other.GoWorkFile {
		return mismatch("go_work_file", b.GoWorkFile, other.GoWorkFile)
	}
	if b.GoFlags != other.GoFlags {
		return mismatch("go_flags", b.GoFlags, other.GoFlags)
	}
	if !slices.Equal(b.ReplaceDirectives, other.ReplaceDirectives) {
		return mismatch("replace_directives", fmt.Sprint(b.ReplaceDirectives), fmt.Sprint(other.ReplaceDirectives))
	}
	if b.BinaryPath != other.BinaryPath {
		return mismatch("binary_path", b.BinaryPath, other.BinaryPath)
	}
	if b.BinarySHA256 != other.BinarySHA256 {
		return mismatch("binary_sha256", b.BinarySHA256, other.BinarySHA256)
	}
	return nil
}

// ValidateNegativeTarget checks the first admission gate for a
// build-dependent negative: the snapshot must carry a valid, scoped product
// target whose build facts match the effective snapshot. A host default is
// analysis context, never a product target. It deliberately does not require
// a supported-targets assumption — that stays a separate product-wide
// condition.
func ValidateNegativeTarget(s ProductSnapshot) error {
	if s.Target == nil {
		return errors.New("no product target: build-dependent negatives require recorded target provenance")
	}
	if err := s.Target.Validate(); err != nil {
		return fmt.Errorf("product target: %w", err)
	}
	if !s.Target.Scoped() {
		return fmt.Errorf("product target source %q has no product scope: host defaults cannot ground a build-dependent negative", s.Target.Source)
	}
	mismatch := func(field, target, effective string) error {
		return fmt.Errorf("%w: target %s %q does not match the effective snapshot %q", ErrBuildContextMismatch, field, target, effective)
	}
	if s.Target.GOOS != s.GOOS {
		return mismatch("GOOS", s.Target.GOOS, s.GOOS)
	}
	if s.Target.GOARCH != s.GOARCH {
		return mismatch("GOARCH", s.Target.GOARCH, s.GOARCH)
	}
	if !sameTargetTags(s.Target.BuildTags, s.BuildTags) {
		return fmt.Errorf("%w: target build tags %v do not match the effective snapshot's %v",
			ErrBuildContextMismatch, s.Target.BuildTags, s.BuildTags)
	}
	if s.Target.CGOEnabled != s.CGOEnabled {
		return mismatch("CGO", fmt.Sprint(s.Target.CGOEnabled), fmt.Sprint(s.CGOEnabled))
	}
	return nil
}

// BuildEnv returns the build-selection environment every package load and
// toolchain probe must share: GOOS/GOARCH, CGO_ENABLED, the effective
// workspace mode and the effective GOFLAGS. It is designed to be appended
// AFTER the ambient/isolation whitelist and the toolchain policy env, so
// the snapshot's resolved selection is the last word for these variables.
func BuildEnv(s ProductSnapshot) []string {
	env := make([]string, 0, 5)
	if s.GOOS != "" {
		env = append(env, "GOOS="+s.GOOS)
	}
	if s.GOARCH != "" {
		env = append(env, "GOARCH="+s.GOARCH)
	}
	cgo := "0"
	if s.CGOEnabled {
		cgo = "1"
	}
	env = append(env, "CGO_ENABLED="+cgo)
	if s.GoWorkFile != "" {
		env = append(env, "GOWORK="+s.GoWorkFile)
	}
	flags := s.GoFlags
	if flags == "" && s.VendorMode {
		// A snapshot resolved before GoFlags existed (or a raw index
		// construction) still records its vendor selection honestly.
		flags = "-mod=vendor"
	}
	if flags != "" {
		env = append(env, "GOFLAGS="+flags)
	}
	return env
}

// EffectiveGoFlags composes the GOFLAGS the build will actually use from the
// flags the environment/toolchain policy supplied. The go command applies
// -mod=vendor implicitly when vendor/modules.txt exists and the caller did
// not select a module mode; recording that composed value keeps the snapshot
// and every probe on the same selection.
func EffectiveGoFlags(envFlags string, vendorMode bool) string {
	flags := strings.TrimSpace(envFlags)
	if hasModFlag(flags) {
		return flags
	}
	if vendorMode {
		return strings.TrimSpace(flags + " -mod=vendor")
	}
	return flags
}

// hasModFlag reports whether a GOFLAGS value already selects a module mode.
func hasModFlag(flags string) bool {
	for _, f := range strings.Fields(flags) {
		if f == "-mod" || strings.HasPrefix(f, "-mod=") {
			return true
		}
	}
	return false
}
