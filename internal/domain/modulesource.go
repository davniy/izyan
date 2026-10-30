package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ModuleSourceKind names the recorded-build carrier one selected module's
// source bytes come from. Persisted descriptors use these names, never a host
// filesystem path.
type ModuleSourceKind string

const (
	// ModuleSourceModuleCache is the Go module cache entry for the effective
	// coordinate the build selected.
	ModuleSourceModuleCache ModuleSourceKind = "module-cache"
	// ModuleSourceVendor is the snapshot's own vendor tree. Import paths stay
	// unchanged under a replacement, so the vendored bytes live under the
	// declared module path even when the effective module differs.
	ModuleSourceVendor ModuleSourceKind = "vendor"
	// ModuleSourceLocalReplacement is a replace target inside the captured
	// snapshot tree. It carries no version: its identity is the captured
	// content, not an invented coordinate.
	ModuleSourceLocalReplacement ModuleSourceKind = "local-replacement"
	// ModuleSourceWorkspace is a go.work member inside the captured snapshot
	// tree. Like a local replacement it carries no version.
	ModuleSourceWorkspace ModuleSourceKind = "workspace"
)

// ModuleSourceFailureKind is the typed cause a selected source could not be
// resolved. A failure is an input problem: it must never be answered with
// another module's bytes, and it is never evidence of absence.
type ModuleSourceFailureKind string

const (
	// ModuleSourceUnavailable: the recorded build's selected source root does
	// not exist (a missing module-cache entry, vendored directory or local
	// replacement directory).
	ModuleSourceUnavailable ModuleSourceFailureKind = "SOURCE_UNAVAILABLE"
	// ModuleSourceUnconfined: the replacement or workspace target resolves
	// outside the captured snapshot tree. Reading a host path is not allowed,
	// so the source is unmeasured rather than substituted.
	ModuleSourceUnconfined ModuleSourceFailureKind = "REPLACEMENT_UNCONFINED"
	// ModuleSourceContradiction: the recorded build's replacement evidence
	// disagrees with the selection the affected chain recorded (for example a
	// release module graph replacing a module the source build does not).
	ModuleSourceContradiction ModuleSourceFailureKind = "SELECTION_CONTRADICTION"
	// ModuleSourceAmbiguous: the record carrier declares more than one identity
	// for the same module path, so no single source is selected.
	ModuleSourceAmbiguous ModuleSourceFailureKind = "SELECTION_AMBIGUOUS"
	// ModuleSourceUnreadable: the replacement or workspace evidence exists but
	// cannot be decoded, so the selection cannot be established.
	ModuleSourceUnreadable ModuleSourceFailureKind = "SELECTION_UNREADABLE"
	// ModuleSourceStale: a previously recorded descriptor no longer matches the
	// bytes the recorded build selects (a mutated or replaced source root).
	ModuleSourceStale ModuleSourceFailureKind = "SOURCE_STALE"
)

// ModuleSourceError is the typed input failure raised when the recorded
// build's effective source cannot be resolved. Callers test it with errors.As
// and must record the cause instead of falling back to the declared module.
type ModuleSourceError struct {
	Kind            ModuleSourceFailureKind
	DeclaredModule  string
	DeclaredVersion string
	Detail          string
}

func (e *ModuleSourceError) Error() string {
	if e == nil {
		return "effective module source: unresolved"
	}
	subject := e.DeclaredModule
	if e.DeclaredVersion != "" {
		subject += "@" + e.DeclaredVersion
	}
	if subject == "" {
		subject = "module"
	}
	return fmt.Sprintf("effective module source for %s: %s: %s", subject, e.Kind, e.Detail)
}

// Failure projects the error onto its persistable form.
func (e *ModuleSourceError) Failure() *ModuleSourceFailure {
	if e == nil {
		return nil
	}
	return &ModuleSourceFailure{Kind: e.Kind, Detail: e.Detail}
}

// NewModuleSourceError builds one typed input failure.
func NewModuleSourceError(kind ModuleSourceFailureKind, module, version, format string, args ...any) *ModuleSourceError {
	return &ModuleSourceError{
		Kind:            kind,
		DeclaredModule:  module,
		DeclaredVersion: version,
		Detail:          fmt.Sprintf(format, args...),
	}
}

// IsModuleSourceFailure reports whether err is a typed effective-source failure
// of the given kind.
func IsModuleSourceFailure(err error, kind ModuleSourceFailureKind) bool {
	var target *ModuleSourceError
	return errors.As(err, &target) && target.Kind == kind
}

// ModuleSourceFailureOf projects a source-resolution error onto its persistable
// failure record. An untyped error is still recorded — as an unreadable
// selection — rather than dropped into an unexplained missing source.
func ModuleSourceFailureOf(err error) *ModuleSourceFailure {
	if err == nil {
		return nil
	}
	var typed *ModuleSourceError
	if errors.As(err, &typed) {
		return typed.Failure()
	}
	return &ModuleSourceFailure{Kind: ModuleSourceUnreadable, Detail: err.Error()}
}

// ModuleSourceFailure is the persisted form of a typed source failure. It
// records why no source root is attached; consumers must treat the selection
// as unmeasured and may not resolve the declared module instead.
type ModuleSourceFailure struct {
	Kind   ModuleSourceFailureKind `json:"kind"`
	Detail string                  `json:"detail"`
}

// WorkspaceSelection records that the recorded build selects this module from
// a Go workspace member rather than from a published coordinate. Directory is
// relative to the captured snapshot root: a workspace member outside that tree
// is refused, never persisted as a host path.
type WorkspaceSelection struct {
	Module    string `json:"module"`
	Directory string `json:"directory"`
}

// LocalReplacementSelection is the identity of a local replacement target.
// It carries no version by design: the captured content is the identity.
type LocalReplacementSelection struct {
	Module    string `json:"module"`
	Directory string `json:"directory"`
}

// EffectiveSourceSelection is the persisted identity of the source the
// recorded build actually selected for one advisory entry.
//
// It separates the advisory's declared coordinate from the effective one so a
// consumer can re-derive which implementation ships without ever substituting
// the published original for a replacement. The descriptor is deliberately
// path-free: SourceRoot names the carrier in a stable, machine-independent form
// (a module-cache coordinate, a snapshot-relative vendor/local/workspace
// directory).
type EffectiveSourceSelection struct {
	// EntryRef is the index of the original advisory affected[] entry this
	// selection was resolved for.
	EntryRef int `json:"entry_ref"`
	// DeclaredModule / DeclaredVersion are the coordinates the record's entry
	// was resolved against in the build graph (the require/header version, not
	// a version range).
	DeclaredModule  string `json:"declared_module"`
	DeclaredVersion string `json:"declared_version,omitempty"`
	// EffectiveModule / EffectiveVersion are the coordinates whose bytes the
	// build selects. EffectiveVersion is empty for a local replacement or a
	// workspace module: those are identified by content, not by a version.
	EffectiveModule  string `json:"effective_module,omitempty"`
	EffectiveVersion string `json:"effective_version,omitempty"`
	// Replacements records the replace directives that applied to this
	// selection in the recorded build's own directive form. A local target is
	// normalised to its snapshot-relative identity, never a host path.
	Replacements []ReplaceDirective `json:"replacements,omitempty"`
	// Workspace records the go.work membership that selected the module.
	Workspace *WorkspaceSelection `json:"workspace,omitempty"`
	// LocalReplacement records a replace target inside the snapshot tree.
	LocalReplacement *LocalReplacementSelection `json:"local_replacement,omitempty"`
	// SourceKind and SourceRoot name the carrier actually selected. Empty
	// SourceKind means no source was resolved, never "the original module".
	SourceKind ModuleSourceKind `json:"source_kind,omitempty"`
	SourceRoot string           `json:"source_root,omitempty"`
	// ContentDigest pins the captured bytes of a local replacement or
	// workspace module. It is the identity of a versionless source and makes a
	// mutated source root detectable.
	ContentDigest string `json:"content_digest,omitempty"`
	// Failure records a typed reason no source root is attached. It is never a
	// permission to read the declared module's published bytes instead.
	Failure *ModuleSourceFailure `json:"failure,omitempty"`
}

// ResolvedModuleSource is one resolved effective source: the persistable
// selection plus the analysis-local directory its bytes were read from. Dir is
// never persisted.
type ResolvedModuleSource struct {
	Selection EffectiveSourceSelection
	Dir       string `json:"-"`
}

// Label renders the resolved carrier for evidence and limitation text.
func (r ResolvedModuleSource) Label() string {
	sel := r.Selection
	switch sel.SourceKind {
	case ModuleSourceModuleCache:
		return fmt.Sprintf("%s@%s (%s source)", sel.EffectiveModule, sel.EffectiveVersion, sel.SourceKind)
	case ModuleSourceVendor, ModuleSourceLocalReplacement, ModuleSourceWorkspace:
		return fmt.Sprintf("%s (%s source at %s)", sel.DeclaredModule, sel.SourceKind, sel.SourceRoot)
	default:
		if sel.EffectiveVersion != "" {
			return fmt.Sprintf("%s@%s", sel.DeclaredModule, sel.EffectiveVersion)
		}
		return sel.DeclaredModule
	}
}

// Validate enforces the structural identity of one persisted descriptor. A
// failed selection carries no source; a resolved one names a stable,
// snapshot-relative or coordinate-derived root and never a host path.
func (s EffectiveSourceSelection) Validate() error {
	if s.EntryRef < 0 {
		return fmt.Errorf("effective source: entry ref %d is negative", s.EntryRef)
	}
	if strings.TrimSpace(s.DeclaredModule) == "" {
		return fmt.Errorf("effective source: entry %d carries no declared module", s.EntryRef)
	}
	if s.LocalReplacement != nil && s.EffectiveVersion != "" {
		return fmt.Errorf("effective source for %s: a local replacement carries no invented version (got %q)",
			s.DeclaredModule, s.EffectiveVersion)
	}
	if s.Failure != nil {
		if s.SourceKind != "" || s.SourceRoot != "" {
			return fmt.Errorf("effective source for %s: a failed selection carries no source (kind %q root %q)",
				s.DeclaredModule, s.SourceKind, s.SourceRoot)
		}
		return validateFailure(s)
	}
	switch s.SourceKind {
	case "":
		// No source was resolved (no source resolver configured). Declared and
		// effective coordinates may still be recorded.
		if s.SourceRoot != "" {
			return fmt.Errorf("effective source for %s: a source root requires a source kind", s.DeclaredModule)
		}
	case ModuleSourceModuleCache:
		if strings.TrimSpace(s.EffectiveModule) == "" || strings.TrimSpace(s.EffectiveVersion) == "" {
			return fmt.Errorf("effective source for %s: a module-cache source requires an effective coordinate", s.DeclaredModule)
		}
		if s.SourceRoot != s.EffectiveModule+"@"+s.EffectiveVersion {
			return fmt.Errorf("effective source for %s: module-cache root %q does not name %s@%s",
				s.DeclaredModule, s.SourceRoot, s.EffectiveModule, s.EffectiveVersion)
		}
	case ModuleSourceVendor, ModuleSourceLocalReplacement, ModuleSourceWorkspace:
		if strings.TrimSpace(s.SourceRoot) == "" {
			return fmt.Errorf("effective source for %s: %s source carries no root", s.DeclaredModule, s.SourceKind)
		}
		if !stableModuleRoot(s.SourceRoot) {
			return fmt.Errorf("effective source for %s: root %q is a host path, not a stable descriptor",
				s.DeclaredModule, s.SourceRoot)
		}
		if s.Workspace != nil && !stableModuleRoot(s.Workspace.Directory) {
			return fmt.Errorf("effective source for %s: workspace directory %q is a host path, not a stable descriptor",
				s.DeclaredModule, s.Workspace.Directory)
		}
		if s.LocalReplacement != nil && !stableModuleRoot(s.LocalReplacement.Directory) {
			return fmt.Errorf("effective source for %s: replacement directory %q is a host path, not a stable descriptor",
				s.DeclaredModule, s.LocalReplacement.Directory)
		}
		if s.SourceKind == ModuleSourceLocalReplacement && s.LocalReplacement == nil {
			return fmt.Errorf("effective source for %s: a local-replacement source requires its replacement identity", s.DeclaredModule)
		}
		if s.SourceKind == ModuleSourceWorkspace && s.Workspace == nil {
			return fmt.Errorf("effective source for %s: a workspace source requires its workspace membership", s.DeclaredModule)
		}
	default:
		return fmt.Errorf("effective source for %s: unknown source kind %q", s.DeclaredModule, s.SourceKind)
	}
	return nil
}

// stableModuleRoot reports whether a persisted root is a machine-independent
// descriptor: a module-cache coordinate or a snapshot-relative directory. An
// absolute path, a drive-qualified path or a parent traversal is a host path.
func stableModuleRoot(root string) bool {
	root = strings.TrimSpace(root)
	if root == "" || strings.HasPrefix(root, "/") || strings.Contains(root, ":") {
		return false
	}
	if root == ".." || strings.HasPrefix(root, "../") || strings.Contains(root, "/../") ||
		strings.HasPrefix(root, "./../") || strings.Contains(root, "\\") {
		return false
	}
	return true
}

func validateFailure(s EffectiveSourceSelection) error {
	switch s.Failure.Kind {
	case ModuleSourceUnavailable, ModuleSourceUnconfined, ModuleSourceContradiction,
		ModuleSourceAmbiguous, ModuleSourceUnreadable, ModuleSourceStale:
	default:
		return fmt.Errorf("effective source for %s: unknown failure kind %q", s.DeclaredModule, s.Failure.Kind)
	}
	if strings.TrimSpace(s.Failure.Detail) == "" {
		return fmt.Errorf("effective source for %s: failure %q carries no detail", s.DeclaredModule, s.Failure.Kind)
	}
	return nil
}

// AdvisoryRecordCapture pins the complete advisory bytes one record-level
// assessment was derived from. The pin alone says which document; the bytes
// let a future checker re-derive its inputs from the persisted case without a
// live record lookup.
type AdvisoryRecordCapture struct {
	Pin   RecordPin `json:"pin"`
	Bytes []byte    `json:"bytes"`
}

// Validate re-checks the capture against its own pin: the bytes must hash to
// the pinned digest, so a persisted capture cannot silently describe a
// different document.
func (c AdvisoryRecordCapture) Validate() error {
	if err := c.Pin.Validate(); err != nil {
		return fmt.Errorf("advisory record capture: %w", err)
	}
	if len(c.Bytes) == 0 {
		return fmt.Errorf("advisory record capture for %q: no document bytes captured", c.Pin.RecordID)
	}
	sum := sha256.Sum256(c.Bytes)
	digest := recordDigestPrefix + hex.EncodeToString(sum[:])
	if digest != c.Pin.DocumentDigest {
		return fmt.Errorf("advisory record capture for %q: captured bytes hash to %s but the pin records %s",
			c.Pin.RecordID, digest, c.Pin.DocumentDigest)
	}
	return nil
}
