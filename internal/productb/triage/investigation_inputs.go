package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/productb/vulnerability"
)

// InvestigationInputsSchemaVersion identifies the strict captured-input
// manifest (investigation-inputs.v1) and its metadata projection artifact.
const InvestigationInputsSchemaVersion = "investigation-inputs.v1"

// investigationArchiveDir is the run-relative directory holding complete
// captured material bytes, addressed by their SHA-256.
const investigationArchiveDir = "materials"

// Bounds: the manifest itself and one captured material file are read into
// memory before they reach the agent, so both carry an explicit ceiling.
// The archive preserves the complete bytes; read_material slices them.
const (
	maxInvestigationManifestBytes int64 = 4 << 20
	maxInvestigationMaterialBytes int64 = 32 << 20
	defaultReadMaterialBytes      int64 = 32 << 10
	maxReadMaterialBytes          int64 = 64 << 10
)

// Captured material kinds.
const (
	CapturedMaterialRecord = "advisory_record"
	CapturedMaterialFix    = "fix"
)

// CapturedFixOutcome is the deterministic acquisition result of one exact
// fix locator. A missing or unavailable fix is a recorded limitation of the
// human investigation, never a technical failure and never an invented
// document.
type CapturedFixOutcome string

const (
	CapturedFixCaptured    CapturedFixOutcome = "captured"
	CapturedFixMissing     CapturedFixOutcome = "missing"
	CapturedFixUnavailable CapturedFixOutcome = "unavailable"
)

// CapturedRecord is one supplied advisory record: its canonical identity,
// explicit aliases, the verbatim document bytes, the digest that binds them
// and the provenance the manifest declared. Raw is deliberately excluded
// from JSON artifacts — the complete bytes live in the digest-addressed
// archive and metadata travels separately.
type CapturedRecord struct {
	RecordID string   `json:"record_id"`
	Aliases  []string `json:"aliases,omitempty"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
	Source   string   `json:"source,omitempty"`
	Partial  bool     `json:"partial,omitempty"`
	Raw      []byte   `json:"-"`
}

// CapturedFix is one fix locator belonging to exactly one captured record.
// The owning record digest is part of the fix identity, so a fix can never
// be rebound to a different advisory. Missing/unavailable outcomes carry no
// bytes and no digest.
type CapturedFix struct {
	RecordID     string             `json:"record_id"`
	RecordSHA256 string             `json:"record_sha256"`
	Locator      string             `json:"locator"`
	Outcome      CapturedFixOutcome `json:"outcome"`
	SHA256       string             `json:"sha256,omitempty"`
	Size         int64              `json:"size,omitempty"`
	Source       string             `json:"source,omitempty"`
	Raw          []byte             `json:"-"`
}

// InvestigationInputs is the complete captured material set an operator
// supplied for one investigation: every advisory record and fix the agent
// may read, plus the optional build input Task 2 resolves. The set is data,
// never instructions; aliases resolve only inside it.
type InvestigationInputs struct {
	Records []CapturedRecord `json:"records,omitempty"`
	Fixes   []CapturedFix    `json:"fixes,omitempty"`
	// Build is the optional operator-supplied build input retained
	// verbatim. ResolveBuildTarget admits it; it is never promoted to a
	// fact here.
	Build json.RawMessage `json:"build,omitempty"`
	// BuildTarget is the one resolved product build selection this set
	// describes. It is derived from Build and/or the finding's
	// target.build, then carried unchanged through every attempt and
	// replay; nil means no product build was identified.
	BuildTarget *domain.ProductTarget `json:"build_target,omitempty"`
}

// Empty reports whether no captured material, build input or resolved build
// target is present.
func (in InvestigationInputs) Empty() bool {
	return len(in.Records) == 0 && len(in.Fixes) == 0 && len(in.Build) == 0 && in.BuildTarget == nil
}

// CapturedRecordMaterialID is the stable material_id of one captured
// record.
func CapturedRecordMaterialID(recordID string) string {
	return "record:" + canonicalVulnID(recordID)
}

// CapturedFixMaterialID is the stable material_id of one captured fix.
func CapturedFixMaterialID(recordID, locator string) string {
	return "fix:" + canonicalVulnID(recordID) + ":" + locator
}

// MaterialID returns the record's stable material id.
func (r CapturedRecord) MaterialID() string { return CapturedRecordMaterialID(r.RecordID) }

// MaterialID returns the fix's stable material id.
func (f CapturedFix) MaterialID() string { return CapturedFixMaterialID(f.RecordID, f.Locator) }

// CapturedMaterial is the agent-facing metadata of one captured material.
// It carries identity, digest, provenance and archive location only; the
// bytes are read through read_material.
type CapturedMaterial struct {
	MaterialID   string             `json:"material_id"`
	Kind         string             `json:"kind"`
	RecordID     string             `json:"record_id"`
	RecordSHA256 string             `json:"record_sha256,omitempty"`
	Aliases      []string           `json:"aliases,omitempty"`
	Locator      string             `json:"locator,omitempty"`
	Outcome      CapturedFixOutcome `json:"outcome,omitempty"`
	SHA256       string             `json:"sha256,omitempty"`
	Size         int64              `json:"size,omitempty"`
	Source       string             `json:"source,omitempty"`
	Partial      bool               `json:"partial,omitempty"`
	ArchivePath  string             `json:"archive_path,omitempty"`
}

// Materials lists the captured material metadata in deterministic order:
// records as declared, then fixes as declared.
func (in InvestigationInputs) Materials() []CapturedMaterial {
	out := make([]CapturedMaterial, 0, len(in.Records)+len(in.Fixes))
	for _, r := range in.Records {
		out = append(out, CapturedMaterial{
			MaterialID: r.MaterialID(), Kind: CapturedMaterialRecord,
			RecordID: r.RecordID, Aliases: append([]string(nil), r.Aliases...),
			SHA256: r.SHA256, Size: r.Size, Source: r.Source, Partial: r.Partial,
			ArchivePath: investigationArchivePath(r.SHA256),
		})
	}
	for _, f := range in.Fixes {
		m := CapturedMaterial{
			MaterialID: f.MaterialID(), Kind: CapturedMaterialFix,
			RecordID: f.RecordID, RecordSHA256: f.RecordSHA256, Locator: f.Locator, Outcome: f.Outcome,
			SHA256: f.SHA256, Size: f.Size, Source: f.Source,
		}
		if f.Outcome == CapturedFixCaptured {
			m.ArchivePath = investigationArchivePath(f.SHA256)
		}
		out = append(out, m)
	}
	return out
}

// FindRecord resolves a record by its canonical id or one of its explicit
// aliases. Aliases never resolve to a different captured record.
func (in InvestigationInputs) FindRecord(id string) (CapturedRecord, bool) {
	want := canonicalVulnID(id)
	if want == "" {
		return CapturedRecord{}, false
	}
	for _, r := range in.Records {
		if r.RecordID == want {
			return r, true
		}
		for _, a := range r.Aliases {
			if a == want {
				return r, true
			}
		}
	}
	return CapturedRecord{}, false
}

// FindFix resolves a fix by its owning record and exact locator.
func (in InvestigationInputs) FindFix(recordID, locator string) (CapturedFix, bool) {
	rec, ok := in.FindRecord(recordID)
	if !ok {
		return CapturedFix{}, false
	}
	for _, f := range in.Fixes {
		if f.RecordID == rec.RecordID && f.Locator == locator {
			return f, true
		}
	}
	return CapturedFix{}, false
}

// ResolveMaterial resolves one material_id to its metadata and complete
// bytes. A record id or alias and an exact fix locator are accepted as
// convenience spellings; everything else misses — no network fallback.
func (in InvestigationInputs) ResolveMaterial(materialID string) (CapturedMaterial, []byte, bool) {
	want := strings.TrimSpace(materialID)
	if want == "" {
		return CapturedMaterial{}, nil, false
	}
	for _, m := range in.Materials() {
		if m.MaterialID != want {
			continue
		}
		return m, in.rawForMaterial(m), true
	}
	if rec, ok := in.FindRecord(want); ok {
		m := CapturedMaterial{MaterialID: rec.MaterialID(), Kind: CapturedMaterialRecord,
			RecordID: rec.RecordID, Aliases: append([]string(nil), rec.Aliases...),
			SHA256: rec.SHA256, Size: rec.Size, Source: rec.Source, Partial: rec.Partial,
			ArchivePath: investigationArchivePath(rec.SHA256)}
		return m, rec.Raw, true
	}
	var matched *CapturedFix
	for i := range in.Fixes {
		if in.Fixes[i].Locator != want {
			continue
		}
		if matched != nil {
			// A bare locator shared by two records is ambiguous; the
			// agent must name the owning record's material_id.
			return CapturedMaterial{}, nil, false
		}
		matched = &in.Fixes[i]
	}
	if matched != nil {
		f := *matched
		m := CapturedMaterial{MaterialID: f.MaterialID(), Kind: CapturedMaterialFix,
			RecordID: f.RecordID, RecordSHA256: f.RecordSHA256, Locator: f.Locator, Outcome: f.Outcome,
			SHA256: f.SHA256, Size: f.Size, Source: f.Source}
		if f.Outcome == CapturedFixCaptured {
			m.ArchivePath = investigationArchivePath(f.SHA256)
		}
		return m, f.Raw, true
	}
	return CapturedMaterial{}, nil, false
}

func (in InvestigationInputs) fixOwnerDigest(recordID string) string {
	if rec, ok := in.FindRecord(recordID); ok {
		return rec.SHA256
	}
	return ""
}

func (in InvestigationInputs) rawForMaterial(m CapturedMaterial) []byte {
	switch m.Kind {
	case CapturedMaterialRecord:
		if rec, ok := in.FindRecord(m.RecordID); ok {
			return rec.Raw
		}
	case CapturedMaterialFix:
		if f, ok := in.FindFix(m.RecordID, m.Locator); ok {
			return f.Raw
		}
	}
	return nil
}

// Projection returns the metadata-only form persisted as
// investigation-inputs.json. Raw bytes never enter the projection.
func (in InvestigationInputs) Projection() InvestigationProjection {
	proj := InvestigationProjection{
		SchemaVersion: InvestigationInputsSchemaVersion,
		Build:         append(json.RawMessage(nil), in.Build...),
		BuildTarget:   cloneBuildTarget(in.BuildTarget),
	}
	for _, m := range in.Materials() {
		if m.Kind == CapturedMaterialRecord {
			proj.Records = append(proj.Records, CapturedRecordProjection{
				RecordID: m.RecordID, Aliases: append([]string(nil), m.Aliases...),
				SHA256: m.SHA256, Size: m.Size, Source: m.Source, Partial: m.Partial,
				ArchivePath: m.ArchivePath,
			})
			continue
		}
		proj.Fixes = append(proj.Fixes, CapturedFixProjection{
			RecordID: m.RecordID, RecordSHA256: in.fixOwnerDigest(m.RecordID), Locator: m.Locator, Outcome: m.Outcome,
			SHA256: m.SHA256, Size: m.Size, Source: m.Source, ArchivePath: m.ArchivePath,
		})
	}
	return proj
}

// InvestigationProjection is the persisted metadata view of a captured
// set. ArchivePath is run-relative and always digest-addressed.
type InvestigationProjection struct {
	SchemaVersion string                     `json:"schema_version"`
	Records       []CapturedRecordProjection `json:"records,omitempty"`
	Fixes         []CapturedFixProjection    `json:"fixes,omitempty"`
	Build         json.RawMessage            `json:"build,omitempty"`
	// BuildTarget is the resolved product build the run used; replay
	// re-derives it from Build/finding inputs and fails closed on drift.
	BuildTarget *domain.ProductTarget `json:"build_target,omitempty"`
}

type CapturedRecordProjection struct {
	RecordID    string   `json:"record_id"`
	Aliases     []string `json:"aliases,omitempty"`
	SHA256      string   `json:"sha256"`
	Size        int64    `json:"size"`
	Source      string   `json:"source,omitempty"`
	Partial     bool     `json:"partial,omitempty"`
	ArchivePath string   `json:"archive_path,omitempty"`
}

type CapturedFixProjection struct {
	RecordID     string             `json:"record_id"`
	RecordSHA256 string             `json:"record_sha256"`
	Locator      string             `json:"locator"`
	Outcome      CapturedFixOutcome `json:"outcome"`
	SHA256       string             `json:"sha256,omitempty"`
	Size         int64              `json:"size,omitempty"`
	Source       string             `json:"source,omitempty"`
	ArchivePath  string             `json:"archive_path,omitempty"`
}

// Empty reports whether the projection carries no captured material, build
// input or resolved build target.
func (p InvestigationProjection) Empty() bool {
	return len(p.Records) == 0 && len(p.Fixes) == 0 && len(p.Build) == 0 && p.BuildTarget == nil
}

// Inputs rebuilds the metadata-only captured set from a persisted
// projection. Raw bytes are absent; decision-scope derivation and archive
// verification only need identity, digest and provenance.
func (p InvestigationProjection) Inputs() (InvestigationInputs, error) {
	if p.SchemaVersion != InvestigationInputsSchemaVersion {
		return InvestigationInputs{}, fmt.Errorf("investigation inputs projection schema %q is not %s", p.SchemaVersion, InvestigationInputsSchemaVersion)
	}
	in := InvestigationInputs{
		Build:       append(json.RawMessage(nil), p.Build...),
		BuildTarget: cloneBuildTarget(p.BuildTarget),
	}
	for _, r := range p.Records {
		in.Records = append(in.Records, CapturedRecord{
			RecordID: r.RecordID, Aliases: append([]string(nil), r.Aliases...),
			SHA256: r.SHA256, Size: r.Size, Source: r.Source, Partial: r.Partial,
		})
	}
	for _, f := range p.Fixes {
		in.Fixes = append(in.Fixes, CapturedFix{
			RecordID: f.RecordID, RecordSHA256: f.RecordSHA256, Locator: f.Locator, Outcome: f.Outcome,
			SHA256: f.SHA256, Size: f.Size, Source: f.Source,
		})
	}
	if err := in.Validate(); err != nil {
		return InvestigationInputs{}, err
	}
	return in, nil
}

// Validate checks the captured-set contract: canonical unique identities,
// declared digests and sizes, complete captured bytes when they are present,
// fix ownership by a declared record digest and explicit fix outcomes. A
// metadata-only set (rebuilt from a persisted projection) validates the same
// identity/ownership rules; it never invents bytes.
func (in InvestigationInputs) Validate() error {
	if len(in.Build) > 0 {
		trimmed := bytes.TrimSpace(in.Build)
		if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
			return errors.New("investigation inputs: build input must be a JSON object")
		}
	}
	if in.BuildTarget != nil {
		if err := in.BuildTarget.Validate(); err != nil {
			return fmt.Errorf("investigation inputs: build target: %w", err)
		}
		if !in.BuildTarget.Scoped() {
			return fmt.Errorf("investigation inputs: build target source %q is analysis context, not a product build", in.BuildTarget.Source)
		}
	}
	identity := map[string]CapturedRecord{}
	byID := map[string]CapturedRecord{}
	for i, rec := range in.Records {
		id := canonicalVulnID(rec.RecordID)
		if err := validateCapturedIdentity("record_id", id); err != nil {
			return fmt.Errorf("investigation inputs: record %d: %w", i, err)
		}
		sha, err := normalizedDigest(rec.SHA256)
		if err != nil {
			return fmt.Errorf("investigation inputs: record %d: %w", i, err)
		}
		if len(rec.Raw) > 0 {
			if rec.Size != 0 && rec.Size != int64(len(rec.Raw)) {
				return fmt.Errorf("investigation inputs: record %q size %d does not match captured bytes %d", id, rec.Size, len(rec.Raw))
			}
			if got := hashBytes(rec.Raw); got != sha {
				return fmt.Errorf("investigation inputs: record %q digest %s does not match captured bytes %s", id, sha, got)
			}
		} else if rec.Size < 0 {
			return fmt.Errorf("investigation inputs: record %q size %d is negative", id, rec.Size)
		}
		norm := CapturedRecord{RecordID: id, SHA256: sha, Size: rec.Size, Source: rec.Source, Partial: rec.Partial, Raw: rec.Raw}
		seenAliases := map[string]bool{id: true}
		for _, raw := range rec.Aliases {
			alias := canonicalVulnID(raw)
			if err := validateCapturedIdentity("alias", alias); err != nil {
				return fmt.Errorf("investigation inputs: record %q: %w", id, err)
			}
			if seenAliases[alias] {
				return fmt.Errorf("investigation inputs: record %q declares duplicate identity %q", id, alias)
			}
			seenAliases[alias] = true
			norm.Aliases = append(norm.Aliases, alias)
		}
		for _, identityID := range append([]string{id}, norm.Aliases...) {
			if prior, ok := identity[identityID]; ok {
				return fmt.Errorf("investigation inputs: duplicate identity %q is declared by records %q and %q (digests %s and %s)", identityID, prior.RecordID, norm.RecordID, prior.SHA256, norm.SHA256)
			}
			identity[identityID] = norm
		}
		if prior, ok := byID[id]; ok {
			return fmt.Errorf("investigation inputs: record %q is declared twice (digests %s and %s)", id, prior.SHA256, sha)
		}
		byID[id] = norm
	}
	fixIdentity := map[string]bool{}
	for i, fix := range in.Fixes {
		id := canonicalVulnID(fix.RecordID)
		if err := validateCapturedIdentity("fix record_id", id); err != nil {
			return fmt.Errorf("investigation inputs: fix %d: %w", i, err)
		}
		if strings.TrimSpace(fix.Locator) == "" {
			return fmt.Errorf("investigation inputs: fix %d: locator is required", i)
		}
		if strings.ContainsAny(fix.Locator, "\r\n\x00") {
			return fmt.Errorf("investigation inputs: fix %d: locator contains control characters", i)
		}
		outcome, err := parseCapturedFixOutcome(string(fix.Outcome))
		if err != nil {
			return fmt.Errorf("investigation inputs: fix %d: %w", i, err)
		}
		owner, ok := byID[id]
		if !ok {
			return fmt.Errorf("investigation inputs: fix %d names undeclared owning record %q", i, id)
		}
		ownerSHA, err := normalizedDigest(fix.RecordSHA256)
		if err != nil {
			return fmt.Errorf("investigation inputs: fix %d: owning record digest: %w", i, err)
		}
		if owner.SHA256 != ownerSHA {
			return fmt.Errorf("investigation inputs: fix %d declares owning record digest %s but record %q has digest %s", i, ownerSHA, id, owner.SHA256)
		}
		switch outcome {
		case CapturedFixCaptured:
			sha, derr := normalizedDigest(fix.SHA256)
			if derr != nil {
				return fmt.Errorf("investigation inputs: fix %d: %w", i, derr)
			}
			if len(fix.Raw) > 0 {
				if got := hashBytes(fix.Raw); got != sha {
					return fmt.Errorf("investigation inputs: fix %q digest %s does not match captured bytes %s", fix.Locator, sha, got)
				}
				if fix.Size != 0 && fix.Size != int64(len(fix.Raw)) {
					return fmt.Errorf("investigation inputs: fix %q size %d does not match captured bytes %d", fix.Locator, fix.Size, len(fix.Raw))
				}
			}
		default:
			if len(fix.Raw) != 0 || strings.TrimSpace(fix.SHA256) != "" {
				return fmt.Errorf("investigation inputs: fix %q with outcome %s must not carry bytes or a digest", fix.Locator, outcome)
			}
		}
		key := id + "\x00" + fix.Locator
		if fixIdentity[key] {
			return fmt.Errorf("investigation inputs: fix locator %q is declared twice for record %q", fix.Locator, id)
		}
		fixIdentity[key] = true
	}
	return nil
}

// WithRecord returns the set extended by one captured record. Re-declaring
// the same identity with the same digest is a no-op (aliases merge);
// conflicting identities fail closed so a foreign document can never
// shadow the selected one.
func (in InvestigationInputs) WithRecord(rec CapturedRecord) (InvestigationInputs, error) {
	norm, err := normalizeCapturedRecord(rec)
	if err != nil {
		return in, err
	}
	out := InvestigationInputs{
		Records:     append([]CapturedRecord(nil), in.Records...),
		Fixes:       append([]CapturedFix(nil), in.Fixes...),
		Build:       append(json.RawMessage(nil), in.Build...),
		BuildTarget: cloneBuildTarget(in.BuildTarget),
	}
	ids := append([]string{norm.RecordID}, norm.Aliases...)
	for _, existing := range out.Records {
		if existing.RecordID == norm.RecordID {
			if existing.SHA256 != norm.SHA256 {
				return in, fmt.Errorf("investigation inputs: record %q already captured with digest %s; refusing different bytes %s", norm.RecordID, existing.SHA256, norm.SHA256)
			}
			merged := existing
			for _, id := range norm.Aliases {
				if !containsString(merged.Aliases, id) && id != merged.RecordID {
					merged.Aliases = append(merged.Aliases, id)
				}
			}
			out.Records = replaceRecord(out.Records, merged)
			return out, out.Validate()
		}
		for _, id := range ids {
			if existing.RecordID == id || containsString(existing.Aliases, id) {
				return in, fmt.Errorf("investigation inputs: identity %q already belongs to record %q with digest %s", id, existing.RecordID, existing.SHA256)
			}
		}
	}
	out.Records = append(out.Records, norm)
	if err := out.Validate(); err != nil {
		return in, err
	}
	return out, nil
}

func replaceRecord(records []CapturedRecord, rec CapturedRecord) []CapturedRecord {
	out := append([]CapturedRecord(nil), records...)
	for i := range out {
		if out[i].RecordID == rec.RecordID {
			out[i] = rec
			return out
		}
	}
	return append(out, rec)
}

// CapturedRecordFromFrozen projects a Stage 0 frozen advisory document into
// a captured record. The complete bytes are required and must reproduce the
// frozen digest exactly; a mismatch is drift, never a different advisory.
func CapturedRecordFromFrozen(rec vulnerability.FrozenAdvisory, raw []byte) (CapturedRecord, error) {
	id := firstNonEmpty(strings.TrimSpace(rec.ResolvedID), strings.TrimSpace(rec.ID))
	if id == "" {
		return CapturedRecord{}, errors.New("investigation inputs: frozen advisory has no identity")
	}
	if strings.TrimSpace(rec.SHA256) == "" {
		return CapturedRecord{}, fmt.Errorf("investigation inputs: frozen advisory %q carries no digest", id)
	}
	if len(raw) == 0 {
		return CapturedRecord{}, fmt.Errorf("investigation inputs: frozen advisory %q carries no bytes", id)
	}
	if rec.Size > 0 && int64(len(raw)) != rec.Size {
		return CapturedRecord{}, fmt.Errorf("investigation inputs: frozen advisory %q size %d does not match recorded size %d", id, len(raw), rec.Size)
	}
	if got := hashBytes(raw); !strings.EqualFold(got, rec.SHA256) {
		return CapturedRecord{}, fmt.Errorf("investigation inputs: frozen advisory %q digest %s does not match recorded digest %s", id, got, rec.SHA256)
	}
	source := "stage0"
	if rec.Source != "" {
		source = "stage0:" + string(rec.Source)
	}
	return normalizeCapturedRecord(CapturedRecord{
		RecordID: id, SHA256: rec.SHA256, Size: int64(len(raw)),
		Source: source, Partial: rec.Partial, Raw: append([]byte(nil), raw...),
	})
}

// LoadInvestigationInputs reads and strictly validates an
// investigation-inputs.v1 manifest. Referenced files resolve relative to
// the manifest directory; absolute paths, traversal and symlink escapes are
// rejected, and every declared digest and size is checked against the bytes.
func LoadInvestigationInputs(path string) (InvestigationInputs, error) {
	var out InvestigationInputs
	manifestPath := strings.TrimSpace(path)
	if manifestPath == "" {
		return out, errors.New("investigation inputs: manifest path is empty")
	}
	abs, err := filepath.Abs(manifestPath)
	if err != nil {
		return out, fmt.Errorf("investigation inputs: resolve manifest path: %w", err)
	}
	base := filepath.Dir(abs)
	baseReal, err := filepath.EvalSymlinks(base)
	if err != nil {
		return out, fmt.Errorf("investigation inputs: resolve manifest directory: %w", err)
	}
	data, err := readFileCapped(abs, maxInvestigationManifestBytes)
	if err != nil {
		return out, fmt.Errorf("investigation inputs: read manifest: %w", err)
	}
	var manifest investigationManifest
	if err := decodeStrictJSON(data, &manifest); err != nil {
		return out, fmt.Errorf("investigation inputs: manifest: %w", err)
	}
	if manifest.SchemaVersion != InvestigationInputsSchemaVersion {
		return out, fmt.Errorf("investigation inputs: manifest schema %q is not %s", manifest.SchemaVersion, InvestigationInputsSchemaVersion)
	}
	out.Build = append(json.RawMessage(nil), manifest.Build...)
	for i, mr := range manifest.Records {
		ref, err := resolveContainedFile(baseReal, mr.Path)
		if err != nil {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: record %d: %w", i, err)
		}
		raw, err := readFileCapped(ref, maxInvestigationMaterialBytes)
		if err != nil {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: record %d: %w", i, err)
		}
		sha, err := normalizedDigest(mr.SHA256)
		if err != nil {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: record %d: %w", i, err)
		}
		if got := hashBytes(raw); got != sha {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: record %d (%s): digest %s does not match declared %s", i, mr.RecordID, got, sha)
		}
		if mr.Size != nil && *mr.Size != int64(len(raw)) {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: record %d (%s): size %d does not match declared %d", i, mr.RecordID, len(raw), *mr.Size)
		}
		rec, err := normalizeCapturedRecord(CapturedRecord{
			RecordID: mr.RecordID, Aliases: mr.Aliases, SHA256: sha,
			Size: int64(len(raw)), Source: mr.Source, Partial: mr.Partial, Raw: raw,
		})
		if err != nil {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: record %d: %w", i, err)
		}
		out.Records = append(out.Records, rec)
	}
	for i, mf := range manifest.Fixes {
		outcome, err := parseCapturedFixOutcome(mf.Outcome)
		if err != nil {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d: %w", i, err)
		}
		fix := CapturedFix{
			RecordID: mf.RecordID, RecordSHA256: mf.RecordSHA256,
			Locator: mf.Locator, Outcome: outcome, Source: mf.Source,
		}
		switch outcome {
		case CapturedFixCaptured:
			if strings.TrimSpace(mf.Path) == "" {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d (%s): captured outcome requires a path", i, mf.Locator)
			}
			sha, derr := normalizedDigest(mf.SHA256)
			if derr != nil {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d: %w", i, derr)
			}
			ref, rerr := resolveContainedFile(baseReal, mf.Path)
			if rerr != nil {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d: %w", i, rerr)
			}
			raw, rerr := readFileCapped(ref, maxInvestigationMaterialBytes)
			if rerr != nil {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d: %w", i, rerr)
			}
			if got := hashBytes(raw); got != sha {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d (%s): digest %s does not match declared %s", i, mf.Locator, got, sha)
			}
			if mf.Size != nil && *mf.Size != int64(len(raw)) {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d (%s): size %d does not match declared %d", i, mf.Locator, len(raw), *mf.Size)
			}
			fix.SHA256, fix.Size, fix.Raw = sha, int64(len(raw)), raw
		default:
			if mf.Path != "" || mf.SHA256 != "" || mf.Size != nil {
				return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d (%s): %s outcome must not carry a path or digest", i, mf.Locator, outcome)
			}
		}
		norm, err := normalizeCapturedFix(fix)
		if err != nil {
			return InvestigationInputs{}, fmt.Errorf("investigation inputs: fix %d: %w", i, err)
		}
		out.Fixes = append(out.Fixes, norm)
	}
	if err := out.Validate(); err != nil {
		return InvestigationInputs{}, err
	}
	return out, nil
}

type investigationManifest struct {
	SchemaVersion string                        `json:"schema_version"`
	Records       []investigationManifestRecord `json:"records,omitempty"`
	Fixes         []investigationManifestFix    `json:"fixes,omitempty"`
	Build         json.RawMessage               `json:"build,omitempty"`
}

type investigationManifestRecord struct {
	RecordID string   `json:"record_id"`
	Aliases  []string `json:"aliases,omitempty"`
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Size     *int64   `json:"size,omitempty"`
	Source   string   `json:"source,omitempty"`
	Partial  bool     `json:"partial,omitempty"`
}

type investigationManifestFix struct {
	RecordID     string `json:"record_id"`
	RecordSHA256 string `json:"record_sha256"`
	Locator      string `json:"locator"`
	Outcome      string `json:"outcome"`
	Path         string `json:"path,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Size         *int64 `json:"size,omitempty"`
	Source       string `json:"source,omitempty"`
}

func normalizeCapturedRecord(rec CapturedRecord) (CapturedRecord, error) {
	id := canonicalVulnID(rec.RecordID)
	if err := validateCapturedIdentity("record_id", id); err != nil {
		return CapturedRecord{}, err
	}
	sha, err := normalizedDigest(rec.SHA256)
	if err != nil {
		return CapturedRecord{}, err
	}
	if len(rec.Raw) == 0 {
		return CapturedRecord{}, fmt.Errorf("record %q carries no captured bytes", id)
	}
	if rec.Size != 0 && rec.Size != int64(len(rec.Raw)) {
		return CapturedRecord{}, fmt.Errorf("record %q size %d does not match captured bytes %d", id, rec.Size, len(rec.Raw))
	}
	if got := hashBytes(rec.Raw); got != sha {
		return CapturedRecord{}, fmt.Errorf("record %q digest %s does not match captured bytes %s", id, sha, got)
	}
	aliases := make([]string, 0, len(rec.Aliases))
	seen := map[string]bool{id: true}
	for _, raw := range rec.Aliases {
		alias := canonicalVulnID(raw)
		if err := validateCapturedIdentity("alias", alias); err != nil {
			return CapturedRecord{}, err
		}
		if seen[alias] {
			continue
		}
		seen[alias] = true
		aliases = append(aliases, alias)
	}
	source := strings.TrimSpace(rec.Source)
	if source == "" {
		source = "investigation-inputs"
	}
	return CapturedRecord{
		RecordID: id, Aliases: aliases, SHA256: sha, Size: int64(len(rec.Raw)),
		Source: source, Partial: rec.Partial, Raw: append([]byte(nil), rec.Raw...),
	}, nil
}

func normalizeCapturedFix(fix CapturedFix) (CapturedFix, error) {
	recID := canonicalVulnID(fix.RecordID)
	if err := validateCapturedIdentity("fix record_id", recID); err != nil {
		return CapturedFix{}, err
	}
	if strings.TrimSpace(fix.Locator) == "" {
		return CapturedFix{}, errors.New("fix locator is required")
	}
	if len(fix.Locator) > 2048 {
		return CapturedFix{}, errors.New("fix locator is longer than 2048 bytes")
	}
	if strings.ContainsAny(fix.Locator, "\r\n\x00") {
		return CapturedFix{}, errors.New("fix locator contains control characters")
	}
	outcome, err := parseCapturedFixOutcome(string(fix.Outcome))
	if err != nil {
		return CapturedFix{}, err
	}
	out := CapturedFix{
		RecordID: recID, Locator: strings.TrimSpace(fix.Locator), Outcome: outcome,
		Source: strings.TrimSpace(fix.Source),
	}
	switch outcome {
	case CapturedFixCaptured:
		sha, derr := normalizedDigest(fix.SHA256)
		if derr != nil {
			return CapturedFix{}, derr
		}
		if len(fix.Raw) == 0 {
			return CapturedFix{}, fmt.Errorf("fix %q for record %q carries no captured bytes", out.Locator, recID)
		}
		if got := hashBytes(fix.Raw); got != sha {
			return CapturedFix{}, fmt.Errorf("fix %q digest %s does not match captured bytes %s", out.Locator, sha, got)
		}
		out.RecordSHA256 = strings.TrimSpace(fix.RecordSHA256)
		out.SHA256, out.Size, out.Raw = sha, int64(len(fix.Raw)), append([]byte(nil), fix.Raw...)
	default:
		if len(fix.Raw) != 0 || strings.TrimSpace(fix.SHA256) != "" {
			return CapturedFix{}, fmt.Errorf("fix %q with outcome %s must not carry bytes or a digest", out.Locator, outcome)
		}
		out.RecordSHA256 = strings.TrimSpace(fix.RecordSHA256)
	}
	ownerSHA, derr := normalizedDigest(out.RecordSHA256)
	if derr != nil {
		return CapturedFix{}, fmt.Errorf("fix %q: owning record digest: %w", out.Locator, derr)
	}
	out.RecordSHA256 = ownerSHA
	return out, nil
}

func parseCapturedFixOutcome(raw string) (CapturedFixOutcome, error) {
	switch CapturedFixOutcome(strings.TrimSpace(strings.ToLower(raw))) {
	case CapturedFixCaptured:
		return CapturedFixCaptured, nil
	case CapturedFixMissing:
		return CapturedFixMissing, nil
	case CapturedFixUnavailable:
		return CapturedFixUnavailable, nil
	default:
		return "", fmt.Errorf("fix outcome %q is not one of captured, missing, unavailable", raw)
	}
}

func validateCapturedIdentity(field, id string) error {
	if id == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(id) > 200 {
		return fmt.Errorf("%s is longer than 200 bytes", field)
	}
	for _, r := range id {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%s %q contains whitespace or control characters", field, id)
		}
	}
	return nil
}

func normalizedDigest(raw string) (string, error) {
	sha := strings.ToLower(strings.TrimSpace(raw))
	if len(sha) != 64 {
		return "", fmt.Errorf("sha256 %q is not 64 hex characters", raw)
	}
	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("sha256 %q is not lowercase hex", raw)
		}
	}
	return sha, nil
}

func investigationArchivePath(sha string) string {
	if strings.TrimSpace(sha) == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Join(investigationArchiveDir, sha))
}

func resolveContainedFile(baseReal, rel string) (string, error) {
	raw := strings.TrimSpace(rel)
	if raw == "" {
		return "", errors.New("referenced path is required")
	}
	if filepath.IsAbs(raw) || filepath.VolumeName(raw) != "" {
		return "", fmt.Errorf("referenced path %q is absolute; paths resolve relative to the manifest", raw)
	}
	clean := filepath.Clean(raw)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("referenced path %q escapes the manifest directory", raw)
	}
	joined := filepath.Join(baseReal, clean)
	if !pathContains(baseReal, joined) {
		return "", fmt.Errorf("referenced path %q escapes the manifest directory", raw)
	}
	real, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", fmt.Errorf("referenced path %q: %w", raw, err)
	}
	if !pathContains(baseReal, real) {
		return "", fmt.Errorf("referenced path %q resolves outside the manifest directory (symlink escape)", raw)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("referenced path %q: %w", raw, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("referenced path %q is not a regular file", raw)
	}
	return real, nil
}

func readFileCapped(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, above the %d byte limit", path, info.Size(), max)
	}
	return os.ReadFile(path)
}

func decodeStrictJSON(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value after the manifest object")
		}
		return fmt.Errorf("trailing data after the manifest object: %w", err)
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// InvestigationInputsArtifactName is the run-relative metadata projection
// of the captured set. Complete bytes live beside it under
// materials/<sha256>; neither artifact grants proof authority.
const InvestigationInputsArtifactName = "investigation-inputs.json"

// PromptInputArtifactName is the run-relative copy of the exact prompt
// surface the first investigator exchange used.
const PromptInputArtifactName = "prompt-input.json"

// WriteInvestigationInputs preserves the complete captured material bytes
// in the digest-addressed archive under dir and writes the metadata
// projection next to them. The archive is independent of the transport
// read bound: a bounded read_material slice never truncates the source.
func (w ArtifactWriter) WriteInvestigationInputs(ctx context.Context, dir string, in InvestigationInputs) error {
	return writeInvestigationArtifacts(ctx, dir, in)
}

func writeInvestigationArtifacts(ctx context.Context, dir string, in InvestigationInputs) error {
	if in.Empty() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	proj := in.Projection()
	if err := verifyProjectionShape(proj); err != nil {
		return err
	}
	written := map[string]bool{}
	writeBlob := func(sha string, raw []byte) error {
		if written[sha] {
			return nil
		}
		if len(raw) == 0 {
			return fmt.Errorf("agenttriage: captured material %s has no bytes", sha)
		}
		if got := hashBytes(raw); got != sha {
			return fmt.Errorf("agenttriage: captured material digest %s does not match bytes %s", sha, got)
		}
		written[sha] = true
		if err := os.MkdirAll(filepath.Join(dir, investigationArchiveDir), 0o755); err != nil {
			return fmt.Errorf("agenttriage: create material archive: %w", err)
		}
		return writeFileAtomic(ctx, filepath.Join(dir, investigationArchiveDir, sha), raw)
	}
	for _, r := range in.Records {
		if err := writeBlob(r.SHA256, r.Raw); err != nil {
			return err
		}
	}
	for _, f := range in.Fixes {
		if f.Outcome != CapturedFixCaptured {
			continue
		}
		if err := writeBlob(f.SHA256, f.Raw); err != nil {
			return err
		}
	}
	if err := writeJSONAtomic(ctx, filepath.Join(dir, InvestigationInputsArtifactName), proj); err != nil {
		return err
	}
	return nil
}

func verifyProjectionShape(proj InvestigationProjection) error {
	if proj.SchemaVersion != InvestigationInputsSchemaVersion {
		return fmt.Errorf("agenttriage: investigation inputs projection schema %q is not %s", proj.SchemaVersion, InvestigationInputsSchemaVersion)
	}
	if _, err := proj.Inputs(); err != nil {
		return fmt.Errorf("agenttriage: %w", err)
	}
	for _, r := range proj.Records {
		want := investigationArchivePath(r.SHA256)
		if r.ArchivePath != want {
			return fmt.Errorf("agenttriage: record %q archive path %q is not the digest-addressed %q", r.RecordID, r.ArchivePath, want)
		}
	}
	for _, f := range proj.Fixes {
		switch f.Outcome {
		case CapturedFixCaptured:
			want := investigationArchivePath(f.SHA256)
			if f.ArchivePath != want {
				return fmt.Errorf("agenttriage: fix %q archive path %q is not the digest-addressed %q", f.Locator, f.ArchivePath, want)
			}
		default:
			if f.ArchivePath != "" || f.SHA256 != "" {
				return fmt.Errorf("agenttriage: fix %q with outcome %s must not carry an archive path or digest", f.Locator, f.Outcome)
			}
		}
	}
	return nil
}

// ReadInvestigationProjection loads and fully verifies the persisted
// metadata projection plus every archived material blob. A missing
// projection returns (nil, nil): historical runs predate it. A present but
// tampered projection or archive is a technical error.
func ReadInvestigationProjection(dir string) (*InvestigationProjection, error) {
	path := filepath.Join(dir, InvestigationInputsArtifactName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agenttriage: read %s: %w", InvestigationInputsArtifactName, err)
	}
	var proj InvestigationProjection
	if err := decodeStrictJSON(data, &proj); err != nil {
		return nil, fmt.Errorf("agenttriage: %s does not parse: %w", InvestigationInputsArtifactName, err)
	}
	if err := verifyProjectionShape(proj); err != nil {
		return nil, err
	}
	for _, r := range proj.Records {
		if err := verifyArchivedBlob(dir, r.ArchivePath, r.SHA256, r.Size, "record", r.RecordID); err != nil {
			return nil, err
		}
	}
	for _, f := range proj.Fixes {
		if f.Outcome != CapturedFixCaptured {
			continue
		}
		if err := verifyArchivedBlob(dir, f.ArchivePath, f.SHA256, f.Size, "fix", f.Locator); err != nil {
			return nil, err
		}
	}
	return &proj, nil
}

func verifyArchivedBlob(dir, archivePath, sha string, size int64, kind, identity string) error {
	rel := filepath.FromSlash(archivePath)
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") || !pathContains(filepath.Join(dir, investigationArchiveDir), filepath.Join(dir, rel)) {
		return fmt.Errorf("agenttriage: %s %q archive path %q escapes the material archive", kind, identity, archivePath)
	}
	data, err := readFileCapped(filepath.Join(dir, rel), maxInvestigationMaterialBytes)
	if err != nil {
		return fmt.Errorf("agenttriage: %s %q archived material %s is missing or unreadable: %w", kind, identity, archivePath, err)
	}
	if size > 0 && int64(len(data)) != size {
		return fmt.Errorf("agenttriage: %s %q archived material drifted: recorded size %d, now %d", kind, identity, size, len(data))
	}
	if got := hashBytes(data); got != sha {
		return fmt.Errorf("agenttriage: %s %q archived material drifted: recorded sha256 %s, recomputed %s", kind, identity, sha, got)
	}
	return nil
}

// CopyInvestigationArchive copies every digest-addressed material blob from
// one run directory into another, preserving the archive as recorded. A
// replay output is itself replayable only when the captured bytes travel
// with it.
func CopyInvestigationArchive(sourceDir, destDir string) error {
	src := filepath.Join(sourceDir, investigationArchiveDir)
	entries, err := os.ReadDir(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("agenttriage: read material archive: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, err := normalizedDigest(name); err != nil {
			return fmt.Errorf("agenttriage: material archive entry %q is not a digest-addressed blob", name)
		}
		data, rerr := readFileCapped(filepath.Join(src, name), maxInvestigationMaterialBytes)
		if rerr != nil {
			return fmt.Errorf("agenttriage: read archived material %s: %w", name, rerr)
		}
		if got := hashBytes(data); got != name {
			return fmt.Errorf("agenttriage: archived material %s drifted: recomputed %s", name, got)
		}
		if err := os.MkdirAll(filepath.Join(destDir, investigationArchiveDir), 0o755); err != nil {
			return fmt.Errorf("agenttriage: create replay material archive: %w", err)
		}
		if err := writeFileAtomic(context.Background(), filepath.Join(destDir, investigationArchiveDir, name), data); err != nil {
			return err
		}
	}
	return nil
}

func investigationProjectionPtr(in InvestigationInputs) *InvestigationProjection {
	if in.Empty() {
		return nil
	}
	proj := in.Projection()
	return &proj
}
