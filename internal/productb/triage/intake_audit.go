package triage

import (
	"context"
	"encoding/json"
	"path/filepath"
)

// IntakeAuditSchemaVersion identifies intake-audit.json, the Stage 0
// provenance artifact stored inside the finding's run directory.
const IntakeAuditSchemaVersion = "intake-audit.v1"

// IntakeFieldAudit is the field-by-field audit record: the deterministic
// validation verdict plus where the value was confirmed from. The extracted
// value itself never enters the audit — only its hash.
type IntakeFieldAudit struct {
	Field               string            `json:"field"`
	Status              IntakeFieldStatus `json:"status"`
	ValueSHA256         string            `json:"value_sha256,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	Provenance          []string          `json:"provenance,omitempty"`
	BlocksRiskReduction bool              `json:"blocks_risk_reduction"`
}

// intakeFieldAudits projects FieldValidations into their audit shape.
func intakeFieldAudits(fields []FieldValidation) []IntakeFieldAudit {
	out := make([]IntakeFieldAudit, 0, len(fields))
	for _, f := range fields {
		a := IntakeFieldAudit{
			Field:               f.Field,
			Status:              f.Status,
			Reason:              f.Reason,
			Provenance:          f.Provenance,
			BlocksRiskReduction: f.BlocksRiskReduction,
		}
		if f.Value != "" {
			a.ValueSHA256 = hashBytes([]byte(f.Value))
		}
		out = append(out, a)
	}
	return out
}

// IntakeAuditDocument is intake-audit.json: the auditable provenance record
// of one Stage 0 resolution. It stores identities, statuses, hashes and the
// deterministic attempt projections — never ticket text, tool payloads or
// credential material (credential_ref names only).
type IntakeAuditDocument struct {
	SchemaVersion string `json:"schema_version"`
	FindingID     string `json:"finding_id,omitempty"`
	// Record identity.
	TicketHash  string `json:"ticket_hash"`
	Format      string `json:"format"`
	RecordIndex int    `json:"record_index"`
	// Resolution pins.
	ConfigHash   string `json:"config_hash,omitempty"`
	ProposalHash string `json:"proposal_hash,omitempty"`
	SnapshotHash string `json:"snapshot_hash,omitempty"`
	AdvisoryHash string `json:"advisory_hash,omitempty"`
	InputHash    string `json:"input_hash,omitempty"`
	// Field-by-field validation audit plus the aggregated limitations and
	// technical errors — kept on separate channels by construction.
	Fields      []IntakeFieldAudit `json:"fields"`
	Limitations []string           `json:"limitations,omitempty"`
	Errors      []string           `json:"errors,omitempty"`
	// Stage provenance projections — the same shapes events.jsonl carries.
	Source          *SourceAudit          `json:"source,omitempty"`
	Ref             *RefResolutionAudit   `json:"ref,omitempty"`
	Materialization *MaterializationAudit `json:"materialization,omitempty"`
	Advisory        *AdvisoryAudit        `json:"advisory,omitempty"`
	Materials       *MaterialsAudit       `json:"materials,omitempty"`
	Toolchain       *ToolchainAudit       `json:"toolchain,omitempty"`
	PackageCheck    *PackageCheckAudit    `json:"package_check,omitempty"`
}

// BuildIntakeAudit projects a Stage0Result into the machine-readable intake
// audit document. Empty stages stay empty — a partial resolution records
// what ran and nothing more; a failed stage never invents provenance.
func BuildIntakeAudit(res Stage0Result) IntakeAuditDocument {
	doc := IntakeAuditDocument{
		SchemaVersion: IntakeAuditSchemaVersion,
		FindingID:     res.Input.Finding.FindingID,
		TicketHash:    res.Raw.TicketHash,
		Format:        string(res.Raw.Format),
		RecordIndex:   res.Raw.RecordIndex,
		ConfigHash:    res.ConfigHash,
		AdvisoryHash:  res.Advisory.SHA256,
		Fields:        intakeFieldAudits(res.Validation.Fields),
		Limitations:   res.Limitations,
		Errors:        res.Validation.Errors,
	}
	if doc.Fields == nil {
		doc.Fields = []IntakeFieldAudit{}
	}
	if res.Proposal.SchemaVersion != "" {
		if b, err := json.Marshal(res.Proposal); err == nil {
			doc.ProposalHash = hashBytes(b)
		}
	}
	if res.Snapshot.ContentHash != "" {
		doc.SnapshotHash = res.Snapshot.ContentHash
		doc.InputHash = res.Snapshot.InputHash
	}
	if res.CatalogEntry.ID != "" {
		doc.Source = sourceAuditOf(res.CatalogEntry)
	}
	if res.RefResolution.SelectedID != "" || len(res.RefResolution.CandidateRefs) > 0 {
		a := refAuditOf(res.RefResolution)
		doc.Ref = &a
	}
	if md := res.Source.Metadata; md.Mode != "" || md.SourceID != "" {
		a := MaterializationAudit(md)
		doc.Materialization = &a
	}
	if res.Resolution != nil {
		doc.Advisory = advisoryAuditOf(res.Resolution)
	} else if rec := res.Advisory; rec.Source != "" || rec.SHA256 != "" {
		doc.Advisory = &AdvisoryAudit{
			ID: rec.ID, ResolvedID: rec.ResolvedID, Source: string(rec.Source),
			Path: rec.Path, SHA256: rec.SHA256,
		}
	}
	if res.Materials.Materials != nil || res.Materials.ModuleGraph != nil || res.Materials.Deploy != nil {
		a := materialsAuditOf(res.Materials)
		doc.Materials = &a
	}
	if res.ReleaseToolchain.Version != "" || res.ReleaseToolchain.Claimed != "" || res.Toolchain.Version != "" {
		a := toolchainAuditOf(res.ReleaseToolchain, res.Toolchain)
		doc.Toolchain = &a
	}
	if res.PackageCheck.Class != "" {
		a := packageCheckAuditOf(res.PackageCheck)
		doc.PackageCheck = &a
	}
	return doc
}

// WriteIntakeAudit persists intake-audit.json inside the finding's run
// directory. The file is atomic like every other artifact; it is a
// provenance record — writing it never changes any decision.
func WriteIntakeAudit(ctx context.Context, dir string, res Stage0Result) error {
	// The document carries nested free-form text — field reasons,
	// limitations, errors, the ref/materialization projections — so it
	// goes through the recursive credential pass, not a top-level scrub.
	return writeJSONAtomicRedacted(ctx, filepath.Join(dir, "intake-audit.json"), BuildIntakeAudit(res))
}
