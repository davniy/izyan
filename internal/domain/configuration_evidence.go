package domain

// ConfigWriterEvidence is a bounded observation, never an effective-value or
// safety certificate. Subject is a field declaration; Objects keep individual
// storage declarations separate. Events are unordered (not reaching definitions).
type ConfigWriterEvidence struct {
	Subject SymbolRef `json:"subject"`
	FieldType string `json:"field_type"`
	Objects []ConfigObject `json:"objects"`
	Assignments []ConfigAssignment `json:"assignments"`
	Blockers []string `json:"blockers"`
	Build BuildContext `json:"build"`
	// RuntimeChannels are scope observations, not proven overrides of an object.
	RuntimeChannels []ConfigWriterEvent `json:"runtime_channels,omitempty"`
	SourceHashes map[string]string `json:"source_hashes"`
	InventoryReference string `json:"inventory_reference,omitempty"`
	InventoryRaw string `json:"inventory_raw,omitempty"`
	InventoryRun PackageListRun `json:"inventory_run"`
	InventoryBuild BuildContext `json:"inventory_build"`
	InventorySHA256 string `json:"inventory_sha256,omitempty"`
	InventorySize int `json:"inventory_size"`
	InventoryScope string `json:"inventory_scope"`
	InventoryError string `json:"inventory_error,omitempty"`
}

type ConfigObject struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Declaration CallSite `json:"declaration"`
	Pointer bool `json:"pointer"`
	Events []ConfigWriterEvent `json:"events"`
	Blockers []string `json:"blockers,omitempty"`
}

// RelatedObject binds copies/aliases to another storage declaration. A call
// consumption identifies the actual argument/receiver, not every Type.Field.
type ConfigWriterEvent struct {
	Kind string `json:"kind"`
	Site CallSite `json:"site"`
	Value string `json:"value,omitempty"`
	ValueSource string `json:"value_source,omitempty"`
	RelatedObject string `json:"related_object,omitempty"`
	Callee SymbolRef `json:"callee,omitempty"`
	Argument int `json:"argument"`
	Channel string `json:"channel,omitempty"`
	Key string `json:"key,omitempty"`
}

const ConfigWriterCertificateSchema = "effective-config.v1"

type ConfigUseSelector struct {
	ConditionID ConditionID `json:"condition_id"`
	Field SymbolRef `json:"field"`
	ObjectID string `json:"object_id"`
	ObjectDeclaration CallSite `json:"object_declaration"`
	Consumer CallSite `json:"consumer"`
	Callee SymbolRef `json:"callee"`
	Argument int `json:"argument"`
}

type ConfigCapturedFile struct {
	Path string `json:"path"`
	Bytes []byte `json:"bytes"`
}

type ConfigCapturedPackage struct {
	ImportPath string `json:"import_path"`
	Directory string `json:"directory"`
	SelectedGoFiles []string `json:"selected_go_files"`
	Files []ConfigCapturedFile `json:"files"`
}

type ConfigWriterCertificate struct {
	Schema string `json:"schema"`
	ConditionID ConditionID `json:"condition_id"`
	Record RecordPin `json:"record"`
	Build BuildContext `json:"build"`
	Subjects []SymbolRef `json:"subjects"`
	InventoryEvidenceID EvidenceID `json:"inventory_evidence_id"`
	InventoryReference string `json:"inventory_reference"`
	SnapshotManifest []byte `json:"snapshot_manifest"`
	Packages []ConfigCapturedPackage `json:"packages"`
	Uses []ConfigUseSelector `json:"uses"`
}
