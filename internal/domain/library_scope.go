package domain

// ProductShapeKind is the proven shape of the analyzed product: a library
// (importable packages, no owned command), an application (an owned package
// main is proven), or UNKNOWN when ownership, the package census or the
// source inventory could not be proven complete.
type ProductShapeKind string

const (
	ProductShapeUnknown     ProductShapeKind = "UNKNOWN"
	ProductShapeLibrary     ProductShapeKind = "LIBRARY"
	ProductShapeApplication ProductShapeKind = "APPLICATION"
)

// ProductModuleShape is one module owned by the product: the module whose
// go.mod governs the product directory plus every effective-workspace member
// inside the analyzed tree. Directory is relative to the product root.
type ProductModuleShape struct {
	Path      string `json:"path"`
	Directory string `json:"directory"`
}

// ProductPackageShape is one inventoried non-test product package directory.
// ClauseComplete records that every non-test source file yielded a package
// clause; Importable records that the directory is a non-main package a
// dependent module could import (not internal, not a command). Files are
// product-relative paths. LoadErrors carries the loader diagnostics of a
// package the loader dropped, so a failed package is auditable rather than
// invisible.
type ProductPackageShape struct {
	Path           string   `json:"path"`
	Module         string   `json:"module"`
	Directory      string   `json:"directory"`
	PackageNames   []string `json:"package_names,omitempty"`
	Files          []string `json:"files,omitempty"`
	ClauseComplete bool     `json:"clause_complete"`
	Importable     bool     `json:"importable"`
	LoadErrors     []string `json:"load_errors,omitempty"`
}

// ProductShape is the persisted product-shape proof: module ownership, the
// manifest-aware non-test source census, the resulting classification and
// the identity of the inputs the proof was derived from. CensusComplete means
// ownership and the source inventory were proven complete; a LIBRARY
// classification additionally required a successful loader reconciliation, so
// only Kind==LIBRARY may be treated as a library proof. Fingerprint pins
// manifests, ownership, build context, file inventory and source content —
// a witness recording it can only be admitted against the same census.
// EvidenceIDs are case-scoped and assigned by the collector.
type ProductShape struct {
	Kind            ProductShapeKind      `json:"kind"`
	CensusComplete  bool                  `json:"census_complete"`
	RootModule      string                `json:"root_module,omitempty"`
	OwnedModules    []ProductModuleShape  `json:"owned_modules,omitempty"`
	ExcludedModules []ProductModuleShape  `json:"excluded_modules,omitempty"`
	WorkspaceFile   string                `json:"workspace_file,omitempty"`
	Packages        []ProductPackageShape `json:"packages,omitempty"`
	Fingerprint     string                `json:"fingerprint"`
	EvidenceIDs     []EvidenceID          `json:"evidence_ids,omitempty"`
	Limitations     []string              `json:"limitations,omitempty"`
}

// LibraryPayloadStepKind classifies one hop of a library payload binding.
type LibraryPayloadStepKind string

const (
	// LibraryPayloadIdentity is a verbatim forwarding step (a local assignment
	// or direct argument pass-through).
	LibraryPayloadIdentity LibraryPayloadStepKind = "identity"
	// LibraryPayloadByteConversion is a conversion that cannot alter the bytes
	// of the payload (string <-> []byte and their defined types).
	LibraryPayloadByteConversion LibraryPayloadStepKind = "byte-preserving-conversion"
	// LibraryPayloadPreservingCall is a call whose body proves the same
	// binding — e.g. a complete-read carrier or a forwarding helper.
	LibraryPayloadPreservingCall LibraryPayloadStepKind = "payload-preserving-call"
)

// LibraryPayloadStep is one preserving hop between the public formal and the
// sink argument.
type LibraryPayloadStep struct {
	Kind LibraryPayloadStepKind `json:"kind"`
	Site CallSite               `json:"site"`
}

// LibraryInputWitness records the proven binding between one product-owned
// public library formal and one exact vulnerable-sink argument: the API
// declaration, the formal slot and type, the resolved sink site/argument and
// the preserving steps in between. It never asserts deployment attacker
// control — DataFlow.Origin stays UNKNOWN. ShapeFingerprint binds the witness
// to the product census it was derived from.
type LibraryInputWitness struct {
	API              SymbolRef            `json:"api"`
	Declaration      CallSite             `json:"declaration"`
	FormalIndex      int                  `json:"formal_index"`
	FormalName       string               `json:"formal_name,omitempty"`
	FormalType       string               `json:"formal_type"`
	Sink             SymbolRef            `json:"sink"`
	Site             CallSite             `json:"site"`
	Arg              int                  `json:"arg"`
	ShapeFingerprint string               `json:"shape_fingerprint"`
	Steps            []LibraryPayloadStep `json:"steps,omitempty"`
	EvidenceIDs      []EvidenceID         `json:"evidence_ids,omitempty"`
}

// ControlBasis names what grounds a claim's attacker-control conclusion.
// library-public-api means the payload is selectable by a consumer of the
// analyzed library through a proven public-API → sink binding; it says
// nothing about whether a downstream application exposes that payload to an
// attacker.
type ControlBasis string

const ControlBasisLibraryPublicAPI ControlBasis = "library-public-api"

// ExploitabilityScope names the product boundary a verdict covers.
// library-api means the conclusion is scoped to the library's public API; the
// deployment-level attacker control of a consuming application stays
// unestablished.
type ExploitabilityScope string

const ScopeLibraryAPI ExploitabilityScope = "library-api"

// LibraryAPIScopeLimitation is the mandatory limitation attached to every
// library-API-scoped conclusion, verbatim, in machine-readable output.
const LibraryAPIScopeLimitation = "Library-API scope: the payload is selectable by a library consumer; whether a downstream application exposes that payload to an attacker is outside the analyzed product and is not established."
