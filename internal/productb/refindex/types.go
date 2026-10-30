// Package refindex builds eval-side "izyan-refindex/1" documents: a frozen,
// deterministic reference index that binds one advisory to one product
// snapshot — advisory identity + digests, the snapshot's build context, the
// resolved defect locus (advisory-declared symbols with their declarations),
// the product-usage stratum and an auxiliary fix-diff summary.
//
// The document is canonical: every field is emitted through encoding/json
// struct order, every list is sorted or document-ordered deterministically,
// and re-running the builder over unchanged inputs produces byte-identical
// output. `hashes.canonical_sha256` is the sha256 of the canonical JSON with
// the hashes field removed.
//
// The package is eval tooling only: it changes neither the analyzer's
// {category, reasoning} response contract nor any production code path.
package refindex

// Schema is the document schema tag frozen into every emitted document.
const Schema = "izyan-refindex/1"

// Doc is the izyan-refindex/1 document root.
type Doc struct {
	Schema       string    `json:"schema"`
	CaseID       string    `json:"case_id"`
	Advisory     Advisory  `json:"advisory"`
	Snapshot     Snapshot  `json:"snapshot"`
	BuildContext BuildCtx  `json:"build_context"`
	Locus        Locus     `json:"locus"`
	Usage        Usage     `json:"usage"`
	Auxiliary    Auxiliary `json:"auxiliary"`
	Hashes       *Hashes   `json:"hashes,omitempty"`
}

// Advisory pins the advisory family the index was built from: the selected
// document's id, a digest of the family corpus (selected document plus every
// alias/related sibling consulted, sorted and hashed verbatim) and the
// per-document sha256 list.
type Advisory struct {
	ID        string        `json:"id"`
	Digest    string        `json:"digest"`
	Documents []AdvisoryDoc `json:"documents"`
}

// AdvisoryDoc records one verbatim advisory document that contributed to
// the family corpus.
type AdvisoryDoc struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

// Snapshot identifies the analyzed tree.
type Snapshot struct {
	Path        string `json:"path"`
	Commit      string `json:"commit,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
}

// BuildCtx records the build context the locus/usage checks ran under.
type BuildCtx struct {
	GOOS       string   `json:"goos"`
	GOARCH     string   `json:"goarch"`
	Tags       []string `json:"tags"`
	CGO        bool     `json:"cgo"`
	Toolchain  string   `json:"toolchain,omitempty"`
	ModuleMode string   `json:"module_mode"` // vendor | mod
}

// LocusStatus reports how far advisory symbol resolution got.
type LocusStatus string

const (
	// LocusResolved: every named-symbol atom resolved its declaration.
	LocusResolved LocusStatus = "resolved"
	// LocusPackageOnly: the advisory declares affected packages but no
	// symbol names — the locus is whole packages.
	LocusPackageOnly LocusStatus = "package_only"
	// LocusWildcard: the advisory declares explicit "*" wildcards only.
	LocusWildcard LocusStatus = "wildcard"
	// LocusUnresolved: at least one named-symbol atom could not be
	// resolved to a declaration.
	LocusUnresolved LocusStatus = "unresolved"
	// LocusNA: the advisory family declares no affected package/symbol
	// material at all.
	LocusNA LocusStatus = "na"
)

// Locus is the resolved defect locus: one atom per advisory-declared
// (module, package, symbol), package atoms carrying an empty symbol.
type Locus struct {
	Atoms  []Atom      `json:"atoms"`
	Status LocusStatus `json:"status"`
}

// Atom is one advisory-declared unit of vulnerable code.
type Atom struct {
	Module     string `json:"module"`
	Package    string `json:"package"`
	Symbol     string `json:"symbol"` // normalized: (*T).M == T.M; "" = whole package
	SymbolKind string `json:"symbol_kind"`
	Role       string `json:"role"`
	AdvisoryID string `json:"advisory_id"`
	Decl       *Decl  `json:"decl"`
}

// Symbol kinds; "package" marks whole-package atoms (wildcard or
// symbol-less imports[] entry).
const (
	KindFunc    = "func"
	KindMethod  = "method"
	KindType    = "type"
	KindVar     = "var"
	KindPackage = "package"
)

// Atom roles: "sink" is the default for advisory-declared defect sites;
// "parse" marks symbols whose name declares a parse/decode role;
// "dispatch" is reserved for atoms proven to route to the defect (the
// builder does not assign it — advisory material alone cannot confirm a
// dispatch role).
const (
	RoleSink     = "sink"
	RoleParse    = "parse"
	RoleDispatch = "dispatch"
)

// Decl pins the declaration of a resolved atom.
type Decl struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
}

// UsageStratum is the usage verdict only: what the bounded product-source
// check could prove about the advisory locus. Module binding (vendored /
// replaced / forked / direct) is reported separately in Usage.Binding —
// the two dimensions are orthogonal, so a vendored module can still be
// proven unreachable and a forked module can be proven reachable.
type UsageStratum string

const (
	// StratumReachableComplete: USED with a closed check scope — concrete
	// product references were found and no case-specific scope gap was
	// recorded for any used atom.
	StratumReachableComplete UsageStratum = "reachable_complete"
	// StratumReachablePartial: USED but at least one atom verdict stayed
	// open (scope gap, unresolved atom, or an UNKNOWN sibling); usage is
	// proven, completeness of the reachable set is not.
	StratumReachablePartial UsageStratum = "reachable_partial"
	// StratumUnreachableComplete: NOT_USED with VERIFIED negative
	// verification (closed scope), independent of binding — a vendored,
	// replaced or direct module all qualify when the negative is closed.
	StratumUnreachableComplete UsageStratum = "unreachable_complete"
	// StratumUnknown: the check could not be closed (UNKNOWN atoms only,
	// a NOT_USED without an in-closure VERIFIED negative, or an
	// unavailable index).
	StratumUnknown UsageStratum = "unknown"
	// StratumNotPresent: the advisory module is absent from the module
	// graph (go.mod require/replace + vendor/modules.txt) — manifest-
	// verified absence, never inferred from the loaded source closure.
	// Empty site lists never reach this stratum.
	StratumNotPresent UsageStratum = "not_present"
	// StratumSelfImplementation: the advisory module IS the product's
	// primary module — the vulnerable code is first-party.
	StratumSelfImplementation UsageStratum = "self_implementation"
)

// Binding classifies how the advisory module's code is bound into the
// product build, independently of the usage verdict.
type Binding string

const (
	// BindingDirect: the advisory module is used as resolved by the module
	// graph (module cache), with no vendor tree or path-changing replace.
	BindingDirect Binding = "direct"
	// BindingVendoredExact: the product builds in vendor mode and the
	// advisory module ships from the checked-in vendor tree — the vendored
	// copy is the exact source the build links.
	BindingVendoredExact Binding = "vendored_exact"
	// BindingReplacementAmbiguous: a replace directive binds the advisory
	// module to a different module path — the linked source is not the
	// advisory's released module, so binding and version are ambiguous.
	BindingReplacementAmbiguous Binding = "replacement_ambiguous"
	// BindingForkCopy: the advisory module binds to a local filesystem
	// replace (a forked copy on disk) or the affected package ships inside
	// the product's own module without a module dependency.
	BindingForkCopy Binding = "fork_copy"
)

// UsageState mirrors the ProductUsage verdict vocabulary.
type UsageState string

const (
	StateUsed    UsageState = "USED"
	StateNotUsed UsageState = "NOT_USED"
	StateUnknown UsageState = "UNKNOWN"
)

// Usage is the merged product-usage verdict over all atoms.
type Usage struct {
	Stratum              UsageStratum `json:"stratum"`
	Binding              Binding      `json:"binding"`
	State                UsageState   `json:"state"`
	NegativeVerification string       `json:"negative_verification"`
	Sites                []Site       `json:"sites"`
	ImportSites          []Site       `json:"import_sites"`
	CheckScope           string       `json:"check_scope"`
	Limitations          []string     `json:"limitations"`
}

// Site is one product-source location, adapted from domain.CallSite.
// Target names the atom the site was recorded for (package for import
// sites, package.symbol for reference sites).
type Site struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Function string `json:"function,omitempty"`
	Package  string `json:"package,omitempty"`
	Target   string `json:"target,omitempty"`
}

// Auxiliary carries evidence that informs but never decides the primary
// locus: the fix-commit diff inventory.
type Auxiliary struct {
	FixDiff FixDiff `json:"fix_diff"`
}

// FixDiff summarizes the advisory's fix patch.
type FixDiff struct {
	Status string        `json:"status"` // available | unavailable | not_attempted
	Files  []FixDiffFile `json:"files"`
}

// Fix-diff statuses.
const (
	FixDiffAvailable    = "available"
	FixDiffUnavailable  = "unavailable"
	FixDiffNotAttempted = "not_attempted"
)

// FixDiffFile counts churn of one file in the fix patch.
type FixDiffFile struct {
	Path      string `json:"path"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
}

// Hashes carries the document self-hash.
type Hashes struct {
	CanonicalSHA256 string `json:"canonical_sha256"`
}
