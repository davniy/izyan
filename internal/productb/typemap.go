package productb

import "encoding/json"

// PortTypeMapSchemaVersion pins the emitted artifact.
const PortTypeMapSchemaVersion = "port-type-map.v1"

// TypeDisposition is the §14.3.2 decision for one V2 type a ported Product
// B surface references.
type TypeDisposition string

const (
	// MappedToCanonical binds to the Shadow canonical type with the same
	// authority semantics (same-module identity types like Observation).
	MappedToCanonical TypeDisposition = "mapped"
	// MappedViaAdapter is bound through an adapter projection or an
	// adapter-local DTO (same shape, no direct package reference).
	MappedViaAdapter TypeDisposition = "adapter-projection"
	// AdapterOnly stays a Product B adapter type: ported and used, but
	// never projected into Product A authority (claims, proposals).
	AdapterOnly TypeDisposition = "adapter-only"
	// Unsupported is referenced by a Product B surface that is not
	// ported in this slice; the surface is non-admitting, never
	// shimmed or guessed.
	Unsupported TypeDisposition = "unsupported"
	// Dropped was used by V2 for a capability the target architecture
	// eliminates entirely (authority duplication, evaluator paths).
	Dropped TypeDisposition = "dropped"
)

// TypeMapEntry is one row of the mandatory V2→Shadow mapping table
// (§14.3.2): what V2 called it, where the ported adapter references it,
// and the disposition the merge assigns.
type TypeMapEntry struct {
	// V2Type is the qualified V2 name as written in the source.
	V2Type string `json:"v2_type"`
	// V2Package is the V2 internal package declaring the type.
	V2Package string `json:"v2_package"`
	// ReferencedBy is the ported Product B file/symbol that touches the
	// V2 contract; empty for surfaces whose port is deferred.
	ReferencedBy string `json:"referenced_by"`
	// Disposition classifies the binding.
	Disposition TypeDisposition `json:"disposition"`
	// Target is the Shadow symbol the type binds to (when mapped or
	// adapted); empty for adapter-only/dropped/unsupported rows.
	Target string `json:"target,omitempty"`
	// Note records the constraint the disposition enforces.
	Note string `json:"note,omitempty"`
}

// PortTypeMap is the code-level registry: every V2 type the ported
// Product B triage surface references, or deliberately does not, with
// its disposition. registry_test.go pins completeness against the actual
// import graph.
func PortTypeMap() []TypeMapEntry {
	return []TypeMapEntry{
		// --- evidence/observation boundary (mapped to Shadow canonical) ---
		{V2Type: "evidencetools.Observation", V2Package: "internal/evidencetools", ReferencedBy: "detools.go Call/ObservationStore, factgate.go observation checks", Disposition: MappedToCanonical, Target: "evidencetools.Observation", Note: "same-module canonical type; identity, scope and completeness flags are the replay contract"},
		{V2Type: "evidencetools.Client", V2Package: "internal/evidencetools", ReferencedBy: "binding.go ClientCaller", Disposition: MappedToCanonical, Target: "*evidencetools.Client.Call", Note: "Shadow MCP-bound client is the DetCaller surface; audit events flow through it"},
		{V2Type: "evidencetools.CheckCatalog/CheckSpec", V2Package: "internal/evidencetools", ReferencedBy: "binding.go CatalogFromCheckCatalog, detools.go Definitions/Call", Disposition: MappedViaAdapter, Target: "DetToolInfo", Note: "Shadow check catalog publishes Description plus session-resolved Available/UnavailableReason; DetToolInfo projects name, description, schema and availability verbatim — no second allowlist"},
		{V2Type: "evidencetools.ToolInfo", V2Package: "internal/evidencetools", ReferencedBy: "detools.go Catalog", Disposition: MappedViaAdapter, Target: "DetToolInfo (adapter-local DTO)", Note: "no Shadow ToolInfo exists; the broker keeps name/description/schema/availability tuples as DTOs"},
		{V2Type: "fix.Provider/Reference/Patch/Parse", V2Package: "internal/fix", ReferencedBy: "binding.go CapturedFixProvider, triage fix-reference/diff research", Disposition: MappedToCanonical, Target: "fix.Provider/fix.Reference", Note: "canonical patch acquisition contract; CapturedFixProvider implements the same Provider interface over the captured fix set — recorded bytes or an ErrRecordUnavailable answer, never a network fetch"},
		{V2Type: "vulnerability.Source", V2Package: "internal/vulnerability", ReferencedBy: "binding.go CapturedAdvisorySource", Disposition: MappedToCanonical, Target: "vulnerability.Source", Note: "canonical advisory source interface; CapturedAdvisorySource implements it over the run's digest-verified captured records and resolves ids/aliases only inside that set"},

		// --- repository / transport / compute surfaces (mapped) ---
		{V2Type: "repository.ResolveRef", V2Package: "internal/repository", ReferencedBy: "factgate.go checkRevision", Disposition: MappedToCanonical, Target: "repository.ResolveRef", Note: "same function, same contract"},
		{V2Type: "llm.ToolDefinition/FunctionSpec/ChatMessage/ModelRole", V2Package: "internal/llm", ReferencedBy: "detools.go, runner.go, intake_llm.go, ref.go", Disposition: MappedToCanonical, Target: "llm.ToolDefinition", Note: "tool/chat surface type is canonical and shared"},
		{V2Type: "toolchain.Toolchain/Resolve/Normalize", V2Package: "internal/toolchain", ReferencedBy: "stage0.go, validation_rules.go, audit.go", Disposition: MappedToCanonical, Target: "toolchain.Toolchain", Note: "identical file in both repos; canonical reuse"},
		{V2Type: "toolaudit.Run", V2Package: "internal/toolaudit", ReferencedBy: "productb/affected golist.go, productb/repository service.go", Disposition: MappedToCanonical, Target: "toolaudit.Run", Note: "identical audited command runner"},
		{V2Type: "exposure.ScanDeployWithOptions/ClassifyPerimeter/DeployScanOptions", V2Package: "internal/exposure", ReferencedBy: "materials.go deploy scan, providers.go", Disposition: MappedToCanonical, Target: "exposure.*", Note: "identical implementation; ExposureFact alias makes the domain types line up"},
		{V2Type: "risk.NominalPriority", V2Package: "internal/risk", ReferencedBy: "decision_rules.go composeBaseline", Disposition: MappedToCanonical, Target: "risk.NominalPriority", Note: "severity→priority ladder; returns domain.TriagePriority used only as a string"},

		// --- adapter-local DTO mirrors of V2-internal packages ---
		{V2Type: "domain.* (data types only)", V2Package: "internal/domain", ReferencedBy: "every ported file's domain.* references", Disposition: MappedViaAdapter, Target: "internal/productb/domain (alias shim)", Note: "type aliases over identical Shadow data structs — Vulnerability, VersionRange, AffectedPackage, SymbolRef, AffectedModule, ProductSnapshot, GoVersionSource, ExposureFact, CallSite, Condition, ExploitModel, Reference, ReplaceDirective; authority types (Claim/NV/Verdict/AnalysisCase) never exported"},
		{V2Type: "affected.Module/GoTool/ExecGoTool/DecodeModules/PackageImportPaths/ParseVendorModules", V2Package: "internal/affected", ReferencedBy: "materials.go collectModuleGraph, stage0.go GoTool", Disposition: MappedViaAdapter, Target: "internal/productb/affected", Note: "V2 golist.go verbatim; GoTool interface takes productb/domain.ProductSnapshot (alias of canonical)"},
		{V2Type: "vulnerability.* (CompositeSource/FrozenAdvisory/RawDocument/OSV/parsing)", V2Package: "internal/vulnerability", ReferencedBy: "advisory.go ResolveAdvisory, stage0.go, binding.go CapturedAdvisorySource (parse)", Disposition: MappedViaAdapter, Target: "internal/productb/vulnerability", Note: "full port of composite.go/osv.go/source.go — Shadow's vulnerability package lacks the freeze/composite machinery"},
		{V2Type: "repository.* (Clone/EnumerateRefs/RefInfo/NewWorktree/BinaryBuildInfo/CheckPathReplacements/DiscoverReleaseEvidence/contenthash/preflight)", V2Package: "internal/repository", ReferencedBy: "materialize.go, ref.go, materials.go, tools.go", Disposition: MappedViaAdapter, Target: "internal/productb/repository", Note: "V2 service.go contenthash.go preflight.go releaseevidence.go verbatim; Shadow repository lacks Clone/EnumerateRefs and returns different release-evidence types"},
		{V2Type: "syscall.Flock sites in agenttriage.artifacts claimRunDir (.owner.lock)", V2Package: "internal/flock", ReferencedBy: "artifacts.go claimRunDir", Disposition: MappedToCanonical, Target: "internal/flock", Note: "Shadow-new shared primitive — flock(2) on unix, LockFileEx on Windows, fail-closed ErrUnsupported elsewhere; the ported code never binds syscall.Flock directly (Windows build matrix)"},

		// --- ported Product B types (adapter-only — never authority) ---
		{V2Type: "agenttriage.Finding/FindingInput/Assessment", V2Package: "internal/agenttriage", ReferencedBy: "types.go, input.go, decode.go", Disposition: AdapterOnly, Note: "finding.v1/assessment.v3 are Product B live schemas; prior assessments are historical only, never upgraded into Product A authority"},
		{V2Type: "agenttriage.FalsifierProposal", V2Package: "internal/agenttriage", ReferencedBy: "types.go, decode.go, conditioncatalog.go AdmitFalsifierProposal", Disposition: AdapterOnly, Note: "proposal-only ingress; forbidden authority fields rejected at decode; bound to condition-catalog entries, never to a verdict"},
		{V2Type: "agenttriage.FactValidation/Check/FactStatus", V2Package: "internal/agenttriage", ReferencedBy: "factgate.go, factfeedback.go", Disposition: AdapterOnly, Note: "fact-gate.v1 is reproducibility evidence, never a proof"},
		{V2Type: "agenttriage.ToolObservation/ToolAuditEvent/ObservationPin", V2Package: "internal/agenttriage", ReferencedBy: "tools.go, tool_audit.go", Disposition: AdapterOnly, Note: "hash-only audit records; not domain observations"},
		{V2Type: "agenttriage.RecordedObservation/ObservationArchive", V2Package: "internal/agenttriage", ReferencedBy: "observation_archive.go", Disposition: AdapterOnly, Note: "observation-archive.v2 stores each canonical observation payload once in a digest-keyed payload table and projects entries by data_sha256 (unresolved or mismatched references fail the read); observation-archive.v1 stays readable as history only — run-bound, hash-verified Product B storage either way"},
		{V2Type: "agenttriage.SnapshotManifest/SnapshotFile/Materializer", V2Package: "internal/agenttriage", ReferencedBy: "snapshot.go, materialize.go, catalog.go, ref.go", Disposition: AdapterOnly, Note: "snapshot.v1 manifest + bounded materialization; no current-HEAD fallback"},
		{V2Type: "agenttriage.ReadOnlyTools", V2Package: "internal/agenttriage", ReferencedBy: "tools.go", Disposition: AdapterOnly, Note: "read_only bounded root-confined snapshot surface; det:/obs: resolution stays on the archive index"},
		{V2Type: "agenttriage.intake/stage0/siteconfig/ref/catalog/materials/validation", V2Package: "internal/agenttriage", ReferencedBy: "stage0.go, intake_*.go, siteconfig.go, ref.go, catalog.go, materials.go, validation_rules.go", Disposition: AdapterOnly, Note: "strict schemas, bounded ref selection, raw bytes/proposal hash retained, technical errors on a separate channel"},
		{V2Type: "agenttriage.ArtifactWriter/RawAgent/ErrorDocument/audit", V2Package: "internal/agenttriage", ReferencedBy: "artifacts.go, audit.go, intake_audit.go", Disposition: AdapterOnly, Note: "raw-agent.v1, triage-error.v1, fact-gate.json, metrics.json, run/attempt-bound audit"},
		{V2Type: "agenttriage.falsifier verifier", V2Package: "internal/agenttriage", ReferencedBy: "falsifier.go, unreachability_proof.go, certificate.go, mandatory_conditions.go", Disposition: AdapterOnly, Note: "deterministic falsifier verification chain; proposal-only, catalog-bound admission; falsifier proposals are optional for a human assessment"},
		{V2Type: "agenttriage.Runner/ChatClient/AgentRun/prompt/chat", V2Package: "internal/agenttriage", ReferencedBy: "runner.go, prompt.go, chat.go, providers.go, stability.go, metrics.go, decision_rules.go, policy.go", Disposition: AdapterOnly, Note: "agent loop + deterministic mechanics"},
		{V2Type: "agenttriage.composer/vex_projection/replay", V2Package: "internal/agenttriage", ReferencedBy: "composer.go, support.go, human_branches.go, environment_answers.go, vex_projection.go, replay.go, human_decision.go, evaluation.go (S-08/S-09)", Disposition: AdapterOnly, Note: "decision-package.v4 separates judgment/action/support/machine disposition and captures complete bounded prepared branches; environment-assertion.v1 is a human premise, never a machine fact; human-decision.v2 binds package/branch/projection/assertion identities with optional comment; replay.v2 copies history verbatim without authority upgrade; triage-vex-projection.v1 is non-authoritative and triage-evaluation.v1 offline-only"},
		{V2Type: "investigation-inputs.v1 / prompt-input.v1 DTOs", V2Package: "(new Product B surface)", ReferencedBy: "investigation_inputs.go, prompt.go, tools.go read_material, replay.go", Disposition: AdapterOnly, Note: "captured advisory/fix bytes are untrusted data archived by digest; read_material returns bounded slices; prompt-input.v1 records the exact prompt surface for replay; neither grants proof authority or mints a Product A identity"},
		{V2Type: "claimshape.*", V2Package: "internal/claimshape", ReferencedBy: "internal/productb/claimshape (S-10)", Disposition: AdapterOnly, Note: "canonical claim-shape normalization; UNSUPPORTED is explicit, never a silent admit; no verdict output"},
		{V2Type: "verification.* (renamed productb/verify)", V2Package: "internal/verification", ReferencedBy: "internal/productb/verify (S-10)", Disposition: AdapterOnly, Note: "universal verification chain: graph/evaluate/interpret/live/payload/replay/stability/certificates over triage DTOs; VALID locator is presence, not proof"},
		{V2Type: "research.*", V2Package: "internal/research", ReferencedBy: "internal/productb/research (S-12)", Disposition: AdapterOnly, Note: "B1 CVE research lane: frozen prompt hash (frozenOfficialSHA256 local constant), replay offline, grounding/consistency reports; output is non-authoritative and never mutates Product A case/verdict/VEX"},
		{V2Type: "refindex.*", V2Package: "internal/refindex", ReferencedBy: "internal/productb/refindex (S-12)", Disposition: AdapterOnly, Note: "izyan-refindex/1 frozen document: advisory digests, decl/usage atoms, fix-diff summary; domain types via productb/domain aliases, canonical goanalysis/fix seams"},
		{V2Type: "agenttriage.siteconfig.DeploymentConfig + collectDeployFacts + declared-assumptions channel", V2Package: "internal/agenttriage", ReferencedBy: "internal/productb/triage (siteconfig/materials) + internal/productb/deployment (S-13)", Disposition: AdapterOnly, Note: "deployment/assumption adapter: DeployFacts + disjoint basis projection (declared-trust via AdmitAssumption on productb/repository channel, auto-perimeter via canonical exposure.ClassifyPerimeter, config-origin fact count); missing manifests = unknown, never isolation; foreign services unattributed; DeploymentProjection schema deployment-projection.v1; no verdict, no evidence ids"},
		{V2Type: "heldoutgate.*", V2Package: "internal/heldoutgate", ReferencedBy: "internal/productb/heldoutgate + cmd/izyan-heldout-gate (S-11)", Disposition: AdapterOnly, Note: "offline held-out gate: corpus replay, absence probe via evidencetools.Client (Shadow has no Session.CallTool — Connect/Client.Call keeps the audited Observation contract), §8.3 hard gates, mutations, 5×3 stability; measurement only — capability stays default-off; Session.CallTool→sess.Connect()+Client.Call adaptation recorded"},

		// --- still deferred ---
		{V2Type: "evaluator.*", V2Package: "internal/evaluator", ReferencedBy: "(V2 offline eval only)", Disposition: Dropped, Note: "Product B evaluator must not reach Product A authority; research-only if ever revived"},

		// --- Product A authority types (never mapped — hard boundary) ---
		{V2Type: "domain.Claim/NegativeVerification/VerdictResult/AnalysisCase", V2Package: "internal/domain", ReferencedBy: "boundary_test.go import guard; productb/domain exports them not", Disposition: Dropped, Note: "no assessment→Claim/NV/Verdict mapping exists or may be added"},
	}
}

// PortTypeMapJSON emits the mandatory artifact form of the table.
func PortTypeMapJSON() ([]byte, error) {
	return json.MarshalIndent(struct {
		SchemaVersion string         `json:"schema_version"`
		Entries       []TypeMapEntry `json:"entries"`
	}{SchemaVersion: PortTypeMapSchemaVersion, Entries: PortTypeMap()}, "", "  ")
}

// RequiredDispositions is the closed enum the completeness test pins.
var RequiredDispositions = []TypeDisposition{MappedToCanonical, MappedViaAdapter, AdapterOnly, Unsupported, Dropped}
