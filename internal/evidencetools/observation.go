// Package evidencetools exposes Izyan's deterministic analyzers to an
// external agent as typed evidence tools (Task 4.1, spec §6). Every call
// returns an Observation: a fact plus the honest scope and completeness
// of the check that produced it. The package never emits verdicts,
// claims or other production-conclusion shapes; completeness defaults to
// PARTIAL and COMPLETE is reserved for closed, enumerated scopes.
package evidencetools

import (
	"encoding/json"
	"fmt"
	"github.com/fedorovmv/izyan/internal/domain"
)

// Completeness states how much of the declared scope the check covered.
// The default is PARTIAL; COMPLETE requires a closed, enumerable scope
// that was fully examined without errors, skips or truncation.
type Completeness string

const (
	// CompletenessComplete — the closed scope named in ScopeDetails was
	// fully examined (e.g. a specific byte range of a specific file, the
	// enumerated module list). Never assigned to ERROR/UNSUPPORTED or to
	// queries over open search spaces (callers, dataflow, dynamic scan).
	CompletenessComplete Completeness = "COMPLETE"
	// CompletenessPartial — the check ran, but covers only part of the
	// relevant space (product roots only, capped results, skipped
	// packages, incomplete dispatch resolution, single build context).
	CompletenessPartial Completeness = "PARTIAL"
	// CompletenessUnknown — coverage cannot be characterized (opaque
	// analysis, budget exhaustion, or the check did not run).
	CompletenessUnknown Completeness = "UNKNOWN"
)

// ToolStatus is the execution outcome of a tool call.
type ToolStatus string

const (
	// StatusOK — the check executed; Data holds the result. An empty
	// result with COMPLETE is "absent in a closed scope"; with PARTIAL it
	// is "not found in the checked part" — never a safety claim.
	StatusOK ToolStatus = "OK"
	// StatusError — the check was attempted and failed. No coverage claim
	// is made; Data is empty.
	StatusError ToolStatus = "ERROR"
	// StatusTimeout — the check exceeded the session's per-tool time
	// bound and was abandoned. No coverage claim is made; Data is empty.
	StatusTimeout ToolStatus = "TIMEOUT"
	// StatusUnsupported — the capability does not exist in this build or
	// is disabled by policy (e.g. exec tools without --allow-exec).
	StatusUnsupported ToolStatus = "UNSUPPORTED"
)

// Observation is the contract object returned by every evidence tool
// (spec §6.1). Fact describes what was observed; Scope + ScopeDetails
// pin down where; Completeness says how much of that scope was really
// covered. An Observation is never a verdict.
type Observation struct {
	ID           string        `json:"id"`
	Tool         string        `json:"tool"`
	Fact         string        `json:"fact"`
	Scope        string        `json:"scope"`
	Completeness Completeness  `json:"completeness"`
	ToolStatus   ToolStatus    `json:"tool_status"`
	EvidenceRefs []string      `json:"evidence_refs,omitempty"`
	Limitations  []string      `json:"limitations,omitempty"`
	ScopeDetails *ScopeDetails `json:"scope_details,omitempty"`
	Error        string        `json:"error,omitempty"`
	// Data is the typed payload of the tool (call sites, modules, source
	// text...). nil for ERROR/UNSUPPORTED observations. For an
	// authoritative check whose payload exceeds the persisted display
	// bound, Data carries only a bounded externalization envelope and
	// PayloadRef pins the complete hash-bound payload sidecar.
	Data any `json:"data,omitempty"`
	// PayloadRef, when present, pins the complete externalized payload:
	// the observation's persisted Data member is a bounded envelope and
	// the authoritative bytes live at the named artifact, verified by
	// sha256 + size before any decode. nil for inline payloads.
	PayloadRef *ObservationPayloadRef `json:"payload_ref,omitempty"`
}

// ObservationPayloadRef is the hash-and-size pin of an observation
// payload externalized to a content-addressed sidecar artifact: the
// persisted observation stays bounded while the complete typed payload
// remains recoverable and tamper-evident. Path is relative to the run
// output directory; SHA256 and SizeBytes pin the exact sidecar bytes;
// Selector names what the sidecar is.
type ObservationPayloadRef struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Selector  string `json:"selector"`
}

// EvidenceClass names how a registered check's successful payload is
// interpreted. The class is tool-contract metadata published by the
// registry: it is never inferred from the tool's name, so a broker records
// exactly the classification the contract declared and cannot keep a second
// name allowlist beside it.
//
// A class states what MAY be positive. Only the typed payload decoder
// decides whether one response actually is: an empty site set, a zero-finding
// govulncheck scan or an inventory fact is never positive evidence.
type EvidenceClass string

const (
	// EvidenceNone — the payload never counts as positive reachability or
	// usage evidence (declarations, source text, guards, configuration and
	// inventory facts).
	EvidenceNone EvidenceClass = ""
	// EvidenceSiteSet — a caller/reference/module-usage site set: a
	// non-zero `count` or `possible_count` is a concrete positive site.
	EvidenceSiteSet EvidenceClass = "site_set"
	// EvidenceGovulncheck — a govulncheck payload: a reported finding with a
	// non-empty trace means the vulnerable symbol is reachable in the scan;
	// a clean scan proves nothing positive.
	EvidenceGovulncheck EvidenceClass = "govulncheck"
	// EvidenceDepInvocation — a dep_invocation_state payload: in-module
	// callers or an explicitly unbounded caller set are positive.
	EvidenceDepInvocation EvidenceClass = "dep_invocation"
)

// valid reports whether the class is one of the registry's declared
// observation contracts. A misspelled class in the table is a defect, never
// a silently inert contract.
func (c EvidenceClass) valid() bool {
	switch c {
	case EvidenceNone, EvidenceSiteSet, EvidenceGovulncheck, EvidenceDepInvocation:
		return true
	}
	return false
}

// PositiveEvidence reports whether one completed observation is positive
// reachability/usage evidence under the class its tool contract declares.
//
// Only an OK observation can be positive; ERROR, TIMEOUT and UNSUPPORTED
// carry no fact. Within an OK observation the class selects the typed payload
// decoder, so marking a tool as potentially reachability-bearing does not
// make every successful response positive: an empty result stays negative.
func PositiveEvidence(class EvidenceClass, obs *Observation) bool {
	if obs == nil || obs.ToolStatus != StatusOK || obs.Data == nil {
		return false
	}
	raw, err := json.Marshal(obs.Data)
	if err != nil {
		return false
	}
	switch class {
	case EvidenceSiteSet:
		var d struct {
			Count         int `json:"count"`
			PossibleCount int `json:"possible_count"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return false
		}
		return d.Count > 0 || d.PossibleCount > 0
	case EvidenceGovulncheck:
		var d struct {
			Count    int `json:"count"`
			Findings []struct {
				Trace []json.RawMessage `json:"trace"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return false
		}
		if d.Count > 0 {
			return true
		}
		for _, f := range d.Findings {
			if len(f.Trace) > 0 {
				return true
			}
		}
		return false
	case EvidenceDepInvocation:
		var d struct {
			CallersInsideModule int  `json:"callers_inside_module"`
			Unbounded           bool `json:"unbounded"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return false
		}
		return d.CallersInsideModule > 0 || d.Unbounded
	default:
		return false
	}
}

// ScopeDetails records the actual boundaries of the performed check —
// built by the adapter from what really ran, not from the request.
type ScopeDetails struct {
	SnapshotHash    string        `json:"snapshot_hash,omitempty"`
	SnapshotRoot    string        `json:"snapshot_root,omitempty"`
	ExternalSHA     string        `json:"external_sha,omitempty"`
	Subject         string        `json:"subject,omitempty"`
	BuildContext    *BuildContext `json:"build_context,omitempty"`
	Packages        []string      `json:"packages,omitempty"`
	SkippedPackages []string      `json:"skipped_packages,omitempty"`
	// Profile names the session profile that bounded the check
	// ("strict" or "default") so every audit record is self-describing.
	Profile string `json:"profile,omitempty"`
	// ReadRoots are the canonical confinement roots the session's read
	// gate enforced (snapshot + declared roots); empty when unconfined.
	ReadRoots []string `json:"read_roots,omitempty"`
	// ToolchainEnv is the env the session applied to every toolchain
	// subprocess (resolved toolchain plus hardening overrides).
	ToolchainEnv []string `json:"toolchain_env,omitempty"`
	// InheritedEnvKeys names the ambient variables subprocesses inherit
	// beyond ToolchainEnv, so the recorded scope is truthful about the
	// effective environment (key names only, never values).
	InheritedEnvKeys []string          `json:"inherited_env_keys,omitempty"`
	Limits           *ScopeLimits      `json:"limits,omitempty"`
	CoverageRule     string            `json:"coverage_rule,omitempty"`
	CoverageRuleVers string            `json:"coverage_rule_version,omitempty"`
	InventoryRef     string            `json:"inventory_ref,omitempty"`
	Extra            map[string]string `json:"extra,omitempty"`
}

// BuildContext is the build configuration the analysis ran under.
type BuildContext struct {
	EffectiveBuild *domain.BuildContext `json:"effective_build,omitempty"`
	GOOS       string   `json:"goos,omitempty"`
	GOARCH     string   `json:"goarch,omitempty"`
	CGOEnabled bool     `json:"cgo_enabled"`
	BuildTags  []string `json:"build_tags,omitempty"`
	GoVersion  string   `json:"go_version,omitempty"`
	VendorMode bool     `json:"vendor_mode,omitempty"`
	// Toolchain binds the check to the resolved toolchain identity —
	// version when known, otherwise the binary path it ran through —
	// so two observations taken under different toolchains can never
	// share a build-context hash.
	Toolchain string `json:"toolchain,omitempty"`
}

// ScopeLimits enumerates the limits that bounded the check. Fields are
// omitempty so a zero means "not applicable", not "unbounded".
type ScopeLimits struct {
	MaxMatches      int  `json:"max_matches,omitempty"`
	Truncated       bool `json:"truncated,omitempty"`
	HopBudget       int  `json:"hop_budget,omitempty"`
	LoadBudgetLeft  int  `json:"load_budget_left,omitempty"`
	OutputTruncated bool `json:"output_truncated,omitempty"`
	// FullPayloadSHA256 / FullPayloadSizeBytes pin the complete payload
	// when the persisted `data` member does not carry it verbatim:
	// either the lane's payload cap truncated the stored bytes (only a
	// prefix was retained) or the payload was externalized to the
	// content-addressed sidecar Observation.PayloadRef names — the
	// digest covers the exact sidecar bytes. Empty/zero when the stored
	// payload is the complete result.
	FullPayloadSHA256    string `json:"full_payload_sha256,omitempty"`
	FullPayloadSizeBytes int64  `json:"full_payload_size_bytes,omitempty"`
}

// evidenceRef renders a stable, hash-bearing reference to a blob of
// tool-produced content the controller can resolve later.
func evidenceRef(kind, locator string, payload []byte) string {
	sum := sha256Of(payload)
	if len(sum) > 16 {
		sum = sum[:16]
	}
	return fmt.Sprintf("ev:%s:%s@%s", kind, locator, sum)
}

// marshalData stores a typed payload and derives an evidence ref naming
// its sha256, so every returned fact is anchored to the exact bytes.
func marshalData(v any) (any, string, error) {
	if v == nil {
		return nil, "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", fmt.Errorf("marshal tool payload: %w", err)
	}
	sum := sha256Of(b)
	return v, "sha256:" + sum, nil
}
