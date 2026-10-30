package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GovulncheckOutcome is the durable result of one govulncheck invocation.
// It is recorded on every invocation path so downstream consumers never
// infer success from evidence presence.
type GovulncheckOutcome string

const (
	// GovulncheckCompletedWithResults: a valid stream completed and reported
	// at least one finding (for any advisory — the stream covers the whole
	// vulnerability database).
	GovulncheckCompletedWithResults GovulncheckOutcome = "completed_with_results"
	// GovulncheckCompletedEmpty: a valid stream completed with no findings.
	// Silence is a negative candidate only with full advisory, subject and
	// scope coverage.
	GovulncheckCompletedEmpty GovulncheckOutcome = "completed_empty"
	// GovulncheckFailed: the process failed, was cancelled, timed out, or its
	// output did not decode. A parseable prefix is not a measurement.
	GovulncheckFailed GovulncheckOutcome = "failed"
	// GovulncheckNotRun: govulncheck was requested but never executed (nil
	// runner, refused auxiliary tool action).
	GovulncheckNotRun GovulncheckOutcome = "not_run"
)

// GovulncheckAdvisoryCoverage states whether the advisory under analysis was
// actually evaluated by the run that produced the record.
type GovulncheckAdvisoryCoverage string

const (
	// GovulncheckCoverageUnknown: the run did not establish coverage.
	GovulncheckCoverageUnknown GovulncheckAdvisoryCoverage = "unknown"
	// GovulncheckCoverageCovered: the scanned database knew the advisory (its
	// OSV document or a finding referencing it appeared in the stream).
	GovulncheckCoverageCovered GovulncheckAdvisoryCoverage = "covered"
	// GovulncheckCoverageNotInDB: the completed stream never mentioned the
	// advisory — silence says nothing about reachability.
	GovulncheckCoverageNotInDB GovulncheckAdvisoryCoverage = "not_in_db"
)

// GovulncheckCoverage names what one run actually covered, for exactly one
// advisory record.
type GovulncheckCoverage struct {
	AdvisoryID string `json:"advisory_id"`
	// Record pins the exact record this coverage belongs to. It is present
	// only when the run was projected for a digest-pinned loaded record;
	// nil means the run carries identity metadata only and cannot prove
	// which document bytes it assessed. A second document sharing the same
	// CVE key, an alias or a related edge never inherits this binding.
	Record *RecordPin `json:"record,omitempty"`
	// Advisory is the run's coverage of the record with this own id.
	// Coverage of another record is never implied by a shared CVE key.
	Advisory GovulncheckAdvisoryCoverage `json:"advisory"`
	// Modules are the affected modules the emitting document declares AND
	// the record's own declarations bind. They are the module half of the
	// record-specific binding; a document sharing the record's CVE key
	// contributes nothing here.
	Modules []string `json:"modules,omitempty"`
	// Subjects are the advisory-declared symbols from the record's own
	// emitted OSV document, intersected with the record's own declarations.
	// A completed-empty silence can only falsify subjects in this set —
	// govulncheck traces to declared vulnerable symbols.
	Subjects []SymbolRef `json:"subjects,omitempty"`
	// ScopeComplete is true only when the run's actual pattern covered the
	// whole analyzed build. A narrowed fallback pattern is partial scope.
	ScopeComplete bool `json:"scope_complete"`
}

// GovulncheckRun is the durable record of one govulncheck invocation.
// Raw output stays in Evidence.Content; findings stay in the parsed result —
// this record carries only the run's identity and outcome.
type GovulncheckRun struct {
	Outcome   GovulncheckOutcome  `json:"outcome"`
	Pattern   string              `json:"pattern,omitempty"`
	Mode      string              `json:"mode,omitempty"`
	ScanLevel string              `json:"scan_level,omitempty"`
	Coverage  GovulncheckCoverage `json:"coverage"`
	Error     string              `json:"error,omitempty"`
}

// PackageListRun is the durable record of one `go list` inventory call.
type PackageListRun struct {
	Completed bool   `json:"completed"`
	Complete  bool   `json:"complete"`
	WithTests bool   `json:"with_tests"`
	// RawSHA256 binds newly measured inventories to the full Evidence.Content.
	// Historical records without it still require strict downstream decoding.
	RawSHA256 string `json:"raw_sha256,omitempty"`
	Pattern   string `json:"pattern"`
	Error     string `json:"error,omitempty"`
}

// SourceScanRun is the durable coverage record of one source-level scan.
type SourceScanRun struct {
	Module       string      `json:"module"`
	Subjects     []SymbolRef `json:"subjects,omitempty"`
	EntrySymbols []string    `json:"entry_symbols,omitempty"`
	Completed    bool        `json:"completed"`
	Complete     bool        `json:"complete"`
	Opaque       bool        `json:"opaque"`
}

// SelectCompletePackageList returns the completed, complete package-list
// evidence whose recorded build context matches the product snapshot. It is
// a pure metadata selector: it does not decode Content. Callers must still
// apply the strict package decoder to the returned evidence.
func SelectCompletePackageList(product ProductSnapshot, evidence []Evidence) (Evidence, error) {
	effective := EffectiveBuildContext(product)
	var selected *Evidence
	for i := range evidence {
		e := &evidence[i]
		if e.Kind != EvidencePackageList || e.PackageList == nil {
			continue
		}
		if !e.PackageList.Completed || !e.PackageList.Complete || e.PackageList.Pattern != "./..." || e.PackageList.Error != "" {
			continue
		}
		if e.PackageList.RawSHA256 != "" {
			sum := sha256.Sum256([]byte(e.Content))
			if hex.EncodeToString(sum[:]) != e.PackageList.RawSHA256 { continue }
		}
		if e.BuildContext == nil {
			continue
		}
		if err := e.BuildContext.Matches(effective); err != nil {
			continue
		}
		selected = e
	}
	if selected == nil {
		return Evidence{}, fmt.Errorf(
			"no completed, complete package-list evidence matches the effective build context")
	}
	return *selected, nil
}
