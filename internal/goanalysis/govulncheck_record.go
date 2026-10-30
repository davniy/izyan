package goanalysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// RecordForCase returns the loaded-record projection target for a case. A
// case pinned to exact bytes projects against those bytes; a legacy case
// without a pin projects identity-only and records no byte proof.
func RecordForCase(c *domain.AnalysisCase) vulnerability.LoadedRecord {
	if c == nil {
		return vulnerability.LoadedRecord{}
	}
	record := vulnerability.LoadedRecord{Vuln: &c.Vulnerability}
	if c.RecordPin != nil {
		record.Pin = *c.RecordPin
	}
	return record
}

// CollectGovulncheck runs govulncheck once for one exact advisory record and
// returns one durable EvidenceGovulncheck record plus the parsed result.
//
// The raw stream is a product measurement of the whole database: callers may
// cache the runner's bytes per BuildContext and re-project the same stream for
// another record. Coverage and findings are never shared, though — the
// returned record is projected against record's own id, pin and declared
// subjects, so a document sharing its CVE key cannot fill its coverage.
//
// The record is produced on every path:
//
//   - nil runner             → not_run
//   - process error/timeout  → failed (a parseable prefix is never a result)
//   - undecodable stream     → failed
//   - record binding failure → failed (another record's bytes can never back it)
//   - valid stream, findings → completed_with_results
//   - valid stream, none     → completed_empty
//
// Call paths are only attached by callers for completed runs; a failed run
// returns an empty Result so a partial prefix can never become a
// measurement. Raw output is preserved in Evidence.Content for audit.
func CollectGovulncheck(
	ctx context.Context,
	runner Runner,
	build domain.ProductSnapshot,
	record vulnerability.LoadedRecord,
) (domain.Evidence, Result) {
	buildContext := domain.EffectiveBuildContext(build)
	mode := "source"
	if build.BinaryPath != "" {
		mode = "binary"
	}
	run := &domain.GovulncheckRun{
		Mode: mode,
		Coverage: domain.GovulncheckCoverage{
			AdvisoryID: recordIdentity(record),
			Advisory:   domain.GovulncheckCoverageUnknown,
			Record:     coverageRecordPin(record),
		},
	}
	ev := domain.Evidence{
		Kind:         domain.EvidenceGovulncheck,
		Quality:      domain.QualityDeterministic,
		Tool:         "govulncheck",
		Repository:   build.Repository,
		Commit:       build.Commit,
		BuildContext: &buildContext,
		Govulncheck:  run,
	}

	if runner == nil {
		run.Outcome = domain.GovulncheckNotRun
		run.Error = "govulncheck runner not configured"
		ev.Source = "govulncheck (not run)"
		ev.Limitations = append(ev.Limitations, "govulncheck did not run: "+run.Error)
		return ev, Result{}
	}

	// The DB snapshot identity doubles as the tool's version for the audit
	// trail and explains an advisory the scanned database never mentioned.
	if informer, ok := runner.(DBInformer); ok {
		if info, err := informer.DBInfo(ctx); err == nil {
			ev.ToolVersion = info
		}
	}

	raw, pattern, runErr := runner.RunGovulncheck(ctx, build.Repository, build)
	ev.Content = string(raw)
	run.Pattern = pattern
	command := "govulncheck -json -mode " + mode
	if pattern != "" {
		command += " " + pattern
	}
	ev.Command = command
	ev.Source = command

	if runErr != nil {
		run.Outcome = domain.GovulncheckFailed
		run.Error = runErr.Error()
		ev.Limitations = append(ev.Limitations, "govulncheck failed: "+runErr.Error())
		return ev, Result{}
	}

	res, parseErr := Parse(raw)
	if parseErr != nil {
		run.Outcome = domain.GovulncheckFailed
		run.Error = "parse: " + parseErr.Error()
		ev.Limitations = append(ev.Limitations,
			"govulncheck output could not be decoded: "+parseErr.Error())
		return ev, Result{}
	}

	if res.Config.ScanMode != "" {
		run.Mode = res.Config.ScanMode
	}
	run.ScanLevel = res.Config.ScanLevel
	if ev.ToolVersion == "" {
		// Runners without the DBInformer capability still name the database
		// they scanned in the stream config; keep that provenance.
		ev.ToolVersion = configIdentity(res.Config)
	}
	res.ScopeComplete = completeScanScope(build, pattern)
	bindEmittedRecord(&res, record)
	projection, projErr := res.ProjectRecord(record)
	if projErr != nil {
		// A stream cannot be re-bound to different bytes claiming the same
		// record id. Failing the measurement keeps the other document's
		// output out of this record's evidence.
		run.Outcome = domain.GovulncheckFailed
		run.Error = projErr.Error()
		ev.Limitations = append(ev.Limitations, "govulncheck record projection failed: "+projErr.Error())
		return ev, Result{}
	}
	run.Coverage = projection.Coverage
	if projection.Coverage.Advisory != domain.GovulncheckCoverageCovered {
		lim := "govulncheck emitted no findings referencing this advisory; " +
			"reachability was not evaluated (silence is not evidence of no path)"
		if ev.ToolVersion != "" {
			modified := ""
			if record.Vuln != nil {
				modified = record.Vuln.Modified
			}
			lim += fmt.Sprintf(" (local DB: %s; advisory modified: %s)",
				ev.ToolVersion, orUnknown(modified))
		}
		ev.Limitations = append(ev.Limitations, lim)
	}
	if !run.Coverage.ScopeComplete {
		ev.Limitations = append(ev.Limitations, fmt.Sprintf(
			"govulncheck ran on narrowed scope %s; packages outside the pattern were not analyzed",
			strings.TrimSpace(pattern)))
	}

	if len(res.Findings) > 0 {
		run.Outcome = domain.GovulncheckCompletedWithResults
	} else {
		run.Outcome = domain.GovulncheckCompletedEmpty
	}
	return ev, res
}

// recordIdentity is the record's own id: the pin's identity when present,
// otherwise the decoded document's id. An alias is never an identity here.
func recordIdentity(record vulnerability.LoadedRecord) string {
	if id := strings.TrimSpace(record.Pin.RecordID); id != "" {
		return id
	}
	if record.Vuln != nil {
		return strings.TrimSpace(record.Vuln.ID)
	}
	return ""
}

// coverageRecordPin binds durable coverage only to a digest-pinned record; an
// identity-only record has no byte proof to record.
func coverageRecordPin(record vulnerability.LoadedRecord) *domain.RecordPin {
	pin := record.Pin
	if pin.Validate() != nil {
		return nil
	}
	return &pin
}

// bindEmittedRecord attaches the exact pin to the emitted entry for this
// record's own id. A later projection for the same id but different bytes is
// then rejected instead of inheriting this run's output.
func bindEmittedRecord(res *Result, record vulnerability.LoadedRecord) {
	id := recordIdentity(record)
	if id == "" {
		return
	}
	bound := record.Pin
	if bound.RecordID == "" {
		bound.RecordID = id
	}
	for i := range res.EmittedAdvisories {
		if res.EmittedAdvisories[i].Record.RecordID == id {
			res.EmittedAdvisories[i].Record = bound
		}
	}
}

// completeScanScope reports whether the run's actual pattern measured the
// whole analyzed build. A binary scan measures exactly the artifact;
// source mode measures the whole tree only for "./...". Narrowed fallback
// patterns are partial scope — a directory/main-file heuristic never grants
// completeness.
func completeScanScope(build domain.ProductSnapshot, pattern string) bool {
	if build.BinaryPath != "" {
		return true
	}
	return pattern == "./..."
}

// configIdentity renders the stream's database/tool identity when the
// runner cannot report DB provenance directly.
func configIdentity(cfg ProtocolConfig) string {
	var parts []string
	if scanner := strings.TrimSpace(cfg.ScannerName + " " + cfg.ScannerVersion); scanner != "" {
		parts = append(parts, "scanner "+scanner)
	}
	if cfg.DB != "" {
		parts = append(parts, "db: "+cfg.DB)
	}
	if cfg.DBLastModified != "" {
		parts = append(parts, "updated: "+cfg.DBLastModified)
	}
	return strings.Join(parts, "; ")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
