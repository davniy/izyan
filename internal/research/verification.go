package research

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// EvidenceCallFunc executes one bounded typed check against the
// confined evidence session created for this case. The only
// production implementation is EvidenceSession.Call: agent-requested
// checks run inside the same strict session as the deterministic lane
// — same confinement roots, same per-tool timeout, same audit trail —
// and no unconfined tool path exists.
type EvidenceCallFunc func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, error)

// VerificationTrace records one bounded verification phase.
// Requests is the declared check list; Observations mirrors the
// executed prefix of it one-to-one — every dispatched request has an
// observation, including a synthesized ERROR record when the call
// produced none. Unexecuted checks always form a contiguous tail of
// Requests and are named in Limitations. Observation IDs, tool
// status, completeness, scope details, build context, evidence refs
// and per-observation limitations are kept verbatim; nothing in the
// trace promotes or upgrades a partial, degraded or empty result —
// the decision function sees exactly what the session recorded.
type VerificationTrace struct {
	Requests     []VerificationRequest        `json:"requests"`
	Observations []*evidencetools.Observation `json:"observations"`
	Limitations  []string                     `json:"limitations,omitempty"`
	// Complete is true only when every declared check executed and
	// every observation came back OK with COMPLETE completeness.
	Complete bool `json:"complete"`
}

// RunVerificationPlan executes an agent-proposed verification plan in
// declared order over the confined evidence session. Execution is
// bounded by maxCalls and additionally hard-capped at
// maxVerificationChecks (8) for this slice; checks beyond the cap,
// checks skipped because the context ended, transport-level tool
// failures and degraded tool results are all recorded as limitations
// — checks are never retried and a missing observation becomes a
// synthesized ERROR record rather than a silent skip. The trace keeps
// every returned observation verbatim; an empty result is never
// promoted without the observation's own closed scope.
// AuditedCallFunc executes one bounded typed check like
// EvidenceCallFunc and additionally returns the session audit record
// the call appended — the authoritative record of the tool and
// arguments actually dispatched. A nil record means the session did
// not record the call at all (transport failure before dispatch or an
// out-of-session fake); such calls can never ground a terminal
// negative because what the session ran is unverifiable.
type AuditedCallFunc func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error)

// RunVerificationPlan is the audit-agnostic entry point kept for
// callers that only need the observations; no session binding is
// asserted. The production path is RunVerificationPlanAudited — only
// it binds every dispatched request to what the session recorded.
func RunVerificationPlan(ctx context.Context, call EvidenceCallFunc, plan VerificationPlan, maxCalls int) (*VerificationTrace, error) {
	if call == nil {
		return nil, errors.New("verification requires an evidence call function over the confined session")
	}
	return runVerification(ctx, func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		obs, err := call(ctx, tool, args)
		return obs, nil, err
	}, plan, maxCalls, false)
}

// RunVerificationPlanAudited is RunVerificationPlan over an audited
// call path. Each dispatched request is bound to the session audit
// record the call produced: the audit-recorded tool and the canonical
// digest of the audit-recorded arguments must equal the declared
// request's. A call the session never recorded, or whose recorded
// tool/arguments differ from what was declared, is marked as a
// limitation and makes the trace incomplete — an observation returned
// for subject A can never be credited to a request declaring subject B.
func RunVerificationPlanAudited(ctx context.Context, call AuditedCallFunc, plan VerificationPlan, maxCalls int) (*VerificationTrace, error) {
	if call == nil {
		return nil, errors.New("verification requires an evidence call function over the confined session")
	}
	return runVerification(ctx, call, plan, maxCalls, true)
}

func runVerification(ctx context.Context, call AuditedCallFunc, plan VerificationPlan, maxCalls int, bindAudit bool) (*VerificationTrace, error) {
	if call == nil {
		return nil, errors.New("verification requires an evidence call function over the confined session")
	}
	if maxCalls < 0 {
		return nil, fmt.Errorf("verification call cap %d is negative", maxCalls)
	}
	budget := min(maxCalls, maxVerificationChecks)
	trace := &VerificationTrace{Requests: append([]VerificationRequest(nil), plan.Checks...), Complete: true}
	// Plan admission is the caller's contract: ValidateVerificationPlan
	// already rejects checks the check catalog does not admit (registered
	// check id, capability, schema-satisfying arguments). The runner does
	// not re-admit at dispatch — a mid-flight rejection would only
	// record a limitation a validated plan can never produce.
	for i, req := range trace.Requests {
		if i >= budget {
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"verification check %q (tool %s) skipped: call budget %d exhausted", req.ID, req.Tool, budget))
			trace.Complete = false
			continue
		}
		if err := ctx.Err(); err != nil {
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"verification check %q (tool %s) skipped: context ended before dispatch: %v", req.ID, req.Tool, err))
			trace.Complete = false
			continue
		}
		obs, rec, callErr := call(ctx, req.Tool, req.Arguments)
		if callErr == nil && bindAudit {
			if why := callAuditMismatch(req, obs, rec); why != "" {
				trace.Limitations = append(trace.Limitations, fmt.Sprintf(
					"verification check %q (tool %s) %s", req.ID, req.Tool, why))
				trace.Complete = false
			}
		}
		if callErr != nil {
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"verification check %q (tool %s) produced no observation: %v", req.ID, req.Tool, callErr))
			obs = &evidencetools.Observation{
				Tool:         req.Tool,
				Fact:         "tool call failed: " + callErr.Error(),
				Scope:        "check not performed",
				Completeness: evidencetools.CompletenessUnknown,
				ToolStatus:   evidencetools.StatusError,
				Error:        callErr.Error(),
				ScopeDetails: &evidencetools.ScopeDetails{},
			}
		}
		trace.Observations = append(trace.Observations, obs)
		switch {
		case obs.ToolStatus != evidencetools.StatusOK:
			reason := obs.Error
			if reason == "" {
				reason = obs.Fact
			}
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"verification check %q (tool %s) returned %s: %s", req.ID, req.Tool, obs.ToolStatus, reason))
			trace.Complete = false
		case obs.Completeness != evidencetools.CompletenessComplete:
			trace.Limitations = append(trace.Limitations, fmt.Sprintf(
				"verification check %q (tool %s) observation completeness is %s: coverage is not closed and cannot ground a negative",
				req.ID, req.Tool, obs.Completeness))
			trace.Complete = false
		}
	}
	return trace, nil
}

// callAuditMismatch binds one dispatched request to the session audit
// record the call appended. The audit record — not the trace — is the
// authority on which tool ran with which arguments: a missing record
// means the session saw nothing, and a recorded tool or canonical
// argument digest that differs from the declared request means the
// observation was produced for a different call. Both are returned as
// a limitation string; the caller marks the trace incomplete.
func callAuditMismatch(req VerificationRequest, obs *evidencetools.Observation, rec *evidencetools.AuditRecord) string {
	if rec == nil {
		return "has no session audit record: the call was not recorded and cannot be bound to its request"
	}
	if rec.Tool != req.Tool {
		return fmt.Sprintf("audit record names tool %q, not the declared %q: the observation belongs to a different call", rec.Tool, req.Tool)
	}
	if !bytes.Equal(canonicalJSON(rec.Args), canonicalJSON(req.Arguments)) {
		return "audit-recorded arguments differ from the declared request arguments: the observation belongs to a different call"
	}
	if obs != nil && obs.ID != "" && rec.Observation != nil && rec.Observation.ID != "" && rec.Observation.ID != obs.ID {
		return "audit record carries a different observation id: the observation belongs to a different call"
	}
	return ""
}

// canonicalJSON renders raw JSON bytes in canonical form (compact,
// sorted map keys) so byte-identity comparisons survive transport
// re-encoding. Non-JSON input compares verbatim.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// EvidenceSession is the reusable handle on the strict confined
// evidence session created for one case: the Session itself, the
// in-memory MCP typed-call client and the session audit buffer. It
// exists so the single strict session can stay open across the
// deterministic lane, the agent turn and the bounded verification
// phase, then be closed exactly once. Call is the only execution
// path; DrainAudit hands the session's own audit records — the
// authoritative tool-execution provenance — to whichever phase
// consumed them.
type EvidenceSession struct {
	sess          *evidencetools.Session
	client        *evidencetools.Client
	advisoryRoots []string

	mu    sync.Mutex
	audit []evidencetools.AuditRecord
}

// Session exposes the confined session for the lane's direct backend
// reads (source index, resolved toolchain, canonical roots).
func (e *EvidenceSession) Session() *evidencetools.Session { return e.sess }

// Call is the EvidenceCallFunc over this session's in-memory MCP
// client.
func (e *EvidenceSession) Call(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, error) {
	return e.client.Call(ctx, tool, args)
}

// CallWithAudit is Call plus the session audit record the call
// appended — the AuditedCallFunc for the bounded verification phase.
// Calls are serialized, so the record is whichever the buffer gained
// while this call was in flight; absent a record it returns nil.
func (e *EvidenceSession) CallWithAudit(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
	e.mu.Lock()
	start := len(e.audit)
	e.mu.Unlock()
	obs, err := e.client.Call(ctx, tool, args)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.audit) <= start {
		return obs, nil, err
	}
	rec := e.audit[start]
	return obs, &rec, err
}

// AdvisoryRoots returns the canonical advisory confinement roots the
// session was opened with (directory of the frozen advisory source);
// callers use them to bind request paths in ValidateVerificationPlan.
func (e *EvidenceSession) AdvisoryRoots() []string {
	return append([]string(nil), e.advisoryRoots...)
}

// Catalog exposes the session-scoped, capability-gated check catalog:
// every dispatchable request this session can admit (registered check,
// capability present, schema-satisfying arguments). The R6 flow broker
// gates scheduling on this view; the runtime still returns UNSUPPORTED
// independently.
func (e *EvidenceSession) Catalog() evidencetools.CheckCatalog {
	return e.sess.CheckCatalog()
}

// DrainAudit returns the session audit records buffered since the
// previous drain and clears the buffer. Consumers drain after each
// phase they own; records from one phase are never re-drained by the
// next.
func (e *EvidenceSession) DrainAudit() []evidencetools.AuditRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	recs := append([]evidencetools.AuditRecord(nil), e.audit...)
	e.audit = nil
	return recs
}

// Close releases the in-memory MCP endpoints. The caller owns the
// handle and must invoke Close exactly once when the case's evidence
// phases are done.
func (e *EvidenceSession) Close() error { return e.client.Close() }

// openEvidenceSession creates the strict confined session for this
// case and connects the in-memory typed-call client. The returned
// handle owns both endpoints; the caller must Close it exactly once.
// Configuration is the lane's fixed strict profile: confinement
// mandatory, network and repo-code execution denied, toolchain exec
// permitted, advisory root confined to the frozen source's directory.
func openEvidenceSession(ctx context.Context, o LaneOptions, root string,
	snap domain.ProductSnapshot, tc toolchain.Toolchain, adv *AdvisoryRecord,
	releaseMeta *domain.ReleaseEvidenceSummary) (*EvidenceSession, error) {
	es := &EvidenceSession{advisoryRoots: []string{filepath.Dir(adv.Input.SourcePath)}}
	confine := true
	// The session's lazy snapshot probe must see the identical release
	// evidence the lane resolved: the same artifact options (plus the
	// output dir as forbidden ground) and the same parsed metadata
	// summary. Credentials are never copied here — the channel reads
	// them from the named environment variable inside the repository
	// package only.
	sessArtifact := o.ArtifactOptions
	if outAbs, aerr := filepath.Abs(o.OutputDir); aerr == nil {
		sessArtifact.ForbidDirs = append(append([]string{}, sessArtifact.ForbidDirs...), outAbs)
	}
	sess, err := evidencetools.NewSession(evidencetools.SessionConfig{
		CVEID:           o.CVE,
		SnapshotRoot:    root,
		ExternalSHA:     o.ExternalCommitSHA,
		GOOS:            snap.GOOS,
		GOARCH:          snap.GOARCH,
		DeclaredGOOS:    o.GOOS,
		DeclaredGOARCH:  o.GOARCH,
		BuildTags:       o.BuildTags,
		Target:          snap.Target,
		CGOEnabled:      snap.CGOEnabled,
		ToolchainBin:    tc.GoBin,
		ToolchainEnv:    tc.Env,
		ToolchainVer:    tc.Version,
		AllowNet:        false,
		AllowExec:       false,
		AllowToolchain:  true,
		Strict:          true,
		Confine:         &confine,
		AdvisoryRoots:   []string{filepath.Dir(adv.Input.SourcePath)},
		GovulnDBRoot:    o.GovulnDB,
		ModCacheRoot:    o.ModCache,
		ToolTimeout:     o.Timeout,
		Artifact:        sessArtifact,
		ReleaseMetadata: releaseMeta,
		VulnSource:      vulnerability.FileSource{Path: adv.Input.SourcePath, NoAliasEnrichment: true},
		Audit: evidencetools.AuditFunc(func(_ context.Context, r evidencetools.AuditRecord) {
			es.mu.Lock()
			defer es.mu.Unlock()
			es.audit = append(es.audit, r)
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("strict session: %w", err)
	}
	client, err := sess.Connect(ctx)
	if err != nil {
		return nil, err
	}
	es.sess, es.client = sess, client
	return es, nil
}
