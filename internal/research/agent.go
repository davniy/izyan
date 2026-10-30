package research

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
)

// agent.go holds the retained *proposal* surface of the one-case agent
// contract: the recorded turn envelope, the strict answer-extraction
// admission of verification plans and locus proposals, and the confinement
// validation every plan must pass before a tool may run. The live model
// harness that used to sit beside it (endpoint resolution, E6 preflight,
// container invocation) is retired: `izyan triage` is the sole live human
// investigator, and this package never starts a model.
type AgentTurn struct {
	Output     AgentOutput
	Answer     *agentAnswer // parsed JSON answer when Status==OK
	AnswerJSON []byte       // extracted final answer text
	RawResult  []byte       // raw result.json bytes (retained artifact)
	Manifest   AgentManifest
	Err        string // operator-facing description of a non-OK status
	// Provider/Model are the resolved endpoint identity the run
	// manifests record — the operator's label verbatim on a live turn,
	// the persisted value on a replay.
	Provider string
	Model    string
	// Slice-2 attempt ledger fields (§2.7).
	StartedAt      time.Time
	FinishedAt     time.Time
	ResultArtifact *AttemptArtifact
	AnswerArtifact *AttemptArtifact
	Extraction     *Extraction
	// ReplayedAttempt is the persisted run.attempts row this turn was
	// replayed from (--replay-agent-turn); nil for a live harness run.
	// On a replay, Manifest and RawResult carry the original run's pins —
	// they land in run-manifest.json, never in the report's run.harness.
	ReplayedAttempt *Attempt
}

// AgentManifest records the environment pins actually used for the run.
type AgentManifest struct {
	HarnessPath        string             `json:"harness_path,omitempty"`
	HarnessCommit      string             `json:"harness_commit,omitempty"`
	HarnessPatchSHA256 string             `json:"harness_patch_sha256,omitempty"`
	PreflightReport    string             `json:"e6_preflight_report,omitempty"`
	PreflightSHA256    string             `json:"e6_preflight_sha256,omitempty"`
	Image              string             `json:"image,omitempty"`
	ImageSHA256        string             `json:"image_sha256,omitempty"`
	PromptPath         string             `json:"prompt_path,omitempty"`
	PromptSHA256       string             `json:"prompt_sha256,omitempty"`
	RenderedPromptPath string             `json:"rendered_prompt_path,omitempty"`
	RenderedPromptSHA  string             `json:"rendered_prompt_sha256,omitempty"`
	CaseFile           string             `json:"case_file,omitempty"`
	ResultPath         string             `json:"result_path,omitempty"`
	PreflightCommand   string             `json:"preflight_command,omitempty"`
	RunCommand         string             `json:"run_command,omitempty"`
	PreflightAttempts  []preflightAttempt `json:"preflight_attempts,omitempty"`
}

// preflightAttempt retains the historical E6 invocation pins. Runtime-only
// diagnostics disappeared with the retired live harness; serialized pins stay.
type preflightAttempt struct {
	Ordinal        int    `json:"ordinal"`
	Status         string `json:"status"`                    // PASS|FAIL ("" when no report parsed)
	ProviderStatus string `json:"provider_status,omitempty"` // e.g. "unreachable_infra"
	ReportPath     string `json:"report_path,omitempty"`
	ReportSHA256   string `json:"report_sha256,omitempty"`
	Error          string `json:"error,omitempty"`
}

var validCategories = map[string]bool{
	"false_positive": true, "code_not_present": true, "code_not_reachable": true,
	"requires_configuration": true, "requires_dependency": true, "requires_environment": true,
	"compiler_protected": true, "runtime_protected": true, "perimeter_protected": true,
	"mitigating_control_protected": true, "uncertain": true, "vulnerable": true,
}

const maxVerificationChecks = 8

// checkCatalog is the fail-closed admission surface for verification
// checks: the typed check catalog in internal/evidencetools is the
// single source of truth for which tools exist and which argument
// shapes each accepts. An unregistered tool or a schema-violating
// argument set is a rejection, never a permissive pass-through.
func checkCatalog() evidencetools.CheckCatalog { return evidencetools.DefaultCheckCatalog() }

var verificationFalsifiers = map[domain.FalsifierKind]bool{
	domain.FalsifierGovulncheckSilence: true, domain.FalsifierNoModuleUsage: true,
	domain.FalsifierUnreachedExportedSubject: true, domain.FalsifierNoProductReader: true,
	domain.FalsifierMissingPairMember: true, domain.FalsifierSnapshotFactMismatch: true,
	domain.FalsifierMissingSourceSymbol: true, domain.FalsifierSafeConfigAssignment: true,
	domain.FalsifierZeroValueConfig: true, domain.FalsifierSafeConfigKey: true,
	domain.FalsifierGuards: true, domain.FalsifierConstantOrGeneratedInput: true,
	domain.FalsifierTrustedInfrastructure: true, domain.FalsifierLocusPackageAbsent: true,
	domain.FalsifierPackageAbsent: true, domain.FalsifierLocusFunctionUnreached: true,
	domain.FalsifierDeclaredSymbolUnreached: true,
	domain.FalsifierProtocolRoleMismatch:    true,
}

// ParseVerificationPlan parses a proposal without granting it authority.
// Invalid proposals return nil plus human-readable limitations.
func ParseVerificationPlan(raw json.RawMessage) (*VerificationPlan, []string) {
	return parseVerificationPlan(raw)
}

// maxImplementationLocusProposals bounds one answer's proposal array. A
// larger array is rejected as a whole: a proposal list is never truncated.
const maxImplementationLocusProposals = 8

// parseImplementationLocusProposals applies the strict proposal schema:
// the member must be an array of at most maxImplementationLocusProposals
// objects, each carrying exactly the typed proposal members. Unknown
// fields, authoritative verdict/claim/negative-verification fields, a
// non-LLM-inferred quality, malformed shapes and duplicate ids reject the
// affected proposal with a named limitation — the proposal is never
// admitted and the answer itself stays parseable for reporting.
func parseImplementationLocusProposals(raw json.RawMessage) ([]domain.ImplementationLocusProposal, []string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, []string{"implementation_locus_proposals is not a JSON array"}
	}
	if len(items) > maxImplementationLocusProposals {
		return nil, []string{fmt.Sprintf("implementation_locus_proposals carries %d entries; the bound is %d — the list is rejected as a whole",
			len(items), maxImplementationLocusProposals)}
	}
	var out []domain.ImplementationLocusProposal
	var limitations []string
	seen := map[string]bool{}
	for i, item := range items {
		where := fmt.Sprintf("implementation_locus_proposals[%d]", i)
		if forbiddenProposalField(item) {
			limitations = append(limitations, where+" contains authoritative verdict/claim/negative-verification fields")
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.DisallowUnknownFields()
		var p domain.ImplementationLocusProposal
		if err := dec.Decode(&p); err != nil {
			limitations = append(limitations, where+" is not a valid typed proposal: "+err.Error())
			continue
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			limitations = append(limitations, where+" carries trailing content after the proposal object")
			continue
		}
		if err := p.Validate(); err != nil {
			limitations = append(limitations, where+" rejected: "+err.Error())
			continue
		}
		if seen[p.ID] {
			limitations = append(limitations, where+" duplicates proposal id "+p.ID)
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out, limitations
}

// AdmitImplementationLocusProposal applies the non-authoritative admission
// gate to one parsed proposal against the lane's frozen advisory: typed
// shape and LLM-inferred quality, an advisory reference that resolves to
// the frozen document or its pinned digest, and a quoted span that is a
// verbatim recorded substring. Admission never grants authority — the
// deterministic verifier re-checks everything against the exact snapshot.
func AdmitImplementationLocusProposal(p domain.ImplementationLocusProposal, a *AdvisoryRecord) error {
	if a == nil {
		return fmt.Errorf("frozen advisory record is unavailable")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := domain.ValidateImplementationAdvisoryRef(p.AdvisoryEvidenceRef, a.Input.ResolvedID,
		a.Input.RawSHA256, a.Input.CanonicalSHA256); err != nil {
		return err
	}
	var summary, details string
	if a.Vuln != nil {
		summary, details = a.Vuln.Summary, a.Vuln.Description
	}
	if field := domain.ImplementationAdvisoryQuoteField(p.AdvisoryQuotedSpan, summary, details, a.RawBytes); field == "" {
		return fmt.Errorf("advisory_quoted_span is not an exact recorded substring of the frozen advisory summary/details/raw body")
	}
	return nil
}

// ImplementationLocusProposals returns the strictly parsed LLM
// implementation-locus hypotheses of this attempt (shape and quality only;
// the affected verifier re-binds each one to the frozen advisory and the
// exact snapshot). They are proposals only: the deterministic
// affected.VerifyImplementationLocus verifier remains the sole route to an
// implementation-presence fact.
func (t *AgentTurn) ImplementationLocusProposals() []domain.ImplementationLocusProposal {
	if t == nil || t.Answer == nil {
		return nil
	}
	return append([]domain.ImplementationLocusProposal(nil), t.Answer.ImplementationLocusProposals...)
}

// maxExploitLocusProposals bounds one answer's exploit-locus proposal
// array. A larger array is rejected as a whole: a proposal list is never
// truncated.
const maxExploitLocusProposals = 8

// parseExploitLocusProposals applies the strict proposal schema to the
// answer's exploit_locus_proposals member: an array of at most
// maxExploitLocusProposals objects, each carrying exactly the typed
// proposal members. Unknown fields, authoritative verdict/claim/
// negative-verification fields, a non-LLM-inferred quality, malformed
// shapes and duplicate ids reject the affected proposal with a named
// limitation — the proposal is never admitted and the answer itself
// stays parseable for reporting.
func parseExploitLocusProposals(raw json.RawMessage) ([]domain.ExploitLocusProposal, []string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, []string{"exploit_locus_proposals is not a JSON array"}
	}
	if len(items) > maxExploitLocusProposals {
		return nil, []string{fmt.Sprintf("exploit_locus_proposals carries %d entries; the bound is %d — the list is rejected as a whole",
			len(items), maxExploitLocusProposals)}
	}
	var out []domain.ExploitLocusProposal
	var limitations []string
	seen := map[string]bool{}
	for i, item := range items {
		where := fmt.Sprintf("exploit_locus_proposals[%d]", i)
		if forbiddenProposalField(item) {
			limitations = append(limitations, where+" contains authoritative verdict/claim/negative-verification fields")
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.DisallowUnknownFields()
		var p domain.ExploitLocusProposal
		if err := dec.Decode(&p); err != nil {
			limitations = append(limitations, where+" is not a valid typed proposal: "+err.Error())
			continue
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			limitations = append(limitations, where+" carries trailing content after the proposal object")
			continue
		}
		if err := p.Validate(); err != nil {
			limitations = append(limitations, where+" rejected: "+err.Error())
			continue
		}
		if seen[p.ID] {
			limitations = append(limitations, where+" duplicates proposal id "+p.ID)
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out, limitations
}

// AdmitExploitLocusProposal applies the non-authoritative admission gate
// to one parsed exploit-locus proposal against the lane's frozen
// advisory: typed shape and LLM-inferred quality, an advisory reference
// that resolves to the frozen document or its pinned digest, and a
// quoted span that is a verbatim recorded substring. Admission never
// grants authority — the deterministic binder re-checks everything
// against the exact snapshot.
func AdmitExploitLocusProposal(p domain.ExploitLocusProposal, a *AdvisoryRecord) error {
	if a == nil {
		return fmt.Errorf("frozen advisory record is unavailable")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := domain.ValidateImplementationAdvisoryRef(p.AdvisoryEvidenceRef, a.Input.ResolvedID,
		a.Input.RawSHA256, a.Input.CanonicalSHA256); err != nil {
		return err
	}
	var summary, details string
	if a.Vuln != nil {
		summary, details = a.Vuln.Summary, a.Vuln.Description
	}
	if field := domain.ImplementationAdvisoryQuoteField(p.AdvisoryQuotedSpan, summary, details, a.RawBytes); field == "" {
		return fmt.Errorf("advisory_quoted_span is not an exact recorded substring of the frozen advisory summary/details/raw body")
	}
	return nil
}

// ExploitLocusProposals returns the strictly parsed LLM exploit-locus
// hypotheses of this attempt (shape and quality only; the affected
// binder re-binds each one to the frozen advisory and the exact
// snapshot). They are proposals only: the deterministic
// affected.VerifyExploitLocus binder remains the sole route to a usable
// exploit-locus binding.
func (t *AgentTurn) ExploitLocusProposals() []domain.ExploitLocusProposal {
	if t == nil || t.Answer == nil {
		return nil
	}
	return append([]domain.ExploitLocusProposal(nil), t.Answer.ExploitLocusProposals...)
}

func parseVerificationPlan(raw json.RawMessage) (*VerificationPlan, []string) {
	var plan VerificationPlan
	if len(raw) == 0 || !json.Valid(raw) || string(raw) == "null" {
		return nil, []string{"verification_plan is malformed JSON"}
	}
	if forbiddenProposalField(raw) {
		return nil, []string{"verification_plan contains authoritative verdict or claim fields"}
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, []string{"verification_plan is malformed: " + err.Error()}
	}
	if err := ValidateVerificationPlan(plan, "", nil); err != nil {
		return nil, []string{err.Error()}
	}
	return &plan, nil
}

func forbiddenProposalField(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	for key := range obj {
		switch strings.ToLower(key) {
		case "negativeverification", "negative_verification", "verdict", "claim", "authoritativeclaim", "authoritative_claim":
			return true
		}
	}
	for _, child := range obj {
		if len(child) > 0 && child[0] == '{' && forbiddenProposalField(child) {
			return true
		}
	}
	return false
}

// ValidateVerificationPlan checks proposal shape and request confinement
// before any evidence-tool execution exists. Empty roots skip path binding;
// the execution lane supplies the session's real snapshot/advisory roots.
func ValidateVerificationPlan(plan VerificationPlan, snapshotRoot string, advisoryRoots []string) error {
	f := plan.Falsifier
	if !verificationFalsifiers[f.Kind] {
		return fmt.Errorf("verification_plan falsifier kind %q is unsupported", f.Kind)
	}
	if strings.TrimSpace(f.ConditionID) == "" {
		return errors.New("verification_plan falsifier condition_id is empty")
	}
	if strings.TrimSpace(f.Statement) == "" || strings.TrimSpace(f.Scope) == "" {
		return errors.New("verification_plan falsifier statement and scope are required")
	}
	if strings.TrimSpace(f.Module) == "" && strings.TrimSpace(f.Package) == "" && strings.TrimSpace(f.Symbol) == "" {
		return errors.New("verification_plan falsifier subject is empty")
	}
	if f.ArgIndex < -2 {
		return fmt.Errorf("verification_plan falsifier arg_index %d is invalid", f.ArgIndex)
	}
	if len(plan.Checks) > maxVerificationChecks {
		return fmt.Errorf("verification_plan has %d checks; maximum is %d", len(plan.Checks), maxVerificationChecks)
	}
	seen := map[string]bool{}
	callsByCheck := map[string]int{}
	for i, c := range plan.Checks {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("verification_plan check %d has empty id", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("verification_plan check %q is duplicated", c.ID)
		}
		seen[c.ID] = true
		spec, ok := checkCatalog().Lookup(c.Tool)
		if !ok {
			return fmt.Errorf("verification_plan check %q uses unsupported tool %q", c.ID, c.Tool)
		}
		if strings.TrimSpace(c.Purpose) == "" || strings.TrimSpace(c.ConditionID) == "" {
			return fmt.Errorf("verification_plan check %q requires purpose and condition_id", c.ID)
		}
		if c.ConditionID != f.ConditionID {
			return fmt.Errorf("verification_plan check %q condition_id %q does not match falsifier %q", c.ID, c.ConditionID, f.ConditionID)
		}
		if len(c.Arguments) == 0 || !json.Valid(c.Arguments) {
			return fmt.Errorf("verification_plan check %q has invalid arguments JSON", c.ID)
		}
		var args any
		if err := json.Unmarshal(c.Arguments, &args); err != nil {
			return fmt.Errorf("verification_plan check %q arguments: %w", c.ID, err)
		}
		if args == nil {
			return fmt.Errorf("verification_plan check %q arguments must be a JSON object", c.ID)
		}
		obj, ok := args.(map[string]any)
		if !ok {
			return fmt.Errorf("verification_plan check %q arguments must be a JSON object", c.ID)
		}
		if err := checkCatalog().Validate(c.Tool, c.Arguments); err != nil {
			return fmt.Errorf("verification_plan check %q: %w", c.ID, err)
		}
		callsByCheck[c.Tool]++
		if spec.MaxCalls > 0 && callsByCheck[c.Tool] > spec.MaxCalls {
			return fmt.Errorf("verification_plan check %q exceeds the catalog bound for tool %q (%d calls)", c.ID, c.Tool, spec.MaxCalls)
		}
		if err := validatePlanArgs(obj, snapshotRoot, advisoryRoots); err != nil {
			return fmt.Errorf("verification_plan check %q arguments: %w", c.ID, err)
		}
	}
	return nil
}

func validatePlanArgs(v any, snapshotRoot string, advisoryRoots []string) error {
	var walk func(any, string) error
	walk = func(x any, key string) error {
		switch t := x.(type) {
		case map[string]any:
			for k, child := range t {
				if err := walk(child, strings.ToLower(k)); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range t {
				if err := walk(child, key); err != nil {
					return err
				}
			}
		case string:
			if key == "url" {
				u := strings.ToLower(strings.TrimSpace(t))
				if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
					return fmt.Errorf("url must use http or https")
				}
			}
			if key == "file" || strings.HasSuffix(key, "_path") || key == "path" || key == "root" {
				if err := planPathAllowed(t, snapshotRoot, advisoryRoots); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(v, "")
}

func planPathAllowed(path, snapshotRoot string, advisoryRoots []string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(path) && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil
	}
	if len(advisoryRoots) == 0 && snapshotRoot == "" {
		return fmt.Errorf("path %q cannot be bound without session roots", path)
	}
	candidate, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	roots := append([]string(nil), advisoryRoots...)
	if snapshotRoot != "" {
		roots = append(roots, snapshotRoot)
	}
	for _, root := range roots {
		r, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(r), filepath.Clean(candidate))
		if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
			return nil
		}
	}
	return fmt.Errorf("path %q is outside the session snapshot/advisory roots", path)
}
func deref(p *string) string {
	if p == nil {
		return "null"
	}
	return *p
}

func singleLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
