package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/fedorovmv/izyan/internal/llm"
)

type ChatClient interface {
	Chat(context.Context, llm.ModelRole, string, []llm.ChatMessage, []llm.ToolDefinition) (llm.ChatMessage, string, error)
}

type AgentLimits struct {
	// MaxSteps is the INITIAL agent-loop exchange budget only. The run's
	// total step counter additionally reserves one finalization round plus
	// the bounded feedback repair turns (MaxFactFeedbackPasses +
	// MaxFalsifierFeedbackPasses turns of factFeedbackMaxToolRounds+1
	// exchanges each); see totalStepBudget. A model exchange is counted
	// when it is issued — the counter can never pass the total budget.
	MaxSteps       int
	MaxToolCalls   int
	MaxSourceBytes int64
	Timeout        time.Duration
}

// Run failure classes recorded on a partial AgentRun: they tell the artifact
// writer and the operator what terminated the run without parsing the error
// text. The provider class covers every chat-call error, transient or not.
const (
	ErrClassProvider   = "provider"
	ErrClassTimeout    = "timeout"
	ErrClassCanceled   = "canceled"
	ErrClassStepBudget = "step_budget"
	ErrClassToolBudget = "tool_budget"
	ErrClassRefusal    = "refusal"
	ErrClassProtocol   = "protocol"
	ErrClassInternal   = "internal"
)

// chatMaxAttempts bounds each chat call to 3 attempts: one initial call plus
// two retries for transient provider failures, spaced by chatBackoff.
const chatMaxAttempts = 3

var chatBackoff = []time.Duration{2 * time.Second, 5 * time.Second}

// budgetNudgeSteps is the remaining-step threshold that triggers the one-shot
// finalization nudge; budgetNudge demands the terminal assessment without any
// further tool calls.
const (
	budgetNudgeSteps = 2
	budgetNudge      = "Step budget is nearly exhausted. Respond now with only the final " + AssessmentSchemaVersion + " JSON object for this finding and no further tool calls. A response that is not a valid " + AssessmentSchemaVersion + " JSON is a technical failure."

	// finalizationMessage is the single bounded fallback turn issued after
	// the step budget ran out without an accepted assessment: no tool
	// definitions travel with the request, so the model can only answer
	// with the assessment object itself.
	finalizationMessage = "Finalization: return one complete " + AssessmentSchemaVersion + " JSON object for this finding as message content only — no tool calls, no prose, no markdown fences. A response that is not a valid " + AssessmentSchemaVersion + " JSON is a technical failure."

	// assessmentToolFeedback answers a tool call that names the assessment
	// schema: the schema is a message format, never a callable tool, so the
	// call is answered in-band instead of being dispatched to the executor
	// or charged to the tool budget.
	assessmentToolFeedback = AssessmentSchemaVersion + " is a message format, not a tool. This tool call was not executed. Respond with the " + AssessmentSchemaVersion + " JSON object as message content."
)

type AgentRun struct {
	Assessment   Assessment
	RawMessages  []llm.ChatMessage
	PromptHash   string
	ResponseHash string
	Steps        int
	ToolCalls    int
	// Observations is the frozen full payload archive for this attempt.
	Observations []RecordedObservation
	DetTools     bool
	// PromptInput is the exact prompt surface this attempt sent: system
	// text, initial data messages and advertised tool definitions. It is
	// persisted as prompt-input.v1 before the first exchange and is what
	// replay verifies instead of rebuilding today's surface.
	PromptInput PromptInput
	// Finalized records that the bounded finalization exchange produced the
	// accepted assessment after the initial exchange loop exhausted its step
	// budget. It is an in-memory run fact, never a completeness claim: the
	// human package records it through BudgetResult.
	Finalized  bool
	ErrorClass string
	FactPasses []FactGatePass
	Attempts   []AgentRun
}

// BudgetResult names the step-budget outcome that travels into the human
// package. A run that needed the bounded finalization round records that
// fact so the human result never reads as an investigation that ran to
// completion; a run that answered inside its exchange budget adds no budget
// caveat. The value is descriptive, not a quality or completeness metric.
func (r AgentRun) BudgetResult() string {
	if r.Finalized {
		return "finalized_after_step_budget"
	}
	return ""
}

type AgentRunner struct {
	Client    ChatClient
	Tools     ToolExecutor
	Limits    AgentLimits
	Materials AgentMaterials
	// Prologue carries verbatim messages of earlier pipeline stages (Stage 0
	// intake extraction and ref selection): it is prefixed into the recorded
	// raw-agent.json transcript so the artifact covers every model exchange
	// of the run, but it is never re-sent to the provider.
	Prologue []llm.ChatMessage
	// Sleep waits between chat retries; nil means time.Sleep. Tests override
	// it to keep retry paths instant — it is still bounded by chatBackoff.
	Sleep func(context.Context, time.Duration) error
	// PromptSink, when set, persists the exact prompt surface BEFORE the
	// first investigator exchange. An error is a technical failure raised
	// before any provider call.
	PromptSink func(PromptInput) error
	// ProposalCapabilities is the catalog-bound answer the prompt reports.
	// The zero value means this caller cannot report capability (a
	// historical replay reconstruction); live runs pass either the bound
	// conditions or the explicit unavailable reason.
	ProposalCapabilities ProposalCapabilities
}

// factFeedbackMaxToolRounds bounds tool-call replies inside one feedback
// pass so a repairing agent can look facts up without turning the repair
// turn into an unbounded second exploration. One turn's exchange ceiling
// is factFeedbackMaxToolRounds+1 chats: rounds[0..4] plus one repair chat.
const factFeedbackMaxToolRounds = 4

// totalStepBudget is the run's single step counter ceiling — the number of
// model exchanges the whole run can issue: the initial loop (maxSteps),
// the bounded finalization round (1), and every bounded feedback repair
// turn (maxFact + maxFalsifier turns, factFeedbackMaxToolRounds+1 chats
// each, already clamped). An exchange is reserved before the provider
// call: when the counter reaches the budget the next call is denied
// without ever hitting the wire — no off-by-one exchange beyond the cap.
func totalStepBudget(maxSteps, maxFact, maxFalsifier int) int {
	return maxSteps + 1 + (maxFact+maxFalsifier)*(factFeedbackMaxToolRounds+2)
}
func hashBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (r AgentRunner) Run(parent context.Context, in FindingInput, manifest SnapshotManifest) (AgentRun, error) {
	run, _, err := r.runInternal(parent, in, manifest, nil, 0, nil, 0)
	return run, err
}

// RunWithFactGate runs the bounded agent loop and then the deterministic
// fact-gate feedback protocol (spec §7): after the accepted assessment the
// gate validates it, unresolved checks go back to the agent as structured
// reproducibility feedback, and the repaired answer is re-validated — at
// most clampFactFeedbackPasses times. Whatever the outcome, the final gate
// report is returned with the run: still-broken references stay recorded
// with their risk-reduction effect for the demotion rules, never retried
// into a desired verdict. Every report and the feedback sent after it are
// preserved in run.FactPasses (raw-agent.json) for replay and audit.
func (r AgentRunner) RunWithFactGate(
	ctx context.Context,
	in FindingInput,
	manifest SnapshotManifest,
	gate FactGate,
	maxFeedbackPasses int,
) (AgentRun, FactValidation, error) {
	return r.RunWithFactGateAndFalsifierFeedback(ctx, in, manifest, gate, maxFeedbackPasses, nil, 0)
}

// RunWithFactGateAndFalsifierFeedback is RunWithFactGate plus the bounded
// falsifier repair protocol: once the fact gate stands, the
// falsifierFeedback callback re-verifies the accepted assessment's
// proposals against the run's recorded observations. A callback that
// returns retry=true hands its message to the agent as one repair turn
// (same bounded tool/shape-repair rules as a fact pass), the gate
// re-validates the repaired assessment and the verifier runs again — at
// most MaxFalsifierFeedbackPasses times. retry=false or an exhausted
// budget leaves the last verifier report standing; an unsupported or
// failed proposal is never turned into a technical failure, and the
// callback's report always matches the last accepted assessment.
func (r AgentRunner) RunWithFactGateAndFalsifierFeedback(
	ctx context.Context,
	in FindingInput,
	manifest SnapshotManifest,
	gate FactGate,
	maxFeedbackPasses int,
	falsifierFeedback FalsifierFeedbackFunc,
	maxFalsifierPasses int,
) (AgentRun, FactValidation, error) {
	return r.runInternal(ctx, in, manifest, &gate, maxFeedbackPasses, falsifierFeedback, maxFalsifierPasses)
}

// runInternal is Run plus the optional fact-gate and falsifier feedback
// loops; a nil gate skips validation entirely, a nil falsifier callback
// skips the verifier repair turns.
func (r AgentRunner) runInternal(parent context.Context, in FindingInput, manifest SnapshotManifest, gate *FactGate, maxFeedbackPasses int, falsifierFeedback FalsifierFeedbackFunc, maxFalsifierPasses int) (AgentRun, FactValidation, error) {
	var out AgentRun
	var fv FactValidation
	if parent == nil {
		parent = context.Background()
	}
	ctx := parent
	cancel := func() {}
	if r.Limits.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, r.Limits.Timeout)
	}
	defer cancel()
	var defs []llm.ToolDefinition
	if r.Tools != nil {
		defs = r.Tools.Definitions()
	}
	out.DetTools = HasDeterministicTools(r.Tools)
	system := BuildPrompt(defs, out.DetTools, r.ProposalCapabilities)
	initial := []llm.ChatMessage{{Role: "user", Content: BuildDataMessage(in, manifest, r.Materials)}, {Role: "user", Content: "Assess the finding using the available read-only snapshot tools."}}
	out.PromptInput = NewPromptInput(system, initial, defs)
	out.PromptHash = out.PromptInput.PromptHash
	messages := append([]llm.ChatMessage(nil), initial...)
	// recorded prefixes the Stage 0 prologue into the persisted transcript;
	// the live `messages` slice sent to the provider stays agent-run only.
	recorded := func() []llm.ChatMessage {
		return append(append([]llm.ChatMessage(nil), r.Prologue...), messages...)
	}
	maxSteps := r.Limits.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 8
	}
	maxTools := r.Limits.MaxToolCalls
	var lastContent, lastFinish string
	var lastParseErr error
	// fail returns a technical error carrying the accumulated partial state:
	// the verbatim transcript, consumed budgets and the failure class, so a
	// dead run is still diagnosable from its artifacts.
	fail := func(class string, err error) (AgentRun, FactValidation, error) {
		out.ErrorClass = class
		out.RawMessages = recorded()
		if lastContent != "" {
			out.ResponseHash = hashBytes([]byte(lastContent))
		}
		return out, fv, err
	}
	if r.Client == nil {
		return fail(ErrClassInternal, errors.New("agenttriage: nil chat client"))
	}
	if r.PromptSink != nil {
		if perr := r.PromptSink(out.PromptInput); perr != nil {
			return fail(ErrClassInternal, fmt.Errorf("agenttriage: persist prompt input before the first exchange: %w", perr))
		}
	}
	nudged := false
	// protocolNudged latches once an assessment.v2 tool call was answered
	// with in-band protocol feedback; a model that repeats the call after
	// being told once is a contract violation the run fails on, not a
	// shape error worth another correction.
	protocolNudged := false
	// The step counter is one total budget across every model exchange the
	// run can issue: the initial loop (maxSteps), the bounded finalization
	// round (1), and each bounded feedback repair turn — maxFact +
	// maxFalsifier already-clamped turns of at most
	// factFeedbackMaxToolRounds+1 chats each (the +2 in totalStepBudget
	// covers the turn's repair chat and is deliberately conservative).
	// spendStep reserves a slot BEFORE the provider call: an exchange that
	// would overrun is denied without ever hitting the wire, so the
	// provider sees at most totalBudget calls — no off-by-one exchange
	// beyond the cap. A reserved-but-failed call still consumed the slot
	// (it reached the wire); Steps therefore counts issued exchanges.
	maxFact, maxFalsifier := clampFactFeedbackPasses(maxFeedbackPasses), clampFalsifierFeedbackPasses(maxFalsifierPasses)
	totalBudget := totalStepBudget(maxSteps, maxFact, maxFalsifier)
	spendStep := func(label string) error {
		if out.Steps >= totalBudget {
			return fmt.Errorf("agenttriage: %s: total step budget exceeded (%d)", label, totalBudget)
		}
		out.Steps++
		return nil
	}
	accepted := false
	for step := range maxSteps {
		if err := ctx.Err(); err != nil {
			return fail(classifyRunErr(err), fmt.Errorf("agenttriage: technical termination: %w", err))
		}
		if serr := spendStep("chat"); serr != nil {
			return fail(ErrClassStepBudget, serr)
		}
		msg, finish, err := r.chat(ctx, system, messages, defs)
		if err != nil {
			return fail(classifyRunErr(err), fmt.Errorf("agenttriage: chat: %w", err))
		}
		messages = append(messages, msg)
		lastContent, lastFinish = msg.Content, finish
		if len(msg.ToolCalls) > 0 {
			if err := r.execToolCalls(ctx, msg, maxTools, &protocolNudged, &out, &messages); err != nil {
				return fail(out.ErrorClass, err)
			}
			// The run is almost out of steps and the agent still requests
			// tools: nudge it once to return the final assessment.v2 JSON
			// instead of burning the remaining steps on more tool calls.
			if remaining := maxSteps - (step + 1); !nudged && remaining > 0 && remaining <= budgetNudgeSteps {
				messages = append(messages, llm.ChatMessage{Role: "user", Content: budgetNudge})
				nudged = true
			}
			continue
		}
		assessment, parseErr := decodeAssessment(msg.Content, in.Finding.FindingID)
		if parseErr != nil {
			lastParseErr = parseErr
		}
		if parseErr == nil {
			out.Assessment = assessment
			accepted = true
			break
		}
		if llm.IsRefusal(msg.Content, finish) {
			return fail(ErrClassRefusal, fmt.Errorf("agenttriage: technical refusal: %s", llm.DescribeBadOutput(msg.Content, finish)))
		}
		// instead of repeating the same shape. A malformed response is never
		// accepted as evidence.
		messages = append(messages, llm.ChatMessage{Role: "user", Content: repairMessage(parseErr, finish, looksTruncatedJSON(lastContent))})
		if out.Steps >= maxSteps {
			break
		}
		if serr := spendStep("repair chat"); serr != nil {
			return fail(ErrClassStepBudget, serr)
		}
		msg, finish, err = r.chat(ctx, system, messages, defs)
		if err != nil {
			return fail(classifyRunErr(err), fmt.Errorf("agenttriage: repair chat: %w", err))
		}
		messages = append(messages, msg)
		lastContent, lastFinish = msg.Content, finish
		if llm.IsRefusal(msg.Content, finish) {
			return fail(ErrClassRefusal, fmt.Errorf("agenttriage: technical refusal: %s", llm.DescribeBadOutput(msg.Content, finish)))
		}
		if a, err := decodeAssessment(msg.Content, in.Finding.FindingID); err == nil {
			out.Assessment = a
			accepted = true
		} else {
			lastParseErr = err
		}
		break
	}
	if !accepted {
		if err := ctx.Err(); err != nil {
			return fail(classifyRunErr(err), fmt.Errorf("agenttriage: technical termination: %w", err))
		}
		// Last-chance salvage: the final assistant message may have carried
		// the assessment alongside tool calls, so its content was never
		// decoded inside the loop.
		if a, err := decodeAssessment(lastContent, in.Finding.FindingID); err == nil {
			out.Assessment = a
			accepted = true
		}
	}
	if !accepted {
		// One bounded finalization round: the request goes out with no
		// tool definitions, so the model cannot spend the fallback on more
		// calls, and a response that is not an assessment — tool calls
		// included — keeps the step-budget failure with the full partial
		// transcript.
		messages = append(messages, llm.ChatMessage{Role: "user", Content: finalizationMessage})
		if serr := spendStep("finalization chat"); serr != nil {
			return fail(ErrClassStepBudget, serr)
		}
		msg, finish, err := r.chat(ctx, system, messages, nil)
		if err != nil {
			return fail(classifyRunErr(err), fmt.Errorf("agenttriage: finalization chat: %w", err))
		}
		messages = append(messages, msg)
		lastContent, lastFinish = msg.Content, finish
		if a, err := decodeAssessment(msg.Content, in.Finding.FindingID); err == nil && len(msg.ToolCalls) == 0 {
			out.Assessment = a
			out.Finalized = true
			accepted = true
		} else if len(msg.ToolCalls) > 0 {
			lastParseErr = errors.New("finalization response requested tool calls; the finalization turn has no tools")
		} else {
			lastParseErr = err
		}
	}
	if !accepted {
		if lastParseErr != nil {
			return fail(ErrClassStepBudget, fmt.Errorf("agenttriage: step budget exceeded (%d): %s (last decode error: %v)", maxSteps, llm.DescribeBadOutput(lastContent, lastFinish), lastParseErr))
		}
		return fail(ErrClassStepBudget, fmt.Errorf("agenttriage: step budget exceeded (%d): %s", maxSteps, llm.DescribeBadOutput(lastContent, lastFinish)))
	}

	// assessmentTurn runs one feedback repair turn: bounded tool rounds
	// (factFeedbackMaxToolRounds) so the agent can look facts up, plus
	// exactly one shape repair for an undecodable reply. It returns the
	// failure class and error on a technical termination; (false, "", nil)
	// means the turn produced no valid assessment without an error.
	assessmentTurn := func(label string) (bool, string, error) {
		repaired := false
		for round := 0; round <= factFeedbackMaxToolRounds; round++ {
			if serr := spendStep(label + " chat"); serr != nil {
				return false, ErrClassStepBudget, serr
			}
			msg, finish, err := r.chat(ctx, system, messages, defs)
			if err != nil {
				return false, classifyRunErr(err), fmt.Errorf("agenttriage: %s chat: %w", label, err)
			}
			messages = append(messages, msg)
			lastContent, lastFinish = msg.Content, finish
			if len(msg.ToolCalls) > 0 {
				if err := r.execToolCalls(ctx, msg, maxTools, &protocolNudged, &out, &messages); err != nil {
					return false, out.ErrorClass, err
				}
				continue
			}
			assessment, parseErr := decodeAssessment(msg.Content, in.Finding.FindingID)
			if parseErr == nil {
				out.Assessment = assessment
				return true, "", nil
			}
			if llm.IsRefusal(msg.Content, finish) {
				return false, ErrClassRefusal, fmt.Errorf("agenttriage: technical refusal: %s", llm.DescribeBadOutput(msg.Content, finish))
			}
			messages = append(messages, llm.ChatMessage{Role: "user", Content: repairMessage(parseErr, finish, looksTruncatedJSON(lastContent))})
			if serr := spendStep(label + " repair chat"); serr != nil {
				return false, ErrClassStepBudget, serr
			}
			msg, finish, err = r.chat(ctx, system, messages, defs)
			if err != nil {
				return false, classifyRunErr(err), fmt.Errorf("agenttriage: %s repair chat: %w", label, err)
			}
			messages = append(messages, msg)
			lastContent, lastFinish = msg.Content, finish
			if llm.IsRefusal(msg.Content, finish) {
				return false, ErrClassRefusal, fmt.Errorf("agenttriage: technical refusal: %s", llm.DescribeBadOutput(msg.Content, finish))
			}
			if a, err := decodeAssessment(msg.Content, in.Finding.FindingID); err == nil {
				out.Assessment = a
				repaired = true
			} else {
				lastParseErr = err
			}
			break
		}
		return repaired, "", nil
	}

	if gate != nil {
		// Observation evidence verifies against this run's own recorded
		// tool audit trail; a caller-supplied index wins only when the run
		// recorded no observations at all (e.g. no tool surface).
		if a, ok := r.Tools.(interface {
			AuditEvents() []ToolAuditEvent
		}); ok {
			if idx := ObservationIndex(a.AuditEvents()); len(idx) > 0 || gate.Observations == nil {
				gate.Observations = idx
			}
		}
		maxPasses := maxFact
		fv = gate.Validate(ctx, in, manifest, out.Assessment)
		// Each iteration records the report it answered together with the
		// feedback sent; the report still standing at the budget — or a
		// clean one — is appended once after the loop as the final report.
		for sent := 0; needsFactRepair(fv) && sent < maxPasses; sent++ {
			fb := gate.BuildFeedback(fv, sent+1)
			out.FactPasses = append(out.FactPasses, FactGatePass{Pass: sent, Validation: fv, Feedback: &fb})
			messages = append(messages, llm.ChatMessage{Role: "user", Content: factFeedbackMessage(fb)})
			repaired, cls, ferr := assessmentTurn("fact feedback")
			if ferr != nil {
				return fail(cls, ferr)
			}
			if !repaired {
				return fail(ErrClassStepBudget, fmt.Errorf(
					"agenttriage: fact feedback pass %d produced no valid assessment (%s)",
					sent+1, llm.DescribeBadOutput(lastContent, lastFinish)))
			}
			fv = gate.Validate(ctx, in, manifest, out.Assessment)
		}
		// The final gate report — whatever it concludes — is recorded too:
		// its pass index counts the feedback turns sent before it. The
		// falsifier repair loop below may re-validate on a repaired
		// assessment; the last recorded report always reflects it, never a
		// superseded one.
		out.FactPasses = append(out.FactPasses, FactGatePass{Pass: len(out.FactPasses), Validation: fv})

		// Bounded falsifier repair protocol: the callback re-verifies the
		// accepted assessment's proposals against this run's recorded
		// observations after every accepted assessment. retry=true feeds
		// the contract failure back as one user message and the same
		// bounded repair turn produces the next assessment; retry=false —
		// a clean report, an external binding the agent cannot repair, or
		// an exhausted budget — ends the loop with the last report
		// standing, never a technical failure. At most maxFalsifier
		// messages are sent; the callback still gets a terminal
		// invocation for the last repaired assessment so the stored
		// report always describes it.
		for pass := 1; falsifierFeedback != nil; pass++ {
			var observations []RecordedObservation
			if s, ok := r.Tools.(ObservationStore); ok {
				observations = s.Observations()
			}
			message, retry, verr := falsifierFeedback(ctx, out.Assessment, fv, observations, pass)
			if verr != nil {
				return fail(ErrClassInternal, fmt.Errorf("agenttriage: falsifier feedback pass %d: %w", pass, verr))
			}
			if !retry || message == "" || pass > maxFalsifier {
				break
			}
			messages = append(messages, llm.ChatMessage{Role: "user", Content: message})
			repaired, cls, ferr := assessmentTurn("falsifier feedback")
			if ferr != nil {
				return fail(cls, ferr)
			}
			if !repaired {
				return fail(ErrClassStepBudget, fmt.Errorf(
					"agenttriage: falsifier feedback pass %d produced no valid assessment (%s)",
					pass, llm.DescribeBadOutput(lastContent, lastFinish)))
			}
			// The repair turn may have recorded fresh observations: re-index
			// before the gate re-derives det:<id> bindings, so a newly cited
			// observation id resolves instead of reading as foreign.
			if a, ok := r.Tools.(interface {
				AuditEvents() []ToolAuditEvent
			}); ok {
				if idx := ObservationIndex(a.AuditEvents()); len(idx) > 0 {
					gate.Observations = idx
				}
			}
			fv = gate.Validate(ctx, in, manifest, out.Assessment)
			out.FactPasses[len(out.FactPasses)-1].Validation = fv
		}
	}

	if s, ok := r.Tools.(ObservationStore); ok {
		out.Observations = s.Observations()
	}
	out.RawMessages = recorded()
	out.ResponseHash = hashBytes([]byte(lastContent))
	return out, fv, nil
}

// execToolCalls executes the tool calls of one assistant message against
// the run's read-only executor, appending the tool observations to the
// transcript. It sets out.ErrorClass before returning an error so the
// caller's fail() classifies the termination correctly. A call that names
// assessment.v2 is a protocol violation, not a tool request: it is never
// dispatched to the executor and never charged to the tool budget. The
// first such call in the run is answered in-band with protocol feedback
// paired to its tool call id; any repeat — in a later message or
// duplicated inside the same one — ends the run as a contract violation.
func (r AgentRunner) execToolCalls(ctx context.Context, msg llm.ChatMessage, maxTools int, protocolNudged *bool, out *AgentRun, messages *[]llm.ChatMessage) error {
	violation := false
	for _, call := range msg.ToolCalls {
		if call.Function.Name == AssessmentSchemaVersion {
			if *protocolNudged || violation {
				// The run records protocol feedback exactly once: the
				// model was told — in a delivered reply or in this very
				// message — that assessment.v2 is a message format, and
				// repeating the call spends no more budget on it.
				out.ErrorClass = ErrClassProtocol
				return fmt.Errorf("agenttriage: repeated %s tool call after protocol feedback", AssessmentSchemaVersion)
			}
			violation = true
			*messages = append(*messages, llm.ChatMessage{Role: "tool", ToolCallID: call.ID, Content: assessmentToolFeedback})
			continue
		}
		if maxTools > 0 && out.ToolCalls >= maxTools {
			out.ErrorClass = ErrClassToolBudget
			return fmt.Errorf("agenttriage: tool budget exceeded")
		}
		if r.Tools == nil {
			out.ErrorClass = ErrClassInternal
			return fmt.Errorf("agenttriage: tool requested without executor")
		}
		obs := r.Tools.Call(ctx, call.Function.Name, json.RawMessage(call.Function.Arguments))
		out.ToolCalls++
		data, _ := json.Marshal(obs)
		*messages = append(*messages, llm.ChatMessage{Role: "tool", ToolCallID: call.ID, Content: string(data)})
	}
	if violation {
		*protocolNudged = true
	}
	return nil
}

// chat calls the provider with up to chatMaxAttempts attempts: transient
// failures (transport errors, HTTP 429 and HTTP 5xx) retry after chatBackoff,
// while every other error is terminal on the first attempt.
func (r AgentRunner) chat(ctx context.Context, system string, messages []llm.ChatMessage, defs []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	return chatWithTransientRetry(ctx, r.Sleep, r.Client, llm.Analyze, system, messages, defs)
}

// classifyRunErr maps a run error onto the stable failure class recorded in
// partial artifacts. Context errors split into timeout/canceled; every other
// chat-side failure is a provider error.
func classifyRunErr(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ErrClassTimeout
	case errors.Is(err, context.Canceled):
		return ErrClassCanceled
	default:
		return ErrClassProvider
	}
}

// isTransientLLMError classifies a provider error as worth retrying. llm.Chat
// surfaces transport failures as "llm request:"/"llm read:" prefixes and
// non-200 responses as "llm status <code>:" — retries cover transport errors,
// HTTP 429 and any 5xx, while 4xx and contract-level errors stay terminal.
func isTransientLLMError(err error) bool {
	s := err.Error()
	if i := strings.Index(s, "llm status "); i >= 0 {
		code := s[i+len("llm status "):]
		return strings.HasPrefix(code, "429") || (len(code) > 0 && code[0] == '5')
	}
	switch {
	case strings.HasPrefix(s, "llm request:"), strings.HasPrefix(s, "llm read:"):
		return true
	case strings.HasPrefix(s, "llm"):
		return false
	default:
		// An unwrapped transport failure (dial refused, reset, EOF) has no
		// llm prefix at all; retry it like the wrapped request errors.
		return true
	}
}

// assessmentMachineFields are top-level assessment fields a model may
// never supply. They are either composed by deterministic code from
// recorded evidence (fact gate, policy/automation, artifact audit, support
// and proof verification) or removed by the v2 cutover. The check runs
// before generic unknown-field rejection so the error names the ownership
// violation instead of reporting a mere schema miss.
var assessmentMachineFields = map[string]string{
	"fact_validation":        "the deterministic fact gate owns this field",
	"fact_validation_detail": "the deterministic fact gate owns this field",
	"automation":             "deterministic policy owns this field",
	"automation_reason":      "deterministic policy owns this field",
	"audit":                  "the artifact writer owns this field",
	"verdict_source":         "the artifact writer owns this field",
	"support":                "computed support owns this field",
	"support_level":          "computed support owns this field",
	"decision_support":       "computed support owns this field",
	"proofs":                 "the deterministic verifier owns this field",
	"falsifier_proofs":       "the deterministic verifier owns this field",
	"falsifier_verification": "the deterministic verifier owns this field",
	"machine_disposition":    "deterministic policy owns this field",
	"machine_safe":           "deterministic policy owns this field",
	"disposition":            "deterministic policy owns this field",
	"policy_outcome":         "deterministic policy owns this field",
	"human_decision":         "the human review record owns this field",
	"recommendation":         "v2 carries proposed_action instead",
}

// decodeAssessment extracts and validates assessment.v2; wantFindingID binds
// the response identity to the input finding — an empty or mismatched
// finding_id is a technical error, never silently corrected.
//
// Ingress is strict and fail-closed: the schema version must be
// assessment.v2, unknown or machine-owned fields are rejected (including
// every deterministic annotation a model might try to self-declare), a
// claim is always an object with a declared premise basis — bare-string
// claims and free-form status are not normalized — and evidence_refs may
// only name declared evidence ids. A claim id cited as evidence is a
// dangling evidence reference; dependencies belong in depends_on. The same
// holds for falsifier proposals: per-entry strictness is enforced by
// FalsifierProposal itself during decode, and a duplicate proposal id, a
// dangling claim_id/evidence_refs binding or a proposal evidence entry
// without a canonical det:<observation-id> locator fails here.
//
// The final gate is ValidateHumanAssessment: the claim premise graph, its
// namespaces, the counterarguments and the proposed action with its
// decisive closure must all be structurally sound before the assessment is
// accepted.
//
// This is the proposal-only ingress required by S-06: the agent describes
// what to verify and what it recommends to a human, never the outcome —
// nothing here creates a verdict, a Claim, a NegativeVerification, a
// machine disposition or any other Product A authority object.
func decodeAssessment(content, wantFindingID string) (Assessment, error) {
	return decodeAssessmentSchema(content, wantFindingID, AssessmentSchemaVersion)
}

// decodeAssessmentSchema is private to recorded version-specific replay.
func decodeAssessmentSchema(content, wantFindingID, schemaVersion string) (Assessment, error) {
	var a Assessment
	// llm.ExtractJSON is the only JSON extraction point: it returns the
	// first balanced span, tolerating markdown fences and surrounding
	// prose and never accepting an unclosed (truncated) object. Prose can
	// still shadow the assessment — a bracketed note or a stray brace
	// yields an earlier span — so the scan walks candidates until one
	// declares schema_version assessment.v2; every earlier balanced value
	// (prose fragments, arrays, foreign documents, historical v1 records)
	// is skipped. Once an assessment.v2 candidate is found the strict
	// validation below applies unchanged: a malformed assessment is never
	// stepped over in search of a later one.
	var raw string
	rest := content
	for {
		candidate := extractJSON(rest)
		if candidate == "" {
			return a, fmt.Errorf("response contains no %s JSON object", schemaVersion)
		}
		if strings.HasPrefix(candidate, "{") {
			var probe struct {
				SchemaVersion string `json:"schema_version"`
			}
			if err := json.Unmarshal([]byte(candidate), &probe); err != nil {
				if strings.Contains(candidate, `"`+schemaVersion+`"`) {
					return a, fmt.Errorf("assessment JSON does not decode: %w", err)
				}
			} else if probe.SchemaVersion == schemaVersion {
				raw = candidate
				break
			}
		}
		if i := strings.Index(rest, candidate); i >= 0 && i+len(candidate) < len(rest) {
			rest = rest[i+len(candidate):]
			continue
		}
		return a, fmt.Errorf("response contains no %s JSON object", schemaVersion)
	}
	// Machine-owned fields exist in the Assessment struct, so generic
	// unknown-field rejection would accept them silently. Name each
	// ownership violation explicitly before decoding.
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return a, fmt.Errorf("assessment JSON does not decode: %w", err)
	}
	names := make([]string, 0, len(top))
	for name := range top {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if reason, forbidden := assessmentMachineFields[name]; forbidden {
			return a, fmt.Errorf("assessment field %q is forbidden: %s", name, reason)
		}
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, fmt.Errorf("assessment JSON does not decode: %w", err)
	}
	if a.SchemaVersion != schemaVersion {
		return a, fmt.Errorf("schema_version %q is not %s", a.SchemaVersion, schemaVersion)
	}
	if schemaVersion == "assessment.v2" && (len(a.EnvironmentVariables) != 0 || len(a.ConditionalActions) != 0 || a.ProposedAction.Kind == HumanActionAcceptEnvironmentalMitigation) {
		return a, errors.New("assessment.v2 cannot carry later environment branch semantics")
	}
	if !a.Verdict.Valid() {
		return a, errors.New("missing verdict")
	}
	if a.FindingID == "" {
		return a, errors.New("missing finding_id")
	}
	if a.FindingID != wantFindingID {
		return a, fmt.Errorf("finding_id %q does not match input %q", a.FindingID, wantFindingID)
	}
	// Claims may cite only declared evidence ids; a dangling reference is a
	// structural error reported to the repair turn with the exact claim and
	// id, never an INVALID the fact gate has to absorb. A claim id is never
	// evidence: citing another claim here is the same dangling error, and
	// the model must express that relation through depends_on instead.
	declared := make(map[string]EvidenceRef, len(a.Evidence))
	for _, ev := range a.Evidence {
		declared[ev.ID] = ev
	}
	claimIDs := make(map[string]bool, len(a.Claims))
	for _, claim := range a.Claims {
		if schemaVersion == AssessmentSchemaVersion && strings.HasPrefix(claim.ID, "environment:") {
			return a, fmt.Errorf("claim id %q is reserved for branch-local human environment premises", claim.ID)
		}
		claimIDs[claim.ID] = true
	}
	for i, claim := range a.Claims {
		name := claim.ID
		if name == "" {
			name = fmt.Sprintf("claims[%d]", i)
		}
		for _, ref := range claim.EvidenceRefs {
			if _, ok := declared[ref]; !ok {
				return a, fmt.Errorf("claim %q cites undeclared evidence id %q", name, ref)
			}
		}
	}
	// Falsifier proposals bind to this assessment only: ids must be unique,
	// claim_id must name a declared claim, evidence_refs must be non-empty,
	// and every entry must name a declared evidence id whose locator is the
	// canonical det:<observation-id> citation — a proposal anchored to a
	// prose/file/path reference carries no observation the verifier can
	// re-derive, so it is a repairable shape error here. Whether the cited
	// evidence id is owned by the proposal's own claim stays verifier-owned
	// ("evidence reference is not owned by claim"), not decode. Per-entry
	// shape rules — required fields, known kind, non-empty subjects, no
	// self-declared verification fields — are enforced inside
	// FalsifierProposal.UnmarshalJSON before this point.
	proposalIDs := make(map[string]bool, len(a.FalsifierProposals))
	for _, proposal := range a.FalsifierProposals {
		if proposalIDs[proposal.ID] {
			return a, fmt.Errorf("duplicate falsifier proposal id %q", proposal.ID)
		}
		proposalIDs[proposal.ID] = true
		if !claimIDs[proposal.ClaimID] {
			return a, fmt.Errorf("falsifier proposal %q cites undeclared claim id %q", proposal.ID, proposal.ClaimID)
		}
		if len(proposal.EvidenceRefs) == 0 {
			return a, fmt.Errorf("falsifier proposal %q requires non-empty evidence_refs", proposal.ID)
		}
		for _, ref := range proposal.EvidenceRefs {
			ev, ok := declared[ref]
			if !ok {
				return a, fmt.Errorf("falsifier proposal %q cites undeclared evidence id %q", proposal.ID, ref)
			}
			if !canonicalDetLocator(ev.Locator) {
				return a, fmt.Errorf("falsifier proposal %q cites evidence %q without a canonical det:<observation-id> locator", proposal.ID, ref)
			}
		}
	}
	if err := ValidateHumanAssessment(a); err != nil {
		return a, err
	}
	return a, nil
}

// canonicalDetLocator reports whether locator is the canonical citation of
// one recorded tool observation: "det:<observation-id>" — lowercase scheme,
// no padding, no @sha256 suffix (the prompt forbids hashes on det:
// citations), and an id drawn from the audited observation-id charset. The
// forgiving spellings the fact gate tolerates for claim evidence are
// deliberately not accepted for proposal bindings: a falsifier proof must
// trace to one reproducible observation, so the contract form is enforced
// at decode.
func canonicalDetLocator(locator string) bool {
	_, ok := canonicalObservationID(locator, "det:")
	return ok
}

// canonicalObservationID extracts the observation id from a canonical
// "<scheme>:<observation-id>" evidence locator — lowercase scheme, no
// padding, no @sha256 suffix (the prompt forbids hashes on observation
// citations), and an id drawn from the audited observation-id charset.
// The forgiving spellings the fact gate tolerates for claim evidence are
// deliberately not accepted for proposal bindings: a falsifier proof must
// trace to one reproducible observation.
func canonicalObservationID(locator, scheme string) (string, bool) {
	id, ok := strings.CutPrefix(locator, scheme)
	if !ok || id == "" {
		return "", false
	}
	for _, r := range id {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return "", false
		}
	}
	return id, true
}

// repairMessage composes the single repair-turn user message: the decode
// error (field-level diagnostics only — the raw model response is never
// echoed back) plus the compact assessment.v2 schema reminder.
func repairMessage(parseErr error, finish string, truncated bool) string {
	if finish == "length" || truncated {
		// Truncation is not a formatting mistake: asking for the same long
		// answer again burns the step budget. Ask for a shorter one.
		return fmt.Sprintf("Repair exactly once: your previous response was cut off by the output length limit and did not decode (%v). Return a much shorter %s JSON object — at most two sentences of summary and at most four claims, each with short statements — preserving every declared environment assignment — and nothing else. %s", parseErr, AssessmentSchemaVersion, assessmentShape)
	}
	if strings.Contains(parseErr.Error(), "cites undeclared evidence id") {
		return fmt.Sprintf("Repair exactly once: return only a valid %s JSON object. The previous response did not decode: %v. `evidence_refs` may contain only ids declared in the top-level `evidence` array — a claim id is not evidence; express a claim relation through `depends_on`. Keep the claim and cite the evidence it actually relies on. %s", AssessmentSchemaVersion, parseErr, assessmentShape)
	}
	return fmt.Sprintf("Repair exactly once: return only a valid %s JSON object. The previous response did not decode: %v. %s", AssessmentSchemaVersion, parseErr, assessmentShape)
}
