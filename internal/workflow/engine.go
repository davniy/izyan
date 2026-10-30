package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/persistence"
)

type Transition struct {
	Next   domain.WorkflowState
	Reason string
}

type StateHandler interface {
	State() domain.WorkflowState
	Run(ctx context.Context, c *domain.AnalysisCase) (Transition, error)
}

type Engine struct {
	handlers map[domain.WorkflowState]StateHandler
	store    persistence.CaseStore
	// FailureState is the registered continuation for a recoverable analysis
	// failure or an exhausted analysis budget. It is not a terminal state: an
	// analysis failure must still reach composition/reporting, so the
	// orchestrator points this at its composition or finalization boundary.
	// Empty keeps the legacy behavior of terminating at StateFailed.
	FailureState domain.WorkflowState
}

// detachedContinuationTimeout bounds the cancellation-detached context used
// only for persistence and the registered failure continuation. Analysis work
// never resumes on it.
const detachedContinuationTimeout = 2 * time.Minute

func New(store persistence.CaseStore, handlers ...StateHandler) *Engine {
	m := make(map[domain.WorkflowState]StateHandler, len(handlers))
	for _, h := range handlers {
		m[h.State()] = h
	}
	return &Engine{handlers: m, store: store}
}

func (e *Engine) Run(ctx context.Context, c *domain.AnalysisCase) error {
	return e.RunUntil(ctx, c, "")
}

// RunUntil runs the workflow until it reaches stop or a terminal state. The
// stop state is not executed: it is the record-only boundary that keeps a
// child assessment from running request discovery, composition or reporting.
// An empty stop runs to a terminal state, exactly like Run.
func (e *Engine) RunUntil(ctx context.Context, c *domain.AnalysisCase, stop domain.WorkflowState) error {
	var (
		budgetHandled bool
		analysisEnded bool
	)
	for !isTerminal(c.Workflow.State) && c.Workflow.State != stop {
		h, ok := e.handlers[c.Workflow.State]
		if !ok {
			return fmt.Errorf("no handler for state %s", c.Workflow.State)
		}
		start := time.Now()
		runCtx, cancel := e.handlerContext(ctx, analysisEnded)
		tr, err := h.Run(runCtx, c)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			// A cancelled or timed-out analysis context is an analysis
			// failure, not a persistence error: record it and continue to
			// the registered reporting boundary. Everything else remains an
			// explicit error.
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			recordGap(c, timeoutGap(c.ID, err))
			analysisEnded = true
			tr = Transition{Next: e.failureContinuation(stop), Reason: "analysis context ended: " + err.Error()}
		}
		next := tr.Next
		reason := tr.Reason

		if next == domain.StateFailed {
			// A handler-declared analysis failure is recoverable only up to
			// the registered continuation. Once analysis has ended, a FAILED
			// transition from the finalization chain is the terminal answer:
			// redirecting it again would re-run reporting forever.
			if !analysisEnded && c.Workflow.State != e.FailureState &&
				c.Workflow.State != domain.StateBuildReport {
				if cont := e.failureContinuation(stop); cont != "" {
					next = cont
					reason = "analysis failure: " + tr.Reason
					analysisEnded = true
				}
			}
		}
		if ctx.Err() != nil && !isTerminal(next) && !analysisEnded {
			recordGap(c, timeoutGap(c.ID, ctx.Err()))
			analysisEnded = true
			next = e.failureContinuation(stop)
			reason = "analysis context ended: " + ctx.Err().Error()
		}
		if c.Workflow.Timings == nil {
			c.Workflow.Timings = map[string]float64{}
		}
		c.Workflow.Timings[string(c.Workflow.State)] += time.Since(start).Seconds()
		c.Workflow.PreviousState = c.Workflow.State
		c.Workflow.State = next
		c.Workflow.Reason = reason
		c.Workflow.UpdatedAt = time.Now().UTC()
		c.Workflow.Iteration++
		if !budgetHandled {
			if lim := c.Workflow.Limits.MaxIterations; lim > 0 && c.Workflow.Iteration >= lim && !isTerminal(c.Workflow.State) {
				// An exhausted analysis budget is an analysis failure, never
				// an environmental answer. Finalization/report writing must
				// still run, so route once to the registered continuation.
				recordGap(c, budgetGap(c.ID))
				c.Workflow.State = e.failureContinuation(stop)
				c.Workflow.Reason = "analysis budget exhausted (max iterations)"
				budgetHandled = true
				analysisEnded = true
			}
		}
		if err := e.save(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// handlerContext returns the context a handler runs under. After analysis has
// ended (cancellation, timeout or budget exhaustion) the registered failure
// continuation runs on a bounded cancellation-detached context so reporting
// and persistence can finish; analysis states never see that context.
func (e *Engine) handlerContext(ctx context.Context, analysisEnded bool) (context.Context, context.CancelFunc) {
	if !analysisEnded {
		return ctx, nil
	}
	return context.WithTimeout(context.WithoutCancel(ctx), detachedContinuationTimeout)
}

// save persists the case. When the analysis context is already cancelled, a
// bounded cancellation-detached context is used so the durable record and the
// eventual diagnostic report are not lost; a persistence failure is still an
// explicit error and never claims the report was written.
func (e *Engine) save(ctx context.Context, c *domain.AnalysisCase) error {
	if ctx.Err() == nil {
		return e.store.Save(ctx, c)
	}
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedContinuationTimeout)
	defer cancel()
	return e.store.Save(saveCtx, c)
}

// failureContinuation resolves where a recoverable failure goes. A registered
// continuation must be a real, non-terminal state; anything else falls back to
// the terminal FAILED state.
func (e *Engine) failureContinuation(stop domain.WorkflowState) domain.WorkflowState {
	if e.FailureState != "" && !isTerminal(e.FailureState) {
		if e.FailureState == stop {
			return e.FailureState
		}
		if _, ok := e.handlers[e.FailureState]; ok {
			return e.FailureState
		}
	}
	return domain.StateFailed
}

func isTerminal(s domain.WorkflowState) bool {
	return s == domain.StateCompleted || s == domain.StateInconclusive || s == domain.StateFailed
}

// recordGap appends a typed case-level gap once. Repeated failures on a resumed
// case must not multiply the same diagnostic.
func recordGap(c *domain.AnalysisCase, gap domain.AnalysisGap) {
	for _, existing := range c.AnalysisGaps {
		if existing.Owner == gap.Owner && existing.Code == gap.Code && existing.Message == gap.Message {
			return
		}
	}
	c.AnalysisGaps = append(c.AnalysisGaps, gap)
}

func budgetGap(id domain.CaseID) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:        domain.GapOwnerCode,
		Code:         domain.GapAnalysisBudgetExhausted,
		Obligation:   domain.ObligationMeasurement,
		AssessmentID: assessmentID(id),
		Message:      "analysis iteration budget exhausted before the workflow reached a terminal analysis state",
	}
}

func timeoutGap(id domain.CaseID, err error) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:        domain.GapOwnerCode,
		Code:         domain.GapAnalysisTimeout,
		Obligation:   domain.ObligationMeasurement,
		AssessmentID: assessmentID(id),
		Message:      "analysis context ended before completion: " + err.Error(),
	}
}

func assessmentID(id domain.CaseID) domain.CaseID {
	if id != "" {
		return id
	}
	return domain.CaseID("assessment")
}
