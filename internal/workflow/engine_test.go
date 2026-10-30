package workflow_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/workflow"
)

// memStore records saves and can fail on demand. Load is unused by the engine.
type memStore struct {
	mu        sync.Mutex
	saves     int
	failAfter int
	err       error
	last      *domain.AnalysisCase
}

func (s *memStore) Create(context.Context, *domain.AnalysisCase) error { return nil }

func (s *memStore) Load(context.Context, domain.CaseID) (*domain.AnalysisCase, error) {
	return nil, fmt.Errorf("memStore: Load not implemented")
}

func (s *memStore) Save(_ context.Context, c *domain.AnalysisCase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.err != nil && (s.failAfter == 0 || s.saves > s.failAfter) {
		return s.err
	}
	s.last = c
	return nil
}

type stepHandler struct {
	state  domain.WorkflowState
	next   domain.WorkflowState
	err    error
	run    func(context.Context, *domain.AnalysisCase)
	runs   int
	ctxErr error
	seen   *[]domain.WorkflowState
}

func (h *stepHandler) State() domain.WorkflowState { return h.state }

func (h *stepHandler) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	h.runs++
	h.ctxErr = ctx.Err()
	if h.seen != nil {
		*h.seen = append(*h.seen, c.Workflow.State)
	}
	if h.run != nil {
		h.run(ctx, c)
	}
	if h.err != nil {
		return workflow.Transition{}, h.err
	}
	return workflow.Transition{Next: h.next, Reason: "step"}, nil
}

func hasGap(c *domain.AnalysisCase, code domain.GapCode) bool {
	for _, g := range c.AnalysisGaps {
		if g.Code == code {
			return true
		}
	}
	return false
}

func newCase(id string, limits domain.AnalysisLimits) *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: domain.CaseID(id),
		Workflow: domain.WorkflowStatus{
			State:  domain.StateCreated,
			Limits: limits,
		},
	}
}

// TestWorkflowFailureReporting pins the engine's failure policy:
//
//   - an exhausted analysis budget becomes FAILED and is routed to the
//     registered continuation, never to a terminal INCONCLUSIVE;
//   - finalization/report writing is not repeatedly stopped by the exhausted
//     budget;
//   - a handler-declared analysis failure continues to the registered
//     reporting/composition boundary instead of terminating before it;
//   - a cancelled analysis context records a timeout and runs the continuation
//     on a bounded cancellation-detached context;
//   - persistence failures remain explicit errors.
func TestWorkflowFailureReporting(t *testing.T) {
	t.Run("budget exhaustion routes to reporting and never INCONCLUSIVE", func(t *testing.T) {
		store := &memStore{}
		var seen []domain.WorkflowState
		first := &stepHandler{state: domain.StateCreated, next: domain.StateSnapshotProduct, seen: &seen}
		second := &stepHandler{state: domain.StateSnapshotProduct, next: domain.StateCollectEvidence, seen: &seen}
		report := &stepHandler{state: domain.StateBuildReport, next: domain.StateCompleted, seen: &seen}
		engine := workflow.New(store, first, second, report)
		engine.FailureState = domain.StateBuildReport

		c := newCase("CASE-BUDGET", domain.AnalysisLimits{MaxIterations: 2})
		if err := engine.Run(context.Background(), c); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if c.Workflow.State != domain.StateCompleted {
			t.Fatalf("final state=%s, want COMPLETED after reporting", c.Workflow.State)
		}
		if report.runs != 1 {
			t.Fatalf("reporting continuation ran %d times, want 1", report.runs)
		}
		if !hasGap(c, domain.GapAnalysisBudgetExhausted) {
			t.Fatalf("missing ANALYSIS_BUDGET_EXHAUSTED gap: %+v", c.AnalysisGaps)
		}
		for _, state := range seen {
			if state == domain.StateInconclusive {
				t.Fatalf("budget exhaustion reached terminal INCONCLUSIVE; visited %v", seen)
			}
		}
		if store.last == nil {
			t.Fatal("case was never persisted")
		}
	})

	t.Run("exhausted budget does not stop finalization", func(t *testing.T) {
		store := &memStore{}
		first := &stepHandler{state: domain.StateCreated, next: domain.StateSnapshotProduct}
		report := &stepHandler{state: domain.StateBuildReport, next: domain.StateCompleted}
		engine := workflow.New(store, first, report)
		engine.FailureState = domain.StateBuildReport

		c := newCase("CASE-FINALIZE", domain.AnalysisLimits{MaxIterations: 1})
		if err := engine.Run(context.Background(), c); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.runs != 1 {
			t.Fatalf("reporting continuation ran %d times, want 1", report.runs)
		}
		if c.Workflow.State != domain.StateCompleted {
			t.Fatalf("final state=%s, want COMPLETED", c.Workflow.State)
		}
	})

	t.Run("declared analysis failure continues to reporting", func(t *testing.T) {
		store := &memStore{}
		failing := &stepHandler{state: domain.StateCreated, next: domain.StateFailed}
		report := &stepHandler{state: domain.StateBuildReport, next: domain.StateCompleted}
		engine := workflow.New(store, failing, report)
		engine.FailureState = domain.StateBuildReport

		c := newCase("CASE-FAILURE", domain.AnalysisLimits{MaxIterations: 10})
		if err := engine.Run(context.Background(), c); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.runs != 1 {
			t.Fatalf("reporting continuation ran %d times, want 1", report.runs)
		}
		if c.Workflow.State != domain.StateCompleted {
			t.Fatalf("final state=%s, want COMPLETED", c.Workflow.State)
		}
	})

	t.Run("no continuation keeps terminal FAILED, not INCONCLUSIVE", func(t *testing.T) {
		store := &memStore{}
		first := &stepHandler{state: domain.StateCreated, next: domain.StateSnapshotProduct}
		engine := workflow.New(store, first)

		c := newCase("CASE-NOCONT", domain.AnalysisLimits{MaxIterations: 1})
		if err := engine.Run(context.Background(), c); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if c.Workflow.State != domain.StateFailed {
			t.Fatalf("final state=%s, want FAILED", c.Workflow.State)
		}
		if !hasGap(c, domain.GapAnalysisBudgetExhausted) {
			t.Fatalf("missing ANALYSIS_BUDGET_EXHAUSTED gap: %+v", c.AnalysisGaps)
		}
	})

	t.Run("cancelled analysis runs reporting on a detached context", func(t *testing.T) {
		store := &memStore{}
		ctx, cancel := context.WithCancel(context.Background())
		first := &stepHandler{
			state: domain.StateCreated,
			next:  domain.StateSnapshotProduct,
			run: func(context.Context, *domain.AnalysisCase) {
				cancel()
			},
		}
		report := &stepHandler{state: domain.StateBuildReport, next: domain.StateCompleted}
		engine := workflow.New(store, first, report)
		engine.FailureState = domain.StateBuildReport

		c := newCase("CASE-CANCEL", domain.AnalysisLimits{MaxIterations: 10})
		if err := engine.Run(ctx, c); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.runs != 1 {
			t.Fatalf("reporting continuation ran %d times, want 1", report.runs)
		}
		if report.ctxErr != nil {
			t.Fatalf("reporting continuation ran on a cancelled context: %v", report.ctxErr)
		}
		if !hasGap(c, domain.GapAnalysisTimeout) {
			t.Fatalf("missing ANALYSIS_TIMEOUT gap: %+v", c.AnalysisGaps)
		}
		if c.Workflow.State != domain.StateCompleted {
			t.Fatalf("final state=%s, want COMPLETED", c.Workflow.State)
		}
	})

	t.Run("handler returns a context timeout", func(t *testing.T) {
		store := &memStore{}
		failing := &stepHandler{state: domain.StateCreated, err: context.DeadlineExceeded}
		report := &stepHandler{state: domain.StateBuildReport, next: domain.StateCompleted}
		engine := workflow.New(store, failing, report)
		engine.FailureState = domain.StateBuildReport

		c := newCase("CASE-DEADLINE", domain.AnalysisLimits{MaxIterations: 10})
		if err := engine.Run(context.Background(), c); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.runs != 1 {
			t.Fatalf("reporting continuation ran %d times, want 1", report.runs)
		}
		if !hasGap(c, domain.GapAnalysisTimeout) {
			t.Fatalf("missing ANALYSIS_TIMEOUT gap: %+v", c.AnalysisGaps)
		}
	})

	t.Run("persistence failure is an explicit error", func(t *testing.T) {
		store := &memStore{failAfter: 0, err: errors.New("disk full")}
		first := &stepHandler{state: domain.StateCreated, next: domain.StateCompleted}
		engine := workflow.New(store, first)

		c := newCase("CASE-DISK", domain.AnalysisLimits{MaxIterations: 10})
		err := engine.Run(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Fatalf("Run error=%v, want explicit persistence failure", err)
		}
	})
}
