package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/persistence"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/review"
	"github.com/fedorovmv/izyan/internal/rootcause"
	"github.com/fedorovmv/izyan/internal/states"
	"github.com/fedorovmv/izyan/internal/tracker"
	"github.com/fedorovmv/izyan/internal/vulnerability"
	"github.com/fedorovmv/izyan/internal/workflow"
)

// recordPipeline assembles the one record-assessment chain used by the root
// request and by every discovered candidate. The root.run also discovers and
// composes; a child run stops at the record-finalization boundary and never
// discovers, composes a request or writes a report.
type recordPipeline struct {
	store       persistence.CaseStore
	source      vulnerability.Source
	sourceIndex *goanalysis.Index

	repoPath        string
	snapshotOptions repository.SnapshotOptions
	snapshotProduct *domain.ProductSnapshot
	vulnID          string

	affectedResolver  affected.Resolver
	rootCause         states.RootCauseResolver
	rootCauseVerifier *rootcause.Verifier
	builder           states.ExploitBuilder
	reviewers         review.Reviewer
	evaluators        []evaluator.ConditionEvaluator
	fallback          evaluator.ConditionEvaluator
	planner           states.HypothesisPlanner
	llmClient         llm.Completer
	govulncheck       goanalysis.Runner
	negativeVerifier  *goanalysis.Verifier

	reportDir string
	tracker   tracker.Sink
	prior     *domain.AnalysisCase

	corpus     states.RelatedRecordSource
	attributor states.AttributionResolver
	intake     *states.RecordIntake

	// Request-scoped operator inputs. They are handed to the primary record
	// only: a manual root cause, locus proposal or exploit model is a
	// conclusion about the primary and must not be broadcast to children.
	manualRC  []domain.RootCause
	modelPath string
	allowExec bool
}

func (p recordPipeline) rootHandlers() []workflow.StateHandler {
	handlers := []workflow.StateHandler{
		states.Created{},
		states.SnapshotProduct{
			Repo:     repository.Service{},
			Path:     p.repoPath,
			Options:  p.snapshotOptions,
			Source:   p.sourceIndex,
			Snapshot: p.snapshotProduct,
		},
		states.ResolveVulnerability{
			Source: p.source,
			ID:     p.vulnID,
			Exact:  true,
			Next:   domain.StateDiscoverRecords,
			Intake: p.intake,
		},
		states.DiscoverRecords{Source: p.corpus, Intake: p.intake, Attributor: p.attributor},
	}
	handlers = append(handlers, p.recordHandlers(domain.StateAssessRelatedRecords, true)...)
	handlers = append(handlers,
		states.AssessRelatedRecords{Source: p.corpus, Runner: p.runRecord, Attributor: p.attributor},
		states.ComposeRequestedFinding{},
		states.BuildReport{Dir: p.reportDir, Tracker: p.tracker, Prior: p.prior},
	)
	return handlers
}

// recordHandlers is the shared deterministic record chain. primary selects the
// request-scoped manual inputs; every other handler, evaluator, verifier and
// reviewer is identical for the primary and for candidates.
func (p recordPipeline) recordHandlers(next domain.WorkflowState, primary bool) []workflow.StateHandler {
	manual := p.manualRC
	modelPath := p.modelPath
	if !primary {
		manual = nil
		modelPath = ""
	}
	return []workflow.StateHandler{
		states.CheckAffected{Resolver: p.affectedResolver},
		states.ResolveRootCause{
			Manual:    manual,
			Resolver:  p.rootCause,
			Verifier:  p.rootCauseVerifier,
			LLMClient: p.llmClient,
		},
		states.BuildExploitModel{ModelPath: modelPath, Builder: p.builder},
		states.CollectEvidence{Govulncheck: p.govulncheck, Source: p.sourceIndex},
		states.EvaluateConditions{Evaluators: p.evaluators},
		states.GapAnalysis{
			Source:     p.sourceIndex,
			Evaluators: p.evaluators,
			Planner:    p.planner,
			Fallback:   p.fallback,
			AllowExec:  p.allowExec,
		},
		states.NegativeCheck{Verifier: p.negativeVerifier},
		states.Review{Reviewer: p.reviewers, Evaluator: evaluator.VerdictEvaluator{}},
		states.RepairAnalysis{},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}, Next: next},
	}
}

// runRecord executes one isolated record assessment and finalizes that
// record's own exact requested finding. The stop state is BUILD_REPORT: the
// record pipeline ends before request discovery, composition and reporting.
func (p recordPipeline) runRecord(ctx context.Context, c *domain.AnalysisCase) error {
	engine := workflow.New(p.store, p.recordHandlers(domain.StateBuildReport, false)...)
	engine.FailureState = domain.StateBuildReport
	if err := engine.RunUntil(ctx, c, domain.StateBuildReport); err != nil {
		return err
	}
	if err := finding.Finalize(c); err != nil {
		return err
	}
	// Finalize is this record's terminal boundary: publish the same
	// requested-outcome terminal the root would select, so the persisted child
	// is a finished independent assessment rather than an in-progress case.
	if c.RequestedFinding.Outcome == domain.OutcomeFailed {
		c.Workflow.State = domain.StateFailed
		c.Workflow.Reason = "record assessment FAILED; requested finding finalized"
	} else {
		c.Workflow.State = domain.StateCompleted
		c.Workflow.Reason = "record assessment finalized; requested finding written"
	}
	c.Workflow.UpdatedAt = time.Now().UTC()
	saveCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		saveCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
	}
	if err := p.store.Save(saveCtx, c); err != nil {
		return fmt.Errorf("persist finalized record assessment: %w", err)
	}
	return nil
}

// attributionResolver admits a record's own identity first, then the
// configured captured publisher/CNA materials. A bare related edge remains
// related_only; it can never lift a positive.
func attributionResolver(materials map[string]string) states.AttributionResolver {
	if len(materials) == 0 {
		return states.OwnIdentityAttribution
	}
	uris := make([]string, 0, len(materials))
	for uri := range materials {
		uris = append(uris, uri)
	}
	sort.Strings(uris)
	source := vulnerability.LocalMaterialSource{Captures: materials}
	return func(ctx context.Context, requestedID string, record vulnerability.LoadedRecord) ([]domain.CVEAttribution, error) {
		own, ownErr := states.OwnIdentityAttribution(ctx, requestedID, record)
		if ownErr == nil {
			for _, attribution := range own {
				if attribution.Admitted() {
					return own, nil
				}
			}
		}
		captured := make([]vulnerability.CapturedMaterial, 0, len(uris))
		for _, uri := range uris {
			material, err := source.Capture(ctx, uri)
			if err != nil {
				return nil, err
			}
			captured = append(captured, material)
		}
		attribution, err := vulnerability.AdmitAttribution(vulnerability.AttributionInput{
			CVEID:     requestedID,
			Record:    record,
			EntryRefs: states.RecordAttributionEntryRefs(record.Vuln),
			Materials: captured,
		})
		if err != nil {
			if ownErr != nil {
				return nil, fmt.Errorf("%v; captured material: %w", ownErr, err)
			}
			return nil, err
		}
		return []domain.CVEAttribution{attribution}, nil
	}
}
