package triage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// ModelMandatoryConditionSource adapts the deterministic exploit model to the
// proof contract. Models are keyed by advisory id; no assessment text is read.
type ModelMandatoryConditionSource struct {
	Models           map[string]domain.ExploitModel
	RuleID           string
	RuleVersion      string
	Module           string
	ResolvedVersion  string
	SnapshotHash     string
	BuildContextHash string
	Ruleset          string
}

func (s ModelMandatoryConditionSource) RuleSetHash() string { return s.Ruleset }

func (s ModelMandatoryConditionSource) Resolve(ctx context.Context, in MandatoryConditionLookup) (MandatoryCondition, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return MandatoryCondition{}, err
	}
	if s.Ruleset == "" || s.SnapshotHash == "" || s.BuildContextHash == "" {
		// Fail closed: an unbound source can never support a proof, and
		// saying so explicitly keeps the failure mode honest instead of
		// returning a condition the verifier must then reject.
		return MandatoryCondition{}, ErrMandatorySourceUnbound
	}
	model, ok := s.Models[in.AdvisoryID]
	if !ok {
		return MandatoryCondition{}, fmt.Errorf("mandatory condition source: advisory %q unsupported", in.AdvisoryID)
	}
	if s.Module != "" && s.Module != in.Module {
		return MandatoryCondition{}, fmt.Errorf("module binding mismatch")
	}
	if s.ResolvedVersion != "" && s.ResolvedVersion != in.ResolvedVersion {
		return MandatoryCondition{}, fmt.Errorf("version binding mismatch")
	}
	if s.SnapshotHash != "" && s.SnapshotHash != in.SnapshotHash {
		return MandatoryCondition{}, fmt.Errorf("snapshot binding mismatch")
	}
	for _, c := range model.MandatoryConditions {
		if string(c.ID) != in.Proposal.ConditionID {
			continue
		}
		if c.Subject == nil && len(c.Subjects) == 0 {
			return MandatoryCondition{}, fmt.Errorf("condition %q has no subjects", c.ID)
		}
		subs := append([]domain.SymbolRef(nil), c.Subjects...)
		if c.Subject != nil {
			subs = append([]domain.SymbolRef{*c.Subject}, subs...)
		}
		expected := make([]FalsifierSubject, 0, len(subs))
		for _, x := range subs {
			expected = append(expected, FalsifierSubject{Package: x.Package, Symbol: x.Symbol})
		}
		kind := conditionFalsifierKind(c.Kind)
		if kind == "" {
			return MandatoryCondition{}, fmt.Errorf("condition kind unsupported")
		}
		// A symbol-reachable condition can only be falsified by function
		// deadness. That is a negative only under the model's admitted
		// invocation-necessity premise: DEFECTIVE_CHECK binds the check,
		// OMITTED_CHECK binds the omission site, and UNRESOLVED/nil admits
		// nothing. A check-only subject set never satisfies an omission
		// contract.
		if kind == FalsifierLocusFunctionAbsent {
			if _, perr := domain.RequireDeadnessPremise(model.DefectSemantics, subs); perr != nil {
				return MandatoryCondition{}, fmt.Errorf("condition %q: %w", c.ID, perr)
			}
		}
		return MandatoryCondition{ID: string(c.ID), Kind: kind, Mandatory: c.Mandatory, RuleID: s.RuleID, RuleVersion: s.RuleVersion, ExpectedSubjects: expected, SnapshotHash: s.SnapshotHash, BuildContextHash: s.BuildContextHash, DefectSemantics: model.DefectSemantics}, nil
	}
	return MandatoryCondition{}, fmt.Errorf("condition %q unsupported", in.Proposal.ConditionID)
}

func conditionFalsifierKind(k domain.ConditionKind) FalsifierKind {
	switch k {
	case domain.ConditionMissingCall:
		return FalsifierCodeAbsent
	case domain.ConditionSymbolReachable:
		return FalsifierLocusFunctionAbsent
	case domain.ConditionBuild:
		return FalsifierLocusPackageAbsent
	}
	return ""
}

// MandatoryConditionSourceOptions binds the deterministic adapter to one
// resolved finding: the advisory-keyed exploit models plus the exact
// module/version/snapshot/build identity the proof must be issued against.
// Every field is required — a partially bound source can never admit a proof,
// and NewConfiguredMandatoryConditionSource refuses to create one.
type MandatoryConditionSourceOptions struct {
	Models           map[string]domain.ExploitModel
	RuleID           string
	RuleVersion      string
	RuleSetHash      string
	Module           string
	ResolvedVersion  string
	SnapshotHash     string
	BuildContextHash string
}

// ErrMandatorySourceUnbound marks a source that is not bound to a ruleset,
// snapshot and build context; under the proof contract such a source can only
// ever answer UNKNOWN.
var ErrMandatorySourceUnbound = errors.New("mandatory condition source is not bound to a ruleset, snapshot and build context")

// NewConfiguredMandatoryConditionSource returns the production adapter: it
// fails closed at construction when any binding is missing, so an unbound
// source can never be used to admit a proof by accident.
func NewConfiguredMandatoryConditionSource(o MandatoryConditionSourceOptions) (MandatoryConditionSource, error) {
	switch {
	case len(o.Models) == 0:
		return nil, errors.New("mandatory condition source: no exploit models")
	case o.RuleID == "" || o.RuleVersion == "":
		return nil, errors.New("mandatory condition source: rule id and version are required")
	case o.RuleSetHash == "":
		return nil, errors.New("mandatory condition source: ruleset hash is required")
	case o.Module == "":
		return nil, errors.New("mandatory condition source: module binding is required")
	case o.ResolvedVersion == "":
		return nil, errors.New("mandatory condition source: resolved version binding is required")
	case o.SnapshotHash == "":
		return nil, errors.New("mandatory condition source: snapshot binding is required")
	case o.BuildContextHash == "":
		return nil, errors.New("mandatory condition source: build context binding is required")
	}
	return ModelMandatoryConditionSource{
		Models:           o.Models,
		RuleID:           o.RuleID,
		RuleVersion:      o.RuleVersion,
		Ruleset:          o.RuleSetHash,
		Module:           o.Module,
		ResolvedVersion:  o.ResolvedVersion,
		SnapshotHash:     o.SnapshotHash,
		BuildContextHash: o.BuildContextHash,
	}, nil
}

// NewModelMandatoryConditionSource returns an intentionally unbound adapter:
// it resolves deterministic conditions for tests and diagnostics only and
// never admits a proof, because the ruleset, snapshot and build-context
// bindings are empty. Production callers use
// NewConfiguredMandatoryConditionSource.
func NewModelMandatoryConditionSource(models map[string]domain.ExploitModel, ruleID, ruleVersion string) MandatoryConditionSource {
	return ModelMandatoryConditionSource{Models: models, RuleID: ruleID, RuleVersion: ruleVersion}
}

func canonicalConditionKey(advisory, module, version, snapshot string) string {
	return strings.Join([]string{advisory, module, version, snapshot}, "\x00")
}
