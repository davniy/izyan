package triage

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// AdvisoryConditionSource derives the mandatory exploit conditions of a
// finding from the advisory's own declared vulnerable symbols — the
// authoritative, deterministic part of the OSV record. It never reads
// assessment prose, LLM output or the agent's verdict: a condition exists
// only because the advisory declares the code the vulnerability lives in,
// and its absence from the closed product/source universe is what makes the
// defect locus unable to execute.
//
// Callers must bind the source to one resolved finding (ruleset, module,
// resolved version, snapshot, build context); an unbound source never
// resolves, because NewConfiguredMandatoryConditionSource refuses it.
type AdvisoryConditionSource struct {
	AdvisoryID       string
	AdvisoryIDs      []string
	Module           string
	ResolvedVersion  string
	SnapshotHash     string
	BuildContextHash string
	RuleID           string
	RuleVersion      string
	RulesetHash      string
	Symbols          []domainSymbolRef
}

// domainSymbolRef mirrors the advisory projection's symbol reference without
// importing the domain package into this file's public surface.
type domainSymbolRef struct {
	Package string
	Symbol  string
}

// AdvisoryConditionOptions is the validated construction input.
type AdvisoryConditionOptions struct {
	AdvisoryID       string
	AdvisoryIDs      []string
	Module           string
	ResolvedVersion  string
	SnapshotHash     string
	BuildContextHash string
	RuleID           string
	RuleVersion      string
	RuleSetHash      string
	Symbols          []FalsifierSubject
}

// AdvisoryConditionID is the deterministic condition identity of one
// advisory's code-absence condition. It is a pure function of the advisory id
// the agent already sees, so a proposal either names the authoritative
// condition or is rejected — there is nothing to guess and nothing to publish
// out of band.
func AdvisoryConditionID(advisoryID string) string {
	return "cond-" + strings.TrimSpace(advisoryID)
}

// NewAdvisoryConditionSource builds the deterministic condition source from
// the advisory's declared symbols. It fails closed when the advisory declares
// no symbols: without an authoritative locus there is no condition, and a
// finding with no condition can never be dismissed by a falsifier.
func NewAdvisoryConditionSource(o AdvisoryConditionOptions) (MandatoryConditionSource, error) {
	switch {
	case strings.TrimSpace(o.AdvisoryID) == "":
		return nil, fmt.Errorf("advisory condition source: advisory id is required")
	case len(o.Symbols) == 0:
		return nil, fmt.Errorf("advisory condition source: advisory %s declares no vulnerable symbols", o.AdvisoryID)
	case o.RuleSetHash == "":
		return nil, fmt.Errorf("advisory condition source: ruleset hash is required")
	case o.Module == "":
		return nil, fmt.Errorf("advisory condition source: module binding is required")
	case o.ResolvedVersion == "":
		return nil, fmt.Errorf("advisory condition source: resolved version binding is required")
	case o.SnapshotHash == "":
		return nil, fmt.Errorf("advisory condition source: snapshot binding is required")
	case o.BuildContextHash == "":
		return nil, fmt.Errorf("advisory condition source: build context binding is required")
	}
	symbols := make([]domainSymbolRef, 0, len(o.Symbols))
	for _, s := range o.Symbols {
		if strings.TrimSpace(s.Package) == "" || strings.TrimSpace(s.Symbol) == "" {
			continue
		}
		symbols = append(symbols, domainSymbolRef{Package: s.Package, Symbol: s.Symbol})
	}
	if len(symbols) == 0 {
		return nil, fmt.Errorf("advisory condition source: advisory %s declares no usable symbols", o.AdvisoryID)
	}
	sort.Slice(symbols, func(i, j int) bool {
		a, b := symbols[i], symbols[j]
		return a.Package+"\x00"+a.Symbol < b.Package+"\x00"+b.Symbol
	})
	ids := []string{o.AdvisoryID}
	for _, alt := range o.AdvisoryIDs {
		if alt != "" && alt != o.AdvisoryID {
			ids = append(ids, alt)
		}
	}
	return AdvisoryConditionSource{
		AdvisoryID:       o.AdvisoryID,
		AdvisoryIDs:      ids,
		Module:           o.Module,
		ResolvedVersion:  o.ResolvedVersion,
		SnapshotHash:     o.SnapshotHash,
		BuildContextHash: o.BuildContextHash,
		RuleID:           o.RuleID,
		RuleVersion:      o.RuleVersion,
		RulesetHash:      o.RuleSetHash,
		Symbols:          symbols,
	}, nil
}

func (s AdvisoryConditionSource) RuleSetHash() string { return s.RulesetHash }

func (s AdvisoryConditionSource) Resolve(ctx context.Context, in MandatoryConditionLookup) (MandatoryCondition, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return MandatoryCondition{}, err
	}
	if s.RulesetHash == "" || s.SnapshotHash == "" || s.BuildContextHash == "" {
		return MandatoryCondition{}, ErrMandatorySourceUnbound
	}
	bound := false
	for _, id := range s.AdvisoryIDs {
		if in.AdvisoryID == id {
			bound = true
			break
		}
	}
	if !bound {
		return MandatoryCondition{}, fmt.Errorf("advisory condition source: advisory %q is not one of the bound advisories", in.AdvisoryID)
	}
	if in.Module != s.Module {
		return MandatoryCondition{}, fmt.Errorf("advisory condition source: module binding mismatch")
	}
	if in.ResolvedVersion != s.ResolvedVersion {
		return MandatoryCondition{}, fmt.Errorf("advisory condition source: version binding mismatch")
	}
	if in.SnapshotHash != s.SnapshotHash {
		return MandatoryCondition{}, fmt.Errorf("advisory condition source: snapshot binding mismatch")
	}
	conditionID := AdvisoryConditionID(s.AdvisoryID)
	if in.Proposal.ConditionID != conditionID {
		return MandatoryCondition{}, fmt.Errorf("advisory condition source: condition %q is not %q", in.Proposal.ConditionID, conditionID)
	}
	expected := make([]FalsifierSubject, 0, len(s.Symbols))
	for _, x := range s.Symbols {
		expected = append(expected, FalsifierSubject{Package: x.Package, Symbol: x.Symbol})
	}
	return MandatoryCondition{
		ID:               conditionID,
		Kind:             FalsifierCodeAbsent,
		Mandatory:        true,
		RuleID:           s.RuleID,
		RuleVersion:      s.RuleVersion,
		ExpectedSubjects: expected,
		SnapshotHash:     s.SnapshotHash,
		BuildContextHash: s.BuildContextHash,
	}, nil
}
