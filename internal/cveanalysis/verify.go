package cveanalysis

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// VerifySites records a ProposalVerification for every checkable
// assertion the current CVE research proposal displays: symbol
// existence and product reachability for each named faulting/auxiliary
// site, plus explicit UNKNOWN records for the checks this analyzer does
// not implement (site role, mechanism semantics). Records are keyed by
// proposal identity, so retries update in place and never duplicate.
//
// source may be nil — existence checks then report UNKNOWN with the
// reason rather than pretending a result. Records are emitted for
// displayed assertions even when nothing could be checked.
func VerifySites(ctx context.Context, c *domain.AnalysisCase, source *goanalysis.Index) error {
	if c == nil || c.CVEAnalysis == nil {
		return nil
	}
	prop := c.CVEAnalysis
	pkgs := AffectedPackagePaths(c.Vulnerability)
	for i, m := range prop.Mechanisms {
		if err := ctx.Err(); err != nil {
			return err
		}
		ref := domain.ProposalRef{
			Source:      domain.ProposalSourceCVEResearch,
			ID:          prop.ID,
			Revision:    prop.Revision,
			MechanismID: m.ID,
		}
		if ref.MechanismID == "" {
			ref.MechanismID = fmt.Sprintf("M-%d", i+1)
		}
		emitSiteRecords(ctx, c, source, ref, domain.AssertionFaultingSite, m.FaultingSites, pkgs)
		emitSiteRecords(ctx, c, source, ref, domain.AssertionAuxiliarySite, m.AuxiliarySites, pkgs)
		c.UpsertProposalVerification(domain.ProposalVerification{
			Proposal:  ref,
			Assertion: domain.AssertionMechanism,
			Check:     domain.CheckMechanism,
			Result:    domain.ClaimUnknown,
			Detail:    "no deterministic checker validates the defect mechanism description; it is an LLM proposal",
		})
	}
	return nil
}

// emitSiteRecords writes the SYMBOL_EXISTS, PRODUCT_REACHABLE and
// SITE_ROLE records for one site reference.
func emitSiteRecords(ctx context.Context, c *domain.AnalysisCase, source *goanalysis.Index,
	ref domain.ProposalRef, assertion domain.ProposalAssertion, sites, pkgs []string) {
	for _, raw := range sites {
		base := domain.ProposalVerification{Proposal: ref, SiteText: raw, Assertion: assertion}
		if subj, ok := NormalizeSite(raw, pkgs); ok {
			s := subj
			base.Subject = &s
		}

		exists := base
		exists.Check = domain.CheckSymbolExists
		if base.Subject == nil {
			exists.Result = domain.ClaimUnknown
			exists.Detail = "site text could not be resolved to a package and symbol; existence not checked"
		} else {
			res, detail, evID := CheckSymbolExists(ctx, c, source, *base.Subject)
			exists.Result, exists.Detail = res, detail
			if evID != "" {
				exists.EvidenceIDs = []domain.EvidenceID{evID}
			}
		}
		c.UpsertProposalVerification(exists)

		reach := base
		reach.Check = domain.CheckProductReachable
		res, detail, ids := ReachableFromEvidence(c, base.Subject)
		reach.Result, reach.Detail, reach.EvidenceIDs = res, detail, ids
		c.UpsertProposalVerification(reach)

		role := base
		role.Check = domain.CheckSiteRole
		role.Result = domain.ClaimUnknown
		role.Detail = roleUnknownDetail(assertion)
		c.UpsertProposalVerification(role)
	}
}

func roleUnknownDetail(assertion domain.ProposalAssertion) string {
	if assertion == domain.AssertionFaultingSite {
		return "faulting role is an LLM classification; no deterministic checker proves the defect executes here — existence or reachability alone do not confirm it"
	}
	return "auxiliary role is an LLM classification; no deterministic checker proves this function only supports the path and is not itself defect-bearing"
}

// CheckSymbolExists verifies one symbol against the analyzed source via
// Index.FindSymbol, reusing a persisted presence check (SymbolDecls)
// when one exists. TRUE means the symbol is declared; FALSE is emitted
// only for the typed "not found in the successfully loaded package"
// outcome — a package that never loaded, a load error or ambiguity is
// UNKNOWN, not absence. Each decisive outcome is persisted as a
// SymbolDecls entry plus a deterministic evidence record.
func CheckSymbolExists(ctx context.Context, c *domain.AnalysisCase, source *goanalysis.Index,
	subj domain.SymbolRef) (domain.ClaimResult, string, domain.EvidenceID) {
	key := subj.Package + "." + subj.Symbol
	if c != nil {
		if site, checked := c.EvidenceGraph.SymbolDeclFor(key); checked {
			if site != nil {
				return domain.ClaimTrue, fmt.Sprintf("declared at %s:%d", site.File, site.Line), presenceEvidenceID(c, key)
			}
			return domain.ClaimFalse, "not found in loaded package source (recorded presence check)", presenceEvidenceID(c, key)
		}
	}
	if source == nil {
		return domain.ClaimUnknown, "no source index available; symbol existence not checked", ""
	}
	site, err := source.FindSymbol(ctx, subj)
	switch {
	case err == nil:
		if c != nil {
			c.EvidenceGraph.AddSymbolDecl(key, site)
		}
		return domain.ClaimTrue, fmt.Sprintf("declared at %s:%d", site.File, site.Line),
			recordSiteEvidence(c, key, fmt.Sprintf("%s declared at %s:%d", key, site.File, site.Line))
	case errors.Is(err, goanalysis.ErrSymbolNotFoundInPackage):
		if c != nil {
			c.EvidenceGraph.AddSymbolDecl(key, nil)
		}
		return domain.ClaimFalse, "not found in the loaded and typed package source",
			recordSiteEvidence(c, key, key+" not found in loaded packages")
	default:
		if c != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("proposal site check %s: %v", key, err))
		}
		return domain.ClaimUnknown, fmt.Sprintf("symbol lookup failed: %v", err), ""
	}
}

// ReachableFromEvidence derives the PRODUCT_REACHABLE result for a
// subject purely from persisted evidence: an intra-module chain
// (ModuleReachable), a govulncheck call-path frame naming the subject,
// or a direct product call site (ModuleUsages). No record is UNKNOWN —
// a missing key is never evidence of unreachability.
func ReachableFromEvidence(c *domain.AnalysisCase, subj *domain.SymbolRef) (domain.ClaimResult, string, []domain.EvidenceID) {
	if c == nil || subj == nil {
		return domain.ClaimUnknown, "site text could not be resolved to a package and symbol; reachability not checked", nil
	}
	key := subj.Package + "." + subj.Symbol
	if chain, ok := c.EvidenceGraph.ModuleReachable[key]; ok {
		return domain.ClaimTrue,
			fmt.Sprintf("persisted module-internal call chain from a product-used API: %s", strings.Join(chain, " -> ")),
			evidenceIDsByTool(c, "goanalysis.Index.ModuleInternalReach")
	}
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			if frameMatches(fr, *subj) {
				var ids []domain.EvidenceID
				if cp.EvidenceID != "" {
					ids = append(ids, cp.EvidenceID)
				}
				return domain.ClaimTrue,
					fmt.Sprintf("persisted call path reaches %s.%s at %s:%d", fr.Package, fr.Function, fr.File, fr.Line), ids
			}
		}
	}
	for _, u := range c.EvidenceGraph.ModuleUsages {
		if u.Callee == key {
			return domain.ClaimTrue,
				fmt.Sprintf("product calls the subject directly at %s:%d", u.File, u.Line),
				evidenceIDsByTool(c, "goanalysis.Index.ModuleUsage")
		}
	}
	return domain.ClaimUnknown, "no persisted call path or module reachability entry for this subject", nil
}

// AttributeChecks re-derives the records that depend on evidence
// collected after VerifySites ran: PRODUCT_REACHABLE is recomputed from
// the evidence graph, and a SYMBOL_EXISTS still UNKNOWN is upgraded from
// a persisted presence check when one was recorded. Decisive results of
// a live check are never downgraded by stored state. Call it at the
// completed COLLECT_EVIDENCE boundary.
func AttributeChecks(c *domain.AnalysisCase) {
	if c == nil {
		return
	}
	for i := range c.ProposalVerifications {
		rec := &c.ProposalVerifications[i]
		switch rec.Check {
		case domain.CheckProductReachable:
			res, detail, ids := ReachableFromEvidence(c, rec.Subject)
			rec.Result, rec.Detail, rec.EvidenceIDs = res, detail, ids
		case domain.CheckSymbolExists:
			if rec.Result != domain.ClaimUnknown || rec.Subject == nil {
				continue
			}
			key := rec.Subject.Package + "." + rec.Subject.Symbol
			if site, checked := c.EvidenceGraph.SymbolDeclFor(key); checked {
				if site != nil {
					rec.Result = domain.ClaimTrue
					rec.Detail = fmt.Sprintf("declared at %s:%d", site.File, site.Line)
				} else {
					rec.Result = domain.ClaimFalse
					rec.Detail = "not found in loaded package source (recorded presence check)"
				}
				if id := presenceEvidenceID(c, key); id != "" {
					rec.EvidenceIDs = []domain.EvidenceID{id}
				}
			}
		}
	}
}

// frameMatches mirrors the locus verifier's frame rule: a govulncheck
// frame names a subject when package and function match, with a
// "Type.Method" subject split onto the frame's receiver.
func frameMatches(cs domain.CallSite, sym domain.SymbolRef) bool {
	if cs.Package != sym.Package {
		return false
	}
	if cs.Function == sym.Symbol {
		return true
	}
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv, fn := sym.Symbol[:i], sym.Symbol[i+1:]
		if cs.Function == fn && normalizeReceiver(cs.Receiver) == normalizeReceiver(recv) {
			return true
		}
	}
	return false
}

func normalizeReceiver(r string) string {
	r = strings.TrimPrefix(r, "(")
	r = strings.TrimSuffix(r, ")")
	return strings.TrimPrefix(r, "*")
}

// recordSiteEvidence persists a symbol-presence outcome as deterministic
// evidence, reusing the existing record when an identical one was
// already emitted (retries never duplicate evidence rows).
func recordSiteEvidence(c *domain.AnalysisCase, key, content string) domain.EvidenceID {
	if c == nil {
		return ""
	}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Tool == "goanalysis.Index.FindSymbol" && e.Source == "presence check "+key && e.Content == content {
			return e.ID
		}
	}
	return c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSearchResult,
		Quality: domain.QualityDeterministic,
		Source:  "presence check " + key,
		Tool:    "goanalysis.Index.FindSymbol",
		Content: content,
	})
}

// presenceEvidenceID finds the evidence record a presence check wrote
// for key, so a verification reusing SymbolDecls can cite it.
func presenceEvidenceID(c *domain.AnalysisCase, key string) domain.EvidenceID {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Tool == "goanalysis.Index.FindSymbol" && e.Source == "presence check "+key {
			return e.ID
		}
	}
	return ""
}

func evidenceIDsByTool(c *domain.AnalysisCase, tool string) []domain.EvidenceID {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Tool == tool {
			ids = append(ids, e.ID)
		}
	}
	return ids
}
