package evaluator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// ConfigFlag retains declaration-wide positive observations for config_flag and
// config_key. Safe assignments, zero defaults and checked-in safe keys remain
// UNKNOWN: none closes the effective object or deployment/runtime overrides.
// The necessary CHECK_TRIGGER configuration-negative helper below uses the
// separate snapshot-anchored certificate checker, not these observations.
type ConfigFlag struct{}

func (ConfigFlag) CanEvaluate(cond domain.Condition) bool {
	ch := cond.Params[domain.ParamCheck]
	return ch == domain.CheckConfigFlag || ch == domain.CheckConfigKey
}

func (ConfigFlag) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evaluateConfigFlagCond(cond, c))
}

func evaluateConfigFlagCond(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.ConfigFlag",
	}
	insecure := cond.Params[domain.ParamInsecure]
	if insecure == "" {
		insecure = "true"
	}
	switch cond.Params[domain.ParamCheck] {
	case domain.CheckConfigFlag:
		return evalConfigFlag(cond, c, claim, insecure)
	case domain.CheckConfigKey:
		return evalConfigKey(cond, c, claim, insecure)
	}
	return claim
}

func evalConfigFlag(cond domain.Condition, c *domain.AnalysisCase, claim domain.Claim, insecure string) domain.Claim {
	pkg, sym := cond.Params[domain.ParamConfigPackage], cond.Params[domain.ParamConfigSymbol]
	if pkg == "" || sym == "" {
		claim.Limitations = append(claim.Limitations, "no config_package/config_symbol param — knob unspecified")
		return claim
	}
	// If the package defining the knob or constructor is not linked into the
	// product's build graph (go list -deps), the configuration cannot exist or be set.
	set, ids, err := packageImportSet(c)
	if err == nil && !set[pkg] {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierPackageAbsent
		claim.EvidenceIDs = ids
		claim.Explanation = fmt.Sprintf(
			"package %s is absent from the product's build graph (go list -deps); configuration knob/symbol cannot be set or executed",
			pkg)
		return claim
	}
	if sym == "*" {
		claim.Result = domain.ClaimTrue
		claim.EvidenceIDs = ids
		claim.Explanation = fmt.Sprintf("package %s is linked into the product's build graph", pkg)
		return claim
	}
	key := pkg + "." + sym
	claim.EvidenceIDs = exposureEvidenceIDs(c, "config flag check ")
	if _, ok := c.EvidenceGraph.SymbolDeclFor(key); !ok {
		claim.Limitations = append(claim.Limitations, "knob existence not verified in source")
	}
	list, checked := c.EvidenceGraph.ConfigFlagsFor(key)
	if !checked {
		claim.Limitations = append(claim.Limitations, "assignment scan did not run")
		return claim
	}
	var insecureSites, safeSites, unresolved []domain.ConfigAssignment
	for _, a := range list {
		switch {
		case a.Source == "":
			unresolved = append(unresolved, a)
		case valueEqual(a.Value, insecure):
			insecureSites = append(insecureSites, a)
		default:
			safeSites = append(safeSites, a)
		}
	}
	if len(insecureSites) > 0 {
		claim.Result = domain.ClaimTrue
		var at []string
		for _, s := range insecureSites {
			at = append(at, fmt.Sprintf("%s:%d", s.File, s.Line))
		}
		claim.Explanation = fmt.Sprintf("knob %s set to insecure value %q at %s", sym, insecure, strings.Join(at, ", "))
		return claim
	}
	if len(unresolved) > 0 {
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"%d assignment(s) to %s use non-literal values — effective value unresolved", len(unresolved), sym))
		return claim
	}
	if len(safeSites) > 0 {
		claim.Limitations = append(claim.Limitations, "safe declaration-wide assignments do not establish a closed effective object")
		return claim
	}
	// Never assigned: Go zero-value semantics apply only when we know the
	// field kind (recorded by the collector in the zero_value param echo)
	// — a bool knob never set is false; if that is not the insecure
	// value the configuration is safe by default.
	if zero, ok := c.EvidenceGraph.SymbolFieldKind(key); ok && zero == "bool" &&
		(insecure == "true" || insecure == "1") {
		claim.Limitations = append(claim.Limitations, "zero-value observation does not establish a closed effective object")
		return claim
	}
	claim.Limitations = append(claim.Limitations,
		fmt.Sprintf("knob %s never assigned in product code; runtime/deployment value unknown", sym))
	return claim
}

func evalConfigKey(cond domain.Condition, c *domain.AnalysisCase, claim domain.Claim, insecure string) domain.Claim {
	key := cond.Params[domain.ParamConfigKey]
	if key == "" {
		claim.Limitations = append(claim.Limitations, "no config_key param — key unspecified")
		return claim
	}
	claim.EvidenceIDs = exposureEvidenceIDs(c, "config key check ")
	var hits, safe []domain.ConfigItem
	matched := false
	for _, it := range c.EvidenceGraph.ConfigItems() {
		if it.Key == "" || !keyMatches(it.Key, key) {
			continue
		}
		matched = true
		if valueEqual(it.Value, insecure) {
			hits = append(hits, it)
		} else {
			safe = append(safe, it)
		}
	}
	if !matched {
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("key %q not found in repo config files; may be set via env/deployment outside the repo", key))
		return claim
	}
	if len(hits) > 0 {
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf("config key %q set to insecure value %q at %s:%d",
			key, insecure, hits[0].File, hits[0].Line)
		return claim
	}
	claim.Limitations = append(claim.Limitations, "safe configuration-file values do not close runtime/deployment overrides")
	return claim
}

// keyMatches mirrors exposure.Lookup semantics: exact key or last dotted
// segment, case-insensitive.
func keyMatches(itemKey, want string) bool {
	k := strings.ToLower(itemKey)
	want = strings.ToLower(want)
	if k == want {
		return true
	}
	if j := strings.LastIndexByte(k, '.'); j >= 0 {
		return k[j+1:] == want
	}
	return false
}

func valueEqual(got, want string) bool {
	return strings.EqualFold(strings.Trim(strings.TrimSpace(got), `"'`), strings.TrimSpace(want))
}

func exposureEvidenceIDs(c *domain.AnalysisCase, prefix string) []domain.EvidenceID {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if strings.HasPrefix(e.Source, "config flag check ") || strings.HasPrefix(e.Source, "config key check ") {
			ids = appendUniqueID(ids, e.ID)
		}
	}
	return ids
}

func evaluateConfigTriggerNegative(cond domain.Condition,c *domain.AnalysisCase,claim domain.Claim) domain.Claim {
	if cond.Kind != domain.ConditionCheckTrigger || !cond.Mandatory { return claim }
	for _,e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidenceConfiguration || e.Tool != goanalysis.ConfigCertificateTool { continue }
		probe := claim
		probe.EvidenceIDs = []domain.EvidenceID{e.ID}
		_,err := goanalysis.ValidateConfigCertificateEvidence(goanalysis.ConfigAdmissionForCase(c),probe,cond)
		if err == nil {
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierSafeConfigAssignment
			claim.EvidenceIDs = []domain.EvidenceID{e.ID}
			claim.Explanation = "every captured invocation's necessary boolean configuration argument has a safe effective value"
			return admitNegative(c,cond,claim)
		}
		status := domain.NegativeInsufficientScope
		if errors.Is(err,goanalysis.ErrConfigWriterContradicted) { status=domain.NegativeContradicted }
		claim.NegativeVerification=&domain.NegativeVerification{Status:status,Notes:err.Error(),EvidenceIDs:[]domain.EvidenceID{e.ID}}
		claim.Limitations=append(claim.Limitations,err.Error())
		claim.AnalysisGaps=append(claim.AnalysisGaps,domain.AnalysisGap{Owner:domain.GapOwnerProof,Code:domain.GapTriggerProofIncomplete,Obligation:domain.ObligationCondition,ConditionID:cond.ID,Message:err.Error()})
		return claim
	}
	message := "no captured effective-configuration certificate establishes the necessary boolean argument"
	claim.NegativeVerification = &domain.NegativeVerification{Status:domain.NegativeInsufficientScope,Notes:message}
	claim.AnalysisGaps = append(claim.AnalysisGaps,domain.AnalysisGap{Owner:domain.GapOwnerProof,Code:domain.GapTriggerProofIncomplete,Obligation:domain.ObligationCondition,ConditionID:cond.ID,Message:message})
	return claim
}
