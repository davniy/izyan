package research

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// This file derives the residual environment/deployment questions the
// human-facing surfaces carry. The research lane never decides
// runtime/deployment posture — that predicate is always an open layer —
// so the contract is allowed exactly one honest output: a bounded set
// of specific questions built only from recorded material. Nothing is
// invented: a question exists only when the residual layer is
// exclusively deployment/config posture AND at least one recorded
// statement names something the deployment must answer — the advisory's
// own declared statements, a recorded deployment-scope fact (e.g. a
// found inbound listener), an agent-stated config hypothesis, or an
// engaged R6 deployment condition. With no such statement the surfaces
// keep today's generic text. When the advisory's own text states one
// or more such preconditions, the R6 artifact additionally keys its
// environment decision on the first recorded statement: the declared
// variable asks whether that recorded condition holds, never an
// invented one, and the remaining statements stay as the additional
// derived questions. The generic perimeter dimension stays the
// fallback for every advisory that declares none.

// variableAdvisoryPrecondition is the code-owned id of the derived
// environment variable an artifact declares when the advisory's frozen
// text states at least one deployment/config-shaped exploitation
// precondition (the first recorded statement grounds the variable).
// It is builder-derived only: deliberately absent from the variable
// registry, so a caller or agent proposal can never force it into
// existence.
const variableAdvisoryPrecondition = "advisory_precondition"

// The closed answer set of variableAdvisoryPrecondition: the condition
// the advisory recorded either holds in the deployed environment (the
// named input/configuration is attacker-influenced), does not hold, or
// cannot be established.
const (
	advisoryConditionHolds    = "holds"
	advisoryConditionNotHolds = "does_not_hold"
	advisoryConditionUnknown  = "unknown"
)

// advisoryPreconditionValues is the declared allowed-value order of the
// derived variable — and the order its branches enumerate.
var advisoryPreconditionValues = []string{
	advisoryConditionHolds, advisoryConditionNotHolds, advisoryConditionUnknown,
}

// genericRuntimePostureStatement prefixes the deterministic fallback
// statement emitted for the always-present runtime/deployment posture
// predicate. It is a scope reminder, not a case-specific condition, so
// it can never drive a derived question.
const genericRuntimePostureStatement = "a runtime configuration/environment predicate must hold for exploitation"

// envPreconditionMarkers are the lowercased tokens that mark an
// advisory sentence as declaring a precondition rather than narrating
// mechanism. A sentence must carry at least one of these plus an
// environment token before it counts as an advisory-declared
// environment-affecting statement.
var envPreconditionMarkers = []string{
	"require", "only if", "only when", "only in",
	" must ", "must be", " if ", "when ", "where ", "unless",
	"controlled by", "enabled", "disabled",
}

// envLayerTokens are the lowercased tokens that mark a statement as
// deployment/config surface — the layer static source evidence can
// never decide. Kept closed and generic: no product, protocol or case
// names.
var envLayerTokens = []string{
	"config", "option", "setting", "flag", "parameter", "argument",
	"environment", "deploy", "listener", "socket", "port",
	"endpoint", "exposed", "exposure", "perimeter", "network", "route",
	"operator", "administrator", "attacker-controlled", "user-controlled",
	"untrusted", "trusted", "upstream", "proxy", "host",
}

// envDriver is one recorded statement that grounds a derived question:
// where it was recorded and the exact text a reviewer is asked to
// confirm against the deployed environment.
type envDriver struct {
	kind string // advisory|fact|hypothesis
	text string
}

// envAnchor names the reached code the question binds to: the
// observed reached subject and, when the bound observation records
// them, its first product call site.
type envAnchor struct {
	subject string // e.g. "symbol example.com/m/pkg.F" or a recorded statement
	site    string // "file.go:123" when the payload records a product site
}

// deploymentShaped reports whether a statement names the deployment/
// config surface the static lane can never decide. The token set is
// deliberately closed and case-free.
func deploymentShaped(statement string) bool {
	s := strings.ToLower(statement)
	for _, tok := range envLayerTokens {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

// advisoryEnvStatements extracts the advisory's own declared
// environment-affecting exploitation statements: sentences of the
// frozen summary/details that state a precondition over the
// deployment/config surface. Extraction is verbatim — the question
// quotes the recorded sentence, never a paraphrase, and a sentence that
// declares no condition is never coerced into one.
func advisoryEnvStatements(summary, description string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range splitAdvisorySentences(summary + "\n" + description) {
		low := " " + strings.ToLower(s) + " "
		pre := false
		for _, m := range envPreconditionMarkers {
			if strings.Contains(low, m) {
				pre = true
				break
			}
		}
		if !pre || !deploymentShaped(s) {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		if len(out) >= MaxEnvironmentQuestions {
			break
		}
	}
	return out
}

// splitAdvisorySentences breaks advisory prose into trimmed sentences:
// line breaks and .!? terminators end a sentence, markdown bullets are
// stripped, and fragments shorter than a real statement are dropped.
// Bounded: at most the first 40 candidate sentences are examined.
func splitAdvisorySentences(text string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		s := strings.TrimSpace(b.String())
		b.Reset()
		s = strings.TrimLeft(s, "-*•> \t")
		s = strings.Trim(s, `"`)
		s = strings.TrimSpace(s)
		if len(s) >= 24 {
			out = append(out, s)
		}
	}
	for _, r := range text {
		switch r {
		case '.', '!', '?', '\n', '\r':
			flush()
		default:
			b.WriteRune(r)
		}
		if len(out) >= 40 {
			break
		}
	}
	flush()
	return out
}

// effectiveCondLayer maps one exploitation-conditions row to the layer
// it opens, recomputing the role rather than trusting a stored field
// (questions run before the slice-2 role pass): deterministic rows take
// the fixed subject table, agent rows take the canonical path/supporting
// split, and a config-shaped agent hypothesis counts as the deployment
// layer — its truth is a deployment fact by construction.
func effectiveCondLayer(c ExploitationCondition) string {
	if c.Origin == OriginDeterm {
		return conditionRoleForSubject(c.Subject)
	}
	if canonicalPathSubject(c.Subject) != "" {
		return ConditionRolePath
	}
	if deploymentShaped(c.Statement) {
		return ConditionRoleDeployment
	}
	return ConditionRoleSupporting
}

// envQuestions derives the residual environment/deployment questions
// for one report. It returns nil unless the residual layer is
// exclusively deployment/config posture: at least one blocking-layer
// condition stays unresolved, every unresolved blocking condition is
// deployment-layer (a still-open applicability/path predicate keeps the
// generic surface), no deterministic condition is REFUTED (a refuted
// predicate makes every deployment question moot), and a deterministic
// SUPPORTED anchor exists. Supporting-layer rows are never blockers, so
// an open agent hypothesis that is not a required path predicate leaves
// the gate alone — though a config-shaped one may still drive a
// question.
func (a *assembler) envQuestions(r *Report) []string {
	var anchorUsage, anchorPath, anchorOther *envAnchor
	refuted := false
	unresolvedBlocking := 0
	unresolvedBlockingNonDeploy := 0
	var detDrivers []envDriver
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		layer := effectiveCondLayer(*c)
		resolved := c.State == StateSupported || c.State == StateRefuted
		// A condition blocks the gate when its layer blocks the
		// disposition (applicability, path or deployment — never
		// supporting) or when the row is explicitly required.
		blocking := layer != ConditionRoleSupporting || c.Necessity == "required"
		switch {
		case !resolved:
			if blocking {
				unresolvedBlocking++
				if layer != ConditionRoleDeployment {
					unresolvedBlockingNonDeploy++
				}
			}
		default:
			if c.Origin == OriginDeterm && c.State == StateRefuted {
				refuted = true
			}
			if c.Origin == OriginDeterm && c.State == StateSupported {
				// The usage-subject anchor is most specific (it names
				// the reached symbol and site); a path-layer anchor
				// (reached code) ranks next; a bare applicability
				// anchor is last. First of each class wins.
				a2 := a.envAnchorFor(c, r)
				switch {
				case a2 == nil:
				case c.UsageSubject != nil:
					if anchorUsage == nil {
						anchorUsage = a2
					}
				case layer == ConditionRolePath:
					if anchorPath == nil {
						anchorPath = a2
					}
				default:
					if anchorOther == nil {
						anchorOther = a2
					}
				}
			}
		}
		// A deterministic deployment-layer statement — resolved or
		// unresolved — is recorded case data, so it can drive a
		// question. The always-present generic runtime-posture row is
		// a scope reminder, not a case statement, and never drives.
		if c.Origin == OriginDeterm && layer == ConditionRoleDeployment &&
			!strings.HasPrefix(c.Statement, genericRuntimePostureStatement) {
			detDrivers = append(detDrivers, envDriver{kind: "fact", text: c.Statement})
		}
	}
	anchor := anchorUsage
	if anchor == nil {
		anchor = anchorPath
	}
	if anchor == nil {
		anchor = anchorOther
	}
	if unresolvedBlocking == 0 || unresolvedBlockingNonDeploy > 0 || refuted || anchor == nil {
		return nil
	}
	var drivers []envDriver
	if a.lane.Advisory.Vuln != nil {
		for _, s := range advisoryEnvStatements(
			a.lane.Advisory.Vuln.Summary, a.lane.Advisory.Vuln.Description) {
			drivers = append(drivers, envDriver{kind: "advisory", text: s})
		}
	}
	drivers = append(drivers, detDrivers...)
	for i := range r.ExploitationConditions {
		c := &r.ExploitationConditions[i]
		if c.Origin == OriginAgent && c.State != StateRefuted && deploymentShaped(c.Statement) {
			drivers = append(drivers, envDriver{kind: "hypothesis", text: c.Statement})
		}
	}
	return renderEnvQuestions(drivers, anchor)
}

// renderEnvQuestions maps drivers to question strings in a stable
// order — advisory declarations first, recorded facts second,
// hypotheses last — deduplicating on driver text and bounding the
// result by the R6 question cap. With no drivers it returns nil: no
// recorded statement exists to make a question specific.
func renderEnvQuestions(drivers []envDriver, anchor *envAnchor) []string {
	if len(drivers) == 0 || anchor == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, kind := range []string{"advisory", "fact", "hypothesis"} {
		for _, d := range drivers {
			if d.kind != kind || seen[d.text] {
				continue
			}
			seen[d.text] = true
			out = append(out, envQuestionText(d, anchor))
			if len(out) >= MaxEnvironmentQuestions {
				return out
			}
		}
	}
	return out
}

// envQuestionText renders one driver into the operator-facing question:
// the recorded statement verbatim, the reached subject/site it binds
// to, and the exact deployment fact to establish. A hypothesis is never
// dressed as an advisory statement — it is named as the agent's
// recorded hypothesis.
func envQuestionText(d envDriver, anchor *envAnchor) string {
	target := anchor.subject
	if anchor.site != "" {
		target += " (reached at " + anchor.site + ")"
	}
	switch d.kind {
	case "advisory":
		return fmt.Sprintf("the advisory declares %q — confirm whether this exploitation precondition holds for %s in the deployed environment, and whether the named input/configuration is attacker-influenced or operator-controlled", d.text, target)
	case "fact":
		return fmt.Sprintf("the recorded deployment-scope condition states %q — confirm whether the deployed environment exposes %s to attacker-controlled input", d.text, target)
	default:
		return fmt.Sprintf("the agent's recorded hypothesis states %q — confirm it against the deployed environment for %s", d.text, target)
	}
}

// envAnchorFor selects the anchor behind a SUPPORTED deterministic
// condition: the advisory-declared usage subject with its first
// recorded product site when the bound observation carries one, else
// the affected component the applicability row names, else the
// condition's statement as the recorded reach fact.
func (a *assembler) envAnchorFor(c *ExploitationCondition, r *Report) *envAnchor {
	if c.Subject == subjProductPackageUsage && c.UsageSubject != nil {
		label := "package " + c.UsageSubject.Package
		if c.UsageSubject.Symbol != "" {
			label = "symbol " + c.UsageSubject.Package + "." + c.UsageSubject.Symbol
		}
		anchor := &envAnchor{subject: label}
		for _, o := range a.lane.Observations {
			if o == nil || o.Tool != evidencetools.PackageUsageTool {
				continue
			}
			d, ok := packageUsageDataOf(o)
			if !ok || d.Package != c.UsageSubject.Package || d.Symbol != c.UsageSubject.Symbol ||
				d.Usage != string(goanalysis.PackageUsageUsed) {
				continue
			}
			if len(d.ProductSites) > 0 {
				site := d.ProductSites[0]
				anchor.site = site.File + ":" + strconv.Itoa(site.Line)
			}
			break
		}
		return anchor
	}
	if r.ProductApplicability.SelectedModule != nil && *r.ProductApplicability.SelectedModule != "" {
		return &envAnchor{subject: "the affected component (" + *r.ProductApplicability.SelectedModule + ")"}
	}
	stmt := c.Statement
	if len(stmt) > 160 {
		stmt = stmt[:160]
	}
	return &envAnchor{subject: stmt}
}

// artifactEnvQuestions derives the environment questions the R6
// artifact's human-action surface carries. It runs only when the
// environment dimension is genuinely open (the builder asks at least
// one declared question and no code-grounded close stands) and positive
// product-linkage evidence exists in the fact envelope — the artifact
// analogue of the report's reached-subject anchor. Question drivers are
// the engaged non-variable deployment/config conditions, then the
// advisory's own declared statements.
func artifactEnvQuestions(b *branchBuilder, questions []string) []string {
	if len(questions) == 0 || b.closeEstablished != nil {
		return nil
	}
	var anchor *envAnchor
	var drivers []envDriver
	for _, c := range b.conditions {
		if variableForCondition(c.ID) != "" {
			// Conditions binding a declared variable are answered by the
			// variable's own question — a second free-text question for
			// the same gate would duplicate the contract ask.
			continue
		}
		if res, ok := b.condResult[c.ID]; ok && res.Status == evaluator.RuleContradicted {
			continue
		}
		if c.Role == ConditionRoleDeployment || deploymentShaped(c.Statement) {
			drivers = append(drivers, envDriver{kind: "fact", text: c.Statement})
		}
	}
	if b.lane.Advisory.Vuln != nil {
		for _, s := range advisoryEnvStatements(
			b.lane.Advisory.Vuln.Summary, b.lane.Advisory.Vuln.Description) {
			drivers = append(drivers, envDriver{kind: "advisory", text: s})
		}
	}
	for _, f := range b.in.RuleFacts {
		if f.Status != "VERIFIED" || f.Digest == "" {
			continue
		}
		usage := f.Predicate == evaluator.PredicateProductSourceUsage &&
			(f.Value == "used" || f.Value == "positive-lowerbound")
		linked := f.Predicate == evaluator.PredicateProductClosureMembership &&
			f.Value == "linked"
		if (usage || linked) && f.Subject != "" {
			anchor = &envAnchor{subject: f.Subject}
			break
		}
	}
	if anchor == nil {
		return nil
	}
	return renderEnvQuestions(drivers, anchor)
}

// advisoryPrecondition returns the advisory-declared environment
// precondition the artifact's environment decision is keyed on: the
// first verbatim sentence (in the deterministic extraction order of
// the frozen summary, then description) plus the field it was read
// from, following the same derived_from provenance convention the
// anchored-subject gate uses. The derivation is deliberately
// conservative: zero extracted statements keep the generic perimeter
// dimension, and a chosen quote that fails to resolve verbatim to a
// recorded field can never produce a variable. When the advisory
// states the condition across several recorded sentences, the first
// grounds the variable and its provenance; the rest stay as the
// additional derived questions the human-action surface already
// emits — no sentence is merged, reordered or dropped. The result is
// computed at most once per build.
func (b *branchBuilder) advisoryPrecondition() *SubjectProvenance {
	if b.advPrecondChecked {
		return b.advPrecond
	}
	b.advPrecondChecked = true
	if b.lane == nil || b.lane.Advisory.Vuln == nil {
		return nil
	}
	stmts := advisoryEnvStatements(
		b.lane.Advisory.Vuln.Summary, b.lane.Advisory.Vuln.Description)
	if len(stmts) == 0 {
		return nil
	}
	field := advisoryAnchorField(b.lane, stmts[0])
	if field != anchorFieldSummary && field != anchorFieldDescription {
		// A statement extracted from summary/description that no
		// recorded field verifies is a derivation defect — never a
		// provenance. Fail closed into the generic dimension.
		return nil
	}
	b.advPrecond = &SubjectProvenance{Field: field, Quote: stmts[0]}
	return b.advPrecond
}
