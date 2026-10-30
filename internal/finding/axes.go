package finding

import (
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// Assessment axes are a presentation projection, never a second evaluator.
//
// The authoritative classification stays where it is: AssessmentOutcome,
// Verdict, affected facts, exploit model, claims, evidence and the requested
// finding. This file derives the two operator-facing facts from that admitted
// material:
//
//	vulnerable_code_in_build  TRUE | FALSE | UNKNOWN
//	exploitable               TRUE | FALSE | UNKNOWN | NOT_APPLICABLE
//
// The projection cannot replace the outcome model. TRUE / UNKNOWN may be an
// external dependency or a failed analysis, a component negative never closes
// a CVE, and a display value is never proof.

// AxisFact is the derived value of one assessment-axis question. UNKNOWN is
// deliberately distinct from FALSE: an unmeasured fact is not a safe one.
type AxisFact string

const (
	AxisTrue          AxisFact = "TRUE"
	AxisFalse         AxisFact = "FALSE"
	AxisUnknown       AxisFact = "UNKNOWN"
	AxisNotApplicable AxisFact = "NOT_APPLICABLE"
)

// AxisRow is one identity-bound, per-profile line of the derived projection.
// SubjectID names the vulnerability identity the row answers for (the
// requested id for requested rows, the record id for record rows);
// AssessmentID names the independently admitted assessment that produced it.
//
// A record row carries the exact RecordPin its assessment was derived from, so
// the row can never stand on another record's bytes. A requested row carries
// no pin: the request-level answer may be composed from several records.
type AxisRow struct {
	SubjectID             string                     `json:"subject_id"`
	AssessmentID          domain.CaseID              `json:"assessment_id"`
	Profile               domain.ThreatProfile       `json:"profile"`
	IsTargetActual        bool                       `json:"is_target_actual"`
	Build                 domain.BuildContext        `json:"build"`
	Record                *domain.RecordPin          `json:"record,omitempty"`
	ExploitabilityScope   domain.ExploitabilityScope `json:"exploitability_scope,omitempty"`
	VulnerableCodeInBuild AxisFact                   `json:"vulnerable_code_in_build"`
	Exploitable           AxisFact                   `json:"exploitable"`
}

// AssessmentAxes is the request-level projection: one array for the requested
// subject (the caller's answer) and one for every record assessment retained
// beside it. Requested rows never inherit a record's axes merely because that
// record was resolved first.
type AssessmentAxes struct {
	Requested []AxisRow `json:"requested"`
	Records   []AxisRow `json:"records"`
}

// Empty reports whether the projection carries no rows at all.
func (a AssessmentAxes) Empty() bool {
	return len(a.Requested) == 0 && len(a.Records) == 0
}

// TargetRequested returns the deployment's actual profile row for the
// requested subject. There is at most one such row.
func (a AssessmentAxes) TargetRequested() (AxisRow, bool) {
	for _, row := range a.Requested {
		if row.IsTargetActual {
			return row, true
		}
	}
	return AxisRow{}, false
}

// TargetRecord returns the target-actual profile row of one assessed record.
func (a AssessmentAxes) TargetRecord(assessmentID domain.CaseID) (AxisRow, bool) {
	for _, row := range a.Records {
		if row.AssessmentID == assessmentID && row.IsTargetActual {
			return row, true
		}
	}
	return AxisRow{}, false
}

// deriveAxes computes the projection from an already recomposed requested
// finding and the re-admitted records it rests on. It allocates fresh slices
// and never mutates a case.
func deriveAxes(requested domain.RequestedFinding, primary *domain.AnalysisCase,
	records []*domain.AnalysisCase) (AssessmentAxes, error) {
	axes := AssessmentAxes{
		Requested: make([]AxisRow, 0, len(requested.Profiles)),
		Records:   make([]AxisRow, 0, len(records)),
	}
	for _, profile := range requested.Profiles {
		axes.Requested = append(axes.Requested, requestedAxisRow(requested, profile, primary))
	}
	for _, record := range records {
		axes.Records = append(axes.Records, recordAxisRows(record)...)
	}
	if err := axes.validate(); err != nil {
		return AssessmentAxes{}, err
	}
	return axes, nil
}

// requestedAxisRow derives one requested-profile row. An exact-record request
// answers for the primary record, so its vulnerability facts come from that
// record's affected chain. A CVE request answers only for its own composition:
// an unresolved CVE never borrows the primary record's facts, and a composed
// positive entails vulnerability through its admitted witnesses.
func requestedAxisRow(requested domain.RequestedFinding, profile domain.FindingProfile,
	primary *domain.AnalysisCase) AxisRow {
	row := AxisRow{
		SubjectID:           requested.RequestedID,
		AssessmentID:        requested.PrimaryAssessmentID,
		Profile:             profile.Profile,
		IsTargetActual:      profile.IsTargetActual,
		Build:               profile.Build,
		ExploitabilityScope: profile.ExploitabilityScope,
		Exploitable:         exploitabilityFact(profile.Outcome, profile.Verdict),
	}
	if requested.RequestedKind == domain.ScopeCVE {
		row.VulnerableCodeInBuild = composedVulnerabilityFact(profile)
		return row
	}
	row.VulnerableCodeInBuild = vulnerabilityFact(profile.Outcome, profile.Verdict, admittedAffected(primary))
	return row
}

// recordAxisRows derives one row per profile assessment a record carries. A
// record that never reached evaluation contributes no rows.
func recordAxisRows(record *domain.AnalysisCase) []AxisRow {
	if record == nil || len(record.ProfileAssessments) == 0 {
		return nil
	}
	affected := admittedAffected(record)
	subject := axisSubjectID(record)
	rows := make([]AxisRow, 0, len(record.ProfileAssessments))
	for _, assessment := range record.ProfileAssessments {
		verdict := verdictOfResult(assessment.Result)
		row := AxisRow{
			SubjectID:             subject,
			AssessmentID:          record.ID,
			Profile:               assessment.Profile,
			IsTargetActual:        assessment.IsTargetActual,
			Build:                 assessment.Build,
			Record:                clonePin(record.RecordPin),
			VulnerableCodeInBuild: vulnerabilityFact(assessment.Result.Outcome, verdict, affected),
			Exploitable:           exploitabilityFact(assessment.Result.Outcome, verdict),
		}
		if assessment.Result.Verdict != nil {
			row.ExploitabilityScope = assessment.Result.Verdict.ExploitabilityScope
		}
		rows = append(rows, row)
	}
	return rows
}

// vulnerabilityFact derives the vulnerability axis for one admitted profile
// result. An earned NOT_AFFECTED establishes FALSE for its admitted boundary,
// and an admitted exploitability positive entails TRUE through its proof
// references. Every other outcome is derived from the recorded applicability
// facts, so a failed or external exploit analysis never erases them.
func vulnerabilityFact(outcome domain.AssessmentOutcome, verdict domain.Verdict,
	affected domain.AffectedResult) AxisFact {
	switch {
	case outcome == domain.OutcomeDecided && verdict == domain.VerdictNotAffected:
		return AxisFalse
	case outcome == domain.OutcomeDecided && verdict == domain.VerdictExploitable:
		return AxisTrue
	}
	return affectedVulnerabilityFact(affected)
}

// composedVulnerabilityFact derives the vulnerability axis of a CVE request.
// Only the request-level composition may answer: an unresolved CVE stays
// UNKNOWN even when the primary record's own facts are affirmative, because
// that record does not close the requested identity.
func composedVulnerabilityFact(profile domain.FindingProfile) AxisFact {
	if profile.Outcome != domain.OutcomeDecided {
		return AxisUnknown
	}
	switch profile.Verdict {
	case domain.VerdictExploitable:
		return AxisTrue
	case domain.VerdictNotAffected:
		return AxisFalse
	default:
		// NEPF alone supplies no affirmative vulnerability fact, and a
		// request-level negative cannot be inferred from it.
		return AxisUnknown
	}
}

// admittedAffected mirrors the verdict evaluator's affected-chain admission:
// a build-dependent negative whose target or inventory prerequisites do not
// hold is demoted to UNKNOWN before the verdict sees it, so the display
// projection must not read that refused FALSE as an admitted absence fact.
// Independent axes (module graph, version range) stay usable.
func admittedAffected(record *domain.AnalysisCase) domain.AffectedResult {
	affected := affectedOf(record)
	if record == nil {
		return affected
	}
	if err := domain.ValidateAffectedNegative(record.Product, affected,
		record.EvidenceGraph.EvidenceList()); err != nil {
		if affected.PackagePresent == domain.ClaimFalse {
			affected.PackagePresent = domain.ClaimUnknown
		}
		if affected.BuildRelevant == domain.ClaimFalse {
			affected.BuildRelevant = domain.ClaimUnknown
		}
		if affected.VulnerableImplementationPresent == domain.ClaimFalse {
			affected.VulnerableImplementationPresent = domain.ClaimUnknown
		}
	}
	return affected
}

// affectedVulnerabilityFact reads the affected chain's admitted facts. The
// four positive axes establish TRUE; an optional implementation-presence
// UNKNOWN does not block that conclusion. An absence fact is FALSE only when
// the subject boundary admits negative closure: a refused component negative
// stays UNKNOWN instead of becoming a safe display value.
func affectedVulnerabilityFact(affected domain.AffectedResult) AxisFact {
	if affected.HasNegative() {
		if affected.Scope != nil && affected.Scope.AllowsNegativeClosure() {
			return AxisFalse
		}
		return AxisUnknown
	}
	if affected.ModulePresent == domain.ClaimTrue &&
		affected.VersionAffected == domain.ClaimTrue &&
		affected.PackagePresent == domain.ClaimTrue &&
		affected.BuildRelevant == domain.ClaimTrue {
		return AxisTrue
	}
	return AxisUnknown
}

// exploitabilityFact projects the already-admitted assessment result. A raw
// FALSE claim, even a VERIFIED one, never reaches this function on its own: it
// arrives only through the result the admission gates earned.
func exploitabilityFact(outcome domain.AssessmentOutcome, verdict domain.Verdict) AxisFact {
	if outcome != domain.OutcomeDecided {
		return AxisUnknown
	}
	switch verdict {
	case domain.VerdictExploitable:
		return AxisTrue
	case domain.VerdictNoExploitPathFound:
		return AxisFalse
	case domain.VerdictNotAffected:
		return AxisNotApplicable
	default:
		return AxisUnknown
	}
}

// validate enforces the one impossible cell: an admitted vulnerability FALSE
// can never accompany exploitability TRUE for the same subject, profile and
// build.
func (a AssessmentAxes) validate() error {
	for _, rows := range [][]AxisRow{a.Requested, a.Records} {
		for _, row := range rows {
			switch row.VulnerableCodeInBuild {
			case AxisTrue, AxisFalse, AxisUnknown:
			default:
				return fmt.Errorf("assessment axes: subject %q: unknown vulnerability axis %q",
					row.SubjectID, row.VulnerableCodeInBuild)
			}
			switch row.Exploitable {
			case AxisTrue, AxisFalse, AxisUnknown, AxisNotApplicable:
			default:
				return fmt.Errorf("assessment axes: subject %q: unknown exploitability axis %q",
					row.SubjectID, row.Exploitable)
			}
			if row.VulnerableCodeInBuild == AxisFalse && row.Exploitable == AxisTrue {
				return fmt.Errorf(
					"assessment axes: subject %q, assessment %q, profile %q: vulnerable code in build is FALSE while exploitable is TRUE",
					row.SubjectID, row.AssessmentID, row.Profile)
			}
		}
	}
	return nil
}

func axisSubjectID(record *domain.AnalysisCase) string {
	if record == nil {
		return ""
	}
	if id := strings.TrimSpace(record.Vulnerability.ID); id != "" {
		return id
	}
	if record.RecordPin != nil {
		if id := strings.TrimSpace(record.RecordPin.RecordID); id != "" {
			return id
		}
	}
	if id := strings.TrimSpace(record.RequestedID); id != "" {
		return id
	}
	return string(record.ID)
}

func clonePin(pin *domain.RecordPin) *domain.RecordPin {
	if pin == nil {
		return nil
	}
	clone := *pin
	return &clone
}
