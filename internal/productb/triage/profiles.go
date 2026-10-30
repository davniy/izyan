package triage

// ConditionalProfileChangesDecision reports whether an alternative profile is
// meaningful. Profiles with the same expected disposition as the package's
// recommendation do not belong in conditional_profiles.
func ConditionalProfileChangesDecision(p ConditionalProfile, current Recommendation) bool {
	return p.ExpectedDisposition.Valid() && p.ExpectedDisposition != current
}

// AddConditionalProfile appends only profiles that can change the final
// decision. Applicability remains descriptive and is never applied here.
func AddConditionalProfile(dst []ConditionalProfile, p ConditionalProfile, current Recommendation) []ConditionalProfile {
	if !ConditionalProfileChangesDecision(p, current) {
		return dst
	}
	return append(dst, p)
}

// ConditionalProfileApplicable is true only for a positively evaluated
// condition. UNKNOWN and UNSATISFIED are intentionally non-applicable.
func ConditionalProfileApplicable(p ConditionalProfile) bool {
	return p.Applicability.Status == ConditionSatisfied
}
