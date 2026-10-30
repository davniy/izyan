package domain

// Named reasons the ticket-build identity check records. They are the
// machine-readable outcome of comparing a tracker ticket's declared
// coordinates against the build the analysis actually resolved — never
// verdicts. TICKET_PACKAGE_VERSION_MISMATCH is the only reason that
// blocks the version axis: when the analyzed build resolved the
// ticket's package at a different version than the ticket declares, an
// "outside the affected range" conclusion would describe a build the
// ticket is not about and must not close. ANALYZED_BUILD_MISMATCH is
// informational: a product-level drift (release train) with an identical
// package version does not invalidate a version-range comparison, but a
// reviewer must see it. TICKET_INVALID degrades a malformed or
// unreadable ticket input to "not checked" — never to a silent pass.
const (
	TicketReasonPackageVersionMismatch = "TICKET_PACKAGE_VERSION_MISMATCH"
	TicketReasonAnalyzedBuildMismatch  = "ANALYZED_BUILD_MISMATCH"
	TicketReasonInvalid                = "TICKET_INVALID"
)

// Per-axis check statuses recorded on TicketCheck. TICKET_CHECK_MATCH
// means the declared claim equals the analyzed value; TICKET_CHECK_MISMATCH
// means they disagree (the named reason in Reasons says why it matters);
// TICKET_CHECK_NOT_CHECKED means the comparison could not be performed
// (claim missing, counterpart unknown, or unparseable input) — a stated
// limitation, never a silent pass.
const (
	TicketCheckMatch      = "MATCH"
	TicketCheckMismatch   = "MISMATCH"
	TicketCheckNotChecked = "NOT_CHECKED"
)

// TicketClaims is the machine-readable subset of a tracker ticket's
// applicability claims (the ticket supplied to the lane): which
// product/distribution and which package version the ticket asserts
// the finding is about. The analyzer never invents them —
// an absent or unparsable claim degrades the corresponding axis to
// NOT_CHECKED. Product/Component/AdvisoryIDs are provenance: today only
// the two version axes drive the comparison.
type TicketClaims struct {
	Product        string   `json:"product,omitempty"`
	ProductVersion string   `json:"product_version,omitempty"`
	Component      string   `json:"component,omitempty"`
	Package        string   `json:"package,omitempty"`
	PackageVersion string   `json:"package_version,omitempty"`
	AdvisoryIDs    []string `json:"advisory_ids,omitempty"`
}

// TicketCheck is the outcome of comparing the ticket's declared claims
// against what the analysis resolved. It is recorded on AffectedResult
// only when a ticket input was supplied (including the malformed-input
// case, which records ParseError). A package-version mismatch marks
// produce the "resolved version is outside the affected range" negative
// that would misdescribe the ticket's build. BlockedModules names the
// advisory entries the refusal covers. DeclaredVersionInRanges is a
// supporting statement about the ticket's own declared version against
// the advisory ranges — triage context, never a verdict input.
type TicketCheck struct {
	// Package axis.
	Package             string `json:"package,omitempty"`
	DeclaredVersion     string `json:"declared_version,omitempty"`
	ResolvedVersion     string `json:"resolved_version,omitempty"`
	PackageVersionCheck string `json:"package_version_check,omitempty"`
	// DeclaredVersionInRanges reports whether the ticket's declared
	// package version falls inside the affected ranges of the advisory
	// entry the comparison ran against (tri-state: nil when the declared
	// version or the comparison was not applicable).
	DeclaredVersionInRanges *bool `json:"declared_version_in_ranges,omitempty"`
	// Product axis.
	ProductVersionCheck string `json:"product_version_check,omitempty"`
	DeclaredProduct     string `json:"declared_product,omitempty"`
	AnalyzedProduct     string `json:"analyzed_product,omitempty"`
	// Reasons aggregates the named mismatch reasons (deterministic order:
	// package reason first). BlockedModules names the advisory entries
	// whose version-axis verdict the mismatch refused.
	Reasons        []string `json:"reasons,omitempty"`
	BlockedModules []string `json:"blocked_modules,omitempty"`
	// ParseError names why a supplied ticket could not be consumed; when
	// set, every axis stays NOT_CHECKED.
	ParseError string `json:"parse_error,omitempty"`
}
