package domain

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type AdvisoryScopeKind string

const (
	ScopeAdvisoryEntries AdvisoryScopeKind = "ADVISORY_ENTRIES"
	ScopeCVE             AdvisoryScopeKind = "CVE"
)

type AdvisoryCoverage string

const (
	CoverageComplete  AdvisoryCoverage = "COMPLETE"
	CoverageKnownOnly AdvisoryCoverage = "KNOWN_ONLY"
)

// RecordExtent classifies how much of the loaded advisory document its Go
// projection actually represents. Only RecordExtentFullRecord may ground a
// negative finding-level conclusion; a projection or an unclassified record
// leaves the requested scope uncovered.
type RecordExtent string

const (
	RecordExtentFullRecord   RecordExtent = "FULL_RECORD"
	RecordExtentGoProjection RecordExtent = "GO_PROJECTION"
	RecordExtentUnknown      RecordExtent = "UNKNOWN"
)

const (
	recordEcosystemGo     = "Go"
	recordDigestPrefix    = "sha256:"
	recordDigestHexLength = 64
)

// RecordEntry is one original OSV affected[] entry, recorded before ecosystem
// filtering and before entries merge by module name. Index is the zero-based
// position in the original affected[] array; AdvisoryID + DocumentDigest +
// Index identify the source entry.
type RecordEntry struct {
	Index     int    `json:"index"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Module    string `json:"module,omitempty"`
}

// RecordInventory is a digest-bound census of the original OSV affected[]
// array. Entries preserves the original order and the original
// ecosystem/module identity of every entry. RepresentedRefs and OmittedRefs
// individually order, deduplicate and partition those indices. A structurally
// valid inventory, including a partial one, is not by itself closure
// authority: see AdvisoryScope.AllowsNegativeClosure.
type RecordInventory struct {
	AdvisoryID         string        `json:"advisory_id"`
	DocumentDigest     string        `json:"document_digest"`
	AffectedEntryCount int           `json:"affected_entry_count"`
	Entries            []RecordEntry `json:"entries"`
	RepresentedRefs    []int         `json:"represented_refs"`
	OmittedRefs        []int         `json:"omitted_refs"`
}

// AdvisoryScope binds applicability facts to the requested advisory identity.
// Kind is what the caller requested; Coverage is the completeness of that
// assertion; RecordExtent and RecordInventory are the structural evidence of
// what the loaded document actually represented. Basis is human explanation
// only and never participates in a closure decision. COMPLETE alone is not
// closure authority: AllowsNegativeClosure additionally requires a full,
// fully represented exact record.
type AdvisoryScope struct {
	RequestedID     string            `json:"requested_id"`
	ResolvedID      string            `json:"resolved_id"`
	Kind            AdvisoryScopeKind `json:"kind"`
	Coverage        AdvisoryCoverage  `json:"coverage"`
	Basis           string            `json:"basis,omitempty"`
	RecordExtent    RecordExtent      `json:"record_extent,omitempty"`
	RecordInventory *RecordInventory  `json:"record_inventory,omitempty"`
}

// Validate checks the structural invariants of the census and that the
// inventory is bound to recordID. It deliberately says nothing about whether
// a negative may close: a partial inventory is structurally valid because it
// honestly records omitted entries, and only AllowsNegativeClosure decides
// whether that evidence is sufficient.
func (i *RecordInventory) Validate(recordID string) error {
	if i == nil {
		return errors.New("record inventory is missing")
	}
	if recordID == "" {
		return errors.New("record inventory: empty recorded advisory identity")
	}
	if i.AdvisoryID == "" {
		return errors.New("record inventory: empty advisory identity")
	}
	if i.AdvisoryID != recordID {
		return fmt.Errorf("record inventory: advisory identity %q does not bind %q", i.AdvisoryID, recordID)
	}
	if err := validateRecordDigest(i.DocumentDigest); err != nil {
		return err
	}
	if i.AffectedEntryCount != len(i.Entries) {
		return fmt.Errorf("record inventory: affected entry count %d does not match %d entries",
			i.AffectedEntryCount, len(i.Entries))
	}
	for n := range i.Entries {
		if i.Entries[n].Index != n {
			return fmt.Errorf("record inventory: entry %d carries original index %d", n, i.Entries[n].Index)
		}
	}
	if err := validateOrderedRefs("represented_refs", i.RepresentedRefs, i.AffectedEntryCount); err != nil {
		return err
	}
	if err := validateOrderedRefs("omitted_refs", i.OmittedRefs, i.AffectedEntryCount); err != nil {
		return err
	}
	return i.validateRefPartition()
}

func validateRecordDigest(digest string) error {
	if !strings.HasPrefix(digest, recordDigestPrefix) {
		return fmt.Errorf("record inventory: document digest %q is not a %ssha256 digest", digest, recordDigestPrefix)
	}
	encoded := digest[len(recordDigestPrefix):]
	if len(encoded) != recordDigestHexLength {
		return fmt.Errorf("record inventory: document digest has %d hex characters, want %d",
			len(encoded), recordDigestHexLength)
	}
	for n := range encoded {
		if c := encoded[n]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("record inventory: document digest character %d (%q) is not lowercase hex", n, c)
		}
	}
	return nil
}

func validateOrderedRefs(name string, refs []int, count int) error {
	for n, ref := range refs {
		if ref < 0 || ref >= count {
			return fmt.Errorf("record inventory: %s[%d]=%d is outside [0,%d)", name, n, ref, count)
		}
		if n > 0 && ref <= refs[n-1] {
			return fmt.Errorf("record inventory: %s is not strictly ordered at position %d (%d after %d)",
				name, n, ref, refs[n-1])
		}
	}
	return nil
}

// validateRefPartition walks the ordered reference lists once, requiring
// every original index to appear in exactly one of them. It allocates nothing
// on the success path.
func (i *RecordInventory) validateRefPartition() error {
	represented, omitted := 0, 0
	for index := range i.AffectedEntryCount {
		hasRepresented := represented < len(i.RepresentedRefs) && i.RepresentedRefs[represented] == index
		hasOmitted := omitted < len(i.OmittedRefs) && i.OmittedRefs[omitted] == index
		switch {
		case hasRepresented && hasOmitted:
			return fmt.Errorf("record inventory: original entry %d is both represented and omitted", index)
		case hasRepresented:
			represented++
		case hasOmitted:
			omitted++
		default:
			return fmt.Errorf("record inventory: original entry %d is neither represented nor omitted", index)
		}
	}
	return nil
}

// AllowsNegativeClosure reports whether the bound scope may ground a negative
// finding-level conclusion. Beyond an exact GO-/GHSA- identity bound through
// ADVISORY_ENTRIES/COMPLETE, it requires structural evidence that the loaded
// record fully represented a nonempty original entry set as resolved Go
// module identities. Request kind is checked structurally, so a CVE request
// never closes even with otherwise valid full-record metadata. Basis is never
// consulted.
func (s *AdvisoryScope) AllowsNegativeClosure() bool {
	if s == nil || s.RequestedID == "" || s.RequestedID != s.ResolvedID {
		return false
	}
	exactRecord := strings.HasPrefix(s.RequestedID, "GO-") && len(s.RequestedID) > len("GO-") ||
		strings.HasPrefix(s.RequestedID, "GHSA-") && len(s.RequestedID) > len("GHSA-")
	if !exactRecord || s.Kind != ScopeAdvisoryEntries || s.Coverage != CoverageComplete {
		return false
	}
	return s.recordFullyRepresented()
}

func (s *AdvisoryScope) recordFullyRepresented() bool {
	if s.RecordExtent != RecordExtentFullRecord || s.RecordInventory == nil {
		return false
	}
	inventory := s.RecordInventory
	if inventory.AffectedEntryCount == 0 || len(inventory.Entries) == 0 {
		return false
	}
	if inventory.Validate(s.ResolvedID) != nil {
		return false
	}
	if len(inventory.RepresentedRefs) != inventory.AffectedEntryCount || len(inventory.OmittedRefs) != 0 {
		return false
	}
	for _, ref := range inventory.RepresentedRefs {
		entry := inventory.Entries[ref]
		if entry.Ecosystem != recordEcosystemGo || entry.Module == "" {
			return false
		}
	}
	return true
}

// Clone returns a deep-enough copy for downstream mutation safety: the scope
// value, the inventory object, and all three inventory slices. It is
// nil-safe.
func (s *AdvisoryScope) Clone() *AdvisoryScope {
	if s == nil {
		return nil
	}
	clone := *s
	if s.RecordInventory != nil {
		inventory := *s.RecordInventory
		inventory.Entries = slices.Clone(s.RecordInventory.Entries)
		inventory.RepresentedRefs = slices.Clone(s.RecordInventory.RepresentedRefs)
		inventory.OmittedRefs = slices.Clone(s.RecordInventory.OmittedRefs)
		clone.RecordInventory = &inventory
	}
	return &clone
}

func (r AffectedResult) HasNegative() bool {
	return r.ModulePresent == ClaimFalse || r.VersionAffected == ClaimFalse ||
		r.PackagePresent == ClaimFalse || r.BuildRelevant == ClaimFalse ||
		(r.VulnerableImplementationPresent == ClaimFalse &&
			r.PackagePresent == ClaimTrue && r.BuildRelevant == ClaimTrue)
}
