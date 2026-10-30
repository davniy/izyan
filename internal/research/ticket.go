package research

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/tracker"
)

// TicketRecord is the lane's record of the tracker-ticket channel: the
// provenance ref, the pinned digest of the exact bytes the claims were
// read from, the claims parsed out of the ticket (nil when the input
// could not be consumed), and the parse error that degraded the check.
// It travels on LaneResult and is projected into input.ticket; nil on
// the lane means no ticket was supplied.
type TicketRecord struct {
	Path   string `json:"path"` // provenance only: local:<basename>
	SHA256 string `json:"sha256,omitempty"`
	// DistributionURL is the ticket's own distribution locator — the
	// sanitized text of the dedicated "Ссылка на дистрибутив" label (or
	// the equivalent JSON field). It is recorded so a refusal can name
	// the exact prerequisite; the lane never fetches it — supplying the
	// distribution stays the explicit --artifact/--artifact-url channel.
	DistributionURL string               `json:"distribution_url,omitempty"`
	Claims          *domain.TicketClaims `json:"claims,omitempty"`
	ParseError      string               `json:"parse_error,omitempty"`
}

// loadTicket reads the tracker ticket through the existing intake —
// a JSON ticket, a JSON array (targetID selects by key) or arbitrary
// plain text, "-" meaning stdin. It never fails: every malformed
// input — unreadable file, unparsable document, no ticket in the
// batch, a targetID that selects nothing — returns a record carrying
// only ParseError, which the resolver records as TICKET_INVALID and
// degrades to NOT_CHECKED. The digest pins the exact bytes the claims
// were read from even when they could not be parsed.
func loadTicket(path, targetID string) *TicketRecord {
	if strings.TrimSpace(path) == "" {
		return nil // the channel was never requested
	}
	rec := &TicketRecord{Path: repository.ProvenanceLocalRef(path)}
	fail := func() *TicketRecord {
		rec.Claims = nil
		if rec.ParseError == "" {
			rec.ParseError = domain.TicketReasonInvalid
		}
		return rec
	}
	var raw []byte
	var err error
	if strings.TrimSpace(path) == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return fail()
	}
	sum := sha256.Sum256(raw)
	rec.SHA256 = hex.EncodeToString(sum[:])
	tickets, err := tracker.ParseTickets(raw)
	if err != nil || len(tickets) == 0 {
		return fail()
	}
	t, err := tracker.SelectTicket(tickets, targetID, rec.Path)
	if err != nil {
		return fail()
	}
	rec.DistributionURL = t.DistributionURL // already sanitized by the intake
	rec.Claims = ticketClaims(t)
	return rec
}

// ticketClaims derives the identity-check claims from a parsed tracker
// ticket: the intake field names differ from the claim axis names, and
// empty fields stay empty — the check tolerates missing claims.
func ticketClaims(t *tracker.Ticket) *domain.TicketClaims {
	return &domain.TicketClaims{
		Product:        strings.TrimSpace(t.Product),
		ProductVersion: strings.TrimSpace(t.Release),
		Component:      strings.TrimSpace(t.Component),
		Package:        strings.TrimSpace(t.Package),
		PackageVersion: strings.TrimSpace(t.Version),
		AdvisoryIDs:    t.Aliases,
	}
}

// claimFieldCount counts the non-empty claim fields for the lane
// observation's fact line — provenance, never a check input.
func claimFieldCount(c *domain.TicketClaims) int {
	if c == nil {
		return 0
	}
	n := 0
	for _, s := range []string{c.Product, c.ProductVersion, c.Component, c.Package, c.PackageVersion} {
		if s != "" {
			n++
		}
	}
	n += len(c.AdvisoryIDs)
	return n
}
