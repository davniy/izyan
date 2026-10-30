package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
)

// TicketAdvisorySource is the "ticket" lane of the advisory composite: the
// intake document's own advisory material. Doc is the verbatim embedded
// advisory (the intake's "osv"/"advisory" object); when absent the source
// projects the intake's advisory fields — aliases, summary, severity,
// module, fixed versions — onto a partial OSV document honestly marked
// database_specific.izyan.partial. A bare id is not advisory material:
// without any of those fields the lane misses cleanly instead of
// shadowing the frozen/OSV lanes with an empty projection.
type TicketAdvisorySource struct {
	Doc           []byte
	Aliases       []string
	Summary       string
	Description   string
	Severity      string
	CVSS          string
	Module        string
	FixedVersions []string
	Symbols       []string
}

func (s *TicketAdvisorySource) Get(ctx context.Context, id string) (*domain.Vulnerability, error) {
	raw, err := s.GetRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	return raw.Vuln, nil
}

func (s *TicketAdvisorySource) GetRaw(_ context.Context, id string) (vulnerability.RawDocument, error) {
	if len(s.Doc) > 0 {
		v, err := vulnerability.ParseAdvisoryDoc(s.Doc)
		if err != nil {
			return vulnerability.RawDocument{}, &vulnerability.AdvisoryError{
				Class: vulnerability.AdvisoryClassParse,
				Err:   fmt.Errorf("ticket advisory: %w", err)}
		}
		if v.Provenance == nil {
			v.Provenance = map[string]string{}
		}
		v.Provenance["document"] = "intake:embedded-osv"
		return vulnerability.RawDocument{Vuln: v, Bytes: s.Doc}, nil
	}
	if len(s.Aliases) == 0 && s.Summary == "" && s.Severity == "" && s.CVSS == "" &&
		s.Module == "" && len(s.FixedVersions) == 0 && len(s.Symbols) == 0 && s.Description == "" {
		return vulnerability.RawDocument{}, &vulnerability.AdvisoryError{
			Class: vulnerability.AdvisoryClassNotFound,
			Err:   errors.New("intake document carries no advisory material")}
	}
	v := &domain.Vulnerability{
		ID:           canonicalVulnID(id),
		Aliases:      append([]string(nil), s.Aliases...),
		Summary:      s.Summary,
		Description:  s.Description,
		BaseSeverity: strings.ToUpper(strings.TrimSpace(s.Severity)),
		Module:       s.Module,
		Provenance: map[string]string{
			"id":               "intake-proposal.v1",
			"document":         "intake:ticket-projection",
			"advisory_partial": "intake",
		},
	}
	if v.BaseSeverity != "" {
		v.SeveritySource = "ticket"
	}
	if score, err := strconv.ParseFloat(strings.TrimSpace(s.CVSS), 64); err == nil && score > 0 {
		v.BaseScore = score
		v.ScoreSource = "ticket"
	}
	if len(s.FixedVersions) > 0 {
		for _, f := range s.FixedVersions {
			v.AffectedVersions = append(v.AffectedVersions, domain.VersionRange{Introduced: "0", Fixed: f})
		}
		v.FixedVersions = append([]string(nil), s.FixedVersions...)
	}
	for _, sym := range s.Symbols {
		pkg, name := sym, ""
		if i := strings.LastIndex(sym, "."); i > 0 {
			pkg, name = sym[:i], sym[i+1:]
		}
		if name != "" {
			v.AffectedSymbols = append(v.AffectedSymbols, domain.SymbolRef{Package: pkg, Symbol: name})
		}
	}
	doc, err := marshalTicketAdvisoryDoc(v)
	if err != nil {
		return vulnerability.RawDocument{}, err
	}
	return vulnerability.RawDocument{Vuln: v, Bytes: doc, Partial: true}, nil
}

// marshalTicketAdvisoryDoc renders the ticket projection as an OSV-shaped
// JSON document marked partial — deterministic bytes for the freeze record.
func marshalTicketAdvisoryDoc(v *domain.Vulnerability) ([]byte, error) {
	doc := map[string]any{"id": v.ID}
	if len(v.Aliases) > 0 {
		doc["aliases"] = v.Aliases
	}
	if v.Summary != "" {
		doc["summary"] = v.Summary
	}
	if v.Description != "" {
		doc["details"] = v.Description
	}
	dbs := map[string]any{"izyan": map[string]any{"partial": true}}
	if v.BaseSeverity != "" {
		dbs["severity"] = v.BaseSeverity
	}
	if v.BaseScore > 0 {
		dbs["izyan"].(map[string]any)["cvss"] = v.BaseScore
		dbs["izyan"].(map[string]any)["score_source"] = v.ScoreSource
	}
	if v.SeveritySource != "" {
		dbs["izyan"].(map[string]any)["severity_source"] = v.SeveritySource
	}
	doc["database_specific"] = dbs
	if v.Module != "" || len(v.AffectedVersions) > 0 || len(v.AffectedSymbols) > 0 {
		aff := map[string]any{"package": map[string]any{"ecosystem": "Go", "name": v.Module}}
		if len(v.AffectedVersions) > 0 {
			var events []map[string]string
			for _, r := range v.AffectedVersions {
				if r.Introduced != "" {
					events = append(events, map[string]string{"introduced": r.Introduced})
				}
				if r.Fixed != "" {
					events = append(events, map[string]string{"fixed": r.Fixed})
				}
				if r.LastAffected != "" {
					events = append(events, map[string]string{"last_affected": r.LastAffected})
				}
			}
			if len(events) > 0 {
				aff["ranges"] = []map[string]any{{"type": "SEMVER", "events": events}}
			}
		}
		if len(v.AffectedSymbols) > 0 {
			byPkg := map[string][]string{}
			var order []string
			for _, s := range v.AffectedSymbols {
				if _, ok := byPkg[s.Package]; !ok {
					order = append(order, s.Package)
				}
				byPkg[s.Package] = append(byPkg[s.Package], s.Symbol)
			}
			var imps []map[string]any
			for _, p := range order {
				imps = append(imps, map[string]any{"path": p, "symbols": byPkg[p]})
			}
			aff["ecosystem_specific"] = map[string]any{"imports": imps}
		}
		doc["affected"] = []map[string]any{aff}
	}
	return json.Marshal(doc)
}

// AdvisoryInput carries what advisory resolution is allowed to consult: the
// validated intake proposal, the raw intake record (for embedded documents
// and deterministic extraction) and the frozen-store/API locations. No
// tracker-specific fields — RawIntake is the generic transport record.
type AdvisoryInput struct {
	Proposal   IntakeProposal
	Raw        *RawIntake
	FrozenDir  string
	OSVBaseURL string
}

// AdvisoryResolution is the Stage 0 advisory verdict: the parsed document,
// its hash-pinned frozen identity, the field-level projection the material
// checks consume, every source attempt and the limitations the miss or
// conflicts produced. Partial marks ticket-derived projections and the
// missing-advisory stub — never an authoritative record.
type AdvisoryResolution struct {
	Vulnerability *domain.Vulnerability         `json:"-"`
	Projection    AdvisoryProjection            `json:"projection,omitempty"`
	Record        vulnerability.FrozenAdvisory  `json:"record"`
	Attempts      []vulnerability.SourceAttempt `json:"attempts"`
	Limitations   []string                      `json:"limitations,omitempty"`
	Partial       bool                          `json:"partial"`
}

// ResolveAdvisory runs the §5.2 advisory pipeline for one intake proposal:
// lanes in configured priority order, the selected document frozen and
// hash-pinned under freezeDir. With freeze:true the remote lane is never
// consulted — resolution is confined to intake material and the frozen
// store, so replay cannot reach the network. A clean miss everywhere
// degrades to a partial stub plus a limitation, never a question and never
// a fabricated advisory.
func ResolveAdvisory(ctx context.Context, cfg SiteConfig, in AdvisoryInput, freezeDir string) (*AdvisoryResolution, error) {
	vulnID := ""
	if len(in.Proposal.VulnerabilityIDs) > 0 {
		vulnID = canonicalVulnID(in.Proposal.VulnerabilityIDs[0])
	}
	if vulnID == "" {
		return nil, errors.New("advisory resolution requires a vulnerability id from the intake proposal")
	}

	priority, err := advisoryPriority(cfg.Sources.Advisory.Priority)
	if err != nil {
		return nil, err
	}

	cs := &vulnerability.CompositeSource{
		Ticket:        buildTicketAdvisorySource(in),
		FreezeDir:     freezeDir,
		MaxBytes:      cfg.Budgets.MaxAdvisoryBytes,
		Priority:      priority,
		PreferPackage: intakePackagePath(in.Proposal.Package),
	}
	frozenDir := in.FrozenDir
	if frozenDir == "" {
		frozenDir = freezeDir
	}
	if frozenDir != "" {
		cs.Frozen = vulnerability.FrozenOSVSource{Dir: frozenDir}
	}
	var extra []vulnerability.SourceAttempt
	if !cfg.Sources.Advisory.Freeze {
		if base, ok := advisoryRemoteBase(in.OSVBaseURL, cfg.Sources.Advisory.AllowedDomains); ok {
			cs.Remote = vulnerability.OSVSource{BaseURL: base}
		} else if base != "" {
			extra = append(extra, vulnerability.SourceAttempt{
				Kind: vulnerability.AdvisoryOSVAPI, Status: vulnerability.AttemptSkipped,
				ErrorClass: "domain_not_allowed"})
		}
	}

	v, rec, attempts, err := cs.GetFrozen(ctx, vulnID)
	attempts = append(attempts, extra...)
	res := &AdvisoryResolution{Attempts: attempts}
	if err != nil {
		if errors.Is(err, vulnerability.ErrAdvisoryNotFound) {
			res.Partial = true
			res.Vulnerability = stubAdvisory(vulnID, in)
			res.Projection = AdvisoryProjectionFromVulnerability(*res.Vulnerability)
			rec := vulnerability.FrozenAdvisory{
				SchemaVersion: vulnerability.FrozenAdvisorySchemaVersion,
				ID:            vulnID,
				ResolvedID:    vulnID,
				Source:        vulnerability.AdvisoryTicket,
				Partial:       true,
			}
			if doc, derr := marshalTicketAdvisoryDoc(res.Vulnerability); derr == nil && freezeDir != "" {
				if fr, ferr := vulnerability.FreezeAdvisory(freezeDir, doc, rec); ferr == nil {
					rec = fr
					rec.Source = vulnerability.AdvisoryTicket
					rec.Partial = true
				}
			}
			if rec.SHA256 == "" {
				if doc, derr := marshalTicketAdvisoryDoc(res.Vulnerability); derr == nil {
					sum := sha256.Sum256(doc)
					rec.SHA256 = hex.EncodeToString(sum[:])
					rec.Size = int64(len(doc))
					rec.FrozenAt = time.Now().UTC().Format(time.RFC3339)
				}
			}
			res.Record = rec
			res.Limitations = append(res.Limitations,
				"no advisory document resolved for "+vulnID+"; proceeding on a partial intake-derived projection")
			return res, nil
		}
		return nil, fmt.Errorf("advisory resolution for %s: %w", vulnID, err)
	}
	res.Vulnerability = v
	res.Projection = AdvisoryProjectionFromVulnerability(*v)
	res.Record = rec
	res.Partial = rec.Partial || v.Provenance["advisory_partial"] != ""
	if v.Provenance["resolved_via_alias"] != "" {
		res.Limitations = append(res.Limitations,
			"advisory resolved via alias "+v.Provenance["resolved_via_alias"])
	}
	if v.Provenance["superseded_document"] != "" {
		res.Limitations = append(res.Limitations,
			"selected advisory "+v.Provenance["superseded_document"]+
				" has no package-scoped ranges; the usable alias document is authoritative")
	} else if res.Partial {
		res.Limitations = append(res.Limitations,
			"advisory projection is partial ("+string(rec.Source)+"): only the fields the source supplied are asserted")
	}
	if lim := advisoryVersionConflict(in.Proposal, v); lim != "" {
		res.Limitations = append(res.Limitations, lim)
	}
	return res, nil
}

// intakePackagePath normalizes the proposal's package claim for advisory
// matching: a pkg:golang PURL yields namespace/name, everything else is
// lowercased and stripped of a trailing slash.
func intakePackagePath(pkg string) string {
	pkg = strings.TrimSpace(pkg)
	if strings.HasPrefix(pkg, "pkg:") {
		if p, ok := parsePURL(pkg); ok && strings.EqualFold(p.Type, "golang") {
			if p.Namespace != "" {
				return strings.ToLower(p.Namespace + "/" + p.Name)
			}
			return strings.ToLower(p.Name)
		}
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(pkg, "/"))
}

func advisoryPriority(cfg []string) ([]vulnerability.AdvisorySourceKind, error) {
	if len(cfg) == 0 {
		return nil, nil
	}
	out := make([]vulnerability.AdvisorySourceKind, 0, len(cfg))
	for _, p := range cfg {
		switch vulnerability.AdvisorySourceKind(p) {
		case vulnerability.AdvisoryTicket, vulnerability.AdvisoryFrozenOSV, vulnerability.AdvisoryOSVAPI:
			out = append(out, vulnerability.AdvisorySourceKind(p))
		default:
			return nil, fmt.Errorf("sources.advisory.priority entry %q is not ticket|frozen_osv|osv_api", p)
		}
	}
	return out, nil
}

// advisoryRemoteBase returns the OSV API base when allowed_domains admits
// it. An empty domain list is a closed boundary: the remote lane stays
// unconfigured, so a bare `freeze: false` never dials out by surprise.
func advisoryRemoteBase(base string, allowed []string) (string, bool) {
	if len(allowed) == 0 {
		return "", false
	}
	if base == "" {
		base = "https://api.osv.dev"
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", false
	}
	host := u.Hostname()
	for _, d := range allowed {
		if strings.EqualFold(host, d) {
			return base, true
		}
	}
	return base, false
}

// buildTicketAdvisorySource assembles the ticket lane from generic intake
// material: an embedded advisory document wins verbatim; otherwise the
// intake's own fields plus the proposal's claims project a partial doc.
func buildTicketAdvisorySource(in AdvisoryInput) *TicketAdvisorySource {
	src := &TicketAdvisorySource{}
	if in.Raw != nil {
		src.Doc = embeddedAdvisoryDoc(in.Raw.Raw)
		if in.Raw.Object != nil {
			src.Aliases = intakeStringSlice(in.Raw.Object, "aliases")
			src.Summary = intakeString(in.Raw.Object, "summary")
			src.Severity = intakeString(in.Raw.Object, "severity")
			src.CVSS = firstNonEmpty(intakeString(in.Raw.Object, "cvss"), intakeString(in.Raw.Object, "cvss_score"))
			src.Module = firstNonEmpty(intakeString(in.Raw.Object, "module"), intakeString(in.Raw.Object, "package"))
			src.FixedVersions = intakeStringSlice(in.Raw.Object, "fixed_versions")
			src.Symbols = intakeStringSlice(in.Raw.Object, "symbols")
			src.Description = intakeString(in.Raw.Object, "description")
		}
	}
	if src.Doc != nil {
		return src
	}
	if len(src.Aliases) == 0 {
		src.Aliases = append([]string(nil), in.Proposal.Aliases...)
	}
	if src.Summary == "" {
		src.Summary = in.Proposal.Summary
	}
	if src.Severity == "" {
		src.Severity = in.Proposal.Severity
	}
	if src.Module == "" {
		src.Module = in.Proposal.Package
	}
	return src
}

// embeddedAdvisoryDoc extracts the verbatim bytes of an embedded advisory
// document ("osv" or "advisory" field) from a JSON intake record. Text
// records have no embedded document — their bytes belong to ticket_hash,
// not to the advisory.
func embeddedAdvisoryDoc(raw []byte) []byte {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed[0] != '{' {
		return nil
	}
	var probe struct {
		OSV      json.RawMessage `json:"osv"`
		Advisory json.RawMessage `json:"advisory"`
	}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return nil
	}
	for _, doc := range []json.RawMessage{probe.OSV, probe.Advisory} {
		if len(doc) > 0 && doc[0] == '{' {
			return doc
		}
	}
	return nil
}

func intakeString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func intakeStringSlice(m map[string]any, key string) []string {
	var out []string
	switch v := m[key].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// advisoryVersionConflict is the deterministic §4.2 rule for a ticket
// version claim that disagrees with the advisory's ranges: the document
// stays authoritative and the disagreement becomes a limitation — never a
// silent rewrite, never a dismissal input.
func advisoryVersionConflict(p IntakeProposal, v *domain.Vulnerability) string {
	ver := strings.TrimSpace(p.Version)
	if ver == "" {
		return ""
	}
	var ranges []domain.VersionRange
	ranges = append(ranges, v.AffectedVersions...)
	for _, am := range v.AffectedModules {
		ranges = append(ranges, am.AffectedVersions...)
	}
	if len(ranges) == 0 {
		return ""
	}
	if normalizeModVersion(ver) == "" {
		return fmt.Sprintf("proposed version %q is not semver-comparable to advisory ranges; applicability stays unresolved", ver)
	}
	if affectedByRanges(ver, ranges) {
		return ""
	}
	return fmt.Sprintf("proposed version %s is outside the advisory's affected ranges; the advisory document remains authoritative", ver)
}

// stubAdvisory builds the honest record for a clean miss: the intake's id
// and aliases, marked partial, no affected claims — present so downstream
// stages consume a typed artifact instead of a gap.
func stubAdvisory(vulnID string, in AdvisoryInput) *domain.Vulnerability {
	v := &domain.Vulnerability{
		ID:      vulnID,
		Aliases: append([]string(nil), in.Proposal.Aliases...),
		Provenance: map[string]string{
			"id":               "intake-proposal.v1",
			"document":         "none: advisory unavailable",
			"advisory_partial": "intake",
		},
	}
	return v
}
