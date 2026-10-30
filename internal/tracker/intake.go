package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Ticket is the generic tracker-intake format: a structured record or parsed ticket
// containing vulnerability and product snapshot metadata.
type Ticket struct {
	ID            string   `json:"id,omitempty"`
	Vulnerability string   `json:"vulnerability,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	Repo          string   `json:"repo,omitempty"`
	Module        string   `json:"module,omitempty"`
	Package       string   `json:"package,omitempty"`
	Imports       []string `json:"imports,omitempty"`
	Symbols       []string `json:"symbols,omitempty"`
	Version       string   `json:"version,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	Component     string   `json:"component,omitempty"`
	Product       string   `json:"product,omitempty"`
	Release       string   `json:"release,omitempty"`
	// DistributionURL is provenance only: the locator the ticket names
	// for its distribution (the dedicated "Ссылка на дистрибутив" label
	// or an explicit JSON field), sanitized so no credential material is
	// ever recorded. It is never fetched and never read as the release
	// artifact — supplying that artifact stays the explicit
	// --artifact/--artifact-url channel's job.
	DistributionURL string          `json:"distribution_url,omitempty"`
	GoVersion       string          `json:"go_version,omitempty"`
	Toolchain       string          `json:"toolchain,omitempty"`
	Severity        string          `json:"severity,omitempty"`
	CVSS            string          `json:"cvss,omitempty"`
	Summary         string          `json:"summary,omitempty"`
	Description     string          `json:"description,omitempty"`
	Rationale       string          `json:"rationale,omitempty"`
	OSV             json.RawMessage `json:"osv,omitempty"`
}

// LoadTicket parses a ticket from a JSON file, arbitrary text file, or stdin (when path is "-").
func LoadTicket(path string) (*Ticket, error) {
	return LoadTicketWithOptions(path, "", nil)
}

// LoadTicketWithID parses tickets from a file or stdin, optionally selecting by ticket ID.
func LoadTicketWithID(path, targetID string) (*Ticket, error) {
	return LoadTicketWithOptions(path, targetID, nil)
}

// LoadTicketWithOptions parses tickets from a file or stdin, with optional ticket ID selection
// and optional LLM fallback for arbitrary text.
func LoadTicketWithOptions(path, targetID string, completer TextCompleter) (*Ticket, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read ticket %s: %w", path, err)
	}

	tickets, err := ParseTickets(b)
	if (err != nil || len(tickets) == 0) && completer != nil {
		tk, llmErr := ExtractTicketWithLLM(context.Background(), completer, string(b))
		if llmErr == nil && tk != nil {
			tickets = []*Ticket{tk}
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ticket %s: %w", path, err)
	}
	if len(tickets) == 0 {
		return nil, fmt.Errorf("ticket %s: no tickets found", path)
	}

	var selected *Ticket
	if targetID != "" {
		selected, err = SelectTicket(tickets, targetID, path)
		if err != nil {
			return nil, err
		}
	} else {
		selected = tickets[0]
	}

	// If missing key fields (package, component, or ID) and completer is provided, enrich from text
	if completer != nil && (selected.Package == "" || selected.Component == "" || selected.ID == "") && selected.Description != "" {
		enriched, llmErr := ExtractTicketWithLLM(context.Background(), completer, selected.Description)
		if llmErr == nil && enriched != nil {
			if selected.ID == "" && enriched.ID != "" {
				selected.ID = enriched.ID
			}
			if selected.Package == "" && enriched.Package != "" {
				selected.Package = enriched.Package
				selected.Module = enriched.Package
				selected.Imports = []string{enriched.Package}
			}
			if selected.Component == "" && enriched.Component != "" {
				selected.Component = enriched.Component
			}
			if selected.Release == "" && enriched.Release != "" {
				selected.Release = enriched.Release
			}
			if selected.Version == "" && enriched.Version != "" {
				selected.Version = enriched.Version
			}
			if selected.Summary == "" && enriched.Summary != "" {
				selected.Summary = enriched.Summary
			}
		}
	}

	return selected, nil
}

// SelectTicket picks one ticket out of an already-parsed batch: the
// ticket whose ID matches targetID (case-insensitive) when one is
// requested, else the first parsed ticket. source names the input in
// the not-found error only. An empty batch with a requested id is a
// selection failure, not a panic.
func SelectTicket(tickets []*Ticket, targetID, source string) (*Ticket, error) {
	if targetID == "" {
		if len(tickets) == 0 {
			return nil, fmt.Errorf("ticket %s: no tickets found", source)
		}
		return tickets[0], nil
	}
	for _, t := range tickets {
		if strings.EqualFold(t.ID, targetID) {
			return t, nil
		}
	}
	var found []string
	for _, t := range tickets {
		if t.ID != "" {
			found = append(found, t.ID)
		}
	}
	return nil, fmt.Errorf("ticket %q not found in %s (found: %s)", targetID, source, strings.Join(found, ", "))
}

// ParseTicket parses a single ticket from JSON or raw text.
func ParseTicket(data []byte) (*Ticket, error) {
	tickets, err := ParseTickets(data)
	if err != nil {
		return nil, err
	}
	if len(tickets) == 0 {
		return nil, fmt.Errorf("no ticket parsed from input")
	}
	return tickets[0], nil
}

// ParseTickets parses data as either a JSON array of tickets, a single JSON ticket,
// or arbitrary plain text containing vulnerability and ticket metadata.
func ParseTickets(data []byte) ([]*Ticket, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty ticket input")
	}

	// 1. If it looks like a JSON array, attempt to parse each element.
	if trimmed[0] == '[' {
		var rawList []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawList); err == nil && len(rawList) > 0 {
			var out []*Ticket
			for _, item := range rawList {
				t, err := parseSingleTicketJSON(item)
				if err == nil && (t.Vulnerability != "" || t.ID != "") {
					out = append(out, t)
				}
			}
			if len(out) > 0 {
				return out, nil
			}
		}
	}

	// 2. If it looks like a JSON object, attempt to parse it.
	if trimmed[0] == '{' {
		t, err := parseSingleTicketJSON(trimmed)
		if err == nil {
			return []*Ticket{t}, nil
		}
	}

	// 3. Fallback: Parse as arbitrary plain text.
	t, err := parseTextTicket(string(trimmed))
	if err != nil {
		return nil, err
	}
	return []*Ticket{t}, nil
}

var (
	reGO   = regexp.MustCompile(`(?i)\b(GO-\d{4}-\d+)\b`)
	reCVE  = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,7})\b`)
	reGHSA = regexp.MustCompile(`(?i)\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b`)
	reBDU  = regexp.MustCompile(`(?i)\b(BDU:\d{4}-\d+)\b`)

	reTicketKey = regexp.MustCompile(`\b([A-Z]{2,15}-\d+)\b`)
	reGoModule  = regexp.MustCompile(`\b((?:github\.com|golang\.org|google\.golang\.org|gopkg\.in|gitlab\.com)/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)\b`)

	reComponentLabel = regexp.MustCompile(`(?i)(?:компонент|component)[\s:=]+([^\r\n,;]+)`)
	reProductLabel   = regexp.MustCompile(`(?i)(?:версия продукта|продукт|product version|product|release|релиз)[\s:=]+([^\r\n,;]+)`)
	rePackageLabel   = regexp.MustCompile(`(?i)(?:библиотека|пакет|модуль|library|package|module)[\s:=]+([^\s,;]+)`)
	// rePackagePair additionally captures the token that follows the
	// package path on the same labelled span — real tracker tickets
	// declare the vulnerable version inline ("Библиотека: <module>
	// <version>"), and that token is the authoritative package version
	// when no explicit version label matched.
	rePackagePair = regexp.MustCompile(`(?i)(?:библиотека|пакет|модуль|library|package|module)[\s:=]+([^\s,;]+)(?:[ \t]+([^\s,;]+))?`)
	// rePURL is the self-contained package+version claim: a purl such
	// as "pkg:golang/github.com/antchfx/xpath@1.3.2" pins both halves,
	// so it wins over the label heuristics whenever it is present.
	rePURL = regexp.MustCompile(`(?i)\bpkg:golang/([^\s@,;]+)@([^\s,;]+)`)
	// reDistribLabel is the dedicated distribution locator label —
	// "Ссылка на дистрибутив:" in real tracker texts, "distribution
	// link/url/artifact" in English forms. Only text under this label is
	// a distribution pointer; arbitrary URLs elsewhere in the ticket
	// (project links, wiki references, advisory references) never
	// qualify. The capture is one token — real tickets run fields
	// together on one line, so the next label is never inside it.
	reDistribLabel   = regexp.MustCompile(`(?i)(?:ссылка на дистрибутив|distribution (?:link|url|artifact))[\s:=]+([^\s,]+)`)
	reVersionLabel   = regexp.MustCompile(`(?i)(?:версия библиотеки|версия пакета|версия|version|ver)[\s:=]+([^\s,;]+)`)
	reGoVersionLabel = regexp.MustCompile(`(?i)(?:версия go|версия компилятора|go_version|go version|toolchain|compiler)[\s:=]+([^\s,;]+)`)
	reSeverityLabel  = regexp.MustCompile(`(?i)(?:критичность|приоритет|severity|priority)[\s:=]+([^\s,;]+)`)
	reCVSSLabel      = regexp.MustCompile(`(?i)(?:cvss|score)[\s:=]+([^\s,;]+)`)
)

func canonicalVulnID(s string) string {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "GHSA-") && len(s) > 5 {
		return "GHSA-" + strings.ToLower(s[5:])
	}
	return upper
}

func vulnPriority(id string) int {
	upper := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(upper, "GO-"):
		return 1
	case strings.HasPrefix(upper, "GHSA-"):
		return 2
	case strings.HasPrefix(upper, "CVE-"):
		return 3
	default:
		return 4
	}
}

func extractVulnIDs(s string) []string {
	var results []string
	seen := make(map[string]bool)
	add := func(matches []string) {
		for _, m := range matches {
			canon := canonicalVulnID(m)
			if !seen[canon] {
				seen[canon] = true
				results = append(results, canon)
			}
		}
	}
	add(reGO.FindAllString(s, -1))
	add(reCVE.FindAllString(s, -1))
	add(reGHSA.FindAllString(s, -1))
	add(reBDU.FindAllString(s, -1))
	return results
}

func isVulnID(s string) bool {
	upper := strings.ToUpper(strings.TrimSpace(s))
	return reGO.MatchString(upper) || reCVE.MatchString(upper) || reGHSA.MatchString(upper) || reBDU.MatchString(upper)
}

func extractTicketID(s string) string {
	matches := reTicketKey.FindAllString(s, -1)
	for _, m := range matches {
		upper := strings.ToUpper(m)
		if isVulnID(upper) ||
			strings.HasPrefix(upper, "EV-") ||
			strings.HasPrefix(upper, "TX-") ||
			strings.HasPrefix(upper, "C-") ||
			strings.HasPrefix(upper, "H-") {
			continue
		}
		return upper
	}
	return ""
}

func stringValue(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case []any:
		for _, item := range val {
			if s := stringValue(item); s != "" {
				return s
			}
		}
	case []string:
		for _, s := range val {
			if strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	case map[string]any:
		for _, k := range []string{"name", "value", "code", "id", "text"} {
			if s := stringValue(val[k]); s != "" {
				return s
			}
		}
	}
	return ""
}

func stringSliceValue(v any) []string {
	if v == nil {
		return nil
	}
	var out []string
	switch val := v.(type) {
	case string:
		if s := strings.TrimSpace(val); s != "" {
			out = append(out, s)
		}
	case []any:
		for _, item := range val {
			if s := stringValue(item); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, s := range val {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case map[string]any:
		if s := stringValue(val); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func findField(m map[string]any, exactKeys []string, keywordFragments ...string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, target := range exactKeys {
		for _, k := range keys {
			if strings.EqualFold(k, target) {
				if s := stringValue(m[k]); s != "" {
					return s
				}
			}
		}
	}
	for _, frag := range keywordFragments {
		for _, k := range keys {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, frag) {
				if frag != "version" && strings.Contains(lowerK, "version") {
					continue
				}
				if s := stringValue(m[k]); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func findFieldSlice(m map[string]any, exactKeys []string, keywordFragments ...string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(v any) {
		for _, s := range stringSliceValue(v) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, target := range exactKeys {
		for _, k := range keys {
			if strings.EqualFold(k, target) {
				add(m[k])
			}
		}
	}
	for _, frag := range keywordFragments {
		for _, k := range keys {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, frag) {
				if frag != "version" && strings.Contains(lowerK, "version") {
					continue
				}
				add(m[k])
			}
		}
	}
	return out
}

func parseSingleTicketJSON(data []byte) (*Ticket, error) {
	// First check standard Ticket schema
	var std Ticket
	if err := json.Unmarshal(data, &std); err == nil && std.Vulnerability != "" {
		std.DistributionURL = sanitizeDistributionLocator(std.DistributionURL)
		if std.DistributionURL == "" {
			text := std.Description
			if text == "" {
				text = std.Summary
			}
			if m := reDistribLabel.FindStringSubmatch(text); len(m) > 1 {
				std.DistributionURL = sanitizeDistributionLocator(m[1])
			}
		}
		if std.Package != "" && std.Module == "" {
			std.Module = std.Package
		}
		if std.Package != "" && len(std.Imports) == 0 {
			std.Imports = []string{std.Package}
		}
		return &std, nil
	}

	// Try custom tracker map
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	t := &Ticket{}

	// Support nested tracker envelopes (e.g. Jira / enterprise issue tracker envelope with unit and attributes)
	if unit, ok := m["unit"].(map[string]any); ok {
		if id := findField(unit, []string{"code", "id", "key"}, "code", "key"); id != "" && t.ID == "" {
			t.ID = id
		}
		if summary := findField(unit, []string{"summary", "title", "name"}, "summary", "title"); summary != "" && t.Summary == "" {
			t.Summary = summary
		}
		if desc := findField(unit, []string{"descriptionPlain", "description", "details", "body", "text"}, "description"); desc != "" && t.Description == "" {
			t.Description = desc
		}
	}
	var vulnCandidates []string
	if attrs, ok := m["attributes"].([]any); ok {
		for _, rawAttr := range attrs {
			attrMap, ok := rawAttr.(map[string]any)
			if !ok {
				continue
			}
			var attrCode string
			if c, ok := attrMap["code"].(string); ok {
				attrCode = c
			} else if sub, ok := attrMap["attribute"].(map[string]any); ok {
				if c, ok := sub["code"].(string); ok {
					attrCode = c
				} else if c, ok := sub["name"].(string); ok {
					attrCode = c
				}
			}
			lowerCode := strings.ToLower(attrCode)
			val := attrMap["value"]

			switch {
			case strings.Contains(lowerCode, "rationale") || strings.Contains(lowerCode, "resolution") || strings.Contains(lowerCode, "result_text") || strings.Contains(lowerCode, "triage_comment") || strings.Contains(lowerCode, "justification"):
				if s := stringValue(val); s != "" && t.Rationale == "" {
					t.Rationale = s
				}
			case strings.Contains(lowerCode, "vulnerabilit") && (strings.Contains(lowerCode, "identifier") || strings.Contains(lowerCode, "id")):
				for _, v := range stringSliceValue(val) {
					if isVulnID(v) {
						vulnCandidates = append(vulnCandidates, canonicalVulnID(v))
					}
				}
			case (strings.Contains(lowerCode, "vulnerable") && strings.Contains(lowerCode, "package")) || lowerCode == "package" || lowerCode == "library":
				if s := stringValue(val); s != "" && t.Package == "" {
					t.Package = s
				}
			case (strings.Contains(lowerCode, "version") && strings.Contains(lowerCode, "package")) || lowerCode == "version":
				if s := stringValue(val); s != "" && t.Version == "" {
					t.Version = s
				}
			case strings.Contains(lowerCode, "component"):
				if s := stringValue(val); s != "" && t.Component == "" {
					t.Component = s
				}
			case strings.Contains(lowerCode, "priority") || strings.Contains(lowerCode, "severity"):
				if s := stringValue(val); s != "" && t.Severity == "" {
					t.Severity = s
				}
			case strings.Contains(lowerCode, "cvss"):
				if s := stringValue(val); s != "" && t.CVSS == "" {
					t.CVSS = s
				}
			}
		}
	}

	// Extract standard or custom ticket ID
	if id := findField(m, []string{"id", "code", "key", "ticket", "ticket_id", "issue_key", "issue_id", "task_id"}, "ticket", "issue"); id != "" && !isVulnID(id) && t.ID == "" {
		t.ID = id
	}

	// Extract vulnerability IDs
	fieldVulns := findFieldSlice(m,
		[]string{"vulnerability", "vuln", "cve", "ghsa", "go_id", "vulnerabilities", "vuln_id"},
		"vulnerabilit", "vuln", "cve")
	vulnCandidates = append(vulnCandidates, fieldVulns...)
	if len(vulnCandidates) == 0 && t.Vulnerability == "" {
		// Fallback: search all string values in m
		vulnCandidates = extractVulnIDs(string(data))
	}
	if len(vulnCandidates) > 0 {
		var unique []string
		seen := make(map[string]bool)
		for _, v := range vulnCandidates {
			canon := canonicalVulnID(v)
			if !seen[canon] {
				seen[canon] = true
				unique = append(unique, canon)
			}
		}
		sort.SliceStable(unique, func(i, j int) bool {
			return vulnPriority(unique[i]) < vulnPriority(unique[j])
		})
		if len(unique) > 0 {
			t.Vulnerability = unique[0]
			if len(unique) > 1 {
				t.Aliases = unique[1:]
			}
		}
	}

	// If ID still empty, scan summary or description for ticket key
	if t.ID == "" {
		summary := findField(m, []string{"summary", "title", "name", "subject", "header"}, "summary", "title")
		if id := extractTicketID(summary); id != "" {
			t.ID = id
		} else {
			desc := findField(m, []string{"description", "details", "body", "text"}, "description")
			if id := extractTicketID(desc); id != "" {
				t.ID = id
			}
		}
	}

	// Component & Product
	if t.Component == "" {
		t.Component = findField(m, []string{"component", "component_name", "service", "service_name", "app", "project"}, "component")
	}
	if t.Product == "" {
		t.Product = findField(m, []string{"product", "product_name", "product_code", "project_code"}, "product")
	}
	if t.Release == "" {
		t.Release = findField(m, []string{"release", "product_version", "target_version", "milestone"}, "release")
	}

	// Package & Module
	if t.Package == "" {
		t.Package = findField(m, []string{"package", "pkg", "module", "library", "lib", "vulnerable_package", "affected_package"}, "package", "module")
	}
	if t.Module == "" {
		t.Module = findField(m, []string{"module"}, "module")
	}

	// Version
	if t.Version == "" {
		t.Version = findField(m, []string{"version", "version_vulnerable_package", "vulnerable_version", "fixed_version", "affected_version", "package_version"}, "version")
	}
	if len(t.FixedVersions) == 0 {
		t.FixedVersions = findFieldSlice(m, []string{"fixed_versions", "fixed_version"}, "fixed_version")
	}

	// Summary & Description & Rationale
	if t.Summary == "" {
		t.Summary = findField(m, []string{"summary", "title", "name", "subject"}, "summary", "title")
	}
	if t.Description == "" {
		t.Description = findField(m, []string{"description", "details", "body", "text"}, "description")
	}
	if t.Rationale == "" {
		t.Rationale = findField(m, []string{"rationale", "comment", "notes", "analysis", "resolution", "result"}, "rationale", "comment", "analysis", "result")
	}
	if t.Repo == "" {
		t.Repo = findField(m, []string{"repo", "repository"}, "repo")
	}

	// Distribution locator: dedicated field names only ("дистрибутив"
	// covers the Russian-labelled key forms) — a generic url/link field
	// is never read as the distribution pointer.
	if t.DistributionURL == "" {
		t.DistributionURL = sanitizeDistributionLocator(findField(m,
			[]string{"distribution_url", "distribution", "distribution_link", "distribution_artifact", "distrib_url", "distrib"},
			"дистрибутив"))
	}

	// Go version & Toolchain
	if t.GoVersion == "" {
		t.GoVersion = findField(m, []string{"go_version", "goversion", "release_go_version", "release_go", "compiler_version", "compiler", "go"}, "go_version", "toolchain")
	}
	if t.Toolchain == "" {
		t.Toolchain = findField(m, []string{"toolchain"}, "toolchain")
	}
	if t.GoVersion == "" && t.Toolchain != "" {
		t.GoVersion = t.Toolchain
	}

	// Severity & CVSS
	if t.Severity == "" {
		t.Severity = findField(m, []string{"severity", "priority"}, "severity", "priority")
	}
	if t.CVSS == "" {
		t.CVSS = findField(m, []string{"cvss", "cvss_score", "score"}, "cvss")
	}

	// Enrich missing fields from structured text in Description or Summary
	textToScan := t.Description
	if textToScan == "" {
		textToScan = t.Summary
	}
	if textToScan != "" {
		if t.ID == "" {
			t.ID = extractTicketID(textToScan)
		}
		if t.Component == "" {
			if m := reComponentLabel.FindStringSubmatch(textToScan); len(m) > 1 {
				t.Component = strings.TrimSpace(m[1])
			}
		}
		if t.Release == "" {
			if m := reProductLabel.FindStringSubmatch(textToScan); len(m) > 1 {
				t.Release = strings.TrimSpace(m[1])
			}
		}
		if t.Package == "" {
			if m := rePackageLabel.FindStringSubmatch(textToScan); len(m) > 1 {
				t.Package = strings.TrimSpace(m[1])
			} else if m := reGoModule.FindStringSubmatch(textToScan); len(m) > 1 {
				t.Package = strings.TrimSpace(m[1])
			}
		}
		if t.Version == "" {
			if m := reVersionLabel.FindStringSubmatch(textToScan); len(m) > 1 {
				t.Version = strings.TrimSpace(m[1])
			}
		}
		if t.GoVersion == "" {
			if m := reGoVersionLabel.FindStringSubmatch(textToScan); len(m) > 1 {
				t.GoVersion = strings.TrimSpace(m[1])
			}
		}
		if t.Vulnerability == "" {
			vulns := extractVulnIDs(textToScan)
			if len(vulns) > 0 {
				t.Vulnerability = vulns[0]
				if len(vulns) > 1 && len(t.Aliases) == 0 {
					t.Aliases = vulns[1:]
				}
			}
		}
		// The distribution label can live inside a JSON ticket's
		// description/summary text (real tracker JSONs embed the labelled
		// line verbatim); it is scanned here with the same dedicated-label
		// rule as the plain-text parser.
		if t.DistributionURL == "" {
			if m := reDistribLabel.FindStringSubmatch(textToScan); len(m) > 1 {
				t.DistributionURL = sanitizeDistributionLocator(m[1])
			}
		}
	}

	if t.Module == "" && t.Package != "" {
		t.Module = t.Package
	}
	if len(t.Imports) == 0 && t.Package != "" {
		t.Imports = []string{t.Package}
	}

	type osvWrapper struct {
		OSV json.RawMessage `json:"osv"`
	}
	var ow osvWrapper
	if err := json.Unmarshal(data, &ow); err == nil && len(ow.OSV) > 0 {
		t.OSV = ow.OSV
	}

	if t.Vulnerability == "" {
		return nil, fmt.Errorf("no vulnerability identifier found in ticket (expected GO-*, CVE-*, GHSA-*, BDU:*)")
	}

	return t, nil
}

func parseTextTicket(text string) (*Ticket, error) {
	vulnIDs := extractVulnIDs(text)
	if len(vulnIDs) == 0 {
		return nil, fmt.Errorf("no vulnerability identifier found in ticket text (expected GO-*, CVE-*, GHSA-*, BDU:*)")
	}

	t := &Ticket{
		Vulnerability: vulnIDs[0],
	}
	if len(vulnIDs) > 1 {
		t.Aliases = vulnIDs[1:]
	}

	t.ID = extractTicketID(text)
	// Component
	if m := reComponentLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Component = trimLabelValue(m[1], false)
	}

	// Product / Release
	if m := reProductLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Release = trimLabelValue(m[1], true)
	}

	// Package
	if m := rePackageLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Package = strings.TrimSpace(m[1])
	} else if m := reGoModule.FindStringSubmatch(text); len(m) > 1 {
		t.Package = strings.TrimSpace(m[1])
	}
	// A PURL is the self-contained package+version claim: when present
	// it pins the package identity over the label heuristics and
	// supplies the authoritative package version.
	purlVersion := ""
	if m := rePURL.FindStringSubmatch(text); len(m) > 2 {
		t.Package = purlUnescape(m[1])
		purlVersion = purlUnescape(m[2])
	}

	if t.Package != "" {
		t.Module = t.Package
		t.Imports = []string{t.Package}
	}

	// Version: the PURL pins it outright; otherwise the first explicit
	// version label whose capture is version-shaped, then the token
	// carried on the package's own label line.
	switch {
	case purlVersion != "":
		t.Version = purlVersion
	default:
		t.Version = textTicketVersion(text)
	}

	// Go Version / Toolchain
	if m := reGoVersionLabel.FindStringSubmatch(text); len(m) > 1 {
		t.GoVersion = strings.TrimSpace(m[1])
	}

	// Severity & CVSS
	if m := reSeverityLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Severity = strings.TrimSpace(m[1])
	}
	if m := reCVSSLabel.FindStringSubmatch(text); len(m) > 1 {
		t.CVSS = strings.TrimSpace(m[1])
	}

	// Distribution locator: only the dedicated label names the ticket's
	// distribution — a Project/wiki/advisory URL elsewhere in the text
	// never does — and the recorded form is sanitized, never fetched.
	if m := reDistribLabel.FindStringSubmatch(text); len(m) > 1 {
		t.DistributionURL = sanitizeDistributionLocator(m[1])
	}

	t.Description = strings.TrimSpace(text)
	return t, nil
}

// versionShaped reports whether s can be a version token: it must
// contain a digit. Words captured after a look-alike label
// ("Version: Gateway", "Версия продукта:" grabbing "продукта:") fail
// this check instead of landing in Ticket.Version.
func versionShaped(s string) bool {
	return strings.IndexFunc(s, unicode.IsDigit) >= 0
}

// textTicketVersion resolves the declared package version from a text
// ticket. reVersionLabel is intentionally loose — its bare
// "version"/"версия"/"ver" alternatives also match inside
// "go_version:" and inside "Версия продукта:" — so a candidate match
// is admitted only when the label is not a suffix of a longer
// identifier (preceded by a letter, digit or '_') and the captured
// token is version-shaped. When no explicit label yields a version,
// the token written next to the package name on its own label line
// ("Библиотека: <module> <version>") is the fallback claim.
func textTicketVersion(text string) string {
	for _, loc := range reVersionLabel.FindAllStringSubmatchIndex(text, -1) {
		if loc[0] > 0 {
			if r, _ := utf8.DecodeLastRuneInString(text[:loc[0]]); r == '_' ||
				unicode.IsLetter(r) || unicode.IsDigit(r) {
				continue // label embedded in a longer word (go_version, productVersion, server)
			}
		}
		if cand := strings.TrimSpace(text[loc[2]:loc[3]]); versionShaped(cand) {
			return cand
		}
	}
	for _, m := range rePackagePair.FindAllStringSubmatch(text, -1) {
		if len(m) > 2 && versionShaped(m[2]) {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// purlUnescape decodes a percent-encoded purl component. Versions
// carry escaped spellings in real tickets ("28.0.1%2Bincompatible" is
// the Go version "28.0.1+incompatible"); PathUnescape restores the
// literal form and leaves an already-plain token (or a malformed
// escape, on error) untouched.
func purlUnescape(s string) string {
	if u, err := url.PathUnescape(strings.TrimSpace(s)); err == nil {
		return u
	}
	return strings.TrimSpace(s)
}

// sanitizeDistributionLocator returns the recordable form of a
// ticket-declared distribution locator: userinfo, query and fragment
// are stripped so the recorded provenance can never carry credential
// material, the way sanitizeURLRef bounds the artifact channel's
// recorded URL. A value that is not a locator (no '/', '\' or '.', or
// carrying quotes/angle brackets — markdown breakers in the rendered
// report) is dropped: the pinned ticket digest already preserves the
// exact bytes, and a non-locator string must not be reported as the
// distribution pointer.
func sanitizeDistributionLocator(raw string) string {
	s := strings.TrimSpace(strings.Trim(raw, "`"))
	if s == "" || strings.ContainsAny(s, "\"'<>\n\r\t") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	s = u.String()
	if !strings.ContainsAny(s, "/.\\") {
		return ""
	}
	return s
}

// labelEndTok reports whether a whitespace-separated token ends a
// Word:-style label ("продукта:", "Project:", "PURL:"): a run of
// letters closed by a colon. URL/scheme tokens never qualify — they
// do not end with ':'.
func labelEndTok(tok string) bool {
	if len(tok) < 2 || !strings.HasSuffix(tok, ":") {
		return false
	}
	for _, r := range tok[:len(tok)-1] {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// labelWordTok reports whether a token can be part of a multi-word
// label that precedes its colon word ("Ссылка на …", "Алиасы на
// уязвимость"): letters only, at least one lowercase — all-caps
// tokens are values (DEMO, HOTFIX, DEMO), never label words.
func labelWordTok(tok string) bool {
	lower := false
	for _, r := range tok {
		if !unicode.IsLetter(r) {
			return false
		}
		if unicode.IsLower(r) {
			lower = true
		}
	}
	return lower
}

// trimLabelValue cuts a multi-token label capture at the boundary of
// the next Word:-style label. Single-line tracker texts run the
// fields together ("Версия продукта: <v> Тип версии продукта: HOTFIX
// Ссылка на …: <url> Компонент: <c>"), so a [^\r\n,;]+ capture
// otherwise swallows every following label. The label boundary is
// generic: a letters-only token closed by ':' plus the word run that
// opens it. For the product axis the value additionally stops at its
// own version token — the release claim is the product name plus its
// version, never the trailing field text.
func trimLabelValue(value string, productAxis bool) string {
	fields := strings.Fields(strings.TrimSpace(value))
	for i := 1; i < len(fields); i++ {
		if labelEndTok(fields[i]) {
			start := i
			for start > 0 && labelWordTok(fields[start-1]) {
				start--
			}
			fields = fields[:start]
			break
		}
	}
	if productAxis {
		for i, f := range fields {
			if versionShaped(f) {
				fields = fields[:i+1]
				break
			}
		}
	}
	return strings.Join(fields, " ")
}

// AdvisoryFile materializes the ticket's advisory data as an OSV JSON
// file the analyzer can consume: the embedded "osv" document verbatim,
// or a minimal synthesized doc from module+fixed_versions. Returns ""
// when the ticket carries no advisory material (the caller falls back
// to the configured vulnerability source).
func (t *Ticket) AdvisoryFile(dir, vulnID string) (string, error) {
	var doc []byte
	switch {
	case len(t.OSV) > 0:
		doc = t.OSV
	case t.Module != "" && len(t.FixedVersions) > 0:
		imports := t.Imports
		if len(imports) == 0 {
			imports = []string{t.Module}
		}
		var imps []map[string]any
		for _, p := range imports {
			imp := map[string]any{"path": p}
			if syms := t.symbolsFor(p); len(syms) > 0 {
				imp["symbols"] = syms
			}
			imps = append(imps, imp)
		}
		synth := map[string]any{
			"id": vulnID,
			"affected": []map[string]any{{
				"package": map[string]any{"ecosystem": "Go", "name": t.Module},
				"ranges": []map[string]any{{
					"type":   "SEMVER",
					"events": ticketEvents(t.FixedVersions),
				}},
				"ecosystem_specific": map[string]any{"imports": imps},
			}},
		}
		b, err := json.Marshal(synth)
		if err != nil {
			return "", err
		}
		doc = b
	default:
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "ticket-advisory.json")
	if err := os.WriteFile(p, doc, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// ticketEvents builds SEMVER range events: introduced at 0, each fixed
// version in listed order. No fixed version = open-ended range.
func ticketEvents(fixed []string) []map[string]string {
	ev := []map[string]string{{"introduced": "0"}}
	for _, f := range fixed {
		ev = append(ev, map[string]string{"fixed": f})
	}
	return ev
}

// symbolsFor returns the ticket's symbol entries scoped to package p —
// symbols are given as "pkg/path.Symbol"; entries whose package matches
// p contribute their bare symbol name, unqualified entries apply to all.
func (t *Ticket) symbolsFor(p string) []string {
	var out []string
	for _, s := range t.Symbols {
		i := strings.LastIndex(s, ".")
		if i <= 0 {
			out = append(out, s)
			continue
		}
		if s[:i] == p {
			out = append(out, s[i+1:])
		}
	}
	return out
}
