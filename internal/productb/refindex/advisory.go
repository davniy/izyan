package refindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
)

// AdvisoryOptions controls advisory resolution in Builder.Build.
type AdvisoryOptions struct {
	// File is a single OSV document to use as the selected advisory.
	// Aliases/related ids are resolved as siblings of this file.
	File string
	// Dir is a directory of OSV documents; ID (or a doc aliasing it)
	// selects the document, all id-matching siblings form the family.
	Dir string
	// ID is the advisory id to resolve (GO-*, CVE-*, GHSA-*). Required
	// when Dir or network resolution is used; optional with File (then it
	// must match the document id or one of its aliases).
	ID string
	// OSVBaseURL overrides the OSV-compatible API base used when neither
	// File nor Dir resolves the document. Empty = https://api.osv.dev.
	OSVBaseURL string
	// NoNet disables all network fetches: family closure only scans the
	// local document set; without File/Dir the build fails.
	NoNet bool
}

// loadedAdvisory is the resolved advisory corpus: the selected document
// plus every family document consulted, verbatim.
type loadedAdvisory struct {
	vuln *pbdomain.Vulnerability
	// docs holds the verbatim bytes of every consulted document, keyed by
	// document id; the selected document is first after sorting.
	docs map[string][]byte
	// docIDs maps document id -> parsed id/alias/related sets, used for
	// family closure matching.
	family []familyDoc
	// notes records non-fatal family-closure gaps (unreachable alias
	// documents); they surface as usage limitations.
	notes []string
}

type familyDoc struct {
	id      string
	aliases []string
	related []string
	bytes   []byte
	vuln    *pbdomain.Vulnerability
}

// osvFamily is the minimal document projection needed for family closure:
// aliases and related ids, which the internal model does not carry.
type osvFamily struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Related []string `json:"related"`
}

const defaultOSVBaseURL = "https://api.osv.dev"

// loadAdvisory resolves the selected document and the family corpus.
func loadAdvisory(ctx context.Context, o AdvisoryOptions) (*loadedAdvisory, error) {
	if o.File != "" {
		return loadAdvisoryFile(ctx, o)
	}
	if o.Dir != "" {
		return loadAdvisoryDir(ctx, o)
	}
	if o.ID == "" {
		return nil, fmt.Errorf("no advisory source: pass --advisory <file|dir> or --cve <id> with network")
	}
	if o.NoNet {
		return nil, fmt.Errorf("--no-net: cannot resolve advisory %s without --advisory", o.ID)
	}
	base := o.OSVBaseURL
	if base == "" {
		base = defaultOSVBaseURL
	}
	src := vulnerability.OSVSource{BaseURL: base, HTTPClient: &http.Client{Timeout: 15 * time.Second}}
	raw, err := src.GetRaw(ctx, o.ID)
	if err != nil {
		return nil, fmt.Errorf("osv fetch %s: %w", o.ID, err)
	}
	la := &loadedAdvisory{
		vuln:   raw.Vuln,
		docs:   map[string][]byte{raw.Vuln.ID: raw.Bytes},
		family: []familyDoc{familyOf(raw.Vuln.ID, raw.Bytes, raw.Vuln)},
	}
	la.notes = la.fetchFamily(ctx, src)
	return la, nil
}

// loadAdvisoryFile loads one explicit document; the family closure scans
// sibling files for documents matching the selected doc's aliases/related
// ids (no network).
func loadAdvisoryFile(_ context.Context, o AdvisoryOptions) (*loadedAdvisory, error) {
	b, err := os.ReadFile(o.File)
	if err != nil {
		return nil, fmt.Errorf("read advisory %s: %w", o.File, err)
	}
	v, err := vulnerability.ParseAdvisoryDoc(b)
	if err != nil {
		return nil, fmt.Errorf("parse advisory %s: %w", o.File, err)
	}
	if o.ID != "" && v.ID != o.ID && !contains(v.Aliases, o.ID) {
		return nil, fmt.Errorf("advisory %s is %s, not %s", o.File, v.ID, o.ID)
	}
	la := &loadedAdvisory{
		vuln:   v,
		docs:   map[string][]byte{v.ID: b},
		family: []familyDoc{familyOf(v.ID, b, v)},
	}
	// Family closure: scan the file's own directory for sibling documents
	// whose id matches the selected doc's aliases/related ids.
	dir := filepath.Dir(o.File)
	wanted := familyIDs(la.family[0])
	for _, d := range readAdvisoryDir(dir) {
		if d.id == v.ID {
			continue
		}
		if !wanted[d.id] {
			continue
		}
		if _, seen := la.docs[d.id]; seen {
			continue
		}
		la.docs[d.id] = d.bytes
		la.family = append(la.family, d)
	}
	return la, nil
}

// loadAdvisoryDir resolves ID inside a directory of OSV documents and
// loads every family member (aliases/related of the selected doc).
func loadAdvisoryDir(ctx context.Context, o AdvisoryOptions) (*loadedAdvisory, error) {
	docs := readAdvisoryDir(o.Dir)
	if len(docs) == 0 {
		return nil, fmt.Errorf("no OSV documents under %s", o.Dir)
	}
	var sel *familyDoc
	for i := range docs {
		if o.ID == "" || docs[i].id == o.ID || contains(docs[i].aliases, o.ID) {
			sel = &docs[i]
			break
		}
	}
	if sel == nil {
		return nil, fmt.Errorf("advisory %s not found in %s", o.ID, o.Dir)
	}
	la := &loadedAdvisory{
		vuln:   sel.vuln,
		docs:   map[string][]byte{sel.id: sel.bytes},
		family: []familyDoc{*sel},
	}
	wanted := familyIDs(*sel)
	for _, d := range docs {
		if d.id == sel.id || !wanted[d.id] {
			continue
		}
		if _, seen := la.docs[d.id]; seen {
			continue
		}
		la.docs[d.id] = d.bytes
		la.family = append(la.family, d)
	}
	// Without network the family is whatever the directory supplies; the
	// network fallback below mirrors FileSource's sibling enrichment for
	// symbols the local corpus cannot provide.
	if o.NoNet || len(la.vuln.AffectedSymbols) > 0 || len(la.vuln.Aliases) == 0 {
		return la, nil
	}
	base := o.OSVBaseURL
	if base == "" {
		base = defaultOSVBaseURL
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	for _, alias := range sortedAliases(la.vuln.Aliases) {
		if _, seen := la.docs[alias]; seen {
			continue
		}
		src := vulnerability.OSVSource{BaseURL: base, HTTPClient: hc}
		raw, err := src.GetRaw(ctx, alias)
		if err != nil || raw.Vuln == nil {
			continue
		}
		la.docs[raw.Vuln.ID] = raw.Bytes
		la.family = append(la.family, familyOf(raw.Vuln.ID, raw.Bytes, raw.Vuln))
	}
	return la, nil
}

// readAdvisoryDir scans a directory for *.json OSV documents, returning
// them sorted by document id for deterministic family iteration.
func readAdvisoryDir(dir string) []familyDoc {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	sort.Strings(files)
	var out []familyDoc
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		v, perr := vulnerability.ParseAdvisoryDoc(b)
		if perr != nil {
			continue
		}
		out = append(out, familyOf(v.ID, b, v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// Bounds for the network family closure: a CVE wrapper's alias fan-out is
// wide, so the BFS is depth-limited and document-limited to keep the run
// bounded and deterministic.
const (
	familyMaxDepth = 2
	familyMaxDocs  = 50
)

// fetchFamily walks aliases/related ids breadth-first from the selected
// document, fetching each unseen id through the OSV source and adding the
// verbatim document to the family. Bounded: depth <= familyMaxDepth,
// total family size <= familyMaxDocs, ids are deduplicated before fetch.
// Fetch failures are recorded as limitations, never fatal - a wrapper may
// legitimately reference entries the backend does not serve.
func (la *loadedAdvisory) fetchFamily(ctx context.Context, src vulnerability.OSVSource) []string {
	var notes []string
	type pending struct {
		id    string
		depth int
	}
	var queue []pending
	seen := map[string]bool{}
	for id := range la.docs {
		seen[id] = true
	}
	enqueue := func(d familyDoc, depth int) {
		ids := make([]string, 0, len(d.aliases)+len(d.related))
		ids = append(ids, sortedAliases(d.aliases)...)
		rel := append([]string{}, d.related...)
		sort.Strings(rel)
		ids = append(ids, rel...)
		for _, id := range ids {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			queue = append(queue, pending{id: id, depth: depth + 1})
		}
	}
	enqueue(la.family[0], 0)
	for i := 0; i < len(queue) && len(la.family) < familyMaxDocs; i++ {
		p := queue[i]
		if p.depth > familyMaxDepth {
			continue
		}
		raw, err := src.GetRaw(ctx, p.id)
		if err != nil || raw.Vuln == nil {
			// Class only: the transport URL and response bodies must not
			// leak into the frozen document (determinism across mirrors).
			class := string(vulnerability.AdvisoryClassUnavailable)
			var ae *vulnerability.AdvisoryError
			if errors.As(err, &ae) {
				class = string(ae.Class)
			}
			notes = append(notes,
				fmt.Sprintf("family document %s could not be fetched (%s)", p.id, class))
			continue
		}
		if la.docs[raw.Vuln.ID] == nil {
			la.docs[raw.Vuln.ID] = raw.Bytes
			fd := familyOf(raw.Vuln.ID, raw.Bytes, raw.Vuln)
			la.family = append(la.family, fd)
			if !seen[raw.Vuln.ID] {
				seen[raw.Vuln.ID] = true
				if p.depth < familyMaxDepth {
					enqueue(fd, p.depth)
				}
			}
		}
	}
	return notes
}

// familyOf derives the family membership facts of one parsed document.
func familyOf(id string, b []byte, v *pbdomain.Vulnerability) familyDoc {
	fd := familyDoc{id: id, bytes: b, vuln: v}
	var fam osvFamily
	if err := json.Unmarshal(b, &fam); err == nil {
		fd.aliases = fam.Aliases
		fd.related = fam.Related
	}
	if len(fd.aliases) == 0 && v != nil {
		fd.aliases = v.Aliases
	}
	return fd
}

// familyIDs is the set of document ids a document claims kinship with.
func familyIDs(d familyDoc) map[string]bool {
	out := map[string]bool{}
	for _, a := range d.aliases {
		out[a] = true
	}
	for _, r := range d.related {
		out[r] = true
	}
	return out
}

// sortedAliases orders alias ids GO-*-first, mirroring FileSource's
// enrichment priority so family adoption stays deterministic.
func sortedAliases(aliases []string) []string {
	out := append([]string{}, aliases...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.HasPrefix(out[i], "GO-") && !strings.HasPrefix(out[j], "GO-")
	})
	return out
}

// advisoryDigest renders the family corpus digest: sha256 over the
// concatenated verbatim document bytes, documents sorted by id.
func (la *loadedAdvisory) advisoryDigest() (string, []AdvisoryDoc) {
	ids := make([]string, 0, len(la.docs))
	for id := range la.docs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	docs := make([]AdvisoryDoc, 0, len(ids))
	for _, id := range ids {
		b := la.docs[id]
		sum := sha256.Sum256(b)
		h.Write(b)
		docs = append(docs, AdvisoryDoc{ID: id, SHA256: "sha256:" + hex.EncodeToString(sum[:])})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), docs
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
