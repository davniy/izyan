// Package advfeed reads operator-supplied OSV vulnerability dumps and
// answers one narrow question for the research lane: which packages and
// symbols does an advisory declare for a given Go module — looked up by
// advisory id and by every alias it carries. A dump is either a local
// directory of OSV JSON documents (or a single zip of them), or a remote
// source in the standard OSV layout
// (<base>/<ecosystem>/all.zip plus <base>/ecosystems.txt).
//
// The package is deterministic and offline-safe by construction: it never
// fabricates subjects, it deduplicates and cross-checks every candidate
// document, and disagreement between candidate records resolves to an
// explicit "ambiguous" status instead of a guess.
package advfeed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/repository"
)

// EcosystemGo is the only ecosystem this analyzer consumes from a dump.
const EcosystemGo = "Go"

// Resolution status vocabulary. Every failure is a named, fail-closed
// outcome — never an implicit empty result.
const (
	// StatusResolved marks a dump acquisition/resolution that supplied data.
	StatusResolved = "resolved"
	// StatusNotRequired means no advisory entry needed feed subjects.
	StatusNotRequired = "not_required"
	// StatusNotFound means neither the id nor any alias indexes a document.
	StatusNotFound = "not_found"
	// StatusNoImports means every candidate document declares no imports
	// for the module.
	StatusNoImports = "no_imports"
	// StatusAmbiguous means candidate documents disagree about the
	// module's imports — the feed declined to pick one.
	StatusAmbiguous = "ambiguous"
	// StatusOSVMissing means the remote source answers ecosystems.txt and
	// the requested ecosystem is not on it — a documented gap, not an
	// error.
	StatusOSVMissing = "osv_missing"
	// StatusFeedError means the configured source could not be read at
	// all (unreachable mirror without a valid cache, unreadable local
	// dump, malformed options).
	StatusFeedError = "feed_error"
)

// Import is one OSV affected[].ecosystem_specific.imports entry.
type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
	GOOS    []string `json:"goos"`
	GOARCH  []string `json:"goarch"`
}

// Prov is dump provenance: where the bytes came from, their digest and
// when the source was last checked. It never carries credentials — Ref is
// a sanitized base URL or a "local:<basename>" label.
type Prov struct {
	Ref       string    `json:"ref,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// Feed is an indexed OSV dump. Documents are indexed by their own id and
// by every alias they list, so a GHSA/CVE id can reach the ecosystem
// record that carries package/symbol subjects.
type Feed struct {
	Prov Prov

	// index maps an id OR an alias to the documents claiming it. Two
	// different records can legitimately share an alias (e.g. a CVE id
	// listed by several databases), so the value is a slice and the
	// resolver deduplicates by document id.
	index map[string][]*dumpDoc
}

// dumpDoc is the projection of one OSV document the feed needs.
type dumpDoc struct {
	ID       string
	Aliases  []string
	Related  []string
	Affected []dumpAffected
}

type dumpAffected struct {
	Ecosystem string
	Name      string
	Imports   []Import
}

// docShape is the minimal OSV decode target; anything else is ignored.
type docShape struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Related  []string `json:"related"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []Import `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// Open indexes a local dump: path is either a directory holding OSV JSON
// documents (searched recursively) or a single zip archive of them.
// Documents that fail to decode are skipped only when they decode to no
// id; a completely unreadable entry makes the open fail closed.
func Open(path string) (*Feed, error) {
	f := &Feed{index: map[string][]*dumpDoc{}}
	var digestMembers []string
	add := func(name string, body []byte) error {
		doc, err := decodeDoc(body)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if doc == nil {
			return nil // no id — not an advisory document
		}
		f.indexDoc(doc)
		sum := sha256.Sum256(body)
		digestMembers = append(digestMembers, name+":"+hex.EncodeToString(sum[:]))
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("osv feed %s: %w", path, err)
	}
	switch {
	case st.IsDir():
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
				return nil
			}
			body, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(path, p)
			return add(rel, body)
		})
	default:
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("osv feed %s: %w", path, rerr)
		}
		zf, zerr := openZipBytes(body, "")
		if zerr != nil {
			return nil, fmt.Errorf("osv feed %s: not a directory and not a zip archive: %w", path, zerr)
		}
		f.index = zf.index
		f.Prov.SHA256 = zf.Prov.SHA256
	}
	if err != nil {
		return nil, fmt.Errorf("osv feed %s: %w", path, err)
	}
	if f.Prov.SHA256 == "" {
		// Directory dumps have no single byte identity: the digest is the
		// canonical member list (relative name + per-file sha256), sorted.
		sort.Strings(digestMembers)
		sum := sha256.Sum256([]byte(strings.Join(digestMembers, "\n")))
		f.Prov.SHA256 = hex.EncodeToString(sum[:])
	}
	f.Prov.Ref = repository.ProvenanceLocalRef(path)
	f.Prov.CheckedAt = time.Now().UTC()
	return f, nil
}

// openZipBytes indexes an OSV dump held in memory — the downloaded or
// operator-supplied archive bytes. ref is the provenance label (a
// sanitized base URL; empty for a caller-supplied path that Open stamps
// itself).
func openZipBytes(body []byte, ref string) (*Feed, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	f := &Feed{index: map[string][]*dumpDoc{}}
	for _, m := range zr.File {
		if m.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(m.Name), ".json") {
			continue
		}
		rc, oerr := m.Open()
		if oerr != nil {
			return nil, fmt.Errorf("member %s: %w", m.Name, oerr)
		}
		mb, rerr := io.ReadAll(io.LimitReader(rc, maxDocBytes))
		rc.Close()
		if rerr != nil {
			return nil, fmt.Errorf("member %s: %w", m.Name, rerr)
		}
		doc, derr := decodeDoc(mb)
		if derr != nil {
			return nil, fmt.Errorf("member %s: %w", m.Name, derr)
		}
		if doc != nil {
			f.indexDoc(doc)
		}
	}
	sum := sha256.Sum256(body)
	f.Prov.SHA256 = hex.EncodeToString(sum[:])
	f.Prov.Ref = ref
	return f, nil
}

const maxDocBytes = 16 << 20 // a single OSV document is kilobytes, never megabytes

func decodeDoc(body []byte) (*dumpDoc, error) {
	var s docShape
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	if s.ID == "" {
		return nil, nil
	}
	d := &dumpDoc{ID: s.ID, Aliases: s.Aliases, Related: append([]string(nil), s.Related...)}
	for _, a := range s.Affected {
		da := dumpAffected{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name}
		for _, imp := range a.EcosystemSpecific.Imports {
			da.Imports = append(da.Imports, Import{
				Path:    imp.Path,
				Symbols: append([]string(nil), imp.Symbols...),
				GOOS:    append([]string(nil), imp.GOOS...),
				GOARCH:  append([]string(nil), imp.GOARCH...),
			})
		}
		d.Affected = append(d.Affected, da)
	}
	return d, nil
}

func (f *Feed) indexDoc(d *dumpDoc) {
	f.index[d.ID] = append(f.index[d.ID], d)
	for _, a := range d.Aliases {
		f.index[a] = append(f.index[a], d)
	}
}

// Resolution is the outcome of one subject lookup.
type Resolution struct {
	OK     bool
	Status string // StatusResolved/StatusNotFound/StatusNoImports/StatusAmbiguous
	Detail string
	// MatchedID is the query id (the advisory's own id or one of its
	// aliases) that indexed the supplying document.
	MatchedID string
	// SourceID is the document id that supplied the imports — the alias
	// record id when the frozen advisory's own document declared nothing.
	SourceID string
	Imports  []Import
}

// ResolveImports returns the declared package/symbol subjects for module
// within the advisory identified by id (or any of its aliases). Every id
// key is consulted; the distinct import sets across all matched documents
// must agree — disagreement is StatusAmbiguous, never a silent pick.
func (f *Feed) ResolveImports(id string, aliases []string, module string) Resolution {
	if module == "" {
		return Resolution{Status: StatusNoImports, Detail: "empty module name"}
	}
	var docs []*dumpDoc
	seen := map[*dumpDoc]bool{}
	keyOf := map[*dumpDoc]string{}
	for _, key := range append([]string{id}, aliases...) {
		for _, d := range f.index[key] {
			if seen[d] {
				continue
			}
			seen[d] = true
			docs = append(docs, d)
			keyOf[d] = key
		}
	}
	if len(docs) == 0 {
		return Resolution{Status: StatusNotFound,
			Detail: "neither the advisory id nor its aliases index a feed document"}
	}
	sets := map[string]*Resolution{}
	declared := 0
	for _, d := range docs {
		imp := importsForModule(d, module)
		if len(imp) == 0 {
			// A document that names the module but declares no imports
			// carries no subject evidence — it is absent data, not a
			// contradiction of another document's declaration.
			continue
		}
		declared++
		key := canonicalImports(imp)
		if _, ok := sets[key]; !ok {
			sets[key] = &Resolution{
				OK: true, Status: StatusResolved,
				MatchedID: keyOf[d], SourceID: d.ID, Imports: imp,
			}
		}
	}
	if len(sets) > 1 {
		var ids []string
		for _, d := range docs {
			ids = append(ids, d.ID)
		}
		return Resolution{Status: StatusAmbiguous,
			Detail: fmt.Sprintf("feed documents %s disagree about imports for module %s",
				strings.Join(ids, ", "), module)}
	}
	for _, r := range sets {
		return *r
	}
	var ids []string
	for _, d := range docs {
		ids = append(ids, d.ID)
	}
	return Resolution{Status: StatusNoImports,
		Detail: fmt.Sprintf("feed document(s) %s declare no imports for module %s",
			strings.Join(ids, ", "), module)}
}

// importsForModule unions the imports of every Go-ecosystem affected
// entry in the document that names the module.
func importsForModule(d *dumpDoc, module string) []Import {
	var out []Import
	for _, a := range d.Affected {
		if a.Name != module || a.Ecosystem != EcosystemGo {
			continue
		}
		out = append(out, a.Imports...)
	}
	return out
}

// canonicalImports renders an import set order-insensitive so equal
// declarations in different documents compare equal.
func canonicalImports(imp []Import) string {
	parts := make([]string, 0, len(imp))
	for _, i := range imp {
		s := append([]string(nil), i.Symbols...)
		goos := append([]string(nil), i.GOOS...)
		goarch := append([]string(nil), i.GOARCH...)
		sort.Strings(s)
		sort.Strings(goos)
		sort.Strings(goarch)
		parts = append(parts, i.Path+"\x00"+strings.Join(s, ",")+
			"\x00"+strings.Join(goos, ",")+"\x00"+strings.Join(goarch, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x01")
}

// Options describes one advisory-feed source. Exactly one of LocalPath
// (offline dump) or BaseURL (remote OSV-layout source) must be set; the
// zero value disables the feed entirely.
type Options struct {
	// LocalPath is an offline dump directory or zip.
	LocalPath string
	// BaseURL is a remote OSV dump source serving
	// <base>/<ecosystem>/all.zip and <base>/ecosystems.txt.
	BaseURL string
	// Ecosystem defaults to EcosystemGo when empty.
	Ecosystem string
	// CacheDir caches remote dumps; empty uses the per-user cache dir.
	CacheDir string
	// DumpTTL caps the age of a cached dump before a forced re-download;
	// zero means no age cap (freshness is then decided by the length
	// probe alone).
	DumpTTL time.Duration
	// NoProxy disables http_proxy/https_proxy handling for feed requests;
	// the default transport honours the standard environment variables.
	NoProxy bool
	// Client injects the HTTP client (tests); nil builds the default.
	Client *http.Client
	// Now overrides the clock for TTL/cache tests; nil uses time.Now.
	Now func() time.Time
}

// Outcome is the result of acquiring a feed. Feed is nil on every
// failure status; Status carries the named reason.
type Outcome struct {
	Feed   *Feed
	Status string // StatusResolved/StatusOSVMissing/StatusFeedError
	Detail string
	Prov   Prov
	// Dump is the exact archive bytes the feed was indexed from when a
	// remote source resolved a zip dump. Corpus enumeration re-enumerates
	// those bytes with tolerant per-document reporting; the existing
	// research lane ignores it.
	Dump []byte
	// CacheFallback marks a remote acquisition served from the validated
	// local cache after the source failed — the cached CheckedAt is kept
	// verbatim so provenance shows the real age of the data.
	CacheFallback bool
}

// Acquire resolves Options into an opened feed: a local dump is indexed
// directly, a remote source goes through the cached fetch path.
func Acquire(ctx context.Context, o Options) (Outcome, error) {
	switch {
	case o.LocalPath != "" && o.BaseURL != "":
		return Outcome{}, fmt.Errorf("advisory feed: LocalPath and BaseURL are mutually exclusive")
	case o.LocalPath == "" && o.BaseURL == "":
		return Outcome{}, fmt.Errorf("advisory feed: no source configured")
	}
	if o.LocalPath != "" {
		f, err := Open(o.LocalPath)
		if err != nil {
			return Outcome{Status: StatusFeedError, Detail: err.Error()}, nil
		}
		return Outcome{Feed: f, Status: StatusResolved, Prov: f.Prov}, nil
	}
	return fetchRemote(ctx, o)
}

// sanitizeURL strips userinfo, query and fragment so the recorded feed
// reference can never carry credential material.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
