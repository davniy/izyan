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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/repository"
	"github.com/davniy/izyan/internal/vulnerability"
)

// Relationship is one of the three independent corpus indexes. Related ids
// are never stored in the alias index: relatedness is a discovery lead, while
// an alias supports identity.
type Relationship string

const (
	RelationshipRecord  Relationship = "record"
	RelationshipAlias   Relationship = "alias"
	RelationshipRelated Relationship = "related"
)

func (r Relationship) kind() (domain.RelationKind, bool) {
	switch r {
	case RelationshipRecord:
		return domain.RelationRecord, true
	case RelationshipAlias:
		return domain.RelationAlias, true
	case RelationshipRelated:
		return domain.RelationRelated, true
	default:
		return "", false
	}
}

// CorpusOptions describes one pinned advisory corpus. Feed is the configured
// source (a local dump directory/zip or a remote OSV-layout source). The
// declaration is the operator-declared corpus identity; the observed manifest
// remains a separate, evidence-only record. Selections choose exact bytes when
// one record id appears with conflicting documents.
type CorpusOptions struct {
	Feed        Options
	Declaration *domain.CorpusDeclaration
	Selections  []domain.RecordPin
}

// Corpus is an enumerated advisory corpus with three separate indexes, the
// pinned document bytes and the observed manifest. It answers discovery
// questions only: it never loads an assessment or transfers facts between
// records.
type Corpus struct {
	manifest    domain.CorpusManifest
	reference   *domain.CorpusReference
	documents   []corpusDocument
	byPin       map[pinKey]int
	recordIndex map[string][]int
	aliasIndex  map[string][]int
	relatedIdx  map[string][]int
	selections  map[string]domain.RecordPin
	// limitations carries acquisition evidence that must remain visible to
	// discovery consumers (a declared/observed digest mismatch or a cache
	// fallback).
	limitations     []string
	selectionMisses []string
}

type pinKey struct {
	recordID string
	digest   string
}

type corpusDocument struct {
	pin      domain.RecordPin
	raw      []byte
	id       string
	aliases  []string
	related  []string
	parseErr error
}

type corpusDocShape struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Related  []string `json:"related"`
	Modified string   `json:"modified"`
}

type corpusEnumeration struct {
	digest    string // raw hex, no "sha256:" prefix
	documents []corpusDocument
	problems  []domain.CorpusProblem
	source    domain.CorpusSource
	detail    string
	available bool
}

var (
	emptyDigest       string
	cveDiscoveryID    = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	corpusMaxDocBytes = int64(maxDocBytes)
)

func init() {
	sum := sha256.Sum256(nil)
	emptyDigest = "sha256:" + hex.EncodeToString(sum[:])
}

// AcquireCorpus enumerates the configured corpus and pins every document.
//
// An absent source or a source that cannot be read is not a Go error: it is an
// explicit discovery capability outcome (not_configured / unavailable) carried
// by the manifest and by RelatedDiscovery.Limitations, so a caller cannot
// mistake "not searched" for "nothing found". Invalid operator input (a
// malformed declaration, a malformed or contradictory selection, mutually
// exclusive feed options) is returned as an error.
func AcquireCorpus(ctx context.Context, o CorpusOptions) (*Corpus, error) {
	now := o.Feed.now()
	var declaration *domain.CorpusDeclaration
	if o.Declaration != nil {
		d := *o.Declaration
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("corpus declaration: %w", err)
		}
		declaration = &d
	}
	if err := validateSelections(o.Selections); err != nil {
		return nil, err
	}
	feed := o.Feed
	switch {
	case feed.LocalPath == "" && feed.BaseURL == "":
		c := newCorpus(declaration, now)
		c.manifest.Enumeration = domain.DiscoveryNotConfigured
		c.manifest.Problems = []domain.CorpusProblem{{Problem: "no advisory corpus source is configured"}}
		c.limitations = append(c.limitations, "no advisory corpus source is configured")
		return c, nil
	case feed.LocalPath != "" && feed.BaseURL != "":
		return nil, fmt.Errorf("advisory corpus: LocalPath and BaseURL are mutually exclusive")
	case feed.LocalPath != "":
		return acquireLocalCorpus(declaration, o.Selections, feed, now)
	default:
		return acquireRemoteCorpus(ctx, declaration, o.Selections, feed, now)
	}
}

func newCorpus(declaration *domain.CorpusDeclaration, now time.Time) *Corpus {
	reference := "advisory corpus"
	if declaration != nil {
		reference = declaration.Reference
	}
	return &Corpus{
		manifest: domain.CorpusManifest{
			Reference:      reference,
			CapturedAt:     now.UTC().Format(time.RFC3339),
			ObservedDigest: emptyDigest,
			Enumeration:    domain.DiscoveryUnavailable,
		},
		byPin:       map[pinKey]int{},
		recordIndex: map[string][]int{},
		aliasIndex:  map[string][]int{},
		relatedIdx:  map[string][]int{},
		selections:  map[string]domain.RecordPin{},
	}
}

func validateSelections(selections []domain.RecordPin) error {
	digests := map[string]string{}
	for _, pin := range selections {
		if err := pin.Validate(); err != nil {
			return fmt.Errorf("corpus selection: %w", err)
		}
		if previous, ok := digests[pin.RecordID]; ok && previous != pin.DocumentDigest {
			return fmt.Errorf("corpus selection: record %s is selected with two different document digests (%s and %s)",
				pin.RecordID, previous, pin.DocumentDigest)
		}
		digests[pin.RecordID] = pin.DocumentDigest
	}
	return nil
}

func acquireLocalCorpus(declaration *domain.CorpusDeclaration, selections []domain.RecordPin, feed Options, now time.Time) (*Corpus, error) {
	ref := repository.ProvenanceLocalRef(feed.LocalPath)
	st, err := os.Stat(feed.LocalPath)
	if err != nil {
		return unavailableCorpus(declaration, ref, now, fmt.Sprintf("read advisory corpus %s: %v", ref, err)), nil
	}
	var enumeration corpusEnumeration
	if st.IsDir() {
		enumeration = enumerateDirectory(feed.LocalPath, now)
	} else {
		enumeration = enumerateZipFile(feed.LocalPath, ref, now)
	}
	return buildCorpus(declaration, enumeration, selections, ref, now), nil
}

func acquireRemoteCorpus(ctx context.Context, declaration *domain.CorpusDeclaration, selections []domain.RecordPin, feed Options, now time.Time) (*Corpus, error) {
	outcome, err := Acquire(ctx, feed)
	if err != nil {
		return nil, fmt.Errorf("advisory corpus: %w", err)
	}
	ref := outcome.Prov.Ref
	if ref == "" {
		ref = sanitizeURL(feed.BaseURL)
	}
	if ref == "" {
		ref = "advisory corpus source"
	}
	switch {
	case outcome.Status != StatusResolved || len(outcome.Dump) == 0:
		detail := outcome.Detail
		if detail == "" {
			detail = "the configured source did not supply a readable dump"
		}
		return unavailableCorpus(declaration, ref, now, detail), nil
	}
	digest := sha256Hex(outcome.Dump)
	if outcome.Prov.SHA256 != "" && outcome.Prov.SHA256 != digest {
		return unavailableCorpus(declaration, ref, now,
			fmt.Sprintf("downloaded dump digest %s does not match the acquisition provenance %s",
				"sha256:"+digest, outcome.Prov.SHA256)), nil
	}
	locator := strings.TrimRight(ref, "/") + "/" + feed.ecosystem() + "/all.zip"
	enumeration := enumerateZip(outcome.Dump, locator, now)
	enumeration.source = domain.CorpusSource{
		Ref:       ref,
		SHA256:    digest,
		CheckedAt: now.UTC().Format(time.RFC3339),
	}
	if declared := outcome.Prov.CheckedAt; !declared.IsZero() {
		enumeration.source.CheckedAt = declared.UTC().Format(time.RFC3339)
	}
	if outcome.CacheFallback && outcome.Detail != "" {
		enumeration.detail = "advisory corpus served from the verified local cache after the source failed: " + outcome.Detail
	}
	return buildCorpus(declaration, enumeration, selections, ref, now), nil
}

func unavailableCorpus(declaration *domain.CorpusDeclaration, ref string, now time.Time, detail string) *Corpus {
	c := newCorpus(declaration, now)
	c.manifest.Reference = ref
	if declaration != nil {
		c.manifest.Reference = declaration.Reference
	}
	c.manifest.Enumeration = domain.DiscoveryUnavailable
	c.manifest.Problems = []domain.CorpusProblem{{Locator: ref, Problem: detail}}
	c.limitations = append(c.limitations, detail)
	return c
}

func enumerateDirectory(root string, now time.Time) corpusEnumeration {
	var (
		documents []corpusDocument
		problems  []domain.CorpusProblem
		members   []string
	)
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = entryName(entry, path)
		}
		locator := "corpus/" + filepath.ToSlash(rel)
		if err != nil {
			problems = append(problems, domain.CorpusProblem{Locator: locator, Problem: err.Error()})
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			return nil
		}
		body, readErr := readCappedFile(path, corpusMaxDocBytes)
		if readErr != nil {
			problems = append(problems, domain.CorpusProblem{Locator: locator, Problem: readErr.Error()})
			return nil
		}
		members = append(members, rel+":"+sha256Hex(body))
		doc, problem := corpusDocumentFromBytes(body, locator)
		if problem != nil {
			problems = append(problems, *problem)
		}
		if doc != nil {
			documents = append(documents, *doc)
		}
		return nil
	})
	if walkErr != nil {
		problems = append(problems, domain.CorpusProblem{Locator: repository.ProvenanceLocalRef(root), Problem: walkErr.Error()})
	}
	sort.Strings(members)
	sum := sha256.Sum256([]byte(strings.Join(members, "\n")))
	return corpusEnumeration{
		digest:    hex.EncodeToString(sum[:]),
		documents: documents,
		problems:  problems,
		source: domain.CorpusSource{
			Ref:       repository.ProvenanceLocalRef(root),
			SHA256:    hex.EncodeToString(sum[:]),
			CheckedAt: now.UTC().Format(time.RFC3339),
		},
		available: true,
	}
}

func enumerateZipFile(path, ref string, now time.Time) corpusEnumeration {
	body, err := readCappedFile(path, maxDownloadBytes)
	if err != nil {
		return corpusEnumeration{
			problems: []domain.CorpusProblem{{Locator: ref, Problem: fmt.Sprintf("read advisory corpus: %v", err)}},
			source:   domain.CorpusSource{Ref: ref, CheckedAt: now.UTC().Format(time.RFC3339)},
		}
	}
	enumeration := enumerateZip(body, ref, now)
	if !enumeration.available && len(enumeration.problems) == 0 {
		enumeration.problems = []domain.CorpusProblem{{Locator: ref, Problem: "not a readable zip archive"}}
	}
	return enumeration
}

func enumerateZip(body []byte, locatorPrefix string, now time.Time) corpusEnumeration {
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	enumeration := corpusEnumeration{
		digest: digest,
		source: domain.CorpusSource{
			Ref:       locatorPrefix,
			SHA256:    digest,
			CheckedAt: now.UTC().Format(time.RFC3339),
		},
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		enumeration.problems = append(enumeration.problems, domain.CorpusProblem{
			Locator: locatorPrefix,
			Problem: "not a readable zip archive: " + err.Error(),
		})
		return enumeration
	}
	members := append([]*zip.File(nil), reader.File...)
	sort.SliceStable(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	for _, member := range members {
		if member.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(member.Name), ".json") {
			continue
		}
		locator := locatorPrefix + "#" + member.Name
		if int64(member.UncompressedSize64) > corpusMaxDocBytes {
			enumeration.problems = append(enumeration.problems, domain.CorpusProblem{
				Locator: locator,
				Problem: fmt.Sprintf("document declares %d bytes, above the %d byte cap", member.UncompressedSize64, corpusMaxDocBytes),
			})
			continue
		}
		rc, openErr := member.Open()
		if openErr != nil {
			enumeration.problems = append(enumeration.problems, domain.CorpusProblem{
				Locator: locator, Problem: openErr.Error(),
			})
			continue
		}
		docBody, readErr := io.ReadAll(io.LimitReader(rc, corpusMaxDocBytes+1))
		rc.Close()
		if readErr != nil {
			enumeration.problems = append(enumeration.problems, domain.CorpusProblem{
				Locator: locator, Problem: readErr.Error(),
			})
			continue
		}
		if int64(len(docBody)) > corpusMaxDocBytes {
			enumeration.problems = append(enumeration.problems, domain.CorpusProblem{
				Locator: locator,
				Problem: fmt.Sprintf("document exceeds the %d byte cap", corpusMaxDocBytes),
			})
			continue
		}
		doc, problem := corpusDocumentFromBytes(docBody, locator)
		if problem != nil {
			enumeration.problems = append(enumeration.problems, *problem)
		}
		if doc != nil {
			enumeration.documents = append(enumeration.documents, *doc)
		}
	}
	enumeration.available = true
	return enumeration
}

// corpusDocumentFromBytes indexes one document. The lightweight shape decides
// whether the document names a record at all; the full exact-bytes parse then
// decides whether that record decodes. A document that names a record but does
// not decode is retained with its pin so discovery can expose it as
// load_failed.
func corpusDocumentFromBytes(body []byte, locator string) (*corpusDocument, *domain.CorpusProblem) {
	var shape corpusDocShape
	if err := json.Unmarshal(body, &shape); err != nil {
		return nil, &domain.CorpusProblem{Locator: locator, Problem: "decode OSV document: " + err.Error()}
	}
	if strings.TrimSpace(shape.ID) == "" {
		return nil, &domain.CorpusProblem{Locator: locator, Problem: "document declares no OSV record id"}
	}
	digest := "sha256:" + sha256Hex(body)
	var parseErr error
	if _, parsedDigest, err := vulnerability.ParseOSV(body); err != nil {
		parseErr = err
	} else if parsedDigest != digest {
		parseErr = fmt.Errorf("document digest %s disagrees with its parsed digest %s", digest, parsedDigest)
	}
	doc := &corpusDocument{
		pin: domain.RecordPin{
			RecordID:       shape.ID,
			DocumentDigest: digest,
			SourceLocator:  locator,
			Modified:       shape.Modified,
		},
		raw:      body,
		id:       shape.ID,
		aliases:  cleanCorpusIDs(shape.Aliases, shape.ID),
		related:  cleanCorpusIDs(shape.Related, shape.ID),
		parseErr: parseErr,
	}
	if parseErr != nil {
		return doc, &domain.CorpusProblem{
			Locator: locator, RecordID: shape.ID, Problem: "decode OSV document: " + parseErr.Error(),
		}
	}
	return doc, nil
}

func cleanCorpusIDs(ids []string, own string) []string {
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || id == own || contains(out, id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

func buildCorpus(declaration *domain.CorpusDeclaration, enumeration corpusEnumeration, selections []domain.RecordPin, ref string, now time.Time) *Corpus {
	c := newCorpus(declaration, now)
	if enumRef := enumeration.source.Ref; enumRef != "" {
		ref = enumRef
	}
	if declaration != nil {
		ref = declaration.Reference
	}
	c.manifest.Reference = ref
	if enumeration.digest != "" {
		c.manifest.ObservedDigest = "sha256:" + enumeration.digest
	}
	c.manifest.Problems = append([]domain.CorpusProblem(nil), enumeration.problems...)

	// Identical ID/digest documents deduplicate. The lexicographically first
	// locator wins; the pin ignores the locator for identity anyway.
	sort.SliceStable(enumeration.documents, func(i, j int) bool {
		if enumeration.documents[i].pin.RecordID != enumeration.documents[j].pin.RecordID {
			return enumeration.documents[i].pin.RecordID < enumeration.documents[j].pin.RecordID
		}
		if enumeration.documents[i].pin.DocumentDigest != enumeration.documents[j].pin.DocumentDigest {
			return enumeration.documents[i].pin.DocumentDigest < enumeration.documents[j].pin.DocumentDigest
		}
		return enumeration.documents[i].pin.SourceLocator < enumeration.documents[j].pin.SourceLocator
	})
	for _, doc := range enumeration.documents {
		key := pinKey{recordID: doc.pin.RecordID, digest: doc.pin.DocumentDigest}
		if _, ok := c.byPin[key]; ok {
			continue
		}
		c.byPin[key] = len(c.documents)
		c.documents = append(c.documents, doc)
	}
	if len(c.documents) == 0 && len(c.manifest.Problems) == 0 {
		c.manifest.Problems = append(c.manifest.Problems, domain.CorpusProblem{
			Locator: ref, Problem: "the corpus contains no OSV documents",
		})
	}
	switch {
	case !enumeration.available:
		c.manifest.Enumeration = domain.DiscoveryUnavailable
	case len(c.manifest.Problems) == 0 && len(c.documents) > 0:
		c.manifest.Enumeration = domain.DiscoveryFinished
	default:
		c.manifest.Enumeration = domain.DiscoveryPartial
	}
	if enumeration.source.Ref != "" {
		c.manifest.Sources = append(c.manifest.Sources, enumeration.source)
	}
	for i := range c.documents {
		doc := &c.documents[i]
		c.recordIndex[doc.id] = append(c.recordIndex[doc.id], i)
		for _, alias := range doc.aliases {
			c.aliasIndex[alias] = append(c.aliasIndex[alias], i)
		}
		for _, related := range doc.related {
			c.relatedIdx[related] = append(c.relatedIdx[related], i)
		}
	}
	c.manifest.Documents = make([]domain.RecordPin, 0, len(c.documents))
	for _, doc := range c.documents {
		c.manifest.Documents = append(c.manifest.Documents, doc.pin)
	}
	if c.manifest.Enumeration == domain.DiscoveryFinished || c.manifest.Enumeration == domain.DiscoveryPartial {
		reference := &domain.CorpusReference{
			Reference:  c.manifest.Reference,
			Digest:     c.manifest.ObservedDigest,
			CapturedAt: c.manifest.CapturedAt,
		}
		if declaration != nil {
			reference.CapturedAt = declaration.CapturedAt
		}
		c.reference = reference
	}
	if declaration != nil && declaration.ExpectedDigest != c.manifest.ObservedDigest {
		c.limitations = append(c.limitations, fmt.Sprintf(
			"declared corpus digest %s does not match the enumerated corpus digest %s; the declared corpus identity is not verified",
			declaration.ExpectedDigest, c.manifest.ObservedDigest))
	}
	if enumeration.detail != "" {
		c.limitations = append(c.limitations, enumeration.detail)
	}
	for _, pin := range selections {
		if _, ok := c.byPin[pinKey{recordID: pin.RecordID, digest: pin.DocumentDigest}]; !ok {
			c.selectionMisses = append(c.selectionMisses, fmt.Sprintf(
				"configured selection %s (%s) does not match an enumerated document",
				pin.RecordID, pin.DocumentDigest))
			continue
		}
		c.selections[pin.RecordID] = pin
	}
	return c
}

// Manifest returns the observed corpus manifest. Slices are copied so a
// consumer cannot mutate the corpus record.
func (c *Corpus) Manifest() domain.CorpusManifest {
	manifest := c.manifest
	manifest.Sources = append([]domain.CorpusSource(nil), c.manifest.Sources...)
	manifest.Documents = append([]domain.RecordPin(nil), c.manifest.Documents...)
	manifest.Problems = append([]domain.CorpusProblem(nil), c.manifest.Problems...)
	return manifest
}

// Lookup returns every pinned document the requested independent index
// reaches. Related lookups never consult the alias index and vice versa.
func (c *Corpus) Lookup(kind Relationship, id string) []domain.RecordPin {
	relation, ok := kind.kind()
	if !ok || id == "" {
		return nil
	}
	var index map[string][]int
	switch relation {
	case domain.RelationRecord:
		index = c.recordIndex
	case domain.RelationAlias:
		index = c.aliasIndex
	case domain.RelationRelated:
		index = c.relatedIdx
	}
	pins := make([]domain.RecordPin, 0, len(index[id]))
	seen := map[pinKey]bool{}
	for _, n := range index[id] {
		pin := c.documents[n].pin
		key := pinKey{recordID: pin.RecordID, digest: pin.DocumentDigest}
		if seen[key] {
			continue
		}
		seen[key] = true
		pins = append(pins, pin)
	}
	sort.SliceStable(pins, func(i, j int) bool {
		if pins[i].DocumentDigest != pins[j].DocumentDigest {
			return pins[i].DocumentDigest < pins[j].DocumentDigest
		}
		return pins[i].SourceLocator < pins[j].SourceLocator
	})
	return pins
}

// Document loads the exact bytes of one pinned document. The pin must name a
// document this corpus enumerated; a pin for other bytes is rejected rather
// than resolved from another source.
func (c *Corpus) Document(ctx context.Context, pin domain.RecordPin) (vulnerability.LoadedRecord, error) {
	_ = ctx
	if err := pin.Validate(); err != nil {
		return vulnerability.LoadedRecord{}, err
	}
	index, ok := c.byPin[pinKey{recordID: pin.RecordID, digest: pin.DocumentDigest}]
	if !ok {
		return vulnerability.LoadedRecord{}, fmt.Errorf(
			"corpus: record %s with document digest %s is not pinned by this corpus",
			pin.RecordID, pin.DocumentDigest)
	}
	doc := c.documents[index]
	raw := append([]byte(nil), doc.raw...)
	return vulnerability.LoadExactBytes(raw, doc.pin.RecordID, doc.pin.SourceLocator)
}

// Discover nominates pinned records that the request and the primary record
// directly name. It performs the mandatory inverse lookup: a record whose own
// related entry names the requested CVE is discovered even when the primary
// record has no outgoing link to it.
//
// Only direct matches are returned: own-id, alias and related hits for the
// explicit CVE seeds, plus the primary record's direct neighbors. No transitive
// related closure is applied, and no candidate receives applicability,
// attribution or exploitability authority.
func (c *Corpus) Discover(requestID string, primary *vulnerability.LoadedRecord) domain.RelatedDiscovery {
	discovery := domain.RelatedDiscovery{
		RequestedID: strings.TrimSpace(requestID),
		Enumeration: c.manifest.Enumeration,
	}
	if c.reference != nil {
		reference := *c.reference
		discovery.Corpus = &reference
	}
	discovery.Limitations = append(discovery.Limitations,
		"discovery nominates records only: it transfers no CVE attribution, applicability or exploitability; every candidate needs its own admitted evidence")

	switch c.manifest.Enumeration {
	case domain.DiscoveryNotConfigured:
		discovery.Limitations = append(discovery.Limitations,
			"no advisory corpus is configured; no CVE discovery was performed")
		return discovery
	case domain.DiscoveryUnavailable:
		discovery.Limitations = append(discovery.Limitations,
			"the configured advisory corpus could not be enumerated")
		if details := corpusProblemLimitations(c.manifest.Problems); len(details) > 0 {
			discovery.Limitations = append(discovery.Limitations, details...)
		} else {
			discovery.Limitations = append(discovery.Limitations, c.limitations...)
		}
		return discovery
	case domain.DiscoveryPartial:
		discovery.Limitations = append(discovery.Limitations, fmt.Sprintf(
			"corpus enumeration is partial: %d read/decode problem(s); nominated candidates may be incomplete",
			len(c.manifest.Problems)))
		discovery.Limitations = append(discovery.Limitations, corpusProblemLimitations(c.manifest.Problems)...)
	}
	discovery.Limitations = append(discovery.Limitations, c.limitations...)
	for _, miss := range c.selectionMisses {
		discovery.Limitations = append(discovery.Limitations, miss)
	}
	discovery.Limitations = append(discovery.Limitations,
		"discovery matches direct own ids, aliases, related entries and direct primary neighbors only; no transitive related closure was applied")

	seeds, neighbors := discoverySeeds(requestID, primary)
	if len(seeds) == 0 && len(neighbors) == 0 {
		discovery.Limitations = append(discovery.Limitations,
			"the request and the primary record name no CVE or direct neighbor id; no discovery query was performed")
		return discovery
	}

	nominations := map[int]map[domain.DiscoveryEdge]bool{}
	addEdge := func(docIndex int, edge domain.DiscoveryEdge) {
		if primary != nil && primary.Pin.Same(c.documents[docIndex].pin) {
			return
		}
		if nominations[docIndex] == nil {
			nominations[docIndex] = map[domain.DiscoveryEdge]bool{}
		}
		nominations[docIndex][edge] = true
	}
	for _, seed := range seeds {
		for _, kind := range []domain.RelationKind{domain.RelationRecord, domain.RelationAlias, domain.RelationRelated} {
			for _, docIndex := range c.indexFor(kind, seed.id) {
				addEdge(docIndex, domain.DiscoveryEdge{Kind: kind, ID: seed.id, FromID: c.documents[docIndex].id})
				if seed.from != "" {
					addEdge(docIndex, domain.DiscoveryEdge{Kind: seed.kind, ID: seed.id, FromID: seed.from})
				}
			}
		}
	}
	for _, neighbor := range neighbors {
		for _, kind := range []domain.RelationKind{domain.RelationRecord, domain.RelationAlias} {
			for _, docIndex := range c.indexFor(kind, neighbor.id) {
				addEdge(docIndex, domain.DiscoveryEdge{Kind: kind, ID: neighbor.id, FromID: c.documents[docIndex].id})
				addEdge(docIndex, domain.DiscoveryEdge{Kind: neighbor.kind, ID: neighbor.id, FromID: neighbor.from})
			}
		}
	}

	if len(nominations) == 0 {
		discovery.Limitations = append(discovery.Limitations, c.noCandidateLimitation(seeds, neighbors))
		return discovery
	}

	byRecordID := map[string][]int{}
	for docIndex := range nominations {
		id := c.documents[docIndex].id
		byRecordID[id] = append(byRecordID[id], docIndex)
	}
	recordIDs := make([]string, 0, len(byRecordID))
	for id := range byRecordID {
		recordIDs = append(recordIDs, id)
	}
	sort.Strings(recordIDs)
	for _, id := range recordIDs {
		indexes := byRecordID[id]
		sort.SliceStable(indexes, func(i, j int) bool {
			left, right := c.documents[indexes[i]].pin, c.documents[indexes[j]].pin
			if left.DocumentDigest != right.DocumentDigest {
				return left.DocumentDigest < right.DocumentDigest
			}
			return left.SourceLocator < right.SourceLocator
		})
		selected, hasSelection := c.selections[id]
		if hasSelection {
			filtered := indexes[:0]
			for _, docIndex := range indexes {
				if c.documents[docIndex].pin.Same(selected) {
					filtered = append(filtered, docIndex)
				}
			}
			indexes = filtered
			if len(indexes) == 0 {
				discovery.Limitations = append(discovery.Limitations, fmt.Sprintf(
					"configured selection %s (%s) was not nominated by the request seeds or direct neighbors",
					selected.RecordID, selected.DocumentDigest))
			}
		}
		versions := map[string]bool{}
		for _, docIndex := range indexes {
			versions[c.documents[docIndex].pin.DocumentDigest] = true
		}
		primaryConflict := false
		if !hasSelection && primary != nil && primary.Pin.RecordID == id {
			if !versions[primary.Pin.DocumentDigest] {
				primaryConflict = true
			}
		}
		conflict := len(versions) > 1 || primaryConflict
		for _, docIndex := range indexes {
			doc := c.documents[docIndex]
			candidate := domain.DiscoveryCandidate{
				Record: doc.pin,
				Edges:  sortedDiscoveryEdges(nominations[docIndex]),
			}
			switch {
			case conflict:
				candidate.Disposition = domain.DispositionAmbiguous
				count := len(versions)
				if primaryConflict {
					count++
				}
				candidate.Note = fmt.Sprintf(
					"%d distinct documents share record id %s; no configured selection chooses the exact bytes",
					count, id)
				if doc.parseErr != nil {
					candidate.Note += "; one version also failed to decode: " + doc.parseErr.Error()
				}
			case doc.parseErr != nil:
				candidate.Disposition = domain.DispositionLoadFailed
				candidate.Note = doc.parseErr.Error()
			default:
				candidate.Disposition = domain.DispositionNotEvaluated
			}
			discovery.Candidates = append(discovery.Candidates, candidate)
		}
		if conflict && !hasSelection {
			discovery.Limitations = append(discovery.Limitations, fmt.Sprintf(
				"record %s has %d conflicting document version(s); the candidate stays ambiguous until an exact source selection is configured",
				id, len(versions)+boolCount(primaryConflict)))
		}
	}
	sort.SliceStable(discovery.Candidates, func(i, j int) bool {
		left, right := discovery.Candidates[i].Record, discovery.Candidates[j].Record
		if left.RecordID != right.RecordID {
			return left.RecordID < right.RecordID
		}
		return left.DocumentDigest < right.DocumentDigest
	})
	if len(discovery.Candidates) == 0 {
		discovery.Limitations = append(discovery.Limitations, c.noCandidateLimitation(seeds, neighbors))
	}
	return discovery
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

type discoverySeed struct {
	id   string
	kind domain.RelationKind
	from string
}

type discoveryNeighbor struct {
	id   string
	kind domain.RelationKind
	from string
}

func discoverySeeds(requestID string, primary *vulnerability.LoadedRecord) ([]discoverySeed, []discoveryNeighbor) {
	var seeds []discoverySeed
	var neighbors []discoveryNeighbor
	seedSeen := map[string]bool{}
	neighborSeen := map[string]bool{}
	addSeed := func(id string, kind domain.RelationKind, from string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		key := string(kind) + "\x00" + id + "\x00" + from
		if seedSeen[key] {
			return
		}
		seedSeen[key] = true
		seeds = append(seeds, discoverySeed{id: id, kind: kind, from: from})
	}
	addNeighbor := func(id string, kind domain.RelationKind, from string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		key := string(kind) + "\x00" + id + "\x00" + from
		if neighborSeen[key] {
			return
		}
		neighborSeen[key] = true
		neighbors = append(neighbors, discoveryNeighbor{id: id, kind: kind, from: from})
	}
	requestIsCVE := isDiscoveryCVE(requestID)
	if requestIsCVE {
		// A CVE request nominates records whose own id, aliases or direct
		// related entries name that CVE, plus direct primary neighbors.
		addSeed(canonicalDiscoveryID(requestID), domain.RelationRecord, "")
	}
	if primary != nil && primary.Vuln != nil {
		record := primary.Vuln
		if !requestIsCVE {
			// An exact request retains every CVE the primary record
			// explicitly names, together with the field that carried it.
			if isDiscoveryCVE(record.ID) {
				addSeed(canonicalDiscoveryID(record.ID), domain.RelationRecord, record.ID)
			}
			for _, alias := range record.Aliases {
				if isDiscoveryCVE(alias) {
					addSeed(canonicalDiscoveryID(alias), domain.RelationAlias, record.ID)
					continue
				}
				addNeighbor(alias, domain.RelationAlias, record.ID)
			}
			for _, related := range record.Related {
				if isDiscoveryCVE(related) {
					addSeed(canonicalDiscoveryID(related), domain.RelationRelated, record.ID)
					continue
				}
				addNeighbor(related, domain.RelationRelated, record.ID)
			}
		} else {
			// A CVE request uses only the requested CVE as a shared-key
			// seed. The primary's other ids are direct neighbors, and their
			// own related entries are not expanded: no transitive closure.
			for _, alias := range record.Aliases {
				addNeighbor(alias, domain.RelationAlias, record.ID)
			}
			for _, related := range record.Related {
				addNeighbor(related, domain.RelationRelated, record.ID)
			}
		}
		addNeighbor(record.ID, domain.RelationRecord, record.ID)
	}
	return seeds, neighbors
}

func isDiscoveryCVE(id string) bool {
	return cveDiscoveryID.MatchString(canonicalDiscoveryID(id))
}

func canonicalDiscoveryID(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return strings.ToUpper(id)
	}
	return id
}

func (c *Corpus) indexFor(kind domain.RelationKind, id string) []int {
	switch kind {
	case domain.RelationRecord:
		return c.recordIndex[id]
	case domain.RelationAlias:
		return c.aliasIndex[id]
	case domain.RelationRelated:
		return c.relatedIdx[id]
	default:
		return nil
	}
}

func sortedDiscoveryEdges(edges map[domain.DiscoveryEdge]bool) []domain.DiscoveryEdge {
	out := make([]domain.DiscoveryEdge, 0, len(edges))
	for edge := range edges {
		out = append(out, edge)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].FromID < out[j].FromID
	})
	return out
}

func corpusProblemLimitations(problems []domain.CorpusProblem) []string {
	out := make([]string, 0, len(problems))
	for _, problem := range problems {
		locator := problem.Locator
		if strings.TrimSpace(locator) == "" {
			locator = "corpus"
		}
		record := ""
		if problem.RecordID != "" {
			record = " (" + problem.RecordID + ")"
		}
		out = append(out, fmt.Sprintf("corpus problem at %s%s: %s", locator, record, problem.Problem))
	}
	return out
}

func (c *Corpus) noCandidateLimitation(seeds []discoverySeed, neighbors []discoveryNeighbor) string {
	if len(seeds) > 0 {
		ids := make([]string, 0, len(seeds))
		for _, seed := range seeds {
			if !contains(ids, seed.id) {
				ids = append(ids, seed.id)
			}
		}
		return fmt.Sprintf(
			"the enumerated corpus has no record whose own id, aliases or related entries name %s; this does not establish that no implementation is affected",
			strings.Join(ids, ", "))
	}
	ids := make([]string, 0, len(neighbors))
	for _, neighbor := range neighbors {
		if !contains(ids, neighbor.id) {
			ids = append(ids, neighbor.id)
		}
	}
	return fmt.Sprintf(
		"the enumerated corpus has no record for the direct neighbor ids %s; this does not establish that no implementation is affected",
		strings.Join(ids, ", "))
}

func readCappedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("document exceeds the %d byte cap", limit)
	}
	return body, nil
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func contains(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func entryName(entry fs.DirEntry, path string) string {
	if entry != nil {
		return entry.Name()
	}
	return filepath.Base(path)
}
