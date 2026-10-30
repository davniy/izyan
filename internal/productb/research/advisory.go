package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
)

// goAffectedRef is one comparable advisory affected entry — a Go module
// with its version data — together with the document it was read from.
// The consistency layer compares these against the snapshot's module
// graph; affected entries without a Go module name (e.g. CPE/GIT entries
// of a CVE-centric document) are never comparable and are only counted.
type goAffectedRef struct {
	am  pbdomain.AffectedModule
	doc AdvisoryDocument
}

// advisoryResult bundles what advisory resolution yields: the report
// info, the comparable Go affected entries (each bound to its source
// document), host facts, recorded gaps and the audit trail.
type advisoryResult struct {
	info         AdvisoryInfo
	affected     []goAffectedRef
	uncomparable int      // raw affected[] entries with no Go module name
	details      string   // advisory details/description text (mechanism reference)
	detailsSrc   string   // id of the document the details were taken from
	cwes         []string // frozen CWE ids from the parsed documents
	primaryDoc   AdvisoryDocument
	ecoDocs      []AdvisoryDocument // consulted ecosystem documents
	searchDir    string             // directory for local alias lookups ("" = none)
	facts        []Fact
	unknowns     []string
	audit        []pbdomain.ToolExecution
}

// resolveAdvisory obtains the advisory for the CVE from --advisory
// (file/dir of OSV documents) or an OSV-compatible API. Advisory absence
// is a recorded gap, never a fatal error: the agent only ever receives
// the CVE id, so research can proceed without the document. A resolved
// document's original bytes are always stored under <runDir>/advisory/ —
// the dossier carries the document itself, not only its digest.
func resolveAdvisory(ctx context.Context, o Options, runDir string) advisoryResult {
	var res advisoryResult

	fail := func(status, reason string, extra ...pbdomain.ToolExecution) advisoryResult {
		res.unknowns = append(res.unknowns, "advisory: "+reason)
		res.info = AdvisoryInfo{Status: status, Reason: reason}
		res.audit = append(res.audit, extra...)
		return res
	}

	switch {
	case o.AdvisoryPath != "":
		res = resolveLocalAdvisory(o, runDir, fail)
	case o.NoNet:
		res = fail("skipped_no_net", "--no-net: advisory fetch disabled")
	default:
		res = fetchAdvisory(ctx, o, runDir, fail)
	}
	res.enrichGoEntries(ctx, o, runDir)
	return res
}

// enrichGoEntries resolves the advisory's ecosystem view when the primary
// document declares no comparable Go affected entry — the common shape of
// CVE-centric documents whose affected[] lists CPE/GIT targets while the
// Go entries live in an alias document (GO-*, GHSA-*). The search order
// mirrors the deterministic lane's resolveMissingSymbolsFromAliases:
// sibling files of the supplied --advisory document first, the
// OSV-compatible API second (skipped under --no-net). At most three alias
// documents are consulted; every consulted document is stored in the
// dossier and listed in advisory.documents. When nothing yields a Go
// entry the consistency layer reports `advisory_uncomparable` rather than
// pretending the module graph was compared.
func (res *advisoryResult) enrichGoEntries(ctx context.Context, o Options, runDir string) {
	if res.info.Status != "resolved" || len(res.affected) > 0 || len(res.info.Aliases) == 0 {
		return
	}
	base := strings.TrimRight(o.OSVURL, "/")
	hc := &http.Client{Timeout: 30 * time.Second}

	aliases := append([]string{}, res.info.Aliases...)
	sort.SliceStable(aliases, func(i, j int) bool {
		return vulnPriority(aliases[i]) < vulnPriority(aliases[j])
	})
	attempts := 0
	for _, alias := range aliases {
		if alias == res.info.ID || attempts >= 3 {
			continue // bounded, mirrors the lane's i>=3 cap
		}
		attempts++
		doc, raw, recs, err := res.obtainAliasDocument(ctx, o, alias, runDir, base, hc)
		res.audit = append(res.audit, recs...)
		if err != nil {
			res.unknowns = append(res.unknowns,
				fmt.Sprintf("advisory alias %s could not be resolved: %v", alias, err))
			continue
		}
		res.ecoDocs = append(res.ecoDocs, doc)
		mergeGoAffected(res, doc, raw)
		res.facts = append(res.facts, Fact{
			Statement: fmt.Sprintf("ecosystem advisory %s consulted for Go affected entries (sha256 %s…)", doc.ID, doc.SHA256[:12]),
			Reference: relDisplay(doc.Path),
			Source:    "advisory",
		})
	}
	res.rebuildAffected()
}

// obtainAliasDocument locates one alias document: first as a sibling of
// the supplied --advisory file (the deterministic lane's candidate list),
// then — unless --no-net — via the OSV-compatible API. A found document
// is parsed with FileSource and copied into the run dossier so the
// report can pin id + sha256 + stored path for every entry it yields.
func (res *advisoryResult) obtainAliasDocument(ctx context.Context, o Options, alias, runDir, base string, hc *http.Client) (AdvisoryDocument, []byte, []pbdomain.ToolExecution, error) {
	if res.searchDir != "" {
		dir := res.searchDir
		candidates := []string{
			filepath.Join(dir, alias+".json"),
			filepath.Join(dir, "..", "reviewed", alias+".json"),
			filepath.Join(dir, "..", "live", alias+".json"),
			filepath.Join(dir, "..", alias+".json"),
		}
		for _, cand := range candidates {
			raw, err := os.ReadFile(cand)
			if err != nil {
				continue
			}
			v, perr := vulnerability.FileSource{Path: cand, NoAliasEnrichment: true}.Get(ctx, "")
			if perr != nil {
				return AdvisoryDocument{}, nil, nil, fmt.Errorf("sibling %s: %w", cand, perr)
			}
			dest, werr := storeAdvisoryDoc(runDir, sanitizeID(v.ID)+".json", raw)
			if werr != nil {
				return AdvisoryDocument{}, nil, nil, fmt.Errorf("cannot store sibling advisory %s: %w", cand, werr)
			}
			return AdvisoryDocument{
				Role: "ecosystem", ID: v.ID, SHA256: sha256Hex(raw),
				Path: dest, Source: "file:" + cand,
			}, raw, nil, nil
		}
	}
	if o.NoNet {
		return AdvisoryDocument{}, nil, nil, errors.New("not found beside the advisory document; network fetch disabled (--no-net)")
	}
	raw, url, recs, err := fetchOSVDoc(ctx, hc, base, alias)
	if err != nil {
		return AdvisoryDocument{}, nil, recs, err
	}
	dest, werr := storeAdvisoryDoc(runDir, sanitizeID(filepath.Base(url))+".json", raw)
	if werr != nil {
		return AdvisoryDocument{}, nil, recs, fmt.Errorf("cannot store fetched advisory %s: %w", alias, werr)
	}
	v, perr := vulnerability.FileSource{Path: dest, NoAliasEnrichment: true}.Get(ctx, "")
	if perr != nil {
		return AdvisoryDocument{}, nil, recs, fmt.Errorf("fetched alias %s does not parse: %w", alias, perr)
	}
	return AdvisoryDocument{
		Role: "ecosystem", ID: v.ID, SHA256: sha256Hex(raw),
		Path: dest, URL: url, Source: "osv:" + url,
	}, raw, recs, nil
}

// mergeGoAffected extracts the Go-ecosystem affected entries of an
// ecosystem document (parsed from its stored copy for provenance) and
// appends every module not already covered — first document wins per
// module. Returns the set of module names the document contributed.
func mergeGoAffected(res *advisoryResult, doc AdvisoryDocument, raw []byte) map[string]bool {
	contributed := map[string]bool{}
	v, err := vulnerability.FileSource{Path: doc.Path, NoAliasEnrichment: true}.Get(context.Background(), "")
	if err != nil {
		return contributed
	}
	// Keep a mechanism reference text when the primary document carries
	// none: the first consulted document with a description wins.
	if res.details == "" && v.Description != "" {
		res.details = v.Description
		res.detailsSrc = v.ID
	}
	for _, c := range v.CWE {
		if !slices.Contains(res.cwes, c) {
			res.cwes = append(res.cwes, c)
		}
	}
	goNames, _ := affectedPackageProbe(raw)
	have := map[string]bool{}
	for _, ref := range res.affected {
		have[ref.am.Module] = true
	}
	for _, am := range v.AffectedModules {
		if am.Module == "" || have[am.Module] {
			continue
		}
		if goNames != nil && !goNames[am.Module] {
			continue
		}
		have[am.Module] = true
		contributed[am.Module] = true
		res.affected = append(res.affected, goAffectedRef{am: am, doc: doc})
	}
	return contributed
}

// resolveLocalAdvisory reads --advisory: a single OSV JSON file, or a
// directory scanned for a document whose id or aliases match the CVE.
// The matched document is copied into the run dossier so the report pins
// the exact bytes it assessed — the original stays untouched.
func resolveLocalAdvisory(o Options, runDir string, fail func(string, string, ...pbdomain.ToolExecution) advisoryResult) advisoryResult {
	path := o.AdvisoryPath
	info, err := os.Stat(path)
	if err != nil {
		return fail("error", fmt.Sprintf("cannot read --advisory %s: %v", path, err))
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return fail("error", fmt.Sprintf("cannot list --advisory dir %s: %v", path, err))
		}
		names := []string{}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		var parseErrs []string
		for _, name := range names {
			fp := filepath.Join(path, name)
			v, gerr := vulnerability.FileSource{Path: fp, NoAliasEnrichment: true}.Get(context.Background(), o.CVE)
			if gerr != nil {
				parseErrs = append(parseErrs, name+": "+gerr.Error())
				continue
			}
			return advisoryFromVuln(v, fp, "file:"+fp, runDir)
		}
		reason := fmt.Sprintf("no OSV document in %s matches %s (checked %d files)", path, o.CVE, len(names))
		if len(parseErrs) > 0 && len(parseErrs) <= 5 {
			reason += "; " + strings.Join(parseErrs, "; ")
		}
		return fail("unavailable", reason)
	}
	v, err := vulnerability.FileSource{Path: path, NoAliasEnrichment: true}.Get(context.Background(), o.CVE)
	if err != nil {
		return fail("unavailable", err.Error())
	}
	return advisoryFromVuln(v, path, "file:"+path, runDir)
}

// fetchAdvisory GETs {osv-url}/v1/vulns/<id>, stores the raw document under
// <runDir>/advisory/, and parses it via FileSource for provenance. When the
// direct id is unknown to the server but the response names aliases,
// each alias is tried in the same order OSVSource would use.
func fetchAdvisory(ctx context.Context, o Options, runDir string, fail func(string, string, ...pbdomain.ToolExecution) advisoryResult) advisoryResult {
	base := strings.TrimRight(o.OSVURL, "/")
	hc := &http.Client{Timeout: 30 * time.Second}

	var audit []pbdomain.ToolExecution
	raw, url, recs, err := fetchOSVDoc(ctx, hc, base, o.CVE)
	audit = append(audit, recs...)
	if err != nil {
		var herr *osvHTTPError
		if errors.As(err, &herr) && herr.StatusCode == http.StatusNotFound {
			if alias := firstAlias(herr.Body); alias != "" {
				raw, url, recs, err = fetchOSVDoc(ctx, hc, base, alias)
				audit = append(audit, recs...)
			}
		}
		if err != nil {
			return fail("unavailable", fmt.Sprintf("osv fetch %s: %v", o.CVE, err), audit...)
		}
	}

	dest, werr := storeAdvisoryDoc(runDir, sanitizeID(filepath.Base(url))+".json", raw)
	if werr != nil {
		return fail("error", fmt.Sprintf("cannot save advisory: %v", werr), audit...)
	}

	v, perr := vulnerability.FileSource{Path: dest, NoAliasEnrichment: true}.Get(ctx, o.CVE)
	if perr != nil {
		return fail("unavailable", fmt.Sprintf("saved advisory %s does not parse/match %s: %v", dest, o.CVE, perr), audit...)
	}
	res := advisoryFromVuln(v, dest, "file:"+dest, runDir)
	res.info.DocumentURL = url
	res.info.Source = "osv:" + url
	res.primaryDoc.URL = url
	res.primaryDoc.Source = "osv:" + url
	res.audit = audit
	res.rebuildAffected()
	return res
}

// storeAdvisoryDoc writes the advisory's original bytes under
// <runDir>/advisory/<name>, creating the directory on demand.
func storeAdvisoryDoc(runDir, name string, raw []byte) (string, error) {
	dir := filepath.Join(runDir, "advisory")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, name)
	return dest, os.WriteFile(dest, raw, 0o644)
}

// osvHTTPError mirrors the OSV transport error (kept local: the package
// must not depend on vulnerability internals).
type osvHTTPError struct {
	StatusCode int
	Body       string
	URL        string
}

func (e *osvHTTPError) Error() string {
	return fmt.Sprintf("osv get %s: unexpected status %d", e.URL, e.StatusCode)
}

// fetchOSVDoc returns the raw body of GET base/v1/vulns/id plus a
// toolaudit record for the outbound request.
func fetchOSVDoc(ctx context.Context, hc *http.Client, base, id string) ([]byte, string, []pbdomain.ToolExecution, error) {
	canon := canonicalOSVID(id)
	url := base + "/v1/vulns/" + canon
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, url, nil, err
	}
	resp, err := hc.Do(req)
	rec := pbdomain.ToolExecution{
		Tool: "http-get", Dir: url,
		Args:       []string{url},
		DurationMs: time.Since(start).Milliseconds(),
	}
	if err != nil {
		rec.ExitCode, rec.Error = -1, err.Error()
		return nil, url, []pbdomain.ToolExecution{rec}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	rec.StdoutSHA256 = sha256Hex(body)
	if err != nil {
		rec.ExitCode, rec.Error = -1, err.Error()
		return nil, url, []pbdomain.ToolExecution{rec}, err
	}
	if resp.StatusCode != http.StatusOK {
		rec.ExitCode = resp.StatusCode
		rec.Error = fmt.Sprintf("status %d", resp.StatusCode)
		return nil, url, []pbdomain.ToolExecution{rec}, &osvHTTPError{StatusCode: resp.StatusCode, Body: string(body), URL: url}
	}
	rec.ExitCode = 0
	return body, url, []pbdomain.ToolExecution{rec}, nil
}

// firstAlias extracts the first alias id from an OSV 404 "aliases were:"
// error body, preferring GO-* then GHSA-* then CVE-*.
func firstAlias(body string) string {
	var resp struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &resp) != nil || !strings.Contains(resp.Message, "aliases were:") {
		return ""
	}
	parts := strings.Split(resp.Message, ":")
	aliases := strings.Fields(parts[len(parts)-1])
	if len(aliases) == 0 {
		return ""
	}
	sort.SliceStable(aliases, func(i, j int) bool {
		return vulnPriority(aliases[i]) < vulnPriority(aliases[j])
	})
	return aliases[0]
}

func vulnPriority(id string) int {
	switch up := strings.ToUpper(id); {
	case strings.HasPrefix(up, "GO-"):
		return 1
	case strings.HasPrefix(up, "GHSA-"):
		return 2
	case strings.HasPrefix(up, "CVE-"):
		return 3
	default:
		return 4
	}
}

func canonicalOSVID(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(strings.ToUpper(id), "GHSA-") && len(id) > 5 {
		return "GHSA-" + strings.ToLower(id[5:])
	}
	return id
}

// affectedPackageProbe re-reads the raw document only for
// affected[].package.{ecosystem,name}: the parsed pbdomain.Vulnerability
// merges every affected entry by package name, so the ecosystem filter
// lives in the raw document. It returns the comparable Go module names
// and the number of raw affected entries that carry no Go module name —
// those can never be checked against a Go module graph.
func affectedPackageProbe(raw []byte) (goNames map[string]bool, uncomparable int) {
	var doc struct {
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		} `json:"affected"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil, 0
	}
	goNames = map[string]bool{}
	for _, a := range doc.Affected {
		name := strings.TrimSpace(a.Package.Name)
		if (a.Package.Ecosystem == "Go" || a.Package.Ecosystem == "") && name != "" {
			goNames[name] = true
		} else {
			uncomparable++
		}
	}
	return goNames, uncomparable
}

// advisoryFromVuln builds the resolution result from a parsed document.
// The document bytes are stored inside the run dossier (unless the
// document already lives there): report.Path points at the stored copy
// so the dossier is self-contained and the SHA256 pins what was read.
// source keeps the original provenance ("file:/original/path" or
// "osv:<url>"). Only Go-ecosystem affected entries become comparable
// references for the consistency layer; other entries are counted.
func advisoryFromVuln(v *pbdomain.Vulnerability, path, source, runDir string) advisoryResult {
	b, err := os.ReadFile(path)
	if err != nil {
		return advisoryResult{
			info:     AdvisoryInfo{Status: "error", Reason: err.Error()},
			unknowns: []string{"advisory: saved document unreadable: " + err.Error()},
		}
	}
	var res advisoryResult
	stored := path
	if !insideDir(runDir, path) {
		if dest, werr := storeAdvisoryDoc(runDir, sanitizeID(v.ID)+".json", b); werr != nil {
			res.unknowns = append(res.unknowns,
				"advisory: could not store a dossier copy of "+path+": "+werr.Error())
		} else {
			stored = dest
		}
	}
	res.searchDir = filepath.Dir(path)
	sum := sha256Hex(b)
	res.primaryDoc = AdvisoryDocument{
		Role: "primary", ID: v.ID, SHA256: sum, Path: stored, Source: source,
	}
	if v.Description != "" {
		res.details = v.Description
		res.detailsSrc = v.ID
	}
	res.cwes = append(res.cwes, v.CWE...)
	adv := AdvisoryInfo{
		Status:        "resolved",
		Source:        source,
		Path:          stored,
		SHA256:        sum,
		ID:            v.ID,
		Aliases:       v.Aliases,
		Module:        v.Module,
		Package:       v.Package,
		Summary:       v.Summary,
		Modified:      v.Modified,
		FixedVersions: v.FixedVersions,
	}
	if u := v.Provenance["document"]; u != "" {
		adv.DocumentURL = u
		res.primaryDoc.URL = u
	}
	res.info = adv

	goNames, uncomparable := affectedPackageProbe(b)
	res.uncomparable = uncomparable
	for _, am := range v.AffectedModules {
		if am.Module == "" {
			continue // merged unnamed entries — already counted uncomparable
		}
		if goNames != nil && !goNames[am.Module] {
			continue // affected entry of a non-Go ecosystem (e.g. Maven, PyPI)
		}
		res.affected = append(res.affected, goAffectedRef{am: am, doc: res.primaryDoc})
	}
	res.rebuildAffected()

	res.facts = []Fact{
		{
			Statement: fmt.Sprintf("advisory %s (sha256 %s…)", v.ID, sum[:12]),
			Reference: relDisplay(stored),
			Source:    "advisory",
		},
	}
	if v.Module != "" {
		stmt := "advisory affects module " + v.Module
		if v.Package != "" {
			stmt += " package " + v.Package
		}
		res.facts = append(res.facts, Fact{Statement: stmt, Reference: relDisplay(stored), Source: "advisory"})
	}
	if len(v.Aliases) > 0 {
		res.facts = append(res.facts, Fact{
			Statement: "advisory aliases: " + strings.Join(v.Aliases, ", "),
			Reference: relDisplay(stored),
			Source:    "advisory",
		})
	}
	return res
}

// rebuildAffected syncs info.Affected/info.Documents with res.affected:
// call it after any change to the comparable-entry set or doc metadata.
func (res *advisoryResult) rebuildAffected() {
	res.info.Affected = nil
	for _, ref := range res.affected {
		entry := AffectedEntry{Module: ref.am.Module, Fixed: ref.am.FixedVersions, Document: ref.doc}
		for _, rg := range ref.am.AffectedVersions {
			entry.Ranges = append(entry.Ranges, displayRange(rg))
		}
		for _, p := range ref.am.AffectedPackages {
			entry.Packages = append(entry.Packages, p.Path)
		}
		res.info.Affected = append(res.info.Affected, entry)
	}
	res.info.Documents = []AdvisoryDocument{res.primaryDoc}
	for _, d := range res.ecoDocs {
		if d.ID != res.primaryDoc.ID {
			res.info.Documents = append(res.info.Documents, d)
		}
	}
	res.info.UncomparableEntries = res.uncomparable
}

// insideDir reports whether p sits under dir.
func insideDir(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// relDisplay shortens a path for report references (basename inside out).
func relDisplay(p string) string {
	return filepath.Base(p)
}

// sanitizeID mirrors the main package's id sanitization for file names.
func sanitizeID(id string) string {
	return strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(id)
}
