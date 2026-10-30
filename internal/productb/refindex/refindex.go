package refindex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/productb/repository"
)

// Options carries everything Build needs; the command maps its flags onto
// this struct and supplies the seams (index, patch fetcher) it resolved.
type Options struct {
	// SnapshotRoot is the analyzed product tree (required).
	SnapshotRoot string
	// Advisory selects the advisory corpus (file/dir/id + net policy).
	Advisory AdvisoryOptions
	// CaseID overrides the document's case_id; default is the selected
	// advisory's id.
	CaseID string
	// Commit records the snapshot identity (external SHA or resolved
	// git HEAD); empty means "not recorded".
	Commit string
	// Toolchain records the resolved analysis toolchain version ("1.23.x");
	// emitted as "go<version>" when non-empty.
	Toolchain string
	// GOOS/GOARCH/Tags/CGO describe the build context the checks run
	// under; empty GOOS/GOARCH fall back to the host.
	GOOS, GOARCH string
	Tags         []string
	CGO          bool
	// Symbols resolves advisory symbols to declarations; nil = locus
	// decls stay unresolved (status degrades honestly).
	Symbols SymbolLocator
	// Usage checks product usage per atom; nil = the usage check could
	// not run (strata degrade per the manifest rules).
	Usage UsageChecker
	// Patch enables the auxiliary fix-diff fetch; nil = not_attempted.
	Patch PatchFetcher
}

// Builder assembles refindex documents.
type Builder struct {
	Opts Options
}

// Build resolves the advisory, derives atoms, resolves declarations,
// classifies usage and emits the sealed document.
func (b Builder) Build(ctx context.Context) (*Doc, error) {
	if b.Opts.SnapshotRoot == "" {
		return nil, fmt.Errorf("snapshot root is required")
	}
	root, err := filepath.Abs(b.Opts.SnapshotRoot)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("snapshot root %s: not a directory", root)
	}
	la, err := loadAdvisory(ctx, b.Opts.Advisory)
	if err != nil {
		return nil, err
	}
	v := la.vuln

	doc := &Doc{Schema: Schema}
	doc.CaseID = b.Opts.CaseID
	if doc.CaseID == "" {
		doc.CaseID = v.ID
	}
	doc.Advisory.ID = v.ID
	doc.Advisory.Digest, doc.Advisory.Documents = la.advisoryDigest()

	doc.Snapshot.Path = root
	doc.Snapshot.Commit = b.Opts.Commit
	if h, herr := repository.ContentHash(root); herr == nil {
		doc.Snapshot.ContentHash = hashPrefix(h)
	}

	mb := readModuleBinding(root)
	doc.BuildContext = BuildCtx{
		GOOS:       orDefault(b.Opts.GOOS, runtime.GOOS),
		GOARCH:     orDefault(b.Opts.GOARCH, runtime.GOARCH),
		Tags:       append([]string{}, b.Opts.Tags...),
		CGO:        b.Opts.CGO,
		Toolchain:  toolchainString(b.Opts.Toolchain),
		ModuleMode: "mod",
	}
	if mb.VendorMode {
		doc.BuildContext.ModuleMode = "vendor"
	}

	atoms, hadWildcard, hadPlainPackage := buildAtoms(la)
	resolveDecls(ctx, b.Opts.Symbols, atoms)
	doc.Locus.Atoms = atoms
	doc.Locus.Status = locusStatus(atoms, hadWildcard, hadPlainPackage)

	usage, notes := classifyUsage(ctx, b.Opts.Usage, mb, atoms, v.Module)
	if mb.ParseErr != nil {
		notes = append(notes, "go.mod could not be parsed: "+mb.ParseErr.Error())
	}
	if b.Opts.Symbols == nil {
		notes = append(notes, "source index unavailable: declarations were not resolved")
	}
	if b.Opts.Usage == nil {
		notes = append(notes, "source index unavailable: product usage was not checked")
	}
	doc.Usage = usage
	doc.Usage.Limitations = unionStrings(doc.Usage.Limitations, append(notes, la.notes...))

	doc.Auxiliary.FixDiff = buildFixDiff(ctx, v, b.Opts.Patch)

	if err := Seal(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// toolchainString renders "go1.x" from a resolved toolchain version.
func toolchainString(v string) string {
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "go") {
		return v
	}
	return "go" + v
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// unionStrings merges two lists, deduplicated and sorted.
func unionStrings(a, b []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, l := range append(append([]string{}, a...), b...) {
		if l == "" || set[l] {
			continue
		}
		set[l] = true
		out = append(out, l)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) { sort.Strings(s) }

// hashPrefix normalizes a digest to the "sha256:<hex>" spelling.
func hashPrefix(h string) string {
	if strings.HasPrefix(h, "sha256:") {
		return h
	}
	return "sha256:" + h
}
