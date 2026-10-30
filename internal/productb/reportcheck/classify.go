package reportcheck

import (
	"path"
	"strings"
)

// metadataBasenames are manifests, lock/checksum files and build
// descriptors: a citation of one is a presence or version reference, never
// a root-cause locus and never a usage site.
var metadataBasenames = map[string]bool{
	"go.mod": true, "go.sum": true, "go.work": true, "go.work.sum": true,
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"cargo.lock": true, "poetry.lock": true, "pipfile.lock": true,
	"gemfile.lock": true, "composer.lock": true, "requirements.txt": true,
	"modules.txt": true, "dockerfile": true, "makefile": true,
}

// metadataExts are non-code formats: documentation, config manifests and
// checksums. A citation of one is metadata, never a locus or usage site.
var metadataExts = map[string]bool{
	".md": true, ".mod": true, ".sum": true, ".lock": true, ".json": true,
	".yaml": true, ".yml": true, ".toml": true, ".txt": true, ".work": true,
	".rst": true,
}

// metadataSegments are directories whose content is documentation or test
// scaffolding, not product code.
var metadataSegments = map[string]bool{
	"docs": true, "doc": true, "testdata": true,
}

// isMetadataPath classifies a normalized citation path as metadata by
// shape alone: a docs/doc/testdata segment, a manifest/lock basename, a
// test-only Go file, or a non-code extension. The classification does not
// depend on the file existing — an invented manifest citation is still a
// metadata claim.
func isMetadataPath(p string) bool {
	if p == "" {
		return false
	}
	segs := strings.Split(p, "/")
	base := segs[len(segs)-1]
	for _, seg := range segs[:len(segs)-1] {
		if metadataSegments[strings.ToLower(seg)] {
			return true
		}
	}
	lower := strings.ToLower(base)
	if metadataBasenames[lower] {
		return true
	}
	if strings.HasSuffix(lower, "_test.go") {
		return true
	}
	return metadataExts[strings.ToLower(path.Ext(base))]
}

// classify resolves a claim's final kind after its citation has been
// located in the snapshot: only tree-derived evidence can distinguish an
// import line from a call site and a code line from a manifest line.
//
// Order of precedence:
//  1. metadata — by path shape (go.mod/go.sum, docs, testdata, test code);
//  2. import — the cited line lies inside an import declaration;
//  3. locus — a claimed symbol outside usage wording, or a code line in a
//     root-cause/mechanism context (inside a declaration for Go files, any
//     non-metadata line for other languages);
//  4. usage — only a concrete site inside a function/method body;
//  5. unknown — everything else, including bare version/import citations.
func classify(ctx string, c claimed, f *fileInfo, found bool, line, end int, enc *declInfo) string {
	if isMetadataPath(c.path) {
		return KindMetadata
	}
	if found && f != nil && f.isGo && line > 0 && f.importLine(line) {
		return KindImport
	}
	if c.symbol != "" && ctx != KindUsage {
		return KindLocus
	}
	switch ctx {
	case KindUsage:
		// A usage site needs a concrete call/reference site: the cited
		// line must sit inside a function or method body. Import lines,
		// package clauses, file-only and symbol-only claims earn nothing.
		if found && f != nil && f.isGo && line > 0 && enc != nil && end <= enc.end {
			return KindUsage
		}
	case KindLocus:
		if line == 0 {
			return KindUnknown
		}
		if found && f != nil {
			if !f.isGo {
				return KindLocus
			}
			if enc != nil {
				return KindLocus
			}
		}
	}
	return KindUnknown
}
