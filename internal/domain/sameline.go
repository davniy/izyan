package domain

import (
	"fmt"
	"strings"
)

// SameLineStatus is the typed outcome of the exact-preimage correspondence
// route. Only SameLineCorresponded records that the complete old changed region
// and its context were found at exactly one place in the selected source, that
// the enclosing declaration read from that source is the change's subject, and
// that the record's own package boundary covers it. Every other value is a
// refusal naming the premise that could not be established.
type SameLineStatus string

const (
	// SameLineCorresponded: the complete preimage matched unambiguously, the
	// enclosing selected declaration is identified, the reconstructed
	// postimage parses, every added helper is carried by that site, and the
	// advisory-declared package boundary covers the declaration.
	SameLineCorresponded SameLineStatus = "CORRESPONDED"
	// SameLineNoPatchBytes: the locator captured no bytes.
	SameLineNoPatchBytes SameLineStatus = "NO_PATCH_BYTES"
	// SameLineNoSelectedSource: no captured bytes of the selected version's own
	// file were available, so nothing could be matched.
	SameLineNoSelectedSource SameLineStatus = "NO_SELECTED_SOURCE"
	// SameLinePathNotInPatch: the patch changes no file at the coordinate.
	SameLinePathNotInPatch SameLineStatus = "PATH_NOT_IN_PATCH"
	// SameLineMalformedChange: the diff entry or a hunk is defective, binary,
	// renamed or not a modification, so its changed region is not total.
	SameLineMalformedChange SameLineStatus = "MALFORMED_CHANGE"
	// SameLineNoChangedRegion: a hunk removes nothing, so the change does not
	// replace any pre-existing code and names no omission site.
	SameLineNoChangedRegion SameLineStatus = "NO_CHANGED_REGION"
	// SameLinePreimageUnmatched: the complete old changed region and its
	// context occur nowhere in the selected source.
	SameLinePreimageUnmatched SameLineStatus = "PREIMAGE_UNMATCHED"
	// SameLinePreimageAmbiguous: the preimage occurs more than once, so path
	// existence and a hunk-header name cannot pick a site.
	SameLinePreimageAmbiguous SameLineStatus = "PREIMAGE_AMBIGUOUS"
	// SameLineNoDeclaration: no enclosing function or method declaration covers
	// the matched span in the selected source.
	SameLineNoDeclaration SameLineStatus = "NO_ENCLOSING_DECLARATION"
	// SameLineMultipleDeclarations: the patch's hunks fall in different
	// declarations, so one same-line subject does not exist.
	SameLineMultipleDeclarations SameLineStatus = "MULTIPLE_DECLARATIONS"
	// SameLinePostimageRejected: splicing the postimage at the matched span
	// does not yield the same parseable declaration.
	SameLinePostimageRejected SameLineStatus = "POSTIMAGE_REJECTED"
	// SameLineAddedHelperWithoutCarrier: the patch introduces a declaration the
	// changed site never names, so the addition is not a repair of a
	// pre-existing pipeline.
	SameLineAddedHelperWithoutCarrier SameLineStatus = "ADDED_HELPER_WITHOUT_CARRIER"
	// SameLineCoverUnestablished: the correspondence holds but no necessary
	// cover exists — the record declares no package boundary that contains the
	// verified declaration, and this route has no mechanism classifier for an
	// opaque change.
	SameLineCoverUnestablished SameLineStatus = "COVER_UNESTABLISHED"
)

// Covers reports whether the route recorded a positive conclusion about the
// subject's identity and its necessity boundary. It says nothing about whether
// the subject is absent from any build.
func (s SameLineStatus) Covers() bool { return s == SameLineCorresponded }

// SameLineCorrespondence records what the exact-preimage route established
// about one captured fix artifact and one selected-source file.
//
// It is evidence about identity and about the necessity boundary, never about
// absence: a subject whose preimage matched exists in the selected version by
// construction, so this record can never itself conclude that the subject is
// missing. What it does establish is that the change repaired a pre-existing
// selected declaration (the omission site), and that every added helper is
// named by that repaired site rather than merely being absent from the
// vulnerable source.
//
// The record is content-bound. PreimageDigest and SelectedFileDigest are the
// digests of the exact bytes the match was measured over, and PreimageDigest is
// re-derived from the model's own captured artifact bytes before any consumer
// relies on the record — so a status written without matching bytes establishes
// nothing.
type SameLineCorrespondence struct {
	// Locator is the declared fix reference the bytes were captured for.
	Locator string `json:"locator,omitempty"`
	// Path is the module-relative selected-source path that was matched.
	Path string `json:"path"`
	// Status is the typed outcome.
	Status SameLineStatus `json:"status"`
	// PreimageDigest pins the complete old changed region and its context: the
	// canonical before-image text of every hunk of Path, in order.
	PreimageDigest string `json:"preimage_digest,omitempty"`
	// SelectedFileDigest pins the complete selected-source bytes the preimage
	// was matched in.
	SelectedFileDigest string `json:"selected_file_digest,omitempty"`
	// StartLine and EndLine are the matched span in the selected source,
	// 1-based and inclusive.
	StartLine int `json:"start_line,omitempty"`
	EndLine   int `json:"end_line,omitempty"`
	// RemovedLines and AddedLines are the changed-region dimensions of the
	// matched hunks. Every added line is a residual of this route: an opaque
	// change carries no operation classification, and the residuals are
	// discharged only by the verified omission site.
	RemovedLines int `json:"removed_lines,omitempty"`
	AddedLines   int `json:"added_lines,omitempty"`
	// OmissionSite is the pre-existing selected declaration the change repairs.
	OmissionSite SymbolRef `json:"omission_site,omitempty"`
	// Cover is the complete advisory-declared package boundary the necessary
	// cover ranges over. It is nonempty only for a corresponded route.
	Cover []string `json:"cover,omitempty"`
	// Detail states the bounded observation behind Status.
	Detail string `json:"detail,omitempty"`
}

// Subject returns the absence subject the route established: the enclosing
// selected declaration.
func (s SameLineCorrespondence) Subject() SymbolRef { return s.OmissionSite }

// Covers reports whether the route established identity and a nonempty
// necessity cover.
func (s SameLineCorrespondence) Covers() bool {
	return s.Status.Covers() && s.OmissionSite.Package != "" && len(s.Cover) > 0
}

// CoversPackage reports whether the declared boundary the cover ranges over
// names pkg. The cover is the record's own scope claim, so a verified
// declaration outside it is not a subject of this advisory.
func (s SameLineCorrespondence) CoversPackage(pkg string) bool {
	for _, p := range s.Cover {
		if p == pkg {
			return true
		}
	}
	return false
}

// PreimageText returns the canonical text of one path's complete old changed
// region: the before-image lines of every hunk of that file entry, in patch
// order, each terminated by a single newline. It is the single definition of
// what "the complete old changed region and its context" means, so the producer
// that matches it and the boundary that re-derives the digest from captured
// bytes cannot disagree.
//
// Only the two format normalisations this contract supports are applied: a CRLF
// line terminator is read as LF, and the diff's own line-prefix byte is removed.
// Nothing else is normalised — a whitespace, comment, literal or token change is
// a different preimage, not the same one.
func PreimageText(patch []byte, path string) (string, bool) {
	if len(patch) == 0 || path == "" {
		return "", false
	}
	var b strings.Builder
	found := false
	current := ""
	inHunk := false
	for _, raw := range strings.Split(string(patch), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		// A hunk header opens a new hunk of the entry that is being read.
		if strings.HasPrefix(line, "@@") {
			inHunk = current == path
			continue
		}
		if inHunk {
			if line == "" {
				inHunk = false
				continue
			}
			kind := line[0]
			switch kind {
			case ' ', '-', '+', '\\':
				// Inside a hunk every prefixed line is content, so a line whose
				// text begins with "-- " or "++ " is a deleted or added line
				// rather than a header. Only ' ' and '-' belong to the
				// before-image; '+' is the postimage and '\' is line-ending
				// metadata.
				if current == path && (kind == ' ' || kind == '-') {
					b.WriteString(line[1:])
					b.WriteByte('\n')
					found = true
				}
				continue
			}
			inHunk = false
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			current = diffGitNewPath(line)
		case strings.HasPrefix(line, "+++ "):
			if p := diffHeaderPath(line[4:]); p != "" {
				current = p
			}
		case strings.HasPrefix(line, "--- "):
			if current == "" {
				current = diffHeaderPath(line[4:])
			}
		}
	}
	if !found {
		return "", false
	}
	return b.String(), true
}

// PreimageDigest is the digest of PreimageText; false when the path carries no
// before-image line.
func PreimageDigest(patch []byte, path string) (string, bool) {
	text, ok := PreimageText(patch, path)
	if !ok {
		return "", false
	}
	return EvidenceContentDigest(text), true
}

// diffGitNewPath returns the post-image path of a "diff --git a/x b/x" line.
func diffGitNewPath(line string) string {
	rest := strings.TrimPrefix(line, "diff --git ")
	if i := strings.Index(rest, " b/"); i >= 0 {
		return strings.Trim(rest[i+3:], "\"")
	}
	if fields := strings.Fields(rest); len(fields) == 2 {
		return strings.TrimPrefix(strings.Trim(fields[1], "\""), "b/")
	}
	return ""
}

// diffHeaderPath returns the module-relative path of a "--- a/x" or "+++ b/x"
// header, or "" for /dev/null.
func diffHeaderPath(rest string) string {
	p := strings.TrimSpace(rest)
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	if p == "/dev/null" || p == "" {
		return ""
	}
	p = strings.Trim(p, "\"")
	p = strings.TrimPrefix(strings.TrimPrefix(p, "a/"), "b/")
	return p
}

// validate refuses a record whose fields cannot describe a measured route, so a
// producer cannot write a status the subject does not carry.
func (s SameLineCorrespondence) validate() error {
	if !s.Status.Covers() {
		return nil
	}
	if s.Locator == "" {
		return fmt.Errorf("same-line correspondence: a corresponded route names no locator")
	}
	if s.Path == "" {
		return fmt.Errorf("same-line correspondence: a corresponded route names no selected-source path")
	}
	if s.PreimageDigest == "" {
		return fmt.Errorf("same-line correspondence: a corresponded route pins no preimage digest")
	}
	if s.SelectedFileDigest == "" {
		return fmt.Errorf("same-line correspondence: a corresponded route pins no selected-source digest")
	}
	if s.StartLine <= 0 || s.EndLine < s.StartLine {
		return fmt.Errorf("same-line correspondence: a corresponded route names no matched span")
	}
	if s.OmissionSite.Package == "" || s.OmissionSite.Symbol == "" {
		return fmt.Errorf("same-line correspondence: a corresponded route names no enclosing declaration")
	}
	if len(s.Cover) == 0 {
		return fmt.Errorf("same-line correspondence: a corresponded route carries no necessity cover")
	}
	return nil
}
