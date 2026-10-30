// Package fixbinding holds the pure extraction and identity primitives a
// content-derived fix binding is built from: a total changed-span account of a
// captured unified diff, resolved API ownership for operation calls, and
// structural resource identities.
//
// The package is deliberately below every consumer. It reads only the bytes it
// is given, performs no acquisition and authorises nothing: an inventory states
// what a patch changes and what remains unresolved, not whether a fix
// corresponds to some selected implementation. Admission is built on top of
// these primitives by a later checker.
//
// Two rules shape every type here.
//
// First, accounting is total. A hunk is not "a hunk that contains a recognised
// operation"; every changed executable token span is either consumed by a
// checked effect, proved non-executable under a supported rule, or retained as
// a blocking residual obligation. Truncated hunks, malformed headers, binary
// files and unnamed files are obligations too, so an incomplete inventory can
// never be mistaken for a complete one.
//
// Second, identity is resolved, never similar. An operation is classified by
// its resolved declaration — owning source, import path, function or receiver
// method, and declared signature — and a resource by its source-owned declared
// type, base-value provenance, selector chain and constructor relationships.
// A matching suffix, type name or mode value establishes nothing. When the
// patch-side imports or declarations needed to resolve an identifier are not
// supplied, the span stays unresolved; nothing is inferred from a convenient
// selected-source match.
package fixbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Image names one side of a patch.
type Image string

const (
	// ImageBefore is the pre-image: context lines plus deleted lines.
	ImageBefore Image = "before"
	// ImageAfter is the post-image: context lines plus added lines.
	ImageAfter Image = "after"
	// ImageSelected is the selected implementation's own source. It is not a
	// patch image: a census scans it to enumerate alternative subjects, so its
	// witnesses must name the selected tree rather than an edit side.
	ImageSelected Image = "selected"
)

// FileStatus is what a diff entry states about the file as a whole.
type FileStatus string

const (
	FileModified FileStatus = "modified"
	FileAdded    FileStatus = "added"
	FileDeleted  FileStatus = "deleted"
	FileRenamed  FileStatus = "renamed"
	FileBinary   FileStatus = "binary"
	FileModeOnly FileStatus = "mode-only"
)

// DefectKind names an accounting fact that blocks inventory completeness. A
// defect is not a Go error: the parse continues so every other file and hunk
// is still accounted for, and the inventory reports the defect as an
// obligation.
type DefectKind string

const (
	// DefectMalformedHunkHeader: an "@@" line that is not a valid hunk header.
	DefectMalformedHunkHeader DefectKind = "malformed-hunk-header"
	// DefectTruncatedHunk: the hunk header declares more lines than the patch
	// carries before EOF or before the next header.
	DefectTruncatedHunk DefectKind = "truncated-hunk"
	// DefectHunkOverrun: the hunk carries more lines than its header declares.
	DefectHunkOverrun DefectKind = "hunk-overrun"
	// DefectStrayHunkLine: a content line outside any hunk.
	DefectStrayHunkLine DefectKind = "stray-hunk-line"
	// DefectUnrecognisedLine: a line the parser cannot place in the diff
	// grammar.
	DefectUnrecognisedLine DefectKind = "unrecognised-diff-line"
	// DefectBinaryFile: the diff carries no textual hunk, so no changed
	// executable span can be inventoried.
	DefectBinaryFile DefectKind = "binary-file"
	// DefectNoHunks: the file entry states a change but carries no hunk and no
	// metadata that accounts for it.
	DefectNoHunks DefectKind = "file-changes-no-hunk"
	// DefectEmptyPatch: the captured bytes carry no diff entry at all.
	DefectEmptyPatch DefectKind = "empty-patch"
)

// Defect is one accounting fact about a file or hunk that blocks a complete
// inventory. Path and Hunk locate it; Detail states what was measured.
type Defect struct {
	Kind   DefectKind
	Path   string
	Hunk   int
	Line   int
	Detail string
}

func (d Defect) String() string {
	at := d.Path
	if at == "" {
		at = "patch"
	}
	if d.Hunk > 0 {
		at = fmt.Sprintf("%s hunk %d", at, d.Hunk)
	}
	if d.Line > 0 {
		at = fmt.Sprintf("%s (patch line %d)", at, d.Line)
	}
	return fmt.Sprintf("%s: %s: %s", at, d.Kind, d.Detail)
}

// HunkLine is one line of a hunk. OldLine and NewLine are 0 for the image the
// line does not belong to.
type HunkLine struct {
	Kind    byte // ' ', '-' or '+'
	Text    string
	OldLine int
	NewLine int
}

// Hunk is one unified-diff hunk with its declared dimensions and parsed lines.
// A hunk whose DeclaredLines do not match Lines is marked Defect; its content
// is still retained so the inventory can state what it did not establish.
type Hunk struct {
	Index     int
	Header    string
	OldStart  int
	OldLines  int
	NewStart  int
	NewLines  int
	Lines     []HunkLine
	Defects   []Defect
	Truncated bool
}

// ImageLines returns the lines of the requested image in file order.
func (h Hunk) ImageLines(img Image) []HunkLine {
	out := make([]HunkLine, 0, len(h.Lines))
	for _, ln := range h.Lines {
		switch img {
		case ImageBefore:
			if ln.Kind != '+' {
				out = append(out, ln)
			}
		case ImageAfter:
			if ln.Kind != '-' {
				out = append(out, ln)
			}
		}
	}
	return out
}

// FilePatch is one file entry of a unified diff.
type FilePatch struct {
	Path     string
	OldPath  string
	NewPath  string
	Status   FileStatus
	Header   string
	Hunks    []Hunk
	Defects  []Defect
	Binary   bool
	Renamed  bool
	ModeFrom string
	ModeTo   string
}

// Patch is a parsed unified diff. Every entry is retained even when it cannot
// be inventoried, so the caller sees the defect rather than a shorter file
// list.
type Patch struct {
	Files   []FilePatch
	Defects []Defect
	Digest  string
}

// ParseUnifiedDiff parses captured patch bytes. It never aborts on a malformed
// entry: a defect is recorded and parsing continues, because a partial
// inventory that silently stopped at the first malformed hunk would look
// complete.
func ParseUnifiedDiff(patch []byte) Patch {
	p := Patch{Digest: DigestBytes(patch)}
	lines := splitPatchLines(string(patch))
	var cur *FilePatch
	var hunk *Hunk
	lineNo := 0

	finishHunk := func() {
		if hunk == nil {
			return
		}
		checkHunk(hunk)
		cur.Hunks = append(cur.Hunks, *hunk)
		hunk = nil
	}
	finishFile := func() {
		finishHunk()
		if cur == nil {
			return
		}
		if len(cur.Hunks) == 0 && !cur.Binary && cur.ModeFrom == "" && !cur.Renamed &&
			cur.Status != FileAdded && cur.Status != FileDeleted {
			cur.Defects = append(cur.Defects, Defect{
				Kind: DefectNoHunks, Path: cur.Path,
				Detail: "the file entry states a change but carries no hunk and no metadata that accounts for it",
			})
		}
		p.Files = append(p.Files, *cur)
		cur = nil
	}

	for i := range lines {
		lineNo = i + 1
		line := lines[i]

		if strings.HasPrefix(line, "\\") {
			// "\ No newline at end of file" is line-ending metadata, not a
			// change and not a hunk line.
			continue
		}

		if hunk != nil {
			if line == "" {
				// A blank line inside a hunk is a genuine empty context line
				// only when the patch writes a single leading space; a truly
				// empty line means the hunk ended without satisfying its
				// declared dimensions.
				hunk.Defects = append(hunk.Defects, Defect{
					Kind: DefectTruncatedHunk, Path: cur.Path, Hunk: len(cur.Hunks) + 1,
					Line: lineNo, Detail: "the hunk ends before its declared line counts are satisfied",
				})
				hunk.Truncated = true
				finishHunk()
				continue
			}
			kind := line[0]
			if kind == ' ' || kind == '-' || kind == '+' {
				text := line[1:]
				if kind == ' ' {
					hunk.Lines = append(hunk.Lines, HunkLine{
						Kind: kind, Text: text,
						OldLine: hunk.OldStart + hunk.oldSeen(),
						NewLine: hunk.NewStart + hunk.newSeen(),
					})
				} else if kind == '-' {
					hunk.Lines = append(hunk.Lines, HunkLine{
						Kind: kind, Text: text,
						OldLine: hunk.OldStart + hunk.oldSeen(),
					})
				} else {
					hunk.Lines = append(hunk.Lines, HunkLine{
						Kind: kind, Text: text,
						NewLine: hunk.NewStart + hunk.newSeen(),
					})
				}
				if hunk.oldCount() > hunk.OldLines || hunk.newCount() > hunk.NewLines {
					hunk.Defects = append(hunk.Defects, Defect{
						Kind: DefectHunkOverrun, Path: cur.Path, Hunk: len(cur.Hunks) + 1,
						Line: lineNo, Detail: "the hunk carries more lines than its header declares",
					})
					hunk.Truncated = true
					finishHunk()
				} else if hunk.oldCount() == hunk.OldLines && hunk.newCount() == hunk.NewLines {
					finishHunk()
				}
				continue
			}
			// A line that cannot belong to a hunk while counts are unsatisfied
			// means the hunk was cut short.
			hunk.Defects = append(hunk.Defects, Defect{
				Kind: DefectTruncatedHunk, Path: cur.Path, Hunk: len(cur.Hunks) + 1,
				Line: lineNo, Detail: "the hunk ends before its declared line counts are satisfied",
			})
			hunk.Truncated = true
			finishHunk()
			// Fall through so the line is parsed as a new directive.
		}

		switch {
		case strings.HasPrefix(line, "diff --git "):
			finishFile()
			cur = &FilePatch{Header: line, Status: FileModified}
			cur.Header = line
			oldPath, newPath := parseDiffGitPaths(line)
			cur.OldPath, cur.NewPath = oldPath, newPath
			cur.Path = newPath
			if cur.Path == "" {
				cur.Path = oldPath
			}
			if cur.Path == "" {
				cur.Defects = append(cur.Defects, Defect{
					Kind: DefectUnrecognisedLine, Line: lineNo,
					Detail: "the diff entry names no file",
				})
			}
			continue

		case strings.HasPrefix(line, "--- "):
			if cur == nil {
				cur = &FilePatch{Status: FileModified}
			}
			if pth := diffSidePath(line); pth != "" {
				cur.OldPath = pth
				if cur.Path == "" {
					cur.Path = pth
				}
			} else {
				cur.Status = FileAdded
				if cur.NewPath == "" && cur.Path == "" {
					cur.Path = cur.NewPath
				}
			}
			continue

		case strings.HasPrefix(line, "+++ "):
			if cur == nil {
				cur = &FilePatch{Status: FileModified}
			}
			if pth := diffSidePath(line); pth != "" {
				cur.NewPath = pth
				cur.Path = pth
			} else {
				// The post-image is /dev/null: a plain unified diff's way of
				// stating a file deletion.
				cur.Status = FileDeleted
				if cur.Path == "" {
					cur.Path = cur.OldPath
				}
			}
			continue

		case strings.HasPrefix(line, "@@"):
			if cur == nil {
				// A hunk without a diff header is still a change; keep it as a
				// pathless file entry whose defect states the unaccounted path.
				cur = &FilePatch{Status: FileModified}
				cur.Defects = append(cur.Defects, Defect{
					Kind: DefectUnrecognisedLine, Line: lineNo,
					Detail: "the hunk is not preceded by a file header",
				})
			}
			h, ok := parseHunkHeader(line)
			if !ok {
				cur.Defects = append(cur.Defects, Defect{
					Kind: DefectMalformedHunkHeader, Path: cur.Path, Hunk: len(cur.Hunks) + 1,
					Line: lineNo, Detail: "the hunk header is not a valid unified-diff header",
				})
				continue
			}
			h.Header = line
			h.Index = len(cur.Hunks)
			// Consume directly into cur.Hunks through the hunk variable.
			hunk = &h
			continue

		case strings.HasPrefix(line, "new file mode "):
			if cur == nil {
				cur = &FilePatch{Status: FileAdded}
			}
			cur.Status = FileAdded
			cur.ModeTo = strings.TrimSpace(strings.TrimPrefix(line, "new file mode "))
			continue

		case strings.HasPrefix(line, "deleted file mode "):
			if cur == nil {
				cur = &FilePatch{Status: FileDeleted}
			}
			cur.Status = FileDeleted
			cur.ModeFrom = strings.TrimSpace(strings.TrimPrefix(line, "deleted file mode "))
			continue

		case strings.HasPrefix(line, "old mode "):
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.ModeFrom = strings.TrimSpace(strings.TrimPrefix(line, "old mode "))
			continue

		case strings.HasPrefix(line, "new mode "):
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.ModeTo = strings.TrimSpace(strings.TrimPrefix(line, "new mode "))
			continue

		case strings.HasPrefix(line, "rename from "):
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.Renamed = true
			cur.Status = FileRenamed
			cur.OldPath = strings.TrimSpace(strings.TrimPrefix(line, "rename from "))
			continue

		case strings.HasPrefix(line, "rename to "):
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.Renamed = true
			cur.Status = FileRenamed
			cur.NewPath = strings.TrimSpace(strings.TrimPrefix(line, "rename to "))
			cur.Path = cur.NewPath
			continue

		case strings.HasPrefix(line, "Binary files "), strings.HasPrefix(line, "GIT binary patch"):
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.Binary = true
			cur.Status = FileBinary
			cur.Defects = append(cur.Defects, Defect{
				Kind: DefectBinaryFile, Path: cur.Path, Line: lineNo,
				Detail: "the file is a binary change, so no textual changed span can be inventoried",
			})
			continue

		case strings.HasPrefix(line, "index "),
			strings.HasPrefix(line, "similarity index "),
			strings.HasPrefix(line, "dissimilarity index "):
			continue
		}

		if line == "" {
			continue
		}
		// Any other non-empty line outside a hunk cannot be placed.
		if cur == nil {
			cur = &FilePatch{}
		}
		cur.Defects = append(cur.Defects, Defect{
			Kind: DefectStrayHunkLine, Path: cur.Path, Line: lineNo,
			Detail: fmt.Sprintf("the line is outside every hunk and cannot be accounted: %q", truncate(line, 120)),
		})
	}
	finishFile()

	// Derive file status when the headers did not state it explicitly.
	for i := range p.Files {
		f := &p.Files[i]
		switch {
		case f.Binary:
			f.Status = FileBinary
		case f.Status == FileRenamed:
		case f.Status == FileAdded:
		case f.Status == FileDeleted:
		case f.ModeFrom != "" && f.ModeTo != "" && len(f.Hunks) == 0:
			f.Status = FileModeOnly
		case f.Status == "":
			f.Status = FileModified
		}
		if len(f.Hunks) == 0 && f.Binary {
			// Defect already recorded at the Binary files line; a
			// GIT binary patch without that line still needs one.
			if !hasDefect(f.Defects, DefectBinaryFile) {
				f.Defects = append(f.Defects, Defect{
					Kind: DefectBinaryFile, Path: f.Path,
					Detail: "the file is a binary change, so no textual changed span can be inventoried",
				})
			}
		}
	}

	if len(p.Files) == 0 {
		p.Defects = append(p.Defects, Defect{
			Kind:   DefectEmptyPatch,
			Detail: "the captured bytes carry no unified-diff file entry",
		})
	}
	return p
}

func hasDefect(defects []Defect, kind DefectKind) bool {
	for _, d := range defects {
		if d.Kind == kind {
			return true
		}
	}
	return false
}

// AllDefects returns every file and patch defect with its file path set, so a
// consumer enumerating obligations cannot miss a nested one.
func (p Patch) AllDefects() []Defect {
	out := append([]Defect(nil), p.Defects...)
	for _, f := range p.Files {
		for _, d := range f.Defects {
			if d.Path == "" {
				d.Path = f.Path
			}
			out = append(out, d)
		}
		for _, h := range f.Hunks {
			for _, d := range h.Defects {
				if d.Path == "" {
					d.Path = f.Path
				}
				out = append(out, d)
			}
		}
	}
	return out
}

func (h *Hunk) oldCount() int {
	n := 0
	for _, ln := range h.Lines {
		if ln.Kind != '+' {
			n++
		}
	}
	return n
}

func (h *Hunk) newCount() int {
	n := 0
	for _, ln := range h.Lines {
		if ln.Kind != '-' {
			n++
		}
	}
	return n
}

func (h *Hunk) oldSeen() int { return h.oldCount() }
func (h *Hunk) newSeen() int { return h.newCount() }

func checkHunk(h *Hunk) {
	if h.oldCount() != h.OldLines || h.newCount() != h.NewLines {
		h.Truncated = true
		h.Defects = append(h.Defects, Defect{
			Kind: DefectTruncatedHunk, Hunk: h.Index + 1,
			Detail: fmt.Sprintf("the hunk carries %d old and %d new lines but declares %d and %d",
				h.oldCount(), h.newCount(), h.OldLines, h.NewLines),
		})
	}
}

// parseHunkHeader reads "@@ -a,b +c,d @@ context". The count is optional and
// defaults to one, as the unified-diff grammar specifies.
func parseHunkHeader(line string) (Hunk, bool) {
	rest := line
	if !strings.HasPrefix(rest, "@@") {
		return Hunk{}, false
	}
	rest = rest[2:]
	end := strings.Index(rest, "@@")
	if end < 0 {
		return Hunk{}, false
	}
	spec := strings.TrimSpace(rest[:end])
	context := strings.TrimSpace(rest[end+2:])
	fields := strings.Fields(spec)
	if len(fields) != 2 {
		return Hunk{}, false
	}
	oldStart, oldLines, ok := parseHunkRange(fields[0], '-')
	if !ok {
		return Hunk{}, false
	}
	newStart, newLines, ok := parseHunkRange(fields[1], '+')
	if !ok {
		return Hunk{}, false
	}
	return Hunk{
		OldStart: oldStart, OldLines: oldLines,
		NewStart: newStart, NewLines: newLines,
		Header: context,
	}, true
}

func parseHunkRange(field string, sigil byte) (start, count int, ok bool) {
	if len(field) < 2 || field[0] != sigil {
		return 0, 0, false
	}
	body := field[1:]
	count = 1
	if i := strings.IndexByte(body, ','); i >= 0 {
		n, err := strconv.Atoi(body[i+1:])
		if err != nil || n < 0 {
			return 0, 0, false
		}
		count = n
		body = body[:i]
	}
	n, err := strconv.Atoi(body)
	if err != nil || n < 0 {
		return 0, 0, false
	}
	return n, count, true
}

// diffSidePath extracts the file path from a "--- a/x" or "+++ b/x" line and
// refuses the /dev/null side of an add/delete.
func diffSidePath(line string) string {
	p := strings.TrimSpace(line[4:])
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	if p == "/dev/null" || p == "" {
		return ""
	}
	p = unquotePath(p)
	p = strings.TrimPrefix(strings.TrimPrefix(p, "a/"), "b/")
	return p
}

// parseDiffGitPaths reads the two paths of "diff --git a/x b/y", respecting
// the quoting git uses for paths with spaces.
func parseDiffGitPaths(line string) (oldPath, newPath string) {
	fields := splitQuotedFields(strings.TrimPrefix(line, "diff --git "))
	if len(fields) < 2 {
		return "", ""
	}
	oldPath = strings.TrimPrefix(unquotePath(fields[0]), "a/")
	newPath = strings.TrimPrefix(unquotePath(fields[len(fields)-1]), "b/")
	return oldPath, newPath
}

func splitQuotedFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for i := range s {
		c := s[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func unquotePath(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		if u, err := strconv.Unquote(p); err == nil {
			return u
		}
	}
	return p
}

func splitPatchLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// DigestBytes is the content identity used by inventories, witnesses and
// wrappers. It is a plain sha256 over the complete bytes.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
