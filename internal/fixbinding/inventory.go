package fixbinding

import (
	"fmt"
	"strings"
)

// SpanDisposition is the accounting outcome of one changed span. Every span
// carries exactly one; an unaccounted span is a validation failure, never a
// silently ignored change.
type SpanDisposition string

const (
	// SpanConsumed: a checked effect consumed the span.
	SpanConsumed SpanDisposition = "CONSUMED"
	// SpanNonExecutable: the span is proved to change no executable behaviour
	// under a named supported rule (ordinary comments, formatting).
	SpanNonExecutable SpanDisposition = "NON_EXECUTABLE"
	// SpanResidual: the span changes executable code this inventory cannot
	// account for. It is a blocking residual obligation.
	SpanResidual SpanDisposition = "RESIDUAL"
)

// Span is one changed token span. Positions are file positions, so two
// statements on one source line produce two distinct spans.
type Span struct {
	ID          string          `json:"id"`
	Path        string          `json:"path"`
	Image       Image           `json:"image"`
	StartLine   int             `json:"start_line"`
	StartCol    int             `json:"start_col"`
	EndLine     int             `json:"end_line"`
	EndCol      int             `json:"end_col"`
	Text        string          `json:"text"`
	Disposition SpanDisposition `json:"disposition"`
	EffectID    string          `json:"effect_id,omitempty"`
	ResidualID  string          `json:"residual_id,omitempty"`
	Rule        string          `json:"rule,omitempty"`
}

// ResidualKind names why a changed executable span was not consumed.
type ResidualKind string

const (
	ResidualGuard         ResidualKind = "GUARD"
	ResidualDerivation    ResidualKind = "DERIVATION"
	ResidualCopy          ResidualKind = "COPY"
	ResidualCall          ResidualKind = "CALL"
	ResidualCallArg       ResidualKind = "CALL_ARG"
	ResidualReturn        ResidualKind = "RETURN"
	ResidualAssignment    ResidualKind = "ASSIGNMENT"
	ResidualControl       ResidualKind = "CONTROL"
	ResidualDeclaration   ResidualKind = "DECLARATION"
	ResidualDirective     ResidualKind = "DIRECTIVE"
	ResidualStatement     ResidualKind = "STATEMENT"
	ResidualMissingSource ResidualKind = "MISSING_PATCH_SOURCE"
	ResidualInconsistent  ResidualKind = "SOURCE_INCONSISTENT"
	ResidualUntokenized   ResidualKind = "UNTOKENIZED_HUNK"
	ResidualTruncatedHunk ResidualKind = "TRUNCATED_HUNK"
	ResidualMalformedHunk ResidualKind = "MALFORMED_HUNK"
	ResidualFileMode      ResidualKind = "FILE_MODE"
	ResidualRename        ResidualKind = "RENAME"
)

// Residual is one blocking changed-span obligation: executable code the
// inventory could not consume or prove equivalent.
type Residual struct {
	ID          string       `json:"id"`
	Kind        ResidualKind `json:"kind"`
	Path        string       `json:"path"`
	Image       Image        `json:"image,omitempty"`
	Line        int          `json:"line,omitempty"`
	Declaration string       `json:"declaration,omitempty"`
	Detail      string       `json:"detail"`
	SpanIDs     []string     `json:"span_ids,omitempty"`
	Blocks      bool         `json:"blocks"`
}

// Guard is an enclosing branch predicate around a consumed operation. It is
// provenance the correspondence step rechecks; a changed guard is itself a
// residual, never silently folded into the effect.
type Guard struct {
	Kind      string        `json:"kind"`
	Condition string        `json:"condition"`
	Tested    *ResolvedExpr `json:"tested,omitempty"`
	Witness   Witness       `json:"witness"`
}

// Effect is one checked operation site or value change: the resolved
// declaration, the resource identity, the normalised permission value, and the
// changed spans it consumes.
type Effect struct {
	ID          string              `json:"id"`
	Path        string              `json:"path"`
	Declaration DeclarationIdentity `json:"declaration"`
	Class       OperationClass      `json:"class"`
	Added       bool                `json:"added"`
	Removed     bool                `json:"removed,omitempty"`
	Before      *Operation          `json:"before,omitempty"`
	After       *Operation          `json:"after,omitempty"`
	Spans       []string            `json:"spans"`
	Branches    []Guard             `json:"branches,omitempty"`
	Scaffold    bool                `json:"scaffold,omitempty"`
}

// FileAccount is the per-file accounting summary: what the diff said about the
// file and how many changed spans were inventoried.
type FileAccount struct {
	Path              string     `json:"path"`
	Status            FileStatus `json:"status"`
	Hunks             int        `json:"hunks"`
	ChangedSpans      int        `json:"changed_spans"`
	NonExecutableNote string     `json:"non_executable_note,omitempty"`
	Defects           []Defect   `json:"defects,omitempty"`
}

// Inventory is the total changed-span account of one captured patch. It is a
// pure observation: it authorises nothing and establishes no correspondence.
type Inventory struct {
	PatchDigest string        `json:"patch_digest"`
	Files       []FileAccount `json:"files,omitempty"`
	Spans       []Span        `json:"spans,omitempty"`
	Effects     []Effect      `json:"effects,omitempty"`
	Residuals   []Residual    `json:"residuals,omitempty"`
	Defects     []Defect      `json:"defects,omitempty"`
	// NonExecutableHunks counts hunks whose token delta was empty: comments,
	// formatting or blank lines only. They are accounted without a span.
	NonExecutableHunks int `json:"non_executable_hunks,omitempty"`
}

// Obligation is one blocking fact a later checker must handle: a parse defect
// or a residual changed span. It is the shape Tasks 5-7 consume; it carries no
// authority of its own.
type Obligation struct {
	Kind   string `json:"kind"` // "DEFECT" or "RESIDUAL"
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail"`
}

// Complete reports whether the inventory accounted for every changed span and
// every file without a defect or residual. It never reports complete because a
// fixed count was reached: the count follows the bytes.
func (inv *Inventory) Complete() bool {
	if inv == nil || len(inv.Defects) > 0 || len(inv.Residuals) > 0 {
		return false
	}
	return inv.Validate() == nil
}

// Validate refuses an inventory that leaves a span unaccounted or points at an
// object it does not contain.
func (inv *Inventory) Validate() error {
	if inv == nil {
		return fmt.Errorf("nil inventory")
	}
	effects := make(map[string]bool, len(inv.Effects))
	for _, e := range inv.Effects {
		if e.ID == "" {
			return fmt.Errorf("effect without an id")
		}
		if effects[e.ID] {
			return fmt.Errorf("effect %s is recorded twice", e.ID)
		}
		effects[e.ID] = true
		if len(e.Spans) == 0 {
			return fmt.Errorf("effect %s consumes no changed span", e.ID)
		}
		if e.Before == nil && e.After == nil {
			return fmt.Errorf("effect %s names no operation", e.ID)
		}
		if e.Added && e.Before != nil {
			return fmt.Errorf("effect %s is added but carries a preimage", e.ID)
		}
		if e.Removed && e.After != nil {
			return fmt.Errorf("effect %s is removed but carries a postimage", e.ID)
		}
	}
	residuals := make(map[string]bool, len(inv.Residuals))
	for _, r := range inv.Residuals {
		if r.ID == "" {
			return fmt.Errorf("residual without an id")
		}
		if residuals[r.ID] {
			return fmt.Errorf("residual %s is recorded twice", r.ID)
		}
		residuals[r.ID] = true
		if r.Kind == "" {
			return fmt.Errorf("residual %s has no kind", r.ID)
		}
	}
	consumed := make(map[string]string)
	for _, s := range inv.Spans {
		if s.ID == "" {
			return fmt.Errorf("span without an id")
		}
		switch s.Disposition {
		case SpanConsumed:
			if !effects[s.EffectID] {
				return fmt.Errorf("span %s is consumed by unknown effect %q", s.ID, s.EffectID)
			}
			if prev, ok := consumed[s.ID]; ok && prev != s.EffectID {
				return fmt.Errorf("span %s is consumed by two effects", s.ID)
			}
			consumed[s.ID] = s.EffectID
		case SpanNonExecutable:
			if s.Rule == "" {
				return fmt.Errorf("span %s is non-executable without a supported rule", s.ID)
			}
			if s.EffectID != "" || s.ResidualID != "" {
				return fmt.Errorf("span %s is non-executable but references an accounting object", s.ID)
			}
		case SpanResidual:
			if !residuals[s.ResidualID] {
				return fmt.Errorf("span %s is residual under unknown obligation %q", s.ID, s.ResidualID)
			}
		default:
			return fmt.Errorf("span %s has no account (disposition %q)", s.ID, s.Disposition)
		}
	}
	seenSpans := make(map[string]bool, len(inv.Spans))
	for _, s := range inv.Spans {
		if seenSpans[s.ID] {
			return fmt.Errorf("span %s is recorded twice", s.ID)
		}
		seenSpans[s.ID] = true
	}
	for _, e := range inv.Effects {
		for _, id := range e.Spans {
			if !seenSpans[id] {
				return fmt.Errorf("effect %s references unknown span %s", e.ID, id)
			}
		}
	}
	return nil
}

// Obligations lists every blocking fact in deterministic order: defects first,
// then residuals.
func (inv *Inventory) Obligations() []Obligation {
	if inv == nil {
		return nil
	}
	out := make([]Obligation, 0, len(inv.Defects)+len(inv.Residuals))
	for _, d := range inv.Defects {
		out = append(out, Obligation{
			Kind: "DEFECT", Code: string(d.Kind), Path: d.Path, Line: d.Line, Detail: d.Detail,
		})
	}
	for _, r := range inv.Residuals {
		if !r.Blocks {
			continue
		}
		out = append(out, Obligation{
			Kind: "RESIDUAL", Code: string(r.Kind), Path: r.Path, Line: r.Line, Detail: r.Detail,
		})
	}
	return out
}

// InventoryOptions configures a patch inventory. Source is the complete
// patch-side source the identifiers may be resolved against; a nil Source
// leaves every changed executable span unqualified rather than inferring it
// from another tree.
type InventoryOptions struct {
	Source *SourceBundle
}

// InventoryPatch builds the total changed-span account of a captured patch.
// Empty bytes are an input error; a patch that parses into defects still yields
// an inventory whose Complete is false.
func InventoryPatch(patch []byte, opts InventoryOptions) (*Inventory, error) {
	if len(strings.TrimSpace(string(patch))) == 0 {
		return nil, fmt.Errorf("empty patch bytes")
	}
	parsed := ParseUnifiedDiff(patch)
	inv := &Inventory{PatchDigest: parsed.Digest}
	inv.Defects = append(inv.Defects, parsed.Defects...)
	a := newAnalyzer(opts.Source)
	seq := &inventorySequencer{inv: inv}

	for _, file := range parsed.Files {
		startSpans := len(inv.Spans)
		acc := FileAccount{
			Path:   file.Path,
			Status: file.Status,
			Hunks:  len(file.Hunks),
		}
		for _, d := range file.Defects {
			if d.Path == "" {
				d.Path = file.Path
			}
			inv.Defects = append(inv.Defects, d)
			acc.Defects = append(acc.Defects, d)
		}

		switch {
		case file.Binary:
			// The binary defect already blocks completeness; no textual span
			// can be invented for opaque bytes.
		case file.Status == FileModeOnly:
			seq.residual(Residual{
				Kind: ResidualFileMode, Path: file.Path,
				Detail: fmt.Sprintf("the patch changes the file mode from %s to %s without a textual hunk, so no executable span proves the change equivalent",
					file.ModeFrom, file.ModeTo),
				Blocks: true,
			})
		}
		if file.Renamed {
			seq.residual(Residual{
				Kind: ResidualRename, Path: file.Path,
				Detail: fmt.Sprintf("the patch renames %s to %s; the changed path/package identity is not established by a changed span",
					file.OldPath, file.NewPath),
				Blocks: true,
			})
		}
		if len(file.Hunks) == 0 && !file.Binary && file.ModeFrom == "" && !file.Renamed {
			switch file.Status {
			case FileAdded, FileDeleted:
				acc.NonExecutableNote = "the file entry adds or removes an empty file, which carries no executable token"
			}
		}
		for _, h := range file.Hunks {
			if len(h.Defects) > 0 {
				for _, d := range h.Defects {
					if d.Path == "" {
						d.Path = file.Path
					}
					inv.Defects = append(inv.Defects, d)
				}
				seq.malformedHunk(file, h)
				continue
			}
			seq.hunk(a, file, h)
		}
		acc.ChangedSpans = len(inv.Spans) - startSpans
		inv.Files = append(inv.Files, acc)
	}
	return inv, nil
}

// inventorySequencer allocates deterministic ids and appends accounting objects.
type inventorySequencer struct {
	inv *Inventory
}

func (s *inventorySequencer) residual(r Residual) string {
	r.ID = fmt.Sprintf("R-%02d", len(s.inv.Residuals)+1)
	s.inv.Residuals = append(s.inv.Residuals, r)
	return r.ID
}

func (s *inventorySequencer) span(sp Span) string {
	sp.ID = fmt.Sprintf("S-%02d", len(s.inv.Spans)+1)
	s.inv.Spans = append(s.inv.Spans, sp)
	return sp.ID
}
