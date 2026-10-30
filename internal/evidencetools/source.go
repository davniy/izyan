package evidencetools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

// ---- find_symbol ----

type symbolRefArgs struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
}

func (a symbolRefArgs) ref() domain.SymbolRef {
	return domain.SymbolRef{Package: a.Package, Symbol: a.Symbol}
}

func (a symbolRefArgs) valid() error {
	if a.Package == "" || a.Symbol == "" {
		return fmt.Errorf("package and symbol are required")
	}
	return nil
}

type findSymbolData struct {
	Found bool             `json:"found"`
	Site  *domain.CallSite `json:"site,omitempty"`
}

func (s *Session) findSymbol(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	if _, perr := s.probeSnapshot(ctx); perr != nil {
		return nil, perr
	}
	ref := a.ref()
	site, err := s.Source.FindSymbol(ctx, ref)
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil && err == nil {
		err = serr
	}
	if sd != nil {
		sd.CoverageRule = fmt.Sprintf("declaration lookup in package %s (loaded and type-checked)", ref.Package)
	}
	if errors.Is(err, goanalysis.ErrSymbolNotFoundInPackage) {
		return s.ok("find_symbol",
			fmt.Sprintf("%s is not declared in package %s (package loaded, symbol absent)", ref.Symbol, ref.Package),
			fmt.Sprintf("declarations of package %s in the loaded index", ref.Package),
			CompletenessComplete,
			findSymbolData{Found: false}, sd, lims), nil
	}
	if err != nil {
		return nil, err
	}
	return s.ok("find_symbol",
		fmt.Sprintf("%s.%s declared at %s:%d", ref.Package, ref.Symbol, site.File, site.Line),
		fmt.Sprintf("declarations of package %s in the loaded index", ref.Package),
		CompletenessComplete,
		findSymbolData{Found: true, Site: site}, sd, lims), nil
}

// ---- find_references ----

type referencesData struct {
	References []domain.CallSite `json:"references"`
	Count      int               `json:"count"`
}

func (s *Session) findReferences(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	sites, err := s.Source.SearchSymbol(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"references enumerated in product packages only; dependency-internal and dynamically-dispatched references are out of scope",
		"call sites, value references and field selections are included; this is reference presence, not proof of execution")
	return s.ok("find_references",
		fmt.Sprintf("%d reference(s) to %s.%s in product packages", len(sites), ref.Package, ref.Symbol),
		fmt.Sprintf("product packages of %s (loaded ./... roots)", s.SnapshotRoot),
		CompletenessPartial,
		referencesData{References: sites, Count: len(sites)}, sd, lims), nil
}

// ---- find_callers ----

type callersData struct {
	CallSites []domain.CallSite `json:"call_sites"`
	Count     int               `json:"count"`
}

func (s *Session) findCallers(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	sites, err := s.Source.FindCallers(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"statically named calls in product packages only: interface-dispatched, function-value, dependency-internal and reflection calls are NOT covered — use find_may_callers / scan_dynamic / find_dep_callers for those")
	return s.ok("find_callers",
		fmt.Sprintf("%d statically-named call site(s) of %s.%s in product packages", len(sites), ref.Package, ref.Symbol),
		fmt.Sprintf("product packages of %s (loaded ./... roots)", s.SnapshotRoot),
		CompletenessPartial,
		callersData{CallSites: sites, Count: len(sites)}, sd, lims), nil
}

// ---- find_may_callers ----

type mayCallersData struct {
	CallSites []goanalysis.MayCallSite `json:"call_sites"`
	Count     int                      `json:"count"`
	// PossibleCount counts sites whose target set is incomplete
	// (signature-compatible may-callers rather than proven callers).
	PossibleCount int `json:"possible_count"`
	// PartialEnumeration is true when extras churn made the scan itself
	// non-closed inside the loaded scope.
	PartialEnumeration bool `json:"partial_enumeration"`
}

func (s *Session) findMayCallers(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	sites, partial, err := s.Source.MayCallSites(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	possible := 0
	for _, c := range sites {
		if c.Possible {
			possible++
		}
	}
	lims = append(lims,
		"may-call scan covers direct, interface-dispatch and function-value sites in the loaded scope (product roots + retained dependency extras); unbounded cross-module callers of exported symbols are not enumerable")
	if partial {
		lims = append(lims, "call enumeration inside the loaded scope is incomplete (candidate sets open or extras generation changed mid-scan)")
	}
	c := CompletenessPartial
	if partial {
		c = CompletenessUnknown
	}
	return s.ok("find_may_callers",
		fmt.Sprintf("%d may-call site(s) of %s.%s (%d with unproven targets)", len(sites), ref.Package, ref.Symbol, possible),
		fmt.Sprintf("loaded scope of %s (product roots + retained dependency packages)", s.SnapshotRoot),
		c,
		mayCallersData{CallSites: sites, Count: len(sites), PossibleCount: possible, PartialEnumeration: partial},
		sd, lims), nil
}

// ---- find_dep_callers ----

func (s *Session) findDepCallers(ctx context.Context, a symbolRefArgs) (*Observation, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	ref := a.ref()
	sites, err := s.Source.FindDepCallers(ctx, ref)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, ref.Package+"."+ref.Symbol)
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"call sites inside the subject's own package/module only; callers in other modules and product code are separate scopes (find_callers / find_may_callers)")
	return s.ok("find_dep_callers",
		fmt.Sprintf("%d dependency-internal call site(s) of %s.%s", len(sites), ref.Package, ref.Symbol),
		fmt.Sprintf("module containing package %s (dependency-internal scope)", ref.Package),
		CompletenessPartial,
		callersData{CallSites: sites, Count: len(sites)}, sd, lims), nil
}

// ---- find_entrypoints ----

type entrypointsData struct {
	Entrypoints []domain.Entrypoint `json:"entrypoints"`
	Count       int                 `json:"count"`
}

func (s *Session) findEntrypoints(ctx context.Context) (*Observation, error) {
	eps, err := s.Source.FindEntrypoints(ctx)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, "")
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"entrypoint recognition covers main/init functions, exported symbols and net/http handlers; other transports (gRPC, message queues, CLI) are not enumerated by this scan")
	return s.ok("find_entrypoints",
		fmt.Sprintf("%d entrypoint(s) recognized in product packages", len(eps)),
		fmt.Sprintf("product packages of %s", s.SnapshotRoot),
		CompletenessPartial,
		entrypointsData{Entrypoints: eps, Count: len(eps)}, sd, lims), nil
}

// ---- read_function ----

type readFunctionArgs struct {
	File     string `json:"file"`
	Function string `json:"function,omitempty"`
}

type sourceData struct {
	File   string `json:"file"`
	Source string `json:"source"`
	Start  int    `json:"start,omitempty"`
	End    int    `json:"end,omitempty"`
	Func   string `json:"function,omitempty"`
	SHA256 string `json:"sha256"`
}

func (s *Session) readFunction(ctx context.Context, a readFunctionArgs) (*Observation, error) {
	if a.File == "" {
		return nil, fmt.Errorf("file is required")
	}
	src, err := s.Source.ReadFunction(ctx, a.File, a.Function)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, a.Function)
	if serr != nil {
		return nil, serr
	}
	data := sourceData{File: a.File, Func: a.Function, Source: src, SHA256: sha256Of([]byte(src))}
	return s.ok("read_function",
		fmt.Sprintf("source of %s in %s (%d bytes)", a.Function, a.File, len(src)),
		fmt.Sprintf("function %s in file %s of the snapshot", a.Function, a.File),
		CompletenessComplete, data, sd, lims), nil
}

// ---- read_source ----

type readSourceArgs struct {
	File  string `json:"file"`
	Start int    `json:"start,omitempty"`
	End   int    `json:"end,omitempty"`
}

func (s *Session) readSource(ctx context.Context, a readSourceArgs) (*Observation, error) {
	if a.File == "" {
		return nil, fmt.Errorf("file is required")
	}
	if a.Start < 0 || a.End < 0 || (a.End > 0 && a.Start > a.End) {
		return nil, fmt.Errorf("invalid line range [%d, %d]", a.Start, a.End)
	}
	src, err := s.Source.ReadSource(ctx, a.File, a.Start, a.End)
	if err != nil {
		return nil, err
	}
	data := sourceData{File: a.File, Source: src, Start: a.Start, End: a.End, SHA256: sha256Of([]byte(src))}
	return s.ok("read_source",
		fmt.Sprintf("%d bytes read from %s lines [%d,%d]", len(src), a.File, a.Start, a.End),
		fmt.Sprintf("file %s lines [%d,%d] under snapshot root / module cache", a.File, a.Start, a.End),
		CompletenessComplete, data,
		&ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			Subject:      a.File,
			CoverageRule: fmt.Sprintf("verbatim bytes of the requested line range of %s", a.File),
		}, nil), nil
}

// ---- search_source ----

type searchSourceArgs struct {
	Pattern string `json:"pattern"`
}

type searchSourceData struct {
	Matches   []string `json:"matches"`
	Count     int      `json:"count"`
	Truncated bool     `json:"truncated"`
}

func (s *Session) searchSource(ctx context.Context, a searchSourceArgs) (*Observation, error) {
	if strings.TrimSpace(a.Pattern) == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	matches, err := s.Source.SearchSource(ctx, a.Pattern)
	if err != nil {
		return nil, err
	}
	sd, lims, serr := s.sourceScope(ctx, a.Pattern)
	if serr != nil {
		return nil, serr
	}
	truncated := len(matches) >= goanalysis.MaxSearchMatches
	lims = append(lims,
		fmt.Sprintf("lexical regex search over loaded Go source files; result capped at %d matches; files that fail to read are skipped silently by the backend", goanalysis.MaxSearchMatches))
	if truncated {
		lims = append(lims, "result list hit the match cap — further matches exist but are not shown")
	}
	sd.Limits = &ScopeLimits{MaxMatches: goanalysis.MaxSearchMatches, Truncated: truncated}
	return s.ok("search_source",
		fmt.Sprintf("%d match(es) for %q in loaded Go sources%s", len(matches), a.Pattern, map[bool]string{true: " (truncated at cap)", false: ""}[truncated]),
		fmt.Sprintf("loaded Go files of %s (product roots + loaded dependency packages)", s.SnapshotRoot),
		CompletenessPartial,
		searchSourceData{Matches: matches, Count: len(matches), Truncated: truncated}, sd, lims), nil
}
