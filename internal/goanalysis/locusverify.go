package goanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
)

// verifyLocusAbsent re-checks the locus-package-absent falsifier against
// the persisted build-graph evidence: every locus subject's package must be
// absent from `go list -deps`. A locus package found linked contradicts the
// FALSE; missing or undecodable package-list evidence leaves the scope
// insufficient — a loading failure is never absence.
//
// Unlike the subject-escape checks this verification needs no source index:
// the falsifier's premise is the build graph itself, so package absence
// cannot be escaped by wrappers, callbacks or dynamic dispatch.
func (v Verifier) verifyLocusAbsent(c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition, proof *domain.ContentAdmission) domain.Claim {

	subjects := append([]domain.SymbolRef{}, cond.Subjects...)
	if cond.Subject != nil {
		subjects = append(subjects, *cond.Subject)
	}
	if len(subjects) == 0 && cond.Params[domain.ParamConfigPackage] != "" {
		subjects = append(subjects, domain.SymbolRef{
			Package: cond.Params[domain.ParamConfigPackage],
			Symbol:  cond.Params[domain.ParamConfigSymbol],
		})
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	if len(subjects) == 0 {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "в условии не указаны уязвимые функции",
		})
	}

	set, evID, err := packageImportSet(c)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status:      domain.NegativeInsufficientScope,
			EvidenceIDs: append([]domain.EvidenceID(nil), claim.EvidenceIDs...),
			Notes:       err.Error(),
		})
	}
	nv.EvidenceIDs = append(nv.EvidenceIDs, evID)

	// One admission for this measurement. The cover check below and the
	// per-subject identity check are answered by the same record the verdict
	// boundary and publication consult, so a fresh verification and a replay
	// cannot disagree.
	absenceAdmission := domain.AdmitAbsence(c, domain.AbsenceBuildGraph{
		Paths: set, EvidenceID: evID, Admitted: true,
	}, proof)

	var present []string
	for _, s := range subjects {
		if set[s.Package] {
			present = append(present, s.Package)
		}
	}
	if len(present) > 0 {
		nv.Status = domain.NegativeContradicted
		nv.Notes = fmt.Sprintf(
			"пакеты с уязвимым кодом (%s) входят в граф сборки снапшота; "+
				"код дефекта включён в приложение, условие отсутствия пакетов не выполняется",
			strings.Join(present, ", "))
		return setNeg(claim, nv)
	}
	// The content route's necessary cover is a disjunction over the record's
	// declared implementation boundary: a single linked member contradicts the
	// absence conclusion, and a graph that measured no package shows no member
	// absent. The saved cover is never read as the premise — the admission
	// re-derived it from the record's own bytes.
	if cover := absenceAdmission.Cover(); cover != nil {
		if len(set) == 0 {
			return setNeg(claim, &domain.NegativeVerification{
				Status:      domain.NegativeInsufficientScope,
				EvidenceIDs: append([]domain.EvidenceID(nil), nv.EvidenceIDs...),
				Notes:       "the admitted build graph measured no package, so no member of the necessary cover was shown absent",
			})
		}
		for _, pkg := range cover.Packages {
			if set[pkg] {
				return setNeg(claim, &domain.NegativeVerification{
					Status:      domain.NegativeContradicted,
					EvidenceIDs: append([]domain.EvidenceID(nil), nv.EvidenceIDs...),
					Notes: fmt.Sprintf(
						"the necessary cover also names %s, which the admitted product build graph links, so the absence of %s cannot establish the defect's absence",
						pkg, strings.Join(subjectPackages(subjects), ", ")),
				})
			}
		}
	}
	// Identity before absence. A package's absence from the build graph is
	// evidence only when the subject is a subject of the selected version at
	// all: a fix-derived candidate whose coordinate does not resolve in that
	// version's own source names nothing there, so its missing package proves
	// nothing. The negative stays unverified — never VERIFIED on a vacuous
	// absence.
	for _, s := range subjects {
		if admission := absenceAdmission.Admits(s); !admission.Admitted {
			return setNeg(claim, &domain.NegativeVerification{
				Status:      domain.NegativeInsufficientScope,
				EvidenceIDs: append([]domain.EvidenceID(nil), nv.EvidenceIDs...),
				Notes:       "absence is not evidence: " + admission.Reason,
			})
		}
	}
	// The verification records the cover it relied on. A claim that does not
	// range over the admitted cover cannot be stamped, and an unstamped claim
	// must not become a VERIFIED absence: replay would refuse it anyway, and an
	// invalid negative must not sit beside an inconclusive verdict as if it
	// had been measured.
	if err := absenceAdmission.Stamp(cond, nv); err != nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status:      domain.NegativeInsufficientScope,
			EvidenceIDs: append([]domain.EvidenceID(nil), nv.EvidenceIDs...),
			Notes:       "the claim does not range over the admitted necessary cover: " + err.Error(),
		})
	}
	nv.Notes = fmt.Sprintf(
		"все пакеты с уязвимым кодом (%d) отсутствуют в графе сборки go list -deps", len(subjects))
	nv.Limitations = append(nv.Limitations,
		"отсутствие пакетов проверено для параметров сборки (GOOS/GOARCH/теги); в других конфигурациях они могут попасть в бинарник")

	// Coverage gap check: files excluded under the recorded build context
	// (other GOOS/GOARCH, build tags, cgo) may still import a locus package
	// — the product could be built in a configuration where the code links.
	// Absence in one context is not absence in the product.
	if gap := excludedBuildImports(c, subjects); gap != "" {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes += "; " + gap
		return setNeg(claim, nv)
	}

	if c.Exploit != nil && len(c.Exploit.NonLocusBasis) > 0 {
		var names []string
		for _, d := range c.Exploit.NonLocusBasis {
			names = append(names, d.Symbol.Package+"."+d.Symbol.Symbol)
		}
		nv.Limitations = append(nv.Limitations, fmt.Sprintf(
			"проверка уязвимости сужена экспертными решениями `non_locus` (ручное подтверждение, не автоматическое доказательство): %s",
			strings.Join(names, ", ")))
	}
	return setNeg(claim, nv)
}

// excludedBuildImports scans the product tree for Go source files that the
// recorded build context excludes (build tags, GOOS/GOARCH filename
// suffixes, cgo rules) but which import a locus package. Their presence
// means a different build configuration links code the package list never
// saw — the absence proof is then scoped to the recorded context only.
// Directories the go tool never builds (vendor, testdata, _/.-prefixed)
// are skipped: excluded files there can never join a product build.
func excludedBuildImports(c *domain.AnalysisCase, subjects []domain.SymbolRef) string {
	root := c.Product.Repository
	if root == "" {
		return ""
	}
	locusPkgs := map[string]bool{}
	for _, s := range subjects {
		locusPkgs[s.Package] = true
	}
	ctx := build.Default
	if c.Product.GOOS != "" {
		ctx.GOOS = c.Product.GOOS
	}
	if c.Product.GOARCH != "" {
		ctx.GOARCH = c.Product.GOARCH
	}
	ctx.BuildTags = append([]string(nil), c.Product.BuildTags...)
	ctx.CgoEnabled = c.Product.CGOEnabled

	var gaps []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "vendor" || base == "testdata" ||
				strings.HasPrefix(base, "_") || (strings.HasPrefix(base, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			// Test files never link into the product binary under any
			// configuration — an excluded test importing the package is
			// not a coverage gap for exploitation.
			return nil
		}
		dir := filepath.Dir(path)
		match, merr := ctx.MatchFile(dir, d.Name())
		if merr == nil && match {
			return nil // part of the recorded build — the package list covers it
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil // cannot compile in any configuration — links nothing
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if locusPkgs[p] {
				rel, rerr := filepath.Rel(root, path)
				if rerr != nil {
					rel = path
				}
				gaps = append(gaps, rel+"→"+p)
				break
			}
		}
		return nil
	})
	if len(gaps) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"файлы продукта, не вошедшие в текущую конфигурацию сборки, импортируют пакеты с уязвимым кодом: %s — "+
			"при сборке с другими тегами или под другую ОС они могут попасть в бинарник",
		strings.Join(gaps, ", "))
}

// packageImportSet decodes the persisted `go list -deps -json` evidence into
// the set of import paths the snapshot links. Only a completed, complete
// inventory whose recorded build context matches the case's effective
// context may prove absence; an undecodable, partial or untyped record is a
// measurement gap, never absence.
func packageImportSet(c *domain.AnalysisCase) (map[string]bool, domain.EvidenceID, error) {
	e, err := domain.SelectCompletePackageList(c.Product, c.EvidenceGraph.EvidenceList())
	if err != nil {
		return nil, "", fmt.Errorf(
			"нет допущенного списка пакетов (go list -deps) для текущего контекста сборки: %w; отсутствие в графе сборки не проверено", err)
	}
	set, derr := affected.PackageImportPaths([]byte(e.Content))
	if derr != nil {
		return nil, "", fmt.Errorf(
			"не удалось прочитать список пакетов %s: %w; отсутствие в графе сборки не проверено", e.ID, derr)
	}
	return set, e.ID, nil
}

// verifyLocusFunctionUnreached verifies the locus-function-unreached falsifier:
// locus packages are linked into the build graph, but the defect functions in L
// are unreached. It verifies:
//  1. No call paths (govulncheck traces), module reachability chains, or module
//     usages reach any subject symbol in L.
//  2. For symbols in internal/ packages, product code does not import the internal
//     package directly (Go compiler restriction guarantees no direct external references).
//  3. If source index is available, product entry points and call sites do not invoke
//     the subject, and dynamic markers (reflection, interface dispatch, func values,
//     go:linkname) do not escape to the subject.
func (v Verifier) verifyLocusFunctionUnreached(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

	subjects, err := exactLocusConditionSubjects(cond)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{Status: domain.NegativeInsufficientScope, Notes: err.Error()})
	}

	nv := &domain.NegativeVerification{
		Status:      domain.NegativeVerified,
		EvidenceIDs: append([]domain.EvidenceID(nil), claim.EvidenceIDs...),
	}

	// 1. EvidenceGraph check: CallPaths, ModuleReachable, ModuleUsages.
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			for _, sym := range subjects {
				if frameMatches(fr, sym) {
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("трасса вызовов достигает уязвимой функции %s.%s; FALSE опровергнут",
						sym.Package, sym.Symbol)
					if cp.EvidenceID != "" {
						nv.EvidenceIDs = append(nv.EvidenceIDs, cp.EvidenceID)
					}
					return setNeg(claim, nv)
				}
			}
		}
	}

	for _, subj := range subjects {
		want := subj.Package + "." + subj.Symbol
		if chain, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
			nv.Status = domain.NegativeContradicted
			nv.Notes = fmt.Sprintf("уязвимая функция %s достижима через вызовы внутри модуля: %s; FALSE опровергнут",
				want, strings.Join(chain, " -> "))
			return setNeg(claim, nv)
		}
		for _, u := range c.EvidenceGraph.ModuleUsages {
			if u.Callee == want {
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("продукт напрямую вызывает %s на %s:%d; FALSE опровергнут",
					want, u.File, u.Line)
				return setNeg(claim, nv)
			}
		}
	}
	if _, err := domain.ValidateDeadnessPremise(c.Exploit, subjects, c.EvidenceGraph.EvidenceList()); err != nil {
		return setNeg(claim, &domain.NegativeVerification{Status: domain.NegativeInsufficientScope, Notes: "deadness premise unavailable: " + err.Error()})
	}

	// Source availability is independent of package-inventory completeness.
	repoDir := ""
	if v.Source != nil && v.Source.Dir != "" {
		repoDir = v.Source.Dir
	} else if c.Product.Repository != "" {
		repoDir = c.Product.Repository
	}

	hasSource := repoDir != "" && dirHasGoFiles(repoDir)

	// 3. Source index checks: the bounded symbol-unreachability primitive
	// re-runs reference/caller scans, dynamic markers, interface dispatch,
	// build-gated references, dep-internal callers and module-internal
	// reachability as one recorded, fail-closed pass.
	var captured UnreachabilityResult
	if v.Source != nil && hasSource {
		mods := caseModules(c)
		module := ""
		if len(mods) > 0 {
			module = mods[0]
		}
		res, uerr := v.Source.VerifyUnreachable(ctx, module, subjects)
		if uerr != nil {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "unreachability check failed: " + uerr.Error()
			return setNeg(claim, nv)
		}
		if len(res.ProductReferences) > 0 {
			nv.Status = domain.NegativeContradicted
			site := res.ProductReferences[0]
			nv.Notes = fmt.Sprintf("найдено %d ссылок на функции локуса в коде продукта (напр. %s:%d); FALSE опровергнут",
				len(res.ProductReferences), site.File, site.Line)
			return setNeg(claim, nv)
		}
		for _, m := range res.DynamicMarkers {
			switch m.Kind {
			case "func_value":
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("символ передан как значение функции (%s:%d); возможен косвенный вызов",
					m.File, m.Line)
				return setNeg(claim, nv)
			case "linkname":
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("символ переопределен через go:linkname (%s:%d)",
					m.File, m.Line)
				return setNeg(claim, nv)
			}
		}
		if res.ValidateComplete(domain.EffectiveBuildContext(c.Product)) != nil {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "проверка недостижимости не закрыта: " + strings.Join(res.Limitations, "; ")
			return setNeg(claim, nv)
		}
		captured = res
	} else {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "bounded unreachability source and inventory unavailable"
		return setNeg(claim, nv)
	}

	nv.Notes = fmt.Sprintf("все функции дефектного локуса (%d) проверены: трассы вызовов отсутствуют, прямые ссылки и динамические утечки не обнаружены", len(subjects))
	if c.Exploit != nil && len(c.Exploit.NonLocusBasis) > 0 {
		var names []string
		for _, d := range c.Exploit.NonLocusBasis {
			names = append(names, d.Symbol.Package+"."+d.Symbol.Symbol)
		}
		nv.Limitations = append(nv.Limitations, fmt.Sprintf(
			"проверка уязвимости сужена экспертными решениями `non_locus` (ручное подтверждение, не автоматическое доказательство): %s",
			strings.Join(names, ", ")))
	}

	payload, err := json.Marshal(captured)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{Status: domain.NegativeInsufficientScope, Notes: "cannot capture bounded unreachability: " + err.Error()})
	}
	build := domain.EffectiveBuildContext(c.Product)
	evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind: domain.EvidenceSourceSnippet, Quality: domain.QualityDeterministic,
		Source: "go-analysis locus function unreachability check", Tool: "goanalysis.Verifier",
		Content: string(payload), BuildContext: &build,
	})
	nv.EvidenceIDs = append(nv.EvidenceIDs, evID)

	return setNeg(claim, nv)
}


func dirHasGoFiles(dir string) bool {
	if dir == "" {
		return false
	}
	has := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if p != dir && (base == ".git" || base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			has = true
			return fs.SkipAll
		}
		return nil
	})
	return has
}


func frameMatches(cs domain.CallSite, sym domain.SymbolRef) bool {
	if cs.Package != sym.Package {
		return false
	}
	if cs.Function == sym.Symbol {
		return true
	}
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv, fn := sym.Symbol[:i], sym.Symbol[i+1:]
		if cs.Function == fn && normalizeReceiver(cs.Receiver) == normalizeReceiver(recv) {
			return true
		}
	}
	return false
}

func normalizeReceiver(r string) string {
	r = strings.TrimPrefix(r, "(")
	r = strings.TrimSuffix(r, ")")
	return strings.TrimPrefix(r, "*")
}

// subjectPackages renders the distinct packages of a subject set for refusal
// text.
func subjectPackages(subjects []domain.SymbolRef) []string {
	var out []string
	for _, s := range subjects {
		if s.Package == "" {
			continue
		}
		seen := false
		for _, existing := range out {
			if existing == s.Package {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, s.Package)
		}
	}
	return out
}
