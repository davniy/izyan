package goanalysis

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestMayCallSitesResolvedFuncValue(t *testing.T) {
	ix := fixture(t, "funcvalprod")
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if partial || len(sites) == 0 {
		t.Fatalf("resolved func-value call must close with a site: sites=%+v partial=%v", sites, partial)
	}
	for _, s := range sites {
		if s.Possible || s.File == "" {
			t.Fatalf("resolved site must be real: %+v", s)
		}
	}
}

func TestMayCallSitesClosedEmpty(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	sites, partial, err := ix.MayCallSites(context.Background(), domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse2"})
	if err != nil {
		t.Fatal(err)
	}
	if partial || len(sites) != 0 {
		t.Fatalf("incompatible empty result must close: sites=%+v partial=%v", sites, partial)
	}
}

func TestMayCallSitesUnresolvedCandidate(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if !partial {
		t.Fatalf("unresolved compatible candidate must remain open: %+v", sites)
	}
	found := false
	for _, s := range sites {
		if s.Function == "main" && s.Possible {
			found = true
		}
	}
	if !found {
		t.Fatalf("possible unresolved site missing: %+v", sites)
	}
}

func TestMayCallSitesUnresolvedSignature(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	sites, partial, err := ix.MayCallSites(context.Background(), domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Runner"})
	if err != nil {
		t.Fatal(err)
	}
	if !partial {
		t.Fatalf("unresolvable signature must remain open: %+v", sites)
	}
	found := false
	for _, s := range sites {
		if s.Possible {
			found = true
		}
	}
	if !found {
		t.Fatalf("possible unresolved site missing: %+v", sites)
	}
}

func TestMayCallSitesExtrasChurnSettles(t *testing.T) {
	ix := fixture(t, "fvchurnprod")
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if partial || len(sites) == 0 {
		t.Fatalf("settled churn must close with real site: sites=%+v partial=%v", sites, partial)
	}
	for _, s := range sites {
		if s.Possible {
			t.Fatalf("settled site is possible: %+v", s)
		}
	}
}

func TestMayCallSitesExtrasSettleAfterGrowth(t *testing.T) {
	ix := fixture(t, "funcvalprod")
	if _, partial, err := ix.MayCallSites(context.Background(), vulnSym); err != nil || partial {
		t.Fatalf("baseline did not close: partial=%v err=%v", partial, err)
	}
	ix.mu.Lock()
	_, err := ix.loadExtra(context.Background(), "example.com/dep/...")
	ix.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if partial || len(sites) == 0 {
		t.Fatalf("scan after growth did not close: sites=%+v partial=%v", sites, partial)
	}
}

func TestMayCallSitesSentinel(t *testing.T) {
	ix := fixture(t, "constprod")
	ix.mu.Lock()
	if err := ix.load(context.Background()); err != nil {
		ix.mu.Unlock()
		t.Fatal(err)
	}
	pkg := ix.pkgByPath(context.Background(), "example.com/dep/vuln")
	if pkg == nil {
		ix.mu.Unlock()
		t.Fatal("dep package not loaded")
	}
	key := callerKey{ref: vulnSym, dep: !ix.isProductPkg(pkg)}
	if ix.callersIn == nil {
		ix.callersIn = map[callerKey]bool{}
	}
	ix.callersIn[key] = true
	refs := ix.callersOf(pkg, vulnSym)
	delete(ix.callersIn, key)
	ix.callerCache = map[callerKey]cachedCallers{key: {gen: ix.extrasGen, refs: refs}}
	ix.mu.Unlock()
	if len(refs) != 1 || !refs[0].possible || refs[0].call != nil {
		t.Fatalf("not sentinel: %+v", refs)
	}
}

func TestMayCallSitesOpenNeverEmptyProof(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) == 0 && !partial {
		t.Fatal("open enumeration returned empty closed result")
	}
}

func TestMayCallSitesExtrasChurnSettlesClosedEmpty(t *testing.T) {
	ix := fixture(t, "fvchurnprod")
	sites, partial, err := ix.MayCallSites(context.Background(), domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 0 || partial {
		t.Fatalf("settled incompatible churn must close empty: sites=%+v partial=%v", sites, partial)
	}
}

func TestMayCallSitesExtrasEvictionDuringChurnStaysOpen(t *testing.T) {
	defer func() { callerSettleHook = nil }()
	ix := fixture(t, "fvopenprod")
	ix.mu.Lock()
	if err := ix.load(context.Background()); err != nil {
		ix.mu.Unlock()
		t.Fatal(err)
	}
	if _, err := ix.loadExtra(context.Background(), "example.com/dep2/..."); err != nil {
		ix.mu.Unlock()
		t.Fatal(err)
	}
	ix.extraWeight["example.com/dep2/..."] = maxExtraImportClosure + 1
	callerSettleHook = func(ix *Index) {
		ix.evictExtra()
		ix.extrasGen++
	}
	ix.mu.Unlock()
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if !partial {
		t.Fatalf("evicted scope during churn must stay open: sites=%+v", sites)
	}
}
