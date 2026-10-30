package triage

import (
	"path/filepath"
	"testing"
)

// testSiteCatalog mirrors a bounded site catalog: two repositories plus an
// artifact source, matching what SiteConfig.Catalog() builds. Roots live in
// a temp workspace returned alongside the catalog.
func testSiteCatalog(t *testing.T) (Catalog, string) {
	t.Helper()
	ws := t.TempDir()
	return Catalog{Entries: []CatalogEntry{
		{ID: "example-service", Kind: "git", Locator: "https://example.org/repos/example-service.git", Ecosystem: "go"},
		{ID: "local-example-service", Kind: "local", Root: filepath.Join(ws, "example-service"), Aliases: []string{"example-svc"}},
		{ID: "example-parser", Kind: "git", Locator: "https://example.org/repos/parser.git", Ecosystem: "go"},
		{ID: "local-sbom", Kind: "filesystem", Root: filepath.Join(ws, "artifacts")},
	}}, ws
}

func mustCatalogMatch(t *testing.T, c Catalog, p IntakeProposal) (CatalogEntry, IntakeFieldStatus) {
	t.Helper()
	e, st, err := c.MatchComponent(p)
	if err != nil {
		t.Fatalf("MatchComponent(%+v): %v", p, err)
	}
	return e, st
}

// TestCatalogMatchComponentPrecedence: a component hit wins over product and
// over source hints, and the matched entry is returned verbatim.
func TestCatalogMatchComponentPrecedence(t *testing.T) {
	c, _ := testSiteCatalog(t)
	e, st := mustCatalogMatch(t, c, IntakeProposal{
		Component:   "example-parser",
		Product:     "example-service",
		SourceHints: []string{"local-example-service"},
	})
	if st != IntakeValid || e.ID != "example-parser" {
		t.Fatalf("component precedence: entry=%q status=%s, want example-parser/VALID", e.ID, st)
	}
}

// TestCatalogMatchProductFallback: an unresolvable component falls through to
// the product tier instead of deciding the run.
func TestCatalogMatchProductFallback(t *testing.T) {
	c, _ := testSiteCatalog(t)
	e, st := mustCatalogMatch(t, c, IntakeProposal{
		Component: "unknown-widget",
		Product:   "example service",
	})
	if st != IntakeValid || e.ID != "example-service" {
		t.Fatalf("product fallback: entry=%q status=%s, want example-service/VALID", e.ID, st)
	}
}

// TestCatalogMatchHintFallback: with neither component nor product resolving,
// an explicit catalog entry id in source_hints is the last resort.
func TestCatalogMatchHintFallback(t *testing.T) {
	c, _ := testSiteCatalog(t)
	e, st := mustCatalogMatch(t, c, IntakeProposal{
		Component:   "unknown-widget",
		SourceHints: []string{"local-example-service", "not-a-catalog-id"},
	})
	if st != IntakeValid || e.ID != "local-example-service" {
		t.Fatalf("hint fallback: entry=%q status=%s, want local-example-service/VALID", e.ID, st)
	}
}

// TestCatalogMatchHintConflict: two hints naming different entries are
// CONFLICTING, never a silent pick.
func TestCatalogMatchHintConflict(t *testing.T) {
	c, _ := testSiteCatalog(t)
	_, st := mustCatalogMatch(t, c, IntakeProposal{
		SourceHints: []string{"example-service", "local-example-service"},
	})
	if st != IntakeConflicting {
		t.Fatalf("conflicting hints status = %s, want CONFLICTING", st)
	}
}

// TestCatalogMatchComponentConflict: an ambiguous component blocks the
// lower-precedence tiers entirely.
func TestCatalogMatchComponentConflict(t *testing.T) {
	c := Catalog{Entries: []CatalogEntry{
		{ID: "parser-a", Kind: "git", Locator: "https://a.example.org/parser.git"},
		{ID: "parser-b", Kind: "git", Locator: "https://b.example.org/parser.git"},
		{ID: "product-entry", Kind: "git", Locator: "https://example.org/product.git"},
	}}
	_, st := mustCatalogMatch(t, c, IntakeProposal{
		Component: "parser",
		Product:   "product-entry",
	})
	if st != IntakeConflicting {
		t.Fatalf("ambiguous component status = %s, want CONFLICTING", st)
	}
}

// TestCatalogMatchNone: nothing resolves → UNVERIFIED, never an invented
// entry and never a negative fact.
func TestCatalogMatchNone(t *testing.T) {
	c, _ := testSiteCatalog(t)
	for _, p := range []IntakeProposal{
		{},
		{Component: "unmatched", Product: "also-unmatched"},
		{SourceHints: []string{"not-a-catalog-id"}},
	} {
		e, st := mustCatalogMatch(t, c, p)
		if st != IntakeUnverified || e.ID != "" {
			t.Fatalf("proposal %+v: entry=%q status=%s, want empty/UNVERIFIED", p, e.ID, st)
		}
	}
}

// TestCatalogMatchAliasTier: an alias match still resolves, but only when the
// id and name tiers found nothing.
func TestCatalogMatchAliasTier(t *testing.T) {
	c, _ := testSiteCatalog(t)
	e, st := mustCatalogMatch(t, c, IntakeProposal{Component: "example-svc"})
	if st != IntakeValid || e.ID != "local-example-service" {
		t.Fatalf("alias match: entry=%q status=%s", e.ID, st)
	}
}

// TestCatalogMatchReference: external references — e.g. the repository path a
// tracker.RepoMap.Resolve returns — resolve against the bounded catalog
// instead of being adopted as repository roots directly.
func TestCatalogMatchReference(t *testing.T) {
	c, ws := testSiteCatalog(t)

	e, st, err := c.MatchReference(filepath.Join(ws, "example-service"))
	if err != nil || st != IntakeValid || e.ID != "local-example-service" {
		t.Fatalf("exact root reference: entry=%q status=%s err=%v", e.ID, st, err)
	}

	e, st, err = c.MatchReference("https://example.org/repos/example-service.git")
	if err != nil || st != IntakeValid || e.ID != "example-service" {
		t.Fatalf("exact locator reference: entry=%q status=%s err=%v", e.ID, st, err)
	}

	e, st, err = c.MatchReference("/elsewhere/parser")
	if err != nil || st != IntakeValid || e.ID != "example-parser" {
		t.Fatalf("name-only reference: entry=%q status=%s err=%v", e.ID, st, err)
	}

	_, st, err = c.MatchReference("/nowhere/mystery")
	if err != nil || st != IntakeUnverified {
		t.Fatalf("unresolved reference status = %s, want UNVERIFIED", st)
	}

	// Two entries answering to the same tail make the reference ambiguous.
	amb := Catalog{Entries: []CatalogEntry{
		{ID: "parser-a", Kind: "git", Locator: "https://a.example.org/parser.git"},
		{ID: "parser-b", Kind: "git", Locator: "https://b.example.org/parser.git"},
	}}
	if _, st, err = amb.MatchReference("/opt/parser"); err != nil || st != IntakeConflicting {
		t.Fatalf("ambiguous reference status = %s, want CONFLICTING", st)
	}

	if _, st, err = c.MatchReference("   "); err != nil || st != IntakeUnverified {
		t.Fatalf("blank reference status = %s, want UNVERIFIED", st)
	}
}
