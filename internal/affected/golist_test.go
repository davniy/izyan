package affected

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func TestPackageInventoryBuildIdentity(t *testing.T) {
	product := domain.ProductSnapshot{Repository: "inventory.test/product", GOOS: "linux", GOARCH: "arm64"}
	build := domain.EffectiveBuildContext(product)
	sum := sha256.Sum256([]byte(completeInventoryStream))
	e := domain.Evidence{ID: "inventory-one", Kind: domain.EvidencePackageList,
		Content: completeInventoryStream, BuildContext: &build,
		PackageList: &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./...", RawSHA256: hex.EncodeToString(sum[:])}}
	g := AdmittedBuildGraph(product, []domain.Evidence{e})
	if !g.Admitted || g.EvidenceID != e.ID || !g.Paths["example.com/dep/vuln"] {
		t.Fatalf("matching inventory not named: %+v", g)
	}
	for _, mutation := range []func(*domain.Evidence){
		func(e *domain.Evidence) { foreign := build; foreign.GOOS = "darwin"; e.BuildContext = &foreign },
		func(e *domain.Evidence) { e.Content += " " },
		func(e *domain.Evidence) { run := *e.PackageList; run.Pattern = "./cmd/..."; e.PackageList = &run },
	} {
		bad := e
		mutation(&bad)
		g = AdmittedBuildGraph(product, []domain.Evidence{bad})
		if g.Admitted || g.Paths != nil { t.Fatalf("mismatched inventory admitted: %+v", g) }
	}
}
