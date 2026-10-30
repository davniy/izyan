package fixbinding

import "testing"

func TestFourCompletenessResultsAreIndependent(t *testing.T) {
	c, err := CensusSource(CensusOptions{Module: ModuleIdentity{Path: "example.com/dep"}, Files: map[string][]byte{"p.go": []byte("package p\nfunc harmless(x string) bool { return x == \"ok\" }\n")}})
	if err != nil {
		t.Fatal(err)
	}
	inv := AssembleInventory(InventoryInput{Module: "example.com/dep", Observed: ObservedSource{Kind: SourceVendor, WalkComplete: true}})
	got := Assess(inv, c)
	if got.Input.Complete || !got.Parse.Complete || !got.Analysis.Complete || got.Cover.Complete {
		t.Fatalf("distinct measured outcomes collapsed: %+v", got)
	}
	c, err = CensusSource(CensusOptions{Module: ModuleIdentity{Path: "example.com/dep"}, Files: map[string][]byte{"p.go": []byte("package p\nfunc escape(x string) { unknown(x) }\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Parse.Complete || c.Analysis.Complete || c.Cover.Complete || len(c.Obligations) == 0 {
		t.Fatalf("unsupported propagation/type error was not blocking: %+v", c)
	}
}
