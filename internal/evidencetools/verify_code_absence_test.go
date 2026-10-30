package evidencetools

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func absenceCall(t *testing.T, s *Session, in VerifyCodeAbsenceArgs) *Observation {
	return s.invoke(context.Background(), "verify_code_absence", nil, func(c context.Context) (*Observation, error) { return s.verifyCodeAbsence(c, in) })
}
func absenceData(t *testing.T, o *Observation) CodeAbsenceData {
	d, ok := o.Data.(CodeAbsenceData)
	if !ok {
		t.Fatalf("data=%T", o.Data)
	}
	return d
}
func forceBool(ix any, n string, b bool) {
	v := reflect.ValueOf(ix).Elem().FieldByName(n)
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().SetBool(b)
}
func forceSkipped(ix any) {
	v := reflect.ValueOf(ix).Elem().FieldByName("skippedImports")
	m := map[string][]string{"broken": {"example.com/broken"}}
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(m))
}
func TestVerifyCodeAbsenceComplete(t *testing.T) {
	s := newTestSession(t)
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Parse"}, {Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	if o.Completeness != CompletenessComplete {
		t.Fatal(o)
	}
	d := absenceData(t, o)
	if !reflect.DeepEqual(d.ExpectedSubjects, d.CheckedSubjects) || len(d.AbsentSubjects) != 1 || d.SnapshotHash == "" || d.BuildContextHash == "" {
		t.Fatal(d)
	}
}

func TestVerifyCodeAbsenceToolchainPinned(t *testing.T) {
	// The session resolves the toolchain it loads packages with: the
	// recorded build context binds the compiler identity, and the hash
	// moves when a different toolchain is claimed.
	s := newTestSession(t)
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	if o.Completeness != CompletenessComplete {
		t.Fatal(o)
	}
	bc1 := o.ScopeDetails.BuildContext
	if bc1 == nil || bc1.Toolchain == "" || bc1.GOOS == "" || bc1.GOARCH == "" {
		t.Fatalf("build context must pin effective target and toolchain: %+v", bc1)
	}

	s2 := newTestSession(t)
	s2.ToolVer = "go9.9.9"
	o2 := absenceCall(t, s2, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	d1, d2 := absenceData(t, o), absenceData(t, o2)
	if d1.BuildContextHash == d2.BuildContextHash {
		t.Fatalf("different toolchains produced the same build context hash")
	}

	s3 := newTestSession(t)
	s3.ToolVer = ""
	s3.ToolBin = ""
	o3 := absenceCall(t, s3, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	if o3.Completeness == CompletenessComplete {
		t.Fatalf("unresolved toolchain must never yield COMPLETE: %+v", o3)
	}
}
func TestVerifyCodeAbsencePartialZeroHits(t *testing.T) {
	s := newTestSession(t)
	forceBool(s.Source, "loadBudgetExhausted", true)
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	if o.Completeness == CompletenessComplete {
		t.Fatal(o)
	}
}
func TestVerifyCodeAbsenceSkippedPackage(t *testing.T) {
	s := newTestSession(t)
	_ = absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	forceSkipped(s.Source)
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	d := absenceData(t, o)
	if o.Completeness != CompletenessPartial || len(d.SkippedPackages) == 0 {
		t.Fatal(o)
	}
}

// absenceSession builds a session over a testdata fixture the same way
// the falsifier controls do: the snapshot is the whole product module.
func absenceSession(t *testing.T, name string) *Session {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// TestVerifyCodeAbsenceDeadSkippedPackageDoesNotBlock: a skipped package
// proven unreachable from the shipping roots is discarded, not listed —
// its type-check failure can no longer keep the closure open.
func TestVerifyCodeAbsenceDeadSkippedPackageDoesNotBlock(t *testing.T) {
	s := absenceSession(t, "scopetestprod")
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{
		{Package: "example.com/scopetestprod/svc", Symbol: "Nope"},
	}})
	d := absenceData(t, o)
	if o.Completeness != CompletenessComplete {
		t.Fatalf("dead skipped/helper packages must not block: %+v %+v", o, d)
	}
	if len(d.AbsentSubjects) != 1 {
		t.Fatalf("the undeclared symbol must be absent: %+v", d)
	}
	if len(d.SkippedPackages) != 0 {
		t.Fatalf("dead skipped packages must not be reported as gaps: %+v", d.SkippedPackages)
	}
}

// TestVerifyCodeAbsenceReachableSkippedPackageBlocks: a skipped package
// reachable from the shipping main still hides references — the check
// can never close while its edges are invisible.
func TestVerifyCodeAbsenceReachableSkippedPackageBlocks(t *testing.T) {
	s := absenceSession(t, "scopeskipp")
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{
		{Package: "example.com/scopeskipp/loose", Symbol: "Nope"},
	}})
	d := absenceData(t, o)
	if o.Completeness == CompletenessComplete {
		t.Fatalf("a reachable skipped member must block: %+v", o)
	}
	if len(d.SkippedPackages) == 0 {
		t.Fatal("the reachable skipped member must be reported")
	}
}

// TestVerifyCodeAbsenceDeadImporterNotInSubjectImporters: importers
// proven dead never appear in the subject importer audit — only the
// effective member importers count.
func TestVerifyCodeAbsenceDeadImporterNotInSubjectImporters(t *testing.T) {
	s := absenceSession(t, "scopetestprod")
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{
		{Package: "example.com/scopetestprod/svc", Symbol: "Serve"},
	}})
	d := absenceData(t, o)
	if d.ImportClosure == nil {
		t.Fatal("closure report missing")
	}
	for _, imp := range d.ImportClosure.SubjectImporters["example.com/scopetestprod/svc"] {
		if imp != "example.com/scopetestprod" {
			t.Fatalf("dead importer %s must not appear in subject importers", imp)
		}
	}
}
func TestVerifyCodeAbsenceTruncatedOutput(t *testing.T) {
	s := newTestSession(t)
	forceBool(s.Source, "loadBudgetExhausted", true)
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	if o.Completeness == CompletenessComplete || !strings.Contains(strings.Join(o.Limitations, " "), "truncated") {
		t.Fatal(o)
	}
}
func TestVerifyCodeAbsenceBuildContextMismatch(t *testing.T) {
	s := newTestSession(t)
	_ = absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	s.Build.GOOS = "windows"
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Nope"}}})
	if o.Completeness != CompletenessPartial {
		t.Fatal(o)
	}
}
func TestVerifyCodeAbsenceDynamicMarker(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/dyn\n\ngo 1.23\n"), 0644)
	os.WriteFile(filepath.Join(root, "main.go"), []byte("package dyn\nimport \"reflect\"\nfunc Parse(){_=reflect.TypeOf(1)}\n"), 0644)
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	if err != nil {
		t.Fatal(err)
	}
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/dyn", Symbol: "Parse"}}})
	d := absenceData(t, o)
	if o.Completeness == CompletenessComplete || len(d.DynamicMarkers) == 0 {
		t.Fatal(o)
	}
}
func TestVerifyCodeAbsenceSubjectSet(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := s.invoke(ctx, "verify_code_absence", nil, func(c context.Context) (*Observation, error) {
		return s.verifyCodeAbsence(c, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package: "example.com/snapdep/vuln", Symbol: "Ghost"}}})
	})
	if o.Completeness == CompletenessComplete {
		t.Fatal(o)
	}
	if _, err := s.verifyCodeAbsence(context.Background(), VerifyCodeAbsenceArgs{}); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestVerifyCodeAbsenceRejectsPartialInventory(t *testing.T) {
	s := newTestSession(t)
	s.GoTool = &inventoryTool{raw: []byte(`{"ImportPath":"example.com/snapdep"} {`)}
	o := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package:"example.com/absent", Symbol:"Missing"}}})
	if o.Completeness == CompletenessComplete { t.Fatalf("partial list became empty universe: %+v", o) }
	d := absenceData(t, o)
	if len(d.AbsentSubjects) != 0 || d.ImportClosure.InventoryError == "" || d.ImportClosure.InventoryReference != "" { t.Fatalf("partial graph proved absence: %+v", d) }
}
