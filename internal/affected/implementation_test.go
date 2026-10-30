package affected

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/repository"
)

// implFixture is a minimal vendored snapshot with two platform-gated
// implementations of one package: a BSD file carrying the vulnerable
// marker and a Linux file without it.
type implFixture struct {
	root     string
	build    domain.ProductSnapshot
	advisory []byte
	entry    domain.AffectedModule
	affected domain.AffectedResult
	hash     string
}

func newImplFixture(t *testing.T) *implFixture {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/product\n\ngo 1.23\n\nrequire example.com/dep v1.0.0\n")
	write("main.go", "package main\n\nimport _ \"example.com/dep/resource\"\n\nfunc main() {}\n")
	write("vendor/modules.txt", "# example.com/dep v1.0.0\n## explicit; go 1.23\nexample.com/dep/resource\n")
	write("vendor/example.com/dep/resource/host_bsd.go",
		"//go:build dragonfly || freebsd || netbsd || openbsd || solaris\n\npackage resource\n\nfunc read() string {\n\treturn execCommand(\"kenv\", \"-q\", \"smbios.system.uuid\")\n}\n\nfunc execCommand(name string, args ...string) string { return name }\n")
	write("vendor/example.com/dep/resource/host_linux.go",
		"//go:build linux\n\npackage resource\n\nfunc read() string { return readFile() }\n\nfunc readFile() string { return \"/etc/hostid\" }\n")
	write("vendor/example.com/dep/resource/host_windows.go",
		"//go:build windows\n\npackage resource\n\nfunc read() string { return \"\" }\n")
	advisory := []byte(`{"id":"GHSA-test-0001","summary":"test advisory: BSD kenv command not using absolute path","details":"The vulnerable implementation is at resource/host_bsd.go and calls ` + "`kenv`" + `."}`)
	hash, err := repository.ContentHash(root)
	if err != nil {
		t.Fatal(err)
	}
	return &implFixture{
		root:     root,
		advisory: advisory,
		hash:     hash,
		build: domain.ProductSnapshot{
			Repository: root, Commit: "deadbeef", GoVersion: "go1.25.0",
			GOOS: "linux", GOARCH: "amd64",
		},
		entry: domain.AffectedModule{Module: "example.com/dep"},
		affected: domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			SelectedModule:  "example.com/dep",
			SelectedModules: []string{"example.com/dep"},
		},
	}
}

func (f *implFixture) proposal() domain.ImplementationLocusProposal {
	return domain.ImplementationLocusProposal{
		ID:                  "locus-1",
		Quality:             domain.QualityLLMInferred,
		Module:              "example.com/dep",
		Version:             "v1.0.0",
		Package:             "example.com/dep/resource",
		File:                "host_bsd.go",
		Function:            "read",
		Marker:              "kenv",
		BuildExpression:     "dragonfly || freebsd || netbsd || openbsd || solaris",
		GOOS:                []string{"dragonfly", "freebsd", "netbsd", "openbsd", "solaris"},
		AdvisoryEvidenceRef: "adv:GHSA-test-0001",
		AdvisoryQuotedSpan:  "calls `kenv`",
	}
}

func (f *implFixture) input(p domain.ImplementationLocusProposal) ImplementationVerificationInput {
	sum := sha256.Sum256(f.advisory)
	return ImplementationVerificationInput{
		Proposal:            p,
		AffectedEntry:       f.entry,
		Affected:            f.affected,
		Build:               f.build,
		SnapshotRoot:        f.root,
		SnapshotContentHash: f.hash,
		AdvisoryID:          "GHSA-test-0001",
		AdvisorySHA256:      hex.EncodeToString(sum[:]),
		AdvisoryBytes:       f.advisory,
	}
}

func verify(t *testing.T, in ImplementationVerificationInput) ImplementationVerification {
	t.Helper()
	return VerifyImplementationLocus(context.Background(), in)
}

func TestVerifyImplementationLocusAbsent(t *testing.T) {
	f := newImplFixture(t)
	res := verify(t, f.input(f.proposal()))
	if res.Status != ImplementationVerifiedAbsent {
		t.Fatalf("status = %s (%s); checks: %+v", res.Status, res.Reason, res.Checks)
	}
	if res.ProposalQuality != domain.QualityLLMInferred {
		t.Fatalf("proposal quality = %q", res.ProposalQuality)
	}
	if got := res.ClaimResult(); got != domain.ClaimFalse {
		t.Fatalf("claim result = %s, want FALSE for verified absence", got)
	}
	if res.FileSHA256 == "" || res.SnapshotContentHash != f.hash {
		t.Fatalf("identity hashes missing: %+v", res)
	}
	if res.AdvisoryQuoteField != domain.ImplementationAdvisoryFieldDetails {
		t.Fatalf("quote field = %q", res.AdvisoryQuoteField)
	}
	if !containsStr(res.ExcludedFiles, "vendor/example.com/dep/resource/host_bsd.go") {
		t.Fatalf("excluded files = %v", res.ExcludedFiles)
	}
	if !containsStr(res.SelectedFiles, "vendor/example.com/dep/resource/host_linux.go") {
		t.Fatalf("selected files = %v", res.SelectedFiles)
	}
	if len(res.AlternateMarkerHits) != 0 {
		t.Fatalf("alternate hits = %v", res.AlternateMarkerHits)
	}
	if len(res.Evidence) < 3 {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
	for _, e := range res.Evidence {
		if e.Quality != domain.QualityDeterministic {
			t.Fatalf("evidence %s quality = %q", e.ID, e.Quality)
		}
	}
}

func TestVerifyImplementationLocusFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput)
	}{
		{"wrong module", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Module = "example.com/other"
			p.Package = "example.com/other/resource"
		}},
		{"wrong version", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Version = "v1.1.0"
		}},
		{"wrong file", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.File = "missing.go"
		}},
		{"wrong function", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Function = "absent"
		}},
		{"absent marker", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Marker = "ioreg"
		}},
		{"wrong build expression", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.BuildExpression = "linux"
		}},
		{"empty build expression", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.BuildExpression = ""
		}},
		{"malformed quote", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.AdvisoryQuotedSpan = "the advisory says a command is invoked by a bare name"
		}},
		{"wrong advisory reference", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.AdvisoryEvidenceRef = "adv:GHSA-other"
		}},
		{"deterministic quality", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Quality = domain.QualityDeterministic
		}},
		{"missing quality", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Quality = ""
		}},
		{"source identity mismatch", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			in.SnapshotContentHash = strings.Repeat("cd", 32)
		}},
		{"advisory digest mismatch", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			in.AdvisorySHA256 = strings.Repeat("cd", 32)
		}},
		{"applicability unknown", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			in.Affected.VersionAffected = domain.ClaimUnknown
		}},
		{"build relevance false", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			in.Affected.BuildRelevant = domain.ClaimFalse
		}},
		{"resolved version mismatch", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			in.Affected.ResolvedVersion = "v1.2.0"
		}},
		{"no recorded target", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			in.Build.GOOS = ""
		}},
		{"proposal claims the recorded target affected", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.GOOS = append(p.GOOS, "linux")
		}},
		{"package directory absent", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Package = "example.com/dep/nothere"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newImplFixture(t)
			p := f.proposal()
			in := f.input(p)
			tc.mutate(f, &p, &in)
			in.Proposal = p
			res := verify(t, in)
			if res.Status != ImplementationVerificationUnknown {
				t.Fatalf("status = %s (%s); a failed deterministic check must be UNKNOWN, never absence", res.Status, res.Reason)
			}
			if res.Reason == "" {
				t.Fatalf("unknown result carries no reason: %+v", res)
			}
		})
	}
}

func TestVerifyImplementationLocusNestedModuleOwnership(t *testing.T) {
	f := newImplFixture(t)
	writeFile(t, f.root, "go.mod",
		"module example.com/product\n\ngo 1.23\n\nrequire (\n\texample.com/dep v1.0.0\n\texample.com/dep/v2 v2.0.0\n)\n")
	writeFile(t, f.root, "vendor/modules.txt",
		"# example.com/dep v1.0.0\n## explicit; go 1.23\nexample.com/dep/resource\n"+
			"# example.com/dep/v2 v2.0.0\n## explicit; go 1.23\nexample.com/dep/v2/resource\n")
	writeFile(t, f.root, "vendor/example.com/dep/v2/resource/host_bsd.go",
		"//go:build dragonfly || freebsd || netbsd || openbsd || solaris\n\npackage resource\n\nfunc read() string { return execCommand(\"kenv\", \"-q\", \"x\") }\n\nfunc execCommand(name string, args ...string) string { return name }\n")
	writeFile(t, f.root, "vendor/example.com/dep/v2/resource/host_linux.go",
		"//go:build linux\n\npackage resource\n\nfunc read() string { return \"\" }\n")
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal()
	p.Package = "example.com/dep/v2/resource"
	in := f.input(p)
	in.SnapshotContentHash = hash
	res := verify(t, in)
	if res.Status != ImplementationVerificationUnknown {
		t.Fatalf("status = %s (%s); a nested module owns its packages", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "owned by module") {
		t.Fatalf("reason %q does not name the ownership mismatch", res.Reason)
	}
}

func TestVerifyImplementationLocusVendorVersionDisagrees(t *testing.T) {
	f := newImplFixture(t)
	// The proposal matches the resolved version, but the vendored inventory
	// names a different version: source identity is not the analyzed build.
	if err := os.WriteFile(filepath.Join(f.root, "vendor", "modules.txt"),
		[]byte("# example.com/dep v1.0.1\n## explicit; go 1.23\nexample.com/dep/resource\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(f.proposal())
	in.SnapshotContentHash = hash
	res := verify(t, in)
	if res.Status != ImplementationVerificationUnknown {
		t.Fatalf("status = %s (%s)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "modules.txt") {
		t.Fatalf("reason %q does not name the inventory mismatch", res.Reason)
	}
}

func TestVerifyImplementationLocusSelectedAlternateMarker(t *testing.T) {
	f := newImplFixture(t)
	// The selected Linux implementation carries the same shell-out marker:
	// implementation absence must never be concluded.
	writeFile(t, f.root, "vendor/example.com/dep/resource/host_linux.go",
		"//go:build linux\n\npackage resource\n\nfunc read() string { return execCommand(\"kenv\", \"-q\", \"smbios.system.uuid\") }\n")
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(f.proposal())
	in.SnapshotContentHash = hash
	res := verify(t, in)
	if res.Status != ImplementationVerifiedPresent {
		t.Fatalf("status = %s (%s); checks: %+v", res.Status, res.Reason, res.Checks)
	}
	if !containsStr(res.AlternateMarkerHits, "vendor/example.com/dep/resource/host_linux.go") {
		t.Fatalf("hits = %v", res.AlternateMarkerHits)
	}
}

func TestVerifyImplementationLocusProposedFileSelected(t *testing.T) {
	f := newImplFixture(t)
	// Under FreeBSD the proposed vulnerable file is selected: the
	// implementation is present, not absent.
	f.build.GOOS = "freebsd"
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(f.proposal())
	in.SnapshotContentHash = hash
	f.affected.SelectedModule = "example.com/dep"
	in.Affected = f.affected
	res := verify(t, in)
	if res.Status != ImplementationVerifiedPresent {
		t.Fatalf("status = %s (%s)", res.Status, res.Reason)
	}
}

func TestVerifyImplementationLocusNoSelectedFiles(t *testing.T) {
	f := newImplFixture(t)
	// darwin selects neither the BSD nor the Linux implementation.
	f.build.GOOS = "darwin"
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(f.proposal())
	in.SnapshotContentHash = hash
	in.Affected = f.affected
	res := verify(t, in)
	if res.Status != ImplementationVerificationUnknown {
		t.Fatalf("status = %s (%s); an empty selection is not a closed absence", res.Status, res.Reason)
	}
}

func TestVerifyImplementationLocusMethodReference(t *testing.T) {
	f := newImplFixture(t)
	writeFile(t, f.root, "vendor/example.com/dep/resource/host_bsd.go",
		"//go:build dragonfly || freebsd || netbsd || openbsd || solaris\n\npackage resource\n\ntype hostIDReaderBSD struct{}\n\nfunc (r *hostIDReaderBSD) read() string {\n\treturn execCommand(\"kenv\", \"-q\", \"smbios.system.uuid\")\n}\n\nfunc execCommand(name string, args ...string) string { return name }\n")
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal()
	p.Function = "(*hostIDReaderBSD).read"
	in := f.input(p)
	in.SnapshotContentHash = hash
	res := verify(t, in)
	if res.Status != ImplementationVerifiedAbsent {
		t.Fatalf("status = %s (%s); checks: %+v", res.Status, res.Reason, res.Checks)
	}
	if res.FunctionLine == 0 {
		t.Fatalf("function line not recorded: %+v", res)
	}
}

// newBindingFixture reshapes the snapshot like a platform-gated binding:
// the gated file declares no functions — the platform gate is a variable
// binding — while the vulnerable implementation lives in an ungated file.
// The layout mirrors the measured vendored snapshot: a BSD-gated
// host_id_bsd.go binding file, an ungated host_id.go carrying the methods,
// and a linux-gated host_id_linux.go binding.
func newBindingFixture(t *testing.T) *implFixture {
	t.Helper()
	f := newImplFixture(t)
	pkgDir := filepath.Join(f.root, "vendor/example.com/dep/resource")
	for _, name := range []string{"host_bsd.go", "host_linux.go", "host_windows.go"} {
		if err := os.Remove(filepath.Join(pkgDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, f.root, "vendor/example.com/dep/resource/host_id_bsd.go",
		"//go:build dragonfly || freebsd || netbsd || openbsd || solaris\n\npackage resource\n\nvar platformHostIDReader hostIDReader = &hostIDReaderBSD{\n\texecCommand: execCommand,\n\treadFile:    readFile,\n}\n")
	writeFile(t, f.root, "vendor/example.com/dep/resource/host_id.go",
		"package resource\n\ntype hostIDReader interface {\n\tread() string\n}\n\ntype hostIDReaderBSD struct {\n\texecCommand func(string, ...string) string\n\treadFile    func() string\n}\n\ntype hostIDReaderLinux struct {\n\treadFile func() string\n}\n\nfunc (r *hostIDReaderBSD) read() string {\n\treturn r.execCommand(\"kenv\", \"-q\", \"smbios.system.uuid\")\n}\n\nfunc (r *hostIDReaderLinux) read() string {\n\treturn r.readFile()\n}\n\nfunc execCommand(name string, args ...string) string { return name }\n\nfunc readFile() string { return \"/etc/hostid\" }\n")
	writeFile(t, f.root, "vendor/example.com/dep/resource/host_id_linux.go",
		"//go:build linux\n\npackage resource\n\nvar platformHostIDReaderLinux hostIDReader = &hostIDReaderLinux{\n\treadFile: readFile,\n}\n")
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.hash = hash
	return f
}

func (f *implFixture) bindingProposal() domain.ImplementationLocusProposal {
	p := f.proposal()
	p.File = "host_id_bsd.go"
	p.Function = ""
	p.Marker = "&hostIDReaderBSD{"
	return p
}

func TestVerifyImplementationLocusBindingLocusAbsent(t *testing.T) {
	f := newBindingFixture(t)
	res := verify(t, f.input(f.bindingProposal()))
	if res.Status != ImplementationVerifiedAbsent {
		t.Fatalf("status = %s (%s); checks: %+v", res.Status, res.Reason, res.Checks)
	}
	if got := res.ClaimResult(); got != domain.ClaimFalse {
		t.Fatalf("claim result = %s, want FALSE for verified absence", got)
	}
	if res.FunctionLine == 0 {
		t.Fatalf("marker line not recorded: %+v", res)
	}
	if !containsStr(res.SelectedFiles, "vendor/example.com/dep/resource/host_id.go") {
		t.Fatalf("selected files = %v", res.SelectedFiles)
	}
	if len(res.AlternateMarkerHits) != 0 {
		t.Fatalf("alternate hits = %v", res.AlternateMarkerHits)
	}
}

func TestVerifyImplementationLocusBindingLocusAlternateMarker(t *testing.T) {
	f := newBindingFixture(t)
	// The binding marker also appears in an ungated, selected file: the
	// vulnerable binding is not excluded by the target.
	writeFile(t, f.root, "vendor/example.com/dep/resource/host_id.go",
		"package resource\n\ntype hostIDReader interface {\n\tread() string\n}\n\ntype hostIDReaderBSD struct {\n\texecCommand func(string, ...string) string\n}\n\nvar fallbackReader hostIDReader = &hostIDReaderBSD{execCommand: execCommand}\n\nfunc (r *hostIDReaderBSD) read() string {\n\treturn r.execCommand(\"kenv\", \"-q\", \"smbios.system.uuid\")\n}\n\nfunc execCommand(name string, args ...string) string { return name }\n")
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(f.bindingProposal())
	in.SnapshotContentHash = hash
	res := verify(t, in)
	if res.Status != ImplementationVerifiedPresent {
		t.Fatalf("status = %s (%s); a selected alternate carrying the marker must stay present", res.Status, res.Reason)
	}
	if !containsStr(res.AlternateMarkerHits, "vendor/example.com/dep/resource/host_id.go") {
		t.Fatalf("hits = %v", res.AlternateMarkerHits)
	}
}

func TestVerifyImplementationLocusBindingLocusFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput)
	}{
		{"binding file declares a function", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			writeFile(t, f.root, "vendor/example.com/dep/resource/host_id_bsd.go",
				"//go:build dragonfly || freebsd || netbsd || openbsd || solaris\n\npackage resource\n\nvar platformHostIDReader hostIDReader = &hostIDReaderBSD{execCommand: execCommand}\n\nfunc execCommand(name string, args ...string) string { return name }\n")
			hash, err := repository.ContentHash(f.root)
			if err != nil {
				t.Fatal(err)
			}
			in.SnapshotContentHash = hash
		}},
		{"marker absent from binding file", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Marker = "&hostIDReaderMissing{"
		}},
		{"named function lives only in another file", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.Function = "read" // exists in host_id.go, not in the gated file
		}},
		{"wrong build expression", func(f *implFixture, p *domain.ImplementationLocusProposal, in *ImplementationVerificationInput) {
			p.BuildExpression = "freebsd"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBindingFixture(t)
			p := f.bindingProposal()
			in := f.input(p)
			tc.mutate(f, &p, &in)
			in.Proposal = p
			res := verify(t, in)
			if res.Status != ImplementationVerificationUnknown {
				t.Fatalf("status = %s (%s); a failed deterministic check must be UNKNOWN, never absence", res.Status, res.Reason)
			}
			if res.Reason == "" {
				t.Fatalf("unknown result carries no reason: %+v", res)
			}
		})
	}
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
