package domain

import (
	"strings"
	"testing"
)

func validImplementationProposal() ImplementationLocusProposal {
	return ImplementationLocusProposal{
		ID:                  "locus-1",
		Quality:             QualityLLMInferred,
		Module:              "example.com/dep",
		Version:             "v1.2.3",
		Package:             "example.com/dep/resource",
		File:                "host_bsd.go",
		Function:            "read",
		Marker:              "kenv",
		BuildExpression:     "dragonfly || freebsd || netbsd || openbsd || solaris",
		GOOS:                []string{"freebsd", "solaris"},
		AdvisoryEvidenceRef: "adv:GHSA-test-0001",
		AdvisoryQuotedSpan:  "calls `kenv`",
	}
}

func TestImplementationProposalValidate(t *testing.T) {
	if err := validImplementationProposal().Validate(); err != nil {
		t.Fatalf("valid proposal rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(p *ImplementationLocusProposal)
	}{
		{"deterministic quality", func(p *ImplementationLocusProposal) { p.Quality = QualityDeterministic }},
		{"missing quality", func(p *ImplementationLocusProposal) { p.Quality = "" }},
		{"missing id", func(p *ImplementationLocusProposal) { p.ID = "" }},
		{"bad module", func(p *ImplementationLocusProposal) { p.Module = "not a path" }},
		{"bad version", func(p *ImplementationLocusProposal) { p.Version = "1.2.3" }},
		{"package outside module", func(p *ImplementationLocusProposal) { p.Package = "example.com/other/resource" }},
		{"absolute file", func(p *ImplementationLocusProposal) { p.File = "/etc/host.go" }},
		{"traversing file", func(p *ImplementationLocusProposal) { p.File = "../host.go" }},
		{"unclean file", func(p *ImplementationLocusProposal) { p.File = "./host.go" }},
		{"non-go file", func(p *ImplementationLocusProposal) { p.File = "host.c" }},
		{"test file", func(p *ImplementationLocusProposal) { p.File = "host_test.go" }},
		{"backslash file", func(p *ImplementationLocusProposal) { p.File = `resource\host.go` }},
		{"overlong function", func(p *ImplementationLocusProposal) { p.Function = strings.Repeat("f", 300) }},
		{"bad function", func(p *ImplementationLocusProposal) { p.Function = "read()" }},
		{"empty marker", func(p *ImplementationLocusProposal) { p.Marker = "  " }},
		{"bad build expression", func(p *ImplementationLocusProposal) { p.BuildExpression = "linux &&" }},
		{"duplicate platform token", func(p *ImplementationLocusProposal) { p.GOOS = []string{"linux", "linux"} }},
		{"bad platform token", func(p *ImplementationLocusProposal) { p.GOOS = []string{"Linux"} }},
		{"empty advisory ref", func(p *ImplementationLocusProposal) { p.AdvisoryEvidenceRef = "" }},
		{"unknown advisory ref form", func(p *ImplementationLocusProposal) { p.AdvisoryEvidenceRef = "advisory:GHSA-test-0001" }},
		{"bad digest ref", func(p *ImplementationLocusProposal) { p.AdvisoryEvidenceRef = "sha256:abc" }},
		{"empty quote", func(p *ImplementationLocusProposal) { p.AdvisoryQuotedSpan = " " }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validImplementationProposal()
			tc.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("proposal accepted: %+v", p)
			}
		})
	}
}

func TestImplementationProposalFunctionForms(t *testing.T) {
	for _, fn := range []string{"", "read", "hostIDReaderBSD.read", "(*hostIDReaderBSD).read", "(hostIDReaderBSD).read"} {
		p := validImplementationProposal()
		p.Function = fn
		if err := p.Validate(); err != nil {
			t.Fatalf("function %q rejected: %v", fn, err)
		}
	}
}

func TestImplementationAdvisoryRefResolution(t *testing.T) {
	raw := strings.Repeat("ab", 32)
	canon := strings.Repeat("cd", 32)
	if err := ValidateImplementationAdvisoryRef("adv:GHSA-test-0001", "GHSA-test-0001", raw, canon); err != nil {
		t.Fatalf("adv ref rejected: %v", err)
	}
	if err := ValidateImplementationAdvisoryRef("sha256:"+raw, "GHSA-test-0001", raw, canon); err != nil {
		t.Fatalf("raw digest ref rejected: %v", err)
	}
	if err := ValidateImplementationAdvisoryRef("sha256:"+canon, "GHSA-test-0001", raw, canon); err != nil {
		t.Fatalf("canonical digest ref rejected: %v", err)
	}
	for _, ref := range []string{
		"adv:GHSA-other",
		"sha256:" + strings.Repeat("ef", 32),
		"adv:",
		"advisory:GHSA-test-0001",
	} {
		if err := ValidateImplementationAdvisoryRef(ref, "GHSA-test-0001", raw, canon); err == nil {
			t.Fatalf("ref %q accepted", ref)
		}
	}
}

func TestImplementationAdvisoryQuoteField(t *testing.T) {
	raw := []byte(`{"summary":"BSD helper command","details":"it calls ` + "`kenv`" + ` with a bare name"}`)
	fields := []struct {
		quote, want string
	}{
		{"calls `kenv`", ImplementationAdvisoryFieldDetails},
		{"BSD   helper\ncommand", ImplementationAdvisoryFieldSummary},
		{`"details":"it calls`, ImplementationAdvisoryFieldRawBody},
		{"a bare name", ImplementationAdvisoryFieldDetails},
		{"paraphrased summary", ""},
		{"", ""},
	}
	for _, f := range fields {
		if got := ImplementationAdvisoryQuoteField(f.quote, "BSD helper command", "it calls `kenv` with a bare name", raw); got != f.want {
			t.Fatalf("quote %q field = %q, want %q", f.quote, got, f.want)
		}
	}
}
