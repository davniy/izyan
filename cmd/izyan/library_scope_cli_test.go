package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// libraryScopeCLICase mirrors the report-side synthetic library case: a TRUE
// attacker-control claim grounded in the proven public library API, an exact
// witness and UNKNOWN deployment origin.
func libraryScopeCLICase() *domain.AnalysisCase {
	w := domain.LibraryInputWitness{
		API:         domain.SymbolRef{Package: "github.com/stretchr/testify/assert", Symbol: "YAMLEq"},
		Declaration: domain.CallSite{File: "assert/assertions.go", Line: 1500, Function: "YAMLEq"},
		FormalIndex: 1,
		FormalName:  "expected",
		FormalType:  "string",
		Sink:        domain.SymbolRef{Package: "gopkg.in/yaml.v3", Symbol: "Unmarshal"},
		Site:        domain.CallSite{File: "assert/assertions.go", Line: 1573, Function: "YAMLEq"},
		Arg:         0,
		Steps: []domain.LibraryPayloadStep{{
			Kind: domain.LibraryPayloadByteConversion,
			Site: domain.CallSite{File: "assert/assertions.go", Line: 1571, Function: "YAMLEq"},
		}},
		ShapeFingerprint: "sha256:shape",
		EvidenceIDs:      []domain.EvidenceID{"EV-LIB-BINDING"},
	}
	return &domain.AnalysisCase{
		ID: "case-library-scope-cli",
		Vulnerability: domain.Vulnerability{
			ID:               "GHSA-lib-test",
			Module:           "gopkg.in/yaml.v3",
			AffectedPackages: []domain.AffectedPackage{{Path: "gopkg.in/yaml.v3"}},
			FixedVersions:    []string{"v3.0.1"},
		},
		Product: domain.ProductSnapshot{
			Repository: "github.com/stretchr/testify",
			Commit:     "abcdef1234567890",
			GoVersion:  "go1.23.0",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
			ResolvedVersion: "v3.0.0",
		},
		Claims: []domain.Claim{
			{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue},
			{ID: "CL-C-LOCUS", ConditionID: "C-LOCUS", Result: domain.ClaimTrue},
			{
				ID: "CL-C-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimTrue,
				ControlBasis: domain.ControlBasisLibraryPublicAPI,
			},
		},
		Verdict: &domain.VerdictResult{
			Verdict:             domain.VerdictExploitable,
			Reason:              "library public-API payload path proven",
			ExploitabilityScope: domain.ScopeLibraryAPI,
		},
		Profiles: []domain.ProfileVerdict{{
			Profile: domain.ProfileZeroTrust, Title: "Public Internet",
			Verdict: domain.VerdictExploitable, Priority: domain.PriorityP1,
			IsTargetActual: true, ExploitabilityScope: domain.ScopeLibraryAPI,
		}},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{{
				ConditionID:  "C-INPUT",
				Arg:          w.Arg,
				Origin:       domain.OriginUnknown,
				LibraryInput: &w,
			}},
		},
	}
}

func TestPrintCaseLibraryScope(t *testing.T) {
	c := libraryScopeCLICase()

	oldStdout := os.Stdout
	r, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = outW

	printCase(c, t.TempDir())

	outW.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	out := buf.String()

	ruLimitation := "Область library-API: полезная нагрузка выбирается потребителем библиотеки"
	want := []string{
		"exploitability_scope: library-api",
		"control_basis: C-INPUT=library-public-api",
		"target_profile: zero_trust (Verdict: EXPLOITABLE, Priority: P1, Scope: library-api)",
		"Exploitable — область публичного API библиотеки (`library-api`)",
		"Ограничение: " + ruLimitation,
		"выбираемая потребителем библиотеки",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("CLI output missing %q:\n%s", w, out)
		}
	}
	for _, forbidden := range []string{
		"удалённого клиента",
		"скомпилирован в бинарный файл",
		"0.0.0.0",
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("CLI output contains fabricated deployment fact %q:\n%s", forbidden, out)
		}
	}
}
