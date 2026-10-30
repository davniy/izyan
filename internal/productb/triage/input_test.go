package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

const validFindingJSON = `{
  "schema_version": "finding.v1",
  "finding_id": "scanner-123",
  "vulnerability": {
    "ids": ["CVE-2025-1234", "GHSA-abcd-efgh-ijkl"],
    "summary": "overflow in parser",
    "description": "long text",
    "references": ["https://example.com/adv"]
  },
  "component": {
    "name": "example.org/library",
    "version": "1.4.2",
    "ecosystem": "go",
    "package": "example.org/library/parser"
  },
  "target": {
    "repository": "/workspace/product",
    "revision": "abc123",
    "distribution": "linux",
    "image": "registry/product@sha256:deadbeef",
    "sbom": "sbom.json"
  },
  "scanner": {"severity": "high", "raw_text": "raw"}
}`

func sha256Hex(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestParseFindingsSingleObject(t *testing.T) {
	inputs, err := ParseFindings(strings.NewReader(validFindingJSON))
	if err != nil {
		t.Fatalf("ParseFindings: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("got %d findings, want 1", len(inputs))
	}
	in := inputs[0]
	if in.Finding.FindingID != "scanner-123" {
		t.Fatalf("finding_id = %q", in.Finding.FindingID)
	}
	if in.Finding.SchemaVersion != "finding.v1" {
		t.Fatalf("schema_version = %q", in.Finding.SchemaVersion)
	}
	if len(in.Finding.Vulnerability.IDs) != 2 {
		t.Fatalf("vulnerability ids = %v", in.Finding.Vulnerability.IDs)
	}
	if in.Finding.Component.Version != "1.4.2" {
		t.Fatalf("component version = %q", in.Finding.Component.Version)
	}
	if in.Finding.Target.Revision != "abc123" {
		t.Fatalf("target revision = %q", in.Finding.Target.Revision)
	}
	if len(in.Raw) == 0 {
		t.Fatal("raw bytes not preserved")
	}
	if got, want := in.SHA256, sha256Hex(t, in.Raw); got != want {
		t.Fatalf("sha256 = %q, want %q (hash of preserved raw bytes)", got, want)
	}
}

func TestParseFindingsJSONArray(t *testing.T) {
	input := `[` + validFindingJSON + `,
{"schema_version":"finding.v1","finding_id":"scanner-456","vulnerability":{"ids":["CVE-2025-9999"]}}
]`
	inputs, err := ParseFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseFindings: %v", err)
	}
	if len(inputs) != 2 {
		t.Fatalf("got %d findings, want 2", len(inputs))
	}
	if inputs[0].Finding.FindingID != "scanner-123" || inputs[1].Finding.FindingID != "scanner-456" {
		t.Fatalf("ids = %q, %q", inputs[0].Finding.FindingID, inputs[1].Finding.FindingID)
	}
	for i, in := range inputs {
		if len(in.Raw) == 0 || in.SHA256 != sha256Hex(t, in.Raw) {
			t.Fatalf("input %d: raw/hash not populated", i)
		}
	}
}

func TestParseFindingsJSONL(t *testing.T) {
	line1 := `{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-2025-0001"]}}`
	line2 := `{"schema_version":"finding.v1","finding_id":"f-2","vulnerability":{"ids":["CVE-2025-0002"]}}`
	input := line1 + "\n\n   \n" + line2 + "\n"
	inputs, err := ParseFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseFindings: %v", err)
	}
	if len(inputs) != 2 {
		t.Fatalf("got %d findings, want 2 (blank lines must be skipped)", len(inputs))
	}
	if inputs[0].Finding.FindingID != "f-1" || inputs[1].Finding.FindingID != "f-2" {
		t.Fatalf("ids = %q, %q", inputs[0].Finding.FindingID, inputs[1].Finding.FindingID)
	}
}

func TestParseFindingsJSONLMalformedLine(t *testing.T) {
	line1 := `{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-2025-0001"]}}`
	input := line1 + "\n\n" + `{"schema_version":` + "\n"
	_, err := ParseFindings(strings.NewReader(input))
	if err == nil {
		t.Fatal("malformed non-empty line must fail")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("error must report line number, got: %v", err)
	}
}

func TestInvalidFinding(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSub string
	}{
		{"empty input", "", "empty"},
		{"whitespace only", "  \n\t\n", "empty"},
		{"empty array", "[]", "no finding"},
		{"malformed json", `{"schema_version": "finding.v1", "finding_id":`, "line 1"},
		{"wrong schema version",
			`{"schema_version":"finding.v2","finding_id":"f-1","vulnerability":{"ids":["CVE-1"]}}`,
			"finding.v1"},
		{"missing schema version",
			`{"finding_id":"f-1","vulnerability":{"ids":["CVE-1"]}}`,
			"finding.v1"},
		{"empty finding_id",
			`{"schema_version":"finding.v1","finding_id":"","vulnerability":{"ids":["CVE-1"]}}`,
			"finding_id"},
		{"missing finding_id",
			`{"schema_version":"finding.v1","vulnerability":{"ids":["CVE-1"]}}`,
			"finding_id"},
		{"no vulnerability ids",
			`{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"summary":"x"}}`,
			"vulnerability"},
		{"empty vulnerability id",
			`{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":[""]}}`,
			"vulnerability"},
		{"duplicate ids in array",
			`[{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-1"]}},` +
				`{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-2"]}}]`,
			"duplicate"},
		{"duplicate ids in jsonl",
			`{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-1"]}}` + "\n" +
				`{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-2"]}}`,
			"duplicate"},
		{"non-object line in jsonl",
			`{"schema_version":"finding.v1","finding_id":"f-1","vulnerability":{"ids":["CVE-1"]}}` + "\n" +
				`"just a string"`,
			"line 2"},
		{"tracker-shaped document without finding.v1",
			`{"key":"EXAMPLE-1","status":"Open","fields":{"descriptionPlain":"see CVE-2099-0001"}}`,
			"finding.v1"},
		{"plain text is not a finding", `scanner reported an overflow`, "must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFindings(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q must contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestParseFindingsTrailingGarbage(t *testing.T) {
	_, err := ParseFindings(strings.NewReader(validFindingJSON + "\nnot json"))
	if err == nil {
		t.Fatal("trailing non-empty garbage must fail")
	}
}

// operatorTarget is one canonical operator-declared build selection.
func operatorTarget(goos, goarch string, tags []string, cgo bool) domain.ProductTarget {
	return domain.ProductTarget{
		GOOS: goos, GOARCH: goarch, BuildTags: tags, CGOEnabled: cgo,
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
}

// buildFinding attaches a declared build to a minimal valid finding.
func buildFinding(build *domain.ProductTarget) FindingInput {
	raw := []byte(`{"schema_version":"finding.v1","finding_id":"f-target","vulnerability":{"ids":["CVE-2026-0001"]}}`)
	return FindingInput{
		Finding: Finding{
			SchemaVersion: FindingSchemaVersion, FindingID: "f-target",
			Vulnerability: Vulnerability{IDs: []string{"CVE-2026-0001"}},
			Target:        Target{Build: build},
		},
		Raw: raw, SHA256: hashBytes(raw),
	}
}

func buildManifest(artifactSHA string) SnapshotManifest {
	return SnapshotManifest{
		SchemaVersion: SnapshotSchemaVersion, FindingID: "f-target",
		Artifacts: []SnapshotFile{{Path: "bin/product", Role: "binary", SHA256: artifactSHA, Size: 10}},
	}
}

// TestResolveBuildTargetRules pins the declaration admission contract:
// absent stays absent, one channel resolves, two channels must agree, the
// host is never a product target and artifact-derived authority must stay
// bound to the artifact bytes the snapshot captured.
func TestResolveBuildTargetRules(t *testing.T) {
	target := operatorTarget("linux", "amd64", []string{"netgo", "osusergo"}, true)
	sorted := operatorTarget("linux", "amd64", []string{"netgo", "osusergo"}, true)
	for _, tc := range []struct {
		name    string
		finding *domain.ProductTarget
		bundle  string
		wantNil bool
		wantErr []string
	}{
		{name: "absent", wantNil: true},
		{name: "finding only", finding: &target},
		{name: "bundle only", bundle: `{"goos":"linux","goarch":"amd64","build_tags":["osusergo","netgo"],"cgo_enabled":true,"source":"operator-declared","scope":"operator"}`},
		{name: "same declaration both channels", finding: &target, bundle: `{"goos":"linux","goarch":"amd64","build_tags":["netgo","osusergo"],"cgo_enabled":true,"source":"operator-declared","scope":"operator"}`},
		{name: "platform conflict", finding: &target, bundle: `{"goos":"linux","goarch":"arm64","build_tags":["netgo","osusergo"],"cgo_enabled":true,"source":"operator-declared","scope":"operator"}`, wantErr: []string{"conflicting product build declarations", "goarch"}},
		{name: "host default rejected", bundle: `{"goos":"linux","goarch":"amd64","build_tags":[],"cgo_enabled":false,"source":"host-default"}`, wantErr: []string{"analysis context", "never a product build target"}},
		{name: "artifact authority unbound", bundle: `{"goos":"linux","goarch":"amd64","build_tags":[],"cgo_enabled":true,"source":"artifact-build-info","scope":"artifact","artifact_sha256":"` + strings.Repeat("a", 64) + `","build_info_sha256":"` + strings.Repeat("b", 64) + `"}`, wantErr: []string{"matches no binary captured", "artifact-build-info"}},
		{name: "artifact authority bound", bundle: `{"goos":"linux","goarch":"amd64","build_tags":["netgo","osusergo"],"cgo_enabled":true,"source":"artifact-build-info","scope":"artifact","artifact_sha256":"` + strings.Repeat("c", 64) + `","build_info_sha256":"` + strings.Repeat("d", 64) + `"}`},
		{name: "unknown field rejected", bundle: `{"goos":"linux","goarch":"amd64","source":"operator-declared","scope":"operator","toolchain":"go1.25"}`, wantErr: []string{"unknown field"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := InvestigationInputs{}
			if tc.bundle != "" {
				inv.Build = json.RawMessage(tc.bundle)
			}
			got, err := ResolveBuildTarget(buildFinding(tc.finding), inv, buildManifest(strings.Repeat("c", 64)))
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("ResolveBuildTarget = %+v, want error", got)
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %v, want %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveBuildTarget: %v", err)
			}
			if tc.wantNil {
				if got != nil {
					t.Fatalf("resolved target = %+v, want absent", got)
				}
				return
			}
			if got == nil {
				t.Fatal("ResolveBuildTarget returned no target")
			}
			if got.GOOS != target.GOOS || got.GOARCH != target.GOARCH || got.CGOEnabled != target.CGOEnabled {
				t.Fatalf("resolved target = %+v, want the declared selection", *got)
			}
			if !sameBuildTags(got.BuildTags, sorted.BuildTags) {
				t.Fatalf("resolved tags = %v, want %v", got.BuildTags, sorted.BuildTags)
			}
		})
	}
}
