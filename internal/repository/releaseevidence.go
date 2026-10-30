package repository

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// goVersionLiteral matches an exact Go version literal ("1.22.8", "go1.22",
// "1.25.0"). A bare minor ("1.22") is only accepted where the source form
// itself normally pins the full release (go directive) — callers decide.
var (
	goVersionLiteral       = regexp.MustCompile(`\b(?:go)?(\d+\.\d+(?:\.\d+)?)\b`)
	fromGolangImage        = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?golang:(\d+\.\d+(?:\.\d+)?)(?:[-@\s]|$)`)
	setupGoVersion         = regexp.MustCompile(`(?m)go-version:\s*['"]?v?(\d+\.\d+(?:\.\d+)?)['"]?`)
	goModGoDirective       = regexp.MustCompile(`(?m)^\s*go\s+(\d+\.\d+(?:\.\d+)?)\s*(?://.*)?$`)
	goModToolchain         = regexp.MustCompile(`(?m)^\s*toolchain\s+(\S+)`)
	toolVersionsGo         = regexp.MustCompile(`(?m)^\s*(?:golang|go)\s+v?(\d+\.\d+(?:\.\d+)?)`)
	miseTomlGo             = regexp.MustCompile(`(?m)^\s*go\s*=\s*["']v?(\d+\.\d+(?:\.\d+)?)["']`)
	normalizeVersionPrefix = regexp.MustCompile(`^(?:go|v)`)
	releaseVersionDigits   = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
)

// supportingItem records one snapshot-local declaration. Every source file
// the snapshot contains is declarable build input: it is corroboration
// evidence only and can never ground a version-based determination alone.
func supportingItem(version string, source domain.GoVersionSource, location string) domain.ReleaseEvidenceItem {
	return domain.ReleaseEvidenceItem{
		Version:    version,
		Source:     source,
		TrustClass: domain.ReleaseTrustSupporting,
		Location:   location,
	}
}

// DiscoverReleaseEvidence collects every release-toolchain declaration in
// the snapshot — go.mod go/toolchain directives, Dockerfile FROM golang,
// CI setup-go, version files (.go-version/mise/asdf/.tool-versions) and
// release scripts that pin a literal version. It never executes anything.
//
// All snapshot-local declarations are classified SUPPORTING: they may
// corroborate an authoritative version but can never establish one, so the
// returned summary resolves only when the item set also carries
// AUTHORITATIVE evidence supplied through ResolveReleaseEvidence.
//
// A partial tag (e.g. "1.22" in a Dockerfile image without a patch level) is
// still recorded for that source form when the form is a full image tag; a
// value that is a variable or computed expression yields no evidence.
func DiscoverReleaseEvidence(root string) domain.ReleaseEvidenceSummary {
	var items []domain.ReleaseEvidenceItem
	items = append(items, goModDeclarations(root)...)
	items = append(items, dockerfileEvidence(root)...)
	items = append(items, ciEvidence(root)...)
	items = append(items, versionFileEvidence(root)...)
	items = append(items, scriptEvidence(root)...)
	return ResolveReleaseEvidence(items)
}

// ResolveReleaseEvidence applies the trust-class precedence to an evidence
// item set:
//
//  1. AUTHORITATIVE items (release binary build info, explicitly supplied
//     ticket/SBOM release metadata) that agree after normalization resolve
//     the release version.
//  2. Disagreeing AUTHORITATIVE items produce CONFLICTED with no selected
//     version — never the first or newest value.
//  3. SUPPORTING items corroborate a resolved version; a disagreeing
//     supporting item is kept in the item list as recorded limitation
//     provenance but cannot override, and supporting-only evidence leaves
//     the release toolchain UNKNOWN.
//  4. No items means absent evidence — UNKNOWN, not a selected version.
func ResolveReleaseEvidence(items []domain.ReleaseEvidenceItem) domain.ReleaseEvidenceSummary {
	summary := domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusUnknown,
		Items:  items,
	}
	if len(items) == 0 {
		summary.ReasonCode = domain.ReleaseReasonAbsent
		return summary
	}
	var selected *domain.ReleaseEvidenceItem
	selectedNorm := ""
	conflict := false
	invalid := false
	for i := range items {
		it := &items[i]
		if it.TrustClass != domain.ReleaseTrustAuthoritative {
			continue
		}
		norm := normalizeReleaseVersion(it.Version)
		if norm == "" {
			invalid = true
			continue
		}
		if selected == nil {
			selected, selectedNorm = it, norm
			continue
		}
		if norm != selectedNorm {
			conflict = true
		}
	}
	if invalid {
		summary.Status = domain.ReleaseStatusConflicted
		summary.ReasonCode = domain.ReleaseReasonReleaseVersionInvalid
		return summary
	}
	if conflict {
		summary.Status = domain.ReleaseStatusConflicted
		summary.ReasonCode = domain.ReleaseReasonConflict
		return summary
	}
	if selected == nil {
		summary.ReasonCode = domain.ReleaseReasonSupportingOnly
		return summary
	}
	summary.Status = domain.ReleaseStatusResolved
	summary.SelectedVersion = selected.Version
	summary.SelectedSource = selected.Source
	summary.SelectedTrust = domain.ReleaseTrustAuthoritative
	summary.ArtifactSHA256 = selected.ArtifactSHA256
	summary.BinaryMember = selected.BinaryMember
	summary.BuildInfoSHA256 = selected.BuildInfoSHA256
	return summary
}

// normalizeReleaseVersion reduces a declared Go version to a canonical
// "M.m.p" digit triple for agreement comparison: the "go"/"v" prefixes and
// platform suffixes ("1.25.8-ubi9") collapse, and a bare minor pads to .0 —
// "1.25" names the same toolchain line as "go1.25.0". A value that is not a
// literal version yields "" and the item cannot participate in a selection.
func normalizeReleaseVersion(v string) string {
	v = strings.TrimSpace(v)
	v = normalizeVersionPrefix.ReplaceAllString(v, "")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		suffix := v[i+1:]
		if isPlatformSuffix(suffix) {
			v = v[:i]
		}
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	m := releaseVersionDigits.FindStringSubmatch(v)
	if m == nil {
		return ""
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	out := m[1] + "." + m[2] + "." + patch
	if m[4] != "" {
		out += "-" + m[4]
	}
	return out
}

func isPlatformSuffix(s string) bool {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "ubi") {
		_, err := strconv.Atoi(strings.TrimPrefix(s, "ubi"))
		return err == nil
	}
	switch s {
	case "alpine", "bookworm", "bullseye", "buster", "slim":
		return true
	default:
		return false
	}
}

// goModDeclarations reads the go.mod `go` directive (the language minimum,
// still only a declaration) and every `toolchain` directive.
func goModDeclarations(root string) []domain.ReleaseEvidenceItem {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil
	}
	content := string(b)
	var items []domain.ReleaseEvidenceItem
	for _, m := range goModGoDirective.FindAllStringSubmatchIndex(content, -1) {
		items = append(items, supportingItem(
			"go"+content[m[2]:m[3]],
			domain.GoVersionSourceGoMod,
			"go.mod:"+itoa(lineOf(content, m[0])),
		))
	}
	for _, m := range goModToolchain.FindAllStringSubmatchIndex(content, -1) {
		v := content[m[2]:m[3]]
		lit := goVersionLiteral.FindStringSubmatch(v)
		if lit == nil {
			continue // a non-literal toolchain name is not a version pin
		}
		items = append(items, supportingItem(
			"go"+lit[1],
			domain.GoVersionSourceToolchain,
			"go.mod:"+itoa(lineOf(content, m[0])),
		))
	}
	return items
}

// dockerfileEvidence reads `FROM golang:X` in build stages. Every declared
// build stage is a separate observation; a bare `golang:1.22` image without
// a patch level is recorded as-is because that is exactly what the source
// pins.
func dockerfileEvidence(root string) []domain.ReleaseEvidenceItem {
	var items []domain.ReleaseEvidenceItem
	for _, name := range []string{"Dockerfile", "docker/Dockerfile", "build/Dockerfile", "Dockerfile.build"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(b)
		for _, m := range fromGolangImage.FindAllStringSubmatchIndex(content, -1) {
			items = append(items, supportingItem(
				"go"+content[m[2]:m[3]],
				domain.GoVersionSourceDockerfile,
				name+":"+itoa(lineOf(content, m[0])),
			))
		}
	}
	return items
}

// ciEvidence reads a setup-go `go-version:` field in CI configurations.
func ciEvidence(root string) []domain.ReleaseEvidenceItem {
	var items []domain.ReleaseEvidenceItem
	dirs := []string{".github/workflows", ".gitlab", ".circleci"}
	for _, d := range dirs {
		base := filepath.Join(root, filepath.FromSlash(d))
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(base, e.Name())
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				continue
			}
			content := string(b)
			for _, m := range setupGoVersion.FindAllStringSubmatchIndex(content, -1) {
				items = append(items, supportingItem(
					"go"+content[m[2]:m[3]],
					domain.GoVersionSourceCI,
					d+"/"+e.Name()+":"+itoa(lineOf(content, m[0])),
				))
			}
		}
	}
	return items
}

// versionFileEvidence reads locally pinned Go version files. Only the Go
// key counts: .tool-versions and mise.toml carry many tool versions, so a
// generic literal scan would mislabel unrelated pins as Go declarations.
func versionFileEvidence(root string) []domain.ReleaseEvidenceItem {
	var items []domain.ReleaseEvidenceItem
	if b, err := os.ReadFile(filepath.Join(root, ".go-version")); err == nil {
		content := string(b)
		if m := goVersionLiteral.FindStringSubmatchIndex(content); m != nil {
			items = append(items, supportingItem(
				"go"+content[m[2]:m[3]],
				domain.GoVersionSourceVersionFile,
				".go-version:"+itoa(lineOf(content, m[0])),
			))
		}
	}
	for _, name := range []string{".tool-versions", "mise.toml", ".mise.toml"} {
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(b)
		re := toolVersionsGo
		if strings.HasSuffix(name, ".toml") {
			re = miseTomlGo
		}
		if m := re.FindStringSubmatchIndex(content); m != nil {
			items = append(items, supportingItem(
				"go"+content[m[2]:m[3]],
				domain.GoVersionSourceVersionFile,
				name+":"+itoa(lineOf(content, m[0])),
			))
		}
	}
	return items
}

// scriptEvidence statically scans common release scripts for a literal Go
// version pin. It never executes them; a variable or computed expression
// yields no evidence.
func scriptEvidence(root string) []domain.ReleaseEvidenceItem {
	candidates := []string{
		"Makefile", "makefile", "GNUmakefile",
		"build.sh", "scripts/build.sh", "hack/build.sh", ".goreleaser.yml", ".goreleaser.yaml",
	}
	var items []domain.ReleaseEvidenceItem
	for _, name := range candidates {
		path := filepath.Join(root, filepath.FromSlash(name))
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(b)
		if !pinsGoVersion(content) {
			continue
		}
		if m := goVersionLiteral.FindStringSubmatchIndex(content); m != nil {
			items = append(items, supportingItem(
				"go"+content[m[2]:m[3]],
				domain.GoVersionSourceVersionFile,
				name+":"+itoa(lineOf(content, m[0])),
			))
		}
	}
	return items
}

// pinsGoVersion reports whether the text carries a recognisable, literal Go
// version binding form. A bare version string elsewhere in a script is not a
// release pin.
func pinsGoVersion(content string) bool {
	markers := []string{"golang.org/dl/go", "GOTOOLCHAIN=go", "go-version", "--go-version", "GOLANG_VERSION"}
	for _, m := range markers {
		if strings.Contains(content, m) {
			return true
		}
	}
	return false
}

// lineOf returns the 1-based line number of byte offset off.
func lineOf(content string, off int) int {
	if off > len(content) {
		off = len(content)
	}
	return strings.Count(content[:off], "\n") + 1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
