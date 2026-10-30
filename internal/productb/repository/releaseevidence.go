package repository

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// ReleaseEvidence is the outcome of snapshot-local release-toolchain
// discovery: the exact toolchain version the product was built with, where
// it was found, and a human-readable location. An empty Version means the
// release toolchain is UNKNOWN — callers must not substitute go.mod or the
// analysis toolchain for it.
type ReleaseEvidence struct {
	Version  string
	Source   domain.GoVersionSource
	Location string // file:line, for the evidence record
}

// goVersionLiteral matches an exact Go version literal ("1.22.8", "go1.22",
// "1.25.0"). A bare minor ("1.22") is only accepted where the source form
// itself normally pins the full release (go directive) — callers decide.
var (
	goVersionLiteral = regexp.MustCompile(`\b(?:go)?(\d+\.\d+(?:\.\d+)?)\b`)
	fromGolangImage  = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?golang:(\d+\.\d+(?:\.\d+)?)(?:[-@\s]|$)`)
	setupGoVersion   = regexp.MustCompile(`(?m)go-version:\s*['"]?v?(\d+\.\d+(?:\.\d+)?)['"]?`)
	// mise.toml style: go = "1.22.5" / golang = "1.22" / GOTOOLCHAIN="go1.23.1"
	miseGoKey = regexp.MustCompile(`(?m)^\s*(?:go|golang|GOTOOLCHAIN)\s*=\s*['"]?(?:go)?(\d+\.\d+(?:\.\d+)?)['"]?\s*$`)
)

// goToolNames are the asdf/mise tool spellings that pin the Go toolchain in
// a mixed .tool-versions file. Any other tool's version is NOT evidence —
// reading it as one is exactly the misattribution this prevents.
var goToolNames = map[string]bool{"go": true, "golang": true, "GOTOOLCHAIN": true}

// DiscoverReleaseEvidence looks for the release toolchain in the snapshot,
// in priority order: go.mod toolchain directive, Dockerfile FROM golang,
// CI setup-go, version files (.go-version/mise/asdf/.tool-versions) and
// release scripts that pin a literal version. It never executes anything.
//
// A partial tag (e.g. "1.22" in a Dockerfile image without a patch level) is
// still exact for that source form when the form is a full image tag; a value
// that is a variable or computed expression yields UNKNOWN.
func DiscoverReleaseEvidence(root string) ReleaseEvidence {
	if ev, ok := toolchainDirective(root); ok {
		return ev
	}
	if ev, ok := dockerfileEvidence(root); ok {
		return ev
	}
	if ev, ok := ciEvidence(root); ok {
		return ev
	}
	if ev, ok := versionFileEvidence(root); ok {
		return ev
	}
	if ev, ok := scriptEvidence(root); ok {
		return ev
	}
	return ReleaseEvidence{}
}

// toolchainDirective reads the go.mod `toolchain` directive, which names the
// exact toolchain a module expects.
func toolchainDirective(root string) (ReleaseEvidence, bool) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ReleaseEvidence{}, false
	}
	for i, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(trimmed, "toolchain ")
		if !ok {
			continue
		}
		v := strings.TrimSpace(rest)
		if m := goVersionLiteral.FindStringSubmatch(v); m != nil {
			return ReleaseEvidence{
				Version:  "go" + m[1],
				Source:   domain.GoVersionSourceToolchain,
				Location: "go.mod:" + itoa(i+1),
			}, true
		}
	}
	return ReleaseEvidence{}, false
}

// dockerfileEvidence reads `FROM golang:X` in a build stage. Only build
// stages are meaningful; a bare `golang:1.22` image without a patch level is
// accepted as-is because that is exactly what the source pins.
func dockerfileEvidence(root string) (ReleaseEvidence, bool) {
	for _, name := range []string{"Dockerfile", "docker/Dockerfile", "build/Dockerfile", "Dockerfile.build"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(b)
		if m := fromGolangImage.FindStringSubmatchIndex(content); m != nil {
			version := content[m[2]:m[3]]
			return ReleaseEvidence{
				Version:  "go" + version,
				Source:   domain.GoVersionSourceDockerfile,
				Location: name + ":" + itoa(lineOf(content, m[0])),
			}, true
		}
	}
	return ReleaseEvidence{}, false
}

// ciEvidence reads a setup-go `go-version:` field.
func ciEvidence(root string) (ReleaseEvidence, bool) {
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
			if m := setupGoVersion.FindStringSubmatchIndex(content); m != nil {
				return ReleaseEvidence{
					Version:  "go" + content[m[2]:m[3]],
					Source:   domain.GoVersionSourceCI,
					Location: d + "/" + e.Name() + ":" + itoa(lineOf(content, m[0])),
				}, true
			}
		}
	}
	return ReleaseEvidence{}, false
}

// versionFileEvidence reads a locally pinned Go version file. Each file
// type is parsed against its own grammar — .go-version is a bare version,
// .tool-versions is `<tool> <version>` lines, mise.toml is `[tools]`-style
// `tool = "version"` keys. In a mixed-tool file only the go/golang/
// GOTOOLCHAIN entry counts; a file whose go pin is ambiguous or non-literal
// yields no evidence rather than a wrong toolchain.
func versionFileEvidence(root string) (ReleaseEvidence, bool) {
	for _, name := range []string{".go-version", ".tool-versions", "mise.toml", ".mise.toml"} {
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(b)
		var version string
		switch name {
		case ".go-version":
			if m := goVersionLiteral.FindStringSubmatchIndex(content); m != nil {
				version = content[m[2]:m[3]]
			}
		case ".tool-versions":
			version = toolVersionsGoVersion(content)
		default: // mise.toml, .mise.toml
			if m := miseGoKey.FindStringSubmatch(content); m != nil {
				version = m[1]
			}
		}
		if version == "" {
			continue
		}
		return ReleaseEvidence{
			Version:  "go" + version,
			Source:   domain.GoVersionSourceVersionFile,
			Location: name,
		}, true
	}
	return ReleaseEvidence{}, false
}

// toolVersionsGoVersion extracts the go entry from an asdf-style
// .tool-versions file ("golang 1.22.5"). Other tools' versions are ignored;
// a non-literal pin ("latest", "system") or multiple conflicting go pins is
// ambiguous and returns "" — never a guessed toolchain.
func toolVersionsGoVersion(content string) string {
	version := ""
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if !goToolNames[fields[0]] {
			continue
		}
		for _, f := range fields[1:] {
			if m := goVersionLiteral.FindStringSubmatch(f); m != nil {
				if version != "" && version != m[1] {
					return "" // conflicting go pins — ambiguous file
				}
				version = m[1]
			}
		}
	}
	return version
}

// scriptEvidence statically scans common release scripts for a literal Go
// version pin. It never executes them; a variable or computed expression
// yields no evidence.
func scriptEvidence(root string) (ReleaseEvidence, bool) {
	candidates := []string{
		"Makefile", "makefile", "GNUmakefile",
		"build.sh", "scripts/build.sh", "hack/build.sh", ".goreleaser.yml", ".goreleaser.yaml",
	}
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
			return ReleaseEvidence{
				Version:  "go" + content[m[2]:m[3]],
				Source:   domain.GoVersionSourceVersionFile,
				Location: name + ":" + itoa(lineOf(content, m[0])),
			}, true
		}
	}
	return ReleaseEvidence{}, false
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
