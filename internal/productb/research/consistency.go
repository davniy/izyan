package research

// Host-fact consistency layer: compares what the agent's answer says with
// the two independent fact sources the run already has — the resolved OSV
// advisory (affected module entries + version ranges) and the snapshot's
// file-level module graph (go.mod require/replace, vendor/modules.txt,
// go.sum). The layer never rewrites the answer and never promotes a check
// into a verdict: every output is either a neutral per-entry fact
// (presence / resolved version / range status) or a finding that records
// a bounded, stated tension for the reviewer to settle — never a
// refutation and never a category substitution.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// absenceCaveat is the standing rule attached to the consistency section:
// a negative lookup is recorded evidence, never a negative proof.
const absenceCaveat = "Not finding a component or a path is not proof that no " +
	"exploitation path exists: the module graph and the file tree record only " +
	"declared dependencies and present files, never all the ways code can be " +
	"reached. Absence findings narrow the search; they never close it."

// presenceNote states what the citation check actually established.
const presenceNote = "a cited path found in the snapshot is a presence check " +
	"only — it does not confirm the claim the agent made about that path"

// safeCategories are the non-vulnerable research categories: each claims
// reduced or absent exposure. The host can never confirm such a category
// — module presence/version facts say nothing about reachability of the
// specific vulnerable operation — so every one is recorded as
// unsupported-by-host (safe_category_unsupported), and `code_not_present`
// additionally collides with a present module only as a
// category_absence_tension, never as a refutation.
var safeCategories = map[string]bool{
	"false_positive": true, "code_not_present": true, "code_not_reachable": true,
	"requires_configuration": true, "requires_dependency": true,
	"requires_environment": true, "compiler_protected": true,
	"runtime_protected": true, "perimeter_protected": true,
	"mitigating_control_protected": true,
}

// ConsistencyEntry is the host-fact status of one advisory affected entry.
// Presence reports where the module was found (or that it was not); the
// range status compares the resolved version against the advisory range.
// "unverifiable" always means the host could not decide — it never means
// the check passed.
type ConsistencyEntry struct {
	Module          string   `json:"module"`
	AdvisoryRanges  []string `json:"advisory_ranges,omitempty"`
	FixedVersions   []string `json:"fixed_versions,omitempty"`
	Presence        string   `json:"presence"` // present | absent_from_graph | unknown
	ResolvedVersion string   `json:"resolved_version,omitempty"`
	RangeStatus     string   `json:"range_status"`          // in_range | out_of_range | unverifiable
	Evidence        string   `json:"evidence"`              // which file the fact came from
	Statement       string   `json:"statement"`             // plain-language record
	DocumentID      string   `json:"document_id,omitempty"` // advisory document the entry came from
	Attempt         string   `json:"attempt"`
	SnapshotHash    string   `json:"snapshot_hash"`
}

// ConsistencyFinding is one visible inconsistency between the answer and
// the host facts. Kinds: category_absence_tension |
// reachability_not_established | mechanism_alignment_not_established |
// coverage_incomplete | version_mismatch | safe_category_unsupported.
// A finding never asserts absence of all exploitation paths and never
// substitutes the agent's category — it shows the mismatch and the
// evidence behind it.
type ConsistencyFinding struct {
	Kind         string `json:"kind"`
	Statement    string `json:"statement"`
	Evidence     string `json:"evidence"`
	Attempt      string `json:"attempt"`
	SnapshotHash string `json:"snapshot_hash"`
}

// ConsistencyReport is the host-fact consistency block of report.json.
// State is "assessed" when an advisory with affected entries was resolved,
// "not_assessed" otherwise — absence of the block is never rendered as
// "all entries consistent".
type ConsistencyReport struct {
	State    string               `json:"state"` // assessed | not_assessed
	Reason   string               `json:"reason,omitempty"`
	Entries  []ConsistencyEntry   `json:"entries"`
	Findings []ConsistencyFinding `json:"findings"`
	Caveat   string               `json:"absence_caveat"`
}

// moduleVersion is one resolved module in the snapshot's file-level graph.
type moduleVersion struct {
	version  string // resolved version; "" when undecidable (e.g. local replace)
	evidence string // which file supplied the fact
}

// moduleIndex is the merged module graph read directly from go.mod,
// vendor/modules.txt and go.sum — the same file-level method
// moduleGraphFacts uses, extended with per-module resolved versions.
type moduleIndex struct {
	mods          map[string]moduleVersion
	main          string // the snapshot's own module path
	goModPresent  bool
	vendorPresent bool
	goSumPresent  bool
}

// readModuleVersions builds the per-module version index. It never fails:
// unreadable or absent files simply narrow what is known, and every lookup
// reports which file supplied (or failed to supply) the fact.
func readModuleVersions(root string) *moduleIndex {
	idx := &moduleIndex{mods: map[string]moduleVersion{}}

	if b, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		idx.goModPresent = true
		if f, perr := modfile.Parse("go.mod", b, nil); perr == nil {
			if f.Module != nil {
				idx.main = f.Module.Mod.Path
			}
			for _, r := range f.Require {
				idx.mods[r.Mod.Path] = moduleVersion{
					version:  r.Mod.Version,
					evidence: "go.mod require",
				}
			}
			for _, r := range f.Replace {
				mv, has := idx.mods[r.Old.Path]
				if !has {
					continue // replace without require is not part of the graph
				}
				if isLocalReplaceTarget(r.New.Path) {
					mv.version = ""
					mv.evidence = "go.mod replace → local path " + r.New.Path
				} else {
					mv.version = r.New.Version
					mv.evidence = "go.mod replace → " + r.New.Path + " " + r.New.Version
				}
				idx.mods[r.Old.Path] = mv
			}
		}
	}

	if b, err := os.ReadFile(filepath.Join(root, "vendor", "modules.txt")); err == nil {
		idx.vendorPresent = true
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "# ") {
				continue
			}
			fields := strings.Fields(strings.TrimSpace(line[2:]))
			if len(fields) == 0 {
				continue
			}
			ver := ""
			if len(fields) > 1 {
				ver = fields[1]
			}
			// The vendored copy is what the build actually compiles; it
			// wins over a go.mod require line whenever both exist.
			idx.mods[fields[0]] = moduleVersion{version: ver, evidence: "vendor/modules.txt"}
		}
	}

	if b, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
		idx.goSumPresent = true
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			mod, ver := fields[0], strings.TrimSuffix(fields[1], "/go.mod")
			mv, has := idx.mods[mod]
			if has && mv.evidence != "go.sum only" {
				continue // a stronger source already resolved it
			}
			if has && !strings.Contains(mv.version, ver) {
				mv.version += ", " + ver
				idx.mods[mod] = mv
				continue
			}
			idx.mods[mod] = moduleVersion{version: ver, evidence: "go.sum only"}
		}
	}
	return idx
}

// graphLoaded reports whether any module-graph source was readable — the
// precondition for "absent_from_graph" to mean anything at all.
func (idx *moduleIndex) graphLoaded() bool {
	return idx.goModPresent || idx.vendorPresent || idx.goSumPresent
}

// lookup resolves a module against the index. The stdlib pseudo-module is
// resolved against the snapshot's toolchain evidence instead.
func (idx *moduleIndex) lookup(mod, toolchainVersion, toolchainEvidence string) (moduleVersion, bool) {
	if mod == "stdlib" {
		if toolchainVersion == "" {
			return moduleVersion{evidence: "no Go toolchain version recorded"}, false
		}
		return moduleVersion{version: toolchainVersion, evidence: toolchainEvidence}, true
	}
	mv, ok := idx.mods[mod]
	return mv, ok
}

// stdlibVersion picks the best toolchain version evidence for a `stdlib`
// advisory entry: release toolchain first, then the go.mod toolchain
// directive, then the go directive (a language floor — a lower bound only).
func stdlibVersion(r *Report) (version, evidence string) {
	switch {
	case r.Snapshot.ReleaseGoVersion != "":
		return r.Snapshot.ReleaseGoVersion, "snapshot release toolchain"
	case r.Snapshot.Module.Toolchain != "":
		return r.Snapshot.Module.Toolchain, "go.mod toolchain directive"
	case r.Snapshot.Module.GoDirective != "":
		return "go" + r.Snapshot.Module.GoDirective, "go.mod go directive (lower bound — language version, not toolchain)"
	case r.Snapshot.GoVersion != "":
		return r.Snapshot.GoVersion, "analysis go version"
	}
	return "", ""
}

// displayRange renders one advisory version range in OSV notation:
// [introduced, fixed) or [introduced, last_affected].
func displayRange(r pbdomain.VersionRange) string {
	lo := r.Introduced
	if lo == "" {
		lo = "0"
	}
	switch {
	case r.Fixed != "":
		return "[" + lo + ", " + r.Fixed + ")"
	case r.LastAffected != "":
		return "[" + lo + ", " + r.LastAffected + "]"
	default:
		return "[" + lo + ", ∞)"
	}
}

// versionInRanges reports whether resolved falls inside any of the OSV
// ranges ([introduced, fixed) / [introduced, last_affected] semantics).
// ok is false when either side cannot be read as semver — that is the
// "unverifiable" case, deliberately distinct from "out of range".
func versionInRanges(resolved string, ranges []pbdomain.VersionRange) (in bool, ok bool) {
	v := normalizeResearchVersion(resolved)
	if v == "" || len(ranges) == 0 {
		return false, false
	}
	for _, r := range ranges {
		if inResearchRange(v, r) {
			return true, true
		}
	}
	return false, true
}

func inResearchRange(v string, r pbdomain.VersionRange) bool {
	if r.Introduced != "" {
		lo := normalizeResearchVersion(r.Introduced)
		if lo != "" && semver.Compare(v, lo) < 0 {
			return false
		}
	}
	if r.Fixed != "" {
		hi := normalizeResearchVersion(r.Fixed)
		if hi == "" || semver.Compare(v, hi) >= 0 {
			return false
		}
		return true
	}
	if r.LastAffected != "" {
		hi := normalizeResearchVersion(r.LastAffected)
		if hi == "" {
			return false
		}
		return semver.Compare(v, hi) <= 0
	}
	return true
}

// normalizeResearchVersion maps OSV/Go version spellings onto canonical
// semver ("0" marks the beginning of history; "go1.2.3" is a toolchain
// spelling). "" means the input cannot be interpreted as a version.
func normalizeResearchVersion(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "", "0":
		return ""
	}
	s = strings.TrimPrefix(s, "go")
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return ""
	}
	return semver.Canonical(s)
}

// fixVersionRx finds version claims in a fix/patch context. The captured
// version must be either v-prefixed or a full three-part semver so prose
// numbers ("fixed 1.5 hours of work") cannot match.
var fixVersionRx = regexp.MustCompile(`(?i)\b(?:fix(?:e[ds])?|patch(?:ed|es)?|upgrad\w*|mitigat\w*|resolv\w*|correct\w*)\b[^0-9]{0,30}?(v\d+\.\d+[\w.-]*|\d+\.\d+\.\d+[\w.-]*)`)

// assessConsistency evaluates the advisory's comparable Go affected
// entries against the snapshot module graph and derives the explicit
// findings the reviewer must see. It runs identically for planned runs
// (no answer yet — the per-entry facts still stand) and executed ones.
// When no advisory document could supply a Go-ecosystem affected entry —
// the common shape of CVE-centric documents whose entries are CPE/GIT —
// the layer reports `advisory_uncomparable` (state not_assessed): the
// module graph was never compared, so no coverage finding can be made.
func assessConsistency(o Options, r *Report, ares advisoryResult) ConsistencyReport {
	cr := ConsistencyReport{
		State:    "assessed",
		Entries:  []ConsistencyEntry{},
		Findings: []ConsistencyFinding{},
		Caveat:   absenceCaveat,
	}
	if len(ares.affected) == 0 {
		cr.State = "not_assessed"
		switch {
		case ares.info.Status != "resolved":
			cr.Reason = "no resolved advisory document — nothing to compare the answer against"
		case ares.uncomparable > 0:
			cr.Reason = fmt.Sprintf("advisory_uncomparable: the resolved advisory documents list %d affected entries but none names a Go module — the snapshot's module graph was never compared", ares.uncomparable)
		default:
			cr.Reason = "advisory_uncomparable: the resolved advisory documents declare no Go-ecosystem affected entries — the snapshot's module graph was never compared"
		}
		if r.Answer.Parsed {
			cr.Findings = safeCategoryUnsupportedFindings(r, len(ares.affected) == 0, cr.Findings)
		}
		return cr
	}
	idx := readModuleVersions(o.SnapshotDir)
	stdVer, stdEvidence := stdlibVersion(r)

	var affected []pbdomain.AffectedModule
	named := map[string]bool{}
	for _, ref := range ares.affected {
		affected = append(affected, ref.am)
		named[ref.am.Module] = r.Answer.Parsed && strings.Contains(r.Answer.Reasoning, ref.am.Module)
	}

	var presentEntries []ConsistencyEntry
	for i, ref := range ares.affected {
		am := affected[i]
		e := ConsistencyEntry{Module: am.Module, FixedVersions: am.FixedVersions, DocumentID: ref.doc.ID}
		for _, rg := range am.AffectedVersions {
			e.AdvisoryRanges = append(e.AdvisoryRanges, displayRange(rg))
		}
		mv, found := idx.lookup(am.Module, stdVer, stdEvidence)
		switch {
		case found:
			e.Presence = "present"
			e.ResolvedVersion = mv.version
			e.Evidence = mv.evidence
		case idx.graphLoaded():
			e.Presence = "absent_from_graph"
			e.Evidence = "not listed in go.mod / vendor/modules.txt / go.sum"
		default:
			e.Presence = "unknown"
			e.Evidence = "no readable module graph files (go.mod, vendor/modules.txt, go.sum)"
		}

		rangeText := strings.Join(e.AdvisoryRanges, ", ")
		switch e.Presence {
		case "present":
			switch {
			case len(am.AffectedVersions) == 0:
				e.RangeStatus = "unverifiable"
				e.Statement = fmt.Sprintf("affected module `%s` is present (version `%s`, %s) but the advisory declares no version range for it — the range check cannot run",
					e.Module, orNone2(e.ResolvedVersion), e.Evidence)
			case e.ResolvedVersion == "":
				e.RangeStatus = "unverifiable"
				e.Statement = fmt.Sprintf("affected module `%s` is present but its version is undecidable (%s) — cannot be compared with the advisory range %s",
					e.Module, e.Evidence, rangeText)
			default:
				in, ok := versionsInRanges(e.ResolvedVersion, am.AffectedVersions)
				switch {
				case !ok:
					e.RangeStatus = "unverifiable"
					e.Statement = fmt.Sprintf("affected module `%s` is present at `%s` (%s) which is not readable as semver — cannot be compared with the advisory range %s",
						e.Module, e.ResolvedVersion, e.Evidence, rangeText)
				case in:
					e.RangeStatus = "in_range"
					e.Statement = fmt.Sprintf("affected module `%s` is present at version `%s` (%s), inside the advisory range %s",
						e.Module, e.ResolvedVersion, e.Evidence, rangeText)
				default:
					e.RangeStatus = "out_of_range"
					e.Statement = fmt.Sprintf("affected module `%s` is present at version `%s` (%s), outside the advisory range %s",
						e.Module, e.ResolvedVersion, e.Evidence, rangeText)
				}
			}
		case "absent_from_graph":
			e.RangeStatus = "unverifiable"
			e.Statement = fmt.Sprintf("affected module `%s` was not found in the snapshot's module graph (%s) — the version check is not evaluated. This is not proof that no exploitation path exists", e.Module, e.Evidence)
		default:
			e.RangeStatus = "unverifiable"
			e.Statement = fmt.Sprintf("whether affected module `%s` is part of the product could not be determined: %s", e.Module, e.Evidence)
		}
		cr.Entries = append(cr.Entries, e)

		if e.Presence == "present" {
			presentEntries = append(presentEntries, e)
		}
	}
	if ares.uncomparable > 0 {
		noun, verb := "affected entries", "declare"
		if ares.uncomparable == 1 {
			noun, verb = "affected entry", "declares"
		}
		cr.Entries = append(cr.Entries, ConsistencyEntry{
			Module:      "",
			Presence:    "unknown",
			RangeStatus: "unverifiable",
			DocumentID:  ares.primaryDoc.ID,
			Evidence:    fmt.Sprintf("%d advisory %s %s no Go module name (non-Go ecosystems, CPE or GIT ranges)", ares.uncomparable, noun, verb),
			Statement:   fmt.Sprintf("the advisory lists %d %s outside the Go module view — they cannot be checked against the snapshot's module graph", ares.uncomparable, noun),
		})
	}

	if r.Answer.Parsed {
		cr.Findings = append(cr.Findings,
			absenceTensionFindings(r, presentEntries)...)
		if f, ok := reachabilityNotEstablishedFinding(r); ok {
			cr.Findings = append(cr.Findings, f)
		}
		if f, ok := mechanismAlignmentFinding(r, affected); ok {
			cr.Findings = append(cr.Findings, f)
		}
		cr.Findings = append(cr.Findings,
			coverageFindings(r, idx, affected, named)...)
		cr.Findings = append(cr.Findings,
			versionMismatchFindings(r, affected)...)
		cr.Findings = safeCategoryUnsupportedFindings(r, len(ares.affected) == 0, cr.Findings)
	}
	return cr
}

// versionsInRanges evaluates a possibly multi-version resolution (go.sum
// can record several versions of one module): "in" is true when any listed
// version falls inside a range, "ok" is false only when no listed version
// can be read as semver.
func versionsInRanges(resolved string, ranges []pbdomain.VersionRange) (in, ok bool) {
	for _, v := range strings.Split(resolved, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		i, valid := versionInRanges(v, ranges)
		if i {
			return true, true
		}
		ok = ok || valid
	}
	return false, ok
}

func orNone2(s string) string {
	if s == "" {
		return "(unresolved)"
	}
	return s
}

// absenceTensionFindings surfaces the single case where the agent's
// category claims absence of the affected code (`code_not_present`)
// while the host sees the advisory-affected module in the module graph.
// Presence of the module does NOT refute the claim — the claim may be
// about a narrower scope (a package, an import, a symbol) which a
// file-level module graph cannot check — so the finding records a
// tension, not a refutation. No other non-vulnerable category collides
// with presence: `code_not_reachable` and the protection categories are
// about reachability or conditions, which presence/version facts cannot
// decide.
func absenceTensionFindings(r *Report, presentEntries []ConsistencyEntry) []ConsistencyFinding {
	if r.Answer.Category != "code_not_present" || len(presentEntries) == 0 {
		return nil
	}
	var mods []string
	for _, e := range presentEntries {
		mods = append(mods, fmt.Sprintf("`%s` at `%s` (advisory range %s → %s)",
			e.Module, orNone2(e.ResolvedVersion), strings.Join(e.AdvisoryRanges, ", "), e.RangeStatus))
	}
	return []ConsistencyFinding{{
		Kind: "category_absence_tension",
		Statement: fmt.Sprintf("the agent's category `code_not_present` asserts the affected code is absent, but the host sees the affected module present in the module graph: %s. The claim may concern a different scope — a package, an import or a specific symbol rather than the whole module — which the host cannot check from the module graph. This is a tension to resolve, not a refutation: module presence does not establish that the specific vulnerable code is present, and the agent's category stays as recorded",
			strings.Join(mods, "; ")),
		Evidence: "snapshot module graph + advisory affected entries",
	}}
}

// reachabilityNotEstablishedFinding fires for every non-vulnerable
// category: the answer's condition and reachability statements are agent
// claims, and the host checks (module presence, version ranges, citation
// presence) can never confirm a necessary transition or an exploitation
// condition — cited paths verify presence only. The reachability and
// condition status therefore stays UNKNOWN: an unconfirmed condition
// supports no confident conclusion either way.
func reachabilityNotEstablishedFinding(r *Report) (ConsistencyFinding, bool) {
	if !safeCategories[r.Answer.Category] {
		return ConsistencyFinding{}, false
	}
	n := len(r.Analysis.ExploitationConditions)
	condNote := fmt.Sprintf("the answer carries %d exploitation-condition statement(s) — all unconfirmed agent claims (citation checks establish presence only)", n)
	if n == 0 {
		condNote = "the answer records no confirmed necessary condition or transition"
	}
	return ConsistencyFinding{
		Kind: "reachability_not_established",
		Statement: fmt.Sprintf("the non-vulnerable category `%s` rests on reachability or exploitation conditions the host did not confirm: %s. Module presence or resolved version cannot establish reachability — the reachability and condition status stays UNKNOWN",
			r.Answer.Category, condNote),
		Evidence: "host checks cover module presence/version and citation presence only",
	}, true
}

// mechanismAlignmentFinding applies the bounded lexical rule on the
// agent's mechanism text: when that text does not name the advisory's
// affected module or package paths, the mechanism shown to the reader
// cannot be trusted to describe the advisory's vulnerability — the
// finding marks the alignment as not established. It never judges the
// text's truth, only whether the reference and the claim name the same
// component.
func mechanismAlignmentFinding(r *Report, affected []pbdomain.AffectedModule) (ConsistencyFinding, bool) {
	mech := r.Analysis.Mechanism
	if mech == "" {
		return ConsistencyFinding{
			Kind:      "mechanism_alignment_not_established",
			Statement: "the answer provides no mechanism description to compare with the advisory's mechanism — alignment between the agent's explanation and the advisory's vulnerable code is not established",
			Evidence:  "agent mechanism claim vs advisory summary/details",
		}, true
	}
	if mechanismNamesAffected(mech, affected) {
		return ConsistencyFinding{}, false
	}
	var names []string
	for _, am := range affected {
		names = append(names, "`"+am.Module+"`")
	}
	return ConsistencyFinding{
		Kind: "mechanism_alignment_not_established",
		Statement: fmt.Sprintf("the agent's mechanism text does not name the advisory's affected module/package (%s) — the text may describe a different component, and its alignment with the advisory's mechanism is not established (lexical check only)",
			strings.Join(names, ", ")),
		Evidence: "agent mechanism text vs advisory affected module/package names",
	}, true
}

// mechanismNamesAffected reports whether the mechanism text names an
// advisory-affected component: a multi-segment module or package path
// must appear literally (covers vendor/… prefixes); a bare name such as
// `stdlib` or `net` must appear as a whole token (>=4 chars to keep
// common words from matching). Lexical only — no semantic check.
func mechanismNamesAffected(mech string, affected []pbdomain.AffectedModule) bool {
	low := strings.ToLower(mech)
	tokens := map[string]bool{}
	for _, t := range strings.FieldsFunc(low, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_')
	}) {
		if len(t) >= 4 {
			tokens[t] = true
		}
	}
	name := func(n string) bool {
		n = strings.ToLower(strings.TrimSpace(n))
		switch {
		case n == "":
			return false
		case strings.Contains(n, "/"):
			return strings.Contains(low, n)
		default:
			return len(n) >= 4 && tokens[n]
		}
	}
	for _, am := range affected {
		if name(am.Module) {
			return true
		}
		for _, p := range am.AffectedPackages {
			if name(p.Path) {
				return true
			}
		}
	}
	return false
}

// coverageFindings detects when the advisory lists more affected entries
// than the answer names, or when the answer names a graph module the
// advisory does not list. Naming is literal: the module path must appear
// in the answer's reasoning text.
func coverageFindings(r *Report, idx *moduleIndex, affected []pbdomain.AffectedModule, named map[string]bool) []ConsistencyFinding {
	var out []ConsistencyFinding
	var unnamed []string
	for _, am := range affected {
		if !named[am.Module] {
			unnamed = append(unnamed, "`"+am.Module+"`")
		}
	}
	if len(unnamed) > 0 {
		out = append(out, ConsistencyFinding{
			Kind: "coverage_incomplete",
			Statement: fmt.Sprintf("the advisory lists %d affected module entries but the answer does not mention %s — whether those entries were assessed is not established",
				len(affected), strings.Join(unnamed, ", ")),
			Evidence: "advisory affected[] vs the answer's reasoning text",
		})
	}
	var extra []string
	for mod := range idx.mods {
		if mod == idx.main || named[mod] {
			continue
		}
		listed := false
		for _, am := range affected {
			if am.Module == mod {
				listed = true
				break
			}
		}
		if !listed && strings.Contains(r.Answer.Reasoning, mod) {
			extra = append(extra, "`"+mod+"`")
		}
	}
	if len(extra) > 0 {
		out = append(out, ConsistencyFinding{
			Kind: "coverage_incomplete",
			Statement: fmt.Sprintf("the answer names module(s) the advisory does not list as affected: %s — either the advisory is narrower than the agent's reading or unrelated modules were associated",
				strings.Join(extra, ", ")),
			Evidence: "answer reasoning text vs advisory affected[]",
		})
	}
	return out
}

// versionMismatchFindings compares the fix/patch versions the answer
// asserts with the fixed versions the advisory declares. Only literal
// claims are compared — the advisory's `affected` is the authority on
// declared fix versions; semantics beyond string equality are not
// inferred.
func versionMismatchFindings(r *Report, affected []pbdomain.AffectedModule) []ConsistencyFinding {
	declared := map[string]string{} // normalized → display
	for _, am := range affected {
		for _, fv := range am.FixedVersions {
			if nv := normalizeResearchVersion(fv); nv != "" {
				declared[nv] = fv
			}
		}
	}
	if len(declared) == 0 {
		return nil
	}
	var claimed []string
	for _, m := range fixVersionRx.FindAllStringSubmatch(r.Answer.Reasoning, -1) {
		nv := normalizeResearchVersion(m[1])
		if nv == "" {
			continue
		}
		if _, ok := declared[nv]; !ok {
			dup := false
			for _, c := range claimed {
				if c == m[1] {
					dup = true
				}
			}
			if !dup {
				claimed = append(claimed, m[1])
			}
		}
	}
	if len(claimed) == 0 {
		return nil
	}
	var declaredList []string
	for _, fv := range declared {
		declaredList = append(declaredList, fv)
	}
	return []ConsistencyFinding{{
		Kind: "version_mismatch",
		Statement: fmt.Sprintf("the answer asserts fix version(s) %s, but the advisory declares fixed version(s) %s — the statements conflict; which is right is not decided here",
			strings.Join(claimed, ", "), strings.Join(declaredList, ", ")),
		Evidence: "answer reasoning (fix-version claims) vs advisory fixed versions",
	}}
}

// safeCategoryUnsupportedFindings marks every non-vulnerable research
// category as unsupported by the host: by construction the host checks
// (module presence/version vs the advisory ranges, citation presence,
// advisory comparability) can never establish safety, so the judgement is
// recorded as unverified regardless of what the checks found. The grounds
// enumerate what was actually checked — including verified citations and
// unremarkable presence facts — so the record never understates how far
// the host support reaches.
func safeCategoryUnsupportedFindings(r *Report, uncomparable bool, findings []ConsistencyFinding) []ConsistencyFinding {
	if !r.Answer.Parsed || !safeCategories[r.Answer.Category] {
		return findings
	}
	var grounds []string
	if uncomparable {
		grounds = append(grounds, "the advisory supplied no comparable Go affected entry — no module could be range-checked")
	} else {
		grounds = append(grounds, "module presence/resolved version/range status was checked against the advisory's comparable Go affected entries")
	}
	if r.Analysis.PresenceSummary.PathsFound == 0 {
		grounds = append(grounds, "no cited path was verified inside the snapshot")
	} else {
		grounds = append(grounds, fmt.Sprintf("%d cited path(s) were verified present in the snapshot — presence is checked, not the claims made about them", r.Analysis.PresenceSummary.PathsFound))
	}
	for _, f := range findings {
		if f.Kind == "category_absence_tension" {
			grounds = append(grounds, "the host sees an advisory-affected module present while the category asserts absence (see the category_absence_tension finding)")
			break
		}
	}
	return append(findings, ConsistencyFinding{
		Kind: "safe_category_unsupported",
		Statement: fmt.Sprintf("the host cannot confirm the non-vulnerable conclusion `%s`: %s. None of these checks establishes safety; the advisory's affected list is not treated as exhaustive, and not finding a path is not proof that no exploitation path exists — the category stays an unverified judgement",
			r.Answer.Category, strings.Join(grounds, "; ")),
		Evidence: "host facts + advisory comparability + citation presence check",
	})
}
