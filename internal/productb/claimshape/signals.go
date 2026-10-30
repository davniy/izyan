package claimshape

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	triage "github.com/davniy/izyan/internal/productb/triage"
)

// signalFamily is the canonical claim family a signal belongs to. The
// classification is a pure function of the artifact's structured fields
// (tool name, payload counts, locator scheme, evidence kind) — claim
// prose never participates.
type signalFamily string

const (
	famApplicability signalFamily = "applicability"
	famSubject       signalFamily = "subject"
	famPath          signalFamily = "path"
	famInput         signalFamily = "input"
	famControl       signalFamily = "control"
	famConfiguration signalFamily = "configuration"
	famEnvironment   signalFamily = "environment"
	famPerimeter     signalFamily = "perimeter"
	famClosure       signalFamily = "closure"
	famProvenance    signalFamily = "provenance"
	// famUnclassified — resolved artifact whose tool/kind has no signal
	// class in the registry; and famUnresolved — a reference that names
	// no recorded artifact at all.
	famUnclassified signalFamily = "unclassified"
	famUnresolved   signalFamily = "unresolved"
)

// sign is the value the underlying deterministic result reported for a
// signal, independent of what the claim asserts about it.
type sign string

const (
	signPositive sign = "positive"
	signNegative sign = "negative"
	signUnknown  sign = "unknown"
)

// weight distinguishes decisional signals (a named check with a
// checkable predicate) from context signals (authoritative records the
// claim references) and weak signals (locators that place code on screen
// but assert no predicate).
type weight string

const (
	weightDecisional weight = "decisional"
	weightContext    weight = "context"
	weightWeak       weight = "weak"
)

// signal is the classification outcome for one cited artifact.
type signal struct {
	family        signalFamily
	sign          sign
	weight        weight
	predicate     string
	subject       Subject
	version       string // resolved module version (get_module_version)
	observationID string
	tool          string
	status        string
	completeness  string
	scope         string
	snapshotHash  string
	buildCtxHash  string
	canonical     bool // canonical locator form (recorded observation id)
}

// toolSignals maps each deterministic evidence tool to the canonical
// signal class its observation belongs to. The map is closed by design:
// a tool not listed contributes an unclassified signal, which surfaces
// in the report instead of being guessed.
var toolSignals = map[string]struct {
	family    signalFamily
	weight    weight
	predicate string
	subject   SubjectKind
}{
	"get_module_version":    {famApplicability, weightContext, "resolved module version", SubjectModule},
	"get_dependency_graph":  {famApplicability, weightContext, "module graph membership", SubjectModuleGraph},
	"lookup_advisory":       {famProvenance, weightContext, "advisory record", SubjectAdvisory},
	"get_product_snapshot":  {famEnvironment, weightDecisional, "build context facts", SubjectBuildContext},
	"find_symbol":           {famSubject, weightDecisional, "declaration lookup", SubjectSymbol},
	"find_references":       {famSubject, weightDecisional, "reference occurrence", SubjectSymbol},
	"search_text":           {famSubject, weightDecisional, "occurrence scan", SubjectPattern},
	"verify_code_absence":   {famSubject, weightDecisional, "closed-scope absence check", SubjectSymbol},
	"find_callers":          {famPath, weightDecisional, "named callers", SubjectSymbol},
	"find_may_callers":      {famPath, weightDecisional, "may-call sites", SubjectSymbol},
	"dep_invocation_state":  {famPath, weightDecisional, "in-module invocation", SubjectSymbol},
	"module_usage":          {famPath, weightDecisional, "module call sites", SubjectModule},
	"run_govulncheck":       {famPath, weightDecisional, "advisory reachability scan", SubjectSymbol},
	"check_call_site_guard": {famControl, weightDecisional, "call-site guard", SubjectCallSite},
	"find_validations":      {famControl, weightDecisional, "guard search", SubjectPattern},
	"gated_refs":            {famEnvironment, weightDecisional, "build-gated references", SubjectSymbol},
	"read_manifest":         {famConfiguration, weightDecisional, "manifest content", SubjectManifest},
	"read_file":             {famSubject, weightWeak, "file content", SubjectPath},
	"list_files":            {famSubject, weightWeak, "directory listing", SubjectPath},
}

// payloadData returns the observation payload's structured data object.
// Wrapped envelopes carry it under "data"; raw-tool payloads carry
// their fields at top level. Both are consulted in that order.
func payloadData(o *triage.RecordedObservation) map[string]any {
	var pl struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal(o.Payload, &pl)
	if len(pl.Data) > 0 {
		return pl.Data
	}
	var raw map[string]any
	if json.Unmarshal(o.Payload, &raw) == nil {
		return raw
	}
	return nil
}

func payloadTop(o *triage.RecordedObservation) map[string]any {
	var raw map[string]any
	_ = json.Unmarshal(o.Payload, &raw)
	return raw
}

func intField(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n), true
			case string:
				if i, err := strconv.Atoi(n); err == nil {
					return i, true
				}
			}
		}
	}
	return 0, false
}

func listLen(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		if xs, ok := v.([]any); ok {
			return len(xs)
		}
	}
	return 0
}

func boolField(m map[string]any, key string) (bool, bool) {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// signFromObservation reads the reported result sign of one recorded
// observation from its structured payload — counts, subject sets and
// result booleans, never the prose fact string.
func signFromObservation(o *triage.RecordedObservation) sign {
	d := payloadData(o)
	top := payloadTop(o)
	switch o.Tool {
	case "get_module_version":
		if p, ok := boolField(d, "present"); ok {
			if p {
				return signPositive
			}
			return signNegative
		}
		return signUnknown
	case "get_dependency_graph", "lookup_advisory", "get_product_snapshot", "read_manifest", "list_files", "read_file":
		return signPositive
	case "find_symbol":
		if f, ok := boolField(d, "found"); ok {
			if f {
				return signPositive
			}
			return signNegative
		}
		return signUnknown
	case "find_references", "find_callers", "module_usage":
		if n, ok := intField(d, "count"); ok {
			if n == 0 {
				return signNegative
			}
			return signPositive
		}
		if listLen(d, "call_sites") > 0 || listLen(d, "references") > 0 {
			return signPositive
		}
		return signUnknown
	case "find_may_callers":
		if n, ok := intField(d, "count"); ok {
			possible, _ := intField(d, "possible_count")
			switch {
			case n > 0:
				return signPositive
			case n == 0 && possible == 0:
				return signNegative
			}
			return signUnknown
		}
		return signUnknown
	case "dep_invocation_state":
		n, ok := intField(d, "callers_inside_module")
		live, _ := boolField(d, "sibling_live")
		unbounded, _ := boolField(d, "unbounded")
		switch {
		case !ok:
			return signUnknown
		case n > 0 || live:
			return signPositive
		case n == 0 && !live && !unbounded:
			return signNegative
		}
		return signUnknown
	case "verify_code_absence":
		checked := listLen(d, "checked_subjects")
		absent := listLen(d, "absent_subjects")
		present := listLen(d, "present_subjects")
		switch {
		case checked == 0:
			return signUnknown
		case present == 0 && absent == 0:
			return signUnknown
		case present == 0 && absent == checked:
			return signNegative
		case present > 0:
			return signPositive
		}
		return signUnknown
	case "check_call_site_guard":
		if g, ok := boolField(d, "gated"); ok {
			if g {
				return signPositive
			}
			return signNegative
		}
		return signUnknown
	case "find_validations", "run_govulncheck":
		return signUnknown
	case "gated_refs":
		if n, ok := intField(d, "count"); ok {
			if n > 0 {
				return signPositive
			}
			return signNegative
		}
		return signUnknown
	case "search_text":
		if n, ok := intField(d, "count"); ok {
			if n == 0 {
				return signNegative
			}
			return signPositive
		}
		if n, ok := intField(top, "count"); ok {
			if n == 0 {
				return signNegative
			}
			return signPositive
		}
		return signUnknown
	}
	return signUnknown
}

// observationSubject recovers the subject a recorded observation
// checked, from its structured scope_details, data and tool-specific
// identity fields — never from prose.
func observationSubject(o *triage.RecordedObservation) Subject {
	var pl struct {
		ScopeDetails struct {
			Subject string `json:"subject"`
		} `json:"scope_details"`
		Data struct {
			Module  string `json:"module"`
			Package string `json:"package"`
			Symbol  string `json:"symbol"`
		} `json:"data"`
		RequestedID string   `json:"requested_id"`
		IDs         []string `json:"ids"`
	}
	_ = json.Unmarshal(o.Payload, &pl)
	name := strings.TrimSpace(pl.ScopeDetails.Subject)
	sub := Subject{Kind: SubjectUnknown, Name: name}
	if spec, ok := toolSignals[o.Tool]; ok {
		sub.Kind = spec.subject
	}
	switch o.Tool {
	case "lookup_advisory":
		sub.Name = pl.RequestedID
		if sub.Name == "" && len(pl.IDs) > 0 {
			sub.Name = pl.IDs[0]
		}
	case "get_product_snapshot":
		var raw struct {
			ScopeDetails struct {
				BuildContext map[string]any `json:"build_context"`
			} `json:"scope_details"`
		}
		_ = json.Unmarshal(o.Payload, &raw)
		var parts []string
		for _, k := range []string{"goos", "goarch", "cgo_enabled", "vendor_mode"} {
			if v, ok := raw.ScopeDetails.BuildContext[k]; ok {
				parts = append(parts, k+"="+fmt.Sprint(v))
			}
		}
		if len(parts) > 0 {
			sub.Name = strings.Join(parts, ",")
		} else {
			sub.Name = "snapshot build context"
		}
	}
	if m := strings.TrimSpace(pl.Data.Module); m != "" {
		sub.Name = m
		sub.Kind = SubjectModule
	}
	if p := strings.TrimSpace(pl.Data.Package); p != "" {
		sub.Package = p
		sub.Kind = SubjectPackage
		if s := strings.TrimSpace(pl.Data.Symbol); s != "" {
			sub.Symbol = s
			sub.Kind = SubjectSymbol
			sub.Name = p + "." + s
		}
	}
	return sub
}

// classifyObservation assigns the canonical signal class of one
// recorded observation.
func classifyObservation(o *triage.RecordedObservation) signal {
	spec, ok := toolSignals[o.Tool]
	if !ok {
		return signal{
			family: famUnclassified, sign: signUnknown, weight: weightWeak,
			predicate: "unregistered tool", subject: Subject{Kind: SubjectUnknown, Name: o.Tool},
			observationID: o.ID, tool: o.Tool, status: o.Status,
			completeness: string(o.Completeness), scope: o.Scope,
			snapshotHash: o.SnapshotHash, buildCtxHash: o.BuildContextHash, canonical: true,
		}
	}
	s := signal{
		family:        spec.family,
		sign:          signFromObservation(o),
		weight:        spec.weight,
		predicate:     spec.predicate,
		subject:       observationSubject(o),
		observationID: o.ID,
		tool:          o.Tool,
		status:        o.Status,
		completeness:  string(o.Completeness),
		scope:         o.Scope,
		snapshotHash:  o.SnapshotHash,
		buildCtxHash:  o.BuildContextHash,
		canonical:     true,
	}
	if o.Tool == "get_module_version" {
		s.version = strField(payloadData(o), "effective_version", "version")
	}
	return s
}

// evidenceKindSignals maps the fact gate's canonical evidence kinds to
// signal classes for evidence that does not resolve to a recorded
// observation. "observation" is deliberately absent: a kind=observation
// entry whose locator names nothing recorded carries no signal.
var evidenceKindSignals = map[string]struct {
	family    signalFamily
	sign      sign
	weight    weight
	predicate string
	subject   SubjectKind
}{
	"source_span": {famSubject, signPositive, weightWeak, "cited code span", SubjectPath},
	"file":        {famSubject, signPositive, weightWeak, "cited file", SubjectPath},
	"advisory":    {famProvenance, signPositive, weightContext, "advisory record", SubjectAdvisory},
	"component":   {famApplicability, signPositive, weightContext, "component identity", SubjectComponent},
	"artifact":    {famProvenance, signPositive, weightContext, "artifact identity", SubjectComponent},
	"revision":    {famProvenance, signPositive, weightContext, "revision identity", SubjectComponent},
}

// classifyEvidence assigns the canonical signal class of one assessment
// evidence entry. The locator shape decides first (recorded observation
// id > synthesized probe > advisory id > declared kind) — mirroring the
// fact gate's own precedence so both layers agree on what an entry is.
func classifyEvidence(ev triage.EvidenceRef, ix *observationIndex) signal {
	loc := strings.TrimSpace(ev.Locator)
	kind := strings.ToLower(strings.TrimSpace(ev.Kind))
	if id, _, ok := parseObservationLocator(loc); ok {
		if o, unresolved := ix.resolve(id); !unresolved {
			return classifyObservation(o)
		}
		return signal{family: famUnresolved, sign: signUnknown, weight: weightWeak,
			predicate: "unresolved observation reference",
			subject:   Subject{Kind: SubjectUnknown, Name: id}, canonical: true}
	}
	if m := searchProbe.FindStringSubmatch(loc); m != nil {
		s := signUnknown
		if m[1] == "0" {
			s = signNegative
		} else if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			s = signPositive
		}
		return signal{family: famSubject, sign: s, weight: weightDecisional,
			predicate: "occurrence scan",
			subject:   Subject{Kind: SubjectPattern, Name: strings.TrimSuffix(strings.TrimPrefix(loc, "search:"), "="+m[1])}}
	}
	if m := listFilesProbe.FindStringSubmatch(loc); m != nil {
		return signal{family: famSubject, sign: signPositive, weight: weightWeak,
			predicate: "directory listing",
			subject:   Subject{Kind: SubjectPath, Name: m[1]}}
	}
	if advisoryID.MatchString(loc) {
		return signal{family: famProvenance, sign: signPositive, weight: weightContext,
			predicate: "advisory record",
			subject:   Subject{Kind: SubjectAdvisory, Name: loc}}
	}
	if spec, ok := evidenceKindSignals[kind]; ok {
		return signal{family: spec.family, sign: spec.sign, weight: spec.weight,
			predicate: spec.predicate,
			subject:   Subject{Kind: spec.subject, Name: loc}}
	}
	return signal{family: famUnclassified, sign: signUnknown, weight: weightWeak,
		predicate: "unrecognized evidence form",
		subject:   Subject{Kind: SubjectUnknown, Name: loc}}
}
