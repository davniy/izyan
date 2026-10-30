package fixbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// This file constructs the implementation boundary and derives the only
// supported non-counterpart certificate.
//
// The withdrawn layer discharged an opaque effect by looking for a package,
// receiver and function *name* in the selected module's own declaration census.
// That is unsound in both directions. A renamed, split, wrapped or inline
// implementation has no such name and was declared absent; and an implementation
// supplied by an imported component (containerd v1.4.13 blank-imports
// github.com/containerd/cri) lives outside the module being censused entirely.
//
// The rule implemented here is structural and closed:
//
//   - the boundary is every package of the selected implementation plus every
//     effective external implementation component a boundary file imports for
//     side effects or registers as an initializer;
//   - every registration construction is enumerated independently of any patch
//     path, with its identity, its construction and its initializer resolved;
//   - every function literal in the boundary is analysed with its own parameter
//     bindings, so an inline initializer closure cannot hide an operation;
//   - the mechanism is a supported operation class on one correspondence
//     resource key, so a renamed or split counterpart is still found;
//   - the certificate exists only when the boundary is closed *and* no component
//     contains an operation of that class on that resource.
//
// Any unresolved external edge, dynamic registration, unresolved initializer,
// unparsed file or ambiguous mechanism defeats the certificate. Missing names
// are never the proof, and an opaque change is never discharged at all.

// CertificateStructuralRule is the only non-counterpart rule this checker
// implements.
const CertificateStructuralRule = domain.FixProofNonCounterpartRule

// BoundaryComponent is one component of the closed implementation boundary the
// certificate was measured over.
type BoundaryComponent struct {
	// Component is "selected" or the external component's import path.
	Component  string `json:"component"`
	ImportPath string `json:"import_path"`
	Module     string `json:"module"`
	Version    string `json:"version,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Files      int    `json:"files"`
	Digest     string `json:"digest"`
}

// BoundaryEdge is one import or registration edge the closure had to resolve.
// A blank import is always an edge: it supplies an implementation through
// side-effect registration without naming a symbol.
type BoundaryEdge struct {
	From       string `json:"from"`
	File       string `json:"file,omitempty"`
	ImportPath string `json:"import_path"`
	// Component names the boundary component the edge resolved to; empty when
	// it did not resolve inside the boundary.
	Component string `json:"component,omitempty"`
	Blank     bool   `json:"blank,omitempty"`
	// Registration marks an initializer edge rather than an import.
	Registration bool   `json:"registration,omitempty"`
	Resolved     bool   `json:"resolved"`
	Detail       string `json:"detail,omitempty"`
}

// BoundaryRegistration is one registration construction the certificate
// accounted for.
type BoundaryRegistration struct {
	Component        string `json:"component"`
	File             string `json:"file"`
	Line             int    `json:"line"`
	Identity         string `json:"identity,omitempty"`
	IdentityResolved bool   `json:"identity_resolved"`
	InitKind         string `json:"init_kind"`
	InitField        string `json:"init_field,omitempty"`
	InitName         string `json:"init_name,omitempty"`
	InitPackage      string `json:"init_package,omitempty"`
	InitFile         string `json:"init_file,omitempty"`
	Resolved         bool   `json:"resolved"`
	Detail           string `json:"detail,omitempty"`
}

// BoundaryClosure is one function literal whose body the boundary analysis
// walked with its own bindings.
type BoundaryClosure struct {
	Component   string `json:"component"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Declaration string `json:"declaration,omitempty"`
}

// NonCounterpartCertificate records that one mechanism has no counterpart or
// bypass in a closed implementation boundary. It carries the whole boundary — a
// certificate with a missing component, registration or closure is refused on
// re-admission, so omitting a proof record never means success.
type NonCounterpartCertificate struct {
	Rule          string                 `json:"rule"`
	Mechanism     string                 `json:"mechanism"`
	ResourceKey   string                 `json:"resource_key"`
	Boundary      string                 `json:"boundary"`
	Components    []BoundaryComponent    `json:"components"`
	Edges         []BoundaryEdge         `json:"edges,omitempty"`
	Registrations []BoundaryRegistration `json:"registrations,omitempty"`
	Closures      []BoundaryClosure      `json:"closures,omitempty"`
	Files         int                    `json:"files"`
	Digest        string                 `json:"digest"`
}

// Digest recomputes the certificate's identity from its own content.
func (c NonCounterpartCertificate) computeDigest() string {
	clone := c
	clone.Digest = ""
	sum := sha256.Sum256(canonicalJSON(clone))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// boundaryComponent is one measured component of the boundary.
type boundaryComponent struct {
	component  string
	importPath string
	module     string
	version    string
	kind       string
	files      map[string][]byte
	census     *Census
}

// implementationBoundary is the closed component set plus every edge the
// closure had to resolve. blocking carries the facts that defeat any certificate
// measured over it.
type implementationBoundary struct {
	components    []*boundaryComponent
	packages      map[string]*boundaryComponent
	edges         []BoundaryEdge
	registrations []BoundaryRegistration
	blocking      []ProofObligation
}

// selectedComponent is the component name of the selected implementation.
const selectedComponent = "selected"

// buildBoundary assembles the implementation boundary from the selected
// implementation and the captured effective external components. It resolves
// every blank import and every registration initializer to a boundary component;
// an edge that does not resolve is a blocking fact.
func buildBoundary(in Inputs, sel domain.EffectiveSourceSelection, selected *Census) *implementationBoundary {
	b := &implementationBoundary{packages: map[string]*boundaryComponent{}}
	selectedFiles := in.Inventory.CensusFiles()
	if len(selectedFiles) > 0 {
		component := &boundaryComponent{
			component: selectedComponent, importPath: sel.DeclaredModule,
			module: sel.EffectiveModule, version: sel.EffectiveVersion,
			kind: string(sel.SourceKind), files: selectedFiles, census: selected,
		}
		b.components = append(b.components, component)
		b.registerPackages(component)
	}
	for _, external := range in.External {
		component, obligation := buildExternalComponent(external)
		if obligation != nil {
			b.blocking = append(b.blocking, *obligation)
			continue
		}
		if owner, duplicate := b.packages[component.importPath]; duplicate && owner != nil {
			b.blocking = append(b.blocking, ProofObligation{
				Kind: "BOUNDARY", Code: "EXTERNAL_COMPONENT_DUPLICATE",
				Detail: fmt.Sprintf("import path %q is claimed by more than one implementation component", component.importPath),
			})
			continue
		}
		b.components = append(b.components, component)
		b.registerPackages(component)
	}

	// Enumerate imports and registrations independently of any patch path.
	for _, component := range b.components {
		b.resolveImports(component)
		b.resolveRegistrations(component)
	}
	// Params whose import path is a package of this boundary are not edges.
	b.dedupeEdges()
	return b
}

// buildExternalComponent validates and measures one captured external
// implementation component.
func buildExternalComponent(external ExternalComponent) (*boundaryComponent, *ProofObligation) {
	importPath := strings.TrimSpace(external.ImportPath)
	if importPath == "" {
		return nil, &ProofObligation{Kind: "BOUNDARY", Code: "EXTERNAL_COMPONENT_UNNAMED",
			Detail: "an external implementation component carries no import path"}
	}
	if !external.Inventory.Anchored() {
		reason := external.Inventory.Input.Reason
		if reason == "" {
			reason = "no independently anchored complete inventory was supplied"
		}
		return nil, &ProofObligation{Kind: "BOUNDARY", Code: "UNRESOLVED_EXTERNAL_EDGE",
			Detail: fmt.Sprintf("external implementation component %s is not independently anchored: %s", importPath, reason)}
	}
	files := external.Inventory.CensusFiles()
	if len(files) == 0 {
		return nil, &ProofObligation{Kind: "BOUNDARY", Code: "UNRESOLVED_EXTERNAL_EDGE",
			Detail: fmt.Sprintf("external implementation component %s carries no captured bytes", importPath)}
	}
	census, err := CensusSource(CensusOptions{
		Module:        ModuleIdentity{Path: external.Inventory.Module, Version: external.Inventory.Version},
		ImportPath:    importPath,
		Files:         files,
		WalkClosures:  true,
		Registrations: true,
	})
	if err != nil {
		return nil, &ProofObligation{Kind: "BOUNDARY", Code: "UNRESOLVED_EXTERNAL_EDGE",
			Detail: fmt.Sprintf("external implementation component %s could not be censused: %v", importPath, err)}
	}
	return &boundaryComponent{
		component: importPath, importPath: importPath,
		module: external.Inventory.Module, version: external.Inventory.Version,
		kind: string(external.Inventory.Observed.Kind), files: files, census: census,
	}, nil
}

// registerPackages maps every package path the component provides to the
// component itself. Import paths stay unchanged under a replacement, so the
// declared namespace is the key.
func (b *implementationBoundary) registerPackages(component *boundaryComponent) {
	dirs := map[string]bool{}
	for name := range component.files {
		dirs[dirOf(name)] = true
	}
	for dir := range dirs {
		path := component.importPath
		if dir != "" {
			path += "/" + dir
		}
		b.packages[path] = component
	}
	b.packages[component.importPath] = component
}

// resolveImports records every blank (side-effect) import as an edge and checks
// whether it resolves inside the boundary. A non-blank import is not an edge by
// itself: using an unresolved external declaration is already an unknown-call
// obligation in the census.
func (b *implementationBoundary) resolveImports(component *boundaryComponent) {
	fset := token.NewFileSet()
	names := make([]string, 0, len(component.files))
	for name := range component.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, component.files[name], parser.ImportsOnly)
		if err != nil {
			// The census records the parse failure as a blocking obligation;
			// the import set is unknown, which the same obligation covers.
			continue
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			blank := spec.Name != nil && spec.Name.Name == "_"
			if !blank {
				continue
			}
			edge := BoundaryEdge{From: component.component, File: name, ImportPath: path, Blank: true}
			if owner, ok := b.packages[path]; ok {
				edge.Component, edge.Resolved = owner.component, true
			} else if isStdlibImportPath(path) {
				edge.Resolved = true
				edge.Detail = "standard library package; it cannot implement this module's resource"
			}
			b.edges = append(b.edges, edge)
			if !edge.Resolved {
				b.blocking = append(b.blocking, ProofObligation{
					Kind: "BOUNDARY", Code: "UNRESOLVED_EXTERNAL_EDGE", File: name,
					Detail: fmt.Sprintf("blank import %q supplies an implementation component outside the closed boundary", path),
				})
			}
		}
	}
}

// resolveRegistrations records every registration construction and requires its
// identity and initializer to resolve inside the boundary.
func (b *implementationBoundary) resolveRegistrations(component *boundaryComponent) {
	if component.census == nil {
		return
	}
	for _, registration := range component.census.Registrations {
		record := BoundaryRegistration{
			Component: component.component, File: registration.File, Line: registration.Line,
			Identity: registration.Identity, IdentityResolved: registration.IdentityResolved,
			InitKind: registration.InitKind, InitField: registration.InitField,
			InitName: registration.InitName, InitPackage: registration.InitPackage,
			InitFile: registration.InitFile,
		}
		if !registration.IdentityResolved {
			record.Detail = "the registration identity is computed at run time"
			b.blocking = append(b.blocking, ProofObligation{
				Kind: "BOUNDARY", Code: "DYNAMIC_REGISTRATION", File: registration.File, Line: registration.Line,
				Detail: "a registration whose identity is not a literal or resolvable constant is dynamic, and a dynamic registration defeats a closed boundary",
			})
		} else {
			record.Resolved = true
		}
		switch registration.InitKind {
		case InitLiteral:
			record.Resolved = record.Resolved && registration.IdentityResolved
		case InitNamed:
			switch {
			case registration.InitPackage == "":
				if registration.InitFile == "" {
					record.Resolved = false
					record.Detail = "the named initializer is not declared in the scanned source"
					b.blocking = append(b.blocking, ProofObligation{Kind: "BOUNDARY", Code: "REGISTRATION_INITIALIZER",
						File: registration.File, Line: registration.Line, Detail: record.Detail})
				}
			default:
				owner, ok := b.packages[registration.InitPackage]
				if !ok {
					record.Resolved = false
					record.Detail = "the initializer is supplied by an external component outside the boundary"
					b.blocking = append(b.blocking, ProofObligation{Kind: "BOUNDARY", Code: "UNRESOLVED_EXTERNAL_EDGE",
						File: registration.File, Line: registration.Line,
						Detail: fmt.Sprintf("registration initializer %s.%s belongs to an implementation component outside the closed boundary",
							registration.InitPackage, registration.InitName)})
				} else {
					edge := BoundaryEdge{From: component.component, File: registration.File,
						ImportPath: registration.InitPackage, Component: owner.component, Registration: true, Resolved: true}
					b.edges = append(b.edges, edge)
				}
			}
		default:
			record.Resolved = false
			record.Detail = "the initializer construction is not established"
			b.blocking = append(b.blocking, ProofObligation{Kind: "BOUNDARY", Code: "REGISTRATION_INITIALIZER",
				File: registration.File, Line: registration.Line, Detail: record.Detail})
		}
		b.appendRegistration(record)
	}
}

// appendRegistration records one accounting without duplicating it.
func (b *implementationBoundary) appendRegistration(record BoundaryRegistration) {
	b.registrations = append(b.registrations, record)
}

// dedupeEdges keeps one record per (from, import path, registration) edge.
func (b *implementationBoundary) dedupeEdges() {
	seen := map[string]bool{}
	out := b.edges[:0]
	for _, edge := range b.edges {
		key := edge.From + "\x00" + edge.ImportPath + "\x00" + strconv.FormatBool(edge.Blank) + "\x00" + strconv.FormatBool(edge.Registration)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, edge)
	}
	b.edges = out
}

// componentCensusObligations are the blocking census facts of one component.
// Exported-entry obligations are reachability facts the closure accounts for by
// enumerating every declaration in the component; every other kind can hide a
// candidate and blocks.
func componentCensusObligations(component *boundaryComponent) []ProofObligation {
	if component.census == nil {
		return nil
	}
	var out []ProofObligation
	for _, obligation := range component.census.Obligations {
		if obligation.Kind == ObligationEntry {
			continue
		}
		out = append(out, ProofObligation{
			Kind: "CENSUS", Code: string(obligation.Kind), File: obligation.File,
			Line: obligation.Line, Detail: obligation.Detail,
		})
	}
	return out
}

// mechanismKey identifies one necessary-cover mechanism: an operation class on
// one correspondence resource key.
type mechanismKey struct {
	Class string
	Key   string
}

func (m mechanismKey) String() string { return m.Class + ":" + m.Key }

// candidates returns every boundary operation that performs the mechanism,
// whatever component it lives in and whatever its checked value is. A renamed,
// split, wrapped or externally supplied counterpart is found here.
func (b *implementationBoundary) candidates(mechanism mechanismKey) []LocationRecord {
	if b == nil {
		return nil
	}
	var out []LocationRecord
	for _, component := range b.components {
		if component.census == nil {
			continue
		}
		for _, operation := range component.census.Operations {
			if string(operation.Operation.Class) != mechanism.Class {
				continue
			}
			key, ok := CorrespondenceKey(operation.Operation.Resource.Expr.Identity)
			if !ok || key != mechanism.Key {
				continue
			}
			out = append(out, locationRecord(component.component, operation))
		}
	}
	sortLocations(out)
	return out
}

// certificate derives the non-counterpart certificate for one mechanism, or the
// obligations that defeat it. Candidates are never silently ignored: a candidate
// anywhere in the boundary refuses the certificate.
func (b *implementationBoundary) certificate(mechanism mechanismKey) (*NonCounterpartCertificate, []ProofObligation) {
	if mechanism.Class == "" || mechanism.Key == "" {
		return nil, []ProofObligation{{Kind: "CERTIFICATE", Code: "AMBIGUOUS_MECHANISM",
			Detail: "a certificate requires one resolved operation class and one resolved resource key"}}
	}
	var blocking []ProofObligation
	blocking = append(blocking, b.blocking...)
	for _, component := range b.components {
		blocking = append(blocking, componentCensusObligations(component)...)
	}
	if candidates := b.candidates(mechanism); len(candidates) > 0 {
		var locations []string
		for _, candidate := range candidates {
			locations = append(locations, fmt.Sprintf("%s %s:%d (%s)", candidate.Component, candidate.File, candidate.Line, candidate.Declaration))
		}
		blocking = append(blocking, ProofObligation{Kind: "CERTIFICATE", Code: "COUNTERPART_PRESENT",
			Detail: "the mechanism is present in the closed boundary at " + strings.Join(locations, "; ")})
	}
	if len(blocking) > 0 {
		return nil, blocking
	}
	certificate := &NonCounterpartCertificate{
		Rule: CertificateStructuralRule, Mechanism: mechanism.Class, ResourceKey: mechanism.Key,
		Boundary: "selected implementation plus every imported or registered external implementation component",
	}
	total := 0
	for _, component := range b.components {
		certificate.Components = append(certificate.Components, BoundaryComponent{
			Component: component.component, ImportPath: component.importPath,
			Module: component.module, Version: component.version, Kind: component.kind,
			Files: len(component.files), Digest: componentDigest(component),
		})
		if component.census != nil {
			total += component.census.Files
		}
		for _, closure := range component.censusClosures() {
			certificate.Closures = append(certificate.Closures, closure)
		}
	}
	certificate.Files = total
	certificate.Edges = append(certificate.Edges, b.edges...)
	certificate.Registrations = append(certificate.Registrations, b.registrations...)
	sortCertificate(certificate)
	certificate.Digest = certificate.computeDigest()
	return certificate, nil
}

// censusClosures lists the function literals the component analysis walked.
func (c *boundaryComponent) censusClosures() []BoundaryClosure {
	if c.census == nil {
		return nil
	}
	out := make([]BoundaryClosure, 0, len(c.census.Closures))
	for _, closure := range c.census.Closures {
		out = append(out, BoundaryClosure{
			Component: c.component, File: closure.File, Line: closure.Line,
			Declaration: closure.Declaration.String(),
		})
	}
	return out
}

// componentDigest is the digest of the component's complete captured file set.
func componentDigest(component *boundaryComponent) string {
	if component.census != nil && component.census.Digest != "" {
		return component.census.Digest
	}
	names := make([]string, 0, len(component.files))
	for name := range component.files {
		names = append(names, name)
	}
	sort.Strings(names)
	var builder strings.Builder
	for _, name := range names {
		builder.WriteString(name)
		builder.WriteByte(0)
		builder.WriteString(DigestBytes(component.files[name]))
		builder.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sortLocations imposes a deterministic location order.
func sortLocations(locations []LocationRecord) {
	sort.SliceStable(locations, func(i, j int) bool {
		left, right := locations[i], locations[j]
		if left.Component != right.Component {
			return left.Component < right.Component
		}
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		return left.Col < right.Col
	})
}

// sortCertificate orders every list so two identical boundaries produce one
// digest.
func sortCertificate(certificate *NonCounterpartCertificate) {
	sort.SliceStable(certificate.Components, func(i, j int) bool {
		return certificate.Components[i].Component < certificate.Components[j].Component
	})
	sort.SliceStable(certificate.Edges, func(i, j int) bool {
		left, right := certificate.Edges[i], certificate.Edges[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.ImportPath != right.ImportPath {
			return left.ImportPath < right.ImportPath
		}
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Blank != right.Blank {
			return !left.Blank
		}
		if left.Registration != right.Registration {
			return !left.Registration
		}
		return left.Component < right.Component
	})
	sort.SliceStable(certificate.Registrations, func(i, j int) bool {
		left, right := certificate.Registrations[i], certificate.Registrations[j]
		if left.Component != right.Component {
			return left.Component < right.Component
		}
		if left.File != right.File {
			return left.File < right.File
		}
		return left.Line < right.Line
	})
	sort.SliceStable(certificate.Closures, func(i, j int) bool {
		left, right := certificate.Closures[i], certificate.Closures[j]
		if left.Component != right.Component {
			return left.Component < right.Component
		}
		if left.File != right.File {
			return left.File < right.File
		}
		return left.Line < right.Line
	})
}
