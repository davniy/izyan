package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// BuildTargetAbsentLimitation is the one explicit statement that the
// investigation has no identified product build. The analyzer host may still
// be the platform the evidence session runs on; it is analysis context, never
// a product declaration, and build-dependent negatives stay inadmissible.
const BuildTargetAbsentLimitation = "no product build target was identified: the analysis platform is the analyzer host, not a product build fact; build-dependent negatives remain inadmissible"

// AgentBuildContext is the agent-facing build distinction: the identified
// product target when one was supplied, otherwise the analyzer's effective
// analysis platform explicitly labelled as context only.
type AgentBuildContext struct {
	ProductTarget       *domain.ProductTarget `json:"product_target,omitempty"`
	AnalysisPlatform    string                `json:"analysis_platform"`
	AnalysisContextOnly bool                  `json:"analysis_context_only,omitempty"`
	Limitations         []string              `json:"limitations,omitempty"`
}

// newAgentBuildContext renders the target/analysis-platform distinction. A
// nil target never becomes a host-shaped product fact.
func newAgentBuildContext(target *domain.ProductTarget) *AgentBuildContext {
	if target != nil {
		out := cloneBuildTarget(target)
		return &AgentBuildContext{ProductTarget: out, AnalysisPlatform: out.Platform()}
	}
	return &AgentBuildContext{
		AnalysisPlatform:    runtime.GOOS + "/" + runtime.GOARCH,
		AnalysisContextOnly: true,
		Limitations:         []string{BuildTargetAbsentLimitation},
	}
}

// BuildTargetAuditLine renders the per-attempt det-tools audit record of the
// resolved build, or the explicit absent-target distinction when none exists.
func BuildTargetAuditLine(target *domain.ProductTarget) string {
	if target == nil {
		return BuildTargetAbsentLimitation
	}
	return fmt.Sprintf("product build target: %s tags=%v cgo=%v source=%s scope=%s",
		target.Platform(), target.BuildTags, target.CGOEnabled, target.Source, target.Scope)
}

// that may be shown to the agent. It is an in-memory context, not an artifact
// schema and never carries raw manifests, credentials, or unbounded text.
type AgentMaterials struct {
	Materials   []AgentMaterial         `json:"materials,omitempty"`
	Deploy      *AgentDeployContext     `json:"deploy,omitempty"`
	ModuleGraph AgentModuleGraphContext `json:"module_graph"`
	// Captured is the metadata of the supplied investigation material
	// (advisory records and fixes). The bytes travel only through
	// read_material; a captured set is untrusted data, never instructions.
	Captured []CapturedMaterial `json:"captured,omitempty"`
	// Build names the identified product build or explicitly labels the
	// analysis platform as host context only.
	Build       *AgentBuildContext `json:"build,omitempty"`
	Limitations []string           `json:"limitations,omitempty"`
}

type AgentMaterial struct {
	ID           string               `json:"material_id"`
	Kind         string               `json:"kind"`
	Source       string               `json:"source,omitempty"`
	Scope        string               `json:"scope,omitempty"`
	Availability MaterialAvailability `json:"availability"`
	SHA256       string               `json:"sha256,omitempty"`
	Size         int64                `json:"size,omitempty"`
	Provenance   []string             `json:"provenance,omitempty"`
	Limitations  []string             `json:"limitations,omitempty"`
}

type AgentModuleGraphContext struct {
	Source   string `json:"source,omitempty"`
	Complete bool   `json:"complete"`
	Count    int    `json:"count"`
	SHA256   string `json:"sha256,omitempty"`
}

type AgentDeployContext struct {
	FactCount    int                 `json:"fact_count"`
	Perimeter    string              `json:"perimeter"`
	Rationale    string              `json:"rationale,omitempty"`
	ScannedPaths []string            `json:"scanned_paths,omitempty"`
	Archives     []string            `json:"archives,omitempty"`
	Exposures    []AgentExposureFact `json:"exposures,omitempty"`
}

type AgentExposureFact struct {
	Direction     string `json:"direction"`
	Kind          string `json:"kind"`
	Target        string `json:"target,omitempty"`
	Scope         string `json:"scope,omitempty"`
	AddressSource string `json:"address_source,omitempty"`
	Owner         string `json:"owner,omitempty"`
	File          string `json:"file,omitempty"`
	Line          int    `json:"line,omitempty"`
	Function      string `json:"function,omitempty"`
}

// BuildAgentMaterials copies only deterministic metadata and safe exposure
// projections. Unknown or absent deployment data remains explicit unknown.
// An optional captured investigation set contributes its material metadata
// only — never bytes and never an authority claim.
func BuildAgentMaterials(set MaterialSet, investigations ...InvestigationInputs) AgentMaterials {
	out := AgentMaterials{Limitations: append([]string(nil), set.Limitations...)}
	if len(investigations) > 0 {
		out.Captured = investigations[0].Materials()
		out.Build = newAgentBuildContext(investigations[0].BuildTarget)
	}
	for _, m := range set.Materials {
		out.Materials = append(out.Materials, AgentMaterial{
			ID: m.ID, Kind: m.Kind, Source: m.Source, Scope: m.Scope,
			Availability: m.Availability, SHA256: m.SHA256, Size: m.Size,
			Provenance: append([]string(nil), m.Provenance...), Limitations: append([]string(nil), m.Limitations...),
		})
	}
	if set.ModuleGraph != nil {
		out.ModuleGraph = AgentModuleGraphContext{Source: set.ModuleGraph.Source, Complete: set.ModuleGraph.Complete, Count: len(set.ModuleGraph.Modules), SHA256: set.ModuleGraph.SHA256}
	}
	if set.Deploy != nil {
		d := set.Deploy
		out.Deploy = &AgentDeployContext{FactCount: d.FactCount, Perimeter: d.Perimeter, Rationale: d.Rationale, ScannedPaths: append([]string(nil), d.ScannedPaths...), Archives: append([]string(nil), d.Archives...)}
		out.Deploy.Exposures = append(out.Deploy.Exposures, d.ExposureProjection...)
		if len(out.Deploy.Exposures) == 0 {
			out.Deploy.Exposures = exposureProjection(d.Facts)
		}
	}
	return out
}

func exposureProjection(facts []domain.ExposureFact) []AgentExposureFact {
	out := make([]AgentExposureFact, 0, len(facts))
	for _, f := range facts {
		out = append(out, AgentExposureFact{Direction: f.Direction, Kind: f.Kind, Target: f.Target, Scope: f.Scope, AddressSource: f.AddressSource, Owner: f.Owner, File: f.File, Line: f.Line, Function: f.Function})
	}
	return out
}

func exposureProjectionHash(projection []AgentExposureFact) string {
	canonical := append([]AgentExposureFact(nil), projection...)
	sort.SliceStable(canonical, func(i, j int) bool {
		left := strings.Join([]string{canonical[i].Direction, canonical[i].Kind, canonical[i].Target, canonical[i].Scope, canonical[i].AddressSource, canonical[i].Owner, canonical[i].File, fmt.Sprint(canonical[i].Line), canonical[i].Function}, "\x00")
		right := strings.Join([]string{canonical[j].Direction, canonical[j].Kind, canonical[j].Target, canonical[j].Scope, canonical[j].AddressSource, canonical[j].Owner, canonical[j].File, fmt.Sprint(canonical[j].Line), canonical[j].Function}, "\x00")
		return left < right
	})
	b, _ := json.Marshal(canonical)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func validateMaterialSet(set MaterialSet) error {
	if set.Deploy == nil || set.Deploy.ProjectionSHA256 == "" {
		return nil
	}
	if got := exposureProjectionHash(set.Deploy.ExposureProjection); got != set.Deploy.ProjectionSHA256 {
		return fmt.Errorf("deployment exposure projection hash mismatch: recorded %s, recomputed %s", set.Deploy.ProjectionSHA256, got)
	}
	return nil
}
