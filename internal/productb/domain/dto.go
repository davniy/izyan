// Package domain is the adapter-local projection of the V2 data types the
// ported Product B runtime references. Every exported name is a type alias
// for the identical Shadow canonical data struct: the alias is the §14.3.2
// "map" disposition in code form — callers inside the adapter see the
// domain spelling their V2 port used, but no new authority is created.
//
// Only pure data types are re-exported. Authority types (Claim,
// NegativeVerification, VerdictResult, AnalysisCase, EvidenceGraph, ...)
// are deliberately absent: nothing in this package can mint, read or
// mutate Product A authority, and the boundary test pins that.
package domain

import (
	shadowdomain "github.com/fedorovmv/izyan/internal/domain"
)

// Advisory data types — the exact shapes finding/stage0/artifacts carry.

type Vulnerability = shadowdomain.Vulnerability
type VersionRange = shadowdomain.VersionRange
type AffectedPackage = shadowdomain.AffectedPackage
type SymbolRef = shadowdomain.SymbolRef
type AffectedModule = shadowdomain.AffectedModule
type Reference = shadowdomain.Reference

// Product identity types — the snapshot/build record and where its
// release toolchain evidence came from.

type ProductSnapshot = shadowdomain.ProductSnapshot
type ProductTarget = shadowdomain.ProductTarget
type BuildContext = shadowdomain.BuildContext
type GoVersionSource = shadowdomain.GoVersionSource

const (
	GoVersionSourceGoMod       = shadowdomain.GoVersionSourceGoMod
	GoVersionSourceToolchain   = shadowdomain.GoVersionSourceToolchain
	GoVersionSourceDockerfile  = shadowdomain.GoVersionSourceDockerfile
	GoVersionSourceCI          = shadowdomain.GoVersionSourceCI
	GoVersionSourceVersionFile = shadowdomain.GoVersionSourceVersionFile
	GoVersionSourceBinary      = shadowdomain.GoVersionSourceBinary
	GoVersionSourceExplicit    = shadowdomain.GoVersionSourceExplicit
)

// Product target provenance vocabulary — the closed source/scope pairs the
// canonical ProductTarget.Validate enforces. A host default is analysis
// context only and carries no scope.
const (
	ProductTargetSourceArtifactBuildInfo = shadowdomain.ProductTargetSourceArtifactBuildInfo
	ProductTargetSourceReleaseMetadata   = shadowdomain.ProductTargetSourceReleaseMetadata
	ProductTargetSourceOperatorDeclared  = shadowdomain.ProductTargetSourceOperatorDeclared
	ProductTargetSourceHostDefault       = shadowdomain.ProductTargetSourceHostDefault

	ProductTargetScopeArtifact = shadowdomain.ProductTargetScopeArtifact
	ProductTargetScopeRelease  = shadowdomain.ProductTargetScopeRelease
	ProductTargetScopeOperator = shadowdomain.ProductTargetScopeOperator
)

// SourceAnalyzerDefault marks severity/score values the analyzer itself
// synthesized because the advisory supplied neither — never an advisory
// source label. Shadow's domain does not define it (the V2 label is
// adapter-local), so the constant lives here.
const SourceAnalyzerDefault = "analyzer default"

type ReplaceDirective = shadowdomain.ReplaceDirective

// Deployment-exposure evidence — identical struct; the alias lets
// internal/exposure feed the adapter without a conversion layer.

type ExposureFact = shadowdomain.ExposureFact

// PerimeterAssessment is the canonical typed exposure classification. The
// alias keeps the V2 adapter boundary intact while the classifier returns the
// canonical type.
type PerimeterAssessment = shadowdomain.PerimeterAssessment
type CallSite = shadowdomain.CallSite
type ToolExecution = shadowdomain.ToolExecution

// Exploit-model data types — the deterministic condition universe the
// mandatory-condition source resolves over. Identical to Shadow's
// canonical structs; only the data shape is exposed.

type ConditionKind = shadowdomain.ConditionKind
type Condition = shadowdomain.Condition
type ExploitModel = shadowdomain.ExploitModel

// Defect-semantics types — the admitted contract and its derived deadness
// premise. They are data shapes whose derivation methods live on the
// canonical type; the adapter never re-derives a premise from names, prose or
// evidence prefixes.
type DefectSemanticsContract = shadowdomain.DefectSemanticsContract
type DeadnessPremise = shadowdomain.DeadnessPremise
var RequireDeadnessPremise = shadowdomain.RequireDeadnessPremise

var ErrDeadnessPremiseUnavailable = shadowdomain.ErrDeadnessPremiseUnavailable

const (
	ConditionSymbolReachable = shadowdomain.ConditionSymbolReachable
	ConditionBuild           = shadowdomain.ConditionBuild
	ConditionMissingCall     = shadowdomain.ConditionMissingCall
)

// Deployment-perimeter classification constants — identical strings the
// exposure classifier emits and decision-fact providers compare.

const (
	PerimeterClusterInternal = shadowdomain.PerimeterClusterInternal
	PerimeterPublic          = shadowdomain.PerimeterPublic
	PerimeterUnknown         = shadowdomain.PerimeterUnknown
)

// Exposure scope constants — the perimeter classifier's vocabulary.

const (
	ScopeAllInterfaces   = shadowdomain.ScopeAllInterfaces
	ScopeLoopback        = shadowdomain.ScopeLoopback
	ScopeUnix            = shadowdomain.ScopeUnix
	ScopeHostSpecific    = shadowdomain.ScopeHostSpecific
	ScopeClusterInternal = shadowdomain.ScopeClusterInternal
	ScopeStatic          = shadowdomain.ScopeStatic
	ScopeConfigured      = shadowdomain.ScopeConfigured
	ScopeUnknown         = shadowdomain.ScopeUnknown
)

// Triage priority vocabulary — data constants only; the adapter uses them
// for baseline/priority comparisons, never to mint a Product A verdict.

type TriagePriority = shadowdomain.TriagePriority

const (
	PriorityP0        = shadowdomain.PriorityP0
	PriorityP1        = shadowdomain.PriorityP1
	PriorityP2        = shadowdomain.PriorityP2
	PriorityP3        = shadowdomain.PriorityP3
	PriorityDismissed = shadowdomain.PriorityDismissed
)

// Declared-assumption channel types — the S-13 deployment adapter binds
// operator policy assertions (config-trust, supported-targets) through
// these. They are *inputs* the policy gate may require, never EvidenceGraph
// members, never verdict material. The domain admission function is the
// same canonical code the Product A channel uses: the alias keeps the
// adapter on one admission semantics.

type DeclaredAssumption = shadowdomain.DeclaredAssumption
type DeclaredAssumptionKind = shadowdomain.DeclaredAssumptionKind
type DeclaredAssumptionsInput = shadowdomain.DeclaredAssumptionsInput
type DeclaredAssumptionsDocument = shadowdomain.DeclaredAssumptionsDocument
type ProductTargetScope = shadowdomain.ProductTargetScope
type AssumptionRejection = shadowdomain.AssumptionRejection

const (
	DeclaredAssumptionsSchema   = shadowdomain.DeclaredAssumptionsSchema
	AssumptionConfigTrust       = shadowdomain.AssumptionConfigTrust
	AssumptionSupportedTargets  = shadowdomain.AssumptionSupportedTargets
	AssumptionScopeProduct      = shadowdomain.AssumptionScopeProduct
	AssumptionScopeArtifact     = shadowdomain.AssumptionScopeArtifact
	AssumptionScopeDeployment   = shadowdomain.AssumptionScopeDeployment
	AssumptionScopeConfigPrefix = shadowdomain.AssumptionScopeConfigPrefix

	AssumptionRejectDocumentAbsent  = shadowdomain.AssumptionRejectDocumentAbsent
	AssumptionRejectDocumentInvalid = shadowdomain.AssumptionRejectDocumentInvalid
	AssumptionRejectAbsent          = shadowdomain.AssumptionRejectAbsent
	AssumptionRejectScopeMismatch   = shadowdomain.AssumptionRejectScopeMismatch
	AssumptionRejectMalformed       = shadowdomain.AssumptionRejectMalformed
	AssumptionRejectDigestMismatch  = shadowdomain.AssumptionRejectDigestMismatch
	AssumptionRejectNotYetValid     = shadowdomain.AssumptionRejectNotYetValid
	AssumptionRejectExpired         = shadowdomain.AssumptionRejectExpired

	AssumptionsLoadUnreadable = shadowdomain.AssumptionsLoadUnreadable
	AssumptionsLoadOversized  = shadowdomain.AssumptionsLoadOversized
	AssumptionsLoadInvalid    = shadowdomain.AssumptionsLoadInvalid
)

// Deployment/trust basis vocabulary — the three disjoint basis spellings
// the adapter projects. declared-trust (operator assertion),
// auto-perimeter (classifier-detected) and config-origin (traced
// provenance) remain separate: a projection never merges them, and none
// of them is evidence inside the Product B artifact.

const (
	BasisDeclaredTrust = shadowdomain.BasisDeclaredTrust
	BasisAutoPerimeter = shadowdomain.BasisAutoPerimeter
	BasisConfigOrigin  = shadowdomain.BasisConfigOrigin
)

// Admission/validation entry points — the canonical functions, re-exported
// as the alias layer's only allowed import of internal/domain. Product B
// adapters call these, never re-implement the checks.

var (
	AdmitAssumption                  = shadowdomain.AdmitAssumption
	ValidateDeclaredAssumptions      = shadowdomain.ValidateDeclaredAssumptions
	ValidateDeclaredAssumption       = shadowdomain.ValidateDeclaredAssumption
	ScopeCovers                      = shadowdomain.ScopeCovers
	ValidAssumptionScope             = shadowdomain.ValidAssumptionScope
	AssumptionRejectionReason        = shadowdomain.AssumptionRejectionReason
	CanonicalAssumptionDigest        = shadowdomain.CanonicalAssumptionDigest
	DeclaredAssumptionsContentDigest = shadowdomain.DeclaredAssumptionsContentDigest
	EffectiveBuildContext            = shadowdomain.EffectiveBuildContext
)
