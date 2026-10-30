package rootcause

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// coordinateResolution answers one question: does this module-relative patch
// coordinate exist in the source of the version the recorded build selected?
//
// It is the single rule both consumers use — a fix-derived candidate's identity
// and a captured artifact's applicability — so the two can never disagree about
// whether fix material belongs to the analysed version. It establishes
// existence only: correspondence between a changed span and a vulnerable
// operation is a separate question this resolution never answers.
type coordinateResolution struct {
	// Reason is non-empty when the coordinate could not be checked at all: no
	// selected-source input, an unresolvable selection, or an unusable path.
	Reason string
	// InputFailure marks Reason as a missing or unreadable input (INPUT-owned)
	// rather than work the analyzer cannot do (CODE-owned).
	InputFailure bool
	// Exists reports whether the coordinate is a regular file in the resolved
	// source. It carries no meaning when Reason is set.
	Exists bool
	// Version is the coordinate's version under the selection that was applied.
	Version string
	// Source is the source the coordinate was tested against.
	Source domain.ResolvedModuleSource
}

// resolved reports whether a source selection could answer the question.
func (r coordinateResolution) resolved() bool { return r.Reason == "" }

// resolveCoordinate applies the recorded build's source selection to one
// module-relative patch coordinate.
func resolveCoordinate(src *goanalysis.Index, c *domain.AnalysisCase, modulePath, relPath string) coordinateResolution {
	version := selectedVersion(c, modulePath)
	if src == nil {
		return coordinateResolution{Version: version, Reason: fmt.Sprintf(
			"no selected-source index is configured, so %s cannot be resolved against %s", relPath, modulePath)}
	}
	// A persisted effective-source descriptor is the recorded build fact: when
	// the affected chain captured one, the coordinate binds to that selection —
	// including its typed failure, which must not fall back to the declared
	// module's published bytes.
	recorded := recordedEffectiveSource(c, modulePath)
	switch {
	case recorded != nil && recorded.Failure != nil:
		return coordinateResolution{Version: version, InputFailure: true, Reason: fmt.Sprintf(
			"the recorded effective source for %s is unavailable (%s): %s",
			modulePath, recorded.Failure.Kind, recorded.Failure.Detail)}
	case recorded != nil && recorded.SourceKind != "":
		source, exists, err := src.SelectedModuleCoordinateFor(*recorded, relPath)
		return coordinateResolution{
			Version:      recorded.EffectiveVersion,
			Exists:       exists,
			Source:       source,
			Reason:       coordinateErrorReason(err),
			InputFailure: err != nil,
		}
	case version == "":
		return coordinateResolution{InputFailure: true, Reason: fmt.Sprintf(
			"the affected chain recorded no resolved version for %s", modulePath)}
	default:
		source, exists, err := src.SelectedModuleCoordinate(modulePath, version, relPath)
		return coordinateResolution{
			Version:      version,
			Exists:       exists,
			Source:       source,
			Reason:       coordinateErrorReason(err),
			InputFailure: err != nil,
		}
	}
}

func coordinateErrorReason(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
