package evidencetools

import (
	"context"
	"fmt"

	"github.com/fedorovmv/izyan/internal/affected"
)

// PackageInventoryArgs selects product packages or the merged test inventory.
type PackageInventoryArgs struct {
	WithTests bool `json:"with_tests"`
}

// PackageInventoryData preserves full digest-bound stdout and decoded package
// identities. Completeness never implies source/load or upstream completeness.
type PackageInventoryData = affected.PackageInventoryMeasurement

func (s *Session) packageInventory(ctx context.Context, a PackageInventoryArgs) (*Observation, error) {
	if s.toolchainDenied() || s.GoTool == nil {
		return s.unsupported("package-inventory", "package inventory requires the toolchain capability"), nil
	}
	if _, err := s.probeSnapshot(ctx); err != nil {
		return nil, err
	}
	data := affected.MeasurePackageInventory(ctx, s.GoTool, s.SnapshotRoot, s.Build, a.WithTests)
	c := CompletenessPartial
	var lims []string
	if data.Run.Complete {
		c = CompletenessComplete
	} else {
		lims = append(lims, data.Run.Error)
	}
	return s.ok("package-inventory", fmt.Sprintf("%d witnessed package identities", len(data.Packages)), data.Scope, c, data,
		&ScopeDetails{SnapshotHash: s.SnapshotHash, SnapshotRoot: s.SnapshotRoot, BuildContext: s.buildContext(),
			CoverageRule: "successful edge-closed package stream for ./... under the identified effective build"}, lims), nil
}
