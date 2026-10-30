package evidencetools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

)

func TestConfigWriterObservationDoesNotProveSafety(t *testing.T) {
	for _, tc := range []struct{fixture, pkg, symbol string}{
		{"configscalarprod", "example.com/configscalar", "Config.Enabled"},
		{"configoverrideprod", "example.com/configoverride", "Options.Enabled"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("..", "..", "testdata", tc.fixture)); must(t, err)
			s, err := NewSession(SessionConfig{SnapshotRoot:root, Strict:true, AllowToolchain:true, Audit:NopAudit{}}); must(t, err)
			ctx := context.Background()
			client, err := s.Connect(ctx); must(t, err); defer client.Close()
			args, err := json.Marshal(map[string]string{"package":tc.pkg,"symbol":tc.symbol}); must(t,err)
			o, err := client.Call(ctx,"field_assignments",args); must(t,err)
			if o.ToolStatus != StatusOK || o.Completeness != CompletenessPartial { t.Fatalf("not an observation: %+v",o) }
			raw, err := json.Marshal(o.Data); must(t,err)
			var data fieldAssignmentsData; must(t,json.Unmarshal(raw,&data))
			if len(data.Writers.Objects) == 0 || data.Writers.InventoryReference == "" || len(data.Writers.SourceHashes) == 0 || len(data.Writers.Blockers) == 0 { t.Fatalf("missing bounded evidence: %s",raw) }
			if data.Count != len(data.Assignments) { t.Fatal("legacy observation projection inconsistent") }
			t.Logf("offline observation: objects=%d assignments=%d channels=%d raw_inventory=%d reference=%s payload=%d completeness=%s",len(data.Writers.Objects),data.Count,len(data.Writers.RuntimeChannels),len(data.Writers.InventoryRaw),data.Writers.InventoryReference,len(raw),o.Completeness)
		})
	}
}
