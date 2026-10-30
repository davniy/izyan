package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// ReplayRun re-derives the verification report of one persisted run
// directory without any LLM call: the same extraction inputs Task 1
// consumed (assessment + observation archive + stage0 projection) plus
// the deterministic materials. The output is a pure function of the
// recorded artifacts — two replays of the same directory produce
// byte-identical reports.
func ReplayRun(runDir, ticket string) (*Report, error) {
	ext, err := claimshape.ExtractRun(runDir, ticket)
	if err != nil {
		return nil, fmt.Errorf("verification replay: extraction: %w", err)
	}
	in := Input{
		RunID:            ext.RunID,
		FindingID:        ext.FindingID,
		Claims:           ext.Claims,
		Advisory:         ext.Advisory,
		AssumeArchiveRun: true,
	}
	if p := filepath.Join(runDir, "observation-archive.json"); fileExists(p) {
		archive, aerr := triage.ReadObservationArchive(p)
		if aerr != nil {
			return nil, fmt.Errorf("verification replay: observation archive: %w", aerr)
		}
		in.Observations = archive.Observations
	}
	if p := filepath.Join(runDir, "materials.json"); fileExists(p) {
		var ms triage.MaterialSet
		if b, rerr := os.ReadFile(p); rerr == nil {
			if json.Unmarshal(b, &ms) == nil {
				in.Deploy = ms.Deploy
			}
		}
	}
	if p := filepath.Join(runDir, "falsifier-verification.json"); fileExists(p) {
		// The persisted proof report enters replay like any other artifact:
		// the graph revalidates each certificate under the generic proof
		// contract instead of trusting the stored status.
		var fr triage.FalsifierReport
		if b, rerr := os.ReadFile(p); rerr == nil && json.Unmarshal(b, &fr) == nil {
			in.Falsifiers = &fr
		}
	}
	if p := filepath.Join(runDir, "challenges.json"); fileExists(p) {
		// The reviewer channel's proposals replay deterministically:
		// a malformed document is a technical error, never a skipped
		// challenge.
		doc, cerr := ReadChallenges(p)
		if cerr != nil {
			return nil, fmt.Errorf("verification replay: challenges: %w", cerr)
		}
		in.Challenges = doc.Challenges
	}
	if in.RunID == "" {
		// Fall back to the deterministic attempt identity the observation
		// store stamps — replay of a run whose artifacts lack a run id
		// still binds its archive.
		if ext.FindingID != "" {
			in.RunID = triage.AttemptRunID(ext.FindingID, 1)
		}
	}
	rep := Evaluate(in)
	return &rep, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
