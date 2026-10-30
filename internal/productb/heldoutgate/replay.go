package heldoutgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	agenttriage "github.com/fedorovmv/izyan/internal/productb/triage"
	"github.com/fedorovmv/izyan/internal/productb/verify"
)

// ReplayIdentity resolves the run identity the archive itself stamped.
// The observation archive stamps its attempt identity (<finding>@attempt-N);
// decision.json carries a timestamped report id. The §5.1 contract binds
// observations to the run that produced them — replay must therefore bind
// to the archive's own stamp, never to the document id. verify.
// ReplayRun picks the document id (a defect the gate reports); this
// driver re-derives the same artifacts with the corrected identity.
func ReplayIdentity(archive []agenttriage.RecordedObservation, findingID string) (string, []string) {
	var notes []string
	ids := map[string]int{}
	for i := range archive {
		ids[archive[i].RunID]++
	}
	delete(ids, "")
	var uniq []string
	for id := range ids {
		uniq = append(uniq, id)
	}
	sort.Strings(uniq)
	switch len(uniq) {
	case 0:
		if findingID == "" {
			notes = append(notes, "archive carries no run_id stamps and finding id is unknown; observations stay unbound")
			return "", notes
		}
		return agenttriage.AttemptRunID(findingID, 1), notes
	case 1:
		return uniq[0], notes
	default:
		notes = append(notes, "archive mixes foreign run_id stamps: "+strings.Join(uniq, ", "))
		return agenttriage.AttemptRunID(findingID, 1), notes
	}
}

// snapshotPins reads the run-level provenance pins the stability
// controller compares across re-derivations (plan §6.5 retry contract).
func snapshotPins(runDir string) verify.AttemptPins {
	var snap struct {
		InputHash        string `json:"input_hash"`
		ContentHash      string `json:"content_hash"`
		ResolvedRevision string `json:"resolved_revision"`
		Revision         string `json:"revision"`
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "snapshot.json")); err == nil {
		_ = json.Unmarshal(b, &snap)
	}
	var st0 struct {
		ConfigHash    string          `json:"config_hash"`
		Advisory      json.RawMessage `json:"advisory"`
		RefResolution struct {
			Selected string `json:"selected"`
		} `json:"ref_resolution"`
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "stage0.json")); err == nil {
		_ = json.Unmarshal(b, &st0)
	}
	var input json.RawMessage
	if b, err := os.ReadFile(filepath.Join(runDir, "input.json")); err == nil {
		input = b
	}
	pins := verify.AttemptPins{
		SnapshotHash:   snap.ContentHash,
		RulesetHash:    st0.ConfigHash,
		SelectedRef:    snap.Revision,
		ResolvedCommit: snap.ResolvedRevision,
	}
	if len(input) > 0 {
		h := sha256.Sum256(input)
		pins.InputHash = hex.EncodeToString(h[:])
	} else {
		pins.InputHash = snap.InputHash
	}
	if len(st0.Advisory) > 0 {
		h := sha256.Sum256(st0.Advisory)
		pins.AdvisoryHash = hex.EncodeToString(h[:])
	}
	return pins
}

// ReplayRun is the corrected-binding replay driver: the same artifact
// set verify.ReplayRun consumes, evaluated under the archive's own
// attempt identity. It returns the report plus the attempt pins.
func ReplayRun(runDir, ticket string, assumeArchiveRun bool) (*verify.Report, verify.AttemptPins, string, error) {
	ext, err := claimshape.ExtractRun(runDir, ticket)
	if err != nil {
		return nil, verify.AttemptPins{}, "", fmt.Errorf("heldout replay: extraction: %w", err)
	}
	var archive []agenttriage.RecordedObservation
	if p := filepath.Join(runDir, "observation-archive.json"); fileExists(p) {
		a, aerr := agenttriage.ReadObservationArchive(p)
		if aerr != nil {
			return nil, verify.AttemptPins{}, "", fmt.Errorf("heldout replay: observation archive: %w", aerr)
		}
		archive = a.Observations
	}
	runID, _ := ReplayIdentity(archive, ext.FindingID)
	in := verify.Input{
		RunID:            runID,
		FindingID:        ext.FindingID,
		Claims:           ext.Claims,
		Observations:     archive,
		Advisory:         ext.Advisory,
		AssumeArchiveRun: assumeArchiveRun,
	}
	if p := filepath.Join(runDir, "materials.json"); fileExists(p) {
		var ms agenttriage.MaterialSet
		if b, rerr := os.ReadFile(p); rerr == nil {
			if json.Unmarshal(b, &ms) == nil {
				in.Deploy = ms.Deploy
			}
		}
	}
	if p := filepath.Join(runDir, "falsifier-verify.json"); fileExists(p) {
		var fr agenttriage.FalsifierReport
		if b, rerr := os.ReadFile(p); rerr == nil && json.Unmarshal(b, &fr) == nil {
			in.Falsifiers = &fr
		}
	}
	if p := filepath.Join(runDir, "challenges.json"); fileExists(p) {
		doc, cerr := verify.ReadChallenges(p)
		if cerr != nil {
			return nil, verify.AttemptPins{}, "", fmt.Errorf("heldout replay: challenges: %w", cerr)
		}
		in.Challenges = doc.Challenges
	}
	rep := verify.Evaluate(in)
	return &rep, snapshotPins(runDir), ext.FindingID, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// groupKey renders the §8.2 grouped hold-out key: repository/source id
// first, then advisory family and advisory id so calibration and
// evaluation can never share a group.
func groupKey(sourceID, family, advisory string) string {
	if sourceID == "" {
		sourceID = "unknown-repo"
	}
	if family == "" {
		family = "unknown-family"
	}
	if advisory == "" {
		advisory = "unknown-advisory"
	}
	return sourceID + "|" + family + "|" + advisory
}

// advisoryFamily mirrors claimshape's private family rule (package wins
// over module) so the gate groups by the same key the Task-1 report used.
func advisoryFamily(a claimshape.AdvisoryFacts) string {
	if a.Package != "" {
		return a.Package
	}
	return a.Module
}
