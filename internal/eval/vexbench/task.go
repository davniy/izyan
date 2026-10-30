// Package vexbench adapts the VEX-Bench benchmark to the analyzer: task
// intake, snapshot lookup, advisory preparation and scoring. It is a pure
// library — it imports no cmd code and performs no network access inside
// the analysis path — so hidden labels (ground truth, reference PRs) stay
// on the control-plane side and never reach the analyzer.
package vexbench

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Task is one VEX-Bench JSONL record. It is control-plane data:
// GroundTruth, GroundTruthCategory and PRURL exist only for the scorer and
// must never be passed to the analysis path (use AgentInputFor).
type Task struct {
	TaskID              string `json:"task_id"`
	RepoURL             string `json:"repo_url"`
	CommitSHA           string `json:"commit_sha"`
	CVEID               string `json:"cve_id"`
	GroundTruth         string `json:"ground_truth"` // exploitable|not_exploitable
	GroundTruthCategory string `json:"ground_truth_category"`
	Language            string `json:"language"` // metadata.language
	PRURL               string `json:"pr_url"`   // metadata.pr_url
}

// AgentInput is the only task data allowed into the analysis: the CVE id,
// the local snapshot path and the pinned external commit.
type AgentInput struct {
	TaskID    string `json:"task_id"`
	CVEID     string `json:"cve_id"`
	RepoPath  string `json:"repo_path"`
	CommitSHA string `json:"commit_sha"`
}

// taskJSON is the wire form: VEX-Bench nests language and pr_url under
// "metadata", while Task keeps them flat for scorer-side use.
type taskJSON struct {
	TaskID              string `json:"task_id"`
	RepoURL             string `json:"repo_url"`
	CommitSHA           string `json:"commit_sha"`
	CVEID               string `json:"cve_id"`
	GroundTruth         string `json:"ground_truth"`
	GroundTruthCategory string `json:"ground_truth_category"`
	Metadata            struct {
		Language string `json:"language"`
		PRURL    string `json:"pr_url"`
	} `json:"metadata"`
}

// LoadGoTasks reads a VEX-Bench JSONL file (one record per line, blank
// lines skipped) and returns the tasks with metadata.language == "go" in
// file order, with their labels kept on the control-plane Task.
func LoadGoTasks(path string) ([]Task, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open tasks: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var tasks []Task
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec taskJSON
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("tasks %s:%d: %w", path, line, err)
		}
		if !strings.EqualFold(rec.Metadata.Language, "go") {
			continue
		}
		tasks = append(tasks, Task{
			TaskID:              rec.TaskID,
			RepoURL:             rec.RepoURL,
			CommitSHA:           rec.CommitSHA,
			CVEID:               rec.CVEID,
			GroundTruth:         rec.GroundTruth,
			GroundTruthCategory: rec.GroundTruthCategory,
			Language:            rec.Metadata.Language,
			PRURL:               rec.Metadata.PRURL,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read tasks %s: %w", path, err)
	}
	return tasks, nil
}

// AgentInputFor strips a task down to what the analysis may see: CVE id,
// snapshot path and commit — never ground truth or the reference PR.
func AgentInputFor(t Task, repoPath string) AgentInput {
	return AgentInput{
		TaskID:    t.TaskID,
		CVEID:     t.CVEID,
		RepoPath:  repoPath,
		CommitSHA: t.CommitSHA,
	}
}

// ControlJoin creates the control-plane join mapping this task to an opaque finding ID.
// This join must be kept outside the agent bundle.
func (t Task) ControlJoin() ControlJoin {
	return ControlJoin{
		TaskID:    t.TaskID,
		FindingID: OpaqueFindingID(t.CVEID, t.CommitSHA),
		CVEID:     t.CVEID,
		CommitSHA: t.CommitSHA,
	}
}

// PrepareTriageCase delegates to PrepareTriageCase using the task's label-free fields:
// RepoURL, CommitSHA and CVEID. Labels (GroundTruth, GroundTruthCategory, PRURL) are excluded.
func (t Task) PrepareTriageCase(reposDir, frozenAdvisoryDir, bundleDir string, buildTarget *domain.ProductTarget) (PreparedCase, error) {
	return PrepareTriageCase(t.CVEID, t.RepoURL, t.CommitSHA, reposDir, frozenAdvisoryDir, bundleDir, buildTarget)
}
