package triage

import (
 "bytes"
 "context"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"

 "github.com/davniy/izyan/internal/flock"
)

const EnvironmentAssertionSchemaVersion = "environment-assertion.v1"
const environmentAssertionsDirName = "environment-assertions"

// EnvironmentAssertion is a human-owned premise, never a code claim or proof.
type EnvironmentAssertion struct {
 ID string `json:"id"`
 Variable string `json:"variable"`
 Value string `json:"value"`
 Principal string `json:"principal"`
 Source string `json:"source"`
 Freshness string `json:"freshness"`
 Timestamp time.Time `json:"timestamp"`
 Supersedes []string `json:"supersedes,omitempty"`
}

type HumanReviewProjection struct {
 PackageHash string `json:"package_hash"`
 BranchID string `json:"branch_id"`
 ProjectionHash string `json:"projection_hash"`
 Judgment LLMJudgment `json:"judgment"`
 Action HumanAction `json:"action"`
 Support DecisionSupport `json:"support"`
 Status HumanBranchStatus `json:"status"`
 AssertionIDs []string `json:"assertion_ids"`
}

func environmentAssertionID(a EnvironmentAssertion) string { a.ID = ""; return "ea-" + projectionHash(a) }
func assertionSource(pkg DecisionPackage, v DecisionVariable) string { return "decision:" + canonicalDecisionHash(pkg) + ":variable:" + v.ID + ":" + projectionHash(v) }

// ApplyEnvironmentAssertions selects only a captured prepared branch. It has no
// investigator, source, model or tool interface, and never modifies the package.
func ApplyEnvironmentAssertions(pkg DecisionPackage, assertions []EnvironmentAssertion) (HumanReviewProjection, error) {
 p := HumanReviewProjection{PackageHash: canonicalDecisionHash(pkg), Judgment: pkg.Judgment, Action: pkg.ProposedAction, Support: pkg.Support, Status: HumanBranchAwaitingInput}
 if err := validateHumanDecisionPackage(pkg); err != nil { return p, err }
 vars := map[string]DecisionVariable{}
 assignments := map[string]string{}
 for _, v := range pkg.HumanReviewPlan.Variables { vars[v.ID] = v; if !v.Required { assignments[v.ID] = v.AllowedValues[0] } }
 seen := map[string]EnvironmentAssertion{}
 superseded := map[string]bool{}
 // Input order is irrelevant, including equal timestamps. A supersession graph
 // must point strictly backward in time and only within one declared variable.
 for _, a := range assertions {
  v, ok := vars[a.Variable]
  if !ok || !v.Required { return p, fmt.Errorf("undeclared environment answer %q", a.Variable) }
  if !containsString(v.AllowedValues, a.Value) { return p, fmt.Errorf("invalid environment answer %s=%s", a.Variable, a.Value) }
  if a.ID != environmentAssertionID(a) || strings.TrimSpace(a.Principal) == "" || a.Timestamp.IsZero() || a.Timestamp.Location() != time.UTC || a.Source != assertionSource(pkg, v) || a.Freshness != "review-session:"+a.Timestamp.Format(time.RFC3339Nano) { return p, fmt.Errorf("invalid environment assertion %q or package binding", a.ID) }
  if _, ok := seen[a.ID]; ok { return p, fmt.Errorf("duplicate assertion %s", a.ID) }; seen[a.ID] = a
 }
 for _, a := range assertions { local := map[string]bool{}; for _, id := range a.Supersedes {
  old, ok := seen[id]
  if !ok || local[id] || old.Variable != a.Variable || !old.Timestamp.Before(a.Timestamp) { return p, fmt.Errorf("invalid assertion supersession %s", id) }; local[id] = true; superseded[id] = true
 } }
 conflict := false
 for _, a := range assertions { if !superseded[a.ID] {
  if old, ok := assignments[a.Variable]; ok && old != a.Value { conflict = true }
  assignments[a.Variable] = a.Value; p.AssertionIDs = append(p.AssertionIDs, a.ID)
 } }
 sort.Strings(p.AssertionIDs)
 if pkg.HumanReviewPlan.Readiness == string(HumanBranchNotDecisionReady) { p.BranchID = pkg.HumanReviewPlan.Branches[0].ID; p.Status = HumanBranchNotDecisionReady; p.Action = conservativeBranchAction(p.Action) } else if conflict {
  for _, v := range vars { if v.Required { assignments[v.ID] = EnvironmentUnknown } }
  for _, branch := range pkg.HumanReviewPlan.Branches {
   if assignmentKey(branch.Assignments) == assignmentKey(assignments) { p.BranchID, p.Judgment, p.Support = branch.ID, branch.Judgment, branch.Support; break }
  }
  p.Status = HumanBranchContradicted; p.Action = conservativeBranchAction(p.Action)
 } else if len(assignments) == len(vars) {
  found := false
  for _, b := range pkg.HumanReviewPlan.Branches { if assignmentKey(b.Assignments) == assignmentKey(assignments) { p.BranchID, p.Judgment, p.Action, p.Support, p.Status = b.ID, b.Judgment, b.Action, b.Support, b.Status; found = true; break } }
  if !found { return p, fmt.Errorf("no prepared branch for environment answers") }
 }
 p.ProjectionHash = projectionHash(p)
 return p, nil
}

type environmentAssertionFile struct { Assertion EnvironmentAssertion; Bytes []byte }
type environmentAssertionEnvelope struct {
 SchemaVersion string `json:"schema_version"`
 PackageHash string `json:"package_hash"`
 Assertion EnvironmentAssertion `json:"assertion"`
}

// Caller holds the shared review lock. Both collections use the same lock so
// selecting a projection and appending its Accept/Reject is one transaction.
func readEnvironmentAssertionFilesUnlocked(dir string, pkg DecisionPackage) ([]environmentAssertionFile, error) {
 entries, err := os.ReadDir(filepath.Join(dir, environmentAssertionsDirName)); if os.IsNotExist(err) { return nil, nil }; if err != nil { return nil, err }
 var files []environmentAssertionFile
 var assertions []EnvironmentAssertion
 for _, e := range entries {
  if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") { return nil, fmt.Errorf("invalid environment assertion file %s", e.Name()) }
  data, err := os.ReadFile(filepath.Join(dir, environmentAssertionsDirName, e.Name())); if err != nil { return nil, err }
  var envelope environmentAssertionEnvelope
  if !json.Valid(data) { return nil, fmt.Errorf("invalid environment assertion JSON %s", e.Name()) }
  dec := json.NewDecoder(bytes.NewReader(data)); dec.DisallowUnknownFields()
  if err := dec.Decode(&envelope); err != nil { return nil, err }
  if envelope.SchemaVersion != EnvironmentAssertionSchemaVersion || envelope.PackageHash != canonicalDecisionHash(pkg) || e.Name() != envelope.Assertion.ID+".json" { return nil, fmt.Errorf("environment assertion package/schema/id mismatch") }
  assertions = append(assertions, envelope.Assertion); files = append(files, environmentAssertionFile{envelope.Assertion, data})
 }
 if len(assertions) > 0 { if _, err := ApplyEnvironmentAssertions(pkg, assertions); err != nil { return nil, err } }
 return files, nil
}

func ReadEnvironmentAssertions(dir string, pkg DecisionPackage) ([]EnvironmentAssertion, error) {
 if _, err := os.Stat(filepath.Join(dir, environmentAssertionsDirName)); os.IsNotExist(err) { return nil, nil } else if err != nil { return nil, err }
 unlock, err := flock.Shared(filepath.Join(dir, humanDecisionsLockName)); if err != nil { return nil, fmt.Errorf("environment assertions: %w", err) }; defer unlock()
 files, err := readEnvironmentAssertionFilesUnlocked(dir, pkg); if err != nil { return nil, err }
 out := make([]EnvironmentAssertion, 0, len(files)); for _, f := range files { out = append(out, f.Assertion) }; return out, nil
}

// WriteEnvironmentAnswers captures provenance from the immutable question and
// configured review principal; no technical narrative is requested from people.
// Existing active answers are explicitly superseded, never overwritten.
func (w ArtifactWriter) WriteEnvironmentAnswers(ctx context.Context, dir, principal string, answers []string) (HumanReviewProjection, error) {
 var zero HumanReviewProjection
 if ctx == nil { ctx = context.Background() }; if err := ctx.Err(); err != nil { return zero, err }
 if len(answers) > MaxEnvironmentQuestions { return zero, fmt.Errorf("at most two --answer variables are allowed") }
 if strings.TrimSpace(principal) == "" { return zero, fmt.Errorf("review principal is required") }
 pkg, err := loadCurrentDecisionPackage(dir); if err != nil { return zero, err }
 unlock, err := flock.Exclusive(filepath.Join(dir, humanDecisionsLockName), 0600); if err != nil { return zero, err }; defer unlock()
 files, err := readEnvironmentAssertionFilesUnlocked(dir, pkg); if err != nil { return zero, err }
 var history []EnvironmentAssertion; for _, f := range files { history = append(history, f.Assertion) }
 current, err := ApplyEnvironmentAssertions(pkg, history); if err != nil { return zero, err }
 active := map[string]bool{}; for _, id := range current.AssertionIDs { active[id] = true }
 seen := map[string]bool{}
 var additions []EnvironmentAssertion
 for _, text := range answers {
  variable, value, ok := strings.Cut(text, "="); if !ok || seen[variable] { return zero, fmt.Errorf("answer must name a distinct variable=value") }; seen[variable] = true
  var contract *DecisionVariable
  for i := range pkg.HumanReviewPlan.Variables { v := &pkg.HumanReviewPlan.Variables[i]; if v.ID == variable && v.Required { contract = v } }
  if contract == nil { return zero, fmt.Errorf("undeclared environment answer %q", variable) }
  a := EnvironmentAssertion{Variable: variable, Value: value, Principal: principal, Source: assertionSource(pkg, *contract), Timestamp: w.now().UTC()}
  a.Freshness = "review-session:" + a.Timestamp.Format(time.RFC3339Nano)
  same := false
  for _, old := range history { if old.Variable == variable && active[old.ID] { if old.Value == value { same = true }; a.Supersedes = append(a.Supersedes, old.ID) } }
  if same && len(a.Supersedes) == 1 { continue }
  sort.Strings(a.Supersedes); a.ID = environmentAssertionID(a); additions = append(additions, a)
 }
 history = append(history, additions...)
 projection, err := ApplyEnvironmentAssertions(pkg, history); if err != nil { return zero, err }
 for _, a := range additions {
  data, err := json.MarshalIndent(environmentAssertionEnvelope{EnvironmentAssertionSchemaVersion, canonicalDecisionHash(pkg), a}, "", "  "); if err != nil { return zero, err }
  data = append(data, '\n')
  path, err := w.appendReviewRecord(ctx, dir, environmentAssertionsDirName, a.ID, data)
  if err != nil { return zero, fmt.Errorf("environment assertion %s persistence path %q: %w", a.ID, path, err) }
  event := AuditEvent{Type: "environment_assertion", Timestamp: a.Timestamp, RunID: pkg.RunID, Status: "ok", Hash: hashBytes(data), Scope: a.ID}
  if err := appendAuditLog(ctx, filepath.Join(dir, "audit", "events.jsonl"), []AuditEvent{event}, pkg.RunID, a.Timestamp); err != nil { return zero, fmt.Errorf("environment assertion %s persisted at %s but audit append failed: %w", a.ID, path, err) }
 }
 return projection, nil
}

// appendReviewRecord shares the review writer's O_EXCL/file+directory durability
// protocol. The caller owns the collection lock. Complete files survive a
// directory-sync failure, and the returned path reports that partial success.
func (w ArtifactWriter) appendReviewRecord(ctx context.Context, dir, collection, id string, data []byte) (string, error) {
	if err := ctx.Err(); err != nil { return "", err }
	recordsDir := filepath.Join(dir, collection)
	if err := os.MkdirAll(recordsDir, 0o755); err != nil { return "", fmt.Errorf("human review: create review collection: %w", err) }
	if err := w.syncReviewDir(dir); err != nil { return "", fmt.Errorf("human review: sync run directory %s: %w", dir, err) }
	path := filepath.Join(recordsDir, id+".json")
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("human review: record %s already exists at %s: %w", id, path, ErrHumanDecisionExists)
	} else if !os.IsNotExist(err) { return "", fmt.Errorf("human review: inspect record %s: %w", path, err) }
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) { return "", fmt.Errorf("human review: record %s already exists at %s: %w", id, path, ErrHumanDecisionExists) }
		return "", fmt.Errorf("human review: create record %s: %w", path, err)
	}
	if collection == humanDecisionsDirName && w.testAfterHumanDecisionCreate != nil { w.testAfterHumanDecisionCreate() }
	fail := func(cause error) (string,error) { _ = f.Close(); _ = os.Remove(path); return "",cause }
	if _, err := f.Write(data); err != nil { return fail(fmt.Errorf("human review: write record %s: %w", path, err)) }
	if err := f.Sync(); err != nil { return fail(fmt.Errorf("human review: sync record %s: %w", path, err)) }
	if err := f.Close(); err != nil { _ = os.Remove(path); return "", fmt.Errorf("human review: close record %s: %w", path, err) }
	if err := w.syncReviewDir(recordsDir); err != nil { return path, fmt.Errorf("human review %s persisted at %s but the review directory sync failed: %w", id, path, err) }
	return path,nil
}

func validateReviewProjection(rec HumanDecisionRecord, pkg DecisionPackage, files []environmentAssertionFile) error {
 byID := map[string]EnvironmentAssertion{}; for _, f := range files { byID[f.Assertion.ID] = f.Assertion }
 selected := map[string]bool{}
 var assertions []EnvironmentAssertion
 var add func(string) error
 add = func(id string) error {
  if selected[id] { return nil }; a, ok := byID[id]; if !ok || a.Timestamp.After(rec.RecordedAt) { return fmt.Errorf("missing or future assertion %s", id) }; selected[id] = true
  for _, parent := range a.Supersedes { if err := add(parent); err != nil { return err } }; assertions = append(assertions, a); return nil
 }
 for _, id := range rec.AssertionIDs { if err := add(id); err != nil { return err } }
 p, err := ApplyEnvironmentAssertions(pkg, assertions); if err != nil { return err }
 if p.Status == HumanBranchAwaitingInput || p.BranchID != rec.BranchID || p.ProjectionHash != rec.ProjectionHash || !jsonEqual(p.AssertionIDs, rec.AssertionIDs) { return fmt.Errorf("review branch/projection/assertion binding mismatch") }; return nil
}
