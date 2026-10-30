package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/llm"
)

// setupRefGitRepo builds a local repository with plain tags, release-style
// tags and extra branches so ref enumeration, selection and fallback can be
// exercised deterministically.
func setupRefGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commitFile := func(name, content, msg string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", name)
		run("commit", "-m", msg)
	}

	run("init")
	run("symbolic-ref", "HEAD", "refs/heads/main")
	run("config", "user.name", "Test")
	run("config", "user.email", "test@example.com")

	commitFile("version.txt", "1.3.9", "release 1.3.9")
	run("tag", "v1.3.9")
	commitFile("version.txt", "1.4.0", "release 1.4.0")
	run("tag", "v1.4.0")
	commitFile("version.txt", "1.5.0", "release 1.5.0")
	run("tag", "v1.5.0")
	run("tag", "release/1.5")
	commitFile("version.txt", "dev", "work")
	run("branch", "devel")
	return dir
}

func publishedReleasePolicy() ReleasePolicy {
	return ReleasePolicy{AllowedRefKinds: []string{"tag", "release"}, RequireResolvedCommit: true}
}

func refEntry(dir string) CatalogEntry {
	return CatalogEntry{ID: "local-example-service", Kind: "local", Root: dir}
}

func candByID(cands []RefCandidate, id string) (RefCandidate, bool) {
	for _, c := range cands {
		if c.ID == id {
			return c, true
		}
	}
	return RefCandidate{}, false
}

func TestRefEnumLocalRepo(t *testing.T) {
	dir := setupRefGitRepo(t)
	enum := RefEnumerator{MaxCandidates: 16}

	cands, err := enum.Enumerate(context.Background(), refEntry(dir), publishedReleasePolicy())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(cands) == 0 {
		t.Fatalf("Enumerate returned no candidates")
	}
	var names []string
	for _, c := range cands {
		names = append(names, c.ID)
		if c.Commit == "" {
			t.Fatalf("candidate %q has no resolved commit", c.ID)
		}
		if c.Source != "local-example-service" {
			t.Fatalf("candidate %q source = %q, want catalog entry id", c.ID, c.Source)
		}
		if c.Mutable {
			t.Fatalf("candidate %q of kind %q must not be mutable", c.ID, c.Kind)
		}
		if c.Kind != RefTag && c.Kind != RefRelease {
			t.Fatalf("policy [tag release] admitted kind %q", c.Kind)
		}
	}
	if _, ok := candByID(cands, "tag:v1.4.0"); !ok {
		t.Fatalf("missing tag:v1.4.0 in %v", names)
	}
	if _, ok := candByID(cands, "release:release/1.5"); !ok {
		t.Fatalf("missing release:release/1.5 in %v", names)
	}
	for _, id := range []string{"branch:devel", "branch:main"} {
		if _, ok := candByID(cands, id); ok {
			t.Fatalf("mutable %s must not be admitted under published-release", id)
		}
	}
	tag, _ := candByID(cands, "tag:v1.4.0")
	if tag.Release != "1.4.0" {
		t.Fatalf("tag:v1.4.0 release = %q, want parsed version 1.4.0", tag.Release)
	}
	rel, _ := candByID(cands, "release:release/1.5")
	if rel.PolicyScore <= tag.PolicyScore {
		t.Fatalf("release score %d must outrank tag score %d", rel.PolicyScore, tag.PolicyScore)
	}
}

func TestRefEnumDeterministicAndBounded(t *testing.T) {
	dir := setupRefGitRepo(t)
	entry := refEntry(dir)
	policy := ReleasePolicy{AllowedRefKinds: []string{"commit", "tag", "release", "branch"}}

	full, err := (RefEnumerator{MaxCandidates: 64}).Enumerate(context.Background(), entry, policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	again, err := (RefEnumerator{MaxCandidates: 64}).Enumerate(context.Background(), entry, policy)
	if err != nil {
		t.Fatalf("Enumerate second call: %v", err)
	}
	if len(full) != len(again) {
		t.Fatalf("unstable enumeration size %d vs %d", len(full), len(again))
	}
	for i := range full {
		if full[i].ID != again[i].ID || full[i].Commit != again[i].Commit {
			t.Fatalf("unstable enumeration at %d: %+v vs %+v", i, full[i], again[i])
		}
	}
	var sawBranch bool
	for _, c := range full {
		if c.Kind == RefBranch {
			sawBranch = true
			if !c.Mutable {
				t.Fatalf("branch candidate %q must be flagged mutable", c.ID)
			}
		}
	}
	if !sawBranch {
		t.Fatalf("policy admitting branch must enumerate branch candidates")
	}

	capped, err := (RefEnumerator{MaxCandidates: 2}).Enumerate(context.Background(), entry, policy)
	if err != nil {
		t.Fatalf("Enumerate cap: %v", err)
	}
	if len(capped) != 2 {
		t.Fatalf("cap produced %d candidates, want 2", len(capped))
	}
	for i := range capped {
		if capped[i].ID != full[i].ID {
			t.Fatalf("cap must keep deterministic prefix: %q vs %q", capped[i].ID, full[i].ID)
		}
	}
}

func TestRefEnumNoLocalRepo(t *testing.T) {
	enum := RefEnumerator{MaxCandidates: 4}
	remote := CatalogEntry{ID: "remote-example", Kind: "git", Locator: "https://example.org/repos/example.git"}
	if _, err := enum.Enumerate(context.Background(), remote, publishedReleasePolicy()); err == nil {
		t.Fatalf("remote locator without local root must error")
	}
	missing := CatalogEntry{ID: "gone", Kind: "local", Root: filepath.Join(t.TempDir(), "absent")}
	if _, err := enum.Enumerate(context.Background(), missing, publishedReleasePolicy()); err == nil {
		t.Fatalf("non-repository root must error")
	}
}

// scriptRefChat returns a stubIntakeChat (shared fake ChatClient) that
// answers each call with the next reply body.
func scriptRefChat(replies ...string) *stubIntakeChat {
	return &stubIntakeChat{replies: replies}
}

func refSelectJSON(id, rule, reason string) string {
	b, _ := json.Marshal(map[string]string{
		"schema_version": RefSelectionSchemaVersion,
		"selected_ref":   id,
		"rule":           rule,
		"reason":         reason,
	})
	return string(b)
}

func selectionRequest(dir, requested string, cands []RefCandidate, policy ReleasePolicy) RefSelectionRequest {
	return RefSelectionRequest{
		Entry:            refEntry(dir),
		Policy:           policy,
		RequestedRelease: requested,
		Candidates:       cands,
		RepoPath:         dir,
	}
}

func TestRefSelectionExactTag(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	want, _ := candByID(cands, "tag:v1.4.0")

	chat := scriptRefChat(refSelectJSON("tag:v1.4.0", "exact", "requested tag exists"))
	res, transcript, err := SelectRef(context.Background(), chat, selectionRequest(dir, "1.4.0", cands, policy))
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v1.4.0" || res.SelectedID != "tag:v1.4.0" {
		t.Fatalf("selected %q (%q), want v1.4.0", res.SelectedRef, res.SelectedID)
	}
	if res.ResolvedCommit != want.Commit {
		t.Fatalf("resolved commit %q, want enumerated %q", res.ResolvedCommit, want.Commit)
	}
	if res.ResolutionRule != RefRuleExact {
		t.Fatalf("rule = %q, want %q", res.ResolutionRule, RefRuleExact)
	}
	if res.SelectionProvenance != RefProvenanceAgent {
		t.Fatalf("provenance = %q, want %q", res.SelectionProvenance, RefProvenanceAgent)
	}
	if res.RequestedRelease != "1.4.0" || len(res.CandidateRefs) != len(cands) {
		t.Fatalf("provenance fields missing: %+v", res)
	}
	if res.Feedback != 0 || res.FallbackReason != "" {
		t.Fatalf("clean selection must not record feedback/fallback: %+v", res)
	}
	if chat.calls != 1 {
		t.Fatalf("chat calls = %d, want 1", chat.calls)
	}
	if len(transcript) != 2 {
		t.Fatalf("transcript len = %d, want 2", len(transcript))
	}
	data := transcript[0].Content
	if !strings.Contains(data, "tag:v1.4.0") || !strings.Contains(data, "published") && !strings.Contains(data, "allowed") {
		t.Fatalf("data message must carry candidate ids and policy: %s", data)
	}
}

func TestRefSelectionOutOfListGetsFeedback(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	chat := scriptRefChat(
		refSelectJSON("tag:v9.9.9", "exact", "invented ref"),
		refSelectJSON("tag:v1.4.0", "exact", "exact requested tag"),
	)
	res, _, err := SelectRef(context.Background(), chat, selectionRequest(dir, "1.4.0", cands, policy))
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if chat.calls != 2 {
		t.Fatalf("chat calls = %d, want 2 (one feedback pass)", chat.calls)
	}
	if res.Feedback != 1 {
		t.Fatalf("feedback passes = %d, want 1", res.Feedback)
	}
	if res.SelectedRef != "v1.4.0" || res.ResolutionRule != RefRuleExact {
		t.Fatalf("selected %q rule %q, want v1.4.0 exact", res.SelectedRef, res.ResolutionRule)
	}
	if res.SelectionProvenance != RefProvenanceAgent {
		t.Fatalf("provenance = %q, want agent", res.SelectionProvenance)
	}
	// The feedback turn must carry a structured rejection naming the bad id.
	if !strings.Contains(chat.sentMsgs[len(chat.sentMsgs)-1].Content, "tag:v9.9.9") {
		t.Fatalf("feedback message must name the rejected id: %q", chat.sentMsgs[len(chat.sentMsgs)-1].Content)
	}
}

func TestRefSelectionMutableBranchRejected(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	// A mutable branch is never enumerated under published-release; inject one
	// to prove validation — not enumeration — is the guard.
	cands = append(cands, RefCandidate{
		ID: "branch:devel", Name: "devel", Kind: RefBranch,
		Commit: cands[0].Commit, Source: "local-example-service", Mutable: true,
	})

	chat := scriptRefChat(
		refSelectJSON("branch:devel", "unversioned", "pick the branch"),
		refSelectJSON("tag:v1.4.0", "exact", "ok"),
	)
	res, _, err := SelectRef(context.Background(), chat, selectionRequest(dir, "1.4.0", cands, policy))
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v1.4.0" {
		t.Fatalf("selected %q, want v1.4.0", res.SelectedRef)
	}
	if !strings.Contains(chat.sentMsgs[len(chat.sentMsgs)-1].Content, "branch:devel") {
		t.Fatalf("feedback must name rejected branch: %q", chat.sentMsgs[len(chat.sentMsgs)-1].Content)
	}
}

func TestRefSelectionNewerForbidden(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	// Requested 1.4.1 has no exact ref: the agent first picks the newer
	// v1.5.0 (rejected by the release policy), then the best available
	// class — the same-series earlier tag v1.4.0.
	chat := scriptRefChat(
		refSelectJSON("tag:v1.5.0", "newer", "take latest"),
		refSelectJSON("tag:v1.4.0", "same-series", "earlier tag in series"),
	)
	req := selectionRequest(dir, "1.4.1", cands, policy)
	res, _, err := SelectRef(context.Background(), chat, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v1.4.0" || res.ResolutionRule != RefRuleSameSeries {
		t.Fatalf("selected %q rule %q, want v1.4.0 same-series — a newer ref must be rejected", res.SelectedRef, res.ResolutionRule)
	}
}

// TestRefSelectionWorseClassRejected: the agent may not pick a lower rule
// class while a better class is offered — the structured feedback names the
// rejected class and the best available candidate, then the repair wins.
func TestRefSelectionWorseClassRejected(t *testing.T) {
	dir := setupRefGitRepo(t)
	// Repo carries 6.2.0-3056 (same-release-build for requested 6.2.0-1530)
	// and an older series tag; the first answer picks the worse class.
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("tag", "v6.2.0-3056")
	run("tag", "v5.8.0-3036")
	policy := publishedReleasePolicy()
	stats := &RefEnumerationStats{}
	cands, err := (RefEnumerator{MaxCandidates: 16, RequestedRelease: "6.2.0-1530", Stats: stats}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	chat := scriptRefChat(
		refSelectJSON("tag:v5.8.0-3036", "nearest-earlier", "older series"),
		refSelectJSON("tag:v6.2.0-3056", "same-release-build", "same release line"),
	)
	req := selectionRequest(dir, "6.2.0-1530", cands, policy)
	res, _, err := SelectRef(context.Background(), chat, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v6.2.0-3056" || res.ResolutionRule != RefRuleSameReleaseBuild {
		t.Fatalf("selected %q rule %q, want v6.2.0-3056 same-release-build", res.SelectedRef, res.ResolutionRule)
	}
	if res.Feedback != 1 {
		t.Fatalf("feedback passes = %d, want 1", res.Feedback)
	}
	fb := chat.sentMsgs[len(chat.sentMsgs)-1].Content
	if !strings.Contains(fb, "nearest-earlier") || !strings.Contains(fb, "same-release-build") || !strings.Contains(fb, "tag:v6.2.0-3056") {
		t.Fatalf("feedback must name rejected and best classes: %q", fb)
	}
}

// TestRefSelectionWorseClassFallback: a stubborn agent that keeps naming
// worse-class candidates exhausts feedback and the deterministic fallback
// still lands on the best available class.
func TestRefSelectionWorseClassFallback(t *testing.T) {
	dir := setupRefGitRepo(t)
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("tag", "v6.2.0-3056")
	run("tag", "v5.8.0-3036")
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16, RequestedRelease: "6.2.0-1530"}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	chat := scriptRefChat(
		refSelectJSON("tag:v5.8.0-3036", "nearest-earlier", "stubborn"),
		refSelectJSON("tag:v5.8.0-3036", "nearest-earlier", "stubborn"),
		refSelectJSON("tag:v5.8.0-3036", "nearest-earlier", "stubborn"),
	)
	req := selectionRequest(dir, "6.2.0-1530", cands, policy)
	res, _, err := SelectRef(context.Background(), chat, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectionProvenance != RefProvenanceFallback {
		t.Fatalf("provenance = %q, want fallback", res.SelectionProvenance)
	}
	if res.SelectedRef != "v6.2.0-3056" || res.ResolutionRule != RefRuleSameReleaseBuild {
		t.Fatalf("fallback picked %q rule %q, want best class same-release-build", res.SelectedRef, res.ResolutionRule)
	}
	if !strings.Contains(res.FallbackReason, "worse than the best available class") {
		t.Fatalf("fallback reason must record the class rejection: %q", res.FallbackReason)
	}
}

// TestRefSelectionNoRequestedClassFree: without a requested release the
// class contract does not apply — any policy-admissible pick stands.
func TestRefSelectionNoRequestedClassFree(t *testing.T) {
	policy := publishedReleasePolicy()
	tag := RefCandidate{ID: "tag:v0.9.9", Name: "v0.9.9", Kind: RefTag, Release: "0.9.9", Commit: strings.Repeat("b2", 20), Source: "svc", PolicyScore: 2}
	other := RefCandidate{ID: "tag:v1.9.0", Name: "v1.9.0", Kind: RefTag, Release: "1.9.0", Commit: strings.Repeat("a1", 20), Source: "svc", PolicyScore: 2}
	chat := scriptRefChat(refSelectJSON("tag:v0.9.9", "unversioned", "any"))
	req := RefSelectionRequest{Policy: policy, Candidates: []RefCandidate{tag, other}}
	res, _, err := SelectRef(context.Background(), chat, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v0.9.9" || res.ResolutionRule != RefRuleUnversioned {
		t.Fatalf("no requested release must not constrain classes: %q %q", res.SelectedRef, res.ResolutionRule)
	}
}

func TestRefSelectionExhaustsFeedbackThenFallback(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	// Every LLM answer names a ref outside the bounded list: after the first
	// call plus MaxFeedbackPasses repairs the deterministic fallback runs.
	chat := scriptRefChat(
		refSelectJSON("v9.9.9", "exact", "nope"),
		refSelectJSON("HEAD", "exact", "still nope"),
		refSelectJSON("refs/tags/none", "exact", "nope again"),
	)
	req := selectionRequest(dir, "1.4.0", cands, policy)
	req.MaxFeedbackPasses = 2
	res, _, err := SelectRef(context.Background(), chat, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if chat.calls != 3 {
		t.Fatalf("chat calls = %d, want 1+2 feedback", chat.calls)
	}
	if res.SelectionProvenance != RefProvenanceFallback {
		t.Fatalf("provenance = %q, want fallback", res.SelectionProvenance)
	}
	if res.SelectedRef != "v1.4.0" || res.ResolutionRule != RefRuleExact {
		t.Fatalf("fallback picked %q rule %q, want exact v1.4.0", res.SelectedRef, res.ResolutionRule)
	}
	if res.FallbackReason == "" {
		t.Fatalf("fallback reason must record why the agent path failed")
	}
	if res.Feedback != 2 {
		t.Fatalf("feedback passes = %d, want 2", res.Feedback)
	}
}

func TestRefSelectionFallbackImpossibleIsError(t *testing.T) {
	dir := setupRefGitRepo(t)
	// Policy admits only release refs; the repo has plain tags and the single
	// release ref is newer than requested with allow_newer unset.
	policy := ReleasePolicy{AllowedRefKinds: []string{"release"}, RequireResolvedCommit: true}
	cands := []RefCandidate{{
		ID: "release:release/9.9", Name: "release/9.9", Kind: RefRelease,
		Commit: strings.Repeat("ab", 20), Release: "9.9.0", Source: "local-example-service",
	}}
	chat := scriptRefChat(refSelectJSON("tag:v1.4.0", "exact", "not a candidate"))
	_, _, err := SelectRef(context.Background(), chat, selectionRequest(dir, "1.4.0", cands, policy))
	if err == nil {
		t.Fatalf("selection with no admissible fallback must error")
	}
}

func TestRefSelectionPinnedCommitFallback(t *testing.T) {
	dir := setupRefGitRepo(t)
	out, _ := exec.Command("git", "-C", dir, "rev-parse", "v1.4.0^{commit}").Output()
	sha := strings.TrimSpace(string(out))
	policy := ReleasePolicy{AllowedRefKinds: []string{"commit", "tag"}, RequireResolvedCommit: true}

	// No LLM client at all: request pins an exact commit, a commit candidate
	// is synthesized, and fallback tier order prefers it over tags.
	res, _, err := SelectRef(context.Background(), nil, selectionRequest(dir, sha, nil, policy))
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != sha || res.ResolvedCommit != sha {
		t.Fatalf("pinned commit resolution = %q/%q, want %q", res.SelectedRef, res.ResolvedCommit, sha)
	}
	if res.ResolutionRule != RefRuleExact || res.SelectionProvenance != RefProvenanceFallback {
		t.Fatalf("rule=%q provenance=%q, want exact/fallback", res.ResolutionRule, res.SelectionProvenance)
	}
}

func TestRefSelectionResolutionFields(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	chat := scriptRefChat(refSelectJSON("tag:v1.4.0", "exact", "ok"))
	res, _, err := SelectRef(context.Background(), chat, selectionRequest(dir, "1.4.0", cands, policy))
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	raw, _ := json.Marshal(res)
	for _, key := range []string{
		"requested_release", "candidate_refs", "selected_ref",
		"resolved_commit", "resolution_rule", "selection_provenance",
	} {
		if !strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatalf("resolution JSON missing %q: %s", key, raw)
		}
	}
	if res.CandidatesHash == "" {
		t.Fatalf("candidate list hash must be recorded")
	}
}

func TestReleasePolicySameSeriesFallback(t *testing.T) {
	policy := publishedReleasePolicy()
	cands := []RefCandidate{
		{ID: "tag:v1.3.9", Name: "v1.3.9", Kind: RefTag, Commit: strings.Repeat("a1", 20), Release: "1.3.9", Source: "s", PolicyScore: 2},
		{ID: "tag:v0.9.9", Name: "v0.9.9", Kind: RefTag, Commit: strings.Repeat("b2", 20), Release: "0.9.9", Source: "s", PolicyScore: 2},
	}
	req := RefSelectionRequest{Policy: policy, RequestedRelease: "1.4.2", Candidates: cands}
	res, _, err := SelectRef(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v1.3.9" || res.ResolutionRule != RefRuleSameSeries {
		t.Fatalf("fallback picked %q rule %q, want v1.3.9 same-series", res.SelectedRef, res.ResolutionRule)
	}
}

func TestReleasePolicyNearestEarlierFallback(t *testing.T) {
	policy := publishedReleasePolicy()
	cands := []RefCandidate{
		{ID: "tag:v1.2.0", Name: "v1.2.0", Kind: RefTag, Commit: strings.Repeat("a1", 20), Release: "1.2.0", Source: "s", PolicyScore: 2},
		{ID: "tag:v1.9.0", Name: "v1.9.0", Kind: RefTag, Commit: strings.Repeat("b2", 20), Release: "1.9.0", Source: "s", PolicyScore: 2},
	}
	req := RefSelectionRequest{Policy: policy, RequestedRelease: "2.1", Candidates: cands}
	res, _, err := SelectRef(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if res.SelectedRef != "v1.9.0" || res.ResolutionRule != RefRuleNearestEarlier {
		t.Fatalf("fallback picked %q rule %q, want nearest earlier v1.9.0", res.SelectedRef, res.ResolutionRule)
	}
}

func TestReleasePolicyAllowNewerGate(t *testing.T) {
	policy := publishedReleasePolicy()
	cands := []RefCandidate{
		{ID: "tag:v1.5.0", Name: "v1.5.0", Kind: RefTag, Commit: strings.Repeat("a1", 20), Release: "1.5.0", Source: "s", PolicyScore: 2},
	}
	req := RefSelectionRequest{Policy: policy, RequestedRelease: "1.4.0", Candidates: cands}
	if _, _, err := SelectRef(context.Background(), nil, req); err == nil {
		t.Fatalf("newer-than-requested candidate must be inadmissible without allow_newer")
	}
	req.AllowNewer = true
	res, _, err := SelectRef(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("allow_newer must admit newer ref: %v", err)
	}
	if res.SelectedRef != "v1.5.0" || res.ResolutionRule != RefRuleNewer {
		t.Fatalf("picked %q rule %q, want v1.5.0 newer", res.SelectedRef, res.ResolutionRule)
	}
}

func TestReleasePolicyBranchRequiresOptIn(t *testing.T) {
	branch := RefCandidate{ID: "branch:devel", Name: "devel", Kind: RefBranch, Commit: strings.Repeat("c3", 20), Source: "s", Mutable: true, PolicyScore: 1}
	tag := RefCandidate{ID: "tag:v1.0.0", Name: "v1.0.0", Kind: RefTag, Commit: strings.Repeat("d4", 20), Release: "1.0.0", Source: "s", PolicyScore: 2}

	// Branch not in allowed kinds: fallback must never take the mutable ref.
	if _, err := FallbackRef([]RefCandidate{branch}, publishedReleasePolicy()); err == nil {
		t.Fatalf("mutable branch must not fall back under published-release")
	}
	if _, err := ValidateRefSelection("branch:devel", []RefCandidate{branch, tag}, publishedReleasePolicy()); err == nil {
		t.Fatalf("mutable branch selection must be rejected")
	}

	// Explicit opt-in: branch is a valid last-tier snapshot.
	policy := ReleasePolicy{AllowedRefKinds: []string{"branch"}, RequireResolvedCommit: true}
	got, err := FallbackRef([]RefCandidate{branch}, policy)
	if err != nil {
		t.Fatalf("policy-allowed branch fallback: %v", err)
	}
	if got.ID != "branch:devel" {
		t.Fatalf("fallback picked %q, want branch:devel", got.ID)
	}
	if _, err := ValidateRefSelection("branch:devel", []RefCandidate{branch}, policy); err != nil {
		t.Fatalf("policy-allowed branch selection rejected: %v", err)
	}
}

func TestReleasePolicyFallbackTierOrder(t *testing.T) {
	policy := ReleasePolicy{AllowedRefKinds: []string{"commit", "release", "tag", "branch"}, RequireResolvedCommit: true}
	commit := RefCandidate{ID: "commit:" + strings.Repeat("e5", 20), Name: strings.Repeat("e5", 20), Kind: RefCommit, Commit: strings.Repeat("e5", 20), Source: "s", PolicyScore: 4}
	release := RefCandidate{ID: "release:r1", Name: "release/1.0", Kind: RefRelease, Commit: strings.Repeat("a1", 20), Release: "1.0.0", Source: "s", PolicyScore: 3}
	tag := RefCandidate{ID: "tag:v0.9", Name: "v0.9", Kind: RefTag, Commit: strings.Repeat("b2", 20), Release: "0.9.0", Source: "s", PolicyScore: 2}
	branch := RefCandidate{ID: "branch:devel", Name: "devel", Kind: RefBranch, Commit: strings.Repeat("c3", 20), Source: "s", Mutable: true, PolicyScore: 1}

	for i, tc := range []struct {
		cands []RefCandidate
		want  string
	}{
		{[]RefCandidate{branch, tag, release, commit}, commit.ID},
		{[]RefCandidate{branch, tag, release}, release.ID},
		{[]RefCandidate{branch, tag}, tag.ID},
		{[]RefCandidate{branch}, branch.ID},
	} {
		got, err := FallbackRef(tc.cands, policy)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got.ID != tc.want {
			t.Fatalf("case %d: fallback picked %q, want %q", i, got.ID, tc.want)
		}
	}
}

func TestReleasePolicyRequireResolvedCommit(t *testing.T) {
	policy := ReleasePolicy{AllowedRefKinds: []string{"tag"}, RequireResolvedCommit: true}
	noCommit := RefCandidate{ID: "tag:v1.0.0", Name: "v1.0.0", Kind: RefTag, Release: "1.0.0", Source: "s", PolicyScore: 2}
	if _, err := ValidateRefSelection("tag:v1.0.0", []RefCandidate{noCommit}, policy); err == nil {
		t.Fatalf("unresolved candidate must be rejected under require_resolved_commit")
	}
	if _, err := FallbackRef([]RefCandidate{noCommit}, policy); err == nil {
		t.Fatalf("unresolved candidate must not fall back")
	}
}

func TestReleasePolicyValidateSelectionBasics(t *testing.T) {
	policy := publishedReleasePolicy()
	tag := RefCandidate{ID: "tag:v1.4.0", Name: "v1.4.0", Kind: RefTag, Commit: strings.Repeat("a1", 20), Source: "s"}
	if _, err := ValidateRefSelection("", []RefCandidate{tag}, policy); err == nil {
		t.Fatalf("empty selection must error")
	}
	if _, err := ValidateRefSelection("tag:v9.9.9", []RefCandidate{tag}, policy); err == nil {
		t.Fatalf("ref outside bounded list must error")
	}
	if _, err := ValidateRefSelection("v1.4.0", []RefCandidate{tag}, policy); err == nil {
		t.Fatalf("bare ref name instead of candidate id must error")
	}
	got, err := ValidateRefSelection("tag:v1.4.0", []RefCandidate{tag}, policy)
	if err != nil || got.Name != "v1.4.0" {
		t.Fatalf("valid selection: %v %+v", err, got)
	}
}

func TestRefSelectionAuditEvent(t *testing.T) {
	res := RefResolution{
		RequestedRelease:    "1.4.0",
		SelectedID:          "tag:v1.4.0",
		SelectedRef:         "v1.4.0",
		ResolvedCommit:      strings.Repeat("a1", 20),
		ResolutionRule:      RefRuleExact,
		SelectionProvenance: RefProvenanceAgent,
		CandidatesHash:      "deadbeef",
	}
	ev := RefAuditEvent(res, "run-1", time.Unix(0, 0).UTC())
	if ev.Type != AuditEventRefResolution {
		t.Fatalf("event type = %q, want %q", ev.Type, AuditEventRefResolution)
	}
	if ev.Ref == nil || ev.Ref.CandidatesHash != "deadbeef" || ev.Ref.SelectedRef != "v1.4.0" {
		t.Fatalf("ref audit fields missing: %+v", ev.Ref)
	}
	if ev.Ref.ResolvedCommit != res.ResolvedCommit || ev.Ref.ResolutionRule != RefRuleExact {
		t.Fatalf("ref audit fields wrong: %+v", ev.Ref)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), "credential") || strings.Contains(string(raw), "secret") {
		t.Fatalf("audit event must not carry credential material: %s", raw)
	}
}

// TestRefSelectionTransientProviderRetry: an HTTP 500 gateway error is a
// transient provider failure — the ref-selection chat retries within
// chatMaxAttempts and the scripted second reply wins.
func TestRefSelectionTransientProviderRetry(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	chat := &erringChat{
		errs: []error{fmt.Errorf("llm status 500: <html>bad gateway</html>")},
		scriptedChat: scriptedChat{
			responses: []llm.ChatMessage{{Role: "assistant", Content: refSelectJSON("tag:v1.4.0", "exact", "ok")}},
		},
	}
	req := selectionRequest(dir, "1.4.0", cands, policy)
	req.Sleep = noSleep
	res, _, err := SelectRef(context.Background(), chat, req)
	if err != nil {
		t.Fatalf("SelectRef: %v", err)
	}
	if chat.calls != 2 {
		t.Fatalf("chat attempts = %d, want 2 (one transient retry)", chat.calls)
	}
	if res.SelectedRef != "v1.4.0" || res.SelectionProvenance != RefProvenanceAgent {
		t.Fatalf("selected %q via %q, want agent-chosen v1.4.0", res.SelectedRef, res.SelectionProvenance)
	}
}

// TestRefSelectionTransientExhausted: persistent 5xx must still fail after
// at most chatMaxAttempts calls — a transient retry is bounded, never a
// hang, and never silently falls back.
func TestRefSelectionTransientExhausted(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	chat := &erringChat{errs: []error{
		fmt.Errorf("llm status 500: unavailable"),
		fmt.Errorf("llm status 502: unavailable"),
		fmt.Errorf("llm status 503: unavailable"),
		fmt.Errorf("llm status 503: unavailable"),
	}}
	req := selectionRequest(dir, "1.4.0", cands, policy)
	req.Sleep = noSleep
	_, _, err = SelectRef(context.Background(), chat, req)
	if err == nil {
		t.Fatalf("persistent 5xx must error")
	}
	if chat.calls != chatMaxAttempts {
		t.Fatalf("chat attempts = %d, want bounded %d", chat.calls, chatMaxAttempts)
	}
	if !strings.Contains(err.Error(), "llm status 503") {
		t.Fatalf("error = %v, want last provider failure", err)
	}
}

// TestRefSelectionNonTransientError: a 400-class provider error is
// terminal — exactly one call, no retry.
func TestRefSelectionNonTransientError(t *testing.T) {
	dir := setupRefGitRepo(t)
	policy := publishedReleasePolicy()
	cands, err := (RefEnumerator{MaxCandidates: 16}).Enumerate(context.Background(), refEntry(dir), policy)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	chat := &erringChat{errs: []error{fmt.Errorf("llm status 400: bad request")}}
	req := selectionRequest(dir, "1.4.0", cands, policy)
	req.Sleep = noSleep
	_, _, err = SelectRef(context.Background(), chat, req)
	if err == nil {
		t.Fatalf("non-transient provider error must fail")
	}
	if chat.calls != 1 {
		t.Fatalf("chat attempts = %d, want exactly 1 (no retry)", chat.calls)
	}
}
