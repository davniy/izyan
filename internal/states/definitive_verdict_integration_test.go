package states_test

// The definitive-verdict integration regression drives the *real* request
// pipeline end to end over the synthetic worked-case product:
//
//	FileSource exact intake of the recorded 22-entry Kubernetes advisory
//	  -> declared, digest-pinned corpus discovery
//	  -> captured publisher attribution
//	  -> isolated record assessments on the same product snapshot
//	  -> requested-finding composition
//	  -> persistence round trip
//	  -> report.json / Markdown / OpenVEX / CycloneDX
//
// Every assessment in this test is the production deterministic chain:
// CHECK_AFFECTED (real `go list` module graph) -> RESOLVE_ROOT_CAUSE (the
// captured upstream fix patch) -> BUILD_EXPLOIT_MODEL -> COLLECT_EVIDENCE (the
// rooted transport and Rapid Reset trigger proof over real source) ->
// EVALUATE_CONDITIONS -> GAP_ANALYSIS -> NEGATIVE_CHECK -> REVIEW ->
// REPAIR_ANALYSIS -> EVALUATE_VERDICT.
//
// What is synthetic: the product tree under testdata/definitiveverdict, which
// reproduces the *shape* of the kubelet podresources listener and of the gRPC-Go
// v1.55.0 stream lifecycle. It is not a Kubernetes measurement, and no result
// here may be reported as one. The advisory document, the GO record, the
// publisher capture and the fix patch are the real captured bytes; their
// provenance is pinned in testdata/definitive-verdict/source-manifest.json and
// re-verified before any analysis runs.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/advfeed"
	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/exploit"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/persistence/filesystem"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/review"
	"github.com/fedorovmv/izyan/internal/rootcause"
	"github.com/fedorovmv/izyan/internal/states"
	"github.com/fedorovmv/izyan/internal/toolaudit"
	"github.com/fedorovmv/izyan/internal/vulnerability"
	"github.com/fedorovmv/izyan/internal/workflow"
)

const (
	dvCVE          = "CVE-2023-44487"
	dvPrimaryGHSA  = "GHSA-qppj-fm5r-hxr3"
	dvGRPC         = "GO-2023-2153"
	dvPublisher    = "GHSA-m425-mq94-257g"
	dvFixPR        = "https://github.com/grpc/grpc-go/pull/6703"
	dvFixCommit    = "https://github.com/grpc/grpc-go/commit/f2180b4d5403d2210b30b93098eb7da31c05c721"
	dvMechanism    = domain.MechanismHTTP2RapidReset
	dvGRPCVersion  = "v1.55.0"
	dvXNetVersion  = "v0.17.0"
	dvPrimaryPath  = "../../eval/agent7/advisories/k8s-44487.json"
	dvGRPCPath     = "../../eval/advisories/reviewed/GO-2023-2153.json"
	dvFixtureDir   = "../../testdata/definitiveverdict"
	dvEvidenceDir  = "testdata/definitive-verdict"
	dvCorpusRef    = "definitive-verdict-corpus"
	dvProductPath  = "product"
	dvGRPCModPath  = "grpc"
	dvFixedEnforce = "newHandlerQuota"
)

// dvSourceManifest is the recorded provenance of the captured fixtures.
type dvSourceManifest struct {
	Schema  string `json:"schema"`
	Sources []struct {
		Role        string `json:"role"`
		URI         string `json:"uri"`
		Path        string `json:"path"`
		SHA256      string `json:"sha256"`
		Retrieved   string `json:"retrieved_at"`
		DerivedFrom string `json:"derived_from"`
		Derivation  []struct {
			Field  string `json:"field"`
			Value  string `json:"value"`
			Anchor string `json:"anchor"`
		} `json:"derivation"`
	} `json:"sources"`
}

type dvCorpusManifest struct {
	Schema         string `json:"schema"`
	Reference      string `json:"reference"`
	CapturedAt     string `json:"captured_at"`
	ExpectedDigest string `json:"expected_digest"`
}

// dvWorkedCase holds one prepared run: the copied product tree, the declared
// corpus, the pinned publisher capture and the captured fix patch.
type dvWorkedCase struct {
	t           *testing.T
	root        string
	product     string
	publisher   string
	patch       string
	corpus      *advfeed.Corpus
	declaration *domain.CorpusDeclaration
	snapshot    domain.ProductSnapshot
}

func dvDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// dvPrepare verifies every captured fixture against the recorded provenance,
// copies the synthetic product into a temporary root (a `testdata` path is
// never production source), and acquires the declared corpus.
func dvPrepare(t *testing.T) dvWorkedCase {
	t.Helper()
	return dvPrepareMutated(t, nil)
}

// dvPrepareMutated copies the synthetic product and applies mut before the
// snapshot is taken: every control runs through the same pipeline with exactly
// one input changed.
func dvPrepareMutated(t *testing.T, mutate func(t *testing.T, product, module string)) dvWorkedCase {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("definitive-verdict integration requires a Go toolchain: %v", err)
	}
	manifest := dvReadSourceManifest(t)
	rawPublisher := dvSourceBytes(t, manifest, "publisher-advisory-raw")
	normalized := dvSourceBytes(t, manifest, "publisher-advisory-normalized")
	patch := dvSourceBytes(t, manifest, "fix-patch")

	// Every normalized field must be an extraction from the captured page, not
	// an invented quotation.
	for _, source := range manifest.Sources {
		if source.Role != "publisher-advisory-normalized" {
			continue
		}
		if source.DerivedFrom != "grpc-publisher-advisory.html" {
			t.Fatalf("normalized capture derived_from = %q", source.DerivedFrom)
		}
		for _, derivation := range source.Derivation {
			if !strings.Contains(string(rawPublisher), derivation.Anchor) {
				t.Fatalf("captured publisher page does not contain the anchor %q for %s",
					derivation.Anchor, derivation.Field)
			}
			if !strings.Contains(string(normalized), derivation.Value) {
				t.Fatalf("normalized capture does not carry %s=%q", derivation.Field, derivation.Value)
			}
		}
	}

	root := t.TempDir()
	for _, name := range []string{dvProductPath, dvGRPCModPath} {
		if err := os.CopyFS(filepath.Join(root, name), os.DirFS(filepath.Join(dvFixtureDir, name))); err != nil {
			t.Fatalf("copy fixture %s: %v", name, err)
		}
	}
	product := filepath.Join(root, dvProductPath)
	if mutate != nil {
		mutate(t, product, filepath.Join(root, dvGRPCModPath))
	}

	dvInitRepo(t, product)
	snap, err := repository.Service{}.Snapshot(context.Background(), product, repository.SnapshotOptions{})
	if err != nil {
		t.Fatalf("snapshot the synthetic product: %v", err)
	}
	corpusDir, declaration := dvDeclaredCorpus(t, root)
	corpus, err := advfeed.AcquireCorpus(context.Background(), advfeed.CorpusOptions{
		Feed:        advfeed.Options{LocalPath: corpusDir, Now: dvClock},
		Declaration: declaration,
	})
	if err != nil {
		t.Fatalf("acquire declared corpus: %v", err)
	}

	return dvWorkedCase{
		t:           t,
		root:        root,
		product:     product,
		publisher:   string(normalized),
		patch:       string(patch),
		corpus:      corpus,
		declaration: declaration,
		snapshot:    snap,
	}
}

// dvInitRepo makes the copied fixture an immutable git tree, so the product
// snapshot is resolved by the real snapshotter rather than supplied by hand.
func dvInitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=dv", "GIT_AUTHOR_EMAIL=dv@example.invalid",
			"GIT_COMMITTER_NAME=dv", "GIT_COMMITTER_EMAIL=dv@example.invalid",
			"GIT_AUTHOR_DATE=2026-10-26T15:30:00Z", "GIT_COMMITTER_DATE=2026-10-26T15:30:00Z",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "fixture product")
}

func dvClock() time.Time { return time.Date(2026, 10, 26, 15, 30, 0, 0, time.UTC) }

func dvReadSourceManifest(t *testing.T) dvSourceManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dvEvidenceDir, "source-manifest.json"))
	if err != nil {
		t.Fatalf("read source manifest: %v", err)
	}
	var manifest dvSourceManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode source manifest: %v", err)
	}
	if manifest.Schema != "captured-source-manifest/1" {
		t.Fatalf("source manifest schema = %q", manifest.Schema)
	}
	return manifest
}

// dvSourceBytes returns one captured fixture's bytes after checking them
// against the manifest digest.
func dvSourceBytes(t *testing.T, manifest dvSourceManifest, role string) []byte {
	t.Helper()
	for _, source := range manifest.Sources {
		if source.Role != role {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dvEvidenceDir, source.Path))
		if err != nil {
			t.Fatalf("read %s: %v", source.Path, err)
		}
		if got := dvDigest(raw); got != source.SHA256 {
			t.Fatalf("%s digest = %s, want the recorded %s", source.Path, got, source.SHA256)
		}
		return raw
	}
	t.Fatalf("source manifest has no %q entry", role)
	return nil
}

// dvDeclaredCorpus writes the real GO record into a temporary corpus root and
// returns the operator declaration read from the recorded manifest.
func dvDeclaredCorpus(t *testing.T, root string) (string, *domain.CorpusDeclaration) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dvEvidenceDir, "corpus-manifest.json"))
	if err != nil {
		t.Fatalf("read corpus manifest: %v", err)
	}
	var declared dvCorpusManifest
	if err := json.Unmarshal(raw, &declared); err != nil {
		t.Fatalf("decode corpus manifest: %v", err)
	}
	dir := filepath.Join(root, "corpus")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	grpc, err := os.ReadFile(dvGRPCPath)
	if err != nil {
		t.Fatalf("read the real gRPC record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, dvGRPC+".json"), grpc, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, declared.CapturedAt); err != nil {
		t.Fatalf("corpus captured_at: %v", err)
	}
	return dir, &domain.CorpusDeclaration{
		Reference:      declared.Reference,
		ExpectedDigest: declared.ExpectedDigest,
		CapturedAt:     declared.CapturedAt,
	}
}

// dvPatchProvider supplies the captured upstream fix patch. It is a Provider,
// not a verdict input: the trigger proof binds its exact bytes by digest.
type dvPatchProvider struct{ patch string }

func (p dvPatchProvider) Acquire(_ context.Context, ref fix.Reference) domain.FixArtifact {
	return domain.FixArtifact{
		Locator:    ref.URL,
		Kind:       ref.Kind,
		Provenance: "test provider",
		Outcome:    domain.FixArtifactComplete,
		Digest:     domain.EvidenceContentDigest(p.patch),
		Size:       len(p.patch),
		Bytes:      p.patch,
		Detail:     "served by the test provider",
	}
}

func dvConditionEvaluators() []evaluator.ConditionEvaluator {
	return []evaluator.ConditionEvaluator{
		evaluator.SymbolReachable{},
		evaluator.ServerTransportInput{},
		evaluator.ArgumentOrigin{},
		evaluator.Validation{},
		evaluator.MissingCall{},
		evaluator.Exposure{},
		evaluator.Authentication{},
		evaluator.ConfigFlag{},
		evaluator.Presence{},
		evaluator.VersionFact{},
		evaluator.Platform{},
		evaluator.Custom{},
	}
}

// dvRecordHandlers is the production record chain with a deterministic-only
// reviewer/evaluator set and the captured fix patch.
func dvRecordHandlers(ix *goanalysis.Index, patch string, next domain.WorkflowState) []workflow.StateHandler {
	evaluators := dvConditionEvaluators()
	return []workflow.StateHandler{
		states.CheckAffected{Resolver: affected.GoResolver{Tool: affected.ExecGoTool{}}},
		states.ResolveRootCause{
			Resolver:  &rootcause.Resolver{Fix: fix.Resolver{}, Patch: dvPatchProvider{patch: patch}, Source: ix},
			Verifier:  &rootcause.Verifier{Source: ix},
			LLMClient: nil,
		},
		states.BuildExploitModel{Builder: &exploit.Builder{Source: ix}},
		states.CollectEvidence{Source: ix},
		states.EvaluateConditions{Evaluators: evaluators},
		states.GapAnalysis{Source: ix, Evaluators: evaluators},
		states.NegativeCheck{Verifier: &goanalysis.Verifier{Source: ix}},
		states.Review{Reviewer: review.Multi{review.Structural{}}, Evaluator: evaluator.VerdictEvaluator{}},
		states.RepairAnalysis{},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}, Next: next},
	}
}

// dvRun executes the whole request pipeline and returns the persisted case.
func dvRun(t *testing.T, wc dvWorkedCase, requestedID string, corpus *advfeed.Corpus,
	declaration *domain.CorpusDeclaration, materials map[string]string) (*domain.AnalysisCase, string) {
	t.Helper()
	t.Setenv("IZYAN_SNAPSHOT_SHA", "e196d2491087e93bd29f0e5a538aab60667021e3")
	ctx := context.Background()
	caseDir := filepath.Join(wc.root, "cases", sanitizeDV(requestedID))
	store := filesystem.New(caseDir)
	c := &domain.AnalysisCase{
		ID:          domain.CaseID("dv-" + sanitizeDV(requestedID)),
		RequestedID: requestedID,
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCreated,
			StartedAt: time.Now().UTC(),
			Limits: domain.AnalysisLimits{
				MaxIterations:       64,
				MaxToolCalls:        256,
				MaxSourceReads:      512,
				MaxReviewIterations: 2,
			},
		},
	}
	c.EvidenceGraph.Version = "1"
	if corpus != nil {
		manifest := corpus.Manifest()
		c.CorpusManifest = &manifest
	}
	c.CorpusDeclaration = declaration
	if err := store.Create(ctx, c); err != nil {
		t.Fatalf("create case: %v", err)
	}
	ctx = toolaudit.WithRecorder(ctx, &toolaudit.Recorder{Sink: c.EvidenceGraph.AddToolExecution})

	ix := &goanalysis.Index{Dir: wc.product}
	intake := &states.RecordIntake{}
	attributor := dvAttributor(materials)

	childRunner := func(ctx context.Context, child *domain.AnalysisCase) error {
		defer func() { dvDumpChild(t, child) }()
		engine := workflow.New(store, dvRecordHandlers(ix, wc.patch, domain.StateBuildReport)...)
		engine.FailureState = domain.StateBuildReport
		if err := engine.RunUntil(ctx, child, domain.StateBuildReport); err != nil {
			return err
		}
		if err := finding.Finalize(child); err != nil {
			return err
		}
		if child.RequestedFinding.Outcome == domain.OutcomeFailed {
			child.Workflow.State = domain.StateFailed
		} else {
			child.Workflow.State = domain.StateCompleted
		}
		child.Workflow.UpdatedAt = time.Now().UTC()
		return store.Save(ctx, child)
	}

	handlers := []workflow.StateHandler{
		states.Created{},
		states.SnapshotProduct{Repo: repository.Service{}, Path: wc.product, Source: ix, Snapshot: &wc.snapshot},
		states.ResolveVulnerability{
			Source: vulnerability.FileSource{Path: dvPrimaryPath, NoAliasEnrichment: true},
			ID:     requestedID,
			Exact:  true,
			Next:   domain.StateDiscoverRecords,
			Intake: intake,
		},
		states.DiscoverRecords{Source: corpus, Intake: intake, Attributor: attributor},
	}
	handlers = append(handlers, dvRecordHandlers(ix, wc.patch, domain.StateAssessRelatedRecords)...)
	handlers = append(handlers,
		states.AssessRelatedRecords{Source: corpus, Runner: childRunner, Attributor: attributor},
		states.ComposeRequestedFinding{},
		states.BuildReport{Dir: filepath.Join(caseDir, string(c.ID))},
	)
	engine := workflow.New(store, handlers...)
	engine.FailureState = domain.StateAssessRelatedRecords
	if err := engine.Run(ctx, c); err != nil {
		t.Fatalf("pipeline %s: %v", requestedID, err)
	}
	loaded, err := store.Load(ctx, c.ID)
	if err != nil {
		t.Fatalf("load persisted case: %v", err)
	}
	t.Logf("%s: state=%s reason=%s record=%q gaps=%v",
		requestedID, loaded.Workflow.State, loaded.Workflow.Reason, loaded.Vulnerability.ID,
		dvGapCodes(loaded.AnalysisGaps))
	for _, limitation := range loaded.EvidenceGraph.Limitations {
		if strings.Contains(limitation, "attribution") || strings.Contains(limitation, "corpus") {
			t.Logf("%s: limitation %s", requestedID, limitation)
		}
	}
	if rf := loaded.RequestedFinding; rf != nil {
		t.Logf("%s: requested outcome=%s verdict=%q reason=%s gaps=%v discovery=%v related=%d",
			requestedID, rf.Outcome, rf.Verdict, rf.Reason, dvGapCodes(rf.Gaps),
			discoveryEnumeration(loaded), len(loaded.RelatedRecords))
		for _, ac := range loaded.Attributions {
			t.Logf("%s: attribution %s admission=%s basis=%s",
				requestedID, ac.Candidate.RecordID, ac.Admission, ac.Basis)
		}
	}
	return loaded, caseDir
}

func sanitizeDV(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		}
		return '-'
	}, value)
}

// dvAttributor admits a record's own identity first, then the supplied
// captured publisher materials — the same order the CLI uses.
func dvAttributor(materials map[string]string) states.AttributionResolver {
	if len(materials) == 0 {
		return states.OwnIdentityAttribution
	}
	uris := make([]string, 0, len(materials))
	for uri := range materials {
		uris = append(uris, uri)
	}
	slices.Sort(uris)
	source := vulnerability.LocalMaterialSource{Captures: materials}
	return func(ctx context.Context, requestedID string, record vulnerability.LoadedRecord) ([]domain.CVEAttribution, error) {
		own, ownErr := states.OwnIdentityAttribution(ctx, requestedID, record)
		if ownErr == nil {
			for _, attribution := range own {
				if attribution.Admitted() {
					return own, nil
				}
			}
		}
		captured := make([]vulnerability.CapturedMaterial, 0, len(uris))
		for _, uri := range uris {
			material, err := source.Capture(ctx, uri)
			if err != nil {
				return nil, err
			}
			captured = append(captured, material)
		}
		attribution, err := vulnerability.AdmitAttribution(vulnerability.AttributionInput{
			CVEID:     requestedID,
			Record:    record,
			EntryRefs: states.RecordAttributionEntryRefs(record.Vuln),
			Materials: captured,
		})
		if err != nil {
			if ownErr != nil {
				return nil, fmt.Errorf("%v; captured material: %w", ownErr, err)
			}
			return nil, err
		}
		return []domain.CVEAttribution{attribution}, nil
	}
}

// dvPublisherMaterials configures the captured publisher document. The local
// source takes a path and pins the bytes it reads, so the digest the attribution
// records is the fixture's own digest.
func dvPublisherMaterials(t *testing.T, wc dvWorkedCase) map[string]string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(dvEvidenceDir, "grpc-publisher-advisory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("captured publisher document: %v", err)
	}
	return map[string]string{
		"https://github.com/grpc/grpc-go/security/advisories/" + dvPublisher: path,
	}
}

// dvPrimary asserts the recorded 22-entry projection survived the run
// unchanged and that the request never gained a gRPC entry.
func dvPrimary(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	if c.Vulnerability.ID != dvPrimaryGHSA {
		t.Fatalf("primary record = %q, want the exact %s document", c.Vulnerability.ID, dvPrimaryGHSA)
	}
	scope := c.Vulnerability.Scope
	if scope == nil || scope.RecordInventory == nil {
		t.Fatalf("primary scope/inventory = %+v", scope)
	}
	if scope.Coverage != domain.CoverageKnownOnly || scope.RecordExtent != domain.RecordExtentGoProjection {
		t.Fatalf("primary scope = %q/%q, want KNOWN_ONLY/GO_PROJECTION", scope.Coverage, scope.RecordExtent)
	}
	inventory := scope.RecordInventory
	if inventory.AffectedEntryCount != 22 || len(inventory.RepresentedRefs) != 1 || len(inventory.OmittedRefs) != 21 {
		t.Fatalf("primary census = %d/%d/%d, want 22/1/21",
			inventory.AffectedEntryCount, len(inventory.RepresentedRefs), len(inventory.OmittedRefs))
	}
	modules := make([]string, 0, len(c.Vulnerability.AffectedModules))
	for _, module := range c.Vulnerability.AffectedModules {
		modules = append(modules, module.Module)
	}
	if !slices.Equal(modules, []string{"golang.org/x/net"}) {
		t.Fatalf("primary Go projection = %v; gRPC must not be appended as an aggregate entry", modules)
	}
	if len(c.Vulnerability.AffectedModules) == 0 {
		t.Fatal("primary lost its Go projection")
	}
	if got := c.Vulnerability.AffectedModules == nil; got {
		t.Fatal("primary module inventory was rewritten")
	}
}

func dvChild(t *testing.T, c *domain.AnalysisCase, record string) *domain.AnalysisCase {
	t.Helper()
	for _, related := range c.RelatedRecords {
		if related.Record.RecordID == record {
			return related.Analysis
		}
	}
	t.Fatalf("no isolated assessment for %s in %d related record(s)", record, len(c.RelatedRecords))
	return nil
}

func dvClaim(c *domain.AnalysisCase, id domain.ConditionID) (domain.Claim, bool) {
	for _, claim := range c.Claims {
		if claim.ConditionID == id {
			return claim, true
		}
	}
	return domain.Claim{}, false
}

func dvGapCodes(gaps []domain.AnalysisGap) []string {
	out := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		out = append(out, string(gap.Owner)+"/"+string(gap.Code))
	}
	return out
}

func dvHasGap(gaps []domain.AnalysisGap, code domain.GapCode) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func dvFinding(t *testing.T, c *domain.AnalysisCase) *domain.RequestedFinding {
	t.Helper()
	if c.RequestedFinding == nil {
		t.Fatalf("case %s has no requested finding", c.ID)
	}
	return c.RequestedFinding
}

// TestDefinitiveVerdictIntegration is the hermetic worked-case regression.
func TestDefinitiveVerdictIntegration(t *testing.T) {
	t.Run("the worked case composes an attributed transport-peer positive", func(t *testing.T) {
		wc := dvPrepare(t)
		grpcRecordBefore, err := os.ReadFile(dvGRPCPath)
		if err != nil {
			t.Fatal(err)
		}
		c, caseDir := dvRun(t, wc, dvCVE, wc.corpus, wc.declaration, dvPublisherMaterials(t, wc))

		dvPrimary(t, c)
		if c.RelatedDiscovery == nil || c.RelatedDiscovery.Enumeration != domain.DiscoveryFinished {
			t.Fatalf("discovery = %+v", c.RelatedDiscovery)
		}
		child := dvChild(t, c, dvGRPC)
		if child.Vulnerability.ID != dvGRPC {
			t.Fatalf("child record = %q", child.Vulnerability.ID)
		}
		if child.RecordPin == nil || child.RecordPin.RecordID != dvGRPC {
			t.Fatalf("child pin = %+v", child.RecordPin)
		}

		// The candidate's own exact bytes: the CVE must never be inserted into
		// the GO record's aliases, and the record must be unchanged on disk.
		if slices.Contains(child.Vulnerability.Aliases, dvCVE) {
			t.Fatalf("the requested CVE was inserted into %s aliases: %v", dvGRPC, child.Vulnerability.Aliases)
		}
		childRaw, err := os.ReadFile(dvGRPCPath)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(childRaw, grpcRecordBefore) {
			t.Fatal("the candidate record file changed during the run")
		}

		// Independent applicability: gRPC v1.55.0 is inside [0,1.56.3).
		if child.Affected == nil {
			t.Fatalf("the isolated assessment recorded no affected result")
		}
		if !slices.Contains(child.Affected.CheckedModules, "google.golang.org/grpc") {
			t.Fatalf("checked modules = %v, want google.golang.org/grpc", child.Affected.CheckedModules)
		}
		if !slices.Contains(child.Affected.VersionAffectedModules, "google.golang.org/grpc") {
			t.Fatalf("version-affected modules = %v, want google.golang.org/grpc inside [0,1.56.3)",
				child.Affected.VersionAffectedModules)
		}
		if child.Affected.VersionAffected != domain.ClaimTrue {
			t.Fatalf("gRPC version_affected = %q, want TRUE", child.Affected.VersionAffected)
		}
		if child.Affected.ResolvedVersion != dvGRPCVersion {
			t.Fatalf("gRPC resolved version = %q, want %s", child.Affected.ResolvedVersion, dvGRPCVersion)
		}
		if slices.Contains(child.Affected.CheckedModules, "golang.org/x/net") ||
			slices.Contains(child.Affected.VersionAffectedModules, "golang.org/x/net") {
			t.Fatalf("the gRPC assessment inherited the primary's x/net entry: %+v", child.Affected)
		}
		if c.Affected != nil && c.Affected.VersionAffected == domain.ClaimTrue {
			t.Fatalf("the primary x/net fact changed: %+v", c.Affected)
		}

		// The typed transport evidence, not the publication: the record's own
		// correspondence is a complete source/fix-bound trigger witness. It
		// is recorded through the applicability-gated route, so the witness
		// is the checker's, never a caller's assertion.
		var trigger *domain.TransportTriggerWitness
		for _, evidence := range child.EvidenceGraph.EvidenceList() {
			if evidence.TransportTrigger != nil {
				trigger = evidence.TransportTrigger
			}
		}
		if trigger == nil {
			t.Fatal("the assessment recorded no transport trigger witness")
		}
		if trigger.Mechanism != dvMechanism {
			t.Fatalf("trigger mechanism = %q", trigger.Mechanism)
		}
		for _, obligation := range trigger.Obligations {
			if !obligation.Satisfied {
				t.Fatalf("trigger obligation %s unsatisfied: %s", obligation.ID, obligation.Detail)
			}
		}
		if trigger.Input.Root.Package != "example.com/definitiveproduct/pkg/kubelet/server" {
			t.Fatalf("rooted input root = %q", trigger.Input.Root.Package)
		}
		if !trigger.Input.Root.Production {
			t.Fatal("the rooted input root is not production source")
		}
		if trigger.Fix.Digest != dvDigest([]byte(wc.patch)) {
			t.Fatalf("fix digest = %s", trigger.Fix.Digest)
		}
		if !slices.Contains(trigger.Fix.EnforcementNames, dvFixedEnforce) {
			t.Fatalf("fix enforcement names = %v, want %s", trigger.Fix.EnforcementNames, dvFixedEnforce)
		}
		constraint, ok := dvClaim(child, "C-INPUT")
		if !ok {
			t.Fatalf("no C-INPUT claim: %+v", child.Claims)
		}
		if constraint.Result != domain.ClaimTrue {
			t.Fatalf("C-INPUT = %s (%s); want the mechanism witness", constraint.Result, constraint.Explanation)
		}

		// The positive is withheld, and the trace is the record's own
		// structured data: GO-2023-2153 carries no CWE, so the class is only a
		// keyword nomination. The peer-gated RESOURCE_EXHAUSTION variant —
		// whose C-PEER-INPUT/C-EXPOSURE/C-TLS-VERIFY conditions this worked
		// case used to merge — required a keyword class and a prose input
		// route, and neither is authority. The modeled conjunction therefore
		// omits the conditions that nomination demanded, and an all-TRUE
		// result over it must not publish a positive.
		for _, claim := range child.Claims {
			if claim.ConditionID == "C-PEER-INPUT" {
				t.Fatalf("the withheld peer variant still merged a C-PEER-INPUT claim: %+v", claim)
			}
		}
		if !child.Exploit.UnresolvedMechanism {
			t.Fatal("the record's keyword-nominated class left the mechanism resolved")
		}
		childFinding := dvFinding(t, child)
		if childFinding.Outcome != domain.OutcomeFailed || childFinding.Verdict != "" {
			t.Fatalf("the isolated gRPC finding = %s/%q; the unresolved mechanism must withhold the positive",
				childFinding.Outcome, childFinding.Verdict)
		}
		if !dvHasGap(childFinding.Gaps, domain.GapRootCauseUnresolved) {
			t.Fatalf("child gaps = %v, want the unresolved-mechanism cause", dvGapCodes(childFinding.Gaps))
		}

		// Registry attribution still binds the publisher material to the
		// record, and no alias is mutated -- but attribution never lifts a
		// record result the record itself did not earn.
		var attribution *domain.CVEAttribution
		for i := range c.Attributions {
			admitted := &c.Attributions[i]
			if admitted.Candidate.RecordID == dvGRPC && admitted.Admitted() {
				attribution = admitted
			}
		}
		if attribution == nil {
			t.Fatalf("no admitted attribution for %s on the request: %+v", dvGRPC, c.Attributions)
		}
		if !attribution.Candidate.Same(*child.RecordPin) {
			t.Fatalf("attribution candidate %+v is not the assessed record pin", attribution.Candidate)
		}
		if attribution.Basis != domain.AttributionPublisher {
			t.Fatalf("attribution basis = %q, want publisher", attribution.Basis)
		}
		if attribution.PublisherAdvisory != dvPublisher {
			t.Fatalf("publisher advisory = %q, want %s", attribution.PublisherAdvisory, dvPublisher)
		}
		if attribution.Module != "google.golang.org/grpc" {
			t.Fatalf("attribution module = %q", attribution.Module)
		}
		if !slices.Contains(attribution.FixRefs, dvFixPR) {
			t.Fatalf("attribution fix refs = %v, want %s", attribution.FixRefs, dvFixPR)
		}
		if attribution.CapturedDigest != dvDigest([]byte(wc.publisher)) {
			t.Fatalf("attribution capture digest = %s", attribution.CapturedDigest)
		}
		if !slices.Equal(attribution.EntryRefs, []int{0}) {
			t.Fatalf("attribution entry refs = %v, want the record's proved affected entry 0", attribution.EntryRefs)
		}

		// The requested CVE is not lifted: no positive was independently
		// earned, and the declared corpus cannot close the request.
		final := dvFinding(t, c)
		if final.RequestedID != dvCVE || final.RequestedKind != domain.ScopeCVE || final.Coverage != domain.CoverageKnownOnly {
			t.Fatalf("requested envelope = %q/%q/%q", final.RequestedID, final.RequestedKind, final.Coverage)
		}
		if final.Outcome != domain.OutcomeFailed || final.Verdict != "" {
			t.Fatalf("outcome/verdict = %s/%q gaps=%v; the CVE must not inherit the candidate's withheld positive",
				final.Outcome, final.Verdict, dvGapCodes(final.Gaps))
		}
		if len(final.ProofOrigins) != 0 {
			t.Fatalf("the request adopted a proof origin: %+v", final.ProofOrigins)
		}

		// Persistence and publication still describe the same run: the case
		// is a valid finalized case and every surface is written.
		if err := domain.ValidateFinalizedCase(c); err != nil {
			t.Fatalf("persisted case is not a valid finalized case: %v", err)
		}
		for _, name := range []string{"report.json", "report.md", "openvex.json", "cyclonedx.json"} {
			if _, err := os.Stat(filepath.Join(caseDir, string(c.ID), name)); err != nil {
				t.Fatalf("%s was not written: %v", name, err)
			}
		}
		reportRaw, err := os.ReadFile(filepath.Join(caseDir, string(c.ID), "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(reportRaw), dvGRPC) {
			t.Fatal("report.json does not name the assessed candidate record")
		}
	})

	t.Run("the exact broad GHSA request is not substituted by the candidate positive", func(t *testing.T) {
		wc := dvPrepare(t)
		c, _ := dvRun(t, wc, dvPrimaryGHSA, wc.corpus, wc.declaration, dvPublisherMaterials(t, wc))

		final := dvFinding(t, c)
		if final.RequestedID != dvPrimaryGHSA || final.RequestedKind != domain.ScopeAdvisoryEntries {
			t.Fatalf("requested envelope = %q/%q", final.RequestedID, final.RequestedKind)
		}
		if final.Outcome != domain.OutcomeFailed || final.Verdict != "" {
			t.Fatalf("exact GHSA request outcome/verdict = %s/%q", final.Outcome, final.Verdict)
		}
		if !dvHasGap(final.Gaps, domain.GapUnsupportedNegativeScope) {
			t.Fatalf("exact GHSA request gaps = %v, want the scope-capability failure", dvGapCodes(final.Gaps))
		}
		if len(final.ProofOrigins) != 0 {
			t.Fatalf("the exact GHSA request adopted a related witness: %+v", final.ProofOrigins)
		}
		// The gRPC record keeps its own result, and that result is not a
		// positive: its class is only a keyword nomination, so the modeled
		// conjunction cannot ground EXPLOITABLE. The exact GHSA request must
		// never substitute the candidate's answer either way.
		child := dvChild(t, c, dvGRPC)
		if child.RequestedFinding == nil || child.RequestedFinding.Outcome != domain.OutcomeFailed ||
			child.RequestedFinding.Verdict != "" {
			t.Fatalf("the isolated gRPC finding = %+v", child.RequestedFinding)
		}
	})

	t.Run("publisher material that does not bind the record cannot lift the CVE", func(t *testing.T) {
		wc := dvPrepare(t)
		tampered := strings.Replace(wc.publisher, dvPublisher, "GHSA-0000-0000-0000", 1)
		if tampered == wc.publisher {
			t.Fatal("the tamper control did not change the captured document")
		}
		path := filepath.Join(t.TempDir(), "capture.json")
		if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
			t.Fatal(err)
		}
		c, _ := dvRun(t, wc, dvCVE, wc.corpus, wc.declaration, map[string]string{
			"https://github.com/grpc/grpc-go/security/advisories/" + dvPublisher: path,
		})

		final := dvFinding(t, c)
		if final.Outcome != domain.OutcomeFailed || final.Verdict != "" {
			t.Fatalf("unbinding material still lifted the CVE: %s/%q", final.Outcome, final.Verdict)
		}
		// The tampered capture cannot bind the record: the attribution stays
		// ambiguous (recorded on the request) and, with no independently
		// earned positive to lift, the request fails its composition.
		var ambiguous bool
		for _, ac := range c.Attributions {
			if ac.Candidate.RecordID == dvGRPC && !ac.Admitted() {
				ambiguous = true
			}
		}
		if !ambiguous {
			t.Fatalf("the tampered capture still admitted %s: %+v", dvGRPC, c.Attributions)
		}
		// The record-level result is retained, not published: the candidate's
		// withhold-positive outcome survives the tampered publisher material,
		// and no proof origin is adopted.
		child := dvChild(t, c, dvGRPC)
		if child.RequestedFinding == nil || child.RequestedFinding.Outcome != domain.OutcomeFailed ||
			child.RequestedFinding.Verdict != "" {
			t.Fatalf("the record-level result was lost: %+v", child.RequestedFinding)
		}
		if len(final.ProofOrigins) != 0 {
			t.Fatalf("the tampered publisher material still produced proof origins: %+v", final.ProofOrigins)
		}
	})

	t.Run("a synchronous dispatch does not earn the transport positive", func(t *testing.T) {
		wc := dvPrepareMutated(t, func(t *testing.T, product, module string) {
			t.Helper()
			path := filepath.Join(module, "server.go")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), "\t\tgo func() {", "\t\tfunc() {", 1)
			if mutated == string(raw) {
				t.Fatal("the no-trigger control did not find the asynchronous handler start")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
				t.Fatal(err)
			}
		})
		c, _ := dvRun(t, wc, dvCVE, wc.corpus, wc.declaration, dvPublisherMaterials(t, wc))

		child := dvChild(t, c, dvGRPC)
		claim, ok := dvClaim(child, "C-INPUT")
		if !ok {
			t.Fatalf("no C-INPUT claim: %+v", child.Claims)
		}
		if claim.Result == domain.ClaimTrue {
			t.Fatal("the trigger was earned without an asynchronous handler lifetime")
		}
		final := dvFinding(t, c)
		if final.Outcome != domain.OutcomeFailed || final.Verdict != "" {
			t.Fatalf("a no-trigger source produced %s/%q", final.Outcome, final.Verdict)
		}
	})

	t.Run("a declared corpus closes the CVE only with its recorded boundary", func(t *testing.T) {
		fixed := dvPrepareMutated(t, func(t *testing.T, product, _ string) {
			t.Helper()
			path := filepath.Join(product, "go.mod")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), "grpc v1.55.0", "grpc v1.56.3", 1)
			if mutated == string(raw) {
				t.Fatal("the fixed-version control did not change the product graph")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
				t.Fatal(err)
			}
		})

		// An undeclared corpus grants no completeness authority: the CVE
		// request fails its scope rather than becoming safe.
		undeclared, _ := dvRun(t, fixed, dvCVE, fixed.corpus, nil, dvPublisherMaterials(t, fixed))
		finalUndeclared := dvFinding(t, undeclared)
		if finalUndeclared.Outcome != domain.OutcomeFailed || finalUndeclared.Verdict != "" {
			t.Fatalf("undeclared corpus outcome = %s/%q", finalUndeclared.Outcome, finalUndeclared.Verdict)
		}
		if !dvHasGap(finalUndeclared.Gaps, domain.GapUnsupportedNegativeScope) {
			t.Fatalf("undeclared corpus gaps = %v", dvGapCodes(finalUndeclared.Gaps))
		}

		// Declared and finished: the same all-negative candidates close the
		// request with the recorded corpus identity.
		declared, _ := dvRun(t, fixed, dvCVE, fixed.corpus, fixed.declaration, dvPublisherMaterials(t, fixed))
		final := dvFinding(t, declared)
		if final.Outcome != domain.OutcomeDecided || final.Verdict != domain.VerdictNotAffected {
			t.Fatalf("declared corpus outcome = %s/%q gaps=%v", final.Outcome, final.Verdict, dvGapCodes(final.Gaps))
		}
		if final.CorpusNegativeBasis == nil {
			t.Fatal("the CVE-wide negative carries no corpus basis")
		}
		basis := final.CorpusNegativeBasis
		if basis.Reference != dvCorpusRef || basis.Enumeration != domain.DiscoveryFinished {
			t.Fatalf("corpus basis = %q/%q", basis.Reference, basis.Enumeration)
		}
		for _, want := range []string{
			"Corpus boundary:", dvCorpusRef, basis.DeclaredDigest, "2026-10-26",
			"implementations outside this corpus were not examined",
		} {
			if !strings.Contains(basis.BoundaryStatement, want) {
				t.Fatalf("boundary statement %q does not carry %q", basis.BoundaryStatement, want)
			}
		}
		if basis.DeclaredDigest != basis.ObservedDigest {
			t.Fatalf("declared digest %s != observed %s", basis.DeclaredDigest, basis.ObservedDigest)
		}
		if !strings.Contains(strings.Join(final.Limitations, "\n"), "implementations outside this corpus were not examined") {
			t.Fatalf("the requested finding lost the corpus boundary limitation: %v", final.Limitations)
		}
	})
}

// dvDumpChild prints one isolated assessment's decided facts so a failing
// expectation states why the record did or did not earn its result.
func dvDumpChild(t *testing.T, c *domain.AnalysisCase) {
	t.Helper()
	if c == nil {
		t.Logf("child <nil>")
		return
	}
	verdict := "<none>"
	if c.Verdict != nil {
		verdict = fmt.Sprintf("%s (%s)", c.Verdict.Verdict, c.Verdict.Reason)
	}
	t.Logf("child %s record=%s state=%s verdict=%s", c.ID, c.Vulnerability.ID, c.Workflow.State, verdict)
	if c.Exploit != nil {
		t.Logf("child model role=%s mandatory=%d supporting=%d", c.Exploit.ProtocolRole,
			len(c.Exploit.MandatoryConditions), len(c.Exploit.SupportingFactors))
		for _, cond := range append(append([]domain.Condition{}, c.Exploit.MandatoryConditions...), c.Exploit.SupportingFactors...) {
			t.Logf("child condition %s kind=%s mandatory=%v check=%q", cond.ID, cond.Kind, cond.Mandatory, cond.Params)
		}
	}
	for _, claim := range c.Claims {
		t.Logf("child claim %s cond=%s result=%s basis=%s why=%s gaps=%v",
			claim.ID, claim.ConditionID, claim.Result, claim.ControlBasis, claim.Explanation, dvGapCodes(claim.AnalysisGaps))
	}
	t.Logf("child gaps=%v", dvGapCodes(c.AnalysisGaps))
	for _, limitation := range c.EvidenceGraph.Limitations {
		t.Logf("child limitation: %s", limitation)
	}
	for _, p := range c.ProfileAssessments {
		t.Logf("child profile %s actual=%v outcome=%s verdict=%q gaps=%v",
			p.Profile, p.IsTargetActual, p.Result.Outcome, p.Result.Verdict, dvGapCodes(p.Result.Gaps))
	}
}

// discoveryEnumeration renders the discovery enumeration outcome for logs.
func discoveryEnumeration(c *domain.AnalysisCase) domain.DiscoveryEnumeration {
	if c == nil || c.RelatedDiscovery == nil {
		return ""
	}
	return c.RelatedDiscovery.Enumeration
}
