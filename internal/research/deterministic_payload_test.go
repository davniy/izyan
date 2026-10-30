package research

// Lane payload bounds (bounded-by-construction members): the
// affected-resolve and ingress-inventory payloads embed resolver /
// source-index evidence whose content is unbounded tool output (e.g.
// the whole `go list -m -json all` stream of a vendored closure).
// A 9.5 MB evidence payload once pushed the persisted
// affected-resolve observation past maxObservationPayloadBytes, the
// last-resort cap downgraded it to PARTIAL, and the lane-discharge
// gate refused it — blocking the entire agent lane before the first
// model call. These tests pin the construction bound: oversized
// content becomes a digest-pinned preview, small content stays
// verbatim, member lists are prefix-bounded with the recorded total,
// and the resulting observation stays COMPLETE and discharges the
// policy-required check.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// oversizedEvidenceContent is tool output far past the observation
// payload cap — the shape that broke discharge on a real snapshot.
func oversizedEvidenceContent() string {
	return strings.Repeat(`{"Path":"example.com/mod","Version":"v1.0.0"}`+"\n",
		(10*1024*1024)/44+1)
}

// boundedResolveObservation reproduces the lane's affected-resolve
// record shape: the semantic members verbatim plus the bounded
// evidence projection.
func boundedResolveObservation(id, snapHash string, ev []domain.Evidence) *evidencetools.Observation {
	evidenceView := laneEvidenceView(ev)
	var lims []string
	if note := laneEvidenceBoundNote(evidenceView); note != "" {
		lims = append(lims, note)
	}
	o := &evidencetools.Observation{
		ID:   id,
		Tool: "affected-resolve",
		Fact: "applicability chain for TEST-0001: module_present=TRUE version_affected=TRUE package_present=TRUE build_relevant=TRUE (selected [example.com/mod])",
		Scope: "affected.GoResolver.Resolve over the snapshot module graph and import closure " +
			"(go list -m, go list -deps under strict toolchain env)",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		Limitations:  lims,
		ScopeDetails: &evidencetools.ScopeDetails{
			SnapshotHash: snapHash,
			Subject:      "TEST-0001",
			CoverageRule: "closed applicability chain: module graph → version ranges → import closure → build relevance",
		},
		Data: map[string]any{
			"affected_result": domain.AffectedResult{
				ModulePresent:   domain.ClaimTrue,
				VersionAffected: domain.ClaimTrue,
				PackagePresent:  domain.ClaimTrue,
				BuildRelevant:   domain.ClaimTrue,
				CheckedModules:  []string{"example.com/mod"},
				EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES", "EV-AFFECTED-PACKAGES"},
			},
			"evidence": evidenceView,
		},
	}
	finishLaneObservation(o)
	return o
}

func payloadBytes(t *testing.T, data any) int {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("payload does not marshal: %v", err)
	}
	return len(raw)
}

func TestLaneEvidenceViewBoundsOversizedContent(t *testing.T) {
	big := oversizedEvidenceContent()
	bigSum := sha256.Sum256([]byte(big))
	ev := []domain.Evidence{
		{
			ID:      "EV-AFFECTED-MODULES",
			Kind:    domain.EvidenceModuleGraph,
			Quality: domain.QualityDeterministic,
			Source:  "go list -m -json all",
			Tool:    "go",
			Command: "go list -m -json all",
			Content: big,
		},
		{
			ID:      "EV-AFFECTED-PACKAGES",
			Kind:    domain.EvidencePackageList,
			Quality: domain.QualityDeterministic,
			Source:  "go list -deps -test -json ./...",
			Content: `{"ImportPath":"example.com/mod/pkg"}`,
		},
	}
	view := laneEvidenceView(ev)
	if len(view) != 2 {
		t.Fatalf("evidence items = %d, want 2", len(view))
	}
	// Oversized item: bounded preview + digest pins, never raw text.
	bigItem := view[0]
	if bigItem.Content != "" || !bigItem.ContentBounded {
		t.Fatalf("oversized item kept verbatim content: %d bytes bounded=%v",
			len(bigItem.Content), bigItem.ContentBounded)
	}
	if bigItem.ContentSHA256 != hex.EncodeToString(bigSum[:]) {
		t.Fatal("content_sha256 does not pin the full content")
	}
	if bigItem.ContentBytes != int64(len(big)) {
		t.Fatalf("content_bytes = %d, want %d", bigItem.ContentBytes, len(big))
	}
	if len(bigItem.ContentPreview) == 0 ||
		len(bigItem.ContentPreview) > laneEvidenceItemPreviewBytes {
		t.Fatalf("preview = %d bytes, want 1..%d",
			len(bigItem.ContentPreview), laneEvidenceItemPreviewBytes)
	}
	if !utf8.ValidString(bigItem.ContentPreview) {
		t.Fatal("preview is not valid UTF-8")
	}
	// Metadata travels verbatim with the bounded record.
	if bigItem.ID != "EV-AFFECTED-MODULES" || bigItem.Kind != domain.EvidenceModuleGraph ||
		bigItem.Source != "go list -m -json all" {
		t.Fatalf("metadata lost in projection: %+v", bigItem.Evidence)
	}
	// Small content stays verbatim with its pins alongside.
	small := view[1]
	if small.Content != ev[1].Content || small.ContentBounded || small.ContentPreview != "" {
		t.Fatalf("small content not verbatim: %+v", small)
	}
	if small.ContentBytes != int64(len(ev[1].Content)) {
		t.Fatalf("small content_bytes = %d", small.ContentBytes)
	}
	// The original evidence is never mutated.
	if ev[0].Content != big {
		t.Fatal("lane evidence mutated by the payload projection")
	}
	// The marshaled projection is orders of magnitude under the cap.
	raw, _ := json.Marshal(view)
	if len(raw) > maxObservationPayloadBytes/2 {
		t.Fatalf("bounded evidence still %d bytes", len(raw))
	}
}

func TestLaneEvidenceViewSharedBudgets(t *testing.T) {
	// More text-carrying items than the per-payload budget: the rest
	// become digest-only, and the embedded text never grows with the
	// item count.
	var ev []domain.Evidence
	for range laneEvidenceTextItems * 3 {
		ev = append(ev, domain.Evidence{
			ID:      domain.EvidenceID("EV-" + strings.Repeat("x", 8)),
			Content: strings.Repeat("y", laneEvidenceItemVerbatimBytes),
		})
	}
	view := laneEvidenceView(ev)
	verbatim, previewed, digestOnly, textBytes := 0, 0, 0, 0
	for _, it := range view {
		switch {
		case it.Content != "":
			verbatim++
			textBytes += len(it.Content)
		case it.ContentPreview != "":
			previewed++
			textBytes += len(it.ContentPreview)
		default:
			digestOnly++
		}
		if it.ContentSHA256 == "" || it.ContentBytes <= 0 {
			t.Fatalf("item lacks digest pins: %+v", it)
		}
	}
	if digestOnly == 0 {
		t.Fatalf("no digest-only items under a %d-item list of %dB contents: verbatim=%d previewed=%d",
			len(ev), laneEvidenceItemVerbatimBytes, verbatim, previewed)
	}
	if verbatim+previewed > laneEvidenceTextItems {
		t.Fatalf("text-carrying items %d exceed budget %d", verbatim+previewed, laneEvidenceTextItems)
	}
	if textBytes > laneEvidencePayloadTextBytes {
		t.Fatalf("embedded text %d exceeds shared budget %d", textBytes, laneEvidencePayloadTextBytes)
	}
}

// The affected-resolve payload must never reach the cap on a real
// snapshot: bounded construction, then persist must leave the
// observation untouched (no truncated_payload marker), COMPLETE, and
// the lane-discharge gate must accept it — the planner is no longer
// blocked on the lane-carried required check.
func TestAffectedResolvePayloadBoundedAndDischarges(t *testing.T) {
	dir := t.TempDir()
	snapHash := strings.Repeat("ab", 32)
	ev := []domain.Evidence{
		{
			ID:      "EV-AFFECTED-MODULES",
			Kind:    domain.EvidenceModuleGraph,
			Quality: domain.QualityDeterministic,
			Source:  "go list -m -json all",
			Content: oversizedEvidenceContent(),
		},
		{
			ID:      "EV-AFFECTED-PACKAGES",
			Kind:    domain.EvidencePackageList,
			Quality: domain.QualityDeterministic,
			Source:  "go list -deps -test -json ./...",
			Content: `{"ImportPath":"example.com/mod/pkg"}`,
		},
	}
	o := boundedResolveObservation("OBS-0002", snapHash, ev)
	if o.Completeness != evidencetools.CompletenessComplete {
		t.Fatalf("lane finish downgraded completeness: %s", o.Completeness)
	}
	lane := &LaneResult{
		SnapshotRoot: dir, ContentHash: snapHash,
		Observations:   []*evidencetools.Observation{o},
		CanonicalByObs: map[string]string{},
		ArtifactByObs:  map[string]ArtifactRef{},
	}
	lane.Records = []evidencetools.AuditRecord{{
		Tool: "affected-resolve", Args: json.RawMessage(`{"vuln":"TEST-0001"}`), Observation: o,
	}}
	if err := lane.persist(dir); err != nil {
		t.Fatal(err)
	}
	// The last-resort cap must never fire on the bounded payload.
	m, ok := o.Data.(map[string]any)
	if !ok {
		t.Fatalf("payload lost: %T", o.Data)
	}
	if _, truncated := m["truncated_payload"]; truncated {
		t.Fatalf("bounded payload hit the last-resort cap: %v", m)
	}
	if payloadBytes(t, o.Data) > maxObservationPayloadBytes {
		t.Fatal("bounded payload exceeds the observation cap")
	}
	if o.Completeness != evidencetools.CompletenessComplete {
		t.Fatalf("completeness = %s, want COMPLETE", o.Completeness)
	}
	noteSeen := false
	for _, l := range o.Limitations {
		if strings.Contains(l, "truncated") {
			t.Fatalf("cap limitation on a bounded payload: %q", l)
		}
		if strings.Contains(l, "bounded by construction") {
			noteSeen = true
		}
	}
	if !noteSeen {
		t.Fatalf("bound not named on the record's limitations: %v", o.Limitations)
	}
	// Semantic members stay intact.
	ar, ok := m["affected_result"].(domain.AffectedResult)
	if !ok || ar.ModulePresent != domain.ClaimTrue {
		t.Fatalf("affected_result lost or mutated: %v", m["affected_result"])
	}
	items, ok := m["evidence"].([]laneEvidenceItem)
	if !ok || len(items) != 2 {
		t.Fatalf("evidence projection missing: %T", m["evidence"])
	}
	if items[0].ContentBytes != int64(len(ev[0].Content)) || items[0].ContentSHA256 == "" {
		t.Fatalf("digest pins missing: %+v", items[0])
	}
	if items[1].Content != ev[1].Content {
		t.Fatal("small evidence content not verbatim")
	}
	// The persisted artifact carries the bounded shape on the wire.
	art, err := os.ReadFile(filepath.Join(dir, "artifacts", "obs-0002.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(art) > maxObservationPayloadBytes*2 {
		t.Fatalf("persisted artifact unbounded: %d bytes", len(art))
	}
	var decoded struct {
		Data struct {
			Evidence []struct {
				ID             string `json:"id"`
				Content        string `json:"content"`
				ContentPreview string `json:"content_preview"`
				ContentSHA256  string `json:"content_sha256"`
				ContentBytes   int64  `json:"content_bytes"`
				ContentBounded bool   `json:"content_bounded"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(art, &decoded); err != nil {
		t.Fatalf("persisted observation does not decode: %v", err)
	}
	big := decoded.Data.Evidence[0]
	if big.ID != "EV-AFFECTED-MODULES" || big.Content != "" ||
		big.ContentPreview == "" || big.ContentSHA256 == "" || !big.ContentBounded {
		t.Fatalf("wire record of oversized evidence wrong: %+v", big)
	}
	small := decoded.Data.Evidence[1]
	if small.Content != ev[1].Content || small.ContentBounded {
		t.Fatalf("wire record of small evidence mutated: %+v", small)
	}
	// The lane discharge accepts the pinned COMPLETE record: the
	// planner surface is no longer blocked on the lane-carried check.
	cats, err := LoadCatalogs(r6ConfigFS(t))
	if err != nil {
		t.Fatalf("catalogs: %v", err)
	}
	completed, evidence := dischargedLaneChecks(lane, cats)
	if len(completed) != 1 || completed[0] != "affected-resolve" {
		t.Fatalf("affected-resolve not discharged: completed=%v", completed)
	}
	if len(evidence) != 1 || evidence[0].ID != "OBS-0002" || !evidence[0].AuditBound {
		t.Fatalf("discharge evidence wrong: %+v", evidence)
	}
}

// The second evidence-embedding site — ingress-inventory — gets the
// same construction bound, and its closure member is prefix-bounded
// with the recorded total.
func TestIngressInventoryPayloadBounded(t *testing.T) {
	big := oversizedEvidenceContent()
	var items []domain.IngressItem
	for i := range lanePayloadMaxListItems + 17 {
		items = append(items, domain.IngressItem{
			CallSite: domain.CallSite{File: "main.go", Line: i, Function: "handler",
				Package: "example.com/prod"},
			Kind: "entry", Callee: "dep.Read", Detail: strings.Repeat("d", 200),
		})
	}
	inv := domain.IngressClosure{
		Module: "example.com/dep", Items: items,
		Blockers: []string{"opaque dispatch"},
	}
	iev := []domain.Evidence{{
		Kind: domain.EvidenceDataFlow, Quality: domain.QualityDeterministic,
		Source:  "source index: ingress closure inventory",
		Tool:    "goanalysis.Index.IngressInventory",
		Content: big,
	}}
	data := map[string]any{
		"closure":  laneClosureViewOf(inv),
		"evidence": laneEvidenceView(iev),
	}
	if payloadBytes(t, data) > maxObservationPayloadBytes {
		t.Fatalf("ingress payload %d bytes exceeds cap", payloadBytes(t, data))
	}
	cv := data["closure"].(laneClosureView)
	if cv.ItemsTotal != len(items) || len(cv.Items) != lanePayloadMaxListItems {
		t.Fatalf("closure items %d/%d, want %d kept of %d",
			len(cv.Items), cv.ItemsTotal, lanePayloadMaxListItems, len(items))
	}
	if len(cv.Blockers) != 1 || cv.Complete {
		t.Fatalf("closure semantics lost: %+v", cv.IngressClosure)
	}
	if len(inv.Items) != len(items) {
		t.Fatal("lane inventory mutated by the payload projection")
	}
	ei := data["evidence"].([]laneEvidenceItem)
	if ei[0].Content != "" || !ei[0].ContentBounded || ei[0].ContentPreview == "" {
		t.Fatalf("ingress evidence content not bounded: %+v", ei[0])
	}
	// The persisted observation never hits the last-resort cap.
	dir := t.TempDir()
	snapHash := strings.Repeat("cd", 32)
	o := &evidencetools.Observation{
		ID: "OBS-0005", Tool: "ingress-inventory",
		Fact:         "ingress inventory for module example.com/dep",
		Scope:        "goanalysis.IngressInventory over module example.com/dep",
		Completeness: evidencetools.CompletenessPartial,
		ToolStatus:   evidencetools.StatusOK,
		ScopeDetails: &evidencetools.ScopeDetails{SnapshotHash: snapHash},
		Data:         data,
	}
	finishLaneObservation(o)
	lane := &LaneResult{
		SnapshotRoot: dir, ContentHash: snapHash,
		Observations:   []*evidencetools.Observation{o},
		CanonicalByObs: map[string]string{},
		ArtifactByObs:  map[string]ArtifactRef{},
		Records: []evidencetools.AuditRecord{{
			Tool: "ingress-inventory", Args: json.RawMessage(`{"module":"example.com/dep"}`), Observation: o,
		}},
	}
	if err := lane.persist(dir); err != nil {
		t.Fatal(err)
	}
	if _, truncated := o.Data.(map[string]any)["truncated_payload"]; truncated {
		t.Fatal("bounded ingress payload hit the last-resort cap")
	}
	if o.Completeness != evidencetools.CompletenessPartial {
		t.Fatalf("completeness mutated: %s", o.Completeness)
	}
}

// Exposure-scan payloads (listen-sites / dial-sites /
// inbound-auth-facts) embed an unbounded fact list; the projection
// keeps the prefix and records the dropped count so a prefix is never
// read as a closed enumeration.
func TestLaneExposureFactsDataBounded(t *testing.T) {
	facts := make([]domain.ExposureFact, lanePayloadMaxListItems+9)
	for i := range facts {
		facts[i] = domain.ExposureFact{
			CallSite:  domain.CallSite{File: "srv.go", Line: i, Function: "serve"},
			Direction: "inbound", Kind: "listener", Target: "net.Listen",
		}
	}
	data, dropped := laneExposureFactsData(facts)
	if dropped != 9 || data["count"] != len(facts) || data["facts_dropped"] != 9 {
		t.Fatalf("count/dropped wrong: %+v", data)
	}
	if note := laneListBoundNote("facts", len(facts)-dropped, len(facts)); note == "" {
		t.Fatal("bound not named on the observation limitations")
	}
	shown, ok := data["facts"].([]domain.ExposureFact)
	if !ok || len(shown) != lanePayloadMaxListItems {
		t.Fatalf("facts prefix %v", data["facts"])
	}
	// Small lists stay verbatim with no dropped marker and no note.
	small, smallDropped := laneExposureFactsData(facts[:3])
	if smallDropped != 0 || small["count"] != 3 {
		t.Fatalf("small count %v", small["count"])
	}
	if _, has := small["facts_dropped"]; has {
		t.Fatal("facts_dropped on an unbounded-below list")
	}
	if laneListBoundNote("facts", 3, 3) != "" {
		t.Fatal("bound note emitted for a full list")
	}
}

// A snapshot payload's release module graph is prefix-bounded: the
// artifact channel can resolve thousands of modules, and the record
// stays under the cap with the full count recorded.
func TestLaneSnapshotViewBoundsReleaseModules(t *testing.T) {
	snap := domain.ProductSnapshot{
		Repository: "/repo", Commit: strings.Repeat("0", 40),
		GOOS: "linux", GOARCH: "amd64",
	}
	for range lanePayloadMaxListItems * 3 {
		snap.ReleaseModules = append(snap.ReleaseModules, domain.ReleaseModule{
			Path: "example.com/m" + strings.Repeat("x", 40), Version: "v1.0.0",
		})
	}
	v := laneSnapshotViewOf(snap)
	if len(v.ReleaseModules) != lanePayloadMaxListItems ||
		v.ReleaseModulesTotal != len(snap.ReleaseModules) {
		t.Fatalf("release modules %d/%d", len(v.ReleaseModules), v.ReleaseModulesTotal)
	}
	if payloadBytes(t, v) > maxObservationPayloadBytes {
		t.Fatal("snapshot payload exceeds cap")
	}
	// A snapshot without the artifact channel keeps the legacy shape:
	// no release_modules_total member.
	plain := laneSnapshotViewOf(domain.ProductSnapshot{Repository: "/repo"})
	raw, _ := json.Marshal(plain)
	if strings.Contains(string(raw), "release_modules_total") {
		t.Fatalf("legacy snapshot gained a member: %s", raw)
	}
}

// ---- Authoritative symbol-proof payload externalization ----
//
// A complete symbol-unreachability proof can exceed the display cap
// (a real run recorded a 293 KB result): the persisted observation
// then carries only a bounded envelope plus the hash-and-size pin of
// a content-addressed sidecar — never a prefix presented as the
// proof — and the authority route rehydrates the complete typed
// result before VerifyDecision. These tests pin the contract.

// oversizedSymbolData builds a closed (or open) symbol-unreachability
// proof whose encoded payload exceeds want bytes: Subjects carry the
// declared pair, while boundaries hold the recorded scope exclusions —
// the member the primitive uses for scope prose — padded to size.
// Complete=false keeps every gate open through Limitations, so the
// same builder covers the semantically open case.
func oversizedSymbolData(t *testing.T, want int, closed bool) evidencetools.SymbolUnreachabilityData {
	t.Helper()
	res := completeSymbolResult([]FactUsageSubject{{Module: testModule, Package: testPackage, Symbol: "Sink"}})
	res.Complete = false
	if closed {
		res.Complete = true
	} else {
		res.Limitations = []string{"dependency caller inventory is open"}
	}
	for i := 0; ; i++ {
		res.Boundaries = append(res.Boundaries,
			fmt.Sprintf("boundary %04d: %s", i, strings.Repeat("x", 1024)))
		b, err := json.Marshal(evidencetools.SymbolUnreachabilityData{Result: res})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > want {
			break
		}
	}
	return evidencetools.SymbolUnreachabilityData{Result: res}
}

// Step 1: a complete typed proof larger than 1 MiB encodes and decodes
// losslessly — the payload itself imposes no size bound; only the
// persisted wire representation does.
func TestSymbolUnreachabilityDataLargeRoundTrip(t *testing.T) {
	data := oversizedSymbolData(t, 1024*1024, true)
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 1024*1024 {
		t.Fatalf("synthetic payload %d bytes, want >1MiB", len(raw))
	}
	var back evidencetools.SymbolUnreachabilityData
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if !reflect.DeepEqual(back, data) {
		t.Fatal("typed proof did not round-trip losslessly")
	}
	if !back.Result.Complete || len(back.Result.ProductReferences) != 0 {
		t.Fatalf("decoded proof lost its closed shape: %+v", back.Result)
	}
}

// symbolProofLane builds the persisted-lane shape the deterministic
// lane produces for a symbol-unreachability call: the wire observation
// (payload normalized through the same JSON decode the client returns)
// plus a session-audit clone — distinct objects, like the production
// path where the session's audit clone never shares the caller's
// pointer.
func symbolProofLane(t *testing.T, o *evidencetools.Observation) *LaneResult {
	t.Helper()
	lane := decisionLane(domain.ClaimTrue)
	lane.DefectSemantics = &domain.DefectSemanticsContract{
		Mode:     domain.DefectSemanticsDefectiveCheck,
		RecordID: "GO-TEST-SYMBOL-PROOF",
		Check:    domain.SymbolRef{Package: testPackage, Symbol: "Sink"},
	}
	// The wire copy is a decoded map payload: marshal then unmarshal so
	// this fixture's Data marshals byte-identically to the audit
	// clone's, exactly like a real session call.
	raw, err := json.Marshal(o.Data)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &o.Data); err != nil {
		t.Fatal(err)
	}
	lane.Observations = []*evidencetools.Observation{o}
	lane.CanonicalByObs = map[string]string{}
	lane.ArtifactByObs = map[string]ArtifactRef{}
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var clone evidencetools.Observation
	if err := json.Unmarshal(b, &clone); err != nil {
		t.Fatal(err)
	}
	lane.Records = []evidencetools.AuditRecord{{
		Tool:        evidencetools.SymbolUnreachabilityTool,
		Args:        json.RawMessage(`{"module":"` + testModule + `","subjects":[{"package":"` + testPackage + `","symbol":"Sink"}]}`),
		Observation: &clone,
		RecordTime:  time.Now().UTC(),
	}}
	return lane
}

// symbolProofTrace builds the LaneSymbolProof wrapper
// decideLaneSymbolProof consumes: one request bound to the record's
// declared arguments and the wire observation.
func symbolProofTrace(lane *LaneResult, o *evidencetools.Observation) *LaneSymbolProof {
	trace := &VerificationTrace{
		Complete: true,
		Requests: []VerificationRequest{{
			ID: "lane-symbol-01", Tool: evidencetools.SymbolUnreachabilityTool,
			Arguments:   lane.Records[0].Args,
			Purpose:     "bounded deterministic unreachability proof",
			ConditionID: "declared-symbol-unreachable",
		}},
		Observations: []*evidencetools.Observation{o},
	}
	return &LaneSymbolProof{Trace: trace, Audit: lane.Records}
}

// An oversized authoritative proof persists externalized, not
// truncated: the wire observation and the audit copy carry the same
func TestPersistExternalizesAuthoritativeSymbolPayload(t *testing.T) {
	data := oversizedSymbolData(t, 1024*1024, true)
	// persist hashes the decoded-map payload: normalize through the
	// same JSON round-trip the wire applies, then digest those bytes.
	typed, _ := json.Marshal(data)
	var wireData any
	if err := json.Unmarshal(typed, &wireData); err != nil {
		t.Fatal(err)
	}
	fullBytes, _ := json.Marshal(wireData)
	fullSum := sha256.Sum256(fullBytes)

	symObs := decisionObservation(evidencetools.SymbolUnreachabilityTool, data)
	symObs.ID = "OBS-0001"
	lane := symbolProofLane(t, symObs)

	// Non-authoritative control: same persist pass, plain oversized
	// payload — truncation semantics must not change.
	big := strings.Repeat("x", maxObservationPayloadBytes*2)
	bigObs := &evidencetools.Observation{
		ID: "OBS-0002", Tool: "listen-sites", Fact: "f", Scope: "s",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		Data:         map[string]any{"blob": big},
	}
	bigFull, _ := json.Marshal(bigObs.Data)
	bigSum := sha256.Sum256(bigFull)
	lane.Observations = append(lane.Observations, bigObs)
	lane.Records = append(lane.Records, evidencetools.AuditRecord{
		Tool: "listen-sites", Args: json.RawMessage(`{}`), Observation: bigObs,
		RecordTime: time.Now().UTC(),
	})

	dir := t.TempDir()
	if err := lane.persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// The wire observation is a bounded envelope + reference.
	if symObs.PayloadRef == nil {
		t.Fatal("authoritative observation carries no payload_ref")
	}
	ref := symObs.PayloadRef
	if ref.SHA256 != hex.EncodeToString(fullSum[:]) ||
		ref.SizeBytes != int64(len(fullBytes)) ||
		ref.Selector != payloadSidecarSelector {
		t.Fatalf("payload_ref = %+v", ref)
	}
	if ref.Path != observationPayloadSidecarPath(ref.SHA256) {
		t.Fatalf("payload_ref path %q is not content-addressed", ref.Path)
	}
	env, ok := symObs.Data.(map[string]any)
	if !ok || env["externalized_payload"] != true {
		t.Fatalf("data is not the externalization envelope: %v", symObs.Data)
	}
	if _, present := env["stored_payload_json"]; present {
		t.Fatal("envelope stores a payload prefix — a prefix is never the proof")
	}
	if env["full_payload_sha256"] != ref.SHA256 {
		t.Fatalf("envelope digest disagrees with payload_ref: %v", env)
	}
	sz, ok := env["full_payload_size_bytes"].(int)
	if !ok || int64(sz) != ref.SizeBytes {
		t.Fatalf("envelope size disagrees with payload_ref: %v", env)
	}
	if symObs.Completeness != evidencetools.CompletenessComplete {
		t.Fatalf("completeness %s — a hash-bound externalized payload is not a truncation", symObs.Completeness)
	}
	if symObs.ScopeDetails.Limits == nil ||
		symObs.ScopeDetails.Limits.FullPayloadSHA256 != ref.SHA256 ||
		symObs.ScopeDetails.Limits.FullPayloadSizeBytes != ref.SizeBytes ||
		symObs.ScopeDetails.Limits.OutputTruncated {
		t.Fatalf("scope limits = %+v", symObs.ScopeDetails.Limits)
	}

	// The audit copy carries the identical envelope + pin (the session
	// clone is a distinct object — persistence covered both).
	recObs := lane.Records[0].Observation
	if recObs.PayloadRef == nil || *recObs.PayloadRef != *ref {
		t.Fatalf("audit payload_ref = %+v", recObs.PayloadRef)
	}
	if !bindDigests(recObs, symObs) {
		t.Fatal("audit envelope does not match the wire envelope")
	}

	// The sidecar is the complete payload, byte-exact to the pin.
	sidecar, err := os.ReadFile(filepath.Join(dir, ref.Path))
	if err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}
	if sum := sha256.Sum256(sidecar); hex.EncodeToString(sum[:]) != ref.SHA256 {
		t.Fatal("sidecar bytes do not hash to the recorded pin")
	}
	var decoded evidencetools.SymbolUnreachabilityData
	if err := json.Unmarshal(sidecar, &decoded); err != nil {
		t.Fatalf("sidecar undecodable: %v", err)
	}
	if !reflect.DeepEqual(decoded, data) {
		t.Fatal("sidecar payload differs from the produced proof")
	}

	// The persisted artifact and digest pins describe the envelope,
	// never the full payload.
	canonical, _ := json.MarshalIndent(symObs, "", "  ")
	if int64(len(canonical)) >= int64(len(fullBytes)) {
		t.Fatal("persisted canonical observation is not bounded")
	}
	csum := sha256.Sum256(canonical)
	if lane.CanonicalByObs["OBS-0001"] != hex.EncodeToString(csum[:]) {
		t.Fatal("canonical digest does not pin the envelope bytes")
	}
	artBytes, err := os.ReadFile(filepath.Join(dir, "artifacts", "obs-0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	asum := sha256.Sum256(artBytes)
	if lane.ArtifactByObs["OBS-0001"].SHA256 != hex.EncodeToString(asum[:]) {
		t.Fatal("artifact pin does not cover the envelope file bytes")
	}
	if lane.ArtifactByObs["OBS-0001"].SHA256 == ref.SHA256 {
		t.Fatal("artifact pin and payload pin conflate two different byte streams")
	}

	// observations.jsonl stays bounded and the row carries the
	// reference, never the payload.
	rawLedger, err := os.ReadFile(filepath.Join(dir, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rawLedger) > maxObservationPayloadBytes*2 {
		t.Fatalf("observations.jsonl unbounded: %d bytes", len(rawLedger))
	}
	var row struct {
		Observation *evidencetools.Observation `json:"observation"`
	}
	dec := json.NewDecoder(bytes.NewReader(rawLedger))
	rows := 0
	for dec.Decode(&row) == nil {
		rows++
		if row.Observation != nil && row.Observation.ID == "OBS-0001" && row.Observation.PayloadRef == nil {
			t.Fatal("ledger row for the authoritative observation lost its payload_ref")
		}
		row.Observation = nil
	}
	if rows != 2 {
		t.Fatalf("ledger rows = %d, want 2", rows)
	}

	// The non-authoritative control truncated exactly as before:
	// prefix envelope, PARTIAL downgrade, no payload_ref, no sidecar.
	m, ok := bigObs.Data.(map[string]any)
	if !ok || m["truncated_payload"] != true {
		t.Fatalf("non-authoritative payload not truncated: %v", bigObs.Data)
	}
	if m["full_payload_sha256"] != hex.EncodeToString(bigSum[:]) {
		t.Fatal("non-authoritative truncation lost its full-payload pin")
	}
	if bigObs.PayloadRef != nil {
		t.Fatal("non-authoritative observation gained a payload_ref")
	}
	if bigObs.Completeness != evidencetools.CompletenessPartial {
		t.Fatalf("non-authoritative completeness %s, want PARTIAL", bigObs.Completeness)
	}
	if _, err := os.Stat(filepath.Join(dir, observationPayloadSidecarPath(hex.EncodeToString(bigSum[:])))); !os.IsNotExist(err) {
		t.Fatal("non-authoritative payload gained a sidecar")
	}
}

// A rehydrated complete oversized proof still closes through the
// authority route: NO_EXPLOIT_PATH_FOUND with the declared-symbol
// falsifier and a VERIFIED negative verification — the persisted
// envelope is never what the decision consumes.
func TestSymbolProofOversizedRehydratedCloses(t *testing.T) {
	data := oversizedSymbolData(t, 1024*1024, true)
	o := decisionObservation(evidencetools.SymbolUnreachabilityTool, data)
	o.ID = "OBS-0001"
	lane := symbolProofLane(t, o)
	dir := t.TempDir()
	if err := lane.persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}
	proof := decideLaneSymbolProof(context.Background(), lane, symbolProofTrace(lane, o))
	if proof.Decision.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("decision = %+v (limitations %v)", proof.Decision, proof.Decision.Limitations)
	}
	if proof.Decision.Falsifier != domain.FalsifierDeclaredSymbolUnreached ||
		proof.Decision.NegativeVerification == nil ||
		proof.Decision.NegativeVerification.Status != domain.NegativeVerified ||
		proof.Decision.Coverage != "COMPLETE" {
		t.Fatalf("decision shape = %+v", proof.Decision)
	}
	// The rehydrated audit payload is the complete typed result the
	// authority consumed — not the envelope and never stored_payload_json.
	var d evidencetools.SymbolUnreachabilityData
	if !decodeData(proof.Audit[0].Observation.Data, &d) || !d.Result.Complete ||
		len(d.Result.Subjects) != 1 || d.Result.Subjects[0].Symbol != "Sink" {
		t.Fatalf("authority did not consume the complete typed proof: %T", proof.Audit[0].Observation.Data)
	}
	if proof.Trace.Observations[0].PayloadRef != nil {
		t.Fatal("authority trace copy still carries the wire envelope")
	}
	// The digest-pinned wire copy stays an envelope: persistence pins
	// remain verifiable against it.
	if o.PayloadRef == nil {
		t.Fatal("persisted wire observation lost its payload_ref")
	}
	if d2, err := canonicalObservationDigest(o); err != nil || d2 != lane.CanonicalByObs[o.ID] {
		t.Fatal("rehydration mutated the pinned wire observation")
	}
}

// The same oversized proof with a semantically open result — a
// named gap in its own record — stays INCONCLUSIVE: persistence
// preserves the result; it never buys closure.
func TestSymbolProofOversizedOpenStaysInconclusive(t *testing.T) {
	data := oversizedSymbolData(t, 1024*1024, false)
	o := decisionObservation(evidencetools.SymbolUnreachabilityTool, data)
	o.ID = "OBS-0001"
	o.Completeness = evidencetools.CompletenessPartial
	o.Fact = "symbol-unreachability is undetermined: dependency caller inventory is open"
	lane := symbolProofLane(t, o)
	dir := t.TempDir()
	if err := lane.persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}
	proof := decideLaneSymbolProof(context.Background(), lane, symbolProofTrace(lane, o))
	requireInconclusive(t, proof.Decision)
	if !strings.Contains(strings.Join(append([]string{proof.Decision.Reason}, proof.Decision.Limitations...), "; "),
		"dependency caller inventory is open") {
		t.Fatalf("open gap not named: %+v", proof.Decision)
	}
}

// Fail-closed persistence: a missing, altered or forged sidecar can
// never produce a terminal negative — every variant ends INCONCLUSIVE.
func TestSymbolProofSidecarTamperFailsClosed(t *testing.T) {
	mkLane := func(t *testing.T) (*LaneResult, *evidencetools.Observation, string) {
		data := oversizedSymbolData(t, 1024*1024, true)
		o := decisionObservation(evidencetools.SymbolUnreachabilityTool, data)
		o.ID = "OBS-0001"
		lane := symbolProofLane(t, o)
		dir := t.TempDir()
		if err := lane.persist(dir); err != nil {
			t.Fatalf("persist: %v", err)
		}
		return lane, o, dir
	}

	t.Run("missing sidecar", func(t *testing.T) {
		lane, o, dir := mkLane(t)
		if err := os.Remove(filepath.Join(dir, o.PayloadRef.Path)); err != nil {
			t.Fatal(err)
		}
		proof := decideLaneSymbolProof(context.Background(), lane, symbolProofTrace(lane, o))
		requireInconclusive(t, proof.Decision)
	})

	t.Run("altered sidecar", func(t *testing.T) {
		lane, o, dir := mkLane(t)
		if err := os.WriteFile(filepath.Join(dir, o.PayloadRef.Path), []byte(`{"result":{"complete":true}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		proof := decideLaneSymbolProof(context.Background(), lane, symbolProofTrace(lane, o))
		requireInconclusive(t, proof.Decision)
	})

	t.Run("undecodable sidecar under a forged pin", func(t *testing.T) {
		lane, o, dir := mkLane(t)
		// A forged reference whose digest honestly names garbage must
		// still fail at decode — and the trace/audit divergence the
		// forgery introduces independently refuses the bind.
		garbage := []byte("not-json-payload")
		sum := sha256.Sum256(garbage)
		forged := hex.EncodeToString(sum[:])
		path := filepath.Join(dir, observationPayloadSidecarPath(forged))
		if err := os.WriteFile(path, garbage, 0o644); err != nil {
			t.Fatal(err)
		}
		// never consumes the caller-constructed trace alone.
		lane.Records[0].Observation.PayloadRef = &evidencetools.ObservationPayloadRef{
			Path: observationPayloadSidecarPath(forged), SHA256: forged,
			SizeBytes: int64(len(garbage)), Selector: payloadSidecarSelector,
		}
		proof := decideLaneSymbolProof(context.Background(), lane, symbolProofTrace(lane, o))
		requireInconclusive(t, proof.Decision)
	})
}

// Metadata mutations must fail even when the referenced sidecar itself is valid.
func TestSymbolProofSidecarBindingFailsClosed(t *testing.T) {
	mutations := []struct {
		name       string
		change     func(*evidencetools.Observation)
		limitation string
	}{
		{"selector", func(o *evidencetools.Observation) { o.PayloadRef.Selector = "other payload" }, "selector"},
		{"envelope digest", func(o *evidencetools.Observation) { o.Data.(map[string]any)["full_payload_sha256"] = "wrong" }, "envelope sha256"},
		{"envelope size", func(o *evidencetools.Observation) { o.Data.(map[string]any)["full_payload_size_bytes"] = 1 }, "envelope size"},
		{"scope digest", func(o *evidencetools.Observation) { o.ScopeDetails.Limits.FullPayloadSHA256 = "wrong" }, "scope limits"},
		{"scope size", func(o *evidencetools.Observation) { o.ScopeDetails.Limits.FullPayloadSizeBytes = 1 }, "scope limits"},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			o := decisionObservation(evidencetools.SymbolUnreachabilityTool, oversizedSymbolData(t, 1024*1024, true))
			o.ID = "OBS-0001"
			lane := symbolProofLane(t, o)
			if err := lane.persist(t.TempDir()); err != nil {
				t.Fatal(err)
			}
			// Mutate the audit authority copy, rather than relying on a
			// mismatched trace to reject the proof before rehydration.
			tc.change(lane.Records[0].Observation)
			proof := decideLaneSymbolProof(context.Background(), lane, symbolProofTrace(lane, o))
			requireInconclusive(t, proof.Decision)
			if !strings.Contains(strings.Join(proof.Decision.Limitations, "; "), tc.limitation) {
				t.Fatalf("missing %q decision limitation: %v", tc.limitation, proof.Decision.Limitations)
			}
		})
	}
}

func TestPackageInventoryPayloadPreservesFullStream(t *testing.T) {
	for _, tool := range []string{"package-inventory", "verify_code_absence"} {
		t.Run(tool, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "artifacts")
			if err := os.Mkdir(dir, 0o755); err != nil { t.Fatal(err) }
			full := strings.Repeat("untrimmed package stdout\n", maxObservationPayloadBytes)
			o := &evidencetools.Observation{Tool:tool, ToolStatus:evidencetools.StatusOK, Completeness:evidencetools.CompletenessComplete, Data:map[string]any{"raw_stream":full}}
			if err := capObservationPayload(o, dir); err != nil { t.Fatal(err) }
			if o.PayloadRef == nil || o.Completeness != evidencetools.CompletenessComplete { t.Fatalf("full inventory lost: %+v", o) }
			bounded, _ := json.Marshal(o.Data)
			if len(bounded) >= maxObservationPayloadBytes { t.Fatal("display projection is unbounded") }
			data, err := loadExternalizedPayload(root, o)
			if err != nil { t.Fatal(err) }
			if data.(map[string]any)["raw_stream"] != full { t.Fatal("full raw stream did not survive persistence") }
		})
	}
}

func TestConfigWriterObservationPreservesFullPayload(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root,"artifacts")
	if err := os.Mkdir(dir,0o755); err != nil { t.Fatal(err) }
	full := strings.Repeat("source/object/build evidence\n",maxObservationPayloadBytes)
	o := &evidencetools.Observation{Tool:"field_assignments", ToolStatus:evidencetools.StatusOK, Completeness:evidencetools.CompletenessPartial, Data:map[string]any{"writers":map[string]any{"inventory_raw":full}}}
	if err := capObservationPayload(o,dir); err != nil { t.Fatal(err) }
	if o.PayloadRef == nil || o.Completeness != evidencetools.CompletenessPartial { t.Fatalf("observation lost or promoted: %+v",o) }
	bounded, err := json.Marshal(o.Data)
	if err != nil || len(bounded) >= maxObservationPayloadBytes { t.Fatalf("unbounded display: %d %v",len(bounded),err) }
	data, err := loadExternalizedPayload(root,o)
	if err != nil { t.Fatal(err) }
	if data.(map[string]any)["writers"].(map[string]any)["inventory_raw"] != full { t.Fatal("configuration payload truncated") }
	path := filepath.Join(root,o.PayloadRef.Path)
	if err := os.WriteFile(path,[]byte("tampered"),0o644); err != nil { t.Fatal(err) }
	if _, err := loadExternalizedPayload(root,o); err == nil { t.Fatal("tampered payload accepted") }
	if err := os.Remove(path); err != nil { t.Fatal(err) }
	if _, err := loadExternalizedPayload(root,o); err == nil { t.Fatal("missing payload accepted") }
}
