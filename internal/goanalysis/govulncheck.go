// Package goanalysis wraps Go-specific analysis tools. govulncheck is the
// primary reachability source per the governing spec; everything else is a
// targeted gap-filler.
package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/toolaudit"
	"github.com/davniy/izyan/internal/vulnerability"
)

// Runner executes govulncheck and returns the raw -json stream plus the
// package pattern that actually produced it ("./...", "./cmd/...", or the
// binary path) — callers record the real scope, a fallback narrows it.
type Runner interface {
	RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) (raw []byte, pattern string, err error)
}

type ExecRunner struct {
	Bin string
	// Env carries the target toolchain (PATH/GOTOOLCHAIN) into the
	// govulncheck subprocess and, for source mode, the `go` it spawns.
	Env []string
	// DBRoot pins the local vulnerability database directory. Non-empty
	// is passed to govulncheck as `-db file://<abs>` — the binary honors
	// the -db flag only (GOVULNDB in Env is audit/provenance evidence,
	// not a govulncheck input). Empty keeps the binary's default
	// https://vuln.go.dev, preserving the non-strict network profile.
	DBRoot string
}

// resolveGovulnBin finds the govulncheck executable: PATH first, then the
// well-known `go install` destinations (GOBIN, GOPATH[0]/bin, ~/go/bin) —
// restricted environments routinely lack ~/go/bin on PATH.
func resolveGovulnBin(ctx context.Context) string {
	if p, err := exec.LookPath("govulncheck"); err == nil {
		return p
	}
	for _, key := range []string{"GOBIN", "GOPATH"} {
		out, err := exec.CommandContext(ctx, "go", "env", key).Output()
		if err != nil {
			continue
		}
		for _, d := range filepath.SplitList(strings.TrimSpace(string(out))) {
			if d == "" {
				continue
			}
			if key == "GOPATH" {
				d = filepath.Join(d, "bin")
			}
			if cand := filepath.Join(d, "govulncheck"); fileExists(cand) {
				return cand
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if cand := filepath.Join(home, "go", "bin", "govulncheck"); fileExists(cand) {
			return cand
		}
	}
	return "govulncheck" // unresolved — the exec error is recorded honestly
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// CachingRunner runs govulncheck once per (repo, build) — its output
// covers the whole vulnerability database, so a single run serves every
// advisory in a batch scan.
func CachingRunner(inner Runner) Runner { return &cachingRunner{inner: inner} }

type cachingRunner struct {
	inner Runner
	// The cache serves exactly one build: the first call captures its
	// repository directory and effective build context; a later call for a
	// different build is refused instead of receiving another build's output.
	// Kept single-build by design — no multi-key cache.
	mu       sync.Mutex
	bound    bool
	boundDir string
	boundCtx domain.BuildContext
	once     sync.Once
	out      []byte
	pattern  string
	err      error
}

// admit locks the cache to one (dir, build) pair before any cached value can
// be served.
func (r *cachingRunner) admit(dir string, build domain.ProductSnapshot) error {
	ctx := domain.EffectiveBuildContext(build)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.bound {
		r.bound, r.boundDir, r.boundCtx = true, dir, ctx
		return nil
	}
	if r.boundDir != dir {
		return fmt.Errorf("govulncheck cache: repository %q != %q: %w", dir, r.boundDir, domain.ErrBuildContextMismatch)
	}
	if err := r.boundCtx.Matches(ctx); err != nil {
		return fmt.Errorf("govulncheck cache: %w", err)
	}
	return nil
}

func (r *cachingRunner) RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, string, error) {
	if err := r.admit(dir, build); err != nil {
		return nil, "", err
	}
	r.once.Do(func() {
		r.out, r.pattern, r.err = r.inner.RunGovulncheck(ctx, dir, build)
	})
	return r.out, r.pattern, r.err
}

// DBInfo forwards the pinned database provenance when the inner runner
// supports it — a cached run otherwise loses the DB identity line.
func (r *cachingRunner) DBInfo(ctx context.Context) (string, error) {
	if informer, ok := r.inner.(DBInformer); ok {
		return informer.DBInfo(ctx)
	}
	return "", errors.New("inner runner does not report DB info")
}

// dbFileURL renders a local DB root as the file:// URL govulncheck's
// -db flag expects. Empty root yields ("", nil) — no flag is added.
func dbFileURL(root string) (string, error) {
	if root == "" {
		return "", nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: "file", Path: abs}).String(), nil
}

func (r ExecRunner) RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, string, error) {
	bin := r.Bin
	if bin == "" {
		bin = resolveGovulnBin(ctx)
	}
	// r.Env carries the target toolchain (PATH/GOTOOLCHAIN): govulncheck
	// source mode loads stdlib through the `go` it finds in PATH.
	extraEnv := r.Env
	var args []string
	if u, derr := dbFileURL(r.DBRoot); derr == nil && u != "" {
		// The -db flag is the only way govulncheck picks its database;
		// prepend it before the positional package pattern.
		args = append(args, "-db", u)
	}
	pattern := "./..."
	if build.BinaryPath != "" {
		// Binary mode reads the release artifact's embedded build info: the
		// real toolchain and module versions, not the source tree's claims.
		args = append(args, "-json", "-mode", "binary", build.BinaryPath)
		pattern = build.BinaryPath
	} else {
		args = append(args, "-json", "-mode", "source")
		if len(build.BuildTags) > 0 {
			args = append(args, "-tags", strings.Join(build.BuildTags, ","))
		}
		args = append(args, "./...")
	}
	// The policy env (target toolchain PATH/GOTOOLCHAIN) comes first, then
	// the snapshot's resolved build selection — one GOOS/GOARCH/CGO/
	// workspace/GOFLAGS set shared with package loading.
	env := make([]string, 0, len(extraEnv)+5)
	env = append(env, extraEnv...)
	env = append(env, domain.BuildEnv(build)...)
	stdout, stderr, err := toolaudit.Run(ctx, "govulncheck", "", dir, bin, env, args...)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 3 {
			// govulncheck exits with code 3 when vulnerabilities are found; stdout has the full JSON stream.
			return stdout, pattern, nil
		}
		// Fallback: if ./... failed (e.g. uncompilable optional subpackages/cgo),
		// try package patterns for main entrypoints if ./cmd exists. The
		// narrowed scope is reported via the pattern return value.
		if len(args) > 0 && args[len(args)-1] == "./..." {
			if st, serr := os.Stat(filepath.Join(dir, "cmd")); serr == nil && st.IsDir() {
				fbArgs := make([]string, len(args)-1)
				copy(fbArgs, args[:len(args)-1])
				fbArgs = append(fbArgs, "./cmd/...")
				fbStdout, fbStderr, fbErr := toolaudit.Run(ctx, "govulncheck", "", dir, bin, env, fbArgs...)
				if fbErr == nil {
					return fbStdout, "./cmd/...", nil
				}
				if errors.As(fbErr, &ee) && ee.ExitCode() == 3 {
					return fbStdout, "./cmd/...", nil
				}
				stderr = append(append(stderr, "\nfallback ./cmd/...: "...), fbStderr...)
			}
		}
		return stdout, pattern, fmt.Errorf("govulncheck: %w: %s", err, stderr)
	}
	return stdout, pattern, nil
}

// DBInformer is an optional Runner capability: it reports the local
// vulnerability database's identity/timestamp so a not-covered advisory can
// be explained ("DB snapshot older than the advisory").
type DBInformer interface {
	DBInfo(ctx context.Context) (string, error)
}

// DBInfo runs `govulncheck -version` and returns the vulndb lines.
func (r ExecRunner) DBInfo(ctx context.Context) (string, error) {
	bin := r.Bin
	if bin == "" {
		bin = resolveGovulnBin(ctx)
	}
	args := []string{"-version"}
	if u, derr := dbFileURL(r.DBRoot); derr == nil && u != "" {
		// -version reports the database it would scan against; without
		// -db the binary would describe https://vuln.go.dev instead.
		args = append(args, "-db", u)
	}
	out, _, err := toolaudit.Run(ctx, "govulncheck", "", "", bin, nil, args...)
	if err != nil {
		return "", err
	}
	var db []string
	for _, ln := range strings.Split(string(out), "\n") {
		low := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(low, "db:") || strings.HasPrefix(low, "db ") ||
			strings.Contains(low, "vulndb") || strings.Contains(low, "updated") {
			db = append(db, strings.TrimSpace(ln))
		}
	}
	if len(db) == 0 {
		return strings.TrimSpace(string(out)), nil
	}
	return strings.Join(db, "; "), nil
}

// Finding is the subset of the govulncheck -json finding message we use.
type Finding struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version"`
	Trace        []TraceFrame `json:"trace"`
}

type TraceFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position"`
}

// ProtocolVersion is the only govulncheck JSON protocol this parser
// accepts. A stream announcing anything else is not a measurement this
// analyzer understands.
const ProtocolVersion = "v1.0.0"

// ProtocolConfig is the stream's initial configuration message. It records
// what the binary actually ran, independent of what the caller requested.
type ProtocolConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name,omitempty"`
	ScannerVersion  string `json:"scanner_version,omitempty"`
	DB              string `json:"db,omitempty"`
	DBLastModified  string `json:"db_last_modified,omitempty"`
	GoVersion       string `json:"go_version,omitempty"`
	ScanLevel       string `json:"scan_level,omitempty"`
	ScanMode        string `json:"scan_mode,omitempty"`
}

// EmittedAdvisory is one advisory identity the run's stream emitted (an OSV
// document or a finding) together with the module/subject bindings that
// document declares. The entry is scoped to the document's own id: aliases
// are recorded in KnownOSVs only and never merge subjects across entries.
// Record is the stream document's identity; CollectGovulncheck replaces it
// with the exact pin it was invoked for so a projection can refuse
// conflicting bytes that claim the same id.
type EmittedAdvisory struct {
	Record   domain.RecordPin
	Subjects []domain.SymbolRef
	Modules  []string
}

// RecordProjection is the exact-record view of one completed run's output.
// It is a product measurement projected against one record; it carries no
// claims, severity, closure or assessment authority.
type RecordProjection struct {
	Coverage domain.GovulncheckCoverage
	Findings []Finding
}

type Result struct {
	Findings []Finding
	// KnownOSVs is the set of advisory ids (and aliases) present in the
	// vulnerability database govulncheck used. An advisory absent here was
	// never evaluated — silence is not evidence of no path. It is metadata:
	// an alias hit never establishes a record's coverage.
	KnownOSVs map[string]bool
	// Config is the stream's parsed initial configuration message.
	Config ProtocolConfig
	// EmittedAdvisories records, per emitted advisory identity, the
	// document's own id and the modules/subjects it declares. It is the
	// only source ProjectRecord projects.
	EmittedAdvisories []EmittedAdvisory
	// ScopeComplete reports whether the run measured the whole analyzed
	// build. Parse leaves it false (unknown); CollectGovulncheck sets it
	// from the pattern that actually produced the stream.
	ScopeComplete bool
}

// Covers reports whether the vulnerability's id or one of its aliases was in
// govulncheck's DB. It is presentation metadata for non-assessment consumers:
// an alias hit says the database mentioned the identity, never that this
// record's document was evaluated. Assessment evidence must use
// ProjectRecord, which matches the record's own id only.
func (r Result) Covers(v domain.Vulnerability) bool {
	if r.KnownOSVs == nil {
		return false
	}
	if r.KnownOSVs[v.ID] {
		return true
	}
	for _, a := range v.Aliases {
		if r.KnownOSVs[a] {
			return true
		}
	}
	return false
}

// Parse decodes the govulncheck -json stream. Framing is strict: the stream
// must start with a config message announcing a supported protocol version
// and decode cleanly through EOF. A valid prefix followed by a malformed or
// trailing value is an error, never a completed measurement — a partially
// written stream from a failed process stays failed.
func Parse(raw []byte) (Result, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Result{}, errors.New("govulncheck stream is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	res := Result{
		KnownOSVs: map[string]bool{},
	}
	sawConfig := false
	for {
		var msg map[string]json.RawMessage
		err := dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("decode govulncheck stream: %w", err)
		}
		if msg == nil {
			return Result{}, errors.New("govulncheck stream message is not a JSON object")
		}
		if !sawConfig {
			cfgRaw, ok := msg["config"]
			if !ok || len(msg) != 1 {
				return Result{}, errors.New("govulncheck stream does not start with a config message")
			}
			cfg, err := decodeProtocolConfig(cfgRaw)
			if err != nil {
				return Result{}, err
			}
			res.Config = cfg
			sawConfig = true
			continue
		}
		if len(msg) != 1 {
			return Result{}, errors.New("govulncheck stream message must carry exactly one message type")
		}
		switch {
		case msg["config"] != nil:
			return Result{}, errors.New("govulncheck stream repeats the initial config message")
		case msg["osv"] != nil:
			doc, err := decodeOSVDocument(msg["osv"])
			if err != nil {
				return Result{}, err
			}
			registerOSV(&res, doc)
		case msg["finding"] != nil:
			finding, err := decodeFinding(msg["finding"])
			if err != nil {
				return Result{}, err
			}
			res.Findings = append(res.Findings, finding)
			res.KnownOSVs[finding.OSV] = true
			registerFindingAdvisory(&res, finding.OSV)
		case msg["progress"] != nil:
			var progress map[string]json.RawMessage
			if err := json.Unmarshal(msg["progress"], &progress); err != nil {
				return Result{}, fmt.Errorf("decode govulncheck progress: %w", err)
			}
			if progress == nil {
				return Result{}, errors.New("govulncheck progress message is not a JSON object")
			}
		case msg["SBOM"] != nil || msg["sbom"] != nil:
			// govulncheck >= v1.9 emits its module SBOM as a protocol
			// message. The analyzer does not consume it, but a valid stream
			// carrying it is still a complete measurement.
			rawSBOM := msg["SBOM"]
			if rawSBOM == nil {
				rawSBOM = msg["sbom"]
			}
			var sbom map[string]json.RawMessage
			if err := json.Unmarshal(rawSBOM, &sbom); err != nil {
				return Result{}, fmt.Errorf("decode govulncheck SBOM: %w", err)
			}
			if sbom == nil {
				return Result{}, errors.New("govulncheck SBOM message is not a JSON object")
			}
		default:
			return Result{}, errors.New("govulncheck stream carries an unknown message type")
		}
	}
	if !sawConfig {
		return Result{}, errors.New("govulncheck stream ended before its config message")
	}
	return res, nil
}

func decodeProtocolConfig(raw json.RawMessage) (ProtocolConfig, error) {
	var cfg ProtocolConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ProtocolConfig{}, fmt.Errorf("decode govulncheck config: %w", err)
	}
	if cfg.ProtocolVersion != ProtocolVersion {
		return ProtocolConfig{}, fmt.Errorf(
			"unsupported govulncheck protocol version %q (want %q)", cfg.ProtocolVersion, ProtocolVersion)
	}
	return cfg, nil
}

// osvDocument is the subset of one govulncheck OSV message we consume:
// advisory identity plus the Go imports/symbols its affected[] entries
// declare.
type osvDocument struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
			Packages []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"packages"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// declaredSymbols returns the package/symbol pairs the advisory document
// declares. A module-level entry declares no symbols; its absence of symbols
// is recorded as such, never invented.
func (d osvDocument) declaredSymbols() []domain.SymbolRef {
	var out []domain.SymbolRef
	add := func(path string, symbols []string) {
		for _, sym := range symbols {
			ref := domain.SymbolRef{Package: path, Symbol: sym}
			if !slices.Contains(out, ref) {
				out = append(out, ref)
			}
		}
	}
	for _, affected := range d.Affected {
		for _, imp := range affected.EcosystemSpecific.Imports {
			add(imp.Path, imp.Symbols)
		}
		for _, pkg := range affected.EcosystemSpecific.Packages {
			if strings.TrimSpace(pkg.Path) == "" {
				continue
			}
			add(pkg.Path, pkg.Symbols)
		}
	}
	return out
}

// declaredModules returns the module paths the advisory document's affected[]
// entries name. An unnamed entry declares no module and contributes nothing.
func (d osvDocument) declaredModules() []string {
	var out []string
	for _, affected := range d.Affected {
		name := strings.TrimSpace(affected.Package.Name)
		if name == "" || slices.Contains(out, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

func decodeOSVDocument(raw json.RawMessage) (osvDocument, error) {
	var doc osvDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return osvDocument{}, fmt.Errorf("decode govulncheck OSV document: %w", err)
	}
	if strings.TrimSpace(doc.ID) == "" {
		return osvDocument{}, errors.New("govulncheck OSV document lacks an advisory id")
	}
	for _, affected := range doc.Affected {
		for _, imp := range affected.EcosystemSpecific.Imports {
			if strings.TrimSpace(imp.Path) == "" {
				return osvDocument{}, errors.New("govulncheck OSV import entry lacks a package path")
			}
		}
	}
	return doc, nil
}

// registerOSV records one emitted OSV document under its own id. Aliases are
// database identity metadata only: they make the id "known" but never copy
// the document's subjects or modules onto another identity.
func registerOSV(res *Result, doc osvDocument) {
	for _, id := range append([]string{doc.ID}, doc.Aliases...) {
		if strings.TrimSpace(id) != "" {
			res.KnownOSVs[id] = true
		}
	}
	registerEmittedAdvisory(res, doc.ID, doc.declaredSymbols(), doc.declaredModules())
}

// registerFindingAdvisory records a finding's advisory id as an emitted
// identity. A finding without a preceding OSV document still establishes that
// this exact id was evaluated, but contributes no declared subjects.
func registerFindingAdvisory(res *Result, id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	registerEmittedAdvisory(res, id, nil, nil)
}

// registerEmittedAdvisory merges repeated mentions of the same document id.
// The emitted entry keeps the document's own id; no alias ever selects it.
func registerEmittedAdvisory(res *Result, id string, symbols []domain.SymbolRef, modules []string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	for i := range res.EmittedAdvisories {
		e := &res.EmittedAdvisories[i]
		if e.Record.RecordID != id {
			continue
		}
		for _, ref := range symbols {
			if !slices.Contains(e.Subjects, ref) {
				e.Subjects = append(e.Subjects, ref)
			}
		}
		for _, module := range modules {
			if !slices.Contains(e.Modules, module) {
				e.Modules = append(e.Modules, module)
			}
		}
		return
	}
	res.EmittedAdvisories = append(res.EmittedAdvisories, EmittedAdvisory{
		Record:   domain.RecordPin{RecordID: id},
		Subjects: symbols,
		Modules:  modules,
	})
}

func decodeFinding(raw json.RawMessage) (Finding, error) {
	var finding Finding
	if err := json.Unmarshal(raw, &finding); err != nil {
		return Finding{}, fmt.Errorf("decode govulncheck finding: %w", err)
	}
	if strings.TrimSpace(finding.OSV) == "" {
		return Finding{}, errors.New("govulncheck finding lacks an advisory id")
	}
	if len(finding.Trace) == 0 {
		return Finding{}, errors.New("govulncheck finding has no trace")
	}
	for _, frame := range finding.Trace {
		if strings.TrimSpace(frame.Module) == "" &&
			strings.TrimSpace(frame.Package) == "" &&
			strings.TrimSpace(frame.Function) == "" {
			return Finding{}, errors.New("govulncheck finding trace frame carries no module, package, or function")
		}
	}
	return finding, nil
}

// ProjectRecord projects the run's emitted output against one exact loaded
// record.
//
// Matching is by the record's own identity and pin only: an emitted document
// must carry the record's own id, and a run bound to one digest is rejected
// for a record claiming the same id from different bytes. Aliases, shared CVE
// keys, related edges and feed subject merges never select an entry. Projected
// subjects and modules are intersected with the record's own declarations, so
// no other record's coverage, symbols or findings can be inherited.
//
// The projection is a product measurement of this record, not an assessment:
// it carries no claims, severity, closure or exploitability authority.
func (r Result) ProjectRecord(record vulnerability.LoadedRecord) (RecordProjection, error) {
	v := record.Vuln
	if v == nil {
		return RecordProjection{}, errors.New(
			"govulncheck record projection: loaded record has no decoded vulnerability")
	}
	pin := record.Pin
	recordID := strings.TrimSpace(pin.RecordID)
	if recordID == "" {
		recordID = strings.TrimSpace(v.ID)
	}
	if recordID == "" {
		return RecordProjection{}, errors.New("govulncheck record projection: record has no id")
	}
	if pin.RecordID != "" && v.ID != "" && pin.RecordID != v.ID {
		return RecordProjection{}, fmt.Errorf(
			"govulncheck record projection: pin names %q but the decoded record is %q", pin.RecordID, v.ID)
	}
	pinned := pin.DocumentDigest != ""
	if pinned {
		if err := pin.Validate(); err != nil {
			return RecordProjection{}, fmt.Errorf("govulncheck record projection: %w", err)
		}
	} else if pin.SourceLocator != "" {
		return RecordProjection{}, errors.New(
			"govulncheck record projection: record pin carries a source locator without a document digest")
	}

	var emitted *EmittedAdvisory
	for i := range r.EmittedAdvisories {
		e := &r.EmittedAdvisories[i]
		if e.Record.RecordID != recordID {
			continue
		}
		if e.Record.DocumentDigest != "" {
			if !pinned {
				return RecordProjection{}, fmt.Errorf(
					"govulncheck record projection: run is bound to pinned record %s (%s) but %s is unpinned",
					e.Record.RecordID, e.Record.DocumentDigest, recordID)
			}
			if e.Record.DocumentDigest != pin.DocumentDigest {
				return RecordProjection{}, fmt.Errorf(
					"govulncheck record projection: emitted document for %s is pinned as %s, not the assessed bytes %s",
					recordID, e.Record.DocumentDigest, pin.DocumentDigest)
			}
		}
		emitted = e
		break
	}

	ownSubjects := recordSubjects(v)
	coverage := domain.GovulncheckCoverage{
		AdvisoryID:    recordID,
		Advisory:      domain.GovulncheckCoverageNotInDB,
		ScopeComplete: r.ScopeComplete,
	}
	if pinned {
		bound := pin
		coverage.Record = &bound
	}
	findings := r.findingsForRecord(recordID)
	if emitted != nil || len(findings) > 0 {
		coverage.Advisory = domain.GovulncheckCoverageCovered
	}
	if emitted != nil {
		coverage.Subjects = projectSubjects(emitted.Subjects, ownSubjects)
		coverage.Modules = projectModules(emitted.Modules, v, ownSubjects)
	}
	return RecordProjection{Coverage: coverage, Findings: findings}, nil
}

// findingsForRecord keeps only findings that name the record's own id. An
// alias match is another identity's finding and never becomes this record's
// positive trace.
func (r Result) findingsForRecord(recordID string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.OSV == recordID {
			out = append(out, f)
		}
	}
	return out
}

// recordSubjects returns the symbols the record's own document declares.
func recordSubjects(v *domain.Vulnerability) []domain.SymbolRef {
	var out []domain.SymbolRef
	add := func(ref domain.SymbolRef) {
		if !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	for _, ref := range v.AffectedSymbols {
		add(ref)
	}
	for _, module := range v.AffectedModules {
		for _, ref := range module.AffectedSymbols {
			add(ref)
		}
	}
	for _, pkg := range v.AffectedPackages {
		for _, symbol := range pkg.Symbols {
			add(domain.SymbolRef{Package: pkg.Path, Symbol: symbol})
		}
	}
	return out
}

// projectSubjects keeps only emitted declarations the record itself claims.
func projectSubjects(emitted, own []domain.SymbolRef) []domain.SymbolRef {
	var out []domain.SymbolRef
	for _, ref := range emitted {
		if slices.Contains(own, ref) && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	return out
}

// projectModules keeps only emitted modules the record itself binds: a
// declared module identity, or a subject package inside that module path.
func projectModules(emitted []string, v *domain.Vulnerability, own []domain.SymbolRef) []string {
	var out []string
	for _, module := range emitted {
		if module == "" || slices.Contains(out, module) || !recordBindsModule(v, own, module) {
			continue
		}
		out = append(out, module)
	}
	return out
}

func recordBindsModule(v *domain.Vulnerability, own []domain.SymbolRef, module string) bool {
	if v.Module == module {
		return true
	}
	for _, m := range v.AffectedModules {
		if m.Module == module {
			return true
		}
	}
	for _, ref := range own {
		if ref.Package == module || strings.HasPrefix(ref.Package, module+"/") {
			return true
		}
	}
	return false
}

// ForVulnerability returns findings whose OSV id matches the vulnerability or
// one of its aliases. It is alias-aware presentation metadata for
// non-assessment consumers; assessment evidence must use ProjectRecord.
func (r Result) ForVulnerability(v domain.Vulnerability) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.OSV == v.ID || hasString(v.Aliases, f.OSV) {
			out = append(out, f)
		}
	}
	return out
}

// TraceReaches reports whether any trace frame invokes the symbol. Function
// names may carry a receiver ("(*T).M"); the receiver is stripped before
// comparison.
func (f Finding) TraceReaches(sym domain.SymbolRef) bool {
	for _, fr := range f.Trace {
		if frameIsSymbol(fr, sym) {
			return true
		}
	}
	return false
}

func frameIsSymbol(fr TraceFrame, sym domain.SymbolRef) bool {
	if fr.Package != sym.Package {
		return false
	}
	fn := fr.Function
	if strings.HasPrefix(fn, "(") {
		if i := strings.Index(fn, ")."); i >= 0 {
			fn = fn[i+2:]
		}
	}
	fn = strings.TrimPrefix(fn, "*")
	// Receiver-qualified symbols ("Type.Method") must also match the frame's
	// receiver; bare symbols match on the function name alone.
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(fr.Receiver, "("), ")"), "*")
		return fn == sym.Symbol[i+1:] && recv == sym.Symbol[:i]
	}
	return fn == sym.Symbol
}

func hasString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// HasCallPath reports whether the finding contains an actual function-level
// call path (at least one frame has a non-empty Function name). Module-level
// and package-level presence findings from govulncheck have no function in trace.
func (f Finding) HasCallPath() bool {
	for _, fr := range f.Trace {
		if strings.TrimSpace(fr.Function) != "" {
			return true
		}
	}
	return false
}

// CallPath converts a finding trace into the graph's normalized form.
// Frames without a function name are filtered out as they represent
// module/package level presence rather than function call sites.
func (f Finding) CallPath() domain.CallPath {
	cp := domain.CallPath{Frames: make([]domain.CallSite, 0, len(f.Trace))}
	for _, fr := range f.Trace {
		if strings.TrimSpace(fr.Function) == "" {
			continue
		}
		cs := domain.CallSite{Package: fr.Package, Function: fr.Function, Receiver: fr.Receiver}
		if fr.Position != nil {
			cs.File = fr.Position.Filename
			cs.Line = fr.Position.Line
		}
		cp.Frames = append(cp.Frames, cs)
	}
	return cp
}
