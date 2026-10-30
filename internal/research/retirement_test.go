package research

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// retirement_test.go pins the Phase-4 cutover boundary of this package:
//
//   - it starts no model and owns no live human projection;
//   - the deterministic proof and saved-turn replay paths still work.
//
// These are structural assertions, not behavioural ones: they read the
// package's own source and exported surface so a future change cannot quietly
// reintroduce a second investigator.

// TestResearchNeverStartsModel requires that no non-test file in this package
// can start a model or a container: no harness invocation, no endpoint probe,
// no exec of an agent runtime. The one live investigator is `izyan triage`.
func TestResearchNeverStartsModel(t *testing.T) {
	// Pure historical validators and canonical authority adapters may import
	// shared types. Pin actual launch constructors, not package ownership.
	banned := map[string]map[string]bool{
		"os/exec":  {"Command": true, "CommandContext": true},
		"net/http": {"Get": true, "Post": true, "PostForm": true, "NewRequest": true, "NewRequestWithContext": true},
		"github.com/davniy/izyan/internal/llm": {"NewClient": true, "NewResearcher": true},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("%s: %v", path, perr)
		}
		imports := map[string]string{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			name := filepath.Base(p)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name == "." && banned[p] != nil {
				t.Errorf("%s uses uninspectable dot import %q", path, p)
			}
			imports[name] = p
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if banned[imports[name.Name]][selector.Sel.Name] {
				t.Errorf("%s invokes %s.%s: research must start no model/container", path, name.Name, selector.Sel.Name)
			}
			return true
		})
	}
}

// TestResearchProofReplaySurvivesRetirement requires that the cutover kept
// the proof and replay surface: the deterministic lane, the decision
// verifier, the bounded verification plan runner and saved-turn replay all
// remain exported and usable without a model.
func TestResearchProofReplaySurvivesRetirement(t *testing.T) {
	// Saved-turn replay of a plain /2 document still works end to end.
	dir, answerText := replayFixture(t)
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("plain /2 replay refused: %v", err)
	}
	if turn.Output.Status != AgentOK {
		t.Fatalf("recorded status rewritten: %s", turn.Output.Status)
	}
	if string(turn.AnswerJSON) != string(answerText) {
		t.Fatal("replayed answer bytes differ from the persisted answer")
	}
	// The replayed turn re-assembles into a report the current contract
	// accepts, with the recorded output preserved verbatim.
	r := Assemble(AssembleInput{Lane: fakeLane(t), Turn: turn, RunID: "retirement-replay"})
	if r.Schema != ReportSchemaV2 {
		t.Fatalf("replayed report changed schema: %s", r.Schema)
	}
	if r.AgentOutput.Status != AgentOK || r.AgentOutput.ReplayedFrom == nil {
		t.Fatalf("replayed output not preserved: %+v", r.AgentOutput)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("replayed report rejected:\n%v", err)
	}
	// The deterministic proof decision still verifies over recorded
	// evidence: an unsupported proposal stays INCONCLUSIVE, never a
	// verdict, and the proof route reports the gap.
	lane := fakeLane(t)
	decision, derr := VerifyDecision(t.Context(), DecisionInput{Lane: lane})
	if derr != nil {
		t.Fatalf("VerifyDecision: %v", derr)
	}
	if decision.Verdict != domain.VerdictInconclusive {
		t.Fatalf("empty evidence produced %q", decision.Verdict)
	}
	if len(decision.HumanQuestions) == 0 && decision.Reason == "" {
		t.Fatal("INCONCLUSIVE decision names no follow-up")
	}
}

// TestHistoricalPlaybackSeparatedFromCurrentAdmission verifies that historical
// saved runs can be played back as evaluation controls, but cannot be admitted
// or published as current authority without fresh canonical assessment.
func TestHistoricalPlaybackSeparatedFromCurrentAdmission(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV4)
	replay, err := PrepareHistoricalReplay(t.Context(), dir)
	if err != nil {
		t.Fatalf("historical playback refused: %v", err)
	}
	if !replay.HistoricalOnly || replay.CurrentAdmission {
		t.Fatalf("historical playback has current authority: %+v", replay)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := ParseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Historical envelope cannot be parsed as current authority.
	envelope, _ := json.Marshal(replay)
	if _, err := ParseReport(envelope); err != ErrHistoricalAuthority {
		t.Fatalf("expected ErrHistoricalAuthority, got %v", err)
	}
	// A /4 report carries historical authority; it cannot publish under /5
	// without going through PublishRequest and fresh canonical admission.
	if persisted.Schema == ReportSchemaV4 && persisted.RequestedCaseSHA256 == "" {
		persisted.Schema = ReportSchemaV5
		if err := Validate(persisted, dir); err == nil {
			t.Fatal("historical /4 report quietly upgraded to canonical /5 authority")
		}
	}
}
