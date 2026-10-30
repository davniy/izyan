package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/gitlock"
	"github.com/davniy/izyan/internal/report"
)

// remediationTarget is one witness-bound fix target: the module and fixed
// version of the record whose independently admitted proof grounds the
// requested answer. It is never the primary record's module unless the primary
// is the deciding witness.
type remediationTarget struct {
	Origin          domain.ProofOrigin
	Module          string
	ResolvedVersion string
	FixedVersion    string
}

// remediationTargets selects fix targets from the requested finding's admitted
// witnesses. A composed CVE positive therefore remediates the gRPC witness, not
// the fixed x/net primary. Only an earned positive is remediated: a FAILED
// analysis and an external dependency have no fix to plan.
func remediationTargets(view requestedView) []remediationTarget {
	f := view.Finding
	if f.Outcome != domain.OutcomeDecided || f.Verdict != domain.VerdictExploitable {
		return nil
	}
	var out []remediationTarget
	seen := map[string]bool{}
	for _, origin := range f.ProofOrigins {
		record := view.View.Records[origin.AssessmentID]
		if record == nil || record.Affected == nil {
			continue
		}
		module, fixed, ok := report.FixTarget(record)
		if !ok || module == "" {
			continue
		}
		key := module + "\x00" + fixed
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, remediationTarget{
			Origin:          origin,
			Module:          module,
			ResolvedVersion: record.Affected.ResolvedVersion,
			FixedVersion:    fixed,
		})
	}
	return out
}

// requestedOutcomeLabel renders the case's requested terminal for the
// before/after line. A FAILED analysis never prints as INCONCLUSIVE.
func requestedOutcomeLabel(c *domain.AnalysisCase) string {
	if c == nil {
		return "NONE"
	}
	if c.RequestedFinding == nil {
		if c.Verdict == nil {
			return "NONE"
		}
		return string(c.Verdict.Verdict)
	}
	switch c.RequestedFinding.Outcome {
	case domain.OutcomeDecided:
		return string(c.RequestedFinding.Verdict)
	case domain.OutcomeExternal:
		return "INCONCLUSIVE (external dependency)"
	default:
		return "FAILED (no verdict)"
	}
}

// runRemediate implements `izyan remediate`: analyze the case, derive the
// witness-bound deterministic fix target (smallest fixed version above the
// resolved one), and — only with --apply — run `go get`/`go mod tidy`, verify
// the build (optionally tests), then re-analyze the product.
//
// Without --apply the command is read-only: it prints the plan and the commands
// it would run. --apply mutates go.mod/go.sum, so it is an explicit opt-in,
// never implied by other flags.
func runRemediate(args []string) error {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	fs.StringVar(&o.vulnID, "vuln", "", "vulnerability id (GO-/CVE-/GHSA-)")
	fs.StringVar(&o.vulnFile, "vuln-file", "", "local OSV JSON file")
	fs.StringVar(&o.exploitModel, "exploit-model", "", "manual exploit model JSON")
	var rootCauseFlags stringList
	fs.Var(&rootCauseFlags, "root-cause", "manual root cause as pkg/path.Symbol (repeatable)")
	apply := fs.Bool("apply", false, "apply the fix (go get/go mod tidy) — mutates go.mod/go.sum")
	runTests := fs.Bool("run-tests", false, "run `go test ./...` after the fix before re-analysis")
	worktree := fs.String("worktree", "", "apply inside `git worktree add <path>` instead of the repository — the fix is validated without touching the source checkout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.rootCauseArgs = rootCauseFlags
	if o.repo == "" || o.vulnID == "" {
		usage()
	}
	kb, err := loadKnowledgeBase(o.knowledge)
	if err != nil {
		return err
	}
	o.kb = kb
	ctx := context.Background()
	// The re-analysis must honour the same operator corpus/capture inputs.
	if err := resolveAdvisorySources(ctx, &o); err != nil {
		return err
	}

	before, err := analyzeCase(ctx, o)
	if err != nil {
		return err
	}
	// The case, its requested outcome and its report path are printed before
	// any exit status: a FAILED assessment is a reported result, not a silent
	// abort.
	printErr := printCase(before, o.caseDir, o.lang)
	beforeView, viewErr := projectRequested(before)
	if viewErr != nil {
		return printErr
	}
	targets := remediationTargets(beforeView)
	if len(targets) == 0 {
		switch beforeView.Finding.Outcome {
		case domain.OutcomeFailed:
			// Already reported with its failure codes; exit nonzero.
			return printErr
		case domain.OutcomeExternal:
			fmt.Printf("remediate: %s — no earned fix target; the answer depends on: %s\n",
				requestedOutcomeLabel(before),
				strings.Join(projectedExternalFacts(beforeView.Finding.FindingProfile), "; "))
			return nil
		default:
			fmt.Printf("remediate: requested verdict %s — no remediation is due\n", beforeView.Finding.Verdict)
			return nil
		}
	}
	steps := [][]string{}
	for _, target := range targets {
		if target.FixedVersion == "" {
			fmt.Printf("remediate: %s has no published fixed version — manual remediation required\n", target.Module)
			continue
		}
		fmt.Printf("remediate: %s %s -> %s (witness %s)\n",
			target.Module, target.ResolvedVersion, target.FixedVersion, target.Origin.Record.RecordID)
		steps = append(steps, []string{"go", "get", target.Module + "@" + target.FixedVersion})
	}
	if len(steps) == 0 {
		fmt.Println("remediate: no applicable fix target — nothing to plan")
		return nil
	}
	steps = append(steps,
		[]string{"go", "mod", "tidy"},
		[]string{"go", "build", "./..."},
	)
	if *runTests {
		steps = append(steps, []string{"go", "test", "./..."})
	}
	for _, s := range steps {
		fmt.Println("  plan:", joinArgs(s))
	}
	if !*apply {
		fmt.Println("remediate: dry-run — rerun with --apply to execute")
		return nil
	}
	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return err
	}
	target := absRepo
	if *worktree != "" {
		wt, err := filepath.Abs(*worktree)
		if err != nil {
			return err
		}
		// Worktree add mutates shared .git/worktrees metadata; the same
		// lock the repository packages take serializes it against any
		// concurrent Product-A/Product-B worktree mutation on this repo.
		unlock, lerr := gitlock.Acquire(ctx, absRepo)
		if lerr != nil {
			return fmt.Errorf("remediate: worktree lock: %w", lerr)
		}
		err = runRemediateStep(absRepo,
			[]string{"git", "worktree", "add", "--detach", wt, "HEAD"})
		unlock()
		if err != nil {
			return fmt.Errorf("remediate step %q failed: %w",
				"git worktree add --detach "+wt+" HEAD", err)
		}
		fmt.Println("remediate: applying in worktree", wt)
		target = wt
	}
	for _, s := range steps {
		if err := runRemediateStep(target, s); err != nil {
			return fmt.Errorf("remediate step %q failed: %w", joinArgs(s), err)
		}
	}
	if target != absRepo {
		o.repo = target // re-analysis reads the fixed worktree
	}
	after, err := analyzeCase(ctx, o)
	if err != nil {
		return err
	}
	afterErr := printCase(after, o.caseDir, o.lang)
	fmt.Printf("remediate: requested outcome %s -> %s\n",
		requestedOutcomeLabel(before), requestedOutcomeLabel(after))
	// A fix that leaves the requested assessment FAILED did not verify.
	return afterErr
}

func runRemediateStep(dir string, cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Dir = dir
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func joinArgs(s []string) string {
	out := ""
	for i, a := range s {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
