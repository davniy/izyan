package evidencetools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/fedorovmv/izyan/internal/toolaudit"
)

// ---- run_build / run_tests ----

type runSubprocessArgs struct{}

type execData struct {
	Subcommand string `json:"subcommand"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
}

const maxExecOutput = 8000

// runSubprocess executes `go build ./...` or `go test ./...` inside the
// snapshot under the session toolchain. Repository code compiles/runs —
// the capability is gated by AllowExec.
func (s *Session) runSubprocess(ctx context.Context, sub string) (*Observation, error) {
	tool := "run_" + sub
	if !s.AllowExec {
		return s.unsupported(tool,
			fmt.Sprintf("%s executes repository code; exec permission is off (pass --allow-exec)", tool)), nil
	}
	args := []string{sub, "./..."}
	if sub == "build" {
		// go build drops executables of main packages into the work dir —
		// keep the analyzed repo clean (same discipline as production).
		out := filepath.Join(os.TempDir(), "izyan-evidence-build-out")
		if err := os.MkdirAll(out, 0o755); err == nil {
			defer os.RemoveAll(out)
			args = []string{"build", "-o", out, "./..."}
		}
	}
	bin := s.ToolBin
	if bin == "" {
		bin = "go"
	}
	stdout, stderr, err := toolaudit.Run(ctx, "go", s.ToolVer, s.SnapshotRoot, bin, s.ToolEnv, args...)
	out := truncateOut(string(stdout), maxExecOutput)
	outTrunc := len(stdout) > maxExecOutput
	if err != nil {
		// A non-zero exit is still a real observation — the command ran
		// and failed. Report it as OK+PARTIAL with exit code, not ERROR:
		// the tool executed correctly, the build itself failed.
		data := execData{Subcommand: sub, ExitCode: exitCodeOf(err),
			Output: out + truncateOut("\n"+string(stderr), 4000), Truncated: outTrunc}
		sd, lims, _ := s.sourceScope(ctx, "")
		lims = append(lims,
			fmt.Sprintf("go %s exited non-zero; output is truncated process output, not a structured diagnosis", sub))
		return s.ok(tool,
			fmt.Sprintf("go %s ./... failed with exit code %d", sub, exitCodeOf(err)),
			fmt.Sprintf("%s ran in snapshot %s", cmdLine(bin, args), s.SnapshotRoot),
			CompletenessPartial, data, sd, lims), nil
	}
	data := execData{Subcommand: sub, ExitCode: 0, Output: out, Truncated: outTrunc}
	sd, lims, serr := s.sourceScope(ctx, "")
	if serr != nil {
		return nil, serr
	}
	lims = append(lims,
		"exit code is an observation of this build context only; other GOOS/GOARCH/tag sets may fail differently")
	return s.ok(tool,
		fmt.Sprintf("go %s ./... exited 0", sub),
		fmt.Sprintf("%s ran in snapshot %s", cmdLine(bin, args), s.SnapshotRoot),
		CompletenessPartial, data, sd, lims), nil
}

func (s *Session) runBuild(ctx context.Context) (*Observation, error) {
	return s.runSubprocess(ctx, "build")
}

func (s *Session) runTests(ctx context.Context) (*Observation, error) {
	return s.runSubprocess(ctx, "test")
}

func truncateOut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

func cmdLine(bin string, args []string) string {
	return fmt.Sprintf("%q %v", bin, args)
}

func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
