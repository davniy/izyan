package research

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_RelativePathsAbsolutized reproduces the acceptance defect: a
// relative --out (and other relative inputs) must never leak into the
// recorded docker argv — docker create rejects relative host paths as
// invalid volume names.
func TestRun_RelativePathsAbsolutized(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(root, "agent.env")
	if err := os.WriteFile(envFile, []byte("OPENAI_API_KEY=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Chdir(root)
	rep, err := Run(context.Background(), Options{
		SnapshotDir:  relOf(t, root, snap),
		CVE:          "CVE-2024-32473",
		OutDir:       "results/variant2-e2e/trivy-32473",
		AdvisoryPath: relOf(t, root, adv),
		AgentEnvFile: relOf(t, root, envFile),
		DryRun:       true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) {
			return stubDigest(""), nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, m := range rep.Run.Mounts {
		if !filepath.IsAbs(m.Host) {
			t.Fatalf("mount host path not absolute: %+v", m)
		}
	}
	if rep.Run.EnvFile != "" && !filepath.IsAbs(rep.Run.EnvFile) {
		t.Fatalf("env file not absolute: %s", rep.Run.EnvFile)
	}
	// The recorded argv is the exact docker command: every -v host side
	// and every file argument must be absolute.
	for i, a := range rep.Run.Argv {
		if a == "-v" && i+1 < len(rep.Run.Argv) {
			host := strings.SplitN(rep.Run.Argv[i+1], ":", 2)[0]
			if !filepath.IsAbs(host) {
				t.Fatalf("argv -v host side relative: %s", rep.Run.Argv[i+1])
			}
		}
		if a == "--env-file" && i+1 < len(rep.Run.Argv) {
			if !filepath.IsAbs(rep.Run.Argv[i+1]) {
				t.Fatalf("--env-file not absolute: %s", rep.Run.Argv[i+1])
			}
		}
	}
	if !filepath.IsAbs(rep.Snapshot.Path) {
		t.Fatalf("snapshot path not absolute: %s", rep.Snapshot.Path)
	}
	if rep.Advisory.Status != "resolved" {
		t.Fatalf("relative advisory path not resolved: %+v", rep.Advisory)
	}
}

// TestRun_DockerStderrSurfaced asserts that a docker-side failure lands
// verbatim in run.error (report.json) and the audit log — never a bare
// "exit status 1".
func TestRun_DockerStderrSurfaced(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")

	fake := filepath.Join(root, "docker-stub.sh")
	stub := `#!/bin/sh
if [ "$1" = "create" ]; then
  echo 'docker: invalid mount config for type "bind": "rel/opencode-config.json" includes invalid characters for a local volume name' >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(fake, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out,
		NoNet: true, AllowAgent: true, DockerBin: fake,
		DigestFetcher: func(_ context.Context, _ string) (string, error) {
			return stubDigest(""), nil
		},
	})
	if err != nil {
		t.Fatalf("Run must still produce a report on launch failure: %v", err)
	}
	if rep.Mode != "failed" || rep.Run.Status != "error" {
		t.Fatalf("mode=%s run=%s", rep.Mode, rep.Run.Status)
	}
	if !strings.Contains(rep.Run.Error, "invalid characters for a local volume name") {
		t.Fatalf("docker stderr not surfaced in run.error: %q", rep.Run.Error)
	}
	runDir := filepath.Join(out, "runs", rep.RunID)
	var doc struct {
		Run struct {
			Error string `json:"error"`
		} `json:"run"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "report.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc.Run.Error, "invalid mount config") {
		t.Fatalf("report.json run.error lacks docker stderr: %q", doc.Run.Error)
	}
	var audit struct {
		RunError string `json:"run_error"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "audit.json")), &audit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit.RunError, "invalid mount config") {
		t.Fatalf("audit run_error lacks docker stderr: %q", audit.RunError)
	}
}

func relOf(t *testing.T, root, p string) string {
	t.Helper()
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("%s not under %s", p, root)
	}
	return rel
}
