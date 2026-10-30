package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalCLIRejectsInvalidInputWithoutWriting(t *testing.T) {
	for _, args := range [][]string{nil, {"--run", "absent"}, {"--out", "absent"}, {"--model", "forbidden"}} {
		if err := runResearchHistory(args); err == nil { t.Fatalf("accepted %v", args) }
	}
	out := filepath.Join(t.TempDir(), "history")
	if err := runResearchHistory([]string{"--run", t.TempDir(), "--out", out}); err == nil { t.Fatal("missing saved report accepted") }
	if _, err := os.Stat(out); !os.IsNotExist(err) { t.Fatal("failed playback created output") }
}

func TestHistoricalCLIPlayback(t *testing.T) {
	run := filepath.Join("testdata", "historical-run")
	out := filepath.Join(t.TempDir(), "history")
	before, err := os.ReadFile(filepath.Join(run, "report.json")); if err != nil { t.Fatal(err) }
	if err := runResearchHistory([]string{"--run", run, "--out", out}); err != nil { t.Fatal(err) }
	after, err := os.ReadFile(filepath.Join(out, "original", "report.json")); if err != nil { t.Fatal(err) }
	if !bytes.Equal(before, after) { t.Fatal("CLI changed original report") }
	if err := runResearchHistory([]string{"--run", run, "--out", out}); err == nil { t.Fatal("CLI overwrote an existing output") }
}
