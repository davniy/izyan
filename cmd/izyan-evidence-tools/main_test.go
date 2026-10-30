package main

import (
	"strings"
	"testing"
)

// Confinement is unconditional in this binary: there is no CLI opt-out
// for any profile, strict or default — a caller cannot run an agent
// session unconfined even by accident (E1).
func TestNoUnconfinedFlag(t *testing.T) {
	for _, args := range [][]string{
		{"--confine=false", "--snapshot-root", t.TempDir(), "--cve", "X"},
		{"--confine", "--snapshot-root", t.TempDir(), "--cve", "X"},
		{"--unsafe-unconfined", "--snapshot-root", t.TempDir(), "--cve", "X"},
	} {
		err := run(args)
		if err == nil {
			t.Fatalf("args %v: expected failure, got nil", args)
		}
		if !strings.Contains(err.Error(), "not defined") {
			t.Fatalf("args %v: expected an unknown-flag error, got %v", args, err)
		}
	}
}

// The strict profile keeps the same required-flag contract as the
// default: a missing --snapshot-root fails closed before serving.
func TestStrictRequiresSnapshotRoot(t *testing.T) {
	if err := run([]string{"--strict", "--cve", "X"}); err == nil {
		t.Fatal("--strict without --snapshot-root must fail")
	} else if !strings.Contains(err.Error(), "snapshot-root") {
		t.Fatalf("unexpected error: %v", err)
	}
}
