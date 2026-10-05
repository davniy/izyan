package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestCLI_SnapshotOptionsArchive(t *testing.T) {
	archives := []string{"manifests.tgz", "manifests.tar.gz", "manifests.zip", "CHART.TGZ"}
	for _, a := range archives {
		o := analyzeOpts{deployManifests: a, perimeterMode: "cluster"}
		opts := buildSnapshotOptions(o)
		if opts.DeployArchive != a {
			t.Errorf("for %s, DeployArchive = %q, want %q", a, opts.DeployArchive, a)
		}
		if len(opts.DeployManifests) != 0 {
			t.Errorf("for %s, DeployManifests = %v, want empty", a, opts.DeployManifests)
		}
		if opts.PerimeterOverride != domain.PerimeterClusterInternal {
			t.Errorf("for %s, PerimeterOverride = %q, want %q", a, opts.PerimeterOverride, domain.PerimeterClusterInternal)
		}
	}
}

func TestCLI_SnapshotOptionsManifestList(t *testing.T) {
	o := analyzeOpts{
		deployManifests: "k8s/service.yaml,helm/values.yaml",
		perimeterMode:   "public",
	}
	opts := buildSnapshotOptions(o)
	if opts.DeployArchive != "" {
		t.Errorf("DeployArchive = %q, want empty", opts.DeployArchive)
	}
	wantList := []string{"k8s/service.yaml", "helm/values.yaml"}
	if !reflect.DeepEqual(opts.DeployManifests, wantList) {
		t.Errorf("DeployManifests = %v, want %v", opts.DeployManifests, wantList)
	}
	if opts.PerimeterOverride != domain.PerimeterPublic {
		t.Errorf("PerimeterOverride = %q, want %q", opts.PerimeterOverride, domain.PerimeterPublic)
	}
}

func TestCLI_Flags_EnvFallback(t *testing.T) {
	t.Setenv("VA_DEPLOY_MANIFESTS", "chart.tgz")
	t.Setenv("VA_PERIMETER", "cluster")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if o.deployManifests != "chart.tgz" {
		t.Errorf("deployManifests = %q, want %q", o.deployManifests, "chart.tgz")
	}
	if o.perimeterMode != "cluster" {
		t.Errorf("perimeterMode = %q, want %q", o.perimeterMode, "cluster")
	}

	opts := buildSnapshotOptions(o)
	if opts.DeployArchive != "chart.tgz" {
		t.Errorf("DeployArchive = %q, want %q", opts.DeployArchive, "chart.tgz")
	}
	if opts.PerimeterOverride != domain.PerimeterClusterInternal {
		t.Errorf("PerimeterOverride = %q, want %q", opts.PerimeterOverride, domain.PerimeterClusterInternal)
	}
}

func TestCLI_PrintCaseWithProfiles(t *testing.T) {
	c := &domain.AnalysisCase{
		ID:                 "case-1",
		DetectedPerimeter:  domain.PerimeterClusterInternal,
		PerimeterRationale: "ClusterIP found",
		Profiles: []domain.ProfileVerdict{
			{
				Profile:        domain.ProfileZeroTrust,
				Verdict:        domain.VerdictInconclusive,
				Priority:       domain.PriorityP1,
				IsTargetActual: false,
			},
			{
				Profile:        domain.ProfileClusterPerimeter,
				Verdict:        domain.VerdictNoExploitPathFound,
				Priority:       domain.PriorityDismissed,
				IsTargetActual: true,
			},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printCase(c, t.TempDir())

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "perimeter: cluster-internal") {
		t.Errorf("missing perimeter in printCase output:\n%s", out)
	}
	if !strings.Contains(out, "target_profile: cluster_perimeter (Verdict: NO_EXPLOIT_PATH_FOUND, Priority: DISMISSED)") {
		t.Errorf("missing target_profile in printCase output:\n%s", out)
	}
}
