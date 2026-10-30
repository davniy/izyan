package vexbench_test

import (
	"testing"

	"github.com/davniy/izyan/internal/eval/vexbench"
	"github.com/davniy/izyan/internal/llm"
	"github.com/davniy/izyan/internal/productb/triage"
)

func TestRunPinsExactPromptAndToolSurface(t *testing.T) {
	// Construct a VexTriageRun and ensure it captures exact prompt, tool surface, model pins
	prompt := triage.NewPromptInput("system instruction", []llm.ChatMessage{{Role: "user", Content: "data"}}, nil)
	run := vexbench.VexTriageRun{
		SchemaVersion: vexbench.VexTriageRunSchemaVersion,
		FindingID: "vex-test-1",
		PromptHash: prompt.PromptHash,
		PromptInput: prompt,
		Model: vexbench.ModelPin{
			RequestedModel: "gpt-4o",
			ReturnedModel: "gpt-4o-2024-08-06",
			ProviderFingerprint: "fp_test",
		},
		ToolRegistryVersion: "tool-registry.v1",
	}

	if err := run.Validate(); err != nil {
		t.Fatalf("run validation failed: %v", err)
	}
	if run.PromptHash != prompt.PromptHash {
		t.Fatalf("prompt hash mismatch")
	}
}
